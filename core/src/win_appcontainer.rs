//! Windows filesystem and network containment via AppContainer.
//!
//! An AppContainer runs a process in a low-privilege sandbox. By default it cannot
//! reach the user's files: it only gets the access granted to the
//! `ALL_APPLICATION_PACKAGES` group (system directories, so programs can load and
//! run) plus whatever we explicitly grant its container SID. We grant the policy's
//! read and write paths and nothing else, so a hijacked command cannot read the
//! user's secrets or write outside the workspace. With no network capability, the
//! Windows Filtering Platform blocks the container's outbound connections, so
//! network is denied.
//!
//! The container SID is derived per launcher process. The paths we grant get a
//! matching ACE that is revoked when the sandbox is dropped, so the change does not
//! outlive the run.

use crate::policy::Policy;
use crate::report::Report;
use std::ffi::c_void;

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo, SetEntriesInAclW,
    SetNamedSecurityInfoW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, REVOKE_ACCESS,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID,
    SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR,
};

// Standard Win32 generic access rights (stable values).
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

/// A registered AppContainer profile plus the filesystem grants made for it.
pub struct AppContainer {
    sid: PSID,
    name: Vec<u16>,
    granted_paths: Vec<Vec<u16>>,
}

impl AppContainer {
    /// Register an AppContainer profile for this launcher and grant the policy's
    /// paths. A registered profile is required to launch a process into it;
    /// deriving the SID alone is not enough.
    pub fn new(policy: &Policy, report: &mut Report) -> Result<AppContainer, String> {
        let name = format!("asphallea.sandbox.{}", std::process::id());
        let name_w = to_wide(&name);
        let mut sid: PSID = std::ptr::null_mut();
        unsafe {
            let hr = CreateAppContainerProfile(
                name_w.as_ptr(),
                name_w.as_ptr(),
                name_w.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            );
            if hr != 0 {
                // Likely already exists from a prior run with this pid; derive it.
                let hr2 = DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid);
                if hr2 < 0 {
                    return Err(format!(
                        "AppContainer profile setup failed (create {hr:#x}, derive {hr2:#x})"
                    ));
                }
            }
        }

        let mut container = AppContainer {
            sid,
            name: name_w,
            granted_paths: Vec::new(),
        };

        for path in &policy.filesystem.read {
            match container.grant(path, GENERIC_READ | GENERIC_EXECUTE) {
                Ok(()) => report.rlimits.push(format!("appcontainer_read={path}")),
                Err(e) => report
                    .warnings
                    .push(format!("appcontainer could not grant read {path}: {e}")),
            }
        }
        for path in &policy.filesystem.write {
            match container.grant(path, GENERIC_ALL) {
                Ok(()) => report.rlimits.push(format!("appcontainer_write={path}")),
                Err(e) => report
                    .warnings
                    .push(format!("appcontainer could not grant write {path}: {e}")),
            }
        }
        Ok(container)
    }

    /// The SECURITY_CAPABILITIES to launch a process into this container. No
    /// capabilities are granted, so brokered resources including network are denied.
    pub fn security_capabilities(&self) -> SECURITY_CAPABILITIES {
        SECURITY_CAPABILITIES {
            AppContainerSid: self.sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        }
    }

    /// Grant `ALL_APPLICATION_PACKAGES` access to an inherited handle (a stdio
    /// pipe) so the contained process can write to it. Best effort.
    pub fn grant_handle_to_packages(&self, handle: HANDLE) {
        if handle.is_null() {
            return;
        }
        unsafe {
            let sid_str = to_wide("S-1-15-2-1"); // ALL_APPLICATION_PACKAGES
            let mut aap: PSID = std::ptr::null_mut();
            if ConvertStringSidToSidW(sid_str.as_ptr(), &mut aap) == 0 {
                return;
            }
            let ea = explicit_access(
                aap,
                GENERIC_ALL,
                GRANT_ACCESS,
                TRUSTEE_IS_WELL_KNOWN_GROUP,
                0,
            );

            let mut old_dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: *mut SECURITY_DESCRIPTOR = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut old_dacl,
                std::ptr::null_mut(),
                &mut sd as *mut _ as *mut *mut c_void,
            );
            if rc == ERROR_SUCCESS {
                let mut new_dacl: *mut ACL = std::ptr::null_mut();
                if SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) == ERROR_SUCCESS {
                    SetSecurityInfo(
                        handle,
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        new_dacl,
                        std::ptr::null_mut(),
                    );
                    LocalFree(new_dacl as *mut c_void);
                }
                LocalFree(sd as *mut c_void);
            }
            FreeSid(aap);
        }
    }

    fn grant(&mut self, path: &str, mask: u32) -> Result<(), String> {
        let path_w = to_wide(path);
        let inherit = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        set_file_ace(&path_w, self.sid, mask, GRANT_ACCESS, inherit)?;
        self.granted_paths.push(path_w);
        Ok(())
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        for path_w in &self.granted_paths {
            // Remove every ACE for our container SID from the path.
            let _ = set_file_ace(path_w, self.sid, 0, REVOKE_ACCESS, 0);
        }
        unsafe {
            if !self.sid.is_null() {
                FreeSid(self.sid);
            }
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

fn set_file_ace(
    path_w: &[u16],
    sid: PSID,
    mask: u32,
    mode: i32,
    inherit: u32,
) -> Result<(), String> {
    unsafe {
        let mut old_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: *mut SECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut sd as *mut _ as *mut *mut c_void,
        );
        if rc != ERROR_SUCCESS {
            return Err(format!("GetNamedSecurityInfo error {rc}"));
        }

        let ea = explicit_access(sid, mask, mode, TRUSTEE_IS_UNKNOWN, inherit);
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let rc2 = SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl);
        if rc2 != ERROR_SUCCESS {
            LocalFree(sd as *mut c_void);
            return Err(format!("SetEntriesInAcl error {rc2}"));
        }

        let rc3 = SetNamedSecurityInfoW(
            path_w.as_ptr() as PWSTR,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl as *mut c_void);
        LocalFree(sd as *mut c_void);
        if rc3 != ERROR_SUCCESS {
            return Err(format!("SetNamedSecurityInfo error {rc3}"));
        }
        Ok(())
    }
}

fn explicit_access(
    sid: PSID,
    mask: u32,
    mode: i32,
    trustee_type: i32,
    inherit: u32,
) -> EXPLICIT_ACCESS_W {
    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode = mode;
    ea.grfInheritance = inherit;
    ea.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0, // NO_MULTIPLE_TRUSTEE
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: trustee_type,
        ptstrName: sid as PWSTR,
    };
    ea
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
