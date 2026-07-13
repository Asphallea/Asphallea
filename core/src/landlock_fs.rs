//! Filesystem allowlist via the Landlock LSM.
//!
//! Landlock lets an unprivileged process drop its own filesystem rights down to a
//! set of allowed hierarchies. It is inode based, applied to the process and every
//! descendant, and cannot be undone, which is exactly what containment needs. A
//! hijacked command cannot read the user's home, cannot write outside the
//! workspace, and cannot delete files the policy did not grant.
//!
//! v0 enforces the Landlock ABI v1 filesystem subset (read, write, execute,
//! create, remove), which every Landlock-capable kernel (5.13+) supports. A
//! baseline of system directories is granted read and execute so ordinary
//! programs and interpreters can actually run; the user's data outside the
//! allowlist stays blocked.

use crate::policy::Policy;
use crate::report::Report;
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};

/// System hierarchies granted read and execute so programs can load and run.
/// The user's home and other data outside the policy allowlist are not here and
/// stay blocked. Missing paths are skipped, so this is safe across distros.
const BASELINE_READ_EXEC: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/opt",
    "/proc",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// Query the Landlock ABI version the running kernel supports.
///
/// Returns the version number, or 0 when Landlock is unavailable. This uses the
/// documented version-probe form of `landlock_create_ruleset`, which reports the
/// supported ABI without creating anything.
pub fn abi_version() -> i64 {
    #[cfg(target_os = "linux")]
    unsafe {
        // LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
        let ret = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        );
        if ret < 0 {
            0
        } else {
            ret
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Apply the filesystem allowlist and record the outcome in the report.
pub fn apply(policy: &Policy, report: &mut Report) {
    report.landlock_abi = abi_version();
    if report.landlock_abi < 1 {
        report.landlock_status = "unsupported".to_string();
        report
            .warnings
            .push("Landlock unsupported on this kernel (needs 5.13+)".to_string());
        return;
    }

    let abi = ABI::V1;
    let mut skipped: Vec<String> = Vec::new();

    let result = (|| -> Result<landlock::RestrictionStatus, RulesetError> {
        let mut created = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?;

        // Baseline: read and execute on system directories so programs run.
        for path in BASELINE_READ_EXEC {
            if let Ok(fd) = PathFd::new(path) {
                created = created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?;
            }
        }
        // Policy read paths: read and execute.
        for path in &policy.filesystem.read {
            match PathFd::new(path) {
                Ok(fd) => {
                    created = created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?;
                }
                Err(_) => skipped.push(format!("read path not found, skipped: {path}")),
            }
        }
        // Policy write paths: full access (read, write, create, remove).
        for path in &policy.filesystem.write {
            match PathFd::new(path) {
                Ok(fd) => {
                    created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
                }
                Err(_) => skipped.push(format!("write path not found, skipped: {path}")),
            }
        }

        created.restrict_self()
    })();

    report.warnings.extend(skipped);

    match result {
        Ok(status) => {
            report.landlock_status = match status.ruleset {
                RulesetStatus::FullyEnforced => "fully_enforced",
                RulesetStatus::PartiallyEnforced => "partially_enforced",
                RulesetStatus::NotEnforced => "not_enforced",
            }
            .to_string();
        }
        Err(e) => {
            report.landlock_status = "not_enforced".to_string();
            report.warnings.push(format!("Landlock error: {e}"));
        }
    }
}
