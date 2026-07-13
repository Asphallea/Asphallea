//! Windows containment: Job Object resource limits and guaranteed termination,
//! plus AppContainer filesystem and network allowlisting.
//!
//! The launcher creates a Job Object (memory, CPU-time, and process-count limits,
//! and `KILL_ON_JOB_CLOSE` so the whole tree dies with the launcher). When the
//! policy asks for filesystem or network containment, it also launches the command
//! inside an AppContainer (see [`crate::win_appcontainer`]) whose only reachable
//! files are the policy's allowlisted paths and the system directories, and which
//! has no network capability. The command is spawned suspended, placed in the job,
//! and only then resumed, so no code runs before the limits are in force.

use crate::policy::Policy;
use crate::report::Report;
use crate::win_appcontainer::AppContainer;
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, TRUE};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

/// Run `command` under Windows containment. Fills `report`, writes it before
/// waiting, then returns the child's exit code.
pub fn run(
    policy: &Policy,
    command: &[String],
    report: &mut Report,
    report_path: &Option<String>,
) -> i32 {
    let needs_appcontainer = !policy.filesystem.read.is_empty()
        || !policy.filesystem.write.is_empty()
        || policy.network_denied();

    let appcontainer = if needs_appcontainer {
        match AppContainer::new(policy, report) {
            Ok(ac) => Some(ac),
            Err(e) => {
                // The policy needs filesystem or network containment and we cannot
                // build the sandbox. Fail closed rather than run exposed.
                report.contained = false;
                report
                    .warnings
                    .push(format!("AppContainer setup failed: {e}"));
                write_report(report_path, report);
                eprintln!(
                    "asphallea-run: AppContainer setup failed ({e}); refusing to run uncontained."
                );
                return 3;
            }
        }
    } else {
        None
    };

    match spawn(policy, command, report, appcontainer.as_ref()) {
        Ok((job, process)) => {
            report.contained = true;
            write_report(report_path, report);
            let code = unsafe {
                WaitForSingleObject(process, INFINITE);
                let mut code: u32 = 0;
                GetExitCodeProcess(process, &mut code);
                CloseHandle(process);
                CloseHandle(job);
                code
            };
            // appcontainer drops here, after the child has exited, revoking its ACEs.
            code as i32
        }
        Err(e) => {
            report.contained = false;
            report.warnings.push(e.clone());
            write_report(report_path, report);
            eprintln!("asphallea-run: {e}");
            127
        }
    }
}

fn spawn(
    policy: &Policy,
    command: &[String],
    report: &mut Report,
    appcontainer: Option<&AppContainer>,
) -> Result<(HANDLE, HANDLE), String> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(format!("CreateJobObject failed (error {})", GetLastError()));
        }
        configure_job(job, policy, report)?;

        let mut cmdline: Vec<u16> = build_command_line(command)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let (in_h, out_h, err_h) = (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        );

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut flags = CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP;

        // Attribute-list storage must outlive CreateProcessW.
        let mut attr_buf: Vec<u8> = Vec::new();
        let mut sec_caps;

        let created = if let Some(ac) = appcontainer {
            // The contained process needs to write to the inherited stdio pipes.
            ac.grant_handle_to_packages(out_h);
            ac.grant_handle_to_packages(err_h);
            ac.grant_handle_to_packages(in_h);

            let mut size: usize = 0;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
            attr_buf = vec![0u8; size];
            let attr_list = attr_buf.as_mut_ptr() as *mut c_void;
            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) == 0 {
                let e = GetLastError();
                CloseHandle(job);
                return Err(format!(
                    "InitializeProcThreadAttributeList failed (error {e})"
                ));
            }
            sec_caps = ac.security_capabilities();
            if UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &mut sec_caps as *mut _ as *mut c_void,
                std::mem::size_of_val(&sec_caps),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                let e = GetLastError();
                DeleteProcThreadAttributeList(attr_list);
                CloseHandle(job);
                return Err(format!("UpdateProcThreadAttribute failed (error {e})"));
            }

            let mut siex: STARTUPINFOEXW = std::mem::zeroed();
            siex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            siex.StartupInfo.hStdInput = in_h;
            siex.StartupInfo.hStdOutput = out_h;
            siex.StartupInfo.hStdError = err_h;
            siex.lpAttributeList = attr_list;
            flags |= EXTENDED_STARTUPINFO_PRESENT;

            report.network = if policy.network_denied() {
                "denied (AppContainer has no network capability)".to_string()
            } else {
                "allowed".to_string()
            };
            report.landlock_status = "appcontainer".to_string(); // filesystem allowlist in force

            let created = CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                TRUE,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &siex as *const _ as *const STARTUPINFOW,
                &mut pi,
            );
            DeleteProcThreadAttributeList(attr_list);
            created
        } else {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = in_h;
            si.hStdOutput = out_h;
            si.hStdError = err_h;
            report.network = "not restricted (resource-only policy)".to_string();

            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                TRUE,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        let _ = &attr_buf; // keep alive until here

        if created == 0 {
            let e = GetLastError();
            CloseHandle(job);
            return Err(format!("CreateProcess failed for {command:?} (error {e})"));
        }

        if AssignProcessToJobObject(job, pi.hProcess) == 0 {
            let e = GetLastError();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(job);
            return Err(format!("AssignProcessToJobObject failed (error {e})"));
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        Ok((job, pi.hProcess))
    }
}

unsafe fn configure_job(job: HANDLE, policy: &Policy, report: &mut Report) -> Result<(), String> {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    let mut flags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    report.rlimits.push("kill_on_close=true".to_string());

    if let Some(n) = policy.limits.max_processes {
        info.BasicLimitInformation.ActiveProcessLimit = n as u32;
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        report.rlimits.push(format!("active_process_limit={n}"));
    }
    if let Some(bytes) = policy.limits.memory_bytes {
        info.ProcessMemoryLimit = bytes as usize;
        info.JobMemoryLimit = bytes as usize;
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
        report.rlimits.push(format!("memory_limit_bytes={bytes}"));
    }
    if let Some(secs) = policy.limits.cpu_seconds {
        info.BasicLimitInformation.PerProcessUserTimeLimit = (secs as i64) * 10_000_000;
        flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        report
            .rlimits
            .push(format!("cpu_time_limit_seconds={secs}"));
    }
    info.BasicLimitInformation.LimitFlags = flags;

    let set = SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &info as *const _ as *const c_void,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    );
    if set == 0 {
        let e = GetLastError();
        CloseHandle(job);
        return Err(format!("SetInformationJobObject failed (error {e})"));
    }
    Ok(())
}

fn write_report(report_path: &Option<String>, report: &Report) {
    if let Some(p) = report_path {
        if let Ok(text) = serde_json::to_string(report) {
            let _ = std::fs::write(p, text);
        }
    }
}

/// Build a Windows command line from an argv, following the standard quoting
/// rules (backslashes are only special before a quote or at the end of a quoted
/// argument).
fn build_command_line(args: &[String]) -> String {
    let mut cmd = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            cmd.push(' ');
        }
        append_quoted(arg, &mut cmd);
    }
    cmd
}

fn append_quoted(arg: &str, out: &mut String) {
    let needs_quote = arg.is_empty() || arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
    if !needs_quote {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let chars: Vec<char> = arg.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let mut backslashes = 0;
        while i < chars.len() && chars[i] == '\\' {
            backslashes += 1;
            i += 1;
        }
        if i == chars.len() {
            for _ in 0..backslashes * 2 {
                out.push('\\');
            }
        } else if chars[i] == '"' {
            for _ in 0..backslashes * 2 + 1 {
                out.push('\\');
            }
            out.push('"');
            i += 1;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(chars[i]);
            i += 1;
        }
    }
    out.push('"');
}
