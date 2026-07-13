//! Windows containment via Job Objects.
//!
//! A Job Object is the Windows primitive for bounding and killing a group of
//! processes. The launcher creates a job, spawns the target into it while the
//! target is still suspended (so no code runs before the limits are in force),
//! then resumes it. Everything the target spawns is inside the job too.
//!
//! What this backend enforces today:
//!
//! - Guaranteed termination. `KILL_ON_JOB_CLOSE` means if the launcher dies (for
//!   example the SDK kills it on a wall-clock timeout), the kernel kills the
//!   target and every descendant. There is no orphan and no escape.
//! - Memory limit (per process and per job).
//! - CPU-time limit (the process is killed when it exceeds it).
//! - Process-count limit.
//!
//! What it does not do yet: filesystem and network allowlisting. That is the
//! AppContainer layer, and it is the next backend. Until then this backend is
//! honest about it in the report, and the policy tier still enforces path
//! allowlists for wrapped callable tools.

use crate::policy::Policy;
use crate::report::Report;

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
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// Run `command` inside a Job Object shaped by `policy`. Fills `report`, writes it
/// to `report_path` before waiting, then returns the child's exit code.
pub fn run(
    policy: &Policy,
    command: &[String],
    report: &mut Report,
    report_path: &Option<String>,
) -> i32 {
    match spawn_in_job(policy, command, report) {
        Ok((job, process)) => {
            report.contained = true;
            write_report(report_path, report);
            // Wait for the child. The SDK enforces the wall-clock timeout by
            // killing this launcher, and KILL_ON_JOB_CLOSE then kills the tree.
            let code = unsafe {
                WaitForSingleObject(process, INFINITE);
                let mut code: u32 = 0;
                GetExitCodeProcess(process, &mut code);
                CloseHandle(process);
                CloseHandle(job);
                code
            };
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

fn spawn_in_job(
    policy: &Policy,
    command: &[String],
    report: &mut Report,
) -> Result<(HANDLE, HANDLE), String> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(format!("CreateJobObject failed (error {})", GetLastError()));
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        // Always: kill the whole tree when the job handle closes, and take down a
        // process that faults rather than popping an error dialog.
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
            // PerProcessUserTimeLimit is in 100-nanosecond units.
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
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if set == 0 {
            let e = GetLastError();
            CloseHandle(job);
            return Err(format!("SetInformationJobObject failed (error {e})"));
        }

        // Build the command line and spawn suspended so nothing runs before the
        // process is inside the job.
        let mut cmdline: Vec<u16> = build_command_line(command)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let created = CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            TRUE, // inherit handles so the child shares our stdio pipes
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        );
        if created == 0 {
            let e = GetLastError();
            CloseHandle(job);
            return Err(format!(
                "CreateProcess failed for {:?} (error {e})",
                command
            ));
        }

        if AssignProcessToJobObject(job, pi.hProcess) == 0 {
            let e = GetLastError();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(job);
            return Err(format!("AssignProcessToJobObject failed (error {e})"));
        }

        // The process is now bound by the job. Let it run.
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        report.network =
            "not restricted (AppContainer network isolation is the next layer)".to_string();
        report
            .warnings
            .push("filesystem is not allowlisted by the Job Object backend yet (AppContainer is next); the policy tier still enforces path allowlists for wrapped callable tools".to_string());

        Ok((job, pi.hProcess))
    }
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
            // Trailing backslashes precede the closing quote: double them.
            for _ in 0..backslashes * 2 {
                out.push('\\');
            }
        } else if chars[i] == '"' {
            // Backslashes before a quote are doubled, then the quote is escaped.
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
