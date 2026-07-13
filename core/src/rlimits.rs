//! Resource limits via `setrlimit`.
//!
//! These are the cheapest and most portable containment control. They cap CPU
//! time, address space, file size, process count, and open descriptors, so a
//! runaway or malicious command cannot exhaust the host. Limits are inherited
//! across `execve` and by every child, so the whole sandboxed tree is bounded.

use crate::policy::Limits;
use crate::report::Report;
use nix::sys::resource::{setrlimit, Resource};

/// Apply every limit set in the policy, recording successes and failures.
pub fn apply(limits: &Limits, report: &mut Report) {
    if let Some(v) = limits.cpu_seconds {
        set(Resource::RLIMIT_CPU, v, "RLIMIT_CPU", report);
    }
    if let Some(v) = limits.memory_bytes {
        set(Resource::RLIMIT_AS, v, "RLIMIT_AS", report);
    }
    if let Some(v) = limits.max_file_size_bytes {
        set(Resource::RLIMIT_FSIZE, v, "RLIMIT_FSIZE", report);
    }
    if let Some(v) = limits.max_processes {
        set(Resource::RLIMIT_NPROC, v, "RLIMIT_NPROC", report);
    }
    if let Some(v) = limits.max_open_files {
        set(Resource::RLIMIT_NOFILE, v, "RLIMIT_NOFILE", report);
    }
}

fn set(resource: Resource, value: u64, name: &str, report: &mut Report) {
    match setrlimit(resource, value, value) {
        Ok(()) => report.rlimits.push(format!("{name}={value}")),
        Err(e) => report
            .warnings
            .push(format!("{name} could not be set: {e}")),
    }
}
