//! Best-effort network isolation via an unprivileged network namespace.
//!
//! When the policy denies network, the launcher tries to move the process into a
//! fresh network namespace that has only a down loopback interface, so there is
//! no route to anywhere. This needs unprivileged user namespaces, which some
//! hardened kernels disable. When it is unavailable the process still has no
//! network, because the seccomp filter blocks IP socket creation. The namespace
//! is defense in depth on top of that syscall block, not the sole guarantee.

use crate::report::Report;
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, getgid, getuid, ForkResult};
use std::fs;

/// Try to enter a new user and network namespace. Records the outcome.
pub fn apply(report: &mut Report) {
    // Capture identity before unshare; afterward getuid reports the overflow uid
    // until the maps are written.
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    match unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET) {
        Ok(()) => {
            // Establish an identity map so the command keeps its own uid and gid.
            let _ = fs::write("/proc/self/setgroups", "deny");
            let _ = fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"));
            let _ = fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"));
            report.net_namespace = true;
            report.network = "denied (network namespace + seccomp socket block)".to_string();
        }
        Err(e) => {
            report.net_namespace = false;
            report.network = "denied (seccomp socket block)".to_string();
            report.warnings.push(format!(
                "network namespace unavailable ({e}); network is still denied by the seccomp socket block"
            ));
        }
    }
}

/// Probe whether unprivileged user namespaces are available, without disturbing
/// this process. Forks a child that attempts the unshare and reports its result.
pub fn userns_supported() -> bool {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let ok = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        Ok(ForkResult::Parent { child }) => {
            matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
        }
        Err(_) => false,
    }
}
