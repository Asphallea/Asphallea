//! Syscall and network-family filtering via seccomp-bpf.
//!
//! This is a denylist: everything is allowed except a fixed set of syscalls that
//! a normal command never needs and that a hijacked one would use to escape the
//! sandbox, tamper with the host, or read other processes. A denylist is the
//! robust choice for running arbitrary commands, where a strict allowlist would
//! break ordinary programs.
//!
//! When the policy denies network, the filter also blocks creation of IP and
//! packet sockets while leaving local `AF_UNIX` sockets alone. That is an
//! unprivileged, airtight block on outbound network at the syscall layer, so it
//! holds even where a network namespace could not be created.
//!
//! The filter is installed last, just before `execve`, and is inherited by the
//! command and everything it spawns.

use crate::report::Report;
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;
use std::convert::TryInto;

/// Whether the kernel supports seccomp-bpf.
pub fn supported() -> bool {
    // PR_GET_SECCOMP returns the current mode (>= 0) when seccomp is compiled in,
    // and -1 with EINVAL when it is not.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
}

/// Build and install the seccomp filter. Returns whether it was applied.
pub fn apply(network_denied: bool, report: &mut Report) -> bool {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Escape, privilege, and host-tampering syscalls. An empty rule vector means
    // the syscall matches unconditionally and gets the match action (deny).
    let deny: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        libc::SYS_acct,
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_syslog,
        libc::SYS_quotactl,
        libc::SYS_mknodat,
    ];
    for &nr in deny {
        rules.entry(nr).or_default();
    }

    // `mknod` exists only on some architectures (x86_64). `mknodat` above covers
    // the modern path on all of them.
    #[cfg(target_arch = "x86_64")]
    {
        rules.entry(libc::SYS_mknod).or_default();
    }

    if network_denied {
        // socket(domain, type, protocol): arg 0 is the address family. Deny IP and
        // packet families; leave AF_UNIX (local IPC) alone.
        let deny_family = |family: u64| -> SeccompRule {
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                family,
            )
            .expect("valid seccomp condition")])
            .expect("valid seccomp rule")
        };
        rules.insert(
            libc::SYS_socket,
            vec![
                deny_family(libc::AF_INET as u64),
                deny_family(libc::AF_INET6 as u64),
                deny_family(libc::AF_PACKET as u64),
            ],
        );
    }

    let rule_count = rules.len();

    let filter = match SeccompFilter::new(
        rules,
        SeccompAction::Allow, // mismatch: allow anything not listed
        SeccompAction::Errno(libc::EPERM as u32), // match: deny with EPERM
        std::env::consts::ARCH
            .try_into()
            .expect("supported target arch"),
    ) {
        Ok(f) => f,
        Err(e) => {
            report.warnings.push(format!("seccomp build error: {e}"));
            return false;
        }
    };

    let program: BpfProgram = match filter.try_into() {
        Ok(p) => p,
        Err(e) => {
            report.warnings.push(format!("seccomp compile error: {e}"));
            return false;
        }
    };

    match apply_filter(&program) {
        Ok(()) => {
            report.seccomp_applied = true;
            report.seccomp_rules = rule_count;
            true
        }
        Err(e) => {
            report.warnings.push(format!("seccomp apply error: {e}"));
            false
        }
    }
}
