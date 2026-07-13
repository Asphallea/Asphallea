//! Structured reports the core writes back to the Python SDK.
//!
//! Before it execs the sandboxed command, the launcher writes a [`Report`] to the
//! path given on `--report`. The SDK reads it and folds the applied controls into
//! the audit trail. The [`Probe`] is what `--probe` prints so the SDK can build an
//! honest capability matrix from the live kernel.

use serde::Serialize;

/// What the launcher actually applied to the sandboxed process.
#[derive(Debug, Serialize, Default)]
pub struct Report {
    /// True when filesystem and syscall enforcement are both in effect.
    pub contained: bool,
    /// The OS name, always `"linux"` here.
    pub platform: String,
    /// Landlock outcome: `fully_enforced`, `partially_enforced`, `not_enforced`,
    /// or `unsupported`.
    pub landlock_status: String,
    /// The Landlock ABI version the kernel reported, or 0.
    pub landlock_abi: i64,
    /// Whether the seccomp filter was installed.
    pub seccomp_applied: bool,
    /// How many syscall rules the filter carried.
    pub seccomp_rules: usize,
    /// A short description of the network decision and how it was enforced.
    pub network: String,
    /// Whether a network namespace was successfully created.
    pub net_namespace: bool,
    /// The resource limits that were set, for example `"RLIMIT_AS=268435456"`.
    pub rlimits: Vec<String>,
    /// Any degradations or skipped controls, in plain language.
    pub warnings: Vec<String>,
}

/// The capability probe printed by `--probe`.
#[derive(Debug, Serialize)]
pub struct Probe {
    /// The core binary version.
    pub version: String,
    /// The OS name.
    pub platform: String,
    /// The Landlock ABI the kernel supports, or 0.
    pub landlock_abi: i64,
    /// Whether seccomp-bpf is available.
    pub seccomp: bool,
    /// Whether unprivileged user namespaces are available.
    pub user_namespaces: bool,
    /// Whether network-namespace isolation is available (tracks user namespaces).
    pub net_namespaces: bool,
}
