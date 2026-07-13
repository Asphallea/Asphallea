//! The containment-relevant slice of an Asphallea policy.
//!
//! The Python SDK serializes only the parts the OS enforcement needs into JSON
//! and passes it on `--policy`. Tool allowlists, rate limits, and spend caps are
//! enforced by the Python policy tier and never reach the core.

use serde::Deserialize;

/// The filesystem, network, and resource-limit portion of a policy.
#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    /// The policy name, for diagnostics.
    #[serde(default)]
    pub name: String,
    /// Filesystem read and write allowlists.
    #[serde(default)]
    pub filesystem: Filesystem,
    /// Network decision: `"deny"` or `"allow"`.
    #[serde(default = "default_network")]
    pub network: String,
    /// OS resource limits.
    #[serde(default)]
    pub limits: Limits,
}

/// Filesystem allowlists. Paths are absolute and normalized by the SDK.
#[derive(Debug, Deserialize, Default)]
pub struct Filesystem {
    /// Prefixes the sandboxed process may read.
    #[serde(default)]
    pub read: Vec<String>,
    /// Prefixes the sandboxed process may write. Write also grants read.
    #[serde(default)]
    pub write: Vec<String>,
}

/// OS resource limits, in bytes and counts and seconds.
#[derive(Debug, Deserialize, Default)]
pub struct Limits {
    /// RLIMIT_CPU, in seconds of CPU time.
    pub cpu_seconds: Option<u64>,
    /// RLIMIT_AS, in bytes of address space.
    pub memory_bytes: Option<u64>,
    /// RLIMIT_FSIZE, in bytes, the largest file the process may create.
    pub max_file_size_bytes: Option<u64>,
    /// RLIMIT_NPROC, the number of processes/threads.
    pub max_processes: Option<u64>,
    /// RLIMIT_NOFILE, the number of open file descriptors.
    pub max_open_files: Option<u64>,
}

fn default_network() -> String {
    "deny".to_string()
}

impl Policy {
    /// Whether the policy denies network access.
    pub fn network_denied(&self) -> bool {
        self.network == "deny"
    }
}
