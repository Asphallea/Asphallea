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

    /// Whether the policy asks for filesystem containment at all.
    ///
    /// A policy with no read and no write prefixes has not requested filesystem
    /// restriction, and the core must not impose one. Landlock is an allowlist:
    /// activating it for such a policy would deny everything outside the baseline
    /// system paths, including the user's home directory, which the policy never
    /// asked to restrict. The SDK draws the same distinction on the Python side
    /// (`requires_fs = bool(policy.read_paths or policy.write_paths)`); this keeps
    /// the two layers agreeing on what a policy means.
    pub fn filesystem_restricted(&self) -> bool {
        !self.filesystem.read.is_empty() || !self.filesystem.write.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_from(json: &str) -> Policy {
        serde_json::from_str(json).expect("policy parses")
    }

    #[test]
    fn empty_filesystem_is_not_a_restriction() {
        // The case that caused the 0.1.0 bug: no paths means no filesystem
        // containment was requested, so the core must not impose one.
        let p = policy_from(r#"{"name":"network-only","network":"deny"}"#);
        assert!(!p.filesystem_restricted());
        assert!(p.network_denied());
    }

    #[test]
    fn read_paths_alone_are_a_restriction() {
        let p = policy_from(r#"{"name":"r","filesystem":{"read":["/ws"],"write":[]}}"#);
        assert!(p.filesystem_restricted());
    }

    #[test]
    fn write_paths_alone_are_a_restriction() {
        let p = policy_from(r#"{"name":"w","filesystem":{"read":[],"write":["/out"]}}"#);
        assert!(p.filesystem_restricted());
    }

    #[test]
    fn network_defaults_to_denied_when_unspecified() {
        let p = policy_from(r#"{"name":"bare"}"#);
        assert!(p.network_denied());
        assert!(!p.filesystem_restricted());
    }
}
