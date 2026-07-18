//! macOS containment via the Seatbelt sandbox.
//!
//! macOS enforces per-process sandboxing with Seatbelt, driven by a profile in the
//! Sandbox Profile Language (SBPL). The launcher generates a deny-by-default
//! profile that allows reading the system directories a program needs to load and
//! run, allows the policy's read and write paths, and denies everything else,
//! including network unless the policy allows it. It then runs the command under
//! that profile with `sandbox-exec`, which is present on every macOS.
//!
//! The profile is inherited by the command and everything it spawns. Resource
//! limits are not expressed by Seatbelt; the Job Object / rlimit equivalents are a
//! follow-up. Process termination is handled by the parent (the SDK kills the
//! process group on a wall-clock timeout).

use crate::policy::Policy;
use crate::report::Report;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// System locations a program needs to load and run (dylibs, the dyld cache,
/// config). Reading these leaks no user data; the user's home and other files
/// outside the policy allowlist stay denied by the deny-default profile.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/System",
    // On Apple Silicon the dyld shared cache lives only in the OS cryptex, on the
    // Preboot volume mounted here — not under /System/Library/dyld, which does not
    // exist. This is a separate volume, so a (subpath "/System") rule does not
    // cover it; without an explicit rule dyld cannot map the cache and every
    // sandboxed process aborts (SIGABRT) before it runs.
    "/System/Volumes/Preboot/Cryptexes",
    "/Library",
    "/bin",
    "/sbin",
    "/dev",
    "/etc",
    "/private/etc",
    "/private/var/db",
    "/private/var/folders",
    "/opt",
    "/Applications",
];

/// Whether Seatbelt can be applied on this host.
pub fn available() -> bool {
    Path::new(SANDBOX_EXEC).exists()
}

/// Run `command` under a Seatbelt profile derived from `policy`.
pub fn run(
    policy: &Policy,
    command: &[String],
    report: &mut Report,
    report_path: &Option<String>,
) -> i32 {
    if !available() {
        report.contained = false;
        report
            .warnings
            .push("sandbox-exec not found; cannot apply Seatbelt".to_string());
        write_report(report_path, report);
        eprintln!("asphallea-run: sandbox-exec not available; refusing to run uncontained.");
        return 3;
    }

    // The sandboxed process inherits stdout/stderr, but under a deny-default
    // profile those pipes have no filesystem path to grant, so its output would be
    // lost. Route output through files in an allowlisted capture directory (files
    // have paths the profile can grant), then forward them afterward.
    let capture = std::env::temp_dir().join(format!("asphallea-cap-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&capture);
    let capture = std::fs::canonicalize(&capture).unwrap_or(capture);
    let out_path = capture.join("stdout");
    let err_path = capture.join("stderr");

    let profile = build_profile(policy, &[capture.to_string_lossy().as_ref()]);
    report.network = if policy.network_denied() {
        "denied (Seatbelt profile)".to_string()
    } else {
        "allowed".to_string()
    };
    report.rlimits.push("seatbelt_profile=applied".to_string());
    report.contained = true;
    // The command runs as a child, so the report is safe to write now.
    write_report(report_path, report);

    let (out_file, err_file) = match (
        std::fs::File::create(&out_path),
        std::fs::File::create(&err_path),
    ) {
        (Ok(o), Ok(e)) => (o, e),
        _ => {
            eprintln!("asphallea-run: could not open capture files under {capture:?}");
            let _ = std::fs::remove_dir_all(&capture);
            return 127;
        }
    };

    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-p").arg(&profile).arg("--");
    for arg in command {
        cmd.arg(arg);
    }
    cmd.stdout(Stdio::from(out_file));
    cmd.stderr(Stdio::from(err_file));

    let code = match cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("asphallea-run: could not launch sandbox-exec: {e}");
            127
        }
    };

    // Forward the captured output to our own streams, which the SDK reads.
    if let Ok(bytes) = std::fs::read(&out_path) {
        let _ = std::io::stdout().write_all(&bytes);
        let _ = std::io::stdout().flush();
    }
    if let Ok(bytes) = std::fs::read(&err_path) {
        let _ = std::io::stderr().write_all(&bytes);
        let _ = std::io::stderr().flush();
    }
    let _ = std::fs::remove_dir_all(&capture);
    code
}

fn build_profile(policy: &Policy, extra_writes: &[&str]) -> String {
    let mut p = String::new();
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");
    // Let programs run: exec/fork, mach services, sysctl reads, metadata, ioctl.
    p.push_str("(allow process*)\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow mach*)\n");
    p.push_str("(allow signal (target self))\n");
    p.push_str("(allow file-read-metadata)\n");
    p.push_str("(allow file-ioctl)\n");
    // The standard streams the process inherited (stdout, stderr, stdin) are pipes
    // or sockets with no filesystem path, so a command's output would be lost under
    // deny-default. Allow data read/write on objects that are not under the
    // filesystem root; regular files keep their path and stay governed by the
    // allowlists below.
    p.push_str("(allow file-read-data file-write-data (require-not (subpath \"/\")))\n");

    // file-map-executable (macOS 11+) governs mmap(PROT_EXEC). dyld needs it to map
    // the shared cache and dylibs, but the cache lives in an OS cryptex whose vnode
    // path Seatbelt does not match by any name we can write, so a subpath rule never
    // grants it and the process aborts (SIGABRT) on load. Allow it unrestricted: it
    // only permits mapping already-open files as executable, and opening is still
    // gated by the file-read* allowlist below, so data outside the policy paths stays
    // unreadable (you cannot map what you cannot open).
    p.push_str("(allow file-map-executable)\n");

    for base in SYSTEM_READ {
        p.push_str(&format!(
            "(allow file-read* (subpath {}))\n",
            sbpl_string(base)
        ));
    }
    for path in &policy.filesystem.read {
        p.push_str(&format!(
            "(allow file-read* (subpath {}))\n",
            sbpl_string(path)
        ));
    }
    for path in &policy.filesystem.write {
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath {}))\n",
            sbpl_string(path)
        ));
    }
    // The stdout/stderr capture directory (see run) is writable so the command's
    // output can be persisted and forwarded.
    for path in extra_writes {
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath {}))\n",
            sbpl_string(path)
        ));
    }
    if !policy.network_denied() {
        p.push_str("(allow network*)\n");
    }
    p
}

/// Format a path as an SBPL string literal (double-quoted, backslash and quote
/// escaped).
fn sbpl_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn write_report(report_path: &Option<String>, report: &Report) {
    if let Some(p) = report_path {
        if let Ok(text) = serde_json::to_string(report) {
            let _ = std::fs::write(p, text);
        }
    }
}
