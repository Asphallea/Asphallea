//! asphallea-run: the OS containment launcher.
//!
//! This binary is invoked by the Asphallea Python SDK for high-blast-radius tools
//! (shells, code execution, spawned processes). It applies containment to itself
//! and then execs the target command, so the restrictions are inherited by the
//! command and everything it spawns, while the agent that launched it is never
//! affected.
//!
//! Order matters: no_new_privs, then resource limits, then the network namespace,
//! then the Landlock filesystem allowlist, then the seccomp syscall filter, then
//! exec. Landlock is applied before seccomp so the filter never blocks the calls
//! Landlock needs, and the filter leaves `execve` allowed.
//!
//! Usage:
//!   asphallea-run --policy <file.json> [--report <file.json>] [--strict] -- CMD [ARGS...]
//!   asphallea-run --probe        # print kernel capability JSON and exit
//!
//! Exit codes: 2 usage error, 3 containment unavailable under --strict, 127 exec
//! failure. On success the process image is replaced by CMD, so this binary does
//! not return.

#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod netns;
#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
mod report;
#[cfg(target_os = "linux")]
mod rlimits;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
fn main() {
    use report::Report;
    use std::ffi::CString;
    use std::process::exit;

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--probe") {
        print_probe();
        return;
    }

    // Parse arguments up to the `--` command separator.
    let mut policy_path: Option<String> = None;
    let mut report_path: Option<String> = None;
    let mut strict = false;
    let mut command: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = args.get(i).cloned();
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).cloned();
            }
            "--strict" => strict = true,
            "--allow-degraded" => {} // accepted for symmetry; --strict is the gate
            "--" => {
                command = args.get(i + 1..).map(|s| s.to_vec()).unwrap_or_default();
                break;
            }
            other => {
                eprintln!("asphallea-run: unexpected argument: {other}");
                exit(2);
            }
        }
        i += 1;
    }

    let policy_path = policy_path.unwrap_or_else(|| {
        eprintln!("asphallea-run: --policy <file> is required");
        exit(2);
    });
    if command.is_empty() {
        eprintln!("asphallea-run: no command given after --");
        exit(2);
    }

    let text = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| {
        eprintln!("asphallea-run: cannot read policy {policy_path}: {e}");
        exit(2);
    });
    let policy: policy::Policy = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("asphallea-run: cannot parse policy: {e}");
        exit(2);
    });

    let mut report = Report {
        platform: "linux".to_string(),
        ..Default::default()
    };
    report.network = if policy.network_denied() {
        "denied".to_string()
    } else {
        "allowed".to_string()
    };

    // 1. no_new_privs: required for unprivileged Landlock and seccomp.
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        report
            .warnings
            .push(format!("could not set no_new_privs: {e}"));
    }

    // 2. resource limits.
    rlimits::apply(&policy.limits, &mut report);

    // 3. network namespace, best effort, when the policy denies network.
    if policy.network_denied() {
        netns::apply(&mut report);
    }

    // 4. filesystem allowlist.
    landlock_fs::apply(&policy, &mut report);
    if strict && report.landlock_status == "not_enforced" {
        report.contained = false;
        write_report(&report_path, &report);
        eprintln!(
            "asphallea-run: filesystem containment could not be enforced and --strict is set. \
             Refusing to run uncontained."
        );
        exit(3);
    }

    // 5. seccomp syscall and network filter, installed last.
    let seccomp_ok = seccomp::apply(policy.network_denied(), &mut report);
    if strict && !seccomp_ok {
        report.contained = false;
        write_report(&report_path, &report);
        eprintln!(
            "asphallea-run: syscall filtering could not be applied and --strict is set. \
             Refusing to run uncontained."
        );
        exit(3);
    }

    report.contained = report.landlock_status != "not_enforced"
        && report.landlock_status != "unsupported"
        && report.seccomp_applied;

    // 6. persist the report before exec. The fd closes on exec, but the bytes are
    // already flushed to disk.
    write_report(&report_path, &report);

    // 7. exec the command. Landlock, seccomp, rlimits, and namespaces are all
    // inherited across execve, so the command runs contained.
    let prog = CString::new(command[0].as_bytes()).unwrap_or_else(|_| {
        eprintln!("asphallea-run: invalid command name");
        exit(2);
    });
    let cargs: Vec<CString> = command
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    let err = nix::unistd::execvp(&prog, &cargs).unwrap_err();
    eprintln!("asphallea-run: could not exec {}: {}", command[0], err);
    exit(127);
}

#[cfg(target_os = "linux")]
fn write_report(path: &Option<String>, report: &report::Report) {
    if let Some(p) = path {
        if let Ok(text) = serde_json::to_string(report) {
            let _ = std::fs::write(p, text);
        }
    }
}

#[cfg(target_os = "linux")]
fn print_probe() {
    let userns = netns::userns_supported();
    let probe = report::Probe {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: "linux".to_string(),
        landlock_abi: landlock_fs::abi_version(),
        seccomp: seccomp::supported(),
        user_namespaces: userns,
        net_namespaces: userns,
    };
    println!(
        "{}",
        serde_json::to_string(&probe).unwrap_or_else(|_| "{}".to_string())
    );
}

// The containment tier is Linux only. The SDK never invokes this binary off
// Linux, but if someone does, be explicit rather than pretend containment.
#[cfg(not(target_os = "linux"))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--probe") {
        println!(
            "{{\"version\":\"{}\",\"platform\":\"{}\",\"landlock_abi\":0,\"seccomp\":false,\"user_namespaces\":false,\"net_namespaces\":false}}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        );
        return;
    }
    eprintln!(
        "asphallea-run: OS containment is available on Linux only; this host is {}.",
        std::env::consts::OS
    );
    std::process::exit(3);
}
