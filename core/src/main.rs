//! asphallea-run: the OS containment launcher.
//!
//! Invoked by the Asphallea Python SDK for high-blast-radius tools (shells, code
//! execution, spawned processes). It applies containment and then runs the target
//! command, so the restrictions cover the command and everything it spawns, while
//! the agent that launched it is never affected.
//!
//! Each OS uses its own containment engine:
//!
//! - Linux: Landlock filesystem allowlist, seccomp-bpf syscall and network filter,
//!   resource limits, network namespace. The launcher applies these to itself and
//!   execs the command, which inherits them.
//! - Windows: a Job Object that bounds memory, CPU time, and process count, and
//!   guarantees the whole process tree is killed on close. Filesystem and network
//!   allowlisting (AppContainer) are the next layer.
//! - Other (macOS today): no engine yet, reported honestly.
//!
//! Usage:
//!   asphallea-run --policy <file.json> [--report <file.json>] [--strict] -- CMD [ARGS...]
//!   asphallea-run --probe        # print kernel/OS capability JSON and exit

// Some policy and report fields are read only by a subset of the OS backends.
// They are part of the wire format, so allow dead_code across platforms.
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[allow(dead_code)]
mod policy;
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[allow(dead_code)]
mod report;

#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod netns;
#[cfg(target_os = "linux")]
mod rlimits;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "windows")]
mod win_appcontainer;
#[cfg(target_os = "windows")]
mod win_contain;

/// A parsed command invocation, shared by the OS backends.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct Invocation {
    policy_path: String,
    report_path: Option<String>,
    // Read by the Linux backend; the Windows Job Object backend always applies.
    #[allow(dead_code)]
    strict: bool,
    command: Vec<String>,
}

/// Parse the CLI up to the `--` separator. Returns `Err(exit_code)` on a usage
/// error, after printing a message.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_invocation(args: &[String]) -> Result<Invocation, i32> {
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
            "--allow-degraded" => {}
            "--" => {
                command = args.get(i + 1..).map(|s| s.to_vec()).unwrap_or_default();
                break;
            }
            other => {
                eprintln!("asphallea-run: unexpected argument: {other}");
                return Err(2);
            }
        }
        i += 1;
    }
    let policy_path = match policy_path {
        Some(p) => p,
        None => {
            eprintln!("asphallea-run: --policy <file> is required");
            return Err(2);
        }
    };
    if command.is_empty() {
        eprintln!("asphallea-run: no command given after --");
        return Err(2);
    }
    Ok(Invocation {
        policy_path,
        report_path,
        strict,
        command,
    })
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn load_policy(path: &str) -> policy::Policy {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("asphallea-run: cannot read policy {path}: {e}");
        std::process::exit(2);
    });
    serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("asphallea-run: cannot parse policy: {e}");
        std::process::exit(2);
    })
}

// ---------------------------------------------------------------- Linux engine

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

    let inv = parse_invocation(&args).unwrap_or_else(|c| exit(c));
    let policy = load_policy(&inv.policy_path);
    let strict = inv.strict;

    let mut report = Report {
        platform: "linux".to_string(),
        backend: "linux-landlock-seccomp".to_string(),
        policy: policy.name.clone(),
        ..Default::default()
    };
    report.network = if policy.network_denied() {
        "denied".to_string()
    } else {
        "allowed".to_string()
    };

    // Open the report file now, before Landlock restricts the filesystem. Landlock
    // governs open(2), not writes to an already-open descriptor, so opening here
    // lets us still write the report after restrict_self even though the report
    // path typically sits outside the write allowlist.
    let mut report_file: Option<std::fs::File> = inv.report_path.as_ref().and_then(|p| {
        std::fs::File::create(p)
            .map_err(|e| eprintln!("asphallea-run: cannot open report {p}: {e}"))
            .ok()
    });

    // 1. no_new_privs: required for unprivileged Landlock and seccomp.
    let nnp = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if nnp != 0 {
        report
            .warnings
            .push("could not set no_new_privs".to_string());
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
        flush_report(&mut report_file, &report);
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
        flush_report(&mut report_file, &report);
        eprintln!(
            "asphallea-run: syscall filtering could not be applied and --strict is set. \
             Refusing to run uncontained."
        );
        exit(3);
    }

    report.contained = report.landlock_status != "not_enforced"
        && report.landlock_status != "unsupported"
        && report.seccomp_applied;

    // 6. write the report through the descriptor opened before Landlock, then exec.
    flush_report(&mut report_file, &report);

    let prog = CString::new(inv.command[0].as_bytes()).unwrap_or_else(|_| {
        eprintln!("asphallea-run: invalid command name");
        exit(2);
    });
    let cargs: Vec<CString> = inv
        .command
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    let err = nix::unistd::execvp(&prog, &cargs).unwrap_err();
    eprintln!("asphallea-run: could not exec {}: {}", inv.command[0], err);
    exit(127);
}

#[cfg(target_os = "linux")]
fn flush_report(file: &mut Option<std::fs::File>, report: &report::Report) {
    use std::io::Write;
    if let Some(f) = file {
        if let Ok(text) = serde_json::to_string(report) {
            let _ = f.write_all(text.as_bytes());
            let _ = f.flush();
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

// -------------------------------------------------------------- Windows engine

#[cfg(target_os = "windows")]
fn main() {
    use report::Report;
    use std::process::exit;

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--probe") {
        print_probe_windows();
        return;
    }

    let inv = parse_invocation(&args).unwrap_or_else(|c| exit(c));
    let policy = load_policy(&inv.policy_path);

    let mut report = Report {
        platform: "windows".to_string(),
        backend: "windows-appcontainer-job".to_string(),
        policy: policy.name.clone(),
        ..Default::default()
    };

    let code = win_contain::run(&policy, &inv.command, &mut report, &inv.report_path);
    exit(code);
}

#[cfg(target_os = "windows")]
fn print_probe_windows() {
    // AppContainer (filesystem + network) is available on Windows 8+, which is
    // every supported Windows. Job Objects give resources and termination.
    println!(
        "{{\"version\":\"{}\",\"platform\":\"windows\",\"backend\":\"windows-appcontainer-job\",\
         \"resource_limits\":true,\"process_kill\":true,\"filesystem_sandbox\":true,\
         \"network_sandbox\":true}}",
        env!("CARGO_PKG_VERSION")
    );
}

// ----------------------------------------------------- Other platforms (macOS)

// No containment engine yet on this OS. The SDK never invokes this binary here,
// but if someone does, be explicit rather than pretend containment.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--probe") {
        println!(
            "{{\"version\":\"{}\",\"platform\":\"{}\",\"backend\":\"none\",\"resource_limits\":false,\"process_kill\":false,\"filesystem_sandbox\":false,\"network_sandbox\":false}}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        );
        return;
    }
    eprintln!(
        "asphallea-run: no OS containment engine for {} yet (macOS Seatbelt is planned).",
        std::env::consts::OS
    );
    std::process::exit(3);
}
