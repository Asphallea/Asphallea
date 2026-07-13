# asphallea-core

The OS-level containment launcher for [Asphallea](../README.md). This crate builds
`asphallea-run`, a small binary the Python SDK invokes for high-blast-radius tools.

It applies containment to itself and then execs the target command, so the
restrictions are inherited by the command and everything it spawns. The agent that
launched it is never restricted.

## What it enforces (Linux)

- **Filesystem allowlist** with the Landlock LSM. Read and write are confined to
  the policy's allowed paths. A baseline of system directories is granted read and
  execute so ordinary programs run.
- **Syscall and network filtering** with seccomp-bpf. A denylist blocks escape and
  host-tampering syscalls. When the policy denies network, IP and packet socket
  creation is blocked at the syscall layer.
- **Resource limits** with setrlimit: CPU time, address space, file size, process
  count, open descriptors.
- **Network namespace** isolation, best effort, on top of the syscall block.

## Build

```sh
cargo build --release
# binary at target/release/asphallea-run
```

Put it on `PATH`, or point the SDK at it with `ASPHALLEA_CORE_BIN`.

## Requirements

- Linux kernel 5.13 or newer for Landlock.
- seccomp-bpf (standard on modern kernels).
- Unprivileged user namespaces for the network namespace layer (optional; the
  seccomp socket block denies network regardless).

On macOS and Windows the crate still builds, but the binary reports that
containment is unavailable and refuses to pretend otherwise.

## Interface

```sh
asphallea-run --policy policy.json [--report report.json] [--strict] -- CMD [ARGS...]
asphallea-run --probe   # print kernel capability JSON
```

`--strict` makes the launcher fail closed: if filesystem or syscall containment
cannot be applied, it refuses to run the command instead of running it exposed.

Licensed under Apache-2.0.
