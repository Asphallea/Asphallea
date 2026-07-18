# Asphallea v0 build plan

A security runtime that contains what your AI agent can do. This plan records the
architecture decisions for the v0 enforce-mode build and the order I build in. It
is deliberately tight. The brief made the product decisions. This file records the
engineering "how".

## 1. What v0 is

Enforce mode only. Two tiers around the tool-execution boundary.

- **Policy tier.** Cross platform. Pure Python. Every tool call is intercepted,
  evaluated against a declarative policy, allowed or denied deterministically, and
  written to an append-only audit log. Works on Linux, macOS, Windows.
- **Containment tier.** Linux first. Real OS enforcement in Rust. For tools that
  spawn processes, execute code, or run a shell, we contain the spawned process
  with Landlock (filesystem allowlist), seccomp-bpf (syscall and network-family
  filtering), resource limits (setrlimit), and best-effort network namespace
  isolation. This is the moat. It is not a Python `if` statement.

No observe mode. No ML. No dashboard. No dollar metering. We contain actions. We do
not judge text.

## 2. The decision the brief left open: Rust core delivery

**Chosen: standalone Rust binary invoked over subprocess for v0. PyO3 later.**

This is not only the safe ship, it is the architecturally correct model. Reasoning:

1. **Containment contains a separate process by nature.** Landlock and seccomp are
   one-way ratchets. Once applied they are inherited by every descendant and cannot
   be relaxed. The thing we want to contain is the process that runs the shell
   command or the model-written code, not the long-lived Python agent. The natural
   shape is a launcher that applies the restrictions to itself and then `execve`s
   the target command. That launcher is a small CLI binary. In-process PyO3 would
   have to `fork` from inside the interpreter to get a separate victim process
   anyway.
2. **fork inside a threaded or async interpreter is a hazard.** Real agents run
   event loops and thread pools. Forking that process to set up a sandbox invites
   deadlocks in the child. A separate `posix_spawn`/`subprocess` of a clean binary
   sidesteps the whole class of bug.
3. **Zero build coupling for the common path.** `pip install .` installs a pure
   Python package with no Rust toolchain required. The policy tier works
   immediately on every platform. The containment binary is built separately with
   `cargo build --release` and discovered on `PATH` or via `ASPHALLEA_CORE_BIN`.
   A developer who only wants the policy tier never touches Rust.
4. **The overhead does not matter.** These are high-blast-radius tools that spawn
   processes anyway. One extra `execve` of a tiny launcher is noise next to running
   a shell.
5. **The Python API does not change when PyO3 lands.** `asphallea/sandbox.py`
   abstracts the invocation. Swapping subprocess for an in-process binding later is
   an internal change.

Trade accepted: a subprocess boundary and JSON marshalling of the policy. Both are
cheap and both are easy to replace.

## 3. Enforcement primitives per tool class

| Tool class | What it is | Policy tier check | Containment tier (Linux) |
|---|---|---|---|
| Pure callable | Python function tool (search, read_file, an API client) | tool allowlist, declared path args vs fs allowlist, network flag, call count, rate, spend cap, wall-clock timeout | not applicable, stays in-process |
| Subprocess / shell / code exec | runs `bash -c ...`, spawns a binary, executes generated code | tool allowlist gate, then hand to containment | Landlock fs allowlist, seccomp denylist + socket-family block, setrlimit (CPU, address space, file size, nproc, nofile), best-effort user+net namespace, parent-side wall-clock kill |

Deterministic evaluation order in the engine. Deny wins. First failing rule is the
one recorded in the audit line:

1. tool allowlist (default deny for unlisted tools)
2. filesystem read paths (declared read args must sit under an allowed prefix)
3. filesystem write paths (declared write args must sit under an allowed prefix)
4. network (a tool marked network-using is denied when the policy denies network)
5. per-tool max call count
6. per-tool rate limit (sliding window)
7. spend cap (max invocations of a named paid tool)
8. allow

Wall-clock timeout is enforced around execution, not as a pre-check. Policy-tier
timeout uses a worker thread with a join deadline and is documented as best effort
because a pure Python callable cannot be force killed. Containment-tier timeout is a
hard kill of the process group by the parent, backed by an RLIMIT_CPU ceiling.

### Containment ordering (matters for correctness)

`PR_SET_NO_NEW_PRIVS` -> `setrlimit` -> namespace setup (best effort) -> Landlock
`restrict_self` -> install seccomp filter -> `execve`. Landlock is applied before
seccomp because the seccomp filter must not block the syscalls Landlock needs, and
the filter is a denylist that leaves `execve` and ordinary file IO allowed.

Network deny in v0 is enforced primarily at the syscall layer: seccomp returns
`EPERM` for `socket(AF_INET|AF_INET6|...)` while allowing `AF_UNIX`. This is
unprivileged and airtight for outbound sockets. A user+network namespace is also
attempted as defense in depth when unprivileged user namespaces are available.
Per-host allowlisting (a filtering proxy or configured netns) is fast-follow.

## 4. Cross-platform degradation strategy

Honesty is the product. We detect capability at runtime and never claim containment
we do not deliver.

- **Policy tier** behaves identically on all three platforms. Deterministic.
- **Containment tier** probes the core binary (`asphallea-run --probe`) which reports
  Landlock ABI, seccomp support, and namespace support as JSON. `sandbox.run`:
  - On Linux with the controls present: contains, records which controls were
    applied, runs the command.
  - When a required control is missing (no binary, non-Linux, kernel too old): the
    default is **fail closed**. The call is denied, logged, and a loud, specific
    warning explains what is missing and how to get it. The developer can opt into
    `allow_degraded=True` to run without OS containment, which logs the degradation
    on every call so it can never pass silently.
- The README carries an explicit platform matrix. No green checks we cannot back up.

## 5. Public Python API (the five-minute surface)

```python
from asphallea import Policy, guard, AuditLog, PolicyViolation, sandbox

policy = (
    Policy.builder("least-privilege")
    .allow_tools("search", "read_file", "run_shell")
    .read_paths("./workspace")
    .write_paths("./workspace/out")
    .deny_network()
    .max_calls("search", 10)
    .rate_limit("search", per_minute=30)
    .timeout(seconds=30)
    .spend_cap("paid_api", max_calls=5)
    .build()
)
# or: policy = Policy.from_yaml("policies/example.yaml")

audit = AuditLog("audit.jsonl")

@guard(policy, tool="read_file", reads="path", audit=audit)
def read_file(path: str) -> str: ...

result = sandbox.run(["bash", "-c", cmd], policy=policy, tool="run_shell", audit=audit)
```

## 6. Build order (file by file)

1. `PLAN.md` (this), `LICENSE` (Apache-2.0), `pyproject.toml`, `.gitignore`
2. `asphallea/policy.py` model, builder, YAML loader
3. `asphallea/audit.py` JSONL sink, redaction hook
4. `asphallea/engine.py` deterministic evaluation, counters, rate, spend
5. `asphallea/guard.py` decorator and generic callable wrapper
6. `asphallea/sandbox.py` containment entrypoint, capability probe, degradation
7. `asphallea/__init__.py` public exports
8. `asphallea/integrations/langchain.py` duck-typed LangChain/LangGraph adapter
9. `core/` Rust crate: `Cargo.toml`, `main.rs`, `policy.rs`, `landlock.rs`,
   `seccomp.rs`, `netns.rs`, `rlimits.rs`, `report.rs`
10. `policies/example.yaml`
11. `examples/quickstart.py`, `examples/demo.py`
12. `tests/` policy, audit, engine, guard, sandbox (Linux-gated)
13. `docs/why-agent-security-is-an-os-problem.md`
14. `README.md` final pass with honest platform matrix and working quickstart

## 7. What "done" looks like

- `pip install .` works. The README quickstart runs and enforces in minutes.
- Policy tier denies disallowed calls deterministically on all three platforms.
- Containment tier on Linux blocks fs access outside the allowlist, blocks network
  when denied, and kills on resource breach, proven by a gated test.
- The injection demo contains an attack that succeeds without Asphallea.
- Audit log is JSONL with the rule that fired on every decision.
- Honest platform matrix. No overclaims.
- `docs/why-agent-security-is-an-os-problem.md` exists as the launch essay stub.

## 8. Verification note for this build machine

This machine is Windows with no Rust toolchain, so the Rust core is written to the
pinned crate APIs and is built and tested on Linux, not here. Everything in the
Python policy tier, the audit log, the guard, the quickstart, and the policy-tier
path of the injection demo is verified to run here. The Linux containment tests are
written and gated to skip off Linux or when the core binary is absent.
