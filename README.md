<p align="center">
  <img src="media/asphallea-logo.jpeg" alt="Asphallea" width="380">
</p>

<h1 align="center">Asphallea</h1>

<p align="center"><em>A Genovo Technologies company</em></p>

**A security runtime that secures what your AI agent does, not what it says.**

Asphallea sits between an agent and its tools (shell, filesystem, network, and MCP
tool-calls) and blocks disallowed actions by declarative policy. Enforcement is
deterministic: the same tool-call against the same policy always yields the same
decision, with no model in the loop, and a full audit trail of everything the agent
tried.

![License](https://img.shields.io/badge/license-Apache--2.0-B87333)
![Mode](https://img.shields.io/badge/mode-enforce-1E2328)
![Policy tier](https://img.shields.io/badge/policy%20tier-Linux%20|%20macOS%20|%20Windows-1E2328)
![Containment](https://img.shields.io/badge/OS%20containment-Linux%20|%20Windows%20|%20macOS-B87333)
![MCP](https://img.shields.io/badge/integrations-MCP%20|%20LangChain-1E2328)

## The problem

An AI agent that runs code, calls tools, browses, and touches APIs is a new kind of
privileged process. It acts on its own, and it has none of the containment we built
for normal processes over the last fifty years. When an agent is prompt-injected or
its tools are poisoned, it can do anything its credentials allow. It can exfiltrate
data, delete infrastructure, call APIs, and spend money.

Asphallea wraps an agent's tool-execution layer and enforces a least-privilege
policy on every action, with a complete audit trail. A hijacked agent can only do
what the policy allows, and you can see everything it did.

## This is not guardrails

Asphallea does not judge or filter what the model says. It contains what the agent
does. This is an operating-systems problem wearing an AI costume: process
isolation, least privilege, syscall filtering, blast-radius containment. That
framing is the whole point. A pure-ML approach cannot give you kernel-level
containment. Asphallea does, on Linux, Windows, and macOS, where it counts.

## Two tiers

**Policy tier.** Cross platform. Every tool call is intercepted, checked against a
declarative policy, allowed or denied deterministically, and logged. Works on
Linux, macOS, and Windows. This alone is useful.

**Containment tier.** For high-blast-radius tools that spawn processes, execute
code, or run shell commands, Asphallea contains them at the OS level using each
platform's own engine. Linux gets a Landlock filesystem allowlist, seccomp-bpf
syscall and network filtering, resource limits, and network-namespace isolation.
Windows gets an AppContainer filesystem allowlist and network deny inside a Job
Object that bounds memory, CPU, and process count and guarantees the whole process
tree is killed. macOS gets a Seatbelt profile that allowlists the filesystem and
denies network. This is the part a pure-ML competitor cannot replicate.

## Install

```sh
pip install asphallea
```

The release wheels are platform specific and bundle a prebuilt, code-signed
`asphallea-run` core binary, so there is no Rust toolchain to install and nothing to
compile. Before it runs that binary, the SDK verifies its SHA-256 against a manifest
shipped inside the wheel and refuses a binary that does not match, so a swapped or
patched core is rejected and the run fails closed. See
[`SECURITY.md`](SECURITY.md) for the trust model.

To build the core yourself instead, see [`core/`](core) and point the SDK at your
binary with `ASPHALLEA_CORE_BIN`.

## Quickstart

Define a policy once and put it between the agent and its tools. This uses only the
policy tier, so it runs the same on every platform.

```python
from asphallea import Interceptor, Policy

# One declarative policy. It governs tools it did not author (an MCP server's) by
# declaring how each tool's arguments map to resources.
policy = (
    Policy.builder("agent")
    .tool("filesystem.read", reads="path")
    .tool("filesystem.delete", writes="path")
    .read_paths("./workspace")
    .write_paths("./workspace/out")
    .deny_network()
    .build()
)

# The choke point: decide a tool-call by name and arguments. Deterministic.
gate = Interceptor(policy)
gate.decide("filesystem.delete", {"path": "/etc/passwd"}).allowed   # -> False
gate.enforce("filesystem.delete", {"path": "/etc/passwd"})          # raises PolicyViolation
```

Wrap an MCP session so every tool-call is decided before it runs:

```python
from asphallea.integrations.mcp import guard_mcp_session

session = guard_mcp_session(session, policy)   # a denied call never reaches the server
```

Or guard a Python function tool directly:

```python
from asphallea import guard

@guard(policy, tool="filesystem.read", reads="path")
def read_file(path: str) -> str:
    with open(path) as fh:
        return fh.read()
```

`@guard`, the MCP adapter, and `Interceptor.decide` all funnel through one decision
point, so a decorated function and an MCP tool-call are decided and logged by the
same code. The full quickstart is [`examples/quickstart.py`](examples/quickstart.py):

```sh
python examples/quickstart.py
```

## The containment tier

The policy tier gates whether a tool runs. For tools that run shell commands or
execute code, the containment tier contains what they then do, at the OS level, on
Linux, Windows, and macOS.

Build the Rust core once (or install a release wheel, which bundles it):

```sh
cd core
cargo build --release
export ASPHALLEA_CORE_BIN="$PWD/target/release/asphallea-run"
```

Then run commands under OS enforcement:

```python
from asphallea import Policy, sandbox

policy = (
    Policy.builder("shell")
    .allow_tools("run_shell")
    .read_paths("./workspace")
    .write_paths("./workspace/out")
    .deny_network()
    .limits(cpu_seconds=10, memory_mb=512, max_processes=64)
    .build()
)

result = sandbox.run(["bash", "-c", "echo hello > ./workspace/out/ok.txt"],
                     policy=policy, tool="run_shell")
print(result.returncode, result.controls)

# Contained: the read lands outside the allowlist and the OS sandbox blocks it.
blocked = sandbox.run(["bash", "-c", "cat ~/.ssh/id_rsa"], policy=policy, tool="run_shell")
print(blocked.returncode, blocked.stderr)  # non-zero, permission denied
```

By default `sandbox.run` **fails closed**. If OS containment is not available (not
Linux, no core binary, kernel too old), it refuses to run the command and tells you
exactly what is missing. Pass `allow_degraded=True` to run without containment; that
is logged loudly on every call so it can never pass silently.

Check what your environment can actually enforce:

```python
from asphallea import capabilities
print(capabilities().explain())
```

## The demo

[`examples/demo.py`](examples/demo.py) is the whole pitch in one file. An agent is
connected to a filesystem tool server over MCP and reads a page carrying an injected
instruction that tells it to steal a credential and delete the production database.
It runs twice: once unguarded, where the attack succeeds against throwaway temp
files, and once with the MCP session wrapped in one line, where both tool-calls are
BLOCKED by policy before they run, the database is intact, the credential is never
read, and the audit log is printed. If the OS containment core is present, it adds a
run showing a shell command contained at the OS level too.

```sh
python examples/demo.py
```

## Policy model

A policy declares, per policy:

- which tools may be called (allowlist), and which are denied outright (a denial
  wins)
- how each tool's arguments map to resources, so a tool it did not author can be
  governed: `.tool("filesystem.delete", writes="path")`
- filesystem paths that are readable and writable
- network hosts that are allowed or denied (exact host or parent domain)
- per-tool call-count and rate limits
- a wall-clock timeout per call
- a spend cap, modeled as a maximum number of invocations of a paid tool
- OS resource limits for the containment tier

Build it fluently or load it from YAML. See
[`policies/example.yaml`](policies/example.yaml).

```python
from asphallea import Policy

policy = Policy.from_yaml("policies/example.yaml")
```

## Audit log

Every decision is written as one JSON object per line (JSONL), append-only. Each
record carries the timestamp, tool, arguments (by name, the shape a tool-call has),
the allow or deny decision, the reason, and the exact policy rule that fired. A
redaction hook scrubs likely secrets before anything is written.

```json
{"timestamp": "2026-07-12T18:20:01Z", "tier": "policy", "tool": "filesystem.delete", "decision": "deny", "rule": "write_paths", "reason": "write path '/etc/passwd' is not under an allowed write prefix", "policy": "agent", "args": [], "kwargs": {"path": "/etc/passwd"}}
```

Swap in your own audit sink or redactor. See [`asphallea/audit.py`](asphallea/audit.py).

## MCP

An MCP tool-call is a tool name and an arguments dict, which is exactly what the
decision point takes, so guarding a session is one line. A denied tool-call never
reaches the server.

```python
from asphallea.integrations.mcp import guard_mcp_session

session = guard_mcp_session(session, policy)          # raises PolicyViolation on deny
# or, to let the agent loop continue on a normal tool error:
session = guard_mcp_session(session, policy, on_deny="error")
```

`guard_call_tool(fn, policy)` wraps a bare `call_tool` (client or server side, sync
or async), and `namespace=` keeps two servers exposing the same tool name apart. The
adapter is duck-typed, so it works whether or not the `mcp` package is installed.

## LangChain and LangGraph

Wrap existing LangChain or LangGraph tools with a policy. The adapter is duck-typed,
so it works whether or not `langchain` is installed.

```python
from asphallea import Policy, Engine, AuditLog
from asphallea.integrations.langchain import guard_tool

policy = Policy.builder("lc").allow_tools("read_file").read_paths("./workspace").build()
engine = Engine(policy)

safe_tool = guard_tool(read_file, engine, reads="path", audit=AuditLog("audit.jsonl"))
# hand `safe_tool` to your agent or graph in place of the original
```

OpenAI and Anthropic tool-calling adapters are fast-follow.

## Honest platform support

Each OS has its own containment engine, and the coverage differs. Asphallea reports
what it actually enforces per dimension and never claims more. When a policy needs a
dimension the local backend cannot deliver, it fails closed rather than run
partially contained.

| Capability | Linux 5.13+ | Windows | macOS |
| --- | --- | --- | --- |
| Policy tier: allow/deny, allowlists, rate, spend, timeout | yes | yes | yes |
| Audit trail (JSONL) | yes | yes | yes |
| Filesystem allowlist at the OS level | yes (Landlock) | yes (AppContainer) | yes (Seatbelt) |
| Network deny at the OS level | yes (seccomp + netns) | yes (AppContainer) | yes (Seatbelt) |
| Syscall filtering | yes (seccomp-bpf) | n/a | n/a |
| Resource limits (memory, CPU, processes) | yes (setrlimit) | yes (Job Objects) | planned |
| Guaranteed process termination | yes | yes (Job Objects) | yes (process group) |
| Containment engine | Landlock + seccomp | AppContainer + Job Objects | Seatbelt |

The policy tier enforces the tool allowlist, path allowlist, rate limits, spend
caps, and timeouts identically on all three. The containment tier is where the OS
matters:

- **Linux** contains with Landlock (filesystem allowlist), seccomp (syscall and
  network filter), network namespaces, and setrlimit, applied to the process and
  everything it spawns.
- **Windows** contains with an AppContainer (filesystem allowlist and network deny)
  inside a Job Object (memory, CPU, and process-count limits, and guaranteed
  termination of the whole process tree). A hijacked shell command cannot read the
  user's files, write outside the workspace, or reach the network.
- **macOS** contains with a Seatbelt profile: a deny-by-default sandbox that allows
  the system directories a program needs to run, allows the policy's read and write
  paths, and denies everything else including network. Resource limits are a
  follow-up.

Coverage is reported per dimension. A run proceeds contained only when the backend
covers every dimension the policy requires; otherwise it fails closed rather than
run partially contained.

## Architecture

The design and the decisions behind it are in [`PLAN.md`](PLAN.md). The short
version: the Python SDK is the developer-facing surface, and the Rust
[`core/`](core) crate is the OS enforcement, invoked as a launcher binary that
applies containment to itself and then execs the sandboxed command. The launch essay
is in [`docs/why-agent-security-is-an-os-problem.md`](docs/why-agent-security-is-an-os-problem.md).

## What v0 is not

No observe mode, no baseline learning, no anomaly detection, no ML. No dashboard, no
web UI, no SaaS backend. No real-time dollar metering. No content filtering or
prompt-injection detection. Asphallea contains actions. It does not judge text.
These are deliberate non-goals for v0.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
