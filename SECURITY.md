# Security and trust model

Asphallea is a security tool, so it should be honest about what it does and does not
protect, and about where its guarantees come from. This document is that statement.

## What Asphallea protects

Asphallea contains what an AI agent's tools *do*. Under a least-privilege policy, a
hijacked or prompt-injected agent can only take the actions the policy allows, and
every action is recorded. The containment is enforced by the operating system:
Landlock and seccomp on Linux, AppContainer and Job Objects on Windows, Seatbelt on
macOS. The Python policy tier deterministically allows or denies each tool call and
keeps the audit trail.

## Where the security comes from (and where it does not)

The containment does not depend on the `asphallea-run` binary being secret. It
depends on the kernel enforcing the restrictions. An attacker who reads and fully
understands the binary still cannot escape a Landlock ruleset, an AppContainer, or a
Seatbelt profile once it has been applied, because the kernel enforces it, not the
binary. This is Kerckhoffs's principle: the system stays secure even when the
adversary knows exactly how it works.

That is why Asphallea is open source. For a security tool, being auditable is a
feature. It is also why we do not claim the binary "cannot be disassembled." No
binary that runs on a user's machine can be made impossible to reverse engineer, and
claiming otherwise would be the kind of overclaim this project exists to avoid.

## The tamper-resistance model

The real risk is not that someone reads the binary. It is that someone *replaces or
patches* it, so the SDK invokes a core that reports "contained" while enforcing
nothing. Asphallea addresses this on two levels.

1. **Architecture.** The launcher applies containment before it runs any
   agent-controlled code, and the OS restrictions are one-way ratchets the contained
   process cannot lift. The policy and the launcher run in the trusted parent
   context, not inside the sandbox, so the contained code cannot rewrite them.
2. **Integrity.** Released wheels bundle a prebuilt, code-signed `asphallea-run` and
   a `_core/checksums.json` manifest of its SHA-256. Before running the core, the SDK
   recomputes the hash and refuses a binary that does not match, failing closed. When
   the binary is code-signed, that signature is the key-backed version of the same
   check: an attacker cannot forge the publisher's signature without the private key.

The hash manifest catches corruption and naive swaps. Code signing raises the bar to
"forge the publisher's key." Neither is defeated by reading the binary.

## Honest limits

- **A compromised host defeats containment.** If an attacker already has root, or
  can load a kernel module, or controls the OS, they can undo anything a userspace
  sandbox does. Asphallea contains an agent running as a normal user, not a kernel
  attacker.
- **The policy tier for in-process callables is best-effort.** A Python function tool
  runs in your interpreter. The engine checks its declared path arguments and
  enforces call, rate, and spend limits, but it cannot contain arbitrary in-process
  behavior the way the OS contains a subprocess. High-blast-radius tools should go
  through the containment tier (`sandbox.run`), not just the policy tier.
- **Coverage differs per OS.** See the platform matrix in the README. When a policy
  needs a dimension the local backend cannot enforce, the SDK fails closed rather
  than run partially contained.
- **Not un-disassemblable.** Stated plainly above.

## Reporting a vulnerability

If you find a way to escape the containment, bypass the integrity check, or make the
audit log lie, please report it privately to security@asphallea.dev rather than
opening a public issue. We will acknowledge and work a fix before disclosure.
