"""Asphallea quickstart: wrap one tool in a least-privilege policy.

Run it:

    python examples/quickstart.py

This uses only the policy tier, so it behaves identically on Linux, macOS, and
Windows. It builds a policy, guards a file-reading tool, shows an allowed call and
a denied call, and prints the audit trail.
"""

import os
import tempfile

from asphallea import AuditLog, Policy, PolicyViolation, guard


def main() -> None:
    # A scratch workspace the tool is allowed to read.
    workspace = tempfile.mkdtemp(prefix="asphallea-quickstart-")
    with open(os.path.join(workspace, "notes.txt"), "w", encoding="utf-8") as fh:
        fh.write("hello from inside the workspace\n")

    audit_path = os.path.join(workspace, "audit.jsonl")

    # Least privilege: this agent may call read_file, and only under the
    # workspace. Network is denied. Everything else is denied by default.
    policy = (
        Policy.builder("quickstart")
        .allow_tools("read_file")
        .read_paths(workspace)
        .deny_network()
        .build()
    )

    # Guard the tool. `reads="path"` tells the engine which argument is a path to
    # check against the read allowlist.
    @guard(policy, tool="read_file", reads="path", audit=AuditLog(audit_path))
    def read_file(path: str) -> str:
        """Read and return the contents of a file."""
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    print("Asphallea quickstart\n" + "=" * 40)

    # 1. Allowed: a path inside the workspace.
    inside = os.path.join(workspace, "notes.txt")
    print(f"\nreading an allowed path:\n  {inside}")
    print(f"  -> {read_file(inside)!r}")

    # 2. Denied: a path outside the workspace. A hijacked agent trying to read
    # your SSH key or /etc/passwd is stopped here, deterministically.
    outside = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
    print(f"\nreading a disallowed path:\n  {outside}")
    try:
        read_file(outside)
    except PolicyViolation as exc:
        print(f"  -> DENIED by rule {exc.decision.rule!r}: {exc.decision.reason}")

    # The audit log recorded both decisions as JSONL.
    print(f"\naudit trail ({audit_path}):")
    with open(audit_path, encoding="utf-8") as fh:
        for line in fh:
            print("  " + line.rstrip())


if __name__ == "__main__":
    main()
