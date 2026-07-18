"""Asphallea quickstart: govern an agent's tool-calls with a policy.

Run it:

    python examples/quickstart.py

This uses only the policy tier, so it behaves identically on Linux, macOS, and
Windows. It shows the two shapes a decision arrives in: a raw tool-call
(``name`` + ``arguments``, which is what MCP gives you) and a wrapped MCP session.
"""

import asyncio
import os
import tempfile

from asphallea import Interceptor, Policy, PolicyViolation
from asphallea.integrations.mcp import guard_mcp_session


class FakeFilesystemServer:
    """Stand-in for an MCP filesystem server whose delete really removes a file."""

    async def call_tool(self, name, arguments=None):
        if name == "filesystem.delete":
            os.remove(arguments["path"])
            return "deleted"
        raise ValueError(name)


def main() -> None:
    workspace = tempfile.mkdtemp(prefix="asphallea-quickstart-")
    # A real file the agent must not touch, outside the workspace.
    protected = os.path.join(tempfile.mkdtemp(), "production.db")
    with open(protected, "w", encoding="utf-8") as fh:
        fh.write("PRODUCTION DATA\n")

    # One declarative policy. It governs tools it did not author by declaring how
    # each tool's arguments map to resources: filesystem.delete's `path` is a
    # write, checked against the write allowlist below.
    policy = (
        Policy.builder("quickstart")
        .tool("filesystem.read", reads="path")
        .tool("filesystem.delete", writes="path")
        .read_paths(workspace)
        .write_paths(workspace)
        .deny_network()
        .build()
    )

    print("Asphallea quickstart\n" + "=" * 40)

    # 1. The choke point: decide a tool-call by name and arguments. Deterministic,
    # no model in the loop.
    gate = Interceptor(policy)
    inside = os.path.join(workspace, "notes.txt")
    allowed = gate.decide("filesystem.delete", {"path": inside})
    denied = gate.decide("filesystem.delete", {"path": protected})
    print(f"\ndelete inside the workspace : allowed={allowed.allowed}")
    print(f"delete the protected file   : allowed={denied.allowed} (rule={denied.rule})")

    # 2. The same policy wrapping an MCP session, in one line. Every call_tool is
    # now decided before it runs, so a denied call never reaches the server.
    session = guard_mcp_session(FakeFilesystemServer(), policy)
    print("\nagent calls filesystem.delete on the protected file through MCP:")
    try:
        asyncio.run(session.call_tool("filesystem.delete", {"path": protected}))
    except PolicyViolation as exc:
        print(f"  BLOCKED by policy [{exc.decision.rule}]: {exc.decision.reason}")
        print(f"  protected file still present: {os.path.exists(protected)}")


if __name__ == "__main__":
    main()
