"""Tests for the MCP tool-call adapter.

These use a fake MCP session, so they run without the ``mcp`` package installed,
the same way the LangChain adapter is tested. The important assertion throughout
is that a denied tool never executes: the side effect does not happen.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from asphallea import AuditLog, Interceptor, Policy, PolicyViolation
from asphallea.integrations.mcp import (
    GuardedSession,
    denial_result,
    guard_call_tool,
    guard_mcp_session,
)


class FakeSession:
    """An MCP-like session whose filesystem tools really do the thing."""

    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, **kwargs):
        arguments = arguments or {}
        self.calls.append((name, dict(arguments)))
        if name == "filesystem.delete":
            os.remove(arguments["path"])
            return {"content": [{"type": "text", "text": "deleted"}]}
        if name == "filesystem.read":
            with open(arguments["path"], encoding="utf-8") as fh:
                return {"content": [{"type": "text", "text": fh.read()}]}
        return {"content": [{"type": "text", "text": "ok"}]}

    async def list_tools(self):
        return ["filesystem.read", "filesystem.delete"]


def arena(tmp_path):
    """A workspace the policy allows, and a protected file it does not."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    inside = ws / "scratch.txt"
    inside.write_text("disposable", encoding="utf-8")
    protected = tmp_path / "production.db"
    protected.write_text("PRODUCTION DATA", encoding="utf-8")
    policy = (
        Policy.builder("mcp-agent")
        .tool("filesystem.read", reads="path")
        .tool("filesystem.delete", writes="path")
        .read_paths(str(ws))
        .write_paths(str(ws))
        .build()
    )
    return policy, str(inside), str(protected)


# --- the core guarantee: a denied tool does not run -------------------------


def test_denied_delete_never_executes(tmp_path):
    policy, inside, protected = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy)

    with pytest.raises(PolicyViolation) as exc:
        asyncio.run(guarded.call_tool("filesystem.delete", {"path": protected}))

    assert exc.value.decision.rule == "write_paths"
    assert os.path.exists(protected), "the protected file must survive"
    assert session.calls == [], "the underlying tool must never be invoked"


def test_allowed_delete_forwards_and_runs(tmp_path):
    policy, inside, _ = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy)

    result = asyncio.run(guarded.call_tool("filesystem.delete", {"path": inside}))

    assert not os.path.exists(inside), "the allowed delete should have happened"
    assert session.calls == [("filesystem.delete", {"path": inside})]
    assert result["content"][0]["text"] == "deleted"


def test_denied_read_never_leaks_content(tmp_path):
    policy, _, protected = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy)

    with pytest.raises(PolicyViolation):
        asyncio.run(guarded.call_tool("filesystem.read", {"path": protected}))
    assert session.calls == []


def test_unlisted_tool_is_denied(tmp_path):
    policy, _, _ = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy)
    with pytest.raises(PolicyViolation) as exc:
        asyncio.run(guarded.call_tool("shell.exec", {"cmd": "rm -rf /"}))
    assert exc.value.decision.rule == "tool_allowlist"
    assert session.calls == []


# --- on_deny="error": the agent loop keeps running --------------------------


def test_on_deny_error_returns_mcp_error_result(tmp_path):
    policy, _, protected = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy, on_deny="error")

    result = asyncio.run(guarded.call_tool("filesystem.delete", {"path": protected}))

    assert result["isError"] is True
    assert "denied" in result["content"][0]["text"]
    assert "write_paths" in result["content"][0]["text"]
    assert os.path.exists(protected)
    assert session.calls == []


def test_invalid_on_deny_rejected(tmp_path):
    policy, _, _ = arena(tmp_path)
    with pytest.raises(ValueError):
        guard_mcp_session(FakeSession(), policy, on_deny="explode")


def test_denial_result_shape():
    from asphallea.engine import Decision

    result = denial_result(Decision.deny("write_paths", "nope"), "fs.delete")
    assert result["isError"] is True
    assert result["content"][0]["type"] == "text"


# --- guard_call_tool on bare callables (client or server side) --------------


def test_guard_call_tool_async(tmp_path):
    policy, inside, protected = arena(tmp_path)
    seen = []

    async def call_tool(name, arguments=None):
        seen.append(name)
        return "ran"

    guarded = guard_call_tool(call_tool, policy)
    assert asyncio.run(guarded("filesystem.delete", {"path": inside})) == "ran"
    with pytest.raises(PolicyViolation):
        asyncio.run(guarded("filesystem.delete", {"path": protected}))
    assert seen == ["filesystem.delete"]  # only the allowed one ran


def test_guard_call_tool_sync(tmp_path):
    policy, inside, protected = arena(tmp_path)
    seen = []

    def call_tool(name, arguments=None):
        seen.append(name)
        return "ran"

    guarded = guard_call_tool(call_tool, policy)
    assert guarded("filesystem.delete", {"path": inside}) == "ran"
    with pytest.raises(PolicyViolation):
        guarded("filesystem.delete", {"path": protected})
    assert seen == ["filesystem.delete"]


# --- namespacing, delegation, audit, shared limits --------------------------


def test_namespace_prefixes_the_policy_tool_name(tmp_path):
    # The policy governs "files.delete"; the server exposes it as "delete".
    ws = tmp_path / "ws"
    ws.mkdir()
    policy = (
        Policy.builder("ns").tool("files.delete", writes="path").write_paths(str(ws)).build()
    )
    session = FakeSession()
    guarded = guard_mcp_session(session, policy, namespace="files")

    # Denied: outside the workspace, matched under the namespaced name.
    with pytest.raises(PolicyViolation):
        asyncio.run(guarded.call_tool("delete", {"path": str(tmp_path / "outside")}))
    # Without the namespace the same call would not match the policy's tool at all.
    assert session.calls == []


def test_other_session_attributes_pass_through(tmp_path):
    policy, _, _ = arena(tmp_path)
    session = FakeSession()
    guarded = guard_mcp_session(session, policy)
    assert asyncio.run(guarded.list_tools()) == ["filesystem.read", "filesystem.delete"]


def test_audit_records_the_mcp_denial(tmp_path):
    policy, _, protected = arena(tmp_path)
    audit_path = str(tmp_path / "audit.jsonl")
    guarded = guard_mcp_session(FakeSession(), policy, audit=AuditLog(audit_path))

    with pytest.raises(PolicyViolation):
        asyncio.run(guarded.call_tool("filesystem.delete", {"path": protected}))

    record = json.loads(open(audit_path, encoding="utf-8").readline())
    assert record["tool"] == "filesystem.delete"
    assert record["decision"] == "deny"
    assert record["rule"] == "write_paths"
    assert record["kwargs"]["path"] == protected


def test_shared_interceptor_counts_across_servers(tmp_path):
    """One interceptor across two servers shares call limits."""
    policy = Policy.builder("p").allow_tools("ping").max_calls("ping", 2).build()
    gate = Interceptor(policy)
    a = guard_mcp_session(FakeSession(), gate)
    b = guard_mcp_session(FakeSession(), gate)

    asyncio.run(a.call_tool("ping", {}))
    asyncio.run(b.call_tool("ping", {}))
    with pytest.raises(PolicyViolation):
        asyncio.run(a.call_tool("ping", {}))


def test_guarded_session_exposes_its_interceptor(tmp_path):
    policy, _, _ = arena(tmp_path)
    guarded = guard_mcp_session(FakeSession(), policy)
    assert isinstance(guarded, GuardedSession)
    assert guarded.interceptor.policy.name == "mcp-agent"
