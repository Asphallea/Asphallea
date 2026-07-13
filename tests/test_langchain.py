"""Tests for the LangChain/LangGraph adapter, using a duck-typed fake tool.

These do not require `langchain` to be installed. The adapter is duck-typed, so a
minimal stand-in with `name` and `invoke` exercises the real code paths.
"""

from __future__ import annotations

import os

import pytest

from asphallea import AuditLog, Engine, Policy, PolicyViolation
from asphallea.integrations.langchain import guard_tool, guard_tools, is_langchain_tool


class FakeTool:
    """A minimal LangChain-like tool: a name and an invoke method."""

    def __init__(self, name, fn):
        self.name = name
        self.description = f"fake tool {name}"
        self._fn = fn

    def invoke(self, input, config=None, **kwargs):
        return self._fn(input)

    async def ainvoke(self, input, config=None, **kwargs):
        return self._fn(input)


def test_is_langchain_tool():
    assert is_langchain_tool(FakeTool("t", lambda x: x))
    assert not is_langchain_tool(object())
    assert not is_langchain_tool("not a tool")


def test_allowed_dict_input(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    tool = FakeTool("read_file", lambda inp: f"read {inp['path']}")
    policy = Policy.builder("p").allow_tool("read_file").read_paths(ws).build()
    safe = guard_tool(tool, policy, reads="path")
    assert safe.invoke({"path": os.path.join(ws, "a.txt")}) == f"read {os.path.join(ws, 'a.txt')}"


def test_denied_dict_input_raises(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    tool = FakeTool("read_file", lambda inp: "data")
    policy = Policy.builder("p").allow_tool("read_file").read_paths(ws).build()
    safe = guard_tool(tool, policy, reads="path")
    with pytest.raises(PolicyViolation) as exc:
        safe.invoke({"path": str(tmp_path / "secret")})
    assert exc.value.decision.rule == "read_paths"


def test_on_deny_return_string(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    tool = FakeTool("read_file", lambda inp: "data")
    policy = Policy.builder("p").allow_tool("read_file").read_paths(ws).build()
    safe = guard_tool(tool, policy, reads="path", on_deny="return")
    result = safe.invoke({"path": str(tmp_path / "secret")})
    assert isinstance(result, str)
    assert "asphallea denied" in result
    assert "read_paths" in result


def test_string_input_single_read(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    tool = FakeTool("read_file", lambda inp: f"read {inp}")
    policy = Policy.builder("p").allow_tool("read_file").read_paths(ws).build()
    safe = guard_tool(tool, policy, reads="path")
    # A bare string input is treated as the single path value.
    assert safe.invoke(os.path.join(ws, "a")).startswith("read")
    with pytest.raises(PolicyViolation):
        safe.invoke(str(tmp_path / "no"))


def test_tool_not_in_allowlist_denied():
    tool = FakeTool("evil", lambda inp: "boom")
    policy = Policy.builder("p").allow_tool("only_this").build()
    safe = guard_tool(tool, policy)
    with pytest.raises(PolicyViolation) as exc:
        safe.invoke({})
    assert exc.value.decision.rule == "tool_allowlist"


def test_attribute_delegation():
    tool = FakeTool("t", lambda inp: inp)
    safe = guard_tool(tool, Policy.builder("p").build())
    assert safe.name == "t"
    assert safe.description == "fake tool t"


def test_audit_written(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    audit_path = str(tmp_path / "a.jsonl")
    tool = FakeTool("read_file", lambda inp: "ok")
    policy = Policy.builder("p").allow_tool("read_file").read_paths(ws).build()
    safe = guard_tool(tool, policy, reads="path", audit=AuditLog(audit_path))
    with pytest.raises(PolicyViolation):
        safe.invoke({"path": str(tmp_path / "no")})
    lines = [line for line in open(audit_path, encoding="utf-8") if line.strip()]
    assert len(lines) == 1
    assert '"decision": "deny"' in lines[0]


def test_guard_tools_shares_engine():
    policy = Policy.builder("p").max_calls("a", 1).max_calls("b", 1).build()
    engine = Engine(policy)
    tools = [FakeTool("a", lambda inp: 1), FakeTool("b", lambda inp: 2)]
    wrapped = guard_tools(tools, engine)
    assert len(wrapped) == 2
    assert wrapped[0].invoke({}) == 1
    assert wrapped[1].invoke({}) == 2
    # a's single call is used up; the shared engine counts it.
    with pytest.raises(PolicyViolation):
        wrapped[0].invoke({})


def test_async_invoke():
    import asyncio

    ws_tool = FakeTool("t", lambda inp: "async-ok")
    policy = Policy.builder("p").allow_tool("t").build()
    safe = guard_tool(ws_tool, policy)
    assert asyncio.run(safe.ainvoke({})) == "async-ok"


def test_invalid_on_deny_rejected():
    with pytest.raises(ValueError):
        guard_tool(FakeTool("t", lambda inp: inp), Policy.builder("p").build(), on_deny="explode")
