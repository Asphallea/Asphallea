"""Tests for the guard decorator and generic wrapper."""

from __future__ import annotations

import asyncio
import os
import time

import pytest

from asphallea import AuditLog, Engine, Policy, PolicyTimeout, PolicyViolation, guard
from asphallea.audit import NullAuditLog


def test_allowed_call_passes_through():
    policy = Policy.builder("p").allow_tool("echo").build()

    @guard(policy, tool="echo")
    def echo(x):
        return x * 2

    assert echo(3) == 6


def test_denied_tool_raises():
    policy = Policy.builder("p").allow_tool("ok").build()

    @guard(policy, tool="blocked")
    def blocked():
        return "ran"

    with pytest.raises(PolicyViolation) as exc:
        blocked()
    assert exc.value.decision.rule == "tool_allowlist"
    assert exc.value.tool == "blocked"


def test_read_path_denied(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    policy = Policy.builder("p").read_paths(ws).build()

    @guard(policy, tool="read", reads="path")
    def read(path):
        return "data"

    assert read(os.path.join(ws, "ok.txt")) == "data"
    with pytest.raises(PolicyViolation) as exc:
        read(str(tmp_path / "secret"))
    assert exc.value.decision.rule == "read_paths"


def test_positional_path_index(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    policy = Policy.builder("p").write_paths(ws).build()

    @guard(policy, tool="w", writes=0)
    def write(path, content):
        return "wrote"

    assert write(os.path.join(ws, "f"), "x") == "wrote"
    with pytest.raises(PolicyViolation):
        write(str(tmp_path / "outside"), "x")


def test_audit_records_allow_and_deny(tmp_path):
    audit_path = str(tmp_path / "a.jsonl")
    audit = AuditLog(audit_path)
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    policy = Policy.builder("p").read_paths(ws).build()

    @guard(policy, tool="read", reads="path", audit=audit)
    def read(path):
        return "ok"

    read(os.path.join(ws, "a"))
    with pytest.raises(PolicyViolation):
        read(str(tmp_path / "no"))
    audit.close()

    lines = [line for line in open(audit_path, encoding="utf-8") if line.strip()]
    assert len(lines) == 2
    assert '"decision": "allow"' in lines[0]
    assert '"decision": "deny"' in lines[1]


def test_shared_engine_counts_across_tools():
    policy = Policy.builder("p").max_calls("a", 1).max_calls("b", 1).build()
    engine = Engine(policy)

    @guard(engine, tool="a")
    def a():
        return 1

    @guard(engine, tool="b")
    def b():
        return 2

    assert a() == 1
    assert b() == 2
    with pytest.raises(PolicyViolation):
        a()  # a's single call is used up


def test_timeout_raises():
    policy = Policy.builder("p").timeout(0.1).build()

    @guard(policy, tool="slow")
    def slow():
        time.sleep(1.0)
        return "done"

    with pytest.raises(PolicyTimeout):
        slow()


def test_underlying_exception_propagates():
    policy = Policy.builder("p").build()

    @guard(policy, tool="boom")
    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        boom()


def test_underlying_exception_propagates_with_timeout_set():
    policy = Policy.builder("p").timeout(5).build()

    @guard(policy, tool="boom")
    def boom():
        raise KeyError("nope")

    with pytest.raises(KeyError):
        boom()


def test_async_tool_allowed_and_denied():
    policy = Policy.builder("p").allow_tool("aecho").build()

    @guard(policy, tool="aecho")
    async def aecho(x):
        await asyncio.sleep(0)
        return x

    assert asyncio.run(aecho(5)) == 5

    @guard(policy, tool="anot")
    async def anot():
        return "ran"

    with pytest.raises(PolicyViolation):
        asyncio.run(anot())


def test_async_timeout():
    policy = Policy.builder("p").timeout(0.1).build()

    @guard(policy, tool="aslow")
    async def aslow():
        await asyncio.sleep(1.0)
        return "done"

    with pytest.raises(PolicyTimeout):
        asyncio.run(aslow())


def test_wrapper_form_not_decorator():
    policy = Policy.builder("p").allow_tool("s").build()

    def search(q):
        return f"results for {q}"

    safe = guard(policy, tool="s", audit=NullAuditLog())(search)
    assert safe("cats") == "results for cats"
    assert safe.__name__ == "search"  # functools.wraps preserved metadata
