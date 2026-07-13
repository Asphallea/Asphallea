"""Tests for the deterministic evaluation engine."""

from __future__ import annotations

import os

from asphallea import Engine, Policy


def make_engine(tmp_path, **kw):
    builder = Policy.builder("t")
    if kw.get("allow"):
        builder.allow_tools(*kw["allow"])
    if "read" in kw:
        builder.read_paths(*kw["read"])
    if "write" in kw:
        builder.write_paths(*kw["write"])
    if kw.get("deny_network"):
        builder.deny_network()
    for tool, n in kw.get("max_calls", {}).items():
        builder.max_calls(tool, n)
    for tool, n in kw.get("spend", {}).items():
        builder.spend_cap(tool, n)
    for tool, pm in kw.get("rate", {}).items():
        builder.rate_limit(tool, per_minute=pm)
    return Engine(builder.build())


def test_allow_when_unrestricted(tmp_path):
    eng = make_engine(tmp_path)
    assert eng.check("anything").allowed


def test_tool_allowlist(tmp_path):
    eng = make_engine(tmp_path, allow=["ok"])
    assert eng.check("ok").allowed
    d = eng.check("nope")
    assert d.denied and d.rule == "tool_allowlist"


def test_read_path_allow_and_deny(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    eng = make_engine(tmp_path, read=[ws])
    assert eng.check("t", reads=[os.path.join(ws, "a.txt")]).allowed
    d = eng.check("t", reads=[str(tmp_path / "elsewhere" / "secret")])
    assert d.denied and d.rule == "read_paths"


def test_prefix_boundary_not_fooled(tmp_path):
    ws = str(tmp_path / "ws")
    evil = str(tmp_path / "ws-evil")
    os.makedirs(ws)
    os.makedirs(evil)
    eng = make_engine(tmp_path, read=[ws])
    # "ws-evil" must not be treated as under "ws"
    d = eng.check("t", reads=[os.path.join(evil, "x")])
    assert d.denied and d.rule == "read_paths"


def test_write_path_enforced(tmp_path):
    out = str(tmp_path / "out")
    os.makedirs(out)
    eng = make_engine(tmp_path, write=[out])
    assert eng.check("t", writes=[os.path.join(out, "f")]).allowed
    d = eng.check("t", writes=[str(tmp_path / "other" / "f")])
    assert d.denied and d.rule == "write_paths"


def test_network_denied(tmp_path):
    eng = make_engine(tmp_path, deny_network=True)
    assert eng.check("t", network=False).allowed
    d = eng.check("t", network=True)
    assert d.denied and d.rule == "network"


def test_max_calls(tmp_path):
    eng = make_engine(tmp_path, max_calls={"t": 2})
    assert eng.check("t").allowed
    assert eng.check("t").allowed
    d = eng.check("t")
    assert d.denied and d.rule == "max_calls"


def test_spend_cap(tmp_path):
    eng = make_engine(tmp_path, spend={"paid": 1})
    assert eng.check("paid").allowed
    d = eng.check("paid")
    assert d.denied and d.rule == "spend_cap"


def test_rate_limit_sliding_window(tmp_path):
    eng = make_engine(tmp_path, rate={"t": 2})  # 2 per minute
    assert eng.check("t", now=1000.0).allowed
    assert eng.check("t", now=1000.5).allowed
    d = eng.check("t", now=1001.0)
    assert d.denied and d.rule == "rate_limit"
    # After the 60s window passes, it recovers.
    assert eng.check("t", now=1062.0).allowed


def test_deny_does_not_consume_counters(tmp_path):
    # A call denied by path must not consume max_calls budget.
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    eng = make_engine(tmp_path, read=[ws], max_calls={"t": 1})
    denied = eng.check("t", reads=[str(tmp_path / "no")])
    assert denied.denied and denied.rule == "read_paths"
    # The one allowed call is still available.
    assert eng.check("t", reads=[os.path.join(ws, "a")]).allowed
    assert eng.snapshot()["calls"]["t"] == 1


def test_ordering_tool_allowlist_before_paths(tmp_path):
    # A disallowed tool with a bad path reports the allowlist, which is checked first.
    eng = make_engine(tmp_path, allow=["ok"], read=[str(tmp_path / "ws")])
    d = eng.check("evil", reads=[str(tmp_path / "no")])
    assert d.rule == "tool_allowlist"
