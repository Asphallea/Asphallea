"""Tests for the single decision choke point.

These exercise enforcement the way an MCP server or any non-Python tool surface
reaches it: a tool name and a dict of arguments, with no decorator and no Python
function involved. They also prove that ``@guard`` routes through the same point.
"""

from __future__ import annotations

import json
import os

import pytest

from asphallea import AuditLog, Interceptor, Policy, PolicyViolation, guard


def workspace_policy(tmp_path, **kw):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    builder = (
        Policy.builder("p")
        .tool("filesystem.read", reads="path")
        .tool("filesystem.delete", writes="path")
        .tool("http.fetch", network="url")
        .read_paths(str(ws))
        .write_paths(str(ws))
    )
    for tool, n in kw.get("max_calls", {}).items():
        builder.max_calls(tool, n)
    return builder.build(), ws


# --- decisions from a tool name + arguments, no decorator -------------------


def test_decide_allows_path_inside_allowlist(tmp_path):
    policy, ws = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    d = gate.decide("filesystem.delete", {"path": str(ws / "scratch.txt")})
    assert d.allowed


def test_decide_denies_path_outside_allowlist(tmp_path):
    policy, ws = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    d = gate.decide("filesystem.delete", {"path": str(tmp_path / "protected.txt")})
    assert d.denied
    assert d.rule == "write_paths"


def test_decide_uses_read_vs_write_access(tmp_path):
    # The same path is readable but the policy maps `path` differently per tool.
    policy, ws = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    outside = str(tmp_path / "secret.txt")
    assert gate.decide("filesystem.read", {"path": outside}).rule == "read_paths"
    assert gate.decide("filesystem.delete", {"path": outside}).rule == "write_paths"


def test_decide_denies_unlisted_tool(tmp_path):
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    d = gate.decide("shell.exec", {"cmd": "rm -rf /"})
    assert d.denied and d.rule == "tool_allowlist"


def test_decide_honours_explicit_denylist(tmp_path):
    policy = (
        Policy.builder("p")
        .tool("filesystem.delete", writes="path")
        .deny_tool("filesystem.delete")
        .build()
    )
    gate = Interceptor(policy)
    d = gate.decide("filesystem.delete", {"path": "/anything"})
    assert d.denied and d.rule == "tool_allowlist"


def test_decide_flags_network_argument(tmp_path):
    policy, _ = workspace_policy(tmp_path)  # network defaults to deny
    gate = Interceptor(policy)
    d = gate.decide("http.fetch", {"url": "https://attacker.example"})
    assert d.denied and d.rule == "network"


# --- network host rules (Step 4) -------------------------------------------


def net_policy(**kw):
    b = Policy.builder("net").tool("http.fetch", network="url")
    if kw.get("allow_default"):
        b.allow_network()
    for h in kw.get("allow_hosts", []):
        b.allow_hosts(h)
    for h in kw.get("deny_hosts", []):
        b.deny_hosts(h)
    return b.build()


def test_allow_hosts_permits_a_listed_host_when_default_deny():
    gate = Interceptor(net_policy(allow_hosts=["api.example.com"]))
    assert gate.decide("http.fetch", {"url": "https://api.example.com/v1"}).allowed


def test_allow_hosts_covers_subdomains_but_not_lookalikes():
    gate = Interceptor(net_policy(allow_hosts=["example.com"]))
    assert gate.decide("http.fetch", {"url": "https://api.example.com/x"}).allowed
    assert gate.decide("http.fetch", {"url": "https://example.com"}).allowed
    # A lookalike domain must not match.
    bad = gate.decide("http.fetch", {"url": "https://notexample.com"})
    assert bad.denied and bad.rule == "network"


def test_unlisted_host_denied_when_default_deny():
    gate = Interceptor(net_policy(allow_hosts=["api.example.com"]))
    d = gate.decide("http.fetch", {"url": "https://attacker.example/steal"})
    assert d.denied and d.rule == "network"


def test_deny_hosts_wins_over_default_allow():
    gate = Interceptor(net_policy(allow_default=True, deny_hosts=["attacker.example"]))
    assert gate.decide("http.fetch", {"url": "https://good.com"}).allowed
    d = gate.decide("http.fetch", {"url": "https://attacker.example"})
    assert d.denied and d.rule == "network"


def test_deny_hosts_wins_over_allow_hosts():
    policy = (
        Policy.builder("net")
        .tool("http.fetch", network="url")
        .allow_hosts("example.com")
        .deny_hosts("secret.example.com")
        .build()
    )
    gate = Interceptor(policy)
    assert gate.decide("http.fetch", {"url": "https://api.example.com"}).allowed
    # A denied subdomain of an allowed domain is still denied.
    d = gate.decide("http.fetch", {"url": "https://secret.example.com"})
    assert d.denied and d.rule == "network"


def test_host_match_ignores_scheme_port_and_case():
    gate = Interceptor(net_policy(allow_hosts=["API.Example.com"]))
    for target in (
        "https://api.example.com/path",
        "http://api.example.com:8443/x",
        "api.example.com",
        "api.example.com:443",
    ):
        assert gate.decide("http.fetch", {"url": target}).allowed, target


def test_forced_network_with_no_target_uses_default(tmp_path):
    # A tool that reaches the network but exposes no URL argument: guard(network=True).
    deny = Interceptor(net_policy())
    assert deny.engine.check("http.fetch", network=True).denied
    allow = Interceptor(net_policy(allow_default=True))
    assert allow.engine.check("http.fetch", network=True).allowed


def test_network_host_rules_are_deterministic():
    gate = Interceptor(net_policy(allow_hosts=["example.com"]))
    call = {"url": "https://attacker.example"}
    outcomes = {gate.decide("http.fetch", call).allowed for _ in range(50)}
    assert outcomes == {False}


def test_decide_checks_every_entry_of_a_list_argument(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    policy = (
        Policy.builder("p").tool("fs.remove", writes="paths").write_paths(str(ws)).build()
    )
    gate = Interceptor(policy)
    ok = gate.decide("fs.remove", {"paths": [str(ws / "a"), str(ws / "b")]})
    assert ok.allowed
    bad = gate.decide("fs.remove", {"paths": [str(ws / "a"), str(tmp_path / "escape")]})
    assert bad.denied and bad.rule == "write_paths"


def test_missing_or_none_arguments_are_skipped(tmp_path):
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    # No `path` argument at all: nothing to check, so the call is allowed.
    assert gate.decide("filesystem.delete", {}).allowed
    assert gate.decide("filesystem.delete", {"path": None}).allowed


def test_enforce_raises_on_deny(tmp_path):
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    with pytest.raises(PolicyViolation) as exc:
        gate.enforce("filesystem.delete", {"path": str(tmp_path / "nope")})
    assert exc.value.decision.rule == "write_paths"


def test_enforce_returns_decision_when_allowed(tmp_path):
    policy, ws = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    assert gate.enforce("filesystem.delete", {"path": str(ws / "ok")}).allowed


# --- determinism (criterion 4) ---------------------------------------------


def test_decisions_are_deterministic(tmp_path):
    """Same tool, same arguments, same policy: same decision every time."""
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    call = {"path": str(tmp_path / "protected.txt")}
    outcomes = {
        (d.allowed, d.rule, d.reason)
        for d in (gate.decide("filesystem.delete", call) for _ in range(50))
    }
    assert len(outcomes) == 1
    (allowed, rule, _reason), = outcomes
    assert allowed is False and rule == "write_paths"


def test_no_model_call_in_the_decision_path(tmp_path, monkeypatch):
    """A denial must not require network or a model. Fail if anything opens a socket."""
    import socket

    def explode(*a, **k):
        raise AssertionError("the decision path must not touch the network")

    monkeypatch.setattr(socket, "socket", explode)
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy)
    assert gate.decide("filesystem.delete", {"path": "/etc/shadow"}).denied


# --- @guard routes through the same choke point ----------------------------


def test_guard_shares_the_interceptor_counters(tmp_path):
    """A decorated call and a raw decide() hit one engine, so limits are shared."""
    policy = Policy.builder("p").allow_tools("t").max_calls("t", 2).build()
    gate = Interceptor(policy)

    @guard(gate, tool="t")
    def t():
        return "ran"

    assert t() == "ran"                      # 1st, through the decorator
    assert gate.decide("t").allowed          # 2nd, through decide()
    with pytest.raises(PolicyViolation):     # 3rd exceeds the shared limit
        t()


def test_guard_merges_its_kwargs_with_the_policy_declaration(tmp_path):
    """The policy declares `path`; the decorator adds `backup` for this call site."""
    ws = tmp_path / "ws"
    ws.mkdir()
    policy = (
        Policy.builder("p").tool("save", writes="path").write_paths(str(ws)).build()
    )
    gate = Interceptor(policy)

    @guard(gate, tool="save", writes="backup")
    def save(path, backup):
        return "saved"

    assert save(str(ws / "a"), str(ws / "b")) == "saved"
    # The policy-declared argument is enforced.
    with pytest.raises(PolicyViolation):
        save(str(tmp_path / "escape"), str(ws / "b"))
    # And so is the decorator-declared one.
    with pytest.raises(PolicyViolation):
        save(str(ws / "a"), str(tmp_path / "escape"))


def test_guard_and_decide_write_to_one_audit_trail(tmp_path):
    audit_path = str(tmp_path / "audit.jsonl")
    policy, ws = workspace_policy(tmp_path)
    gate = Interceptor(policy, audit=AuditLog(audit_path))

    @guard(gate, tool="filesystem.delete")
    def delete(path):
        return "deleted"

    delete(str(ws / "ok.txt"))
    with pytest.raises(PolicyViolation):
        gate.enforce("filesystem.delete", {"path": str(tmp_path / "protected")})

    records = [json.loads(line) for line in open(audit_path, encoding="utf-8") if line.strip()]
    assert len(records) == 2
    assert records[0]["decision"] == "allow"
    assert records[1]["decision"] == "deny" and records[1]["rule"] == "write_paths"
    # Arguments are recorded by name, the shape a tool-call actually has.
    assert "path" in records[1]["kwargs"]


def test_audit_records_the_named_arguments(tmp_path):
    audit_path = str(tmp_path / "a.jsonl")
    policy, _ = workspace_policy(tmp_path)
    gate = Interceptor(policy, audit=AuditLog(audit_path))
    gate.decide("filesystem.delete", {"path": str(tmp_path / "x")})
    record = json.loads(open(audit_path, encoding="utf-8").readline())
    assert record["tool"] == "filesystem.delete"
    assert record["kwargs"]["path"].endswith("x")


def test_interceptor_accepts_a_shared_engine(tmp_path):
    from asphallea import Engine

    policy = Policy.builder("p").allow_tools("a").max_calls("a", 1).build()
    engine = Engine(policy)
    gate = Interceptor(engine)
    assert gate.decide("a").allowed
    assert gate.decide("a").denied  # the engine's counter was shared
    assert engine.snapshot()["calls"]["a"] == 1
