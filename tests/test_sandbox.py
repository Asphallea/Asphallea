"""Tests for the containment tier.

The policy-tier gating and the degraded/fail-closed behavior are tested on any
platform. The real OS containment tests require a Linux host with the
``asphallea-run`` core binary built, and are skipped otherwise.
"""

from __future__ import annotations

import os
import sys

import pytest

from asphallea import (
    ContainmentUnavailable,
    Policy,
    PolicyViolation,
    capabilities,
    sandbox,
)

CAPS = capabilities()
CONTAINED = CAPS.can_contain

need_uncontained = pytest.mark.skipif(
    CONTAINED, reason="OS containment is available here; testing the unavailable path"
)
need_contained = pytest.mark.skipif(
    not CONTAINED, reason="requires Linux with the asphallea-run core binary built"
)


def base_policy(tmp_path):
    ws = str(tmp_path / "ws")
    out = str(tmp_path / "ws" / "out")
    os.makedirs(out, exist_ok=True)
    return (
        Policy.builder("sbx")
        .allow_tools("run_shell")
        .read_paths(ws)
        .write_paths(out)
        .deny_network()
        .limits(cpu_seconds=10, memory_mb=512, max_processes=64)
        .build()
    )


def test_capabilities_shape():
    caps = capabilities()
    assert caps.platform in ("Linux", "Darwin", "Windows")
    assert isinstance(caps.explain(), str)
    if caps.platform != "Linux":
        assert caps.can_contain is False


def test_run_requires_policy_or_engine(tmp_path):
    with pytest.raises(ValueError):
        sandbox.run(["echo", "hi"])


def test_policy_tier_tool_allowlist_denies(tmp_path):
    # A tool not in the allowlist is denied before containment is even considered,
    # so this holds on every platform.
    policy = Policy.builder("sbx").allow_tools("something_else").build()
    with pytest.raises(PolicyViolation) as exc:
        sandbox.run(["echo", "hi"], policy=policy, tool="run_shell")
    assert exc.value.decision.rule == "tool_allowlist"


@need_uncontained
def test_fail_closed_when_unavailable(tmp_path):
    policy = base_policy(tmp_path)
    with pytest.raises(ContainmentUnavailable) as exc:
        sandbox.run([sys.executable, "-c", "print('x')"], policy=policy, tool="run_shell")
    assert exc.value.decision.rule == "containment_unavailable"


@need_uncontained
def test_degraded_mode_runs_and_warns(tmp_path):
    policy = base_policy(tmp_path)
    with pytest.warns(RuntimeWarning):
        result = sandbox.run(
            [sys.executable, "-c", "print('degraded-ok')"],
            policy=policy,
            tool="run_shell",
            allow_degraded=True,
        )
    assert result.degraded is True
    assert result.contained is False
    assert "degraded-ok" in result.stdout


@need_uncontained
def test_degraded_mode_audits(tmp_path):
    from asphallea import AuditLog

    audit_path = str(tmp_path / "a.jsonl")
    policy = base_policy(tmp_path)
    with pytest.warns(RuntimeWarning):
        sandbox.run(
            [sys.executable, "-c", "print('x')"],
            policy=policy,
            tool="run_shell",
            audit=AuditLog(audit_path),
            allow_degraded=True,
        )
    lines = [line for line in open(audit_path, encoding="utf-8") if line.strip()]
    # one policy-tier allow, one containment-tier degraded allow
    assert any('"tier": "containment"' in line and '"degraded"' in line for line in lines)


# --- real OS containment (Linux only) --------------------------------------


@need_contained
def test_contained_allows_write_inside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "ws" / "out" / "ok.txt")
    result = sandbox.run(["sh", "-c", f"echo hi > '{target}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert os.path.exists(target)


@need_contained
def test_contained_blocks_read_outside(tmp_path):
    policy = base_policy(tmp_path)
    secret = str(tmp_path / "secret.txt")
    with open(secret, "w") as fh:
        fh.write("TOPSECRET")
    result = sandbox.run(["sh", "-c", f"cat '{secret}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert result.returncode != 0
    assert "TOPSECRET" not in result.stdout


@need_contained
def test_contained_blocks_write_outside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "escape.txt")
    result = sandbox.run(["sh", "-c", f"echo pwned > '{target}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert not os.path.exists(target)


@need_contained
def test_probe_reports_landlock():
    caps = capabilities(refresh=True)
    assert caps.landlock_abi >= 1
    assert caps.seccomp is True
