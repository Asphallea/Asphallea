"""Tests for the containment tier.

Containment coverage differs per OS, so the gates are per capability, not a single
flag. The policy-tier gating is tested everywhere. The fail-closed and degraded
paths run wherever the sample policy is not fully contained. The real filesystem
containment assertions run on Linux (Landlock); the Job Object resource and
termination assertions run on Windows.
"""

from __future__ import annotations

import os
import platform
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
IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

# The sample policy below requires filesystem and network containment. It is fully
# covered only by a complete backend (Linux Landlock + seccomp).
BASE_COVERED = CAPS.covers(filesystem=True, network=True)

uncovered = pytest.mark.skipif(
    BASE_COVERED, reason="the sample policy is fully contained on this host"
)
linux_contained = pytest.mark.skipif(
    not (IS_LINUX and CAPS.can_contain),
    reason="requires the Linux Landlock/seccomp backend",
)
windows_contained = pytest.mark.skipif(
    not (IS_WINDOWS and CAPS.can_contain),
    reason="requires the Windows Job Object backend",
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


def resource_policy():
    """A policy needing only resource limits, coverable by the Windows backend."""
    return (
        Policy.builder("res")
        .allow_tools("run_shell")
        .allow_network()
        .limits(cpu_seconds=10, memory_mb=512, max_processes=32)
        .build()
    )


def test_capabilities_shape():
    caps = capabilities()
    assert caps.platform in ("Linux", "Darwin", "Windows")
    assert isinstance(caps.explain(), str)
    for flag in (
        caps.filesystem_sandbox,
        caps.network_sandbox,
        caps.resource_limits,
        caps.process_kill,
    ):
        assert isinstance(flag, bool)
    # can_contain implies a backend binary was located.
    if caps.can_contain:
        assert caps.core_binary is not None


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


@uncovered
def test_fail_closed_when_uncovered(tmp_path):
    policy = base_policy(tmp_path)
    with pytest.raises(ContainmentUnavailable) as exc:
        sandbox.run([sys.executable, "-c", "print('x')"], policy=policy, tool="run_shell")
    assert exc.value.decision.rule == "containment_unavailable"


@uncovered
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


@uncovered
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


# --- real filesystem containment (Linux) -----------------------------------


@linux_contained
def test_contained_allows_write_inside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "ws" / "out" / "ok.txt")
    result = sandbox.run(["sh", "-c", f"echo hi > '{target}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert os.path.exists(target)


@linux_contained
def test_contained_blocks_read_outside(tmp_path):
    policy = base_policy(tmp_path)
    secret = str(tmp_path / "secret.txt")
    with open(secret, "w") as fh:
        fh.write("TOPSECRET")
    result = sandbox.run(["sh", "-c", f"cat '{secret}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert result.returncode != 0
    assert "TOPSECRET" not in result.stdout


@linux_contained
def test_contained_blocks_write_outside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "escape.txt")
    result = sandbox.run(["sh", "-c", f"echo pwned > '{target}'"], policy=policy, tool="run_shell")
    assert result.contained is True
    assert not os.path.exists(target)


@linux_contained
def test_probe_reports_landlock():
    caps = capabilities(refresh=True)
    assert caps.landlock_abi >= 1
    assert caps.seccomp is True
    assert caps.filesystem_sandbox is True


# --- Job Object containment (Windows) --------------------------------------


@windows_contained
def test_windows_resource_policy_runs_contained():
    # A resource-only policy is fully covered by the Job Object backend.
    result = sandbox.run(
        [sys.executable, "-c", "print('win-contained')"],
        policy=resource_policy(),
        tool="run_shell",
    )
    assert result.contained is True
    assert result.returncode == 0
    assert "win-contained" in result.stdout
    assert result.controls.get("backend") == "windows-appcontainer-job"


@windows_contained
def test_windows_contained_allows_workspace_read(tmp_path):
    policy = base_policy(tmp_path)
    ws_file = str(tmp_path / "ws" / "notes.txt")
    with open(ws_file, "w") as fh:
        fh.write("PUBLIC-workspace")
    result = sandbox.run(["cmd", "/c", "type", ws_file], policy=policy, tool="run_shell")
    assert result.contained is True
    assert "PUBLIC-workspace" in result.stdout


@windows_contained
def test_windows_contained_blocks_read_outside(tmp_path):
    policy = base_policy(tmp_path)
    secret = str(tmp_path / "secret.txt")
    with open(secret, "w") as fh:
        fh.write("TOPSECRET-win")
    result = sandbox.run(["cmd", "/c", "type", secret], policy=policy, tool="run_shell")
    assert result.contained is True
    assert result.returncode != 0
    assert "TOPSECRET-win" not in result.stdout


@windows_contained
def test_windows_contained_blocks_write_outside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "escape.txt")
    sandbox.run(["cmd", "/c", f"echo pwned > {target}"], policy=policy, tool="run_shell")
    assert not os.path.exists(target)


@windows_contained
def test_windows_probe_reports_backend():
    caps = capabilities(refresh=True)
    assert caps.backend == "windows-appcontainer-job"
    assert caps.filesystem_sandbox is True
    assert caps.network_sandbox is True
    assert caps.resource_limits is True
    assert caps.process_kill is True
