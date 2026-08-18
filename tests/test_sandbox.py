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
IS_MACOS = platform.system() == "Darwin"

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
macos_contained = pytest.mark.skipif(
    not (IS_MACOS and CAPS.can_contain),
    reason="requires the macOS Seatbelt backend",
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


# --- policy composition: containment matches what the policy asked for ------
#
# Regression coverage for the 0.1.0 bug where the Linux core applied Landlock on
# every run, including for policies that declared no filesystem paths. Because
# Landlock is an allowlist and the baseline grants cover only system directories,
# a network-only policy silently lost access to $HOME: user files, project files,
# and virtualenv interpreters. The Python SDK and the Rust core disagreed about
# what an empty filesystem policy meant, so these tests assert the contract from
# both sides.


def network_only_policy():
    return Policy.builder("network-only").allow_tools("run_shell").deny_network().build()


@linux_contained
def test_network_only_policy_does_not_restrict_filesystem(tmp_path):
    # A file outside any allowlist, because there is no allowlist to be outside of.
    target = tmp_path / "ordinary.txt"
    target.write_text("ORDINARY-CONTENT", encoding="utf-8")
    policy = network_only_policy()
    assert policy.read_paths == ()
    assert policy.write_paths == ()

    result = sandbox.run(["/bin/cat", str(target)], policy=policy, tool="run_shell")

    assert result.contained is True
    assert result.returncode == 0
    assert "ORDINARY-CONTENT" in result.stdout


@linux_contained
def test_no_filesystem_policy_reports_landlock_not_requested(tmp_path):
    # The core must say it did not restrict, rather than reporting a Landlock state
    # that implies it tried and failed.
    result = sandbox.run(["/bin/true"], policy=network_only_policy(), tool="run_shell")
    assert result.controls["landlock_status"] == "not_requested"
    assert result.controls["landlock_abi"] >= 1  # the kernel supports it; nothing to do
    assert result.contained is True


@linux_contained
def test_network_only_policy_still_denies_network():
    # The fix must not cost the containment the policy did ask for.
    result = sandbox.run(
        [
            sys.executable,
            "-c",
            "import socket; s=socket.socket(); s.settimeout(5);"
            " s.connect(('1.1.1.1', 80)); print('CONNECTED')",
        ],
        policy=network_only_policy(),
        tool="run_shell",
    )
    assert result.returncode != 0
    assert "CONNECTED" not in result.stdout


@linux_contained
def test_network_only_policy_can_launch_a_virtualenv_interpreter():
    # sys.executable is the running interpreter, which under a virtualenv lives in
    # the project tree and reads pyvenv.cfg at startup. The 0.1.0 core denied that
    # read, so Python died before running anything.
    result = sandbox.run(
        [sys.executable, "-c", "print('INTERPRETER-STARTED')"],
        policy=network_only_policy(),
        tool="run_shell",
    )
    assert result.returncode == 0
    assert "INTERPRETER-STARTED" in result.stdout


@linux_contained
def test_resource_only_policy_does_not_restrict_filesystem(tmp_path):
    target = tmp_path / "resource.txt"
    target.write_text("RESOURCE-ONLY", encoding="utf-8")
    policy = (
        Policy.builder("resource-only")
        .allow_tools("run_shell")
        .allow_network()
        .limits(memory_mb=256)
        .build()
    )

    result = sandbox.run(["/bin/cat", str(target)], policy=policy, tool="run_shell")

    assert result.returncode == 0
    assert "RESOURCE-ONLY" in result.stdout
    assert result.controls["landlock_status"] == "not_requested"


@linux_contained
def test_filesystem_policy_still_enforces_landlock(tmp_path):
    # The other half of the contract: asking for filesystem containment must still
    # get it, and must still deny what is outside the allowlist.
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "inside.txt").write_text("INSIDE", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
    policy = (
        Policy.builder("fs")
        .allow_tools("run_shell")
        .read_paths(str(ws))
        .deny_network()
        .build()
    )

    allowed = sandbox.run(["/bin/cat", str(ws / "inside.txt")], policy=policy, tool="run_shell")
    denied = sandbox.run(["/bin/cat", str(outside)], policy=policy, tool="run_shell")

    assert allowed.returncode == 0
    assert "INSIDE" in allowed.stdout
    assert allowed.controls["landlock_status"] in {"fully_enforced", "partially_enforced"}
    assert denied.returncode != 0
    assert "OUTSIDE-SECRET" not in denied.stdout


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


# --- Seatbelt containment (macOS) ------------------------------------------


@macos_contained
def test_macos_contained_allows_workspace_read(tmp_path):
    policy = base_policy(tmp_path)
    ws_file = str(tmp_path / "ws" / "notes.txt")
    with open(ws_file, "w") as fh:
        fh.write("PUBLIC-mac")
    result = sandbox.run(["/bin/cat", ws_file], policy=policy, tool="run_shell")
    assert result.contained is True
    assert "PUBLIC-mac" in result.stdout


@macos_contained
def test_macos_contained_blocks_read_outside(tmp_path):
    policy = base_policy(tmp_path)
    secret = str(tmp_path / "secret.txt")
    with open(secret, "w") as fh:
        fh.write("TOPSECRET-mac")
    result = sandbox.run(["/bin/cat", secret], policy=policy, tool="run_shell")
    assert result.contained is True
    assert result.returncode != 0
    assert "TOPSECRET-mac" not in result.stdout


@macos_contained
def test_macos_contained_blocks_write_outside(tmp_path):
    policy = base_policy(tmp_path)
    target = str(tmp_path / "escape.txt")
    sandbox.run(["/bin/sh", "-c", f"echo pwned > {target}"], policy=policy, tool="run_shell")
    assert not os.path.exists(target)


@macos_contained
def test_macos_probe_reports_backend():
    caps = capabilities(refresh=True)
    assert caps.backend == "macos-seatbelt"
    assert caps.filesystem_sandbox is True
    assert caps.network_sandbox is True
