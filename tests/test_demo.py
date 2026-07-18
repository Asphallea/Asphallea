"""Tests for the consolidated injection demo (the launch asset).

The demo is criterion #5, so it gets asserted, not just eyeballed. We load its
functions directly to check the invariants (attack blocked, file intact, tool
never invoked), and we run the whole script as a subprocess to prove it finishes
clean and prints the promised result.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_PATH = ROOT / "examples" / "demo.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("asphallea_demo", DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = _load_demo()


def test_guarded_run_blocks_every_injected_call():
    arena = demo.build_arena()
    try:
        server = demo.FilesystemServer()
        outcomes = asyncio.run(demo.run_guarded(arena, server))

        # Every injected tool-call is blocked, by the expected rule.
        assert all(blocked for _, blocked, _ in outcomes)
        rules = {name: rule for name, blocked, rule in outcomes}
        assert rules["filesystem.read"] == "read_paths"
        assert rules["filesystem.delete"] == "write_paths"

        # Sandbox intact: the protected file survives and the server never ran.
        assert os.path.exists(arena["production"]), "the database must survive"
        assert server.calls == [], "a blocked tool-call must never reach the server"
    finally:
        demo._rmtree(arena["root"])


def test_unguarded_run_shows_the_attack_succeeding():
    # The contrast half of the demo must actually be dangerous, or the block proves
    # nothing.
    arena = demo.build_arena()
    try:
        server = demo.FilesystemServer()
        asyncio.run(demo.run_unguarded(arena, server))
        assert not os.path.exists(arena["production"]), "unguarded, the delete happens"
        assert ("filesystem.read", {"path": arena["secret"]}) in server.calls
    finally:
        demo._rmtree(arena["root"])


def test_decision_is_deterministic_across_runs():
    # Same injected call, same policy, same decision, many times over.
    arena = demo.build_arena()
    try:
        seen = set()
        for _ in range(20):
            server = demo.FilesystemServer()
            outcomes = asyncio.run(demo.run_guarded(arena, server))
            seen.add(tuple(outcomes))
            assert os.path.exists(arena["production"])
        assert len(seen) == 1, "enforcement must be deterministic"
    finally:
        demo._rmtree(arena["root"])


def test_demo_script_runs_clean_end_to_end():
    proc = subprocess.run(
        [sys.executable, str(DEMO_PATH)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"demo exited {proc.returncode}\n{proc.stderr}"
    out = proc.stdout
    assert "BLOCKED by policy" in out
    assert "sandbox intact" in out
    assert "production.db present : True" in out
    assert "credential unread    : True" in out
    assert "server tools invoked : 0" in out
