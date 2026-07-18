"""Deterministic allow/deny evaluation.

The :class:`Engine` holds a :class:`~asphallea.policy.Policy` and the small amount
of mutable state the policy needs at runtime: per-tool call counts, sliding rate
windows, and spend tallies. Its one job is :meth:`Engine.check`, which returns a
:class:`Decision` for a proposed tool call.

Evaluation is deterministic and order-fixed. Deny wins, and the first failing rule
is the one reported, so an audit line always names the exact reason a call was
stopped. Counters are only advanced when a call is allowed, and the whole check is
atomic under a lock, so a denied call never consumes rate or spend budget and
concurrent calls cannot corrupt the tallies.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Sequence

from .policy import Policy

__all__ = ["Engine", "Decision"]


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating a proposed tool call.

    Attributes:
        allowed: True if the call may proceed.
        rule: The rule that decided the outcome, for example ``"read_paths"``.
            ``"allow"`` when nothing denied.
        reason: Human-readable explanation, recorded in the audit line.
    """

    allowed: bool
    rule: str
    reason: str

    @property
    def denied(self) -> bool:
        """True if the call was denied."""
        return not self.allowed

    @classmethod
    def allow(cls, reason: str = "all rules passed") -> "Decision":
        """Construct an allow decision."""
        return cls(True, "allow", reason)

    @classmethod
    def deny(cls, rule: str, reason: str) -> "Decision":
        """Construct a deny decision naming the ``rule`` that fired."""
        return cls(False, rule, reason)


class Engine:
    """Evaluates tool calls against a policy and tracks runtime counters.

    One engine instance owns the counters for one running agent. Share it across
    every guard that enforces the same policy so that call counts, rate limits,
    and spend caps are counted globally rather than per-tool-wrapper.
    """

    def __init__(self, policy: Policy) -> None:
        """Create an engine bound to ``policy`` with fresh, empty counters."""
        self.policy = policy
        self._lock = threading.Lock()
        self._call_counts: Dict[str, int] = defaultdict(int)
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._spend_counts: Dict[str, int] = defaultdict(int)

    def check(
        self,
        tool: str,
        *,
        reads: Sequence[str] = (),
        writes: Sequence[str] = (),
        network_targets: Sequence[str] = (),
        network: bool = False,
        now: Optional[float] = None,
    ) -> Decision:
        """Evaluate a proposed call to ``tool`` and return a :class:`Decision`.

        Args:
            tool: The tool name being called.
            reads: Filesystem paths this call will read. Checked against the
                policy read allowlist.
            writes: Filesystem paths this call will write. Checked against the
                policy write allowlist.
            network_targets: Network destinations this call will reach (URLs or
                hosts). Each is checked against the policy host rules.
            network: Force this call to count as network-using with an unknown
                host, decided by the policy default. Use when a tool reaches the
                network but exposes no target argument.
            now: Monotonic timestamp override for rate-window tests.

        The call's counters advance only if the decision is allow. The method is
        atomic under an internal lock.
        """
        policy = self.policy
        clock = time.monotonic() if now is None else now

        with self._lock:
            # 1. tool allowlist
            if not policy.tool_allowed(tool):
                return Decision.deny(
                    "tool_allowlist", f"tool {tool!r} is not in the allowed set"
                )

            # 2. filesystem reads
            for path in reads:
                if not _within_any(path, policy.read_paths):
                    return Decision.deny(
                        "read_paths",
                        f"read path {path!r} is not under an allowed read prefix",
                    )

            # 3. filesystem writes
            for path in writes:
                if not _within_any(path, policy.write_paths):
                    return Decision.deny(
                        "write_paths",
                        f"write path {path!r} is not under an allowed write prefix",
                    )

            # 4. network: each declared target is checked against the host rules;
            # a forced network flag with no target is decided by the default.
            targets = list(network_targets)
            if network and not targets:
                targets = [None]
            for target in targets:
                if not policy.network_allowed(target):
                    if target is None:
                        reason = f"tool {tool!r} uses the network but network is denied"
                    else:
                        reason = f"network target {target!r} is not allowed by the host rules"
                    return Decision.deny("network", reason)

            # 5. per-tool max calls
            if tool in policy.max_calls:
                if self._call_counts[tool] >= policy.max_calls[tool]:
                    return Decision.deny(
                        "max_calls",
                        f"tool {tool!r} reached its call limit of {policy.max_calls[tool]}",
                    )

            # 6. rate limit (sliding window)
            rl = policy.rate_limits.get(tool)
            if rl is not None:
                window = self._rate_events[tool]
                cutoff = clock - rl.window_seconds
                while window and window[0] <= cutoff:
                    window.popleft()
                if len(window) >= rl.max_calls:
                    return Decision.deny(
                        "rate_limit",
                        f"tool {tool!r} exceeded {rl.max_calls} calls per {rl.window_seconds:g}s",
                    )

            # 7. spend cap (paid-tool invocation ceiling)
            if tool in policy.spend_caps:
                if self._spend_counts[tool] >= policy.spend_caps[tool]:
                    return Decision.deny(
                        "spend_cap",
                        f"tool {tool!r} reached its spend cap of {policy.spend_caps[tool]} invocations",
                    )

            # Allowed. Commit all counters atomically.
            self._call_counts[tool] += 1
            if rl is not None:
                self._rate_events[tool].append(clock)
            if tool in policy.spend_caps:
                self._spend_counts[tool] += 1

            return Decision.allow()

    def snapshot(self) -> Dict[str, Dict[str, int]]:
        """Return a copy of current counters for introspection and tests."""
        with self._lock:
            return {
                "calls": dict(self._call_counts),
                "spend": dict(self._spend_counts),
                "rate_window_sizes": {k: len(v) for k, v in self._rate_events.items()},
            }


def _within_any(path: str, prefixes: Sequence[str]) -> bool:
    """Return whether ``path`` resolves to a location under one of ``prefixes``.

    Both sides are made absolute, user-expanded, symlink-resolved, and case
    normalized before comparison so the boundary cannot be crossed by ``..``, a
    home shortcut, a symlink, or case tricks on case-insensitive filesystems.
    """
    real = os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(path))))
    for prefix in prefixes:
        norm_prefix = os.path.normcase(prefix)
        try:
            if os.path.commonpath([real, norm_prefix]) == norm_prefix:
                return True
        except ValueError:
            # Different drives on Windows, or a mix that cannot be compared.
            continue
    return False
