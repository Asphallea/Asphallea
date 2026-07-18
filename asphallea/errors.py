"""Exceptions raised when a policy denies or interrupts a tool call.

These live in their own module so every enforcement path (the interceptor, the
guard decorator, the sandbox, the framework adapters) can raise the same types
without importing each other.
"""

from __future__ import annotations

from .engine import Decision

__all__ = ["PolicyViolation", "PolicyTimeout"]


class PolicyViolation(Exception):
    """Raised when a tool call is denied by policy.

    Attributes:
        decision: The :class:`~asphallea.engine.Decision` that denied the call,
            carrying the rule that fired and a human-readable reason.
        tool: The tool name that was denied.
    """

    def __init__(self, decision: Decision, tool: str) -> None:
        self.decision = decision
        self.tool = tool
        super().__init__(
            f"asphallea denied {tool!r}: {decision.reason} (rule={decision.rule})"
        )


class PolicyTimeout(PolicyViolation):
    """Raised when a tool call exceeds the policy wall-clock timeout."""
