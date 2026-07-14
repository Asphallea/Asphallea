"""Asphallea: a security runtime that contains what your AI agent can do.

Least-privilege sandboxing and a full audit trail for agent tool-execution, so a
hijacked agent cannot wreck your systems.

Two enforcement tiers wrap the tool-execution boundary:

* the policy tier (:func:`guard`, :class:`Engine`) intercepts every tool call,
  checks it against a declarative :class:`Policy`, allows or denies it
  deterministically, and records the decision. It works on Linux, macOS, and
  Windows.
* the containment tier (:mod:`asphallea.sandbox`) runs high-blast-radius tools
  under real OS enforcement on Linux: a Landlock filesystem allowlist, seccomp-bpf
  syscall and network filtering, and resource limits.

Quickstart::

    from asphallea import Policy, guard, AuditLog

    policy = (
        Policy.builder("least-privilege")
        .allow_tools("read_file")
        .read_paths("./workspace")
        .deny_network()
        .build()
    )

    @guard(policy, tool="read_file", reads="path", audit=AuditLog("audit.jsonl"))
    def read_file(path: str) -> str:
        with open(path) as fh:
            return fh.read()
"""

from __future__ import annotations

from . import sandbox
from .audit import (
    AuditLog,
    AuditRecord,
    AuditSink,
    NullAuditLog,
    StreamAuditLog,
    default_redactor,
    no_redaction,
)
from .engine import Decision, Engine
from .guard import PolicyTimeout, PolicyViolation, guard
from .integrity import IntegrityError, IntegrityResult, verify_core
from .policy import Policy, PolicyBuilder, PolicyError, RateLimit, ResourceLimits
from .sandbox import Capabilities, ContainmentUnavailable, SandboxResult, capabilities

__version__ = "0.0.1"

__all__ = [
    "__version__",
    # policy
    "Policy",
    "PolicyBuilder",
    "PolicyError",
    "RateLimit",
    "ResourceLimits",
    # engine
    "Engine",
    "Decision",
    # guard
    "guard",
    "PolicyViolation",
    "PolicyTimeout",
    # audit
    "AuditLog",
    "StreamAuditLog",
    "NullAuditLog",
    "AuditRecord",
    "AuditSink",
    "default_redactor",
    "no_redaction",
    # containment
    "sandbox",
    "capabilities",
    "Capabilities",
    "SandboxResult",
    "ContainmentUnavailable",
    # integrity
    "IntegrityError",
    "IntegrityResult",
    "verify_core",
]
