"""The single decision choke point: a tool name plus arguments, in; allow or deny, out.

Every enforcement path in Asphallea routes through :meth:`Interceptor.decide`. The
``@guard`` decorator, the MCP adapter, the LangChain adapter, and any integration
you write yourself all funnel here, so there is exactly one place where a policy
decision is made and exactly one place it is recorded.

The interceptor resolves which of a call's argument *values* are filesystem paths
or network targets using the mapping the policy declares for that tool (see
:class:`~asphallea.policy.ToolArgs`), then evaluates the deterministic rules in
:class:`~asphallea.engine.Engine`. That indirection is the point: because the
mapping lives in the policy rather than in Python at the call site, a policy can
govern a tool it did not author, which is what an MCP tool-call is.

There is no model anywhere in this path. The same tool name and arguments against
the same policy always produce the same decision.

    from asphallea import Interceptor, Policy

    policy = Policy.builder("agent").tool("filesystem.delete", writes="path").build()
    gate = Interceptor(policy)

    gate.decide("filesystem.delete", {"path": "/etc/passwd"})   # -> Decision(denied)
    gate.enforce("filesystem.delete", {"path": "/etc/passwd"})  # raises PolicyViolation
"""

from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

from .audit import AuditRecord, AuditSink
from .engine import Decision, Engine
from .errors import PolicyViolation
from .policy import Policy

__all__ = ["Interceptor"]


def _as_tuple(value: Union[str, Iterable[str], None]) -> tuple:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _values_for(arguments: Mapping[str, Any], names: Sequence[str]) -> List[str]:
    """Pull the values of ``names`` out of ``arguments`` as a flat list of strings.

    Missing and ``None`` arguments are skipped. A list-valued argument contributes
    each of its entries, so a tool taking ``paths=[a, b]`` is checked per path.
    """
    out: List[str] = []
    for name in names:
        if name not in arguments:
            continue
        value = arguments[name]
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            out.extend(str(v) for v in value)
        else:
            out.append(str(value))
    return out


class Interceptor:
    """Binds a policy (and optional audit sink) and decides tool calls.

    One interceptor owns one :class:`~asphallea.engine.Engine`, so call counts,
    rate limits, and spend caps accumulate across every tool it gates. Share a
    single interceptor across an agent's whole toolset.
    """

    def __init__(
        self,
        policy_or_engine: Union[Policy, Engine],
        *,
        audit: Optional[AuditSink] = None,
    ) -> None:
        """Create an interceptor over ``policy_or_engine``, recording to ``audit``."""
        self.engine = (
            policy_or_engine
            if isinstance(policy_or_engine, Engine)
            else Engine(policy_or_engine)
        )
        self.policy = self.engine.policy
        self.audit = audit

    # -- the choke point ---------------------------------------------------

    def decide(
        self,
        tool: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        reads: Union[str, Iterable[str], None] = None,
        writes: Union[str, Iterable[str], None] = None,
        network: bool = False,
    ) -> Decision:
        """Return the deterministic :class:`~asphallea.engine.Decision` for a call.

        Args:
            tool: The tool name, matched against the policy allowlist and denylist.
            arguments: The call's arguments by name. Values named by the policy's
                declared mapping for this tool are checked against the filesystem
                and network rules.
            reads: Extra argument names to treat as read paths for this call only,
                merged with what the policy declares.
            writes: Extra argument names to treat as write paths for this call only.
            network: Force this call to count as network-using, regardless of
                arguments. Used by callers that know a tool reaches the network.

        The decision is recorded to the audit sink before it is returned, so the
        trail contains denials and allows alike.
        """
        args: Mapping[str, Any] = arguments or {}
        declared = self.policy.args_for(tool)

        read_names = tuple(declared.reads) + _as_tuple(reads)
        write_names = tuple(declared.writes) + _as_tuple(writes)

        read_values = _values_for(args, read_names)
        write_values = _values_for(args, write_names)
        uses_network = bool(network) or bool(_values_for(args, declared.network))

        decision = self.engine.check(
            tool,
            reads=read_values,
            writes=write_values,
            network=uses_network,
        )
        self.record(tool, decision, args)
        return decision

    def enforce(
        self,
        tool: str,
        arguments: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Decision:
        """:meth:`decide`, raising :class:`PolicyViolation` when the call is denied."""
        decision = self.decide(tool, arguments, **kwargs)
        if decision.denied:
            raise PolicyViolation(decision, tool)
        return decision

    def allowed(self, tool: str, arguments: Optional[Mapping[str, Any]] = None, **kw) -> bool:
        """Convenience: True if the call is allowed. Still records the decision."""
        return self.decide(tool, arguments, **kw).allowed

    # -- audit -------------------------------------------------------------

    def record(
        self,
        tool: str,
        decision: Decision,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        tier: str = "policy",
        rule: Optional[str] = None,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Write one decision to the audit sink. No-op when no sink is configured.

        Exposed so callers can record events that are not a plain decide(), such as
        a wall-clock timeout, through the same trail.
        """
        if self.audit is None:
            return
        self.audit.write(
            AuditRecord(
                tool=tool,
                decision="allow" if decision.allowed else "deny",
                rule=rule if rule is not None else decision.rule,
                reason=decision.reason,
                tier=tier,
                args=[],
                kwargs=dict(arguments or {}),
                policy=self.policy.name,
                detail=dict(detail) if detail is not None else None,
            )
        )
