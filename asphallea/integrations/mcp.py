"""Guard MCP (Model Context Protocol) tool-calls with an Asphallea policy.

An MCP tool-call is a tool name and a dictionary of arguments, which is exactly
the shape :meth:`asphallea.intercept.Interceptor.decide` takes. This adapter is
therefore thin: it intercepts ``call_tool(name, arguments)``, asks the policy, and
either forwards the call or blocks it. The tool never runs when the policy says no.

This matters because you do not author the tools an MCP server exposes. The policy
declares how each tool's arguments map to resources, so it can govern a server it
has never seen::

    policy = (
        Policy.builder("agent")
        .tool("filesystem.read", reads="path")
        .tool("filesystem.delete", writes="path")
        .read_paths("./workspace")
        .write_paths("./workspace/out")
        .build()
    )
    session = guard_mcp_session(session, policy, audit=AuditLog("audit.jsonl"))
    # every session.call_tool(...) is now decided before it runs

Both sides of the protocol have the same signature, so :func:`guard_call_tool`
wraps a client's ``call_tool`` or a server's tool-call handler equally.

The adapter is duck-typed and does not import the ``mcp`` package, so it works and
is testable without that dependency installed.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Mapping, Optional, Union

from ..audit import AuditSink
from ..engine import Decision, Engine
from ..errors import PolicyViolation
from ..intercept import Interceptor
from ..policy import Policy

__all__ = [
    "guard_mcp_session",
    "guard_call_tool",
    "GuardedSession",
    "denial_result",
]

_ON_DENY = ("raise", "error")


def denial_result(decision: Decision, tool: str) -> Dict[str, Any]:
    """Build an MCP-shaped error result describing a denial.

    Returned instead of raising when ``on_deny="error"``, so an agent loop sees a
    normal tool error, learns it may not do that, and keeps running. The shape
    matches an MCP ``CallToolResult`` with ``isError`` set.
    """
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": (
                    f"[asphallea] denied {tool}: {decision.reason} "
                    f"(rule={decision.rule})"
                ),
            }
        ],
    }


def _as_interceptor(
    policy_or_interceptor: Union[Policy, Engine, Interceptor],
    audit: Optional[AuditSink],
) -> Interceptor:
    if isinstance(policy_or_interceptor, Interceptor):
        return policy_or_interceptor
    return Interceptor(policy_or_interceptor, audit=audit)


def _policy_tool_name(name: str, namespace: Optional[str]) -> str:
    """The name the policy sees. A namespace keeps servers apart in one policy."""
    return f"{namespace}.{name}" if namespace else name


def _handle_denial(on_deny: str, decision: Decision, tool: str) -> Dict[str, Any]:
    if on_deny == "raise":
        raise PolicyViolation(decision, tool)
    return denial_result(decision, tool)


def guard_call_tool(
    call_tool: Callable[..., Any],
    policy_or_interceptor: Union[Policy, Engine, Interceptor],
    *,
    audit: Optional[AuditSink] = None,
    on_deny: str = "raise",
    namespace: Optional[str] = None,
) -> Callable[..., Any]:
    """Wrap a ``call_tool(name, arguments)`` callable so the policy decides first.

    Works for an MCP client's ``call_tool`` and for a server-side tool-call
    handler, sync or async. The wrapped callable keeps its signature.

    Args:
        call_tool: The callable to wrap.
        policy_or_interceptor: A policy, a shared engine, or an existing
            interceptor. Pass one interceptor across servers to share call, rate,
            and spend limits.
        audit: Where to record decisions. Ignored when an interceptor is passed.
        on_deny: ``"raise"`` to raise :class:`PolicyViolation`, or ``"error"`` to
            return an MCP error result and let the agent continue.
        namespace: Optional prefix for the policy tool name, so two servers
            exposing ``read`` can be governed separately.
    """
    if on_deny not in _ON_DENY:
        raise ValueError(f"on_deny must be one of {_ON_DENY}, got {on_deny!r}")
    gate = _as_interceptor(policy_or_interceptor, audit)

    if inspect.iscoroutinefunction(call_tool):

        @functools.wraps(call_tool)
        async def async_wrapper(name: str, arguments: Optional[Mapping[str, Any]] = None,
                                *args: Any, **kwargs: Any) -> Any:
            decision = gate.decide(_policy_tool_name(name, namespace), arguments or {})
            if decision.denied:
                return _handle_denial(on_deny, decision, name)
            return await call_tool(name, arguments, *args, **kwargs)

        return async_wrapper

    @functools.wraps(call_tool)
    def sync_wrapper(name: str, arguments: Optional[Mapping[str, Any]] = None,
                     *args: Any, **kwargs: Any) -> Any:
        decision = gate.decide(_policy_tool_name(name, namespace), arguments or {})
        if decision.denied:
            return _handle_denial(on_deny, decision, name)
        return call_tool(name, arguments, *args, **kwargs)

    return sync_wrapper


class GuardedSession:
    """An MCP client session whose ``call_tool`` is decided by a policy.

    Every other attribute (``list_tools``, ``initialize``, ``read_resource``, and
    anything else the session exposes) passes straight through, so this is a
    drop-in replacement for the session you already hold.
    """

    def __init__(
        self,
        session: Any,
        policy_or_interceptor: Union[Policy, Engine, Interceptor],
        *,
        audit: Optional[AuditSink] = None,
        on_deny: str = "raise",
        namespace: Optional[str] = None,
    ) -> None:
        """Wrap ``session``. See :func:`guard_call_tool` for the arguments."""
        if on_deny not in _ON_DENY:
            raise ValueError(f"on_deny must be one of {_ON_DENY}, got {on_deny!r}")
        self._session = session
        self._gate = _as_interceptor(policy_or_interceptor, audit)
        self._on_deny = on_deny
        self._namespace = namespace

    @property
    def interceptor(self) -> Interceptor:
        """The interceptor deciding this session's calls."""
        return self._gate

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Decide, then forward to the wrapped session. The tool never runs on deny."""
        decision = self._gate.decide(
            _policy_tool_name(name, self._namespace), arguments or {}
        )
        if decision.denied:
            return _handle_denial(self._on_deny, decision, name)
        result = self._session.call_tool(name, arguments, *args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result

    def __getattr__(self, item: str) -> Any:
        # Only reached for attributes we do not define; delegate to the session.
        return getattr(self._session, item)

    def __repr__(self) -> str:
        return f"GuardedSession({self._session!r}, policy={self._gate.policy.name!r})"


def guard_mcp_session(
    session: Any,
    policy_or_interceptor: Union[Policy, Engine, Interceptor],
    *,
    audit: Optional[AuditSink] = None,
    on_deny: str = "raise",
    namespace: Optional[str] = None,
) -> GuardedSession:
    """Wrap an MCP client session. See :class:`GuardedSession`."""
    return GuardedSession(
        session,
        policy_or_interceptor,
        audit=audit,
        on_deny=on_deny,
        namespace=namespace,
    )
