"""The guard: least-privilege interception at the tool-call boundary.

:func:`guard` wraps a tool (any callable) so that every invocation is checked
against a policy before it runs, logged, and either allowed through or denied. It
is the framework-neutral core of Asphallea. Adapters for specific agent frameworks
are thin shims over this.

Usage as a decorator::

    @guard(policy, tool="read_file", reads="path", audit=audit)
    def read_file(path: str) -> str:
        ...

Usage as a wrapper::

    safe_search = guard(policy, tool="search", network=True, audit=audit)(search)

Sync and async callables are both supported. If the policy sets a wall-clock
timeout, the guard enforces it around the call.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import threading
from typing import Any, Callable, List, Optional, Sequence, Union

from .audit import AuditRecord, AuditSink
from .engine import Decision, Engine
from .policy import Policy

__all__ = ["guard", "PolicyViolation", "PolicyTimeout"]

_MISSING = object()

# A path spec names which parameters carry filesystem paths: a parameter name, a
# positional index, or a list mixing both.
PathSpec = Union[str, int, Sequence[Union[str, int]], None]


class PolicyViolation(Exception):
    """Raised when a guarded tool call is denied by policy.

    Attributes:
        decision: The :class:`~asphallea.engine.Decision` that denied the call.
        tool: The tool name that was denied.
    """

    def __init__(self, decision: Decision, tool: str) -> None:
        self.decision = decision
        self.tool = tool
        super().__init__(
            f"asphallea denied {tool!r}: {decision.reason} (rule={decision.rule})"
        )


class PolicyTimeout(PolicyViolation):
    """Raised when a guarded tool call exceeds the policy wall-clock timeout."""


def guard(
    policy_or_engine: Union[Policy, Engine],
    *,
    tool: str,
    reads: PathSpec = None,
    writes: PathSpec = None,
    network: bool = False,
    audit: Optional[AuditSink] = None,
    timeout: Optional[float] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return a decorator that enforces ``policy`` around a tool callable.

    Args:
        policy_or_engine: A :class:`~asphallea.policy.Policy` or a shared
            :class:`~asphallea.engine.Engine`. Pass a shared engine to count call
            limits, rate limits, and spend caps across several tools. Passing a
            policy creates a private engine for this one tool.
        tool: The tool name recorded in the audit trail and matched against the
            policy tool allowlist.
        reads: Which call parameters carry paths the tool reads. Checked against
            the policy read allowlist. A name, an index, or a list of them.
        writes: Which call parameters carry paths the tool writes. Checked
            against the policy write allowlist.
        network: Whether this tool uses the network. Denied when the policy
            denies network.
        audit: Where to record decisions. Defaults to no audit sink, which still
            enforces but keeps no trail. Pass an :class:`~asphallea.audit.AuditLog`
            to keep one.
        timeout: Wall-clock ceiling in seconds, overriding the policy timeout for
            this tool.

    Returns:
        A decorator. Applying it to a callable returns a wrapped callable with the
        same signature that enforces the policy on every call.
    """
    engine = policy_or_engine if isinstance(policy_or_engine, Engine) else Engine(policy_or_engine)
    policy = engine.policy
    effective_timeout = timeout if timeout is not None else policy.timeout_seconds

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        read_names = _spec_to_list(reads)
        write_names = _spec_to_list(writes)

        def evaluate(args: tuple, kwargs: dict) -> Decision:
            reads_resolved = _resolve_paths(fn, args, kwargs, read_names)
            writes_resolved = _resolve_paths(fn, args, kwargs, write_names)
            return engine.check(
                tool,
                reads=reads_resolved,
                writes=writes_resolved,
                network=network,
            )

        def record(decision: Decision, args: tuple, kwargs: dict, tier: str = "policy",
                   reason: Optional[str] = None, rule: Optional[str] = None) -> None:
            if audit is None:
                return
            audit.write(
                AuditRecord(
                    tool=tool,
                    decision="allow" if decision.allowed else "deny",
                    rule=rule if rule is not None else decision.rule,
                    reason=reason if reason is not None else decision.reason,
                    tier=tier,
                    args=list(args),
                    kwargs=dict(kwargs),
                    policy=policy.name,
                )
            )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                decision = evaluate(args, kwargs)
                record(decision, args, kwargs)
                if decision.denied:
                    raise PolicyViolation(decision, tool)
                if effective_timeout is None:
                    return await fn(*args, **kwargs)
                try:
                    return await asyncio.wait_for(fn(*args, **kwargs), effective_timeout)
                except asyncio.TimeoutError:
                    timeout_decision = Decision.deny(
                        "timeout", f"tool {tool!r} exceeded timeout of {effective_timeout:g}s"
                    )
                    record(timeout_decision, args, kwargs)
                    raise PolicyTimeout(timeout_decision, tool) from None

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = evaluate(args, kwargs)
            record(decision, args, kwargs)
            if decision.denied:
                raise PolicyViolation(decision, tool)
            if effective_timeout is None:
                return fn(*args, **kwargs)
            return _run_with_timeout(fn, args, kwargs, effective_timeout, tool, record)

        return sync_wrapper

    return decorator


def _run_with_timeout(fn, args, kwargs, timeout, tool, record):
    """Run ``fn`` in a worker thread with a join deadline.

    A pure Python callable cannot be force killed, so on timeout the worker
    thread is abandoned and a :class:`PolicyTimeout` is raised to the caller. This
    is documented, best-effort enforcement. The containment tier enforces hard
    wall-clock and CPU limits for subprocess tools where it matters most.
    """
    holder: dict = {}

    def target() -> None:
        try:
            holder["result"] = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - propagate to caller thread
            holder["error"] = exc

    worker = threading.Thread(target=target, daemon=True, name=f"asphallea-{tool}")
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        decision = Decision.deny("timeout", f"tool {tool!r} exceeded timeout of {timeout:g}s")
        record(decision, args, kwargs)
        raise PolicyTimeout(decision, tool)
    if "error" in holder:
        raise holder["error"]
    return holder.get("result")


def _spec_to_list(spec: PathSpec) -> List[Union[str, int]]:
    if spec is None:
        return []
    if isinstance(spec, (str, int)):
        return [spec]
    return list(spec)


def _resolve_paths(fn, args: tuple, kwargs: dict, names: Sequence[Union[str, int]]) -> List[str]:
    """Extract path values named by ``names`` from a call's arguments.

    Names may be parameter names or positional indices. A resolved value may be a
    single path string or an iterable of path strings. Missing and ``None`` values
    are skipped. Falls back to raw positional and keyword access when the callable
    has no inspectable signature.
    """
    if not names:
        return []

    bound_arguments = None
    param_names: List[str] = []
    try:
        sig = inspect.signature(fn)
        param_names = list(sig.parameters)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        bound_arguments = bound.arguments
    except (TypeError, ValueError):
        bound_arguments = None

    values: List[str] = []
    for name in names:
        raw = _MISSING
        if isinstance(name, int):
            if bound_arguments is not None and 0 <= name < len(param_names):
                raw = bound_arguments.get(param_names[name], _MISSING)
            elif name < len(args):
                raw = args[name]
        else:
            if bound_arguments is not None and name in bound_arguments:
                raw = bound_arguments[name]
            elif name in kwargs:
                raw = kwargs[name]
        if raw is _MISSING or raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(v) for v in raw)
        else:
            values.append(str(raw))
    return values
