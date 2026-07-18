"""The guard decorator: least-privilege interception around a Python callable.

:func:`guard` wraps a tool so every invocation is decided before it runs. It is a
thin adapter over the single choke point in :mod:`asphallea.intercept`: it binds
the call's positional and keyword arguments into a name-to-value mapping and hands
that to :meth:`~asphallea.intercept.Interceptor.decide`. All the policy logic and
all the audit recording live there, so a decorated function, an MCP tool-call, and
a LangChain tool are decided by exactly the same code.

Usage as a decorator::

    @guard(policy, tool="read_file", reads="path", audit=audit)
    def read_file(path: str) -> str:
        ...

Usage as a wrapper::

    safe_search = guard(policy, tool="search", network=True)(search)

The ``reads``/``writes`` keywords name which parameters carry paths. They are a
per-call-site shorthand; the durable place to declare that mapping is the policy
itself (``Policy.builder(...).tool("read_file", reads="path")``), which is what
lets a policy govern tools it did not author. Both sources are merged.

Sync and async callables are both supported. If the policy sets a wall-clock
timeout, the guard enforces it around the call.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .audit import AuditSink
from .engine import Decision, Engine
from .errors import PolicyTimeout, PolicyViolation
from .intercept import Interceptor
from .policy import Policy

__all__ = ["guard", "PolicyViolation", "PolicyTimeout"]

# A path spec names which parameters carry filesystem paths: a parameter name, a
# positional index, or a list mixing both.
PathSpec = Union[str, int, Sequence[Union[str, int]], None]


def guard(
    policy_or_engine: Union[Policy, Engine, Interceptor],
    *,
    tool: str,
    reads: PathSpec = None,
    writes: PathSpec = None,
    network: bool = False,
    audit: Optional[AuditSink] = None,
    timeout: Optional[float] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return a decorator that enforces a policy around a tool callable.

    Args:
        policy_or_engine: A :class:`~asphallea.policy.Policy`, a shared
            :class:`~asphallea.engine.Engine`, or an existing
            :class:`~asphallea.intercept.Interceptor`. Pass a shared engine or
            interceptor to count call, rate, and spend limits across several tools.
        tool: The tool name, matched against the policy and recorded in the audit.
        reads: Which parameters carry paths the tool reads. A name, a positional
            index, or a list of them. Merged with the policy's declaration.
        writes: Which parameters carry paths the tool writes.
        network: Whether this tool reaches the network.
        audit: Where to record decisions. Ignored when an interceptor is passed,
            since that already carries its sink.
        timeout: Wall-clock ceiling in seconds, overriding the policy timeout.

    Returns:
        A decorator producing a wrapped callable with the same signature.
    """
    gate = (
        policy_or_engine
        if isinstance(policy_or_engine, Interceptor)
        else Interceptor(policy_or_engine, audit=audit)
    )
    effective_timeout = timeout if timeout is not None else gate.policy.timeout_seconds

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        read_spec = _spec_to_list(reads)
        write_spec = _spec_to_list(writes)

        def evaluate(args: tuple, kwargs: dict) -> Tuple[Decision, Dict[str, Any]]:
            arguments, read_names, write_names = _bind_call(
                fn, args, kwargs, read_spec, write_spec
            )
            decision = gate.decide(
                tool,
                arguments,
                reads=read_names,
                writes=write_names,
                network=network,
            )
            return decision, arguments

        def on_timeout(arguments: Dict[str, Any]) -> PolicyTimeout:
            decision = Decision.deny(
                "timeout", f"tool {tool!r} exceeded timeout of {effective_timeout:g}s"
            )
            gate.record(tool, decision, arguments)
            return PolicyTimeout(decision, tool)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                decision, arguments = evaluate(args, kwargs)
                if decision.denied:
                    raise PolicyViolation(decision, tool)
                if effective_timeout is None:
                    return await fn(*args, **kwargs)
                try:
                    return await asyncio.wait_for(fn(*args, **kwargs), effective_timeout)
                except asyncio.TimeoutError:
                    raise on_timeout(arguments) from None

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            decision, arguments = evaluate(args, kwargs)
            if decision.denied:
                raise PolicyViolation(decision, tool)
            if effective_timeout is None:
                return fn(*args, **kwargs)
            return _run_with_timeout(fn, args, kwargs, effective_timeout, tool, on_timeout, arguments)

        return sync_wrapper

    return decorator


def _run_with_timeout(fn, args, kwargs, timeout, tool, on_timeout, arguments):
    """Run ``fn`` in a worker thread with a join deadline.

    A pure Python callable cannot be force killed, so on timeout the worker thread
    is abandoned and a :class:`PolicyTimeout` is raised to the caller. This is
    documented, best-effort enforcement. The containment tier enforces hard
    wall-clock and CPU limits for subprocess tools, where it matters most.
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
        raise on_timeout(arguments)
    if "error" in holder:
        raise holder["error"]
    return holder.get("result")


def _spec_to_list(spec: PathSpec) -> List[Union[str, int]]:
    if spec is None:
        return []
    if isinstance(spec, (str, int)):
        return [spec]
    return list(spec)


def _bind_call(
    fn: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    read_spec: Sequence[Union[str, int]],
    write_spec: Sequence[Union[str, int]],
) -> Tuple[Dict[str, Any], Tuple[str, ...], Tuple[str, ...]]:
    """Bind a call into a name-to-value mapping and resolve index specs to names.

    The interceptor works on named arguments, which is the shape an MCP tool-call
    already has. A decorated Python function is bound to that shape here, so both
    reach the choke point identically. Positional index specs (``reads=0``) are
    resolved against the signature. Callables with no inspectable signature fall
    back to positional names (``arg0``, ``arg1``).
    """
    arguments: Dict[str, Any]
    param_names: List[str]
    try:
        signature = inspect.signature(fn)
        param_names = list(signature.parameters)
        bound = signature.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
    except (TypeError, ValueError):
        arguments = dict(kwargs)
        param_names = []
        for index, value in enumerate(args):
            name = f"arg{index}"
            arguments[name] = value
            param_names.append(name)

    def resolve(spec: Sequence[Union[str, int]]) -> Tuple[str, ...]:
        names: List[str] = []
        for item in spec:
            if isinstance(item, int):
                if 0 <= item < len(param_names):
                    names.append(param_names[item])
            else:
                names.append(item)
        return tuple(names)

    return arguments, resolve(read_spec), resolve(write_spec)
