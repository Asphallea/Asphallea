"""Wrap LangChain and LangGraph tools with an Asphallea policy.

LangChain tools (``BaseTool`` instances, ``@tool``-decorated functions, and
``StructuredTool``) are invoked through ``invoke`` / ``ainvoke`` (and the older
``run`` / ``arun``). This adapter returns a drop-in stand-in that runs every
invocation through the policy engine first, records the decision, and either
delegates to the real tool or refuses.

The adapter is duck-typed. It does not import ``langchain``, so it is usable and
testable without the dependency installed. It works with anything that exposes a
``name`` and an ``invoke`` method, which is exactly the LangChain and LangGraph
tool contract.

Example::

    from langchain_core.tools import tool
    from asphallea import Policy, Engine, AuditLog
    from asphallea.integrations.langchain import guard_tool

    @tool
    def read_file(path: str) -> str:
        "Read a file."
        with open(path) as fh:
            return fh.read()

    policy = Policy.builder("lc").allow_tools("read_file").read_paths("./workspace").build()
    engine = Engine(policy)
    safe = guard_tool(read_file, engine, reads="path", audit=AuditLog("audit.jsonl"))
    # hand `safe` to your agent or graph in place of `read_file`
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from ..audit import AuditRecord, AuditSink
from ..engine import Decision, Engine
from ..guard import PolicyTimeout, PolicyViolation
from ..policy import Policy

__all__ = ["guard_tool", "guard_tools", "GuardedTool", "is_langchain_tool"]

_NameSpec = Union[str, int, Sequence[Union[str, int]], None]


def is_langchain_tool(obj: Any) -> bool:
    """Return whether ``obj`` looks like a LangChain or LangGraph tool.

    Duck-typed: any object with a string ``name`` and a callable ``invoke``
    qualifies. This deliberately avoids importing LangChain.
    """
    return (
        hasattr(obj, "name")
        and isinstance(getattr(obj, "name"), str)
        and callable(getattr(obj, "invoke", None))
    )


class GuardedTool:
    """A LangChain-compatible tool that enforces a policy on every invocation.

    Attribute access falls through to the wrapped tool, so the guarded tool keeps
    its ``name``, ``description``, and ``args_schema`` and remains a valid tool for
    agents and graphs. Only the execution entry points are intercepted.
    """

    def __init__(
        self,
        tool: Any,
        policy_or_engine: Union[Policy, Engine],
        *,
        reads: _NameSpec = None,
        writes: _NameSpec = None,
        network: bool = False,
        audit: Optional[AuditSink] = None,
        timeout: Optional[float] = None,
        on_deny: str = "raise",
        name: Optional[str] = None,
    ) -> None:
        """Wrap ``tool``.

        Args:
            tool: The LangChain or LangGraph tool to wrap.
            policy_or_engine: A policy, or a shared engine for cross-tool counting.
            reads: Input keys (or the whole string input) that carry read paths.
            writes: Input keys that carry write paths.
            network: Whether the tool uses the network.
            audit: Where to record decisions.
            timeout: Wall-clock ceiling in seconds for a synchronous invocation.
            on_deny: ``"raise"`` to raise :class:`PolicyViolation`, or ``"return"``
                to return a denial string the agent can read and move past.
            name: Override the tool name used for policy checks and the audit
                trail. Defaults to the wrapped tool's ``name``.
        """
        if on_deny not in ("raise", "return"):
            raise ValueError("on_deny must be 'raise' or 'return'")
        self._tool = tool
        self._engine = policy_or_engine if isinstance(policy_or_engine, Engine) else Engine(policy_or_engine)
        self._policy = self._engine.policy
        self._read_names = _to_list(reads)
        self._write_names = _to_list(writes)
        self._network = network
        self._audit = audit
        self._timeout = timeout if timeout is not None else self._policy.timeout_seconds
        self._on_deny = on_deny
        self._name = name or getattr(tool, "name", "tool")

    # -- tool identity -----------------------------------------------------

    @property
    def name(self) -> str:
        """The tool name (delegated unless overridden)."""
        return self._name

    def __getattr__(self, item: str) -> Any:
        # Only called for attributes not found normally; delegate to the tool.
        return getattr(self._tool, item)

    def __repr__(self) -> str:
        return f"GuardedTool(name={self._name!r}, policy={self._policy.name!r})"

    # -- guarded execution -------------------------------------------------

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Policy-checked, audited ``invoke`` delegating to the wrapped tool."""
        decision = self._decide(input)
        if decision.denied:
            return self._deny(decision)
        if self._timeout is None:
            return self._tool.invoke(input, config, **kwargs)
        return _call_with_timeout(
            lambda: self._tool.invoke(input, config, **kwargs), self._timeout, self
        )

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Policy-checked, audited ``ainvoke`` delegating to the wrapped tool."""
        decision = self._decide(input)
        if decision.denied:
            return self._deny(decision)
        return await self._tool.ainvoke(input, config, **kwargs)

    def run(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Policy-checked ``run`` for the older tool API."""
        payload = tool_input if tool_input is not None else kwargs
        decision = self._decide(payload)
        if decision.denied:
            return self._deny(decision)
        return self._tool.run(tool_input, *args, **kwargs)

    async def arun(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> Any:
        """Policy-checked ``arun`` for the older async tool API."""
        payload = tool_input if tool_input is not None else kwargs
        decision = self._decide(payload)
        if decision.denied:
            return self._deny(decision)
        return await self._tool.arun(tool_input, *args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        payload = args[0] if len(args) == 1 and not kwargs else (kwargs or list(args))
        decision = self._decide(payload)
        if decision.denied:
            return self._deny(decision)
        return self._tool(*args, **kwargs)

    # -- internals ---------------------------------------------------------

    def _decide(self, input_obj: Any) -> Decision:
        reads = _extract(input_obj, self._read_names)
        writes = _extract(input_obj, self._write_names)
        decision = self._engine.check(
            self._name, reads=reads, writes=writes, network=self._network
        )
        if self._audit is not None:
            self._audit.write(
                AuditRecord(
                    tool=self._name,
                    decision="allow" if decision.allowed else "deny",
                    rule=decision.rule,
                    reason=decision.reason,
                    tier="policy",
                    args=_as_args(input_obj),
                    kwargs=_as_kwargs(input_obj),
                    policy=self._policy.name,
                )
            )
        return decision

    def _deny(self, decision: Decision) -> Any:
        if self._on_deny == "return":
            return f"[asphallea denied {self._name}] {decision.reason} (rule={decision.rule})"
        raise PolicyViolation(decision, self._name)


def guard_tool(
    tool: Any,
    policy_or_engine: Union[Policy, Engine],
    *,
    reads: _NameSpec = None,
    writes: _NameSpec = None,
    network: bool = False,
    audit: Optional[AuditSink] = None,
    timeout: Optional[float] = None,
    on_deny: str = "raise",
    name: Optional[str] = None,
) -> GuardedTool:
    """Wrap a single LangChain or LangGraph tool. See :class:`GuardedTool`."""
    return GuardedTool(
        tool,
        policy_or_engine,
        reads=reads,
        writes=writes,
        network=network,
        audit=audit,
        timeout=timeout,
        on_deny=on_deny,
        name=name,
    )


def guard_tools(
    tools: Iterable[Any],
    policy_or_engine: Union[Policy, Engine],
    *,
    specs: Optional[Dict[str, Dict[str, Any]]] = None,
    audit: Optional[AuditSink] = None,
    on_deny: str = "raise",
) -> List[GuardedTool]:
    """Wrap a list of tools, sharing one engine so limits count across them.

    Args:
        tools: The tools to wrap.
        policy_or_engine: A policy or shared engine. A policy is promoted to a
            single shared engine so call and spend limits are global.
        specs: Optional per-tool-name settings, for example
            ``{"read_file": {"reads": "path"}, "search": {"network": True}}``.
        audit: Shared audit sink.
        on_deny: Applied to every wrapped tool.

    Returns:
        The list of guarded tools, in input order.
    """
    engine = policy_or_engine if isinstance(policy_or_engine, Engine) else Engine(policy_or_engine)
    specs = specs or {}
    wrapped: List[GuardedTool] = []
    for tool in tools:
        spec = specs.get(getattr(tool, "name", ""), {})
        wrapped.append(
            GuardedTool(
                tool,
                engine,
                reads=spec.get("reads"),
                writes=spec.get("writes"),
                network=spec.get("network", False),
                audit=audit,
                timeout=spec.get("timeout"),
                on_deny=on_deny,
                name=spec.get("name"),
            )
        )
    return wrapped


def _to_list(spec: _NameSpec) -> List[Union[str, int]]:
    if spec is None:
        return []
    if isinstance(spec, (str, int)):
        return [spec]
    return list(spec)


def _extract(input_obj: Any, names: Sequence[Union[str, int]]) -> List[str]:
    """Pull path values out of a tool input by key, index, or whole-string."""
    if not names:
        return []
    values: List[str] = []
    for name in names:
        raw = None
        if isinstance(input_obj, dict):
            raw = input_obj.get(name) if not isinstance(name, int) else None
        elif isinstance(input_obj, (list, tuple)) and isinstance(name, int):
            raw = input_obj[name] if 0 <= name < len(input_obj) else None
        elif isinstance(input_obj, str) and len(names) == 1:
            raw = input_obj
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(v) for v in raw)
        else:
            values.append(str(raw))
    return values


def _as_args(input_obj: Any) -> list:
    if isinstance(input_obj, (list, tuple)):
        return list(input_obj)
    if isinstance(input_obj, dict):
        return []
    return [input_obj]


def _as_kwargs(input_obj: Any) -> dict:
    return dict(input_obj) if isinstance(input_obj, dict) else {}


def _call_with_timeout(fn, timeout: float, tool: GuardedTool) -> Any:
    holder: Dict[str, Any] = {}

    def target() -> None:
        try:
            holder["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - propagate to caller thread
            holder["error"] = exc

    worker = threading.Thread(target=target, daemon=True, name=f"asphallea-lc-{tool.name}")
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise PolicyTimeout(
            Decision.deny("timeout", f"tool {tool.name!r} exceeded timeout of {timeout:g}s"),
            tool.name,
        )
    if "error" in holder:
        raise holder["error"]
    return holder.get("result")
