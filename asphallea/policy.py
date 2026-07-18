"""Declarative least-privilege policy for agent tool-execution.

A :class:`Policy` is an immutable description of what an agent is allowed to do:
which tools it may call, which filesystem paths it may read or write, whether it
may touch the network, how often it may call a tool, how long a call may run, and
how many times a paid tool may be invoked.

Policies are built two ways:

* fluently, with :meth:`Policy.builder`
* declaratively, from YAML, with :meth:`Policy.from_yaml`

A policy carries no runtime state. Counters, rate windows, and spend tallies live
in the :class:`~asphallea.engine.Engine` that evaluates against the policy, so the
same policy object can be shared safely across guards.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

__all__ = [
    "Policy",
    "PolicyBuilder",
    "RateLimit",
    "ResourceLimits",
    "ToolArgs",
    "network_host",
    "host_matches",
    "PolicyError",
]


class PolicyError(ValueError):
    """Raised when a policy is malformed or internally inconsistent."""


def _normalize_path(path: str) -> str:
    """Return an absolute, symlink-resolved, normalized form of ``path``.

    Resolution is best effort: components that do not exist yet are still
    normalized. Symlinks are resolved so that an allowlisted prefix cannot be
    escaped by pointing a link outside it. This is the cross-platform
    convenience check. On Linux the containment tier enforces the same boundary
    at the kernel with Landlock, which is inode based and not fooled by links.
    """
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


@dataclass(frozen=True)
class RateLimit:
    """A sliding-window rate limit: at most ``max_calls`` per ``window_seconds``."""

    max_calls: int
    window_seconds: float

    def __post_init__(self) -> None:
        if self.max_calls <= 0:
            raise PolicyError("rate limit max_calls must be positive")
        if self.window_seconds <= 0:
            raise PolicyError("rate limit window_seconds must be positive")


@dataclass(frozen=True)
class ResourceLimits:
    """OS resource limits applied by the containment tier on Linux.

    All fields are optional. ``None`` means "do not set this limit". Sizes are
    given in whole megabytes and whole seconds at this layer; they are converted
    to bytes and passed to the Rust core when a sandbox is launched.
    """

    cpu_seconds: Optional[int] = None
    memory_mb: Optional[int] = None
    max_file_size_mb: Optional[int] = None
    max_processes: Optional[int] = None
    max_open_files: Optional[int] = None

    def to_core_json(self) -> Dict[str, int]:
        """Serialize to the byte-and-count shape the Rust core expects."""
        out: Dict[str, int] = {}
        if self.cpu_seconds is not None:
            out["cpu_seconds"] = int(self.cpu_seconds)
        if self.memory_mb is not None:
            out["memory_bytes"] = int(self.memory_mb) * 1024 * 1024
        if self.max_file_size_mb is not None:
            out["max_file_size_bytes"] = int(self.max_file_size_mb) * 1024 * 1024
        if self.max_processes is not None:
            out["max_processes"] = int(self.max_processes)
        if self.max_open_files is not None:
            out["max_open_files"] = int(self.max_open_files)
        return out


def network_host(value: Any) -> str:
    """Extract a comparable hostname from a URL or ``host[:port]`` string.

    Pure string parsing, no DNS and no network. ``"https://api.example.com/x"`` and
    ``"api.example.com:443"`` both yield ``"api.example.com"``. Lowercased so
    comparison is case-insensitive.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if "://" in text:
        host = urlsplit(text).hostname or ""
    else:
        host = text.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    return host.lower()


def host_matches(target: str, rule: str) -> bool:
    """Whether ``target`` host is covered by ``rule``: exact host or a subdomain.

    Rule ``example.com`` matches ``example.com`` and ``api.example.com`` but not
    ``notexample.com``. Both are expected already normalized by :func:`network_host`.
    """
    if not target or not rule:
        return False
    return target == rule or target.endswith("." + rule)


def _as_names(value: Any) -> Tuple[str, ...]:
    """Coerce an argument-name spec (``"path"`` or ``["src", "dst"]``) to a tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


@dataclass(frozen=True)
class ToolArgs:
    """Which of a tool's arguments name filesystem paths or network targets.

    This is what lets a policy govern a tool it did not author. An MCP server
    exposes ``filesystem.delete(path=...)``; the policy declares that ``path`` is a
    filesystem write, and the engine checks that value against the write allowlist.
    Without this the SDK would have to be told the mapping in Python at every call
    site, which is impossible for tools you did not write.

    Attributes:
        reads: Argument names whose values are paths the tool reads.
        writes: Argument names whose values are paths the tool writes.
        network: Argument names whose values are network targets (URL or host).
    """

    reads: Tuple[str, ...] = ()
    writes: Tuple[str, ...] = ()
    network: Tuple[str, ...] = ()

    @property
    def declared(self) -> bool:
        """True if this tool declares any resource-bearing argument."""
        return bool(self.reads or self.writes or self.network)


@dataclass(frozen=True)
class Policy:
    """An immutable least-privilege policy.

    Attributes:
        name: A short identifier recorded in every audit line.
        allowed_tools: If ``None``, tools are not restricted by an allowlist and
            the act of wrapping a tool is the opt-in. If a set, only listed tool
            names are permitted and every other tool is denied.
        denied_tools: Tool names denied outright. A denial wins over the
            allowlist, so a tool can be blocked without rewriting the allowlist.
        tool_args: Per-tool declaration of which arguments carry filesystem paths
            or network targets, keyed by tool name. This is what lets the policy
            govern tools it did not author, such as MCP tool-calls.
        read_paths: Absolute, normalized prefixes a tool may read from.
        write_paths: Absolute, normalized prefixes a tool may write to. A write
            path also grants read.
        network: The default network decision, ``"deny"`` or ``"allow"``, applied
            to a declared network target whose host matches no explicit rule.
        network_allow_hosts: Hosts allowed even when the default is deny. A rule
            matches the host exactly or as a parent domain (``example.com`` covers
            ``api.example.com``).
        network_deny_hosts: Hosts denied even when the default is allow. A denial
            wins over an allow rule.
        max_calls: Per-tool ceiling on total invocations.
        rate_limits: Per-tool sliding-window rate limit.
        spend_caps: Per-tool ceiling on invocations of a paid tool. Modeled as a
            call count. Real-time dollar metering is out of scope for v0.
        timeout_seconds: Wall-clock ceiling for a single call.
        limits: OS resource limits for the containment tier.
    """

    name: str
    allowed_tools: Optional[frozenset] = None
    denied_tools: frozenset = frozenset()
    tool_args: Mapping[str, ToolArgs] = field(default_factory=dict)
    read_paths: Tuple[str, ...] = ()
    write_paths: Tuple[str, ...] = ()
    network: str = "deny"
    network_allow_hosts: frozenset = frozenset()
    network_deny_hosts: frozenset = frozenset()
    max_calls: Mapping[str, int] = field(default_factory=dict)
    rate_limits: Mapping[str, RateLimit] = field(default_factory=dict)
    spend_caps: Mapping[str, int] = field(default_factory=dict)
    timeout_seconds: Optional[float] = None
    limits: ResourceLimits = field(default_factory=ResourceLimits)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise PolicyError("policy name must be a non-empty string")
        if self.network not in ("deny", "allow"):
            raise PolicyError(f"network must be 'deny' or 'allow', got {self.network!r}")

    # -- construction ------------------------------------------------------

    @staticmethod
    def builder(name: str) -> "PolicyBuilder":
        """Start a fluent :class:`PolicyBuilder` named ``name``."""
        return PolicyBuilder(name)

    @classmethod
    def from_yaml(cls, path: "str | os.PathLike[str]") -> "Policy":
        """Load a policy from a YAML file.

        See ``policies/example.yaml`` for the schema. Raises
        :class:`PolicyError` on unknown keys or invalid values so a typo in a
        security policy fails loudly rather than silently doing nothing.
        """
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - dependency always present
            raise PolicyError(
                "PyYAML is required to load policies from YAML. "
                "Install it with `pip install asphallea` or `pip install pyyaml`."
            ) from exc

        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise PolicyError("policy YAML must be a mapping at the top level")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        """Build a policy from a plain mapping following the YAML schema."""
        known = {"name", "tools", "filesystem", "network", "limits", "spend"}
        unknown = set(data) - known
        if unknown:
            raise PolicyError(f"unknown policy keys: {sorted(unknown)}")

        name = data.get("name")
        if not name:
            raise PolicyError("policy is missing required key 'name'")

        builder = PolicyBuilder(str(name))

        tools = data.get("tools") or {}
        if tools:
            _reject_unknown(tools, {"allow", "deny", "args"}, "tools")
            for tool in tools.get("allow", []) or []:
                builder.allow_tool(str(tool))
            for tool in tools.get("deny", []) or []:
                builder.deny_tool(str(tool))
            for tool, spec in (tools.get("args") or {}).items():
                spec = spec or {}
                _reject_unknown(spec, {"reads", "writes", "network"}, f"tools.args.{tool}")
                builder.tool(
                    str(tool),
                    reads=spec.get("reads"),
                    writes=spec.get("writes"),
                    network=spec.get("network"),
                )

        fs = data.get("filesystem") or {}
        if fs:
            _reject_unknown(fs, {"read", "write"}, "filesystem")
            for p in fs.get("read", []) or []:
                builder.read_paths(str(p))
            for p in fs.get("write", []) or []:
                builder.write_paths(str(p))

        net = data.get("network") or {}
        if net:
            _reject_unknown(net, {"default", "allow_hosts", "deny_hosts"}, "network")
            default = str(net.get("default", "deny"))
            if default == "deny":
                builder.deny_network()
            elif default == "allow":
                builder.allow_network()
            else:
                raise PolicyError(f"network.default must be 'deny' or 'allow', got {default!r}")
            builder.allow_hosts(*(net.get("allow_hosts") or []))
            builder.deny_hosts(*(net.get("deny_hosts") or []))

        limits = data.get("limits") or {}
        if limits:
            _reject_unknown(
                limits,
                {
                    "timeout_seconds",
                    "calls",
                    "rate",
                    "cpu_seconds",
                    "memory_mb",
                    "max_file_size_mb",
                    "max_processes",
                    "max_open_files",
                },
                "limits",
            )
            if "timeout_seconds" in limits:
                builder.timeout(float(limits["timeout_seconds"]))
            for tool, n in (limits.get("calls") or {}).items():
                builder.max_calls(str(tool), int(n))
            for tool, spec in (limits.get("rate") or {}).items():
                spec = spec or {}
                _reject_unknown(spec, {"per_minute", "per_second"}, f"limits.rate.{tool}")
                builder.rate_limit(
                    str(tool),
                    per_minute=spec.get("per_minute"),
                    per_second=spec.get("per_second"),
                )
            builder.limits(
                cpu_seconds=limits.get("cpu_seconds"),
                memory_mb=limits.get("memory_mb"),
                max_file_size_mb=limits.get("max_file_size_mb"),
                max_processes=limits.get("max_processes"),
                max_open_files=limits.get("max_open_files"),
            )

        spend = data.get("spend") or {}
        for tool, spec in spend.items():
            spec = spec or {}
            _reject_unknown(spec, {"max_calls"}, f"spend.{tool}")
            if "max_calls" not in spec:
                raise PolicyError(f"spend.{tool} requires 'max_calls'")
            builder.spend_cap(str(tool), int(spec["max_calls"]))

        return builder.build()

    # -- queries -----------------------------------------------------------

    def tool_allowed(self, tool: str) -> bool:
        """Return whether ``tool`` passes the tool allowlist and denylist.

        A denial always wins: a tool named in ``denied_tools`` is refused even if
        it also appears in the allowlist.
        """
        if tool in self.denied_tools:
            return False
        return self.allowed_tools is None or tool in self.allowed_tools

    def args_for(self, tool: str) -> ToolArgs:
        """Return the declared argument mapping for ``tool`` (empty if none)."""
        return self.tool_args.get(tool, ToolArgs())

    def network_allowed(self, target: Optional[str]) -> bool:
        """Whether a network ``target`` (URL or host) is permitted.

        A denied host wins, then an allowed host, then the default. ``target`` of
        ``None`` means "uses the network, host unknown", decided by the default
        alone. Deterministic and offline: this only parses the string.
        """
        if target is None:
            return self.network == "allow"
        host = network_host(target)
        if any(host_matches(host, rule) for rule in self.network_deny_hosts):
            return False
        if any(host_matches(host, rule) for rule in self.network_allow_hosts):
            return True
        return self.network == "allow"

    def to_core_json(self) -> Dict[str, Any]:
        """Serialize the containment-relevant fields for the Rust core.

        Only the parts the OS enforcement needs are included: filesystem
        allowlists, the network decision, and resource limits. Tool allowlists,
        rate limits, and spend caps are enforced by the Python policy tier and
        are not part of the sandbox launch.
        """
        return {
            "name": self.name,
            "filesystem": {
                "read": list(self.read_paths),
                "write": list(self.write_paths),
            },
            "network": self.network,
            "limits": self.limits.to_core_json(),
        }


def _reject_unknown(mapping: Mapping[str, Any], known: set, where: str) -> None:
    unknown = set(mapping) - known
    if unknown:
        raise PolicyError(f"unknown keys in {where}: {sorted(unknown)}")


class PolicyBuilder:
    """Fluent builder for a :class:`Policy`.

    Every method returns ``self`` so calls chain. Call :meth:`build` to produce
    the immutable policy. Paths are normalized to absolute, symlink-resolved form
    at build time so the resulting policy is unambiguous.
    """

    def __init__(self, name: str) -> None:
        """Start building a policy named ``name``."""
        self._name = name
        self._allowed_tools: Optional[set] = None
        self._denied_tools: set = set()
        self._tool_args: Dict[str, ToolArgs] = {}
        self._read_paths: list = []
        self._write_paths: list = []
        self._network = "deny"
        self._network_allow_hosts: set = set()
        self._network_deny_hosts: set = set()
        self._max_calls: Dict[str, int] = {}
        self._rate_limits: Dict[str, RateLimit] = {}
        self._spend_caps: Dict[str, int] = {}
        self._timeout_seconds: Optional[float] = None
        self._limits = ResourceLimits()

    def allow_tool(self, name: str) -> "PolicyBuilder":
        """Add ``name`` to the tool allowlist. Enables allowlist enforcement."""
        if self._allowed_tools is None:
            self._allowed_tools = set()
        self._allowed_tools.add(name)
        return self

    def allow_tools(self, *names: str) -> "PolicyBuilder":
        """Add several tool names to the allowlist."""
        for name in names:
            self.allow_tool(name)
        return self

    def deny_tool(self, name: str) -> "PolicyBuilder":
        """Deny ``name`` outright. A denial wins over the allowlist."""
        self._denied_tools.add(name)
        return self

    def deny_tools(self, *names: str) -> "PolicyBuilder":
        """Deny several tool names outright."""
        for name in names:
            self.deny_tool(name)
        return self

    def tool(
        self,
        name: str,
        *,
        reads: Any = None,
        writes: Any = None,
        network: Any = None,
        allow: bool = True,
    ) -> "PolicyBuilder":
        """Declare a tool and how its arguments map to resources.

        This is the declarative equivalent of the ``reads=``/``writes=`` keywords
        on :func:`~asphallea.guard.guard`, and it is what makes a policy able to
        govern a tool it did not author (an MCP tool-call, for example)::

            Policy.builder("agent")
                .tool("filesystem.read", reads="path")
                .tool("filesystem.delete", writes="path")
                .tool("http.fetch", network="url")
                .read_paths("./workspace")
                .build()

        Each of ``reads``, ``writes``, and ``network`` takes an argument name or a
        list of argument names. Declaring a tool also adds it to the allowlist, so
        the policy above permits exactly those three tools and denies the rest.
        Pass ``allow=False`` to declare the mapping without allowlisting.
        """
        self._tool_args[name] = ToolArgs(
            reads=_as_names(reads),
            writes=_as_names(writes),
            network=_as_names(network),
        )
        if allow:
            self.allow_tool(name)
        return self

    def read_paths(self, *paths: str) -> "PolicyBuilder":
        """Allow reads under each of ``paths``. Normalized at build time."""
        self._read_paths.extend(paths)
        return self

    def write_paths(self, *paths: str) -> "PolicyBuilder":
        """Allow writes (and reads) under each of ``paths``."""
        self._write_paths.extend(paths)
        return self

    def deny_network(self) -> "PolicyBuilder":
        """Deny network access. This is the default."""
        self._network = "deny"
        return self

    def allow_network(self) -> "PolicyBuilder":
        """Allow network access by default. Narrow it with :meth:`deny_hosts`."""
        self._network = "allow"
        return self

    def allow_hosts(self, *hosts: str) -> "PolicyBuilder":
        """Allow these hosts even when the default is deny.

        A host rule matches exactly or as a parent domain, so ``example.com``
        permits ``api.example.com``. A URL is accepted and reduced to its host.
        """
        for host in hosts:
            self._network_allow_hosts.add(network_host(host))
        return self

    def deny_hosts(self, *hosts: str) -> "PolicyBuilder":
        """Deny these hosts even when the default is allow. A denial wins."""
        for host in hosts:
            self._network_deny_hosts.add(network_host(host))
        return self

    def max_calls(self, tool: str, n: int) -> "PolicyBuilder":
        """Cap total invocations of ``tool`` at ``n``."""
        if n < 0:
            raise PolicyError("max_calls must be non-negative")
        self._max_calls[tool] = int(n)
        return self

    def rate_limit(
        self,
        tool: str,
        *,
        per_minute: Optional[int] = None,
        per_second: Optional[int] = None,
    ) -> "PolicyBuilder":
        """Rate limit ``tool``. Provide exactly one of ``per_minute``/``per_second``."""
        if (per_minute is None) == (per_second is None):
            raise PolicyError("rate_limit requires exactly one of per_minute or per_second")
        if per_minute is not None:
            self._rate_limits[tool] = RateLimit(int(per_minute), 60.0)
        else:
            self._rate_limits[tool] = RateLimit(int(per_second), 1.0)
        return self

    def spend_cap(self, tool: str, max_calls: int) -> "PolicyBuilder":
        """Cap invocations of a paid ``tool`` at ``max_calls`` (spend proxy)."""
        if max_calls < 0:
            raise PolicyError("spend_cap max_calls must be non-negative")
        self._spend_caps[tool] = int(max_calls)
        return self

    def timeout(self, seconds: float) -> "PolicyBuilder":
        """Set the wall-clock ceiling for a single call, in seconds."""
        if seconds <= 0:
            raise PolicyError("timeout seconds must be positive")
        self._timeout_seconds = float(seconds)
        return self

    def limits(
        self,
        *,
        cpu_seconds: Optional[int] = None,
        memory_mb: Optional[int] = None,
        max_file_size_mb: Optional[int] = None,
        max_processes: Optional[int] = None,
        max_open_files: Optional[int] = None,
    ) -> "PolicyBuilder":
        """Set OS resource limits for the containment tier (Linux)."""
        self._limits = ResourceLimits(
            cpu_seconds=cpu_seconds,
            memory_mb=memory_mb,
            max_file_size_mb=max_file_size_mb,
            max_processes=max_processes,
            max_open_files=max_open_files,
        )
        return self

    def build(self) -> Policy:
        """Produce the immutable :class:`Policy`."""
        read = tuple(dict.fromkeys(_normalize_path(p) for p in self._read_paths))
        # A write path implies read, so writes are also present in the read set
        # for the policy tier. The containment tier grants read on write paths too.
        write = tuple(dict.fromkeys(_normalize_path(p) for p in self._write_paths))
        read_union = tuple(dict.fromkeys(read + write))
        return Policy(
            name=self._name,
            allowed_tools=(frozenset(self._allowed_tools) if self._allowed_tools is not None else None),
            denied_tools=frozenset(self._denied_tools),
            tool_args=dict(self._tool_args),
            network_allow_hosts=frozenset(h for h in self._network_allow_hosts if h),
            network_deny_hosts=frozenset(h for h in self._network_deny_hosts if h),
            read_paths=read_union,
            write_paths=write,
            network=self._network,
            max_calls=dict(self._max_calls),
            rate_limits=dict(self._rate_limits),
            spend_caps=dict(self._spend_caps),
            timeout_seconds=self._timeout_seconds,
            limits=self._limits,
        )
