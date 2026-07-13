"""Structured, append-only audit logging for every enforcement decision.

Every time the engine allows or denies a tool call, a record is written as one
JSON object on its own line (JSONL). A record captures what was attempted, the
decision, the reason, the exact policy rule that fired, the enforcement tier, and
a timestamp. Secrets in tool arguments are scrubbed by a redaction hook before
anything touches disk.

The default sink, :class:`AuditLog`, appends to a file and flushes each line so
the trail survives a crash. Swap in :class:`StreamAuditLog` to print to a stream,
:class:`NullAuditLog` to discard, or implement the :class:`AuditSink` protocol for
your own destination.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:  # Protocol is 3.8+, runtime_checkable for isinstance support
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol, runtime_checkable  # type: ignore

__all__ = [
    "AuditRecord",
    "AuditSink",
    "AuditLog",
    "StreamAuditLog",
    "NullAuditLog",
    "Redactor",
    "default_redactor",
    "no_redaction",
    "REDACTED",
]

REDACTED = "***REDACTED***"

# A redactor takes a raw record dict and returns a scrubbed copy safe to persist.
Redactor = Callable[[Dict[str, Any]], Dict[str, Any]]

_SECRET_KEY_RE = re.compile(
    r"(?i)(pass|passwd|password|secret|token|api[-_]?key|apikey|authorization"
    r"|auth|credential|private[-_]?key|access[-_]?key|session)"
)

# Value shapes that look like credentials regardless of the argument name.
_SECRET_VALUE_RES = [
    re.compile(r"^sk-[A-Za-z0-9]{16,}$"),            # OpenAI-style keys
    re.compile(r"^gh[pousr]_[A-Za-z0-9]{20,}$"),     # GitHub tokens
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),   # Slack tokens
    re.compile(r"^AKIA[0-9A-Z]{16}$"),               # AWS access key id
    re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^[A-Fa-f0-9]{40,}$"),               # long hex blobs
]

_MAX_VALUE_LENGTH = 512


@dataclass
class AuditRecord:
    """One enforcement decision.

    Attributes:
        tool: The tool name the call targeted.
        decision: ``"allow"`` or ``"deny"``.
        reason: Human-readable explanation of the decision.
        rule: The policy rule that fired, for example ``"read_paths"`` or
            ``"tool_allowlist"``. ``"allow"`` when nothing denied.
        tier: ``"policy"`` for the cross-platform tier, ``"containment"`` for
            the OS enforcement tier.
        args: Positional arguments of the call, post-redaction.
        kwargs: Keyword arguments of the call, post-redaction.
        policy: The policy name.
        timestamp: RFC 3339 / ISO 8601 UTC timestamp, set at construction.
        detail: Optional extra structured data, for example the controls a
            sandbox applied or an error message.
    """

    tool: str
    decision: str
    reason: str
    rule: str
    tier: str = "policy"
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    policy: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    detail: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return an ordered, JSON-safe dict of this record."""
        data = {
            "timestamp": self.timestamp,
            "tier": self.tier,
            "tool": self.tool,
            "decision": self.decision,
            "rule": self.rule,
            "reason": self.reason,
            "policy": self.policy,
            "args": _json_safe(self.args),
            "kwargs": _json_safe(self.kwargs),
        }
        if self.detail is not None:
            data["detail"] = _json_safe(self.detail)
        return data


@runtime_checkable
class AuditSink(Protocol):
    """Anything that can receive audit records."""

    def write(self, record: AuditRecord) -> None:
        """Persist or emit one record."""
        ...


class AuditLog:
    """Append-only JSONL audit sink backed by a file.

    Each record is redacted, serialized to a single line, written, and flushed.
    Writes are serialized with a lock so the log stays well formed under
    concurrent tool calls. The file is opened in append mode so an existing trail
    is never truncated.
    """

    def __init__(
        self,
        path: str,
        *,
        redactor: Redactor = None,  # type: ignore[assignment]
        encoding: str = "utf-8",
    ) -> None:
        """Open ``path`` for appending. ``redactor`` defaults to :func:`default_redactor`."""
        self._path = path
        self._redactor = redactor if redactor is not None else default_redactor
        self._encoding = encoding
        self._lock = threading.Lock()
        self._file = open(path, "a", encoding=encoding, newline="\n")

    @property
    def path(self) -> str:
        """The file this log appends to."""
        return self._path

    def write(self, record: AuditRecord) -> None:
        """Redact, serialize, append, and flush one record."""
        payload = self._redactor(record.to_dict())
        line = json.dumps(payload, ensure_ascii=False, default=_fallback)
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()

    def close(self) -> None:
        """Close the underlying file."""
        with self._lock:
            if not self._file.closed:
                self._file.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class StreamAuditLog:
    """Audit sink that writes JSONL to a text stream, defaulting to stderr."""

    def __init__(self, stream=None, *, redactor: Redactor = None) -> None:  # type: ignore[assignment]
        """Emit records to ``stream`` (default ``sys.stderr``)."""
        self._stream = stream if stream is not None else sys.stderr
        self._redactor = redactor if redactor is not None else default_redactor
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        """Redact, serialize, and write one record followed by a newline."""
        payload = self._redactor(record.to_dict())
        line = json.dumps(payload, ensure_ascii=False, default=_fallback)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


class NullAuditLog:
    """Audit sink that discards everything. Useful in tests."""

    def write(self, record: AuditRecord) -> None:
        """Do nothing."""
        return None


def no_redaction(record: Dict[str, Any]) -> Dict[str, Any]:
    """A redactor that passes records through unchanged. Use with care."""
    return record


def default_redactor(record: Dict[str, Any]) -> Dict[str, Any]:
    """Scrub likely secrets from a record before it is written.

    Keyword arguments whose name looks credential-like are masked wholesale.
    Any string value that matches a known credential shape is masked wherever it
    appears. This is a heuristic, not a guarantee. Provide your own redactor for
    exact control.
    """
    record = dict(record)
    record["args"] = [_redact_value(v) for v in record.get("args", [])]
    kwargs = record.get("kwargs", {})
    if isinstance(kwargs, dict):
        record["kwargs"] = {
            k: (REDACTED if _SECRET_KEY_RE.search(str(k)) else _redact_value(v))
            for k, v in kwargs.items()
        }
    return record


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED if _looks_secret(value) else value
    if isinstance(value, dict):
        return {
            k: (REDACTED if _SECRET_KEY_RE.search(str(k)) else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def _looks_secret(value: str) -> bool:
    return any(rx.search(value) for rx in _SECRET_VALUE_RES)


def _json_safe(value: Any) -> Any:
    """Coerce arbitrary values into a JSON-serializable, size-bounded form."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE_LENGTH else value[:_MAX_VALUE_LENGTH] + "...[truncated]"
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    text = repr(value)
    return text if len(text) <= _MAX_VALUE_LENGTH else text[:_MAX_VALUE_LENGTH] + "...[truncated]"


def _fallback(value: Any) -> str:
    return repr(value)
