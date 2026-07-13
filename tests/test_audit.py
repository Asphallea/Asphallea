"""Tests for the append-only JSONL audit log and redaction."""

from __future__ import annotations

import json

from asphallea import AuditLog, AuditRecord, NullAuditLog, default_redactor, no_redaction
from asphallea.audit import REDACTED


def read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_writes_jsonl_append(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    log.write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok"))
    log.write(AuditRecord(tool="t", decision="deny", rule="read_paths", reason="no"))
    log.close()
    records = read_lines(path)
    assert len(records) == 2
    assert records[0]["decision"] == "allow"
    assert records[1]["rule"] == "read_paths"
    assert records[0]["timestamp"].endswith("Z")


def test_append_does_not_truncate(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path).write(AuditRecord(tool="a", decision="allow", rule="allow", reason="1"))
    AuditLog(path).write(AuditRecord(tool="b", decision="allow", rule="allow", reason="2"))
    assert len(read_lines(path)) == 2


def test_redaction_by_kwarg_name(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    log.write(
        AuditRecord(
            tool="t",
            decision="allow",
            rule="allow",
            reason="ok",
            kwargs={"api_key": "supersecretvalue", "path": "/ok"},
        )
    )
    log.close()
    rec = read_lines(path)[0]
    assert rec["kwargs"]["api_key"] == REDACTED
    assert rec["kwargs"]["path"] == "/ok"


def test_redaction_by_value_shape(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    jwt = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJ"
    log.write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok", args=[jwt, "normal"]))
    log.close()
    rec = read_lines(path)[0]
    assert rec["args"][0] == REDACTED
    assert rec["args"][1] == "normal"


def test_no_redaction_passthrough(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path, redactor=no_redaction)
    log.write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok", kwargs={"password": "p"}))
    log.close()
    rec = read_lines(path)[0]
    assert rec["kwargs"]["password"] == "p"


def test_long_value_truncated(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    log.write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok", args=["x" * 5000]))
    log.close()
    rec = read_lines(path)[0]
    assert rec["args"][0].endswith("...[truncated]")


def test_non_serializable_arg_coerced(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)

    class Weird:
        def __repr__(self):
            return "WEIRD"

    log.write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok", args=[Weird()]))
    log.close()
    rec = read_lines(path)[0]
    assert rec["args"][0] == "WEIRD"


def test_default_redactor_is_default(tmp_path):
    # A record dict with a secret-looking key is scrubbed by the default.
    scrubbed = default_redactor({"args": [], "kwargs": {"token": "abc"}})
    assert scrubbed["kwargs"]["token"] == REDACTED


def test_null_audit_log():
    NullAuditLog().write(AuditRecord(tool="t", decision="allow", rule="allow", reason="ok"))
