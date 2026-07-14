"""Tests for core-binary integrity verification (tamper resistance)."""

from __future__ import annotations

import hashlib
import json

import pytest

from asphallea import IntegrityError, verify_core
from asphallea.integrity import require_trusted_core, sha256_file, write_manifest


def _make_binary(tmp_path, name, data=b"fake-core-binary"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_sha256_file(tmp_path):
    p = _make_binary(tmp_path, "b.bin", b"hello")
    assert sha256_file(p) == hashlib.sha256(b"hello").hexdigest()


def test_verify_no_manifest_entry_passes(tmp_path):
    # No entry for this binary: nothing to verify against, so ok with method none.
    p = _make_binary(tmp_path, "asphallea-run")
    result = verify_core(p, manifest={})
    assert result.ok is True
    assert result.method == "none"
    assert result.verified is False


def test_verify_matching_hash(tmp_path):
    p = _make_binary(tmp_path, "asphallea-run", b"real")
    manifest = {"asphallea-run": {"sha256": hashlib.sha256(b"real").hexdigest()}}
    result = verify_core(p, manifest=manifest)
    assert result.ok is True
    assert result.method == "sha256"
    assert result.verified is True


def test_verify_mismatch_fails(tmp_path):
    p = _make_binary(tmp_path, "asphallea-run", b"tampered")
    manifest = {"asphallea-run": {"sha256": hashlib.sha256(b"original").hexdigest()}}
    result = verify_core(p, manifest=manifest)
    assert result.ok is False
    assert result.method == "sha256"
    assert "does not match" in result.reason


def test_require_trusted_core_raises_on_mismatch(tmp_path, monkeypatch):
    p = _make_binary(tmp_path, "asphallea-run", b"tampered")
    # Point the bundled manifest loader at a wrong hash.
    from asphallea import integrity

    monkeypatch.setattr(
        integrity, "_load_manifest", lambda: {"asphallea-run": {"sha256": "0" * 64}}
    )
    with pytest.raises(IntegrityError):
        require_trusted_core(p)


def test_require_trusted_core_ok_when_no_manifest(tmp_path, monkeypatch):
    p = _make_binary(tmp_path, "asphallea-run")
    from asphallea import integrity

    monkeypatch.setattr(integrity, "_load_manifest", lambda: {})
    # Should not raise: nothing to verify against.
    result = require_trusted_core(p)
    assert result.method == "none"


def test_write_manifest_roundtrip(tmp_path):
    p = _make_binary(tmp_path, "asphallea-run", b"payload")
    dest = tmp_path / "checksums.json"
    write_manifest(p, destination=str(dest))
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["asphallea-run"]["sha256"] == hashlib.sha256(b"payload").hexdigest()
    # A binary matching the written manifest verifies.
    result = verify_core(p, manifest=data)
    assert result.ok and result.verified


def test_write_manifest_merges(tmp_path):
    a = _make_binary(tmp_path, "asphallea-run", b"linux")
    b = _make_binary(tmp_path, "asphallea-run.exe", b"windows")
    dest = tmp_path / "checksums.json"
    write_manifest(a, destination=str(dest))
    write_manifest(b, destination=str(dest))
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert "asphallea-run" in data and "asphallea-run.exe" in data
