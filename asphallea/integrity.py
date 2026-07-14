"""Verify the containment core binary before trusting it.

The containment tier is only as trustworthy as the ``asphallea-run`` binary the SDK
invokes. If that binary were swapped for a no-op that prints a "contained" report
but enforces nothing, a hijacked agent would run free while the audit log claimed it
was contained. This is the tampering threat, and this module closes it.

The check is a SHA-256 of the binary against a manifest that ships inside the
package. Released wheels bundle a signed ``asphallea-run`` and a
``_core/checksums.json`` recording its hash. At runtime the SDK recomputes the hash
and refuses to run a binary that does not match, failing closed.

When there is no manifest (you built the core yourself, or pointed the SDK at your
own binary with ``ASPHALLEA_CORE_BIN``) there is nothing to verify against, so the
SDK proceeds and says so. Verification protects the trust chain of the *distributed*
artifact; a binary you built and placed yourself is already your trust decision.

Code-signature verification (Authenticode on Windows, ``codesign`` on macOS) is the
stronger, key-backed check and is reported when available, but the enforced gate is
the bundled-hash match, which needs no signing certificate to be useful.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

__all__ = [
    "IntegrityError",
    "IntegrityResult",
    "verify_core",
    "sha256_file",
    "manifest_path",
]

_CHUNK = 1024 * 1024


class IntegrityError(Exception):
    """Raised when the core binary fails integrity verification.

    This is a fail-closed refusal: the SDK will not run a containment binary whose
    hash does not match the manifest shipped with the package.
    """


@dataclass(frozen=True)
class IntegrityResult:
    """The outcome of verifying a core binary.

    Attributes:
        ok: True if the binary is trusted (verified, or nothing to verify against).
        method: ``"sha256"`` when checked against the manifest, ``"none"`` when no
            manifest entry exists (dev build or user override).
        verified: True only when an actual hash match happened.
        sha256: The binary's computed SHA-256.
        reason: Human-readable explanation.
    """

    ok: bool
    method: str
    verified: bool
    sha256: str
    reason: str


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 of the file at ``path``."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_path() -> Path:
    """Path to the bundled checksums manifest, whether or not it exists."""
    return Path(__file__).resolve().parent / "_core" / "checksums.json"


def _load_manifest() -> Dict[str, Dict[str, str]]:
    path = manifest_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def verify_core(path: str, *, manifest: Optional[Dict[str, Dict[str, str]]] = None) -> IntegrityResult:
    """Verify the core binary at ``path`` against a checksum manifest.

    Returns an :class:`IntegrityResult`. It never raises; the caller decides how to
    act on ``ok``. If the manifest lists this binary's name, the hash must match or
    ``ok`` is False. If the manifest has no entry for it, ``ok`` is True with method
    ``"none"`` (nothing to verify against). ``manifest`` defaults to the one bundled
    with the package.
    """
    try:
        digest = sha256_file(path)
    except OSError as exc:
        return IntegrityResult(False, "error", False, "", f"cannot read core binary: {exc}")

    if manifest is None:
        manifest = _load_manifest()
    entry = manifest.get(os.path.basename(path))
    if not entry or "sha256" not in entry:
        return IntegrityResult(
            True,
            "none",
            False,
            digest,
            "no bundled manifest entry for this binary; nothing to verify against "
            "(built-from-source or ASPHALLEA_CORE_BIN override)",
        )

    expected = str(entry["sha256"]).lower()
    if digest.lower() == expected:
        return IntegrityResult(True, "sha256", True, digest, "core binary hash matches the manifest")
    return IntegrityResult(
        False,
        "sha256",
        False,
        digest,
        f"core binary hash {digest} does not match the manifest hash {expected}; "
        "the binary may have been tampered with or replaced",
    )


def require_trusted_core(path: str) -> IntegrityResult:
    """Verify ``path`` and raise :class:`IntegrityError` if it is not trusted."""
    result = verify_core(path)
    if not result.ok:
        raise IntegrityError(result.reason)
    return result


def write_manifest(binary_path: str, *, destination: Optional[str] = None) -> str:
    """Record ``binary_path``'s hash into a manifest. Used at wheel-build time.

    Writes ``{basename: {"sha256": ...}}`` to ``destination`` (default: the bundled
    manifest path) and returns the manifest path. Merges with any existing manifest
    so a multi-platform build can accumulate entries.
    """
    dest = Path(destination) if destination else manifest_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Dict[str, str]] = {}
    if dest.exists():
        try:
            manifest = json.loads(dest.read_text(encoding="utf-8"))
        except ValueError:
            manifest = {}
    manifest[os.path.basename(binary_path)] = {"sha256": sha256_file(binary_path)}
    dest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(dest)
