#!/usr/bin/env python3
"""Verify that a built wheel really ships a working core binary.

A release wheel that silently lost its ``asphallea/_core`` payload still imports,
still passes the policy tier, and still looks fine — it just cannot contain
anything. That is the worst possible failure for this package, so the release
pipeline proves the opposite on every wheel before publishing.

Two levels of check:

* **static** (works on any wheel, on any host): the archive contains the core
  binary and its checksum manifest, and the wheel's platform tag is one PyPI will
  actually accept — never ``any``, never a bare ``linux_*``.
* **live** (only for a wheel matching this host): install it into a throwaway
  virtualenv and assert the installed package resolves the bundled binary, that
  the binary's SHA-256 matches the bundled manifest, and that the OS reports real
  containment.

Usage::

    python scripts/verify_wheel.py dist/*.whl          # static checks on all
    python scripts/verify_wheel.py --live dist/foo.whl # plus install-and-run
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

CORE_NAMES = ("asphallea/_core/asphallea-run", "asphallea/_core/asphallea-run.exe")
MANIFEST = "asphallea/_core/checksums.json"

# PyPI rejects these outright. "any" means the core binary never made it in.
BAD_TAG_PREFIXES = ("linux_",)


class VerificationError(Exception):
    """A wheel failed a release gate."""


def static_check(path: Path) -> str:
    """Assert the wheel carries a core binary and an uploadable platform tag."""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        wheel_meta = next(n for n in names if n.endswith(".dist-info/WHEEL"))
        tags = [
            line.split(":", 1)[1].strip()
            for line in zf.read(wheel_meta).decode().splitlines()
            if line.startswith("Tag:")
        ]
        core = [n for n in names if n in CORE_NAMES]
        if not core:
            raise VerificationError(
                f"{path.name}: no core binary inside. The wheel would install a "
                "policy tier with no OS containment. Run scripts/bundle_core.py "
                "before building, and build with `python -m build --wheel` (a "
                "wheel built from the sdist has no binary to bundle)."
            )
        if MANIFEST not in names:
            raise VerificationError(f"{path.name}: core binary present but {MANIFEST} is missing")
        manifest = json.loads(zf.read(MANIFEST))
        binary_name = Path(core[0]).name
        if binary_name not in manifest:
            raise VerificationError(
                f"{path.name}: manifest has no entry for {binary_name}; "
                "the runtime integrity check would not verify it"
            )
        if zf.getinfo(core[0]).file_size == 0:
            raise VerificationError(f"{path.name}: core binary is empty")

    for tag in tags:
        platform = tag.rsplit("-", 1)[-1]
        if platform == "any":
            raise VerificationError(
                f"{path.name}: tagged 'any' but ships a native binary; it would "
                "install on every platform and work on one"
            )
        if platform.startswith(BAD_TAG_PREFIXES):
            raise VerificationError(
                f"{path.name}: platform tag '{platform}' is not uploadable to "
                "PyPI. Linux wheels must be manylinux_* or musllinux_*."
            )
    if not tags:
        raise VerificationError(f"{path.name}: no Tag: line in WHEEL metadata")
    return ", ".join(tags)


PROBE = """
import json, sys
import asphallea
from asphallea import integrity, sandbox

caps = sandbox.capabilities()
binary = caps.core_binary
report = {
    "version": asphallea.__version__,
    "core_binary": binary,
    "bundled": bool(binary and "_core" in binary and "site-packages" in binary),
    "can_contain": caps.can_contain,
    "backend": caps.backend,
    "explain": caps.explain(),
}
if binary:
    result = integrity.verify_core(binary)
    report["integrity_ok"] = result.ok
    report["integrity_verified"] = result.verified
    report["integrity_reason"] = result.reason
print(json.dumps(report))
"""


def live_check(path: Path) -> dict | None:
    """Install the wheel in a throwaway venv and prove containment actually works.

    Returns ``None`` when the wheel targets a different platform than this host
    (the musllinux wheel on a glibc runner, say). That is not a failure: the static
    checks still ran, and the wheel gets its live check on a matching host.
    """
    with tempfile.TemporaryDirectory() as tmp:
        env_dir = Path(tmp) / "venv"
        venv.create(env_dir, with_pip=True)
        bin_dir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
        python = bin_dir / ("python.exe" if sys.platform == "win32" else "python")
        install = subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet", str(path)],
            capture_output=True,
            text=True,
        )
        if install.returncode != 0:
            if "not a supported wheel on this platform" in install.stderr:
                return None
            raise VerificationError(f"{path.name}: install failed:\n{install.stderr}")
        # Run outside the repo so a stray source tree cannot satisfy the import.
        proc = subprocess.run(
            [str(python), "-c", PROBE], capture_output=True, text=True, cwd=tmp, check=True
        )
    report = json.loads(proc.stdout)

    if not report["bundled"]:
        raise VerificationError(
            f"{path.name}: the installed package did not resolve its own bundled "
            f"core binary (got {report['core_binary']!r})"
        )
    if not report.get("integrity_verified"):
        raise VerificationError(
            f"{path.name}: bundled binary failed hash verification: "
            f"{report.get('integrity_reason')}"
        )
    if not report["can_contain"]:
        raise VerificationError(
            f"{path.name}: installed but reports no containment: {report['explain']}"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    parser.add_argument(
        "--live",
        action="store_true",
        help="also install each wheel and assert real containment (this host's wheel only)",
    )
    args = parser.parse_args()

    failures = []
    for wheel in args.wheels:
        if wheel.suffix != ".whl":
            continue
        try:
            tags = static_check(wheel)
            print(f"ok   {wheel.name}\n     tag: {tags}, core binary bundled and hashed")
            if args.live:
                report = live_check(wheel)
                if report is None:
                    print("     live: skipped, not installable on this host")
                else:
                    print(f"     live: {report['explain']}")
        except VerificationError as exc:
            failures.append(str(exc))
            print(f"FAIL {exc}", file=sys.stderr)

    if failures:
        print(f"\n{len(failures)} wheel(s) failed verification", file=sys.stderr)
        return 1
    print("\nall wheels carry a verified core binary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
