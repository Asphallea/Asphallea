#!/usr/bin/env python3
"""Bundle the built ``asphallea-run`` core binary into the package for a wheel.

The distributed wheels ship a prebuilt (and, in the release pipeline, code-signed)
core binary so users never build Rust. This script copies the compiled binary into
``asphallea/_core/`` and records its SHA-256 in ``asphallea/_core/checksums.json``,
which the SDK verifies at runtime to reject a tampered or swapped binary.

Run it after ``cargo build --release`` in ``core/`` and before building the wheel:

    python scripts/bundle_core.py
    python -m build --wheel
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from asphallea import integrity  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="Path to the built asphallea-run binary.")
    parser.add_argument("--profile", default="release", help="Cargo profile dir (default: release).")
    args = parser.parse_args()

    exe = "asphallea-run.exe" if os.name == "nt" else "asphallea-run"
    src = Path(args.binary) if args.binary else ROOT / "core" / "target" / args.profile / exe
    if not src.is_file():
        sys.exit(
            f"core binary not found: {src}\n"
            "Build it first: (cd core && cargo build --release)"
        )

    dest_dir = ROOT / "asphallea" / "_core"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)
    if os.name != "nt":
        os.chmod(dest, 0o755)

    manifest = integrity.write_manifest(str(dest), destination=str(dest_dir / "checksums.json"))
    print(f"bundled {src.name} -> {dest}")
    print(f"manifest -> {manifest}")
    print("sha256  ->", integrity.sha256_file(str(dest)))


if __name__ == "__main__":
    main()
