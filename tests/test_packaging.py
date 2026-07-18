"""Tests for the packaging config that ships the core binary in the wheel.

These guard the wheel-tagging and bundling contract without doing a slow full
build. The end-to-end "pip install the wheel and run it" check is a documented
command (see the README / scripts/bundle_core.py); this keeps the config honest on
every run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # hatch_build.py lives at the repo root, not installed

import hatch_build  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None  # type: ignore[assignment]

needs_toml = pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")


def _pyproject():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)


@needs_toml
def test_wheel_declares_the_core_bundle_artifacts():
    cfg = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert "asphallea/_core/**" in cfg["artifacts"]


@needs_toml
def test_wheel_uses_the_platform_tagging_hook():
    hooks = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["hooks"]
    assert hooks["custom"]["path"] == "hatch_build.py"


def test_bundled_binary_present_detects_the_core(tmp_path):
    # No _core directory -> pure Python source build.
    assert hatch_build.bundled_binary_present(str(tmp_path)) is False
    core = tmp_path / "asphallea" / "_core"
    core.mkdir(parents=True)
    (core / "checksums.json").write_text("{}", encoding="utf-8")
    # Manifest alone is not a binary.
    assert hatch_build.bundled_binary_present(str(tmp_path)) is False
    (core / "asphallea-run").write_bytes(b"\x7fELF")
    assert hatch_build.bundled_binary_present(str(tmp_path)) is True


def test_platform_tag_is_abi_agnostic_and_platform_specific():
    tag = hatch_build.platform_tag()
    assert tag.startswith("py3-none-")
    assert tag != "py3-none-any"  # a bundled wheel must be platform specific
    assert " " not in tag


@needs_toml
def test_project_metadata_is_well_formed():
    project = _pyproject()["project"]
    assert project["name"] == "asphallea"
    assert project["license"] == "Apache-2.0"
    assert project["authors"] == [{"name": "Genovo Technologies"}]
    # Every declared URL is absolute.
    for url in project.get("urls", {}).values():
        assert url.startswith("https://"), url
