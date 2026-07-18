"""Hatchling build hook: tag the wheel platform-specific when it bundles a binary.

A source build (no ``asphallea/_core`` binary) is pure Python and stays
``py3-none-any``. A release build, where ``scripts/bundle_core.py`` has dropped the
prebuilt core binary into ``asphallea/_core``, ships a native executable, so the
wheel must carry this platform's tag. This hook flips that on only when the binary
is present, so one release job per OS produces one correctly tagged wheel.

The decision helpers are plain stdlib so they can be unit-tested without hatchling
installed; the hatchling import is guarded for the same reason.
"""

from __future__ import annotations

import os
import sysconfig

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # tests import the helpers without hatchling present
    BuildHookInterface = object  # type: ignore[assignment,misc]


def bundled_binary_present(root: str) -> bool:
    """Whether a prebuilt core binary has been staged into ``asphallea/_core``."""
    core_dir = os.path.join(root, "asphallea", "_core")
    return os.path.isdir(core_dir) and any(
        name.startswith("asphallea-run") for name in os.listdir(core_dir)
    )


def platform_tag() -> str:
    """The wheel tag for a bundled build: ABI-agnostic, platform-specific."""
    plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return f"py3-none-{plat}"


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if bundled_binary_present(self.root):
            # The bundled core is a data binary, not a CPython extension, so the
            # wheel is platform specific but ABI agnostic: py3-none-<platform>.
            build_data["pure_python"] = False
            build_data["tag"] = platform_tag()
