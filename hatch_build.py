"""Hatchling build hook: tag the wheel platform-specific when it bundles a binary.

A source build (no ``asphallea/_core`` binary) is pure Python and stays
``py3-none-any``. A release build, where ``scripts/bundle_core.py`` has dropped the
prebuilt core binary into ``asphallea/_core``, ships a native executable, so the
wheel must carry this platform's tag. This hook flips that on only when the binary
is present, so one release job per OS produces one correctly tagged wheel.
"""

from __future__ import annotations

import os
import sysconfig

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        core_dir = os.path.join(self.root, "asphallea", "_core")
        has_binary = os.path.isdir(core_dir) and any(
            name.startswith("asphallea-run") for name in os.listdir(core_dir)
        )
        if has_binary:
            # The bundled core is a data binary, not a CPython extension, so the
            # wheel is platform specific but ABI agnostic: py3-none-<platform>.
            plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
            build_data["pure_python"] = False
            build_data["tag"] = f"py3-none-{plat}"
