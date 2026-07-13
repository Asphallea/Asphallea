"""Containment tier: run high-blast-radius tools under real OS enforcement.

Tools that spawn processes, execute generated code, or run a shell are the ones a
hijacked agent turns into a weapon. The policy tier can gate whether such a tool
runs at all, but it cannot contain what the spawned process then does. This module
does, by handing the command to the ``asphallea-run`` Rust core, which applies a
Landlock filesystem allowlist, a seccomp-bpf syscall and network filter, resource
limits, and best-effort network-namespace isolation before it executes the command.

Honesty about platforms is the whole point. Real containment is Linux first and
needs a recent kernel. This module probes what the running kernel and the installed
core binary can actually do, and it never claims containment it cannot deliver. When
containment is unavailable it fails closed by default: the command does not run, the
refusal is logged, and a loud message explains what is missing. A developer who
understands the risk can opt into degraded, uncontained execution, which is logged
on every call so it can never pass silently.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .audit import AuditRecord, AuditSink
from .engine import Decision, Engine
from .guard import PolicyViolation
from .policy import Policy

__all__ = [
    "run",
    "capabilities",
    "core_binary",
    "Capabilities",
    "SandboxResult",
    "ContainmentUnavailable",
    "CORE_BINARY_NAME",
]

CORE_BINARY_NAME = "asphallea-run"


class ContainmentUnavailable(PolicyViolation):
    """Raised when OS containment cannot be delivered and degraded mode is off.

    This is a fail-closed refusal, not a policy deny. It means Asphallea would
    have had to run the command without the OS enforcement the policy implies, so
    it declined. Pass ``allow_degraded=True`` to run anyway, at your own risk.
    """


@dataclass(frozen=True)
class Capabilities:
    """What OS containment the running environment can actually deliver.

    Attributes:
        platform: The OS name, for example ``"Linux"``.
        core_binary: Path to the ``asphallea-run`` binary, or ``None``.
        landlock_abi: The Landlock ABI version the kernel supports, or 0.
        seccomp: Whether seccomp-bpf filtering is available.
        user_namespaces: Whether unprivileged user namespaces are available.
        net_namespaces: Whether network-namespace isolation is available.
        version: The core binary version string, if known.
    """

    platform: str
    core_binary: Optional[str]
    landlock_abi: int = 0
    seccomp: bool = False
    user_namespaces: bool = False
    net_namespaces: bool = False
    version: Optional[str] = None

    @property
    def can_contain(self) -> bool:
        """True when the core can enforce at least filesystem and syscall limits."""
        return (
            self.platform == "Linux"
            and self.core_binary is not None
            and self.landlock_abi >= 1
            and self.seccomp
        )

    def explain(self) -> str:
        """Return a one-line, specific reason containment is or is not available."""
        if self.platform != "Linux":
            return (
                f"OS containment is Linux only. This host is {self.platform}. "
                "The policy tier still enforces; the containment tier is unavailable."
            )
        if self.core_binary is None:
            return (
                f"the {CORE_BINARY_NAME} core binary was not found. Build it with "
                "`cargo build --release` in core/ and put it on PATH or set "
                "ASPHALLEA_CORE_BIN."
            )
        if self.landlock_abi < 1:
            return (
                "this kernel does not support Landlock (needs 5.13+). Filesystem "
                "containment cannot be enforced."
            )
        if not self.seccomp:
            return "this kernel does not support seccomp-bpf. Syscall filtering cannot be enforced."
        return "OS containment is available."


@dataclass
class SandboxResult:
    """The outcome of a contained (or explicitly degraded) command execution.

    Attributes:
        returncode: The process exit code. A non-zero code often means the
            contained command tried something the sandbox blocked.
        stdout: Captured standard output.
        stderr: Captured standard error.
        contained: True if OS containment was actually applied.
        degraded: True if the command ran without containment under
            ``allow_degraded``.
        controls: What the core reported applying, for example Landlock status and
            seccomp filter size.
        command: The command that was run.
    """

    returncode: int
    stdout: str
    stderr: str
    contained: bool
    degraded: bool = False
    controls: Dict[str, Any] = field(default_factory=dict)
    command: List[str] = field(default_factory=list)


_CAPS_CACHE: Optional[Capabilities] = None


def core_binary() -> Optional[str]:
    """Locate the ``asphallea-run`` core binary.

    Search order: the ``ASPHALLEA_CORE_BIN`` environment variable, then ``PATH``,
    then a few conventional build locations relative to this package. Returns the
    path, or ``None`` if not found.
    """
    env = os.environ.get("ASPHALLEA_CORE_BIN")
    if env and Path(env).is_file():
        return env

    on_path = shutil.which(CORE_BINARY_NAME)
    if on_path:
        return on_path

    exe = CORE_BINARY_NAME + (".exe" if os.name == "nt" else "")
    here = Path(__file__).resolve().parent
    candidates = [
        here / "_core" / exe,                                   # bundled next to package
        here.parent / "core" / "target" / "release" / exe,     # dev build
        here.parent / "core" / "target" / "debug" / exe,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def capabilities(*, refresh: bool = False) -> Capabilities:
    """Detect what OS containment this environment can deliver.

    Probes the core binary (``asphallea-run --probe``) on Linux to read the
    Landlock ABI and seccomp and namespace support from the live kernel. Results
    are cached; pass ``refresh=True`` to re-probe.
    """
    global _CAPS_CACHE
    if _CAPS_CACHE is not None and not refresh:
        return _CAPS_CACHE

    system = platform.system()
    binary = core_binary()

    caps = Capabilities(platform=system, core_binary=binary)
    if system == "Linux" and binary is not None:
        caps = _probe(binary, system)

    _CAPS_CACHE = caps
    return caps


def _probe(binary: str, system: str) -> Capabilities:
    try:
        proc = subprocess.run(
            [binary, "--probe"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return Capabilities(platform=system, core_binary=binary)

    return Capabilities(
        platform=system,
        core_binary=binary,
        landlock_abi=int(data.get("landlock_abi", 0)),
        seccomp=bool(data.get("seccomp", False)),
        user_namespaces=bool(data.get("user_namespaces", False)),
        net_namespaces=bool(data.get("net_namespaces", False)),
        version=data.get("version"),
    )


def run(
    command: Sequence[str],
    *,
    policy: Optional[Policy] = None,
    engine: Optional[Engine] = None,
    tool: str = "sandbox",
    audit: Optional[AuditSink] = None,
    allow_degraded: bool = False,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    input: Optional[str] = None,
) -> SandboxResult:
    """Run ``command`` under OS containment defined by ``policy``.

    Args:
        command: The command and arguments, for example ``["bash", "-c", src]``.
        policy: The policy to enforce. Provide this or ``engine``.
        engine: A shared engine, to count call and spend limits across tools.
        tool: The tool name for the policy tier check and the audit trail.
        audit: Where to record the decision.
        allow_degraded: If True and containment is unavailable, run the command
            without OS enforcement and log the degradation. If False (default),
            fail closed and raise :class:`ContainmentUnavailable`.
        timeout: Wall-clock ceiling in seconds. On breach the whole process group
            is killed.
        cwd: Working directory for the command.
        env: Environment for the command. Defaults to the current environment.
        input: Optional string written to the command's stdin.

    Returns:
        A :class:`SandboxResult`.

    Raises:
        PolicyViolation: If the policy tier denies the tool (allowlist, call
            limit, rate, or spend).
        ContainmentUnavailable: If OS containment is unavailable and
            ``allow_degraded`` is False.
    """
    if engine is None:
        if policy is None:
            raise ValueError("run() requires either policy or engine")
        engine = Engine(policy)
    policy = engine.policy
    command = list(command)

    # Policy tier: gate whether this tool may run at all, and count it. Network
    # and filesystem are enforced by the OS containment below, not pre-checked
    # here, because a shell can reference paths we cannot see from the arguments.
    decision = engine.check(tool, network=False)
    _audit(audit, tool, decision, command, policy.name, tier="policy")
    if decision.denied:
        raise PolicyViolation(decision, tool)

    caps = capabilities()

    if not caps.can_contain:
        reason = caps.explain()
        if not allow_degraded:
            deny = Decision.deny("containment_unavailable", reason)
            _audit(audit, tool, deny, command, policy.name, tier="containment",
                   detail={"capabilities": _caps_dict(caps)})
            raise ContainmentUnavailable(deny, tool)

        message = (
            f"ASPHALLEA DEGRADED MODE: running {tool!r} WITHOUT OS containment. {reason}"
        )
        warnings.warn(message, RuntimeWarning, stacklevel=2)
        print(message, file=sys.stderr)
        degraded_allow = Decision.allow("ran without OS containment (allow_degraded)")
        _audit(audit, tool, degraded_allow, command, policy.name, tier="containment",
               rule="degraded", detail={"capabilities": _caps_dict(caps)})
        proc = _exec(command, timeout=timeout, cwd=cwd, env=env, input=input)
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            contained=False,
            degraded=True,
            controls={"contained": False, "reason": reason},
            command=command,
        )

    return _run_contained(
        command,
        policy=policy,
        binary=caps.core_binary,  # type: ignore[arg-type]
        tool=tool,
        audit=audit,
        timeout=timeout,
        cwd=cwd,
        env=env,
        input=input,
    )


def _run_contained(command, *, policy, binary, tool, audit, timeout, cwd, env, input):
    with tempfile.TemporaryDirectory(prefix="asphallea-") as tmp:
        policy_path = os.path.join(tmp, "policy.json")
        report_path = os.path.join(tmp, "report.json")
        with open(policy_path, "w", encoding="utf-8") as fh:
            json.dump(policy.to_core_json(), fh)

        argv = [binary, "--policy", policy_path, "--report", report_path, "--strict", "--"]
        argv.extend(command)

        proc = _exec(argv, timeout=timeout, cwd=cwd, env=env, input=input)

        controls: Dict[str, Any] = {}
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                controls = json.load(fh)
        except (OSError, ValueError):
            controls = {"contained": True, "report": "unavailable"}

        allow = Decision.allow("contained by OS enforcement")
        _audit(audit, tool, allow, command, policy.name, tier="containment", detail=controls)
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            contained=True,
            degraded=False,
            controls=controls,
            command=command,
        )


def _exec(argv, *, timeout, cwd, env, input):
    """Run a process, killing the whole group if it overruns the timeout."""
    new_session = os.name == "posix"
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        start_new_session=new_session,
    )
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        stdout, stderr = proc.communicate()
        stderr = (stderr or "") + f"\nasphallea: killed after timeout of {timeout:g}s\n"
        return subprocess.CompletedProcess(argv, returncode=124, stdout=stdout or "", stderr=stderr)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout or "", stderr or "")


def _kill_tree(proc: "subprocess.Popen") -> None:
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), 9)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _audit(audit, tool, decision, command, policy_name, *, tier, rule=None, detail=None):
    if audit is None:
        return
    audit.write(
        AuditRecord(
            tool=tool,
            decision="allow" if decision.allowed else "deny",
            rule=rule if rule is not None else decision.rule,
            reason=decision.reason,
            tier=tier,
            args=list(command),
            kwargs={},
            policy=policy_name,
            detail=detail,
        )
    )


def _caps_dict(caps: Capabilities) -> Dict[str, Any]:
    return {
        "platform": caps.platform,
        "core_binary": caps.core_binary,
        "landlock_abi": caps.landlock_abi,
        "seccomp": caps.seccomp,
        "user_namespaces": caps.user_namespaces,
        "net_namespaces": caps.net_namespaces,
    }
