"""Containment tier: run high-blast-radius tools under real OS enforcement.

Tools that spawn processes, execute generated code, or run a shell are the ones a
hijacked agent turns into a weapon. The policy tier can gate whether such a tool
runs at all, but it cannot contain what the spawned process then does. This module
does, by handing the command to the ``asphallea-run`` Rust core, which applies the
running platform's containment engine before it executes the command. On Linux that
is a Landlock filesystem allowlist, a seccomp-bpf syscall and network filter,
resource limits, and network-namespace isolation. On Windows it is a Job Object that
bounds memory, CPU, and process count and guarantees the whole process tree is
killed.

Honesty about platforms is the whole point. Containment coverage differs per OS, so
this module probes what the running host can actually enforce, per dimension, and
never claims more. A run proceeds contained only when the backend covers every
dimension the policy requires. When it does not, the call fails closed by default:
the command does not run, the refusal is logged, and the message names exactly which
dimension is missing. A developer who understands the risk can opt into degraded,
uncontained execution, which is logged on every call so it can never pass silently.
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

    Containment is multi-dimensional and the coverage differs per OS, so this is
    reported per dimension rather than as a single yes/no. Linux delivers all four
    (Landlock filesystem, seccomp network, resource limits, process termination).
    Windows delivers resource limits and guaranteed process termination via Job
    Objects today; filesystem and network allowlisting (AppContainer) are the next
    backend. macOS has no engine yet.

    Attributes:
        platform: The OS name, for example ``"Linux"``.
        core_binary: Path to the ``asphallea-run`` binary, or ``None``.
        backend: The containment engine, for example ``"linux-landlock-seccomp"``
            or ``"windows-job-object"``, or ``"none"``.
        filesystem_sandbox: Whether the backend enforces a filesystem allowlist.
        network_sandbox: Whether the backend denies network at the OS level.
        resource_limits: Whether the backend enforces memory/CPU/process limits.
        process_kill: Whether the backend guarantees termination of the process
            tree.
        landlock_abi: Linux only. The Landlock ABI version, or 0.
        seccomp: Linux only. Whether seccomp-bpf is available.
        user_namespaces: Linux only.
        net_namespaces: Linux only.
        version: The core binary version string, if known.
    """

    platform: str
    core_binary: Optional[str]
    backend: str = "none"
    filesystem_sandbox: bool = False
    network_sandbox: bool = False
    resource_limits: bool = False
    process_kill: bool = False
    landlock_abi: int = 0
    seccomp: bool = False
    user_namespaces: bool = False
    net_namespaces: bool = False
    version: Optional[str] = None

    @property
    def can_contain(self) -> bool:
        """True when a real OS containment backend is present on this host."""
        return self.core_binary is not None and (
            self.filesystem_sandbox or self.resource_limits or self.process_kill
        )

    def covers(self, *, filesystem: bool, network: bool) -> bool:
        """Whether the backend enforces every dimension a policy requires."""
        if not self.can_contain:
            return False
        if filesystem and not self.filesystem_sandbox:
            return False
        if network and not self.network_sandbox:
            return False
        return True

    def dimensions(self) -> str:
        """A human list of what the backend enforces."""
        parts = []
        if self.filesystem_sandbox:
            parts.append("filesystem allowlist")
        if self.network_sandbox:
            parts.append("network deny")
        if self.resource_limits:
            parts.append("resource limits")
        if self.process_kill:
            parts.append("process termination")
        return ", ".join(parts) if parts else "nothing"

    def shortfall(self, *, filesystem: bool, network: bool) -> str:
        """The required dimensions this backend cannot enforce."""
        missing = []
        if filesystem and not self.filesystem_sandbox:
            missing.append("filesystem allowlisting")
        if network and not self.network_sandbox:
            missing.append("network isolation")
        return ", ".join(missing)

    def explain(self) -> str:
        """Return a one-line summary of what containment this host delivers."""
        if not self.can_contain:
            if self.core_binary is None:
                return (
                    f"the {CORE_BINARY_NAME} core binary was not found for "
                    f"{self.platform}. Build it in core/ (cargo build --release) and "
                    "put it on PATH or set ASPHALLEA_CORE_BIN."
                )
            return (
                f"no OS containment engine is available on {self.platform} yet "
                "(macOS Seatbelt is planned)."
            )
        return f"{self.backend} on {self.platform} contains: {self.dimensions()}."


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
    if binary is not None and system in ("Linux", "Windows"):
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

    if system == "Linux":
        landlock_abi = int(data.get("landlock_abi", 0))
        seccomp = bool(data.get("seccomp", False))
        return Capabilities(
            platform=system,
            core_binary=binary,
            backend="linux-landlock-seccomp",
            filesystem_sandbox=landlock_abi >= 1,
            network_sandbox=seccomp,  # seccomp blocks IP socket creation
            resource_limits=True,
            process_kill=True,
            landlock_abi=landlock_abi,
            seccomp=seccomp,
            user_namespaces=bool(data.get("user_namespaces", False)),
            net_namespaces=bool(data.get("net_namespaces", False)),
            version=data.get("version"),
        )

    # Windows: the Job Object backend reports its dimensions directly.
    return Capabilities(
        platform=system,
        core_binary=binary,
        backend=str(data.get("backend", "windows-job-object")),
        filesystem_sandbox=bool(data.get("filesystem_sandbox", False)),
        network_sandbox=bool(data.get("network_sandbox", False)),
        resource_limits=bool(data.get("resource_limits", False)),
        process_kill=bool(data.get("process_kill", False)),
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
    # Which containment dimensions does this policy actually require?
    requires_fs = bool(policy.read_paths or policy.write_paths)
    requires_net = policy.network == "deny"

    if not caps.covers(filesystem=requires_fs, network=requires_net):
        # The backend cannot enforce every dimension this policy requires. Fail
        # closed rather than run partially contained and pretend otherwise.
        if caps.can_contain:
            short = caps.shortfall(filesystem=requires_fs, network=requires_net)
            reason = (
                f"{caps.backend} on {caps.platform} enforces {caps.dimensions()}, but "
                f"this policy also requires {short}, which this backend cannot deliver "
                "yet. Failing closed rather than run partially contained."
            )
        else:
            reason = caps.explain()
        if not allow_degraded:
            deny = Decision.deny("containment_unavailable", reason)
            _audit(audit, tool, deny, command, policy.name, tier="containment",
                   detail={"capabilities": _caps_dict(caps)})
            raise ContainmentUnavailable(deny, tool)

        message = (
            f"ASPHALLEA DEGRADED MODE: running {tool!r} without full OS containment. {reason}"
        )
        warnings.warn(message, RuntimeWarning, stacklevel=2)
        print(message, file=sys.stderr)
        degraded_allow = Decision.allow("ran without full OS containment (allow_degraded)")
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
        "backend": caps.backend,
        "core_binary": caps.core_binary,
        "filesystem_sandbox": caps.filesystem_sandbox,
        "network_sandbox": caps.network_sandbox,
        "resource_limits": caps.resource_limits,
        "process_kill": caps.process_kill,
        "landlock_abi": caps.landlock_abi,
        "seccomp": caps.seccomp,
    }
