"""Project-scoped process ownership and cancellation helpers.

Dashboard-triggered runs are launched in their own POSIX session.  This module records and
validates that identity before cancellation so a stale PID can never cause an unrelated
process group to be signalled.  Container shutdown is also scoped to the deterministic name
assigned to the same trigger.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from typing import Any


class RunControlError(RuntimeError):
    """The requested run cannot be controlled without violating ownership checks."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pgid: int
    start_ticks: int


_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def container_name(project: str, trigger_id: str) -> str:
    """Return a bounded, deterministic Docker/Podman name for one trigger."""
    raw = f"orchestrator-cookie-{project}-{trigger_id}"
    if len(raw) <= 120 and _CONTAINER_RE.fullmatch(raw):
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    prefix = re.sub(r"[^A-Za-z0-9_.-]", "-", raw)[:100].rstrip("-.")
    value = f"{prefix}-{digest}"
    if not _CONTAINER_RE.fullmatch(value):
        raise RunControlError("could not derive a safe runner container name")
    return value


def _start_ticks(pid: int) -> int:
    """Read Linux /proc start ticks (field 22), which protects against PID reuse."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise RunControlError("the run process is no longer present") from exc
    close_paren = raw.rfind(")")
    fields = raw[close_paren + 2 :].split()
    if close_paren < 0 or len(fields) <= 19:
        raise RunControlError("could not validate the run process identity")
    try:
        return int(fields[19])
    except ValueError as exc:
        raise RunControlError("could not validate the run process start time") from exc


def _cmdline(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as exc:
        raise RunControlError("the run process is no longer present") from exc
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def _matches_trigger_process(
    pid: int,
    *,
    project: str,
    control_path: str,
    script_path: str,
) -> bool:
    try:
        argv = _cmdline(pid)
    except RunControlError:
        return False
    expected_script = os.path.realpath(script_path)
    expected_control = os.path.realpath(control_path)
    for index, argument in enumerate(argv):
        if os.path.realpath(argument) != expected_script:
            continue
        if index + 2 >= len(argv):
            return False
        return (
            argv[index + 1] == project
            and os.path.realpath(argv[index + 2]) == expected_control
        )
    return False


def capture_process_identity(
    pid: int,
    *,
    project: str,
    control_path: str,
    script_path: str,
) -> ProcessIdentity:
    """Capture a newly spawned trigger only after verifying its exact argv/session."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise RunControlError("the launcher did not return a valid process id")
    try:
        pgid = os.getpgid(pid)
        sid = os.getsid(pid)
    except OSError as exc:
        raise RunControlError("the run process ended before its identity was recorded") from exc
    if pgid != pid or sid != pid:
        raise RunControlError("the run process is not in its expected isolated session")
    if not _matches_trigger_process(
        pid,
        project=project,
        control_path=control_path,
        script_path=script_path,
    ):
        raise RunControlError("the run process command does not match its trigger")
    return ProcessIdentity(pid=pid, pgid=pgid, start_ticks=_start_ticks(pid))


def resolve_process_identity(
    payload: dict[str, Any],
    *,
    project: str,
    control_path: str,
    script_path: str,
) -> ProcessIdentity | None:
    """Resolve persisted metadata, falling back to exact /proc discovery for old runs."""
    pid = payload.get("pid")
    pgid = payload.get("pgid")
    start_ticks = payload.get("process_start_ticks")
    if all(isinstance(value, int) and not isinstance(value, bool) for value in (pid, pgid, start_ticks)):
        identity = ProcessIdentity(pid=pid, pgid=pgid, start_ticks=start_ticks)
        validate_process_identity(
            identity,
            project=project,
            control_path=control_path,
            script_path=script_path,
        )
        return identity

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        # Non-Linux cancellation remains safely scoped by deterministic container
        # identity. The Python wrapper exits when that exact container is stopped.
        return None
    matches: list[ProcessIdentity] = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        candidate = int(entry.name)
        if not _matches_trigger_process(
            candidate,
            project=project,
            control_path=control_path,
            script_path=script_path,
        ):
            continue
        try:
            matches.append(
                capture_process_identity(
                    candidate,
                    project=project,
                    control_path=control_path,
                    script_path=script_path,
                )
            )
        except RunControlError:
            continue
    if len(matches) > 1:
        raise RunControlError("multiple processes claim the same project trigger")
    return matches[0] if matches else None


def spawn_session_kwargs() -> dict[str, Any]:
    """Return the platform-native isolated process-group flags for Popen."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def validate_process_identity(
    identity: ProcessIdentity,
    *,
    project: str,
    control_path: str,
    script_path: str,
) -> None:
    """Revalidate PID, session, argv, and start time immediately before signalling."""
    try:
        observed_pgid = os.getpgid(identity.pid)
        observed_sid = os.getsid(identity.pid)
    except OSError as exc:
        raise RunControlError("the run process is no longer present") from exc
    if observed_pgid != identity.pgid or observed_sid != identity.pid:
        raise RunControlError("the run process session identity changed")
    if identity.pgid != identity.pid:
        raise RunControlError("refusing to signal a non-isolated process group")
    if _start_ticks(identity.pid) != identity.start_ticks:
        raise RunControlError("the recorded run PID has been reused")
    if not _matches_trigger_process(
        identity.pid,
        project=project,
        control_path=control_path,
        script_path=script_path,
    ):
        raise RunControlError("the recorded process no longer matches this project trigger")


def terminate_process_group(identity: ProcessIdentity, *, grace_seconds: float = 3.0) -> None:
    """Terminate one previously validated isolated process group, then bound escalation."""
    try:
        os.killpg(identity.pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline:
        try:
            os.killpg(identity.pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.killpg(identity.pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def resolve_engine() -> str | None:
    configured = os.environ.get("ENGINE", "").strip()
    if configured:
        if os.path.sep in configured:
            return configured if os.path.isfile(configured) and os.access(configured, os.X_OK) else None
        return shutil.which(configured)
    return shutil.which("docker") or shutil.which("podman")


def stop_container(name: str, *, timeout_seconds: int = 8) -> bool:
    """Stop exactly one named runner container; return False when it does not exist."""
    if not _CONTAINER_RE.fullmatch(name):
        raise RunControlError("refusing an invalid runner container name")
    engine = resolve_engine()
    if not engine:
        return False
    inspected = subprocess.run(
        [engine, "inspect", name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=timeout_seconds,
    )
    if inspected.returncode != 0:
        return False
    stopped = subprocess.run(
        [engine, "stop", "--time", "3", name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
        text=True,
    )
    if stopped.returncode != 0:
        raise RunControlError("the project runner container could not be stopped")
    return True


def container_state(name: str, *, timeout_seconds: int = 8) -> str:
    """'absent' | 'stopped' | 'running' | 'unknown'.  Only 'absent' and 'stopped' confirm a teardown; an unreadable engine is 'unknown' (uncertain)."""
    if not _CONTAINER_RE.fullmatch(name):
        raise RunControlError("refusing an invalid runner container name")
    engine = resolve_engine()
    if not engine:
        return "unknown"
    try:
        result = subprocess.run(
            [engine, "inspect", "--format", "{{.State.Running}}", name],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    out = (result.stdout or "").strip().lower()
    if result.returncode == 0:
        return "running" if out == "true" else "stopped" if out == "false" else "unknown"
    err = (result.stderr or "").lower()
    return "absent" if ("no such" in err or "not found" in err or "no container" in err) else "unknown"


def process_group_alive(pgid: int):
    """True if the process group still exists, False if it is gone, None if that cannot be determined."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True
