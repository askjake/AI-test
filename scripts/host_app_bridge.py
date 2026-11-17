#!/usr/bin/env python3
"""Launch one explicitly allowlisted GUI application on the host X display.

The orchestrator itself remains inside its hardened container.  ``run_container.sh``
starts this small host-side manager alongside a single-project run and the container
signals it once Xvfb is accepting connections.  The child is placed in its own process
group and is terminated when the container run ends.

This is intentionally not a shell bridge.  The executable and working directory must
resolve below ``HOST_APP_ALLOW_ROOTS`` and argv is passed directly to ``Popen`` without
shell interpretation.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import yaml


class BridgeError(RuntimeError):
    """A host application request violates the bridge contract."""


_DISPLAY_RE = re.compile(r"^(?::[0-9]+|127\.0\.0\.1:[0-9]+)$")
_TRUE = {"1", "true", "yes", "on"}


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _inside(path: str, roots: list[str]) -> bool:
    return any(os.path.commonpath([root, path]) == root for root in roots)


def _roots() -> list[str]:
    raw = os.environ.get("HOST_APP_ALLOW_ROOTS", "")
    roots = [_real(item) for item in raw.split(os.pathsep) if item.strip()]
    if not roots:
        raise BridgeError(
            "HOST_APP_ALLOW_ROOTS is empty; refusing host application launch"
        )
    missing = [root for root in roots if not os.path.isdir(root)]
    if missing:
        raise BridgeError(f"allowlisted host application root is missing: {missing[0]}")
    return roots


def _load_target(config_path: str) -> dict | None:
    try:
        with open(config_path, encoding="utf-8") as fh:
            payload = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise BridgeError(f"cannot read project config {config_path!r}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BridgeError("project config must contain a YAML mapping")
    target = payload.get("target") or {}
    if not isinstance(target, dict):
        raise BridgeError("project target must be a YAML mapping")
    return target if str(target.get("type", "local-app")) == "host-app" else None


def _launch_plan(config_path: str) -> tuple[list[str], str] | None:
    target = _load_target(config_path)
    if target is None:
        return None
    if not _enabled(os.environ.get("HOST_APP_ENABLED")):
        raise BridgeError(
            "host-app target requested but HOST_APP_ENABLED is not set to 1"
        )

    raw_app = str(target.get("app") or "").strip()
    if not raw_app:
        raise BridgeError("host-app target requires an 'app' path")
    try:
        requested = shlex.split(raw_app)
    except ValueError as exc:
        raise BridgeError(f"invalid host-app command: {exc}") from exc
    if not requested:
        raise BridgeError("host-app target requires an 'app' path")

    roots = _roots()
    executable = _real(requested[0])
    if not os.path.isfile(executable):
        raise BridgeError(f"host application does not exist: {executable}")
    if not _inside(executable, roots):
        raise BridgeError(
            f"host application {executable!r} is outside HOST_APP_ALLOW_ROOTS"
        )

    raw_cwd = str(target.get("cwd") or os.path.dirname(executable))
    cwd = _real(raw_cwd)
    if not os.path.isdir(cwd):
        raise BridgeError(f"host application working directory does not exist: {cwd}")
    if not _inside(cwd, roots):
        raise BridgeError(
            f"host application working directory {cwd!r} is outside HOST_APP_ALLOW_ROOTS"
        )

    if os.access(executable, os.X_OK):
        argv = [executable, *requested[1:]]
    elif executable.endswith(".sh"):
        argv = ["/bin/bash", executable, *requested[1:]]
    else:
        raise BridgeError(f"host application is not executable: {executable}")
    return argv, cwd


def _wait_ready(path: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.isfile(path):
            return
        time.sleep(0.05)
    raise BridgeError(f"container X display did not become ready within {timeout:g}s")


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _stop_group(proc: subprocess.Popen) -> None:
    pgid = proc.pid
    if not _group_alive(pgid):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while _group_alive(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if not _group_alive(pgid):
        if proc.poll() is None:
            proc.wait(timeout=1)
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    if proc.poll() is None:
        proc.wait(timeout=5)


def _child_environment(display: str, xauthority: str | None = None) -> dict[str, str]:
    """Build a minimal desktop environment without dashboard/cloud credentials."""
    allowed_names = {
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "SHELL",
        "LANG",
        "TERM",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key in allowed_names or key.startswith("LC_")
    }
    env["DISPLAY"] = display
    if xauthority:
        env["XAUTHORITY"] = xauthority
    else:
        env.pop("XAUTHORITY", None)
    env["ORCHESTRATOR_HOST_APP"] = "1"
    return env


def run(
    config_path: str,
    display: str,
    ready_file: str,
    log_path: str,
    xauthority: str | None = None,
) -> int:
    if not _DISPLAY_RE.fullmatch(display):
        raise BridgeError(f"invalid X display: {display!r}")
    plan = _launch_plan(config_path)
    if plan is None:
        return 0

    try:
        timeout = float(os.environ.get("HOST_APP_READY_TIMEOUT", "30"))
    except ValueError as exc:
        raise BridgeError("HOST_APP_READY_TIMEOUT must be numeric") from exc
    if not 1 <= timeout <= 120:
        raise BridgeError("HOST_APP_READY_TIMEOUT must be between 1 and 120 seconds")
    _wait_ready(ready_file, timeout)

    authority = Path(xauthority) if xauthority else None
    if display.startswith("127.0.0.1:") and (
        authority is None
        or not authority.is_absolute()
        or authority.is_symlink()
        or not authority.is_file()
        or authority.parent != Path(ready_file).parent
    ):
        raise BridgeError("Xauthority file failed the per-run bridge boundary")

    argv, cwd = plan
    env = _child_environment(display, str(authority) if authority else None)

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    stop_requested = False

    def request_stop(_signum, _frame) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    print(
        f"[host-app] launching {argv[0]} on DISPLAY={display} (cwd={cwd})",
        flush=True,
    )
    with open(log_path, "ab", buffering=0) as log:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        print(f"[host-app] manager child pid={proc.pid}", flush=True)
        # BOOM-style wrappers sometimes background their GUI and exit. Keep the
        # manager alive while any process remains in the wrapper's process group,
        # so cleanup still owns the real application rather than orphaning it.
        while not stop_requested:
            direct_rc = proc.poll()
            if direct_rc is not None and not _group_alive(proc.pid):
                break
            time.sleep(0.1)
        if stop_requested:
            _stop_group(proc)
            print("[host-app] stopped with container run", flush=True)
            return 0
        rc = int(proc.returncode or 0)
        print(f"[host-app] process exited rc={rc}", flush=True)
        return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--display")
    parser.add_argument("--ready-file")
    parser.add_argument("--log")
    parser.add_argument("--xauthority")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--is-host-app", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.is_host_app:
            return 0 if _load_target(args.config) is not None else 3
        if not all((args.display, args.ready_file, args.log)):
            raise BridgeError("display, ready-file, and log are required")
        if args.check:
            _launch_plan(args.config)
            return 0
        return run(
            args.config,
            args.display,
            args.ready_file,
            args.log,
            args.xauthority,
        )
    except BridgeError as exc:
        print(f"[host-app] ERROR: {exc}", file=sys.stderr, flush=True)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
