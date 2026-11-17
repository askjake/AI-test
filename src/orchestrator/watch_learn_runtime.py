"""Post-drop display handoff for the private Watch & Learn worker.

The root bootstrap has already opened the private FIFO descriptors and
permanently dropped identity before this module starts.  Display helpers run
with the control descriptors marked close-on-exec.  Only the final bounded
worker command receives the descriptors.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import time


def _launch_stage(stage: str) -> None:
    if stage not in {"x_display_start", "display_ready", "worker_exec"}:
        raise ValueError("unallowlisted runtime launch stage")
    print(f"WATCH_LEARN_STAGE={stage}", flush=True)


def _control_descriptors() -> tuple[int, int]:
    values = (
        os.environ.get("WATCH_LEARN_REQUEST_FD", ""),
        os.environ.get("WATCH_LEARN_RESPONSE_FD", ""),
    )
    if any(not value.isdigit() for value in values):
        raise ValueError("private control descriptors are unavailable")
    descriptors = int(values[0]), int(values[1])
    if any(descriptor < 3 or descriptor > 1_024 for descriptor in descriptors):
        raise ValueError("private control descriptors are invalid")
    for descriptor in descriptors:
        os.fstat(descriptor)
    return descriptors


def _stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run(
    command: list[str],
    *,
    display: str,
    screen_width: int,
    screen_height: int,
    screen_depth: int,
) -> int:
    if os.getuid() == 0 or os.getgid() == 0 or os.getgroups():
        raise PermissionError("Watch & Learn display handoff requires permanent non-root identity")
    if not command or not command[0]:
        raise ValueError("Watch & Learn worker command is required")
    descriptors = _control_descriptors()
    for descriptor in descriptors:
        os.set_inheritable(descriptor, False)

    os.environ["DISPLAY"] = display
    runtime_dir = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp/runtime"))
    home = Path(os.environ.get("HOME", "/home/orchestrator"))
    for directory in (Path("/tmp/.X11-unix"), runtime_dir, home):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    try:
        runtime_dir.chmod(0o700)
    except OSError:
        pass

    print(
        f"[entrypoint] runtime privileges dropped to uid={os.getuid()} gid={os.getgid()}",
        flush=True,
    )
    print(
        f"[entrypoint] starting Xvfb on {display} at "
        f"{screen_width}x{screen_height}x{screen_depth}",
        flush=True,
    )
    xvfb: subprocess.Popen[bytes] | None = None
    window_manager: subprocess.Popen[bytes] | None = None
    try:
        _launch_stage("x_display_start")
        xvfb = subprocess.Popen(
            [
                "Xvfb", display, "-screen", "0",
                f"{screen_width}x{screen_height}x{screen_depth}", "-nolisten", "tcp",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        for _ in range(50):
            if xvfb.poll() is not None:
                raise RuntimeError(f"Xvfb exited before display {display} became ready")
            ready = subprocess.run(
                ["xdpyinfo", "-display", display],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1,
                check=False,
                close_fds=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"Xvfb did not come up on {display}")

        print("[entrypoint] launching window manager (fluxbox)", flush=True)
        window_manager = subprocess.Popen(
            ["fluxbox"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        _launch_stage("display_ready")
        for descriptor in descriptors:
            os.set_inheritable(descriptor, True)
        print("[entrypoint] display ready; handing off to bounded Watch & Learn worker", flush=True)
        _launch_stage("worker_exec")
        os.execvpe(command[0], command, os.environ)
    finally:
        _stop(window_manager)
        _stop(xvfb)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--display", required=True)
    parser.add_argument("--screen-width", type=int, required=True)
    parser.add_argument("--screen-height", type=int, required=True)
    parser.add_argument("--screen-depth", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    return run(
        command,
        display=arguments.display,
        screen_width=arguments.screen_width,
        screen_height=arguments.screen_height,
        screen_depth=arguments.screen_depth,
    )


if __name__ == "__main__":
    raise SystemExit(main())
