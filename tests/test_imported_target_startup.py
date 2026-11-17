"""Regression coverage for imported-project target startup repairs."""

from __future__ import annotations

import subprocess
from pathlib import Path
import stat
import sys

import pytest

from orchestrator.targets import TargetError, TargetSpec, Targets


REPO_ROOT = Path(__file__).resolve().parents[1]


class Process:
    pid = 2468

    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        return int(self.returncode or 0)


class Launcher:
    def __init__(self, process: Process) -> None:
        self.process = process

    def __call__(self, *_args, **_kwargs) -> Process:
        return self.process


class ProcessWindowRunner:
    def __init__(self, process_window: str = "9012\n") -> None:
        self.process_window = process_window
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str]) -> str:
        self.calls.append(command)
        if "--pid" in command:
            if self.process_window:
                return self.process_window
            raise subprocess.CalledProcessError(1, command)
        if command[1] == "search":
            raise subprocess.CalledProcessError(1, command)
        return ""


def target(process: Process, runner: ProcessWindowRunner) -> Targets:
    return Targets(
        display=":99",
        vnc_host_allowlist=["vnchost"],
        ssh_host_allowlist=[],
        rdp_host_allowlist=[],
        secrets_dir="secrets",
        runner=runner,
        launcher=Launcher(process),
        sleep=lambda _seconds: None,
        window_wait_seconds=0.1,
        poll_interval=0.1,
    )


def test_vnc_discovers_visible_window_by_launched_process_when_title_differs() -> None:
    process = Process()
    runner = ProcessWindowRunner()
    handle = target(process, runner).open_target(
        TargetSpec("vnc", {"host": "vnchost", "window": "guessed-title"})
    )

    assert handle.window_id == "9012"
    assert ["xdotool", "search", "--onlyvisible", "--pid", "2468"] in runner.calls
    assert ["xdotool", "windowactivate", "9012"] in runner.calls
    assert ["xdotool", "windowraise", "9012"] in runner.calls


def test_vnc_reports_early_client_exit_and_cleans_up() -> None:
    process = Process(returncode=23)
    runner = ProcessWindowRunner(process_window="")

    with pytest.raises(TargetError, match="exited with status 23"):
        target(process, runner).open_target(TargetSpec("vnc", {"host": "vnchost"}))

    assert process.terminated is False


def test_xauthority_cookie_is_private_nonshell_binary(tmp_path: Path) -> None:
    authority = tmp_path / "Xauthority"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "xauthority_cookie.py"),
            "--display",
            ":99",
            "--output",
            str(authority),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert stat.S_IMODE(authority.stat().st_mode) == 0o644
    payload = authority.read_bytes()
    assert b"MIT-MAGIC-COOKIE-1" in payload
    assert len(payload) < 128

    duplicate = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "xauthority_cookie.py"),
            "--display",
            ":99",
            "--output",
            str(authority),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode != 0


def test_host_app_bridge_stays_authenticated_loopback_only_and_the_launcher_refuses_it_under_the_0755_contract() -> None:
    """CP45-P: CP45-I deliberately REFUSES host-app targets (they needed a world-writable bridge state directory), so the old assertions that the launcher
    creates 'chmod 0711/0733' state directories are replaced by the opposite, negative ones.  What the bridge itself guarantees if it is ever re-enabled
    (authenticated, loopback-only X11) is still pinned; the refusal behaviour is executed for real in tests/test_cp45n_lifecycle_and_launch_refusals.py."""
    import re

    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()
    bridge = (REPO_ROOT / "scripts" / "host_app_bridge.py").read_text()

    # the deliberate refusal, in both places the launcher decides (before anything is created, and again before the bridge would start)
    assert "host-app targets are not supported (HOST_APP_ENABLED does not enable them)" in runner
    assert "host-app targets are not supported under the 0755 reports contract (CP45-I)" in runner
    assert runner.count("exit 78") >= 2
    # NEGATIVE coverage: the launcher must never create or loosen host-bridge state directories (the removed 0711 / 0733 behaviour) nor anything
    # world/group-writable or sticky anywhere
    assert 'chmod 0711 "${HOST_APP_STATE_ROOT}"' not in runner and 'chmod 0733 "${HOST_BRIDGE_STATE_DIR}"' not in runner
    assert not re.search(r"chmod\s+(-R\s+)?(0?[0-7]?[0-7][2367][2367]|[ugoa]*\+w|1[0-7]{3})\b", runner), re.findall(r"chmod[^\n]*", runner)
    assert not re.search(r"mkdir\s+-m\s*0?[0-7]*[2367][2367]\b", runner)
    # what the bridge guarantees if it is ever re-enabled stays pinned (loopback-only, authenticated X11)
    assert '127.0.0.1:${X11_PORT}:${X11_PORT}/tcp' in runner
    assert 'HOST_APP_X11_BRIDGE=1' in runner
    assert 'XAUTHORITY=${XAUTHORITY_CONTAINER}' in runner
    assert 'XVFB_TRANSPORT_ARGS=(-listen tcp -auth "${XAUTHORITY}")' in entrypoint
    assert 'env["XAUTHORITY"] = xauthority' in bridge
    assert "0.0.0.0:${X11_PORT}" not in runner and "-ac" not in re.findall(r"XVFB_TRANSPORT_ARGS=\([^)]*\)", entrypoint)


def test_imported_target_smoke_has_no_model_or_aws_client() -> None:
    smoke = (REPO_ROOT / "scripts" / "imported_target_startup_smoke.py").read_text()
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()

    assert "BedrockClient" not in smoke
    assert "boto" not in smoke
    assert "open_target" in smoke
    assert "close_target" in smoke
    assert "getwindowname" in smoke
    assert 'ORCHESTRATOR_DISABLE_AWS_FORWARDING:-0' in runner
