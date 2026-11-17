"""R2J safe local-app launch diagnostics and source contracts."""

from __future__ import annotations

import io
import os
from pathlib import Path
import stat

from dashboard.capture_adapter import (
    CaptureLaunchError,
    RunnerControlledCaptureAdapter,
    _DIAGNOSTIC_LOG_LIMIT,
    _LaunchObservation,
)
from orchestrator.watch_learn_worker import WorkerState


def test_launch_observer_is_allowlisted_bounded_and_monotonic():
    observer = _LaunchObservation()
    observer.feed(b"password=must-not-become-state\n")
    observer.feed(b"WATCH_LEARN_STAGE=worker_started\n")
    observer.feed(b"WATCH_LEARN_STAGE=runner_start\n")
    observer.feed(b"WATCH_LEARN_STAGE=not-a-stage\n")
    observer.feed(b"WATCH_LEARN_FAILURE=app_launch_started:window_match_failed\n")
    observer.feed(b"WATCH_LEARN_FAILURE=worker_started:secret-value-here\n")
    assert observer.snapshot() == (
        "worker_started", "app_launch_started", "window_match_failed"
    )


def test_private_runner_log_is_mode_0600_and_hard_bounded(tmp_path):
    path = tmp_path / "private.log"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    observer = _LaunchObservation()
    stream = io.BytesIO(
        b"x" * (_DIAGNOSTIC_LOG_LIMIT + 8_192)
        + b"\nWATCH_LEARN_STAGE=initial_capture_started\n"
    )
    RunnerControlledCaptureAdapter._drain_diagnostic_output(
        stream, descriptor, observer
    )
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_size == _DIAGNOSTIC_LOG_LIMIT
    assert observer.snapshot()[0] == "initial_capture_started"


def test_typed_error_contains_only_safe_fixed_fields():
    failure = CaptureLaunchError(
        stage="app_launch_started",
        reason_code="window_match_failed",
        exit_status=3,
        container_name="phase17-" + "a" * 32,
        request_fifo_ready=True,
        response_fifo_ready=True,
        app_launch_reached=True,
        launch_window_verified=False,
        initial_frame_captured=False,
        cleanup_outcome="completed",
    )
    assert set(failure.safe_fields()) == {
        "stage", "reason_code", "exit_status", "container_name",
        "request_fifo_ready", "response_fifo_ready", "app_launch_reached",
        "launch_window_verified", "initial_frame_captured", "cleanup_outcome",
    }
    assert "password" not in str(failure).lower()
    assert "stderr" not in str(failure).lower()


class _Screenshot:
    png = b"redacted-png"


class _Computer:
    def screenshot(self):
        return _Screenshot()

    def release_controls(self):
        pass


def test_worker_initial_frame_emits_once_after_redacted_capture(capsys):
    state = WorkerState(_Computer(), None, None, "t" * 48)
    assert state.frame() == b"redacted-png"
    assert state.frame() == b"redacted-png"
    output = capsys.readouterr().out
    assert output.count("WATCH_LEARN_STAGE=initial_capture_started") == 1
    assert output.count("WATCH_LEARN_STAGE=initial_frame_captured_redacted") == 1


def test_runner_and_entrypoint_keep_local_capture_isolated():
    root = Path(__file__).resolve().parents[1]
    runner = (root / "scripts/run_container.sh").read_text(encoding="utf-8")
    entrypoint = (root / "docker/entrypoint.sh").read_text(encoding="utf-8")
    adapter = (root / "src/dashboard/capture_adapter.py").read_text(encoding="utf-8")
    assert 'NETWORK_ARGS=(--network=none)' in runner
    assert '--pull=never' in runner
    assert '--security-opt no-new-privileges' in runner
    assert 'echo "WATCH_LEARN_STAGE=runner_invoked"' in runner
    assert 'echo "WATCH_LEARN_STAGE=container_bootstrap"' in entrypoint
    assert "stdout=subprocess.PIPE" in adapter
    assert "stderr=subprocess.STDOUT" in adapter
    assert "_DIAGNOSTIC_LOG_LIMIT = 64 * 1024" in adapter
    assert "arbitrary subprocess" not in str(CaptureLaunchError).lower()
