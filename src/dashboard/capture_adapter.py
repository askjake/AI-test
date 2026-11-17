"""Private runner-controlled capture transport for Phase 17.

The production adapter uses the hardened runner and an explicitly mounted pair
of private FIFOs. The runner root bootstrap creates the endpoints, makes them
dashboard-owned, and passes open descriptors across the
permanent uid-10001 drop. A random capability crosses only the dashboard-owned
stdin pipe. Nothing is exposed on TCP and no capability is placed in argv,
environment, logs, or a shared file.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import stat
import struct
import subprocess
import tempfile
import threading
import time
from typing import Callable, Protocol

from .authoring import ProjectDocument
from .config import DashboardSettings
from .demonstration_models import CaptureAction, ReceiptOutcome, TargetCapability, TargetType
from watch_learn_privacy import (
    WATCH_LEARN_SELF_TEST_REDACTION,
    redaction_configuration_revision,
)


_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,240}@sha256:[a-f0-9]{64}$")
_SESSION_RE = re.compile(r"^[a-f0-9]{32}$")
_UNAVAILABLE_DETAIL = (
    "This target type has no approved runner-controlled Watch & Learn adapter. "
    "No adapter or target will be contacted."
)
_DIAGNOSTIC_LOG_LIMIT = 64 * 1024
_LAUNCH_STAGE_SEQUENCE = (
    "project_mount_preparation",
    "pinned_image_verification",
    "control_directory",
    "runner_start",
    "capability_handoff",
    "fifo_wait",
    "runner_invoked",
    "container_bootstrap",
    "fifo_bootstrap",
    "x_display_start",
    "display_ready",
    "worker_exec",
    "worker_started",
    "project_loaded",
    "app_launch_started",
    "launch_window_verified",
    "initial_capture_started",
    "initial_frame_captured_redacted",
    "initial_frame_returned",
)
_LAUNCH_STAGES = frozenset(_LAUNCH_STAGE_SEQUENCE)
_LAUNCH_STAGE_RANK = {name: index for index, name in enumerate(_LAUNCH_STAGE_SEQUENCE)}
_LAUNCH_FAILURE_REASONS = frozenset({
    "project_mount_unreadable",
    "runtime_verification_failed",
    "control_directory_failed",
    "runner_start_failed",
    "capability_handoff_failed",
    "runner_exited",
    "fifo_timeout",
    "fifo_invalid",
    "project_config_invalid",
    "target_launch_failed",
    "window_match_failed",
    "capture_failed",
    "initial_frame_invalid",
    "initial_frame_timeout",
    "unexpected_failure",
})


class CaptureLaunchError(RuntimeError):
    """Typed, browser-safe launch failure with no subprocess text or secret values."""

    def __init__(
        self,
        *,
        stage: str,
        reason_code: str,
        exit_status: int | None,
        container_name: str,
        request_fifo_ready: bool,
        response_fifo_ready: bool,
        app_launch_reached: bool,
        launch_window_verified: bool,
        initial_frame_captured: bool,
        cleanup_outcome: str,
    ) -> None:
        if stage not in _LAUNCH_STAGES or reason_code not in _LAUNCH_FAILURE_REASONS:
            raise ValueError("unallowlisted capture launch diagnostic")
        if not re.fullmatch(r"phase17-[a-f0-9]{32}", container_name):
            raise ValueError("invalid capture container name")
        if cleanup_outcome not in {"completed", "partial", "not-started"}:
            raise ValueError("invalid capture cleanup outcome")
        self.stage = stage
        self.reason_code = reason_code
        self.exit_status = exit_status
        self.container_name = container_name
        self.request_fifo_ready = request_fifo_ready
        self.response_fifo_ready = response_fifo_ready
        self.app_launch_reached = app_launch_reached
        self.launch_window_verified = launch_window_verified
        self.initial_frame_captured = initial_frame_captured
        self.cleanup_outcome = cleanup_outcome
        super().__init__(
            "runner-controlled capture launch failed "
            f"stage={stage} reason={reason_code} exit_status={exit_status} "
            f"container={container_name} request_fifo={request_fifo_ready} "
            f"response_fifo={response_fifo_ready} app_launch={app_launch_reached} "
            f"window_verified={launch_window_verified} "
            f"initial_frame={initial_frame_captured} cleanup={cleanup_outcome}"
        )

    def safe_fields(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "reason_code": self.reason_code,
            "exit_status": self.exit_status,
            "container_name": self.container_name,
            "request_fifo_ready": self.request_fifo_ready,
            "response_fifo_ready": self.response_fifo_ready,
            "app_launch_reached": self.app_launch_reached,
            "launch_window_verified": self.launch_window_verified,
            "initial_frame_captured": self.initial_frame_captured,
            "cleanup_outcome": self.cleanup_outcome,
        }


class _LaunchObservation:
    """Accept only exact allowlisted markers from otherwise untrusted runner output."""

    def __init__(self) -> None:
        self.stage: str | None = None
        self.failure_stage: str | None = None
        self.failure_reason: str | None = None
        self._pending = b""
        self._discard_line = False
        self._lock = threading.Lock()

    def feed(self, value: bytes) -> None:
        with self._lock:
            for byte in value:
                if byte == 10:
                    if not self._discard_line:
                        self._accept(self._pending.rstrip(b"\r"))
                    self._pending = b""
                    self._discard_line = False
                elif not self._discard_line:
                    if len(self._pending) < 512:
                        self._pending += bytes((byte,))
                    else:
                        self._pending = b""
                        self._discard_line = True

    def _accept(self, line: bytes) -> None:
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            return
        if text.startswith("WATCH_LEARN_STAGE="):
            stage = text.removeprefix("WATCH_LEARN_STAGE=")
            if (
                stage in _LAUNCH_STAGES
                and _LAUNCH_STAGE_RANK[stage] >= _LAUNCH_STAGE_RANK.get(self.stage or "", -1)
            ):
                self.stage = stage
        elif text.startswith("WATCH_LEARN_FAILURE="):
            fields = text.removeprefix("WATCH_LEARN_FAILURE=").split(":", 1)
            if len(fields) == 2 and fields[0] in _LAUNCH_STAGES and fields[1] in _LAUNCH_FAILURE_REASONS:
                self.failure_stage, self.failure_reason = fields

    def snapshot(self) -> tuple[str | None, str | None, str | None]:
        with self._lock:
            return self.stage, self.failure_stage, self.failure_reason


@dataclass(frozen=True)
class AdapterConnection:
    initial_evidence_png: bytes


@dataclass(frozen=True)
class AdapterResult:
    outcome: ReceiptOutcome
    detail: str
    evidence_png: bytes | None = None


class CaptureAdapter(Protocol):
    target_type: TargetType

    def available(self) -> tuple[bool, str]: ...
    def connect(
        self, session_id: str, project: ProjectDocument, privacy_revision: str
    ) -> AdapterConnection: ...
    def dispatch(self, session_id: str, action: CaptureAction) -> AdapterResult: ...
    def prove_session(self, session_id: str, ready_window: str) -> AdapterResult: ...
    def frame(self, session_id: str) -> bytes: ...
    def release_controls(self, session_id: str) -> None: ...
    def disconnect(self, session_id: str) -> None: ...


@dataclass
class _WorkerClient:
    process: subprocess.Popen
    control_dir: str
    token: str
    request_fd: int
    response_fd: int
    diagnostic_thread: threading.Thread
    observation: _LaunchObservation


class RunnerControlledCaptureAdapter:
    """Approved-target adapter backed by the existing hardened runner abstraction."""

    target_type: TargetType = "local-app"

    def __init__(
        self,
        settings: DashboardSettings,
        *,
        repo_root: str | None = None,
        popen_factory: Callable[..., subprocess.Popen] | None = None,
        run_factory: Callable[..., subprocess.CompletedProcess] | None = None,
        monotonic: Callable[[], float] | None = None,
        target_type: TargetType = "local-app",
    ):
        if target_type not in {"local-app", "vnc"}:
            raise ValueError("runner-controlled capture supports local-app and VNC")
        self.target_type = target_type
        self.settings = settings
        self.repo_root = os.path.abspath(repo_root or str(Path(__file__).resolve().parents[2]))
        self._popen = popen_factory or subprocess.Popen
        self._run = run_factory or subprocess.run
        self._monotonic = monotonic or time.monotonic
        self._clients: dict[str, _WorkerClient] = {}
        self._lock = threading.RLock()
        self._io_lock = threading.RLock()

    @property
    def runner_path(self) -> str:
        return os.path.join(self.repo_root, "scripts", "run_container.sh")

    @property
    def worker_path(self) -> str:
        return os.path.join(self.repo_root, "src", "orchestrator", "watch_learn_worker.py")

    @property
    def engine(self) -> str | None:
        configured = os.environ.get("ENGINE")
        if configured:
            if os.path.isabs(configured):
                return configured if os.access(configured, os.X_OK) else None
            return shutil.which(configured)
        return shutil.which("docker") or shutil.which("podman")

    @property
    def control_root(self) -> str:
        # Keep capability-only runtime endpoints short and ephemeral; all
        # durable evidence remains in the configured clone-local private root.
        return os.path.join(
            tempfile.gettempdir(), f"orchestrator-cookie-watch-learn-{os.getuid()}"
        )

    def available(self) -> tuple[bool, str]:
        if not os.path.isfile(self.worker_path) or not os.access(self.runner_path, os.X_OK):
            return False, "The runner-controlled Watch & Learn worker is not installed."
        if not self.engine:
            return False, "No approved container engine is available for the hardened capture worker."
        image = self.settings.watch_learn_runner_image
        if not image or not _IMAGE_RE.fullmatch(image):
            return False, "A reviewed digest-pinned Watch & Learn runner image is not configured."
        target_label = "Local application" if self.target_type == "local-app" else "VNC-over-SSH"
        return True, (
            f"{target_label} capture uses a private capability-authenticated FIFO pair, "
            "the hardened runner, and the repository's allowlisted Targets and Computer abstractions."
        )

    def _verify_runtime(self) -> tuple[str, str]:
        available, detail = self.available()
        if not available:
            raise RuntimeError(detail)
        engine = self.engine
        image = self.settings.watch_learn_runner_image
        assert engine is not None and image is not None
        if os.path.basename(engine) not in {"docker", "podman"}:
            raise RuntimeError("unsupported container engine for explicit no-pull semantics")
        try:
            version = self._run(
                [engine, "version", "--format", "{{.Server.Version}}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=self.settings.watch_learn_action_timeout_seconds,
                check=True, text=True,
            )
            if not version.stdout.strip() or len(version.stdout) > 256:
                raise RuntimeError("container engine readiness response is invalid")
            inspected = self._run(
                [engine, "image", "inspect", "--format", "{{json .RepoDigests}}", image],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=self.settings.watch_learn_action_timeout_seconds,
                check=True, text=True,
            )
            digests = json.loads(inspected.stdout)
            if not isinstance(digests, list) or image not in digests:
                raise RuntimeError("runner image provenance does not match the configured digest")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise RuntimeError("container engine or runner-image provenance check failed") from exc
        return engine, image

    @staticmethod
    def _cleanup_process(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    @staticmethod
    def _join_diagnostic_thread(thread: threading.Thread) -> bool:
        thread.join(timeout=2)
        return not thread.is_alive()

    def _diagnostic_log_path(self, session_id: str) -> str:
        root = os.path.join(
            os.path.dirname(os.path.abspath(self.settings.watch_learn_state_root)),
            "watch-learn-launch-diagnostics",
        )
        os.makedirs(root, mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        info = os.lstat(root)
        if (
            os.path.islink(root)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_gid != os.getgid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RuntimeError("unsafe Watch & Learn diagnostic directory")
        return os.path.join(root, f"{session_id}.log")

    @staticmethod
    def _drain_diagnostic_output(
        stream: object,
        descriptor: int,
        observation: _LaunchObservation,
    ) -> None:
        written = 0
        try:
            reader = getattr(stream, "read1", stream.read)
            while True:
                chunk = reader(4_096)
                if not chunk:
                    break
                observation.feed(chunk)
                if written < _DIAGNOSTIC_LOG_LIMIT:
                    bounded = chunk[: _DIAGNOSTIC_LOG_LIMIT - written]
                    offset = 0
                    while offset < len(bounded):
                        offset += os.write(descriptor, bounded[offset:])
                    written += len(bounded)
        finally:
            try:
                stream.close()
            finally:
                os.close(descriptor)

    def _start_diagnostic_drain(
        self,
        process: subprocess.Popen,
        descriptor: int,
        observation: _LaunchObservation,
    ) -> threading.Thread:
        if process.stdout is None:
            os.close(descriptor)
            raise RuntimeError("capture runner diagnostic stream is unavailable")
        thread = threading.Thread(
            target=self._drain_diagnostic_output,
            args=(process.stdout, descriptor, observation),
            name="watch-learn-launch-diagnostic",
            daemon=True,
        )
        thread.start()
        return thread

    @staticmethod
    def _fifo_ready(path: str) -> bool:
        try:
            return stat.S_ISFIFO(os.lstat(path).st_mode)
        except OSError:
            return False

    def _typed_launch_error(
        self,
        *,
        default_stage: str,
        default_reason: str,
        session_id: str,
        control_dir: str | None,
        process: subprocess.Popen | None,
        observation: _LaunchObservation | None,
        cleanup_outcome: str,
        observed_exit_status: int | None = None,
    ) -> CaptureLaunchError:
        stage, failure_stage, failure_reason = (
            observation.snapshot() if observation is not None else (None, None, None)
        )
        effective_stage = failure_stage or stage or default_stage
        effective_reason = failure_reason or default_reason
        if effective_stage not in _LAUNCH_STAGES:
            effective_stage = default_stage
        if effective_reason not in _LAUNCH_FAILURE_REASONS:
            effective_reason = default_reason
        reached = _LAUNCH_STAGE_RANK.get(stage or default_stage, -1)
        request_path = os.path.join(control_dir, "requests.fifo") if control_dir else ""
        response_path = os.path.join(control_dir, "responses.fifo") if control_dir else ""
        return CaptureLaunchError(
            stage=effective_stage,
            reason_code=effective_reason,
            exit_status=(
                observed_exit_status
                if observed_exit_status is not None
                else process.poll() if process is not None else None
            ),
            container_name=f"phase17-{session_id}",
            request_fifo_ready=bool(request_path and self._fifo_ready(request_path)),
            response_fifo_ready=bool(response_path and self._fifo_ready(response_path)),
            app_launch_reached=reached >= _LAUNCH_STAGE_RANK["app_launch_started"],
            launch_window_verified=reached >= _LAUNCH_STAGE_RANK["launch_window_verified"],
            initial_frame_captured=reached >= _LAUNCH_STAGE_RANK["initial_frame_captured_redacted"],
            cleanup_outcome=cleanup_outcome,
        )

    def _prepare_control_dir(self, session_id: str) -> str:
        if not _SESSION_RE.fullmatch(session_id):
            raise RuntimeError("invalid capture session identifier")
        root = self.control_root
        os.makedirs(root, mode=0o700, exist_ok=True)
        root_info = os.lstat(root)
        os.chmod(root, 0o700)
        root_info = os.lstat(root)
        if (
            os.path.islink(root) or not os.path.isdir(root)
            or root_info.st_uid != os.getuid()
            or root_info.st_gid != os.getgid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise RuntimeError("unsafe Watch & Learn transport root")
        control_dir = os.path.join(root, session_id)
        os.mkdir(control_dir, 0o700)
        control_info = os.lstat(control_dir)
        if (
            not stat.S_ISDIR(control_info.st_mode)
            or stat.S_IMODE(control_info.st_mode) != 0o700
            or control_info.st_uid != os.getuid()
            or control_info.st_gid != os.getgid()
        ):
            self._cleanup_control_dir(control_dir)
            raise RuntimeError("unsafe Watch & Learn control directory")
        return control_dir

    def _cleanup_control_dir(self, control_dir: str) -> None:
        root = self.control_root
        if os.path.dirname(control_dir) != root or not _SESSION_RE.fullmatch(os.path.basename(control_dir)):
            return
        if not os.path.lexists(control_dir) or os.path.islink(control_dir):
            return
        for name in os.listdir(control_dir):
            path = os.path.join(control_dir, name)
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode):
                os.unlink(path)
        try:
            os.rmdir(control_dir)
        except OSError:
            pass
        try:
            os.rmdir(root)
        except OSError:
            pass

    @staticmethod
    def _read_exact(descriptor: int, length: int, timeout: float) -> bytes:
        value = bytearray()
        deadline = time.monotonic() + timeout
        while len(value) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise RuntimeError("capture worker response timed out")
            try:
                chunk = os.read(descriptor, length - len(value))
            except BlockingIOError:
                continue
            if not chunk:
                raise RuntimeError("capture worker response ended early")
            value.extend(chunk)
        return bytes(value)

    @staticmethod
    def _write_all(descriptor: int, value: bytes, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(value):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                raise RuntimeError("capture worker request timed out")
            try:
                offset += os.write(descriptor, value[offset:])
            except BlockingIOError:
                continue

    def _request(
        self, client: _WorkerClient, method: str, *, body: dict | None = None,
        maximum: int, timeout: float | None = None,
    ) -> tuple[bytes, str]:
        payload = json.dumps(
            {"token": client.token, "method": method, "body": body or {}},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > 4_096:
            raise RuntimeError("bounded worker request exceeded")
        request_timeout = timeout or self.settings.watch_learn_action_timeout_seconds
        try:
            with self._io_lock:
                self._write_all(client.request_fd, struct.pack("!I", len(payload)) + payload, request_timeout)
                size = struct.unpack("!I", self._read_exact(client.response_fd, 4, request_timeout))[0]
                if size < 2 or size > maximum:
                    raise RuntimeError("capture worker response exceeded its bound")
                raw = self._read_exact(client.response_fd, size, request_timeout)
        except (OSError, struct.error) as exc:
            raise RuntimeError("runner-controlled worker request failed") from exc
        try:
            response = json.loads(raw)
            if set(response) != {"status", "media_type", "body_base64"}:
                raise ValueError("response shape")
            if response["status"] != 200 or not isinstance(response["media_type"], str):
                raise ValueError("response status")
            value = base64.b64decode(response["body_base64"], validate=True)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError("capture worker returned an invalid typed response") from exc
        return value, response["media_type"]

    def _wait_initial_frame(self, client: _WorkerClient) -> bytes:
        # Send exactly one readiness request. Retrying a timed-out framed request
        # could leave a late response queued and desynchronize later actions.
        if client.process.poll() is not None:
            raise RuntimeError("capture worker exited before readiness")
        return self._frame(
            client, timeout=self.settings.watch_learn_connect_timeout_seconds
        )

    def _open_private_channel(self, process: subprocess.Popen, control_dir: str) -> tuple[int, int]:
        request_path = os.path.join(control_dir, "requests.fifo")
        response_path = os.path.join(control_dir, "responses.fifo")
        deadline = self._monotonic() + self.settings.watch_learn_connect_timeout_seconds
        while self._monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("capture worker exited before private transport readiness")
            try:
                request_info, response_info = os.lstat(request_path), os.lstat(response_path)
                if (
                    not stat.S_ISFIFO(request_info.st_mode) or not stat.S_ISFIFO(response_info.st_mode)
                    or request_info.st_uid != os.getuid() or response_info.st_uid != os.getuid()
                    or request_info.st_gid != os.getgid() or response_info.st_gid != os.getgid()
                    or stat.S_IMODE(request_info.st_mode) != 0o600
                    or stat.S_IMODE(response_info.st_mode) != 0o600
                ):
                    raise RuntimeError("private transport endpoint failed ownership validation")
                return (
                    os.open(request_path, os.O_WRONLY | os.O_NONBLOCK),
                    os.open(response_path, os.O_RDONLY | os.O_NONBLOCK),
                )
            except FileNotFoundError:
                time.sleep(0.05)
        raise RuntimeError("private transport readiness timed out")

    def _launch(
        self,
        session_id: str,
        project: ProjectDocument,
        *,
        privacy_revision: str,
        self_test: bool,
    ) -> AdapterConnection:
        if project.target.type != self.target_type:
            raise RuntimeError("runner-controlled adapter target type does not match the project")
        try:
            _engine, image = self._verify_runtime()  # must precede worker Popen
        except Exception as exc:
            raise self._typed_launch_error(
                default_stage="pinned_image_verification",
                default_reason="runtime_verification_failed",
                session_id=session_id,
                control_dir=None,
                process=None,
                observation=None,
                cleanup_outcome="not-started",
            ) from exc
        try:
            control_dir = self._prepare_control_dir(session_id)
        except Exception as exc:
            raise self._typed_launch_error(
                default_stage="control_directory",
                default_reason="control_directory_failed",
                session_id=session_id,
                control_dir=None,
                process=None,
                observation=None,
                cleanup_outcome="not-started",
            ) from exc
        token = secrets.token_urlsafe(48)
        container_name = f"phase17-{session_id}"
        command = [
            self.runner_path, "python", "-m", "orchestrator.watch_learn_worker",
            "--project", project.dir_name,
            "--privacy-revision", privacy_revision,
            *(["--self-test"] if self_test else []),
        ]
        environment = {
            **os.environ, "IMAGE": image,
            "ORCHESTRATOR_RUN_PROJECT": project.dir_name,
            "ORCHESTRATOR_CONTAINER_NAME": container_name,
            "WATCH_LEARN_CONTROL_DIR_HOST": control_dir,
            "WATCH_LEARN_SELF_TEST": "1" if self_test else "0",
            "WATCH_LEARN_NETWORK_MODE": "target" if self.target_type == "vnc" else "none",
            # The managed dashboard stores imported projects and saved login
            # references below its private runtime root.  The host runner uses
            # these unprefixed variables for its read-only container mounts;
            # inheriting only DASHBOARD_* would silently select repository
            # defaults that do not contain managed imports or references.
            "SPECS_DIR": os.path.abspath(self.settings.specs_dir),
            "SECRETS_DIR": os.path.abspath(self.settings.secrets_dir),
        }
        with self._lock:
            if session_id in self._clients:
                self._cleanup_control_dir(control_dir)
                raise RuntimeError("capture worker already exists")
            diagnostic_descriptor = -1
            diagnostic_thread: threading.Thread | None = None
            observation = _LaunchObservation()
            process: subprocess.Popen | None = None
            try:
                diagnostic_path = self._diagnostic_log_path(session_id)
                diagnostic_descriptor = os.open(
                    diagnostic_path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.fchmod(diagnostic_descriptor, 0o600)
                process = self._popen(
                    command, cwd=self.repo_root, env=environment,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, start_new_session=True,
                )
                diagnostic_thread = self._start_diagnostic_drain(
                    process, diagnostic_descriptor, observation
                )
                observation.feed(b"WATCH_LEARN_STAGE=runner_start\n")
                diagnostic_descriptor = -1
            except BaseException as exc:
                if diagnostic_descriptor >= 0:
                    os.close(diagnostic_descriptor)
                if process is not None:
                    self._cleanup_process(process)
                self._cleanup_control_dir(control_dir)
                if not isinstance(exc, Exception):
                    raise
                raise self._typed_launch_error(
                    default_stage="runner_start",
                    default_reason="runner_start_failed",
                    session_id=session_id,
                    control_dir=control_dir,
                    process=process,
                    observation=observation,
                    cleanup_outcome="completed",
                ) from exc
            assert process is not None and diagnostic_thread is not None
            request_fd = response_fd = -1
            try:
                if process.stdin is None:
                    raise RuntimeError("capture worker has no private capability pipe")
                process.stdin.write((token + "\n").encode("ascii"))
                process.stdin.flush()
                process.stdin.close()
                observation.feed(b"WATCH_LEARN_STAGE=capability_handoff\n")
                observation.feed(b"WATCH_LEARN_STAGE=fifo_wait\n")
                request_fd, response_fd = self._open_private_channel(process, control_dir)
                client = _WorkerClient(
                    process=process, control_dir=control_dir, token=token,
                    request_fd=request_fd, response_fd=response_fd,
                    diagnostic_thread=diagnostic_thread,
                    observation=observation,
                )
                frame = self._wait_initial_frame(client)
                observation.feed(b"WATCH_LEARN_STAGE=initial_frame_returned\n")
                self._clients[session_id] = client
                return AdapterConnection(initial_evidence_png=frame)
            except BaseException as exc:
                failure_exit_status = process.poll()
                for descriptor in (request_fd, response_fd):
                    if descriptor >= 0:
                        os.close(descriptor)
                self._cleanup_process(process)
                thread_stopped = self._join_diagnostic_thread(diagnostic_thread)
                if failure_exit_status is not None:
                    reason = "runner_exited"
                elif request_fd < 0 and "ownership validation" in str(exc):
                    reason = "fifo_invalid"
                elif request_fd >= 0 and "timed out" in str(exc):
                    reason = "initial_frame_timeout"
                elif request_fd >= 0:
                    reason = "initial_frame_invalid"
                else:
                    reason = "fifo_timeout"
                error = self._typed_launch_error(
                    default_stage="initial_capture_started" if request_fd >= 0 else "fifo_wait",
                    default_reason=reason,
                    session_id=session_id,
                    control_dir=control_dir,
                    process=process if failure_exit_status is not None else None,
                    observation=observation,
                    cleanup_outcome="completed" if thread_stopped else "partial",
                    observed_exit_status=failure_exit_status,
                )
                self._cleanup_control_dir(control_dir)
                if not isinstance(exc, Exception):
                    raise
                raise error from exc

    def connect(
        self, session_id: str, project: ProjectDocument, privacy_revision: str
    ) -> AdapterConnection:
        return self._launch(
            session_id,
            project,
            privacy_revision=privacy_revision,
            self_test=False,
        )

    def transport_self_test(self, session_id: str, project: ProjectDocument) -> AdapterResult:
        """Exercise the production runner/channel without opening a target."""
        self._launch(
            session_id,
            project,
            privacy_revision=redaction_configuration_revision(
                WATCH_LEARN_SELF_TEST_REDACTION
            ),
            self_test=True,
        )
        try:
            return self.dispatch(session_id, _SelfTestKey())
        finally:
            self.disconnect(session_id)

    def _client(self, session_id: str) -> _WorkerClient:
        with self._lock:
            client = self._clients.get(session_id)
        if client is None or client.process.poll() is not None:
            raise RuntimeError("capture worker is unavailable")
        return client

    def _frame(self, client: _WorkerClient, *, timeout: float | None = None) -> bytes:
        value, media_type = self._request(
            client, "frame", maximum=self.settings.watch_learn_max_evidence_bytes * 2,
            timeout=timeout,
        )
        if media_type != "image/png" or len(value) > self.settings.watch_learn_max_evidence_bytes:
            raise RuntimeError("capture worker returned an invalid bounded frame")
        return value

    def frame(self, session_id: str) -> bytes:
        return self._frame(self._client(session_id))

    def dispatch(self, session_id: str, action: CaptureAction) -> AdapterResult:
        if action.kind == "text_intent":
            raise RuntimeError("semantic text intent must never reach the adapter")
        value, media_type = self._request(
            self._client(session_id), "action", body=action.model_dump(mode="json"),
            maximum=self.settings.watch_learn_max_evidence_bytes * 2,
        )
        if media_type != "application/json":
            raise RuntimeError("capture worker returned an invalid action response")
        try:
            payload = json.loads(value)
            if set(payload) != {"outcome", "detail", "evidence_png_base64"}:
                raise ValueError("response shape")
            outcome, detail, encoded = payload["outcome"], payload["detail"], payload["evidence_png_base64"]
            if outcome not in {"accepted", "executed", "rejected", "failed"}:
                raise ValueError("outcome")
            if not isinstance(detail, str) or not 1 <= len(detail) <= 300 or not isinstance(encoded, str):
                raise ValueError("fields")
            evidence = base64.b64decode(encoded, validate=True) if encoded else None
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError("capture worker returned an invalid typed response") from exc
        if evidence is not None and len(evidence) > self.settings.watch_learn_max_evidence_bytes:
            raise RuntimeError("capture worker evidence exceeded its bound")
        return AdapterResult(outcome=outcome, detail=detail, evidence_png=evidence)

    def prove_session(self, session_id: str, ready_window: str) -> AdapterResult:
        if (
            not ready_window
            or len(ready_window) > 240
            or any(ord(char) < 32 or ord(char) == 127 for char in ready_window)
        ):
            raise RuntimeError("configured session proof window is invalid")
        value, media_type = self._request(
            self._client(session_id),
            "session-proof",
            body={"ready_window": ready_window},
            maximum=self.settings.watch_learn_max_evidence_bytes * 2,
        )
        if media_type != "application/json":
            raise RuntimeError("capture worker returned an invalid session proof")
        try:
            payload = json.loads(value)
            if set(payload) != {"outcome", "detail", "evidence_png_base64"}:
                raise ValueError("response shape")
            outcome = payload["outcome"]
            detail = payload["detail"]
            encoded = payload["evidence_png_base64"]
            if outcome not in {"executed", "failed"}:
                raise ValueError("outcome")
            if not isinstance(detail, str) or not 1 <= len(detail) <= 300 or not isinstance(encoded, str):
                raise ValueError("fields")
            evidence = base64.b64decode(encoded, validate=True) if encoded else None
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError("capture worker returned an invalid typed session proof") from exc
        if evidence is not None and len(evidence) > self.settings.watch_learn_max_evidence_bytes:
            raise RuntimeError("session proof evidence exceeded its bound")
        return AdapterResult(outcome=outcome, detail=detail, evidence_png=evidence)

    def release_controls(self, session_id: str) -> None:
        value, media_type = self._request(
            self._client(session_id), "release", maximum=2_048
        )
        if media_type != "application/json":
            raise RuntimeError("capture worker returned an invalid release response")
        try:
            payload = json.loads(value)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("capture worker returned an invalid release response") from exc
        if payload != {"released": True}:
            raise RuntimeError("capture worker did not confirm release")

    def disconnect(self, session_id: str) -> None:
        with self._lock:
            client = self._clients.pop(session_id, None)
        if client is None:
            return
        try:
            self._request(client, "close", maximum=2_048)
        except Exception:
            pass
        os.close(client.request_fd)
        os.close(client.response_fd)
        self._cleanup_process(client.process)
        self._join_diagnostic_thread(client.diagnostic_thread)
        self._cleanup_control_dir(client.control_dir)


class _SelfTestKey:
    kind = "key"
    key = "TAB"

    @staticmethod
    def model_dump(*, mode: str = "json") -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "key",
            "key": "TAB",
            "phase": "press",
            "modifiers": [],
            "repeat": 1,
        }


class CaptureAdapterRegistry:
    """Explicit allowlist with one initial production adapter."""

    def __init__(
        self,
        adapters: list[CaptureAdapter] | None = None,
        *,
        capabilities: dict[TargetType, TargetCapability] | None = None,
    ):
        self._adapters = {adapter.target_type: adapter for adapter in (adapters or [])}
        self._capabilities = {
            target_type: capability.model_copy(deep=True)
            for target_type, capability in (capabilities or {}).items()
        }
        for target_type in self._adapters:
            self._capabilities.setdefault(
                target_type,
                TargetCapability(
                    target_type=target_type,
                    available=True,
                    reason_code="runner_controlled_adapter_registered",
                    detail=(
                        "A runner-controlled adapter is registered. Runtime and exact "
                        "image provenance are verified only by explicit Connect."
                    ),
                ),
            )

    @classmethod
    def production(cls, settings: DashboardSettings) -> "CaptureAdapterRegistry":
        adapters = [
            RunnerControlledCaptureAdapter(settings, target_type="local-app"),
            RunnerControlledCaptureAdapter(settings, target_type="vnc"),
        ]
        availability = {item.target_type: item.available() for item in adapters}
        return cls(
            adapters,
            capabilities={
                target_type: TargetCapability(
                    target_type=target_type,
                    available=availability[target_type][0],
                    reason_code=(
                        "runner_controlled_adapter_available"
                        if availability[target_type][0]
                        else "runner_controlled_adapter_unavailable"
                    ),
                    detail=availability[target_type][1],
                )
                for target_type in ("local-app", "vnc")
            },
        )

    def capability(self, target_type: TargetType) -> TargetCapability:
        capability = self._capabilities.get(target_type)
        if capability is None:
            return TargetCapability(target_type=target_type, available=False,
                reason_code="controlled_adapter_unavailable", detail=_UNAVAILABLE_DETAIL)
        return capability.model_copy(deep=True)

    def require(self, target_type: TargetType) -> CaptureAdapter:
        adapter = self._adapters.get(target_type)
        if adapter is None:
            raise RuntimeError(_UNAVAILABLE_DETAIL)
        available, detail = adapter.available()
        if not available:
            raise RuntimeError(detail)
        return adapter
