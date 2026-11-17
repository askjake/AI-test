"""Runner-contained, target-bounded Watch & Learn worker.

The hardened entrypoint supplies inherited descriptors for two private FIFOs. The capability
is read once from stdin and retained only in memory. There is no TCP listener,
text-input operation, model client, or ambient target-selection API.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import io
import json
import os
import re
import stat
import struct
import threading
from typing import Any

from .computer import Computer
from .projects import load_project_config
from .redaction import (
    WATCH_LEARN_SELF_TEST_REDACTION,
    configured_redactor,
)
from .targets import TargetSpec, Targets, WindowNotFoundError


_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_REVISION_RE = re.compile(r"^[a-f0-9]{64}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
SELF_TEST_SECRET_MARKER = "PHASE17-RAW-SECRET-MARKER"
_KEYS = {
    "ENTER": "Return", "TAB": "Tab", "ESC": "Escape", "UP": "Up",
    "DOWN": "Down", "LEFT": "Left", "RIGHT": "Right", "HOME": "Home",
    "END": "End", "PAGEUP": "Prior", "PAGEDOWN": "Next",
    "BACKSPACE": "BackSpace", "DELETE": "Delete",
    "A": "a",
}
_MODIFIERS = {"CTRL": "ctrl", "SHIFT": "shift"}
_BUTTONS = {"left", "middle", "right"}


def _launch_stage(stage: str) -> None:
    """Emit one fixed marker consumed only by the bounded private launch log."""
    allowed = {
        "worker_started", "project_loaded", "app_launch_started",
        "launch_window_verified", "initial_capture_started",
        "initial_frame_captured_redacted",
    }
    if stage not in allowed:
        raise ValueError("unallowlisted worker launch stage")
    print(f"WATCH_LEARN_STAGE={stage}", flush=True)


def _launch_failure(stage: str, reason_code: str) -> None:
    allowed_stages = {"worker_started", "app_launch_started", "initial_capture_started"}
    allowed_reasons = {
        "project_config_invalid", "target_launch_failed", "window_match_failed",
        "capture_failed", "unexpected_failure",
    }
    if stage in allowed_stages and reason_code in allowed_reasons:
        print(f"WATCH_LEARN_FAILURE={stage}:{reason_code}", flush=True)


def _action_fields(payload: dict[str, Any], expected: set[str]) -> None:
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported action schema")
    if set(payload) != expected | {"schema_version"}:
        raise ValueError("invalid action shape")


def _bounded_int(value: object, low: int, high: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"invalid {label}")
    return value


def _frame_point(payload: dict[str, Any], x_name: str = "x", y_name: str = "y") -> tuple[int, int]:
    revision = payload.get("frame_revision")
    if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
        raise ValueError("invalid frame revision")
    width = _bounded_int(payload.get("frame_width"), 1, 8_192, "frame width")
    height = _bounded_int(payload.get("frame_height"), 1, 8_192, "frame height")
    x = _bounded_int(payload.get(x_name), 0, 16_383, x_name)
    y = _bounded_int(payload.get(y_name), 0, 16_383, y_name)
    if x >= width or y >= height:
        raise ValueError("pointer outside frame")
    return x, y


class WorkerState:
    def __init__(
        self,
        computer: Any,
        targets: Targets | None,
        handle: Any,
        token: str,
        secrets_dir: str = "/app/secrets",
    ):
        self.computer = computer
        self.targets = targets
        self.handle = handle
        self.token = token
        self.lock = threading.RLock()
        self.requests = 0
        self.maximum_requests = 1_100
        self.closed = False
        self.secrets_dir = os.path.abspath(secrets_dir)
        self._release_timer: threading.Timer | None = None
        self._initial_frame_complete = False

    def _cancel_release_timer(self) -> None:
        timer, self._release_timer = self._release_timer, None
        if timer is not None:
            timer.cancel()

    def _schedule_release(self) -> None:
        self._cancel_release_timer()
        timer = threading.Timer(2.0, self.release_controls)
        timer.daemon = True
        self._release_timer = timer
        timer.start()

    def release_controls(self) -> None:
        with self.lock:
            self._cancel_release_timer()
            self.computer.release_controls()

    def frame(self) -> bytes:
        with self.lock:
            initial = not self._initial_frame_complete
            if initial:
                _launch_stage("initial_capture_started")
            try:
                value = self.computer.screenshot().png
            except Exception:
                if initial:
                    _launch_failure("initial_capture_started", "capture_failed")
                raise
            if initial:
                self._initial_frame_complete = True
                _launch_stage("initial_frame_captured_redacted")
            return value

    def _read_secret(self, reference: object) -> str:
        if not isinstance(reference, str) or not _REFERENCE_RE.fullmatch(reference):
            raise ValueError("invalid secret reference")
        path = os.path.abspath(os.path.join(self.secrets_dir, reference))
        if os.path.commonpath((self.secrets_dir, path)) != self.secrets_dir:
            raise ValueError("invalid secret reference")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or not 1 <= info.st_size <= 1_025
            ):
                raise ValueError("secret reference failed private-file validation")
            raw = os.read(descriptor, 1_026)
        finally:
            os.close(descriptor)
        if len(raw) > 1_025:
            raise ValueError("secret reference exceeded its bound")
        try:
            value = raw.decode("utf-8").removesuffix("\n")
        except UnicodeError as exc:
            raise ValueError("secret reference is not UTF-8 text") from exc
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("secret reference contains prohibited control data")
        return value

    def action(self, payload: dict[str, Any]) -> tuple[str, str, bytes | None]:
        with self.lock:
            self.requests += 1
            if self.requests > self.maximum_requests:
                raise ValueError("bounded worker request quota exceeded")
            kind = payload.get("kind")
            if kind == "secret_text":
                _action_fields(payload, {"kind", "purpose", "secret_reference"})
                if payload.get("purpose") != "establish-approved-session":
                    raise ValueError("invalid secret-entry purpose")
                secret = self._read_secret(payload.get("secret_reference"))
                try:
                    self.computer.type_secret(secret)
                finally:
                    secret = ""
                return (
                    "executed",
                    "Approved secret reference was entered while capture remained paused.",
                    None,
                )
            if kind == "click":
                _action_fields(payload, {
                    "kind", "x", "y", "button", "clicks",
                    "frame_revision", "frame_width", "frame_height",
                })
                x, y = _frame_point(payload)
                button = payload.get("button")
                clicks = payload.get("clicks")
                if button not in _BUTTONS or clicks not in {1, 2}:
                    raise ValueError("invalid pointer button")
                self.computer.click(x, y, button, clicks)
            elif kind == "pointer_button":
                _action_fields(payload, {
                    "kind", "phase", "x", "y", "button",
                    "frame_revision", "frame_width", "frame_height",
                })
                x, y = _frame_point(payload)
                phase, button = payload.get("phase"), payload.get("button")
                if phase not in {"down", "up"} or button not in _BUTTONS:
                    raise ValueError("invalid pointer lifecycle")
                self.computer.pointer_button(phase, button, x, y)
                if phase == "down":
                    self._schedule_release()
                else:
                    self._cancel_release_timer()
                return "executed", "Runner-controlled pointer lifecycle updated.", None
            elif kind == "pointer_move":
                _action_fields(payload, {
                    "kind", "x", "y", "during_drag",
                    "frame_revision", "frame_width", "frame_height",
                })
                x, y = _frame_point(payload)
                if not isinstance(payload.get("during_drag"), bool):
                    raise ValueError("invalid drag movement state")
                self.computer.mouse_move(x, y)
                return "executed", "Runner-controlled pointer position updated.", None
            elif kind == "drag":
                _action_fields(payload, {
                    "kind", "button", "start_x", "start_y", "end_x", "end_y", "path",
                    "frame_revision", "frame_width", "frame_height",
                })
                start = _frame_point(payload, "start_x", "start_y")
                end = _frame_point(payload, "end_x", "end_y")
                button, path_value = payload.get("button"), payload.get("path")
                if button not in {"left", "middle"} or not isinstance(path_value, list) or len(path_value) > 32:
                    raise ValueError("invalid drag")
                path: list[tuple[int, int]] = []
                for point in path_value:
                    if not isinstance(point, dict) or set(point) != {"x", "y"}:
                        raise ValueError("invalid drag path")
                    merged = {**payload, **point}
                    path.append(_frame_point(merged))
                if start == end and not path:
                    raise ValueError("empty drag")
                self.computer.drag(start, end, button=button, path=path)
            elif kind == "wheel":
                _action_fields(payload, {
                    "kind", "x", "y", "delta_x", "delta_y",
                    "frame_revision", "frame_width", "frame_height",
                })
                x, y = _frame_point(payload)
                delta_x = _bounded_int(payload.get("delta_x"), -20, 20, "wheel x")
                delta_y = _bounded_int(payload.get("delta_y"), -20, 20, "wheel y")
                if delta_x == delta_y == 0:
                    raise ValueError("empty wheel")
                self.computer.wheel(x, y, delta_x, delta_y)
            elif kind == "key":
                _action_fields(payload, {"kind", "key", "phase", "modifiers", "repeat"})
                key = payload.get("key")
                if key not in _KEYS:
                    raise ValueError("invalid key")
                phase, modifiers, repeat = payload.get("phase"), payload.get("modifiers"), payload.get("repeat")
                if phase not in {"press", "down", "up"} or not isinstance(modifiers, list):
                    raise ValueError("invalid key lifecycle")
                if len(modifiers) > 1 or len(set(modifiers)) != len(modifiers) or any(item not in _MODIFIERS for item in modifiers):
                    raise ValueError("invalid modifiers")
                chord = (tuple(modifiers), key)
                if modifiers and chord not in {(('SHIFT',), 'TAB'), (('CTRL',), 'A')}:
                    raise ValueError("invalid key chord")
                if key == "A" and chord != (("CTRL",), "A"):
                    raise ValueError("invalid key chord")
                repeat = _bounded_int(repeat, 1, 3, "key repeat")
                if phase != "press" and (modifiers or repeat != 1):
                    raise ValueError("invalid key lifecycle")
                self.computer.key_control(
                    _KEYS[key], phase=phase,
                    modifiers=[_MODIFIERS[item] for item in modifiers], repeat=repeat,
                )
                if phase == "down":
                    self._schedule_release()
                elif phase == "up":
                    self._cancel_release_timer()
            elif kind == "scroll":
                _action_fields(payload, {"kind", "direction", "amount"})
                direction, amount = payload.get("direction"), payload.get("amount")
                if direction not in {"up", "down"}:
                    raise ValueError("invalid scroll direction")
                if not isinstance(amount, int) or isinstance(amount, bool) or not 1 <= amount <= 20:
                    raise ValueError("invalid scroll amount")
                self.computer.scroll(direction, amount)
            else:
                raise ValueError("unsupported controlled action")
            return "executed", "Runner-controlled action completed.", self.frame()

    def prove_session(self, ready_window: object) -> tuple[str, str, bytes | None]:
        with self.lock:
            if (
                self.targets is None
                or not isinstance(ready_window, str)
                or not 1 <= len(ready_window) <= 240
                or any(ord(char) < 32 or ord(char) == 127 for char in ready_window)
            ):
                return "failed", "Configured session proof is unavailable.", None
            exact_pattern = "^" + re.escape(ready_window) + "$"
            if self.targets.focus(exact_pattern) is None:
                return "failed", "The configured post-login ready window was not found.", None
            return "executed", "The configured post-login ready window was verified.", self.frame()

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            try:
                self.release_controls()
            except Exception:
                pass
            if self.targets is not None:
                self.targets.close_target(self.handle)


class _SelfTestComputer:
    """Real Computer redaction path over a synthetic raw frame; no target opens."""

    def __init__(self, expected_privacy_revision: str):
        redactor, _revision = configured_redactor(
            WATCH_LEARN_SELF_TEST_REDACTION,
            expected_revision=expected_privacy_revision,
        )
        self._computer = Computer(
            model_w=64,
            model_h=32,
            native_w=64,
            native_h=32,
            runner=lambda _command: "",
            capture=synthetic_self_test_raw_png,
            redactor=redactor,
        )

    def screenshot(self):
        return self._computer.screenshot()

    def left_click(self, _x, _y): pass
    def right_click(self, _x, _y): pass
    def click(self, _x, _y, _button, _clicks): pass
    def pointer_button(self, _phase, _button, _x, _y): pass
    def mouse_move(self, _x, _y): pass
    def drag(self, _start, _end, *, button, path): pass
    def wheel(self, _x, _y, _dx, _dy): pass
    def key(self, _key): pass
    def key_control(self, _key, *, phase, modifiers, repeat): pass
    def scroll(self, _direction, _amount): pass
    def release_controls(self): pass


def synthetic_self_test_raw_png() -> bytes:
    """Return the deliberately unsafe fixture consumed only by target-free self-test."""
    from PIL import Image, ImageDraw
    from PIL.PngImagePlugin import PngInfo

    image = Image.new("RGB", (64, 32), "#28405c")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 31, 31), fill="#f23d4f")
    draw.text((1, 10), "MASK", fill="white")
    output = io.BytesIO()
    metadata = PngInfo()
    metadata.add_text("synthetic-marker", SELF_TEST_SECRET_MARKER)
    image.save(output, format="PNG", pnginfo=metadata)
    return output.getvalue()


def _read_exact(descriptor: int, length: int) -> bytes:
    value = bytearray()
    while len(value) < length:
        chunk = os.read(descriptor, length - len(value))
        if not chunk:
            raise ValueError("request ended early")
        value.extend(chunk)
    return bytes(value)


def _response(status: int, media_type: str, body: bytes) -> bytes:
    value = json.dumps({
        "status": status,
        "media_type": media_type,
        "body_base64": base64.b64encode(body).decode("ascii"),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return struct.pack("!I", len(value)) + value


def _json_body(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _handle(request: dict[str, Any], state: WorkerState) -> tuple[bytes, bool]:
    try:
        if not isinstance(request, dict) or set(request) != {"token", "method", "body"}:
            raise ValueError("request shape")
        token, method, body = request["token"], request["method"], request["body"]
        if not isinstance(token, str) or not hmac.compare_digest(token, state.token):
            return _response(404, "application/json", _json_body({"error": "not_found"})), False
        if not isinstance(body, dict):
            raise ValueError("body mapping required")
        if method == "frame" and not body:
            return _response(200, "image/png", state.frame()), False
        elif method == "action":
            outcome, detail, frame = state.action(body)
            return _response(200, "application/json", _json_body({
                "outcome": outcome, "detail": detail,
                "evidence_png_base64": (
                    base64.b64encode(frame).decode("ascii") if frame is not None else ""
                ),
            })), False
        elif method == "session-proof" and set(body) == {"ready_window"}:
            outcome, detail, frame = state.prove_session(body.get("ready_window"))
            return _response(200, "application/json", _json_body({
                "outcome": outcome,
                "detail": detail,
                "evidence_png_base64": (
                    base64.b64encode(frame).decode("ascii") if frame is not None else ""
                ),
            })), False
        elif method == "release" and not body:
            state.release_controls()
            return _response(200, "application/json", _json_body({"released": True})), False
        elif method == "close" and not body:
            return _response(200, "application/json", _json_body({"closed": True})), True
        else:
            raise ValueError("unsupported method")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, struct.error):
        return _response(422, "application/json", _json_body({"error": "invalid_request"})), False
    except Exception:
        return _response(502, "application/json", _json_body({"error": "worker_failure"})), False


def _capability_from_stdin() -> str:
    raw = os.read(0, 130)
    value = raw.decode("ascii", errors="strict").strip()
    if not _TOKEN_RE.fullmatch(value):
        raise ValueError("invalid private capability")
    try:
        os.close(0)
    except OSError:
        pass
    return value


def run(
    project: str, *, privacy_revision: str, self_test: bool = False
) -> int:
    if not _PROJECT_RE.fullmatch(project):
        raise ValueError("invalid project identifier")
    if not _REVISION_RE.fullmatch(privacy_revision):
        raise ValueError("invalid redaction posture revision")
    token = _capability_from_stdin()
    request_text = os.environ.get("WATCH_LEARN_REQUEST_FD", "")
    response_text = os.environ.get("WATCH_LEARN_RESPONSE_FD", "")
    if (
        not request_text.isdigit() or not response_text.isdigit()
        or not 3 <= int(request_text) <= 1_024
        or not 3 <= int(response_text) <= 1_024
    ):
        raise ValueError("inherited private control descriptors are unavailable")
    request_fd, response_fd = int(request_text), int(response_text)
    owner_uid_text = os.environ.get("WATCH_LEARN_CONTROL_OWNER_UID", "")
    owner_gid_text = os.environ.get("WATCH_LEARN_CONTROL_OWNER_GID", "")
    if (
        request_fd == response_fd
        or not owner_uid_text.isdigit()
        or not owner_gid_text.isdigit()
        or int(owner_uid_text) < 1
        or int(owner_gid_text) < 1
    ):
        raise ValueError("private control descriptor ownership is unavailable")
    owner_uid, owner_gid = int(owner_uid_text), int(owner_gid_text)
    for descriptor in (request_fd, response_fd):
        info = os.fstat(descriptor)
        if (
            not stat.S_ISFIFO(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
        ):
            raise ValueError("private control descriptor validation failed")

    _launch_stage("worker_started")

    if self_test:
        state = WorkerState(
            _SelfTestComputer(privacy_revision), None, None, token
        )
    else:
        specs_root = os.path.abspath(os.environ.get("TESTS_SPECS_DIR", "/app/tests_specs"))
        project_dir = os.path.join(specs_root, project)
        try:
            config = load_project_config(project_dir, specs_root=specs_root)
            if config.target.type not in {"local-app", "vnc"}:
                raise ValueError("Watch & Learn worker supports approved local-app and VNC targets only")
            redactor, _revision = configured_redactor(
                config.redaction,
                expected_revision=privacy_revision,
            )
        except Exception:
            _launch_failure("worker_started", "project_config_invalid")
            raise
        _launch_stage("project_loaded")
        targets = Targets(
            ssh_host_allowlist=config.ssh_host_allowlist,
            rdp_host_allowlist=config.rdp_host_allowlist,
            vnc_host_allowlist=config.vnc_host_allowlist,
            secrets_dir=os.environ.get("SECRETS_RUNTIME_DIR", "/app/secrets"),
        )
        computer = Computer(redactor=redactor)
        _launch_stage("app_launch_started")
        try:
            handle = targets.open_target(TargetSpec(config.target.type, dict(config.target.params)))
        except WindowNotFoundError:
            _launch_failure("app_launch_started", "window_match_failed")
            raise
        except Exception:
            _launch_failure("app_launch_started", "target_launch_failed")
            raise
        _launch_stage("launch_window_verified")
        state = WorkerState(
            computer,
            targets,
            handle,
            token,
            secrets_dir=os.environ.get("SECRETS_RUNTIME_DIR", "/app/secrets"),
        )
    try:
        while not state.closed:
            try:
                size = struct.unpack("!I", _read_exact(request_fd, 4))[0]
                if not 2 <= size <= 4_096:
                    raise ValueError("bounded request required")
                request = json.loads(_read_exact(request_fd, size))
                response, should_close = _handle(request, state)
            except (ValueError, json.JSONDecodeError, struct.error):
                response = _response(422, "application/json", _json_body({"error": "invalid_request"}))
                should_close = False
            offset = 0
            while offset < len(response):
                offset += os.write(response_fd, response[offset:])
            if should_close:
                break
    finally:
        state.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--privacy-revision", required=True)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    return run(
        arguments.project,
        privacy_revision=arguments.privacy_revision,
        self_test=arguments.self_test,
    )


if __name__ == "__main__":
    raise SystemExit(main())
