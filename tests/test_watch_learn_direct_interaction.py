"""Target-free acceptance for bounded Watch & Learn direct interaction."""
from __future__ import annotations

from pathlib import Path

import pytest

from dashboard.capture_adapter import CaptureAdapterRegistry
from dashboard.demonstration_models import (
    CaptureActionRequest,
    DragAction,
    KeyAction,
    PointAction,
    PointerButtonAction,
    PointerMoveAction,
    WheelAction,
)
from dashboard.demonstrations import DemonstrationError, DemonstrationService
from orchestrator.watch_learn_worker import WorkerState
from tests.test_phase17_watch_learn import (
    FakeAdapter,
    OPERATOR,
    _point,
    _recording,
    _settings,
)


def _frame_fields(session) -> dict[str, object]:
    frame = session.evidence[-1]
    return {
        "frame_revision": frame.sha256,
        "frame_width": frame.width,
        "frame_height": frame.height,
    }


@pytest.mark.parametrize("button", ["left", "middle", "right"])
@pytest.mark.parametrize("clicks", [1, 2])
def test_versioned_click_schema_supports_bounded_buttons_and_double_click(button, clicks):
    action = PointAction(
        x=19,
        y=9,
        button=button,
        clicks=clicks,
        frame_revision="a" * 64,
        frame_width=20,
        frame_height=10,
    )
    assert action.schema_version == 1
    assert action.button == button and action.clicks == clicks


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "click", "x": 20, "y": 0, "button": "left", "clicks": 1},
        {"kind": "wheel", "x": 1, "y": 1, "delta_x": 0, "delta_y": 0},
        {"kind": "drag", "button": "right", "start_x": 1, "start_y": 1, "end_x": 2, "end_y": 2, "path": []},
    ],
)
def test_coordinate_schema_rejects_outside_empty_or_unsafe_actions(payload):
    with pytest.raises(Exception):
        CaptureActionRequest.model_validate({
            "expected_version": 1,
            "idempotency_key": "bounded-action-1",
            "action": {
                "schema_version": 1,
                "frame_revision": "a" * 64,
                "frame_width": 20,
                "frame_height": 10,
                **payload,
            },
        })


def test_drag_path_is_bounded_and_future_pointer_actions_are_discriminated():
    fields = {"frame_revision": "b" * 64, "frame_width": 100, "frame_height": 50}
    drag = DragAction(
        **fields,
        start_x=1,
        start_y=2,
        end_x=90,
        end_y=40,
        path=[{"x": index + 2, "y": 3} for index in range(32)],
    )
    assert len(drag.path) == 32
    assert PointerButtonAction(**fields, phase="down", x=2, y=3).kind == "pointer_button"
    assert PointerMoveAction(**fields, x=4, y=5, during_drag=True).during_drag is True
    with pytest.raises(Exception):
        DragAction(
            **fields,
            start_x=1,
            start_y=2,
            end_x=90,
            end_y=40,
            path=[{"x": index + 1, "y": 3} for index in range(33)],
        )


@pytest.mark.parametrize(
    "key,modifiers",
    [("TAB", []), ("TAB", ["SHIFT"]), ("A", ["CTRL"]), ("ENTER", [])],
)
def test_safe_key_controls_are_allowlisted(key, modifiers):
    action = KeyAction(key=key, modifiers=modifiers, repeat=3)
    assert action.repeat == 3


@pytest.mark.parametrize(
    "value",
    [
        {"key": "A", "modifiers": []},
        {"key": "ENTER", "modifiers": ["CTRL"]},
        {"key": "TAB", "modifiers": ["CTRL", "SHIFT"]},
        {"key": "TAB", "phase": "down", "modifiers": ["SHIFT"]},
        {"key": "TAB", "repeat": 4},
        {"key": "F12"},
        {"key": "ALT+TAB"},
    ],
)
def test_browser_and_system_shortcuts_or_unbounded_repeats_are_denied(value):
    with pytest.raises(Exception):
        KeyAction.model_validate(value)


def test_server_rejects_stale_frame_without_journal_or_target_dispatch(tmp_path):
    adapter = FakeAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    before_version = session.version
    with pytest.raises(DemonstrationError) as stale:
        service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=session.version,
            idempotency_key="stale-frame-1",
            action=PointAction(
                x=2,
                y=3,
                frame_revision="f" * 64,
                frame_width=20,
                frame_height=10,
            ),
        )
    assert stale.value.code == "stale_frame_revision"
    assert adapter.dispatches == []
    persisted = service.get(OPERATOR, session.session_id)
    assert persisted.version == before_version and persisted.journals == []


def test_current_frame_click_dispatches_once_and_advances_expected_version(tmp_path):
    adapter = FakeAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    updated, receipt = service.capture_action(
        OPERATOR,
        session.session_id,
        expected_version=session.version,
        idempotency_key="current-frame-1",
        action=_point(session, 5, 5),
    )
    assert receipt.outcome == "executed"
    assert updated.version == session.version + 3
    assert len(adapter.dispatches) == 1
    duplicate, duplicate_receipt = service.capture_action(
        OPERATOR,
        session.session_id,
        expected_version=session.version,
        idempotency_key="current-frame-1",
        action=_point(session, 5, 5),
    )
    assert duplicate.version == updated.version
    assert duplicate_receipt == receipt and len(adapter.dispatches) == 1


def test_same_idempotency_key_with_different_action_is_a_conflict(tmp_path):
    adapter = FakeAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    updated, _receipt = service.capture_action(
        OPERATOR,
        session.session_id,
        expected_version=session.version,
        idempotency_key="conflicting-key-1",
        action=KeyAction(key="TAB"),
    )
    with pytest.raises(DemonstrationError) as conflict:
        service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=updated.version,
            idempotency_key="conflicting-key-1",
            action=KeyAction(key="ENTER"),
        )
    assert conflict.value.code == "idempotency_conflict"
    assert len(adapter.dispatches) == 1


def test_pointer_move_is_journaled_but_creates_no_evidence_or_learned_step(tmp_path):
    adapter = FakeAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    evidence_count = len(session.evidence)
    moved, receipt = service.capture_action(
        OPERATOR,
        session.session_id,
        expected_version=session.version,
        idempotency_key="hover-move-1",
        action=PointerMoveAction(**_frame_fields(session), x=5, y=5),
    )
    assert receipt.outcome == "executed"
    assert moved.journals[-1].intent.kind == "pointer_move"
    assert len(moved.evidence) == evidence_count
    stopped = service.stop(OPERATOR, moved.session_id, moved.version)
    analyzed = service.deterministic_analysis(
        OPERATOR, stopped.session_id, expected_version=stopped.version
    )
    assert analyzed.analyses[-1].steps == []


def test_server_rate_limit_rejects_without_extra_dispatch(tmp_path):
    adapter = FakeAdapter()
    settings = _settings(tmp_path).model_copy(update={"watch_learn_action_rate_per_second": 2})
    service = DemonstrationService(
        settings,
        adapters=CaptureAdapterRegistry([adapter]),
        monotonic=lambda: 100.0,
    )
    session = _recording(service, adapter)
    for index in range(2):
        session, _receipt = service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=session.version,
            idempotency_key=f"rate-action-{index}",
            action=KeyAction(key="TAB"),
        )
    with pytest.raises(DemonstrationError) as limited:
        service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=session.version,
            idempotency_key="rate-action-overflow",
            action=KeyAction(key="ENTER"),
        )
    assert limited.value.code == "capture_action_rate"
    assert len(adapter.dispatches) == 2


def test_pause_releases_supported_controls_and_prevents_further_relay(tmp_path):
    class ReleasingAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.releases = []

        def release_controls(self, session_id):
            self.releases.append(session_id)

    adapter = ReleasingAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    paused = service.pause(OPERATOR, session.session_id, session.version)
    assert paused.state == "paused" and adapter.releases == [session.session_id]
    with pytest.raises(DemonstrationError):
        service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=paused.version,
            idempotency_key="paused-action-1",
            action=KeyAction(key="TAB"),
        )
    assert adapter.dispatches == []


def test_failed_pause_release_is_visible_and_capture_remains_fail_closed(tmp_path):
    class FailedReleaseAdapter(FakeAdapter):
        def release_controls(self, session_id):
            raise TimeoutError("release confirmation unavailable")

    adapter = FailedReleaseAdapter()
    service = DemonstrationService(_settings(tmp_path), adapters=CaptureAdapterRegistry([adapter]))
    session = _recording(service, adapter)
    failed = service.pause(OPERATOR, session.session_id, session.version)
    assert failed.state == "capture_failed"
    with pytest.raises(DemonstrationError):
        service.capture_action(
            OPERATOR,
            session.session_id,
            expected_version=failed.version,
            idempotency_key="release-failed-action",
            action=KeyAction(key="ENTER"),
        )


def test_worker_executes_bounded_pointer_drag_wheel_and_key_contracts():
    calls = []

    class Frame:
        png = b"frame"

    class Computer:
        def screenshot(self): return Frame()
        def click(self, *args): calls.append(("click", *args))
        def pointer_button(self, *args): calls.append(("pointer", *args))
        def mouse_move(self, *args): calls.append(("move", *args))
        def drag(self, *args, **kwargs): calls.append(("drag", *args, kwargs))
        def wheel(self, *args): calls.append(("wheel", *args))
        def key_control(self, *args, **kwargs): calls.append(("key", *args, kwargs))
        def release_controls(self): calls.append(("release",))

    worker = WorkerState(Computer(), None, None, "opaque-token")
    frame = {
        "schema_version": 1,
        "frame_revision": "a" * 64,
        "frame_width": 100,
        "frame_height": 50,
    }
    assert worker.action({**frame, "kind": "click", "x": 1, "y": 2, "button": "middle", "clicks": 2})[0] == "executed"
    assert worker.action({**frame, "kind": "pointer_button", "phase": "down", "x": 2, "y": 3, "button": "left"})[2] is None
    assert worker.action({**frame, "kind": "pointer_button", "phase": "up", "x": 3, "y": 4, "button": "left"})[2] is None
    assert worker.action({**frame, "kind": "pointer_move", "x": 4, "y": 5, "during_drag": False})[2] is None
    assert worker.action({**frame, "kind": "drag", "button": "left", "start_x": 1, "start_y": 2, "end_x": 9, "end_y": 10, "path": [{"x": 5, "y": 6}]})[0] == "executed"
    assert worker.action({**frame, "kind": "wheel", "x": 7, "y": 8, "delta_x": -2, "delta_y": 3})[0] == "executed"
    assert worker.action({"schema_version": 1, "kind": "key", "key": "A", "phase": "press", "modifiers": ["CTRL"], "repeat": 1})[0] == "executed"
    assert [call[0] for call in calls] == ["click", "pointer", "pointer", "move", "drag", "wheel", "key"]
    with pytest.raises(ValueError):
        worker.action({"kind": "scroll", "direction": "down", "amount": 1})


def test_direct_interaction_ui_is_canvas_scoped_serialized_and_privacy_preserving():
    page = (
        Path(__file__).resolve().parents[1]
        / "templates"
        / "dashboard"
        / "watch_learn.html"
    ).read_text(encoding="utf-8")
    for required in (
        'id="arm-direct"',
        'id="emergency-stop"',
        "directArmed",
        "if(actionInFlight)return",
        "ACTION_QUEUE_LIMIT=32",
        "DRAG_PATH_LIMIT=32",
        "KEY_REPEAT_LIMIT=3",
        "frame_revision:binding.revision",
        "frameCoordinator.isCurrent",
        "canvasUpdating",
        "getBoundingClientRect()",
        'image.addEventListener("pointerdown"',
        'image.addEventListener("pointermove"',
        'image.addEventListener("pointerup"',
        'image.addEventListener("pointercancel"',
        'image.addEventListener("lostpointercapture"',
        'image.addEventListener("wheel"',
        'image.addEventListener("keydown"',
        '"beforeinput","compositionstart","compositionupdate","compositionend","paste","drop"',
        "Action outcome is uncertain; reconciliation is required and no retry was attempted.",
        "document.activeElement!==image",
    ):
        assert required in page
    for prohibited in (
        'document.addEventListener("keydown"',
        'window.addEventListener("keydown"',
        "navigator.clipboard",
        "localStorage",
        "sessionStorage",
        "innerHTML",
        "insertAdjacentHTML",
        "WebSocket",
        "noVNC",
    ):
        assert prohibited not in page
