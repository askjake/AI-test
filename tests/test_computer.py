"""Phase 2 tests for orchestrator.computer (P2-3, P2-4, action argv shape).

These exercise the screenshot downscaling and coordinate mapping without a real X
display, by injecting a fake command runner and a fake screen-capture function.
"""

from __future__ import annotations

import io
import subprocess

import pytest
from PIL import Image

from orchestrator.computer import Computer, annotate_action


def _png_bytes(w: int, h: int, color=(10, 20, 30)) -> bytes:
    img = Image.new("RGB", (w, h), color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class FakeRunner:
    """Records argv lists and returns canned stdout keyed by the first xdotool verb."""

    def __init__(self, outputs=None):
        self.calls: list[list[str]] = []
        self._outputs = outputs or {}

    def __call__(self, cmd: list[str]) -> str:
        self.calls.append(cmd)
        # cmd[0] is "xdotool"; key on the subcommand.
        verb = cmd[1] if len(cmd) > 1 else ""
        return self._outputs.get(verb, "")


def _computer(runner, native=(2560, 1600), model=(1280, 800)):
    return Computer(
        display=":99",
        model_w=model[0],
        model_h=model[1],
        native_w=native[0],
        native_h=native[1],
        runner=runner,
        capture=lambda: _png_bytes(*native),
    )


def test_screenshot_returns_png_at_model_dims():
    """P2-3: screenshot returns valid PNG downscaled to model dims; scale recorded."""
    runner = FakeRunner()
    comp = _computer(runner, native=(2560, 1600), model=(1280, 800))
    shot = comp.screenshot()

    img = Image.open(io.BytesIO(shot.png))
    assert img.format == "PNG"
    assert img.size == (1280, 800)
    assert shot.model_size == (1280, 800)
    assert shot.native_size == (2560, 1600)
    assert shot.scale_x == pytest.approx(2.0)
    assert shot.scale_y == pytest.approx(2.0)


def test_screenshot_no_resize_when_dims_match():
    runner = FakeRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    shot = comp.screenshot()
    img = Image.open(io.BytesIO(shot.png))
    assert img.size == (1280, 800)
    assert shot.scale_x == pytest.approx(1.0)


def test_coordinate_roundtrip():
    """P2-4: model -> native -> model round-trips within rounding tolerance."""
    comp = _computer(FakeRunner(), native=(2560, 1600), model=(1280, 800))
    for mx, my in [(0, 0), (640, 400), (1279, 799), (100, 250)]:
        nx, ny = comp.to_native(mx, my)
        rx, ry = comp.to_model(nx, ny)
        assert abs(rx - mx) <= 1
        assert abs(ry - my) <= 1


def test_to_native_scales_up():
    comp = _computer(FakeRunner(), native=(2560, 1600), model=(1280, 800))
    assert comp.to_native(640, 400) == (1280, 800)


def test_left_click_maps_and_clicks():
    runner = FakeRunner()
    comp = _computer(runner, native=(2560, 1600), model=(1280, 800))
    comp.left_click(640, 400)
    assert runner.calls[-1] == [
        "xdotool", "mousemove", "1280", "800", "click", "1",
    ]


def test_double_click_uses_repeat():
    runner = FakeRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    comp.double_click(10, 20)
    assert runner.calls[-1] == [
        "xdotool", "mousemove", "10", "20", "click", "--repeat", "2", "1",
    ]


def test_middle_click_and_pointer_button_lifecycle_are_explicit():
    runner = FakeRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    comp.click(10, 20, "middle")
    comp.pointer_button("down", "right", 11, 21)
    comp.pointer_button("up", "right", 12, 22)
    assert runner.calls == [
        ["xdotool", "mousemove", "10", "20", "click", "2"],
        ["xdotool", "mousemove", "11", "21", "mousedown", "3"],
        ["xdotool", "mousemove", "12", "22", "mouseup", "3"],
    ]


def test_drag_preserves_bounded_path_order_and_always_releases():
    runner = FakeRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    comp.drag((1, 2), (9, 10), path=[(3, 4), (5, 6)])
    assert runner.calls == [
        ["xdotool", "mousemove", "1", "2", "mousedown", "1"],
        ["xdotool", "mousemove", "3", "4"],
        ["xdotool", "mousemove", "5", "6"],
        ["xdotool", "mousemove", "9", "10"],
        ["xdotool", "mouseup", "1"],
    ]


def test_drag_failure_still_attempts_pointer_release():
    class FailingRunner(FakeRunner):
        def __call__(self, cmd):
            super().__call__(cmd)
            if cmd[1:3] == ["mousemove", "3"]:
                raise subprocess.CalledProcessError(1, cmd)
            return ""

    runner = FailingRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    with pytest.raises(subprocess.CalledProcessError):
        comp.drag((1, 2), (9, 10), path=[(3, 4)])
    assert runner.calls[-1] == ["xdotool", "mouseup", "1"]


def test_type_uses_guard():
    runner = FakeRunner()
    comp = _computer(runner)
    comp.type("--weird text")
    assert runner.calls[-1] == ["xdotool", "type", "--", "--weird text"]


def test_secret_typing_uses_stdin_and_never_process_argv(monkeypatch):
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed.update(kwargs)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("orchestrator.computer.subprocess.run", fake_run)
    marker = "login-value-must-not-appear-in-argv"
    comp = Computer(
        display=":99",
        model_w=1280,
        model_h=800,
        native_w=1280,
        native_h=800,
        runner=FakeRunner(),
        capture=lambda: _png_bytes(1280, 800),
    )
    comp.type_secret(marker)

    assert observed["argv"] == [
        "xdotool", "type", "--clearmodifiers", "--file", "-",
    ]
    assert marker not in observed["argv"]
    assert observed["input"] == marker
    assert observed["text"] is True
    assert observed["stdout"] is subprocess.DEVNULL
    assert observed["stderr"] is subprocess.DEVNULL


def test_key_combo():
    runner = FakeRunner()
    comp = _computer(runner)
    comp.key("ctrl+c")
    assert runner.calls[-1] == ["xdotool", "key", "--", "ctrl+c"]


def test_bounded_key_control_supports_press_down_up_and_repeat():
    runner = FakeRunner()
    comp = _computer(runner)
    comp.key_control("Tab", modifiers=["shift"], repeat=2)
    comp.key_control("Left", phase="down")
    comp.key_control("Left", phase="up")
    assert runner.calls == [
        ["xdotool", "key", "--", "shift+Tab"],
        ["xdotool", "key", "--", "shift+Tab"],
        ["xdotool", "keydown", "--", "Left"],
        ["xdotool", "keyup", "--", "Left"],
    ]


def test_scroll_down_is_button_5():
    runner = FakeRunner()
    comp = _computer(runner)
    comp.scroll("down", 3)
    assert runner.calls[-1] == ["xdotool", "click", "--repeat", "3", "5"]


def test_scroll_invalid_direction():
    comp = _computer(FakeRunner())
    with pytest.raises(ValueError):
        comp.scroll("sideways")


def test_wheel_moves_to_frame_point_then_applies_vertical_and_horizontal_steps():
    runner = FakeRunner()
    comp = _computer(runner, native=(1280, 800), model=(1280, 800))
    comp.wheel(10, 20, -2, 3)
    assert runner.calls == [
        ["xdotool", "mousemove", "10", "20"],
        ["xdotool", "click", "--repeat", "3", "5"],
        ["xdotool", "click", "--repeat", "2", "6"],
    ]


def test_release_controls_clears_all_supported_buttons_and_modifiers():
    runner = FakeRunner()
    comp = _computer(runner)
    comp.release_controls()
    assert runner.calls[-1] == [
        "xdotool", "mouseup", "1", "mouseup", "2", "mouseup", "3",
        "keyup", "--", "ctrl", "keyup", "--", "shift",
    ]


def test_cursor_position_maps_to_model_space():
    runner = FakeRunner(outputs={"getmouselocation": "X=1280\nY=800\nSCREEN=0\nWINDOW=1\n"})
    comp = _computer(runner, native=(2560, 1600), model=(1280, 800))
    assert comp.cursor_position() == (640, 400)


def test_annotate_action_draws_red_box():
    """A red rounded-rectangle is drawn around the action point; image dims preserved."""
    src = _png_bytes(1280, 800, color=(0, 0, 0))
    out = annotate_action(src, (640, 400))
    img = Image.open(io.BytesIO(out)).convert("RGB")
    assert img.size == (1280, 800)
    reds = [1 for (r, g, b) in img.getdata() if r > 150 and g < 80 and b < 80]
    assert reds  # marker pixels present
    assert out != src


def test_annotate_action_clamps_near_edge():
    """A point near the corner still produces a valid in-bounds PNG."""
    src = _png_bytes(1280, 800)
    out = annotate_action(src, (2, 2))
    img = Image.open(io.BytesIO(out)).convert("RGB")
    assert img.size == (1280, 800)


def test_native_resolution_detected_lazily():
    runner = FakeRunner(outputs={"getdisplaygeometry": "1920 1080\n"})
    comp = Computer(
        display=":99",
        model_w=1280,
        model_h=800,
        runner=runner,
        capture=lambda: _png_bytes(1920, 1080),
    )
    assert comp.native_w == 1920
    assert comp.native_h == 1080
    assert ["xdotool", "getdisplaygeometry"] in runner.calls
