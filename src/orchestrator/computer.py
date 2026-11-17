"""Executes computer-use actions on the Xvfb virtual display (Phase 2).

Wraps ``xdotool`` (input) and ``scrot`` (capture) to provide screenshot capture and
mouse/keyboard actions, plus coordinate mapping between the **model display size**
(``model_w`` x ``model_h`` — the resolution Claude reasons in) and the **actual Xvfb
resolution** the display is running at (``screen_w`` x ``screen_h``).

The agent always works in model space; this module converts to/from native pixels so
``xdotool`` clicks land where Claude intended and screenshots come back at model dims.

Both the subprocess runner and the raw screen capture are injectable so the logic can be
unit-tested without a real X display.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable

from PIL import Image, ImageDraw

from .config import settings
from .redaction import Redactor

# Actions whose ``coordinate`` input names an on-screen point worth marking in the report.
POINT_ACTIONS = frozenset(
    {
        "left_click",
        "right_click",
        "double_click",
        "mouse_move",
        "left_mouse_down",
        "left_mouse_up",
        "scroll",
    }
)
# Red action marker geometry (model-space pixels).
_MARKER_HALF = 22  # half-width/height of the box around the action point
_MARKER_RADIUS = 8  # corner radius of the rounded rectangle
_MARKER_WIDTH = 3  # stroke width
_MARKER_COLOR = (220, 20, 20)  # red


def annotate_action(png: bytes, coordinate: tuple[int, int]) -> bytes:
    """Return ``png`` with a red rounded-rectangle drawn around ``coordinate``.

    ``coordinate`` is in **model space** — the same space the saved screenshot is in — so
    the box lands on the spot the agent acted. Used only for report evidence; the bytes
    sent back to Claude stay un-annotated so the marker never biases the next decision.
    """
    x, y = int(coordinate[0]), int(coordinate[1])
    img = Image.open(io.BytesIO(png)).convert("RGB")
    w, h = img.size
    draw = ImageDraw.Draw(img)
    left = max(0, x - _MARKER_HALF)
    top = max(0, y - _MARKER_HALF)
    right = min(w - 1, x + _MARKER_HALF)
    bottom = min(h - 1, y + _MARKER_HALF)
    draw.rounded_rectangle(
        [left, top, right, bottom],
        radius=_MARKER_RADIUS,
        outline=_MARKER_COLOR,
        width=_MARKER_WIDTH,
    )
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

# A function that runs an argv list and returns its stdout (text).
Runner = Callable[[list[str]], str]
# A function that captures the whole screen at native resolution as PNG bytes.
Capture = Callable[[], bytes]
SecretTyper = Callable[[str], None]


def _default_runner(display: str) -> Runner:
    """Build a runner that executes ``xdotool``/X commands with DISPLAY set."""

    def run(cmd: list[str]) -> str:
        env = {**os.environ, "DISPLAY": display}
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, check=True
        )
        return proc.stdout

    return run


def _default_capture(display: str) -> Capture:
    """Build a capture fn that grabs the root window via ``scrot`` to a temp file."""

    def capture() -> bytes:
        env = {**os.environ, "DISPLAY": display}
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            path = tmp.name
        try:
            subprocess.run(
                ["scrot", "--overwrite", path],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            with open(path, "rb") as fh:
                return fh.read()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    return capture


def _default_secret_typer(display: str) -> SecretTyper:
    """Type sensitive text over stdin so it never appears in process argv."""
    def type_secret(value: str) -> None:
        env = {**os.environ, "DISPLAY": display}
        subprocess.run(
            ["xdotool", "type", "--clearmodifiers", "--file", "-"],
            env=env,
            input=value,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    return type_secret


@dataclass
class Screenshot:
    """A captured screenshot, downscaled to model space.

    ``png`` is the PNG bytes at model dimensions. ``scale_x``/``scale_y`` are the
    native/model ratios used (a native pixel is ``scale`` model pixels); they are recorded
    so callers can reason about precision. ``native_size``/``model_size`` are ``(w, h)``.
    """

    png: bytes
    scale_x: float
    scale_y: float
    native_size: tuple[int, int]
    model_size: tuple[int, int]


# Keys/modifiers xdotool understands directly; passed through as a key chord.
_SCROLL_BUTTON = {"up": 4, "down": 5, "left": 6, "right": 7}
_POINTER_BUTTON = {"left": 1, "middle": 2, "right": 3}


class Computer:
    """Drives the virtual display: screenshots + mouse/keyboard via ``xdotool``.

    Coordinates accepted by the action methods are in **model space** (the resolution
    Claude sees). They are converted to native Xvfb pixels before being handed to
    ``xdotool``; ``cursor_position`` converts the other way.
    """

    def __init__(
        self,
        *,
        display: str | None = None,
        model_w: int | None = None,
        model_h: int | None = None,
        native_w: int | None = None,
        native_h: int | None = None,
        runner: Runner | None = None,
        capture: Capture | None = None,
        redactor: Redactor | None = None,
        secret_typer: SecretTyper | None = None,
    ) -> None:
        self.display = display or settings.display
        self.model_w = model_w or settings.model_w
        self.model_h = model_h or settings.model_h
        self._run = runner or _default_runner(self.display)
        self._capture = capture or _default_capture(self.display)
        # Optional screenshot redaction (Phase 8); no-op when no regions are configured.
        self.redactor = redactor or Redactor(regions=[])
        self._secret_typer = secret_typer or _default_secret_typer(self.display)
        # Native resolution may be supplied (tests / explicit) or detected lazily.
        self._native_w = native_w
        self._native_h = native_h

    # --- native resolution -------------------------------------------------

    def _detect_native(self) -> tuple[int, int]:
        """Detect the Xvfb resolution via ``xdotool getdisplaygeometry``."""
        out = self._run(["xdotool", "getdisplaygeometry"]).strip()
        w_str, h_str = out.split()
        return int(w_str), int(h_str)

    @property
    def native_w(self) -> int:
        if self._native_w is None:
            self._native_w, self._native_h = self._detect_native()
        return self._native_w

    @property
    def native_h(self) -> int:
        if self._native_h is None:
            self._native_w, self._native_h = self._detect_native()
        return self._native_h

    # --- coordinate mapping ------------------------------------------------

    def to_native(self, x: int, y: int) -> tuple[int, int]:
        """Map a model-space point to native Xvfb pixels."""
        nx = round(x * self.native_w / self.model_w)
        ny = round(y * self.native_h / self.model_h)
        return nx, ny

    def to_model(self, x: int, y: int) -> tuple[int, int]:
        """Map a native Xvfb point back to model space."""
        mx = round(x * self.model_w / self.native_w)
        my = round(y * self.model_h / self.native_h)
        return mx, my

    # --- screenshot --------------------------------------------------------

    def screenshot(self) -> Screenshot:
        """Capture the screen and downscale it to model dimensions.

        Returns a :class:`Screenshot` whose ``png`` is at model dims and whose
        ``scale_x``/``scale_y`` record the native/model ratio.
        """
        raw = self._capture()
        img = Image.open(io.BytesIO(raw))
        native_w, native_h = img.size
        # Trust the actual captured size as native truth; cache it.
        self._native_w, self._native_h = native_w, native_h

        if (native_w, native_h) != (self.model_w, self.model_h):
            img = img.convert("RGB").resize(
                (self.model_w, self.model_h), Image.LANCZOS
            )

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        # Redact sensitive regions (model space) before the bytes reach Claude or the report.
        png = self.redactor.apply(buf.getvalue())
        return Screenshot(
            png=png,
            scale_x=native_w / self.model_w,
            scale_y=native_h / self.model_h,
            native_size=(native_w, native_h),
            model_size=(self.model_w, self.model_h),
        )

    # --- mouse/keyboard actions (model-space coordinates in) ---------------

    def left_click(self, x: int, y: int) -> None:
        self.click(x, y, "left")

    def right_click(self, x: int, y: int) -> None:
        self.click(x, y, "right")

    def click(self, x: int, y: int, button: str = "left", clicks: int = 1) -> None:
        number = _POINTER_BUTTON.get(button)
        if number is None or clicks not in {1, 2}:
            raise ValueError("invalid bounded pointer click")
        nx, ny = self.to_native(x, y)
        command = ["xdotool", "mousemove", str(nx), str(ny), "click"]
        if clicks == 2:
            command.extend(["--repeat", "2"])
        command.append(str(number))
        self._run(command)

    def double_click(self, x: int, y: int) -> None:
        self.click(x, y, "left", 2)

    def mouse_move(self, x: int, y: int) -> None:
        nx, ny = self.to_native(x, y)
        self._run(["xdotool", "mousemove", str(nx), str(ny)])

    def pointer_button(self, phase: str, button: str, x: int, y: int) -> None:
        number = _POINTER_BUTTON.get(button)
        if number is None or phase not in {"down", "up"}:
            raise ValueError("invalid pointer button lifecycle")
        nx, ny = self.to_native(x, y)
        verb = "mousedown" if phase == "down" else "mouseup"
        self._run(["xdotool", "mousemove", str(nx), str(ny), verb, str(number)])

    def drag(
        self,
        start: tuple[int, int],
        end: tuple[int, int],
        *,
        button: str = "left",
        path: list[tuple[int, int]] | None = None,
    ) -> None:
        number = _POINTER_BUTTON.get(button)
        if number not in {1, 2}:
            raise ValueError("invalid drag button")
        self.pointer_button("down", button, *start)
        try:
            for point in [*(path or []), end]:
                self.mouse_move(*point)
        finally:
            # A release is idempotent and is attempted even if an intermediate
            # movement fails; the caller still treats the operation as uncertain.
            self._run(["xdotool", "mouseup", str(number)])

    def type(self, text: str) -> None:
        # ``--`` guards against text that looks like an option.
        self._run(["xdotool", "type", "--", text])

    def type_secret(self, text: str) -> None:
        """Type a secret through stdin; callers must keep capture paused."""
        self._secret_typer(text)

    def key(self, combo: str) -> None:
        # e.g. "Return", "ctrl+c", "alt+Tab".
        self._run(["xdotool", "key", "--", combo])

    def key_control(
        self,
        key: str,
        *,
        phase: str = "press",
        modifiers: list[str] | None = None,
        repeat: int = 1,
    ) -> None:
        if phase not in {"press", "down", "up"} or not 1 <= repeat <= 3:
            raise ValueError("invalid key lifecycle")
        combo = "+".join([*(modifiers or []), key])
        if phase == "press":
            for _ in range(repeat):
                self._run(["xdotool", "key", "--", combo])
        else:
            self._run(["xdotool", "keydown" if phase == "down" else "keyup", "--", combo])

    def scroll(self, direction: str, amount: int = 1) -> None:
        button = _SCROLL_BUTTON.get(direction)
        if button is None:
            raise ValueError(f"invalid scroll direction: {direction!r}")
        self._run(["xdotool", "click", "--repeat", str(max(1, amount)), str(button)])

    def wheel(self, x: int, y: int, delta_x: int, delta_y: int) -> None:
        self.mouse_move(x, y)
        for delta, negative, positive in (
            (delta_y, "up", "down"),
            (delta_x, "left", "right"),
        ):
            if delta:
                self.scroll(positive if delta > 0 else negative, abs(delta))

    def release_controls(self) -> None:
        """Idempotently clear supported held buttons/modifiers after capture loss."""
        self._run([
            "xdotool", "mouseup", "1", "mouseup", "2", "mouseup", "3",
            "keyup", "--", "ctrl", "keyup", "--", "shift",
        ])

    def cursor_position(self) -> tuple[int, int]:
        """Return the current pointer position in **model space**."""
        out = self._run(["xdotool", "getmouselocation", "--shell"])
        coords: dict[str, int] = {}
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                if k in ("X", "Y"):
                    coords[k] = int(v)
        return self.to_model(coords.get("X", 0), coords.get("Y", 0))
