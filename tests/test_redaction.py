"""Phase 8 tests for orchestrator.redaction + Computer integration (P8-4 redaction hook)."""

from __future__ import annotations

import io

from PIL import Image

from orchestrator.computer import Computer
from orchestrator.redaction import Redactor, Region, redactor_from_regions


def _png(w, h, color=(200, 100, 50)):
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


def _pixel(png, x, y):
    return Image.open(io.BytesIO(png)).convert("RGB").getpixel((x, y))


def test_no_regions_is_noop():
    r = Redactor(regions=[])
    src = _png(20, 20)
    assert r.apply(src) == src
    assert r.active is False


def test_region_blanks_pixels():
    r = Redactor(regions=[Region(2, 2, 6, 6)])
    out = r.apply(_png(20, 20, color=(200, 100, 50)))
    assert _pixel(out, 4, 4) == (0, 0, 0)        # inside the region -> black
    assert _pixel(out, 15, 15) == (200, 100, 50)  # outside -> untouched


def test_region_from_list_and_dict():
    assert Region.from_obj([1, 2, 3, 4]) == Region(1, 2, 3, 4)
    assert Region.from_obj({"x": 1, "y": 2, "width": 3, "height": 4}) == Region(1, 2, 3, 4)


def test_redactor_from_regions_parses_list():
    r = redactor_from_regions([[0, 0, 5, 5], {"x": 10, "y": 10, "w": 2, "h": 2}])
    assert len(r.regions) == 2
    assert r.active is True


def test_computer_screenshot_is_redacted():
    """The redaction hook runs inside screenshot(), so the model never sees the region."""
    comp = Computer(
        display=":99",
        model_w=20,
        model_h=20,
        native_w=20,
        native_h=20,
        runner=lambda cmd: "",
        capture=lambda: _png(20, 20, color=(123, 222, 111)),
        redactor=Redactor(regions=[Region(0, 0, 10, 10)]),
    )
    shot = comp.screenshot()
    assert _pixel(shot.png, 5, 5) == (0, 0, 0)
    assert _pixel(shot.png, 15, 15) == (123, 222, 111)
