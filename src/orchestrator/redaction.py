"""Optional screenshot redaction hook (Phase 8).

A defence-in-depth complement to the "secrets never typed by Claude" rule: even though the
agent never types credentials and they never appear on screen by construction, a project may
still want to blank fixed-position sensitive regions (a password field, a license banner)
before the PNG is sent to Bedrock or written to a report.

:class:`Redactor` blacks out rectangular regions, given in **model space** (the same
coordinate system Claude reasons in). It is applied inside :meth:`Computer.screenshot` after
downscaling, so every screenshot the model and the report see is already redacted. The hook
is a no-op unless regions are configured, so it costs nothing when unused.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from PIL import Image, ImageDraw
from watch_learn_privacy import (
    WATCH_LEARN_SELF_TEST_REDACTION,
    redaction_configuration_revision,
    validate_redaction_posture,
)


@dataclass(frozen=True)
class Region:
    """A rectangle to blank, in model-space pixels (top-left origin)."""

    x: int
    y: int
    width: int
    height: int

    @classmethod
    def from_obj(cls, obj: object) -> "Region":
        """Build from a ``[x, y, w, h]`` list or an ``{x, y, width, height}`` mapping."""
        if isinstance(obj, (list, tuple)) and len(obj) == 4:
            x, y, w, h = obj
            return cls(int(x), int(y), int(w), int(h))
        if isinstance(obj, dict):
            return cls(
                int(obj["x"]), int(obj["y"]),
                int(obj.get("width", obj.get("w", 0))),
                int(obj.get("height", obj.get("h", 0))),
            )
        raise ValueError(f"cannot parse redaction region from {obj!r}")


@dataclass
class Redactor:
    """Blanks configured regions of a PNG. A no-op when ``regions`` is empty."""

    regions: list[Region]
    fill: tuple[int, int, int] = (0, 0, 0)
    require_in_bounds: bool = False

    @property
    def active(self) -> bool:
        return bool(self.regions)

    def apply(self, png: bytes) -> bytes:
        """Return ``png`` with every configured region filled; unchanged if none."""
        if not self.regions:
            return png
        img = Image.open(io.BytesIO(png)).convert("RGB")
        draw = ImageDraw.Draw(img)
        for r in self.regions:
            if self.require_in_bounds and (
                r.x < 0
                or r.y < 0
                or r.width < 1
                or r.height < 1
                or r.x + r.width > img.width
                or r.y + r.height > img.height
            ):
                raise ValueError("configured redaction region is outside the captured canvas")
            draw.rectangle([r.x, r.y, r.x + r.width, r.y + r.height], fill=self.fill)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()


def redactor_from_regions(raw: object) -> Redactor:
    """Build a :class:`Redactor` from a list of region objects (e.g. project config)."""
    if not raw:
        return Redactor(regions=[])
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"redaction regions must be a list, got {type(raw).__name__}")
    return Redactor(regions=[Region.from_obj(item) for item in raw])


def configured_redactor(
    raw: object, *, expected_revision: str | None = None
) -> tuple[Redactor, str]:
    """Return the existing fixed-region redactor only for a proven active posture.

    The caller must supply the server-loaded project configuration. Empty,
    malformed, unbounded, or stale configurations fail closed. The returned
    redactor also refuses a frame whose dimensions do not contain every region,
    preventing silent clipping from being mistaken for protection.
    """
    normalized = validate_redaction_posture(raw, expected_revision=expected_revision)
    revision = redaction_configuration_revision(raw)
    regions = [Region(*item) for item in normalized]
    return Redactor(regions=regions, require_in_bounds=True), revision
