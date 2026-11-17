"""Shared, target-free Watch & Learn redaction-posture contract.

This neutral module keeps the dashboard independent from the orchestrator
package while giving both sides one canonical configuration fingerprint and
strict validator.  Pixel processing remains runner-only.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any


_POSTURE_SCHEMA = "orchestrator-cookie/fixed-region-redaction/v1"
_MAX_REGIONS = 64
_MAX_COORDINATE = 16_384
WATCH_LEARN_SELF_TEST_REDACTION: tuple[tuple[int, int, int, int], ...] = (
    (0, 0, 32, 32),
)


def redaction_configuration_revision(raw: object) -> str:
    """Fingerprint server-loaded configuration, including invalid posture values."""
    try:
        encoded = json.dumps(
            {"schema": _POSTURE_SCHEMA, "regions": raw},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = json.dumps(
            {"schema": _POSTURE_SCHEMA, "invalid_type": type(raw).__name__},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_region(value: Any) -> tuple[int, int, int, int]:
    if isinstance(value, dict) and set(value).issubset(
        {"x", "y", "width", "height", "w", "h"}
    ):
        values = (
            value.get("x"),
            value.get("y"),
            value.get("width", value.get("w")),
            value.get("height", value.get("h")),
        )
    elif isinstance(value, (list, tuple)) and len(value) == 4:
        values = tuple(value)
    else:
        raise ValueError("redaction posture contains an invalid region shape")
    if any(
        not isinstance(item, (int, float))
        or isinstance(item, bool)
        or not math.isfinite(item)
        or int(item) != item
        for item in values
    ):
        raise ValueError("redaction posture coordinates must be finite integers")
    x, y, width, height = (int(item) for item in values)
    if (
        x < 0
        or y < 0
        or width < 1
        or height < 1
        or x + width > _MAX_COORDINATE
        or y + height > _MAX_COORDINATE
    ):
        raise ValueError("redaction posture coordinates are outside bounded model space")
    return x, y, width, height


def validate_redaction_posture(
    raw: object, *, expected_revision: str | None = None
) -> tuple[tuple[int, int, int, int], ...]:
    """Validate an active, bounded posture and return its normalized regions."""
    revision = redaction_configuration_revision(raw)
    if expected_revision is not None and revision != expected_revision:
        raise ValueError("redaction posture revision is stale")
    if not isinstance(raw, (list, tuple)) or not 1 <= len(raw) <= _MAX_REGIONS:
        raise ValueError("an active configured redaction posture is required")
    return tuple(_strict_region(item) for item in raw)
