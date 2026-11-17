#!/usr/bin/env python3
"""Phase 2 exit gate (P2-GATE): prove the virtual display is screenshot-able and drivable.

Launches a sample GUI app on the configured display, takes a screenshot, performs a
scripted interaction (move + type into an xterm, or a click), takes a second screenshot,
and asserts the two differ — i.e. the action produced a visible change.

Run inside the (podman) container, where Xvfb + a WM are already up via entrypoint.sh:

    python scripts/smoke_computer.py

Exits 0 on a confirmed visible change, 1 otherwise.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import time

from PIL import Image, ImageChops

# Allow `python scripts/smoke_computer.py` without installing the package.
sys.path.insert(0, "src")

from orchestrator.computer import Computer  # noqa: E402
from orchestrator.config import settings  # noqa: E402


def _changed_fraction(a: bytes, b: bytes) -> float:
    """Fraction of pixels that differ between two PNG screenshots (0..1)."""
    ia = Image.open(io.BytesIO(a)).convert("RGB")
    ib = Image.open(io.BytesIO(b)).convert("RGB")
    diff = ImageChops.difference(ia, ib)
    if diff.getbbox() is None:
        return 0.0
    # Count pixels whose summed channel difference is non-zero via the luminance
    # histogram of the diff: bin 0 is unchanged pixels, the rest changed.
    mono = diff.convert("L")
    hist = mono.histogram()
    unchanged = hist[0]
    total = mono.width * mono.height
    return (total - unchanged) / total


def main() -> int:
    comp = Computer()
    print(f"[smoke] display={comp.display} model={comp.model_w}x{comp.model_h}")

    # Launch a sample GUI app: an xterm we can type into to force a visible change.
    proc = subprocess.Popen(
        ["xterm", "-geometry", "80x24+0+0", "-e", "bash", "-c", "cat"],
        env={**os.environ, "DISPLAY": comp.display},
    )
    try:
        time.sleep(2.0)  # let the window map

        before = comp.screenshot().png
        print(f"[smoke] before screenshot: {len(before)} bytes")

        # Focus and type a visible string into the terminal.
        comp.left_click(comp.model_w // 4, comp.model_h // 4)
        comp.type("ORCHESTRATOR COOKIE PHASE 2 GATE")
        comp.key("Return")
        time.sleep(1.0)

        after = comp.screenshot().png
        print(f"[smoke] after screenshot: {len(after)} bytes")

        frac = _changed_fraction(before, after)
        print(f"[smoke] changed pixel fraction: {frac:.4%}")

        if frac > 0.001:
            print("[smoke] PASS — scripted action produced a visible change")
            return 0
        print("[smoke] FAIL — no visible change detected", file=sys.stderr)
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
