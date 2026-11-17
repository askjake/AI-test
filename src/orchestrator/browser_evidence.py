"""browser_verify evidence analysis (b4r12-dev): pure functions, Pillow only, no I/O, no model, no network.

What this module can and cannot establish
-----------------------------------------
* Stream IDENTIFICATION (where a player is, what it is called) comes from a classifier PROPOSAL.  Proposals are untrusted: bounds,
  size, overlap and stability across frames are validated here before any region is analysed.
* ADVANCEMENT is judged only from non-model temporal pixel differences inside a validated, stable region.  A model's opinion
  ("looks playing") never promotes a stream to PLAYBACK_ADVANCING; it can only add LOADING / ERROR / overlay hints.
* Pixel motion cannot tell live video from a recording, so live-source freshness is always UNVERIFIED.  Audio is never assessed.
* Simple pixel differences do NOT reject every false positive.  Spinners, clocks and cursors are handled heuristically (small changed
  area, translation test); anything ambiguous is reported UNDETERMINED with reason codes instead of guessed.
"""
from __future__ import annotations

import io
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Sequence

from PIL import Image, ImageChops, ImageStat

SCHEMA = "nrdp.browser_verify.v1"

PLAYBACK_ADVANCING = "PLAYBACK_ADVANCING"
STATIC = "STATIC"
LOADING = "LOADING"
ERROR = "ERROR"
UNDETERMINED = "UNDETERMINED"
STREAM_STATES = (PLAYBACK_ADVANCING, STATIC, LOADING, ERROR, UNDETERMINED)

NO_CHANGE, LOCALIZED, TRANSLATION, BROAD_CHANGE, MIXED = "NO_CHANGE", "LOCALIZED", "TRANSLATION", "BROAD_CHANGE", "MIXED"
REFERENCE_WIDTH = 1920   # remote desktop width the launch geometry is expressed in (runner display is 1:1 in production)


@dataclass(frozen=True)
class AnalysisLimits:
    min_frames: int = 6
    min_span_s: float = 15.0
    max_streams: int = 16
    min_region_w_frac: float = 0.04      # of frame width
    min_region_h_frac: float = 0.04      # of frame height
    max_area_fraction: float = 0.90
    overlap_iou: float = 0.10
    overlap_min_fraction: float = 0.25   # intersection / smaller region
    stable_iou: float = 0.80
    work_w: int = 96
    work_h: int = 54
    mad_floor: float = 0.6               # mean abs difference (0-255) below which a pair is "no change" (compression noise level)
    noise_peak_max: float = 6.0          # strongest 1/96 block of the difference (0-255); compression noise stays below it
    block_thr: float = 6.0
    localized_max_fraction: float = 0.12  # changed area share below which a change is "small" (spinner, clock, caret, cursor)
    broad_min_fraction: float = 0.25
    broad_min_mad: float = 2.0
    shift_max: int = 6
    shift_step: int = 2
    shift_ratio: float = 0.5             # a pure shift explaining >= half of the change => scroll / pan / resize-like
    advancing_pair_fraction: float = 0.6
    advancing_min_pairs: int = 3


@dataclass(frozen=True)
class Region:
    label: str
    x: int
    y: int
    w: int
    h: int

    @property
    def box(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.x + self.w, self.y + self.h)

    @property
    def area(self) -> int:
        return self.w * self.h


@dataclass
class Frame:
    ref: str | None
    t: float            # seconds on the run clock
    png: bytes


@dataclass
class Track:
    id: str
    label: str
    box: tuple[int, int, int, int]
    stable: bool = True
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


_LABEL_BAD = re.compile(r"[^\w .:+()/#'\-]", re.UNICODE)


def sanitize_label(value: Any, limit: int = 60) -> str:
    text = value if isinstance(value, str) else ""
    text = _LABEL_BAD.sub("?", text.replace("\r", " ").replace("\n", " "))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def norm_label(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip().casefold()


def _num(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)):
        return None
    return int(round(v))


def iou(a: Region, b: Region) -> float:
    ix = max(0, min(a.x + a.w, b.x + b.w) - max(a.x, b.x))
    iy = max(0, min(a.y + a.h, b.y + b.h) - max(a.y, b.y))
    inter = ix * iy
    union = a.area + b.area - inter
    return inter / union if union else 0.0


def _inter_frac_of_smaller(a: Region, b: Region) -> float:
    ix = max(0, min(a.x + a.w, b.x + b.w) - max(a.x, b.x))
    iy = max(0, min(a.y + a.h, b.y + b.h) - max(a.y, b.y))
    return (ix * iy) / max(1, min(a.area, b.area))


def validate_regions(raw: Any, frame_size: tuple[int, int], limits: AnalysisLimits = AnalysisLimits()) -> tuple[list[Region], list[dict]]:
    """Classifier proposals -> (accepted regions sorted top-left first, rejected [{index,label,reason}]).  Never raises."""
    W, H = frame_size
    accepted: list[tuple[int, Region]] = []
    rejected: list[dict] = []
    if not isinstance(raw, (list, tuple)):
        return [], [{"index": -1, "label": "", "reason": "REGIONS_NOT_A_LIST"}]
    for i, item in enumerate(raw):
        label = sanitize_label(item.get("label") if isinstance(item, dict) else "")
        if i >= limits.max_streams:
            rejected.append({"index": i, "label": label, "reason": "TOO_MANY_REGIONS"})
            continue
        if not isinstance(item, dict):
            rejected.append({"index": i, "label": label, "reason": "NOT_AN_OBJECT"})
            continue
        vals = [_num(item.get(k)) for k in ("x", "y", "w", "h")]
        if any(v is None for v in vals):
            rejected.append({"index": i, "label": label, "reason": "NON_NUMERIC"})
            continue
        x, y, w, h = vals  # type: ignore[misc]
        if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > W or y + h > H:
            rejected.append({"index": i, "label": label, "reason": "OUT_OF_BOUNDS"})
            continue
        if w < limits.min_region_w_frac * W or h < limits.min_region_h_frac * H:
            rejected.append({"index": i, "label": label, "reason": "TOO_SMALL"})
            continue
        if w * h > limits.max_area_fraction * W * H:
            rejected.append({"index": i, "label": label, "reason": "TOO_LARGE"})
            continue
        accepted.append((i, Region(label, x, y, w, h)))
    bad: set[int] = set()
    for a in range(len(accepted)):
        for b in range(a + 1, len(accepted)):
            ra, rb = accepted[a][1], accepted[b][1]
            if iou(ra, rb) > limits.overlap_iou or _inter_frac_of_smaller(ra, rb) > limits.overlap_min_fraction:
                bad.update((a, b))
    keep: list[Region] = []
    for pos, (i, r) in enumerate(accepted):
        if pos in bad:
            rejected.append({"index": i, "label": r.label, "reason": "OVERLAP"})
        else:
            keep.append(r)
    keep.sort(key=lambda r: (r.y, r.x))
    return keep, rejected


def build_tracks(per_frame: Sequence[Sequence[Region]], limits: AnalysisLimits = AnalysisLimits()) -> tuple[list[Track], list[str]]:
    """Stable player regions.  The first frame's accepted regions are the reference; each later frame must contain a region with
    IoU >= stable_iou and the same label.  Anything else marks that track unstable (never silently re-aligned)."""
    if not per_frame or not per_frame[0]:
        return [], []
    ref = list(per_frame[0])
    counts = Counter(norm_label(r.label) for r in ref)
    tracks: list[Track] = []
    claimed: list[set[int]] = [set() for _ in per_frame]
    for n, r in enumerate(ref, 1):
        t = Track(id=f"s{n}", label=r.label or f"stream-{n}", box=r.box)
        if not r.label:
            t.warnings.append("LABEL_NOT_VISIBLE")
        elif counts[norm_label(r.label)] > 1:
            t.warnings.append("DUPLICATE_LABEL")
        for fi in range(1, len(per_frame)):
            cands = [(iou(r, c), ci, c) for ci, c in enumerate(per_frame[fi])]
            best = max(cands, key=lambda z: z[0], default=None)
            if best is None or best[0] <= 0.0:
                t.stable = False
                if "REGION_MISSING" not in t.reasons:
                    t.reasons.append("REGION_MISSING")
                continue
            claimed[fi].add(best[1])
            if best[0] < limits.stable_iou:
                t.stable = False
                if "REGION_MOVED_OR_RESIZED" not in t.reasons:
                    t.reasons.append("REGION_MOVED_OR_RESIZED")
            elif r.label and norm_label(best[2].label) != norm_label(r.label):
                t.stable = False
                if "LABEL_CHANGED" not in t.reasons:
                    t.reasons.append("LABEL_CHANGED")
        tracks.append(t)
    set_problems: list[str] = []
    for fi in range(1, len(per_frame)):
        if len(per_frame[fi]) > len(claimed[fi]) and "EXTRA_REGION_APPEARED" not in set_problems:
            set_problems.append("EXTRA_REGION_APPEARED")
    return tracks, set_problems


# ----------------------------------------------------------------------------------------- temporal metrics


def decode_gray(png: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(png))
    img.load()
    return img.convert("L")


def _work(gray: Image.Image, box: tuple[int, int, int, int], limits: AnalysisLimits) -> Image.Image:
    return gray.crop(box).resize((limits.work_w, limits.work_h), Image.BOX)


def pair_metrics(a: Image.Image, b: Image.Image, limits: AnalysisLimits = AnalysisLimits()) -> dict:
    d = ImageChops.difference(a, b)
    mad = ImageStat.Stat(d).mean[0]
    blocks = d.resize((12, 8), Image.BOX)
    vals = list(blocks.tobytes())
    changed = sum(1 for v in vals if v >= limits.block_thr) / len(vals)
    peak = max(vals)
    m = 8
    W, H = a.size
    inner_b = b.crop((m, m, W - m, H - m))
    mad0 = ImageStat.Stat(ImageChops.difference(a.crop((m, m, W - m, H - m)), inner_b)).mean[0]
    best = mad0
    for dx in range(-limits.shift_max, limits.shift_max + 1, limits.shift_step):
        for dy in range(-limits.shift_max, limits.shift_max + 1, limits.shift_step):
            if dx == 0 and dy == 0:
                continue
            s = ImageStat.Stat(ImageChops.difference(a.crop((m + dx, m + dy, W - m + dx, H - m + dy)), inner_b)).mean[0]
            best = min(best, s)
    translation = mad0 >= 1.0 and best <= limits.shift_ratio * mad0
    return {"mad": round(mad, 3), "changed": round(changed, 3), "peak": round(float(peak), 2), "shift_mad": round(best, 3), "translation": bool(translation)}


def classify_pair(m: dict, limits: AnalysisLimits = AnalysisLimits()) -> str:
    if m["mad"] < limits.mad_floor and m["peak"] < limits.noise_peak_max:
        return NO_CHANGE
    if m["translation"]:
        return TRANSLATION
    if m["changed"] >= limits.broad_min_fraction and m["mad"] >= limits.broad_min_mad:
        return BROAD_CHANGE
    if m["changed"] < limits.localized_max_fraction:
        return LOCALIZED
    return MIXED


def _hint_majority(hints: Sequence[dict], key: str, value: str) -> bool:
    n = sum(1 for h in hints if h.get(key) == value)
    return bool(hints) and n * 2 >= len(hints)


def analyze_stream(track: Track, grays: Sequence[tuple[float, Image.Image]], hints: Sequence[dict],
                   limits: AnalysisLimits = AnalysisLimits()) -> dict:
    """One stream's verdict.  hints: per frame {"state": playing|loading|error|unknown, "overlay": bool} from the classifier (advisory)."""
    out: dict[str, Any] = {"id": track.id, "label": track.label, "box": list(track.box), "state": UNDETERMINED, "reasons": [],
                           "warnings": list(track.warnings), "live_source_freshness": "UNVERIFIED", "audio": "NOT_ASSESSED",
                           "basis": "non-model temporal pixel difference in a validated region; classifier hints advisory only"}
    reasons: list[str] = out["reasons"]
    if not track.stable:
        reasons += ["REGION_UNSTABLE"] + track.reasons
        return out
    n = len(grays)
    span = (grays[-1][0] - grays[0][0]) if n else 0.0
    out["frames_used"], out["span_s"] = n, round(span, 2)
    if n < limits.min_frames or span < limits.min_span_s:
        reasons.append("INSUFFICIENT_OBSERVATION")
        return out
    if any(h.get("overlay") for h in hints):
        reasons.append("OVERLAY_PRESENT")
    if _hint_majority(hints, "state", "error"):
        out["state"] = ERROR
        reasons.append("MODEL_REPORTS_ERROR")
        return out
    if _hint_majority(hints, "state", "loading"):
        out["state"] = LOADING
        reasons.append("MODEL_REPORTS_LOADING")
        return out
    works = [_work(g, track.box, limits) for _, g in grays]
    metrics = [pair_metrics(works[i], works[i + 1], limits) for i in range(len(works) - 1)]
    kinds = [classify_pair(m, limits) for m in metrics]
    c = Counter(kinds)
    out["pairs"] = {"total": len(kinds), **{k: c.get(k, 0) for k in (NO_CHANGE, LOCALIZED, TRANSLATION, BROAD_CHANGE, MIXED)}}
    out["mad_mean"] = round(sum(m["mad"] for m in metrics) / len(metrics), 3)
    out["mad_max"] = round(max(m["mad"] for m in metrics), 3)
    if "OVERLAY_PRESENT" in reasons:
        return out
    half = len(kinds) // 2
    broad_idx = [i for i, k in enumerate(kinds) if k == BROAD_CHANGE]
    if c[NO_CHANGE] == len(kinds):
        out["state"] = STATIC
        reasons.append("NO_PIXEL_CHANGE_OVER_SPAN")
    elif (len(broad_idx) >= max(limits.advancing_min_pairs, math.ceil(limits.advancing_pair_fraction * len(kinds)))
          and c[TRANSLATION] == 0 and any(i < half for i in broad_idx) and any(i >= half for i in broad_idx)):
        out["state"] = PLAYBACK_ADVANCING
        reasons.append("BROAD_SUSTAINED_TEMPORAL_CHANGE")
    else:
        if c[TRANSLATION]:
            reasons.append("TRANSLATION_LIKE_CHANGE")
        if c[LOCALIZED] and not broad_idx:
            reasons.append("LOCALIZED_CHANGE_ONLY")
        if broad_idx and not reasons:
            reasons.append("CHANGE_NOT_SUSTAINED")
        if not reasons:
            reasons.append("MIXED_OR_SPARSE_CHANGE")
    return out


def analyze(frames: Sequence[Frame], per_frame_regions: Sequence[Sequence[Region]], per_frame_hints: Sequence[dict],
            limits: AnalysisLimits = AnalysisLimits()) -> dict:
    """per_frame_regions[i] are the VALIDATED regions proposed on frames[i]; per_frame_hints[i] = {label: {"state","overlay"}}."""
    problems: list[str] = []
    sizes = set()
    grays: list[tuple[float, Image.Image]] = []
    for fr in frames:
        try:
            g = decode_gray(fr.png)
        except Exception:
            problems.append("FRAME_UNDECODABLE")
            break
        sizes.add(g.size)
        grays.append((fr.t, g))
    tracks, set_problems = build_tracks(per_frame_regions, limits)
    problems += set_problems
    streams: list[dict] = []
    if len(sizes) > 1:
        problems.append("FRAME_SIZE_CHANGED")
    for tr in tracks:
        if "FRAME_UNDECODABLE" in problems or "FRAME_SIZE_CHANGED" in problems:
            streams.append({"id": tr.id, "label": tr.label, "box": list(tr.box), "state": UNDETERMINED,
                            "reasons": [p for p in problems if p.startswith("FRAME_")], "warnings": [],
                            "live_source_freshness": "UNVERIFIED", "audio": "NOT_ASSESSED"})
            continue
        hints = [h.get(tr.label, {}) if isinstance(h, dict) else {} for h in per_frame_hints]
        streams.append(analyze_stream(tr, grays, hints, limits))
    return {"streams": streams, "problems": problems, "frames": len(frames),
            "span_s": round(frames[-1].t - frames[0].t, 2) if frames else 0.0}


def run_verdict(streams: Sequence[dict]) -> str:
    if not streams:
        return "NO_STREAMS"
    states = [s["state"] for s in streams]
    adv = states.count(PLAYBACK_ADVANCING)
    if adv == len(states):
        return "PLAYBACK_ADVANCING_ALL"
    if adv:
        return "PLAYBACK_ADVANCING_PARTIAL"
    if all(s == STATIC for s in states):
        return "PLAYBACK_NOT_ADVANCING"
    return "OBSERVATION_INCONCLUSIVE"


# ------------------------------------------------------------------------------ window-geometry corroboration only


def find_new_rectangle(before_png: bytes, after_png: bytes, expected_ref_box: tuple[int, int, int, int],
                       min_inside: float = 0.5, max_ring: float = 0.35, ring_px: int = 12, tol_frac: float = 0.03) -> dict:
    """Did a NEW rectangle of roughly the requested geometry appear between two frames?  Measured as: most pixels INSIDE the requested
    rectangle changed while the thin ring just OUTSIDE it mostly did not (so an unrelated clock tick or notification elsewhere does not
    matter).  CORROBORATION ONLY: it never proves that a window belongs to this run (another window could appear at the same time or place)."""
    a, b = decode_gray(before_png), decode_gray(after_png)
    if a.size != b.size:
        return {"found": False, "reason": "FRAME_SIZE_CHANGED"}
    W, H = a.size
    scale = W / REFERENCE_WIDTH
    x0, y0, x1, y1 = (int(round(v * scale)) for v in expected_ref_box)
    inner = (max(0, x0), max(0, y0), min(W, x1), min(H, y1))
    outer = (max(0, x0 - ring_px), max(0, y0 - ring_px), min(W, x1 + ring_px), min(H, y1 + ring_px))
    diff = ImageChops.difference(a, b).point(lambda v: 255 if v > 24 else 0)

    def count(box: tuple[int, int, int, int]) -> tuple[int, int]:
        if box[2] <= box[0] or box[3] <= box[1]:
            return 0, 0
        c = diff.crop(box)
        return sum(1 for v in c.tobytes() if v), c.size[0] * c.size[1]

    ci, ai = count(inner)
    co, ao = count(outer)
    inside = ci / ai if ai else 0.0
    ring = (co - ci) / (ao - ai) if ao > ai else 0.0
    return {"found": bool(inside >= min_inside and ring <= max_ring), "inside_changed_fraction": round(inside, 3), "ring_changed_fraction": round(ring, 3),
            "expected": [x0, y0, x1, y1], "tolerance_px": round(tol_frac * W, 1), "scale": round(scale, 4),
            "basis": "changed pixels inside the requested rectangle vs a thin ring outside it; corroboration only, never ownership proof"}


# ------------------------------------------------------------------------------------------------ sanitizer

_FORBIDDEN_KEYS = re.compile(r"(?i)^(password|passwd|secret|token|credential|argv|environ|env|raw|raw_response|response|command|command_text|typed|text)$")
_FORBIDDEN_TEXT = re.compile(r"(?i)(/p:|password\s*[=:]|--user-data-dir|--window-size|chrome\s+--|\bcmd\s+/k\b|BEGIN [A-Z ]*PRIVATE KEY)")


def assert_sanitized(obj: Any, _path: str = "$") -> None:
    """Raises ValueError when a result would carry typed command text, credentials-like keys/text or an oversized string."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str) or _FORBIDDEN_KEYS.match(k):
                raise ValueError(f"forbidden key at {_path}.{k}")
            assert_sanitized(v, f"{_path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            assert_sanitized(v, f"{_path}[{i}]")
    elif isinstance(obj, str):
        if len(obj) > 300 or _FORBIDDEN_TEXT.search(obj):
            raise ValueError(f"forbidden or oversized text at {_path}")
