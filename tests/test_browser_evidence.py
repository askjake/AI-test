"""browser_evidence: region validation, stability, temporal metrics, verdicts, sanitizer.  Synthetic frames only; no model, no network."""
import io

import pytest
from PIL import Image

from bv_sim import tile_image
from orchestrator import browser_evidence as ev

BOX = (40, 40, 232, 148)
REG = ev.Region("Stream 1", 40, 40, 192, 108)


def png(img):
    b = io.BytesIO()
    img.save(b, "PNG")
    return b.getvalue()


def frame_png(tile, size=(400, 240)):
    img = Image.new("RGB", size, (20, 40, 60))
    img.paste(tile, (40, 40))
    return png(img)


def frames(mode, n=6, step=3.0, t0=0.0):
    return [ev.Frame(f"f{i}", i * step, frame_png(tile_image(mode, 1, t0 + i * step))) for i in range(n)]


def stream(mode, n=6, step=3.0, t0=0.0, hints=None):
    fr = frames(mode, n, step, t0)
    out = ev.analyze(fr, [[REG]] * n, hints or [{}] * n)
    return out["streams"][0]


# ------------------------------------------------------------------------------------ region validation
def test_region_validation_rejects_bad_proposals_and_never_raises():
    raw = [{"label": "ok", "x": 10, "y": 10, "w": 100, "h": 60},
           {"label": "oob", "x": 350, "y": 10, "w": 100, "h": 60},
           {"label": "neg", "x": -1, "y": 0, "w": 50, "h": 50},
           {"label": "tiny", "x": 0, "y": 0, "w": 4, "h": 4},
           {"label": "huge", "x": 0, "y": 0, "w": 400, "h": 240},
           {"label": "nan", "x": float("nan"), "y": 0, "w": 50, "h": 50},
           {"label": "bool", "x": True, "y": 0, "w": 50, "h": 50},
           {"label": "str", "x": "1", "y": 0, "w": 50, "h": 50},
           "junk", None, 7]
    ok, rej = ev.validate_regions(raw, (400, 240))
    assert [r.label for r in ok] == ["ok"]
    reasons = {r["reason"] for r in rej}
    assert {"OUT_OF_BOUNDS", "TOO_SMALL", "TOO_LARGE", "NON_NUMERIC", "NOT_AN_OBJECT"} <= reasons
    assert ev.validate_regions("nope", (400, 240))[1][0]["reason"] == "REGIONS_NOT_A_LIST"


def test_overlapping_regions_are_both_rejected_not_silently_resolved():
    raw = [{"label": "a", "x": 10, "y": 10, "w": 100, "h": 60}, {"label": "b", "x": 60, "y": 30, "w": 100, "h": 60},
           {"label": "c", "x": 250, "y": 10, "w": 100, "h": 60}]
    ok, rej = ev.validate_regions(raw, (400, 240))
    assert [r.label for r in ok] == ["c"] and sorted(r["label"] for r in rej if r["reason"] == "OVERLAP") == ["a", "b"]


def test_too_many_regions_and_label_sanitising():
    raw = [{"label": f"s{i}", "x": (i % 8) * 48, "y": (i // 8) * 40, "w": 40, "h": 30} for i in range(20)]
    ok, rej = ev.validate_regions(raw, (400, 240), ev.AnalysisLimits(min_region_w_frac=0.01, min_region_h_frac=0.01))
    assert len(ok) == 16 and sum(r["reason"] == "TOO_MANY_REGIONS" for r in rej) == 4
    lab = ev.sanitize_label("Cam\x00 1\n<script>" + "x" * 200)
    assert "\x00" not in lab and "\n" not in lab and "<" not in lab and len(lab) <= 60


# --------------------------------------------------------------------------------------- stability
def test_stable_regions_make_stable_tracks():
    tr, prob = ev.build_tracks([[REG]] * 4)
    assert len(tr) == 1 and tr[0].stable and not prob


@pytest.mark.parametrize("second,reason", [
    (ev.Region("Stream 1", 80, 40, 192, 108), "REGION_MOVED_OR_RESIZED"),
    (ev.Region("Stream 1", 40, 40, 150, 90), "REGION_MOVED_OR_RESIZED"),
    (ev.Region("Other", 40, 40, 192, 108), "LABEL_CHANGED"),
    (ev.Region("Stream 1", 300, 150, 60, 50), "REGION_MISSING")])
def test_moved_resized_relabelled_or_missing_regions_are_unstable(second, reason):
    tr, _ = ev.build_tracks([[REG], [second]])
    assert tr[0].stable is False and reason in tr[0].reasons


def test_extra_region_and_duplicate_labels_are_flagged():
    extra = ev.Region("New", 250, 150, 100, 60)
    _, prob = ev.build_tracks([[REG], [REG, extra]])
    assert "EXTRA_REGION_APPEARED" in prob
    a, b = ev.Region("Same", 10, 10, 100, 60), ev.Region("Same", 200, 10, 100, 60)
    tr, _ = ev.build_tracks([[a, b]])
    assert all("DUPLICATE_LABEL" in t.warnings for t in tr)


# ----------------------------------------------------------------------------- temporal verdicts
def test_advancing_content_is_playback_advancing_without_freshness_or_audio_claims():
    s = stream("advancing")
    assert s["state"] == ev.PLAYBACK_ADVANCING and s["reasons"] == ["BROAD_SUSTAINED_TEMPORAL_CHANGE"]
    assert s["live_source_freshness"] == "UNVERIFIED" and s["audio"] == "NOT_ASSESSED"


@pytest.mark.parametrize("mode", ["frozen", "noisy_frozen"])
def test_frozen_content_even_with_compression_noise_is_static(mode):
    assert stream(mode)["state"] == ev.STATIC


@pytest.mark.parametrize("mode", ["spinner", "clock", "cursor"])
def test_spinner_clock_cursor_only_changes_are_inconclusive_not_advancing(mode):
    s = stream(mode)
    assert s["state"] == ev.UNDETERMINED and "LOCALIZED_CHANGE_ONLY" in s["reasons"]


def test_scrolling_like_translation_is_inconclusive():
    s = stream("scroll")
    assert s["state"] == ev.UNDETERMINED and "TRANSLATION_LIKE_CHANGE" in s["reasons"]


def test_one_scroll_like_pair_among_advancing_pairs_keeps_the_stream_inconclusive():
    tiles = [tile_image("scroll", 1, 0.0), tile_image("scroll", 1, 3.0)] + [tile_image("advancing", 1, 6.0 + 3 * i) for i in range(4)]
    fr = [ev.Frame(f"f{i}", i * 3.0, frame_png(t)) for i, t in enumerate(tiles)]
    s = ev.analyze(fr, [[REG]] * 6, [{}] * 6)["streams"][0]
    assert s["pairs"]["TRANSLATION"] >= 1 and s["pairs"]["BROAD_CHANGE"] >= 3
    assert s["state"] == ev.UNDETERMINED and "TRANSLATION_LIKE_CHANGE" in s["reasons"]


def test_a_single_scene_change_is_not_sustained_advancement():
    s = stream("cut_once", t0=21.0)
    assert s["state"] == ev.UNDETERMINED and "CHANGE_NOT_SUSTAINED" in s["reasons"]


def test_model_opinion_cannot_promote_a_frozen_stream():
    s = stream("frozen", hints=[{"Stream 1": {"state": "playing", "overlay": False}}] * 6)
    assert s["state"] == ev.STATIC


def test_model_loading_and_error_hints_are_reported_and_overlay_makes_it_inconclusive():
    h = lambda st, ov=False: [{"Stream 1": {"state": st, "overlay": ov}}] * 6
    assert stream("advancing", hints=h("loading"))["state"] == ev.LOADING
    assert stream("advancing", hints=h("error"))["state"] == ev.ERROR
    s = stream("advancing", hints=h("playing", True))
    assert s["state"] == ev.UNDETERMINED and "OVERLAY_PRESENT" in s["reasons"]


def test_too_few_frames_or_too_short_a_span_is_insufficient():
    assert "INSUFFICIENT_OBSERVATION" in stream("advancing", n=4)["reasons"]
    s = stream("advancing", n=6, step=2.0)           # span 10 s < 15 s
    assert s["state"] == ev.UNDETERMINED and "INSUFFICIENT_OBSERVATION" in s["reasons"]


def test_unstable_track_is_never_analysed():
    fr = frames("advancing")
    moved = ev.Region("Stream 1", 100, 40, 192, 108)
    out = ev.analyze(fr, [[REG]] * 5 + [[moved]], [{}] * 6)["streams"][0]
    assert out["state"] == ev.UNDETERMINED and "REGION_UNSTABLE" in out["reasons"] and "pairs" not in out


def test_frame_resize_makes_everything_undetermined():
    fr = frames("advancing")
    fr[3] = ev.Frame("f3", 9.0, frame_png(tile_image("advancing", 1, 9.0), size=(420, 250)))
    out = ev.analyze(fr, [[REG]] * 6, [{}] * 6)
    assert "FRAME_SIZE_CHANGED" in out["problems"] and out["streams"][0]["state"] == ev.UNDETERMINED


def test_run_verdicts():
    st = lambda *s: [{"state": x} for x in s]
    A, S_, U, L = ev.PLAYBACK_ADVANCING, ev.STATIC, ev.UNDETERMINED, ev.LOADING
    assert ev.run_verdict([]) == "NO_STREAMS"
    assert ev.run_verdict(st(A, A)) == "PLAYBACK_ADVANCING_ALL"
    assert ev.run_verdict(st(A, S_)) == "PLAYBACK_ADVANCING_PARTIAL"
    assert ev.run_verdict(st(S_, S_)) == "PLAYBACK_NOT_ADVANCING"
    assert ev.run_verdict(st(S_, U)) == "OBSERVATION_INCONCLUSIVE" and ev.run_verdict(st(L)) == "OBSERVATION_INCONCLUSIVE"


# ----------------------------------------------------------------------- geometry corroboration + sanitizer
def test_new_rectangle_is_corroboration_only_and_ignores_unrelated_changes():
    a = Image.new("RGB", (1280, 720), (30, 60, 90))
    b = a.copy()
    b.paste(Image.new("RGB", (400, 300), (250, 250, 250)), (60, 60))
    exp = (90, 90, 90 + 600, 90 + 450)                                  # reference px (x1.5 of the 1280 frame)
    r = ev.find_new_rectangle(png(a), png(b), exp)
    assert r["found"] is True and "never ownership proof" in r["basis"]
    clock = b.copy()
    clock.paste(Image.new("RGB", (60, 20), (255, 255, 0)), (1200, 690))   # an unrelated clock tick elsewhere must not break it
    assert ev.find_new_rectangle(png(a), png(clock), exp)["found"] is True
    assert ev.find_new_rectangle(png(a), png(a), exp)["found"] is False
    assert ev.find_new_rectangle(png(a), png(b), (900, 900, 1400, 1100))["found"] is False
    huge = a.copy()
    huge.paste(Image.new("RGB", (1000, 650), (250, 250, 250)), (20, 20))  # a much bigger window changes the ring too: not "the requested" one
    assert ev.find_new_rectangle(png(a), png(huge), exp)["found"] is False


def test_sanitizer_rejects_secrets_commands_and_oversized_text():
    ev.assert_sanitized({"a": [1, "fine", {"b": "also fine"}]})
    for bad in ({"password": "x"}, {"x": {"raw_response": "..."}}, {"x": "run /p:abc"}, {"x": "chrome --user-data-dir=%TEMP%\\z"},
                {"x": "a" * 301}, {"command": "x"}, {"x": ["cmd /k echo"]}):
        with pytest.raises(ValueError):
            ev.assert_sanitized(bad)
