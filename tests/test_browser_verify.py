"""browser_verify state machine against the REAL ChainController + a stateful simulator of the adapter contract (screenshot/key/type only).

Honest scope: these tests prove controller logic, refusal paths and evidence handling against fakes.  They do NOT prove that a real Windows
desktop, a real Chrome or a real model behaves this way, and ContractPortDouble tests prove only the ownership EVALUATOR, not a capability.
"""
import json

import pytest

import bv_sim as V
from bv_sim import PROJECT, REQ, build, inputs_after
from orchestrator import browser_evidence as ev
from orchestrator import browser_verify as B
from test_chain import PW1

CLOSE_KEYS = {"alt+f4", "ctrl+w", "ctrl+shift+w"}
ACTIONS = ["bv.open_run_dialog", "bv.select_field", "bv.type_launch", "bv.submit_launch"]


@pytest.fixture
def mk():
    made = []

    def make(*a, **k):
        h = build(*a, **k)
        made.append(h)
        return h
    yield make
    for h in made:
        h.env.close()


def no_close_key_sent(h):
    return not (CLOSE_KEYS & set(h.sim.keys)) and h.sim.closed_by_key == []


# ===================================================================================== refusal paths (no session use at all)
def untouched(h):
    return len(h.env.log) == h.mark and h.env.targets.closed == []


def test_default_policy_refuses_everything_before_touching_the_session(mk):
    h = mk(policy=B.DEFAULT_POLICY)
    res = h.ver.run(REQ)
    assert res["status"] == "refused" and res["code"] == "CAPABILITY_DISABLED" and res["capability"]["enabled"] is False
    assert untouched(h) and res["actions"] == [] and res["escape_count"] == 0


@pytest.mark.parametrize("policy", [
    B.BrowserVerifyPolicy(enabled="yes", allowed_projects=frozenset({PROJECT})),     # truthy is not True
    B.BrowserVerifyPolicy(enabled=True, allowed_projects=frozenset({PROJECT}), allowed_url="http://127.0.0.1:5004/x"),   # cannot widen the URL
    None, "enabled", {"enabled": True}])
def test_a_malformed_or_widened_policy_is_disabled(mk, policy):
    h = mk(policy=policy)
    assert h.ver.run(REQ)["code"] == "CAPABILITY_DISABLED" and untouched(h)


@pytest.mark.parametrize("req,code", [
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "", B.ALLOWED_URL, REQ.confirm_phrase), "REQUEST_MODE_MISSING"),          # request-less Retry shape
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "connection_test", B.ALLOWED_URL, REQ.confirm_phrase), "REQUEST_MODE_MISSING"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "full_run", B.ALLOWED_URL, REQ.confirm_phrase), "REQUEST_MODE_MISSING"),
    (B.BrowserVerifyRequest("other-project", REQ.run_id, "browser_verify", B.ALLOWED_URL, B.expected_confirm_phrase("other-project")), "PROJECT_NOT_ALLOWLISTED"),
    (B.BrowserVerifyRequest("bad project!", REQ.run_id, "browser_verify", B.ALLOWED_URL, REQ.confirm_phrase), "PROJECT_NOT_ALLOWLISTED"),
    (B.BrowserVerifyRequest(PROJECT, "not-a-run", "browser_verify", B.ALLOWED_URL, REQ.confirm_phrase), "REQUEST_INVALID"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "http://127.0.0.1:5004", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "http://127.0.0.1:5004/?x=1", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "https://127.0.0.1:5004/", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "http://localhost:5004/", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", "http://127.0.0.1:5005/", REQ.confirm_phrase), "URL_NOT_ALLOWED"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", B.ALLOWED_URL, ""), "CONFIRMATION_MISSING"),
    (B.BrowserVerifyRequest(PROJECT, REQ.run_id, "browser_verify", B.ALLOWED_URL, PROJECT), "CONFIRMATION_MISSING"),
    (None, "REQUEST_MODE_MISSING")])
def test_every_incomplete_or_wrong_request_is_refused_without_any_input(mk, req, code):
    h = mk()
    res = h.ver.run(req)
    assert res["status"] == "refused" and res["code"] == code and untouched(h)
    assert res["request"]["url"] in ("REJECTED", B.ALLOWED_URL)


def test_identity_not_confirmed_stops_before_any_screenshot_or_input(mk):
    h = mk(establish=False)                                        # controller never established a chain
    res = h.ver.run(REQ)
    assert res["code"] == "IDENTITY_NOT_CONFIRMED" and res["status"] == "aborted"
    assert [e for e in h.env.log[h.mark:] if e[0] in ("key", "type", "screenshot")] == []
    h2 = mk()
    h2.env.controller._identities.clear()                          # confirmed hop but no recorded identity result
    r2 = h2.ver.run(REQ)
    assert r2["code"] == "IDENTITY_NOT_CONFIRMED" and inputs_after(h2) == []


# ============================================================================= launch command allow-list
def test_launch_command_is_allow_listed_and_contains_only_the_allowed_url():
    n = "a1b2c3d4"
    cmd = B.launch_command(n, B.geometry_for_nonce(n))
    assert cmd.count("http") == 1 and cmd.endswith(" " + B.ALLOWED_URL) and f"nrdp-bv-{n}" in cmd
    for forbidden in ("taskkill", "Stop-Process", "-Force", "powershell", "start ", "cmd", "&", "|", ">", "elevat", "runas", "net ", "sc "):
        assert forbidden.lower() not in cmd.lower()
    for bad in ("zzzzzzzz", "a1b2c3", "a1b2c3d4e5", "A1B2C3D4", "a1b2c3d4 & calc"):
        with pytest.raises(ValueError):
            B.geometry_for_nonce(bad)
    assert B.geometry_for_nonce("00000000") != B.geometry_for_nonce("ffffffff")
    with pytest.raises(ValueError):
        B.launch_command(n, (-1, 10, 1000, 600))


def test_limits_can_only_be_tightened():
    for bad in ({"min_frames": 3}, {"min_span_s": 5.0}, {"load_timeout_s": 61.0}, {"total_deadline_s": 301.0}, {"max_frames": 4}, {"frame_interval_s": 0}):
        with pytest.raises(ValueError):
            B.BrowserVerifyLimits(**bad)
    B.BrowserVerifyLimits(total_deadline_s=40.0, load_timeout_s=30.0)


# ================================================================================= production-shaped happy path
def test_happy_path_advancing_streams_leaves_the_window_open_because_ownership_is_unprovable(mk):
    h = mk()
    assert h.sess.ownership_port() is None                         # the production adapter exposes no remote window inventory
    res = h.ver.run(REQ)
    assert (res["status"], res["code"], res["verdict"]) == ("completed", "PLAYBACK_ADVANCING_ALL", "PLAYBACK_ADVANCING_ALL")
    assert [s["state"] for s in res["streams"]] == ["PLAYBACK_ADVANCING"] * 3
    assert all(s["live_source_freshness"] == "UNVERIFIED" and s["audio"] == "NOT_ASSESSED" for s in res["streams"])
    t = res["timeline"]
    assert t["frames_included"] >= 6 and t["span_s"] >= 15.0 and t["total_s"] <= t["deadline_s"]
    assert [a["action_id"] for a in res["actions"]] == ACTIONS and res["escape_count"] == 0
    assert [a["guard"] for a in res["actions"]] == ["FOCUS_ONLY", "PASS", "PASS", "PASS"]
    # cleanup is honest: nothing was closed, and the result says a window may remain
    cl = res["cleanup"]
    assert cl["status"] == "NOT_PERFORMED" and cl["window_state_after"] == "OPEN_OBSERVED"
    assert cl["ownership"]["level"] == "UNPROVEN" and cl["ownership"]["visual_correlation"]["found"] is True
    assert "ADAPTER_EXPOSES_NO_REMOTE_WINDOW_INVENTORY" in cl["ownership"]["reasons"]
    assert no_close_key_sent(h) and len(h.sim.windows) == 1
    # exactly one text was typed: the allow-listed launch command (it replaced the remembered Run text)
    assert len(h.sim.typed_log) == 1 and h.sim.executed[-1] == h.sim.typed_log[0] and h.sim.typed_log[0].startswith("chrome --user-data-dir=")
    assert h.env.targets.closed != []                               # the existing RDP teardown ran
    assert any("ownership was not established" in n for n in h.env.controller.notes())
    assert res["identity"]["recomputed_whole_token_match"] is True and res["identity"]["nonce"] == "NOT_RETAINED_BY_CONTROLLER"
    assert res["model_usage"]["status"] == "UNAVAILABLE"
    dumped = json.dumps(res)
    for leak in ("--user-data-dir", "--window-size", PW1, "/p:", "cmd /k"):
        assert leak not in dumped
    ev.assert_sanitized(res)


def test_a_remembered_run_entry_is_replaced_not_appended_or_executed(mk):
    h = mk({"remembered": "calc.exe"})
    h.ver.run(REQ)
    assert "calc" not in h.sim.executed[-1] and h.sim.executed == [h.sim.typed_log[0]]


def test_preexisting_run_dialog_gets_exactly_one_escape_then_proceeds(mk):
    h = mk({"preexisting_dialog": True, "remembered": "old entry"})
    res = h.ver.run(REQ)
    assert res["escape_count"] == 1 and h.sim.keys.count("Escape") == 1
    assert [a["action_id"] for a in res["actions"]] == [B.ESCAPE_ACTION] + ACTIONS and res["code"] == "PLAYBACK_ADVANCING_ALL"


def test_a_dialog_that_survives_its_single_escape_stops_the_run(mk):
    h = mk({"preexisting_dialog": True, "escape_works": False})
    res = h.ver.run(REQ)
    assert res["code"] == "DESKTOP_NOT_READY" and h.sim.keys.count("Escape") == 1 and h.sim.typed_log == [] and res["cleanup"]["status"] == "NOT_LAUNCHED"


def test_unexpected_prompt_before_launch_stops_without_input(mk):
    h = mk()
    h.sim.prompt_after = h.env.clock.t
    res = h.ver.run(REQ)
    assert res["code"] == "UNEXPECTED_PROMPT" and inputs_after(h) == []


# ===================================================================================== guarded input
def test_guard_failure_before_the_first_input_sends_nothing(mk):
    h = mk()
    h.env.targets.fg_focus_id = "some-other-window"
    res = h.ver.run(REQ)
    assert res["code"] == "BROWSER_INPUT_BLOCKED" and "ctrl+a" not in h.sim.keys and h.sim.typed_log == []
    assert res["actions"][-1]["guard"] == "BLOCKED:CREDENTIAL_FOCUS_CHANGED" and res["actions"][-1]["result"] == "NOT_SENT"
    assert res["cleanup"]["status"] == "NOT_LAUNCHED"


def test_guard_failure_before_submit_leaves_the_command_typed_but_not_run(mk):
    h = mk()
    h.sim.after_type = lambda: setattr(h.env.targets, "fg_focus_id", "other")
    res = h.ver.run(REQ)
    assert res["code"] == "BROWSER_INPUT_BLOCKED" and res["launch"]["state"] == "COMMAND_TYPED_NOT_SUBMITTED"
    assert "Return" not in h.sim.keys and h.sim.executed == [] and h.sim.windows == []
    assert res["cleanup"]["status"] == "NOT_LAUNCHED" and "Run box may still hold it" in res["cleanup"]["note"]


def test_run_dialog_never_confirmed_types_nothing(mk):
    h = mk({"super_r_works": False})
    res = h.ver.run(REQ)
    assert res["code"] == "RUN_DIALOG_NOT_CONFIRMED" and h.sim.typed_log == [] and "ctrl+a" not in h.sim.keys


# ================================================================== launch / page failures (no invented success)
def test_launch_that_never_opens_a_browser_times_out_and_reports_possible_open_window(mk):
    h = mk({"launch_fails": True})
    res = h.ver.run(REQ)
    assert (res["status"], res["code"]) == ("aborted", "BROWSER_OPEN_FAILED") and res["timeline"]["total_s"] >= 60
    assert res["cleanup"]["status"] == "NOT_PERFORMED" and res["cleanup"]["window_state_after"] == "UNKNOWN_MAY_BE_OPEN"
    assert no_close_key_sent(h)


def test_wrong_address_error_page_and_missing_streams(mk):
    wrong = mk({"url_ok": False}).ver.run(REQ)
    assert wrong["code"] == "PAGE_NOT_REACHED" and wrong["timeline"]["total_s"] < 10      # stops at once, not after the load timeout
    assert mk({"error_page": True}).ver.run(REQ)["code"] == "PAGE_NOT_REACHED"
    r = mk({"no_regions": True}).ver.run(REQ)
    assert r["code"] == "STREAMS_NOT_FOUND" and r["streams"] == []


def test_prompt_during_load_and_during_observation_stops_with_partial_evidence(mk):
    h = mk()
    h.sim.prompt_after = h.env.clock.t + 1
    r = h.ver.run(REQ)
    assert r["code"] == "UNEXPECTED_PROMPT" and len(inputs_after(h)) == 4 and r["verdict"] in ("NO_STREAMS", "NOT_RUN")
    h2 = mk()
    h2.sim.prompt_after = h2.env.clock.t + 8
    r2 = h2.ver.run(REQ)
    assert r2["code"] == "UNEXPECTED_PROMPT" and 1 <= r2["timeline"]["frames_included"] < 6
    assert all(s["state"] == "UNDETERMINED" and "INSUFFICIENT_OBSERVATION" in s["reasons"] for s in r2["streams"])
    assert len(inputs_after(h2)) == 4 and no_close_key_sent(h2)


# ===================================================== content scenarios through the whole machine
@pytest.mark.parametrize("modes,verdict,states", [
    (["frozen"] * 3, "PLAYBACK_NOT_ADVANCING", ["STATIC"] * 3),
    (["noisy_frozen"] * 2, "PLAYBACK_NOT_ADVANCING", ["STATIC"] * 2),
    (["advancing", "frozen", "advancing"], "PLAYBACK_ADVANCING_PARTIAL", ["PLAYBACK_ADVANCING", "STATIC", "PLAYBACK_ADVANCING"]),
    (["spinner"] * 2, "OBSERVATION_INCONCLUSIVE", ["UNDETERMINED"] * 2),
    (["clock", "cursor"], "OBSERVATION_INCONCLUSIVE", ["UNDETERMINED"] * 2),
    (["scroll"] * 2, "OBSERVATION_INCONCLUSIVE", ["UNDETERMINED"] * 2),
    (["loading", "loading"], "OBSERVATION_INCONCLUSIVE", ["LOADING"] * 2),
    (["error", "advancing"], "PLAYBACK_ADVANCING_PARTIAL", ["ERROR", "PLAYBACK_ADVANCING"])])
def test_content_scenarios(mk, modes, verdict, states):
    res = mk({"modes": modes}).ver.run(REQ)
    assert res["status"] == "completed" and res["verdict"] == verdict and [s["state"] for s in res["streams"]] == states


def test_overlay_and_unstable_regions_are_inconclusive(mk):
    r = mk({"overlay": True}).ver.run(REQ)
    assert r["verdict"] == "OBSERVATION_INCONCLUSIVE" and all("OVERLAY_PRESENT" in s["reasons"] for s in r["streams"])
    r2 = mk({"unstable": True}).ver.run(REQ)
    s1 = r2["streams"][0]
    assert s1["state"] == "UNDETERMINED" and "REGION_UNSTABLE" in s1["reasons"] and r2["verdict"] != "PLAYBACK_ADVANCING_ALL"


def test_bad_classifier_regions_are_rejected_and_reported_not_analysed(mk):
    bad = [{"label": "Off", "x": -9, "y": 0, "w": 80, "h": 60}, {"label": "Nan", "x": float("nan"), "y": 0, "w": 80, "h": 60}]
    h = mk({"region_perturb": lambda regs: regs + bad})
    r = h.ver.run(REQ)
    reasons = {x["reason"] for x in r["analysis"]["rejected_regions"]}
    assert {"OUT_OF_BOUNDS", "NON_NUMERIC"} <= reasons and r["verdict"] == "PLAYBACK_ADVANCING_ALL" and len(r["streams"]) == 3
    h2 = mk({"region_perturb": lambda regs: regs + [dict(regs[1], label="Overlap", x=regs[1]["x"] + 20)]})
    r2 = h2.ver.run(REQ)
    assert [x["label"] for x in r2["streams"]] == ["Stream 1", "Stream 3"] and sorted(x["label"] for x in r2["analysis"]["rejected_regions"] if x["reason"] == "OVERLAP") == ["Overlap", "Stream 2"]


def test_observation_that_is_too_short_is_partial_not_a_verdict(mk):
    h = mk(limits=B.BrowserVerifyLimits(max_frames=6, frame_interval_s=1.0))
    r = h.ver.run(REQ)
    assert (r["status"], r["code"]) == ("partial", "OBSERVATION_INCOMPLETE")
    assert all("INSUFFICIENT_OBSERVATION" in s["reasons"] for s in r["streams"]) and r["verdict"] == "OBSERVATION_INCONCLUSIVE"


# =========================================================================== cancellation, deadline, existing windows
def test_cancellation_mid_observation_keeps_partial_evidence_and_still_tears_down(mk):
    h = mk()
    h.page.on_call = lambda n: setattr(h.env.cancel, "flag", True) if n == 7 else None
    r = h.ver.run(REQ)
    assert (r["status"], r["code"]) == ("cancelled", "CANCELLED") and r["timeline"]["frames_included"] >= 1
    assert r["cleanup"]["status"] == "NOT_PERFORMED" and no_close_key_sent(h) and h.env.targets.closed != []
    assert [a["action_id"] for a in r["actions"]] == ACTIONS


def test_the_overall_deadline_is_enforced_and_reports_partial_evidence(mk):
    h = mk(limits=B.BrowserVerifyLimits(total_deadline_s=12.0))
    r = h.ver.run(REQ)
    assert (r["status"], r["code"]) == ("aborted", "DEADLINE_EXCEEDED") and r["timeline"]["total_s"] <= 12.0 + 6.0
    assert r["frames"] and no_close_key_sent(h)


def test_a_browser_that_was_already_open_is_never_accepted_as_this_runs(mk):
    h = mk({"preexisting_chrome": True, "launch_fails": True})
    r = h.ver.run(REQ)
    assert r["code"] == "NEW_WINDOW_NOT_SEEN" and r["streams"] == [] and no_close_key_sent(h) and len(h.sim.windows) == 1


def test_an_existing_browser_window_is_never_closed_by_keys(mk):
    h = mk({"preexisting_chrome": True})
    r = h.ver.run(REQ)
    assert r["status"] == "completed" and no_close_key_sent(h) and {w["id"] for w in h.sim.windows} == {"pre1", "w-nrdp-bv-a1b2c3d4"}


# ================================================================ ownership: evaluator logic against the REQUIRED contract
class Cap(V.OraclePageClassifier):
    def usage_counters(self):
        return {"calls": self.calls}


def test_model_usage_is_reported_only_when_measured(mk):
    r = mk(page_cls=Cap).ver.run(REQ)
    assert r["model_usage"]["status"] == "MEASURED" and r["model_usage"]["counters"]["page_classifier"]["calls"] >= 6


def test_contract_double_proven_ownership_closes_by_id_only_and_verifies(mk):
    """CONTRACT DOUBLE: proves the evaluator, NOT a production capability."""
    h = mk({"preexisting_chrome": True}, port=lambda sim: V.ContractPortDouble(sim))
    r = h.ver.run(REQ)
    cl = r["cleanup"]
    assert cl["status"] == "CLOSED_VERIFIED" and cl["ownership"]["level"] == "PROVEN"
    assert h.sess.ownership_port().close_calls == ["w-nrdp-bv-a1b2c3d4"] and no_close_key_sent(h)
    assert [w["id"] for w in h.sim.windows] == ["pre1"]            # the user's own Chrome window was not touched


@pytest.mark.parametrize("kw,reason", [({"duplicate": True}, "MULTIPLE_WINDOWS_WITH_RUN_PROFILE"), ({"rect_shift": 400}, "INVENTORY_DISAGREES_WITH_SCREEN"),
                                       ({"list_raises": True}, "INVENTORY_FAILED")])
def test_contract_double_that_does_not_prove_ownership_closes_nothing(mk, kw, reason):
    h = mk(port=lambda sim: V.ContractPortDouble(sim, **kw))
    r = h.ver.run(REQ)
    assert r["cleanup"]["status"] == "NOT_PERFORMED" and reason in r["cleanup"]["ownership"]["reasons"]
    assert h.sess.ownership_port().close_calls == [] and no_close_key_sent(h)


def test_a_close_that_cannot_be_verified_is_reported_once_with_no_retry_or_force(mk):
    h = mk(port=lambda sim: V.ContractPortDouble(sim, close_works=False))
    r = h.ver.run(REQ)
    assert r["cleanup"]["status"] == "CLOSE_FAILED" and len(h.sess.ownership_port().close_calls) == 1 and no_close_key_sent(h)


def test_assess_ownership_units():
    A = B.assess_ownership
    assert A(None, "a1b2c3d4", {"found": True}).missing == list(B.REQUIRED_PORT_METHODS)

    class Half:
        def list_windows(self): return []
    assert A(Half(), "a1b2c3d4", None).reasons == ["PORT_INCOMPLETE"]

    class P(Half):
        def foreground_window_id(self): return None
        def close_window(self, i): return True
        wins = []
        def list_windows(self): return self.wins
    p = P()
    assert A(p, "a1b2c3d4", None).reasons == ["NO_VISIBLE_WINDOW_WITH_RUN_PROFILE"]
    ok = {"id": "x", "pid": 1, "profile": "nrdp-bv-a1b2c3d4", "top_level": True, "visible": True, "rect": [10, 10, 500, 400]}
    vis = {"found": True, "expected": [7, 7, 333, 267], "tolerance_px": 38.0, "scale": 2 / 3}
    for bad, reason in (({**ok, "visible": False}, "NO_VISIBLE_WINDOW_WITH_RUN_PROFILE"), ({**ok, "id": ""}, "INVENTORY_ENTRY_MALFORMED"),
                        ({**ok, "rect": [1, 2, 3]}, "INVENTORY_ENTRY_MALFORMED"), ({**ok, "pid": "7"}, "INVENTORY_ENTRY_MALFORMED")):
        p.wins = [bad]
        assert A(p, "a1b2c3d4", vis).reasons == [reason]
    p.wins = [ok]
    assert A(p, "a1b2c3d4", None).reasons == ["WINDOW_NOT_SEEN_ON_SCREEN"]
    assert A(p, "a1b2c3d4", {**vis, "found": False}).reasons == ["WINDOW_NOT_SEEN_ON_SCREEN"]
    assert A(p, "a1b2c3d4", {k: v for k, v in vis.items() if k != "scale"}).reasons == ["SCREEN_SCALE_UNKNOWN"]
    assert A(p, "a1b2c3d4", vis).level == "PROVEN"
    assert A(p, "ffffffff", vis).level == "UNPROVEN"                  # a window from a different run's profile never counts
