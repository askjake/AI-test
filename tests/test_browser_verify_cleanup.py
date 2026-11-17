"""CP42-A: leave-open cleanup contract for browser_verify.  Stateful fakes expose ONLY screenshot / key / type (no window inventory, no close
channel).  These tests prove the local contract; they say nothing about real Windows / Chrome behaviour."""
import dataclasses
import json

import pytest

import bv_sim as V
from bv_sim import PROJECT, REQ, build
from orchestrator import browser_verify as B

CLOSE_KEYS = {"alt+f4", "ctrl+w", "ctrl+shift+w"}
NOPE = dataclasses.replace


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


def no_close(h):
    return not (CLOSE_KEYS & set(h.sim.keys)) and h.sim.closed_by_key == []


def test_production_shaped_session_offers_no_close_or_inventory_capability(mk):
    h = mk()
    assert h.sess.ownership_port() is None
    for name in ("close_window", "list_windows", "foreground_window_id", "kill", "terminate", "delete_profile"):
        assert not hasattr(h.sess, name) and not hasattr(h.ver, name)


@pytest.mark.parametrize("ack", ["", "LEAVE-OPEN", "leave-open " + PROJECT, "LEAVE-OPEN other-project", PROJECT, "BROWSER-VERIFY " + PROJECT])
def test_missing_or_wrong_leave_open_ack_is_refused_before_any_input(mk, ack):
    h = mk()
    n = len(h.env.log)
    r = h.ver.run(NOPE(REQ, leave_open_ack=ack))
    assert r["status"] == "refused" and r["code"] == "LEAVE_OPEN_ACK_MISSING"
    assert len(h.env.log) == n and r["actions"] == [] and r["cleanup"]["status"] == "NOT_LAUNCHED" and r["launch"]["state"] == "NOT_ATTEMPTED"


def test_ack_does_not_bypass_earlier_gates(mk):
    h = mk(policy=B.DEFAULT_POLICY)
    assert h.ver.run(REQ)["code"] == "CAPABILITY_DISABLED"
    h2 = mk()
    assert h2.ver.run(NOPE(REQ, confirm_phrase=""))["code"] == "CONFIRMATION_MISSING"      # confirmation is checked before the ack


def test_leave_open_contract_on_a_completed_run(mk):
    h = mk()
    r = h.ver.run(REQ)
    cl = r["cleanup"]
    assert (r["status"], r["code"]) == ("completed", r["verdict"]) and r["verdict"] == "PLAYBACK_ADVANCING_ALL"
    assert cl["status"] == "NOT_PERFORMED" and cl["reason"] == B.CLEANUP_REASON_UNPROVEN and cl["route"] == "LEAVE_OPEN"
    assert cl["fulfilment"] == "DELIBERATE_PARTIAL_NOT_AUTOMATIC_CLEANUP" and cl["close_input_sent"] is False
    assert "CLOSED" not in json.dumps(cl).replace("CLOSE_FAILED", "")
    assert no_close(h) and h.env.targets.closed != []                 # session torn down; target window untouched
    kinds = {a["kind"]: a for a in cl["expected_artifacts"]}
    assert set(kinds) == {"browser_window", "profile_directory", "run_history_entry"}
    assert kinds["profile_directory"]["location"] == "%TEMP%\\nrdp-bv-a1b2c3d4" and kinds["profile_directory"]["state"] == "POSSIBLE_NOT_VERIFIED"
    assert kinds["browser_window"]["state"] == "OPEN_OBSERVED" and kinds["browser_window"]["url"] == B.ALLOWED_URL
    assert kinds["run_history_entry"]["state"] == "POSSIBLE_NOT_VERIFIED"
    g = " ".join(cl["operator_guidance"])
    assert "optional" in g and "identify" in g and "still using it" in g and "nrdp-bv-a1b2c3d4" in g and "did not clean up" in g
    assert "does not clear Run history" in g and "clear all" not in g.lower() and "delete the profile" not in g.lower()
    assert not any(w in g.lower() for w in ("stop-process", "taskkill", "-force", "kill "))
    # only the four launch actions were ever sent: no cleanup input of any kind
    assert [a["action_id"] for a in r["actions"]] == ["bv.open_run_dialog", "bv.select_field", "bv.type_launch", "bv.submit_launch"]


def test_playback_outcome_is_reported_separately_from_cleanup(mk):
    good = mk().ver.run(REQ)
    bad = mk({"modes": ["frozen"] * 3}).ver.run(REQ)
    for r, v in ((good, "PLAYBACK_ADVANCING_ALL"), (bad, "PLAYBACK_NOT_ADVANCING")):
        assert r["playback"] == {"status": "completed", "code": v, "verdict": v, "independent_of_cleanup": True}
        assert r["cleanup"]["status"] == "NOT_PERFORMED"            # same cleanup outcome whatever the playback outcome


def test_cancellation_keeps_partial_playback_and_reports_cleanup_not_performed(mk):
    h = mk()
    h.page.on_call = lambda n: setattr(h.env.cancel, "flag", True) if n == 7 else None
    r = h.ver.run(REQ)
    assert r["playback"]["status"] == "cancelled" and r["playback"]["code"] == "CANCELLED"
    assert r["cleanup"]["status"] == "NOT_PERFORMED" and r["cleanup"]["close_input_sent"] is False and no_close(h)
    assert len(r["cleanup"]["expected_artifacts"]) == 3 and r["cleanup"]["operator_guidance"]


def test_not_launched_runs_have_nothing_to_clean_and_no_artifacts(mk):
    r = mk(establish=False).ver.run(REQ)                              # identity never confirmed -> no launch
    assert r["cleanup"]["status"] == "NOT_LAUNCHED" and "expected_artifacts" not in r["cleanup"] and r["playback"]["verdict"] == "NO_STREAMS"


class ListOnlyPort:
    """Partial adapter: can enumerate but cannot close. Must be treated as no capability."""
    def __init__(self, sim):
        self.calls = []

    def list_windows(self):
        self.calls.append("list")
        return []


def test_partial_adapter_without_close_is_not_used_and_cleanup_is_not_performed(mk):
    h = mk(port=lambda sim: ListOnlyPort(sim))
    r = h.ver.run(NOPE(REQ, leave_open_ack=""))                         # a port object is present, so ack is not demanded by the route check
    assert r["cleanup"]["status"] == "NOT_PERFORMED" and "PORT_INCOMPLETE" in r["cleanup"]["ownership"]["reasons"]
    assert h.sess.ownership_port().calls == [] and no_close(h)


def test_contract_double_still_closes_by_id_only_and_needs_no_ack(mk):
    h = mk(port=lambda sim: V.ContractPortDouble(sim))
    r = h.ver.run(NOPE(REQ, leave_open_ack=""))
    assert r["cleanup"]["status"] == "CLOSED_VERIFIED" and h.sess.ownership_port().close_calls == ["w-nrdp-bv-a1b2c3d4"] and no_close(h)
