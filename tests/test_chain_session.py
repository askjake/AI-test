"""run_chain_session: re-checking the final desktop around steps, mode honesty, notes, report (Reviewer C5/R2/C10)."""
from types import SimpleNamespace as NS

from orchestrator import chain_runtime as cr


class Controller:
    def __init__(self, ok=True):
        self.ok = ok
        self.torn = 0
        self._notes = ["No Windows session was signed out by this run."]

    def establish(self, chain):
        hop = NS(order=1, host="10.70.115.36", user="u1", status=NS(value="confirmed"), detail="")
        hop2 = NS(order=2, host="172.20.33.215", user="u2", status=NS(value="confirmed"), detail="")
        return NS(ok=self.ok, state=NS(hops=[hop, hop2]), evidence=[], failed_hop=None if self.ok else 2,
                  code=None if self.ok else "IDENTITY_UNCONFIRMED", message="")

    def active_desktop(self):
        return 2

    def teardown(self):
        self.torn += 1
        self._notes.append("Teardown: the first Remote Desktop window opened by this run was closed.")

    def notes(self):
        return list(self._notes)


STEPS = [
    {"order": 1, "title": "elevation", "kind": "procedure-step", "mutating": False, "read_only_ok": True},
    {"order": 2, "title": "stop", "kind": "procedure-step", "mutating": True, "read_only_ok": False},
    {"order": 3, "title": "swap wires", "kind": "operator-checkpoint", "mutating": True, "read_only_ok": False},
    {"order": 4, "title": "start", "kind": "procedure-step", "mutating": True, "read_only_ok": False},
]
PROC = {"steps": STEPS, "required_checkpoints": [3], "final_hop": 2}
CHAIN = [NS(order=1, host="a", user="u1"), NS(order=2, host="b", user="u2")]


class Gate:
    records = []

    def request(self, step):
        return NS(note="ok")

    def unacked_required(self, required):
        return []


def run(mode="full_run", revalidate_script=None, drive=None, **kw):
    ctl = Controller()
    driven, checks = [], []
    script = list(revalidate_script or [])

    def revalidate():
        checks.append(1)
        return script.pop(0) if script else (True, None, "")

    def drive_step(step, preamble):
        driven.append(step["order"])
        return (drive or (lambda s: {"status": "passed", "summary": "done"}))(step)

    out = cr.run_chain_session(controller=ctl, chain=CHAIN, procedure=PROC, mode=mode, drive_step=drive_step,
                               gate=Gate(), revalidate=revalidate, **kw)
    return out, ctl, driven, checks


def test_final_desktop_is_rechecked_before_every_step_and_after_every_mutating_step():
    out, ctl, driven, checks = run()
    assert out.status == "passed" and driven == [1, 2, 4]
    # steps 1, 2, 4 -> a check before each (3) + after each mutating one (2 and 4) = 5; checkpoint 3 needs none
    assert len(checks) == 5


def test_dropped_inner_session_before_a_step_sends_no_input_for_it():
    ok = (True, None, "")
    lost = (False, "IDENTITY_HOST_MISMATCH", "Hop 2: the computer shown on this desktop is not 172.20.33.215.")
    out, ctl, driven, checks = run(revalidate_script=[ok, ok, ok, lost])    # before1, before2, after2, before4 -> lost
    assert driven == [1, 2]                               # step 4 (Start-Service) never reached hop 1's desktop
    assert out.status == "failed" and out.error["code"] == "ACTIVE_DESKTOP_CHANGED"
    assert out.steps[-1]["status"] == "failed" and "no input was sent" in out.steps[-1]["summary"]
    assert ctl.torn == 1


def test_mutating_step_whose_desktop_cannot_be_reconfirmed_afterwards_is_reported_failed():
    ok = (True, None, "")
    lost = (False, "IDENTITY_HOST_MISMATCH", "wrong computer")
    out, ctl, driven, checks = run(revalidate_script=[ok, ok, lost])          # before1, before2, after2 -> lost
    assert driven == [1, 2] and out.status == "failed"
    assert out.steps[-1]["order"] == 2 and out.steps[-1]["status"] == "failed"
    assert out.error["code"] == "ACTIVE_DESKTOP_CHANGED" and "after step 2" in out.error["message"]


def test_cancel_during_revalidation_is_incomplete_not_an_error():
    out, ctl, driven, checks = run(revalidate_script=[(False, "CANCELLED", "Cancelled by the operator.")])
    assert out.status == "incomplete" and out.error is None and driven == []


def test_guard_violation_error_code_from_a_step_reaches_the_outcome():
    out, ctl, driven, checks = run(drive=lambda s: {"status": "errored", "summary": "AUTH_PROMPT_DURING_STEP: x",
                                                    "error_code": "AUTH_PROMPT_DURING_STEP"})
    assert out.status == "errored" and out.error["code"] == "AUTH_PROMPT_DURING_STEP"


def test_connection_test_never_revalidates_or_drives_and_flags_the_downgrade():
    out, ctl, driven, checks = run(mode="connection_test", requested_mode="full_run",
                                   downgrade_reason="run request missing or unreadable")
    assert out.status == "passed" and driven == [] and checks == []
    assert out.downgraded and out.requested_mode == "full_run" and out.mode == "connection_test"
    assert out.downgrade_reason == "run request missing or unreadable"
    html = cr.render_chain_section_html(out.as_dict())
    assert "Requested mode: full_run" in html and "Effective mode: connection_test" in html
    assert "NOT a completed operating procedure" in html


def test_honest_run_is_not_flagged_as_downgraded():
    out, *_ = run(mode="full_run", requested_mode="full_run")
    assert not out.downgraded and "NOT a completed" not in cr.render_chain_section_html(out.as_dict())


def test_controller_notes_including_teardown_reach_the_outcome_and_the_report():
    out, ctl, driven, checks = run(mode="connection_test")
    assert any("signed out" in n for n in out.notes) and any("Teardown" in n for n in out.notes)
    html = cr.render_chain_section_html(out.as_dict())
    assert "Session notes" in html and "Teardown" in html


def test_failed_chain_skips_every_step_and_still_carries_notes():
    ctl = Controller(ok=False)
    out = cr.run_chain_session(controller=ctl, chain=CHAIN, procedure=PROC, mode="full_run",
                               drive_step=lambda s, p: {"status": "passed"}, gate=Gate(),
                               revalidate=lambda: (True, None, ""))
    assert out.status == "errored" or out.error["code"] == "IDENTITY_UNCONFIRMED"
    assert all(s["status"] == "skipped" for s in out.skipped) and not out.steps
    assert out.notes and ctl.torn == 1
