"""Tests for orchestrator.chain_runtime (NRDP-1 S1b-2). Fakes only; no display/network."""
import json
import os
import threading
from types import SimpleNamespace

import pytest

try:
    from orchestrator import chain_runtime as cr
except ImportError:  # pragma: no cover
    from src.orchestrator import chain_runtime as cr


@pytest.fixture(autouse=True)
def posix_view(monkeypatch):
    """On Windows, present files as the dashboard-owned 0644 / 0755 objects they would be on the host.

    The permission LOGIC is exercised for real (and with forged variants) in test_chain_runtime_trust.py;
    on POSIX hosts (the 3090 gate) this fixture is a no-op and the real stat() results are used.
    """
    if os.name == "posix":
        return

    def fake(path):
        real = os.lstat(path)
        return SimpleNamespace(st_mode=real.st_mode & ~0o022, st_nlink=real.st_nlink, st_uid=1000)

    monkeypatch.setattr(cr, "_LSTAT", fake)


def _req(tmp_path, project="p1", tid="trig_1_abcd", body=None):
    d = tmp_path / project / ".nrdp-runs" / tid / "control"
    d.mkdir(parents=True)
    if body is not None:
        (d / "run_request.json").write_text(body if isinstance(body, str) else json.dumps(body))
    return str(tmp_path)


def test_request_missing_is_connection_test(tmp_path, monkeypatch):
    monkeypatch.delenv(cr.TRIGGER_ENV, raising=False)
    assert cr.read_run_request(str(tmp_path), "p1", None).mode == cr.CONNECTION_TEST
    root = _req(tmp_path)
    assert cr.read_run_request(root, "p1", "trig_1_abcd").mode == cr.CONNECTION_TEST


def test_request_invalid_json_and_mode(tmp_path):
    root = _req(tmp_path, body="{not json")
    assert cr.read_run_request(root, "p1", "trig_1_abcd").mode == cr.CONNECTION_TEST
    root2 = _req(tmp_path, project="p2", body={"mode": "rm -rf", "chain": True})
    r2 = cr.read_run_request(root2, "p2", "trig_1_abcd")
    assert r2.refused is True and r2.mode == "refused" and r2.requested_mode == "unrecognized"      # CP44: an unknown mode is REFUSED and carries no runnable mode (was: connection_test)


def test_request_valid_and_full_run_needs_confirm(tmp_path):
    """Connection-only qualification: a VALID operating request is still refused at the runtime.

    The M2 rules below are deliberately still exercised first, each with its own reason, so the
    connection-only gate does not hide them.
    """
    root = _req(tmp_path, body={"mode": "read_only_check", "project": "p1", "chain": True})
    r = cr.read_run_request(root, "p1", "trig_1_abcd")
    assert r.mode == cr.CONNECTION_TEST and r.source == "request"
    assert r.requested_mode == cr.READ_ONLY_CHECK          # the refusal stays visible
    assert "connection-only" in r.reason
    # M2 preserved: an unconfirmed full run still reports its OWN reason, not the policy reason.
    root2 = _req(tmp_path, project="p3", body={"mode": "full_run", "chain": True})
    r2 = cr.read_run_request(root2, "p3", "trig_1_abcd")
    assert r2.mode == cr.CONNECTION_TEST and "without recorded confirmation" in r2.reason
    # A perfectly formed, confirmed, run-id-bound full run reaches the policy gate and is refused.
    root3 = _req(tmp_path, project="p4", body={"mode": "full_run", "chain": True,
                                               "confirm_recorded": True, "run_id": "trig_1_abcd"})
    r3 = cr.read_run_request(root3, "p4", "trig_1_abcd")
    assert r3.mode == cr.CONNECTION_TEST and r3.requested_mode == cr.FULL_RUN
    assert "connection-only" in r3.reason


def test_m2_full_run_must_be_bound_to_its_run_id(tmp_path):
    """An unbound full_run request is downgraded, never honoured."""
    root = _req(tmp_path, project="p5", body={"mode": "full_run", "chain": True,
                                              "confirm_recorded": True})
    r = cr.read_run_request(root, "p5", "trig_1_abcd")
    assert r.mode == cr.CONNECTION_TEST and "not bound to a run id" in r.reason
    assert r.requested_mode == cr.FULL_RUN


def test_m2_a_request_stamped_for_another_run_is_refused(tmp_path):
    """A request cannot be replayed into a different run directory."""
    root = _req(tmp_path, project="p6", body={"mode": "full_run", "chain": True,
                                              "confirm_recorded": True, "run_id": "trig_9_zzzz"})
    r = cr.read_run_request(root, "p6", "trig_1_abcd")
    assert r.mode == cr.CONNECTION_TEST and "another run id" in r.reason


def test_request_env_trigger(tmp_path, monkeypatch):
    root = _req(tmp_path, body={"mode": "read_only_check", "chain": True})
    monkeypatch.setenv(cr.TRIGGER_ENV, "trig_1_abcd")
    # The env trigger still resolves the request; the operating mode is refused by policy.
    r = cr.read_run_request(root, "p1", None)
    assert r.mode == cr.CONNECTION_TEST and r.requested_mode == cr.READ_ONLY_CHECK


def test_request_traversal_rejected(tmp_path):
    for project, tid in [("../x", "t"), ("p1", "../../etc"), ("p1", "a/b"), ("..", "t"), ("p1", "")]:
        r = cr.read_run_request(str(tmp_path), project, tid)
        assert r.mode == cr.CONNECTION_TEST


def test_forged_run_request_is_not_trusted(tmp_path):
    """A group/world-writable or linked request must never upgrade the run beyond connection_test."""
    body = {"mode": "read_only_check", "project": "p1", "chain": True}
    root = _req(tmp_path, body=body)
    path = tmp_path / "p1" / ".nrdp-runs" / "trig_1_abcd" / "control" / "run_request.json"
    trusted = cr.read_run_request(root, "p1", "trig_1_abcd")
    # policy refusal, NOT a trust refusal: the reason must distinguish the two
    assert trusted.mode == cr.CONNECTION_TEST and "not trusted" not in trusted.reason
    if os.name == "posix":
        os.chmod(path, 0o666)                      # anyone could have rewritten it
        r = cr.read_run_request(root, "p1", "trig_1_abcd")
        assert r.mode == cr.CONNECTION_TEST and "not trusted" in r.reason
        os.chmod(path, 0o644)
        link = tmp_path / "p1" / ".nrdp-runs" / "trig_1_abcd" / "control" / "hard.json"
        os.link(path, link)                        # a second link means someone else holds the file
        assert cr.read_run_request(root, "p1", "trig_1_abcd").mode == cr.CONNECTION_TEST
        os.unlink(link)
        other = tmp_path / "elsewhere.json"
        other.write_text(json.dumps(body))
        os.unlink(path)
        os.symlink(other, path)                    # symlink to a file someone else controls
        assert cr.read_run_request(root, "p1", "trig_1_abcd").mode == cr.CONNECTION_TEST


@pytest.mark.skipif(os.name != "posix", reason="needs chmod; the same logic runs everywhere in test_chain_runtime_trust.py")
def test_forged_checkpoint_ack_is_ignored(tmp_path):
    g, c = _gate(tmp_path)
    (tmp_path / "control").mkdir()
    ack = tmp_path / "control" / "checkpoint_ack.json"
    ack.write_text(json.dumps({"id": "cp-3-aaaa0001", "acknowledged_by": "shared-operator", "note": "forged"}))
    if os.name == "posix":
        os.chmod(ack, 0o666)                       # world-writable => untrusted, even with the right id
    assert g.request({"order": 3}) is None and g.records[0]["outcome"] == "timeout"
    assert g.unacked_required([3]) == [3]


STEPS = [
    {"order": 1, "title": "elev", "kind": "procedure-step", "mutating": False, "read_only_ok": True},
    {"order": 2, "title": "stop", "kind": "procedure-step", "mutating": True, "read_only_ok": False},
    {"order": 3, "title": "cable", "kind": "operator-checkpoint", "mutating": False, "read_only_ok": True},
    {"order": 4, "title": "unmarked", "kind": "procedure-step"},
]


def test_select_steps_matrix():
    run, skip = cr.select_steps(STEPS, "connection_test")
    assert run == [] and len(skip) == 4 and all(s["status"] == "skipped" and s["reason"] for s in skip)
    run, skip = cr.select_steps(STEPS, "read_only_check")
    assert [s["order"] for s in run] == [1]
    assert {s["order"] for s in skip} == {2, 3, 4}
    run, skip = cr.select_steps(STEPS, "full_run")
    assert [s["order"] for s in run] == [1, 2, 3, 4] and skip == []
    run, _ = cr.select_steps(STEPS, "bogus")
    assert run == []


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _gate(tmp_path, **kw):
    c = Clock()
    ids = iter(["aaaa0001", "bbbb0002", "cccc0003"])
    g = cr.CheckpointGate(str(tmp_path / "control"), clock=c, sleep=c.sleep, timeout=10, poll=1,
                          new_id=lambda: next(ids), **kw)
    return g, c


def test_gate_writes_and_times_out(tmp_path):
    g, _ = _gate(tmp_path)
    assert g.request({"order": 3, "title": "cable", "instructions": "plug"}) is None
    # the runner cannot write the dashboard-owned control/ folder: its request lands in the run folder
    data = json.loads((tmp_path / "checkpoint.json").read_text())
    assert data["id"] == "cp-3-aaaa0001" and data["step_order"] == 3
    assert not (tmp_path / "control" / "checkpoint.json").exists()
    if os.name == "posix":
        assert (os.stat(tmp_path / "checkpoint.json").st_mode & 0o777) == 0o644
    assert g.records[0]["outcome"] == "timeout" and g.unacked_required([3]) == [3]


def test_gate_ignores_stale_accepts_matching(tmp_path):
    g, c = _gate(tmp_path)
    ack = tmp_path / "control" / "checkpoint_ack.json"
    (tmp_path / "control").mkdir()
    ack.write_text(json.dumps({"id": "cp-3-old", "note": "stale"}))
    orig = c.sleep

    def sleep(s):
        orig(s)
        if c.t >= 3:
            ack.write_text(json.dumps({"id": "cp-3-aaaa0001", "acknowledged_by": "shared-operator", "note": "ok"}))
    g._sleep = sleep
    a = g.request({"order": 3})
    assert a is not None and a.note == "ok" and c.t >= 3
    assert g.unacked_required([3]) == []


def test_gate_cancel(tmp_path):
    ev = threading.Event()
    ev.set()
    g, _ = _gate(tmp_path, cancel_event=ev)
    assert g.request({"order": 1}) is None and g.records[0]["outcome"] == "cancelled"


def test_preamble_safe():
    text = cr.chain_prompt_preamble([{"order": 1, "host": "10.70.115.36", "user": "u1", "password_file": "ref1"},
                                     {"order": 2, "host": "172.20.33.215", "user": "u2"}], 2)
    low = text.lower()
    assert "never type" in low and "hop 2" in low and "linux" in low
    assert "ref1" not in text and "password_file" not in text
    assert "10.70.115.36" in text and "u2" in text


def test_labelled_evidence():
    ev = cr.labelled_evidence([{"path": "a.png"}, "b.png", {"path": "c.png", "hop": 1}], 2)
    assert [e["label"] for e in ev] == ["Hop 2 desktop", "Hop 2 desktop", "Hop 1 desktop"]


class FakeState:
    def __init__(self, hops):
        self.hops = hops


class FakeHop:
    def __init__(self, order, status, detail=""):
        self.order, self.host, self.user, self.status, self.detail = order, f"h{order}", f"u{order}", status, detail


class FakeResult:
    def __init__(self, ok, failed_hop=None, code=None, message=""):
        self.ok, self.failed_hop, self.code, self.message = ok, failed_hop, code, message
        self.state = FakeState([FakeHop(1, "confirmed"), FakeHop(2, "confirmed" if ok else "failed")])
        self.evidence = []


class FakeController:
    def __init__(self, result=None, raise_exc=None):
        self.result, self.raise_exc, self.torn = result, raise_exc, 0

    def establish(self, chain):
        if self.raise_exc:
            raise self.raise_exc
        return self.result

    def teardown(self):
        self.torn += 1

    def active_desktop(self):
        return 2


PROC = {"final_hop": 2, "steps": STEPS, "required_checkpoints": [3]}


def _drive_recorder():
    calls = []

    def drive(step, preamble):
        calls.append((step["order"], preamble))
        return {"status": "passed", "summary": "ok", "evidence": [{"path": "s.png"}]}
    return drive, calls


def test_connection_test_never_invokes_agent():
    ctl = FakeController(FakeResult(True))
    drive, calls = _drive_recorder()
    o = cr.run_chain_session(controller=ctl, chain=[], procedure=PROC, mode="connection_test",
                             drive_step=drive, gate=None)
    assert o.status == "passed" and calls == [] and not o.agent_invoked and ctl.torn == 1
    assert len(o.skipped) == 4


def test_failed_hop_runs_nothing():
    ctl = FakeController(FakeResult(False, 2, "IDENTITY_UNCONFIRMED", "hop 2 not confirmed"))
    drive, calls = _drive_recorder()
    o = cr.run_chain_session(controller=ctl, chain=[], procedure=PROC, mode="full_run",
                             drive_step=drive, gate=None)
    assert o.status == "errored" and calls == [] and o.error["hop"] == 2
    assert o.error["code"] == "IDENTITY_UNCONFIRMED" and ctl.torn == 1


def test_unacked_checkpoint_not_passed(tmp_path):
    ctl = FakeController(FakeResult(True))
    drive, calls = _drive_recorder()
    g, _ = _gate(tmp_path)
    o = cr.run_chain_session(controller=ctl, chain=[], procedure=PROC, mode="full_run",
                             drive_step=drive, gate=g)
    assert o.status == "incomplete" and [c[0] for c in calls] == [1, 2]
    assert cr.guard_report_result(o, [3], g) != "passed"
    assert "never type" in calls[0][1].lower()


def test_guard_overrides_passed_when_required_unacked(tmp_path):
    g, _ = _gate(tmp_path)
    o = cr.ChainRunOutcome(status="passed", mode="full_run")
    assert cr.guard_report_result(o, [3], g) == "incomplete"


def test_read_only_runs_only_safe_steps():
    ctl = FakeController(FakeResult(True))
    drive, calls = _drive_recorder()
    o = cr.run_chain_session(controller=ctl, chain=[], procedure=PROC, mode="read_only_check",
                             drive_step=drive, gate=None)
    assert [c[0] for c in calls] == [1] and o.status == "passed"
    assert o.evidence[-1]["label"] == "Hop 2 desktop"


def test_teardown_on_exception():
    ctl = FakeController(raise_exc=RuntimeError("boom"))
    drive, calls = _drive_recorder()
    o = cr.run_chain_session(controller=ctl, chain=[], procedure=PROC, mode="full_run",
                             drive_step=drive, gate=None)
    assert ctl.torn == 1 and o.status == "errored" and calls == []


def test_read_secret_traversal(tmp_path):
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "ref1").write_text("fictional-Pw!\n")
    rs = cr.make_read_secret(str(tmp_path / "s"))
    assert rs("ref1") == "fictional-Pw!"
    import pytest
    with pytest.raises(RuntimeError) as ei:
        rs("../s/ref1x")
    assert "fictional" not in str(ei.value)


def test_report_section_escaped():
    h = cr.render_chain_section_html({"mode": "full_run", "status": "errored",
                                      "hops": [{"order": 1, "host": "<b>x", "user": "u", "status": "failed", "detail": "&"}],
                                      "error": {"hop": 1, "code": "C", "message": "<script>"},
                                      "skipped": [{"order": 2, "title": "t", "reason": "r"}],
                                      "checkpoints": [], "evidence": [{"path": "a.png", "label": "Hop 1 desktop"}]})
    assert "<script>" not in h and "&lt;b&gt;x" in h and "Hop 1 desktop" in h and "SKIPPED" in h


def test_cancel_watcher_sets_event_only_for_a_trusted_request(tmp_path):
    ctl = tmp_path / "control"
    ctl.mkdir()
    ev = threading.Event()
    ticks = []

    def sleep(_s):
        ticks.append(1)
        if len(ticks) == 2:
            (ctl / "cancel_request.json").write_text("{}")
            if os.name == "posix":
                os.chmod(ctl / "cancel_request.json", 0o666)   # untrusted at first
        if len(ticks) == 4 and os.name == "posix":
            os.chmod(ctl / "cancel_request.json", 0o644)       # now trusted
        if len(ticks) > 50:
            raise RuntimeError("watcher did not stop")

    stop = cr.start_cancel_watcher(str(ctl), ev, poll=0.0, sleep=sleep)
    for _ in range(2000):
        if ev.is_set():
            break
        threading.Event().wait(0.005)
    stop()
    assert ev.is_set()
    if os.name == "posix":
        assert len(ticks) >= 4      # it ignored the untrusted file until it became trusted


def test_m2_a_request_for_another_project_is_refused(tmp_path):
    """procedure_runs.start_run stamps ``project``; a request naming another one is refused."""
    root = _req(tmp_path, project="p7", body={"mode": "full_run", "chain": True,
                                              "confirm_recorded": True, "run_id": "trig_1_abcd",
                                              "project": "someone-elses-project"})
    r = cr.read_run_request(root, "p7", "trig_1_abcd")
    assert r.mode == cr.CONNECTION_TEST and "another project" in r.reason
    assert r.requested_mode == ""          # never advertised as a requested full run


@pytest.mark.parametrize("project,body", [
    ("q1", {"mode": "full_run", "chain": True, "confirm_recorded": True}),                      # unbound run id
    ("q2", {"mode": "full_run", "chain": True, "confirm_recorded": True, "run_id": "trig_9_z"}), # foreign run id
    ("q3", {"mode": "full_run", "chain": True, "confirm_recorded": True, "run_id": "trig_1_abcd",
            "project": "elsewhere"}),                                                            # foreign project
    ("q4", {"mode": "full_run", "chain": True, "run_id": "trig_1_abcd"}),                        # unconfirmed
    ("q5", {"mode": "rm -rf", "chain": True, "run_id": "trig_1_abcd"}),                          # unknown mode
    ("q6", {"mode": "full_run", "chain": False, "run_id": "trig_1_abcd"}),                       # not a chain request
])
def test_m2_invalid_control_data_selects_no_operating_steps(tmp_path, project, body):
    """Every refusal path must collapse to connection_test AND run zero operating steps."""
    root = _req(tmp_path, project=project, body=body)
    r = cr.read_run_request(root, project, "trig_1_abcd")
    if body.get("mode") == "rm -rf":      # CP44: unknown mode -> refused outright (mode "refused"); every OTHER path still collapses to connection_test
        assert r.refused is True and r.mode == "refused", r.reason
    else:
        assert r.mode == cr.CONNECTION_TEST, r.reason
    to_run, skipped = cr.select_steps(STEPS, r.mode)
    assert to_run == []
    assert len(skipped) == len(STEPS) and all(s["status"] == "skipped" for s in skipped)
