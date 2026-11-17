"""NRDP-1 S2b: procedure_runs tests (mocked launcher/cancel; temp reports dir)."""
from __future__ import annotations

import json
import os
import stat
from types import SimpleNamespace as NS

import pytest

try:
    from dashboard import procedure_runs as pr
except ImportError:  # pragma: no cover
    from src.dashboard import procedure_runs as pr

PW = "Fict!onal-Run-Pw"
PROJ = "foo-service-maintenance-01234567"
RID = "trig_20261027T120000_deadbeef"


@pytest.fixture
def env(tmp_path):
    calls = {"launch": [], "cancel": []}
    seen_before = []

    def launch(project):
        seen_before.append(os.path.isfile(os.path.join(tmp_path, project, ".nrdp-runs", ".pending", "run_request.json")))
        calls["launch"].append(project)
        return RID

    pr.configure(reports_root=lambda: str(tmp_path), launch=launch,
                 cancel=lambda p: calls["cancel"].append(p) or {"status": "cancelled"})
    yield NS(root=tmp_path, calls=calls, seen_before=seen_before)
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel)


def _rd(env):
    return os.path.join(env.root, PROJ, ".nrdp-runs", RID)


def test_mode_validation(env):
    with pytest.raises(pr.RunError) as e:
        pr.start_run(NS(id="x"), PROJ, "everything", None)
    assert e.value.status_code == 400 and env.calls["launch"] == []


def test_full_run_is_refused_before_anything_is_written_or_launched(env):
    """Connection-only qualification: the CORRECT project name cannot bypass the refusal."""
    for phrase in (None, "", PROJ.upper(), PROJ):          # PROJ is the exact confirmation phrase
        with pytest.raises(pr.RunError) as e:
            pr.start_run(NS(id="x"), PROJ, "full_run", phrase)
        assert e.value.status_code == 409
        assert "connection tests only" in str(e.value.message)
    # FAIL BEFORE MUTATION: no runner was launched and no request file exists anywhere.
    assert env.calls["launch"] == []
    for base, _dirs, files in os.walk(str(env.root)):
        assert "run_request.json" not in files, base


def test_connection_test_request_written_before_launch(env):
    assert pr.start_run(NS(id="x"), PROJ, "connection_test", None)["run_id"] == RID
    assert env.seen_before == [True]
    p = os.path.join(_rd(env), "control", "run_request.json")
    req = json.load(open(p))
    assert req["mode"] == "connection_test" and req["chain"] is True and req["project"] == PROJ
    assert req["steps_allowed"] is False
    if os.name == "posix":   # mode bits are not meaningful on Windows; the 3090 gate runs this
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644


def test_read_only_check_is_refused_too(env):
    """read_only_check is NOT qualified: a read-only step still types and clicks, so it can act
    on the wrong desktop.  It must be refused exactly like full_run."""
    with pytest.raises(pr.RunError) as e:
        pr.start_run(NS(id="x"), PROJ, "read_only_check", None)
    assert e.value.status_code == 409 and "connection tests only" in str(e.value.message)
    assert env.calls["launch"] == []


def test_capability_reports_connection_only(env):
    cap = pr.capability()
    assert cap["connection_only"] is True
    assert cap["allowed_modes"] == ["connection_test"]
    assert sorted(cap["disabled_modes"]) == ["browser_verify", "full_run", "read_only_check"]      # CP43: browser_verify is served as disabled by default
    assert cap["browser_verify"]["available"] is False
    assert "connection tests only" in cap["reason"]
    assert pr.allowed_modes() == ("connection_test",)


def test_path_traversal_rejected(env):
    for p, r in (("../x", RID), (PROJ, "../../etc"), (PROJ, "trig_../a"), ("a/b", RID)):
        with pytest.raises(pr.RunError):
            pr.get_run(p, r)
        with pytest.raises(pr.RunError):
            pr.ack_checkpoint(p, r, "cp1", None)
    with pytest.raises(pr.RunError):
        pr.start_run(NS(id="x"), "../evil", "connection_test", None)


def _checkpoint(env, cid="cp-3"):
    # the runner (another uid) writes its request into the run folder, not into control/
    os.makedirs(os.path.join(_rd(env), "control"), exist_ok=True)
    json.dump({"id": cid, "step_order": 3, "title": "Swap wires", "instructions": "do it",
               "requested_at": "t"}, open(os.path.join(_rd(env), "checkpoint.json"), "w"))


def test_ack_validation(env):
    os.makedirs(os.path.join(_rd(env), "control"))
    with pytest.raises(pr.RunError) as e:
        pr.ack_checkpoint(PROJ, RID, "cp-3", None)
    assert e.value.status_code == 409
    _checkpoint(env)
    with pytest.raises(pr.RunError) as e:
        pr.ack_checkpoint(PROJ, RID, "cp-2", None)
    assert e.value.status_code == 409
    with pytest.raises(pr.RunError):
        pr.ack_checkpoint(PROJ, RID, "cp-3", "x" * 501)
    out = pr.ack_checkpoint(PROJ, RID, "cp-3", "done")
    assert out["acknowledged_by"] == "shared-operator" and out["id"] == "cp-3"
    p = os.path.join(_rd(env), "control", "checkpoint_ack.json")
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644
    with pytest.raises(pr.RunError) as e:  # already acked -> none pending
        pr.ack_checkpoint(PROJ, RID, "cp-3", None)
    assert e.value.status_code == 409


def test_get_run_never_contains_secrets(env):
    _checkpoint(env)
    rd = _rd(env)
    json.dump({"state": "running", "password": PW, "note": f"password={PW}"}, open(os.path.join(rd, "status.json"), "w"))
    json.dump({"phase": "hop2", "hops": [{"order": 2, "detail": f"token: {PW}", "password_file": "ref.pw"}]},
              open(os.path.join(rd, "chain_progress.json"), "w"))
    os.makedirs(os.path.join(rd, "evidence"))
    open(os.path.join(rd, "evidence", "hop1.png"), "wb").write(b"\x89PNG")
    out = pr.get_run(PROJ, RID)
    assert PW not in json.dumps(out)
    assert out["checkpoint_pending"] is True and out["state"] == "running"
    assert out["status"] == "running" and isinstance(out["status"], str)  # the UI compares a plain string
    assert out["chain_progress"]["hops"][0]["password_file"] == "ref.pw"
    assert {"name": "hop1.png", "url": f"/reports/{PROJ}/.nrdp-runs/{RID}/evidence/hop1.png"} in out["evidence"]


def test_cancel_uses_existing_mechanism(env):
    os.makedirs(_rd(env))
    out = pr.cancel_run(PROJ, RID)
    assert env.calls["cancel"] == [PROJ] and out["cancelled"] is True
    with pytest.raises(pr.RunError) as e:
        pr.cancel_run(PROJ, "trig_missing")
    assert e.value.status_code == 404


# ----------------------------------------------------------------------------- NRDP-1 repairs


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_control_folder_and_run_folder_are_dashboard_owned_0755_not_shared(env):
    pr.start_run(NS(id="x"), PROJ, "connection_test", None)
    assert stat.S_IMODE(os.stat(os.path.join(_rd(env), "control")).st_mode) == 0o755   # runner reads, nobody else writes
    assert stat.S_IMODE(os.stat(_rd(env)).st_mode) == 0o755                             # CP45-G: no sticky/shared folder; the entrypoint hands the run folder to the runner uid
    p = os.path.join(_rd(env), "control", "run_request.json")
    assert os.stat(p).st_uid == os.getuid()                                              # dashboard-owned message


def test_no_sticky_or_shared_run_folder_exists_in_the_module():
    """CP45-I: the legacy 1777 exception is gone (the watcher backend that needed it is refused)."""
    import re
    code = "\n".join(l for l in open(pr.__file__).read().splitlines() if not l.lstrip().startswith("#"))
    assert not hasattr(pr, "_legacy_shared_runs") and not re.search(r"chmod\([^)]*0o1?777", code)


def test_runner_checkpoint_in_run_folder_is_pending_until_acked(env):
    _checkpoint(env)
    out = pr.get_run(PROJ, RID)
    assert out["checkpoint_pending"] is True and out["checkpoint"]["id"] == "cp-3"
    pr.ack_checkpoint(PROJ, RID, "cp-3", "done")
    again = pr.get_run(PROJ, RID)
    assert again["checkpoint_pending"] is False        # the UI must stop showing the prompt after an ack
    assert not os.path.exists(os.path.join(_rd(env), "control", "checkpoint.json"))


def test_get_run_has_the_exact_shape_the_ui_reads(env):
    os.makedirs(_rd(env), exist_ok=True)
    out = pr.get_run(PROJ, RID)
    for key in ("run_id", "project", "state", "status", "mode", "requested_mode", "effective_mode", "downgraded",
                "downgrade_reason", "chain_progress", "checkpoint", "checkpoint_pending", "evidence", "notes"):
        assert key in out, key
    assert isinstance(out["status"], str) and out["status"] == out["state"] == "pending"


def test_requested_and_effective_mode_are_both_reported(env):
    rd = _rd(env)
    os.makedirs(os.path.join(rd, "control"))
    json.dump({"mode": "full_run", "chain": True, "confirm_recorded": True}, open(os.path.join(rd, "control", "run_request.json"), "w"))
    json.dump({"state": "complete", "requested_mode": "full_run", "effective_mode": "connection_test", "mode": "connection_test",
               "downgraded": True, "downgrade_reason": "run request missing or unreadable"}, open(os.path.join(rd, "status.json"), "w"))
    out = pr.get_run(PROJ, RID)
    assert out["requested_mode"] == "full_run" and out["effective_mode"] == "connection_test" and out["downgraded"] is True
    assert "missing" in out["downgrade_reason"]


def _confirmed_cancel_record(root, project, rid):
    import os as _os, json as _json
    from datetime import datetime as _dt, timezone as _tz
    d = _os.path.join(root, ".ctrl", project); _os.makedirs(d, exist_ok=True)
    _json.dump({"schema": 1, "project": project, "run_id": rid, "state": "cancelled", "pre_state": "running", "runner_started_at": None,
                "teardown": {"confirmed": True, "confirmed_at": _dt.now(_tz.utc).isoformat()}}, open(_os.path.join(d, "cancel_%s.json" % rid), "w"))


def test_cancel_request_finalizes_a_run_whose_runner_was_killed(env):
    from datetime import datetime, timedelta, timezone
    now = {"t": datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)}
    pr.configure(now=lambda: now["t"])
    try:
        rd = _rd(env)
        os.makedirs(os.path.join(rd, "control"))
        json.dump({"state": "running"}, open(os.path.join(rd, "status.json"), "w"))
        _checkpoint(env)
        pr.cancel_run(PROJ, RID)
        assert pr.get_run(PROJ, RID)["state"] == "running"            # grace period: the runner may still finish its own teardown
        now["t"] += timedelta(seconds=pr.CANCEL_GRACE_SECONDS + 1)
        assert pr.get_run(PROJ, RID)["state"] == "running"            # CP45-D: elapsed time alone is NOT a teardown confirmation
        _confirmed_cancel_record(os.path.dirname(os.path.dirname(os.path.dirname(rd))), PROJ, RID)
        out = pr.get_run(PROJ, RID)
        assert out["state"] == "cancelled" and out["status"] == "cancelled" and out["checkpoint_pending"] is False
        assert out["state_source"] == "cancel_record"
        # a runner that DID finish keeps its own terminal status
        json.dump({"state": "failed"}, open(os.path.join(rd, "status.json"), "w"))
        assert pr.get_run(PROJ, RID)["state"] == "failed"
    finally:
        pr.configure(now=lambda: datetime.now(timezone.utc))
