"""CP45-D option A: dashboard-owned cancellation records, one effective-state rule for every dashboard reader, and the failure/race/duplicate/stale cases."""
from __future__ import annotations

import contextlib
import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from dashboard import run_state as rs
from dashboard.run_control import RunControlError
from tests.test_run_cancel import _headers, _make_app, _write_active_run

TRIG = "trig_20260821T120000_deadbeef"
STARTED = "2026-08-21T12:00:00+00:00"
CANCEL = "/api/v1/projects/checkout/runs/cancel"


def _setup(tmp_path):
    app, reports, routes = _make_app(tmp_path, backend="spawn")
    run_dir = _write_active_run(reports)
    st = json.loads((run_dir / "status.json").read_text()); st["started_at"] = STARTED
    (run_dir / "status.json").write_text(json.dumps(st))
    ctrl = reports / ".ctrl" / "checkout"; ctrl.mkdir(parents=True); os.chmod(ctrl, 0o755)
    claimed = ctrl / f"trigger_{TRIG}.json.claimed"
    claimed.write_text(json.dumps({"project": "checkout", "trigger_id": TRIG, "backend": "spawn", "container_name": routes.container_name("checkout", TRIG),
                                   "pid": 41001, "pgid": 41001, "process_start_ticks": 12345}))
    identity = routes.resolve_process_identity.__globals__["ProcessIdentity"](pid=41001, pgid=41001, start_ticks=12345)
    return app, reports, routes, run_dir, ctrl, claimed, identity


@contextlib.contextmanager
def teardown(identity, *, container="absent", group=False, stop=True, stop_effect=None):
    with (patch("dashboard.routes.resolve_process_identity", return_value=identity), patch("dashboard.routes.validate_process_identity"),
          patch("dashboard.routes.stop_container", return_value=stop, side_effect=stop_effect) as stopm, patch("dashboard.routes.terminate_process_group"),
          patch("dashboard.routes.container_state", return_value=container), patch("dashboard.routes.process_group_alive", return_value=group)):
        yield stopm


def readers(client, routes, run_dir):
    st = client.get(f"/api/v1/runs/checkout/{run_dir.name}/status", headers=_headers("viewer")).json()["state"]
    routes._index.scan_once()
    row = routes._index.get_run("checkout", run_dir.name)
    idle = client.get("/api/v1/projects/checkout/running", headers=_headers("viewer")).json()
    return st, (row.state if row else None), idle["run_ts"]


def test_cancel_writes_only_the_dashboard_owned_record_and_all_readers_agree(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    before = {f: ((run_dir / f).read_bytes(), (run_dir / f).stat().st_mtime_ns) for f in ("status.json", "run.json")}
    os.chmod(run_dir / "status.json", 0o444); os.chmod(run_dir / "run.json", 0o444); os.chmod(run_dir, 0o555)      # like the runner's 10001-owned files for the dashboard uid
    try:
        with teardown(identity), TestClient(app) as client:
            r = client.post(CANCEL, headers=_headers("operator"))
            assert r.status_code == 200, r.text
            assert readers(client, routes, run_dir) == ("cancelled", "cancelled", None)
    finally:
        os.chmod(run_dir, 0o755)
    assert {f: ((run_dir / f).read_bytes(), (run_dir / f).stat().st_mtime_ns) for f in before} == before
    rec = json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())
    assert (rec["project"], rec["run_id"], rec["state"], rec["trigger_id"], rec["runner_started_at"]) == ("checkout", run_dir.name, "cancelled", TRIG, STARTED)
    assert rec["teardown"]["confirmed"] is True and rec["teardown"]["container"] == "absent" and stat.S_IMODE((ctrl / f"cancel_{run_dir.name}.json").stat().st_mode) == 0o600
    assert (ctrl / f"trigger_{TRIG}.json.cancelled").is_file() and not claimed.exists() and not list(ctrl.glob(".cancel_*"))


@pytest.mark.parametrize("kwargs,effect", [
    ({}, RunControlError("the project runner container could not be stopped")),
    ({"container": "running"}, None), ({"container": "unknown"}, None), ({"group": True}, None), ({"group": None}, None)])
def test_failed_or_uncertain_stop_never_reports_cancelled(tmp_path, kwargs, effect):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    with teardown(identity, stop_effect=effect, **kwargs), TestClient(app) as client:
        r = client.post(CANCEL, headers=_headers("operator"))
        assert r.status_code == 503, r.text
        assert readers(client, routes, run_dir) == ("cancelling", "cancelling", run_dir.name)       # still active (run list agrees): a second run stays blocked
    assert claimed.exists() and not list(ctrl.glob("*.cancelled"))
    assert json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())["state"] == "cancelling"


def test_retry_after_a_failed_stop_succeeds_and_keeps_the_original_request_time(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    mark = ctrl / f"cancel_{run_dir.name}.json"
    with TestClient(app) as client:
        with teardown(identity, container="running"):
            assert client.post(CANCEL, headers=_headers("operator")).status_code == 503
        first = json.loads(mark.read_text())
        with teardown(identity):
            assert client.post(CANCEL, headers=_headers("operator")).status_code == 200
        assert readers(client, routes, run_dir)[0] == "cancelled"
    final = json.loads(mark.read_text())
    assert final["attempts"] == 2 and final["requested_at"] == first["requested_at"] and final["state"] == "cancelled"


def test_duplicate_cancel_is_idempotent_and_does_not_stop_anything_twice(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    mark = ctrl / f"cancel_{run_dir.name}.json"
    with teardown(identity) as stop, TestClient(app) as client:
        assert client.post(CANCEL, headers=_headers("operator")).status_code == 200
        frozen = mark.read_bytes()
        again = client.post(CANCEL, headers=_headers("operator"))
        assert again.status_code == 200 and again.json()["run_ts"] == run_dir.name and "already cancelled" in again.json()["message"]
    assert stop.call_count == 1 and mark.read_bytes() == frozen


def test_completion_racing_cancellation_preserves_the_committed_result(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)

    def runner_completes(_name):
        (run_dir / "status.json").write_text(json.dumps({"state": "complete", "started_at": STARTED}))
        return True
    with teardown(identity, stop_effect=runner_completes), TestClient(app) as client:
        r = client.post(CANCEL, headers=_headers("operator"))
        assert r.status_code == 409 and "preserved" in r.text
        assert readers(client, routes, run_dir)[0] == "complete"
    assert claimed.exists() and not list(ctrl.glob("*.cancelled"))
    assert json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())["state"] == "superseded"


def test_launcher_ack_before_the_cancel_lands_is_never_overwritten(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)

    def wrapper_acks(_name):
        claimed.rename(ctrl / f"trigger_{TRIG}.json.ack")
        return True
    with teardown(identity, stop_effect=wrapper_acks), TestClient(app) as client:
        r = client.post(CANCEL, headers=_headers("operator"))
        assert r.status_code == 409 and "preserved" in r.text
    assert (ctrl / f"trigger_{TRIG}.json.ack").is_file() and not list(ctrl.glob("*.cancelled"))
    assert json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())["state"] == "superseded"


def _marker(ctrl, rid, **kw):
    rec = {"schema": 1, "project": "checkout", "run_id": rid, "state": "cancelled", "trigger_id": TRIG, "runner_started_at": STARTED,
           "teardown": {"confirmed": True, "confirmed_at": rs.utc_now()}}
    rec.update(kw)
    (ctrl / f"cancel_{rid}.json").write_text(json.dumps(rec))


def test_stale_and_forged_records_are_ignored(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    with TestClient(app) as client:
        _marker(ctrl, run_dir.name, runner_started_at="2026-08-20T00:00:00+00:00")            # another incarnation of this run id
        assert readers(client, routes, run_dir)[0] == "running"
        _marker(ctrl, run_dir.name, run_id="20990101T000000Z")                                 # content bound to a different run
        assert readers(client, routes, run_dir)[0] == "running"
        _marker(ctrl, run_dir.name, project="other")                                           # content bound to a different project
        assert readers(client, routes, run_dir)[0] == "running"
        (ctrl / f"cancel_{run_dir.name}.json").write_text("{not json")
        assert readers(client, routes, run_dir)[0] == "running"
        (ctrl / f"cancel_{run_dir.name}.json").unlink()
        (ctrl / f"cancel_{run_dir.name}.json").symlink_to(tmp_path / "elsewhere.json")
        assert readers(client, routes, run_dir)[0] == "running"
        (ctrl / f"cancel_{run_dir.name}.json").unlink()
        _marker(ctrl, run_dir.name)                                                            # valid record, then the runner reports a terminal state
        (run_dir / "status.json").write_text(json.dumps({"state": "complete", "started_at": STARTED}))
        assert readers(client, routes, run_dir)[0] == "complete"


def test_untrusted_control_directory_blocks_the_record_before_any_teardown(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    os.chmod(ctrl, 0o777)
    with teardown(identity) as stop, TestClient(app) as client:
        r = client.post(CANCEL, headers=_headers("operator"))
        assert r.status_code == 503 and "safely" in r.text
        _marker(ctrl, run_dir.name)
        assert readers(client, routes, run_dir)[0] == "running"                               # a record in a world-writable directory is not trusted
    assert stop.call_count == 0 and claimed.exists()


def test_run_list_refreshes_old_runs_when_only_the_record_changes(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    for newer in ("20260822T120000Z", "20260823T120000Z"):
        d = reports / "checkout" / newer; d.mkdir()
        (d / "run.json").write_text(json.dumps({"project": "checkout", "run_ts": newer, "state": "complete"}))
    routes._index.scan_once()
    assert routes._index.get_run("checkout", run_dir.name).state == "running"
    _marker(ctrl, run_dir.name)
    routes._index.scan_once()
    assert routes._index.get_run("checkout", run_dir.name).state == "cancelled"


@pytest.mark.parametrize("status,marker,stale,expect", [
    (None, None, False, None), ({"state": "running"}, None, False, "running"), ({"state": "running"}, None, True, "error"),
    ({"state": "running"}, {"state": "cancelling"}, False, "cancelling"), ({"state": "running"}, {"state": "cancelling"}, True, "error"),
    ({"state": "running"}, {"state": "cancelled", "teardown": {"confirmed": True}}, True, "cancelled"),
    ({"state": "running"}, {"state": "cancelled", "teardown": {"confirmed": False}}, False, "cancelling"),
    ({"state": "complete"}, {"state": "cancelled", "teardown": {"confirmed": True}}, False, "complete"),
    ({"state": "error"}, {"state": "cancelled", "teardown": {"confirmed": True}}, False, "error"),
    ({"state": "running"}, {"state": "superseded"}, False, "running"),
    (None, {"state": "cancelled", "teardown": {"confirmed": True}}, False, "cancelled"),
    (None, {"state": "cancelling"}, False, "cancelling"),
    ({"state": "running", "started_at": "b"}, {"state": "cancelled", "runner_started_at": "a", "teardown": {"confirmed": True}}, False, "running"),
])
def test_effective_state_table(status, marker, stale, expect):
    assert rs.effective_state(status, marker, stale=stale)[0] == expect


def test_error_written_by_the_killed_runner_is_a_consequence_not_a_prior_result(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)

    def killed(_n):
        (run_dir / "status.json").write_text(json.dumps({"state": "error", "started_at": STARTED}))
        return True
    with teardown(identity, stop_effect=killed), TestClient(app) as client:
        assert client.post(CANCEL, headers=_headers("operator")).status_code == 200
        assert readers(client, routes, run_dir) == ("cancelled", "cancelled", None)
    rec = json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())
    assert rec["state"] == "cancelled" and rec["pre_state"] == "running"
    assert json.loads((ctrl / f"cancel_{TRIG}.json").read_text())["state"] == "cancelled"      # also bound to the exact trigger/run id the operator cancelled


def test_terminal_result_before_the_cancel_is_preserved_even_if_it_is_error(tmp_path):
    app, reports, routes, run_dir, ctrl, claimed, identity = _setup(tmp_path)
    proc = reports / "checkout" / ".nrdp-runs" / TRIG; proc.mkdir(parents=True)
    (proc / "status.json").write_text(json.dumps({"state": "error"}))
    with teardown(identity) as stop, TestClient(app) as client:
        r = client.post(CANCEL, headers=_headers("operator"))
        assert r.status_code == 409 and "before cancellation began" in r.text
    assert stop.call_count == 0 and claimed.exists()
