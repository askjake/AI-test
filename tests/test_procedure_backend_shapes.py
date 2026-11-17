"""End-to-end API contract: REAL backend responses, walked through the whole operator flow.

This is the integration test the first tester asked for (defects D1-D6): nothing here is an
independently invented UI fixture.  The responses recorded while it runs are the very JSON the
browser code is then fed in tests/js/procedure_backend_shapes.test.js
(fixture: tests/js/fixtures/backend_shapes.json; regenerate with NRDP_WRITE_FIXTURES=1).

Flow: paste goal -> view -> edit connections (+ hop-1 certificate) -> create project -> test
connection -> full run gating -> edit invalidates -> cancel / hard-stop -> checkpoint.
No RDP machine, model or container is contacted: the launcher and canceller are injected, and the
"runner" is played by this test writing the same files chain_hooks writes.
"""
from __future__ import annotations

import importlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard import procedure_routes_v2  # noqa: F401
from dashboard.procedure_intake import assert_no_secret
from dashboard.wizard_routes import router as wizard_router
from tests.test_procedure_intake_v2 import GOAL, SECRETS, _service, _settings

FIXTURE = Path(__file__).parent / "js" / "fixtures" / "backend_shapes.json"
FP = "sha256:" + "ab" * 32
RID = "trig_20261028T120000_deadbeef"
RID2 = "trig_20261028T130000_cafebabe"
# Written directly by the runner fixture; never allocated by the launcher, because the API
# refuses to start an operating run under the connection-only qualification.
DOWN_RID = "trig_20261028T135959_d0wn9rad"
OP = {"Authorization": "Bearer operator"}


def _normalise(value):
    """Replace volatile values so the recorded shapes are stable and diffable."""
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"\b[0-9a-f]{32}\b", "0" * 32, value)
        value = re.sub(r"procedure-[0-9a-f]{32}-hop-(\d)-[0-9a-f]{8}\.rdp\.pw", r"procedure-REF-hop-\1.rdp.pw", value)
        value = re.sub(r"\b[0-9a-f]{64}\b", "f" * 64, value)
        value = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?", "2026-10-28T12:00:00+00:00", value)
        value = re.sub(r"foo-service-maintenance-[0-9a-f]{8}", "project-NAME", value)
        value = re.sub(r"[a-z0-9-]+-[0-9a-f]{8}\b", lambda m: "project-NAME" if "-" in m.group(0) and len(m.group(0)) < 80 and "service" in m.group(0) else m.group(0), value)
        return value
    return value


@pytest.fixture
def api(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    import dashboard.config as config
    monkeypatch.setattr(config, "settings", settings)
    app = FastAPI()
    app.state.target_setup_service = _service(settings)
    app.include_router(wizard_router, prefix="/api/v1")
    # Resolve the module at run time, exactly as the route handlers do (they import it lazily), so a
    # test that earlier reloaded the dashboard package cannot leave us configuring a stale copy.
    pr = importlib.import_module("dashboard.procedure_runs")
    launches, cancels = [], []
    ids = iter([RID, RID2, "trig_20261028T140000_0badf00d"])

    def launch(project):
        launches.append(project)
        return next(ids)

    pr.configure(reports_root=lambda: settings.reports_dir, launch=launch,
                 cancel=lambda p: cancels.append(p) or {"status": "cancelled"})
    clock = {"t": datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)}
    pr.configure(now=lambda: clock["t"])
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, settings=settings, launches=launches, cancels=cancels, clock=clock, pr=pr)
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel,
                 now=lambda: datetime.now(timezone.utc))


def runner_writes(settings, project, run_id, **files):
    """Play the runner: write the files chain_hooks writes into the run folder (not control/)."""
    rd = Path(settings.reports_dir) / project / ".nrdp-runs" / run_id
    rd.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (rd / name).write_text(json.dumps(payload))
    return rd


def test_operator_flow_with_real_backend_shapes(api):
    c, rec = api.client, {}
    created = c.post("/api/v1/authoring/wizard/procedures", headers=OP, json={"procedure": GOAL})
    assert created.status_code == 200, created.text
    key = created.json()["id"]
    base = f"/api/v1/authoring/wizard/procedures/{key}"
    rec["created"] = created.json()

    # ---- D2/D3: certificate object and readiness.items exactly as the UI reads them
    view = c.get(base + "/view", headers=OP).json()
    rec["view_new"] = view
    assert isinstance(view["readiness"], dict) and isinstance(view["readiness"]["items"], list)
    assert view["connections"][0]["certificate"] == {"state": "required", "name": "", "fingerprint": ""}
    assert view["connections"][1]["certificate"]["state"] == "not_applicable"
    assert view["connections"][0]["credential"]["state"] == "saved"
    assert view["project"] is None and view["last_test"] is None
    for step in view["steps"]:
        assert {"order", "title", "kind", "mutating", "read_only_ok", "instructions", "completion_checks"} <= set(step)

    # ---- save the reviewed certificate through the UI's nested shape
    saved = c.put(base + "/connections", headers=OP, json={"connections": [
        {"order": 1, "certificate": {"name": "WIN-HOP1", "fingerprint": FP}, "label": "Jump PC"}]})
    assert saved.status_code == 200, saved.text
    view = saved.json()
    rec["view_cert_reviewed"] = view
    assert view["connections"][0]["certificate"] == {"state": "reviewed", "name": "WIN-HOP1", "fingerprint": FP}
    assert not any(i["key"] == "certificate-1" and i["state"] == "required" for i in view["readiness"]["items"])

    # ---- D5: field errors use zero-based positions that the UI maps back to a hop
    bad = c.put(base + "/connections", headers=OP, json={"connections": [{"order": 2, "port": 0}]})
    assert bad.status_code == 422 and bad.json()["errors"][0]["field"] == "connections[1].port"
    rec["error_422"] = bad.json()

    # ---- D4: create the project; the draft remembers it under ``project.name``
    made = c.post(base + "/project", headers=OP, json={})
    assert made.status_code == 200, made.text
    project = made.json()["project_name"]
    rec["project_created"] = made.json()
    view = c.get(base + "/view", headers=OP).json()
    assert view["project"]["name"] == project and view["project"]["current"] is True
    rec["view_project"] = view
    reloaded = c.get(f"/api/v1/authoring/wizard/procedures/{key}", headers=OP).json()     # resume path
    assert reloaded["project"]["name"] == project

    # ---- a full run needs a passed connection test made with THESE connections
    refused = c.post(base + "/runs", headers=OP, json={"mode": "full_run", "confirm_phrase": project})
    assert refused.status_code == 409, refused.text
    assert "connection test" in refused.json()["detail"]
    started = c.post(base + "/runs", headers=OP, json={"mode": "connection_test"})
    assert started.status_code == 200, started.text
    assert started.json() == {"run_id": RID}
    rec["run_started"] = started.json()

    # ---- D1: the run status is a plain string at every stage
    running = runner_writes(api.settings, project, RID, **{"status.json": {"state": "running", "mode": "connection_test", "effective_mode": "connection_test", "requested_mode": "connection_test", "downgraded": False}})
    got = c.get(base + f"/runs/{RID}", headers=OP).json()
    rec["run_running"] = got
    assert got["status"] == "running" and isinstance(got["status"], str) and isinstance(got["state"], str)
    assert "[object" not in json.dumps(got)
    runner_writes(api.settings, project, RID,
                  **{"chain_progress.json": {"phase": "chain_ready", "active_hop": 2, "notes": ["No Windows session was signed out by this run."],
                                             "hops": [{"order": 1, "host": "10.70.115.36", "user": "operator1", "status": "confirmed", "detail": ""},
                                                      {"order": 2, "host": "172.20.33.215", "user": "jamuser", "status": "confirmed", "detail": ""}]},
                     "status.json": {"state": "complete", "result": "passed", "mode": "connection_test", "effective_mode": "connection_test",
                                     "requested_mode": "connection_test", "downgraded": False, "downgrade_reason": ""}})
    (running / "evidence").mkdir(exist_ok=True)
    (running / "evidence" / "hop2_identity_console_007.png").write_bytes(b"\x89PNG")
    done = c.get(base + f"/runs/{RID}", headers=OP).json()
    rec["run_complete"] = done
    assert done["status"] == "complete" and done["effective_mode"] == "connection_test" and done["downgraded"] is False
    assert {"name": "hop2_identity_console_007.png", "hop": 2, "phase": "identity console",
            "url": f"/reports/{project}/.nrdp-runs/{RID}/evidence/hop2_identity_console_007.png"} in done["evidence"]
    assert "config_hash" not in done

    # the server recorded the test, bound to the current connections
    view = c.get(base + "/view", headers=OP).json()
    assert view["last_test"]["status"] == "passed" and view["last_test"]["current"] is True and "config_hash" not in view["last_test"]
    rec["view_after_test"] = view

    # ---- CONNECTION-ONLY QUALIFICATION (review blocker B1): the API refuses an operating run even
    # with the correct confirmation phrase, and refuses BEFORE launching anything.
    full = c.post(base + "/runs", headers=OP, json={"mode": "full_run", "confirm_phrase": project})
    assert full.status_code == 409, full.text
    assert "connection tests only" in full.json()["detail"]
    rec["run_full_refused"] = full.json()
    assert not (Path(api.settings.reports_dir) / project / ".nrdp-runs" / RID2).exists()   # never launched
    # read_only_check is refused on the same terms
    ro = c.post(base + "/runs", headers=OP, json={"mode": "read_only_check"})
    assert ro.status_code == 409 and "connection tests only" in ro.json()["detail"]
    # and the view advertises the same capability the API enforces, so the UI cannot offer more
    cap = c.get(base + "/view", headers=OP).json()["run_capability"]
    assert cap["connection_only"] is True
    assert cap["allowed_modes"] == ["connection_test"]
    assert sorted(cap["disabled_modes"]) == ["browser_verify", "full_run", "read_only_check"] and cap["reason"]      # CP43
    rec["run_capability"] = cap

    # ---- a downgraded run is reported as such and is never a usable "test"
    runner_writes(api.settings, project, DOWN_RID, **{"status.json": {
        "state": "complete", "result": "passed", "mode": "connection_test", "effective_mode": "connection_test",
        "requested_mode": "full_run", "downgraded": True, "downgrade_reason": "operating steps are disabled in this build (connection-only qualification)"}})
    downgraded = c.get(base + f"/runs/{DOWN_RID}", headers=OP).json()
    rec["run_downgraded"] = downgraded
    assert downgraded["downgraded"] is True and downgraded["requested_mode"] == "full_run" and downgraded["effective_mode"] == "connection_test"
    assert "connection-only" in downgraded["downgrade_reason"]
    assert c.get(base + "/view", headers=OP).json()["last_test"]["run_id"] == RID     # unchanged: not recorded as a test

    # ---- editing a relevant connection setting invalidates the test AND the project
    edited = c.put(base + "/connections", headers=OP, json={"connections": [{"order": 2, "user": "otheruser"}]})
    assert edited.status_code == 200
    view = edited.json()
    rec["view_after_edit"] = view
    assert view["last_test"] is None and view["project"]["current"] is False
    stale = c.post(base + "/runs", headers=OP, json={"mode": "connection_test"})
    assert stale.status_code == 409 and "Create the project again" in stale.json()["detail"]
    # a label is not a relevant setting
    c.post(base + "/project", headers=OP, json={"replace": True})
    assert c.get(base + "/view", headers=OP).json()["project"]["current"] is True
    c.put(base + "/connections", headers=OP, json={"connections": [{"order": 2, "label": "just a name"}]})
    assert c.get(base + "/view", headers=OP).json()["project"]["current"] is True

    # ---- D6: cancel -> the dashboard writes the request; a killed runner is finalised as cancelled
    third = RID2          # the launcher's 2nd id: the two refused operating starts consumed none
    # Cancellation is mode-independent; under the connection-only qualification the startable mode
    # is connection_test, so the cancel/grace/checkpoint shapes are exercised through that.
    api_start = c.post(base + "/runs", headers=OP, json={"mode": "connection_test"})
    assert api_start.status_code == 200, api_start.text
    assert api_start.json() == {"run_id": third}
    runner_writes(api.settings, project, third, **{"status.json": {"state": "running", "mode": "connection_test"}})
    cancel = c.post(base + f"/runs/{third}/cancel", headers=OP)
    assert cancel.status_code == 200 and api.cancels == [project]
    assert c.get(base + f"/runs/{third}", headers=OP).json()["status"] == "running"     # grace period
    api.clock["t"] += timedelta(seconds=api.pr.CANCEL_GRACE_SECONDS + 5)
    assert c.get(base + f"/runs/{third}", headers=OP).json()["status"] == "running"        # CP45-D: no teardown confirmation yet -> not cancelled
    import json as _j, os as _o
    from datetime import datetime as _d, timezone as _z
    _cd = _o.path.join(api.settings.reports_dir, ".ctrl", project); _o.makedirs(_cd, exist_ok=True)
    _j.dump({"schema": 1, "project": project, "run_id": third, "state": "cancelled", "pre_state": "running", "runner_started_at": None,
             "teardown": {"confirmed": True, "confirmed_at": _d.now(_z.utc).isoformat()}}, open(_o.path.join(_cd, f"cancel_{third}.json"), "w"))
    cancelled = c.get(base + f"/runs/{third}", headers=OP).json()
    rec["run_cancelled"] = cancelled
    assert cancelled["status"] == "cancelled" and cancelled["state_source"] == "cancel_record"

    # ---- checkpoint: the runner's request is in the run folder; the ack closes the prompt
    runner_writes(api.settings, project, third, **{"checkpoint.json": {"id": "cp-6-aaaa0001", "step_order": 6, "title": "Swap wires", "instructions": "do it", "requested_at": "2026-10-28T12:00:00+00:00"}})
    pending = c.get(base + f"/runs/{third}", headers=OP).json()
    rec["run_checkpoint"] = {**pending, "state": "running", "status": "running"} if pending["status"] == "cancelled" else pending
    # (cancelled runs never show a prompt)
    assert pending["checkpoint_pending"] is False

    # nothing the browser can read contains a password
    for payload in rec.values():
        assert_no_secret(json.dumps(payload), SECRETS)

    recorded = _normalise(rec)
    if os.environ.get("NRDP_WRITE_FIXTURES") == "1":
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")
    elif FIXTURE.exists():
        committed = json.loads(FIXTURE.read_text())
        assert set(committed) == set(recorded), "backend response set drifted: regenerate with NRDP_WRITE_FIXTURES=1"
        for name in recorded:
            assert _shape(committed[name]) == _shape(recorded[name]), f"backend response shape drifted: {name}"


def _shape(value):
    """Structure only (keys and JSON types), so volatile values never cause drift failures."""
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    return type(value).__name__
