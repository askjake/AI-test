"""Project-scoped dashboard run cancellation regressions."""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_app(tmp_path: Path, *, backend: str = "watcher", reports_path: Path | None = None):
    reports = reports_path if reports_path is not None else tmp_path / "reports"
    specs = tmp_path / "tests_specs" / "checkout"
    specs.mkdir(parents=True)
    reports.mkdir(exist_ok=True)
    os.chmod(reports, 0o755)      # CP45-N: the supported root mode (initialize_runtime creates it 0755); a 0700 root is refused at launch
    (specs / "project.yaml").write_text(
        "name: checkout\n"
        "target:\n"
        "  type: local-app\n"
        "  app: xterm -T checkout\n"
        "  window: checkout\n"
        "enabled: true\n"
    )
    (specs / "000-checkout.md").write_text(
        "# Test: Checkout\n\n## Goal\nExercise checkout.\n"
    )

    for key in list(os.environ):
        if key.startswith("DASHBOARD_"):
            del os.environ[key]
    os.environ.update(
        {
            "DASHBOARD_AUTH_TOKEN": "viewer",
            "DASHBOARD_AUTH_OPERATOR_TOKEN": "operator",
            "DASHBOARD_REPORTS_DIR": str(reports),
            "DASHBOARD_SPECS_DIR": str(tmp_path / "tests_specs"),
            "DASHBOARD_INDEX_INTERVAL": "999",
            "DASHBOARD_TRIGGER_BACKEND": backend,
        }
    )

    import dashboard.app as dashboard_app
    import dashboard.config as dashboard_config
    import dashboard.index as dashboard_index
    import dashboard.routes as dashboard_routes

    importlib.reload(dashboard_config)
    importlib.reload(dashboard_routes)
    importlib.reload(dashboard_index)
    importlib.reload(dashboard_app)

    app = dashboard_app.create_app()
    index = dashboard_index.RunIndex(str(reports), interval=999)
    index.scan_once()
    dashboard_routes.set_index(index)
    return app, reports, dashboard_routes


def _write_active_run(reports: Path, project: str = "checkout") -> Path:
    run_dir = reports / project / "20260821T120000Z"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "status.json").write_text(
        json.dumps(
            {
                "state": "running",
                "current_spec": "Checkout",
                "current_spec_index": 0,
                "specs_total": 1,
                "specs_completed": [],
            }
        )
    )
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "project": project,
                "run_ts": run_dir.name,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "errored": 0,
                "spec_total": 1,
                "duration_seconds": 0,
                "state": "running",
            }
        )
    )
    return run_dir


def test_operator_can_cancel_only_this_projects_queued_trigger(tmp_path):
    app, reports, _routes = _make_app(tmp_path, backend="watcher")
    other_ctrl = reports / ".ctrl" / "sublime3"
    other_ctrl.mkdir(parents=True)
    other_trigger = other_ctrl / "trigger_trig_20260821T120001_feedface.json.claimed"
    other_trigger.write_text(
        json.dumps(
            {
                "project": "sublime3",
                "trigger_id": "trig_20260821T120001_feedface",
            }
        )
    )
    trigger_id = "trig_20260821T120002_cafebabe"          # CP45-I: the API no longer creates watcher triggers, so a pre-existing queued one is written by hand
    queued = reports / ".ctrl" / "checkout"
    queued.mkdir(parents=True)
    (queued / f"trigger_{trigger_id}.json").write_text(json.dumps({"project": "checkout", "trigger_id": trigger_id, "backend": "watcher"}))
    with TestClient(app) as client:

        cancelled = client.post(
            "/api/v1/projects/checkout/runs/cancel", headers=_headers("operator")
        )
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["trigger_id"] == trigger_id

        running = client.get(
            "/api/v1/projects/checkout/running", headers=_headers("viewer")
        )
        assert running.json()["run_ts"] is None
        lifecycle = client.get(
            f"/api/v1/projects/checkout/triggers/{trigger_id}",
            headers=_headers("viewer"),
        )
        assert lifecycle.json()["status"] == "cancelled"

    outcomes = list((reports / ".ctrl" / "checkout").glob("*.json.cancelled"))
    assert len(outcomes) == 1
    assert json.loads(outcomes[0].read_text())["cancelled"] is True
    assert other_trigger.is_file(), "another project's trigger was modified"


def test_viewer_cannot_cancel_a_run(tmp_path):
    app, _reports, _routes = _make_app(tmp_path, backend="watcher")
    queued = _reports / ".ctrl" / "checkout"
    queued.mkdir(parents=True)
    (queued / "trigger_trig_20260821T120003_feedbeef.json").write_text(json.dumps({"project": "checkout", "trigger_id": "trig_20260821T120003_feedbeef"}))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/projects/checkout/runs/cancel", headers=_headers("viewer")
        )
    assert response.status_code == 403


def test_cancel_without_active_run_returns_conflict(tmp_path):
    app, _reports, _routes = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/projects/checkout/runs/cancel", headers=_headers("operator")
        )
    assert response.status_code == 409
    assert "No active run" in response.json()["detail"]


def test_spawn_cancel_signals_only_recorded_project_group(tmp_path):
    app, reports, routes = _make_app(tmp_path, backend="spawn")
    run_dir = _write_active_run(reports)
    trigger_id = "trig_20260821T120000_deadbeef"
    ctrl = reports / ".ctrl" / "checkout"
    ctrl.mkdir(parents=True)
    claimed = ctrl / f"trigger_{trigger_id}.json.claimed"
    claimed.write_text(
        json.dumps(
            {
                "project": "checkout",
                "trigger_id": trigger_id,
                "backend": "spawn",
                "container_name": routes.container_name("checkout", trigger_id),
                "pid": 41001,
                "pgid": 41001,
                "process_start_ticks": 12345,
            }
        )
    )
    identity = routes.resolve_process_identity.__globals__["ProcessIdentity"](
        pid=41001, pgid=41001, start_ticks=12345
    )

    with (
        patch("dashboard.routes.resolve_process_identity", return_value=identity),
        patch("dashboard.routes.validate_process_identity") as validate,
        patch("dashboard.routes.stop_container", return_value=False) as stop,
        patch("dashboard.routes.terminate_process_group") as terminate,
        patch("dashboard.routes.container_state", return_value="absent"),
        patch("dashboard.routes.process_group_alive", return_value=False),
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/projects/checkout/runs/cancel", headers=_headers("operator")
        )

    assert response.status_code == 200, response.text
    stop.assert_called_once_with(routes.container_name("checkout", trigger_id))
    validate.assert_called_once()
    terminate.assert_called_once_with(identity)
    assert not claimed.exists()
    assert (ctrl / f"trigger_{trigger_id}.json.cancelled").is_file()
    # CP45-D option A: runner-owned files are NOT rewritten; the dashboard-owned record plus the shared effective-state rule drive every reader
    assert json.loads((run_dir / "status.json").read_text())["state"] == "running"
    assert json.loads((run_dir / "run.json").read_text())["state"] == "running"
    assert json.loads((ctrl / f"cancel_{run_dir.name}.json").read_text())["state"] == "cancelled"
    routes._index.scan_once()
    assert routes._index.get_run("checkout", run_dir.name).state == "cancelled"


def test_pid_identity_failure_never_signals_or_changes_run_state(tmp_path):
    app, reports, routes = _make_app(tmp_path, backend="spawn")
    run_dir = _write_active_run(reports)
    trigger_id = "trig_20260821T120000_bad00bad"
    ctrl = reports / ".ctrl" / "checkout"
    ctrl.mkdir(parents=True)
    claimed = ctrl / f"trigger_{trigger_id}.json.claimed"
    claimed.write_text(
        json.dumps(
            {
                "project": "checkout",
                "trigger_id": trigger_id,
                "container_name": routes.container_name("checkout", trigger_id),
            }
        )
    )

    with (
        patch(
            "dashboard.routes.resolve_process_identity",
            side_effect=routes.RunControlError("the recorded run PID has been reused"),
        ),
        patch("dashboard.routes.stop_container", return_value=False),
        patch("dashboard.routes.terminate_process_group") as terminate,
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/projects/checkout/runs/cancel", headers=_headers("operator")
        )

    assert response.status_code == 409
    assert "reused" in response.json()["detail"]
    terminate.assert_not_called()
    assert claimed.is_file()
    assert json.loads((run_dir / "status.json").read_text())["state"] == "running"


def test_spawn_records_process_and_container_ownership(tmp_path):
    app, reports, routes = _make_app(tmp_path, backend="spawn")
    fake_process = type("FakeProcess", (), {"pid": 42001})()
    identity_type = routes.capture_process_identity.__globals__["ProcessIdentity"]
    identity = identity_type(pid=42001, pgid=42001, start_ticks=98765)

    with (
        patch("dashboard.routes.subprocess.Popen", return_value=fake_process) as popen,
        patch("dashboard.routes.capture_process_identity", return_value=identity),
        TestClient(app) as client,
    ):
        response = client.post(
            "/api/v1/projects/checkout/runs", headers=_headers("operator")
        )

    assert response.status_code == 202
    trigger_id = response.json()["trigger_id"]
    claimed = reports / response.json()["ctrl_file"]
    payload = json.loads(claimed.read_text())
    expected_container = routes.container_name("checkout", trigger_id)
    assert payload["pid"] == 42001
    assert payload["pgid"] == 42001
    assert payload["process_start_ticks"] == 98765
    assert payload["container_name"] == expected_container
    spawned_env = popen.call_args.kwargs["env"]
    assert spawned_env["ORCHESTRATOR_CONTAINER_NAME"] == expected_container
    assert spawned_env["ORCHESTRATOR_TRIGGER_ID"] == trigger_id


def test_process_identity_detects_start_time_change_before_signalling(monkeypatch):
    import dashboard.run_control as run_control

    identity = run_control.ProcessIdentity(pid=41001, pgid=41001, start_ticks=100)
    monkeypatch.setattr(run_control.os, "getpgid", lambda _pid: 41001)
    monkeypatch.setattr(run_control.os, "getsid", lambda _pid: 41001)
    monkeypatch.setattr(run_control, "_start_ticks", lambda _pid: 101)
    monkeypatch.setattr(run_control, "_matches_trigger_process", lambda *_a, **_k: True)

    with pytest.raises(run_control.RunControlError, match="reused"):
        run_control.validate_process_identity(
            identity,
            project="checkout",
            control_path="/reports/.ctrl/checkout/trigger.json.claimed",
            script_path="/app/scripts/run_trigger.sh",
        )


def test_cancelled_live_stream_is_terminal(tmp_path):
    import asyncio
    from dashboard.live import tail_run

    reports = tmp_path / "reports"
    run_dir = reports / "checkout" / "20260821T120000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "status.json").write_text(json.dumps({"state": "cancelled"}))

    async def collect():
        return [event async for event in tail_run(str(reports), "checkout", run_dir.name)]

    events = asyncio.run(collect())
    assert events[-1]["event"] == "run_complete"
    assert json.loads(events[-1]["data"])["state"] == "cancelled"
