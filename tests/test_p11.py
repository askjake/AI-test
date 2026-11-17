"""Phase 11 tests — on-demand run triggering.

P11-1  POST /runs with operator token returns 202 + trigger file on disk
P11-2  POST /runs with viewer-only token returns 403
P11-3  POST /runs for unknown project returns 404
P11-4  POST /runs while run in progress returns 409
P11-5  TriggerWatcher.check() fires run_project_once on a pending trigger
P11-6  TriggerWatcher.check() writes .ack on success
P11-7  TriggerWatcher.check() writes .busy when run already in progress
P11-8  TriggerWatcher._is_running() reads status.json correctly
P11-9  TriggerWatcher._prune() removes old completed files
P11-10 Trigger file is valid JSON and contains expected fields
P11-11 Two rapid triggers: second is rejected with 409
P11-12 Completed run re-enables trigger (409 no longer fires)
P11-13 _ctrl_dir_for creates directory tree
P11-14 trigger_id has expected format (trig_<ts>_<hex>)
P11-15 No orchestrator import in dashboard package
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def reports_dir(tmp_path):
    rdir = tmp_path / "reports"
    rdir.mkdir(exist_ok=True)
    os.chmod(rdir, 0o755)      # CP45-N: the supported root mode (initialize_runtime creates it 0755); a 0700 root is refused at launch
    specs = tmp_path / "tests_specs" / "checkout"
    specs.mkdir(parents=True)
    (specs / "project.yaml").write_text(
        "name: checkout\n"
        "target:\n"
        "  type: local-app\n"
        "  app: xterm -T checkout\n"
        "  window: checkout\n"
        "enabled: true\n"
    )
    (specs / "000-checkout.md").write_text(
        "# Test: Checkout\n\n## Goal\nExercise checkout.\n\n"
        "## Assertions\n- Checkout completes.\n"
    )
    run = rdir / "checkout" / "20260101T120000Z"
    run.mkdir(parents=True)
    os.chmod(rdir / "checkout", 0o755)      # CP45-N: created under a restrictive umask above; the supported project mode is 0755
    (run / "run.json").write_text(json.dumps({
        "project": "checkout", "run_ts": "20260101T120000Z",
        "model_id": "m", "total": 2, "passed": 2, "failed": 0,
        "errored": 0, "spec_total": 1, "duration_seconds": 5.0,
    }))
    (run / "report.html").write_text("<html>r</html>")
    return str(rdir)


def _make_app(
    reports_dir,
    auth_token="viewer",
    operator_token=None,
    monkeypatch=None,
    trigger_backend="spawn",
):
    # Clear ALL DASHBOARD_ vars first to avoid cross-test pollution.
    for k in list(os.environ.keys()):
        if k.startswith("DASHBOARD_"):
            del os.environ[k]
    os.environ["DASHBOARD_AUTH_TOKEN"] = auth_token
    if operator_token:
        os.environ["DASHBOARD_AUTH_OPERATOR_TOKEN"] = operator_token
    os.environ["DASHBOARD_REPORTS_DIR"] = reports_dir
    os.environ["DASHBOARD_SPECS_DIR"] = os.path.join(
        os.path.dirname(reports_dir), "tests_specs"
    )
    os.environ["DASHBOARD_INDEX_INTERVAL"] = "999"
    os.environ["DASHBOARD_TRIGGER_BACKEND"] = trigger_backend

    import dashboard.config as dcfg
    import dashboard.routes as droutes
    import dashboard.index as didx
    import dashboard.app as dapp

    importlib.reload(dcfg)
    importlib.reload(droutes)
    importlib.reload(didx)
    importlib.reload(dapp)

    from dashboard.app import create_app
    from dashboard.index import RunIndex
    from dashboard.routes import set_index

    a = create_app()
    idx = RunIndex(
        reports_dir=reports_dir,
        specs_dir=os.path.join(os.path.dirname(reports_dir), "tests_specs"),
        interval=999,
    )
    idx.scan_once()
    set_index(idx)
    return a


@pytest.fixture()
def two_token_client(reports_dir):
    a = _make_app(reports_dir, auth_token="viewer", operator_token="operator")
    with patch("dashboard.routes.subprocess.Popen"), TestClient(a, raise_server_exceptions=True) as c:      # CP45-I: spawn is the supported backend; no real process
        yield c


@pytest.fixture()
def single_token_client(reports_dir):
    a = _make_app(reports_dir, auth_token="master")
    with patch("dashboard.routes.subprocess.Popen"), TestClient(a, raise_server_exceptions=True) as c:      # CP45-I: spawn is the supported backend; no real process
        yield c


def _vh(token):
    return {"Authorization": f"Bearer {token}"}


def test_sse_uses_scoped_httponly_cookie_instead_of_query_token(two_token_client):
    rejected = two_token_client.get(
        "/api/v1/runs/checkout/20260101T120000Z/live?token=viewer"
    )
    assert rejected.status_code == 401

    response = two_token_client.post(
        "/api/v1/auth/sse-session", headers=_vh("viewer")
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "dashboard_sse_token=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/api/v1/runs" in cookie


def test_project_inventory_includes_configured_project_before_first_run(tmp_path):
    from dashboard.index import RunIndex

    reports = tmp_path / "reports"
    specs = tmp_path / "tests_specs" / "never-run"
    reports.mkdir()
    specs.mkdir(parents=True)
    (specs / "project.yaml").write_text("name: Never Run\n", encoding="utf-8")

    index = RunIndex(str(reports), specs_dir=str(specs.parent))

    assert index.projects() == [{
        "name": "never-run",
        "run_count": 0,
        "latest": None,
        "index_href": "/reports/never-run/index.html",
    }]
    assert index.has_project("never-run") is True


def test_stale_running_status_does_not_block_new_trigger(two_token_client, reports_dir):
    stale_run = os.path.join(reports_dir, "checkout", "20260819T120000Z")
    os.makedirs(stale_run)
    status_path = os.path.join(stale_run, "status.json")
    with open(status_path, "w", encoding="utf-8") as fh:
        json.dump({"state": "running"}, fh)
    old = time.time() - 3 * 60 * 60
    os.utime(status_path, (old, old))

    running = two_token_client.get(
        "/api/v1/projects/checkout/running", headers=_vh("viewer")
    )
    assert running.status_code == 200
    assert running.json()["run_ts"] is None

    triggered = two_token_client.post(
        "/api/v1/projects/checkout/runs", headers=_vh("operator")
    )
    assert triggered.status_code == 202


# ─────────────────────────────────────────────────────────────────────────────
# P11-1: trigger returns 202 + trigger file written
# ─────────────────────────────────────────────────────────────────────────────

def test_trigger_returns_202(two_token_client, reports_dir):
    """P11-1: POST /api/v1/projects/checkout/runs returns 202 and writes trigger file."""
    r = two_token_client.post(
        "/api/v1/projects/checkout/runs",
        headers=_vh("operator"),
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert body["project"] == "checkout"
    assert body["trigger_id"].startswith("trig_")

    # Trigger file must exist on disk
    ctrl_file = os.path.join(reports_dir, ".ctrl", "checkout",
                              os.path.basename(body["ctrl_file"]))
    assert os.path.isfile(ctrl_file), f"trigger file not found: {ctrl_file}"

    # File must contain valid JSON with required fields
    with open(ctrl_file) as f:
        data = json.load(f)
    assert data["project"] == "checkout"
    assert data["trigger_id"] == body["trigger_id"]
    assert "requested_at" in data


# ─────────────────────────────────────────────────────────────────────────────
# P11-2: viewer-only token rejected (403)
# ─────────────────────────────────────────────────────────────────────────────

def test_trigger_viewer_token_rejected(two_token_client):
    """P11-2: viewer token cannot trigger a run when operator token is set."""
    r = two_token_client.post(
        "/api/v1/projects/checkout/runs",
        headers=_vh("viewer"),
    )
    assert r.status_code == 403, r.text


# ─────────────────────────────────────────────────────────────────────────────
# P11-3: unknown project → 404
# ─────────────────────────────────────────────────────────────────────────────

def test_trigger_unknown_project(two_token_client):
    """P11-3: trigger for non-existent project returns 404."""
    r = two_token_client.post(
        "/api/v1/projects/does-not-exist/runs",
        headers=_vh("operator"),
    )
    assert r.status_code == 404, r.text


# ─────────────────────────────────────────────────────────────────────────────
# P11-4: 409 when run already in progress
# ─────────────────────────────────────────────────────────────────────────────

def test_trigger_409_when_running(two_token_client, reports_dir):
    """P11-4: trigger rejected with 409 when a run is already in state=running."""
    run_dir = os.path.join(reports_dir, "checkout", "20260101T120000Z")
    status = {"state": "running", "current_spec": "Login", "specs_total": 1,
              "specs_completed": [], "started_at": "2026-01-01T12:00:00Z"}
    with open(os.path.join(run_dir, "status.json"), "w") as f:
        json.dump(status, f)

    r = two_token_client.post(
        "/api/v1/projects/checkout/runs",
        headers=_vh("operator"),
    )
    assert r.status_code == 409, r.text
    assert "in progress" in r.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# P11-5/P11-6: TriggerWatcher fires run_fn and writes .ack
def _queue(tmp_path, tid="trig_20260101T000000Z_aabbccdd", project="myproject"):
    ctrl = tmp_path / ".ctrl" / project
    ctrl.mkdir(parents=True, exist_ok=True)
    f = ctrl / f"trigger_{tid}.json"
    f.write_text(json.dumps({"project": project, "trigger_id": tid, "requested_at": "2026-01-01T00:00:00Z", "requester": "dashboard"}))
    return ctrl, f, tid


def test_watcher_refuses_every_trigger_and_never_runs_a_project(tmp_path):
    """CP45-I (was P11-5/6): the in-process watcher is unsupported under the 0755 reports contract - it never calls run_fn, and the refusal is a visible .err."""
    from orchestrator.trigger_watcher import TriggerWatcher, UNSUPPORTED_MESSAGE
    ctrl, trigger_file, tid = _queue(tmp_path)
    (tmp_path / "reports" / "myproject").mkdir(parents=True)
    calls = []
    TriggerWatcher(ctrl_dir=str(tmp_path / ".ctrl"), run_fn=lambda name, **k: calls.append(name), reports_dir=str(tmp_path / "reports")).check()
    assert calls == [], "run_fn must never be called"
    err = ctrl / f"trigger_{tid}.json.err"
    assert err.exists() and not trigger_file.exists() and not (ctrl / f"trigger_{tid}.json.ack").exists()
    body = json.loads(err.read_text())
    assert body["error"] == UNSUPPORTED_MESSAGE and body["exit_code"] == 78 and body["trigger_id"] == tid
    assert sorted(p.name for p in (tmp_path / "reports" / "myproject").iterdir()) == []      # nothing created under reports/


def test_watcher_refuses_even_with_a_run_in_progress_and_with_unreadable_triggers(tmp_path):
    from orchestrator.trigger_watcher import TriggerWatcher
    ctrl, _f, tid = _queue(tmp_path)
    run = tmp_path / "reports" / "myproject" / "20260101T000000Z"
    run.mkdir(parents=True)
    (run / "status.json").write_text(json.dumps({"state": "running"}))
    (ctrl / "trigger_garbage.json").write_text("{not json")
    calls = []
    TriggerWatcher(ctrl_dir=str(tmp_path / ".ctrl"), run_fn=lambda name, **k: calls.append(name), reports_dir=str(tmp_path / "reports")).check()
    assert calls == [] and (ctrl / f"trigger_{tid}.json.err").exists() and (ctrl / "trigger_garbage.json.err").exists()
    assert not list(ctrl.glob("*.busy")) and not list(ctrl.glob("*.ack"))


# ─────────────────────────────────────────────────────────────────────────────

def test_is_running(tmp_path):
    """P11-8: _is_running returns correct state based on status.json."""
    from orchestrator.trigger_watcher import TriggerWatcher

    w = TriggerWatcher(str(tmp_path / ".ctrl"), lambda **k: None,
                       reports_dir=str(tmp_path / "reports"))

    proj = tmp_path / "reports" / "proj" / "20260101T000000Z"
    proj.mkdir(parents=True)

    assert w._is_running("proj") is False  # no status.json

    (proj / "status.json").write_text(json.dumps({"state": "complete"}))
    assert w._is_running("proj") is False

    (proj / "status.json").write_text(json.dumps({"state": "running"}))
    assert w._is_running("proj") is True


# ─────────────────────────────────────────────────────────────────────────────
# P11-9: _prune keeps only _KEEP_COMPLETED files
# ─────────────────────────────────────────────────────────────────────────────

def test_prune(tmp_path):
    """P11-9: _prune removes old completed files, keeps most recent 20."""
    from orchestrator.trigger_watcher import TriggerWatcher, _KEEP_COMPLETED

    ctrl = tmp_path / ".ctrl" / "proj"
    ctrl.mkdir(parents=True)

    # Create 25 .ack files
    for i in range(25):
        (ctrl / f"trigger_2026010{i:02d}T000000Z_aabb.json.ack").touch()

    w = TriggerWatcher(str(tmp_path / ".ctrl"), lambda **k: None)
    w._prune(str(ctrl))

    remaining = list(ctrl.iterdir())
    assert len(remaining) == _KEEP_COMPLETED, f"Expected {_KEEP_COMPLETED}, got {len(remaining)}"


# ─────────────────────────────────────────────────────────────────────────────
# P11-11: second rapid trigger → 409
# ─────────────────────────────────────────────────────────────────────────────

def test_second_trigger_rejected(two_token_client, reports_dir):
    """P11-11: second trigger while first run is in progress returns 409."""
    run_dir = os.path.join(reports_dir, "checkout", "20260101T120000Z")
    with open(os.path.join(run_dir, "status.json"), "w") as f:
        json.dump({"state": "running"}, f)

    r1 = two_token_client.post("/api/v1/projects/checkout/runs", headers=_vh("operator"))
    assert r1.status_code == 409


# ─────────────────────────────────────────────────────────────────────────────
# P11-12: completed run re-enables trigger
# ─────────────────────────────────────────────────────────────────────────────

def test_completed_run_allows_trigger(two_token_client, reports_dir):
    """P11-12: after run completes (state=complete) trigger is accepted again."""
    run_dir = os.path.join(reports_dir, "checkout", "20260101T120000Z")
    with open(os.path.join(run_dir, "status.json"), "w") as f:
        json.dump({"state": "complete"}, f)

    r = two_token_client.post("/api/v1/projects/checkout/runs", headers=_vh("operator"))
    assert r.status_code == 202, r.text


# ─────────────────────────────────────────────────────────────────────────────
# P11-13: _ctrl_dir_for creates directory
# ─────────────────────────────────────────────────────────────────────────────

def test_ctrl_dir_created(two_token_client, reports_dir):
    """P11-13: triggering creates the .ctrl/<project>/ directory."""
    ctrl = os.path.join(reports_dir, ".ctrl", "checkout")
    assert not os.path.exists(ctrl) or not os.listdir(ctrl)  # starts empty
    two_token_client.post("/api/v1/projects/checkout/runs", headers=_vh("operator"))
    assert os.path.isdir(ctrl)


# ─────────────────────────────────────────────────────────────────────────────
# P11-14: trigger_id format
# ─────────────────────────────────────────────────────────────────────────────

def test_trigger_id_format(two_token_client):
    """P11-14: trigger_id has format trig_<YYYYMMDDTHHmmss>_<8hex>."""
    import re
    r = two_token_client.post("/api/v1/projects/checkout/runs", headers=_vh("operator"))
    tid = r.json()["trigger_id"]
    assert re.match(r"^trig_\d{8}T\d{6}_[0-9a-f]{8}$", tid), f"Bad format: {tid}"


# ─────────────────────────────────────────────────────────────────────────────
# P11-15: no orchestrator imports in dashboard
# ─────────────────────────────────────────────────────────────────────────────

def test_no_orchestrator_imports():
    """P11-15: dashboard package must not import from orchestrator.*"""
    import ast, pathlib
    violations = []
    dash_dir = pathlib.Path(__file__).resolve().parents[1] / "src" / "dashboard"
    for py_file in dash_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("orchestrator"):
                        violations.append(f"{py_file.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("orchestrator"):
                    violations.append(f"{py_file.name}: from {node.module}")
    assert violations == [], violations


# ─────────────────────────────────────────────────────────────────────────────
# P11-S: single-token client (viewer == operator)
# ─────────────────────────────────────────────────────────────────────────────

def test_single_token_can_trigger(single_token_client):
    """When only DASHBOARD_AUTH_TOKEN is set, that token is both viewer and operator."""
    r = single_token_client.post(
        "/api/v1/projects/checkout/runs",
        headers=_vh("master"),
    )
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "queued"


def test_spawn_backend_claims_before_starting(reports_dir):
    """Dashboard-owned execution is invisible to the scheduler watcher."""
    app = _make_app(
        reports_dir,
        auth_token="viewer",
        operator_token="operator",
        trigger_backend="spawn",
    )
    with patch("dashboard.routes.subprocess.Popen") as popen:
        with TestClient(app, raise_server_exceptions=True) as client:
            response = client.post(
                "/api/v1/projects/checkout/runs", headers=_vh("operator")
            )

    assert response.status_code == 202, response.text
    ctrl_file = os.path.join(
        reports_dir,
        response.json()["ctrl_file"],
    )
    assert ctrl_file.endswith(".json.claimed")
    assert os.path.isfile(ctrl_file)
    popen.assert_called_once()
    assert popen.call_args.args[0][0] == sys.executable
    assert popen.call_args.args[0][1].endswith("src/orchestrator/runtime_trigger.py")


def test_spawn_failure_is_durable_and_returns_503(reports_dir):
    app = _make_app(
        reports_dir,
        auth_token="viewer",
        operator_token="operator",
        trigger_backend="spawn",
    )
    with patch("dashboard.routes.subprocess.Popen", side_effect=OSError("no process")):
        with TestClient(app, raise_server_exceptions=True) as client:
            response = client.post(
                "/api/v1/projects/checkout/runs", headers=_vh("operator")
            )

    assert response.status_code == 503
    ctrl = os.path.join(reports_dir, ".ctrl", "checkout")
    outcomes = [name for name in os.listdir(ctrl) if name.endswith(".json.err")]
    assert len(outcomes) == 1
    with open(os.path.join(ctrl, outcomes[0]), encoding="utf-8") as fh:
        assert "no process" in json.load(fh)["error"]
