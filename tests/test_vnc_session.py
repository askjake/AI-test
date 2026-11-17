"""A VNC procedure created by the dashboard, loaded by the runner's real loader and run through vnc_hooks.

Fakes are only the outside world: the VNC viewer launcher/window (FakeTargets), the screen (FakeScreen: real PNG bytes) and the agent
loop.  Real: build_procedure, create_project, find_project, load_spec, start_run, run_vnc_project, VncSessionController, run_chain_session,
CheckpointGate, status/outcome/report files.  No VNC server, remote desktop, model or network is contacted.
"""
from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from PIL import Image

from dashboard import procedure_project
from dashboard import procedure_runs as pr
from dashboard.procedure_intake import build_procedure
from orchestrator import chain_runtime as cr
from orchestrator import vnc_hooks
from orchestrator.projects import find_project, load_manual
from orchestrator.test_loader import load_spec
from tests.test_procedure_intake_v2 import _service, _settings
from tests.test_vnc_intake import GOAL_NUMBERED as GOAL, VNC_PW

RID = "trig_20261028T160000_vnc00001"


def png(kind="desktop", size=(800, 500)):
    image = Image.new("RGB", size, (0, 0, 0))
    if kind == "desktop":
        for x in range(0, size[0], 4):
            for y in range(0, size[1], 50):
                image.putpixel((x, y), (30 + x % 200, 90, 160))
        image.paste((40, 90, 160), (0, 0, 400, 200))
    buf = io.BytesIO()
    image.save(buf, "PNG")
    return buf.getvalue()


class FakeScreen:
    def __init__(self, frames=None):
        self.frames = list(frames or [])
        self.default = png("desktop")
        self.actions = []

    def screenshot(self):
        return NS(png=self.frames.pop(0) if self.frames else self.default)

    def key(self, *a, **k):
        self.actions.append(("key", a))

    def type_text(self, *a, **k):
        self.actions.append(("type", a))

    def click(self, *a, **k):
        self.actions.append(("click", a))


class FakeProc:
    def __init__(self):
        self.alive = True

    def poll(self):
        return None if self.alive else 1


class FakeTargets:
    def __init__(self, fail_open=None):
        self.opened, self.closed, self.focused = [], [], []
        self.proc = FakeProc()
        self.window_ok = True
        self.fail_open = fail_open

    def open_target(self, spec):
        self.opened.append(spec)
        if self.fail_open:
            raise self.fail_open
        return NS(type="vnc", window_name="TigerVNC", window_id="77", process=self.proc, auxiliary_processes=())

    def focus(self, name):
        self.focused.append(name)
        return "77" if self.window_ok else None

    def close_target(self, handle):
        self.closed.append(handle)


@pytest.fixture
def stack(tmp_path, monkeypatch):
    real_sleep = time.sleep
    monkeypatch.setattr(vnc_hooks, "CHECKPOINT_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(time, "sleep", lambda s: real_sleep(0.0005))
    if os.name != "posix":
        def fake(path):
            real = os.lstat(path)
            return NS(st_mode=real.st_mode & ~0o022, st_nlink=real.st_nlink, st_uid=1000)
        monkeypatch.setattr(cr, "_LSTAT", fake)
    settings = _settings(tmp_path)
    service = _service(settings)
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    made = procedure_project.create_project(draft, specs_root=settings.specs_dir, secrets_root=service._secrets_root())
    project = find_project(made["project_name"], specs_root=settings.specs_dir)
    assert project is not None and project.config.target.type == "vnc"
    loaded = []
    for spec_path, group in __import__("orchestrator.runner", fromlist=["_ordered_specs"])._ordered_specs(project.dir):
        spec = load_spec(spec_path, config=project.config)
        spec.manual_text = load_manual(project.config.manual_dir)
        loaded.append((spec_path, group, spec, os.path.join(settings.reports_dir, project.name, "ts", "spec"), None))
    pr.configure(reports_root=lambda: settings.reports_dir, launch=lambda p: RID, cancel=lambda p: {})
    yield NS(settings=settings, service=service, draft=draft, project=project, loaded=loaded, name=made["project_name"])
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel)


def run(stack, mode, *, screen=None, targets=None, agent=None, confirm=None, request=True, cancel=None,
        lift=None, trigger=None):
    """``lift`` is a monkeypatch fixture and is ONLY for the step-machinery tests below.

    Passing it clears the connection-only policy constants so the per-step execution machinery
    (per-step goals, dropped viewer, blank screen, cancellation) can still be exercised.  It is
    deliberately explicit and per-test: production keeps the policy, and the production refusal is
    proved WITHOUT any lift by the production-path test at the end of this module and by
    tests/test_connection_only.py.
    """
    if lift is not None:
        lift.setattr(cr, "CONNECTION_ONLY", False)
        lift.setattr(pr, "CONNECTION_ONLY", False)
        # CP43 replaced chain_hooks' constant-based check with a hard allow-list that ignores CONNECTION_ONLY (a deliberate hardening: production can
        # NOT run steps without a reviewed source change).  These step-machinery tests therefore also restore, for THIS test only, the pre-CP43 semantic
        # "an operating mode passes when the policy constant is lifted"; every other mode shape is still judged by the real allow-list.
        from orchestrator import browser_modes as _bm
        from orchestrator import chain_hooks as _ch
        _real_enforce = _ch._enforce_connection_only

        def _lifted_enforce(req):
            if getattr(req, "refused", False) is True or not _bm.is_canonical(req.mode) or req.mode == _bm.BROWSER_VERIFY:
                return _real_enforce(req)
            return req if cr.operating_execution_allowed(req.mode) else _real_enforce(req)
        lift.setattr(_ch, "_enforce_connection_only", _lifted_enforce)
    screen = screen or FakeScreen()
    targets = targets or FakeTargets()
    goals = []

    def default_agent(spec, **kw):
        goals.append((spec.goal, spec.manual_text, kw.get("computer")))
        return NS(status=NS(value="passed"), summary="ok")

    if request:
        pr.start_run(stack.draft, stack.name, mode, confirm)
    results = vnc_hooks.run_vnc_project(
        project=stack.project, loaded=stack.loaded, reports_dir=stack.settings.reports_dir, run_ts="ts", targets=targets, computer=screen,
        client_factory=lambda: object(), drive_agent=agent or default_agent,
        trigger_id=(trigger or RID) if (request or trigger) else None, cancel_event=cancel)
    run_dir = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID
    if not request and not trigger:
        run_dir = Path(stack.settings.reports_dir) / stack.name / "ts"
    return results, screen, targets, run_dir, goals


def read(run_dir, name):
    return json.loads((run_dir / name).read_text())


def test_connection_test_opens_the_viewer_confirms_a_picture_and_runs_no_step(stack):
    results, screen, targets, run_dir, goals = run(stack, "connection_test")
    assert results[0].status.value == "passed" and goals == []
    spec = targets.opened[0]
    assert spec.type == "vnc" and spec.params["host"] == "192.0.2.47" and spec.params["port"] == "5900"
    assert spec.params["password_file"].endswith(".vnc.pw") and spec.params.get("window", "TigerVNC") == "TigerVNC"
    assert VNC_PW not in json.dumps(spec.params) and "example-user" not in json.dumps(spec.params)
    status = read(run_dir, "status.json")
    assert status["state"] == "complete" and status["protocol"] == "vnc" and status["effective_mode"] == "connection_test" and status["downgraded"] is False
    progress = read(run_dir, "chain_progress.json")
    assert progress["protocol"] == "vnc" and progress["hops"][0]["status"] == "confirmed"
    outcome = read(run_dir, "chain_outcome.json")
    assert outcome["agent_invoked"] is False and any("does not expose a machine or account identity" in n for n in outcome["notes"])
    assert list((run_dir / "evidence").glob("vnc-*.png"))
    assert len(targets.closed) == 1 and screen.actions == []                    # the viewer was closed; no input was ever sent to the remote


def test_a_blank_picture_fails_with_a_clear_code_and_still_closes_only_the_viewer(stack):
    black = png("black")
    results, screen, targets, run_dir, goals = run(stack, "connection_test", screen=FakeScreen([black] * 40))
    assert results[0].status.value == "failed" or results[0].status.value == "errored"
    outcome = read(run_dir, "chain_outcome.json")
    assert outcome["error"]["code"] == "VNC_NO_PICTURE" and "password" in outcome["error"]["message"] and goals == []
    assert len(targets.closed) == 1


def test_a_viewer_that_cannot_open_reports_only_the_exception_type(stack):
    boom = RuntimeError("xtigervncviewer -passwd /secrets/host.vnc.pw 192.0.2.47 failed: " + VNC_PW)
    results, screen, targets, run_dir, goals = run(stack, "connection_test", targets=FakeTargets(fail_open=boom))
    outcome = read(run_dir, "chain_outcome.json")
    assert outcome["error"]["code"] == "VNC_OPEN_FAILED" and "RuntimeError" in outcome["error"]["message"]
    blob = json.dumps(outcome) + (run_dir / "chain_report.html").read_text() + json.dumps(read(run_dir, "chain_progress.json"))
    assert VNC_PW not in blob and "/secrets/" not in blob and goals == []


def test_full_run_executes_each_step_alone_and_leaves_remote_applications_open(stack, monkeypatch):
    """STEP-MACHINERY TEST (policy lifted explicitly): proves per-step execution still works.
    Production availability of full_run is refused -- see the production-path test below."""
    results, screen, targets, run_dir, goals = run(stack, "full_run", confirm=stack.name, lift=monkeypatch)
    assert results[0].status.value == "passed" and len(goals) == 5
    for number, (goal, manual, computer) in enumerate(goals, 1):
        assert goal.startswith(f"Perform ONLY step {number} on the VNC desktop")
        assert "Leave applications you open running" in goal
        assert "CONNECTION CHAIN CONTEXT" not in manual and "Leave every application you open" in manual and "never log off, lock or shut down" in manual
        assert computer is screen                                              # the agent drives the plain screen: no Windows guard is pretended
    assert "Leave the browser open" in goals[4][0]
    summary = results[0].summary
    assert "left open" in summary and "not logged off, locked or shut down" in summary
    assert len(targets.closed) == 1 and targets.closed[0] is not None           # only the runner's own viewer; nothing remote was closed
    assert not any(a[0] == "key" for a in screen.actions)                       # the application itself sent no key (no Alt+F4 / logoff / lock)
    status = read(run_dir, "status.json")
    assert status["state"] == "complete" and status["result"] == "passed"


def test_a_run_without_a_trusted_request_is_downgraded_to_a_connection_test_and_says_so(stack):
    results, screen, targets, run_dir, goals = run(stack, "full_run", request=False)
    assert goals == [] and results[0].status.value == "passed"
    status = read(run_dir, "status.json")
    assert status["effective_mode"] == "connection_test" and status["downgraded"] is True and status["downgrade_reason"]
    assert "CONNECTION_TEST ONLY" in results[0].summary.upper() or "connection_test only" in results[0].summary


def test_a_dropped_viewer_stops_the_run_before_the_next_step_and_replays_nothing(stack, monkeypatch):
    """STEP-MACHINERY TEST (policy lifted explicitly)."""
    targets = FakeTargets()
    calls = []

    def agent(spec, **kw):
        calls.append(spec.goal.split(":")[0])
        if len(calls) == 2:
            targets.proc.alive = False                                           # the session drops during step 2
        return NS(status=NS(value="passed"), summary="ok")

    results, screen, _t, run_dir, goals = run(stack, "full_run", targets=targets, agent=agent,
                                               confirm=stack.name, lift=monkeypatch)
    outcome = read(run_dir, "chain_outcome.json")
    assert len(calls) == 2 and results[0].status.value in ("failed", "errored")
    assert outcome["error"]["code"] == "ACTIVE_DESKTOP_CHANGED" and "VNC_DISCONNECTED" in outcome["error"]["message"]
    assert [s["order"] for s in outcome["steps"] if s["status"] == "passed"] == [1, 2] and len(targets.closed) == 1


def test_a_blank_screen_before_a_step_sends_no_input_for_that_step(stack, monkeypatch):
    """STEP-MACHINERY TEST (policy lifted explicitly)."""
    screen = FakeScreen()
    targets = FakeTargets()
    calls = []

    def agent(spec, **kw):
        calls.append(1)
        screen.frames = [png("black")] * 50                                       # the picture disappears after step 1
        return NS(status=NS(value="passed"), summary="ok")

    results, _s, _t, run_dir, goals = run(stack, "full_run", screen=screen, targets=targets,
                                           agent=agent, confirm=stack.name, lift=monkeypatch)
    outcome = read(run_dir, "chain_outcome.json")
    assert len(calls) == 1 and outcome["error"]["code"] == "ACTIVE_DESKTOP_CHANGED" and "VNC_NO_PICTURE" in outcome["error"]["message"]


def test_cancel_stops_before_the_next_step_and_closes_the_viewer(stack, monkeypatch):
    """STEP-MACHINERY TEST (policy lifted explicitly): cancellation must still stop the run."""
    cancel = threading.Event()
    calls = []

    def agent(spec, **kw):
        calls.append(1)
        cancel.set()
        return NS(status=NS(value="passed"), summary="ok")

    results, screen, targets, run_dir, goals = run(stack, "full_run", agent=agent,
                                                   confirm=stack.name, cancel=cancel, lift=monkeypatch)
    assert len(calls) == 1 and read(run_dir, "status.json")["state"] == "cancelled" and len(targets.closed) == 1


# ------------------------------------------------- production path: operating modes unavailable
#
# vnc_hooks.run_vnc_project is the SECOND production caller of chain_runtime.run_chain_session
# (chain_hooks.run_chain_project is the first).  It obtains its RunRequest from the SHARED
# chain_hooks._await_request funnel, so the connection-only policy applies to it too.  No policy
# lift here: this is the real shipped behaviour.
def test_a_requested_full_run_is_refused_by_the_vnc_production_path(stack):
    """A genuine, dashboard-shaped, trusted, confirmed, run-id-bound full_run control file is
    written directly (as the dashboard would if the API gate were bypassed).  The runner must
    still execute ZERO steps and must not present the run as a completed operating procedure."""
    control = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID / "control"
    control.mkdir(parents=True, exist_ok=True)
    (control / "run_request.json").write_text(json.dumps(
        {"mode": "full_run", "project": stack.name, "chain": True,
         "confirm_recorded": True, "run_id": RID, "steps_allowed": True}))

    # request=False skips the dashboard API (that gate is proved separately); trigger=RID keeps the
    # real run id, so this models the API gate being bypassed entirely.
    results, screen, targets, run_dir, goals = run(stack, "full_run", request=False, trigger=RID)

    assert goals == []                                  # the agent was never asked to do a step
    outcome = read(run_dir, "chain_outcome.json")
    assert outcome["mode"] == "connection_test"
    assert outcome["requested_mode"] == "full_run"      # the request stays visible
    assert outcome["downgraded"] is True
    assert "connection-only" in outcome["downgrade_reason"]
    assert outcome["steps"] == []                       # zero operating steps executed
    status = read(run_dir, "status.json")
    assert status["effective_mode"] == "connection_test" and status["downgraded"] is True
    assert status["state"] in ("complete", "failed", "error", "incomplete")   # terminal, not "running"
    # the operator-facing summary must not read as a completed operating procedure
    assert "not a completed operating procedure" in results[0].summary
    assert "REQUESTED MODE WAS full_run" in results[0].summary
    assert VNC_PW not in results[0].summary


def test_desktop_picture_check():
    assert vnc_hooks.desktop_looks_usable(png("desktop"))[0] is True
    assert vnc_hooks.desktop_looks_usable(png("black"))[0] is False
    assert vnc_hooks.desktop_looks_usable(png("desktop", (100, 80)))[0] is False
    assert vnc_hooks.desktop_looks_usable(b"not a png")[0] is False


def test_the_runner_routes_only_dashboard_vnc_procedures_to_the_hook():
    src = (Path(__file__).resolve().parents[1] / "src" / "orchestrator" / "runner.py").read_text()
    assert 'config.target.type", None) == "vnc" and (getattr(config, "procedure", None) or {}).get("protocol") == "vnc"' in src.replace("getattr(config.target, \"type\"", "getattr(config.target, \"type") or \
        'getattr(config.target, "type", None) == "vnc" and (getattr(config, "procedure", None) or {}).get("protocol") == "vnc"' in src
    assert src.count("run_vnc_project") == 2
