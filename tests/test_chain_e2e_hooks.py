"""Project created by the dashboard -> loaded by the runner's loader -> run through chain_hooks.

The only fakes are the outside world: a tiny simulated Windows pair (hop 1 and hop 2 desktops) that
plays both the screen (Computer) and the vision model (client), plus the FreeRDP launcher.  Everything
in between is the real code: procedure_project.create_project, projects.find_project, test_loader,
procedure_runs.start_run, chain_hooks.run_chain_project, ChainController, the step guard, status and
report files, and report.render_spec_report.

No RDP machine, model, Docker or network is contacted.  Fictional credentials only.
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from dashboard import procedure_project
from dashboard import procedure_runs as pr
from dashboard.procedure_intake import build_procedure, update_connections
from orchestrator import chain_hooks, chain_runtime as cr
from orchestrator.models import TestStatus
from orchestrator.projects import find_project, load_manual
from orchestrator.report import render_spec_report
from orchestrator.test_loader import load_spec
from tests.test_procedure_intake_v2 import GOAL, PW1, PW2, _service, _settings

FP = "sha256:" + "cd" * 32
RID = "trig_20261028T150000_e2e00001"


class World:
    """Which desktop input reaches, what is on screen, and what the 'model' says about it."""

    def __init__(self, drop_inner_after_steps=False):
        self.desktop = 1
        self.screen = "desktop"
        self.pending = ""
        self.typed_on = {1: [], 2: []}
        self.secrets = []
        self.shots = 0
        self.drop_after = drop_inner_after_steps
        self.step_commands = 0
        self.nonce = None
        self.closed = []

    # ---- Computer
    def screenshot(self):
        self.shots += 1
        tag = f"{self.screen}:{self.desktop}"
        if self.screen == "connecting":          # one 'Welcome' frame, then the new desktop appears
            self.screen, self.desktop = "desktop", 2
        return NS(png=f"STATE:{tag}".encode())

    def key(self, combo):
        if combo == "super+r" and self.screen == "desktop":
            self.screen = "run"
        elif combo == "Tab" and self.screen == "cred_user":
            self.screen = "cred_pw"
        elif combo == "Return":
            if self.screen == "run":
                if self.pending.startswith("cmd /k"):
                    self.nonce = re.search(r"NRDP-ID-START-([0-9a-f]+)", self.pending).group(1)
                    self.screen = "console"
                elif self.pending.startswith("mstsc /f /v:172.20.33.215"):
                    self.screen = "cred_user"
            elif self.screen == "console" and self.pending == "exit":
                self.screen = "desktop"
            elif self.screen == "cred_pw":
                self.screen = "connecting"

    def type(self, text):
        if self.screen == "run":
            self.pending = text
        elif self.screen == "console":
            self.pending = text
        elif self.screen == "desktop":
            self.typed_on[self.desktop].append(text)
            self.step_commands += 1
            if self.drop_after and self.step_commands >= 1 and self.desktop == 2:
                self.desktop = 1                  # the inner session drops: input now reaches hop 1

    def type_secret(self, text):
        self.secrets.append(text)

    # ---- model
    def observation(self, state):
        screen, desktop = state.split(":")
        if screen == "desktop":
            return dict(state="remote_desktop_ready", focused_field="none", fullscreen=True, confidence=0.95, password_masked=False,
                        identity_evidence="", displayed_username="", console_text="", connection_bar=False)
        base = dict(focused_field="none", fullscreen=True, confidence=0.95, password_masked=False, identity_evidence="",
                    displayed_username="", console_text="", connection_bar=False)
        if screen == "run":
            return dict(base, state="rdp_client_run_dialog")
        if screen == "connecting":
            return dict(base, state="connecting")
        if screen == "cred_user":
            return dict(base, state="credential_prompt", focused_field="username")
        if screen == "cred_pw":
            return dict(base, state="credential_prompt", focused_field="password", password_masked=True, displayed_username="jamuser")
        if screen == "console":
            host, who, ip = ("HOP1PC", "HOP1PC\\operator1", "10.70.115.36") if desktop == "1" else ("HOP2PC", "HOP2PC\\jamuser", "172.20.33.215")
            text = "\n".join(["Microsoft Windows [Version 10.0]", f"NRDP-ID-START-{self.nonce}", host, who,
                              f"   IPv4 Address. . . . . . . . . . . : {ip}", f"NRDP-ID-END-{self.nonce}"])
            return dict(base, state="command_console", console_text=text)
        return dict(base, state="unknown", confidence=0.1)


class Client:
    def __init__(self, world):
        self.world = world
        self.calls = 0

    def invoke(self, *, messages, tools, max_tokens, tool_choice):
        self.calls += 1
        data = messages[0]["content"][0]["source"]["data"]
        state = base64.b64decode(data).decode().replace("STATE:", "")
        return NS(first_tool_use=lambda: NS(input=self.world.observation(state)), content=[])


class Targets:
    def __init__(self, secrets_dir, world):
        self.secrets_dir, self.world = secrets_dir, world
        self.opened, self.closed = [], []
        self.window_id = "w1"
        # pre-typing guard (security D2): a capable adapter reports the foreground truthfully.
        self.fg_present = True
        self.fg_focus_id = None          # None => keyboard is on self.window_id

    def open_target(self, spec):
        self.opened.append(spec)
        return NS(window_name=spec.params["window"], window_id=self.window_id)

    def foreground_state(self, handle):
        title = getattr(handle, "window_name", None)
        return {
            "expected_id": getattr(handle, "window_id", None),
            "expected_name": title,
            "focused_id": self.window_id if self.fg_focus_id is None else self.fg_focus_id,
            "focused_name": title,
            "handle_present": self.fg_present,
        }

    def focus(self, name):
        return "w1"

    def window_covers_display(self, handle):
        return True

    def close_target(self, handle):
        self.closed.append(handle)


@pytest.fixture
def stack(tmp_path, monkeypatch):
    real_sleep = time.sleep
    monkeypatch.setattr(chain_hooks, "CHECKPOINT_TIMEOUT_SECONDS", 20.0)       # a missing ack fails the test, never hangs it
    monkeypatch.setattr(time, "sleep", lambda s: real_sleep(0.0005))         # fast, but always yields (no busy-wait starving the ack thread)
    if os.name != "posix":                                                   # POSIX permission view, as in test_chain_runtime
        def fake(path):
            real = os.lstat(path)
            return NS(st_mode=real.st_mode & ~0o022, st_nlink=real.st_nlink, st_uid=1000)
        monkeypatch.setattr(cr, "_LSTAT", fake)
    settings = _settings(tmp_path)
    service = _service(settings)
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    draft = update_connections(draft.id, [{"order": 1, "certificate_name": "HOP1", "certificate_fingerprint": FP}],
                               settings.wizard_state_root, service)
    made = procedure_project.create_project(draft, specs_root=settings.specs_dir, secrets_root=service._secrets_root())
    project = find_project(made["project_name"], specs_root=settings.specs_dir)
    assert project is not None
    config = project.config
    loaded = []
    for spec_path, group in __import__("orchestrator.runner", fromlist=["_ordered_specs"])._ordered_specs(project.dir):
        spec = load_spec(spec_path, config=config)
        spec.manual_text = load_manual(config.manual_dir)
        loaded.append((spec_path, group, spec, os.path.join(settings.reports_dir, project.name, "ts", "spec"), None))
    pr.configure(reports_root=lambda: settings.reports_dir, launch=lambda p: RID, cancel=lambda p: {})
    yield NS(settings=settings, service=service, draft=draft, project=project, loaded=loaded, name=made["project_name"])
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel)


def run(stack, mode, world=None, agent=None, confirm=None, ack=False):
    world = world or World()
    pr.start_run(stack.draft, stack.name, mode, confirm)
    targets = Targets(stack.service._secrets_root(), world)
    agent = agent or (lambda spec, **kw: NS(status=NS(value="passed"), summary="ok"))
    stopper = None
    if ack:
        stopper = threading.Event()
        control = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID / "control"
        run_dir = control.parent

        def acker():
            done = set()
            while not stopper.is_set():
                try:
                    cp = run_dir / "checkpoint.json"
                    if cp.exists():
                        cid = json.loads(cp.read_text())["id"]
                        if cid not in done:
                            pr.ack_checkpoint(stack.name, RID, cid, "done")
                            done.add(cid)
                except (OSError, ValueError, pr.RunError):
                    pass                    # e.g. Windows refuses to replace a file the runner has open: retry
                stopper.wait(0.01)

        threading.Thread(target=acker, daemon=True).start()
    try:
        results = chain_hooks.run_chain_project(
            project=stack.project, loaded=stack.loaded, reports_dir=stack.settings.reports_dir, run_ts="ts",
            targets=targets, computer=world, client_factory=lambda: Client(world), drive_agent=agent, trigger_id=RID)
    finally:
        if stopper:
            stopper.set()
    run_dir = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID
    status = json.loads((run_dir / "status.json").read_text())
    return results, world, targets, run_dir, status


def test_connection_test_end_to_end_uses_independent_identity_and_never_runs_a_step(stack):
    drove = []
    results, world, targets, run_dir, status = run(stack, "connection_test", agent=lambda s, **k: drove.append(1))
    assert drove == [] and len(results) == 1
    r = results[0]
    assert r.status == TestStatus.PASSED, (r.error, r.summary)
    assert status["state"] == "complete" and status["effective_mode"] == "connection_test" and status["downgraded"] is False
    assert world.secrets == [PW2]                       # only the hop-2 password was typed; hop 1 never was
    assert targets.opened[0].params["password_transport"] == "stdin" and len(targets.opened) == 1
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    assert [h["status"] for h in outcome["hops"]] == ["confirmed", "confirmed"]
    assert any("signed out" in n for n in outcome["notes"]) and any("Teardown" in n for n in outcome["notes"])
    assert len(targets.closed) == 1                      # teardown closed the one window this run opened
    assert "Connection chain" in (run_dir / "chain_report.html").read_text()
    for blob in (json.dumps(status), json.dumps(outcome), r.summary or "", (run_dir / "chain_report.html").read_text()):
        assert PW1 not in blob and PW2 not in blob


def test_chain_result_flows_into_the_standard_html_report(stack):
    results, *_ = run(stack, "connection_test")
    result = results[0]
    os.makedirs(result.evidence_dir, exist_ok=True)
    path = render_spec_report(result, model_id="test-model")
    html = Path(path).read_text(encoding="utf-8")
    assert "172.20.33.215" in html and "Hop 2" in html and "Mode: connection_test" in html
    assert "Not established by this run" in html


@pytest.mark.skip(reason="operating execution is disabled by the connection-only "
                         "qualification (b4r6); the step-driving guards this covers are "
                         "still exercised at session level in tests/test_chain_session.py. "
                         "Re-enable together with operating modes.")
def test_read_only_check_runs_only_read_only_steps_and_skips_the_rest(stack):
    seen = []

    goals = []

    def agent(spec, **kw):
        seen.append(spec.title)
        goals.append(spec.goal)
        kw["computer"].screenshot()
        kw["computer"].type("Get-Service -Name JAMboreeVision")
        return NS(status=NS(value="passed"), summary="ok")

    results, world, targets, run_dir, status = run(stack, "read_only_check", agent=agent)
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    ran = {s["order"] for s in outcome["steps"]}
    skipped = {s["order"] for s in outcome["skipped"]}
    assert ran == {1, 3, 4, 8, 9, 10} and skipped == {2, 5, 6, 7, 11}, (ran, skipped)
    assert not any("Stop-Service" in t or "Start-Service" in t for t in world.typed_on[2])
    assert world.typed_on[2].count("Get-Service -Name JAMboreeVision") == len(seen)
    assert goals and all(g.startswith("Perform ONLY step") and "Do not start, prepare or partly perform any other step." in g for g in goals)
    # before every step the final desktop was re-proved: probe commands = hop1 + hop2 + one per step
    probes = [t for t in world.typed_on[1] + world.typed_on[2]]
    assert not any(t.startswith("cmd /k") for t in probes)      # probe text goes through the Run box, never the desktop
    assert status["state"] in ("complete", "incomplete")


@pytest.mark.skip(reason="operating execution is disabled by the connection-only "
                         "qualification (b4r6); the step-driving guards this covers are "
                         "still exercised at session level in tests/test_chain_session.py. "
                         "Re-enable together with operating modes.")
def test_dropped_inner_session_stops_the_run_before_any_command_reaches_hop_one(stack):
    world = World(drop_inner_after_steps=True)
    calls = []

    def agent(spec, **kw):
        calls.append(spec.title)
        kw["computer"].screenshot()
        kw["computer"].type("Get-Service -Name JAMboreeVision")      # the session drops right after this command
        return NS(status=NS(value="passed"), summary="ok")

    results, world, targets, run_dir, status = run(stack, "read_only_check", world=world, agent=agent)
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    assert outcome["status"] == "failed" and outcome["error"]["code"] == "ACTIVE_DESKTOP_CHANGED"
    assert len(calls) == 1                                 # the agent was never started for the second step
    assert [s["status"] for s in outcome["steps"]] == ["passed", "failed"]
    assert "no input was sent" in outcome["steps"][1]["summary"]
    assert world.typed_on[1] == []                         # nothing the agent typed ever reached hop 1
    assert status["state"] == "failed" and status["error_code"] == "ACTIVE_DESKTOP_CHANGED"


@pytest.mark.skip(reason="operating execution is disabled by the connection-only "
                         "qualification (b4r6); the step-driving guards this covers are "
                         "still exercised at session level in tests/test_chain_session.py. "
                         "Re-enable together with operating modes.")
def test_forbidden_command_is_blocked_by_the_application_not_the_prompt(stack):
    def agent(spec, **kw):
        kw["computer"].screenshot()
        kw["computer"].type("Stop-Process -Name JAMboreeVision")
        return NS(status=NS(value="passed"), summary="ok")

    results, world, targets, run_dir, status = run(stack, "read_only_check", agent=agent)
    r = results[0]
    assert r.status == TestStatus.ERRORED
    assert world.typed_on[2] == []
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    assert outcome["error"]["code"] == "FORBIDDEN_COMMAND"


@pytest.mark.skip(reason="operating execution is disabled by the connection-only "
                         "qualification (b4r6); the step-driving guards this covers are "
                         "still exercised at session level in tests/test_chain_session.py. "
                         "Re-enable together with operating modes.")
def test_full_run_with_checkpoints_runs_every_step_in_order_and_needs_the_operator(stack):
    def agent(spec, **kw):
        comp = kw["computer"]
        comp.screenshot()
        if spec.title.startswith("Step 2:"):
            comp.type("Stop-Service -Name JAMboreeVision")
        elif spec.title.startswith("Step 7:"):
            comp.type("Start-Service -Name JAMboreeVision")
        return NS(status=NS(value="passed"), summary="ok")

    # the draft's project is current; a full run needs a passed test made with these connections
    results, world, targets, run_dir, status = run(stack, "full_run", agent=agent, confirm=stack.name, ack=True)
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    assert outcome["status"] == "passed", outcome["error"]
    assert [s["order"] for s in outcome["steps"]] == list(range(1, 12))
    assert [s["status"] for s in outcome["steps"] if s["order"] in (6, 11)] == ["acknowledged", "acknowledged"]
    assert status["state"] == "complete" and status["effective_mode"] == "full_run" and status["downgraded"] is False
    assert "Stop-Service -Name JAMboreeVision" in world.typed_on[2] and "Start-Service -Name JAMboreeVision" in world.typed_on[2]
    assert world.typed_on[2].index("Stop-Service -Name JAMboreeVision") < world.typed_on[2].index("Start-Service -Name JAMboreeVision")
    assert world.typed_on[1] == []                       # nothing was ever typed into the hop-1 desktop by a step


def test_every_operating_mode_is_refused_end_to_end_and_nothing_is_launched(stack):
    """Dashboard -> runner path: both operating modes are refused before a runner can start.

    This is the end-to-end form of the connection-only qualification.  The refusal happens in
    procedure_runs.start_run, so no run_request.json is written and the launcher is never called.
    The CORRECT confirmation phrase is supplied, proving it cannot bypass the restriction.
    """
    for mode in ("read_only_check", "full_run"):
        with pytest.raises(pr.RunError) as exc:
            pr.start_run(stack.draft, stack.name, mode, stack.name)
        assert exc.value.status_code == 409
        assert "connection tests only" in str(exc.value.message)
    root = Path(stack.settings.reports_dir)
    assert not list(root.rglob("run_request.json")), "a request was written despite the refusal"


def test_a_trusted_operating_request_on_disk_still_runs_zero_steps(stack):
    """Dashboard bypassed: a genuine, confirmed, run-id-bound full_run control file is planted
    directly in the dashboard-owned control directory.  The RUNTIME must still refuse it."""
    world = World()
    pr.start_run(stack.draft, stack.name, "connection_test", None)   # creates the run + control dir
    request = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID / "control" / "run_request.json"
    data = json.loads(request.read_text())
    data.update(mode="full_run", confirm_recorded=True, run_id=RID)  # everything the runtime wants
    request.write_text(json.dumps(data))
    targets = Targets(stack.service._secrets_root(), world)
    results = chain_hooks.run_chain_project(
        project=stack.project, loaded=stack.loaded, reports_dir=stack.settings.reports_dir,
        run_ts="ts", targets=targets, computer=world, client_factory=lambda: Client(world),
        drive_agent=lambda *a, **k: pytest.fail("a procedure step was executed"), trigger_id=RID)
    run_dir = Path(stack.settings.reports_dir) / stack.name / ".nrdp-runs" / RID
    status = json.loads((run_dir / "status.json").read_text())
    assert status["requested_mode"] == "full_run" and status["effective_mode"] == "connection_test"
    assert status["downgraded"] is True
    outcome = json.loads((run_dir / "chain_outcome.json").read_text())
    assert outcome["steps"] == []                       # zero operating steps executed
    # the report must not present the refused operating run as a completed procedure
    assert "REQUESTED MODE WAS full_run" in results[0].summary
    assert world.typed_on[2] == []
