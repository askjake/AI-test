"""Tests for the shared-session (hierarchical context) runner path."""

from __future__ import annotations

import json
import os
import textwrap

from orchestrator import runner
from orchestrator.models import TestResult, TestStatus
from orchestrator.targets import TargetError, TargetHandle


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


class FakeScreenshot:
    png = b"PNGBYTES"


class FakeComputer:
    instances = 0

    def __init__(self):
        FakeComputer.instances += 1

    def screenshot(self):
        return FakeScreenshot()


class FakeTargets:
    """Records open/close/focus calls; never touches a real display."""

    last = None

    def __init__(self, config):
        self.config = config
        self.log_dir = None
        self.open_calls = []
        self.close_calls = 0
        self.focus_calls = []
        FakeTargets.last = self

    def open_target(self, spec):
        self.open_calls.append(spec)
        return TargetHandle(spec.type, "win", "0x1", None)

    def close_target(self, handle):
        self.close_calls += 1

    def focus(self, name):
        self.focus_calls.append(name)
        return "0x1"


def _mk_manual(tmp_path, name="app"):
    """Create a manual dir with a master manual.md OUTSIDE the specs root (required per project)."""
    d = tmp_path.with_name(tmp_path.name + "-manuals") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "manual.md").write_text("MASTER")
    return str(d)


def _vnc_project(tmp_path, manual_dir=None):
    """A hierarchical-session project: root login spec + two nested child specs."""
    manual_dir = manual_dir or _mk_manual(tmp_path)
    _write(
        tmp_path / "app" / "project.yaml",
        f"""
        name: app
        manual_dir: {manual_dir}
        target:
          type: vnc
          host: vnc-host
        vnc_host_allowlist: ["vnc-host"]
        """,
    )
    _write(
        tmp_path / "app" / "00-login.md",
        "# Test: Login\n## Goal\nLog in.\n",
    )
    _write(
        tmp_path / "app" / "records" / "10-create.md",
        "# Test: Create\n## Goal\nCreate a record.\n",
    )
    _write(
        tmp_path / "app" / "records" / "20-search.md",
        "# Test: Search\n## Goal\nSearch a record.\n",
    )


def _run(tmp_path, fake_agent):
    return runner.run_project(
        "app",
        reports_dir=str(tmp_path / "reports"),
        specs_root=str(tmp_path),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: object(),
    )


def test_status_file_is_dashboard_readable_under_restrictive_umask(tmp_path):
    """Container-written status must be readable by the host dashboard user."""
    run_dir = tmp_path / "reports" / "app" / "20260820T182231Z"
    run_dir.mkdir(parents=True)

    previous_umask = os.umask(0o077)
    try:
        runner._write_status(
            str(run_dir),
            state="running",
            specs_total=1,
            current_spec="Login",
        )
    finally:
        os.umask(previous_umask)

    status_path = run_dir / "status.json"
    assert status_path.stat().st_mode & 0o777 == 0o644
    assert json.loads(status_path.read_text())["state"] == "running"


def test_session_opens_and_closes_target_once(tmp_path, monkeypatch):
    _vnc_project(tmp_path)

    def fake(spec, **kw):
        return TestResult(
            title=spec.title, target_type=spec.target_type,
            status=TestStatus.PASSED, passed=True, step_count=1,
        )

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    FakeComputer.instances = 0

    run = _run(tmp_path, fake)

    assert run.spec_total == 3
    assert all(r.status == TestStatus.PASSED for r in run.results)
    # ONE open, ONE close for the whole tree.
    assert len(FakeTargets.last.open_calls) == 1
    assert FakeTargets.last.open_calls[0].type == "vnc"
    assert FakeTargets.last.close_calls == 1
    # ONE computer reused across all specs.
    assert FakeComputer.instances == 1
    # The shared window is re-focused before each spec runs.
    assert FakeTargets.last.focus_calls == ["win", "win", "win"]


def test_session_runs_specs_depth_first(tmp_path, monkeypatch):
    _vnc_project(tmp_path)
    order = []

    def fake(spec, **kw):
        order.append(spec.title)
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    _run(tmp_path, fake)

    # Root file before descending into the records/ subdir.
    assert order == ["Login", "Create", "Search"]


def test_session_accumulates_digest_into_prior_context(tmp_path, monkeypatch):
    _vnc_project(tmp_path)
    seen = []

    def fake(spec, **kw):
        seen.append((spec.title, kw.get("prior_context")))
        return TestResult(
            title=spec.title, target_type=spec.target_type,
            status=TestStatus.PASSED, passed=True,
            summary=f"{spec.title} done",
            ending_state=f"after {spec.title}",
        )

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    # First spec sees no prior context.
    assert seen[0] == ("Login", None)
    # Second spec sees the login's outcome + ending state.
    assert "Login" in seen[1][1]
    assert "after Login" in seen[1][1]
    # Third spec sees both earlier specs.
    assert "Login" in seen[2][1] and "Create" in seen[2][1]
    # Rolled-up session summary is carried on the RunResult.
    assert run.session_summary and "Search" in run.session_summary


def test_session_emits_per_spec_reports(tmp_path, monkeypatch):
    _vnc_project(tmp_path)

    def fake(spec, **kw):
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    for r in run.results:
        assert os.path.isfile(os.path.join(r.evidence_dir, "result.json"))
        assert os.path.isfile(os.path.join(r.evidence_dir, "report.html"))
    # Aggregated report shows the session summary panel.
    with open(os.path.join(run.report_dir, "report.html")) as fh:
        html = fh.read()
    assert "Session summary" in html


def test_session_target_open_failure_errors_all_specs(tmp_path, monkeypatch):
    _vnc_project(tmp_path)

    class FailingTargets(FakeTargets):
        def open_target(self, spec):
            self.open_calls.append(spec)
            raise TargetError("connection refused")

    def fake(spec, **kw):
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)

    run = runner.run_project(
        "app",
        reports_dir=str(tmp_path / "reports"),
        specs_root=str(tmp_path),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FailingTargets(cfg),
        client_factory=lambda: object(),
    )

    assert run.spec_total == 3
    assert all(r.status == TestStatus.ERRORED for r in run.results)
    assert all("target setup failed" in r.error for r in run.results)
    # A failed open means no handle, so close is never called.
    assert FakeTargets.last.close_calls == 0


def test_session_injects_master_manual_into_every_spec(tmp_path, monkeypatch):
    manual = tmp_path.with_name(tmp_path.name + "-manuals") / "app"
    _write(manual / "manual.md", "MASTER MANUAL BODY")
    _vnc_project(tmp_path, manual_dir=str(manual))
    seen = []

    def fake(spec, **kw):
        seen.append((spec.title, spec.manual_text))
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    # Master manual is present on every spec's resolved text, and it is not run as a spec.
    assert run.spec_total == 3
    assert all("MASTER MANUAL BODY" in text for _title, text in seen)


def test_session_ignores_spec_manual_section_and_passes_manual_dir(tmp_path, monkeypatch):
    """A spec no longer names manual pages: every spec gets master-only manual_text, a stray
    ## Manual section is ignored, and the planner is handed the manual/ dir to load pages on
    demand via read_manual_page."""
    manual = tmp_path.with_name(tmp_path.name + "-manuals") / "app"
    _write(manual / "manual.md", "MASTER")
    _write(manual / "create.md", "CREATE DETAIL")
    _vnc_project(tmp_path, manual_dir=str(manual))
    _write(
        tmp_path / "app" / "records" / "10-create.md",
        "# Test: Create\n## Goal\nCreate a record.\n## Manual\n- create.md\n",
    )
    seen = {}

    def fake(spec, **kw):
        seen[spec.title] = {"manual_text": spec.manual_text, "manual_dir": kw.get("manual_dir")}
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    _run(tmp_path, fake)

    # The stray ## Manual section is not resolved into manual_text for any spec (master only).
    assert all("CREATE DETAIL" not in v["manual_text"] for v in seen.values())
    assert all(v["manual_text"] == "MASTER" for v in seen.values())
    # Every spec is handed the project's manual dir so it can read pages on demand.
    expected_dir = str(manual)
    assert all(v["manual_dir"] == expected_dir for v in seen.values())


def test_session_stray_manual_section_does_not_error(tmp_path, monkeypatch):
    """A spec that still carries a ## Manual section is not a load error — it is simply ignored."""
    _vnc_project(tmp_path)
    _write(
        tmp_path / "app" / "records" / "10-create.md",
        "# Test: Create\n## Goal\nCreate.\n## Manual\n- missing.md\n",
    )

    def fake(spec, **kw):
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    assert all(r.status == TestStatus.PASSED for r in run.results)


def test_manual_dir_not_run_as_spec(tmp_path, monkeypatch):
    """A stray in-project manual/ dir is still defensively excluded from spec collection."""
    _vnc_project(tmp_path)
    _write(tmp_path / "app" / "manual" / "manual.md", "MASTER")
    _write(tmp_path / "app" / "manual" / "topic.md", "TOPIC")

    def fake(spec, **kw):
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    # Still exactly the 3 real specs — manual pages are never walked as specs.
    assert run.spec_total == 3
    assert {r.title for r in run.results} == {"Login", "Create", "Search"}


def test_session_spec_with_target_section_errors_only_that_spec(tmp_path, monkeypatch):
    _vnc_project(tmp_path)
    # A spec that still carries a ## Target section is a load error (target lives in project.yaml).
    _write(
        tmp_path / "app" / "records" / "10-create.md",
        "# Test: Create\n## Target\nlocal-app: app=foo\n## Goal\nCreate.\n",
    )

    def fake(spec, **kw):
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)
    run = _run(tmp_path, fake)

    by_title = {r.title: r for r in run.results}
    # A load error titles the result from the filename, since the spec never parsed.
    assert by_title["10-create"].status == TestStatus.ERRORED
    assert "no longer supported" in by_title["10-create"].error
    # Siblings still run normally.
    assert by_title["Login"].status == TestStatus.PASSED
    assert by_title["Search"].status == TestStatus.PASSED
