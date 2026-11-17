"""Phase 5 tests for orchestrator.runner (P5-10..P5-12, evidence + run_project)."""

from __future__ import annotations

import json
import os
import textwrap

from orchestrator import runner
from orchestrator.models import AssertionResult, TestResult, TestStatus
from orchestrator.projects import find_project
from orchestrator.targets import TargetHandle, HostNotAllowedError


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


def _mk_manual(tmp_path, name="checkout", body="MASTER"):
    """Create a manual dir OUTSIDE the specs root (required per project) and return its abs path."""
    d = tmp_path.with_name(tmp_path.name + "-manuals") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "manual.md").write_text(body)
    return str(d)


class FakeScreenshot:
    png = b"PNGBYTES"


class FakeComputer:
    def screenshot(self):
        return FakeScreenshot()


class FakeTargets:
    """Records open/close; never touches a real display."""

    last = None

    def __init__(self, config):
        self.config = config
        self.opened = None
        self.closed = False
        FakeTargets.last = self

    def open_target(self, spec):
        self.opened = spec
        return TargetHandle(spec.type, "win", "0x1", None)

    def close_target(self, handle):
        self.closed = True

    def focus(self, name):
        return "0x1"


class FakeClient:
    pass


def _fake_agent(monkeypatch, *, passed=True):
    """Patch run_planner_agent (imported into runner) to return a canned TestResult."""
    def fake(spec, **kw):
        # Write a fake screenshot so the evidence dir mirrors real output.
        return TestResult(
            title=spec.title,
            target_type=spec.target_type,
            status=TestStatus.PASSED if passed else TestStatus.FAILED,
            passed=passed,
            per_assertion=[AssertionResult(text="ok", passed=passed)],
            declared_assertions=1,
            step_count=1,
        )

    monkeypatch.setattr(runner, "run_planner_agent", fake)


def _isolate_specs_root(tmp_path, monkeypatch):
    """Point project discovery at an empty dir so run_spec (no project/specs_root given) resolves
    to the no-project fallback instead of scanning the real tests_specs/ (whose sample projects
    would now trip the required manual_dir check)."""
    empty = tmp_path / "_empty_specs"
    empty.mkdir(exist_ok=True)
    monkeypatch.setattr(runner.settings, "tests_specs_dir", str(empty))
    from orchestrator import projects as _projects
    monkeypatch.setattr(_projects.settings, "tests_specs_dir", str(empty))


def test_run_spec_writes_evidence(tmp_path, monkeypatch):
    """P5-10: run_spec opens the target, writes result.json, closes the target."""
    _isolate_specs_root(tmp_path, monkeypatch)
    _write(tmp_path / "checkout" / "a.md", "# Test: A Spec\n## Goal\nG\n")
    _fake_agent(monkeypatch)

    result = runner.run_spec(
        str(tmp_path / "checkout" / "a.md"),
        reports_dir=str(tmp_path / "reports"),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )

    assert result.status == TestStatus.PASSED
    assert FakeTargets.last.opened.type == "local-app"
    assert FakeTargets.last.closed is True

    result_json = os.path.join(result.evidence_dir, "result.json")
    assert os.path.isfile(result_json)
    assert os.path.basename(result.evidence_dir) == "a-spec"  # slug of "A Spec"
    with open(result_json) as fh:
        data = json.load(fh)
    assert data["title"] == "A Spec"
    assert data["status"] == "passed"


def test_run_spec_target_failure_is_errored(tmp_path, monkeypatch):
    """A target setup failure yields an errored result, not an exception."""
    _isolate_specs_root(tmp_path, monkeypatch)
    _write(tmp_path / "checkout" / "a.md", "# Test: A\n## Goal\nG\n")
    _fake_agent(monkeypatch)

    class FailingTargets(FakeTargets):
        def open_target(self, spec):
            raise HostNotAllowedError("nope")

    result = runner.run_spec(
        str(tmp_path / "checkout" / "a.md"),
        reports_dir=str(tmp_path / "reports"),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FailingTargets(cfg),
        client_factory=lambda: FakeClient(),
    )
    assert result.status == TestStatus.ERRORED
    assert "target setup failed" in result.error


def test_run_spec_parse_failure_is_errored(tmp_path, monkeypatch):
    """A spec that fails to parse yields an errored result, not an exception.

    Guards the runner's contract that one bad spec (e.g. the shipped TEMPLATE.md with a
    placeholder ## Target) can't abort a whole project run.
    """
    _isolate_specs_root(tmp_path, monkeypatch)
    _write(
        tmp_path / "checkout" / "bad.md",
        "# Test: Bad\n## Target\nnot-a-real-target: x=1\n## Goal\nG\n",
    )
    _fake_agent(monkeypatch)

    result = runner.run_spec(
        str(tmp_path / "checkout" / "bad.md"),
        reports_dir=str(tmp_path / "reports"),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )
    assert result.status == TestStatus.ERRORED
    assert "spec load failed" in result.error
    # Evidence dir + result.json still written so the report shows the failure.
    assert os.path.isfile(os.path.join(result.evidence_dir, "result.json"))


def test_project_discovery_excludes_documentation_templates_and_duplicate_root(tmp_path):
    from orchestrator.projects import discover_projects

    (tmp_path / "TEMPLATE.md").write_text("# Test: Placeholder\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("documentation\n", encoding="utf-8")
    duplicate = tmp_path / tmp_path.name
    duplicate.mkdir()
    (duplicate / "project.yaml").write_text("name: duplicate\n", encoding="utf-8")

    assert discover_projects(str(tmp_path)) == []


def test_run_project_runs_all_specs(tmp_path, monkeypatch):
    """P5-11: run_project runs every spec and returns a RunResult carrying the project."""
    _write(tmp_path / "checkout" / "project.yaml", f"name: checkout\nmanual_dir: {_mk_manual(tmp_path)}\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: A\n## Goal\nG\n")
    _write(tmp_path / "checkout" / "b.md", "# Test: B\n## Goal\nG\n")
    _fake_agent(monkeypatch)

    run = runner.run_project(
        "checkout",
        reports_dir=str(tmp_path / "reports"),
        specs_root=str(tmp_path),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )

    assert run.project == "checkout"
    assert run.total == 2
    assert run.passed_count == 2
    # All evidence lands under one run_ts dir for the project.
    assert run.report_dir.endswith(run.run_ts)
    for r in run.results:
        assert r.evidence_dir.startswith(run.report_dir)


def test_run_project_uses_directory_slug_for_display_named_project(tmp_path, monkeypatch):
    """Dashboard directory identities remain stable when YAML has a display name."""
    _write(
        tmp_path / "stable-slug" / "project.yaml",
        f"name: Pretty Project Name\nmanual_dir: {_mk_manual(tmp_path)}\n",
    )
    _write(tmp_path / "stable-slug" / "a.md", "# Test: A\n## Goal\nG\n")
    _fake_agent(monkeypatch)

    run = runner.run_project(
        "stable-slug",
        reports_dir=str(tmp_path / "reports"),
        specs_root=str(tmp_path),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )

    assert run.project == "stable-slug"
    assert run.report_dir.startswith(str(tmp_path / "reports" / "stable-slug"))


def test_render_single_emits_html(tmp_path, monkeypatch):
    """A single-spec CLI run produces report.html + both indexes, not just result.json."""
    _isolate_specs_root(tmp_path, monkeypatch)
    _write(tmp_path / "checkout" / "a.md", "# Test: A Spec\n## Goal\nG\n")
    _fake_agent(monkeypatch)

    result = runner.run_spec(
        str(tmp_path / "checkout" / "a.md"),
        reports_dir=str(tmp_path / "reports"),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )
    report_path = runner._render_single(result)

    assert report_path is not None and os.path.isfile(report_path)
    assert os.path.basename(report_path) == "report.html"
    run_dir = os.path.dirname(result.evidence_dir)
    project_dir = os.path.dirname(run_dir)
    reports_dir = os.path.dirname(project_dir)
    assert os.path.isfile(os.path.join(project_dir, "index.html"))
    assert os.path.isfile(os.path.join(reports_dir, "index.html"))
    assert os.path.isfile(os.path.join(run_dir, "run.json"))


def test_run_spec_resolves_manual(tmp_path, monkeypatch):
    """A single-spec run resolves the project's manual and attaches it to the spec."""
    manual = _mk_manual(tmp_path, body="MASTER MANUAL")
    _write(tmp_path / "checkout" / "project.yaml", f"name: checkout\nmanual_dir: {manual}\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: A\n## Goal\nG\n")
    project = find_project("checkout", str(tmp_path))

    captured = {}

    def fake(spec, **kw):
        captured["manual_text"] = spec.manual_text
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)

    runner.run_spec(
        str(tmp_path / "checkout" / "a.md"),
        project=project,
        reports_dir=str(tmp_path / "reports"),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )
    assert captured["manual_text"] == "MASTER MANUAL"


def test_run_project_uses_effective_caps(tmp_path, monkeypatch):
    """The project's merged caps are passed through to the agent."""
    _write(tmp_path / "checkout" / "project.yaml", f"name: checkout\nmax_planner_steps: 7\nmanual_dir: {_mk_manual(tmp_path)}\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: A\n## Goal\nG\n")

    captured = {}

    def fake(spec, **kw):
        captured.update(kw)
        return TestResult(title=spec.title, target_type=spec.target_type,
                          status=TestStatus.PASSED, passed=True)

    monkeypatch.setattr(runner, "run_planner_agent", fake)

    runner.run_project(
        "checkout",
        reports_dir=str(tmp_path / "reports"),
        specs_root=str(tmp_path),
        computer_factory=lambda cfg: FakeComputer(),
        targets_factory=lambda cfg: FakeTargets(cfg),
        client_factory=lambda: FakeClient(),
    )
    assert captured["max_planner_steps"] == 7
