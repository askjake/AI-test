"""Phase 7 tests for orchestrator.scheduler (P7-1..P7-7).

A fake scheduler captures the jobs that would be registered, and ``runner.run_project`` is
patched to return a canned RunResult so nothing touches a real display, Bedrock, or
APScheduler.
"""

from __future__ import annotations

import logging
import textwrap

from orchestrator import scheduler
from orchestrator.models import AssertionResult, RunResult, TestResult, TestStatus


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


def _manual_dir(tmp_path, name):
    """Create a manual dir (with master manual.md) OUTSIDE the specs root; return its abs path.

    Every project's project.yaml now requires a manual_dir, so scheduler fixtures declare one.
    It lives outside the specs root so discovery doesn't treat the manual dir as a project.
    """
    d = tmp_path.with_name(tmp_path.name + "-manuals") / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "manual.md").write_text("MASTER")
    return str(d)


def _project_yaml(tmp_path, name, extra=""):
    """A minimal project.yaml body carrying the required manual_dir plus optional extra lines."""
    return f"name: {name}\nmanual_dir: {_manual_dir(tmp_path, name)}\n{extra}"


def _fake_run_project(monkeypatch, recorder=None):
    """Patch runner.run_project to record calls and return a canned RunResult."""
    def fake(name, *, run_ts=None, reports_dir=None, specs_root=None, **kw):
        if recorder is not None:
            recorder.append(name)
        return RunResult(
            project=name,
            run_ts="20260611T000000Z",
            results=[
                TestResult(title="t", target_type="local-app",
                           status=TestStatus.PASSED, passed=True,
                           per_assertion=[AssertionResult(text="ok", passed=True)],
                           declared_assertions=1)
            ],
        )
    monkeypatch.setattr(scheduler.runner, "run_project", fake)


class FakeScheduler:
    """Captures add_job calls; start/shutdown are no-ops."""

    def __init__(self):
        self.jobs = []
        self.started = False

    def add_job(self, func, *, trigger, id, name, replace_existing=False,
                 kwargs=None, **_extra):
        self.jobs.append({"func": func, "trigger": trigger, "kwargs": kwargs,
                          "id": id, "name": name})

    def start(self):
        self.started = True

    def shutdown(self):
        self.started = False


def test_build_schedule_plan_per_project(tmp_path):
    """P7-1: one trigger per enabled project; per-project schedule, else default_cron."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout", 'schedule: "*/5 * * * *"\n'))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "backups" / "project.yaml", _project_yaml(tmp_path, "backups"))
    _write(tmp_path / "backups" / "b.md", "# Test: b\n## Goal\nG\n")  # no schedule -> default

    plan = {j.project: j.cron for j in scheduler.build_schedule_plan(str(tmp_path))}
    assert plan["checkout"] == "*/5 * * * *"
    assert plan["backups"] == scheduler.settings.default_cron


def test_schedule_and_run_use_slug_when_yaml_name_is_display_only(tmp_path, monkeypatch):
    _write(
        tmp_path / "stable-slug" / "project.yaml",
        _project_yaml(tmp_path, "Pretty Project Name"),
    )
    _write(tmp_path / "stable-slug" / "a.md", "# Test: a\n## Goal\nG\n")
    ran = []
    _fake_run_project(monkeypatch, ran)

    plan = scheduler.build_schedule_plan(str(tmp_path))
    assert [job.project for job in plan] == ["stable-slug"]
    scheduler.run_once("Pretty Project Name", specs_root=str(tmp_path))
    assert ran == ["stable-slug"]


def test_build_schedule_plan_skips_specless_project(tmp_path):
    """A project directory with no *.md specs is not scheduled."""
    _write(tmp_path / "empty" / "project.yaml", _project_yaml(tmp_path, "empty"))
    _write(tmp_path / "real" / "project.yaml", _project_yaml(tmp_path, "real"))
    _write(tmp_path / "real" / "a.md", "# Test: a\n## Goal\nG\n")

    names = {j.project for j in scheduler.build_schedule_plan(str(tmp_path))}
    assert names == {"real"}


def test_start_registers_one_trigger_per_project(tmp_path):
    """P7-1: start() adds one job per enabled project on the fake scheduler."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "backups" / "project.yaml", _project_yaml(tmp_path, "backups"))
    _write(tmp_path / "backups" / "b.md", "# Test: b\n## Goal\nG\n")

    fake = FakeScheduler()
    scheduler.start(
        specs_root=str(tmp_path),
        scheduler_factory=lambda: fake,
        block=False,
    )
    ids = {job["id"] for job in fake.jobs if job["id"].startswith("project:")}
    assert ids == {"project:checkout", "project:backups"}


def test_trigger_runs_project(tmp_path, monkeypatch):
    """P7-2/P7-3: a registered job's func runs the project via runner.run_project."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    ran = []
    _fake_run_project(monkeypatch, ran)

    fake = FakeScheduler()
    scheduler.start(specs_root=str(tmp_path), scheduler_factory=lambda: fake, block=False)

    # Invoke the registered job exactly as APScheduler would.
    job = fake.jobs[0]
    job["func"](**job["kwargs"])
    assert ran == ["checkout"]


def test_run_once_all_projects(tmp_path, monkeypatch):
    """P7-4: --once runs every enabled project once."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "backups" / "project.yaml", _project_yaml(tmp_path, "backups"))
    _write(tmp_path / "backups" / "b.md", "# Test: b\n## Goal\nG\n")
    ran = []
    _fake_run_project(monkeypatch, ran)

    runs = scheduler.run_once(specs_root=str(tmp_path))
    assert sorted(ran) == ["backups", "checkout"]
    assert len(runs) == 2


def test_run_once_single_project(tmp_path, monkeypatch):
    """P7-5: --project narrows the run to one project."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "backups" / "project.yaml", _project_yaml(tmp_path, "backups"))
    _write(tmp_path / "backups" / "b.md", "# Test: b\n## Goal\nG\n")
    ran = []
    _fake_run_project(monkeypatch, ran)

    scheduler.run_once("checkout", specs_root=str(tmp_path))
    assert ran == ["checkout"]


def test_run_once_unknown_project_raises(tmp_path):
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    try:
        scheduler.run_once("nope", specs_root=str(tmp_path))
    except ValueError as exc:
        assert "nope" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown project")


def test_start_single_project_filters_plan(tmp_path):
    """P7-5: start(project=...) registers only that project's trigger."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "backups" / "project.yaml", _project_yaml(tmp_path, "backups"))
    _write(tmp_path / "backups" / "b.md", "# Test: b\n## Goal\nG\n")

    fake = FakeScheduler()
    scheduler.start("checkout", specs_root=str(tmp_path),
                    scheduler_factory=lambda: fake, block=False)
    assert [job["id"] for job in fake.jobs if job["id"].startswith("project:")] == ["project:checkout"]


def test_log_run_is_structured(tmp_path, monkeypatch, caplog):
    """P7-7: each run is logged with project-tagged structured fields."""
    _write(tmp_path / "checkout" / "project.yaml", _project_yaml(tmp_path, "checkout"))
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _fake_run_project(monkeypatch)

    with caplog.at_level(logging.INFO, logger="orchestrator.scheduler"):
        scheduler.run_project_once("checkout", specs_root=str(tmp_path))

    records = [r for r in caplog.records if r.msg == "scheduled run complete"]
    assert records, "expected a 'scheduled run complete' log record"
    rec = records[0]
    assert rec.project == "checkout"
    assert rec.passed == 1
    assert rec.total == 1
