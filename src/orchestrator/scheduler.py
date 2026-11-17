"""Cron-style scheduling, one trigger per project (Phase 7).

Registers **one cron trigger per enabled project** (its ``schedule``, falling back to
``default_cron`` from :mod:`orchestrator.config`) on an APScheduler scheduler. On a project's
trigger it runs that project via :func:`orchestrator.runner.run_project` — which itself renders
the run report and refreshes the per-project and top-level ``index.html``.

Two run modes:

- **Long-running** (default): a foreground scheduler stays up and fires each project on its
  own schedule. This is the container's default command.
- **One-shot** (``--once``): run every enabled project once and exit (for external
  cron/systemd). ``--project <name>`` narrows either mode to a single project.

APScheduler is imported lazily inside :func:`start` so the one-shot path and the
schedule-plan helpers stay importable (and unit-testable) without the dependency present.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Callable, NamedTuple, Optional

from .config import settings
from .models import Project, RunResult
from .projects import discover_projects, find_project, project_slug
from . import runner
from .trigger_watcher import TriggerWatcher

logger = logging.getLogger("orchestrator.scheduler")


class ScheduledJob(NamedTuple):
    """A project paired with the cron expression it should run on."""

    project: str
    cron: str


def _log_run(run: RunResult) -> None:
    """Emit a structured, project-tagged log line for one completed run."""
    logger.info(
        "scheduled run complete",
        extra={
            "project": run.project,
            "run_ts": run.run_ts,
            "total": run.total,
            "passed": run.passed_count,
            "failed": run.failed_count,
            "errored": run.errored_count,
            "duration_seconds": round(run.duration_seconds, 1),
        },
    )


def build_schedule_plan(specs_root: str | None = None) -> list[ScheduledJob]:
    """Return one :class:`ScheduledJob` per enabled project that has at least one spec.

    A project's cron is its merged ``schedule`` (from ``project.yaml``), falling back to
    the global ``default_cron`` when unset. Projects with no specs are skipped — there is
    nothing to run (P7-1).
    """
    plan: list[ScheduledJob] = []
    for project in discover_projects(specs_root):
        if not project.specs:
            continue
        cron = project.config.schedule or settings.default_cron
        plan.append(ScheduledJob(project=project_slug(project), cron=cron))
    return plan


def run_project_once(
    name: str,
    *,
    specs_root: str | None = None,
    reports_dir: str | None = None,
) -> RunResult:
    """Run one project now (rendering its report) and log the outcome (P7-2/P7-3)."""
    logger.info("scheduled run starting", extra={"project": name})
    run = runner.run_project(name, reports_dir=reports_dir, specs_root=specs_root)
    _log_run(run)
    return run


def run_once(
    project: str | None = None,
    *,
    specs_root: str | None = None,
    reports_dir: str | None = None,
) -> list[RunResult]:
    """Run all enabled projects once (or just ``project``) and return their results (P7-4/P7-5)."""
    if project is not None:
        selected = find_project(project, specs_root, include_disabled=True)
        if selected is None:
            raise ValueError(f"no enabled project named {project!r} under the specs root")
        names = [project_slug(selected)]
    else:
        names = [project_slug(p) for p in discover_projects(specs_root) if p.specs]

    run_selected = run_requested_project_once if project is not None else run_project_once
    return [
        run_selected(name, specs_root=specs_root, reports_dir=reports_dir)
        for name in names
    ]


def run_requested_project_once(name: str, *, specs_root: str | None = None,
                               reports_dir: str | None = None) -> RunResult:
    """Explicit single-project request; does not change scheduling eligibility."""
    run = runner.run_project(name, reports_dir=reports_dir, specs_root=specs_root, allow_disabled=True)
    _log_run(run)
    return run


def start(
    project: str | None = None,
    *,
    specs_root: str | None = None,
    reports_dir: str | None = None,
    scheduler_factory: Optional[Callable[[], object]] = None,
    block: bool = True,
) -> object:
    """Register one cron trigger per (selected) project and run the scheduler (P7-1/P7-6).

    Each project's trigger calls :func:`run_project_once`. With ``block=True`` (the default)
    this runs APScheduler's :class:`BlockingScheduler` in the foreground until interrupted;
    ``block=False`` returns the started scheduler (used by tests with an injected
    ``scheduler_factory``). APScheduler is imported lazily so importing this module never
    requires it.
    """
    plan = build_schedule_plan(specs_root)
    if project is not None:
        selected = find_project(project, specs_root)
        if selected is None:
            raise ValueError(f"no enabled project named {project!r} under the specs root")
        selected_slug = project_slug(selected)
        plan = [job for job in plan if job.project == selected_slug]

    if scheduler_factory is None:
        from apscheduler.schedulers.blocking import BlockingScheduler

        scheduler_factory = BlockingScheduler

    from apscheduler.triggers.cron import CronTrigger

    scheduler = scheduler_factory()
    for job in plan:
        scheduler.add_job(
            run_project_once,
            trigger=CronTrigger.from_crontab(job.cron),
            kwargs={"name": job.project, "specs_root": specs_root, "reports_dir": reports_dir},
            id=f"project:{job.project}",
            name=job.project,
            replace_existing=True,
        )
        logger.info("registered cron trigger", extra={"project": job.project, "cron": job.cron})

    # ── Phase 11: trigger-file watcher (on-demand runs from dashboard) ──
    from .config import settings as _settings
    import os as _os
    _ctrl_dir = _os.path.join(
        reports_dir if reports_dir is not None else _settings.reports_dir,
        '.ctrl',
    )
    _watcher = TriggerWatcher(
        ctrl_dir=_ctrl_dir,
        run_fn=run_requested_project_once,
        reports_dir=reports_dir,
        specs_root=specs_root,
    )
    scheduler.add_job(
        _watcher.check,
        trigger='interval',
        seconds=2,
        id='trigger_watcher',
        name='trigger_watcher',
        replace_existing=True,
        max_instances=1,
    )
    logger.info('trigger watcher registered (ctrl_dir: %s)', _ctrl_dir)

    if not plan:
        logger.warning("no enabled projects with specs to schedule")

    if block:
        try:
            scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown()
    return scheduler


def _configure_logging() -> None:
    """Structured-ish per-run logging: project name and run fields on every line (P7-7)."""
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s "
            "project=%(project)s %(message)s",
            defaults={"project": "-"},
        )
    )
    level_name = os.environ.get("ORCHESTRATOR_LOG_LEVEL", "INFO").upper()
    root = logging.getLogger("orchestrator")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level_name, logging.INFO))
    root.propagate = False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m orchestrator.scheduler",
        description="Schedule per-project test runs (cron), or run them once.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run enabled projects once and exit (all, or just --project).",
    )
    parser.add_argument(
        "--project",
        help="Run/schedule only this project (instead of every enabled project).",
    )
    args = parser.parse_args(argv)

    _configure_logging()

    if args.once:
        runs = run_once(args.project)
        failed = sum(r.failed_count + r.errored_count for r in runs)
        return 0 if failed == 0 else 1

    start(args.project)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
