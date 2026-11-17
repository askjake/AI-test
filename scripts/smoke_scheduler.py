#!/usr/bin/env python3
"""Phase 7 exit gate (P7-GATE): a short per-project cron produces fresh reports.

Rewrites each discovered project's effective ``schedule`` to fire every minute, starts a
background scheduler against ``tests_specs/``, and waits for a fresh timestamped report
tree to appear under ``reports/<project>/``. Also exercises the ``--once`` and
``--project`` one-shot paths.

Run inside the (podman) container, where Xvfb + a WM are up via entrypoint.sh, so the
agent loop can actually open windows and screenshot them:

    python scripts/smoke_scheduler.py

Exits 0 if the one-shot paths run and the cron produces a fresh report within the wait
window, 1 otherwise. The cron leg is time-based; pass ``--no-cron`` to skip it and verify
only the one-shot modes (useful where waiting a full minute is undesirable).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, "src")

from orchestrator import scheduler  # noqa: E402
from orchestrator.config import settings  # noqa: E402
from orchestrator.projects import discover_projects  # noqa: E402


def _report_dirs(reports_dir: str, project: str) -> set[str]:
    base = os.path.join(reports_dir, project)
    if not os.path.isdir(base):
        return set()
    return {e for e in os.listdir(base) if os.path.isdir(os.path.join(base, e))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 7 scheduler smoke / exit gate.")
    parser.add_argument("--no-cron", action="store_true", help="Skip the timed cron leg.")
    parser.add_argument("--wait", type=int, default=90, help="Seconds to wait for a cron run.")
    args = parser.parse_args()

    specs_root = settings.tests_specs_dir
    reports_dir = settings.reports_dir
    projects = [p.name for p in discover_projects(specs_root) if p.specs]
    if not projects:
        print(f"[smoke] FAIL — no enabled projects with specs under {specs_root!r}", file=sys.stderr)
        return 1
    print(f"[smoke] discovered projects: {projects}")

    # 1) one-shot: a single project.
    one = projects[0]
    runs = scheduler.run_once(one)
    if len(runs) != 1 or runs[0].project != one:
        print("[smoke] FAIL — --once --project did not run exactly the named project", file=sys.stderr)
        return 1
    print(f"[smoke] --once --project {one}: OK ({runs[0].total} test(s))")

    # 2) one-shot: all projects.
    runs = scheduler.run_once()
    if {r.project for r in runs} != set(projects):
        print("[smoke] FAIL — --once did not cover every enabled project", file=sys.stderr)
        return 1
    print(f"[smoke] --once (all): OK ({len(runs)} project run(s))")

    if args.no_cron:
        print("[smoke] PASS — one-shot modes verified (cron leg skipped)")
        return 0

    # 3) cron leg: force every-minute schedules, run the scheduler in the background,
    #    and wait for a new timestamped report tree per project.
    before = {p: _report_dirs(reports_dir, p) for p in projects}

    from apscheduler.schedulers.background import BackgroundScheduler

    every_minute = "* * * * *"
    plan = scheduler.build_schedule_plan(specs_root)
    sch = BackgroundScheduler()
    from apscheduler.triggers.cron import CronTrigger

    for job in plan:
        sch.add_job(
            scheduler.run_project_once,
            trigger=CronTrigger.from_crontab(every_minute),
            kwargs={"name": job.project, "specs_root": specs_root, "reports_dir": reports_dir},
            id=f"project:{job.project}",
            name=job.project,
            replace_existing=True,
        )
    sch.start()
    print(f"[smoke] every-minute cron started for {len(plan)} project(s); waiting up to {args.wait}s")

    fresh: set[str] = set()
    deadline = time.monotonic() + args.wait
    try:
        while time.monotonic() < deadline and fresh != set(projects):
            time.sleep(2)
            for p in projects:
                if _report_dirs(reports_dir, p) - before[p]:
                    fresh.add(p)
    finally:
        sch.shutdown(wait=False)

    if fresh == set(projects):
        print(f"[smoke] PASS — fresh timestamped reports appeared for: {sorted(fresh)}")
        return 0
    missing = sorted(set(projects) - fresh)
    print(f"[smoke] FAIL — no fresh report within {args.wait}s for: {missing}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
