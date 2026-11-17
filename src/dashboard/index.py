"""Cross-project in-memory run index (Phase 10).

Walks reports/ on startup and on a background timer, reading each run.json into
an in-memory list of RunSummaryModel objects. Existing entries are refreshed so
provisional summaries written at run start cannot remain stale after completion.

The index is built and accessed through the module-level singleton RunIndex
instance, injected into the FastAPI app at startup.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from . import run_state
from .config import settings
from .models import RunSummaryModel

logger = logging.getLogger("dashboard.index")


def _read_status_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


class RunIndex:
    """Thread-safe (asyncio) in-memory index of run.json summaries."""

    def __init__(
        self,
        reports_dir: str,
        interval: int = 30,
        specs_dir: str | None = None,
    ) -> None:
        self.reports_dir = reports_dir
        self.specs_dir = specs_dir
        self.interval = interval
        # {(project, run_ts): RunSummaryModel}
        self._runs: dict[tuple[str, str], RunSummaryModel] = {}
        # Older immutable history can be skipped when its stat signature is
        # unchanged. The newest two runs are always re-read because some host
        # filesystems coarsen timestamps enough to hide rapid same-size writes.
        self._signatures: dict[tuple[str, str], tuple[int, int]] = {}
        self._task: asyncio.Task | None = None

    # ── public query interface ─────────────────────────────────────────────

    def projects(self) -> list[dict[str, Any]]:
        """Return configured projects with independent latest-run metadata.

        A project must not disappear from the dashboard merely because it has
        never run.  Report directories remain a compatibility source, but the
        configured specification root is authoritative when supplied.
        """
        by_project: dict[str, list[RunSummaryModel]] = {}
        for (project, _), run in self._runs.items():
            by_project.setdefault(project, []).append(run)
        result = []
        for name, runs in sorted(by_project.items()):
            runs_sorted = sorted(runs, key=lambda r: r.run_ts, reverse=True)
            result.append(
                {
                    "name": name,
                    "run_count": len(runs_sorted),
                    "latest": runs_sorted[0] if runs_sorted else None,
                    "index_href": f"/reports/{name}/index.html",
                }
            )
        # Also surface project dirs that exist on disk but have no runs yet.
        known = {p['name'] for p in result}
        if os.path.isdir(self.reports_dir):
            for d in sorted(os.listdir(self.reports_dir)):
                if d.startswith('.'):
                    continue  # skip hidden dirs (.ctrl, .tmp, etc.)
                if d not in known and os.path.isdir(os.path.join(self.reports_dir, d)):
                    result.append({'name': d, 'run_count': 0, 'latest': None,
                                   'index_href': f'/reports/{d}/index.html'})
                    known.add(d)
        if self.specs_dir and os.path.isdir(self.specs_dir):
            for entry in sorted(os.scandir(self.specs_dir), key=lambda item: item.name.lower()):
                if (
                    entry.name.startswith(".")
                    or not entry.is_dir(follow_symlinks=False)
                    or entry.name in known
                    or not os.path.isfile(os.path.join(entry.path, "project.yaml"))
                ):
                    continue
                result.append({
                    'name': entry.name,
                    'run_count': 0,
                    'latest': None,
                    'index_href': f'/reports/{entry.name}/index.html',
                })
                known.add(entry.name)
        return sorted(result, key=lambda item: item['name'].lower())

    def has_project(self, name: str) -> bool:
        """Return whether a configured or historical project exists."""
        if not name or name.startswith(".") or os.path.basename(name) != name:
            return False
        return any(item["name"] == name for item in self.projects())

    def runs_for_project(
        self, project: str, limit: int = 50, offset: int = 0
    ) -> list[RunSummaryModel]:
        """All runs for a project, newest first, paginated."""
        runs = [
            r for (p, _), r in self._runs.items() if p == project
        ]
        runs.sort(key=lambda r: r.run_ts, reverse=True)
        return runs[offset : offset + limit]

    def get_run(self, project: str, run_ts: str) -> RunSummaryModel | None:
        return self._runs.get((project, run_ts))

    def search(
        self,
        *,
        q: str | None = None,
        project: str | None = None,
        status: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[RunSummaryModel]:
        """Filter runs.  status: 'passed' | 'failed' | 'errored'."""
        results = list(self._runs.values())

        if project:
            results = [r for r in results if r.project == project]

        if status == "passed":
            results = [r for r in results if r.failed == 0 and r.errored == 0 and r.total > 0]
        elif status == "failed":
            results = [r for r in results if r.failed > 0]
        elif status == "errored":
            results = [r for r in results if r.errored > 0]

        if since:
            results = [r for r in results if r.run_ts >= since]

        if q:
            q_lower = q.lower()
            results = [r for r in results if q_lower in r.project.lower()]

        results.sort(key=lambda r: r.run_ts, reverse=True)
        return results[:limit]

    # ── scan logic ────────────────────────────────────────────────────────

    def scan_once(self) -> int:
        """Walk reports/, refreshing summaries and returning the new-run count."""
        added = 0
        if not os.path.isdir(self.reports_dir):
            return 0
        for project in os.listdir(self.reports_dir):
            project_dir = os.path.join(self.reports_dir, project)
            if not os.path.isdir(project_dir):
                continue
            if project.startswith('.'):
                continue  # skip hidden dirs (.ctrl, .tmp, etc.)
            run_entries = sorted(os.listdir(project_dir), reverse=True)
            for position, run_ts in enumerate(run_entries):
                key = (project, run_ts)
                is_new = key not in self._runs
                run_json = os.path.join(project_dir, run_ts, "run.json")
                if not os.path.isfile(run_json):
                    continue
                try:
                    stat = os.stat(run_json)
                    ctrl = run_state.ctrl_root(self.reports_dir, getattr(settings, "ctrl_dir", None))
                    signature = (stat.st_mtime_ns, stat.st_size, run_state.marker_signature(ctrl, project, run_ts))
                    always_refresh = position < 2
                    if (
                        not is_new
                        and not always_refresh
                        and self._signatures.get(key) == signature
                    ):
                        continue
                    with open(run_json, encoding="utf-8") as f:
                        data = json.load(f)
                    state = data.get("state")
                    marker = run_state.read_marker(ctrl, project, run_ts)
                    if marker is not None:   # same rule as the status endpoint; runner-owned run.json is never rewritten
                        status = _read_status_json(os.path.join(project_dir, run_ts, "status.json"))
                        state = run_state.effective_state(status or data, marker)[0] or state
                    self._runs[key] = RunSummaryModel(
                        project=data.get("project", project),
                        run_ts=data.get("run_ts", run_ts),
                        model_id=data.get("model_id"),
                        total=data.get("total", 0),
                        passed=data.get("passed", 0),
                        failed=data.get("failed", 0),
                        errored=data.get("errored", 0),
                        spec_total=data.get("spec_total", 0),
                        duration_seconds=data.get("duration_seconds", 0.0),
                        state=state,
                        report_href=f"/reports/{project}/{run_ts}/report.html",
                    )
                    self._signatures[key] = signature
                    if is_new:
                        added += 1
                except (json.JSONDecodeError, OSError, KeyError) as exc:
                    logger.debug("could not index %s: %s", run_json, exc)
        return added

    # ── background task ───────────────────────────────────────────────────

    async def _background_scan(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                added = self.scan_once()
                if added:
                    logger.debug("index: added %d new run(s)", added)
            except Exception as exc:  # noqa: BLE001
                logger.warning("index scan error: %s", exc)

    def start_background_scan(self) -> None:
        """Start the periodic background scan as an asyncio task."""
        self._task = asyncio.create_task(self._background_scan())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
