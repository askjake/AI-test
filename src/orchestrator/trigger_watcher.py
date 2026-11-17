"""Trigger-file watcher for on-demand run requests (Phase 11).

The dashboard writes a trigger file to reports/.ctrl/<project>/trigger_<id>.json.
This module provides TriggerWatcher, which is registered as an APScheduler
IntervalJob in scheduler.start() to poll that directory every 2 seconds.

Trigger lifecycle:
  trigger_<id>.json         — pending (written by dashboard)
  trigger_<id>.json.claimed — being processed (atomic rename; prevents double-fire)
  trigger_<id>.json.ack     — run started successfully
  trigger_<id>.json.busy    — rejected: a run was already in progress for this project
  trigger_<id>.json.err     — rejected: project not found or other error

The watcher never modifies reports/<project>/ directly; it delegates to
run_project_once() in scheduler.py, which is the same path cron triggers use.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Callable

logger = logging.getLogger("orchestrator.trigger_watcher")

# How many completed .ack/.busy/.err files to keep per project before pruning.
_KEEP_COMPLETED = 20


UNSUPPORTED_MESSAGE = ("The in-process trigger watcher is not supported under the 0755 reports contract; start runs from the dashboard (trigger_backend=spawn).")


class TriggerWatcher:
    """Poll reports/.ctrl/ and fire run_project_once() for each pending trigger.

    Args:
        ctrl_dir:        Path to the control directory (reports/.ctrl by default).
        run_fn:          Callable matching run_project_once(name, **kwargs) signature.
        reports_dir:     Passed through to run_fn as the reports_dir kwarg.
        specs_root:      Passed through to run_fn as the specs_root kwarg.
    """

    def __init__(
        self,
        ctrl_dir: str,
        run_fn: Callable,
        *,
        reports_dir: str | None = None,
        specs_root: str | None = None,
    ) -> None:
        self.ctrl_dir = ctrl_dir
        self.run_fn = run_fn
        self.reports_dir = reports_dir
        self.specs_root = specs_root

    # ── public API (called by APScheduler every 2s) ───────────────────────────

    def check(self) -> None:
        """Scan ctrl_dir for pending trigger files and process each one."""
        if not os.path.isdir(self.ctrl_dir):
            return
        for project in os.listdir(self.ctrl_dir):
            project_ctrl = os.path.join(self.ctrl_dir, project)
            if not os.path.isdir(project_ctrl):
                continue
            # Process pending files sorted by name (timestamp order).
            pending = sorted(
                f for f in os.listdir(project_ctrl)
                if f.endswith(".json") and not f.startswith(".")
            )
            for fname in pending:
                fpath = os.path.join(project_ctrl, fname)
                self._process_one(project, fpath)
            # Prune old completed files.
            self._prune(project_ctrl)

    # ── internal ──────────────────────────────────────────────────────────────

    def _process_one(self, project: str, fpath: str) -> None:
        """CP45-I: REFUSE the trigger.  Running a project from this in-process watcher would write reports as the watcher's own uid into a project
        directory the dashboard no longer opens to it (0755 contract).  Nothing is launched; the claimed file becomes a visible .err with the reason."""
        import tempfile
        from datetime import datetime, timezone
        claimed = fpath + ".claimed"
        try:
            os.rename(fpath, claimed)
        except OSError:
            return                      # claimed by a concurrent check() or gone
        try:
            try:
                with open(claimed, encoding="utf-8") as f:
                    trigger = json.load(f)
            except (OSError, ValueError):
                trigger = {}
            trigger = trigger if isinstance(trigger, dict) else {}
            trigger.update({"error": UNSUPPORTED_MESSAGE, "exit_code": 78, "finished_at": datetime.now(timezone.utc).isoformat()})
            logger.error("trigger refused: %s", UNSUPPORTED_MESSAGE, extra={"project": project, "trigger_id": trigger.get("trigger_id")})
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(claimed), prefix=".trig_", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(trigger, fh, indent=2)
                os.replace(tmp, claimed)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError:
            pass                        # the outcome rename below still makes the refusal visible
        finally:
            try:
                os.rename(claimed, claimed.replace(".json.claimed", ".json") + ".err")
            except OSError:
                pass

    def _is_running(self, project: str) -> bool:
        """Return True if any run for this project has state=='running' in status.json."""
        if not self.reports_dir:
            return False
        project_dir = os.path.join(self.reports_dir, project)
        if not os.path.isdir(project_dir):
            return False
        for run_ts in os.listdir(project_dir):
            status_path = os.path.join(project_dir, run_ts, "status.json")
            if not os.path.isfile(status_path):
                continue
            try:
                with open(status_path, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("state") == "running":
                    return True
            except (json.JSONDecodeError, OSError):
                continue
        return False

    def _prune(self, project_ctrl: str) -> None:
        """Keep only the most recent _KEEP_COMPLETED completed files per project."""
        completed = sorted(
            f for f in os.listdir(project_ctrl)
            if any(f.endswith(ext) for ext in (".json.ack", ".json.busy", ".json.err"))
        )
        for old in completed[:-_KEEP_COMPLETED]:
            try:
                os.remove(os.path.join(project_ctrl, old))
            except OSError:
                pass
