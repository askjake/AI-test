"""API routes for dashboard history, live activity, and on-demand runs.

Route map:
  GET  /api/v1/projects                         — list all projects
  GET  /api/v1/projects/{name}/runs             — paginated run history
  GET  /api/v1/runs/{project}/{run_ts}          — single run detail
  GET  /api/v1/runs/{project}/{run_ts}/status   — live status.json
  GET  /api/v1/runs/{project}/{run_ts}/live     — SSE step stream
  GET  /api/v1/search                           — cross-project filter
  POST /api/v1/projects/{name}/runs             — queue an on-demand run
  POST /api/v1/projects/{name}/runs/cancel      — stop that project's active run
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sse_starlette.sse import EventSourceResponse

from .auth import verify_operator, verify_viewer, verify_viewer_sse
from .config import settings
from .live import tail_run
from .models import (
    CancelRunResponseModel,
    ProjectSummaryModel,
    RunStatusModel,
    RunSummaryModel,
    SearchResultModel,
    TriggerResponseModel,
)
from .project_access import ProjectAccessError, precreate_run_dirs, prepare_project_mounts
from . import run_state
from .run_control import container_state, process_group_alive
from .run_control import (
    RunControlError,
    capture_process_identity,
    container_name,
    resolve_process_identity,
    stop_container,
    spawn_session_kwargs,
    terminate_process_group,
    validate_process_identity,
)

router = APIRouter(prefix="/api/v1")

# ── dependency: injected RunIndex (set by app.py at startup) ──────────────────
_index = None  # type: ignore[assignment]


def get_index():
    return _index


def set_index(idx) -> None:
    global _index
    _index = idx


@router.get("/runtime-identity")
async def runtime_identity(
    _token: Annotated[str, Depends(verify_viewer)],
) -> dict[str, Any]:
    """Return non-sensitive process identity used by the installer stop guard."""
    return {
        "instance_id": os.environ.get("ORCHESTRATOR_COOKIE_INSTANCE_ID", ""),
        "pid": os.getpid(),
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _run_dir(project: str, run_ts: str) -> str:
    return os.path.join(settings.reports_dir, project, run_ts)


def _read_status(project: str, run_ts: str) -> dict[str, Any] | None:
    path = os.path.join(_run_dir(project, run_ts), "status.json")
    marker = run_state.read_marker(_ctrl_root(), project, run_ts)
    value = None
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                loaded = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(loaded, dict):
            return None
        value = loaded
    if value is None:
        if marker is None:
            return None
        state, source = run_state.effective_state(None, marker)
        return {"state": state, "state_source": source} if state in ("cancelled", "cancelling") else None
    stale = _status_is_stale(path, value)
    if marker is None:
        return {**value, "state": "error"} if stale else value
    state, source = run_state.effective_state(value, marker, stale=stale)
    return {**value, "state": state, "state_source": source}


# ── read endpoints ────────────────────────────────────────────────────────────

@router.get("/projects", response_model=list[ProjectSummaryModel])
async def list_projects(
    _token: Annotated[str, Depends(verify_viewer)],
    idx=Depends(get_index),
) -> list[dict]:
    """List all projects with latest run summary."""
    idx.scan_once()
    return idx.projects()


@router.get("/projects/{name}/runs", response_model=list[RunSummaryModel])
async def list_runs(
    name: str,
    _token: Annotated[str, Depends(verify_viewer)],
    idx=Depends(get_index),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[RunSummaryModel]:
    """Paginated run history for one project, newest first."""
    idx.scan_once()
    runs = idx.runs_for_project(name, limit=limit, offset=offset)
    if not runs and offset == 0:
        # A configured project may exist without any report directory yet.
        if not idx.has_project(name):
            raise HTTPException(status_code=404, detail=f"Project {name!r} not found.")
    return runs


@router.get("/runs/{project}/{run_ts}", response_model=RunSummaryModel)
async def get_run(
    project: str,
    run_ts: str,
    _token: Annotated[str, Depends(verify_viewer)],
    idx=Depends(get_index),
) -> RunSummaryModel:
    """Detail for a single run."""
    run = idx.get_run(project, run_ts)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@router.get("/runs/{project}/{run_ts}/status", response_model=RunStatusModel)
async def get_run_status(
    project: str,
    run_ts: str,
    _token: Annotated[str, Depends(verify_viewer)],
) -> RunStatusModel:
    """Live status of an in-progress or completed run (from status.json)."""
    data = _read_status(project, run_ts)
    if data is None:
        # Run exists but is not yet started / no status file
        run_dir = _run_dir(project, run_ts)
        if not os.path.isdir(run_dir):
            raise HTTPException(status_code=404, detail="Run not found.")
        return RunStatusModel(state="pending")
    return RunStatusModel(
        state=data.get("state", "unknown"),
        current_spec=data.get("current_spec"),
        current_spec_index=data.get("current_spec_index", 0),
        specs_total=data.get("specs_total", 0),
        specs_completed=data.get("specs_completed", []),
        started_at=data.get("started_at"),
        current_evidence_dir=data.get("current_evidence_dir"),
    )


@router.get("/runs/{project}/{run_ts}/live")
async def live_stream(
    project: str,
    run_ts: str,
    _token: Annotated[str, Depends(verify_viewer_sse)],
) -> EventSourceResponse:
    """SSE stream of step events for an in-progress run."""

    async def event_generator():
        async for payload in tail_run(
            settings.reports_dir,
            project,
            run_ts,
            stale_seconds=settings.run_stale_seconds,
        ):
            yield {"event": payload["event"], "data": payload["data"]}

    return EventSourceResponse(event_generator())


@router.get("/search", response_model=list[SearchResultModel])
async def search_runs(
    _token: Annotated[str, Depends(verify_viewer)],
    idx=Depends(get_index),
    q: str | None = Query(None),
    project: str | None = Query(None),
    status: str | None = Query(None, pattern="^(passed|failed|errored)$"),
    since: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> list[SearchResultModel]:
    """Search runs across all projects."""
    runs = idx.search(q=q, project=project, status=status, since=since, limit=limit)
    return [
        SearchResultModel(
            project=r.project,
            run_ts=r.run_ts,
            total=r.total,
            passed=r.passed,
            failed=r.failed,
            errored=r.errored,
            duration_seconds=r.duration_seconds,
            report_href=r.report_href or f"/reports/{r.project}/{r.run_ts}/report.html",
        )
        for r in runs
    ]


# ── Phase 11: run trigger endpoint ───────────────────────────────────────────

_PROJECT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TRIGGER_RE = re.compile(r"^trig_[A-Za-z0-9_-]+$")
_TRIGGER_STALE_SECS = 300
_CLAIMED_STALE_SECS = 3600
_ACTIVE_STATES = {"pending", "running"}
_ACTIVE_EFFECTIVE = _ACTIVE_STATES | {"cancelling"}
_COMMITTED = frozenset({"complete", "completed", "passed", "failed"})
_CANCEL_GUARD = threading.Lock()
_CANCEL_LOCKS: dict[str, threading.Lock] = {}


def _status_is_stale(path: str, status: dict[str, Any]) -> bool:
    if status.get("state") not in _ACTIVE_STATES or settings.run_stale_seconds <= 0:
        return False
    try:
        return time.time() - os.path.getmtime(path) > settings.run_stale_seconds
    except OSError:
        return False


def _validate_project_name(project: str) -> None:
    if not _PROJECT_RE.fullmatch(project):
        raise HTTPException(status_code=400, detail="Invalid project name.")


def _ctrl_root() -> str:
    return os.path.abspath(
        settings.ctrl_dir
        or os.path.join(os.path.abspath(settings.reports_dir), ".ctrl")
    )

def _ctrl_dir_for(project: str) -> str:
    """Return the per-project control subdir, creating it if needed."""
    ctrl = os.path.join(_ctrl_root(), project)
    os.makedirs(ctrl, exist_ok=True)
    return ctrl


def _read_json(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".trig_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _trigger_files(ctrl: str) -> list[str]:
    """Return only live trigger files, never terminal outcome files."""
    try:
        names = os.listdir(ctrl)
    except OSError:
        return []
    return sorted(
        os.path.join(ctrl, name)
        for name in names
        if name.startswith("trigger_")
        and (name.endswith(".json") or name.endswith(".json.claimed"))
    )


def _mark_trigger_error(path: str, message: str) -> None:
    payload = _read_json(path) or {}
    payload["error"] = message
    payload["finished_at"] = datetime.now(timezone.utc).isoformat()
    try:
        _atomic_write_json(path, payload)
        base = path[:-8] if path.endswith(".claimed") else path
        os.replace(path, f"{base}.err")
    except OSError:
        pass


def _trigger_base(path: str) -> str:
    return path[:-8] if path.endswith(".claimed") else path


def _mark_trigger_cancelled(path: str, message: str) -> str:
    """Persist a cancellation even if the wrapper raced to another terminal suffix."""
    base = _trigger_base(path)
    target = f"{base}.cancelled"
    terminal_candidates = (path, f"{base}.err", f"{base}.ack", f"{base}.busy")

    if os.path.isfile(target):
        source = target
    elif not path.endswith(".claimed"):
        # Atomically claim a queued watcher trigger before changing its state. If the
        # watcher won the rename race, it may already be executing in-process and is no
        # longer safely cancellable by this dashboard.
        try:
            os.replace(path, target)
        except FileNotFoundError as exc:
            raise RunControlError("the trigger was claimed while cancellation began") from exc
        source = target
    else:
        source = ""
        for _ in range(3):
            candidate = next(
                (item for item in terminal_candidates if os.path.isfile(item)),
                "",
            )
            if not candidate:
                break
            if candidate.endswith(".ack"):
                raise RunControlError("the run completed before cancellation; its result is preserved")
            try:
                os.replace(candidate, target)
                source = target
                break
            except FileNotFoundError:
                continue
        if not source:
            raise RunControlError("the trigger outcome changed before cancellation was recorded")

    payload = _read_json(source) or {}
    payload.update(
        {
            "status": "cancelled",
            "cancelled": True,
            "error": message,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "exit_code": 130,
        }
    )
    _atomic_write_json(target, payload)
    for candidate in set(terminal_candidates):
        if candidate != target:
            try:
                os.unlink(candidate)
            except FileNotFoundError:
                pass
    return target


def _status_dir(project: str, rid: str) -> str:
    """Directory holding the runner-written status.json for this id: the procedure run folder for trig_* ids, else the project's timestamp run folder."""
    if rid.startswith("trig_"):
        return os.path.join(os.path.abspath(settings.reports_dir), project, ".nrdp-runs", rid)
    return _run_dir(project, rid)


def _begin_cancel_record(project: str, run_ts: str, trigger_id: str) -> None:
    """Option A: the dashboard records the request in ITS OWN control directory; runner-owned status.json/run.json are never rewritten."""
    root = _ctrl_root()
    existing = run_state.read_marker(root, project, run_ts)
    status = _read_json(os.path.join(_status_dir(project, run_ts), "status.json")) or {}
    now = run_state.utc_now()
    attempts = existing.get("attempts") if existing else 0
    run_state.write_marker(root, project, run_ts, {
        "state": "cancelling", "trigger_id": trigger_id,
        "requested_at": (existing or {}).get("requested_at") or now, "updated_at": now,
        "runner_started_at": (existing or {}).get("runner_started_at") or status.get("started_at"),
        "pre_state": (existing or {}).get("pre_state") or status.get("state"),
        "attempts": (attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0) + 1,
        "teardown": {"confirmed": False}, "message": "Cancelled by operator.",
    })


def _update_cancel_record(project: str, run_ts: str, *, state: str, teardown: dict, note: str | None = None, rebind: bool = False) -> None:
    root = _ctrl_root()
    record = dict(run_state.read_marker(root, project, run_ts) or {"trigger_id": "", "requested_at": run_state.utc_now(), "attempts": 1})
    record.pop("schema", None)
    record.update({"state": state, "updated_at": run_state.utc_now(), "teardown": dict(teardown)})
    if note:
        record["note"] = note[:300]
    if rebind:   # a confirmed record is bound to the incarnation observed AFTER teardown
        record["runner_started_at"] = (_read_json(os.path.join(_status_dir(project, run_ts), "status.json")) or {}).get("started_at")
    run_state.write_marker(root, project, run_ts, record)


def _already_cancelled(name: str):
    for marker in run_state.confirmed_markers(_ctrl_root(), name):
        runner = _read_json(os.path.join(_status_dir(name, marker["run_id"]), "status.json"))
        if run_state.effective_state(runner, marker)[0] == "cancelled":
            return CancelRunResponseModel(
                project=name, status="cancelled", trigger_id=str(marker.get("trigger_id") or ""), run_ts=marker["run_id"],
                message=f"Run for project {name!r} was already cancelled; no further action was taken.",
            )
    return None


def _sweep_stale_triggers(project: str) -> None:
    ctrl = os.path.join(_ctrl_root(), project)
    now = time.time()
    active = _active_run(project)
    for path in _trigger_files(ctrl):
        try:
            is_claimed = path.endswith(".claimed")
            if is_claimed and active is not None:
                continue
            stale_after = _CLAIMED_STALE_SECS if is_claimed else _TRIGGER_STALE_SECS
            if now - os.path.getmtime(path) > stale_after:
                _mark_trigger_error(path, "Trigger timed out before a run started.")
        except OSError:
            continue


def _active_run(project: str) -> str | None:
    project_dir = os.path.join(os.path.abspath(settings.reports_dir), project)
    if not os.path.isdir(project_dir):
        return None
    for entry in sorted(os.listdir(project_dir), reverse=True):
        if entry.startswith("."):
            continue
        entry_path = os.path.join(project_dir, entry)
        if not os.path.isdir(entry_path):
            continue
        status_path = os.path.join(entry_path, "status.json")
        status = _read_json(status_path)
        marker = run_state.read_marker(_ctrl_root(), project, entry)
        stale = bool(status) and _status_is_stale(status_path, status)
        effective, _source = run_state.effective_state(status, marker, stale=stale)
        if status and effective in _ACTIVE_EFFECTIVE:
            return entry
        if status is None and not os.path.isfile(os.path.join(entry_path, "run.json")):
            if effective == "cancelled":
                continue
            try:
                if time.time() - os.path.getmtime(entry_path) < 600:
                    return entry
            except OSError:
                pass
    return None


def _pending_trigger(project: str) -> tuple[str, str] | None:
    ctrl = os.path.join(_ctrl_root(), project)
    now = time.time()
    for path in _trigger_files(ctrl):
        try:
            if now - os.path.getmtime(path) > _TRIGGER_STALE_SECS:
                continue
        except OSError:
            continue
        payload = _read_json(path)
        if payload:
            return str(payload.get("trigger_id") or os.path.basename(path)), path
    return None


def _project_exists(project: str, idx) -> bool:
    report_dir = os.path.join(os.path.abspath(settings.reports_dir), project)
    specs_dir = os.path.join(os.path.abspath(settings.specs_dir), project)
    return bool(
        os.path.isdir(report_dir)
        or os.path.isdir(specs_dir)
        or idx.runs_for_project(project, limit=1)
    )


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|secret|password|authorization|aws_access_key_id|"
    r"aws_secret_access_key|aws_session_token)\b(\s*[=:]\s*)(\S+)"
)
_QUERY_SECRET_RE = re.compile(r"(?i)([?&](?:token|key|secret)=)[^&\s\"]+")
_ERROR_HINT_RE = re.compile(
    r"(?i)\b(error|failed|failure|denied|forbidden|not found|cannot|unable|"
    r"invalid|missing|required|timed out|timeout|refused)\b"
)


def _redact_trigger_line(line: str) -> str:
    line = _ANSI_ESCAPE_RE.sub("", line)
    line = "".join(char for char in line if char == "\t" or ord(char) >= 32)
    line = _QUERY_SECRET_RE.sub(r"\1[redacted]", line)
    line = _SECRET_ASSIGNMENT_RE.sub(r"\1\2[redacted]", line)
    return line.strip()[:600]


def _trigger_failure_message(path: str, payload: dict[str, Any]) -> str:
    """Return a concise, redacted reason captured by the spawn wrapper."""
    if payload.get("error"):
        return _redact_trigger_line(str(payload["error"]))

    log_path = f"{path}.log"
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = [_redact_trigger_line(line) for line in fh.readlines()[-80:]]
    except OSError:
        lines = []
    lines = [line for line in lines if line]
    exit_line = next(
        (line for line in reversed(lines) if line.startswith("trigger_exit_code=")),
        None,
    )
    candidates = [line for line in lines if not line.startswith("trigger_exit_code=")]
    reason = next((line for line in reversed(candidates) if _ERROR_HINT_RE.search(line)), None)
    reason = reason or (candidates[-1] if candidates else None)
    if reason and exit_line:
        return f"{reason} ({exit_line.replace('_', ' ')})"
    if reason:
        return reason
    return "Run process exited unsuccessfully; inspect reports/spawn.log for details."


@router.post("/projects/{name}/runs", status_code=202, response_model=TriggerResponseModel)
async def trigger_run(
    name: str,
    _token: Annotated[str, Depends(verify_operator)],
    idx=Depends(get_index),
) -> TriggerResponseModel:
    """Queue one on-demand run using exactly one configured backend."""
    _validate_project_name(name)
    if not _project_exists(name, idx):
        raise HTTPException(status_code=404, detail=f"Project {name!r} not found.")

    if settings.trigger_backend != "spawn":
        # CP45-I: only the spawn backend can satisfy the 0755 reports contract (dashboard precreates, the entrypoint hands over).  The watcher backend
        # would need a world-writable project directory, so it is refused HERE: no project directory, trigger file, process or container is created.
        raise HTTPException(
            status_code=409,
            detail=(f"The {settings.trigger_backend!r} trigger backend is not supported: it would need world-writable report folders. "
                    "Set DASHBOARD_TRIGGER_BACKEND=spawn (the default)."),
        )
    try:
        prepare_project_mounts(settings.specs_dir, settings.reports_dir, name)
    except ProjectAccessError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Project files are not accessible to the runner container: {exc}",
        ) from exc

    _sweep_stale_triggers(name)
    if _find_running_run(name) is not None:
        raise HTTPException(status_code=409, detail="A run is already in progress")

    trigger_id = (
        f"trig_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_"
        f"{uuid.uuid4().hex[:8]}"
    )
    ctrl = _ctrl_dir_for(name)
    suffix = ".json" if settings.trigger_backend == "watcher" else ".json.claimed"
    fname = f"trigger_{trigger_id}{suffix}"
    fpath = os.path.join(ctrl, fname)
    payload = {
        "project": name,
        "trigger_id": trigger_id,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "requester": "dashboard",
        "backend": settings.trigger_backend,
    }
    report_run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if settings.trigger_backend == "spawn":
        payload["container_name"] = container_name(name, trigger_id)
        # CP45-G: the dashboard precreates the run's report paths (0755, its own uid) BEFORE the trigger exists or the container starts;
        # the entrypoint hands them to the runner uid before the privilege drop.  Failure here is a visible 422 with no trigger written.
        try:
            precreate_run_dirs(settings.reports_dir, name, trigger_id, report_run_ts)
        except ProjectAccessError as exc:
            raise HTTPException(status_code=422, detail=f"The run's report folders could not be prepared: {exc}") from exc
    _atomic_write_json(fpath, payload)

    if settings.trigger_backend == "spawn":
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        script = os.path.join(root, "src", "orchestrator", "runtime_trigger.py")
        env = {
            **os.environ,
            "REPORTS_DIR": os.path.abspath(settings.reports_dir),
            "SPECS_DIR": os.path.abspath(settings.specs_dir),
            "RDP_WARMUP_SKIP": "1",
            "ORCHESTRATOR_LOG_LEVEL": os.environ.get(
                "ORCHESTRATOR_LOG_LEVEL", "DEBUG"
            ),
            "DASHBOARD_PYTHON": sys.executable,
            "ORCHESTRATOR_TRIGGER_ID": trigger_id,
            "ORCHESTRATOR_CONTAINER_NAME": str(payload.get("container_name", "")),
            "ORCHESTRATOR_RUN_TS": report_run_ts,
            "ORCHESTRATOR_REPORT_PROJECT": name,
        }
        log_path = os.path.join(os.path.abspath(settings.reports_dir), "spawn.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        try:
            with open(log_path, "a", encoding="utf-8") as log_fh:
                log_fh.write(f"--- spawn {name} ({trigger_id}) ---\n")
                log_fh.flush()
                process = subprocess.Popen(
                    [sys.executable, script, name, fpath],
                    cwd=root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log_fh,
                    stderr=log_fh,
                    **spawn_session_kwargs(),
                )
                if isinstance(process.pid, int) and not isinstance(process.pid, bool):
                    try:
                        identity = capture_process_identity(
                            process.pid,
                            project=name,
                            control_path=fpath,
                            script_path=script,
                        )
                    except RunControlError:
                        # Exact /proc discovery remains available to cancellation. A very
                        # short run may also have completed before metadata can be captured.
                        identity = None
                    if identity is not None and os.path.isfile(fpath):
                        current = _read_json(fpath) or payload
                        current.update(
                            {
                                "pid": identity.pid,
                                "pgid": identity.pgid,
                                "process_start_ticks": identity.start_ticks,
                            }
                        )
                        _atomic_write_json(fpath, current)
        except (OSError, subprocess.SubprocessError) as exc:
            _mark_trigger_error(fpath, f"Could not start run: {exc}")
            raise HTTPException(
                status_code=503,
                detail="The run could not be started; see the trigger status for details.",
            ) from exc

    rel = os.path.join(".ctrl", name, fname)
    return TriggerResponseModel(
        trigger_id=trigger_id,
        project=name,
        status="queued",
        ctrl_file=rel,
        message=f"Run queued for project {name!r} via {settings.trigger_backend} backend.",
    )


@router.post(
    "/projects/{name}/runs/cancel",
    response_model=CancelRunResponseModel,
)
def cancel_project_run(
    name: str,
    _token: Annotated[str, Depends(verify_operator)],
    idx=Depends(get_index),
) -> CancelRunResponseModel:
    """Cancel only the dashboard-owned active trigger for *name* (one cancellation per project at a time)."""
    _validate_project_name(name)
    with _CANCEL_GUARD:
        lock = _CANCEL_LOCKS.setdefault(name, threading.Lock())
    with lock:
        return _cancel_project_run_locked(name, idx)


def _cancel_project_run_locked(name: str, idx) -> CancelRunResponseModel:
    """Cancel only the dashboard-owned active trigger for *name*."""
    _validate_project_name(name)
    if not _project_exists(name, idx):
        raise HTTPException(status_code=404, detail=f"Project {name!r} not found.")

    _sweep_stale_triggers(name)
    controls = []
    for path in _trigger_files(os.path.join(_ctrl_root(), name)):
        payload = _read_json(path) or {}
        if payload.get("project") == name:
            controls.append((path, payload))
    if not controls:
        already = _already_cancelled(name)
        if already is not None:
            return already
        if _active_run(name) is not None:
            raise HTTPException(
                status_code=409,
                detail="The active run is not owned by a cancellable dashboard trigger.",
            )
        raise HTTPException(status_code=409, detail="No active run exists for this project.")
    if len(controls) != 1:
        raise HTTPException(
            status_code=409,
            detail="Multiple active triggers exist for this project; refusing an ambiguous stop.",
        )

    control_path, payload = controls[0]
    trigger_id = str(payload.get("trigger_id", ""))
    if not _TRIGGER_RE.fullmatch(trigger_id):
        raise HTTPException(status_code=409, detail="The active trigger identity is invalid.")
    if os.path.basename(_trigger_base(control_path)) != f"trigger_{trigger_id}.json":
        raise HTTPException(
            status_code=409,
            detail="The active trigger file does not match its recorded identity.",
        )
    run_ts = _active_run(name)
    reason = "Cancelled by operator."
    teardown: dict[str, Any] = {"container": "none", "process_group": "none", "confirmed": True}
    cancel_ids = [trigger_id] + ([run_ts] if (run_ts and not run_ts.startswith("trig_")) else [])
    record_run = True

    def _upd(**kw) -> None:
        for rid in cancel_ids:
            _update_cancel_record(name, rid, **kw)

    # Snapshot BEFORE anything is stopped: a terminal state seen now is a real earlier result (a retry of a half-done cancel is the only exception).
    for rid in cancel_ids:
        cur = (_read_json(os.path.join(_status_dir(name, rid), "status.json")) or {}).get("state")
        prior = run_state.read_marker(_ctrl_root(), name, rid)
        if isinstance(cur, str) and cur not in _ACTIVE_STATES and not (prior and prior.get("state") == "cancelling"):
            raise HTTPException(
                status_code=409,
                detail=f"The run already reached a terminal state ({cur}) before cancellation began; its result is preserved and nothing was stopped.",
            )
    try:
        for rid in cancel_ids:
            _begin_cancel_record(name, rid, trigger_id)
    except run_state.CancelRecordError as exc:
        raise HTTPException(status_code=503, detail=f"The cancellation cannot be recorded safely: {exc}") from exc

    # A watcher-owned trigger that has not yet been claimed is safe to cancel by
    # durable state transition alone. Once claimed, only the spawn backend has an
    # isolated process group/container that this dashboard can safely stop.
    if control_path.endswith(".claimed"):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        script = os.path.join(root, "src", "orchestrator", "runtime_trigger.py")
        identity = None
        identity_error: RunControlError | None = None
        try:
            identity = resolve_process_identity(
                payload,
                project=name,
                control_path=control_path,
                script_path=script,
            )
        except RunControlError as exc:
            identity_error = exc

        expected_container = container_name(name, trigger_id)
        recorded_container = payload.get("container_name")
        if recorded_container not in (None, "", expected_container):
            raise HTTPException(
                status_code=409,
                detail="The runner container identity does not match this project trigger.",
            )
        try:
            container_stopped = stop_container(expected_container)
        except (RunControlError, OSError, subprocess.SubprocessError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        process_stopped = False
        if identity is not None:
            try:
                validate_process_identity(
                    identity,
                    project=name,
                    control_path=control_path,
                    script_path=script,
                )
                terminate_process_group(identity)
                process_stopped = True
            except RunControlError as exc:
                # A successful container stop normally lets the wrapper exit before
                # this second check. That is already a successful scoped stop.
                if not container_stopped:
                    raise HTTPException(status_code=409, detail=str(exc)) from exc
        if not container_stopped and not process_stopped:
            if identity_error is not None:
                raise HTTPException(status_code=409, detail=str(identity_error)) from identity_error
            raise HTTPException(
                status_code=409,
                detail="No safely owned process or container remains for this trigger.",
            )
        container_after = container_state(expected_container)
        group_alive = process_group_alive(identity.pgid) if identity is not None else False
        teardown = {
            "container": container_after,
            "process_group": "none" if identity is None else ("stopped" if group_alive is False else "alive" if group_alive else "unknown"),
            "confirmed": False,
        }
        teardown["confirmed"] = container_after in ("absent", "stopped") and teardown["process_group"] in ("none", "stopped")
        if not teardown["confirmed"]:
            if record_run:
                _upd(state="cancelling", teardown=teardown)
            raise HTTPException(
                status_code=503,
                detail=(f"Teardown could not be confirmed (container: {container_after}, process group: {teardown['process_group']}); "
                        "the run stays 'cancelling' and is not reported as cancelled."),
            )

    committed = None
    for rid in cancel_ids:   # only a result the RUNNER committed counts; 'error'/'cancelled' written by the killed runner are consequences of the stop
        cur = (_read_json(os.path.join(_status_dir(name, rid), "status.json")) or {}).get("state")
        if cur in _COMMITTED:
            committed = cur
    if committed:
        _upd(state="superseded", teardown=teardown, note=f"runner committed {committed}")
        raise HTTPException(
            status_code=409,
            detail=f"The run reached a terminal state ({committed}) before cancellation took effect; its result is preserved.",
        )
    try:
        _mark_trigger_cancelled(control_path, reason)
    except RunControlError as exc:
        if record_run:
            _upd(state="superseded", teardown=teardown, note=str(exc))
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record_run:
        teardown["confirmed_at"] = run_state.utc_now()
        _upd(state="cancelled", teardown=teardown, rebind=True)
    if idx is not None:
        idx.scan_once()
    return CancelRunResponseModel(
        project=name,
        status="cancelled",
        trigger_id=trigger_id,
        run_ts=run_ts if run_ts and not run_ts.startswith("trig_") else None,
        message=f"Run for project {name!r} was cancelled.",
    )


def _find_running_run(project: str) -> str | None:
    """Return an active run timestamp or queued trigger id."""
    active = _active_run(project)
    if active is not None:
        return active
    pending = _pending_trigger(project)
    return pending[0] if pending else None


@router.get("/projects/{name}/running")
async def get_running_run(
    name: str,
    _token: Annotated[str, Depends(verify_viewer)],
) -> dict:
    """Return the active run, queued trigger, or an idle response."""
    _validate_project_name(name)
    _sweep_stale_triggers(name)
    active = _active_run(name)
    if active is not None:
        return {"project": name, "run_ts": active, "queued": False}
    pending = _pending_trigger(name)
    if pending is not None:
        return {"project": name, "run_ts": pending[0], "queued": True}
    return {"project": name, "run_ts": None, "queued": None}


@router.get("/projects/{name}/triggers/{trigger_id}")
async def get_trigger_status(
    name: str,
    trigger_id: str,
    _token: Annotated[str, Depends(verify_viewer)],
) -> dict:
    """Return the durable lifecycle state for a dashboard trigger."""
    _validate_project_name(name)
    if not _TRIGGER_RE.fullmatch(trigger_id):
        raise HTTPException(status_code=400, detail="Invalid trigger id.")
    _sweep_stale_triggers(name)
    base = os.path.join(_ctrl_root(), name, f"trigger_{trigger_id}.json")
    states = (
        (".cancelled", "cancelled"),
        (".err", "error"),
        (".busy", "busy"),
        (".ack", "succeeded"),
        (".claimed", "starting"),
        ("", "queued"),
    )
    for suffix, state in states:
        path = f"{base}{suffix}"
        if not os.path.isfile(path):
            continue
        payload = _read_json(path) or {}
        return {
            "project": name,
            "trigger_id": trigger_id,
            "status": state,
            "message": (
                _trigger_failure_message(path, payload)
                if state == "error"
                else payload.get("error")
            ),
        }
    return {
        "project": name,
        "trigger_id": trigger_id,
        "status": "unknown",
        "message": "Trigger outcome is no longer available.",
    }

from . import aws_status as _aws_status  # noqa: E402
router.include_router(_aws_status.router)
