"""Run control for rdp-chain procedure projects (NRDP-1, S2b).

Stdlib-only pure logic; the real spawn/cancel adapters are imported lazily from
``dashboard.routes`` (the EXISTING trigger_run / cancel_project_run path) and can be
replaced via ``configure()`` for tests.

Run-request mechanism (documented for S1b):
  * run_id == the trigger_id returned by routes.trigger_run (``trig_<UTC>_<8hex>``).
  * Before launch we write ``<reports_dir>/<project>/.nrdp-runs/<run_id>/control/run_request.json``
    (0600) = {mode, project, requested_at, chain: true, run_id, confirm_recorded}.
    reports_dir is bind-mounted into the runner container (scripts/run_container.sh REPORTS_DIR ->
    /app/reports), so the runner reads ``/app/reports/<project>/.nrdp-runs/<run_id>/control/``.
  * The runner identifies its run via ORCHESTRATOR_TRIGGER_ID (set by routes.trigger_run for the
    spawn backend). If that env var does not reach the container, the runner must take the
    newest run_request.json under ``.nrdp-runs/`` whose ``consumed_at`` is absent. A runner that
    finds NO run_request for an rdp-chain project must default to connection_test (never steps).
  * Layout of ``.nrdp-runs/<run_id>/`` (the contract's ``<run_dir>``):
    control/   DASHBOARD-OWNED, mode 0755 (the runner only reads it): run_request.json,
               checkpoint_ack.json, cancel_request.json.  Other local users cannot add, rename or
               delete anything here, and the runner trusts a file only if the dashboard's uid
               (ORCHESTRATOR_CONTROL_UID) owns it and nobody else can write it.
    <run_dir>  dashboard-PRECREATED 0755 (CP45-I: never shared or sticky); docker/entrypoint.sh hands this folder to the runner uid
               (orchestrator.report_handoff) before the privilege drop, so the runner can write what only IT produces:
               status.json, chain_progress.json, checkpoint.json (the runner's request for an
               operator checkpoint), chain_outcome.json, evidence/.
  The leading dot keeps the directory out of existing run listings (routes._active_run and
  index scans skip dot entries).
"""
from __future__ import annotations

import hashlib
import json
import os
from . import run_state
import re
import stat
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable

MODES = ("connection_test", "browser_verify", "read_only_check", "full_run")

# ------------------------------------------------- connection-only qualification (review B1)
# The dashboard refuses to START an operating run.  This mirrors (and is independently enforced
# by) orchestrator.chain_runtime.CONNECTION_ONLY on the runner side; neither relies on the other.
# No environment variable and no hidden switch: lifting it needs a reviewed source change.
CONNECTION_ONLY = True
OPERATING_MODES = ("read_only_check", "full_run")
CONNECTION_ONLY_MESSAGE = (
    "This release is qualified for connection tests only. Read-only checks and full runs are "
    "disabled: a procedure step can type or click on the wrong desktop, and that risk is "
    "unresolved. Run a connection test instead."
)


# ------------------------------------------------- browser_verify (CP43)
# The dashboard imports nothing from orchestrator.* (package rule), so this MIRRORS the runner's vocabulary and gate and is enforced independently of
# it; tests assert the two stay identical (phrases, URL, binding fingerprint).  DISABLED by default: None means off.  There is no environment variable
# and no hidden switch -- enabling needs a reviewed source change HERE (the API serves and accepts the request) AND in
# orchestrator.chain_runtime.BROWSER_VERIFY_POLICY (the runner independently re-validates every field before any browser launch).  A policy here is
# {"enabled": True, "allowed_projects": frozenset({...})}.
BROWSER_VERIFY_POLICY: Any = None
BROWSER_VERIFY_MODE = "browser_verify"
BROWSER_VERIFY_URL = "http://127.0.0.1:5004/"
BROWSER_VERIFY_DISABLED_MESSAGE = (
    "Browser playback verification is not available in this build: it is disabled by default and needs a reviewed configuration change on both the "
    "dashboard and the runner. Use Test connection."
)
BROWSER_VERIFY_CLEANUP_NOTE = (
    "The browser window, its profile folder and a possible Run-history entry are LEFT on the target. Automatic cleanup is NOT performed (window "
    "ownership cannot be proven); you must acknowledge this to start."
)


def _bv_policy() -> dict | None:
    p = BROWSER_VERIFY_POLICY
    if isinstance(p, dict) and p.get("enabled") is True and isinstance(p.get("allowed_projects"), (set, frozenset)) and p["allowed_projects"]:
        return p
    return None


def browser_verify_confirm_phrase(project: str) -> str:
    return f"BROWSER-VERIFY {project}"


def browser_verify_leave_open_phrase(project: str) -> str:
    return f"LEAVE-OPEN {project}"


def connection_binding(project: Any, rows: Any) -> str:
    """Identical algorithm to orchestrator.browser_modes.connection_binding (asserted by a cross-module test)."""
    return hashlib.sha256(json.dumps([str(project), rows], separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()


def allowed_modes() -> tuple[str, ...]:
    base = ("connection_test",) if CONNECTION_ONLY else tuple(m for m in MODES if m != BROWSER_VERIFY_MODE)
    return base + ((BROWSER_VERIFY_MODE,) if _bv_policy() is not None else ())


def browser_verify_capability() -> dict:
    p = _bv_policy()
    if p is None:
        return {"available": False, "reason": BROWSER_VERIFY_DISABLED_MESSAGE, "url": BROWSER_VERIFY_URL, "projects": []}
    return {"available": True, "reason": "", "url": BROWSER_VERIFY_URL, "projects": sorted(p["allowed_projects"]),
            "confirm_phrase_template": "BROWSER-VERIFY {project}", "leave_open_phrase_template": "LEAVE-OPEN {project}",
            "cleanup_note": BROWSER_VERIFY_CLEANUP_NOTE}


def capability() -> dict:
    """What the backend will actually start.  The UI renders from this, never from its own guess."""
    return {
        "connection_only": CONNECTION_ONLY,
        "allowed_modes": list(allowed_modes()),
        "disabled_modes": (list(OPERATING_MODES) if CONNECTION_ONLY else []) + ([] if _bv_policy() is not None else [BROWSER_VERIFY_MODE]),
        "reason": CONNECTION_ONLY_MESSAGE if CONNECTION_ONLY else "",
        "browser_verify": browser_verify_capability(),
    }


_PROJECT_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")
_RUN_RE = re.compile(r"trig_[A-Za-z0-9_-]{1,80}")
_CP_RE = re.compile(r"[A-Za-z0-9_.:-]{1,120}")
RUNS_SUBDIR = ".nrdp-runs"
CONTROL_SUBDIR = "control"
CANCEL_GRACE_SECONDS = 20.0   # after a cancel request, an unfinished status is reported as cancelled
_TERMINAL = ("complete", "completed", "passed", "failed", "error", "errored", "cancelled", "incomplete", "timeout", "blocked")
_EVIDENCE_EXT = (".png", ".jpg", ".jpeg")   # inline evidence is screenshots only; status/progress files are not evidence
_EVIDENCE_NAME = re.compile(r"^hop(\d{1,2})_(.+)_\d{3}\.png$")
_SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|credential|authorization)")
_SECRET_ASSIGN_RE = re.compile(r"(?i)\b(password|passwd|secret|token|authorization)\b(\s*[=:]\s*)(\S+)")


class RunError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# ── injectable adapters ──────────────────────────────────────────────────────

def _default_reports_root() -> str:
    from .config import settings  # lazy: keeps module exec-testable
    return os.path.abspath(settings.reports_dir)


def _default_launch(project: str) -> str:
    """Start via the EXISTING routes.trigger_run path; return trigger_id."""
    import asyncio
    from fastapi import HTTPException
    from . import routes
    try:
        resp = asyncio.run(routes.trigger_run(project, "shared-operator", routes.get_index()))
    except HTTPException as exc:
        raise RunError(str(exc.detail), exc.status_code) from exc
    return resp.trigger_id


def _default_cancel(project: str) -> dict:
    from fastapi import HTTPException
    from . import routes
    try:
        resp = routes.cancel_project_run(project, "shared-operator", routes.get_index())
    except HTTPException as exc:
        raise RunError(str(exc.detail), exc.status_code) from exc
    return resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)


_cfg: dict[str, Callable] = {"reports_root": _default_reports_root, "launch": _default_launch,
                             "cancel": _default_cancel, "now": lambda: datetime.now(timezone.utc)}


def configure(**kw: Callable) -> None:
    """Override reports_root / launch / cancel / now (tests)."""
    for k, v in kw.items():
        if k not in _cfg:
            raise KeyError(k)
        _cfg[k] = v


# ── helpers ──────────────────────────────────────────────────────────────────

def _check_project(name: str) -> None:
    if not isinstance(name, str) or not _PROJECT_RE.fullmatch(name):
        raise RunError("Invalid project name.", 400)


def _check_run(run_id: str) -> None:
    if not isinstance(run_id, str) or not _RUN_RE.fullmatch(run_id):
        raise RunError("Invalid run ID.", 400)


def run_dir(project_name: str, run_id: str) -> str:
    _check_project(project_name); _check_run(run_id)
    root = os.path.realpath(_cfg["reports_root"]())
    path = os.path.realpath(os.path.join(root, project_name, RUNS_SUBDIR, run_id))
    if not path.startswith(root + os.sep):
        raise RunError("Invalid run path.", 400)
    return path


def _share_dirs(path: str) -> None:
    """Create ``path`` dashboard-owned 0755 (CP45-G: nothing here is shared; the entrypoint hands the run folder to the runner uid).

    The runner container drops to a different uid than the dashboard, so it can only write its own
    files into folders created here if they are world-writable; the sticky bit (1777) stops other
    local users from replacing or deleting files they do not own.  The ``control`` folder is the
    opposite: dashboard-owned 0755, readable by the runner, writable by nobody else.  Nothing under
    either holds a secret (mode, hop progress, checkpoint prompts, screenshots).
    """
    created: set[str] = set()      # CP45-G: only directories created HERE are (re)moded; an existing run folder may already belong to the runner uid
    probe = os.path.abspath(path)
    while probe and not os.path.isdir(probe):
        created.add(probe)
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        raise RunError("The reports folder is not writable by the dashboard.", 500) from None
    parts = os.path.normpath(path).split(os.sep)
    if RUNS_SUBDIR not in parts:
        return
    leaf_index = len(parts)
    start = parts.index(RUNS_SUBDIR) - 1  # include the <project> folder itself
    for end in range(start + 1, leaf_index + 1):
        current = os.sep.join(parts[:end]) or os.sep
        if current not in created:
            continue
        try:
            os.chmod(current, 0o755)    # CP45-I: never shared or sticky; the runner owns only what report_handoff gives it
        except OSError:
            pass  # not ours to change (already created by the runner); it is writable or the run will report it


def _atomic_json(path: str, payload: dict) -> None:
    _share_dirs(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.chmod(tmp, 0o644)  # readable by the runner's uid; contains no secret
        os.replace(tmp, path)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _read_json(path: str) -> dict | None:
    try:
        if os.path.islink(path) or os.path.getsize(path) > 2_000_000:
            return None
        with open(path, encoding="utf-8") as fh:
            v = json.load(fh)
        return v if isinstance(v, dict) else None
    except (OSError, ValueError):
        return None


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[redacted]" if _SECRET_KEY_RE.search(str(k)) and not str(k).endswith(("_file", "_reference", "_state")) else scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return _SECRET_ASSIGN_RE.sub(r"\1\2[redacted]", value)
    return value


def _now() -> str:
    return _cfg["now"]().isoformat()


# ── API ──────────────────────────────────────────────────────────────────────

_PASSED = ("complete", "completed", "passed", "succeeded")


def check_preconditions(*, project: dict | None, last_test: dict | None, config_hash: str, mode: str) -> None:
    """Server-side gate for starting a run (the UI mirrors it, this enforces it).

    * The created project must have been built from the CURRENT connection settings.
    * A full run additionally needs a PASSED connection test made with those same settings.
    Editing a host, port, user, credential, hop-1 certificate or identity policy invalidates both.
    """
    if CONNECTION_ONLY and mode in OPERATING_MODES:
        raise RunError(CONNECTION_ONLY_MESSAGE, 409)
    if mode == BROWSER_VERIFY_MODE and _bv_policy() is None:
        raise RunError(BROWSER_VERIFY_DISABLED_MESSAGE, 409)          # capability first: nothing else about the request is considered
    if not project or not (project.get("project_name") or project.get("name")):
        raise RunError("Create the project before running this procedure.", 409)
    if project.get("config_hash") != config_hash:
        raise RunError("The connections changed after the project was created. Create the project again, then test the connections.", 409)
    if mode in ("full_run", BROWSER_VERIFY_MODE):
        ok = (isinstance(last_test, dict) and last_test.get("mode") == "connection_test"
              and str(last_test.get("status", "")).lower() in _PASSED and last_test.get("config_hash") == config_hash)
        if not ok:
            raise RunError("Run a connection test with the current connection settings before " + ("browser verification." if mode == BROWSER_VERIFY_MODE else "a full run."), 409)


def _browser_verify_block(draft, project_name: str, confirm_phrase: Any, leave_open_ack: Any, url: Any) -> dict:
    """API-side gate for browser_verify, in the same order as the runner's: capability, project, URL, confirmation, acknowledgement, binding."""
    pol = _bv_policy()
    if pol is None:
        raise RunError(BROWSER_VERIFY_DISABLED_MESSAGE, 409)
    if project_name not in pol["allowed_projects"]:
        raise RunError("This project is not enabled for browser verification.", 409)
    if url != BROWSER_VERIFY_URL:
        raise RunError("Only http://127.0.0.1:5004/ may be opened.", 400)
    if confirm_phrase != browser_verify_confirm_phrase(project_name):
        raise RunError("Type the confirmation phrase exactly: " + browser_verify_confirm_phrase(project_name), 400)
    if leave_open_ack != browser_verify_leave_open_phrase(project_name):
        raise RunError("Acknowledge that the browser window, its profile folder and a Run-history entry are left on the target: type " + browser_verify_leave_open_phrase(project_name), 400)
    if any(getattr(h, "protocol", "rdp") != "rdp" for h in draft.connections):
        raise RunError("Browser verification supports plain RDP chains only.", 409)
    try:
        rows = [[int(h.order), str(h.host), int(h.port), str(h.user), str(h.password_reference), str(h.certificate_name or ""),
                 str(h.certificate_fingerprint or ""), str(h.identity_policy)] for h in draft.connections]
    except Exception:
        raise RunError("The saved connections could not be read for this project.", 409) from None
    return {"url": url, "confirm_phrase": confirm_phrase, "leave_open_ack": leave_open_ack, "binding": connection_binding(project_name, rows)}


def start_run(draft, project_name: str, mode: str, confirm_phrase: str | None, config_hash: str | None = None, *,
              leave_open_ack: Any = None, url: Any = None) -> dict:
    _check_project(project_name)
    if not isinstance(mode, str) or mode not in MODES:
        raise RunError(f"Unknown run mode; use one of {', '.join(allowed_modes())}.", 400)
    if CONNECTION_ONLY and mode in OPERATING_MODES:
        # FAIL BEFORE MUTATION: nothing is written under .pending/ and _cfg["launch"] is never
        # called, so no runner is started.  Checked BEFORE the confirmation phrase, so supplying
        # the correct project name cannot bypass it.
        raise RunError(CONNECTION_ONLY_MESSAGE, 409)
    if mode == "full_run" and confirm_phrase != project_name:
        raise RunError("Type the project name exactly to confirm a full run.", 400)
    bv_block = _browser_verify_block(draft, project_name, confirm_phrase, leave_open_ack, url) if mode == BROWSER_VERIFY_MODE else None
    root = os.path.realpath(_cfg["reports_root"]())
    pending = os.path.join(root, project_name, RUNS_SUBDIR, ".pending")
    request = {"mode": mode, "project": project_name, "requested_at": _now(), "chain": True,
               "draft_id": str(getattr(draft, "id", "") if not isinstance(draft, dict) else draft.get("id", "")),
               "confirm_recorded": mode == "full_run",
               "steps_allowed": mode in OPERATING_MODES}
    if bv_block is not None:
        request["browser_verify"] = bv_block          # serialized to the runner, which re-validates every field on its own
    if config_hash:
        request["config_hash"] = config_hash   # what this run was made with; a passed test is bound to it
    # Written BEFORE launch (pending), then moved under the run_id once known.
    _atomic_json(os.path.join(pending, "run_request.json"), request)
    try:
        run_id = _cfg["launch"](project_name)
    except BaseException:
        try: os.unlink(os.path.join(pending, "run_request.json"))
        except OSError: pass
        raise
    _check_run(run_id)
    rd = run_dir(project_name, run_id)
    request["run_id"] = run_id
    _atomic_json(os.path.join(rd, "control", "run_request.json"), request)
    try: os.unlink(os.path.join(pending, "run_request.json"))
    except OSError: pass
    return {"run_id": run_id}


def _evidence(rd: str, root: str) -> list[dict]:
    out: list[dict] = []
    for base, dirs, files in os.walk(rd):
        dirs[:] = sorted(d for d in dirs if d != "control" and not d.startswith("."))
        for f in sorted(files):
            p = os.path.join(base, f)
            if os.path.islink(p) or not f.lower().endswith(_EVIDENCE_EXT) or f == "chain_progress.json":
                continue
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            item = {"name": f, "url": "/reports/" + rel}       # served by app.py /reports/{path}
            labelled = _EVIDENCE_NAME.match(f)
            if labelled:                                        # hop1_identity_console_007.png -> hop 1, phase
                item["hop"], item["phase"] = int(labelled.group(1)), labelled.group(2).replace("_", " ")
            out.append(item)
            if len(out) >= 500:
                return out
    return out


def _parse_iso(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


LAUNCHER_RECORD_MAX_BYTES = 16384
_LAUNCHER_EXIT_RE = re.compile(r"^Runner exited with status (\d{1,3}); inspect reports/spawn\.log\.$")


def _read_trusted_small_json(path: str) -> dict | None:
    """Parse a small JSON object from a file the DASHBOARD user owns, or return None.

    The file is opened WITHOUT following links and validated through the OPEN descriptor (regular file, our uid, not
    group/world-writable, small), so a swap between check and use cannot redirect the read; the read itself is bounded.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > LAUNCHER_RECORD_MAX_BYTES:
            return None
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            return None
        if info.st_mode & 0o022:
            return None
        raw = os.read(fd, LAUNCHER_RECORD_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > LAUNCHER_RECORD_MAX_BYTES:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _launcher_outcome(root: str, project_name: str, run_id: str) -> dict | None:
    """What the spawn launcher recorded when this run's runner PROCESS ENDED (``.ctrl/<project>/trigger_<run>.json.err|.ack``).

    Proof that the process is gone; it says nothing about connections.  Only the exit status and a FIXED-VOCABULARY
    classification are returned: launcher error text can carry paths or other detail, so it is never passed on.
    """
    base = os.path.join(root, ".ctrl", project_name)
    for suffix, kind in ((".json.err", "failed"), (".json.ack", "ended")):
        data = _read_trusted_small_json(os.path.join(base, f"trigger_{run_id}{suffix}"))
        if data is None or data.get("trigger_id") != run_id or data.get("project") != project_name:
            continue
        code = data.get("exit_code")
        code = code if isinstance(code, int) and not isinstance(code, bool) and -255 <= code <= 255 else None
        if kind == "ended":
            return {"kind": "ended", "exit_code": 0, "known": True}
        if code == 0:
            continue                                   # an error record that claims success is inconsistent: ignore it
        text = data.get("error")
        return {"kind": "failed", "exit_code": code, "known": isinstance(text, str) and bool(_LAUNCHER_EXIT_RE.fullmatch(text.strip()))}
    return None


def _launcher_error(outcome: dict) -> dict:
    if outcome["kind"] == "ended":
        return {"hop": None, "code": "RUNNER_NO_RESULT",
                "message": "The runner finished (exit status 0) but recorded no result for this run, so no connection result exists."}
    if outcome["known"] and outcome["exit_code"] is not None:
        return {"hop": None, "code": "RUNNER_EXITED_EARLY",
                "message": ("The runner process exited (status %d) before reporting a result for this run. No connection result was "
                            "recorded, so neither hop is known to have been tried. Details: reports/spawn.log on the dashboard host."
                            % outcome["exit_code"])}
    return {"hop": None, "code": "LAUNCHER_ERROR",
            "message": ("The launcher recorded an error before the runner reported a result for this run. No connection result was "
                        "recorded. Details: reports/spawn.log on the dashboard host.")}


def get_run(project_name: str, run_id: str) -> dict:
    """Run state for the UI.  Precedence (deterministic): a TERMINAL runner state > a cancel request that has taken effect >
    a launcher record proving the runner process ended without a result > the runner's own non-terminal state > pending."""
    rd = run_dir(project_name, run_id)
    if not os.path.isdir(rd):
        raise RunError("Run not found.", 404)
    root = os.path.realpath(_cfg["reports_root"]())
    req = _read_json(os.path.join(rd, "control", "run_request.json")) or {}
    status = _read_json(os.path.join(rd, "status.json"))
    progress = _read_json(os.path.join(rd, "chain_progress.json"))
    # The runner publishes its checkpoint request in the run folder (it cannot write control/).
    cp = _read_json(os.path.join(rd, "checkpoint.json")) or _read_json(os.path.join(rd, "control", "checkpoint.json"))
    ack = _read_json(os.path.join(rd, "control", "checkpoint_ack.json"))
    cancel = _read_json(os.path.join(rd, "control", "cancel_request.json"))
    pending = cp if cp and not (ack and ack.get("id") == cp.get("id")) else None
    state = (status or {}).get("state") or (progress or {}).get("phase") or "pending"
    state_source = "status" if (status or {}).get("state") else "progress"
    runner_terminal = str(state).lower() in _TERMINAL
    launcher = None if runner_terminal else _launcher_outcome(root, project_name, run_id)
    error = None
    if cancel and not runner_terminal:
        # A hard stop (container kill) can end the runner before it writes a final status.  Once the cancel request is older
        # than the grace period - or the launcher has recorded that the process ended - the UI must stop polling: "cancelled".
        asked = _parse_iso(cancel.get("requested_at"))
        if launcher is not None:   # CP45-D: elapsed time alone is NOT a teardown confirmation; only process-ended proof or a confirmed cancel record is
            state, state_source = "cancelled", "cancel_request"
            pending = None
    elif launcher is not None:
        # The runner process has ENDED without a result: a truthful terminal error, not "pending" forever.  A runner that
        # reported a terminal state never reaches this branch; its partial progress (if any) is kept as written.
        state, state_source = "error", "launcher"
        error = _launcher_error(launcher)
        pending = None
    marker = run_state.read_marker(os.path.join(root, ".ctrl"), project_name, run_id)
    if marker is not None:    # same effective-state rule as the project status / run list / idle readers
        eff, _src = run_state.effective_state(status, marker)
        if eff == "cancelled":
            state, state_source, pending, error = "cancelled", "cancel_record", None, None
        elif eff == "cancelling":
            state, state_source, pending = "cancelling", "cancel_pending", None
    requested_mode = (status or {}).get("requested_mode") or req.get("mode")
    effective_mode = (status or {}).get("effective_mode") or (status or {}).get("mode") or req.get("mode")
    downgraded = bool((status or {}).get("downgraded")) or bool(requested_mode and effective_mode and requested_mode != effective_mode)
    notes = list((progress or {}).get("notes") or [])
    if error is not None and not progress:
        notes.append("No runner progress was recorded for this run.")
    # ``status`` is the plain state string the UI compares; the full status.json is ``status_detail``.
    out = {"run_id": run_id, "project": project_name, "mode": effective_mode, "requested_mode": requested_mode,
           "effective_mode": effective_mode, "downgraded": downgraded,
           "downgrade_reason": (status or {}).get("downgrade_reason") or "",
           "config_hash": req.get("config_hash"),
           "state": state, "state_source": state_source,
           "status": state, "status_detail": status, "chain_progress": progress,
           "notes": notes,
           "checkpoint": {k: pending.get(k) for k in ("id", "step_order", "title", "instructions", "requested_at")} if pending else None,
           "checkpoint_pending": bool(pending), "checkpoint_ack": ack,
           "report_url": ("/reports/" + os.path.relpath(os.path.join(rd, "chain_report.html"), root).replace(os.sep, "/"))
                         if os.path.isfile(os.path.join(rd, "chain_report.html")) else None,
           "evidence": _evidence(rd, root)}
    bo = _read_json(os.path.join(rd, "chain_outcome.json")) or {}
    if isinstance(bo.get("browser"), dict):
        out["browser_verify"] = _browser_summary(bo["browser"])
    if error is not None:
        out["error"] = error          # only present when the launcher proved the process ended; the UI reads it as run.error
    return scrub(out)


def _browser_summary(b: dict) -> dict:
    """The sanitized subset the UI renders.  Playback and cleanup are separate keys; no raw model text, typed command or credential exists in it."""
    keep = lambda d, ks: {k: d.get(k) for k in ks if k in d} if isinstance(d, dict) else {}   # noqa: E731
    cl = keep(b.get("cleanup"), ("status", "reason", "route", "close_input_sent", "fulfilment", "window_state_after", "note", "expected_artifacts", "operator_guidance"))
    return {"status": b.get("status"), "code": b.get("code"), "message": b.get("message"), "verdict": b.get("verdict"),
            "playback": keep(b.get("playback"), ("status", "code", "verdict", "independent_of_cleanup")),
            "cleanup": cl, "claims": b.get("claims") or {}, "timeline": b.get("timeline") or {},
            "streams": [keep(s, ("label", "state", "reasons")) for s in (b.get("streams") or []) if isinstance(s, dict)],
            "model_usage": b.get("model_usage") or {}, "model_budget": keep(b.get("model_budget"), ("attempts", "failed", "cap", "failure_cap", "deadline_s", "exhausted", "exhausted_reason")), "evaluation_binding": keep(b.get("evaluation_binding"), ("request_contract_unchanged", "runtime_model_matches_evaluated_profile", "note")),
            "frames": [keep(f, ("ref", "t_rel", "page_state", "phase")) for f in (b.get("frames") or []) if isinstance(f, dict)][:40],
            "not_proven": b.get("not_proven") or []}


def cancel_run(project_name: str, run_id: str) -> dict:
    rd = run_dir(project_name, run_id)
    if not os.path.isdir(rd):
        raise RunError("Run not found.", 404)
    # Written FIRST so the runner can stop gracefully (cancel its own event, tear down) before the
    # existing hard stop (container stop/kill) takes effect.
    _atomic_json(os.path.join(rd, "control", "cancel_request.json"), {"run_id": run_id, "requested_at": _now()})
    result = _cfg["cancel"](project_name)
    return scrub({"run_id": run_id, "cancelled": True, "detail": result})


def ack_checkpoint(project_name: str, run_id: str, checkpoint_id: str, note: str | None) -> dict:
    rd = run_dir(project_name, run_id)
    if not isinstance(checkpoint_id, str) or not _CP_RE.fullmatch(checkpoint_id):
        raise RunError("Invalid checkpoint ID.", 400)
    if note is not None and (not isinstance(note, str) or len(note) > 500):
        raise RunError("The note must be at most 500 characters.", 400)
    cp = _read_json(os.path.join(rd, "checkpoint.json")) or _read_json(os.path.join(rd, "control", "checkpoint.json"))
    ack_path = os.path.join(rd, "control", "checkpoint_ack.json")
    prior = _read_json(ack_path)
    if not cp or (prior and prior.get("id") == cp.get("id")):
        raise RunError("No operator checkpoint is pending for this run.", 409)
    if cp.get("id") != checkpoint_id:
        raise RunError("This checkpoint is no longer the pending one; refresh the run.", 409)
    payload = {"id": checkpoint_id, "acknowledged_by": "shared-operator",
               "note": scrub(note) if note else None, "ts": _now()}
    _atomic_json(ack_path, payload)
    return payload
