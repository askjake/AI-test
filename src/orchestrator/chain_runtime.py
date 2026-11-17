"""Run-time glue for nested-RDP (``rdp-chain``) projects (NRDP-1, S1b-2).

Pure and dependency-injected: standard library only, NO intra-package imports, so it
can be exec-tested without the package.  The runner adapter (see
``run_chain_session``) receives a ChainController-like object, a step driver and a
CheckpointGate; it never sees a secret.

Contents
* read_run_request(reports_dir, project, trigger_id) -> RunRequest
* select_steps(steps, mode) -> (to_run, skipped)
* CheckpointGate(control_dir, clock, sleep, cancel_event, timeout).request(step)
* labelled_evidence(step_records, active_desktop)
* chain_prompt_preamble(chain_hops_public, final_hop)
* make_read_secret(secrets_dir) -> callable(password_file) -> str
* run_chain_session(...) -> ChainRunOutcome   (orchestration; fakes in tests)
* StepGuard / GuardedComputer: application-enforced screen + command checks while a step runs
* render_chain_section_html(outcome_dict) -> str (escaped HTML for report.py)
"""
from __future__ import annotations

import html
import json
import os
import re
import secrets as _secrets
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import browser_modes as bm

CONNECTION_TEST = "connection_test"
READ_ONLY_CHECK = "read_only_check"
FULL_RUN = "full_run"
MODES = (CONNECTION_TEST, READ_ONLY_CHECK, FULL_RUN)

# ------------------------------------------------- connection-only qualification (review B1)
# This build is qualified for CONNECTION TESTS ONLY.  Operating execution is disabled in the
# RUNTIME, not just in the dashboard, so bypassing the dashboard (a generic/direct trigger, the
# CLI, the scheduler, or a forged-but-trusted control file) still cannot run a procedure step.
#
# read_only_check is disabled as well.  A "read-only" step is only read-only in its INTENT: it
# still types and clicks, so it can act on the wrong desktop.  The wrong-desktop and
# inner-dialog-authenticity risks that make an operating run unsafe are unresolved, so neither
# operating mode is offered.
#
# Deliberately a module constant with NO environment variable and NO hidden enable switch:
# lifting this restriction requires a reviewed source change and a re-packaged candidate.
CONNECTION_ONLY = True
OPERATING_MODES = (READ_ONLY_CHECK, FULL_RUN)
CONNECTION_ONLY_REASON = ("operating steps are disabled in this build "
                          "(connection-only qualification)")


# CP43: the RUNNER'S OWN browser_verify capability.  None == disabled (shipped default).  This is deliberately NOT the dashboard's switch
# (procedure_runs.BROWSER_VERIFY_POLICY): the API serves/accepts a request, the runner independently decides whether to honour it from THIS value.
# No env-var switch and no hidden flag: enabling requires a reviewed source change on BOTH sides.
BROWSER_VERIFY_POLICY: Any = None


def browser_verify_policy() -> Any:
    if BROWSER_VERIFY_POLICY is not None:
        return BROWSER_VERIFY_POLICY
    from . import browser_verify as _bv
    return _bv.DEFAULT_POLICY


def operating_execution_allowed(mode: Any) -> bool:
    """False whenever ``mode`` would execute procedure steps under the current policy."""
    return not (CONNECTION_ONLY and _mode_value(mode) in OPERATING_MODES)

TRIGGER_ENV = "ORCHESTRATOR_TRIGGER_ID"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _mode_value(mode: Any) -> str:
    value = getattr(mode, "value", mode)
    return value if value in MODES else CONNECTION_TEST


def _safe_name(name: Any) -> bool:
    return isinstance(name, str) and bool(_NAME_RE.fullmatch(name)) and ".." not in name


# ----------------------------------------------------------------- run request


@dataclass
class RunRequest:
    mode: str = CONNECTION_TEST
    confirmed: bool = False
    source: str = "default"          # "default" | "request"
    reason: str = ""
    run_dir: str | None = None       # <reports>/<project>/.nrdp-runs/<trigger_id>
    requested_mode: str = ""         # what the dashboard asked for; differs from ``mode`` on a downgrade
    refused: bool = False            # CP43: rejected outright -- NO session, browser, model or input activity of any kind
    browser: Any = None              # CP43: bm.BrowserGrant, created ONLY by read_run_request after the runner's own validation

    def __post_init__(self) -> None:
        if self.refused is True:
            self.mode = bm.REFUSED_MODE      # CP44: a refused request carries no runnable mode, so no later code can treat it as a connection_test


def run_dir_for(reports_dir: str, project: str, trigger_id: str) -> str | None:
    if not (_safe_name(project) and _safe_name(trigger_id)):
        return None
    base = os.path.abspath(reports_dir)
    path = os.path.abspath(os.path.join(base, project, ".nrdp-runs", trigger_id))
    if not path.startswith(base + os.sep):
        return None
    return path


def start_cancel_watcher(control_dir: str, event: Any, *, poll: float = 1.0,
                         sleep: Callable[[float], None] = time.sleep) -> Callable[[], None]:
    """Set ``event`` when the dashboard writes a trusted control/cancel_request.json.

    Returns a stop function.  The existing hard stop (container stop/kill) still applies; this
    gives the controller a chance to cancel at its next check and tear down its own resources.
    """
    import threading
    stop = threading.Event()
    path = os.path.join(control_dir, "cancel_request.json")

    def loop() -> None:
        while not stop.is_set() and not event.is_set():
            if os.path.lexists(path) and trusted_control_file(path):
                event.set()
                return
            sleep(poll)

    thread = threading.Thread(target=loop, name="nrdp-cancel-watch", daemon=True)
    thread.start()
    return stop.set


def install_sigterm_cancel(event: Any) -> Callable[[], None]:
    """Map SIGTERM (docker stop) to ``event``; returns a restore function. No-op off the main thread."""
    import signal
    try:
        previous = signal.signal(signal.SIGTERM, lambda *_a: event.set())
    except (ValueError, OSError, AttributeError):
        return lambda: None
    return lambda: signal.signal(signal.SIGTERM, previous)


CONTROL_UID_ENV = "ORCHESTRATOR_CONTROL_UID"


def _control_uid(environ: Any) -> int | None:
    """The pinned dashboard uid, or None when it is absent or not a plain decimal uid.

    SECURITY M2: only an ASCII decimal value counts.  ``str.isdigit()`` alone is not a safe
    gate -- it is also true for superscripts (``"\u00b2"``, where ``int()`` then raises
    ValueError and would propagate out of the trust check instead of refusing) and for
    non-ASCII decimal digits (``"\u0661\u0662\u0663"`` parses as 123, so a confusable value
    could alias a real uid).  An unparsable pin must simply refuse control trust.
    """
    value = (environ.get(CONTROL_UID_ENV) or "").strip()
    if not value.isascii() or not value.isdigit():
        return None
    return int(value)


_LSTAT: Callable[[str], Any] = os.lstat   # indirection so tests can present a POSIX view on any OS


def trusted_control_file(path: str, *, lstat: Callable[[str], Any] | None = None, environ: Any = None,
                         posix: bool | None = None) -> bool:
    """True only for a regular file the dashboard wrote into a dashboard-owned control folder.

    Authenticity comes from OWNERSHIP, not from a sticky bit: the ``control`` folder is created by
    the dashboard (mode 0755, so no other local user can add, rename or delete anything in it) and
    every message in it is a dashboard-owned, single-link, non-group/world-writable regular file.
    ``ORCHESTRATOR_CONTROL_UID`` (the dashboard's uid, passed in by the host launcher) must be set
    on POSIX: both the folder and the file must belong to exactly that uid.  ``posix`` is injectable
    so the permission logic can be exercised as POSIX on any OS, the same way ``lstat`` is.
    """
    environ = os.environ if environ is None else environ
    lstat = lstat or _LSTAT
    posix = (os.name == "posix") if posix is None else posix
    try:
        info = lstat(path)
        folder = lstat(os.path.dirname(path))
    except OSError:
        return False
    import stat as _stat
    if not _stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return False
    if info.st_mode & 0o022:
        return False
    if not _stat.S_ISDIR(folder.st_mode) or folder.st_mode & 0o022:
        return False          # a folder others can write to lets them swap the file
    pinned = _control_uid(environ)
    if pinned is not None:
        return info.st_uid == pinned and folder.st_uid == pinned
    # SECURITY M2: without the pinned dashboard uid, "file and folder share an owner" is a much
    # weaker test -- any single local account satisfies it inside a folder it owns itself.  The
    # host launcher always passes ORCHESTRATOR_CONTROL_UID (scripts/run_container.sh L21/L399), so
    # on POSIX a missing or non-numeric value means we cannot attribute this request and must
    # refuse it.  Refusing downgrades the run to connection_test rather than honouring an
    # unattributable request.  Non-POSIX keeps the owner rule (no meaningful uid there).
    if posix:
        return False
    return info.st_uid == folder.st_uid


def read_run_request(reports_dir: str, project: str, trigger_id: str | None, expected_binding: str | None = None) -> RunRequest:
    """Missing / invalid / unsafe => connection_test (never anything stronger); an unknown or malformed mode, or a browser_verify request that fails
    ANY runner-side check, is REFUSED (no session at all).  ``expected_binding`` is recomputed by the caller from the project the runner loaded."""
    if trigger_id is None:
        trigger_id = os.environ.get(TRIGGER_ENV) or None  # no "newest request" fallback: id must match
    if not trigger_id:
        return RunRequest(reason="no trigger id")
    run_dir = run_dir_for(reports_dir, project, trigger_id)
    if run_dir is None:
        return RunRequest(reason="unsafe project or trigger id")
    path = os.path.join(run_dir, "control", "run_request.json")
    if os.path.lexists(path) and not trusted_control_file(path):
        return RunRequest(reason="run request is not trusted (owner, link or permission check failed)", run_dir=run_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return RunRequest(reason="run request missing or unreadable", run_dir=run_dir)
    claims_bv = isinstance(data, dict) and data.get("mode") == bm.BROWSER_VERIFY

    def deny(reason: str) -> RunRequest:
        # CP44: a request that CLAIMS browser_verify and fails any identity check is refused outright, never run as something else.
        if claims_bv:
            return RunRequest(refused=True, reason=f"browser_verify refused before launch: {reason}", run_dir=run_dir, requested_mode=bm.BROWSER_VERIFY)
        return RunRequest(reason=reason, run_dir=run_dir)
    if not isinstance(data, dict) or data.get("chain") is not True:
        return deny("run request invalid")
    if data.get("project") not in (None, project):
        return deny("run request is for another project")
    # SECURITY M2: the request must belong to the run it was found under, so a request cannot be
    # replayed into a different run directory.  The dashboard stamps run_id when it moves the
    # request from .pending into control/ (procedure_runs.start_run).
    request_run_id = data.get("run_id")
    if request_run_id is not None and str(request_run_id) != str(trigger_id):
        return deny("run request is for another run id")
    if "mode" not in data:
        # CP43 documented compatibility path: a legacy/request-less request is a connection_test and nothing else.
        return RunRequest(reason=bm.LEGACY_REASON, run_dir=run_dir)
    mode = data.get("mode")
    if not bm.is_canonical(mode):
        return RunRequest(refused=True, reason="mode rejected: unknown or malformed mode value", run_dir=run_dir, requested_mode=bm.UNRECOGNIZED)
    confirmed = data.get("confirm_recorded") is True
    if mode == FULL_RUN and not confirmed:
        return RunRequest(mode=CONNECTION_TEST, reason="full_run without recorded confirmation",
                          run_dir=run_dir, requested_mode=mode)
    if mode == FULL_RUN and request_run_id is None:
        # SECURITY M2: never escalate to a full run on a request that is not bound to this run id.
        return RunRequest(mode=CONNECTION_TEST, reason="full_run request is not bound to a run id",
                          run_dir=run_dir, requested_mode=mode)
    if CONNECTION_ONLY and mode in OPERATING_MODES:
        # Last gate before an operating mode would be granted.  Deliberately placed AFTER the
        # project, run-id, confirmation and run-id-binding rules so those M2 checks still run and
        # still report their own specific reasons; this only removes the final success path.
        # Independent of the dashboard: a generic/direct trigger, the CLI, the scheduler or a
        # genuinely dashboard-owned, confirmed, run-id-bound operating request all land here.
        return RunRequest(mode=CONNECTION_TEST, confirmed=confirmed, source="request",
                          reason=CONNECTION_ONLY_REASON, run_dir=run_dir, requested_mode=mode)
    if mode == bm.BROWSER_VERIFY:
        def refuse(code: str) -> RunRequest:
            return RunRequest(refused=True, reason=f"browser_verify refused before launch: {code}", run_dir=run_dir, requested_mode=mode)
        if request_run_id is None:
            return refuse("RUN_ID_NOT_BOUND")                 # never grant on a request that is not bound to this run id
        grant, code = bm.validate_browser_request(policy=browser_verify_policy(), project=project, run_id=str(trigger_id),
                                                  block=data.get("browser_verify"), expected_binding=expected_binding)
        if grant is None:
            return refuse(code)
        return RunRequest(mode=bm.BROWSER_VERIFY, confirmed=True, source="request", run_dir=run_dir, requested_mode=mode, browser=grant)
    return RunRequest(mode=mode, confirmed=confirmed, source="request", run_dir=run_dir, requested_mode=mode)


# --------------------------------------------------------------- step selection


def _is_checkpoint(step: dict) -> bool:
    return str(step.get("kind", "")) == "operator-checkpoint"


def select_steps(procedure_steps: Iterable[dict], mode: Any) -> tuple[list[dict], list[dict]]:
    mode = _mode_value(mode)
    steps = sorted((dict(s) for s in procedure_steps or []), key=lambda s: int(s.get("order", 0)))
    to_run: list[dict] = []
    skipped: list[dict] = []
    for step in steps:
        if mode == CONNECTION_TEST:
            reason = "connection test does not run operating steps"
        elif mode == READ_ONLY_CHECK:
            if _is_checkpoint(step):
                reason = "operator checkpoint is not run in read-only check"
            elif step.get("mutating", True) is not False:
                reason = "mutating step is not run in read-only check"
            elif step.get("read_only_ok") is not True:
                reason = "step is not marked read-only"
            else:
                reason = ""
        else:
            reason = ""
        if reason:
            skipped.append({"order": step.get("order"), "title": step.get("title", ""),
                            "status": "skipped", "reason": reason})
        else:
            to_run.append(step)
    return to_run, skipped


# -------------------------------------------------------------- checkpoint gate


def _atomic_write_json(path: str, payload: dict) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        try:
            os.fchmod(fd, 0o644)  # no secrets; the dashboard (a different uid) must read it
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class Ack:
    id: str
    acknowledged_by: str = ""
    note: str = ""
    ts: Any = None


class CheckpointGate:
    def __init__(self, control_dir: str, *, clock: Callable[[], float] | None = None,
                 sleep: Callable[[float], None] | None = None, cancel_event: Any = None,
                 timeout: float = 3600.0, poll: float = 2.0,
                 now_iso: Callable[[], str] | None = None,
                 new_id: Callable[[], str] | None = None,
                 request_dir: str | None = None) -> None:
        # ``control_dir`` is dashboard->runner (read-only for the runner).  The runner publishes
        # its checkpoint request in ``request_dir`` (the run folder), which it can write.
        self.control_dir = control_dir
        self.request_dir = request_dir or os.path.dirname(os.path.abspath(control_dir))
        self._clock = clock if clock is not None else (lambda: time.monotonic())
        self._sleep = sleep if sleep is not None else (lambda seconds: time.sleep(seconds))
        self._cancel = cancel_event
        self.timeout = timeout
        self.poll = poll
        self._now_iso = now_iso or (lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self._new_id = new_id or (lambda: _secrets.token_hex(4))
        self.records: list[dict] = []

    def _cancelled(self) -> bool:
        return bool(self._cancel is not None and self._cancel.is_set())

    def _read_ack(self, cp_id: str) -> Ack | None:
        ack_path = os.path.join(self.control_dir, "checkpoint_ack.json")
        if os.path.lexists(ack_path) and not trusted_control_file(ack_path):
            return None  # forged, linked or foreign-owned acknowledgements never count
        try:
            with open(ack_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("id") != cp_id:
            return None  # stale or foreign ack
        return Ack(id=cp_id, acknowledged_by=str(data.get("acknowledged_by", ""))[:64],
                   note=str(data.get("note", ""))[:1000], ts=data.get("ts"))

    def request(self, step: dict) -> Ack | None:
        order = step.get("order")
        cp_id = f"cp-{order}-{self._new_id()}"
        record = {"id": cp_id, "step_order": order, "title": str(step.get("title", "")),
                  "requested": True, "acked": False, "note": "", "outcome": "pending"}
        self.records.append(record)
        _atomic_write_json(os.path.join(self.request_dir, "checkpoint.json"), {
            "id": cp_id, "step_order": order, "title": record["title"],
            "instructions": str(step.get("instructions", "")), "requested_at": self._now_iso(),
        })
        deadline = self._clock() + self.timeout
        while True:
            if self._cancelled():
                record["outcome"] = "cancelled"
                return None
            ack = self._read_ack(cp_id)
            if ack is not None:
                record.update(acked=True, note=ack.note, outcome="acknowledged")
                return ack
            if self._clock() >= deadline:
                record["outcome"] = "timeout"
                return None
            self._sleep(self.poll)

    def unacked_required(self, required: Iterable[int]) -> list[int]:
        acked = {r["step_order"] for r in self.records if r["acked"]}
        return [o for o in required if o not in acked]


# -------------------------------------------------------------- evidence/prompt


def labelled_evidence(step_records: Iterable[Any], active_desktop: int) -> list[dict]:
    out = []
    for rec in step_records or []:
        item = dict(rec) if isinstance(rec, dict) else {"path": str(rec)}
        item.setdefault("hop", active_desktop)
        item["active_desktop"] = item.get("hop", active_desktop)
        item["label"] = f"Hop {item['active_desktop']} desktop"
        out.append(item)
    return out


FORBIDDEN_TYPED = re.compile(
    r"(?i)(?:\bstart\.cmd\b|\bstart\.ps1\b|\bManage-Service\.ps1\b|\bStop-Process\b|\btaskkill\b"
    r"|\b(?:Stop|Restart)-Service\b[^\r\n]*\s-Force\b|\bStop-Service\b[^\r\n]*\s-NoWait\b)")
SERVICE_VERBS = re.compile(r"(?i)\b(Stop|Start|Restart|Suspend|Resume|Set)-Service\b")
POWER_OR_SERVICE_TOOLS = re.compile(
    r"(?i)\bsc(?:\.exe)?\s+(?:stop|start|config|delete)\b|\bnet\s+(?:stop|start)\b|\b(?:Restart|Stop)-Computer\b|\bshutdown(?:\.exe)?\b")
ELEVATION_REQUEST = re.compile(r"(?i)\b(?:as\s+administrator|run\s+as\s+admin|elevated|PowerShell\s*\(Admin\))")


def chain_prompt_preamble(chain_hops_public: Iterable[Any], final_hop: int) -> str:
    def g(h, k):
        return h.get(k) if isinstance(h, dict) else getattr(h, k, None)
    lines = []
    for h in chain_hops_public or []:
        host = re.sub(r"[^A-Za-z0-9_.:\-]", "", str(g(h, "host") or ""))
        user = re.sub(r"[^A-Za-z0-9_.@\\\-]", "", str(g(h, "user") or ""))
        lines.append(f"- hop {g(h, 'order')}: {host} (user {user})")
    return (
        "CONNECTION CHAIN CONTEXT (set by the application)\n"
        + "\n".join(lines) + "\n"
        f"All actions apply ONLY to the Windows desktop of hop {int(final_hop)}, which is shown "
        "full screen inside the earlier desktops. Sign-in to every hop has already been done by "
        "the application.\n"
        "Rules: never type, request, reveal or look for passwords or credentials. Never run "
        "anything on the Linux runner host. If any sign-in, lock, credential, certificate or "
        "identity prompt appears, STOP and report it instead of answering it. Hardware or physical "
        "work (cables, COM ports, remote-control button tests) is done by the operator through an "
        "operator checkpoint; do not attempt it yourself.\n"
        "Do ONLY the step you are given now. The rest of the manual is background, not permission "
        "to perform later steps.\n"
        "Elevation: when the step tells you to open an administrator window, a User Account Control "
        "box that only offers Yes/No may be approved with Yes. If any elevation or sign-in box asks "
        "for a user name or password, STOP and report it.\n"
        "Forbidden as substitutes or recovery: start.cmd, start.ps1, Manage-Service.ps1, Stop-Process, "
        "taskkill, -Force, and any other forced termination. Use Stop-Service / Start-Service exactly "
        "as the step says. If a service does not stop or start in the time allowed, STOP and report "
        "the failure; never force it.\n"
        "A free TCP port does not prove a serial (COM) handle was released; a Running service does "
        "not prove the application is healthy; HTTP 200 does not prove the inventory is correct.\n"
    )


def make_read_secret(secrets_dir: str, max_bytes: int = 4096) -> Callable[[str], str]:
    """Same traversal guard as Targets._secret_path; value is never logged."""
    base = os.path.abspath(secrets_dir)

    def read_secret(password_file: str) -> str:
        path = os.path.abspath(os.path.join(base, str(password_file)))
        if not path.startswith(base + os.sep) or not os.path.isfile(path):
            raise RuntimeError("saved credential reference not found")
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read(max_bytes)
        return value.rstrip("\r\n")

    return read_secret


# --------------------------------------------------------------- orchestration


@dataclass
class ChainRunOutcome:
    status: str                       # passed | failed | errored | incomplete
    mode: str
    chain_ok: bool = False
    error: dict | None = None         # {hop, code, message}
    hops: list[dict] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    checkpoints: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    agent_invoked: bool = False
    requested_mode: str = ""          # what the operator asked for
    downgrade_reason: str = ""        # why the effective mode is weaker than requested (empty = none)
    notes: list[str] = field(default_factory=list)
    browser: dict | None = None       # CP43: sanitized browser_verify result (playback and cleanup are SEPARATE keys inside it)

    @property
    def downgraded(self) -> bool:
        return bool(self.requested_mode and self.requested_mode != self.mode)

    def as_dict(self) -> dict:
        data = dict(self.__dict__)
        data["downgraded"] = self.downgraded
        data["effective_mode"] = self.mode
        return data


def _hops_from(result: Any) -> list[dict]:
    state = getattr(result, "state", None)
    out = []
    for h in getattr(state, "hops", []) or []:
        st = getattr(h, "status", "")
        out.append({"order": h.order, "host": h.host, "user": h.user,
                    "status": getattr(st, "value", st), "detail": h.detail})
    return out


def run_chain_session(*, controller: Any, chain: list, procedure: dict | None, mode: Any,
                      drive_step: Callable[[dict, str], dict], gate: CheckpointGate | None,
                      cancel_event: Any = None,
                      revalidate: Callable[[], tuple[bool, str | None, str]] | None = None,
                      requested_mode: str | None = None, downgrade_reason: str = "",
                      browser_runner: Callable[[], dict] | None = None) -> ChainRunOutcome:
    """Establish chain -> (mode) run steps -> teardown in finally.

    drive_step(step, preamble) runs the existing agent loop for ONE step and returns
    {status: passed|failed|errored, summary, evidence:[...]}.  It is never called for
    connection_test, after a failed hop, or for operator checkpoints.
    """
    is_bv = getattr(mode, "value", mode) == bm.BROWSER_VERIFY
    mode = bm.BROWSER_VERIFY if is_bv else _mode_value(mode)
    procedure = procedure or {}
    out = ChainRunOutcome(status="errored", mode=mode, requested_mode=requested_mode or mode,
                          downgrade_reason=downgrade_reason if (requested_mode and requested_mode != mode) else "")
    try:
        result = controller.establish(chain)
        out.hops = _hops_from(result)
        out.evidence = labelled_evidence(getattr(result, "evidence", []) or [], 0)
        if not getattr(result, "ok", False):
            out.error = {"hop": getattr(result, "failed_hop", None),
                         "code": getattr(result, "code", None) or "CHAIN_FAILED",
                         "message": getattr(result, "message", "")}
            _, out.skipped = select_steps(procedure.get("steps", []), CONNECTION_TEST)
            for s in out.skipped:
                s["reason"] = "connection chain failed; no step was run"
            return out
        out.chain_ok = True
        if is_bv:
            # The final desktop identity was confirmed by establish() above; the verifier re-checks it itself before it types anything.
            _, out.skipped = select_steps(procedure.get("steps", []), CONNECTION_TEST)
            for s in out.skipped:
                s["reason"] = "browser_verify runs no procedure steps"
            if browser_runner is None:
                out.error = {"hop": None, "code": "BROWSER_RUNNER_MISSING", "message": "no browser runner was supplied"}
                out.status = "errored"
                return out
            result = browser_runner()
            out.browser = result if isinstance(result, dict) else None
            out.status = bm.run_status_from(out.browser)
            return out
        to_run, out.skipped = select_steps(procedure.get("steps", []), mode)
        if mode == CONNECTION_TEST:
            out.status = "passed"
            return out
        preamble = chain_prompt_preamble(chain, int(procedure.get("final_hop") or len(chain)))
        status = "passed"
        for step in to_run:
            if cancel_event is not None and cancel_event.is_set():
                status = "incomplete"
                break
            if _is_checkpoint(step):
                ack = gate.request(step) if gate is not None else None
                rec = {"order": step.get("order"), "title": step.get("title", ""),
                       "status": "acknowledged" if ack else "incomplete",
                       "note": "operator acknowledged; physical result not verified by the application"
                       if ack else "checkpoint not acknowledged"}
                out.steps.append(rec)
                if ack is None:
                    status = "incomplete"
                    break
                continue
            if revalidate is not None:
                # Before ANY operating step: prove input still reaches the final desktop.
                ok, code, message = revalidate()
                if not ok:
                    status = _desktop_lost(out, step, chain, code, message, "before")
                    break
            out.agent_invoked = True
            res = drive_step(step, preamble) or {}
            st = res.get("status", "errored")
            record = {"order": step.get("order"), "title": step.get("title", ""),
                      "status": st, "summary": res.get("summary", "")}
            out.steps.append(record)
            out.evidence += labelled_evidence(res.get("evidence", []), controller.active_desktop())
            if res.get("error_code"):
                out.error = {"hop": len(chain), "code": res["error_code"], "message": res.get("summary", "")}
            if st != "passed":
                status = "failed" if st == "failed" else "errored"
                break
            if revalidate is not None and step.get("mutating") is True:
                # After a change: confirm it was applied to the intended machine.
                ok, code, message = revalidate()
                if not ok:
                    record["status"] = "failed"
                    record["summary"] = (record.get("summary") or "") + " The final desktop could not be re-confirmed after this step."
                    status = _desktop_lost(out, step, chain, code, message, "after", append=False)
                    break
        required = [int(o) for o in procedure.get("required_checkpoints", []) or []]
        if status == "passed" and required and mode == FULL_RUN:
            missing = gate.unacked_required(required) if gate is not None else required
            if missing:
                status = "incomplete"
        out.status = status
        return out
    except Exception as exc:  # never leak secrets: controller already withholds them
        out.status = "errored"
        out.error = out.error or {"hop": None, "code": "RUNTIME_ERROR", "message": type(exc).__name__}
        return out
    finally:
        if gate is not None:
            out.checkpoints = list(gate.records)
        try:
            controller.teardown()
        except Exception:
            pass
        try:  # what teardown did, and what it did NOT close, belongs in the report
            out.notes = list(controller.notes())
        except Exception:
            out.notes = out.notes or []


def _desktop_lost(out: ChainRunOutcome, step: dict, chain: list, code: str | None, message: str,
                  when: str, append: bool = True) -> str:
    if code == "CANCELLED":
        if append:
            out.steps.append({"order": step.get("order"), "title": step.get("title", ""), "status": "incomplete",
                              "summary": "Cancelled before this step started."})
        return "incomplete"
    out.error = {"hop": len(chain), "code": "ACTIVE_DESKTOP_CHANGED",
                 "message": f"The final desktop could not be re-confirmed {when} step {step.get('order')} "
                            f"({code}). {message}".strip()}
    if append:
        out.steps.append({"order": step.get("order"), "title": step.get("title", ""), "status": "failed",
                          "summary": "Not run: the final desktop could not be re-confirmed first; "
                                     "no input was sent for this step."})
    return "failed"


def guard_report_result(outcome: ChainRunOutcome, required: Iterable[int],
                        gate: CheckpointGate | None) -> str:
    """Final status may never be 'passed' while a required checkpoint lacks an ack."""
    missing = gate.unacked_required(list(required)) if gate is not None else list(required)
    if outcome.mode == FULL_RUN and missing and outcome.status == "passed":
        return "incomplete"
    return outcome.status


# ------------------------------------------------------------- step guard (F4 / C5)
#
# While an operating step runs, the vision agent has free keyboard and mouse control of the
# final desktop.  These classes make three rules APPLICATION-enforced instead of prompt-only:
#   1. no input is sent while the latest screen is a sign-in, lock, certificate or credential
#      elevation prompt (a consent-only elevation prompt is allowed only for the step that
#      asks for an administrator window);
#   2. forbidden recovery commands (start.cmd, Stop-Process, taskkill, -Force, ...) are never typed;
#   3. service/power commands are typed only if THIS step asks for them (the manual is context,
#      not permission for later steps).

BLOCKING_STATES = frozenset({
    "credential_prompt", "credential_account_list", "lock_or_logon_screen", "certificate_warning",
    "uac_credential_prompt", "remote_desktop_identity_mismatch",
})
_READ_ONLY_COMPUTER_CALLS = frozenset({"screenshot", "cursor_position", "mouse_move", "scale_point"})
_BLOCKED_ALWAYS = frozenset({"type_secret"})


class StepGuardViolation(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


class StepGuard:
    def __init__(self, classify: Callable[[bytes], Any], *, allow_uac_consent: bool = False,
                 step_text: str = "", mutating_allowed: bool = False, min_confidence: float = 0.6) -> None:
        self._classify = classify
        self.allow_uac_consent = allow_uac_consent
        self.min_confidence = min_confidence
        self.mutating_allowed = mutating_allowed
        self.allowed_verbs = {m.group(1).lower() for m in SERVICE_VERBS.finditer(step_text or "")} if mutating_allowed else set()
        self.violation: tuple[str, str] | None = None
        self.actions = 0
        self._latest: bytes | None = None
        self._latest_checked = True

    def note_screenshot(self, png: bytes) -> None:
        self._latest, self._latest_checked = png, False

    def _screen_check(self) -> None:
        if self._latest_checked or self._latest is None:
            return
        self._latest_checked = True
        try:
            obs = self._classify(self._latest)
        except Exception:
            self._set("GUARD_CLASSIFIER_ERROR", "The screen could not be checked before the next action; stopped.")
            return
        state = getattr(getattr(obs, "state", ""), "value", getattr(obs, "state", ""))
        confidence = float(getattr(obs, "confidence", 0.0) or 0.0)
        if confidence < self.min_confidence:
            return          # unreadable: the agent's own prompt still says to stop on prompts
        if state in BLOCKING_STATES:
            self._set("AUTH_PROMPT_DURING_STEP", f"A {state.replace('_', ' ')} appeared during the step; no further input was sent.")
        elif state == "uac_consent_prompt" and not self.allow_uac_consent:
            self._set("UAC_PROMPT_NOT_PERMITTED", "An elevation prompt appeared in a step that did not ask for one; no further input was sent.")

    def _set(self, code: str, message: str) -> None:
        if self.violation is None:
            self.violation = (code, message)

    def check_text(self, text: str) -> None:
        if FORBIDDEN_TYPED.search(text or ""):
            self._set("FORBIDDEN_COMMAND", "A forbidden recovery or forced-termination command was about to be typed; nothing was typed.")
            return
        verbs = {m.group(1).lower() for m in SERVICE_VERBS.finditer(text or "")}
        if verbs or POWER_OR_SERVICE_TOOLS.search(text or ""):
            if not self.mutating_allowed or (verbs - self.allowed_verbs) or POWER_OR_SERVICE_TOOLS.search(text or ""):
                self._set("MUTATION_NOT_IN_THIS_STEP", "A service or power command that this step does not ask for was about to be typed; nothing was typed.")

    def before_action(self, name: str, args: tuple, kwargs: dict) -> None:
        if name in _BLOCKED_ALWAYS:
            self._set("SECRET_TYPING_BLOCKED", "The agent cannot type saved credentials.")
        if name == "type":
            text = args[0] if args else kwargs.get("text", "")
            self.check_text(str(text))
        if self.violation is None:
            self._screen_check()
        if self.violation is not None:
            raise StepGuardViolation(*self.violation)
        self.actions += 1


class GuardedComputer:
    """Proxy for the Computer handed to the step agent; every input call passes the guard first."""

    def __init__(self, inner: Any, guard: StepGuard) -> None:
        self._inner = inner
        self._guard = guard

    def screenshot(self, *a: Any, **k: Any) -> Any:
        shot = self._inner.screenshot(*a, **k)
        self._guard.note_screenshot(getattr(shot, "png", shot))
        return shot

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr) or name.startswith("_") or name in _READ_ONLY_COMPUTER_CALLS:
            return attr

        def guarded(*a: Any, **k: Any) -> Any:
            self._guard.before_action(name, a, k)
            return attr(*a, **k)

        return guarded


# --------------------------------------------------------------------- report


def render_chain_section_html(o: dict) -> str:
    e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
    rows = "".join(f"<tr><td>{e(h['order'])}</td><td>{e(h['host'])}</td><td>{e(h['user'])}</td>"
                   f"<td>{e(h['status'])}</td><td>{e(h.get('detail'))}</td></tr>" for h in o.get("hops", []))
    parts = ["<section class=\"connection-chain\"><h2>Connection chain</h2>",
             f"<p>Mode: {e(o.get('mode'))} &middot; Status: {e(o.get('status'))}</p>",
             (f"<p class=\"mode-downgrade\"><strong>Requested mode: {e(o.get('requested_mode'))}. "
              f"Effective mode: {e(o.get('mode'))}.</strong> {e(o.get('downgrade_reason'))} "
              "This run is NOT a completed operating procedure.</p>") if o.get("downgraded") else "",
             "<table><tr><th>Order</th><th>Host</th><th>User</th><th>Status</th><th>Detail</th></tr>",
             rows, "</table>"]
    err = o.get("error")
    if err:
        parts.append(f"<p class=\"chain-error\">Failed hop {e(err.get('hop'))}: {e(err.get('code'))} "
                     f"&mdash; {e(err.get('message'))}</p>")
    if o.get("checkpoints"):
        parts.append("<h3>Operator checkpoints</h3><ul>" + "".join(
            f"<li>Step {e(c.get('step_order'))} {e(c.get('title'))}: requested, "
            f"{'acknowledged' if c.get('acked') else e(c.get('outcome'))} {e(c.get('note'))}</li>"
            for c in o["checkpoints"]) + "</ul>")
    if o.get("skipped"):
        parts.append("<h3>Skipped steps</h3><ul>" + "".join(
            f"<li>Step {e(s.get('order'))} {e(s.get('title'))}: SKIPPED &mdash; {e(s.get('reason'))}</li>"
            for s in o["skipped"]) + "</ul>")
    b = o.get("browser")
    if isinstance(b, dict):
        pb, cl = b.get("playback") or {}, b.get("cleanup") or {}
        parts.append("<h3>Browser verification</h3>")
        parts.append(f"<p class=\"bv-playback\"><strong>Playback:</strong> {e(pb.get('verdict') or pb.get('code') or 'NOT_RUN')} (verification {e(pb.get('status'))}). "
                     "Advancing pixel content only; live-source freshness UNVERIFIED; audio NOT_ASSESSED.</p>")
        parts.append(f"<p class=\"bv-cleanup\"><strong>Cleanup:</strong> {e(cl.get('status'))}"
                     + (f" ({e(cl.get('reason'))})" if cl.get("reason") else "") + f". {e(cl.get('note'))}</p>")
        if cl.get("expected_artifacts"):
            parts.append("<ul class=\"bv-leftovers\">" + "".join(f"<li>{e(a.get('kind'))}: {e(a.get('state'))}</li>" for a in cl["expected_artifacts"]) + "</ul>")
        if cl.get("operator_guidance"):
            parts.append("<ul class=\"bv-guidance\">" + "".join(f"<li>{e(g)}</li>" for g in cl["operator_guidance"]) + "</ul>")
    if o.get("notes"):
        parts.append("<h3>Session notes</h3><ul>" + "".join(f"<li>{e(n)}</li>" for n in o["notes"]) + "</ul>")
    ev = [x for x in o.get("evidence", []) if x.get("path")]
    if ev:
        parts.append("<h3>Evidence</h3><div class=\"thumbs\">" + "".join(
            f"<figure><img src=\"{e(x['path'])}\" alt=\"{e(x.get('label'))}\" width=\"240\">"
            f"<figcaption>{e(x.get('label'))}</figcaption></figure>" for x in ev) + "</div>")
    parts.append("</section>")
    return "".join(parts)
