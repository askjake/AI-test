"""browser_verify backend / state machine (b4r12-dev).  NOT WIRED into the dashboard or the runner; DISABLED by default.

Scope: after a nonce-bound desktop identity confirmation, launch a new Chrome window at exactly http://127.0.0.1:5004/ on the remote
Windows desktop through the Run dialog, observe the player regions over time, report per-stream evidence, and close ONLY a window whose
ownership is proven.  The production adapter (ChainController: screenshot / key / type, plus a runner-side X-window guard) exposes NO
inventory of windows INSIDE the RDP desktop, so ownership is NOT establishable with it: no close key is ever sent in that case and the
result says so (cleanup = NOT_PERFORMED, route LEAVE_OPEN: a deliberate partial fulfilment of the cleanup goal).  See OwnershipPort for the exact, testable adapter requirement.
"""
from __future__ import annotations

import io
import re
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from PIL import Image, ImageChops

from orchestrator import browser_evidence as ev
from orchestrator import chain as _chain

ALLOWED_URL = "http://127.0.0.1:5004/"
MODE_NAME = "browser_verify"
LAUNCH_COMMAND_ID = "bv.launch.v1"
PROFILE_PREFIX = "nrdp-bv-"
ESCAPE_ACTION = "bv.escape_preexisting_dialog"
CLEANUP_NOT_PERFORMED = "NOT_PERFORMED"
CLEANUP_ROUTE_LEAVE_OPEN = "LEAVE_OPEN"
CLEANUP_REASON_UNPROVEN = "OWNERSHIP_UNPROVEN_LEAVE_OPEN_ROUTE"   # fixed reason code; never free text
CLEANUP_FULFILMENT = "DELIBERATE_PARTIAL_NOT_AUTOMATIC_CLEANUP"
_PROJECT_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")
_RUN_RE = re.compile(r"trig_[A-Za-z0-9_-]{1,80}")
_NONCE_RE = re.compile(r"[0-9a-f]{8}")
_CMD_RE = re.compile(
    r"chrome --user-data-dir=%TEMP%\\nrdp-bv-[0-9a-f]{8} --no-first-run --no-default-browser-check --new-window "
    r"--window-position=\d{2,4},\d{2,4} --window-size=\d{3,4},\d{3,4} http://127\.0\.0\.1:5004/")
_CHAIN_STOPS = ("CANCELLED", "TOTAL_TIMEOUT", "HOP_TIMEOUT")
_PROMPT_STATES = {"credential_prompt", "credential_account_list", "certificate_warning", "error_dialog", "lock_or_logon_screen",
                  "uac_consent_prompt", "uac_credential_prompt", "rdp_client_computer_prompt", "remote_desktop_identity_mismatch"}


# ------------------------------------------------------------------------------------------ gating


@dataclass(frozen=True)
class BrowserVerifyPolicy:
    """Explicit capability switch.  The default is DISABLED.  There is no environment variable or hidden flag; enabling needs a code change."""
    enabled: bool = False
    allowed_projects: frozenset = frozenset()
    allowed_url: str = ALLOWED_URL


DEFAULT_POLICY = BrowserVerifyPolicy()


@dataclass(frozen=True)
class BrowserVerifyRequest:
    project: str = ""
    run_id: str = ""
    requested_mode: str = ""      # must be exactly "browser_verify": an absent / unknown mode (e.g. request-less Retry) never enables it
    url: str = ""
    confirm_phrase: str = ""      # operator confirmation
    leave_open_ack: str = ""      # explicit acknowledgement that the browser window, profile folder and Run-history entry stay on the target


def expected_confirm_phrase(project: str) -> str:
    return f"BROWSER-VERIFY {project}"


def expected_leave_open_phrase(project: str) -> str:
    return f"LEAVE-OPEN {project}"


def validate_request(req: Any, policy: Any, *, require_leave_open_ack: bool = True) -> tuple[str, str] | None:
    """None when allowed, else (code, message).  Order matters: nothing about the request is trusted until the capability is enabled."""
    if not isinstance(policy, BrowserVerifyPolicy) or policy.enabled is not True or policy.allowed_url != ALLOWED_URL:
        return "CAPABILITY_DISABLED", "browser_verify is disabled in this build; nothing was launched or typed."
    if not isinstance(req, BrowserVerifyRequest) or req.requested_mode != MODE_NAME:
        return "REQUEST_MODE_MISSING", "No explicit browser_verify request; a missing or different mode never enables it."
    if not _PROJECT_RE.fullmatch(req.project or "") or req.project not in policy.allowed_projects:
        return "PROJECT_NOT_ALLOWLISTED", "This project is not allow-listed for browser_verify."
    if not _RUN_RE.fullmatch(req.run_id or ""):
        return "REQUEST_INVALID", "The run id is missing or malformed."
    if req.url != ALLOWED_URL:
        return "URL_NOT_ALLOWED", "Only the single allow-listed address may be opened."
    if req.confirm_phrase != expected_confirm_phrase(req.project):
        return "CONFIRMATION_MISSING", "The operator confirmation is missing or wrong."
    if require_leave_open_ack and req.leave_open_ack != expected_leave_open_phrase(req.project):
        return "LEAVE_OPEN_ACK_MISSING", "The acknowledgement that the browser window, its profile folder and a Run-history entry stay on the target is missing or wrong."
    return None


@dataclass(frozen=True)
class BrowserVerifyLimits:
    load_timeout_s: float = 60.0       # wait for the page + stream regions
    poll_interval_s: float = 2.0
    min_frames: int = 6
    min_span_s: float = 15.0
    frame_interval_s: float = 3.0
    max_frames: int = 12
    observe_max_s: float = 45.0
    dialog_timeout_s: float = 30.0
    close_wait_s: float = 10.0
    total_deadline_s: float = 180.0    # THE overall deadline for the whole browser_verify workflow
    max_unclear_frames: int = 3

    def __post_init__(self) -> None:
        if self.min_frames < 6 or self.min_span_s < 15.0 or self.load_timeout_s > 60.0 or self.total_deadline_s > 300.0:
            raise ValueError("browser_verify bounds may be tightened, not loosened")
        if self.max_frames < self.min_frames or self.observe_max_s < self.min_span_s or self.frame_interval_s <= 0:
            raise ValueError("inconsistent observation bounds")


class BVAbort(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


class ClassifierBudgetExhausted(Exception):
    """The model-attempt budget or deadline was reached (raised BEFORE a request is sent).  Never swallowed as an ordinary classifier failure."""


class InputBlocked(Exception):
    def __init__(self, guard_code: str) -> None:
        super().__init__(guard_code)
        self.guard_code = guard_code


# ----------------------------------------------------------------------------------- launch command


def geometry_for_nonce(nonce: str) -> tuple[int, int, int, int]:
    """(x, y, w, h) in remote-desktop pixels, deliberately unusual per run.  CORROBORATION ONLY (see find_new_rectangle)."""
    if not _NONCE_RE.fullmatch(nonce):
        raise ValueError("bad nonce")
    b = bytes.fromhex(nonce)
    return (40 + b[0] % 40, 30 + b[1] % 30, 1000 + b[2] % 60, 620 + b[3] % 40)


def launch_command(nonce: str, geometry: tuple[int, int, int, int]) -> str:
    x, y, w, h = geometry
    cmd = (f"chrome --user-data-dir=%TEMP%\\{PROFILE_PREFIX}{nonce} --no-first-run --no-default-browser-check --new-window "
           f"--window-position={x},{y} --window-size={w},{h} {ALLOWED_URL}")
    if not _CMD_RE.fullmatch(cmd):
        raise ValueError("launch command is not on the allow-list")
    return cmd


# ------------------------------------------------------------------------------------ ownership contract


class OwnershipPort(Protocol):
    """REQUIRED adapter capability to prove that a window on the REMOTE Windows desktop belongs to this run.  The production adapter does
    NOT implement it (xdotool sees only the runner's own X windows, e.g. the single FreeRDP window; the desktop inside is pixels).

    list_windows()        -> [{"id": str, "pid": int, "profile": str, "top_level": bool, "visible": bool, "rect": [x0, y0, x1, y1]}]
                             read-only enumeration of top-level windows INSIDE the remote desktop; ``profile`` is the --user-data-dir
                             folder name from the owning process's command line (the per-run nonce profile).
    foreground_window_id()-> str | None   (informational; closing never relies on a key sent to "whatever has focus")
    close_window(id)      -> bool         graceful close request addressed to that window id (WM_CLOSE-style).  Not a key shortcut, not
                                          process termination, not forced.
    """

    def list_windows(self) -> list[dict]: ...
    def foreground_window_id(self) -> str | None: ...
    def close_window(self, window_id: str) -> bool: ...


REQUIRED_PORT_METHODS = ("list_windows", "foreground_window_id", "close_window")
PROVEN, UNPROVEN = "PROVEN", "UNPROVEN"


@dataclass
class OwnershipAssessment:
    level: str
    basis: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    window_id: str | None = None
    visual_correlation: dict | None = None

    def to_dict(self) -> dict:
        return {"level": self.level, "basis": self.basis, "missing_adapter_capabilities": self.missing, "reasons": self.reasons,
                "visual_correlation": self.visual_correlation,
                "note": "A new rectangle on screen is corroboration only; PROVEN needs the adapter inventory below."}


def assess_ownership(port: Any, nonce: str, visual: dict | None) -> OwnershipAssessment:
    if port is None:
        return OwnershipAssessment(UNPROVEN, missing=list(REQUIRED_PORT_METHODS), reasons=["ADAPTER_EXPOSES_NO_REMOTE_WINDOW_INVENTORY"],
                                   visual_correlation=visual)
    missing = [m for m in REQUIRED_PORT_METHODS if not callable(getattr(port, m, None))]
    if missing:
        return OwnershipAssessment(UNPROVEN, missing=missing, reasons=["PORT_INCOMPLETE"], visual_correlation=visual)
    try:
        wins = port.list_windows()
    except Exception:
        return OwnershipAssessment(UNPROVEN, reasons=["INVENTORY_FAILED"], visual_correlation=visual)
    prof = PROFILE_PREFIX + nonce
    mine = [w for w in (wins if isinstance(wins, list) else []) if isinstance(w, dict) and w.get("profile") == prof
            and w.get("visible") is True and w.get("top_level") is True]
    if not mine:
        return OwnershipAssessment(UNPROVEN, reasons=["NO_VISIBLE_WINDOW_WITH_RUN_PROFILE"], visual_correlation=visual)
    if len(mine) > 1:
        return OwnershipAssessment(UNPROVEN, reasons=["MULTIPLE_WINDOWS_WITH_RUN_PROFILE"], visual_correlation=visual)
    w = mine[0]
    rect = w.get("rect")
    if (not isinstance(w.get("id"), str) or not w["id"] or not isinstance(w.get("pid"), int) or not isinstance(rect, list) or len(rect) != 4
            or not all(isinstance(v, int) and not isinstance(v, bool) for v in rect)):
        return OwnershipAssessment(UNPROVEN, reasons=["INVENTORY_ENTRY_MALFORMED"], visual_correlation=visual)
    if not visual or visual.get("found") is not True or len(visual.get("expected") or []) != 4:
        return OwnershipAssessment(UNPROVEN, reasons=["WINDOW_NOT_SEEN_ON_SCREEN"], visual_correlation=visual)
    tol = float(visual.get("tolerance_px", 0)) or 1.0
    scale = visual.get("scale")
    if not isinstance(scale, (int, float)) or scale <= 0:
        return OwnershipAssessment(UNPROVEN, reasons=["SCREEN_SCALE_UNKNOWN"], visual_correlation=visual)
    if max(abs(round(rect[i] * scale) - visual["expected"][i]) for i in range(4)) > tol:
        return OwnershipAssessment(UNPROVEN, reasons=["INVENTORY_DISAGREES_WITH_SCREEN"], visual_correlation=visual)
    return OwnershipAssessment(PROVEN, basis=["single visible top-level window enumerated with the per-run profile (nonce typed by this run)",
                                              "graceful close addressed by window id (no key shortcut)"],
                               window_id=w["id"], visual_correlation=visual)


# --------------------------------------------------------------------------------------- page classifier


@dataclass
class PageObservation:
    state: str = "unknown"          # browser_page | loading | error_page | not_browser | unexpected_prompt | unknown
    confidence: float = 0.0
    address_ok: bool | None = None  # the address bar shows exactly the allow-listed URL (None = not readable)
    prompt_kind: str = ""
    regions: list = field(default_factory=list)       # untrusted proposals [{label,x,y,w,h}]
    region_states: dict = field(default_factory=dict)  # label -> playing | loading | error | unknown   (advisory)
    overlay: bool = False


_PAGE_STATES = {"browser_page", "loading", "error_page", "not_browser", "unexpected_prompt", "unknown"}
_REGION_STATES = {"playing", "loading", "error", "unknown"}


def clean_page_observation(raw: Any) -> PageObservation:
    get = (lambda k, d=None: raw.get(k, d)) if isinstance(raw, dict) else (lambda k, d=None: getattr(raw, k, d))
    state = get("state", "unknown")
    try:
        conf = float(get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    conf = 0.0 if conf != conf else max(0.0, min(1.0, conf))
    rs = get("region_states", {})
    rs = {ev.sanitize_label(k): (v if v in _REGION_STATES else "unknown") for k, v in (rs.items() if isinstance(rs, dict) else [])}
    regions = get("regions", [])
    addr = get("address_ok", None)
    return PageObservation(state if state in _PAGE_STATES else "unknown", conf, addr if isinstance(addr, bool) else None,
                           ev.sanitize_label(get("prompt_kind", ""), 40), list(regions)[:40] if isinstance(regions, (list, tuple)) else [],
                           rs, bool(get("overlay", False)))


class UnavailablePageClassifier:
    """Production placeholder: no page-classification prompt has been written or qualified, and no model call is made in this stage."""

    def describe(self, png: bytes) -> PageObservation:
        raise NotImplementedError("page classifier not implemented/qualified")


# ----------------------------------------------------------------------------------- controller adapter


class ControllerSession:
    """Adapter over an ESTABLISHED ChainController.  Uses only its screenshot / key / type, its pre-input guard and its teardown; chain.py is unchanged."""

    def __init__(self, controller: Any, ownership_port: Any = None) -> None:
        self._c = controller
        self._port = ownership_port

    @property
    def hop(self) -> Any:
        return self._c._chain[-1]

    def now(self) -> float:
        return self._c._clock()

    def sleep(self, seconds: float) -> None:
        self._c._sleep(seconds)

    def check(self) -> None:
        self._c._check()

    def min_confidence(self) -> float:
        return self._c.limits.min_confidence

    def ownership_port(self) -> Any:
        return self._port

    def identity_state(self) -> tuple[bool, str, dict]:
        c = self._c
        if c._torn_down or not c._chain:
            return False, "CHAIN_NOT_ESTABLISHED", {}
        hop = self.hop
        if c._state.active_hop != hop.order or c._hop_state(hop.order).status != _chain.HopStatus.CONFIRMED:
            return False, "FINAL_HOP_NOT_CONFIRMED", {}
        ident = c._identities.get(hop.order)
        if ident is None:
            return False, "IDENTITY_RESULT_NOT_RECORDED", {}
        ok, code, _ = _chain.identity_matches(hop, ident, [c._identities[o] for o in sorted(c._identities) if o < hop.order])
        summary = {"controller_status": "confirmed", "recomputed_whole_token_match": bool(ok), "recomputed_code": code or "",
                   "computer": ev.sanitize_label(ident.hostname, 40), "account": ev.sanitize_label(f"{ident.domain}\\{ident.user}", 80),
                   "ipv4_count": len(ident.ipv4), "configured_host": ev.sanitize_label(hop.host, 40),
                   "nonce": "NOT_RETAINED_BY_CONTROLLER",
                   "source": "recomputed from the controller's retained parsed identity; the original comparison record is not retained"}
        return bool(ok), code or "", summary

    def screenshot(self, check: bool = True) -> bytes:
        c = self._c
        if c._capture_blocked:
            raise RuntimeError("screenshot attempted while a credential is being entered")
        if check:
            c._check()
        shot = c._computer.screenshot()
        return getattr(shot, "png", shot)

    def save_frame(self, phase: str, png: bytes) -> str | None:
        c = self._c
        c._seq += 1
        if not c._evidence_dir:
            return None
        _chain.ensure_shared_dir(c._evidence_dir)
        name = "hop%d_bv_%s_%03d.png" % (self.hop.order, _chain._SAFE.sub("_", phase), c._seq)
        c._save_png(f"{c._evidence_dir}/{name}", png)
        return name

    def desktop_state(self, phase: str) -> tuple[str, float]:
        o = self._c._observe(self.hop, phase, "is the desktop ready for a Run-dialog launch, or is a dialog or prompt on top")
        return o.state.value, float(o.confidence)

    def open_run_dialog(self, deadline: float) -> bool:
        return self._c._open_run_dialog(self.hop, deadline, "bv_run_dialog") == _chain.ObservedState.RDP_CLIENT_RUN_DIALOG

    def guarded_input(self, action: Callable[[], None]) -> None:
        c = self._c
        try:
            c._assert_safe_to_type(self.hop)
        except _chain._Abort as abort:
            if abort.code in _CHAIN_STOPS:
                raise
            raise InputBlocked(abort.code) from None
        c._check()
        action()
        c._check()

    def key(self, combo: str) -> None:
        self._c._computer.key(combo)

    def type(self, text: str) -> None:
        self._c._computer.type(text)

    def note(self, text: str) -> None:
        self._c._note(text)

    def teardown(self) -> None:
        self._c.teardown()

    def model_usage(self, *objs: Any) -> dict:
        found: dict[str, Any] = {}
        for name, obj in (("desktop_classifier", self._c._classifier),) + tuple(("page_classifier", o) for o in objs):
            fn = getattr(obj, "usage_counters", None)
            if callable(fn):
                try:
                    found[name] = fn()
                except Exception:
                    pass
        return {"status": "MEASURED", "counters": found} if found else {
            "status": "UNAVAILABLE", "detail": "the classifiers expose no usage counters; none are estimated"}


# ----------------------------------------------------------------------------------------- state machine


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rect_changed_fraction(a_png: bytes, b_png: bytes, ref_box: tuple[int, int, int, int]) -> float:
    a, b = ev.decode_gray(a_png), ev.decode_gray(b_png)
    if a.size != b.size:
        return 1.0
    s = a.size[0] / ev.REFERENCE_WIDTH
    box = tuple(int(round(v * s)) for v in ref_box)
    d = ImageChops.difference(a.crop(box), b.crop(box)).point(lambda v: 255 if v > 24 else 0)
    px = d.tobytes()
    return sum(1 for v in px if v) / max(1, len(px))


NOT_PROVEN_ALWAYS = [
    "live-source freshness (pixel motion cannot tell live video from a recording)", "audio", "serial/COM handle release",
    "application health beyond the observed regions", "inventory correctness", "any physical receiver behaviour",
    "model page-classification quality on real Chrome frames (no real model call was made in qualification)",
]


class BrowserVerifier:
    def __init__(self, session: Any, page_classifier: Any, *, policy: BrowserVerifyPolicy = DEFAULT_POLICY,
                 limits: BrowserVerifyLimits | None = None, analysis: ev.AnalysisLimits | None = None,
                 nonce_factory: Callable[[], str] | None = None) -> None:
        self.s, self.pc, self.policy = session, page_classifier, policy
        self.lim = limits or BrowserVerifyLimits()
        self.an = analysis or ev.AnalysisLimits(min_frames=self.lim.min_frames, min_span_s=self.lim.min_span_s)
        self._nonce_factory = nonce_factory or (lambda: _secrets.token_hex(4))

    # -- helpers ---------------------------------------------------------------------------------
    def _tick(self) -> None:
        self.s.check()
        if self.s.now() > self._deadline:
            raise BVAbort("DEADLINE_EXCEEDED", "The browser_verify overall deadline was reached.")

    def _t(self) -> float:
        return round(self.s.now() - self._t0, 2)

    def _act(self, action_id: str, fn: Callable[[], None]) -> None:
        self._tick()
        entry = {"seq": len(self.actions) + 1, "action_id": action_id, "t_rel": self._t(), "utc": _utc(), "guard": "PASS",
                 "frame_ref": self._last_ref, "result": "NOT_SENT"}
        sent = [False]

        def wrapped() -> None:
            fn()
            sent[0] = True
        try:
            self.s.guarded_input(wrapped)
            entry["result"] = "SENT"
        except InputBlocked as blocked:
            entry["guard"] = "BLOCKED:" + blocked.guard_code
            self.actions.append(entry)
            raise BVAbort("BROWSER_INPUT_BLOCKED", f"The keyboard check failed ({blocked.guard_code}) just before {action_id}; that input was not sent.") from None
        except BaseException:
            entry["guard"] = "PASS_OR_ABORTED"
            entry["result"] = "SENT_THEN_ABORTED" if sent[0] else "NOT_SENT_ABORTED"
            self.actions.append(entry)
            raise
        self.actions.append(entry)
        if action_id == ESCAPE_ACTION:
            self.escape_count += 1

    def _capture(self, phase: str, *, describe: bool = True) -> PageObservation | None:
        png = self.s.screenshot()
        ref = self.s.save_frame(phase, png)
        self._last_ref = ref
        t = self._t()
        if not describe:
            return None
        try:
            raw = self.pc.describe(png)
        except ClassifierBudgetExhausted:
            raise BVAbort("CLASSIFIER_BUDGET_EXHAUSTED", "The model attempt budget or deadline was reached; partial evidence is kept and no verdict is claimed.") from None
        except NotImplementedError:
            raise BVAbort("CLASSIFIER_UNAVAILABLE", "The page classifier is not implemented in this build.") from None
        except Exception as exc:
            raise BVAbort("CLASSIFIER_ERROR", f"Page classification failed ({type(exc).__name__}).") from None
        po = clean_page_observation(raw)
        try:
            size = Image.open(io.BytesIO(png)).size
        except Exception:
            raise BVAbort("FRAME_UNDECODABLE", "A captured frame could not be decoded.") from None
        regions, rejected = ev.validate_regions(po.regions, size, self.an)
        for r in rejected:
            if r not in self.rejected:
                self.rejected.append(r)
        self._cur = {"png": png, "ref": ref, "t": t, "po": po, "regions": regions}
        self.frame_log.append({"ref": ref, "t_rel": t, "page_state": po.state, "confidence": round(po.confidence, 2),
                               "address_ok": po.address_ok, "accepted_regions": len(regions), "phase": phase})
        return po

    def _include_current(self) -> None:
        c = self._cur
        po: PageObservation = c["po"]
        self.frames.append(ev.Frame(c["ref"], c["t"], c["png"]))
        self.region_lists.append(c["regions"])
        self.hints.append({r.label: {"state": po.region_states.get(r.label, "unknown"), "overlay": po.overlay} for r in c["regions"]})

    def _confident(self, po: PageObservation) -> bool:
        return po.confidence >= self.s.min_confidence()

    # -- the workflow ----------------------------------------------------------------------------
    def run(self, request: Any) -> dict:
        self.actions: list[dict] = []
        self.escape_count = 0
        self.frames: list[ev.Frame] = []
        self.region_lists: list[list[ev.Region]] = []
        self.hints: list[dict] = []
        self.frame_log: list[dict] = []
        self.rejected: list[dict] = []
        self._last_ref: str | None = None
        self._cur: dict = {}
        self.launch = {"state": "NOT_ATTEMPTED", "command_id": LAUNCH_COMMAND_ID, "nonce": None, "geometry_requested": None, "profile": None}
        self.visual: dict | None = None
        self.identity: dict = {}
        self.before_png: bytes | None = None
        res: dict[str, Any] = {"schema": ev.SCHEMA, "kind": MODE_NAME, "capability": {"enabled": bool(getattr(self.policy, "enabled", False)), "default": "disabled"},
                               "request": {"requested_mode": getattr(request, "requested_mode", "") or "", "run_id": getattr(request, "run_id", "") or "",
                                           "url": ALLOWED_URL if getattr(request, "url", "") == ALLOWED_URL else "REJECTED",
                                           "project": ev.sanitize_label(getattr(request, "project", ""), 80)}}
        refusal = validate_request(request, self.policy, require_leave_open_ack=self.s.ownership_port() is None)
        if refusal:
            return self._finish(res, "refused", refusal[0], refusal[1], session_used=False)
        begin = getattr(self.pc, "begin_run", None)
        if callable(begin):
            begin()                      # a page classifier may keep per-run state (region identity); it must not carry it across runs
        self._t0 = self.s.now()
        self._deadline = self._t0 + self.lim.total_deadline_s
        status, code, message = "completed", "", ""
        try:
            try:
                self._preconditions()
                self._launch()
                self._wait_for_page()
                self._observe()
            except BVAbort as a:
                status, code, message = ("cancelled" if a.code == "CANCELLED" else ("partial" if a.code == "CLASSIFIER_BUDGET_EXHAUSTED" else "aborted")), a.code, a.message
            except _chain._Abort as a:
                if a.code == "CANCELLED":
                    status, code, message = "cancelled", "CANCELLED", "Cancelled by the operator; partial evidence is kept."
                elif a.code in ("TOTAL_TIMEOUT", "HOP_TIMEOUT"):
                    status, code, message = "aborted", "DEADLINE_EXCEEDED", "A time limit was reached; partial evidence is kept."
                else:
                    status, code, message = "aborted", a.code, "The connection controller stopped the workflow."
            except Exception as exc:
                status, code, message = "aborted", "UNEXPECTED_ERROR", f"{type(exc).__name__} during browser_verify."
            self._analyse(res)
            if status == "completed":
                got = len(self.frames) >= self.lim.min_frames and (self.frames[-1].t - self.frames[0].t) >= self.lim.min_span_s
                if not got:
                    status, code, message = "partial", "OBSERVATION_INCOMPLETE", "Fewer frames or a shorter span than required were observed."
                else:
                    code = res["verdict"]
            self._cleanup(res)
        finally:
            try:
                self.s.teardown()
            except Exception:
                pass
        return self._finish(res, status, code, message, session_used=True)

    def _preconditions(self) -> None:
        ok, code, summary = self.s.identity_state()
        self.identity = summary
        if not ok:
            raise BVAbort("IDENTITY_NOT_CONFIRMED", f"The desktop identity is not confirmed ({code or 'not confirmed'}); nothing was launched or typed.")
        for attempt in (1, 2):
            state, conf = self.s.desktop_state("bv_before")
            if conf >= self.s.min_confidence() and state == "remote_desktop_ready":
                self._tick()
                self.before_png = self.s.screenshot()        # baseline AFTER any dialog was dismissed, so the diff isolates the new window
                self._last_ref = self.s.save_frame("before", self.before_png)
                return
            if attempt == 1 and conf >= self.s.min_confidence() and state == "rdp_client_run_dialog":
                self._act(ESCAPE_ACTION, lambda: self.s.key("Escape"))   # at most ONE Escape, only for a dialog this run did not open
                continue
            if conf >= self.s.min_confidence() and state in _PROMPT_STATES:
                raise BVAbort("UNEXPECTED_PROMPT", f"An unexpected prompt ({state}) is on the desktop; stopped without launching.")
            break
        raise BVAbort("DESKTOP_NOT_READY", "The desktop was not confirmed ready for a launch; nothing was typed.")

    def _launch(self) -> None:
        nonce = self._nonce_factory()
        geom = geometry_for_nonce(nonce)
        cmd = launch_command(nonce, geom)
        self.launch.update({"nonce": nonce, "geometry_requested": list(geom), "profile": PROFILE_PREFIX + nonce})
        self._tick()
        if not self.s.open_run_dialog(min(self._deadline, self.s.now() + self.lim.dialog_timeout_s + 5.0)):
            self.actions.append({"seq": len(self.actions) + 1, "action_id": "bv.open_run_dialog", "t_rel": self._t(), "utc": _utc(),
                                 "guard": "FOCUS_ONLY", "frame_ref": self._last_ref, "result": "DIALOG_NOT_CONFIRMED"})
            raise BVAbort("RUN_DIALOG_NOT_CONFIRMED", "The Run dialog could not be confirmed on the screen; nothing was typed.")
        self.actions.append({"seq": len(self.actions) + 1, "action_id": "bv.open_run_dialog", "t_rel": self._t(), "utc": _utc(),
                             "guard": "FOCUS_ONLY", "frame_ref": self._last_ref, "result": "SENT"})
        self._act("bv.select_field", lambda: self.s.key("ctrl+a"))
        self._act("bv.type_launch", lambda: self.s.type(cmd))
        self.launch["state"] = "COMMAND_TYPED_NOT_SUBMITTED"
        self._act("bv.submit_launch", lambda: self.s.key("Return"))
        self.launch["state"] = "SUBMITTED"

    def _wait_for_page(self) -> None:
        start, seen_browser, seen_addr = self.s.now(), False, False
        unclear = 0
        while True:
            self._tick()
            po = self._capture("load")
            conf_ok = self._confident(po)
            if conf_ok and po.state == "unexpected_prompt":
                raise BVAbort("UNEXPECTED_PROMPT", f"An unexpected prompt ({po.prompt_kind or 'unknown'}) appeared; stopped without further input.")
            if conf_ok and po.state in ("browser_page", "loading"):
                if not seen_browser:
                    self.visual = ev.find_new_rectangle(self.before_png, self._cur["png"], self._expected_box())
                    if not self.visual.get("found"):
                        raise BVAbort("NEW_WINDOW_NOT_SEEN", "No new window of the requested geometry appeared; a browser that was already open is never accepted as this run's.")
                seen_browser = True
                if po.address_ok is False:
                    raise BVAbort("PAGE_NOT_REACHED", "The browser address is not the allow-listed address; no input was sent to the page.")
                if po.address_ok is True:
                    seen_addr = True
                    if po.state == "browser_page" and self._cur["regions"]:
                        self._include_current()
                        return
            elif conf_ok and po.state == "error_page":
                raise BVAbort("PAGE_NOT_REACHED", "The browser shows an error page.")
            else:
                unclear += 1
            if self.s.now() - start >= self.lim.load_timeout_s:
                if seen_addr:
                    raise BVAbort("STREAMS_NOT_FOUND", "The page was reached but no valid player region was identified in time.")
                raise BVAbort("PAGE_NOT_REACHED" if seen_browser else "BROWSER_OPEN_FAILED",
                              "A browser window with the allow-listed page was not confirmed in time.")
            self.s.sleep(self.lim.poll_interval_s)

    def _expected_box(self) -> tuple[int, int, int, int]:
        x, y, w, h = self.launch["geometry_requested"]
        return (x, y, x + w, y + h)

    def _observe(self) -> None:
        unclear = 0
        t_first = self.frames[0].t
        while True:
            enough = len(self.frames) >= self.lim.min_frames and (self.frames[-1].t - t_first) >= self.lim.min_span_s
            if enough or len(self.frames) >= self.lim.max_frames or (self.frames[-1].t - t_first) >= self.lim.observe_max_s:
                return
            self.s.sleep(self.lim.frame_interval_s)
            self._tick()
            po = self._capture("observe")
            if self._confident(po) and po.state == "unexpected_prompt":
                raise BVAbort("UNEXPECTED_PROMPT", f"An unexpected prompt ({po.prompt_kind or 'unknown'}) appeared; stopped without further input.")
            if self._confident(po) and po.state == "not_browser":
                raise BVAbort("BROWSER_WINDOW_LOST", "The browser window is no longer on the screen.")
            if self._confident(po) and po.state == "error_page":
                raise BVAbort("PAGE_NOT_REACHED", "The browser shows an error page.")
            if self._confident(po) and po.state in ("browser_page", "loading") and po.address_ok is not False:
                self._include_current()
            else:
                unclear += 1
                if unclear > self.lim.max_unclear_frames:
                    raise BVAbort("OBSERVATION_UNCLEAR", "Too many frames could not be classified confidently.")

    def _analyse(self, res: dict) -> None:
        a = ev.analyze(self.frames, self.region_lists, self.hints, self.an) if self.frames else {"streams": [], "problems": [], "frames": 0, "span_s": 0.0}
        res["streams"], res["verdict"] = a["streams"], ev.run_verdict(a["streams"])
        res["analysis"] = {"frames_analysed": a["frames"], "span_s": a["span_s"], "problems": a["problems"],
                           "rejected_regions": self.rejected[:20],
                           "stream_identification": "classifier-proposed regions, validated for bounds / size / overlap / cross-frame stability"}

    def _cleanup(self, res: dict) -> None:
        launched = self.launch["state"] == "SUBMITTED"
        cl: dict[str, Any] = {"status": "NOT_LAUNCHED", "window_state_after": "NO_WINDOW_STARTED", "ownership": None, "note": ""}
        if self.launch["state"] == "COMMAND_TYPED_NOT_SUBMITTED":
            cl["note"] = "The launch command was typed into the Run box but not submitted; the Run box may still hold it. No cleanup input was sent."
        if launched:
            seen = any(f["page_state"] in ("browser_page", "loading") for f in self.frame_log)
            a = assess_ownership(self.s.ownership_port(), self.launch["nonce"], self.visual)
            cl["ownership"] = a.to_dict()
            if a.level != PROVEN:
                state = "OPEN_OBSERVED" if seen else "UNKNOWN_MAY_BE_OPEN"
                cl.update(status=CLEANUP_NOT_PERFORMED, reason=CLEANUP_REASON_UNPROVEN, route=CLEANUP_ROUTE_LEAVE_OPEN, close_input_sent=False,
                          fulfilment=CLEANUP_FULFILMENT, window_state_after=state,
                          note="Cleanup was NOT performed: window ownership could not be established, so no close key or command was sent. This is a deliberate partial fulfilment of the cleanup goal, not automatic browser cleanup.",
                          expected_artifacts=self._expected_artifacts(state), operator_guidance=self._operator_guidance())
                self.s.note("browser_verify: window ownership was not established; cleanup NOT_PERFORMED (leave-open route); the Chrome window it started (if any) was left open and no close key was sent.")
            else:
                cl.update(self._close_proven(a))
        res["cleanup"] = cl

    def _expected_artifacts(self, window_state: str) -> list[dict]:
        return [{"kind": "browser_window", "state": window_state, "url": ALLOWED_URL, "requested_geometry": self.launch.get("geometry_requested")},
                {"kind": "profile_directory", "state": "POSSIBLE_NOT_VERIFIED", "location": "%TEMP%\\" + PROFILE_PREFIX + str(self.launch.get("nonce"))},
                {"kind": "run_history_entry", "state": "POSSIBLE_NOT_VERIFIED", "detail": "The Windows Run dialog may remember the launch command."}]

    def _operator_guidance(self) -> list[str]:
        prof = "%TEMP%\\" + PROFILE_PREFIX + str(self.launch.get("nonce"))
        return ["This run did not clean up after itself; nothing was closed, terminated or deleted automatically.",
                "Manual cleanup is optional. Close a Chrome window only if you can identify it as the one this test opened (it shows http://127.0.0.1:5004/); leave any window you cannot identify.",
                f"A profile folder named {prof} may have been created (not verified). Delete it only after confirming that no Chrome window or process is still using it; if you are unsure, leave it.",
                "The Run dialog may remember the launch command (not verified). This tool does not clear Run history; do not clear entries you cannot attribute to this test."]

    def _close_proven(self, a: OwnershipAssessment) -> dict:
        port = self.s.ownership_port()
        try:
            accepted = port.close_window(a.window_id)
            deadline = self.s.now() + self.lim.close_wait_s
            gone = False
            while True:
                gone = not any(isinstance(w, dict) and w.get("id") == a.window_id for w in (port.list_windows() or []))
                if gone or self.s.now() >= deadline:
                    break
                self.s.sleep(1.0)
            png = self.s.screenshot(check=False)
            ref = self.s.save_frame("after_close", png)
            changed = _rect_changed_fraction(self.frames[-1].png, png, self._expected_box()) if self.frames else 0.0
        except Exception as exc:
            return {"status": "CLOSE_FAILED", "window_state_after": "UNKNOWN_MAY_BE_OPEN", "note": f"The close request failed ({type(exc).__name__}); no retry and no forced close."}
        if accepted and gone and changed > 0.05:
            return {"status": "CLOSED_VERIFIED", "window_state_after": "CLOSED_VERIFIED", "note": "Closed by id; absence confirmed by inventory and by the screen.", "after_close_frame": ref}
        return {"status": "CLOSE_FAILED", "window_state_after": "UNKNOWN_MAY_BE_OPEN", "note": "The close could not be verified; no retry and no forced close.", "after_close_frame": ref}

    def _finish(self, res: dict, status: str, code: str, message: str, *, session_used: bool) -> dict:
        res.setdefault("streams", [])
        res.setdefault("verdict", "NOT_RUN")
        res.setdefault("cleanup", {"status": "NOT_LAUNCHED", "window_state_after": "NO_WINDOW_STARTED", "ownership": None, "note": ""})
        res.update(status=status, code=code, message=message[:240])
        res["identity"] = self.identity if session_used else {}
        res["launch"] = self.launch if session_used else {"state": "NOT_ATTEMPTED"}
        res["timeline"] = {"total_s": self._t() if session_used else 0.0, "deadline_s": self.lim.total_deadline_s,
                           "load_timeout_s": self.lim.load_timeout_s, "frames_included": len(self.frames), "frames_captured": len(self.frame_log),
                           "span_s": round(self.frames[-1].t - self.frames[0].t, 2) if self.frames else 0.0}
        res["frames"] = self.frame_log
        res["actions"] = self.actions
        res["escape_count"] = self.escape_count
        res["model_usage"] = self.s.model_usage(self.pc) if session_used else {"status": "UNAVAILABLE", "detail": "no model call was made"}
        res["playback"] = {"status": status, "code": code, "verdict": res["verdict"], "independent_of_cleanup": True}
        res["claims"] = {"playback": "advancing pixel content only", "live_source_freshness": "UNVERIFIED", "audio": "NOT_ASSESSED"}
        res["not_proven"] = list(NOT_PROVEN_ALWAYS)
        try:
            ev.assert_sanitized(res)
        except ValueError:
            return {"schema": ev.SCHEMA, "kind": MODE_NAME, "status": "aborted", "code": "RESULT_REJECTED_BY_SANITIZER",
                    "message": "The result was withheld because it failed the sanitizer.", "streams": [], "verdict": "NOT_RUN"}
        return res
