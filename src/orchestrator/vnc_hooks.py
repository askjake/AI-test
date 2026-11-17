"""VNC procedure runs: the same run modes, checkpoints, cancellation, evidence and report as the nested-RDP chain, for ONE VNC desktop.

Called from ``runner._run_session`` only when ``target.type == "vnc"`` AND the project carries a dashboard ``procedure`` block with
``protocol: vnc``.  Every other VNC project (and every other target type) runs exactly as before.

What a VNC "connection test" proves - and does not:
  * proves: the runner's VNC viewer opened a window for the configured host/port with the saved (obfuscated) password file, and a
    non-blank desktop image was captured;
  * does NOT prove the machine or account identity (VNC exposes none), and performs NO operating step.

Session end (documented, enforced by construction):
  * remote applications the steps opened (for example a browser) are never closed by the application;
  * only the runner's own viewer window/process is closed ("disconnect the automation client");
  * the remote session is never logged off, locked or shut down.
"""
from __future__ import annotations

import io
import os
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable

from PIL import Image

from . import chain_runtime as cr
from .chain import ChainResult, ChainState, HopState, HopStatus, RunMode, ensure_shared_dir
from .chain_hooks import (CHECKPOINT_TIMEOUT_SECONDS, _await_request, _summary_text, _write_nrdp_status)
from .models import AssertionResult, TestResult, TestStatus
from .targets import TargetSpec

SESSION_END_NOTE = ("Session end: the runner's own VNC viewer was closed (the automation client disconnected). Applications on the remote desktop, "
                    "including any browser the steps opened, were left open, and the remote session was not logged off, locked or shut down.")


def desktop_looks_usable(png: bytes) -> tuple[bool, str]:
    """A captured desktop must not be blank/uniform (a black or single-colour frame means the viewer has no picture)."""
    try:
        image = Image.open(io.BytesIO(png)).convert("L")
    except Exception:
        return False, "the captured image could not be decoded"
    if image.size[0] < 320 or image.size[1] < 200:
        return False, "the captured image is too small to be a desktop"
    low, high = image.getextrema()
    if high - low < 8:
        return False, "the captured image is uniform (blank or black); the VNC session shows no picture"
    return True, ""


class VncSessionController:
    """Quacks like ChainController for ``run_chain_session``: establish / teardown / notes / active_desktop / revalidate."""

    def __init__(self, *, targets: Any, computer: Any, target_params: dict, progress_path: str | None, evidence_dir: str | None,
                 cancel_event: Any, mode: RunMode, sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 window_title: str = "TigerVNC") -> None:
        self._targets, self._computer, self._params = targets, computer, dict(target_params)
        self._progress_path, self._evidence_dir, self._cancel = progress_path, evidence_dir, cancel_event
        self.mode, self._sleep, self._clock = mode, sleep, clock
        self._window_title = window_title
        self._handle: Any = None
        self._torn_down = False
        self._notes: list[str] = []
        self._evidence: list[dict] = []
        self._state = ChainState(mode=mode, hops=[HopState(order=1, host=str(target_params.get("host", "")), user="")])
        self._seq = 0

    # -- ChainController surface
    def active_desktop(self) -> int:
        return self._state.active_hop

    def notes(self) -> list[str]:
        return list(self._notes)

    def _progress(self, phase: str) -> None:
        if not self._progress_path:
            return
        payload = {"schema": 1, "mode": self.mode.value, "phase": phase, "checkpoint": None, "active_hop": self._state.active_hop,
                   "error": self._state.error, "hops": [h.model_dump(mode="json") for h in self._state.hops], "notes": list(self._notes),
                   "protocol": "vnc", "updated_at": time.time()}
        cr._atomic_write_json(self._progress_path, payload)

    def _set(self, status: HopStatus, detail: str = "") -> None:
        hop = self._state.hops[0]
        hop.status, hop.detail = status, detail
        self._progress("vnc_" + status.value)

    def _save(self, png: bytes, phase: str) -> dict | None:
        if not self._evidence_dir:
            return None
        ensure_shared_dir(self._evidence_dir)
        self._seq += 1
        path = os.path.join(self._evidence_dir, f"vnc-{self._seq:02d}-{phase}.png")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o644)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as fh:
            fh.write(png)
        item = {"path": path, "hop": 1, "phase": phase, "ts": time.time()}
        self._evidence.append(item)
        return item

    def _fail(self, code: str, message: str) -> ChainResult:
        self._state.error = {"hop": 1, "code": code, "message": message}
        status = HopStatus.CANCELLED if code == "CANCELLED" else HopStatus.FAILED
        self._set(status, message)
        self.teardown()
        self._progress("failed")
        return ChainResult(ok=False, failed_hop=1, code=code, message=message, state=self._state, evidence=list(self._evidence), notes=self.notes())

    def establish(self, chain: list) -> ChainResult:
        self._progress("starting")
        if self._cancel.is_set():
            return self._fail("CANCELLED", "Cancelled before the VNC viewer was opened.")
        self._set(HopStatus.CONNECTING, "Opening the VNC viewer from the runner.")
        params = {k: str(v) for k, v in self._params.items() if v not in (None, "")}
        params.setdefault("window", self._window_title)      # the viewer has no title flag: its window title contains "TigerVNC"
        try:
            self._handle = self._targets.open_target(TargetSpec("vnc", params))
        except Exception as exc:                      # type name only: client text could echo a command line
            return self._fail("VNC_OPEN_FAILED", f"Could not open the VNC viewer ({type(exc).__name__}). See the viewer log in the run folder.")
        self._set(HopStatus.VERIFYING, "Confirming the VNC desktop shows a picture.")
        deadline = self._clock() + 20.0
        reason = "no picture"
        while self._clock() < deadline:
            if self._cancel.is_set():
                return self._fail("CANCELLED", "Cancelled while waiting for the VNC desktop.")
            try:
                shot = self._computer.screenshot()
            except Exception as exc:
                return self._fail("VNC_CAPTURE_FAILED", f"The screen could not be captured ({type(exc).__name__}).")
            png = getattr(shot, "png", shot)
            self._save(png, "desktop")
            ok, reason = desktop_looks_usable(png)
            if ok:
                self._state.active_hop = 1
                self._set(HopStatus.CONFIRMED, "VNC viewer open and a desktop image was captured. Remote identity cannot be verified over VNC.")
                self._notes.append("VNC does not expose a machine or account identity: this run confirmed only that the viewer opened and showed a picture.")
                return ChainResult(ok=True, message="VNC desktop visible.", state=self._state, evidence=list(self._evidence), notes=self.notes())
            self._sleep(1.0)
        return self._fail("VNC_NO_PICTURE", f"The VNC viewer opened but never showed a usable desktop ({reason}). Check the password, the display/port and that the VNC server is running.")

    def revalidate_final_desktop(self) -> tuple[bool, str | None, str]:
        """Before each operating step: the viewer is still alive and still has a picture.  (The window is re-focused first.)"""
        if self._cancel.is_set():
            return False, "CANCELLED", "The run was cancelled."
        proc = getattr(self._handle, "process", None)
        if proc is not None and proc.poll() is not None:
            return False, "VNC_DISCONNECTED", "The VNC viewer exited (the session dropped); no input was sent."
        try:
            if self._targets.focus(getattr(self._handle, "window_name", self._window_title)) is None:
                return False, "VNC_WINDOW_LOST", "The VNC viewer window is no longer available; no input was sent."
            ok, reason = desktop_looks_usable(getattr(self._computer.screenshot(), "png", b""))
        except Exception as exc:
            return False, "VNC_CAPTURE_FAILED", f"The VNC desktop could not be re-checked ({type(exc).__name__})."
        return (True, None, "") if ok else (False, "VNC_NO_PICTURE", f"The VNC desktop no longer shows a picture ({reason}).")

    def teardown(self) -> None:
        if self._torn_down:
            return
        self._torn_down = True
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                self._targets.close_target(handle)
                self._notes.append(SESSION_END_NOTE)
            except Exception as exc:
                self._notes.append(f"Closing the runner's VNC viewer failed ({type(exc).__name__}); check the runner.")


def run_vnc_project(*, project: Any, loaded: list, reports_dir: str, run_ts: str, targets: Any, computer: Any,
                    client_factory: Callable[[], Any], drive_agent: Callable[..., Any], cancel_event: Any = None,
                    trigger_id: str | None = None) -> list:
    config = project.config
    req = _await_request(reports_dir, project.name, trigger_id)
    run_dir = req.run_dir or os.path.join(reports_dir, project.name, run_ts)
    os.makedirs(run_dir, exist_ok=True)
    cancel_event = cancel_event or threading.Event()
    stop_watch = cr.start_cancel_watcher(os.path.join(run_dir, "control"), cancel_event)
    restore_sigterm = cr.install_sigterm_cancel(cancel_event)
    mode_info = {"mode": req.mode, "effective_mode": req.mode, "requested_mode": req.requested_mode or (req.mode if req.source == "request" else "unknown"),
                 "downgraded": bool(req.requested_mode and req.requested_mode != req.mode) or (req.source != "request"),
                 "downgrade_reason": req.reason if (req.source != "request" or req.requested_mode != req.mode) else "", "protocol": "vnc"}
    _write_nrdp_status(run_dir, "running", mode_info)
    procedure = getattr(config, "procedure", None) or {}
    specs = [(p, s, ev) for (p, _g, s, ev, err) in loaded if s is not None and err is None]
    controller = VncSessionController(targets=targets, computer=computer, target_params=dict(config.target.params),
                                      progress_path=os.path.join(run_dir, "chain_progress.json"),
                                      evidence_dir=os.path.join(run_dir, "evidence"), cancel_event=cancel_event, mode=RunMode(req.mode))
    gate = cr.CheckpointGate(os.path.join(run_dir, "control"), cancel_event=cancel_event, timeout=CHECKPOINT_TIMEOUT_SECONDS)
    chain = [SimpleNamespace(order=1, host=str(config.target.params.get("host", "")), user="")]
    preamble = ("This is a VNC desktop. Take actions only on the VNC viewer window. Execute ONLY the current step. "
                "Leave every application you open (for example the browser) open; never close it, never log off, lock or shut down the remote machine. "
                "Never type, request or repeat a password.")

    def drive_step(step: dict, pre: str) -> dict:
        if not specs:
            return {"status": "errored", "summary": "no spec available"}
        path, spec, ev = specs[0]
        step_spec = spec.model_copy(deep=True)
        order, title = step.get("order"), str(step.get("title", ""))
        step_spec.title = f"Step {order}: {title}"
        step_spec.goal = (f"Perform ONLY step {order} on the VNC desktop: {title}\n" + str(step.get("instructions", ""))
                          + "\nDo not start, prepare or partly perform any other step. Leave applications you open running.")
        step_spec.assertions = [str(c) for c in (step.get("completion_checks") or [])] or [f"Step {order} ({title}) completed as described, with visible evidence."]
        step_spec.manual_text = preamble + "\n\n" + (spec.manual_text or "")      # the VNC preamble, not the Windows chain one passed in `pre`
        step_ev = os.path.join(ev, f"step-{order}")
        ensure_shared_dir(step_ev)
        evidence = lambda: [{"path": os.path.join(step_ev, f)} for f in sorted(os.listdir(step_ev)) if f.endswith(".png")]  # noqa: E731
        r = drive_agent(step_spec, config=config, evidence_dir=step_ev, computer=computer, client=client_factory(), manual_dir=config.manual_dir)
        return {"status": r.status.value, "summary": r.summary or "", "evidence": evidence()}

    final, outcome = "errored", None
    try:
        outcome = cr.run_chain_session(controller=controller, chain=chain, procedure=procedure, mode=req.mode, drive_step=drive_step, gate=gate,
                                       cancel_event=cancel_event, revalidate=controller.revalidate_final_desktop,
                                       requested_mode=req.requested_mode or (req.mode if req.source == "request" else "unknown"),
                                       downgrade_reason=req.reason)
        final = cr.guard_report_result(outcome, procedure.get("required_checkpoints", []) or [], gate)
    except Exception as exc:
        outcome = cr.ChainRunOutcome(status="errored", mode=req.mode, error={"hop": None, "code": "RUNTIME_ERROR", "message": type(exc).__name__})
        try:
            controller.teardown()
        except Exception:
            pass
    finally:
        stop_watch()
        restore_sigterm()
        state = {"passed": "complete", "failed": "failed", "incomplete": "incomplete"}.get(final, "error")
        if cancel_event.is_set():
            state = "cancelled"
        _write_nrdp_status(run_dir, state, {**mode_info, "result": final, "error_code": (outcome.error or {}).get("code") if outcome else None})
    outcome = outcome or cr.ChainRunOutcome(status="errored", mode=req.mode, error={"hop": None, "code": "RUNTIME_ERROR", "message": "no outcome"})
    status = {"passed": TestStatus.PASSED, "failed": TestStatus.FAILED}.get(final, TestStatus.ERRORED)
    err = None
    if outcome.error:
        err = f"{outcome.error.get('code')}: {outcome.error.get('message')}"
    elif final == "incomplete":
        err = "run incomplete: operator checkpoint not acknowledged, cancelled or timed out"
    cr._atomic_write_json(os.path.join(run_dir, "chain_outcome.json"), outcome.as_dict())
    try:
        with open(os.path.join(run_dir, "chain_report.html"), "w", encoding="utf-8") as fh:
            fh.write("<!doctype html><meta charset=utf-8><title>VNC session</title>" + cr.render_chain_section_html(outcome.as_dict()))
        os.chmod(os.path.join(run_dir, "chain_report.html"), 0o644)
    except OSError:
        pass
    per_assertion = [AssertionResult(text=f"Step {s.get('order')}: {s.get('title')}", passed=s.get("status") in ("passed", "acknowledged"),
                                     evidence=s.get("summary") or s.get("note")) for s in outcome.steps]
    results = []
    for path, spec, ev in specs[:1]:
        r = TestResult(title=spec.title, target_type="vnc", status=status, declared_assertions=len(spec.assertions), error=err,
                       per_assertion=per_assertion, summary=_summary_text(outcome))
        r.spec_path, r.evidence_dir = path, ev
        results.append(r)
    return results
