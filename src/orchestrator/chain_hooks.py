"""Package adapter wiring chain_runtime into runner._run_session (NRDP-1).

Called from runner._run_session ONLY when config.target.type == "rdp-chain"; the
single-target path never imports this module.  Returns the list of TestResult objects.

Secrets: this module never reads or logs a password.  The ChainController receives a
``read_secret`` callable and passes the value straight to ``Computer.type_secret``.
"""
from __future__ import annotations

import html
import json
import os
import threading
import time
from typing import Any, Callable

from . import browser_modes as bm
from . import chain_runtime as cr
from .chain import (
    ChainController,
    ensure_shared_dir,
    ObservedState,
    OperatorConfirmClassifier,
    RunMode,
    VisionDesktopClassifier,
)
from .models import AssertionResult, TestResult, TestStatus

REQUEST_WAIT_SECONDS = 30.0
CHECKPOINT_TIMEOUT_SECONDS = 3600.0   # how long a run waits for the operator at a physical checkpoint
_STATE_TOOL_NAME = "report_screen_state"


def _state_tool() -> dict:
    """Forced structured-output tool: the model can only describe the screen, never act."""
    return {
        "name": _STATE_TOOL_NAME,
        "description": "Report which kind of Windows screen the screenshot shows. This tool does not act on the screen.",
        "input_schema": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "enum": [m.value for m in ObservedState]},
                "focused_field": {"type": "string", "enum": ["username", "password", "none", "unknown"]},
                "identity_evidence": {"type": "string"},
                "password_masked": {"type": "boolean"},
                "displayed_username": {"type": "string"},
                "console_text": {"type": "string"},
                "fullscreen": {"type": "boolean"},
                "connection_bar": {"type": "boolean"},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": ["state", "focused_field", "identity_evidence", "password_masked", "confidence"],
        },
    }


def _ask_model_from_client(client: Any) -> Callable[[bytes, str], str] | None:
    """Screenshot + question -> JSON text, via BedrockClient.invoke with a forced tool.

    ``BedrockClient.invoke`` requires ``tools``; a single non-acting tool with a forced
    ``tool_choice`` gives structured output without any computer-control tool.
    """
    invoke = getattr(client, "invoke", None)
    if invoke is None:
        return None
    import base64

    tool = _state_tool()

    def ask(png: bytes, prompt: str) -> str:
        messages = [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": base64.b64encode(png).decode("ascii")}},
            {"type": "text", "text": prompt + f" Answer by calling {_STATE_TOOL_NAME}."}]}]
        result = invoke(messages=messages, tools=[tool], max_tokens=1400,
                        tool_choice={"type": "tool", "name": _STATE_TOOL_NAME})
        use = result.first_tool_use() if hasattr(result, "first_tool_use") else None
        if use is not None and isinstance(getattr(use, "input", None), dict):
            return json.dumps(use.input)
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                return text
        return ""

    return ask


def _enforce_connection_only(req: "cr.RunRequest") -> "cr.RunRequest":
    """Independent backstop for the connection-only qualification (review blocker B1).

    chain_runtime.read_run_request already refuses operating modes, but this does not TRUST that:
    whatever mode reaches the production runner is re-checked here, at the point where the chain
    session is about to be built.  Any operating mode becomes a connection test, and the request
    the operator made is preserved in ``requested_mode`` so the report cannot present a refused
    operating run as a completed procedure.
    """
    # CP43: explicit ALLOW-LIST (closes characterisation risk R1: the old check let any unknown mode string through).  Only exact shapes pass.
    if getattr(req, "refused", False) is True:
        return req
    if not bm.is_canonical(req.mode):
        return cr.RunRequest(refused=True, reason="mode rejected: unknown or malformed mode value", run_dir=req.run_dir, requested_mode=bm.UNRECOGNIZED)
    if req.mode == bm.CONNECTION_TEST:
        return req
    if req.mode == bm.BROWSER_VERIFY:
        if isinstance(getattr(req, "browser", None), bm.BrowserGrant) and req.source == "request" and getattr(cr.browser_verify_policy(), "enabled", False) is True:
            return req
        return cr.RunRequest(refused=True, reason="browser_verify refused before launch: no validated grant", run_dir=req.run_dir, requested_mode=bm.BROWSER_VERIFY)
    return cr.RunRequest(mode=cr.CONNECTION_TEST, confirmed=req.confirmed, source=req.source,
                         reason=cr.CONNECTION_ONLY_REASON, run_dir=req.run_dir,
                         requested_mode=req.requested_mode or req.mode)


def _await_request(reports_dir: str, project: str, trigger_id: str | None,
                   wait: float = REQUEST_WAIT_SECONDS,
                   sleep: Callable[[float], None] = time.sleep,
                   clock: Callable[[], float] = time.monotonic,
                   expected_binding: str | None = None) -> "cr.RunRequest":
    """The dashboard publishes run_request.json just after launching the container; wait briefly.

    Anything missing after the bounded wait degrades to connection_test (never stronger).
    """
    deadline = clock() + wait
    while True:
        req = _enforce_connection_only(cr.read_run_request(reports_dir, project, trigger_id, expected_binding))
        # Only a MISSING request is worth waiting for (the dashboard writes it just after launch).  A request
        # that exists but is invalid, foreign or untrusted will not improve with time: decide now.
        waiting = req.reason.startswith("run request missing")
        if not waiting or not trigger_id or clock() >= deadline:
            return req
        sleep(1.0)


def _write_nrdp_status(run_dir: str | None, state: str, detail: dict | None = None) -> None:
    if not run_dir:
        return
    try:
        cr._atomic_write_json(os.path.join(run_dir, "status.json"),
                              {"state": state, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               **(detail or {})})
    except Exception:
        pass  # status is best-effort; chain_progress.json and the report remain


def _summary_text(outcome: "cr.ChainRunOutcome") -> str:
    lines = [f"Mode: {outcome.mode}. Result: {outcome.status}."]
    if outcome.downgraded:
        lines.append(f"REQUESTED MODE WAS {outcome.requested_mode}; THIS RUN WAS {outcome.mode} ONLY "
                     f"({outcome.downgrade_reason or 'reason not recorded'}). It is not a completed operating procedure.")
    b = getattr(outcome, "browser", None)
    if isinstance(b, dict):
        pb, cl = b.get("playback") or {}, b.get("cleanup") or {}
        lines.append(f"Browser verification playback: {pb.get('verdict') or pb.get('code') or 'NOT_RUN'} (verification {pb.get('status')}); live-source freshness UNVERIFIED.")
        lines.append(f"Browser cleanup: {cl.get('status')}" + (f" ({cl.get('reason')})" if cl.get("reason") else "") + "; playback and cleanup are separate results.")
    for note in getattr(outcome, "notes", []) or []:
        lines.append(f"Note: {note}")
    for hop in outcome.hops:
        lines.append(f"Hop {hop['order']} ({hop['host']}, {hop['user']}): {hop['status']}"
                     + (f" - {hop['detail']}" if hop.get("detail") else ""))
    if outcome.error:
        lines.append(f"Failed at hop {outcome.error.get('hop')}: {outcome.error.get('code')} - {outcome.error.get('message')}")
    for step in outcome.steps:
        lines.append(f"Step {step.get('order')} {step.get('title')}: {step.get('status')}")
    if outcome.skipped:
        lines.append(f"{len(outcome.skipped)} step(s) NOT run: "
                     + "; ".join(f"{s.get('order')} ({s.get('reason')})" for s in outcome.skipped))
    lines.append("Not established by this run: serial/COM handle release, application health beyond the "
                 "checks listed, production inventory correctness, or any physical receiver behaviour.")
    return "\n".join(lines)


BROWSER_MODEL_CALL_CAP = 60      # hard per-run cap on page-classifier model calls (load polls + observation frames)


def _browser_runner(*, controller: Any, client: Any, budget: Any, grant: Any) -> Callable[[], dict]:
    """Runner-side dispatch for a GRANTED browser_verify request: the real page-classifier adapter on the evaluated request path through the
    pre-verified, budget-governed model client; the real verifier on the controller session.  The production adapter exposes no remote window
    inventory (ownership port None)."""
    def run() -> dict:
        from . import browser_model_path as mp
        from . import browser_page_classifier as pcl
        from . import browser_verify as bv
        ask = mp.ask_model_from_client(client)
        ask.budget = budget                                              # type: ignore[union-attr]  (surfaced through the classifier's usage counters)
        classifier = pcl.VisionPageClassifier(ask, max_calls=budget.max_attempts + 2)      # secondary guard only: the transport budget trips first and names the reason
        verifier = bv.BrowserVerifier(bv.ControllerSession(controller, None), classifier, policy=cr.browser_verify_policy())
        request = bv.BrowserVerifyRequest(project=grant.project, run_id=grant.run_id, requested_mode=bv.MODE_NAME, url=grant.url,
                                          confirm_phrase=bv.expected_confirm_phrase(grant.project), leave_open_ack=bv.expected_leave_open_phrase(grant.project))
        result = verifier.run(request)
        result["evaluation_binding"] = mp.evaluation_binding(client)
        result["model_budget"] = budget.counters()
        return result
    return run


def run_chain_project(*, project: Any, loaded: list, reports_dir: str, run_ts: str,
                      targets: Any, computer: Any, client_factory: Callable[[], Any],
                      drive_agent: Callable[..., Any], cancel_event: Any = None,
                      trigger_id: str | None = None) -> list:
    config = project.config
    try:
        expected_binding = bm.connection_binding(project.name, bm.hop_rows_from_chain(config.target.hops))   # recomputed from the project THIS runner loaded
    except Exception:
        expected_binding = None
    req = _await_request(reports_dir, project.name, trigger_id, expected_binding=expected_binding)
    run_dir = req.run_dir or os.path.join(reports_dir, project.name, run_ts)
    os.makedirs(run_dir, exist_ok=True)
    cancel_event = cancel_event or threading.Event()
    # Dashboard cancel = trusted control/cancel_request.json, or SIGTERM from `docker stop`.
    stop_watch = cr.start_cancel_watcher(os.path.join(run_dir, "control"), cancel_event)
    restore_sigterm = cr.install_sigterm_cancel(cancel_event)
    # CP44: the configured model/profile, region and request contract must equal the CP42-C evaluated binding BEFORE any session is launched.  A
    # mismatch refuses the request here (no controller, no desktop, no input, no model call).  Pure attribute reads and a local body build.
    bv_client, bv_budget = None, None
    if req.mode == bm.BROWSER_VERIFY and not req.refused:
        from . import browser_budget as _bb
        from . import browser_model_path as _mp
        from . import browser_verify as _bv
        try:
            bv_client = client_factory()                       # a SEPARATE instance: the identity classifier's client keeps its production retry behaviour
            ok, code = _mp.verify_evaluated_binding(bv_client)
        except Exception:
            ok, code = False, "BINDING_UNVERIFIABLE"
        if ok:
            bv_budget = _bb.budget_for(_bv.BrowserVerifyLimits())
            bv_budget.install(bv_client)                       # no application retries; every transport attempt counted
        else:
            req = cr.RunRequest(refused=True, reason=f"browser_verify refused before launch: {code}", run_dir=req.run_dir, requested_mode=bm.BROWSER_VERIFY)
    mode_info = {"mode": req.mode, "effective_mode": req.mode, "requested_mode": req.requested_mode or (req.mode if req.source == "request" else "unknown"),
                 "downgraded": bool(req.requested_mode and req.requested_mode != req.mode) or
                               (req.source != "request"),
                 "downgrade_reason": req.reason if (req.source != "request" or req.requested_mode != req.mode) else ""}
    if req.refused:
        # CP43: refused BEFORE any client, controller, browser, model or input exists.
        stop_watch()
        restore_sigterm()
        _write_nrdp_status(run_dir, "blocked", {**mode_info, "result": "refused", "error_code": "MODE_REFUSED"})
        refused = cr.ChainRunOutcome(status="errored", mode=req.mode, requested_mode=req.requested_mode, downgrade_reason=req.reason,
                                     error={"hop": None, "code": "MODE_REFUSED", "message": req.reason})
        cr._atomic_write_json(os.path.join(run_dir, "chain_outcome.json"), refused.as_dict())
        out_results = []
        for path, spec, ev in [(p, s, e) for (p, _g, s, e, err) in loaded if s is not None and err is None][:1]:
            r = TestResult(title=spec.title, target_type="rdp-chain", status=TestStatus.ERRORED, declared_assertions=len(spec.assertions),
                           error="request refused before any session was started: " + req.reason, per_assertion=[],
                           summary="Request refused before any session, browser, model call or input. " + req.reason)
            r.spec_path, r.evidence_dir = path, ev
            out_results.append(r)
        return out_results
    _write_nrdp_status(run_dir, "running", mode_info)
    try:
        ask = _ask_model_from_client(client_factory())
    except Exception:
        ask = None
    classifier = VisionDesktopClassifier(ask) if ask else OperatorConfirmClassifier()
    controller = ChainController(
        targets=targets, computer=computer, classifier=classifier,
        read_secret=cr.make_read_secret(getattr(targets, "secrets_dir", "/app/secrets")),
        progress_path=os.path.join(run_dir, "chain_progress.json"),
        cancel_event=cancel_event, evidence_dir=os.path.join(run_dir, "evidence"),
        mode=RunMode(cr.CONNECTION_TEST if req.mode == bm.BROWSER_VERIFY else req.mode))      # the controller only ever establishes + confirms; browser_verify is not a controller mode
    gate = cr.CheckpointGate(os.path.join(run_dir, "control"), cancel_event=cancel_event, timeout=CHECKPOINT_TIMEOUT_SECONDS)
    procedure = getattr(config, "procedure", None) or {}
    specs = [(p, s, ev) for (p, _g, s, ev, err) in loaded if s is not None and err is None]

    def drive_step(step: dict, preamble: str) -> dict:
        if not specs:
            return {"status": "errored", "summary": "no spec available"}
        path, spec, ev = specs[0]
        step_spec = spec.model_copy(deep=True)
        order, title = step.get("order"), str(step.get("title", ""))
        instructions = str(step.get("instructions", ""))
        # Judge ONLY this step: its own goal and its own completion checks.
        step_spec.title = f"Step {order}: {title}"
        step_spec.goal = (f"Perform ONLY step {order} on the desktop of the final hop: {title}\n" + instructions
                          + "\nDo not start, prepare or partly perform any other step.")
        step_spec.assertions = [str(c) for c in (step.get("completion_checks") or [])] or [
            f"Step {order} ({title}) completed as described, with visible evidence."]
        step_spec.manual_text = preamble + "\n\n" + (spec.manual_text or "")
        step_ev = os.path.join(ev, f"step-{order}")
        ensure_shared_dir(step_ev)
        text = f"{title}\n{instructions}"
        guard = cr.StepGuard(controller.classify_screen,
                             allow_uac_consent=bool(cr.ELEVATION_REQUEST.search(text)),
                             step_text=text,
                             mutating_allowed=(req.mode == cr.FULL_RUN and step.get("mutating") is True))
        guarded = cr.GuardedComputer(computer, guard)
        evidence = lambda: [{"path": os.path.join(step_ev, f)} for f in sorted(os.listdir(step_ev)) if f.endswith(".png")]  # noqa: E731
        try:
            r = drive_agent(step_spec, config=config, evidence_dir=step_ev, computer=guarded,
                            client=client_factory(), manual_dir=config.manual_dir)
        except cr.StepGuardViolation as violation:
            return {"status": "errored", "summary": f"{violation.code}: {violation.message}",
                    "error_code": violation.code, "evidence": evidence()}
        if guard.violation is not None:   # the agent loop may have swallowed the exception: still a failure
            code, message = guard.violation
            return {"status": "errored", "summary": f"{code}: {message}", "error_code": code, "evidence": evidence()}
        return {"status": r.status.value, "summary": r.summary or "", "evidence": evidence()}

    browser_runner = None
    if req.mode == bm.BROWSER_VERIFY:
        browser_runner = _browser_runner(controller=controller, client=bv_client, budget=bv_budget, grant=req.browser)
    final = "errored"
    outcome = None
    try:
        outcome = cr.run_chain_session(browser_runner=browser_runner, controller=controller, chain=list(config.target.hops),
                                       procedure=procedure, mode=req.mode, drive_step=drive_step,
                                       gate=gate, cancel_event=cancel_event,
                                       revalidate=controller.revalidate_final_desktop,
                                       requested_mode=req.requested_mode or (req.mode if req.source == "request" else "unknown"),
                                       downgrade_reason=req.reason)
        final = cr.guard_report_result(outcome, procedure.get("required_checkpoints", []) or [], gate)
    except Exception as exc:  # run_chain_session handles its own errors; this is the last resort
        outcome = cr.ChainRunOutcome(status="errored", mode=req.mode,
                                     error={"hop": None, "code": "RUNTIME_ERROR", "message": type(exc).__name__})
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
        _write_nrdp_status(run_dir, state, {**mode_info, "result": final,
                                            "error_code": (outcome.error or {}).get("code") if outcome else None})
    if outcome is None:   # defensive: a failure before the session produced anything
        outcome = cr.ChainRunOutcome(status="errored", mode=req.mode,
                                     error={"hop": None, "code": "RUNTIME_ERROR", "message": "no outcome was produced"})
    status = {"passed": TestStatus.PASSED, "failed": TestStatus.FAILED}.get(final, TestStatus.ERRORED)
    err = None
    if outcome.error:
        err = f"hop {outcome.error.get('hop')}: {outcome.error.get('code')}: {outcome.error.get('message')}"
    elif final == "incomplete":
        err = "run incomplete: operator checkpoint not acknowledged, cancelled or timed out"
    cr._atomic_write_json(os.path.join(run_dir, "chain_outcome.json"), outcome.as_dict())
    try:
        with open(os.path.join(run_dir, "chain_report.html"), "w", encoding="utf-8") as fh:
            fh.write("<!doctype html><meta charset=utf-8><title>Connection chain</title>"
                     + cr.render_chain_section_html(outcome.as_dict()))
        os.chmod(os.path.join(run_dir, "chain_report.html"), 0o644)
    except OSError:
        pass
    per_assertion = [AssertionResult(text=f"Step {s.get('order')}: {s.get('title')}",
                                     passed=s.get("status") in ("passed", "acknowledged"),
                                     evidence=s.get("summary") or s.get("note"))
                     for s in outcome.steps]
    results = []
    for path, spec, ev in specs[:1]:
        r = TestResult(title=spec.title, target_type="rdp-chain", status=status,
                       declared_assertions=len(spec.assertions), error=err,
                       per_assertion=per_assertion, summary=_summary_text(outcome))
        r.spec_path, r.evidence_dir = path, ev
        results.append(r)
    return results
