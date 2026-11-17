"""Runs one test or one project and collects evidence (Phase 5).

``run_spec`` opens the spec's target window, runs the agent loop under the spec's
**effective** (project-merged) caps, and writes evidence to
``reports/<project>/<run_ts>/<test_slug>/`` (per-step screenshots + ``result.json``),
closing the target afterward. ``run_project`` runs every spec in a project under a single
``run_ts`` and returns a :class:`RunResult`.

The :class:`Computer`, :class:`Targets`, and :class:`BedrockClient` are injectable so the
orchestration can be unit-tested without a real display or Bedrock.
"""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
import re
import sys
from datetime import datetime, timezone
from typing import Callable, Optional

from .agent import run_planner_agent
from .audit import AuditLog
from .bedrock_client import BedrockClient
from .computer import Computer
from .config import settings
from .models import (
    DigestEntry,
    EffectiveConfig,
    Project,
    RunResult,
    Target,
    TestResult,
    TestSpec,
    TestStatus,
)
from .projects import (
    MANUAL_DIR,
    ManualError,
    discover_projects,
    find_project,
    load_manual,
    project_slug,
    project_for_spec,
)
from .redaction import redactor_from_regions
from .report import render_all, render_spec_report
from .targets import TargetError, TargetSpec, Targets
from .test_loader import SpecError, load_spec

# Factories let tests inject fakes; defaults build the real thing from config.
ComputerFactory = Callable[[EffectiveConfig], object]
TargetsFactory = Callable[[EffectiveConfig], Targets]
ClientFactory = Callable[[], BedrockClient]


def _json_write(path: str, data: dict) -> None:
    """Atomically write *data* as JSON to *path*, creating parent dirs."""
    import json as _json, os as _os
    _os.makedirs(_os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as _f:
        _json.dump(data, _f, indent=2)


def _env_run_ts() -> str | None:
    """CP45-G: the dashboard precreates reports/<project>/<run_ts>/ and forwards its name; anything malformed is ignored (the runner then names its own)."""
    import re as _re
    value = os.environ.get("ORCHESTRATOR_RUN_TS", "")
    return value if _re.fullmatch(r"\d{8}T\d{6}Z", value) else None


def _now_ts() -> str:
    """A filesystem-safe UTC timestamp used as a run directory name."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(text: str) -> str:
    """Turn a spec title or filename into a safe directory slug."""
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return base or "test"


def _default_targets(config: EffectiveConfig) -> Targets:
    return Targets(
        ssh_host_allowlist=list(config.ssh_host_allowlist),
        rdp_host_allowlist=list(config.rdp_host_allowlist),
        vnc_host_allowlist=list(config.vnc_host_allowlist),
    )


def _default_computer(config: EffectiveConfig) -> Computer:
    """Build a Computer with the project's screenshot redactor (Phase 8)."""
    return Computer(redactor=redactor_from_regions(config.redaction))


def run_spec(
    path: str,
    *,
    project: Project | None = None,
    run_ts: str | None = None,
    reports_dir: str | None = None,
    computer_factory: ComputerFactory = _default_computer,
    targets_factory: TargetsFactory = _default_targets,
    client_factory: ClientFactory = BedrockClient,
) -> TestResult:
    """Run a single spec end-to-end and return its :class:`TestResult`.

    Resolves the spec's owning project (for the effective config + report tree), loads and
    validates the spec, opens its target, runs the agent under the project's caps, writes
    evidence, and closes the target. A spec-parse or target/setup failure yields an
    ``errored`` :class:`TestResult` rather than raising, so a project run isn't aborted by
    one bad spec.
    """
    project = project or project_for_spec(path)
    config = project.config if project else _effective_from_settings()
    project_name = project.name if project else "default"
    run_ts = run_ts or _now_ts()
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir

    manual_dir = project.config.manual_dir if project is not None else None
    try:
        spec = load_spec(path, config=config)
        if project is not None:
            spec.manual_text = load_manual(manual_dir)
    except (SpecError, ManualError) as exc:
        title = os.path.splitext(os.path.basename(path))[0]
        evidence_dir = os.path.join(reports_dir, project_name, run_ts, _slug(title))
        os.makedirs(evidence_dir, exist_ok=True)
        result = TestResult(
            title=title,
            target_type="",
            status=TestStatus.ERRORED,
            error=f"spec load failed: {exc}",
        )
        result.spec_path = path
        result.evidence_dir = evidence_dir
        _write_result_json(evidence_dir, result)
        return result

    evidence_dir = os.path.join(
        reports_dir, project_name, run_ts, _slug(spec.title)
    )
    os.makedirs(evidence_dir, exist_ok=True)

    result = _run_one(
        spec,
        config=config,
        evidence_dir=evidence_dir,
        computer_factory=computer_factory,
        targets_factory=targets_factory,
        client_factory=client_factory,
        manual_dir=manual_dir,
    )
    result.spec_path = path
    result.evidence_dir = evidence_dir
    _write_result_json(evidence_dir, result)
    return result


def _run_one(
    spec: TestSpec,
    *,
    config: EffectiveConfig,
    evidence_dir: str,
    computer_factory: ComputerFactory,
    targets_factory: TargetsFactory,
    client_factory: ClientFactory,
    manual_dir: str | None = None,
) -> TestResult:
    """Open the target, drive the agent, close the target. Failures -> errored result."""
    targets = targets_factory(config)
    # Capture client stdout+stderr (for example a VNC client startup failure) into the
    # run's evidence dir so a failed launch is debuggable from the report, not just live logs.
    if getattr(targets, "log_dir", None) is None:
        targets.log_dir = evidence_dir
    target_spec = TargetSpec(config.target.type, dict(config.target.params))

    try:
        handle = targets.open_target(target_spec)
    except TargetError as exc:
        return TestResult(
            title=spec.title,
            target_type=spec.target_type,
            status=TestStatus.ERRORED,
            declared_assertions=len(spec.assertions),
            error=f"target setup failed: {exc}",
        )

    try:
        return _drive_agent(
            spec,
            config=config,
            evidence_dir=evidence_dir,
            computer=computer_factory(config),
            client=client_factory(),
            manual_dir=manual_dir,
        )
    finally:
        targets.close_target(handle)


def _drive_agent(
    spec: TestSpec,
    *,
    config: EffectiveConfig,
    evidence_dir: str,
    computer: object,
    client: BedrockClient,
    prior_context: str | None = None,
    manual_dir: str | None = None,
) -> TestResult:
    """Run the agent loop against an ALREADY-open target; owns no target open/close.

    Shared by the per-spec path (:func:`_run_one`) and the shared-session path
    (:func:`_run_session`). ``prior_context`` is the accumulated session digest seeded into the
    agent's fresh context, or None for an isolated run.

    Every spec runs as a text-only planner that dispatches each step to a fresh vision-executor
    sub-context (:func:`run_planner_agent`), so the main per-spec context never holds a
    screenshot and a session can run many steps without its context growing.
    """
    audit = AuditLog(os.path.join(evidence_dir, "audit.jsonl"))
    return run_planner_agent(
        spec,
        computer=computer,
        client=client,
        screenshots_dir=evidence_dir,
        max_planner_steps=config.max_planner_steps,
        step_max_steps=config.step_max_steps,
        max_seconds=config.max_seconds,
        max_tokens=config.max_tokens,
        max_total_tokens=config.max_total_tokens,
        step_max_tokens=config.step_max_tokens,
        keep_last_n_screenshots=config.keep_last_n_screenshots,
        action_delay_seconds=config.action_delay_seconds,
        prior_context=prior_context,
        manual_dir=manual_dir,
        audit=audit,
    )


def _write_status(run_dir: str, *, state: str, specs_total: int = 0,
                  specs_completed: "list[dict]" = None,
                  current_spec: str | None = None,
                  current_spec_index: int = 0,
                  current_evidence_dir: str | None = None,
                  started_at: str | None = None) -> None:
    """Write (or overwrite) ``status.json`` inside *run_dir*.

    Fields match the RunStatusModel consumed by the dashboard status endpoint.
    Written atomically via a temp-file rename so readers never see a partial file.

    The runner normally executes as container uid 10001 while the dashboard runs
    as the host user.  ``mkstemp`` deliberately creates mode 0600 files, so the
    status file must be made world-readable before publication or the dashboard
    cannot distinguish an active run from its still-claimed trigger.
    """
    import json as _json
    payload: dict = {
        "state": state,
        "specs_total": specs_total,
        "specs_completed": specs_completed or [],
        "current_spec": current_spec,
        "current_spec_index": current_spec_index,
        "current_evidence_dir": current_evidence_dir,
        "started_at": started_at,
    }
    path = os.path.join(run_dir, "status.json")
    fd, tmp = tempfile.mkstemp(dir=run_dir, prefix=".status_", suffix=".json")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as fh:
            _json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run_project(
    name: str,
    *,
    run_ts: str | None = None,
    reports_dir: str | None = None,
    specs_root: str | None = None,
    allow_disabled: bool = False,
    computer_factory: ComputerFactory = _default_computer,
    targets_factory: TargetsFactory = _default_targets,
    client_factory: ClientFactory = BedrockClient,
) -> RunResult:
    """Run every spec in project ``name`` under one ``run_ts`` and return a RunResult."""
    project = find_project(name, specs_root, include_disabled=True) if allow_disabled else find_project(name, specs_root)
    if project is None:
        raise ValueError(f"no enabled project named {name!r} under the specs root")
    stable_name = project_slug(project)
    if project.name != stable_name:
        project = project.model_copy(update={"name": stable_name})

    run_ts = run_ts or _env_run_ts() or _now_ts()
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir

    session_summary: str | None = None
    if project.specs:
        results, session_summary = _run_session(
            project,
            run_ts=run_ts,
            reports_dir=reports_dir,
            computer_factory=computer_factory,
            targets_factory=targets_factory,
            client_factory=client_factory,
        )
    else:
        results = []

    run = RunResult(
        project=project.name,
        run_ts=run_ts,
        results=results,
        report_dir=os.path.join(reports_dir, project.name, run_ts),
        session_summary=session_summary,
    )
    render_all(run, model_id=settings.bedrock_model_id, reports_dir=reports_dir)
    return run


# Cap on the session digest carried into each child's context. The digest is plain text (a few
# lines per spec), but a very deep tree could still grow it without bound; keeping the most
# recent entries keeps every child's seed small. The login/setup entry is always kept.
_DIGEST_KEEP_LAST = 12


def _ordered_specs(project_dir: str) -> list[tuple[str, str]]:
    """Return ``(spec_path, group)`` pairs under ``project_dir`` in depth-first, sorted order.

    Specs directly in a directory (sorted) come before descending into its sub-directories
    (sorted), so a shared session runs the root ``00-*.md`` setup spec before any child group.
    ``group`` is the spec's directory relative to ``project_dir`` (``""`` at the root), used to
    group rows under sub-headings in the aggregated report.
    """
    ordered: list[tuple[str, str]] = []

    def walk(directory: str) -> None:
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            return
        files = [e for e in entries if e.endswith(".md") and os.path.isfile(os.path.join(directory, e))]
        subdirs = [
            e for e in entries
            if os.path.isdir(os.path.join(directory, e)) and e != MANUAL_DIR
        ]
        for name in files:
            path = os.path.join(directory, name)
            group = os.path.relpath(directory, project_dir).replace(os.sep, "/")
            ordered.append((path, "" if group == "." else group))
        for name in subdirs:
            walk(os.path.join(directory, name))

    walk(project_dir)
    return ordered


def _render_digest(digest: list[DigestEntry]) -> str | None:
    """Render the accumulated digest as the compact text seeded into the next child's context."""
    if not digest:
        return None
    kept = digest if len(digest) <= _DIGEST_KEEP_LAST else [digest[0], *digest[-(_DIGEST_KEEP_LAST - 1):]]
    lines: list[str] = []
    for entry in kept:
        line = f"- {entry.title}: {entry.status.value}"
        if entry.summary:
            line += f" — {entry.summary}"
        if entry.ending_state:
            line += f" (ending state: {entry.ending_state})"
        lines.append(line)
    return "\n".join(lines)


def _render_session_summary(digest: list[DigestEntry]) -> str | None:
    """Render the concise per-spec roll-up shown in the mother report's Session summary panel.

    Unlike :func:`_render_digest` (the verbose text seeded into each child's context), this is
    one terse line per spec — just the spec title and its pass/fail status — so the panel stays
    scannable instead of repeating every spec's full summary and ending state.
    """
    if not digest:
        return None
    return "\n".join(f"- {entry.title}: {entry.status.value}" for entry in digest)


def _run_session(
    project: Project,
    *,
    run_ts: str,
    reports_dir: str,
    computer_factory: ComputerFactory,
    targets_factory: TargetsFactory,
    client_factory: ClientFactory,
) -> tuple[list[TestResult], str | None]:
    """Run a project's specs over ONE shared target (Phase: hierarchical session).

    Opens the target once (from the project's ``project.yaml`` ``target:``), walks the spec tree
    depth-first, runs each spec in a fresh agent context seeded with the accumulated digest of
    earlier specs, and closes the target once. Returns the per-spec results and the rolled-up
    session-summary text. Mirrors ``run_spec``'s evidence bookkeeping (spec_path, evidence_dir,
    result.json) since it bypasses ``run_spec``, and renders a per-spec report for every spec.
    """
    config = project.config
    project_name = project.name
    manual_dir = project.config.manual_dir

    # 1. Load every spec up front; a parse error becomes a recorded load-error (not an abort).
    loaded: list[tuple[str, str, TestSpec | None, str, str | None]] = []
    for spec_path, group in _ordered_specs(project.dir):
        try:
            spec = load_spec(spec_path, config=config)
            spec.manual_text = load_manual(manual_dir)
            evidence_dir = os.path.join(reports_dir, project_name, run_ts, _slug(spec.title))
            loaded.append((spec_path, group, spec, evidence_dir, None))
        except (SpecError, ManualError) as exc:
            title = os.path.splitext(os.path.basename(spec_path))[0]
            evidence_dir = os.path.join(reports_dir, project_name, run_ts, _slug(title))
            loaded.append((spec_path, group, None, evidence_dir, f"spec load failed: {exc}"))

    # 2. One Targets + one Computer for the whole tree; client log goes to the run dir.
    targets = targets_factory(config)
    run_dir = os.path.join(reports_dir, project_name, run_ts)
    _run_started_at = datetime.utcnow().isoformat()
    if getattr(targets, "log_dir", None) is None:
        os.makedirs(run_dir, exist_ok=True)
        targets.log_dir = run_dir
    computer = computer_factory(config)

    # Write initial status.json FIRST so the live monitor can connect
    # immediately and get_running_run never sees run.json without status.json.
    os.makedirs(run_dir, exist_ok=True)
    _write_status(
        run_dir,
        state='running',
        current_spec=loaded[0][2].title if loaded and loaded[0][2] else None,
        current_spec_index=0,
        current_evidence_dir=os.path.basename(loaded[0][3]) if loaded else None,
        specs_total=len(loaded),
        specs_completed=[],
        started_at=_run_started_at,
    )
    # Write provisional run.json after status.json so the index never sees
    # run.json without a corresponding status.json (which would make
    # get_running_run return null for an actively-starting run).
    _prov_path = os.path.join(run_dir, "run.json")
    import json as _json
    with open(_prov_path, "w", encoding="utf-8") as _pf:
        _json.dump({
            "project": project_name,
            "run_ts":  run_ts,
            "model_id": settings.bedrock_model_id,
            "total":   0,
            "passed":  0,
            "failed":  0,
            "errored": 0,
            "spec_total": len(loaded),
            "duration_seconds": 0.0,
            "state": "running",
        }, _pf, indent=2)
    results: list[TestResult] = []
    digest: list[DigestEntry] = []
    handle = None
    session_error: str | None = None

    try:
        # NRDP-1: nested desktop-RDP chain projects take their own path. The single-target
        # code below is untouched and never imports chain_hooks.
        if getattr(config.target, "type", None) == "rdp-chain":
            from .chain_hooks import run_chain_project
            chain_results = run_chain_project(
                project=project, loaded=loaded, reports_dir=reports_dir, run_ts=run_ts,
                targets=targets, computer=computer, client_factory=client_factory,
                drive_agent=_drive_agent, trigger_id=os.environ.get("ORCHESTRATOR_TRIGGER_ID"))
            for chain_result in chain_results:
                if chain_result.evidence_dir:
                    os.makedirs(chain_result.evidence_dir, exist_ok=True)
                    _write_result_json(chain_result.evidence_dir, chain_result)
                    render_spec_report(chain_result, model_id=settings.bedrock_model_id)
            results.extend(chain_results)
            if any(r.status in (TestStatus.ERRORED, TestStatus.TIMEOUT) for r in chain_results):
                logging.getLogger(__name__).warning("nested remote desktop chain did not complete")
                # Keep the reason: the run state must say "error", not a clean "complete".
                session_error = "nested remote desktop chain did not complete (see the connection chain section of the report)"
            return results, session_error

        # VNC procedures created by the dashboard (single VNC desktop, run modes, checkpoints, session-end policy).
        # Any other VNC project, and every other target type, takes the unchanged single-target path below.
        if getattr(config.target, "type", None) == "vnc" and (getattr(config, "procedure", None) or {}).get("protocol") == "vnc":
            from .vnc_hooks import run_vnc_project
            vnc_results = run_vnc_project(
                project=project, loaded=loaded, reports_dir=reports_dir, run_ts=run_ts,
                targets=targets, computer=computer, client_factory=client_factory,
                drive_agent=_drive_agent, trigger_id=os.environ.get("ORCHESTRATOR_TRIGGER_ID"))
            for vnc_result in vnc_results:
                if vnc_result.evidence_dir:
                    os.makedirs(vnc_result.evidence_dir, exist_ok=True)
                    _write_result_json(vnc_result.evidence_dir, vnc_result)
                    render_spec_report(vnc_result, model_id=settings.bedrock_model_id)
            results.extend(vnc_results)
            if any(r.status in (TestStatus.ERRORED, TestStatus.TIMEOUT) for r in vnc_results):
                session_error = "VNC session did not complete (see the connection section of the report)"
            return results, session_error

        # 3. Open the shared target once, from the project's configured target.
        target_spec = TargetSpec(config.target.type, dict(config.target.params))
        try:
            handle = targets.open_target(target_spec)
        except TargetError as exc:
            session_error = f"shared session target setup failed: {exc}"

        # 4. Run each spec in order, accumulating the digest.
        for spec_path, group, spec, evidence_dir, load_error in loaded:
            os.makedirs(evidence_dir, exist_ok=True)

            if load_error is not None:
                result = TestResult(
                    title=os.path.splitext(os.path.basename(spec_path))[0],
                    target_type="",
                    status=TestStatus.ERRORED,
                    error=load_error,
                )
            elif session_error is not None:
                result = TestResult(
                    title=spec.title,
                    target_type=spec.target_type,
                    status=TestStatus.ERRORED,
                    declared_assertions=len(spec.assertions),
                    error=session_error,
                )
            else:
                if handle is not None:
                    targets.focus(handle.window_name)
                result = _drive_agent(
                    spec,
                    config=config,
                    evidence_dir=evidence_dir,
                    computer=computer,
                    client=client_factory(),
                    prior_context=_render_digest(digest),
                    manual_dir=manual_dir,
                )
                digest.append(
                    DigestEntry(
                        title=spec.title,
                        status=result.status,
                        summary=result.summary,
                        ending_state=result.ending_state,
                    )
                )

            result.spec_path = spec_path
            result.evidence_dir = evidence_dir
            _write_result_json(evidence_dir, result)
            render_spec_report(result, model_id=settings.bedrock_model_id)
            results.append(result)
            # ── status.json: spec complete, advance to next spec ─────────
            _next_idx = len(results)
            _next_spec = loaded[_next_idx][2].title if _next_idx < len(loaded) and loaded[_next_idx][2] else None
            _next_evdir = os.path.basename(loaded[_next_idx][3]) if _next_idx < len(loaded) else None
            _write_status(
                run_dir,
                state='running',
                current_spec=_next_spec,
                current_spec_index=_next_idx,
                current_evidence_dir=_next_evdir,
                specs_total=len(loaded),
                specs_completed=[
                    {
                        'title': r.title,
                        'status': r.status.value,
                        'evidence_dir': os.path.basename(r.evidence_dir or ''),
                    }
                    for r in results
                ],
                started_at=_run_started_at,
            )
            # Update provisional run.json with latest counts after each spec.
            import time as _time
            _elapsed = round(_time.time() - _time.mktime(
                __import__('datetime').datetime.fromisoformat(_run_started_at).timetuple()
            ), 1)
            _json_write(_prov_path, {
                "project": project_name,
                "run_ts":  run_ts,
                "model_id": settings.bedrock_model_id,
                "total":   sum(1 for r in results for _ in r.per_assertion) if results and hasattr(results[0], 'per_assertion') else len(results),
                "passed":  sum(1 for r in results if r.status.value == 'passed'),
                "failed":  sum(1 for r in results if r.status.value == 'failed'),
                "errored": sum(1 for r in results if r.status.value == 'errored'),
                "spec_total": len(loaded),
                "duration_seconds": _elapsed,
                "state": "running",
            })
    finally:
        # ── status.json: run complete or error ──────────────────────────
        _write_status(
            run_dir,
            state='error' if session_error else 'complete',
            specs_total=len(loaded),
            specs_completed=[
                {
                    'title': r.title,
                    'status': r.status.value,
                    'evidence_dir': os.path.basename(r.evidence_dir or ''),
                }
                for r in results
            ],
            started_at=_run_started_at,
        )
        # 5. Close the shared target once (only if it actually opened).
        if handle is not None:
            targets.close_target(handle)

    return results, _render_session_summary(digest)


def _render_single(result: TestResult) -> str | None:
    """Render the HTML report tree for a single-spec run.

    ``run_spec`` writes only ``result.json`` + screenshots; the CLI single-spec path wraps
    its one result in a :class:`RunResult` so the same :func:`render_all` used by project
    runs also produces ``report.html`` and refreshes both indexes. Returns the run report
    path, or ``None`` if the evidence dir layout is unexpected.
    """
    if not result.evidence_dir:
        return None
    run_dir = os.path.dirname(result.evidence_dir)
    project_dir = os.path.dirname(run_dir)
    reports_dir = os.path.dirname(project_dir)
    project_name = os.path.basename(project_dir)
    run_ts = os.path.basename(run_dir)
    if not project_name or not run_ts:
        return None
    run = RunResult(
        project=project_name,
        run_ts=run_ts,
        results=[result],
        report_dir=run_dir,
    )
    return render_all(run, model_id=settings.bedrock_model_id, reports_dir=reports_dir)


def _effective_from_settings() -> EffectiveConfig:
    """Fallback effective config when a spec has no discoverable project."""
    return EffectiveConfig(
        max_steps=settings.max_steps,
        max_seconds=settings.max_seconds,
        max_tokens=settings.max_tokens,
        max_total_tokens=settings.max_total_tokens,
        step_max_tokens=settings.step_max_tokens,
        keep_last_n_screenshots=settings.keep_last_n_screenshots,
        action_delay_seconds=settings.action_delay_seconds,
        max_planner_steps=settings.max_planner_steps,
        step_max_steps=settings.step_max_steps,
        ssh_host_allowlist=list(settings.ssh_host_allowlist),
        rdp_host_allowlist=list(settings.rdp_host_allowlist),
        target=Target(type="local-app"),
        schedule=settings.default_cron,
    )


def _write_result_json(evidence_dir: str, result: TestResult) -> None:
    path = os.path.join(evidence_dir, "result.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(result.model_dump_json(indent=2))


def _configure_logging() -> None:
    """Surface orchestrator logs on the CLI. ``ORCHESTRATOR_LOG_LEVEL=DEBUG`` reveals the
    per-step planner context-size debug lines (`orchestrator.agent`)."""
    level_name = os.environ.get("ORCHESTRATOR_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("orchestrator")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    parser = argparse.ArgumentParser(
        prog="python -m orchestrator.runner",
        description="Run a single spec or a whole project of plain-English tests.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("spec", nargs="?", help="Path to a single .md spec to run.")
    group.add_argument("--project", help="Name of a project to run (all its specs).")
    args = parser.parse_args(argv)

    if args.project:
        run = run_project(args.project, allow_disabled=True)
        print(
            f"[runner] project={run.project} run_ts={run.run_ts} "
            f"total={run.total} passed={run.passed_count} failed={run.failed_count} "
            f"errored={run.errored_count}"
        )
        for r in run.results:
            print(f"  - {r.title}: {r.status.value} ({r.evidence_dir})")
        return 0 if run.errored_count == 0 else 1

    result = run_spec(args.spec)
    report_path = _render_single(result)
    print(f"[runner] {result.title}: {result.status.value} ({result.evidence_dir})")
    if report_path:
        print(f"[runner] report: {report_path}")
    if result.error:
        print(f"[runner] error: {result.error}", file=sys.stderr)
    return 0 if result.status != TestStatus.ERRORED else 1


if __name__ == "__main__":
    raise SystemExit(main())
