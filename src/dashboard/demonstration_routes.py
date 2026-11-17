"""Authenticated, owner-scoped Watch & Learn API routes."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response

from .auth import Actor, verify_operator
from .authoring import (
    AuthoringValidationError,
    content_revision,
    validate_spec_for_apply,
)
from .demonstration_models import (
    AnnotationRequest,
    CaptureActionRequest,
    CaptureActionResponse,
    ConnectDemonstrationRequest,
    CreateDemonstrationRequest,
    DeleteDemonstrationRequest,
    DeletionStatus,
    DemonstrationCapabilities,
    DemonstrationSession,
    DemonstrationSummary,
    ModelEnrichmentRequest,
    ModelJob,
    PrivateDraftUpdateRequest,
    PrivateLearnedDraft,
    PromoteRequest,
    PromotionPreview,
    PromotionResult,
    RedactEvidenceRequest,
    VersionedRequest,
)
from .demonstrations import (
    DemonstrationError,
    DemonstrationService,
    VersionConflict,
    owner_principal,
)
from .editor_routes import _authoring_project
from .target_probe import TargetProbeResult
from watch_learn_privacy import (
    redaction_configuration_revision,
    validate_redaction_posture,
)


router = APIRouter(prefix="/demonstrations", tags=["watch-learn"])


def _service(request: Request) -> DemonstrationService:
    return request.app.state.demonstration_service


def _error(exc: DemonstrationError) -> HTTPException:
    detail: dict[str, object] = {"code": exc.code, "message": exc.message}
    if isinstance(exc, VersionConflict):
        detail["current_version"] = exc.current
    return HTTPException(status_code=exc.status_code, detail=detail)


def _project_context(request: Request, name: str, actor: Actor):
    dir_name, project_dir, _yaml_path, raw, parsed = _authoring_project(name)
    base_project = parsed.document
    project_revision = content_revision(raw)
    readiness = getattr(request.app.state, "watch_learn_readiness_service", None)
    imported_project = bool(readiness and readiness.is_imported_project(Path(project_dir)))
    base_target_revision = request.app.state.target_probe_service.target_revision(base_project)
    record = None
    project = base_project
    if readiness is not None:
        project, record = readiness.effective_project(
            actor, base_project, project_revision=project_revision,
            base_target_revision=base_target_revision, imported_project=imported_project,
        )
    target_revision = request.app.state.target_probe_service.target_revision(project)
    privacy_revision = redaction_configuration_revision(project.redaction)
    try:
        validate_redaction_posture(
            project.redaction, expected_revision=privacy_revision
        )
        privacy_ready = True
        privacy_notice = (
            "Server-derived fixed-region redaction is active and revision-bound; "
            "the worker must apply it before returning any frame."
        )
    except ValueError:
        privacy_ready = False
        privacy_notice = (
            "Connect is unavailable until the stored project has a valid, active "
            "fixed-region redaction configuration."
        )
    return (
        dir_name,
        project,
        project_revision,
        target_revision,
        privacy_revision,
        privacy_ready,
        privacy_notice,
        imported_project,
        record,
    )


def _capture_preflight_satisfies(
    result: TargetProbeResult | None, *, target_revision: str, target_type: str
) -> bool:
    """Require exact launch gates; session proof occurs only after Connect."""
    if result is None or result.revision != target_revision or result.target_type != target_type:
        return False
    checks = {item.stage: item.status for item in result.checks}
    allowed_auth = {"unsupported"} if target_type == "local-app" else {"unsupported", "passed"}
    return (
        target_type in {"local-app", "vnc"}
        and checks.get("static-policy") == "passed"
        and checks.get("client-runtime") == "passed"
        and checks.get("transport") in ({"passed"} if target_type == "vnc" else {"not-run"})
        and checks.get("authentication-session") in allowed_auth
        and "failed" not in checks.values()
    )


def _session_proof_window(project) -> str | None:
    value = getattr(project.target, "watch_learn_ready_window", None)
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > 240
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        return None
    return value.strip()


@router.get("/capabilities", response_model=DemonstrationCapabilities)
def capabilities(
    request: Request,
    project_name: str = Query(min_length=1, max_length=120),
    actor: Actor = Depends(verify_operator),
):
    """Read local metadata only; this route never calls an adapter or target."""
    (
        dir_name,
        project,
        project_revision,
        target_revision,
        privacy_revision,
        privacy_ready,
        privacy_notice,
        imported_project,
        readiness_record,
    ) = _project_context(request, project_name, actor)
    current_probe = request.app.state.target_probe_service.current_result(project)
    readiness = getattr(request.app.state, "watch_learn_readiness_service", None)
    readiness_active = not imported_project or bool(
        readiness and readiness.activation_active(readiness_record, target_revision)
    )
    connect_authorized = _capture_preflight_satisfies(
        current_probe, target_revision=target_revision, target_type=project.target.type
    ) and privacy_ready and readiness_active
    result = _service(request).capabilities(
        actor,
        dir_name,
        project_revision,
        target_revision,
        privacy_revision,
        project.target.type,
        privacy_ready,
        privacy_notice,
        connect_authorized=connect_authorized,
        preflight_expires_at=(
            current_probe.expires_at
            if connect_authorized and current_probe is not None
            else None
        ),
        session_proof_configured=_session_proof_window(project) is not None,
    )
    return result.model_copy(update={
        "imported_project": imported_project,
        "readiness_configuration_required": imported_project and readiness_record is None,
        "readiness_check_passed": bool(
            readiness and readiness.readiness_check_active(readiness_record, target_revision)
        ),
        "target_contact_activated": imported_project and readiness_active,
        "readiness_configuration_revision": readiness_record.configuration_revision if readiness_record else None,
    })


@router.post("", status_code=201, response_model=DemonstrationSession)
def create_demonstration(
    body: CreateDemonstrationRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    (
        dir_name,
        project,
        project_revision,
        target_revision,
        privacy_revision,
        _privacy_ready,
        _privacy_notice,
        imported_project,
        readiness_record,
    ) = _project_context(request, body.project_name, actor)
    if (
        body.project_revision != project_revision
        or body.target_revision != target_revision
        or body.privacy_revision != privacy_revision
        or body.readiness_configuration_revision != (
            readiness_record.configuration_revision if readiness_record else None
        )
        or dir_name != project.dir_name
    ):
        raise HTTPException(status_code=409, detail={
            "code": "revision_conflict",
            "message": "Project or target changed after capability metadata was loaded.",
            "project_revision": project_revision,
            "target_revision": target_revision,
        })
    try:
        return _service(request).create(
            actor,
            project=project,
            project_revision=project_revision,
            target_revision=target_revision,
            privacy_revision=privacy_revision,
            operator_goal=body.operator_goal,
            readiness_configuration_revision=(
                readiness_record.configuration_revision if readiness_record else None
            ),
            frame_contract_width=(
                readiness_record.configuration.frame_width
                if imported_project and readiness_record else None
            ),
            frame_contract_height=(
                readiness_record.configuration.frame_height
                if imported_project and readiness_record else None
            ),
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.get("", response_model=list[DemonstrationSummary])
def list_demonstrations(request: Request, actor: Actor = Depends(verify_operator)):
    try:
        return _service(request).list(actor)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.get("/{session_id}", response_model=DemonstrationSession)
def get_demonstration(
    session_id: str, request: Request, actor: Actor = Depends(verify_operator)
):
    try:
        return _service(request).get(actor, session_id)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/connect", response_model=DemonstrationSession)
def connect_demonstration(
    session_id: str,
    body: ConnectDemonstrationRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        session = _service(request).get(actor, session_id)
        (
            _dir_name,
            project,
            project_revision,
            target_revision,
            privacy_revision,
            privacy_ready,
            _privacy_notice,
            imported_project,
            readiness_record,
        ) = _project_context(request, session.project_name, actor)
        current_probe = request.app.state.target_probe_service.current_result(project)
        readiness = getattr(request.app.state, "watch_learn_readiness_service", None)
        readiness_active = not imported_project or bool(
            readiness and readiness.activation_active(readiness_record, target_revision)
        )
        if _session_proof_window(project) is None:
            raise DemonstrationError(
                "session_proof_configuration_required",
                "Configure target.watch_learn_ready_window before Connect.",
            )
        return _service(request).connect(
            actor,
            session_id,
            expected_version=body.expected_version,
            request_project_revision=body.project_revision,
            request_target_revision=body.target_revision,
            request_privacy_revision=body.privacy_revision,
            project=project,
            project_revision=project_revision,
            target_revision=target_revision,
            privacy_revision=privacy_revision,
            privacy_ready=privacy_ready,
            preflight_revision=current_probe.revision if current_probe else None,
            preflight_satisfies=_capture_preflight_satisfies(
                current_probe,
                target_revision=target_revision,
                target_type=project.target.type,
            ) and readiness_active,
            readiness_configuration_revision=(
                readiness_record.configuration_revision if readiness_record else None
            ),
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/session/confirm", response_model=DemonstrationSession)
def confirm_session(
    session_id: str,
    body: VersionedRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        session = _service(request).get(actor, session_id)
        (
            _dir_name,
            project,
            project_revision,
            target_revision,
            _privacy_revision,
            _privacy_ready,
            _privacy_notice,
            _imported_project,
            _readiness_record,
        ) = _project_context(request, session.project_name, actor)
        ready_window = _session_proof_window(project)
        if ready_window is None:
            raise DemonstrationError(
                "session_proof_configuration_required",
                "Configure target.watch_learn_ready_window before proving the session.",
            )
        return _service(request).confirm_session(
            actor,
            session_id,
            expected_version=body.expected_version,
            ready_window=ready_window,
            project_revision=project_revision,
            target_revision=target_revision,
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


def _transition(
    request: Request,
    actor: Actor,
    session_id: str,
    body: VersionedRequest,
    method: str,
):
    try:
        return getattr(_service(request), method)(actor, session_id, body.expected_version)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/capture/start", response_model=DemonstrationSession)
def start_capture(session_id: str, body: VersionedRequest, request: Request, actor: Actor = Depends(verify_operator)):
    return _transition(request, actor, session_id, body, "start")


@router.post("/{session_id}/capture/pause", response_model=DemonstrationSession)
def pause_capture(session_id: str, body: VersionedRequest, request: Request, actor: Actor = Depends(verify_operator)):
    return _transition(request, actor, session_id, body, "pause")


@router.post("/{session_id}/capture/resume", response_model=DemonstrationSession)
def resume_capture(session_id: str, body: VersionedRequest, request: Request, actor: Actor = Depends(verify_operator)):
    return _transition(request, actor, session_id, body, "resume")


@router.post("/{session_id}/capture/stop", response_model=DemonstrationSession)
def stop_capture(session_id: str, body: VersionedRequest, request: Request, actor: Actor = Depends(verify_operator)):
    return _transition(request, actor, session_id, body, "stop")


@router.post("/{session_id}/actions", response_model=CaptureActionResponse)
def capture_action(
    session_id: str,
    body: CaptureActionRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        session, receipt = _service(request).capture_action(
            actor,
            session_id,
            expected_version=body.expected_version,
            idempotency_key=body.idempotency_key,
            action=body.action,
        )
        return CaptureActionResponse(session=session, receipt=receipt)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/annotations", response_model=DemonstrationSession)
def annotate(
    session_id: str,
    body: AnnotationRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).annotate(
            actor,
            session_id,
            expected_version=body.expected_version,
            event_id=body.event_id,
            note=body.note,
            control_label=body.control_label,
            expected_result=body.expected_result,
            variable_name=body.variable_name,
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.get("/{session_id}/evidence/{evidence_id}")
def evidence(
    session_id: str,
    evidence_id: str,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        data = _service(request).read_evidence(actor, session_id, evidence_id)
        return Response(
            content=data,
            media_type="image/png",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/evidence/{evidence_id}/redact", response_model=DemonstrationSession)
def redact_evidence(
    session_id: str,
    evidence_id: str,
    body: RedactEvidenceRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).redact(
            actor,
            session_id,
            evidence_id,
            expected_version=body.expected_version,
            regions=body.regions,
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/analyses/deterministic", response_model=DemonstrationSession)
def deterministic_analysis(
    session_id: str,
    body: VersionedRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).deterministic_analysis(
            actor, session_id, expected_version=body.expected_version
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/analyses/model", status_code=202, response_model=ModelJob)
def model_enrichment(
    session_id: str,
    body: ModelEnrichmentRequest,
    request: Request,
    background: BackgroundTasks,
    actor: Actor = Depends(verify_operator),
):
    try:
        service = _service(request)
        job = service.queue_model_enrichment(
            actor,
            session_id,
            expected_version=body.expected_version,
            deterministic_analysis_id=body.deterministic_analysis_id,
            include_visual_evidence=body.include_visual_evidence,
        )
        background.add_task(
            service.run_model_job, owner_principal(actor), session_id, job.job_id
        )
        return job
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.get("/{session_id}/analysis-jobs/{job_id}", response_model=ModelJob)
def model_job(
    session_id: str,
    job_id: str,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).get_model_job(actor, session_id, job_id)
    except DemonstrationError as exc:
        raise _error(exc) from exc


def _promotion(
    session_id: str,
    body: PromoteRequest,
    request: Request,
    actor: Actor,
):
    try:
        preview, document = _service(request).promotion_preview(
            actor,
            session_id,
            expected_version=body.expected_version,
            analysis_id=body.analysis_id,
            spec_path=body.spec_path,
        )
        _rendered, diagnostics = validate_spec_for_apply(document)
        preview = preview.model_copy(update={
            "valid": not any(item.severity == "error" for item in diagnostics),
            "diagnostics": [item.message for item in diagnostics],
        })
        return preview, document
    except AuthoringValidationError as exc:
        raise HTTPException(status_code=422, detail={
            "code": "promotion_validation_failed",
            "diagnostics": [item.model_dump() for item in exc.diagnostics],
        }) from exc
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.post("/{session_id}/promotion/validate", response_model=PromotionPreview)
def validate_promotion(
    session_id: str,
    body: PromoteRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    preview, _document = _promotion(session_id, body, request, actor)
    return preview


@router.post("/{session_id}/promote", status_code=201, response_model=PromotionResult)
def promote(
    session_id: str,
    body: PromoteRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    preview, document = _promotion(session_id, body, request, actor)
    if not preview.valid:
        raise HTTPException(status_code=422, detail={
            "code": "promotion_validation_failed",
            "message": "Learned draft did not pass local authoring validation.",
            "diagnostics": preview.diagnostics,
        })
    try:
        session, draft = _service(request).commit_private_promotion(
            actor,
            session_id,
            expected_version=body.expected_version,
            analysis_id=body.analysis_id,
            spec_path=document.path,
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc
    return PromotionResult(session=session, draft=draft)


@router.get(
    "/{session_id}/private-drafts/{draft_id}",
    response_model=PrivateLearnedDraft,
)
def get_private_draft(
    session_id: str,
    draft_id: str,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).get_private_draft(actor, session_id, draft_id)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.put(
    "/{session_id}/private-drafts/{draft_id}",
    response_model=PromotionResult,
)
def update_private_draft(
    session_id: str,
    draft_id: str,
    body: PrivateDraftUpdateRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        session, draft = _service(request).update_private_draft(
            actor,
            session_id,
            draft_id,
            expected_version=body.expected_version,
            expected_draft_version=body.expected_draft_version,
            content=body.content,
        )
        return PromotionResult(session=session, draft=draft)
    except DemonstrationError as exc:
        raise _error(exc) from exc


@router.get("/{session_id}/private-drafts/{draft_id}/export")
def export_private_draft(
    session_id: str,
    draft_id: str,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        draft, rendered = _service(request).export_private_draft(
            actor, session_id, draft_id
        )
    except DemonstrationError as exc:
        raise _error(exc) from exc
    return Response(
        content=rendered.encode("utf-8"),
        media_type="text/markdown",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="private-{draft.draft_id}.md"',
            "X-Watch-Learn-Authority": "none",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/{session_id}", status_code=204)
def delete_demonstration(
    session_id: str,
    body: DeleteDemonstrationRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        _service(request).delete(actor, session_id, expected_version=body.expected_version)
    except DemonstrationError as exc:
        raise _error(exc) from exc
    return Response(status_code=204)


@router.get("/{session_id}/deletion-status", response_model=DeletionStatus)
def deletion_status(
    session_id: str,
    request: Request,
    actor: Actor = Depends(verify_operator),
):
    try:
        return _service(request).deletion_status(actor, session_id)
    except DemonstrationError as exc:
        raise _error(exc) from exc
