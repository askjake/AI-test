"""Operator-only Phase 14 Project Builder Wizard routes."""
from __future__ import annotations

import hashlib
import os

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from pydantic import ValidationError

from .auth import verify_operator
from .authoring import (
    AuthoringDiagnostic,
    AuthoringValidationError,
    TypedProjectCreateRequest,
    content_revision,
    validate_spec_for_apply,
)
from .editor_routes import _authoring_error, _authoring_project, _prepare_typed_project_create
from .wizard import (
    BlueprintCatalog,
    BlueprintImportPreview,
    BlueprintImportRequest,
    ProjectMap,
    ProjectWizardService,
    ReadinessResult,
    VerificationCapabilities,
    VerificationHandoff,
    VerificationHandoffRequest,
    WizardAssessmentRequest,
    WizardAuditEvent,
    WizardContextPreview,
    WizardContextRequest,
    WizardPlanCreateRequest,
    WizardPlanJob,
    WizardPlanProposal,
    WizardProposalDecision,
    WizardValidatedSpecification,
    WizardValidationRequest,
    WizardValidationResult,
    assess_readiness,
    project_map,
    verification_capabilities,
    verification_handoff,
)
from .target_setup import (
    KnownHostsSaveRequest,
    KnownHostsSaveResponse,
    PasswordSaveRequest,
    PasswordSaveResponse,
    SecretAlreadyExistsError,
    TargetOptions,
    TargetSetupError,
    TargetSetupService,
)
from .target_probe import (
    TargetProbeAuditEvent,
    TargetProbeBusyError,
    TargetProbeRequest,
    TargetProbeResult,
    TargetProbeService,
    TargetProbeValidationError,
)


from .builder_policy import BuilderValidationRoute, review_diagnostics, review_revision, trust_diagnostics

from .wizard_visual import router as visual_router

router = APIRouter(route_class=BuilderValidationRoute)
router.include_router(visual_router)


def _service(request: Request) -> ProjectWizardService:
    service = getattr(request.app.state, "project_wizard_service", None)
    if not isinstance(service, ProjectWizardService):
        raise HTTPException(status_code=503, detail="Project Builder Wizard is unavailable.")
    return service


def _target_service(request: Request) -> TargetSetupService:
    service = getattr(request.app.state, "target_setup_service", None)
    if not isinstance(service, TargetSetupService):
        raise HTTPException(status_code=503, detail="Target setup helpers are unavailable.")
    return service


def _probe_service(request: Request, *, required: bool = True) -> TargetProbeService | None:
    service = getattr(request.app.state, "target_probe_service", None)
    if isinstance(service, TargetProbeService):
        return service
    if required:
        raise HTTPException(status_code=503, detail="Target preflight is unavailable.")
    return None


def _safe_error(exc: ValueError, *, status: int = 422) -> HTTPException:
    message = str(exc)
    allowed = {
        "Blueprint is not approved and eligible.",
        "Blueprint fields must be unique.",
        "Blueprint selections must be unique.",
        "Guidance selections must be unique.",
        "Safe context exceeds the configured context limit.",
        "Project-plan drafting is disabled or missing explicit authoring configuration.",
        "Project-plan queue is full; wait for queued work to finish.",
        "Context preview is stale; inspect the exact current context again.",
        "Project-plan job was not found.",
        "Project-plan proposal was not found.",
        "Proposal sections must be unique.",
        "Only a ready proposal may be reviewed.",
        "Confirmation must exactly name the project.",
        "The existing runner does not support selected-spec triggers.",
    }
    detail = message if message in allowed else "Wizard request failed guarded validation."
    return HTTPException(status_code=status, detail=detail)


@router.get("/authoring/wizard/target-options", response_model=TargetOptions)
def target_options(request: Request, _u=Depends(verify_operator)):
    """Return operator-only known hosts and saved reference names, never values."""
    return _target_service(request).options()


@router.post("/authoring/wizard/passwords", response_model=PasswordSaveResponse)
def save_target_password(
    request: Request,
    body: object = Body(...),
    _u=Depends(verify_operator),
):
    """Persist one password without reflecting validation input or its host path."""
    try:
        parsed = PasswordSaveRequest.model_validate(body)
        response = _target_service(request).save_password(parsed)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Password request failed guarded validation.") from exc
    except SecretAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TargetSetupError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _service(request).record_password_save(
        kind=response.kind,
        reference_name=response.reference_name,
        status=response.status,
    )
    return response


@router.post("/authoring/wizard/known-hosts", response_model=KnownHostsSaveResponse)
def save_target_known_hosts(
    request: Request,
    body: object = Body(...),
    _u=Depends(verify_operator),
):
    """Persist reviewed OpenSSH host keys without returning their contents."""
    try:
        parsed = KnownHostsSaveRequest.model_validate(body)
        response = _target_service(request).save_known_hosts(parsed)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Known-hosts request failed guarded validation.") from exc
    except SecretAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TargetSetupError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _service(request).record_password_save(
        kind="known_hosts",
        reference_name=response.reference_name,
        status=response.status,
    )
    return response


@router.get("/authoring/wizard/blueprints", response_model=BlueprintCatalog)
def list_blueprints(
    request: Request,
    q: str = Query(default="", max_length=500),
    target_type: str | None = Query(default=None),
    verification_category: str | None = Query(default=None, max_length=80),
    tags: list[str] = Query(default=[]),
    _u=Depends(verify_operator),
):
    service = _service(request)
    if target_type not in {None, "local-app", "host-app", "ssh-terminal", "rdp", "vnc"}:
        raise HTTPException(status_code=422, detail="Unsupported target-type filter.")
    return service.catalog.catalog(
        query=q,
        target_type=target_type,  # type: ignore[arg-type]
        verification_category=verification_category,
        tags=tags,
    )


@router.post(
    "/authoring/wizard/blueprints/{blueprint_id}/preview",
    response_model=BlueprintImportPreview,
)
def preview_blueprint(
    blueprint_id: str,
    body: BlueprintImportRequest,
    request: Request,
    _u=Depends(verify_operator),
):
    try:
        return _service(request).catalog.preview_import(blueprint_id, body.fields)
    except ValueError as exc:
        raise _safe_error(exc) from exc


def _refuse_credentials_for_model(body) -> None:
    """Defence in depth: connection credentials are never forwarded to the planning model, whatever the browser did."""
    from .connection_intake import guard_texts
    draft = getattr(body, "draft", None)
    texts = [getattr(body, "intent", "") or "", getattr(draft, "display_name", "") or "", getattr(draft, "goal", "") or ""]
    texts += [str(x) for x in (getattr(draft, "manual_outline", None) or [])]
    for spec in getattr(draft, "specifications", None) or []:
        texts += [getattr(spec, "title", "") or "", getattr(spec, "goal", "") or "", getattr(spec, "setup", "") or ""] + [str(x) for x in (getattr(spec, "assertions", None) or [])]
    message = guard_texts(*texts)
    if message:
        raise HTTPException(status_code=422, detail={"message": message + " Nothing was sent to the model.", "field": "intent"})


@router.post("/authoring/wizard/context-preview", response_model=WizardContextPreview)
def preview_plan_context(
    body: WizardContextRequest,
    request: Request,
    _u=Depends(verify_operator),
):
    _refuse_credentials_for_model(body)
    try:
        preview, _prepared = _service(request).preview_context(body)
        return preview
    except ValueError as exc:
        raise _safe_error(exc) from exc


@router.post("/authoring/wizard/plan-jobs", status_code=202, response_model=WizardPlanJob)
def create_plan_job(
    body: WizardPlanCreateRequest,
    request: Request,
    background: BackgroundTasks,
    _u=Depends(verify_operator),
):
    _refuse_credentials_for_model(body)
    service = _service(request)
    try:
        job = service.create_job(body)
    except ValueError as exc:
        raise _safe_error(exc) from exc
    background.add_task(service.drain)
    return job


@router.get("/authoring/wizard/plan-jobs/{job_id}", response_model=WizardPlanJob)
def get_plan_job(job_id: str, request: Request, _u=Depends(verify_operator)):
    try:
        return _service(request).get_job(job_id)
    except ValueError as exc:
        raise _safe_error(exc, status=404) from exc


@router.post(
    "/authoring/wizard/proposals/{proposal_id}/accept",
    response_model=WizardPlanProposal,
)
def accept_plan_sections(
    proposal_id: str,
    body: WizardProposalDecision,
    request: Request,
    _u=Depends(verify_operator),
):
    try:
        return _service(request).decide(
            proposal_id=proposal_id,
            sections=body.sections,
            current_draft=body.current_draft,
            accept=True,
        )
    except ValueError as exc:
        raise _safe_error(exc, status=409 if "ready" in str(exc).lower() else 404) from exc


@router.post(
    "/authoring/wizard/proposals/{proposal_id}/reject",
    response_model=WizardPlanProposal,
)
def reject_plan_sections(
    proposal_id: str,
    body: WizardProposalDecision,
    request: Request,
    _u=Depends(verify_operator),
):
    try:
        return _service(request).decide(
            proposal_id=proposal_id,
            sections=body.sections,
            current_draft=body.current_draft,
            accept=False,
        )
    except ValueError as exc:
        raise _safe_error(exc, status=409 if "ready" in str(exc).lower() else 404) from exc


@router.post("/authoring/wizard/readiness", response_model=ReadinessResult)
def readiness(body: WizardAssessmentRequest, request: Request, _u=Depends(verify_operator)):
    service = _probe_service(request, required=False)
    probe = service.current_result(body.project) if service else None
    return assess_readiness(body, probe)


@router.post('/authoring/wizard/review')
def review_plan(body: WizardAssessmentRequest, _u=Depends(verify_operator)):
    """Confirm answered plan semantics only; no credential or target activity."""
    diagnostics = review_diagnostics(body.project, body.specifications, body.manual_outline,
                                    body.goal, body.builder_review, confirmation=False)
    errors = [item for item in diagnostics if item["severity"] == "error"]
    if errors:
        raise _authoring_error(AuthoringValidationError([AuthoringDiagnostic(**item) for item in errors]))
    return {'reviewed_revision': review_revision(body.project, body.specifications,
                                                body.manual_outline, body.goal, body.builder_review)}


@router.post("/authoring/wizard/validate", response_model=WizardValidationResult)
def validate_wizard_project(
    body: WizardValidationRequest,
    request: Request,
    _u=Depends(verify_operator),
):
    """Validate every exact planned document and collision without writing."""
    diagnostics: list[AuthoringDiagnostic] = []
    if body.builder_review is not None or body.project.target.type in {'rdp', 'vnc'}:
        diagnostics.extend(AuthoringDiagnostic(**item) for item in review_diagnostics(
            body.project, body.specifications, body.manual_outline, body.goal, body.builder_review))
    if body.builder_review is not None:
        diagnostics.extend(AuthoringDiagnostic(**item) for item in trust_diagnostics(body.project, body.trust_review))
    if body.builder_review is not None and body.project.enabled:
        diagnostics.append(AuthoringDiagnostic(code='new_project_disabled',
            message='Create this project disabled. Scheduling is a separate decision after verification.', field='enabled'))
    lint_project = body.project
    if not lint_project.manual_dir:
        lint_project = lint_project.model_copy(update={'manual_dir': 'managed-by-server'})
    from .authoring import lint_project_document
    _, typed_diagnostics = lint_project_document(lint_project, require_manual_on_disk=False,
                                                require_schedule=True, new_project=True)
    diagnostics.extend(item for item in typed_diagnostics if item.severity == 'error')
    if not body.specifications:
        diagnostics.append(AuthoringDiagnostic(
            code="specifications_missing",
            message="Add at least one typed specification.",
            field="specifications",
        ))
    outline = [item.strip() for item in body.manual_outline if item.strip()]
    if not outline:
        diagnostics.append(AuthoringDiagnostic(
            code="manual_outline_missing",
            message="Add a bounded operating-manual outline before creation.",
            field="manual_outline",
        ))
    manual = (body.manual_template or "").strip()
    if not manual:
        diagnostics.append(AuthoringDiagnostic(
            code="manual_template_missing",
            message="The managed manual template must be generated from the reviewed outline.",
            field="manual_outline",
        ))
    elif not manual.startswith("# ") or any(
        f"## {heading}" not in manual for heading in outline
    ) or any(ord(char) < 32 and char not in "\n\t" for char in manual) or 'Add reviewed operating guidance' in manual:
        diagnostics.append(AuthoringDiagnostic(
            code="manual_template_invalid",
            message="The managed manual template must contain a title and every reviewed outline heading.",
            field="manual_outline",
        ))
    diagnostics = [item for item in diagnostics if item.severity == "error"]
    if diagnostics:
        raise _authoring_error(AuthoringValidationError(diagnostics))
    service = _probe_service(request)
    assert service is not None
    try:
        target_checks = service.static_checks(body.project)
    except TargetProbeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    secret_check = next(item for item in target_checks if item.stage == "secret-reference")
    if secret_check.status == "failed":
        secret_fields = service.invalid_secret_fields(body.project)
        raise HTTPException(status_code=422, detail={
            "diagnostics": [{
                "code": "secret_reference_unavailable",
                "message": secret_check.detail,
                "field": secret_fields[0] if secret_fields else "target.secret_reference",
                "severity": "error",
            }],
        })

    first = body.specifications[0]
    create = TypedProjectCreateRequest(
        document=body.project,
        initial_spec=first,
        manual_template=manual,
        additional_specs=body.specifications[1:],
        builder_review=body.builder_review,
        builder_goal=body.goal,
        manual_outline=body.manual_outline,
        trust_review=body.trust_review,
    )
    (
        _root,
        project_dir,
        _manual_root,
        manual_dir,
        document,
        yaml_content,
        first_content,
        project_diagnostics,
    ) = _prepare_typed_project_create(create)
    if os.path.exists(project_dir):
        raise HTTPException(status_code=409, detail={
            "diagnostics": [{
                "code": "project_exists",
                "message": "A project directory already exists with this slug.",
                "field": "dir_name",
                "severity": "error",
            }],
        })
    if os.path.exists(manual_dir):
        raise HTTPException(status_code=409, detail={
            "diagnostics": [{
                "code": "manual_exists",
                "message": "A managed manual already exists for this project slug.",
                "field": "manual_outline",
                "severity": "error",
            }],
        })

    previews: list[WizardValidatedSpecification] = []
    seen: set[str] = set()
    for index, spec in enumerate(body.specifications):
        if spec.path in seen:
            diagnostics.append(AuthoringDiagnostic(
                code="spec_path_duplicate",
                message="Every planned specification path must be unique.",
                field=f"specifications[{index}].path",
            ))
            continue
        seen.add(spec.path)
        if spec.path == "project.yaml":
            diagnostics.append(AuthoringDiagnostic(
                code="spec_path",
                message="A specification path may not be project.yaml.",
                field=f"specifications[{index}].path",
            ))
            continue
        try:
            rendered, spec_diagnostics = (
                (first_content, []) if index == 0 else validate_spec_for_apply(spec)
            )
        except AuthoringValidationError as exc:
            diagnostics.extend(
                item.model_copy(update={
                    "field": f"specifications[{index}].{item.field or 'document'}"
                })
                for item in exc.diagnostics
            )
            continue
        diagnostics.extend(
            item.model_copy(update={
                "field": f"specifications[{index}].{item.field or 'document'}"
            })
            for item in spec_diagnostics
        )
        previews.append(WizardValidatedSpecification(
            document=spec,
            rendered_markdown=rendered,
            revision=content_revision(rendered),
        ))
    diagnostics = [item for item in diagnostics if item.severity == "error"]
    if diagnostics:
        raise _authoring_error(AuthoringValidationError(diagnostics))
    revision = hashlib.sha256(body.model_dump_json().encode("utf-8")).hexdigest()
    return WizardValidationResult(
        revision=revision,
        document=document,
        rendered_yaml=yaml_content,
        specifications=previews,
        manual_template=manual + "\n",
        diagnostics=project_diagnostics,
        target_checks=target_checks,
    )


@router.post("/authoring/wizard/target-probes", response_model=TargetProbeResult)
def run_target_probe(
    body: TargetProbeRequest,
    request: Request,
    _u=Depends(verify_operator),
):
    """Run one explicit, bounded preflight; never create, run, or launch."""
    try:
        service = _probe_service(request)
        assert service is not None
        return service.run(body)
    except TargetProbeBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TargetProbeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/authoring/wizard/target-probes/audit", response_model=list[TargetProbeAuditEvent])
def target_probe_audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    _u=Depends(verify_operator),
):
    service = _probe_service(request)
    assert service is not None
    return service.audit(limit)


@router.post("/authoring/wizard/project-map", response_model=ProjectMap)
def map_project(body: WizardAssessmentRequest, _u=Depends(verify_operator)):
    return project_map(body)


@router.get("/authoring/wizard/verification-capabilities", response_model=VerificationCapabilities)
def runner_capabilities(_u=Depends(verify_operator)):
    return verification_capabilities()


@router.post(
    "/projects/{name}/authoring/wizard/verification-handoff",
    response_model=VerificationHandoff,
)
def prepare_verification_handoff(
    name: str,
    body: VerificationHandoffRequest,
    request: Request,
    _u=Depends(verify_operator),
):
    # Resolve through the established typed project boundary.  This reads
    # project identity only; it does not trigger, probe, or launch anything.
    dir_name, _project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    try:
        response = verification_handoff(dir_name, body)
    except ValueError as exc:
        raise _safe_error(exc, status=409) from exc
    _service(request).record_handoff(project=dir_name, scope=body.scope)
    return response


@router.get("/authoring/wizard/audit", response_model=list[WizardAuditEvent])
def wizard_audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    _u=Depends(verify_operator),
):
    return _service(request).audit(limit)


@router.post('/authoring/wizard/procedures')
def intake_full_procedure(request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    """Extract ordered connection credentials locally and save a complete procedure draft."""
    from .procedure_intake import IntakeRequest, IntakeError, build_procedure, public_view
    try:
        parsed = IntakeRequest.model_validate(body)
        service = _target_service(request)
        draft = build_procedure(parsed.procedure.get_secret_value(), service, service.settings.wizard_state_root)
        return public_view(draft, service._secrets_root())
    except (ValidationError, IntakeError, TargetSetupError) as exc:
        message = str(exc) if isinstance(exc, IntakeError) else 'Procedure intake failed; no credential values are returned.'
        field = getattr(exc, 'field', 'procedure') if isinstance(exc, IntakeError) else 'procedure'
        raise HTTPException(status_code=422, detail=message if field == 'procedure' else {'message': message, 'field': field}) from None


@router.get('/authoring/wizard/procedures/{key}')
def read_full_procedure(key: str, request: Request, _u=Depends(verify_operator)):
    from .procedure_intake import IntakeError, load_procedure, public_view
    try:
        service = _target_service(request)
        return public_view(load_procedure(key, service.settings.wizard_state_root), service._secrets_root())
    except IntakeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None


@router.put('/authoring/wizard/procedures/{key}')
def update_full_procedure(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from .procedure_intake import IntakeError, ProcedureUpdateRequest, update_procedure, public_view
    try:
        parsed=ProcedureUpdateRequest.model_validate(body)
        service = _target_service(request)
        draft = update_procedure(key,parsed.instructions.get_secret_value(),service.settings.wizard_state_root)
        return public_view(draft, service._secrets_root())
    except (ValidationError, IntakeError) as exc:
        message=str(exc) if isinstance(exc,IntakeError) else 'The procedure update could not be read.'
        raise HTTPException(status_code=422,detail=message) from None


# Registered last so the v2 routes share this router (connections, certificate probe, project, runs).
from . import procedure_routes_v2  # noqa: E402,F401
from . import procedure_routes_vnc_ssh  # noqa: E402,F401
