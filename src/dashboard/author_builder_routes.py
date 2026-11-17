"""Explicit command endpoints for the owner-scoped Author Builder."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .auth import Actor, verify_operator
from .author_builder import (
    ActionLedgerEvent,
    AuthorBuilderError,
    AuthorBuilderService,
    CandidateApplyRequest,
    CandidateCreateRequest,
    CandidatePlan,
    CandidateRecord,
    CandidateValidationReport,
    CandidateValidationRequest,
    HistoryCapsule,
    HistoryDeleteRequest,
    HistoryPreviewRequest,
    HistoryRetentionRequest,
    HostKeyCandidate,
    HostKeyDiscoverRequest,
    HostKeyDiscoveryService,
    HostKeyEligibility,
    HostKeyEligibilityRequest,
    HostKeySaveRequest,
    HostKeySaveResponse,
    IntentCreateRequest,
    IntentUpdateRequest,
    ModelRefineRequest,
    PlanCreateRequest,
    ProjectInventory,
    StructuredIntent,
)


router = APIRouter(prefix="/authoring/builder", tags=["author-builder"])


def _builder(request: Request) -> AuthorBuilderService:
    service = getattr(request.app.state, "author_builder_service", None)
    if not isinstance(service, AuthorBuilderService):
        raise HTTPException(status_code=503, detail={"code": "builder_unavailable", "message": "Author Builder is unavailable."})
    return service


def _host_keys(request: Request) -> HostKeyDiscoveryService:
    service = getattr(request.app.state, "host_key_discovery_service", None)
    if not isinstance(service, HostKeyDiscoveryService):
        raise HTTPException(status_code=503, detail={"code": "host_key_discovery_unavailable", "message": "Host-key discovery is unavailable."})
    return service


def _error(exc: AuthorBuilderError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message})


@router.get("/projects/{project}/inventory", response_model=ProjectInventory)
def inventory(project: str, request: Request, actor: Actor = Depends(verify_operator)) -> ProjectInventory:
    """Metadata-only inspection; it cannot invoke models, tests, or targets."""
    try:
        return _builder(request).inventory(actor, project)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/intents", response_model=StructuredIntent, status_code=201)
def create_intent(project: str, body: IntentCreateRequest, request: Request, actor: Actor = Depends(verify_operator)) -> StructuredIntent:
    try:
        return _builder(request).create_intent(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.put("/projects/{project}/intents/{intent_id}", response_model=StructuredIntent)
def update_intent(project: str, intent_id: str, body: IntentUpdateRequest, request: Request, actor: Actor = Depends(verify_operator)) -> StructuredIntent:
    try:
        return _builder(request).update_intent(actor, project, intent_id, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/history/preview", response_model=HistoryCapsule)
def preview_history(project: str, body: HistoryPreviewRequest, request: Request, actor: Actor = Depends(verify_operator)) -> HistoryCapsule:
    try:
        return _builder(request).history_capsule(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.delete("/projects/{project}/history")
def delete_history(project: str, body: HistoryDeleteRequest, request: Request, actor: Actor = Depends(verify_operator)) -> dict:
    try:
        return _builder(request).delete_history(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.put("/projects/{project}/history/retention")
def set_history_retention(project: str, body: HistoryRetentionRequest, request: Request, actor: Actor = Depends(verify_operator)) -> dict:
    try:
        return _builder(request).set_history_retention(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/plans", response_model=CandidatePlan, status_code=201)
def create_plan(project: str, body: PlanCreateRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CandidatePlan:
    try:
        return _builder(request).create_plan(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/plans/refine", response_model=CandidatePlan)
def refine_plan(project: str, body: ModelRefineRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CandidatePlan:
    """The sole model boundary; an explicit confirmation and current plan are required."""
    try:
        return _builder(request).refine_plan(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/candidates", response_model=CandidateRecord, status_code=201)
def create_candidate(project: str, body: CandidateCreateRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CandidateRecord:
    try:
        return _builder(request).create_candidate(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post(
    "/projects/{project}/candidates/{candidate_id}/validation",
    response_model=CandidateValidationReport,
)
def validate_candidate(
    project: str,
    candidate_id: str,
    body: CandidateValidationRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
) -> CandidateValidationReport:
    """Run only the selected static, in-process validation; never execute a project or target."""
    try:
        return _builder(request).validate_candidate(actor, project, candidate_id, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/candidates/{candidate_id}/apply", response_model=CandidateRecord)
def apply_candidate(project: str, candidate_id: str, body: CandidateApplyRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CandidateRecord:
    try:
        return _builder(request).apply_candidate(actor, project, candidate_id, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.get("/projects/{project}/actions", response_model=list[ActionLedgerEvent])
def actions(project: str, request: Request, limit: int = Query(default=200, ge=1, le=500), actor: Actor = Depends(verify_operator)) -> list[ActionLedgerEvent]:
    try:
        return _builder(request).actions(actor, project, limit=limit)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/host-key/eligibility", response_model=HostKeyEligibility)
def host_key_eligibility(project: str, body: HostKeyEligibilityRequest, request: Request, actor: Actor = Depends(verify_operator)) -> HostKeyEligibility:
    try:
        return _host_keys(request).eligibility(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/host-key/discover", response_model=HostKeyCandidate)
def discover_host_key(project: str, body: HostKeyDiscoverRequest, request: Request, actor: Actor = Depends(verify_operator)) -> HostKeyCandidate:
    try:
        return _host_keys(request).discover(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc


@router.post("/projects/{project}/host-key/save", response_model=HostKeySaveResponse, status_code=201)
def save_host_key(project: str, body: HostKeySaveRequest, request: Request, actor: Actor = Depends(verify_operator)) -> HostKeySaveResponse:
    try:
        return _host_keys(request).save(actor, project, body)
    except AuthorBuilderError as exc:
        raise _error(exc) from exc
