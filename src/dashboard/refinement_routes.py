"""Operator-only Phase 13D HTTP contract.

Browser requests provide intent only.  This router resolves every project,
specification, revision, guidance document, and safe context source on the
server before a job can exist.
"""
from __future__ import annotations

import os
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .authoring import AuthoringValidationError, SpecDocument, content_revision, parse_spec_document, validate_spec_for_apply
from .auth import verify_operator
from .editor_routes import _authoring_project, _collect_specs, _safe_spec_path
from .refinement import ContextPreview, GuidanceCatalog, RefinementError, RefinementJob, RefinementProposal, RefinementService


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RefinementIntent(_StrictModel):
    mode: Literal["this", "selected", "all"]
    paths: list[str] = Field(default_factory=list, max_length=30)
    include_manual: bool = True
    include_siblings: bool = True
    full_sibling_paths: list[str] = Field(default_factory=list, max_length=30)
    guidance_ids: list[str] = Field(default_factory=list, max_length=20)


class CreateRefinementJob(RefinementIntent):
    fingerprint: str = Field(min_length=64, max_length=64)
    confirm_all: bool = False


class ContextResponse(_StrictModel):
    configured: bool
    disabled_reason: str | None = None
    preview: ContextPreview


router = APIRouter()


def _service(request: Request) -> RefinementService:
    service = getattr(request.app.state, "refinement_service", None)
    if not isinstance(service, RefinementService):
        raise HTTPException(status_code=503, detail="Refinement service is unavailable.")
    return service


def _error(exc: RefinementError) -> HTTPException:
    return HTTPException(status_code=400, detail={"code": "refinement_request", "message": str(exc)})


def _resolved_context(name: str, intent: RefinementIntent, service: RefinementService):
    _dir_name, project_dir, _yaml_path, _raw, parsed = _authoring_project(name)
    all_paths = _collect_specs(project_dir)

    def read_spec(path: str) -> tuple[SpecDocument, str]:
        full = _safe_spec_path(project_dir, path)
        # _safe_spec_path protects traversal; retain a separate no-symlink
        # boundary before source content enters the safe-context transformer.
        lexical = os.path.join(project_dir, path.lstrip("/"))
        if os.path.islink(lexical) or not os.path.isfile(full):
            raise RefinementError("Specification source is unavailable or unsafe.")
        stat = os.stat(full, follow_symlinks=False)
        if stat.st_size > service.settings.authoring_max_source_chars:
            raise RefinementError("Specification source exceeds the safe context limit.")
        raw = open(full, encoding="utf-8").read()
        try:
            document = parse_spec_document(raw, path=path)
            validate_spec_for_apply(document)
        except AuthoringValidationError as exc:
            raise RefinementError("Specification fails normal typed validation.") from exc
        return document, content_revision(raw)

    preview, plans = service.preview(
        project_name=name,
        project=parsed.document,
        project_dir=project_dir,
        requested_paths=intent.paths,
        mode=intent.mode,
        include_manual=intent.include_manual,
        include_siblings=intent.include_siblings,
        full_sibling_paths=intent.full_sibling_paths,
        guidance_ids=intent.guidance_ids,
        read_spec=read_spec,
        all_paths=all_paths,
    )
    return preview, plans, read_spec


@router.post("/projects/{name}/authoring/refinements/context-preview", response_model=ContextResponse)
def context_preview(name: str, intent: RefinementIntent, request: Request, _u=Depends(verify_operator)):
    service = _service(request)
    try:
        preview, _plans, _read_spec = _resolved_context(name, intent, service)
    except RefinementError as exc:
        raise _error(exc) from exc
    return ContextResponse(configured=service.configured, disabled_reason=service.disabled_reason, preview=preview)


@router.get("/projects/{name}/authoring/refinements/guidance", response_model=GuidanceCatalog)
def guidance_catalog(name: str, request: Request, _u=Depends(verify_operator)):
    # Resolve the project first so guidance is not an unauthorised global data
    # channel for arbitrary viewer/browser input.
    _authoring_project(name)
    return _service(request).guidance_catalog()


@router.post("/projects/{name}/authoring/refinements/jobs", response_model=RefinementJob, status_code=202)
def create_job(name: str, body: CreateRefinementJob, request: Request, background: BackgroundTasks, _u=Depends(verify_operator)):
    service = _service(request)
    if body.mode == "all" and not body.confirm_all:
        raise HTTPException(status_code=400, detail={"code": "all_confirmation_required", "message": "Enhance all requires explicit confirmation."})
    intent = RefinementIntent.model_validate(body.model_dump(exclude={"fingerprint", "confirm_all"}))
    try:
        preview, plans, _read_spec = _resolved_context(name, intent, service)
        if preview.fingerprint != body.fingerprint:
            raise RefinementError("Context changed; inspect the rebuilt context before creating a job.")
        job = service.create_job(project_name=name, mode=body.mode, preview=preview, plans=plans)
    except RefinementError as exc:
        raise _error(exc) from exc
    background.add_task(service.drain)
    return job


@router.get("/projects/{name}/authoring/refinements/jobs/{job_id}", response_model=RefinementJob)
def job_status(name: str, job_id: str, request: Request, _u=Depends(verify_operator)):
    service = _service(request)
    try:
        job = service.get_job(job_id)
    except RefinementError as exc:
        raise HTTPException(status_code=404, detail="Refinement job was not found.") from exc
    if job.project_name != name:
        raise HTTPException(status_code=404, detail="Refinement job was not found.")
    return job


@router.post("/projects/{name}/authoring/refinements/jobs/{job_id}/cancel", response_model=RefinementJob)
def cancel_job(name: str, job_id: str, request: Request, _u=Depends(verify_operator)):
    service = _service(request)
    try:
        job = service.get_job(job_id)
        if job.project_name != name:
            raise RefinementError("Refinement job was not found.")
        return service.cancel(job_id)
    except RefinementError as exc:
        raise HTTPException(status_code=404, detail="Refinement job was not found.") from exc


@router.post("/projects/{name}/authoring/refinements/proposals/{proposal_id}/accept", response_model=RefinementProposal)
def accept_proposal(name: str, proposal_id: str, request: Request, _u=Depends(verify_operator)):
    service = _service(request)
    # Build the reader from current server-side project data.  A proposal can
    # only be locally accepted when its exact source revision still exists.
    try:
        existing = service.get_proposal(proposal_id)
        if service.get_job(existing.job_id).project_name != name:
            raise RefinementError("Refinement proposal was not found.")
    except RefinementError as exc:
        raise HTTPException(status_code=404, detail="Refinement proposal was not found.") from exc
    _dir_name, project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    def read_current(path: str) -> tuple[SpecDocument, str]:
        full = _safe_spec_path(project_dir, path)
        if os.path.islink(os.path.join(project_dir, path.lstrip("/"))) or not os.path.isfile(full):
            raise RefinementError("Current specification is unavailable or unsafe.")
        raw = open(full, encoding="utf-8").read()
        try:
            document = parse_spec_document(raw, path=path)
            validate_spec_for_apply(document)
        except AuthoringValidationError as exc:
            raise RefinementError("Current specification fails typed validation.") from exc
        return document, content_revision(raw)
    try:
        proposal = service.accept(proposal_id=proposal_id, read_current=read_current)
    except RefinementError as exc:
        raise _error(exc) from exc
    return proposal


@router.post("/projects/{name}/authoring/refinements/proposals/{proposal_id}/reject", response_model=RefinementProposal)
def reject_proposal(name: str, proposal_id: str, request: Request, _u=Depends(verify_operator)):
    service = _service(request)
    try:
        existing = service.get_proposal(proposal_id)
        if service.get_job(existing.job_id).project_name != name:
            raise RefinementError("Refinement proposal was not found.")
        proposal = service.reject(proposal_id)
        return proposal
    except RefinementError as exc:
        raise HTTPException(status_code=404, detail="Refinement proposal was not found.") from exc


@router.get("/projects/{name}/authoring/refinements/audit")
def refinement_audit(name: str, request: Request, limit: int = 100, _u=Depends(verify_operator)):
    _authoring_project(name)
    service = _service(request)
    return [item for item in service.audit(limit=limit) if item.job_id is None or service.get_job(item.job_id).project_name == name]
