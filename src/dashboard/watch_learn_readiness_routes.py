"""Operator-only imported-project Watch & Learn readiness routes."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import Actor, verify_operator
from .authoring import content_revision
from .editor_routes import _authoring_project
from .target_probe import (
    TargetProbeBusyError,
    TargetProbeRequest,
    TargetProbeResult,
    TargetProbeValidationError,
)
from .watch_learn_readiness import (
    ReadinessActivateRequest,
    ReadinessError,
    ReadinessInspection,
    ReadinessPreviewRequest,
    ReadinessRevisionRequest,
    ReadinessSaveRequest,
    ReadinessTargetPreflightRequest,
    WatchLearnReadinessService,
)


router = APIRouter(prefix="/watch-learn/readiness", tags=["watch-learn-readiness"])


def _service(request: Request) -> WatchLearnReadinessService:
    return request.app.state.watch_learn_readiness_service


def _error(exc: ReadinessError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


def _context(request: Request, project_name: str):
    dir_name, project_dir, _yaml_path, raw, parsed = _authoring_project(project_name)
    project = parsed.document
    project_revision = content_revision(raw)
    base_target_revision = request.app.state.target_probe_service.target_revision(project)
    imported = _service(request).is_imported_project(Path(project_dir))
    return dir_name, Path(project_dir), project, project_revision, base_target_revision, imported


def _inspection(request: Request, actor: Actor, project_name: str) -> ReadinessInspection:
    _name, project_dir, project, project_revision, target_revision, imported = _context(request, project_name)
    return _service(request).inspect(
        actor, project, project_dir=project_dir, project_revision=project_revision,
        base_target_revision=target_revision,
        probe_service=request.app.state.target_probe_service,
        adapters=request.app.state.demonstration_service.adapters,
        imported_project=imported,
    )


@router.get("/{project_name}", response_model=ReadinessInspection)
def inspect_readiness(
    project_name: str, request: Request, actor: Actor = Depends(verify_operator),
) -> ReadinessInspection:
    try:
        return _inspection(request, actor, project_name)
    except ReadinessError as exc:
        raise _error(exc) from exc


@router.post("/{project_name}/preview", response_model=ReadinessInspection)
@router.post("/{project_name}/validate", response_model=ReadinessInspection)
def preview_readiness(
    project_name: str, body: ReadinessPreviewRequest, request: Request,
    actor: Actor = Depends(verify_operator),
) -> ReadinessInspection:
    try:
        _name, project_dir, project, project_revision, target_revision, imported = _context(request, project_name)
        return _service(request).preview(
            actor, project, project_revision=project_revision,
            base_target_revision=target_revision, imported_project=imported, body=body,
            probe_service=request.app.state.target_probe_service,
            adapters=request.app.state.demonstration_service.adapters,
            project_dir=project_dir,
        )
    except ReadinessError as exc:
        raise _error(exc) from exc


@router.put("/{project_name}/configuration", response_model=ReadinessInspection)
def save_readiness(
    project_name: str, body: ReadinessSaveRequest, request: Request,
    actor: Actor = Depends(verify_operator),
) -> ReadinessInspection:
    try:
        _name, _project_dir, project, project_revision, target_revision, imported = _context(request, project_name)
        _service(request).save(
            actor, project, project_revision=project_revision,
            base_target_revision=target_revision, imported_project=imported, body=body,
        )
        return _inspection(request, actor, project_name)
    except ReadinessError as exc:
        raise _error(exc) from exc


@router.post("/{project_name}/check", response_model=ReadinessInspection)
def check_readiness(
    project_name: str, body: ReadinessRevisionRequest, request: Request,
    actor: Actor = Depends(verify_operator),
) -> ReadinessInspection:
    try:
        _name, _project_dir, project, project_revision, target_revision, _imported = _context(request, project_name)
        _service(request).check(
            actor, project, project_revision=project_revision,
            base_target_revision=target_revision, body=body,
            probe_service=request.app.state.target_probe_service,
            adapters=request.app.state.demonstration_service.adapters,
        )
        return _inspection(request, actor, project_name)
    except ReadinessError as exc:
        raise _error(exc) from exc


@router.post("/{project_name}/activate", response_model=ReadinessInspection)
def activate_target_contact(
    project_name: str, body: ReadinessActivateRequest, request: Request,
    actor: Actor = Depends(verify_operator),
) -> ReadinessInspection:
    try:
        _name, _project_dir, project, project_revision, target_revision, _imported = _context(request, project_name)
        _service(request).activate(
            actor, project, project_revision=project_revision,
            base_target_revision=target_revision, body=body,
            probe_service=request.app.state.target_probe_service,
        )
        return _inspection(request, actor, project_name)
    except ReadinessError as exc:
        raise _error(exc) from exc


@router.post("/{project_name}/target-preflight", response_model=TargetProbeResult)
def run_activated_target_preflight(
    project_name: str, body: ReadinessTargetPreflightRequest, request: Request,
    actor: Actor = Depends(verify_operator),
) -> TargetProbeResult:
    """The only onboarding route that may contact a target; activation is checked first."""
    try:
        _name, _project_dir, project, project_revision, target_revision, _imported = _context(request, project_name)
        effective, _record = _service(request).require_activation(
            actor, project, project_revision=project_revision,
            base_target_revision=target_revision, body=body,
            probe_service=request.app.state.target_probe_service,
        )
        return request.app.state.target_probe_service.run(TargetProbeRequest(project=effective))
    except ReadinessError as exc:
        raise _error(exc) from exc
    except TargetProbeBusyError as exc:
        raise HTTPException(status_code=409, detail={"code": "target_probe_busy", "message": str(exc)}) from exc
    except TargetProbeValidationError as exc:
        raise HTTPException(status_code=422, detail={"code": "target_probe_invalid", "message": str(exc)}) from exc
