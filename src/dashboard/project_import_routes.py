"""Typed operator-only routes for project-folder import."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import Actor, verify_operator
from .authoring import AuthoringValidationError
from .project_import import (
    ProjectImportApplyRequest,
    ProjectImportApplyResponse,
    ProjectImportBrowseRequest,
    ProjectImportBrowseResponse,
    ProjectImportDiscoverRequest,
    ProjectImportDiscoverResponse,
    ProjectImportCapabilities,
    ProjectImportError,
    ProjectImportPreviewRequest,
    ProjectImportPreviewResponse,
    ProjectImportRootSummary,
    ProjectImportService,
)


router = APIRouter(prefix="/authoring/project-import", tags=["project-import"])


def _service(request: Request) -> ProjectImportService:
    return request.app.state.project_import_service


def _http_error(exc: ProjectImportError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


@router.get("/capabilities", response_model=ProjectImportCapabilities)
def capabilities(
    request: Request,
    _actor: Actor = Depends(verify_operator),
) -> ProjectImportCapabilities:
    return _service(request).capabilities()


@router.get("/roots", response_model=list[ProjectImportRootSummary])
def roots(
    request: Request,
    _actor: Actor = Depends(verify_operator),
) -> list[ProjectImportRootSummary]:
    return _service(request).root_summaries()


@router.post("/browse", response_model=ProjectImportBrowseResponse)
def browse(
    body: ProjectImportBrowseRequest,
    request: Request,
    _actor: Actor = Depends(verify_operator),
) -> ProjectImportBrowseResponse:
    try:
        return _service(request).browse(body)
    except ProjectImportError as exc:
        raise _http_error(exc) from exc


@router.post("/discover", response_model=ProjectImportDiscoverResponse)
def discover(
    body: ProjectImportDiscoverRequest,
    request: Request,
    _actor: Actor = Depends(verify_operator),
) -> ProjectImportDiscoverResponse:
    try:
        return _service(request).discover(body)
    except ProjectImportError as exc:
        raise _http_error(exc) from exc


@router.post("/preview", response_model=ProjectImportPreviewResponse)
def preview(
    body: ProjectImportPreviewRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
) -> ProjectImportPreviewResponse:
    try:
        return _service(request).preview(body, actor)
    except ProjectImportError as exc:
        raise _http_error(exc) from exc


@router.post("/apply", response_model=ProjectImportApplyResponse)
def apply(
    body: ProjectImportApplyRequest,
    request: Request,
    actor: Actor = Depends(verify_operator),
) -> ProjectImportApplyResponse:
    try:
        return _service(request).apply(body, actor)
    except ProjectImportError as exc:
        raise _http_error(exc) from exc
    except AuthoringValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "staged_validation_failed",
                "message": "The staged project failed existing authoring validation.",
                "diagnostics": [item.model_dump() for item in exc.diagnostics],
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "project_import_failed",
                "message": "The project import failed without publishing a project.",
            },
        ) from exc
