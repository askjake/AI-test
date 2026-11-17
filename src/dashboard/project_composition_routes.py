"""Explicit preview/create routes for multi-root project composition."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import Actor, verify_operator
from .author_builder import AuthorBuilderError
from .project_composition import (
    CompositionCreateRequest,
    CompositionCreateResponse,
    CompositionPreview,
    CompositionPreviewRequest,
    ProjectCompositionService,
)
from .project_import import ProjectImportError


router = APIRouter(prefix="/authoring/project-composition", tags=["project-composition"])


def _service(request: Request) -> ProjectCompositionService:
    service = getattr(request.app.state, "project_composition_service", None)
    if not isinstance(service, ProjectCompositionService):
        raise HTTPException(status_code=503, detail={"code": "composition_unavailable", "message": "Project composition is unavailable."})
    return service


def _error(exc: ProjectImportError | AuthorBuilderError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message})


@router.post("/preview", response_model=CompositionPreview)
def preview(body: CompositionPreviewRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CompositionPreview:
    try:
        return _service(request).preview(body, actor)
    except (ProjectImportError, AuthorBuilderError) as exc:
        raise _error(exc) from exc


@router.post("/create", response_model=CompositionCreateResponse, status_code=201)
def create(body: CompositionCreateRequest, request: Request, actor: Actor = Depends(verify_operator)) -> CompositionCreateResponse:
    try:
        return _service(request).create(body, actor)
    except (ProjectImportError, AuthorBuilderError) as exc:
        raise _error(exc) from exc
