"""Application sign-in, session, bootstrap, OIDC, and sign-out routes."""
from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from .auth import (
    Actor,
    OIDC_FLOW_COOKIE_NAME,
    SSE_COOKIE_NAME,
    SessionManager,
    bootstrap_actor,
    clear_session_cookie,
    set_session_cookie,
    verify_viewer,
)
from .config import settings
from .oidc import OidcDenied, OidcError, OidcProvider, OidcUnavailable


router = APIRouter(prefix="/api/v1")


class BootstrapLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential: str = Field(min_length=32, max_length=512)


def _manager(request: Request) -> SessionManager:
    manager = getattr(request.app.state, "session_manager", None)
    if not all(callable(getattr(manager, name, None)) for name in ("create", "get", "revoke")):
        raise HTTPException(status_code=503, detail={
            "code": "authentication_unavailable",
            "message": "Sign in is temporarily unavailable.",
        })
    return manager


def _provider(request: Request) -> OidcProvider:
    provider = getattr(request.app.state, "oidc_provider", None)
    if not all(
        callable(getattr(provider, name, None))
        for name in ("authorization_request", "complete", "reject_response")
    ):
        raise OidcUnavailable("Organization sign in is unavailable")
    return provider


def _session_body(record) -> dict[str, object]:
    return {
        "authenticated": True,
        "role": record.actor.role,
        "display_name": record.actor.display_name,
        "auth_method": record.actor.auth_method,
        "csrf_token": record.csrf_token,
        "expires_at": record.expires_at,
    }


@router.get("/auth/config")
def auth_config() -> dict[str, object]:
    return {
        "organization_sign_in": settings.oidc_configured,
        "organization_sign_in_url": "/api/v1/auth/oidc/start" if settings.oidc_configured else None,
        "provider_label": settings.oidc_provider_label,
        "test_only": settings.oidc_test_only,
        "local_bootstrap_available": bool(settings.auth_token),
        "roles": {
            "viewer": "Inspect projects, live display, reports, screenshots, and logs.",
            "operator": "Create, edit, refine, preflight, and control approved project work.",
        },
    }


@router.post("/auth/bootstrap/session")
def bootstrap_session(body: BootstrapLogin, request: Request) -> JSONResponse:
    actor = bootstrap_actor(body.credential)
    if actor is None:
        raise HTTPException(status_code=401, detail={
            "code": "bootstrap_denied",
            "message": "The local bootstrap credential was not accepted.",
        })
    session_actor = Actor(
        subject=actor.subject,
        role=actor.role,
        auth_method="bootstrap-session",
        display_name=actor.display_name,
    )
    record = _manager(request).create(session_actor)
    request.state.actor = record.actor
    response = JSONResponse(_session_body(record))
    set_session_cookie(response, record, secure=settings.secure_cookies)
    return response


@router.get("/auth/session")
def current_session(
    request: Request,
    actor: Annotated[Actor, Depends(verify_viewer)],
) -> dict[str, object]:
    record = _manager(request).get(actor.session_id)
    return {
        "authenticated": True,
        "role": actor.role,
        "display_name": actor.display_name,
        "auth_method": actor.auth_method,
        "csrf_token": record.csrf_token if record else None,
        "expires_at": record.expires_at if record else None,
    }


@router.post("/auth/logout")
def logout(
    request: Request,
    actor: Annotated[Actor, Depends(verify_viewer)],
) -> JSONResponse:
    _manager(request).revoke(actor.session_id)
    response = JSONResponse({"status": "signed-out"})
    clear_session_cookie(response)
    return response


@router.post("/auth/sse-session")
def create_sse_session(
    request: Request,
    actor: Annotated[Actor, Depends(verify_viewer)],
) -> JSONResponse:
    """Create an opaque scoped session for EventSource; never cookie a token."""
    record = _manager(request).create(Actor(
        subject=actor.subject,
        role=actor.role,
        auth_method="sse-session",
        display_name=actor.display_name,
    ))
    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        key=SSE_COOKIE_NAME,
        value=record.actor.session_id or "",
        max_age=max(1, int(record.expires_at - time.time())),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/api/v1/runs",
    )
    return response


@router.get("/auth/oidc/start")
def oidc_start(request: Request) -> RedirectResponse:
    try:
        flow, destination = _provider(request).authorization_request()
    except OidcError:
        return RedirectResponse("/sign-in?state=sso-unavailable", status_code=303)
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        key=OIDC_FLOW_COOKIE_NAME,
        value=flow.flow_id,
        max_age=600,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/api/v1/auth/oidc/callback",
    )
    return response


@router.get("/auth/oidc/callback")
def oidc_callback(
    request: Request,
    code: str | None = Query(default=None, max_length=4096),
    state: str | None = Query(default=None, max_length=512),
    iss: str | None = Query(default=None, max_length=2048),
    error: str | None = Query(default=None, max_length=128),
) -> RedirectResponse:
    destination = "/sign-in?state=denied"
    actor: Actor | None = None
    try:
        if error is None:
            actor = _provider(request).complete(
                flow_id=request.cookies.get(OIDC_FLOW_COOKIE_NAME),
                state=state,
                code=code,
                response_issuer=iss,
            )
        else:
            _provider(request).reject_response(
                flow_id=request.cookies.get(OIDC_FLOW_COOKIE_NAME),
                state=state,
                response_issuer=iss,
            )
    except Exception as exc:
        # Dashboard modules are reloaded by the development server and legacy
        # tests. Match the provider's narrow public error code so an in-flight
        # provider instance from the prior module generation remains safe.
        error_code = getattr(exc, "code", None)
        if error_code == OidcUnavailable.code:
            destination = "/sign-in?state=sso-unavailable"
        elif error_code == OidcDenied.code:
            destination = "/sign-in?state=denied"
        else:
            raise
    response = RedirectResponse("/" if actor else destination, status_code=303)
    request.state.audit_outcome = "allowed" if actor else "denied"
    response.delete_cookie(OIDC_FLOW_COOKIE_NAME, path="/api/v1/auth/oidc/callback")
    if actor is not None:
        record = _manager(request).create(actor)
        request.state.actor = record.actor
        set_session_cookie(response, record, secure=settings.secure_cookies)
    return response
