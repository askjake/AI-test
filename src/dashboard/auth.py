"""Server-derived dashboard actors, opaque sessions, and CSRF enforcement."""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import os
import secrets
import threading
import time
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


Role = Literal["viewer", "operator"]
SESSION_COOKIE_NAME = "orchestrator_cookie_session"
SSE_COOKIE_NAME = "dashboard_sse_token"
OIDC_FLOW_COOKIE_NAME = "orchestrator_cookie_oidc_flow"
CSRF_HEADER_NAME = "X-CSRF-Token"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Actor:
    subject: str
    role: Role
    auth_method: str
    display_name: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class SessionRecord:
    actor: Actor
    csrf_token: str
    expires_at: float


class SessionManager:
    """Bounded in-memory opaque sessions; credentials never enter cookies."""

    def __init__(self, ttl_seconds: int = 28_800, *, maximum: int = 2048) -> None:
        self.ttl_seconds = ttl_seconds
        self.maximum = maximum
        self._records: dict[str, SessionRecord] = {}
        self._lock = threading.RLock()

    def _prune(self, now: float) -> None:
        for session_id, record in list(self._records.items()):
            if record.expires_at <= now:
                self._records.pop(session_id, None)
        if len(self._records) >= self.maximum:
            oldest = sorted(self._records, key=lambda key: self._records[key].expires_at)
            for session_id in oldest[: max(1, len(self._records) - self.maximum + 1)]:
                self._records.pop(session_id, None)

    def create(self, actor: Actor) -> SessionRecord:
        now = time.time()
        session_id = secrets.token_urlsafe(32)
        stored_actor = Actor(
            subject=actor.subject,
            role=actor.role,
            auth_method=actor.auth_method,
            display_name=actor.display_name,
            session_id=session_id,
        )
        record = SessionRecord(
            actor=stored_actor,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._prune(now)
            self._records[session_id] = record
        return record

    def get(self, session_id: str | None) -> SessionRecord | None:
        if not session_id:
            return None
        now = time.time()
        with self._lock:
            record = self._records.get(session_id)
            if record is None:
                return None
            if record.expires_at <= now:
                self._records.pop(session_id, None)
                return None
            return record

    def revoke(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._records.pop(session_id, None)


def _session_manager(value: object) -> SessionManager | None:
    if all(callable(getattr(value, name, None)) for name in ("create", "get", "revoke")):
        return value  # type: ignore[return-value]
    return None


def bootstrap_actor(token: str | None) -> Actor | None:
    """Map a clone-local token to a role using constant-time comparisons."""
    from .config import settings

    if not token:
        return None
    operator = settings.effective_operator_token
    viewer = settings.auth_token
    if operator and hmac.compare_digest(token, operator):
        return Actor(
            subject="local-bootstrap-operator",
            role="operator",
            auth_method="bootstrap-bearer",
            display_name="Local operator",
        )
    if viewer and hmac.compare_digest(token, viewer):
        return Actor(
            subject="local-bootstrap-viewer",
            role="viewer",
            auth_method="bootstrap-bearer",
            display_name="Local viewer",
        )
    return None


def shared_operator_enabled() -> bool:
    return os.environ.get("DASHBOARD_SHARED_OPERATOR_MODE") == "true"


def is_shared_operator(actor: Actor) -> bool:
    return (shared_operator_enabled() and actor.role == "operator"
            and actor.auth_method == "shared-operator"
            and actor.subject == "shared-private-operator")


def authenticate_optional(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = None,
    *,
    include_sse: bool = False,
) -> tuple[Actor, SessionRecord | None] | None:
    """Resolve bearer compatibility or an opaque server-side session."""
    from .config import settings

    bearer = bootstrap_actor(credentials.credentials if credentials else None)
    if bearer is not None:
        request.state.actor = bearer
        return bearer, None

    if shared_operator_enabled():
        actor = Actor("shared-private-operator", "operator", "shared-operator", "Shared operator (no login)")
        request.state.actor = actor
        return actor, None

    manager = _session_manager(getattr(request.app.state, "session_manager", None))
    if manager is not None:
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        record = manager.get(session_id)
        if record is None and include_sse:
            session_id = request.cookies.get(SSE_COOKIE_NAME)
            record = manager.get(session_id)
        if record is not None:
            request.state.actor = record.actor
            return record.actor, record

    # Preserve the historical loopback-only unauthenticated development mode.
    # Managed installations always provide clone-local tokens.
    if settings.auth_token is None:
        actor = Actor("anonymous-loopback", "viewer", "anonymous", "Local viewer")
        request.state.actor = actor
        return actor, None
    return None


def _unauthenticated(request: Request) -> HTTPException:
    had_cookie = bool(
        request.cookies.get(SESSION_COOKIE_NAME) or request.cookies.get(SSE_COOKIE_NAME)
    )
    return HTTPException(
        status_code=401,
        detail={
            "code": "session_expired" if had_cookie else "unauthenticated",
            "message": "Your session expired. Sign in again." if had_cookie else "Sign in is required.",
            "sign_in_url": "/sign-in",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def _enforce_csrf(request: Request, record: SessionRecord | None) -> None:
    if record is None or request.method.upper() in _SAFE_METHODS:
        return
    supplied = request.headers.get(CSRF_HEADER_NAME, "")
    if not supplied or not hmac.compare_digest(supplied, record.csrf_token):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "csrf_required",
                "message": "This action could not be verified. Refresh and try again.",
            },
        )


def verify_viewer(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Actor:
    resolved = authenticate_optional(request, credentials)
    if resolved is None:
        raise _unauthenticated(request)
    actor, record = resolved
    _enforce_csrf(request, record)
    return actor


def verify_operator(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Actor:
    resolved = authenticate_optional(request, credentials)
    if resolved is None:
        raise _unauthenticated(request)
    actor, record = resolved
    _enforce_csrf(request, record)
    if actor.role != "operator":
        raise HTTPException(
            status_code=403,
            detail={
                "code": "operator_required",
                "message": "Operator access is required for this action.",
                "sign_in_url": "/sign-in?state=operator-required",
            },
        )
    return actor


def verify_viewer_sse(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Actor:
    resolved = authenticate_optional(request, credentials, include_sse=True)
    if resolved is None:
        raise _unauthenticated(request)
    return resolved[0]


def set_session_cookie(response: Response, record: SessionRecord, *, secure: bool) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=record.actor.session_id or "",
        max_age=max(1, int(record.expires_at - time.time())),
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(SSE_COOKIE_NAME, path="/api/v1/runs")
