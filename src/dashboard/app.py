"""FastAPI application factory for the Orchestrator Cookie dashboard (Phase 10).

The app:
  - Mounts reports/ as static files at /reports/ (existing HTML unchanged).
  - Registers the API router under /api/v1/.
  - Serves the dashboard SPA shell at / and /dashboard.
  - Starts/stops the background run-index scan task via lifespan events.
  - Refuses unauthenticated non-loopback configuration before serving.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse

from .audit_log import MutationAuditTrail, mutation_action
from .auth import SESSION_COOKIE_NAME, SessionManager, authenticate_optional, verify_operator, verify_viewer
from .auth_routes import router as auth_router
from .config import settings
from .switch_guard import require_resolved as _require_switch_resolved  # CP45-R
from .index import RunIndex
from .routes import router, set_index
from .editor_routes import router as editor_router
from .refinement import RefinementService
from .refinement_routes import router as refinement_router
from .wizard import ProjectWizardService
from .wizard_routes import router as wizard_router
from .target_setup import TargetSetupService
from .target_probe import TargetProbeService
from .oidc import OidcProvider
from .demonstrations import DemonstrationService
from .demonstration_routes import router as demonstration_router
from .project_import import ProjectImportService
from .project_import_routes import router as project_import_router
from .author_builder import AuthorBuilderService, HostKeyDiscoveryService
from .author_builder_routes import router as author_builder_router
from .project_composition import ProjectCompositionService
from .project_composition_routes import router as project_composition_router
from .watch_learn_readiness import WatchLearnReadinessService
from .watch_learn_readiness_routes import router as watch_learn_readiness_router

logger = logging.getLogger("dashboard.app")

_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "templates",
    "dashboard",
)
_DASHBOARD_HTML = os.path.join(_TEMPLATES_DIR, "index.html")
_SIGNIN_HTML = os.path.join(_TEMPLATES_DIR, "signin.html")
_WATCH_LEARN_HTML = os.path.join(_TEMPLATES_DIR, "watch_learn.html")
_WATCH_LEARN_LIFECYCLE_JS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "static",
    "watch_learn_lifecycle.js",
)
_WATCH_LEARN_FRAME_ANCESTORS_CSP = "frame-ancestors 'none'"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate config, seed the index, start background scan."""
    _require_switch_resolved(settings.reports_dir)   # CP45-R: re-check at serving time, before expire/recover/makedirs/index
    settings.require_safe_binding()

    # Persisted queued/drafting proposals are intentionally never retried after
    # a reloader/process boundary.  They remain reviewable as expired drafts.
    app.state.refinement_service.expire_unfinished()
    app.state.project_wizard_service.expire_unfinished()
    app.state.demonstration_service.recover()

    # Resolve reports_dir relative to cwd (uvicorn is run from the project root).
    reports_dir = os.path.abspath(settings.reports_dir)
    if not os.path.isdir(reports_dir):
        logger.warning("reports_dir %r does not exist — index will be empty.", reports_dir)
        os.makedirs(reports_dir, exist_ok=True)
    else:
        logger.info("reports_dir: %s", reports_dir)

    # Seed the in-memory index from existing reports.
    idx = RunIndex(
        reports_dir=reports_dir,
        specs_dir=os.path.abspath(settings.specs_dir),
        interval=settings.index_interval,
    )
    added = idx.scan_once()
    logger.info("index: loaded %d run(s) from %s", added, reports_dir)

    # Inject into routes.
    set_index(idx)

    # Start background periodic rescan.
    idx.start_background_scan()

    yield

    # Shutdown: cancel background task.
    idx.stop()


def create_app() -> FastAPI:
    _require_switch_resolved(settings.reports_dir)   # CP45-R: before any service object (and its state directories) is built
    settings.require_safe_binding()
    app = FastAPI(
        title="Orchestrator Cookie Dashboard",
        description="Role-aware dashboard for the Orchestrator Cookie agent.",
        version="1.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # API routes.
    # The service only records safe private state at construction.  It does not
    # import boto3 or construct any model client until an explicit queued job.
    app.state.refinement_service = RefinementService(settings)
    app.state.project_wizard_service = ProjectWizardService(settings)
    app.state.target_setup_service = TargetSetupService(settings)
    app.state.target_probe_service = TargetProbeService(settings)
    app.state.author_builder_service = AuthorBuilderService(settings)
    app.state.demonstration_service = DemonstrationService(settings)
    app.state.watch_learn_readiness_service = WatchLearnReadinessService(settings)
    app.state.project_import_service = ProjectImportService(
        settings,
        on_publish=lambda actor, project, revision: app.state.author_builder_service.claim_created_project_if_eligible(
            actor, project, revision
        ),
        on_rollback=lambda actor, project, revision: app.state.author_builder_service.unclaim_created_project_if_eligible(
            actor, project, revision
        ),
    )
    app.state.host_key_discovery_service = HostKeyDiscoveryService(
        settings, app.state.author_builder_service
    )
    app.state.project_composition_service = ProjectCompositionService(
        settings, app.state.project_import_service, app.state.author_builder_service
    )
    app.state.session_manager = SessionManager(settings.session_ttl_seconds)
    app.state.oidc_provider = OidcProvider(settings)
    app.state.mutation_audit = MutationAuditTrail(
        settings.auth_audit_path
        or os.path.join(os.path.abspath(settings.reports_dir), ".auth", "mutations.jsonl")
    )
    app.include_router(auth_router)
    app.include_router(router)
    app.include_router(editor_router, prefix='/api/v1')
    app.include_router(refinement_router, prefix='/api/v1')
    app.include_router(wizard_router, prefix='/api/v1')
    app.include_router(demonstration_router, prefix='/api/v1')
    app.include_router(project_import_router, prefix='/api/v1')
    app.include_router(author_builder_router, prefix='/api/v1')
    app.include_router(project_composition_router, prefix='/api/v1')
    app.include_router(watch_learn_readiness_router, prefix='/api/v1')

    @app.middleware("http")
    async def mutation_audit(request: Request, call_next):
        oidc_callback = request.url.path == "/api/v1/auth/oidc/callback"
        if (
            request.method.upper() in {"GET", "HEAD", "OPTIONS"}
            and not oidc_callback
        ) or not request.url.path.startswith("/api/v1"):
            return await call_next(request)
        try:
            response = await call_next(request)
        except BaseException:
            try:
                app.state.mutation_audit.record(
                    actor=getattr(request.state, "actor", None),
                    action=mutation_action(request),
                    outcome="failed",
                )
            except OSError:
                logger.error("mutation audit write failed")
            raise
        outcome = getattr(request.state, "audit_outcome", None) or (
            "allowed" if response.status_code < 400 else (
                "denied" if response.status_code in {401, 403} else "failed"
            )
        )
        try:
            app.state.mutation_audit.record(
                actor=getattr(request.state, "actor", None),
                action=mutation_action(request),
                outcome=outcome,
            )
        except OSError:
            logger.error("mutation audit write failed")
        return response

    @app.get("/sign-in", include_in_schema=False)
    async def sign_in_shell() -> FileResponse:
        if os.path.isfile(_SIGNIN_HTML):
            return FileResponse(_SIGNIN_HTML, media_type="text/html")
        raise HTTPException(status_code=503, detail="Sign in is unavailable.")

    @app.get("/reports/{path:path}", include_in_schema=False)
    async def protected_report(
        path: str,
        _actor=Depends(verify_viewer),
    ) -> FileResponse:
        reports_abs = os.path.realpath(os.path.abspath(settings.reports_dir))
        candidate = os.path.realpath(os.path.join(reports_abs, path.lstrip("/")))
        try:
            inside = os.path.commonpath((reports_abs, candidate)) == reports_abs
        except ValueError:
            inside = False
        if not inside or not os.path.isfile(candidate):
            raise HTTPException(status_code=404, detail="Report file was not found.")
        return FileResponse(candidate)

    @app.get("/watch-learn", include_in_schema=False)
    async def watch_learn_shell(_actor=Depends(verify_operator)) -> FileResponse:
        if os.path.isfile(_WATCH_LEARN_HTML):
            return FileResponse(
                _WATCH_LEARN_HTML,
                media_type="text/html",
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": _WATCH_LEARN_FRAME_ANCESTORS_CSP,
                },
            )
        raise HTTPException(status_code=503, detail="Watch & Learn is unavailable.")

    @app.get("/watch-learn-assets/lifecycle.js", include_in_schema=False)
    async def watch_learn_lifecycle(_actor=Depends(verify_operator)) -> FileResponse:
        if os.path.isfile(_WATCH_LEARN_LIFECYCLE_JS):
            return FileResponse(
                _WATCH_LEARN_LIFECYCLE_JS,
                media_type="text/javascript",
                headers={"Cache-Control": "no-store"},
            )
        raise HTTPException(status_code=503, detail="Watch & Learn lifecycle support is unavailable.")

    # Dashboard SPA shell.
    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def dashboard_shell(request: Request):
        if authenticate_optional(request) is None:
            state = "expired" if request.cookies.get(SESSION_COOKIE_NAME) else "unauthenticated"
            return RedirectResponse(f"/sign-in?state={state}", status_code=303)
        if os.path.isfile(_DASHBOARD_HTML):
            return FileResponse(_DASHBOARD_HTML, media_type="text/html")
        return FileResponse(
            path=__file__,  # fallback — unreachable in practice
            media_type="text/plain",
            status_code=503,
        )

    return app


# Module-level singleton used by uvicorn: uvicorn dashboard.app:app
app = create_app()
