"""Dashboard configuration (Phase 10).

All settings read from environment variables (DASHBOARD_ prefix).
auth_token is required when host is non-loopback; application construction is
refused if it is absent so an unauthenticated listener is never created.

auth_operator_token is reserved for Phase 11 (write access / run triggering).
Defaults to auth_token so a single-token deployment still covers both roles.
The two-token split is established now to avoid a tear-out at Phase 11.
"""
from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProjectImportRootSetting(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    label: str = Field(min_length=1, max_length=80, pattern=r"^[^\r\n\x00<>]+$")
    path: str = Field(min_length=1, max_length=4096)


class DashboardSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DASHBOARD_",
        case_sensitive=False,
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8080
    # Path to the reports/ directory (the shared volume the agent writes to).
    reports_dir: str = "reports"
    # Path to the tests_specs/ directory used by both the editor and spawned runs.
    specs_dir: str = "tests_specs"
    # Viewer token — required when binding non-localhost.
    # Accepted by every read endpoint.
    auth_token: str | None = None
    # Operator token — Phase 11 write access.  Falls back to auth_token so a
    # single-token setup already satisfies the operator check.
    auth_operator_token: str | None = None
    # Background index re-scan interval in seconds.
    index_interval: int = 5
    # A status file left in pending/running for longer than this is treated as
    # abandoned.  Set to 0 to disable stale-run detection.
    run_stale_seconds: int = 7200
    # Control directory override. Defaults to <reports_dir>/.ctrl at runtime.
    ctrl_dir: str | None = None
    # A trigger must have exactly one execution owner. ``spawn`` is the
    # standalone dashboard default; ``watcher`` delegates to a separately
    # running orchestrator scheduler.
    trigger_backend: Literal["spawn", "watcher"] = "spawn"

    # Phase 13D: draft-only specification refinement, text-only by default.
    # This is deliberately disabled by default. There is no model/credential fallback:
    # all of the explicit authoring values below are required before an
    # invocation can be constructed.
    authoring_refinement_enabled: bool = False
    authoring_model_id: str | None = None
    authoring_region: str | None = None
    authoring_profile: str | None = None
    authoring_shared_credentials_file: str | None = None
    authoring_shared_config_file: str | None = None
    authoring_state_root: str = ".dashboard_refinement_state"
    authoring_guidance_root: str = "authoring_guidance"
    authoring_max_selection: int = 12
    authoring_max_context_chars: int = 24_000
    authoring_max_source_chars: int = 6_000
    authoring_max_output_chars: int = 12_000
    authoring_request_timeout_seconds: int = 45
    authoring_queue_concurrency: int = 1

    # Phase 14: Project Builder Wizard. Approved blueprints are read-only,
    # hash-pinned sources. Plan jobs use only the Phase 13D text method and model
    # configuration but retain a separate private state document.
    wizard_state_root: str = ".dashboard_refinement_state"
    wizard_blueprint_root: str = "project_blueprints"
    wizard_max_source_chars: int = 8_000
    # A project-plan proposal is structurally broader than one specification
    # refinement. Keep its response independently bounded so the Phase 13D
    # per-spec cap cannot reject an otherwise valid multi-spec plan simply
    # because JSON serialization is a little larger than 12 KiB.
    wizard_max_output_chars: int = 16_384
    wizard_max_pending_jobs: int = 2
    # Phase 14.1: explicit, isolated target preflight.  Results are memory-only
    # and expire quickly; process output is never returned and remains bounded.
    wizard_probe_timeout_seconds: float = Field(default=5.0, ge=0.25, le=15.0)
    wizard_probe_ttl_seconds: int = Field(default=120, ge=10, le=600)
    wizard_probe_output_bytes: int = Field(default=8_192, ge=1_024, le=65_536)
    # Host-side source directory mounted read-only into runner containers.
    # DASHBOARD_SECRETS_DIR is preferred; the target-setup service also honors
    # the established SECRETS_DIR environment variable used by run_container.sh.
    secrets_dir: str = "secrets"

    # Phase 16: explicit OIDC authorization-code + PKCE configuration.  OIDC
    # remains inert until every required value is configured by the clone
    # owner.  The client secret value is never an environment variable.
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_client_secret_file: str | None = None
    oidc_ca_file: str | None = None
    oidc_provider_label: str = "organization account"
    oidc_test_only: bool = False
    oidc_role_claim: str = "groups"
    oidc_viewer_values: tuple[str, ...] = ()
    oidc_operator_values: tuple[str, ...] = ()
    oidc_identity_claim: str = "preferred_username"
    oidc_scopes: tuple[str, ...] = ("openid", "profile", "email")
    oidc_signing_algorithms: tuple[str, ...] = ("RS256",)
    oidc_tls_terminated: bool = False
    oidc_trusted_proxy_cidrs: tuple[str, ...] = ()
    session_ttl_seconds: int = Field(default=28_800, ge=300, le=86_400)
    auth_audit_path: str | None = None

    # Project-folder import is disabled until at least one administrator-owned,
    # absolute root is configured by the managed installer. Browser clients see
    # only the id and friendly label, never these host paths.
    project_import_roots: tuple[ProjectImportRootSetting, ...] = ()
    project_import_audit_path: str | None = None
    project_import_preview_ttl_seconds: int = Field(default=300, ge=30, le=1_800)
    project_import_max_previews: int = Field(default=256, ge=1, le=4_096)
    project_import_max_depth: int = Field(default=16, ge=1, le=64)
    project_import_max_files: int = Field(default=1_000, ge=1, le=20_000)
    project_import_max_file_bytes: int = Field(
        default=2 * 1024 * 1024, ge=1_024, le=100 * 1024 * 1024
    )
    project_import_max_total_bytes: int = Field(
        default=50 * 1024 * 1024, ge=1_024, le=2 * 1024 * 1024 * 1024
    )
    project_import_max_browse_entries: int = Field(default=500, ge=1, le=5_000)
    project_import_max_excluded_entries: int = Field(default=100, ge=1, le=1_000)

    # Owner-scoped Author Builder state. Existing projects are authorable only
    # when listed for an exact OIDC subject in the optional server-owned grants
    # file; newly composed projects receive an opaque owner record at creation.
    author_builder_state_root: str = ".orchestrator-cookie/author-builder/v1"
    author_builder_grants_file: str | None = None
    author_builder_max_files: int = Field(default=2_000, ge=1, le=20_000)
    author_builder_max_file_bytes: int = Field(
        default=2 * 1024 * 1024, ge=1_024, le=100 * 1024 * 1024
    )
    author_builder_max_total_bytes: int = Field(
        default=100 * 1024 * 1024, ge=1_024, le=2 * 1024 * 1024 * 1024
    )
    author_builder_history_max_items: int = Field(default=1_000, ge=1, le=20_000)
    # Discovery remains inert until both deployment configuration and a user's
    # explicit revision-bound command enable the one-host ssh-keyscan adapter.
    author_builder_host_key_discovery_enabled: bool = False
    author_builder_host_key_timeout_seconds: float = Field(default=5.0, ge=0.25, le=15.0)
    author_builder_host_key_ttl_seconds: int = Field(default=300, ge=30, le=1_800)
    author_builder_host_key_max_bytes: int = Field(default=16_384, ge=1_024, le=65_536)

    # Phase 17: Watch & Learn. State is clone-local, private, bounded, and
    # disabled for target contact unless a controlled adapter and exact reviewed
    # runner image are explicitly available.
    watch_learn_state_root: str = ".orchestrator-cookie/demonstrations/v1"
    # Imported-project readiness is owner-scoped and deliberately separate from
    # runnable project YAML. Saving configuration never activates target contact.
    watch_learn_readiness_root: str = ".orchestrator-cookie/watch-learn-readiness/v1"
    watch_learn_readiness_activation_ttl_seconds: int = Field(default=600, ge=60, le=1_800)
    watch_learn_max_sessions_per_owner: int = Field(default=100, ge=1, le=1_000)
    watch_learn_max_owner_bytes: int = Field(
        default=256 * 1024 * 1024, ge=1_048_576, le=2_147_483_648
    )
    watch_learn_max_actions: int = Field(default=500, ge=1, le=2_000)
    # State-changing capture requests are serialized by the browser, but the
    # server independently enforces a short-window ceiling for direct API use.
    watch_learn_action_rate_per_second: int = Field(default=20, ge=1, le=100)
    watch_learn_max_evidence_bytes: int = Field(
        default=5 * 1024 * 1024, ge=65_536, le=25 * 1024 * 1024
    )
    watch_learn_max_evidence_pixels: int = Field(
        default=16_777_216, ge=65_536, le=67_108_864
    )
    watch_learn_max_pending_model_jobs: int = Field(default=2, ge=1, le=8)
    watch_learn_model_max_output_chars: int = Field(default=12_000, ge=1_000, le=32_000)
    # Redacted screenshots are sent to the configured Bedrock model only when
    # this deployment flag and the operator's per-job opt-in are both true.
    watch_learn_visual_enrichment_enabled: bool = False
    watch_learn_visual_enrichment_max_images: int = Field(default=8, ge=1, le=20)
    watch_learn_visual_enrichment_max_bytes: int = Field(
        default=10 * 1024 * 1024, ge=65_536, le=50 * 1024 * 1024
    )
    watch_learn_connect_timeout_seconds: float = Field(default=45.0, ge=5.0, le=120.0)
    watch_learn_action_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    # Capture never uses a mutable image tag.  Connect remains unavailable until
    # an operator configures the exact reviewed runner digest; the adapter also
    # verifies that digest with the local engine before starting a subprocess.
    watch_learn_runner_image: str | None = None

    @property
    def effective_operator_token(self) -> str | None:
        """The operator token, falling back to the viewer token."""
        return self.auth_operator_token or self.auth_token

    @property
    def authoring_refinement_configured(self) -> bool:
        """True only when refinement may create a text-only model client.

        Keeping this check here makes the disabled path explicit and testable;
        callers must not infer a model, region, profile, or credential source.
        """
        return bool(
            self.authoring_refinement_enabled
            and self.authoring_model_id
            and self.authoring_region
            and self.authoring_profile
            and self.authoring_shared_credentials_file
            and self.authoring_shared_config_file
        )

    @property
    def oidc_configured(self) -> bool:
        return bool(
            self.oidc_enabled
            and self.oidc_issuer
            and self.oidc_client_id
            and self.oidc_redirect_uri
            and (self.oidc_viewer_values or self.oidc_operator_values)
        )

    @property
    def secure_cookies(self) -> bool:
        """Cookie security follows the validated deployment posture, not headers."""
        return bool(self.oidc_tls_terminated)

    def require_safe_binding(self) -> None:
        """Refuse unauthenticated non-loopback exposure before the app can serve."""
        if self.host not in ("127.0.0.1", "localhost", "::1") and self.auth_token is None:
            raise RuntimeError(
                "DASHBOARD_AUTH_TOKEN is required for every non-loopback dashboard binding"
            )
        if self.oidc_enabled and not self.oidc_configured:
            raise RuntimeError("OIDC is enabled but required provider or role mapping is incomplete")
        if self.oidc_enabled:
            issuer = urlsplit(self.oidc_issuer or "")
            redirect = urlsplit(self.oidc_redirect_uri or "")
            if issuer.scheme != "https" or not issuer.netloc:
                raise RuntimeError("OIDC issuer must use HTTPS")
            if redirect.scheme not in {"http", "https"} or not redirect.netloc:
                raise RuntimeError("OIDC redirect URI is invalid")
            if redirect.path != "/api/v1/auth/oidc/callback":
                raise RuntimeError("OIDC redirect URI callback path is invalid")
            if self.host not in ("127.0.0.1", "localhost", "::1"):
                if redirect.scheme != "https" or not self.oidc_tls_terminated:
                    raise RuntimeError("LAN OIDC requires HTTPS and explicit TLS termination")
        if self.oidc_tls_terminated and not self.oidc_trusted_proxy_cidrs:
            raise RuntimeError("TLS termination requires explicit trusted proxy networks")


settings = DashboardSettings()
