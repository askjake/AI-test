"""Phase 16 sign-in, authorization, bootstrap, OIDC, CSRF, and audit acceptance."""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import stat
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from dashboard.auth import SESSION_COOKIE_NAME
from dashboard.config import DashboardSettings
from dashboard.oidc import OidcDenied, OidcProvider, OidcUnavailable
from orchestrator_cookie import cli
from orchestrator_cookie.config import (
    OidcConfig,
    RuntimeConfig,
    initialize_runtime,
    load_config,
    load_tokens,
)
from orchestrator_cookie.lifecycle import _dashboard_argv


ROOT = Path(__file__).resolve().parents[1]


def _reload_app(tmp_path: Path, monkeypatch, *, secure_cookies: bool = False):
    for key in list(os.environ):
        if key.startswith("DASHBOARD_"):
            monkeypatch.delenv(key, raising=False)
    reports = tmp_path / "reports"
    specs = tmp_path / "specs" / "sample"
    manual = tmp_path / "manuals" / "sample"
    reports.mkdir(parents=True)
    specs.mkdir(parents=True)
    manual.mkdir(parents=True)
    (manual / "manual.md").write_text("# Manual\n")
    (reports / "sample" / "run" ).mkdir(parents=True)
    (reports / "sample" / "run" / "report.html").write_text("<html>report</html>")
    (specs / "project.yaml").write_text(
        "name: sample\n"
        f"manual_dir: {manual}\n"
        "target:\n  type: local-app\n  app: example\n  window: Example\n"
        "schedule: '0 3 * * *'\nmax_steps: 30\nmax_seconds: 1800\nenabled: true\n"
    )
    (specs / "010-one.md").write_text(
        "# Test: One\n\n## Goal\nInspect.\n\n## Assertions\n- Visible.\n"
    )
    values = {
        "DASHBOARD_AUTH_TOKEN": "v" * 48,
        "DASHBOARD_AUTH_OPERATOR_TOKEN": "o" * 48,
        "DASHBOARD_REPORTS_DIR": str(reports),
        "DASHBOARD_SPECS_DIR": str(specs.parent),
        "DASHBOARD_INDEX_INTERVAL": "999",
        "DASHBOARD_AUTH_AUDIT_PATH": str(tmp_path / "private" / "mutation-audit.jsonl"),
    }
    if secure_cookies:
        values.update({
            "DASHBOARD_OIDC_TLS_TERMINATED": "true",
            "DASHBOARD_OIDC_TRUSTED_PROXY_CIDRS": '["127.0.0.1/32"]',
        })
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    import dashboard.config as config_module
    import dashboard.routes as routes_module
    import dashboard.auth_routes as auth_routes_module
    import dashboard.app as app_module

    importlib.reload(config_module)
    importlib.reload(routes_module)
    importlib.reload(auth_routes_module)
    importlib.reload(app_module)
    return app_module.create_app(), reports, specs, Path(values["DASHBOARD_AUTH_AUDIT_PATH"])


def _bootstrap(client: TestClient, role: str) -> dict:
    credential = ("o" if role == "operator" else "v") * 48
    response = client.post(
        "/api/v1/auth/bootstrap/session",
        json={"credential": credential},
    )
    assert response.status_code == 200, response.text
    assert credential not in response.text
    assert credential not in response.headers.get("set-cookie", "")
    return response.json()


def test_dedicated_sign_in_and_unauthenticated_report_gate(tmp_path, monkeypatch):
    app, reports, _specs, _audit = _reload_app(tmp_path, monkeypatch)
    with TestClient(app, follow_redirects=False) as client:
        root = client.get("/")
        assert root.status_code == 303
        assert root.headers["location"] == "/sign-in?state=unauthenticated"
        assert client.get("/api/v1/projects").status_code == 401
        assert client.get("/reports/sample/run/report.html").status_code == 401
        sign_in = client.get("/sign-in")
        assert sign_in.status_code == 200
        assert "Sign in with organization account" in sign_in.text
        assert "Local bootstrap access" in sign_in.text
        assert "dashboard_tokens.json" not in sign_in.text
        assert str(reports) not in sign_in.text


def test_bootstrap_sessions_derive_roles_and_csrf_server_side(tmp_path, monkeypatch):
    app, _reports, specs, audit_path = _reload_app(tmp_path, monkeypatch)
    source = (specs / "project.yaml").read_text()
    with TestClient(app) as viewer:
        viewer_session = _bootstrap(viewer, "viewer")
        assert viewer_session["role"] == "viewer"
        assert viewer.get("/api/v1/projects/sample/config").status_code == 200
        denied = viewer.put(
            "/api/v1/projects/sample/config",
            headers={"X-CSRF-Token": viewer_session["csrf_token"]},
            json={"raw_yaml": source},
        )
        assert denied.status_code == 403
        assert denied.json()["detail"]["code"] == "operator_required"

    with TestClient(app) as operator:
        operator_session = _bootstrap(operator, "operator")
        missing_csrf = operator.put(
            "/api/v1/projects/sample/config",
            json={"raw_yaml": source},
        )
        assert missing_csrf.status_code == 403
        assert missing_csrf.json()["detail"]["code"] == "csrf_required"
        allowed = operator.put(
            "/api/v1/projects/sample/config",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"raw_yaml": source},
        )
        assert allowed.status_code == 200, allowed.text

    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(event["role"] == "viewer" and event["outcome"] == "denied" for event in events)
    assert any(event["role"] == "operator" and event["outcome"] == "allowed" for event in events)
    audit_text = audit_path.read_text()
    assert "v" * 48 not in audit_text
    assert "o" * 48 not in audit_text
    if os.name != "nt":
        assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600


def test_bootstrap_bearer_compatibility_and_opaque_sse_cookie(tmp_path, monkeypatch):
    app, _reports, _specs, _audit = _reload_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        viewer = "v" * 48
        operator = "o" * 48
        assert client.get(
            "/api/v1/projects", headers={"Authorization": f"Bearer {viewer}"}
        ).status_code == 200
        assert client.get(
            "/api/v1/projects", headers={"Authorization": f"Bearer {operator}"}
        ).status_code == 200
        response = client.post(
            "/api/v1/auth/sse-session",
            headers={"Authorization": f"Bearer {viewer}"},
        )
        cookie = response.headers["set-cookie"]
        assert response.status_code == 200
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert viewer not in cookie and operator not in cookie


def test_expired_session_and_secure_cookie_posture(tmp_path, monkeypatch):
    app, _reports, _specs, _audit = _reload_app(
        tmp_path, monkeypatch, secure_cookies=True
    )
    with TestClient(app, base_url="https://dashboard.example.test") as client:
        response = client.post(
            "/api/v1/auth/bootstrap/session",
            json={"credential": "v" * 48},
        )
        assert "Secure" in response.headers["set-cookie"]
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, "expired-opaque-session")
        response = client.get("/api/v1/auth/session")
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "session_expired"


def test_access_cli_clipboard_rotation_and_failure_never_emit_credentials(tmp_path, monkeypatch, capsys):
    initialize_runtime(tmp_path)
    original = load_tokens(tmp_path)
    captured: list[str] = []
    monkeypatch.setattr(cli, "_copy_to_clipboard", lambda value, system=None: captured.append(value) or True)
    assert cli.main(["access", "--role", "viewer", "--copy"], repo_root=tmp_path) == 0
    output = capsys.readouterr().out
    assert captured == [original["viewer_token"]]
    assert all(value not in output for value in original.values())

    monkeypatch.setattr(cli, "_copy_to_clipboard", lambda value, system=None: False)
    assert cli.main(["access", "--role", "operator", "--copy"], repo_root=tmp_path) == 3
    failed = capsys.readouterr()
    assert all(value not in failed.out + failed.err for value in original.values())
    assert "not printed" in failed.err

    assert cli.main(["access", "--regenerate-tokens"], repo_root=tmp_path) == 0
    rotated = load_tokens(tmp_path)
    rotate_output = capsys.readouterr().out
    assert rotated != original
    assert all(value not in rotate_output for value in (*original.values(), *rotated.values()))
    assert cli.main(["access", "--show-path"], repo_root=tmp_path) == 0
    path_output = capsys.readouterr().out.strip()
    assert path_output.endswith(".orchestrator-cookie/config/dashboard_tokens.json")
    assert all(value not in path_output for value in rotated.values())


def test_owner_cli_configures_oidc_with_private_file_path_not_secret_value(tmp_path, capsys):
    initialize_runtime(tmp_path)
    secret = tmp_path / ".orchestrator-cookie" / "secrets" / "oidc-client-secret"
    value = "q" * 48
    secret.write_text(value)
    secret.chmod(0o600)
    args = [
        "configure", "--non-interactive", "--enable-oidc",
        "--oidc-issuer", "https://identity.example.test",
        "--oidc-client-id", "orchestrator-cookie",
        "--oidc-client-secret-file", str(secret),
        "--oidc-redirect-uri", "https://dashboard.example.test/api/v1/auth/oidc/callback",
        "--oidc-viewer-value", "cookie-viewers",
        "--oidc-operator-value", "cookie-operators",
        "--oidc-tls-terminated",
        "--oidc-trusted-proxy", "127.0.0.1/32",
    ]
    assert cli.main(args, repo_root=tmp_path) == 0
    output = capsys.readouterr().out
    configured = load_config(tmp_path)
    assert configured.oidc.enabled is True
    assert configured.oidc.client_secret_file == str(secret)
    assert value not in output
    assert value not in (tmp_path / ".orchestrator-cookie" / "config" / "runtime.json").read_text()


class FakeOidcTransport:
    def __init__(self, issuer: str, jwk: dict):
        self.issuer = issuer
        self.jwk = jwk
        self.id_token: str | None = None
        self.posted: dict[str, str] | None = None
        self.metadata_issuer = issuer

    def get_json(self, url: str):
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": self.metadata_issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
                "code_challenge_methods_supported": ["S256"],
            }
        if url.endswith("/jwks"):
            return {"keys": [self.jwk]}
        raise AssertionError(f"unexpected fake OIDC URL: {url}")

    def post_form(self, url: str, form):
        assert url == f"{self.issuer}/token"
        self.posted = dict(form)
        return {"id_token": self.id_token}


@pytest.fixture()
def oidc_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    return private, jwk


def _oidc_settings(**updates) -> DashboardSettings:
    values = {
        "auth_token": "v" * 48,
        "auth_operator_token": "o" * 48,
        "oidc_enabled": True,
        "oidc_issuer": "https://identity.example.test",
        "oidc_client_id": "orchestrator-cookie",
        "oidc_redirect_uri": "https://dashboard.example.test/api/v1/auth/oidc/callback",
        "oidc_role_claim": "groups",
        "oidc_viewer_values": ("cookie-viewers",),
        "oidc_operator_values": ("cookie-operators",),
        "oidc_identity_claim": "preferred_username",
        "oidc_signing_algorithms": ("RS256",),
        "oidc_tls_terminated": True,
        "oidc_trusted_proxy_cidrs": ("127.0.0.1/32",),
    }
    values.update(updates)
    return DashboardSettings(**values)


def _start_oidc(oidc_keys, **settings_updates):
    private, jwk = oidc_keys
    settings = _oidc_settings(**settings_updates)
    transport = FakeOidcTransport(settings.oidc_issuer or "", jwk)
    provider = OidcProvider(settings, transport)
    flow, authorization_url = provider.authorization_request()
    query = parse_qs(urlsplit(authorization_url).query)
    return provider, transport, private, flow, query


def _id_token(private, query, **claims_updates):
    now = int(time.time())
    claims = {
        "iss": "https://identity.example.test",
        "aud": "orchestrator-cookie",
        "sub": "subject-123",
        "iat": now,
        "exp": now + 300,
        "nonce": query["nonce"][0],
        "groups": ["cookie-operators"],
        "preferred_username": "engineer@example.test",
    }
    claims.update(claims_updates)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})


def test_oidc_pkce_claim_mapping_and_no_token_retention(oidc_keys):
    provider, transport, private, flow, query = _start_oidc(oidc_keys)
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43
    assert flow.code_verifier not in urlencode_query(query)
    transport.id_token = _id_token(private, query)
    actor = provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")
    assert actor.role == "operator"
    assert actor.subject == "oidc:subject-123"
    assert transport.posted is not None
    assert transport.posted["code_verifier"] == flow.code_verifier
    assert "access_token" not in actor.__dict__ and "id_token" not in actor.__dict__


def test_oidc_mock_route_creates_server_session_without_real_provider(tmp_path, monkeypatch, oidc_keys):
    app, _reports, _specs, audit_path = _reload_app(tmp_path, monkeypatch)
    provider, transport, private, _unused_flow, _unused_query = _start_oidc(oidc_keys)
    # Use the injected deterministic provider boundary; application startup did
    # not call it and no network transport is available to this test.
    app.state.oidc_provider = provider
    with TestClient(app, follow_redirects=False) as client:
        started = client.get("/api/v1/auth/oidc/start")
        assert started.status_code == 303
        query = parse_qs(urlsplit(started.headers["location"]).query)
        transport.id_token = _id_token(private, query, groups=["cookie-viewers"])
        callback = client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": "authorization-code", "state": query["state"][0]},
        )
        assert callback.status_code == 303
        assert callback.headers["location"] == "/"
        assert transport.id_token not in callback.headers.get("set-cookie", "")
        session = client.get("/api/v1/auth/session")
        assert session.status_code == 200
        assert session.json()["role"] == "viewer"
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(
        event["action"] == "GET_/api/v1/auth/oidc/callback"
        and event["role"] == "viewer"
        and event["outcome"] == "allowed"
        for event in events
    )


def test_oidc_error_callback_validates_and_consumes_state(tmp_path, monkeypatch, oidc_keys):
    app, _reports, _specs, _audit_path = _reload_app(tmp_path, monkeypatch)
    provider, _transport, _private, _flow, _query = _start_oidc(oidc_keys)
    app.state.oidc_provider = provider
    with TestClient(app, follow_redirects=False) as client:
        started = client.get("/api/v1/auth/oidc/start")
        query = parse_qs(urlsplit(started.headers["location"]).query)
        denied = client.get(
            "/api/v1/auth/oidc/callback",
            params={"error": "access_denied", "state": query["state"][0]},
        )
        assert denied.status_code == 303
        assert denied.headers["location"] == "/sign-in?state=denied"
        flow_cookie = started.cookies.get("orchestrator_cookie_oidc_flow")
        with pytest.raises(OidcDenied, match="expired"):
            provider.flows.consume(flow_cookie, query["state"][0])
        replay = client.get(
            "/api/v1/auth/oidc/callback",
            params={"error": "access_denied", "state": query["state"][0]},
        )
        assert replay.status_code == 303
        assert replay.headers["location"] == "/sign-in?state=denied"


def urlencode_query(query: dict[str, list[str]]) -> str:
    return "&".join(f"{key}={value}" for key, values in query.items() for value in values)


@pytest.mark.parametrize(
    "claim_update",
    [
        {"nonce": "wrong-nonce"},
        {"iss": "https://other.example.test"},
        {"aud": "different-client"},
        {"exp": 1},
        {"groups": ["unmapped-group"]},
    ],
)
def test_oidc_rejects_nonce_issuer_audience_expiry_and_unmapped_claims(oidc_keys, claim_update):
    provider, transport, private, flow, query = _start_oidc(oidc_keys)
    transport.id_token = _id_token(private, query, **claim_update)
    with pytest.raises(OidcDenied):
        provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")


def test_oidc_rejects_state_signature_jwks_and_discovery_issuer_failures(oidc_keys):
    provider, _transport, _private, flow, _query = _start_oidc(oidc_keys)
    with pytest.raises(OidcDenied):
        provider.complete(flow_id=flow.flow_id, state="wrong-state", code="authorization-code")

    provider, transport, _private, flow, query = _start_oidc(oidc_keys)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport.id_token = _id_token(other, query)
    with pytest.raises(OidcDenied):
        provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")

    private, jwk = oidc_keys
    settings = _oidc_settings()
    transport = FakeOidcTransport(settings.oidc_issuer or "", {**jwk, "kid": "other-key"})
    provider = OidcProvider(settings, transport)
    flow, url = provider.authorization_request()
    query = parse_qs(urlsplit(url).query)
    transport.id_token = _id_token(private, query)
    with pytest.raises(OidcDenied):
        provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")

    transport = FakeOidcTransport(settings.oidc_issuer or "", jwk)
    transport.metadata_issuer = "https://other.example.test"
    with pytest.raises(OidcUnavailable):
        OidcProvider(settings, transport).authorization_request()


def test_oidc_private_client_secret_is_owner_only_and_sent_only_to_token_endpoint(tmp_path, oidc_keys):
    secret = tmp_path / "oidc-client-secret"
    value = "s" * 40
    secret.write_text(value)
    secret.chmod(0o600)
    provider, transport, private, flow, query = _start_oidc(
        oidc_keys, oidc_client_secret_file=str(secret)
    )
    transport.id_token = _id_token(private, query)
    provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")
    assert transport.posted is not None and transport.posted["client_secret"] == value

    secret.chmod(0o644)
    provider, transport, private, flow, query = _start_oidc(
        oidc_keys, oidc_client_secret_file=str(secret)
    )
    transport.id_token = _id_token(private, query)
    with pytest.raises(OidcUnavailable):
        provider.complete(flow_id=flow.flow_id, state=flow.state, code="authorization-code")


def test_runtime_oidc_migration_lan_tls_and_proxy_fail_closed():
    migrated = RuntimeConfig.from_mapping({"schema_version": 1, "port": 8083})
    assert migrated.oidc.enabled is False
    migrated.validate()

    oidc = OidcConfig(
        enabled=True,
        issuer="https://identity.example.test",
        client_id="cookie",
        redirect_uri="https://dashboard.example.test/api/v1/auth/oidc/callback",
        viewer_values=("viewers",),
    )
    with pytest.raises(ValueError, match="LAN OIDC"):
        RuntimeConfig(bind_host="0.0.0.0", lan_enabled=True, oidc=oidc).validate()
    with pytest.raises(ValueError, match="trust every address"):
        OidcConfig(trusted_proxy_cidrs=("0.0.0.0/0",)).validate()

    no_proxy = _dashboard_argv(RuntimeConfig())
    assert "--no-proxy-headers" in no_proxy
    trusted = _dashboard_argv(RuntimeConfig(oidc=OidcConfig(
        tls_terminated=True,
        trusted_proxy_cidrs=("127.0.0.1/32",),
    )))
    assert trusted[-3:] == ["--proxy-headers", "--forwarded-allow-ips", "127.0.0.1/32"]


def test_frontend_has_sign_in_and_role_controls_without_browser_token_storage():
    dashboard = (ROOT / "templates" / "dashboard" / "index.html").read_text()
    sign_in = (ROOT / "templates" / "dashboard" / "signin.html").read_text()
    combined = dashboard + sign_in
    for required in (
        "Sign in with organization account",
        "Local bootstrap access",
        "Viewer",
        "Operator",
        "Operator access required",
        "X-CSRF-Token",
        "/auth/bootstrap/session",
    ):
        assert required in combined
    for forbidden in (
        "Dashboard Authentication",
        'localStorage.getItem("dash_token")',
        'localStorage.setItem("dash_token")',
        'localStorage.getItem("op_token")',
        "?token=",
        "dashboard_tokens.json",
    ):
        assert forbidden not in combined
