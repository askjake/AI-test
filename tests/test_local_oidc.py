"""Acceptance tests for the packaged, explicitly test-only Keycloak profile."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest
from cryptography import x509

from dashboard.config import DashboardSettings
from dashboard.oidc import OidcProvider
from orchestrator_cookie import cli
from orchestrator_cookie.config import (
    ConfigurationError,
    RuntimeConfig,
    atomic_write_json,
    initialize_runtime,
    load_config,
    runtime_root,
    save_config,
)
from orchestrator_cookie.image import CommandResult
from orchestrator_cookie.doctor import run_doctor
from orchestrator_cookie.lifecycle import start_dashboard
from orchestrator_cookie.lifecycle import DashboardState
from orchestrator_cookie.local_oidc import (
    KEYCLOAK_IMAGE,
    KEYCLOAK_RUNTIME_UID,
    NGINX_IMAGE,
    RUNTIME_BACKUP_RELATIVE,
    LocalOidcState,
    _nginx_document,
    _engine_json,
    _realm_document,
    _start_containers,
    deactivate_local_oidc,
    load_local_oidc_state,
    provision_local_oidc,
    validate_public_host,
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "clone"
    repo.mkdir()
    initialize_runtime(repo)
    return repo


def _state(tmp_path: Path) -> LocalOidcState:
    files = {
        name: str((tmp_path / name).resolve())
        for name in (
            "realm_file",
            "nginx_config",
            "ca_certificate",
            "server_certificate",
            "server_private_key",
            "client_secret_file",
            "viewer_password_file",
            "operator_password_file",
            "admin_environment_file",
        )
    }
    return LocalOidcState(
        schema_version=1,
        public_host="192.0.2.10",
        dashboard_port=8025,
        app_https_port=8443,
        idp_https_port=9443,
        engine="/usr/bin/docker",
        platform="linux/amd64",
        owner_id="a1b2c3d4e5f6",
        network_name="orchestrator-cookie-oidc-a1b2c3d4e5f6",
        network_subnet="172.30.0.0/24",
        keycloak_ip="172.30.0.2",
        proxy_ip="172.30.0.3",
        keycloak_container="orchestrator-cookie-oidc-a1b2c3d4e5f6-keycloak",
        proxy_container="orchestrator-cookie-oidc-a1b2c3d4e5f6-proxy",
        keycloak_image=KEYCLOAK_IMAGE,
        nginx_image=NGINX_IMAGE,
        **files,
    )


@pytest.mark.parametrize(
    "value",
    ("host/name", "host:9443", "0.0.0.0", "::1", "localhost", "bad host", "-bad.example"),
)
def test_local_oidc_public_host_rejects_unsafe_or_ambiguous_values(value):
    with pytest.raises(ConfigurationError):
        validate_public_host(value)
    assert validate_public_host("192.0.2.10") == "192.0.2.10"
    assert validate_public_host("oidc.example.test") == "oidc.example.test"


def test_realm_is_private_confidential_pkce_and_maps_unique_group_identities(tmp_path):
    value = _realm_document(
        public_host="192.0.2.10",
        app_https_port=8443,
        client_secret="client-secret-value",
        viewer_password="viewer-password-value",
        operator_password="operator-password-value",
    )
    assert value["realm"] == "orchestrator-cookie"
    assert value["registrationAllowed"] is False
    assert value["resetPasswordAllowed"] is False
    assert [group["name"] for group in value["groups"]] == ["viewers", "operators"]
    client = value["clients"][0]
    assert client["publicClient"] is False
    assert client["secret"] == "client-secret-value"
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["directAccessGrantsEnabled"] is False
    mapper = client["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-group-membership-mapper"
    assert mapper["config"]["claim.name"] == "groups"
    users = {user["username"]: user for user in value["users"]}
    assert users["local-viewer"]["groups"] == ["/viewers"]
    assert users["local-operator"]["groups"] == ["/operators"]
    assert users["local-viewer"]["credentials"][0]["temporary"] is False


def test_nginx_exposes_only_app_and_required_realm_paths_and_overwrites_proxy_headers(tmp_path):
    document = _nginx_document(_state(tmp_path))
    assert "listen 8443 ssl" in document
    assert "listen 9443 ssl" in document
    assert "host.docker.internal:8025" in document
    assert "location ^~ /realms/orchestrator-cookie/" in document
    assert "location ^~ /resources/" in document
    assert "location / { return 404; }" in document
    assert 'proxy_set_header Forwarded ""' in document
    assert "proxy_set_header X-Forwarded-For $remote_addr" in document
    assert document.count('proxy_set_header X-Original-Forwarded-For ""') == 3
    assert document.count('proxy_set_header X-Forwarded-Access-Token ""') == 3
    assert "/admin/" not in document
    assert "/metrics" not in document
    assert "/health" not in document


def test_container_contract_has_no_keycloak_host_port_and_hardens_proxy(monkeypatch, tmp_path):
    state = _state(tmp_path)
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._start_existing_container",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._run_container",
        lambda _engine, argv, label: calls.append((label, list(argv))),
    )

    assert _start_containers("/usr/bin/docker", state) == [
        state.keycloak_container,
        state.proxy_container,
    ]
    keycloak = next(argv for label, argv in calls if label == "Keycloak")
    proxy = next(argv for label, argv in calls if label == "TLS proxy")

    assert state.keycloak_image in keycloak
    assert "--publish" not in keycloak
    assert keycloak[keycloak.index("--user") + 1] == (
        f"{KEYCLOAK_RUNTIME_UID}:{os.getgid()}"
    )
    assert keycloak[keycloak.index("--entrypoint") + 1] == "/bin/sh"
    assert 'umask 0007; exec /opt/keycloak/bin/kc.sh "$@"' in keycloak
    assert keycloak[keycloak.index("--cap-drop") + 1] == "ALL"
    assert keycloak[keycloak.index("--security-opt") + 1] == "no-new-privileges"
    assert keycloak[keycloak.index("--memory") + 1] == "1g"
    assert "--import-realm" in keycloak
    assert "--proxy-headers=xforwarded" in keycloak
    assert not any("password-value" in value for value in keycloak)

    assert state.nginx_image in proxy
    assert "--read-only" in proxy
    assert proxy[proxy.index("--cap-drop") + 1] == "ALL"
    assert proxy[proxy.index("--security-opt") + 1] == "no-new-privileges"
    assert proxy.count("--publish") == 2
    assert f"0.0.0.0:8443:8443" in proxy
    assert f"0.0.0.0:9443:9443" in proxy
    assert proxy[proxy.index("--entrypoint") + 1] == "/usr/sbin/nginx"


def test_read_only_engine_inspection_treats_command_timeout_as_unavailable(monkeypatch):
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc.run_checked",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("docker", 30)
        ),
    )
    assert _engine_json("/usr/bin/docker", ["container", "inspect", "example"]) is None


def test_provision_generates_private_state_and_configures_exact_8025(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr("orchestrator_cookie.local_oidc.resolve_engine", lambda _value: "/usr/bin/docker")
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc.engine_reachable",
        lambda _engine: (True, "ready"),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._port_available",
        lambda _port: True,
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc.acquire_images",
        lambda _engine, _platform: calls.append("acquire"),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._network",
        lambda *_args: (
            "orchestrator-cookie-oidc-111111111111",
            "172.30.0.0/24",
            "172.30.0.2",
            "172.30.0.3",
            False,
        ),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._start_containers",
        lambda *_args: calls.append("start") or [],
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._wait_ready",
        lambda _state: calls.append("ready"),
    )

    state = provision_local_oidc(repo, public_host="192.0.2.10")
    configured = load_config(repo)
    persisted = load_local_oidc_state(repo, required=True)

    assert calls == ["acquire", "start", "ready"]
    assert persisted == state
    assert configured.bind_host == "0.0.0.0"
    assert configured.lan_enabled is True
    assert configured.port == configured.preferred_port == 8025
    assert configured.port_fallback_enabled is False
    assert configured.oidc.enabled is True
    assert configured.oidc.issuer == "https://192.0.2.10:9443/realms/orchestrator-cookie"
    assert configured.oidc.redirect_uri == (
        "https://192.0.2.10:8443/api/v1/auth/oidc/callback"
    )
    assert configured.oidc.viewer_values == ("viewers",)
    assert configured.oidc.operator_values == ("operators",)
    assert configured.oidc.trusted_proxy_cidrs == ("172.30.0.3/32",)
    assert configured.oidc.ca_file == state.ca_certificate
    backup = RuntimeConfig.from_mapping(json.loads(
        (runtime_root(repo) / RUNTIME_BACKUP_RELATIVE).read_text(encoding="utf-8")
    ))
    assert backup.bind_host == "127.0.0.1"
    assert backup.preferred_port == 8080

    secret_paths = (
        state.client_secret_file,
        state.viewer_password_file,
        state.operator_password_file,
        state.admin_environment_file,
        state.server_private_key,
    )
    for path_text in secret_paths:
        path = Path(path_text)
        assert path.is_file() and not path.is_symlink()
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    runtime_text = (
        runtime_root(repo) / "config" / "runtime.json"
    ).read_text(encoding="utf-8")
    for path_text in (
        state.client_secret_file,
        state.viewer_password_file,
        state.operator_password_file,
    ):
        value = Path(path_text).read_text(encoding="utf-8").strip()
        assert value not in runtime_text

    realm_path = Path(state.realm_file)
    assert realm_path.name == "orchestrator-cookie-realm.json"
    assert stat.S_IMODE(realm_path.stat().st_mode) == 0o640
    assert stat.S_IMODE(realm_path.parent.stat().st_mode) == 0o770
    assert stat.S_IMODE(realm_path.parent.parent.stat().st_mode) == 0o770
    certificate = x509.load_pem_x509_certificate(
        Path(state.server_certificate).read_bytes()
    )
    alternatives = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert "192.0.2.10" in {
        str(value) for value in alternatives.get_values_for_type(x509.IPAddress)
    }

    ca_certificate = x509.load_pem_x509_certificate(
        Path(state.ca_certificate).read_bytes()
    )
    ca_subject_key = ca_certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value
    ca_authority_key = ca_certificate.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value
    server_subject_key = certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value
    server_authority_key = certificate.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value

    assert ca_authority_key.key_identifier == ca_subject_key.digest
    assert server_authority_key.key_identifier == ca_subject_key.digest
    assert server_subject_key.digest != ca_subject_key.digest


def test_provision_selects_next_available_https_ports_but_never_moves_dashboard(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    monkeypatch.setattr("orchestrator_cookie.local_oidc.resolve_engine", lambda _value: "/usr/bin/docker")
    monkeypatch.setattr("orchestrator_cookie.local_oidc.engine_reachable", lambda _engine: (True, "ready"))
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._port_available",
        lambda port: port not in {8443, 9443},
    )
    monkeypatch.setattr("orchestrator_cookie.local_oidc.acquire_images", lambda *_args: None)
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._network",
        lambda *_args: ("orchestrator-cookie-oidc-111111111111", "172.30.0.0/24", "172.30.0.2", "172.30.0.3", False),
    )
    monkeypatch.setattr("orchestrator_cookie.local_oidc._start_containers", lambda *_args: [])
    monkeypatch.setattr("orchestrator_cookie.local_oidc._wait_ready", lambda *_args: None)

    # Port 8025 is independently required.  Make only that check available,
    # then make 8443/9443 collide during their sequential scans.
    observed: list[int] = []

    def availability(port: int) -> bool:
        observed.append(port)
        if len(observed) == 1:
            return port == 8025
        return port not in {8443, 9443}

    monkeypatch.setattr("orchestrator_cookie.local_oidc._port_available", availability)
    state = provision_local_oidc(repo, public_host="192.0.2.10")
    assert state.dashboard_port == 8025
    assert state.app_https_port == 8444
    assert state.idp_https_port == 9444
    assert load_config(repo).port_fallback_enabled is False


def test_exact_dashboard_port_fails_closed_instead_of_scanning(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    config = replace(
        load_config(repo),
        port=8025,
        preferred_port=8025,
        port_fallback_enabled=False,
    )
    save_config(repo, config)
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.dashboard_status",
        lambda *_args: type("State", (), {"running": False})(),
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_args: False)
    with pytest.raises(ConfigurationError, match="required dashboard port"):
        start_dashboard(repo, config)


def test_failed_readiness_rolls_back_runtime_state_and_owned_engine_resources(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    before = (runtime_root(repo) / "config" / "runtime.json").read_bytes()
    removed: list[list[str]] = []
    monkeypatch.setattr("orchestrator_cookie.local_oidc.resolve_engine", lambda _value: "/usr/bin/docker")
    monkeypatch.setattr("orchestrator_cookie.local_oidc.engine_reachable", lambda _engine: (True, "ready"))
    monkeypatch.setattr("orchestrator_cookie.local_oidc._port_available", lambda _port: True)
    monkeypatch.setattr("orchestrator_cookie.local_oidc.acquire_images", lambda *_args: None)
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._network",
        lambda *_args: ("orchestrator-cookie-oidc-111111111111", "172.30.0.0/24", "172.30.0.2", "172.30.0.3", True),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._start_containers",
        lambda _engine, state: [state.keycloak_container, state.proxy_container],
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc._wait_ready",
        lambda _state: (_ for _ in ()).throw(ConfigurationError("not ready")),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc.run_checked",
        lambda argv, **_kwargs: removed.append(list(argv)) or CommandResult(0, "", ""),
    )

    with pytest.raises(ConfigurationError, match="not ready"):
        provision_local_oidc(repo, public_host="192.0.2.10")

    assert (runtime_root(repo) / "config" / "runtime.json").read_bytes() == before
    assert not (runtime_root(repo) / "config" / "local_oidc.json").exists()
    assert not (runtime_root(repo) / "state" / "local_oidc").exists()
    assert not (runtime_root(repo) / "secrets" / "local_oidc").exists()
    assert any(command[1:4] == ["container", "rm", "--force"] for command in removed)
    assert any(command[1:3] == ["network", "rm"] for command in removed)


def test_cli_requires_confirmation_and_never_prints_local_password(monkeypatch, tmp_path, capsys):
    repo = _repo(tmp_path)
    assert cli.main(
        ["local-oidc", "provision", "--public-host", "192.0.2.10"],
        repo_root=repo,
    ) == 3
    assert "rerun with --yes" in capsys.readouterr().err

    password = "local-password-must-not-print"
    monkeypatch.setattr(cli, "read_local_oidc_password", lambda *_args: password)
    monkeypatch.setattr(cli, "_copy_to_clipboard", lambda value, **_kwargs: value == password)
    args = type("Args", (), {"role": "operator", "show_path": False})()
    cli._local_oidc_access(repo, args)
    output = capsys.readouterr().out
    assert "local-operator" in output
    assert password not in output


def test_uninstall_stops_owned_local_oidc_before_preserving_or_purging(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    calls: list[Path] = []
    monkeypatch.setattr(cli, "load_local_oidc_state", lambda _repo: object())
    monkeypatch.setattr(
        cli,
        "stop_local_oidc",
        lambda selected: calls.append(selected),
    )

    cli._remove_generated(repo, purge_user_data=False, confirmation=None)

    assert calls == [repo]
    assert runtime_root(repo).is_dir()


def test_deactivate_restores_pre_oidc_runtime_and_preserves_identity_state(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    original = load_config(repo)
    backup_path = runtime_root(repo) / RUNTIME_BACKUP_RELATIVE
    atomic_write_json(backup_path, original.to_dict())
    local_config = replace(
        original,
        bind_host="0.0.0.0",
        port=8025,
        preferred_port=8025,
        port_fallback_enabled=False,
        lan_enabled=True,
    )
    save_config(repo, local_config)
    state = _state(tmp_path)
    atomic_write_json(
        runtime_root(repo) / "config" / "local_oidc.json",
        state.to_dict(),
    )
    stopped: list[Path] = []
    monkeypatch.setattr(
        "orchestrator_cookie.local_oidc.stop_local_oidc",
        lambda selected: stopped.append(selected),
    )

    result = deactivate_local_oidc(repo)

    assert stopped == [repo]
    assert result.ready is False
    assert load_config(repo) == original
    assert load_local_oidc_state(repo, required=True) == state


def test_runtime_config_migration_keeps_sequential_fallback_by_default(tmp_path):
    migrated = RuntimeConfig.from_mapping({"schema_version": 1, "port": 8025})
    assert migrated.port_fallback_enabled is True


def test_doctor_reports_exact_port_and_missing_oidc_as_separate_gates(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    config = replace(
        load_config(repo),
        port=8025,
        preferred_port=8025,
        port_fallback_enabled=False,
    )
    save_config(repo, config)
    monkeypatch.setattr(
        "orchestrator_cookie.doctor._port_available",
        lambda _host, _port: (False, "0.0.0.0:8025 is already in use"),
    )
    monkeypatch.setattr("orchestrator_cookie.doctor.resolve_engine", lambda _configured: None)
    report = run_doctor(repo)
    port = next(finding for finding in report.findings if finding.code == "port")
    oidc = next(
        finding for finding in report.findings
        if finding.code == "organization-sign-in"
    )
    assert port.severity == "BLOCK"
    assert "fallback is disabled" in port.summary
    assert oidc.severity == "BLOCK"
    assert "not configured" in oidc.summary


def test_doctor_accepts_exact_port_owned_by_authenticated_managed_dashboard(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    config = replace(
        load_config(repo),
        port=8025,
        preferred_port=8025,
        port_fallback_enabled=False,
    )
    save_config(repo, config)
    monkeypatch.setattr(
        "orchestrator_cookie.doctor.dashboard_status",
        lambda *_args: DashboardState(True, "dashboard is running", 123, None, 8025),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.doctor._port_available",
        lambda *_args: (_ for _ in ()).throw(AssertionError("managed port was rebound")),
    )
    monkeypatch.setattr("orchestrator_cookie.doctor.resolve_engine", lambda _configured: None)

    report = run_doctor(repo)

    port = next(finding for finding in report.findings if finding.code == "port")
    assert port.severity == "PASS"
    assert "authenticated managed dashboard" in port.summary


def test_oidc_transport_uses_the_configured_ca_without_disabling_verification(monkeypatch):
    sentinel = object()
    observed: list[str | None] = []

    def context(*, cafile=None):
        observed.append(cafile)
        return sentinel

    monkeypatch.setattr("dashboard.oidc.ssl.create_default_context", context)
    provider = OidcProvider(DashboardSettings(oidc_ca_file="/private/local-ca.crt"))
    assert provider.transport.ssl_context is sentinel
    assert observed == ["/private/local-ca.crt"]


def test_sign_in_ui_identifies_local_provider_as_test_only():
    template = (
        Path(__file__).resolve().parents[1]
        / "templates"
        / "dashboard"
        / "signin.html"
    ).read_text(encoding="utf-8")
    assert 'config.provider_label||"organization account"' in template
    assert "if(config.test_only)" in template
    assert "This is not a corporate account" in template
