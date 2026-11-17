"""Focused Phase 15 cross-platform installer and runtime security tests."""
from __future__ import annotations

from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from orchestrator.bedrock_relay import BedrockRelayLease
from orchestrator.runtime_runner import (
    _private_hosts_file,
    _project_target_relay,
    build_runner_argv,
)
from orchestrator.target_relay import ProjectTransport, TargetRelayLease
from orchestrator_cookie import cli
from orchestrator_cookie.config import (
    AwsConfig,
    ConfigurationError,
    HostAppConfig,
    ImageSource,
    ImageSourceKind,
    RuntimeConfig,
    generate_tokens,
    initialize_runtime,
    load_config,
    load_tokens,
    normalize_clone_path,
    runtime_root,
    save_config,
    save_tokens,
    validate_bind_host,
    windows_acl_command,
)
from orchestrator_cookie.doctor import (
    _aws_profile_ready,
    _capability_matrix,
    detect_platform,
    run_doctor,
)
from orchestrator_cookie.image import (
    CommandResult,
    validate_argv,
    validate_image,
)
from orchestrator_cookie.lifecycle import (
    DashboardState,
    StartupOutcome,
    _candidate_ports,
    _dashboard_argv,
    _is_bind_collision,
    _port_available,
    dashboard_environment,
    dashboard_status,
    start_dashboard,
    stop_dashboard,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _runtime_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "clone anywhere"
    repo.mkdir()
    initialize_runtime(repo)
    return repo


def test_platform_detection_is_explicit_and_testable():
    info = detect_platform(system="Windows", machine="AMD64", python=(3, 12, 4))
    assert info.system == "Windows"
    assert info.machine == "AMD64"
    assert info.python == (3, 12, 4)


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
def test_capability_matrix_keeps_host_app_linux_only(system):
    capabilities = _capability_matrix(
        detect_platform(system=system, machine="x86_64", python=(3, 12, 0)),
        initialized=True,
        dependencies=True,
        engine_ok=True,
        image_ok=True,
        model_configured=True,
        host_app_enabled=True,
    )
    host_app = next(item for item in capabilities if item.name == "Linux host-app")
    assert host_app.state == ("READY" if system == "Linux" else "UNAVAILABLE")


def test_windows_and_posix_path_handling():
    assert normalize_clone_path(r"C:\\Users\\engineer\\cookie", "Windows").startswith("C:\\")
    assert normalize_clone_path("/opt/engineering/cookie", "Linux") == "/opt/engineering/cookie"
    with pytest.raises(ConfigurationError):
        normalize_clone_path(r"relative\\cookie", "Windows")


def test_runtime_initialization_is_isolated_idempotent_and_git_ignored(tmp_path):
    repo = _runtime_repo(tmp_path)
    first_tokens = load_tokens(repo)
    initialize_runtime(repo)
    assert load_tokens(repo) == first_tokens
    assert ".orchestrator-cookie/" in (REPO_ROOT / ".gitignore").read_text()
    assert (runtime_root(repo) / "tests_specs").is_dir()
    assert list((runtime_root(repo) / "tests_specs").iterdir()) == []
    if os.name != "nt":
        assert stat.S_IMODE((runtime_root(repo) / "config" / "dashboard_tokens.json").stat().st_mode) == 0o600
        assert stat.S_IMODE((runtime_root(repo) / "tests_specs").stat().st_mode) == 0o755
        assert stat.S_IMODE((runtime_root(repo) / "reports").stat().st_mode) == 0o755      # CP45-I (was 0o777)


def test_windows_acl_command_is_literal_argv():
    path = Path(r"C:\Users\engineer\clone with spaces\tokens.json")
    assert windows_acl_command(path, "DOMAIN\\engineer") == [
        "icacls",
        str(path),
        "/inheritance:r",
        "/grant:r",
        "DOMAIN\\engineer:(F)",
    ]


def test_tokens_are_strong_distinct_and_absent_from_nonsecret_config(tmp_path):
    repo = _runtime_repo(tmp_path)
    tokens = load_tokens(repo)
    assert len(tokens["viewer_token"]) >= 32
    assert len(tokens["operator_token"]) >= 32
    assert tokens["viewer_token"] != tokens["operator_token"]
    config_text = (runtime_root(repo) / "config" / "runtime.json").read_text()
    assert tokens["viewer_token"] not in config_text
    assert tokens["operator_token"] not in config_text


def test_token_validation_rejects_short_or_shared_values(tmp_path):
    repo = _runtime_repo(tmp_path)
    with pytest.raises(ConfigurationError):
        save_tokens(repo, {"viewer_token": "short", "operator_token": "x" * 40})
    with pytest.raises(ConfigurationError):
        save_tokens(repo, {"viewer_token": "x" * 40, "operator_token": "x" * 40})


def test_lan_binding_requires_explicit_operator_choice():
    with pytest.raises(ConfigurationError, match="lan_enabled"):
        RuntimeConfig(bind_host="0.0.0.0", lan_enabled=False).validate()
    RuntimeConfig(bind_host="0.0.0.0", lan_enabled=True).validate()
    assert validate_bind_host("127.0.0.1") is True
    assert validate_bind_host("10.57.24.5") is False
    with pytest.raises(ConfigurationError):
        validate_bind_host("host; shutdown")


def test_image_sources_require_verifiable_provenance(tmp_path):
    with pytest.raises(ConfigurationError, match="pinned"):
        ImageSource(kind="reference", image_ref="registry.example/cookie:latest").validate()
    ImageSource(
        kind="reference",
        image_ref="registry.example/cookie@sha256:" + "a" * 64,
    ).validate()
    with pytest.raises(ConfigurationError, match="checksum"):
        ImageSource(kind="archive", archive_path=str(tmp_path / "runner.tar")).validate()


def test_image_validation_distinguishes_present_from_verified(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    image = ImageSource(
        kind="reference",
        image_ref="registry.example/cookie@sha256:" + "b" * 64,
    )
    config = replace(load_config(repo), image=image)
    monkeypatch.setattr(
        "orchestrator_cookie.image._image_inspect",
        lambda _engine, _ref: {
            "Id": "sha256:image",
            "RepoDigests": [image.image_ref],
            "Config": {"Entrypoint": ["/app/entrypoint.sh"]},
        },
    )
    assert validate_image(repo, config, "/usr/bin/docker").ready is True


def test_engine_autodetection_prefers_docker_then_podman(monkeypatch):
    from orchestrator_cookie.image import resolve_engine

    monkeypatch.setattr(
        "orchestrator_cookie.image.shutil.which",
        lambda name: "/usr/local/bin/docker" if name == "docker" else "/usr/local/bin/podman",
    )
    assert resolve_engine() == "/usr/local/bin/docker"


def test_subprocess_contract_uses_argv_and_never_shell(monkeypatch):
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["shell"] = kwargs["shell"]
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    from orchestrator_cookie.image import run_checked

    result = run_checked(["docker", "image", "inspect", "$(touch /tmp/nope)"])
    assert result.returncode == 0
    assert observed["shell"] is False
    assert observed["argv"][-1] == "$(touch /tmp/nope)"
    with pytest.raises(ConfigurationError):
        validate_argv(["docker", "bad\nargument"])


def test_runner_argv_preserves_hardening_and_never_contains_credentials(tmp_path):
    repo = _runtime_repo(tmp_path)
    credentials = tmp_path / "credentials"
    credentials.write_text("aws_secret_access_key=do-not-copy-into-argv\n")
    os.chmod(credentials, 0o600)
    config = RuntimeConfig(
        image=ImageSource(
            kind="reference",
            image_ref="registry.example/cookie@sha256:" + "c" * 64,
        ),
        aws=AwsConfig(
            credentials_file=str(credentials),
            profile="engineering",
            region="us-west-2",
            bedrock_model_id="profile-id",
        ),
    )
    hosts_file = tmp_path / "private-hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")
    hosts_file.chmod(0o644)
    relay = BedrockRelayLease(
        endpoint="bedrock-runtime.us-west-2.amazonaws.com",
        bind_host="172.17.0.1",
        port=45678,
        client_network="172.17.0.0/16",
        proxy_url="http://runner:ephemeral-test-token@172.17.0.1:45678",
    )
    target_relay = TargetRelayLease(
        kind="vnc-direct",
        endpoint="vnc-approved",
        destination_port=5902,
        bind_host="172.17.0.1",
        port=45679,
        client_network="172.17.0.0/16",
        token="t" * 43,
    )
    argv = build_runner_argv(
        repo,
        config,
        "/usr/bin/docker",
        ["python", "-m", "orchestrator.runner", "--project", "sample"],
        container_name="orchestrator-cookie-sample-trigger",
        display=":99",
        hosts_file=hosts_file,
        bedrock_relay=relay,
        target_relay=target_relay,
        project_name="sample",
    )
    text = " ".join(argv)
    assert "--read-only" in argv
    assert "no-new-privileges" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in argv
    assert "--pid=host" not in argv and "--ipc=host" not in argv
    assert argv[argv.index("--network") + 1] == "bridge"
    assert "host" not in argv[argv.index("--network") + 1]
    assert f"{hosts_file.resolve()}:/etc/hosts:ro" in argv
    assert "ORCHESTRATOR_BEDROCK_PROXY_HOST=172.17.0.1" in argv
    assert "ORCHESTRATOR_BEDROCK_PROXY_PORT=45678" in argv
    assert "ORCHESTRATOR_EGRESS_PROJECT=sample" in argv
    assert "ORCHESTRATOR_TARGET_RELAY_KIND=vnc-direct" in argv
    assert "ORCHESTRATOR_TARGET_RELAY_ENDPOINT=vnc-approved" in argv
    assert "ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT=5902" in argv
    assert "ORCHESTRATOR_TARGET_RELAY_HOST=172.17.0.1" in argv
    assert "ORCHESTRATOR_TARGET_RELAY_PORT=45679" in argv
    assert f"ORCHESTRATOR_TARGET_RELAY_TOKEN={'t' * 43}" in argv
    assert f"HTTPS_PROXY={relay.proxy_url}" in argv
    assert "DAC_OVERRIDE" not in argv
    assert "do-not-copy-into-argv" not in text
    assert str(credentials.parent) in text


def test_dashboard_project_target_relay_uses_pinned_host_resolution_and_closes(
    monkeypatch, tmp_path
):
    from contextlib import contextmanager
    import orchestrator.runtime_runner as runtime_runner

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "127.0.0.1 localhost\n10.79.85.47 vnc-approved\n",
        encoding="utf-8",
    )
    transport = ProjectTransport("vnc-direct", "vnc-approved", 5902)
    lease = TargetRelayLease(
        kind="vnc-direct",
        endpoint="vnc-approved",
        destination_port=5902,
        bind_host="172.17.0.1",
        port=45679,
        client_network="172.17.0.0/16",
        token="r" * 43,
    )
    observed = []

    def describe(project_name, *, specs_root):
        observed.append(("describe", project_name, specs_root))
        return transport

    @contextmanager
    def connect(engine, *, transport, addresses):
        observed.append(("connect", engine, transport, addresses))
        try:
            yield lease
        finally:
            observed.append(("closed",))

    monkeypatch.setattr(runtime_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtime_runner, "describe_project_transport", describe)
    monkeypatch.setattr(runtime_runner, "target_connect_relay", connect)

    specs_root = tmp_path / "specs"
    with _project_target_relay(
        "/usr/bin/docker",
        project_name="sample-vnc",
        specs_root=specs_root,
        hosts_file=hosts_file,
    ) as actual:
        assert actual == lease
        assert observed[-1] == (
            "connect",
            "/usr/bin/docker",
            transport,
            ("10.79.85.47",),
        )
    assert observed[0] == ("describe", "sample-vnc", str(specs_root))
    assert observed[-1] == ("closed",)


def test_dashboard_non_vnc_project_does_not_start_target_relay(monkeypatch, tmp_path):
    import orchestrator.runtime_runner as runtime_runner

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    monkeypatch.setattr(runtime_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        runtime_runner,
        "describe_project_transport",
        lambda _project_name, *, specs_root: None,
    )
    monkeypatch.setattr(
        runtime_runner,
        "target_connect_relay",
        lambda *_args, **_kwargs: pytest.fail("target relay must not start"),
    )

    with _project_target_relay(
        "/usr/bin/docker",
        project_name="local-app",
        specs_root=tmp_path / "specs",
        hosts_file=hosts_file,
    ) as actual:
        assert actual is None


def test_dashboard_run_request_wires_exact_project_policy_and_target_relay(
    monkeypatch, tmp_path
):
    from contextlib import contextmanager
    import orchestrator.runtime_runner as runtime_runner

    repo = _runtime_repo(tmp_path)
    project_config = runtime_root(repo) / "tests_specs" / "sample-vnc" / "project.yaml"
    project_config.parent.mkdir()
    project_config.write_text("name: Sample VNC\n", encoding="utf-8")
    hosts_file = tmp_path / "private-hosts"
    hosts_file.write_text(
        "127.0.0.1 localhost\n"
        "192.0.2.10 bedrock-runtime.us-west-2.amazonaws.com\n"
        "10.79.85.47 vnc-approved\n",
        encoding="utf-8",
    )
    target_relay = TargetRelayLease(
        kind="vnc-direct",
        endpoint="vnc-approved",
        destination_port=5902,
        bind_host="172.17.0.1",
        port=45679,
        client_network="172.17.0.0/16",
        token="r" * 43,
    )
    bedrock_relay = BedrockRelayLease(
        endpoint="bedrock-runtime.us-west-2.amazonaws.com",
        bind_host="172.17.0.1",
        port=45678,
        client_network="172.17.0.0/16",
        proxy_url="http://runner:ephemeral-test-token@172.17.0.1:45678",
    )
    observed = {}

    monkeypatch.setattr(runtime_runner, "_repo_root", lambda: repo)
    monkeypatch.setattr(runtime_runner, "load_config", lambda _repo: RuntimeConfig())
    monkeypatch.setattr(runtime_runner, "resolve_engine", lambda _engine: "/usr/bin/docker")
    monkeypatch.setattr(runtime_runner, "engine_reachable", lambda _engine: (True, "ok"))
    monkeypatch.setattr(
        runtime_runner,
        "validate_image",
        lambda _repo, _config, _engine: SimpleNamespace(ready=True, detail="ready"),
    )
    monkeypatch.setattr(
        runtime_runner,
        "_request_command",
        lambda _repo, project, spec: (
            ["python", "-m", "orchestrator.runner", "--project", project],
            project_config,
        ),
    )

    @contextmanager
    def private_hosts(_repo, _config, *, project_name=None, include_bedrock=True):
        observed["private_hosts"] = (project_name, include_bedrock)
        yield hosts_file

    def policy(*, region, specs_root, project_name=None, include_bedrock=True):
        observed["policy"] = (region, specs_root, project_name, include_bedrock)
        return SimpleNamespace(bedrock="bedrock-runtime.us-west-2.amazonaws.com")

    @contextmanager
    def project_relay(engine, *, project_name, specs_root, hosts_file):
        observed["target_context"] = (engine, project_name, specs_root, hosts_file)
        yield target_relay

    @contextmanager
    def bedrock_context(engine, *, endpoint, addresses):
        observed["bedrock_context"] = (engine, endpoint, addresses)
        yield bedrock_relay

    @contextmanager
    def host_bridge(_repo, _config, config_path, reports, display):
        observed["host_bridge"] = (config_path, reports, display)
        yield [], None

    def build(*args, **kwargs):
        observed["build_args"] = args
        observed["build_kwargs"] = kwargs
        return ["/usr/bin/docker", "run"]

    def run(argv, *, cwd, check, shell):
        observed["run"] = (argv, cwd, check, shell)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(runtime_runner, "_private_hosts_file", private_hosts)
    monkeypatch.setattr(runtime_runner, "compute_policy", policy)
    monkeypatch.setattr(runtime_runner, "_project_target_relay", project_relay)
    monkeypatch.setattr(runtime_runner, "bedrock_connect_relay", bedrock_context)
    monkeypatch.setattr(runtime_runner, "_host_app_bridge", host_bridge)
    monkeypatch.setattr(runtime_runner, "build_runner_argv", build)
    monkeypatch.setattr(runtime_runner.subprocess, "run", run)
    monkeypatch.setattr(runtime_runner.platform, "system", lambda: "Linux")

    assert runtime_runner.run_request(project="sample-vnc") == 0
    assert observed["private_hosts"] == ("sample-vnc", True)
    assert observed["policy"][2:] == ("sample-vnc", True)
    assert observed["target_context"] == (
        "/usr/bin/docker",
        "sample-vnc",
        runtime_root(repo) / "tests_specs",
        hosts_file,
    )
    assert observed["bedrock_context"] == (
        "/usr/bin/docker",
        "bedrock-runtime.us-west-2.amazonaws.com",
        ("192.0.2.10",),
    )
    assert observed["build_kwargs"]["project_name"] == "sample-vnc"
    assert observed["build_kwargs"]["target_relay"] == target_relay
    assert observed["build_kwargs"]["bedrock_relay"] == bedrock_relay
    assert observed["run"] == (
        ["/usr/bin/docker", "run"],
        repo,
        False,
        False,
    )


def test_private_runner_hosts_file_is_bounded_readable_and_ephemeral(tmp_path):
    repo = _runtime_repo(tmp_path)
    with _private_hosts_file(
        repo,
        RuntimeConfig(),
        resolver=lambda _policy: [
            ("192.0.2.10", "bedrock-runtime.us-west-2.amazonaws.com"),
        ],
    ) as hosts_file:
        assert hosts_file.is_file() and not hosts_file.is_symlink()
        assert hosts_file.parent.name == "runner-hosts"
        assert hosts_file.read_text(encoding="utf-8") == (
            "127.0.0.1 localhost orchestrator-cookie-runner\n"
            "::1 localhost ip6-localhost ip6-loopback\n"
            "192.0.2.10 bedrock-runtime.us-west-2.amazonaws.com\n"
        )
        if os.name != "nt":
            assert stat.S_IMODE(hosts_file.stat().st_mode) == 0o644
            assert stat.S_IMODE(hosts_file.parent.stat().st_mode) == 0o700
    assert not hosts_file.exists()


def test_private_runner_hosts_file_fails_closed_before_creation(tmp_path):
    repo = _runtime_repo(tmp_path)

    def fail_resolution(_policy):
        from orchestrator.egress import EgressResolutionError

        raise EgressResolutionError("approved endpoint could not be resolved on the host")

    with pytest.raises(ConfigurationError, match="could not be resolved on the host"):
        with _private_hosts_file(repo, RuntimeConfig(), resolver=fail_resolution):
            pass

    hosts_root = runtime_root(repo) / "state" / "runner-hosts"
    assert not hosts_root.exists()


def test_dashboard_environment_does_not_put_tokens_in_urls_or_argv(tmp_path):
    repo = _runtime_repo(tmp_path)
    tokens = load_tokens(repo)
    env = dashboard_environment(repo, load_config(repo), instance_id="instance")
    assert env["DASHBOARD_AUTH_TOKEN"] == tokens["viewer_token"]
    assert "token=" not in env["ORCHESTRATOR_COOKIE_CONFIG"]
    assert env["TESTS_MANUALS_DIR"] == str(runtime_root(repo) / "tests_manuals")


def test_dashboard_environment_exports_managed_watch_learn_image(tmp_path, monkeypatch):
    repo = _runtime_repo(tmp_path)
    digest = "a" * 64
    image_ref = f"registry.example/orchestrator-cookie@sha256:{digest}"
    config = replace(
        load_config(repo),
        image=ImageSource(
            kind=ImageSourceKind.REFERENCE.value,
            image_ref=image_ref,
        ),
    )
    monkeypatch.setenv(
        "DASHBOARD_WATCH_LEARN_RUNNER_IMAGE",
        f"ambient.example/denied@sha256:{'b' * 64}",
    )

    env = dashboard_environment(repo, config, instance_id="instance")

    assert env["IMAGE"] == image_ref
    assert env["DASHBOARD_WATCH_LEARN_RUNNER_IMAGE"] == image_ref


def test_dashboard_environment_scrubs_unmanaged_watch_learn_image(tmp_path, monkeypatch):
    repo = _runtime_repo(tmp_path)
    monkeypatch.setenv(
        "DASHBOARD_WATCH_LEARN_RUNNER_IMAGE",
        f"ambient.example/denied@sha256:{'b' * 64}",
    )

    env = dashboard_environment(repo, load_config(repo), instance_id="instance")

    assert "DASHBOARD_WATCH_LEARN_RUNNER_IMAGE" not in env


def test_dashboard_environment_scrubs_ambient_profile_and_exports_managed_profile(tmp_path, monkeypatch):
    repo = _runtime_repo(tmp_path)
    credentials = tmp_path / "credentials"
    config_file = tmp_path / "config"
    credentials.write_text("[approved]\naws_access_key_id=x\naws_secret_access_key=y\n")
    config_file.write_text("[profile approved]\nregion=us-west-2\n")
    config = replace(
        load_config(repo),
        aws=AwsConfig(
            credentials_file=str(credentials), config_file=str(config_file),
            profile="approved", region="us-west-2", bedrock_model_id="model",
        ),
    )
    monkeypatch.setenv("AWS_PROFILE", "ambient-denied")
    env = dashboard_environment(repo, config, instance_id="instance")
    assert "AWS_PROFILE" not in env
    assert env["ORCHESTRATOR_AWS_PROFILE"] == "approved"
    assert env["DASHBOARD_AUTHORING_PROFILE"] == "approved"


def test_doctor_requires_the_exact_configured_aws_profile_sections(tmp_path):
    credentials = tmp_path / "credentials"
    config_file = tmp_path / "config"
    credentials.write_text("[approved]\naws_access_key_id=x\naws_secret_access_key=y\n")
    config_file.write_text("[profile approved]\nregion=us-west-2\n")
    credentials.chmod(0o600)
    config_file.chmod(0o600)
    good = RuntimeConfig(aws=AwsConfig(
        credentials_file=str(credentials), config_file=str(config_file),
        profile="approved", region="us-west-2", bedrock_model_id="model",
    ))
    assert _aws_profile_ready(good)[0] is True
    missing = replace(good, aws=replace(good.aws, profile="missing"))
    ready, detail = _aws_profile_ready(missing)
    assert ready is False
    assert "[missing]" in detail


def test_doctor_requires_default_section_when_no_profile_is_configured(tmp_path):
    credentials = tmp_path / "credentials"
    credentials.write_text("[named]\naws_access_key_id=x\naws_secret_access_key=y\n")
    credentials.chmod(0o600)
    config = RuntimeConfig(aws=AwsConfig(
        credentials_file=str(credentials), profile=None,
        region="us-west-2", bedrock_model_id="model",
    ))
    ready, detail = _aws_profile_ready(config)
    assert ready is False
    assert "[default]" in detail


def test_background_start_persists_only_nonsensitive_process_metadata(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    config = load_config(repo)
    fake_process = Mock(pid=43123)
    fake_process.poll.return_value = None
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.dashboard_status",
        lambda *_a: DashboardState(False, "stopped"),
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_a: True)
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._spawn_dashboard",
        lambda *_a, **_k: (fake_process, 0),
    )
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._await_startup",
        lambda *_a, **_k: StartupOutcome("healthy", "ok"),
    )
    state = start_dashboard(repo, config)
    assert state.running is True
    metadata = json.loads((runtime_root(repo) / "state" / "dashboard.json").read_text())
    assert metadata["pid"] == 43123
    assert set(metadata) == {"schema_version", "pid", "instance_id", "started_at", "bind_host", "port"}
    serialized = json.dumps(metadata)
    for token in load_tokens(repo).values():
        assert token not in serialized


def _mock_background_attempts(monkeypatch, outcomes):
    attempted_ports = []
    processes = []
    outcomes = iter(outcomes)

    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.dashboard_status",
        lambda *_a: DashboardState(False, "stopped"),
    )

    def spawn(_repo, actual, _instance_id, _log_path):
        attempted_ports.append(actual.port)
        process = Mock(pid=44000 + len(attempted_ports))
        process.poll.return_value = None
        processes.append(process)
        return process, 0

    monkeypatch.setattr("orchestrator_cookie.lifecycle._spawn_dashboard", spawn)
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._await_startup",
        lambda *_a, **_k: next(outcomes),
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._terminate_started_process", lambda *_a, **_k: None)
    return attempted_ports, processes


def test_preferred_port_available_is_selected(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    attempted, _ = _mock_background_attempts(
        monkeypatch, [StartupOutcome("healthy", "ok")]
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_a: True)
    state = start_dashboard(repo, load_config(repo))
    assert attempted == [8080]
    assert state.port == 8080
    assert load_config(repo).preferred_port == 8080


def test_occupied_preferred_port_selects_next_and_persists_actual(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    attempted, _ = _mock_background_attempts(
        monkeypatch, [StartupOutcome("healthy", "ok")]
    )
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._port_available",
        lambda _host, port: port != 8080,
    )
    state = start_dashboard(repo, load_config(repo))
    saved = load_config(repo)
    assert attempted == [8081]
    assert state.port == saved.port == 8081
    assert saved.preferred_port == 8080
    assert "fallback port 8081" in state.detail


def test_multiple_occupied_ports_select_first_sequential_candidate(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    attempted, _ = _mock_background_attempts(
        monkeypatch, [StartupOutcome("healthy", "ok")]
    )
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._port_available",
        lambda _host, port: port >= 8083,
    )
    state = start_dashboard(repo, load_config(repo))
    assert attempted == [8083]
    assert state.port == 8083


def test_existing_managed_dashboard_is_idempotent(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    (runtime_root(repo) / "state" / "dashboard.json").write_text("{}")
    running = DashboardState(True, "dashboard is running", 55, "http://127.0.0.1:8087", 8087)
    monkeypatch.setattr("orchestrator_cookie.lifecycle.dashboard_status", lambda *_a: running)
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._spawn_dashboard",
        lambda *_a, **_k: pytest.fail("must not spawn a second dashboard"),
    )
    assert start_dashboard(repo, load_config(repo)) is running


def test_probe_to_bind_race_retries_only_collision(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    attempted, _ = _mock_background_attempts(
        monkeypatch,
        [StartupOutcome("bind-collision", "raced"), StartupOutcome("healthy", "ok")],
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_a: True)
    state = start_dashboard(repo, load_config(repo))
    assert attempted == [8080, 8081]
    assert state.port == 8081


def test_unrelated_startup_failure_is_not_retried_or_persisted(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    before = (runtime_root(repo) / "config" / "runtime.json").read_bytes()
    attempted, _ = _mock_background_attempts(
        monkeypatch, [StartupOutcome("failed", "import failed")]
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_a: True)
    state = start_dashboard(repo, load_config(repo))
    assert state.running is False
    assert attempted == [8080]
    assert "import failed" in state.detail
    assert not (runtime_root(repo) / "state" / "dashboard.json").exists()
    assert (runtime_root(repo) / "config" / "runtime.json").read_bytes() == before


def test_actual_port_is_not_persisted_before_authenticated_health(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    before = load_config(repo)
    attempted, _ = _mock_background_attempts(
        monkeypatch, [StartupOutcome("timeout", "not healthy")]
    )
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle._port_available",
        lambda _host, port: port == 8084,
    )
    state = start_dashboard(repo, before, maximum_port=8084)
    assert attempted == [8084]
    assert state.running is False
    assert load_config(repo) == before
    assert not (runtime_root(repo) / "state" / "dashboard.json").exists()


def test_status_uses_actual_metadata_port(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    config = replace(load_config(repo), port=8084, preferred_port=8080)
    save_config(repo, config)
    metadata = {
        "schema_version": 1,
        "pid": 45555,
        "instance_id": "managed-instance",
        "started_at": "2026-08-25T00:00:00+00:00",
        "bind_host": "127.0.0.1",
        "port": 8084,
    }
    (runtime_root(repo) / "state" / "dashboard.json").write_text(json.dumps(metadata))
    seen = []

    def identity(endpoint, _token, timeout=1.5):
        seen.append((endpoint.port, timeout))
        return {"instance_id": "managed-instance", "pid": 45555}

    monkeypatch.setattr("orchestrator_cookie.lifecycle._runtime_identity", identity)
    state = dashboard_status(repo, config)
    assert state.running is True
    assert state.url == "http://127.0.0.1:8084"
    assert seen[0][0] == 8084


def test_port_exhaustion_and_invalid_range_are_actionable(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.dashboard_status",
        lambda *_a: DashboardState(False, "stopped"),
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._port_available", lambda *_a: False)
    with pytest.raises(ConfigurationError, match="no bindable dashboard port"):
        start_dashboard(repo, load_config(repo), maximum_port=8082)
    with pytest.raises(ConfigurationError, match="scan maximum"):
        list(_candidate_ports(8080, maximum=8079))


def test_bind_collision_detection_is_narrow():
    assert _is_bind_collision("ERROR [Errno 98] address already in use") is True
    assert _is_bind_collision("ModuleNotFoundError: dashboard") is False


def test_non_collision_bind_probe_error_is_actionable(monkeypatch):
    class DeniedSocket:
        def bind(self, _address):
            raise OSError(errno.EACCES, "permission denied")

        def close(self):
            pass

    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.socket.socket",
        lambda *_a, **_k: DeniedSocket(),
    )
    with pytest.raises(ConfigurationError, match="cannot test local bind availability"):
        _port_available("127.0.0.1", 80)


def test_dashboard_argv_has_actual_port_but_no_tokens(tmp_path):
    repo = _runtime_repo(tmp_path)
    config = replace(load_config(repo), port=8091)
    argv = _dashboard_argv(config)
    assert argv[argv.index("--port") + 1] == "8091"
    joined = " ".join(argv)
    for token in load_tokens(repo).values():
        assert token not in joined


def test_stop_requires_authenticated_instance_and_removes_metadata(monkeypatch, tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX process-group assertion")
    repo = _runtime_repo(tmp_path)
    config = load_config(repo)
    metadata = {
        "schema_version": 1,
        "pid": 43124,
        "instance_id": "instance",
        "started_at": "2026-08-25T00:00:00+00:00",
        "bind_host": "127.0.0.1",
        "port": 8080,
    }
    (runtime_root(repo) / "state" / "dashboard.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(
        "orchestrator_cookie.lifecycle.dashboard_status",
        lambda *_a: DashboardState(True, "running", 43124, "http://127.0.0.1:8080"),
    )
    monkeypatch.setattr("orchestrator_cookie.lifecycle._runtime_identity", lambda *_a, **_k: None)
    signalled = []
    monkeypatch.setattr("orchestrator_cookie.lifecycle.os.killpg", lambda pid, sig: signalled.append((pid, sig)))
    state = stop_dashboard(repo, config)
    assert state.running is False
    assert signalled and signalled[0][0] == 43124
    assert not (runtime_root(repo) / "state" / "dashboard.json").exists()


def test_host_app_configuration_requires_allow_roots():
    with pytest.raises(ConfigurationError):
        HostAppConfig(enabled=True).validate()
    HostAppConfig(enabled=True, allow_roots=("/opt/apps",)).validate()


def test_production_wrappers_are_thin_and_safe():
    shell = (REPO_ROOT / "install.sh").read_text()
    powershell = (REPO_ROOT / "install.ps1").read_text()
    cmd = (REPO_ROOT / "install.cmd").read_text()
    dashboard = (REPO_ROOT / "scripts" / "run_dashboard.sh").read_text()
    run_specs = (REPO_ROOT / "scripts" / "run_specs.sh").read_text()
    assert "scripts/installer.py" in shell
    assert "scripts\\installer.py" in powershell
    assert "managed environment exists but its Python is unusable" in shell
    assert "managed environment exists but its Python is unusable" in powershell
    assert "${1:-}" in shell
    assert "$ManagerArgs[0] -ne 'init'" in powershell
    assert "powershell.exe" in cmd.lower()
    assert '"%~dp0install.ps1" %*' in cmd
    assert 'DASHBOARD_HOST:-127.0.0.1' in dashboard
    assert 'DASHBOARD_RELOAD:-0' in dashboard
    assert "--reload" in dashboard  # available only behind explicit development opt-in
    assert '[[ -x "${RDP_PREWARM_SCRIPT}" ]]' in run_specs
    assert "optional RDP pre-warm helper is unavailable" in run_specs


def test_dependency_profiles_are_locked_and_testclient_is_test_only():
    runtime = (REPO_ROOT / "requirements-dashboard.txt").read_text()
    test = (REPO_ROOT / "requirements-test.txt").read_text()
    constraints = (REPO_ROOT / "constraints.txt").read_text()
    assert "httpx2" not in runtime
    assert "httpx2==2.10.0" in test
    assert "fastapi==0.141.1" in runtime
    assert "starlette==1.6.0" in runtime
    assert "pytest" not in (REPO_ROOT / "requirements.txt").read_text().lower()
    assert ">=" not in "\n".join(
        line for line in constraints.splitlines() if line and not line.startswith("#")
    )


def test_configure_port_resets_preferred_start(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    save_config(repo, replace(load_config(repo), port=8087, preferred_port=8080))
    assert cli.main(["configure", "--port", "8090", "--non-interactive"], repo_root=repo) == 0
    config = load_config(repo)
    assert config.port == 8090
    assert config.preferred_port == 8090


def test_doctor_is_read_only_and_explains_automatic_fallback(monkeypatch, tmp_path):
    repo = _runtime_repo(tmp_path)
    before = {
        path.relative_to(runtime_root(repo)): path.read_bytes()
        for path in runtime_root(repo).rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "orchestrator_cookie.doctor._port_available",
        lambda host, port: (False, f"{host}:{port} is occupied"),
    )
    monkeypatch.setattr("orchestrator_cookie.doctor.resolve_engine", lambda *_a: None)
    report = run_doctor(repo)
    finding = next(item for item in report.findings if item.code == "port")
    assert finding.severity == "WARN"
    assert "scan upward sequentially" in finding.summary
    assert "No action is required" in finding.remediation
    after = {
        path.relative_to(runtime_root(repo)): path.read_bytes()
        for path in runtime_root(repo).rglob("*")
        if path.is_file()
    }
    assert after == before


def test_cli_never_prints_generated_tokens(tmp_path, capsys):
    repo = tmp_path / "clone"
    repo.mkdir()
    assert cli.main(["init", "--skip-deps"], repo_root=repo) == 0
    tokens = load_tokens(repo)
    output = capsys.readouterr().out
    assert tokens["viewer_token"] not in output
    assert tokens["operator_token"] not in output


def test_uninstall_keeps_user_data_without_explicit_purge(tmp_path):
    repo = _runtime_repo(tmp_path)
    report = runtime_root(repo) / "reports" / "important.txt"
    report.write_text("keep")
    secret = runtime_root(repo) / "secrets" / "target.pw"
    secret.write_text("keep")
    cli._remove_generated(repo, purge_user_data=False, confirmation=None)
    assert report.read_text() == "keep"
    assert secret.read_text() == "keep"


def test_uninstall_purge_requires_exact_confirmation(tmp_path):
    repo = _runtime_repo(tmp_path)
    with pytest.raises(ConfigurationError, match="requires"):
        cli._remove_generated(repo, purge_user_data=True, confirmation="yes")
    assert runtime_root(repo).is_dir()


def test_dashboard_settings_default_to_loopback(monkeypatch):
    monkeypatch.delenv("DASHBOARD_HOST", raising=False)
    from dashboard.config import DashboardSettings

    assert DashboardSettings().host == "127.0.0.1"
    with pytest.raises(RuntimeError):
        DashboardSettings(host="0.0.0.0", auth_token=None).require_safe_binding()


def test_rdp_source_has_vetted_args_and_no_certificate_bypass():
    source = (REPO_ROOT / "src" / "orchestrator" / "targets.py").read_text()
    command_section = source[source.index("cmd = [", source.index("def _open_rdp")) : source.index("user =", source.index("def _open_rdp"))]
    assert '"/gdi:sw"' in command_section
    assert '"/network:auto"' in command_section
    assert '"/timeout:30000"' in command_section
    assert '"/cert:ignore"' not in command_section
    assert 'f"/cert:deny,name:{certificate_name},"' in source
    assert 'f"fingerprint:{client_fingerprint}"' in source
    assert "rdp target requires a reviewed certificate_name" in source
    assert "rdp target requires a reviewed sha256 or sha1 certificate_fingerprint" in source
    assert 'f"/server-name:{host}"' not in source
