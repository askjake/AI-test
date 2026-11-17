"""Cross-platform dashboard lifecycle with authenticated actual-port state."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import (
    ConfigurationError,
    ImageSourceKind,
    PROCESS_RELATIVE,
    RuntimeConfig,
    atomic_write_json,
    load_tokens,
    runtime_root,
    save_config,
    validate_bind_host,
)
from .portcheck import PortProbeError, port_available as _probe_port_available
from .config import ConfigurationError as _CP45NConfigurationError  # CP45-N
from .switch_guard import require_resolved as _require_switch_resolved  # CP45-R


@dataclass(frozen=True)
class DashboardState:
    running: bool
    detail: str
    pid: int | None = None
    url: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class StartupOutcome:
    state: str
    detail: str


def _display_host(host: str) -> str:
    if host == "0.0.0.0":
        return "127.0.0.1"
    if host == "::":
        return "::1"
    return host


def local_url(config: RuntimeConfig, *, port: int | None = None) -> str:
    host = _display_host(config.bind_host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port if port is not None else config.port}"


def _runtime_identity(config: RuntimeConfig, token: str, timeout: float = 1.5) -> dict | None:
    request = Request(
        f"{local_url(config)}/api/v1/runtime-identity",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read(4096).decode("utf-8"))
    except (OSError, HTTPError, URLError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def read_process_metadata(repo_root: Path) -> dict[str, Any] | None:
    path = runtime_root(repo_root) / PROCESS_RELATIVE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _metadata_endpoint(config: RuntimeConfig, metadata: dict[str, Any]) -> RuntimeConfig | None:
    bind_host = metadata.get("bind_host")
    port = metadata.get("port")
    if bind_host != config.bind_host or not isinstance(port, int) or not 1 <= port <= 65535:
        return None
    endpoint = replace(config, port=port)
    try:
        endpoint.validate()
    except ConfigurationError:
        return None
    return endpoint


def dashboard_status(repo_root: Path, config: RuntimeConfig) -> DashboardState:
    metadata = read_process_metadata(repo_root)
    preferred_url = local_url(config, port=config.preferred_port)
    if not metadata:
        return DashboardState(False, "dashboard is stopped", url=preferred_url, port=config.preferred_port)
    pid = metadata.get("pid")
    instance_id = metadata.get("instance_id")
    endpoint = _metadata_endpoint(config, metadata)
    if (
        not isinstance(pid, int)
        or pid <= 1
        or not isinstance(instance_id, str)
        or endpoint is None
    ):
        return DashboardState(False, "dashboard metadata is invalid", url=preferred_url, port=config.preferred_port)
    actual_url = local_url(endpoint)
    try:
        tokens = load_tokens(repo_root)
    except ConfigurationError:
        return DashboardState(False, "dashboard token file is unavailable", pid, actual_url, endpoint.port)
    identity = _runtime_identity(endpoint, tokens["viewer_token"])
    if identity and identity.get("instance_id") == instance_id and identity.get("pid") == pid:
        return DashboardState(True, "dashboard is running", pid, actual_url, endpoint.port)
    return DashboardState(False, "recorded dashboard process is not responding", pid, actual_url, endpoint.port)


def dashboard_environment(
    repo_root: Path,
    config: RuntimeConfig,
    *,
    instance_id: str,
) -> dict[str, str]:
    if config.trigger_backend != "spawn":   # CP45-N: refuse BEFORE any environment, process or log is created
        raise _CP45NConfigurationError("trigger_backend must be 'spawn': the 'watcher' backend is not supported under the 0755 report permission contract")
    _require_switch_resolved(runtime_root(repo_root) / "reports")   # CP45-R: before any environment, process, log or directory
    tokens = load_tokens(repo_root)
    root = runtime_root(repo_root)
    env = dict(os.environ)
    # Shared no-login mode is clone-local and explicitly enabled by its owner.
    marker = root / "config" / "shared-operator.enabled"
    enabled = marker.is_file() and not marker.is_symlink() and marker.read_text().strip() == "enabled"
    env["DASHBOARD_SHARED_OPERATOR_MODE"] = "true" if enabled else "false"
    # Managed configuration owns profile selection. An ambient shell profile
    # must never silently choose another account inside the dashboard/runner.
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)
    for key in list(env):
        if key.startswith("DASHBOARD_OIDC_"):
            env.pop(key, None)
    # The managed image configuration is the only authority for Watch & Learn.
    # Never inherit an unrelated shell override into the long-lived dashboard.
    env.pop("DASHBOARD_WATCH_LEARN_RUNNER_IMAGE", None)
    source_path = str(repo_root / "src")
    prior_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path + (os.pathsep + prior_pythonpath if prior_pythonpath else "")
    env.update(
        {
            "DASHBOARD_HOST": config.bind_host,
            "DASHBOARD_PORT": str(config.port),
            "DASHBOARD_AUTH_TOKEN": tokens["viewer_token"],
            "DASHBOARD_AUTH_OPERATOR_TOKEN": tokens["operator_token"],
            "DASHBOARD_REPORTS_DIR": str(root / "reports"),
            "DASHBOARD_SPECS_DIR": str(root / "tests_specs"),
            "TESTS_MANUALS_DIR": str(root / "tests_manuals"),
            "DASHBOARD_SECRETS_DIR": str(root / "secrets"),
            "DASHBOARD_AUTHORING_STATE_ROOT": str(root / "state" / "authoring"),
            "DASHBOARD_WIZARD_STATE_ROOT": str(root / "state" / "authoring"),
            "DASHBOARD_AUTHORING_GUIDANCE_ROOT": str(repo_root / "authoring_guidance"),
            "DASHBOARD_WIZARD_BLUEPRINT_ROOT": str(repo_root / "project_blueprints"),
            "DASHBOARD_TRIGGER_BACKEND": config.trigger_backend,
            "DASHBOARD_AUTH_AUDIT_PATH": str(root / "state" / "authentication_audit.jsonl"),
            "DASHBOARD_PROJECT_IMPORT_ROOTS": json.dumps(
                [item.__dict__ for item in config.project_import_roots]
            ),
            "DASHBOARD_PROJECT_IMPORT_AUDIT_PATH": str(
                root / "state" / "project_import_audit.jsonl"
            ),
            "DASHBOARD_SESSION_TTL_SECONDS": str(config.oidc.session_ttl_seconds),
            "DASHBOARD_OIDC_ENABLED": "true" if config.oidc.enabled else "false",
            "DASHBOARD_OIDC_ROLE_CLAIM": config.oidc.role_claim,
            "DASHBOARD_OIDC_VIEWER_VALUES": json.dumps(config.oidc.viewer_values),
            "DASHBOARD_OIDC_OPERATOR_VALUES": json.dumps(config.oidc.operator_values),
            "DASHBOARD_OIDC_IDENTITY_CLAIM": config.oidc.identity_claim,
            "DASHBOARD_OIDC_SCOPES": json.dumps(config.oidc.scopes),
            "DASHBOARD_OIDC_SIGNING_ALGORITHMS": json.dumps(config.oidc.signing_algorithms),
            "DASHBOARD_OIDC_TLS_TERMINATED": "true" if config.oidc.tls_terminated else "false",
            "DASHBOARD_OIDC_PROVIDER_LABEL": config.oidc.provider_label,
            "DASHBOARD_OIDC_TEST_ONLY": "true" if config.oidc.test_only else "false",
            "DASHBOARD_OIDC_TRUSTED_PROXY_CIDRS": json.dumps(config.oidc.trusted_proxy_cidrs),
            "ORCHESTRATOR_COOKIE_RUNTIME_ROOT": str(root),
            "ORCHESTRATOR_COOKIE_CONFIG": str(root / "config" / "runtime.json"),
            "ORCHESTRATOR_COOKIE_INSTANCE_ID": instance_id,
        }
    )
    if config.oidc.issuer:
        env["DASHBOARD_OIDC_ISSUER"] = config.oidc.issuer
    if config.oidc.client_id:
        env["DASHBOARD_OIDC_CLIENT_ID"] = config.oidc.client_id
    if config.oidc.redirect_uri:
        env["DASHBOARD_OIDC_REDIRECT_URI"] = config.oidc.redirect_uri
    if config.oidc.client_secret_file:
        env["DASHBOARD_OIDC_CLIENT_SECRET_FILE"] = config.oidc.client_secret_file
    if config.oidc.ca_file:
        env["DASHBOARD_OIDC_CA_FILE"] = config.oidc.ca_file
    if config.engine:
        env["ENGINE"] = config.engine
    env["IMAGE"] = config.image.image_ref
    if config.image.kind == ImageSourceKind.REFERENCE.value:
        # Reference sources are validated as immutable digest-pinned references.
        # The capture adapter independently verifies that this exact digest is
        # present in the local engine before it contacts a target.
        env["DASHBOARD_WATCH_LEARN_RUNNER_IMAGE"] = config.image.image_ref
    if config.aws.credentials_file:
        env["ORCHESTRATOR_AWS_CREDENTIALS_FILE"] = config.aws.credentials_file
        env["DASHBOARD_AUTHORING_SHARED_CREDENTIALS_FILE"] = config.aws.credentials_file
    if config.aws.config_file:
        env["ORCHESTRATOR_AWS_CONFIG_FILE"] = config.aws.config_file
        env["DASHBOARD_AUTHORING_SHARED_CONFIG_FILE"] = config.aws.config_file
    if config.aws.profile:
        env["ORCHESTRATOR_AWS_PROFILE"] = config.aws.profile
        env["DASHBOARD_AUTHORING_PROFILE"] = config.aws.profile
    if config.aws.bedrock_model_id:
        env["BEDROCK_MODEL_ID"] = config.aws.bedrock_model_id
        env["DASHBOARD_AUTHORING_MODEL_ID"] = config.aws.bedrock_model_id
    env["AWS_REGION"] = config.aws.region
    env["AWS_DEFAULT_REGION"] = config.aws.region
    env["DASHBOARD_AUTHORING_REGION"] = config.aws.region
    if config.aws.credentials_file and config.aws.config_file and config.aws.profile and config.aws.bedrock_model_id:
        env["DASHBOARD_AUTHORING_REFINEMENT_ENABLED"] = "true"
    if config.host_app.enabled:
        env["HOST_APP_ENABLED"] = "1"
        env["HOST_APP_ALLOW_ROOTS"] = os.pathsep.join(config.host_app.allow_roots)
    return env


def _popen_session_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _port_available(host: str, port: int) -> bool:
    """True when a dashboard may bind: free, or no listener is detected.

    A live listener is never "available".  See portcheck for the platform rules
    (SO_REUSEADDR is never used on Windows).
    """
    try:
        return _probe_port_available(host, port)
    except PortProbeError as exc:
        raise ConfigurationError(
            f"cannot test local bind availability for {host}:{port} ({type(exc.original).__name__})"
        ) from exc.original


def _candidate_ports(preferred_port: int, *, maximum: int = 65535) -> Iterator[int]:
    if not 1 <= preferred_port <= maximum <= 65535:
        raise ConfigurationError("preferred port or scan maximum is invalid")
    yield from range(preferred_port, maximum + 1)


def _dashboard_argv(config: RuntimeConfig) -> list[str]:
    argv = [
        sys.executable,
        "-m",
        "uvicorn",
        "dashboard.app:app",
        "--host",
        config.bind_host,
        "--port",
        str(config.port),
        "--log-level",
        "info",
    ]
    if config.oidc.trusted_proxy_cidrs:
        argv.extend([
            "--proxy-headers",
            "--forwarded-allow-ips",
            ",".join(config.oidc.trusted_proxy_cidrs),
        ])
    else:
        argv.append("--no-proxy-headers")
    return argv


def _spawn_dashboard(
    repo_root: Path,
    config: RuntimeConfig,
    instance_id: str,
    log_path: Path,
) -> tuple[subprocess.Popen, int]:
    env = dashboard_environment(repo_root, config, instance_id=instance_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        offset = log_path.stat().st_size
    except FileNotFoundError:
        offset = 0
    with log_path.open("ab", buffering=0) as log_handle:
        process = subprocess.Popen(
            _dashboard_argv(config),
            cwd=repo_root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            shell=False,
            **_popen_session_kwargs(),
        )
    return process, offset


def _log_tail_from(path: Path, offset: int, *, maximum: int = 65536) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            return handle.read(maximum).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _is_bind_collision(log_text: str) -> bool:
    lowered = log_text.lower()
    indicators = (
        "address already in use",
        "only one usage of each socket address",
        "winerror 10048",
        "errno 98",
        "errno 48",
    )
    return any(value in lowered for value in indicators)


def _await_startup(
    process: subprocess.Popen,
    config: RuntimeConfig,
    *,
    token: str,
    instance_id: str,
    wait_seconds: float,
    log_path: Path,
    log_offset: int,
) -> StartupOutcome:
    deadline = time.monotonic() + max(0.25, wait_seconds)
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            log_text = _log_tail_from(log_path, log_offset)
            if _is_bind_collision(log_text):
                return StartupOutcome("bind-collision", "port was claimed during startup")
            return StartupOutcome(
                "failed",
                f"dashboard exited during startup with status {returncode}",
            )
        identity = _runtime_identity(config, token, timeout=0.3)
        if identity and identity.get("instance_id") == instance_id and identity.get("pid") == process.pid:
            return StartupOutcome("healthy", "authenticated runtime identity is healthy")
        time.sleep(0.1)
    return StartupOutcome("timeout", "dashboard did not become ready before the startup deadline")


def _terminate_started_process(process: subprocess.Popen, *, grace_seconds: float = 2.0) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=max(0.1, grace_seconds))
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass


def _persist_healthy_state(
    repo_root: Path,
    original: RuntimeConfig,
    actual: RuntimeConfig,
    *,
    process: subprocess.Popen,
    instance_id: str,
) -> None:
    state_path = runtime_root(repo_root) / PROCESS_RELATIVE
    metadata = {
        "schema_version": 1,
        "pid": process.pid,
        "instance_id": instance_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "bind_host": actual.bind_host,
        "port": actual.port,
    }
    try:
        atomic_write_json(state_path, metadata)
        save_config(repo_root, actual)
    except BaseException:
        try:
            state_path.unlink()
        except FileNotFoundError:
            pass
        try:
            save_config(repo_root, original)
        except Exception:
            pass
        _terminate_started_process(process)
        raise


def start_dashboard(
    repo_root: Path,
    config: RuntimeConfig,
    *,
    foreground: bool = False,
    wait_seconds: float = 12.0,
    maximum_port: int = 65535,
) -> DashboardState:
    if config.trigger_backend != "spawn":   # CP45-N: refuse BEFORE any environment, process or log is created
        raise _CP45NConfigurationError("trigger_backend must be 'spawn': the 'watcher' backend is not supported under the 0755 report permission contract")
    _require_switch_resolved(runtime_root(repo_root) / "reports")   # CP45-R: before tokens, logs, ports or processes
    config.validate()
    if not validate_bind_host(config.bind_host):
        load_tokens(repo_root)  # Mandatory and validated before any non-loopback bind.
    existing_metadata = read_process_metadata(repo_root)
    existing = dashboard_status(repo_root, config)
    if existing.running:
        return existing
    if existing_metadata:
        raise ConfigurationError(
            "managed dashboard metadata exists but cannot be authenticated; no process was changed"
        )

    log_path = runtime_root(repo_root) / "logs" / "dashboard.log"
    tokens = load_tokens(repo_root)
    candidate_ports = (
        _candidate_ports(config.preferred_port, maximum=maximum_port)
        if config.port_fallback_enabled
        else iter((config.preferred_port,))
    )
    for port in candidate_ports:
        if not _port_available(config.bind_host, port):
            continue
        actual = replace(config, port=port)
        instance_id = secrets.token_urlsafe(24)
        if foreground:
            returncode = subprocess.call(
                _dashboard_argv(actual),
                cwd=repo_root,
                env=dashboard_environment(repo_root, actual, instance_id=instance_id),
                shell=False,
            )
            return DashboardState(
                False,
                f"foreground dashboard exited with status {returncode}; foreground runs are not persisted or managed",
                url=local_url(actual),
                port=port,
            )

        process, log_offset = _spawn_dashboard(repo_root, actual, instance_id, log_path)
        outcome = _await_startup(
            process,
            actual,
            token=tokens["viewer_token"],
            instance_id=instance_id,
            wait_seconds=wait_seconds,
            log_path=log_path,
            log_offset=log_offset,
        )
        if outcome.state == "bind-collision":
            continue
        if outcome.state != "healthy":
            _terminate_started_process(process)
            return DashboardState(
                False,
                f"{outcome.detail}; inspect {log_path}",
                process.pid,
                local_url(actual),
                port,
            )
        try:
            _persist_healthy_state(
                repo_root,
                config,
                actual,
                process=process,
                instance_id=instance_id,
            )
        except OSError as exc:
            return DashboardState(
                False,
                f"dashboard was healthy but state persistence failed ({type(exc).__name__}); process was stopped",
                process.pid,
                local_url(actual),
                port,
            )
        detail = "dashboard is running"
        if port != config.preferred_port:
            detail += f" on fallback port {port} (preferred {config.preferred_port} was unavailable)"
        return DashboardState(True, detail, process.pid, local_url(actual), port)

    if not config.port_fallback_enabled:
        raise ConfigurationError(
            f"required dashboard port {config.bind_host}:{config.preferred_port} is unavailable"
        )
    raise ConfigurationError(
        f"no bindable dashboard port exists from {config.preferred_port} through {maximum_port} on {config.bind_host}"
    )


def stop_dashboard(repo_root: Path, config: RuntimeConfig, *, grace_seconds: float = 8.0) -> DashboardState:
    metadata = read_process_metadata(repo_root)
    state_path = runtime_root(repo_root) / PROCESS_RELATIVE
    if not metadata:
        return DashboardState(
            False,
            "dashboard is already stopped",
            url=local_url(config, port=config.preferred_port),
            port=config.preferred_port,
        )
    endpoint = _metadata_endpoint(config, metadata)
    if endpoint is None:
        raise ConfigurationError("dashboard metadata endpoint is invalid; refusing to signal any PID")
    state = dashboard_status(repo_root, config)
    if not state.running:
        raise ConfigurationError(
            "refusing to signal a PID whose authenticated runtime identity cannot be verified"
        )
    assert state.pid is not None
    try:
        if os.name == "nt":
            os.kill(state.pid, signal.SIGTERM)
        else:
            os.killpg(state.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + max(0.0, grace_seconds)
    token = load_tokens(repo_root)["viewer_token"]
    while time.monotonic() < deadline:
        if _runtime_identity(endpoint, token, timeout=0.3) is None:
            break
        time.sleep(0.1)
    else:
        try:
            if os.name == "nt":
                os.kill(state.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            else:
                os.killpg(state.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        state_path.unlink()
    except FileNotFoundError:
        pass
    return DashboardState(False, "dashboard stopped", state.pid, state.url, state.port)
