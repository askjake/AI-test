"""Actionable, side-effect-free deployment diagnostics and capability matrix."""
from __future__ import annotations

from dataclasses import dataclass
import configparser
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import sys
from typing import Iterable

from .config import (
    CONFIG_RELATIVE,
    TOKEN_RELATIVE,
    ConfigurationError,
    RuntimeConfig,
    load_config,
    load_tokens,
    runtime_root,
    normalize_project_import_root,
    validate_bind_host,
)
from .image import engine_reachable, resolve_engine, validate_image
from .lifecycle import dashboard_status
from .local_oidc import load_local_oidc_state, local_oidc_status
from .dependencies import RUNTIME_PROFILE, TEST_PROFILE, environment_readiness
from .python_selection import is_supported_python, python_remediation


@dataclass(frozen=True)
class PlatformInfo:
    system: str
    machine: str
    python: tuple[int, int, int]


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    summary: str
    remediation: str | None = None


@dataclass(frozen=True)
class Capability:
    name: str
    state: str
    explanation: str


@dataclass(frozen=True)
class DoctorReport:
    platform: PlatformInfo
    findings: tuple[Finding, ...]
    capabilities: tuple[Capability, ...]


def detect_platform(
    *,
    system: str | None = None,
    machine: str | None = None,
    python: tuple[int, int, int] | None = None,
) -> PlatformInfo:
    return PlatformInfo(
        system=system or platform.system(),
        machine=machine or platform.machine(),
        python=python or sys.version_info[:3],
    )


def _port_available(host: str, port: int) -> tuple[bool, str]:
    from .portcheck import CLOSING, PortProbeError, probe_port

    try:
        result = probe_port(host, port)
    except PortProbeError as exc:
        return False, f"{host}:{port} cannot be tested ({type(exc.original).__name__})"
    if result.state == CLOSING:
        return True, f"{host}:{port} is available (no listener detected; a plain bind is refused but a server-style bind works)"
    if not result.bindable:
        return False, f"{host}:{port} is already in use or cannot be bound"
    return True, f"{host}:{port} is available"


def _regular_private_file(path: str | None, label: str) -> tuple[bool, str]:
    if not path:
        return False, f"{label} is not configured"
    candidate = Path(path).expanduser()
    if candidate.is_symlink() or not candidate.is_file():
        return False, f"{label} is not a regular non-symlink file"
    if os.name != "nt" and stat.S_IMODE(candidate.stat().st_mode) & 0o077:
        return False, f"{label} is readable by another user"
    return True, f"{label} exists with an acceptable file type"


def _aws_profile_ready(config: RuntimeConfig) -> tuple[bool, str]:
    """Validate section identity without invoking AWS or reading secret values."""
    credentials_ok, detail = _regular_private_file(
        config.aws.credentials_file, "AWS credentials file"
    )
    if not credentials_ok:
        return False, detail
    parser = configparser.RawConfigParser(interpolation=None)
    try:
        with Path(config.aws.credentials_file or "").expanduser().open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error, UnicodeError):
        return False, "AWS credentials file is not valid shared-credentials INI"
    profile = config.aws.profile or "default"
    if not parser.has_section(profile):
        return False, f"AWS credentials file has no [{profile}] profile section"
    if config.aws.profile and config.aws.config_file:
        config_ok, config_detail = _regular_private_file(config.aws.config_file, "AWS config file")
        if not config_ok:
            return False, config_detail
        config_parser = configparser.RawConfigParser(interpolation=None)
        try:
            with Path(config.aws.config_file).expanduser().open(encoding="utf-8") as handle:
                config_parser.read_file(handle)
        except (OSError, configparser.Error, UnicodeError):
            return False, "AWS config file is not valid shared-config INI"
        named = f"profile {config.aws.profile}"
        if not (config_parser.has_section(named) or config_parser.has_section(config.aws.profile)):
            return False, f"AWS config file has no [{named}] section"
    return True, f"AWS profile [{profile}] exists in the configured private files"


def _capability_matrix(
    info: PlatformInfo,
    *,
    initialized: bool,
    dependencies: bool,
    engine_ok: bool,
    image_ok: bool,
    model_configured: bool,
    host_app_enabled: bool,
    project_import_ready: bool = False,
) -> tuple[Capability, ...]:
    dashboard_ready = initialized and dependencies
    remote_ready = dashboard_ready and engine_ok and image_ok
    host_supported = info.system == "Linux"
    return (
        Capability(
            "Dashboard access",
            "READY" if dashboard_ready else "BLOCKED",
            "Local authoring, wizard, reports, screenshots, and live display. Network targets are not contacted.",
        ),
        Capability(
            "Runner image",
            "READY" if engine_ok and image_ok else "BLOCKED",
            "Verified container engine plus verified image provenance; this does not prove target reachability.",
        ),
        Capability(
            "Remote RDP/VNC/SSH targets",
            "READY" if remote_ready else "BLOCKED",
            "Runs in the Linux runner container on all host OSes. Reachability and allowlists remain separate gates.",
        ),
        Capability(
            "AWS/model execution",
            "CONFIGURED_NOT_PROBED" if model_configured else "BLOCKED",
            "Doctor never invokes Bedrock. Explicit GUI refinement/run actions remain the only model calls.",
        ),
        Capability(
            "Linux host-app",
            "READY" if remote_ready and host_supported and host_app_enabled else "UNAVAILABLE",
            "Linux-only, explicitly enabled, path-allowlisted bridge; unavailable on macOS and Windows.",
        ),
        Capability(
            "Project-folder import",
            "READY" if dashboard_ready and project_import_ready else "UNAVAILABLE",
            "Operator-only browsing of configured server roots; no target or model activity.",
        ),
    )


def run_doctor(repo_root: Path) -> DoctorReport:
    info = detect_platform()
    findings: list[Finding] = []
    supported_os = info.system in {"Linux", "Darwin", "Windows"}
    findings.append(
        Finding(
            "PASS" if supported_os else "BLOCK",
            "platform",
            f"host platform: {info.system} {info.machine}",
            None if supported_os else "Use macOS, Windows, or Linux.",
        )
    )
    py_ok = is_supported_python(info.python)
    resolved_python = os.environ.get("ORCHESTRATOR_RESOLVED_PYTHON")
    python_summary = f"Python {'.'.join(str(value) for value in info.python)}"
    if resolved_python:
        python_summary += f" selected by the install wrapper ({resolved_python})"
    findings.append(
        Finding(
            "PASS" if py_ok else "BLOCK",
            "python",
            python_summary,
            None if py_ok else python_remediation(info.system),
        )
    )

    initialized = (runtime_root(repo_root) / CONFIG_RELATIVE).is_file()
    if not initialized:
        findings.append(
            Finding(
                "BLOCK",
                "runtime",
                "per-clone runtime is not initialized",
                "Run install.sh init (macOS/Linux) or .\\install.ps1 init (Windows).",
            )
        )
        config = RuntimeConfig()
    else:
        try:
            config = load_config(repo_root)
            load_tokens(repo_root)
            findings.append(Finding("PASS", "runtime", "runtime configuration and tokens are valid"))
        except ConfigurationError as exc:
            config = RuntimeConfig()
            findings.append(Finding("BLOCK", "runtime", str(exc), "Run configure or regenerate tokens."))

    runtime_environment = environment_readiness(repo_root, RUNTIME_PROFILE)
    deps_ok = runtime_environment.ready
    findings.append(
        Finding(
            "PASS" if deps_ok else "BLOCK",
            "dashboard-dependencies",
            runtime_environment.detail,
            None if deps_ok else "Run init through the platform install wrapper to repair the managed environment.",
        )
    )
    test_environment = environment_readiness(repo_root, TEST_PROFILE)
    findings.append(
        Finding(
            "PASS" if test_environment.ready else "WARN",
            "developer-test-dependencies",
            test_environment.detail,
            None if test_environment.ready else "Run install init --with-test before full-suite validation.",
        )
    )
    try:
        loopback = validate_bind_host(config.bind_host)
        binding_safe = loopback or (config.lan_enabled and initialized)
    except ConfigurationError:
        binding_safe = False
        loopback = False
    findings.append(
        Finding(
            "PASS" if binding_safe else "BLOCK",
            "binding",
            (
                f"dashboard binding is {'loopback-only' if loopback else 'explicit LAN'} at "
                f"{config.bind_host}:{config.preferred_port} (preferred start)"
            ),
            None if binding_safe else "Use configure --loopback or explicitly enable LAN binding.",
        )
    )
    findings.append(
        Finding(
            "PASS" if initialized and deps_ok and binding_safe else "BLOCK",
            "dashboard-bootstrap",
            (
                "dashboard-only prerequisites are ready; a container engine is optional until project work"
                if initialized and deps_ok and binding_safe
                else "dashboard-only prerequisites require runtime, dependencies, and a safe binding"
            ),
            None if initialized and deps_ok and binding_safe else "Resolve runtime, dashboard-dependencies, and binding findings; Docker is a separate gate.",
        )
    )
    preferred_port = getattr(config, "preferred_port", config.port)
    try:
        managed = dashboard_status(repo_root, config)
    except ConfigurationError:
        managed = None
    if managed is not None and managed.running and managed.port == preferred_port:
        port_ok = True
        port_detail = (
            f"{config.bind_host}:{preferred_port} is occupied by the authenticated managed dashboard"
        )
    else:
        port_ok, port_detail = _port_available(config.bind_host, preferred_port)
    findings.append(
        Finding(
            "PASS" if port_ok else ("WARN" if config.port_fallback_enabled else "BLOCK"),
            "port",
            (
                f"preferred port {port_detail}"
                if port_ok
                else (
                    f"preferred port {port_detail}; start will scan upward sequentially without affecting the occupant"
                    if config.port_fallback_enabled
                    else f"required exact port {port_detail}; fallback is disabled for this deployment"
                )
            ),
            (
                None
                if port_ok
                else "No action is required; start will select the next locally bindable port."
                if config.port_fallback_enabled
                else "Free the required port before starting the dashboard."
            ),
        )
    )

    engine = resolve_engine(config.engine)
    engine_ok = False
    if engine:
        engine_ok, detail = engine_reachable(engine)
        findings.append(
            Finding(
                "PASS" if engine_ok else "BLOCK",
                "container-engine",
                detail,
                None if engine_ok else "Start Docker Desktop/Docker/Podman and rerun doctor.",
            )
        )
    else:
        findings.append(
            Finding(
                "BLOCK",
                "container-engine",
                "Docker or Podman was not found",
                "Install Docker Desktop on macOS/Windows, or Docker/Podman on Linux.",
            )
        )

    image_ok = False
    if engine_ok:
        image_state = validate_image(repo_root, config, engine)  # no acquisition or pull
        image_ok = image_state.ready
        findings.append(
            Finding(
                "PASS" if image_ok else "BLOCK",
                "runner-image",
                image_state.detail,
                None if image_ok else "Configure a verified source, then run acquire-image explicitly.",
            )
        )
    else:
        findings.append(
            Finding(
                "BLOCK",
                "runner-image",
                "runner image cannot be validated until the engine is reachable",
                "Resolve the container-engine finding first.",
            )
        )

    if not config.oidc.enabled:
        findings.append(
            Finding(
                "BLOCK",
                "organization-sign-in",
                "OIDC organization sign-in is not configured",
                "Configure an approved provider or explicitly provision the packaged local test identity.",
            )
        )
    else:
        secret_ok = True
        secret_detail = "public PKCE client"
        if config.oidc.client_secret_file:
            secret_ok, secret_detail = _regular_private_file(
                config.oidc.client_secret_file,
                "OIDC client secret file",
            )
        ca_ok = True
        ca_detail = "system trust store"
        if config.oidc.ca_file:
            candidate = Path(config.oidc.ca_file).expanduser()
            ca_ok = candidate.is_file() and not candidate.is_symlink()
            ca_detail = (
                "configured OIDC CA certificate exists"
                if ca_ok
                else "configured OIDC CA certificate is unavailable"
            )
        if config.oidc.test_only:
            try:
                local_state = load_local_oidc_state(repo_root, required=True)
                assert local_state is not None
                stack = local_oidc_status(repo_root)
                local_ok = stack.ready
                local_detail = stack.detail
            except ConfigurationError as exc:
                local_ok = False
                local_detail = str(exc)
            ready = secret_ok and ca_ok and local_ok
            findings.append(
                Finding(
                    "PASS" if ready else "BLOCK",
                    "organization-sign-in",
                    (
                        "packaged test-only OIDC material and containers are ready; "
                        "provider discovery was not contacted"
                        if ready
                        else f"packaged test-only OIDC is incomplete: {local_detail}; {secret_detail}; {ca_detail}"
                    ),
                    None if ready else "Run local-oidc provision or local-oidc start, then rerun doctor.",
                )
            )
        else:
            ready = secret_ok and ca_ok
            findings.append(
                Finding(
                    "WARN" if ready else "BLOCK",
                    "organization-sign-in",
                    (
                        "OIDC configuration and local credential material are valid but "
                        "the provider was intentionally not contacted"
                        if ready
                        else f"OIDC credential material is incomplete: {secret_detail}; {ca_detail}"
                    ),
                    (
                        "Use the sign-in action for an explicit provider test."
                        if ready
                        else "Repair the configured OIDC client secret or CA file."
                    ),
                )
            )

    credentials_ok, credential_detail = _aws_profile_ready(config)
    model_configured = bool(
        credentials_ok and config.aws.bedrock_model_id and config.aws.region
    )
    findings.append(
        Finding(
            "WARN" if model_configured else "BLOCK",
            "aws-model",
            (
                "AWS/model settings are configured but intentionally not contacted"
                if model_configured
                else credential_detail if not credentials_ok else "Bedrock model id is not configured"
            ),
            (
                "Use an explicit authorized refinement or run to validate Bedrock access."
                if model_configured
                else "Configure an owner-only credentials file and a current Bedrock model/profile id."
            ),
        )
    )
    findings.append(
        Finding(
            "WARN",
            "target-reachability",
            "target reachability was not probed",
            "Use the revision-bound Target Preflight action in the wizard for an explicit bounded check.",
        )
    )

    host_app_enabled = config.host_app.enabled
    if info.system != "Linux":
        findings.append(
            Finding(
                "WARN",
                "host-app",
                f"host-app is unavailable on {info.system}",
                "Use a remote RDP/VNC/SSH target, or run on an explicitly configured Linux host.",
            )
        )
    elif not host_app_enabled:
        findings.append(
            Finding(
                "WARN",
                "host-app",
                "Linux host-app is disabled by default",
                "Enable it explicitly and supply absolute allowlisted roots only if required.",
            )
        )
    else:
        roots_ok = all(Path(value).is_dir() for value in config.host_app.allow_roots)
        findings.append(
            Finding(
                "PASS" if roots_ok else "BLOCK",
                "host-app",
                "Linux host-app policy is enabled" if roots_ok else "one or more host-app allow roots do not exist",
                None if roots_ok else "Correct the allow roots and rerun doctor.",
            )
        )

    import_roots_ok = bool(config.project_import_roots)
    if import_roots_ok:
        try:
            for item in config.project_import_roots:
                normalize_project_import_root(item.id, item.label, item.path)
        except ConfigurationError:
            import_roots_ok = False
    findings.append(
        Finding(
            "PASS" if import_roots_ok else ("WARN" if not config.project_import_roots else "BLOCK"),
            "project-folder-import",
            (
                f"{len(config.project_import_roots)} project import root(s) are configured and valid"
                if import_roots_ok
                else "project-folder import is disabled because no roots are configured"
                if not config.project_import_roots
                else "one or more project import roots are unavailable or unsafe"
            ),
            (
                None
                if import_roots_ok
                else "Use configure --project-import-root ID LABEL ABSOLUTE_PATH with an existing non-link directory."
            ),
        )
    )

    return DoctorReport(
        platform=info,
        findings=tuple(findings),
        capabilities=_capability_matrix(
            info,
            initialized=initialized,
            dependencies=deps_ok,
            engine_ok=engine_ok,
            image_ok=image_ok,
            model_configured=model_configured,
            host_app_enabled=host_app_enabled,
            project_import_ready=import_roots_ok,
        ),
    )


def format_report(report: DoctorReport) -> str:
    lines = [
        f"Orchestrator Cookie doctor — {report.platform.system} {report.platform.machine}",
        "",
        "Findings",
    ]
    for item in report.findings:
        lines.append(f"[{item.severity:<5}] {item.code}: {item.summary}")
        if item.remediation:
            lines.append(f"        remediation: {item.remediation}")
    lines.extend(("", "Capability matrix"))
    for item in report.capabilities:
        lines.append(f"[{item.state:<20}] {item.name}: {item.explanation}")
    lines.extend(
        (
            "",
            "Readiness layers: dashboard access != runner image != target reachability != AWS/model access.",
            "No target or model was contacted by this command.",
        )
    )
    return "\n".join(lines)
