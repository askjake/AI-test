"""Command-line interface shared by the POSIX and PowerShell wrappers."""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, replace
import getpass
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
from typing import Iterable, Sequence

from .config import (
    AwsConfig,
    ConfigurationError,
    HostAppConfig,
    ImageSource,
    ImageSourceKind,
    OidcConfig,
    ProjectImportRoot,
    RuntimeConfig,
    TOKEN_RELATIVE,
    atomic_write_json,
    generate_tokens,
    import_sample_workspace,
    initialize_runtime,
    load_config,
    load_tokens,
    normalize_project_import_root,
    read_private_token_file,
    repo_root_from,
    runtime_root,
    save_config,
    save_tokens,
    validate_name,
    validate_private_secret_file,
)
from .dependencies import (
    ENVIRONMENT_RELATIVE,
    RUNTIME_PROFILE,
    TEST_PROFILE,
    environment_readiness,
    expected_distributions,
    managed_python,
    managed_venv_root,
    requirements_digest,
    safe_detail,
)
from .doctor import format_report, run_doctor
from .image import acquire_image
from .lifecycle import (
    dashboard_status,
    local_url,
    start_dashboard,
    stop_dashboard,
    read_process_metadata,
)
from .local_oidc import (
    OPERATOR_USERNAME,
    VIEWER_USERNAME,
    deactivate_local_oidc,
    load_local_oidc_state,
    local_oidc_password_path,
    local_oidc_status,
    provision_local_oidc,
    read_local_oidc_password,
    start_local_oidc,
    stop_local_oidc,
)


EXIT_USAGE = 2
EXIT_BLOCKED = 3
_GIT_BRANCH_RE = re.compile(r"^(?![-/])(?!.*(?:\.\.|@\{|//))[A-Za-z0-9._/-]{1,240}$")
_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|password|authorization|aws_access_key_id|"
    r"aws_secret_access_key|aws_session_token)\b(\s*[=:]\s*)(\S+)"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install",
        description="Orchestrator Cookie cross-platform installer/runtime manager",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check prerequisites without contacting targets/models")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable output")

    init = sub.add_parser("init", help="initialize this clone and install Python dependencies")
    init.add_argument("--import-samples", action="store_true")
    init.add_argument(
        "--with-test",
        action="store_true",
        help="also install and validate the locked developer/full-test profile",
    )
    init.add_argument("--skip-deps", action="store_true", help=argparse.SUPPRESS)

    configure = sub.add_parser("configure", help="configure binding, runner, AWS, and host-app gates")
    binding = configure.add_mutually_exclusive_group()
    binding.add_argument("--lan", action="store_true", help="explicitly permit a non-loopback bind")
    binding.add_argument("--loopback", action="store_true", help="reset to 127.0.0.1")
    configure.add_argument("--bind", help="literal bind IP or localhost")
    configure.add_argument("--port", type=int)
    port_fallback = configure.add_mutually_exclusive_group()
    port_fallback.add_argument(
        "--exact-port",
        action="store_true",
        help="fail closed instead of scanning when the preferred port is occupied",
    )
    port_fallback.add_argument(
        "--sequential-port-fallback",
        action="store_true",
        help="scan upward from the preferred port when it is occupied",
    )
    configure.add_argument("--engine", help="Docker/Podman executable name or absolute path")
    configure.add_argument(
        "--image-source",
        choices=[item.value for item in ImageSourceKind],
    )
    configure.add_argument("--image-ref")
    configure.add_argument("--image-archive")
    configure.add_argument("--image-sha256")
    configure.add_argument("--vendor-artifact")
    configure.add_argument("--vendor-sha256")
    configure.add_argument("--runner-platform", choices=["linux/amd64", "linux/arm64"])
    configure.add_argument("--aws-credentials-file")
    configure.add_argument("--aws-config-file")
    configure.add_argument("--aws-profile")
    configure.add_argument("--aws-region")
    configure.add_argument("--bedrock-model-id")
    configure.add_argument("--clear-aws", action="store_true")
    host_app = configure.add_mutually_exclusive_group()
    host_app.add_argument("--enable-host-app", action="store_true")
    host_app.add_argument("--disable-host-app", action="store_true")
    configure.add_argument("--host-app-root", action="append", default=[])
    project_import = configure.add_mutually_exclusive_group()
    project_import.add_argument(
        "--project-import-root",
        action="append",
        nargs=3,
        metavar=("ID", "LABEL", "ABSOLUTE_PATH"),
        help="replace project import roots; repeat for each id/label/absolute path",
    )
    project_import.add_argument(
        "--clear-project-import-roots",
        action="store_true",
        help="disable project-folder import and remove all configured roots",
    )
    configure.add_argument("--regenerate-tokens", action="store_true")
    configure.add_argument("--viewer-token-file")
    configure.add_argument("--operator-token-file")
    oidc_toggle = configure.add_mutually_exclusive_group()
    oidc_toggle.add_argument("--enable-oidc", action="store_true")
    oidc_toggle.add_argument("--disable-oidc", action="store_true")
    configure.add_argument("--oidc-issuer")
    configure.add_argument("--oidc-client-id")
    oidc_secret = configure.add_mutually_exclusive_group()
    oidc_secret.add_argument("--oidc-client-secret-file")
    oidc_secret.add_argument("--oidc-public-client", action="store_true")
    configure.add_argument("--oidc-ca-file")
    configure.add_argument("--oidc-redirect-uri")
    configure.add_argument("--oidc-role-claim")
    configure.add_argument("--oidc-viewer-value", action="append")
    configure.add_argument("--oidc-operator-value", action="append")
    configure.add_argument("--oidc-identity-claim")
    configure.add_argument("--oidc-scope", action="append")
    configure.add_argument("--oidc-signing-algorithm", action="append")
    tls = configure.add_mutually_exclusive_group()
    tls.add_argument("--oidc-tls-terminated", action="store_true")
    tls.add_argument("--oidc-no-tls-terminated", action="store_true")
    configure.add_argument("--oidc-trusted-proxy", action="append")
    configure.add_argument("--oidc-session-ttl", type=int)
    configure.add_argument("--non-interactive", action="store_true")

    access = sub.add_parser("access", help="manage clone-local bootstrap access without printing credentials")
    access.add_argument("--role", choices=("viewer", "operator"))
    access_action = access.add_mutually_exclusive_group(required=True)
    access_action.add_argument("--copy", action="store_true", help="copy one credential to the local clipboard")
    access_action.add_argument("--show-path", action="store_true", help="show only the private credential-file path")
    access_action.add_argument("--regenerate-tokens", action="store_true", help="rotate both bootstrap credentials")

    acquire = sub.add_parser("acquire-image", help="explicitly acquire the configured verified image")
    acquire.add_argument("--yes", action="store_true", help="confirm the configured engine mutation")

    local_oidc = sub.add_parser(
        "local-oidc",
        help="manage the packaged test-only Keycloak identity provider",
    )
    local_oidc_sub = local_oidc.add_subparsers(dest="local_oidc_command", required=True)
    local_provision = local_oidc_sub.add_parser(
        "provision",
        help="generate private identity material and provision pinned containers",
    )
    local_provision.add_argument("--public-host", required=True)
    local_provision.add_argument("--dashboard-port", type=int, default=8025)
    local_provision.add_argument("--app-https-port", type=int)
    local_provision.add_argument("--idp-https-port", type=int)
    local_provision.add_argument(
        "--platform",
        choices=("linux/amd64", "linux/arm64"),
        default="linux/amd64",
    )
    local_provision.add_argument(
        "--yes",
        action="store_true",
        help="confirm image pulls, container/network creation, and runtime configuration",
    )
    local_oidc_sub.add_parser("start", help="start and verify the provisioned identity stack")
    local_oidc_sub.add_parser("status", help="inspect identity stack state without mutation")
    local_oidc_sub.add_parser("stop", help="stop only this clone's identity containers")
    local_oidc_sub.add_parser(
        "deactivate",
        help="stop local identity and restore the saved pre-OIDC runtime configuration",
    )
    local_access = local_oidc_sub.add_parser(
        "access",
        help="recover a generated local test account without printing its password",
    )
    local_access.add_argument("--role", choices=("viewer", "operator"), required=True)
    local_access_action = local_access.add_mutually_exclusive_group(required=True)
    local_access_action.add_argument("--copy", action="store_true")
    local_access_action.add_argument("--show-path", action="store_true")

    start = sub.add_parser("start", help="start the production dashboard")
    start.add_argument("--foreground", action="store_true")
    sub.add_parser("status", help="show managed dashboard state")
    logs = sub.add_parser("logs", help="show redacted dashboard logs")
    logs.add_argument("--lines", type=int, default=200)
    sub.add_parser("stop", help="stop only the authenticated managed dashboard")

    update = sub.add_parser("update", help="fast-forward this clone while preserving runtime data")
    update.add_argument("--remote", default="origin")
    update.add_argument("--branch", default="main")
    update.add_argument("--skip-deps", action="store_true")

    uninstall = sub.add_parser("uninstall", help="remove generated runtime components")
    uninstall.add_argument("--purge-user-data", action="store_true")
    uninstall.add_argument("--confirm-delete-data")

    sub.add_parser("import-samples", help="explicitly import tracked sample projects into the empty workspace")
    sub.add_parser("tunnel-help", help="print safe SSH tunnel guidance")
    return parser


def _venv_python(repo_root: Path) -> Path:
    return managed_python(repo_root)


def _install_dependencies(repo_root: Path, *, profile: str = RUNTIME_PROFILE) -> None:
    if not ((3, 11) <= sys.version_info[:2] < (3, 14)):
        raise ConfigurationError("Python 3.11, 3.12, or 3.13 is required")
    if profile not in {RUNTIME_PROFILE, TEST_PROFILE}:
        raise ConfigurationError("unsupported dependency profile")
    venv_root = managed_venv_root(repo_root)
    python = _venv_python(repo_root)
    if python.is_file():
        if Path(sys.prefix).resolve() != venv_root.resolve():
            if venv_root.is_symlink() or venv_root.resolve().parent != runtime_root(repo_root).resolve():
                raise ConfigurationError("refusing to repair an unexpected managed environment path")
            shutil.rmtree(venv_root)
    if not python.is_file():
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(venv_root)],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            check=False,
            shell=False,
        )
        if result.returncode != 0 or not python.is_file():
            raise ConfigurationError("could not create the isolated Python environment")
    requirements = "requirements-test.txt" if profile == TEST_PROFILE else "requirements-dashboard.txt"
    requirement_args = ["-r", str(repo_root / "requirements.txt")]
    if profile == TEST_PROFILE:
        requirement_args = ["-r", str(repo_root / requirements)]
    else:
        requirement_args.extend(["-r", str(repo_root / requirements)])
    result = subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            "--constraint",
            str(repo_root / "constraints.txt"),
            *requirement_args,
        ],
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            f"managed {profile} dependency installation failed; the previous source and user data were not changed"
        )
    checked = subprocess.run(
        [str(python), "-m", "pip", "check"],
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        shell=False,
    )
    if checked.returncode != 0:
        raise ConfigurationError(f"managed environment dependency check failed: {safe_detail(checked.stdout)}")
    smoke = subprocess.run(
        [str(python), str(repo_root / "scripts" / "environment_smoke.py"), "--profile", profile],
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        shell=False,
    )
    if smoke.returncode != 0:
        raise ConfigurationError(f"managed environment readiness failed: {safe_detail(smoke.stdout)}")
    atomic_write_json(
        runtime_root(repo_root) / ENVIRONMENT_RELATIVE,
        {
            "schema_version": 2,
            "profile": profile,
            "requirements_sha256": requirements_digest(repo_root, profile),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "bootstrap_interpreter": os.environ.get("ORCHESTRATOR_RESOLVED_PYTHON", sys.executable),
            "validated_distributions": expected_distributions(profile),
        },
    )


def _interactive_config(config: RuntimeConfig) -> RuntimeConfig:
    print("Press Enter to keep each safe default. Tokens are generated/stored separately.")
    bind = input(f"Dashboard bind [{config.bind_host}]: ").strip() or config.bind_host
    port_text = input(f"Dashboard port [{config.port}]: ").strip()
    port = int(port_text) if port_text else config.port
    lan_enabled = config.lan_enabled
    if bind not in {"127.0.0.1", "localhost", "::1"}:
        answer = input("Permit LAN binding? Type YES to confirm [no]: ").strip()
        lan_enabled = answer == "YES"
    else:
        lan_enabled = False
    return replace(
        config,
        bind_host=bind,
        port=port,
        preferred_port=port,
        lan_enabled=lan_enabled,
    )


def _configured_image(args: argparse.Namespace, current: ImageSource) -> ImageSource:
    kind = args.image_source or current.kind
    return ImageSource(
        kind=kind,
        image_ref=args.image_ref or current.image_ref,
        archive_path=args.image_archive if args.image_archive is not None else current.archive_path,
        archive_sha256=args.image_sha256 if args.image_sha256 is not None else current.archive_sha256,
        vendor_artifact_path=(
            args.vendor_artifact if args.vendor_artifact is not None else current.vendor_artifact_path
        ),
        vendor_artifact_sha256=(
            args.vendor_sha256 if args.vendor_sha256 is not None else current.vendor_artifact_sha256
        ),
        platform=args.runner_platform or current.platform,
    )


def _configure(repo_root: Path, args: argparse.Namespace) -> None:
    config = load_config(repo_root)
    mutation_flags = any(
        value
        for value in (
            args.lan,
            args.loopback,
            args.bind,
            args.port,
            args.exact_port,
            args.sequential_port_fallback,
            args.engine,
            args.image_source,
            args.image_ref,
            args.image_archive,
            args.image_sha256,
            args.vendor_artifact,
            args.vendor_sha256,
            args.runner_platform,
            args.aws_credentials_file,
            args.aws_config_file,
            args.aws_profile,
            args.aws_region,
            args.bedrock_model_id,
            args.clear_aws,
            args.enable_host_app,
            args.disable_host_app,
            args.host_app_root,
            args.project_import_root,
            args.clear_project_import_roots,
            args.regenerate_tokens,
            args.viewer_token_file,
            args.operator_token_file,
            args.enable_oidc,
            args.disable_oidc,
            args.oidc_issuer,
            args.oidc_client_id,
            args.oidc_client_secret_file,
            args.oidc_public_client,
            args.oidc_ca_file,
            args.oidc_redirect_uri,
            args.oidc_role_claim,
            args.oidc_viewer_value,
            args.oidc_operator_value,
            args.oidc_identity_claim,
            args.oidc_scope,
            args.oidc_signing_algorithm,
            args.oidc_tls_terminated,
            args.oidc_no_tls_terminated,
            args.oidc_trusted_proxy,
            args.oidc_session_ttl,
        )
    )
    if mutation_flags and read_process_metadata(repo_root):
        state = dashboard_status(repo_root, config)
        if state.running:
            raise ConfigurationError(
                "stop the authenticated managed dashboard before changing its configuration"
            )
        raise ConfigurationError(
            "managed dashboard metadata cannot be authenticated; configuration was not changed"
        )
    if not mutation_flags and not args.non_interactive and sys.stdin.isatty():
        config = _interactive_config(config)
    else:
        bind_host = "127.0.0.1" if args.loopback else (args.bind or config.bind_host)
        lan_enabled = False if args.loopback else (True if args.lan else config.lan_enabled)
        if args.bind and args.bind in {"127.0.0.1", "localhost", "::1"}:
            lan_enabled = False
        aws = AwsConfig() if args.clear_aws else AwsConfig(
            credentials_file=(
                args.aws_credentials_file
                if args.aws_credentials_file is not None
                else config.aws.credentials_file
            ),
            config_file=(
                args.aws_config_file if args.aws_config_file is not None else config.aws.config_file
            ),
            profile=args.aws_profile if args.aws_profile is not None else config.aws.profile,
            region=args.aws_region or config.aws.region,
            bedrock_model_id=(
                args.bedrock_model_id
                if args.bedrock_model_id is not None
                else config.aws.bedrock_model_id
            ),
        )
        if args.disable_host_app:
            host = HostAppConfig()
        else:
            roots = tuple(args.host_app_root) if args.host_app_root else config.host_app.allow_roots
            host = HostAppConfig(
                enabled=True if args.enable_host_app else config.host_app.enabled,
                allow_roots=roots,
            )
        if host.enabled and platform.system() != "Linux":
            raise ConfigurationError("host-app can be enabled only on Linux")
        if args.clear_project_import_roots:
            project_import_roots: tuple[ProjectImportRoot, ...] = ()
        elif args.project_import_root is not None:
            project_import_roots = tuple(
                normalize_project_import_root(root_id, label, path)
                for root_id, label, path in args.project_import_root
            )
        else:
            project_import_roots = config.project_import_roots
        client_secret_file = (
            None
            if args.oidc_public_client
            else (
                args.oidc_client_secret_file
                if args.oidc_client_secret_file is not None
                else config.oidc.client_secret_file
            )
        )
        if client_secret_file is not None:
            client_secret_file = str(
                validate_private_secret_file(client_secret_file, "OIDC client secret file")
            )
        oidc = OidcConfig(
            enabled=False if args.disable_oidc else (
                True if args.enable_oidc else config.oidc.enabled
            ),
            issuer=args.oidc_issuer if args.oidc_issuer is not None else config.oidc.issuer,
            client_id=(
                args.oidc_client_id if args.oidc_client_id is not None else config.oidc.client_id
            ),
            redirect_uri=(
                args.oidc_redirect_uri
                if args.oidc_redirect_uri is not None
                else config.oidc.redirect_uri
            ),
            client_secret_file=client_secret_file,
            ca_file=(
                args.oidc_ca_file
                if args.oidc_ca_file is not None
                else config.oidc.ca_file
            ),
            provider_label=config.oidc.provider_label,
            test_only=config.oidc.test_only,
            role_claim=args.oidc_role_claim or config.oidc.role_claim,
            viewer_values=(
                tuple(args.oidc_viewer_value)
                if args.oidc_viewer_value is not None
                else config.oidc.viewer_values
            ),
            operator_values=(
                tuple(args.oidc_operator_value)
                if args.oidc_operator_value is not None
                else config.oidc.operator_values
            ),
            identity_claim=args.oidc_identity_claim or config.oidc.identity_claim,
            scopes=(
                tuple(args.oidc_scope) if args.oidc_scope is not None else config.oidc.scopes
            ),
            signing_algorithms=(
                tuple(args.oidc_signing_algorithm)
                if args.oidc_signing_algorithm is not None
                else config.oidc.signing_algorithms
            ),
            tls_terminated=False if args.oidc_no_tls_terminated else (
                True if args.oidc_tls_terminated else config.oidc.tls_terminated
            ),
            trusted_proxy_cidrs=(
                tuple(args.oidc_trusted_proxy)
                if args.oidc_trusted_proxy is not None
                else config.oidc.trusted_proxy_cidrs
            ),
            session_ttl_seconds=(
                args.oidc_session_ttl
                if args.oidc_session_ttl is not None
                else config.oidc.session_ttl_seconds
            ),
        )
        config = RuntimeConfig(
            schema_version=config.schema_version,
            bind_host=bind_host,
            port=args.port if args.port is not None else config.port,
            preferred_port=(
                args.port if args.port is not None else config.preferred_port
            ),
            port_fallback_enabled=(
                False
                if args.exact_port
                else True
                if args.sequential_port_fallback
                else config.port_fallback_enabled
            ),
            lan_enabled=lan_enabled,
            trigger_backend=config.trigger_backend,
            engine=args.engine or config.engine,
            image=_configured_image(args, config.image),
            aws=aws,
            host_app=host,
            project_import_roots=project_import_roots,
            oidc=oidc,
        )
    config.validate()
    save_config(repo_root, config)

    if args.regenerate_tokens:
        tokens = generate_tokens()
    else:
        tokens = load_tokens(repo_root)
    if args.viewer_token_file:
        tokens["viewer_token"] = read_private_token_file(args.viewer_token_file)
    if args.operator_token_file:
        tokens["operator_token"] = read_private_token_file(args.operator_token_file)
    save_tokens(repo_root, tokens)
    print(f"Configuration saved. Tokens remain private in {runtime_root(repo_root) / 'config'}.")


def _copy_to_clipboard(value: str, *, system: str | None = None) -> bool:
    """Copy through a local executable; never place the value in argv or output."""
    system = system or platform.system()
    candidates: list[list[str]] = []
    if system == "Windows":
        candidates = [["clip.exe"], ["clip"]]
    elif system == "Darwin":
        candidates = [["pbcopy"]]
    else:
        if os.environ.get("WAYLAND_DISPLAY"):
            candidates.append(["wl-copy"])
        candidates.extend([
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ])
    for command in candidates:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        try:
            result = subprocess.run(
                [executable, *command[1:]],
                input=value,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            return True
    return False


def _access(repo_root: Path, args: argparse.Namespace) -> None:
    token_path = runtime_root(repo_root) / TOKEN_RELATIVE
    if args.show_path:
        if args.role:
            raise ConfigurationError("--role is used only with --copy")
        load_tokens(repo_root)
        print(token_path)
        return
    if args.regenerate_tokens:
        if args.role:
            raise ConfigurationError("--role is used only with --copy")
        metadata = read_process_metadata(repo_root)
        if metadata:
            state = dashboard_status(repo_root, load_config(repo_root))
            if state.running:
                raise ConfigurationError("stop the authenticated managed dashboard before rotating access")
            raise ConfigurationError(
                "managed dashboard metadata cannot be authenticated; access was not changed"
            )
        save_tokens(repo_root, generate_tokens())
        print("Bootstrap viewer and operator credentials were regenerated; no credential was printed.")
        return
    if not args.copy or not args.role:
        raise ConfigurationError("--copy requires --role viewer or --role operator")
    tokens = load_tokens(repo_root)
    credential = tokens[f"{args.role}_token"]
    if not _copy_to_clipboard(credential):
        raise ConfigurationError(
            "a supported local clipboard utility is unavailable; the credential was not printed. "
            "Use access --show-path only for owner recovery."
        )
    print(f"{args.role.capitalize()} bootstrap credential copied to the local clipboard; it was not printed.")


def _local_oidc_access(repo_root: Path, args: argparse.Namespace) -> None:
    username = OPERATOR_USERNAME if args.role == "operator" else VIEWER_USERNAME
    if args.show_path:
        print(local_oidc_password_path(repo_root, args.role))
        print(f"Username: {username}")
        return
    password = read_local_oidc_password(repo_root, args.role)
    if not _copy_to_clipboard(password):
        raise ConfigurationError(
            "a supported local clipboard utility is unavailable; the password was not printed. "
            "Use local-oidc access --show-path only for owner recovery."
        )
    print(f"{args.role.capitalize()} local OIDC password copied; username: {username}. The password was not printed.")


def _lan_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            address = info[4][0].split("%", 1)[0]
            if address not in {"127.0.0.1", "::1"}:
                addresses.add(address)
    except OSError:
        pass
    return sorted(addresses)


def _print_access(repo_root: Path, config: RuntimeConfig, state: DashboardState) -> None:
    actual_port = state.port if state.port is not None else config.port
    print(f"Local URL: {state.url or local_url(config, port=actual_port)}")
    if config.lan_enabled:
        for address in _lan_addresses():
            wrapped = f"[{address}]" if ":" in address else address
            print(f"LAN URL:   http://{wrapped}:{actual_port}")
    local_oidc = load_local_oidc_state(repo_root)
    if local_oidc and config.oidc.enabled:
        print(
            "OIDC URL:  "
            f"https://{local_oidc.public_host}:{local_oidc.app_https_port}"
        )
        print(f"Local CA:  {local_oidc.ca_certificate}")
    print("Authentication tokens are not printed and are never placed in URLs.")


def _redact(text: str) -> str:
    return _SECRET_RE.sub(r"\1\2[redacted]", text)


def _show_logs(repo_root: Path, lines: int) -> None:
    if not 1 <= lines <= 5000:
        raise ConfigurationError("--lines must be between 1 and 5000")
    path = runtime_root(repo_root) / "logs" / "dashboard.log"
    if not path.is_file():
        print("No dashboard log exists yet.")
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        content = deque(handle, maxlen=lines)
    sys.stdout.write(_redact("".join(content)))


def _git(repo_root: Path, args: Sequence[str], *, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,
    )


def _update(repo_root: Path, remote: str, branch: str, *, skip_deps: bool) -> None:
    validate_name(remote, "git remote")
    if not _GIT_BRANCH_RE.fullmatch(branch):
        raise ConfigurationError("git branch name is invalid")
    if not (repo_root / ".git").exists():
        raise ConfigurationError("update requires a Git clone; this source snapshot has no .git metadata")
    try:
        if dashboard_status(repo_root, load_config(repo_root)).running:
            raise ConfigurationError("stop the managed dashboard before updating its code/environment")
    except ConfigurationError as exc:
        if "runtime is not initialized" not in str(exc):
            raise
    current = _git(repo_root, ["branch", "--show-current"])
    if current.returncode != 0 or current.stdout.strip() != branch:
        raise ConfigurationError(f"update requires the current branch to be {branch!r}")
    dirty = _git(repo_root, ["status", "--porcelain", "--untracked-files=no"])
    if dirty.returncode != 0 or dirty.stdout.strip():
        raise ConfigurationError("tracked files are modified; update refuses to overwrite them")
    fetched = _git(repo_root, ["fetch", remote, branch], timeout=600)
    if fetched.returncode != 0:
        raise ConfigurationError("git fetch failed")
    merged = _git(repo_root, ["merge", "--ff-only", "FETCH_HEAD"], timeout=300)
    if merged.returncode != 0:
        raise ConfigurationError("update is not a clean fast-forward; no reset was performed")
    if not skip_deps:
        _install_dependencies(repo_root)
    print("Update complete. Per-clone configuration, tokens, projects, reports, and secrets were preserved.")


def _remove_generated(repo_root: Path, *, purge_user_data: bool, confirmation: str | None) -> None:
    root = runtime_root(repo_root)
    if not root.exists():
        print("Nothing is installed for this clone.")
        return
    metadata = read_process_metadata(repo_root)
    try:
        config = load_config(repo_root)
        state = dashboard_status(repo_root, config)
        if state.running:
            stop_dashboard(repo_root, config)
        elif metadata:
            raise ConfigurationError(
                "managed process metadata exists but its identity cannot be verified; refusing uninstall"
            )
    except ConfigurationError:
        if metadata:
            raise
    if load_local_oidc_state(repo_root):
        stop_local_oidc(repo_root)
    if purge_user_data:
        if confirmation != "DELETE ORCHESTRATOR COOKIE DATA":
            raise ConfigurationError(
                "purging projects/reports/manuals/secrets requires --confirm-delete-data "
                "'DELETE ORCHESTRATOR COOKIE DATA'"
            )
        resolved = root.resolve()
        if resolved.parent != repo_root.resolve() or resolved.name != ".orchestrator-cookie":
            raise ConfigurationError("refusing to remove an unexpected runtime path")
        shutil.rmtree(root)
        print("Removed the entire per-clone runtime, including user data. Recovery requires a backup.")
        return
    generated = (
        root / "venv",
        root / "state" / "image-build",
    )
    for path in generated:
        if path.is_dir():
            shutil.rmtree(path)
    for path in (root / "state" / "dashboard.json", root / "state" / "runner_image.json"):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    print(
        "Removed generated environment/process/image state. Configuration, tokens, logs, "
        "projects, reports, manuals, and secrets were retained."
    )


def _json_doctor(repo_root: Path) -> str:
    report = run_doctor(repo_root)
    return json.dumps(
        {
            "platform": asdict(report.platform),
            "findings": [asdict(value) for value in report.findings],
            "capabilities": [asdict(value) for value in report.capabilities],
        },
        indent=2,
    )


def main(argv: Sequence[str] | None = None, *, repo_root: Path | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = (repo_root or repo_root_from(__file__)).resolve()
    try:
        if args.command == "doctor":
            print(_json_doctor(repo_root) if args.json else format_report(run_doctor(repo_root)))
        elif args.command == "init":
            initialize_runtime(repo_root, import_samples=args.import_samples)
            if not args.skip_deps:
                _install_dependencies(
                    repo_root,
                    profile=TEST_PROFILE if args.with_test else RUNTIME_PROFILE,
                )
            print(f"Initialized isolated runtime at {runtime_root(repo_root)}")
            print("A safe empty workspace is active." if not args.import_samples else "Tracked samples were explicitly imported.")
        elif args.command == "configure":
            _configure(repo_root, args)
        elif args.command == "access":
            _access(repo_root, args)
        elif args.command == "acquire-image":
            if not args.yes:
                raise ConfigurationError("acquire-image mutates the local engine; rerun with --yes")
            state = acquire_image(repo_root, load_config(repo_root))
            print(state.detail)
        elif args.command == "local-oidc":
            if args.local_oidc_command == "provision":
                if not args.yes:
                    raise ConfigurationError(
                        "local OIDC provisioning mutates the engine and runtime; rerun with --yes"
                    )
                metadata = read_process_metadata(repo_root)
                if metadata:
                    state = dashboard_status(repo_root, load_config(repo_root))
                    if state.running:
                        raise ConfigurationError(
                            "stop the authenticated managed dashboard before provisioning local OIDC"
                        )
                    raise ConfigurationError(
                        "managed dashboard metadata cannot be authenticated; local OIDC was not changed"
                    )
                state = provision_local_oidc(
                    repo_root,
                    public_host=args.public_host,
                    dashboard_port=args.dashboard_port,
                    app_https_port=args.app_https_port,
                    idp_https_port=args.idp_https_port,
                    platform=args.platform,
                )
                print("Local test OIDC provisioned with generated private credentials.")
                print(f"Application URL: https://{state.public_host}:{state.app_https_port}")
                print(f"Issuer: {state.issuer}")
                print(f"Local CA certificate: {state.ca_certificate}")
                print("No password, client secret, or private key was printed.")
            elif args.local_oidc_command == "start":
                print(start_local_oidc(repo_root).detail)
            elif args.local_oidc_command == "status":
                state = local_oidc_status(repo_root)
                print(state.detail)
                if state.app_url:
                    print(f"Application URL: {state.app_url}")
                if state.issuer:
                    print(f"Issuer: {state.issuer}")
            elif args.local_oidc_command == "stop":
                print(stop_local_oidc(repo_root).detail)
            elif args.local_oidc_command == "deactivate":
                metadata = read_process_metadata(repo_root)
                if metadata:
                    state = dashboard_status(repo_root, load_config(repo_root))
                    if state.running:
                        raise ConfigurationError(
                            "stop the authenticated managed dashboard before deactivating local OIDC"
                        )
                    raise ConfigurationError(
                        "managed dashboard metadata cannot be authenticated; local OIDC was not changed"
                    )
                print(deactivate_local_oidc(repo_root).detail)
            else:
                _local_oidc_access(repo_root, args)
        elif args.command == "start":
            from .switch_guard import require_resolved as _require_switch_resolved  # CP45-R
            _require_switch_resolved(runtime_root(repo_root) / "reports")   # first thing: before readiness checks, local OIDC or any directory
            readiness = environment_readiness(repo_root, RUNTIME_PROFILE)
            if not readiness.ready:
                raise ConfigurationError(readiness.detail)
            config = load_config(repo_root)
            if config.oidc.enabled and load_local_oidc_state(repo_root):
                start_local_oidc(repo_root)
            state = start_dashboard(repo_root, config, foreground=args.foreground)
            print(state.detail)
            if state.url:
                _print_access(repo_root, config, state)
            if not state.running and not args.foreground:
                return EXIT_BLOCKED
        elif args.command == "status":
            config = load_config(repo_root)
            state = dashboard_status(repo_root, config)
            print(f"{state.detail}; pid={state.pid if state.pid else '-'}; url={state.url}")
            oidc_state = local_oidc_status(repo_root)
            if oidc_state.configured:
                print(oidc_state.detail)
        elif args.command == "logs":
            _show_logs(repo_root, args.lines)
        elif args.command == "stop":
            print(stop_dashboard(repo_root, load_config(repo_root)).detail)
            if load_local_oidc_state(repo_root):
                print(stop_local_oidc(repo_root).detail)
        elif args.command == "update":
            _update(repo_root, args.remote, args.branch, skip_deps=args.skip_deps)
        elif args.command == "uninstall":
            _remove_generated(
                repo_root,
                purge_user_data=args.purge_user_data,
                confirmation=args.confirm_delete_data,
            )
        elif args.command == "import-samples":
            import_sample_workspace(repo_root)
            print("Tracked samples were imported into the isolated workspace.")
        elif args.command == "tunnel-help":
            config = load_config(repo_root)
            print(
                f"Preferred remote access (run on your workstation):\n"
                f"  ssh -N -L {config.port}:127.0.0.1:{config.port} USER@DASHBOARD_HOST\n"
                f"Then open http://127.0.0.1:{config.port} and use the Sign in screen.\n"
                "No firewall rule is created automatically."
            )
        return 0
    except (ConfigurationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"BLOCKED: {_redact(str(exc))}", file=sys.stderr)
        return EXIT_BLOCKED
