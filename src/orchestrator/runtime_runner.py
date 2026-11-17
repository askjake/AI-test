"""Cross-platform hardened container launcher used by dashboard triggers.

All engine invocations are explicit argv arrays.  This path preserves the
existing secret staging, current AWS-file synchronization, container hardening,
project isolation, and Linux-only host-app bridge without relying on Bash.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Iterator, Sequence

import yaml

from orchestrator_cookie.config import (
    ConfigurationError,
    RuntimeConfig,
    load_config,
    runtime_root,
    validate_name,
)
from orchestrator_cookie.image import engine_reachable, resolve_engine, validate_image
from orchestrator.bedrock_relay import BedrockRelayLease, bedrock_connect_relay
from orchestrator.egress import EgressResolutionError, compute_policy, resolve_policy_ipv4
from orchestrator.target_relay import (
    ProjectTransport,
    TargetRelayError,
    TargetRelayLease,
    describe_project_transport,
    target_connect_relay,
)


_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
# Same shape procedure_runs accepts for a run id.  The dashboard generates it (routes.trigger_run).
_TRIGGER_RE = re.compile(r"^trig_[A-Za-z0-9_-]{1,80}$")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _regular_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ConfigurationError(f"{label} must be a real non-symlink directory")
    return path.resolve()


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"{label} must be a regular non-symlink file")
    return path.resolve()


def _volume(path: Path, container_path: str, mode: str) -> str:
    if mode not in {"ro", "rw"} or not container_path.startswith("/app/"):
        raise ConfigurationError("invalid runner volume contract")
    text = str(path)
    if any(value in text for value in ("\0", "\r", "\n")):
        raise ConfigurationError("runner volume path contains control data")
    if platform.system() != "Windows" and ":" in text:
        raise ConfigurationError("runner volume paths may not contain ':' on this host")
    return f"{text}:{container_path}:{mode}"


def _system_file_volume(path: Path, container_path: str, mode: str) -> str:
    """Return the one reviewed non-/app bind used by the egress bootstrap."""
    if container_path != "/etc/hosts" or mode != "ro":
        raise ConfigurationError("invalid runner system-file volume contract")
    source = _regular_file(path, "private runner hosts file")
    text = str(source)
    if any(value in text for value in ("\0", "\r", "\n")):
        raise ConfigurationError("runner volume path contains control data")
    if platform.system() != "Windows" and ":" in text:
        raise ConfigurationError("runner volume paths may not contain ':' on this host")
    return f"{text}:{container_path}:{mode}"


@contextmanager
def _private_hosts_file(
    repo_root: Path,
    config: RuntimeConfig,
    *,
    project_name: str | None = None,
    include_bedrock: bool = True,
    resolver=resolve_policy_ipv4,
) -> Iterator[Path]:
    """Create one non-sensitive, per-run hosts file and remove it after use.

    Docker bridge DNS may not have access to a host VPN resolver. The host
    therefore resolves the reviewed endpoint policy into this dedicated file,
    which is mounted read-only instead of exposing any host-global file. The
    container independently recomputes the policy before installing rules.
    """
    root = runtime_root(repo_root)
    policy = compute_policy(
        region=config.aws.region,
        specs_root=str(root / "tests_specs"),
        project_name=project_name,
        include_bedrock=include_bedrock,
    )
    try:
        resolved_entries = resolver(policy)
    except EgressResolutionError as exc:
        raise ConfigurationError(str(exc)) from exc
    if not resolved_entries:
        raise ConfigurationError("host-side egress resolution returned no entries")

    state_root = root / "state" / "runner-hosts"
    state_root.mkdir(parents=True, exist_ok=True)
    if state_root.is_symlink() or not state_root.is_dir():
        raise ConfigurationError("private runner hosts directory is unsafe")
    if os.name != "nt":
        os.chmod(state_root, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix="hosts.", dir=state_root)
    hosts_file = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "127.0.0.1 localhost orchestrator-cookie-runner\n"
                "::1 localhost ip6-localhost ip6-loopback\n"
            )
            for address, host in resolved_entries:
                handle.write(f"{address} {host}\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield hosts_file
    finally:
        try:
            hosts_file.unlink()
        except FileNotFoundError:
            pass


def _load_project_target(config_path: Path) -> dict:
    try:
        value = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError("project configuration is unreadable") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("project configuration must be a YAML mapping")
    target = value.get("target") or {}
    if not isinstance(target, dict):
        raise ConfigurationError("project target must be a YAML mapping")
    return target


def _pinned_endpoint_addresses(
    hosts_file: Path,
    endpoint: str,
    *,
    label: str = "approved endpoint",
) -> tuple[str, ...]:
    """Recover the already-validated host-side addresses for one endpoint."""
    values: list[str] = []
    for line in hosts_file.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == endpoint:
            values.append(fields[0])
    if not values:
        raise ConfigurationError(f"{label} is absent from private runner hosts file")
    return tuple(values)


@contextmanager
def _project_target_relay(
    engine: str,
    *,
    project_name: str | None,
    specs_root: Path,
    hosts_file: Path,
) -> Iterator[TargetRelayLease | None]:
    """Attach Linux project runs to the existing destination-locked target relay."""
    if platform.system() != "Linux" or project_name is None:
        yield None
        return
    transport: ProjectTransport | None = describe_project_transport(
        project_name,
        specs_root=str(specs_root),
    )
    if transport is None:
        yield None
        return
    addresses = _pinned_endpoint_addresses(
        hosts_file,
        transport.endpoint,
        label="project target endpoint",
    )
    with target_connect_relay(
        engine,
        transport=transport,
        addresses=addresses,
    ) as relay:
        print("[target-relay] project-scoped host transport attached to private runner")
        yield relay


@contextmanager
def _host_app_bridge(
    repo_root: Path,
    config: RuntimeConfig,
    project_config: Path,
    reports: Path,
    display: str,
) -> Iterator[tuple[list[str], subprocess.Popen | None]]:
    target = _load_project_target(project_config)
    if str(target.get("type", "local-app")) != "host-app":
        yield [], None
        return
    # CP45-I: a host-app target needs a host-side display bridge whose state directory the uid-10001 runner must write (it used to be chmod 0777).
    # That cannot satisfy the 0755 reports contract, so the launch is refused here and nothing is created.
    raise ConfigurationError(HOST_APP_UNSUPPORTED)


def build_runner_argv(
    repo_root: Path,
    config: RuntimeConfig,
    engine: str,
    command: Sequence[str],
    *,
    container_name: str | None,
    display: str,
    hosts_file: Path,
    bedrock_relay: BedrockRelayLease | None,
    target_relay: TargetRelayLease | None = None,
    project_name: str | None = None,
    host_bridge_env: Sequence[str] = (),
) -> list[str]:
    root = runtime_root(repo_root)
    reports = _regular_directory(root / "reports", "reports directory")
    specs = _regular_directory(root / "tests_specs", "specifications directory")
    manuals = _regular_directory(root / "tests_manuals", "manuals directory")
    secrets = _regular_directory(root / "secrets", "secrets directory")
    if not command or not all(isinstance(value, str) and value for value in command):
        raise ConfigurationError("runner command is invalid")

    args = [engine, "run", "--rm", "--platform", config.image.platform]
    if container_name:
        if not _CONTAINER_RE.fullmatch(container_name):
            raise ConfigurationError("invalid project runner container name")
        args.extend(("--name", container_name))
    args.extend(
        (
            "--user",
            "root",
            "-e",
            f"DISPLAY={display}",
            "-e",
            "SECRETS_SOURCE_DIR=/app/secrets-source",
            "-e",
            "SECRETS_RUNTIME_DIR=/app/secrets",
            "--network",
            "bridge",
            "-v",
            _system_file_volume(hosts_file, "/etc/hosts", "ro"),
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "DAC_READ_SEARCH",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "SETUID",
            "--cap-add",
            "SETGID",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "--tmpfs",
            "/home/orchestrator:rw,nosuid,nodev,size=64m,mode=1777",
            "--tmpfs",
            "/app/secrets:rw,nosuid,nodev,noexec,size=16m,mode=0700",
            "--tmpfs",
            "/app/aws-runtime:rw,nosuid,nodev,noexec,size=4m,mode=0700",
        )
    )
    if bedrock_relay is not None:
        proxy_args = (
            "-e", f"ORCHESTRATOR_BEDROCK_PROXY_HOST={bedrock_relay.bind_host}",
            "-e", f"ORCHESTRATOR_BEDROCK_PROXY_PORT={bedrock_relay.port}",
            "-e", f"ORCHESTRATOR_BEDROCK_ENDPOINT={bedrock_relay.endpoint}",
            "-e", f"HTTPS_PROXY={bedrock_relay.proxy_url}",
            "-e", f"https_proxy={bedrock_relay.proxy_url}",
            "-e", "HTTP_PROXY=",
            "-e", "http_proxy=",
            "-e", "ALL_PROXY=",
            "-e", "all_proxy=",
            "-e", "NO_PROXY=",
            "-e", "no_proxy=",
        )
        image_index = args.index("--read-only")
        args[image_index:image_index] = proxy_args
    if project_name is not None:
        validate_name(project_name, "project name")
        project_args = ("-e", f"ORCHESTRATOR_EGRESS_PROJECT={project_name}")
        image_index = args.index("--read-only")
        args[image_index:image_index] = project_args
    if target_relay is not None:
        if project_name is None:
            raise ConfigurationError("target relay requires one exact project")
        target_args = (
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_KIND={target_relay.kind}",
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_ENDPOINT={target_relay.endpoint}",
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT={target_relay.destination_port}",
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_HOST={target_relay.bind_host}",
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_PORT={target_relay.port}",
            "-e",
            f"ORCHESTRATOR_TARGET_RELAY_TOKEN={target_relay.token}",
        )
        image_index = args.index("--read-only")
        args[image_index:image_index] = target_args
    args.extend(host_bridge_env)

    credentials_text = config.aws.credentials_file
    if not credentials_text:
        raise ConfigurationError(
            "cross-platform runs require a configured current AWS credentials file"
        )
    credentials = _regular_file(Path(credentials_text).expanduser(), "AWS credentials file")
    args.extend(
        (
            "-v",
            _volume(credentials.parent, "/app/aws-credentials-source", "ro"),
            "-e",
            f"ORCHESTRATOR_AWS_CREDENTIALS_SOURCE=/app/aws-credentials-source/{credentials.name}",
            "-e",
            "AWS_SHARED_CREDENTIALS_FILE=/app/aws-runtime/credentials",
        )
    )
    if config.aws.config_file:
        aws_config = _regular_file(Path(config.aws.config_file).expanduser(), "AWS config file")
        args.extend(
            (
                "-v",
                _volume(aws_config.parent, "/app/aws-config-source", "ro"),
                "-e",
                f"ORCHESTRATOR_AWS_CONFIG_SOURCE=/app/aws-config-source/{aws_config.name}",
                "-e",
                "AWS_CONFIG_FILE=/app/aws-runtime/config",
            )
        )
    if config.aws.profile:
        args.extend(("-e", f"AWS_PROFILE={config.aws.profile}"))
    if not config.aws.bedrock_model_id:
        raise ConfigurationError("a current Bedrock model/profile id must be configured")

    # The runner finds its run-control folder from ORCHESTRATOR_TRIGGER_ID and trusts a control file only when
    # the dashboard's uid (ORCHESTRATOR_CONTROL_UID) owns it.  scripts/run_container.sh forwards both; this
    # (the spawn backend's) launcher did not, so every run reported "no trigger id", wrote its progress where the
    # dashboard never looks, and the UI stayed at "Starting".  Validated, never free text.
    control_env: list[str] = []
    trigger_id = os.environ.get("ORCHESTRATOR_TRIGGER_ID", "")
    if trigger_id:
        if not _TRIGGER_RE.fullmatch(trigger_id):
            raise ConfigurationError("invalid trigger id")
        control_env.extend(("-e", f"ORCHESTRATOR_TRIGGER_ID={trigger_id}"))
        handoff_ts = os.environ.get("ORCHESTRATOR_RUN_TS", "")
        handoff_project = os.environ.get("ORCHESTRATOR_REPORT_PROJECT", "")
        if handoff_ts or handoff_project:      # CP45-G: both or neither, each validated; the entrypoint then hands the precreated paths to the runner uid
            from orchestrator.report_handoff import PROJECT_RE as _P, RUN_TS_RE as _T
            if not (_T.fullmatch(handoff_ts) and _P.fullmatch(handoff_project)):
                raise ConfigurationError("invalid report handoff values")
            control_env.extend(("-e", f"ORCHESTRATOR_RUN_TS={handoff_ts}", "-e", f"ORCHESTRATOR_REPORT_PROJECT={handoff_project}", "-e", "ORCHESTRATOR_REPORT_HANDOFF=1"))
    if hasattr(os, "getuid"):
        control_env.extend(("-e", f"ORCHESTRATOR_CONTROL_UID={os.getuid()}"))

    args.extend(
        (
            "-v",
            _volume(reports, "/app/reports", "rw"),
            "-v",
            _volume(specs, "/app/tests_specs", "ro"),
            "-v",
            _volume(manuals, "/app/tests_manuals", "ro"),
            "-v",
            _volume(secrets, "/app/secrets-source", "ro"),
            "-e",
            f"AWS_REGION={config.aws.region}",
            "-e",
            f"AWS_DEFAULT_REGION={config.aws.region}",
            "-e",
            f"BEDROCK_MODEL_ID={config.aws.bedrock_model_id}",
            "-e",
            f"ORCHESTRATOR_LOG_LEVEL={os.environ.get('ORCHESTRATOR_LOG_LEVEL', 'DEBUG')}",
            *control_env,
            config.image.image_ref,
            *command,
        )
    )
    if any(any(char in value for char in ("\0", "\r", "\n")) for value in args):
        raise ConfigurationError("runner argv contains invalid control data")
    return args


def _request_command(repo_root: Path, project: str | None, spec: str | None) -> tuple[list[str], Path | None]:
    root = runtime_root(repo_root)
    if project:
        validate_name(project, "project name")
        project_config = root / "tests_specs" / project / "project.yaml"
        _regular_file(project_config, "project configuration")
        return ["python", "-m", "orchestrator.runner", "--project", project], project_config
    if spec:
        requested = Path(spec)
        if requested.is_absolute() or ".." in requested.parts:
            raise ConfigurationError("spec path must be relative to the isolated workspace")
        candidate = (root / "tests_specs" / requested).resolve()
        specs_root = (root / "tests_specs").resolve()
        if os.path.commonpath((str(candidate), str(specs_root))) != str(specs_root):
            raise ConfigurationError("spec path escapes the isolated workspace")
        _regular_file(candidate, "specification")
        container_spec = Path("tests_specs") / requested
        return ["python", "-m", "orchestrator.runner", str(container_spec).replace(os.sep, "/")], None
    return ["python", "-m", "orchestrator.scheduler", "--once"], None


HOST_APP_UNSUPPORTED = ("host-app targets are not supported under the 0755 reports contract (they need a world-writable host bridge state directory); "
                        "use a local-app, ssh-terminal, rdp or vnc target")


def _refuse_unsupported_target(project_config: Path) -> None:
    if str(_load_project_target(project_config).get("type", "local-app")) == "host-app":
        raise ConfigurationError(HOST_APP_UNSUPPORTED)


def run_request(*, project: str | None = None, spec: str | None = None) -> int:
    repo_root = _repo_root()
    config = load_config(repo_root)
    engine = resolve_engine(config.engine)
    if not engine:
        raise ConfigurationError("Docker or Podman is not installed")
    reachable, detail = engine_reachable(engine)
    if not reachable:
        raise ConfigurationError(detail)
    image_state = validate_image(repo_root, config, engine)
    if not image_state.ready:
        raise ConfigurationError(image_state.detail)
    command, project_config = _request_command(repo_root, project, spec)
    if project_config is not None:
        _refuse_unsupported_target(project_config)      # before any relay, listener, container or target/model activity
    container_name = os.environ.get("ORCHESTRATOR_CONTAINER_NAME") or None
    display = ":99"
    root = runtime_root(repo_root)
    reports = root / "reports"
    specs_root = root / "tests_specs"
    with _private_hosts_file(repo_root, config, project_name=project) as hosts_file:
        policy = compute_policy(
            region=config.aws.region,
            specs_root=str(specs_root),
            project_name=project,
        )
        if policy.bedrock is None:
            raise ConfigurationError("normal project runs require the Bedrock endpoint")
        addresses = _pinned_endpoint_addresses(
            hosts_file,
            policy.bedrock,
            label="Bedrock endpoint",
        )
        relay_context = (
            bedrock_connect_relay(engine, endpoint=policy.bedrock, addresses=addresses)
            if platform.system() == "Linux"
            else nullcontext(None)
        )
        try:
            with _project_target_relay(
                engine,
                project_name=project,
                specs_root=specs_root,
                hosts_file=hosts_file,
            ) as target_relay:
                with relay_context as relay:
                    if project_config is None:
                        argv = build_runner_argv(
                            repo_root,
                            config,
                            engine,
                            command,
                            container_name=container_name,
                            display=display,
                            hosts_file=hosts_file,
                            bedrock_relay=relay,
                            target_relay=target_relay,
                            project_name=project,
                        )
                        return subprocess.run(
                            argv, cwd=repo_root, check=False, shell=False
                        ).returncode
                    with _host_app_bridge(
                        repo_root, config, project_config, reports, display
                    ) as (bridge_env, _bridge):
                        argv = build_runner_argv(
                            repo_root,
                            config,
                            engine,
                            command,
                            container_name=container_name,
                            display=display,
                            hosts_file=hosts_file,
                            bedrock_relay=relay,
                            target_relay=target_relay,
                            project_name=project,
                            host_bridge_env=bridge_env,
                        )
                        return subprocess.run(
                            argv, cwd=repo_root, check=False, shell=False
                        ).returncode
        except TargetRelayError as exc:
            raise ConfigurationError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--project")
    group.add_argument("--spec")
    args = parser.parse_args(argv)
    try:
        return run_request(project=args.project, spec=args.spec)
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
