"""Bounded, operator-requested target preflight for the Project Builder.

This module is intentionally independent from ``orchestrator.targets``.  A
preflight never opens a viewer, creates a project, invokes a model, or runs a
specification.  Browser values are accepted only through ``ProjectDocument``;
network activity uses ``socket.create_connection`` after exact allowlist
enforcement, and the only subprocess arguments are fixed client capability
commands or a fixed non-mutating SSH session check.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .authoring import ProjectDocument, lint_project_document
from .config import DashboardSettings
from target_routing import SshRouteError, build_ssh_argv, build_ssh_gateway_probe_argv


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


ProbeStatus = Literal["passed", "failed", "partial", "unsupported", "not-run"]
ProbeStage = Literal[
    "static-policy",
    "secret-reference",
    "client-runtime",
    "transport",
    "authentication-session",
    "expected-window",
]


class TargetProbeCheck(_StrictModel):
    stage: ProbeStage
    status: ProbeStatus
    detail: str = Field(min_length=1, max_length=300)


class TargetProbeRequest(_StrictModel):
    project: ProjectDocument

    @model_validator(mode="after")
    def _bounded_request(self):
        if len(self.model_dump_json()) > 128_000:
            raise ValueError("Target preflight request exceeds the bounded typed payload size.")
        return self


class TargetProbeResult(_StrictModel):
    probe_id: str = Field(min_length=8, max_length=80)
    revision: str = Field(min_length=64, max_length=64)
    target_type: Literal["local-app", "host-app", "ssh-terminal", "rdp", "vnc"]
    outcome: ProbeStatus
    started_at: str
    completed_at: str
    expires_at: str
    checks: list[TargetProbeCheck] = Field(min_length=6, max_length=6)


class TargetProbeAuditEvent(_StrictModel):
    action: Literal["test-target"] = "test-target"
    target_type: Literal["local-app", "host-app", "ssh-terminal", "rdp", "vnc"]
    outcome: ProbeStatus
    revision: str = Field(min_length=64, max_length=64)
    timestamp: str


class TargetProbeBusyError(ValueError):
    """The exact target revision already has an active bounded probe."""


class TargetProbeValidationError(ValueError):
    """Static target policy rejected the request before any activity."""


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _default_connect(host: str, port: int, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        return


class TargetProbeService:
    """Run and retain isolated preflights for exact non-secret target revisions.

    Results are intentionally memory-only.  A process restart forgets them,
    and a short TTL plus canonical target digest prevents stale satisfaction.
    Dependencies are injectable so tests never launch a client or contact a
    target.
    """

    def __init__(
        self,
        settings: DashboardSettings,
        *,
        clock: Callable[[], datetime] | None = None,
        connector: Callable[[str, int, float], None] | None = None,
        popen_factory: Callable[..., subprocess.Popen] | None = None,
        which: Callable[[str], str | None] | None = None,
        probe_hook: Callable[[ProjectDocument], list[TargetProbeCheck] | None] | None = None,
    ) -> None:
        self.settings = settings
        self._clock = clock or _now
        self._connect = connector or _default_connect
        self._popen = popen_factory or subprocess.Popen
        self._which = which or shutil.which
        self._probe_hook = probe_hook
        self._lock = threading.RLock()
        self._inflight: set[str] = set()
        self._results: dict[str, TargetProbeResult] = {}
        self._audit: list[TargetProbeAuditEvent] = []

    def _secrets_root(self) -> str:
        value = (
            os.environ.get("DASHBOARD_SECRETS_DIR")
            or os.environ.get("SECRETS_DIR")
            or self.settings.secrets_dir
        )
        return os.path.abspath(value)

    def _secret_state(self, reference: str | None) -> dict[str, object]:
        if not reference or not _REFERENCE_RE.fullmatch(reference) or ".." in reference:
            return {"set": bool(reference), "safe": False, "regular": False}
        root = self._secrets_root()
        candidate = os.path.abspath(os.path.join(root, reference))
        if os.path.commonpath((root, candidate)) != root:
            return {"set": True, "safe": False, "regular": False}
        try:
            info = os.lstat(candidate)
        except OSError:
            return {"set": True, "safe": True, "regular": False}
        regular = stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        private = (
            regular
            and stat.S_IMODE(info.st_mode) & 0o077 == 0
            and info.st_uid == os.geteuid()
        )
        # Metadata, never bytes or length, invalidates a cached result after a
        # reference is replaced while keeping password content out of the digest.
        return {
            "set": True,
            "safe": True,
            "regular": regular,
            "private": private,
            "mode": stat.S_IMODE(info.st_mode) if regular else None,
            "inode": info.st_ino if regular else None,
            "modified_ns": info.st_mtime_ns if regular else None,
        }

    def target_revision(self, project: ProjectDocument) -> str:
        target = project.target
        target_data = target.model_dump(mode="json", exclude_none=True)
        reference_names = {
            name: target_data.pop(name, None)
            for name in ("key", "password_file", "gateway_password_file")
        }
        route_data = target_data.get("route")
        if isinstance(route_data, dict):
            reference_names["route.known_hosts_file"] = route_data.pop("known_hosts_file", None)
        relevant_allowlists: dict[str, list[str]] = {}
        if target.type == "ssh-terminal":
            relevant_allowlists["ssh"] = project.ssh_host_allowlist
        elif target.type == "rdp":
            relevant_allowlists["rdp"] = project.rdp_host_allowlist
        elif target.type == "vnc":
            relevant_allowlists["vnc"] = project.vnc_host_allowlist
            route = getattr(target, "route", None)
            if getattr(target, "via", None) or (route is not None and route.type == "ssh-jump"):
                relevant_allowlists["ssh"] = project.ssh_host_allowlist
        payload = {
            "project": project.dir_name,
            "target": target_data,
            "allowlists": relevant_allowlists,
            "secret_references": {
                name: {
                    "name_digest": _digest(reference) if reference else None,
                    "state": self._secret_state(reference),
                }
                for name, reference in reference_names.items()
            },
            "runtime_policy": {
                "host_app_enabled": os.environ.get("HOST_APP_ENABLED") == "1",
                "host_app_allow_roots_digest": _digest(os.environ.get("HOST_APP_ALLOW_ROOTS", "")),
            } if target.type == "host-app" else {},
        }
        return _digest(payload)

    def current_result(self, project: ProjectDocument) -> TargetProbeResult | None:
        revision = self.target_revision(project)
        with self._lock:
            result = self._results.get(revision)
        if not result:
            return None
        try:
            expires = datetime.fromisoformat(result.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if self._clock() >= expires:
            with self._lock:
                self._results.pop(revision, None)
            return None
        return result

    def audit(self, limit: int = 100) -> list[TargetProbeAuditEvent]:
        with self._lock:
            return list(self._audit[-max(1, min(limit, 200)):])

    def static_checks(self, project: ProjectDocument) -> list[TargetProbeCheck]:
        """Check typed policy, secret metadata, and local client capability only.

        This method performs no DNS lookup, socket connection, authentication,
        window query, target launch, or model/project activity.
        """
        self._static_gate(project)
        return [
            self._check(
                "static-policy", "passed",
                "Typed target schema, policy, and exact effective allowlists passed.",
            ),
            self._reference_check(project),
            self._runtime_check(project),
        ]

    @staticmethod
    def _check(stage: ProbeStage, status: ProbeStatus, detail: str) -> TargetProbeCheck:
        return TargetProbeCheck(stage=stage, status=status, detail=detail)

    def _static_gate(self, project: ProjectDocument) -> None:
        lint_project = project
        if not lint_project.manual_dir:
            lint_project = lint_project.model_copy(update={"manual_dir": "managed-by-server"})
        _normalised, diagnostics = lint_project_document(
            lint_project,
            require_manual_on_disk=False,
            require_schedule=False,
            new_project=False,
        )
        if any(item.severity == "error" for item in diagnostics):
            raise TargetProbeValidationError(
                "Static target validation must pass before target activity."
            )
        target = project.target
        if target.type in {"ssh-terminal", "rdp", "vnc"}:
            host = getattr(target, "host", None)
            allowlist = {
                "ssh-terminal": project.ssh_host_allowlist,
                "rdp": project.rdp_host_allowlist,
                "vnc": project.vnc_host_allowlist,
            }[target.type]
            if not host or not _HOST_RE.fullmatch(host) or host not in allowlist:
                raise TargetProbeValidationError(
                    "The exact target host must be in the effective allowlist before target activity."
                )
        if target.type == "vnc" and getattr(target, "via", None):
            gateway = target.via.rsplit("@", 1)[-1]
            if not _HOST_RE.fullmatch(gateway) or gateway not in project.ssh_host_allowlist:
                raise TargetProbeValidationError(
                    "The exact VNC gateway must be in the effective SSH allowlist before target activity."
                )
        route = getattr(target, "route", None)
        if route is not None and route.type == "ssh-jump":
            if target.type not in {"ssh-terminal", "vnc"}:
                raise TargetProbeValidationError(
                    "Jump-host routing is supported only for SSH terminal and VNC targets."
                )
            if not route.host or not _HOST_RE.fullmatch(route.host) or route.host not in project.ssh_host_allowlist:
                raise TargetProbeValidationError(
                    "The exact approved jump host must be in the effective SSH allowlist before target activity."
                )
            if route.user and not _USER_RE.fullmatch(route.user):
                raise TargetProbeValidationError("SSH jump user is not safe for a typed preflight.")
        if target.type == "ssh-terminal" and getattr(target, "user", None):
            if not _USER_RE.fullmatch(target.user):
                raise TargetProbeValidationError("SSH user is not safe for a typed preflight.")

    def _reference_check(self, project: ProjectDocument) -> TargetProbeCheck:
        target = project.target
        references: list[str | None] = []
        if target.type == "ssh-terminal":
            references = [getattr(target, "key", None)]
            route = getattr(target, "route", None)
            if route is not None and route.type == "ssh-jump":
                references.append(route.known_hosts_file)
        elif target.type == "rdp":
            references = [getattr(target, "password_file", None)]
        elif target.type == "vnc":
            references = [getattr(target, "password_file", None)]
            route = getattr(target, "route", None)
            if route is not None and route.type == "ssh-jump":
                references.append(getattr(target, "gateway_password_file", None))
                references.append(route.known_hosts_file)
        configured = [item for item in references if item]
        if not configured:
            return self._check(
                "secret-reference",
                "partial" if target.type in {"ssh-terminal", "rdp", "vnc"} else "not-run",
                "No secret reference is configured; authentication may require one.",
            )
        if all(self._secret_state(item).get("private") for item in configured):
            return self._check(
                "secret-reference", "passed",
                "Configured secret references resolve to private regular files; values were not read.",
            )
        return self._check(
            "secret-reference", "failed",
            "A configured secret reference is missing or is not a private regular file.",
        )

    def invalid_secret_fields(self, project: ProjectDocument) -> list[str]:
        """Return typed field identifiers only; never reference names or values."""
        target = project.target
        fields = []
        for field in ("key", "password_file", "gateway_password_file"):
            reference = getattr(target, field, None)
            if reference and not self._secret_state(reference).get("private"):
                fields.append(f"target.{field}")
        route = getattr(target, "route", None)
        if route is not None and route.type == "ssh-jump":
            reference = route.known_hosts_file
            if reference and not self._secret_state(reference).get("private"):
                fields.append("target.route.known_hosts_file")
        return fields

    def _bounded_command(
        self,
        argv: list[str],
        *,
        timeout: float,
        input_bytes: bytes | None = None,
    ) -> tuple[int | None, bytes]:
        process = self._popen(
            argv,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={**os.environ, "LC_ALL": "C", "SSH_ASKPASS_REQUIRE": "never"},
        )
        try:
            output, _unused = process.communicate(input=input_bytes, timeout=timeout)
            return process.returncode, (output or b"")[: self.settings.wizard_probe_output_bytes]
        except subprocess.TimeoutExpired:
            self._cleanup_process_group(process)
            return None, b""
        except BaseException:
            self._cleanup_process_group(process)
            raise

    @staticmethod
    def _cleanup_process_group(process: subprocess.Popen) -> None:
        """Terminate only the subprocess group created for this one probe."""
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=0.5)
            return
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass

    def _runtime_check(self, project: ProjectDocument) -> TargetProbeCheck:
        target = project.target
        route = getattr(target, "route", None)
        if target.type == "vnc" and route is not None and route.type == "ssh-jump":
            missing = [name for name in ("xtigervncviewer", "ssh", "sshpass") if not self._which(name)]
            if missing:
                return self._check(
                    "client-runtime", "unsupported",
                    "VNC over SSH requires TigerVNC, OpenSSH, and sshpass in the approved runtime.",
                )
            client = "xtigervncviewer"
        else:
            client = {
                "ssh-terminal": "ssh",
                "rdp": "xfreerdp",
                "vnc": "xtigervncviewer",
            }.get(target.type)
        if target.type in {"local-app", "host-app"}:
            try:
                parts = shlex.split(getattr(target, "app", None) or "")
            except ValueError:
                return self._check("client-runtime", "failed", "Application command is not valid typed argv text.")
            if not parts:
                return self._check("client-runtime", "failed", "Application command is missing.")
            if target.type == "host-app":
                return self._host_app_policy_check(project)
            found = self._which(parts[0])
            return self._check(
                "client-runtime",
                "passed" if found else "unsupported",
                "Application executable is available in the dashboard runtime; it was not launched."
                if found else
                "Application availability in the isolated runner image could not be proven without launching a run.",
            )
        executable = self._which(client) if client else None
        if not client or not executable:
            return self._check("client-runtime", "unsupported", "The required target client is not installed in this runtime.")
        version_argv = {
            "ssh": [executable, "-V"],
            "xfreerdp": [executable, "/version"],
            "xtigervncviewer": [executable, "--version"],
        }[client]
        code, output = self._bounded_command(
            version_argv, timeout=min(2.0, self.settings.wizard_probe_timeout_seconds)
        )
        if code is None:
            return self._check("client-runtime", "failed", "The installed client version check exceeded its bounded timeout.")
        summary = re.sub(
            r"[^A-Za-z0-9 ._:+()/\-]+", " ",
            output.decode("utf-8", errors="replace").splitlines()[0] if output else "",
        ).strip()[:120]
        if code != 0 and not summary:
            return self._check("client-runtime", "failed", "The installed client did not provide a bounded local version result.")
        return self._check(
            "client-runtime", "passed",
            "The required client is installed and its bounded local version check completed"
            + (f": {summary}." if summary else "."),
        )

    def _host_app_policy_check(self, project: ProjectDocument) -> TargetProbeCheck:
        target = project.target
        if os.environ.get("HOST_APP_ENABLED") != "1":
            return self._check("client-runtime", "failed", "Host application launch policy is disabled.")
        roots = [
            os.path.realpath(item)
            for item in os.environ.get("HOST_APP_ALLOW_ROOTS", "").split(os.pathsep)
            if item
        ]
        if not roots:
            return self._check("client-runtime", "failed", "Host application allow roots are not configured.")
        try:
            command = shlex.split(getattr(target, "app", None) or "")
        except ValueError:
            command = []
        candidates = [command[0] if command else "", getattr(target, "cwd", None) or ""]
        for raw in candidates:
            resolved = os.path.realpath(raw)
            if not raw or not os.path.exists(resolved) or not any(
                os.path.commonpath((root, resolved)) == root for root in roots
            ):
                return self._check("client-runtime", "failed", "Host application path or working directory is outside the effective allow roots.")
        return self._check(
            "client-runtime", "passed",
            "Host application policy, real paths, and allow roots are valid; the application was not launched.",
        )

    def _transport_check(self, project: ProjectDocument) -> TargetProbeCheck:
        target = project.target
        if target.type in {"local-app", "host-app"}:
            return self._check("transport", "not-run", "No network transport applies to this target type.")
        host = getattr(target, "host", None)
        port = {"ssh-terminal": 22, "rdp": 3389, "vnc": getattr(target, "port", None) or 5900}[target.type]
        route = getattr(target, "route", None)
        if target.type in {"ssh-terminal", "vnc"} and route is not None and route.type == "ssh-jump":
            host = route.host
            port = route.port
        if target.type == "vnc" and getattr(target, "via", None):
            host = target.via.rsplit("@", 1)[-1]
            port = 22
        try:
            self._connect(host, port, self.settings.wizard_probe_timeout_seconds)
        except Exception:
            return self._check("transport", "failed", "The allowlisted transport did not accept a connection within the bounded timeout.")
        return self._check("transport", "passed", "The allowlisted transport accepted a bounded connection; this does not prove authentication or a window.")

    def _session_check(
        self,
        project: ProjectDocument,
        runtime: TargetProbeCheck,
        transport: TargetProbeCheck,
        secret: TargetProbeCheck,
    ) -> TargetProbeCheck:
        target = project.target
        route = getattr(target, "route", None)
        vnc_jump = target.type == "vnc" and route is not None and route.type == "ssh-jump"
        if target.type != "ssh-terminal" and not vnc_jump:
            detail = (
                "Local application preflight cannot prove a post-login session before launch, so "
                "this stage is unsupported. Watch & Learn may Connect paused after the independent "
                "static-policy and client-runtime gates pass; recording remains blocked until the "
                "runner verifies target.watch_learn_ready_window."
                if target.type == "local-app"
                else "The installed client has no safely supported noninteractive authentication-only proof in this preflight."
            )
            return self._check(
                "authentication-session", "unsupported",
                detail,
            )
        if runtime.status != "passed":
            return self._check("authentication-session", "not-run", "SSH session validation requires an available SSH client.")
        if transport.status != "passed":
            return self._check("authentication-session", "not-run", "SSH session validation requires a successful bounded transport check.")
        if secret.status == "failed":
            return self._check("authentication-session", "not-run", "SSH session validation requires a valid configured secret reference.")
        if vnc_jump:
            password_reference = getattr(target, "gateway_password_file", None)
            known_hosts_reference = route.known_hosts_file
            if not password_reference or not self._secret_state(password_reference).get("private"):
                return self._check("authentication-session", "failed", "The VNC jump-host password reference is unavailable; no session was attempted.")
            if not known_hosts_reference or not self._secret_state(known_hosts_reference).get("private"):
                return self._check("authentication-session", "failed", "The strict jump-host known-hosts reference is unavailable; no session was attempted.")
            sshpass = self._which("sshpass")
            ssh_executable = self._which("ssh")
            if not sshpass or not ssh_executable:
                return self._check("authentication-session", "not-run", "VNC jump authentication requires OpenSSH and sshpass.")
            gateway = f"{route.user}@{route.host}" if route.user else route.host
            try:
                argv = [
                    sshpass, "-f", str(Path(self._secrets_root()) / password_reference),
                    *build_ssh_gateway_probe_argv(
                        ssh_executable, gateway,
                        gateway_port=route.port,
                        known_hosts_path=str(Path(self._secrets_root()) / known_hosts_reference),
                        connect_timeout=max(1, int(self.settings.wizard_probe_timeout_seconds)),
                    ),
                ]
            except SshRouteError:
                return self._check("authentication-session", "failed", "The typed VNC jump route could not be represented safely; no session was attempted.")
            code, _output = self._bounded_command(argv, timeout=self.settings.wizard_probe_timeout_seconds)
            if code is None:
                return self._check("authentication-session", "failed", "The VNC jump-host authentication check timed out and was cleaned up.")
            return self._check(
                "authentication-session", "passed" if code == 0 else "failed",
                "The SSH jump host authenticated and exited without opening the VNC target."
                if code == 0 else "The bounded VNC jump-host authentication check did not succeed.",
            )
        destination = f"{target.user}@{target.host}" if getattr(target, "user", None) else target.host
        ssh_executable = self._which("ssh")
        if not ssh_executable:
            return self._check("authentication-session", "not-run", "SSH session validation requires an available SSH client.")
        reference = getattr(target, "key", None)
        key_path = None
        if reference:
            state = self._secret_state(reference)
            if not state.get("private"):
                return self._check("authentication-session", "failed", "The SSH key reference is unavailable; no session was attempted.")
            key_path = str(Path(self._secrets_root()) / reference)
        jump_host = route.host if route is not None and route.type == "ssh-jump" else None
        known_hosts_path = None
        if jump_host:
            state = self._secret_state(route.known_hosts_file)
            if not state.get("private"):
                return self._check("authentication-session", "failed", "The strict known-hosts reference is unavailable; no session was attempted.")
            known_hosts_path = str(Path(self._secrets_root()) / route.known_hosts_file)
        try:
            argv = build_ssh_argv(
                ssh_executable,
                destination,
                key_path=key_path,
                jump_host=jump_host,
                jump_user=route.user if jump_host else None,
                jump_port=route.port if jump_host else 22,
                known_hosts_path=known_hosts_path,
                batch_mode=True,
                connect_timeout=max(1, int(self.settings.wizard_probe_timeout_seconds)),
                remote_command=("exit",),
            )
        except SshRouteError:
            return self._check("authentication-session", "failed", "The typed SSH route could not be represented safely; no session was attempted.")
        if not jump_host:
            destination_index = argv.index(destination)
            argv[destination_index:destination_index] = [
                "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null"
            ]
        code, _output = self._bounded_command(
            argv, timeout=self.settings.wizard_probe_timeout_seconds
        )
        if code is None:
            return self._check("authentication-session", "failed", "The SSH session check timed out and its process group was cleaned up.")
        if code == 0:
            return self._check("authentication-session", "passed", "A bounded noninteractive SSH session authenticated and exited without running project work.")
        return self._check("authentication-session", "failed", "The bounded SSH authentication/session check did not succeed.")

    @staticmethod
    def _window_check() -> TargetProbeCheck:
        return TargetProbeService._check(
            "expected-window", "unsupported",
            "Window confirmation requires launching the configured target; preflight deliberately does not launch or leave a viewer/application running.",
        )

    @staticmethod
    def _outcome(checks: list[TargetProbeCheck]) -> ProbeStatus:
        statuses = {item.status for item in checks}
        if "failed" in statuses:
            return "failed"
        applicable = [item for item in checks if item.status != "not-run"]
        if applicable and all(item.status == "passed" for item in applicable):
            return "passed"
        if "passed" in statuses or "partial" in statuses:
            return "partial"
        return "unsupported"

    def run(self, request: TargetProbeRequest) -> TargetProbeResult:
        project = request.project
        revision = self.target_revision(project)
        with self._lock:
            if revision in self._inflight:
                raise TargetProbeBusyError("A probe is already running for this exact target revision.")
            self._inflight.add(revision)
        started = self._clock()
        try:
            # This gate is deliberately before hook, process, path capability,
            # DNS, socket, or client activity.
            self._static_gate(project)
            checks = self._probe_hook(project) if self._probe_hook else None
            if checks is None:
                static, secret, runtime = self.static_checks(project)
                transport = self._transport_check(project)
                checks = [
                    static,
                    secret,
                    runtime,
                    transport,
                    self._session_check(project, runtime, transport, secret),
                    self._window_check(),
                ]
            if [item.stage for item in checks] != [
                "static-policy", "secret-reference", "client-runtime", "transport",
                "authentication-session", "expected-window",
            ]:
                raise ValueError("Probe implementation returned an invalid check sequence.")
            completed = self._clock()
            outcome = self._outcome(checks)
            result = TargetProbeResult(
                probe_id=uuid.uuid4().hex,
                revision=revision,
                target_type=project.target.type,
                outcome=outcome,
                started_at=_timestamp(started),
                completed_at=_timestamp(completed),
                expires_at=_timestamp(completed + timedelta(seconds=self.settings.wizard_probe_ttl_seconds)),
                checks=checks,
            )
            event = TargetProbeAuditEvent(
                target_type=project.target.type,
                outcome=outcome,
                revision=revision,
                timestamp=result.completed_at,
            )
            with self._lock:
                self._results[revision] = result
                self._audit.append(event)
                self._audit = self._audit[-500:]
            return result
        finally:
            with self._lock:
                self._inflight.discard(revision)
