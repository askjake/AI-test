"""Owner-scoped, target-free readiness configuration for imported projects."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import Actor
from .authoring import ProjectDocument, SshJumpConnectionRoute, lint_project_document
from .capture_adapter import CaptureAdapterRegistry
from .config import DashboardSettings
from .demonstrations import owner_principal, ownership_scope
from .target_probe import TargetProbeCheck, TargetProbeResult, TargetProbeService
from watch_learn_privacy import redaction_configuration_revision, validate_redaction_posture


_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
AdapterName = Literal["runner-local-app", "runner-vnc"]
SecretField = Literal["password_file", "gateway_password_file", "route_known_hosts_file"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReadinessError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ReadinessRegion(_StrictModel):
    x: int = Field(ge=0, le=8191)
    y: int = Field(ge=0, le=8191)
    width: int = Field(ge=1, le=8192)
    height: int = Field(ge=1, le=8192)


class SecretReferenceAssignment(_StrictModel):
    field: SecretField
    reference_name: str = Field(min_length=1, max_length=127, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

    @field_validator("reference_name")
    @classmethod
    def _safe_reference(cls, value: str) -> str:
        if not _REFERENCE_RE.fullmatch(value) or ".." in value:
            raise ValueError("Secret reference name is not safe.")
        return value


class ReadinessDraft(_StrictModel):
    schema_version: Literal[1] = 1
    adapter: AdapterName
    ready_window: str = Field(min_length=1, max_length=240)
    frame_width: int = Field(ge=1, le=8192)
    frame_height: int = Field(ge=1, le=8192)
    redaction_regions: list[ReadinessRegion] = Field(min_length=1, max_length=64)
    secret_references: list[SecretReferenceAssignment] = Field(default_factory=list, max_length=3)

    @field_validator("ready_window")
    @classmethod
    def _safe_window(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Ready-window text contains prohibited characters.")
        return value

    @model_validator(mode="after")
    def _bounded_unique_values(self):
        fields = [item.field for item in self.secret_references]
        if len(fields) != len(set(fields)):
            raise ValueError("Secret-reference fields must be unique.")
        for region in self.redaction_regions:
            if region.x + region.width > self.frame_width or region.y + region.height > self.frame_height:
                raise ValueError("Redaction bounds must fit the declared frame contract.")
        return self


class ReadinessPreviewRequest(ReadinessDraft):
    expected_project_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_target_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReadinessSaveRequest(ReadinessPreviewRequest):
    confirm_security_values: Literal[True]


class ReadinessRevisionRequest(_StrictModel):
    configuration_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReadinessActivateRequest(ReadinessRevisionRequest):
    readiness_check_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_target_contact: Literal[True]


class ReadinessTargetPreflightRequest(ReadinessRevisionRequest):
    activation_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReadinessComponent(_StrictModel):
    key: Literal[
        "source-import", "specifications", "manual", "target", "adapter", "destination-policy",
        "client-static-policy", "ready-window", "redaction", "pre-relay-redaction",
        "secret-references", "readiness-check", "target-contact-activation", "connect",
    ]
    state: Literal["ready", "missing", "invalid", "pending", "not-required"]
    detail: str = Field(min_length=1, max_length=400)


class SecretReferenceStatus(_StrictModel):
    field: SecretField
    required: bool
    reference_name: str | None = Field(default=None, max_length=127)
    private_regular_file: bool = False


class ReadinessConfiguration(ReadinessDraft):
    pass


class ReadinessInspection(_StrictModel):
    project_name: str
    imported_project: bool
    workflow_required: bool
    source_import_complete: bool
    specifications_imported: bool
    manual_imported: bool
    project_revision: str
    base_target_revision: str
    effective_target_revision: str
    privacy_revision: str
    target_type: str
    approved_adapters: list[AdapterName]
    destination_policy: str
    configuration: ReadinessConfiguration | None = None
    configuration_revision: str | None = None
    readiness_check_revision: str | None = None
    readiness_checked: bool = False
    target_contact_activated: bool = False
    activation_revision: str | None = None
    activation_expires_at: str | None = None
    connect_authorized: bool = False
    secret_references: list[SecretReferenceStatus] = Field(default_factory=list)
    static_checks: list[TargetProbeCheck] = Field(default_factory=list)
    components: list[ReadinessComponent]
    contacts_target: Literal[False] = False


class _StoredReadiness(_StrictModel):
    schema_version: Literal[1] = 1
    owner_principal: str = Field(pattern=r"^[a-f0-9]{64}$")
    project_name: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"
    )
    project_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    base_target_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    configuration: ReadinessConfiguration
    configuration_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    saved_at: str
    readiness_check_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    readiness_target_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    checked_at: str | None = None
    activation_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    activated_at: str | None = None
    activation_expires_at: str | None = None

    @model_validator(mode="after")
    def _consistent_receipts(self):
        checked = (
            self.readiness_check_revision,
            self.readiness_target_revision,
            self.checked_at,
        )
        if any(checked) != all(checked):
            raise ValueError("Readiness check metadata is incomplete.")
        activated = (
            self.activation_revision,
            self.activated_at,
            self.activation_expires_at,
        )
        if any(activated) != all(activated) or (all(activated) and not all(checked)):
            raise ValueError("Target-contact activation metadata is incomplete.")
        return self


class WatchLearnReadinessService:
    """Private CAS state; all validation paths are target-free."""

    def __init__(self, settings: DashboardSettings, *, clock=None):
        self.settings = settings
        self.root = os.path.abspath(settings.watch_learn_readiness_root)
        self._clock = clock or _now
        self._lock = threading.RLock()

    @staticmethod
    def _require_unique_owner(actor: Actor) -> None:
        if ownership_scope(actor)[0] not in {"unique-identity", "shared-operator"}:
            raise ReadinessError(
                "unique_identity_required",
                "Imported-project Watch & Learn readiness requires approved OIDC sign-in with a unique subject.",
                status_code=403,
            )

    def _owner_dir(self, actor: Actor) -> tuple[str, str]:
        self._require_unique_owner(actor)
        principal = owner_principal(actor)
        return principal, os.path.join(self.root, "owners", principal)

    @staticmethod
    def _project_name(project: ProjectDocument) -> str:
        if not _PROJECT_RE.fullmatch(project.dir_name):
            raise ReadinessError("invalid_project", "Project identity is invalid.", status_code=422)
        return project.dir_name

    def _ensure_private_root(self, owner_dir: str) -> None:
        for path in (self.root, os.path.join(self.root, "owners"), owner_dir):
            os.makedirs(path, mode=0o700, exist_ok=True)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ReadinessError("unsafe_readiness_store", "Private readiness storage is unsafe.", status_code=503)
            os.chmod(path, 0o700)

    def _path(self, actor: Actor, project: ProjectDocument) -> tuple[str, str]:
        principal, owner_dir = self._owner_dir(actor)
        return principal, os.path.join(owner_dir, self._project_name(project) + ".json")

    def _load(self, actor: Actor, project: ProjectDocument) -> _StoredReadiness | None:
        principal, path = self._path(actor, project)
        if not os.path.exists(path):
            return None
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ReadinessError("unsafe_readiness_record", "Private readiness state is unsafe.", status_code=503)
        try:
            record = _StoredReadiness.model_validate_json(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            raise ReadinessError("invalid_readiness_record", "Private readiness state is invalid.", status_code=503) from exc
        if record.owner_principal != principal or record.project_name != project.dir_name:
            raise ReadinessError("readiness_owner_mismatch", "Private readiness state ownership is invalid.", status_code=503)
        return record

    def _save(self, actor: Actor, project: ProjectDocument, record: _StoredReadiness) -> None:
        _principal, path = self._path(actor, project)
        owner_dir = os.path.dirname(path)
        self._ensure_private_root(owner_dir)
        descriptor, temporary = tempfile.mkstemp(prefix=".readiness-", suffix=".tmp", dir=owner_dir)
        try:
            os.fchmod(descriptor, 0o600)
            payload = (record.model_dump_json(exclude_none=False) + "\n").encode("utf-8")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write while saving readiness configuration")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory = os.open(owner_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _approved_adapter(target_type: str) -> AdapterName | None:
        return {"local-app": "runner-local-app", "vnc": "runner-vnc"}.get(target_type)

    @staticmethod
    def _required_secret_fields(project: ProjectDocument) -> list[SecretField]:
        if project.target.type != "vnc":
            return []
        fields: list[SecretField] = ["password_file"]
        if isinstance(project.target.route, SshJumpConnectionRoute):
            fields.extend(["gateway_password_file", "route_known_hosts_file"])
        return fields

    @staticmethod
    def _configuration(body: ReadinessDraft) -> ReadinessConfiguration:
        return ReadinessConfiguration.model_validate(body.model_dump(include={
            "schema_version", "adapter", "ready_window", "frame_width", "frame_height",
            "redaction_regions", "secret_references",
        }))

    def apply_configuration(self, project: ProjectDocument, configuration: ReadinessConfiguration) -> ProjectDocument:
        expected = self._approved_adapter(project.target.type)
        if expected is None or configuration.adapter != expected:
            raise ReadinessError("adapter_mismatch", "The selected adapter is not approved for this target type.", status_code=422)
        assignments = {item.field: item.reference_name for item in configuration.secret_references}
        allowed = set(self._required_secret_fields(project))
        if set(assignments) - allowed:
            raise ReadinessError("secret_reference_field", "A secret reference was supplied for an inapplicable field.", status_code=422)
        updates: dict[str, object] = {"watch_learn_ready_window": configuration.ready_window}
        if project.target.type == "vnc":
            updates["password_file"] = assignments.get("password_file")
            updates["gateway_password_file"] = assignments.get("gateway_password_file")
            route = project.target.route
            if isinstance(route, SshJumpConnectionRoute):
                updates["route"] = route.model_copy(update={
                    "known_hosts_file": assignments.get("route_known_hosts_file")
                }, deep=True)
        target = project.target.model_copy(update=updates, deep=True)
        redaction = [[item.x, item.y, item.width, item.height] for item in configuration.redaction_regions]
        effective = project.model_copy(update={"target": target, "redaction": redaction}, deep=True)
        normalised, diagnostics = lint_project_document(
            effective, require_manual_on_disk=False, require_schedule=False, new_project=False
        )
        if any(item.severity == "error" for item in diagnostics):
            raise ReadinessError("configuration_invalid", "Readiness configuration failed typed project validation.", status_code=422)
        validate_redaction_posture(normalised.redaction)
        return normalised

    @staticmethod
    def _manifest_state(project_dir: Path) -> bool:
        path = project_dir / "support" / "project-import-manifest.json"
        if not path.is_file() or path.is_symlink():
            return False
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value.get("version") == 1 and value.get("origin") == "project-folder-import" and isinstance(value.get("files"), list)
        except (OSError, ValueError, AttributeError):
            return False

    def is_imported_project(self, project_dir: Path) -> bool:
        """Recognize new manifests and the private audit record used by legacy imports."""
        if self._manifest_state(project_dir):
            return True
        audit_path = Path(
            self.settings.project_import_audit_path
            or Path(self.settings.reports_dir) / ".auth" / "project_import.jsonl"
        ).absolute()
        try:
            info = os.lstat(audit_path)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > 8 * 1024 * 1024
            ):
                return False
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if (
                    isinstance(event, dict)
                    and event.get("action") == "apply"
                    and event.get("result") == "imported"
                    and event.get("destination_slug") == project_dir.name
                ):
                    return True
        except (OSError, UnicodeError, ValueError):
            return False
        return False

    @staticmethod
    def _content_state(project_dir: Path) -> tuple[bool, bool]:
        specs = any(path.is_file() and path.name not in {"README.md", "TEMPLATE.md"} for path in project_dir.rglob("*.md") if "manual" not in path.relative_to(project_dir).parts)
        manual = (project_dir / "manual" / "manual.md").is_file()
        return specs, manual

    def _current_record(
        self, actor: Actor, project: ProjectDocument, project_revision: str, base_target_revision: str
    ) -> _StoredReadiness | None:
        record = self._load(actor, project)
        if record and (record.project_revision != project_revision or record.base_target_revision != base_target_revision):
            return None
        return record

    def effective_project(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, imported_project: bool,
    ) -> tuple[ProjectDocument, _StoredReadiness | None]:
        if not imported_project or ownership_scope(actor)[0] not in {"unique-identity", "shared-operator"}:
            return project, None
        record = self._current_record(actor, project, project_revision, base_target_revision)
        if record is None:
            return project, None
        return self.apply_configuration(project, record.configuration), record

    def preview(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, imported_project: bool, body: ReadinessPreviewRequest,
        probe_service: TargetProbeService, adapters: CaptureAdapterRegistry | None = None,
        project_dir: Path | None = None,
    ) -> ReadinessInspection:
        self._require_unique_owner(actor)
        if not imported_project:
            raise ReadinessError("readiness_not_required", "This project was not created by project-folder import.", status_code=409)
        if body.expected_project_revision != project_revision or body.expected_target_revision != base_target_revision:
            raise ReadinessError("revision_conflict", "The project or destination policy changed; inspect it again.", status_code=409)
        configuration = self._configuration(body)
        effective = self.apply_configuration(project, configuration)
        return self.inspect(
            actor, project, project_dir=project_dir, project_revision=project_revision,
            base_target_revision=base_target_revision, probe_service=probe_service,
            adapters=adapters, imported_project=True, preview_configuration=configuration,
            effective_override=effective,
        )

    def save(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, imported_project: bool, body: ReadinessSaveRequest,
    ) -> _StoredReadiness:
        self._require_unique_owner(actor)
        if not imported_project:
            raise ReadinessError("readiness_not_required", "This project was not created by project-folder import.")
        if body.expected_project_revision != project_revision or body.expected_target_revision != base_target_revision:
            raise ReadinessError("revision_conflict", "The project or destination policy changed; inspect it again.")
        configuration = self._configuration(body)
        self.apply_configuration(project, configuration)
        principal = owner_principal(actor)
        revision = _digest({"project_revision": project_revision, "target_revision": base_target_revision, "configuration": configuration.model_dump(mode="json")})
        record = _StoredReadiness(
            owner_principal=principal, project_name=project.dir_name,
            project_revision=project_revision, base_target_revision=base_target_revision,
            configuration=configuration, configuration_revision=revision,
            saved_at=_timestamp(self._clock()), readiness_check_revision=None,
            readiness_target_revision=None,
            checked_at=None, activation_revision=None, activated_at=None, activation_expires_at=None,
        )
        with self._lock:
            self._save(actor, project, record)
        return record

    def check(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, body: ReadinessRevisionRequest,
        probe_service: TargetProbeService, adapters: CaptureAdapterRegistry,
    ) -> _StoredReadiness:
        with self._lock:
            record = self._current_record(actor, project, project_revision, base_target_revision)
            if record is None or record.configuration_revision != body.configuration_revision:
                raise ReadinessError("configuration_revision_conflict", "Readiness configuration changed; inspect it again.")
            effective = self.apply_configuration(project, record.configuration)
            try:
                checks = probe_service.static_checks(effective)
            except Exception as exc:
                raise ReadinessError(
                    "readiness_check_failed",
                    "Target-free readiness checks did not pass.",
                    status_code=422,
                ) from exc
            capability = adapters.capability(effective.target.type)
            required = set(self._required_secret_fields(effective))
            configured = {item.field for item in record.configuration.secret_references}
            if required - configured or any(item.status != "passed" for item in checks if item.stage in {"static-policy", "client-runtime"}) or any(item.status == "failed" for item in checks) or not capability.available:
                raise ReadinessError("readiness_check_failed", "Target-free readiness checks did not pass.", status_code=422)
            readiness_target_revision = probe_service.target_revision(effective)
            checked = _digest({"configuration_revision": record.configuration_revision, "target_revision": readiness_target_revision, "checks": [item.model_dump(mode="json") for item in checks], "adapter": capability.reason_code})
            updated = record.model_copy(update={
                "readiness_check_revision": checked,
                "readiness_target_revision": readiness_target_revision,
                "checked_at": _timestamp(self._clock()), "activation_revision": None,
                "activated_at": None, "activation_expires_at": None,
            })
            self._save(actor, project, updated)
        return updated

    def activate(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, body: ReadinessActivateRequest,
        probe_service: TargetProbeService,
    ) -> _StoredReadiness:
        with self._lock:
            record = self._current_record(actor, project, project_revision, base_target_revision)
            effective = self.apply_configuration(project, record.configuration) if record else None
            current_target_revision = probe_service.target_revision(effective) if effective else None
            if (
                record is None or record.configuration_revision != body.configuration_revision
                or not record.readiness_check_revision
                or record.readiness_check_revision != body.readiness_check_revision
                or record.readiness_target_revision != current_target_revision
            ):
                raise ReadinessError("readiness_check_required", "Run the current target-free readiness check before activation.")
            activated = self._clock()
            expires = activated + timedelta(seconds=self.settings.watch_learn_readiness_activation_ttl_seconds)
            activation = _digest({"configuration_revision": record.configuration_revision, "check_revision": record.readiness_check_revision, "target_revision": current_target_revision, "activated_at": _timestamp(activated)})
            updated = record.model_copy(update={
                "activation_revision": activation, "activated_at": _timestamp(activated),
                "activation_expires_at": _timestamp(expires),
            })
            self._save(actor, project, updated)
        return updated

    def readiness_check_active(
        self, record: _StoredReadiness | None, effective_target_revision: str
    ) -> bool:
        return bool(
            record
            and record.readiness_check_revision
            and record.readiness_target_revision == effective_target_revision
        )

    def activation_active(
        self, record: _StoredReadiness | None, effective_target_revision: str | None = None
    ) -> bool:
        if not record or not record.activation_revision or not record.activation_expires_at:
            return False
        if (
            effective_target_revision is not None
            and record.readiness_target_revision != effective_target_revision
        ):
            return False
        try:
            expires = datetime.fromisoformat(record.activation_expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return self._clock() < expires

    @staticmethod
    def _target_preflight_satisfies(
        result: TargetProbeResult | None, project: ProjectDocument, target_revision: str
    ) -> bool:
        if (
            result is None
            or result.revision != target_revision
            or result.target_type != project.target.type
        ):
            return False
        checks = {item.stage: item.status for item in result.checks}
        allowed_auth = {"unsupported"} if project.target.type == "local-app" else {"unsupported", "passed"}
        return (
            project.target.type in {"local-app", "vnc"}
            and checks.get("static-policy") == "passed"
            and checks.get("client-runtime") == "passed"
            and checks.get("transport") == ("passed" if project.target.type == "vnc" else "not-run")
            and checks.get("authentication-session") in allowed_auth
            and "failed" not in checks.values()
        )

    def require_activation(
        self, actor: Actor, project: ProjectDocument, *, project_revision: str,
        base_target_revision: str, body: ReadinessTargetPreflightRequest,
        probe_service: TargetProbeService,
    ) -> tuple[ProjectDocument, _StoredReadiness]:
        with self._lock:
            record = self._current_record(actor, project, project_revision, base_target_revision)
            effective = self.apply_configuration(project, record.configuration) if record else None
            current_target_revision = probe_service.target_revision(effective) if effective else None
            if (
                record is None or record.configuration_revision != body.configuration_revision
                or record.activation_revision != body.activation_revision
                or not self.activation_active(record, current_target_revision)
            ):
                raise ReadinessError("target_contact_activation_required", "Explicit current target-contact activation is required.", status_code=403)
            return effective, record

    @staticmethod
    def _destination_policy(project: ProjectDocument) -> str:
        target = project.target
        if target.type == "vnc":
            route = "direct" if target.route.type == "direct" else "approved SSH jump"
            return f"Exact allowlisted VNC destination {target.host}:{target.port or 5900} via {route}; destination fields are read-only here."
        if target.type == "local-app":
            return "Clone-configured local application; command and window destination fields are read-only here."
        return "No approved Watch & Learn adapter exists for this target type."

    def inspect(
        self, actor: Actor, project: ProjectDocument, *, project_dir: Path | None,
        project_revision: str, base_target_revision: str,
        probe_service: TargetProbeService, adapters: CaptureAdapterRegistry | None,
        imported_project: bool | None = None,
        preview_configuration: ReadinessConfiguration | None = None,
        effective_override: ProjectDocument | None = None,
        connect_authorized: bool = False,
    ) -> ReadinessInspection:
        self._require_unique_owner(actor)
        if imported_project is None:
            imported_project = bool(project_dir and self.is_imported_project(project_dir))
        specs, manual = self._content_state(project_dir) if project_dir else (True, True)
        record = None if preview_configuration else self._current_record(actor, project, project_revision, base_target_revision)
        configuration = preview_configuration or (record.configuration if record else None)
        effective = effective_override or (self.apply_configuration(project, configuration) if configuration else project)
        effective_target_revision = probe_service.target_revision(effective)
        privacy_revision = redaction_configuration_revision(effective.redaction)
        checks: list[TargetProbeCheck] = []
        try:
            checks = probe_service.static_checks(effective)
        except Exception:
            checks = []
        required = self._required_secret_fields(effective)
        configured = {item.field: item.reference_name for item in configuration.secret_references} if configuration else {}
        secret_status: list[SecretReferenceStatus] = []
        for field in required:
            name = configured.get(field)
            metadata = probe_service._secret_state(name) if name else {}
            secret_status.append(SecretReferenceStatus(
                field=field, required=True, reference_name=name,
                private_regular_file=bool(metadata.get("private")),
            ))
        configured_complete = bool(configuration) and not (set(required) - set(configured))
        references_private = configured_complete and all(
            item.private_regular_file for item in secret_status
        )
        approved = self._approved_adapter(project.target.type)
        adapter_available = bool(adapters and adapters.capability(project.target.type).available) if adapters else approved is not None
        check_states = {item.stage: item.status for item in checks}
        static_ready = (
            check_states.get("static-policy") == "passed"
            and check_states.get("client-runtime") == "passed"
            and "failed" not in check_states.values()
        )
        checked = self.readiness_check_active(record, effective_target_revision)
        activated = self.activation_active(record, effective_target_revision)
        current_probe = probe_service.current_result(effective) if configuration else None
        connect_authorized = connect_authorized or (
            activated and self._target_preflight_satisfies(
                current_probe, effective, effective_target_revision
            )
        )
        components = [
            ReadinessComponent(key="source-import", state="ready" if imported_project else "not-required", detail="Trusted project-folder import provenance is present." if imported_project else "This managed project does not require imported-project onboarding."),
            ReadinessComponent(key="specifications", state="ready" if specs else "missing", detail="Runnable specifications are present." if specs else "No runnable specification was found."),
            ReadinessComponent(key="manual", state="ready" if manual else "missing", detail="The portable project manual is present." if manual else "manual/manual.md is missing."),
            ReadinessComponent(key="target", state="ready" if approved else "invalid", detail=f"Configured target type: {project.target.type}."),
            ReadinessComponent(key="adapter", state="ready" if configuration and adapter_available else "missing", detail="The approved adapter is selected and locally available." if configuration and adapter_available else "Select the one allowlisted adapter for this target type."),
            ReadinessComponent(key="destination-policy", state="ready" if approved else "invalid", detail=self._destination_policy(project)),
            ReadinessComponent(key="client-static-policy", state="ready" if static_ready else "pending", detail="Target-free typed policy and local runtime checks passed." if static_ready else "Save and run the target-free readiness check."),
            ReadinessComponent(key="ready-window", state="ready" if configuration and configuration.ready_window else "missing", detail="An explicit post-login ready-window rule is configured." if configuration else "Configure and confirm the exact ready-window title."),
            ReadinessComponent(key="redaction", state="ready" if configuration else "missing", detail=f"Fixed-region redaction is bound to {configuration.frame_width}×{configuration.frame_height}." if configuration else "Configure frame dimensions and at least one fixed redaction region."),
            ReadinessComponent(key="pre-relay-redaction", state="ready" if record and configuration else "pending", detail="The saved fixed regions are activated in the runner before any frame reaches the dashboard." if record and configuration else ("The previewed regions will become pre-relay policy only after explicit save." if configuration else "Pre-relay redaction remains unavailable until a valid configuration is saved.")),
            ReadinessComponent(key="secret-references", state=("not-required" if not required else "ready" if references_private else "invalid" if configured_complete else "missing"), detail=("This target type requires no secret reference." if not required else "Every required reference resolves to a private regular file; values were not read." if references_private else "Reference names are configured, but one or more private files are unavailable." if configured_complete else "Configure every required secret reference name.")),
            ReadinessComponent(key="readiness-check", state="ready" if checked else "pending", detail="The current saved configuration passed target-free readiness checks." if checked else "A target-free readiness check is required after save."),
            ReadinessComponent(key="target-contact-activation", state="ready" if activated else "pending", detail="Target contact is explicitly activated for a short window." if activated else "Target contact remains disabled until explicitly activated."),
            ReadinessComponent(key="connect", state="ready" if connect_authorized else "pending", detail="Connect is currently authorized." if connect_authorized else "Connect remains unavailable until activation and the existing bounded target preflight pass."),
        ]
        return ReadinessInspection(
            project_name=project.dir_name, imported_project=imported_project,
            workflow_required=imported_project, source_import_complete=imported_project,
            specifications_imported=specs, manual_imported=manual,
            project_revision=project_revision, base_target_revision=base_target_revision,
            effective_target_revision=effective_target_revision, privacy_revision=privacy_revision,
            target_type=project.target.type,
            approved_adapters=[approved] if approved else [],
            destination_policy=self._destination_policy(project), configuration=configuration,
            configuration_revision=record.configuration_revision if record else None,
            readiness_check_revision=record.readiness_check_revision if record and checked else None,
            readiness_checked=checked, target_contact_activated=activated,
            activation_revision=record.activation_revision if record and activated else None,
            activation_expires_at=record.activation_expires_at if record and activated else None,
            connect_authorized=connect_authorized, secret_references=secret_status,
            static_checks=checks, components=components,
        )
