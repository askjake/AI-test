"""Typed, non-executing project authoring primitives (Phase 13A).

This module deliberately lives with the dashboard rather than the runner.  It
turns project YAML and spec Markdown into a small, reviewable document contract
and performs only parsing, validation, rendering, hashing, and filesystem-safe
write preparation.  It never opens a target, reads a secret, starts a process,
or constructs an LLM client.  A later text-only drafting service must submit
the same typed documents through this validation path.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import shlex
from typing import Annotated, Any, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .builder_policy import BuilderReview, BuilderTrustReview, target_capability


PROJECT_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
SECRET_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
RDP_CERTIFICATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
RDP_CERTIFICATE_FINGERPRINT_RE = re.compile(
    r"^(?P<algorithm>sha1|sha256):(?P<digest>[0-9A-Fa-f: -]+)$",
    re.IGNORECASE,
)
SENSITIVE_KEY_RE = re.compile(r"(?:^|[_-])(password|secret|token|access[_-]?key)(?:$|[_-])", re.I)

PROCEDURE_PROJECT_MESSAGE = "This project was created from a procedure; edit it from the procedure screen."


def is_procedure_project(raw: Any) -> bool:
    """True for nested-RDP (rdp-chain) projects written by procedure_project.py."""
    return (
        isinstance(raw, dict)
        and isinstance(raw.get("target"), dict)
        and raw["target"].get("type") == "rdp-chain"
    )


PROJECT_KEYS = {
    "name",
    "ssh_host_allowlist",
    "rdp_host_allowlist",
    "vnc_host_allowlist",
    "max_steps",
    "max_seconds",
    "max_tokens",
    "max_total_tokens",
    "step_max_tokens",
    "keep_last_n_screenshots",
    "action_delay_seconds",
    "max_planner_steps",
    "step_max_steps",
    "target",
    "schedule",
    "enabled",
    "redaction",
    "manual_dir",
}

TARGET_FIELDS: dict[str, set[str]] = {
    "local-app": {"type", "app", "window", "watch_learn_ready_window"},
    "host-app": {"type", "app", "cwd", "window", "startup_timeout"},
    "ssh-terminal": {"type", "host", "user", "key", "window", "route"},
    "rdp": {
        "type",
        "host",
        "user",
        "password_file",
        "certificate_name",
        "certificate_fingerprint",
        "window",
        "extra_args",
        "route",
    },
    "vnc": {
        "type",
        "host",
        "port",
        "password_file",
        "window",
        "via",
        "gateway_password_file",
        "watch_learn_ready_window",
        "route",
    },
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalAppTarget(_StrictModel):
    type: Literal["local-app"] = "local-app"
    app: str | None = None
    window: str | None = None
    # Exact post-login/ready window title used by Watch & Learn to prove that
    # recording may begin. It is configuration, not a browser assertion.
    watch_learn_ready_window: str | None = Field(default=None, max_length=240)


class HostAppTarget(_StrictModel):
    type: Literal["host-app"] = "host-app"
    app: str | None = None
    cwd: str | None = None
    window: str | None = None
    startup_timeout: float | None = None


class DirectConnectionRoute(_StrictModel):
    type: Literal["direct"] = "direct"


class SshJumpConnectionRoute(_StrictModel):
    type: Literal["ssh-jump"] = "ssh-jump"
    host: str | None = None
    user: str | None = None
    port: int = 22
    known_hosts_file: str | None = None


ConnectionRoute = Annotated[
    Union[DirectConnectionRoute, SshJumpConnectionRoute],
    Field(discriminator="type"),
]


class SshTerminalTarget(_StrictModel):
    type: Literal["ssh-terminal"] = "ssh-terminal"
    host: str | None = None
    user: str | None = None
    key: str | None = None
    window: str | None = None
    route: ConnectionRoute = Field(default_factory=DirectConnectionRoute)


class RdpTarget(_StrictModel):
    type: Literal["rdp"] = "rdp"
    host: str | None = None
    user: str | None = None
    password_file: str | None = None
    certificate_name: str | None = None
    certificate_fingerprint: str | None = None
    window: str | None = None
    extra_args: str | None = None
    route: ConnectionRoute = Field(default_factory=DirectConnectionRoute)


class VncTarget(_StrictModel):
    type: Literal["vnc"] = "vnc"
    host: str | None = None
    port: int | None = None
    password_file: str | None = None
    window: str | None = None
    via: str | None = None
    gateway_password_file: str | None = None
    watch_learn_ready_window: str | None = Field(default=None, max_length=240)
    route: ConnectionRoute = Field(default_factory=DirectConnectionRoute)


TargetDocument = Annotated[
    Union[LocalAppTarget, HostAppTarget, SshTerminalTarget, RdpTarget, VncTarget],
    Field(discriminator="type"),
]


class ProjectDocument(_StrictModel):
    """The user-editable, dashboard-local representation of ``project.yaml``.

    ``legacy`` is populated only while parsing an existing source file.  Apply
    rejects any change to it, which keeps unrecognised historical data from
    vanishing while preventing typed clients from inventing new raw keys.
    """

    dir_name: str
    display_name: str
    enabled: bool = True
    schedule: str | None = None
    manual_dir: str | None = None
    target: TargetDocument
    ssh_host_allowlist: list[str] = Field(default_factory=list)
    rdp_host_allowlist: list[str] = Field(default_factory=list)
    vnc_host_allowlist: list[str] = Field(default_factory=list)
    max_steps: int | None = None
    max_seconds: int | None = None
    max_tokens: int | None = None
    max_total_tokens: int | None = None
    step_max_tokens: int | None = None
    keep_last_n_screenshots: int | None = None
    action_delay_seconds: float | None = None
    max_planner_steps: int | None = None
    step_max_steps: int | None = None
    redaction: list[Any] = Field(default_factory=list)
    legacy: dict[str, Any] = Field(default_factory=dict)


class SpecDocument(_StrictModel):
    path: str
    title: str
    goal: str
    setup: str | None = None
    assertions: list[str] = Field(default_factory=list)


class AuthoringDiagnostic(_StrictModel):
    code: str
    message: str
    field: str | None = None
    severity: Literal["error", "warning"] = "error"


class ProjectAuthoringResponse(_StrictModel):
    document: ProjectDocument
    rendered_yaml: str
    revision: str
    diagnostics: list[AuthoringDiagnostic] = Field(default_factory=list)
    inherited_fields: list[str] = Field(default_factory=list)


class SpecAuthoringResponse(_StrictModel):
    document: SpecDocument
    rendered_markdown: str
    revision: str
    diagnostics: list[AuthoringDiagnostic] = Field(default_factory=list)


class SpecPreviewResponse(_StrictModel):
    """Non-writing canonical preview for a new, not-yet-persisted spec."""

    document: SpecDocument
    rendered_markdown: str
    diagnostics: list[AuthoringDiagnostic] = Field(default_factory=list)


class AuthoringSpecSummary(_StrictModel):
    """Safe typed metadata for a project's selectable specification list."""

    path: str
    title: str
    diagnostics: list[AuthoringDiagnostic] = Field(default_factory=list)


class ProjectValidateRequest(_StrictModel):
    document: ProjectDocument


class ProjectApplyRequest(ProjectValidateRequest):
    base_revision: str


class SpecValidateRequest(_StrictModel):
    document: SpecDocument


class SpecApplyRequest(SpecValidateRequest):
    base_revision: str
    # Optional Phase 13D provenance only.  It never changes validation or the
    # compare-and-swap write itself; the server records linkage after success.
    refinement_proposal_id: str | None = Field(default=None, min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")


class SpecCreateRequest(_StrictModel):
    """Create one typed specification after a separate preview action."""

    document: SpecDocument


class TypedProjectCreateRequest(_StrictModel):
    document: ProjectDocument
    initial_spec: SpecDocument
    manual_template: str | None = None
    additional_specs: list[SpecDocument] = Field(default_factory=list, max_length=19)
    builder_review: BuilderReview | None = None
    builder_goal: str = Field(default='', max_length=2000)
    manual_outline: list[str] = Field(default_factory=list, max_length=20)
    trust_review: BuilderTrustReview | None = None


class TypedProjectCreatePreviewResponse(_StrictModel):
    """Non-writing preview for the guided new-project workflow.

    ``manual_bootstrap`` intentionally reports state rather than a host path;
    guided clients must never need to know where the managed manual lives.
    """

    document: ProjectDocument
    initial_spec: SpecDocument
    rendered_yaml: str
    rendered_markdown: str
    diagnostics: list[AuthoringDiagnostic] = Field(default_factory=list)
    manual_bootstrap: Literal["will_create_manual"] = "will_create_manual"


class AuthoringValidationError(ValueError):
    """A stable, user-oriented collection of authoring diagnostics."""

    def __init__(self, diagnostics: list[AuthoringDiagnostic]):
        self.diagnostics = diagnostics
        super().__init__("authoring validation failed")


@dataclass(frozen=True)
class ParsedProject:
    document: ProjectDocument
    diagnostics: list[AuthoringDiagnostic]
    inherited_fields: list[str]


def content_revision(content: str | bytes) -> str:
    """Return a stable SHA-256 revision of exact on-disk source bytes."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def _diagnostic(
    code: str,
    message: str,
    field: str | None = None,
    severity: Literal["error", "warning"] = "error",
) -> AuthoringDiagnostic:
    return AuthoringDiagnostic(code=code, message=message, field=field, severity=severity)


def _nonempty(value: str | None) -> bool:
    return bool(value and value.strip())


def _safe_relative_markdown(path: str) -> bool:
    if not path or os.path.isabs(path) or "\\" in path or not path.endswith(".md"):
        return False
    if ".." in path.split("/"):
        return False
    normal = os.path.normpath(path)
    return normal != "." and not normal.startswith(".." + os.sep) and normal != ".."


def _safe_secret_reference(value: str) -> bool:
    return bool(SECRET_REFERENCE_RE.fullmatch(value)) and ".." not in value


def _validate_cron(value: str) -> bool:
    """Validate the five-field numeric cron subset accepted by project schedules."""
    fields = value.split()
    if len(fields) != 5:
        return False
    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))

    def valid_atom(atom: str, low: int, high: int) -> bool:
        base, *step = atom.split("/", 1)
        if len(step) and (not step[0].isdigit() or int(step[0]) <= 0):
            return False
        if base == "*":
            return True
        if "-" in base:
            pair = base.split("-", 1)
            if len(pair) != 2 or not all(part.isdigit() for part in pair):
                return False
            return low <= int(pair[0]) <= int(pair[1]) <= high
        return base.isdigit() and low <= int(base) <= high

    for field, (low, high) in zip(fields, ranges):
        if not all(valid_atom(atom, low, high) for atom in field.split(",")):
            return False
    return True


def _normalise_rdp_extra_args(value: str | None) -> tuple[str | None, list[AuthoringDiagnostic]]:
    if not _nonempty(value):
        return None, []
    diagnostics: list[AuthoringDiagnostic] = []
    try:
        parts = shlex.split(value)
    except ValueError:
        return value, [_diagnostic("rdp_extra_args_invalid", "RDP extra arguments are not shell-quotable.", "target.extra_args")]
    retained: list[str] = []
    for part in parts:
        lowered = part.lower()
        if lowered.startswith(("/p:", "/password:")):
            diagnostics.append(_diagnostic(
                "rdp_extra_args_password",
                "RDP extra arguments must not contain password material; use password_file.",
                "target.extra_args",
            ))
        elif lowered == "/gfx-":
            diagnostics.append(_diagnostic(
                "rdp_extra_args_gfx_normalized",
                "Removed unsupported /gfx- compatibility flag.",
                "target.extra_args",
                "warning",
            ))
        elif lowered.startswith("/cert:") or lowered.startswith("/cert-"):
            diagnostics.append(_diagnostic(
                "rdp_extra_args_cert_normalized",
                "Removed an RDP certificate-policy argument; use the typed certificate name and fingerprint fields.",
                "target.extra_args",
                "warning",
            ))
        else:
            retained.append(part)
    return " ".join(shlex.quote(part) for part in retained) or None, diagnostics


def _normalise_rdp_certificate_fingerprint(value: str | None) -> str | None:
    if not _nonempty(value):
        return None
    match = RDP_CERTIFICATE_FINGERPRINT_RE.fullmatch(value.strip())
    if match is None:
        return None
    algorithm = match.group("algorithm").lower()
    digest = re.sub(r"[: -]", "", match.group("digest")).lower()
    expected_length = 40 if algorithm == "sha1" else 64
    if len(digest) != expected_length or not re.fullmatch(r"[0-9a-f]+", digest):
        return None
    return f"{algorithm}:{digest}"


def _normalise_redaction(value: list[Any]) -> tuple[list[list[int | float]], list[AuthoringDiagnostic]]:
    result: list[list[int | float]] = []
    diagnostics: list[AuthoringDiagnostic] = []
    for index, region in enumerate(value):
        values: list[Any]
        if isinstance(region, dict):
            values = [region.get("x"), region.get("y"), region.get("w", region.get("width")), region.get("h", region.get("height"))]
        elif isinstance(region, (list, tuple)):
            values = list(region)
        else:
            values = []
        if len(values) != 4 or any(not isinstance(item, (int, float)) or isinstance(item, bool) for item in values):
            diagnostics.append(_diagnostic("redaction_shape", "Each redaction region must be [x, y, width, height] or an equivalent mapping.", f"redaction[{index}]"))
            continue
        x, y, width, height = values
        if x < 0 or y < 0 or width <= 0 or height <= 0:
            diagnostics.append(_diagnostic("redaction_bounds", "Redaction coordinates must be non-negative and width/height must be positive.", f"redaction[{index}]"))
            continue
        result.append([x, y, width, height])
    return result, diagnostics


def _validate_allowlist(values: list[str], field: str) -> list[AuthoringDiagnostic]:
    diagnostics: list[AuthoringDiagnostic] = []
    if len(values) != len(set(values)):
        diagnostics.append(_diagnostic("allowlist_duplicate", "Allowlist entries must be unique.", field))
    for index, value in enumerate(values):
        if not _nonempty(value) or any(char.isspace() for char in value):
            diagnostics.append(_diagnostic("allowlist_value", "Allowlist entries must be non-empty host names without whitespace.", f"{field}[{index}]"))
    return diagnostics


def _target_data(target: TargetDocument) -> dict[str, Any]:
    return target.model_dump(exclude_none=True)


def _target_from_raw(raw: Any, legacy: dict[str, Any], diagnostics: list[AuthoringDiagnostic]) -> TargetDocument:
    if raw is None:
        raw = {"type": "local-app"}
    if not isinstance(raw, dict):
        raise AuthoringValidationError([_diagnostic("target_mapping", "target must be a YAML mapping.", "target")])
    target_type = raw.get("type", "local-app")
    if target_type not in TARGET_FIELDS:
        raise AuthoringValidationError([_diagnostic("target_type", "target.type must be one of local-app, host-app, ssh-terminal, rdp, or vnc.", "target.type")])
    allowed = TARGET_FIELDS[str(target_type)]
    unknown = {key: value for key, value in raw.items() if key not in allowed}
    if unknown:
        sensitive = [str(key) for key in unknown if SENSITIVE_KEY_RE.search(str(key))]
        if sensitive:
            diagnostics.append(_diagnostic("legacy_sensitive_target", "project target contains an unsupported sensitive field and cannot be exposed by authoring APIs.", "target"))
        else:
            legacy["target"] = unknown
            diagnostics.append(_diagnostic("legacy_target_preserved", "Unsupported target fields are preserved as legacy data and cannot be edited in the guided form.", "target", "warning"))
    payload = {key: value for key, value in raw.items() if key in allowed}
    try:
        # Pydantic's discriminated union is intentionally the only target decoder.
        return _target_adapter().validate_python(payload)
    except ValidationError as exc:
        raise AuthoringValidationError([_diagnostic("target_schema", "target does not match the selected target type.", "target")]) from exc


def _target_adapter():
    # Kept lazy so importing this dashboard-local module has no runner-model dependency.
    from pydantic import TypeAdapter
    return TypeAdapter(TargetDocument)


def parse_project_document(raw_yaml: str, *, dir_name: str) -> ParsedProject:
    """Parse existing YAML without silently losing unrecognised, safe fields."""
    try:
        raw = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError as exc:
        raise AuthoringValidationError([_diagnostic("yaml_parse", "project.yaml is not valid YAML.", "project")]) from exc
    if not isinstance(raw, dict):
        raise AuthoringValidationError([_diagnostic("yaml_mapping", "project.yaml must contain a YAML mapping.", "project")])

    if is_procedure_project(raw):
        # Single choke point for every guided-editor, raw-YAML save, import and composition path:
        # a procedure project can never be re-saved as a single-target project.
        raise AuthoringValidationError([_diagnostic("procedure_project", PROCEDURE_PROJECT_MESSAGE, "target.type")])

    diagnostics: list[AuthoringDiagnostic] = []
    legacy: dict[str, Any] = {}
    for key, value in raw.items():
        if key in PROJECT_KEYS:
            continue
        if SENSITIVE_KEY_RE.search(str(key)):
            diagnostics.append(_diagnostic("legacy_sensitive_field", "project.yaml contains an unsupported sensitive field and cannot be exposed by authoring APIs.", f"legacy.{key}"))
        else:
            legacy[str(key)] = value
    if legacy:
        diagnostics.append(_diagnostic("legacy_fields_preserved", "Unsupported project.yaml fields are preserved as legacy data and cannot be edited in the guided form.", "legacy", "warning"))

    target = _target_from_raw(raw.get("target"), legacy, diagnostics)
    payload = {
        "dir_name": dir_name,
        "display_name": str(raw.get("name", dir_name)),
        "enabled": raw.get("enabled", True),
        "schedule": raw.get("schedule"),
        "manual_dir": raw.get("manual_dir"),
        "target": _target_data(target),
        "ssh_host_allowlist": raw.get("ssh_host_allowlist") or [],
        "rdp_host_allowlist": raw.get("rdp_host_allowlist") or [],
        "vnc_host_allowlist": raw.get("vnc_host_allowlist") or [],
        "redaction": raw.get("redaction") or [],
        "legacy": legacy,
    }
    for key in (
        "max_steps", "max_seconds", "max_tokens", "max_total_tokens", "step_max_tokens",
        "keep_last_n_screenshots", "action_delay_seconds", "max_planner_steps", "step_max_steps",
    ):
        payload[key] = raw.get(key)
    try:
        document = ProjectDocument.model_validate(payload)
    except ValidationError as exc:
        raise AuthoringValidationError([_diagnostic("project_schema", "project.yaml has values that do not match the typed authoring contract.", "project")]) from exc
    if any(item.severity == "error" for item in diagnostics):
        raise AuthoringValidationError(diagnostics)
    inherited = [key for key in PROJECT_KEYS - {"target", "name", "enabled", "manual_dir", "redaction"} if key not in raw]
    return ParsedProject(document=document, diagnostics=diagnostics, inherited_fields=sorted(inherited))


def lint_project_document(
    document: ProjectDocument,
    *,
    require_manual_on_disk: bool,
    require_schedule: bool,
    new_project: bool = False,
) -> tuple[ProjectDocument, list[AuthoringDiagnostic]]:
    """Validate and canonically normalise a typed project without side effects."""
    diagnostics: list[AuthoringDiagnostic] = []
    if not PROJECT_SLUG_RE.fullmatch(document.dir_name):
        diagnostics.append(_diagnostic("project_slug", "Directory slug may contain only letters, digits, hyphens, and underscores and may not begin with a punctuation mark.", "dir_name"))
    if not _nonempty(document.display_name):
        diagnostics.append(_diagnostic("display_name", "Display name is required.", "display_name"))
    if require_schedule and document.enabled and not _nonempty(document.schedule):
        diagnostics.append(_diagnostic("schedule_required", "A project schedule is required.", "schedule"))
    elif document.schedule is not None and not _validate_cron(document.schedule):
        diagnostics.append(_diagnostic("schedule_invalid", "Schedule must be a valid five-field cron expression.", "schedule"))
    if not _nonempty(document.manual_dir):
        diagnostics.append(_diagnostic("manual_dir_required", "A project manual_dir is required.", "manual_dir"))
    elif require_manual_on_disk and not os.path.isfile(
        os.path.join(_authoring_manual_directory(document), "manual.md")
    ):
        diagnostics.append(_diagnostic("manual_missing", "manual_dir must contain a readable master manual.md before Apply.", "manual_dir"))

    for name, maximum in {
        "max_steps": 10_000,
        "max_seconds": 86_400,
        "max_tokens": 1_000_000,
        "max_total_tokens": 10_000_000,
        "step_max_tokens": 10_000_000,
        "keep_last_n_screenshots": 100,
        "max_planner_steps": 10_000,
        "step_max_steps": 10_000,
    }.items():
        value = getattr(document, name)
        if value is not None and not 1 <= value <= maximum:
            diagnostics.append(_diagnostic("limit_range", f"{name} must be between 1 and {maximum}.", name))
    if document.action_delay_seconds is not None and not 0 <= document.action_delay_seconds <= 120:
        diagnostics.append(_diagnostic("limit_range", "action_delay_seconds must be between 0 and 120.", "action_delay_seconds"))

    diagnostics.extend(_validate_allowlist(document.ssh_host_allowlist, "ssh_host_allowlist"))
    diagnostics.extend(_validate_allowlist(document.rdp_host_allowlist, "rdp_host_allowlist"))
    diagnostics.extend(_validate_allowlist(document.vnc_host_allowlist, "vnc_host_allowlist"))
    redaction, redaction_diagnostics = _normalise_redaction(document.redaction)
    diagnostics.extend(redaction_diagnostics)
    updated = document.model_copy(update={"redaction": redaction}, deep=True)

    target = updated.target
    route_type = getattr(getattr(target, 'route', None), 'type', 'direct')
    capability = target_capability(target.type)
    if route_type not in capability.routes:
        diagnostics.append(_diagnostic('jump_route_unsupported', capability.explanation,
                                       'target.route.type'))
    if isinstance(target, LocalAppTarget):
        if not _nonempty(target.app):
            diagnostics.append(_diagnostic("target_required", "local-app requires app.", "target.app"))
        if not _nonempty(target.window):
            diagnostics.append(_diagnostic("target_required", "Choose the window title text to focus; use the suggested title if unsure.", "target.window"))
    elif isinstance(target, HostAppTarget):
        for field in ("app", "cwd"):
            if not _nonempty(getattr(target, field)):
                diagnostics.append(_diagnostic("target_required", f"host-app requires {field}.", f"target.{field}"))
        if not _nonempty(target.window):
            diagnostics.append(_diagnostic("target_required", "Choose the window title text to focus; use the suggested title if unsure.", "target.window"))
        if target.startup_timeout is None or not 1 <= target.startup_timeout <= 300:
            diagnostics.append(_diagnostic("host_app_timeout", "host-app startup_timeout must be between 1 and 300 seconds.", "target.startup_timeout"))
    elif isinstance(target, SshTerminalTarget):
        if not _nonempty(target.host):
            diagnostics.append(_diagnostic("target_required", "ssh-terminal requires host.", "target.host"))
        elif target.host not in updated.ssh_host_allowlist:
            diagnostics.append(_diagnostic("target_allowlist", "Allow the selected SSH host for this project before continuing.", "target.host"))
        if not _nonempty(target.window):
            diagnostics.append(_diagnostic("target_required", "Choose the window title text to focus; use the suggested title if unsure.", "target.window"))
        if target.key and not _safe_secret_reference(target.key):
            diagnostics.append(_diagnostic("secret_reference", "key must be a safe secret reference filename, not a path.", "target.key"))
        if isinstance(target.route, SshJumpConnectionRoute):
            if not _nonempty(target.route.host):
                diagnostics.append(_diagnostic(
                    "jump_route_unconfigured",
                    "Via approved jump host requires a jump-host name.",
                    "target.route.host",
                ))
            elif target.route.host not in updated.ssh_host_allowlist:
                diagnostics.append(_diagnostic(
                    "jump_route_allowlist",
                    "Allow the approved jump host in the SSH allowlist before continuing.",
                    "target.route.host",
                ))
            if not 1 <= target.route.port <= 65535:
                diagnostics.append(_diagnostic(
                    "jump_route_port", "Jump-host port must be between 1 and 65535.", "target.route.port"
                ))
            if not _nonempty(target.route.known_hosts_file):
                diagnostics.append(_diagnostic(
                    "jump_route_known_hosts",
                    "A clone-local known-hosts reference is required for strict jump-host verification.",
                    "target.route.known_hosts_file",
                ))
            elif not _safe_secret_reference(target.route.known_hosts_file):
                diagnostics.append(_diagnostic(
                    "secret_reference",
                    "known_hosts_file must be a safe clone-local reference filename, not a path.",
                    "target.route.known_hosts_file",
                ))
    elif isinstance(target, RdpTarget):
        if not _nonempty(target.host):
            diagnostics.append(_diagnostic("target_required", "rdp requires host.", "target.host"))
        elif target.host not in updated.rdp_host_allowlist:
            diagnostics.append(_diagnostic("target_allowlist", "Allow the selected RDP host for this project before continuing.", "target.host"))
        if not _nonempty(target.window):
            diagnostics.append(_diagnostic("target_required", "Choose the window title text to focus; use the suggested title if unsure.", "target.window"))
        if target.password_file and not _safe_secret_reference(target.password_file):
            diagnostics.append(_diagnostic("secret_reference", "password_file must be a safe secret reference filename, not a path.", "target.password_file"))
        certificate_name = target.certificate_name.strip() if _nonempty(target.certificate_name) else None
        if certificate_name is None:
            diagnostics.append(_diagnostic(
                "rdp_certificate_name_required",
                "RDP requires the reviewed certificate name shown by the target server.",
                "target.certificate_name",
            ))
        elif RDP_CERTIFICATE_NAME_RE.fullmatch(certificate_name) is None:
            diagnostics.append(_diagnostic(
                "rdp_certificate_name_invalid",
                "RDP certificate name must be a hostname-like value without spaces or command syntax.",
                "target.certificate_name",
            ))
        certificate_fingerprint = _normalise_rdp_certificate_fingerprint(
            target.certificate_fingerprint
        )
        if certificate_fingerprint is None:
            diagnostics.append(_diagnostic(
                "rdp_certificate_fingerprint_invalid"
                if _nonempty(target.certificate_fingerprint)
                else "rdp_certificate_fingerprint_required",
                "RDP requires a reviewed sha256:<64 hex> or sha1:<40 hex> certificate fingerprint.",
                "target.certificate_fingerprint",
            ))
        normalised_args, args_diagnostics = _normalise_rdp_extra_args(target.extra_args)
        diagnostics.extend(args_diagnostics)
        updated = updated.model_copy(update={"target": target.model_copy(update={
            "certificate_name": certificate_name,
            "certificate_fingerprint": certificate_fingerprint,
            "extra_args": normalised_args,
        })}, deep=True)
    elif isinstance(target, VncTarget):
        if not _nonempty(target.host):
            diagnostics.append(_diagnostic("target_required", "vnc requires host.", "target.host"))
        elif target.host not in updated.vnc_host_allowlist:
            diagnostics.append(_diagnostic("target_allowlist", "Allow the selected VNC host for this project before continuing.", "target.host"))
        if not _nonempty(target.window):
            diagnostics.append(_diagnostic("target_required", "Choose the window title text to focus; use the suggested title if unsure.", "target.window"))
        if target.port is not None and not 1 <= target.port <= 65535:
            diagnostics.append(_diagnostic("vnc_port", "vnc port must be between 1 and 65535.", "target.port"))
        for field in ("password_file", "gateway_password_file"):
            value = getattr(target, field)
            if value and not _safe_secret_reference(value):
                diagnostics.append(_diagnostic("secret_reference", f"{field} must be a safe secret reference filename, not a path.", f"target.{field}"))
        if target.via:
            diagnostics.append(_diagnostic(
                "vnc_via_legacy",
                "Legacy VNC via text must be migrated to the typed SSH jump route before use.",
                "target.via",
            ))
        if isinstance(target.route, SshJumpConnectionRoute):
            if not _nonempty(target.route.host):
                diagnostics.append(_diagnostic("jump_route_unconfigured", "VNC over SSH requires a jump-host name.", "target.route.host"))
            elif target.route.host not in updated.ssh_host_allowlist:
                diagnostics.append(_diagnostic("jump_route_allowlist", "Allow the VNC jump host in the SSH allowlist before continuing.", "target.route.host"))
            if not 1 <= target.route.port <= 65535:
                diagnostics.append(_diagnostic("jump_route_port", "Jump-host port must be between 1 and 65535.", "target.route.port"))
            if not _nonempty(target.route.known_hosts_file):
                diagnostics.append(_diagnostic("jump_route_known_hosts", "A clone-local known-hosts reference is required for strict VNC jump-host verification.", "target.route.known_hosts_file"))
            elif not _safe_secret_reference(target.route.known_hosts_file):
                diagnostics.append(_diagnostic("secret_reference", "known_hosts_file must be a safe clone-local reference filename, not a path.", "target.route.known_hosts_file"))
            if not _nonempty(target.gateway_password_file):
                diagnostics.append(_diagnostic("jump_route_password", "VNC over SSH currently requires a saved jump-host password reference.", "target.gateway_password_file"))
        elif target.gateway_password_file:
            diagnostics.append(_diagnostic("jump_route_password_unused", "A jump-host password may be set only when the VNC route is SSH jump.", "target.gateway_password_file"))

    if new_project and updated.legacy:
        diagnostics.append(_diagnostic("legacy_new_project", "New typed projects cannot include legacy or unsupported YAML fields.", "legacy"))
    return updated, diagnostics


def _authoring_manual_directory(document: ProjectDocument) -> str:
    """Resolve portable manuals while retaining legacy cwd-relative paths."""

    raw = str(document.manual_dir or "").strip()
    if raw == "./manual":
        specs_root = os.path.abspath(
            os.environ.get("DASHBOARD_SPECS_DIR")
            or os.environ.get("TESTS_SPECS_DIR")
            or "tests_specs"
        )
        return os.path.join(specs_root, document.dir_name, "manual")
    portable = raw.replace("\\", "/")
    if portable == "tests_manuals" or portable.startswith("tests_manuals/"):
        parts = portable.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return os.path.abspath(raw)
        manual_root = os.path.abspath(
            os.environ.get("TESTS_MANUALS_DIR", "tests_manuals")
        )
        return os.path.join(manual_root, *parts[1:])
    return os.path.abspath(raw)


def _raise_on_errors(diagnostics: list[AuthoringDiagnostic]) -> None:
    if any(item.severity == "error" for item in diagnostics):
        raise AuthoringValidationError(diagnostics)


def render_project_yaml(document: ProjectDocument) -> str:
    """Render canonical project YAML, retaining only baseline legacy data."""
    target = _target_data(document.target)
    target_legacy = document.legacy.get("target") if isinstance(document.legacy.get("target"), dict) else {}
    target.update(target_legacy)
    payload: dict[str, Any] = {
        "name": document.display_name,
        "manual_dir": document.manual_dir,
        "target": target,
        "schedule": document.schedule,
        "max_steps": document.max_steps,
        "max_seconds": document.max_seconds,
        "max_tokens": document.max_tokens,
        "max_total_tokens": document.max_total_tokens,
        "step_max_tokens": document.step_max_tokens,
        "keep_last_n_screenshots": document.keep_last_n_screenshots,
        "action_delay_seconds": document.action_delay_seconds,
        "max_planner_steps": document.max_planner_steps,
        "step_max_steps": document.step_max_steps,
        "ssh_host_allowlist": document.ssh_host_allowlist,
        "rdp_host_allowlist": document.rdp_host_allowlist,
        "vnc_host_allowlist": document.vnc_host_allowlist,
        "redaction": document.redaction,
        "enabled": document.enabled,
    }
    payload = {key: value for key, value in payload.items() if value is not None}
    payload.update({key: value for key, value in document.legacy.items() if key != "target"})
    return yaml.safe_dump(payload, allow_unicode=True, default_flow_style=False, sort_keys=False)


def parse_spec_document(markdown: str, *, path: str) -> SpecDocument:
    """Mirror production spec parsing and add the Phase 13A assertion rule.

    This intentionally stays dashboard-local: importing runner modules into a
    dashboard boundary would violate the existing Phase 11 import contract.
    The section/title rules below are kept byte-for-byte equivalent in spirit
    to the production loader and are locked down by authoring tests.
    """
    if not _safe_relative_markdown(path):
        raise AuthoringValidationError([_diagnostic("spec_path", "Spec path must be a safe relative .md path.", "path")])

    title: str | None = None
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in markdown.splitlines():
        line = raw.rstrip()
        h1 = re.match(r"^#\s+(.*)$", line)
        h2 = re.match(r"^##\s+(.*)$", line)
        if h2:
            current = h2.group(1).strip().lower()
            sections.setdefault(current, [])
            continue
        if h1 and title is None:
            title = h1.group(1).strip()
            current = None
            continue
        if current is not None:
            sections[current].append(raw)

    def section(keyword: str) -> str | None:
        for heading, lines in sections.items():
            if keyword in heading:
                return "\n".join(lines).strip()
        return None

    goal = section("goal")
    if not goal:
        raise AuthoringValidationError([_diagnostic(
            "spec_parse", "Spec Markdown must contain a non-empty ## Goal section.", "spec"
        )])
    if not title:
        raise AuthoringValidationError([_diagnostic(
            "spec_parse", "Spec Markdown must contain a # Test title.", "spec"
        )])
    title = re.sub(r"^test\s*:\s*", "", title, flags=re.IGNORECASE).strip() or title
    if section("target") is not None:
        raise AuthoringValidationError([_diagnostic(
            "spec_parse", "## Target is not supported; declare the target in project.yaml.", "spec"
        )])

    assertions: list[str] = []
    assertion_body = section("assertion")
    if assertion_body:
        for raw in assertion_body.splitlines():
            match = re.match(r"^\s*[-*]\s+(.*)$", raw)
            if match and match.group(1).strip():
                assertions.append(match.group(1).strip())
    if not assertions:
        raise AuthoringValidationError([_diagnostic("assertions_required", "Spec must contain at least one non-empty assertion.", "assertions")])
    return SpecDocument(
        path=path,
        title=title,
        goal=goal,
        setup=section("setup") or None,
        assertions=assertions,
    )


def lint_spec_document(document: SpecDocument) -> list[AuthoringDiagnostic]:
    diagnostics: list[AuthoringDiagnostic] = []
    if not _safe_relative_markdown(document.path):
        diagnostics.append(_diagnostic("spec_path", "Spec path must be a safe relative .md path.", "path"))
    if not _nonempty(document.title):
        diagnostics.append(_diagnostic("spec_title", "Spec title is required.", "title"))
    if not _nonempty(document.goal):
        diagnostics.append(_diagnostic("spec_goal", "Spec Goal is required.", "goal"))
    if not document.assertions:
        diagnostics.append(_diagnostic("assertions_required", "Spec must contain at least one assertion.", "assertions"))
    for index, assertion in enumerate(document.assertions):
        if not _nonempty(assertion):
            diagnostics.append(_diagnostic("assertion_empty", "Assertions must be non-empty.", f"assertions[{index}]"))
    try:
        parse_spec_document(render_spec_markdown(document), path=document.path)
    except AuthoringValidationError as exc:
        diagnostics.extend(exc.diagnostics)
    return diagnostics


def render_spec_markdown(document: SpecDocument) -> str:
    """Render canonical, production-parseable Markdown for a typed spec."""
    blocks = [f"# Test: {document.title.strip()}", "", "## Goal", document.goal.strip()]
    if _nonempty(document.setup):
        blocks.extend(["", "## Setup", document.setup.strip()])
    blocks.extend(["", "## Assertions"])
    blocks.extend(f"- {assertion.strip()}" for assertion in document.assertions)
    return "\n".join(blocks) + "\n"


def validate_project_for_apply(
    document: ProjectDocument,
    *,
    require_manual_on_disk: bool,
    require_schedule: bool = True,
    new_project: bool = False,
) -> tuple[ProjectDocument, str, list[AuthoringDiagnostic]]:
    updated, diagnostics = lint_project_document(
        document,
        require_manual_on_disk=require_manual_on_disk,
        require_schedule=require_schedule,
        new_project=new_project,
    )
    _raise_on_errors(diagnostics)
    return updated, render_project_yaml(updated), diagnostics


def validate_spec_for_apply(document: SpecDocument) -> tuple[str, list[AuthoringDiagnostic]]:
    diagnostics = lint_spec_document(document)
    _raise_on_errors(diagnostics)
    return render_spec_markdown(document), diagnostics


def default_manual_template(display_name: str) -> str:
    return (
        f"# {display_name.strip()} operating manual\n\n"
        "## Purpose\n"
        "Describe the application, its safe operating boundary, and the intended test scope.\n\n"
        "## Normal procedure\n"
        "Document the normal starting state and the steps an operator expects to be available.\n\n"
        "## Verification cues\n"
        "List visible cues that distinguish success from an incomplete or unsafe state.\n\n"
        "## Recovery notes\n"
        "Record safe recovery guidance and known UI quirks.\n"
    )
