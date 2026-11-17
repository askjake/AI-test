"""Typed, non-secret per-clone configuration and private token storage.

This module intentionally uses only the Python standard library.  It must be
usable before the per-clone virtual environment or dashboard dependencies have
been installed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Any, Mapping
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
RUNTIME_DIRNAME = ".orchestrator-cookie"
REPORTS_ROOT_MODE = 0o755      # CP45-I: dashboard-owned, traversable by the runner uid, never writable by it (see docs/G2_PERMISSION_CONTRACT.md)
_log = logging.getLogger(__name__)

RUNTIME_SUBDIRS = (
    "config",
    "state",
    "logs",
    "reports",
    "tests_specs",
    "tests_manuals",
    "secrets",
)
CONFIG_RELATIVE = Path("config") / "runtime.json"
TOKEN_RELATIVE = Path("config") / "dashboard_tokens.json"
PROCESS_RELATIVE = Path("state") / "dashboard.json"
IMAGE_MARKER_RELATIVE = Path("state") / "runner_image.json"

_ENGINE_RE = re.compile(r"^[A-Za-z0-9_.+:/\\-]{1,512}$")
_IMAGE_RE = re.compile(
    r"^(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)?"
    r"[A-Za-z0-9_./-]+(?:[:][A-Za-z0-9_.-]+|@sha256:[a-fA-F0-9]{64})?$"
)
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_CLAIM_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_IMPORT_ROOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_OIDC_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ConfigurationError(ValueError):
    """Configuration would violate a deployment or security invariant."""


class ImageSourceKind(str, Enum):
    UNAVAILABLE = "unavailable"
    REFERENCE = "reference"
    ARCHIVE = "archive"
    VENDOR_ARTIFACT = "vendor-artifact"


@dataclass(frozen=True)
class ImageSource:
    kind: str = ImageSourceKind.UNAVAILABLE.value
    image_ref: str = "orchestrator-cookie:latest"
    archive_path: str | None = None
    archive_sha256: str | None = None
    vendor_artifact_path: str | None = None
    vendor_artifact_sha256: str | None = None
    platform: str = "linux/amd64"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "ImageSource":
        data = dict(value or {})
        return cls(**{key: data[key] for key in cls.__dataclass_fields__ if key in data})

    def validate(self) -> None:
        try:
            kind = ImageSourceKind(self.kind)
        except ValueError as exc:
            raise ConfigurationError("unsupported runner image source") from exc
        validate_image_reference(self.image_ref)
        if not re.fullmatch(r"linux/(?:amd64|arm64)", self.platform):
            raise ConfigurationError("runner platform must be linux/amd64 or linux/arm64")
        if kind is ImageSourceKind.REFERENCE:
            if "@sha256:" not in self.image_ref:
                raise ConfigurationError(
                    "a prebuilt image reference must be pinned with @sha256:<digest>"
                )
        elif kind is ImageSourceKind.ARCHIVE:
            validate_required_file_reference(
                self.archive_path, self.archive_sha256, "image archive"
            )
        elif kind is ImageSourceKind.VENDOR_ARTIFACT:
            validate_required_file_reference(
                self.vendor_artifact_path,
                self.vendor_artifact_sha256,
                "vendor artifact",
            )


@dataclass(frozen=True)
class AwsConfig:
    credentials_file: str | None = None
    config_file: str | None = None
    profile: str | None = None
    region: str = "us-west-2"
    bedrock_model_id: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "AwsConfig":
        data = dict(value or {})
        return cls(**{key: data[key] for key in cls.__dataclass_fields__ if key in data})

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", self.region):
            raise ConfigurationError("AWS region has an invalid format")
        for label, value in (("profile", self.profile), ("model id", self.bedrock_model_id)):
            if value is not None and (not value.strip() or any(c in value for c in "\r\n\0")):
                raise ConfigurationError(f"AWS {label} is invalid")
        for label, value in (
            ("credentials file", self.credentials_file),
            ("config file", self.config_file),
        ):
            if value is not None:
                validate_path_text(value, label)


@dataclass(frozen=True)
class HostAppConfig:
    enabled: bool = False
    allow_roots: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "HostAppConfig":
        data = dict(value or {})
        roots = data.get("allow_roots") or ()
        if not isinstance(roots, (list, tuple)):
            raise ConfigurationError("host-app allow_roots must be a list")
        return cls(enabled=bool(data.get("enabled", False)), allow_roots=tuple(roots))

    def validate(self) -> None:
        for root in self.allow_roots:
            validate_path_text(root, "host-app allow root")
            if not Path(root).is_absolute():
                raise ConfigurationError("host-app allow roots must be absolute")
        if self.enabled and not self.allow_roots:
            raise ConfigurationError("enabled host-app support requires at least one allow root")


@dataclass(frozen=True)
class ProjectImportRoot:
    """One administrator-approved server-side project import root."""

    id: str
    label: str
    path: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProjectImportRoot":
        if not isinstance(value, Mapping):
            raise ConfigurationError("project import roots must be objects")
        if set(value) != {"id", "label", "path"}:
            raise ConfigurationError(
                "project import roots require only id, label, and path"
            )
        return cls(
            id=value.get("id", ""),
            label=value.get("label", ""),
            path=value.get("path", ""),
        )

    def validate(self) -> None:
        if not isinstance(self.id, str) or not _IMPORT_ROOT_ID_RE.fullmatch(self.id):
            raise ConfigurationError("project import root id is invalid")
        if (
            not isinstance(self.label, str)
            or not 1 <= len(self.label) <= 80
            or any(character in self.label for character in "\r\n\0<>")
        ):
            raise ConfigurationError("project import root label is invalid")
        if not isinstance(self.path, str):
            raise ConfigurationError("project import root path is invalid")
        validate_path_text(self.path, "project import root path")
        if not Path(self.path).expanduser().is_absolute():
            raise ConfigurationError("project import roots must be absolute")


def _path_is_link_or_reparse(path: Path) -> bool:
    try:
        status = path.lstat()
    except OSError as exc:
        raise ConfigurationError("project import root is unavailable") from exc
    return path.is_symlink() or bool(
        getattr(status, "st_file_attributes", 0) & _REPARSE_POINT
    )


def normalize_project_import_root(root_id: str, label: str, value: str) -> ProjectImportRoot:
    """Return a canonical existing directory with no linked/reparse component."""

    candidate = ProjectImportRoot(root_id, label, value)
    candidate.validate()
    expanded = Path(value).expanduser()
    try:
        if not expanded.is_dir():
            raise ConfigurationError("project import root must be an existing directory")
    except OSError as exc:
        raise ConfigurationError("project import root must be an existing directory") from exc
    lineage = [expanded, *expanded.parents]
    for component in reversed(lineage):
        if _path_is_link_or_reparse(component):
            raise ConfigurationError("project import roots may not contain links or reparse points")
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise ConfigurationError("project import root must be an existing directory") from exc
    return ProjectImportRoot(candidate.id, candidate.label, str(resolved))


@dataclass(frozen=True)
class OidcConfig:
    """Clone-local OIDC metadata; credential material remains in a private file."""

    enabled: bool = False
    issuer: str | None = None
    client_id: str | None = None
    redirect_uri: str | None = None
    client_secret_file: str | None = None
    ca_file: str | None = None
    provider_label: str = "organization account"
    test_only: bool = False
    role_claim: str = "groups"
    viewer_values: tuple[str, ...] = ()
    operator_values: tuple[str, ...] = ()
    identity_claim: str = "preferred_username"
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    signing_algorithms: tuple[str, ...] = ("RS256",)
    tls_terminated: bool = False
    trusted_proxy_cidrs: tuple[str, ...] = ()
    session_ttl_seconds: int = 28_800

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "OidcConfig":
        data = dict(value or {})

        def strings(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
            raw = data.get(name, default)
            if not isinstance(raw, (list, tuple)) or not all(isinstance(item, str) for item in raw):
                raise ConfigurationError(f"OIDC {name.replace('_', ' ')} must be a list of strings")
            return tuple(raw)

        return cls(
            enabled=bool(data.get("enabled", False)),
            issuer=data.get("issuer"),
            client_id=data.get("client_id"),
            redirect_uri=data.get("redirect_uri"),
            client_secret_file=data.get("client_secret_file"),
            ca_file=data.get("ca_file"),
            provider_label=data.get("provider_label", "organization account"),
            test_only=bool(data.get("test_only", False)),
            role_claim=data.get("role_claim", "groups"),
            viewer_values=strings("viewer_values"),
            operator_values=strings("operator_values"),
            identity_claim=data.get("identity_claim", "preferred_username"),
            scopes=strings("scopes", ("openid", "profile", "email")),
            signing_algorithms=strings("signing_algorithms", ("RS256",)),
            tls_terminated=bool(data.get("tls_terminated", False)),
            trusted_proxy_cidrs=strings("trusted_proxy_cidrs"),
            session_ttl_seconds=data.get("session_ttl_seconds", 28_800),
        )

    def validate(self) -> None:
        if (
            not isinstance(self.provider_label, str)
            or not 1 <= len(self.provider_label) <= 80
            or any(character in self.provider_label for character in "\r\n\0<>")
        ):
            raise ConfigurationError("OIDC provider label is invalid")
        if not isinstance(self.session_ttl_seconds, int) or not 300 <= self.session_ttl_seconds <= 86_400:
            raise ConfigurationError("OIDC session TTL must be between 300 and 86400 seconds")
        for label, claim in (("role", self.role_claim), ("identity", self.identity_claim)):
            if not isinstance(claim, str) or not _CLAIM_RE.fullmatch(claim):
                raise ConfigurationError(f"OIDC {label} claim name is invalid")
        if not self.scopes or "openid" not in self.scopes:
            raise ConfigurationError("OIDC scopes must include openid")
        for scope in self.scopes:
            if not _CLAIM_RE.fullmatch(scope):
                raise ConfigurationError("OIDC scope is invalid")
        if not self.signing_algorithms or any(
            algorithm not in _OIDC_ALGORITHMS for algorithm in self.signing_algorithms
        ):
            raise ConfigurationError("OIDC signing algorithms must use an approved asymmetric algorithm")
        for label, values in (("viewer", self.viewer_values), ("operator", self.operator_values)):
            if len(values) != len(set(values)) or any(
                not value or len(value) > 256 or any(char in value for char in "\r\n\0")
                for value in values
            ):
                raise ConfigurationError(f"OIDC {label} role values are invalid")
        if set(self.viewer_values) & set(self.operator_values):
            raise ConfigurationError("OIDC viewer and operator role values must be distinct")
        for cidr in self.trusted_proxy_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigurationError("OIDC trusted proxy entries must be literal IP networks") from exc
            if network.prefixlen == 0:
                raise ConfigurationError("OIDC trusted proxy configuration may not trust every address")
        if self.tls_terminated and not self.trusted_proxy_cidrs:
            raise ConfigurationError("OIDC TLS termination requires at least one explicit trusted proxy network")
        if not self.enabled:
            return
        for label, value in (
            ("issuer", self.issuer),
            ("client ID", self.client_id),
            ("redirect URI", self.redirect_uri),
        ):
            if not isinstance(value, str) or not value or any(char in value for char in "\r\n\0"):
                raise ConfigurationError(f"OIDC {label} is required when OIDC is enabled")
        issuer = urlsplit(self.issuer or "")
        if issuer.scheme != "https" or not issuer.netloc or issuer.query or issuer.fragment:
            raise ConfigurationError("OIDC issuer must be an HTTPS URL without query or fragment")
        redirect = urlsplit(self.redirect_uri or "")
        if redirect.scheme not in {"http", "https"} or not redirect.netloc or redirect.fragment:
            raise ConfigurationError("OIDC redirect URI must be an absolute HTTP(S) URL without a fragment")
        if redirect.query:
            raise ConfigurationError("OIDC redirect URI must not contain a query")
        if redirect.path != "/api/v1/auth/oidc/callback":
            raise ConfigurationError("OIDC redirect URI must end at /api/v1/auth/oidc/callback")
        try:
            redirect_host = ipaddress.ip_address(redirect.hostname or "")
            redirect_loopback = redirect_host.is_loopback
        except ValueError:
            redirect_loopback = (redirect.hostname or "").lower() == "localhost"
        if redirect.scheme != "https" and not redirect_loopback:
            raise ConfigurationError("OIDC redirect URI must use HTTPS except on loopback")
        if not self.viewer_values and not self.operator_values:
            raise ConfigurationError("OIDC requires at least one viewer or operator claim value")
        if self.client_secret_file is not None:
            validate_path_text(self.client_secret_file, "OIDC client secret file")
            if not Path(self.client_secret_file).expanduser().is_absolute():
                raise ConfigurationError("OIDC client secret file must be absolute")
        if self.ca_file is not None:
            validate_path_text(self.ca_file, "OIDC CA file")
            if not Path(self.ca_file).expanduser().is_absolute():
                raise ConfigurationError("OIDC CA file must be absolute")


@dataclass(frozen=True)
class RuntimeConfig:
    schema_version: int = SCHEMA_VERSION
    bind_host: str = "127.0.0.1"
    port: int = 8080
    preferred_port: int = 8080
    port_fallback_enabled: bool = True
    lan_enabled: bool = False
    trigger_backend: str = "spawn"
    engine: str | None = None
    image: ImageSource = field(default_factory=ImageSource)
    aws: AwsConfig = field(default_factory=AwsConfig)
    host_app: HostAppConfig = field(default_factory=HostAppConfig)
    project_import_roots: tuple[ProjectImportRoot, ...] = ()
    oidc: OidcConfig = field(default_factory=OidcConfig)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeConfig":
        data = dict(value)
        return cls(
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            bind_host=data.get("bind_host", "127.0.0.1"),
            port=data.get("port", 8080),
            preferred_port=data.get("preferred_port", data.get("port", 8080)),
            port_fallback_enabled=bool(data.get("port_fallback_enabled", True)),
            lan_enabled=bool(data.get("lan_enabled", False)),
            trigger_backend=data.get("trigger_backend", "spawn"),
            engine=data.get("engine"),
            image=ImageSource.from_mapping(data.get("image")),
            aws=AwsConfig.from_mapping(data.get("aws")),
            host_app=HostAppConfig.from_mapping(data.get("host_app")),
            project_import_roots=tuple(
                normalize_project_import_root(root.id, root.label, root.path)
                for root in (
                    ProjectImportRoot.from_mapping(item)
                    for item in _project_import_root_mappings(data.get("project_import_roots"))
                )
            ),
            oidc=OidcConfig.from_mapping(data.get("oidc")),
        )

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ConfigurationError(
                f"unsupported runtime schema {self.schema_version}; expected {SCHEMA_VERSION}"
            )
        loopback = validate_bind_host(self.bind_host)
        if not 1 <= self.port <= 65535:
            raise ConfigurationError("dashboard port must be between 1 and 65535")
        if not 1 <= self.preferred_port <= 65535:
            raise ConfigurationError("preferred dashboard port must be between 1 and 65535")
        if not loopback and not self.lan_enabled:
            raise ConfigurationError(
                "non-loopback binding requires the explicit lan_enabled setting"
            )
        if self.trigger_backend != "spawn":
            # CP45-N: the 'watcher' backend needs world-writable report folders and is not supported under the 0755 report contract.
            # Refused here so no lifecycle command (start, status, configure) can proceed with it; the dashboard route refuses it again.
            raise ConfigurationError(
                "trigger_backend must be 'spawn': the 'watcher' backend is not supported under the 0755 report permission contract "
                "(it needs world-writable report folders); remove trigger_backend from runtime.json or set it to 'spawn'"
            )
        if self.engine is not None:
            validate_engine(self.engine)
        self.image.validate()
        self.aws.validate()
        self.host_app.validate()
        seen_ids: set[str] = set()
        seen_paths: set[str] = set()
        for root in self.project_import_roots:
            root.validate()
            normalized = normalize_project_import_root(root.id, root.label, root.path)
            if normalized.path != root.path:
                raise ConfigurationError("project import root paths must be canonical")
            canonical = os.path.normcase(normalized.path)
            if root.id in seen_ids:
                raise ConfigurationError("project import root ids must be unique")
            if canonical in seen_paths:
                raise ConfigurationError("project import root paths must be unique")
            seen_ids.add(root.id)
            seen_paths.add(canonical)
        self.oidc.validate()
        if self.oidc.enabled and not loopback:
            redirect = urlsplit(self.oidc.redirect_uri or "")
            if redirect.scheme != "https" or not self.oidc.tls_terminated:
                raise ConfigurationError(
                    "LAN OIDC requires an HTTPS redirect URI and explicit TLS termination"
                )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _project_import_root_mappings(value: Any) -> tuple[Mapping[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ConfigurationError("project import roots must be a list of objects")
    return tuple(value)


def repo_root_from(file_path: str | Path) -> Path:
    """Locate the clone root from a script or module below it."""
    path = Path(file_path).resolve()
    for candidate in (path.parent, *path.parents):
        if (candidate / "src" / "dashboard").is_dir() and (candidate / "scripts").is_dir():
            return candidate
    raise ConfigurationError("could not locate the Orchestrator Cookie clone root")


def runtime_root(repo_root: Path) -> Path:
    return repo_root / RUNTIME_DIRNAME


def validate_path_text(value: str, label: str = "path") -> None:
    if not value or any(char in value for char in ("\0", "\r", "\n")):
        raise ConfigurationError(f"{label} is invalid")


def normalize_clone_path(value: str, system: str) -> str:
    """Normalize a path according to an explicit platform for testable UX checks."""
    validate_path_text(value)
    if system == "Windows":
        path = PureWindowsPath(value)
        if not path.is_absolute():
            raise ConfigurationError("Windows clone paths must be absolute")
        return str(path)
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigurationError("clone paths must be absolute")
    return str(path.resolve(strict=False))


def validate_engine(value: str) -> str:
    if not _ENGINE_RE.fullmatch(value) or any(char in value for char in "\r\n\0"):
        raise ConfigurationError("container engine path/name is invalid")
    return value


def validate_image_reference(value: str) -> str:
    if len(value) > 512 or not _IMAGE_RE.fullmatch(value) or ".." in value.split("/"):
        raise ConfigurationError("runner image reference is invalid")
    return value


def validate_sha256(value: str | None, label: str = "checksum") -> str:
    if value is None or not _SHA256_RE.fullmatch(value):
        raise ConfigurationError(f"{label} must be a 64-character SHA-256 value")
    return value.lower()


def validate_required_file_reference(path: str | None, digest: str | None, label: str) -> None:
    if path is None:
        raise ConfigurationError(f"{label} path is required")
    validate_path_text(path, f"{label} path")
    if not Path(path).expanduser().is_absolute():
        raise ConfigurationError(f"{label} path must be absolute")
    validate_sha256(digest, f"{label} checksum")


def validate_name(value: str, label: str = "name") -> str:
    if not _NAME_RE.fullmatch(value):
        raise ConfigurationError(f"{label} contains unsupported characters")
    return value


def validate_bind_host(host: str) -> bool:
    """Return whether *host* is loopback; reject ambiguous host syntax."""
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ConfigurationError(
            "bind host must be localhost or a literal IPv4/IPv6 address"
        ) from exc
    return address.is_loopback


def atomic_write_bytes(path: Path, payload: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, mode)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload, mode=mode)


def windows_acl_command(path: Path, username: str) -> list[str]:
    validate_path_text(str(path), "ACL path")
    if not username or any(char in username for char in "\r\n\0"):
        raise ConfigurationError("Windows username is invalid")
    return [
        "icacls",
        str(path),
        "/inheritance:r",
        "/grant:r",
        f"{username}:(F)",
    ]


def restrict_private_path(path: Path, *, system: str | None = None) -> None:
    system = system or ("Windows" if os.name == "nt" else "Unix")
    if system == "Windows":
        username = os.environ.get("USERNAME")
        if not username:
            raise ConfigurationError("USERNAME is unavailable; cannot protect private data")
        domain = os.environ.get("USERDOMAIN")
        if domain:
            username = f"{domain}\\{username}"
        result = subprocess.run(
            windows_acl_command(path, username),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise ConfigurationError("could not apply a current-user-only Windows ACL")
    else:
        os.chmod(path, 0o600 if path.is_file() else 0o700)


def inspect_reports_root(repo_root: Path) -> dict:
    """Read-only look at reports/ against the CP45-I contract (dashboard-owned 0755, no group/world write, no ACL). Changes nothing."""
    path = runtime_root(repo_root) / "reports"
    out: dict = {"path": str(path), "exists": False, "mode": None, "owner_uid": None, "findings": []}
    if os.name == "nt":
        return out
    try:
        info = os.lstat(path)
    except OSError:
        return out
    out.update(exists=True, mode=oct(info.st_mode & 0o7777), owner_uid=info.st_uid)
    mode, findings = info.st_mode & 0o7777, out["findings"]
    if not stat.S_ISDIR(info.st_mode):
        findings.append("reports root is not a plain directory")
        return out
    if mode & 0o022:
        findings.append("reports root is group/world-writable (mode %s): not tightened automatically; migration: chmod 0755 on this one directory (not recursive)" % oct(mode))
    if not mode & 0o001:
        findings.append("reports root is not traversable by other users (mode %s): the runner uid cannot reach its report folders; migration: chmod 0755 on this one directory" % oct(mode))
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        findings.append("reports root is owned by uid %d, not the dashboard user" % info.st_uid)
    try:
        if any(name.startswith("system.posix_acl") for name in os.listxattr(path, follow_symlinks=False)):
            findings.append("reports root carries a POSIX ACL; the contract needs none (setfacl -b on this directory removes it)")
    except (OSError, AttributeError):
        pass
    return out


import re as _re_cp45n

_CP45N_PROJECT_RE = _re_cp45n.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_CP45N_TRIGGER_RE = _re_cp45n.compile(r"^trig_[A-Za-z0-9_-]+$")
_CP45N_RUN_TS_RE = _re_cp45n.compile(r"^\d{8}T\d{6}Z$")
RUNNER_UID = 10001


def inspect_reports_hierarchy(
    repo_root: Path,
    *,
    runner_uid: int = RUNNER_UID,
    dashboard_uid: int | None = None,
    max_entries: int = 100000,
    _lstat=os.lstat,
) -> dict:
    """CP45-N: read-only walk of the real report path hierarchy against the 0755 report contract.  Changes nothing.

    Expected, NOT a problem: runner-uid-owned trigger run folders (``<project>/.nrdp-runs/trig_*``), report folders (``<project>/<run_ts>``) and
    project ``index.html`` - report_handoff gives exactly those to the runner.  BLOCKING (new launches are refused): a root/project/``.nrdp-runs``/
    ``.pending``/``control``/``.ctrl`` directory that is foreign-owned (runner uid included), group/world-writable, ACL'd, sticky/setid or
    not traversable, and a group/world-writable project ``index.html``.  REVIEW (inert history that still needs a reviewed plan): loose or
    unknown-owner trigger/report folders, odd top-level entries.  Contents below those folders are never opened.
    """
    reports = runtime_root(repo_root) / "reports"
    out: dict = {"path": str(reports), "exists": False, "blocking": [], "review": [], "expected_runner_owned": [], "expected_runner_owned_count": 0,
                 "inspected": 0, "truncated": False, "migration_blocked": False, "findings": []}
    if os.name == "nt":
        return out
    me = os.geteuid() if dashboard_uid is None else dashboard_uid
    budget = [max_entries]

    def rel(path) -> str:
        r = os.path.relpath(str(path), str(reports))
        return "." if r == "." else r

    def add(severity: str, code: str, path, info, message: str) -> None:
        item = {"code": code, "path": rel(path), "owner_uid": None if info is None else info.st_uid,
                "mode": None if info is None else "%04o" % stat.S_IMODE(info.st_mode), "message": message}
        out["blocking" if severity == "blocking" else "review"].append(item)

    def look(path):
        if budget[0] <= 0:
            out["truncated"] = True
            return None
        budget[0] -= 1
        out["inspected"] += 1
        try:
            return _lstat(str(path))
        except OSError:
            return None

    def children(path) -> list:
        try:
            with os.scandir(str(path)) as it:
                return sorted(it, key=lambda e: e.name)
        except OSError as exc:
            add("review", "UNREADABLE", path, look(path), "cannot be listed (%s); its contents were not inspected" % (exc.strerror or exc))
            return []

    def has_acl(path) -> bool:
        try:
            return any(n.startswith("system.posix_acl") for n in os.listxattr(str(path), follow_symlinks=False))
        except (OSError, AttributeError):
            return False

    def check_dir(path, role: str, owners: set, severity: str = "blocking", runner_expected: bool = False) -> bool:
        info = look(path)
        if info is None:
            return False
        if stat.S_ISLNK(info.st_mode):
            add(severity, "SYMLINK", path, info, "%s is a symbolic link" % role)
            return False
        if not stat.S_ISDIR(info.st_mode):
            add(severity, "NOT_A_DIRECTORY", path, info, "%s is not a directory" % role)
            return False
        problems = 0
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in owners:
            problems += 1
            if info.st_uid == runner_uid:
                add(severity, "FOREIGN_OWNER", path, info, "%s is owned by the runner uid %d but must be dashboard-owned (uid %d): the dashboard cannot create or "
                    "update records in it" % (role, runner_uid, me))
            else:
                add(severity, "FOREIGN_OWNER", path, info, "%s is owned by uid %d, neither the dashboard (uid %d) nor the runner (uid %d)" % (role, info.st_uid, me, runner_uid))
        if mode & 0o022:
            problems += 1
            add(severity, "GROUP_WORLD_WRITABLE", path, info, "%s is group- or world-writable (mode %04o)" % (role, mode))
        if mode & 0o7000:
            problems += 1
            add(severity, "SPECIAL_MODE_BITS", path, info, "%s has setuid/setgid/sticky bits (mode %04o)" % (role, mode))
        if not mode & 0o001:
            problems += 1
            add(severity, "NOT_TRAVERSABLE", path, info, "%s is not traversable by other users (mode %04o): the runner uid cannot reach it" % (role, mode))
        if has_acl(path):
            problems += 1
            add(severity, "ACL", path, info, "%s carries a POSIX ACL; the contract needs none" % role)
        if runner_expected and not problems and info.st_uid == runner_uid:
            out["expected_runner_owned_count"] += 1
            if len(out["expected_runner_owned"]) < 50:
                out["expected_runner_owned"].append(rel(path))
        return True

    def check_index(path, project_level: bool) -> None:
        info = look(path)
        if info is None:
            return
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            add("blocking" if project_level else "review", "UNSAFE_INDEX", path, info, "index.html is not a plain single-link regular file")
        elif mode & 0o022:
            add("blocking" if project_level else "review", "GROUP_WORLD_WRITABLE", path, info,
                "index.html is group- or world-writable (mode %04o)%s" % (mode, ": the handoff would stop the launch" if project_level else ""))
        elif info.st_uid not in (me, runner_uid):
            add("review", "FOREIGN_OWNER", path, info, "index.html is owned by uid %d, neither the dashboard (uid %d) nor the runner (uid %d)" % (info.st_uid, me, runner_uid))
        elif info.st_uid == runner_uid and project_level:
            out["expected_runner_owned_count"] += 1
            if len(out["expected_runner_owned"]) < 50:
                out["expected_runner_owned"].append(rel(path))

    if not check_dir(reports, "reports root", {me}):
        out["exists"] = look(reports) is not None
    else:
        out["exists"] = True
        for entry in children(reports):
            name = entry.name
            if name == ".ctrl":
                check_dir(entry.path, ".ctrl directory", {me})
            elif name == ".host-app":
                add("review", "HOST_APP_STATE", entry.path, look(entry.path), "legacy host-app state directory (host-app targets are unsupported); contents not inspected")
            elif name == "index.html":
                check_index(entry.path, False)
            elif entry.is_symlink():
                add("blocking", "SYMLINK", entry.path, look(entry.path), "report entry %s is a symbolic link" % name)
            elif not entry.is_dir(follow_symlinks=False):
                continue
            elif not _CP45N_PROJECT_RE.match(name):
                add("review", "UNRECOGNISED_ENTRY", entry.path, look(entry.path), "directory %s is not a project folder name; ignored" % name)
            elif check_dir(entry.path, "project directory", {me}):
                for child in children(entry.path):
                    if child.name == ".nrdp-runs":
                        if check_dir(child.path, ".nrdp-runs directory", {me}):
                            for run in children(child.path):
                                if run.name == ".pending":
                                    check_dir(run.path, ".pending directory", {me})
                                elif _CP45N_TRIGGER_RE.match(run.name):
                                    if check_dir(run.path, "trigger run folder", {me, runner_uid}, "review", True):
                                        control = os.path.join(run.path, "control")
                                        if look(control) is not None:
                                            check_dir(control, "control directory", {me})
                    elif child.name == "index.html":
                        check_index(child.path, True)
                    elif _CP45N_RUN_TS_RE.match(child.name):
                        check_dir(child.path, "report folder", {me, runner_uid}, "review", True)
    out["migration_blocked"] = bool(out["blocking"] or out["review"] or out["truncated"])
    if out["truncated"]:
        out["review"].append({"code": "TRUNCATED", "path": ".", "owner_uid": None, "mode": None, "message": "inspection stopped after %d entries; the layout is not fully known" % max_entries})
    out["findings"] = ["%s: %s" % (i["path"], i["message"]) for i in out["blocking"] + out["review"]]
    return out


def initialize_runtime(repo_root: Path, *, import_samples: bool = False) -> Path:
    from .switch_guard import require_resolved as _require_switch_resolved  # CP45-R (local import: switch_guard imports this module)
    _require_switch_resolved(runtime_root(repo_root) / "reports", check_image=False)   # init is configuration, not startup: only the reports-switch state blocks it (CP45-V)   # refuse BEFORE anything is created or chmod'ed
    root = runtime_root(repo_root)
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(root, 0o700)
    for relative in RUNTIME_SUBDIRS:
        directory = root / relative
        existed = directory.exists() or directory.is_symlink()
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            # The hardened non-root runner needs the mounted workspace roots to
            # be traversable, and the reports mount to be writable. Secrets and
            # all manager-owned state remain owner-only.
            mode = 0o755 if relative in {"tests_specs", "tests_manuals"} else 0o700
            if relative == "reports":
                # CP45-I: a FRESH reports/ is 0755 (the runner never writes here; the dashboard precreates and hands over each run's folders).
                # An EXISTING reports/ is inspected, never chmod'ed in either direction: see inspect_reports_root() and the migration notes.
                if existed:
                    continue
                mode = REPORTS_ROOT_MODE
            elif mode == 0o700 and existed:
                mode = stat.S_IMODE(os.lstat(directory).st_mode) & 0o700      # CP45-I: an existing private directory is tightened to owner-only, NEVER given a bit it lacks
            os.chmod(directory, mode)
        elif relative in {"config", "state", "logs", "secrets"}:
            restrict_private_path(directory, system="Windows")

    for finding in inspect_reports_root(repo_root)["findings"]:
        _log.warning("reports root: %s", finding)
    _layout = inspect_reports_hierarchy(repo_root)
    for item in _layout["blocking"]:
        _log.warning("reports layout BLOCKS launches: %s: %s", item["path"], item["message"])
    for item in _layout["review"]:
        _log.warning("reports layout needs review: %s: %s", item["path"], item["message"])

    config_path = root / CONFIG_RELATIVE
    if not config_path.exists():
        save_config(repo_root, RuntimeConfig())
    token_path = root / TOKEN_RELATIVE
    if not token_path.exists():
        save_tokens(repo_root, generate_tokens())

    marker = root / "state" / "workspace.json"
    if not marker.exists():
        atomic_write_json(
            marker,
            {"schema_version": 1, "samples_imported": False},
        )
    if import_samples:
        import_sample_workspace(repo_root)
    return root


def import_sample_workspace(repo_root: Path) -> None:
    import shutil

    root = runtime_root(repo_root)
    if not root.is_dir():
        raise ConfigurationError("run init before importing samples")
    destinations = (
        (repo_root / "tests_specs", root / "tests_specs"),
        (repo_root / "tests_manuals", root / "tests_manuals"),
    )
    for source, destination in destinations:
        if any(destination.iterdir()):
            raise ConfigurationError(
                f"refusing to import over non-empty workspace: {destination.name}"
            )
        for entry in source.iterdir():
            target = destination / entry.name
            if entry.is_dir():
                shutil.copytree(entry, target, symlinks=False)
            elif entry.is_file():
                shutil.copy2(entry, target, follow_symlinks=False)
    atomic_write_json(
        root / "state" / "workspace.json",
        {"schema_version": 1, "samples_imported": True},
    )


def load_config(repo_root: Path) -> RuntimeConfig:
    path = runtime_root(repo_root) / CONFIG_RELATIVE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError("runtime is not initialized; run init") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("runtime configuration is unreadable") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("runtime configuration must be a JSON object")
    config = RuntimeConfig.from_mapping(value)
    config.validate()
    return config


def save_config(repo_root: Path, config: RuntimeConfig) -> None:
    config.validate()
    path = runtime_root(repo_root) / CONFIG_RELATIVE
    atomic_write_json(path, config.to_dict())
    restrict_private_path(path)


def generate_tokens() -> dict[str, str]:
    return {
        "viewer_token": secrets.token_urlsafe(48),
        "operator_token": secrets.token_urlsafe(48),
    }


def validate_tokens(value: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in ("viewer_token", "operator_token"):
        token = value.get(key)
        if not isinstance(token, str) or len(token) < 32 or any(c.isspace() for c in token):
            raise ConfigurationError(f"{key} must contain at least 32 non-space characters")
        result[key] = token
    if result["viewer_token"] == result["operator_token"]:
        raise ConfigurationError("viewer and operator tokens must be distinct")
    return result


def save_tokens(repo_root: Path, value: Mapping[str, Any]) -> None:
    tokens = validate_tokens(value)
    path = runtime_root(repo_root) / TOKEN_RELATIVE
    atomic_write_json(path, tokens)
    restrict_private_path(path)


def load_tokens(repo_root: Path) -> dict[str, str]:
    path = runtime_root(repo_root) / TOKEN_RELATIVE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("dashboard token file is unavailable") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("dashboard token file is invalid")
    tokens = validate_tokens(value)
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ConfigurationError("dashboard token file permissions are not owner-only")
    return tokens


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_private_token_file(path_text: str) -> str:
    path = validate_private_secret_file(path_text, "token input file")
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32 or any(char.isspace() for char in token):
        raise ConfigurationError("token input must contain at least 32 non-space characters")
    return token


def validate_private_secret_file(path_text: str, label: str = "secret file") -> Path:
    path = Path(path_text).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"{label} must be an absolute regular non-symlink file")
    if os.name == "nt":
        restrict_private_path(path, system="Windows")
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigurationError(f"{label} must be owner-only")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigurationError(f"{label} is unavailable") from exc
    if not 1 <= size <= 4096:
        raise ConfigurationError(f"{label} must contain between 1 and 4096 bytes")
    return path
