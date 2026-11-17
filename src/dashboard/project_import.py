"""Operator-only, allowlisted, preview-bound project-folder import.

The browser never submits an absolute host path. Every filesystem operation is
root-id plus normalized relative path, revalidates containment and link/reparse
state, and treats the preview manifest as a one-time compare-and-swap token.
This module has no runner, target, subprocess, AWS, or model dependency.
"""
from __future__ import annotations

from collections import OrderedDict
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import shlex
import shutil
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field
import yaml

from .auth import Actor
from .authoring import (
    AuthoringValidationError,
    PROJECT_SLUG_RE,
    ProjectDocument,
    SshJumpConnectionRoute,
    lint_project_document,
    parse_project_document,
    parse_spec_document,
    render_project_yaml,
    validate_project_for_apply,
    validate_spec_for_apply,
)
from .config import DashboardSettings, ProjectImportRootSetting


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SAFE_ENTRY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
_SENSITIVE_RE = re.compile(
    r"(?:^|[._ -])(credential|password|passwd|secret|token|private[ _-]?key|"
    r"access[ _-]?key|session)(?:$|[._ -])",
    re.IGNORECASE,
)
_SENSITIVE_EXACT = {
    ".env", "credentials", "credentials.json", "dashboard_tokens.json",
    "oidc_client_secret", "id_rsa", "id_ed25519", "known_hosts",
}
_SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".jks", ".pass"}
_MANUAL_ASSET_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"}
_EXCLUDED_DIRS = {
    ".git", ".orchestrator-cookie", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", "coverage", "reports", "screenshots", "artifacts",
}
_EXCLUDED_FILES = {"README.md", "TEMPLATE.md"}
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectImportCapabilities(_StrictModel):
    enabled: bool
    portable_folder_contract: str = (
        "project.yaml + specs + manual/manual.md, or a root-contained relative legacy manual_dir"
    )
    selection_contract: str = "configured root id plus normalized relative path"
    preview_ttl_seconds: int
    max_depth: int
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    reparse_policy: Literal["deny"] = "deny"


class ProjectImportRootSummary(_StrictModel):
    id: str
    label: str


class ProjectImportBreadcrumb(_StrictModel):
    label: str
    path: str


class ProjectImportDirectory(_StrictModel):
    name: str
    path: str


class ProjectImportBrowseRequest(_StrictModel):
    root_id: str = Field(min_length=1, max_length=64)
    path: str = Field(default="", max_length=4096)


class ProjectImportBrowseResponse(_StrictModel):
    root_id: str
    root_label: str
    path: str
    breadcrumbs: list[ProjectImportBreadcrumb]
    directories: list[ProjectImportDirectory]
    truncated: bool = False


class ProjectImportDiscoverRequest(_StrictModel):
    root_id: str = Field(min_length=1, max_length=64)


class ProjectImportCandidate(_StrictModel):
    path: str
    destination_slug: str
    project_name: str
    layout: Literal["portable", "split", "incomplete"]
    manual_path: str | None = None


class ProjectImportDiscoverResponse(_StrictModel):
    root_id: str
    root_label: str
    projects: list[ProjectImportCandidate]
    truncated: bool = False


class ProjectImportDiagnostic(_StrictModel):
    code: str
    message: str
    severity: Literal["error", "warning"] = "error"
    path: str | None = None


class ProjectImportExcludedEntry(_StrictModel):
    path: str
    reason: str


class ProjectImportPreviewRequest(_StrictModel):
    root_id: str = Field(min_length=1, max_length=64)
    path: str = Field(default="", max_length=4096)
    destination_slug: str = Field(min_length=1, max_length=128)


class ProjectImportPreviewResponse(_StrictModel):
    can_import: bool
    preview_token: str | None = None
    root_id: str
    root_label: str
    selected_path: str
    project_name: str | None = None
    destination_slug: str
    proposed_destination: str
    spec_count: int = 0
    manual_count: int = 0
    included_file_count: int = 0
    total_bytes: int = 0
    manifest_digest: str | None = None
    diagnostics: list[ProjectImportDiagnostic] = Field(default_factory=list)
    excluded_files: list[ProjectImportExcludedEntry] = Field(default_factory=list)
    excluded_count: int = 0
    expires_at: str | None = None


class ProjectImportApplyRequest(_StrictModel):
    preview_token: str = Field(min_length=20, max_length=256)
    destination_slug: str = Field(min_length=1, max_length=128)


class ProjectImportApplyResponse(_StrictModel):
    status: Literal["imported"] = "imported"
    destination_slug: str
    project_name: str
    spec_count: int
    manual_count: int
    included_file_count: int
    total_bytes: int
    manifest_digest: str
    message: str


class ProjectImportError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 422):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ProjectImportConfigurationError(RuntimeError):
    """Configured roots or destination storage are unsafe."""


@dataclass(frozen=True)
class _Root:
    id: str
    label: str
    path: Path
    identity: tuple[int, int]


@dataclass(frozen=True)
class _ManifestEntry:
    path: str
    kind: str
    size: int
    mtime_ns: int
    device: int
    inode: int
    digest: str | None = None

    def serializable(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "device": self.device,
            "inode": self.inode,
            "digest": self.digest,
        }


@dataclass
class _Scan:
    source: Path
    relative_path: str
    destination_slug: str
    project_name: str | None
    document: ProjectDocument | None
    rendered_project: str | None
    manifest: tuple[_ManifestEntry, ...]
    manifest_digest: str
    contents: dict[str, bytes]
    roles: dict[str, str]
    diagnostics: list[ProjectImportDiagnostic]
    excluded: list[ProjectImportExcludedEntry]
    excluded_count: int
    total_bytes: int
    spec_count: int
    manual_count: int
    legacy_manual_used: bool


@dataclass(frozen=True)
class _PreviewToken:
    root_id: str
    relative_path: str
    destination_slug: str
    manifest_digest: str
    actor_key: str
    expires_at: float


def _bounded(value: object, maximum: int = 256) -> str:
    text = "".join(character for character in str(value) if character >= " " and character != "\x7f")
    return text[:maximum]


def _legacy_runtime_window(target: object) -> str | None:
    """Return the exact window fallback already used by the runner."""

    target_type = getattr(target, "type", None)
    host = str(getattr(target, "host", "") or "").strip()
    if target_type == "ssh-terminal" and host:
        return f"orchestrator-ssh-{host}"
    if target_type == "rdp" and host:
        return f"orchestrator-rdp-{host}"
    if target_type == "vnc":
        return "TigerVNC"
    if target_type in {"local-app", "host-app"}:
        app = str(getattr(target, "app", "") or "").strip()
        if not app:
            return None
        try:
            command = shlex.split(app)[0]
        except (ValueError, IndexError):
            return None
        return os.path.basename(command)
    return None


def _is_reparse(status: os.stat_result) -> bool:
    return bool(getattr(status, "st_file_attributes", 0) & _REPARSE_POINT)


def _is_special_entry(status: os.stat_result) -> bool:
    """Classify sockets, devices, FIFOs, and other non-file entries."""

    return not (
        stat.S_ISDIR(status.st_mode)
        or stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
    )


def _safe_nofollow_reads_supported() -> bool:
    """Return true only where Python exposes an enforceable no-follow open."""

    # Windows reparse-safe handle semantics require a separately reviewed
    # CreateFileW implementation.  Until then the feature fails closed before
    # reading source contents; browse still exposes only approved directories.
    return os.name != "nt" and bool(getattr(os, "O_NOFOLLOW", 0))


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
    )


def _safe_entry_name(name: str) -> bool:
    if not _SAFE_ENTRY_RE.fullmatch(name) or name.endswith((" ", ".")):
        return False
    stem = name.split(".", 1)[0].upper()
    return stem not in _WINDOWS_RESERVED


def _sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _SENSITIVE_EXACT
        or any(lowered.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES)
        or bool(_SENSITIVE_RE.search(lowered))
    )


def _normalize_relative(value: str) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, str) or any(character in value for character in "\0\r\n"):
        raise ProjectImportError("invalid_path", "The selected folder path is invalid.", status_code=400)
    if value in {"", "."}:
        return "", ()
    if "\\" in value or value.startswith("/"):
        raise ProjectImportError("invalid_path", "Only a root-relative folder path is accepted.", status_code=400)
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if windows.is_absolute() or windows.drive or posix.is_absolute():
        raise ProjectImportError("invalid_path", "Absolute folder paths are not accepted.", status_code=400)
    parts = posix.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ProjectImportError("invalid_path", "Folder traversal is not accepted.", status_code=400)
    for part in parts:
        if part.startswith(".") or _sensitive_name(part) or not _safe_entry_name(part):
            raise ProjectImportError("invalid_path", "The selected folder name is not permitted.", status_code=400)
    normalized = "/".join(parts)
    return normalized, tuple(parts)


def _lstat_safe(path: Path) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as exc:
        raise ProjectImportError("path_unavailable", "The selected folder is unavailable.", status_code=404) from exc
    if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
        raise ProjectImportError("linked_path", "Linked or reparse-point folders are not permitted.", status_code=400)
    return status


def _fsync_directory(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_publish_noreplace(source: Path, destination: Path) -> None:
    """Rename a directory atomically while refusing an existing destination."""

    if os.name == "nt":
        try:
            os.rename(source, destination)
        except FileExistsError as exc:
            raise ProjectImportError(
                "project_exists",
                "A managed project already exists with this destination slug.",
                status_code=409,
            ) from exc
        except OSError as exc:
            raise ProjectImportError(
                "publish_failed",
                "The staged project could not be published atomically.",
                status_code=500,
            ) from exc
        return
    encoded_source = os.fsencode(source)
    encoded_destination = os.fsencode(destination)
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise ProjectImportError(
                "atomic_publish_unavailable",
                "This host cannot prove an atomic no-overwrite directory publish.",
                status_code=503,
            )
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, encoded_source, -100, encoded_destination, 1)
    elif sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise ProjectImportError(
                "atomic_publish_unavailable",
                "This host cannot prove an atomic no-overwrite directory publish.",
                status_code=503,
            )
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(encoded_source, encoded_destination, 0x00000004)
    else:
        raise ProjectImportError(
            "atomic_publish_unavailable",
            "This platform is denied because atomic no-overwrite publish is unproven.",
            status_code=503,
        )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ProjectImportError(
            "project_exists",
            "A managed project already exists with this destination slug.",
            status_code=409,
        )
    raise ProjectImportError(
        "publish_failed",
        "The staged project could not be published atomically.",
        status_code=500,
    )


class ProjectImportAuditTrail:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        actor: Actor,
        action: str,
        result: str,
        root_id: str,
        source_digest: str,
        manifest_digest: str | None,
        destination_slug: str,
        spec_count: int,
        manual_count: int,
        file_count: int,
        total_bytes: int,
    ) -> None:
        session_material = actor.session_id or f"{actor.auth_method}:{actor.subject}"
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": _bounded(actor.subject),
            "session_digest": hashlib.sha256(session_material.encode("utf-8")).hexdigest(),
            "auth_method": _bounded(actor.auth_method, 64),
            "action": action,
            "result": _bounded(result, 80),
            "root_id": _bounded(root_id, 64),
            "source_relative_path_digest": source_digest,
            "manifest_digest": manifest_digest,
            "destination_slug": _bounded(destination_slug, 128),
            "spec_count": max(0, int(spec_count)),
            "manual_count": max(0, int(manual_count)),
            "file_count": max(0, int(file_count)),
            "total_bytes": max(0, int(total_bytes)),
        }
        payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.name != "nt":
                os.chmod(self.path, 0o600)


class ProjectImportService:
    def __init__(
        self,
        settings: DashboardSettings,
        *,
        clock=time.time,
        on_publish: Callable[[Actor, str, str], None] | None = None,
        on_rollback: Callable[[Actor, str, str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.clock = clock
        self.on_publish = on_publish
        self.on_rollback = on_rollback
        # BaseSettings has already applied the supported environment contract.
        # Re-reading os.environ here would create a second, order-dependent
        # destination authority after application configuration was validated.
        self.specs_root = Path(settings.specs_dir).expanduser().absolute()
        self.roots: dict[str, _Root] = {}
        for configured in settings.project_import_roots:
            root = self._configure_root(configured)
            if root.id in self.roots:
                raise ProjectImportConfigurationError("project import root ids must be unique")
            if any(os.path.normcase(str(item.path)) == os.path.normcase(str(root.path)) for item in self.roots.values()):
                raise ProjectImportConfigurationError("project import root paths must be unique")
            self.roots[root.id] = root
        audit_path = settings.project_import_audit_path or (
            Path(settings.reports_dir).absolute() / ".auth" / "project_import.jsonl"
        )
        self.audit = ProjectImportAuditTrail(audit_path)
        self._tokens: OrderedDict[str, _PreviewToken] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def _configure_root(configured: ProjectImportRootSetting) -> _Root:
        path = Path(configured.path).expanduser()
        if not path.is_absolute():
            raise ProjectImportConfigurationError("project import roots must be absolute")
        try:
            lineage = [path, *path.parents]
            for component in reversed(lineage):
                status = component.lstat()
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
                    raise ProjectImportConfigurationError(
                        "project import roots may not contain links or reparse points"
                    )
            if not path.is_dir():
                raise ProjectImportConfigurationError("project import roots must be existing directories")
            resolved = path.resolve(strict=True)
            status = resolved.lstat()
        except OSError as exc:
            raise ProjectImportConfigurationError("project import root is unavailable") from exc
        return _Root(configured.id, configured.label, resolved, (status.st_dev, status.st_ino))

    def capabilities(self) -> ProjectImportCapabilities:
        return ProjectImportCapabilities(
            enabled=bool(self.roots) and _safe_nofollow_reads_supported(),
            preview_ttl_seconds=self.settings.project_import_preview_ttl_seconds,
            max_depth=self.settings.project_import_max_depth,
            max_files=self.settings.project_import_max_files,
            max_file_bytes=self.settings.project_import_max_file_bytes,
            max_total_bytes=self.settings.project_import_max_total_bytes,
        )

    def root_summaries(self) -> list[ProjectImportRootSummary]:
        return [
            ProjectImportRootSummary(id=item.id, label=item.label)
            for item in sorted(self.roots.values(), key=lambda value: value.label.casefold())
        ]

    def _root(self, root_id: str) -> _Root:
        if not self.roots:
            raise ProjectImportError(
                "project_import_disabled",
                "Project-folder import is disabled because no roots are configured.",
                status_code=503,
            )
        try:
            return self.roots[root_id]
        except KeyError as exc:
            raise ProjectImportError("unknown_root", "The configured import root was not found.", status_code=404) from exc

    def _resolve_directory(self, root: _Root, relative: str) -> tuple[Path, str, tuple[str, ...]]:
        normalized, parts = _normalize_relative(relative)
        root_status = _lstat_safe(root.path)
        try:
            root_resolved = root.path.resolve(strict=True)
        except OSError as exc:
            raise ProjectImportError("root_changed", "The configured import root changed.", status_code=409) from exc
        if (
            (root_status.st_dev, root_status.st_ino) != root.identity
            or os.path.normcase(str(root_resolved)) != os.path.normcase(str(root.path))
        ):
            raise ProjectImportError("root_changed", "The configured import root changed.", status_code=409)
        current = root.path
        traversed: list[tuple[Path, tuple[int, int, int]]] = [
            (current, (root_status.st_dev, root_status.st_ino, root_status.st_mode))
        ]
        for part in parts:
            current = current / part
            status = _lstat_safe(current)
            if not stat.S_ISDIR(status.st_mode):
                raise ProjectImportError("not_a_directory", "The selected path is not a folder.", status_code=400)
            traversed.append((current, (status.st_dev, status.st_ino, status.st_mode)))
        try:
            resolved = current.resolve(strict=True)
            inside = os.path.commonpath((str(root.path), str(resolved))) == str(root.path)
        except (OSError, ValueError) as exc:
            raise ProjectImportError("path_escape", "The selected folder is outside the configured root.", status_code=400) from exc
        if not inside:
            raise ProjectImportError("path_escape", "The selected folder is outside the configured root.", status_code=400)
        for component, expected in traversed:
            status = _lstat_safe(component)
            if (status.st_dev, status.st_ino, status.st_mode) != expected:
                raise ProjectImportError(
                    "path_changed",
                    "The selected folder path changed while it was being checked.",
                    status_code=409,
                )
        return resolved, normalized, parts

    def browse(self, body: ProjectImportBrowseRequest) -> ProjectImportBrowseResponse:
        root = self._root(body.root_id)
        directory, normalized, parts = self._resolve_directory(root, body.path)
        choices: list[ProjectImportDirectory] = []
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise ProjectImportError("browse_failed", "The selected folder could not be listed.", status_code=404) from exc
        truncated = False
        for entry in entries:
            name = entry.name
            if name.startswith(".") or _sensitive_name(name) or not _safe_entry_name(name):
                continue
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(status.st_mode) or _is_reparse(status) or not stat.S_ISDIR(status.st_mode):
                continue
            if len(choices) >= self.settings.project_import_max_browse_entries:
                truncated = True
                break
            child = "/".join((*parts, name))
            choices.append(ProjectImportDirectory(name=name, path=child))
        breadcrumbs = [ProjectImportBreadcrumb(label=root.label, path="")]
        for index, part in enumerate(parts):
            breadcrumbs.append(ProjectImportBreadcrumb(label=part, path="/".join(parts[: index + 1])))
        return ProjectImportBrowseResponse(
            root_id=root.id,
            root_label=root.label,
            path=normalized,
            breadcrumbs=breadcrumbs,
            directories=choices,
            truncated=truncated,
        )

    def discover(self, body: ProjectImportDiscoverRequest) -> ProjectImportDiscoverResponse:
        """Discover logical projects without assuming their manuals are co-located.

        Only safe root-relative metadata is returned.  Candidate discovery follows
        no links and reads only bounded top-level ``project.yaml`` files; the normal
        preview/apply compare-and-swap scan remains the authority for import.
        """

        root = self._root(body.root_id)
        projects: list[ProjectImportCandidate] = []
        truncated = False
        visited = 0
        stack: list[tuple[Path, tuple[str, ...], int]] = [(root.path, (), 0)]
        while stack:
            directory, parts, depth = stack.pop()
            if depth > self.settings.project_import_max_depth:
                continue
            before = _lstat_safe(directory)
            if not stat.S_ISDIR(before.st_mode):
                continue
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
            except OSError:
                continue
            project_file: Path | None = None
            children: list[tuple[Path, tuple[str, ...], int]] = []
            for entry in entries:
                name = entry.name
                if name == "project.yaml":
                    try:
                        status = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(status.st_mode) and not _is_reparse(status):
                        project_file = Path(entry.path)
                    continue
                if (
                    depth >= self.settings.project_import_max_depth
                    or name.startswith(".")
                    or name.lower() in _EXCLUDED_DIRS
                    or _sensitive_name(name)
                    or not _safe_entry_name(name)
                ):
                    continue
                try:
                    status = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status) or not stat.S_ISDIR(status.st_mode):
                    continue
                child_parts = (*parts, name)
                # Historical release archives sometimes contain a packaged
                # tests_specs tree inside tests_specs.  It is distribution
                # residue, not another operator project collection.
                if child_parts.count("tests_specs") > 1:
                    continue
                children.append((Path(entry.path), child_parts, depth + 1))
            stack.extend(reversed(children))
            visited += 1
            if visited > self.settings.project_import_max_browse_entries * 8:
                truncated = True
                break
            if project_file is None or not parts:
                continue
            try:
                data, _status = self._read_stable_file(project_file)
                mapping = yaml.safe_load(data.decode("utf-8")) or {}
            except (ProjectImportError, UnicodeDecodeError, yaml.YAMLError):
                continue
            if not isinstance(mapping, dict):
                continue
            relative = "/".join(parts)
            name = str(mapping.get("name") or parts[-1]).strip()[:240] or parts[-1]
            destination_slug = re.sub(r"[^A-Za-z0-9_-]+", "-", parts[-1]).strip("-_")
            if not PROJECT_SLUG_RE.fullmatch(destination_slug):
                destination_slug = "imported-project"
            layout: Literal["portable", "split", "incomplete"] = "incomplete"
            manual_path: str | None = None
            manual_value = mapping.get("manual_dir")
            portable = directory / "manual" / "manual.md"
            try:
                portable_status = portable.lstat()
            except OSError:
                portable_status = None
            if portable_status is not None and stat.S_ISREG(portable_status.st_mode) and not _is_reparse(portable_status):
                layout = "portable"
                manual_path = "/".join((*parts, "manual"))
            elif isinstance(manual_value, str):
                try:
                    candidate_manual, normalized_manual, _ = self._resolve_directory(root, manual_value.strip())
                    master = candidate_manual / "manual.md"
                    master_status = master.lstat()
                    if stat.S_ISREG(master_status.st_mode) and not _is_reparse(master_status):
                        layout = "split"
                        manual_path = normalized_manual
                except (OSError, ProjectImportError):
                    pass
            if layout == "incomplete":
                # The advanced folder browser remains available for diagnosis,
                # but a root defaults file is not presented as an importable
                # project merely because it happens to be named project.yaml.
                continue
            projects.append(ProjectImportCandidate(
                path=relative,
                destination_slug=destination_slug,
                project_name=name,
                layout=layout,
                manual_path=manual_path,
            ))
            if len(projects) >= self.settings.project_import_max_browse_entries:
                truncated = True
                break
        projects.sort(key=lambda item: (item.project_name.casefold(), item.path.casefold()))
        return ProjectImportDiscoverResponse(
            root_id=root.id,
            root_label=root.label,
            projects=projects,
            truncated=truncated,
        )

    @staticmethod
    def _source_digest(root_id: str, relative: str) -> str:
        return hashlib.sha256(f"{root_id}\0{relative}".encode("utf-8")).hexdigest()

    @staticmethod
    def _actor_key(actor: Actor) -> str:
        material = f"{actor.subject}\0{actor.session_id or actor.auth_method}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _read_stable_file(self, path: Path) -> tuple[bytes, os.stat_result]:
        if not _safe_nofollow_reads_supported():
            raise ProjectImportError(
                "safe_read_unavailable",
                "This host cannot prove no-follow source reads, so import is safely disabled.",
                status_code=503,
            )
        before = _lstat_safe(path)
        if not stat.S_ISREG(before.st_mode):
            raise ProjectImportError("special_file", "Only regular project files are permitted.")
        if before.st_size > self.settings.project_import_max_file_bytes:
            raise ProjectImportError("file_too_large", "A project file exceeds the configured size limit.")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ProjectImportError("file_open_failed", "A project file could not be opened safely.") from exc
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not _same_identity(before, opened):
                raise ProjectImportError("source_changed", "The source changed while it was being inspected.", status_code=409)
            chunks: list[bytes] = []
            remaining = self.settings.project_import_max_file_bytes + 1
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > self.settings.project_import_max_file_bytes:
                raise ProjectImportError("file_too_large", "A project file exceeds the configured size limit.")
            final_fd = os.fstat(fd)
        finally:
            os.close(fd)
        try:
            after = path.lstat()
        except OSError as exc:
            raise ProjectImportError("source_changed", "The source changed while it was being inspected.", status_code=409) from exc
        if not _same_identity(before, final_fd) or not _same_identity(before, after):
            raise ProjectImportError("source_changed", "The source changed while it was being inspected.", status_code=409)
        return data, before

    def _excluded(
        self,
        excluded: list[ProjectImportExcludedEntry],
        *,
        path: str,
        reason: str,
        redact: bool = False,
    ) -> None:
        if len(excluded) >= self.settings.project_import_max_excluded_entries:
            return
        excluded.append(ProjectImportExcludedEntry(
            path="<entry redacted>" if redact else path,
            reason=reason,
        ))

    def _scan_legacy_manual(
        self,
        root: _Root,
        relative: str,
        *,
        selected_source: Path,
        manifest: list[_ManifestEntry],
        contents: dict[str, bytes],
        roles: dict[str, str],
        diagnostics: list[ProjectImportDiagnostic],
        excluded: list[ProjectImportExcludedEntry],
        file_count: int,
        total_bytes: int,
        excluded_count: int,
    ) -> tuple[int, int, int, int, bool]:
        """Scan one legacy manual tree into the portable ``manual/`` namespace.

        The legacy path is interpreted only as a normalized relative path below
        the already-configured import root.  It is resolved with the same
        component identity and no-link checks used for browser selections; no
        absolute, parent-relative, cross-root, linked, or reparse path is
        followed.
        """

        try:
            manual_source, normalized, _parts = self._resolve_directory(root, relative)
        except ProjectImportError:
            diagnostics.append(ProjectImportDiagnostic(
                code="legacy_manual_unavailable",
                message=(
                    "The relative legacy manual_dir is unavailable or unsafe inside the "
                    "selected import root."
                ),
                path="manual_dir",
            ))
            return file_count, total_bytes, excluded_count, 0, True
        try:
            overlap = (
                os.path.commonpath((str(selected_source), str(manual_source))) == str(selected_source)
                or os.path.commonpath((str(selected_source), str(manual_source))) == str(manual_source)
            )
        except ValueError:
            overlap = True
        if overlap:
            diagnostics.append(ProjectImportDiagnostic(
                code="legacy_manual_overlap",
                message=(
                    "The legacy manual directory must be a separate sibling tree inside the "
                    "configured import root."
                ),
                path="manual_dir",
            ))
            return file_count, total_bytes, excluded_count, 0, True

        # Bind the chosen root-relative source location into the freshness
        # manifest without returning the host path to the browser or audit log.
        location_digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        manifest.append(_ManifestEntry(
            "manual", "legacy-directory", 0, 0, 0, 0, location_digest,
        ))
        manual_count = 0
        limit_hit = False
        stack: list[tuple[Path, tuple[str, ...], int]] = [(manual_source, ("manual",), 1)]

        while stack and not limit_hit:
            directory, relative_parts, depth = stack.pop()
            directory_before = _lstat_safe(directory)
            if not stat.S_ISDIR(directory_before.st_mode):
                raise ProjectImportError(
                    "source_changed", "The legacy manual folder changed during preview.", status_code=409
                )
            directory_path = "/".join(relative_parts)
            manifest.append(_ManifestEntry(
                directory_path, "directory", 0, directory_before.st_mtime_ns,
                directory_before.st_dev, directory_before.st_ino,
            ))
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold(), reverse=True)
            except OSError as exc:
                raise ProjectImportError(
                    "scan_failed", "The legacy manual could not be inspected."
                ) from exc

            for entry in entries:
                name = entry.name
                child_parts = (*relative_parts, name)
                safe_path = "/".join(child_parts)
                lowered = name.lower()
                sensitive_or_hidden = (
                    name.startswith(".") or _sensitive_name(name) or not _safe_entry_name(name)
                )
                visible_path = None if sensitive_or_hidden else safe_path
                try:
                    status = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ProjectImportError(
                        "source_changed", "A legacy manual entry changed during preview.", status_code=409
                    ) from exc
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
                    diagnostics.append(ProjectImportDiagnostic(
                        code="linked_entry",
                        message="Symlinks, junctions, and reparse points are not permitted.",
                        path=visible_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "linked", 0, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if not stat.S_ISDIR(status.st_mode):
                    file_count += 1
                    if file_count > self.settings.project_import_max_files:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="file_count_limit",
                            message="The selected project exceeds the configured file-count limit.",
                        ))
                        limit_hit = True
                        break
                if _is_special_entry(status):
                    diagnostics.append(ProjectImportDiagnostic(
                        code="special_file",
                        message="Sockets, devices, FIFOs, and other special entries are not permitted.",
                        path=visible_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "special", 0, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if name.startswith(".") or lowered in _EXCLUDED_DIRS:
                    excluded_count += 1
                    sensitive = _sensitive_name(name) or lowered == ".env"
                    self._excluded(
                        excluded, path=safe_path,
                        reason="sensitive" if sensitive else "runtime_or_hidden", redact=True,
                    )
                    if sensitive:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="sensitive_entry",
                            message="The legacy manual contains a sensitive-looking entry; remove it before import.",
                        ))
                    continue
                if _sensitive_name(name):
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="sensitive", redact=True)
                    diagnostics.append(ProjectImportDiagnostic(
                        code="sensitive_entry",
                        message="The legacy manual contains a sensitive-looking entry; remove it before import.",
                    ))
                    continue
                if not _safe_entry_name(name):
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="unsafe_filename", redact=True)
                    diagnostics.append(ProjectImportDiagnostic(
                        code="unsafe_filename",
                        message="The legacy manual contains a filename that is not portable or safe.",
                    ))
                    continue
                if stat.S_ISDIR(status.st_mode):
                    if depth + 1 > self.settings.project_import_max_depth:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="depth_limit",
                            message="The selected project exceeds the configured directory depth limit.",
                            path=safe_path,
                        ))
                        limit_hit = True
                        break
                    stack.append((Path(entry.path), child_parts, depth + 1))
                    continue

                total_bytes += status.st_size
                if status.st_size > self.settings.project_import_max_file_bytes:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="file_too_large",
                        message="A project file exceeds the configured single-file size limit.",
                        path=safe_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "oversized", status.st_size, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if total_bytes > self.settings.project_import_max_total_bytes:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="total_size_limit",
                        message="The selected project exceeds the configured total-byte limit.",
                    ))
                    limit_hit = True
                    break

                suffix = Path(name).suffix.lower()
                if suffix == ".md":
                    role = "manual"
                elif suffix in _MANUAL_ASSET_SUFFIXES:
                    role = "manual-asset"
                else:
                    role = "excluded"
                if role == "excluded":
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="not_required_by_project_format")
                    manifest.append(_ManifestEntry(
                        safe_path, "excluded", status.st_size, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                try:
                    data, stable_status = self._read_stable_file(Path(entry.path))
                except ProjectImportError as exc:
                    diagnostics.append(ProjectImportDiagnostic(
                        code=exc.code, message=exc.message, path=safe_path
                    ))
                    continue
                manifest.append(_ManifestEntry(
                    safe_path, role, len(data), stable_status.st_mtime_ns,
                    stable_status.st_dev, stable_status.st_ino, hashlib.sha256(data).hexdigest(),
                ))
                contents[safe_path] = data
                roles[safe_path] = role
                if role == "manual":
                    manual_count += 1

            directory_after = _lstat_safe(directory)
            if not _same_identity(directory_before, directory_after):
                raise ProjectImportError(
                    "source_changed", "The legacy manual folder changed during preview.", status_code=409
                )

        return file_count, total_bytes, excluded_count, manual_count, limit_hit

    def _scan_project(self, root: _Root, relative: str, destination_slug: str) -> _Scan:
        normalized, _parts = _normalize_relative(relative)
        if not PROJECT_SLUG_RE.fullmatch(destination_slug):
            raise ProjectImportError(
                "invalid_destination_slug",
                "Destination slug may contain only letters, digits, hyphens, and underscores and may not begin with punctuation.",
                status_code=400,
            )
        source, _normalized_again, _selection_parts = self._resolve_directory(root, normalized)
        diagnostics: list[ProjectImportDiagnostic] = []
        excluded: list[ProjectImportExcludedEntry] = []
        manifest: list[_ManifestEntry] = []
        contents: dict[str, bytes] = {}
        roles: dict[str, str] = {}
        total_bytes = 0
        file_count = 0
        excluded_count = 0
        spec_count = 0
        manual_count = 0
        legacy_manual_used = False
        limit_hit = False
        stack: list[tuple[Path, tuple[str, ...], int]] = [(source, (), 0)]

        while stack and not limit_hit:
            directory, relative_parts, depth = stack.pop()
            directory_before = _lstat_safe(directory)
            if not stat.S_ISDIR(directory_before.st_mode):
                raise ProjectImportError("source_changed", "The source folder changed during preview.", status_code=409)
            directory_path = "/".join(relative_parts)
            manifest.append(_ManifestEntry(
                directory_path, "directory", 0, directory_before.st_mtime_ns,
                directory_before.st_dev, directory_before.st_ino,
            ))
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold(), reverse=True)
            except OSError as exc:
                raise ProjectImportError("scan_failed", "The selected project could not be inspected.") from exc
            for entry in entries:
                name = entry.name
                child_parts = (*relative_parts, name)
                safe_path = "/".join(child_parts)
                lowered = name.lower()
                sensitive_or_hidden = (
                    name.startswith(".")
                    or _sensitive_name(name)
                    or not _safe_entry_name(name)
                )
                visible_path = None if sensitive_or_hidden else safe_path
                try:
                    status = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ProjectImportError(
                        "source_changed",
                        "A source entry changed during preview.",
                        status_code=409,
                    ) from exc
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
                    diagnostics.append(ProjectImportDiagnostic(
                        code="linked_entry",
                        message="Symlinks, junctions, and reparse points are not permitted.",
                        path=visible_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "linked", 0, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if not stat.S_ISDIR(status.st_mode):
                    file_count += 1
                    if file_count > self.settings.project_import_max_files:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="file_count_limit",
                            message="The selected project exceeds the configured file-count limit.",
                        ))
                        limit_hit = True
                        break
                if _is_special_entry(status):
                    diagnostics.append(ProjectImportDiagnostic(
                        code="special_file",
                        message="Sockets, devices, FIFOs, and other special entries are not permitted.",
                        path=visible_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "special", 0, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if name.startswith(".") or lowered in _EXCLUDED_DIRS:
                    excluded_count += 1
                    sensitive = _sensitive_name(name) or lowered == ".env"
                    self._excluded(excluded, path=safe_path, reason="sensitive" if sensitive else "runtime_or_hidden", redact=True)
                    if sensitive:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="sensitive_entry",
                            message="The selected folder contains a sensitive-looking entry; remove it before import.",
                        ))
                    continue
                if _sensitive_name(name):
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="sensitive", redact=True)
                    diagnostics.append(ProjectImportDiagnostic(
                        code="sensitive_entry",
                        message="The selected folder contains a sensitive-looking entry; remove it before import.",
                    ))
                    continue
                if not _safe_entry_name(name):
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="unsafe_filename", redact=True)
                    diagnostics.append(ProjectImportDiagnostic(
                        code="unsafe_filename",
                        message="The selected folder contains a filename that is not portable or safe.",
                    ))
                    continue
                if stat.S_ISDIR(status.st_mode):
                    if depth + 1 > self.settings.project_import_max_depth:
                        diagnostics.append(ProjectImportDiagnostic(
                            code="depth_limit",
                            message="The selected project exceeds the configured directory depth limit.",
                            path=safe_path,
                        ))
                        limit_hit = True
                        break
                    stack.append((Path(entry.path), child_parts, depth + 1))
                    continue
                total_bytes += status.st_size
                if status.st_size > self.settings.project_import_max_file_bytes:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="file_too_large",
                        message="A project file exceeds the configured single-file size limit.",
                        path=safe_path,
                    ))
                    manifest.append(_ManifestEntry(
                        safe_path, "oversized", status.st_size, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                if total_bytes > self.settings.project_import_max_total_bytes:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="total_size_limit",
                        message="The selected project exceeds the configured total-byte limit.",
                    ))
                    limit_hit = True
                    break

                first = child_parts[0]
                if safe_path == "project.yaml":
                    role = "project"
                elif name == "project.yaml":
                    role = "excluded"
                    diagnostics.append(ProjectImportDiagnostic(
                        code="nested_project_metadata",
                        message="Nested project.yaml files are not permitted.",
                        path=safe_path,
                    ))
                elif first == "manual" and name.lower().endswith(".md"):
                    role = "manual"
                elif first == "manual" and Path(name).suffix.lower() in _MANUAL_ASSET_SUFFIXES:
                    role = "manual-asset"
                elif first != "manual" and name.lower().endswith(".md") and name not in _EXCLUDED_FILES:
                    role = "spec"
                else:
                    role = "excluded"

                if role == "excluded":
                    excluded_count += 1
                    self._excluded(excluded, path=safe_path, reason="not_required_by_project_format")
                    manifest.append(_ManifestEntry(
                        safe_path, "excluded", status.st_size, status.st_mtime_ns,
                        status.st_dev, status.st_ino,
                    ))
                    continue
                try:
                    data, stable_status = self._read_stable_file(Path(entry.path))
                except ProjectImportError as exc:
                    diagnostics.append(ProjectImportDiagnostic(code=exc.code, message=exc.message, path=safe_path))
                    continue
                digest = hashlib.sha256(data).hexdigest()
                manifest.append(_ManifestEntry(
                    safe_path, role, len(data), stable_status.st_mtime_ns,
                    stable_status.st_dev, stable_status.st_ino, digest,
                ))
                contents[safe_path] = data
                roles[safe_path] = role
                if role == "spec":
                    spec_count += 1
                elif role == "manual":
                    manual_count += 1

            directory_after = _lstat_safe(directory)
            if not _same_identity(directory_before, directory_after):
                raise ProjectImportError("source_changed", "The source folder changed during preview.", status_code=409)

        if "project.yaml" not in contents:
            diagnostics.append(ProjectImportDiagnostic(
                code="project_metadata_missing",
                message="The selected folder must contain project.yaml at its top level.",
                path="project.yaml",
            ))

        # Historical AI-Test repositories keep each specification project in
        # ``tests_specs/<slug>`` and its manual in a sibling
        # ``tests_manuals/<slug>`` tree.  Support that layout only when the
        # selected folder has no portable ``manual/`` directory and the YAML
        # names a normalized relative directory below this same configured
        # import root.  Absolute and parent-relative paths remain rejected.
        portable_manual_directory = any(
            item.path == "manual" and item.kind == "directory" for item in manifest
        )
        raw_project = contents.get("project.yaml")
        if raw_project is not None and "manual/manual.md" not in contents and not portable_manual_directory:
            legacy_manual: object = None
            try:
                raw_mapping = yaml.safe_load(raw_project.decode("utf-8")) or {}
                if isinstance(raw_mapping, dict):
                    legacy_manual = raw_mapping.get("manual_dir")
            except (UnicodeDecodeError, yaml.YAMLError):
                # The canonical project parse below owns the user-facing YAML
                # diagnostic.  Do not add a second, potentially confusing one.
                legacy_manual = None
            if isinstance(legacy_manual, str) and legacy_manual.strip() not in {"", ".", "./manual", "manual"}:
                try:
                    legacy_relative, _legacy_parts = _normalize_relative(legacy_manual.strip())
                except ProjectImportError:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="legacy_manual_path_invalid",
                        message=(
                            "Legacy manual_dir must be a normalized relative directory inside "
                            "the selected import root."
                        ),
                        path="manual_dir",
                    ))
                else:
                    (
                        file_count,
                        total_bytes,
                        excluded_count,
                        imported_manual_count,
                        legacy_limit_hit,
                    ) = self._scan_legacy_manual(
                        root,
                        legacy_relative,
                        selected_source=source,
                        manifest=manifest,
                        contents=contents,
                        roles=roles,
                        diagnostics=diagnostics,
                        excluded=excluded,
                        file_count=file_count,
                        total_bytes=total_bytes,
                        excluded_count=excluded_count,
                    )
                    manual_count += imported_manual_count
                    limit_hit = limit_hit or legacy_limit_hit
                    if "manual/manual.md" in contents:
                        legacy_manual_used = True
                        diagnostics.append(ProjectImportDiagnostic(
                            code="legacy_manual_copied",
                            message=(
                                "The root-contained legacy manual will be copied into the "
                                "managed portable project."
                            ),
                            severity="warning",
                            path="manual_dir",
                        ))
        if "manual/manual.md" not in contents:
            diagnostics.append(ProjectImportDiagnostic(
                code="portable_manual_missing",
                message=(
                    "The project must contain manual/manual.md or reference a relative legacy "
                    "manual_dir inside the same configured import root."
                ),
                path="manual/manual.md",
            ))
        if spec_count == 0:
            diagnostics.append(ProjectImportDiagnostic(
                code="spec_missing",
                message="The selected folder must contain at least one runnable Markdown specification.",
            ))

        project_name: str | None = None
        document: ProjectDocument | None = None
        rendered_project: str | None = None
        if raw_project is not None:
            try:
                raw_text = raw_project.decode("utf-8")
                parsed = parse_project_document(raw_text, dir_name=destination_slug)
                project_name = parsed.document.display_name
                # Project-relative storage works in both the host-managed store
                # and the runner's /app/tests_specs mount.
                final_manual = "./manual"
                document = parsed.document.model_copy(update={"manual_dir": final_manual}, deep=True)
                if document.target.type == "vnc" and document.target.via:
                    via = document.target.via.strip()
                    if "@" in via:
                        jump_user, jump_host = via.rsplit("@", 1)
                    else:
                        jump_user, jump_host = None, via
                    known_hosts = re.sub(r"[^A-Za-z0-9_.-]+", "-", jump_host).strip("-.")
                    route = SshJumpConnectionRoute(
                        host=jump_host,
                        user=jump_user or None,
                        port=22,
                        known_hosts_file=f"{known_hosts or 'vnc-jump'}.known_hosts",
                    )
                    document = document.model_copy(update={
                        "target": document.target.model_copy(
                            update={"via": None, "route": route}, deep=True
                        )
                    }, deep=True)
                    diagnostics.append(ProjectImportDiagnostic(
                        code="legacy_vnc_route_migrated",
                        message=(
                            "Legacy VNC via routing was migrated to an explicit SSH local-forward "
                            "route with strict host-key verification. Supply the named known-hosts "
                            "reference before target preflight."
                        ),
                        severity="warning",
                        path="target.route",
                    ))
                if legacy_manual_used and not str(getattr(document.target, "window", "") or "").strip():
                    default_window = _legacy_runtime_window(document.target)
                    if default_window:
                        document = document.model_copy(
                            update={
                                "target": document.target.model_copy(
                                    update={"window": default_window}, deep=True
                                )
                            },
                            deep=True,
                        )
                        diagnostics.append(ProjectImportDiagnostic(
                            code="legacy_window_defaulted",
                            message=(
                                "The legacy project omitted target.window; import will persist "
                                "the runner's existing deterministic window-title fallback."
                            ),
                            severity="warning",
                            path="target.window",
                        ))
                diagnostics.append(ProjectImportDiagnostic(
                    code="watch_learn_readiness_required",
                    message=(
                        "The source project may be imported, but Watch & Learn remains disabled "
                        "until its owner completes the separate readiness workflow."
                    ),
                    severity="warning",
                    path="watch-learn-readiness",
                ))
                if legacy_manual_used and document.schedule is None:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="legacy_schedule_retained",
                        message=(
                            "The legacy project has no schedule. It can be run explicitly and "
                            "will remain unscheduled after import."
                        ),
                        severity="warning",
                        path="schedule",
                    ))
                document, rendered_project, project_diagnostics = validate_project_for_apply(
                    document,
                    require_manual_on_disk=False,
                    require_schedule=not legacy_manual_used,
                    new_project=False,
                )
                diagnostics.extend(ProjectImportDiagnostic(
                    code=item.code,
                    message=item.message,
                    severity=item.severity,
                    path=item.field,
                ) for item in [*parsed.diagnostics, *project_diagnostics])
                if parsed.document.manual_dir != final_manual:
                    diagnostics.append(ProjectImportDiagnostic(
                        code="manual_dir_rebased",
                        message="The imported project will use its managed portable manual; the source manual_dir is not followed.",
                        severity="warning",
                        path="manual_dir",
                    ))
            except UnicodeDecodeError:
                diagnostics.append(ProjectImportDiagnostic(
                    code="project_encoding",
                    message="project.yaml must be valid UTF-8.",
                    path="project.yaml",
                ))
            except AuthoringValidationError as exc:
                diagnostics.extend(ProjectImportDiagnostic(
                    code=item.code,
                    message=item.message,
                    severity=item.severity,
                    path=item.field,
                ) for item in exc.diagnostics)

        for path, role in roles.items():
            if role not in {"spec", "manual"}:
                continue
            try:
                text = contents[path].decode("utf-8")
            except UnicodeDecodeError:
                diagnostics.append(ProjectImportDiagnostic(
                    code="utf8_required",
                    message="Project Markdown must be valid UTF-8.",
                    path=path,
                ))
                continue
            if role == "spec":
                try:
                    parsed_spec = parse_spec_document(text, path=path)
                    validate_spec_for_apply(parsed_spec)
                except AuthoringValidationError as exc:
                    diagnostics.extend(ProjectImportDiagnostic(
                        code=item.code,
                        message=item.message,
                        severity=item.severity,
                        path=path,
                    ) for item in exc.diagnostics)
            elif path == "manual/manual.md":
                if not text.strip() or not any(
                    line.startswith("# ") and line[2:].strip()
                    for line in text.splitlines()
                ):
                    diagnostics.append(ProjectImportDiagnostic(
                        code="manual_heading_missing",
                        message="manual/manual.md must contain a non-empty level-one heading.",
                        path=path,
                    ))

        destination = self.specs_root / destination_slug
        if destination.exists() or destination.is_symlink():
            diagnostics.append(ProjectImportDiagnostic(
                code="project_exists",
                message="A managed project already exists with this destination slug.",
                path="destination_slug",
            ))
        if excluded_count:
            diagnostics.append(ProjectImportDiagnostic(
                code="files_excluded",
                message=f"{excluded_count} file or directory entr{'y was' if excluded_count == 1 else 'ies were'} excluded from import.",
                severity="warning",
            ))

        ordered_manifest = tuple(sorted(manifest, key=lambda item: (item.path, item.kind)))
        payload = json.dumps(
            [item.serializable() for item in ordered_manifest],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        manifest_digest = hashlib.sha256(payload).hexdigest()
        return _Scan(
            source=source,
            relative_path=normalized,
            destination_slug=destination_slug,
            project_name=project_name,
            document=document,
            rendered_project=rendered_project,
            manifest=ordered_manifest,
            manifest_digest=manifest_digest,
            contents=contents,
            roles=roles,
            diagnostics=diagnostics,
            excluded=excluded,
            excluded_count=excluded_count,
            total_bytes=total_bytes,
            spec_count=spec_count,
            manual_count=manual_count,
            legacy_manual_used=legacy_manual_used,
        )

    def _prune_tokens(self) -> None:
        now = self.clock()
        for token, record in list(self._tokens.items()):
            if record.expires_at <= now:
                self._tokens.pop(token, None)
        while len(self._tokens) >= self.settings.project_import_max_previews:
            self._tokens.popitem(last=False)

    def preview(self, body: ProjectImportPreviewRequest, actor: Actor) -> ProjectImportPreviewResponse:
        if not _safe_nofollow_reads_supported():
            raise ProjectImportError(
                "safe_read_unavailable",
                "This host cannot prove no-follow source reads, so import is safely disabled.",
                status_code=503,
            )
        root = self._root(body.root_id)
        scan = self._scan_project(root, body.path, body.destination_slug)
        errors = any(item.severity == "error" for item in scan.diagnostics)
        token: str | None = None
        expires_at: float | None = None
        if not errors:
            token = secrets.token_urlsafe(32)
            expires_at = self.clock() + self.settings.project_import_preview_ttl_seconds
            with self._lock:
                self._prune_tokens()
                self._tokens[token] = _PreviewToken(
                    root_id=root.id,
                    relative_path=scan.relative_path,
                    destination_slug=body.destination_slug,
                    manifest_digest=scan.manifest_digest,
                    actor_key=self._actor_key(actor),
                    expires_at=expires_at,
                )
        try:
            self.audit.record(
                actor=actor,
                action="preview",
                result="ready" if token else "validation_error",
                root_id=root.id,
                source_digest=self._source_digest(root.id, scan.relative_path),
                manifest_digest=scan.manifest_digest,
                destination_slug=body.destination_slug,
                spec_count=scan.spec_count,
                manual_count=scan.manual_count,
                file_count=len(scan.contents),
                total_bytes=scan.total_bytes,
            )
        except OSError as exc:
            if token is not None:
                with self._lock:
                    self._tokens.pop(token, None)
            raise ProjectImportError(
                "audit_unavailable",
                "The import preview could not be recorded safely.",
                status_code=503,
            ) from exc
        return ProjectImportPreviewResponse(
            can_import=token is not None,
            preview_token=token,
            root_id=root.id,
            root_label=root.label,
            selected_path=scan.relative_path,
            project_name=scan.project_name,
            destination_slug=body.destination_slug,
            proposed_destination=f"Managed projects/{body.destination_slug}",
            spec_count=scan.spec_count,
            manual_count=scan.manual_count,
            included_file_count=len(scan.contents),
            total_bytes=scan.total_bytes,
            manifest_digest=scan.manifest_digest,
            diagnostics=scan.diagnostics,
            excluded_files=scan.excluded,
            excluded_count=scan.excluded_count,
            expires_at=(
                datetime.fromtimestamp(expires_at, timezone.utc).isoformat()
                if expires_at is not None else None
            ),
        )

    def _take_token(self, token: str, actor: Actor, destination_slug: str) -> _PreviewToken:
        with self._lock:
            self._prune_tokens()
            record = self._tokens.pop(token, None)
        if record is None:
            raise ProjectImportError(
                "preview_expired",
                "The import preview expired or was already used; preview the folder again.",
                status_code=409,
            )
        if record.actor_key != self._actor_key(actor):
            raise ProjectImportError(
                "preview_owner_mismatch",
                "This preview belongs to another authenticated session.",
                status_code=403,
            )
        if record.destination_slug != destination_slug:
            raise ProjectImportError(
                "preview_destination_mismatch",
                "The destination slug changed after preview; preview the folder again.",
                status_code=409,
            )
        return record

    def _ensure_destination_root(self) -> None:
        try:
            for component in reversed([self.specs_root, *self.specs_root.parents]):
                if not component.exists() and not component.is_symlink():
                    continue
                status = component.lstat()
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
                    raise ProjectImportConfigurationError(
                        "managed project storage may not contain links or reparse points"
                    )
            self.specs_root.mkdir(parents=True, exist_ok=True)
            for component in reversed([self.specs_root, *self.specs_root.parents]):
                status = component.lstat()
                if stat.S_ISLNK(status.st_mode) or _is_reparse(status):
                    raise ProjectImportConfigurationError(
                        "managed project storage may not contain links or reparse points"
                    )
            if not self.specs_root.is_dir():
                raise ProjectImportConfigurationError("managed project storage is unsafe")
        except OSError as exc:
            raise ProjectImportConfigurationError("managed project storage is unavailable") from exc

    @staticmethod
    def _write_stage_file(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _copy_to_stage(self, stage: Path, scan: _Scan) -> None:
        for path, data in sorted(scan.contents.items()):
            if scan.roles.get(path) == "project" or path == "support/project-import-manifest.json":
                continue
            self._write_stage_file(stage.joinpath(*PurePosixPath(path).parts), data)

    def _validate_stage(self, stage: Path, scan: _Scan) -> None:
        if scan.document is None or scan.rendered_project is None:
            raise ProjectImportError("staged_validation_failed", "The staged project metadata is unavailable.")
        staged_document = scan.document.model_copy(
            update={"manual_dir": str((stage / "manual").absolute())},
            deep=True,
        )
        validate_project_for_apply(
            staged_document,
            require_manual_on_disk=True,
            require_schedule=not scan.legacy_manual_used,
            new_project=False,
        )
        for path, role in scan.roles.items():
            if role != "spec":
                continue
            full = stage.joinpath(*PurePosixPath(path).parts)
            text = full.read_text(encoding="utf-8")
            validate_spec_for_apply(parse_spec_document(text, path=path))
        for path, role in scan.roles.items():
            if role == "manual":
                stage.joinpath(*PurePosixPath(path).parts).read_text(encoding="utf-8")
        final_document, diagnostics = lint_project_document(
            scan.document,
            require_manual_on_disk=False,
            require_schedule=not scan.legacy_manual_used,
        )
        if any(item.severity == "error" for item in diagnostics):
            raise ProjectImportError("staged_validation_failed", "The staged project failed final validation.")
        rendered = render_project_yaml(final_document)
        if rendered != scan.rendered_project:
            raise ProjectImportError("staged_validation_failed", "The staged project metadata changed after preview.")
        self._write_stage_file(stage / "project.yaml", rendered.encode("utf-8"))
        manifest_path = stage / "support" / "project-import-manifest.json"
        files = []
        for source in sorted(path for path in stage.rglob("*") if path.is_file()):
            relative = source.relative_to(stage).as_posix()
            if relative == "support/project-import-manifest.json":
                continue
            data = source.read_bytes()
            files.append({
                "path": relative,
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
            })
        manifest = {
            "version": 1,
            "origin": "project-folder-import",
            "files": files,
        }
        self._write_stage_file(
            manifest_path,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )

    @staticmethod
    def _prepare_stage_modes(stage: Path) -> None:
        for current, directories, files in os.walk(stage, followlinks=False):
            os.chmod(current, 0o755)
            for directory in directories:
                os.chmod(Path(current) / directory, 0o755)
            for filename in files:
                os.chmod(Path(current) / filename, 0o644)
            _fsync_directory(Path(current))

    def _publish(self, stage: Path, destination: Path) -> None:
        atomic_publish_noreplace(stage, destination)
        _fsync_directory(destination.parent)

    def _cleanup_stage(self, stage: Path, identity: tuple[int, int] | None) -> None:
        if stage.parent != self.specs_root or not stage.name.startswith(".project_import_"):
            return
        try:
            status = stage.lstat()
        except FileNotFoundError:
            return
        if (
            identity is not None
            and (status.st_dev, status.st_ino) == identity
            and not stat.S_ISLNK(status.st_mode)
            and not _is_reparse(status)
            and stat.S_ISDIR(status.st_mode)
        ):
            shutil.rmtree(stage)

    def apply(self, body: ProjectImportApplyRequest, actor: Actor) -> ProjectImportApplyResponse:
        record = self._take_token(body.preview_token, actor, body.destination_slug)
        root = self._root(record.root_id)
        source_digest = self._source_digest(root.id, record.relative_path)
        scan: _Scan | None = None
        stage: Path | None = None
        stage_identity: tuple[int, int] | None = None
        destination = self.specs_root / body.destination_slug
        published = False
        published_identity: tuple[int, int] | None = None
        ownership_claimed = False
        try:
            scan = self._scan_project(root, record.relative_path, body.destination_slug)
            if scan.manifest_digest != record.manifest_digest:
                raise ProjectImportError(
                    "stale_preview",
                    "The source changed after preview; preview the folder again.",
                    status_code=409,
                )
            if any(item.severity == "error" for item in scan.diagnostics):
                raise ProjectImportError(
                    "stale_preview",
                    "The source or destination is no longer valid; preview the folder again.",
                    status_code=409,
                )
            self._ensure_destination_root()
            if destination.exists() or destination.is_symlink():
                raise ProjectImportError(
                    "project_exists",
                    "A managed project already exists with this destination slug.",
                    status_code=409,
                )
            stage = Path(tempfile.mkdtemp(prefix=".project_import_", dir=self.specs_root))
            stage_status = stage.lstat()
            stage_identity = (stage_status.st_dev, stage_status.st_ino)
            if os.name != "nt":
                os.chmod(stage, 0o700)
            self._copy_to_stage(stage, scan)
            self._validate_stage(stage, scan)
            final_scan = self._scan_project(root, record.relative_path, body.destination_slug)
            if final_scan.manifest_digest != record.manifest_digest:
                raise ProjectImportError(
                    "stale_preview",
                    "The source changed during import; preview the folder again.",
                    status_code=409,
                )
            self._prepare_stage_modes(stage)
            self._publish(stage, destination)
            published = True
            destination_status = destination.lstat()
            published_identity = (destination_status.st_dev, destination_status.st_ino)
            if self.on_publish is not None:
                # Ownership assignment is part of the same fail-closed publish
                # transaction. A failure reaches the existing rollback path.
                self.on_publish(actor, body.destination_slug, scan.manifest_digest)
                ownership_claimed = True
            try:
                self.audit.record(
                    actor=actor,
                    action="apply",
                    result="imported",
                    root_id=root.id,
                    source_digest=source_digest,
                    manifest_digest=scan.manifest_digest,
                    destination_slug=body.destination_slug,
                    spec_count=scan.spec_count,
                    manual_count=scan.manual_count,
                    file_count=len(scan.contents),
                    total_bytes=scan.total_bytes,
                )
            except OSError as exc:
                raise ProjectImportError(
                    "audit_unavailable",
                    "The imported project could not be recorded safely and was rolled back.",
                    status_code=503,
                ) from exc
            return ProjectImportApplyResponse(
                destination_slug=body.destination_slug,
                project_name=scan.project_name or body.destination_slug,
                spec_count=scan.spec_count,
                manual_count=scan.manual_count,
                included_file_count=len(scan.contents),
                total_bytes=scan.total_bytes,
                manifest_digest=scan.manifest_digest,
                message=f"Imported {scan.spec_count} specification(s) and {scan.manual_count} manual page(s).",
            )
        except BaseException as exc:
            try:
                current_destination = destination.lstat()
            except OSError:
                current_destination = None
            if (
                published
                and current_destination is not None
                and published_identity is not None
                and (current_destination.st_dev, current_destination.st_ino) == published_identity
                and stat.S_ISDIR(current_destination.st_mode)
                and not _is_reparse(current_destination)
            ):
                rollback = self.specs_root / f".project_import_rollback_{secrets.token_hex(8)}"
                try:
                    os.rename(destination, rollback)
                    shutil.rmtree(rollback)
                    published = False
                except OSError:
                    pass
            if ownership_claimed and self.on_rollback is not None:
                try:
                    self.on_rollback(actor, body.destination_slug, scan.manifest_digest if scan else record.manifest_digest)
                except Exception:
                    pass
            try:
                self.audit.record(
                    actor=actor,
                    action="apply",
                    result=exc.code if isinstance(exc, ProjectImportError) else "failed",
                    root_id=root.id,
                    source_digest=source_digest,
                    manifest_digest=(scan.manifest_digest if scan else record.manifest_digest),
                    destination_slug=body.destination_slug,
                    spec_count=scan.spec_count if scan else 0,
                    manual_count=scan.manual_count if scan else 0,
                    file_count=len(scan.contents) if scan else 0,
                    total_bytes=scan.total_bytes if scan else 0,
                )
            except OSError:
                pass
            raise
        finally:
            if stage is not None:
                self._cleanup_stage(stage, stage_identity)
