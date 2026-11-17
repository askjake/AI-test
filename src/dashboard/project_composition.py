"""Manifest-driven multi-root composition into a new managed project."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import tempfile
import threading
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .auth import Actor
from .author_builder import AuthorBuilderService, author_principal
from .authoring import (
    AuthoringValidationError,
    PROJECT_SLUG_RE,
    parse_project_document,
    parse_spec_document,
    render_project_yaml,
    validate_project_for_apply,
    validate_spec_for_apply,
)
from .config import DashboardSettings
from .project_import import (
    ProjectImportError,
    ProjectImportService,
    _is_reparse,
    _safe_entry_name,
    _sensitive_name,
    atomic_publish_noreplace,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


CompositionRole = Literal["project-spec", "specs", "manual-root", "assets", "support-files"]
_TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".json", ".txt"}
_ASSET_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"}
_SUBDIR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class CompositionSource(_StrictModel):
    root_id: str = Field(min_length=1, max_length=64)
    path: str = Field(default="", max_length=4096)
    role: CompositionRole
    destination_subdir: str = Field(default="", max_length=256)

    @field_validator("destination_subdir")
    @classmethod
    def _safe_subdir(cls, value: str) -> str:
        value = value.strip().strip("/")
        if not value:
            return ""
        pure = PurePosixPath(value)
        if not _SUBDIR_RE.fullmatch(value) or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise ValueError("Destination subdirectory is invalid.")
        return pure.as_posix()


class CompositionPreviewRequest(_StrictModel):
    destination_slug: str = Field(min_length=1, max_length=128)
    sources: list[CompositionSource] = Field(min_length=2, max_length=20)


class CompositionProvenance(_StrictModel):
    destination_path: str
    source_root_id: str
    source_relative_path: str
    role: CompositionRole
    digest: str
    size: int


class CompositionPreview(_StrictModel):
    can_create: bool
    preview_token: str | None = None
    destination_slug: str
    project_name: str | None = None
    project_revision: str
    manifest_digest: str
    sources: list[CompositionSource]
    provenance: list[CompositionProvenance]
    diagnostics: list[str]
    expires_at: str | None = None
    status: Literal["preview-only-no-files-copied"] = "preview-only-no-files-copied"


class CompositionCreateRequest(_StrictModel):
    preview_token: str = Field(min_length=20, max_length=256)
    destination_slug: str = Field(min_length=1, max_length=128)
    project_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmation: str = Field(min_length=1, max_length=128)


class CompositionCreateResponse(_StrictModel):
    status: Literal["candidate-project-created"] = "candidate-project-created"
    destination_slug: str
    project_name: str
    project_revision: str
    manifest_digest: str
    included_file_count: int
    message: str


class _CompositionScan:
    def __init__(self, *, body: CompositionPreviewRequest, contents: dict[str, bytes], provenance: list[CompositionProvenance], project_name: str, project_revision: str):
        self.body = body
        self.contents = contents
        self.provenance = provenance
        self.project_name = project_name
        self.project_revision = project_revision
        self.manifest_digest = hashlib.sha256(json.dumps(
            [item.model_dump() for item in provenance], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()


class _CompositionToken:
    def __init__(self, *, actor_key: str, body: CompositionPreviewRequest, manifest_digest: str, project_revision: str, expires_at: float):
        self.actor_key = actor_key
        self.body = body
        self.manifest_digest = manifest_digest
        self.project_revision = project_revision
        self.expires_at = expires_at


class ProjectCompositionService:
    def __init__(self, settings: DashboardSettings, imports: ProjectImportService, builder: AuthorBuilderService, *, clock=time.time):
        self.settings = settings
        self.imports = imports
        self.builder = builder
        self.clock = clock
        self._tokens: OrderedDict[str, _CompositionToken] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def _destination_base(source: CompositionSource) -> PurePosixPath:
        subdir = PurePosixPath(source.destination_subdir) if source.destination_subdir else PurePosixPath()
        if source.role == "project-spec":
            if source.destination_subdir:
                raise ProjectImportError("invalid_mapping", "Project metadata cannot use a destination subdirectory.")
            return PurePosixPath()
        if source.role == "specs":
            return PurePosixPath("specs") / subdir
        if source.role == "manual-root":
            return PurePosixPath("manual") / subdir
        if source.role == "assets":
            return PurePosixPath("manual/assets") / subdir
        return PurePosixPath("support") / subdir

    def _read_tree(self, source: CompositionSource) -> list[tuple[str, bytes]]:
        root = self.imports._root(source.root_id)
        selected, normalized, _parts = self.imports._resolve_directory(root, source.path)
        found: list[tuple[str, bytes]] = []
        for current, directories, files in os.walk(selected, followlinks=False):
            safe_directories: list[str] = []
            for name in sorted(directories):
                path = Path(current) / name
                info = path.lstat()
                if path.is_symlink() or _is_reparse(info):
                    raise ProjectImportError("unsafe_source", "Composition source contains a symbolic link or reparse point.")
                if name.startswith(".") or _sensitive_name(name) or not _safe_entry_name(name):
                    raise ProjectImportError("unsafe_source", "Composition source contains a prohibited directory.")
                safe_directories.append(name)
            directories[:] = safe_directories
            for name in sorted(files):
                path = Path(current) / name
                relative = path.relative_to(selected).as_posix()
                info = path.lstat()
                if path.is_symlink() or _is_reparse(info):
                    raise ProjectImportError("unsafe_source", "Composition source contains a symbolic link or reparse point.")
                if not stat.S_ISREG(info.st_mode):
                    raise ProjectImportError("unsafe_source", "Composition source contains an unsupported file type.")
                if name.startswith(".") or _sensitive_name(name) or not _safe_entry_name(name):
                    raise ProjectImportError("unsafe_source", "Composition source contains a prohibited file category.")
                if info.st_size > self.settings.project_import_max_file_bytes:
                    raise ProjectImportError("file_too_large", "Composition source contains an oversized file.", status_code=413)
                suffix = path.suffix.lower()
                allowed = _TEXT_SUFFIXES | (_ASSET_SUFFIXES if source.role in {"manual-root", "assets"} else set())
                if suffix not in allowed:
                    raise ProjectImportError("unsafe_file_type", "Composition source contains a file type not allowed for its destination role.")
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                        raise ProjectImportError("source_changed", "Composition source changed while it was read.", status_code=409)
                    data = os.read(descriptor, info.st_size + 1)
                    finished = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if len(data) != info.st_size or (finished.st_size, finished.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
                    raise ProjectImportError("source_changed", "Composition source changed while it was read.", status_code=409)
                found.append((f"{normalized}/{relative}".strip("/"), data))
        return found

    def _scan(self, body: CompositionPreviewRequest) -> _CompositionScan:
        if not PROJECT_SLUG_RE.fullmatch(body.destination_slug):
            raise ProjectImportError("invalid_destination", "Destination slug is invalid.")
        if len({(item.root_id, item.path, item.role, item.destination_subdir) for item in body.sources}) != len(body.sources):
            raise ProjectImportError("duplicate_source", "Composition sources must be unique.")
        project_sources = [item for item in body.sources if item.role == "project-spec"]
        if len(project_sources) != 1:
            raise ProjectImportError("project_source_required", "Composition requires exactly one project-spec source.")
        contents: dict[str, bytes] = {}
        provenance: list[CompositionProvenance] = []
        total = 0
        raw_project: bytes | None = None
        for source in body.sources:
            base = self._destination_base(source)
            for source_relative, data in self._read_tree(source):
                local_name = PurePosixPath(source_relative).name
                relative_within_selected = PurePosixPath(source_relative)
                if source.path:
                    selected_parts = PurePosixPath(source.path).parts
                    relative_within_selected = PurePosixPath(*relative_within_selected.parts[len(selected_parts):])
                if source.role == "project-spec":
                    if local_name == "project.yaml" and len(relative_within_selected.parts) == 1:
                        destination = "project.yaml"
                        raw_project = data
                    elif relative_within_selected.parts and relative_within_selected.parts[0] == "manual":
                        continue
                    elif PurePosixPath(local_name).suffix.lower() == ".md":
                        destination = relative_within_selected.as_posix()
                    else:
                        continue
                else:
                    destination = (base / relative_within_selected).as_posix()
                if destination in contents:
                    raise ProjectImportError("destination_conflict", "Two composition sources map to the same destination path.")
                total += len(data)
                if len(contents) + 1 > self.settings.project_import_max_files or total > self.settings.project_import_max_total_bytes:
                    raise ProjectImportError("manifest_too_large", "Composition manifest exceeds configured limits.", status_code=413)
                contents[destination] = data
                provenance.append(CompositionProvenance(
                    destination_path=destination,
                    source_root_id=source.root_id,
                    source_relative_path=source_relative,
                    role=source.role,
                    digest=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                ))
        if raw_project is None:
            raise ProjectImportError("project_yaml_missing", "The project-spec source must contain project.yaml at its selected root.")
        if "manual/manual.md" not in contents:
            raise ProjectImportError("master_manual_missing", "Composition must map a master manual to manual/manual.md.")
        try:
            parsed = parse_project_document(raw_project.decode("utf-8"), dir_name=body.destination_slug)
            document = parsed.document.model_copy(update={
                "dir_name": body.destination_slug,
                "manual_dir": "./manual",
                "legacy": {},
            }, deep=True)
            document, _rendered_once, _diagnostics = validate_project_for_apply(
                document, require_manual_on_disk=False, require_schedule=True, new_project=True
            )
            rendered = render_project_yaml(document).encode("utf-8")
        except (UnicodeError, AuthoringValidationError) as exc:
            raise ProjectImportError("project_validation_failed", "Composed project metadata failed typed validation.") from exc
        contents["project.yaml"] = rendered
        for path, data in contents.items():
            if path == "project.yaml" or not path.endswith(".md") or path.startswith("manual/"):
                continue
            try:
                validate_spec_for_apply(parse_spec_document(data.decode("utf-8"), path=path))
            except (UnicodeError, AuthoringValidationError) as exc:
                raise ProjectImportError("spec_validation_failed", "A composed specification failed typed validation.") from exc
        # Project normalization changes one manifest member; provenance records
        # the exact normalized candidate bytes used for compare-and-swap.
        provenance = [item for item in provenance if item.destination_path != "project.yaml"]
        provenance.append(CompositionProvenance(
            destination_path="project.yaml",
            source_root_id=project_sources[0].root_id,
            source_relative_path=f"{project_sources[0].path}/project.yaml".strip("/"),
            role="project-spec",
            digest=hashlib.sha256(rendered).hexdigest(),
            size=len(rendered),
        ))
        provenance.sort(key=lambda item: item.destination_path)
        inventory_entries = [
            {
                "path": path,
                "role": self.builder._role(path),
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
            }
            for path, data in sorted(contents.items())
        ]
        project_revision = hashlib.sha256(json.dumps(
            inventory_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")).hexdigest()
        return _CompositionScan(
            body=body, contents=contents, provenance=provenance,
            project_name=document.display_name, project_revision=project_revision,
        )

    def _prune(self) -> None:
        now_value = self.clock()
        for token, record in list(self._tokens.items()):
            if record.expires_at <= now_value:
                self._tokens.pop(token, None)
        while len(self._tokens) >= self.settings.project_import_max_previews:
            self._tokens.popitem(last=False)

    def preview(self, body: CompositionPreviewRequest, actor: Actor) -> CompositionPreview:
        principal = author_principal(actor)
        destination = Path(self.settings.specs_dir).absolute() / body.destination_slug
        if destination.exists() or destination.is_symlink():
            raise ProjectImportError("project_exists", "A managed project already exists with this destination slug.", status_code=409)
        scan = self._scan(body)
        token = secrets.token_urlsafe(32)
        expires_at = self.clock() + self.settings.project_import_preview_ttl_seconds
        with self._lock:
            self._prune()
            self._tokens[token] = _CompositionToken(
                actor_key=principal,
                body=body,
                manifest_digest=scan.manifest_digest,
                project_revision=scan.project_revision,
                expires_at=expires_at,
            )
        return CompositionPreview(
            can_create=True,
            preview_token=token,
            destination_slug=body.destination_slug,
            project_name=scan.project_name,
            project_revision=scan.project_revision,
            manifest_digest=scan.manifest_digest,
            sources=body.sources,
            provenance=scan.provenance,
            diagnostics=[],
            expires_at=datetime.fromtimestamp(expires_at, timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    @staticmethod
    def _write_file(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name != "nt":
            os.chmod(path, 0o644)

    def create(self, body: CompositionCreateRequest, actor: Actor) -> CompositionCreateResponse:
        principal = author_principal(actor)
        with self._lock:
            self._prune()
            record = self._tokens.pop(body.preview_token, None)
        if record is None:
            raise ProjectImportError("preview_expired", "Composition preview expired or was already used.", status_code=409)
        if record.actor_key != principal:
            raise ProjectImportError("preview_owner_mismatch", "Composition preview belongs to another OIDC subject.", status_code=403)
        if body.destination_slug != record.body.destination_slug or body.confirmation != body.destination_slug:
            raise ProjectImportError("preview_destination_mismatch", "Destination or confirmation changed after preview.", status_code=409)
        if body.project_revision != record.project_revision:
            raise ProjectImportError("stale_preview", "Composition revision changed; preview it again.", status_code=409)
        scan = self._scan(record.body)
        if scan.manifest_digest != record.manifest_digest or scan.project_revision != record.project_revision:
            raise ProjectImportError("stale_preview", "A composition source changed; preview it again.", status_code=409)
        root = Path(self.settings.specs_dir).absolute()
        root.mkdir(parents=True, exist_ok=True)
        destination = root / body.destination_slug
        if destination.exists() or destination.is_symlink():
            raise ProjectImportError("project_exists", "A managed project already exists with this destination slug.", status_code=409)
        stage = Path(tempfile.mkdtemp(prefix=".project_composition_", dir=root))
        published = False
        ownership_claimed = False
        try:
            for path, data in sorted(scan.contents.items()):
                self._write_file(stage.joinpath(*PurePosixPath(path).parts), data)
            for current, directories, _files in os.walk(stage):
                if os.name != "nt":
                    os.chmod(current, 0o755)
                directories.sort()
            atomic_publish_noreplace(stage, destination)
            published = True
            self.builder.claim_created_project(actor, body.destination_slug, scan.project_revision)
            ownership_claimed = True
            actual_revision = self.builder.inventory(actor, body.destination_slug).project_revision
            if actual_revision != scan.project_revision:
                raise ProjectImportError("published_revision_mismatch", "Published candidate did not match the reviewed manifest.", status_code=500)
        except BaseException:
            if published and destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination, ignore_errors=True)
            if ownership_claimed:
                self.builder.unclaim_created_project_if_eligible(
                    actor, body.destination_slug, scan.project_revision
                )
            raise
        finally:
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
        self.builder._ledger(actor, body.destination_slug, "create-composed-project", "project-write", scan.project_revision, "created", count=len(scan.contents))
        return CompositionCreateResponse(
            destination_slug=body.destination_slug,
            project_name=scan.project_name,
            project_revision=scan.project_revision,
            manifest_digest=scan.manifest_digest,
            included_file_count=len(scan.contents),
            message="Created a new managed candidate project; no existing project was merged or overwritten.",
        )
