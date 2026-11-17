from __future__ import annotations

import os
import re
import shutil
import tempfile

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from typing import Annotated

from .auth import verify_operator, verify_viewer
from .project_access import (
    ensure_manual_directory,
    ensure_manual_file,
    ensure_report_project,
    ensure_spec_directory,
    ensure_spec_file,
    normalize_spec_project,
)
from .models import (
    ProjectCloneModel,
    ProjectConfigModel,
    ProjectCreateModel,
    ProjectUpdateModel,
    SpecContentModel,
    SpecFileModel,
    TargetModel,
)
from .authoring import (
    _authoring_manual_directory,
    AuthoringSpecSummary,
    AuthoringDiagnostic,
    AuthoringValidationError,
    LocalAppTarget,
    ProjectApplyRequest,
    ProjectAuthoringResponse,
    ProjectDocument,
    ProjectValidateRequest,
    SpecApplyRequest,
    SpecAuthoringResponse,
    SpecCreateRequest,
    SpecDocument,
    SpecPreviewResponse,
    SpecValidateRequest,
    TypedProjectCreateRequest,
    TypedProjectCreatePreviewResponse,
    content_revision,
    default_manual_template,
    lint_project_document,
    parse_project_document,
    parse_spec_document,
    render_project_yaml,
    validate_project_for_apply,
    validate_spec_for_apply,
)

from .builder_policy import BuilderValidationRoute, review_diagnostics, trust_diagnostics

router = APIRouter(route_class=BuilderValidationRoute)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _specs_root():
    # DASHBOARD_SPECS_DIR is the host-side source of truth. Keep the older
    # TESTS_SPECS_DIR override working for existing deployments and tests.
    from .config import settings
    value = (
        os.environ.get("DASHBOARD_SPECS_DIR")
        or os.environ.get("TESTS_SPECS_DIR")
        or settings.specs_dir
    )
    return os.path.abspath(value)


def _reports_root():
    """Return the reports directory so new projects appear in the sidebar."""
    from .config import settings
    return os.path.abspath(settings.reports_dir)


def _project_dir(specs_root, dir_name):
    p = os.path.join(specs_root, dir_name)
    if not os.path.isdir(p):
        raise HTTPException(status_code=404, detail=f"Project directory {dir_name} not found.")
    return p


def _safe_spec_path(project_dir, rel):
    rel = rel.lstrip("/")
    full = os.path.realpath(os.path.join(project_dir, rel))
    if not full.startswith(os.path.realpath(project_dir) + os.sep):
        raise HTTPException(status_code=400, detail="Path escapes project directory.")
    return full


def _read_project_yaml(project_dir):
    p = os.path.join(project_dir, "project.yaml")
    if not os.path.isfile(p):
        return {}, ""
    raw = open(p, encoding="utf-8").read()
    return yaml.safe_load(raw) or {}, raw


def _write_atomic(path, content):
    d = os.path.dirname(path) or "."
    ensure_spec_directory(d)
    fd, tmp = tempfile.mkstemp(prefix=".edit_", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
        ensure_spec_file(path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _authoring_error(exc: AuthoringValidationError) -> HTTPException:
    """Keep API failures structured without reflecting source or secret contents."""
    return HTTPException(
        status_code=422,
        detail={"diagnostics": [item.model_dump() for item in exc.diagnostics]},
    )


def _authoring_project(name: str):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    yaml_path = os.path.join(project_dir, "project.yaml")
    if not os.path.isfile(yaml_path):
        raise HTTPException(status_code=404, detail="Project has no project.yaml to author.")
    raw = open(yaml_path, encoding="utf-8").read()
    try:
        parsed = parse_project_document(raw, dir_name=dir_name)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return dir_name, project_dir, yaml_path, raw, parsed


def _assert_project_document_matches(
    document: ProjectDocument,
    *,
    dir_name: str,
    existing_legacy: dict,
) -> None:
    diagnostics: list[AuthoringDiagnostic] = []
    if document.dir_name != dir_name:
        diagnostics.append(AuthoringDiagnostic(
            code="project_identity", message="The document directory slug does not match the selected project.", field="dir_name"
        ))
    if document.legacy != existing_legacy:
        diagnostics.append(AuthoringDiagnostic(
            code="legacy_changed", message="Legacy YAML data is read-only until explicitly migrated; it must be preserved unchanged.", field="legacy"
        ))
    if diagnostics:
        raise AuthoringValidationError(diagnostics)


def _assert_spec_path(document: SpecDocument, path: str) -> None:
    if document.path != path:
        raise AuthoringValidationError([AuthoringDiagnostic(
            code="spec_identity", message="The document path does not match the selected spec.", field="path"
        )])


def _prepare_typed_project_create(body: TypedProjectCreateRequest):
    """Validate a guided project create request without changing disk state.

    The form deliberately omits ``manual_dir``.  Resolving it server-side
    keeps managed host paths out of the browser while retaining Phase 13A's
    scope and atomic-bootstrap guarantees for API callers that still provide
    an explicit managed path.
    """
    root = _specs_root()
    if body.builder_review is not None:
        review_errors = review_diagnostics(body.document, [body.initial_spec, *body.additional_specs],
                                          body.manual_outline, body.builder_goal, body.builder_review)
        review_errors.extend(trust_diagnostics(body.document, body.trust_review))
        if body.document.enabled:
            review_errors.append(dict(code='new_project_disabled',
                message='Create this reviewed project disabled; scheduling requires a later decision.',
                field='enabled', severity='error'))
        if not body.manual_template or 'Add reviewed operating guidance' in body.manual_template:
            review_errors.append(dict(code='manual_unfinished', message='Provide the reviewed operating manual before creation.',
                                      field='manual_outline', severity='error'))
        review_errors = [item for item in review_errors if item["severity"] == "error"]
        if review_errors:
            raise _authoring_error(AuthoringValidationError([AuthoringDiagnostic(**item) for item in review_errors]))
    seen = {body.initial_spec.path}
    for index, spec in enumerate(body.additional_specs, 1):
        if spec.path in seen:
            raise _authoring_error(AuthoringValidationError([AuthoringDiagnostic(
                code='spec_path_duplicate', message='Every planned specification path must be unique.',
                field=f'specifications[{index}].path')]))
        seen.add(spec.path)
        try:
            validate_spec_for_apply(spec)
        except AuthoringValidationError as exc:
            indexed = [item.model_copy(update={'field': f'specifications[{index}].{item.field or "document"}'})
                       for item in exc.diagnostics]
            raise _authoring_error(AuthoringValidationError(indexed)) from exc
    manual_root = os.path.abspath(os.environ.get("TESTS_MANUALS_DIR", "tests_manuals"))
    document = body.document
    if not document.manual_dir:
        document = document.model_copy(update={
            "manual_dir": f"tests_manuals/{document.dir_name}",
        })
    project_dir = os.path.join(root, document.dir_name)
    manual_dir = _authoring_manual_directory(document)
    try:
        if os.path.commonpath((manual_root, manual_dir)) != manual_root:
            raise AuthoringValidationError([AuthoringDiagnostic(
                code="manual_dir_scope", message="New project manuals must be managed below TESTS_MANUALS_DIR.", field="manual_dir"
            )])
        if body.initial_spec.path == "project.yaml":
            raise AuthoringValidationError([AuthoringDiagnostic(
                code="spec_path", message="Initial spec may not be project.yaml.", field="initial_spec.path"
            )])
        document, yaml_content, project_diagnostics = validate_project_for_apply(
            document,
            require_manual_on_disk=False,
            require_schedule=True,
            new_project=True,
        )
        spec_content, spec_diagnostics = validate_spec_for_apply(body.initial_spec)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return (
        root,
        project_dir,
        manual_root,
        manual_dir,
        document,
        yaml_content,
        spec_content,
        [*project_diagnostics, *spec_diagnostics],
    )


def _parse_spec_title(text):
    for line in text.splitlines():
        m = re.match(r"^#\s+(.*)", line)
        if m:
            title = re.sub(r"^test\s*:\s*", "", m.group(1), flags=re.IGNORECASE).strip()
            return title, ""
    return "", "missing # title"


def _collect_specs(project_dir):
    paths = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [name for name in dirs if name != "manual"]
        for f in files:
            if f.endswith(".md"):
                rel = os.path.relpath(os.path.join(root, f), project_dir)
                if not rel.startswith("."):
                    paths.append(rel)
    return sorted(paths)


def _dir_name_from_display(specs_root, name):
    for entry in os.listdir(specs_root):
        d = os.path.join(specs_root, entry)
        if not os.path.isdir(d):
            continue
        data, _ = _read_project_yaml(d)
        if str(data.get("name", entry)) == name or entry == name:
            return entry
    raise HTTPException(status_code=404, detail=f"Project {name} not found.")


# ---------------------------------------------------------------------------
# Config routes
# ---------------------------------------------------------------------------

@router.get("/projects/{name}/config")
def get_project_config(name: str, _u=Depends(verify_viewer)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    data, raw = _read_project_yaml(project_dir)
    target_raw = data.pop("target", {}) or {}
    target = TargetModel(
        type=str(target_raw.get("type", "local-app")),
        params={k: str(v) for k, v in target_raw.items() if k != "type"},
    )
    return ProjectConfigModel(
        dir_name=dir_name,
        name=str(data.get("name", dir_name)),
        enabled=bool(data.get("enabled", True)),
        schedule=str(data.get("schedule", "0 3 * * *")),
        manual_dir=str(data.get("manual_dir", "")),
        target=target,
        ssh_host_allowlist=list(data.get("ssh_host_allowlist", [])),
        rdp_host_allowlist=list(data.get("rdp_host_allowlist", [])),
        vnc_host_allowlist=list(data.get("vnc_host_allowlist", [])),
        max_steps=int(data.get("max_steps", 30)),
        max_seconds=int(data.get("max_seconds", 1800)),
        raw_yaml=raw,
    )


@router.put("/projects/{name}/config")
def update_project_config(name: str, body: ProjectUpdateModel, _u=Depends(verify_operator)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    try:
        parsed = yaml.safe_load(body.raw_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"YAML parse error: {exc}")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="project.yaml must be a YAML mapping.")
    # Retain the raw source route, but send clear semantic hazards through the
    # same parser as typed authoring. Historical projects may inherit schedule
    # and manual settings, so this compatibility path does not require an
    # existing manual on disk.
    try:
        authored = parse_project_document(body.raw_yaml, dir_name=dir_name)
        _normalised, diagnostics = lint_project_document(
            authored.document,
            require_manual_on_disk=False,
            require_schedule=False,
        )
        combined = [*authored.diagnostics, *diagnostics]
        if any(item.severity == "error" for item in combined):
            raise AuthoringValidationError(combined)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    _write_atomic(os.path.join(project_dir, "project.yaml"), body.raw_yaml)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Spec routes
# ---------------------------------------------------------------------------

@router.get("/projects/{name}/specs")
def list_project_specs(name: str, _u=Depends(verify_viewer)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    result = []
    for rel in _collect_specs(project_dir):
        full = os.path.join(project_dir, rel)
        size = os.path.getsize(full)
        text = open(full, encoding="utf-8").read()
        title, err = _parse_spec_title(text)
        result.append(SpecFileModel(path=rel, title=title or rel, size_bytes=size, parse_error=err or None))
    return result


@router.get("/projects/{name}/specs/{path:path}")
def get_spec_content(name: str, path: str, _u=Depends(verify_viewer)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    full = _safe_spec_path(project_dir, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"Spec file {path} not found.")
    text = open(full, encoding="utf-8").read()
    return SpecContentModel(project=name, rel_path=path, content=text, size_bytes=len(text.encode("utf-8")))


@router.put("/projects/{name}/specs/{path:path}")
def write_spec_file(
    name: str,
    path: str,
    content: Annotated[str, Body(media_type="text/plain")],
    _u=Depends(verify_operator),
):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    if not path.endswith(".md"):
        raise HTTPException(status_code=400, detail="Spec files must have a .md extension.")
    try:
        # Validation only: the raw route keeps its existing formatting while a
        # typed Apply renders canonical Markdown.
        parse_spec_document(content, path=path)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    full = _safe_spec_path(project_dir, path)
    _write_atomic(full, content)
    return {"status": "ok", "size_bytes": len(content.encode("utf-8"))}


@router.delete("/projects/{name}/specs/{path:path}")
def delete_spec_file(name: str, path: str, _u=Depends(verify_operator)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    full = _safe_spec_path(project_dir, path)
    if os.path.basename(full) == "project.yaml":
        raise HTTPException(status_code=400, detail="project.yaml cannot be deleted via this endpoint.")
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"Spec file {path} not found.")
    os.remove(full)
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------

@router.post("/projects", status_code=201)
def create_project(body: ProjectCreateModel, _u=Depends(verify_operator)):
    """Retain the Phase 12 API while using the complete typed create transaction.

    The dashboard UI now uses the guided authoring flow, but older API clients
    still call this endpoint.  Its former implementation wrote a project and
    starter spec without creating the required manual, leaving a project that
    appeared in the sidebar but could never run.  Map the legacy local-app
    shape into the same atomic project/spec/manual operation used by the
    current UI.
    """

    root = _specs_root()
    dir_name = body.dir_name.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", dir_name):
        raise HTTPException(status_code=400, detail="dir_name must contain only letters, digits, hyphens, and underscores.")
    project_dir = os.path.join(root, dir_name)
    if os.path.exists(project_dir):
        raise HTTPException(status_code=409, detail=f"Directory {dir_name} already exists.")
    display_name = body.display_name or dir_name
    target_type = body.target_type or "local-app"
    if target_type != "local-app":
        raise HTTPException(
            status_code=422,
            detail=(
                "The compatibility create endpoint supports local-app only; use the guided "
                "project builder for SSH, RDP, or VNC targets."
            ),
        )
    target_app = body.target_app or (
        f"/usr/bin/xmessage -center -title {dir_name} "
        "-buttons OK:0 -default OK Ready"
    )
    target_window = body.target_window or dir_name
    schedule = body.schedule or "0 3 * * *"
    request = TypedProjectCreateRequest(
        document=ProjectDocument(
            dir_name=dir_name,
            display_name=display_name,
            schedule=schedule,
            manual_dir=body.manual_dir or None,
            target=LocalAppTarget(app=target_app, window=target_window),
            max_steps=30,
            max_seconds=1800,
        ),
        initial_spec=SpecDocument(
            path="000-first-test.md",
            title=f"{display_name} - first test",
            goal="Describe what the agent should accomplish in the target window.",
            setup="Describe any starting state the agent can rely on.",
            assertions=[
                "The first observable condition must hold.",
                "The second observable condition must hold.",
            ],
        ),
    )
    return create_authoring_project(request, _u)


@router.delete("/projects/{name}")
def disable_project(name: str, _u=Depends(verify_operator)):
    root = _specs_root()
    dir_name = _dir_name_from_display(root, name)
    project_dir = _project_dir(root, dir_name)
    _, raw = _read_project_yaml(project_dir)
    if not raw.strip():
        raise HTTPException(status_code=422, detail="Cannot disable a project with no project.yaml.")
    if re.search(r"^enabled\s*:", raw, re.MULTILINE):
        new_raw = re.sub(r"^(enabled\s*:).*$", r"\g<1> false", raw, flags=re.MULTILINE)
    else:
        new_raw = raw.rstrip() + "\nenabled: false\n"
    _write_atomic(os.path.join(project_dir, "project.yaml"), new_raw)
    return {"status": "disabled"}


@router.post("/projects/{name}/clone")
def clone_project(name: str, body: ProjectCloneModel, _u=Depends(verify_operator)):
    root = _specs_root()
    src_dir_name = _dir_name_from_display(root, name)
    src_dir = _project_dir(root, src_dir_name)
    dst_dir_name = body.dir_name.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", dst_dir_name):
        raise HTTPException(status_code=400, detail="dir_name must contain only letters, digits, hyphens, and underscores.")
    dst_dir = os.path.join(root, dst_dir_name)
    if os.path.exists(dst_dir):
        raise HTTPException(status_code=409, detail=f"Directory {dst_dir_name} already exists.")
    shutil.copytree(src_dir, dst_dir)
    normalize_spec_project(dst_dir)
    display_name = (body.display_name or "").strip() or dst_dir_name
    _, raw = _read_project_yaml(dst_dir)
    if raw:
        if re.search(r"^name\s*:", raw, re.MULTILINE):
            new_raw = re.sub(r"^(name\s*:).*$", f"\\g<1> {display_name}", raw, flags=re.MULTILINE)
        else:
            new_raw = f"name: {display_name}\n" + raw
        _write_atomic(os.path.join(dst_dir, "project.yaml"), new_raw)
    # Ensure the project directory exists in reports/ so it appears in the sidebar.
    ensure_report_project(_reports_root(), dst_dir_name)
    return {"status": "created", "dir_name": dst_dir_name}


# ---------------------------------------------------------------------------
# Phase 13A typed authoring routes
# ---------------------------------------------------------------------------

@router.get("/projects/{name}/authoring", response_model=ProjectAuthoringResponse)
@router.get("/projects/{name}/authoring/project", response_model=ProjectAuthoringResponse)
def get_authoring_project(name: str, _u=Depends(verify_viewer)):
    """Read one typed project document plus diagnostics; this route never writes."""
    _dir, _project_dir_value, _path, raw, parsed = _authoring_project(name)
    document, lint_diagnostics = lint_project_document(
        parsed.document,
        require_manual_on_disk=True,
        require_schedule=False,
    )
    return ProjectAuthoringResponse(
        document=document,
        rendered_yaml=render_project_yaml(document),
        revision=content_revision(raw),
        diagnostics=[*parsed.diagnostics, *lint_diagnostics],
        inherited_fields=parsed.inherited_fields,
    )


@router.post("/projects/{name}/authoring/project/validate", response_model=ProjectAuthoringResponse)
def validate_authoring_project(name: str, body: ProjectValidateRequest, _u=Depends(verify_operator)):
    """Validate/render a typed project without modifying the filesystem."""
    dir_name, _project_dir_value, _path, raw, parsed = _authoring_project(name)
    try:
        _assert_project_document_matches(body.document, dir_name=dir_name, existing_legacy=parsed.document.legacy)
        document, rendered, diagnostics = validate_project_for_apply(
            body.document,
            require_manual_on_disk=True,
            require_schedule=True,
        )
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return ProjectAuthoringResponse(
        document=document,
        rendered_yaml=rendered,
        revision=content_revision(raw),
        diagnostics=[*parsed.diagnostics, *diagnostics],
        inherited_fields=parsed.inherited_fields,
    )


@router.put("/projects/{name}/authoring/project", response_model=ProjectAuthoringResponse)
@router.put("/projects/{name}/authoring", response_model=ProjectAuthoringResponse)
def apply_authoring_project(name: str, body: ProjectApplyRequest, _u=Depends(verify_operator)):
    """Compare-and-swap apply for a typed project document."""
    dir_name, _project_dir_value, yaml_path, raw, parsed = _authoring_project(name)
    current_revision = content_revision(raw)
    if body.base_revision != current_revision:
        raise HTTPException(status_code=409, detail={
            "code": "revision_conflict",
            "message": "project.yaml changed after this document was read.",
            "current_revision": current_revision,
        })
    try:
        _assert_project_document_matches(body.document, dir_name=dir_name, existing_legacy=parsed.document.legacy)
        document, rendered, diagnostics = validate_project_for_apply(
            body.document,
            require_manual_on_disk=True,
            require_schedule=True,
        )
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    _write_atomic(yaml_path, rendered)
    return ProjectAuthoringResponse(
        document=document,
        rendered_yaml=rendered,
        revision=content_revision(rendered),
        diagnostics=[*parsed.diagnostics, *diagnostics],
        inherited_fields=parsed.inherited_fields,
    )


@router.get("/projects/{name}/authoring/specs", response_model=list[AuthoringSpecSummary])
def list_authoring_specs(name: str, _u=Depends(verify_viewer)):
    """List selectable specs without falling back to the legacy editor API."""
    _dir_name, project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    summaries: list[AuthoringSpecSummary] = []
    for path in _collect_specs(project_dir):
        full = _safe_spec_path(project_dir, path)
        raw = open(full, encoding="utf-8").read()
        try:
            document = parse_spec_document(raw, path=path)
            _rendered, diagnostics = validate_spec_for_apply(document)
            summaries.append(AuthoringSpecSummary(
                path=path,
                title=document.title,
                diagnostics=diagnostics,
            ))
        except AuthoringValidationError as exc:
            # Preserve the selectable path and present structured diagnostics;
            # do not return raw Markdown from the list endpoint.
            title, _ignored = _parse_spec_title(raw)
            summaries.append(AuthoringSpecSummary(
                path=path,
                title=title or path,
                diagnostics=exc.diagnostics,
            ))
    return summaries


@router.post(
    "/projects/{name}/authoring/specs/validate",
    response_model=SpecPreviewResponse,
)
def validate_new_authoring_spec(
    name: str,
    body: SpecValidateRequest,
    _u=Depends(verify_operator),
):
    """Render a new spec before it is created; no file is opened for write."""
    _dir_name, _project_dir_value, _yaml_path, _raw, _parsed = _authoring_project(name)
    try:
        rendered, diagnostics = validate_spec_for_apply(body.document)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return SpecPreviewResponse(
        document=body.document,
        rendered_markdown=rendered,
        diagnostics=diagnostics,
    )


@router.post(
    "/projects/{name}/authoring/specs",
    status_code=201,
    response_model=SpecAuthoringResponse,
)
def create_authoring_spec(
    name: str,
    body: SpecCreateRequest,
    _u=Depends(verify_operator),
):
    """Create one validated typed spec without using the raw Markdown route."""
    _dir_name, project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    try:
        rendered, diagnostics = validate_spec_for_apply(body.document)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    full = _safe_spec_path(project_dir, body.document.path)
    if os.path.exists(full):
        raise HTTPException(status_code=409, detail={
            "code": "spec_exists",
            "message": "A specification already exists at this path.",
        })
    _write_atomic(full, rendered)
    return SpecAuthoringResponse(
        document=body.document,
        rendered_markdown=rendered,
        revision=content_revision(rendered),
        diagnostics=diagnostics,
    )


@router.get("/projects/{name}/authoring/specs/{path:path}", response_model=SpecAuthoringResponse)
def get_authoring_spec(name: str, path: str, _u=Depends(verify_viewer)):
    _dir_name, project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    full = _safe_spec_path(project_dir, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"Spec file {path} not found.")
    raw = open(full, encoding="utf-8").read()
    try:
        document = parse_spec_document(raw, path=path)
        rendered, diagnostics = validate_spec_for_apply(document)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return SpecAuthoringResponse(
        document=document,
        rendered_markdown=rendered,
        revision=content_revision(raw),
        diagnostics=diagnostics,
    )


@router.post("/projects/{name}/authoring/specs/{path:path}/validate", response_model=SpecAuthoringResponse)
def validate_authoring_spec(name: str, path: str, body: SpecValidateRequest, _u=Depends(verify_operator)):
    _dir_name, project_dir, _yaml_path, _raw, _parsed = _authoring_project(name)
    full = _safe_spec_path(project_dir, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"Spec file {path} not found.")
    raw = open(full, encoding="utf-8").read()
    try:
        _assert_spec_path(body.document, path)
        rendered, diagnostics = validate_spec_for_apply(body.document)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    return SpecAuthoringResponse(
        document=body.document,
        rendered_markdown=rendered,
        revision=content_revision(raw),
        diagnostics=diagnostics,
    )


@router.put("/projects/{name}/authoring/specs/{path:path}", response_model=SpecAuthoringResponse)
def apply_authoring_spec(name: str, path: str, body: SpecApplyRequest, request: Request, _u=Depends(verify_operator)):
    _dir_name, project_dir, _yaml_path, _project_raw, _parsed = _authoring_project(name)
    full = _safe_spec_path(project_dir, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"Spec file {path} not found.")
    raw = open(full, encoding="utf-8").read()
    current_revision = content_revision(raw)
    if body.base_revision != current_revision:
        raise HTTPException(status_code=409, detail={
            "code": "revision_conflict",
            "message": "Spec changed after this document was read.",
            "current_revision": current_revision,
        })
    try:
        _assert_spec_path(body.document, path)
        rendered, diagnostics = validate_spec_for_apply(body.document)
    except AuthoringValidationError as exc:
        raise _authoring_error(exc) from exc
    _write_atomic(full, rendered)
    response = SpecAuthoringResponse(
        document=body.document,
        rendered_markdown=rendered,
        revision=content_revision(rendered),
        diagnostics=diagnostics,
    )
    # Provenance is deliberately post-write and best-effort: a private-audit
    # fault must never turn a valid established Phase 13A CAS Apply into a
    # partial failure or a second write path.
    service = getattr(request.app.state, "refinement_service", None)
    if service is not None:
        try:
            service.link_apply(
                proposal_id=body.refinement_proposal_id,
                spec_path=path,
                base_revision=body.base_revision,
                resulting_revision=response.revision,
            )
        except Exception:
            pass
    return response


@router.post(
    "/projects/authoring/validate",
    response_model=TypedProjectCreatePreviewResponse,
)
def validate_authoring_project_create(
    body: TypedProjectCreateRequest,
    _u=Depends(verify_operator),
):
    """Validate a guided project and its first spec without creating files."""
    (
        _root,
        project_dir,
        _manual_root,
        manual_dir,
        document,
        yaml_content,
        spec_content,
        diagnostics,
    ) = _prepare_typed_project_create(body)
    if os.path.exists(project_dir):
        raise HTTPException(status_code=409, detail={
            "code": "project_exists",
            "message": "A project directory already exists with this slug.",
        })
    if os.path.exists(manual_dir):
        raise HTTPException(status_code=409, detail={
            "code": "manual_exists",
            "message": "A managed manual already exists for this project slug.",
        })
    return TypedProjectCreatePreviewResponse(
        document=document,
        initial_spec=body.initial_spec,
        rendered_yaml=yaml_content,
        rendered_markdown=spec_content,
        diagnostics=diagnostics,
    )


@router.post("/projects/authoring", status_code=201)
def create_authoring_project(body: TypedProjectCreateRequest, _u=Depends(verify_operator)):
    """Create a complete typed project, initial spec, and master manual.

    Each final directory is prepared in a same-parent staging directory and
    renamed into place.  No existing project or manual directory is replaced.
    """
    (
        root,
        project_dir,
        manual_root,
        manual_dir,
        document,
        yaml_content,
        spec_content,
        diagnostics,
    ) = _prepare_typed_project_create(body)
    if os.path.exists(project_dir):
        raise HTTPException(status_code=409, detail="Project directory already exists.")
    if os.path.exists(manual_dir):
        raise HTTPException(status_code=409, detail="Managed manual directory already exists.")

    ensure_spec_directory(root)
    ensure_manual_directory(manual_root)
    project_stage = tempfile.mkdtemp(prefix=".authoring_project_", dir=root)
    manual_stage_parent = os.path.dirname(manual_dir)
    ensure_manual_directory(manual_stage_parent)
    manual_stage = tempfile.mkdtemp(prefix=".authoring_manual_", dir=manual_stage_parent)
    project_created = False
    try:
        _write_atomic(os.path.join(project_stage, "project.yaml"), yaml_content)
        _write_atomic(os.path.join(project_stage, body.initial_spec.path), spec_content)
        for spec in body.additional_specs:
            rendered_spec, _ = validate_spec_for_apply(spec)
            _write_atomic(os.path.join(project_stage, spec.path), rendered_spec)
        manual_content = body.manual_template or default_manual_template(document.display_name)
        manual_file = os.path.join(manual_stage, "manual.md")
        with open(manual_file, "w", encoding="utf-8") as fh:
            fh.write(manual_content.rstrip() + "\n")
        ensure_manual_file(manual_file)
        ensure_manual_directory(manual_stage)
        os.replace(project_stage, project_dir)
        project_created = True
        os.replace(manual_stage, manual_dir)
    except BaseException:
        # Roll back only exact directories created in this request; all
        # pre-existing targets were rejected before staging began.
        if project_created and os.path.isdir(project_dir):
            shutil.rmtree(project_dir)
        if os.path.isdir(project_stage):
            shutil.rmtree(project_stage)
        if os.path.isdir(manual_stage):
            shutil.rmtree(manual_stage)
        raise
    ensure_report_project(_reports_root(), document.dir_name)
    return {
        "status": "created",
        "dir_name": document.dir_name,
        "display_name": document.display_name,
        "project_revision": content_revision(yaml_content),
        "spec_revision": content_revision(spec_content),
        "diagnostics": [item.model_dump() for item in diagnostics],
        "manual_bootstrap": "created",
        "created_specifications": [body.initial_spec.path, *(spec.path for spec in body.additional_specs)],
    }
