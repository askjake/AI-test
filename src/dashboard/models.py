"""Dashboard-local Pydantic response models (Phase 10).

These are distinct from orchestrator.models — the dashboard has no import
dependency on the agent codebase.  Field names mirror the equivalent
orchestrator.models fields where they overlap so Phase 11 integration is
semantically obvious.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RunSummaryModel(BaseModel):
    """Summary of one completed (or in-progress) run, sourced from run.json."""

    project: str
    run_ts: str
    model_id: str | None = None
    total: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    spec_total: int = 0
    duration_seconds: float = 0.0
    state: str | None = None
    report_href: str | None = None  # relative URL to report.html


class ProjectSummaryModel(BaseModel):
    """One project entry in the project list response."""

    name: str
    run_count: int
    latest: RunSummaryModel | None = None
    index_href: str  # relative URL to the project's index.html


class RunStatusModel(BaseModel):
    """Live status of an in-progress or completed run (from status.json)."""

    state: str  # "running" | "complete" | "error" | "cancelled"
    current_spec: str | None = None
    current_spec_index: int = 0
    specs_total: int = 0
    specs_completed: list[dict[str, Any]] = []
    started_at: str | None = None
    # Internal: evidence subdir for the active spec (relative to run dir).
    # Used by the SSE live endpoint; not exposed in API responses.
    current_evidence_dir: str | None = None


class SearchResultModel(BaseModel):
    """One run returned by the search/filter endpoint."""

    project: str
    run_ts: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    duration_seconds: float = 0.0
    report_href: str


class TriggerResponseModel(BaseModel):
    """Response returned by POST /api/v1/projects/{name}/runs (Phase 11)."""

    trigger_id: str
    project: str
    status: str   # "queued" | "busy" | "error"
    ctrl_file: str  # relative path of the trigger file written
    message: str


class CancelRunResponseModel(BaseModel):
    """Durable result returned after stopping one project's active run."""

    project: str
    status: str  # "cancelled"
    trigger_id: str
    run_ts: str | None = None
    message: str


# ── Phase 12: project editor models ──────────────────────────────────────────

class TargetModel(BaseModel):
    type: str = "local-app"
    params: dict[str, str] = {}


class ProjectConfigModel(BaseModel):
    """Parsed, editable representation of a project.yaml (Phase 12)."""
    dir_name: str                         # filesystem directory name (not the display name)
    name: str                             # display name from project.yaml or dir_name
    enabled: bool = True
    schedule: str = "0 3 * * *"
    manual_dir: str = ""
    target: TargetModel = TargetModel()
    ssh_host_allowlist: list[str] = []
    rdp_host_allowlist: list[str] = []
    vnc_host_allowlist: list[str] = []
    max_steps: int = 30
    max_seconds: int = 1800
    raw_yaml: str = ""                    # full raw text of the project.yaml file


class SpecFileModel(BaseModel):
    """Metadata for one spec file inside a project (Phase 12)."""
    path: str          # path relative to project dir (e.g. "010-login.md")
    title: str         # parsed title from the spec, or filename if unparsable
    size_bytes: int
    parse_error: str | None = None


class SpecContentModel(BaseModel):
    """Full content of a single spec file (Phase 12)."""
    project: str
    rel_path: str      # path relative to project dir
    content: str       # raw Markdown text
    size_bytes: int


class ProjectCreateModel(BaseModel):
    """Request body for POST /api/v1/projects (Phase 12)."""
    dir_name: str                         # new directory name (slug, no spaces)
    display_name: str = ""
    target_type: str = "local-app"
    target_app: str = ""
    target_window: str = ""
    schedule: str = "0 3 * * *"
    manual_dir: str = ""


class ProjectUpdateModel(BaseModel):
    """Request body for PUT /api/v1/projects/{name}/config (Phase 12)."""
    raw_yaml: str      # caller sends the full YAML text; server validates and writes it


class ProjectCloneModel(BaseModel):
    """Body for POST /projects/{name}/clone."""
    dir_name: str
    display_name: str = ""
