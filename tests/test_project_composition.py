from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from dashboard.auth import Actor
from dashboard.author_builder import AuthorBuilderService
from dashboard.config import DashboardSettings, ProjectImportRootSetting
from dashboard.project_composition import (
    CompositionCreateRequest,
    CompositionPreviewRequest,
    CompositionSource,
    ProjectCompositionService,
)
from dashboard.project_import import ProjectImportError, ProjectImportService


PROJECT = """\
name: Composed Project
enabled: true
schedule: 0 3 * * *
manual_dir: ./old-manual
target:
  type: local-app
  app: xterm
  window: xterm
ssh_host_allowlist: []
rdp_host_allowlist: []
vnc_host_allowlist: []
"""
SPEC = "# Test: Smoke\n\n## Goal\nOpen the application.\n\n## Assertions\n- The application is visible.\n"


def actor(name="alice"):
    return Actor(subject=f"oidc:{name}", role="operator", auth_method="oidc")


def setup(tmp_path: Path):
    meta = tmp_path / "meta"
    specs = tmp_path / "extra-specs"
    manual = tmp_path / "manual"
    assets = tmp_path / "assets"
    managed = tmp_path / "managed"
    for path in (meta, specs, manual, assets, managed):
        path.mkdir()
    (meta / "project.yaml").write_text(PROJECT, encoding="utf-8")
    (specs / "001-smoke.md").write_text(SPEC, encoding="utf-8")
    (manual / "manual.md").write_text("# Operating manual\n", encoding="utf-8")
    (assets / "screen.png").write_bytes(b"safe-image-placeholder")
    settings = DashboardSettings(
        specs_dir=str(managed), reports_dir=str(tmp_path / "reports"),
        secrets_dir=str(tmp_path / "secrets"),
        author_builder_state_root=str(tmp_path / "builder"),
        project_import_roots=(
            ProjectImportRootSetting(id="meta", label="Metadata", path=str(meta)),
            ProjectImportRootSetting(id="specs", label="Specifications", path=str(specs)),
            ProjectImportRootSetting(id="manual", label="Manual", path=str(manual)),
            ProjectImportRootSetting(id="assets", label="Assets", path=str(assets)),
        ),
    )
    builder = AuthorBuilderService(settings)
    imports = ProjectImportService(settings)
    composition = ProjectCompositionService(settings, imports, builder)
    request = CompositionPreviewRequest(destination_slug="composed", sources=[
        CompositionSource(root_id="meta", role="project-spec"),
        CompositionSource(root_id="specs", role="specs"),
        CompositionSource(root_id="manual", role="manual-root"),
        CompositionSource(root_id="assets", role="assets", destination_subdir="ui"),
    ])
    return settings, builder, composition, request


def test_multi_root_preview_is_deterministic_and_create_is_new_owner_scoped_project(tmp_path):
    settings, builder, composition, request = setup(tmp_path)
    preview = composition.preview(request, actor())
    destination = Path(settings.specs_dir) / "composed"
    assert preview.status == "preview-only-no-files-copied"
    assert not destination.exists()
    assert [item.destination_path for item in preview.provenance] == sorted(
        item.destination_path for item in preview.provenance
    )
    assert {item.destination_path for item in preview.provenance} == {
        "project.yaml", "specs/001-smoke.md", "manual/manual.md", "manual/assets/ui/screen.png"
    }

    result = composition.create(CompositionCreateRequest(
        preview_token=preview.preview_token,
        destination_slug="composed",
        project_revision=preview.project_revision,
        confirmation="composed",
    ), actor())
    assert result.status == "candidate-project-created"
    assert destination.is_dir()
    assert "manual_dir: ./manual" in (destination / "project.yaml").read_text(encoding="utf-8")
    assert builder.inventory(actor(), "composed").project_revision == preview.project_revision
    with pytest.raises(Exception):
        builder.inventory(actor("bob"), "composed")


def test_composition_rejects_existing_destination_and_stale_source(tmp_path):
    settings, _builder, composition, request = setup(tmp_path)
    preview = composition.preview(request, actor())
    (Path(settings.project_import_roots[1].path) / "001-smoke.md").write_text(SPEC + "\n", encoding="utf-8")
    with pytest.raises(ProjectImportError, match="changed"):
        composition.create(CompositionCreateRequest(
            preview_token=preview.preview_token,
            destination_slug="composed",
            project_revision=preview.project_revision,
            confirmation="composed",
        ), actor())

    (Path(settings.specs_dir) / "taken").mkdir()
    taken = request.model_copy(update={"destination_slug": "taken"})
    with pytest.raises(ProjectImportError) as exists:
        composition.preview(taken, actor())
    assert exists.value.code == "project_exists"


def test_composition_rejects_symlink_duplicate_destination_and_missing_master_manual(tmp_path):
    settings, _builder, composition, request = setup(tmp_path)
    specs_root = Path(settings.project_import_roots[1].path)
    (specs_root / "link.md").symlink_to(specs_root / "001-smoke.md")
    with pytest.raises(ProjectImportError, match="symbolic link"):
        composition.preview(request, actor())
    (specs_root / "link.md").unlink()

    duplicate = request.model_copy(update={"sources": [
        *request.sources,
        CompositionSource(root_id="specs", role="specs"),
    ]})
    with pytest.raises(ProjectImportError):
        composition.preview(duplicate, actor())

    (Path(settings.project_import_roots[2].path) / "manual.md").unlink()
    with pytest.raises(ProjectImportError) as missing:
        composition.preview(request, actor())
    assert missing.value.code == "master_manual_missing"


def test_composition_rolls_back_owner_claim_when_published_revision_mismatches(tmp_path, monkeypatch):
    settings, builder, composition, request = setup(tmp_path)
    preview = composition.preview(request, actor())
    monkeypatch.setattr(
        builder,
        "inventory",
        lambda *_args, **_kwargs: SimpleNamespace(project_revision="f" * 64),
    )
    with pytest.raises(ProjectImportError) as mismatch:
        composition.create(CompositionCreateRequest(
            preview_token=preview.preview_token,
            destination_slug="composed",
            project_revision=preview.project_revision,
            confirmation="composed",
        ), actor())
    assert mismatch.value.code == "published_revision_mismatch"
    assert not (Path(settings.specs_dir) / "composed").exists()
    assert "composed" not in builder._read_grants()
