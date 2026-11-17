"""Focused, target-free regression coverage for the R3 relay/manual repair."""

from __future__ import annotations

import yaml

from dashboard.authoring import (
    LocalAppTarget,
    ProjectDocument,
    SpecDocument,
    TypedProjectCreateRequest,
)
from dashboard.editor_routes import _prepare_typed_project_create


def test_default_managed_manual_is_portable_and_resolves_to_runtime(tmp_path, monkeypatch):
    specs_root = tmp_path / "runtime" / "tests_specs"
    manuals_root = tmp_path / "runtime" / "tests_manuals"
    monkeypatch.setenv("DASHBOARD_SPECS_DIR", str(specs_root))
    monkeypatch.setenv("TESTS_MANUALS_DIR", str(manuals_root))

    body = TypedProjectCreateRequest(
        document=ProjectDocument(
            dir_name="portable-typed",
            display_name="Portable Typed",
            enabled=True,
            schedule="0 4 * * *",
            target=LocalAppTarget(app="xterm -T typed", window="typed"),
            max_steps=30,
            max_seconds=1800,
        ),
        initial_spec=SpecDocument(
            path="000-first.md",
            title="First typed test",
            goal="Verify the initial workspace.",
            assertions=["A visible initial state is present."],
        ),
    )

    (
        observed_specs_root,
        project_dir,
        observed_manuals_root,
        manual_dir,
        document,
        yaml_content,
        _spec_content,
        _diagnostics,
    ) = _prepare_typed_project_create(body)

    assert observed_specs_root == str(specs_root)
    assert project_dir == str(specs_root / "portable-typed")
    assert observed_manuals_root == str(manuals_root)
    assert manual_dir == str(manuals_root / "portable-typed")
    assert document.manual_dir == "tests_manuals/portable-typed"
    assert yaml.safe_load(yaml_content)["manual_dir"] == "tests_manuals/portable-typed"
