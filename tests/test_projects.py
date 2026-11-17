"""Phase 5 tests for orchestrator.projects (P5-6..P5-9)."""

from __future__ import annotations

import textwrap

import pytest

from orchestrator.projects import (
    ManualError,
    discover_projects,
    find_project,
    load_manual,
    load_manual_page,
    load_project_config,
    project_slug,
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


def _mk_manual(tmp_path, name):
    """Create a manual dir (with a master manual.md) OUTSIDE the specs root and return its path.

    manual_dir is a required project.yaml field, resolved relative to the cwd; tests use an
    absolute path so it resolves regardless of where pytest runs from. It must live outside the
    specs root (a sibling of tmp_path) so discovery doesn't treat the manual dir as a project.
    """
    d = tmp_path.with_name(tmp_path.name + "-manuals") / name
    _write(d / "manual.md", "MASTER")
    return str(d)


def test_discover_projects_per_subdir(tmp_path):
    """P5-6: each immediate sub-dir is a project; specs collected recursively."""
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "checkout" / "nested" / "b.md", "# Test: b\n## Goal\nG\n")
    _write(tmp_path / "backups" / "c.md", "# Test: c\n## Goal\nG\n")
    _write(tmp_path / "checkout" / "project.yaml", f"manual_dir: {_mk_manual(tmp_path, 'checkout')}\n")
    _write(tmp_path / "backups" / "project.yaml", f"manual_dir: {_mk_manual(tmp_path, 'backups')}\n")

    projects = {p.name: p for p in discover_projects(str(tmp_path))}
    assert set(projects) == {"checkout", "backups"}
    assert len(projects["checkout"].specs) == 2  # recursive
    assert len(projects["backups"].specs) == 1


def test_root_specs_become_default_project(tmp_path):
    """P5-7: a *.md directly in the root forms the implicit default project."""
    _write(tmp_path / "loose.md", "# Test: loose\n## Goal\nG\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "checkout" / "project.yaml", f"manual_dir: {_mk_manual(tmp_path, 'checkout')}\n")

    projects = {p.name: p for p in discover_projects(str(tmp_path))}
    assert "default" in projects
    assert projects["default"].specs == [str(tmp_path / "loose.md")]
    assert project_slug(projects["default"]) == "default"


def test_project_yaml_merge(tmp_path):
    """P5-8: effective config = global <- root project.yaml <- per-project project.yaml."""
    _write(tmp_path / "project.yaml", "max_total_tokens: 99999\nmax_seconds: 111\n")
    manual = _mk_manual(tmp_path, "checkout")
    _write(
        tmp_path / "checkout" / "project.yaml",
        f"""
        name: checkout
        manual_dir: {manual}
        target:
          type: rdp
          host: winbox01
          user: Administrator
        ssh_host_allowlist:
          - build01
        max_seconds: 222
        schedule: "0 5 * * *"
        """,
    )
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")

    cfg = load_project_config(str(tmp_path / "checkout"), specs_root=str(tmp_path))
    assert cfg.manual_dir == manual
    assert cfg.max_total_tokens == 99999  # from root project.yaml
    assert cfg.max_seconds == 222  # per-project wins over root's 111
    assert cfg.target.type == "rdp"
    assert cfg.target.params == {"host": "winbox01", "user": "Administrator"}
    assert cfg.ssh_host_allowlist == ["build01"]  # replaces global []
    assert cfg.schedule == "0 5 * * *"


def test_disabled_project_skipped(tmp_path):
    """P5-9: a project with enabled: false is excluded from discovery."""
    _write(tmp_path / "on" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "on" / "project.yaml", f"manual_dir: {_mk_manual(tmp_path, 'on')}\n")
    _write(tmp_path / "off" / "project.yaml", "enabled: false\n")
    _write(tmp_path / "off" / "b.md", "# Test: b\n## Goal\nG\n")

    names = {p.name for p in discover_projects(str(tmp_path))}
    assert "on" in names
    assert "off" not in names


def test_project_name_from_yaml(tmp_path):
    _write(tmp_path / "dir1" / "project.yaml", f"name: pretty-name\nmanual_dir: {_mk_manual(tmp_path, 'dir1')}\n")
    _write(tmp_path / "dir1" / "a.md", "# Test: a\n## Goal\nG\n")
    names = {p.name for p in discover_projects(str(tmp_path))}
    assert "pretty-name" in names
    by_slug = find_project("dir1", str(tmp_path))
    by_display_name = find_project("pretty-name", str(tmp_path))
    assert by_slug is not None and by_display_name is not None
    assert by_slug.dir == by_display_name.dir
    assert project_slug(by_slug) == "dir1"


def test_empty_root_returns_no_projects(tmp_path):
    assert discover_projects(str(tmp_path)) == []


# --- manual/ resolution ---------------------------------------------------


def test_load_manual_master_only(tmp_path):
    """The master manual.md is returned when present, with no referenced pages."""
    _write(tmp_path / "manual" / "manual.md", "How to drive the app.")
    assert load_manual(str(tmp_path / "manual")) == "How to drive the app."


def test_load_manual_appends_referenced_pages(tmp_path):
    """Referenced pages follow the master, in order, each under a labeled separator."""
    _write(tmp_path / "manual" / "manual.md", "MASTER")
    _write(tmp_path / "manual" / "create.md", "CREATE DETAIL")
    text = load_manual(str(tmp_path / "manual"), ["create.md"])
    assert text.startswith("MASTER")
    assert "## Manual page: create.md" in text
    assert "CREATE DETAIL" in text
    assert text.index("MASTER") < text.index("CREATE DETAIL")


def test_load_manual_missing_dir_returns_none(tmp_path):
    """No manual dir -> None (the single-spec / no-project path has no manual)."""
    assert load_manual(str(tmp_path / "manual")) is None
    assert load_manual(None) is None


def test_load_manual_master_absent_topic_only(tmp_path):
    """A manual dir with only topic pages (no master) still resolves the referenced page."""
    _write(tmp_path / "manual" / "topic.md", "TOPIC")
    assert "TOPIC" in load_manual(str(tmp_path / "manual"), ["topic.md"])


def test_load_manual_missing_referenced_page_raises(tmp_path):
    """A referenced page that does not exist is a hard error."""
    _write(tmp_path / "manual" / "manual.md", "MASTER")
    with pytest.raises(ManualError, match="not found"):
        load_manual(str(tmp_path / "manual"), ["nope.md"])


def test_load_manual_rejects_path_escape(tmp_path):
    """A reference must be a bare filename; path separators / .. are refused."""
    _write(tmp_path / "manual" / "manual.md", "MASTER")
    with pytest.raises(ManualError, match="bare filename"):
        load_manual(str(tmp_path / "manual"), ["../secrets/x.md"])


def test_load_manual_page_reads_nested_topic(tmp_path):
    """A page path from the TOC (with subdirs) loads that topic file's text on demand."""
    manual_dir = tmp_path / "manual"
    _write(manual_dir / "services" / "100-create.md", "CREATE PROCEDURE")
    assert load_manual_page(str(manual_dir), "services/100-create.md") == "CREATE PROCEDURE"


def test_load_manual_page_missing_raises(tmp_path):
    """A page that does not exist is a hard error, so the planner learns it asked for nothing."""
    manual_dir = tmp_path / "manual"
    _write(manual_dir / "manual.md", "MASTER")
    with pytest.raises(ManualError, match="not found"):
        load_manual_page(str(manual_dir), "services/nope.md")


def test_load_manual_page_rejects_escape(tmp_path):
    """A .. path that escapes the manual/ dir is refused (cannot read outside the manual tree)."""
    manual_dir = tmp_path / "manual"
    _write(manual_dir / "manual.md", "MASTER")
    _write(tmp_path / "secret.md", "SECRET")
    with pytest.raises(ManualError, match="escapes"):
        load_manual_page(str(manual_dir), "../secret.md")


def test_manual_dir_excluded_from_specs(tmp_path):
    """A stray in-project manual/ dir is docs, not specs: it must not be collected as specs."""
    _write(tmp_path / "app" / "a.md", "# Test: a\n## Goal\nG\n")
    _write(tmp_path / "app" / "project.yaml", f"manual_dir: {_mk_manual(tmp_path, 'app')}\n")
    _write(tmp_path / "app" / "manual" / "manual.md", "MASTER")
    _write(tmp_path / "app" / "manual" / "topic.md", "TOPIC")
    projects = {p.name: p for p in discover_projects(str(tmp_path))}
    assert projects["app"].specs == [str(tmp_path / "app" / "a.md")]


# --- manual_dir config resolution + validation -----------------------------


def test_manual_dir_resolves_to_absolute(tmp_path):
    """A project.yaml manual_dir pointing at a dir with manual.md resolves to an abs path."""
    manual = _mk_manual(tmp_path, "checkout")
    _write(tmp_path / "checkout" / "project.yaml", f"name: checkout\nmanual_dir: {manual}\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    cfg = load_project_config(str(tmp_path / "checkout"), specs_root=str(tmp_path))
    assert cfg.manual_dir == manual


def test_portable_tests_manuals_path_resolves_beside_specs_root(tmp_path):
    specs_root = tmp_path / "tests_specs"
    manual = tmp_path / "tests_manuals" / "checkout"
    _write(manual / "manual.md", "MASTER")
    _write(
        specs_root / "checkout" / "project.yaml",
        "name: checkout\nmanual_dir: tests_manuals/checkout\n",
    )
    _write(specs_root / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")

    cfg = load_project_config(
        str(specs_root / "checkout"), specs_root=str(specs_root)
    )

    assert cfg.manual_dir == str(manual)


def test_missing_manual_dir_raises(tmp_path):
    """A real (sub-directory) project without manual_dir is a hard config error."""
    _write(tmp_path / "checkout" / "project.yaml", "name: checkout\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    with pytest.raises(ValueError, match="manual_dir"):
        load_project_config(str(tmp_path / "checkout"), specs_root=str(tmp_path))


def test_manual_dir_without_master_raises(tmp_path):
    """manual_dir set but the dir has no master manual.md is a hard config error."""
    empty = tmp_path / "_manuals" / "empty"
    empty.mkdir(parents=True)
    _write(tmp_path / "checkout" / "project.yaml", f"name: checkout\nmanual_dir: {empty}\n")
    _write(tmp_path / "checkout" / "a.md", "# Test: a\n## Goal\nG\n")
    with pytest.raises(ValueError, match="manual"):
        load_project_config(str(tmp_path / "checkout"), specs_root=str(tmp_path))


def test_root_default_layer_exempt_from_manual_dir(tmp_path):
    """The implicit default project (root project.yaml layer) needs no manual_dir."""
    cfg = load_project_config(str(tmp_path), specs_root=str(tmp_path))
    assert cfg.manual_dir is None
