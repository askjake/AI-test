"""Security, transaction, API, installer, and UI tests for project-folder import."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from dashboard.auth import Actor
from dashboard.config import DashboardSettings, ProjectImportRootSetting
from dashboard.project_import import (
    ProjectImportApplyRequest,
    ProjectImportBrowseRequest,
    ProjectImportDiscoverRequest,
    ProjectImportConfigurationError,
    ProjectImportError,
    ProjectImportPreviewRequest,
    ProjectImportService,
    _REPARSE_POINT,
    _is_reparse,
    _safe_nofollow_reads_supported,
    _is_special_entry,
    atomic_publish_noreplace,
)
from orchestrator.projects import discover_projects
from orchestrator_cookie import cli
from orchestrator_cookie.config import (
    ConfigurationError,
    ProjectImportRoot,
    RuntimeConfig,
    initialize_runtime,
    load_config,
    normalize_project_import_root,
)
from orchestrator_cookie.doctor import run_doctor
from orchestrator_cookie.lifecycle import dashboard_environment


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = Actor("operator-subject", "operator", "test", "Operator", "session-one")
OTHER_OPERATOR = Actor("operator-subject", "operator", "test", "Operator", "session-two")


def _valid_project(path: Path, *, name: str = "Imported Example") -> Path:
    path.mkdir(parents=True)
    (path / "manual").mkdir()
    (path / "project.yaml").write_text(
        f"name: {name}\n"
        "manual_dir: /source/path/that/must/not/be-followed\n"
        "target:\n  type: local-app\n  app: xterm -T import-test\n  window: import-test\n"
        "schedule: '0 3 * * *'\n"
        "max_steps: 30\nmax_seconds: 1800\nenabled: true\n",
        encoding="utf-8",
    )
    (path / "010-smoke.md").write_text(
        "# Test: Imported smoke\n\n## Goal\nInspect the application.\n\n"
        "## Assertions\n- A visible result is present.\n",
        encoding="utf-8",
    )
    (path / "manual" / "manual.md").write_text(
        "# Imported operating manual\n\nUse the visible controls.\n",
        encoding="utf-8",
    )
    (path / "manual" / "topic.md").write_text(
        "# Topic\n\nAdditional navigation guidance.\n",
        encoding="utf-8",
    )
    return path


def _legacy_split_project(root: Path, *, name: str = "Legacy Example") -> tuple[Path, Path]:
    project = root / "tests_specs" / "legacy-example"
    manual = root / "tests_manuals" / "legacy-example"
    project.mkdir(parents=True)
    manual.mkdir(parents=True)
    (project / "project.yaml").write_text(
        f"name: {name}\n"
        "manual_dir: tests_manuals/legacy-example\n"
        "target:\n  type: local-app\n  app: xmessage legacy\n  window: xmessage\n"
        "schedule: '0 3 * * *'\n"
        "max_steps: 30\nmax_seconds: 1800\nenabled: true\n",
        encoding="utf-8",
    )
    (project / "010-smoke.md").write_text(
        "# Test: Legacy smoke\n\n## Goal\nInspect the application.\n\n"
        "## Assertions\n- A visible result is present.\n",
        encoding="utf-8",
    )
    (manual / "manual.md").write_text("# Legacy operating manual\n", encoding="utf-8")
    (manual / "topic.md").write_text("# Legacy topic\n", encoding="utf-8")
    (manual / "img").mkdir()
    (manual / "img" / "screen.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"safe-asset")
    return project, manual


def _settings(tmp_path: Path, source_root: Path, **overrides) -> DashboardSettings:
    values = {
        "auth_token": "v" * 48,
        "auth_operator_token": "o" * 48,
        "reports_dir": str(tmp_path / "reports"),
        "specs_dir": str(tmp_path / "managed-projects"),
        "project_import_roots": (
            ProjectImportRootSetting(id="approved", label="Approved projects", path=str(source_root)),
        ),
        "project_import_audit_path": str(tmp_path / "private" / "project-import.jsonl"),
    }
    values.update(overrides)
    return DashboardSettings(**values)


def _service(tmp_path: Path, source_root: Path, **overrides) -> ProjectImportService:
    return ProjectImportService(_settings(tmp_path, source_root, **overrides))


def _preview(service: ProjectImportService, path: str = "candidate", slug: str = "imported"):
    return service.preview(
        ProjectImportPreviewRequest(root_id="approved", path=path, destination_slug=slug),
        OPERATOR,
    )


def _tree_fingerprint(path: Path) -> str:
    items = []
    for entry in sorted(path.rglob("*")):
        relative = entry.relative_to(path).as_posix()
        status = entry.lstat()
        digest = hashlib.sha256(entry.read_bytes()).hexdigest() if entry.is_file() else None
        items.append((relative, status.st_mode, status.st_size, digest))
    return hashlib.sha256(repr(items).encode()).hexdigest()


def test_discovery_exposes_logical_split_projects_not_manual_folders(tmp_path):
    root = tmp_path / "legacy"
    project, _manual = _legacy_split_project(root, name="Split Product")
    nested_residue = root / "tests_specs" / "tests_specs" / "duplicate"
    _valid_project(nested_residue, name="Packaging residue")
    service = _service(tmp_path, root)

    response = service.discover(ProjectImportDiscoverRequest(root_id="approved"))

    assert [(item.project_name, item.path, item.layout, item.manual_path) for item in response.projects] == [
        ("Split Product", project.relative_to(root).as_posix(), "split", "tests_manuals/legacy-example")
    ]


def _assert_no_staging(specs_root: Path) -> None:
    assert not list(specs_root.glob(".project_import_*")) if specs_root.exists() else True


def test_configuration_defaults_disabled_and_rejects_malformed_roots(tmp_path):
    settings = DashboardSettings()
    assert settings.project_import_roots == ()
    assert ProjectImportService(settings).capabilities().enabled is False
    assert RuntimeConfig().project_import_roots == ()

    with pytest.raises(ConfigurationError, match="absolute"):
        normalize_project_import_root("root", "Projects", "relative")
    with pytest.raises(ConfigurationError, match="existing"):
        normalize_project_import_root("root", "Projects", str(tmp_path / "missing"))
    with pytest.raises(ConfigurationError, match="id"):
        ProjectImportRoot("bad id", "Projects", str(tmp_path)).validate()
    with pytest.raises(ConfigurationError, match="label"):
        ProjectImportRoot("root", "bad\nlabel", str(tmp_path)).validate()

    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ConfigurationError, match="links or reparse"):
        normalize_project_import_root("root", "Projects", str(linked))


def test_persisted_roots_are_recanonicalized_and_duplicates_fail(tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    root = normalize_project_import_root("one", "One", str(first / ".." / "first"))
    assert root.path == str(first.resolve())
    loaded = RuntimeConfig.from_mapping({"project_import_roots": [root.__dict__]})
    assert loaded.project_import_roots == (root,)
    with pytest.raises(ConfigurationError, match="ids must be unique"):
        RuntimeConfig(project_import_roots=(root, root)).validate()
    duplicate_path = ProjectImportRoot("two", "Two", root.path)
    with pytest.raises(ConfigurationError, match="paths must be unique"):
        RuntimeConfig(project_import_roots=(root, duplicate_path)).validate()
    with pytest.raises(ConfigurationError, match="canonical"):
        RuntimeConfig(project_import_roots=(
            ProjectImportRoot("raw", "Raw", str(first / ".." / "first")),
        )).validate()
    with pytest.raises(ConfigurationError, match="only id, label, and path"):
        RuntimeConfig.from_mapping({
            "project_import_roots": [
                {"id": "one", "label": "One", "path": str(first), "extra": True},
            ],
        })


def test_installer_cli_environment_and_doctor_contract(tmp_path, capsys):
    initialize_runtime(tmp_path)
    approved = tmp_path / "incoming"
    approved.mkdir()
    result = cli.main([
        "configure", "--non-interactive", "--project-import-root",
        "incoming", "Incoming projects", str(approved),
    ], repo_root=tmp_path)
    assert result == 0
    capsys.readouterr()
    config = load_config(tmp_path)
    assert config.project_import_roots[0].path == str(approved.resolve())
    environment = dashboard_environment(tmp_path, config, instance_id="test-instance")
    exported = json.loads(environment["DASHBOARD_PROJECT_IMPORT_ROOTS"])
    assert exported == [{"id": "incoming", "label": "Incoming projects", "path": str(approved.resolve())}]
    assert environment["DASHBOARD_PROJECT_IMPORT_AUDIT_PATH"].endswith("project_import_audit.jsonl")
    report = run_doctor(tmp_path)
    finding = next(item for item in report.findings if item.code == "project-folder-import")
    capability = next(item for item in report.capabilities if item.name == "Project-folder import")
    assert finding.severity == "PASS"
    assert capability.state in {"READY", "UNAVAILABLE"}

    assert cli.main(["configure", "--non-interactive", "--clear-project-import-roots"], repo_root=tmp_path) == 0
    assert load_config(tmp_path).project_import_roots == ()


def test_browse_returns_friendly_relative_navigation_only(tmp_path):
    source = tmp_path / "approved-root"
    source.mkdir()
    (source / "Alpha").mkdir()
    (source / "Alpha" / "Nested").mkdir()
    (source / ".hidden").mkdir()
    (source / "client-secret").mkdir()
    (source / "not-a-folder.txt").write_text("x")
    (source / "linked").symlink_to(source / "Alpha", target_is_directory=True)
    service = _service(tmp_path, source, project_import_max_browse_entries=10)

    top = service.browse(ProjectImportBrowseRequest(root_id="approved", path=""))
    assert top.root_label == "Approved projects"
    assert [item.name for item in top.directories] == ["Alpha"]
    assert top.breadcrumbs[0].model_dump() == {"label": "Approved projects", "path": ""}
    nested = service.browse(ProjectImportBrowseRequest(root_id="approved", path="Alpha"))
    assert nested.path == "Alpha"
    assert [item.path for item in nested.directories] == ["Alpha/Nested"]
    payload = top.model_dump_json() + nested.model_dump_json()
    assert str(source) not in payload
    assert ".hidden" not in payload and "client-secret" not in payload


@pytest.mark.parametrize("value", ["..", "../sibling", "Alpha/../sibling", "/tmp", "C:/Windows", "Alpha\\Nested"])
def test_browse_rejects_traversal_absolute_and_cross_platform_paths(tmp_path, value):
    source = tmp_path / "allow"
    source.mkdir()
    service = _service(tmp_path, source)
    with pytest.raises(ProjectImportError) as caught:
        service.browse(ProjectImportBrowseRequest(root_id="approved", path=value))
    assert caught.value.code == "invalid_path"


def test_sibling_prefix_and_root_swap_are_denied(tmp_path):
    source = tmp_path / "allowed"
    source.mkdir()
    sibling = tmp_path / "allowed-other"
    sibling.mkdir()
    service = _service(tmp_path, source)
    with pytest.raises(ProjectImportError):
        service.browse(ProjectImportBrowseRequest(root_id="approved", path="../allowed-other"))

    moved = tmp_path / "allowed-original"
    source.rename(moved)
    source.mkdir()
    with pytest.raises(ProjectImportError) as caught:
        service.browse(ProjectImportBrowseRequest(root_id="approved", path=""))
    assert caught.value.code == "root_changed"


def test_preview_rejects_links_broken_links_fifo_and_socket_without_leaks(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    (project / "linked.md").symlink_to(project / "010-smoke.md")
    (project / "broken.md").symlink_to(project / "missing.md")
    (project / ".secret-link").symlink_to(project / "010-smoke.md")
    (project / "nested").mkdir()
    (project / "nested" / "linked").symlink_to(project / "manual", target_is_directory=True)
    fifo = project / "pipe"
    os.mkfifo(fifo)
    sock_path = project / "local.sock"
    sock = None
    try:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(sock_path))
        except PermissionError:
            if sock is not None:
                sock.close()
            sock = None
        preview = _preview(_service(tmp_path, source))
    finally:
        if sock is not None:
            sock.close()
    codes = [item.code for item in preview.diagnostics]
    assert codes.count("linked_entry") == 4
    assert codes.count("special_file") == (2 if sock is not None else 1)
    assert preview.can_import is False
    payload = preview.model_dump_json()
    assert ".secret-link" not in payload
    assert str(source) not in payload


def test_reparse_detection_and_unproven_atomic_platform_fail_closed(monkeypatch, tmp_path):
    assert _is_reparse(SimpleNamespace(st_file_attributes=_REPARSE_POINT))
    assert not _is_reparse(SimpleNamespace(st_file_attributes=0))
    assert _is_special_entry(SimpleNamespace(st_mode=stat.S_IFIFO))
    assert _is_special_entry(SimpleNamespace(st_mode=stat.S_IFSOCK))
    assert _is_special_entry(SimpleNamespace(st_mode=stat.S_IFCHR))
    assert _is_special_entry(SimpleNamespace(st_mode=stat.S_IFBLK))
    assert not _is_special_entry(SimpleNamespace(st_mode=stat.S_IFREG))
    monkeypatch.setattr("dashboard.project_import.os.name", "nt")
    assert _safe_nofollow_reads_supported() is False
    monkeypatch.setattr("dashboard.project_import.os.name", "posix")
    source = tmp_path / "stage"
    destination = tmp_path / "destination"
    source.mkdir()
    monkeypatch.setattr("dashboard.project_import.sys.platform", "freebsd")
    with pytest.raises(ProjectImportError) as caught:
        atomic_publish_noreplace(source, destination)
    assert caught.value.code == "atomic_publish_unavailable"
    assert source.is_dir() and not destination.exists()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda project: (project / "project.yaml").unlink(), "project_metadata_missing"),
        (lambda project: (project / "010-smoke.md").write_text("not a spec"), "spec_parse"),
        (lambda project: (project / "manual" / "manual.md").write_text("no heading"), "manual_heading_missing"),
        (lambda project: (project / "credentials.json").write_text("not-a-real-secret"), "sensitive_entry"),
    ],
)
def test_invalid_metadata_specs_manuals_and_sensitive_files(tmp_path, mutation, expected):
    source = tmp_path / "incoming"
    source.mkdir(parents=True)
    project = _valid_project(source / "candidate")
    mutation(project)
    preview = _preview(_service(tmp_path, source))
    assert preview.can_import is False
    assert expected in {item.code for item in preview.diagnostics}
    assert not (tmp_path / "managed-projects" / "imported").exists()


def test_unsafe_filename_is_redacted_and_rejected(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    (project / "unsafe:name.md").write_text("not imported")
    preview = _preview(_service(tmp_path, source))
    assert preview.can_import is False
    assert "unsafe_filename" in {item.code for item in preview.diagnostics}
    assert "unsafe:name.md" not in preview.model_dump_json()


@pytest.mark.parametrize(
    ("overrides", "builder", "expected"),
    [
        ({"project_import_max_depth": 1}, lambda p: (p / "nested" / "too-deep").mkdir(parents=True), "depth_limit"),
        ({"project_import_max_files": 3}, lambda p: (p / "extra.md").write_text("# Test: X\n\n## Goal\nX\n\n## Assertions\n- X\n"), "file_count_limit"),
        ({"project_import_max_file_bytes": 1024}, lambda p: (p / "manual" / "topic.md").write_bytes(b"x" * 1025), "file_too_large"),
        ({"project_import_max_total_bytes": 1024}, lambda p: (p / "ignored.bin").write_bytes(b"x" * 1025), "total_size_limit"),
    ],
)
def test_depth_count_single_file_and_total_size_limits(tmp_path, overrides, builder, expected):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    builder(project)
    preview = _preview(_service(tmp_path, source, **overrides))
    assert expected in {item.code for item in preview.diagnostics}
    assert preview.can_import is False


def test_preview_is_no_write_and_never_invokes_runner_target_model_or_network(tmp_path, monkeypatch):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    service = _service(tmp_path, source)
    source_before = _tree_fingerprint(project)
    specs_root = Path(service.settings.specs_dir)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("preview attempted prohibited activity")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    preview = _preview(service)
    assert preview.can_import is True
    assert _tree_fingerprint(project) == source_before
    assert not specs_root.exists()


def test_atomic_success_preserves_source_and_produces_runnable_portable_project(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    (project / "README.md").write_text("excluded")
    service = _service(tmp_path, source)
    source_before = _tree_fingerprint(project)
    spec_bytes = (project / "010-smoke.md").read_bytes()
    manual_bytes = (project / "manual" / "manual.md").read_bytes()
    preview = _preview(service)
    assert preview.can_import is True
    assert preview.excluded_count == 1
    result = service.apply(
        ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="imported"),
        OPERATOR,
    )
    destination = Path(service.settings.specs_dir) / "imported"
    assert result.status == "imported"
    assert (destination / "010-smoke.md").read_bytes() == spec_bytes
    assert (destination / "manual" / "manual.md").read_bytes() == manual_bytes
    project_yaml = (destination / "project.yaml").read_text()
    assert "manual_dir: ./manual" in project_yaml
    assert "/source/path" not in project_yaml
    assert not (destination / "README.md").exists()
    import_manifest = json.loads(
        (destination / "support" / "project-import-manifest.json").read_text()
    )
    assert import_manifest["version"] == 1
    assert import_manifest["origin"] == "project-folder-import"
    assert {item["path"] for item in import_manifest["files"]} == {
        "010-smoke.md", "manual/manual.md", "manual/topic.md", "project.yaml"
    }
    assert _tree_fingerprint(project) == source_before
    projects = discover_projects(str(Path(service.settings.specs_dir)))
    assert len(projects) == 1
    assert projects[0].name == "Imported Example"
    assert projects[0].config.manual_dir == str((destination / "manual").resolve())
    assert [Path(path).name for path in projects[0].specs] == ["010-smoke.md"]
    _assert_no_staging(Path(service.settings.specs_dir))

    audit_path = Path(service.settings.project_import_audit_path)
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert [event["action"] for event in events] == ["preview", "apply"]
    assert events[-1]["result"] == "imported"
    audit_text = audit_path.read_text()
    assert str(source) not in audit_text and "candidate" not in audit_text
    assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600


def test_root_contained_legacy_split_manual_is_preview_bound_and_copied(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, manual = _legacy_split_project(source)
    service = _service(tmp_path, source)
    source_before = _tree_fingerprint(source)

    preview = _preview(
        service,
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )

    assert preview.can_import is True
    assert preview.manual_count == 2
    assert preview.included_file_count == 5
    assert "legacy_manual_copied" in {item.code for item in preview.diagnostics}
    assert str(source) not in preview.model_dump_json()
    result = service.apply(
        ProjectImportApplyRequest(
            preview_token=preview.preview_token,
            destination_slug="legacy-imported",
        ),
        OPERATOR,
    )

    destination = Path(service.settings.specs_dir) / "legacy-imported"
    assert result.status == "imported"
    assert (destination / "manual" / "manual.md").read_bytes() == (manual / "manual.md").read_bytes()
    assert (destination / "manual" / "topic.md").read_bytes() == (manual / "topic.md").read_bytes()
    assert (destination / "manual" / "img" / "screen.png").read_bytes() == (
        manual / "img" / "screen.png"
    ).read_bytes()
    assert "manual_dir: ./manual" in (destination / "project.yaml").read_text(encoding="utf-8")
    assert "tests_manuals/legacy-example" not in (destination / "project.yaml").read_text(encoding="utf-8")
    assert _tree_fingerprint(source) == source_before
    assert project.is_dir()


def test_legacy_split_import_persists_runner_window_fallback_and_no_schedule(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, _manual = _legacy_split_project(source, name="Legacy SSH")
    (project / "project.yaml").write_text(
        "name: Legacy SSH\n"
        "manual_dir: tests_manuals/legacy-example\n"
        "target:\n  type: ssh-terminal\n  host: build01\n  user: ci\n  key: build01_id_ed25519\n"
        "ssh_host_allowlist:\n  - build01\n"
        "max_steps: 30\nmax_seconds: 1800\nenabled: true\n",
        encoding="utf-8",
    )
    service = _service(tmp_path, source)

    preview = _preview(
        service,
        path="tests_specs/legacy-example",
        slug="legacy-ssh",
    )

    codes = {item.code for item in preview.diagnostics}
    assert preview.can_import is True
    assert {"legacy_manual_copied", "legacy_window_defaulted", "legacy_schedule_retained"} <= codes
    result = service.apply(
        ProjectImportApplyRequest(
            preview_token=preview.preview_token,
            destination_slug="legacy-ssh",
        ),
        OPERATOR,
    )
    assert result.status == "imported"
    written = (Path(service.settings.specs_dir) / "legacy-ssh" / "project.yaml").read_text(
        encoding="utf-8"
    )
    assert "window: orchestrator-ssh-build01" in written
    assert "schedule:" not in written


def test_legacy_vnc_via_is_migrated_but_watch_learn_remains_unconfigured(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, _manual = _legacy_split_project(source, name="Legacy VNC")
    (project / "project.yaml").write_text(
        "name: Legacy VNC\n"
        "manual_dir: tests_manuals/legacy-example\n"
        "target:\n  type: vnc\n  host: 10.57.24.249\n  port: 5900\n"
        "  via: ikim@10.74.11.30\n  gateway_password_file: mul.pass\n"
        "vnc_host_allowlist:\n  - 10.57.24.249\n"
        "ssh_host_allowlist:\n  - 10.74.11.30\n"
        "max_steps: 40\nmax_seconds: 1800\nenabled: true\n",
        encoding="utf-8",
    )
    service = _service(tmp_path, source)
    preview = _preview(
        service, path="tests_specs/legacy-example", slug="legacy-vnc"
    )
    codes = {item.code for item in preview.diagnostics}
    assert preview.can_import is True
    assert {
        "legacy_vnc_route_migrated",
        "legacy_window_defaulted",
        "watch_learn_readiness_required",
    } <= codes
    service.apply(
        ProjectImportApplyRequest(
            preview_token=preview.preview_token, destination_slug="legacy-vnc"
        ),
        OPERATOR,
    )
    written = (Path(service.settings.specs_dir) / "legacy-vnc" / "project.yaml").read_text()
    assert "via:" not in written
    assert "type: ssh-jump" in written
    assert "host: 10.74.11.30" in written
    assert "user: ikim" in written
    assert "known_hosts_file: 10.74.11.30.known_hosts" in written
    assert "gateway_password_file: mul.pass" in written
    assert "window: TigerVNC" in written
    assert "watch_learn_ready_window:" not in written


@pytest.mark.parametrize(
    "manual_dir",
    ["../outside", "/tmp/outside", "C:/outside", "tests_manuals\\legacy-example"],
)
def test_legacy_manual_path_must_remain_relative_and_inside_root(tmp_path, manual_dir):
    source = tmp_path / "incoming"
    source.mkdir()
    project, _manual = _legacy_split_project(source)
    yaml_path = project / "project.yaml"
    yaml_path.write_text(
        yaml_path.read_text(encoding="utf-8").replace(
            "tests_manuals/legacy-example", manual_dir
        ),
        encoding="utf-8",
    )

    preview = _preview(
        _service(tmp_path, source),
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )

    assert preview.can_import is False
    assert "legacy_manual_path_invalid" in {item.code for item in preview.diagnostics}
    assert str(source) not in preview.model_dump_json()


def test_legacy_manual_link_is_rejected_without_following_it(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, manual = _legacy_split_project(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "manual.md").write_text("# Outside\n", encoding="utf-8")
    shutil.rmtree(manual)
    manual.symlink_to(outside, target_is_directory=True)

    preview = _preview(
        _service(tmp_path, source),
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )

    assert preview.can_import is False
    assert "legacy_manual_unavailable" in {item.code for item in preview.diagnostics}
    assert "Outside" not in preview.model_dump_json()
    assert project.is_dir()


def test_legacy_manual_change_after_preview_invalidates_apply(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    _project, manual = _legacy_split_project(source)
    service = _service(tmp_path, source)
    preview = _preview(
        service,
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )
    (manual / "topic.md").write_text("# Changed after preview\n", encoding="utf-8")

    with pytest.raises(ProjectImportError) as stale:
        service.apply(
            ProjectImportApplyRequest(
                preview_token=preview.preview_token,
                destination_slug="legacy-imported",
            ),
            OPERATOR,
        )

    assert stale.value.code == "stale_preview"
    assert not (Path(service.settings.specs_dir) / "legacy-imported").exists()


def test_existing_partial_portable_manual_never_falls_back_to_legacy_tree(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, _manual = _legacy_split_project(source)
    (project / "manual").mkdir()
    (project / "manual" / "topic.md").write_text("# Partial\n", encoding="utf-8")

    preview = _preview(
        _service(tmp_path, source),
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )

    assert preview.can_import is False
    assert "portable_manual_missing" in {item.code for item in preview.diagnostics}
    assert "legacy_manual_copied" not in {item.code for item in preview.diagnostics}


def test_legacy_manual_may_not_overlap_selected_project_tree(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    project, _manual = _legacy_split_project(source)
    nested = project / "docs"
    nested.mkdir()
    (nested / "manual.md").write_text("# Nested manual\n", encoding="utf-8")
    yaml_path = project / "project.yaml"
    yaml_path.write_text(
        yaml_path.read_text(encoding="utf-8").replace(
            "tests_manuals/legacy-example", "tests_specs/legacy-example/docs"
        ),
        encoding="utf-8",
    )

    preview = _preview(
        _service(tmp_path, source),
        path="tests_specs/legacy-example",
        slug="legacy-imported",
    )

    assert preview.can_import is False
    assert "legacy_manual_overlap" in {item.code for item in preview.diagnostics}


def test_collision_expiry_owner_binding_and_destination_binding(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    _valid_project(source / "candidate")
    clock = [100.0]
    settings = _settings(tmp_path, source, project_import_preview_ttl_seconds=30)
    service = ProjectImportService(settings, clock=lambda: clock[0])
    Path(settings.specs_dir).mkdir()
    (Path(settings.specs_dir) / "taken").mkdir()
    collision = _preview(service, slug="taken")
    assert collision.can_import is False
    assert "project_exists" in {item.code for item in collision.diagnostics}

    preview = _preview(service, slug="fresh")
    with pytest.raises(ProjectImportError) as owner:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="fresh"), OTHER_OPERATOR)
    assert owner.value.code == "preview_owner_mismatch"

    preview = _preview(service, slug="fresh")
    with pytest.raises(ProjectImportError) as destination:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="changed"), OPERATOR)
    assert destination.value.code == "preview_destination_mismatch"

    preview = _preview(service, slug="fresh")
    clock[0] += 31
    with pytest.raises(ProjectImportError) as expired:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="fresh"), OPERATOR)
    assert expired.value.code == "preview_expired"


def test_stale_fingerprint_and_copy_time_source_mutation_leave_no_destination(tmp_path, monkeypatch):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    service = _service(tmp_path, source)
    preview = _preview(service)
    (project / "010-smoke.md").write_text(
        (project / "010-smoke.md").read_text() + "\nChanged after preview.\n"
    )
    with pytest.raises(ProjectImportError) as stale:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="imported"), OPERATOR)
    assert stale.value.code == "stale_preview"
    assert not (Path(service.settings.specs_dir) / "imported").exists()

    service = _service(tmp_path / "second", source)
    preview = _preview(service)
    original_copy = service._copy_to_stage

    def mutate_after_copy(stage, scan):
        original_copy(stage, scan)
        (project / "manual" / "topic.md").write_text("# Mutated\n")

    monkeypatch.setattr(service, "_copy_to_stage", mutate_after_copy)
    with pytest.raises(ProjectImportError) as during:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="imported"), OPERATOR)
    assert during.value.code == "stale_preview"
    assert not (Path(service.settings.specs_dir) / "imported").exists()
    _assert_no_staging(Path(service.settings.specs_dir))


@pytest.mark.parametrize("failure_point", ["copy", "validation", "publish"])
def test_injected_failures_roll_back_owned_staging_only(tmp_path, monkeypatch, failure_point):
    source = tmp_path / "incoming"
    source.mkdir()
    project = _valid_project(source / "candidate")
    service = _service(tmp_path, source)
    preview = _preview(service)
    before = _tree_fingerprint(project)
    owned = Path(service.settings.specs_dir) / ".unrelated"
    owned.parent.mkdir(parents=True, exist_ok=True)
    owned.mkdir()

    def fail(*_args, **_kwargs):
        raise RuntimeError("injected failure")

    attribute = {"copy": "_copy_to_stage", "validation": "_validate_stage", "publish": "_publish"}[failure_point]
    monkeypatch.setattr(service, attribute, fail)
    with pytest.raises(RuntimeError, match="injected failure"):
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="imported"), OPERATOR)
    assert _tree_fingerprint(project) == before
    assert not (Path(service.settings.specs_dir) / "imported").exists()
    assert owned.is_dir()
    _assert_no_staging(Path(service.settings.specs_dir))


def test_audit_failure_after_publish_rolls_back_project(tmp_path, monkeypatch):
    source = tmp_path / "incoming"
    source.mkdir()
    _valid_project(source / "candidate")
    service = _service(tmp_path, source)
    claims = []
    rollbacks = []
    service.on_publish = lambda actor, slug, revision: claims.append((actor.subject, slug, revision))
    service.on_rollback = lambda actor, slug, revision: rollbacks.append((actor.subject, slug, revision))
    preview = _preview(service)
    original_record = service.audit.record

    def fail_apply_audit(**kwargs):
        if kwargs["action"] == "apply" and kwargs["result"] == "imported":
            raise OSError("audit unavailable")
        return original_record(**kwargs)

    monkeypatch.setattr(service.audit, "record", fail_apply_audit)
    with pytest.raises(ProjectImportError) as caught:
        service.apply(ProjectImportApplyRequest(preview_token=preview.preview_token, destination_slug="imported"), OPERATOR)
    assert caught.value.code == "audit_unavailable"
    assert not (Path(service.settings.specs_dir) / "imported").exists()
    assert claims == rollbacks
    assert len(claims) == 1
    _assert_no_staging(Path(service.settings.specs_dir))


def test_atomic_publish_collision_race_never_overwrites(tmp_path, monkeypatch):
    source = tmp_path / "incoming"
    source.mkdir()
    _valid_project(source / "candidate")
    service = _service(tmp_path, source)
    preview = _preview(service)
    destination = Path(service.settings.specs_dir) / "imported"

    def collide(stage, requested_destination):
        requested_destination.mkdir()
        (requested_destination / "owner.txt").write_text("pre-existing")
        atomic_publish_noreplace(stage, requested_destination)

    monkeypatch.setattr(service, "_publish", collide)
    with pytest.raises(ProjectImportError) as caught:
        service.apply(
            ProjectImportApplyRequest(
                preview_token=preview.preview_token,
                destination_slug="imported",
            ),
            OPERATOR,
        )
    assert caught.value.code == "project_exists"
    assert (destination / "owner.txt").read_text() == "pre-existing"
    _assert_no_staging(Path(service.settings.specs_dir))


def test_linked_managed_destination_root_is_denied(tmp_path):
    source = tmp_path / "incoming"
    source.mkdir()
    _valid_project(source / "candidate")
    real_store = tmp_path / "real-store"
    real_store.mkdir()
    linked_store = tmp_path / "linked-store"
    linked_store.symlink_to(real_store, target_is_directory=True)
    service = _service(tmp_path, source, specs_dir=str(linked_store))
    preview = _preview(service)
    assert preview.can_import is True
    with pytest.raises(ProjectImportConfigurationError, match="links or reparse"):
        service.apply(
            ProjectImportApplyRequest(
                preview_token=preview.preview_token,
                destination_slug="imported",
            ),
            OPERATOR,
        )
    assert not (real_store / "imported").exists()


def _api_app(tmp_path: Path, monkeypatch, *, roots: bool = True):
    import dashboard.app as app_module
    import dashboard.config as config_module

    source = tmp_path / "incoming"
    source.mkdir(parents=True)
    _valid_project(source / "candidate")
    settings = _settings(tmp_path, source)
    if not roots:
        settings = settings.model_copy(update={"project_import_roots": ()})
    monkeypatch.setattr(config_module, "settings", settings)
    monkeypatch.setattr(app_module, "settings", settings)
    return app_module.create_app(), source


def _body_for(endpoint: str) -> dict:
    if endpoint == "browse":
        return {"root_id": "approved", "path": ""}
    if endpoint == "preview":
        return {"root_id": "approved", "path": "candidate", "destination_slug": "imported"}
    return {"preview_token": "x" * 32, "destination_slug": "imported"}


@pytest.mark.parametrize("endpoint,method", [("capabilities", "get"), ("roots", "get"), ("browse", "post"), ("preview", "post"), ("apply", "post")])
def test_every_api_endpoint_has_unauthenticated_and_viewer_gate(tmp_path, monkeypatch, endpoint, method):
    app, source = _api_app(tmp_path, monkeypatch)
    url = f"/api/v1/authoring/project-import/{endpoint}"
    kwargs = {} if method == "get" else {"json": _body_for(endpoint)}
    with TestClient(app) as client:
        unauthenticated = getattr(client, method)(url, **kwargs)
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["detail"]["code"] == "unauthenticated"
        viewer = getattr(client, method)(
            url,
            headers={"Authorization": "Bearer " + "v" * 48},
            **kwargs,
        )
        assert viewer.status_code == 403
        assert viewer.json()["detail"]["code"] == "operator_required"
        assert str(source) not in viewer.text
        assert "Approved projects" not in viewer.text


def test_cookie_operator_requires_csrf_on_every_post_endpoint(tmp_path, monkeypatch):
    app, _source = _api_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        session = client.post(
            "/api/v1/auth/bootstrap/session",
            json={"credential": "o" * 48},
        ).json()
        for endpoint in ("browse", "preview", "apply"):
            url = f"/api/v1/authoring/project-import/{endpoint}"
            body = _body_for(endpoint)
            denied = client.post(url, json=body)
            assert denied.status_code == 403
            assert denied.json()["detail"]["code"] == "csrf_required"
            verified = client.post(
                url,
                headers={"X-CSRF-Token": session["csrf_token"]},
                json=body,
            )
            assert verified.status_code in {200, 409}
            if endpoint == "apply":
                assert verified.json()["detail"]["code"] == "preview_expired"


def test_operator_api_browse_preview_apply_and_default_disabled(tmp_path, monkeypatch):
    app, source = _api_app(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer " + "o" * 48}
    with TestClient(app) as client:
        capabilities = client.get("/api/v1/authoring/project-import/capabilities", headers=headers)
        assert capabilities.status_code == 200 and capabilities.json()["enabled"] is True
        roots = client.get("/api/v1/authoring/project-import/roots", headers=headers)
        assert roots.json() == [{"id": "approved", "label": "Approved projects"}]
        assert str(source) not in roots.text
        browse = client.post(
            "/api/v1/authoring/project-import/browse", headers=headers,
            json={"root_id": "approved", "path": ""},
        )
        assert browse.status_code == 200
        preview = client.post(
            "/api/v1/authoring/project-import/preview", headers=headers,
            json={"root_id": "approved", "path": "candidate", "destination_slug": "imported"},
        )
        assert preview.status_code == 200 and preview.json()["can_import"] is True
        apply = client.post(
            "/api/v1/authoring/project-import/apply", headers=headers,
            json={"preview_token": preview.json()["preview_token"], "destination_slug": "imported"},
        )
        assert apply.status_code == 200
        assert apply.json()["status"] == "imported"

    disabled_app, _ = _api_app(tmp_path / "disabled", monkeypatch, roots=False)
    with TestClient(disabled_app) as client:
        capabilities = client.get("/api/v1/authoring/project-import/capabilities", headers=headers)
        assert capabilities.json()["enabled"] is False
        response = client.post(
            "/api/v1/authoring/project-import/browse", headers=headers,
            json={"root_id": "approved", "path": ""},
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "project_import_disabled"


def test_dashboard_modal_accessibility_error_and_success_hooks_are_retained():
    html = (ROOT / "templates" / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert '>Import project folder</button>' in html
    assert 'id="project-import-dialog" aria-labelledby="project-import-title"' in html
    assert 'aria-describedby="project-import-description"' in html
    assert 'aria-label="Selected folder breadcrumbs"' in html
    assert 'role="alert"' in html and 'aria-live="polite"' in html
    assert '.addEventListener("cancel"' in html
    assert 'confirmation.type = "checkbox"' in html
    assert 'await loadProjects();\n    await selectProject(result.destination_slug);' in html
    assert 'setProjectImportMessage(error.message' in html
    assert 'location.replace("/sign-in?state=expired")' in html
    assert 'href="/watch-learn"' in html
