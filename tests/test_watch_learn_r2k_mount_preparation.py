"""R2K selected-project mount preparation and acceptance contracts."""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
import stat

import pytest

from dashboard.capture_adapter import CaptureAdapterRegistry
from dashboard.demonstrations import DemonstrationError, DemonstrationService
from dashboard.project_access import ProjectAccessError, prepare_watch_learn_project_mount
from tests.test_phase17_watch_learn import (
    FakeAdapter,
    OPERATOR,
    _created,
    _privacy_revision,
    _project,
    _settings,
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _restricted_project(root: Path, name: str) -> tuple[Path, Path, Path]:
    project = root / name
    manual = project / "manual"
    manual.mkdir(parents=True, mode=0o700)
    yaml = project / "project.yaml"
    markdown = manual / "manual.md"
    yaml.write_text("name: Selected\nmanual_dir: ./manual\n", encoding="utf-8")
    markdown.write_text("# Manual\n", encoding="utf-8")
    for path in (root, project, manual):
        path.chmod(0o700)
    for path in (yaml, markdown):
        path.chmod(0o600)
    return project, yaml, markdown


def test_selected_project_is_readable_to_uid_10001_without_broadening_neighbors(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir(mode=0o700)
    project, yaml, markdown = _restricted_project(specs, "selected")
    nested = project / "manual"
    arbitrary = project / "payload.bin"
    arbitrary.write_bytes(b"not a project document")
    arbitrary.chmod(0o600)
    other, other_yaml, _other_markdown = _restricted_project(specs, "unselected")

    prepare_watch_learn_project_mount(str(specs), "selected")

    assert _mode(specs) == 0o755
    assert all(_mode(path) & stat.S_IXOTH for path in (specs, project, nested))
    assert all(_mode(path) & stat.S_IROTH for path in (yaml, markdown))
    assert _mode(project) == _mode(nested) == 0o755
    assert _mode(yaml) == _mode(markdown) == 0o644
    assert _mode(arbitrary) == 0o600
    assert _mode(other) == 0o700 and _mode(other_yaml) == 0o600


def test_symlinks_are_not_followed_and_external_targets_remain_private(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir(mode=0o700)
    project, _yaml, _markdown = _restricted_project(specs, "selected")
    outside_file = tmp_path / "outside.yaml"
    outside_file.write_text("secret_reference: name-only\n", encoding="utf-8")
    outside_file.chmod(0o600)
    outside_dir = tmp_path / "outside-directory"
    outside_dir.mkdir(mode=0o700)
    outside_markdown = outside_dir / "manual.md"
    outside_markdown.write_text("# Outside\n", encoding="utf-8")
    outside_markdown.chmod(0o600)
    (project / "linked.yaml").symlink_to(outside_file)
    (project / "linked-directory").symlink_to(outside_dir, target_is_directory=True)

    prepare_watch_learn_project_mount(str(specs), "selected")

    assert _mode(outside_file) == 0o600
    assert _mode(outside_dir) == 0o700
    assert _mode(outside_markdown) == 0o600


@pytest.mark.parametrize("name", ["../escape", "nested/project", ".", "bad name"])
def test_project_path_cannot_escape_or_select_a_non_immediate_child(tmp_path, name):
    specs = tmp_path / "specs"
    specs.mkdir()
    with pytest.raises(ProjectAccessError):
        prepare_watch_learn_project_mount(str(specs), name)


def test_project_directory_symlink_is_rejected(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (specs / "selected").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProjectAccessError):
        prepare_watch_learn_project_mount(str(specs), "selected")


def test_missing_selected_project_does_not_broaden_specs_root(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir(mode=0o700)
    specs.chmod(0o700)
    with pytest.raises(ProjectAccessError):
        prepare_watch_learn_project_mount(str(specs), "missing")
    assert _mode(specs) == 0o700


def test_configured_specs_root_symlink_is_rejected(tmp_path):
    actual = tmp_path / "actual-specs"
    actual.mkdir()
    _restricted_project(actual, "selected")
    linked = tmp_path / "linked-specs"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ProjectAccessError):
        prepare_watch_learn_project_mount(str(linked), "selected")


def test_mount_failure_is_typed_safe_and_precedes_adapter_contact(tmp_path, caplog, monkeypatch):
    adapter = FakeAdapter()
    service = DemonstrationService(
        _settings(tmp_path), adapters=CaptureAdapterRegistry([adapter])
    )
    session = _created(service)

    def fail_without_paths(*_args):
        raise ProjectAccessError("private/path owner=1003:1004")

    monkeypatch.setitem(
        DemonstrationService.connect.__globals__,
        "prepare_watch_learn_project_mount",
        fail_without_paths,
    )
    with caplog.at_level(logging.ERROR), pytest.raises(DemonstrationError) as failed:
        service.connect(
            OPERATOR,
            session.session_id,
            expected_version=session.version,
            request_project_revision="a" * 64,
            request_target_revision="b" * 64,
            request_privacy_revision=_privacy_revision(),
            project=_project(),
            project_revision="a" * 64,
            target_revision="b" * 64,
            privacy_revision=_privacy_revision(),
            privacy_ready=True,
            preflight_revision="b" * 64,
            preflight_satisfies=True,
        )

    assert failed.value.code == "connection_failed"
    assert failed.value.message == "Controlled canvas connection failed explicitly."
    assert adapter.connects == [] and adapter.disconnects == []
    assert service.get(OPERATOR, session.session_id).state == "connection_failed"
    message = caplog.messages[-1]
    assert '"stage":"project_mount_preparation"' in message
    assert '"reason_code":"project_mount_unreadable"' in message
    assert "private/path" not in message and "1003" not in message


def test_r2k_acceptance_fixture_preserves_private_and_runner_readable_modes(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "run_watch_learn_r2k_local_app_acceptance.py"
    spec = importlib.util.spec_from_file_location("r2k_acceptance", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = module.real_directory(tmp_path / "evidence", 0o700)
    specs = module.real_directory(root / "specs", 0o755)
    secrets_dir = module.real_directory(root / "secrets", 0o700)
    state = module.real_directory(root / "state", 0o700)
    module.write_project(specs)
    module.verify_precontact_modes(root, specs, secrets_dir, state)
    assert _mode(root) == _mode(secrets_dir) == _mode(state) == 0o700
    assert _mode(specs) == _mode(specs / module.PROJECT) == 0o755
    assert _mode(specs / module.PROJECT / "manual") == 0o755
    assert _mode(specs / module.PROJECT / "project.yaml") == 0o644
    assert _mode(specs / module.PROJECT / "manual" / "manual.md") == 0o644


def test_r2k_source_keeps_isolation_and_generation_markers():
    root = Path(__file__).resolve().parents[1]
    runner = (root / "scripts" / "run_container.sh").read_text(encoding="utf-8")
    acceptance = (root / "scripts" / "run_watch_learn_r2k_local_app_acceptance.py").read_text(
        encoding="utf-8"
    )
    assert "--network=none" in runner
    assert "--pull=never" in runner
    assert 'PROJECT = "r2k-synthetic-local-app"' in acceptance
    assert "R2K_SYNTHETIC_LOCAL_APP_PASS" in acceptance
    assert "verify_precontact_modes(root, specs, secrets_dir, state)" in acceptance
    assert not (root / "scripts" / "run_watch_learn_r2j_local_app_acceptance.py").exists()


def test_shallow_image_helper_never_pulls_pushes_or_accepts_deep_bases():
    root = Path(__file__).resolve().parents[1]
    helper = (root / "scripts" / "build_watch_learn_r2k_shallow_validation_image.sh").read_text(
        encoding="utf-8"
    )
    assert "--build-reviewed-validation-image" in helper
    assert "@sha256:" in helper
    assert "--pull=false" in helper and "--pull=never" in helper
    assert "len(layers) > 114" in helper
    assert "len(layers) > 120" in helper
    assert "--network=none" in helper
    assert "push" not in "\n".join(
        line for line in helper.splitlines() if not line.startswith("#") and "NOTICE:" not in line
    )
    for field in ("Entrypoint", "Cmd", "WorkingDir", "User", "Env", "Os", "Architecture"):
        assert field in helper
