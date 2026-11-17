"""Phase 12 tests — project editor API.

P12-A-1   GET /projects/{name}/config returns parsed project.yaml
P12-A-2   GET /projects/{name}/config for unknown project returns 404
P12-A-3   GET /projects/{name}/specs returns list of spec files with titles
P12-A-4   GET /projects/{name}/specs/{path} returns spec content
P12-A-5   GET /projects/{name}/specs/{path} for missing file returns 404
P12-A-6   Path traversal in spec path returns 400
P12-B-1   PUT /projects/{name}/config updates the project.yaml
P12-B-2   PUT /projects/{name}/config with invalid YAML returns 422
P12-B-3   PUT /projects/{name}/config with viewer token returns 403
P12-B-4   PUT /projects/{name}/specs/{path} creates a new spec file
P12-B-5   PUT /projects/{name}/specs/{path} with non-.md extension returns 400
P12-B-6   POST /projects creates directory + project.yaml + starter spec
P12-B-7   POST /projects with existing dir_name returns 409
P12-B-8   POST /projects with unsafe dir_name returns 400
P12-C-1   DELETE /projects/{name}/specs/{path} removes the file
P12-C-2   DELETE /projects/{name}/specs/project.yaml returns 400
P12-C-3   DELETE /projects/{name} sets enabled: false
P12-C-4   DELETE /projects/{name} on unknown project returns 404
P12-X-1   No circular import between editor_routes and orchestrator models
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import stat
import tempfile

import pytest
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_PROJECT_YAML = """name: test-proj
manual_dir: tests_manuals/test-proj
target:
  type: local-app
  app: xterm -T test
  window: test
schedule: "0 3 * * *"
max_steps: 30
max_seconds: 1800
enabled: true
"""

SAMPLE_SPEC = """# Test: Login works

## Goal
Open the application and verify login succeeds.

## Assertions
- A welcome message is visible.
- The session token is stored.
"""


@pytest.fixture()
def specs_root(tmp_path, monkeypatch):
    """A fake tests_specs/ with one project."""
    sroot = tmp_path / "tests_specs"
    proj = sroot / "test-proj"
    proj.mkdir(parents=True)
    (proj / "project.yaml").write_text(SAMPLE_PROJECT_YAML)
    (proj / "010-login.md").write_text(SAMPLE_SPEC)
    (proj / "020-logout.md").write_text("# Test: Logout\n\n## Goal\nLogout.\n\n## Assertions\n- User is logged out.\n")
    subdir = proj / "sub"
    subdir.mkdir()
    (subdir / "030-deep.md").write_text("# Test: Deep spec\n\n## Goal\nDeep.\n\n## Assertions\n- Works.\n")
    # root project.yaml
    (sroot / "project.yaml").write_text("# root\n")
    monkeypatch.setenv("TESTS_MANUALS_DIR", str(tmp_path / "tests_manuals"))
    return str(sroot)


def _make_editor_app(specs_root, reports_dir, auth_token="viewer", operator_token="operator"):
    for k in list(os.environ.keys()):
        if k.startswith("DASHBOARD_"):
            del os.environ[k]
    os.environ["DASHBOARD_AUTH_TOKEN"] = auth_token
    os.environ["DASHBOARD_AUTH_OPERATOR_TOKEN"] = operator_token
    os.environ["DASHBOARD_REPORTS_DIR"] = str(reports_dir)
    os.environ["DASHBOARD_INDEX_INTERVAL"] = "999"
    # Point the orchestrator config at our fake specs_root
    os.environ["TESTS_SPECS_DIR"] = specs_root

    import dashboard.config as dcfg
    import dashboard.app as dapp
    import dashboard.routes as droutes
    import dashboard.index as didx
    import dashboard.editor_routes as der

    for m in [dcfg, dapp, droutes, didx, der]:
        importlib.reload(m)

    # Patch orchestrator.config.settings.tests_specs_dir lazily via env
    import orchestrator.config as ocfg
    importlib.reload(ocfg)

    from dashboard.app import create_app
    from dashboard.index import RunIndex
    from dashboard.routes import set_index

    a = create_app()
    idx = RunIndex(reports_dir=str(reports_dir), interval=999)
    set_index(idx)
    return a


@pytest.fixture()
def editor_client(specs_root, tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    a = _make_editor_app(specs_root, reports_dir)
    with TestClient(a, raise_server_exceptions=True) as c:
        yield c


def _vh(token="viewer"):
    return {"Authorization": f"Bearer {token}"}

def _op():
    return _vh("operator")


# ─────────────────────────────────────────────────────────────────────────────
# P12-A: read endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_get_project_config(editor_client):
    """P12-A-1: GET /projects/{name}/config returns parsed project.yaml."""
    r = editor_client.get("/api/v1/projects/test-proj/config", headers=_vh())
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["name"] == "test-proj"
    assert d["dir_name"] == "test-proj"
    assert d["enabled"] is True
    assert d["target"]["type"] == "local-app"
    assert "xterm" in d["target"]["params"].get("app", "")
    assert "raw_yaml" in d
    assert "project.yaml" not in d["raw_yaml"]  # it's raw file content, not a filename


def test_get_project_config_unknown(editor_client):
    """P12-A-2: Unknown project returns 404."""
    r = editor_client.get("/api/v1/projects/no-such/config", headers=_vh())
    assert r.status_code == 404


def test_list_project_specs(editor_client):
    """P12-A-3: GET /projects/{name}/specs lists all spec files."""
    r = editor_client.get("/api/v1/projects/test-proj/specs", headers=_vh())
    assert r.status_code == 200, r.text
    specs = r.json()
    paths = [s["path"] for s in specs]
    assert "010-login.md" in paths
    assert "020-logout.md" in paths
    assert any("030-deep.md" in p for p in paths)
    # All should have titles
    for s in specs:
        assert s["title"]
        assert s["parse_error"] is None or s["parse_error"]


def test_get_spec_content(editor_client):
    """P12-A-4: GET /projects/{name}/specs/{path} returns raw Markdown."""
    r = editor_client.get("/api/v1/projects/test-proj/specs/010-login.md", headers=_vh())
    assert r.status_code == 200, r.text
    d = r.json()
    assert "Login works" in d["content"]
    assert d["project"] == "test-proj"
    assert d["rel_path"] == "010-login.md"


def test_get_spec_missing(editor_client):
    """P12-A-5: Missing spec returns 404."""
    r = editor_client.get("/api/v1/projects/test-proj/specs/999-nope.md", headers=_vh())
    assert r.status_code == 404


def test_path_traversal_rejected(editor_client):
    """P12-A-6: Path traversal attempt returns 400."""
    r = editor_client.get("/api/v1/projects/test-proj/specs/../../etc/passwd", headers=_vh())
    assert r.status_code in (400, 404)


# ─────────────────────────────────────────────────────────────────────────────
# P12-B: write endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_update_project_config(editor_client, specs_root):
    """P12-B-1: PUT /projects/{name}/config writes the project.yaml."""
    new_yaml = SAMPLE_PROJECT_YAML.replace("max_steps: 30", "max_steps: 50")
    r = editor_client.put(
        "/api/v1/projects/test-proj/config",
        headers=_op(),
        json={"raw_yaml": new_yaml},
    )
    assert r.status_code == 200, r.text
    # Verify file on disk
    with open(os.path.join(specs_root, "test-proj", "project.yaml")) as f:
        disk = f.read()
    assert "max_steps: 50" in disk


def test_update_project_config_bad_yaml(editor_client):
    """P12-B-2: Invalid YAML returns 422."""
    r = editor_client.put(
        "/api/v1/projects/test-proj/config",
        headers=_op(),
        json={"raw_yaml": "key: [unclosed"},
    )
    assert r.status_code == 422


def test_update_project_config_viewer_rejected(editor_client):
    """P12-B-3: Viewer token cannot write config."""
    r = editor_client.put(
        "/api/v1/projects/test-proj/config",
        headers=_vh("viewer"),
        json={"raw_yaml": SAMPLE_PROJECT_YAML},
    )
    assert r.status_code == 403


def test_write_spec_file(editor_client, specs_root):
    """P12-B-4: PUT /projects/{name}/specs/{path} creates a new spec file."""
    new_spec = "# Test: New spec\n\n## Goal\nDo something.\n\n## Assertions\n- It works.\n"
    r = editor_client.put(
        "/api/v1/projects/test-proj/specs/040-new.md",
        headers={**_op(), "Content-Type": "text/plain"},
        content=new_spec,
    )
    assert r.status_code == 200, r.text
    written = os.path.join(specs_root, "test-proj", "040-new.md")
    assert os.path.isfile(written)


def test_write_spec_non_md_rejected(editor_client):
    """P12-B-5: Non-.md extension returns 400."""
    r = editor_client.put(
        "/api/v1/projects/test-proj/specs/script.sh",
        headers={**_op(), "Content-Type": "text/plain"},
        content="rm -rf /",
    )
    assert r.status_code == 400


def test_create_project(editor_client, specs_root):
    """P12-B-6: compatibility POST creates a complete runnable project."""
    r = editor_client.post(
        "/api/v1/projects",
        headers=_op(),
        json={
            "dir_name": "new-feature",
            "display_name": "New Feature",
            "target_type": "local-app",
            "target_app": "xterm -T new-feat",
            "target_window": "new-feat",
            "schedule": "0 5 * * *",
        },
    )
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["dir_name"] == "new-feature"
    assert d["display_name"] == "New Feature"
    assert os.path.isdir(os.path.join(specs_root, "new-feature"))
    assert os.path.isfile(os.path.join(specs_root, "new-feature", "project.yaml"))
    assert os.path.isfile(os.path.join(specs_root, "new-feature", "000-first-test.md"))
    manual = Path(os.environ["TESTS_MANUALS_DIR"]) / "new-feature" / "manual.md"
    assert manual.is_file()
    assert "# New Feature operating manual" in manual.read_text(encoding="utf-8")
    assert d["manual_bootstrap"] == "created"
    project_yaml = Path(specs_root, "new-feature", "project.yaml").read_text(encoding="utf-8")
    assert "app: xterm -T new-feat" in project_yaml
    assert stat.S_IMODE(os.stat(os.path.join(specs_root, "new-feature")).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(os.path.join(specs_root, "new-feature", "project.yaml")).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(os.path.join(specs_root, "new-feature", "000-first-test.md")).st_mode) == 0o644
    assert stat.S_IMODE(manual.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(manual.stat().st_mode) == 0o644


def test_create_project_modes_ignore_restrictive_process_umask(editor_client, specs_root):
    previous = os.umask(0o077)
    try:
        response = editor_client.post(
            "/api/v1/projects",
            headers=_op(),
            json={"dir_name": "restricted-umask"},
        )
    finally:
        os.umask(previous)

    assert response.status_code == 201, response.text
    project = os.path.join(specs_root, "restricted-umask")
    assert stat.S_IMODE(os.stat(project).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(os.path.join(project, "project.yaml")).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(os.path.join(project, "000-first-test.md")).st_mode) == 0o644
    manual = Path(os.environ["TESTS_MANUALS_DIR"]) / "restricted-umask" / "manual.md"
    assert stat.S_IMODE(manual.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(manual.stat().st_mode) == 0o644
    project_yaml = Path(project, "project.yaml").read_text(encoding="utf-8")
    assert "/usr/bin/xmessage" in project_yaml
    assert "window: restricted-umask" in project_yaml


def test_compatibility_create_rejects_incomplete_remote_target(editor_client):
    response = editor_client.post(
        "/api/v1/projects",
        headers=_op(),
        json={"dir_name": "legacy-remote", "target_type": "vnc"},
    )

    assert response.status_code == 422
    assert "guided project builder" in response.text


def test_create_project_duplicate(editor_client):
    """P12-B-7: Duplicate dir_name returns 409."""
    r = editor_client.post(
        "/api/v1/projects",
        headers=_op(),
        json={"dir_name": "test-proj"},
    )
    assert r.status_code == 409


def test_create_project_unsafe_name(editor_client):
    """P12-B-8: Unsafe dir_name (spaces, slashes) returns 400."""
    for bad in ["../evil", "has space", "../../etc"]:
        r = editor_client.post(
            "/api/v1/projects",
            headers=_op(),
            json={"dir_name": bad},
        )
        assert r.status_code == 400, f"Expected 400 for {bad!r}, got {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# P12-C: delete endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_spec(editor_client, specs_root):
    """P12-C-1: DELETE removes the spec file."""
    path = os.path.join(specs_root, "test-proj", "020-logout.md")
    assert os.path.isfile(path)
    r = editor_client.delete("/api/v1/projects/test-proj/specs/020-logout.md", headers=_op())
    assert r.status_code == 200, r.text
    assert not os.path.isfile(path)


def test_delete_project_yaml_rejected(editor_client):
    """P12-C-2: Deleting project.yaml via spec endpoint returns 400."""
    r = editor_client.delete("/api/v1/projects/test-proj/specs/project.yaml", headers=_op())
    assert r.status_code == 400


def test_disable_project(editor_client, specs_root):
    """P12-C-3: DELETE /projects/{name} sets enabled: false."""
    r = editor_client.delete("/api/v1/projects/test-proj", headers=_op())
    assert r.status_code == 200, r.text
    with open(os.path.join(specs_root, "test-proj", "project.yaml")) as f:
        disk = f.read()
    assert "enabled: false" in disk


def test_disable_unknown_project(editor_client):
    """P12-C-4: Disabling unknown project returns 404."""
    r = editor_client.delete("/api/v1/projects/nobody", headers=_op())
    assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# P12-X-1: no circular import
# ─────────────────────────────────────────────────────────────────────────────

def test_no_circular_import():
    """P12-X-1: editor_routes can import without circular dependency."""
    import importlib, sys
    # Remove cached modules
    for key in list(sys.modules.keys()):
        if "dashboard" in key:
            del sys.modules[key]
    import dashboard.editor_routes  # should not raise
    assert hasattr(dashboard.editor_routes, "router")
