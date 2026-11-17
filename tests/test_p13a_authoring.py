"""Phase 13A typed authoring contract and semantic linting tests.

These tests use only temporary files and FastAPI's in-process client.  They
never launch targets, inspect secret contents, invoke a model, or contact a
network service.
"""
from __future__ import annotations

import importlib
import os
import stat

import pytest
import yaml
from fastapi.testclient import TestClient

from dashboard.authoring import (
    AuthoringValidationError,
    HostAppTarget,
    LocalAppTarget,
    ProjectDocument,
    RdpTarget,
    SpecDocument,
    SshTerminalTarget,
    SshJumpConnectionRoute,
    VncTarget,
    parse_project_document,
    parse_spec_document,
    render_project_yaml,
    validate_project_for_apply,
)


RDP_CERTIFICATE = {
    "certificate_name": "WIN01",
    "certificate_fingerprint": "sha256:" + "a" * 64,
}


def _manual(tmp_path, name="test-proj"):
    manual_dir = tmp_path / "tests_manuals" / name
    manual_dir.mkdir(parents=True, exist_ok=True)
    (manual_dir / "manual.md").write_text("# Operator manual\n\nUse the app safely.\n")
    return manual_dir


def _project(tmp_path, target=None, *, name="test-proj"):
    manual_dir = _manual(tmp_path, name)
    return ProjectDocument(
        dir_name=name,
        display_name="Test Project",
        enabled=True,
        schedule="0 3 * * *",
        manual_dir=str(manual_dir),
        target=target or LocalAppTarget(app="xterm -T test", window="test"),
        max_steps=30,
        max_seconds=1800,
    )


def _errors(call):
    with pytest.raises(AuthoringValidationError) as exc:
        call()
    return {item.code for item in exc.value.diagnostics if item.severity == "error"}


@pytest.mark.parametrize(
    "target",
    [
        LocalAppTarget(app="xterm -T local", window="local"),
        HostAppTarget(app="/opt/app/run.sh", cwd="/opt/app", window="host", startup_timeout=60),
        SshTerminalTarget(host="build01", user="ci", key="id_build01", window="ssh-build01"),
        RdpTarget(
            host="win01",
            user="Administrator",
            password_file="win01.pw",
            window="win01",
            **RDP_CERTIFICATE,
        ),
        VncTarget(host="vnc01", port=5901, password_file="vnc01.pw", window="vnc01"),
    ],
)
def test_all_target_documents_parse_render_and_round_trip(tmp_path, target):
    document = _project(tmp_path, target)
    if isinstance(target, SshTerminalTarget):
        document = document.model_copy(update={"ssh_host_allowlist": ["build01"]})
    elif isinstance(target, RdpTarget):
        document = document.model_copy(update={"rdp_host_allowlist": ["win01"]})
    elif isinstance(target, VncTarget):
        document = document.model_copy(update={"vnc_host_allowlist": ["vnc01"]})

    normalised, rendered, diagnostics = validate_project_for_apply(
        document, require_manual_on_disk=True
    )
    assert not [item for item in diagnostics if item.severity == "error"]
    reparsed = parse_project_document(rendered, dir_name=document.dir_name)
    assert reparsed.document.target.type == target.type
    assert render_project_yaml(normalised) == rendered


def test_authoring_rejects_target_and_safety_failures(tmp_path):
    assert "target_required" in _errors(lambda: validate_project_for_apply(
        _project(tmp_path, LocalAppTarget(app=None, window="x")), require_manual_on_disk=True
    ))
    assert "target_allowlist" in _errors(lambda: validate_project_for_apply(
        _project(tmp_path, SshTerminalTarget(host="not-allowed", window="ssh")), require_manual_on_disk=True
    ))
    assert "secret_reference" in _errors(lambda: validate_project_for_apply(
        _project(
            tmp_path,
            RdpTarget(
                host="win01", password_file="../password", window="rdp",
                **RDP_CERTIFICATE,
            ),
        ).model_copy(update={"rdp_host_allowlist": ["win01"]}),
        require_manual_on_disk=True,
    ))
    assert "rdp_extra_args_password" in _errors(lambda: validate_project_for_apply(
        _project(
            tmp_path,
            RdpTarget(
                host="win01", extra_args="/p:not-allowed", window="rdp",
                **RDP_CERTIFICATE,
            ),
        ).model_copy(update={"rdp_host_allowlist": ["win01"]}),
        require_manual_on_disk=True,
    ))


def test_rdp_compatibility_arguments_are_normalised_with_diagnostic(tmp_path):
    document = _project(
        tmp_path,
        RdpTarget(
            host="win01", window="rdp",
            extra_args="/gdi:sw /gfx- /cert:ignore /cert:tofu",
            **RDP_CERTIFICATE,
        ),
    ).model_copy(update={"rdp_host_allowlist": ["win01"]})
    normalised, rendered, diagnostics = validate_project_for_apply(document, require_manual_on_disk=True)
    assert normalised.target.extra_args == "/gdi:sw"
    assert "/gfx-" not in rendered and "/cert:ignore" not in rendered
    assert {item.code for item in diagnostics} >= {
        "rdp_extra_args_gfx_normalized", "rdp_extra_args_cert_normalized"
    }


def test_rdp_certificate_identity_is_required_and_normalised(tmp_path):
    base = _project(tmp_path, RdpTarget(host="win01", window="rdp")).model_copy(
        update={"rdp_host_allowlist": ["win01"]}
    )
    missing = _errors(lambda: validate_project_for_apply(
        base, require_manual_on_disk=True
    ))
    assert missing >= {
        "rdp_certificate_name_required",
        "rdp_certificate_fingerprint_required",
    }

    invalid = base.model_copy(update={"target": RdpTarget(
        host="win01",
        window="rdp",
        certificate_name="unsafe name",
        certificate_fingerprint="sha256:not-a-digest",
    )})
    invalid_codes = _errors(lambda: validate_project_for_apply(
        invalid, require_manual_on_disk=True
    ))
    assert invalid_codes >= {
        "rdp_certificate_name_invalid",
        "rdp_certificate_fingerprint_invalid",
    }

    separated = base.model_copy(update={"target": RdpTarget(
        host="win01",
        window="rdp",
        certificate_name=" WIN01 ",
        certificate_fingerprint="SHA256:" + ":".join(["AA"] * 32),
    )})
    normalised, rendered, diagnostics = validate_project_for_apply(
        separated, require_manual_on_disk=True
    )
    assert not [item for item in diagnostics if item.severity == "error"]
    assert normalised.target.certificate_name == "WIN01"
    assert normalised.target.certificate_fingerprint == "sha256:" + "aa" * 32
    assert "certificate_name: WIN01" in rendered
    assert "certificate_fingerprint: sha256:" in rendered


def test_vnc_ssh_jump_route_requires_allowlist_known_hosts_and_gateway_password(tmp_path):
    target = VncTarget(
        host="vnc01", port=5900, password_file="vnc.pass", window="TigerVNC",
        watch_learn_ready_window="Remote Desktop",
        gateway_password_file="jump.pw",
        route=SshJumpConnectionRoute(
            host="jump01", user="operator", port=22,
            known_hosts_file="jump.known_hosts",
        ),
    )
    document = _project(tmp_path, target).model_copy(update={
        "vnc_host_allowlist": ["vnc01"], "ssh_host_allowlist": ["jump01"]
    })
    normalised, rendered, diagnostics = validate_project_for_apply(
        document, require_manual_on_disk=True
    )
    assert not [item for item in diagnostics if item.severity == "error"]
    assert "watch_learn_ready_window: Remote Desktop" in rendered
    assert "known_hosts_file: jump.known_hosts" in rendered
    assert normalised.target.route.type == "ssh-jump"


def test_authoring_rejects_limits_cron_redaction_and_missing_manual(tmp_path):
    assert "limit_range" in _errors(lambda: validate_project_for_apply(
        _project(tmp_path).model_copy(update={"max_steps": 0}), require_manual_on_disk=True
    ))
    assert "schedule_invalid" in _errors(lambda: validate_project_for_apply(
        _project(tmp_path).model_copy(update={"schedule": "every midnight"}), require_manual_on_disk=True
    ))
    assert "redaction_bounds" in _errors(lambda: validate_project_for_apply(
        _project(tmp_path).model_copy(update={"redaction": [[0, 0, 0, 1]]}), require_manual_on_disk=True
    ))
    missing = _project(tmp_path).model_copy(update={"manual_dir": str(tmp_path / "absent")})
    assert "manual_missing" in _errors(lambda: validate_project_for_apply(missing, require_manual_on_disk=True))


@pytest.mark.parametrize(
    "markdown",
    [
        "# Test: no goal\n\n## Assertions\n- one\n",
        "# Test: no assertions\n\n## Goal\nSomething\n",
        "# Test: target\n\n## Goal\nSomething\n\n## Target\nrdp\n\n## Assertions\n- one\n",
    ],
)
def test_authoring_rejects_malformed_specs(markdown):
    codes = _errors(lambda: parse_spec_document(markdown, path="010-test.md"))
    assert codes & {"spec_parse", "assertions_required"}


def test_authoring_rejects_traversal_spec_path():
    codes = _errors(lambda: parse_spec_document(
        "# Test: x\n\n## Goal\nG\n\n## Assertions\n- one\n", path="sub/../escape.md"
    ))
    assert "spec_path" in codes


def test_unknown_legacy_yaml_is_preserved_but_sensitive_unknown_is_not_exposed():
    parsed = parse_project_document(
        """name: Existing
manual_dir: /tmp/manual
target:
  type: local-app
  app: xterm
  window: xterm
legacy_tuning: 3
""",
        dir_name="existing",
    )
    assert parsed.document.legacy["legacy_tuning"] == 3
    assert "legacy_tuning: 3" in render_project_yaml(parsed.document)
    codes = _errors(lambda: parse_project_document(
        """name: Existing
manual_dir: /tmp/manual
target: {type: local-app, app: xterm, window: xterm}
private_token: should-not-be-returned
""",
        dir_name="existing",
    ))
    assert "legacy_sensitive_field" in codes


def _make_authoring_app(specs_root, manuals_root, reports_root):
    for key in list(os.environ):
        if key.startswith("DASHBOARD_") or key == "TESTS_SPECS_DIR":
            del os.environ[key]
    os.environ.update({
        "DASHBOARD_AUTH_TOKEN": "viewer",
        "DASHBOARD_AUTH_OPERATOR_TOKEN": "operator",
        "DASHBOARD_SPECS_DIR": str(specs_root),
        "DASHBOARD_REPORTS_DIR": str(reports_root),
        "DASHBOARD_INDEX_INTERVAL": "999",
        "TESTS_MANUALS_DIR": str(manuals_root),
    })
    import dashboard.config as dcfg
    import dashboard.app as dapp
    import dashboard.editor_routes as der
    import dashboard.index as didx
    import dashboard.routes as droutes

    for module in (dcfg, der, droutes, didx, dapp):
        importlib.reload(module)
    from dashboard.app import create_app
    return create_app()


@pytest.fixture()
def authoring_client(tmp_path):
    specs_root = tmp_path / "tests_specs"
    project_dir = specs_root / "test-proj"
    manual_dir = _manual(tmp_path)
    project_dir.mkdir(parents=True)
    (project_dir / "project.yaml").write_text(
        "name: Test Project\n"
        f"manual_dir: {manual_dir}\n"
        "target:\n  type: local-app\n  app: xterm -T test\n  window: test\n"
        "schedule: '0 3 * * *'\nmax_steps: 30\nmax_seconds: 1800\nenabled: true\n"
    )
    (project_dir / "010-test.md").write_text(
        "# Test: Existing\n\n## Goal\nCheck the app.\n\n## Assertions\n- A visible result is present.\n"
    )
    reports_root = tmp_path / "reports"
    reports_root.mkdir()
    app = _make_authoring_app(specs_root, tmp_path / "tests_manuals", reports_root)
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client, project_dir, tmp_path / "tests_manuals"


def _viewer():
    return {"Authorization": "Bearer viewer"}


def _operator():
    return {"Authorization": "Bearer operator"}


def test_authoring_api_operator_gate_validate_and_no_write_on_failure(authoring_client):
    client, project_dir, _manuals = authoring_client
    read = client.get("/api/v1/projects/Test%20Project/authoring", headers=_viewer())
    assert read.status_code == 200, read.text
    response = read.json()
    assert response["document"]["display_name"] == "Test Project"
    baseline = (project_dir / "project.yaml").read_text()

    viewer = client.post(
        "/api/v1/projects/Test%20Project/authoring/project/validate",
        headers=_viewer(), json={"document": response["document"]},
    )
    assert viewer.status_code == 403

    bad_document = response["document"]
    bad_document["target"]["app"] = ""
    invalid = client.post(
        "/api/v1/projects/Test%20Project/authoring/project/validate",
        headers=_operator(), json={"document": bad_document},
    )
    assert invalid.status_code == 422
    assert (project_dir / "project.yaml").read_text() == baseline


def test_authoring_api_revision_conflict_preserves_current_source(authoring_client):
    client, project_dir, _manuals = authoring_client
    read = client.get("/api/v1/projects/Test%20Project/authoring", headers=_viewer())
    assert read.status_code == 200
    stale = read.json()
    current = (project_dir / "project.yaml").read_text() + "# changed by another editor\n"
    (project_dir / "project.yaml").write_text(current)
    response = client.put(
        "/api/v1/projects/Test%20Project/authoring/project",
        headers=_operator(),
        json={"base_revision": stale["revision"], "document": stale["document"]},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["current_revision"] != stale["revision"]
    assert (project_dir / "project.yaml").read_text() == current


def test_authoring_spec_list_preview_create_and_duplicate_are_typed(authoring_client):
    client, project_dir, _manuals = authoring_client
    invalid_path = project_dir / "020-incomplete.md"
    invalid_path.write_text("# Test: Incomplete\n\n## Goal\nMissing assertions.\n")

    listing = client.get(
        "/api/v1/projects/Test%20Project/authoring/specs",
        headers=_viewer(),
    )
    assert listing.status_code == 200, listing.text
    listed = {item["path"]: item for item in listing.json()}
    assert listed["010-test.md"]["title"] == "Existing"
    assert listed["020-incomplete.md"]["diagnostics"]
    assert "content" not in listed["020-incomplete.md"]

    candidate = {
        "path": "030-guided.md",
        "title": "Guided spec",
        "goal": "Verify structured authoring.",
        "assertions": ["The project has a canonical spec."],
    }
    viewer = client.post(
        "/api/v1/projects/Test%20Project/authoring/specs/validate",
        headers=_viewer(),
        json={"document": candidate},
    )
    assert viewer.status_code == 403

    preview = client.post(
        "/api/v1/projects/Test%20Project/authoring/specs/validate",
        headers=_operator(),
        json={"document": candidate},
    )
    assert preview.status_code == 200, preview.text
    assert not (project_dir / "030-guided.md").exists()
    assert preview.json()["rendered_markdown"].startswith("# Test: Guided spec")

    created = client.post(
        "/api/v1/projects/Test%20Project/authoring/specs",
        headers=_operator(),
        json={"document": candidate},
    )
    assert created.status_code == 201, created.text
    written = (project_dir / "030-guided.md").read_text()
    assert written == created.json()["rendered_markdown"]

    duplicate = client.post(
        "/api/v1/projects/Test%20Project/authoring/specs",
        headers=_operator(),
        json={"document": candidate},
    )
    assert duplicate.status_code == 409
    assert (project_dir / "030-guided.md").read_text() == written


def test_authoring_new_spec_rejects_invalid_input_without_a_write(authoring_client):
    client, project_dir, _manuals = authoring_client
    response = client.post(
        "/api/v1/projects/Test%20Project/authoring/specs/validate",
        headers=_operator(),
        json={
            "document": {
                "path": "../escape.md",
                "title": "Unsafe",
                "goal": "Must not write.",
                "assertions": ["No file is created."],
            }
        },
    )
    assert response.status_code == 422
    assert not (project_dir.parent / "escape.md").exists()
    assert not (project_dir / "escape.md").exists()


def test_authoring_spec_revision_conflict_preserves_current_source(authoring_client):
    client, project_dir, _manuals = authoring_client
    read = client.get(
        "/api/v1/projects/Test%20Project/authoring/specs/010-test.md",
        headers=_viewer(),
    )
    assert read.status_code == 200, read.text
    stale = read.json()
    current = (project_dir / "010-test.md").read_text() + "\n<!-- changed elsewhere -->\n"
    (project_dir / "010-test.md").write_text(current)
    response = client.put(
        "/api/v1/projects/Test%20Project/authoring/specs/010-test.md",
        headers=_operator(),
        json={"base_revision": stale["revision"], "document": stale["document"]},
    )
    assert response.status_code == 409
    assert (project_dir / "010-test.md").read_text() == current


def test_authoring_create_preview_derives_manual_path_without_writing(authoring_client):
    client, project_dir, manuals_root = authoring_client
    payload = {
        "document": {
            "dir_name": "preview-only",
            "display_name": "Preview only",
            "enabled": True,
            "schedule": "0 4 * * *",
            "target": {"type": "local-app", "app": "xterm -T preview", "window": "preview"},
            "max_steps": 30,
            "max_seconds": 1800,
        },
        "initial_spec": {
            "path": "000-first.md",
            "title": "Preview spec",
            "goal": "Validate before any source is created.",
            "assertions": ["No project directory exists after preview."],
        },
    }
    preview = client.post(
        "/api/v1/projects/authoring/validate",
        headers=_operator(),
        json=payload,
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["manual_bootstrap"] == "will_create_manual"
    assert not (project_dir.parent / "preview-only").exists()
    assert not (manuals_root / "preview-only").exists()

    created = client.post(
        "/api/v1/projects/authoring",
        headers=_operator(),
        json=payload,
    )
    assert created.status_code == 201, created.text
    assert (project_dir.parent / "preview-only" / "project.yaml").is_file()
    assert (manuals_root / "preview-only" / "manual.md").is_file()


def test_authoring_api_create_bootstraps_manual_and_runner_modes(authoring_client):
    client, _project_dir, manuals_root = authoring_client
    manual_dir = manuals_root / "new-typed"
    response = client.post(
        "/api/v1/projects/authoring",
        headers=_operator(),
        json={
            "document": {
                "dir_name": "new-typed",
                "display_name": "New Typed",
                "enabled": True,
                "schedule": "0 4 * * *",
                "manual_dir": str(manual_dir),
                "target": {"type": "local-app", "app": "xterm -T typed", "window": "typed"},
                "max_steps": 30,
                "max_seconds": 1800,
            },
            "initial_spec": {
                "path": "000-first.md",
                "title": "First typed test",
                "goal": "Verify the initial workspace.",
                "assertions": ["A visible initial state is present."],
            },
        },
    )
    assert response.status_code == 201, response.text
    specs_root = _project_dir.parent
    assert (specs_root / "new-typed" / "project.yaml").is_file()
    assert (specs_root / "new-typed" / "000-first.md").is_file()
    assert (manual_dir / "manual.md").is_file()
    assert stat.S_IMODE((specs_root / "new-typed").stat().st_mode) == 0o755
    assert stat.S_IMODE((specs_root / "new-typed" / "project.yaml").stat().st_mode) == 0o644
    assert stat.S_IMODE((manual_dir / "manual.md").stat().st_mode) == 0o644
    parsed = yaml.safe_load((specs_root / "new-typed" / "project.yaml").read_text())
    assert parsed["manual_dir"] == str(manual_dir)
