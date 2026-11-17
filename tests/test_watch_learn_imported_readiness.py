"""Imported-project Watch & Learn readiness remains explicit and target-free."""
from __future__ import annotations

import io
import json
from pathlib import Path
import stat

from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError
import pytest

from dashboard.auth import Actor, SESSION_COOKIE_NAME, SessionManager
from dashboard.authoring import (
    LocalAppTarget,
    ProjectDocument,
    SshJumpConnectionRoute,
    VncTarget,
)
from dashboard.capture_adapter import AdapterConnection, CaptureAdapterRegistry
from dashboard.config import DashboardSettings
from dashboard.demonstrations import DemonstrationError, DemonstrationService
from dashboard.target_probe import TargetProbeService
from dashboard.watch_learn_readiness import (
    ReadinessActivateRequest,
    ReadinessError,
    ReadinessPreviewRequest,
    ReadinessRevisionRequest,
    ReadinessSaveRequest,
    ReadinessTargetPreflightRequest,
    WatchLearnReadinessService,
)
from dashboard.watch_learn_readiness_routes import router as readiness_router


OPERATOR = Actor("oidc:readiness-one", "operator", "oidc", "One")
OTHER_OPERATOR = Actor("oidc:readiness-two", "operator", "oidc", "Two")
BOOTSTRAP = Actor("local-bootstrap-operator", "operator", "bootstrap-session", "Local")


def _settings(tmp_path: Path) -> DashboardSettings:
    project_dir = tmp_path / "specs" / "imported"
    manual_dir = project_dir / "manual"
    manual_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "project.yaml").write_text(
        "name: Imported\nmanual_dir: ./manual\n", encoding="utf-8"
    )
    (manual_dir / "manual.md").write_text("# Imported\n", encoding="utf-8")
    return DashboardSettings(
        auth_token="v" * 48,
        auth_operator_token="o" * 48,
        reports_dir=str(tmp_path / "reports"),
        specs_dir=str(tmp_path / "specs"),
        secrets_dir=str(tmp_path / "secrets"),
        watch_learn_state_root=str(tmp_path / "private" / "demonstrations"),
        watch_learn_readiness_root=str(tmp_path / "private" / "readiness"),
        project_import_audit_path=str(tmp_path / "private" / "project-import.jsonl"),
        watch_learn_max_owner_bytes=8 * 1024 * 1024,
    )


def _project(*, name: str = "imported") -> ProjectDocument:
    return ProjectDocument(
        dir_name=name,
        display_name="Imported",
        schedule="0 3 * * *",
        manual_dir="./manual",
        target=LocalAppTarget(app="python", window="Imported Application"),
        max_steps=30,
        max_seconds=1800,
    )


class AvailableLocalAdapter:
    target_type = "local-app"

    def __init__(self, *, width: int = 2, height: int = 2):
        image = Image.new("RGB", (width, height), color=(10, 20, 30))
        value = io.BytesIO()
        image.save(value, format="PNG")
        self.evidence = value.getvalue()
        self.disconnects: list[str] = []

    def available(self):
        return True, "Injected digest-pinned test adapter."

    def connect(self, session_id, _project, _privacy_revision):
        return AdapterConnection(self.evidence)

    def disconnect(self, session_id):
        self.disconnects.append(session_id)


class AvailableVncAdapter:
    target_type = "vnc"

    def available(self):
        return True, "Injected digest-pinned VNC test adapter."


class CompletedVersionProcess:
    returncode = 0
    pid = 123456

    def communicate(self, *, input=None, timeout=None):
        return b"approved-client 1.0\n", None


def _probe(settings: DashboardSettings, **kwargs) -> TargetProbeService:
    return TargetProbeService(settings, which=lambda _name: "/approved/runtime/client", **kwargs)


def _body(project_revision: str, target_revision: str, **updates) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 1,
        "adapter": "runner-local-app",
        "ready_window": "Imported Ready",
        "frame_width": 1280,
        "frame_height": 720,
        "redaction_regions": [{"x": 10, "y": 20, "width": 200, "height": 80}],
        "secret_references": [],
        "expected_project_revision": project_revision,
        "expected_target_revision": target_revision,
    }
    body.update(updates)
    return body


def _context(tmp_path: Path):
    settings = _settings(tmp_path)
    service = WatchLearnReadinessService(settings)
    project = _project()
    probe = _probe(settings)
    project_revision = "a" * 64
    target_revision = probe.target_revision(project)
    adapters = CaptureAdapterRegistry([AvailableLocalAdapter()])
    return settings, service, project, probe, project_revision, target_revision, adapters


def test_incomplete_import_is_structured_private_and_disabled_by_default(tmp_path):
    settings, service, project, probe, project_revision, target_revision, adapters = _context(tmp_path)

    result = service.inspect(
        OPERATOR, project, project_dir=None, project_revision=project_revision,
        base_target_revision=target_revision, probe_service=probe, adapters=adapters,
        imported_project=True,
    )

    states = {item.key: item.state for item in result.components}
    assert result.workflow_required is True
    assert result.contacts_target is False
    assert result.configuration is None
    assert result.connect_authorized is False
    assert states["adapter"] == "missing"
    assert states["ready-window"] == "missing"
    assert states["redaction"] == "missing"
    assert states["pre-relay-redaction"] == "pending"
    assert states["readiness-check"] == "pending"
    assert states["target-contact-activation"] == "pending"
    assert not Path(settings.watch_learn_readiness_root).exists()


def test_legacy_private_import_audit_enables_onboarding_without_guessing(tmp_path):
    settings, service, _project_value, _probe_value, _project_revision, _target_revision, _adapters = _context(tmp_path)
    project_dir = Path(settings.specs_dir) / "legacy-imported"
    project_dir.mkdir(parents=True)
    audit = Path(settings.project_import_audit_path)
    audit.parent.mkdir(parents=True)
    audit.write_text(json.dumps({
        "action": "apply", "result": "imported", "destination_slug": "legacy-imported",
    }) + "\n")
    audit.chmod(0o600)

    assert service.is_imported_project(project_dir) is True
    assert service.is_imported_project(project_dir.with_name("purpose-built")) is False


def test_purpose_built_project_behavior_is_unchanged(tmp_path):
    settings, service, _project_value, probe, project_revision, _target_revision, adapters = _context(tmp_path)
    purpose_built = _project(name="purpose-built").model_copy(update={
        "target": LocalAppTarget(
            app="python", window="Purpose Built", watch_learn_ready_window="Purpose Ready"
        ),
        "redaction": [[0, 0, 20, 20]],
    })
    target_revision = probe.target_revision(purpose_built)

    inspected = service.inspect(
        OPERATOR, purpose_built, project_dir=None, project_revision=project_revision,
        base_target_revision=target_revision, probe_service=probe, adapters=adapters,
        imported_project=False,
    )

    assert inspected.workflow_required is False
    assert inspected.configuration is None
    assert inspected.components[0].state == "not-required"
    with pytest.raises(ReadinessError, match="not created by project-folder import"):
        service.save(
            OPERATOR, purpose_built, project_revision=project_revision,
            base_target_revision=target_revision, imported_project=False,
            body=ReadinessSaveRequest.model_validate(
                {**_body(project_revision, target_revision), "confirm_security_values": True}
            ),
        )


def test_preview_and_validation_are_no_write_no_target_operations(tmp_path):
    settings, service, project, probe, project_revision, target_revision, _adapters = _context(tmp_path)
    request = ReadinessPreviewRequest.model_validate(_body(project_revision, target_revision))

    preview = service.preview(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision, imported_project=True, body=request,
        probe_service=probe,
    )

    assert preview.configuration is not None
    assert preview.configuration_revision is None
    assert preview.contacts_target is False
    assert not Path(settings.watch_learn_readiness_root).exists()
    assert project.target.watch_learn_ready_window is None
    assert project.redaction == []


def test_vnc_overlay_preserves_destination_and_uses_reference_names_only(tmp_path):
    settings = _settings(tmp_path)
    secrets = Path(settings.secrets_dir)
    secrets.mkdir(parents=True)
    for name in ("target.ref", "gateway.ref", "known-hosts.ref"):
        path = secrets / name
        path.write_text("test fixture\n")
        path.chmod(0o600)
    project = ProjectDocument(
        dir_name="imported-vnc", display_name="Imported VNC", manual_dir="./manual",
        target=VncTarget(
            host="target.example", port=5901, window="TigerVNC",
            route=SshJumpConnectionRoute(
                host="gateway.example", user="operator", port=2222,
            ),
        ),
        vnc_host_allowlist=["target.example"],
        ssh_host_allowlist=["gateway.example"],
        max_steps=30, max_seconds=1800,
    )
    probe = TargetProbeService(
        settings,
        connector=lambda *_args: (_ for _ in ()).throw(AssertionError("target contact")),
        which=lambda _name: "/approved/runtime/client",
        popen_factory=lambda *_args, **_kwargs: CompletedVersionProcess(),
    )
    service = WatchLearnReadinessService(settings)
    project_revision = "a" * 64
    target_revision = probe.target_revision(project)
    body = ReadinessSaveRequest.model_validate({
        **_body(
            project_revision, target_revision, adapter="runner-vnc",
            secret_references=[
                {"field": "password_file", "reference_name": "target.ref"},
                {"field": "gateway_password_file", "reference_name": "gateway.ref"},
                {"field": "route_known_hosts_file", "reference_name": "known-hosts.ref"},
            ],
        ),
        "confirm_security_values": True,
    })
    saved = service.save(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision, imported_project=True, body=body,
    )
    effective, record = service.effective_project(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision, imported_project=True,
    )
    assert record is not None
    assert effective.target.host == "target.example"
    assert effective.target.port == 5901
    assert effective.target.route.host == "gateway.example"
    assert effective.target.route.port == 2222
    assert effective.target.password_file == "target.ref"
    assert effective.target.gateway_password_file == "gateway.ref"
    assert effective.target.route.known_hosts_file == "known-hosts.ref"
    checked = service.check(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision,
        body=ReadinessRevisionRequest(configuration_revision=saved.configuration_revision),
        probe_service=probe,
        adapters=CaptureAdapterRegistry([AvailableVncAdapter()]),
    )
    assert checked.readiness_check_revision


def test_strict_schema_rejects_stale_destination_widening_secrets_and_bad_bounds(tmp_path):
    _settings_value, service, project, probe, project_revision, target_revision, _adapters = _context(tmp_path)
    with pytest.raises(ValidationError):
        ReadinessPreviewRequest.model_validate(
            _body(project_revision, target_revision, adapter="unknown-adapter")
        )
    with pytest.raises(ValidationError):
        ReadinessPreviewRequest.model_validate(
            {**_body(project_revision, target_revision), "host": "broadened.example"}
        )
    with pytest.raises(ValidationError):
        ReadinessPreviewRequest.model_validate(
            {**_body(project_revision, target_revision), "secret_value": "not-accepted"}
        )
    with pytest.raises(ValidationError):
        ReadinessPreviewRequest.model_validate(_body(
            project_revision, target_revision,
            secret_references=[{"field": "password_file", "reference_name": "unsafe..name"}],
        ))
    with pytest.raises(ValidationError):
        ReadinessPreviewRequest.model_validate(_body(
            project_revision, target_revision,
            frame_width=100,
            redaction_regions=[{"x": 90, "y": 0, "width": 11, "height": 1}],
        ))
    stale = ReadinessPreviewRequest.model_validate(_body("b" * 64, target_revision))
    with pytest.raises(ReadinessError) as caught:
        service.preview(
            OPERATOR, project, project_revision=project_revision,
            base_target_revision=target_revision, imported_project=True, body=stale,
            probe_service=probe,
        )
    assert caught.value.code == "revision_conflict"


def test_save_is_owner_scoped_and_requires_check_then_short_activation(tmp_path):
    _settings_value, service, project, probe, project_revision, target_revision, adapters = _context(tmp_path)
    save = ReadinessSaveRequest.model_validate({
        **_body(project_revision, target_revision), "confirm_security_values": True,
    })
    first = service.save(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision, imported_project=True, body=save,
    )
    other = service.inspect(
        OTHER_OPERATOR, project, project_dir=None, project_revision=project_revision,
        base_target_revision=target_revision, probe_service=probe, adapters=adapters,
        imported_project=True,
    )
    assert other.configuration is None
    other_project = _project(name="another-import")
    other_target_revision = probe.target_revision(other_project)
    same_owner_other_project = service.inspect(
        OPERATOR, other_project, project_dir=None, project_revision=project_revision,
        base_target_revision=other_target_revision, probe_service=probe, adapters=adapters,
        imported_project=True,
    )
    assert same_owner_other_project.configuration is None
    assert first.readiness_check_revision is None
    assert first.activation_revision is None
    record_path = next(Path(service.root).rglob("imported.json"))
    assert stat.S_IMODE(record_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(record_path.parent.stat().st_mode) == 0o700

    with pytest.raises(ReadinessError) as premature:
        service.activate(
            OPERATOR, project, project_revision=project_revision,
            base_target_revision=target_revision,
            body=ReadinessActivateRequest(
                configuration_revision=first.configuration_revision,
                readiness_check_revision="c" * 64,
                confirm_target_contact=True,
            ),
            probe_service=probe,
        )
    assert premature.value.code == "readiness_check_required"

    checked = service.check(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision,
        body=ReadinessRevisionRequest(configuration_revision=first.configuration_revision),
        probe_service=probe, adapters=adapters,
    )
    activated = service.activate(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision,
        body=ReadinessActivateRequest(
            configuration_revision=checked.configuration_revision,
            readiness_check_revision=checked.readiness_check_revision,
            confirm_target_contact=True,
        ),
        probe_service=probe,
    )
    assert service.activation_active(activated) is True
    assert service.readiness_check_active(activated, "f" * 64) is False
    assert service.activation_active(activated, "f" * 64) is False
    effective, active = service.require_activation(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision,
        body=ReadinessTargetPreflightRequest(
            configuration_revision=activated.configuration_revision,
            activation_revision=activated.activation_revision,
        ),
        probe_service=probe,
    )
    assert active.activation_revision == activated.activation_revision
    assert effective.target.watch_learn_ready_window == "Imported Ready"
    assert effective.redaction == [[10, 20, 200, 80]]

    second_save = ReadinessSaveRequest.model_validate({
        **_body(project_revision, target_revision, ready_window="Changed Ready"),
        "confirm_security_values": True,
    })
    changed = service.save(
        OPERATOR, project, project_revision=project_revision,
        base_target_revision=target_revision, imported_project=True, body=second_save,
    )
    assert changed.configuration_revision != first.configuration_revision
    assert changed.readiness_check_revision is None
    assert changed.activation_revision is None


def test_bootstrap_identity_cannot_read_or_write_private_readiness(tmp_path):
    _settings_value, service, project, probe, project_revision, target_revision, adapters = _context(tmp_path)
    with pytest.raises(ReadinessError) as caught:
        service.inspect(
            BOOTSTRAP, project, project_dir=None, project_revision=project_revision,
            base_target_revision=target_revision, probe_service=probe, adapters=adapters,
            imported_project=True,
        )
    assert caught.value.code == "unique_identity_required"


def _route_app(tmp_path: Path, monkeypatch):
    import dashboard.config as config_module

    settings = _settings(tmp_path)
    project_dir = Path(settings.specs_dir) / "imported"
    (project_dir / "manual").mkdir(parents=True, exist_ok=True)
    (project_dir / "manual" / "manual.md").write_text("# Manual\n")
    (project_dir / "010-smoke.md").write_text(
        "# Test: Imported\n\n## Goal\nInspect.\n\n## Assertions\n- Visible.\n"
    )
    (project_dir / "project.yaml").write_text(
        "name: Imported\nmanual_dir: ./manual\n"
        "target:\n  type: local-app\n  app: python\n  window: Imported Application\n"
        "schedule: '0 3 * * *'\nmax_steps: 30\nmax_seconds: 1800\nenabled: true\n"
    )
    (project_dir / "support").mkdir(exist_ok=True)
    (project_dir / "support" / "project-import-manifest.json").write_text(json.dumps({
        "version": 1, "origin": "project-folder-import", "files": [],
    }))
    monkeypatch.setattr(config_module, "settings", settings)
    monkeypatch.setenv("DASHBOARD_SPECS_DIR", settings.specs_dir)
    adapter = AvailableLocalAdapter()
    app = FastAPI()
    app.state.session_manager = SessionManager()
    app.state.watch_learn_readiness_service = WatchLearnReadinessService(settings)
    app.state.target_probe_service = _probe(
        settings,
        connector=lambda *_args: (_ for _ in ()).throw(AssertionError("target contact")),
        popen_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("process launch")),
    )
    app.state.demonstration_service = DemonstrationService(
        settings, adapters=CaptureAdapterRegistry([adapter])
    )
    app.include_router(readiness_router, prefix="/api/v1")
    return app


def _oidc_client(app: FastAPI, actor: Actor = OPERATOR):
    record = app.state.session_manager.create(actor)
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, record.actor.session_id)
    return client, {"X-CSRF-Token": record.csrf_token}


def test_readiness_routes_enforce_auth_csrf_and_target_free_validation(tmp_path, monkeypatch):
    app = _route_app(tmp_path, monkeypatch)
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/watch-learn/readiness/imported").status_code == 401
        viewer = anonymous.get(
            "/api/v1/watch-learn/readiness/imported",
            headers={"Authorization": "Bearer " + "v" * 48},
        )
        assert viewer.status_code == 403
        assert viewer.json()["detail"]["code"] == "operator_required"
    client, headers = _oidc_client(app)
    with client:
        inspection = client.get("/api/v1/watch-learn/readiness/imported")
        assert inspection.status_code == 200
        base = inspection.json()
        body = _body(base["project_revision"], base["base_target_revision"])
        mutation_cases = [
            ("post", "preview", body),
            ("post", "validate", body),
            ("put", "configuration", {**body, "confirm_security_values": True}),
            ("post", "check", {"configuration_revision": "d" * 64}),
            ("post", "activate", {
                "configuration_revision": "d" * 64,
                "readiness_check_revision": "e" * 64,
                "confirm_target_contact": True,
            }),
            ("post", "target-preflight", {
                "configuration_revision": "d" * 64,
                "activation_revision": "e" * 64,
            }),
        ]
        for method, endpoint, payload in mutation_cases:
            denied = getattr(client, method)(
                f"/api/v1/watch-learn/readiness/imported/{endpoint}", json=payload
            )
            assert denied.status_code == 403
            assert denied.json()["detail"]["code"] == "csrf_required"
        preview = client.post(
            "/api/v1/watch-learn/readiness/imported/validate", headers=headers, json=body
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["contacts_target"] is False
        blocked = client.post(
            "/api/v1/watch-learn/readiness/imported/target-preflight",
            headers=headers,
            json={"configuration_revision": "d" * 64, "activation_revision": "e" * 64},
        )
        assert blocked.status_code == 403
        assert blocked.json()["detail"]["code"] == "target_contact_activation_required"


def test_saved_frame_contract_is_enforced_before_evidence_is_accepted(tmp_path):
    settings = _settings(tmp_path)
    adapter = AvailableLocalAdapter(width=2, height=2)
    demonstrations = DemonstrationService(
        settings, adapters=CaptureAdapterRegistry([adapter])
    )
    project = _project().model_copy(update={
        "target": LocalAppTarget(
            app="python", window="Imported Application", watch_learn_ready_window="Imported Ready"
        ),
        "redaction": [[0, 0, 1, 1]],
    })
    created = demonstrations.create(
        OPERATOR, project=project, project_revision="a" * 64,
        target_revision="b" * 64, privacy_revision="c" * 64,
        operator_goal="Inspect imported application",
        readiness_configuration_revision="d" * 64,
        frame_contract_width=1280, frame_contract_height=720,
    )
    with pytest.raises(DemonstrationError) as caught:
        demonstrations.connect(
            OPERATOR, created.session_id, expected_version=created.version,
            request_project_revision=created.project_revision,
            request_target_revision=created.target_revision,
            request_privacy_revision=created.privacy_revision,
            project=project, project_revision=created.project_revision,
            target_revision=created.target_revision, privacy_revision=created.privacy_revision,
            privacy_ready=True, preflight_revision=created.target_revision,
            preflight_satisfies=True, readiness_configuration_revision="d" * 64,
        )
    assert getattr(caught.value, "code", None) == "frame_contract_mismatch"
    failed = demonstrations.get(OPERATOR, created.session_id)
    assert failed.state == "connection_failed"
    assert failed.evidence == []
    assert adapter.disconnects == [created.session_id]


def test_operator_page_exposes_bounded_imported_readiness_workflow_only():
    page = (
        Path(__file__).resolve().parents[1]
        / "templates" / "dashboard" / "watch_learn.html"
    ).read_text(encoding="utf-8")
    for value in (
        'id="readiness-panel"', 'id="readiness-adapter"',
        'id="readiness-window"', 'id="readiness-frame-width"',
        'id="readiness-redact-x"', 'id="readiness-password-file"',
        'id="readiness-preview"', 'id="readiness-validate"',
        'id="readiness-save"', 'id="readiness-check"',
        'id="readiness-activate"', "/target-preflight",
        "confirm_security_values:true", "confirm_target_contact:true",
        "readiness_configuration_revision:capability.readiness_configuration_revision",
    ):
        assert value in page
    for forbidden in (
        'id="readiness-host"', 'id="readiness-port"',
        'id="readiness-route"', 'id="readiness-secret-value"',
    ):
        assert forbidden not in page
