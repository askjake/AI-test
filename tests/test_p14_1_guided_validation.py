"""Phase 14.1 guided validation and isolated target-preflight contract."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard.authoring import (
    LocalAppTarget,
    ProjectDocument,
    RdpTarget,
    SpecDocument,
    SshJumpConnectionRoute,
    SshTerminalTarget,
    VncTarget,
)
from dashboard.config import DashboardSettings
from dashboard.target_probe import (
    TargetProbeCheck,
    TargetProbeRequest,
    TargetProbeService,
    TargetProbeValidationError,
)
from dashboard.target_setup import TargetSetupService
from dashboard.wizard import ProjectWizardService, WizardAssessmentRequest, assess_readiness
from dashboard.wizard_routes import router as wizard_router


ROOT = Path(__file__).parents[1]
TEMPLATE = (ROOT / "templates" / "dashboard" / "index.html").read_text()


def _settings(tmp_path: Path) -> DashboardSettings:
    return DashboardSettings(
        auth_token="viewer",
        auth_operator_token="operator",
        reports_dir=str(tmp_path / "reports"),
        specs_dir=str(tmp_path / "specs"),
        wizard_state_root=str(tmp_path / "wizard-state"),
        wizard_blueprint_root=str(ROOT / "project_blueprints"),
        secrets_dir=str(tmp_path / "secrets"),
        wizard_probe_timeout_seconds=0.25,
        wizard_probe_ttl_seconds=30,
        wizard_probe_output_bytes=1_024,
    )


def _spec(path: str = "000-initial.md", *, assertions: list[str] | None = None) -> SpecDocument:
    return SpecDocument(
        path=path,
        title="Initial visible state",
        goal="Confirm the expected visible state.",
        assertions=["The expected surface is visible."] if assertions is None else assertions,
    )


def _local_project(name: str = "sample") -> ProjectDocument:
    return ProjectDocument(
        dir_name=name,
        display_name="Sample",
        schedule="0 3 * * *",
        target=LocalAppTarget(app="example-app", window="Example"),
        max_steps=30,
        max_seconds=1800,
    )


def _all_passed_checks() -> list[TargetProbeCheck]:
    return [
        TargetProbeCheck(stage=stage, status="passed", detail="Mocked safe proof.")
        for stage in (
            "static-policy",
            "secret-reference",
            "client-runtime",
            "transport",
            "authentication-session",
            "expected-window",
        )
    ]


def test_template_guards_every_forward_path_and_marks_fields_only_after_attempt():
    for required in (
        "async function wizardGoStep(step, options)",
        "wizardGuardTransition(requestedStep)",
        "showWizardGateFailure(failures, requestedStep)",
        'item.category === "must-resolve"',
        "wizardGuardBusy",
        "wizardAttemptedSteps",
        'field.setAttribute("aria-invalid", "true")',
        'field.setAttribute("aria-describedby", errorId)',
        "field-error-inline",
        "clearAuthoringFieldInvalid",
        "field.closest(\"[hidden]\")",
        "The plan job is still ",
        "disabled aria-describedby=\"wizard-context-status\"",
        "Validate step and continue",
        "await wizardGoStep(3)",
        "await wizardGoStep(4)",
    ):
        assert required in TEMPLATE
    # Initial markup does not eagerly label every blank input as invalid.
    initial_form = TEMPLATE[TEMPLATE.index("function authoringMarkup()") : TEMPLATE.index("function boundedAuthoringDiff")]
    assert 'aria-invalid="true"' not in initial_form
    assert "renderWizardStep(requested)" in TEMPLATE
    assert "renderWizardStep(earliest)" in TEMPLATE


def test_template_uses_one_write_only_password_input_and_complete_validation_route():
    for field in ("pa-rdp-password", "pa-vnc-password"):
        assert f'id="{field}" type="password"' in TEMPLATE
    assert 'id="pa-gateway-password" type="password"' in TEMPLATE
    assert "Via approved SSH jump host" in TEMPLATE
    assert "password-confirm" not in TEMPLATE
    assert "ids.confirm" not in TEMPLATE
    assert "password !== confirmation" not in TEMPLATE
    draft = TEMPLATE[TEMPLATE.index("function saveWizardDraft()") : TEMPLATE.index("function restoreWizardDraft()")]
    assert "password" not in draft.lower()
    assert "/authoring/wizard/validate" in TEMPLATE
    assert "specifications: wizardCurrentSpecs()" in TEMPLATE
    assert "Validate project and test target" in TEMPLATE
    assert "Test target now" in TEMPLATE
    assert "Typed documents:" in TEMPLATE
    assert "Target policy:" in TEMPLATE
    assert "Target probe:" in TEMPLATE
    assert "Optional for ordinary runs. Watch &amp; Learn requires at least one valid fixed-region rectangle" in TEMPLATE
    assert "If this slug already exists, open that project or choose a new slug." in TEMPLATE
    assert "Existing content was not changed. Open the existing project or choose a new slug." in TEMPLATE


def test_static_invalid_probe_performs_no_process_network_or_hook_activity(tmp_path):
    calls: list[str] = []
    service = TargetProbeService(
        _settings(tmp_path),
        connector=lambda *_args: calls.append("network"),
        popen_factory=lambda *_args, **_kwargs: calls.append("process"),
        which=lambda _name: calls.append("which"),
        probe_hook=lambda _project: calls.append("hook"),
    )
    invalid = ProjectDocument(
        dir_name="sample",
        display_name="Sample",
        schedule="0 3 * * *",
        target=RdpTarget(host="not-allowed", window="RDP"),
        rdp_host_allowlist=["allowed"],
        max_steps=30,
        max_seconds=1800,
    )
    with pytest.raises(TargetProbeValidationError, match="Static target validation"):
        service.run(TargetProbeRequest(project=invalid))
    assert calls == []
    assert service.audit() == []


def test_transport_authentication_and_window_are_distinct_and_redacted(tmp_path):
    settings = _settings(tmp_path)
    secret_root = Path(settings.secrets_dir)
    secret_root.mkdir()
    password = "never-reflect-this-value"
    secret = secret_root / "target.rdp.pw"
    secret.write_text(password)
    secret.chmod(0o600)
    connections: list[tuple[str, int, float]] = []
    project = ProjectDocument(
        dir_name="rdp-sample",
        display_name="RDP Sample",
        schedule="0 3 * * *",
        target=RdpTarget(
            host="rdp.example",
            user="operator",
            password_file="target.rdp.pw",
            certificate_name="RDP-EXAMPLE",
            certificate_fingerprint="sha256:" + "a" * 64,
            window="orchestrator-rdp",
        ),
        rdp_host_allowlist=["rdp.example"],
        max_steps=30,
        max_seconds=1800,
    )

    class VersionProcess:
        pid = 9001
        returncode = 0

        def communicate(self, **_kwargs):
            return b"FreeRDP version mocked", None

    service = TargetProbeService(
        settings,
        connector=lambda host, port, timeout: connections.append((host, port, timeout)),
        popen_factory=lambda *_args, **_kwargs: VersionProcess(),
        which=lambda name: f"/mock/{name}",
    )
    result = service.run(TargetProbeRequest(project=project))
    checks = {item.stage: item.status for item in result.checks}
    assert checks["static-policy"] == "passed"
    assert checks["secret-reference"] == "passed"
    assert checks["transport"] == "passed"
    assert checks["authentication-session"] == "unsupported"
    assert checks["expected-window"] == "unsupported"
    assert result.outcome == "partial"
    assert connections == [("rdp.example", 3389, 0.25)]
    rendered = result.model_dump_json() + json.dumps([item.model_dump() for item in service.audit()])
    assert password not in rendered
    assert str(secret_root) not in rendered
    assert "rdp.example" not in json.dumps([item.model_dump() for item in service.audit()])


def test_ssh_session_uses_fixed_bounded_argv_and_never_shell(tmp_path):
    commands: list[tuple[list[str], dict]] = []

    class Process:
        pid = 41
        returncode = 0

        def communicate(self, **_kwargs):
            return b"mocked", None

    def popen(argv, **kwargs):
        commands.append((argv, kwargs))
        return Process()

    project = ProjectDocument(
        dir_name="ssh-sample",
        display_name="SSH Sample",
        schedule="0 3 * * *",
        target=SshTerminalTarget(host="ssh.example", user="operator", window="SSH"),
        ssh_host_allowlist=["ssh.example"],
        max_steps=30,
        max_seconds=1800,
    )
    service = TargetProbeService(
        _settings(tmp_path),
        connector=lambda *_args: None,
        popen_factory=popen,
        which=lambda name: f"/mock/{name}",
    )
    result = service.run(TargetProbeRequest(project=project))
    session = commands[-1]
    assert session[0][-2:] == ["operator@ssh.example", "exit"]
    assert session[1]["start_new_session"] is True
    assert "shell" not in session[1]
    assert {item.stage: item.status for item in result.checks}["authentication-session"] == "passed"
    assert result.outcome == "partial"  # no viewer/window is invented


def test_vnc_jump_preflight_contacts_only_gateway_and_uses_strict_host_key(tmp_path):
    settings = _settings(tmp_path)
    secrets = Path(settings.secrets_dir)
    secrets.mkdir()
    for name, value in (
        ("gateway.pw", "gateway-secret\n"),
        ("gateway.known_hosts", "gateway.example ssh-ed25519 AAAATEST\n"),
        ("target.vncpass", "opaque-vnc-value"),
    ):
        path = secrets / name
        path.write_text(value)
        path.chmod(0o600)
    commands: list[list[str]] = []
    connections: list[tuple[str, int, float]] = []

    class Process:
        pid = 77
        returncode = 0

        def communicate(self, **_kwargs):
            return b"mocked", None

    def launch(argv, **_kwargs):
        commands.append(list(argv))
        return Process()

    project = ProjectDocument(
        dir_name="jump-vnc",
        display_name="Jump VNC",
        schedule="0 3 * * *",
        target=VncTarget(
            host="vnc.internal",
            port=5900,
            password_file="target.vncpass",
            gateway_password_file="gateway.pw",
            window="TigerVNC",
            watch_learn_ready_window="TigerVNC",
            route=SshJumpConnectionRoute(
                host="gateway.example",
                user="operator",
                port=22,
                known_hosts_file="gateway.known_hosts",
            ),
        ),
        ssh_host_allowlist=["gateway.example"],
        vnc_host_allowlist=["vnc.internal"],
        max_steps=30,
        max_seconds=1800,
    )
    service = TargetProbeService(
        settings,
        connector=lambda host, port, timeout: connections.append((host, port, timeout)),
        popen_factory=launch,
        which=lambda name: f"/mock/{name}",
    )
    result = service.run(TargetProbeRequest(project=project))
    statuses = {item.stage: item.status for item in result.checks}
    assert statuses["static-policy"] == "passed"
    assert statuses["authentication-session"] == "passed"
    assert connections == [("gateway.example", 22, 0.25)]
    session = commands[-1]
    assert session[:3] == ["/mock/sshpass", "-f", str(secrets / "gateway.pw")]
    assert "StrictHostKeyChecking=yes" in session
    assert f"UserKnownHostsFile={secrets / 'gateway.known_hosts'}" in session
    assert "operator@gateway.example" in session
    assert "vnc.internal" not in session
    assert "gateway-secret" not in " ".join(session)


def test_timeout_cleans_only_its_process_group(tmp_path, monkeypatch):
    signals: list[tuple[int, int]] = []

    class TimedProcess:
        pid = 771
        returncode = None

        def communicate(self, **_kwargs):
            raise subprocess.TimeoutExpired(["fixed-client", "--version"], 0.1)

        def wait(self, **_kwargs):
            self.returncode = -15
            return self.returncode

    monkeypatch.setattr(os, "killpg", lambda pid, signal: signals.append((pid, signal)))
    service = TargetProbeService(_settings(tmp_path), popen_factory=lambda *_a, **_k: TimedProcess())
    code, output = service._bounded_command(["fixed-client", "--version"], timeout=0.1)
    assert code is None
    assert output == b""
    assert signals == [(771, 15)]


def test_pass_is_revision_ttl_bound_and_does_not_satisfy_another_project(tmp_path):
    moment = [datetime(2026, 8, 24, 20, 0, tzinfo=timezone.utc)]
    service = TargetProbeService(
        _settings(tmp_path),
        clock=lambda: moment[0],
        probe_hook=lambda _project: _all_passed_checks(),
    )
    first = _local_project("first")
    second = _local_project("second")
    result = service.run(TargetProbeRequest(project=first))
    assert result.outcome == "passed"
    assert service.current_result(first) == result
    assert service.current_result(second) is None
    edited = first.model_copy(update={"target": LocalAppTarget(app="changed", window="Example")})
    assert service.current_result(edited) is None

    request = WizardAssessmentRequest(
        project=first,
        specifications=[_spec()],
        manual_outline=["Purpose"],
        verification_path="authoring-only",
    )
    readiness = assess_readiness(request, result)
    assert readiness.stages.target_probe == "passed"
    assert not any(item.code == "target_not_probed" for item in readiness.findings)
    assert readiness.ready_for_run is True

    moment[0] += timedelta(seconds=31)
    assert service.current_result(first) is None
    expired = assess_readiness(request)
    assert expired.stages.target_probe == "not-run"
    assert any(item.code == "target_not_probed" for item in expired.findings)


def _api_app(tmp_path: Path, monkeypatch) -> tuple[FastAPI, DashboardSettings]:
    settings = _settings(tmp_path)
    import dashboard.config as config

    monkeypatch.setattr(config, "settings", settings)
    monkeypatch.setenv("DASHBOARD_SPECS_DIR", settings.specs_dir)
    monkeypatch.setenv("DASHBOARD_SECRETS_DIR", settings.secrets_dir)
    monkeypatch.setenv("TESTS_MANUALS_DIR", str(tmp_path / "manuals"))
    app = FastAPI()
    app.state.project_wizard_service = ProjectWizardService(settings)
    app.state.target_setup_service = TargetSetupService(settings)
    app.state.target_probe_service = TargetProbeService(
        settings, probe_hook=lambda _project: _all_passed_checks()
    )
    app.include_router(wizard_router, prefix="/api/v1")
    return app, settings


def _validation_body(specs: list[SpecDocument]) -> dict:
    project = _local_project()
    return {
        "project": project.model_dump(mode="json"),
        "specifications": [item.model_dump(mode="json") for item in specs],
        "manual_outline": ["Purpose", "Visible evidence"],
        "manual_template": "# Sample operating manual\n\n## Purpose\nReviewed.\n\n## Visible evidence\nReviewed.\n",
        "verification_path": "authoring-only",
    }


def test_complete_nonwriting_validation_rejects_a_later_invalid_spec(tmp_path, monkeypatch):
    app, settings = _api_app(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer operator"}
    Path(settings.specs_dir).mkdir(parents=True)
    good = _validation_body([_spec(), _spec("001-second.md")])
    bad = _validation_body([_spec(), _spec("001-second.md", assertions=[])])
    with TestClient(app) as client:
        valid = client.post("/api/v1/authoring/wizard/validate", headers=headers, json=good)
        assert valid.status_code == 200, valid.text
        assert len(valid.json()["specifications"]) == 2
        assert [item["stage"] for item in valid.json()["target_checks"]] == [
            "static-policy", "secret-reference", "client-runtime"
        ]
        invalid = client.post("/api/v1/authoring/wizard/validate", headers=headers, json=bad)
        assert invalid.status_code == 422, invalid.text
        diagnostics = invalid.json()["detail"]["diagnostics"]
        assert any(item["field"].startswith("specifications[1].") for item in diagnostics)
    assert not (Path(settings.specs_dir) / "sample").exists()
    assert not (tmp_path / "manuals" / "sample").exists()


def test_probe_api_is_operator_only_and_readiness_accepts_only_server_cache(tmp_path, monkeypatch):
    app, settings = _api_app(tmp_path, monkeypatch)
    project = _local_project()
    body = {"project": project.model_dump(mode="json")}
    assessment = _validation_body([_spec()])
    assessment.pop("manual_template")
    viewer = {"Authorization": "Bearer viewer"}
    operator = {"Authorization": "Bearer operator"}
    with TestClient(app) as client:
        assert client.post("/api/v1/authoring/wizard/target-probes", headers=viewer, json=body).status_code == 403
        before = client.post("/api/v1/authoring/wizard/readiness", headers=operator, json=assessment)
        assert before.json()["stages"]["target_probe"] == "not-run"
        probe = client.post("/api/v1/authoring/wizard/target-probes", headers=operator, json=body)
        assert probe.status_code == 200, probe.text
        after = client.post("/api/v1/authoring/wizard/readiness", headers=operator, json=assessment)
        assert after.json()["stages"]["target_probe"] == "passed"
        assert after.json()["ready_for_run"] is True
        audit = client.get("/api/v1/authoring/wizard/target-probes/audit", headers=operator)
        assert audit.status_code == 200
        assert "example-app" not in audit.text
