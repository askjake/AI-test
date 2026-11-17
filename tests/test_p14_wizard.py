"""Phase 14 Project Builder Wizard safety and compatibility contract."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard.authoring import LocalAppTarget, ProjectDocument, SpecDocument
from dashboard.config import DashboardSettings
from dashboard.refinement import Boto3TextOnlyAuthoringClient, _build_structured_anthropic_request
from dashboard.wizard import (
    BlueprintCatalogService,
    ProjectWizardService,
    VerificationHandoffRequest,
    WizardAssessmentRequest,
    WizardContextDraft,
    WizardContextRequest,
    WizardContextSpec,
    WizardPlanCreateRequest,
    assess_readiness,
    project_map,
    verification_handoff,
)
from dashboard.wizard_routes import router as wizard_router
from dashboard.target_setup import (
    KnownHostsSaveRequest,
    PasswordSaveRequest,
    SecretAlreadyExistsError,
    TargetSetupError,
    TargetSetupService,
    _vnc_password_file,
)


ROOT = Path(__file__).parents[1]


class FakePlanClient:
    def __init__(self, response: str):
        self.response = response
        self.calls: list[dict] = []

    def draft_plan(self, **kwargs):
        self.calls.append(kwargs)
        return self.response, {"input_tokens": 19, "output_tokens": 11}


class FakeClientError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__("private SDK detail must not be exposed")
        self.response = {"Error": {"Code": code, "Message": message}}


class RaisingPlanClient:
    def __init__(self, error: BaseException):
        self.error = error

    def draft_plan(self, **_kwargs):
        raise self.error


def _settings(tmp_path: Path, *, enabled: bool = True) -> DashboardSettings:
    return DashboardSettings(
        auth_token="viewer",
        auth_operator_token="operator",
        reports_dir=str(tmp_path / "reports"),
        specs_dir=str(tmp_path / "specs"),
        authoring_refinement_enabled=enabled,
        authoring_model_id="approved-profile",
        authoring_region="us-west-2",
        authoring_profile="rotating-profile",
        authoring_shared_credentials_file=str(tmp_path / "credentials"),
        authoring_shared_config_file=str(tmp_path / "config"),
        authoring_state_root=str(tmp_path / "private-p13d"),
        authoring_guidance_root=str(tmp_path / "guidance"),
        wizard_state_root=str(tmp_path / "private-p14"),
        wizard_blueprint_root=str(ROOT / "project_blueprints"),
        secrets_dir=str(tmp_path / "secrets"),
    )


def _context_draft(goal: str = "Verify a clear visible state.") -> WizardContextDraft:
    return WizardContextDraft(
        display_name="Sample verification",
        goal=goal,
        target_type="local-app",
        specifications=[WizardContextSpec(
            title="Initial state",
            goal="Confirm a stable visible state.",
            assertions=["The expected primary surface is visible."],
        )],
        manual_outline=["Purpose", "Normal procedure", "Visible completion cues"],
        verification_path="authoring-only",
    )


def _project() -> ProjectDocument:
    return ProjectDocument(
        dir_name="sample",
        display_name="Sample verification",
        manual_dir=None,
        target=LocalAppTarget(app="example-app", window="Example"),
        schedule="0 3 * * *",
        max_steps=30,
        max_seconds=1800,
    )


def _spec(path: str = "000-initial.md") -> SpecDocument:
    return SpecDocument(
        path=path,
        title="Initial state",
        goal="Confirm a stable visible state.",
        assertions=["The expected primary surface is visible."],
    )


def _valid_plan() -> str:
    return json.dumps({
        "display_name": "Reviewed project plan",
        "goal": "Verify a stable application state and one bounded interaction.",
        "target_type_suggestion": "local-app",
        "field_placeholders": [{"field": "target.window", "placeholder": "Expected primary window"}],
        "specifications": [{
            "title": "Initial visible state",
            "goal": "Confirm that initialization reaches a stable visible state.",
            "setup": None,
            "assertions": ["The primary surface is visible.", "A completion cue is present."],
        }],
        "manual_outline": ["Purpose", "Normal procedure", "Visible completion cues"],
        "assumptions": ["The documented normal starting state is available."],
        "open_questions": ["Which visible cue best distinguishes completion?"],
        "risks": ["A transient loading state could be mistaken for completion."],
        "suggested_verification_plan": "Review readiness, then explicitly choose whether to run the whole project.",
    })


def test_blueprint_catalog_is_hash_pinned_ranked_and_field_selective(tmp_path):
    catalog = BlueprintCatalogService(_settings(tmp_path))
    result = catalog.catalog(query="visible smoke", target_type="local-app", tags=["bounded"])
    assert len(result.eligible) == 1
    entry = result.eligible[0].entry
    assert entry.approval_state == "approved"
    assert entry.sha256 == "f3506a652707f74b9227a3c14656b76a1b4c96cc85b05e34c222eaa27219fa25"
    assert "file" not in entry.model_dump(mode="json")
    preview = catalog.preview_import(entry.id, ["goal", "specifications"])
    assert [item.field for item in preview.fields] == ["goal", "specifications"]
    assert all(item.source_revision == entry.sha256 for item in preview.fields)
    assert not {"target.app", "target.host", "allowlist"} & {item.field for item in preview.fields}


def test_context_inspector_excludes_unsafe_intent_and_never_sends_target_values(tmp_path):
    fake = FakePlanClient(_valid_plan())
    service = ProjectWizardService(_settings(tmp_path), lambda: fake)
    request = WizardContextRequest(
        intent="Launch /home/operator/private-app and inspect token=not-safe",
        draft=_context_draft(),
        blueprint_ids=[],
        guidance_ids=[],
    )
    preview, _prepared = service.preview_context(request)
    intent = next(item for item in preview.sources if item.kind == "operator-intent")
    assert intent.selected is False
    assert not hasattr(intent, "excerpt")
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()
    completed = service.get_job(job.id)
    assert completed.proposal.state == "ready"
    prompt = fake.calls[0]["prompt"]
    assert "/home/operator" not in prompt
    assert "not-safe" not in prompt
    assert "example-app" not in prompt


def test_plan_proposal_is_draft_only_section_reviewed_and_stale_safe(tmp_path):
    service = ProjectWizardService(_settings(tmp_path), lambda: FakePlanClient(_valid_plan()))
    request = WizardContextRequest(intent="Verify one bounded visible workflow.", draft=_context_draft())
    preview, _prepared = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()
    proposal = service.get_job(job.id).proposal
    assert proposal.state == "ready"
    assert not (tmp_path / "specs").exists()
    accepted = service.decide(
        proposal_id=proposal.id,
        sections=["project"],
        current_draft=request.draft,
        accept=True,
    )
    assert accepted.accepted_sections == ["project"]
    assert not (tmp_path / "specs").exists()

    changed = request.draft.model_copy(update={"goal": "A separately edited goal."})
    stale = service.decide(
        proposal_id=proposal.id,
        sections=["target"],
        current_draft=changed,
        accept=True,
    )
    assert stale.state == "stale"
    assert stale.error == "The local wizard draft changed after plan generation."


def test_complete_plan_can_be_accepted_locally_in_one_guarded_decision(tmp_path):
    fake = FakePlanClient(_valid_plan())
    service = ProjectWizardService(_settings(tmp_path), lambda: fake)
    request = WizardContextRequest(
        intent="Verify the visible initialization and one bounded workflow.",
        draft=_context_draft(),
    )
    preview, _prepared = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(
        **request.model_dump(), fingerprint=preview.fingerprint
    ))
    service.drain()
    proposal = service.get_job(job.id).proposal
    sections = ["project", "target", "specifications", "manual", "analysis", "verification"]
    accepted = service.decide(
        proposal_id=proposal.id,
        sections=sections,
        current_draft=request.draft,
        accept=True,
    )
    assert accepted.state == "accepted-locally"
    assert set(accepted.accepted_sections) == set(sections)
    assert accepted.rejected_sections == []
    assert accepted.proposal is not None
    assert accepted.proposal.specifications[0].assertions
    assert not (tmp_path / "specs").exists()
    prompt = fake.calls[0]["prompt"]
    assert "Transform the operator's plain-language description" in prompt
    assert "starting state, bounded workflow or checks, observable evidence" in prompt
    assert "Generate every permitted missing authoring field" in prompt


def test_plan_queue_is_bounded_before_any_client_is_constructed(tmp_path):
    settings = _settings(tmp_path)
    settings.wizard_max_pending_jobs = 1
    factory_calls = 0
    def factory():
        nonlocal factory_calls
        factory_calls += 1
        return FakePlanClient(_valid_plan())
    service = ProjectWizardService(settings, factory)
    request = WizardContextRequest(intent="Verify one bounded visible workflow.", draft=_context_draft())
    preview, _prepared = service.preview_context(request)
    create = WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint)
    service.create_job(create)
    with pytest.raises(ValueError, match="queue is full"):
        service.create_job(create)
    assert factory_calls == 0


def test_invalid_or_prohibited_model_output_never_becomes_ready(tmp_path):
    bad = json.loads(_valid_plan())
    bad["risks"] = ["Read token=not-safe before continuing."]
    service = ProjectWizardService(_settings(tmp_path), lambda: FakePlanClient(json.dumps(bad)))
    request = WizardContextRequest(intent="Verify a safe visible state.", draft=_context_draft())
    preview, _prepared = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()
    proposal = service.get_job(job.id).proposal
    assert proposal.state == "invalid-output"
    assert proposal.proposal is None
    assert "risks[0] (rule: credential-value)" in proposal.error
    assert "not-safe" not in proposal.error


def test_project_plan_uses_its_own_bounded_output_limit(tmp_path):
    settings = _settings(tmp_path)
    assert settings.wizard_max_output_chars > settings.authoring_max_output_chars

    plan = json.loads(_valid_plan())
    plan["specifications"] = [
        {
            "title": f"Observable phase {index}",
            "goal": "Confirm the expected visible state is stable. " + ("evidence " * 75),
            "setup": "Begin from the documented normal starting state. " + ("prepare " * 75),
            "assertions": [
                "The expected surface remains visible and observable. " + ("signal " * 55),
                "A concrete completion cue is present for review. " + ("signal " * 55),
            ],
        }
        for index in range(6)
    ]
    raw = json.dumps(plan, separators=(",", ":"))
    assert settings.authoring_max_output_chars < len(raw) <= settings.wizard_max_output_chars

    fake = FakePlanClient(raw)
    service = ProjectWizardService(settings, lambda: fake)
    request = WizardContextRequest(intent="Verify a bounded visible workflow.", draft=_context_draft())
    preview, _prepared = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()

    completed = service.get_job(job.id)
    assert completed.proposal.state == "ready"
    assert fake.calls[0]["max_output_chars"] == settings.wizard_max_output_chars


def test_readiness_and_map_are_deterministic_non_network_and_sanitized():
    request = WizardAssessmentRequest(
        project=_project(),
        specifications=[_spec()],
        manual_outline=["Purpose", "Normal procedure", "Visible completion cues"],
        verification_path="authoring-only",
    )
    first = assess_readiness(request)
    second = assess_readiness(request)
    assert first == second
    assert first.ready_for_create is True
    assert first.ready_for_run is False
    assert {item.category for item in first.findings} == {
        "verify-before-run",
        "optional-improvement",
    }
    assert any(item.code == "target_not_probed" for item in first.findings)
    assert {
        "watch_learn_ready_window_unset",
        "watch_learn_redaction_unset",
    }.issubset({item.code for item in first.findings})

    graph = project_map(request)
    assert graph == project_map(request)
    rendered = graph.model_dump_json()
    assert "example-app" not in rendered
    assert "Example" not in rendered
    assert "sample" not in rendered.lower()
    assert "Planned specification 1" in rendered
    assert graph.text_alternative


def test_watch_learn_advisories_clear_without_blocking_ordinary_run_readiness():
    project = _project().model_copy(update={
        "target": LocalAppTarget(
            app="example-app",
            window="Example",
            watch_learn_ready_window="Example Ready",
        ),
        "redaction": [[0, 0, 32, 32]],
    })
    request = WizardAssessmentRequest(
        project=project,
        specifications=[_spec()],
        manual_outline=["Purpose", "Normal procedure", "Visible completion cues"],
        verification_path="authoring-only",
    )

    result = assess_readiness(request)

    codes = {item.code for item in result.findings}
    assert "watch_learn_ready_window_unset" not in codes
    assert "watch_learn_redaction_unset" not in codes
    assert result.ready_for_create is True
    assert result.ready_for_run is False  # Target preflight remains an independent gate.


def test_readiness_groups_real_gaps_and_links_back_to_steps():
    request = WizardAssessmentRequest(
        project=ProjectDocument(
            dir_name="bad slug",
            display_name="TBD",
            target=LocalAppTarget(app=None, window=None),
            schedule="not cron",
        ),
        specifications=[],
        manual_outline=[],
        verification_path="none",
    )
    result = assess_readiness(request)
    assert result.ready_for_create is False
    assert {"must-resolve", "verify-before-run", "optional-improvement"}.issubset(
        {item.category for item in result.findings}
    )
    assert all(1 <= item.step <= 6 for item in result.findings)
    assert any(item.code == "unresolved_placeholder" for item in result.findings)
    assert any(item.code == "verification_path_missing" and item.step == 6 for item in result.findings)


def test_structured_client_contract_is_forced_and_expiry_retry_is_bounded(tmp_path, monkeypatch):
    schema = {"type": "object", "properties": {"goal": {"type": "string"}}, "required": ["goal"], "additionalProperties": False}
    request = _build_structured_anthropic_request(
        prompt="safe", max_output_chars=4_000, response_name="submit_plan",
        response_description="Return one plan.", response_schema=schema,
    )
    assert request["tool_choice"] == {"type": "tool", "name": "submit_plan"}
    assert request["tools"][0]["strict"] is True
    assert request["tools"][0]["input_schema"] == schema

    from tests.test_p13d_refinement import _write_rotating_credentials
    _write_rotating_credentials(tmp_path / "credentials", "OLD")
    client = Boto3TextOnlyAuthoringClient(_settings(tmp_path))
    attempts = []
    class ExpiredTokenException(Exception):
        pass
    def invoke(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            _write_rotating_credentials(tmp_path / "credentials", "NEW")
            raise ExpiredTokenException("expired")
        return '{"goal":"safe"}', {}
    monkeypatch.setattr(client, "_invoke_structured_once", invoke)
    result = client.invoke_structured(
        model_id="approved-profile", prompt="safe", max_output_chars=4_000,
        timeout_seconds=45, response_name="submit_plan",
        response_description="Return one plan.", response_schema=schema,
    )
    assert result[0] == '{"goal":"safe"}'
    assert len(attempts) == 2


def test_structured_client_falls_back_once_for_explicit_strict_rejection(tmp_path, monkeypatch):
    client = Boto3TextOnlyAuthoringClient(_settings(tmp_path))
    attempts = []

    def invoke(**kwargs):
        attempts.append(kwargs)
        if kwargs["strict"]:
            raise FakeClientError(
                "ValidationException",
                "This model does not support strict tool use.",
            )
        return '{"goal":"safe"}', {}

    monkeypatch.setattr(client, "_invoke_structured_once", invoke)
    result = client.invoke_structured(
        model_id="approved-profile", prompt="safe", max_output_chars=4_000,
        timeout_seconds=45, response_name="submit_plan",
        response_description="Return one plan.",
        response_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )

    assert result[0] == '{"goal":"safe"}'
    assert [item["strict"] for item in attempts] == [True, False]


def test_structured_client_does_not_retry_unrelated_validation_failure(tmp_path, monkeypatch):
    client = Boto3TextOnlyAuthoringClient(_settings(tmp_path))
    attempts = []

    def invoke(**kwargs):
        attempts.append(kwargs)
        raise FakeClientError("ValidationException", "max_tokens is invalid")

    monkeypatch.setattr(client, "_invoke_structured_once", invoke)
    with pytest.raises(FakeClientError):
        client.invoke_structured(
            model_id="approved-profile", prompt="safe", max_output_chars=4_000,
            timeout_seconds=45, response_name="submit_plan",
            response_description="Return one plan.",
            response_schema={"type": "object", "properties": {}, "additionalProperties": False},
        )
    assert len(attempts) == 1


@pytest.mark.parametrize(("error", "expected"), [
    (
        FakeClientError("AccessDeniedException", "private principal detail"),
        "The text-only project-plan request failed. Bedrock denied access for the configured AWS profile or model.",
    ),
    (
        FakeClientError("ValidationException", "private schema detail"),
        "The text-only project-plan request failed. Bedrock rejected the structured request for the configured model or profile.",
    ),
    (
        RuntimeError("private unexpected detail"),
        "The text-only project-plan request failed. An unexpected client failure occurred.",
    ),
])
def test_project_plan_client_failures_are_safely_classified(tmp_path, error, expected):
    service = ProjectWizardService(_settings(tmp_path), lambda: RaisingPlanClient(error))
    request = WizardContextRequest(intent="Verify one bounded visible workflow.", draft=_context_draft())
    preview, _prepared = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(
        **request.model_dump(), fingerprint=preview.fingerprint
    ))

    service.drain()

    proposal = service.get_job(job.id).proposal
    assert proposal.state == "failed"
    assert proposal.error == expected
    assert "private" not in proposal.error


def test_target_options_merge_configured_and_past_hosts_without_reports(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    specs = Path(settings.specs_dir)
    project = specs / "historical"
    project.mkdir(parents=True)
    (project / "project.yaml").write_text(
        "ssh_host_allowlist: [past-ssh]\n"
        "rdp_host_allowlist: [past-rdp]\n"
        "vnc_host_allowlist: [past-vnc]\n"
        "target:\n  type: vnc\n  host: current-vnc\n  via: ops@gateway-01\n"
    )
    secrets = Path(settings.secrets_dir)
    secrets.mkdir()
    (secrets / "known.rdp.pw").write_text("not-read-by-options\n")
    (secrets / "unsafe name").write_text("excluded\n")
    monkeypatch.setenv("DASHBOARD_SPECS_DIR", settings.specs_dir)
    monkeypatch.setenv("DASHBOARD_SECRETS_DIR", settings.secrets_dir)
    service = TargetSetupService(settings, SimpleNamespace(
        ssh_host_allowlist=["configured-ssh"],
        rdp_host_allowlist=["configured-rdp", "past-rdp"],
        vnc_host_allowlist=["configured-vnc"],
    ))
    result = service.options()
    assert [item.host for item in result.hosts["ssh-terminal"]] == [
        "configured-ssh", "gateway-01", "past-ssh"
    ]
    rdp = {item.host: item.sources for item in result.hosts["rdp"]}
    assert rdp["past-rdp"] == ["configured", "past-project"]
    assert {item.host for item in result.hosts["vnc"]} == {
        "configured-vnc", "current-vnc", "past-vnc"
    }
    assert result.password_references == ["known.rdp.pw"]


def test_password_save_is_owner_only_write_only_and_vnc_compatible(tmp_path):
    settings = _settings(tmp_path)
    service = TargetSetupService(settings)
    secret_value = "correct horse battery staple"
    created = service.save_password(PasswordSaveRequest(
        kind="rdp",
        reference_name="host.rdp.pw",
        password=secret_value,
    ))
    destination = Path(settings.secrets_dir) / "host.rdp.pw"
    assert created.status == "created"
    assert created.model_dump() == {
        "reference_name": "host.rdp.pw", "kind": "rdp", "status": "created"
    }
    assert destination.read_text() == secret_value + "\n"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(settings.secrets_dir).stat().st_mode) == 0o700
    with pytest.raises(SecretAlreadyExistsError):
        service.save_password(PasswordSaveRequest(
            kind="rdp", reference_name="host.rdp.pw", password="different"
        ))
    assert destination.read_text() == secret_value + "\n"

    replaced = service.save_password(PasswordSaveRequest(
        kind="rdp", reference_name="host.rdp.pw", password="different", overwrite=True
    ))
    assert replaced.status == "replaced"
    assert destination.read_text() == "different\n"

    application = service.save_password(PasswordSaveRequest(
        kind="application", reference_name="sample.login", password="app-value"
    ))
    assert application.model_dump() == {
        "reference_name": "sample.login",
        "kind": "application",
        "status": "created",
    }
    assert (Path(settings.secrets_dir) / "sample.login").read_text() == "app-value\n"
    assert stat.S_IMODE(
        (Path(settings.secrets_dir) / "sample.login").stat().st_mode
    ) == 0o600

    vnc = service.save_password(PasswordSaveRequest(
        kind="vnc", reference_name="host.vncpass", password="password"
    ))
    assert vnc.status == "created"
    assert (Path(settings.secrets_dir) / "host.vncpass").read_bytes().hex() == "33483fd570cf869b"
    assert _vnc_password_file(b"password").hex() == "33483fd570cf869b"
    with pytest.raises(TargetSetupError, match="at most 8 UTF-8 bytes"):
        service.save_password(PasswordSaveRequest(
            kind="vnc", reference_name="too-long.vncpass", password="ninechars"
        ))


def test_password_reference_rejects_paths_and_symlink_targets(tmp_path):
    settings = _settings(tmp_path)
    service = TargetSetupService(settings)
    with pytest.raises(ValueError):
        PasswordSaveRequest(kind="rdp", reference_name="../escape", password="safe")
    secrets = Path(settings.secrets_dir)
    secrets.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    (secrets / "linked.pw").symlink_to(outside)
    with pytest.raises(TargetSetupError, match="not a regular file"):
        service.save_password(PasswordSaveRequest(
            kind="rdp", reference_name="linked.pw", password="new", overwrite=True
        ))
    assert outside.read_text() == "unchanged"


def test_known_hosts_save_requires_exact_reviewable_host_and_owner_only_file(tmp_path):
    settings = _settings(tmp_path)
    service = TargetSetupService(settings)
    key_data = "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="
    created = service.save_known_hosts(KnownHostsSaveRequest(
        expected_host="10.74.11.30",
        reference_name="10.74.11.30.known_hosts",
        known_hosts=f"10.74.11.30 ssh-ed25519 {key_data}\n",
    ))
    destination = Path(settings.secrets_dir) / created.reference_name
    assert created.status == "created"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.read_text() == f"10.74.11.30 ssh-ed25519 {key_data}\n"
    with pytest.raises(TargetSetupError, match="exact expected jump host"):
        service.save_known_hosts(KnownHostsSaveRequest(
            expected_host="other.example",
            reference_name="other.known_hosts",
            known_hosts=f"10.74.11.30 ssh-ed25519 {key_data}\n",
        ))
    with pytest.raises(TargetSetupError, match="Hashed hostnames"):
        service.save_known_hosts(KnownHostsSaveRequest(
            expected_host="10.74.11.30",
            reference_name="hashed.known_hosts",
            known_hosts=f"|1|salt|hash ssh-ed25519 {key_data}\n",
        ))


def _api_app(tmp_path: Path, monkeypatch) -> tuple[FastAPI, DashboardSettings]:
    settings = _settings(tmp_path)
    import dashboard.config as config
    monkeypatch.setattr(config, "settings", settings)
    app = FastAPI()
    app.state.project_wizard_service = ProjectWizardService(settings, lambda: FakePlanClient(_valid_plan()))
    app.state.target_setup_service = TargetSetupService(settings, SimpleNamespace(
        ssh_host_allowlist=["configured-ssh"],
        rdp_host_allowlist=["configured-rdp"],
        vnc_host_allowlist=["configured-vnc"],
    ))
    app.include_router(wizard_router, prefix="/api/v1")
    return app, settings


def test_routes_are_operator_only_and_handoff_never_triggers(tmp_path, monkeypatch):
    app, settings = _api_app(tmp_path, monkeypatch)
    specs = Path(settings.specs_dir) / "sample"
    manual = tmp_path / "manuals" / "sample"
    reports = Path(settings.reports_dir)
    specs.mkdir(parents=True)
    manual.mkdir(parents=True)
    reports.mkdir(parents=True)
    (manual / "manual.md").write_text("# Manual\n")
    (specs / "project.yaml").write_text(
        "name: Sample\nmanual_dir: " + str(manual) + "\ntarget:\n  type: local-app\n  app: example-app\n  window: Example\n"
    )
    monkeypatch.setenv("DASHBOARD_SPECS_DIR", settings.specs_dir)
    monkeypatch.setenv("DASHBOARD_SECRETS_DIR", settings.secrets_dir)
    viewer = {"Authorization": "Bearer viewer"}
    operator = {"Authorization": "Bearer operator"}
    with TestClient(app) as client:
        assert client.get("/api/v1/authoring/wizard/blueprints", headers=viewer).status_code == 403
        assert client.get("/api/v1/authoring/wizard/target-options", headers=viewer).status_code == 403
        catalog = client.get("/api/v1/authoring/wizard/blueprints", headers=operator)
        assert catalog.status_code == 200, catalog.text
        assert "file" not in catalog.text
        options = client.get("/api/v1/authoring/wizard/target-options", headers=operator)
        assert options.status_code == 200, options.text
        assert options.json()["hosts"]["rdp"][0]["host"] == "configured-rdp"

        password_value = "route-secret-must-not-be-reflected"
        invalid = client.post(
            "/api/v1/authoring/wizard/passwords",
            headers=operator,
            json={
                "kind": "vnc", "reference_name": "host.vncpass",
                "password": password_value, "overwrite": False,
            },
        )
        assert invalid.status_code == 422
        assert password_value not in invalid.text
        saved = client.post(
            "/api/v1/authoring/wizard/passwords",
            headers=operator,
            json={
                "kind": "rdp", "reference_name": "host.rdp.pw",
                "password": password_value, "overwrite": False,
            },
        )
        assert saved.status_code == 200, saved.text
        assert saved.json() == {
            "reference_name": "host.rdp.pw", "kind": "rdp", "status": "created"
        }
        assert password_value not in saved.text
        assert str(Path(settings.secrets_dir)) not in saved.text

        host_key = "10.74.11.30 ssh-ed25519 eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="
        known_hosts = client.post(
            "/api/v1/authoring/wizard/known-hosts",
            headers=operator,
            json={
                "expected_host": "10.74.11.30",
                "reference_name": "10.74.11.30.known_hosts",
                "known_hosts": host_key,
                "overwrite": False,
            },
        )
        assert known_hosts.status_code == 200, known_hosts.text
        assert known_hosts.json() == {
            "reference_name": "10.74.11.30.known_hosts", "status": "created"
        }
        assert host_key not in known_hosts.text

        wrong = client.post(
            "/api/v1/projects/Sample/authoring/wizard/verification-handoff",
            headers=operator,
            json={"confirmation_project": "Other", "scope": "all", "selected_specs": []},
        )
        assert wrong.status_code == 409
        handoff = client.post(
            "/api/v1/projects/Sample/authoring/wizard/verification-handoff",
            headers=operator,
            json={"confirmation_project": "sample", "scope": "all", "selected_specs": []},
        )
        assert handoff.status_code == 200, handoff.text
        assert handoff.json()["project"] == "sample"
        assert handoff.json()["trigger_path"].endswith("/projects/sample/runs")
        assert not (reports / ".ctrl").exists()


def test_handoff_truthfully_rejects_selected_scope():
    try:
        verification_handoff(
            "Sample",
            VerificationHandoffRequest(
                confirmation_project="Sample", scope="all", selected_specs=["000-one.md"]
            ),
        )
    except ValueError as exc:
        assert str(exc) == "The existing runner does not support selected-spec triggers."
    else:
        raise AssertionError("selected-spec scope must not be faked")


def test_template_contract_exposes_progressive_accessible_review_only_flow():
    text = (ROOT / "templates" / "dashboard" / "index.html").read_text()
    for required in (
        "Blank project",
        "Start from a blueprint",
        "Describe what you want to verify",
        "Build draft and continue",
        "generateWizardDraftAndContinue",
        "waitForWizardPlanJob",
        "The first schema-constrained request can take a few minutes",
        "Goal, connections, and operating instructions",
        "Numbered steps are optional",
        "Goal and scope",
        "Target and environment",
        "Project plan and specifications",
        "Context and historical examples",
        "Readiness and gaps",
        "Review, create, and optional verification",
        "Context Inspector",
        "Draft a plan",
        "Accept this section",
        "Reject this section",
        "Project map",
        "Stop after authoring",
        "Confirm and Trigger Run",
        "updateWizardRunConfirmation",
        "wizard-run-confirm-button",
        "confirmation_project:confirmation",
        "const projectSlug = String(response.dir_name || \"\").trim();",
        "authoringState.wizardCreatedProject = projectSlug",
        "Choose a known host or type a new one",
        "Allow this host for this project",
        "What is the window title?",
        "Use suggested title",
        "Save or replace the RDP password",
        "Save or replace the VNC password",
        "/authoring/wizard/target-options",
        "/authoring/wizard/passwords",
        "localStorage.setItem(WIZARD_DRAFT_KEY",
        'aria-current", "step"',
        'role="status" aria-live="polite"',
    ):
        assert required in text
    assert "response.display_name || response.dir_name" not in text
    save_draft = text[text.index("function saveWizardDraft()") : text.index("function restoreWizardDraft()")]
    assert "password" not in save_draft.lower()
    assert "Windows Explorer" not in text
