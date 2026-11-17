"""Phase 13D guarded draft-refinement contract tests.

Every model interaction in this module is injected.  The tests deliberately
fail by design if production boto3 construction is needed to exercise a case.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.authoring import LocalAppTarget, ProjectDocument, SpecDocument, content_revision
from dashboard.config import DashboardSettings
from dashboard.refinement import (
    Boto3TextOnlyAuthoringClient,
    RefinementError,
    RefinementService,
    _UNSAFE_TEXT,
    _build_anthropic_request,
    _extract_schema_proposal,
    _strict_schema_read_timeout,
)


class FakeClient:
    def __init__(self, response: str):
        self.response = response
        self.calls: list[dict] = []

    def refine(self, **kwargs):
        self.calls.append(kwargs)
        return self.response, {"input_tokens": 11, "output_tokens": 7}


def _write_rotating_credentials(path, key):
    import os as _os, time as _time
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(f"[rotating-profile]\naws_access_key_id = FAKEFICTIONAL{key}\naws_secret_access_key = fictional-secret-{key}-0123456789abcdef\n"
                 f"aws_session_token = fictional-token-{key}-0123456789abcdef\nexpiration = 2099-01-01T00:00:00Z\n")
    _os.replace(tmp, path)
    _os.utime(path, (_time.time() - 5, _time.time() - 5))          # outside the settle window


def _settings(tmp_path: Path, *, enabled: bool = True) -> DashboardSettings:
    return DashboardSettings(
        authoring_refinement_enabled=enabled,
        authoring_model_id="approved-profile",
        authoring_region="us-west-2",
        authoring_profile="rotating-profile",
        authoring_shared_credentials_file=str(tmp_path / "credentials"),
        authoring_shared_config_file=str(tmp_path / "config"),
        authoring_state_root=str(tmp_path / "private-state"),
        authoring_guidance_root=str(tmp_path / "guidance"),
        authoring_max_context_chars=20_000,
        authoring_max_source_chars=4_000,
    )


def _project(tmp_path: Path) -> ProjectDocument:
    manual = tmp_path / "manuals" / "sample"
    manual.mkdir(parents=True, exist_ok=True)
    (manual / "manual.md").write_text("# Manual\n\nUse visible application cues safely.\n")
    return ProjectDocument(
        dir_name="sample",
        display_name="Sample",
        manual_dir=str(manual),
        target=LocalAppTarget(app="ignored", window="ignored"),
        max_steps=20,
        max_seconds=60,
    )


def _docs():
    first = SpecDocument(path="010-first.md", title="First", goal="Check visible state.", assertions=["A status card is present."])
    second = SpecDocument(path="020-second.md", title="Second", goal="Check a second view.", assertions=["A result is displayed."])
    payload = {first.path: first, second.path: second}
    return payload, {path: content_revision(document.model_dump_json()) for path, document in payload.items()}


def _preview(service: RefinementService, tmp_path: Path, *, paths=None, mode="selected"):
    project = _project(tmp_path)
    docs, revisions = _docs()
    def read(path):
        return docs[path], revisions[path]
    preview, plans = service.preview(
        project_name="Sample", project=project, project_dir=str(tmp_path / "specs"),
        requested_paths=paths or ["010-first.md"], mode=mode,
        include_manual=False, include_siblings=True, full_sibling_paths=[], guidance_ids=[],
        read_spec=read, all_paths=list(docs),
    )
    return preview, plans, docs, revisions, read


def _valid_output(goal="Check a clear visible state."):
    return json.dumps({
        "goal": goal,
        "setup": None,
        "assertions": ["A clear status card is visible.", "The displayed state matches the requested condition."],
        "rationale": "Makes the expected observation and completion criterion explicit.",
        "change_notes": ["Clarified visible outcome."],
    })


def test_disabled_configuration_cannot_construct_a_client(tmp_path):
    settings = _settings(tmp_path, enabled=False)
    called = False
    def forbidden_factory():
        nonlocal called
        called = True
        raise AssertionError("a disabled service must not construct a client")
    service = RefinementService(settings, forbidden_factory)
    preview, plans, *_ = _preview(service, tmp_path)
    assert not service.configured
    with pytest.raises(RefinementError):
        service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    assert not called


def test_expired_token_rebuilds_once_but_other_errors_do_not_retry(tmp_path, monkeypatch):
    _write_rotating_credentials(tmp_path / "credentials", "OLD")
    client = Boto3TextOnlyAuthoringClient(_settings(tmp_path))
    attempts = []
    class ExpiredTokenException(Exception):
        pass
    def expired_once(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            _write_rotating_credentials(tmp_path / "credentials", "NEW")      # the existing helper renews the file
            raise ExpiredTokenException("expired")
        return "{}", {}
    monkeypatch.setattr(client, "_invoke_once", expired_once)
    assert client.refine(model_id="approved-profile", prompt="safe", max_output_chars=100, timeout_seconds=1) == ("{}", {})
    assert len(attempts) == 2
    def denied(**kwargs):
        attempts.append(kwargs)
        raise RuntimeError("denied")
    monkeypatch.setattr(client, "_invoke_once", denied)
    with pytest.raises(RuntimeError):
        client.refine(model_id="approved-profile", prompt="safe", max_output_chars=100, timeout_seconds=1)
    assert len(attempts) == 3


def test_anthropic_request_forces_one_named_schema_response():
    request = _build_anthropic_request(prompt="safe bounded context", max_output_chars=12_000)
    assert request["messages"] == [{"role": "user", "content": "safe bounded context"}]
    assert request["tool_choice"] == {
        "type": "tool", "name": "submit_specification_refinement",
    }
    assert len(request["tools"]) == 1
    assert request["tools"][0]["strict"] is True
    response_schema = request["tools"][0]["input_schema"]
    assert response_schema["required"] == [
        "goal", "setup", "assertions", "rationale", "change_notes",
    ]
    assert response_schema["additionalProperties"] is False
    assert response_schema["properties"]["assertions"]["minItems"] == 1
    assert response_schema["properties"]["setup"]["anyOf"] == [
        {"type": "string"}, {"type": "null"},
    ]
    assert _strict_schema_read_timeout(45) == 240
    assert _strict_schema_read_timeout(300) == 300


def test_schema_response_extracts_only_one_named_envelope_and_discards_prose():
    proposal = json.loads(_valid_output())
    payload = {
        "content": [
            {"type": "text", "text": "untrusted preamble that must not be retained"},
            {
                "type": "tool_use",
                "name": "submit_specification_refinement",
                "input": proposal,
            },
        ],
    }
    extracted = _extract_schema_proposal(payload)
    assert json.loads(extracted) == proposal
    assert "untrusted preamble" not in extracted


@pytest.mark.parametrize("payload", [
    {},
    {"content": [{"type": "text", "text": "raw model output"}]},
    {"content": [{"type": "tool_use", "name": "unexpected", "input": {}}]},
    {"content": [{
        "type": "tool_use", "name": "submit_specification_refinement", "input": "not-an-object",
    }]},
    {"content": [
        {"type": "tool_use", "name": "submit_specification_refinement", "input": {}},
        {"type": "tool_use", "name": "submit_specification_refinement", "input": {}},
    ]},
])
def test_missing_or_ambiguous_schema_response_is_safely_rejected(payload):
    with pytest.raises(RefinementError) as caught:
        _extract_schema_proposal(payload)
    assert str(caught.value) == "Model returned no schema proposal."
    assert "raw model output" not in str(caught.value)


def test_batch_uses_one_injected_client_per_spec_and_keeps_source_unchanged(tmp_path):
    settings = _settings(tmp_path)
    clients: list[FakeClient] = []
    def factory():
        client = FakeClient(_valid_output())
        clients.append(client)
        return client
    service = RefinementService(settings, factory)
    preview, plans, docs, revisions, _read = _preview(service, tmp_path, paths=["010-first.md", "020-second.md"])
    original = {path: document.model_dump() for path, document in docs.items()}
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    result = service.get_job(job.id)
    assert result.state == "completed"
    assert [proposal.state for proposal in result.proposals] == ["ready", "ready"]
    assert len(clients) == 2
    assert all(len(client.calls) == 1 for client in clients)
    assert {path: document.model_dump() for path, document in docs.items()} == original
    assert all("target" not in client.calls[0]["prompt"].lower() or "target type" in client.calls[0]["prompt"].lower() for client in clients)


def test_invalid_or_unsafe_model_output_never_creates_a_ready_proposal(tmp_path):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient('{"goal":"x"}'))
    preview, plans, *_ = _preview(service, tmp_path)
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == "invalid-output"
    assert proposal.proposed is None
    assert proposal.error == "Model proposal did not match the required field schema."


def test_benign_credential_language_is_not_mistaken_for_secret_material(tmp_path):
    assert _UNSAFE_TEXT.search("Use the configured credentials.") is None
    for unsafe in ("password=not-safe", "Read .env", "Read .aws/credentials"):
        assert _UNSAFE_TEXT.search(unsafe) is not None
    service = RefinementService(
        _settings(tmp_path),
        lambda: FakeClient(_valid_output("Use the configured credentials supplied outside this specification.")),
    )
    preview, plans, *_ = _preview(service, tmp_path)
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == "ready"
    assert proposal.proposed is not None
    assert "configured credentials" in proposal.proposed.goal


@pytest.mark.parametrize(("raw", "expected"), [
    ("not json", "Model response was not valid JSON."),
    (json.dumps({**json.loads(_valid_output()), "target": "not allowed"}), "Model proposal included unsupported fields."),
    (json.dumps({**json.loads(_valid_output()), "goal": "Use token=not-safe."}), "Authoring text rejected at goal (rule: credential-value). Use separate credential controls for values; rejected text is not shown."),
    (json.dumps({**json.loads(_valid_output()), "assertions": ["   "]}), "Model proposal failed normal typed specification validation."),
])
def test_invalid_output_status_exposes_only_a_safe_validation_class(tmp_path, raw, expected):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(raw))
    preview, plans, *_ = _preview(service, tmp_path)
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == "invalid-output"
    assert proposal.error == expected
    assert "not-safe" not in proposal.error
    assert "target" not in proposal.error.lower()


def test_exact_json_markdown_fence_is_normalized_before_strict_validation(tmp_path):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(f"```json\n{_valid_output()}\n```"))
    preview, plans, docs, _revisions, _read = _preview(service, tmp_path)
    original = {path: document.model_dump() for path, document in docs.items()}
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == "ready"
    assert proposal.proposed is not None
    assert {path: document.model_dump() for path, document in docs.items()} == original


@pytest.mark.parametrize("raw", [
    f"Here is the proposal:\n{_valid_output()}",
    f"```json\n{_valid_output()}\n```\nReview it carefully.",
    f"```yaml\n{_valid_output()}\n```",
])
def test_prose_or_non_json_fence_remains_invalid_output(tmp_path, raw):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(raw))
    preview, plans, *_ = _preview(service, tmp_path)
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == "invalid-output"
    assert proposal.proposed is None


def test_accept_is_local_only_and_stale_source_is_never_merged(tmp_path):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(_valid_output()))
    preview, plans, docs, revisions, read = _preview(service, tmp_path)
    job = service.create_job(project_name="Sample", mode="selected", preview=preview, plans=plans)
    service.drain()
    ready = service.get_job(job.id).proposals[0]
    accepted = service.accept(proposal_id=ready.id, read_current=read)
    assert accepted.state == "accepted-locally"
    assert docs[ready.spec_path].goal == "Check visible state."

    # A separate ready proposal sees the changed revision and becomes stale;
    # neither case writes the source or attempts an automatic merge.
    preview2, plans2, _docs2, _revisions2, _read2 = _preview(service, tmp_path)
    second_job = service.create_job(project_name="Sample", mode="selected", preview=preview2, plans=plans2)
    service.drain()
    second_ready = service.get_job(second_job.id).proposals[0]
    revisions[ready.spec_path] = "f" * 64
    stale = service.accept(proposal_id=second_ready.id, read_current=read)
    assert stale.state == "stale"
    assert docs[ready.spec_path].goal == "Check visible state."


def test_context_rejects_unsafe_selected_content_and_reports_invalid_guidance(tmp_path):
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(_valid_output()))
    project = _project(tmp_path)
    bad = SpecDocument(path="010-first.md", title="Bad", goal="Use token=not-safe.", assertions=["Never run."])
    with pytest.raises(RefinementError):
        service.preview(
            project_name="Sample", project=project, project_dir=str(tmp_path), requested_paths=[bad.path], mode="this",
            include_manual=False, include_siblings=False, full_sibling_paths=[], guidance_ids=["unknown"],
            read_spec=lambda _path: (bad, "a" * 64), all_paths=[bad.path],
        )
    catalog = service.guidance_catalog()
    assert catalog.eligible == []
    assert catalog.excluded


def _make_refinement_app(tmp_path: Path, fake: FakeClient):
    specs = tmp_path / "specs" / "sample"
    manuals = tmp_path / "manuals" / "sample"
    reports = tmp_path / "reports"
    specs.mkdir(parents=True); manuals.mkdir(parents=True); reports.mkdir()
    (manuals / "manual.md").write_text("# Manual\n\nVisible checks only.\n")
    (specs / "project.yaml").write_text(
        "name: Sample\nmanual_dir: " + str(manuals) + "\ntarget:\n  type: local-app\n  app: ignored\n  window: ignored\n"
        "schedule: '0 3 * * *'\nmax_steps: 20\nmax_seconds: 60\nenabled: true\n"
    )
    (specs / "010-first.md").write_text("# Test: First\n\n## Goal\nCheck visible state.\n\n## Assertions\n- A status card is present.\n")
    for key in list(os.environ):
        if key.startswith("DASHBOARD_") or key == "TESTS_MANUALS_DIR":
            os.environ.pop(key)
    os.environ.update({
        "DASHBOARD_AUTH_TOKEN": "viewer", "DASHBOARD_AUTH_OPERATOR_TOKEN": "operator",
        "DASHBOARD_SPECS_DIR": str(specs.parent), "DASHBOARD_REPORTS_DIR": str(reports),
        "DASHBOARD_INDEX_INTERVAL": "999", "TESTS_MANUALS_DIR": str(tmp_path / "manuals"),
        "DASHBOARD_AUTHORING_REFINEMENT_ENABLED": "true", "DASHBOARD_AUTHORING_MODEL_ID": "approved-profile",
        "DASHBOARD_AUTHORING_REGION": "us-west-2", "DASHBOARD_AUTHORING_PROFILE": "rotating-profile",
        "DASHBOARD_AUTHORING_SHARED_CREDENTIALS_FILE": str(tmp_path / "credentials"),
        "DASHBOARD_AUTHORING_SHARED_CONFIG_FILE": str(tmp_path / "config"),
        "DASHBOARD_AUTHORING_STATE_ROOT": str(tmp_path / "private-state"),
        "DASHBOARD_AUTHORING_GUIDANCE_ROOT": str(tmp_path / "guidance"),
    })
    import dashboard.config as config
    import dashboard.editor_routes as editor_routes
    import dashboard.refinement as refinement
    import dashboard.refinement_routes as refinement_routes
    import dashboard.app as app_module
    for module in (config, editor_routes, refinement_routes, app_module):
        importlib.reload(module)
    app = app_module.create_app()
    # Earlier full-suite tests deliberately reload/remove dashboard modules.
    # Inject the service class from the current module identity so the router's
    # intentional isinstance boundary remains valid under that test isolation.
    app.state.refinement_service = refinement.RefinementService(config.settings, lambda: fake)
    return app, specs


def test_routes_are_operator_only_and_accept_populates_no_source_write(tmp_path):
    fake = FakeClient(_valid_output())
    app, specs = _make_refinement_app(tmp_path, fake)
    viewer = {"Authorization": "Bearer viewer"}; operator = {"Authorization": "Bearer operator"}
    with TestClient(app, raise_server_exceptions=True) as client:
        intent = {"mode": "this", "paths": ["010-first.md"], "include_manual": False, "include_siblings": False, "full_sibling_paths": [], "guidance_ids": []}
        assert client.post("/api/v1/projects/Sample/authoring/refinements/context-preview", headers=viewer, json=intent).status_code == 403
        preview = client.post("/api/v1/projects/Sample/authoring/refinements/context-preview", headers=operator, json=intent)
        assert preview.status_code == 200, preview.text
        original = (specs / "010-first.md").read_text()
        job = client.post("/api/v1/projects/Sample/authoring/refinements/jobs", headers=operator, json={**intent, "fingerprint": preview.json()["preview"]["fingerprint"], "confirm_all": False})
        assert job.status_code == 202, job.text
        proposal = client.get(f"/api/v1/projects/Sample/authoring/refinements/jobs/{job.json()['id']}", headers=operator).json()["proposals"][0]
        assert proposal["state"] == "ready"
        accepted = client.post(f"/api/v1/projects/Sample/authoring/refinements/proposals/{proposal['id']}/accept", headers=operator)
        assert accepted.status_code == 200
        assert accepted.json()["state"] == "accepted-locally"
        assert (specs / "010-first.md").read_text() == original


def test_template_contract_has_guarded_controls_without_raw_prompt_surface():
    template = Path(__file__).parents[1] / "templates" / "dashboard" / "index.html"
    text = template.read_text()
    for required in (
        "Enhance this specification", "Enhance selected specifications", "Enhance all specifications",
        "Context Inspector", "Accept into typed form", "Reject proposal", "Cancel queued work",
        "Validate / Preview", "refinement_proposal_id",
    ):
        assert required in text
    assert "raw prompt" not in text.lower()
