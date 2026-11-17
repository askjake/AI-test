from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard.auth import Actor
from dashboard.author_builder import (
    AuthorBuilderError,
    AuthorBuilderService,
    CandidateApplyRequest,
    CandidateCreateRequest,
    CandidateValidationRequest,
    FileChange,
    HistoryDeleteRequest,
    HistoryPreviewRequest,
    HistoryRetentionRequest,
    HostKeyDiscoverRequest,
    HostKeyDiscoveryService,
    HostKeyEligibilityRequest,
    HostKeySaveRequest,
    IntentCreateRequest,
    ModelRefineRequest,
    PlanCreateRequest,
    route_revision,
)
from dashboard.authoring import parse_project_document
from dashboard.config import DashboardSettings
from dashboard.author_builder_routes import router as builder_router
from dashboard.auth import verify_operator
from target_routing import build_ssh_local_forward_argv


PROJECT_YAML = """\
name: Sample
enabled: true
schedule: 0 3 * * *
manual_dir: ./manual
target:
  type: local-app
  app: xterm
  window: xterm
ssh_host_allowlist: []
rdp_host_allowlist: []
vnc_host_allowlist: []
"""

SPEC = """# Test: Login\n\n## Goal\nOpen the login page.\n\n## Assertions\n- The login page is visible.\n"""
UPDATED_SPEC = """# Test: Login\n\n## Goal\nOpen and verify the login page.\n\n## Assertions\n- The login page is visible.\n- The form is ready.\n"""


def actor(name: str = "alice") -> Actor:
    return Actor(subject=f"oidc:{name}", role="operator", auth_method="oidc", display_name=name)


def make_project(root: Path, slug: str = "sample", project_yaml: str = PROJECT_YAML) -> Path:
    project = root / slug
    (project / "manual").mkdir(parents=True)
    (project / "project.yaml").write_text(project_yaml, encoding="utf-8")
    (project / "001-login.md").write_text(SPEC, encoding="utf-8")
    (project / "manual" / "manual.md").write_text("# Manual\n", encoding="utf-8")
    return project


class FakeModel:
    def __init__(self):
        self.calls = []

    def refine(self, payload):
        self.calls.append(payload)
        return {
            "summary": "Refine the login specification in the isolated candidate.",
            "files": ["001-login.md"],
            "validations": ["project-bundle"],
            "risks": ["Human review remains required."],
        }


def service(
    tmp_path: Path, *, model=None, host_key_enabled: bool = False
) -> tuple[AuthorBuilderService, DashboardSettings]:
    specs = tmp_path / "specs"
    specs.mkdir()
    settings = DashboardSettings(
        specs_dir=str(specs),
        reports_dir=str(tmp_path / "reports"),
        secrets_dir=str(tmp_path / "secrets"),
        author_builder_state_root=str(tmp_path / "builder-state"),
        author_builder_host_key_discovery_enabled=host_key_enabled,
    )
    result = AuthorBuilderService(settings, model_client=model)
    return result, settings


def authorize(builder: AuthorBuilderService, who: Actor, slug: str = "sample") -> str:
    builder.claim_created_project(who, slug, "0" * 64)
    return builder.inventory(who, slug).project_revision


def test_builder_requires_unique_oidc_and_project_authorization(tmp_path):
    builder, settings = service(tmp_path)
    make_project(Path(settings.specs_dir))
    bootstrap = Actor("local-bootstrap-operator", "operator", "bootstrap-bearer")
    with pytest.raises(AuthorBuilderError, match="OIDC") as denied:
        builder.inventory(bootstrap, "sample")
    assert denied.value.status_code == 403

    authorize(builder, actor("alice"))
    with pytest.raises(AuthorBuilderError) as hidden:
        builder.inventory(actor("bob"), "sample")
    assert hidden.value.status_code == 404


def test_builder_routes_do_not_turn_shared_dashboard_access_into_author_access(tmp_path):
    builder, settings = service(tmp_path)
    make_project(Path(settings.specs_dir))
    owner = actor("alice")
    authorize(builder, owner)
    discovery_calls = []
    discovery = HostKeyDiscoveryService(
        settings, builder,
        transport=lambda *args: discovery_calls.append(args) or b"",
    )
    app = FastAPI()
    app.state.author_builder_service = builder
    app.state.host_key_discovery_service = discovery
    app.include_router(builder_router, prefix="/api/v1")
    app.dependency_overrides[verify_operator] = lambda: owner
    with TestClient(app) as client:
        response = client.get("/api/v1/authoring/builder/projects/sample/inventory")
        assert response.status_code == 200
        assert discovery_calls == []
        app.dependency_overrides[verify_operator] = lambda: actor("bob")
        assert client.get("/api/v1/authoring/builder/projects/sample/inventory").status_code == 404
        app.dependency_overrides[verify_operator] = lambda: Actor(
            "local-bootstrap-operator", "operator", "bootstrap-bearer"
        )
        assert client.get("/api/v1/authoring/builder/projects/sample/inventory").status_code == 403


def test_public_host_key_api_rejects_client_route_policy_and_never_calls_transport(tmp_path):
    builder, settings = service(tmp_path, host_key_enabled=True)
    make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    owner = actor()
    project_revision = authorize(builder, owner)
    calls = []
    discovery = HostKeyDiscoveryService(
        settings, builder, transport=lambda *args: calls.append(args) or b"unreachable"
    )
    app = FastAPI()
    app.state.author_builder_service = builder
    app.state.host_key_discovery_service = discovery
    app.include_router(builder_router, prefix="/api/v1")
    app.dependency_overrides[verify_operator] = lambda: owner
    attacker_policy = {
        "dir_name": "sample",
        "target": {
            "type": "vnc", "host": "10.0.0.20", "port": 5902,
            "route": {"type": "ssh-jump", "host": "attacker.example", "port": 22},
        },
        "ssh_host_allowlist": ["attacker.example"],
    }
    with TestClient(app) as client:
        eligibility = client.post(
            "/api/v1/authoring/builder/projects/sample/host-key/eligibility",
            json={"project_revision": project_revision, "project": attacker_policy},
        )
        assert eligibility.status_code == 422
        discovery_attempt = client.post(
            "/api/v1/authoring/builder/projects/sample/host-key/discover",
            json={
                "project_revision": project_revision,
                "expected_route_revision": "0" * 64,
                "confirmation": "Discover host-key candidate",
                "route": {"host": "attacker.example", "port": 22},
                "ssh_host_allowlist": ["attacker.example"],
            },
        )
        assert discovery_attempt.status_code == 422
    assert calls == []


def test_inspect_understand_plan_candidate_offline_validation_and_explicit_apply(tmp_path):
    model = FakeModel()
    builder, settings = service(tmp_path, model=model)
    project = make_project(Path(settings.specs_dir))
    who = actor()
    revision = authorize(builder, who)

    inventory = builder.inventory(who, "sample")
    assert inventory.status == "local-inspection-only"
    assert {item.path for item in inventory.files} == {"001-login.md", "manual/manual.md", "project.yaml"}
    assert model.calls == []

    intent = builder.create_intent(who, "sample", IntentCreateRequest(
        project_revision=revision,
        objective="Improve the login test without contacting its target.",
        success_criteria=["The candidate passes typed specification checks."],
        allowed_offline_actions=["inventory", "diff", "static-authoring-tests"],
    ))
    plan = builder.create_plan(who, "sample", PlanCreateRequest(
        intent_id=intent.id,
        intent_revision=intent.revision,
        project_revision=revision,
        proposed_files=["001-login.md"],
        validation_categories=["project-bundle"],
    ))
    assert plan.history.selected_projects == []
    assert plan.history.items == []
    assert model.calls == []

    refined = builder.refine_plan(who, "sample", ModelRefineRequest(
        plan_id=plan.id,
        plan_revision=plan.revision,
        confirmation="Refine this plan with the configured model",
    ))
    assert len(model.calls) == 1
    assert set(model.calls[0]) == {"intent", "inventory", "history_capsule", "constraints", "response_schema"}
    assert SPEC not in str(model.calls[0])

    candidate = builder.create_candidate(who, "sample", CandidateCreateRequest(
        plan_id=refined.id,
        plan_revision=refined.revision,
        project_revision=revision,
        changes=[FileChange(path="001-login.md", operation="write", content=UPDATED_SPEC)],
    ))
    assert (project / "001-login.md").read_text(encoding="utf-8") == SPEC
    assert "original project unchanged" not in candidate.model_dump_json().lower()
    report = builder.validate_candidate(who, "sample", candidate.id, CandidateValidationRequest(
        candidate_revision=candidate.revision,
        categories=["project-bundle"],
    ))
    assert report.status == "passed"
    assert report.results[0].components == [
        "typed-project-config", "all-managed-specs", "referenced-manual-structure",
        "json-yaml-syntax", "optional-import-composition-manifest-consistency",
    ]
    assert "no project was executed" in report.results[0].message
    assert (project / "001-login.md").read_text(encoding="utf-8") == SPEC

    with pytest.raises(AuthorBuilderError, match="Confirmation"):
        builder.apply_candidate(who, "sample", candidate.id, CandidateApplyRequest(
            candidate_revision=candidate.revision,
            expected_project_revision=revision,
            confirmation="wrong-project",
        ))
    applied = builder.apply_candidate(who, "sample", candidate.id, CandidateApplyRequest(
        candidate_revision=candidate.revision,
        expected_project_revision=revision,
        confirmation="sample",
    ))
    assert applied.state == "applied"
    assert (project / "001-login.md").read_text(encoding="utf-8") == UPDATED_SPEC
    if os.name != "nt":
        assert stat.S_IMODE((project / "001-login.md").stat().st_mode) == 0o644
        assert stat.S_IMODE((project / "manual").stat().st_mode) == 0o755
    scopes = {item.action_scope for item in builder.actions(who, "sample")}
    assert {"metadata-only", "model", "candidate-only", "project-write"} <= scopes


def test_exact_owner_claim_can_be_removed_for_publish_rollback(tmp_path):
    builder, settings = service(tmp_path)
    make_project(Path(settings.specs_dir))
    who = actor()
    builder.claim_created_project(who, "sample", "1" * 64)
    builder.unclaim_created_project_if_eligible(who, "sample", "1" * 64)
    with pytest.raises(AuthorBuilderError) as hidden:
        builder.inventory(who, "sample")
    assert hidden.value.status_code == 404


def test_project_bundle_reports_static_component_failures_without_executing_project(tmp_path):
    builder, settings = service(tmp_path)
    project = make_project(Path(settings.specs_dir))
    who = actor()
    revision = authorize(builder, who)
    intent = builder.create_intent(who, "sample", IntentCreateRequest(
        project_revision=revision,
        objective="Validate a deliberately broken isolated candidate.",
        allowed_offline_actions=["typed-validation", "static-authoring-tests"],
    ))
    plan = builder.create_plan(who, "sample", PlanCreateRequest(
        intent_id=intent.id,
        intent_revision=intent.revision,
        project_revision=revision,
        proposed_files=["manual/manual.md", "support/data.json"],
        validation_categories=["project-bundle"],
    ))
    candidate = builder.create_candidate(who, "sample", CandidateCreateRequest(
        plan_id=plan.id,
        plan_revision=plan.revision,
        project_revision=revision,
        changes=[
            FileChange(path="manual/manual.md", operation="delete"),
            FileChange(path="support/data.json", operation="write", content="{broken"),
        ],
    ))
    with pytest.raises(AuthorBuilderError) as mismatched:
        builder.validate_candidate(
            who, "sample", candidate.id,
            CandidateValidationRequest(
                candidate_revision=candidate.revision, categories=["typed-project"]
            ),
        )
    assert mismatched.value.code == "validation_selection_mismatch"
    report = builder.validate_candidate(
        who, "sample", candidate.id,
        CandidateValidationRequest(
            candidate_revision=candidate.revision, categories=["project-bundle"]
        ),
    )
    assert report.status == "failed"
    assert set(report.results[0].failed_components) == {
        "referenced-manual-structure", "json-yaml-syntax"
    }
    assert (project / "manual" / "manual.md").is_file()
    with pytest.raises(AuthorBuilderError) as blocked:
        builder.apply_candidate(who, "sample", candidate.id, CandidateApplyRequest(
            candidate_revision=candidate.revision,
            expected_project_revision=revision,
            confirmation="sample",
        ))
    assert blocked.value.code == "offline_validation_not_passing"
    assert any(
        item.action == "run-offline-validation"
        and item.details["validation_categories"] == ["project-bundle"]
        for item in builder.actions(who, "sample")
    )


def test_project_bundle_checks_optional_import_composition_manifest_content(tmp_path):
    builder, settings = service(tmp_path)
    project = make_project(Path(settings.specs_dir))
    support = project / "support"
    support.mkdir()
    data = b'{"enabled":true}\n'
    (support / "data.json").write_bytes(data)
    manifest = {
        "version": 1,
        "files": [{
            "path": "support/data.json",
            "size": len(data),
            "digest": hashlib.sha256(data).hexdigest(),
        }],
    }
    (support / "project-import-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    who = actor()
    revision = authorize(builder, who)
    intent = builder.create_intent(who, "sample", IntentCreateRequest(
        project_revision=revision,
        objective="Change structured data while retaining exact import provenance.",
        allowed_offline_actions=["typed-validation", "static-authoring-tests"],
    ))
    plan = builder.create_plan(who, "sample", PlanCreateRequest(
        intent_id=intent.id,
        intent_revision=intent.revision,
        project_revision=revision,
        proposed_files=["support/data.json"],
        validation_categories=["project-bundle"],
    ))
    candidate = builder.create_candidate(who, "sample", CandidateCreateRequest(
        plan_id=plan.id,
        plan_revision=plan.revision,
        project_revision=revision,
        changes=[FileChange(
            path="support/data.json", operation="write", content='{"enabled":false}\n'
        )],
    ))
    report = builder.validate_candidate(
        who, "sample", candidate.id,
        CandidateValidationRequest(
            candidate_revision=candidate.revision, categories=["project-bundle"]
        ),
    )
    assert report.status == "failed"
    assert report.results[0].failed_components == [
        "optional-import-composition-manifest-consistency"
    ]
    assert (support / "data.json").read_bytes() == data


def test_model_refinement_cannot_weaken_plan_bound_offline_validation(tmp_path):
    class WeakeningModel(FakeModel):
        def refine(self, payload):
            result = super().refine(payload)
            result["validations"] = ["typed-project"]
            return result

    builder, settings = service(tmp_path, model=WeakeningModel())
    make_project(Path(settings.specs_dir))
    who = actor()
    revision = authorize(builder, who)
    intent = builder.create_intent(who, "sample", IntentCreateRequest(
        project_revision=revision, objective="Preserve the complete reviewed validation gate."
    ))
    plan = builder.create_plan(who, "sample", PlanCreateRequest(
        intent_id=intent.id,
        intent_revision=intent.revision,
        project_revision=revision,
        proposed_files=["001-login.md"],
        validation_categories=["project-bundle"],
    ))
    with pytest.raises(AuthorBuilderError) as rejected:
        builder.refine_plan(who, "sample", ModelRefineRequest(
            plan_id=plan.id,
            plan_revision=plan.revision,
            confirmation="Refine this plan with the configured model",
        ))
    assert rejected.value.code == "invalid_model_output"


def test_stale_revisions_and_changes_outside_plan_are_rejected(tmp_path):
    builder, settings = service(tmp_path)
    project = make_project(Path(settings.specs_dir))
    who = actor()
    revision = authorize(builder, who)
    intent = builder.create_intent(who, "sample", IntentCreateRequest(
        project_revision=revision, objective="Improve one test."
    ))
    plan = builder.create_plan(who, "sample", PlanCreateRequest(
        intent_id=intent.id, intent_revision=intent.revision,
        project_revision=revision, proposed_files=["001-login.md"],
        validation_categories=["typed-specs"],
    ))
    with pytest.raises(AuthorBuilderError, match="outside"):
        builder.create_candidate(who, "sample", CandidateCreateRequest(
            plan_id=plan.id, plan_revision=plan.revision, project_revision=revision,
            changes=[FileChange(path="project.yaml", operation="write", content=PROJECT_YAML)],
        ))
    (project / "manual" / "manual.md").write_text("# Changed manual\n", encoding="utf-8")
    with pytest.raises(AuthorBuilderError, match="changed"):
        builder.create_candidate(who, "sample", CandidateCreateRequest(
            plan_id=plan.id, plan_revision=plan.revision, project_revision=revision,
            changes=[FileChange(path="001-login.md", operation="write", content=UPDATED_SPEC)],
        ))


def test_history_is_selected_redacted_owner_only_detachable_and_retained(tmp_path):
    builder, settings = service(tmp_path)
    make_project(Path(settings.specs_dir), "sample")
    make_project(Path(settings.specs_dir), "other", PROJECT_YAML.replace("Sample", "Other"))
    who = actor()
    sample_revision = authorize(builder, who, "sample")
    other_revision = authorize(builder, who, "other")
    builder.record_history(
        who, project="other", project_revision=other_revision,
        request_summary="Improve prior login coverage for 10.79.85.47:5902.", structural_category="desktop-ui",
        change_category="spec-refactor", plan_decision="Kept the change candidate-only.",
        test_identifiers=["typed-specs"], outcome_classification="passed",
        evidence_summary="One offline category passed.",
    )
    assert builder.history_capsule(who, "sample", HistoryPreviewRequest()).items == []
    capsule = builder.history_capsule(who, "sample", HistoryPreviewRequest(source_projects=["other"]))
    assert len(capsule.items) == 1
    assert capsule.items[0].project == "other"
    assert "10.79.85.47" not in capsule.items[0].request_summary
    assert "redacted" in capsule.items[0].request_summary
    with pytest.raises(AuthorBuilderError, match="credential"):
        builder.record_history(
            who, project="sample", project_revision=sample_revision,
            request_summary="password=do-not-store", structural_category="desktop-ui",
            change_category="spec", plan_decision="none", test_identifiers=[],
            outcome_classification="failed", evidence_summary="Rejected.",
        )
    retention = builder.set_history_retention(who, "sample", HistoryRetentionRequest(
        expected_project_revision=sample_revision, maximum_items=1, maximum_age_days=30,
    ))
    assert retention["maximum_items"] == 1
    deleted = builder.delete_history(who, "other", HistoryDeleteRequest(
        expected_project_revision=other_revision, detach_project=True,
    ))
    assert deleted == {"deleted": 1, "detached": True}


def vnc_jump_document() -> str:
    return """\
name: Sample
enabled: true
schedule: 0 3 * * *
manual_dir: ./manual
target:
  type: vnc
  host: 10.0.0.20
  port: 5902
  password_file: vnc.pass
  window: TigerVNC
  gateway_password_file: jump.pass
  route:
    type: ssh-jump
    host: jump.example.test
    user: operator
    port: 2222
    known_hosts_file: pending.hosts
ssh_host_allowlist:
  - jump.example.test
rdp_host_allowlist: []
vnc_host_allowlist:
  - 10.0.0.20
"""


def test_host_key_discovery_is_explicit_bounded_revision_bound_and_separate_from_trust(tmp_path):
    builder, settings = service(tmp_path, host_key_enabled=True)
    make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    who = actor()
    project_revision = authorize(builder, who)
    document = parse_project_document(vnc_jump_document(), dir_name="sample").document
    revision = route_revision(document)
    key = base64.b64encode(b"a" * 32).decode("ascii")
    calls = []
    now = [1_700_000_000.0]

    def transport(host, port, timeout, maximum):
        calls.append((host, port, timeout, maximum))
        return f"ignored ssh-ed25519 {key}\n".encode()

    discovery = HostKeyDiscoveryService(settings, builder, transport=transport, clock=lambda: now[0])
    eligible = discovery.eligibility(who, "sample", HostKeyEligibilityRequest(
        project_revision=project_revision,
    ))
    assert eligible.host == "jump.example.test"
    assert calls == []

    candidate = discovery.discover(who, "sample", HostKeyDiscoverRequest(
        project_revision=project_revision, expected_route_revision=revision,
        confirmation="Discover host-key candidate",
    ))
    assert calls == [("jump.example.test", 2222, settings.author_builder_host_key_timeout_seconds, settings.author_builder_host_key_max_bytes)]
    assert candidate.known_hosts_candidate.startswith("[jump.example.test]:2222 ssh-ed25519 ")
    assert not Path(settings.secrets_dir).exists()

    secrets = Path(settings.secrets_dir)
    secrets.mkdir()
    outside = tmp_path / "outside.hosts"
    outside.write_text("must remain unchanged\n", encoding="utf-8")
    (secrets / "linked.hosts").symlink_to(outside)
    with pytest.raises(AuthorBuilderError):
        discovery.save(who, "sample", HostKeySaveRequest(
            project_revision=project_revision, expected_route_revision=revision,
            candidate_id=candidate.id, reference_name="linked.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
            confirmation="Save reviewed host key",
        ))
    assert outside.read_text(encoding="utf-8") == "must remain unchanged\n"

    saved = discovery.save(who, "sample", HostKeySaveRequest(
        project_revision=project_revision, expected_route_revision=revision,
        candidate_id=candidate.id, reference_name="jump-reviewed-20260914.hosts",
        reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
        confirmation="Save reviewed host key",
    ))
    path = Path(settings.secrets_dir) / saved.reference_name
    assert path.is_file() and not path.is_symlink()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8").strip() == candidate.known_hosts_candidate
    with pytest.raises(AuthorBuilderError):
        discovery.save(who, "sample", HostKeySaveRequest(
            project_revision=project_revision, expected_route_revision=revision,
            candidate_id=candidate.id, reference_name="another.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
            confirmation="Save reviewed host key",
        ))
    ledger_text = "\n".join(item.model_dump_json() for item in builder.actions(who, "sample"))
    assert candidate.known_hosts_candidate not in ledger_text
    assert key not in ledger_text


def test_duplicate_or_malformed_host_key_save_does_not_consume_valid_candidate(tmp_path):
    builder, settings = service(tmp_path, host_key_enabled=True)
    make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    who = actor()
    project_revision = authorize(builder, who)
    document = parse_project_document(vnc_jump_document(), dir_name="sample").document
    revision = route_revision(document)
    key = base64.b64encode(b"d" * 32).decode("ascii")
    discovery = HostKeyDiscoveryService(
        settings, builder, transport=lambda *_: f"host ssh-ed25519 {key}\n".encode()
    )
    candidate = discovery.discover(who, "sample", HostKeyDiscoverRequest(
        project_revision=project_revision,
        expected_route_revision=revision,
        confirmation="Discover host-key candidate",
    ))
    root = Path(settings.secrets_dir)
    root.mkdir()
    duplicate = root / "duplicate.hosts"
    duplicate.write_text("existing\n", encoding="utf-8")
    duplicate.chmod(0o600)
    common = dict(
        project_revision=project_revision,
        expected_route_revision=revision,
        candidate_id=candidate.id,
        confirmation="Save reviewed host key",
    )
    with pytest.raises(AuthorBuilderError) as malformed:
        discovery.save(who, "sample", HostKeySaveRequest(
            **common, reference_name="malformed.hosts",
            reviewed_known_hosts_candidate="attacker.example ssh-ed25519 " + key,
        ))
    assert malformed.value.code == "invalid_host_key"
    with pytest.raises(AuthorBuilderError) as exists:
        discovery.save(who, "sample", HostKeySaveRequest(
            **common, reference_name="duplicate.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
        ))
    assert exists.value.code == "reference_exists"
    saved = discovery.save(who, "sample", HostKeySaveRequest(
        **common, reference_name="final.hosts",
        reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
    ))
    assert saved.status == "created"
    assert duplicate.read_text(encoding="utf-8") == "existing\n"


def test_host_key_candidate_expires_and_route_change_invalidates_it(tmp_path):
    builder, settings = service(tmp_path, host_key_enabled=True)
    make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    who = actor()
    project_revision = authorize(builder, who)
    document = parse_project_document(vnc_jump_document(), dir_name="sample").document
    revision = route_revision(document)
    key = base64.b64encode(b"b" * 32).decode("ascii")
    now = [100.0]
    discovery = HostKeyDiscoveryService(
        settings, builder,
        transport=lambda *_: f"host ssh-ed25519 {key}\n".encode(),
        clock=lambda: now[0],
    )
    candidate = discovery.discover(who, "sample", HostKeyDiscoverRequest(
        project_revision=project_revision, expected_route_revision=revision,
        confirmation="Discover host-key candidate",
    ))
    (Path(settings.specs_dir) / "sample" / "project.yaml").write_text(
        vnc_jump_document().replace("port: 2222", "port: 2223"), encoding="utf-8"
    )
    changed_revision = builder.inventory(who, "sample").project_revision
    with pytest.raises(AuthorBuilderError, match="route"):
        discovery.save(who, "sample", HostKeySaveRequest(
            project_revision=changed_revision, expected_route_revision=revision,
            candidate_id=candidate.id, reference_name="changed.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
            confirmation="Save reviewed host key",
        ))
    (Path(settings.specs_dir) / "sample" / "project.yaml").write_text(
        vnc_jump_document(), encoding="utf-8"
    )
    project_revision = builder.inventory(who, "sample").project_revision
    candidate = discovery.discover(who, "sample", HostKeyDiscoverRequest(
        project_revision=project_revision, expected_route_revision=revision,
        confirmation="Discover host-key candidate",
    ))
    now[0] += settings.author_builder_host_key_ttl_seconds + 1
    with pytest.raises(AuthorBuilderError, match="expired"):
        discovery.save(who, "sample", HostKeySaveRequest(
            project_revision=project_revision, expected_route_revision=revision,
            candidate_id=candidate.id, reference_name="expired.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
            confirmation="Save reviewed host key",
        ))


@pytest.mark.parametrize("policy_change", [
    lambda raw: raw.replace("type: vnc", "type: local-app", 1),
    lambda raw: raw.replace("10.0.0.20", "10.0.0.21"),
    lambda raw: raw.replace("port: 5902", "port: 5903", 1),
    lambda raw: raw.replace("user: operator", "user: reviewer", 1),
    lambda raw: raw.replace("jump.example.test", "jump-two.example.test"),
    lambda raw: raw.replace("port: 2222", "port: 2223", 1),
    lambda raw: raw.replace(
        "  - jump.example.test\nrdp_host_allowlist:",
        "  - jump.example.test\n  - spare.example.test\nrdp_host_allowlist:",
    ),
], ids=["target-kind", "target-host", "target-port", "jump-user", "jump-host", "jump-port", "ssh-allowlist"])
def test_each_persisted_route_policy_change_invalidates_candidate(tmp_path, policy_change):
    builder, settings = service(tmp_path, host_key_enabled=True)
    project = make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    who = actor()
    project_revision = authorize(builder, who)
    document = parse_project_document(vnc_jump_document(), dir_name="sample").document
    old_route_revision = route_revision(document)
    key = base64.b64encode(b"c" * 32).decode("ascii")
    discovery = HostKeyDiscoveryService(
        settings, builder, transport=lambda *_: f"host ssh-ed25519 {key}\n".encode()
    )
    candidate = discovery.discover(who, "sample", HostKeyDiscoverRequest(
        project_revision=project_revision,
        expected_route_revision=old_route_revision,
        confirmation="Discover host-key candidate",
    ))
    project.joinpath("project.yaml").write_text(
        policy_change(vnc_jump_document()), encoding="utf-8"
    )
    changed_revision = builder.inventory(who, "sample").project_revision
    with pytest.raises(AuthorBuilderError):
        discovery.save(who, "sample", HostKeySaveRequest(
            project_revision=changed_revision,
            expected_route_revision=old_route_revision,
            candidate_id=candidate.id,
            reference_name="changed-policy.hosts",
            reviewed_known_hosts_candidate=candidate.known_hosts_candidate,
            confirmation="Save reviewed host key",
        ))


def test_host_key_discovery_disabled_stale_missing_and_disallowed_routes_fail_without_transport(tmp_path):
    builder, settings = service(tmp_path)
    project = make_project(Path(settings.specs_dir), project_yaml=vnc_jump_document())
    who = actor()
    revision = authorize(builder, who)
    calls = []
    disabled = HostKeyDiscoveryService(
        settings, builder, transport=lambda *args: calls.append(args) or b"unreachable"
    )
    with pytest.raises(AuthorBuilderError) as denied:
        disabled.eligibility(who, "sample", HostKeyEligibilityRequest(project_revision=revision))
    assert denied.value.code == "host_key_discovery_disabled"
    assert calls == []

    enabled_settings = settings.model_copy(update={"author_builder_host_key_discovery_enabled": True})
    discovery = HostKeyDiscoveryService(
        enabled_settings, builder, transport=lambda *args: calls.append(args) or b"unreachable"
    )
    with pytest.raises(AuthorBuilderError) as stale:
        discovery.eligibility(who, "sample", HostKeyEligibilityRequest(project_revision="0" * 64))
    assert stale.value.code == "stale_project"
    assert calls == []

    project.joinpath("project.yaml").write_text(PROJECT_YAML, encoding="utf-8")
    missing_revision = builder.inventory(who, "sample").project_revision
    with pytest.raises(AuthorBuilderError) as missing:
        discovery.eligibility(
            who, "sample", HostKeyEligibilityRequest(project_revision=missing_revision)
        )
    assert missing.value.code == "ssh_jump_required"

    project.joinpath("project.yaml").write_text(
        vnc_jump_document().replace("  - jump.example.test\n", ""), encoding="utf-8"
    )
    disallowed_revision = builder.inventory(who, "sample").project_revision
    with pytest.raises(AuthorBuilderError) as disallowed:
        discovery.eligibility(
            who, "sample", HostKeyEligibilityRequest(project_revision=disallowed_revision)
        )
    assert disallowed.value.code in {"persisted_project_invalid", "jump_host_not_allowed"}
    assert calls == []

def test_vnc_jump_proxy_keeps_original_gateway_identity_and_strict_known_hosts():
    argv = build_ssh_local_forward_argv(
        "ssh", "operator@jump.example.test",
        local_port=45901, target_host="10.0.0.20", target_port=5902,
        gateway_port=2222, known_hosts_path="/run/secrets/jump.hosts",
        proxy_command=("python", "-m", "orchestrator.target_relay", "connect-loopback", "--port", "45100"),
    )
    assert "StrictHostKeyChecking=yes" in argv
    assert "UserKnownHostsFile=/run/secrets/jump.hosts" in argv
    assert argv[-1] == "operator@jump.example.test"
    proxy = next(item for item in argv if item.startswith("ProxyCommand="))
    assert "127.0.0.1" not in argv[-1]
    assert "connect-loopback" in proxy
    assert not any("password" in item.lower() for item in argv)


def test_author_builder_ui_exposes_staged_actions_without_automatic_effects():
    html = Path("templates/dashboard/index.html").read_text(encoding="utf-8")
    for marker in (
        "1. Understand", "2. Inspect", "3. Approved history", "4. Plan",
        "5. Create and validate isolated candidate", "6. Review and choose",
        "Discover host-key candidate", "Save reviewed host key",
        "Compose a project from multiple approved roots",
        "History off by default", "Original unchanged until Apply",
        "Target preflight / project run requires explicit authorization",
        "Complete project bundle (recommended)",
    ):
        assert marker in html
    assert "onclick=\"discoverAuthorHostKey()\"" in html
    assert "onload=\"discoverAuthorHostKey()\"" not in html
