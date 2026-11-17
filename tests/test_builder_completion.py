"""Builder completion regressions; no live target, model, or credential use."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard.auth import verify_operator
from dashboard.authoring import ProjectDocument, RdpTarget, SpecDocument, lint_project_document
from dashboard.builder_policy import BuilderReview, BuilderTrustReview, review_diagnostics, review_revision, target_capability
from dashboard.wizard import WizardAssessmentRequest, WizardContextRequest, WizardPlanCreateRequest, assess_readiness
from dashboard.wizard_routes import router as wizard_router
from dashboard.editor_routes import router as editor_router
from dashboard.target_probe import TargetProbeService
from tests.test_p14_wizard import _settings, _context_draft, _valid_plan, FakePlanClient
from dashboard.wizard import ProjectWizardService
from orchestrator import runner, scheduler
from orchestrator.projects import discover_projects, find_project
from orchestrator.egress import compute_policy


def project():
    return ProjectDocument(dir_name='monitor-layout', display_name='Monitor Layout', enabled=False,
        schedule=None, target=RdpTarget(host='192.0.2.35', user='fixture-user',
            password_file='desktop.rdp.pw', certificate_name='desktop.example.invalid',
            certificate_fingerprint='sha256:' + 'a'*64, window='orchestrator-rdp-viewer'),
        rdp_host_allowlist=['192.0.2.35'], max_steps=20, max_seconds=120)


def specs():
    return [SpecDocument(path='000-gpu.md', title='GPU Monitor',
        goal='Inspect GPU Monitor on the left physical monitor.', setup='Observe the existing desktop layout.',
        assertions=['The independently identified GPU Monitor is maximized on the left display.']),
        SpecDocument(path='001-system.md', title='System Monitor',
        goal='Inspect System Monitor on the right physical monitor.', setup='Observe without changing window state.',
        assertions=['The independently identified System Monitor shows detailed resource graphs on the right display.'])]


def reviewed(p, items):
    review = BuilderReview(mode='audit', session_scope='physical-console',
        application_cues='GPU Monitor and System Monitor titles and visible resource graphs.',
        window_state='GPU Monitor maximized; System Monitor expanded with CPU and memory graphs.',
        evidence_strategy='One screenshot spans both captured displays; left and right geometry reviewed independently.',
        questions=['What identifies completion?'], answers=['Both monitor windows and resource graphs are visible.'])
    review.reviewed_revision = review_revision(p, items, ['Procedure'], 'Inspect the existing desktop.', review)
    return review


def assessment(p=None, items=None):
    p, items = p or project(), items or specs()
    return WizardAssessmentRequest(project=p, specifications=items, goal='Inspect the existing desktop.',
        manual_outline=['Procedure'], verification_path='authoring-only', builder_review=reviewed(p, items),
        trust_review=BuilderTrustReview(confirmed=True, independent_source='Fixture operator independently reviewed the pin in the console record.',
            host=p.target.host, identity_name=p.target.certificate_name, identity_reference=p.target.certificate_fingerprint))


@pytest.mark.parametrize('text', ['password=DUMMY-ONLY', 'token=DUMMY-ONLY',
                                  'passphrase=DUMMY-ONLY', 'credentials=DUMMY-ONLY'])
def test_secret_prose_is_excluded_from_model_context_and_persisted_jobs(tmp_path, text):
    fake = FakePlanClient(_valid_plan())
    service = ProjectWizardService(_settings(tmp_path), lambda: fake)
    request = WizardContextRequest(intent=text, draft=_context_draft())
    preview, _ = service.preview_context(request)
    assert not next(x for x in preview.sources if x.kind == 'operator-intent').selected
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()
    assert 'DUMMY-ONLY' not in fake.calls[0]['prompt']
    for file in Path(service.settings.wizard_state_root).rglob('*'):
        if file.is_file(): assert b'DUMMY-ONLY' not in file.read_bytes()
    assert service.get_job(job.id).state == 'completed'


def test_rdp_jump_is_rejected_with_specific_fields_before_generic_preflight_error():
    from dashboard.authoring import SshJumpConnectionRoute
    p = project().model_copy(update={'target': project().target.model_copy(update={
        'route': SshJumpConnectionRoute(host='192.0.2.47')})})
    assert 'ssh-jump' not in target_capability('rdp').routes
    assert 'ssh-jump' in target_capability('vnc').routes
    request = assessment(p)
    result = assess_readiness(request)
    route = next(x for x in result.findings if x.code == 'jump_route_unsupported')
    assert route.field == 'target.route.type'
    assert not result.ready_for_create


def test_questions_scope_session_and_staleness_are_material_gates():
    body = assessment()
    assert assess_readiness(body).ready_for_create
    open_review = body.builder_review.model_copy(update={'answers': []})
    assert 'plan_questions_open' in {x['code'] for x in review_diagnostics(body.project, body.specifications,
        body.manual_outline, body.goal, open_review)}
    separate = body.builder_review.model_copy(update={'session_scope': 'separate-session'})
    assert 'desktop_session_mismatch' in {x['code'] for x in review_diagnostics(body.project, body.specifications,
        body.manual_outline, body.goal, separate)}
    edited = [body.specifications[0].model_copy(update={'goal':'Inspect another visible application.'}),body.specifications[1]]
    assert 'plan_review_stale' in {x['code'] for x in review_diagnostics(body.project, edited,
        body.manual_outline, body.goal, body.builder_review)}
    changed_setup = [body.specifications[0].model_copy(update={'setup':'Move the window to the left display.'})]
    assert 'spec_action_scope' in {x['code'] for x in review_diagnostics(body.project, changed_setup,
        body.manual_outline, body.goal, body.builder_review)}


def test_connection_setup_and_first_use_trust_cannot_be_viewer_specs():
    items = [specs()[0].model_copy(update={'setup':'Open a local terminal. Accept the host key if first prompted.'})]
    errors = review_diagnostics(project(), items, ['Procedure'], 'Inspect desktop.', reviewed(project(),items))
    assert {'spec_target_scope','spec_trust_instruction'} <= {x['code'] for x in errors}


def test_disabled_unscheduled_validation_and_explicit_run_preserve_scheduler_boundary(tmp_path, monkeypatch):
    p = project()
    _, errors = lint_project_document(p.model_copy(update={'manual_dir':'managed'}),
        require_manual_on_disk=False, require_schedule=True, new_project=True)
    assert not errors
    root=tmp_path/'specs'; folder=root/p.dir_name; folder.mkdir(parents=True)
    manual=tmp_path/'manual'; manual.mkdir(); (manual/'manual.md').write_text('# Fixture\n')
    (folder/'project.yaml').write_text(yaml.safe_dump({'name':'Monitor Layout','enabled':False,
        'manual_dir':str(manual),'target':{'type':'local-app','app':'fixture','window':'fixture'}}))
    assert not discover_projects(str(root))
    assert find_project(p.dir_name,str(root)) is None
    assert find_project(p.dir_name,str(root),include_disabled=True).enabled is False
    assert scheduler.build_schedule_plan(str(root)) == []
    with pytest.raises(ValueError,match='no enabled'):
        runner.run_project(p.dir_name,specs_root=str(root))
    # A zero-spec fixture exercises discovery and reporting without any target factory.
    run=runner.run_project(p.dir_name,specs_root=str(root),reports_dir=str(tmp_path/'reports'),allow_disabled=True,
        targets_factory=lambda *_: pytest.fail('target factory must not run'),
        client_factory=lambda *_: pytest.fail('model factory must not run'))
    assert run.project == p.dir_name
    assert scheduler.build_schedule_plan(str(root)) == []
    assert yaml.safe_load((folder/'project.yaml').read_text())['enabled'] is False
    policy=compute_policy(project_name=p.dir_name,specs_root=str(root),include_bedrock=False)
    assert not policy.ssh_hosts and not policy.rdp_hosts and not policy.vnc_hosts


@pytest.fixture
def client(tmp_path,monkeypatch):
    for name,sub in [('DASHBOARD_SPECS_DIR','specs'),('TESTS_SPECS_DIR','specs'),
                     ('TESTS_MANUALS_DIR','manuals'),('DASHBOARD_REPORTS_DIR','reports'),
                     ('DASHBOARD_SECRETS_DIR','secrets')]:
        monkeypatch.setenv(name,str(tmp_path/sub))
    secrets=tmp_path/'secrets'; secrets.mkdir(mode=0o700)
    (secrets/'desktop.rdp.pw').write_text('DUMMY-ONLY\n'); (secrets/'desktop.rdp.pw').chmod(0o600)
    app=FastAPI(); app.dependency_overrides[verify_operator]=lambda:'operator'
    app.state.target_probe_service=TargetProbeService(_settings(tmp_path),
        connector=lambda *_: pytest.fail('target network contact forbidden'),
        popen_factory=lambda *_args,**_kwargs: pytest.fail('process launch forbidden'), which=lambda _:None)
    app.include_router(wizard_router,prefix='/api/v1'); app.include_router(editor_router,prefix='/api/v1')
    with TestClient(app) as c: yield c,tmp_path


def test_target_free_review_validate_complete_create_and_no_scheduler_registration(client):
    c,root=client
    body=assessment().model_dump(mode='json')
    body['builder_review']['reviewed_revision']=None
    review=c.post('/api/v1/authoring/wizard/review',json=body)
    assert review.status_code==200,review.text
    body['builder_review']['reviewed_revision']=review.json()['reviewed_revision']
    body['manual_template']='# Monitor Layout\n\n## Procedure\n\nInspect both reviewed monitor windows; stop on mismatch.\n'
    valid=c.post('/api/v1/authoring/wizard/validate',json=body)
    assert valid.status_code==200,valid.text
    assert 'target_not_probed' in {x.code for x in assess_readiness(WizardAssessmentRequest.model_validate(
        {k:v for k,v in body.items() if k!='manual_template'})).findings}
    assert not (root/'specs'/'monitor-layout').exists()
    create={'document':body['project'],'initial_spec':body['specifications'][0],
        'additional_specs':body['specifications'][1:],'builder_goal':body['goal'],
        'builder_review':body['builder_review'],'trust_review':body['trust_review'],
        'manual_outline':body['manual_outline'],'manual_template':body['manual_template']}
    response=c.post('/api/v1/projects/authoring',json=create)
    assert response.status_code==201,response.text
    assert response.json()['created_specifications']==['000-gpu.md','001-system.md']
    source=root/'specs'/'monitor-layout'
    saved=yaml.safe_load((source/'project.yaml').read_text())
    assert saved['enabled'] is False and 'schedule' not in saved
    assert (source/'000-gpu.md').is_file() and (source/'001-system.md').is_file()
    assert (root/'manuals'/'monitor-layout'/'manual.md').is_file()
    assert scheduler.build_schedule_plan(str(root/'specs')) == []


def test_apply_requires_current_review_but_not_duplicate_attestation(client):
    c,root=client
    body=assessment().model_dump(mode='json')
    body['manual_template']='# Monitor\n\n## Procedure\n\nObserve.\n'
    body['builder_review']['answers']=[]
    response=c.post('/api/v1/authoring/wizard/validate',json=body)
    assert response.status_code==422
    assert 'plan_review_stale' in response.text
    body=assessment().model_dump(mode='json');body['manual_template']='# Monitor\n\n## Procedure\n\nObserve.\n'
    body['trust_review']['confirmed']=False
    response=c.post('/api/v1/authoring/wizard/validate',json=body)
    assert response.status_code==200, response.text
    body=assessment().model_dump(mode='json')
    body['specifications'][1]['assertions']=[]
    create={'document':body['project'],'initial_spec':body['specifications'][0],
        'additional_specs':body['specifications'][1:],'manual_template':'# Fixture\n'}
    response=c.post('/api/v1/projects/authoring',json=create)
    assert response.status_code==422
    assert not (root/'specs'/'monitor-layout').exists()
    assert not (root/'manuals'/'monitor-layout').exists()


def test_outcome_answers_enter_safe_context_but_sensitive_answers_are_excluded(tmp_path):
    from dashboard.builder_policy import OutcomeDecisions
    service=ProjectWizardService(_settings(tmp_path),lambda:pytest.fail('model must not run'))
    draft=_context_draft().model_copy(update={'operator_decisions':OutcomeDecisions(
        mode='audit',session_scope='physical-console',application_cues='Reviewed visible graph titles.',
        answered_questions=[{'question':'Which view?', 'answer':'CPU and memory resource graphs are expanded.'}])})
    preview,prepared=service.preview_context(WizardContextRequest(intent='Inspect both monitoring windows.',draft=draft))
    assert next(x for x in preview.sources if x.kind=='wizard-draft').selected
    assert 'CPU and memory resource graphs are expanded.' in prepared.context_text
    draft.operator_decisions.application_cues='password=DUMMY-ANSWER'
    preview,prepared=service.preview_context(WizardContextRequest(intent='Inspect both monitoring windows.',draft=draft))
    assert not next(x for x in preview.sources if x.kind=='wizard-draft').selected
    assert 'DUMMY-ANSWER' not in prepared.context_text


@pytest.mark.parametrize('path', ['/api/v1/authoring/wizard/readiness','/api/v1/projects/authoring'])
def test_builder_schema_errors_never_reflect_rejected_input(client,path):
    c,_=client
    response=c.post(path,json={'unexpected':'password is DUMMY-REJECTED'})
    assert response.status_code==422
    assert 'DUMMY-REJECTED' not in response.text
    assert response.json()['detail']['diagnostics'][0]['code']=='builder_request_schema'


def test_explicit_disabled_run_and_egress_do_not_enable_cron_or_bulk_runs(tmp_path,monkeypatch):
    from orchestrator.models import RunResult
    from tests.test_scheduler import FakeScheduler
    root=tmp_path/'specs'; manual=tmp_path/'manual'; manual.mkdir();(manual/'manual.md').write_text('# Fixture')
    for slug,enabled,host in [('disabled-project',False,'192.0.2.35'),('enabled-project',True,'192.0.2.36')]:
        folder=root/slug;folder.mkdir(parents=True)
        (folder/'project.yaml').write_text(yaml.safe_dump({'name':slug,'enabled':enabled,
            'manual_dir':str(manual),'target':{'type':'rdp','host':host,'user':'fixture',
            'password_file':'desktop.rdp.pw','certificate_name':'fixture.invalid',
            'certificate_fingerprint':'sha256:'+'a'*64},'rdp_host_allowlist':[host]}))
        (folder/'000-check.md').write_text('# Test: Fixture\n\n## Goal\nObserve.\n\n## Assertions\n- Visible.\n')
    calls=[]
    def fake(name,**kwargs):
        calls.append((name,kwargs.get('allow_disabled',False)))
        return RunResult(project=name,run_ts='offline',results=[])
    monkeypatch.setattr(runner,'run_project',fake)
    scheduler.run_once('disabled-project',specs_root=str(root))
    assert calls==[('disabled-project',True)]
    calls.clear();scheduler.run_once(specs_root=str(root));assert calls==[('enabled-project',False)]
    fake_scheduler=FakeScheduler()
    scheduler.start(specs_root=str(root),reports_dir=str(tmp_path/'reports'),
        scheduler_factory=lambda:fake_scheduler,block=False)
    cron=[x for x in fake_scheduler.jobs if x['id'].startswith('project:')]
    assert [x['id'] for x in cron]==['project:enabled-project']
    watcher=next(x['func'].__self__ for x in fake_scheduler.jobs if x['id']=='trigger_watcher')
    assert watcher.run_fn is scheduler.run_requested_project_once
    scoped=compute_policy(project_name='disabled-project',specs_root=str(root),include_bedrock=False)
    bulk=compute_policy(specs_root=str(root),include_bedrock=False)
    assert scoped.rdp_hosts==frozenset({'192.0.2.35'})
    assert bulk.rdp_hosts==frozenset({'192.0.2.36'})
    assert yaml.safe_load((root/'disabled-project'/'project.yaml').read_text())['enabled'] is False
