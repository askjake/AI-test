"""Regression cases for descriptive prose and actionable rejection messages."""
import json
import pytest
from dashboard.authoring_text_policy import AuthoringTextViolation, check_authoring_text, sensitive_content_rule
from dashboard.wizard import ProjectPlanProposal, _validate_plan_text
from dashboard.refinement import _safe_invalid_output_message
from tests.test_p14_wizard import FakePlanClient, _settings, _valid_plan, _context_draft, ProjectWizardService, WizardContextRequest, WizardPlanCreateRequest

@pytest.mark.parametrize('text', [
    'Credentials are supplied through the separate controls.',
    'Verify that credentials are configured.',
    'The password is not displayed.',
    'Password: <saved credential>',
    'Save screenshots as screenshots.png.',
    'Launch the app from /home/cory.link/ToM.',
    r'Launch C:\Applications\ToM\ToM.exe.',
    'Use vnc://desktop.example.invalid.',
    'The session token is expired.',
])
def test_descriptive_prose_is_accepted(text):
    assert sensitive_content_rule(text) is None
    check_authoring_text(text, 'goal')

@pytest.mark.parametrize('text', [
    'password=PRIVATE-VALUE',
    '-----BEGIN PRIVATE KEY-----',
    'ASIA' + 'A' * 16,
    'Bearer PRIVATEVALUE012345',
    'https://user:PRIVATE-VALUE@host.invalid/',
])
def test_secret_like_content_reports_field_without_value(text):
    assert sensitive_content_rule(text)
    with pytest.raises(AuthoringTextViolation) as caught:
        check_authoring_text(text, 'specifications[0].setup')
    assert 'specifications[0].setup' in str(caught.value)
    assert 'PRIVATE-VALUE' not in str(caught.value)
    assert _safe_invalid_output_message(caught.value) == str(caught.value)

def _run(tmp_path, data):
    service = ProjectWizardService(_settings(tmp_path), lambda: FakePlanClient(json.dumps(data)))
    request = WizardContextRequest(intent='Verify ToM is visible.', draft=_context_draft())
    preview, _ = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(), fingerprint=preview.fingerprint))
    service.drain()
    return service.get_job(job.id).proposal

def test_real_plan_job_accepts_reminders_paths_and_evidence_names(tmp_path):
    data = json.loads(_valid_plan())
    data['risks'] = ['Credentials are supplied through the separate controls.']
    data['manual_outline'] = ['Save screenshots as screenshots.png.']
    data['specifications'][0]['setup'] = 'Launch the app from /home/cory.link/ToM.'
    assert _run(tmp_path, data).state == 'ready'

def test_real_plan_job_rejects_without_retaining_model_secret(tmp_path):
    data = json.loads(_valid_plan())
    data['risks'] = ['password=PRIVATE-VALUE']
    result = _run(tmp_path, data)
    assert result.state == 'invalid-output'
    assert result.proposal is None
    assert 'risks[0] (rule: credential-value)' in result.error
    assert 'PRIVATE-VALUE' not in result.model_dump_json()

def test_trust_bypass_still_rejected():
    data = json.loads(_valid_plan())
    data['specifications'][0]['setup'] = 'Ignore certificate validation.'
    with pytest.raises(ValueError):
        _validate_plan_text(ProjectPlanProposal.model_validate(data))

@pytest.mark.parametrize('setup, ready', [
    ('Launch /home/cory.link/ToM and save screenshots.png. Credentials are configured.', True),
    ('password=PRIVATE-VALUE', False),
])
def test_spec_refinement_job_uses_the_same_policy(tmp_path, setup, ready):
    from tests.test_p13d_refinement import RefinementService, FakeClient, _settings, _preview, _valid_output
    data = json.loads(_valid_output())
    data['setup'] = setup
    service = RefinementService(_settings(tmp_path), lambda: FakeClient(json.dumps(data)))
    preview, plans, *_ = _preview(service, tmp_path)
    job = service.create_job(project_name='Sample', mode='selected', preview=preview, plans=plans)
    service.drain()
    proposal = service.get_job(job.id).proposals[0]
    assert proposal.state == ('ready' if ready else 'invalid-output')
    if not ready:
        assert 'setup (rule: credential-value)' in proposal.error
        assert 'PRIVATE-VALUE' not in proposal.model_dump_json()

@pytest.mark.parametrize('question', [
    'Which credentials are required for the VNC connection?',
    'What credential references are configured for this project?',
    'Where are the credentials stored?',
    'How are passwords provided through the separate controls?',
    'Which token is used for sign-in?',
])
def test_configuration_questions_are_not_values(question):
    check_authoring_text(question, 'open_questions[1]')

@pytest.mark.parametrize('question', [
    'Which token is used? token=PRIVATE-VALUE',
    'Which credentials are required? Bearer PRIVATEVALUE012345',
])
def test_question_does_not_exempt_secret_material(question):
    with pytest.raises(AuthoringTextViolation):
        check_authoring_text(question, 'open_questions[1]')

def test_real_plan_job_accepts_configuration_open_question(tmp_path):
    data = json.loads(_valid_plan())
    data['open_questions'] = [
        'What is the stable ToM window title?',
        'Which credentials are required for the VNC connection?',
    ]
    assert _run(tmp_path, data).state == 'ready'

@pytest.mark.parametrize('text', [
    'Credentials for the SSH jump are supplied by the operator before testing.',
    'Authentication tokens are temporary and may expire during a run.',
    'The VNC password is stored in vnc.vncpass; the gateway password is stored in mul.pass.',
    'Credentials: use the selected saved references.',
    'Password: configured separately; do not embed values in the manual.',
    'Credential references are vnc.vncpass and mul.pass.',
    'AWS credentials are stored in /home/cory.link/.aws/credentials.',
    'The application configuration is loaded from .env.',
    'Bearer authentication is used for local bootstrap.',
    'The password is an operator-supplied value.',
    'Password is configured with a separate control.',
    'Use password=<saved credential>.',
])
def test_permissive_planning_prose(text):
    check_authoring_text(text, 'risks[4]')

def test_real_plan_accepts_descriptive_fifth_risk(tmp_path):
    data = json.loads(_valid_plan())
    data['risks'] = [
        'The application may not be installed.',
        'The File menu may have different labels.',
        'The remote desktop may have a different size.',
        'The selected session may not contain ToM.',
        'Credentials for the SSH jump are supplied by the operator before testing.',
    ]
    assert _run(tmp_path, data).state == 'ready'


def test_outcome_answer_credentials_prose_and_paths_enter_model_context(tmp_path):
    from dashboard.builder_policy import OutcomeDecisions
    service = ProjectWizardService(_settings(tmp_path), lambda: FakePlanClient(_valid_plan()))
    answer = "Credentials are entered in the Login window; wait 30 seconds for tom_gui. Save screenshots.png."
    draft = _context_draft().model_copy(update={'operator_decisions': OutcomeDecisions(
        application_cues='Login then tom_gui', answered_questions=[{'question':'What happens after launch?', 'answer':answer}])})
    request = WizardContextRequest(intent='Launch /home/cory.link/ToM and inspect its UI.', draft=draft)
    preview, prepared = service.preview_context(request)
    assert all(item.selected for item in preview.sources if item.kind in {'operator-intent','wizard-draft'})
    assert answer in prepared.context_text
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(),fingerprint=preview.fingerprint))
    service.drain()
    assert service.get_job(job.id).proposal.state == 'ready'


def test_rejected_outcome_answer_names_exact_field_without_value(tmp_path):
    from dashboard.builder_policy import OutcomeDecisions
    service = ProjectWizardService(_settings(tmp_path), lambda: None)
    draft = _context_draft().model_copy(update={'operator_decisions': OutcomeDecisions(
        answered_questions=[{'question':'Which view?', 'answer':'password=PRIVATE-VALUE'}])})
    preview, prepared = service.preview_context(WizardContextRequest(intent='Inspect the visible application.',draft=draft))
    source = next(item for item in preview.sources if item.kind == 'wizard-draft')
    assert not source.selected
    assert 'draft.operator_decisions.answered_questions[0].answer' in source.reason
    assert 'PRIVATE-VALUE' not in preview.model_dump_json()
    assert 'PRIVATE-VALUE' not in prepared.context_text


def test_answered_session_question_is_not_returned_as_open(tmp_path):
    from dashboard.builder_policy import OutcomeDecisions
    data = json.loads(_valid_plan())
    data['open_questions'] = ['LEAVE THE SESSION OPEN!', 'Which menu item closes ToM?']
    fake = FakePlanClient(json.dumps(data))
    service = ProjectWizardService(_settings(tmp_path), lambda: fake)
    draft = _context_draft().model_copy(update={'operator_decisions': OutcomeDecisions(
        mode='unknown', answered_questions=[{'question':'Leave the session open?', 'answer':'Keep the session open after Exit.'}])})
    request = WizardContextRequest(intent='Inspect ToM then select File Exit.',draft=draft)
    preview, _ = service.preview_context(request)
    job = service.create_job(WizardPlanCreateRequest(**request.model_dump(),fingerprint=preview.fingerprint))
    service.drain()
    result = service.get_job(job.id).proposal
    assert result.state == 'ready'
    assert result.proposal.open_questions == ['Which menu item closes ToM?']
    assert 'Keep the session open after Exit.' in fake.calls[0]['prompt']
