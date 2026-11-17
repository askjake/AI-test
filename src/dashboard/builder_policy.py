"""Typed builder capabilities and operator plan review; no target activity."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse

from .authoring_text_policy import sensitive_content_rule


class TargetCapability(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    target_type: Literal['local-app', 'host-app', 'ssh-terminal', 'rdp', 'vnc']
    routes: tuple[Literal['direct', 'ssh-jump'], ...]
    explanation: str
    session_notice: str


TARGET_CAPABILITIES = (
    TargetCapability(target_type='local-app', routes=('direct',),
        explanation='One local application window.', session_notice='Evidence covers this application window.'),
    TargetCapability(target_type='host-app', routes=('direct',),
        explanation='One host application window.', session_notice='Evidence covers this application window.'),
    TargetCapability(target_type='ssh-terminal', routes=('direct', 'ssh-jump'),
        explanation='SSH terminal with independently reviewed jump-host keys when routed.',
        session_notice='Terminal evidence cannot establish a remote graphical desktop layout.'),
    TargetCapability(target_type='rdp', routes=('direct',),
        explanation='Direct RDP only. Generic SSH jump routing is unsupported.',
        session_notice='RDP may create a separate session. Verify session and display fidelity before claiming the physical desktop.'),
    TargetCapability(target_type='vnc', routes=('direct', 'ssh-jump'),
        explanation='Direct VNC or an approved SSH local forward with a separate gateway credential and strict host-key checking.',
        session_notice='Identify the VNC server desktop and authentication method. This client uses TigerVNC password files with an eight-byte limit.'),
)


def target_capability(target_type: str) -> TargetCapability:
    return next(item for item in TARGET_CAPABILITIES if item.target_type == target_type)


# Deliberately conservative for natural-language authoring. Credentials belong
# in the separate write-only typed controls, never prose. This is one defense;
# raw intent is also excluded from browser persistence unconditionally.
SENSITIVE_PROSE = re.compile(
    r"(?ix)\b(?:passwords?|passphrases?|secrets?|tokens?|credentials?|authorization|api[_ -]?keys?)\b"
    r"(?:\s*[\"']?\s*[:=]|[^\n.!?]{0,60}?\b(?:is|are|was|were)\b)"
    r"|-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"
)

UNSAFE_TRUST_INSTRUCTION = re.compile(
    r'(?i)\b(?:accept|ignore|bypass)\b[^\n.!?]{0,70}\b(?:host[- ]?key|certificate|fingerprint)\b'
    r'|\b(?:trust.on.first.use|StrictHostKeyChecking\s*=\s*no|cert:ignore)\b'
)
LOCAL_TRANSPORT_INSTRUCTION = re.compile(
    r'(?i)\b(?:open|launch|start|initiate)\b[^\n.!?]{0,45}'
    r'\b(?:local terminal|terminal on the local|SSH (?:connection|session)|remote desktop client|RDP or VNC)\b'
)


class BuilderReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: Literal['unknown', 'audit', 'arrange'] = 'unknown'
    session_scope: Literal['unknown', 'physical-console', 'separate-session', 'application-window'] = 'unknown'
    application_cues: str = Field(default='', max_length=2000)
    window_state: str = Field(default='', max_length=2000)
    evidence_strategy: str = Field(default='', max_length=2000)
    questions: list[str] = Field(default_factory=list, max_length=20)
    answers: list[str] = Field(default_factory=list, max_length=20)
    assumptions: list[str] = Field(default_factory=list, max_length=20)
    risks: list[str] = Field(default_factory=list, max_length=20)
    reviewed_revision: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')


class BuilderTrustReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    confirmed: bool = False
    independent_source: str = Field(default='', max_length=500)
    host: str = Field(default='', max_length=253)
    identity_name: str = Field(default='', max_length=253)
    identity_reference: str = Field(default='', max_length=253)


class OutcomeAnswer(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question: str = Field(min_length=1, max_length=2000)
    answer: str = Field(min_length=1, max_length=2000)


class OutcomeDecisions(BaseModel):
    """Only outcome decisions may enter model context; never trust or credentials."""
    model_config = ConfigDict(extra='forbid')
    mode: Literal['unknown', 'audit', 'arrange'] = 'unknown'
    session_scope: Literal['unknown', 'physical-console', 'separate-session', 'application-window'] = 'unknown'
    application_cues: str = Field(default='', max_length=2000)
    window_state: str = Field(default='', max_length=2000)
    evidence_strategy: str = Field(default='', max_length=2000)
    answered_questions: list[OutcomeAnswer] = Field(default_factory=list, max_length=20)


def trust_diagnostics(project, review: BuilderTrustReview | None) -> list[dict]:
    target = project.target
    route = getattr(target, 'route', None)
    if target.type == 'rdp':
        expected = (target.host or '', target.certificate_name or '', target.certificate_fingerprint or '')
    elif route is not None and route.type == 'ssh-jump':
        expected = (route.host or '', 'OpenSSH known_hosts', route.known_hosts_file or '')
    else:
        return []
    # Typed certificate/known-host requirements are validated by target setup.
    # Requiring a second prose attestation adds no runtime identity verification.
    return []



def review_revision(project, specifications, outline, goal: str, review: BuilderReview) -> str:
    """Bind decisions to executable plan semantics; connection trust has its own gate."""
    payload = {
        'goal': goal, 'target_type': project.target.type,
        'route_type': getattr(getattr(project.target, 'route', None), 'type', 'direct'),
        'specifications': [item.model_dump(mode='json') for item in specifications],
        'manual_outline': outline,
        'review': review.model_dump(mode='json', exclude={'reviewed_revision'}),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False).encode()).hexdigest()


def review_diagnostics(project, specifications, outline, goal: str,
                       review: BuilderReview | None, *, confirmation: bool = True) -> list[dict]:
    diagnostics = []
    def add(code, message, field='builder_review', severity='error'):
        diagnostics.append(dict(code=code, message=message, field=field, severity=severity))
    if review is None:
        add('plan_review_missing', 'Review the executable plan and answer its material questions before completion.')
        return diagnostics
    values = [*review.questions, *review.answers, *review.assumptions, *review.risks,
              review.application_cues, review.window_state, review.evidence_strategy]
    if any(len(value) > 2000 or sensitive_content_rule(value) for value in values):
        add('plan_review_sensitive', 'Remove credential-like prose; use the separate credential controls.')
    if review.mode == 'unknown':
        add('action_scope_unanswered', 'Choose inspection only or bounded arrangement actions.', 'builder_review.mode')
    desktop = project.target.type in {'rdp', 'vnc'}
    if desktop:
        if review.session_scope not in {'physical-console', 'separate-session'}:
            add('desktop_session_unanswered', 'Identify the existing console or a separate remote session. Unknown session identity cannot establish this desktop goal.', 'builder_review.session_scope', severity='warning')
        for field, message in [('application_cues', 'Identify the exact remote applications and stable window cues.'),
                               ('window_state', 'Define the observable maximized or expanded window states.'),
                               ('evidence_strategy', 'Define display geometry and evidence covering every required display.')]:
            if len(getattr(review, field).strip()) < 12:
                add('desktop_gap_unanswered', message, 'builder_review.' + field, severity='warning')
        physical_claim = re.search(r'(?i)\b(?:physical (?:monitor|desktop|console)|existing desktop)\b',
            ' '.join([goal, *(s.goal for s in specifications), *(a for s in specifications for a in s.assertions)]))
        if physical_claim and review.session_scope == 'separate-session':
            add('desktop_session_mismatch', 'A separate session cannot prove the requested existing physical desktop. Change the goal or choose a protocol exposing that console.', 'builder_review.session_scope')
    if len(review.questions) != len(review.answers) or any(len(a.strip()) < 8 for a in review.answers):
        add('plan_questions_open', 'Some optional planning questions are unanswered. Continue if the specifications already describe the test.', 'builder_review.answers', severity='warning')
    for index, spec in enumerate(specifications):
        text = ' '.join([spec.title, spec.goal, spec.setup or '', *spec.assertions])
        if UNSAFE_TRUST_INSTRUCTION.search(text):
            add('spec_trust_instruction', 'Remove instructions to accept or bypass identity checks. Trust is reviewed in target setup.', f'specifications[{index}].setup')
        if desktop and LOCAL_TRANSPORT_INSTRUCTION.search(text):
            add('spec_target_scope', 'This runner observes one remote viewer. Put SSH and connection setup in typed transport fields, not a separate local terminal specification.', f'specifications[{index}].setup')
        if review.mode == 'audit' and re.search(r'(?im)(?:^|[.!?]\s+)(?:move|resize|maximize|rearrange|drag)\b', spec.setup or ''):
            add('spec_action_scope', 'Inspection-only review conflicts with a window arrangement instruction.', f'specifications[{index}].setup')
    if confirmation and review.reviewed_revision != review_revision(project, specifications, outline, goal, review):
        add('plan_review_stale', 'Review and confirm this exact plan after changing its goal, route, specifications, or answers.')
    return diagnostics


class BuilderValidationRoute(APIRoute):
    """Do not reflect rejected request inputs from credential-adjacent authoring."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                if not (request.url.path.startswith('/api/v1/authoring/wizard/')
                        or request.url.path == '/api/v1/projects/authoring'):
                    raise
                return JSONResponse(status_code=422, content={'detail': {'diagnostics': [{
                    'code': 'builder_request_schema', 'field': 'request', 'severity': 'error',
                    'message': 'The builder request does not match the bounded typed fields. Keep credentials in the separate credential controls.'}]}})

        return safe_handler
