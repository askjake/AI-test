"""NRDP-1 S2a: nested-RDP procedure intake v2 (fictional passwords only)."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from dashboard.config import DashboardSettings
from dashboard import procedure_routes_v2  # noqa: F401  registers v2 routes on the wizard router
from dashboard.procedure_intake import (
    ConnectionEditError, assert_no_secret, build_procedure, classify_step,
    compute_readiness, load_procedure, public_view, update_connections, upgrade_draft,
)
from dashboard.target_setup import TargetSetupService
from dashboard.wizard_routes import router as wizard_router

PW1 = 'Zq9-NOTREAL-pw-1'
PW2 = 'Hop2-NOTREAL-pw-2'
SECRETS = [PW1, PW2]

GOAL = f"""RDP to 10.70.115.36
username: operator1
password: {PW1}
Then RDP to 172.20.33.215
jamuser
{PW2}
1. Confirm the PowerShell session is elevated
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
2. Stop the service
Stop-Service -Name JAMboreeVision
3. Confirm it is stopped
Get-Service -Name JAMboreeVision
must show Stopped
4. Confirm serial handle release
Get-NetTCPConnection -LocalPort 5004
5. Wait 10 seconds
6. Swap wires COM3 to COM4 for Guide and Select hardware work, operator pause
7. Start the service
Start-Service -Name JAMboreeVision
8. Confirm it is Running
Get-Service -Name JAMboreeVision
9. Check health
Invoke-WebRequest http://localhost:5004/ should return 200
10. Open Chrome and inspect http://localhost:5004/
11. Physically press Guide then Select on the receiver and confirm the menu
"""


def _settings(tmp_path: Path) -> DashboardSettings:
    return DashboardSettings(
        auth_token='viewer', auth_operator_token='operator',
        reports_dir=str(tmp_path / 'reports'), specs_dir=str(tmp_path / 'specs'),
        authoring_state_root=str(tmp_path / 'private-p13d'), wizard_state_root=str(tmp_path / 'private-p14'),
        secrets_dir=str(tmp_path / 'secrets'),
    )


def _service(settings):
    return TargetSetupService(settings, SimpleNamespace(ssh_host_allowlist=[], rdp_host_allowlist=[], vnc_host_allowlist=[]))


@pytest.fixture
def env(tmp_path):
    settings = _settings(tmp_path)
    service = _service(settings)
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    return settings, service, draft


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _files(settings, draft):
    root = Path(settings.wizard_state_root).resolve() / 'procedure-drafts' / draft.id
    return (root / 'draft.json').read_text(), (root / 'manual.md').read_text()


def test_goal_parses_two_hops_and_eleven_steps(env):
    settings, service, draft = env
    assert [h.host for h in draft.connections] == ['10.70.115.36', '172.20.33.215']
    assert [h.user for h in draft.connections] == ['operator1', 'jamuser']
    assert draft.final_hop == 2 and draft.schema_version == 2
    assert len(draft.steps) == 11
    assert [s.order for s in draft.steps if s.mutating] == [2, 7]
    assert [s.order for s in draft.steps if s.kind == 'operator-checkpoint'] == [6, 11]
    assert not any(s.read_only_ok for s in draft.steps if s.kind == 'operator-checkpoint')
    assert draft.steps[2].read_only_ok and draft.steps[8].read_only_ok
    text = draft.model_dump_json() + draft.manual
    assert 'Execution unavailable' not in text
    for banned in ('start.cmd', 'start.ps1', 'Manage-Service.ps1', 'Stop-Process', 'taskkill'):
        # they may appear ONLY inside a prohibition, never as an instruction
        for hit in re.finditer(re.escape(banned), text):
            window = text[max(0, hit.start() - 200):hit.start()].lower()
            assert 'never' in window or 'forbid' in window or 'must not' in window, banned
    assert 'Nested Remote Desktop' in draft.findings[0]
    assert 'inside the previous desktop with Windows Remote Desktop' in draft.manual
    assert 'Opened from runner desktop' in draft.manual
    assert draft.execution_supported is False  # certificate not yet reviewed


def test_classify_step_rules():
    assert classify_step('Stop-Service -Name X', 'Stop') == (True, False)
    assert classify_step('Get-Service X', 'Check') == (False, True)
    assert classify_step('Get-Service X', 'Check', 'operator-checkpoint') == (False, False)
    assert classify_step('Wait 10 seconds', 'Wait') == (False, False)


def test_v1_draft_loads_with_defaults(env):
    settings, _svc, draft = env
    raw = json.loads(draft.model_dump_json())
    for k in ('schema_version', 'final_hop', 'project', 'last_test'):
        raw.pop(k)
    for c in raw['connections']:
        for k in ('label', 'certificate_name', 'certificate_fingerprint', 'identity_policy'):
            c.pop(k)
    for s in raw['steps']:
        s.pop('mutating'); s.pop('read_only_ok')
    p = Path(settings.wizard_state_root).resolve() / 'procedure-drafts' / draft.id / 'draft.json'
    p.write_text(json.dumps(raw))
    loaded = load_procedure(draft.id, settings.wizard_state_root)
    assert loaded.schema_version == 2 and loaded.final_hop == 2
    assert loaded.connections[0].identity_policy == 'stop'
    assert upgrade_draft({'connections': [1, 2, 3]})['final_hop'] == 3


def test_readiness_and_public_view(env):
    settings, service, draft = env
    root = service._secrets_root()
    states = {i['key']: i['state'] for i in compute_readiness(draft, root)}
    assert states['credential-hop-1'] == 'known' and states['certificate-hop-1'] == 'required'
    view = public_view(draft, root)
    assert view['connections'][1]['credential'] == {'state': 'saved', 'reference': draft.connections[1].password_reference}
    assert view['execution_supported'] is False
    assert_no_secret(view, SECRETS)
    draft_json, manual = _files(settings, draft)
    assert_no_secret(draft_json, SECRETS); assert_no_secret(manual, SECRETS)


def test_connection_edit_validation_errors(env):
    settings, service, draft = env
    with pytest.raises(ConnectionEditError) as exc:
        update_connections(draft.id, [
            {'order': 1, 'host': 'bad host!', 'port': 70000, 'user': ''},
            {'order': 2, 'certificate_name': 'x'},
            {'order': 9},
            {'order': 1, 'certificate_fingerprint': 'md5:abc'},
        ], settings.wizard_state_root, service)
    fields = {e['field'] for e in exc.value.errors}
    # Field paths are zero-based positions (order - 1), matching the UI's parseFieldErrors; an
    # unknown order is reported at its position in the submitted list.
    assert {'connections[0].host', 'connections[0].port', 'connections[0].user',
            'connections[1].certificate_name', 'connections[2].order',
            'connections[0].certificate_fingerprint'} <= fields


def test_certificate_review_normalises_and_enables_execution(env):
    settings, service, draft = env
    fp = ':'.join(['AB'] * 32)
    updated = update_connections(draft.id, [{'order': 1, 'certificate_name': 'HOP1.example', 'certificate_fingerprint': 'SHA256:' + fp}],
                                 settings.wizard_state_root, service)
    assert updated.connections[0].certificate_fingerprint == 'sha256:' + 'ab' * 32
    assert updated.execution_supported is True


def test_new_password_creates_new_reference_and_leaves_old_bytes(env):
    settings, service, draft = env
    root = Path(service._secrets_root())
    old1, old2 = root / draft.connections[0].password_reference, root / draft.connections[1].password_reference
    before1, before2 = _sha(old1), _sha(old2)
    updated = update_connections(draft.id, [{'order': 2, 'new_password': SecretStr('New-NOTREAL-pw-3')}], settings.wizard_state_root, service)
    ref = updated.connections[1].password_reference
    assert ref != draft.connections[1].password_reference and ref.startswith(f'procedure-{draft.id}-hop-2-')
    assert (root / ref).is_file()
    assert updated.connections[0].password_reference == draft.connections[0].password_reference
    assert _sha(old1) == before1 and _sha(old2) == before2
    draft_json, manual = _files(settings, updated)
    assert_no_secret(draft_json + manual, SECRETS + ['New-NOTREAL-pw-3'])


def test_failed_edit_persists_nothing(env):
    settings, service, draft = env
    root = Path(service._secrets_root())
    before = sorted(p.name for p in root.iterdir())
    draft_before = _files(settings, draft)
    with pytest.raises(ConnectionEditError):
        update_connections(draft.id, [{'order': 1, 'new_password': SecretStr('X-NOTREAL'), 'port': 0}], settings.wizard_state_root, service)
    assert sorted(p.name for p in root.iterdir()) == before
    assert _files(settings, draft) == draft_before


def test_routes_operator_only_and_no_secret(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    import dashboard.config as config
    monkeypatch.setattr(config, 'settings', settings)
    app = FastAPI(); service = _service(settings)
    app.state.target_setup_service = service
    app.include_router(wizard_router, prefix='/api/v1')
    op = {'Authorization': 'Bearer operator'}
    with TestClient(app) as client:
        created = client.post('/api/v1/authoring/wizard/procedures', headers=op, json={'procedure': GOAL})
        assert created.status_code == 200, created.text
        key = created.json()['id']
        base = f'/api/v1/authoring/wizard/procedures/{key}'
        assert client.get(base + '/view', headers={'Authorization': 'Bearer viewer'}).status_code == 403
        view = client.get(base + '/view', headers=op)
        assert view.status_code == 200 and 'readiness' in view.json()
        body = view.json()
        # UI contract shapes (the Tester found these mismatched): nested certificate, {items: [...]} readiness.
        assert isinstance(body['readiness'], dict) and isinstance(body['readiness']['items'], list)
        assert body['connections'][0]['certificate']['state'] == 'required'
        assert body['connections'][1]['certificate']['state'] == 'not_applicable'
        assert body['connections'][1]['predecessor'] == 1 and body['connections'][0]['predecessor'] is None
        assert body['project'] is None
        bad = client.put(base + '/connections', headers=op, json={'connections': [{'order': 1, 'port': 0}]})
        assert bad.status_code == 422 and bad.json()['errors'][0]['field'] == 'connections[0].port'
        ok = client.put(base + '/connections', headers=op, json={'connections': [{'order': 2, 'label': 'JAM PC'}]})
        assert ok.status_code == 200, ok.text
        assert client.post(base + '/connections/2/certificate/probe', headers=op).status_code == 422
        for r in (created, view, bad, ok):
            assert_no_secret(r.text, SECRETS)
