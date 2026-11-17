from types import SimpleNamespace
from pathlib import Path
import importlib.util
import json
import pytest
from dashboard.builder_policy import BuilderReview, review_diagnostics, trust_diagnostics
from tests.test_builder_completion import project, specs, assessment
from fastapi import FastAPI
from fastapi.testclient import TestClient
from dashboard.auth import verify_operator
from dashboard.wizard_routes import router


def test_unanswered_optional_questions_do_not_block_review():
    body = assessment().model_dump(mode='json')
    body['builder_review'].update(answers=[], application_cues='', window_state='', evidence_strategy='')
    app = FastAPI(); app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[verify_operator] = lambda: None
    response = TestClient(app).post('/api/v1/authoring/wizard/review', json=body)
    assert response.status_code == 200, response.text
    assert len(response.json()['reviewed_revision']) == 64


def test_actual_scope_conflicts_still_block():
    b = assessment()
    b.builder_review.session_scope = 'separate-session'
    result = review_diagnostics(b.project, b.specifications, b.manual_outline, b.goal, b.builder_review)
    assert any(x['code'] == 'desktop_session_mismatch' and x['severity'] == 'error' for x in result)
    assert trust_diagnostics(b.project, None) == []


def helper():
    spec = importlib.util.spec_from_file_location('cory_app', Path(__file__).parents[1]/'scripts/cory_app.py')
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def test_stale_recovery_only_archives_dead_pid(tmp_path, monkeypatch):
    import orchestrator_cookie.lifecycle as lifecycle
    m = helper()
    path = tmp_path/'.orchestrator-cookie/state/dashboard.json'
    path.parent.mkdir(parents=True)
    raw = json.dumps(dict(pid=123456, bind_host='127.0.0.1', port=8025))
    path.write_text(raw)
    monkeypatch.setattr(lifecycle, 'dashboard_status', lambda *a: SimpleNamespace(running=False))
    monkeypatch.setattr(m, 'port_available', lambda *a: True)
    monkeypatch.setattr(m.os, 'kill', lambda *a: None)
    cfg = SimpleNamespace(bind_host='127.0.0.1')
    with pytest.raises(RuntimeError, match='still present'):
        m.archive_dead_metadata(tmp_path,cfg)
    assert path.read_text()==raw
    def dead(*a): raise ProcessLookupError()
    monkeypatch.setattr(m.os,'kill',dead)
    monkeypatch.setattr(m, 'port_available', lambda *a: False)
    with pytest.raises(RuntimeError, match='occupied'):
        m.archive_dead_metadata(tmp_path,cfg)
    monkeypatch.setattr(m, 'port_available', lambda *a: True)
    m.archive_dead_metadata(tmp_path,cfg)
    assert not path.exists()
    assert next(path.parent.glob('stale-dashboard-*/dashboard.json')).read_text()==raw
