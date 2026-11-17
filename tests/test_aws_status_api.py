"""Dashboard AWS status API against the real FastAPI router (dependencies overridden; no model call, no AWS contact)."""
from __future__ import annotations

import json
import os
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aws_refresh import UpstreamRenewalFailed, reset_registry
from dashboard import aws_status
from dashboard.refinement import safe_authoring_failure
from tests.test_aws_refresh import NEW, OLD, SECRETS, body, client_error, expired_error, no_secrets, write_atomic


@pytest.fixture
def api(tmp_path, monkeypatch):
    reset_registry()
    path = tmp_path / "credentials"
    write_atomic(str(path), body(OLD, 3000, profile="rotating"))
    os.utime(path, (time.time() - 5, time.time() - 5))
    monkeypatch.setattr(aws_status.settings, "authoring_shared_credentials_file", str(path))
    monkeypatch.setattr(aws_status.settings, "authoring_shared_config_file", None)
    monkeypatch.setattr(aws_status.settings, "authoring_profile", "rotating")
    monkeypatch.setattr(aws_status.settings, "authoring_region", "us-west-2")
    monkeypatch.setattr(aws_status.settings, "authoring_model_id", "approved-profile")
    monkeypatch.setattr(aws_status, "_last_test", {"at": 0.0, "result": None})
    monkeypatch.setattr(aws_status, "_reload_times", [])
    monkeypatch.setattr(aws_status, "_daily", {"day": "", "count": 0})
    app = FastAPI()
    app.include_router(aws_status.router, prefix="/api/v1")
    app.dependency_overrides[aws_status.verify_viewer] = lambda: None
    app.dependency_overrides[aws_status.verify_operator] = lambda: None
    client = TestClient(app, headers={"X-Requested-With": "nrdp"})
    client.path = path
    client.app = app
    return client


def never_call(*_a, **_k):
    raise AssertionError("a model client must not be created by a status view")


def test_status_view_is_redacted_and_makes_no_model_call(api, monkeypatch):
    monkeypatch.setattr("aws_refresh.Coordinator.client", never_call)
    r = api.get("/api/v1/aws/status")
    assert r.status_code == 200
    data = r.json()
    no_secrets(r.text)
    assert data["configured"] and data["profile"] == "rotating" and data["state"] == "valid" and data["region"] == "us-west-2"
    assert data["source_path"].endswith("credentials") and data["expires_at_utc"] and data["last_failure"] is None
    assert {item["category"] for item in data["legend"]} >= {"expired_token", "upstream_renewal_failed", "access_denied", "model_config", "network"}


def test_reload_uses_the_same_coordinated_implementation_and_sees_a_rotation(api):
    api.get("/api/v1/aws/status")
    write_atomic(str(api.path), body(NEW, 3000, profile="rotating"))
    r = api.post("/api/v1/aws/reload")
    assert r.status_code == 200 and r.json()["changed"] is True and r.json()["usable"] is True
    assert r.json()["status"]["credential_changes"] >= 2
    no_secrets(r.text)


def test_reload_of_a_broken_file_reports_the_failure_and_keeps_serving_the_old_credentials(api):
    api.get("/api/v1/aws/status")
    with open(api.path, "w") as fh:
        fh.write("[rotating]\naws_access_key_id = AKIAPARTIAL\n")
    r = api.post("/api/v1/aws/reload").json()
    assert r["reloaded"] is False and r["status"]["last_failure"]["code"] == "incomplete"
    no_secrets(json.dumps(r))


def test_model_test_requires_explicit_confirmation_and_is_rate_limited(api, monkeypatch):
    calls = []

    class Client:
        def invoke_model(self, **kw):
            calls.append(kw["modelId"])
            return {}

    monkeypatch.setattr("aws_refresh.Coordinator.client", lambda self, *a, **k: Client())
    assert api.post("/api/v1/aws/test-model").status_code == 422 and calls == []
    assert api.post("/api/v1/aws/test-model", json={"confirm": False}).status_code == 422 and calls == []
    ok = api.post("/api/v1/aws/test-model", json={"confirm": True})
    assert ok.status_code == 200 and ok.json()["ok"] is True and calls == ["approved-profile"]
    assert api.post("/api/v1/aws/test-model", json={"confirm": True}).status_code == 429 and len(calls) == 1


@pytest.mark.parametrize("error,category", [
    (lambda: client_error("AccessDeniedException"), "access_denied"), (lambda: client_error("ResourceNotFoundException"), "model_config"),
    (lambda: TimeoutError("t"), "network"), (lambda: client_error("ThrottlingException"), "throttled"),
])
def test_model_test_separates_failure_kinds(api, monkeypatch, error, category):
    class Client:
        def invoke_model(self, **kw):
            raise error()

    monkeypatch.setattr("aws_refresh.Coordinator.client", lambda self, *a, **k: Client())
    r = api.post("/api/v1/aws/test-model", json={"confirm": True}).json()
    assert r["ok"] is False and r["category"] == category
    assert api.get("/api/v1/aws/status").json()["configured"]


def test_model_test_after_expiry_reports_upstream_renewal_failure(api, monkeypatch):
    write_atomic(str(api.path), body(OLD, -900, profile="rotating"))

    class Client:
        def invoke_model(self, **kw):
            raise expired_error()

    monkeypatch.setattr("aws_refresh.Coordinator.client", lambda self, *a, **k: Client())
    r = api.post("/api/v1/aws/test-model", json={"confirm": True}).json()
    assert r["category"] == "upstream_renewal_failed" and "cannot renew a human login" in r["message"]
    no_secrets(json.dumps(r))


def test_unconfigured_deployment_reports_not_configured(api, monkeypatch):
    monkeypatch.setattr(aws_status.settings, "authoring_shared_credentials_file", None)
    data = api.get("/api/v1/aws/status").json()
    assert data["configured"] is False and data["state"] == "not-configured"
    assert api.post("/api/v1/aws/reload").status_code == 409


def test_authoring_failure_text_distinguishes_renewal_failure_from_other_kinds():
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}

    renewal = safe_authoring_failure(UpstreamRenewalFailed("AWS credentials are expired and the configured credential file has not been renewed. Renew it."), operation="project-plan request")
    assert "has not been renewed" in renewal and "project-plan request" in renewal
    assert "denied access" in safe_authoring_failure(Denied(), operation="project-plan request")
    assert "AWS credentials expired" in safe_authoring_failure(expired_error(), operation="project-plan request")
    assert "invalid" in safe_authoring_failure(client_error("UnrecognizedClientException"), operation="x")


def test_write_endpoints_require_the_dashboard_header_and_a_matching_origin(api):
    bare = TestClient(api.app)
    assert bare.post("/api/v1/aws/reload").status_code == 403
    assert bare.post("/api/v1/aws/test-model", json={"confirm": True}).status_code == 403
    assert api.post("/api/v1/aws/reload", headers={"Origin": "http://evil.example", "X-Requested-With": "nrdp"}).status_code == 403
    assert api.post("/api/v1/aws/reload", headers={"Origin": "http://testserver", "X-Requested-With": "nrdp"}).status_code == 200
    assert api.get("/api/v1/aws/status").status_code == 200                      # reads need nothing extra


def test_reload_is_rate_limited_and_the_model_test_has_a_daily_cap(api, monkeypatch):
    codes = [api.post("/api/v1/aws/reload").status_code for _ in range(aws_status.RELOAD_BURST + 1)]
    assert codes[:-1] == [200] * aws_status.RELOAD_BURST and codes[-1] == 429
    monkeypatch.setattr(aws_status, "TEST_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(aws_status, "TEST_DAILY_CAP", 2)

    class Client:
        def invoke_model(self, **kw):
            return {}

    monkeypatch.setattr("aws_refresh.Coordinator.client", lambda self, *a, **k: Client())
    codes = [api.post("/api/v1/aws/test-model", json={"confirm": True}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
