"""AWS credential status, reload and a separately initiated bounded model test (never called by page load or by polling).

* GET  /api/v1/aws/status      redacted status (source, profile, expiry, last reload/failure, categories).  No AWS call, no model call.
* POST /api/v1/aws/reload      the SAME coordinated reload the retry path uses; operator only.
* POST /api/v1/aws/test-model  ONE tiny model call, only with {"confirm": true}; operator only; rate limited.  Costs a few tokens.
"""
from __future__ import annotations

import json
import os
import threading
import time

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from aws_refresh import classify_error, clear_model_error, describe_category, get_coordinator, last_model_error, read_options
from .auth import verify_operator, verify_viewer
from .config import settings

router = APIRouter()
_TEST_LOCK = threading.Lock()
_last_test = {"at": 0.0, "result": None}
TEST_INTERVAL_SECONDS = 30.0
TEST_DAILY_CAP = 200
RELOAD_BURST = 6          # at most 6 reloads per 10 s (a reload only re-reads a local file; this bounds abuse, not normal clicking)
RELOAD_WINDOW = 10.0
REQUIRED_HEADER = ("x-requested-with", "nrdp")
_daily = {"day": "", "count": 0}
_reload_times: list = []


def same_origin_mutation(request: Request) -> None:
    """CSRF / DNS-rebinding defence for the WRITE endpoints.  In shared-operator no-login mode there is no CSRF token, so a web page in any LAN browser
    could otherwise POST here.  A cross-site form or simple fetch cannot set a custom header, and a rebinding page presents a foreign Host/Origin."""
    if request.headers.get(REQUIRED_HEADER[0]) != REQUIRED_HEADER[1]:
        raise HTTPException(status_code=403, detail={"code": "csrf_header_required", "message": "This action must be sent by the dashboard page itself."})
    origin = request.headers.get("origin")
    if origin:
        from urllib.parse import urlparse
        host = (request.headers.get("host") or "").lower()
        if urlparse(origin).netloc.lower() != host:
            raise HTTPException(status_code=403, detail={"code": "origin_mismatch", "message": "Cross-origin request refused."})

LEGEND = [
    {"category": "expired_token", "label": "Expired credentials", "meaning": "The source file holds credentials that AWS says are expired. Reload picks up a renewed file."},
    {"category": "upstream_renewal_failed", "label": "Upstream renewal failed", "meaning": "Expired and the file has not been renewed. The existing refresh procedure (or your login) must run; this app cannot renew a human login."},
    {"category": "access_denied", "label": "Access denied", "meaning": "The credentials are valid but not allowed to use Bedrock or this model."},
    {"category": "model_config", "label": "Model configuration", "meaning": "The model or inference profile is unavailable in the region; check the configured id."},
    {"category": "network", "label": "Network", "meaning": "The Bedrock endpoint was unreachable or timed out; credentials are not implicated."},
]


def _coordinator():
    if not settings.authoring_shared_credentials_file:
        return None
    config_path = os.environ.get("ORCHESTRATOR_COOKIE_CONFIG") or ""
    return get_coordinator(settings.authoring_shared_credentials_file, settings.authoring_profile or "default", region=settings.authoring_region,
                           config_file=settings.authoring_shared_config_file,
                           options=read_options(os.path.dirname(config_path) if config_path else None))


def build_status() -> dict:
    coordinator = _coordinator()
    base = {"legend": LEGEND, "last_model_error": last_model_error(), "model_id": settings.authoring_model_id,
            "authoring_enabled": bool(settings.authoring_refinement_configured)}
    if coordinator is None:
        return {**base, "configured": False, "state": "not-configured", "provider": "none", "profile": settings.authoring_profile,
                "warnings": ["No AWS credential file is configured for model calls."], "expires_at_utc": None, "expires_in_seconds": None,
                "last_reload_ok_utc": None, "last_failure": None}
    return {**base, "configured": True, **coordinator.status()}


@router.get("/aws/status")
def get_aws_status(_user=Depends(verify_viewer)) -> dict:
    return build_status()


@router.post("/aws/reload")
def post_aws_reload(_user=Depends(verify_operator), _same=Depends(same_origin_mutation)) -> dict:
    import time as _t
    now = _t.monotonic()
    _reload_times[:] = [t for t in _reload_times if now - t < RELOAD_WINDOW]
    if len(_reload_times) >= RELOAD_BURST:
        raise HTTPException(status_code=429, detail="Too many reloads in a short time; wait a few seconds.")
    _reload_times.append(now)
    coordinator = _coordinator()
    if coordinator is None:
        raise HTTPException(status_code=409, detail="No AWS credential file is configured.")
    outcome = coordinator.reload("manual")
    if outcome.usable:
        clear_model_error()
    return {"reloaded": outcome.reason in ("reloaded", "unchanged"), "changed": outcome.changed, "usable": outcome.usable, "reason": outcome.reason,
            "status": build_status()}


@router.post("/aws/test-model")
def post_aws_test_model(body: object = Body(default=None), _user=Depends(verify_operator), _same=Depends(same_origin_mutation)) -> dict:
    if not isinstance(body, dict) or body.get("confirm") is not True:
        raise HTTPException(status_code=422, detail='Send {"confirm": true} to run one small model call (it uses a few tokens).')
    coordinator = _coordinator()
    if coordinator is None or not settings.authoring_model_id:
        raise HTTPException(status_code=409, detail="AWS credentials or the model id are not configured.")
    import datetime as _dt
    today = _dt.date.today().isoformat()
    if _daily["day"] != today:
        _daily.update(day=today, count=0)
    if _daily["count"] >= TEST_DAILY_CAP:
        raise HTTPException(status_code=429, detail="The daily limit for model tests was reached.")
    if not _TEST_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A model test is already running.")
    try:
        wait = TEST_INTERVAL_SECONDS - (time.monotonic() - _last_test["at"])
        if _last_test["result"] is not None and wait > 0:
            raise HTTPException(status_code=429, detail=f"Wait {int(wait) + 1} s before another model test.")
        _daily["count"] += 1
        started = time.monotonic()
        result: dict
        try:
            from botocore.config import Config
            client = coordinator.client("bedrock-runtime", config=Config(connect_timeout=10, read_timeout=30, retries={"max_attempts": 0}))
            payload = json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 8,
                                  "messages": [{"role": "user", "content": "Reply with the single word OK."}]})
            coordinator.call(lambda: client.invoke_model(modelId=settings.authoring_model_id, body=payload,
                                                         contentType="application/json", accept="application/json"))
            result = {"ok": True, "category": "ok", "message": "The model answered with the configured credentials."}
        except Exception as exc:                                       # categories only; no exception text is returned
            category = classify_error(exc)
            message = getattr(exc, "safe_reason", None) or describe_category(category)
            result = {"ok": False, "category": category, "message": message}
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        _last_test.update({"at": time.monotonic(), "result": result})
        return {**result, "status": build_status()}
    finally:
        _TEST_LOCK.release()
