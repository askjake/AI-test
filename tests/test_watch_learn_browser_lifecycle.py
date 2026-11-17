"""Deterministic browser-state tests plus host browser-gate presence checks."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import subprocess

from fastapi.testclient import TestClient
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_extracted_javascript_lifecycle_suite_passes():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for deterministic lifecycle execution")
    completed = subprocess.run(
        [node, "--test", "tests/js/watch_learn_lifecycle.test.js"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def test_browser_gate_support_suite_passes():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for browser-gate support execution")
    completed = subprocess.run(
        [node, "--test", "tests/js/watch_learn_browser_gate_support.test.js"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def test_watch_learn_csp_allows_only_inline_and_same_origin_scripts():
    page = (ROOT / "templates" / "dashboard" / "watch_learn.html").read_text(encoding="utf-8")
    match = re.search(
        r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">',
        page,
    )
    assert match is not None
    directives = {}
    for raw in match.group(1).split(";"):
        fields = raw.strip().split()
        if fields:
            directives[fields[0]] = fields[1:]
    assert directives["script-src"] == ["'self'", "'unsafe-inline'"]
    assert not {"*", "data:", "blob:", "'unsafe-eval'"}.intersection(
        directives["script-src"]
    )
    lifecycle_tag = '<script src="/watch-learn-assets/lifecycle.js"></script>'
    assert page.count(lifecycle_tag) == 1
    assert page.index(lifecycle_tag) < page.index('<script>\n"use strict";')
    assert "frame-ancestors" not in directives


def test_initialization_contract_is_non_sensitive_and_published_after_handlers():
    page = (ROOT / "templates" / "dashboard" / "watch_learn.html").read_text(encoding="utf-8")
    coordinator = "const frameCoordinator=new WatchLearnLifecycle.FrameCoordinator()"
    ready_call = "directInputHandlersInstalled=true;publishWatchLearnInitialization()"
    publication = 'document.documentElement.dataset.watchLearnInitialization="ready"'
    ready_event = 'document.dispatchEvent(new Event("watch-learn:ready"))'
    assert page.count(publication) == 1
    assert page.count(ready_event) == 1
    assert page.index(coordinator) < page.index(publication) < page.index(ready_call)
    for installed_handler in (
        '$("arm-direct").addEventListener("click"',
        'window.addEventListener("blur"',
        'document.addEventListener("visibilitychange"',
    ):
        assert page.index(installed_handler) < page.index(ready_call)
    assert "CustomEvent" not in page
    assert 'dataset.watchLearnInitialization="ready"' in page


def test_lifecycle_asset_is_operator_authenticated_and_never_cached(tmp_path, monkeypatch):
    from tests.test_phase16_auth import _bootstrap, _reload_app

    app, _reports, _specs, _audit = _reload_app(tmp_path, monkeypatch)
    path = "/watch-learn-assets/lifecycle.js"
    with TestClient(app) as anonymous:
        assert anonymous.get(path).status_code == 401
    with TestClient(app) as viewer:
        _bootstrap(viewer, "viewer")
        assert viewer.get(path).status_code == 403
    with TestClient(app) as operator:
        _bootstrap(operator, "operator")
        shell = operator.get("/watch-learn")
        assert shell.status_code == 200
        assert shell.headers["cache-control"] == "no-store"
        assert shell.headers["content-security-policy"] == "frame-ancestors 'none'"
        response = operator.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"].startswith("text/javascript")
        assert "FrameCoordinator" in response.text


def test_real_browser_gate_is_fail_fast_explicit_and_never_downloads_a_browser():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    support = (ROOT / "scripts" / "watch_learn_r2_browser_gate_support.js").read_text(encoding="utf-8")
    complete_gate = gate + support
    for required in (
        "PLAYWRIGHT_CHROMIUM_PATH",
        "chromium.launch",
        'page.on("pageerror"',
        'page.on("console"',
        'page.on("requestfailed"',
        'page.on("response"',
        'document.addEventListener("securitypolicyviolation"',
        'dataset.watchLearnInitialization === "ready"',
        "Watch & Learn initialization timeout",
        "Lifecycle asset request failed",
        "Unexpected console error",
        "click frame B without rearming",
    ):
        assert required in complete_gate
    assert "playwright install" not in complete_gate


def test_browser_gate_mocks_exact_refresh_and_favicon_without_hiding_404s():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    support = (ROOT / "scripts" / "watch_learn_r2_browser_gate_support.js").read_text(encoding="utf-8")
    page = (ROOT / "templates" / "dashboard" / "watch_learn.html").read_text(encoding="utf-8")
    assert 'api("/demonstrations/"+encodeURIComponent(current.session_id))' in page
    assert 'const sessionId = "session1234567890abcdef"' in gate
    assert 'url.pathname === `/api/v1/demonstrations/${sessionId}` && request.method === "GET"' in gate
    assert "json(response, 200, session(99, frameB))" in gate
    assert "state.sessionRefreshes" in gate
    assert 'url.pathname !== "/favicon.ico"' in support
    assert 'response.writeHead(204, {"content-type": "image/x-icon", "cache-control": "no-store"})' in support
    assert "formatUnmatchedMockRoute(request.method, url.href)" in gate
    assert "Unexpected HTTP response" in support
    assert 'response.status() === 404' in support
    assert "message.text()" in support
    assert "message.location()" in support
    assert "request.resourceType()" in support
    assert "request.failure()?.errorText" in support
    assert "ignoreHTTPSErrors" not in gate + support


def test_browser_gate_separates_viewport_resize_from_toolbar_focus_loss():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    resize = 'await page.setViewportSize({width: 760, height: 600})'
    resized_armed = 'assert.equal(resized.armed, true, `Viewport resize caused a fail-closed transition: ${JSON.stringify(resized)}`)'
    mapped_click = "await dispatchMappedClick(frameA, {targetX: 40, targetY: 20})"
    assert resize in gate
    assert resized_armed in gate
    assert mapped_click in gate
    assert gate.index(resize) < gate.index(resized_armed) < gate.index(mapped_click)
    assert 'assert.equal(resized.focused, "controlled-frame"' in gate
    assert 'assert.equal(resized.revision, frameA.sha256)' in gate


def test_browser_gate_requires_disarm_and_explicit_rearm_for_every_toolbar_control():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    for selector in (
        "#canvas-zoom-in",
        "#canvas-zoom-out",
        "#canvas-fit",
        "#canvas-expand",
    ):
        assert f'await assertToolbarDisarms("{selector}")' in gate
    for contract in (
        "must disarm direct input",
        "must not queue target input",
        "must not dispatch target input",
        "must require explicit rearming before target input",
        "Canvas focus was lost",
    ):
        assert contract in gate
    assert "await dispatchMappedClick(frameA, {rearm: true, targetX: 40, targetY: 20})" in gate
    assert "await dispatchMappedClick(frameA, {rearm: true, targetX: 65, targetY: 30})" in gate
    contradictory = 'await page.click("#canvas-fullscreen");\n    assert.equal(await page.evaluate(() => directArmed), true);'
    assert contradictory not in gate


def test_browser_gate_waits_for_fullscreen_event_convergence_and_retains_focus_boundaries():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    for required in (
        'const FULLSCREEN_CONVERGENCE_TIMEOUT_MS = 3000',
        'expected === "entry-or-unavailable"',
        'fullscreenElement === document.getElementById("canvas-card")',
        'buttonText === "Exit fullscreen"',
        'expected === "exited"',
        '!fullscreenElement && buttonText === "Fullscreen" && inputSettled',
        '/Fullscreen is unavailable in this browser/i.test(statusText)',
        'waitForFullscreenConvergence("entry-or-unavailable", fullscreenDispatchesBefore)',
        'waitForFullscreenConvergence("exited", exitDispatchesBefore)',
        'assert.ok(["entered", "unavailable"].includes(fullscreenDisposition))',
        "fullscreen toolbar use must require explicit rearming",
        "fullscreen exit must require explicit rearming",
        'window.dispatchEvent(new Event("blur"))',
        "Browser focus was lost",
        'document.dispatchEvent(new Event("visibilitychange"))',
        '"lostpointercapture"',
    ):
        assert required in gate
    assert 'await page.waitForFunction(() => !document.fullscreenElement)' not in gate
    helper = gate[
        gate.index("async function waitForFullscreenConvergence") :
        gate.index("async function assertFocusLossDisarm")
    ]
    assert "waitForTimeout" not in helper
    for diagnostic in (
        "fullscreenPresent",
        "fullscreenElementId",
        "fullscreenButtonText",
        "activeElementId",
        "directArmed",
        "queuedActionCount",
        "pendingClick",
        "dispatchedActionCount",
    ):
        assert diagnostic in gate
    assert "snapshot=${JSON.stringify(snapshot)}" in gate
    assert "PASS: real Chromium Watch & Learn R2G frame-retirement, fullscreen convergence, initialization, and mock-completeness gate completed with local mocks only." in gate


def test_retired_canvas_identity_is_event_order_independent_and_current_blur_is_fail_closed():
    page = (ROOT / "templates" / "dashboard" / "watch_learn.html").read_text(encoding="utf-8")
    assert "const retiredCanvases=new WeakSet()" in page
    assert "retiringCanvas" not in page
    assert "function retireCanvas(image){if(image)retiredCanvases.add(image)}" in page
    current_guard = 'function isCurrentCanvas(image){return Boolean(image&&image.isConnected&&image===$("controlled-frame")&&!retiredCanvases.has(image))}'
    assert current_guard in page
    replacement = 'const old=$("controlled-frame");retireCanvas(old);root.replaceChildren(image)'
    empty = 'const root=$("canvas"),old=$("controlled-frame");directArmed=false;retireCanvas(old);root.replaceChildren()'
    blur = 'image.addEventListener("blur",()=>{if(!isCurrentCanvas(image))return;if(directArmed){clearQueuedActions("Canvas focus was lost.");disarmDirect("Canvas focus was lost; direct input is paused locally.",true)}})'
    assert replacement in page
    assert empty in page
    assert blur in page
    assert page.index("retireCanvas(old)", page.index(replacement)) < page.index("root.replaceChildren(image)")


def test_browser_gate_proves_retired_blur_semantics_and_current_canvas_safety():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    for required in (
        'oldImage.dispatchEvent(new Event("blur"))',
        'oldImage => oldImage.dispatchEvent(new Event("blur")), retiredFrameA',
        'oldImage => oldImage.dispatchEvent(new Event("blur")), retiredFrameB',
        'waitForFrameTransition(frameB, 0, retiredFrameA, "Obsolete disposable input was discarded.")',
        'waitForFrameTransition(frameC, 0, retiredFrameB, "meaningful unsent action must be repeated")',
        'assert.equal(frameCAfterLateBlur.directArmed, true)',
        'assert.equal(frameCAfterLateBlur.activeElementId, "controlled-frame")',
        'assert.equal(frameCAfterLateBlur.eventSourceRetired, true)',
        'assert.equal(frameCAfterLateBlur.eventSourceCurrent, false)',
        'await dispatchMappedClick(frameC, {targetX: 45, targetY: 25})',
        'new Set(state.actions.map(item => item.idempotency_key)).size',
        'await page.focus("#canvas-fit")',
        'await assertFocusLossDisarm(currentBlurDispatches, "current frame C blur")',
        'cancelled meaningful input must never be replayed',
    ):
        assert required in gate
    assert 'assert.equal(frameCAfterLateBlur.directArmed, false)' not in gate


def test_transition_wait_is_bounded_diagnostic_and_repeated():
    gate = (ROOT / "scripts" / "run_watch_learn_r2_browser_gate.js").read_text(encoding="utf-8")
    assert "const FRAME_TRANSITION_CONVERGENCE_TIMEOUT_MS = 3000" in gate
    assert "const FRAME_RETIREMENT_REPETITIONS = 5" in gate
    helper = gate[
        gate.index("async function frameTransitionSnapshot") :
        gate.index("async function fullscreenDiagnosticSnapshot")
    ]
    assert "waitForTimeout" not in helper
    for diagnostic in (
        "directArmed",
        "activeElementId",
        "directState",
        "statusText",
        "canvasUpdating",
        "canvasRevision",
        "bindingRevision",
        "bindingGeneration",
        "currentImageConnected",
        "eventSourceRetired",
        "eventSourceCurrent",
        "pendingClick",
        "wheelBurst",
        "hoverPending",
        "queueLength",
        "actionInFlight",
        "dispatchedActionCount",
    ):
        assert diagnostic in helper
    assert "Frame transition convergence timed out after ${FRAME_TRANSITION_CONVERGENCE_TIMEOUT_MS} ms" in helper
    assert "for (let index = 0; index < FRAME_RETIREMENT_REPETITIONS; index += 1)" in gate


def test_r2g_production_sources_match_authoritative_hashes():
    expected = {
        "templates/dashboard/watch_learn.html": "75bb7cc462489fac284d9a47b36bb2665c5c974f54425c880f74bd2c7dbf0663",
        "static/watch_learn_lifecycle.js": "656c573cafce19800fe30722e6f44b9f29fe80eeedd8380dc3162e690ab54675",
        # b4r11's app.py was 5933d1b9...; CP45-R added exactly three lines (the reports-switch guard import and two _require_switch_resolved calls).
        # Every package since cp45r records 5933d1b9 -> 0bf684f2 for this file in its MANIFEST, so 0bf684f2 is the established expected byte state.
        "src/dashboard/app.py": "0bf684f2a8a2d3fa4466165b1e0a18d7ec92c7fa71569a22580038e83c0951a6",
    }
    for relative_path, expected_digest in expected.items():
        assert hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest() == expected_digest
