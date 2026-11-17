#!/usr/bin/env node
"use strict";

// Localhost-only, mock-backed real-browser acceptance. This script never starts
// the dashboard, contacts a target, reads secrets, or downloads a browser.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const {
  assertSingleInitialization,
  attachFatalObservers,
  createFatalLatch,
  formatUnmatchedMockRoute,
  installCspAndReadinessInstrumentation,
  serveExpectedFavicon,
  waitForInitialization,
} = require("./watch_learn_r2_browser_gate_support.js");

let chromium;
try {
  ({chromium} = require("playwright"));
} catch (_) {
  process.stderr.write("BLOCKED: the Node.js playwright package is not installed.\n");
  process.exit(78);
}

const browserPath = process.env.PLAYWRIGHT_CHROMIUM_PATH || chromium.executablePath();
if (!browserPath || !fs.existsSync(browserPath)) {
  process.stderr.write("BLOCKED: set PLAYWRIGHT_CHROMIUM_PATH to an already-installed Chromium executable. No browser will be downloaded.\n");
  process.exit(78);
}

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "templates/dashboard/watch_learn.html"));
const lifecycle = fs.readFileSync(path.join(root, "static/watch_learn_lifecycle.js"));
const revision = value => value.repeat(64);
const state = {actions: [], mode: "normal", actionResponseEvidence: null, actionResponseVersion: null, pauseCount: 0, lifecycleRequests: 0, sessionRefreshes: 0, faviconRequests: 0};
const lifecycleResponses = [];
const FULLSCREEN_CONVERGENCE_TIMEOUT_MS = 3000;
const FRAME_TRANSITION_CONVERGENCE_TIMEOUT_MS = 3000;
const FRAME_RETIREMENT_REPETITIONS = 5;

function isExpectedActionConflictConsoleError(message) {
  if (message.type() !== "error" || !["stale", "revision"].includes(state.mode)) return false;
  const location = message.location() || {};
  let pathname = "";
  try { pathname = new URL(location.url).pathname; } catch (_) { return false; }
  return pathname === `/api/v1/demonstrations/${sessionId}/actions`
    && /^Failed to load resource: the server responded with a status of 409 \(Conflict\)$/.test(message.text());
}

function evidence(id, digest, width = 100, height = 50) {
  return {evidence_id: id, event_id: `event-${id}-1234567890`, access_state: "available", sha256: digest,
    width, height, byte_length: 100, mime_type: "image/png", created_at: "2026-09-15T00:00:00Z",
    redacted_at: null, pending_redactions: []};
}
function session(version, item, sessionState = "recording") {
  return {session_id: "session1234567890abcdef", owner_principal: revision("1"), ownership_mode: "unique-identity",
    ownership_notice: "Private test owner.", project_name: "sample", project_revision: revision("2"),
    target_revision: revision("3"), privacy_revision: revision("4"), target_type: "local-app",
    operator_goal: "Browser lifecycle test", state: sessionState, version,
    created_at: "2026-09-15T00:00:00Z", updated_at: "2026-09-15T00:00:00Z",
    journals: [], receipts: [], evidence: item ? [item] : [], annotations: [], analyses: [], model_jobs: [], private_drafts: []};
}
const frameA = evidence("frame-a-1234567890", revision("a"));
const frameB = evidence("frame-b-1234567890", revision("b"));
const frameC = evidence("frame-c-1234567890", revision("c"));
const sessionId = "session1234567890abcdef";

function json(response, status, body) {
  response.writeHead(status, {"content-type": "application/json", "cache-control": "no-store"});
  response.end(JSON.stringify(body));
}
function image(response, id) {
  if (id.startsWith("bad-")) {
    response.writeHead(200, {"content-type": "image/png", "cache-control": "no-store"});
    response.end("not-a-decodable-image");
    return;
  }
  const color = id.includes("frame-a") ? "#224488" : id.includes("frame-b") ? "#228844" : "#884422";
  response.writeHead(200, {"content-type": "image/svg+xml", "cache-control": "public,max-age=3600"});
  response.end(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="50"><rect width="100" height="50" fill="${color}"/></svg>`);
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);
  if (serveExpectedFavicon(request, response, url)) { state.faviconRequests += 1; return; }
  if (url.pathname === "/watch-learn") {
    response.writeHead(200, {"content-type": "text/html", "content-security-policy": "frame-ancestors 'none'"});
    response.end(html);
    return;
  }
  if (url.pathname === "/watch-learn-assets/lifecycle.js") {
    state.lifecycleRequests += 1;
    response.writeHead(200, {"content-type": "text/javascript", "cache-control": "no-store"});
    response.end(lifecycle);
    return;
  }
  if (url.pathname.includes("/evidence/")) { image(response, decodeURIComponent(url.pathname.split("/evidence/")[1])); return; }
  if (url.pathname === "/api/v1/auth/session") { json(response, 200, {role: "operator", csrf_token: "csrf"}); return; }
  if (url.pathname === "/api/v1/projects") { json(response, 200, [{name: "sample"}]); return; }
  if (url.pathname === "/api/v1/authoring/wizard/target-options") { json(response, 200, {password_references: []}); return; }
  if (url.pathname === "/api/v1/demonstrations" && request.method === "GET") { json(response, 200, []); return; }
  if (url.pathname === `/api/v1/demonstrations/${sessionId}` && request.method === "GET") {
    state.sessionRefreshes += 1;
    json(response, 200, session(99, frameB));
    return;
  }
  if (url.pathname.endsWith("/capture/pause")) { state.pauseCount += 1; json(response, 200, session(50, frameB, "paused")); return; }
  if (url.pathname.endsWith("/actions")) {
    let body = "";
    request.on("data", chunk => { body += chunk; });
    request.on("end", () => {
      const parsed = JSON.parse(body); state.actions.push(parsed);
      if (state.mode === "stale" || state.mode === "revision") {
        json(response, 409, {detail: {code: state.mode === "stale" ? "stale_frame_revision" : "revision_conflict", message: "Mock rejected stale input.", current_version: 99}}); return;
      }
      const outcome = state.mode === "uncertain" ? "outcome_unknown" : "executed";
      const responseEvidence = state.actionResponseEvidence || frameB;
      const responseVersion = state.actionResponseVersion || (state.actions.length === 1 ? 4 : 4 + state.actions.length * 3);
      const next = session(responseVersion, responseEvidence);
      json(response, 200, {session: next, receipt: {event_id: `event-${state.actions.length}-1234567890`, idempotency_key: parsed.idempotency_key, outcome, detail: "Mock receipt.", recorded_at: "2026-09-15T00:00:00Z", evidence_id: outcome === "executed" ? responseEvidence.evidence_id : null}});
    });
    return;
  }
  process.stderr.write(`${formatUnmatchedMockRoute(request.method, url.href)}\n`);
  json(response, 404, {detail: {message: "mock route missing"}});
});

function waitFor(predicate, timeout = 5000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (predicate()) resolve();
      else if (Date.now() - started > timeout) reject(new Error("browser gate timed out"));
      else setTimeout(poll, 20);
    };
    poll();
  });
}

async function load(page, initial = session(1, frameA)) {
  state.actions.length = 0; state.mode = "normal"; state.actionResponseEvidence = null; state.actionResponseVersion = null;
  const requestsBefore = state.lifecycleRequests;
  const responsesBefore = lifecycleResponses.length;
  await page.goto(`${baseUrl}/watch-learn`, {waitUntil: "load"});
  await waitForInitialization(page);
  const readyEventCount = await page.evaluate(() => globalThis.__watchLearnReadyEventCount || 0);
  assertSingleInitialization({
    lifecycleRequestsBefore: requestsBefore,
    lifecycleRequestsAfter: state.lifecycleRequests,
    lifecycleResponsesBefore: responsesBefore,
    lifecycleResponsesAfter: lifecycleResponses.length,
    readyEventCount,
  });
  const lifecycleResponse = lifecycleResponses[lifecycleResponses.length - 1];
  assert.equal(lifecycleResponse.status(), 200);
  assert.match(lifecycleResponse.headers()["content-type"] || "", /^text\/javascript/);
  assert.equal(lifecycleResponse.headers()["cache-control"], "no-store");
  assert.equal(await page.evaluate(() => globalThis.__watchLearnCspViolationCount || 0), 0);
  assert.equal(await page.evaluate(() => typeof WatchLearnLifecycle === "object"), true);
  assert.equal(await page.evaluate(() => frameCoordinator instanceof WatchLearnLifecycle.FrameCoordinator), true);
  await page.evaluate(value => showSession(value), initial);
  await page.waitForSelector("#controlled-frame");
}

let baseUrl;
(async () => {
  let browser;
  let context;
  let detachFatalObservers = () => {};
  let fatalLatch;
  let primaryError;
  const cleanupErrors = [];
  try {
    await new Promise((resolve, reject) => {
      const onError = error => reject(error);
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    process.stdout.write(`BROWSER_EXECUTABLE=${browserPath}\n`);
    browser = await chromium.launch({headless: true, executablePath: browserPath});
    context = await browser.newContext({deviceScaleFactor: 2, viewport: {width: 1100, height: 800}});
    const page = await context.newPage();
    fatalLatch = createFatalLatch();
    detachFatalObservers = attachFatalObservers(
      page,
      error => fatalLatch.fail(error),
      lifecycleResponses,
      {isExpectedConsoleError: isExpectedActionConflictConsoleError},
    );
    await installCspAndReadinessInstrumentation(page, error => fatalLatch.fail(error));

    async function runGate() {
    async function directInputSnapshot() {
      return await page.evaluate(() => ({
        armed: directArmed,
        focused: document.activeElement?.id || "",
        directState: document.getElementById("direct-state").textContent,
        queued: actionQueue.length,
        pendingClick: Boolean(pendingClick),
        wheelBurst: Boolean(wheelBurst),
        hoverPending: Boolean(hoverPending),
        revision: frameCoordinator.binding()?.revision || null,
      }));
    }

    async function frameTransitionSnapshot(eventSource = null) {
      const browserState = await page.evaluate(source => {
        const currentImage = document.getElementById("controlled-frame");
        const binding = frameCoordinator.binding();
        return {
          directArmed,
          activeElementId: document.activeElement?.id || "",
          directState: document.getElementById("direct-state")?.textContent || "",
          statusText: document.getElementById("status")?.textContent || "",
          canvasUpdating,
          canvasRevision: canvasRecord?.sha256 || null,
          bindingRevision: binding?.revision || null,
          bindingGeneration: binding?.generation || null,
          currentImageConnected: Boolean(currentImage?.isConnected),
          eventSourceRetired: source ? retiredCanvases.has(source) : null,
          eventSourceCurrent: source ? source === currentImage : null,
          pendingClick: Boolean(pendingClick),
          wheelBurst: Boolean(wheelBurst),
          hoverPending: Boolean(hoverPending),
          queueLength: actionQueue.length,
          actionInFlight,
        };
      }, eventSource);
      return {...browserState, dispatchedActionCount: state.actions.length};
    }

    async function waitForFrameTransition(expectedFrame, dispatchesBefore, eventSource = null, expectedNotice = "") {
      try {
        await page.waitForFunction(expected => {
          const currentImage = document.getElementById("controlled-frame");
          const binding = frameCoordinator.binding();
          const directState = document.getElementById("direct-state")?.textContent || "";
          return directArmed
            && document.activeElement === currentImage
            && Boolean(currentImage?.isConnected)
            && !canvasUpdating
            && canvasRecord?.sha256 === expected.revision
            && binding?.revision === expected.revision
            && binding?.width === expected.width
            && binding?.height === expected.height
            && actionQueue.length === 0
            && pendingClick === null
            && wheelBurst === null
            && hoverPending === null
            && !actionInFlight
            && (!expected.notice || directState.includes(expected.notice));
        }, {
          revision: expectedFrame.sha256,
          width: expectedFrame.width,
          height: expectedFrame.height,
          notice: expectedNotice,
        }, {timeout: FRAME_TRANSITION_CONVERGENCE_TIMEOUT_MS});
      } catch (error) {
        const snapshot = await frameTransitionSnapshot(eventSource);
        throw new Error(`Frame transition convergence timed out after ${FRAME_TRANSITION_CONVERGENCE_TIMEOUT_MS} ms: ${error.message}; snapshot=${JSON.stringify(snapshot)}`);
      }
      const snapshot = await frameTransitionSnapshot(eventSource);
      assert.equal(snapshot.dispatchedActionCount, dispatchesBefore, `Frame transition must not dispatch obsolete input; snapshot=${JSON.stringify(snapshot)}`);
      return snapshot;
    }

    async function fullscreenDiagnosticSnapshot() {
      const browserState = await page.evaluate(() => ({
        fullscreenPresent: Boolean(document.fullscreenElement),
        fullscreenElementId: document.fullscreenElement?.id || "",
        fullscreenButtonText: document.getElementById("canvas-fullscreen")?.textContent || "",
        activeElementId: document.activeElement?.id || "",
        directArmed,
        queuedActionCount: actionQueue.length,
        pendingClick: Boolean(pendingClick),
        actionInFlight,
      }));
      return {...browserState, dispatchedActionCount: state.actions.length};
    }

    async function waitForFullscreenConvergence(expectedState, dispatchesBefore) {
      try {
        await page.waitForFunction(expected => {
          const fullscreenElement = document.fullscreenElement;
          const buttonText = document.getElementById("canvas-fullscreen")?.textContent || "";
          const statusText = document.getElementById("status")?.textContent || "";
          const inputSettled = !directArmed && actionQueue.length === 0 && pendingClick === null && !actionInFlight;
          const entered = fullscreenElement === document.getElementById("canvas-card")
            && buttonText === "Exit fullscreen"
            && inputSettled;
          const unavailable = !fullscreenElement
            && buttonText === "Fullscreen"
            && /Fullscreen is unavailable in this browser/i.test(statusText)
            && inputSettled;
          if (expected === "entry-or-unavailable") return entered || unavailable;
          if (expected === "exited") return !fullscreenElement && buttonText === "Fullscreen" && inputSettled;
          return false;
        }, expectedState, {timeout: FULLSCREEN_CONVERGENCE_TIMEOUT_MS});
      } catch (error) {
        const snapshot = await fullscreenDiagnosticSnapshot();
        throw new Error(`Fullscreen ${expectedState} convergence timed out after ${FULLSCREEN_CONVERGENCE_TIMEOUT_MS} ms: ${error.message}; snapshot=${JSON.stringify(snapshot)}`);
      }
      const snapshot = await fullscreenDiagnosticSnapshot();
      assert.equal(
        snapshot.dispatchedActionCount,
        dispatchesBefore,
        `Fullscreen ${expectedState} convergence must not dispatch target input; snapshot=${JSON.stringify(snapshot)}`,
      );
      return snapshot;
    }

    async function assertFocusLossDisarm(dispatchesBefore, label) {
      await page.waitForFunction(() => !directArmed);
      const snapshot = await directInputSnapshot();
      assert.equal(snapshot.armed, false, `${label} must disarm direct input`);
      assert.notEqual(snapshot.focused, "controlled-frame", `${label} must move focus away from the controlled frame`);
      assert.match(snapshot.directState, /Canvas focus was lost|direct input is disarmed|paused locally/i);
      assert.equal(snapshot.queued, 0, `${label} must not queue target input`);
      assert.equal(snapshot.pendingClick, false, `${label} must cancel pending clicks`);
      assert.equal(snapshot.wheelBurst, false, `${label} must cancel pending wheel input`);
      assert.equal(snapshot.hoverPending, false, `${label} must cancel pending hover input`);
      assert.equal(state.actions.length, dispatchesBefore, `${label} must not dispatch target input`);
    }

    async function assertToolbarDisarms(selector) {
      await load(page);
      await page.click("#arm-direct");
      assert.deepEqual(await page.evaluate(() => ({armed: directArmed, focused: document.activeElement.id})), {
        armed: true,
        focused: "controlled-frame",
      });
      const dispatchesBefore = state.actions.length;
      await page.click(selector);
      await assertFocusLossDisarm(dispatchesBefore, selector);
      await page.locator("#controlled-frame").click({position: {x: 35, y: 20}});
      await page.waitForTimeout(320);
      assert.equal(state.actions.length, dispatchesBefore, `${selector} must require explicit rearming before target input`);
      assert.equal(await page.evaluate(() => directArmed), false);
    }

    async function dispatchMappedClick(expectedFrame, {rearm = false, targetX = 40, targetY = 20} = {}) {
      if (rearm) await page.click("#arm-direct");
      const image = page.locator("#controlled-frame");
      await image.scrollIntoViewIfNeeded();
      const point = await page.evaluate(({targetX: x, targetY: y}) => {
        const controlled = document.getElementById("controlled-frame");
        const bounds = controlled.getBoundingClientRect();
        if (!directArmed || document.activeElement !== controlled || bounds.width <= 0 || bounds.height <= 0) {
          throw new Error(`Controlled frame is not armed, focused, and measurable: ${document.getElementById("direct-state").textContent}`);
        }
        return {
          clientX: bounds.left + (x + 0.5) * bounds.width / canvasRecord.width,
          clientY: bounds.top + (y + 0.5) * bounds.height / canvasRecord.height,
        };
      }, {targetX, targetY});
      const dispatchesBefore = state.actions.length;
      await page.mouse.click(point.clientX, point.clientY);
      await waitFor(() => state.actions.length === dispatchesBefore + 1);
      const action = state.actions[dispatchesBefore].action;
      assert.deepEqual({
        kind: action.kind,
        revision: action.frame_revision,
        width: action.frame_width,
        height: action.frame_height,
        x: action.x,
        y: action.y,
      }, {
        kind: "click",
        revision: expectedFrame.sha256,
        width: expectedFrame.width,
        height: expectedFrame.height,
        x: targetX,
        y: targetY,
      });
      await page.waitForFunction(() => !actionInFlight && !canvasUpdating);
      assert.equal(state.actions.length, dispatchesBefore + 1, "mapped click must dispatch exactly once");
    }

    // Primary acceptance: click frame A -> load frame B -> click frame B without rearming.
    await load(page);
    await page.click("#arm-direct");
    await page.locator("#controlled-frame").click({position: {x: 25, y: 20}});
    await waitFor(() => state.actions.length === 1);
    await page.waitForFunction(() => directArmed && !canvasUpdating && document.activeElement.id === "controlled-frame" && document.getElementById("controlled-frame").complete);
    assert.equal(state.actions[0].action.frame_revision, frameA.sha256);
    assert.deepEqual(await page.evaluate(() => ({
      revision: canvasRecord.sha256,
      binding: frameCoordinator.binding().revision,
      naturalWidth: document.getElementById("controlled-frame").naturalWidth,
      naturalHeight: document.getElementById("controlled-frame").naturalHeight,
      focused: document.activeElement.id,
      armed: directArmed,
    })), {
      revision: frameB.sha256,
      binding: frameB.sha256,
      naturalWidth: 100,
      naturalHeight: 50,
      focused: "controlled-frame",
      armed: true,
    });
    await page.locator("#controlled-frame").click({position: {x: 70, y: 30}}); // click frame B without rearming
    await waitFor(() => state.actions.length === 2);
    assert.equal(state.actions[1].action.frame_revision, frameB.sha256);
    assert.equal(state.actions[1].action.frame_width, 100);
    assert.equal(state.actions[1].action.frame_height, 50);
    assert.equal(new Set(state.actions.map(item => item.idempotency_key)).size, 2);
    assert.equal(state.actions.some(item => item.action.kind === "pointer_move" && item.action.frame_revision === frameA.sha256), false);

    // Same evidence and out-of-order responses retain the exact canvas node.
    await page.evaluate(() => { document.getElementById("controlled-frame").dataset.identity = "retained"; });
    await page.evaluate(value => showSession(value), session(20, frameB));
    await page.evaluate(value => showSession(value), session(19, frameC));
    assert.equal(await page.getAttribute("#controlled-frame", "data-identity"), "retained");
    assert.equal(await page.evaluate(() => canvasRecord.sha256), frameB.sha256);

    // Hover immediately before a click is cancelled instead of becoming a stale disposable action.
    await load(page);
    await page.click("#arm-direct");
    await page.locator("#controlled-frame").hover({position: {x: 10, y: 10}});
    await page.locator("#controlled-frame").click({position: {x: 50, y: 25}});
    await waitFor(() => state.actions.length === 1);
    await page.waitForTimeout(220);
    assert.equal(state.actions.length, 1);
    assert.equal(state.actions[0].action.kind, "click");

    // A viewport-only resize retains focused authority and exact coordinate mapping.
    await load(page);
    await page.click("#arm-direct");
    assert.equal(await page.evaluate(() => devicePixelRatio), 2);
    await page.setViewportSize({width: 760, height: 600});
    const resized = await directInputSnapshot();
    assert.equal(resized.armed, true, `Viewport resize caused a fail-closed transition: ${JSON.stringify(resized)}`);
    assert.equal(resized.focused, "controlled-frame", `Viewport resize changed canvas focus: ${JSON.stringify(resized)}`);
    assert.equal(resized.revision, frameA.sha256);
    assert.equal(state.actions.length, 0);
    await dispatchMappedClick(frameA, {targetX: 40, targetY: 20});

    // Every non-canvas view control loses canvas focus, disarms, and requires explicit rearming.
    await assertToolbarDisarms("#canvas-zoom-in");
    assert.match(await page.textContent("#canvas-view-status"), /125% · 100×50/);
    await dispatchMappedClick(frameA, {rearm: true, targetX: 40, targetY: 20});
    await assertToolbarDisarms("#canvas-zoom-out");
    await assertToolbarDisarms("#canvas-fit");
    await assertToolbarDisarms("#canvas-expand");
    assert.equal(await page.textContent("#canvas-expand"), "Restore workspace");
    await dispatchMappedClick(frameA, {rearm: true, targetX: 65, targetY: 30});

    // Fullscreen may be supported or explicitly unavailable; its toolbar click always disarms.
    await load(page);
    await page.click("#arm-direct");
    const fullscreenDispatchesBefore = state.actions.length;
    await page.click("#canvas-fullscreen");
    const fullscreenSnapshot = await waitForFullscreenConvergence("entry-or-unavailable", fullscreenDispatchesBefore);
    await assertFocusLossDisarm(fullscreenDispatchesBefore, "#canvas-fullscreen");
    const fullscreenDisposition = fullscreenSnapshot.fullscreenPresent ? "entered" : "unavailable";
    assert.ok(["entered", "unavailable"].includes(fullscreenDisposition));
    process.stdout.write(`FULLSCREEN_DISPOSITION=${fullscreenDisposition}\n`);
    await page.locator("#controlled-frame").click({position: {x: 35, y: 20}});
    await page.waitForTimeout(320);
    assert.equal(state.actions.length, fullscreenDispatchesBefore, "fullscreen toolbar use must require explicit rearming");
    if (fullscreenDisposition === "entered") {
      await dispatchMappedClick(frameA, {rearm: true, targetX: 55, targetY: 25});
      const exitDispatchesBefore = state.actions.length;
      await page.click("#canvas-fullscreen");
      await waitForFullscreenConvergence("exited", exitDispatchesBefore);
      await assertFocusLossDisarm(exitDispatchesBefore, "#canvas-fullscreen exit");
      await page.locator("#controlled-frame").click({position: {x: 35, y: 20}});
      await page.waitForTimeout(320);
      assert.equal(state.actions.length, exitDispatchesBefore, "fullscreen exit must require explicit rearming");
    }

    // Retired-image blur is harmless; disposable and meaningful obsolete input keep distinct semantics.
    await load(page); await page.click("#arm-direct");
    await page.evaluate(() => {
      const root = document.getElementById("canvas");
      root.__watchLearnOriginalReplaceChildren = root.replaceChildren;
      root.replaceChildren = function(...nodes) {
        const oldImage = document.getElementById("controlled-frame");
        const result = Element.prototype.replaceChildren.apply(this, nodes);
        if (oldImage) oldImage.dispatchEvent(new Event("blur"));
        return result;
      };
    });
    const retiredFrameA = await page.locator("#controlled-frame").elementHandle();
    await page.locator("#controlled-frame").hover({position: {x: 10, y: 10}});
    const retiredFrameABox = await page.locator("#controlled-frame").boundingBox();
    assert.ok(retiredFrameABox, "controlled frame geometry must be available before wheel input");
    await page.dispatchEvent("#controlled-frame", "wheel", {
      deltaY: 120,
      clientX: retiredFrameABox.x + Math.min(20, retiredFrameABox.width / 2),
      clientY: retiredFrameABox.y + Math.min(20, retiredFrameABox.height / 2),
    });
    await page.evaluate(value => showSession(value), session(5, frameB));
    await waitForFrameTransition(frameB, 0, retiredFrameA, "Obsolete disposable input was discarded.");
    await page.evaluate(oldImage => oldImage.dispatchEvent(new Event("blur")), retiredFrameA);
    const frameBAfterLateBlur = await waitForFrameTransition(frameB, 0, retiredFrameA, "Obsolete disposable input was discarded.");
    assert.equal(frameBAfterLateBlur.eventSourceRetired, true);
    assert.equal(frameBAfterLateBlur.eventSourceCurrent, false);

    const retiredFrameB = await page.locator("#controlled-frame").elementHandle();
    await page.locator("#controlled-frame").click({position: {x: 20, y: 20}});
    await page.waitForFunction(() => Boolean(pendingClick));
    await page.evaluate(value => showSession(value), session(8, frameC));
    await waitForFrameTransition(frameC, 0, retiredFrameB, "meaningful unsent action must be repeated");
    await page.evaluate(oldImage => oldImage.dispatchEvent(new Event("blur")), retiredFrameB);
    const frameCAfterLateBlur = await waitForFrameTransition(frameC, 0, retiredFrameB, "meaningful unsent action must be repeated");
    assert.equal(frameCAfterLateBlur.directArmed, true);
    assert.equal(frameCAfterLateBlur.activeElementId, "controlled-frame");
    assert.equal(frameCAfterLateBlur.currentImageConnected, true);
    assert.equal(frameCAfterLateBlur.eventSourceRetired, true);
    assert.equal(frameCAfterLateBlur.eventSourceCurrent, false);
    assert.ok(Number.isInteger(frameCAfterLateBlur.bindingGeneration));
    await page.waitForTimeout(320);
    assert.equal(state.actions.length, 0, "cancelled meaningful input must never be replayed");
    await page.evaluate(() => {
      const root = document.getElementById("canvas");
      root.replaceChildren = root.__watchLearnOriginalReplaceChildren;
      delete root.__watchLearnOriginalReplaceChildren;
    });
    state.actionResponseEvidence = frameC;
    state.actionResponseVersion = 9;
    await dispatchMappedClick(frameC, {targetX: 45, targetY: 25});
    assert.equal(new Set(state.actions.map(item => item.idempotency_key)).size, 1);
    assert.deepEqual({
      revision: state.actions[0].action.frame_revision,
      width: state.actions[0].action.frame_width,
      height: state.actions[0].action.frame_height,
    }, {revision: frameC.sha256, width: frameC.width, height: frameC.height});
    assert.equal((await frameTransitionSnapshot()).bindingGeneration, frameCAfterLateBlur.bindingGeneration);
    const currentBlurDispatches = state.actions.length;
    await page.focus("#canvas-fit");
    await assertFocusLossDisarm(currentBlurDispatches, "current frame C blur");
    state.actionResponseEvidence = null;
    state.actionResponseVersion = null;

    // Repeated bounded transitions exercise delayed blur ordering without target dispatch.
    await load(page); await page.click("#arm-direct");
    let repeatedFrame = frameA;
    for (let index = 0; index < FRAME_RETIREMENT_REPETITIONS; index += 1) {
      const oldImage = await page.locator("#controlled-frame").elementHandle();
      const nextFrame = evidence(`repeat-frame-${index}-1234567890`, revision(String.fromCharCode(100 + index)));
      await page.evaluate(value => showSession(value), session(200 + index, nextFrame));
      await waitForFrameTransition(nextFrame, 0, oldImage);
      await page.evaluate(retiredImage => retiredImage.dispatchEvent(new Event("blur")), oldImage);
      const repeatedSnapshot = await waitForFrameTransition(nextFrame, 0, oldImage);
      assert.equal(repeatedSnapshot.eventSourceRetired, true);
      assert.equal(repeatedSnapshot.eventSourceCurrent, false);
      await oldImage.dispose();
      repeatedFrame = nextFrame;
    }
    assert.equal(state.actions.length, 0);
    assert.equal(await page.evaluate(() => canvasRecord.sha256), repeatedFrame.sha256);

    // Double-click and drag are each one meaningful dispatch.
    await load(page); await page.click("#arm-direct");
    await page.locator("#controlled-frame").dblclick({position: {x: 30, y: 20}, delay: 40});
    await waitFor(() => state.actions.length === 1);
    assert.equal(state.actions[0].action.clicks, 2);
    await load(page); await page.click("#arm-direct");
    const box = await page.locator("#controlled-frame").boundingBox();
    await page.mouse.move(box.x + 10, box.y + 10); await page.mouse.down();
    await page.mouse.move(box.x + 70, box.y + 35, {steps: 5}); await page.mouse.up();
    await waitFor(() => state.actions.length === 1);
    assert.equal(state.actions[0].action.kind, "drag");

    // Clipboard/composition/text are blocked only on the armed focused canvas; body input is never captured.
    await load(page); await page.click("#arm-direct");
    for (const type of ["paste", "beforeinput", "compositionstart", "drop"]) {
      assert.equal(await page.evaluate(kind => !document.getElementById("controlled-frame").dispatchEvent(new Event(kind, {bubbles: true, cancelable: true})), type), true);
    }
    await page.evaluate(() => document.body.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", code: "Enter", bubbles: true})));
    await page.waitForTimeout(50); assert.equal(state.actions.length, 0);

    // Image-load, dimension, geometry, focus, visibility, and pointer-capture failures fail closed.
    await page.evaluate(value => showSession(value), session(9, evidence("bad-frame-123456", revision("f"))));
    await page.waitForFunction(() => !directArmed && !canvasUpdating);
    assert.match(await page.textContent("#direct-state"), /failed|recovery|match/i);
    await load(page); await page.click("#arm-direct");
    await page.evaluate(value => showSession(value), session(2, evidence("dimension-frame-123456", revision("d"), 101, 50)));
    await page.waitForFunction(() => !directArmed && !canvasUpdating);
    assert.match(await page.textContent("#direct-state"), /metadata did not match|recovery/i);
    assert.equal(state.actions.length, 0);
    await load(page); await page.click("#arm-direct");
    await page.evaluate(() => {
      const image = document.getElementById("controlled-frame");
      image.getBoundingClientRect = () => ({left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0, toJSON() { return {}; }});
      image.dispatchEvent(new PointerEvent("pointerdown", {pointerId: 17, button: 0, clientX: 0, clientY: 0, bubbles: true, cancelable: true}));
    });
    assert.equal(await page.evaluate(() => directArmed), false);
    assert.equal(state.actions.length, 0);
    await load(page); await page.click("#arm-direct");
    await page.evaluate(() => window.dispatchEvent(new Event("blur")));
    assert.equal(await page.evaluate(() => directArmed), false);
    assert.match(await page.textContent("#direct-state"), /Browser focus was lost/i);
    assert.equal(state.actions.length, 0);
    await load(page); await page.click("#arm-direct");
    await page.evaluate(() => { Object.defineProperty(document, "hidden", {configurable: true, get: () => true}); document.dispatchEvent(new Event("visibilitychange")); });
    assert.equal(await page.evaluate(() => directArmed), false);
    await load(page); await page.click("#arm-direct");
    const pointerBox = await page.locator("#controlled-frame").boundingBox();
    await page.mouse.move(pointerBox.x + 10, pointerBox.y + 10); await page.mouse.down();
    const pointerId = await page.evaluate(() => pointerGesture.pointerId);
    await page.dispatchEvent("#controlled-frame", "lostpointercapture", {pointerId});
    assert.equal(await page.evaluate(() => directArmed), false);
    await page.mouse.up();

    // Emergency pause waits for the queue and disarms. Queue overflow is bounded.
    await load(page); await page.click("#arm-direct"); await page.click("#emergency-stop");
    await waitFor(() => state.pauseCount > 0); assert.equal(await page.evaluate(() => directArmed), false);
    await load(page); await page.evaluate(() => { for(let i=0;i<40;i+=1) void enqueueAction({schema_version:1,kind:"key",key:"TAB",phase:"press",modifiers:[],repeat:1}).catch(()=>{}); });
    await page.waitForTimeout(50); assert.equal(await page.evaluate(() => actionQueue.length <= ACTION_QUEUE_LIMIT), true);

    // Server stale/revision/uncertain outcomes dispatch once, never replay, and disarm.
    for (const mode of ["stale", "revision", "uncertain"]) {
      await load(page);
      const refreshesBefore = state.sessionRefreshes;
      state.mode = mode;
      await page.click("#arm-direct");
      await page.locator("#controlled-frame").click({position: {x: 20, y: 20}});
      await waitFor(() => state.actions.length === 1); await page.waitForTimeout(400);
      assert.equal(state.actions.length, 1); assert.equal(await page.evaluate(() => directArmed), false);
      assert.equal(
        state.sessionRefreshes,
        refreshesBefore + (mode === "uncertain" ? 0 : 1),
        `${mode} must perform exactly the expected faithful session refresh`,
      );
    }

      process.stdout.write("PASS: real Chromium Watch & Learn R2G frame-retirement, fullscreen convergence, initialization, and mock-completeness gate completed with local mocks only.\n");
    }

    await Promise.race([runGate(), fatalLatch.promise]);
  } catch (error) {
    primaryError = error;
  } finally {
    if (fatalLatch) fatalLatch.deactivate();
    detachFatalObservers();
    if (context) {
      try { await context.close(); } catch (error) { cleanupErrors.push(new Error(`context close failed: ${error.message}`)); }
    }
    if (browser) {
      try { await browser.close(); } catch (error) { cleanupErrors.push(new Error(`browser close failed: ${error.message}`)); }
    }
    if (server.listening) {
      try {
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      } catch (error) {
        cleanupErrors.push(new Error(`server close failed: ${error.message}`));
      }
    }
  }
  if (cleanupErrors.length) {
    for (const error of cleanupErrors) process.stderr.write(`CLEANUP_ERROR: ${error.message}\n`);
    if (!primaryError) throw new AggregateError(cleanupErrors, "Browser-gate cleanup failed");
  }
  if (primaryError) throw primaryError;
})().catch(error => {
  process.stderr.write(`FAIL: ${error.stack || error}\n`); process.exitCode = 1;
});
