"use strict";

const assert = require("node:assert/strict");

const LIFECYCLE_PATH = "/watch-learn-assets/lifecycle.js";

function parseUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch (_) {
    return new URL(rawUrl, "http://127.0.0.1");
  }
}

function pathWithQuery(rawUrl) {
  const parsed = parseUrl(rawUrl);
  return `${parsed.pathname}${parsed.search}`;
}

function requestDescription(request, status = "unavailable") {
  const rawUrl = request.url();
  const resourceType = typeof request.resourceType === "function" ? request.resourceType() : "unavailable";
  return `method=${request.method()} url=${rawUrl} path=${pathWithQuery(rawUrl)} status=${status} resource_type=${resourceType || "unavailable"}`;
}

function formatUnmatchedMockRoute(method, rawUrl) {
  return `UNMATCHED_MOCK_ROUTE method=${method} url=${rawUrl} path=${pathWithQuery(rawUrl)} status=404`;
}

function formatConsoleError(message) {
  const location = message.location() || {};
  return `Unexpected console error: ${message.text()}; location_url=${location.url || "unavailable"} line=${location.lineNumber ?? "unavailable"} column=${location.columnNumber ?? "unavailable"}`;
}

function formatRequestFailure(request, prefix = "Unexpected request failure") {
  const errorText = request.failure()?.errorText || "unknown error";
  return `${prefix}: ${requestDescription(request)} error=${errorText}`;
}

function serveExpectedFavicon(request, response, url) {
  if (request.method !== "GET" || url.pathname !== "/favicon.ico") return false;
  response.writeHead(204, {"content-type": "image/x-icon", "cache-control": "no-store"});
  response.end();
  return true;
}

function createFatalLatch() {
  let active = true;
  let reported = false;
  let rejectFatal;
  const promise = new Promise((_, reject) => { rejectFatal = reject; });
  return {
    promise,
    fail(error) {
      if (!active || reported) return;
      reported = true;
      rejectFatal(error instanceof Error ? error : new Error(String(error)));
    },
    deactivate() { active = false; },
    reported() { return reported; },
  };
}

function attachFatalObservers(page, failImmediately, lifecycleResponses, options = {}) {
  const isExpectedConsoleError = options.isExpectedConsoleError || (() => false);
  const onPageError = error => failImmediately(new Error(`Unexpected pageerror: ${error.message}`));
  const onConsole = message => {
    if (message.type() === "error" && !isExpectedConsoleError(message)) {
      failImmediately(new Error(formatConsoleError(message)));
    }
  };
  const onRequestFailed = request => {
    const lifecycle = parseUrl(request.url()).pathname === LIFECYCLE_PATH;
    failImmediately(new Error(formatRequestFailure(
      request,
      lifecycle ? "Lifecycle asset request failed" : "Unexpected request failure",
    )));
  };
  const onResponse = response => {
    const request = response.request();
    const lifecycle = parseUrl(response.url()).pathname === LIFECYCLE_PATH;
    if (lifecycle) lifecycleResponses.push(response);
    if (lifecycle && !response.ok()) {
      failImmediately(new Error(`Lifecycle asset returned non-success: ${requestDescription(request, response.status())}`));
      return;
    }
    if (response.status() === 404) {
      failImmediately(new Error(`Unexpected HTTP response: ${requestDescription(request, response.status())}`));
    }
  };
  page.on("pageerror", onPageError);
  page.on("console", onConsole);
  page.on("requestfailed", onRequestFailed);
  page.on("response", onResponse);
  return () => {
    page.off("pageerror", onPageError);
    page.off("console", onConsole);
    page.off("requestfailed", onRequestFailed);
    page.off("response", onResponse);
  };
}

async function installCspAndReadinessInstrumentation(page, failImmediately) {
  await page.exposeBinding("__watchLearnReportCspViolation", (_source, directive) => {
    failImmediately(new Error(`CSP violation: ${String(directive || "unknown directive")}`));
  });
  await page.addInitScript(() => {
    globalThis.__watchLearnCspViolationCount = 0;
    globalThis.__watchLearnReadyEventCount = 0;
    document.addEventListener("securitypolicyviolation", event => {
      globalThis.__watchLearnCspViolationCount += 1;
      void globalThis.__watchLearnReportCspViolation(event.violatedDirective);
    });
    document.addEventListener("watch-learn:ready", () => {
      globalThis.__watchLearnReadyEventCount += 1;
    });
  });
}

async function waitForInitialization(page, timeout = 5000) {
  try {
    await page.waitForFunction(
      () => document.documentElement.dataset.watchLearnInitialization === "ready",
      null,
      {timeout},
    );
  } catch (error) {
    throw new Error(`Watch & Learn initialization timeout: ${error.message}`);
  }
}

function assertSingleInitialization(snapshot) {
  assert.equal(snapshot.lifecycleRequestsAfter, snapshot.lifecycleRequestsBefore + 1, "lifecycle.js must be requested exactly once per page load");
  assert.equal(snapshot.lifecycleResponsesAfter, snapshot.lifecycleResponsesBefore + 1, "lifecycle.js must return exactly once per page load");
  assert.equal(snapshot.readyEventCount, 1, "watch-learn:ready must fire exactly once per page load");
}

module.exports = {
  LIFECYCLE_PATH,
  assertSingleInitialization,
  attachFatalObservers,
  createFatalLatch,
  formatConsoleError,
  formatRequestFailure,
  formatUnmatchedMockRoute,
  installCspAndReadinessInstrumentation,
  pathWithQuery,
  requestDescription,
  serveExpectedFavicon,
  waitForInitialization,
};
