"use strict";

const assert = require("node:assert/strict");
const {EventEmitter} = require("node:events");
const test = require("node:test");

const {
  assertSingleInitialization,
  attachFatalObservers,
  createFatalLatch,
  formatUnmatchedMockRoute,
  installCspAndReadinessInstrumentation,
  serveExpectedFavicon,
  waitForInitialization,
} = require("../../scripts/watch_learn_r2_browser_gate_support.js");

function request(url, {method = "GET", resourceType = "fetch", failure = null} = {}) {
  return {
    url: () => url,
    method: () => method,
    resourceType: () => resourceType,
    failure: () => failure,
  };
}

function response(url, status, options = {}) {
  const related = request(url, options);
  return {
    url: () => url,
    status: () => status,
    ok: () => status >= 200 && status < 300,
    request: () => related,
  };
}

function observedPage(options = {}) {
  const page = new EventEmitter();
  const latch = createFatalLatch();
  const lifecycleResponses = [];
  const detach = attachFatalObservers(page, error => latch.fail(error), lifecycleResponses, options);
  return {page, latch, lifecycleResponses, detach};
}

test("unmatched mock route diagnostics include exact method, loopback URL, path, and status", () => {
  assert.equal(
    formatUnmatchedMockRoute("POST", "http://127.0.0.1:43123/unexpected/path?probe=1"),
    "UNMATCHED_MOCK_ROUTE method=POST url=http://127.0.0.1:43123/unexpected/path?probe=1 path=/unexpected/path?probe=1 status=404",
  );
});

test("a genuine unexpected 404 remains fatal with request and resource attribution", async () => {
  const observed = observedPage();
  observed.page.emit("response", response("http://127.0.0.1:43123/unexpected", 404, {method: "POST", resourceType: "xhr"}));
  await assert.rejects(
    observed.latch.promise,
    /Unexpected HTTP response: method=POST url=http:\/\/127\.0\.0\.1:43123\/unexpected path=\/unexpected status=404 resource_type=xhr/,
  );
  observed.detach();
});

test("the exact favicon request receives a deterministic no-store success", () => {
  const writes = [];
  const mockRequest = {method: "GET"};
  const mockResponse = {
    writeHead: (status, headers) => writes.push({status, headers}),
    end: value => writes.push({end: value}),
  };
  assert.equal(serveExpectedFavicon(mockRequest, mockResponse, new URL("http://127.0.0.1:43123/favicon.ico")), true);
  assert.deepEqual(writes, [
    {status: 204, headers: {"content-type": "image/x-icon", "cache-control": "no-store"}},
    {end: undefined},
  ]);
  assert.equal(serveExpectedFavicon({method: "POST"}, mockResponse, new URL("http://127.0.0.1:43123/favicon.ico")), false);
  assert.equal(serveExpectedFavicon(mockRequest, mockResponse, new URL("http://127.0.0.1:43123/nested/favicon.ico")), false);
});

test("a successful favicon response cannot trigger the fatal observer", async () => {
  const observed = observedPage();
  observed.page.emit("response", response("http://127.0.0.1:43123/favicon.ico", 204, {resourceType: "other"}));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(observed.latch.reported(), false);
  observed.detach();
  observed.latch.deactivate();
});

test("lifecycle-script 404 remains fatal and is recorded", async () => {
  const observed = observedPage();
  observed.page.emit("response", response("http://127.0.0.1:43123/watch-learn-assets/lifecycle.js", 404, {resourceType: "script"}));
  await assert.rejects(observed.latch.promise, /Lifecycle asset returned non-success: .*status=404 resource_type=script/);
  assert.equal(observed.lifecycleResponses.length, 1);
  observed.detach();
});

test("console errors include source location and remain fatal", async () => {
  const observed = observedPage();
  observed.page.emit("console", {
    type: () => "error",
    text: () => "synthetic console failure",
    location: () => ({url: "http://127.0.0.1:43123/watch-learn", lineNumber: 27, columnNumber: 9}),
  });
  await assert.rejects(observed.latch.promise, /location_url=http:\/\/127\.0\.0\.1:43123\/watch-learn line=27 column=9/);
  observed.detach();
});

test("an explicitly recognized conflict console error is ignored without weakening other errors", async () => {
  const observed = observedPage({
    isExpectedConsoleError: message => message.text() === "expected action conflict",
  });
  observed.page.emit("console", {
    type: () => "error",
    text: () => "expected action conflict",
    location: () => ({url: "http://127.0.0.1:43123/api/v1/demonstrations/session/actions"}),
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(observed.latch.reported(), false);
  observed.page.emit("console", {
    type: () => "error",
    text: () => "different console failure",
    location: () => ({url: "http://127.0.0.1:43123/watch-learn"}),
  });
  await assert.rejects(observed.latch.promise, /different console failure/);
  observed.detach();
});

test("page errors and request failures remain fatal with complete diagnostics", async t => {
  await t.test("pageerror", async () => {
    const observed = observedPage();
    observed.page.emit("pageerror", new Error("synthetic page failure"));
    await assert.rejects(observed.latch.promise, /Unexpected pageerror: synthetic page failure/);
    observed.detach();
  });
  await t.test("requestfailed", async () => {
    const observed = observedPage();
    observed.page.emit("requestfailed", request("http://127.0.0.1:43123/watch-learn-assets/lifecycle.js", {
      resourceType: "script",
      failure: {errorText: "net::ERR_FAILED"},
    }));
    await assert.rejects(observed.latch.promise, /Lifecycle asset request failed: .*path=\/watch-learn-assets\/lifecycle\.js.*resource_type=script error=net::ERR_FAILED/);
    observed.detach();
  });
});

test("CSP violations remain fatal and readiness instrumentation is payload-free", async () => {
  const latch = createFatalLatch();
  let binding;
  let initScript;
  const page = {
    exposeBinding: async (_name, callback) => { binding = callback; },
    addInitScript: async callback => { initScript = callback; },
  };
  await installCspAndReadinessInstrumentation(page, error => latch.fail(error));
  assert.match(initScript.toString(), /securitypolicyviolation/);
  assert.match(initScript.toString(), /watch-learn:ready/);
  binding({}, "script-src-elem");
  await assert.rejects(latch.promise, /CSP violation: script-src-elem/);
});

test("readiness timeout and duplicate or missing initialization remain fatal", async t => {
  await assert.rejects(
    waitForInitialization({waitForFunction: async () => { throw new Error("Timeout 25ms exceeded"); }}, 25),
    /Watch & Learn initialization timeout: Timeout 25ms exceeded/,
  );
  const valid = {
    lifecycleRequestsBefore: 4,
    lifecycleRequestsAfter: 5,
    lifecycleResponsesBefore: 4,
    lifecycleResponsesAfter: 5,
    readyEventCount: 1,
  };
  assert.doesNotThrow(() => assertSingleInitialization(valid));
  for (const invalid of [
    {...valid, lifecycleRequestsAfter: 4},
    {...valid, lifecycleRequestsAfter: 6},
    {...valid, lifecycleResponsesAfter: 4},
    {...valid, lifecycleResponsesAfter: 6},
    {...valid, readyEventCount: 0},
    {...valid, readyEventCount: 2},
  ]) {
    assert.throws(() => assertSingleInitialization(invalid));
  }
});

test("fatal observers can be detached and deactivated before browser cleanup", () => {
  const observed = observedPage();
  observed.detach();
  observed.latch.deactivate();
  observed.page.emit("console", {type: () => "error", text: () => "late", location: () => ({})});
  assert.equal(observed.latch.reported(), false);
});
