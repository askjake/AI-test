"use strict";
// Production-JavaScript scenarios for the AWS credential status panel (stub DOM, fictional data, no network).
// Run: node --test tests/js/aws_ui.test.js   (from the repository root)
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const {load, flush, httpError, ROOT, FakeNode} = require("./procedure_ui_harness.js");

// The production panel sets element.style.*; the harness DOM has no style object.
if (!Object.getOwnPropertyDescriptor(FakeNode.prototype, "style")) {
  Object.defineProperty(FakeNode.prototype, "style", {get() { return this._style || (this._style = {}); }});
}

function region() {
  const html = fs.readFileSync(path.join(ROOT, "templates/dashboard/index.html"), "utf8");
  const a = html.indexOf("// <nrdp-aws>"), b = html.indexOf("// </nrdp-aws>");
  assert.ok(a > 0 && b > a, "AWS UI markers present");
  return html.slice(a, b);
}

const STATUS = {
  configured: true, provider: "shared credentials file, re-read on change", source_path: "/home/montjac/.aws/credentials", profile: "default", region: "us-west-2",
  state: "valid", expires_at_utc: "2026-10-28T21:00:00+00:00", expires_in_seconds: 1800, last_reload_ok_utc: "2026-10-28T20:31:00+00:00", last_failure: null,
  file: {exists: true, mtime_utc: "2026-10-28T20:30:00+00:00"}, model_id: "approved-profile", warnings: [], renewal_hint: "Renew the upstream login.", last_model_error: null,
  legend: [{category: "expired_token", label: "Expired credentials", meaning: "m1"}, {category: "access_denied", label: "Access denied", meaning: "m2"}],
};

function setup(status = STATUS) {
  const h = load();
  const badge = h.document.createElement("button"); badge.setAttribute("id", "aws-badge"); h.document.body.appendChild(badge);
  h.ctx.api = h.apiOp; h.ctx.localStorage = h.localStorage;
  h.apiOp.route("GET", /\/aws\/status$/, () => status);
  vm.runInContext(region(), h.ctx);
  return {h, badge};
}

test("the badge shows state and minutes left, and turns red when expired or missing", async () => {
  const {h, badge} = setup();
  await h.ctx.refreshAws(); await flush();
  assert.equal(badge.textContent, "AWS: valid · 30 min"); assert.equal(badge.dataset.state, "ok");
  const expired = setup(Object.assign({}, STATUS, {state: "expired", expires_in_seconds: -60}));
  await expired.h.ctx.refreshAws(); await flush();
  assert.equal(expired.badge.textContent, "AWS: EXPIRED"); assert.equal(expired.badge.dataset.state, "error");
  const unknown = setup(Object.assign({}, STATUS, {state: "unknown", expires_at_utc: null, expires_in_seconds: null}));
  await unknown.h.ctx.refreshAws(); await flush();
  assert.equal(unknown.badge.textContent, "AWS: expiry unknown"); assert.equal(unknown.badge.dataset.state, "warn");
  const off = setup({configured: false, state: "not-configured"});
  await off.h.ctx.refreshAws(); await flush();
  assert.equal(off.badge.textContent, "AWS: not configured");
});

test("opening the panel is read-only: it fetches status and makes no reload or model call", async () => {
  const {h} = setup();
  h.ctx.toggleAwsPanel(); await flush();
  const panel = h.document.getElementById("aws-panel");
  const text = panel.textContent;
  for (const needle of ["shared credentials file", "/home/montjac/.aws/credentials", "Profile: default", "Region: us-west-2", "Expires (UTC): 2026-10-28T21:00:00+00:00",
    "Last successful reload (UTC): 2026-10-28T20:31:00+00:00", "Model id: approved-profile", "Expired credentials — m1", "Access denied — m2"]) assert.ok(text.includes(needle), needle);
  assert.deepEqual(h.apiOp.calls.filter((c) => c.method !== "GET"), []);
  assert.equal(h.apiOp.calls.some((c) => /test-model/.test(c.path)), false);
});

test("unknown values are shown as 'unknown', never as blank or as a guess", async () => {
  const {h} = setup(Object.assign({}, STATUS, {state: "unknown", expires_at_utc: null, last_reload_ok_utc: null}));
  h.ctx.toggleAwsPanel(); await flush();
  const text = h.document.getElementById("aws-panel").textContent;
  assert.ok(text.includes("Expires (UTC): unknown")); assert.ok(text.includes("Last successful reload (UTC): unknown"));
});

test("last refresh failure, last model failure and warnings are shown distinctly", async () => {
  const {h} = setup(Object.assign({}, STATUS, {state: "expired", last_failure: {code: "incomplete", message: "The AWS credential file is incomplete.", at: "t1"},
    last_model_error: {category: "access_denied", label: "AWS denied access for the configured credentials, profile or model.", at: "t2"},
    warnings: ["The configured file is a one-time copy made during migration. Nothing renews it."]}));
  h.ctx.toggleAwsPanel(); await flush();
  const text = h.document.getElementById("aws-panel").textContent;
  assert.ok(text.includes("Last refresh failure: incomplete — The AWS credential file is incomplete.")); assert.ok(text.includes("Last model-call failure: AWS denied access"));
  assert.ok(text.includes("one-time copy"));
});

function buttons(panel) { return panel.all((n) => n.tagName === "BUTTON"); }

test("Reload credentials posts to the one reload endpoint and shows the result", async () => {
  const {h, badge} = setup();
  h.ctx.AUTH_SESSION = {role: "operator"};
  h.ctx.apiOp = h.apiOp;
  h.apiOp.route("POST", /\/aws\/reload$/, () => ({reloaded: true, changed: true, usable: true, reason: "reloaded", status: Object.assign({}, STATUS, {expires_in_seconds: 3500})}));
  h.ctx.toggleAwsPanel(); await flush();
  const panel = h.document.getElementById("aws-panel");
  buttons(panel).find((b) => b.textContent === "Reload credentials").onclick(); await flush();
  assert.equal(h.apiOp.calls.filter((c) => c.method === "POST").length, 1); assert.match(h.apiOp.calls.find((c) => c.method === "POST").path, /\/aws\/reload$/);
  assert.equal(badge.textContent, "AWS: valid · 58 min");
});

test("the model test needs confirmation, sends confirm:true once and shows the category", async () => {
  const declined = setup(); declined.h.ctx.confirm = () => false; declined.h.ctx.apiOp = declined.h.apiOp;
  declined.h.ctx.toggleAwsPanel(); await flush();
  buttons(declined.h.document.getElementById("aws-panel")).find((b) => /Test model/.test(b.textContent)).onclick(); await flush();
  assert.equal(declined.h.apiOp.calls.some((c) => /test-model/.test(c.path)), false);

  const {h} = setup(); h.ctx.confirm = () => true; h.ctx.apiOp = h.apiOp;
  h.apiOp.route("POST", /\/aws\/test-model$/, (call) => {
    assert.deepEqual(JSON.parse(call.body), {confirm: true});
    return {ok: false, category: "upstream_renewal_failed", message: "AWS credentials are expired and the configured credential file has not been renewed.", latency_ms: 12, status: STATUS};
  });
  h.ctx.toggleAwsPanel(); await flush();
  buttons(h.document.getElementById("aws-panel")).find((b) => /Test model/.test(b.textContent)).onclick(); await flush();
  const text = h.document.getElementById("aws-panel").textContent;
  assert.ok(text.includes("✘ AWS credentials are expired and the configured credential file has not been renewed.")); assert.ok(text.includes("upstream_renewal_failed"));
  assert.equal(h.apiOp.calls.filter((c) => /test-model/.test(c.path)).length, 1);
});

test("a status endpoint failure is shown as unavailable, not as valid", async () => {
  const h = load();
  const badge = h.document.createElement("button"); badge.setAttribute("id", "aws-badge"); h.document.body.appendChild(badge);
  h.ctx.api = async () => { throw httpError(500, "x"); };
  vm.runInContext(region(), h.ctx);
  await h.ctx.refreshAws(); await flush();
  assert.equal(badge.textContent, "AWS: unavailable"); assert.equal(badge.dataset.state, "error");
});
