#!/usr/bin/env node
"use strict";
// NRDP-1 procedure UI browser gate. Real Chromium + the production dashboard HTML on localhost.
// Every API response is a controlled local fixture (fictional TEST-NET hosts, example users,
// fictional passwords). No target, cloud, model, or run endpoint is contacted; any request to
// another origin is aborted and fails the gate. Label: MOCKED backend / real browser.
// Usage (repository root):  PLAYWRIGHT_CHROMIUM_PATH=/path/to/chrome node scripts/run_procedure_ui_browser_gate.js
const assert = require("node:assert/strict"), fs = require("node:fs"), http = require("node:http"), path = require("node:path");
const {execFileSync} = require("node:child_process");
const {chromium} = require(process.env.PROCEDURE_GATE_PLAYWRIGHT_MODULE || process.env.BUILDER_GATE_PLAYWRIGHT_MODULE || "playwright");
const root = path.resolve(__dirname, "..");
const exe = process.env.PLAYWRIGHT_CHROMIUM_PATH || chromium.executablePath();
if (!fs.existsSync(exe)) { console.error("BLOCKED: set PLAYWRIGHT_CHROMIUM_PATH to installed Chromium."); process.exit(78); }
const python = process.env.PROCEDURE_GATE_PYTHON || process.env.BUILDER_GATE_PYTHON || "python3";
let capabilities = [];
try {
  capabilities = JSON.parse(execFileSync(python, ["-c", "import json; from dashboard.builder_policy import TARGET_CAPABILITIES; print(json.dumps([x.model_dump(mode='json') for x in TARGET_CAPABILITIES]))"],
    {env: {...process.env, PYTHONPATH: path.join(root, "src")}, cwd: root}));
} catch (error) { console.error("WARN: capabilities unavailable; using an empty list (" + error.message.split("\n")[0] + ")"); }

const PW1 = "FICTIONAL-GATE-PW-one-91c2", PW2 = "FICTIONAL-GATE-PW-two-4be7", PW_NEW = "FICTIONAL-GATE-PW-new-0d55";
const ID = "d".repeat(32), PROJECT = "examplesvc-gate";
const FP = "sha256:" + "e".repeat(64);
const GOAL = ["RDP to 192.0.2.10", "example-operator", PW1,
  "From that desktop, open Windows Remote Desktop and RDP to 198.51.100.20", "example-service-admin", PW2,
  "1. Open PowerShell as administrator and confirm it is elevated.", "2. Stop-Service ExampleService and Start-Service ExampleService.", "3. Physically reseat the example cable."].join("\n");
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "base64");

const state = {host2: "198.51.100.20", cert: {state: "required", name: "", fingerprint: ""}, ref2: "procedure-dddd-hop2.pw", project: null,
  delayPutMs: 0, runs: {}, runSeq: 0, acked: {}, cancelled: {}};
function draft() {
  const certReady = state.cert.state === "reviewed";
  return {id: ID, title: "ExampleService service maintenance", status: "draft-only", schema_version: 2, final_hop: 2, execution_supported: true,
    connections: [
      {order: 1, protocol: "rdp", host: "192.0.2.10", port: 3389, user: "example-operator", label: "", opened_from: "runner desktop",
        credential: {state: "saved", reference: "procedure-dddd-hop1.pw"}, certificate: state.cert, identity_policy: "stop", predecessor: null},
      {order: 2, protocol: "rdp", host: state.host2, port: 3389, user: "example-service-admin", label: "", opened_from: "RDP desktop from hop 1",
        credential: {state: "saved", reference: state.ref2}, certificate: {state: "not_applicable", name: "", fingerprint: ""}, identity_policy: "stop", predecessor: 1}],
    steps: [
      {order: 1, title: "Check elevation", kind: "procedure-step", mutating: false, read_only_ok: true, instructions: "1. Open PowerShell as administrator and confirm it is elevated.", completion_checks: []},
      {order: 2, title: "Restart service", kind: "procedure-step", mutating: true, read_only_ok: false, instructions: "2. Stop-Service ExampleService and Start-Service ExampleService.", completion_checks: []},
      {order: 3, title: "Reseat cable", kind: "operator-checkpoint", mutating: true, read_only_ok: false, instructions: "3. Physically reseat the example cable.", completion_checks: []}],
    findings: ["Fixture finding."], manual: "# Fixture", project: state.project, last_test: null,
    readiness: {items: [{key: "connections", label: "2 connections in order", state: "known", detail: ""},
      {key: "certificate-1", label: "Reviewed certificate for connection 1", state: certReady ? "known" : "required", detail: ""},
      {key: "label-1", label: "Name for connection 1", state: "optional", detail: ""}]}};
}
function runView(id) {
  const r = state.runs[id]; r.polls++;
  const hops = (a, b) => [{order: 1, host: "192.0.2.10", user: "example-operator", status: a, detail: ""}, {order: 2, host: state.host2, user: "example-service-admin", status: b, detail: ""}];
  const ev = [{url: "/evidence/" + id + "/hop1.png", hop: 1, phase: "remote_desktop_ready", ts: "t1"}];
  if (state.cancelled[id]) return {run_id: id, mode: r.mode, status: "cancelled", chain_progress: {active_hop: 2, hops: hops("confirmed", "cancelled")}, evidence: ev};
  if (r.polls === 1) return {run_id: id, mode: r.mode, status: "running", chain_progress: {active_hop: 1, hops: hops("connecting", "pending")}, evidence: []};
  if (r.mode === "connection_test" && r.fail) return {run_id: id, mode: r.mode, status: "failed", chain_progress: {active_hop: 2, hops: hops("confirmed", "failed"), error: {hop: 2, code: "IDENTITY_UNCONFIRMED", message: "The final desktop could not be confirmed."}}, evidence: ev};
  if (r.mode === "connection_test") return {run_id: id, mode: r.mode, status: "passed", chain_progress: {active_hop: 2, hops: hops("confirmed", "confirmed")}, evidence: ev.concat([{url: "/evidence/" + id + "/hop2.png", hop: 2, phase: "remote_desktop_ready", ts: "t2"}])};
  if (r.mode === "full_run" && !state.acked[id]) return {run_id: id, mode: r.mode, status: "awaiting_checkpoint", chain_progress: {active_hop: 2, hops: hops("confirmed", "confirmed")}, evidence: ev,
    checkpoint: {id: "cp-" + id, step_order: 3, title: "Reseat cable", instructions: "Physically reseat the example cable.", requested_at: "t3"}};
  if (r.mode === "read_only_check" && r.hold) return {run_id: id, mode: r.mode, status: "running", chain_progress: {active_hop: 2, hops: hops("confirmed", "verifying")}, evidence: ev};
  return {run_id: id, mode: r.mode, status: "complete", chain_progress: {active_hop: 2, hops: hops("confirmed", "confirmed")}, evidence: ev};
}

const html = fs.readFileSync(path.join(root, "templates/dashboard/index.html"), "utf8").replace("\ninitializeAuthenticatedApp();", "\n// Offline gate supplies an operator session without authentication.");
const events = [], unexpected = [], errors = [];
let browser, server, failNextTest = true;
const P = "/api/v1/authoring/wizard/procedures";
async function main() {
  server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url, "http://127.0.0.1").pathname;
    if (pathname === "/" || pathname === "/favicon.ico") { res.setHeader("Content-Type", pathname === "/" ? "text/html" : "image/x-icon"); res.end(pathname === "/" ? html : ""); return; }
    if (/^\/evidence\/[\w-]+\/hop\d\.png$/.test(pathname)) { res.setHeader("Content-Type", "image/png"); res.end(PNG); return; }
    let raw = ""; for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : null;
    events.push({path: pathname, method: req.method, raw});
    let status = 200, result;
    if (pathname === "/api/v1/authoring/wizard/target-options") result = {hosts: {"ssh-terminal": [], rdp: [], vnc: []}, password_references: [], capabilities};
    else if (pathname === "/api/v1/projects") result = [];
    else if (pathname === P && req.method === "POST") result = draft();
    else if (pathname === P + "/" + ID && req.method === "GET") result = draft();
    else if (pathname === P + "/" + ID && req.method === "PUT") result = draft();
    else if (pathname === P + "/" + ID + "/connections" && req.method === "PUT") {
      if (state.delayPutMs) await new Promise((r) => setTimeout(r, state.delayPutMs));
      const hop2 = body.connections.find((c) => c.order === 2), hop1 = body.connections.find((c) => c.order === 1);
      if (!/^[A-Za-z0-9.-]+$/.test(hop2.host)) { status = 422; result = {errors: [{field: "connections[1].host", message: "Enter a valid host name or address."}]}; }
      else {
        state.host2 = hop2.host;
        if (hop2.new_password) state.ref2 = "procedure-dddd-hop2-r2.pw";
        if (hop1.certificate && hop1.certificate.fingerprint) state.cert = {state: "reviewed", name: hop1.certificate.name, fingerprint: hop1.certificate.fingerprint};
        result = draft();
      }
    } else if (pathname === P + "/" + ID + "/connections/1/certificate/probe" && req.method === "POST") result = {candidate: {name: "EXAMPLE-JUMP-01", fingerprint: FP}};
    else if (pathname === P + "/" + ID + "/project" && req.method === "POST") { state.project = {name: PROJECT, created_at: "t"}; result = {project_name: PROJECT, warnings: ["Hop 2 identity is confirmed only during a run."]}; }
    else if (pathname === P + "/" + ID + "/runs" && req.method === "POST") {
      const id = "run" + (++state.runSeq);
      state.runs[id] = {mode: body.mode, confirm: body.confirm_phrase, polls: 0, fail: body.mode === "connection_test" && failNextTest, hold: body.mode === "read_only_check"};
      if (body.mode === "connection_test") failNextTest = false;
      result = {run_id: id};
    } else if (/^\/api\/v1\/authoring\/wizard\/procedures\/d+\/runs\/run\d+$/.test(pathname) && req.method === "GET") result = runView(pathname.split("/").pop());
    else if (/\/runs\/run\d+\/checkpoint$/.test(pathname) && req.method === "POST") { state.acked[pathname.split("/").at(-2)] = body; result = {acknowledged: true}; }
    else if (/\/runs\/run\d+\/cancel$/.test(pathname) && req.method === "POST") { state.cancelled[pathname.split("/").at(-2)] = true; result = {cancelled: true}; }
    else { unexpected.push(req.method + " " + pathname); status = 500; result = {detail: "Forbidden/unmatched offline route"}; }
    res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(result));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  browser = await chromium.launch({executablePath: exe, headless: true, args: ["--no-sandbox", "--disable-gpu"]});
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  page.on("pageerror", (e) => errors.push(e.message)); page.on("dialog", (d) => d.accept());
  await page.route("**/*", (route) => { if (new URL(route.request().url()).origin !== origin) { unexpected.push("external-request"); return route.abort(); } return route.continue(); });
  await page.goto(origin);
  const storageClean = async (label) => {
    const dump = await page.evaluate(() => JSON.stringify({l: {...localStorage}, s: {...sessionStorage}}));
    for (const secret of [PW1, PW2, PW_NEW]) assert(!dump.includes(secret), label + ": browser storage contains a fictional password");
    assert(!dump.includes("Physically reseat"), label + ": browser storage contains raw goal text");
    return JSON.parse(dump);
  };
  const stateClean = async (label) => {
    const json = await page.evaluate(() => { const seen = new WeakSet(); return JSON.stringify(authoringState, (k, v) => { if (v instanceof Node) return undefined; if (v && typeof v === "object") { if (seen.has(v)) return undefined; seen.add(v); } return v; }); });
    for (const secret of [PW1, PW2, PW_NEW]) assert(!json.includes(secret), label + ": wizard state contains a fictional password");
  };

  await page.evaluate(() => { AUTH_SESSION = {role: "operator", csrf_token: "offline-test"}; openNewProjectDialog(); });
  await page.locator("#procedure-example summary").click();
  assert.match(await page.locator("#procedure-example pre").textContent(), /RDP to 192\.0\.2\.10\nusername: example-operator\npassword: Example-Only-Not-Real-1/);
  await page.locator("#wizard-intent").fill(GOAL);
  await storageClean("typed goal");
  await page.locator("#wizard-step1-continue").click();
  await page.locator('[data-testid="procedure-connection-2"]').waitFor();
  assert.deepEqual((await storageClean("after intake")).l["cookie-last-procedure-id"], ID);
  assert.equal(await page.evaluate(() => authoringState.wizardIntent), "");
  assert.equal(await page.locator('[data-testid="procedure-predecessor-1"]').textContent(), "Opened from: runner desktop");
  assert.equal(await page.locator('[data-testid="procedure-predecessor-2"]').textContent(), "Opened from the desktop of hop 1, using Windows Remote Desktop");
  assert.equal(await page.locator('[data-testid="procedure-credential-chip-2"]').textContent(), "Password: Saved");
  assert.equal(await page.locator('[data-testid="procedure-certificate-chip-1"]').textContent(), "Certificate: Required");
  assert.equal(await page.locator("#procedure-conn-2-password").getAttribute("autocomplete"), "new-password");
  assert.equal(await page.locator("#procedure-conn-2-password").isVisible(), false, "Replace password starts collapsed");
  console.log("PASS intake: ordered connections, chips, predecessor text, pointer-only storage, example format");

  await page.locator("#procedure-conn-2-edit summary").click();
  await page.locator("#procedure-conn-2-host").fill("bad host!");
  await page.locator("#procedure-next").click();
  await page.locator("#procedure-instructions").fill("1. Edited operating step.");
  await page.locator("#procedure-back-connections").click();
  assert.equal(await page.locator("#procedure-conn-2-host").inputValue(), "bad host!");
  await page.locator("#procedure-save-connections").click();
  await page.locator("#procedure-conn-2-host-error").filter({hasText: "Enter a valid host"}).waitFor();
  assert.equal(await page.locator("#procedure-conn-2-host").getAttribute("aria-invalid"), "true");
  console.log("PASS back/forward preserves edits; 422 error shown beside the field");

  await page.locator("#procedure-conn-2-host").fill("198.51.100.21");
  await page.locator("#procedure-conn-2-replace summary").click();
  await page.locator("#procedure-conn-2-password").fill(PW_NEW);
  await page.locator("#procedure-save-connections").click();
  await page.locator("#procedure-conn-status").filter({hasText: "Connections saved."}).waitFor();
  const put = events.filter((e) => e.path.endsWith("/connections")).at(-1);
  assert.equal(JSON.parse(put.raw).connections[1].new_password, PW_NEW);
  assert.equal(await page.locator("#procedure-conn-2-password").inputValue(), "");
  await storageClean("after password replace"); await stateClean("after password replace");
  console.log("PASS replace password: write-only, sent once, cleared, absent from state and storage");

  await page.locator("#procedure-cert-fetch-1").click();
  await page.locator("#procedure-cert-candidate-fingerprint-1").filter({hasText: FP}).waitFor();
  assert.equal(state.cert.state, "required", "probe alone never persists");
  await page.locator("#procedure-cert-use-1").click();
  await page.locator('[data-testid="procedure-certificate-chip-1"]').filter({hasText: "Certificate: Reviewed"}).waitFor();
  console.log("PASS certificate fetched for review and saved only on Use this certificate");

  await page.locator('[data-testid="procedure-stage-project"]').click();
  await page.locator("#procedure-create-project").click();
  await page.locator("#procedure-project-name").filter({hasText: "Project: " + PROJECT}).waitFor();
  assert.match(await page.locator("#procedure-project-warnings").textContent(), /confirmed only during a run/);
  await page.locator("#procedure-test-connection").click();
  await page.locator("#procedure-run-headline").filter({hasText: "Hop 1 of 2"}).waitFor();
  await page.locator("#procedure-run-error").filter({hasText: "Hop 2 (198.51.100.21): IDENTITY_UNCONFIRMED"}).waitFor({timeout: 15000});
  assert.equal(await page.locator('[data-testid="procedure-hop-2"]').getAttribute("aria-current"), "step");
  assert.match(await page.locator("#procedure-run-evidence figcaption").first().textContent(), /^Hop 1/);
  assert.equal(JSON.parse(events.find((e) => e.path.endsWith("/runs") && e.method === "POST").raw).mode, "connection_test");
  await page.locator("#procedure-run-retry").click();
  await page.locator("#procedure-run-status").filter({hasText: "passed"}).waitFor({timeout: 15000});
  const pollsAfter = events.filter((e) => /\/runs\/run2$/.test(e.path)).length;
  await page.waitForTimeout(4500);
  assert.equal(events.filter((e) => /\/runs\/run2$/.test(e.path)).length, pollsAfter, "polling stops at a terminal state");
  console.log("PASS test connection: hop-by-hop progress, highlighted failing hop, labelled screenshots, retry, polling stops");

  await page.locator("#procedure-run-mode").selectOption("full_run");
  assert.match(await page.locator("#procedure-run-warning").textContent(), /stop and start the service/);
  assert.equal(await page.locator("#procedure-run-start").isDisabled(), true);
  await page.locator("#procedure-run-confirm").fill(PROJECT);
  await page.locator("#procedure-run-start").click();
  await page.locator("#procedure-checkpoint-title").filter({hasText: "Reseat cable"}).waitFor({timeout: 15000});
  const runPost = events.filter((e) => e.path.endsWith("/runs") && e.method === "POST").at(-1);
  assert.deepEqual(JSON.parse(runPost.raw), {mode: "full_run", confirm_phrase: PROJECT});
  await page.waitForTimeout(5000);
  assert.equal(events.filter((e) => e.path.endsWith("/checkpoint")).length, 0, "checkpoint never auto-acknowledged");
  await page.locator("#procedure-checkpoint-note").fill("Reseated by the operator (fixture).");
  await page.locator("#procedure-checkpoint-ack").click();
  await page.locator("#procedure-run-status").filter({hasText: "complete"}).waitFor({timeout: 15000});
  assert.deepEqual(state.acked.run3, {id: "cp-run3", note: "Reseated by the operator (fixture)."});
  console.log("PASS full run: typed confirmation, checkpoint waits for the operator, ack posts once");

  await page.locator("#procedure-run-mode").selectOption("read_only_check");
  await page.locator("#procedure-run-start").click();
  await page.locator("#procedure-run-cancel").waitFor();
  await page.locator("#procedure-run-cancel").click();
  await page.locator("#procedure-run-status").filter({hasText: "cancelled"}).waitFor({timeout: 15000});
  console.log("PASS cancel run");

  await page.locator('[data-testid="procedure-stage-connections"]').click();
  // The edit panel stays open once the operator opened it; only click the summary when it is closed.
  if (!(await page.locator("#procedure-conn-2-edit").evaluate((d) => d.open))) await page.locator("#procedure-conn-2-edit summary").click();
  await page.locator("#procedure-conn-2-host").fill("198.51.100.55");
  state.delayPutMs = 1500;
  await page.locator("#procedure-save-connections").click();
  await page.locator("#procedure-start-fresh").click();
  await page.locator("#wizard-intent").waitFor();
  await page.waitForTimeout(2200);
  assert.equal(await page.evaluate(() => authoringState.procedureDraft), null, "stale PUT response did not repopulate the wizard");
  assert.equal(await page.locator("#wizard-intent").isVisible(), true);
  assert.equal((await storageClean("after start fresh")).l["cookie-last-procedure-id"], undefined);
  state.delayPutMs = 0;
  console.log("PASS Start fresh: wizard cleared, pointer cleared, stale async response dropped");

  await page.evaluate((id) => { localStorage.setItem("cookie-last-procedure-id", id); closeEditor(true); openNewProjectDialog(true); }, ID);
  await page.locator("#procedure-resume").click();
  await page.locator('[data-testid="procedure-project-create"]').waitFor();
  assert.equal(await page.locator('input[type="password"]:visible').count(), 0, "resume on the project stage asks for no password");
  await stateClean("after resume"); await storageClean("after resume");
  console.log("PASS resume without re-entering passwords");

  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  console.log("PROCEDURE_UI_BROWSER_GATE=PASS");
}
main().catch((e) => { console.error(e.stack); process.exitCode = 1; }).finally(async () => { if (browser) await browser.close(); if (server) await new Promise((resolve) => server.close(resolve)); });
