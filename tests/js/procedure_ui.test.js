"use strict";
// Production-JavaScript DOM scenarios for the NRDP procedure workflow (stub DOM, fictional data).
// Run: node --test tests/js/procedure_ui.test.js   (from the repository root)
const assert = require("node:assert/strict");
const test = require("node:test");
const {load, flush, fixtureDraft, httpError, deferred} = require("./procedure_ui_harness.js");

const PW = "FICTIONAL-PW-hop2-7f3a";
const ID = "a".repeat(32);
const base = "/authoring/wizard/procedures/" + ID;

function open(h, draft, stage) {
  h.ctx.renderFullProcedure(draft || fixtureDraft(), stage ? {stage} : {});
  return h.document.getElementById("wizard-content");
}
const plain = (x) => JSON.parse(JSON.stringify(x));
function byId(h, id) { return h.document.getElementById(id); }
function type(node, value) { node.value = value; node.dispatch(node.tagName === "SELECT" ? "change" : "input"); }
function stateJson(h) { return JSON.stringify(h.ctx.authoringState, (k, v) => (k === "ownerDocument" ? undefined : v)); }

test("v1 drafts are upgraded in memory with predecessor, chips and derived readiness", () => {
  const h = load();
  const d = h.ctx.ProcedureUi.normalizeDraft({id: "b".repeat(32), title: "T", connections: [
    {order: 1, host: "192.0.2.10", port: 3389, user: "u1", password_reference: "r1.pw", opened_from: "runner desktop"},
    {order: 2, host: "198.51.100.20", port: 3390, user: "u2", password_reference: "", opened_from: "RDP desktop from hop 1"}],
    steps: [{order: 1, title: "s", kind: "procedure-step", instructions: "x", completion_checks: []}], action_context_hop: 2, findings: [], manual: ""});
  assert.equal(d.final_hop, 2);
  assert.equal(h.ctx.ProcedureUi.predecessorText(d.connections[0]), "Opened from: runner desktop");
  assert.equal(h.ctx.ProcedureUi.predecessorText(d.connections[1]), "Opened from the desktop of hop 1, using Windows Remote Desktop");
  assert.equal(h.ctx.ProcedureUi.credentialChip(d.connections[0]).text, "Password: Saved");
  assert.equal(h.ctx.ProcedureUi.credentialChip(d.connections[1]).text, "Password: Missing");
  assert.equal(h.ctx.ProcedureUi.certificateChip(d.connections[0]).text, "Certificate: Required");
  assert.equal(h.ctx.ProcedureUi.certificateChip(d.connections[1]), null);
  const groups = h.ctx.ProcedureUi.readinessGroups(d);
  assert.deepEqual(plain(groups.required.map((i) => i.key).sort()), ["certificate-1", "credential-2"]);
  assert.equal(h.ctx.ProcedureUi.createReadiness(d, false).ok, false);
  assert.match(h.ctx.ProcedureUi.createReadiness(d, true).reason, /Save your connection changes/);
});

test("422 field errors map to order.field for both contract and FastAPI shapes", () => {
  const h = load(), d = h.ctx.ProcedureUi.normalizeDraft(fixtureDraft());
  const a = h.ctx.ProcedureUi.parseFieldErrors(httpError(422, {errors: [{field: "connections[1].host", message: "Bad host"}, {field: "connections[0].new_password", message: "Too long"}, {field: "other", message: "General"}]}), d);
  assert.deepEqual(plain(a.fields), {"2.host": "Bad host", "1.password": "Too long"});
  assert.deepEqual(plain(a.general), ["General"]);
  const b = h.ctx.ProcedureUi.parseFieldErrors(httpError(422, {detail: {errors: [{field: "connections[0].certificate.fingerprint", message: "Use sha256:"}]}}), d);
  assert.deepEqual(plain(b.fields), {"1.certificate_fingerprint": "Use sha256:"});
  const c = h.ctx.ProcedureUi.parseFieldErrors(httpError(422, {detail: [{loc: ["body", "connections", 1, "port"], msg: "Port range"}]}), d);
  assert.deepEqual(plain(c.fields), {"2.port": "Port range"});
  const e = h.ctx.ProcedureUi.parseFieldErrors(httpError(500, {detail: "Server unhappy"}), d);
  assert.deepEqual(plain(e.general), ["Server unhappy"]);
});

test("payload carries new_password only for the hop given and certificate only for hop 1", () => {
  const h = load(), d = h.ctx.ProcedureUi.normalizeDraft(fixtureDraft()), store = h.ctx.ProcedureUi.createEditStore();
  store.setField(d.id, 2, "host", "198.51.100.21");
  const p = h.ctx.ProcedureUi.buildConnectionsPayload(d, store, {2: PW}, {});
  assert.equal(p.connections[1].host, "198.51.100.21");
  assert.equal(p.connections[1].new_password, PW);
  assert.equal("new_password" in p.connections[0], false);
  assert.equal("certificate" in p.connections[1], false);
  const s = h.ctx.ProcedureUi.buildConnectionsPayload(d, store, null, {serverOnly: true, certificate: {order: 1, name: "JUMP-01", fingerprint: "sha256:" + "b".repeat(64)}});
  assert.equal(s.connections[1].host, "198.51.100.20", "certificate save never persists unsaved edits");
  assert.deepEqual(plain(s.connections[0].certificate), {name: "JUMP-01", fingerprint: "sha256:" + "b".repeat(64)});
});

// LIBRARY-LOGIC TEST: the confirmation-phrase rules still exist and are still correct, but they
// are only REACHABLE when the backend advertises the mode.  A permissive capability is supplied
// explicitly here; production advertises connection-only (next test).
test("full run requires the typed project name; read-only does not (capability permitting)", () => {
  const h = load(), U = h.ctx.ProcedureUi;
  const permissive = {connection_only: false, allowed_modes: ["connection_test", "read_only_check", "full_run"],
                      disabled_modes: [], reason: ""};
  assert.equal(U.runRequest("full_run", "proj-x", "proj", permissive).ok, false);
  assert.deepEqual(plain(U.runRequest("full_run", "proj-x", "proj-x", permissive).body), {mode: "full_run", confirm_phrase: "proj-x"});
  assert.deepEqual(plain(U.runRequest("read_only_check", "proj-x", "", permissive).body), {mode: "read_only_check"});
  assert.equal(U.runRequest("connection_test", "", "", permissive).ok, false);
  assert.equal(U.runRequest("rm -rf", "proj-x", "", permissive).ok, false);
});

// PRODUCTION-CAPABILITY TEST: what the shipped backend advertises, and what the UI must do when
// the capability is missing or unparsable.
test("connection-only capability disables operating modes and a missing capability fails closed", () => {
  const h = load(), U = h.ctx.ProcedureUi;
  const backend = {connection_only: true, allowed_modes: ["connection_test"],
                   disabled_modes: ["read_only_check", "full_run"], reason: "Connection tests only."};
  // the correct confirmation phrase cannot bypass the capability
  assert.equal(U.runRequest("full_run", "proj-x", "proj-x", backend).ok, false);
  assert.equal(U.runRequest("full_run", "proj-x", "proj-x", backend).reason, "Connection tests only.");
  assert.equal(U.runRequest("read_only_check", "proj-x", "", backend).ok, false);
  assert.deepEqual(plain(U.runRequest("connection_test", "proj-x", "", backend).body), {mode: "connection_test"});
  // FAIL CLOSED: missing, null, empty, partial or nonsense capability keeps operating modes off
  [undefined, null, {}, "nonsense", 7, {allowed_modes: []}, {connection_only: true}, {allowed_modes: "full_run"}].forEach((cap) => {
    assert.equal(U.runRequest("full_run", "proj-x", "proj-x", cap).ok, false, "full_run must stay refused");
    assert.equal(U.runRequest("read_only_check", "proj-x", "", cap).ok, false, "read_only_check must stay refused");
    assert.equal(U.modeAllowed(cap, "full_run"), false);
    assert.equal(U.modeAllowed(cap, "read_only_check"), false);
    assert.equal(U.modeAllowed(cap, "connection_test"), true, "connection tests remain available");
    const norm = U.runCapability(cap);
    assert.equal(norm.connection_only, true);
    assert.deepEqual(plain(norm.allowed_modes), ["connection_test"]);
    assert.ok(norm.reason.length > 0, "a refusal always carries an understandable reason");
  });
  // an explicit false is honoured (so the restriction can be lifted by the backend, not the UI)
  assert.equal(U.runCapability({connection_only: false, allowed_modes: ["full_run"]}).connection_only, false);
});

test("run progress: headline, current hop, error text, evidence labels and unsafe URLs dropped", () => {
  const h = load(), U = h.ctx.ProcedureUi, d = U.normalizeDraft(fixtureDraft());
  const run = U.normalizeRun({run_id: "r1", mode: "connection_test", status: "running", chain_progress: {active_hop: 2, hops: [{order: 1, status: "confirmed"}, {order: 2, status: "verifying"}]},
    evidence: [{url: "/evidence/r1/h1.png", hop: 1, phase: "ready"}, {url: "//evil.example/x.png", hop: 2}, {url: "javascript:alert(1)", hop: 2}, "/evidence/r1/h2.png"]});
  assert.equal(U.hopHeadline(run, d), "Hop 2 of 2 — Windows Remote Desktop inside 192.0.2.10");
  const rows = U.hopRows(run, d);
  assert.equal(rows[0].status, "confirmed"); assert.equal(rows[0].current, false);
  assert.equal(rows[1].current, true);
  assert.deepEqual(plain(run.evidence.map((e) => e.url)), ["/evidence/r1/h1.png", "/evidence/r1/h2.png"]);
  const failed = U.normalizeRun({status: "failed", chain_progress: {active_hop: 2, error: {hop: 2, code: "UNEXPECTED_IDENTITY_PROMPT", message: "Identity warning shown"}}});
  assert.equal(failed.terminal, true); assert.equal(failed.failed, true);
  assert.equal(U.errorText(failed, d), "Hop 2 (198.51.100.20): UNEXPECTED_IDENTITY_PROMPT — Identity warning shown");
});

test("poller: ~2 s cadence, error backoff, stop on terminal, isCurrent false, and stale in-flight responses dropped", async () => {
  const h = load(), U = h.ctx.ProcedureUi, seen = [], errors = [];
  let responses = [];
  const poller = U.createRunPoller({setTimer: h.timers.setTimeout, clearTimer: h.timers.clearTimeout,
    fetchRun: () => { const r = responses.shift(); return r instanceof Error ? Promise.reject(r) : Promise.resolve(r); },
    onUpdate: (raw) => { const run = U.normalizeRun(raw); seen.push(run.status); return run; }, onError: (e, final) => errors.push(final)});
  let current = true;
  responses = [{status: "running"}, new Error("x"), {status: "running"}, {status: "complete"}];
  poller.start("r1", () => current); await flush();
  assert.deepEqual(h.timers.pending().map((t) => t.ms), [2000]);
  h.timers.runAll(); await flush();
  assert.deepEqual(h.timers.pending().map((t) => t.ms), [4000], "first error backs off");
  h.timers.runAll(); await flush();
  assert.deepEqual(h.timers.pending().map((t) => t.ms), [2000], "success resets cadence");
  h.timers.runAll(); await flush();
  assert.deepEqual(seen, ["running", "running", "complete"]);
  assert.equal(h.timers.pending().length, 0, "terminal stops polling");
  assert.equal(poller.isActive(), false);
  // isCurrent false (navigation / Start fresh) stops before applying
  responses = [{status: "running"}, {status: "running"}];
  poller.start("r2", () => current); await flush();
  current = false; h.timers.runAll(); await flush();
  assert.equal(seen.length, 4); assert.equal(h.timers.pending().length, 0);
  // stale in-flight response after stop() is dropped
  current = true; const late = deferred();
  const p2 = U.createRunPoller({setTimer: h.timers.setTimeout, clearTimer: h.timers.clearTimeout, fetchRun: () => late.promise,
    onUpdate: (raw) => { seen.push("LATE"); return U.normalizeRun(raw); }, onError: () => {}});
  p2.start("r3", () => true); p2.stop(); late.resolve({status: "running"}); await flush();
  assert.equal(seen.includes("LATE"), false);
  // repeated errors stop with a final error
  const p3 = U.createRunPoller({setTimer: h.timers.setTimeout, clearTimer: h.timers.clearTimeout, fetchRun: () => Promise.reject(new Error("down")),
    onUpdate: () => null, onError: (e, final) => errors.push(final), maxErrors: 3});
  p3.start("r4", () => true); await flush(); h.timers.runAll(); await flush(); h.timers.runAll(); await flush();
  assert.equal(errors.at(-1), true); assert.equal(h.timers.pending().length, 0);
});

test("connection cards render escaped text, chips, predecessor and write-only password inputs", () => {
  const h = load();
  const draft = fixtureDraft();
  draft.connections[1].user = "<img src=x onerror=alert(1)>";
  const root = open(h, draft);
  assert.equal(root.innerHTMLWrites, 0, "no innerHTML writes in the procedure workspace");
  assert.equal(root.byTestId("procedure-user-2").textContent, "<img src=x onerror=alert(1)>");
  assert.equal(root.byTestId("procedure-predecessor-2").textContent, "Opened from the desktop of hop 1, using Windows Remote Desktop");
  assert.equal(root.byTestId("procedure-credential-chip-1").textContent, "Password: Saved");
  assert.equal(root.byTestId("procedure-certificate-chip-1").textContent, "Certificate: Required");
  assert.equal(root.byTestId("procedure-certificate-chip-2"), null);
  const pw = byId(h, "procedure-conn-2-password");
  assert.equal(pw.getAttribute("type"), "password");
  assert.equal(pw.getAttribute("autocomplete"), "new-password");
  assert.equal(byId(h, "procedure-conn-2-replace").open, false, "Replace password is collapsed");
  assert.equal(byId(h, "procedure-conn-2-edit").open, false, "Edit is collapsed");
  const stages = h.document.getElementById("wizard-stepper").children.map((b) => b.textContent);
  assert.deepEqual(stages, ["1. Connections", "2. Procedure", "3. Review", "4. Project", "Start fresh"]);
  assert.deepEqual(h.localStorage.dump(), {});
});

test("back/forward preserves unsaved edits; resume of the same draft does not overwrite them", async () => {
  const h = load();
  open(h);
  type(byId(h, "procedure-conn-2-host"), "198.51.100.99");
  type(byId(h, "procedure-conn-2-identity_policy"), "accept_reviewed_prompt");
  byId(h, "procedure-next").click();
  type(byId(h, "procedure-instructions"), "1. Edited step");
  byId(h, "procedure-back-connections").click();
  assert.equal(byId(h, "procedure-conn-2-host").value, "198.51.100.99");
  assert.equal(byId(h, "procedure-conn-2-identity_policy").children.find((o) => o.selected).value, "accept_reviewed_prompt");
  h.ctx.showProcedureStage("procedure");
  assert.equal(byId(h, "procedure-instructions").value, "1. Edited step");
  // Simulate close + Resume (server returns the old values) — edits survive.
  h.localStorage.setItem("cookie-last-procedure-id", ID);
  h.apiOp.route("GET", new RegExp("^" + base + "$"), () => fixtureDraft());
  h.ctx.closeEditor(true);
  await h.ctx.reopenFullProcedure(); await flush();
  assert.equal(h.ctx.authoringState.procedureStage, "connections");
  assert.equal(byId(h, "procedure-conn-2-host").value, "198.51.100.99");
  assert.match(byId(h, "procedure-conn-status").textContent, /Unsaved changes/);
  assert.equal(byId(h, "procedure-conn-1-password").value, "", "resume never asks for or fills a password");
});

test("save connections: 422 shows errors beside fields; password cleared and never stored", async () => {
  const h = load();
  open(h);
  type(byId(h, "procedure-conn-2-host"), "bad host!");
  byId(h, "procedure-conn-2-password").value = PW;
  h.apiOp.route("PUT", new RegExp("^" + base + "/connections$"), () => { throw httpError(422, {errors: [{field: "connections[1].host", message: "Enter a valid host name or address."}]}); });
  const pending = h.ctx.procedureSaveConnections();
  assert.equal(byId(h, "procedure-conn-2-password").value, "", "cleared at submit time");
  await pending; await flush();
  const call = h.apiOp.calls.at(-1);
  assert.equal(call.method, "PUT");
  assert.equal(JSON.parse(call.body).connections[1].new_password, PW);
  assert.equal(byId(h, "procedure-conn-2-host-error").textContent, "Enter a valid host name or address.");
  assert.equal(byId(h, "procedure-conn-2-host-error").hidden, false);
  assert.equal(byId(h, "procedure-conn-2-host").getAttribute("aria-invalid"), "true");
  assert.equal(byId(h, "procedure-conn-2-edit").open, true, "Edit opens to show the error");
  assert.equal(byId(h, "procedure-conn-2-host").value, "bad host!", "edit kept after 422");
  assert.equal(byId(h, "procedure-conn-2-password").value, "");
  assert.equal(stateJson(h).includes(PW), false);
  assert.equal(JSON.stringify(h.localStorage.dump()).includes(PW), false);
  assert.equal(h.sessionStorage.length, 0);
  // Success clears edits and errors and uses the server draft.
  h.apiOp.route("PUT", new RegExp("^" + base + "/connections$"), (c) => { const d = fixtureDraft(); d.connections[1].host = JSON.parse(c.body).connections[1].host; return d; });
  type(byId(h, "procedure-conn-2-host"), "198.51.100.30");
  await h.ctx.procedureSaveConnections(); await flush();
  assert.equal(byId(h, "procedure-conn-2-host").value, "198.51.100.30");
  assert.equal(byId(h, "procedure-conn-2-host-error").hidden, true);
  assert.equal(byId(h, "procedure-conn-status").textContent, "Connections saved.");
  assert.equal(h.ctx.authoringState.procedureEdits.dirtyConnections(ID, h.ctx.authoringState.procedureDraft), false);
});

test("certificate: fetch shows a candidate for review; only Use this certificate PUTs it", async () => {
  const h = load();
  open(h);
  const fp = "sha256:" + "c".repeat(64);
  h.apiOp.route("POST", new RegExp("^" + base + "/connections/1/certificate/probe$"), () => ({candidate: {name: "JUMP-01", fingerprint: fp}}));
  h.apiOp.route("PUT", new RegExp("^" + base + "/connections$"), () => { const d = fixtureDraft(); d.connections[0].certificate = {state: "reviewed", name: "JUMP-01", fingerprint: fp}; d.readiness.items[1].state = "known"; return d; });
  byId(h, "procedure-cert-fetch-1").click(); await flush();
  assert.equal(byId(h, "procedure-cert-candidate-fingerprint-1").textContent, fp);
  assert.equal(h.apiOp.calls.filter((c) => c.method === "PUT").length, 0, "probe never persists");
  byId(h, "procedure-cert-use-1").click(); await flush();
  const put = h.apiOp.calls.find((c) => c.method === "PUT");
  assert.deepEqual(JSON.parse(put.body).connections[0].certificate, {name: "JUMP-01", fingerprint: fp});
  assert.equal(h.document.getElementById("wizard-content").byTestId("procedure-certificate-chip-1").textContent, "Certificate: Reviewed");
});

test("Start fresh drops stale async results, clears the pointer and keeps server data untouched", async () => {
  const h = load();
  h.localStorage.setItem("cookie-last-procedure-id", ID);
  open(h);
  type(byId(h, "procedure-conn-2-host"), "198.51.100.77");
  const slow = deferred();
  h.apiOp.route("PUT", new RegExp("^" + base + "/connections$"), () => slow.promise);
  const pending = h.ctx.procedureSaveConnections();
  byId(h, "procedure-start-fresh").click();
  assert.equal(h.ctx.authoringState.procedureDraft, null);
  assert.equal(h.localStorage.getItem("cookie-last-procedure-id"), null);
  slow.resolve(fixtureDraft({title: "STALE"})); await pending; await flush();
  assert.equal(h.ctx.authoringState.procedureDraft, null, "stale response did not repopulate the wizard");
  assert.equal(h.document.getElementById("wizard-content").textContent, "step-1");
  assert.deepEqual(plain(h.ctx.authoringState.procedureEdits.snapshot()), {});
  assert.equal(h.apiOp.calls.some((c) => c.method === "DELETE"), false, "no server-side deletion");
  // A stale intake response after Start fresh is also dropped.
  const h2 = load(); const intake = deferred();
  const input = h2.document.createElement("textarea"); input.setAttribute("id", "wizard-intent"); input.value = "RDP to 192.0.2.10\nexample-operator\n" + PW; h2.document.body.appendChild(input);
  const button = h2.document.createElement("button"); button.setAttribute("id", "wizard-step1-continue"); h2.document.body.appendChild(button);
  h2.apiOp.route("POST", /^\/authoring\/wizard\/procedures$/, () => intake.promise);
  const run = h2.ctx.buildFullProcedure(); h2.ctx.authoringState.wizardEpoch += 1; intake.resolve(fixtureDraft()); await run; await flush();
  assert.equal(h2.ctx.authoringState.procedureDraft, null);
  assert.equal(h2.localStorage.getItem("cookie-last-procedure-id"), null);
  assert.equal(input.value, "", "goal textarea cleared after successful intake");
});

test("intake stores only the draft id; goal text and passwords never reach storage", async () => {
  const h = load();
  const input = h.document.createElement("textarea"); input.setAttribute("id", "wizard-intent"); input.value = "RDP to 192.0.2.10\nexample-operator\n" + PW + "\n1. Check"; h.document.body.appendChild(input);
  const button = h.document.createElement("button"); button.setAttribute("id", "wizard-step1-continue"); h.document.body.appendChild(button);
  h.apiOp.route("POST", /^\/authoring\/wizard\/procedures$/, () => fixtureDraft());
  await h.ctx.buildFullProcedure(); await flush();
  assert.deepEqual(h.localStorage.dump(), {"cookie-last-procedure-id": ID});
  assert.equal(h.sessionStorage.length, 0);
  assert.equal(stateJson(h).includes(PW), false);
  assert.equal(input.value, "");
});

test("project stage: create disabled with reason, then create, test connection, checkpoint, cancel", async () => {
  const h = load();
  open(h, fixtureDraft(), "project");
  const create = byId(h, "procedure-create-project");
  assert.equal(create.disabled, true);
  assert.match(byId(h, "procedure-create-reason").textContent, /Still required: Reviewed certificate for connection 1/);
  assert.equal(byId(h, "procedure-test-connection").disabled, true);
  // Readiness satisfied.
  const ready = fixtureDraft(); ready.readiness.items[1].state = "known";
  h.ctx.renderFullProcedure(ready, {stage: "project"});
  assert.equal(byId(h, "procedure-create-project").disabled, false);
  h.apiOp.route("POST", new RegExp("^" + base + "/project$"), () => ({project_name: "examplesvc-maint", warnings: ["Hop 2 identity is confirmed only at run time."]}));
  byId(h, "procedure-create-project").click(); await flush();
  assert.equal(byId(h, "procedure-project-name").textContent, "Project: examplesvc-maint");
  assert.equal(byId(h, "procedure-project-warnings").children[0].textContent, "Hop 2 identity is confirmed only at run time.");
  // Test connection with polling.
  let polls = 0;
  const states = [
    {run_id: "run1", mode: "connection_test", status: "running", chain_progress: {active_hop: 1, hops: [{order: 1, status: "connecting"}, {order: 2, status: "pending"}]}},
    {run_id: "run1", mode: "connection_test", status: "running", chain_progress: {active_hop: 2, hops: [{order: 1, status: "confirmed"}, {order: 2, status: "verifying"}]}, evidence: [{url: "/evidence/run1/hop1.png", hop: 1, phase: "remote_desktop_ready"}]},
    {run_id: "run1", mode: "connection_test", status: "failed", chain_progress: {active_hop: 2, hops: [{order: 1, status: "confirmed"}, {order: 2, status: "failed"}], error: {hop: 2, code: "IDENTITY_UNCONFIRMED", message: "Final desktop not confirmed"}}},
  ];
  h.apiOp.route("POST", new RegExp("^" + base + "/runs$"), () => ({run_id: "run1"}));
  h.apiOp.route("GET", new RegExp("^" + base + "/runs/run1$"), () => states[Math.min(polls++, states.length - 1)]);
  byId(h, "procedure-test-connection").click(); await flush();
  assert.deepEqual(JSON.parse(h.apiOp.calls.find((c) => c.path === base + "/runs").body), {mode: "connection_test"});
  assert.equal(byId(h, "procedure-run-headline").textContent, "Hop 1 of 2 — Remote Desktop from the runner to 192.0.2.10");
  assert.equal(byId(h, "procedure-hop-list").children[0].getAttribute("aria-current"), "step");
  assert.equal(byId(h, "procedure-test-connection").disabled, true, "no second run while one is active");
  h.timers.runAll(); await flush();
  assert.equal(byId(h, "procedure-run-headline").textContent, "Hop 2 of 2 — Windows Remote Desktop inside 192.0.2.10");
  assert.equal(byId(h, "procedure-run-evidence").children[0].children[1].textContent, "Hop 1 · remote_desktop_ready");
  h.timers.runAll(); await flush();
  assert.equal(byId(h, "procedure-run-error").textContent, "Hop 2 (198.51.100.20): IDENTITY_UNCONFIRMED — Final desktop not confirmed");
  assert.equal(h.timers.pending().length, 0, "polling stopped at the terminal state");
  assert.ok(byId(h, "procedure-run-retry"), "Retry offered after failure");
  // CONNECTION-ONLY QUALIFICATION: the fixture draft carries no run_capability, so the UI falls
  // back to connection-only and the operating controls must be unavailable.  Even a passed,
  // current connection test does not unlock them, and the confirmation input is not offered.
  assert.equal(byId(h, "procedure-run-mode").disabled, true, "the mode select is disabled");
  assert.match(byId(h, "procedure-connection-only").textContent, /connection tests only/i);
  assert.equal(byId(h, "procedure-run-confirm"), null, "no confirmation input is rendered");
  assert.equal(byId(h, "procedure-run-warning"), null, "no full-run warning is rendered");
  assert.equal(byId(h, "procedure-run-start").disabled, true);
  h.ctx.authoringState.procedureDraft.last_test = {run_id: "run0", mode: "connection_test", status: "passed", at: "t", current: true};
  h.ctx.renderWizardContent();
  assert.equal(byId(h, "procedure-run-start").disabled, true, "a passed current test still does not unlock an operating run");
  assert.equal(byId(h, "procedure-run-confirm"), null);
  assert.match(byId(h, "procedure-run-reason").textContent, /connection tests only/i);
  // Checkpoint and cancel are mode-independent UI behaviour: drive them through a connection test.
  const cpRun = {run_id: "run2", mode: "connection_test", status: "awaiting_checkpoint", chain_progress: {active_hop: 2, hops: [{order: 1, status: "confirmed"}, {order: 2, status: "confirmed"}]},
    checkpoint: {id: "cp-3", step_order: 3, title: "Swap cable", instructions: "Physically reseat the example cable.", requested_at: "t"}};
  h.apiOp.route("POST", new RegExp("^" + base + "/runs$"), () => ({run_id: "run2"}));
  h.apiOp.route("GET", new RegExp("^" + base + "/runs/run2$"), () => cpRun);
  h.apiOp.route("POST", new RegExp("^" + base + "/runs/run2/checkpoint$"), () => ({ok: true}));
  h.apiOp.route("POST", new RegExp("^" + base + "/runs/run2/cancel$"), () => ({ok: true}));
  byId(h, "procedure-test-connection").click(); await flush();
  assert.deepEqual(JSON.parse(h.apiOp.calls.filter((c) => c.path === base + "/runs").at(-1).body), {mode: "connection_test"});
  assert.equal(byId(h, "procedure-checkpoint-title").textContent, "Swap cable");
  h.timers.runAll(); await flush(); h.timers.runAll(); await flush();
  assert.equal(h.apiOp.calls.filter((c) => c.path.endsWith("/checkpoint")).length, 0, "never auto-acknowledged");
  type(byId(h, "procedure-checkpoint-note"), "Reseated by operator");
  byId(h, "procedure-checkpoint-ack").click(); await flush();
  const ack = h.apiOp.calls.filter((c) => c.path.endsWith("/checkpoint"));
  assert.equal(ack.length, 1);
  assert.deepEqual(JSON.parse(ack[0].body), {id: "cp-3", note: "Reseated by operator"});
  assert.equal(byId(h, "procedure-checkpoint-ack").disabled, true);
  byId(h, "procedure-checkpoint-ack").click(); await flush();
  assert.equal(h.apiOp.calls.filter((c) => c.path.endsWith("/checkpoint")).length, 1, "no duplicate ack");
  byId(h, "procedure-run-cancel").click(); await flush();
  assert.equal(h.apiOp.calls.filter((c) => c.path.endsWith("/cancel")).length, 1);
  // Navigating away stops polling.
  h.ctx.showProcedureStage("review");
  assert.equal(h.timers.pending().length, 0);
  h.timers.runAll(); await flush();
  assert.deepEqual(Object.keys(h.localStorage.dump()), []);
});


test("run headline for a VNC hop names the VNC viewer and the SSH tunnel, never Remote Desktop", () => {
  const h = load(), U = h.ctx.ProcedureUi;
  const vnc = U.normalizeDraft(fixtureDraft({
    connections: [{order: 1, protocol: "vnc", host: "192.0.2.47", port: 5902, display: 2, user: "", label: "", opened_from: "runner (VNC viewer) through the SSH gateway",
      credential: {state: "saved", reference: "procedure-aaaa-hop1.vnc.pw"}, certificate: {state: "required", name: "", fingerprint: ""}, identity_policy: "stop", auth_method: "vnc-password"}],
    gateway: {host: "192.0.2.10", port: 22, user: "gwuser", route: "ssh-jump", credential: {state: "saved", reference: "g.pw"}, host_key: {state: "approved"}},
  }));
  const run = U.normalizeRun({run_id: "r1", mode: "connection_test", status: "running", chain_progress: {active_hop: 1, hops: [{order: 1, status: "connecting"}]}});
  const headline = U.hopHeadline(run, vnc);
  assert.equal(headline, "Hop 1 of 1 — VNC viewer from the runner through the SSH tunnel to 192.0.2.47:2");
  assert.ok(!/Remote Desktop/.test(headline));
  const direct = U.normalizeDraft(fixtureDraft({connections: [Object.assign({}, vnc.connections[0])], gateway: null}));
  assert.equal(U.hopHeadline(run, direct), "Hop 1 of 1 — VNC viewer from the runner to 192.0.2.47:2");
});
