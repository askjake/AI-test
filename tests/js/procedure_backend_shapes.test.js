"use strict";
// The browser code, fed with REAL backend responses recorded by tests/test_procedure_backend_shapes.py
// (fixtures/backend_shapes.json).  Nothing here is an independently invented response shape.
// Run: node --test tests/js/procedure_backend_shapes.test.js   (from the repository root)
const assert = require("node:assert/strict");
const test = require("node:test");
const fixture = require("./fixtures/backend_shapes.json");
const {load, flush} = require("./procedure_ui_harness.js");

const U = () => load().ctx.ProcedureUi;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("D2/D3: a reviewed hop-1 certificate and the server readiness list reach the UI as the backend sent them", () => {
  const ui = U();
  const fresh = ui.normalizeDraft(fixture.view_new);
  assert.equal(fresh.connections[0].certificate.state, "required");
  assert.equal(fresh.connections[1].certificate.state, "not_applicable");
  assert.equal(fresh.readiness.derived, false, "the server readiness is used, not a client guess");
  const reviewed = ui.normalizeDraft(fixture.view_cert_reviewed);
  assert.equal(reviewed.connections[0].certificate.state, "reviewed");
  assert.equal(reviewed.connections[0].certificate.name, "WIN-HOP1");
  assert.match(reviewed.connections[0].certificate.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(ui.certificateChip(reviewed.connections[0]).text, "Certificate: Reviewed");
  assert.equal(reviewed.readiness.derived, false);
  assert.ok(!reviewed.readiness.items.some((i) => i.key === "certificate-1" && i.state === "required"));
  assert.equal(reviewed.connections[1].predecessor, 1);
});

test("D4: the project survives a reload under project.name, and goes stale when connections change", () => {
  const ui = U();
  const after = ui.normalizeDraft(fixture.view_project);
  assert.ok(after.project && after.project.name, "resume keeps the project association");
  assert.equal(after.project.current, true);
  assert.equal(ui.normalizeDraft(fixture.view_new).project, null);
  const edited = ui.normalizeDraft(fixture.view_after_edit);
  assert.equal(edited.project.current, false);
  assert.equal(edited.last_test, null, "editing a connection clears the connection test");
  const tested = ui.normalizeDraft(fixture.view_after_test);
  assert.equal(tested.last_test.status, "passed");
  assert.equal(tested.last_test.current, true);
});

test("D1: backend run statuses are plain strings; running keeps polling, complete/cancelled stop", () => {
  const ui = U();
  const running = ui.normalizeRun(fixture.run_running);
  assert.equal(running.status, "running");
  assert.equal(running.terminal, false);
  assert.ok(!JSON.stringify(running).includes("[object"));
  const done = ui.normalizeRun(fixture.run_complete);
  assert.equal(done.status, "complete");
  assert.equal(done.terminal, true);
  assert.equal(done.failed, false);
  assert.deepEqual(plain(done.hops.map((h) => h.status)), ["confirmed", "confirmed"]);
  assert.equal(done.evidence.length, 1);
  assert.equal(done.evidence[0].hop, 2);
  assert.match(done.evidence[0].url, /^\/reports\//);
  const cancelled = ui.normalizeRun(fixture.run_cancelled);
  assert.equal(cancelled.status, "cancelled");
  assert.equal(cancelled.terminal, true, "a hard-stopped run no longer polls forever");
  assert.equal(cancelled.failed, true);
  assert.equal(cancelled.checkpoint, null);
});

test("R2: a downgraded run is shown as what it really was", () => {
  const ui = U();
  const run = ui.normalizeRun(fixture.run_downgraded);
  // The structured fields carry the contract: the operating mode that was asked for is kept, the mode
  // that actually ran is the connection test, and the downgrade is explicit rather than silent.
  assert.equal(run.downgraded, true);
  assert.equal(run.requested_mode, "full_run");
  assert.equal(run.effective_mode, "connection_test");
  assert.notEqual(run.requested_mode, run.effective_mode, "a downgrade means the two modes differ");
  // The reason must exist and say why (this build qualifies connection tests only).  Only the stable
  // "connection-only" phrase is matched, not the rest of the sentence.
  assert.equal(typeof run.downgrade_reason, "string");
  assert.ok(run.downgrade_reason.trim().length > 0, "a downgrade always carries a reason");
  assert.match(run.downgrade_reason, /connection[- ]only/i);
});

test("D10: an acknowledged checkpoint does not keep showing its prompt", () => {
  const ui = U();
  assert.equal(ui.normalizeRun(fixture.run_checkpoint).checkpoint, null);
  const pending = ui.normalizeRun({...plain(fixture.run_checkpoint), status: "running", state: "running", checkpoint_pending: true,
    checkpoint: {id: "cp-6-aaaa0001", step_order: 6, title: "Swap wires", instructions: "do it", requested_at: "t"}});
  assert.equal(pending.checkpoint.id, "cp-6-aaaa0001");
});

test("422 field errors from the backend map back to the right hop", () => {
  const h = load(), ui = h.ctx.ProcedureUi;
  const draft = ui.normalizeDraft(fixture.view_new);
  const parsed = ui.parseFieldErrors(h.httpError(422, fixture.error_422), draft);
  assert.deepEqual(plain(parsed.fields), {"2.port": fixture.error_422.errors[0].message});
});

test("D1 end to end in the page: a complete backend run stops the poller and the panel says it finished", async () => {
  const h = load(), id = "0".repeat(32), base = "/authoring/wizard/procedures/" + id;
  h.ctx.renderFullProcedure(plain(fixture.view_project), {stage: "project"});
  const calls = [];
  h.apiOp.route("POST", new RegExp("^" + base + "/runs$"), () => ({run_id: "run1"}));
  const seq = [fixture.run_running, fixture.run_complete];
  h.apiOp.route("GET", new RegExp("^" + base + "/runs/run1$"), () => { calls.push(1); return plain(seq[Math.min(calls.length - 1, 1)]); });
  h.document.getElementById("procedure-test-connection").click();
  await flush();
  assert.match(h.document.getElementById("procedure-run-status").textContent, /Running/);
  h.timers.runAll(); await flush();
  assert.match(h.document.getElementById("procedure-run-status").textContent, /finished: complete/);
  assert.equal(h.timers.pending().length, 0, "polling stopped");
  assert.ok(!h.document.getElementById("wizard-content").textContent.includes("[object"));
});
