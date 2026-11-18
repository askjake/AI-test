"use strict";
// Regression: VNC-through-SSH gateway host-key review.
//  1. Typing the independently verified fingerprint enables "Approve host key" (no checkbox needed).
//  2. The "I compared this fingerprint" checkbox confirms ONLY the exact discovered key the operator reviewed:
//     it is cleared when discovery starts, when the candidate is replaced/invalidated, and after a rejected or successful approval.
//  3. The comparison flag is sent only when the CURRENT candidate was explicitly checked; the server's fingerprint check is unchanged.
// Stub DOM (tests/js/procedure_ui_harness.js) + a fake server that validates like the real route. Fictional TEST-NET data.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const test = require("node:test");
const {load, flush, httpError, fixtureDraft, deferred, ROOT} = require("./procedure_ui_harness.js");

const FP1 = "SHA256:" + "A".repeat(43), FP2 = "SHA256:" + "B".repeat(43);
const KEYS = [
  {id: "1".repeat(32), key_algorithm: "ssh-ed25519", fingerprint: FP1, retrieved_at: "t0", expires_at: "t9", source: "fixture-1", known_hosts_line: "192.0.2.10 ssh-ed25519 AAAAFIXTURE1"},
  {id: "2".repeat(32), key_algorithm: "ssh-ed25519", fingerprint: FP2, retrieved_at: "t1", expires_at: "t9", source: "fixture-2", known_hosts_line: "192.0.2.10 ssh-ed25519 AAAAFIXTURE2"},
];

function setup() {
  const h = load();
  const html = fs.readFileSync(path.join(ROOT, "templates/dashboard/index.html"), "utf8");
  const a = html.indexOf("// <nrdp-vnc-ssh>"), b = html.indexOf("// </nrdp-vnc-ssh>");
  assert.ok(a > 0 && b > a, "nrdp-vnc-ssh markers present");
  vm.runInContext(html.slice(a, b), h.ctx, {filename: "index.html#nrdp-vnc-ssh"});
  const D = "c".repeat(32);
  const gateway = (over) => Object.assign({host: "192.0.2.10", port: 22, user: "example-user", credential: {state: "saved", reference: "procedure-" + D + "-gateway.gateway.pw"}, host_key: {state: "missing"}}, over);
  const vncDraft = (gw) => fixtureDraft({id: D, final_hop: 1, gateway: gw, connections: [{order: 1, protocol: "vnc", host: "192.0.2.47", port: 5902, display: 2, user: "", label: "", opened_from: "runner (VNC viewer)", auth_method: "vnc-password",
    vnc: {display: 2, tcp_port: 5902, auth_method: "vnc-password", username_sent: false, address_form: ":2"}, credential: {state: "saved", reference: "procedure-" + D + "-hop-1.vnc.pw"}, certificate: {state: "not_applicable", name: "", fingerprint: ""}, predecessor: null}]});
  h.ctx.authoringState.procedureDraft = vncDraft(gateway());
  // Render the REAL gateway card (edit form, Save gateway button and host-key review) the way the dashboard does.
  h.ctx.renderWizardContent = () => { const r = h.document.getElementById("wizard-content"); r.textContent = ""; r.appendChild(h.ctx.renderVncSshGatewayCard()); };
  h.ctx.renderWizardStepper = () => {};
  let n = 0; const bodies = [];
  h.apiOp.route("POST", /\/gateway\/host-key\/discover$/, () => KEYS[Math.min(n++, KEYS.length - 1)]);
  h.apiOp.route("POST", /\/gateway\/host-key\/approve$/, (call) => {   // mirrors the real route: typed fingerprint must match; otherwise the flag must be true
    const body = JSON.parse(call.body); bodies.push(body);
    const key = KEYS.find((k) => k.id === body.candidate_id);
    if (!key) throw httpError(422, {detail: "unknown candidate"});
    if (body.expected_fingerprint !== undefined) {
      if (body.expected_fingerprint !== key.fingerprint) throw httpError(422, {detail: "The fingerprint you entered does not match this key. Nothing was saved."});
    } else if (body.fingerprint_compared !== true) throw httpError(422, {detail: "Enter the SHA256 fingerprint or tick the box."});
    return {id: D, gateway: {host: "192.0.2.10", port: 22, user: "example-user", host_key: {state: "approved"}}};
  });
  const puts = [];
  const get = (id) => h.document.getElementById(id);
  const byTestId = (id) => { const walk = (n) => { if ((n.attributes && n.attributes["data-testid"]) === id || (n.dataset && n.dataset.testid === id)) return n; for (const c of n.children || []) { const r = walk(c); if (r) return r; } return null; }; return walk(h.document.getElementById("wizard-content")); };
  const discover = async () => { h.ctx.vncSshDiscover(); await flush(); };
  const tick = (checked) => { const box = get("vnc-ssh-compared"); box.checked = checked; box.dispatch("change"); };
  const type = (v) => { const i = get("vnc-ssh-verify-fp"); i.value = v; i.dispatch("input"); };
  const approve = async () => { get("vnc-ssh-approve").dispatch("click"); await flush(); };
  return {h, get, byTestId, discover, tick, type, approve, bodies, puts, vncDraft, gateway, D};
}

test("approve is disabled until the operator checks the box or types a fingerprint", async () => {
  const s = setup(); await s.discover();
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
});

test("typing the correct fingerprint enables Approve without the checkbox, and sends only that fingerprint", async () => {
  const s = setup(); await s.discover();
  s.type(FP1);
  assert.equal(s.get("vnc-ssh-approve").disabled, false);
  await s.approve();
  assert.equal(s.bodies.length, 1);
  assert.equal(s.bodies[0].expected_fingerprint, FP1);
  assert.equal("fingerprint_compared" in s.bodies[0], false, "no comparison flag when the operator typed the fingerprint");
});

test("clearing the typed text disables Approve again when the box is not checked", async () => {
  const s = setup(); await s.discover();
  s.type(FP1); s.type("   ");
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
});

test("review of the first key never carries over to a second discovered key", async () => {
  const s = setup(); await s.discover();
  assert.equal(s.byTestId("vnc-ssh-cand-fingerprint").textContent, FP1);
  s.tick(true);
  assert.equal(s.get("vnc-ssh-approve").disabled, false, "first key explicitly reviewed");
  await s.discover();                                            // a different key (fixture 2) replaces the candidate
  assert.equal(s.byTestId("vnc-ssh-cand-fingerprint").textContent, FP2);
  assert.equal(s.get("vnc-ssh-compared").checked, false, "checkbox cleared by the new discovery");
  assert.equal(s.get("vnc-ssh-approve").disabled, true, "second key not yet reviewed");
  s.tick(true);
  assert.equal(s.get("vnc-ssh-approve").disabled, false, "second key explicitly reviewed");
  await s.approve();
  assert.deepEqual(s.bodies.map((b) => [b.candidate_id, b.fingerprint_compared]), [[KEYS[1].id, true]]);
});

test("a stale review is not sent if the candidate is replaced without a new discovery", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  const ui = s.h.ctx.vncSshUi(); ui.candidate = KEYS[1];          // candidate swapped underneath the screen
  s.h.ctx.renderWizardContent();
  assert.equal(s.get("vnc-ssh-compared").checked, false);
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
  await s.h.ctx.vncSshApprove("discovered"); await flush();      // even if invoked directly
  assert.equal(s.bodies.length, 0, "no approve request without an explicit review of this exact candidate");
});

test("a wrong typed fingerprint is rejected even when the box is checked, and the review is then cleared", async () => {
  const s = setup(); await s.discover();
  s.tick(true); s.type(FP2);                                     // FP2 does not match candidate 1
  await s.approve();
  assert.equal(s.bodies.length, 1);
  assert.equal(s.bodies[0].expected_fingerprint, FP2);
  assert.equal("fingerprint_compared" in s.bodies[0], false, "the typed value wins; the checkbox does not rescue a wrong fingerprint");
  assert.match(s.h.ctx.vncSshUi().hkStatus, /does not match/);
  assert.equal(s.h.ctx.vncSshUi().hkState, "error");
  assert.equal(s.get("vnc-ssh-compared").checked, false, "rejection clears the review");
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
});

test("a successful approval clears the review state", async () => {
  const s = setup(); await s.discover(); s.tick(true); await s.approve();
  assert.equal(s.bodies.length, 1);
  assert.equal(s.h.ctx.vncSshUi().comparedId, null);
});

test("the real Save gateway handler discards the candidate and the review (host change)", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  assert.ok(s.h.ctx.vncSshUi().comparedId, "reviewed before saving");
  assert.ok(s.get("vnc-ssh-candidate"), "candidate on screen before saving");
  s.h.apiOp.route("PUT", /\/gateway$/, (call) => {                       // fixture server: host changed, so the approval is gone and the draft returns without a key
    s.puts.push(JSON.parse(call.body));
    return s.vncDraft(s.gateway({host: "192.0.2.11"}));
  });
  const host = s.get("vnc-ssh-edit-host"); host.value = "192.0.2.11"; host.dispatch("input");
  s.get("vnc-ssh-save-gateway").dispatch("click"); await flush();         // the production click handler -> vncSshSaveGateway()
  assert.deepEqual(s.puts, [{host: "192.0.2.11"}], "only the changed field is sent");
  const ui = s.h.ctx.vncSshUi();
  assert.equal(ui.candidate, null, "candidate discarded by the save handler");
  assert.equal(ui.comparedId, null, "review cleared by the save handler");
  assert.equal(s.get("vnc-ssh-candidate"), null, "candidate card no longer rendered");
  assert.match(ui.gwStatus, /approve the key again/);
  await s.discover();                                                    // the next candidate (fixture 2) starts unreviewed
  assert.equal(s.byTestId("vnc-ssh-cand-fingerprint").textContent, FP2);
  assert.equal(s.get("vnc-ssh-compared").checked, false);
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
});

test("the real Save gateway handler also clears the review for a username-only change", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  s.h.apiOp.route("PUT", /\/gateway$/, (call) => { s.puts.push(JSON.parse(call.body)); return s.vncDraft(s.gateway({user: "example-user2"})); });
  const user = s.get("vnc-ssh-edit-user"); user.value = "example-user2"; user.dispatch("input");
  s.get("vnc-ssh-save-gateway").dispatch("click"); await flush();
  assert.deepEqual(s.puts, [{user: "example-user2"}]);
  assert.equal(s.h.ctx.vncSshUi().candidate, null);
  assert.equal(s.h.ctx.vncSshUi().comparedId, null);
});

test("a failed gateway save keeps the candidate and the review it did not change", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  s.h.apiOp.route("PUT", /\/gateway$/, () => { throw httpError(422, {detail: "fixture: rejected"}); });
  const host = s.get("vnc-ssh-edit-host"); host.value = "192.0.2.11"; host.dispatch("input");
  s.get("vnc-ssh-save-gateway").dispatch("click"); await flush();
  assert.equal(s.h.ctx.vncSshUi().gwState, "error");
  assert.equal(s.h.ctx.vncSshUi().candidate.id, KEYS[0].id, "nothing changed on the server, so the reviewed key stays");
  assert.equal(s.h.ctx.vncSshUi().comparedId, KEYS[0].id);
});

test("starting a new discovery clears the old candidate and review immediately, before the new key arrives", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  assert.equal(s.get("vnc-ssh-approve").disabled, false, "first key reviewed");
  const gate = deferred();
  s.h.apiOp.route("POST", /\/gateway\/host-key\/discover$/, () => gate.promise);   // second discovery stays in flight
  s.h.ctx.vncSshDiscover(); await flush();
  const ui = s.h.ctx.vncSshUi();
  assert.equal(ui.candidate, null, "old candidate removed while discovery is running");
  assert.equal(ui.comparedId, null, "review cleared while discovery is running");
  assert.equal(s.get("vnc-ssh-candidate"), null, "old candidate card not shown while discovery is running");
  assert.equal(s.get("vnc-ssh-approve"), null, "no Approve button for a key that is no longer current");
  gate.resolve(KEYS[1]); await flush();
  assert.equal(s.byTestId("vnc-ssh-cand-fingerprint").textContent, FP2);
  assert.equal(s.get("vnc-ssh-compared").checked, false);
  assert.equal(s.get("vnc-ssh-approve").disabled, true);
});

test("a failed discovery leaves no candidate and no review", async () => {
  const s = setup(); await s.discover(); s.tick(true);
  s.h.apiOp.route("POST", /\/gateway\/host-key\/discover$/, () => { throw httpError(503, {detail: "fixture: discovery off"}); });
  await s.discover();
  assert.equal(s.h.ctx.vncSshUi().candidate, null);
  assert.equal(s.h.ctx.vncSshUi().comparedId, null);
  assert.equal(s.h.ctx.vncSshUi().hkState, "error");
});
