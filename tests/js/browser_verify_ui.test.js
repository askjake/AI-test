"use strict";
// CP43: minimum browser_verify UI, driven through the PRODUCTION procedure-UI code (stub DOM, fictional data).
// Run: node --test tests/js/browser_verify_ui.test.js   (Node >= 18)
const assert = require("node:assert/strict");
const test = require("node:test");
const {load, flush, fixtureDraft} = require("./procedure_ui_harness.js");

const ID = "a".repeat(32);
const base = "/authoring/wizard/procedures/" + ID;
const PROJ = "foo-service-maintenance-01234567";
const URL = "http://127.0.0.1:5004/";
const byId = (h, id) => h.document.getElementById(id);
function type(node, value) { node.value = value; node.dispatch(node.tagName === "SELECT" ? "change" : "input"); }
const CAP_OFF = {connection_only: true, allowed_modes: ["connection_test"], disabled_modes: ["read_only_check", "full_run", "browser_verify"], reason: "connection tests only",
  browser_verify: {available: false, reason: "Browser playback verification is not available in this build: it is disabled by default.", url: URL, projects: []}};
const CAP_ON = {connection_only: true, allowed_modes: ["connection_test", "browser_verify"], disabled_modes: ["read_only_check", "full_run"], reason: "connection tests only",
  browser_verify: {available: true, reason: "", url: URL, projects: [PROJ], cleanup_note: "The browser window, its profile folder and a possible Run-history entry are LEFT on the target.",
    confirm_phrase_template: "BROWSER-VERIFY {project}", leave_open_phrase_template: "LEAVE-OPEN {project}"}};
const PASSED = {run_id: "run0", mode: "connection_test", status: "passed", at: "t", current: true};
function open(h, overrides) {
  h.ctx.renderFullProcedure(fixtureDraft(Object.assign({project: {name: PROJ, current: true}, last_test: PASSED}, overrides)), {stage: "project"});
}
const startCalls = (h) => h.apiOp.calls.filter((c) => c.path === base + "/runs");

test("disabled capability: availability is explained and NO actionable browser-run control exists", () => {
  for (const cap of [CAP_OFF, undefined, {allowed_modes: ["connection_test", "browser_verify"], browser_verify: "yes"}, {allowed_modes: ["browser_verify"], browser_verify: {available: "true"}}]) {
    const h = load();
    open(h, cap === undefined ? {} : {run_capability: cap});
    assert.ok(byId(h, "procedure-browser-verify-note"), "an explanation is shown");
    assert.match(byId(h, "procedure-browser-verify-note").textContent, /not available/i);
    for (const id of ["procedure-bv-mode", "procedure-bv-confirm", "procedure-bv-ack", "procedure-bv-start"]) assert.equal(byId(h, id), null, id + " must not exist");
    assert.ok(byId(h, "procedure-test-connection"), "connection test stays available");
    assert.equal(byId(h, "procedure-run-mode").disabled, true);
  }
});

test("pure request builder: refuses unless the served capability, project, phrases and acknowledgement all line up", () => {
  const U = load().ctx.ProcedureUi;
  const ok = U.runRequest("browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, CAP_ON, {ack: "LEAVE-OPEN " + PROJ});
  assert.deepEqual(JSON.parse(JSON.stringify(ok)), {ok: true, body: {mode: "browser_verify", url: URL, confirm_phrase: "BROWSER-VERIFY " + PROJ, leave_open_ack: "LEAVE-OPEN " + PROJ}});
  const bad = (args) => U.runRequest(...args).ok;
  assert.equal(bad(["browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, CAP_OFF, {ack: "LEAVE-OPEN " + PROJ}]), false, "capability off");
  assert.equal(bad(["browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, undefined, {ack: "LEAVE-OPEN " + PROJ}]), false, "no capability fails closed");
  assert.equal(bad(["browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, Object.assign({}, CAP_ON, {allowed_modes: ["connection_test"]}), {ack: "LEAVE-OPEN " + PROJ}]), false, "not in allowed_modes");
  assert.equal(bad(["browser_verify", "other-project", "BROWSER-VERIFY other-project", CAP_ON, {ack: "LEAVE-OPEN other-project"}]), false, "project not allow-listed");
  assert.equal(bad(["browser_verify", PROJ, "", CAP_ON, {ack: "LEAVE-OPEN " + PROJ}]), false, "no confirmation");
  assert.equal(bad(["browser_verify", PROJ, PROJ, CAP_ON, {ack: "LEAVE-OPEN " + PROJ}]), false, "project name alone is not the phrase");
  assert.equal(bad(["browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, CAP_ON, {}]), false, "no acknowledgement");
  assert.equal(bad(["browser_verify", PROJ, "BROWSER-VERIFY " + PROJ, CAP_ON, {ack: "leave-open " + PROJ}]), false, "acknowledgement is exact");
  assert.equal(bad(["browser_verify", "", "x", CAP_ON, {ack: "y"}]), false, "no project");
  for (const m of ["full_run", "read_only_check", "", "Browser_Verify", null]) assert.equal(U.runRequest(m, PROJ, PROJ, CAP_ON, {ack: "LEAVE-OPEN " + PROJ}).ok, false, String(m));
  assert.deepEqual(JSON.parse(JSON.stringify(U.runRequest("connection_test", PROJ, "", CAP_ON))), {ok: true, body: {mode: "connection_test"}}, "connection_test request is unchanged");
});

test("enabled fixture: explicit mode selection AND the acknowledgement are required before the start control works", async () => {
  const h = load();
  open(h, {run_capability: CAP_ON});
  assert.match(byId(h, "procedure-bv-cleanup-note").textContent, /LEFT on the target/);
  assert.equal(byId(h, "procedure-bv-start").disabled, true, "nothing selected");
  type(byId(h, "procedure-bv-confirm"), "BROWSER-VERIFY " + PROJ);
  type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN " + PROJ);
  assert.equal(byId(h, "procedure-bv-start").disabled, true, "phrases alone do not select the mode");
  type(byId(h, "procedure-bv-mode"), "browser_verify");
  assert.equal(byId(h, "procedure-bv-start").disabled, false, "selected + confirmed + acknowledged + current passed connection test");
  type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN");
  assert.equal(byId(h, "procedure-bv-start").disabled, true, "a wrong acknowledgement disables it again");
  assert.match(byId(h, "procedure-bv-reason").textContent, /LEAVE-OPEN/);
  type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN " + PROJ);
  byId(h, "procedure-bv-start").click(); await flush();
  assert.deepEqual(JSON.parse(startCalls(h).at(-1).body), {mode: "browser_verify", url: URL, confirm_phrase: "BROWSER-VERIFY " + PROJ, leave_open_ack: "LEAVE-OPEN " + PROJ});
});

test("enabled fixture still needs a current passed connection test and a current project", () => {
  let h = load();
  open(h, {run_capability: CAP_ON, last_test: null});
  type(byId(h, "procedure-bv-mode"), "browser_verify"); type(byId(h, "procedure-bv-confirm"), "BROWSER-VERIFY " + PROJ); type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN " + PROJ);
  assert.equal(byId(h, "procedure-bv-start").disabled, true);
  assert.match(byId(h, "procedure-bv-reason").textContent, /connection test/i);
  h = load();
  open(h, {run_capability: CAP_ON, project: {name: PROJ, current: false}});
  type(byId(h, "procedure-bv-mode"), "browser_verify"); type(byId(h, "procedure-bv-confirm"), "BROWSER-VERIFY " + PROJ); type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN " + PROJ);
  assert.equal(byId(h, "procedure-bv-start").disabled, true);
  assert.match(byId(h, "procedure-bv-reason").textContent, /connections changed/i);
});

test("result view keeps playback and cleanup SEPARATE and never presents a left-open window as cleaned up", async () => {
  const h = load();
  open(h, {run_capability: CAP_ON});
  const result = {run_id: "runbv", mode: "browser_verify", status: "complete", state: "complete", chain_progress: {active_hop: 2, hops: [{order: 1, status: "confirmed"}, {order: 2, status: "confirmed"}]},
    browser_verify: {status: "completed", code: "PLAYBACK_ADVANCING_ALL", verdict: "PLAYBACK_ADVANCING_ALL",
      playback: {status: "completed", code: "PLAYBACK_ADVANCING_ALL", verdict: "PLAYBACK_ADVANCING_ALL", independent_of_cleanup: true},
      claims: {playback: "advancing pixel content only", live_source_freshness: "UNVERIFIED", audio: "NOT_ASSESSED"},
      streams: [{label: "Stream 1", state: "PLAYBACK_ADVANCING"}, {label: "Stream 2", state: "PLAYBACK_ADVANCING"}],
      cleanup: {status: "NOT_PERFORMED", reason: "OWNERSHIP_UNPROVEN_LEAVE_OPEN_ROUTE", close_input_sent: false, note: "Cleanup was NOT performed.",
        expected_artifacts: [{kind: "browser_window", state: "OPEN_OBSERVED"}, {kind: "profile_directory", state: "POSSIBLE_NOT_VERIFIED"}, {kind: "run_history_entry", state: "POSSIBLE_NOT_VERIFIED"}],
        operator_guidance: ["Manual cleanup is optional.", "Delete the profile folder only after confirming nothing is using it."]}}};
  h.apiOp.route("POST", new RegExp("^" + base + "/runs$"), () => ({run_id: "runbv"}));
  h.apiOp.route("GET", new RegExp("^" + base + "/runs/runbv$"), () => result);
  type(byId(h, "procedure-bv-mode"), "browser_verify"); type(byId(h, "procedure-bv-confirm"), "BROWSER-VERIFY " + PROJ); type(byId(h, "procedure-bv-ack"), "LEAVE-OPEN " + PROJ);
  byId(h, "procedure-bv-start").click(); await flush(); h.timers.runAll(); await flush();
  const playback = byId(h, "procedure-bv-playback"), cleanup = byId(h, "procedure-bv-cleanup");
  assert.ok(playback && cleanup && playback !== cleanup);
  assert.match(byId(h, "procedure-bv-playback-verdict").textContent, /^PLAYBACK_ADVANCING_ALL/);
  assert.match(playback.textContent, /Live-source freshness: UNVERIFIED/);
  assert.match(byId(h, "procedure-bv-cleanup-status").textContent, /^NOT_PERFORMED \(OWNERSHIP_UNPROVEN_LEAVE_OPEN_ROUTE\)/);
  assert.doesNotMatch(cleanup.textContent, /PLAYBACK_ADVANCING/, "cleanup section never carries the playback verdict");
  assert.doesNotMatch(playback.textContent, /NOT_PERFORMED|profile/i, "playback section never carries cleanup facts");
  assert.doesNotMatch(cleanup.textContent, /\b(closed|cleaned up)\b(?! automatically)/i);
  assert.equal(byId(h, "procedure-bv-leftovers").children.length, 3);
  assert.equal(byId(h, "procedure-bv-guidance").children.length, 2);
});

test("a failed playback and an unknown or hostile result shape render safely", () => {
  const U = load().ctx.ProcedureUi;
  assert.equal(U.normalizeBrowserVerify(null), null);
  assert.equal(U.normalizeBrowserVerify("<img onerror=x>"), null);
  const n = U.normalizeBrowserVerify({verdict: "PLAYBACK_NOT_ADVANCING", status: "completed", cleanup: {guidance: "not-a-list", expected_artifacts: [null, {kind: "browser_window"}]}, streams: [null]});
  assert.equal(n.playback.verdict, "PLAYBACK_NOT_ADVANCING");
  assert.equal(n.cleanup.status, "NOT_PERFORMED", "an absent cleanup status is reported as NOT_PERFORMED, never as success");
  assert.equal(n.freshness, "UNVERIFIED");
  assert.deepEqual(JSON.parse(JSON.stringify(n.cleanup.guidance)), []);
});
