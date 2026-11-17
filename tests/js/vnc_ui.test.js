"use strict";
// Production-JavaScript DOM scenarios for VNC intake (stub DOM, fictional data).
// Run: node --test tests/js/vnc_ui.test.js   (from the repository root)
const assert = require("node:assert/strict");
const test = require("node:test");
const {load, flush, fixtureDraft, httpError} = require("./procedure_ui_harness.js");

const ID = "c".repeat(32);
const GOAL = [
  "VNC to 192.0.2.47", "username: example-user", "password=pw-v1x", "",
  "Open Chrome on that desktop.", "Go to http://127.0.0.1:5004/.", "Expand the browser to cover the desktop.",
  "Verify active video streams.", "Leave the browser open and finish the automation.",
].join("\n");

function vncDraft(overrides = {}) {
  return fixtureDraft(Object.assign({
    id: ID, title: "VNC desktop operating procedure", final_hop: 1,
    connections: [{order: 1, protocol: "vnc", host: "192.0.2.47", port: 5900, display: 0, user: "example-user", label: "", opened_from: "runner (VNC viewer)",
      auth_method: "vnc-password", vnc: {display: 0, tcp_port: 5900, auth_method: "vnc-password", username_sent: false, address_form: ":0"},
      credential: {state: "saved", reference: "procedure-" + ID + "-hop-1.vnc.pw"}, certificate: {state: "not_applicable", name: "", fingerprint: ""}, predecessor: null}],
    steps: [{order: 1, title: "Open Chrome", kind: "procedure-step", mutating: false, read_only_ok: true, instructions: "1. Open Chrome.", completion_checks: []}],
    readiness: {items: [{key: "credential-hop-1", label: "Hop 1 credential saved", state: "known", detail: ""}, {key: "auth-method", label: "VNC authentication method", state: "known", detail: ""}]},
  }, overrides));
}

function el(h, id) { return h.document.getElementById(id); }
function field(h, name) { return el(h, "procedure-conn-1-" + name); }
function type(node, value) { node.value = value; node.dispatch(node.tagName === "SELECT" ? "change" : "input"); }
const plain = (x) => JSON.parse(JSON.stringify(x));

test("goal text is classified before any model request", () => {
  const h = load();
  const k = h.ctx.connectionBlockKind;
  assert.equal(k(GOAL), "vnc");
  assert.equal(k("connect via vnc to host.example:2\npassword=abc"), "vnc");
  assert.equal(k("RDP to 192.0.2.10\nexample-operator\nSecret-pass-1\n1. open it"), "rdp");
  assert.equal(k("Verify the VNC viewer shows the desktop"), "");
  assert.equal(k("Use VNC to inspect the box"), "");
});

test("credential-like text outside a recognised block is refused locally", () => {
  const h = load();
  const g = h.ctx.credentialGuardMessage;
  assert.match(g("Log in\npassword: hunter22\nthen continue"), /Line 2 looks like a credential/);
  assert.match(g("open https://u:hunter22@10.0.0.5/ now"), /embedded user name and password/);
  assert.equal(g("Verify that four video streams are active and leave the browser open."), "");
  assert.doesNotMatch(g("password: hunter22"), /hunter22/);
});

test("a VNC draft is normalised with protocol, display, authentication and no certificate", () => {
  const h = load();
  const d = h.ctx.ProcedureUi.normalizeDraft(plain(vncDraft()));
  const c = d.connections[0];
  assert.equal(c.protocol, "vnc"); assert.equal(c.display, 0); assert.equal(c.port, 5900); assert.equal(c.auth_method, "vnc-password");
  assert.equal(h.ctx.ProcedureUi.certificateChip(c), null);
  assert.match(h.ctx.ProcedureUi.predecessorText(c), /VNC viewer/);
  const rdp = h.ctx.ProcedureUi.normalizeDraft(plain(fixtureDraft())).connections[0];
  assert.equal(rdp.protocol, "rdp"); assert.equal(rdp.display, null); assert.equal(rdp.port, 3389);
});

test("the connection card shows VNC facts and VNC-specific fields only", () => {
  const h = load();
  h.ctx.renderFullProcedure(vncDraft(), {});
  const root = el(h, "wizard-content");
  assert.match(root.textContent, /Connection 1 · VNC/);
  assert.match(root.byTestId("procedure-destination-1").textContent, /192\.0\.2\.47:0 \(display 0, TCP 5900\)/);
  assert.match(root.byTestId("procedure-user-1").textContent, /recorded, not sent/);
  assert.match(root.byTestId("procedure-auth-1").textContent, /VNC password/);
  assert.ok(field(h, "display") && field(h, "port") && field(h, "user") && field(h, "auth_method") && field(h, "host"));
  assert.equal(field(h, "identity_policy"), null); assert.equal(field(h, "certificate_name"), null); assert.equal(root.byTestId("procedure-cert-1"), null);
  assert.equal(root.byTestId("procedure-certificate-chip-1"), null);
  assert.match(root.textContent, /The runner opens this VNC desktop with its own viewer/);
  assert.doesNotMatch(root.textContent, /inside the previous desktop/);
});

test("editing the display sends the display only; editing the TCP port sends the port only", async () => {
  const h = load();
  const draft = vncDraft();
  h.ctx.renderFullProcedure(draft, {});
  type(field(h, "display"), "2");
  let body = plain(h.ctx.ProcedureUi.buildConnectionsPayload(h.ctx.authoringState.procedureDraft, h.ctx.procedureEdits(), {}, {})).connections[0];
  assert.deepEqual(Object.keys(body).sort(), ["auth_method", "display", "host", "label", "order", "user"]);
  assert.equal(body.display, 2);
  type(field(h, "display"), "0"); type(field(h, "port"), "6001");
  body = plain(h.ctx.ProcedureUi.buildConnectionsPayload(h.ctx.authoringState.procedureDraft, h.ctx.procedureEdits(), {}, {})).connections[0];
  assert.equal(body.port, 6001); assert.equal("display" in body, false);
  assert.equal("identity_policy" in body, false); assert.equal("certificate" in body, false);
});

test("a replacement password is sent as new_password and field errors map to the VNC fields", async () => {
  const h = load();
  h.ctx.renderFullProcedure(vncDraft(), {});
  type(field(h, "display"), "100");
  h.apiOp.route("PUT", /\/connections$/, () => { throw httpError(422, {detail: {errors: [{field: "connections[0].display", message: "VNC display must be 0 through 99."}]}}); });
  await h.ctx.procedureSaveConnections();
  await flush();
  assert.match(el(h, "procedure-conn-1-display-error").textContent, /display must be 0 through 99/);
  const call = h.apiOp.calls.find((c) => c.method === "PUT");
  assert.ok(call); assert.doesNotMatch(call.body, /certificate|identity_policy/);
});

test("intake of a VNC block posts only to the local intake route and keeps no raw text afterwards", async () => {
  const h = load();
  const input = h.document.createElement("textarea"); input.setAttribute("id", "wizard-intent"); input.value = GOAL;
  const button = h.document.createElement("button"); button.setAttribute("id", "wizard-step1-continue");
  const err = h.document.createElement("p"); err.setAttribute("id", "wizard-intent-error");
  [input, button, err].forEach((n) => h.document.body.appendChild(n));
  h.apiOp.route("POST", /\/authoring\/wizard\/procedures$/, () => vncDraft());
  await h.ctx.buildFullProcedure(GOAL);
  await flush();
  const posts = h.apiOp.calls.filter((c) => c.method === "POST");
  assert.equal(posts.length, 1); assert.match(posts[0].path, /\/authoring\/wizard\/procedures$/);
  assert.equal(h.apiOp.calls.some((c) => /context-preview|plan-jobs/.test(c.path)), false);
  assert.equal(input.value, "");                                        // the raw goal (with its password) is cleared after a successful intake
  assert.equal(JSON.stringify(h.ctx.authoringState, (k, v) => (k === "ownerDocument" ? undefined : v)).includes("pw-v1x"), false);
});

test("a rejected VNC block shows a field-tagged message and says nothing was sent to the model", async () => {
  const h = load();
  const input = h.document.createElement("textarea"); input.setAttribute("id", "wizard-intent"); input.value = "VNC to 192.0.2.47:5901\npassword=abc";
  const button = h.document.createElement("button"); button.setAttribute("id", "wizard-step1-continue");
  const err = h.document.createElement("p"); err.setAttribute("id", "wizard-intent-error"); err.hidden = true;
  [input, button, err].forEach((n) => h.document.body.appendChild(n));
  h.apiOp.route("POST", /\/authoring\/wizard\/procedures$/, () => { throw httpError(422, {detail: {message: "'\:5901' is ambiguous: write :1 or ::5901.", field: "vnc.port"}}); });
  await h.ctx.buildFullProcedure("VNC to 192.0.2.47:5901\npassword=abc");
  await flush();
  assert.equal(err.hidden, false); assert.match(err.textContent, /ambiguous/); assert.match(err.textContent, /vnc\.port/);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.match(h.generation.at(-1).message, /Nothing was sent to the model/); assert.equal(h.generation.at(-1).state, "error");
  assert.equal(input.value, "VNC to 192.0.2.47:5901\npassword=abc");   // kept so the operator can fix it
});

test("the example and the syntax help are present and use only fictional values", () => {
  const h = load();
  assert.match(h.ctx.PROCEDURE_EXAMPLE_VNC_GOAL, /^VNC to 192\.0\.2\.47/);
  assert.match(h.ctx.PROCEDURE_VNC_SYNTAX, /VNC to HOST::5902 {7}TCP port 5902/);
  assert.match(h.ctx.PROCEDURE_VNC_SYNTAX, /HOST:5901" is rejected as ambiguous/);
});


test("guard bypass attempts (normalisation, widened labels) are refused; prose about a password field is not", () => {
  const h = load();
  const g = h.ctx.credentialGuardMessage;
  for (const text of ["p\u0430ssword: hunter22", "pass\u200bword: x1", "PASSWORD\uff1ahunter22", "my password is hunter2", "password - hunter2", "pw: x1y2", "passcode: 1234",
                      "password\n: hunter2", "the token=abc123", "Use credentials: admin:hunter2"]) assert.notEqual(g(text), "", JSON.stringify(text));
  for (const text of ["Verify the Password: field is shown", "Check that the password is required", "Open the password manager and take a screenshot", "Leave the browser open"]) assert.equal(g(text), "", JSON.stringify(text));
});


test("tester D1: JSON-quoted label, a non-English label and 'as user / secret' are refused", () => {
  const h = load();
  const g = h.ctx.credentialGuardMessage;
  for (const text of ['"pass' + 'word": "hunter22"', "kennwort: hunter22", "Log in to the box as bob / hunter22 and open Chrome", "pass" + "word - hunter22"]) assert.notEqual(g(text), "", JSON.stringify(text));
  assert.equal(g("Leave the browser open and verify four streams"), "");
});
