"use strict";
// Stub-DOM harness for the production NRDP procedure UI code in templates/dashboard/index.html.
// It extracts the exact text between the <nrdp-procedure-ui> markers and evaluates it in a
// node:vm context with a hand-rolled fake document, fetch-free apiOp, localStorage, and timers.
// Fictional data only. No network, no browser.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.resolve(__dirname, "..", "..");
const START = "// <nrdp-procedure-ui>";
const END = "// </nrdp-procedure-ui>";

function extractRegion(html) {
  const text = html === undefined ? fs.readFileSync(path.join(ROOT, "templates/dashboard/index.html"), "utf8") : html;
  const a = text.indexOf(START), b = text.indexOf(END);
  if (a < 0 || b < 0 || b < a) throw new Error("procedure UI markers not found");
  return text.slice(a, b + END.length);
}

function camel(name) { return name.replace(/-([a-z])/g, (_, c) => c.toUpperCase()); }

class FakeNode {
  constructor(doc, tag) {
    this.ownerDocument = doc; this.tagName = String(tag).toUpperCase(); this.children = []; this.parentNode = null;
    this.attributes = {}; this.listeners = {}; this._text = ""; this.dataset = {}; this.className = ""; this.id = "";
    this.hidden = false; this.disabled = false; this.value = ""; this.open = false; this.selected = false; this.checked = false;
    this.innerHTMLWrites = 0;
    const self = this;
    this.classList = {
      add(c) { const s = new Set(self.className.split(/\s+/).filter(Boolean)); s.add(c); self.className = [...s].join(" "); },
      remove(c) { self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(" "); },
      toggle(c, on) { const has = this.contains(c); const want = on === undefined ? !has : Boolean(on); if (want) this.add(c); else this.remove(c); return want; },
      contains(c) { return self.className.split(/\s+/).includes(c); },
    };
  }
  appendChild(child) { if (child.parentNode) child.parentNode.removeChild(child); child.parentNode = this; this.children.push(child); return child; }
  removeChild(child) { const i = this.children.indexOf(child); if (i >= 0) this.children.splice(i, 1); child.parentNode = null; return child; }
  setAttribute(k, v) {
    const value = String(v); this.attributes[k] = value;
    if (k === "id") this.id = value;
    if (k.startsWith("data-")) this.dataset[camel(k.slice(5))] = value;
  }
  getAttribute(k) {
    if (k === "id") return this.id || null;
    if (k.startsWith("data-") && this.dataset[camel(k.slice(5))] !== undefined) return this.dataset[camel(k.slice(5))];
    return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null;
  }
  hasAttribute(k) { return this.getAttribute(k) !== null; }
  removeAttribute(k) { delete this.attributes[k]; if (k === "id") this.id = ""; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type) { (this.listeners[type] || []).forEach((fn) => fn.call(this, {type, target: this, preventDefault() {}})); }
  click() { if (this.disabled) return false; this.dispatch("click"); return true; }
  focus() { this.ownerDocument.activeElement = this; }
  get textContent() { return this.tagName === "#TEXT" ? this._text : this._text + this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { this.children.forEach((c) => { c.parentNode = null; }); this.children = []; this._text = String(v); }
  get innerHTML() { return this._html || ""; }
  set innerHTML(v) { this.innerHTMLWrites++; this.children = []; this._text = ""; this._html = String(v); }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n === this.ownerDocument.body; }
  walk(fn) { fn(this); this.children.forEach((c) => c.walk(fn)); }
  all(pred) { const out = []; this.walk((n) => { if (n !== this && pred(n)) out.push(n); }); return out; }
  byTestId(id) { return this.all((n) => n.dataset && n.dataset.testid === id)[0] || null; }
}

function makeDocument() {
  const doc = {activeElement: null};
  doc.createElement = (tag) => new FakeNode(doc, tag);
  doc.createTextNode = (text) => { const n = new FakeNode(doc, "#text"); n._text = String(text); return n; };
  doc.body = new FakeNode(doc, "body");
  doc.getElementById = (id) => { let found = null; doc.body.walk((n) => { if (!found && n.id === id) found = n; }); return found; };
  ["editor-panel-title", "wizard-stepper", "wizard-content"].forEach((id) => { const n = doc.createElement("div"); n.setAttribute("id", id); doc.body.appendChild(n); });
  return doc;
}

function makeStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(String(k)) ? map.get(String(k)) : null),
    setItem: (k, v) => { map.set(String(k), String(v)); },
    removeItem: (k) => { map.delete(String(k)); },
    clear: () => map.clear(),
    key: (i) => [...map.keys()][i] || null,
    get length() { return map.size; },
    dump: () => Object.fromEntries(map),
  };
}

function makeTimers() {
  let seq = 0; const pending = new Map();
  return {
    setTimeout: (fn, ms) => { const id = ++seq; pending.set(id, {fn, ms: Number(ms) || 0}); return id; },
    clearTimeout: (id) => { pending.delete(id); },
    pending: () => [...pending.entries()].map(([id, t]) => ({id, ms: t.ms})),
    // Runs every currently scheduled timer once (newly scheduled ones wait for the next call).
    runAll: () => { const due = [...pending.entries()]; due.forEach(([id]) => pending.delete(id)); due.forEach(([, t]) => t.fn()); return due.length; },
  };
}

// Mirrors api() in index.html: non-2xx -> Error("<status> <message>") with .status and .detail.
function httpError(status, body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  let detail = raw; try { detail = JSON.parse(raw).detail || raw; } catch (_) {}
  const message = typeof detail === "string" ? detail : (detail.message || "error");
  const error = new Error(status + " " + message); error.status = status; error.detail = detail; return error;
}

function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; }

function makeApi() {
  const routes = [], calls = [];
  const api = async (p, opts = {}) => {
    const method = String(opts.method || "GET").toUpperCase();
    const call = {method, path: p, body: opts.body === undefined ? undefined : String(opts.body)};
    calls.push(call);
    const route = routes.find((r) => r.method === method && r.re.test(p));
    if (!route) throw httpError(500, {detail: "unmatched fake route " + method + " " + p});
    return route.handler(call);
  };
  api.route = (method, re, handler) => { routes.unshift({method, re, handler}); };
  api.calls = calls;
  return api;
}

function load(options = {}) {
  const document = makeDocument(), localStorage = makeStorage(), sessionStorage = makeStorage(), timers = makeTimers(), apiOp = makeApi();
  const generation = [];
  const ctx = {
    document, localStorage, sessionStorage, apiOp, console,
    setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout,
    confirm: () => (options.confirm === undefined ? true : options.confirm),
    URL: {createObjectURL: () => "blob:fake", revokeObjectURL() {}}, Blob: function Blob(parts) { this.parts = parts; },
    esc: (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"),
    authoringState: {wizardEpoch: 1, procedureDraft: null, procedureStage: null, wizardIntent: ""},
    setWizardGenerationStatus: (message, state) => generation.push({message, state}),
  };
  ctx.window = ctx;
  // Minimal mirrors of the surrounding production functions (the real ones are covered by the Playwright gate).
  ctx.renderWizardStepper = () => { const c = document.getElementById("wizard-stepper"); c.textContent = ""; if (ctx.authoringState.procedureDraft) ctx.renderProcedureStepper(c); };
  ctx.renderWizardContent = () => { const r = document.getElementById("wizard-content"); if (ctx.authoringState.procedureDraft) ctx.renderProcedureWorkspace(r); else r.textContent = "step-1"; };
  ctx.resetAuthoringState = () => {
    ctx.authoringState.wizardEpoch += 1; ctx.procedureStopPolling(); ctx.procedureClearPasswordInputs();
    ctx.authoringState.procedureDraft = null; ctx.authoringState.procedureUi = null;
  };
  ctx.closeEditor = () => { ctx.resetAuthoringState(); ctx.renderWizardContent(); return true; };
  ctx.startFreshWizard = () => { if (!ctx.confirm("start fresh?")) return; ctx.procedureStartFresh(); ctx.closeEditor(true); };
  vm.createContext(ctx);
  vm.runInContext(extractRegion(options.html), ctx, {filename: "index.html#nrdp-procedure-ui"});
  return {ctx, document, localStorage, sessionStorage, timers, apiOp, generation, httpError, deferred, flush};
}

async function flush(times = 6) { for (let i = 0; i < times; i++) await new Promise((r) => setImmediate(r)); }

// Fictional two-hop draft (TEST-NET addresses, example users). No real hosts or passwords.
function fixtureDraft(overrides = {}) {
  return Object.assign({
    id: "a".repeat(32), title: "ExampleService service maintenance", status: "draft-only", schema_version: 2,
    connections: [
      {order: 1, protocol: "rdp", host: "192.0.2.10", port: 3389, user: "example-operator", label: "", opened_from: "runner desktop",
        credential: {state: "saved", reference: "procedure-aaaa-hop1.pw"}, certificate: {state: "required", name: "", fingerprint: ""}, identity_policy: "stop", predecessor: null},
      {order: 2, protocol: "rdp", host: "198.51.100.20", port: 3389, user: "example-service-admin", label: "", opened_from: "RDP desktop from hop 1",
        credential: {state: "saved", reference: "procedure-aaaa-hop2.pw"}, certificate: {state: "not_applicable", name: "", fingerprint: ""}, identity_policy: "stop", predecessor: 1},
    ],
    steps: [
      {order: 1, title: "Check elevation", kind: "procedure-step", mutating: false, read_only_ok: true, instructions: "1. Open PowerShell as administrator.", completion_checks: ["Elevated"]},
      {order: 2, title: "Restart service", kind: "procedure-step", mutating: true, read_only_ok: false, instructions: "2. Stop-Service ExampleService; Start-Service ExampleService", completion_checks: []},
      {order: 3, title: "Swap cable", kind: "operator-checkpoint", mutating: true, read_only_ok: false, instructions: "3. Physically reseat the example cable.", completion_checks: []},
    ],
    final_hop: 2, findings: ["Fixture finding."], manual: "# Fixture manual", project: null,
    readiness: {items: [
      {key: "connections", label: "2 connections in order", state: "known", detail: ""},
      {key: "certificate-1", label: "Reviewed certificate for connection 1", state: "required", detail: "Fetch it."},
      {key: "label-1", label: "Name for connection 1", state: "optional", detail: ""},
    ]},
    last_test: null, execution_supported: true,
  }, overrides);
}

module.exports = {extractRegion, load, flush, fixtureDraft, httpError, deferred, FakeNode, START, END, ROOT};
