#!/usr/bin/env node
"use strict";
// AWS status panel + VNC intake browser gate - REAL browser against the REAL dashboard code (uvicorn started by this script).
// Label for the report: REAL BROWSER + REAL BACKEND ROUTES, FICTIONAL credentials, FICTIONAL targets.
// Nothing here calls a model, AWS, a VNC server or a remote desktop. The AWS credentials file is a temp file of fictional values; the
// "Test model" button is only checked for its confirmation prompt (declined). Every request to another origin is aborted and fails the gate.
//
// Env (all required):
//   GATE_PY         python that can run the dashboard (fastapi, uvicorn, boto3, pydantic-settings, ...)
//   GATE_TREE       repository root holding src/ and templates/
//   GATE_EDGE       msedge.exe / chrome.exe
//   GATE_PW_MODULE  path to playwright-core
//   GATE_PORT       optional (default 18197)
const assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), cp = require("node:child_process"), http = require("node:http");
const need = (k) => { if (!process.env[k]) { console.error("BLOCKED: set " + k); process.exit(78); } return process.env[k]; };
const PY = need("GATE_PY"), TREE = need("GATE_TREE"), EDGE = need("GATE_EDGE"), PWM = need("GATE_PW_MODULE"), PORT = process.env.GATE_PORT || "18197";
const {chromium} = require(PWM);
const BASE = "http://127.0.0.1:" + PORT;
const log = (m) => console.log(m);
const KEY_OLD = "FAKEGATEKEYOLD001", SEC_OLD = "gate/secret/OLD/0123456789abcdefghijklmnopqrstuv", TOK_OLD = "gate-token-OLD-" + "x".repeat(40);
const KEY_NEW = "FAKEGATEKEYNEW002", SEC_NEW = "gate/secret/NEW/0123456789abcdefghijklmnopqrstuv", TOK_NEW = "gate-token-NEW-" + "y".repeat(40);
const VNC_PW = "pw-g8x";
const SECRETS = [KEY_OLD, SEC_OLD, TOK_OLD, KEY_NEW, SEC_NEW, TOK_NEW, VNC_PW];
const stamp = (seconds) => new Date(Date.now() + seconds * 1000).toISOString().replace(/\.\d+Z$/, "Z");
const creds = (k, s, t, ttl) => "[default]\naws_access_key_id = " + k + "\naws_secret_access_key = " + s + "\naws_session_token = " + t + "\nexpiration = " + stamp(ttl) + "\n";

function atomicWrite(file, text) {
  const tmp = file + ".tmp" + process.pid;
  fs.writeFileSync(tmp, text, {mode: 0o600});
  fs.renameSync(tmp, file);                       // new inode, like an external refresher
  const old = new Date(Date.now() - 5000); fs.utimesSync(file, old, old);
}
function waitHttp(url, ms) {
  const end = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const tick = () => http.get(url, (r) => { r.resume(); resolve(r.statusCode); }).on("error", () => { if (Date.now() > end) reject(new Error("dashboard did not start")); else setTimeout(tick, 400); });
    tick();
  });
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nrdp-gate-"));
  for (const d of ["reports", "specs", "secrets", "state", "manuals", "guidance"]) fs.mkdirSync(path.join(root, d), {recursive: true});
  const credFile = path.join(root, "credentials"), confFile = path.join(root, "config");
  fs.writeFileSync(confFile, "[default]\nregion = us-west-2\n");
  atomicWrite(credFile, creds(KEY_OLD, SEC_OLD, TOK_OLD, 1800));
  const env = Object.assign({}, process.env, {
    PYTHONPATH: path.join(TREE, "src"), PYTHONDONTWRITEBYTECODE: "1", PYTHONIOENCODING: "utf-8",
    DASHBOARD_HOST: "127.0.0.1", DASHBOARD_PORT: PORT, DASHBOARD_AUTH_TOKEN: "viewer-token", DASHBOARD_AUTH_OPERATOR_TOKEN: "operator-token", DASHBOARD_SHARED_OPERATOR_MODE: "true",
    DASHBOARD_REPORTS_DIR: path.join(root, "reports"), DASHBOARD_SPECS_DIR: path.join(root, "specs"), DASHBOARD_SECRETS_DIR: path.join(root, "secrets"), TESTS_MANUALS_DIR: path.join(root, "manuals"),
    DASHBOARD_AUTHORING_STATE_ROOT: path.join(root, "state"), DASHBOARD_WIZARD_STATE_ROOT: path.join(root, "state"), DASHBOARD_AUTHORING_GUIDANCE_ROOT: path.join(root, "guidance"),
    DASHBOARD_AUTHORING_SHARED_CREDENTIALS_FILE: credFile, DASHBOARD_AUTHORING_SHARED_CONFIG_FILE: confFile, DASHBOARD_AUTHORING_PROFILE: "default",
    DASHBOARD_AUTHORING_MODEL_ID: "gate-model-id", DASHBOARD_AUTHORING_REGION: "us-west-2", DASHBOARD_AUTHORING_REFINEMENT_ENABLED: "true",
    AWS_ACCESS_KEY_ID: "FAKEINHERITED000", AWS_SECRET_ACCESS_KEY: "inherited-secret-must-not-win",   // inherited environment keys must never be used
    ORCHESTRATOR_COOKIE_CONFIG: path.join(root, "state", "runtime.json"),
  });
  const server = cp.spawn(PY, ["-m", "uvicorn", "dashboard.app:app", "--host", "127.0.0.1", "--port", PORT, "--log-level", "warning"], {cwd: TREE, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true});
  let serverOut = ""; server.stdout.on("data", (d) => { serverOut += d; }); server.stderr.on("data", (d) => { serverOut += d; });
  const killServer = () => { try { if (process.platform === "win32") cp.execFileSync("taskkill", ["/PID", String(server.pid), "/T", "/F"], {stdio: "ignore", windowsHide: true}); else server.kill("SIGTERM"); } catch (_) {} };
  process.on("exit", killServer);
  try { await waitHttp(BASE + "/dashboard", 60000); } catch (e) { console.error(serverOut.slice(-3000)); throw e; }

  const external = [], pageErrors = [], responses = [], apiCalls = [];
  const browser = await chromium.launch({executablePath: EDGE, headless: true, args: ["--no-sandbox", "--disable-gpu"]});
  try {
    const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}});
    const page = await ctx.newPage();
    page.on("pageerror", (e) => pageErrors.push(e.message));
    const dialogs = []; page.on("dialog", (d) => { dialogs.push(d.message()); d.dismiss(); });
    page.on("request", (r) => { const u = new URL(r.url()); if (u.origin === BASE && u.pathname.startsWith("/api/")) apiCalls.push(r.method() + " " + u.pathname); });
    page.on("response", async (r) => { try { if (new URL(r.url()).origin === BASE) responses.push(r.url() + " " + (await r.text()).slice(0, 300000)); } catch (_) {} });
    await page.route("**/*", (route) => { if (new URL(route.request().url()).origin !== BASE) { external.push(route.request().url()); return route.abort(); } return route.continue(); });
    await page.goto(BASE + "/dashboard");

    // ---------------------------------------------------------------- AWS
    await page.locator("#aws-badge").waitFor({state: "visible", timeout: 30000});
    await page.waitForFunction(() => /AWS: valid/.test(document.getElementById("aws-badge").textContent), null, {timeout: 20000});
    const badge1 = (await page.locator("#aws-badge").textContent()).trim();
    assert.match(badge1, /^AWS: valid · (2\d|3\d|1\d) min$/);
    await page.locator("#aws-badge").click();
    const panel1 = await page.locator("#aws-panel").textContent();
    for (const needle of ["shared credentials file, re-read on change", credFile, "Profile: default", "Region: us-west-2", "Model id: gate-model-id", "Expired credentials", "Upstream renewal failed", "Access denied", "Network"]) assert(panel1.includes(needle), "panel shows: " + needle);
    assert(!/Expires \(UTC\): (unknown)?$/m.test(panel1));
    assert(apiCalls.every((c) => c !== "POST /api/v1/aws/test-model") && !apiCalls.some((c) => c.startsWith("POST /api/v1/aws/")), "opening the panel makes no POST (no reload, no model call)");
    log("PASS AWS badge '" + badge1 + "' and panel: provider, source path, profile, region, model id, failure-kind legend; read-only on open");

    // rotation on disk (atomic replace, new inode) -> Reload credentials, no restart
    const inodeBefore = fs.statSync(credFile).ino;
    atomicWrite(credFile, creds(KEY_NEW, SEC_NEW, TOK_NEW, 3500));
    await page.locator("#aws-panel button", {hasText: "Reload credentials"}).click();
    await page.waitForFunction(() => /AWS: valid · (5\d|4\d) min/.test(document.getElementById("aws-badge").textContent), null, {timeout: 20000});
    const status = await page.evaluate(() => fetch("/api/v1/aws/status").then((r) => r.json()));
    assert(status.credential_changes >= 2 && status.last_failure === null && status.state === "valid", JSON.stringify(status).slice(0, 300));
    log("PASS rotation (new inode: " + (fs.statSync(credFile).ino !== inodeBefore) + ") picked up by 'Reload credentials' without a restart; badge now " + (await page.locator("#aws-badge").textContent()).trim());

    // a broken (half-written) file keeps the previous good credentials and reports the failure
    fs.writeFileSync(credFile, "[default]\naws_access_key_id = " + KEY_OLD + "\n");
    const oldT = new Date(Date.now() - 5000); fs.utimesSync(credFile, oldT, oldT);
    await page.locator("#aws-panel button", {hasText: "Reload credentials"}).click();
    await page.waitForFunction(() => /Last refresh failure: incomplete/.test(document.getElementById("aws-panel").textContent), null, {timeout: 20000});
    assert.match(await page.locator("#aws-badge").textContent(), /AWS: valid/);
    log("PASS a half-written file is rejected ('Last refresh failure: incomplete'); previous good credentials stay in use (badge still valid)");
    atomicWrite(credFile, creds(KEY_NEW, SEC_NEW, TOK_NEW, 3400));
    await page.locator("#aws-panel button", {hasText: "Reload credentials"}).click();
    await page.waitForFunction(() => !/Last refresh failure/.test(document.getElementById("aws-panel").textContent), null, {timeout: 20000});

    // expired file -> distinct EXPIRED state with the migration/renewal warning text path
    atomicWrite(credFile, creds(KEY_OLD, SEC_OLD, TOK_OLD, -600));
    await page.locator("#aws-panel button", {hasText: "Reload credentials"}).click();
    await page.waitForFunction(() => /AWS: EXPIRED/.test(document.getElementById("aws-badge").textContent), null, {timeout: 20000});
    assert.equal(await page.locator("#aws-badge").getAttribute("data-state"), "error");
    log("PASS an expired file shows 'AWS: EXPIRED' (error state)");
    atomicWrite(credFile, creds(KEY_NEW, SEC_NEW, TOK_NEW, 3300));
    await page.locator("#aws-panel button", {hasText: "Reload credentials"}).click();
    await page.waitForFunction(() => /AWS: valid/.test(document.getElementById("aws-badge").textContent), null, {timeout: 20000});

    // model test: confirmation is required; declining makes no request
    const before = apiCalls.length;
    await page.locator("#aws-panel button", {hasText: "Test model"}).click();
    await page.waitForTimeout(300);
    assert(dialogs.some((m) => /ONE small Bedrock call/.test(m)), "a confirmation prompt was shown");
    assert(!apiCalls.slice(before).some((c) => /test-model/.test(c)), "declined -> no model request");
    log("PASS 'Test model' asks for confirmation; declining sends nothing");
    await page.locator("#aws-panel button", {hasText: "Close"}).click();

    // ---------------------------------------------------------------- VNC intake
    const GOAL = ["VNC to 192.0.2.47", "username: example-user", "password=" + VNC_PW, "", "Open Chrome on that desktop.", "Go to http://127.0.0.1:5004/.",
      "Expand the browser to cover the desktop.", "Verify active video streams.", "Leave the browser open and finish the automation."].join("\n");
    await page.locator("#new-project-btn").click();
    await page.locator("#wizard-intent").fill(GOAL);
    const dump0 = await page.evaluate(() => JSON.stringify({l: {...localStorage}, s: {...sessionStorage}}));
    assert(!dump0.includes(VNC_PW), "no password in browser storage while typing");
    const callsBefore = apiCalls.length;
    await page.locator("#wizard-step1-continue").click();
    await page.locator('[data-testid="procedure-connection-1"]').waitFor({timeout: 30000});
    const newCalls = apiCalls.slice(callsBefore);
    assert(newCalls.includes("POST /api/v1/authoring/wizard/procedures"), "local intake route used: " + newCalls.join(", "));
    assert(!newCalls.some((c) => /context-preview|plan-jobs/.test(c)), "the planning model routes were not called: " + newCalls.join(", "));
    const card = await page.locator('[data-testid="procedure-connection-1"]').textContent();
    assert.match(card, /Connection 1 · VNC/); assert.match(card, /192\.0\.2\.47:0 \(display 0, TCP 5900\)/); assert.match(card, /example-user \(recorded, not sent/);
    assert.equal(await page.locator('[data-testid="procedure-credential-chip-1"]').textContent(), "Password: Saved");
    assert.equal(await page.locator('[data-testid="procedure-certificate-chip-1"]').count(), 0); assert.equal(await page.locator("#procedure-cert-fetch-1").count(), 0);
    const dump1 = await page.evaluate(() => JSON.stringify({l: {...localStorage}, s: {...sessionStorage}, i: authoringState.wizardIntent}));
    assert(!dump1.includes(VNC_PW), "no password in browser storage after intake");
    assert.equal(await page.locator("#wizard-intent").count() === 0 ? "" : await page.locator("#wizard-intent").inputValue(), "", "goal text is cleared");
    assert(!(await page.content()).includes(VNC_PW), "no password anywhere in the page");
    log("PASS VNC goal read locally: VNC card (host:display, TCP port, username recorded-not-sent, password Saved, no certificate); model routes NOT called");

    // the draft survives a reload and resumes without asking for the password again
    await page.reload();
    await page.evaluate(() => { closeEditor(true); openNewProjectDialog(true); });
    await page.locator("#procedure-resume").click();
    await page.locator('[data-testid="procedure-connection-1"]').waitFor({timeout: 30000});
    assert.equal(await page.locator('input[type="password"]:visible').count(), 0, "resume does not ask for the password");
    assert.equal(await page.locator('[data-testid="procedure-credential-chip-1"]').textContent(), "Password: Saved");
    log("PASS resume after reload: connection and saved password restored, no password prompt");

    // create the project; it is a VNC project on disk; no credentials in it
    await page.locator('[data-testid="procedure-stage-project"]').click();
    await page.locator("#procedure-create-project").click();
    await page.locator("#procedure-project-name").filter({hasText: /^Project:/}).waitFor({timeout: 60000});
    const projectName = (await page.locator("#procedure-project-name").textContent()).replace(/^Project:\s*/, "").trim();
    const yaml = fs.readFileSync(path.join(root, "specs", projectName, "project.yaml"), "utf8");
    assert(yaml.includes('"type": "vnc"') && yaml.includes('"vnc_host_allowlist"') && !yaml.includes(VNC_PW) && !yaml.includes("example-user"), "project.yaml is a VNC target without credentials");
    const files = fs.readdirSync(path.join(root, "secrets"));
    const pwFile = files.find((f) => f.endsWith(".vnc.pw")); assert(pwFile, "a .vnc.pw reference was written: " + files.join(","));
    const raw = fs.readFileSync(path.join(root, "secrets", pwFile)); assert.equal(raw.length, 8, "VNC password file is the 8-byte obfuscated form"); assert(!raw.toString("latin1").includes(VNC_PW));
    log("PASS project '" + projectName + "' created as a VNC target; password stored as the 8-byte VNC-obfuscated file; no credential in project.yaml");

    // ambiguous / incomplete blocks: local field error, nothing sent to the planner
    await page.evaluate(() => { closeEditor(true); openNewProjectDialog(true); });
    await page.locator("#wizard-intent").fill("VNC to 192.0.2.47:5901\npassword=abc\n1. Open Chrome.");
    const c2 = apiCalls.length;
    await page.locator("#wizard-step1-continue").click();
    await page.locator("#wizard-intent-error").filter({hasText: /ambiguous/}).waitFor({timeout: 20000});
    assert.match(await page.locator("#wizard-intent-error").textContent(), /::5901/);
    assert.equal(await page.locator("#wizard-intent").getAttribute("aria-invalid"), "true");
    assert(!apiCalls.slice(c2).some((c) => /context-preview|plan-jobs/.test(c)), "ambiguous block not sent to the planner");
    log("PASS 'VNC to host:5901' is rejected locally as ambiguous with a field error; planner not contacted");

    await page.locator("#wizard-intent").fill("Please log in with password=hunter22 and open the console page");
    const c3 = apiCalls.length;
    await page.locator("#wizard-step1-continue").click();
    await page.waitForTimeout(500);
    assert(!apiCalls.slice(c3).some((c) => /\/authoring\//.test(c)), "credential-bearing prose caused NO authoring request at all: " + apiCalls.slice(c3).join(", "));
    assert.match(await page.locator("#wizard-step1-generation-status").textContent(), /credential/i);
    log("PASS credential-bearing prose is refused in the browser before any request (not forwarded to the model)");

    // ---------------------------------------------------------------- global invariants
    const allResponses = responses.join("\n");
    for (const s of SECRETS) assert(!allResponses.includes(s), "a secret value appeared in a server response: " + s.slice(0, 6) + "...");
    assert.deepEqual(external, [], "no request left this origin"); assert.deepEqual(pageErrors, [], "no page errors: " + pageErrors.join(" | "));
    log("PASS no credential value in any of " + responses.length + " server responses; no external request; no page error");
    log("GATE_RESULT=PASS (real browser + real dashboard routes; fictional credentials; no model, AWS, VNC or RDP contact)");
  } finally {
    await browser.close();
    killServer();
    try { fs.rmSync(root, {recursive: true, force: true}); } catch (_) {}
  }
}
main().catch((e) => { console.error("GATE_RESULT=FAIL " + (e && e.stack || e)); process.exit(1); });
