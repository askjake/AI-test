"""NRDP-1 procedure UI contract: static assertions on templates/dashboard/index.html plus the
production-JavaScript stub-DOM suite (tests/js/procedure_ui.test.js) when Node.js is available."""
from __future__ import annotations

from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
START = "// <nrdp-procedure-ui>"
END = "// </nrdp-procedure-ui>"
REAL_SCENARIO_HOSTS = ("10.70.115.36", "172.20.33.215")
GUARD = re.compile(r"procedureCurrent\(epoch|epoch !== authoringState\.wizardEpoch|epoch === authoringState\.wizardEpoch")
STATE_TOUCH = re.compile(r"authoringState|\bui\.|render|Pointer|procedureApply")


def _page() -> str:
    return (ROOT / "templates" / "dashboard" / "index.html").read_text(encoding="utf-8")


def _region() -> str:
    page = _page()
    assert page.count(START) == 1 and page.count(END) == 1
    return page[page.index(START): page.index(END) + len(END)]


def _top_level_functions(region: str) -> dict[str, str]:
    """Split the region at top-level declarations (the region keeps one declaration per column-0 line)."""
    out: dict[str, str] = {}
    starts = [m for m in re.finditer(r"(?m)^(async function|function|var) (\w+)", region)]
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(region)
        out[match.group(2)] = (match.group(1), region[match.start(): end])
    return out


def test_region_never_writes_innerhtml_and_escapes_example():
    region = _region()
    assert "innerHTML" not in region
    page = _page()
    assert "esc(PROCEDURE_EXAMPLE_GOAL)" in page


def test_browser_storage_holds_only_the_draft_id():
    region = _region()
    page = _page()
    assert "sessionStorage" not in region
    setters = re.findall(r"localStorage\.setItem\(([^,]+),", region)
    assert setters == ["PROCEDURE_POINTER_KEY"]
    assert page.count("'cookie-last-procedure-id'") == 1  # only the constant definition
    assert "localStorage.setItem('cookie-last-procedure-id'" not in page
    # The pointer is set from the server-issued id, never from the goal text.
    assert "procedureSetPointer(result.id)" in region
    intake = _top_level_functions(region)["buildFullProcedure"][1]
    assert "input.value = '';" in intake


def test_passwords_are_write_only_cleared_and_never_kept_in_state():
    region = _region()
    assert "type: 'password', autocomplete: 'new-password'" in region
    assert not re.search(r"authoringState\.\w*[Pp]assword", region)
    assert not re.search(r"\bui\.\w*[Pp]assword", region)
    collect = _top_level_functions(region)["procedureCollectPasswords"][1]
    assert "input.value = '';" in collect
    save = _top_level_functions(region)["procedureSaveConnections"][1]
    # Passwords are collected (and inputs cleared) before the first await.
    assert save.index("procedureCollectPasswords()") < save.index("await apiOp(")
    page = _page()
    reset = page[page.index("function resetAuthoringState()"): page.index("function resetAuthoringState()") + 600]
    assert "procedureClearPasswordInputs();" in reset
    save_draft = page[page.index("function saveWizardDraft()"): page.index("function startFreshWizard()")]
    assert "procedure" not in save_draft.lower()


def test_every_async_handler_captures_and_checks_the_epoch():
    functions = _top_level_functions(_region())
    async_functions = {name: body for name, (kind, body) in functions.items() if kind == "async function"}
    assert set(async_functions) >= {
        "procedureSaveConnections", "procedureFetchCertificate", "procedureUseCertificate", "procedureCreateProject",
        "procedureStartRun", "procedureCancelRun", "procedureAckCheckpoint", "saveProcedureAndReview",
        "buildFullProcedure", "reopenFullProcedure",
    }
    for name, body in async_functions.items():
        assert "const epoch = authoringState.wizardEpoch" in body, name
        lines = body.splitlines()
        for index, line in enumerate(lines):
            if "await " in line:
                tail = line.split("await ", 1)[1]
                for follower in lines[index + 1:]:
                    if GUARD.search(follower):
                        break
                    assert not STATE_TOUCH.search(follower), (name, follower)
                else:
                    pytest.fail(f"{name}: await without a following epoch guard: {tail}")
            if re.search(r"catch \(error\) \{\s*$", line):
                assert GUARD.search(lines[index + 1]), (name, lines[index + 1])
    tick = _region()[_region().index("async function tick()"):]
    tick = tick[: tick.index("tick();")]
    assert tick.count("await o.fetchRun") == 1
    assert tick.count("if (!alive()) return;") >= 3


def test_start_fresh_bumps_epoch_clears_pointer_and_stops_polling_only():
    page = _page()
    region = _region()
    fresh = page[page.index("function startFreshWizard()"): page.index("function restoreWizardDraft()")]
    assert "procedureStartFresh();" in fresh
    start_fresh = _top_level_functions(region)["procedureStartFresh"][1]
    for call in ("procedureStopPolling()", "procedureClearPointer()", "procedureClearPasswordInputs()", ".reset()"):
        assert call in start_fresh
    assert "DELETE" not in region and "method: 'DELETE'" not in region
    reset = page[page.index("function resetAuthoringState()"): page.index("function resetAuthoringState()") + 600]
    assert "authoringState.wizardEpoch = (authoringState.wizardEpoch || 0) + 1;" in reset
    assert "procedureStopPolling();" in reset
    show = _top_level_functions(region)["showProcedureStage"][1]
    assert "if (stage !== 'project') procedureStopPolling();" in show


def test_required_ids_testids_and_routes_exist():
    region = _region()
    for ident in (
        "procedure-start-fresh", "procedure-save-connections", "procedure-next", "procedure-conn-status", "procedure-conn-errors",
        "procedure-cert-fetch-1", "procedure-cert-use-1", "procedure-cert-candidate-1", "procedure-readiness",
        "procedure-instructions", "procedure-review", "procedure-next-project", "procedure-create-project", "procedure-create-reason",
        "procedure-rebuild-project", "procedure-project-name", "procedure-project-warnings", "procedure-test-connection",
        "procedure-run-mode", "procedure-run-confirm", "procedure-run-start", "procedure-run-warning", "procedure-run-panel",
        "procedure-run-headline", "procedure-hop-list", "procedure-run-error", "procedure-run-cancel", "procedure-run-retry",
        "procedure-run-refresh", "procedure-run-evidence", "procedure-checkpoint", "procedure-checkpoint-note", "procedure-checkpoint-ack",
    ):
        assert "'" + ident + "'" in region, ident
    for pattern in ("'procedure-connection-' + c.order", "'procedure-credential-chip-' + c.order", "'procedure-certificate-chip-' + c.order",
                    "'procedure-predecessor-' + c.order", "'procedure-conn-' + c.order + '-password'", "'procedure-hop-' + row.order",
                    "'procedure-stage-' + item[0]", "'procedure-readiness-' + key"):
        assert pattern in region, pattern
    for route in ("'/connections'", "'/certificate/probe'", "'/project'", "'/runs'", "'/cancel'", "'/checkpoint'"):
        assert route in region, route
    assert "['project', 'Project']" in region
    assert "'Opened from: runner desktop'" in region
    assert "', using Windows Remote Desktop'" in region
    assert "' — Windows Remote Desktop inside '" in region
    assert "'I completed this'" in region


def test_example_goal_is_fictional_and_shows_the_format():
    region = _region()
    example = region[region.index("var PROCEDURE_EXAMPLE_GOAL"):]
    for host in REAL_SCENARIO_HOSTS:
        assert host not in example
    for fragment in ("'RDP to 192.0.2.10'", "username: ", "password: Example-Only-Not-Real-1", "RDP to 198.51.100.20", "'1. ", "'4. "):
        assert fragment in example
    assert 'id="procedure-example"' in _page() and "See an example" in _page()


def test_full_run_requires_typed_project_name_and_checkpoints_never_auto_ack():
    region = _region()
    assert "if (str(typed).trim() !== projectName) return {ok: false" in region
    assert "confirm_phrase: projectName" in region
    # The only checkpoint POST is inside the click handler procedureAckCheckpoint.
    assert region.count("'/checkpoint'") == 1
    ack = _top_level_functions(region)["procedureAckCheckpoint"][1]
    assert "'/checkpoint'" in ack
    assert "procedureAckCheckpoint" in _top_level_functions(region)["renderProcedureRunPanel"][1]


def test_browser_gate_script_is_local_only():
    gate = (ROOT / "scripts" / "run_procedure_ui_browser_gate.js").read_text(encoding="utf-8")
    assert "external-request" in gate and "route.abort()" in gate
    assert "PROCEDURE_UI_BROWSER_GATE=PASS" in gate
    for host in REAL_SCENARIO_HOSTS:
        assert host not in gate


def _node_executable(environ=None, which=None):
    """The Node binary to run: ``NRDP_NODE`` (set by the isolated gate to the REAL binary) if it is a usable
    absolute file, otherwise whatever ``node`` is on PATH.  Returns None when there is none."""
    import os
    import shutil

    environ = os.environ if environ is None else environ
    explicit = environ.get("NRDP_NODE")
    if explicit and os.path.isabs(explicit) and os.path.isfile(explicit) and os.access(explicit, os.X_OK):
        return explicit
    return (which or shutil.which)("node", path=environ.get("PATH"))


def test_node_executable_prefers_the_gate_resolved_binary_over_a_path_shim(tmp_path):
    import os
    real = tmp_path / "real-node"
    real.write_text("#!/bin/sh\n")
    os.chmod(real, 0o755)
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    shim = shim_dir / "node"
    shim.write_text("#!/bin/sh\n")
    os.chmod(shim, 0o755)
    env = {"PATH": str(shim_dir), "NRDP_NODE": str(real)}
    assert _node_executable(env) == str(real)
    assert _node_executable({"PATH": str(shim_dir)}, which=lambda name, path=None: str(shim)) == str(shim)
    # an unusable NRDP_NODE (relative, missing, directory) is ignored, never trusted blindly
    for bad in ("node", str(tmp_path / "missing"), str(tmp_path)):
        assert _node_executable({"PATH": str(shim_dir), "NRDP_NODE": bad}, which=lambda name, path=None: "FALLBACK") == "FALLBACK"
    assert _node_executable({"PATH": ""}, which=lambda name, path=None: None) is None


def test_production_javascript_stub_dom_suite_passes():
    # Includes the VNC-through-SSH host-key review suite (tests/js/vnc_ssh_host_key_ui.test.js).
    assert (ROOT / "tests/js/vnc_ssh_host_key_ui.test.js").is_file(), "host-key review suite is part of the release JS gate"
    import subprocess

    node = _node_executable()
    if node is None:
        pytest.skip("Node.js is unavailable for the procedure UI stub-DOM suite")
    # Fail in seconds, and say WHY, if node cannot even start in this (possibly isolated-HOME) environment,
    # instead of timing out silently while a launcher shim looks for its toolchain.
    try:
        probe = subprocess.run([node, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=20, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail("node (%s) did not start within 20 s in this environment; a launcher shim that resolves its "
                    "toolchain from HOME cannot run here. The isolated gate resolves the real binary and passes it "
                    "through NRDP_NODE." % node)
    assert probe.returncode == 0, probe.stdout
    try:
        completed = subprocess.run(
            [node, "--test", "tests/js/procedure_ui.test.js", "tests/js/vnc_ssh_host_key_ui.test.js"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail("node --test timed out after 60 s. Partial output:\n%s" % ((exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")))
    assert completed.returncode == 0, completed.stdout
