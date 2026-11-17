"""Connection-only qualification (review blocker B1) -- NRDP-1 b4r6.

This release starts CONNECTION TESTS ONLY for rdp-chain procedure projects.  Operating execution
(read_only_check and full_run) is refused in three independent places:

  1. dashboard.procedure_runs.start_run      -- before anything is written or launched
  2. orchestrator.chain_runtime.read_run_request -- whatever control file reaches the runner
  3. orchestrator.chain_hooks._enforce_connection_only -- re-checked where the session is built

read_only_check is refused too: a "read-only" step is only read-only in INTENT, it still types and
clicks, so it can act on the wrong desktop.

All fixtures here are fictional; no target, model or network is contacted.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace as NS

import pytest

from dashboard import procedure_runs as pr
from orchestrator import chain_hooks
from orchestrator import chain_runtime as cr

PROJ = "foo-service-maintenance-01234567"
RID = "trig_20261029T120000_feedface"


# ----------------------------------------------------------------- policy surface
def test_the_policy_is_a_source_constant_with_no_environment_override(monkeypatch):
    """Requirement: no environment-variable bypass and no hidden enable switch."""
    assert cr.CONNECTION_ONLY is True
    assert pr.CONNECTION_ONLY is True
    assert set(cr.OPERATING_MODES) == {"read_only_check", "full_run"}
    # Nothing in the environment can turn operating execution back on.
    for var in ("ORCHESTRATOR_CONNECTION_ONLY", "CONNECTION_ONLY", "ORCHESTRATOR_ALLOW_FULL_RUN",
                "ORCHESTRATOR_OPERATING_MODES", "NRDP_ALLOW_OPERATING"):
        monkeypatch.setenv(var, "0")
    monkeypatch.setenv("ORCHESTRATOR_CONNECTION_ONLY", "false")
    assert cr.operating_execution_allowed("full_run") is False
    assert cr.operating_execution_allowed("read_only_check") is False
    assert cr.operating_execution_allowed("connection_test") is True
    # and the source really does not read any such variable
    src = open(cr.__file__, encoding="utf-8").read()
    head = src[src.index("CONNECTION_ONLY = True"):src.index("def operating_execution_allowed")]
    assert "environ" not in head and "getenv" not in head


# ----------------------------------------------------------------- runtime funnel
def _control(tmp_path, body, project=PROJ, rid=RID):
    d = tmp_path / project / ".nrdp-runs" / rid / "control"
    d.mkdir(parents=True, exist_ok=True)
    (d / "run_request.json").write_text(json.dumps(body))
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _posix_view(monkeypatch):
    """Present the control files as dashboard-owned 0644/0755 objects on any OS."""
    if os.name == "posix":
        return
    def fake(path):
        real = os.lstat(path)
        return NS(st_mode=real.st_mode & ~0o022, st_nlink=real.st_nlink, st_uid=1000)
    monkeypatch.setattr(cr, "_LSTAT", fake)


@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
def test_a_fully_valid_trusted_operating_request_is_refused_by_the_runtime(tmp_path, mode):
    """Everything the runtime asks for is present: trusted file, right project, bound run id,
    recorded confirmation.  It is still refused, and the request stays visible."""
    root = _control(tmp_path, {"mode": mode, "project": PROJ, "chain": True,
                               "confirm_recorded": True, "run_id": RID})
    req = cr.read_run_request(root, PROJ, RID)
    assert req.mode == cr.CONNECTION_TEST
    assert req.requested_mode == mode              # never silently reported as the requested run
    assert "connection-only" in req.reason
    # and the selection layer runs nothing for the effective mode
    steps = [{"order": 1, "title": "a", "mutating": False, "read_only_ok": True},
             {"order": 2, "title": "b", "mutating": True}]
    to_run, skipped = cr.select_steps(steps, req.mode)
    assert to_run == [] and len(skipped) == 2


def test_the_m2_rules_still_report_their_own_reasons_first(tmp_path):
    """The policy gate must not mask the control-trust diagnostics."""
    foreign = _control(tmp_path, {"mode": "full_run", "project": "somewhere-else", "chain": True,
                                  "confirm_recorded": True, "run_id": RID}, project="p-a")
    r = cr.read_run_request(foreign, "p-a", RID)
    assert r.mode == cr.CONNECTION_TEST and "another project" in r.reason

    wrong_run = _control(tmp_path, {"mode": "full_run", "project": "p-b", "chain": True,
                                    "confirm_recorded": True, "run_id": "trig_other"}, project="p-b")
    r = cr.read_run_request(wrong_run, "p-b", RID)
    assert r.mode == cr.CONNECTION_TEST and "another run id" in r.reason

    unconfirmed = _control(tmp_path, {"mode": "full_run", "project": "p-c", "chain": True,
                                      "run_id": RID}, project="p-c")
    r = cr.read_run_request(unconfirmed, "p-c", RID)
    assert r.mode == cr.CONNECTION_TEST and "without recorded confirmation" in r.reason


# --------------------------------------- generic / direct trigger, CLI and scheduled execution
@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
def test_a_generic_or_direct_trigger_cannot_bypass_the_restriction(tmp_path, monkeypatch, mode):
    """The generic trigger supplies the run id through ORCHESTRATOR_TRIGGER_ID rather than an
    argument.  That path reaches the same funnel and is refused identically."""
    root = _control(tmp_path, {"mode": mode, "project": PROJ, "chain": True,
                               "confirm_recorded": True, "run_id": RID})
    monkeypatch.setenv(cr.TRIGGER_ENV, RID)
    req = cr.read_run_request(root, PROJ, None)          # trigger id resolved from the environment
    assert req.mode == cr.CONNECTION_TEST and req.requested_mode == mode


@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
def test_cli_and_scheduled_execution_cannot_bypass_the_restriction(mode):
    """The CLI (orchestrator.runner) and the scheduler never pass a mode: they let the runner read
    the control file, so they inherit the funnel.  chain_hooks additionally re-checks whatever mode
    it is handed, which is what protects a caller that constructs a RunRequest itself.
    """
    handed = cr.RunRequest(mode=mode, confirmed=True, source="request",
                           reason="", run_dir="/tmp/x", requested_mode=mode)
    out = chain_hooks._enforce_connection_only(handed)
    assert out.mode == cr.CONNECTION_TEST
    assert out.requested_mode == mode and "connection-only" in out.reason
    # an already-safe request is passed through untouched
    safe = cr.RunRequest(mode=cr.CONNECTION_TEST, source="request", run_dir="/tmp/x")
    assert chain_hooks._enforce_connection_only(safe) is safe


# ----------------------------------------------------------------- dashboard API
@pytest.fixture
def api(tmp_path):
    calls = {"launch": [], "cancel": []}
    pr.configure(reports_root=lambda: str(tmp_path),
                 launch=lambda p: calls["launch"].append(p) or RID,
                 cancel=lambda p: calls["cancel"].append(p) or {"status": "cancelled"})
    yield NS(root=tmp_path, calls=calls)
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch,
                 cancel=pr._default_cancel)


@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
@pytest.mark.parametrize("phrase", [None, "", PROJ, PROJ.upper(), "  " + PROJ + "  "])
def test_no_confirmation_phrase_can_start_an_operating_run(api, mode, phrase):
    with pytest.raises(pr.RunError) as exc:
        pr.start_run(NS(id="x"), PROJ, mode, phrase)
    assert exc.value.status_code == 409
    assert api.calls["launch"] == []                     # the runner was never launched
    assert not list(api.root.rglob("run_request.json"))  # nothing was written


@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
def test_check_preconditions_also_refuses(mode):
    with pytest.raises(pr.RunError) as exc:
        pr.check_preconditions(project={"project_name": PROJ}, last_test=None,
                               config_hash="h", mode=mode)
    assert exc.value.status_code == 409


def test_a_connection_test_is_still_accepted_and_written(api):
    assert pr.start_run(NS(id="x"), PROJ, "connection_test", None) == {"run_id": RID}
    assert api.calls["launch"] == [PROJ]
    body = json.loads((api.root / PROJ / ".nrdp-runs" / RID / "control" / "run_request.json").read_text())
    assert body["mode"] == "connection_test" and body["run_id"] == RID
    assert body["steps_allowed"] is False


def test_cancellation_still_works_for_a_connection_test(api):
    pr.start_run(NS(id="x"), PROJ, "connection_test", None)
    result = pr.cancel_run(PROJ, RID)
    # cancel_run's real contract: {"run_id", "cancelled", "detail"}
    assert result["cancelled"] is True and result["run_id"] == RID
    assert result["detail"] == {"status": "cancelled"}
    assert api.calls["cancel"] == [PROJ]
    # the runner-facing cancel request really was written into the run's control dir
    body = json.loads((api.root / PROJ / ".nrdp-runs" / RID / "control" / "cancel_request.json").read_text())
    assert body["run_id"] == RID and body["requested_at"]


# ----------------------------------------------------------------- unrelated projects untouched
def test_single_target_projects_are_unaffected(tmp_path):
    """The restriction is scoped to rdp-chain procedure execution.  A non-procedure project has no
    run_request at all and never consults this policy; its loader/runner path is unchanged."""
    # no control file anywhere: read_run_request is simply "no trigger id" / missing, as before
    assert cr.read_run_request(str(tmp_path), "ordinary-project", None).mode == cr.CONNECTION_TEST
    r = cr.read_run_request(str(tmp_path), "ordinary-project", "trig_nope")
    assert r.mode == cr.CONNECTION_TEST and "connection-only" not in r.reason
    # the step-selection library itself is untouched for non-procedure callers
    steps = [{"order": 1, "title": "a", "mutating": False, "read_only_ok": True}]
    assert cr.select_steps(steps, "read_only_check")[0] == steps
    assert cr.select_steps(steps, "full_run")[0] == steps


# ------------------------------------------- guard placement: every production entry path
#
# chain_runtime.run_chain_session is deliberately left as a PURE, unguarded library function so the
# step machinery stays unit-testable.  That is only acceptable while every PRODUCTION caller is
# guarded.  These tests pin that invariant structurally, so a new adapter cannot quietly reach
# operating steps.
def _module_source(mod):
    return open(mod.__file__, encoding="utf-8").read()


def test_every_production_caller_of_run_chain_session_is_guarded():
    """Enumerate the real callers from source and assert each one funnels through the guard."""
    import pathlib as _p
    from orchestrator import vnc_hooks
    src_root = _p.Path(chain_hooks.__file__).parent
    callers = sorted(
        f.name for f in src_root.glob("*.py")
        if "run_chain_session" in f.read_text(encoding="utf-8") and f.name != "chain_runtime.py")
    # If this list grows, the new module MUST obtain its RunRequest from the guarded funnel.
    assert callers == ["chain_hooks.py", "vnc_hooks.py"], (
        "a new production caller of run_chain_session appeared: %s -- it must take its RunRequest "
        "from chain_hooks._await_request (or apply _enforce_connection_only itself)" % callers)
    # chain_hooks applies the guard inside its own request funnel ...
    assert "_enforce_connection_only(cr.read_run_request(" in _module_source(chain_hooks)
    # ... and vnc_hooks reuses that exact funnel rather than reading the request itself.
    vnc_src = _module_source(vnc_hooks)
    assert "_await_request" in vnc_src
    assert "read_run_request" not in vnc_src, (
        "vnc_hooks must not read the run request directly; it must use the guarded funnel")


@pytest.mark.parametrize("mode", ["read_only_check", "full_run"])
def test_the_shared_request_funnel_refuses_operating_modes(tmp_path, mode):
    """Both production adapters obtain their RunRequest from chain_hooks._await_request."""
    root = _control(tmp_path, {"mode": mode, "project": PROJ, "chain": True,
                               "confirm_recorded": True, "run_id": RID})
    req = chain_hooks._await_request(root, PROJ, RID, wait=0.0, sleep=lambda s: None,
                                    clock=lambda: 0.0)
    assert req.mode == cr.CONNECTION_TEST
    assert req.requested_mode == mode
    assert "connection-only" in req.reason


def test_run_chain_session_itself_stays_an_unguarded_library_function():
    """Documents the deliberate design: the policy lives at the entry paths, not in the machinery.

    If this ever changes, the step-machinery tests (and the explicit lifts in
    tests/test_vnc_session.py) must be revisited together with it.
    """
    runtime_src = _module_source(cr)
    body = runtime_src[runtime_src.index("def run_chain_session("):]
    assert "CONNECTION_ONLY" not in body[:body.index("def ", 30)] if "def " in body[30:] else True


# ------------------------------------------- UI / backend capability agreement
def test_the_backend_capability_shape_is_what_the_ui_contract_expects():
    """procedure_runs.capability() must carry exactly the keys the dashboard JS normalises."""
    cap = pr.capability()
    assert set(cap) == {"connection_only", "allowed_modes", "disabled_modes", "reason", "browser_verify"}      # CP43 adds the browser_verify block
    assert cap["connection_only"] is True
    assert cap["allowed_modes"] == ["connection_test"]
    assert sorted(cap["disabled_modes"]) == ["browser_verify", "full_run", "read_only_check"]
    assert isinstance(cap["reason"], str) and cap["reason"]
    # the advertised set and the enforced set cannot disagree
    for mode in cap["disabled_modes"]:
        with pytest.raises(pr.RunError) as exc:
            pr.start_run(NS(id="x"), PROJ, mode, PROJ)
        assert exc.value.status_code == 409
    assert pr.allowed_modes() == ("connection_test",)


def test_the_dashboard_view_advertises_the_capability():
    """The run surface the UI renders from must include the backend capability."""
    from dashboard import procedure_routes_v2 as routes
    src = open(routes.__file__, encoding="utf-8").read()
    assert "run_capability" in src and "procedure_runs.capability()" in src


def test_the_ui_falls_back_to_connection_only_when_the_capability_is_absent():
    """Fail-closed default lives in the shipped template, not only in the test."""
    import pathlib as _p
    tpl = _p.Path(pr.__file__).parents[2] / "templates" / "dashboard" / "index.html"
    js = tpl.read_text(encoding="utf-8")
    assert "function runCapability(" in js
    # a missing flag must read as connection-only (!== false), never as "false by default"
    assert "connection_only: o.connection_only !== false" in js
    assert "['connection_test']" in js or '["connection_test"]' in js


# ------------------------------------------- refusal is terminal and understandable
def test_the_refusal_message_is_specific_and_actionable():
    assert "connection tests only" in pr.CONNECTION_ONLY_MESSAGE
    assert "wrong desktop" in pr.CONNECTION_ONLY_MESSAGE          # says WHY
    assert "Run a connection test instead" in pr.CONNECTION_ONLY_MESSAGE   # says WHAT TO DO
    assert "connection-only" in cr.CONNECTION_ONLY_REASON


def test_a_refused_operating_run_is_never_reported_as_a_completed_procedure(tmp_path):
    """The outcome must stay visibly downgraded so a refusal cannot read as a successful run."""
    root = _control(tmp_path, {"mode": "full_run", "project": PROJ, "chain": True,
                               "confirm_recorded": True, "run_id": RID})
    req = cr.read_run_request(root, PROJ, RID)
    outcome = cr.ChainRunOutcome(status="passed", mode=req.mode,
                                 requested_mode=req.requested_mode,
                                 downgrade_reason=req.reason)
    data = outcome.as_dict()
    assert data["downgraded"] is True
    assert data["effective_mode"] == "connection_test" and data["requested_mode"] == "full_run"
    summary = chain_hooks._summary_text(outcome)
    assert "REQUESTED MODE WAS full_run" in summary
    assert "not a completed operating procedure" in summary
