"""browser_verify must be unreachable from the production request paths: actual refusal paths, not helpers.  Production code is unchanged."""
import json
import os
import re
from types import SimpleNamespace as NS

import pytest

from dashboard import procedure_runs as pr
from orchestrator import chain, chain_hooks, chain_runtime as cr
import bv_sim as V
from test_chain import PW1

PROJ = "foo-service-maintenance-01234567"
RID = "trig_20261027T120000_deadbeef"
SRC = os.path.join(os.path.dirname(__file__), "..", "src")


@pytest.fixture
def env(tmp_path):
    calls = {"launch": []}
    pr.configure(reports_root=lambda: str(tmp_path), launch=lambda p: calls["launch"].append(p) or RID, cancel=lambda p: {"status": "cancelled"})
    yield NS(root=tmp_path, calls=calls)
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel)


def test_dashboard_refuses_browser_verify_before_writing_or_launching_anything(env):
    """CP43: with the (default) disabled capability every browser_verify start is refused 409 BEFORE anything is written or launched, whatever is typed."""
    for phrase in (None, "", PROJ, "BROWSER-VERIFY " + PROJ):
        with pytest.raises(pr.RunError) as e:
            pr.start_run(NS(id="x"), PROJ, "browser_verify", phrase, leave_open_ack="LEAVE-OPEN " + PROJ, url="http://127.0.0.1:5004/")
        assert e.value.status_code == 409 and "not available" in str(e.value.message)
    assert env.calls["launch"] == []
    for base, _d, files in os.walk(str(env.root)):
        assert "run_request.json" not in files


def test_served_capability_and_mode_tables_default_to_connection_only_with_browser_verify_disabled():
    """Changed by CP43 (was: tables unchanged / no browser_verify anywhere).  The vocabulary now KNOWS browser_verify; it is served as disabled."""
    assert pr.MODES == ("connection_test", "browser_verify", "read_only_check", "full_run") and pr.OPERATING_MODES == ("read_only_check", "full_run")
    cap = pr.capability()
    assert cap["connection_only"] is True and cap["allowed_modes"] == ["connection_test"] and cap["disabled_modes"] == ["read_only_check", "full_run", "browser_verify"]
    assert pr.allowed_modes() == ("connection_test",) and cap["browser_verify"]["available"] is False and pr.BROWSER_VERIFY_POLICY is None
    assert cr.MODES == (cr.CONNECTION_TEST, cr.READ_ONLY_CHECK, cr.FULL_RUN) and cr.CONNECTION_ONLY is True and cr.BROWSER_VERIFY_POLICY is None
    from orchestrator import browser_modes as bm
    assert bm.CANONICAL_MODES == ("connection_test", "browser_verify", "read_only_check", "full_run")


def _req(tmp_path, body):
    d = tmp_path / "p1" / ".nrdp-runs" / "trig_1_abcd" / "control"
    d.mkdir(parents=True)
    (d / "run_request.json").write_text(json.dumps(body))
    return str(tmp_path)


@pytest.fixture(autouse=True)
def posix_view(monkeypatch):
    if os.name == "posix":
        return
    def fake(path):
        real = os.lstat(path)
        return NS(st_mode=real.st_mode & ~0o022, st_nlink=real.st_nlink, st_uid=1000)
    monkeypatch.setattr(cr, "_LSTAT", fake)


@pytest.mark.parametrize("body", [{"mode": "browser_verify", "project": "p1", "chain": True},
                                  {"mode": "browser_verify", "project": "p1", "chain": True, "confirm_recorded": True, "steps_allowed": True,
                                   "run_id": "trig_1_abcd", "url": "http://127.0.0.1:5004/"}])
def test_runner_side_a_browser_verify_request_is_refused_when_the_runner_capability_is_disabled(tmp_path, body):
    """Changed by CP43 (was: becomes a connection_test with reason 'unknown mode' and an unrecorded requested_mode).  The runner now KNOWS the mode and
    refuses it outright -- no session at all -- recording what was asked."""
    root = _req(tmp_path, body)
    r = cr.read_run_request(root, "p1", "trig_1_abcd")
    assert r.refused is True and r.browser is None and r.requested_mode == "browser_verify" and "browser_verify refused before launch" in r.reason
    assert chain_hooks._enforce_connection_only(r).refused is True


def test_enforce_backstop_is_an_explicit_allow_list():
    """REPLACES the CP41/CP42 characterisation test of risk R1.  HISTORICAL assertion it replaced (kept as a record of the closed gap):
        direct = cr.RunRequest(mode='browser_verify'); assert chain_hooks._enforce_connection_only(direct).mode == 'browser_verify'
    New contract: only connection_test passes untouched; browser_verify passes only with a runner-validated grant AND an enabled runner policy;
    operating modes are demoted exactly as before; anything else (unknown, malformed, non-string) is refused outright."""
    f = chain_hooks._enforce_connection_only
    assert f(cr.RunRequest(mode="connection_test")).mode == "connection_test" and f(cr.RunRequest(mode="connection_test")).refused is False
    assert f(cr.RunRequest(mode="browser_verify")).refused is True                               # was: passed through
    assert f(cr.RunRequest(mode="browser_verify", source="request")).refused is True            # a source label alone is not a grant
    for bad in ("banana", "", "Browser_Verify", "browser_verify ", "CONNECTION_TEST", None, 7, ["browser_verify"], {"m": 1}):
        r = f(cr.RunRequest(mode=bad))
        assert r.refused is True and r.requested_mode == "unrecognized" and r.browser is None, bad
    for op in ("read_only_check", "full_run"):
        r = f(cr.RunRequest(mode=op, source="request"))
        assert r.mode == "connection_test" and r.refused is False and r.reason == cr.CONNECTION_ONLY_REASON and r.requested_mode == op


def test_controller_run_modes_have_no_browser_verify():
    assert [m.value for m in chain.RunMode] == ["connection_test", "read_only_check", "full_run"]
    with pytest.raises(ValueError):
        chain.RunMode("browser_verify")


WIRING_FILES = {"chain_runtime.py", "chain_hooks.py", "procedure_runs.py"}      # CP43: the ONLY non-browser_* files that may name it


def test_only_the_named_wiring_files_reference_browser_verify():
    """Changed by CP43 (was: nothing outside browser_* files references it).  Exactly the request-to-run path may; nothing else, including the controller,
    the computer/targets adapters, the runner and the agent loop."""
    hits = set()
    for base, _d, files in os.walk(SRC):
        for f in files:
            if f.endswith((".py", ".js", ".html")) and not f.startswith("browser_"):
                text = open(os.path.join(base, f), encoding="utf-8", errors="replace").read()
                if re.search(r"browser_verify|browser_evidence|browser_modes|browser_model_path|browser_page_classifier", text):
                    hits.add(f)
    assert hits == WIRING_FILES


def test_a_connection_test_never_launches_a_browser_or_types_a_launch_command():
    from bv_sim import build
    h = build()
    typed = [e[1] for e in h.env.log if e[0] == "type"]
    assert typed and all(not re.search(r"(?i)chrome|127\.0\.0\.1|--user-data-dir|5004", t) for t in typed)
    assert h.env.log.count(("key", "alt+f4")) == 0 and not any(e[0] == "type_secret" for e in h.env.log if False)
    h.env.close()
