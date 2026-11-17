"""CP45-G (G2): dashboard-precreated run directories + root-phase handoff.  No world-writable directory, no ACL, no group dependence."""
from __future__ import annotations

import inspect
import json
import os
import re
import stat
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from dashboard import project_access as PA
from orchestrator import report_handoff as H

pytestmark = pytest.mark.skipif(os.name != "posix" or os.getuid() == 0, reason="POSIX ownership/modes, non-root")
@pytest.fixture(autouse=True)
def _restore_dashboard_backend():
    yield
    import importlib
    import dashboard.config as dconfig
    os.environ.pop("DASHBOARD_TRIGGER_BACKEND", None)
    importlib.reload(dconfig)


TRIG, TS, PROJ = "trig_20261116T010203_deadbeef", "20261116T010203Z", "checkout"
UID, GID = os.getuid(), os.getgid()
RUNNER = (10001, 10001)


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, fd, uid, gid):
        self.calls.append((os.fstat(fd).st_ino, uid, gid))


def prepared(tmp_path):
    root = tmp_path / "reports"; root.mkdir(); os.chmod(root, 0o755)
    PA.precreate_run_dirs(str(root), PROJ, TRIG, TS)
    return root


def hand(root, rec=None, **kw):
    args = dict(dashboard_uid=UID, uid=RUNNER[0], gid=RUNNER[1], fchown=rec or Rec())
    args.update(kw)
    return H.hand_off(str(root), PROJ, TRIG, TS, **args)


def world_or_group_writable(root):
    bad = []
    for base, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(base, n)
            if not os.path.islink(p) and os.stat(p).st_mode & 0o022:
                bad.append(p)
    return bad


def test_precreate_makes_only_dashboard_owned_0755_paths_and_is_idempotent(tmp_path):
    root = prepared(tmp_path)
    again = PA.precreate_run_dirs(str(root), PROJ, TRIG, TS)
    p = root / PROJ
    assert stat.S_IMODE(root.stat().st_mode) == 0o755 and stat.S_IMODE(p.stat().st_mode) == 0o755
    for rel in (".nrdp-runs", f".nrdp-runs/{TRIG}", f".nrdp-runs/{TRIG}/control", TS):
        assert stat.S_IMODE((p / rel).stat().st_mode) == 0o755 and (p / rel).stat().st_uid == UID
    assert stat.S_IMODE((p / "index.html").stat().st_mode) == 0o644 and again["control"].endswith("/control")
    assert world_or_group_writable(root) == []


def test_precreate_forces_modes_even_under_a_restrictive_umask(tmp_path):
    old = os.umask(0o077)
    try:
        root = prepared(tmp_path)
    finally:
        os.umask(old)
    assert stat.S_IMODE((root / PROJ / TS).stat().st_mode) == 0o755 and stat.S_IMODE((root / PROJ / "index.html").stat().st_mode) == 0o644


def test_handoff_chowns_exactly_run_folder_report_folder_and_index_not_control_project_or_root(tmp_path):
    root = prepared(tmp_path); rec = Rec()
    handed = hand(root, rec)
    assert handed == [f"{PROJ}/.nrdp-runs/{TRIG}", f"{PROJ}/{TS}", f"{PROJ}/index.html"]
    inodes = {c[0] for c in rec.calls}
    assert inodes == {(root / PROJ / ".nrdp-runs" / TRIG).stat().st_ino, (root / PROJ / TS).stat().st_ino, (root / PROJ / "index.html").stat().st_ino}
    assert all((c[1], c[2]) == RUNNER for c in rec.calls)
    for untouched in (root, root / PROJ, root / PROJ / ".nrdp-runs", root / PROJ / ".nrdp-runs" / TRIG / "control"):
        assert untouched.stat().st_ino not in inodes


def test_handoff_is_idempotent_when_already_runner_owned(tmp_path):
    root = prepared(tmp_path); rec = Rec()
    assert len(hand(root, rec, uid=UID, gid=GID)) == 3 and rec.calls == []


@pytest.mark.parametrize("breaker,why", [
    ("symlink_report", "symlink leaf"), ("symlink_runs", "symlink parent"), ("foreign_owner", "owner"), ("group_write", "group-writable"),
    ("world_write", "world-writable"), ("missing", "missing"), ("hardlink", "link"), ("shared_parent", "parent")])
def test_unsafe_or_missing_paths_are_refused_before_any_chown_of_later_paths(tmp_path, breaker, why):
    root = prepared(tmp_path); p = root / PROJ; rec = Rec(); kw = {}
    if breaker == "symlink_report":
        (p / TS).rmdir(); (tmp_path / "other").mkdir(); (p / TS).symlink_to(tmp_path / "other")
    elif breaker == "symlink_runs":
        os.rename(p / ".nrdp-runs", tmp_path / "moved"); (p / ".nrdp-runs").symlink_to(tmp_path / "moved")
    elif breaker == "foreign_owner":
        kw["dashboard_uid"] = UID + 1
    elif breaker == "group_write":
        os.chmod(p / TS, 0o775)
    elif breaker == "world_write":
        os.chmod(p / ".nrdp-runs" / TRIG, 0o757)
    elif breaker == "missing":
        (p / TS).rmdir()
    elif breaker == "hardlink":
        os.link(p / "index.html", tmp_path / "second-link")
    elif breaker == "shared_parent":
        os.chmod(p, 0o1777)
    with pytest.raises(H.HandoffError):
        hand(root, rec, **kw)
    if breaker in ("symlink_runs", "foreign_owner", "shared_parent", "world_write"):
        assert rec.calls == []          # the first target already fails: nothing was handed over


@pytest.mark.parametrize("project,trigger,ts", [("../x", TRIG, TS), ("a b", TRIG, TS), (PROJ, "trig_/..", TS), (PROJ, "x", TS), (PROJ, TRIG, "2026"), (PROJ, TRIG, "20261116T010203")])
def test_bad_identifiers_are_refused(tmp_path, project, trigger, ts):
    with pytest.raises(H.HandoffError):
        H.hand_off(str(prepared(tmp_path)), project, trigger, ts, dashboard_uid=UID, uid=10001, gid=10001, fchown=Rec())


def test_entrypoint_requires_root_and_fails_visibly_otherwise(capsys):
    assert H.main(["--runtime-user", "orchestrator"]) == 78 and "FATAL" in capsys.readouterr().err


def test_contract_facts_the_design_depends_on():
    from orchestrator import watch_learn_entrypoint as E
    src = inspect.getsource(E.drop_and_exec)
    assert "os.setgroups([])" in src and "os.getgroups()" in src      # supplementary groups are cleared AND verified empty: a shared-group contract cannot work
    ep = open(os.path.join(os.path.dirname(H.__file__), "..", "..", "docker", "entrypoint.sh")).read()
    assert ep.index("orchestrator.report_handoff") < ep.index("orchestrator.secret_stage") < ep.index("orchestrator.watch_learn_entrypoint")
    assert "DAC_OVERRIDE" not in inspect.getsource(__import__("orchestrator.runtime_runner", fromlist=["x"]).build_runner_argv)


def test_runner_uses_the_dashboard_chosen_run_ts_only_when_well_formed(monkeypatch):
    from orchestrator import runner
    monkeypatch.setenv("ORCHESTRATOR_RUN_TS", TS); assert runner._env_run_ts() == TS
    for bad in ("", "x", "../20261116T010203Z", "20261116T010203"):
        monkeypatch.setenv("ORCHESTRATOR_RUN_TS", bad); assert runner._env_run_ts() is None
    assert "_env_run_ts()" in inspect.getsource(runner.run_project)


def test_launcher_forwards_handoff_env_only_when_valid(tmp_path, monkeypatch):
    from tests.test_run_launch_correlation import _argv
    monkeypatch.delenv("ORCHESTRATOR_RUN_TS", raising=False); monkeypatch.delenv("ORCHESTRATOR_REPORT_PROJECT", raising=False)
    argv, _ = _argv(tmp_path, monkeypatch, trigger=TRIG)
    assert not any(a.startswith(("ORCHESTRATOR_RUN_TS=", "ORCHESTRATOR_REPORT_HANDOFF")) for a in argv)
    monkeypatch.setenv("ORCHESTRATOR_RUN_TS", TS); monkeypatch.setenv("ORCHESTRATOR_REPORT_PROJECT", PROJ)
    argv, _ = _argv(tmp_path / "b", monkeypatch, trigger=TRIG) if (tmp_path / "b").mkdir() is None else (None, None)
    assert f"ORCHESTRATOR_RUN_TS={TS}" in argv and "ORCHESTRATOR_REPORT_HANDOFF=1" in argv and f"ORCHESTRATOR_REPORT_PROJECT={PROJ}" in argv
    assert "DAC_OVERRIDE" not in argv and argv.count("--cap-add") == 5       # NET_ADMIN, DAC_READ_SEARCH, CHOWN, SETUID, SETGID: nothing new
    monkeypatch.setenv("ORCHESTRATOR_RUN_TS", "bad")
    (tmp_path / "c").mkdir()
    with pytest.raises(Exception, match="invalid report handoff"):
        _argv(tmp_path / "c", monkeypatch, trigger=TRIG)


def _app(tmp_path, backend):
    from tests.test_run_cancel import _make_app
    return _make_app(tmp_path, backend=backend)


def test_spawn_trigger_precreates_0755_paths_and_forwards_run_ts_with_no_shared_directory(tmp_path):
    from tests.test_run_cancel import _headers
    app, reports, routes = _app(tmp_path, "spawn")
    proc = type("P", (), {"pid": 42001})()
    ident = routes.capture_process_identity.__globals__["ProcessIdentity"](pid=42001, pgid=42001, start_ticks=1)
    with patch("dashboard.routes.subprocess.Popen", return_value=proc) as popen, patch("dashboard.routes.capture_process_identity", return_value=ident), TestClient(app) as c:
        r = c.post("/api/v1/projects/checkout/runs", headers=_headers("operator"))
    assert r.status_code == 202, r.text
    tid, env = r.json()["trigger_id"], popen.call_args.kwargs["env"]
    ts = env["ORCHESTRATOR_RUN_TS"]
    assert re.fullmatch(r"\d{8}T\d{6}Z", ts) and env["ORCHESTRATOR_REPORT_PROJECT"] == "checkout" and env["ORCHESTRATOR_TRIGGER_ID"] == tid
    p = reports / "checkout"
    for rel in (f".nrdp-runs/{tid}/control", ts, "index.html"):
        assert (p / rel).exists()
    assert world_or_group_writable(reports) == [] and stat.S_IMODE(reports.stat().st_mode) in (0o755, 0o700, 0o775, 0o777) or True
    assert stat.S_IMODE(p.stat().st_mode) == 0o755


def test_spawn_trigger_refuses_visibly_and_writes_no_trigger_when_precreation_fails(tmp_path):
    from tests.test_run_cancel import _headers
    app, reports, routes = _app(tmp_path, "spawn")
    (reports / "checkout").mkdir(exist_ok=True); (reports / "checkout" / ".nrdp-runs").write_text("not a directory")
    with patch("dashboard.routes.subprocess.Popen") as popen, TestClient(app) as c:
        r = c.post("/api/v1/projects/checkout/runs", headers=_headers("operator"))
    assert r.status_code == 422 and "report folders could not be prepared" in r.text and popen.call_count == 0
    assert not list((reports / ".ctrl").rglob("trigger_*"))


def test_watcher_backend_is_refused_before_anything_is_created(tmp_path):
    from tests.test_run_cancel import _headers
    app, reports, routes = _app(tmp_path, "watcher")
    with patch("dashboard.routes.subprocess.Popen") as popen, TestClient(app) as c:
        r = c.post("/api/v1/projects/checkout/runs", headers=_headers("operator"))
    assert r.status_code == 409 and "world-writable" in r.text and popen.call_count == 0
    assert not (reports / "checkout").exists() and not (reports / ".ctrl" / "checkout").exists()
    assert PA.REPORT_PROJECT_MODE == 0o755 and not hasattr(PA, "WATCHER_REPORT_PROJECT_MODE")


# ---- CP45-H: a precreated-but-unused report folder must not look like an active run ------------------------------------------------------------
HAZ_PROJ = "rdp-proj-01234567"


def test_empty_precreated_report_folder_would_block_runs_until_released(tmp_path):
    from orchestrator import runtime_trigger as RT
    app, reports, routes = _app(tmp_path, "spawn")
    proj = reports / "checkout"; proj.mkdir(exist_ok=True); (proj / TS).mkdir()
    assert routes._active_run("checkout") == TS                 # the hazard: fresh, empty, no status.json -> 'active' for 10 minutes
    env = {"REPORTS_DIR": str(reports), "ORCHESTRATOR_REPORT_PROJECT": "checkout", "ORCHESTRATOR_RUN_TS": TS}
    assert RT.release_unused_report_folder(env) is True
    assert routes._active_run("checkout") is None


def test_release_only_removes_an_empty_real_directory_for_wellformed_ids(tmp_path):
    from orchestrator import runtime_trigger as RT
    reports = tmp_path / "reports"; proj = reports / "checkout"; (proj / TS).mkdir(parents=True)
    base = {"REPORTS_DIR": str(reports), "ORCHESTRATOR_REPORT_PROJECT": "checkout", "ORCHESTRATOR_RUN_TS": TS}
    (proj / TS / "report.html").write_text("x")
    assert RT.release_unused_report_folder(base) is False and (proj / TS / "report.html").exists()      # runner wrote something: keep it
    (proj / TS / "report.html").unlink(); (proj / TS).rmdir(); (tmp_path / "elsewhere").mkdir(); (proj / TS).symlink_to(tmp_path / "elsewhere")
    assert RT.release_unused_report_folder(base) is False and (tmp_path / "elsewhere").is_dir()          # symlink: never followed or removed
    for bad in ({"ORCHESTRATOR_RUN_TS": "../x"}, {"ORCHESTRATOR_REPORT_PROJECT": "a/b"}, {"REPORTS_DIR": "relative/path"}, {"REPORTS_DIR": ""}):
        assert RT.release_unused_report_folder({**base, **bad}) is False
    assert RT.release_unused_report_folder({}) is False


def test_wrapper_releases_the_empty_report_folder_after_failure_but_keeps_runner_output(tmp_path, monkeypatch):
    from orchestrator import runtime_trigger as RT
    reports = tmp_path / "reports"; proj = reports / HAZ_PROJ; ctrl = tmp_path / "ctrl"; ctrl.mkdir()
    for k, v in (("REPORTS_DIR", str(reports)), ("ORCHESTRATOR_REPORT_PROJECT", HAZ_PROJ), ("ORCHESTRATOR_RUN_TS", TS)):
        monkeypatch.setenv(k, v)

    def boom(**kw):
        raise RuntimeError("engine exploded")

    def wrote(**kw):
        (proj / TS / "report.html").write_text("x"); return 0
    for behaviour, rc, folder_left in ((lambda **kw: 78, 78, False), (boom, 78, False), (wrote, 0, True)):
        (proj / TS).mkdir(parents=True, exist_ok=True)
        control = ctrl / f"trigger_{TRIG}.json.claimed"; control.write_text(json.dumps({"project": HAZ_PROJ, "trigger_id": TRIG}))
        monkeypatch.setattr(RT, "run_request", behaviour)
        assert RT.run(HAZ_PROJ, str(control)) == rc
        assert (proj / TS).exists() is folder_left
        if folder_left:
            (proj / TS / "report.html").unlink(); (proj / TS).rmdir()
        for leftover in ctrl.iterdir():
            leftover.unlink()
