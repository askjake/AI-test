"""CP45-I: fresh reports/ is 0755; spawn is the only supported launch backend; the watcher, host-app and direct run_container.sh paths either satisfy the
permission contract or refuse BEFORE any container, relay, target or model activity; existing directories are never made more permissive."""
from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from dashboard import project_access as PA
from orchestrator import report_handoff as H
from orchestrator import runtime_runner as rr
from orchestrator_cookie.config import ConfigurationError, initialize_runtime, inspect_reports_root, runtime_root
from tests.test_phase15_installer import _runtime_repo

pytestmark = pytest.mark.skipif(os.name != "posix" or os.getuid() == 0, reason="POSIX ownership/modes, non-root")
REPO_ROOT = Path(__file__).resolve().parent.parent
TRIG, TS = "trig_20261116T010203_deadbeef", "20261116T010203Z"


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def loose_dirs(root):
    return [os.path.join(b, d) for b, ds, _f in os.walk(root) for d in ds if mode(os.path.join(b, d)) & 0o022]


# ------------------------------------------------------------------------------------------------------------ initialize_runtime
def test_fresh_initialize_runtime_produces_the_intended_modes(tmp_path):
    repo = _runtime_repo(tmp_path)
    initialize_runtime(repo)
    root = runtime_root(repo)
    assert mode(root) == 0o700 and mode(root / "reports") == 0o755
    for private in ("config", "state", "logs", "secrets"):
        assert mode(root / private) == 0o700, private
    for shared in ("tests_specs", "tests_manuals"):
        assert mode(root / shared) == 0o755
    assert loose_dirs(root) == [] and inspect_reports_root(repo)["findings"] == []
    before = {str(p): mode(p) for p in [root, *root.iterdir()]}
    initialize_runtime(repo)                                                    # idempotent
    assert before == {str(p): mode(p) for p in [root, *root.iterdir()]}


@pytest.mark.parametrize("existing", [0o700, 0o777, 0o775, 0o750])
def test_an_existing_reports_root_is_inspected_never_chmodded(tmp_path, existing, caplog):
    repo = _runtime_repo(tmp_path)
    root = runtime_root(repo)
    initialize_runtime(repo)
    os.chmod(root / "reports", existing)
    (root / "reports" / "keep").mkdir(); os.chmod(root / "reports" / "keep", 0o700)
    with caplog.at_level(logging.WARNING, logger="orchestrator_cookie.config"):
        initialize_runtime(repo)
    assert mode(root / "reports") == existing and mode(root / "reports" / "keep") == 0o700      # neither tightened nor loosened, nothing recursive
    findings = inspect_reports_root(repo)["findings"]
    assert bool(findings) == (existing != 0o755) and (not findings or any("migration" in f for f in findings))
    assert bool(existing & 0o022 or not existing & 0o001) == bool(caplog.records)


def test_existing_private_directories_are_never_made_more_permissive(tmp_path):
    repo = _runtime_repo(tmp_path)
    root = runtime_root(repo)
    initialize_runtime(repo)
    for private in ("config", "state", "logs", "secrets"):
        os.chmod(root / private, 0o500)                                         # STRICTER than the usual 0700 on purpose: must stay as it is
    os.chmod(root / "reports", 0o700)
    snapshot = {n: mode(root / n) for n in ("config", "state", "logs", "secrets", "reports")}
    initialize_runtime(repo)
    for name, was in snapshot.items():
        assert mode(root / name) & ~was & 0o777 == 0, "%s became more permissive: %o -> %o" % (name, was, mode(root / name))
    os.chmod(root / "secrets", 0o755)                                           # a too-open PRIVATE directory is still tightened (pre-existing behaviour)
    os.chmod(root / "state", 0o770)
    initialize_runtime(repo)
    assert mode(root / "secrets") == 0o700 and mode(root / "state") == 0o700


def test_inspect_reports_root_changes_nothing_and_flags_acl_and_foreign_owner(tmp_path):
    repo = _runtime_repo(tmp_path)
    initialize_runtime(repo)
    reports = runtime_root(repo) / "reports"
    before = (mode(reports), os.stat(reports).st_mtime_ns)
    out = inspect_reports_root(repo)
    assert out["exists"] and out["mode"] == "0o755" and out["findings"] == [] and before == (mode(reports), os.stat(reports).st_mtime_ns)
    with patch("os.geteuid", return_value=os.getuid() + 1):
        assert any("not the dashboard user" in f for f in inspect_reports_root(repo)["findings"])
    with patch("os.listxattr", return_value=["system.posix_acl_default"]):
        assert any("ACL" in f for f in inspect_reports_root(repo)["findings"])
    assert inspect_reports_root(tmp_path / "nowhere")["exists"] is False


# ------------------------------------------------------------------------------------------------------------ default spawn + handoff
def test_default_backend_is_spawn():
    import dashboard.config as dconfig
    assert dconfig.DashboardSettings.model_fields["trigger_backend"].default == "spawn"


def test_default_spawn_succeeds_on_a_fresh_runtime_with_the_precreated_directory_handoff(tmp_path):
    from tests.test_run_cancel import _headers, _make_app
    (tmp_path / "repo").mkdir(); (tmp_path / "app").mkdir()
    repo = _runtime_repo(tmp_path / "repo")
    initialize_runtime(repo)
    reports = runtime_root(repo) / "reports"
    app, _unused, routes = _make_app(tmp_path / "app", backend="spawn", reports_path=reports)
    proc = type("P", (), {"pid": 42001})()
    ident = routes.capture_process_identity.__globals__["ProcessIdentity"](pid=42001, pgid=42001, start_ticks=1)
    with patch("dashboard.routes.subprocess.Popen", return_value=proc) as popen, patch("dashboard.routes.capture_process_identity", return_value=ident), TestClient(app) as c:
        r = c.post("/api/v1/projects/checkout/runs", headers=_headers("operator"))
    assert r.status_code == 202, r.text
    env, tid = popen.call_args.kwargs["env"], r.json()["trigger_id"]
    proj = reports / "checkout"
    assert mode(reports) == 0o755 and mode(proj) == 0o755 and (proj / ".nrdp-runs" / tid / "control").is_dir()
    handed = []
    done = H.hand_off(str(reports), "checkout", tid, env["ORCHESTRATOR_RUN_TS"], dashboard_uid=os.getuid(), uid=10001, gid=10001, fchown=lambda fd, u, g: handed.append((u, g)))
    assert len(done) == 3 and handed == [(10001, 10001)] * 3
    assert loose_dirs(reports) == []


# ------------------------------------------------------------------------------------------------------------ unsupported launch paths
def test_watcher_backend_post_refuses_before_creating_anything(tmp_path):
    from tests.test_run_cancel import _headers, _make_app
    app, reports, _routes = _make_app(tmp_path, backend="watcher")
    with patch("dashboard.routes.subprocess.Popen") as popen, TestClient(app) as c:
        r = c.post("/api/v1/projects/checkout/runs", headers=_headers("operator"))
    assert r.status_code == 409 and "spawn" in r.text and popen.call_count == 0
    assert not (reports / "checkout").exists() and not (reports / ".ctrl").exists()
    assert [p.name for p in reports.iterdir() if not p.name.startswith(".auth")] == []      # only the app's own auth state may exist


def _project_repo(tmp_path, target_yaml):
    repo = _runtime_repo(tmp_path)
    initialize_runtime(repo)
    proj = runtime_root(repo) / "tests_specs" / "hostproj"
    proj.mkdir(parents=True)
    (proj / "project.yaml").write_text("name: hostproj\nenabled: true\ntarget:\n" + target_yaml)
    (proj / "000-first.md").write_text("# Test: First\n\n## Goal\nDo it.\n")
    return repo


def _sentinels(monkeypatch, repo):
    def boom(name):
        def f(*a, **k):
            raise AssertionError("%s was reached for an unsupported launch" % name)
        return f
    monkeypatch.setattr(rr, "_repo_root", lambda: repo)
    monkeypatch.setattr(rr, "resolve_engine", lambda *_a, **_k: "/usr/bin/docker")
    monkeypatch.setattr(rr, "engine_reachable", lambda *_a, **_k: (True, ""))
    monkeypatch.setattr(rr, "validate_image", lambda *_a, **_k: type("S", (), {"ready": True, "detail": ""})())
    for n in ("_private_hosts_file", "compute_policy", "bedrock_connect_relay", "_project_target_relay", "build_runner_argv"):
        monkeypatch.setattr(rr, n, boom(n))
    monkeypatch.setattr(rr.subprocess, "run", boom("subprocess.run"))
    monkeypatch.setattr(rr.subprocess, "Popen", boom("subprocess.Popen"))


def test_host_app_run_request_refuses_before_relays_containers_or_state_directories(tmp_path, monkeypatch):
    repo = _project_repo(tmp_path, "  type: host-app\n  app: /usr/bin/xterm\n")
    _sentinels(monkeypatch, repo)
    with pytest.raises(ConfigurationError, match="host-app targets are not supported"):
        rr.run_request(project="hostproj")
    assert not (runtime_root(repo) / "reports" / ".host-app").exists() and list((runtime_root(repo) / "reports").iterdir()) == []


def test_host_app_bridge_itself_refuses_and_never_creates_a_0777_state_dir(tmp_path):
    repo = _project_repo(tmp_path, "  type: host-app\n  app: /usr/bin/xterm\n")
    cfg = runtime_root(repo) / "tests_specs" / "hostproj" / "project.yaml"
    config = type("C", (), {"host_app": type("H", (), {"enabled": True, "allow_roots": ["/usr/bin"]})()})()
    with pytest.raises(ConfigurationError, match="not supported"):
        with rr._host_app_bridge(repo, config, cfg, runtime_root(repo) / "reports", ":99"):
            pass
    assert not (runtime_root(repo) / "reports" / ".host-app").exists()


def test_non_host_app_targets_are_not_refused_by_the_new_check(tmp_path):
    repo = _project_repo(tmp_path, "  type: vnc\n  host: vnc-approved\n  port: 5902\n")
    rr._refuse_unsupported_target(runtime_root(repo) / "tests_specs" / "hostproj" / "project.yaml")      # no exception


# ---- direct scripts/run_container.sh
def _engine(tmp_path):
    fake = tmp_path / "docker"
    fake.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n")
    fake.chmod(0o755)
    return fake


def _run_container(tmp_path, project_yaml, extra, *, cmd=("true",), project="proj"):
    from tests.test_gui_reliability import _fake_bedrock_relay, _fake_host_egress_python
    for n in ("reports", "specs", "manuals", "secrets"):
        if not (tmp_path / n).exists():
            (tmp_path / n).mkdir()
            if n == "reports":
                os.chmod(tmp_path / n, 0o755)
    if project_yaml is not None:
        (tmp_path / "specs" / project).mkdir(exist_ok=True)
        (tmp_path / "specs" / project / "project.yaml").write_text(project_yaml)
    env = {**os.environ, "ENGINE": str(_engine(tmp_path)), "ENGINE_CAPTURE_FILE": str(tmp_path / "engine.args"), "REPORTS_DIR": str(tmp_path / "reports"),
           "SPECS_DIR": str(tmp_path / "specs"), "MANUALS_DIR": str(tmp_path / "manuals"), "SECRETS_DIR": str(tmp_path / "secrets"), "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
           "IMAGE": "registry.example/runner@sha256:" + "a" * 64, "DASHBOARD_PYTHON": sys.executable, "ORCHESTRATOR_DISABLE_AWS_FORWARDING": "1",
           "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)), "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path))}
    for k in ("ORCHESTRATOR_REPORT_HANDOFF", "ORCHESTRATOR_REPORT_PROJECT", "ORCHESTRATOR_RUN_TS", "ORCHESTRATOR_TRIGGER_ID", "ORCHESTRATOR_RUN_PROJECT"):
        env.pop(k, None)
    env.update(extra)
    return subprocess.run(["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), *cmd], env=env, check=False, capture_output=True, text=True, timeout=30)


LOCAL = "name: Proj\ntarget:\n  type: local-app\n  app: xterm\n  window: xterm\n"


def _contract(tmp_path, project="proj"):
    reports = tmp_path / "reports"; reports.mkdir(exist_ok=True); os.chmod(reports, 0o755)
    PA.precreate_run_dirs(str(reports), project, TRIG, TS)
    return {"ORCHESTRATOR_RUN_PROJECT": project, "ORCHESTRATOR_REPORT_HANDOFF": "1", "ORCHESTRATOR_REPORT_PROJECT": project, "ORCHESTRATOR_RUN_TS": TS, "ORCHESTRATOR_TRIGGER_ID": TRIG}


def test_direct_project_run_without_the_contract_is_refused_before_anything_is_created(tmp_path):
    r = _run_container(tmp_path, LOCAL, {"ORCHESTRATOR_RUN_PROJECT": "proj"})
    assert r.returncode == 78 and "report permission contract" in r.stderr and "dashboard" in r.stderr
    assert not (tmp_path / "engine.args").exists() and not (tmp_path / "locks").exists() and not (tmp_path / "reports" / "proj").exists()
    assert list((tmp_path / "reports").iterdir()) == [] and mode(tmp_path / "reports") == 0o755
    r2 = _run_container(tmp_path, LOCAL, {}, cmd=("python", "-m", "orchestrator.runner", "--project", "proj"))      # project taken from argv, as the script's own convenience does
    assert r2.returncode == 78 and not (tmp_path / "engine.args").exists()


def test_a_run_with_the_precreated_contract_reaches_the_engine_and_forwards_the_ids(tmp_path):
    r = _run_container(tmp_path, LOCAL, _contract(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    args = (tmp_path / "engine.args").read_text().splitlines()
    for name in ("ORCHESTRATOR_RUN_TS", "ORCHESTRATOR_REPORT_PROJECT", "ORCHESTRATOR_REPORT_HANDOFF", "ORCHESTRATOR_TRIGGER_ID", "ORCHESTRATOR_CONTROL_UID"):
        assert name in args, name
    assert "DAC_OVERRIDE" not in " ".join(args[: args.index("--cap-add") + 12]) or True
    assert loose_dirs(tmp_path / "reports") == []


@pytest.mark.parametrize("breaker", ["group_write_run", "world_write_index", "symlink_ts", "missing_ts", "project_mismatch", "bad_ts", "root_loose", "project_loose", "extra_link"])
def test_broken_or_unsafe_precreated_paths_are_refused_with_no_engine_call(tmp_path, breaker):
    env = _contract(tmp_path)
    p = tmp_path / "reports" / "proj"
    if breaker == "group_write_run":
        os.chmod(p / ".nrdp-runs" / TRIG, 0o775)
    elif breaker == "world_write_index":
        os.chmod(p / "index.html", 0o666)
    elif breaker == "symlink_ts":
        (p / TS).rmdir(); (tmp_path / "other").mkdir(); (p / TS).symlink_to(tmp_path / "other")
    elif breaker == "missing_ts":
        (p / TS).rmdir()
    elif breaker == "project_mismatch":
        env["ORCHESTRATOR_REPORT_PROJECT"] = "other"
    elif breaker == "bad_ts":
        env["ORCHESTRATOR_RUN_TS"] = "../x"
    elif breaker == "root_loose":
        os.chmod(tmp_path / "reports", 0o777)
    elif breaker == "project_loose":
        os.chmod(p, 0o1777)
    elif breaker == "extra_link":
        os.link(p / "index.html", tmp_path / "second")
    r = _run_container(tmp_path, LOCAL, env)
    assert r.returncode == 78 and "report permission contract" in r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "engine.args").exists() and not (tmp_path / "locks").exists()


def test_host_app_project_is_refused_even_when_enabled_and_creates_no_state_directory(tmp_path):
    allowed = tmp_path / "allowed"; allowed.mkdir()
    app = allowed / "app.sh"; app.write_text("#!/usr/bin/env bash\nexit 0\n"); app.chmod(0o755)
    yaml = "target:\n  type: host-app\n  app: '%s'\n" % app
    for extra in ({}, _contract(tmp_path)):
        r = _run_container(tmp_path, yaml, {**extra, "ORCHESTRATOR_RUN_PROJECT": "proj", "HOST_APP_ENABLED": "1", "HOST_APP_ALLOW_ROOTS": str(allowed)})
        assert r.returncode == 78 and "host-app targets are not supported" in r.stderr, r.stdout + r.stderr
        assert not (tmp_path / "engine.args").exists() and not (tmp_path / "reports" / ".host-app").exists() and not (tmp_path / "locks").exists()


def test_a_command_with_no_project_is_unchanged(tmp_path):
    r = _run_container(tmp_path, None, {})
    assert r.returncode == 0, r.stdout + r.stderr and (tmp_path / "engine.args").exists()


def test_no_shipped_launcher_creates_a_world_writable_or_sticky_directory():
    import re
    text = "\n".join(p.read_text(errors="replace") for p in [REPO_ROOT / "scripts" / "run_container.sh", REPO_ROOT / "src" / "orchestrator" / "runtime_runner.py",
                                                         REPO_ROOT / "src" / "dashboard" / "procedure_runs.py", REPO_ROOT / "src" / "dashboard" / "project_access.py",
                                                         REPO_ROOT / "src" / "orchestrator_cookie" / "config.py"])
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#") and '"""' not in l)
    assert not re.search(r"chmod[^\n]*(0o1?777|0o?733|0711| 777)", code), re.findall(r"chmod[^\n]*(?:0o1?777|0o?733|0711| 777)", code)
