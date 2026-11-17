"""CP45-N focused regressions: unsupported launch configurations are refused BEFORE anything starts (captured, not transcribed)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dashboard import project_access as PA
from orchestrator_cookie import config as CC, lifecycle as LC

ROOT = Path(__file__).resolve().parent.parent
TID, TS = "trig_20261116T170000_beef0001", "20261116T170000Z"


def test_validate_rejects_the_watcher_backend_and_keeps_spawn():
    with pytest.raises(CC.ConfigurationError, match="trigger_backend must be 'spawn'"):
        CC.RuntimeConfig(trigger_backend="watcher").validate()
    CC.RuntimeConfig(trigger_backend="spawn").validate()
    CC.RuntimeConfig().validate()


def test_an_existing_runtime_json_with_watcher_is_refused_when_loaded(tmp_path):
    path = CC.runtime_root(tmp_path) / CC.CONFIG_RELATIVE
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": CC.SCHEMA_VERSION, "trigger_backend": "watcher"}), encoding="utf-8")
    with pytest.raises(CC.ConfigurationError, match="watcher"):
        CC.load_config(tmp_path)


def test_lifecycle_refuses_before_any_process_environment_log_or_state(tmp_path, monkeypatch):
    cfg = CC.RuntimeConfig(trigger_backend="watcher")            # built WITHOUT validate(): the lifecycle guard must refuse on its own
    spawned = []

    def forbidden(*a, **k):
        spawned.append(a)
        raise AssertionError("a process was started")
    monkeypatch.setattr(LC.subprocess, "Popen", forbidden)
    monkeypatch.setattr(LC.subprocess, "call", forbidden)
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    for call in (lambda: LC.start_dashboard(tmp_path, cfg),
                 lambda: LC.start_dashboard(tmp_path, cfg, foreground=True),
                 lambda: LC.dashboard_environment(tmp_path, cfg, instance_id="x")):
        with pytest.raises(CC.ConfigurationError, match="watcher"):
            call()
    assert spawned == [] and sorted(str(p) for p in tmp_path.rglob("*")) == before


def _launch(tmp_path, target_type, *, contract):
    root = tmp_path / "w"
    for n in ("reports", "specs", "manuals", "secrets"):
        (root / n).mkdir(parents=True)
    os.chmod(root / "reports", 0o755)
    (root / "specs" / "hp").mkdir()
    (root / "specs" / "hp" / "project.yaml").write_text("name: HP\ntarget:\n  type: %s\n  app: xterm\n  window: xterm\n" % target_type)
    log = tmp_path / "engine_calls.log"
    shim = tmp_path / "engine_shim.sh"
    shim.write_text('#!/bin/bash\necho "ENGINE_CALLED: $*" >> "%s"\nexit 97\n' % log)
    shim.chmod(0o755)
    env = {**os.environ, "ENGINE": str(shim), "IMAGE": "nrdp1-test:none", "REPORTS_DIR": str(root / "reports"), "SPECS_DIR": str(root / "specs"),
           "MANUALS_DIR": str(root / "manuals"), "SECRETS_DIR": str(root / "secrets"), "DISPLAY_LOCK_DIR": str(root / "locks"),
           "DASHBOARD_PYTHON": sys.executable, "ORCHESTRATOR_DISABLE_AWS_FORWARDING": "1", "ORCHESTRATOR_RUN_PROJECT": "hp", "HOST_APP_ENABLED": "1", "PYTHONPATH": ""}
    for k in ("ORCHESTRATOR_REPORT_HANDOFF", "ORCHESTRATOR_REPORT_PROJECT", "ORCHESTRATOR_RUN_TS", "ORCHESTRATOR_TRIGGER_ID"):
        env.pop(k, None)
    if contract:
        PA.precreate_run_dirs(str(root / "reports"), "hp", TID, TS)
        env.update({"ORCHESTRATOR_REPORT_HANDOFF": "1", "ORCHESTRATOR_REPORT_PROJECT": "hp", "ORCHESTRATOR_RUN_TS": TS, "ORCHESTRATOR_TRIGGER_ID": TID})
    before = sorted(p.name for p in (root / "reports").iterdir())
    r = subprocess.run(["bash", str(ROOT / "scripts" / "run_container.sh"), "python", "-c", "print('SHOULD_NOT_RUN')"], env=env, capture_output=True, text=True, timeout=120)
    return root, r, log, before


@pytest.mark.parametrize("contract", [False, True], ids=["no_contract", "full_contract_env"])
def test_host_app_projects_are_refused_before_any_engine_call_lock_or_directory(tmp_path, contract):
    root, r, log, before = _launch(tmp_path, "host-app", contract=contract)
    assert r.returncode == 78, (r.returncode, r.stderr[-400:])
    assert "host-app targets are not supported" in r.stderr and "HOST_APP_ENABLED does not enable them" in r.stderr
    assert "SHOULD_NOT_RUN" not in r.stdout
    assert not log.exists(), "the engine was called"
    assert not (root / "locks").exists() and os.listdir(root / "secrets") == []
    assert sorted(p.name for p in (root / "reports").iterdir()) == before


def test_a_direct_local_app_launch_without_the_contract_is_refused_before_any_engine_call(tmp_path):
    root, r, log, before = _launch(tmp_path, "local-app", contract=False)
    assert r.returncode == 78 and "report permission contract" in r.stderr and "no precreated report paths" in r.stderr
    assert not log.exists() and not (root / "locks").exists()
    assert sorted(p.name for p in (root / "reports").iterdir()) == before
