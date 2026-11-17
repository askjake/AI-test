"""Spawn-launch correlation (b4r7): the runner must learn WHICH run it is, write where the API polls, and an ended runner
must surface a truthful terminal state.  Real filesystem, real wrapper (runtime_trigger.run), real request lookup
(chain_runtime.read_run_request), real status writer (chain_hooks._write_nrdp_status), real API function
(procedure_runs.get_run).  MOCKED: the container engine itself (a fake stands in for ``docker run``) - the argv it receives
is built by the real build_runner_argv.  Fictional values only."""
import json
import os
import stat
from types import SimpleNamespace as NS

import pytest

try:
    from tests import test_phase15_installer as T15
except ImportError:  # pragma: no cover
    import test_phase15_installer as T15
from orchestrator import chain_hooks as ch
from orchestrator import chain_runtime as cr
from orchestrator import runtime_runner as rr
from orchestrator import runtime_trigger as rt

try:
    from dashboard import procedure_runs as pr
except ImportError:  # pragma: no cover
    from src.dashboard import procedure_runs as pr

PROJ = "rdp-proj-01234567"
RID = "trig_20261030T162341_c43f8a74"


# ---------------------------------------------------------------- build_runner_argv (the spawn launcher's container command)
def _argv(tmp_path, monkeypatch, trigger="unset"):
    if trigger == "unset":
        monkeypatch.delenv("ORCHESTRATOR_TRIGGER_ID", raising=False)
    else:
        monkeypatch.setenv("ORCHESTRATOR_TRIGGER_ID", trigger)
    repo = T15._runtime_repo(tmp_path)
    creds = tmp_path / "credentials"
    creds.write_text("aws_secret_access_key=do-not-copy-into-argv\n")
    os.chmod(creds, 0o600)
    config = T15.RuntimeConfig(image=T15.ImageSource(kind="reference", image_ref="registry.example/cookie@sha256:" + "c" * 64),
                               aws=T15.AwsConfig(credentials_file=str(creds), profile="engineering", region="us-west-2", bedrock_model_id="profile-id"))
    hosts = tmp_path / "private-hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    hosts.chmod(0o644)
    relay = T15.BedrockRelayLease(endpoint="bedrock-runtime.us-west-2.amazonaws.com", bind_host="172.17.0.1", port=45678,
                                  client_network="172.17.0.0/16", proxy_url="http://172.17.0.1:45678")
    return rr.build_runner_argv(repo, config, "/usr/bin/docker", ["python", "-m", "orchestrator.runner", "--project", PROJ],
                                container_name="orchestrator-cookie-" + PROJ + "-" + RID, display=":99", hosts_file=hosts,
                                bedrock_relay=relay, project_name=PROJ), config


def _env_pairs(argv):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-e"]


@pytest.mark.skipif(os.name != "posix", reason="uid")
def test_valid_trigger_id_and_dashboard_uid_reach_the_container_before_the_image(tmp_path, monkeypatch):
    argv, config = _argv(tmp_path, monkeypatch, trigger=RID)
    pairs = _env_pairs(argv)
    assert f"ORCHESTRATOR_TRIGGER_ID={RID}" in pairs
    assert f"ORCHESTRATOR_CONTROL_UID={os.getuid()}" in pairs
    image_at = argv.index(config.image.image_ref)
    assert all(argv.index("-e") < image_at for _ in [0]) and argv[image_at + 1:] == ["python", "-m", "orchestrator.runner", "--project", PROJ]
    assert argv.index(f"ORCHESTRATOR_TRIGGER_ID={RID}") < image_at and argv.index(f"ORCHESTRATOR_CONTROL_UID={os.getuid()}") < image_at
    # hardening and secrecy are untouched
    assert "--read-only" in argv and "no-new-privileges" in argv and argv[argv.index("--cap-drop") + 1] == "ALL" and "--privileged" not in argv
    assert "do-not-copy-into-argv" not in " ".join(argv)


@pytest.mark.skipif(os.name != "posix", reason="uid")
def test_without_a_trigger_id_only_the_uid_is_forwarded_for_scheduler_and_cli_launches(tmp_path, monkeypatch):
    argv, _ = _argv(tmp_path, monkeypatch, trigger="unset")
    pairs = _env_pairs(argv)
    assert not any(p.startswith("ORCHESTRATOR_TRIGGER_ID") for p in pairs)
    assert f"ORCHESTRATOR_CONTROL_UID={os.getuid()}" in pairs


@pytest.mark.parametrize("bad", ["../x", "trig_x; rm -rf /", "trig_a\nb", "trig_ a", "TRIG_20261030", "x", "trig_" + "a" * 81, "trig_", "trig_é"])
def test_invalid_trigger_ids_fail_before_any_launch_and_are_not_echoed(tmp_path, monkeypatch, bad):
    with pytest.raises(rr.ConfigurationError) as err:
        _argv(tmp_path, monkeypatch, trigger=bad)
    assert bad not in str(err.value)


# ---------------------------------------------------------------- launch -> runner -> status -> API, with the real wrapper
class World:
    """One dashboard-side run: request written by procedure_runs, wrapper around a fake container."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp, self.mp = tmp_path, monkeypatch
        self.reports = tmp_path / "reports"
        self.reports.mkdir()
        self.argv_cfg = None
        pr.configure(reports_root=lambda: str(self.reports), launch=lambda p: RID, cancel=lambda p: {"status": "cancelled"})
        pr.start_run(NS(id="a" * 32), PROJ, "connection_test", None, config_hash="h" * 64)
        ctrl = self.reports / ".ctrl" / PROJ
        ctrl.mkdir(parents=True, mode=0o700)
        self.control = ctrl / f"trigger_{RID}.json.claimed"
        pr._atomic_json(str(self.control), {"project": PROJ, "trigger_id": RID, "requested_at": "2026-10-30T16:23:41+00:00", "requester": "dashboard", "backend": "spawn"})
        self.seen = {}

    def run_wrapper(self, runner, *, forward_trigger=True, uid_delta=0):
        """Run the REAL wrapper around ``runner(env, world)`` which stands in for the container."""
        def fake_run_request(*, project=None, spec=None):
            argv, _ = _argv(self.tmp / "argvbuild", self.mp, trigger=RID)
            pairs = _env_pairs(argv)
            env = dict(p.split("=", 1) for p in pairs if p.split("=", 1)[0] in ("ORCHESTRATOR_TRIGGER_ID", "ORCHESTRATOR_CONTROL_UID"))
            if not forward_trigger:
                env.pop("ORCHESTRATOR_TRIGGER_ID", None)               # the b4r6 launcher: nothing forwarded
            if "ORCHESTRATOR_CONTROL_UID" in env:
                env["ORCHESTRATOR_CONTROL_UID"] = str(int(env["ORCHESTRATOR_CONTROL_UID"]) + uid_delta)
            for key in ("ORCHESTRATOR_TRIGGER_ID", "ORCHESTRATOR_CONTROL_UID"):
                self.mp.delenv(key, raising=False)                     # the container sees ONLY what -e forwarded
            for key, value in env.items():
                self.mp.setenv(key, value)
            self.seen["env"] = dict(env)
            return runner(self)
        self.mp.setattr(rt, "run_request", fake_run_request)
        (self.tmp / "argvbuild").mkdir(exist_ok=True)
        return rt.run(PROJ, str(self.control))

    def lookup(self):
        return cr.read_run_request(str(self.reports), PROJ, None)      # exactly what chain_hooks does inside the container

    def get(self):
        return pr.get_run(PROJ, RID)


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World(tmp_path, monkeypatch)
    yield w
    pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel, now=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_request_progress_and_api_polling_share_the_trigger_bound_directory(world):
    def runner(w):
        req = w.lookup()
        w.seen["req"] = req
        ch._write_nrdp_status(req.run_dir, "error", {"mode": req.mode, "requested_mode": req.requested_mode, "result": "errored"})
        return 1
    rc = world.run_wrapper(runner)
    req = world.seen["req"]
    assert req.source == "request" and req.mode == "connection_test" and req.reason in ("", None)
    assert req.run_dir == pr.run_dir(PROJ, RID)                              # runner and API agree on the directory
    api = world.get()
    assert rc == 1 and api["state"] == "error" and api["state_source"] == "status"
    assert api["requested_mode"] == "connection_test" and api["effective_mode"] == "connection_test" and api["downgraded"] is False
    assert "error" not in api                                              # the runner's own status won; no fallback was used


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_the_b4r6_launcher_defect_runner_without_trigger_id_cannot_find_its_request(world):
    """Regression for the observed incident: nothing forwarded -> 'no trigger id', request unseen, nothing at the polled path."""
    def runner(w):
        w.seen["req"] = w.lookup()
        return 1                                                            # and it writes elsewhere (a timestamp dir), never the polled path
    world.run_wrapper(runner, forward_trigger=False)
    assert world.seen["req"].reason == "no trigger id" and world.seen["req"].run_dir is None
    assert not os.path.exists(os.path.join(pr.run_dir(PROJ, RID), "status.json"))


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_early_runner_exit_gives_a_truthful_terminal_error_not_pending(world):
    before = world.get()
    assert before["state"] == "pending" and "error" not in before          # slow startup: no launcher record yet -> not declared failed
    world.run_wrapper(lambda w: 1)                                          # the real wrapper writes the .err record
    api = world.get()
    assert api["state"] == "error" and api["state_source"] == "launcher" and api["status"] == "error"
    assert api["error"]["code"] == "RUNNER_EXITED_EARLY" and "status 1" in api["error"]["message"]
    assert api["error"]["hop"] is None and api["chain_progress"] is None    # no hop is claimed as tried or connected
    assert "No runner progress was recorded for this run." in api["notes"]
    assert world.get() == api                                               # deterministic


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_clean_exit_without_any_result_is_also_terminal(world):
    world.run_wrapper(lambda w: 0)                                          # wrapper moves the control file to .ack
    api = world.get()
    assert api["state"] == "error" and api["error"]["code"] == "RUNNER_NO_RESULT"


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_exception_text_from_the_launcher_is_never_passed_to_the_ui(world):
    def runner(w):
        raise RuntimeError("password=hunter2 failed for /srv/secret/path token: abc123")
    rc = world.run_wrapper(runner)
    raw = open(str(world.control)[: -len(".claimed")] + ".err").read()
    api = world.get()
    assert rc == 78 and "hunter2" not in raw                                # the wrapper already redacts assignments ...
    blob = json.dumps(api)
    assert api["error"]["code"] == "LAUNCHER_ERROR"                          # ... and the API carries only the fixed vocabulary
    for leaked in ("hunter2", "abc123", "/srv/secret", "password"):
        assert leaked not in blob


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_a_runner_that_reported_a_terminal_state_always_wins_over_the_launcher_record(world):
    def runner(w):
        req = w.lookup()
        ch._write_nrdp_status(req.run_dir, "complete", {"mode": req.mode})
        return 1                                                            # exit status disagrees; the runner's terminal word stands
    world.run_wrapper(runner)
    api = world.get()
    assert api["state"] == "complete" and api["state_source"] == "status" and "error" not in api


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_non_terminal_runner_state_with_an_ended_process_becomes_a_terminal_error_keeping_progress(world):
    def runner(w):
        req = w.lookup()
        cr._atomic_write_json(os.path.join(req.run_dir, "chain_progress.json"), {"schema": 1, "phase": "running", "active_hop": 1, "hops": [{"order": 1, "host": "h1", "status": "connecting"}]})
        return 1                                                            # killed mid-run
    world.run_wrapper(runner)
    api = world.get()
    assert api["state"] == "error" and api["error"]["code"] == "RUNNER_EXITED_EARLY"
    assert api["chain_progress"]["hops"][0]["status"] == "connecting"       # what the runner DID record is kept, not rewritten


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_cancel_precedence_is_deterministic(world):
    from datetime import datetime, timezone, timedelta
    now = {"t": datetime(2026, 10, 30, 16, 25, 40, tzinfo=timezone.utc)}
    pr.configure(now=lambda: now["t"])
    pr._atomic_json(os.path.join(pr.run_dir(PROJ, RID), "control", "cancel_request.json"), {"run_id": RID, "requested_at": "2026-10-30T16:25:32+00:00"})
    assert world.get()["state"] == "pending"                                  # 8 s < grace, process not known to have ended: not yet cancelled
    now["t"] += timedelta(seconds=30)
    assert world.get()["state"] == "pending"                                  # CP45-D: elapsed time alone is NOT a teardown confirmation, so it is never reported as cancelled
    now["t"] = datetime(2026, 10, 30, 16, 25, 40, tzinfo=timezone.utc)
    world.run_wrapper(lambda w: 1)                                            # process ended (launcher record) inside the grace period
    api = world.get()
    assert api["state"] == "cancelled" and api["state_source"] == "cancel_request" and "error" not in api


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_control_file_trust_and_bindings_still_hold_with_the_forwarded_values(world):
    seen = {}
    def runner(w):
        seen["trusted"] = w.lookup()
        return 1
    world.run_wrapper(runner)                                                    # the values exactly as the launcher forwards them
    assert seen["trusted"].source == "request" and seen["trusted"].reason in ("", None)
    # a wrong dashboard uid in the container -> the request is NOT trusted (owner check still enforced)
    world.mp.setenv("ORCHESTRATOR_TRIGGER_ID", RID)
    world.mp.setenv("ORCHESTRATOR_CONTROL_UID", str(os.getuid() + 1))
    untrusted = world.lookup()
    assert untrusted.reason.startswith("run request is not trusted") and untrusted.mode == "connection_test"
    # a request bound to another run or project is refused by the runner-side lookup
    world.mp.setenv("ORCHESTRATOR_CONTROL_UID", str(os.getuid()))
    req_path = os.path.join(pr.run_dir(PROJ, RID), "control", "run_request.json")
    data = json.load(open(req_path))
    for patch, expect in (({"run_id": "trig_20200101T000000_deadbeef"}, "another run id"), ({"project": "other-project-01234567"}, "another project")):
        os.chmod(req_path, 0o600)
        pr._atomic_json(req_path, {**data, **patch})
        assert expect in world.lookup().reason


# ---------------------------------------------------------------- the launcher-record reader itself
def _write_err(world, payload=None, mode=0o600, name=None):
    base = world.reports / ".ctrl" / PROJ
    path = base / (name or f"trigger_{RID}.json.err")
    data = {"project": PROJ, "trigger_id": RID, "error": "Runner exited with status 1; inspect reports/spawn.log.", "exit_code": 1, **(payload or {})}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


@pytest.mark.skipif(os.name != "posix", reason="uid / modes / links")
@pytest.mark.parametrize("label, kwargs", [
    ("group-writable", {"mode": 0o620}), ("world-writable", {"mode": 0o602}),
    ("other run id", {"payload": {"trigger_id": "trig_20200101T000000_deadbeef"}}),
    ("other project", {"payload": {"project": "other-project-01234567"}}),
    ("exit code zero in an error record", {"payload": {"exit_code": 0}}),
    ("oversized", {"payload": {"pad": "x" * 20000}}),
])
def test_untrustworthy_launcher_records_are_ignored(world, label, kwargs):
    _write_err(world, **kwargs)
    api = world.get()
    assert api["state"] == "pending" and "error" not in api, label


@pytest.mark.skipif(os.name != "posix", reason="uid / modes / links")
def test_symlink_wrong_owner_and_garbage_records_are_ignored(world, monkeypatch):
    base = world.reports / ".ctrl" / PROJ
    real = _write_err(world, name="elsewhere.txt")
    os.symlink(real, base / f"trigger_{RID}.json.err")                           # a link is never followed
    assert world.get()["state"] == "pending"
    os.unlink(base / f"trigger_{RID}.json.err")
    _write_err(world)
    assert world.get()["state"] == "error"                                       # sanity: a good record IS used
    real_uid = os.getuid()
    monkeypatch.setattr(pr.os, "getuid", lambda: real_uid + 1)                   # not owned by the dashboard user
    assert world.get()["state"] == "pending"
    monkeypatch.undo()
    for garbage in ("not json", "[1,2,3]", ""):
        (base / f"trigger_{RID}.json.err").write_text(garbage)
        os.chmod(base / f"trigger_{RID}.json.err", 0o600)
        assert world.get()["state"] == "pending"


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_a_fifo_in_place_of_the_record_does_not_block_the_api(world):
    path = world.reports / ".ctrl" / PROJ / f"trigger_{RID}.json.err"
    os.mkfifo(path)                                                              # O_NONBLOCK + regular-file check: returns at once
    assert world.get()["state"] == "pending"


@pytest.mark.skipif(os.name != "posix", reason="uid / modes")
def test_unrecognised_launcher_text_and_missing_exit_code_use_the_generic_message(world):
    _write_err(world, payload={"error": "Could not open /home/someone/private/file.json", "exit_code": 78})
    api = world.get()
    assert api["error"]["code"] == "LAUNCHER_ERROR" and "/home/someone" not in json.dumps(api)
