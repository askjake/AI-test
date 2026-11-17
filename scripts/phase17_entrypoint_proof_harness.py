#!/usr/bin/env python3
"""Target-free proof of the production Watch & Learn entrypoint chain.

This source-validation harness supplies only the container-engine boundary.  It
does not create or open control FIFOs.  The production adapter, runner shell,
container entrypoint, privilege-drop module, and worker self-test execute
unchanged.  A small temporary set-id launcher models the engine's root
entrypoint while the dashboard side runs as a distinct unprivileged account.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


IMAGE = "phase17.invalid/orchestrator-cookie@sha256:" + "a" * 64
SESSION_IDS = {
    "success": "1" * 32,
    "malformed": "2" * 32,
    "preexisting": "3" * 32,
    "partial": "4" * 32,
}


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def _account(name: str) -> pwd.struct_passwd:
    account = pwd.getpwnam(name)
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise RuntimeError(f"{name} must resolve to a non-root uid and gid")
    return account


def _drop_to(account: pwd.struct_passwd) -> None:
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def _mode_owner(path: Path) -> dict[str, Any]:
    info = os.lstat(path)
    return {
        "type": (
            "directory" if stat.S_ISDIR(info.st_mode)
            else "fifo" if stat.S_ISFIFO(info.st_mode)
            else "regular" if stat.S_ISREG(info.st_mode)
            else "other"
        ),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


def _parse_status(path: Path) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            fields[name] = value.strip()
    return {
        "uid": [int(item) for item in fields["Uid"].split()],
        "gid": [int(item) for item in fields["Gid"].split()],
        "groups": [int(item) for item in fields.get("Groups", "").split()],
    }


def _environment(path: Path) -> list[str]:
    return [
        item.decode("utf-8", errors="replace")
        for item in path.read_bytes().split(b"\0")
        if item
    ]


def _runtime_cannot_reopen(paths: list[Path], account: pwd.struct_passwd) -> bool:
    child = os.fork()
    if child == 0:
        try:
            _drop_to(account)
            for path in paths:
                try:
                    descriptor = os.open(path, os.O_RDWR | os.O_NONBLOCK)
                except PermissionError:
                    continue
                else:
                    os.close(descriptor)
                    os._exit(1)
            os._exit(0)
        except BaseException:
            os._exit(2)
    _pid, status_value = os.waitpid(child, 0)
    return os.WIFEXITED(status_value) and os.WEXITSTATUS(status_value) == 0


def _docker_environment(arguments: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        if arguments[index] == "-e" and index + 1 < len(arguments):
            item = arguments[index + 1]
            if "=" in item:
                key, value = item.split("=", 1)
                values[key] = value
            elif item in os.environ:
                values[item] = os.environ[item]
            index += 2
            continue
        index += 1
    return values


def _control_mount(arguments: list[str]) -> Path:
    suffix = ":/app/watch-learn-control:rw"
    for index, item in enumerate(arguments[:-1]):
        if item == "-v" and arguments[index + 1].endswith(suffix):
            return Path(arguments[index + 1][:-len(suffix)])
    raise RuntimeError("private Watch & Learn mount is missing")


def _image_index(arguments: list[str]) -> int:
    try:
        return arguments.index(IMAGE)
    except ValueError as exc:
        raise RuntimeError("unexpected digest-pinned harness image") from exc


def _safe_run_contract(arguments: list[str], command: list[str]) -> dict[str, bool]:
    forwarded = _docker_environment(arguments)
    volume_values = [
        arguments[index + 1]
        for index, item in enumerate(arguments[:-1])
        if item == "-v"
    ]
    checks = {
        "network_none": "--network=none" in arguments,
        "no_published_port": not any(
            item in {"-p", "--publish"} or item.startswith("--publish=")
            for item in arguments
        ),
        "no_pull_or_build": (
            "--pull=never" in arguments
            and "pull" not in arguments
            and "build" not in arguments
        ),
        "only_private_control_bind": (
            len(volume_values) == 1
            and volume_values[0].endswith(":/app/watch-learn-control:rw")
        ),
        "no_host_app_forwarding": not any(
            "HOST_APP" in item or "HOST_DISPLAY" in item for item in arguments
        ),
        "no_target_source_forwarding": not any(
            target in item
            for item in arguments
            for target in ("/app/reports", "/app/tests_specs", "/app/tests_manuals", "/app/secrets-source")
        ),
        "no_model_or_aws_forwarding": not any(
            key.startswith("AWS_") or "BEDROCK" in key
            for key in forwarded
        ),
        "worker_self_test_only": (
            command[:3] == ["python", "-m", "orchestrator.watch_learn_worker"]
            and "--self-test" in command
        ),
    }
    if not all(checks.values()):
        raise RuntimeError(f"unsafe deterministic engine invocation: {checks}")
    return checks


def _engine(arguments: list[str]) -> int:
    if arguments[:1] == ["version"]:
        print("phase17-deterministic-engine-1")
        return 0
    if arguments[:2] == ["image", "inspect"]:
        print(json.dumps([arguments[-1]]))
        return 0
    if arguments[:1] != ["run"]:
        return 64

    repo_root = Path(os.environ["PHASE17_HARNESS_REPO_ROOT"])
    evidence_path = Path(os.environ["PHASE17_ENGINE_EVIDENCE"])
    entrypoint_log = Path(os.environ["PHASE17_ENTRYPOINT_LOG"])
    stub_bin = Path(os.environ["PHASE17_STUB_BIN"])
    stub_log = Path(os.environ["PHASE17_STUB_LOG"])
    runtime = _account(os.environ["PHASE17_RUNTIME_USER"])
    dashboard = _account(os.environ["PHASE17_DASHBOARD_USER"])
    control = _control_mount(arguments)
    image_index = _image_index(arguments)
    command = list(arguments[image_index + 1:])
    contract = _safe_run_contract(arguments, command)
    forwarded = _docker_environment(arguments)

    environment = dict(os.environ)
    environment.update(forwarded)
    environment.update({
        "PATH": f"{stub_bin}:{environment.get('PATH', '/usr/bin:/bin')}",
        "PYTHONPATH": str(repo_root / "src"),
        "WATCH_LEARN_CONTROL_DIR": str(control),
        "WATCH_LEARN_ENTRYPOINT_HARNESS": "1",
        "ORCHESTRATOR_RUNTIME_USER": runtime.pw_name,
        "PHASE17_STUB_LOG": str(stub_log),
    })
    environment.pop("ORCHESTRATOR_PRIVILEGES_DROPPED", None)
    safe_environment = {
        key: environment.get(key, "")
        for key in (
            "WATCH_LEARN_CONTROL_DIR", "WATCH_LEARN_CONTROL_OWNER_UID",
            "WATCH_LEARN_CONTROL_OWNER_GID", "WATCH_LEARN_SELF_TEST",
            "ORCHESTRATOR_RUNTIME_USER",
        )
    }

    evidence: dict[str, Any] = {
        "engine_operation": "run",
        "engine_created_fifos": False,
        "engine_opened_fifo_descriptors": False,
        "run_contract": contract,
        "command": command,
        "forwarded_environment": safe_environment,
        "control_before_entrypoint": _mode_owner(control),
        "worker": None,
    }
    entrypoint_log.parent.mkdir(parents=True, exist_ok=True)
    with entrypoint_log.open("wb", buffering=0) as output:
        process = subprocess.Popen(
            [str(repo_root / "docker" / "entrypoint.sh"), *command],
            cwd=repo_root,
            env=environment,
            stdin=0,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=False,
        )
        try:
            os.close(0)
        except OSError:
            pass

        deadline = time.monotonic() + 15.0
        request_path = control / "requests.fifo"
        response_path = control / "responses.fifo"
        while time.monotonic() < deadline and process.poll() is None:
            proc = Path("/proc") / str(process.pid)
            try:
                command_line = proc.joinpath("cmdline").read_bytes().replace(b"\0", b" ").decode(
                    "utf-8", errors="replace"
                ).strip()
                if (
                    "orchestrator.watch_learn_worker" in command_line
                    and request_path.exists() and response_path.exists()
                ):
                    status_value = _parse_status(proc / "status")
                    process_environment = _environment(proc / "environ")
                    fd_values = {
                        item.split("=", 1)[0]: item.split("=", 1)[1]
                        for item in process_environment
                        if item.startswith("WATCH_LEARN_REQUEST_FD=")
                        or item.startswith("WATCH_LEARN_RESPONSE_FD=")
                    }
                    request_fd = fd_values["WATCH_LEARN_REQUEST_FD"]
                    response_fd = fd_values["WATCH_LEARN_RESPONSE_FD"]
                    request_link = os.readlink(proc / "fd" / request_fd)
                    response_link = os.readlink(proc / "fd" / response_fd)
                    evidence["worker"] = {
                        "pid": process.pid,
                        "cmdline": command_line,
                        "uid": status_value["uid"],
                        "gid": status_value["gid"],
                        "groups": status_value["groups"],
                        "permanent_nonroot": (
                            status_value["uid"] == [runtime.pw_uid] * 4
                            and status_value["gid"] == [runtime.pw_gid] * 4
                            and status_value["groups"] == []
                        ),
                        "control_dir": _mode_owner(control),
                        "requests_fifo": _mode_owner(request_path),
                        "responses_fifo": _mode_owner(response_path),
                        "descriptor_links": [request_link, response_link],
                        "descriptors_survived_drop": (
                            request_link == str(request_path)
                            and response_link == str(response_path)
                            and stat.S_ISFIFO(os.stat(proc / "fd" / request_fd).st_mode)
                            and stat.S_ISFIFO(os.stat(proc / "fd" / response_fd).st_mode)
                        ),
                        "runtime_cannot_reopen_endpoints": _runtime_cannot_reopen(
                            [request_path, response_path], runtime
                        ),
                        "dashboard_owner": {
                            "uid": dashboard.pw_uid,
                            "gid": dashboard.pw_gid,
                        },
                        "args_environment": command_line + "\n" + "\n".join(process_environment),
                    }
                    break
            except (FileNotFoundError, KeyError, PermissionError, ProcessLookupError):
                pass
            time.sleep(0.01)

        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            return_code = process.wait(timeout=5)
            evidence["timeout"] = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    evidence["entrypoint_return_code"] = return_code
    evidence["stub_invocations"] = (
        stub_log.read_text(encoding="utf-8").splitlines() if stub_log.exists() else []
    )
    _write_json(evidence_path, evidence)
    return return_code


def _fixture_adapter(base_class, scenario: str):
    class FixtureAdapter(base_class):
        def _prepare_control_dir(self, session_id: str) -> str:
            control = Path(super()._prepare_control_dir(session_id))
            if scenario == "malformed":
                (control / "requests.fifo").write_bytes(b"not-a-fifo")
                os.chmod(control / "requests.fifo", 0o600)
            elif scenario == "preexisting":
                os.mkfifo(control / "requests.fifo", 0o600)
                os.mkfifo(control / "responses.fifo", 0o600)
            elif scenario == "partial":
                os.mkfifo(control / "requests.fifo", 0o600)
            return str(control)

    return FixtureAdapter


def _adapter_child(scenario: str) -> int:
    from PIL import Image

    from dashboard.authoring import LocalAppTarget, ProjectDocument
    from dashboard.capture_adapter import RunnerControlledCaptureAdapter
    from dashboard.config import DashboardSettings
    import dashboard.capture_adapter as capture_adapter_module
    from orchestrator.watch_learn_worker import SELF_TEST_SECRET_MARKER

    repo_root = Path(os.environ["PHASE17_HARNESS_REPO_ROOT"])
    state_root = Path(os.environ["PHASE17_CHILD_STATE"])
    state_root.mkdir(parents=True, exist_ok=True)
    project = ProjectDocument(
        dir_name="phase17-self-test",
        display_name="Phase 17 target-free entrypoint proof",
        schedule="0 0 * * *",
        target=LocalAppTarget(app="never-opened", window="Never opened"),
        redaction=[[0, 0, 32, 32]],
        max_steps=1,
        max_seconds=30,
    )
    settings = DashboardSettings(
        watch_learn_runner_image=IMAGE,
        watch_learn_connect_timeout_seconds=15,
        watch_learn_action_timeout_seconds=15,
        watch_learn_state_root=str(state_root / "private-state"),
    )
    adapter_class = (
        RunnerControlledCaptureAdapter
        if scenario == "success"
        else _fixture_adapter(RunnerControlledCaptureAdapter, scenario)
    )
    adapter = adapter_class(settings, repo_root=str(repo_root))
    token = secrets.token_urlsafe(48)
    capture_adapter_module.secrets.token_urlsafe = lambda _size: token
    session_id = SESSION_IDS[scenario]
    result: dict[str, Any] = {
        "scenario": scenario,
        "success": False,
        "cleanup_removed_control_directory": False,
        "capability_absent_from_emitted_evidence": False,
    }
    evidence_path = Path(os.environ["PHASE17_ENGINE_EVIDENCE"])
    log_path = Path(os.environ["PHASE17_ENTRYPOINT_LOG"])
    try:
        if scenario == "success":
            outcome = adapter.transport_self_test(session_id, project)
            if outcome.evidence_png is None:
                raise RuntimeError("self-test returned no redacted evidence")
            image = Image.open(io.BytesIO(outcome.evidence_png))
            image.load()
            raw_sources = [
                outcome.evidence_png,
                evidence_path.read_bytes(),
                log_path.read_bytes(),
            ]
            capability_absent = all(token.encode("ascii") not in item for item in raw_sources)
            result.update({
                "success": outcome.outcome == "executed",
                "outcome": outcome.outcome,
                "evidence_sha256": hashlib.sha256(outcome.evidence_png).hexdigest(),
                "evidence_png_bounded": len(outcome.evidence_png) <= settings.watch_learn_max_evidence_bytes,
                "raw_secret_marker_absent": SELF_TEST_SECRET_MARKER.encode("ascii") not in outcome.evidence_png,
                "png_metadata_empty": not image.info,
                "capability_accepted_over_stdin": outcome.outcome == "executed",
                "capability_absent_from_emitted_evidence": capability_absent,
            })
        else:
            try:
                adapter.transport_self_test(session_id, project)
            except RuntimeError:
                result["success"] = True
                result["failed_closed"] = True
            else:
                result["failed_closed"] = False
    finally:
        control_path = Path(adapter.control_root) / session_id
        result["cleanup_removed_control_directory"] = not control_path.exists()
        result["control_root_removed"] = not Path(adapter.control_root).exists()
    if not result["success"] or not result["cleanup_removed_control_directory"]:
        raise RuntimeError(f"entrypoint harness scenario failed: {result}")
    print(json.dumps(result, sort_keys=True))
    return 0


def _compile_engine(wrapper: Path, repo_root: Path) -> None:
    source = wrapper.with_suffix(".c")
    python_literal = json.dumps(sys.executable)
    script_literal = json.dumps(str(repo_root / "scripts" / "phase17_entrypoint_proof_harness.py"))
    source.write_text(
        """
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (setgroups(0, NULL) != 0 || setgid(0) != 0 || setuid(0) != 0) {
        perror("phase17 deterministic engine privilege setup");
        return 78;
    }
    char **next = calloc((size_t)argc + 3, sizeof(char *));
    if (next == NULL) return 70;
    next[0] = %s;
    next[1] = %s;
    next[2] = "__engine";
    for (int i = 1; i < argc; ++i) next[i + 2] = argv[i];
    execv(next[0], next);
    perror("phase17 deterministic engine exec");
    return errno == 0 ? 70 : errno;
}
""" % (python_literal, script_literal),
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-o", str(wrapper), str(source)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    os.chown(wrapper, 0, 0)
    os.chmod(wrapper, 0o4755)
    source.unlink()


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    os.chmod(path, 0o755)


_STUB_FD_CHECK = (
    'fifo_fds=0\nfor handle in /proc/self/fd/*; do '
    'target="$(readlink "$handle" 2>/dev/null || true)"; '
    'case "$target" in *requests.fifo|*responses.fifo) fifo_fds=$((fifo_fds+1));; esac; '
    'done\n'
)


def _run_child(
    *,
    scenario: str,
    repo_root: Path,
    root: Path,
    engine: Path,
    dashboard: pwd.struct_passwd,
    runtime: pwd.struct_passwd,
) -> tuple[dict[str, Any], dict[str, Any]]:
    scenario_root = root / scenario
    scenario_root.mkdir(mode=0o755)
    child_state = scenario_root / "child"
    child_state.mkdir(mode=0o700)
    os.chown(child_state, dashboard.pw_uid, dashboard.pw_gid)
    child_home = scenario_root / "home"
    child_home.mkdir(mode=0o700)
    os.chown(child_home, dashboard.pw_uid, dashboard.pw_gid)
    child_tmp = scenario_root / "tmp"
    child_tmp.mkdir(mode=0o700)
    os.chown(child_tmp, dashboard.pw_uid, dashboard.pw_gid)
    engine_evidence = scenario_root / "engine.json"
    entrypoint_log = scenario_root / "entrypoint.log"
    stub_log = scenario_root / "stubs.log"
    stub_log.touch(mode=0o666)
    os.chmod(stub_log, 0o666)
    environment = {
        **os.environ,
        "ENGINE": str(engine),
        "IMAGE": IMAGE,
        "HOME": str(child_home),
        "TMPDIR": str(child_tmp),
        "PYTHONPATH": str(repo_root / "src"),
        "REPORTS_DIR": str(child_state / "reports"),
        "SPECS_DIR": str(child_state / "specs"),
        "MANUALS_DIR": str(child_state / "manuals"),
        "SECRETS_DIR": str(child_state / "secrets"),
        "DISPLAY_LOCK_DIR": str(child_state / "locks"),
        "PHASE17_HARNESS_REPO_ROOT": str(repo_root),
        "PHASE17_ENGINE_EVIDENCE": str(engine_evidence),
        "PHASE17_ENTRYPOINT_LOG": str(entrypoint_log),
        "PHASE17_STUB_BIN": str(root / "stubs"),
        "PHASE17_STUB_LOG": str(stub_log),
        "PHASE17_CHILD_STATE": str(child_state),
        "PHASE17_DASHBOARD_USER": dashboard.pw_name,
        "PHASE17_RUNTIME_USER": runtime.pw_name,
    }
    completed = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "phase17_entrypoint_proof_harness.py"), "__adapter", scenario],
        cwd=repo_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
        preexec_fn=lambda: _drop_to(dashboard),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{scenario} adapter child failed rc={completed.returncode}: {completed.stderr[-2000:]}"
        )
    child_result = json.loads(completed.stdout.strip().splitlines()[-1])
    engine_result = json.loads(engine_evidence.read_text(encoding="utf-8"))
    return child_result, engine_result


def _coordinator(output: Path, workspace: Path) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    dashboard = _account("nobody")
    runtime = _account("daemon")
    blockers: list[str] = []
    if os.geteuid() != 0:
        blockers.append("isolated source-validation process is not root")
    uid_map = Path("/proc/self/uid_map")
    gid_map = Path("/proc/self/gid_map")
    if uid_map.exists():
        mapped_uids = [
            (int(parts[0]), int(parts[2]))
            for line in uid_map.read_text(encoding="ascii").splitlines()
            if len(parts := line.split()) == 3
        ]
        if not any(start <= dashboard.pw_uid < start + length for start, length in mapped_uids):
            blockers.append(f"dashboard proof uid {dashboard.pw_uid} is not mapped")
        if not any(start <= runtime.pw_uid < start + length for start, length in mapped_uids):
            blockers.append(f"worker proof uid {runtime.pw_uid} is not mapped")
    if gid_map.exists():
        mapped_gids = [
            (int(parts[0]), int(parts[2]))
            for line in gid_map.read_text(encoding="ascii").splitlines()
            if len(parts := line.split()) == 3
        ]
        if not any(start <= dashboard.pw_gid < start + length for start, length in mapped_gids):
            blockers.append(f"dashboard proof gid {dashboard.pw_gid} is not mapped")
        if not any(start <= runtime.pw_gid < start + length for start, length in mapped_gids):
            blockers.append(f"worker proof gid {runtime.pw_gid} is not mapped")
    if not shutil.which("gcc"):
        blockers.append("local C compiler is unavailable")
    if blockers:
        blocked = {
            "classification": "TARGET_FREE_ENTRYPOINT_PROOF_NOT_RUN_BLOCKED",
            "absent_prerequisites": blockers,
            "no_target_or_model_contact": True,
            "no_image_pull_or_build": True,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        _write_json(output, blocked)
        print(json.dumps(blocked, sort_keys=True))
        return 2
    if dashboard.pw_uid == runtime.pw_uid or dashboard.pw_gid == runtime.pw_gid:
        raise RuntimeError("dashboard and worker proof identities must be distinct")
    workspace.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace, 0o755)
    root = Path(tempfile.mkdtemp(prefix="phase17-entrypoint-proof-", dir=workspace))
    os.chmod(root, 0o755)
    try:
        stubs = root / "stubs"
        stubs.mkdir(mode=0o755)
        _stub(
            stubs / "Xvfb",
            _STUB_FD_CHECK
            + 'printf "Xvfb uid=%s gid=%s fifo_fds=%s\\n" "$(id -u)" "$(id -g)" "$fifo_fds" >>"$PHASE17_STUB_LOG"\n'
            "trap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n",
        )
        _stub(
            stubs / "xdpyinfo",
            _STUB_FD_CHECK
            + 'printf "xdpyinfo uid=%s gid=%s fifo_fds=%s\\n" "$(id -u)" "$(id -g)" "$fifo_fds" >>"$PHASE17_STUB_LOG"\nexit 0\n',
        )
        _stub(
            stubs / "fluxbox",
            _STUB_FD_CHECK
            + 'printf "fluxbox uid=%s gid=%s fifo_fds=%s\\n" "$(id -u)" "$(id -g)" "$fifo_fds" >>"$PHASE17_STUB_LOG"\n'
            "trap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n",
        )
        engine = root / "docker"
        _compile_engine(engine, repo_root)
        if not (engine.stat().st_mode & stat.S_ISUID):
            raise RuntimeError("deterministic engine launcher is not set-id")

        child_results: dict[str, Any] = {}
        engine_results: dict[str, Any] = {}
        for scenario in ("success", "malformed", "preexisting", "partial"):
            child_results[scenario], engine_results[scenario] = _run_child(
                scenario=scenario,
                repo_root=repo_root,
                root=root,
                engine=engine,
                dashboard=dashboard,
                runtime=runtime,
            )

        success_engine = engine_results["success"]
        worker = success_engine.get("worker") or {}
        expected_stub_identity = f"uid={runtime.pw_uid} gid={runtime.pw_gid}"
        proof = {
            "classification": "TARGET_FREE_ENTRYPOINT_PROOF_PASS",
            "production_chain": [
                "RunnerControlledCaptureAdapter",
                "scripts/run_container.sh",
                "docker/entrypoint.sh",
                "orchestrator.watch_learn_entrypoint",
                "real FIFO creation/opening/ownership verification",
                "permanent non-root transition",
                "watch_learn_worker --self-test",
            ],
            "dashboard_identity": {"uid": dashboard.pw_uid, "gid": dashboard.pw_gid},
            "worker_identity": {"uid": runtime.pw_uid, "gid": runtime.pw_gid},
            "success": child_results["success"],
            "engine": success_engine,
            "failure_scenarios": {
                name: child_results[name] for name in ("malformed", "preexisting", "partial")
            },
            "assertions": {
                "real_fifo_types_modes_owners": (
                    worker.get("control_dir") == {
                        "type": "directory", "mode": "0700",
                        "uid": dashboard.pw_uid, "gid": dashboard.pw_gid,
                    }
                    and worker.get("requests_fifo") == {
                        "type": "fifo", "mode": "0600",
                        "uid": dashboard.pw_uid, "gid": dashboard.pw_gid,
                    }
                    and worker.get("responses_fifo") == {
                        "type": "fifo", "mode": "0600",
                        "uid": dashboard.pw_uid, "gid": dashboard.pw_gid,
                    }
                ),
                "descriptors_survive_permanent_nonroot_drop": (
                    worker.get("permanent_nonroot") is True
                    and worker.get("descriptors_survived_drop") is True
                    and worker.get("runtime_cannot_reopen_endpoints") is True
                ),
                "capability_stdin_only": (
                    child_results["success"].get("capability_accepted_over_stdin") is True
                    and child_results["success"].get("capability_absent_from_emitted_evidence") is True
                ),
                "post_handoff_stubs_are_nonroot": (
                    success_engine.get("stub_invocations")
                    and all(
                        expected_stub_identity in line and "fifo_fds=0" in line
                        for line in success_engine["stub_invocations"]
                    )
                ),
                "failure_inputs_fail_closed_and_cleanup": all(
                    child_results[name].get("failed_closed") is True
                    and child_results[name].get("cleanup_removed_control_directory") is True
                    for name in ("malformed", "preexisting", "partial")
                ),
                "self_test_isolated_no_pull_build_target_model": all(
                    success_engine["run_contract"].values()
                ),
                "adapter_cleanup_removed_private_control_directory": (
                    child_results["success"].get("cleanup_removed_control_directory") is True
                    and child_results["success"].get("control_root_removed") is True
                ),
            },
        }
        if not all(proof["assertions"].values()):
            raise RuntimeError(f"entrypoint proof assertion failed: {proof['assertions']}")
        _write_json(output, proof)
        print(json.dumps({
            "classification": proof["classification"],
            "evidence": str(output),
            "assertions": proof["assertions"],
        }, sort_keys=True))
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values[:1] == ["__engine"]:
        return _engine(values[1:])
    if values[:1] == ["__adapter"]:
        if len(values) != 2 or values[1] not in SESSION_IDS:
            return 64
        return _adapter_child(values[1])
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    arguments = parser.parse_args(values)
    return _coordinator(arguments.output.resolve(), arguments.workspace.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
