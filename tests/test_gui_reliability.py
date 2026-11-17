"""Regression tests for dashboard run launch, refresh, and replay reliability."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

from dashboard.index import RunIndex
from dashboard.live import _rewrite_screenshot, tail_run
from dashboard.project_access import prepare_project_mounts


REPO_ROOT = Path(__file__).resolve().parents[1]


def _fake_host_egress_python(tmp_path: Path) -> Path:
    resolver = tmp_path / "host-egress-python"
    resolver.write_text(
        "#!/usr/bin/env bash\n"
        "printf '192.0.2.10\\tbedrock-runtime.us-west-2.amazonaws.com\\n'\n"
    )
    resolver.chmod(0o755)
    return resolver


def _fake_bedrock_relay(tmp_path: Path) -> Path:
    relay = tmp_path / "host-bedrock-relay"
    relay.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "state= endpoint=\n"
        "while (( $# )); do\n"
        "  case \"$1\" in\n"
        "    --state-file) state=$2; shift 2 ;;\n"
        "    --endpoint) endpoint=$2; shift 2 ;;\n"
        "    --engine|--address) shift 2 ;;\n"
        "    *) exit 64 ;;\n"
        "  esac\n"
        "done\n"
        "printf '{\"endpoint\":\"%s\",\"bind_host\":\"172.17.0.1\","
        "\"port\":45678,\"proxy_url\":\"http://runner:test-token@172.17.0.1:45678\"}\\n' "
        "\"$endpoint\" >\"$state\"\n"
        "trap 'exit 0' TERM INT\n"
        "while true; do sleep 1; done\n"
    )
    relay.chmod(0o755)
    return relay


def _fake_target_relay(tmp_path: Path) -> Path:
    relay = tmp_path / "host-target-relay"
    relay.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "state= kind= endpoint= destination_port=\n"
        "while (( $# )); do\n"
        "  case \"$1\" in\n"
        "    --state-file) state=$2; shift 2 ;;\n"
        "    --kind) kind=$2; shift 2 ;;\n"
        "    --endpoint) endpoint=$2; shift 2 ;;\n"
        "    --destination-port) destination_port=$2; shift 2 ;;\n"
        "    --engine|--address) shift 2 ;;\n"
        "    *) exit 64 ;;\n"
        "  esac\n"
        "done\n"
        "printf '{\"kind\":\"%s\",\"endpoint\":\"%s\","
        "\"destination_port\":%s,\"bind_host\":\"172.17.0.1\","
        "\"port\":45679,\"token\":\"abcdefghijklmnopqrstuvwxyzABCDEFGH\"}\\n' "
        "\"$kind\" \"$endpoint\" \"$destination_port\" >\"$state\"\n"
        "trap 'exit 0' TERM INT\n"
        "while true; do sleep 1; done\n"
    )
    relay.chmod(0o755)
    return relay


def _run_summary(project: str, run_ts: str, *, passed: int) -> dict:
    return {
        "project": project,
        "run_ts": run_ts,
        "model_id": "model",
        "total": passed,
        "passed": passed,
        "failed": 0,
        "errored": 0,
        "spec_total": 1,
        "duration_seconds": 1.0,
    }



def _contract_env(tmp_path, project):
    """CP45-I: what the dashboard hands a launch - precreated 0755 report paths plus the ids, exactly as routes.trigger_run does."""
    from dashboard.project_access import precreate_run_dirs
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    os.chmod(reports, 0o755)
    tid, ts = "trig_20261116T010203_deadbeef", "20261116T010203Z"
    precreate_run_dirs(str(reports), project, tid, ts)
    return {"ORCHESTRATOR_REPORT_HANDOFF": "1", "ORCHESTRATOR_REPORT_PROJECT": project, "ORCHESTRATOR_RUN_TS": ts, "ORCHESTRATOR_TRIGGER_ID": tid}


def test_index_refreshes_an_existing_provisional_run(tmp_path):
    reports = tmp_path / "reports"
    run_dir = reports / "project" / "20260820T120000Z"
    run_dir.mkdir(parents=True)
    run_json = run_dir / "run.json"
    run_json.write_text(json.dumps(_run_summary("project", run_dir.name, passed=0)))

    index = RunIndex(str(reports))
    assert index.scan_once() == 1
    assert index.get_run("project", run_dir.name).passed == 0

    run_json.write_text(json.dumps(_run_summary("project", run_dir.name, passed=3)))
    assert index.scan_once() == 0
    assert index.get_run("project", run_dir.name).passed == 3


def test_completed_run_replays_audit_history(tmp_path):
    reports = tmp_path / "reports"
    run_dir = reports / "project" / "20260820T120000Z"
    evidence = run_dir / "login"
    evidence.mkdir(parents=True)
    (evidence / "result.json").write_text(json.dumps({"title": "Login"}))
    (evidence / "audit.jsonl").write_text(
        json.dumps({
            "kind": "action",
            "seq": 1,
            "screenshot_path": "/app/reports/project/20260820T120000Z/login/shot.png",
        }) + "\n"
    )
    (run_dir / "status.json").write_text(json.dumps({
        "state": "complete",
        "specs_total": 1,
        "specs_completed": [{
            "title": "Login",
            "status": "passed",
            "evidence_dir": "login",
        }],
    }))

    async def collect():
        return [item async for item in tail_run(str(reports), "project", run_dir.name)]

    events = asyncio.run(collect())
    assert [event["event"] for event in events] == [
        "spec_change", "audit_event", "run_complete"
    ]
    audit = json.loads(events[1]["data"])
    assert audit["screenshot_url"] == (
        "/reports/project/20260820T120000Z/login/shot.png"
    )


def test_live_event_rewrites_before_and_after_screenshots(tmp_path):
    from dashboard.live import _parse_audit_line

    reports = tmp_path / "reports"
    reports.mkdir()
    event = _parse_audit_line(json.dumps({
        "kind": "action",
        "before_screenshot_path": "reports/project/run/spec/before.png",
        "after_screenshot_path": "reports/project/run/spec/after.png",
    }), str(reports))
    data = json.loads(event["data"])
    assert data["before_screenshot_url"] == "/reports/project/run/spec/before.png"
    assert data["after_screenshot_url"] == "/reports/project/run/spec/after.png"


def test_screenshot_rewrite_rejects_paths_outside_reports(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    assert _rewrite_screenshot("/etc/passwd", str(reports)) is None
    assert _rewrite_screenshot("../secret.png", str(reports)) is None


def test_screenshot_rewrite_does_not_duplicate_relative_reports_prefix(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    path = "reports/project/20260820T120000Z/login/shot.png"
    assert _rewrite_screenshot(path, str(reports)) == (
        "/reports/project/20260820T120000Z/login/shot.png"
    )


def test_trigger_preparation_repairs_restrictive_project_modes(tmp_path):
    specs = tmp_path / "tests_specs"
    reports = tmp_path / "reports"
    project = specs / "rdp2"
    project.mkdir(parents=True, mode=0o700)
    config = project / "project.yaml"
    spec = project / "000-first-test.md"
    config.write_text("name: rdp2\nenabled: true\n")
    spec.write_text("# Test: RDP\n\n## Goal\nConnect.\n")
    os.chmod(project, 0o700)
    os.chmod(config, 0o600)
    os.chmod(spec, 0o600)

    prepare_project_mounts(str(specs), str(reports), "rdp2")

    assert stat.S_IMODE(project.stat().st_mode) == 0o755
    assert stat.S_IMODE(config.stat().st_mode) == 0o644
    assert stat.S_IMODE(spec.stat().st_mode) == 0o644
    assert stat.S_IMODE((reports / "rdp2").stat().st_mode) == 0o755      # CP45-G: dashboard-owned, not shared


def test_stale_running_stream_replays_then_closes(tmp_path):
    reports = tmp_path / "reports"
    run_dir = reports / "project" / "20260820T120000Z"
    run_dir.mkdir(parents=True)
    status_path = run_dir / "status.json"
    status_path.write_text(json.dumps({"state": "running"}))
    old = time.time() - 10
    os.utime(status_path, (old, old))

    async def collect():
        return [
            item
            async for item in tail_run(
                str(reports), "project", run_dir.name, stale_seconds=1
            )
        ]

    events = asyncio.run(collect())
    assert events[-1]["event"] == "run_complete"
    assert json.loads(events[-1]["data"])["state"] == "error"


@pytest.mark.parametrize("exit_code,outcome", [(0, "ack"), (7, "err")])
def test_spawn_wrapper_records_process_outcome(tmp_path, exit_code, outcome):
    fake_runner = tmp_path / "fake-runner.sh"
    fake_runner.write_text(
        f"#!/usr/bin/env bash\n"
        f"echo 'error: deliberate trigger failure'\n"
        f"exit {exit_code}\n"
    )
    fake_runner.chmod(0o755)
    claimed = tmp_path / "trigger_trig_20260820T120000_deadbeef.json.claimed"
    claimed.write_text(json.dumps({"project": "project"}))
    env = {**os.environ, "RUN_SPECS_SCRIPT": str(fake_runner)}

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_trigger.sh"), "project", str(claimed)],
        env=env,
        check=False,
    )

    assert result.returncode == exit_code
    assert (tmp_path / f"trigger_trig_20260820T120000_deadbeef.json.{outcome}").is_file()
    assert not claimed.exists()
    if outcome == "err":
        payload = json.loads(
            (tmp_path / "trigger_trig_20260820T120000_deadbeef.json.err").read_text()
        )
        assert payload["error"] == "error: deliberate trigger failure"
        assert payload["exit_code"] == exit_code


def test_frontend_never_puts_auth_token_in_eventsource_url():
    html = (REPO_ROOT / "templates" / "dashboard" / "index.html").read_text()
    assert 'new EventSource(url)' in html
    assert 'EventSource(url + "?token="' not in html
    assert 'api("/auth/sse-session", {method: "POST"})' in html


def test_frontend_has_large_live_screenshot_viewport():
    html = (REPO_ROOT / "templates" / "dashboard" / "index.html").read_text()
    assert 'id="live-preview"' in html
    assert 'class="live-workspace"' in html
    assert "d.after_screenshot_url || d.screenshot_url" in html


def test_frontend_has_project_scoped_stop_controls():
    html = (REPO_ROOT / "templates" / "dashboard" / "index.html").read_text()
    assert 'id="stop-run-btn"' in html
    assert 'id="live-stop-btn"' in html
    assert 'data-project="${esc(name)}"' in html
    assert 'async function cancelRun(btn)' in html
    assert '"/runs/cancel"' in html
    assert 'Other projects will continue running.' in html
    assert 'triggerPollProjects.delete(project)' in html


def test_container_uses_trigger_owned_name_when_supplied():
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    assert 'ORCHESTRATOR_CONTAINER_NAME="${ORCHESTRATOR_CONTAINER_NAME:-}"' in runner
    assert 'CONTAINER_NAME_ARGS=(--name "${ORCHESTRATOR_CONTAINER_NAME}")' in runner
    assert '"${CONTAINER_NAME_ARGS[@]}"' in runner


def test_container_allocates_unique_x_display_and_rejects_dead_xvfb():
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()
    assert 'DISPLAY_SLOT_MIN="${DISPLAY_SLOT_MIN:-99}"' in runner
    assert '-e "DISPLAY=:${DISPLAY_SLOT}"' in runner
    assert "flock -n" in runner
    assert '-e DISPLAY=:99' not in runner
    assert 'kill -0 "${XVFB_PID}"' in entrypoint
    assert 'scripts/host_app_bridge.py' in runner
    assert 'HOST_APP_BRIDGE_ACTIVE=1' in runner
    assert '--check' in runner
    assert 'HOST_DISPLAY_READY_FILE' in runner
    assert 'HOST_DISPLAY_READY_FILE' in entrypoint


def test_container_stages_owner_only_secrets_in_tmpfs_before_agent_start():
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()

    assert '--user root' in runner
    assert 'mkdir -p -m 0700 "${SECRETS_DIR}"' in runner
    assert '${SECRETS_DIR}:/app/secrets-source:ro' in runner
    assert '--tmpfs /app/secrets:rw,nosuid,nodev,noexec,size=16m,mode=0700' in runner
    assert '--cap-add DAC_READ_SEARCH' in runner
    assert '--cap-add CHOWN' in runner
    assert '--cap-add SETUID' in runner
    assert '--cap-add SETGID' in runner
    assert 'python -m orchestrator.secret_stage' in entrypoint
    assert 'os.setuid(account.pw_uid)' in entrypoint
    assert 'runtime privileges dropped' in entrypoint
    assert 'SECRETS_DIR}:/app/secrets:ro' not in runner


def test_container_applies_egress_in_private_network_namespace_before_drop():
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()
    firewall = (REPO_ROOT / "docker" / "egress_firewall.sh").read_text()

    assert 'NETWORK_ARGS=(--network=bridge)' in runner
    assert '--network=host' not in runner
    assert '${RUNNER_HOSTS_FILE}:/etc/hosts:ro' in runner
    assert 'orchestrator.egress --resolved-hosts' in runner
    assert '-e VNC_HOST_ALLOWLIST' in runner
    assert '/app/docker/egress_firewall.sh' in entrypoint
    assert entrypoint.index('/app/docker/egress_firewall.sh') < entrypoint.index('exec python -m orchestrator.watch_learn_entrypoint')
    assert 'IP6TABLES' in firewall
    assert 'getent' not in firewall
    assert "' /etc/hosts | sort -u" in firewall
    assert '--dport "${ports}"' in firewall
    assert '--dport 53' not in firewall
    assert 'ORCHESTRATOR_BEDROCK_PROXY_HOST' in firewall
    assert 'ORCHESTRATOR_BEDROCK_PROXY_PORT' in firewall
    assert 'host}" == "${BEDROCK_ENDPOINT}' in firewall
    assert 'RULES+=("${BEDROCK_PROXY_HOST}" "${BEDROCK_PROXY_PORT}")' in firewall
    assert 'orchestrator.target_relay describe' in runner
    assert 'ORCHESTRATOR_TARGET_RELAY_TOKEN' in runner
    assert 'ORCHESTRATOR_TARGET_RELAY_TOKEN' in firewall
    assert 'RULES+=("${TARGET_RELAY_HOST}" "${TARGET_RELAY_PORT}")' in firewall
    assert 'target_endpoint_count' in firewall
    assert "bedrock_connect_relay" in (REPO_ROOT / "src/orchestrator/runtime_runner.py").read_text()
    runtime_runner = (REPO_ROOT / "src/orchestrator/runtime_runner.py").read_text()
    assert "target_connect_relay" in runtime_runner
    assert "ORCHESTRATOR_TARGET_RELAY_TOKEN" in runtime_runner
    assert "ORCHESTRATOR_EGRESS_PROJECT" in runtime_runner


def test_image_normalizes_only_packaged_non_secret_runtime_content():
    dockerfile = (REPO_ROOT / "docker" / "Dockerfile").read_text()

    normalization = "chmod -R a+rX /app/src /app/templates /app/scripts"
    assert normalization in dockerfile
    assert dockerfile.index("COPY src/ /app/src/") < dockerfile.index(normalization)
    assert dockerfile.index(normalization) < dockerfile.index("USER orchestrator")
    normalization_line = next(
        line for line in dockerfile.splitlines() if normalization in line
    )
    assert "/app/secrets" not in normalization_line
    assert "/app/aws-runtime" not in normalization_line
    assert "/app/reports" not in normalization_line
    assert "/app/tests_specs" not in normalization_line
    assert "/app/tests_manuals" not in normalization_line
    assert "chmod 0755 /app/entrypoint.sh /app/docker/egress_firewall.sh" in dockerfile
    assert "chmod +x /app/entrypoint.sh /app/docker/egress_firewall.sh" not in dockerfile


def test_standard_runner_hosts_bind_exists_only_for_the_container_call(tmp_path):
    fake_engine = tmp_path / "docker"
    captured = tmp_path / "engine.args"
    hosts_evidence = tmp_path / "hosts.evidence"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    *:/etc/hosts:ro)\n"
        "      source_path=${arg%:/etc/hosts:ro}\n"
        "      test -f \"$source_path\"\n"
        "      printf 'path=%s\\nmode=%s\\n' \"$source_path\" "
        "\"$(stat -c '%a' -- \"$source_path\")\" >\"${HOSTS_EVIDENCE_FILE}\"\n"
        "      cat -- \"$source_path\" >>\"${HOSTS_EVIDENCE_FILE}\"\n"
        "      ;;\n"
        "  esac\n"
        "done\n"
    )
    fake_engine.chmod(0o755)
    for name in ("reports", "specs", "manuals", "secrets"):
        (tmp_path / name).mkdir()
    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_FILE": str(captured),
        "HOSTS_EVIDENCE_FILE": str(hosts_evidence),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "SPECS_DIR": str(tmp_path / "specs"),
        "MANUALS_DIR": str(tmp_path / "manuals"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "IMAGE": "registry.example/runner@sha256:" + "a" * 64,
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)),
        "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path)),
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = hosts_evidence.read_text(encoding="utf-8")
    source_line = next(line for line in evidence.splitlines() if line.startswith("path="))
    hosts_path = Path(source_line.removeprefix("path="))
    assert "mode=644" in evidence
    assert "127.0.0.1 localhost orchestrator-cookie-runner" in evidence
    assert "::1 localhost ip6-localhost ip6-loopback" in evidence
    assert "192.0.2.10 bedrock-runtime.us-west-2.amazonaws.com" in evidence
    assert not hosts_path.exists()
    args = captured.read_text(encoding="utf-8").splitlines()
    assert "--network=bridge" in args
    assert "--network=host" not in args
    assert "DAC_OVERRIDE" not in args
    assert any(value.endswith(":/etc/hosts:ro") for value in args)
    assert "ORCHESTRATOR_BEDROCK_ENDPOINT=bedrock-runtime.us-west-2.amazonaws.com" in args
    assert "ORCHESTRATOR_BEDROCK_PROXY_HOST=172.17.0.1" in args
    assert "ORCHESTRATOR_BEDROCK_PROXY_PORT=45678" in args
    assert any(value.startswith("HTTPS_PROXY=http://runner:") for value in args)
    assert "ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1" not in args


def test_standard_runner_rejects_invalid_host_resolution_before_engine(tmp_path):
    marker = tmp_path / "engine-called"
    fake_engine = tmp_path / "docker"
    fake_engine.write_text(f"#!/usr/bin/env bash\ntouch '{marker}'\n")
    fake_engine.chmod(0o755)
    invalid_resolver = tmp_path / "invalid-host-egress-python"
    invalid_resolver.write_text(
        "#!/usr/bin/env bash\n"
        "printf '999.0.0.1\\tbedrock-runtime.us-west-2.amazonaws.com\\n'\n"
    )
    invalid_resolver.chmod(0o755)
    for name in ("reports", "specs", "manuals", "secrets"):
        (tmp_path / name).mkdir()
    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "SPECS_DIR": str(tmp_path / "specs"),
        "MANUALS_DIR": str(tmp_path / "manuals"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(invalid_resolver),
    }

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 69
    assert "invalid IPv4 data" in result.stderr
    assert not marker.exists()


def test_vnc_runner_uses_destination_locked_host_relay_and_omits_direct_target(tmp_path):
    fake_engine = tmp_path / "docker"
    captured = tmp_path / "engine.args"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n"
    )
    fake_engine.chmod(0o755)
    resolver = tmp_path / "host-egress-python"
    resolver.write_text(
        "#!/usr/bin/env bash\n"
        "printf '10.79.85.47\\tvnc-approved\\n'\n"
    )
    resolver.chmod(0o755)
    for name in ("reports", "specs", "manuals", "secrets"):
        (tmp_path / name).mkdir()
    project = tmp_path / "specs" / "sample-vnc"
    project.mkdir()
    (project / "manual").mkdir()
    (project / "manual" / "manual.md").write_text("# Manual\n")
    (project / "test.md").write_text("# Test: VNC\n\n## Goal\nConnect.\n")
    (project / "project.yaml").write_text(
        "name: Sample VNC\n"
        "manual_dir: ./manual\n"
        "vnc_host_allowlist: [vnc-approved]\n"
        "target:\n  type: vnc\n  host: vnc-approved\n  port: 5902\n"
    )
    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_FILE": str(captured),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "SPECS_DIR": str(tmp_path / "specs"),
        "MANUALS_DIR": str(tmp_path / "manuals"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "ORCHESTRATOR_RUN_PROJECT": "sample-vnc",
        **_contract_env(tmp_path, "sample-vnc"),
        "ORCHESTRATOR_DISABLE_AWS_FORWARDING": "1",
        "DASHBOARD_PYTHON": sys.executable,
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(resolver),
        "ORCHESTRATOR_HOST_TARGET_RELAY": str(_fake_target_relay(tmp_path)),
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = captured.read_text().splitlines()
    assert "ORCHESTRATOR_TARGET_RELAY_KIND=vnc-direct" in args
    assert "ORCHESTRATOR_TARGET_RELAY_ENDPOINT=vnc-approved" in args
    assert "ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT=5902" in args
    assert "ORCHESTRATOR_TARGET_RELAY_HOST=172.17.0.1" in args
    assert "ORCHESTRATOR_TARGET_RELAY_PORT=45679" in args
    assert any(value.startswith("ORCHESTRATOR_TARGET_RELAY_TOKEN=") for value in args)
    assert not any(value.startswith("ORCHESTRATOR_BEDROCK_") for value in args)
    assert "ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1" in args
    assert "project-scoped host transport" in result.stdout


def test_target_relay_bedrock_exclusion_contract_is_narrow_and_consumed_in_container():
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text(encoding="utf-8")
    firewall = (REPO_ROOT / "docker" / "egress_firewall.sh").read_text(encoding="utf-8")
    branch_start = runner.index(
        'elif [[ "${ORCHESTRATOR_DISABLE_AWS_FORWARDING:-0}" == "1"'
    )
    branch_end = runner.index("    fi", branch_start)
    branch = runner[branch_start:branch_end]
    assert '&& -n "${TARGET_RELAY_KIND}"' in branch
    assert "EGRESS_POLICY_ARGS+=(--exclude-bedrock)" in branch
    assert 'RUNTIME_ENV_ARGS+=(' in branch
    assert '-e "ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1"' in branch
    assert runner.count('ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1') == 2
    assert 'if [[ "${ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK:-0}" == "1" ]]' in firewall
    assert 'POLICY_ARGS+=(--exclude-bedrock)' in firewall
    assert '^(rdp-direct|vnc-(direct|ssh-jump))$' in firewall


def test_watch_learn_capture_is_offline_by_default_and_target_scoped_for_vnc(tmp_path):
    runner = (REPO_ROOT / "scripts" / "run_container.sh").read_text()
    assert 'WATCH_LEARN_CAPTURE="1"' in runner
    assert 'WATCH_LEARN_SELF_TEST}" == "1" || "${WATCH_LEARN_CAPTURE}" == "1"' in runner
    assert 'NETWORK_ARGS=(--network=none)' in runner
    assert 'ORCHESTRATOR_EGRESS_MODE=${EGRESS_MODE}' in runner

    default_start = runner.index("CAPABILITY_ARGS=(")
    self_test_start = runner.index(
        'if [[ "${WATCH_LEARN_SELF_TEST}" == "1" ]]; then',
        default_start,
    )
    capture_start = runner.index(
        'elif [[ "${WATCH_LEARN_CAPTURE}" == "1" ]]; then',
        self_test_start,
    )
    launch_start = runner.index('if "${ENGINE}" run --rm', capture_start)

    default_capabilities = runner[default_start:self_test_start]
    self_test_capabilities = runner[self_test_start:capture_start]
    capture_capabilities = runner[capture_start:launch_start]

    assert runner.count("--cap-add DAC_OVERRIDE") == 2
    assert "--cap-add DAC_OVERRIDE" not in default_capabilities
    assert "--cap-add DAC_OVERRIDE" in self_test_capabilities
    assert "--cap-add DAC_OVERRIDE" in capture_capabilities
    assert "--cap-add NET_ADMIN" not in self_test_capabilities
    target_mode_start = capture_capabilities.index(
        'if [[ "${WATCH_LEARN_NETWORK_MODE}" == "target" ]]; then'
    )
    offline_capture = capture_capabilities[:target_mode_start]
    target_capture = capture_capabilities[target_mode_start:]
    assert "--cap-add NET_ADMIN" not in offline_capture
    assert "--network=none" in offline_capture
    assert "--cap-add NET_ADMIN" in target_capture
    assert "--network=bridge" in target_capture
    assert 'ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1' in target_capture
    assert 'EGRESS_POLICY_ARGS+=(--exclude-bedrock)' in capture_capabilities
    assert "--network=none" in self_test_capabilities
    assert "--network=none" in capture_capabilities


def test_watch_learn_capture_mounts_required_inputs_but_no_reports_or_aws(tmp_path):
    fake_engine = tmp_path / "docker"
    captured = tmp_path / "engine.args"
    fake_engine.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n"
    )
    fake_engine.chmod(0o755)
    for name in ("reports", "specs", "manuals", "secrets"):
        (tmp_path / name).mkdir()
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_FILE": str(captured),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "SPECS_DIR": str(tmp_path / "specs"),
        "MANUALS_DIR": str(tmp_path / "manuals"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "WATCH_LEARN_CONTROL_DIR_HOST": str(control),
        "ORCHESTRATOR_RUN_PROJECT": "sample",
        **_contract_env(tmp_path, "sample"),
        "ORCHESTRATOR_CONTAINER_NAME": "phase17-test",
        "IMAGE": "registry.example/runner@sha256:" + "a" * 64,
        "AWS_ACCESS_KEY_ID": "must-not-forward",
        "AWS_SECRET_ACCESS_KEY": "must-not-forward",
        "AWS_SESSION_TOKEN": "must-not-forward",
        "BEDROCK_MODEL_ID": "must-not-forward",
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    args = captured.read_text().splitlines()
    assert "--network=none" in args
    assert "NET_ADMIN" not in args
    assert f"{(tmp_path / 'specs').resolve()}:/app/tests_specs:ro" in args
    assert f"{(tmp_path / 'manuals').resolve()}:/app/tests_manuals:ro" in args
    assert f"{(tmp_path / 'secrets').resolve()}:/app/secrets-source:ro" in args
    assert not any("/app/reports" in value for value in args)
    joined = "\n".join(args)
    for forbidden in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "BEDROCK_MODEL_ID", "must-not-forward", "/app/aws-credentials-source",
    ):
        assert forbidden not in joined


def test_container_prefers_live_aws_file_over_dashboard_environment(tmp_path):
    fake_engine = tmp_path / "fake-engine.sh"
    captured = tmp_path / "engine.args"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n"
    )
    fake_engine.chmod(0o755)

    reports = tmp_path / "reports"
    specs = tmp_path / "specs"
    manuals = tmp_path / "manuals"
    secrets = tmp_path / "secrets"
    aws_dir = tmp_path / ".aws"
    for directory in (reports, specs, manuals, secrets, aws_dir):
        directory.mkdir()
    credentials = aws_dir / "credentials"
    credentials.write_text(
        "[default]\naws_access_key_id=fresh\naws_secret_access_key=fresh\n"
        "aws_session_token=fresh\n"
    )
    credentials.chmod(0o600)

    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_FILE": str(captured),
        "REPORTS_DIR": str(reports),
        "SPECS_DIR": str(specs),
        "MANUALS_DIR": str(manuals),
        "SECRETS_DIR": str(secrets),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "AWS_ACCESS_KEY_ID": "stale-dashboard-value",
        "AWS_SECRET_ACCESS_KEY": "stale-dashboard-value",
        "AWS_SESSION_TOKEN": "stale-dashboard-value",
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)),
        "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path)),
    }
    # This case exercises the standard HOME fallback specifically. Managed
    # launches may export explicit path selectors, so remove them from this
    # synthetic subprocess rather than inheriting the developer's AWS setup.
    for key in (
        "ORCHESTRATOR_AWS_CREDENTIALS_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "ORCHESTRATOR_AWS_CONFIG_FILE",
        "AWS_CONFIG_FILE",
        "ORCHESTRATOR_AWS_CONFIG_DISABLED",
    ):
        env.pop(key, None)
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = captured.read_text().splitlines()
    assert f"{aws_dir.resolve()}:/app/aws-credentials-source:ro" in args
    assert "AWS_SHARED_CREDENTIALS_FILE=/app/aws-runtime/credentials" in args
    assert "/app/aws-runtime:rw,nosuid,nodev,noexec,size=4m,mode=0700" in args
    assert "AWS_ACCESS_KEY_ID" not in args
    assert "AWS_SECRET_ACCESS_KEY" not in args
    assert "AWS_SESSION_TOKEN" not in args
    assert "stale-dashboard-value" not in captured.read_text()
    assert "current on-disk file" in result.stdout


def test_container_uses_only_explicit_managed_aws_profile(tmp_path):
    fake_engine = tmp_path / "fake-engine.sh"
    captured = tmp_path / "engine.args"
    fake_engine.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_FILE}\"\n")
    fake_engine.chmod(0o755)
    for name in ("reports", "specs", "manuals", "secrets", "aws"):
        (tmp_path / name).mkdir()
    credentials = tmp_path / "aws" / "credentials"
    credentials.write_text("[approved]\naws_access_key_id=x\naws_secret_access_key=y\n")
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_FILE": str(captured),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "SPECS_DIR": str(tmp_path / "specs"),
        "MANUALS_DIR": str(tmp_path / "manuals"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "ORCHESTRATOR_AWS_CREDENTIALS_FILE": str(credentials),
        "AWS_PROFILE": "ambient-denied",
        "ORCHESTRATOR_AWS_PROFILE": "approved",
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)),
        "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path)),
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env, check=False, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    args = captured.read_text().splitlines()
    assert "AWS_PROFILE=approved" in args
    assert "ORCHESTRATOR_AWS_PROFILE=approved" in args
    assert "ambient-denied" not in captured.read_text()


def test_two_container_launches_receive_different_x_displays(tmp_path):
    fake_engine = tmp_path / "fake-engine.sh"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$@\" >\"${ENGINE_CAPTURE_DIR}/engine-${BASHPID}.args\"\n"
        "sleep 0.5\n"
    )
    fake_engine.chmod(0o755)
    capture = tmp_path / "captures"
    capture.mkdir()
    lock_dir = tmp_path / "locks"
    reports = tmp_path / "reports"
    specs = tmp_path / "specs"
    manuals = tmp_path / "manuals"
    secrets = tmp_path / "secrets"
    for directory in (reports, specs, manuals, secrets):
        directory.mkdir()

    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "ENGINE_CAPTURE_DIR": str(capture),
        "DISPLAY_SLOT_MIN": "150",
        "DISPLAY_SLOT_MAX": "151",
        "DISPLAY_LOCK_DIR": str(lock_dir),
        "REPORTS_DIR": str(reports),
        "SPECS_DIR": str(specs),
        "MANUALS_DIR": str(manuals),
        "SECRETS_DIR": str(secrets),
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)),
        "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path)),
    }
    command = ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"]
    first = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    second = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    first_out, first_err = first.communicate(timeout=10)
    second_out, second_err = second.communicate(timeout=10)

    assert first.returncode == 0, (first_out + first_err).decode(errors="replace")
    assert second.returncode == 0, (second_out + second_err).decode(errors="replace")
    displays = set()
    for args_file in capture.glob("*.args"):
        for line in args_file.read_text().splitlines():
            if line.startswith("DISPLAY=:"):
                displays.add(line)
    assert displays == {"DISPLAY=:150", "DISPLAY=:151"}


def test_host_app_is_refused_under_the_report_contract_even_when_enabled_and_allowlisted(tmp_path):      # CP45-I (was: display handshake launches the host app)
    fake_engine = tmp_path / "fake-engine.sh"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    HOST_DISPLAY_READY_FILE=/app/reports/*)\n"
        "      rel=${arg#HOST_DISPLAY_READY_FILE=/app/reports/}\n"
        "      mkdir -p \"${REPORTS_DIR}/$(dirname \"$rel\")\"\n"
        "      printf ':155\\n' >\"${REPORTS_DIR}/$rel\"\n"
        "      ;;\n"
        "  esac\n"
        "done\n"
        "sleep 0.5\n"
    )
    fake_engine.chmod(0o755)

    reports = tmp_path / "reports"
    specs = tmp_path / "specs"
    manuals = tmp_path / "manuals"
    secrets = tmp_path / "secrets"
    allowed = tmp_path / "JAMboree"
    for directory in (reports, specs, manuals, secrets, allowed):
        directory.mkdir()
    project = specs / "jamboree"
    project.mkdir()
    observed = allowed / "observed.txt"
    app = allowed / "BOOM.sh"
    app.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$DISPLAY\" >'{observed}'\n"
    )
    app.chmod(0o644)
    (project / "project.yaml").write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{app}'\n"
        f"  cwd: '{allowed}'\n"
        "  window: JAMboree\n"
    )

    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "REPORTS_DIR": str(reports),
        "SPECS_DIR": str(specs),
        "MANUALS_DIR": str(manuals),
        "SECRETS_DIR": str(secrets),
        "DISPLAY_SLOT_MIN": "155",
        "DISPLAY_SLOT_MAX": "155",
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "ORCHESTRATOR_RUN_PROJECT": "jamboree",
        **_contract_env(tmp_path, "jamboree"),
        "DASHBOARD_PYTHON": sys.executable,
        "ORCHESTRATOR_HOST_EGRESS_PYTHON": str(_fake_host_egress_python(tmp_path)),
        "ORCHESTRATOR_HOST_BEDROCK_RELAY": str(_fake_bedrock_relay(tmp_path)),
        "HOST_APP_ENABLED": "1",
        "HOST_APP_ALLOW_ROOTS": str(allowed),
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 78, result.stdout + result.stderr
    assert "host-app targets are not supported" in result.stderr and "[host-app] launching" not in result.stdout
    assert not observed.exists()                                   # the allowlisted app never ran
    assert not (reports / ".host-app").exists()                    # no world-writable bridge state directory was created
    assert not (tmp_path / "locks").exists()                       # no display slot was taken: refused before anything was created


def test_container_refuses_disabled_host_app_before_engine_launch(tmp_path):
    marker = tmp_path / "engine-called"
    fake_engine = tmp_path / "fake-engine.sh"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        f"touch '{marker}'\n"
    )
    fake_engine.chmod(0o755)
    reports = tmp_path / "reports"
    specs = tmp_path / "specs"
    manuals = tmp_path / "manuals"
    secrets = tmp_path / "secrets"
    allowed = tmp_path / "allowed"
    for directory in (reports, specs, manuals, secrets, allowed):
        directory.mkdir()
    project = specs / "host-project"
    project.mkdir()
    app = allowed / "app.sh"
    app.write_text("#!/usr/bin/env bash\nexit 0\n")
    (project / "project.yaml").write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{app}'\n"
    )
    env = {
        **os.environ,
        "ENGINE": str(fake_engine),
        "REPORTS_DIR": str(reports),
        "SPECS_DIR": str(specs),
        "MANUALS_DIR": str(manuals),
        "SECRETS_DIR": str(secrets),
        "DISPLAY_LOCK_DIR": str(tmp_path / "locks"),
        "ORCHESTRATOR_RUN_PROJECT": "host-project",
        "DASHBOARD_PYTHON": sys.executable,
        "HOST_APP_ENABLED": "0",
        "HOST_APP_ALLOW_ROOTS": str(allowed),
    }

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_container.sh"), "true"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 78
    assert "HOST_APP_ENABLED" in result.stderr
    assert not marker.exists()


def test_run_specs_preserves_container_engine_autodetection():
    script = (REPO_ROOT / "scripts" / "run_specs.sh").read_text(encoding="utf-8")
    assert 'ENGINE="${ENGINE:-podman}"' not in script
    assert 'exec "${PROJECT_ROOT}/scripts/run_container.sh" "$@"' in script
    assert 'export ORCHESTRATOR_RUN_PROJECT="$1"' in script


def test_dashboard_launcher_never_logs_auth_token(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uvicorn = fake_bin / "uvicorn"
    fake_uvicorn.write_text("#!/usr/bin/env bash\nexit 0\n")
    fake_uvicorn.chmod(0o755)
    secret = "regression-secret-that-must-not-be-printed"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        "DASHBOARD_AUTH_TOKEN": secret,
        "DASHBOARD_HOST": "127.0.0.1",
    }

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "run_dashboard.sh")],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "[dashboard] auth:        token set" in output
    assert secret not in output
