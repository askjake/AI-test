"""Host-app bridge security, display handoff, and argv lifecycle tests."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE = REPO_ROOT / "scripts" / "host_app_bridge.py"


def _run_bridge(config: Path, ready: Path, log: Path, *, roots: list[Path], enabled=True):
    env = {
        **os.environ,
        "HOST_APP_ENABLED": "1" if enabled else "0",
        "HOST_APP_ALLOW_ROOTS": os.pathsep.join(str(root) for root in roots),
        "HOST_APP_READY_TIMEOUT": "2",
        "AWS_SECRET_ACCESS_KEY": "must-not-reach-host-app",
        "DASHBOARD_AUTH_TOKEN": "must-not-reach-host-app",
    }
    return subprocess.run(
        [
            sys.executable,
            str(BRIDGE),
            "--config", str(config),
            "--display", ":150",
            "--ready-file", str(ready),
            "--log", str(log),
        ],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_bridge_launches_allowlisted_script_on_assigned_display(tmp_path):
    allowed = tmp_path / "JAMboree"
    allowed.mkdir()
    observed = allowed / "observed.txt"
    script = allowed / "BOOM.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'DISPLAY=%s\\nCWD=%s\\nARG=%s\\nAWS=%s\\nTOKEN=%s\\n' "
        '"$DISPLAY" "$PWD" "$1" "${AWS_SECRET_ACCESS_KEY-ABSENT}" '
        '"${DASHBOARD_AUTH_TOKEN-ABSENT}" >"$2"\n'
    )
    script.chmod(0o644)  # .sh fallback is deliberately supported without +x.
    config = tmp_path / "project.yaml"
    config.write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{script} canary {observed}'\n"
        f"  cwd: '{allowed}'\n"
        "  window: JAMboree\n"
    )
    ready = tmp_path / "display.ready"
    ready.write_text(":150\n")
    log = tmp_path / "host-app.log"

    result = _run_bridge(config, ready, log, roots=[allowed])

    assert result.returncode == 0, result.stderr
    assert "[host-app] launching" in result.stdout
    assert observed.read_text().splitlines() == [
        "DISPLAY=:150",
        f"CWD={allowed}",
        "ARG=canary",
        "AWS=ABSENT",
        "TOKEN=ABSENT",
    ]


def test_bridge_rejects_executable_outside_allowlisted_roots(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/usr/bin/env bash\nexit 0\n")
    outside.chmod(0o755)
    config = tmp_path / "project.yaml"
    config.write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{outside}'\n"
        "  window: Outside\n"
    )

    result = _run_bridge(
        config,
        tmp_path / "unused.ready",
        tmp_path / "host-app.log",
        roots=[allowed],
    )

    assert result.returncode == 78
    assert "outside HOST_APP_ALLOW_ROOTS" in result.stderr


def test_bridge_requires_explicit_enablement(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    script = allowed / "app.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n")
    config = tmp_path / "project.yaml"
    config.write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{script}'\n"
    )

    result = _run_bridge(
        config,
        tmp_path / "unused.ready",
        tmp_path / "host-app.log",
        roots=[allowed],
        enabled=False,
    )

    assert result.returncode == 78
    assert "HOST_APP_ENABLED" in result.stderr


def test_bridge_ignores_non_host_app_project_without_enablement(tmp_path):
    config = tmp_path / "project.yaml"
    config.write_text("target:\n  type: local-app\n  app: xterm\n")

    result = _run_bridge(
        config,
        tmp_path / "unused.ready",
        tmp_path / "host-app.log",
        roots=[],
        enabled=False,
    )

    assert result.returncode == 0
    assert not (tmp_path / "host-app.log").exists()


def test_bridge_owns_background_child_until_manager_is_stopped(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    child_pid = allowed / "child.pid"
    script = allowed / "BOOM.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "sleep 30 &\n"
        f"printf '%s\\n' \"$!\" >'{child_pid}'\n"
    )
    config = tmp_path / "project.yaml"
    config.write_text(
        "target:\n"
        "  type: host-app\n"
        f"  app: '{script}'\n"
    )
    ready = tmp_path / "display.ready"
    ready.write_text(":150\n")
    env = {
        **os.environ,
        "HOST_APP_ENABLED": "1",
        "HOST_APP_ALLOW_ROOTS": str(allowed),
        "HOST_APP_READY_TIMEOUT": "2",
    }
    bridge = subprocess.Popen(
        [
            sys.executable,
            str(BRIDGE),
            "--config", str(config),
            "--display", ":150",
            "--ready-file", str(ready),
            "--log", str(tmp_path / "host-app.log"),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not child_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert child_pid.exists()
        time.sleep(0.2)
        assert bridge.poll() is None  # wrapper exited; its background child is still owned.
        bridge.terminate()
        stdout, stderr = bridge.communicate(timeout=10)
        assert bridge.returncode == 0, stdout + stderr
        assert "stopped with container run" in stdout
    finally:
        if bridge.poll() is None:
            bridge.kill()
            bridge.wait(timeout=5)
