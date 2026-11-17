"""Phase 16R interpreter resolution and typed target-route acceptance."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from dashboard.authoring import (
    DirectConnectionRoute,
    ProjectDocument,
    RdpTarget,
    SshJumpConnectionRoute,
    SshTerminalTarget,
    VncTarget,
    lint_project_document,
)
from dashboard.config import DashboardSettings
from dashboard.target_probe import TargetProbeService
from orchestrator.projects import load_project_config
from orchestrator.targets import TargetError, TargetSpec, Targets
from orchestrator_cookie.doctor import _capability_matrix, detect_platform
from orchestrator_cookie import cli
from orchestrator_cookie.config import initialize_runtime, runtime_root
from orchestrator_cookie.python_selection import (
    interpreter_candidates,
    python_remediation,
    select_interpreter,
)
from target_routing import build_ssh_argv


REPO_ROOT = Path(__file__).resolve().parents[1]


class _Process:
    pid = 1234

    def poll(self): return None
    def terminate(self): return None
    def kill(self): return None
    def wait(self, timeout=None): return 0


def _project(target, *, ssh=None, rdp=None, vnc=None) -> ProjectDocument:
    return ProjectDocument(
        dir_name="route-test",
        display_name="Route test",
        schedule="0 3 * * *",
        manual_dir="managed-by-server",
        target=target,
        ssh_host_allowlist=ssh or [],
        rdp_host_allowlist=rdp or [],
        vnc_host_allowlist=vnc or [],
    )


def test_python_resolution_precedence_and_explicit_override_never_falls_back():
    versions = {
        "python3.13": (3, 14, 1),
        "python3.12": (3, 12, 9),
        "python3.11": (3, 11, 8),
    }
    selected = select_interpreter(
        "Darwin", probe=lambda item: versions.get(item.label)
    )
    assert selected.selected is not None
    assert selected.selected.candidate.label == "python3.12"
    assert [item.candidate.label for item in selected.discoveries] == ["python3.13", "python3.12"]

    explicit = select_interpreter(
        "Darwin", override="/opt/python3.14", probe=lambda _item: (3, 14, 7)
    )
    assert explicit.selected is None
    assert explicit.explicit is True
    assert len(explicit.discoveries) == 1


def test_platform_candidate_orders_include_windows_launchers_after_versioned_names():
    assert [item.label for item in interpreter_candidates("Linux")][:5] == [
        "python3.13", "python3.12", "python3.11", "python3", "python"
    ]
    windows = [item.label for item in interpreter_candidates("Windows")]
    assert windows[:6] == [
        "python3.13", "python3.12", "python3.11", "py -3.13", "py -3.12", "py -3.11"
    ]
    assert windows[-3:] == ["python.exe", "python", "python3"]


def _wrapper_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "wrapper"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "install.sh", root / "install.sh")
    os.chmod(root / "install.sh", 0o755)
    (root / "scripts" / "installer.py").write_text(
        "import os,sys; print(os.environ.get('ORCHESTRATOR_RESOLVED_PYTHON')); print(sys.executable)\n"
    )
    return root


def test_posix_wrapper_rejects_explicit_python_314_before_installer_logic(tmp_path):
    root = _wrapper_fixture(tmp_path)
    fake = tmp_path / "python314"
    fake.write_text(
        "#!/bin/sh\nprintf '3.14.7\\n'\n"
    )
    os.chmod(fake, 0o755)
    result = subprocess.run(
        [str(root / "install.sh"), "init"],
        cwd=root,
        env={**os.environ, "ORCHESTRATOR_PYTHON": str(fake)},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 3
    assert "Python 3.14.7" in result.stderr
    assert "ORCHESTRATOR_RESOLVED_PYTHON" not in result.stdout


def test_posix_wrapper_uses_same_supported_override_for_doctor_and_init(tmp_path):
    root = _wrapper_fixture(tmp_path)
    outputs = []
    for command in ("doctor", "init"):
        result = subprocess.run(
            [str(root / "install.sh"), command],
            cwd=root,
            env={**os.environ, "ORCHESTRATOR_PYTHON": sys.executable},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert result.returncode == 0
        outputs.append(result.stdout.splitlines())
    assert outputs[0] == outputs[1]
    assert Path(outputs[0][0]).resolve() == Path(sys.executable).resolve()


def test_init_creates_managed_environment_from_the_wrapper_selected_interpreter(
    tmp_path, monkeypatch
):
    repo = tmp_path / "clone"
    repo.mkdir()
    initialize_runtime(repo)
    for name in ("requirements.txt", "requirements-dashboard.txt", "constraints.txt"):
        (repo / name).write_text("# deterministic test\n")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["-m", "venv"]:
            managed = repo / ".orchestrator-cookie" / "venv" / (
                "Scripts/python.exe" if os.name == "nt" else "bin/python"
            )
            managed.parent.mkdir(parents=True)
            managed.write_text("managed test placeholder")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setenv("ORCHESTRATOR_RESOLVED_PYTHON", sys.executable)
    cli._install_dependencies(repo)
    assert calls[0][:3] == [sys.executable, "-m", "venv"]
    state = json.loads((runtime_root(repo) / "state" / "environment.json").read_text())
    assert state["bootstrap_interpreter"] == sys.executable
    assert state["schema_version"] == 2


def test_powershell_wrapper_has_deterministic_resolution_and_no_automatic_install():
    source = (REPO_ROOT / "install.ps1").read_text()
    order = [source.index(name) for name in (
        "'python3.13'", "'python3.12'", "'python3.11'", "'3.13'", "'3.12'", "'3.11'"
    )]
    assert order == sorted(order)
    assert "ORCHESTRATOR_PYTHON" in source
    assert "Get-PythonVersion" in source
    assert "Test-SupportedPython" in source
    assert "winget install" in source
    assert "Start-Process" not in source


def test_macos_and_windows_remediation_is_actionable_but_noninstalling():
    mac = python_remediation("Darwin")
    assert "brew install python@3.13" in mac
    assert "ORCHESTRATOR_PYTHON" in mac
    assert "Otherwise" in mac
    windows = python_remediation("Windows")
    assert "winget install" in windows
    assert "ORCHESTRATOR_PYTHON" in windows


def test_dashboard_capability_does_not_depend_on_optional_engine():
    capabilities = _capability_matrix(
        detect_platform(system="Darwin", machine="arm64", python=(3, 13, 2)),
        initialized=True,
        dependencies=True,
        engine_ok=False,
        image_ok=False,
        model_configured=False,
        host_app_enabled=False,
    )
    assert next(item for item in capabilities if item.name == "Dashboard access").state == "READY"
    assert next(item for item in capabilities if item.name == "Runner image").state == "BLOCKED"


def test_direct_and_jump_routes_are_typed_rdp_rejects_and_vnc_requires_credentials():
    direct = _project(
        SshTerminalTarget(host="target.internal", window="SSH", route=DirectConnectionRoute()),
        ssh=["target.internal"],
    )
    _normalised, diagnostics = lint_project_document(
        direct, require_manual_on_disk=False, require_schedule=True, new_project=True
    )
    assert not [item for item in diagnostics if item.severity == "error"]

    jump = SshJumpConnectionRoute(
        host="jump.internal", user="operator", port=22, known_hosts_file="approved_known_hosts"
    )
    routed = _project(
        SshTerminalTarget(host="target.internal", window="SSH", route=jump),
        ssh=["target.internal", "jump.internal"],
    )
    _normalised, diagnostics = lint_project_document(
        routed, require_manual_on_disk=False, require_schedule=True, new_project=True
    )
    assert not [item for item in diagnostics if item.severity == "error"]

    _normalised, diagnostics = lint_project_document(
        _project(RdpTarget(
            host="rdp.internal",
            window="RDP",
            certificate_name="RDP-INTERNAL",
            certificate_fingerprint="sha256:" + "a" * 64,
            route=jump,
        ), rdp=["rdp.internal"]),
        require_manual_on_disk=False, require_schedule=True, new_project=True,
    )
    assert any(item.code == "jump_route_unsupported" for item in diagnostics)

    vnc = VncTarget(
        host="vnc.internal", window="VNC", route=jump,
        gateway_password_file="jump.pw",
    )
    _normalised, diagnostics = lint_project_document(
        _project(vnc, vnc=["vnc.internal"], ssh=["jump.internal"]),
        require_manual_on_disk=False, require_schedule=True, new_project=True,
    )
    assert not [item for item in diagnostics if item.severity == "error"]


def test_ssh_proxyjump_argv_is_literal_strict_and_contains_no_secret_value(tmp_path):
    key = tmp_path / "id_target"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("PRIVATE MATERIAL")
    known_hosts.write_text("jump.internal ssh-ed25519 AAAATEST")
    argv = build_ssh_argv(
        "/usr/bin/ssh",
        "target-user@target.internal",
        key_path=str(key),
        jump_host="jump.internal",
        jump_user="jump-user",
        jump_port=2222,
        known_hosts_path=str(known_hosts),
    )
    assert argv[0] == "/usr/bin/ssh"
    assert "StrictHostKeyChecking=yes" in argv
    assert "ProxyJump=jump-user@jump.internal:2222" in argv
    assert "StrictHostKeyChecking=no" not in " ".join(argv)
    assert "PRIVATE MATERIAL" not in " ".join(argv)
    assert not any(item in {"sh", "bash", "-c"} for item in argv)


def test_runner_ssh_jump_uses_proxyjump_and_rejects_unsupported_routes_before_launch(tmp_path):
    (tmp_path / "known_hosts").write_text("jump.internal ssh-ed25519 AAAATEST")
    commands = []
    targets = Targets(
        ssh_host_allowlist=["target.internal", "jump.internal"],
        rdp_host_allowlist=["rdp.internal"],
        vnc_host_allowlist=["vnc.internal"],
        secrets_dir=str(tmp_path),
        launcher=lambda command, **_kwargs: commands.append(command) or _Process(),
        runner=lambda command: "777\n" if "search" in command else "",
        sleep=lambda _seconds: None,
    )
    targets.open_target(TargetSpec("ssh-terminal", {
        "host":"target.internal", "window":"SSH", "route_type":"ssh-jump",
        "jump_host":"jump.internal", "jump_user":"operator", "jump_port":"22",
        "jump_known_hosts_file":"known_hosts",
    }))
    assert "ProxyJump=operator@jump.internal" in commands[0]
    before = len(commands)
    with pytest.raises(TargetError, match="RDP jump routing"):
        targets.open_target(TargetSpec("rdp", {"host":"rdp.internal", "route_type":"ssh-jump"}))
    with pytest.raises(TargetError, match="VNC SSH jump"):
        targets.open_target(TargetSpec("vnc", {"host":"vnc.internal", "route_type":"ssh-jump"}))
    assert len(commands) == before


def test_project_loader_flattens_typed_route_without_shell_text(tmp_path):
    manual = tmp_path / "manual"
    manual.mkdir()
    (manual / "manual.md").write_text("# Manual\n")
    project = tmp_path / "project"
    project.mkdir()
    (project / "project.yaml").write_text(
        "name: Routed\nmanual_dir: " + str(manual) + "\n"
        "ssh_host_allowlist: [target.internal, jump.internal]\n"
        "target:\n  type: ssh-terminal\n  host: target.internal\n  window: SSH\n"
        "  route:\n    type: ssh-jump\n    host: jump.internal\n    user: operator\n"
        "    port: 22\n    known_hosts_file: approved_known_hosts\n"
    )
    config = load_project_config(str(project), specs_root=str(tmp_path))
    assert config.target.params["route_type"] == "ssh-jump"
    assert config.target.params["jump_host"] == "jump.internal"
    assert "ProxyCommand" not in json.dumps(config.target.params)


def test_route_revision_changes_and_readiness_never_runs_implicit_preflight(tmp_path):
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    known = secret_root / "known_hosts"
    known.write_text("jump.internal ssh-ed25519 AAAATEST")
    os.chmod(known, 0o600)
    settings = DashboardSettings(
        specs_dir=str(tmp_path / "specs"), secrets_dir=str(secret_root)
    )
    connections = []
    service = TargetProbeService(
        settings, connector=lambda *args: connections.append(args), which=lambda _name: None
    )
    direct = _project(
        SshTerminalTarget(host="target.internal", window="SSH"), ssh=["target.internal", "jump.internal"]
    )
    routed = direct.model_copy(update={"target": direct.target.model_copy(update={
        "route": SshJumpConnectionRoute(host="jump.internal", known_hosts_file="known_hosts")
    })})
    assert service.target_revision(direct) != service.target_revision(routed)
    assert service.current_result(routed) is None
    assert connections == []


def test_route_change_ui_preserves_allowlists_and_requires_discard_confirmation():
    template = (REPO_ROOT / "templates" / "dashboard" / "index.html").read_text()
    function = template[template.index("function changeConnectionPath"):template.index("function markProjectAuthoringDirty")]
    assert "confirm(" in function
    assert "allowlists will be retained" in function
    assert "ssh_host_allowlist" not in function
    assert "runWizardTargetProbe" not in function
    assert all(state in template for state in (
        "unconfigured", "configured-but-unprobed", "preflight-ready", "verified-current"
    ))
