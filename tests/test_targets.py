"""Phase 3 tests for orchestrator.targets.

Exercise dispatch, host-allowlist enforcement (P3-3/P3-5), the focus helper (P3-6), the
ssh/rdp argv shape (secrets passed as a file path / to the client, never typed — P3-8),
and close_target cleanup (P3-7), all with injected runner/launcher so no real X display
or network is needed.
"""

from __future__ import annotations

import os

import pytest

from orchestrator.targets import (
    HostNotAllowedError,
    TargetError,
    TargetSpec,
    Targets,
    WindowNotFoundError,
    _default_launcher,
)


RDP_CERTIFICATE = {
    "certificate_name": "WINHOST",
    "certificate_fingerprint": "sha256:" + "a" * 64,
}


class FakeRunner:
    """Records argv lists and returns canned stdout keyed by the xdotool subcommand."""

    def __init__(self, outputs=None):
        self.calls: list[list[str]] = []
        self._outputs = outputs or {}

    def __call__(self, cmd: list[str]) -> str:
        self.calls.append(cmd)
        verb = cmd[1] if len(cmd) > 1 else ""
        return self._outputs.get(verb, "")


class FakeProcess:
    def __init__(self, pid=4321):
        self.pid = pid
        self._alive = True
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self.terminated = True
        self._alive = False

    def kill(self):
        self.killed = True
        self._alive = False

    def wait(self, timeout=None):
        return 0


class FakeLauncher:
    def __init__(self):
        self.commands: list[list[str]] = []
        self.envs: list[dict[str, str | None] | None] = []
        self.log_paths: list[str | None] = []
        self.proc = FakeProcess()

    def __call__(
        self,
        cmd: list[str],
        env: dict[str, str | None] | None = None,
        log_path: str | None = None,
    ):
        self.commands.append(cmd)
        self.envs.append(env)
        self.log_paths.append(log_path)
        return self.proc


def _targets(runner=None, launcher=None, **kw):
    # A search runner that always finds window id "777" so waits resolve immediately.
    runner = runner or FakeRunner(outputs={"search": "777\n"})
    launcher = launcher or FakeLauncher()
    defaults = dict(
        display=":99",
        ssh_host_allowlist=["build01"],
        rdp_host_allowlist=["winhost"],
        vnc_host_allowlist=["vnchost"],
        secrets_dir="secrets",
        runner=runner,
        launcher=launcher,
        sleep=lambda _s: None,
    )
    defaults.update(kw)
    return Targets(**defaults), runner, launcher


# --- allowlist (P3-3 / P3-5) ----------------------------------------------


def test_ssh_non_allowlisted_refused_before_launch():
    t, _runner, launcher = _targets()
    spec = TargetSpec("ssh-terminal", {"host": "evil.example", "user": "x"})
    with pytest.raises(HostNotAllowedError):
        t.open_target(spec)
    assert launcher.commands == []  # no process ever launched


def test_rdp_non_allowlisted_refused_before_launch():
    t, _runner, launcher = _targets()
    spec = TargetSpec("rdp", {"host": "not-allowed", "user": "x"})
    with pytest.raises(HostNotAllowedError):
        t.open_target(spec)
    assert launcher.commands == []


# --- ssh-terminal (P3-2 / P3-8) -------------------------------------------


def test_ssh_terminal_argv_uses_xterm_and_key_path(tmp_path):
    keyfile = tmp_path / "id_build01"
    keyfile.write_text("PRIVATE KEY MATERIAL")
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec(
        "ssh-terminal", {"host": "build01", "user": "ci", "key": "id_build01"}
    )
    handle = t.open_target(spec)

    cmd = launcher.commands[0]
    assert cmd[0] == "xterm"
    assert "ssh" in cmd
    assert "-i" in cmd
    assert str(keyfile) in cmd  # key passed by path...
    assert "ci@build01" in cmd
    # ...and the key *material* is never on the command line.
    assert "PRIVATE KEY MATERIAL" not in " ".join(cmd)
    assert handle.type == "ssh-terminal"


def test_ssh_missing_host_errors():
    t, _runner, _launcher = _targets()
    with pytest.raises(TargetError):
        t.open_target(TargetSpec("ssh-terminal", {"user": "ci"}))


def test_secret_path_traversal_refused():
    t, _runner, _launcher = _targets()
    spec = TargetSpec(
        "ssh-terminal", {"host": "build01", "key": "../../etc/passwd"}
    )
    with pytest.raises(TargetError):
        t.open_target(spec)


# --- rdp (P3-4 / P3-8) ----------------------------------------------------


def test_rdp_argv_passes_password_to_client_not_typed(tmp_path):
    pw = tmp_path / "winhost.pw"
    pw.write_text("hunter2\n")
    t, runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec(
        "rdp", {
            "host": "winhost",
            "user": "admin",
            "password_file": "winhost.pw",
            **RDP_CERTIFICATE,
        }
    )
    t.open_target(spec)

    cmd = launcher.commands[0]
    assert cmd[0] == "xfreerdp"
    assert "/v:winhost" in cmd
    assert "/u:admin" in cmd
    assert "/p:hunter2" in cmd  # handed to the client process
    assert "/w:1280" in cmd
    assert "/h:800" in cmd
    # The agent's input runner (xdotool type) is never used to enter the password.
    assert not any("type" in c for c in runner.calls)


def test_rdp_unsafe_cert_and_legacy_gfx_args_are_removed(tmp_path):
    pw = tmp_path / "winhost.pw"
    pw.write_text("hunter2\n")
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec(
        "rdp",
        {
            "host": "winhost",
            "user": "studio",
            "password_file": "winhost.pw",
            "extra_args": "/gdi:sw /gfx- /network:auto /cert:ignore /cert:tofu /timeout:30000",
            **RDP_CERTIFICATE,
        },
    )
    t.open_target(spec)

    cmd = launcher.commands[0]
    assert "/u:studio" in cmd
    assert "/gfx-" not in cmd
    assert "/cert:ignore" not in cmd
    assert "/cert:tofu" not in cmd
    assert cmd.count(
        "/cert:deny,name:WINHOST,fingerprint:sha256:" + ":".join(["aa"] * 32)
    ) == 1
    assert cmd.count("/gdi:sw") == 1
    assert cmd.count("/network:auto") == 1
    assert cmd.count("/timeout:30000") == 1


def test_rdp_extra_args_cannot_smuggle_password(tmp_path):
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    with pytest.raises(TargetError, match="password_file"):
        t.open_target(
            TargetSpec("rdp", {
                "host": "winhost",
                "extra_args": "/p:not-allowed",
                **RDP_CERTIFICATE,
            })
        )
    assert launcher.commands == []


def test_direct_rdp_uses_authenticated_loopback_proxy_and_preserves_certificate_name(monkeypatch):
    class Relay:
        pid = -1
        local_port = 45233
        closed = False

        def poll(self):
            return 0 if self.closed else None

        def terminate(self):
            self.closed = True

        kill = terminate

        def wait(self, timeout=None):
            return 0

    relay = Relay()
    observed = {}

    def from_environment(**kwargs):
        observed.update(kwargs)
        return relay

    monkeypatch.setattr(
        "orchestrator.targets.TargetRelayClient.from_environment", from_environment
    )
    t, _runner, launcher = _targets()
    handle = t.open_target(TargetSpec(
        "rdp", {"host": "winhost", "port": "3390", **RDP_CERTIFICATE}
    ))

    assert observed == {
        "kind": "rdp-direct", "endpoint": "winhost", "destination_port": 3390
    }
    command = launcher.commands[0]
    assert "/v:127.0.0.1:45233" in command
    assert "/cert:deny,name:WINHOST,fingerprint:sha256:" + ":".join(["aa"] * 32) in command
    assert not any(value.startswith("/server-name:") for value in command)
    assert not any(value.startswith("/v:winhost") for value in command)
    assert relay in handle.auxiliary_processes


def test_rdp_launch_captures_client_log_when_log_dir_set(tmp_path):
    t, _runner, launcher = _targets(log_dir=str(tmp_path))
    t.open_target(TargetSpec("rdp", {"host": "winhost", **RDP_CERTIFICATE}))
    assert launcher.log_paths[0] == str(tmp_path / "rdp_client.log")


def test_rdp_child_omits_model_proxy_without_changing_runner_environment(monkeypatch):
    proxy_keys = (
        "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
        "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
    )
    for key in proxy_keys:
        monkeypatch.setenv(key, "http://runner:fixture@127.0.0.1:9")
    monkeypatch.setenv("UNRELATED_TARGET_ENV", "retained")
    for key in (
        "KIND", "ENDPOINT", "DESTINATION_PORT", "HOST", "PORT", "TOKEN",
    ):
        monkeypatch.delenv(f"ORCHESTRATOR_TARGET_RELAY_{key}", raising=False)

    launched = []

    def popen(*, args, env, **kwargs):
        launched.append((args, env))
        return FakeProcess()

    monkeypatch.setattr("orchestrator.targets.subprocess.Popen", popen)
    launcher = _default_launcher(":99")
    t, _runner, _launcher = _targets(launcher=launcher)
    t.open_target(TargetSpec("rdp", {"host": "winhost", **RDP_CERTIFICATE}))

    command, child_env = launched[0]
    assert command[0] == "xfreerdp"
    assert all(key not in child_env for key in proxy_keys)
    assert child_env["DISPLAY"] == ":99"
    assert child_env["UNRELATED_TARGET_ENV"] == "retained"
    assert os.environ["HTTPS_PROXY"] == "http://runner:fixture@127.0.0.1:9"

    launcher(["other-client"], env=None)
    assert launched[1][1]["HTTPS_PROXY"] == os.environ["HTTPS_PROXY"]


@pytest.mark.parametrize("algorithm, count", [("sha1", 20), ("sha256", 32)])
def test_rdp_compiles_reviewed_fingerprint_in_freerdp_byte_format(algorithm, count):
    t, _runner, launcher = _targets()
    digest = "01" * count
    t.open_target(TargetSpec("rdp", {
        "host": "winhost", "certificate_name": "WINHOST",
        "certificate_fingerprint": f"{algorithm}:{digest}",
    }))
    cert_options = [arg for arg in launcher.commands[0] if arg.startswith("/cert:")]
    assert cert_options == [
        f"/cert:deny,name:WINHOST,fingerprint:{algorithm}:" + ":".join(["01"] * count)
    ]


@pytest.mark.parametrize(
    "params, error",
    [
        ({"certificate_fingerprint": "sha256:" + "a" * 64}, "certificate_name"),
        ({"certificate_name": "WINHOST"}, "certificate_fingerprint"),
        ({
            "certificate_name": "bad name",
            "certificate_fingerprint": "sha256:" + "a" * 64,
        }, "certificate_name"),
        ({
            "certificate_name": "WINHOST",
            "certificate_fingerprint": "sha256:not-hex",
        }, "certificate_fingerprint"),
    ],
)
def test_rdp_requires_reviewed_certificate_identity_before_launch(params, error):
    t, _runner, launcher = _targets()
    with pytest.raises(TargetError, match=error):
        t.open_target(TargetSpec("rdp", {"host": "winhost", **params}))
    assert launcher.commands == []


@pytest.mark.parametrize("port", ["not-a-port", "0", "65536"])
def test_rdp_rejects_invalid_port_before_launch(port):
    t, _runner, launcher = _targets()
    with pytest.raises(TargetError, match="RDP port"):
        t.open_target(TargetSpec("rdp", {"host": "winhost", "port": port}))
    assert launcher.commands == []


# --- vnc (P3-4 / P3-8) ----------------------------------------------------


def test_vnc_non_allowlisted_refused_before_launch():
    t, _runner, launcher = _targets()
    spec = TargetSpec("vnc", {"host": "not-allowed"})
    with pytest.raises(HostNotAllowedError):
        t.open_target(spec)
    assert launcher.commands == []


def test_vnc_argv_uses_viewer_and_passwd_file_path(tmp_path):
    pw = tmp_path / "vnchost.vncpass"
    pw.write_text("ENCRYPTED VNC PASSWD")
    t, runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec("vnc", {"host": "vnchost", "password_file": "vnchost.vncpass"})
    handle = t.open_target(spec)

    cmd = launcher.commands[0]
    assert cmd[0] == "xtigervncviewer"
    assert "-passwd" in cmd
    assert str(pw) in cmd  # password passed by file path...
    assert "vnchost" in cmd  # ...destination is the bare host (display 0)
    # ...and the password *material* is never on the command line.
    assert "ENCRYPTED VNC PASSWD" not in " ".join(cmd)
    # The agent's input runner (xdotool type) is never used to enter the password.
    assert not any("type" in c for c in runner.calls)
    assert handle.type == "vnc"


def test_vnc_port_maps_to_double_colon_form():
    t, _runner, launcher = _targets()
    t.open_target(TargetSpec("vnc", {"host": "vnchost", "port": "5901"}))
    assert "vnchost::5901" in launcher.commands[0]


def test_vnc_missing_host_errors():
    t, _runner, _launcher = _targets()
    with pytest.raises(TargetError):
        t.open_target(TargetSpec("vnc", {}))


# --- unsupported legacy VNC jump route -----------------------------------


def test_legacy_vnc_via_is_rejected_without_launch(tmp_path):
    gw = tmp_path / "gw.pass"
    gw.write_text("GATEWAY SECRET\n")
    # The gateway host (build01) is in the helper's ssh_host_allowlist.
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec(
        "vnc",
        {"host": "vnchost", "port": "5900", "via": "ikim@build01", "gateway_password_file": "gw.pass"},
    )
    with pytest.raises(TargetError, match="explicit-argv"):
        t.open_target(spec)
    assert launcher.commands == []


def test_vnc_launch_captures_client_log_when_log_dir_set(tmp_path):
    # With a log_dir, the VNC client's stdout+stderr is captured for local diagnostics.
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path), log_dir=str(tmp_path))
    t.open_target(TargetSpec("vnc", {"host": "vnchost"}))
    assert launcher.log_paths[0] == str(tmp_path / "vnc_client.log")


def test_vnc_launch_no_log_path_without_log_dir(tmp_path):
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    t.open_target(TargetSpec("vnc", {"host": "vnchost"}))
    assert launcher.log_paths[0] is None


def test_vnc_via_gateway_is_rejected_before_any_route_fallback(tmp_path):
    (tmp_path / "gw.pass").write_text("x")
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    spec = TargetSpec(
        "vnc",
        {"host": "vnchost", "via": "ikim@evil-gateway", "gateway_password_file": "gw.pass"},
    )
    with pytest.raises(TargetError, match="VNC jump routing is disabled"):
        t.open_target(spec)
    assert launcher.commands == []  # refused before launch


def test_vnc_via_without_gateway_password_file_errors():
    t, _runner, launcher = _targets()
    spec = TargetSpec("vnc", {"host": "vnchost", "via": "ikim@build01"})
    with pytest.raises(TargetError):
        t.open_target(spec)
    assert launcher.commands == []


def test_vnc_typed_ssh_jump_uses_strict_loopback_forward_and_separate_passwords(tmp_path):
    (tmp_path / "jump.pw").write_text("gateway-secret\n")
    (tmp_path / "jump.known_hosts").write_text("build01 ssh-ed25519 AAAATEST\n")
    (tmp_path / "vnc.pass").write_text("encrypted-vnc-secret")
    t, _runner, launcher = _targets(
        secrets_dir=str(tmp_path),
        tunnel_port_allocator=lambda: 43123,
        tunnel_probe=lambda host, port: (host, port) == ("127.0.0.1", 43123),
    )
    handle = t.open_target(TargetSpec("vnc", {
        "host": "vnchost", "port": "5900", "password_file": "vnc.pass",
        "route_type": "ssh-jump", "jump_host": "build01", "jump_user": "ikim",
        "jump_port": "22", "jump_known_hosts_file": "jump.known_hosts",
        "gateway_password_file": "jump.pw",
    }))

    tunnel, viewer = launcher.commands
    assert tunnel[:3] == ["sshpass", "-f", str(tmp_path / "jump.pw")]
    assert "StrictHostKeyChecking=yes" in tunnel
    assert f"UserKnownHostsFile={tmp_path / 'jump.known_hosts'}" in tunnel
    assert "127.0.0.1:43123:vnchost:5900" in tunnel
    assert "ikim@build01" in tunnel
    assert "gateway-secret" not in " ".join(tunnel)
    assert viewer[0] == "xtigervncviewer"
    assert "127.0.0.1::43123" in viewer
    assert "vnchost" not in viewer
    assert handle.auxiliary_processes


def test_vnc_typed_jump_rejects_non_allowlisted_gateway_before_launch(tmp_path):
    (tmp_path / "jump.pw").write_text("secret\n")
    (tmp_path / "jump.known_hosts").write_text("evil ssh-ed25519 AAAATEST\n")
    t, _runner, launcher = _targets(secrets_dir=str(tmp_path))
    with pytest.raises(HostNotAllowedError):
        t.open_target(TargetSpec("vnc", {
            "host": "vnchost", "route_type": "ssh-jump", "jump_host": "evil",
            "jump_known_hosts_file": "jump.known_hosts", "gateway_password_file": "jump.pw",
        }))
    assert launcher.commands == []


def test_direct_vnc_uses_only_the_authenticated_loopback_proxy(monkeypatch):
    class Relay:
        pid = -1
        local_port = 45231
        closed = False

        def poll(self):
            return 0 if self.closed else None

        def terminate(self):
            self.closed = True

        kill = terminate

        def wait(self, timeout=None):
            return 0

    relay = Relay()
    observed = {}

    def from_environment(**kwargs):
        observed.update(kwargs)
        return relay

    monkeypatch.setattr(
        "orchestrator.targets.TargetRelayClient.from_environment", from_environment
    )
    t, _runner, launcher = _targets()
    handle = t.open_target(TargetSpec("vnc", {"host": "vnchost", "port": "5902"}))

    assert observed == {
        "kind": "vnc-direct", "endpoint": "vnchost", "destination_port": 5902
    }
    assert "127.0.0.1::45231" in launcher.commands[0]
    assert "vnchost::5902" not in launcher.commands[0]
    assert relay in handle.auxiliary_processes


def test_jump_vnc_proxy_preserves_original_ssh_destination_for_host_key(monkeypatch, tmp_path):
    class Relay:
        pid = -1
        local_port = 45232

        def poll(self):
            return None

        def terminate(self):
            return None

        kill = terminate

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        "orchestrator.targets.TargetRelayClient.from_environment", lambda **_kw: Relay()
    )
    (tmp_path / "jump.pw").write_text("gateway-secret\n")
    (tmp_path / "jump.known_hosts").write_text("jump.example ssh-ed25519 AAAATEST\n")
    t, _runner, launcher = _targets(
        secrets_dir=str(tmp_path),
        ssh_host_allowlist=["jump.example"],
        tunnel_port_allocator=lambda: 43123,
        tunnel_probe=lambda _host, _port: True,
    )
    t.open_target(TargetSpec("vnc", {
        "host": "vnchost", "port": "5900", "route_type": "ssh-jump",
        "jump_host": "jump.example", "jump_user": "operator", "jump_port": "2222",
        "jump_known_hosts_file": "jump.known_hosts",
        "gateway_password_file": "jump.pw",
    }))

    tunnel = launcher.commands[0]
    assert "operator@jump.example" in tunnel
    assert tunnel[tunnel.index("-p") + 1] == "2222"
    proxy = next(value for value in tunnel if value.startswith("ProxyCommand="))
    assert proxy == (
        "ProxyCommand=python -m orchestrator.target_relay connect-loopback --port 45232"
    )
    assert "HostKeyAlias" not in " ".join(tunnel)


# --- local-app ------------------------------------------------------------


def test_local_app_launches_and_focuses():
    t, runner, launcher = _targets()
    handle = t.open_target(TargetSpec("local-app", {"app": "gedit", "window": "gedit"}))
    assert launcher.commands[0] == ["gedit"]
    assert handle.window_id == "777"
    # focus issued windowactivate + windowraise.
    verbs = [c[1] for c in runner.calls if len(c) > 1]
    assert "windowactivate" in verbs and "windowraise" in verbs


def test_local_app_requires_app_param():
    t, _runner, _launcher = _targets()
    with pytest.raises(TargetError):
        t.open_target(TargetSpec("local-app", {}))


def test_host_app_waits_for_bridge_window_without_container_launch(monkeypatch):
    monkeypatch.setenv("HOST_APP_BRIDGE_ACTIVE", "1")
    t, runner, launcher = _targets()
    handle = t.open_target(TargetSpec(
        "host-app",
        {
            "app": "~/JAMboree/BOOM.sh",
            "window": "JAMboree",
            "startup_timeout": "60",
        },
    ))
    assert launcher.commands == []
    assert handle.type == "host-app"
    assert handle.process is None
    assert handle.window_id == "777"
    assert ["xdotool", "windowactivate", "777"] in runner.calls


def test_host_app_refuses_to_run_without_host_bridge(monkeypatch):
    monkeypatch.delenv("HOST_APP_BRIDGE_ACTIVE", raising=False)
    t, _runner, launcher = _targets()
    with pytest.raises(TargetError, match="host launch bridge"):
        t.open_target(TargetSpec(
            "host-app", {"app": "~/JAMboree/BOOM.sh", "window": "JAMboree"}
        ))
    assert launcher.commands == []


def test_host_app_rejects_unbounded_startup_timeout(monkeypatch):
    monkeypatch.setenv("HOST_APP_BRIDGE_ACTIVE", "1")
    t, _runner, launcher = _targets()
    with pytest.raises(TargetError, match="between 1 and 300"):
        t.open_target(TargetSpec(
            "host-app",
            {"app": "~/JAMboree/BOOM.sh", "startup_timeout": "999"},
        ))
    assert launcher.commands == []


def test_unknown_target_type():
    t, _runner, _launcher = _targets()
    with pytest.raises(TargetError):
        t.open_target(TargetSpec("carrier-pigeon", {}))


# --- focus helper (P3-6) --------------------------------------------------


def test_focus_activates_found_window():
    runner = FakeRunner(outputs={"search": "12345\n"})
    t, _runner, _launcher = _targets(runner=runner)
    wid = t.focus("some-window")
    assert wid == "12345"
    assert ["xdotool", "windowactivate", "12345"] in runner.calls
    assert ["xdotool", "windowraise", "12345"] in runner.calls


def test_focus_returns_none_when_no_window():
    runner = FakeRunner(outputs={"search": ""})
    t, _runner, _launcher = _targets(runner=runner)
    assert t.focus("nope") is None


# --- wait timeout ---------------------------------------------------------


def test_wait_for_window_times_out():
    runner = FakeRunner(outputs={"search": ""})  # never finds a window
    t, _runner, _launcher = _targets(runner=runner, window_wait_seconds=0.5, poll_interval=0.1)
    with pytest.raises(WindowNotFoundError):
        t.open_target(TargetSpec("local-app", {"app": "gedit"}))


# --- close_target (P3-7) --------------------------------------------------


def test_close_target_closes_window_and_terminates_process():
    t, runner, launcher = _targets()
    handle = t.open_target(TargetSpec("local-app", {"app": "gedit"}))
    t.close_target(handle)
    assert ["xdotool", "windowclose", "777"] in runner.calls
    assert launcher.proc.terminated is True
