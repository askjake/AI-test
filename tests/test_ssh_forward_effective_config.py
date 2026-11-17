"""The runner's SSH local-forward argv must actually keep its -L forward.

Regression: the argv carried both ``-o ClearAllForwardings=yes`` and ``-L``; OpenSSH then drops the forward, so the tunnel process starts
(``-N``) but nothing ever listens and the VNC open times out with no client output.  ``ssh -G`` prints the effective configuration without
connecting, so this test makes no network use.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from target_routing import build_ssh_gateway_probe_argv, build_ssh_local_forward_argv

pytestmark = pytest.mark.skipif(shutil.which("ssh") is None, reason="ssh client not installed")


def _effective(argv: list[str]) -> dict[str, list[str]]:
    # argv ends with the destination; -G evaluates the configuration and prints it without connecting.
    out = subprocess.run([argv[0], "-G", *argv[1:]], capture_output=True, text=True, timeout=10, check=True,
                         env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}).stdout
    cfg: dict[str, list[str]] = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        cfg.setdefault(key.lower(), []).append(value)
    return cfg


def _forward(**over):
    kw = dict(local_port=45901, target_host="192.0.2.47", target_port=5902, gateway_port=22, known_hosts_path="/tmp/does-not-need-to-exist.hosts")
    kw.update(over)
    return build_ssh_local_forward_argv("ssh", "gwuser@192.0.2.10", **kw)


def test_the_forward_survives_into_the_effective_ssh_configuration():
    cfg = _effective(_forward())
    assert cfg["localforward"] == ["[127.0.0.1]:45901 [192.0.2.47]:5902"]
    assert cfg["clearallforwardings"] == ["no"]


def test_the_forward_is_loopback_only_and_uses_the_requested_target_port():
    cfg = _effective(_forward(local_port=45999, target_host="192.0.2.99", target_port=5905))
    assert cfg["localforward"] == ["[127.0.0.1]:45999 [192.0.2.99]:5905"]


def test_strict_host_key_checking_and_the_dedicated_known_hosts_file_are_still_in_force():
    argv = _forward(known_hosts_path="/run/secrets/jump.hosts")
    cfg = _effective(argv)
    assert cfg["stricthostkeychecking"] == ["true"]
    assert cfg["userknownhostsfile"] == ["/run/secrets/jump.hosts"]
    assert cfg["globalknownhostsfile"] == ["/dev/null"]
    assert cfg["exitonforwardfailure"] == ["yes"]           # ssh -G prints some yes-values as "true" (stricthostkeychecking) and some as "yes"
    assert cfg["connectionattempts"] == ["1"]
    assert "-N" in argv and "-T" in argv and argv[-1] == "gwuser@192.0.2.10"


def test_exit_on_forward_failure_means_a_dead_forward_cannot_look_ready():
    assert "ExitOnForwardFailure=yes" in _forward()


def test_a_non_default_gateway_port_and_a_proxy_command_do_not_disturb_the_forward():
    cfg = _effective(_forward(gateway_port=2222, proxy_command=("python", "-m", "orchestrator.target_relay", "connect-loopback", "--port", "45100")))
    assert cfg["port"] == ["2222"]
    assert cfg["localforward"] == ["[127.0.0.1]:45901 [192.0.2.47]:5902"]
    assert cfg["proxycommand"][0].startswith("python -m orchestrator.target_relay connect-loopback")


def test_the_gateway_probe_builder_still_declares_no_forward_and_stays_strict():
    probe = build_ssh_gateway_probe_argv("ssh", "gwuser@192.0.2.10", gateway_port=22, known_hosts_path="/tmp/x.hosts", connect_timeout=5)
    assert "-L" not in probe and "StrictHostKeyChecking=yes" in probe
    cfg = _effective(probe)
    assert cfg["stricthostkeychecking"] == ["true"] and "localforward" not in cfg


# ------------------------------------------------------------------------------------------------ ambient configuration isolation (-F /dev/null)
import os
import shlex
import tempfile
import textwrap

HOSTILE_USER_CONFIG = textwrap.dedent("""\
    Host *
        LocalForward 19999 evil-user.example.test:22
        DynamicForward 19998
        RemoteForward 19997 evil-remote.example.test:22
        ProxyJump evil-hop.example.test
        HostName rewritten.example.test
        StrictHostKeyChecking no
        UserKnownHostsFile /tmp/ambient-known-hosts
""")
HOSTILE_SYSTEM_CONFIG = textwrap.dedent("""\
    Host *
        LocalForward 19996 evil-system.example.test:22
        ClearAllForwardings no
""")


def _ns_ssh_g(argv: list[str]) -> dict[str, list[str]] | None:
    """Run ``ssh -G`` for argv inside a private user+mount namespace where the invoking account's ~/.ssh/config and /etc/ssh/ssh_config are
    replaced by hostile fixtures.  Nothing on the real filesystem is touched.  None when unprivileged namespaces are unavailable."""
    if shutil.which("unshare") is None:
        return None
    with tempfile.TemporaryDirectory(prefix="ssh-ambient-") as tmp:
        user_cfg, system_cfg = os.path.join(tmp, "user_config"), os.path.join(tmp, "system_config")
        open(user_cfg, "w").write(HOSTILE_USER_CONFIG)
        open(system_cfg, "w").write(HOSTILE_SYSTEM_CONFIG)
        os.chmod(user_cfg, 0o600)
        script = (f"mount -t tmpfs tmpfs /root && mkdir -p /root/.ssh && cp {shlex.quote(user_cfg)} /root/.ssh/config && chmod 600 /root/.ssh/config"
                  f" && mount --bind {shlex.quote(system_cfg)} /etc/ssh/ssh_config && exec {shlex.join([argv[0], '-G', *argv[1:]])}")
        done = subprocess.run(["unshare", "-r", "-m", "sh", "-c", script], capture_output=True, text=True, timeout=20,
                              env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    if done.returncode != 0:
        return None
    cfg: dict[str, list[str]] = {}
    for line in done.stdout.splitlines():
        key, _, value = line.partition(" ")
        cfg.setdefault(key.lower(), []).append(value)
    return cfg


def _strip_isolation(argv: list[str]) -> list[str]:
    i = argv.index("-F")
    return argv[:i] + argv[i + 2:]


def test_the_forward_argv_isolates_the_tunnel_from_ambient_ssh_configuration():
    argv = _forward()
    i = argv.index("-F")
    assert argv[i + 1] == "/dev/null" and i < argv.index("-N"), "-F /dev/null must be an explicit option, ahead of the forward"
    assert argv.count("-F") == 1 and argv[-1] == "gwuser@192.0.2.10"


def test_a_hostile_ambient_config_fixture_really_adds_forwards_without_the_isolation_negative_control():
    without = _ns_ssh_g(_strip_isolation(_forward()))
    if without is None:
        pytest.skip("unprivileged user+mount namespaces are unavailable here, so the ambient-config fixture cannot be built")
    forwards = without["localforward"]
    assert any("evil-user.example.test" in f for f in forwards) and any("evil-system.example.test" in f for f in forwards), forwards
    assert "dynamicforward" in without and "remoteforward" in without and "proxyjump" in without     # the fixture is effective


def test_an_ambient_config_fixture_cannot_add_a_forward_or_change_the_route_when_the_isolation_is_present():
    cfg = _ns_ssh_g(_forward())
    if cfg is None:
        pytest.skip("unprivileged user+mount namespaces are unavailable here, so the ambient-config fixture cannot be built")
    assert cfg["localforward"] == ["[127.0.0.1]:45901 [192.0.2.47]:5902"], cfg["localforward"]
    for key in ("dynamicforward", "remoteforward", "proxyjump"):
        assert key not in cfg, (key, cfg[key])
    assert cfg["hostname"] == ["192.0.2.10"]
    assert cfg["stricthostkeychecking"] == ["true"] and cfg["userknownhostsfile"] == ["/tmp/does-not-need-to-exist.hosts"]
    assert cfg["globalknownhostsfile"] == ["/dev/null"] and cfg["clearallforwardings"] == ["no"] and cfg["exitonforwardfailure"] == ["yes"]


def test_the_isolation_also_holds_with_a_gateway_proxy_command_and_a_non_default_port():
    cfg = _ns_ssh_g(_forward(gateway_port=2222, proxy_command=("python", "-m", "orchestrator.target_relay", "connect-loopback", "--port", "45100")))
    if cfg is None:
        pytest.skip("unprivileged user+mount namespaces are unavailable here, so the ambient-config fixture cannot be built")
    assert cfg["localforward"] == ["[127.0.0.1]:45901 [192.0.2.47]:5902"] and cfg["port"] == ["2222"] and "proxyjump" not in cfg
    assert cfg["proxycommand"][0].startswith("python -m orchestrator.target_relay connect-loopback")


def test_the_gateway_probe_builder_is_not_part_of_the_forward_change():
    probe = build_ssh_gateway_probe_argv("ssh", "gwuser@192.0.2.10", gateway_port=22, known_hosts_path="/tmp/x.hosts", connect_timeout=5)
    assert "-L" not in probe
