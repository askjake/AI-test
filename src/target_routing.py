"""Pure target-route argv construction shared without importing runner code into dashboard."""
from __future__ import annotations

import re
import shlex
from collections.abc import Sequence


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SshRouteError(ValueError):
    """A typed SSH route cannot be represented by the bounded argv contract."""


def _safe_value(value: str, label: str, pattern: re.Pattern[str]) -> str:
    if not value or not pattern.fullmatch(value):
        raise SshRouteError(f"{label} is invalid for a typed SSH route")
    return value


def build_ssh_argv(
    executable: str,
    destination: str,
    *,
    key_path: str | None = None,
    jump_host: str | None = None,
    jump_user: str | None = None,
    jump_port: int = 22,
    known_hosts_path: str | None = None,
    batch_mode: bool = False,
    connect_timeout: int | None = None,
    remote_command: tuple[str, ...] = (),
) -> list[str]:
    """Build one literal OpenSSH argv; no shell or credential-bearing URL is involved."""
    if not executable or any(char in executable for char in "\r\n\0"):
        raise SshRouteError("SSH executable is invalid")
    if not destination or any(char.isspace() or ord(char) < 32 for char in destination):
        raise SshRouteError("SSH destination is invalid")
    argv = [executable]
    if batch_mode:
        argv.extend(["-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0"])
    if connect_timeout is not None:
        if not 1 <= connect_timeout <= 300:
            raise SshRouteError("SSH connect timeout must be between 1 and 300 seconds")
        argv.extend(["-o", f"ConnectTimeout={connect_timeout}", "-o", "ConnectionAttempts=1"])
    if jump_host is not None:
        host = _safe_value(jump_host, "jump host", _HOST_RE)
        if jump_user:
            _safe_value(jump_user, "jump user", _USER_RE)
        if not 1 <= jump_port <= 65535:
            raise SshRouteError("jump port must be between 1 and 65535")
        if not known_hosts_path or any(char in known_hosts_path for char in "\r\n\0"):
            raise SshRouteError("a known-hosts file is required for an SSH jump route")
        jump = f"{jump_user}@{host}" if jump_user else host
        if jump_port != 22:
            jump = f"{jump}:{jump_port}"
        argv.extend([
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts_path}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"ProxyJump={jump}",
        ])
    else:
        argv.extend(["-o", "StrictHostKeyChecking=accept-new"])
    if key_path:
        if any(char in key_path for char in "\r\n\0"):
            raise SshRouteError("SSH key path is invalid")
        argv.extend(["-o", "IdentitiesOnly=yes", "-i", key_path])
    argv.append(destination)
    for value in remote_command:
        if any(char in value for char in "\r\n\0"):
            raise SshRouteError("SSH remote command contains an invalid character")
        argv.append(value)
    return argv


def build_ssh_local_forward_argv(
    executable: str,
    gateway: str,
    *,
    local_port: int,
    target_host: str,
    target_port: int,
    gateway_port: int = 22,
    known_hosts_path: str,
    connect_timeout: int = 15,
    proxy_command: Sequence[str] | None = None,
) -> list[str]:
    """Build a strict, loopback-only OpenSSH local-forward argv.

    This is the protocol-specific route used for VNC over an SSH jump host.
    No shell, dynamic forwarding, remote command, or credential-bearing URL is
    involved.  The caller may prefix this argv with ``sshpass -f <file>``.
    """

    if not executable or any(char in executable for char in "\r\n\0"):
        raise SshRouteError("SSH executable is invalid")
    if not gateway or any(char.isspace() or ord(char) < 32 for char in gateway):
        raise SshRouteError("SSH gateway destination is invalid")
    _safe_value(target_host, "forward target host", _HOST_RE)
    if not 1 <= local_port <= 65535 or not 1 <= target_port <= 65535:
        raise SshRouteError("forward ports must be between 1 and 65535")
    if not 1 <= gateway_port <= 65535:
        raise SshRouteError("gateway port must be between 1 and 65535")
    if not known_hosts_path or any(char in known_hosts_path for char in "\r\n\0"):
        raise SshRouteError("a known-hosts file is required for an SSH local forward")
    if not 1 <= connect_timeout <= 300:
        raise SshRouteError("SSH connect timeout must be between 1 and 300 seconds")
    argv = [
        executable,
        # Ambient configuration must not shape the tunnel: -F /dev/null makes ssh ignore ~/.ssh/config AND /etc/ssh/ssh_config, so a stray
        # LocalForward/DynamicForward/RemoteForward/ProxyJump/StrictHostKeyChecking there cannot change the one explicit loopback forward below.
        "-F", "/dev/null",
        "-N", "-T",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
    ]
    if proxy_command is not None:
        if not proxy_command:
            raise SshRouteError("SSH proxy command must not be empty")
        for value in proxy_command:
            if not value or any(char in value for char in "\r\n\0"):
                raise SshRouteError("SSH proxy command contains an invalid value")
        argv.extend(["-o", f"ProxyCommand={shlex.join(proxy_command)}"])
    argv.extend([
        "-p", str(gateway_port),
        "-L", f"127.0.0.1:{local_port}:{target_host}:{target_port}",
        gateway,
    ])
    return argv


def build_ssh_gateway_probe_argv(
    executable: str,
    gateway: str,
    *,
    gateway_port: int,
    known_hosts_path: str,
    connect_timeout: int,
) -> list[str]:
    """Build a bounded strict-host-key gateway authentication probe."""

    if not executable or any(char in executable for char in "\r\n\0"):
        raise SshRouteError("SSH executable is invalid")
    if not gateway or any(char.isspace() or ord(char) < 32 for char in gateway):
        raise SshRouteError("SSH gateway destination is invalid")
    if not 1 <= gateway_port <= 65535:
        raise SshRouteError("gateway port must be between 1 and 65535")
    if not known_hosts_path or any(char in known_hosts_path for char in "\r\n\0"):
        raise SshRouteError("a known-hosts file is required for an SSH gateway probe")
    if not 1 <= connect_timeout <= 300:
        raise SshRouteError("SSH connect timeout must be between 1 and 300 seconds")
    return [
        executable, "-T",
        "-o", "BatchMode=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "ConnectionAttempts=1",
        "-p", str(gateway_port), gateway, "exit",
    ]
