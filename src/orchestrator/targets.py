"""Opens and focuses target windows on the virtual display (Phase 3).

Five target types share one vision loop and differ only in which window is focused:
``local-app`` (a containerized Linux GUI app), ``host-app`` (an allowlisted GUI app launched
on the host into the run's virtual display), ``ssh-terminal`` (an ``xterm``
running ``ssh`` from *inside* the container), ``rdp`` (an ``xfreerdp`` window connected to
an **existing** remote Windows machine — Windows is never virtualized in-container), and
``vnc`` (an ``xtigervncviewer`` window connected to an **existing** remote VNC server).

Security invariants enforced here:

- **Host allowlists.** ``ssh-terminal`` / ``rdp`` hosts are validated against the spec's
  effective allowlist and refused otherwise, *before* any process is launched.
- **Secrets never touch Claude.** SSH keys, RDP passwords, and VNC password files come from
  the read-only ``secrets/`` mount and are handed to the client process (``ssh -i <key>`` /
  ``xfreerdp /p:`` / ``xtigervncviewer -passwd <file>``) — they are never typed by the agent
  and never appear in a screenshot.

The subprocess launcher and the ``xdotool`` runner are injectable so the dispatch,
allowlist, and focus logic can be unit-tested without a real X display.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .config import settings
from .target_relay import TargetRelayClient, TargetRelayError
from target_routing import SshRouteError, build_ssh_argv, build_ssh_local_forward_argv


class TargetError(Exception):
    """Base error for target setup problems."""


class HostNotAllowedError(TargetError):
    """Raised when an ssh/rdp host is not in the effective allowlist.

    This is a security gate: it is raised *before* any connection is attempted, so a
    non-allowlisted host never causes a process launch or network call.
    """


class WindowNotFoundError(TargetError):
    """Raised when a target's window never appears within the wait timeout."""


# Runs an argv list with DISPLAY set and returns stdout (text). Same shape as computer.py.
Runner = Callable[[list[str]], str]


class Process(Protocol):
    """The slice of ``subprocess.Popen`` that :class:`Targets` relies on."""

    pid: int

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = ...) -> int: ...


# Launches a detached client process for a target window. ``env`` overlays explicit
# environment variables on the launcher's base environment; None removes a variable.
# ``log_path``, when given,
# captures the child's stdout+stderr so a failed client launch leaves local diagnostics.
Launcher = Callable[..., Process]


_RDP_CERTIFICATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
_RDP_CERTIFICATE_FINGERPRINT_RE = re.compile(
    r"^(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$"
)


@dataclass
class TargetSpec:
    """A minimal description of what window to open and how.

    Phase 5 parses ``## Target`` lines into this; here it is the unit of dispatch.
    ``type`` is ``local-app`` | ``host-app`` | ``ssh-terminal`` | ``rdp`` | ``vnc``.
    ``params`` carries the
    type-specific keys parsed from the spec (e.g. ``host``, ``user``, ``key``, ``app``,
    ``window``, ``password_file``).
    """

    type: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class TargetHandle:
    """A live target: its window name/id and the client process backing it."""

    type: str
    window_name: str
    window_id: str | None
    process: Process | None
    auxiliary_processes: tuple[Process, ...] = ()


def _default_runner(display: str) -> Runner:
    def run(cmd: list[str]) -> str:
        env = {**os.environ, "DISPLAY": display}
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
        return proc.stdout

    return run


def _default_launcher(display: str) -> Launcher:
    def launch(
        cmd: list[str],
        env: dict[str, str | None] | None = None,
        log_path: str | None = None,
        stdin_data: bytes | None = None,
    ) -> Process:
        full_env = {**os.environ, "DISPLAY": display}
        for key, value in (env or {}).items():
            if value is None:
                full_env.pop(key, None)
            else:
                full_env[key] = value
        stdin = subprocess.PIPE if stdin_data is not None else None
        if log_path is None:
            proc = subprocess.Popen(env=full_env, args=cmd, stdin=stdin)
        else:
            # Capture the client's stdout+stderr to a file so a failed launch (e.g. a vnc ``-via``
            # SSH tunnel that never comes up) leaves its diagnostics in the run directory instead
            # of being lost. The child dups the fd, so we close our copy right after Popen.
            log = open(log_path, "wb")
            try:
                proc = subprocess.Popen(env=full_env, args=cmd, stdout=log, stderr=log, stdin=stdin)
            finally:
                log.close()
        if stdin_data is not None:
            # Secret-bearing arguments travel over this pipe, never the process argument list.
            try:
                proc.stdin.write(stdin_data)
                proc.stdin.close()
            except OSError:
                pass  # the client already exited; its exit status is handled by the caller
        return proc

    return launch


class Targets:
    """Opens, focuses, and closes target windows on the virtual display.

    ``ssh_host_allowlist`` / ``rdp_host_allowlist`` default to the global config but are
    overridable so Phase 5 can pass a project's **effective** (merged) allowlists. The
    enforcement point is unchanged regardless of where the lists come from.
    """

    def __init__(
        self,
        *,
        display: str | None = None,
        ssh_host_allowlist: list[str] | None = None,
        rdp_host_allowlist: list[str] | None = None,
        vnc_host_allowlist: list[str] | None = None,
        secrets_dir: str | None = None,
        log_dir: str | None = None,
        rdp_width: int | None = None,
        rdp_height: int | None = None,
        runner: Runner | None = None,
        launcher: Launcher | None = None,
        sleep: Callable[[float], None] | None = None,
        window_wait_seconds: float = 15.0,
        poll_interval: float = 0.25,
        tunnel_port_allocator: Callable[[], int] | None = None,
        tunnel_probe: Callable[[str, int], bool] | None = None,
    ) -> None:
        self.display = display or settings.display
        self.rdp_width = rdp_width if rdp_width is not None else settings.rdp_width
        self.rdp_height = rdp_height if rdp_height is not None else settings.rdp_height
        self.ssh_host_allowlist = (
            ssh_host_allowlist if ssh_host_allowlist is not None else list(settings.ssh_host_allowlist)
        )
        self.rdp_host_allowlist = (
            rdp_host_allowlist if rdp_host_allowlist is not None else list(settings.rdp_host_allowlist)
        )
        self.vnc_host_allowlist = (
            vnc_host_allowlist if vnc_host_allowlist is not None else list(settings.vnc_host_allowlist)
        )
        self.secrets_dir = secrets_dir or settings.secrets_dir
        self.log_dir = log_dir
        self._run = runner or _default_runner(self.display)
        self._launch = launcher or _default_launcher(self.display)
        self._sleep = sleep or time.sleep
        self._stdin_probe_seconds = 1.5  # how long a stdin-argument FreeRDP launch must stay up
        self.window_wait_seconds = window_wait_seconds
        self.poll_interval = poll_interval
        self._tunnel_port_allocator = tunnel_port_allocator or self._allocate_loopback_port
        self._tunnel_probe = tunnel_probe or self._probe_loopback_port

    # --- dispatch ----------------------------------------------------------

    def open_target(self, spec: TargetSpec) -> TargetHandle:
        """Open the window for ``spec`` and return a focused :class:`TargetHandle`."""
        if spec.type == "local-app":
            return self._open_local_app(spec)
        if spec.type == "host-app":
            return self._open_host_app(spec)
        if spec.type == "ssh-terminal":
            return self._open_ssh_terminal(spec)
        if spec.type == "rdp":
            return self._open_rdp(spec)
        if spec.type == "vnc":
            return self._open_vnc(spec)
        raise TargetError(f"unknown target type: {spec.type!r}")

    # --- local-app ---------------------------------------------------------

    def _open_local_app(self, spec: TargetSpec) -> TargetHandle:
        app = spec.params.get("app")
        if not app:
            raise TargetError("local-app target requires an 'app' param (command to launch)")
        # ``window`` overrides the title pattern to search for; default to the app basename.
        window_name = spec.params.get("window") or os.path.basename(shlex.split(app)[0])
        proc = self._launch(shlex.split(app))
        window_id = self._wait_for_window(window_name)
        self.focus(window_name)
        return TargetHandle("local-app", window_name, window_id, proc)

    # --- host-app ----------------------------------------------------------

    def _open_host_app(self, spec: TargetSpec) -> TargetHandle:
        """Wait for the host bridge to launch an allowlisted app into this display."""
        app = spec.params.get("app")
        if not app:
            raise TargetError("host-app target requires an 'app' path")
        if os.environ.get("HOST_APP_BRIDGE_ACTIVE") != "1":
            raise TargetError(
                "host-app target requires the host launch bridge; run one project via "
                "scripts/run_specs.sh or the dashboard spawn backend"
            )
        window_name = spec.params.get("window") or os.path.basename(shlex.split(app)[0])
        timeout_raw = spec.params.get("startup_timeout")
        timeout = self.window_wait_seconds
        if timeout_raw is not None:
            try:
                timeout = float(timeout_raw)
            except ValueError as exc:
                raise TargetError("host-app startup_timeout must be numeric") from exc
            if not 1 <= timeout <= 300:
                raise TargetError("host-app startup_timeout must be between 1 and 300 seconds")
        window_id = self._wait_for_window(window_name, timeout=timeout)
        self.focus(window_name)
        return TargetHandle("host-app", window_name, window_id, None)

    # --- ssh-terminal ------------------------------------------------------

    def _open_ssh_terminal(self, spec: TargetSpec) -> TargetHandle:
        host = spec.params.get("host")
        if not host:
            raise TargetError("ssh-terminal target requires a 'host' param")
        self._check_allowed(host, self.ssh_host_allowlist, "ssh")

        user = spec.params.get("user")
        destination = f"{user}@{host}" if user else host
        title = spec.params.get("window") or f"orchestrator-ssh-{host}"

        route_type = spec.params.get("route_type", "direct")
        if route_type not in {"direct", "ssh-jump"}:
            raise TargetError(f"unsupported SSH connection route: {route_type!r}")
        jump_host = spec.params.get("jump_host") if route_type == "ssh-jump" else None
        known_hosts_path = None
        if jump_host:
            self._check_allowed(jump_host, self.ssh_host_allowlist, "ssh jump")
            known_hosts_reference = spec.params.get("jump_known_hosts_file")
            if not known_hosts_reference:
                raise TargetError("SSH jump route requires a clone-local known-hosts reference")
            known_hosts_path = self._secret_path(known_hosts_reference)
        key = spec.params.get("key")
        try:
            jump_port = int(spec.params.get("jump_port", "22"))
        except ValueError as exc:
            raise TargetError("SSH jump port must be numeric") from exc
        try:
            ssh_cmd = build_ssh_argv(
                "ssh",
                destination,
                key_path=self._secret_path(key) if key else None,
                jump_host=jump_host,
                jump_user=spec.params.get("jump_user"),
                jump_port=jump_port,
                known_hosts_path=known_hosts_path,
            )
        except SshRouteError as exc:
            raise TargetError(str(exc)) from exc

        cmd = ["xterm", "-T", title, "-e", *ssh_cmd]
        proc = self._launch(cmd)
        window_id = self._wait_for_window(title)
        self.focus(title)
        return TargetHandle("ssh-terminal", title, window_id, proc)

    # --- rdp ---------------------------------------------------------------

    def _open_rdp(self, spec: TargetSpec) -> TargetHandle:
        host = spec.params.get("host")
        if not host:
            raise TargetError("rdp target requires a 'host' param")
        self._check_allowed(host, self.rdp_host_allowlist, "rdp")
        if spec.params.get("route_type", "direct") != "direct":
            raise TargetError(
                "RDP jump routing is disabled because no generic route meets the explicit-argv safety contract"
            )

        try:
            remote_port = int(spec.params.get("port") or "3389")
        except ValueError as exc:
            raise TargetError("RDP port must be numeric") from exc
        if not 1 <= remote_port <= 65535:
            raise TargetError("RDP port must be between 1 and 65535")

        certificate_name = (spec.params.get("certificate_name") or "").strip()
        if _RDP_CERTIFICATE_NAME_RE.fullmatch(certificate_name) is None:
            raise TargetError(
                "rdp target requires a reviewed certificate_name before launch"
            )
        certificate_fingerprint = (
            spec.params.get("certificate_fingerprint") or ""
        ).strip().lower()
        if _RDP_CERTIFICATE_FINGERPRINT_RE.fullmatch(certificate_fingerprint) is None:
            raise TargetError(
                "rdp target requires a reviewed sha256 or sha1 certificate_fingerprint "
                "before launch"
            )
        algorithm, digest = certificate_fingerprint.split(":", 1)
        client_fingerprint = f"{algorithm}:" + ":".join(
            digest[index:index + 2] for index in range(0, len(digest), 2)
        )

        title = spec.params.get("window") or f"orchestrator-rdp-{host}"
        destination = f"{host}:{remote_port}" if spec.params.get("port") else host
        # Chain hop 1 must fill the runner display (1:1 screen coordinates; window_covers_display() is the
        # safeguard).  A windowed client at the configured size cannot cover a larger display, so such a
        # target asks FreeRDP for full screen at the MEASURED display size.  Other rdp targets are unchanged.
        want_fullscreen = str(spec.params.get("fullscreen") or "").strip().lower() in {"1", "true", "yes"}
        rdp_width, rdp_height = self.rdp_width, self.rdp_height
        if want_fullscreen:
            rdp_width, rdp_height = self._display_size() or (rdp_width, rdp_height)
        cmd = [
            "xfreerdp",
            f"/v:{destination}",
            (
                f"/cert:deny,name:{certificate_name},"
                f"fingerprint:{client_fingerprint}"
            ),
            f"/title:{title}",
            f"/w:{rdp_width}",
            f"/h:{rdp_height}",
            *(("/f",) if want_fullscreen else ()),
            "/gdi:sw",
            "/network:auto",
            "/timeout:30000",
        ]

        user = spec.params.get("user")
        if user:
            cmd.append(f"/u:{user}")
        # Password comes from the read-only secrets mount, handed straight to the client.
        # ``password_transport=stdin`` (used by nested chains) keeps it out of the process
        # argument list and the environment: the client is started with ``/from-stdin`` and the
        # password is written to its stdin as ONE line (see _launch_rdp_over_stdin).  The pinned
        # FreeRDP 2.11.7 has no ``/args-from`` option, so the earlier all-arguments-over-stdin form
        # could never work with it.
        transport = (spec.params.get("password_transport") or "argv").strip().lower()
        if transport not in ("argv", "stdin"):
            raise TargetError("unknown rdp password transport")
        password_file = spec.params.get("password_file")
        stdin_password: str | None = None
        if transport == "stdin":
            # With /from-stdin FreeRDP prompts for any MISSING field on the same pipe (a missing user name
            # would swallow the password line as a user name), so both must be present up front.
            if not user:
                raise TargetError("rdp password over stdin requires a user name")
            if not password_file:
                raise TargetError("rdp password over stdin requires a saved password")
        if password_file:
            password = self._read_secret(password_file)
            if transport == "stdin":
                self._stdin_password_payload(password)          # validate now; the payload is rebuilt at launch
                stdin_password = password
            else:
                cmd.append(f"/p:{password}")
            del password

        # extra_args: optional space-separated xfreerdp flags from project.yaml
        extra_args = spec.params.get("extra_args")
        if extra_args:
            import shlex as _shlex
            for arg in _shlex.split(extra_args):
                lowered = arg.lower()
                if lowered == "/gfx-":
                    # FreeRDP toggles use ``-gfx`` rather than the legacy-looking ``/gfx-``.
                    # Software GDI is already requested by affected projects, so dropping the
                    # invalid token is the most portable behavior across FreeRDP 2/3.
                    continue
                if lowered.startswith("/cert:") or lowered.startswith("/cert-"):
                    # Certificate policy is compiled exactly once from the typed reviewed
                    # name and fingerprint; free-form input may not weaken or replace it.
                    continue
                if lowered.startswith(("/from-stdin", "+from-stdin", "-from-stdin")):
                    # The credential channel is owned by the adapter; free-form input cannot add or alter it.
                    continue
                if lowered in {"/gdi:sw", "/network:auto", "/timeout:30000"}:
                    # Vetted compatibility arguments are already present exactly once.
                    continue
                if lowered.startswith(("/p:", "/password:")):
                    raise TargetError(
                        "rdp extra_args must not contain password material; use password_file"
                    )
                cmd.append(arg)

        relay: TargetRelayClient | None = None
        proc: Process | None = None
        try:
            try:
                relay = TargetRelayClient.from_environment(
                    kind="rdp-direct",
                    endpoint=host,
                    destination_port=remote_port,
                )
            except TargetRelayError as exc:
                raise TargetError(str(exc)) from exc
            if relay is not None:
                cmd[1] = f"/v:127.0.0.1:{relay.local_port}"
            # The runner's HTTPS proxy is reserved for its Bedrock relay. FreeRDP
            # honors that environment and would send even the loopback /v: socket
            # toward the proxy, failing before it reaches the target relay.
            proxy_env = {
                key: None for key in (
                    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                    "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
                )
            }
            if transport == "stdin":
                proc = self._launch_rdp_over_stdin(cmd, stdin_password, proxy_env)
                stdin_password = None
            else:
                proc = self._launch(cmd, env=proxy_env, log_path=self._log_path("rdp"))
            try:
                window_id = self._wait_for_window(title, process=proc)
            except TargetError as exc:
                reason = self._client_failure_reason("rdp") if str(exc).startswith("target client exited") else ""
                if reason:
                    raise TargetError(f"{exc} ({reason})") from None
                raise
            self._focus_window(window_id)
            return TargetHandle(
                "rdp", title, window_id, proc,
                tuple(item for item in (relay,) if item is not None),
            )
        except BaseException:
            for process in (proc, relay):
                if process is not None:
                    self._terminate_process(process)
            raise

    FREERDP_PASSWORD_MAX_BYTES = 511     # client_cli_authenticate_raw reads into a 512-byte buffer
    _FREERDP_ERROR_RE = re.compile(r"ERRCONNECT_[A-Z0-9_]+")

    @classmethod
    def _stdin_password_payload(cls, password: str) -> bytes:
        """The exact bytes written to FreeRDP's stdin: the password and ONE line feed.

        FreeRDP 2.11.7 (client/common/client.c, libfreerdp/utils/passphrase.c) reads the password with raw
        ``read(0)`` calls up to the first line feed, into a 512-byte buffer.  Any extra leading line is
        taken AS the password, so the payload must be exactly one line.  Messages never contain the value.
        """
        if not isinstance(password, str) or password == "":
            raise TargetError("the saved password is empty and cannot be passed over stdin")
        if "\n" in password or "\r" in password or "\x00" in password:
            raise TargetError("the saved password cannot be passed over stdin (it contains a line break or NUL)")
        data = password.encode("utf-8")
        if len(data) > cls.FREERDP_PASSWORD_MAX_BYTES:
            raise TargetError("the saved password is too long to pass over stdin")
        return data + b"\n"

    def _client_failure_reason(self, kind: str) -> str:
        """The last ``ERRCONNECT_*`` code in the tail of the client log (a fixed token, never free text)."""
        path = self._log_path(kind)
        if not path:
            return ""
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - 16384))
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            return ""
        found = self._FREERDP_ERROR_RE.findall(text)
        return found[-1] if found else ""

    def _launch_rdp_over_stdin(self, cmd: list[str], password: str | None, proxy_env: dict) -> Process:
        """Start FreeRDP with ``/from-stdin`` and feed the password on stdin; nothing secret is in argv or env.

        ``/from-stdin`` makes the client prompt on stderr ("Password: ") and read the password from stdin when
        the server asks for NLA and none was supplied.  The launcher writes the line and closes the pipe at once
        (EOF), so a second prompt (for example after a rejected password) reads nothing and fails instead of
        waiting.  Certificate checking is unchanged: ``/cert:deny,name:...,fingerprint:...`` is in ``cmd`` and
        is evaluated before any credential is requested.  A client that exits within the probe window is a
        failure (never "up"), and the client log tail supplies the FreeRDP error code.
        """
        payload = self._stdin_password_payload(password or "")
        proc = self._launch([*cmd, "/from-stdin"], env=proxy_env,
                            log_path=self._log_path("rdp"), stdin_data=payload)
        del payload
        self._sleep(self._stdin_probe_seconds)
        code = proc.poll()
        if code is not None:
            reason = self._client_failure_reason("rdp")
            raise TargetError(f"FreeRDP exited at once with status {code}" + (f" ({reason})" if reason else "")
                              + "; see the client log in the run folder")
        return proc

    def _display_size(self) -> tuple[int, int] | None:
        """The runner display size in pixels (xdotool), or None when it cannot be measured."""
        try:
            width, height = (int(v) for v in self._run(["xdotool", "getdisplaygeometry"]).split()[:2])
        except (ValueError, OSError, TargetError, RuntimeError, subprocess.CalledProcessError):
            return None
        return (width, height) if 1 <= width <= 16384 and 1 <= height <= 16384 else None

    def window_covers_display(self, handle: TargetHandle) -> bool | None:
        """True when the window fills (about) the whole display; None when it cannot be measured."""
        try:
            geo = {}
            for line in self._run(["xdotool", "getwindowgeometry", "--shell", str(handle.window_id)]).splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    geo[key.strip().upper()] = int(value.strip())
            width, height = (int(v) for v in self._run(["xdotool", "getdisplaygeometry"]).split()[:2])
            x, y, w, h = geo["X"], geo["Y"], geo["WIDTH"], geo["HEIGHT"]
        except (KeyError, ValueError, OSError, TargetError, RuntimeError):
            return None
        return x <= 40 and y <= 40 and w * h >= 0.95 * width * height

    # --- vnc ---------------------------------------------------------------

    def _open_vnc(self, spec: TargetSpec) -> TargetHandle:
        host = spec.params.get("host")
        if not host:
            raise TargetError("vnc target requires a 'host' param")
        self._check_allowed(host, self.vnc_host_allowlist, "vnc")
        route_type = spec.params.get("route_type", "direct")
        if spec.params.get("via"):
            raise TargetError(
                "VNC jump routing is disabled for legacy via because it cannot meet the "
                "explicit-argv contract; migrate to the typed SSH jump route"
            )
        if route_type not in {"direct", "ssh-jump"}:
            raise TargetError("VNC requires either Direct or the typed SSH jump route")

        # ``host::<port>`` selects a raw TCP port (e.g. 5901); ``host`` alone uses display 0
        # (5900). An explicit ``port`` param maps to the ``::`` form.
        port_text = spec.params.get("port") or "5900"
        try:
            remote_port = int(port_text)
        except ValueError as exc:
            raise TargetError("VNC port must be numeric") from exc
        if not 1 <= remote_port <= 65535:
            raise TargetError("VNC port must be between 1 and 65535")
        destination = f"{host}::{remote_port}" if spec.params.get("port") else host

        # The viewer offers no title flag; its window title contains "TigerVNC", which the
        # window search matches. ``window`` overrides for a more specific match.
        title = spec.params.get("window") or "TigerVNC"

        cmd = ["xtigervncviewer"]
        # Password comes from the read-only secrets mount as a vncpasswd-format file; only its
        # path is passed, so the secret is never on the command line or in a screenshot.
        password_file = spec.params.get("password_file")
        if password_file:
            cmd += ["-passwd", self._secret_path(password_file)]

        tunnel: Process | None = None
        relay: TargetRelayClient | None = None
        proc: Process | None = None
        try:
            if route_type == "ssh-jump":
                jump_host = spec.params.get("jump_host")
                if not jump_host:
                    raise TargetError("VNC SSH jump route requires a jump host")
                self._check_allowed(jump_host, self.ssh_host_allowlist, "VNC SSH jump")
                known_hosts = spec.params.get("jump_known_hosts_file")
                gateway_password = spec.params.get("gateway_password_file")
                if not known_hosts:
                    raise TargetError("VNC SSH jump route requires a clone-local known-hosts reference")
                if not gateway_password:
                    raise TargetError("VNC SSH jump route requires a saved gateway password reference")
                try:
                    jump_port = int(spec.params.get("jump_port", "22"))
                except ValueError as exc:
                    raise TargetError("VNC SSH jump port must be numeric") from exc
                try:
                    relay = TargetRelayClient.from_environment(
                        kind="vnc-ssh-jump",
                        endpoint=jump_host,
                        destination_port=jump_port,
                    )
                except TargetRelayError as exc:
                    raise TargetError(str(exc)) from exc
                local_port = self._tunnel_port_allocator()
                gateway = (
                    f"{spec.params['jump_user']}@{jump_host}"
                    if spec.params.get("jump_user") else jump_host
                )
                try:
                    forward = build_ssh_local_forward_argv(
                        "ssh", gateway,
                        local_port=local_port,
                        target_host=host,
                        target_port=remote_port,
                        gateway_port=jump_port,
                        known_hosts_path=self._secret_path(known_hosts),
                        proxy_command=(
                            "python", "-m", "orchestrator.target_relay",
                            "connect-loopback", "--port", str(relay.local_port),
                        ) if relay is not None else None,
                    )
                except SshRouteError as exc:
                    raise TargetError(str(exc)) from exc
                tunnel_cmd = [
                    "sshpass", "-f", self._secret_path(gateway_password), *forward
                ]
                tunnel = self._launch(
                    tunnel_cmd, env={"SSHPASS": ""},
                    log_path=self._log_path("vnc_ssh_tunnel"),
                )
                self._wait_for_tunnel(tunnel, local_port)
                destination = f"127.0.0.1::{local_port}"
            else:
                try:
                    relay = TargetRelayClient.from_environment(
                        kind="vnc-direct",
                        endpoint=host,
                        destination_port=remote_port,
                    )
                except TargetRelayError as exc:
                    raise TargetError(str(exc)) from exc
                if relay is not None:
                    destination = f"127.0.0.1::{relay.local_port}"
            cmd.append(destination)
            proc = self._launch(cmd, env=None, log_path=self._log_path("vnc"))
            window_id = self._wait_for_window(title, process=proc)
            self._focus_window(window_id)
            return TargetHandle(
                "vnc", title, window_id, proc,
                tuple(item for item in (tunnel, relay) if item is not None),
            )
        except BaseException:
            for process in (proc, tunnel, relay):
                if process is not None:
                    self._terminate_process(process)
            raise

    # --- allowlist / secrets ----------------------------------------------

    @staticmethod
    def _check_allowed(host: str, allowlist: list[str], kind: str) -> None:
        if host not in allowlist:
            raise HostNotAllowedError(
                f"{kind} host {host!r} is not in the allowlist {allowlist!r}; refusing to connect"
            )

    def _secret_path(self, name: str) -> str:
        """Resolve a secret file path under ``secrets_dir``, guarding against traversal."""
        base = os.path.abspath(self.secrets_dir)
        path = os.path.abspath(os.path.join(base, name))
        if os.path.commonpath([base, path]) != base:
            raise TargetError(f"secret {name!r} escapes the secrets directory")
        if not os.path.exists(path):
            raise TargetError(f"secret {name!r} not found under {self.secrets_dir!r}")
        return path

    def _log_path(self, kind: str) -> str | None:
        """Path under ``log_dir`` to capture a client's stdout+stderr, or None if unset."""
        if not self.log_dir:
            return None
        return os.path.join(self.log_dir, f"{kind}_client.log")

    def _read_secret(self, name: str) -> str:
        with open(self._secret_path(name), "r", encoding="utf-8") as fh:
            return fh.read().strip()

    @staticmethod
    def _allocate_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    @staticmethod
    def _probe_loopback_port(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.15):
                return True
        except OSError:
            return False

    def _wait_for_tunnel(self, process: Process, port: int) -> None:
        waited = 0.0
        while waited <= self.window_wait_seconds:
            if process.poll() is not None:
                raise TargetError("VNC SSH local-forward process exited before readiness")
            if self._tunnel_probe("127.0.0.1", port):
                return
            self._sleep(self.poll_interval)
            waited += self.poll_interval
        raise TargetError("VNC SSH local forward did not become ready within the bounded timeout")

    # --- window helpers ----------------------------------------------------

    def _find_window(self, name: str) -> str | None:
        """Return the first matching window id for ``name``, or None if none match."""
        try:
            out = self._run(["xdotool", "search", "--name", name]).strip()
        except subprocess.CalledProcessError:
            # xdotool exits non-zero when nothing matches; treat as "not yet".
            return None
        ids = [line for line in out.splitlines() if line.strip()]
        return ids[0] if ids else None

    def _find_process_window(self, process: Process) -> str | None:
        """Return a visible window owned by ``process``, independent of its title."""
        try:
            out = self._run(
                ["xdotool", "search", "--onlyvisible", "--pid", str(process.pid)]
            ).strip()
        except subprocess.CalledProcessError:
            return None
        ids = [line for line in out.splitlines() if line.strip()]
        return ids[0] if ids else None

    def _wait_for_window(
        self,
        name: str,
        *,
        timeout: float | None = None,
        process: Process | None = None,
    ) -> str:
        """Poll for the expected title or a visible window owned by ``process``."""
        deadline = self.window_wait_seconds if timeout is None else timeout
        waited = 0.0
        while True:
            window_id = self._find_window(name)
            if window_id is None and process is not None:
                window_id = self._find_process_window(process)
            if window_id is not None:
                return window_id
            if process is not None:
                returncode = process.poll()
                if returncode is not None:
                    raise TargetError(
                        f"target client exited with status {returncode} before its window appeared"
                    )
            if waited >= deadline:
                raise WindowNotFoundError(
                    f"window {name!r} did not appear within {deadline:g}s"
                )
            self._sleep(self.poll_interval)
            waited += self.poll_interval

    def focus(self, name: str) -> str | None:
        """Raise and activate the window titled ``name`` (xdotool search + activate)."""
        window_id = self._find_window(name)
        if window_id is None:
            return None
        self._focus_window(window_id)
        return window_id

    def _focus_window(self, window_id: str) -> None:
        """Raise and activate an already discovered window id."""
        self._run(["xdotool", "windowactivate", window_id])
        self._run(["xdotool", "windowraise", window_id])

    # --- pre-input foreground verification (security D2) -------------------

    def foreground_state(self, handle: TargetHandle | None) -> dict:
        """Cheap, NON-MODEL X11 snapshot of what currently owns keyboard input.

        Called immediately before a credential is typed.  It answers, without contacting any
        model and without taking a screenshot: which window has input focus, what that window
        is called, and whether the run-owned client window is still mapped.

        Values are ``None`` when they could not be determined.  Callers MUST treat anything
        they cannot positively confirm as unsafe.  Ordinary "xdotool found nothing" cases are
        reported as data, not raised, so the caller decides the policy.

        Scope limitation: this describes the OUTER window on the runner's own X display (the
        display this adapter drives).  It cannot say anything about the authenticity of a
        remote dialog drawn inside that window.
        """
        expected_id = getattr(handle, "window_id", None) if handle is not None else None
        expected_name = getattr(handle, "window_name", None) if handle is not None else None
        state: dict = {
            "expected_id": expected_id,
            "expected_name": expected_name,
            "focused_id": None,
            "focused_name": None,
            "handle_present": None,
        }

        try:
            raw = self._run(["xdotool", "getactivewindow"]).strip()
        except Exception:
            raw = ""
        focused_id = next((line.strip() for line in raw.splitlines() if line.strip()), None)
        if focused_id:
            state["focused_id"] = focused_id
            try:
                state["focused_name"] = self._run(
                    ["xdotool", "getwindowname", focused_id]
                ).strip()
            except Exception:
                state["focused_name"] = None

        if expected_id is not None:
            # getwindowname fails for an unmapped/destroyed id, so this is an existence probe
            # for the exact window this run opened -- not merely "some window with that title".
            try:
                self._run(["xdotool", "getwindowname", str(expected_id)])
                state["handle_present"] = True
            except Exception:
                state["handle_present"] = False
        return state

    # --- cleanup -----------------------------------------------------------

    def close_target(self, handle: TargetHandle) -> None:
        """Close the target window and terminate its client process (no orphans)."""
        if handle.window_id is not None:
            try:
                self._run(["xdotool", "windowclose", handle.window_id])
            except subprocess.CalledProcessError:
                pass  # window may already be gone

        proc = handle.process
        if proc is not None:
            self._terminate_process(proc)
        for auxiliary in reversed(handle.auxiliary_processes):
            self._terminate_process(auxiliary)

    @staticmethod
    def _terminate_process(proc: Process) -> None:
        if proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
