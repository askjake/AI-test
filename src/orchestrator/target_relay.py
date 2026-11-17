"""Authenticated destination-locked relay for approved runner target traffic.

Linux Docker bridges commonly cannot traverse routes installed by a host VPN even
though the host itself can reach the target.  This module keeps the runner off host
networking: a short-lived host listener accepts only a per-run credential from the
Docker bridge subnet and forwards to one pinned project-derived endpoint and port.

Inside the runner, :class:`TargetRelayClient` exposes a loopback-only TCP socket to
the ordinary VNC/SSH client.  The local proxy authenticates each connection to the
host listener.  Neither side accepts a caller-selected destination.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
from typing import Callable, Iterator, Sequence

import yaml

from orchestrator.projects import (
    RDP_CHAIN,
    ChainProjectError,
    discover_projects,
    explain_chain_project_error,
    project_slug,
    rdp_chain_outer_hop,
)


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PROTOCOL = "OC-TARGET-RELAY/1"


class TargetRelayError(RuntimeError):
    """The approved target relay contract is absent, invalid, or unavailable."""


@dataclass(frozen=True)
class ProjectTransport:
    kind: str
    endpoint: str
    port: int


@dataclass(frozen=True)
class TargetRelayLease:
    kind: str
    endpoint: str
    destination_port: int
    bind_host: str
    port: int
    client_network: str
    token: str


def _port(value: object, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise TargetRelayError(f"{label} must be numeric") from exc
    if not 1 <= result <= 65535:
        raise TargetRelayError(f"{label} must be between 1 and 65535")
    return result


def _host(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HOST_RE.fullmatch(value):
        raise TargetRelayError(f"{label} is invalid")
    return value


def describe_project_transport(
    project_name: str,
    *,
    specs_root: str | None = None,
) -> ProjectTransport | None:
    """Return the exact host-reachable transport for one RDP or VNC project.

    Direct RDP/VNC relays the reviewed target endpoint.  VNC-over-SSH relays only
    the approved jump-host SSH socket; the existing strict OpenSSH local forward
    still owns the onward target connection and host-key verification.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", project_name):
        raise TargetRelayError("project name is invalid")
    if specs_root is not None:
        root = Path(specs_root).resolve()
        project_path = (root / project_name).resolve()
        try:
            project_path.relative_to(root)
        except ValueError as exc:
            raise TargetRelayError("project path escapes the specs root") from exc
        config_path = project_path / "project.yaml"
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise TargetRelayError("the exact project configuration could not be read") from exc
        if not isinstance(raw, dict):
            raise TargetRelayError("the exact project configuration is invalid")
        raw_target = raw.get("target")
        if isinstance(raw_target, dict) and raw_target.get("type") not in {None, "rdp", "vnc", RDP_CHAIN}:
            return None
    matches = [item for item in discover_projects(specs_root) if project_slug(item) == project_name]
    if len(matches) != 1:
        detail = None
        if specs_root is not None:
            detail = explain_chain_project_error(str(Path(specs_root).resolve() / project_name), str(Path(specs_root).resolve()))
        raise TargetRelayError(detail or "the exact project could not be resolved")
    config = matches[0].config
    target = config.target
    if target.type == RDP_CHAIN:
        # Nested chain: the runner connects ONLY to hop 1, through the same authenticated relay as
        # plain direct RDP.  The logical destination (host/port) stays hop 1's reviewed endpoint;
        # certificate name/fingerprint checks are unchanged and never bound to the relay socket.
        try:
            first = rdp_chain_outer_hop(target)
        except ChainProjectError as exc:
            raise TargetRelayError(f"rdp-chain project transport is invalid: {exc}") from exc
        endpoint = _host(first.host, "RDP chain hop 1 endpoint")
        if endpoint not in config.rdp_host_allowlist:
            raise TargetRelayError("RDP chain hop 1 endpoint is outside the effective allowlist")
        exposed = sorted({hop.host for hop in target.hops[1:] if hop.host != endpoint and hop.host in config.rdp_host_allowlist})
        if exposed:
            raise TargetRelayError("RDP chain hop 2 or later must not be a direct runner destination")
        return ProjectTransport(
            kind="rdp-direct",
            endpoint=endpoint,
            port=_port(first.port, "RDP chain hop 1 port"),
        )
    if target.type == "rdp":
        if target.params.get("route_type", "direct") != "direct":
            raise TargetRelayError("RDP project has an unsupported route type")
        endpoint = _host(target.params.get("host"), "RDP endpoint")
        if endpoint not in config.rdp_host_allowlist:
            raise TargetRelayError("RDP endpoint is outside the effective allowlist")
        return ProjectTransport(
            kind="rdp-direct",
            endpoint=endpoint,
            port=_port(target.params.get("port") or 3389, "RDP port"),
        )
    if target.type != "vnc":
        return None
    route_type = target.params.get("route_type", "direct")
    if route_type == "direct":
        endpoint = _host(target.params.get("host"), "VNC endpoint")
        if endpoint not in config.vnc_host_allowlist:
            raise TargetRelayError("VNC endpoint is outside the effective allowlist")
        return ProjectTransport(
            kind="vnc-direct",
            endpoint=endpoint,
            port=_port(target.params.get("port") or 5900, "VNC port"),
        )
    if route_type == "ssh-jump":
        endpoint = _host(target.params.get("jump_host"), "VNC jump host")
        if endpoint not in config.ssh_host_allowlist:
            raise TargetRelayError("VNC jump host is outside the effective SSH allowlist")
        return ProjectTransport(
            kind="vnc-ssh-jump",
            endpoint=endpoint,
            port=_port(target.params.get("jump_port") or 22, "VNC jump-host port"),
        )
    raise TargetRelayError("VNC project has an unsupported route type")


def resolve_transport_ipv4(
    endpoint: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    endpoint = _host(endpoint, "target relay endpoint")
    try:
        answers = resolver(endpoint, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise TargetRelayError("target relay endpoint could not be resolved on the host") from exc
    addresses: set[str] = set()
    for answer in answers:
        try:
            address = ipaddress.IPv4Address(answer[4][0])
        except (IndexError, TypeError, ipaddress.AddressValueError):
            continue
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            continue
        addresses.add(str(address))
    if not addresses:
        raise TargetRelayError("target relay endpoint returned no usable IPv4 address")
    return tuple(sorted(addresses, key=ipaddress.IPv4Address))


def _connect_address(addresses: Sequence[str], port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for value in addresses:
        try:
            parsed = ipaddress.IPv4Address(value)
            if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
                continue
            return socket.create_connection((str(parsed), port), timeout=timeout)
        except ipaddress.AddressValueError:
            continue
        except OSError as exc:
            last_error = exc
    raise TargetRelayError("approved target connection failed") from last_error


def _read_line(stream: socket.socket, *, limit: int = 256) -> bytes:
    data = bytearray()
    while len(data) < limit:
        chunk = stream.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)
    raise TargetRelayError("target relay returned an invalid handshake")


def _copy_bidirectional(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while sockets:
        readable, _, exceptional = select.select(sockets, [], sockets, 300)
        if exceptional or not readable:
            break
        for source in readable:
            destination = right if source is left else left
            try:
                data = source.recv(65536)
                if not data:
                    return
                destination.sendall(data)
            except OSError:
                return


class _HostRelayServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        *,
        client_network: str,
        token: str,
        connector: Callable[[], socket.socket],
    ) -> None:
        self.client_network = ipaddress.IPv4Network(client_network, strict=False)
        self.token = token
        self.connector = connector
        super().__init__(address, _HostRelayHandler, bind_and_activate=True)


class _HostRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _HostRelayServer):
            return
        try:
            peer = ipaddress.IPv4Address(self.client_address[0])
            if peer not in server.client_network:
                return
            request = _read_line(self.request)
            expected = f"{_PROTOCOL} {server.token}\n".encode("ascii")
            if not hmac.compare_digest(request, expected):
                self.request.sendall(b"DENIED\n")
                return
            upstream = server.connector()
        except (OSError, TargetRelayError, UnicodeError):
            try:
                self.request.sendall(b"ERROR\n")
            except OSError:
                pass
            return
        try:
            self.request.sendall(b"OK\n")
            self.request.settimeout(300)
            upstream.settimeout(300)
            _copy_bidirectional(self.request, upstream)
        finally:
            upstream.close()


class DestinationLockedTargetRelay:
    """Host relay bound to one bridge and one pinned upstream socket."""

    def __init__(
        self,
        *,
        engine: str,
        transport: ProjectTransport,
        addresses: Sequence[str],
        connect_timeout: float = 8.0,
        connector: Callable[[], socket.socket] | None = None,
    ) -> None:
        from orchestrator.bedrock_relay import inspect_bridge_contract

        bridge = inspect_bridge_contract(engine)
        gateway = str(ipaddress.IPv4Address(bridge.gateway))
        network = ipaddress.IPv4Network(bridge.subnet, strict=False)
        if ipaddress.IPv4Address(gateway) not in network:
            raise TargetRelayError("bridge gateway is outside the client network")
        token = secrets.token_urlsafe(32)
        if not _TOKEN_RE.fullmatch(token):
            raise TargetRelayError("generated target relay credential is invalid")
        destination_port = _port(transport.port, "target relay destination port")
        pinned_values: list[str] = []
        for value in addresses:
            try:
                address = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError as exc:
                raise TargetRelayError("target relay received an invalid pinned address") from exc
            if address.is_unspecified or address.is_multicast or address.is_loopback:
                raise TargetRelayError("target relay received an unsafe pinned address")
            text = str(address)
            if text not in pinned_values:
                pinned_values.append(text)
        pinned = tuple(pinned_values)
        if not pinned:
            raise TargetRelayError("target relay requires at least one pinned address")
        if connector is None:
            connector = lambda: _connect_address(pinned, destination_port, connect_timeout)
        self._server = _HostRelayServer(
            (gateway, 0),
            client_network=str(network),
            token=token,
            connector=connector,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.lease = TargetRelayLease(
            kind=transport.kind,
            endpoint=transport.endpoint,
            destination_port=destination_port,
            bind_host=gateway,
            port=int(self._server.server_address[1]),
            client_network=str(network),
            token=token,
        )

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@contextmanager
def target_connect_relay(
    engine: str,
    *,
    transport: ProjectTransport,
    addresses: Sequence[str],
) -> Iterator[TargetRelayLease]:
    """Lease one destination-locked host relay for a single runner lifetime."""
    relay = DestinationLockedTargetRelay(
        engine=engine,
        transport=transport,
        addresses=addresses,
    )
    try:
        yield relay.lease
    finally:
        relay.close()


class _LocalRelayServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], *, connector: Callable[[], socket.socket]) -> None:
        self.connector = connector
        super().__init__(address, _LocalRelayHandler, bind_and_activate=True)


class _LocalRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _LocalRelayServer):
            return
        try:
            upstream = server.connector()
        except (OSError, TargetRelayError):
            return
        try:
            self.request.settimeout(300)
            upstream.settimeout(300)
            _copy_bidirectional(self.request, upstream)
        finally:
            upstream.close()


class TargetRelayClient:
    """Loopback-only runner proxy implementing the target process cleanup protocol."""

    pid = -1

    def __init__(self, *, relay_host: str, relay_port: int, token: str) -> None:
        try:
            host = str(ipaddress.IPv4Address(relay_host))
        except ipaddress.AddressValueError as exc:
            raise TargetRelayError("target relay host must be a literal IPv4 address") from exc
        port = _port(relay_port, "target relay port")
        if not _TOKEN_RE.fullmatch(token):
            raise TargetRelayError("target relay credential is invalid")

        def connect() -> socket.socket:
            connection = socket.create_connection((host, port), timeout=8)
            try:
                connection.sendall(f"{_PROTOCOL} {token}\n".encode("ascii"))
                if _read_line(connection, limit=32) != b"OK\n":
                    raise TargetRelayError("authenticated target relay rejected the connection")
                return connection
            except BaseException:
                connection.close()
                raise

        self._server = _LocalRelayServer(("127.0.0.1", 0), connector=connect)
        self.local_port = int(self._server.server_address[1])
        self._closed = False
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @classmethod
    def from_environment(
        cls,
        *,
        kind: str,
        endpoint: str,
        destination_port: int,
    ) -> "TargetRelayClient | None":
        values = {
            "kind": os.environ.get("ORCHESTRATOR_TARGET_RELAY_KIND", ""),
            "endpoint": os.environ.get("ORCHESTRATOR_TARGET_RELAY_ENDPOINT", ""),
            "destination_port": os.environ.get("ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT", ""),
            "host": os.environ.get("ORCHESTRATOR_TARGET_RELAY_HOST", ""),
            "port": os.environ.get("ORCHESTRATOR_TARGET_RELAY_PORT", ""),
            "token": os.environ.get("ORCHESTRATOR_TARGET_RELAY_TOKEN", ""),
        }
        if not any(values.values()):
            return None
        if not all(values.values()):
            raise TargetRelayError("target relay environment contract is incomplete")
        if values["kind"] != kind or values["endpoint"] != endpoint:
            raise TargetRelayError("target relay is bound to a different project transport")
        if _port(values["destination_port"], "target relay destination port") != destination_port:
            raise TargetRelayError("target relay destination port differs from the project")
        return cls(
            relay_host=values["host"],
            relay_port=_port(values["port"], "target relay port"),
            token=values["token"],
        )

    def poll(self) -> int | None:
        return 0 if self._closed else None

    def terminate(self) -> None:
        self.close()

    def kill(self) -> None:
        self.close()

    def wait(self, timeout: float | None = None) -> int:
        self._thread.join(timeout=timeout)
        return 0

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _bridge_standard_io(port: int) -> int:
    """Carry one OpenSSH ProxyCommand stream through a loopback relay client."""
    port = _port(port, "loopback proxy port")
    connection = socket.create_connection(("127.0.0.1", port), timeout=8)
    stdin_fd = sys.stdin.buffer.fileno()
    stdout_fd = sys.stdout.buffer.fileno()
    try:
        connection.settimeout(None)
        input_open = True
        while True:
            readers: list[object] = [connection]
            if input_open:
                readers.append(stdin_fd)
            readable, _, exceptional = select.select(readers, [], [connection], 300)
            if exceptional or not readable:
                return 1
            if connection in readable:
                data = connection.recv(65536)
                if not data:
                    return 0
                os.write(stdout_fd, data)
            if input_open and stdin_fd in readable:
                data = os.read(stdin_fd, 65536)
                if data:
                    connection.sendall(data)
                else:
                    input_open = False
                    connection.shutdown(socket.SHUT_WR)
    finally:
        connection.close()


def _write_state(path: Path, lease: TargetRelayLease) -> None:
    if path.is_symlink() or not path.is_file():
        raise TargetRelayError("target relay state path must be a pre-created regular file")
    state = path.stat()
    if stat.S_IMODE(state.st_mode) != 0o600 or state.st_uid != os.getuid() or state.st_nlink != 1:
        raise TargetRelayError("target relay state path has unsafe mode, ownership, or links")
    document = {
        "kind": lease.kind,
        "endpoint": lease.endpoint,
        "destination_port": lease.destination_port,
        "bind_host": lease.bind_host,
        "port": lease.port,
        "client_network": lease.client_network,
        "token": lease.token,
    }
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    describe = subparsers.add_parser("describe")
    describe.add_argument("--project", required=True)
    describe.add_argument("--specs-root", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--engine", required=True)
    serve.add_argument("--kind", required=True)
    serve.add_argument("--endpoint", required=True)
    serve.add_argument("--destination-port", required=True, type=int)
    serve.add_argument("--address", action="append", required=True)
    serve.add_argument("--state-file", required=True)
    connect_loopback = subparsers.add_parser("connect-loopback")
    connect_loopback.add_argument("--port", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.action == "connect-loopback":
            return _bridge_standard_io(args.port)
        if args.action == "describe":
            transport = describe_project_transport(args.project, specs_root=args.specs_root)
            if transport is not None:
                print(transport.kind)
                print(transport.endpoint)
                print(transport.port)
            return 0

        transport = ProjectTransport(
            kind=args.kind,
            endpoint=_host(args.endpoint, "target relay endpoint"),
            port=_port(args.destination_port, "target relay destination port"),
        )
        relay = DestinationLockedTargetRelay(
            engine=args.engine,
            transport=transport,
            addresses=args.address,
        )
        _write_state(Path(args.state_file), relay.lease)
        print("[target-relay] authenticated destination-locked transport ready", flush=True)
        stop = threading.Event()
        parent_pid = os.getppid()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda _signum, _frame: stop.set())
        while not stop.wait(1):
            if os.getppid() != parent_pid:
                break
        relay.close()
        return 0
    except (OSError, TargetRelayError) as exc:
        print(f"[target-relay] FATAL: {exc}", file=os.sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
