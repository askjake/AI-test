"""Authenticated, destination-locked host relay for Bedrock runner traffic.

Linux Docker bridges can lose routes supplied by a host VPN even when the host
itself can reach Bedrock.  The runner must not use host networking because its
short-lived firewall bootstrap owns ``NET_ADMIN``.  This module instead exposes
one ephemeral HTTP CONNECT listener on the bridge gateway.  It accepts only an
unguessable per-run credential and the exact regional Bedrock runtime authority;
TLS remains end-to-end between botocore and AWS.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import ssl
import stat
import subprocess
import threading
from typing import Callable, Iterator, Sequence
from urllib.parse import quote, unquote, urlsplit
from urllib.request import proxy_bypass


class BedrockRelayError(RuntimeError):
    """The bounded host relay could not be established safely."""


@dataclass(frozen=True)
class BridgeContract:
    gateway: str
    subnet: str


@dataclass(frozen=True)
class BedrockRelayLease:
    endpoint: str
    bind_host: str
    port: int
    client_network: str
    proxy_url: str


def _ipv4(value: str, label: str, *, global_only: bool = False) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise BedrockRelayError(f"{label} must be a literal IPv4 address") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise BedrockRelayError(f"{label} is not an acceptable IPv4 address")
    if global_only and not address.is_global:
        raise BedrockRelayError(f"{label} must be globally routable")
    return str(address)


def inspect_bridge_contract(
    engine: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> BridgeContract:
    """Return the default bridge gateway/subnet used by ``--network=bridge``."""
    result = runner(
        [engine, "network", "inspect", "bridge"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        shell=False,
    )
    if result.returncode != 0:
        raise BedrockRelayError("container engine bridge network could not be inspected")
    try:
        document = json.loads(result.stdout)
        configurations = document[0]["IPAM"]["Config"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise BedrockRelayError("container engine returned an invalid bridge contract") from exc
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        gateway_text = configuration.get("Gateway")
        subnet_text = configuration.get("Subnet")
        if not isinstance(gateway_text, str) or not isinstance(subnet_text, str):
            continue
        try:
            network = ipaddress.IPv4Network(subnet_text, strict=False)
            gateway = ipaddress.IPv4Address(_ipv4(gateway_text, "bridge gateway"))
        except (BedrockRelayError, ipaddress.AddressValueError):
            continue
        if gateway in network:
            return BridgeContract(gateway=str(gateway), subnet=str(network))
    raise BedrockRelayError("container engine bridge has no usable IPv4 gateway")


def _resolved_ipv4(host: str) -> tuple[str, ...]:
    try:
        answers = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise BedrockRelayError("configured host proxy could not be resolved") from exc
    values: set[str] = set()
    for answer in answers:
        try:
            values.add(_ipv4(answer[4][0], "host proxy address"))
        except (IndexError, TypeError, BedrockRelayError):
            continue
    if not values:
        raise BedrockRelayError("configured host proxy returned no usable IPv4 address")
    return tuple(sorted(values, key=ipaddress.IPv4Address))


@dataclass(frozen=True)
class _UpstreamProxy:
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    authorization: str | None


def _host_upstream_proxy(endpoint: str) -> _UpstreamProxy | None:
    if proxy_bypass(endpoint):
        return None
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if not raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BedrockRelayError("host HTTPS proxy URL is unsupported")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise BedrockRelayError("host HTTPS proxy URL contains unsupported components")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise BedrockRelayError("host HTTPS proxy port is invalid") from exc
    authorization = None
    if parsed.username is not None:
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
        authorization = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
    return _UpstreamProxy(
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=port,
        addresses=_resolved_ipv4(parsed.hostname),
        authorization=authorization,
    )


def _connect_address(addresses: Sequence[str], port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            last_error = exc
    raise BedrockRelayError("approved upstream connection failed") from last_error


def _read_headers(stream: socket.socket, *, limit: int = 16384) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = stream.recv(min(4096, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) >= limit:
            raise BedrockRelayError("upstream proxy response exceeded the header limit")
    if b"\r\n\r\n" not in data:
        raise BedrockRelayError("upstream proxy returned an incomplete response")
    return bytes(data)


def _connect_via_proxy(proxy: _UpstreamProxy, endpoint: str, timeout: float) -> socket.socket:
    connection = _connect_address(proxy.addresses, proxy.port, timeout)
    try:
        if proxy.scheme == "https":
            connection = ssl.create_default_context().wrap_socket(
                connection,
                server_hostname=proxy.hostname,
            )
        lines = [
            f"CONNECT {endpoint}:443 HTTP/1.1",
            f"Host: {endpoint}:443",
            "Proxy-Connection: Keep-Alive",
        ]
        if proxy.authorization:
            lines.append(f"Proxy-Authorization: {proxy.authorization}")
        connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        response = _read_headers(connection)
        status_line = response.split(b"\r\n", 1)[0].split()
        if len(status_line) < 2 or not status_line[1].isdigit() or not status_line[1].startswith(b"2"):
            raise BedrockRelayError("host HTTPS proxy rejected the approved Bedrock tunnel")
        return connection
    except BaseException:
        connection.close()
        raise


class _RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        *,
        endpoint: str,
        client_network: str,
        authorization: str,
        connector: Callable[[], socket.socket],
    ) -> None:
        self.endpoint = endpoint
        self.client_network = ipaddress.IPv4Network(client_network, strict=False)
        self.authorization = authorization
        self.connector = connector
        super().__init__(address, _RelayHandler, bind_and_activate=True)


class _RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OrchestratorCookieRelay"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _deny(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        server = self.server
        assert isinstance(server, _RelayServer)
        try:
            peer = ipaddress.IPv4Address(self.client_address[0])
        except ipaddress.AddressValueError:
            self._deny(403)
            return
        authorization = self.headers.get_all("Proxy-Authorization") or []
        content_length = self.headers.get("Content-Length")
        if (
            peer not in server.client_network
            or self.path != f"{server.endpoint}:443"
            or len(authorization) != 1
            or not hmac.compare_digest(authorization[0], server.authorization)
            or self.headers.get("Transfer-Encoding") is not None
            or (content_length not in {None, "0"})
        ):
            self._deny(403)
            return
        try:
            upstream = server.connector()
        except (OSError, BedrockRelayError):
            self._deny(502)
            return
        try:
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.connection.settimeout(300)
            upstream.settimeout(300)
            sockets = [self.connection, upstream]
            while sockets:
                readable, _, exceptional = select.select(sockets, [], sockets, 300)
                if exceptional or not readable:
                    break
                for source in readable:
                    destination = upstream if source is self.connection else self.connection
                    try:
                        data = source.recv(65536)
                    except (OSError, ssl.SSLWantReadError):
                        sockets = []
                        break
                    if not data:
                        sockets = []
                        break
                    try:
                        destination.sendall(data)
                    except OSError:
                        sockets = []
                        break
        finally:
            upstream.close()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._deny(405)

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_HEAD = do_GET


class BedrockConnectRelay:
    """Lifecycle wrapper for one destination-locked authenticated relay."""

    def __init__(
        self,
        *,
        endpoint: str,
        addresses: Sequence[str],
        bridge: BridgeContract,
        connect_timeout: float = 8.0,
        connector: Callable[[], socket.socket] | None = None,
    ) -> None:
        if not endpoint or any(character in endpoint for character in "\0\r\n/:@"):
            raise BedrockRelayError("Bedrock relay endpoint is invalid")
        pinned = tuple(dict.fromkeys(_ipv4(value, "Bedrock address", global_only=True) for value in addresses))
        if not pinned:
            raise BedrockRelayError("Bedrock relay requires at least one pinned address")
        gateway = _ipv4(bridge.gateway, "bridge gateway")
        try:
            client_network = ipaddress.IPv4Network(bridge.subnet, strict=False)
        except ipaddress.AddressValueError as exc:
            raise BedrockRelayError("bridge client network is invalid") from exc
        if ipaddress.IPv4Address(gateway) not in client_network:
            raise BedrockRelayError("bridge gateway is outside the client network")
        token = secrets.token_urlsafe(32)
        username = "runner"
        authorization = "Basic " + base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
        if connector is None:
            host_proxy = _host_upstream_proxy(endpoint)
            if host_proxy is None:
                connector = lambda: _connect_address(pinned, 443, connect_timeout)
            else:
                connector = lambda: _connect_via_proxy(host_proxy, endpoint, connect_timeout)
        self._server = _RelayServer(
            (gateway, 0),
            endpoint=endpoint,
            client_network=str(client_network),
            authorization=authorization,
            connector=connector,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        port = int(self._server.server_address[1])
        self.lease = BedrockRelayLease(
            endpoint=endpoint,
            bind_host=gateway,
            port=port,
            client_network=str(client_network),
            proxy_url=f"http://{username}:{quote(token, safe='')}@{gateway}:{port}",
        )

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> BedrockRelayLease:
        return self.lease

    def __exit__(self, *_exc: object) -> None:
        self.close()


@contextmanager
def bedrock_connect_relay(
    engine: str,
    *,
    endpoint: str,
    addresses: Sequence[str],
) -> Iterator[BedrockRelayLease]:
    bridge = inspect_bridge_contract(engine)
    relay = BedrockConnectRelay(endpoint=endpoint, addresses=addresses, bridge=bridge)
    try:
        yield relay.lease
    finally:
        relay.close()


def _write_state(path: Path, lease: BedrockRelayLease) -> None:
    if path.is_symlink() or not path.is_file():
        raise BedrockRelayError("relay state path must be a pre-created regular file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise BedrockRelayError("relay state path must have mode 0600")
    if path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1:
        raise BedrockRelayError("relay state path has unsafe ownership or links")
    document = {
        "endpoint": lease.endpoint,
        "bind_host": lease.bind_host,
        "port": lease.port,
        "client_network": lease.client_network,
        "proxy_url": lease.proxy_url,
    }
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--address", action="append", required=True)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args(argv)
    stop = threading.Event()
    parent_pid = os.getppid()
    try:
        bridge = inspect_bridge_contract(args.engine)
        relay = BedrockConnectRelay(
            endpoint=args.endpoint,
            addresses=args.address,
            bridge=bridge,
        )
        _write_state(Path(args.state_file), relay.lease)
        print("[relay] authenticated destination-locked Bedrock tunnel ready", flush=True)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda _signum, _frame: stop.set())
        while not stop.wait(1):
            if os.getppid() != parent_pid:
                break
        relay.close()
        return 0
    except (BedrockRelayError, OSError) as exc:
        print(f"[relay] FATAL: {exc}", file=os.sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
