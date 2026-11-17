"""Security and lifecycle tests for the bounded host-side Bedrock relay."""
from __future__ import annotations

import base64
import json
import socket
import subprocess
import threading

import pytest

from orchestrator.bedrock_relay import (
    BedrockConnectRelay,
    BedrockRelayError,
    BridgeContract,
    _RelayServer,
    inspect_bridge_contract,
)


ENDPOINT = "bedrock-runtime.us-west-2.amazonaws.com"


def test_bridge_contract_uses_exact_engine_argv_and_validates_gateway():
    observed = {}

    def runner(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps([
                {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}]}}
            ]),
            stderr="",
        )

    contract = inspect_bridge_contract("/usr/bin/docker", runner=runner)
    assert contract == BridgeContract(gateway="172.17.0.1", subnet="172.17.0.0/16")
    assert observed["argv"] == ["/usr/bin/docker", "network", "inspect", "bridge"]
    assert observed["kwargs"]["shell"] is False


@pytest.mark.parametrize(
    "document",
    [
        "not-json",
        "[]",
        '[{"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"127.0.0.1"}]}}]',
        '[{"IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.17.0.1"}]}}]',
    ],
)
def test_bridge_contract_fails_closed_on_invalid_engine_data(document):
    def runner(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=document, stderr="")

    with pytest.raises(BedrockRelayError):
        inspect_bridge_contract("docker", runner=runner)


def _relay_server(connector, authorization: str) -> tuple[_RelayServer, threading.Thread]:
    server = _RelayServer(
        ("127.0.0.1", 0),
        endpoint=ENDPOINT,
        client_network="127.0.0.0/8",
        authorization=authorization,
        connector=connector,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _response(client: socket.socket) -> bytes:
    value = bytearray()
    while b"\r\n\r\n" not in value:
        value.extend(client.recv(4096))
    return bytes(value)


def test_relay_accepts_only_authenticated_exact_connect_and_tunnels_bytes():
    expected = "Basic " + base64.b64encode(b"runner:secret").decode("ascii")
    upstream, observer = socket.socketpair()
    server, thread = _relay_server(lambda: upstream, expected)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        request = (
            f"CONNECT {ENDPOINT}:443 HTTP/1.1\r\n"
            f"Host: {ENDPOINT}:443\r\n"
            f"Proxy-Authorization: {expected}\r\n\r\n"
        )
        client.sendall(request.encode("ascii"))
        assert _response(client).startswith(b"HTTP/1.1 200")
        client.sendall(b"client-to-bedrock")
        assert observer.recv(64) == b"client-to-bedrock"
        observer.sendall(b"bedrock-to-client")
        assert client.recv(64) == b"bedrock-to-client"
    finally:
        client.close()
        observer.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    ("authority", "authorization"),
    [
        ("api.anthropic.com:443", "valid"),
        (f"{ENDPOINT}:80", "valid"),
        (f"{ENDPOINT}:443", "invalid"),
        (f"{ENDPOINT}:443", "duplicate"),
    ],
)
def test_relay_rejects_wrong_destination_port_or_credential(authority, authorization):
    expected = "Basic " + base64.b64encode(b"runner:secret").decode("ascii")
    called = []
    server, thread = _relay_server(lambda: called.append(True), expected)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        headers = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
        ]
        if authorization == "valid":
            headers.append(f"Proxy-Authorization: {expected}")
        elif authorization == "invalid":
            headers.append("Proxy-Authorization: Basic aW52YWxpZA==")
        else:
            headers.extend((f"Proxy-Authorization: {expected}", f"Proxy-Authorization: {expected}"))
        client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        assert _response(client).startswith(b"HTTP/1.1 403")
        assert called == []
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_relay_rejects_non_connect_methods_without_opening_upstream():
    called = []
    server, thread = _relay_server(lambda: called.append(True), "Basic expected")
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        client.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert _response(client).startswith(b"HTTP/1.1 405")
        assert called == []
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_relay_constructor_rejects_private_or_malformed_bedrock_addresses():
    bridge = BridgeContract(gateway="172.17.0.1", subnet="172.17.0.0/16")
    for address in ("127.0.0.1", "10.0.0.1", "224.0.0.1", "not-an-ip"):
        with pytest.raises(BedrockRelayError):
            BedrockConnectRelay(
                endpoint=ENDPOINT,
                addresses=[address],
                bridge=bridge,
                connector=lambda: socket.socket(),
            )


def test_relay_state_never_uses_a_predictable_credential(monkeypatch):
    class FakeServer:
        server_address = ("172.17.0.1", 45678)

        def serve_forever(self):
            return None

        def shutdown(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setattr("orchestrator.bedrock_relay.secrets.token_urlsafe", lambda _n: "unique-token")
    monkeypatch.setattr("orchestrator.bedrock_relay._RelayServer", lambda *_a, **_kw: FakeServer())
    bridge = BridgeContract(gateway="172.17.0.1", subnet="172.17.0.0/16")
    relay = BedrockConnectRelay(
        endpoint=ENDPOINT,
        addresses=["8.8.8.8"],
        bridge=bridge,
        connector=lambda: socket.socket(),
    )
    try:
        assert relay.lease.proxy_url == "http://runner:unique-token@172.17.0.1:45678"
    finally:
        relay.close()
