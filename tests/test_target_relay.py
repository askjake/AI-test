"""Security and byte-flow tests for project-scoped host target transport."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from orchestrator.bedrock_relay import BridgeContract
from orchestrator.target_relay import (
    DestinationLockedTargetRelay,
    ProjectTransport,
    TargetRelayClient,
    TargetRelayError,
    TargetRelayLease,
    _HostRelayServer,
    describe_project_transport,
    target_connect_relay,
)


def _server(connector, token: str = "a" * 32):
    server = _HostRelayServer(
        ("127.0.0.1", 0),
        client_network="127.0.0.0/8",
        token=token,
        connector=connector,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_host_relay_requires_credential_before_opening_destination():
    opened: list[bool] = []
    server, thread = _server(lambda: opened.append(True), token="b" * 32)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        client.sendall(b"OC-TARGET-RELAY/1 wrong-credential-value-00000000\n")
        assert client.recv(32) == b"DENIED\n"
        assert opened == []
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_runner_loopback_client_authenticates_and_relays_bytes(monkeypatch):
    upstream, observer = socket.socketpair()
    monkeypatch.setattr(
        "orchestrator.bedrock_relay.inspect_bridge_contract",
        lambda _engine: BridgeContract(gateway="127.0.0.1", subnet="127.0.0.0/8"),
    )
    relay = DestinationLockedTargetRelay(
        engine="docker",
        transport=ProjectTransport("vnc-direct", "vnc-approved", 5902),
        addresses=["192.0.2.10"],
        connector=lambda: upstream,
    )
    client_proxy = TargetRelayClient(
        relay_host=relay.lease.bind_host,
        relay_port=relay.lease.port,
        token=relay.lease.token,
    )
    client = socket.create_connection(("127.0.0.1", client_proxy.local_port), timeout=2)
    try:
        client.sendall(b"runner-to-target")
        assert observer.recv(64) == b"runner-to-target"
        observer.sendall(b"target-to-runner")
        assert client.recv(64) == b"target-to-runner"
    finally:
        client.close()
        observer.close()
        client_proxy.close()
        relay.close()


def test_target_relay_context_closes_lease_when_runner_fails(monkeypatch):
    import orchestrator.target_relay as target_relay_module

    lease = TargetRelayLease(
        kind="vnc-direct",
        endpoint="vnc-approved",
        destination_port=5902,
        bind_host="172.17.0.1",
        port=45679,
        client_network="172.17.0.0/16",
        token="r" * 43,
    )
    closed = []

    class Relay:
        def __init__(self, *, engine, transport, addresses):
            assert engine == "docker"
            assert transport == ProjectTransport("vnc-direct", "vnc-approved", 5902)
            assert addresses == ("10.79.85.47",)
            self.lease = lease

        def close(self):
            closed.append(True)

    monkeypatch.setattr(target_relay_module, "DestinationLockedTargetRelay", Relay)
    with pytest.raises(RuntimeError, match="runner failed"):
        with target_connect_relay(
            "docker",
            transport=ProjectTransport("vnc-direct", "vnc-approved", 5902),
            addresses=("10.79.85.47",),
        ) as actual:
            assert actual == lease
            raise RuntimeError("runner failed")
    assert closed == [True]


def test_openssh_proxycommand_helper_carries_standard_io_bytes():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    observed: list[bytes] = []

    def serve():
        connection, _address = listener.accept()
        with connection:
            observed.append(connection.recv(64))
            connection.sendall(b"proxy-reply")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "orchestrator.target_relay",
                "connect-loopback", "--port", str(listener.getsockname()[1]),
            ],
            input=b"ssh-bytes",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": "src"},
            check=False,
            timeout=5,
        )
    finally:
        listener.close()
        thread.join(timeout=2)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert observed == [b"ssh-bytes"]
    assert result.stdout == b"proxy-reply"


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "bad"])
def test_target_relay_rejects_unsafe_pinned_addresses(monkeypatch, address):
    monkeypatch.setattr(
        "orchestrator.bedrock_relay.inspect_bridge_contract",
        lambda _engine: BridgeContract(gateway="127.0.0.1", subnet="127.0.0.0/8"),
    )
    with pytest.raises(TargetRelayError):
        DestinationLockedTargetRelay(
            engine="docker",
            transport=ProjectTransport("vnc-direct", "vnc-approved", 5900),
            addresses=[address],
            connector=lambda: socket.socket(),
        )


def test_environment_contract_is_all_or_nothing(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_TARGET_RELAY_KIND", "vnc-direct")
    with pytest.raises(TargetRelayError, match="incomplete"):
        TargetRelayClient.from_environment(
            kind="vnc-direct", endpoint="vnc-approved", destination_port=5900
        )


def _write_project(root, name: str, body: str):
    project = root / name
    project.mkdir()
    (project / "manual").mkdir()
    (project / "manual" / "manual.md").write_text("# Manual\n")
    (project / "test.md").write_text("# Test: Relay\n\n## Goal\nConnect.\n")
    (project / "project.yaml").write_text(
        f"name: Relay\nmanual_dir: ./manual\n{body}"
    )


def test_project_transport_is_exact_for_direct_and_jump_vnc(tmp_path):
    _write_project(
        tmp_path,
        "direct",
        "vnc_host_allowlist: [vnc-approved]\n"
        "target:\n  type: vnc\n  host: vnc-approved\n  port: 5902\n",
    )
    _write_project(
        tmp_path,
        "jump",
        "ssh_host_allowlist: [jump-approved]\n"
        "vnc_host_allowlist: [vnc-private]\n"
        "target:\n  type: vnc\n  host: vnc-private\n  port: 5901\n"
        "  route:\n    type: ssh-jump\n    host: jump-approved\n    port: 2222\n",
    )
    assert describe_project_transport("direct", specs_root=str(tmp_path)) == ProjectTransport(
        "vnc-direct", "vnc-approved", 5902
    )
    assert describe_project_transport("jump", specs_root=str(tmp_path)) == ProjectTransport(
        "vnc-ssh-jump", "jump-approved", 2222
    )


def test_project_transport_is_exact_for_direct_rdp(tmp_path):
    _write_project(
        tmp_path,
        "rdp",
        "rdp_host_allowlist: [rdp-approved]\n"
        "target:\n  type: rdp\n  host: rdp-approved\n  port: 3390\n",
    )
    assert describe_project_transport("rdp", specs_root=str(tmp_path)) == ProjectTransport(
        "rdp-direct", "rdp-approved", 3390
    )


def test_project_transport_rejects_non_allowlisted_rdp(tmp_path):
    _write_project(
        tmp_path,
        "rdp",
        "rdp_host_allowlist: [other]\n"
        "target:\n  type: rdp\n  host: rdp-approved\n",
    )
    with pytest.raises(TargetRelayError, match="effective allowlist"):
        describe_project_transport("rdp", specs_root=str(tmp_path))


def test_relay_state_never_prints_or_embeds_a_client_selected_destination(monkeypatch):
    monkeypatch.setattr(
        "orchestrator.bedrock_relay.inspect_bridge_contract",
        lambda _engine: BridgeContract(gateway="127.0.0.1", subnet="127.0.0.0/8"),
    )
    relay = DestinationLockedTargetRelay(
        engine="docker",
        transport=ProjectTransport("vnc-ssh-jump", "jump-approved", 22),
        addresses=["192.0.2.11"],
        connector=lambda: socket.socket(),
    )
    try:
        document = json.loads(json.dumps(relay.lease.__dict__))
        assert document["endpoint"] == "jump-approved"
        assert "destination" not in document
    finally:
        relay.close()
