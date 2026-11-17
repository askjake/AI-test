"""Certificate probe (SECURITY F6): one overall deadline, one probe at a time, no unsafe targets.

Uses a fake socket/clock: nothing here connects to any machine.
"""
import threading

import pytest

from dashboard import rdp_cert_probe as probe

DER = b"0\x82\x01fake-der-bytes"
CONFIRM = bytes([0x03, 0, 0, 0x13, 0x0E, 0xD0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 0x02, 0, 0, 0])   # RDP_NEG_RSP, TLS


class Clock:
    def __init__(self):
        self.t = 0.0


class Sock:
    def __init__(self, clock, chunks, step=0.0):
        self.clock, self.chunks, self.step = clock, list(chunks), step
        self.timeouts, self.sent, self.closed = [], [], False

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        self.clock.t += self.step
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        self.closed = True


def test_happy_path_returns_name_and_sha256_and_never_sends_credentials():
    clock = Clock()
    sock = Sock(clock, [CONFIRM])
    result = probe.probe_rdp_certificate("10.70.115.36", connector=lambda *a, **k: sock, tls_wrap=lambda s: DER, clock=lambda: clock.t)
    assert result["fingerprint"].startswith("sha256:") and len(result["fingerprint"]) == 71
    assert result["name"] == "10.70.115.36"                    # CN undecodable -> the host that was asked for
    assert len(sock.sent) == 1 and sock.closed                  # only the X.224 connection request


def test_one_overall_deadline_bounds_a_slow_trickling_server():
    clock = Clock()
    sock = Sock(clock, [b"\x03"] * 19, step=3.0)                # one byte every 3 s would be 57 s without an overall deadline
    with pytest.raises(probe.RdpProbeError) as err:
        probe.probe_rdp_certificate("10.70.115.36", timeout=8.0, connector=lambda *a, **k: sock, tls_wrap=lambda s: DER, clock=lambda: clock.t)
    assert "deadline" in str(err.value)
    assert clock.t <= 9.0 + 3.0 and sock.closed
    assert all(t <= 8.0 for t in sock.timeouts)                  # no read is ever given more than the total


def test_every_read_gets_only_what_is_left_of_the_deadline():
    clock = Clock()
    sock = Sock(clock, [CONFIRM[:10], CONFIRM[10:]], step=2.0)
    probe.probe_rdp_certificate("10.70.115.36", timeout=8.0, connector=lambda *a, **k: sock, tls_wrap=lambda s: DER, clock=lambda: clock.t)
    assert sock.timeouts == sorted(sock.timeouts, reverse=True)  # strictly shrinking budget


def test_only_one_probe_runs_at_a_time():
    clock = Clock()
    inside, release = threading.Event(), threading.Event()

    class Blocking(Sock):
        def recv(self, n):
            inside.set()
            release.wait(5)
            return super().recv(n)

    sock = Blocking(clock, [CONFIRM])
    results = []

    def first():
        results.append(probe.probe_rdp_certificate("10.70.115.36", connector=lambda *a, **k: sock, tls_wrap=lambda s: DER, clock=lambda: clock.t))

    thread = threading.Thread(target=first)
    thread.start()
    assert inside.wait(5)
    with pytest.raises(probe.RdpProbeBusy):
        probe.probe_rdp_certificate("10.70.115.37", connector=lambda *a, **k: Sock(clock, [CONFIRM]), tls_wrap=lambda s: DER)
    release.set()
    thread.join(5)
    assert results and results[0]["fingerprint"].startswith("sha256:")
    # and the lock is free again afterwards
    probe.probe_rdp_certificate("10.70.115.37", connector=lambda *a, **k: Sock(clock, [CONFIRM]), tls_wrap=lambda s: DER, clock=lambda: clock.t)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "localhost", "fe80::1", "bad host", ""])
def test_unsafe_or_invalid_targets_are_refused_before_any_connection(host):
    called = []
    with pytest.raises(ValueError):
        probe.probe_rdp_certificate(host, connector=lambda *a, **k: called.append(1))
    assert called == []


@pytest.mark.parametrize("host", ["10.70.115.36", "172.20.33.215", "192.0.2.10", "winhost.example"])
def test_private_and_named_targets_are_allowed(host):
    clock = Clock()
    assert probe.probe_rdp_certificate(host, connector=lambda *a, **k: Sock(clock, [CONFIRM]), tls_wrap=lambda s: DER, clock=lambda: clock.t)


def test_bad_port_and_non_tls_server_are_reported_without_secrets():
    clock = Clock()
    with pytest.raises(ValueError):
        probe.probe_rdp_certificate("10.0.0.5", port=0)
    plain = bytes([0x03, 0, 0, 0x13, 0x0E, 0xD0, 0, 0, 0, 0, 0, 0x03, 0, 0x08, 0, 0x01, 0, 0, 0])   # RDP_NEG_FAILURE
    with pytest.raises(probe.RdpProbeError):
        probe.probe_rdp_certificate("10.0.0.5", connector=lambda *a, **k: Sock(clock, [plain]), tls_wrap=lambda s: DER, clock=lambda: clock.t)
