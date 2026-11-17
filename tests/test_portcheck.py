"""Regression tests for the dashboard port check (portcheck + lifecycle + doctor + cory_app).

The leftover-connection mechanism is demonstrated here with real loopback sockets on
POSIX.  It is NOT claimed to be the proven historical cause of the 2026-10-29 stops.
"""
from __future__ import annotations

import errno
import importlib.util
import os
import re
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from orchestrator_cookie import portcheck
from orchestrator_cookie.config import ConfigurationError
from orchestrator_cookie.portcheck import CLOSING, FREE, LIVE, PortProbeError, probe_port

POSIX = os.name != "nt"


# --------------------------------------------------------------------------- helpers
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _listener(port: int, host: str = "127.0.0.1") -> socket.socket:
    s = socket.socket()
    if POSIX:  # mirrors uvicorn/asyncio on POSIX; never set on Windows
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    return s


class Script:
    """Scripted socket factory: outcomes for successive bind() calls plus a connect() outcome."""

    def __init__(self, binds, connect=None):
        self.binds = list(binds)
        self.connect_exc = connect
        self.sockets = []
        self.options = []
        self.addresses = []

    def factory(self, *_a, **_k):
        sock = _Fake(self)
        self.sockets.append(sock)
        return sock


class _Fake:
    def __init__(self, script):
        self.script, self.closed, self.bound = script, False, False

    def setsockopt(self, level, opt, value):
        self.script.options.append((level, opt, value))

    def bind(self, _address):
        self.script.addresses.append(_address)
        outcome = self.script.binds.pop(0)
        if outcome is not None:
            raise outcome

    def settimeout(self, _t):
        pass

    def connect(self, _address):
        if self.script.connect_exc is not None:
            raise self.script.connect_exc

    def close(self):
        self.closed = True


def _inuse():
    return OSError(errno.EADDRINUSE, "address in use")


def _patch(monkeypatch, script, *, windows=False):
    monkeypatch.setattr(portcheck.socket, "socket", script.factory)
    monkeypatch.setattr(portcheck, "_is_windows", lambda: windows)


# --------------------------------------------------------------------------- classification (scripted)
def test_free_port_is_free(monkeypatch):
    s = Script([None])
    _patch(monkeypatch, s)
    result = probe_port("127.0.0.1", 8095)
    assert result.state == FREE and result.bindable
    assert s.options == []  # the first attempt is a plain bind, like the old check
    assert all(x.closed for x in s.sockets)


def test_live_listener_refused_even_with_reuseaddr(monkeypatch):
    s = Script([_inuse(), _inuse()])
    _patch(monkeypatch, s)
    result = probe_port("0.0.0.0", 8095)
    assert result.state == LIVE and not result.bindable
    assert all(x.closed for x in s.sockets)


def test_closing_only_when_reuse_bind_ok_and_nothing_accepts(monkeypatch):
    s = Script([_inuse(), None], connect=ConnectionRefusedError())
    _patch(monkeypatch, s)
    result = probe_port("0.0.0.0", 8095)
    assert result.state == CLOSING and result.bindable
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in s.options
    assert all(x.closed for x in s.sockets)


def test_reuse_bind_ok_but_peer_accepts_is_live(monkeypatch):
    s = Script([_inuse(), None], connect=None)
    _patch(monkeypatch, s)
    result = probe_port("0.0.0.0", 8095)
    assert result.state == LIVE and not result.bindable


def test_windows_never_sets_reuseaddr_and_busy_is_live(monkeypatch):
    s = Script([OSError(errno.EADDRINUSE, "x")])
    _patch(monkeypatch, s, windows=True)
    result = probe_port("0.0.0.0", 8095)
    assert result.state == LIVE and not result.bindable
    assert s.options == []  # SO_REUSEADDR would allow port hijack on Windows
    assert len(s.sockets) == 1


def test_windows_winerror_10048_is_in_use(monkeypatch):
    exc = OSError(0, "in use")
    exc.winerror = 10048
    s = Script([exc])
    _patch(monkeypatch, s, windows=True)
    assert probe_port("127.0.0.1", 8095).state == LIVE


def test_permission_error_is_not_treated_as_busy(monkeypatch):
    s = Script([OSError(errno.EACCES, "denied")])
    _patch(monkeypatch, s)
    with pytest.raises(PortProbeError):
        probe_port("127.0.0.1", 80)
    assert len(s.sockets) == 1  # no second attempt
    assert s.options == []


def test_unexpected_error_on_reuse_attempt_is_error_not_closing(monkeypatch):
    s = Script([_inuse(), OSError(errno.EADDRNOTAVAIL, "bad address")])
    _patch(monkeypatch, s)
    with pytest.raises(PortProbeError):
        probe_port("203.0.113.9", 8095)


def test_localhost_maps_to_loopback(monkeypatch):
    s = Script([None])
    _patch(monkeypatch, s)
    probe_port("localhost", 8095)
    assert s.addresses == [("127.0.0.1", 8095)]


def test_ipv6_literal_uses_ipv6_family(monkeypatch):
    seen = []

    def factory(family, *_a, **_k):
        seen.append(family)
        return _Fake(Script([None]))

    monkeypatch.setattr(portcheck.socket, "socket", factory)
    probe_port("::1", 8095)
    assert seen == [socket.AF_INET6]


# --------------------------------------------------------------------------- real sockets
def test_real_free_port_is_free():
    assert probe_port("127.0.0.1", _free_port()).state == FREE


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0"])
def test_real_live_listener_blocks(host):
    port = _free_port()
    srv = _listener(port, host)
    try:
        result = probe_port(host, port)
        assert result.state == LIVE and not result.bindable
    finally:
        srv.close()


@pytest.mark.skipif(not POSIX, reason="closing-only state is POSIX semantics")
def test_real_leftover_established_connection_is_closing_not_live():
    port = _free_port()
    srv = _listener(port, "0.0.0.0")
    cli = socket.create_connection(("127.0.0.1", port))
    acc, _ = srv.accept()
    srv.close()  # listener gone, accepted connection remains
    try:
        plain = socket.socket()
        try:
            plain.bind(("0.0.0.0", port))
            pytest.skip("kernel allowed a plain bind; nothing to distinguish")
        except OSError as exc:
            assert exc.errno == errno.EADDRINUSE
        finally:
            plain.close()
        result = probe_port("0.0.0.0", port)
        assert result.state == CLOSING and result.bindable
        again = _listener(port, "0.0.0.0")  # a server-style bind really works now
        again.close()
    finally:
        acc.close()
        cli.close()


@pytest.mark.skipif(not POSIX, reason="TIME_WAIT bind semantics are POSIX")
def test_real_time_wait_leftover_is_closing_not_live():
    port = _free_port()
    srv = _listener(port, "0.0.0.0")
    cli = socket.create_connection(("127.0.0.1", port))
    acc, _ = srv.accept()
    acc.close()  # server closes first -> TIME_WAIT on the server port
    cli.close()
    srv.close()
    plain = socket.socket()
    try:
        plain.bind(("0.0.0.0", port))
        pytest.skip("no TIME_WAIT leftover produced")
    except OSError:
        pass
    finally:
        plain.close()
    assert probe_port("0.0.0.0", port).state == CLOSING


@pytest.mark.skipif(POSIX, reason="Windows-specific")
def test_real_windows_live_listener_blocks_and_free_port_is_free():
    port = _free_port()
    assert probe_port("127.0.0.1", port).state == FREE
    srv = _listener(port)
    try:
        assert probe_port("127.0.0.1", port).state == LIVE
    finally:
        srv.close()


# --------------------------------------------------------------------------- lifecycle / doctor
def test_lifecycle_port_available_follows_probe(monkeypatch):
    import orchestrator_cookie.lifecycle as lc

    monkeypatch.setattr(lc, "_probe_port_available", lambda h, p: True)
    assert lc._port_available("127.0.0.1", 8095) is True
    monkeypatch.setattr(lc, "_probe_port_available", lambda h, p: False)
    assert lc._port_available("127.0.0.1", 8095) is False


def test_lifecycle_probe_error_is_actionable(monkeypatch):
    import orchestrator_cookie.lifecycle as lc

    def boom(h, p):
        raise PortProbeError(h, p, PermissionError())

    monkeypatch.setattr(lc, "_probe_port_available", boom)
    with pytest.raises(ConfigurationError, match="cannot test local bind availability"):
        lc._port_available("127.0.0.1", 80)


def test_doctor_reports_closing_only_as_available_and_live_as_busy(monkeypatch):
    import orchestrator_cookie.doctor as doctor

    monkeypatch.setattr(portcheck, "probe_port", lambda h, p: portcheck.PortProbe(CLOSING, "x"))
    ok, detail = doctor._port_available("127.0.0.1", 8095)
    assert ok and "no listener detected" in detail
    monkeypatch.setattr(portcheck, "probe_port", lambda h, p: portcheck.PortProbe(LIVE, "x"))
    assert doctor._port_available("127.0.0.1", 8095)[0] is False

    def boom(h, p):
        raise PortProbeError(h, p, PermissionError())

    monkeypatch.setattr(portcheck, "probe_port", boom)
    ok, detail = doctor._port_available("127.0.0.1", 80)
    assert ok is False and "cannot be tested" in detail and "PermissionError" in detail


# --------------------------------------------------------------------------- cory_app.wait_for_port
def _app():
    spec = importlib.util.spec_from_file_location("cory_app", Path(__file__).parents[1] / "scripts/cory_app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CFG = SimpleNamespace(bind_host="0.0.0.0", preferred_port=8095)


def _results(*states):
    items = [portcheck.PortProbe(s, s) for s in states]
    return lambda h, p: items.pop(0) if len(items) > 1 else items[0]


def test_wait_free_returns_without_sleeping():
    m, slept = _app(), []
    m.wait_for_port(CFG, probe=_results(FREE), sleep=slept.append)
    assert slept == []


def test_wait_closing_only_continues_and_says_so(capsys):
    m = _app()
    m.wait_for_port(CFG, probe=_results(CLOSING), sleep=lambda s: pytest.fail("must not wait"))
    assert "no-listener-detected" in capsys.readouterr().out


def test_wait_live_then_free_is_bounded_polling():
    m, slept = _app(), []
    m.wait_for_port(CFG, probe=_results(LIVE, LIVE, FREE), sleep=slept.append)
    assert len(slept) == 2 and all(0 < s <= 1.0 for s in slept)


def test_wait_live_forever_refuses_with_evidence_and_signals_nothing(monkeypatch):
    m = _app()
    now = [0.0]
    calls = []

    def fake_sleep(s):
        now[0] += s

    def probe(h, p):
        calls.append(1)
        return portcheck.PortProbe(LIVE, "live")

    monkeypatch.setattr(m.os, "kill", lambda *a: pytest.fail("a process was signalled"))
    with pytest.raises(RuntimeError) as err:
        m.wait_for_port(CFG, timeout=5, probe=probe, sleep=fake_sleep, clock=lambda: now[0],
                        evidence=lambda port: "LISTEN x1")
    text = str(err.value)
    assert "listener or an unidentified socket" in text and "did not stop or signal any process" in text
    assert "LISTEN x1" in text
    assert len(calls) <= 7  # bounded: timeout/1s polls plus the first and last


def test_wait_and_probe_code_contain_no_process_control():
    """Structural guard: neither the wait loop nor the probe module can signal a process."""
    app = (Path(__file__).parents[1] / "scripts/cory_app.py").read_text(encoding="utf-8")
    wait_src = app[app.index("def wait_for_port"):app.index("def acquire_lock")]
    probe_src = Path(portcheck.__file__).read_text(encoding="utf-8")
    forbidden = re.compile(r"os\.kill|killpg|signal\.(?:SIG|signal|raise_signal)|\.terminate\(|Popen|subprocess|taskkill")
    for text in (wait_src, probe_src):
        assert not forbidden.search(text), forbidden.search(text).group(0)


def test_wait_probe_error_fails_fast_without_retry():
    m, calls = _app(), []

    def probe(h, p):
        calls.append(1)
        raise RuntimeError("cannot test local bind availability")

    with pytest.raises(RuntimeError):
        m.wait_for_port(CFG, probe=probe, sleep=lambda s: pytest.fail("must not retry"))
    assert len(calls) == 1


def test_wait_real_probe_error_wraps_and_fails_fast(monkeypatch):
    """Through the real portcheck: a permission error is one bind, no retry, RuntimeError."""
    m = _app()
    s = Script([OSError(errno.EACCES, "denied")])
    _patch(monkeypatch, s)
    with pytest.raises(RuntimeError, match="cannot test local bind availability"):
        m.wait_for_port(CFG, probe=None, sleep=lambda x: pytest.fail("must not retry"))
    assert len(s.sockets) == 1


def test_wait_interruption_propagates():
    m = _app()

    def interrupt(_s):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        m.wait_for_port(CFG, probe=_results(LIVE), sleep=interrupt)


@pytest.mark.skipif(not POSIX, reason="flock is POSIX")
def test_concurrent_lifecycle_command_is_refused(tmp_path):
    m = _app()
    path = tmp_path / "cory-app.lock"
    with path.open("a") as first, path.open("a") as second:
        m.acquire_lock(first)
        with pytest.raises(RuntimeError, match="already running"):
            m.acquire_lock(second)


@pytest.mark.skipif(not POSIX, reason="flock is POSIX")
def test_lock_is_refused_across_processes(tmp_path):
    """A second PROCESS (not just a second descriptor) is refused while the first holds the lock."""
    import subprocess
    import sys

    m = _app()
    path = tmp_path / "cory-app.lock"
    code = (
        "import fcntl,sys,time\n"
        "f=open(sys.argv[1],'a'); fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
        "print('locked',flush=True); time.sleep(20)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", code, str(path)], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        with path.open("a") as mine:
            with pytest.raises(RuntimeError, match="already running"):
                m.acquire_lock(mine)
    finally:
        child.kill()
        child.wait()


def test_archive_dead_metadata_with_closing_only_port_archives(tmp_path, monkeypatch):
    """Real archive_dead_metadata path: a dead PID + no-listener port => metadata is archived."""
    import json
    import orchestrator_cookie.lifecycle as lifecycle

    m = _app()
    path = tmp_path / ".orchestrator-cookie/state/dashboard.json"
    path.parent.mkdir(parents=True)
    raw = json.dumps(dict(pid=123456, bind_host="127.0.0.1", port=8025))
    path.write_text(raw)
    monkeypatch.setattr(lifecycle, "dashboard_status", lambda *a: SimpleNamespace(running=False))
    monkeypatch.setattr(portcheck, "probe_port", lambda h, p: portcheck.PortProbe(CLOSING, "x"))
    def dead(*a):
        raise ProcessLookupError()

    monkeypatch.setattr(m.os, "kill", dead)
    m.archive_dead_metadata(tmp_path, SimpleNamespace(bind_host="127.0.0.1"))
    assert not path.exists()
    monkeypatch.setattr(portcheck, "probe_port", lambda h, p: portcheck.PortProbe(LIVE, "x"))
    path.write_text(raw)
    with pytest.raises(RuntimeError, match="occupied"):
        m.archive_dead_metadata(tmp_path, SimpleNamespace(bind_host="127.0.0.1"))
    assert path.read_text() == raw


# --------------------------------------------------------------------------- evidence parser
_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _row(n, local, remote, st, inode="0"):
    return f"   {n}: {local} {remote} {st} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0 0 10 0\n"


def test_report_counts_states_and_peers(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(
        _HDR
        + _row(0, "00000000:1F9F", "00000000:0000", "0A", "555")
        + _row(1, "0100007F:1F9F", "2F554F0A:C350", "01")
        + _row(2, "0100007F:1F9F", "2F554F0A:C351", "06")
        + _row(3, "0100007F:0050", "00000000:0000", "0A", "9")  # other port ignored
    )
    (net / "tcp6").write_text(_HDR)
    report = portcheck.port_socket_report(8095, proc_root=str(tmp_path))
    assert report["states"] == {"LISTEN": 1, "ESTABLISHED": 1, "TIME_WAIT": 1}
    assert report["peers"] == ["10.79.85.47"]
    text = portcheck.format_port_report(report)
    assert "LISTEN x1" in text and "TIME_WAIT x1" in text and "10.79.85.47" in text


def test_report_unavailable_never_raises(tmp_path):
    report = portcheck.port_socket_report(8095, proc_root=str(tmp_path / "missing"))
    assert report["available"] is False
    assert "unavailable" in portcheck.format_port_report(report)


def test_report_has_no_command_lines(tmp_path):
    src = Path(portcheck.__file__).read_text(encoding="utf-8")
    assert "cmdline" not in src  # only /proc/<pid>/comm is ever read
