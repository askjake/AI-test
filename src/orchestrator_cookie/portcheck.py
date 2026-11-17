"""Port-state classification for the managed dashboard (read-only, never signals a process).

Why this exists
---------------
The launcher used to decide "is the dashboard port free?" with a bare ``bind()``
and no ``SO_REUSEADDR``.  On POSIX a bare bind also fails while *closing* TCP
connections (FIN_WAIT / TIME_WAIT, or sockets still owned by a process that is
exiting) remain on the port, although nothing is listening.  The dashboard
server itself (uvicorn) binds with ``SO_REUSEADDR`` and would have started.

This module separates three outcomes:

``FREE``      a plain bind succeeds.
``CLOSING``   (POSIX only) a plain bind fails with EADDRINUSE, but a bind with
              ``SO_REUSEADDR`` succeeds AND no peer accepts a TCP connection:
              no listener was detected (consistent with leftovers; not proven).  Startup may proceed.
``LIVE``      something listens (or may accept) on the port.  Startup must not
              proceed.  Nothing is ever killed or signalled by this module.

Platform notes
--------------
* POSIX/Linux: ``SO_REUSEADDR`` does not permit a second *listening* bind, so a
  live listener still reports EADDRINUSE for both attempts.
* Windows: ``SO_REUSEADDR`` has different (permissive, hijack-prone) semantics
  and Windows does not block ``bind`` on TIME_WAIT leftovers, so it is NEVER
  set here.  A failing plain bind is always ``LIVE``.
* A bind that fails for any other reason (permission, bad address) raises
  :class:`PortProbeError`; it is not retried as if it were a busy port.

IMPORTANT distinction (kept deliberately): the leftover-connection mechanism is
demonstrated by experiment; it has NOT been proven to be the historical cause
of the two "port still unavailable" stops on the 3090 on 2026-10-29.
:func:`port_socket_report` exists so that the next occurrence leaves evidence.
"""
from __future__ import annotations

import errno
import os
import socket
import sys
from dataclasses import dataclass

FREE = "free"
CLOSING = "closing-only"
LIVE = "live-listener"

_WSAEADDRINUSE = 10048


class PortProbeError(Exception):
    """The port could not be tested (not "busy"): permission, bad address, ..."""

    def __init__(self, host: str, port: int, original: BaseException):
        super().__init__(f"cannot test local bind availability for {host}:{port} ({type(original).__name__})")
        self.host = host
        self.port = port
        self.original = original


@dataclass(frozen=True)
class PortProbe:
    state: str
    detail: str

    @property
    def bindable(self) -> bool:
        """True when a start may proceed (free, or no listener detected)."""
        return self.state in (FREE, CLOSING)


def _is_windows() -> bool:
    return os.name == "nt"


def _in_use(exc: OSError) -> bool:
    return exc.errno == errno.EADDRINUSE or getattr(exc, "winerror", None) == _WSAEADDRINUSE


def _candidate(host: str) -> tuple[str, int]:
    candidate = "127.0.0.1" if host == "localhost" else host
    family = socket.AF_INET6 if ":" in candidate else socket.AF_INET
    return candidate, family


def _connect_target(candidate: str) -> str:
    if candidate in ("0.0.0.0", ""):
        return "127.0.0.1"
    if candidate == "::":
        return "::1"
    return candidate


def _accepts_connection(candidate: str, port: int, timeout: float) -> bool:
    """True when something accepts a TCP connection on the port (we send nothing)."""
    target = _connect_target(candidate)
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((target, port))
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True


def probe_port(host: str, port: int, *, connect_timeout: float = 0.25) -> PortProbe:
    """Classify ``host:port``.  Read-only: binds and immediately closes a probe socket."""
    candidate, family = _candidate(host)

    # Attempt 1: plain bind, exactly what the old check did (no setsockopt first).
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((candidate, port))
    except OSError as exc:
        if not _in_use(exc):
            raise PortProbeError(host, port, exc) from exc
    else:
        return PortProbe(FREE, f"{host}:{port} is free")
    finally:
        sock.close()

    if _is_windows():
        return PortProbe(LIVE, f"{host}:{port} is in use (plain bind refused; Windows has no closing-only state)")

    # Attempt 2 (POSIX): the same bind with SO_REUSEADDR, as the server itself does.
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((candidate, port))
    except OSError as exc:
        if _in_use(exc):
            return PortProbe(LIVE, f"{host}:{port} has a live listener (bind refused even with SO_REUSEADDR)")
        raise PortProbeError(host, port, exc) from exc
    finally:
        sock.close()

    # The kernel allows a server bind.  Defend against platforms whose SO_REUSEADDR is
    # looser than Linux's: if anything still accepts connections it is a live listener.
    if _accepts_connection(candidate, port, connect_timeout):
        return PortProbe(LIVE, f"{host}:{port} accepts connections (live listener)")
    return PortProbe(CLOSING, f"{host}:{port}: no listener detected (plain bind refused, SO_REUSEADDR bind succeeded, "
                              "no connection accepted); consistent with closing connections, not proven")


def port_available(host: str, port: int) -> bool:
    """Boolean form used by launchers: True for FREE or CLOSING; PortProbeError propagates."""
    return probe_port(host, port).bindable


# ---------------------------------------------------------------------------
# Evidence (Linux /proc only; read-only; no command lines, no signalling)
# ---------------------------------------------------------------------------
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}


def _decode_addr(text: str):
    ip, _, hexport = text.partition(":")
    try:
        port = int(hexport, 16)
    except ValueError:
        return None
    try:
        if len(ip) == 8:
            return ".".join(str(b) for b in bytes.fromhex(ip)[::-1]), port
        if len(ip) == 32:
            raw = b"".join(bytes.fromhex(ip[i:i + 8])[::-1] for i in range(0, 32, 8))
            if raw[:12] == b"\x00" * 10 + b"\xff\xff":
                return ".".join(str(b) for b in raw[12:]), port
            return "ipv6", port
    except ValueError:
        return None
    return None


def _socket_owners(proc_root: str, inodes: set[str]) -> dict[str, tuple[str, str]]:
    owners: dict[str, tuple[str, str]] = {}
    if not inodes:
        return owners
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return owners
    for pid in entries:
        if not pid.isdigit():
            continue
        fd_dir = os.path.join(proc_root, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # other users' processes are not readable; that is fine
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                inode = target[8:-1]
                try:
                    with open(os.path.join(proc_root, pid, "comm"), encoding="utf-8", errors="replace") as handle:
                        comm = handle.read().strip()[:32]
                except OSError:
                    comm = "?"
                owners.setdefault(inode, (pid, comm))
    return owners


def port_socket_report(port: int, *, proc_root: str = "/proc") -> dict:
    """Socket states on ``port`` from ``<proc_root>/net/tcp{,6}``.  Never raises."""
    report: dict = {"port": port, "available": False, "states": {}, "listeners": [], "peers": []}
    states: dict[str, int] = {}
    listeners: list[dict] = []
    peers: set[str] = set()
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc_root, "net", name), encoding="utf-8") as handle:
                lines = handle.read().splitlines()[1:]
        except OSError:
            continue
        report["available"] = True
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            local = _decode_addr(fields[1])
            if local is None or local[1] != port:
                continue
            state = _TCP_STATES.get(fields[3].upper(), fields[3])
            states[state] = states.get(state, 0) + 1
            if state == "LISTEN":
                listeners.append({"addr": local[0], "inode": fields[9]})
            else:
                remote = _decode_addr(fields[2])
                if remote is not None and remote[0] not in ("127.0.0.1", "0.0.0.0"):
                    peers.add(remote[0])
    owners = _socket_owners(proc_root, {item["inode"] for item in listeners})
    for item in listeners:
        pid_comm = owners.get(item["inode"])
        item["pid"], item["comm"] = pid_comm if pid_comm else (None, None)
    report.update(states=states, listeners=listeners, peers=sorted(peers)[:8])
    return report


def format_port_report(report: dict) -> str:
    if not report.get("available"):
        return f"socket evidence unavailable on this platform ({sys.platform})"
    if not report["states"]:
        return f"no sockets on port {report['port']}"
    parts = [f"{name} x{count}" for name, count in sorted(report["states"].items())]
    text = f"port {report['port']}: " + ", ".join(parts)
    for item in report["listeners"]:
        owner = f"pid {item['pid']} ({item['comm']})" if item.get("pid") else "owner not visible to this user"
        text += f"; LISTEN {item['addr']} {owner}"
    if report["peers"]:
        text += "; remote peers " + ", ".join(report["peers"])
    return text
