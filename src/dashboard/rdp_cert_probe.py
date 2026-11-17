"""Read the TLS certificate an RDP server presents (name + sha256 fingerprint) for OPERATOR REVIEW.

This performs the standard RDP security negotiation (X.224 connection request asking for TLS)
and then a TLS handshake WITHOUT sending any credentials.  Nothing is trusted or persisted
here: the dashboard shows the candidate and the operator must explicitly accept it (the
fingerprint is later pinned by FreeRDP's ``/cert:deny,name:...,fingerprint:...``).

It runs from the dashboard host and only ever contacts the host/port of hop 1 of a saved
procedure; it is never used for hop 2 (which is reached from inside the first desktop).
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import ssl
import struct
import tempfile
import threading
import time
from typing import Any, Callable

_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")

# TPKT(4) + X.224 CR(7) + RDP_NEG_REQ(8): request TLS (1) and CredSSP (2); either upgrades to TLS.
_CONNECTION_REQUEST = (
    b"\x03\x00\x00\x13" b"\x0e\xe0\x00\x00\x00\x00\x00" b"\x01\x00\x08\x00\x03\x00\x00\x00"
)


class RdpProbeError(Exception):
    """Probe failure with a message that never contains credentials."""


class RdpProbeBusy(Exception):
    """Another probe is already running; the dashboard host never runs two at once."""


# One probe at a time, dashboard-wide: the probe is a deliberate network contact made FROM the
# dashboard host, so it must not become a way to fan out connections to internal machines.
_PROBE_LOCK = threading.Lock()
TOTAL_DEADLINE_SECONDS = 8.0   # ONE deadline for connect + negotiation + TLS handshake together


def _refused_address(address: ipaddress._BaseAddress) -> bool:
    return (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
            or address.is_reserved)


def _validate_host(host: str) -> None:
    """Syntax check plus: never the dashboard host itself, link-local/metadata, multicast or reserved space."""
    if not isinstance(host, str):
        raise ValueError("The host is not a valid address or hostname.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.fullmatch(host) or host.lower() in ("localhost", "localhost.localdomain"):
            raise ValueError("The host is not a valid address or hostname.") from None
        return
    if _refused_address(address):
        raise ValueError("That address cannot be probed from the dashboard host (loopback, link-local, multicast or reserved).")


def _read_exact(sock: Any, count: int, remaining: Callable[[], float]) -> bytes:
    data = b""
    while len(data) < count:
        left = remaining()
        if left <= 0:
            raise RdpProbeError("The RDP server did not answer within the probe deadline.")
        sock.settimeout(left)              # every read is bounded by what is LEFT of the single deadline
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RdpProbeError("The server closed the connection during RDP negotiation.")
        data += chunk
    return data


def _common_name(der: bytes) -> str | None:
    """Best-effort subject CN using the interpreter's own certificate decoder (no extra packages)."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(prefix=".rdpcert_", suffix=".pem")
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(pem)
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        for rdn in decoded.get("subject", ()):
            for key, value in rdn:
                if key == "commonName" and isinstance(value, str):
                    return value
    except Exception:
        return None
    return None


def probe_rdp_certificate(
    host: str,
    port: int = 3389,
    *,
    timeout: float = TOTAL_DEADLINE_SECONDS,
    connector: Callable[..., Any] | None = None,
    tls_wrap: Callable[[Any], bytes] | None = None,
    clock: Callable[[], float] | None = None,
) -> dict:
    """Return ``{"name": str, "fingerprint": "sha256:<hex>"}`` for the server's TLS certificate.

    ``timeout`` is ONE overall deadline for the whole probe (connect, negotiation, handshake), and only
    one probe may run at a time (:class:`RdpProbeBusy` otherwise).
    """
    _validate_host(host)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535.")
    if not _PROBE_LOCK.acquire(blocking=False):
        raise RdpProbeBusy("Another certificate probe is running; try again in a few seconds.")
    try:
        return _probe_locked(host, port, timeout, connector, tls_wrap, clock or time.monotonic)
    finally:
        _PROBE_LOCK.release()


def _probe_locked(host: str, port: int, timeout: float, connector: Any, tls_wrap: Any, clock: Callable[[], float]) -> dict:
    started = clock()

    def remaining() -> float:
        return timeout - (clock() - started)

    connect = connector or socket.create_connection
    try:
        sock = connect((host, port), timeout=max(0.1, remaining()))
    except OSError:
        raise RdpProbeError("Could not connect to the RDP port.") from None
    try:
        sock.settimeout(max(0.1, remaining()))
        sock.sendall(_CONNECTION_REQUEST)
        reply = _read_exact(sock, 19, remaining)
        if reply[0] != 0x03 or reply[5] != 0xD0:
            raise RdpProbeError("The server did not answer with an RDP connection confirmation.")
        if reply[11] != 0x02:  # RDP_NEG_RSP
            raise RdpProbeError("The server did not accept a TLS-based RDP security protocol.")
        selected = struct.unpack("<I", reply[15:19])[0]
        if selected not in (1, 2, 8):  # TLS, CredSSP, CredSSP+early-auth
            raise RdpProbeError("The server selected a non-TLS RDP security protocol.")
        if tls_wrap is not None:
            der = tls_wrap(sock)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # we only READ the certificate; the operator reviews it
            if remaining() <= 0:
                raise RdpProbeError("The RDP server did not answer within the probe deadline.")
            sock.settimeout(remaining())       # the handshake gets only what is left of the same deadline
            with context.wrap_socket(sock) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            raise RdpProbeError("The server presented no certificate.")
    except (OSError, ssl.SSLError):
        raise RdpProbeError("The TLS handshake with the RDP server failed.") from None
    finally:
        try:
            sock.close()
        except Exception:
            pass
    name = _common_name(der)
    if not name or not _NAME_OK.fullmatch(name):
        name = host  # FreeRDP matches the name it is told; the pinned fingerprint is what protects the session
    return {"name": name, "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest()}
