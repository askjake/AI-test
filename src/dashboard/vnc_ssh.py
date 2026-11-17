"""VNC through SSH for the simplified connection workspace (development change, hop-free: a gateway plus ONE VNC destination).

Deterministic intake only.  While a draft is created, edited, saved or turned into a project, nothing here starts a process, opens a
socket or calls a model.  The single network action is the operator-requested SSH host-key discovery (reads a public key; no credential
is sent).  Passwords are written once to owner-only secret storage; only reference NAMES travel through drafts, manuals, specs, responses
and logs.  The runner side is unchanged: the project written for this draft uses the existing typed ``ssh-jump`` route of the VNC target.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import secrets as _secrets
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictInt

from . import connection_intake as CI
from . import procedure_intake as PI
from .target_setup import KnownHostsSaveRequest, PasswordSaveRequest, TargetSetupError

SESSION_END = {
    "remote_applications": "close_test_instance_only",   # only the application instance this test opened; never anything else
    "automation_client": "disconnect",                    # the run's own VNC viewer and SSH tunnel end with the run
    "remote_session": "never_log_off",
}
SESSION_END_TEXT = PI.GATEWAY_SESSION_END_TEXT
CONFIRM_TARGET_PHRASE = "Confirm gateway, destination and account"
DISCOVER_PHRASE = "Discover host key"
APPROVE_PHRASE = "Approve host key"

_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class VncSshError(ValueError):
    def __init__(self, errors: list[dict], status_code: int = 422) -> None:
        self.errors = errors
        self.status_code = status_code
        super().__init__("; ".join(e["message"] for e in errors))


def _err(field: str, message: str, status: int = 422) -> VncSshError:
    return VncSshError([{"field": field, "message": message}], status)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GatewayInput(_Strict):
    host: str = Field(max_length=253)
    port: StrictInt = 22
    user: str = Field(max_length=64)
    password: Optional[SecretStr] = None
    password_reference: Optional[str] = Field(default=None, max_length=127)


class DestinationInput(_Strict):
    host: str = Field(max_length=253)
    port: Optional[StrictInt] = None
    display: Optional[StrictInt] = None
    password: Optional[SecretStr] = None
    password_reference: Optional[str] = Field(default=None, max_length=127)


class VncSshRequest(_Strict):
    title: Optional[str] = Field(default=None, max_length=120)
    gateway: GatewayInput
    destination: DestinationInput
    goal: str = Field(max_length=30000)


def check_host(value: object, field: str, what: str) -> str:
    v = value.strip() if isinstance(value, str) else ""
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        if not _HOST.fullmatch(v) or v.lower() == "localhost" or v.lower().endswith(".localhost"):
            raise _err(field, f"{what} must be an IPv4 address or a hostname.") from None
        return v
    if ip.version != 4:
        raise _err(field, "IPv6 literals are not supported: use an IPv4 address or a hostname.")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise _err(field, f"{what} cannot be a loopback, unspecified, multicast or link-local address.")
    return v


def _check_port(value: object, field: str, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise _err(field, f"{label} must be between 1 and 65535.")
    return value


def _ref_ok(reference: Optional[str], secrets_root: str) -> bool:
    return bool(reference) and bool(_REF.fullmatch(reference)) and ".." not in reference and PI._reference_exists(secrets_root, reference)


def _secret_text(value: Optional[SecretStr]) -> Optional[str]:
    return value.get_secret_value() if value is not None else None


def validate_request(req: VncSshRequest, secrets_root: str) -> dict:
    """Pure (apart from file-existence checks of saved references).  Returns normalised values; raises VncSshError with every problem found."""
    errors: list[dict] = []

    def run(fn, *args):
        try:
            return fn(*args)
        except VncSshError as exc:
            errors.extend(exc.errors)
            return None

    g, d = req.gateway, req.destination
    gw_host = run(check_host, g.host, "gateway.host", "The SSH gateway")
    gw_port = run(_check_port, g.port, "gateway.port", "The SSH port")
    gw_user = g.user.strip()
    if not _USER.fullmatch(gw_user):
        errors.append({"field": "gateway.user", "message": "Enter the SSH username (letters, digits and . _ @ -, at most 64 characters)."})
    gw_pw, gw_ref = _secret_text(g.password), (g.password_reference or "").strip() or None
    if (gw_pw is None or not gw_pw) == (gw_ref is None):
        errors.append({"field": "gateway.credential", "message": "Give either the SSH password or the name of an already saved gateway credential, not both and not neither."})
    elif gw_ref is not None and not _ref_ok(gw_ref, secrets_root):
        errors.append({"field": "gateway.credential", "message": "That saved gateway credential does not exist. Enter the password instead."})
    elif gw_pw is not None and (len(gw_pw) > 1024 or _CONTROL.search(gw_pw)):
        errors.append({"field": "gateway.credential", "message": "The SSH password must be 1-1024 characters without control characters."})

    vnc_host = run(check_host, d.host, "destination.host", "The VNC destination")
    if d.port is not None and d.display is not None:
        errors.append({"field": "destination.port", "message": "Give either the VNC display number or the TCP port, not both."})
        vnc_port = vnc_display = None
    elif d.display is not None:
        if isinstance(d.display, bool) or not 0 <= d.display <= 99:
            errors.append({"field": "destination.display", "message": "The VNC display must be 0 through 99 (TCP 5900 plus the display). For another TCP port enter the port instead."})
            vnc_port = vnc_display = None
        else:
            vnc_display, vnc_port = d.display, 5900 + d.display
    else:
        vnc_port = run(_check_port, d.port if d.port is not None else 5900, "destination.port", "The VNC TCP port")
        vnc_display = (vnc_port - 5900) if vnc_port is not None and 5900 <= vnc_port <= 5999 else None
    vnc_pw, vnc_ref = _secret_text(d.password), (d.password_reference or "").strip() or None
    if (vnc_pw is None or not vnc_pw) == (vnc_ref is None):
        errors.append({"field": "destination.credential", "message": "Give either the VNC password or the name of an already saved VNC credential, not both and not neither."})
    elif vnc_ref is not None and not _ref_ok(vnc_ref, secrets_root):
        errors.append({"field": "destination.credential", "message": "That saved VNC credential does not exist. Enter the password instead."})
    elif vnc_pw is not None and len(vnc_pw.encode("utf-8")) > CI.MAX_VNC_PASSWORD_BYTES:
        errors.append({"field": "destination.credential", "message": f"Classic VNC authentication uses at most {CI.MAX_VNC_PASSWORD_BYTES} bytes; a longer password would be silently truncated by the server."})
    elif vnc_pw is not None and (_CONTROL.search(vnc_pw)):
        errors.append({"field": "destination.credential", "message": "The VNC password must not contain control characters."})

    goal = (req.goal or "").strip()
    if len(goal) < 12:
        errors.append({"field": "goal", "message": "Describe what the test should do (at least 12 characters)."})
    elif "\0" in goal:
        errors.append({"field": "goal", "message": "The goal contains an invalid character."})
    else:
        if (any(PI.RDP_LINE.search(line) or CI.VNC_LINE.search(line.strip()) for line in goal.splitlines()) or CI.credential_guard_message(goal)
                or re.search(r"(?im)^\s*(?:password|passwd|secret|token)\s*[:=]", goal)):
            errors.append({"field": "goal", "message": "Keep connection details and passwords out of the goal: enter them in the gateway and destination sections."})
        for secret in (gw_pw, vnc_pw):
            if secret and len(secret) >= 4 and secret in goal:
                errors.append({"field": "goal", "message": "The goal contains a password value. Remove it; passwords are entered only in the credential fields."})
                break
    if vnc_host and gw_host and vnc_host == gw_host and vnc_port == gw_port:
        errors.append({"field": "destination.host", "message": "The VNC destination and the SSH gateway are the same endpoint."})
    if errors:
        raise VncSshError(errors)
    return {"gw_host": gw_host, "gw_port": gw_port, "gw_user": gw_user, "gw_pw": gw_pw, "gw_ref": gw_ref,
            "vnc_host": vnc_host, "vnc_port": vnc_port, "vnc_display": vnc_display, "vnc_pw": vnc_pw, "vnc_ref": vnc_ref,
            "goal": goal, "title": (req.title or "").strip() or f"VNC through SSH to {vnc_host}"}


def _findings(gateway: PI.Gateway) -> list[str]:
    return list(PI.GATEWAY_FINDINGS)


def _persist_new(key: str, state_root: str, draft: PI.ProcedureDraft) -> None:
    root = Path(state_root).resolve() / "procedure-drafts"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    temp = Path(tempfile.mkdtemp(prefix=".intake-", dir=root))
    try:
        for filename, data in (("draft.json", draft.model_dump_json(indent=2)), ("manual.md", draft.manual)):
            p = temp / filename
            p.write_text(data)
            p.chmod(0o600)
        temp.rename(root / key)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def build_vnc_ssh_procedure(req: VncSshRequest, service, state_root: str) -> PI.ProcedureDraft:
    secrets_root = service._secrets_root()
    v = validate_request(req, secrets_root)
    key = uuid.uuid4().hex
    saved: list[str] = []
    try:
        gw_ref = v["gw_ref"]
        if gw_ref is None:
            gw_ref = service.save_password(PasswordSaveRequest(kind="gateway", reference_name=f"procedure-{key}-gateway.gateway.pw", password=SecretStr(v["gw_pw"]))).reference_name
            saved.append(gw_ref)
        vnc_ref = v["vnc_ref"]
        if vnc_ref is None:
            vnc_ref = service.save_password(PasswordSaveRequest(kind="vnc", reference_name=f"procedure-{key}-hop-1.vnc.pw", password=SecretStr(v["vnc_pw"]))).reference_name
            saved.append(vnc_ref)
        body = v["goal"]
        for value in sorted({v["gw_host"], v["vnc_host"]}, key=len, reverse=True):
            body = body.replace(value, "[saved connection value]")      # connection endpoints never become manual or model prose
        conn = PI._Conn(v["vnc_host"], v["vnc_port"], "", SecretStr(""), protocol="vnc", display=v["vnc_display"])
        _unused, steps, _title, findings = PI._finish_parse(body, [conn], protocol="vnc")
        gateway = PI.Gateway(host=v["gw_host"], port=v["gw_port"], user=v["gw_user"], password_reference=gw_ref)
        hop = PI.Hop(order=1, protocol="vnc", host=v["vnc_host"], port=v["vnc_port"], user="", password_reference=vnc_ref,
                     opened_from="runner (VNC viewer) through the SSH gateway", display=v["vnc_display"])
        findings = PI.gateway_findings(findings)
        title = v["title"]
        manual = PI.render_manual(title, [hop], steps, findings, gateway)
        draft = PI.ProcedureDraft(id=key, title=title, connections=[hop], steps=steps, action_context_hop=1, findings=findings, manual=manual,
                                  final_hop=1, session_end=dict(SESSION_END), gateway=gateway)
        draft = PI._with_readiness(draft, secrets_root)
        _persist_new(key, state_root, draft)
        return draft
    except Exception:
        for reference in saved:
            (Path(secrets_root) / reference).unlink(missing_ok=True)
        raise


def _load_gateway_draft(key: str, state_root: str) -> PI.ProcedureDraft:
    try:
        draft = PI.load_procedure(key, state_root)
    except PI.IntakeError as exc:
        raise _err("procedure", str(exc), 404) from None
    if draft.gateway is None:
        raise _err("gateway", "This procedure has no SSH gateway.", 409)
    return draft


def update_gateway(key: str, edit: object, state_root: str, service) -> PI.ProcedureDraft:
    draft = _load_gateway_draft(key, state_root)
    if not isinstance(edit, dict) or not edit:
        raise _err("gateway", "Provide at least one gateway edit.")
    errors: list[dict] = []
    for extra in sorted(set(edit) - {"host", "port", "user", "new_password"}):
        errors.append({"field": f"gateway.{extra}", "message": "Unknown field."})
    gw, change = draft.gateway, {}
    try:
        if "host" in edit:
            change["host"] = check_host(edit["host"], "gateway.host", "The SSH gateway")
        if "port" in edit:
            change["port"] = _check_port(edit["port"], "gateway.port", "The SSH port")
        if "user" in edit:
            user = edit["user"].strip() if isinstance(edit["user"], str) else ""
            if not _USER.fullmatch(user):
                raise _err("gateway.user", "Enter the SSH username (letters, digits and . _ @ -, at most 64 characters).")
            change["user"] = user
    except VncSshError as exc:
        errors.extend(exc.errors)
    password = edit.get("new_password")
    if password is not None:
        if not isinstance(password, str) or not password.strip() or len(password) > 1024 or _CONTROL.search(password):
            errors.append({"field": "gateway.password", "message": "The SSH password must be 1-1024 characters without control characters."})
    if errors:
        raise VncSshError(errors)
    secrets_root = service._secrets_root()
    written: list[str] = []
    try:
        if password is not None:
            reference = f"procedure-{key}-gateway-{_secrets.token_hex(4)}.gateway.pw"
            written.append(service.save_password(PasswordSaveRequest(kind="gateway", reference_name=reference, password=SecretStr(password), overwrite=False)).reference_name)
            change["password_reference"] = written[0]       # the previous reference file is left untouched
        if ("host" in change and change["host"] != gw.host) or ("port" in change and change["port"] != gw.port):
            change.update(known_hosts_reference=None, host_key_algorithm=None, host_key_fingerprint=None, host_key_source=None, host_key_approved_at=None)
        new_gw = PI.Gateway.model_validate({**gw.model_dump(), **change})
        updated = draft.model_copy(update={"gateway": new_gw})
        updated = updated.model_copy(update={"manual": PI.render_manual(updated.title, updated.connections, updated.steps, updated.findings, new_gw)})
        if PI.connection_config_hash(updated) != PI.connection_config_hash(draft):
            updated = updated.model_copy(update={"last_test": None})
        updated = PI._with_readiness(updated, secrets_root)
        PI.persist_draft(key, state_root, updated)
        return updated
    except Exception:
        for reference in written:
            (Path(secrets_root) / reference).unlink(missing_ok=True)
        raise


# ----------------------------------------------------------------------------------------------------------- SSH host key (explicit operator actions)

_CANDIDATES: dict[tuple[str, str], tuple[dict, float]] = {}
_LOCK = threading.Lock()
_DISCOVERY_SLOT = threading.Semaphore(1)


def _now(clock) -> datetime:
    return datetime.fromtimestamp(clock(), timezone.utc)


def discover_host_key(key: str, state_root: str, settings, confirmation: object, *, transport=None, clock=time.time) -> dict:
    """Operator-requested: read the gateway's PUBLIC host key (ssh-keyscan, no credential).  The candidate is kept in memory only; nothing is trusted yet."""
    from . import author_builder as AB
    if confirmation != DISCOVER_PHRASE:
        raise _err("confirmation", f"Type the confirmation exactly: {DISCOVER_PHRASE}.")
    if not settings.author_builder_host_key_discovery_enabled:
        raise _err("host_key", "Host-key discovery is turned off on this dashboard host. Obtain the key independently and use 'Paste a reviewed host-key line' instead.", 503)
    draft = _load_gateway_draft(key, state_root)
    gw = draft.gateway
    check_host(gw.host, "gateway.host", "The SSH gateway")
    if not _DISCOVERY_SLOT.acquire(blocking=False):
        raise _err("host_key", "Another host-key discovery is running; try again in a moment.", 429)
    try:
        send = transport or AB.ssh_keyscan_transport
        raw = send(gw.host, gw.port, settings.author_builder_host_key_timeout_seconds, settings.author_builder_host_key_max_bytes)
        algorithm, fingerprint, line = AB.HostKeyDiscoveryService._parse_key(raw, gw.host, gw.port)
    except AB.AuthorBuilderError as exc:
        raise _err("host_key", exc.message, exc.status_code if exc.status_code >= 400 else 409) from None
    finally:
        _DISCOVERY_SLOT.release()
    now = clock()
    expires = now + settings.author_builder_host_key_ttl_seconds
    candidate = {"id": uuid.uuid4().hex, "host": gw.host, "port": gw.port, "key_algorithm": algorithm, "fingerprint": fingerprint,
                 "known_hosts_line": line, "retrieved_at": _now(lambda: now).isoformat().replace("+00:00", "Z"),
                 "expires_at": _now(lambda: expires).isoformat().replace("+00:00", "Z"), "source": "ssh-keyscan from the dashboard host"}
    with _LOCK:
        for k in [k for k, (_c, exp) in _CANDIDATES.items() if exp <= now]:
            _CANDIDATES.pop(k, None)
        while len(_CANDIDATES) >= 64:
            _CANDIDATES.pop(next(iter(_CANDIDATES)))
        _CANDIDATES[(key, candidate["id"])] = (candidate, expires)
    return candidate


def approve_host_key(key: str, state_root: str, service, body: object, *, clock=time.time) -> PI.ProcedureDraft:
    """Operator approval: the reviewed line must name exactly this gateway host and port, and the operator must type the fingerprint they
    obtained INDEPENDENTLY; it must equal the one computed from the line.  Only then is the known-hosts reference written (owner-only)."""
    from . import author_builder as AB
    if not isinstance(body, dict):
        raise _err("host_key", "Provide the reviewed host-key line and the fingerprint you verified.")
    if body.get("confirmation") != APPROVE_PHRASE:
        raise _err("confirmation", f"Type the confirmation exactly: {APPROVE_PHRASE}.")
    line = body.get("reviewed_known_hosts_line")
    expected_fp = body.get("expected_fingerprint")
    candidate_id = body.get("candidate_id")
    if not isinstance(line, str) or not line.strip() or len(line) > 16384 or _CONTROL.search(line.replace("\n", "")):
        raise _err("reviewed_known_hosts_line", "Paste the reviewed host-key line (one OpenSSH known_hosts line).")
    # One-click approval of a DISCOVERED key: the operator states that they compared the fingerprint shown with the gateway's own.  Only for a live,
    # single-use candidate bound to this gateway host and port; a pasted line always needs the independently obtained fingerprint.
    compared = candidate_id is not None and body.get("fingerprint_compared") is True
    typed = isinstance(expected_fp, str) and bool(expected_fp.strip())
    if not typed and not compared:
        raise _err("expected_fingerprint", "Enter the SHA256 fingerprint you obtained independently (for example from ssh-keygen -lf on the gateway), or tick the box saying you compared it.")
    draft = _load_gateway_draft(key, state_root)
    gw = draft.gateway
    shape = gw.host if gw.port == 22 else f"[{gw.host}]:{gw.port}"
    stripped = line.strip()
    fields = stripped.split()
    if len([ln for ln in stripped.splitlines() if ln.strip()]) > 1:
        raise _err("reviewed_known_hosts_line", "Paste exactly one line (ssh-keyscan prints several keys: choose one, normally the ssh-ed25519 line). Nothing was saved.")
    if stripped.startswith("|"):
        raise _err("reviewed_known_hosts_line", f"Hashed known_hosts entries are not accepted. Paste the unhashed line that starts with '{shape} '. Nothing was saved.")
    if fields and re.fullmatch(r"ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)", fields[0]):
        raise _err("reviewed_known_hosts_line", f"That line has no host in front of the key. Start it with '{shape} ' and leave out any comment. Nothing was saved.")
    if len(fields) > 3 and fields[0] == shape:
        raise _err("reviewed_known_hosts_line", "Remove everything after the key data (no comment or options): the line must be exactly HOST ALGORITHM KEY. Nothing was saved.")
    source = "pasted"
    with _LOCK:
        if candidate_id is not None:
            stored = _CANDIDATES.get((key, str(candidate_id)))
            if stored is None or stored[1] <= clock():
                _CANDIDATES.pop((key, str(candidate_id)), None)
                raise _err("candidate_id", "That discovered host key expired or was already used; discover it again.", 404)
            cand = stored[0]
            if (cand["host"], cand["port"]) != (gw.host, gw.port):
                raise _err("candidate_id", "The gateway host or port changed after discovery; discover the key again.", 409)
            if line.strip() != cand["known_hosts_line"]:
                raise _err("reviewed_known_hosts_line", "The reviewed line differs from the discovered key. Nothing was saved.")
            source = "discovered"
    try:
        algorithm, fingerprint, normalised = AB.HostKeyDiscoveryService._parse_key(line.strip().encode("utf-8"), gw.host, gw.port)
    except AB.AuthorBuilderError:
        raise _err("reviewed_known_hosts_line", "That is not a supported OpenSSH host-key line (ssh-ed25519, ecdsa or ssh-rsa).") from None
    try:
        blob = base64.b64decode(normalised.split()[2], validate=True)
        label = blob[4:4 + int.from_bytes(blob[:4], "big")].decode("ascii")
    except Exception:
        label = None
    if label != algorithm:
        raise _err("reviewed_known_hosts_line", "The key data does not match its algorithm label, so it is not a valid host key. Nothing was saved.")
    if line.strip() != normalised:
        raise _err("reviewed_known_hosts_line", f"The line must name exactly this gateway: start it with '{shape} '. Nothing was saved.")
    if not typed:
        expected_fp = fingerprint          # compared == True here: the candidate's own, already bound to this gateway and line
    if expected_fp.strip() != fingerprint:
        raise _err("expected_fingerprint", "The fingerprint you entered does not match this key. Nothing was saved.")
    secrets_root = service._secrets_root()
    reference = f"procedure-{key}-gateway-{_secrets.token_hex(4)}.known_hosts"
    try:
        service.save_known_hosts(KnownHostsSaveRequest(expected_host=gw.host, reference_name=reference, known_hosts=SecretStr(normalised), overwrite=False))
    except TargetSetupError as exc:
        raise _err("reviewed_known_hosts_line", str(exc)) from None
    try:
        new_gw = gw.model_copy(update={"known_hosts_reference": reference, "host_key_algorithm": algorithm, "host_key_fingerprint": fingerprint,
                                       "host_key_source": source, "host_key_approved_at": _now(clock).isoformat(timespec="seconds").replace("+00:00", "Z")})
        updated = draft.model_copy(update={"gateway": new_gw})
        updated = updated.model_copy(update={"manual": PI.render_manual(updated.title, updated.connections, updated.steps, updated.findings, new_gw)})
        if PI.connection_config_hash(updated) != PI.connection_config_hash(draft):
            updated = updated.model_copy(update={"last_test": None})
        updated = PI._with_readiness(updated, secrets_root)
        PI.persist_draft(key, state_root, updated)
    except Exception:
        (Path(secrets_root) / reference).unlink(missing_ok=True)
        raise
    if candidate_id is not None:
        with _LOCK:
            _CANDIDATES.pop((key, str(candidate_id)), None)
    return updated


def confirm_target(key: str, state_root: str, body: object, *, clock=time.time) -> PI.ProcedureDraft:
    """The operator confirms the exact gateway, destination and account.  Bound to the current connection settings: any later edit makes it stale."""
    if not isinstance(body, dict) or body.get("confirmation") != CONFIRM_TARGET_PHRASE:
        raise _err("confirmation", f"Type the confirmation exactly: {CONFIRM_TARGET_PHRASE}.")
    draft = _load_gateway_draft(key, state_root)
    current = PI.connection_config_hash(draft)
    if body.get("config_hash") != current:
        raise _err("config_hash", "The connection settings changed since this page was loaded. Review them again.", 409)
    updated = draft.model_copy(update={"target_confirmation": {"config_hash": current, "at": _now(clock).isoformat(timespec="seconds").replace("+00:00", "Z")}})
    PI.persist_draft(key, state_root, updated)
    return updated
