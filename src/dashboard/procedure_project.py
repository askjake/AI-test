"""Create an rdp-chain project directory from a reviewed ProcedureDraft (NRDP-1, S2b).

Import-light: stdlib only, no intra-package imports, so it can be exec-tested.
Credentials are referenced by FILENAME only; secret files are checked for existence
and never opened.

project.yaml is written as JSON text (JSON is a strict subset of YAML 1.2, and
``yaml.safe_load`` reads it), which keeps this module free of a PyYAML dependency.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any

MAX_HOPS = 8
MANUAL_DIR = "manual"          # mirrors orchestrator.projects.MANUAL_DIR
MASTER_MANUAL = "manual.md"    # mirrors orchestrator.projects.MASTER_MANUAL
SPEC_NAME = "procedure.md"
REPLACED_DIR = ".replaced"
_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_USER_RE = re.compile(r"[\w.@\\-]{1,256}")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}")
_FP_RE = re.compile(r"(?:sha256:[0-9a-fA-F]{64}|sha1:[0-9a-fA-F]{40})")
_PROJECT_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")
_POLICIES = ("stop", "accept_reviewed_prompt")

GOAL_RULES = [
    "All commands run INSIDE the final Windows desktop (hop {final}) only after the application confirms that desktop.",
    "Credentials are handled by the application; the agent must never type, request, read or repeat a password.",
    "The agent must not run anything on the Linux host or runner; goal text is never a shell command there.",
    "Stop immediately on any unexpected authentication, certificate or identity state.",
    "Operator checkpoints must be requested from the operator and waited for; never skip or self-complete them.",
    "A free TCP port does not prove serial (COM) handles are released.",
    "A Windows service in Running state does not prove the application is healthy.",
    "An HTTP 200 response does not prove correct inventory or physical behaviour.",
    "Open PowerShell as Administrator on the final desktop, then verify elevation with WindowsPrincipal.IsInRole(Administrator) before any service command.",
    "A User Account Control box that only asks Yes/No may be approved for that explicit elevation request; if any box asks for a user name or password, stop.",
    "Control services only with Stop-Service and Start-Service. Never use start.cmd, start.ps1, Manage-Service.ps1, Stop-Process, taskkill, -Force or any forced termination as a substitute or recovery.",
    "If a service does not stop or start in time, stop and report the failure; do not force it.",
    "Execute only the current step; the manual is context, not permission to perform later steps.",
    "Hardware flashing or wiring and the physical Guide/Select button tests are operator checkpoints; their result is never inferred from screenshots or HTTP status.",
]


class ProjectError(Exception):
    def __init__(self, errors: list[dict]):
        self.errors = errors
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))


def _g(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def project_name_for(draft: Any) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(_g(draft, "title", "") or "").lower()).strip("-")[:40].strip("-")
    did = re.sub(r"[^0-9a-f]", "", str(_g(draft, "id", "")).lower())
    return f"{slug or 'procedure'}-{did[:8] or 'draft'}"


def _hops(draft: Any) -> list[Any]:
    return sorted(list(_g(draft, "connections", None) or []), key=lambda h: int(_g(h, "order", 0)))


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.fullmatch(host or ""))


def validate_draft(draft: Any, *, secrets_root: str | None) -> list[dict]:
    errs: list[dict] = []
    hops = _hops(draft)
    if not hops:
        return [{"field": "connections", "message": "At least one RDP or VNC connection is required."}]
    if any(_g(h, "protocol", "rdp") == "vnc" for h in hops):
        return _validate_vnc_draft(draft, hops, secrets_root)
    if len(hops) > MAX_HOPS:
        errs.append({"field": "connections", "message": f"At most {MAX_HOPS} hops are supported."})
    for i, h in enumerate(hops):
        f = f"connections[{i}]"
        order = _g(h, "order")
        if order != i + 1:
            errs.append({"field": f + ".order", "message": "Hop orders must be 1..N and contiguous."})
        host = str(_g(h, "host", "") or "")
        if not _valid_host(host):
            errs.append({"field": f + ".host", "message": "Enter a valid IP address or hostname."})
        port = _g(h, "port", 3389)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errs.append({"field": f + ".port", "message": "Port must be between 1 and 65535."})
        if not _USER_RE.fullmatch(str(_g(h, "user", "") or "")):
            errs.append({"field": f + ".user", "message": "Enter a valid username."})
        ref = str(_g(h, "password_reference", "") or "")
        if not _REF_RE.fullmatch(ref) or ".." in ref:
            errs.append({"field": f + ".credential", "message": "A saved password reference is required."})
        elif secrets_root is not None:
            p = os.path.join(secrets_root, ref)
            if not os.path.isfile(p) or os.path.islink(p):   # existence only; never read
                errs.append({"field": f + ".credential", "message": "The saved password is missing; replace the password for this hop."})
        policy = _g(h, "identity_policy", None) or "stop"
        if policy not in _POLICIES:
            errs.append({"field": f + ".identity_policy", "message": "identity_policy must be 'stop' or 'accept_reviewed_prompt'."})
        if i == 0:
            if not str(_g(h, "certificate_name", "") or "").strip():
                errs.append({"field": f + ".certificate.name", "message": "Review and save the hop-1 certificate name."})
            if not _FP_RE.fullmatch(str(_g(h, "certificate_fingerprint", "") or "")):
                errs.append({"field": f + ".certificate.fingerprint", "message": "Review and save the hop-1 certificate fingerprint (sha256:<64 hex> or sha1:<40 hex>)."})
    if not re.fullmatch(r"[0-9a-f]{32}", str(_g(draft, "id", ""))):
        errs.append({"field": "id", "message": "Invalid procedure draft ID."})
    return errs


def _validate_vnc_draft(draft: Any, hops: list, secrets_root: str | None) -> list[dict]:
    errs: list[dict] = []
    if len(hops) != 1 or any(_g(h, "protocol", "rdp") != "vnc" for h in hops):
        return [{"field": "connections", "message": "A VNC procedure has exactly one VNC connection; mixed RDP/VNC chains are not supported."}]
    h = hops[0]
    f = "connections[0]"
    if not _valid_host(str(_g(h, "host", "") or "")):
        errs.append({"field": f + ".host", "message": "Enter a valid IP address or hostname."})
    port = _g(h, "port", 5900)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errs.append({"field": f + ".port", "message": "VNC TCP port must be between 1 and 65535."})
    display = _g(h, "display", None)
    if display is not None and (not isinstance(display, int) or isinstance(display, bool) or not 0 <= display <= 99 or port != 5900 + display):
        errs.append({"field": f + ".display", "message": "VNC display must be 0-99 and match TCP port 5900 + display."})
    user = str(_g(h, "user", "") or "")
    if user and not re.fullmatch(r"[^\x00-\x1f\x7f]{1,256}", user):
        errs.append({"field": f + ".user", "message": "Enter a valid username or leave it empty."})
    if _g(h, "auth_method", "vnc-password") != "vnc-password":
        errs.append({"field": f + ".auth_method", "message": "The runner's VNC viewer supports password-only authentication; a username + password method cannot be executed."})
    ref = str(_g(h, "password_reference", "") or "")
    if not _REF_RE.fullmatch(ref) or ".." in ref:
        errs.append({"field": f + ".credential", "message": "A saved password reference is required."})
    elif secrets_root is not None:
        p = os.path.join(secrets_root, ref)
        if not os.path.isfile(p) or os.path.islink(p):
            errs.append({"field": f + ".credential", "message": "The saved password is missing; replace the password for this connection."})
    if not re.fullmatch(r"[0-9a-f]{32}", str(_g(draft, "id", ""))):
        errs.append({"field": "id", "message": "Invalid procedure draft ID."})
    gw = _g(draft, "gateway", None)
    if gw is not None:
        errs += _validate_gateway(gw, secrets_root)
    return errs


_GW_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}")


def _validate_gateway(gw: Any, secrets_root: str | None) -> list[dict]:
    errs: list[dict] = []
    if not _valid_host(str(_g(gw, "host", "") or "")):
        errs.append({"field": "gateway.host", "message": "Enter a valid gateway IP address or hostname."})
    port = _g(gw, "port", 22)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errs.append({"field": "gateway.port", "message": "The SSH port must be between 1 and 65535."})
    if not _GW_USER_RE.fullmatch(str(_g(gw, "user", "") or "")):
        errs.append({"field": "gateway.user", "message": "Enter the SSH username."})
    for name, field, missing in (("password_reference", "gateway.credential", "A saved gateway credential is required."),
                                 ("known_hosts_reference", "gateway.host_key", "Approve the gateway host key before creating the project.")):
        ref = str(_g(gw, name, "") or "")
        if not ref:
            errs.append({"field": field, "message": missing})
        elif not _REF_RE.fullmatch(ref) or ".." in ref:
            errs.append({"field": field, "message": "Invalid saved reference."})
        elif secrets_root is not None:
            p = os.path.join(secrets_root, ref)
            if not os.path.isfile(p) or os.path.islink(p):
                errs.append({"field": field, "message": "The saved file is missing; save or approve it again."})
    if not _g(gw, "host_key_fingerprint", None):
        errs.append({"field": "gateway.host_key", "message": "Approve the gateway host key before creating the project."})
    return errs


def validate_vnc_yaml(doc: dict) -> list[dict]:
    errs: list[dict] = []
    t = doc.get("target") if isinstance(doc, dict) else None
    if not isinstance(t, dict) or t.get("type") != "vnc":
        return [{"field": "target.type", "message": "target.type must be vnc."}]
    if not _valid_host(str(t.get("host", ""))):
        errs.append({"field": "target.host", "message": "Invalid host."})
    port = str(t.get("port", ""))
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        errs.append({"field": "target.port", "message": "Invalid VNC TCP port."})
    if not _REF_RE.fullmatch(str(t.get("password_file", ""))) or ".." in str(t.get("password_file", "")):
        errs.append({"field": "target.password_file", "message": "Invalid password reference."})
    for forbidden in ("password", "user", "username"):
        if forbidden in t:
            errs.append({"field": "target." + forbidden, "message": "Credentials and unused usernames are not written to project.yaml."})
    if doc.get("vnc_host_allowlist") != [t.get("host")]:
        errs.append({"field": "vnc_host_allowlist", "message": "vnc_host_allowlist must contain only the VNC host."})
    route, gpf = t.get("route"), t.get("gateway_password_file")
    if route is None:
        if gpf is not None:
            errs.append({"field": "target.gateway_password_file", "message": "A gateway credential needs an ssh-jump route."})
    else:
        if (not isinstance(route, dict) or route.get("type") != "ssh-jump" or set(route) - {"type", "host", "user", "port", "known_hosts_file"}):
            errs.append({"field": "target.route", "message": "The only supported VNC route is a typed ssh-jump mapping (type, host, user, port, known_hosts_file)."})
        else:
            rport = route.get("port")
            if not _valid_host(str(route.get("host", ""))):
                errs.append({"field": "target.route.host", "message": "Invalid gateway host."})
            if not _GW_USER_RE.fullmatch(str(route.get("user", ""))):
                errs.append({"field": "target.route.user", "message": "Invalid gateway user."})
            if not isinstance(rport, int) or isinstance(rport, bool) or not 1 <= rport <= 65535:
                errs.append({"field": "target.route.port", "message": "Invalid gateway port."})
            for value, field in ((route.get("known_hosts_file"), "target.route.known_hosts_file"), (gpf, "target.gateway_password_file")):
                if not _REF_RE.fullmatch(str(value or "")) or ".." in str(value or ""):
                    errs.append({"field": field, "message": "Invalid saved reference."})
            if doc.get("ssh_host_allowlist") != [route.get("host")]:
                errs.append({"field": "ssh_host_allowlist", "message": "ssh_host_allowlist must contain only the SSH gateway."})
    proc = doc.get("procedure")
    if not isinstance(proc, dict) or proc.get("protocol") != "vnc" or proc.get("final_hop") != 1:
        errs.append({"field": "procedure", "message": "A VNC procedure block with final_hop 1 is required."})
    elif not isinstance(proc.get("steps"), list):
        errs.append({"field": "procedure.steps", "message": "steps must be a list."})
    if not doc.get("manual_dir"):
        errs.append({"field": "manual_dir", "message": "manual_dir is required."})
    return errs


def validate_chain_yaml(doc: dict) -> list[dict]:
    """Validate a parsed project.yaml dict against the NRDP contract."""
    errs: list[dict] = []
    t = doc.get("target") if isinstance(doc, dict) else None
    if not isinstance(t, dict) or t.get("type") != "rdp-chain":
        return [{"field": "target.type", "message": "target.type must be rdp-chain."}]
    chain = t.get("chain")
    if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_HOPS:
        return [{"field": "target.chain", "message": f"target.chain must list 1..{MAX_HOPS} hops."}]
    for i, h in enumerate(chain):
        f = f"target.chain[{i}]"
        if not isinstance(h, dict):
            errs.append({"field": f, "message": "Each hop must be a mapping."}); continue
        if h.get("order") != i + 1:
            errs.append({"field": f + ".order", "message": "Orders must be contiguous from 1."})
        if not _valid_host(str(h.get("host", ""))):
            errs.append({"field": f + ".host", "message": "Invalid host."})
        p = h.get("port", 3389)
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            errs.append({"field": f + ".port", "message": "Invalid port."})
        if not _USER_RE.fullmatch(str(h.get("user", ""))):
            errs.append({"field": f + ".user", "message": "Invalid user."})
        if not _REF_RE.fullmatch(str(h.get("password_file", ""))) or ".." in str(h.get("password_file", "")):
            errs.append({"field": f + ".password_file", "message": "Invalid password reference."})
        if "password" in h:
            errs.append({"field": f + ".password", "message": "Password values are forbidden in project.yaml."})
        if h.get("identity_policy", "stop") not in _POLICIES:
            errs.append({"field": f + ".identity_policy", "message": "Invalid identity_policy."})
        if i == 0:
            if not h.get("certificate_name"):
                errs.append({"field": f + ".certificate_name", "message": "Hop 1 needs certificate_name."})
            if not _FP_RE.fullmatch(str(h.get("certificate_fingerprint", ""))):
                errs.append({"field": f + ".certificate_fingerprint", "message": "Hop 1 needs a sha256/sha1 fingerprint."})
        elif "certificate_name" in h or "certificate_fingerprint" in h:
            errs.append({"field": f + ".certificate_name", "message": "Certificate pinning applies to hop 1 only."})
    if isinstance(chain[0], dict) and doc.get("rdp_host_allowlist") != [chain[0].get("host")]:
        errs.append({"field": "rdp_host_allowlist", "message": "rdp_host_allowlist must contain only hop 1."})
    if doc.get("chain_hosts") != [h.get("host") for h in chain if isinstance(h, dict)]:
        errs.append({"field": "chain_hosts", "message": "chain_hosts must list every hop host in order."})
    proc = doc.get("procedure")
    if not isinstance(proc, dict):
        errs.append({"field": "procedure", "message": "procedure block is required."})
    else:
        if proc.get("final_hop") != len(chain):
            errs.append({"field": "procedure.final_hop", "message": "final_hop must equal the number of hops."})
        steps = proc.get("steps")
        if not isinstance(steps, list):
            errs.append({"field": "procedure.steps", "message": "steps must be a list."})
        else:
            cps = [s.get("order") for s in steps if isinstance(s, dict) and s.get("kind") == "operator-checkpoint"]
            if sorted(proc.get("required_checkpoints") or []) != sorted(cps):
                errs.append({"field": "procedure.required_checkpoints", "message": "Every operator checkpoint must be required."})
    if not doc.get("manual_dir"):
        errs.append({"field": "manual_dir", "message": "manual_dir is required."})
    return errs


def _step_dict(s: Any) -> dict:
    kind = str(_g(s, "kind", "procedure-step"))
    mutating = _g(s, "mutating", None)
    if mutating is None:
        mutating = kind == "operator-checkpoint" or bool(re.search(r"(?i)\b(Stop|Start|Restart|Set|Remove|New)-\w+", str(_g(s, "instructions", ""))))
    ro = _g(s, "read_only_ok", None)
    if ro is None:
        ro = (not mutating) and kind == "procedure-step"
    return {"order": int(_g(s, "order")), "title": str(_g(s, "title", "")), "kind": kind,
            "mutating": bool(mutating), "read_only_ok": bool(ro) and kind != "operator-checkpoint",
            "instructions": str(_g(s, "instructions", "") or ""),
            "completion_checks": [str(c) for c in (_g(s, "completion_checks", None) or [])]}


VNC_GOAL_RULES = [
    "All actions are taken on the VNC desktop of the runner's viewer window; there is no other machine in this procedure.",
    "Credentials are handled by the application; the agent must never type, request, read or repeat a password.",
    "The agent must not run anything on the Linux host or runner; goal text is never a shell command there.",
    "Stop immediately on any unexpected login, lock or authentication screen; do not try credentials.",
    "Execute only the current step; the manual is context, not permission to perform later steps.",
    "Leave every application the steps opened (for example a browser) open when the steps are done. Never close it, never log off, lock or shut down the remote machine.",
    "Operator checkpoints must be requested from the operator and waited for; never skip or self-complete them.",
]

# A VNC-through-SSH test closes ONLY the application instance it opened (session_end.remote_applications == close_test_instance_only).
VNC_GOAL_RULES_CLOSE_TEST_INSTANCE = [
    r if not r.startswith("Leave every application") else
    "When the steps are done, close ONLY the application instance this test opened. Never close any window, application or instance that was already open before the test, never log off, lock or shut down the remote machine."
    for r in VNC_GOAL_RULES
]


def build_vnc_project_doc(draft: Any) -> dict:
    h = _hops(draft)[0]
    steps = [_step_dict(s) for s in (_g(draft, "steps", None) or []) if str(_g(s, "kind", "")) != "needs-input"]
    host = str(_g(h, "host"))
    return {
        "name": project_name_for(draft), "enabled": True, "manual_dir": "./" + MANUAL_DIR,
        "target": {"type": "vnc", "host": host, "port": str(int(_g(h, "port", 5900) or 5900)), "password_file": str(_g(h, "password_reference"))},
        "vnc_host_allowlist": [host],
        "procedure": {"draft_id": str(_g(draft, "id")), "protocol": "vnc", "final_hop": 1, "display": _g(h, "display", None),
                      "username_recorded": bool(_g(h, "user")), "auth_method": _g(h, "auth_method", "vnc-password"),
                      "session_end": dict(_g(draft, "session_end", None) or {"remote_applications": "leave_open", "automation_client": "disconnect", "remote_session": "never_log_off"}),
                      "steps": steps, "required_checkpoints": [s["order"] for s in steps if s["kind"] == "operator-checkpoint"]},
    }


def _with_gateway(doc: dict, draft: Any) -> dict:
    gw = _g(draft, "gateway", None)
    if gw is None:
        return doc
    doc["target"]["gateway_password_file"] = str(_g(gw, "password_reference"))
    doc["target"]["route"] = {"type": "ssh-jump", "host": str(_g(gw, "host")), "user": str(_g(gw, "user")), "port": int(_g(gw, "port", 22) or 22),
                              "known_hosts_file": str(_g(gw, "known_hosts_reference"))}
    doc["ssh_host_allowlist"] = [str(_g(gw, "host"))]
    return doc


def build_project_doc(draft: Any) -> dict:
    hops = _hops(draft)
    if hops and _g(hops[0], "protocol", "rdp") == "vnc":
        return _with_gateway(build_vnc_project_doc(draft), draft)
    chain = []
    for i, h in enumerate(hops):
        e: dict[str, Any] = {"order": int(_g(h, "order")), "host": str(_g(h, "host")), "port": int(_g(h, "port", 3389) or 3389),
                             "user": str(_g(h, "user")), "password_file": str(_g(h, "password_reference"))}
        if _g(h, "label"):
            e["label"] = str(_g(h, "label"))
        if i == 0:
            e["certificate_name"] = str(_g(h, "certificate_name", "") or "")
            e["certificate_fingerprint"] = str(_g(h, "certificate_fingerprint", "") or "")
        else:
            e["identity_policy"] = str(_g(h, "identity_policy", None) or "stop")
        chain.append(e)
    steps = [_step_dict(s) for s in (_g(draft, "steps", None) or []) if str(_g(s, "kind", "")) != "needs-input"]
    name = project_name_for(draft)
    return {
        "name": name,
        "enabled": True,
        "manual_dir": "./" + MANUAL_DIR,   # the loader only accepts "./manual" (project-relative) here; a bare "manual" resolves against the CWD and the project is silently skipped
        "target": {"type": "rdp-chain", "chain": chain},
        "rdp_host_allowlist": [chain[0]["host"]] if chain else [],
        "chain_hosts": [h["host"] for h in chain],
        "procedure": {"draft_id": str(_g(draft, "id")), "final_hop": len(chain), "steps": steps,
                      "required_checkpoints": [s["order"] for s in steps if s["kind"] == "operator-checkpoint"]},
    }


def render_spec(doc: dict, title: str) -> str:
    if doc.get("procedure", {}).get("protocol") == "vnc":
        lines = [f"# {title}", "", "## Goal", "", "Perform the reviewed operating procedure on the VNC desktop shown in the viewer window.", ""]
        close_only = (doc["procedure"].get("session_end") or {}).get("remote_applications") == "close_test_instance_only"
        lines += ["- " + r for r in (VNC_GOAL_RULES_CLOSE_TEST_INSTANCE if close_only else VNC_GOAL_RULES)]
        lines += ["", "## Steps", ""]
        for s in doc["procedure"]["steps"]:
            tag = "operator checkpoint" if s["kind"] == "operator-checkpoint" else ("mutating" if s["mutating"] else "read-only")
            lines.append(f"{s['order']}. {s['title']} ({tag})")
        lines += ["", "## Assertions", ""]
        for s in doc["procedure"]["steps"]:
            for c in s["completion_checks"]:
                lines.append(f"- Step {s['order']}: {c}")
        if not any(s["completion_checks"] for s in doc["procedure"]["steps"]):
            lines.append("- The VNC desktop is visible and responsive before any step.")
        return "\n".join(lines) + "\n"
    final = doc["procedure"]["final_hop"]
    lines = [f"# {title}", "", "## Goal", "",
             f"Perform the reviewed operating procedure on the final Windows desktop (hop {final}) reached through nested Remote Desktop.", ""]
    lines += ["- " + r.format(final=final) for r in GOAL_RULES]
    lines += ["", "## Steps", ""]
    for s in doc["procedure"]["steps"]:
        tag = "operator checkpoint" if s["kind"] == "operator-checkpoint" else ("mutating" if s["mutating"] else "read-only")
        lines.append(f"{s['order']}. {s['title']} ({tag})")
    lines += ["", "## Assertions", ""]
    for s in doc["procedure"]["steps"]:
        for c in s["completion_checks"]:
            lines.append(f"- Step {s['order']}: {c}")
    if not any(s["completion_checks"] for s in doc["procedure"]["steps"]):
        lines.append(f"- The final desktop (hop {final}) is confirmed by the application before any step.")
    return "\n".join(lines) + "\n"


def _secret_values(secrets_root: str | None, draft: Any) -> list[str]:
    """Never reads secrets; returns nothing. Kept as an explicit hook for the scrub test."""
    return []


def render_project_files(draft: Any, *, forbidden: list[str] | None = None) -> dict[str, str]:
    """Pure: relpath -> text. ``forbidden`` = strings (e.g. test passwords) that must not appear."""
    doc = build_project_doc(draft)
    title = str(_g(draft, "title", "") or "Procedure")
    manual = str(_g(draft, "manual", "") or f"# {title}\n")
    files = {
        "project.yaml": json.dumps(doc, indent=2, sort_keys=False) + "\n",
        f"{MANUAL_DIR}/{MASTER_MANUAL}": manual if manual.endswith("\n") else manual + "\n",
        SPEC_NAME: render_spec(doc, title),
    }
    for text in files.values():
        assert not re.search(r"(?im)^\s*(?:password|passwd)\s*[:=]\s*\S", text), "password field in generated file"
        for value in forbidden or []:
            assert not value or value not in text, "secret value in generated file"
    return files


def _existing_for_draft(specs_root: str, draft_id: str) -> str | None:
    try:
        names = sorted(os.listdir(specs_root))
    except OSError:
        return None
    for n in names:
        if n.startswith(".") or not _PROJECT_RE.fullmatch(n):
            continue
        p = os.path.join(specs_root, n, "project.yaml")
        try:
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("procedure"), dict) and doc["procedure"].get("draft_id") == draft_id:
            return n
    return None


def create_project(draft, *, specs_root: str, secrets_root: str, replace: bool = False) -> dict:
    errs = validate_draft(draft, secrets_root=secrets_root)
    if errs:
        raise ProjectError(errs)
    warnings: list[str] = []
    files = render_project_files(draft)
    doc = json.loads(files["project.yaml"])
    cerrs = validate_vnc_yaml(doc) if doc.get("target", {}).get("type") == "vnc" else validate_chain_yaml(doc)
    if cerrs:
        raise ProjectError(cerrs)
    if not doc["procedure"]["steps"]:
        warnings.append("No operating steps yet: only a connection test is meaningful.")
    root = os.path.abspath(specs_root)
    os.makedirs(root, exist_ok=True)
    draft_id = str(_g(draft, "id"))
    existing = _existing_for_draft(root, draft_id)
    if existing and not replace:
        return {"project_name": existing, "warnings": ["Project already exists for this draft; returned unchanged."]}
    name = existing or doc["name"]
    if not _PROJECT_RE.fullmatch(name):
        raise ProjectError([{"field": "title", "message": "Could not derive a valid project name."}])
    final = os.path.join(root, name)
    if os.path.exists(final) and not existing:
        raise ProjectError([{"field": "title", "message": f"A different project named {name!r} already exists."}])
    tmp = tempfile.mkdtemp(prefix=".nrdp-", dir=root)
    try:
        os.chmod(tmp, 0o755)
        for rel, text in files.items():
            p = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True, mode=0o755)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(p, 0o644)
        if os.path.exists(final):
            backups = os.path.join(root, REPLACED_DIR)
            os.makedirs(backups, exist_ok=True, mode=0o700)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            os.rename(final, os.path.join(backups, f"{name}.{stamp}"))
            warnings.append("Previous project version moved to .replaced/.")
        os.rename(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return {"project_name": name, "warnings": warnings}
