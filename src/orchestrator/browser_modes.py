"""Canonical run-mode vocabulary and the browser_verify request grant (CP43, b4r12-dev).

ONE vocabulary, imported by the dashboard API (procedure_runs) and the runner (chain_runtime / chain_hooks), each of which enforces it INDEPENDENTLY:
the runner never trusts that the API ran.  A request reaches a browser launch only through ``validate_browser_request``, which produces an immutable
``BrowserGrant`` -- and only ``chain_runtime.read_run_request`` (the runner's own validation of the on-disk request) creates one.

Nothing a model says can create, widen or carry a grant: model output is never an input to this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

CONNECTION_TEST = "connection_test"
BROWSER_VERIFY = "browser_verify"
READ_ONLY_CHECK = "read_only_check"
FULL_RUN = "full_run"
CANONICAL_MODES = (CONNECTION_TEST, BROWSER_VERIFY, READ_ONLY_CHECK, FULL_RUN)       # the whole vocabulary: anything else is rejected
OPERATING_MODES = (READ_ONLY_CHECK, FULL_RUN)                                       # always refused (connection-only qualification)
BLOCK_KEYS = frozenset({"url", "confirm_phrase", "leave_open_ack", "binding"})       # the serialized request's browser_verify block, exactly
REFUSED_MODE = "refused"          # the ONLY mode a refused request carries: nothing can mistake it for connection_test
UNRECOGNIZED = "unrecognized"                                                        # fixed marker recorded as requested_mode for an invalid value
LEGACY_REASON = "legacy run request without a mode: connection_test only (documented compatibility path; never browser_verify or operating steps)"
API_PRECHECK_RUN_ID = "trig_api_precheck"                                            # syntactic placeholder: the real run id exists only after launch


def is_canonical(mode: Any) -> bool:
    return isinstance(mode, str) and mode in CANONICAL_MODES


def connection_binding(project: Any, rows: Any) -> str:
    """Fingerprint of WHICH project and WHICH machines (order, host, port, user).  Computed by the API from the saved draft and recomputed by the
    runner from the project it actually loaded, so a request made for other settings or another project is refused as stale.  (The wider dashboard
    config_hash also covers credential references and certificates; the runner cannot recompute that and does not claim to.)"""
    return hashlib.sha256(json.dumps([str(project), rows], separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()


def hop_rows_from_draft(draft: Any) -> list:
    """Revision rows from the saved draft.  NON-SECRET metadata only: order, host, port, user, the credential REFERENCE NAME (a file name, not the
    password and not derived from it), the certificate name/fingerprint and the identity policy.  No credential value or password digest is ever read."""
    return [[int(h.order), str(h.host), int(h.port), str(h.user), str(h.password_reference), str(h.certificate_name or ""),
             str(h.certificate_fingerprint or ""), str(h.identity_policy)] for h in draft.connections]


def hop_rows_from_chain(hops: Any) -> list:
    """The same rows from the project the RUNNER loaded (project.yaml)."""
    return [[int(h.order), str(h.host), int(h.port), str(h.user), str(h.password_file), str(h.certificate_name or ""),
             str(h.certificate_fingerprint or ""), str(h.identity_policy)] for h in hops]


@dataclass(frozen=True)
class BrowserGrant:
    project: str
    run_id: str
    url: str
    binding: str


def validate_browser_request(*, policy: Any, project: str, run_id: str, block: Any, expected_binding: Any) -> tuple[Any, str]:
    """(grant, "") or (None, fixed_code).  Order: capability -> shape -> mode/project/url/confirmation/acknowledgement -> project binding."""
    from orchestrator import browser_verify as bv
    if not isinstance(block, dict) or set(block) != BLOCK_KEYS or not all(isinstance(block[k], str) for k in BLOCK_KEYS):
        # capability is still reported first so a disabled build never reveals more than "disabled"
        refusal = bv.validate_request(bv.BrowserVerifyRequest(), policy)
        return None, ("CAPABILITY_DISABLED" if refusal and refusal[0] == "CAPABILITY_DISABLED" else "BROWSER_BLOCK_MALFORMED")
    req = bv.BrowserVerifyRequest(project=project, run_id=run_id, requested_mode=bv.MODE_NAME, url=block["url"],
                                  confirm_phrase=block["confirm_phrase"], leave_open_ack=block["leave_open_ack"])
    refusal = bv.validate_request(req, policy)               # capability, mode, project allow-list, run id, exact URL, confirmation, leave-open ack
    if refusal:
        return None, refusal[0]
    if not isinstance(expected_binding, str) or not expected_binding:
        return None, "REVISION_UNVERIFIABLE"
    if not hmac.compare_digest(block["binding"].encode("utf-8"), expected_binding.encode("utf-8")):
        return None, "REVISION_MISMATCH"
    return BrowserGrant(project=project, run_id=run_id, url=block["url"], binding=block["binding"]), ""


def api_precheck(policy: Any, project: str, url: Any, confirm_phrase: Any, leave_open_ack: Any) -> tuple[str, str] | None:
    """The API's own first-line check (same gate function, placeholder run id).  The runner repeats the full check with the real run id."""
    from orchestrator import browser_verify as bv
    req = bv.BrowserVerifyRequest(project=project, run_id=API_PRECHECK_RUN_ID, requested_mode=bv.MODE_NAME,
                                  url=url if isinstance(url, str) else "", confirm_phrase=confirm_phrase if isinstance(confirm_phrase, str) else "",
                                  leave_open_ack=leave_open_ack if isinstance(leave_open_ack, str) else "")
    return bv.validate_request(req, policy)


def run_status_from(res: Any) -> str:
    """Run-level status from the verifier result.  Playback and cleanup stay separate fields; this only decides passed/failed/incomplete/errored."""
    res = res if isinstance(res, dict) else {}
    st = res.get("status")
    if st == "completed":
        return {"PLAYBACK_ADVANCING_ALL": "passed", "PLAYBACK_NOT_ADVANCING": "failed", "PLAYBACK_ADVANCING_PARTIAL": "failed"}.get(res.get("verdict"), "incomplete")
    if st in ("cancelled", "partial"):
        return "incomplete"
    return "errored"
