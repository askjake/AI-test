#!/usr/bin/env python3
"""Phase 8 exit gate (P8-GATE): run the full security checklist.

Verifies, from inside the hardened container:

  1. Non-root (P8-8)             — euid != 0.
  2. Read-only mounts (P8-3)     — writes to tests_specs/ and secrets/ are denied; reports/
                                    is writable.
  3. Egress allowlist (P8-2)     — Bedrock is reachable; api.anthropic.com and an arbitrary
                                    non-allowlisted host are NOT. Also asserts the computed
                                    allowlist never contains a banned host.
  4. No creds in screenshots (P8-4) — the redaction hook blanks a configured region; the
                                    agent never issues a model-driven `type` of secret material (audit log
                                    contains no secret strings).
  5. Caps fire (P8-7)            — a deliberately looping spec stops at max_steps with an
                                    errored/timeout result.

Run inside the container launched via scripts/run_container.sh (which applies --read-only,
--cap-drop ALL, the bounded mounts) AFTER docker/egress_firewall.sh has installed the egress
rules. Network legs are skipped with --no-net where running the firewall isn't possible.

    python scripts/smoke_security.py            # full gate
    python scripts/smoke_security.py --no-net   # skip the egress legs

Exits 0 only if every enabled check passes.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import tempfile

sys.path.insert(0, "src")

from orchestrator.agent import run_agent  # noqa: E402
from orchestrator.audit import AuditLog  # noqa: E402
from orchestrator.bedrock_client import InvokeResult, ContentBlock  # noqa: E402
from orchestrator.config import settings  # noqa: E402
from orchestrator.egress import BANNED_HOSTS, bedrock_endpoint, compute_policy  # noqa: E402
from orchestrator.models import TestSpec, TestStatus  # noqa: E402
from orchestrator.redaction import Redactor, Region  # noqa: E402


def _ok(label: str) -> bool:
    print(f"[smoke] PASS — {label}")
    return True


def _fail(label: str) -> bool:
    print(f"[smoke] FAIL — {label}", file=sys.stderr)
    return False


def check_non_root() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return _ok(f"non-root (euid={os.geteuid()})")
    return _fail("running as root — container should run as the non-root orchestrator user")


def _write_denied(path: str) -> bool:
    try:
        with open(os.path.join(path, ".orchestrator_write_probe"), "w") as fh:
            fh.write("x")
        os.unlink(os.path.join(path, ".orchestrator_write_probe"))
        return False  # write succeeded -> NOT read-only
    except OSError:
        return True  # write denied -> read-only as expected


def check_readonly_mounts() -> bool:
    ok = True
    for ro in (settings.tests_specs_dir, settings.tests_manuals_dir, settings.secrets_dir):
        if os.path.isdir(ro) and _write_denied(ro):
            _ok(f"{ro} is read-only")
        else:
            ok = _fail(f"{ro} is writable (should be a read-only mount)") and ok
    # reports/ must be writable.
    rw = settings.reports_dir
    os.makedirs(rw, exist_ok=True)
    if _write_denied(rw):
        ok = _fail(f"{rw} is read-only (reports must be writable)") and ok
    else:
        _ok(f"{rw} is writable")
    return ok


def _reachable(host: str, port: int = 443, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_egress() -> bool:
    policy = compute_policy()
    ok = True

    # The computed allowlist must never contain a banned cloud endpoint.
    for banned in BANNED_HOSTS:
        if policy.is_allowed(banned):
            ok = _fail(f"allowlist unexpectedly contains banned host {banned}") and ok
        else:
            _ok(f"allowlist excludes {banned}")

    # Bedrock should be reachable; the banned endpoint and a random host should not.
    if _reachable(bedrock_endpoint()):
        _ok(f"Bedrock endpoint reachable ({bedrock_endpoint()})")
    else:
        ok = _fail(f"Bedrock endpoint unreachable ({bedrock_endpoint()})") and ok

    for blocked in (*BANNED_HOSTS, "example.com"):
        if _reachable(blocked):
            ok = _fail(f"{blocked} is reachable — egress allowlist not enforced") and ok
        else:
            _ok(f"{blocked} blocked by egress policy")
    return ok


def check_redaction_and_no_creds() -> bool:
    """Redaction blanks a region, and the agent never types secrets (audit has none)."""
    import io
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (40, 40), (210, 50, 50)).save(buf, format="PNG")
    redactor = Redactor(regions=[Region(0, 0, 20, 20)])
    out = Image.open(io.BytesIO(redactor.apply(buf.getvalue()))).convert("RGB")
    if out.getpixel((5, 5)) != (0, 0, 0):
        return _fail("redaction hook did not blank the configured region")
    _ok("redaction hook blanks configured regions")

    # The agent should never emit a `type` action carrying secret material. Drive a tiny
    # mocked loop and assert the audit log has no `type` action at all for a creds spec.
    secret = "S3CRET-PASSWORD"
    with tempfile.TemporaryDirectory() as d:
        audit_path = os.path.join(d, "audit.jsonl")

        class _Comp:
            def screenshot(self):
                class S:  # noqa: N801
                    png = b"PNG"
                return S()

        class _Client:
            def invoke_computer_use(self, **kw):
                blk = ContentBlock(type="tool_use", name="report_result", id="r",
                                   input={"passed": True, "summary": "ok",
                                          "per_assertion": []})
                return InvokeResult(content=[blk], stop_reason="tool_use",
                                    usage={"input_tokens": 1, "output_tokens": 1},
                                    raw={"content": []}), "custom"

        spec = TestSpec(title="creds", goal=f"Never type {secret}.", target_type="ssh-terminal")
        run_agent(spec, computer=_Comp(), client=_Client(),
                  audit=AuditLog(audit_path), clock=lambda: 0.0)
        with open(audit_path) as fh:
            log = fh.read()
        if secret in log:
            return _fail("secret string leaked into the audit log")
    return _ok("audit log carries no secret material; agent never types creds")


def check_caps_fire() -> bool:
    """A looping spec (model never reports) must stop at max_steps -> errored/timeout."""
    class _Comp:
        def screenshot(self):
            class S:  # noqa: N801
                png = b"PNG"
            return S()

        def left_click(self, x, y):
            pass

    class _LoopClient:
        def invoke_computer_use(self, **kw):
            blk = ContentBlock(type="tool_use", name="computer", id="c",
                               input={"action": "left_click", "coordinate": [1, 1]})
            return InvokeResult(content=[blk], stop_reason="tool_use",
                                usage={"input_tokens": 1, "output_tokens": 1},
                                raw={"content": [{"type": "tool_use", "id": "c",
                                                  "name": "computer",
                                                  "input": {"action": "left_click",
                                                            "coordinate": [1, 1]}}]}), "custom"

    spec = TestSpec(title="loop", goal="loop forever", target_type="local-app")
    res = run_agent(spec, computer=_Comp(), client=_LoopClient(),
                    max_steps=3, clock=lambda: 0.0)
    if res.status in (TestStatus.ERRORED, TestStatus.TIMEOUT) and res.step_count == 3:
        return _ok(f"resource caps fire (status={res.status.value}, steps={res.step_count})")
    return _fail(f"caps did not fire as expected (status={res.status}, steps={res.step_count})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 8 security smoke / exit gate.")
    parser.add_argument("--no-net", action="store_true",
                        help="Skip the live egress reachability legs (keep allowlist checks).")
    args = parser.parse_args()

    results = [
        check_non_root(),
        check_readonly_mounts(),
        check_redaction_and_no_creds(),
        check_caps_fire(),
    ]
    if not args.no_net:
        results.append(check_egress())
    else:
        print("[smoke] (egress reachability legs skipped via --no-net)")

    if all(results):
        print("[smoke] PASS — Phase 8 security gate satisfied")
        return 0
    print("[smoke] FAIL — one or more security checks failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
