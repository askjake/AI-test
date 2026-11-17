#!/usr/bin/env python3
"""Phase 3 exit gate (P3-GATE): open each target type and screenshot it; refuse a bad host.

Run inside the (podman) container, where Xvfb + a WM are up via entrypoint.sh. ssh/rdp
targets only run if reachable allowlisted hosts are configured via env; otherwise those
legs are skipped (and reported as skipped). The non-allowlisted refusal leg always runs.

    SSH_HOST_ALLOWLIST=build01 SMOKE_SSH_USER=ci SMOKE_SSH_KEY=id_build01 \
        python scripts/smoke_targets.py

Exits 0 if the allowlist refusal fires and every attempted target is captured as a
focusable window, 1 otherwise.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "src")

from orchestrator.computer import Computer  # noqa: E402
from orchestrator.targets import HostNotAllowedError, TargetSpec, Targets  # noqa: E402


def _open_and_capture(t: Targets, comp: Computer, spec: TargetSpec) -> bool:
    handle = t.open_target(spec)
    try:
        shot = comp.screenshot()
        ok = bool(shot.png) and handle.window_id is not None
        print(
            f"[smoke] {spec.type}: window={handle.window_name} id={handle.window_id} "
            f"screenshot={len(shot.png)} bytes -> {'OK' if ok else 'FAIL'}"
        )
        return ok
    finally:
        t.close_target(handle)


def main() -> int:
    t = Targets()
    comp = Computer()
    ok = True

    # 1) Non-allowlisted host must be refused before any launch (security gate).
    try:
        t.open_target(TargetSpec("ssh-terminal", {"host": "evil.example.invalid", "user": "x"}))
        print("[smoke] FAIL — non-allowlisted ssh host was NOT refused", file=sys.stderr)
        ok = False
    except HostNotAllowedError:
        print("[smoke] refusal OK — non-allowlisted ssh host rejected")

    # 2) local-app: launch a sample GUI app (xterm) and capture it.
    ok &= _open_and_capture(
        t, comp, TargetSpec("local-app", {"app": "xterm -T orchestrator-local", "window": "orchestrator-local"})
    )

    # 3) ssh-terminal: only if an allowlisted host + creds are configured.
    ssh_host = os.environ.get("SMOKE_SSH_HOST")
    if ssh_host:
        params = {"host": ssh_host}
        if os.environ.get("SMOKE_SSH_USER"):
            params["user"] = os.environ["SMOKE_SSH_USER"]
        if os.environ.get("SMOKE_SSH_KEY"):
            params["key"] = os.environ["SMOKE_SSH_KEY"]
        ok &= _open_and_capture(t, comp, TargetSpec("ssh-terminal", params))
    else:
        print("[smoke] ssh-terminal: SKIPPED (set SMOKE_SSH_HOST to run)")

    # 4) rdp: only if an allowlisted host is configured.
    rdp_host = os.environ.get("SMOKE_RDP_HOST")
    if rdp_host:
        params = {"host": rdp_host}
        if os.environ.get("SMOKE_RDP_USER"):
            params["user"] = os.environ["SMOKE_RDP_USER"]
        if os.environ.get("SMOKE_RDP_PASSWORD_FILE"):
            params["password_file"] = os.environ["SMOKE_RDP_PASSWORD_FILE"]
        ok &= _open_and_capture(t, comp, TargetSpec("rdp", params))
    else:
        print("[smoke] rdp: SKIPPED (set SMOKE_RDP_HOST to run)")

    # 5) vnc: only if an allowlisted host is configured.
    vnc_host = os.environ.get("SMOKE_VNC_HOST")
    if vnc_host:
        params = {"host": vnc_host}
        if os.environ.get("SMOKE_VNC_PORT"):
            params["port"] = os.environ["SMOKE_VNC_PORT"]
        if os.environ.get("SMOKE_VNC_PASSWORD_FILE"):
            params["password_file"] = os.environ["SMOKE_VNC_PASSWORD_FILE"]
        ok &= _open_and_capture(t, comp, TargetSpec("vnc", params))
    else:
        print("[smoke] vnc: SKIPPED (set SMOKE_VNC_HOST to run)")

    if ok:
        print("[smoke] PASS — targets open as focusable windows; bad host refused")
        return 0
    print("[smoke] FAIL — see messages above", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
