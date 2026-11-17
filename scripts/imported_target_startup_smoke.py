#!/usr/bin/env python3
"""Open and close one imported target without invoking AWS or a model."""

from __future__ import annotations

import argparse
from pathlib import Path

from orchestrator.config import settings
from orchestrator.projects import find_project
from orchestrator.targets import TargetSpec, Targets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project")
    args = parser.parse_args()

    project = find_project(args.project)
    if project is None:
        raise SystemExit(f"project not found: {args.project}")
    config = project.config
    log_dir = Path(settings.reports_dir) / ".startup-smoke" / args.project
    log_dir.mkdir(parents=True, exist_ok=True)
    targets = Targets(
        ssh_host_allowlist=list(config.ssh_host_allowlist),
        rdp_host_allowlist=list(config.rdp_host_allowlist),
        vnc_host_allowlist=list(config.vnc_host_allowlist),
        secrets_dir=settings.secrets_dir,
        log_dir=str(log_dir),
    )
    handle = targets.open_target(
        TargetSpec(config.target.type, dict(config.target.params))
    )
    try:
        if handle.window_id is None:
            raise SystemExit("target opened without an accessible window")
        title = targets._run(["xdotool", "getwindowname", handle.window_id]).strip()
        print(
            f"IMPORTED_TARGET_STARTUP_SMOKE=PASS project={args.project} "
            f"target_type={handle.type} window_id={handle.window_id} "
            f"window_title={title!r}"
        )
        print("AWS_CONTACT=false")
        print("MODEL_CONTACT=false")
    finally:
        targets.close_target(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
