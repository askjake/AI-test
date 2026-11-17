"""Prepared-host, target-free native Watch & Learn transport acceptance."""
from __future__ import annotations

import os
from pathlib import Path
import secrets

from .authoring import LocalAppTarget, ProjectDocument
from .capture_adapter import RunnerControlledCaptureAdapter
from .config import DashboardSettings


def _project() -> ProjectDocument:
    return ProjectDocument(
        dir_name="phase17-native-self-test",
        display_name="Phase 17 target-free native self-test",
        schedule=None,
        target=LocalAppTarget(
            app="self-test-target-is-never-opened",
            window="self-test-target-is-never-opened",
        ),
        redaction=[[0, 0, 32, 32]],
        max_steps=1,
        max_seconds=30,
    )


def main() -> int:
    image = os.environ.get("DASHBOARD_WATCH_LEARN_RUNNER_IMAGE", "")
    settings = DashboardSettings(watch_learn_runner_image=image or None)
    root = str(Path(__file__).resolve().parents[2])
    adapter = RunnerControlledCaptureAdapter(settings, repo_root=root)
    try:
        result = adapter.transport_self_test(secrets.token_hex(16), _project())
        if result.outcome != "executed":
            raise RuntimeError("native worker returned a non-executed outcome")
    except Exception as exc:
        print("NATIVE_TRANSPORT_SELF_TEST=NOT_RUN_BLOCKED")
        print("ABSENT_PREREQUISITE=" + str(exc).replace("\n", " ")[:240])
        print("NO_IMAGE_PULL_OR_BUILD=true")
        print("NO_TARGET_OR_MODEL_CONTACT=true")
        return 2
    print("NATIVE_TRANSPORT_SELF_TEST=PASS")
    print("NETWORK_MODE=none")
    print("PUBLISHED_PORTS=none")
    print("HOST_APP_BRIDGE=disabled")
    print("TARGET_OPENED=false")
    print("MODEL_CALLED=false")
    print("IMAGE_PULL_OR_BUILD=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
