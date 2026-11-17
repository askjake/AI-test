#!/usr/bin/env python3
"""Phase 4 exit gate (P4-GATE): run a trivial spec end-to-end against local-app.

Opens a sample GUI window (``xterm``), then runs the see->decide->act loop with a trivial
spec ("take a screenshot and report pass"). The loop drives a real :class:`Computer` and a
real :class:`BedrockClient`, so this exercises the full Phase 1 + 2 + 4 stack. Run inside
the (podman) container where Xvfb + a WM are up via entrypoint.sh.

    export BEDROCK_MODEL_ID="<inference-profile ARN or id>"
    export AWS_REGION="us-west-2"
    PYTHONPATH=src python scripts/smoke_agent.py

Exits 0 if the loop completes with a populated TestResult carrying step records.
"""

from __future__ import annotations

import sys
import tempfile

sys.path.insert(0, "src")

from orchestrator.agent import run_agent  # noqa: E402
from orchestrator.computer import Computer  # noqa: E402
from orchestrator.models import TestSpec, TestStatus  # noqa: E402
from orchestrator.targets import TargetSpec, Targets  # noqa: E402


def main() -> int:
    spec = TestSpec(
        title="Smoke: screenshot and report pass",
        goal=(
            "Take a screenshot of the current screen. You do not need to interact with "
            "anything. Then report the test as passed."
        ),
        assertions=["A screen is visible."],
        target_type="local-app",
    )

    targets = Targets()
    comp = Computer()
    handle = targets.open_target(
        TargetSpec("local-app", {"app": "xterm -T orchestrator-agent", "window": "orchestrator-agent"})
    )
    try:
        with tempfile.TemporaryDirectory() as shots:
            result = run_agent(spec, computer=comp, screenshots_dir=shots)
    finally:
        targets.close_target(handle)

    print(f"[smoke] status={result.status.value} passed={result.passed}")
    print(f"[smoke] steps={result.step_count} tokens(in/out)={result.input_tokens}/{result.output_tokens}")
    print(f"[smoke] summary={result.summary!r}")
    for step in result.steps:
        print(f"  step {step.index}: action={step.action} shot={step.screenshot_path}")

    ok = (
        result.status in (TestStatus.PASSED, TestStatus.FAILED)
        and len(result.steps) >= 1
    )
    if ok:
        print("[smoke] PASS — agent loop completed with a populated TestResult + step records")
        return 0
    print(f"[smoke] FAIL — loop did not complete cleanly (error={result.error!r})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
