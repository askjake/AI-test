"""Phase 8 tests for orchestrator.audit + agent-loop auditability (P8-9)."""

from __future__ import annotations

import json

from orchestrator.agent import run_planner_agent
from orchestrator.audit import AuditLog
from orchestrator.models import TestSpec, TestStatus
from tests.test_agent_planner import (
    FakeClient,
    FakeComputer,
    _click,
    _next_step,
    _report,
    _result,
    _step_done,
)


def _read_events(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_disabled_audit_is_noop(tmp_path):
    a = AuditLog(None)
    assert a.enabled is False
    a.run_start(title="t", target_type="local-app")  # must not raise / not write
    assert not list(tmp_path.iterdir())


def test_audit_records_full_run(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    spec = TestSpec(title="T", goal="g", assertions=["a"], target_type="local-app")
    client = FakeClient(
        planner_results=[
            _result([{"type": "text", "text": "planning"}, _next_step("click", 0)]),
            _result([{"type": "text", "text": "done"}, _report()]),
        ],
        executor_results=[
            _result([{"type": "text", "text": "clicking"}, _click()]),
            _result([_step_done()]),
        ],
    )
    run_planner_agent(spec, computer=FakeComputer(), client=client,
                      audit=AuditLog(path), clock=lambda: 0.0)

    events = _read_events(path)
    kinds = [e["kind"] for e in events]
    assert kinds[0] == "run_start"
    assert kinds[-1] == "run_end"
    assert "model_response" in kinds
    assert "action" in kinds
    # seq is monotonic and contiguous.
    assert [e["seq"] for e in events] == list(range(len(events)))
    # The executed action (from the vision-executor step) is captured.
    action_ev = next(e for e in events if e["kind"] == "action")
    assert action_ev["action"] == "left_click"
    assert action_ev["screenshot_path"] is None  # no screenshots_dir given
    assert action_ev["before_screenshot_path"] is None
    assert action_ev["after_screenshot_path"] is None
    end = events[-1]
    assert end["status"] == TestStatus.PASSED.value


def test_audit_records_cap_breach(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    spec = TestSpec(title="T", goal="g", target_type="local-app")
    planner = [_result([_next_step("go", i)]) for i in range(10)]
    executor = [_result([_step_done()]) for _ in range(10)]
    client = FakeClient(planner_results=planner, executor_results=executor)
    run_planner_agent(spec, computer=FakeComputer(), client=client, max_planner_steps=2,
                      audit=AuditLog(path), clock=lambda: 0.0)
    events = _read_events(path)
    end = events[-1]
    assert end["kind"] == "run_end"
    assert end["status"] == TestStatus.ERRORED.value
    assert "max_steps" in end["error"]
