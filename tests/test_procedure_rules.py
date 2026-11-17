"""Generated procedure rules (Reviewer P1/P2/R4/D2, user constraints for the JAMboreeVision procedure)."""
import re

from dashboard import procedure_project
from dashboard.procedure_intake import build_procedure, classify_step, upgrade_draft
from tests.test_procedure_intake_v2 import GOAL, _service, _settings


def _draft(tmp_path):
    settings = _settings(tmp_path)
    return build_procedure(GOAL, _service(settings), settings.wizard_state_root)


def test_step_one_explicitly_opens_an_administrator_window_before_checking_elevation(tmp_path):
    step = _draft(tmp_path).steps[0]
    text = step.instructions
    assert "Run as administrator" in text and text.index("Run as administrator") < text.index("IsInRole")
    assert "IsInRole" in text and "S-1-5-32-544" not in text          # membership of the Administrators group is not elevation
    assert any("consent-only User Account Control" in c for c in step.completion_checks)
    assert any("IsInRole(Administrator) returns True" in c for c in step.completion_checks)


def test_service_steps_forbid_forced_recovery_and_state_the_failure_policy(tmp_path):
    draft = _draft(tmp_path)
    for order in (2, 7):
        checks = " ".join(draft.steps[order - 1].completion_checks)
        assert "stop and report the failure" in checks and "Never force it" in checks
        for forbidden in ("-Force", "Stop-Process", "taskkill", "start.cmd", "start.ps1", "Manage-Service.ps1"):
            assert forbidden in checks


def test_generated_spec_carries_the_hard_rules_the_agent_sees(tmp_path):
    doc = procedure_project.build_project_doc(_draft(tmp_path))
    spec = procedure_project.render_spec(doc, "T")
    low = spec.lower()
    for needle in ("stop-service and start-service", "start.cmd", "manage-service.ps1", "taskkill", "do not force",
                   "only the current step", "yes/no", "operator checkpoints", "free tcp port does not prove"):
        assert needle in low, needle


def test_hardware_and_physical_checks_are_operator_checkpoints_never_read_only(tmp_path):
    draft = _draft(tmp_path)
    assert [s.order for s in draft.steps if s.kind == "operator-checkpoint"] == [6, 11]
    assert not any(s.read_only_ok for s in draft.steps if s.kind == "operator-checkpoint")


def test_pasted_text_that_names_a_forbidden_substitute_is_flagged_not_executed(tmp_path):
    settings = _settings(tmp_path)
    goal = GOAL.replace("2. Stop the service", "2. Stop the service (if it hangs use taskkill /F or .\\start.cmd)")
    draft = build_procedure(goal, _service(settings), settings.wizard_state_root)
    assert any("never types these" in f and "taskkill" in f for f in draft.findings)
    assert "taskkill" not in " ".join(draft.steps[1].completion_checks).replace("Never force it: no -Force, Stop-Process or taskkill", "")


def test_v1_drafts_get_their_run_safety_classified_not_defaulted_to_read_only():
    old = {"id": "a" * 32, "title": "t", "connections": [], "steps": [
        {"order": 1, "title": "Stop it", "kind": "procedure-step", "instructions": "Stop-Service -Name X", "completion_checks": []},
        {"order": 2, "title": "Look", "kind": "procedure-step", "instructions": "Get-Service -Name X", "completion_checks": []}],
        "action_context_hop": 1, "findings": [], "manual": ""}
    steps = upgrade_draft(old)["steps"]
    assert steps[0]["mutating"] is True and steps[0]["read_only_ok"] is False
    assert steps[1]["mutating"] is False and steps[1]["read_only_ok"] is True
