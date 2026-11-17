"""Application-enforced checks while an operating step runs (SECURITY F4, Reviewer C5/P1/R4)."""
from types import SimpleNamespace as NS

import pytest

from orchestrator import chain_runtime as cr
from orchestrator.chain import DesktopObservation, ObservedState

S = ObservedState


class Computer:
    def __init__(self):
        self.calls = []
        self.level = 0

    def screenshot(self):
        self.calls.append(("screenshot",))
        return NS(png=b"png")

    def left_click(self, x, y):
        self.calls.append(("left_click", x, y))
        return "clicked"

    def type(self, text):
        self.calls.append(("type", text))

    def key(self, combo):
        self.calls.append(("key", combo))

    def type_secret(self, text):
        self.calls.append(("type_secret",))

    def cursor_position(self):
        return (1, 2)

    def mouse_move(self, x, y):
        self.calls.append(("mouse_move", x, y))


def make(state=S.REMOTE_DESKTOP_READY, conf=0.9, **kw):
    seen = []
    box = {"state": state, "conf": conf, "boom": False}

    def classify(png):
        seen.append(png)
        if box["boom"]:
            raise RuntimeError("model down")
        return DesktopObservation(state=box["state"], confidence=box["conf"])

    guard = cr.StepGuard(classify, **kw)
    computer = Computer()
    return guard, cr.GuardedComputer(computer, guard), computer, box, seen


def act(g, computer):
    g.screenshot()
    g.left_click(1, 1)


def test_normal_screen_lets_actions_through_and_returns_their_results():
    guard, g, computer, box, seen = make()
    g.screenshot()
    assert g.left_click(5, 6) == "clicked"
    g.type("Get-Service -Name JAMboreeVision")
    assert ("left_click", 5, 6) in computer.calls and ("type", "Get-Service -Name JAMboreeVision") in computer.calls
    assert len(seen) == 1            # one classification per fresh screenshot, not per keystroke


@pytest.mark.parametrize("state", [S.CREDENTIAL_PROMPT, S.LOCK_OR_LOGON_SCREEN, S.CERTIFICATE_WARNING,
                                   S.UAC_CREDENTIAL_PROMPT, S.CREDENTIAL_ACCOUNT_LIST,
                                   S.REMOTE_DESKTOP_IDENTITY_MISMATCH])
def test_no_input_is_sent_while_a_credential_lock_or_certificate_state_is_on_screen(state):
    guard, g, computer, box, seen = make(state)
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation) as e:
        g.left_click(1, 1)
    assert e.value.code == "AUTH_PROMPT_DURING_STEP"
    assert [c for c in computer.calls if c[0] != "screenshot"] == []
    with pytest.raises(cr.StepGuardViolation):
        g.key("Return")                  # and it stays blocked
    assert guard.violation[0] == "AUTH_PROMPT_DURING_STEP"


def test_consent_only_elevation_prompt_is_allowed_only_for_the_step_that_asks_for_it():
    guard, g, computer, box, _ = make(S.UAC_CONSENT_PROMPT, allow_uac_consent=True)
    g.screenshot()
    g.left_click(10, 10)                                        # "Yes" on a consent-only box
    guard, g, computer, box, _ = make(S.UAC_CONSENT_PROMPT, allow_uac_consent=False)
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation) as e:
        g.left_click(10, 10)
    assert e.value.code == "UAC_PROMPT_NOT_PERMITTED"


def test_elevation_box_that_asks_for_credentials_is_never_allowed():
    guard, g, computer, box, _ = make(S.UAC_CREDENTIAL_PROMPT, allow_uac_consent=True)
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation):
        g.type("anything")


def test_unreadable_screen_does_not_block_but_classifier_failure_does():
    guard, g, computer, box, _ = make(S.CREDENTIAL_PROMPT, conf=0.2)
    g.screenshot()
    g.left_click(1, 1)                   # low confidence: the agent's own prompt still says to stop on prompts
    guard, g, computer, box, _ = make()
    box["boom"] = True
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation) as e:
        g.left_click(1, 1)
    assert e.value.code == "GUARD_CLASSIFIER_ERROR"


@pytest.mark.parametrize("text", [
    "Stop-Process -Name JAMboreeVision", "taskkill /F /IM jam.exe", "& .\\start.cmd", "powershell .\\start.ps1",
    ".\\Manage-Service.ps1 -Restart", "Stop-Service -Name JAMboreeVision -Force", "Restart-Service JAMboreeVision -Force",
])
def test_forbidden_recovery_commands_are_never_typed_even_in_a_mutating_step(text):
    guard, g, computer, box, _ = make(mutating_allowed=True, step_text="Stop-Service -Name JAMboreeVision")
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation) as e:
        g.type(text)
    assert e.value.code == "FORBIDDEN_COMMAND"
    assert ("type", text) not in computer.calls


def test_service_commands_are_typed_only_in_the_step_that_asks_for_them():
    # read-only step: no service control at all
    guard, g, computer, box, _ = make(mutating_allowed=False, step_text="Get-Service -Name JAMboreeVision")
    g.screenshot()
    g.type("Get-Service -Name JAMboreeVision")
    with pytest.raises(cr.StepGuardViolation) as e:
        g.type("Stop-Service -Name JAMboreeVision")
    assert e.value.code == "MUTATION_NOT_IN_THIS_STEP"
    # the Stop step may Stop, but not Start (that is a LATER step)
    guard, g, computer, box, _ = make(mutating_allowed=True, step_text="2. Stop it\nStop-Service -Name JAMboreeVision")
    g.screenshot()
    g.type("Stop-Service -Name JAMboreeVision")
    with pytest.raises(cr.StepGuardViolation):
        g.type("Start-Service -Name JAMboreeVision")


@pytest.mark.parametrize("text", ["sc stop JAMboreeVision", "net stop JAMboreeVision", "shutdown /r /t 0", "Restart-Computer"])
def test_other_service_or_power_tools_are_never_typed(text):
    guard, g, computer, box, _ = make(mutating_allowed=True, step_text="Stop-Service -Name x")
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation):
        g.type(text)


def test_the_agent_can_never_type_a_saved_credential():
    guard, g, computer, box, _ = make()
    g.screenshot()
    with pytest.raises(cr.StepGuardViolation) as e:
        g.type_secret("x")
    assert e.value.code == "SECRET_TYPING_BLOCKED" and ("type_secret",) not in computer.calls


def test_observation_calls_are_not_guarded():
    guard, g, computer, box, seen = make(S.CREDENTIAL_PROMPT)
    g.screenshot()
    assert g.cursor_position() == (1, 2)
    g.mouse_move(3, 4)
    assert seen == []                    # nothing classified yet: no input has been attempted


def test_preamble_forbids_the_recovery_commands_and_defines_the_elevation_policy():
    text = cr.chain_prompt_preamble([{"order": 1, "host": "a", "user": "u"}, {"order": 2, "host": "b", "user": "v"}], 2)
    for needle in ("start.cmd", "start.ps1", "Manage-Service.ps1", "Stop-Process", "taskkill", "-Force",
                   "Do ONLY the step", "Yes/No", "user name or password"):
        assert needle in text, needle
    assert cr.ELEVATION_REQUEST.search("Open Windows PowerShell as Administrator")
    assert not cr.ELEVATION_REQUEST.search("Get-Service -Name JAMboreeVision")
