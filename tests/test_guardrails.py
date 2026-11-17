"""Phase 8 tests for orchestrator.guardrails + agent enforcement (P8-6)."""

from __future__ import annotations

import pytest

from orchestrator.agent import _execute_action
from orchestrator.guardrails import DEFAULT_GUARDRAILS, GuardrailViolation, Guardrails


@pytest.mark.parametrize(
    "combo",
    ["alt+F4", "Alt+f4", "ctrl+q", "ctrl+w", "alt+Tab", "ctrl+alt+Delete",
     "ctrl+alt+BackSpace", "ctrl+alt+F1", "ctrl+alt+F7"],
)
def test_dangerous_chords_blocked(combo):
    g = Guardrails()
    assert g.check("key", {"text": combo}) is not None


@pytest.mark.parametrize("combo", ["ctrl+c", "Return", "ctrl+a", "Tab", "shift+Home", "ctrl+s"])
def test_benign_chords_allowed(combo):
    g = Guardrails()
    assert g.check("key", {"text": combo}) is None


def test_bare_super_key_blocked():
    g = Guardrails()
    assert g.check("key", {"text": "super"}) is not None


def test_non_key_actions_never_blocked():
    g = Guardrails()
    assert g.check("left_click", {"coordinate": [1, 2]}) is None
    assert g.check("type", {"text": "alt+F4"}) is None  # typing the literal text is fine
    assert g.check("screenshot", {}) is None


def test_enforce_raises():
    with pytest.raises(GuardrailViolation):
        Guardrails().enforce("key", {"text": "alt+F4"})


class _SpyComputer:
    def __init__(self):
        self.keys: list[str] = []

    def key(self, combo):
        self.keys.append(combo)


def test_execute_action_skips_blocked_key():
    comp = _SpyComputer()
    msg = _execute_action(comp, {"action": "key", "text": "alt+F4"}, DEFAULT_GUARDRAILS)
    assert "blocked" in msg.lower()
    assert comp.keys == []  # never reached the executor


def test_execute_action_allows_benign_key():
    comp = _SpyComputer()
    _execute_action(comp, {"action": "key", "text": "Return"}, DEFAULT_GUARDRAILS)
    assert comp.keys == ["Return"]
