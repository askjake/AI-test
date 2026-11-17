"""Adapter-level tests for Targets.foreground_state (security review D2).

These exercise the REAL xdotool code path in orchestrator.targets, with the injectable runner
standing in for the xdotool binary, including the CalledProcessError that xdotool produces when
a window id is gone or nothing has focus.  xdotool itself is present in the runner image
(docker/Dockerfile) but is not installed on the development host, so the binary is simulated
here; the parsing and fail-closed branching under test is production code.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from orchestrator.targets import Targets


def _targets(responses, tmp_path):
    """responses: dict mapping the xdotool argv tail -> output string, or an Exception to raise."""
    calls = []

    def runner(cmd):
        calls.append(list(cmd))
        key = tuple(cmd[1:])
        if key not in responses:
            raise subprocess.CalledProcessError(1, cmd)
        value = responses[key]
        if isinstance(value, Exception):
            raise value
        return value

    t = Targets(display=":99", secrets_dir=str(tmp_path), runner=runner, sleep=lambda _s: None)
    return t, calls


HANDLE = SimpleNamespace(window_name="NRDP Hop 1", window_id="12345")


def test_foreground_state_reports_the_run_owned_window_when_it_holds_the_keyboard(tmp_path):
    t, calls = _targets({
        ("getactivewindow",): "12345\n",
        ("getwindowname", "12345"): "NRDP Hop 1\n",
    }, tmp_path)
    state = t.foreground_state(HANDLE)
    assert state["expected_id"] == "12345"
    assert state["focused_id"] == "12345"
    assert state["focused_name"] == "NRDP Hop 1"
    assert state["handle_present"] is True
    # cheap: no screenshot, no model, only xdotool queries
    assert all(c[0] == "xdotool" for c in calls)


def test_foreground_state_reports_a_different_focused_window(tmp_path):
    t, _ = _targets({
        ("getactivewindow",): "99999\n",
        ("getwindowname", "99999"): "Some Other Window\n",
        ("getwindowname", "12345"): "NRDP Hop 1\n",
    }, tmp_path)
    state = t.foreground_state(HANDLE)
    assert state["focused_id"] == "99999"
    assert state["focused_name"] == "Some Other Window"
    assert state["handle_present"] is True     # still mapped, just not focused


def test_foreground_state_marks_the_handle_absent_when_its_window_is_gone(tmp_path):
    t, _ = _targets({
        ("getactivewindow",): "99999\n",
        ("getwindowname", "99999"): "Some Other Window\n",
        # no entry for 12345 => xdotool exits non-zero => window destroyed
    }, tmp_path)
    state = t.foreground_state(HANDLE)
    assert state["handle_present"] is False


def test_foreground_state_reports_no_focus_when_nothing_is_active(tmp_path):
    t, _ = _targets({
        ("getwindowname", "12345"): "NRDP Hop 1\n",
        # getactivewindow absent => xdotool fails => no focused window
    }, tmp_path)
    state = t.foreground_state(HANDLE)
    assert state["focused_id"] is None
    assert state["focused_name"] is None
    assert state["handle_present"] is True


def test_foreground_state_tolerates_an_unnameable_focused_window(tmp_path):
    t, _ = _targets({
        ("getactivewindow",): "99999\n",
        ("getwindowname", "12345"): "NRDP Hop 1\n",
        # getwindowname 99999 absent => name unknown, id still known
    }, tmp_path)
    state = t.foreground_state(HANDLE)
    assert state["focused_id"] == "99999"
    assert state["focused_name"] is None


def test_foreground_state_never_raises_for_a_totally_broken_xdotool(tmp_path):
    def runner(cmd):
        raise OSError("xdotool not installed")

    t = Targets(display=":99", secrets_dir=str(tmp_path), runner=runner, sleep=lambda _s: None)
    state = t.foreground_state(HANDLE)
    # it reports ignorance rather than raising; the caller fails closed on that
    assert state["focused_id"] is None
    assert state["handle_present"] is False


def test_foreground_state_handles_a_handle_without_an_id(tmp_path):
    t, _ = _targets({("getactivewindow",): "12345\n",
                     ("getwindowname", "12345"): "NRDP Hop 1\n"}, tmp_path)
    state = t.foreground_state(SimpleNamespace(window_name="NRDP Hop 1", window_id=None))
    assert state["expected_id"] is None
    assert state["handle_present"] is None     # unknown, never silently True


def test_foreground_state_handles_no_handle_at_all(tmp_path):
    t, _ = _targets({("getactivewindow",): "12345\n",
                     ("getwindowname", "12345"): "NRDP Hop 1\n"}, tmp_path)
    state = t.foreground_state(None)
    assert state["expected_id"] is None and state["expected_name"] is None
    assert state["handle_present"] is None
