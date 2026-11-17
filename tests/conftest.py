"""Shared test fixtures."""

from __future__ import annotations

import os as _os_t, sys as _sys_t
_T_DIR = _os_t.path.dirname(_os_t.path.abspath(__file__))      # CP45-I: tests import 'bv_sim' as a bare module; the installer gate does not put tests/ on sys.path
if _T_DIR not in _sys_t.path:
    _sys_t.path.insert(0, _T_DIR)


import os

import pytest

from orchestrator.config import settings


@pytest.fixture(autouse=True)
def _no_action_delay(monkeypatch):
    """Zero the post-action settle delay so the agent loop runs instantly in tests."""
    monkeypatch.setattr(settings, "action_delay_seconds", 0.0)


# ---------------------------------------------------------------------------- POSIX fixture file modes
#
# NRDP-1 / CP12 (2026-10-29): deterministic fixture permissions.
#
# Production requires the AWS credential source to be owner-only: aws_refresh.source.check_trust()
# refuses any credential file with st_mode & 0o022 ("writable by group or others").  That check is
# correct and must NOT be relaxed -- a source another local user can rewrite would let them
# substitute their own AWS identity.
#
# The tests, however, create credential fixtures with plain Path.write_text()/open(), which inherit
# the *process* umask.  Both NRDP GPU hosts run umask 0002, so fixtures landed at mode 0664 and
# check_trust() refused them with code "unsafe_permissions" BEFORE the behaviour under test was
# reached.  That masked 63 tests on Linux.  On Windows check_trust() returns immediately
# (os.name != "posix"), which is why the earlier Windows suites never showed this.
#
# Pinning the umask for the test session makes the harness match production (0600) and makes results
# independent of the operator's umask.  This is a test-harness fix only; no product code changed.
@pytest.fixture(autouse=True, scope="session")
def _owner_only_umask():
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


# ---------------------------------------------------------------------------- control uid pin
#
# NRDP-1 / CP12 (2026-10-29), security finding M2.
#
# chain_runtime.trusted_control_file() now REQUIRES ORCHESTRATOR_CONTROL_UID on POSIX.  Without
# it, "the file and its folder share an owner" is a weak test that any single local account
# satisfies inside a folder it owns, so an unattributable run request is refused (and the run is
# downgraded to connection_test).
#
# Production always sets this: scripts/run_container.sh exports ORCHESTRATOR_CONTROL_UID="$(id -u)"
# (L21) and passes it into the container (L399).  The real-filesystem tests must therefore model a
# pinned environment too, otherwise they exercise a configuration that cannot occur in production.
#
# Tests that deliberately probe the UNPINNED behaviour pass environ=/posix= explicitly to
# trusted_control_file and are unaffected by this fixture.
@pytest.fixture(autouse=True)
def _pinned_control_uid(monkeypatch):
    if os.name == "posix" and hasattr(os, "getuid"):
        monkeypatch.setenv("ORCHESTRATOR_CONTROL_UID", str(os.getuid()))
