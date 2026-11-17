"""Adapter: the startup guard (reports-switch state + source/image agreement, CP45-R/V).  The implementation is dashboard/switch_guard.py (standard library, read-only).

Managed commands (cory-app start, lifecycle.start_dashboard / dashboard_environment) call require_resolved() before they create or modify anything; it raises a
ConfigurationError subclass so the CLI prints the message (reasons, refusal notice and the recovery commands) and exits with its usual configuration-error status.
``check_image=False`` (used by init) keeps only the reports-switch check.
"""
from __future__ import annotations

from dashboard import switch_guard as _guard
from dashboard.switch_guard import agreement_check, observe, problems  # noqa: F401  (re-exported)

from .config import ConfigurationError


class ReportsSwitchUnresolved(ConfigurationError, _guard.ReportsSwitchUnresolved):
    pass


class AgreementRefused(ConfigurationError, _guard.AgreementRefused):
    pass


def require_resolved(reports_dir, **kw) -> None:
    try:
        _guard.require_resolved(reports_dir, **kw)
    except _guard.ReportsSwitchUnresolved as exc:
        raise ReportsSwitchUnresolved(str(exc)) from None
    except _guard.AgreementRefused as exc:
        raise AgreementRefused(str(exc)) from None
