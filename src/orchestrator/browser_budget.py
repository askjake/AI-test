"""Model-attempt budget and deadline for the browser page classifier (CP44, b4r12-dev).

Counts every ACTUAL request attempt at the transport level (boto ``invoke_model``), including failed attempts, and closes the hidden-retry paths of the
production BedrockClient: throttling back-off retries (``max_retries`` is forced to 0 on the instance this budget governs) and the expired-credential
rebuild-and-resend (the rebuilt boto client is wrapped through the client factory).  Exhaustion raises ``BudgetExhausted`` BEFORE a request is sent.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from orchestrator import browser_verify as bv

MAX_FAILED_ATTEMPTS = 6            # failed transport attempts tolerated per run (each is also counted in the attempt cap)
ATTEMPT_MARGIN = 4                 # slack above the zero-latency worst case of the observation schedule


class BudgetExhausted(bv.ClassifierBudgetExhausted):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def schedule_bounds(lim: Any) -> dict:
    """Upper bound of page-classifier calls the workflow can make under ``lim`` even with a zero-latency model.
    wait phase: one call per poll until load_timeout; observation: frames after the first plus the unclear frames that trip the abort."""
    wait = int(lim.load_timeout_s // lim.poll_interval_s) + 1
    observe = (lim.max_frames - 1) + (lim.max_unclear_frames + 1)
    return {"wait_calls": wait, "observe_calls": observe, "worst_case_calls": wait + observe}


class AttemptBudget:
    def __init__(self, *, max_attempts: int, max_failures: int, deadline_s: float) -> None:
        for v in (max_attempts, max_failures):
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ValueError("attempt limits must be positive integers")
        if not isinstance(deadline_s, (int, float)) or isinstance(deadline_s, bool) or deadline_s <= 0:
            raise ValueError("deadline must be a positive number")
        self.max_attempts, self.max_failures, self.deadline_s = max_attempts, max_failures, float(deadline_s)
        self.used = 0
        self.failed = 0
        self.reason = ""
        self._t0: float | None = None

    def _stop(self, why: str) -> None:
        self.reason = why
        raise BudgetExhausted(why)

    def before_send(self) -> None:
        if self.reason:
            raise BudgetExhausted(self.reason)
        now = time.monotonic()
        if self._t0 is None:
            self._t0 = now
        if now - self._t0 >= self.deadline_s:
            self._stop("DEADLINE")
        if self.used >= self.max_attempts:
            self._stop("ATTEMPTS")
        if self.failed >= self.max_failures:
            self._stop("FAILURES")
        self.used += 1

    def wrap(self, fn: Callable) -> Callable:
        def counted(*a: Any, **k: Any) -> Any:
            self.before_send()
            try:
                return fn(*a, **k)
            except BudgetExhausted:
                raise
            except BaseException:
                self.failed += 1
                raise
        return counted

    def install(self, client: Any) -> str:
        """Govern ``client``: no application retries, every transport attempt counted.  Returns where the count is taken."""
        if hasattr(client, "max_retries"):
            client.max_retries = 0
        raw = getattr(client, "_client", None)
        if raw is not None and callable(getattr(raw, "invoke_model", None)):
            raw.invoke_model = self.wrap(raw.invoke_model)
            factory = getattr(client, "_client_factory", None)
            if callable(factory):
                def counted_factory() -> Any:
                    fresh = factory()
                    fresh.invoke_model = self.wrap(fresh.invoke_model)
                    return fresh
                client._client_factory = counted_factory
            return "transport"
        client.invoke = self.wrap(client.invoke)
        return "invoke"

    def counters(self) -> dict:
        return {"attempts": self.used, "failed": self.failed, "cap": self.max_attempts, "failure_cap": self.max_failures,
                "deadline_s": self.deadline_s, "exhausted": bool(self.reason), "exhausted_reason": self.reason}


def budget_for(lim: Any) -> AttemptBudget:
    return AttemptBudget(max_attempts=schedule_bounds(lim)["worst_case_calls"] + ATTEMPT_MARGIN, max_failures=MAX_FAILED_ATTEMPTS, deadline_s=lim.total_deadline_s)
