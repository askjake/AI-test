"""Per-run audit log (Phase 8 — auditability, P8-9).

Every test run writes a full, append-only ``audit.jsonl`` alongside its evidence so the
exact sequence of model responses and executed actions is retained with the report. Each
line is one JSON event with a monotonic ``seq`` and a ``kind``:

- ``run_start`` / ``run_end`` — bookends with the spec title, target, and final status.
- ``model_response`` — the model's reasoning text, stop reason, token usage, and the
  tool calls it requested (name + input) for that turn.
- ``action`` — one executed (or guardrail-blocked) computer action and the screenshot it
  produced.

Screenshots are referenced by path, never inlined, so the log stays small and never carries
image bytes. No credentials are ever written here — the agent never handles them, and tool
inputs that reach this log are model-authored ``{action, coordinate, text}`` values.

:class:`AuditLog` is injectable and a no-op when no path is given, mirroring the rest of the
runner so the agent loop stays unit-testable without touching disk.
"""

from __future__ import annotations

import json
import os
from typing import Any


class AuditLog:
    """Append-only JSONL sink. With ``path=None`` every method is a cheap no-op."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._seq = 0
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # Truncate any prior file so a run's log is exactly that run.
            with open(path, "w", encoding="utf-8"):
                pass

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def _emit(self, kind: str, **fields: Any) -> None:
        if not self.path:
            return
        event = {"seq": self._seq, "kind": kind, **fields}
        self._seq += 1
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")

    # --- event helpers -----------------------------------------------------

    def run_start(self, *, title: str, target_type: str) -> None:
        self._emit("run_start", title=title, target_type=target_type)

    def model_response(
        self,
        *,
        step: int,
        reasoning: str | None,
        stop_reason: str | None,
        tool_calls: list[dict[str, Any]],
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        self._emit(
            "model_response",
            step=step,
            reasoning=reasoning,
            stop_reason=stop_reason,
            tool_calls=tool_calls,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    def action(
        self,
        *,
        step: int,
        action: str | None,
        action_input: dict[str, Any],
        result: str,
        screenshot_path: str | None,
        before_screenshot_path: str | None = None,
        after_screenshot_path: str | None = None,
    ) -> None:
        self._emit(
            "action",
            step=step,
            action=action,
            action_input=action_input,
            result=result,
            screenshot_path=screenshot_path,
            before_screenshot_path=before_screenshot_path,
            after_screenshot_path=after_screenshot_path or screenshot_path,
        )

    def run_end(self, *, status: str, step_count: int, error: str | None = None) -> None:
        self._emit("run_end", status=status, step_count=step_count, error=error)
