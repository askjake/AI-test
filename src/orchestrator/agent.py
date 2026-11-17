"""The see -> decide -> act loop tying Bedrock + computer + target together (Phase 4).

Screenshot -> ``bedrock_client.invoke_computer_use`` -> execute computer actions -> repeat,
until the model calls the forced final ``report_result`` tool or a resource cap
(steps / wall-clock seconds / cumulative tokens) trips.

The target window is already opened and focused by ``targets.py`` before this loop runs;
the agent only drives the focused window by vision. ``Computer`` and ``BedrockClient`` are
injected so the loop is unit-testable without a real display or Bedrock.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from typing import Any, Callable

from .audit import AuditLog
from .bedrock_client import BedrockClient, ContentBlock, InvokeResult
from .computer import POINT_ACTIONS, annotate_action
from .config import settings
from .guardrails import DEFAULT_GUARDRAILS, Guardrails
from .models import (
    AssertionResult,
    PlannerTurnMetric,
    StepOutcome,
    StepRecord,
    TestResult,
    TestSpec,
    TestStatus,
)
from .projects import ManualError, load_manual_page

# Returns a monotonic wall-clock reading (seconds). Injectable for deterministic tests.
Clock = Callable[[], float]

logger = logging.getLogger("orchestrator.agent")


def report_result_tool() -> dict[str, Any]:
    """The custom tool the model must call to finish a test with a structured verdict."""
    return {
        "name": "report_result",
        "description": (
            "Call this once the goal has been pursued and every assertion has been "
            "evaluated. This ends the test. Provide an overall pass/fail, a per-assertion "
            "verdict with on-screen evidence, and a short summary."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "passed": {
                    "type": "boolean",
                    "description": "True only if every assertion passed.",
                },
                "per_assertion": {
                    "type": "array",
                    "description": "One entry per assertion, in order.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "The assertion text."},
                            "passed": {"type": "boolean"},
                            "evidence": {
                                "type": "string",
                                "description": "What on screen supports this verdict.",
                            },
                        },
                        "required": ["text", "passed"],
                    },
                },
                "summary": {
                    "type": "string",
                    "description": "A short human-readable summary of the outcome.",
                },
                "ending_state": {
                    "type": "string",
                    "description": (
                        "Briefly describe the app's ending state for the next test in this "
                        "session: which screen is shown, who is logged in, what is open or "
                        "selected. Omit any passwords or secrets."
                    ),
                },
            },
            "required": ["passed", "summary"],
        },
    }


def step_done_tool() -> dict[str, Any]:
    """The tool a vision-executor must call to finish one planner-issued instruction."""
    return {
        "name": "step_done",
        "description": (
            "Call this once you have carried out the instruction (or determined you cannot). "
            "This ends the step. Report whether the instruction succeeded and describe the "
            "resulting screen state for the planner, which cannot see the screen."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean",
                    "description": "True if the instruction was carried out as asked.",
                },
                "summary": {
                    "type": "string",
                    "description": (
                        "One or two sentences: what you did and whether it worked. This is the "
                        "planner's only view of the screen, so be concrete."
                    ),
                },
                "ending_state": {
                    "type": "string",
                    "description": (
                        "Describe the screen now so the planner can decide the next step: which "
                        "dialog/screen is shown, which fields hold what values, what is focused "
                        "or enabled, any error text. Omit any passwords or secrets."
                    ),
                },
            },
            "required": ["success", "summary"],
        },
    }


def next_step_tool() -> dict[str, Any]:
    """The tool the text-only planner calls to issue the next UI instruction."""
    return {
        "name": "next_step",
        "description": (
            "Issue the single next UI action for the vision executor to perform. The executor "
            "will look at the screen, carry out this one instruction, and report back a text "
            "summary of the resulting state. Issue exactly one concrete step at a time."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "instruction": {
                    "type": "string",
                    "description": (
                        "A single concrete UI action in plain English, e.g. \"Enter the "
                        "username 'alice' into the User Name field of the login dialog\" or "
                        "\"Click the Login button\". Name the target element precisely."
                    ),
                },
                "rationale": {
                    "type": "string",
                    "description": "Why this step now (for the audit log).",
                },
            },
            "required": ["instruction"],
        },
    }


def read_manual_page_tool() -> dict[str, Any]:
    """The tool the planner calls to load one topic page from the app's operating manual."""
    return {
        "name": "read_manual_page",
        "description": (
            "Load the full text of one topic page from the application's operating manual. The "
            "manual in your system prompt contains a table of contents listing topic pages by "
            "path. Call this BEFORE performing UI steps a page covers (e.g. a create/login/bind "
            "procedure) to get its detailed, step-by-step instructions. The page text is "
            "returned to you as text; only load the pages you actually need."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "page": {
                    "type": "string",
                    "description": (
                        "The path of the topic page exactly as it appears in the manual's "
                        "table-of-contents links, e.g. \"services/100-create-service.md\"."
                    ),
                },
            },
            "required": ["page"],
        },
    }


def build_executor_prompt(instruction: str) -> str:
    """System prompt for a single vision-executor step: do one instruction, then finish."""
    return "\n".join(
        [
            "You are an automated UI test agent driving a computer by vision (screenshots).",
            "",
            f"Every screenshot you receive is {settings.model_w}x{settings.model_h} pixels. "
            "Coordinates you provide are [x, y] pixels from the top-left of that screenshot, "
            f"so x is in [0, {settings.model_w - 1}] and y is in [0, {settings.model_h - 1}].",
            "",
            "Operate ONLY within the currently focused target window. Do not switch to other "
            "windows, open new applications, or take actions outside the window under test. "
            "Never close or quit the target application and never use window-switching, "
            "application-exit, or system key combinations (e.g. Alt+F4, Ctrl+Q, Alt+Tab, "
            "Ctrl+Alt+Delete) — such actions are blocked and will be refused.",
            "",
            "You are given ONE instruction to carry out. Use the `computer` tool to act, "
            "taking screenshots as needed to see the current state. Before each `computer` "
            "action, state ONE short sentence explaining why, phrased from what is currently "
            'on screen (e.g. "Since the Name text field is shown, I will left-click it."). '
            "Keep it to a single sentence — no lists or multi-paragraph reasoning. Do only "
            "what the instruction asks — do not pursue later steps. When the instruction is done (or "
            "you determine it cannot be done), you MUST call the `step_done` tool with a "
            "success flag, a short summary, and a description of the resulting screen state. "
            "Do not stop without calling `step_done`.",
            "",
            f"Instruction:\n{instruction}",
        ]
    )


def build_planner_prompt(spec: TestSpec, prior_context: str | None = None) -> str:
    """System prompt for the text-only planner: plan blind, one step at a time, then verdict.

    The planner never receives screenshots. It decides each next step from the goal, the
    assertions, the session digest, and the running text summaries returned by the executor
    after each step. ``prior_context`` is the shared-session digest of earlier specs' outcomes,
    appended so the planner knows the state the app is already in (e.g. already logged in).
    """
    lines = [
        "You are the PLANNER for an automated UI test. You CANNOT see the screen. A separate "
        "vision executor performs each step you issue and reports back a short text summary of "
        "the resulting screen state; those summaries are your only view of the app.",
        "",
        "Drive the test by issuing ONE concrete UI step at a time with the `next_step` tool "
        "(e.g. \"enter the username\", \"click Login\"). After each step you receive the "
        "executor's summary and ending state. Use it to decide the next step. When you cannot "
        "verify a state by reasoning alone, issue an explicit verification step (e.g. "
        "\"confirm the login dialog is no longer visible\"). If a step reports failure or an "
        "unexpected state, adjust and re-plan rather than pressing on blindly.",
        "",
        f"Goal:\n{spec.goal}",
    ]
    if spec.setup:
        lines += ["", f"Setup context:\n{spec.setup}"]
    if spec.manual_text:
        lines += [
            "",
            "Application operating manual (how to drive this specific app — use it to turn each "
            "high-level goal step into concrete UI actions; it describes buttons, fields, tabs, "
            "dialog flow, and known UI quirks/workarounds. Image links in the manual are for "
            "human readers and are not shown to you). Its table of contents lists detailed topic "
            "pages by path; call the `read_manual_page` tool with a page's path to load that "
            "page's step-by-step procedure BEFORE performing the UI steps it covers:",
            spec.manual_text,
        ]
    if prior_context:
        lines += [
            "",
            "Session context (results of earlier tests in this session; the app is already "
            f"in this state — do not redo their setup or log in again):\n{prior_context}",
        ]
    if spec.assertions:
        bullets = "\n".join(f"- {a}" for a in spec.assertions)
        lines += [
            "",
            "You must evaluate each of these assertions, using the executor's reported states "
            f"as evidence (issue verification steps where needed):\n{bullets}",
        ]
    lines += [
        "",
        "When the goal has been pursued and every assertion has been evaluated, you MUST call "
        "the `report_result` tool with your overall pass/fail, a per-assertion verdict, and a "
        "summary. Do not call `report_result` until the work is done, and do not stop without "
        "calling it.",
    ]
    return "\n".join(lines)


def _b64(png: bytes) -> str:
    return base64.b64encode(png).decode("ascii")


def _image_block(png: bytes) -> dict[str, Any]:
    return {
        "type": "image",
        "source": {"type": "base64", "media_type": "image/png", "data": _b64(png)},
    }


_PRUNED_IMAGE_PLACEHOLDER = "[earlier screenshot omitted to save context]"


def _prune_old_images(messages: list[dict[str, Any]], keep_last_n: int) -> None:
    """Replace all but the most recent ``keep_last_n`` screenshots with a text placeholder.

    Mutates ``messages`` in place. Pruning is permanent and deterministic: once an image ages
    out of the window it becomes the same placeholder text block on every future call, so the
    stable prefix stays cache-friendly. ``tool_result`` blocks keep their text and
    ``tool_use_id`` — only the image sub-block is swapped — so tool_use/tool_result pairing
    survives.
    """
    # Collect references to every live image block, in order, with a setter to replace it.
    image_slots: list[tuple[list[dict[str, Any]], int]] = []
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for i, block in enumerate(content):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "image":
                image_slots.append((content, i))
            elif block.get("type") == "tool_result":
                inner = block.get("content")
                if isinstance(inner, list):
                    for j, sub in enumerate(inner):
                        if isinstance(sub, dict) and sub.get("type") == "image":
                            image_slots.append((inner, j))

    for content, idx in image_slots[: max(0, len(image_slots) - keep_last_n)]:
        content[idx] = {"type": "text", "text": _PRUNED_IMAGE_PLACEHOLDER}


def _message_has_live_image(message: dict[str, Any]) -> bool:
    """True if the message still carries a real ``image`` block (not a pruned placeholder)."""
    content = message.get("content")
    if not isinstance(content, list):
        return False
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "image":
            return True
        if block.get("type") == "tool_result":
            inner = block.get("content")
            if isinstance(inner, list) and any(
                isinstance(sub, dict) and sub.get("type") == "image" for sub in inner
            ):
                return True
    return False


def _set_message_cache_breakpoint(messages: list[dict[str, Any]], keep_n: int) -> None:
    """Place a single rolling ``cache_control`` breakpoint over the frozen message prefix.

    Must run *after* :func:`_prune_old_images`. The breakpoint goes on the last content block
    of the message immediately before the earliest message that still holds a live image, so
    the cached region contains only already-frozen content. Because pruning advances the
    live-image window by one image per turn, that frozen prefix is byte-identical between
    consecutive calls — Bedrock returns it as ``cache_read_input_tokens`` (excluded from
    ``input_tokens``) instead of re-counting it, which is what keeps ``max_total_tokens`` from
    growing super-linearly. Any prior breakpoint is cleared first so exactly one rolling
    message breakpoint exists (staying within Anthropic's 4-breakpoint limit alongside the
    system + tools breakpoints set in ``bedrock_client``).
    """
    # Always clear stale breakpoints so a moved anchor can't leave two behind.
    for message in messages:
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)

    if not settings.enable_prompt_caching:
        return

    live_indices = [i for i, m in enumerate(messages) if _message_has_live_image(m)]
    if not live_indices:
        return
    anchor = live_indices[0] - 1
    # Need at least one fully-frozen message before the live window to cache; early turns
    # (anchor < 1) are cheap, so skip to avoid churn on a tiny prefix.
    if anchor < 1:
        return

    content = messages[anchor].get("content")
    if isinstance(content, list) and content and isinstance(content[-1], dict):
        content[-1]["cache_control"] = {"type": "ephemeral"}


def _set_text_prefix_cache_breakpoint(messages: list[dict[str, Any]]) -> None:
    """Rolling ``cache_control`` breakpoint on the frozen prefix of the text-only planner.

    The planner conversation is append-only and never holds an image, so the image-window logic
    in :func:`_set_message_cache_breakpoint` doesn't apply. Every turn appends exactly one
    message; all prior messages are frozen and byte-identical across calls. Anchor the single
    rolling breakpoint on the last block of ``messages[-2]`` — the newest fully-frozen message,
    byte-identical to the prior request — so Bedrock's longest-prefix match returns the re-sent
    ``[0..-2]`` prefix as ``cache_read_input_tokens`` (excluded from ``input_tokens``) instead of
    re-billing it. ``messages[-1]`` is this turn's fresh append and didn't exist last turn, so
    caching it would only help next turn. Any prior breakpoint is cleared first so exactly one
    rolling message breakpoint exists (system + last-tool breakpoints set in ``bedrock_client``
    bring the total to 3, within Anthropic's 4-breakpoint limit).
    """
    # Always clear stale breakpoints so a moved anchor can't leave two behind.
    for message in messages:
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)

    if not settings.enable_prompt_caching:
        return
    # Need at least one fully-frozen message before the live tail (seed user + assistant + user
    # tool_result) — earlier turns are cheap, so skip to avoid churn on a tiny prefix.
    if len(messages) < 3:
        return

    content = messages[-2].get("content")
    if isinstance(content, list) and content and isinstance(content[-1], dict):
        content[-1]["cache_control"] = {"type": "ephemeral"}


class _Budget:
    """Tracks and enforces the per-run resource caps for the text-only PLANNER context.

    ``total_tokens`` sums the ``input_tokens + output_tokens`` Bedrock reports per PLANNER call
    only; executor (screenshot-bearing) calls are bounded separately per step by
    ``step_max_tokens`` and are NOT summed here, so ``max_total_tokens`` no longer trips on
    cumulative image tokens. Cache-read tokens are also excluded: with prompt caching on,
    Bedrock reports the re-sent prefix as ``cache_read_input_tokens`` (not ``input_tokens``),
    so the counter does not grow super-linearly with the conversation length. ``max_seconds``
    remains the shared whole-run wall-clock guard across planner and executor.
    """

    def __init__(self, *, max_steps: int, max_seconds: float, max_total_tokens: int, clock: Clock):
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.max_total_tokens = max_total_tokens
        self._clock = clock
        self._start = clock()
        self.steps = 0
        self.total_tokens = 0

    @property
    def elapsed(self) -> float:
        return self._clock() - self._start

    def breach(self) -> tuple[TestStatus, str] | None:
        """Return a (status, message) if any cap is breached, else None."""
        if self.steps >= self.max_steps:
            return TestStatus.ERRORED, f"max_steps ({self.max_steps}) reached without a result"
        if self.elapsed >= self.max_seconds:
            return TestStatus.TIMEOUT, f"max_seconds ({self.max_seconds}s) wall-clock budget exceeded"
        if self.total_tokens >= self.max_total_tokens:
            return TestStatus.ERRORED, f"max_total_tokens ({self.max_total_tokens}) budget exceeded"
        return None


def run_step(
    instruction: str,
    *,
    computer: Any,
    client: BedrockClient,
    budget: _Budget,
    step_max_steps: int,
    step_max_tokens: int,
    per_call_tokens: int,
    keep_n: int,
    action_delay: float,
    screenshots_dir: str | None,
    planner_step: int,
    guardrails: Guardrails,
    audit: AuditLog,
    sleep: Callable[[float], None] = time.sleep,
) -> StepOutcome:
    """Run ONE planner-issued instruction in a fresh, disposable vision-executor context.

    Holds its own ``messages`` (with screenshots) that are discarded when it returns; only the
    text :class:`StepOutcome` survives back to the planner. This step's screenshot-heavy tokens
    are NOT folded into the planner's ``budget`` — they are bounded per step by
    ``step_max_tokens`` (reset each step) so a session can run many steps without a cumulative
    image-token ceiling tripping the whole run. The shared ``budget`` still enforces the
    whole-run wall-clock guard (``max_seconds``). The step is additionally capped at
    ``step_max_steps`` vision-loop iterations so one confused instruction can't burn the run.
    Screenshots are saved under ``screenshots_dir`` and returned as :class:`StepRecord`s so the
    HTML report still shows per-step evidence even though the planner never held an image.
    """
    system = build_executor_prompt(instruction)
    tools = [step_done_tool()]
    steps: list[StepRecord] = []
    in_total = 0
    out_total = 0

    initial = computer.screenshot()
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": f"Here is the current screen. Instruction: {instruction}"},
                _image_block(initial.png),
            ],
        }
    ]

    local_steps = 0
    step_tokens = 0
    while True:
        _prune_old_images(messages, keep_n)
        _set_message_cache_breakpoint(messages, keep_n)

        # Only the whole-run wall-clock guard applies inside a step; the planner's cumulative
        # token/step caps are not the executor's ceiling (its image tokens are bounded per step
        # by step_max_tokens instead, checked below).
        if budget.elapsed >= budget.max_seconds:
            return StepOutcome(
                summary=(
                    f"Step aborted: max_seconds ({budget.max_seconds}s) wall-clock budget "
                    "exceeded."
                ),
                success=False,
                steps=steps,
                input_tokens=in_total,
                output_tokens=out_total,
            )
        if step_tokens >= step_max_tokens:
            return StepOutcome(
                summary=(
                    f"Step aborted: step_max_tokens ({step_max_tokens}) budget exceeded; "
                    "instruction may be too large or the screen was unexpected."
                ),
                success=False,
                steps=steps,
                input_tokens=in_total,
                output_tokens=out_total,
            )
        if local_steps >= step_max_steps:
            return StepOutcome(
                summary=(
                    f"Step did not finish within step_max_steps ({step_max_steps}); "
                    "instruction may be too large or the screen was unexpected."
                ),
                success=False,
                steps=steps,
                input_tokens=in_total,
                output_tokens=out_total,
            )

        result, _mode = client.invoke_computer_use(
            messages=messages,
            system=system,
            max_tokens=per_call_tokens,
            extra_tools=tools,
        )
        local_steps += 1
        step_tokens += _tokens(result)
        in_tok = int(result.usage.get("input_tokens", 0) or 0)
        out_tok = int(result.usage.get("output_tokens", 0) or 0)
        in_total += in_tok
        out_total += out_tok

        reasoning = _collect_text(result)
        if reasoning:
            logger.info("  [Step %d exec] reasoning: %s", planner_step, reasoning)
        step_idx = planner_step
        audit.model_response(
            step=step_idx,
            reasoning=reasoning,
            stop_reason=result.stop_reason,
            tool_calls=[{"name": b.name, "input": b.input or {}} for b in result.tool_uses()],
            input_tokens=in_tok,
            output_tokens=out_tok,
        )

        done = _find_tool(result, "step_done")
        if done is not None:
            inp = done.input or {}
            logger.info(
                "  [Step %d exec] step_done (success=%s): %s",
                planner_step,
                bool(inp.get("success", True)),
                inp.get("summary", ""),
            )
            steps.append(
                StepRecord(
                    index=planner_step,
                    reasoning=reasoning,
                    action="step_done",
                    action_input=inp,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                )
            )
            ending = inp.get("ending_state")
            return StepOutcome(
                summary=inp.get("summary"),
                ending_state=str(ending) if ending else None,
                success=bool(inp.get("success", True)),
                steps=steps,
                input_tokens=in_total,
                output_tokens=out_total,
            )

        messages.append({"role": "assistant", "content": result.raw.get("content", [])})

        tool_uses = [b for b in result.tool_uses() if b.name == "computer"]
        if not tool_uses:
            steps.append(
                StepRecord(index=planner_step, reasoning=reasoning, action=None,
                           input_tokens=in_tok, output_tokens=out_tok)
            )
            messages.append({
                "role": "user",
                "content": [{"type": "text", "text": (
                    "Use the `computer` tool to act, or call `step_done` to finish this step."
                )}],
            })
            continue

        tool_results: list[dict[str, Any]] = []
        last_action: str | None = None
        last_input: dict[str, Any] = {}
        before_path: str | None = None
        after_path: str | None = None
        for tu in tool_uses:
            inp = tu.input or {}
            before = computer.screenshot()
            before_path = _save_screenshot(
                screenshots_dir,
                f"step_{planner_step:03d}_{local_steps:02d}_before",
                _evidence_png(before.png, inp),
            )
            text_result = _execute_action(computer, inp, guardrails)
            if action_delay > 0:
                sleep(action_delay)
            after = computer.screenshot()
            after_path = _save_screenshot(
                screenshots_dir, f"step_{planner_step:03d}_{local_steps:02d}_after", after.png
            )
            last_action = inp.get("action")
            last_input = inp
            logger.info("  [Step %d exec] action: %s", planner_step, text_result)
            audit.action(
                step=step_idx,
                action=last_action,
                action_input=inp,
                result=text_result,
                screenshot_path=after_path,
                before_screenshot_path=before_path,
                after_screenshot_path=after_path,
            )
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": [
                    {"type": "text", "text": text_result},
                    _image_block(after.png),
                ],
            })

        steps.append(
            StepRecord(
                index=planner_step,
                reasoning=reasoning,
                action=last_action,
                action_input=last_input,
                before_screenshot_path=before_path,
                after_screenshot_path=after_path,
                input_tokens=in_tok,
                output_tokens=out_tok,
            )
        )
        messages.append({"role": "user", "content": tool_results})


def run_planner_agent(
    spec: TestSpec,
    *,
    computer: Any,
    client: BedrockClient | None = None,
    screenshots_dir: str | None = None,
    max_planner_steps: int | None = None,
    step_max_steps: int | None = None,
    max_seconds: float | None = None,
    max_tokens: int | None = None,
    max_total_tokens: int | None = None,
    step_max_tokens: int | None = None,
    keep_last_n_screenshots: int | None = None,
    action_delay_seconds: float | None = None,
    prior_context: str | None = None,
    manual_dir: str | None = None,
    guardrails: Guardrails | None = None,
    audit: AuditLog | None = None,
    clock: Clock = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> TestResult:
    """Run one spec as a text-only planner that dispatches steps to vision-executor contexts.

    The planner's own ``messages`` never hold a screenshot: each turn it either issues one
    ``next_step`` (dispatched to :func:`run_step`, whose text :class:`StepOutcome` is fed back
    as text) or calls ``report_result`` to finish. Because the planner context stays flat, a
    session can run many steps without its context growing. Returns a :class:`TestResult`.

    Budgets split by tier: ``max_total_tokens`` caps only the text-only planner context (via the
    shared :class:`_Budget`) — it never holds a screenshot, so it grows slowly — while each
    executor step is bounded independently by ``step_max_tokens`` (reset per step). Whole-run
    caps still compose: ``max_seconds`` is the shared wall-clock guard across both tiers and
    ``max_planner_steps`` bounds planner turns; ``step_max_steps`` bounds each executor. This
    tier split is what lets a session run many steps without a cumulative image-token ceiling
    tripping the run.
    """
    client = client or BedrockClient()
    guardrails = guardrails if guardrails is not None else DEFAULT_GUARDRAILS
    audit = audit if audit is not None else AuditLog(None)
    audit.run_start(title=spec.title, target_type=spec.target_type)
    budget = _Budget(
        max_steps=max_planner_steps if max_planner_steps is not None else settings.max_planner_steps,
        max_seconds=max_seconds if max_seconds is not None else settings.max_seconds,
        max_total_tokens=(
            max_total_tokens if max_total_tokens is not None else settings.max_total_tokens
        ),
        clock=clock,
    )
    per_call_tokens = max_tokens if max_tokens is not None else settings.max_tokens
    keep_n = (
        keep_last_n_screenshots
        if keep_last_n_screenshots is not None
        else settings.keep_last_n_screenshots
    )
    action_delay = (
        action_delay_seconds
        if action_delay_seconds is not None
        else settings.action_delay_seconds
    )
    step_cap = step_max_steps if step_max_steps is not None else settings.step_max_steps
    step_token_cap = step_max_tokens if step_max_tokens is not None else settings.step_max_tokens

    system = build_planner_prompt(spec, prior_context)
    manual_available = bool(manual_dir) and os.path.isdir(manual_dir)
    tools = [next_step_tool(), report_result_tool()]
    if manual_available:
        tools.append(read_manual_page_tool())
    steps: list[StepRecord] = []
    planner_metrics: list[PlannerTurnMetric] = []
    # Visible step number for the report and screenshot filenames. Counts only dispatched
    # `next_step` instructions (0-based), so manual-read/no-op planner turns don't leave
    # gaps — "Step N" always lines up with `step_00N_*.png`.
    visible_step = -1
    # Text-only planner conversation. NEVER receives an image block.
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": [{"type": "text", "text": (
                "Begin the test. Issue the first step with `next_step`, or call "
                "`report_result` if there is nothing to do."
            )}],
        }
    ]

    while True:
        breach = budget.breach()
        if breach is not None:
            status, message = breach
            audit.run_end(status=status.value, step_count=budget.steps, error=message)
            return _capped_result(spec, steps, planner_metrics, budget, status, message)

        _set_text_prefix_cache_breakpoint(messages)
        result = client.invoke(
            messages=messages,
            tools=tools,
            system=system,
            max_tokens=per_call_tokens,
        )
        planner_step = budget.steps
        budget.steps += 1
        in_tok = int(result.usage.get("input_tokens", 0) or 0)
        out_tok = int(result.usage.get("output_tokens", 0) or 0)
        cache_read = int(result.usage.get("cache_read_input_tokens", 0) or 0)
        cache_write = int(result.usage.get("cache_creation_input_tokens", 0) or 0)
        budget.total_tokens += in_tok + out_tok
        # Debug: current planner context size. `context_tokens` is the full prompt sent this
        # turn (fresh input + cached prefix) — the live conversation size; `in_tok` alone omits
        # the cached prefix, so it under-reports once prompt caching kicks in.
        logger.debug(
            "planner context size: step=%d messages=%d context_tokens=%d "
            "(input=%d cache_read=%d cache_write=%d) output=%d cumulative_billed=%d/%d",
            planner_step,
            len(messages),
            in_tok + cache_read,
            in_tok,
            cache_read,
            cache_write,
            out_tok,
            budget.total_tokens,
            budget.max_total_tokens,
        )
        planner_metrics.append(
            PlannerTurnMetric(
                step=planner_step,
                messages=len(messages),
                context_tokens=in_tok + cache_read,
                input_tokens=in_tok,
                cache_read=cache_read,
                cache_write=cache_write,
                output_tokens=out_tok,
                cumulative_billed=budget.total_tokens,
                max_total_tokens=budget.max_total_tokens,
            )
        )

        reasoning = _collect_text(result)
        if reasoning:
            logger.info("[planner turn %d] reasoning: %s", planner_step, reasoning)
        audit.model_response(
            step=planner_step,
            reasoning=reasoning,
            stop_reason=result.stop_reason,
            tool_calls=[{"name": b.name, "input": b.input or {}} for b in result.tool_uses()],
            input_tokens=in_tok,
            output_tokens=out_tok,
        )

        report = _find_report(result)
        if report is not None:
            _rep = report.input or {}
            logger.info(
                "[planner turn %d] report_result (passed=%s): %s",
                planner_step,
                bool(_rep.get("passed", False)),
                _rep.get("summary", ""),
            )
            steps.append(
                StepRecord(
                    index=planner_step,
                    reasoning=reasoning,
                    action="report_result",
                    action_input=report.input or {},
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                )
            )
            res = _result_from_report(spec, report.input or {}, steps, planner_metrics, budget)
            audit.run_end(status=res.status.value, step_count=budget.steps)
            return res

        messages.append({"role": "assistant", "content": result.raw.get("content", [])})

        # Bedrock requires EVERY tool_use in this assistant turn to be answered by a matching
        # tool_result in the immediately following message, or the next invoke fails with
        # "tool_use ids were found without tool_result blocks". The model can emit more than
        # one tool_use per turn (e.g. read_manual_page + next_step, or two next_steps), so we
        # act on a single primary tool and answer every other tool_use with a tool_result too.
        tool_uses = list(result.tool_uses())

        read = _find_tool(result, "read_manual_page")
        if read is not None:
            page = str((read.input or {}).get("page", "")).strip()
            logger.info("[planner turn %d] reading manual page: %s", planner_step, page)
            try:
                body = load_manual_page(manual_dir, page)  # type: ignore[arg-type]
                content = f"Manual page {page}:\n{body}"
                loaded_ok = True
            except ManualError as exc:
                content = f"Could not load manual page {page!r}: {exc}"
                loaded_ok = False
            steps.append(
                StepRecord(
                    index=planner_step,
                    reasoning=reasoning,
                    action="read_manual_page",
                    action_input={"page": page, "ok": loaded_ok},
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                )
            )
            tool_results = [_text_tool_result(read.id, content)]
            # Defer any other tool_use in this turn: the planner re-issues it after reading.
            for tu in tool_uses:
                if tu.id != read.id:
                    tool_results.append(_text_tool_result(
                        tu.id,
                        "Deferred: read the requested manual page first, then re-issue this call.",
                    ))
            messages.append({"role": "user", "content": tool_results})
            continue

        plan = _find_tool(result, "next_step")
        if plan is None:
            nudge = "Call `next_step` to issue the next UI step, or `report_result` to finish."
            # Answer every dangling tool_use with a tool_result; if the turn held no tool_use
            # at all, a plain text nudge is valid.
            if tool_uses:
                messages.append({
                    "role": "user",
                    "content": [_text_tool_result(tu.id, nudge) for tu in tool_uses],
                })
            else:
                messages.append({
                    "role": "user",
                    "content": [{"type": "text", "text": nudge}],
                })
            continue

        instruction = str((plan.input or {}).get("instruction", "")).strip()
        visible_step += 1
        rationale = str((plan.input or {}).get("rationale", "")).strip()
        logger.info(
            "[Step %d] next_step: %s%s",
            visible_step,
            instruction,
            f" (rationale: {rationale})" if rationale else "",
        )
        # Record the planner's decision as a StepRecord for the report/audit.
        steps.append(
            StepRecord(
                index=visible_step,
                reasoning=reasoning,
                action="next_step",
                action_input=plan.input or {},
                input_tokens=in_tok,
                output_tokens=out_tok,
            )
        )

        outcome = run_step(
            instruction,
            computer=computer,
            client=client,
            budget=budget,
            step_max_steps=step_cap,
            step_max_tokens=step_token_cap,
            per_call_tokens=per_call_tokens,
            keep_n=keep_n,
            action_delay=action_delay,
            screenshots_dir=screenshots_dir,
            planner_step=visible_step,
            guardrails=guardrails,
            audit=audit,
            sleep=sleep,
        )
        # The executor's per-turn records carry the screenshots the planner never saw.
        steps.extend(outcome.steps)

        # Feed ONLY text back into the planner — this is what keeps the context flat.
        # The next_step tool_use is answered with the executor feedback; any other tool_use
        # emitted in the same turn is answered too (only one step runs per turn), so no
        # tool_use is left without its matching tool_result.
        feedback = _render_step_feedback(instruction, outcome)
        tool_results = [_text_tool_result(plan.id, feedback)]
        for tu in tool_uses:
            if tu.id != plan.id:
                tool_results.append(_text_tool_result(
                    tu.id,
                    "Ignored: issue one `next_step` at a time; this extra call was not run.",
                ))
        messages.append({"role": "user", "content": tool_results})


def _text_tool_result(tool_use_id: str, text: str) -> dict[str, Any]:
    """A ``tool_result`` block answering ``tool_use_id`` with a single text sub-block."""
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": [{"type": "text", "text": text}],
    }


def _render_step_feedback(instruction: str, outcome: StepOutcome) -> str:
    """Compose the text block fed back to the planner after one executor step (no images)."""
    status = "succeeded" if outcome.success else "did NOT succeed"
    lines = [f"Step {status}: {instruction}"]
    if outcome.summary:
        lines.append(f"Summary: {outcome.summary}")
    if outcome.ending_state:
        lines.append(f"Current screen state: {outcome.ending_state}")
    lines.append("Decide the next step, or call `report_result` if the test is complete.")
    return "\n".join(lines)


def _tokens(result: InvokeResult) -> int:
    return int(result.usage.get("input_tokens", 0) or 0) + int(
        result.usage.get("output_tokens", 0) or 0
    )


def _find_tool(result: InvokeResult, name: str) -> ContentBlock | None:
    for b in result.tool_uses():
        if b.name == name:
            return b
    return None


def _execute_action(computer: Any, inp: dict[str, Any], guardrails: Guardrails) -> str:
    """Dispatch a computer action on the executor; return a short text result for the model.

    A guardrail-refused action (e.g. an app-exit / window-switch key combo) is not executed;
    the returned text tells the model it was blocked so it can choose another action.
    """
    action = inp.get("action")
    coordinate = inp.get("coordinate") or [0, 0]
    text = inp.get("text") or ""

    reason = guardrails.check(action, inp)
    if reason is not None:
        return f"Action blocked by guardrails: {reason}."

    if action == "screenshot":
        return "Screenshot captured."
    if action == "left_click":
        computer.left_click(int(coordinate[0]), int(coordinate[1]))
        return f"Left-clicked at {coordinate}."
    if action == "right_click":
        computer.right_click(int(coordinate[0]), int(coordinate[1]))
        return f"Right-clicked at {coordinate}."
    if action == "double_click":
        computer.double_click(int(coordinate[0]), int(coordinate[1]))
        return f"Double-clicked at {coordinate}."
    if action == "mouse_move":
        computer.mouse_move(int(coordinate[0]), int(coordinate[1]))
        return f"Moved cursor to {coordinate}."
    if action == "type":
        computer.type(text)
        return "Typed the requested text."
    if action == "key":
        computer.key(text)
        return f"Pressed key combo {text!r}."
    if action == "scroll":
        direction = inp.get("scroll_direction", "down")
        amount = int(inp.get("scroll_amount", 1) or 1)
        computer.scroll(direction, amount)
        return f"Scrolled {direction} by {amount}."
    if action == "cursor_position":
        x, y = computer.cursor_position()
        return f"Cursor is at ({x}, {y})."
    return f"Unknown action {action!r}; ignored."


def _collect_text(result: InvokeResult) -> str | None:
    texts = [b.text for b in result.content if b.type == "text" and b.text]
    return "\n".join(texts) if texts else None


def _find_report(result: InvokeResult) -> ContentBlock | None:
    for b in result.tool_uses():
        if b.name == "report_result":
            return b
    return None


def _evidence_png(png: bytes, inp: dict[str, Any]) -> bytes:
    """PNG for the report: marked with a red box at the action point, when there is one.

    Coordinate-bearing actions (clicks, mouse_move, scroll) get a red rounded-rectangle
    around where the agent acted; coordinate-free actions (type, key, screenshot) return
    the PNG unchanged. A scroll without a coordinate also returns the PNG unchanged.
    """
    if inp.get("action") not in POINT_ACTIONS:
        return png
    coordinate = inp.get("coordinate")
    if not coordinate or len(coordinate) < 2:
        return png
    return annotate_action(png, (coordinate[0], coordinate[1]))


def _save_screenshot(screenshots_dir: str | None, name: str, png: bytes) -> str | None:
    if not screenshots_dir:
        return None
    os.makedirs(screenshots_dir, exist_ok=True)
    path = os.path.join(screenshots_dir, f"{name}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    return path


def _result_from_report(
    spec: TestSpec,
    report: dict[str, Any],
    steps: list[StepRecord],
    planner_metrics: list[PlannerTurnMetric],
    budget: _Budget,
) -> TestResult:
    per_assertion = []
    for item in report.get("per_assertion", []) or []:
        if isinstance(item, dict):
            per_assertion.append(
                AssertionResult(
                    text=item.get("text", ""),
                    passed=bool(item.get("passed", False)),
                    evidence=item.get("evidence"),
                )
            )
        else:
            per_assertion.append(
                AssertionResult(text=str(item), passed=False, evidence=None)
            )
    passed = bool(report.get("passed", False))
    ending_state = report.get("ending_state")
    return TestResult(
        title=spec.title,
        target_type=spec.target_type,
        status=TestStatus.PASSED if passed else TestStatus.FAILED,
        passed=passed,
        per_assertion=per_assertion,
        declared_assertions=len(spec.assertions),
        summary=report.get("summary"),
        steps=steps,
        step_count=budget.steps,
        input_tokens=sum(s.input_tokens for s in steps),
        output_tokens=sum(s.output_tokens for s in steps),
        duration_seconds=budget.elapsed,
        planner_metrics=planner_metrics,
        ending_state=str(ending_state) if ending_state else None,
    )


def _capped_result(
    spec: TestSpec,
    steps: list[StepRecord],
    planner_metrics: list[PlannerTurnMetric],
    budget: _Budget,
    status: TestStatus,
    message: str,
) -> TestResult:
    return TestResult(
        title=spec.title,
        target_type=spec.target_type,
        status=status,
        passed=None,
        declared_assertions=len(spec.assertions),
        steps=steps,
        step_count=budget.steps,
        input_tokens=sum(s.input_tokens for s in steps),
        output_tokens=sum(s.output_tokens for s in steps),
        duration_seconds=budget.elapsed,
        planner_metrics=planner_metrics,
        error=message,
    )
