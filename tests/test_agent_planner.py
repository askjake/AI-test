"""Tests for the text-planner + vision-executor mode (run_planner_agent / run_step).

The planner runs in a text-only context and dispatches each step to a fresh vision-executor
sub-context. The Bedrock client is faked with two queues: planner turns (``invoke``) and
executor turns (``invoke_computer_use``). A fake clock makes the wall-clock cap deterministic.
The central invariant under test: the planner's own messages NEVER carry an image block.
"""

from __future__ import annotations

import copy
import io

from PIL import Image

from orchestrator.agent import (
    build_executor_prompt,
    build_planner_prompt,
    next_step_tool,
    read_manual_page_tool,
    run_planner_agent,
    step_done_tool,
)
from orchestrator.bedrock_client import ContentBlock, InvokeResult
from orchestrator.models import TestSpec, TestStatus


def _real_png(w=1280, h=800, color=(30, 30, 30)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


class FakeScreenshot:
    def __init__(self, png=None):
        self.png = png if png is not None else _real_png()


class FakeComputer:
    def __init__(self):
        self.actions: list[tuple] = []
        self.screenshots = 0

    def screenshot(self):
        self.screenshots += 1
        return FakeScreenshot()

    def left_click(self, x, y):
        self.actions.append(("left_click", x, y))

    def type(self, text):
        self.actions.append(("type", text))


def _raw_content(blocks):
    out = []
    for b in blocks:
        if b["type"] == "text":
            out.append({"type": "text", "text": b["text"]})
        else:
            out.append({"type": "tool_use", "id": b["id"], "name": b["name"], "input": b["input"]})
    return out


def _result(blocks, usage=None):
    content = []
    for b in blocks:
        if b["type"] == "text":
            content.append(ContentBlock(type="text", text=b["text"]))
        else:
            content.append(ContentBlock(type="tool_use", name=b["name"], input=b["input"], id=b["id"]))
    return InvokeResult(
        content=content,
        stop_reason="tool_use",
        usage=usage or {"input_tokens": 5, "output_tokens": 3},
        raw={"content": _raw_content(blocks)},
    )


def _assert_tool_pairing(messages):
    """Mirror Bedrock's rule: each assistant ``tool_use`` must be immediately followed by a
    user message whose FIRST block is a ``tool_result`` for that id. Catches the class of bug
    where the planner appends a plain-text turn after issuing a ``next_step`` tool_use."""
    for i, m in enumerate(messages):
        if m.get("role") != "assistant":
            continue
        pending = [b.get("id") for b in m.get("content", [])
                   if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not pending:
            continue
        nxt = messages[i + 1] if i + 1 < len(messages) else None
        results = []
        if nxt and nxt.get("role") == "user":
            results = [b.get("tool_use_id") for b in nxt.get("content", [])
                       if isinstance(b, dict) and b.get("type") == "tool_result"]
        missing = [tid for tid in pending if tid not in results]
        assert not missing, f"tool_use {missing} had no matching tool_result in next message"


class FakeClient:
    """Two independent queues: planner turns via ``invoke``, executor turns via
    ``invoke_computer_use``. Records the (deep-copied) kwargs of every call so tests can
    inspect exactly what context each tier was sent. Validates tool_use/tool_result pairing
    on every call, as Bedrock does."""

    def __init__(self, planner_results, executor_results):
        self._planner = list(planner_results)
        self._executor = list(executor_results)
        self.planner_calls = []
        self.executor_calls = []

    def invoke(self, **kwargs):
        _assert_tool_pairing(kwargs["messages"])
        self.planner_calls.append({**kwargs, "messages": copy.deepcopy(kwargs["messages"])})
        return self._planner.pop(0)

    def invoke_computer_use(self, **kwargs):
        _assert_tool_pairing(kwargs["messages"])
        self.executor_calls.append({**kwargs, "messages": copy.deepcopy(kwargs["messages"])})
        return self._executor.pop(0), "custom"


def _spec():
    return TestSpec(
        title="Login",
        goal="Log in with a username and password.",
        assertions=["The login dialog is gone."],
        target_type="local-app",
    )


def _next_step(instruction, idx=0):
    return {"type": "tool_use", "id": f"n{idx}", "name": "next_step",
            "input": {"instruction": instruction, "rationale": "because"}}


def _report(passed=True, summary="done", per_assertion=None):
    return {"type": "tool_use", "id": "r1", "name": "report_result",
            "input": {"passed": passed, "summary": summary,
                      "per_assertion": per_assertion or [
                          {"text": "The login dialog is gone.", "passed": True, "evidence": "gone"}
                      ]}}


def _read_manual_page(page, idx=0):
    return {"type": "tool_use", "id": f"m{idx}", "name": "read_manual_page",
            "input": {"page": page}}


def _click(idx=0):
    return {"type": "tool_use", "id": f"c{idx}", "name": "computer",
            "input": {"action": "left_click", "coordinate": [100, 200]}}


def _step_done(success=True, summary="typed it", ending="login dialog, username filled"):
    return {"type": "tool_use", "id": "d0", "name": "step_done",
            "input": {"success": success, "summary": summary, "ending_state": ending}}


# --- prompt / tool shapes -------------------------------------------------


def test_planner_prompt_says_cannot_see_and_forces_report():
    prompt = build_planner_prompt(_spec())
    assert "CANNOT see the screen" in prompt
    assert "next_step" in prompt
    assert "report_result" in prompt
    assert "Log in with a username and password." in prompt


def test_planner_prompt_injects_manual():
    """When the spec carries manual_text, the planner prompt includes it under an operating-
    manual framing so the blind planner can turn goal steps into concrete UI actions."""
    spec = _spec()
    spec.manual_text = "Click the Search button in the top-right of the Services area."
    prompt = build_planner_prompt(spec)
    assert "operating manual" in prompt
    assert "Click the Search button in the top-right of the Services area." in prompt
    # The prompt must point the planner at the on-demand page-loading tool.
    assert "read_manual_page" in prompt


def test_planner_prompt_no_manual_unchanged():
    """No manual_text -> no operating-manual framing (guards against an empty injected block)."""
    prompt = build_planner_prompt(_spec())
    assert "operating manual" not in prompt


def test_executor_prompt_never_holds_manual():
    """The manual is a planner-tier input only; it must never reach the vision executor."""
    prompt = build_executor_prompt("Click the Search button")
    assert "operating manual" not in prompt


def test_tool_shapes():
    assert next_step_tool()["name"] == "next_step"
    assert "instruction" in next_step_tool()["input_schema"]["properties"]
    assert read_manual_page_tool()["name"] == "read_manual_page"
    assert "page" in read_manual_page_tool()["input_schema"]["properties"]
    assert step_done_tool()["name"] == "step_done"
    assert {"success", "summary", "ending_state"} <= set(
        step_done_tool()["input_schema"]["properties"]
    )


# --- core: planner context holds NO images --------------------------------


def _all_text(messages) -> str:
    """Flatten all text in the conversation, including text nested inside tool_result blocks."""
    out = []
    for m in messages:
        for b in m.get("content", []):
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text":
                out.append(b.get("text", ""))
            elif b.get("type") == "tool_result":
                for s in b.get("content", []):
                    if isinstance(s, dict) and s.get("type") == "text":
                        out.append(s.get("text", ""))
    return "".join(out)


def _has_image(messages) -> bool:
    for m in messages:
        for b in m.get("content", []):
            if not isinstance(b, dict):
                continue
            if b.get("type") == "image":
                return True
            if b.get("type") == "tool_result":
                if any(isinstance(s, dict) and s.get("type") == "image"
                       for s in b.get("content", [])):
                    return True
    return False


def test_planner_context_never_holds_an_image(tmp_path):
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()])],
    )
    run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                      screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    # Every planner call's context must be free of image blocks.
    assert client.planner_calls, "planner was never called"
    for call in client.planner_calls:
        assert not _has_image(call["messages"]), "planner context leaked an image block"
    # The executor, by contrast, DOES receive images.
    assert client.executor_calls
    assert _has_image(client.executor_calls[0]["messages"])


def test_executor_summary_fed_back_as_text(tmp_path):
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done(summary="typed alice",
                                              ending="username field shows alice")])],
    )
    run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                      screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    # The second planner turn must see the executor's text summary + ending state.
    second = client.planner_calls[1]["messages"]
    text = _all_text(second)
    assert "typed alice" in text
    assert "username field shows alice" in text


def test_planner_reads_manual_page_on_demand(tmp_path):
    """A read_manual_page tool call loads the topic file and returns its text to the planner as a
    tool_result, without dispatching to the executor. Only requested pages enter context."""
    manual_dir = tmp_path / "manual"
    (manual_dir / "services").mkdir(parents=True)
    (manual_dir / "services" / "100-create.md").write_text("STEP 1: open the Create dialog.")

    client = FakeClient(
        planner_results=[
            _result([_read_manual_page("services/100-create.md", 0)]),
            _result([_next_step("Open the Create dialog", 0)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()])],
    )
    result = run_planner_agent(
        _spec(), computer=FakeComputer(), client=client,
        screenshots_dir=str(tmp_path), manual_dir=str(manual_dir), clock=lambda: 0.0,
    )
    assert result.status is TestStatus.PASSED
    # The page body must have been fed back to the planner as text (no executor dispatch for it).
    second = client.planner_calls[1]["messages"]
    assert "STEP 1: open the Create dialog." in _all_text(second)
    # The manual read consumed one planner turn but no executor step.
    assert len(client.executor_calls) == 1
    # The read is recorded so the report can surface which manual pages were referenced.
    reads = [s for s in result.steps if s.action == "read_manual_page"]
    assert [s.action_input for s in reads] == [{"page": "services/100-create.md", "ok": True}]


def test_planner_read_manual_page_missing_is_recoverable(tmp_path):
    """A missing page returns an error text (not an exception) so the planner can carry on."""
    manual_dir = tmp_path / "manual"
    manual_dir.mkdir()
    client = FakeClient(
        planner_results=[
            _result([_read_manual_page("services/nope.md", 0)]),
            _result([_report()]),
        ],
        executor_results=[],
    )
    result = run_planner_agent(
        _spec(), computer=FakeComputer(), client=client,
        screenshots_dir=str(tmp_path), manual_dir=str(manual_dir), clock=lambda: 0.0,
    )
    assert result.status is TestStatus.PASSED
    second = client.planner_calls[1]["messages"]
    assert "Could not load manual page" in _all_text(second)
    # A failed read is still recorded, flagged not-ok, so the report can surface it.
    reads = [s for s in result.steps if s.action == "read_manual_page"]
    assert [s.action_input for s in reads] == [{"page": "services/nope.md", "ok": False}]


def test_planner_multiple_tool_uses_in_one_turn_are_all_answered(tmp_path):
    """The model can emit more than one tool_use in a single assistant turn (e.g. a
    read_manual_page alongside a next_step, or two next_steps). Bedrock rejects the next
    invoke unless EVERY such tool_use is answered by a matching tool_result, so the planner
    must act on one and answer the rest. FakeClient._assert_tool_pairing enforces this on
    each call; this is the regression guard for the "tool_use ids were found without
    tool_result blocks" ValidationException."""
    manual_dir = tmp_path / "manual"
    (manual_dir / "services").mkdir(parents=True)
    (manual_dir / "services" / "100-create.md").write_text("STEP 1: open the Create dialog.")

    client = FakeClient(
        planner_results=[
            # read_manual_page AND next_step in the same turn -> both must be answered.
            _result([_read_manual_page("services/100-create.md", 0),
                     _next_step("Open the Create dialog", 0)]),
            # two next_steps in one turn -> one runs, the other must still be answered.
            _result([_next_step("Type the name", 1), _next_step("Click OK", 2)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()])],
    )
    result = run_planner_agent(
        _spec(), computer=FakeComputer(), client=client,
        screenshots_dir=str(tmp_path), manual_dir=str(manual_dir), clock=lambda: 0.0,
    )
    assert result.status is TestStatus.PASSED
    # The read branch answers the read and does not dispatch, so only the two accepted
    # next_step turns each run one executor step -> just one executor step total here
    # (the second turn's extra next_step is answered but not run).
    assert len(client.executor_calls) == 1


# --- terminal result ------------------------------------------------------


def test_report_result_terminates_and_captures_steps(tmp_path):
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_next_step("Click Login", 1)]),
            _result([_report(passed=True, summary="logged in")]),
        ],
        executor_results=[
            _result([_step_done(summary="username entered")]),
            _result([_step_done(summary="clicked login", ending="main screen")]),
        ],
    )
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    assert res.status == TestStatus.PASSED
    assert res.passed is True
    assert res.summary == "logged in"
    # Two next_step planner records + the two executors' step_done records + the report record.
    actions = [s.action for s in res.steps]
    assert actions.count("next_step") == 2
    assert actions.count("step_done") == 2
    assert actions.count("report_result") == 1


def test_executor_action_executed_and_screenshots_saved(tmp_path):
    client = FakeClient(
        planner_results=[
            _result([_next_step("Click the login button", 0)]),
            _result([_report()]),
        ],
        executor_results=[_result([_click(0)]), _result([_step_done()])]
        ,
    )
    # The single executor step needs two turns: a click then step_done. Give it both by
    # queueing two executor results (the executor loops until step_done).
    comp = FakeComputer()
    res = run_planner_agent(_spec(), computer=comp, client=client,
                            screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    assert ("left_click", 100, 200) in comp.actions
    assert res.status == TestStatus.PASSED
    written = sorted(p.name for p in tmp_path.glob("*.png"))
    # step 000 = the planner's first dispatched step; executor saves an initial + before/after.
    assert any(n.startswith("step_000_") for n in written)


# --- budgets compose ------------------------------------------------------


def test_max_planner_steps_cap_errored(tmp_path):
    # Planner always issues another step, never reports -> must stop at max_planner_steps.
    planner = [_result([_next_step("keep going", i)]) for i in range(100)]
    # Each dispatched step finishes immediately.
    executor = [_result([_step_done()]) for _ in range(100)]
    client = FakeClient(planner_results=planner, executor_results=executor)
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), max_planner_steps=3,
                            clock=lambda: 0.0)
    assert res.status == TestStatus.ERRORED
    assert "max_steps" in res.error  # _Budget reports the planner-turn cap as max_steps
    assert res.step_count == 3


def test_max_total_tokens_counts_only_planner_not_executor(tmp_path):
    # max_total_tokens bounds the text-only planner context ONLY. Executor turns are hugely
    # expensive (screenshots) but must NOT count toward it — otherwise a long session would
    # trip the cap the way it did before the budget was split. Here each planner turn costs
    # 300 and each executor turn costs 100000; a 1000 planner budget must trip on planner
    # tokens alone, and the error must attribute to max_total_tokens (not step_max_tokens).
    planner = [_result([_next_step("go", i)], usage={"input_tokens": 200, "output_tokens": 100})
               for i in range(100)]
    executor = [_result([_step_done()], usage={"input_tokens": 90000, "output_tokens": 10000})
                for _ in range(100)]
    client = FakeClient(planner_results=planner, executor_results=executor)
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), max_total_tokens=1000,
                            step_max_tokens=10**9, max_planner_steps=100, clock=lambda: 0.0)
    assert res.status == TestStatus.ERRORED
    assert "max_total_tokens" in res.error


def test_step_max_tokens_bounds_one_executor_step_then_planner_replans(tmp_path):
    # An executor step whose screenshot tokens exceed step_max_tokens must end (success=False)
    # WITHOUT tripping the whole run, so the planner still gets text feedback and can report.
    # Each executor turn costs 600; a 1000 step cap ends the step after the second turn.
    executor = [_result([_click(i)], usage={"input_tokens": 400, "output_tokens": 200})
                for i in range(100)]
    client = FakeClient(
        planner_results=[
            _result([_next_step("do the thing", 0)]),
            _result([_report(passed=False, summary="could not")]),
        ],
        executor_results=executor,
    )
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), step_max_tokens=1000,
                            max_total_tokens=10**9, clock=lambda: 0.0)
    # The step stopped on its own token cap (2 turns: 600 then 1200 >= 1000), not the run.
    assert len(client.executor_calls) == 2
    # The run still reached a terminal verdict via the planner.
    assert res.status == TestStatus.FAILED
    second = client.planner_calls[1]["messages"]
    text = _all_text(second)
    assert "did NOT succeed" in text
    assert "step_max_tokens" in text


def test_step_max_steps_bounds_a_runaway_executor(tmp_path):
    # The executor never calls step_done -> its inner cap must end the step (success=False),
    # and the planner then still gets text feedback and can report.
    client = FakeClient(
        planner_results=[
            _result([_next_step("do the thing", 0)]),
            _result([_report(passed=False, summary="could not")]),
        ],
        executor_results=[_result([_click(i)]) for i in range(100)],
    )
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), step_max_steps=2,
                            clock=lambda: 0.0)
    # Executor ran exactly step_max_steps turns for the one step before giving up.
    assert len(client.executor_calls) == 2
    # Planner still finished (reported), so the run has a terminal verdict.
    assert res.status == TestStatus.FAILED
    # The feedback for the failed step reached the planner's second turn.
    second = client.planner_calls[1]["messages"]
    text = _all_text(second)
    assert "did NOT succeed" in text


# --- planner metrics capture ----------------------------------------------


def test_planner_metrics_captured_per_turn(tmp_path):
    """Each planner turn appends one PlannerTurnMetric mirroring the 'planner context size'
    debug log: context_tokens = input + cache_read, and cumulative_billed accumulates
    input+output across turns (executor tokens excluded)."""
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)],
                    usage={"input_tokens": 200, "output_tokens": 50,
                           "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 300}),
            _result([_report()],
                    usage={"input_tokens": 100, "output_tokens": 80,
                           "cache_read_input_tokens": 1500, "cache_creation_input_tokens": 0}),
        ],
        executor_results=[_result([_step_done()],
                                  usage={"input_tokens": 90000, "output_tokens": 10000})],
    )
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    m = res.planner_metrics
    assert [x.step for x in m] == [0, 1]
    # context_tokens = fresh input + cached prefix.
    assert m[0].context_tokens == 200 + 1000
    assert m[1].context_tokens == 100 + 1500
    assert m[0].cache_write == 300
    # cumulative_billed accumulates planner input+output only (executor's 100000 is excluded).
    assert m[0].cumulative_billed == 250
    assert m[1].cumulative_billed == 250 + 180


def test_planner_metrics_captured_on_cap(tmp_path):
    """A capped/errored run still carries the metrics collected up to the breach."""
    planner = [_result([_next_step("go", i)],
                       usage={"input_tokens": 200, "output_tokens": 100})
               for i in range(100)]
    executor = [_result([_step_done()]) for _ in range(100)]
    client = FakeClient(planner_results=planner, executor_results=executor)
    res = run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                            screenshots_dir=str(tmp_path), max_planner_steps=3,
                            clock=lambda: 0.0)
    assert res.status == TestStatus.ERRORED
    assert len(res.planner_metrics) == 3


# --- planner prompt caching -----------------------------------------------


def _cache_control_locations(messages):
    """(message_index, block_index) of every block carrying cache_control."""
    locs = []
    for mi, m in enumerate(messages):
        for bi, b in enumerate(m.get("content", [])):
            if isinstance(b, dict) and "cache_control" in b:
                locs.append((mi, bi))
    return locs


def _strip_cache_control(messages):
    out = copy.deepcopy(messages)
    for m in out:
        for b in m.get("content", []):
            if isinstance(b, dict):
                b.pop("cache_control", None)
    return out


def test_planner_places_cache_breakpoint_on_frozen_prefix(tmp_path):
    """The growing planner conversation gets one rolling cache_control breakpoint, anchored on
    the newest fully-frozen message (messages[-2]) so Bedrock reads the re-sent prefix from
    cache instead of re-billing it as input tokens."""
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_next_step("Enter the password", 1)]),
            _result([_next_step("Click login", 2)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()]) for _ in range(3)],
    )
    run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                      screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    # A late planner call has a real frozen prefix; assert exactly one breakpoint on messages[-2].
    msgs = client.planner_calls[2]["messages"]
    locs = _cache_control_locations(msgs)
    assert len(locs) == 1
    mi, _ = locs[0]
    assert mi == len(msgs) - 2  # newest frozen message, not the fresh final one


def test_planner_cache_breakpoint_advances_as_history_grows(tmp_path):
    """The rolling breakpoint moves forward each turn and the prefix up to it is byte-identical
    across successive calls — the property that makes Bedrock return a growing cache_read."""
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_next_step("Enter the password", 1)]),
            _result([_next_step("Click login", 2)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()]) for _ in range(3)],
    )
    run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                      screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    earlier = client.planner_calls[1]["messages"]
    later = client.planner_calls[2]["messages"]
    e_anchor = _cache_control_locations(earlier)[0][0]
    l_anchor = _cache_control_locations(later)[0][0]
    assert l_anchor > e_anchor  # anchor advanced with the conversation
    # The cached prefix (up to and including the earlier anchor) is byte-stable across turns.
    e_clean = _strip_cache_control(earlier)
    l_clean = _strip_cache_control(later)
    assert e_clean[: e_anchor + 1] == l_clean[: e_anchor + 1]


def test_planner_no_breakpoint_when_caching_disabled(tmp_path, monkeypatch):
    from orchestrator.config import settings
    monkeypatch.setattr(settings, "enable_prompt_caching", False)
    client = FakeClient(
        planner_results=[
            _result([_next_step("Enter the username", 0)]),
            _result([_next_step("Enter the password", 1)]),
            _result([_report()]),
        ],
        executor_results=[_result([_step_done()]) for _ in range(2)],
    )
    run_planner_agent(_spec(), computer=FakeComputer(), client=client,
                      screenshots_dir=str(tmp_path), clock=lambda: 0.0)
    for call in client.planner_calls:
        assert _cache_control_locations(call["messages"]) == []
