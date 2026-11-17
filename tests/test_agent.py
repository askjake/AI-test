"""Tests for orchestrator.agent's vision-executor step and shared context helpers.

The see->decide->act loop now lives in :func:`run_step` (one planner-issued instruction per
call); the text-only planner that drives it is covered in ``test_agent_planner.py``. Here the
Bedrock client and the Computer executor are faked so a step runs with no real display or
network, and the image-pruning / cache-breakpoint helpers are exercised directly.
"""

from __future__ import annotations

import copy
import io

from PIL import Image

from orchestrator.agent import (
    _PRUNED_IMAGE_PLACEHOLDER,
    _Budget,
    _image_block,
    _prune_old_images,
    _set_message_cache_breakpoint,
    report_result_tool,
    run_step,
)
from orchestrator.audit import AuditLog
from orchestrator.bedrock_client import InvokeResult
from orchestrator.guardrails import DEFAULT_GUARDRAILS


def _real_png(w=1280, h=800, color=(30, 30, 30)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


class FakeScreenshot:
    def __init__(self, png=None):
        self.png = png if png is not None else _real_png()


class FakeComputer:
    """Records actions; returns a canned screenshot for every capture."""

    def __init__(self):
        self.actions: list[tuple] = []
        self.screenshots = 0

    def screenshot(self):
        self.screenshots += 1
        return FakeScreenshot()

    def left_click(self, x, y):
        self.actions.append(("left_click", x, y))

    def right_click(self, x, y):
        self.actions.append(("right_click", x, y))

    def double_click(self, x, y):
        self.actions.append(("double_click", x, y))

    def mouse_move(self, x, y):
        self.actions.append(("mouse_move", x, y))

    def type(self, text):
        self.actions.append(("type", text))

    def key(self, combo):
        self.actions.append(("key", combo))

    def scroll(self, direction, amount):
        self.actions.append(("scroll", direction, amount))

    def cursor_position(self):
        return (10, 20)


def _raw_content(blocks):
    """Build the raw `.content` list that the loop echoes back as the assistant turn."""
    out = []
    for b in blocks:
        if b["type"] == "text":
            out.append({"type": "text", "text": b["text"]})
        else:
            out.append({
                "type": "tool_use",
                "id": b["id"],
                "name": b["name"],
                "input": b["input"],
            })
    return out


def _result(blocks, usage=None):
    from orchestrator.bedrock_client import ContentBlock

    content = []
    for b in blocks:
        if b["type"] == "text":
            content.append(ContentBlock(type="text", text=b["text"]))
        else:
            content.append(ContentBlock(type="tool_use", name=b["name"],
                                        input=b["input"], id=b["id"]))
    return InvokeResult(
        content=content,
        stop_reason="tool_use",
        usage=usage or {"input_tokens": 5, "output_tokens": 3},
        raw={"content": _raw_content(blocks)},
    )


class FakeClient:
    """Returns queued InvokeResults; records the kwargs of each call.

    ``messages`` is deep-copied per call because the loop mutates the list in place
    (pruning, cache breakpoints); a shared reference would show only the final state.
    """

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def invoke_computer_use(self, **kwargs):
        self.calls.append({**kwargs, "messages": copy.deepcopy(kwargs["messages"])})
        return self._results.pop(0), "custom"


def _run_step(instruction, *, computer, client, screenshots_dir=None,
              step_max_steps=8, step_max_tokens=10**9, keep_n=3, action_delay=0.0,
              planner_step=0, clock=lambda: 0.0):
    """Drive a single vision-executor step under a generous budget (caps tested elsewhere)."""
    budget = _Budget(max_steps=10**9, max_seconds=1e9, max_total_tokens=10**9, clock=clock)
    return run_step(
        instruction,
        computer=computer,
        client=client,
        budget=budget,
        step_max_steps=step_max_steps,
        step_max_tokens=step_max_tokens,
        per_call_tokens=4096,
        keep_n=keep_n,
        action_delay=action_delay,
        screenshots_dir=screenshots_dir,
        planner_step=planner_step,
        guardrails=DEFAULT_GUARDRAILS,
        audit=AuditLog(None),
    )


def _click_block(idx=0):
    return {"type": "tool_use", "id": f"c{idx}", "name": "computer",
            "input": {"action": "left_click", "coordinate": [100, 200]}}


def _step_done_block(success=True, summary="did it", ending="screen state"):
    return {"type": "tool_use", "id": "d0", "name": "step_done",
            "input": {"success": success, "summary": summary, "ending_state": ending}}


# --- report_result tool shape (still used by the planner) -----------------


def test_report_result_tool_shape():
    tool = report_result_tool()
    assert tool["name"] == "report_result"
    props = tool["input_schema"]["properties"]
    assert {"passed", "per_assertion", "summary"} <= set(props)


# --- computer action executed within a step -------------------------------


def test_click_action_executed_and_tool_result_returned():
    comp = FakeComputer()
    client = FakeClient([
        _result([_click_block()]),
        _result([_step_done_block()]),
    ])
    _run_step("click the button", computer=comp, client=client)
    assert ("left_click", 100, 200) in comp.actions
    # Second invoke must carry a tool_result for the click's tool_use id, with a new image.
    second_messages = client.calls[1]["messages"]
    tool_result_msg = second_messages[-1]
    assert tool_result_msg["role"] == "user"
    tr = tool_result_msg["content"][0]
    assert tr["type"] == "tool_result"
    assert tr["tool_use_id"] == "c0"
    assert any(part.get("type") == "image" for part in tr["content"])


# --- step_done terminates the step with a text outcome --------------------


def test_step_done_returns_text_outcome():
    client = FakeClient([_result([
        {"type": "text", "text": "I can see the screen."},
        _step_done_block(success=True, summary="clicked ok", ending="main window"),
    ])])
    outcome = _run_step("do it", computer=FakeComputer(), client=client)
    assert outcome.success is True
    assert outcome.summary == "clicked ok"
    assert outcome.ending_state == "main window"
    assert len(client.calls) == 1  # finished on the first turn


def test_step_done_failure_flag_preserved():
    client = FakeClient([_result([_step_done_block(success=False, summary="could not")])])
    outcome = _run_step("do it", computer=FakeComputer(), client=client)
    assert outcome.success is False
    assert outcome.summary == "could not"


def test_step_max_steps_bounds_a_runaway_step():
    # Never calls step_done -> the inner cap must end the step with success=False.
    client = FakeClient([_result([_click_block(i)]) for i in range(100)])
    outcome = _run_step("loop forever", computer=FakeComputer(), client=client,
                        step_max_steps=3)
    assert outcome.success is False
    assert "step_max_steps" in outcome.summary
    assert len(client.calls) == 3


# --- StepRecord captured per turn -----------------------------------------


def test_step_records_capture_reasoning_action_and_screenshot(tmp_path):
    client = FakeClient([
        _result([{"type": "text", "text": "clicking now"}, _click_block()]),
        _result([{"type": "text", "text": "all good"}, _step_done_block()]),
    ])
    outcome = _run_step("click", computer=FakeComputer(), client=client,
                        screenshots_dir=str(tmp_path))
    assert len(outcome.steps) == 2
    step0 = outcome.steps[0]
    assert step0.reasoning == "clicking now"
    assert step0.action == "left_click"
    assert step0.action_input["coordinate"] == [100, 200]
    assert step0.before_screenshot_path is not None
    assert step0.before_screenshot_path.endswith("step_000_01_before.png")
    assert step0.after_screenshot_path is not None
    assert step0.after_screenshot_path.endswith("step_000_01_after.png")
    # Final turn records the step_done action.
    assert outcome.steps[1].action == "step_done"


def test_screenshots_written_to_disk(tmp_path):
    client = FakeClient([
        _result([_click_block()]),
        _result([_step_done_block()]),
    ])
    _run_step("click", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path))
    written = sorted(p.name for p in tmp_path.glob("*.png"))
    # The seed screenshot is not persisted; only the acting turn's before+after pair is.
    assert "step_000_00_initial.png" not in written
    assert "step_000_01_before.png" in written
    assert "step_000_01_after.png" in written


# --- Red action marker on report screenshots ------------------------------


def _has_red(png: bytes) -> bool:
    img = Image.open(io.BytesIO(png)).convert("RGB")
    return any(r > 150 and g < 80 and b < 80 for (r, g, b) in img.getdata())


def test_report_screenshot_marks_click_location(tmp_path):
    """A coordinate-bearing action gets a red box on the *before* shot; the *after* is plain."""
    client = FakeClient([
        _result([_click_block()]),
        _result([_step_done_block()]),
    ])
    _run_step("click", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path))
    assert _has_red((tmp_path / "step_000_01_before.png").read_bytes())
    # The after shot shows the result un-marked.
    assert not _has_red((tmp_path / "step_000_01_after.png").read_bytes())


def test_model_facing_screenshot_stays_unmarked(tmp_path):
    """The image bytes returned to Claude must NOT carry the red marker."""
    client = FakeClient([
        _result([_click_block()]),
        _result([_step_done_block()]),
    ])
    _run_step("click", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path))
    import base64

    tr = client.calls[1]["messages"][-1]["content"][0]
    image_part = next(p for p in tr["content"] if p.get("type") == "image")
    sent_png = base64.b64decode(image_part["source"]["data"])
    assert not _has_red(sent_png)


def test_non_point_action_screenshot_not_marked(tmp_path):
    """A coordinate-free action (type) leaves the report screenshot unmarked."""
    type_block = {"type": "tool_use", "id": "t0", "name": "computer",
                  "input": {"action": "type", "text": "hello"}}
    client = FakeClient([
        _result([type_block]),
        _result([_step_done_block()]),
    ])
    _run_step("type hello", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path))
    assert not _has_red((tmp_path / "step_000_01_before.png").read_bytes())
    assert not _has_red((tmp_path / "step_000_01_after.png").read_bytes())


def test_prune_old_images_keeps_last_n():
    """Only the most recent keep_last_n images survive; older become placeholder text."""
    seed = {"role": "user", "content": [
        {"type": "text", "text": "begin"},
        _image_block(_real_png()),  # image 1
    ]}
    def tool_result_msg(uid):
        return {"role": "user", "content": [{
            "type": "tool_result",
            "tool_use_id": uid,
            "content": [
                {"type": "text", "text": "did a thing"},
                _image_block(_real_png()),
            ],
        }]}
    messages = [seed]
    for uid in ("t1", "t2", "t3", "t4", "t5"):  # images 2..6
        messages.append({"role": "assistant", "content": []})
        messages.append(tool_result_msg(uid))

    _prune_old_images(messages, keep_last_n=3)

    def image_count(msgs):
        n = 0
        for m in msgs:
            for b in m["content"]:
                if b.get("type") == "image":
                    n += 1
                elif b.get("type") == "tool_result":
                    n += sum(1 for s in b["content"] if s.get("type") == "image")
        return n

    assert image_count(messages) == 3
    # The seed image (oldest) is now a placeholder.
    assert messages[0]["content"][1] == {"type": "text", "text": _PRUNED_IMAGE_PLACEHOLDER}
    # tool_result structure stays intact: id + text result preserved.
    last_tr = messages[-1]["content"][0]
    assert last_tr["tool_use_id"] == "t5"
    assert last_tr["content"][0] == {"type": "text", "text": "did a thing"}
    assert last_tr["content"][1]["type"] == "image"  # most recent image kept


def test_prune_old_images_noop_when_under_window():
    seed = {"role": "user", "content": [_image_block(_real_png())]}
    messages = [seed]
    _prune_old_images(messages, keep_last_n=3)
    assert messages[0]["content"][0]["type"] == "image"


# --- Rolling message cache breakpoint -------------------------------------


def _strip_cache_control(messages):
    out = copy.deepcopy(messages)
    for m in out:
        for b in m.get("content", []):
            if isinstance(b, dict):
                b.pop("cache_control", None)
    return out


def _cache_control_locations(messages):
    """(message_index, block_index) of every block carrying cache_control."""
    locs = []
    for mi, m in enumerate(messages):
        for bi, b in enumerate(m.get("content", [])):
            if isinstance(b, dict) and "cache_control" in b:
                locs.append((mi, bi))
    return locs


def _history():
    """Seed user image + five (assistant tool_use, user tool_result+image) turns."""
    messages = [{"role": "user", "content": [
        {"type": "text", "text": "begin"},
        _image_block(_real_png()),  # image 1
    ]}]
    for i, uid in enumerate(("t1", "t2", "t3", "t4", "t5")):  # images 2..6
        messages.append({"role": "assistant", "content": [
            {"type": "tool_use", "id": uid, "name": "computer",
             "input": {"action": "left_click", "coordinate": [1, 2]}},
        ]})
        messages.append({"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": uid,
            "content": [{"type": "text", "text": "ok"}, _image_block(_real_png())],
        }]})
    return messages


def test_set_message_cache_breakpoint_sits_on_frozen_prefix():
    messages = _history()
    _prune_old_images(messages, keep_last_n=3)
    _set_message_cache_breakpoint(messages, keep_n=3)

    locs = _cache_control_locations(messages)
    assert len(locs) == 1  # exactly one rolling breakpoint
    mi, _ = locs[0]
    # The earliest message still holding a live image is the tool_result for image 4 (idx 6);
    # the breakpoint anchors on the message just before it (idx 5), which is fully frozen.
    assert not _message_live_image(messages[mi])
    assert mi == 5


def _message_live_image(message):
    from orchestrator.agent import _message_has_live_image
    return _message_has_live_image(message)


def test_set_message_cache_breakpoint_noop_disabled(monkeypatch):
    from orchestrator.config import settings
    monkeypatch.setattr(settings, "enable_prompt_caching", False)
    messages = _history()
    _prune_old_images(messages, keep_last_n=3)
    _set_message_cache_breakpoint(messages, keep_n=3)
    assert _cache_control_locations(messages) == []


def test_set_message_cache_breakpoint_clears_stale():
    """A second call moves the single breakpoint forward; it never leaves two behind."""
    messages = _history()
    _prune_old_images(messages, keep_last_n=3)
    _set_message_cache_breakpoint(messages, keep_n=3)
    first = _cache_control_locations(messages)
    # Grow history by one turn, re-prune, re-set: breakpoint advances, stays singular.
    messages.append({"role": "assistant", "content": [
        {"type": "tool_use", "id": "t6", "name": "computer",
         "input": {"action": "left_click", "coordinate": [1, 2]}}]})
    messages.append({"role": "user", "content": [{
        "type": "tool_result", "tool_use_id": "t6",
        "content": [{"type": "text", "text": "ok"}, _image_block(_real_png())]}]})
    _prune_old_images(messages, keep_last_n=3)
    _set_message_cache_breakpoint(messages, keep_n=3)
    second = _cache_control_locations(messages)
    assert len(second) == 1
    assert second[0][0] > first[0][0]  # anchor moved forward


def _many_clicks_then_done(n):
    return FakeClient([_result([_click_block(i)]) for i in range(n)]
                      + [_result([_step_done_block()])])


def test_step_emits_single_breakpoint_on_frozen_block(tmp_path):
    client = _many_clicks_then_done(7)
    _run_step("work", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path), step_max_steps=20)
    msgs = client.calls[-1]["messages"]  # the step_done turn sees the most history
    locs = _cache_control_locations(msgs)
    assert len(locs) == 1
    mi, bi = locs[0]
    # The breakpoint must sit on a non-image block within a fully-frozen message.
    assert msgs[mi]["content"][bi]["type"] != "image"
    assert not _message_live_image(msgs[mi])


def test_cached_prefix_is_byte_stable_across_turns(tmp_path):
    client = _many_clicks_then_done(8)
    _run_step("work", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path), step_max_steps=20)
    # Pick two late consecutive calls that both carry a breakpoint.
    a, b = client.calls[-3]["messages"], client.calls[-2]["messages"]
    locs_a = _cache_control_locations(a)
    assert locs_a, "expected a breakpoint in the earlier call"
    anchor = locs_a[0][0]
    # The frozen content up to the anchor must be identical (ignoring the moving marker).
    a_clean, b_clean = _strip_cache_control(a), _strip_cache_control(b)
    assert a_clean[: anchor + 1] == b_clean[: anchor + 1]


def test_step_no_breakpoint_when_caching_disabled(monkeypatch, tmp_path):
    from orchestrator.config import settings
    monkeypatch.setattr(settings, "enable_prompt_caching", False)
    client = _many_clicks_then_done(7)
    _run_step("work", computer=FakeComputer(), client=client,
              screenshots_dir=str(tmp_path), step_max_steps=20)
    for call in client.calls:
        assert _cache_control_locations(call["messages"]) == []
