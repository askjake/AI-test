"""Phase 6 tests for orchestrator.report (P6-1..P6-6)."""

from __future__ import annotations

import os

from orchestrator import report
from orchestrator.models import (
    AssertionResult,
    PlannerTurnMetric,
    RunResult,
    StepRecord,
    TestResult,
    TestStatus,
)


def _run_with_one_passing_test(tmp_path, project="checkout", run_ts="20260611T120000Z"):
    """Build a RunResult whose evidence/screenshots live under reports_dir, like a real run."""
    reports_dir = str(tmp_path / "reports")
    run_dir = os.path.join(reports_dir, project, run_ts)
    test_dir = os.path.join(run_dir, "a-spec")
    os.makedirs(test_dir, exist_ok=True)
    before_shot = os.path.join(test_dir, "step_001_before.png")
    after_shot = os.path.join(test_dir, "step_001_after.png")
    for shot in (before_shot, after_shot):
        with open(shot, "wb") as fh:
            fh.write(b"\x89PNG\r\n")

    result = TestResult(
        title="A Spec",
        target_type="local-app",
        status=TestStatus.PASSED,
        passed=True,
        summary="all good",
        step_count=1,
        duration_seconds=3.2,
        per_assertion=[
            AssertionResult(text="Window opens", passed=True, evidence="saw it"),
            AssertionResult(text="Title is right", passed=True),
        ],
        steps=[
            StepRecord(
                index=1,
                reasoning="I will click",
                action="left_click",
                action_input={"coordinate": [10, 20]},
                before_screenshot_path=before_shot,
                after_screenshot_path=after_shot,
            )
        ],
        evidence_dir=test_dir,
    )
    run = RunResult(
        project=project,
        run_ts=run_ts,
        results=[result],
        report_dir=run_dir,
    )
    return run, reports_dir


def test_run_report_header_and_totals(tmp_path):
    """P6-1: header shows project, timestamp, model id, totals, duration."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    path = report.render_run_report(run, model_id="my-model-arn", reports_dir=reports_dir)

    html = open(path, encoding="utf-8").read()
    assert "checkout" in html
    assert "2026-06-11T12:00:00" in html  # run_ts rendered human-readable
    assert "my-model-arn" in html
    assert ">1<" in html  # totals rendered


def test_run_report_per_test_detail_and_relative_screenshot(tmp_path):
    """P6-2 + P6-5: pass/fail badge, per-assertion results, step log, relative screenshot."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()

    assert "Window opens" in html
    assert "Title is right" in html
    # actions render as human-readable descriptions, not raw tool names or JSON
    assert "Left-click at (10, 20)" in html
    assert "left_click" not in html
    # each action carries its short reasoning line
    assert "I will click" in html
    # both before/after screenshots referenced relatively to the run dir, not absolute paths
    assert 'src="a-spec/step_001_before.png"' in html
    assert 'src="a-spec/step_001_after.png"' in html
    assert reports_dir not in html


def test_project_index_lists_runs(tmp_path):
    """P6-3: per-project index lists runs, each linking to its report.html."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    report.render_run_report(run, reports_dir=reports_dir)
    path = report.render_project_index("checkout", reports_dir=reports_dir)

    html = open(path, encoding="utf-8").read()
    assert "20260611T120000Z" in html
    assert "20260611T120000Z/report.html" in html


def test_top_index_lists_projects(tmp_path):
    """P6-4: top-level index lists projects, linking to each per-project index."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    report.render_run_report(run, reports_dir=reports_dir)
    report.render_project_index("checkout", reports_dir=reports_dir)
    path = report.render_top_index(reports_dir=reports_dir)

    html = open(path, encoding="utf-8").read()
    assert "checkout" in html
    assert "checkout/index.html" in html


def test_render_all_produces_full_tree(tmp_path):
    """P6-GATE: render_all writes run report + both indexes."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    report.render_all(run, reports_dir=reports_dir)

    assert os.path.isfile(os.path.join(reports_dir, "index.html"))
    assert os.path.isfile(os.path.join(reports_dir, "checkout", "index.html"))
    assert os.path.isfile(
        os.path.join(reports_dir, "checkout", "20260611T120000Z", "report.html")
    )


def test_empty_run_renders(tmp_path):
    """P6-6: a run with zero tests renders without crashing and states the condition."""
    reports_dir = str(tmp_path / "reports")
    run = RunResult(
        project="empty",
        run_ts="20260611T130000Z",
        results=[],
        report_dir=os.path.join(reports_dir, "empty", "20260611T130000Z"),
    )
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "no tests" in html.lower()


def test_errored_run_renders(tmp_path):
    """P6-6: an all-errored run renders, surfacing the error."""
    reports_dir = str(tmp_path / "reports")
    run_dir = os.path.join(reports_dir, "p", "20260611T140000Z")
    run = RunResult(
        project="p",
        run_ts="20260611T140000Z",
        results=[
            TestResult(
                title="Broken",
                target_type="ssh-terminal",
                status=TestStatus.ERRORED,
                error="target setup failed: host not allowed",
            )
        ],
        report_dir=run_dir,
    )
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "host not allowed" in html
    assert "error" in html.lower()


def test_totals_count_assertions_not_specs():
    """The run totals aggregate over assertions; an errored spec's assertions count as errored."""
    run = RunResult(
        project="p",
        run_ts="20260611T140000Z",
        results=[
            TestResult(
                title="Mixed",
                target_type="vnc",
                status=TestStatus.FAILED,
                passed=False,
                per_assertion=[
                    AssertionResult(text="a", passed=True),
                    AssertionResult(text="b", passed=True),
                    AssertionResult(text="c", passed=False),
                ],
                declared_assertions=3,
            ),
            TestResult(
                title="Broken",
                target_type="vnc",
                status=TestStatus.ERRORED,
                declared_assertions=2,
                error="target setup failed",
            ),
        ],
    )
    assert run.spec_total == 2
    assert run.total == 5  # 3 + 2 declared
    assert run.passed_count == 2
    assert run.failed_count == 1
    assert run.errored_count == 2  # the errored spec's 2 assertions are unevaluated


def test_report_shows_assertion_totals(tmp_path):
    """The run report's summary cards label and count assertions, plus a Specs card."""
    reports_dir = str(tmp_path / "reports")
    run_dir = os.path.join(reports_dir, "p", "20260611T140000Z")
    run = RunResult(
        project="p",
        run_ts="20260611T140000Z",
        results=[
            TestResult(
                title="Four asserts",
                target_type="vnc",
                status=TestStatus.PASSED,
                passed=True,
                per_assertion=[
                    AssertionResult(text=t, passed=True)
                    for t in ("a", "b", "c", "d")
                ],
                declared_assertions=4,
            )
        ],
        report_dir=run_dir,
    )
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "Assertions" in html
    assert ">4<" in html  # four assertions counted
    assert "Specs" in html


def test_fmt_ts_formats_compact_timestamp():
    """A compact run_ts renders as YYYY-MM-DDTHH:mm:ss; odd values pass through."""
    assert report._fmt_ts("20260615T175522Z") == "2026-06-15T17:55:22"
    assert report._fmt_ts("") == ""
    assert report._fmt_ts("not-a-timestamp") == "not-a-timestamp"


def test_step_log_aggregates_planner_step_into_one_dropdown(tmp_path):
    """One planner step's next_step/action/step_done records collapse into a single entry."""
    reports_dir = str(tmp_path / "reports")
    run_dir = os.path.join(reports_dir, "p", "20260706T120000Z")
    result = TestResult(
        title="Grouped",
        target_type="local-app",
        status=TestStatus.PASSED,
        passed=True,
        per_assertion=[AssertionResult(text="ok", passed=True)],
        declared_assertions=1,
        steps=[
            StepRecord(index=0, action="next_step",
                       action_input={"instruction": "Click the Save button",
                                     "rationale": "persist the record"}),
            StepRecord(index=0, action="left_click", action_input={"coordinate": [30, 40]},
                       reasoning="Since the Save button is shown, I will left-click it."),
            StepRecord(index=0, action="step_done",
                       action_input={"success": True, "summary": "Clicked Save",
                                     "ending_state": "Dialog closed"}),
            StepRecord(index=1, action="report_result", action_input={"passed": True}),
        ],
    )
    run = RunResult(project="p", run_ts="20260706T120000Z", results=[result], report_dir=run_dir)
    views = report._step_group_views(result.steps, run_dir)
    # report_result is omitted; the single planner step collapses to one group
    assert len(views) == 1
    g = views[0]
    assert g["instruction"] == "Click the Save button"
    assert g["rationale"] == "persist the record"
    assert g["success"] is True
    assert g["outcome"] == "Clicked Save"
    assert g["ending_state"] == "Dialog closed"
    assert [a["detail"] for a in g["actions"]] == ["Left-click at (30, 40)"]
    assert [a["reasoning"] for a in g["actions"]] == [
        "Since the Save button is shown, I will left-click it."
    ]

    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "next_step" not in html
    assert "step_done" not in html
    assert "Click the Save button" in html
    assert "Clicked Save" in html
    assert "Since the Save button is shown, I will left-click it." in html


def test_manual_reads_surface_in_report_and_skip_step_log(tmp_path):
    """read_manual_page records populate a 'Manuals referenced' section (deduped, first-seen
    order) and are omitted from the step log, which has no screenshots or instruction for them."""
    reports_dir = str(tmp_path / "reports")
    run_dir = os.path.join(reports_dir, "p", "20260709T120000Z")
    result = TestResult(
        title="Manuals",
        target_type="local-app",
        status=TestStatus.PASSED,
        passed=True,
        per_assertion=[AssertionResult(text="ok", passed=True)],
        declared_assertions=1,
        steps=[
            StepRecord(index=0, action="read_manual_page",
                       action_input={"page": "services/100-create.md", "ok": True}),
            StepRecord(index=1, action="read_manual_page",
                       action_input={"page": "services/100-create.md", "ok": True}),
            StepRecord(index=2, action="read_manual_page",
                       action_input={"page": "services/nope.md", "ok": False}),
            StepRecord(index=3, action="next_step",
                       action_input={"instruction": "Open the Create dialog"}),
            StepRecord(index=3, action="step_done",
                       action_input={"success": True, "summary": "Opened"}),
        ],
    )
    run = RunResult(project="p", run_ts="20260709T120000Z", results=[result], report_dir=run_dir)

    # Deduped, first-seen order; failed read flagged not-ok.
    pages = report._manual_pages(result.steps)
    assert pages == [
        {"page": "services/100-create.md", "ok": True},
        {"page": "services/nope.md", "ok": False},
    ]
    # The reads are not rendered as step-log entries.
    views = report._step_group_views(result.steps, run_dir)
    assert [v["index"] for v in views] == [3]

    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "Manuals referenced" in html
    assert "services/100-create.md" in html
    assert "services/nope.md" in html
    assert "read_manual_page" not in html


def test_describe_action_renders_common_actions():
    """Actions render as concise English, never raw JSON input dicts."""
    assert report._describe_action("left_click", {"coordinate": [5, 6]}) == "Left-click at (5, 6)"
    assert report._describe_action("type", {"text": "alice"}) == 'Type "alice"'
    assert report._describe_action("key", {"text": "Return"}) == "Press Return"
    assert report._describe_action("scroll", {"scroll_direction": "up", "scroll_amount": 3}) == "Scroll up by 3"
    assert report._describe_action("screenshot", {}) == "Take screenshot"


def test_clean_reasoning_handles_empty_and_long_text():
    """Reasoning is dropped when empty and truncated when overly long."""
    assert report._clean_reasoning(None) is None
    assert report._clean_reasoning("   ") is None
    assert report._clean_reasoning("  Since X,\n I click Y.  ") == "Since X, I click Y."
    long = report._clean_reasoning("word " * 100)
    assert len(long) <= 240
    assert long.endswith("…")


def test_md_renders_bold_lists_and_escapes_html():
    """The report markdown filter renders bold + bullet/numbered lists and escapes HTML."""
    out = str(report._md("Intro:\n- one\n- two **bold**\n\n1. first\n2. second"))
    assert "<strong>bold</strong>" in out
    assert "<ul><li>one</li><li>two <strong>bold</strong></li></ul>" in out
    assert "<ol><li>first</li><li>second</li></ol>" in out
    assert "<p>Intro:</p>" in out
    # raw HTML in model output is escaped, never emitted as live markup
    assert "&lt;script&gt;" in str(report._md("danger <script>alert(1)</script>"))
    assert "<script>" not in str(report._md("danger <script>alert(1)</script>"))
    assert str(report._md("")) == ""


def _metric(step, ctx, inp, cr, cw, out, cum, cap=150000):
    return PlannerTurnMetric(
        step=step, messages=step * 2 + 1, context_tokens=ctx, input_tokens=inp,
        cache_read=cr, cache_write=cw, output_tokens=out,
        cumulative_billed=cum, max_total_tokens=cap,
    )


def test_planner_charts_rendered_when_metrics_present(tmp_path):
    """A result carrying planner_metrics renders both SVG chart sections."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    run.results[0].planner_metrics = [
        _metric(0, 351, 351, 0, 2830, 86, 437),
        _metric(1, 3248, 418, 2830, 437, 119, 974),
        _metric(2, 3545, 278, 3267, 537, 163, 1415),
    ]
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "Planner context (per step)" in html
    assert "Cumulative tokens billed vs budget" in html
    assert "<svg" in html
    assert "<polyline" in html
    # Legend labels for the context series are present.
    assert "cache_read" in html
    assert "cumulative_billed" in html


def test_planner_charts_omitted_when_no_metrics(tmp_path):
    """No planner_metrics -> the chart section is omitted entirely."""
    run, reports_dir = _run_with_one_passing_test(tmp_path)
    assert run.results[0].planner_metrics == []
    path = report.render_run_report(run, reports_dir=reports_dir)
    html = open(path, encoding="utf-8").read()
    assert "Planner context (per step)" not in html


def test_planner_chart_svg_is_marked_safe():
    """The SVG must be emitted as live markup (not escaped) so the chart renders."""
    result = TestResult(
        title="t", target_type="local-app", status=TestStatus.PASSED, passed=True,
        planner_metrics=[_metric(0, 100, 100, 0, 50, 10, 110),
                         _metric(1, 200, 120, 80, 40, 12, 242)],
    )
    charts = report._planner_charts(result)
    assert charts is not None
    svg = str(charts["context_svg"])
    assert svg.startswith("<svg")
    assert "polyline" in svg
    assert report._planner_charts(
        TestResult(title="t", target_type="local-app", status=TestStatus.PASSED)
    ) is None
