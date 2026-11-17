"""Renders self-contained HTML reports from run results via Jinja2 templates (Phase 6).

Three render functions produce the report tree under ``reports/``:

- :func:`render_run_report` -> ``reports/<project>/<run_ts>/report.html`` — the per-run
  dashboard: header (project, timestamp, model id, totals, duration), then per test a
  pass/fail badge, per-assertion results, and an expandable step log (reasoning + action +
  screenshot thumbnail). It also drops a tiny ``run.json`` summary the per-project index
  reads back.
- :func:`render_project_index` -> ``reports/<project>/index.html`` — that project's run
  history, newest first, each linking to its ``report.html``.
- :func:`render_top_index` -> ``reports/index.html`` — every project, linking to its index.

Screenshots are referenced **relatively** to the per-run directory so the output renders
standalone when copied or opened straight off disk. :func:`render_all` is the convenience
the runner/scheduler call after a run: write the run report and refresh both indexes.
"""

from __future__ import annotations

import html
import json
import logging
import math
import os
import re
from datetime import datetime
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .config import settings
from .models import RunResult, TestResult, TestStatus

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates")

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)


def _fmt_ts(run_ts: str | None) -> str:
    """Render a compact run_ts (``20260615T175522Z``) as ``2026-06-15T17:55:22``.

    Falls back to the original string if it isn't in the expected compact form, so an
    unexpected value still renders rather than erroring in the template.
    """
    if not run_ts:
        return ""
    try:
        dt = datetime.strptime(run_ts, "%Y%m%dT%H%M%SZ")
    except ValueError:
        return run_ts
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


_env.filters["fmt_ts"] = _fmt_ts


_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_NUMBERED_RE = re.compile(r"^\s*\d+[.)]\s+(.*)$")


def _inline(text: str) -> str:
    """Escape a line of model prose, then apply inline ``**bold**`` and ``code`` spans."""
    out = html.escape(text)
    out = _BOLD_RE.sub(r"<strong>\1</strong>", out)
    out = _INLINE_CODE_RE.sub(r"<code>\1</code>", out)
    return out


def _md(text: str | None) -> Markup:
    """Render the small markdown subset the model emits (bold, bullet/numbered lists, paragraphs).

    Input is HTML-escaped before any markup is added, so this is safe to mark as
    ``Markup`` (no autoescape) without risking injection from model output.
    """
    if not text:
        return Markup("")

    blocks: list[str] = []
    para: list[str] = []
    list_items: list[str] = []
    list_tag: str | None = None  # "ul" or "ol" while a list is open

    def flush_para() -> None:
        if para:
            blocks.append("<p>" + "<br>".join(_inline(p) for p in para) + "</p>")
            para.clear()

    def flush_list() -> None:
        nonlocal list_tag
        if list_tag and list_items:
            items = "".join(f"<li>{it}</li>" for it in list_items)
            blocks.append(f"<{list_tag}>{items}</{list_tag}>")
        list_items.clear()
        list_tag = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush_para()
            flush_list()
            continue
        bullet = _BULLET_RE.match(line)
        numbered = _NUMBERED_RE.match(line)
        if bullet:
            flush_para()
            if list_tag != "ul":
                flush_list()
                list_tag = "ul"
            list_items.append(_inline(bullet.group(1)))
        elif numbered:
            flush_para()
            if list_tag != "ol":
                flush_list()
                list_tag = "ol"
            list_items.append(_inline(numbered.group(1)))
        else:
            flush_list()
            para.append(line.strip())

    flush_para()
    flush_list()
    return Markup("".join(blocks))


_env.filters["md"] = _md


def _badge(status: TestStatus) -> str:
    return {
        TestStatus.PASSED: "pass",
        TestStatus.FAILED: "fail",
        TestStatus.ERRORED: "error",
        TestStatus.TIMEOUT: "error",
    }.get(status, "error")


def _rel_screenshot(path: str | None, run_dir: str) -> str | None:
    """Path to a screenshot relative to the per-run directory (so reports are portable)."""
    if not path:
        return None
    return os.path.relpath(path, run_dir).replace(os.sep, "/")


def _spec_href(result: TestResult, run_dir: str) -> str | None:
    """Relative link from the run report to a spec's own ``report.html`` (or None)."""
    if not result.evidence_dir:
        return None
    rel = os.path.relpath(result.evidence_dir, run_dir).replace(os.sep, "/")
    return f"{rel}/report.html"


_CLICK_VERBS = {
    "left_click": "Left-click",
    "right_click": "Right-click",
    "double_click": "Double-click",
    "middle_click": "Middle-click",
    "mouse_move": "Move cursor",
}


def _describe_action(action: str | None, inp: dict[str, Any]) -> str:
    """A short, fact-based English description of one executor action (no JSON)."""
    if not action:
        return "No action"
    coord = inp.get("coordinate")
    xy = f"({coord[0]}, {coord[1]})" if isinstance(coord, (list, tuple)) and len(coord) >= 2 else None
    if action in _CLICK_VERBS:
        verb = _CLICK_VERBS[action]
        return f"{verb} at {xy}" if xy else verb
    if action == "type":
        text = str(inp.get("text") or "")
        if len(text) > 80:
            text = text[:77] + "…"
        return f'Type "{text}"'
    if action == "key":
        return f"Press {inp.get('text') or ''}".rstrip()
    if action == "scroll":
        direction = inp.get("scroll_direction", "down")
        amount = inp.get("scroll_amount", 1)
        at = f" at {xy}" if xy else ""
        return f"Scroll {direction} by {amount}{at}"
    if action == "screenshot":
        return "Take screenshot"
    if action == "cursor_position":
        return "Read cursor position"
    return action.replace("_", " ").capitalize()


def _clean_reasoning(text: str | None) -> str | None:
    """A short, plain-text rationale for one action, or None when there is nothing to show."""
    if not text:
        return None
    collapsed = " ".join(text.split())
    if not collapsed:
        return None
    if len(collapsed) > 240:
        collapsed = collapsed[:239].rstrip() + "…"
    return collapsed


def _step_group_views(steps: list[StepRecord], run_dir: str) -> list[dict[str, Any]]:
    """Collapse the flat StepRecord list into one group per planner step.

    Each planner step emits records sharing one ``index``: a ``next_step`` (the plain-English
    instruction), zero or more executor actions (with before/after screenshots), and a
    ``step_done`` (the executor's result + ending state). They are aggregated into a single
    dropdown so the report shows one entry per step instead of three raw bullets. The final
    ``report_result`` record is omitted here — its verdict is already shown in the Summary and
    Assertions sections.
    """
    groups: dict[int, dict[str, Any]] = {}
    order: list[dict[str, Any]] = []
    for s in steps:
        if s.action in ("report_result", "read_manual_page"):
            continue
        g = groups.get(s.index)
        if g is None:
            g = {
                "index": s.index,
                "instruction": None,
                "rationale": None,
                "success": None,
                "outcome": None,
                "ending_state": None,
                "actions": [],
            }
            groups[s.index] = g
            order.append(g)
        inp = s.action_input or {}
        if s.action == "next_step":
            g["instruction"] = inp.get("instruction")
            g["rationale"] = inp.get("rationale")
        elif s.action == "step_done":
            g["success"] = inp.get("success")
            g["outcome"] = inp.get("summary")
            g["ending_state"] = inp.get("ending_state")
        elif s.action:
            g["actions"].append(
                {
                    "detail": _describe_action(s.action, inp),
                    "reasoning": _clean_reasoning(s.reasoning),
                    "before_screenshot": _rel_screenshot(s.before_screenshot_path, run_dir),
                    "after_screenshot": _rel_screenshot(s.after_screenshot_path, run_dir),
                }
            )
    return order


def _manual_pages(steps: list[StepRecord]) -> list[dict[str, Any]]:
    """The on-demand manual topic pages this spec loaded, de-duplicated in first-seen order.

    Reflects `read_manual_page` reads only; the master manual.md is auto-injected, not a read,
    so it never appears here. Carries an ``ok`` flag so a failed/mistyped read can be flagged.
    """
    pages: list[dict[str, Any]] = []
    seen: set[str] = set()
    for s in steps:
        if s.action != "read_manual_page":
            continue
        inp = s.action_input or {}
        page = inp.get("page")
        if not page or page in seen:
            continue
        seen.add(page)
        pages.append({"page": page, "ok": bool(inp.get("ok", True))})
    return pages


# Chart geometry (SVG user units); the viewBox scales responsively via CSS.
_CHART_W = 720
_CHART_H = 240
_PAD_L = 56  # room for y-axis labels
_PAD_R = 12
_PAD_T = 12
_PAD_B = 28  # room for x-axis labels


def _nice_ceiling(value: int) -> int:
    """Round a max value up to a friendly axis top (1/2/5 x 10^n)."""
    if value <= 0:
        return 1
    exp = math.floor(math.log10(value))
    base = 10 ** exp
    for mult in (1, 2, 5, 10):
        top = mult * base
        if top >= value:
            return int(top)
    return int(10 * base)


def _line_chart_svg(
    x_values: list[int],
    series: list[tuple[str, str, list[float]]],
    *,
    y_max: float | None = None,
) -> Markup:
    """A dependency-free inline SVG line chart.

    ``series`` is a list of ``(label, color, y_points)`` where each ``y_points`` aligns with
    ``x_values``. All values are numeric (ints from token counts), so the output is safe markup.
    """
    if not x_values:
        return Markup("")
    all_ys = [y for _, _, ys in series for y in ys]
    raw_max = y_max if y_max is not None else (max(all_ys) if all_ys else 1)
    top = _nice_ceiling(int(math.ceil(raw_max)))

    x_min, x_max = min(x_values), max(x_values)
    x_span = (x_max - x_min) or 1
    plot_w = _CHART_W - _PAD_L - _PAD_R
    plot_h = _CHART_H - _PAD_T - _PAD_B

    def px(x: int) -> float:
        return _PAD_L + (x - x_min) / x_span * plot_w

    def py(y: float) -> float:
        return _PAD_T + (1 - y / top) * plot_h

    parts: list[str] = [
        f'<svg viewBox="0 0 {_CHART_W} {_CHART_H}" role="img" '
        f'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="11">'
    ]
    # Horizontal gridlines + y labels (0, mid, top).
    for frac in (0.0, 0.5, 1.0):
        y = py(top * frac)
        parts.append(
            f'<line x1="{_PAD_L}" y1="{y:.1f}" x2="{_CHART_W - _PAD_R}" y2="{y:.1f}" '
            f'stroke="#d0d7de" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{_PAD_L - 6}" y="{y + 3:.1f}" text-anchor="end" fill="#656d76">'
            f"{int(round(top * frac))}</text>"
        )
    # X-axis labels: every step if few, else thinned to ~10 ticks.
    stride = max(1, len(x_values) // 10)
    for i, x in enumerate(x_values):
        if i % stride and i != len(x_values) - 1:
            continue
        parts.append(
            f'<text x="{px(x):.1f}" y="{_CHART_H - 8}" text-anchor="middle" fill="#656d76">'
            f"{x}</text>"
        )
    # One polyline per series.
    for _, color, ys in series:
        pts = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in zip(x_values, ys))
        parts.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linejoin="round" points="{pts}"/>'
        )
    parts.append("</svg>")

    # Legend below the chart.
    legend = ['<div class="legend">']
    for label, color, _ in series:
        legend.append(
            f'<span class="lg"><span class="sw" style="background:{color}"></span>{html.escape(label)}</span>'
        )
    legend.append("</div>")

    return Markup("".join(parts) + "".join(legend))


# Distinct, colour-blind-friendlier palette for the up-to-5 context series.
_CTX_COLORS = {
    "context_tokens": "#0969da",
    "input": "#1a7f37",
    "cache_read": "#8250df",
    "cache_write": "#bf8700",
    "output": "#cf222e",
}


def _planner_charts(result: TestResult) -> dict[str, Markup] | None:
    """Two inline-SVG charts of the planner's per-turn token accounting, or None if no data."""
    metrics = result.planner_metrics
    if not metrics:
        return None
    xs = [m.step for m in metrics]
    context = _line_chart_svg(
        xs,
        [
            ("context_tokens", _CTX_COLORS["context_tokens"], [m.context_tokens for m in metrics]),
            ("input", _CTX_COLORS["input"], [m.input_tokens for m in metrics]),
            ("cache_read", _CTX_COLORS["cache_read"], [m.cache_read for m in metrics]),
            ("cache_write", _CTX_COLORS["cache_write"], [m.cache_write for m in metrics]),
            ("output", _CTX_COLORS["output"], [m.output_tokens for m in metrics]),
        ],
    )
    budget_ceiling = max((m.max_total_tokens for m in metrics), default=0)
    cumulative = _line_chart_svg(
        xs,
        [
            ("cumulative_billed", "#0969da", [m.cumulative_billed for m in metrics]),
            ("budget", "#cf222e", [budget_ceiling for _ in metrics]),
        ],
        y_max=budget_ceiling or None,
    )
    return {"context_svg": context, "cumulative_svg": cumulative}


def _test_view(result: TestResult, run_dir: str) -> dict[str, Any]:
    return {
        "title": result.title,
        "target_type": result.target_type,
        "status": result.status.value,
        "badge": _badge(result.status),
        "summary": result.summary,
        "error": result.error,
        "ending_state": result.ending_state,
        "step_count": result.step_count,
        "duration_seconds": round(result.duration_seconds, 1),
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "spec_href": _spec_href(result, run_dir),
        "assertions": [
            {"text": a.text, "passed": a.passed, "evidence": a.evidence}
            for a in result.per_assertion
        ],
        "manual_pages": _manual_pages(result.steps),
        "steps": _step_group_views(result.steps, run_dir),
        "planner_charts": _planner_charts(result),
    }


def _spec_groups(results: list[TestResult]) -> list[str]:
    """Per-result sub-group label (the spec's directory), for grouping rows in the report.

    Derived from each result's ``spec_path`` relative to the common parent of all spec paths,
    so a session laid out as ``00-login.md`` + ``records/10.md`` yields groups ``""`` and
    ``records``. Returns ``""`` for every result when paths are flat or unavailable, so the
    template simply omits sub-headings for ordinary runs.
    """
    paths = [r.spec_path for r in results if r.spec_path]
    if len(paths) < 2:
        return ["" for _ in results]
    base = os.path.commonpath([os.path.dirname(os.path.abspath(p)) for p in paths])
    groups: list[str] = []
    for r in results:
        if not r.spec_path:
            groups.append("")
            continue
        rel = os.path.relpath(os.path.dirname(os.path.abspath(r.spec_path)), base)
        groups.append("" if rel == "." else rel.replace(os.sep, "/"))
    return groups


def render_spec_report(
    result: TestResult,
    *,
    model_id: str | None = None,
) -> str | None:
    """Render a single spec's own ``report.html`` inside its evidence directory.

    Used by the shared-session runner so every spec has a standalone report alongside the
    aggregated session report. Wraps the one result in a one-result :class:`RunResult` rooted
    at the spec's evidence dir, so the existing relative-screenshot logic resolves. Returns the
    report path, or None if the result has no evidence dir.
    """
    if not result.evidence_dir:
        return None
    run = RunResult(
        project=result.title,
        run_ts="",
        results=[result],
        report_dir=result.evidence_dir,
    )
    return render_run_report(run, model_id=model_id, reports_dir=result.evidence_dir)


def render_run_report(
    run: RunResult,
    *,
    model_id: str | None = None,
    reports_dir: str | None = None,
) -> str:
    """Render ``reports/<project>/<run_ts>/report.html`` and return its path.

    Also writes a small ``run.json`` next to it so :func:`render_project_index` can show
    this run's totals without re-reading every test's ``result.json``.
    """
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir
    run_dir = run.report_dir or os.path.join(reports_dir, run.project, run.run_ts)
    os.makedirs(run_dir, exist_ok=True)

    model_id = model_id if model_id is not None else settings.bedrock_model_id
    tests = [_test_view(r, run_dir) for r in run.results]
    groups = _spec_groups(run.results)
    for view, group in zip(tests, groups):
        view["group"] = group

    html = _env.get_template("report.html.j2").render(
        project=run.project,
        run_ts=run.run_ts,
        model_id=model_id,
        total=run.total,
        passed=run.passed_count,
        failed=run.failed_count,
        errored=run.errored_count,
        spec_total=run.spec_total,
        duration_seconds=round(run.duration_seconds, 1),
        tests=tests,
        session_summary=run.session_summary,
    )
    out_path = os.path.join(run_dir, "report.html")
    _write(out_path, html)

    _write(
        os.path.join(run_dir, "run.json"),
        json.dumps(
            {
                "project": run.project,
                "run_ts": run.run_ts,
                "model_id": model_id,
                "total": run.total,
                "passed": run.passed_count,
                "failed": run.failed_count,
                "errored": run.errored_count,
                "spec_total": run.spec_total,
                "duration_seconds": round(run.duration_seconds, 1),
            },
            indent=2,
        ),
    )
    return out_path


def _scan_runs(project_dir: str) -> list[dict[str, Any]]:
    """Collect each run's summary under ``project_dir``, newest run_ts first."""
    runs: list[dict[str, Any]] = []
    if not os.path.isdir(project_dir):
        return runs
    for entry in sorted(os.listdir(project_dir), reverse=True):
        run_dir = os.path.join(project_dir, entry)
        if not os.path.isdir(run_dir):
            continue
        if not os.path.isfile(os.path.join(run_dir, "report.html")):
            continue
        summary = _read_json(os.path.join(run_dir, "run.json"))
        runs.append(
            {
                "run_ts": entry,
                "report_href": f"{entry}/report.html",
                "total": summary.get("total", 0),
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "errored": summary.get("errored", 0),
                "spec_total": summary.get("spec_total", 0),
                "model_id": summary.get("model_id"),
                "duration_seconds": summary.get("duration_seconds", 0),
            }
        )
    return runs


def render_project_index(
    project: str,
    *,
    reports_dir: str | None = None,
) -> str:
    """Render ``reports/<project>/index.html`` (that project's run history)."""
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir
    project_dir = os.path.join(reports_dir, project)
    os.makedirs(project_dir, exist_ok=True)

    runs = _scan_runs(project_dir)
    html = _env.get_template("project_index.html.j2").render(
        project=project,
        runs=runs,
    )
    out_path = os.path.join(project_dir, "index.html")
    _write(out_path, html)
    return out_path


def render_top_index(*, reports_dir: str | None = None) -> str:
    """Render the top-level ``reports/index.html`` listing every project."""
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir
    os.makedirs(reports_dir, exist_ok=True)

    projects: list[dict[str, Any]] = []
    for entry in sorted(os.listdir(reports_dir)):
        project_dir = os.path.join(reports_dir, entry)
        if not os.path.isdir(project_dir):
            continue
        if not os.path.isfile(os.path.join(project_dir, "index.html")):
            continue
        runs = _scan_runs(project_dir)
        latest = runs[0] if runs else None
        projects.append(
            {
                "name": entry,
                "index_href": f"{entry}/index.html",
                "run_count": len(runs),
                "latest": latest,
            }
        )

    html = _env.get_template("index.html.j2").render(projects=projects)
    out_path = os.path.join(reports_dir, "index.html")
    # CP45-C: the cross-project index is a convenience view shared by every project (nothing in src/ reads it).
    # When the reports root is not writable by the runner uid (0755, host-owned) the refresh is skipped with a
    # warning.  ONLY this write is tolerated: per-run report, run.json, status.json and the project index still raise.
    try:
        _write(out_path, html)
    except PermissionError as exc:
        logger.warning("top-level reports index not refreshed (reports root %s not writable by uid %s): %s",
                       reports_dir, os.getuid() if hasattr(os, "getuid") else "?", exc)
        return ""
    return out_path


def render_all(
    run: RunResult,
    *,
    model_id: str | None = None,
    reports_dir: str | None = None,
) -> str:
    """Write the run report and refresh both indexes; return the run report path."""
    reports_dir = reports_dir if reports_dir is not None else settings.reports_dir
    report_path = render_run_report(run, model_id=model_id, reports_dir=reports_dir)
    render_project_index(run.project, reports_dir=reports_dir)
    render_top_index(reports_dir=reports_dir)
    return report_path


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read_json(path: str) -> dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}
