"""Pydantic data models shared across the runner (Phase 4+).

Phase 4 introduces the agent-loop models: :class:`TestSpec` (a description of what the
agent should pursue), :class:`StepRecord` (one see->decide->act turn),
:class:`AssertionResult`, and :class:`TestResult` (the structured verdict the HTML reports
render). Phase 5 adds the project layer: :class:`EffectiveConfig` (caps + allowlists +
schedule a project runs under), :class:`Project` (a sub-directory of specs with its merged
config), and :class:`RunResult` (the outcome of running a whole project).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from .chain import ChainHop


class TestStatus(str, Enum):
    """Terminal status of a single test run.

    ``passed``/``failed`` come from the model's ``report_result`` verdict; ``errored`` and
    ``timeout`` are produced when a resource cap (steps/tokens vs. wall-clock) trips before
    the model reports a result.
    """

    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMEOUT = "timeout"


class Target(BaseModel):
    """A project's single target: the window type and the params to open it.

    ``type`` is ``local-app`` | ``host-app`` | ``ssh-terminal`` | ``rdp`` | ``vnc``;
    ``params`` carries the
    type-specific keys (e.g. ``host``, ``user``, ``app``, ``port``, ``via``,
    ``password_file``) the runner hands to ``targets.open_target``. Declared once per project
    in ``project.yaml`` — specs never carry their own target.

    ``rdp-chain`` targets (nested desktop RDP) carry their ordered connections in ``hops``;
    ``params`` stays empty for them.  Every other target type leaves ``hops`` empty, so
    existing projects validate and serialize as before.
    """

    type: str = "local-app"
    params: dict[str, str] = Field(default_factory=dict)
    hops: list[ChainHop] = Field(default_factory=list)


class TestSpec(BaseModel):
    """What a test should accomplish (parsed from a Markdown spec in Phase 5).

    The agent reads ``goal`` and ``assertions`` to drive the loop and ``title`` for
    reporting. ``target_type`` records which window type the test runs against (copied from the
    project's :class:`Target` for reporting/audit). ``source_path`` is the spec file it was
    loaded from (used to slug the evidence directory).
    """

    title: str
    goal: str
    assertions: list[str] = Field(default_factory=list)
    setup: str | None = None
    target_type: str = "local-app"
    source_path: str | None = None
    # The project's master manual.md text, injected into the planner prompt (always, when the
    # project has one). None -> no manual. Detailed topic pages are loaded on demand by the
    # planner via the `read_manual_page` tool, not concatenated here.
    manual_text: str | None = None


class AssertionResult(BaseModel):
    """The model's verdict on a single assertion."""

    text: str
    passed: bool
    evidence: str | None = None


class StepRecord(BaseModel):
    """One turn of the see->decide->act loop.

    Records the model's reasoning text, the action it took (tool name + input), and two
    screenshots kept as report evidence: ``before_screenshot_path`` captured just before the
    action (with a red marker on the action point) and ``after_screenshot_path`` captured
    right after it (plain, showing the result).
    """

    index: int
    reasoning: str | None = None
    action: str | None = None
    action_input: dict = Field(default_factory=dict)
    before_screenshot_path: str | None = None
    after_screenshot_path: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0


class PlannerTurnMetric(BaseModel):
    """One planner-loop turn's token accounting (mirrors the 'planner context size' debug log).

    Captured once per planner turn in ``run_planner_agent`` so the HTML report can chart how the
    text-only planner's context and cumulative billed tokens evolve over a run.
    """

    step: int  # planner_step (0-based)
    messages: int  # len(messages) at this turn
    context_tokens: int  # in_tok + cache_read (full prompt sent this turn)
    input_tokens: int  # in_tok (fresh, uncached input)
    cache_read: int
    cache_write: int
    output_tokens: int
    cumulative_billed: int  # budget.total_tokens after this turn
    max_total_tokens: int  # budget ceiling (constant per run)


class StepOutcome(BaseModel):
    """The result of running one planner-issued instruction in a vision-executor sub-context.

    Returned by ``run_step`` to the planner. Only the *text* fields (``summary``,
    ``ending_state``, ``success``) are fed back into the planner's context — the planner never
    sees a screenshot. ``steps`` carries the executor's per-turn :class:`StepRecord`s (with
    their saved screenshot paths) so the HTML report can still render per-step evidence even
    though the planner's own context held no images.
    """

    summary: str | None = None
    ending_state: str | None = None
    success: bool = True
    steps: list["StepRecord"] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class TestResult(BaseModel):
    """The outcome of running one :class:`TestSpec` through the agent loop."""

    title: str
    target_type: str
    status: TestStatus
    passed: bool | None = None
    per_assertion: list[AssertionResult] = Field(default_factory=list)
    summary: str | None = None
    steps: list[StepRecord] = Field(default_factory=list)
    step_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_seconds: float = 0.0
    # Per-planner-turn token accounting, for the report's context-size charts. Separate from
    # ``steps`` (which mixes in executor sub-context records); one entry per planner loop turn.
    planner_metrics: list[PlannerTurnMetric] = Field(default_factory=list)
    error: str | None = None
    spec_path: str | None = None
    evidence_dir: str | None = None
    # Number of assertions the spec declared. Lets an errored/timeout result — which carries no
    # per-assertion verdicts — still contribute its assertions to the run's assertion totals.
    declared_assertions: int = 0
    # In a shared session, the model's brief description of the app's ending state, handed to
    # the next spec as session context. None outside a session or if the model omitted it.
    ending_state: str | None = None

    @property
    def assertion_total(self) -> int:
        """Assertions this result accounts for: declared count if errored, else verdict count."""
        if self.status in (TestStatus.ERRORED, TestStatus.TIMEOUT):
            return self.declared_assertions
        return len(self.per_assertion)

    @property
    def assertion_passed(self) -> int:
        if self.status in (TestStatus.ERRORED, TestStatus.TIMEOUT):
            return 0
        return sum(1 for a in self.per_assertion if a.passed)

    @property
    def assertion_failed(self) -> int:
        if self.status in (TestStatus.ERRORED, TestStatus.TIMEOUT):
            return 0
        return sum(1 for a in self.per_assertion if not a.passed)

    @property
    def assertion_errored(self) -> int:
        """An errored/timeout spec's assertions are all unevaluated -> counted as errored."""
        if self.status in (TestStatus.ERRORED, TestStatus.TIMEOUT):
            return self.declared_assertions
        return 0


class DigestEntry(BaseModel):
    """One earlier spec's outcome, accumulated into the shared-session digest.

    The digest is the compact text carried *down* into each later child's fresh context (so it
    sees what earlier specs did and the app's resulting state) and rolled *up* into the
    aggregated session report. It holds no screenshots or transcript — only this small summary.
    """

    title: str
    status: TestStatus
    summary: str | None = None
    ending_state: str | None = None


class EffectiveConfig(BaseModel):
    """A project's resolved settings after merging global <- root <- per-project layers.

    Carries the caps the agent loop runs under, the allowlists ``targets.py`` enforces, the
    project's single :class:`Target` (opened once for the whole spec tree), and the cron
    schedule the scheduler (Phase 7) uses. Holds **no secrets** — those live only in the
    read-only ``secrets/`` mount.
    """

    max_steps: int
    max_seconds: int
    max_tokens: int
    max_total_tokens: int
    step_max_tokens: int = 200_000
    keep_last_n_screenshots: int = 3
    action_delay_seconds: float = 3.0
    max_planner_steps: int = 60
    step_max_steps: int = 8
    ssh_host_allowlist: list[str] = Field(default_factory=list)
    rdp_host_allowlist: list[str] = Field(default_factory=list)
    vnc_host_allowlist: list[str] = Field(default_factory=list)
    target: Target = Field(default_factory=Target)
    schedule: str | None = None
    # Absolute path to the project's operating-manual directory (resolved at config load from
    # the required project.yaml ``manual_dir``). None only for the implicit default/single-spec
    # path, which has no owning project.
    manual_dir: str | None = None
    # Optional screenshot-redaction regions (model space), each [x, y, w, h] or
    # {x, y, width, height}. Empty -> redaction is a no-op. Carries no secrets (Phase 8).
    redaction: list = Field(default_factory=list)


class Project(BaseModel):
    """A project: an immediate sub-directory of ``tests_specs/`` with its merged config.

    ``specs`` are the spec paths collected recursively under ``dir`` (``<project>/**/*.md``).
    A ``*.md`` left directly in the ``tests_specs/`` root belongs to the implicit
    ``default`` project. ``config`` is the project's :class:`EffectiveConfig`.
    """

    name: str
    dir: str
    config: EffectiveConfig
    specs: list[str] = Field(default_factory=list)
    enabled: bool = True


class RunResult(BaseModel):
    """The outcome of running every spec in one project (one scheduled/CLI run)."""

    project: str
    run_ts: str
    results: list[TestResult] = Field(default_factory=list)
    report_dir: str | None = None
    # In a shared session, the rolled-up digest text shown as a "Session summary" panel in the
    # aggregated report. None for ordinary (non-session) runs.
    session_summary: str | None = None

    @property
    def total(self) -> int:
        """Total assertions across every spec in the run (not the number of specs)."""
        return sum(r.assertion_total for r in self.results)

    @property
    def passed_count(self) -> int:
        return sum(r.assertion_passed for r in self.results)

    @property
    def failed_count(self) -> int:
        return sum(r.assertion_failed for r in self.results)

    @property
    def errored_count(self) -> int:
        return sum(r.assertion_errored for r in self.results)

    @property
    def spec_total(self) -> int:
        return len(self.results)

    @property
    def spec_errored_count(self) -> int:
        return sum(
            1 for r in self.results if r.status in (TestStatus.ERRORED, TestStatus.TIMEOUT)
        )

    @property
    def duration_seconds(self) -> float:
        return sum(r.duration_seconds for r in self.results)
