"""Global configuration (Phase 0).

Settings are read from the environment first (12-factor); nothing is hard-coded and no
secret values live here. These are *global defaults* — each project's
`tests_specs/<project>/project.yaml` may override allowlists, caps, default target, and
schedule (Phase 5). AWS credentials come from the standard credential chain (env / role /
profile), never from this config.
"""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Orchestrator Cookie global settings, populated from environment variables.

    Env vars are the field names upper-cased (e.g. ``BEDROCK_MODEL_ID``, ``MAX_STEPS``).
    List fields accept either JSON (``["a","b"]``) or a comma-separated string.
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Bedrock / model ---------------------------------------------------
    bedrock_model_id: str | None = Field(
        default=None,
        description="Bedrock model id or inference-profile ARN (computer-use capable).",
    )
    aws_region: str = Field(default="us-west-2", description="AWS region for bedrock-runtime.")
    anthropic_version: str = Field(
        default="bedrock-2023-05-31",
        description="anthropic_version sent in the Bedrock invoke body.",
    )
    computer_use_beta: str = Field(
        default="computer-use-2025-11-24",
        description="anthropic_beta flag enabling the native computer-use tool.",
    )
    computer_use_tool_type: str = Field(
        default="computer_20251124",
        description="Native Anthropic computer-use tool type paired with the beta flag.",
    )
    computer_tool_mode: str = Field(
        default="auto",
        description=(
            "How the computer tool is declared to Bedrock: 'beta' (native "
            "computer_20251124), 'custom' (plain custom tool, no beta header), or 'auto' "
            "(try beta, fall back to custom on rejection)."
        ),
    )

    @field_validator("computer_tool_mode")
    @classmethod
    def _valid_tool_mode(cls, v: str) -> str:
        allowed = {"auto", "beta", "custom"}
        if v not in allowed:
            raise ValueError(f"computer_tool_mode must be one of {sorted(allowed)}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _valid_computer_use_pair(self) -> "Settings":
        supported = {
            "computer_20250124": "computer-use-2025-01-24",
            "computer_20251124": "computer-use-2025-11-24",
        }
        expected_beta = supported.get(self.computer_use_tool_type)
        if expected_beta is None:
            raise ValueError("computer_use_tool_type is not a reviewed native tool type")
        if self.computer_use_beta != expected_beta:
            raise ValueError(
                "computer_use_tool_type and computer_use_beta must be a reviewed matching pair"
            )
        return self

    # --- Resource caps (cost + runaway-loop safety) ------------------------
    max_steps: int = Field(default=40, ge=1, description="Max agent loop iterations per test.")
    max_seconds: int = Field(default=1800, ge=1, description="Wall-clock budget per test (seconds).")
    max_tokens: int = Field(default=4096, ge=1, description="Max output tokens per model call.")
    max_total_tokens: int = Field(
        default=200_000,
        ge=1,
        description=(
            "Cumulative token budget for the text-only PLANNER context across one spec (sum "
            "of planner calls only). The planner never holds a screenshot, so this grows "
            "slowly; executor screenshot tokens are bounded separately by step_max_tokens."
        ),
    )
    step_max_tokens: int = Field(
        default=200_000,
        ge=1,
        description=(
            "Cumulative token budget for ONE vision-executor step (sum across that step's "
            "screenshot-bearing calls). Reset per step, so a session can run many steps; a "
            "single confused step that burns this cap ends with success=False and the planner "
            "re-plans. max_seconds remains the whole-run runaway guard."
        ),
    )
    action_delay_seconds: float = Field(
        default=3.0,
        ge=0,
        description=(
            "Seconds to wait after executing a computer action before taking the 'after' "
            "screenshot, so the UI has settled and the screenshot reflects the action's "
            "result rather than its mid-transition state."
        ),
    )
    keep_last_n_screenshots: int = Field(
        default=3,
        ge=1,
        description=(
            "Most recent screenshots kept as real images in the prompt; older ones are "
            "replaced with a text placeholder to bound input-token growth."
        ),
    )
    enable_prompt_caching: bool = Field(
        default=True,
        description=(
            "Add cache_control breakpoints to the static prompt prefix (system + tools) and a "
            "rolling breakpoint over the frozen message-history prefix, so re-sent context is "
            "read from cache instead of re-counted as input tokens."
        ),
    )

    # --- Planner/executor loop (screenshot-free main context) --------------
    # Every spec runs as a text-only planner that dispatches one step at a time to a fresh
    # vision-executor sub-context, so the planner never holds a screenshot and a session can
    # run many steps without its context growing. These two caps bound that loop.
    max_planner_steps: int = Field(
        default=60,
        ge=1,
        description="Max planner iterations per spec (one iteration dispatches one step).",
    )
    step_max_steps: int = Field(
        default=8,
        ge=1,
        description="Max vision-loop iterations inside one executor step before it must finish.",
    )

    # --- Virtual display ---------------------------------------------------
    display: str = Field(default=":1", description="X display the agent drives (Xvfb).")
    # Native Xvfb resolution (what apps render at). Decoupled from model space below.
    screen_w: int = Field(default=1920, ge=1, description="Native Xvfb screen width (px).")
    screen_h: int = Field(default=1080, ge=1, description="Native Xvfb screen height (px).")
    # Model-space resolution (what Claude sees / reasons in). Screenshots are downscaled to
    # this; clicks are scaled back up to native. Kept at/below ~1280px wide for click accuracy
    # and at the native 16:9 aspect ratio so the downscale stays uniform (no distortion).
    model_w: int = Field(default=1280, ge=1, description="Model-space screen width (px).")
    model_h: int = Field(default=720, ge=1, description="Model-space screen height (px).")

    # --- rdp client geometry ----------------------------------------------
    rdp_width: int = Field(default=1280, ge=1, description="xfreerdp connection width (px).")
    rdp_height: int = Field(default=800, ge=1, description="xfreerdp connection height (px).")

    # --- Host allowlists (enforced in targets.py + at spec load) -----------
    ssh_host_allowlist: Annotated[list[str], NoDecode] = Field(
        default_factory=list, description="Hosts permitted for ssh-terminal targets."
    )
    rdp_host_allowlist: Annotated[list[str], NoDecode] = Field(
        default_factory=list, description="Hosts permitted for rdp targets."
    )
    vnc_host_allowlist: Annotated[list[str], NoDecode] = Field(
        default_factory=list, description="Hosts permitted for vnc targets."
    )

    # --- Paths (mounts) ----------------------------------------------------
    tests_specs_dir: str = Field(default="tests_specs", description="Read-only specs root.")
    tests_manuals_dir: str = Field(
        default="tests_manuals", description="Read-only operating-manuals root (outside the spec tree)."
    )
    reports_dir: str = Field(default="reports", description="Writable reports output root.")
    secrets_dir: str = Field(default="secrets", description="Read-only secrets mount (keys/creds).")

    # --- Scheduling --------------------------------------------------------
    default_cron: str = Field(
        default="0 2 * * *", description="Global fallback cron schedule for projects."
    )

    @field_validator("ssh_host_allowlist", "rdp_host_allowlist", "vnc_host_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        """Accept either a JSON list or a comma-separated string from the environment."""
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            if s.startswith("["):
                return json.loads(s)
            return [item.strip() for item in s.split(",") if item.strip()]
        return v


settings = Settings()


if __name__ == "__main__":
    print(settings)
