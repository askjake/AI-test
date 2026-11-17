"""Phase 5 tests for orchestrator.test_loader (P5-1..P5-5)."""

from __future__ import annotations

import pytest

from orchestrator.models import EffectiveConfig, Target
from orchestrator.test_loader import SpecError, load_spec, parse_spec

FULL_SPEC = """\
# Test: Verify nightly backup ran

## Goal
Connect to the server and confirm today's backup exists in /var/backups.

## Setup
Terminal opens at the home directory.

## Assertions
- A backup file dated today is present in /var/backups.
- `systemctl status backup.service` shows "active".
"""


def _config(**kw) -> EffectiveConfig:
    base = dict(
        max_steps=10,
        max_seconds=60,
        max_tokens=1024,
        max_total_tokens=10000,
        ssh_host_allowlist=["build01"],
        rdp_host_allowlist=["winbox01"],
        target=Target(type="local-app"),
    )
    base.update(kw)
    return EffectiveConfig(**base)


def test_parse_full_spec():
    """P5-1: a complete spec yields title, goal, setup, assertions; target_type from config."""
    spec = parse_spec(FULL_SPEC, config=_config(target=Target(type="ssh-terminal")))
    assert spec.title == "Verify nightly backup ran"
    assert spec.target_type == "ssh-terminal"  # copied from the project's configured target
    assert "today's backup" in spec.goal
    assert spec.setup == "Terminal opens at the home directory."
    assert len(spec.assertions) == 2
    assert spec.assertions[0].startswith("A backup file")


def test_target_type_taken_from_project_config():
    """P5-2: a spec's target_type is the project's configured target type."""
    text = "# Test: x\n## Goal\nDo a thing.\n"
    spec = parse_spec(text, config=_config(target=Target(type="rdp")))
    assert spec.target_type == "rdp"


def test_target_defaults_to_local_app_without_config():
    """P5-2: no config -> local-app."""
    spec = parse_spec("# Test: x\n## Goal\nDo a thing.\n")
    assert spec.target_type == "local-app"


def test_assertions_parsed_as_list():
    """P5-3: each bullet becomes a separate assertion; star bullets too."""
    text = (
        "# Test: x\n## Goal\nG\n## Assertions\n"
        "- one\n* two\n-   three  \n"
    )
    spec = parse_spec(text)
    assert spec.assertions == ["one", "two", "three"]


def test_target_section_rejected():
    """A spec carrying a ## Target section is a load error (target lives in project.yaml)."""
    text = "# Test: x\n## Target\nssh-terminal: host=build01\n## Goal\nG\n"
    with pytest.raises(SpecError, match="no longer supported"):
        parse_spec(text, config=_config())


def test_missing_goal_rejected():
    """P5-5: a spec without a Goal is a clear error."""
    text = "# Test: x\n## Assertions\n- a\n"
    with pytest.raises(SpecError, match="Goal"):
        parse_spec(text)


def test_plain_title_without_test_prefix():
    spec = parse_spec("# My Title\n## Goal\nG\n")
    assert spec.title == "My Title"


def test_manual_section_is_ignored():
    """A ## Manual section is no longer parsed; specs never name manual pages, parse does no I/O.

    The project's manual is injected/loaded by the runner and planner; a spec that still carries
    a ## Manual section is simply ignored (no manual_pages field exists anymore).
    """
    text = (
        "# Test: x\n## Goal\nG\n## Manual\n"
        "- create-service.md\n* bind-stream.md\n"
    )
    spec = parse_spec(text)
    assert not hasattr(spec, "manual_pages")
    assert spec.manual_text is None  # resolution is the runner's job, not the parser's


def test_no_manual_text_after_parse():
    """Parsing never resolves manual text; that is the runner's job."""
    spec = parse_spec(FULL_SPEC)
    assert spec.manual_text is None


def test_load_spec_from_file(tmp_path):
    p = tmp_path / "spec.md"
    p.write_text(FULL_SPEC)
    spec = load_spec(str(p), config=_config())
    assert spec.source_path == str(p)
    assert spec.title == "Verify nightly backup ran"
