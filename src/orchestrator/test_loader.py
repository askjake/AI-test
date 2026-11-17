"""Parses plain-English Markdown test specs into :class:`TestSpec` models (Phase 5).

A spec looks like::

    # Test: Verify nightly backup ran
    ## Goal
    Connect to the server and confirm today's backup exists.
    ## Setup (optional)
    Terminal opens at the home directory.
    ## Assertions
    - A backup file dated today is present in /var/backups.
    - `systemctl status backup.service` shows "active".

Parsing rules:

- ``# Test: <title>`` (or just ``# <title>``) -> ``title``.
- ``## Goal`` -> ``goal`` (required; a missing/empty Goal is a load error).
- ``## Setup`` (optional, any heading containing "Setup") -> ``setup``.
- ``## Assertions`` bullet list -> ``assertions`` (one entry per ``-``/``*`` bullet).

The target is **not** declared in the spec — every project has one target set in its
``project.yaml`` (see :mod:`orchestrator.projects`). A spec that still carries a ``## Target``
section is a load error. The spec's ``target_type`` is copied from the project's effective
:class:`Target` purely for reporting/audit; host allowlists are enforced in ``targets.py``
when the target is opened.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from .models import EffectiveConfig, TestSpec


class SpecError(ValueError):
    """Raised when a spec is malformed (missing Goal, missing title, stray ## Target, ...)."""


def _split_sections(text: str) -> tuple[Optional[str], dict[str, str]]:
    """Split Markdown into (title, {section_heading_lower: body}).

    The title is the first ``#`` (level-1) heading; ``## `` level-2 headings start sections.
    Body text before the first ``##`` (other than the title) is ignored.
    """
    title: Optional[str] = None
    sections: dict[str, list[str]] = {}
    current: Optional[str] = None

    for raw in text.splitlines():
        line = raw.rstrip()
        h1 = re.match(r"^#\s+(.*)$", line)
        h2 = re.match(r"^##\s+(.*)$", line)
        if h2:
            current = h2.group(1).strip().lower()
            sections.setdefault(current, [])
            continue
        if h1 and title is None:
            title = h1.group(1).strip()
            current = None
            continue
        if current is not None:
            sections[current].append(raw)

    return title, {k: "\n".join(v).strip() for k, v in sections.items()}


def _find_section(sections: dict[str, str], keyword: str) -> Optional[str]:
    """Return the body of the first section whose heading contains ``keyword``."""
    for heading, body in sections.items():
        if keyword in heading:
            return body
    return None


def _parse_assertions(body: Optional[str]) -> list[str]:
    """Extract bullet items (``-`` or ``*``) from an ``## Assertions`` body."""
    if not body:
        return []
    items: list[str] = []
    for raw in body.splitlines():
        m = re.match(r"^\s*[-*]\s+(.*)$", raw)
        if m and m.group(1).strip():
            items.append(m.group(1).strip())
    return items


def parse_spec(
    text: str,
    *,
    config: EffectiveConfig | None = None,
    source_path: str | None = None,
) -> TestSpec:
    """Parse spec ``text`` into a :class:`TestSpec`, validating against ``config``."""
    title, sections = _split_sections(text)

    goal = _find_section(sections, "goal")
    if not goal:
        raise SpecError("spec is missing a non-empty '## Goal' section")

    if not title:
        raise SpecError("spec is missing a '# Test' title")
    # Allow either "# Test: Foo" or "# Foo".
    title = re.sub(r"^test\s*:\s*", "", title, flags=re.IGNORECASE).strip() or title

    if _find_section(sections, "target") is not None:
        raise SpecError(
            "## Target is no longer supported; declare the target once in the project's "
            "project.yaml (target: type/host/...)"
        )

    target_type = config.target.type if config else "local-app"

    return TestSpec(
        title=title,
        goal=goal,
        setup=_find_section(sections, "setup") or None,
        assertions=_parse_assertions(_find_section(sections, "assertion")),
        target_type=target_type,
        source_path=source_path,
    )


def load_spec(
    path: str,
    *,
    config: EffectiveConfig | None = None,
) -> TestSpec:
    """Load and parse a spec file from ``path``."""
    if not os.path.isfile(path):
        raise SpecError(f"spec file not found: {path!r}")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return parse_spec(text, config=config, source_path=path)
