#!/usr/bin/env python3
"""Dependency-free bootstrap into the shared Phase 15 Python manager."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from orchestrator_cookie.cli import main  # noqa: E402

raise SystemExit(main(repo_root=ROOT))
