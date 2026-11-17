#!/usr/bin/env python3
"""Validate one managed-environment profile without contacting external systems."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from orchestrator_cookie.dependencies import environment_readiness  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("runtime", "test"), required=True)
    args = parser.parse_args()
    readiness = environment_readiness(ROOT, args.profile)
    print(readiness.detail)
    return 0 if readiness.ready else 3


raise SystemExit(main())
