#!/usr/bin/env python3
"""Create one private Xauthority entry without invoking a shell or external tool."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import struct


DISPLAY_RE = re.compile(r"^:([0-9]{1,3})$")
AUTH_NAME = b"MIT-MAGIC-COOKIE-1"
FAMILY_WILD = 65535


def _field(value: bytes) -> bytes:
    if len(value) > 65535:
        raise ValueError("Xauthority field is too long")
    return struct.pack(">H", len(value)) + value


def create(path: Path, display: str) -> None:
    match = DISPLAY_RE.fullmatch(display)
    if match is None:
        raise ValueError("display must be an X display number such as :99")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Xauthority output must be an absolute non-link path")
    path.parent.resolve(strict=True)
    payload = (
        struct.pack(">H", FAMILY_WILD)
        + _field(b"")
        + _field(match.group(1).encode("ascii"))
        + _field(AUTH_NAME)
        + _field(secrets.token_bytes(16))
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--display", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    create(args.output, args.display)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
