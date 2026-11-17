"""Credential-free mutation audit trail for dashboard authorization decisions."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

from fastapi import Request

from .auth import Actor


_ACTION_RE = re.compile(r"[^A-Za-z0-9_./{}:-]+")


def _bounded(value: object, maximum: int = 256) -> str:
    text = "".join(char for char in str(value) if char >= " " and char not in "\x7f")
    return text[:maximum]


class MutationAuditTrail:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, *, actor: Actor | None, action: str, outcome: str) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": _bounded(actor.subject if actor else "unauthenticated"),
            "role": actor.role if actor else "none",
            "auth_method": _bounded(actor.auth_method if actor else "none", 64),
            "action": _ACTION_RE.sub("_", action)[:300],
            "outcome": outcome,
        }
        payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.name != "nt":
                os.chmod(self.path, 0o600)


def mutation_action(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    path = template if isinstance(template, str) else request.url.path
    return f"{request.method.upper()} {path}"
