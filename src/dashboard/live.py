"""SSE live-tailing of audit.jsonl for an in-progress run (Phase 10).

The SSE endpoint tails the active spec's audit.jsonl, identified from the
run's status.json.  When the spec changes (one finishes, the next starts) the
server reads the updated status.json and switches to the new audit.jsonl
automatically — the client holds a single connection for the whole run.

Event types emitted:
  audit_event   — one parsed audit.jsonl line (action / model_response / run_start / run_end)
  spec_change   — the active spec changed (status.json transitioned current_spec)
  run_complete  — run_end seen in audit log, or status.json state == "complete"
  heartbeat     — sent every HEARTBEAT_INTERVAL seconds when idle
  no_active_run — no status.json found; stream closes immediately

Screenshot paths in action events are rewritten to /reports/... URLs so
the browser can display thumbnails directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

logger = logging.getLogger("dashboard.live")

POLL_INTERVAL = 0.2   # seconds between audit.jsonl polls
HEARTBEAT_INTERVAL = 5  # seconds between heartbeat events
STATUS_POLL_INTERVAL = 1.0  # seconds between status.json checks for spec transitions


def _rewrite_screenshot(path: str | None, reports_dir: str) -> str | None:
    """Rewrite an absolute screenshot path to a /reports/... URL."""
    if not path:
        return None
    try:
        reports_root = os.path.realpath(reports_dir)
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        if normalized.startswith("reports/"):
            candidate = os.path.join(reports_root, normalized[len("reports/"):])
        elif "/reports/" in normalized:
            # Container audit logs commonly record /app/reports/... while the
            # dashboard serves the same volume from a different host path.
            candidate = os.path.join(reports_root, normalized.split("/reports/", 1)[1])
        elif os.path.isabs(path):
            candidate = path
        else:
            candidate = os.path.join(reports_root, path)
        candidate = os.path.realpath(candidate)
        if os.path.commonpath((reports_root, candidate)) != reports_root:
            return None
        rel = os.path.relpath(candidate, reports_root)
        return "/reports/" + rel.replace(os.sep, "/")
    except ValueError:
        return None


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _audit_dirs(run_dir: str, status: dict) -> list[tuple[str, str]]:
    """Return completed evidence directories in stable spec order."""
    found: dict[str, tuple[str, str, float]] = {}
    try:
        entries = os.listdir(run_dir)
    except OSError:
        return []
    for entry in entries:
        evidence_dir = os.path.join(run_dir, entry)
        audit_path = os.path.join(evidence_dir, "audit.jsonl")
        if not os.path.isfile(audit_path):
            continue
        result = _read_json(os.path.join(evidence_dir, "result.json"))
        title = str(result.get("title") or result.get("spec") or entry)
        try:
            mtime = os.path.getmtime(audit_path)
        except OSError:
            mtime = 0.0
        found[entry] = (title, audit_path, mtime)

    ordered: list[tuple[str, str]] = []
    used: set[str] = set()
    for completed in status.get("specs_completed", []):
        if not isinstance(completed, dict):
            continue
        evidence_name = completed.get("evidence_dir")
        match = found.get(str(evidence_name)) if evidence_name else None
        if match is None:
            wanted_title = str(completed.get("title") or "")
            for name, candidate in found.items():
                if name not in used and candidate[0] == wanted_title:
                    evidence_name, match = name, candidate
                    break
        if match is not None and evidence_name is not None:
            used.add(str(evidence_name))
            ordered.append((match[0], match[1]))

    for name, candidate in sorted(found.items(), key=lambda item: (item[1][2], item[0])):
        if name not in used:
            ordered.append((candidate[0], candidate[1]))
    return ordered


async def _replay_completed_run(
    run_dir: str, status: dict, reports_dir: str
) -> "AsyncGenerator[dict, None]":
    audits = _audit_dirs(run_dir, status)
    total = int(status.get("specs_total") or len(audits))
    for index, (title, audit_path) in enumerate(audits):
        yield {
            "event": "spec_change",
            "data": json.dumps({"spec": title, "index": index, "total": total}),
        }
        try:
            with open(audit_path, encoding="utf-8") as audit_fh:
                for line in audit_fh:
                    line = line.strip()
                    if line:
                        yield _parse_audit_line(line, reports_dir)
        except OSError:
            continue
    yield {
        "event": "run_complete",
        "data": json.dumps({"state": status.get("state", "complete")}),
    }


async def tail_run(
    reports_dir: str,
    project: str,
    run_ts: str,
    *,
    stale_seconds: int = 0,
) -> "AsyncGenerator[dict, None]":
    """Async generator yielding SSE payload dicts for a run.

    Each yielded dict has keys: ``event`` (str) and ``data`` (str, JSON).
    The caller (routes.py EventSourceResponse) formats them as SSE wire frames.
    """
    run_dir = os.path.join(reports_dir, project, run_ts)
    status_path = os.path.join(run_dir, "status.json")

    # ── Gate: run must exist ──────────────────────────────────────────────
    if not os.path.isdir(run_dir):
        yield {"event": "no_active_run", "data": json.dumps({"reason": "run dir not found"})}
        return

    # Wait for status.json to appear — the container may still be starting up.
    _WAIT_FOR_STATUS_SECS = 30
    _status_waited = 0.0
    while not os.path.isfile(status_path) and _status_waited < _WAIT_FOR_STATUS_SECS:
        await asyncio.sleep(0.5)
        _status_waited += 0.5

    if not os.path.isfile(status_path):
        yield {"event": "no_active_run", "data": json.dumps({"reason": "status.json not found after 30s"})}
        return

    initial_status = _read_json(status_path)
    if _status_is_stale(status_path, initial_status, stale_seconds):
        initial_status = {
            **initial_status,
            "state": "error",
            "reason": "stale status file",
        }
    if initial_status.get("state") in ("complete", "error", "cancelled"):
        async for payload in _replay_completed_run(run_dir, initial_status, reports_dir):
            yield payload
        return

    last_heartbeat = asyncio.get_event_loop().time()
    last_status_check = 0.0
    current_evidence_dir: str | None = None
    audit_fh = None
    audit_path: str | None = None

    try:
        while True:
            now = asyncio.get_event_loop().time()

            # ── Periodically re-read status.json ─────────────────────────
            if now - last_status_check >= STATUS_POLL_INTERVAL:
                last_status_check = now
                try:
                    with open(status_path, encoding="utf-8") as sf:
                        status = json.load(sf)
                except (json.JSONDecodeError, OSError):
                    status = {}

                new_evidence_dir = status.get("current_evidence_dir")
                state = status.get("state", "running")
                if _status_is_stale(status_path, status, stale_seconds):
                    state = "error"

                # Detect spec transition: close old audit fh, open new one.
                if new_evidence_dir and new_evidence_dir != current_evidence_dir:
                    if audit_fh:
                        audit_fh.close()
                        audit_fh = None
                    current_evidence_dir = new_evidence_dir
                    audit_path = os.path.join(run_dir, current_evidence_dir, "audit.jsonl")
                    if current_evidence_dir:
                        yield {
                            "event": "spec_change",
                            "data": json.dumps({
                                "spec": status.get("current_spec"),
                                "index": status.get("current_spec_index", 0),
                                "total": status.get("specs_total", 0),
                            }),
                        }
                    # Open audit file and seek to start (tail from beginning for new spec)
                    if audit_path and os.path.isfile(audit_path):
                        audit_fh = open(audit_path, encoding="utf-8")  # noqa: WPS515

                # Run complete via status.json.
                # Fire run_complete whenever state is terminal — do NOT gate on
                # new_evidence_dir == current_evidence_dir.  The final _write_status
                # call sets current_evidence_dir=None (no next spec), so the old
                # equality check was always False and the stream never closed.
                if state in ("complete", "error", "cancelled"):
                    # Drain any remaining audit lines before closing
                    if audit_fh:
                        for line in audit_fh:
                            line = line.strip()
                            if line:
                                yield _parse_audit_line(line, reports_dir)
                    yield {"event": "run_complete", "data": json.dumps({"state": state})}
                    return

            # ── Drain new lines from current audit.jsonl ─────────────────
            # Re-open audit file if it appeared after the spec_change event.
            if audit_fh is None and audit_path and os.path.isfile(audit_path):
                audit_fh = open(audit_path, encoding="utf-8")  # noqa: WPS515
            if audit_fh:
                new_lines = 0
                while True:
                    line = audit_fh.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        event = _parse_audit_line(line, reports_dir)
                        yield event
                        new_lines += 1
                        last_heartbeat = now
                        # run_end in audit closes this spec's stream
                        if _is_run_end(line):
                            # Let status.json drive the final close (above loop)
                            pass

            # ── Heartbeat ─────────────────────────────────────────────────
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                yield {"event": "heartbeat", "data": json.dumps({"ts": now})}
                last_heartbeat = now

            await asyncio.sleep(POLL_INTERVAL)

    finally:
        if audit_fh:
            audit_fh.close()


def _parse_audit_line(line: str, reports_dir: str) -> dict:
    """Parse one audit.jsonl line and rewrite screenshot paths to /reports/ URLs."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return {"event": "audit_event", "data": line}

    screenshot_fields = (
        ("screenshot_path", "screenshot_url"),
        ("before_screenshot_path", "before_screenshot_url"),
        ("after_screenshot_path", "after_screenshot_url"),
    )
    for path_field, url_field in screenshot_fields:
        if path_field in event:
            event[url_field] = _rewrite_screenshot(event[path_field], reports_dir)

    return {"event": "audit_event", "data": json.dumps(event)}


def _is_run_end(line: str) -> bool:
    try:
        return json.loads(line).get("kind") == "run_end"
    except (json.JSONDecodeError, AttributeError):
        return False


def _status_is_stale(path: str, status: dict, stale_seconds: int) -> bool:
    if stale_seconds <= 0 or status.get("state") not in ("pending", "running"):
        return False
    try:
        return time.time() - os.path.getmtime(path) > stale_seconds
    except OSError:
        return False
