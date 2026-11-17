"""CP45-D (option A): dashboard-owned run-cancellation records and the ONE effective-state rule used by every dashboard reader.

The runner (container uid 10001) owns reports/<project>/<run>/status.json and run.json.  The dashboard never rewrites them.  A cancellation is recorded
instead as ``<ctrl_root>/<project>/cancel_<run_id>.json`` in the dashboard-owned control directory (atomic: mkstemp + os.replace, mode 0600), bound to the
exact project and run id (and to the runner's ``started_at`` incarnation).  Stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

SCHEMA = 1
PREFIX = "cancel_"
ACTIVE = frozenset({"pending", "running"})
CANCELLING = "cancelling"
ACTIVE_EFFECTIVE = ACTIVE | {CANCELLING}
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_STATES = frozenset({"cancelling", "cancelled", "superseded"})
_MAX_BYTES = 65536


class CancelRecordError(RuntimeError):
    """The cancellation record cannot be written safely (untrusted control directory, bad identity, I/O error)."""


def ctrl_root(reports_dir: str, ctrl_dir: str | None = None) -> str:
    return os.path.abspath(ctrl_dir or os.path.join(os.path.abspath(reports_dir), ".ctrl"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ctrl_dir_trusted(path: str) -> tuple[bool, str]:
    """The project control directory must be a real directory owned by the dashboard user and not writable by other users or by a foreign group."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        return False, "control directory is not accessible (%s)" % (exc.strerror or type(exc).__name__)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return False, "control path is not a plain directory"
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        return False, "control directory is not owned by the dashboard user"
    if info.st_mode & 0o002:
        return False, "control directory is world-writable"
    if info.st_mode & 0o020 and hasattr(os, "getegid") and info.st_gid != os.getegid():
        return False, "control directory is group-writable by a foreign group"
    return True, ""


def _check_ids(project: str, run_id: str) -> None:
    if not isinstance(project, str) or not _PROJECT_RE.fullmatch(project) or not isinstance(run_id, str) or not _RUN_RE.fullmatch(run_id):
        raise CancelRecordError("invalid project or run identity")


def marker_path(root: str, project: str, run_id: str) -> str:
    _check_ids(project, run_id)
    return os.path.join(root, project, "%s%s.json" % (PREFIX, run_id))


def read_marker(root: str, project: str, run_id: str) -> dict[str, Any] | None:
    """Return the record only when it is trustworthy and bound to exactly this project and run id; otherwise None."""
    try:
        path = marker_path(root, project, run_id)
    except CancelRecordError:
        return None
    if not ctrl_dir_trusted(os.path.dirname(path))[0]:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES or (hasattr(os, "geteuid") and info.st_uid != os.geteuid()):
            return None
        raw = os.read(fd, _MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or value.get("project") != project or value.get("run_id") != run_id:
        return None
    if value.get("state") not in _STATES:
        return None
    return value


def write_marker(root: str, project: str, run_id: str, record: dict[str, Any]) -> str:
    """Atomically publish the record (temporary file in the same dashboard-owned directory, fchmod 0600, os.replace)."""
    path = marker_path(root, project, run_id)
    parent = os.path.dirname(path)
    ok, why = ctrl_dir_trusted(parent)
    if not ok:
        raise CancelRecordError(why)
    body = dict(record, schema=SCHEMA, project=project, run_id=run_id)
    try:
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=".cancel_", suffix=".tmp")
    except OSError as exc:
        raise CancelRecordError("cannot create the cancellation record (%s)" % (exc.strerror or type(exc).__name__)) from exc
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(body, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise CancelRecordError("cannot write the cancellation record (%s)" % (exc.strerror or type(exc).__name__)) from exc
    return path


def marker_signature(root: str, project: str, run_id: str):
    try:
        info = os.stat(marker_path(root, project, run_id))
    except (OSError, CancelRecordError):
        return None
    return (info.st_mtime_ns, info.st_size)


def confirmed_markers(root: str, project: str, within_seconds: float = 600.0) -> list[dict[str, Any]]:
    out = []
    base = os.path.join(root, project) if _PROJECT_RE.fullmatch(project or "") else None
    if not base:
        return out
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        if not (name.startswith(PREFIX) and name.endswith(".json")):
            continue
        rec = read_marker(root, project, name[len(PREFIX):-len(".json")])
        if rec is None or rec.get("state") != "cancelled" or (rec.get("teardown") or {}).get("confirmed") is not True:
            continue
        try:
            at = datetime.fromisoformat(str((rec.get("teardown") or {}).get("confirmed_at"))).timestamp()
        except ValueError:
            continue
        if time.time() - at <= within_seconds:
            out.append(rec)
    return out


def _binding_problem(marker: dict[str, Any] | None, status: dict[str, Any] | None) -> str | None:
    if marker is None:
        return None
    bound = marker.get("runner_started_at")
    current = status.get("started_at") if status else None
    if bound is not None and current is not None and bound != current:
        return "stale_marker_ignored"      # the record belongs to another incarnation of this run id
    if bound is None and current is not None and marker.get("state") == "cancelled":
        return "stale_marker_ignored"      # a confirmed record is always bound to the last incarnation seen at confirmation
    return None


def effective_state(runner_status: dict[str, Any] | None, marker: dict[str, Any] | None, *, stale: bool = False) -> tuple[str | None, str]:
    """THE rule (status endpoint, idle/active detection and the run list all call this).

    1. No usable record: the runner's own state (an active state whose file went stale is an error, as before).
    2. A record that is superseded, or bound to a different incarnation: ignored.
    3. The runner already committed a terminal state: that result is preserved (a cancel never overwrites it).
    4. Runner still active (or no status yet): 'cancelled' ONLY when the record carries confirmed teardown; otherwise 'cancelling'
       (still active; becomes 'error' once the status file is stale, never 'cancelled').
    """
    status = runner_status if isinstance(runner_status, dict) else None
    rs = status.get("state") if status else None
    rs = rs if isinstance(rs, str) else None
    active = rs in ACTIVE
    base = "error" if (stale and active) else rs
    if marker is None:
        return base, "runner"
    if marker.get("state") == "superseded":
        return base, "marker_superseded"
    problem = _binding_problem(marker, status)
    if problem:
        return base, problem
    if rs is not None and not active:
        # 'error'/'cancelled' written by a runner that was killed by THIS cancellation is a consequence of the stop, not an earlier result.
        consequence = rs in ("error", "cancelled") and marker.get("pre_state") in ACTIVE and marker.get("state") in ("cancelling", "cancelled")
        if not consequence:
            return rs, "terminal_preserved"
    confirmed = marker.get("state") == "cancelled" and (marker.get("teardown") or {}).get("confirmed") is True
    if confirmed:
        return "cancelled", "cancel_record"
    if stale and active:
        return "error", "stale_unconfirmed"
    return CANCELLING, "cancel_pending"
