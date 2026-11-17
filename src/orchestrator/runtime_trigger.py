"""Run one dashboard-owned project and durably record its redacted outcome."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from orchestrator.runtime_runner import run_request
from orchestrator_cookie.config import ConfigurationError, validate_name


_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|password|authorization|aws_access_key_id|"
    r"aws_secret_access_key|aws_session_token)\b(\s*[=:]\s*)(\S+)"
)


def _atomic_json(path: Path, payload: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".trig_result_", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


_PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_RUN_TS_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")


def release_unused_report_folder(environ=None) -> bool:
    """CP45-H: the dashboard precreates reports/<project>/<run_ts>/ (CP45-G).  If the runner never wrote anything into it (launch failed early),
    remove the EMPTY folder so it cannot look like an active run.  Host-side, dashboard uid: removing an empty directory needs write access to the
    dashboard-owned project directory only.  Never follows links; rmdir fails (harmlessly) if anything is inside."""
    env = os.environ if environ is None else environ
    reports, project, run_ts = env.get("REPORTS_DIR", ""), env.get("ORCHESTRATOR_REPORT_PROJECT", ""), env.get("ORCHESTRATOR_RUN_TS", "")
    if not (reports and os.path.isabs(reports) and _PROJECT_ID_RE.fullmatch(project) and _RUN_TS_ID_RE.fullmatch(run_ts)):
        return False
    path = os.path.join(reports, project, run_ts)
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return False
        os.rmdir(path)
        return True
    except OSError:
        return False


def run(project: str, control_text: str) -> int:
    validate_name(project, "project name")
    control = Path(control_text).resolve()
    if not control.name.endswith(".json.claimed") or not control.is_file():
        raise ConfigurationError("control file must be an existing .json.claimed file")
    try:
        payload = json.loads(control.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("control file is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("project") != project:
        raise ConfigurationError("control file project identity does not match")

    error: str | None = None
    try:
        rc = run_request(project=project)
        if rc != 0:
            error = f"Runner exited with status {rc}; inspect reports/spawn.log."
    except Exception as exc:  # The wrapper must always persist a terminal state.
        rc = 78
        error = str(exc) or type(exc).__name__
    release_unused_report_folder()
    if error:
        error = _SECRET_RE.sub(r"\1\2[redacted]", error)[:600]
        payload.update(
            {
                "error": error,
                "exit_code": rc,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        _atomic_json(control, payload)
    outcome = "ack" if rc == 0 else "err"
    destination = Path(str(control)[: -len(".claimed")] + f".{outcome}")
    if not control.is_file():
        return rc
    os.replace(control, destination)
    return rc


def main(argv: list[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    if len(values) != 2:
        print("usage: runtime_trigger.py PROJECT CONTROL_FILE", file=sys.stderr)
        return 64
    try:
        return run(values[0], values[1])
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
