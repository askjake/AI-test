#!/usr/bin/env bash
# Run one dashboard-owned trigger and record its durable outcome.
set -uo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 PROJECT CONTROL_FILE" >&2
    exit 64
fi

PROJECT="$1"
CONTROL_FILE="$2"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SPECS_SCRIPT="${RUN_SPECS_SCRIPT:-${PROJECT_ROOT}/scripts/run_specs.sh}"

if [[ ! "${PROJECT}" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "error: invalid project name: ${PROJECT}" >&2
    exit 64
fi

if [[ "${CONTROL_FILE}" != *.json.claimed ]]; then
    echo "error: control file must end in .json.claimed" >&2
    exit 64
fi

run_log="$(mktemp -t app-gui-trigger.XXXXXX)"
trap 'rm -f -- "${run_log}"' EXIT
"${RUN_SPECS_SCRIPT}" "${PROJECT}" 2>&1 | tee "${run_log}"
pipeline_status=("${PIPESTATUS[@]}")
rc="${pipeline_status[0]}"

outcome="err"
if [[ "${rc}" -eq 0 ]]; then
    outcome="ack"
else
    # Persist only a concise redacted reason in the control JSON. The complete
    # output still flows to reports/spawn.log via the parent process, while the
    # temporary capture is removed on exit.
    "${DASHBOARD_PYTHON:-python3}" - "${CONTROL_FILE}" "${run_log}" "${rc}" <<'PY' || true
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import sys
import tempfile

control_path, log_path, exit_code = sys.argv[1:]
ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
secret = re.compile(
    r"(?i)\b(token|secret|password|authorization|aws_access_key_id|"
    r"aws_secret_access_key|aws_session_token)\b(\s*[=:]\s*)(\S+)"
)
query_secret = re.compile(r'(?i)([?&](?:token|key|secret)=)[^&\s"]+')
error_hint = re.compile(
    r"(?i)\b(error|failed|failure|denied|forbidden|not found|cannot|unable|"
    r"invalid|missing|required|timed out|timeout|refused)\b"
)

with open(log_path, encoding="utf-8", errors="replace") as fh:
    raw_lines = fh.readlines()[-80:]

lines: list[str] = []
for raw in raw_lines:
    line = ansi.sub("", raw)
    line = "".join(char for char in line if char == "\t" or ord(char) >= 32)
    line = query_secret.sub(r"\1[redacted]", line)
    line = secret.sub(r"\1\2[redacted]", line).strip()
    if line:
        lines.append(line[:600])

reason = next((line for line in reversed(lines) if error_hint.search(line)), None)
reason = reason or (lines[-1] if lines else "Run process exited unsuccessfully.")

try:
    with open(control_path, encoding="utf-8") as fh:
        payload = json.load(fh)
except (OSError, json.JSONDecodeError):
    payload = {}
payload["error"] = reason
payload["exit_code"] = int(exit_code)
payload["finished_at"] = datetime.now(timezone.utc).isoformat()

parent = os.path.dirname(control_path)
fd, temporary = tempfile.mkstemp(dir=parent, prefix=".trig_result_", suffix=".json")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(temporary, control_path)
except BaseException:
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PY
fi

base="${CONTROL_FILE%.claimed}"
target="${base}.${outcome}"
if [[ -f "${CONTROL_FILE}" ]]; then
    if ! mv -f -- "${CONTROL_FILE}" "${target}"; then
        echo "error: could not record trigger outcome: ${target}" >&2
        exit 74
    fi
else
    echo "error: control file disappeared before outcome could be recorded" >&2
    exit 74
fi

exit "${rc}"
