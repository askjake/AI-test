#!/usr/bin/env bash
# Phase 10 — host-side dashboard launcher.
# Runs the dashboard directly on the host via uvicorn (no container).
# The dashboard reads from reports/ (shared with the agent container via the
# host filesystem) and exposes a read-only HTTP interface.
#
# Prerequisites:
#   pip install -r requirements-dashboard.txt
#   DASHBOARD_AUTH_TOKEN=<secret>   # required only for an explicit non-loopback bind
#
# Usage:
#   DASHBOARD_AUTH_TOKEN=mysecret scripts/run_dashboard.sh
#   DASHBOARD_PORT=9090 scripts/run_dashboard.sh
set -euo pipefail

# Resolve project root early so .env can be sourced before other vars.
_DASH_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_DASH_PROJECT_ROOT="$(dirname "${_DASH_SCRIPT_DIR}")"

# Source .env if present — provides BEDROCK_MODEL_ID, ENGINE, etc.
# for run_specs.sh when runs are triggered from the dashboard.
if [[ -f "${_DASH_PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck source=../.env
    source "${_DASH_PROJECT_ROOT}/.env"
    set +a
fi
unset _DASH_SCRIPT_DIR _DASH_PROJECT_ROOT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

export PYTHONPATH="${PROJECT_ROOT}/src"
export DASHBOARD_REPORTS_DIR="${DASHBOARD_REPORTS_DIR:-${PROJECT_ROOT}/reports}"
export DASHBOARD_SPECS_DIR="${DASHBOARD_SPECS_DIR:-${PROJECT_ROOT}/tests_specs}"
export DASHBOARD_HOST="${DASHBOARD_HOST:-127.0.0.1}"
export DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
# Use "watcher" only when a separate orchestrator scheduler owns trigger files.
export DASHBOARD_TRIGGER_BACKEND="${DASHBOARD_TRIGGER_BACKEND:-spawn}"

# Refuse non-loopback exposure without authentication.
if [[ "${DASHBOARD_HOST}" != "127.0.0.1" && "${DASHBOARD_HOST}" != "localhost" && -z "${DASHBOARD_AUTH_TOKEN:-}" ]]; then
    echo "error: DASHBOARD_AUTH_TOKEN is required for non-loopback binding" >&2
    exit 78
fi

echo "[dashboard] reports_dir: ${DASHBOARD_REPORTS_DIR}"
echo "[dashboard] specs_dir:  ${DASHBOARD_SPECS_DIR}"
echo "[dashboard] binding:     ${DASHBOARD_HOST}:${DASHBOARD_PORT}"
echo "[dashboard] triggers:    ${DASHBOARD_TRIGGER_BACKEND}"
if [[ -n "${DASHBOARD_AUTH_TOKEN:-}" ]]; then
    echo "[dashboard] auth:        token set"
else
    echo "[dashboard] auth:        *** NOT SET ***"
fi

if [[ "${DASHBOARD_RELOAD:-0}" == "1" ]]; then
    exec uvicorn dashboard.app:app \
        --host "${DASHBOARD_HOST}" \
        --port "${DASHBOARD_PORT}" \
        --reload \
        --reload-dir "${PROJECT_ROOT}/src" \
        --reload-dir "${PROJECT_ROOT}/templates" \
        --log-level info
fi

exec uvicorn dashboard.app:app \
    --host "${DASHBOARD_HOST}" \
    --port "${DASHBOARD_PORT}" \
    --log-level info
