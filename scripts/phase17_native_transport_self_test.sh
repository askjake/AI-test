#!/usr/bin/env bash
# Prepared-host acceptance only. This does not start or alter the dashboard.
set -Eeuo pipefail
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHON_BIN="${PHASE17_SELF_TEST_PYTHON:-python3}"
IMAGE_VALUE="${DASHBOARD_WATCH_LEARN_RUNNER_IMAGE:-}"

blocked() {
    printf '%s\n' 'NATIVE_TRANSPORT_SELF_TEST=NOT_RUN_BLOCKED'
    printf 'ABSENT_PREREQUISITE=%s\n' "$1"
    printf '%s\n' 'NO_IMAGE_PULL_OR_BUILD=true'
    printf '%s\n' 'NO_TARGET_OR_MODEL_CONTACT=true'
    exit 2
}

if [[ -z "${ENGINE:-}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        ENGINE="$(command -v docker)"
    elif command -v podman >/dev/null 2>&1; then
        ENGINE="$(command -v podman)"
    else
        blocked 'sandbox source development; no approved locally-present image/engine validation input'
    fi
fi
[[ -x "${ENGINE}" ]] || blocked 'configured-engine-unavailable'
case "$(basename -- "${ENGINE}")" in
    docker|podman) ;;
    *) blocked 'unsupported-engine-no-pull-semantics' ;;
esac
[[ "${IMAGE_VALUE}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,240}@sha256:[a-f0-9]{64}$ ]] \
    || blocked 'digest-pinned-runner-image-not-configured'
command -v "${PYTHON_BIN}" >/dev/null 2>&1 || blocked 'python-runtime-unavailable'

export ENGINE
export WATCH_LEARN_SELF_TEST=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="${ROOT}/src"
cd "${ROOT}"
exec "${PYTHON_BIN}" -m dashboard.watch_learn_native_self_test
