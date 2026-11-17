#!/usr/bin/env bash
# Phase 8 — hardened container launch (P8-1, P8-3, P8-8, and the egress half of P8-2).
# Runs the orchestrator image with least privilege:
#   - read-only root filesystem (--read-only), writable state only on tmpfs
#   - all Linux capabilities dropped (--cap-drop ALL); only mode-specific bounded
#     bootstrap capabilities are re-added, then cleared by the permanent uid drop
#   - no new privileges
#   - reports (rw), specs/manuals (ro), and an owner-only host secret source (ro)
#   - a private /app/secrets tmpfs populated before permanent uid-10001 privilege drop
#   - the newest host AWS credentials file is staged privately for each container launch;
#     stale credential values inherited by the long-lived dashboard are not forwarded
#
# Works with docker or podman (set ENGINE). The egress allowlist itself is applied INSIDE
# the container by docker/egress_firewall.sh (see docker-run.md); this script wires up the
# isolation that makes that enforceable.
set -euo pipefail
umask 077

# NRDP-1: the runner trusts control/ messages only when THIS uid (the dashboard user that launches
# the container) owns them.  Never taken from the environment of an untrusted caller.
export ORCHESTRATOR_CONTROL_UID="$(id -u)"

ENGINE="${ENGINE:-$(command -v docker 2>/dev/null || command -v podman 2>/dev/null || echo docker)}"
IMAGE="${IMAGE:-orchestrator-cookie:latest}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

HOST_RUNTIME_PYTHON="${DASHBOARD_PYTHON:-}"
if [[ -z "${HOST_RUNTIME_PYTHON}" ]]; then
    if [[ -x "${PROJECT_ROOT}/.orchestrator-cookie/venv/bin/python" ]]; then
        HOST_RUNTIME_PYTHON="${PROJECT_ROOT}/.orchestrator-cookie/venv/bin/python"
    else
        HOST_RUNTIME_PYTHON="$(command -v python3 2>/dev/null || true)"
    fi
fi
HOST_POLICY_PYTHON="${ORCHESTRATOR_HOST_EGRESS_PYTHON:-${HOST_RUNTIME_PYTHON}}"
HOST_RELAY_PROGRAM="${ORCHESTRATOR_HOST_BEDROCK_RELAY:-}"
HOST_TARGET_RELAY_PROGRAM="${ORCHESTRATOR_HOST_TARGET_RELAY:-}"

# Resolve host mount sources (override via env for non-default layouts).
REPORTS_DIR="${REPORTS_DIR:-${PROJECT_ROOT}/reports}"
SPECS_DIR="${SPECS_DIR:-${PROJECT_ROOT}/tests_specs}"
MANUALS_DIR="${MANUALS_DIR:-${PROJECT_ROOT}/tests_manuals}"
SECRETS_DIR="${SECRETS_DIR:-${PROJECT_ROOT}/secrets}"
DISPLAY_SLOT_MIN="${DISPLAY_SLOT_MIN:-99}"
DISPLAY_SLOT_MAX="${DISPLAY_SLOT_MAX:-159}"
DISPLAY_LOCK_DIR="${DISPLAY_LOCK_DIR:-/tmp/orchestrator-cookie-display-locks}"
HOST_APP_STATE_ROOT="${REPORTS_DIR}/.host-app"
ORCHESTRATOR_CONTAINER_NAME="${ORCHESTRATOR_CONTAINER_NAME:-}"
WATCH_LEARN_CONTROL_DIR_HOST="${WATCH_LEARN_CONTROL_DIR_HOST:-}"
WATCH_LEARN_SELF_TEST="${WATCH_LEARN_SELF_TEST:-0}"

# CP45-I report permission contract.  A project run is accepted only when the dashboard has ALREADY precreated this run's report paths
# (ORCHESTRATOR_REPORT_HANDOFF=1 and the ids it forwards); the container's root phase then hands exactly those paths to uid 10001.  Anything else
# (a direct/CLI run, a host-app target) is REFUSED here, before a directory, a lock, a credential file or a container is created.  Nothing is broadened.
_contract_project="${ORCHESTRATOR_RUN_PROJECT:-}"
if [[ -z "${_contract_project}" ]]; then
    _contract_args=("$@")
    for ((_ci = 0; _ci + 1 < ${#_contract_args[@]}; _ci++)); do
        if [[ "${_contract_args[$_ci]}" == "--project" ]]; then
            _contract_project="${_contract_args[$((_ci + 1))]}"
            break
        fi
    done
fi
if [[ "${WATCH_LEARN_SELF_TEST}" != "1" && -n "${_contract_project}" ]]; then
    contract_refuse() {
        echo "error: report permission contract: $1" >&2
        echo "       start project runs from the dashboard (trigger_backend=spawn); direct runs are not supported" >&2
        exit 78
    }
    [[ "${_contract_project}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || contract_refuse "invalid project name"
    _contract_cfg="${SPECS_DIR}/${_contract_project}/project.yaml"
    if [[ -f "${_contract_cfg}" ]] && "${DASHBOARD_PYTHON:-python3}" "${PROJECT_ROOT}/scripts/host_app_bridge.py" --config "${_contract_cfg}" --is-host-app; then
        contract_refuse "host-app targets are not supported (HOST_APP_ENABLED does not enable them): they need a world-writable bridge state directory"
    fi
    [[ "${ORCHESTRATOR_REPORT_HANDOFF:-0}" == "1" ]] || contract_refuse "no precreated report paths were handed to this launch"
    [[ "${ORCHESTRATOR_REPORT_PROJECT:-}" == "${_contract_project}" ]] || contract_refuse "ORCHESTRATOR_REPORT_PROJECT does not match the project"
    [[ "${ORCHESTRATOR_RUN_TS:-}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || contract_refuse "invalid ORCHESTRATOR_RUN_TS"
    [[ "${ORCHESTRATOR_TRIGGER_ID:-}" =~ ^trig_[A-Za-z0-9_-]+$ ]] || contract_refuse "invalid ORCHESTRATOR_TRIGGER_ID"
    _contract_uid="$(id -u)"
    _contract_base="${REPORTS_DIR}/${_contract_project}"
    for _contract_entry in "d:${REPORTS_DIR}" "d:${_contract_base}" "d:${_contract_base}/.nrdp-runs/${ORCHESTRATOR_TRIGGER_ID}" \
                           "d:${_contract_base}/${ORCHESTRATOR_RUN_TS}" "f:${_contract_base}/index.html"; do
        _contract_kind="${_contract_entry%%:*}"
        _contract_path="${_contract_entry#*:}"
        [[ ! -L "${_contract_path}" ]] || contract_refuse "${_contract_path} is a symlink"
        if [[ "${_contract_kind}" == "d" ]]; then
            [[ -d "${_contract_path}" ]] || contract_refuse "${_contract_path} was not precreated"
        else
            [[ -f "${_contract_path}" ]] || contract_refuse "${_contract_path} was not precreated"
            [[ "$(stat -c %h -- "${_contract_path}")" == "1" ]] || contract_refuse "${_contract_path} has more than one link"
        fi
        [[ "$(stat -c %u -- "${_contract_path}")" == "${_contract_uid}" ]] || contract_refuse "${_contract_path} is not owned by the launching user"
        (( (8#$(stat -c %a -- "${_contract_path}") & 8#022) == 0 )) || contract_refuse "${_contract_path} is group- or world-writable"
    done
fi
WATCH_LEARN_NETWORK_MODE="${WATCH_LEARN_NETWORK_MODE:-none}"
WATCH_LEARN_CAPTURE="0"
if [[ -n "${WATCH_LEARN_CONTROL_DIR_HOST}" && "${WATCH_LEARN_SELF_TEST}" != "1" ]]; then
    WATCH_LEARN_CAPTURE="1"
fi

if [[ "${WATCH_LEARN_SELF_TEST}" == "1" && -z "${WATCH_LEARN_CONTROL_DIR_HOST}" ]]; then
    echo "error: Watch & Learn self-test requires a private control directory" >&2
    exit 78
fi
if [[ "${WATCH_LEARN_NETWORK_MODE}" != "none" && "${WATCH_LEARN_NETWORK_MODE}" != "target" ]]; then
    echo "error: unsupported Watch & Learn network mode" >&2
    exit 78
fi

WATCH_LEARN_CONTROL_ARGS=()
WATCH_LEARN_ENGINE_ARGS=()
if [[ -n "${WATCH_LEARN_CONTROL_DIR_HOST}" ]]; then
    CONTROL_REAL="$(realpath -e -- "${WATCH_LEARN_CONTROL_DIR_HOST}")" || {
        echo "error: Watch & Learn control directory is unavailable" >&2
        exit 78
    }
    if [[ "${CONTROL_REAL}" != "${WATCH_LEARN_CONTROL_DIR_HOST}" \
        || -L "${CONTROL_REAL}" || ! -d "${CONTROL_REAL}" \
        || "$(stat -c '%a' -- "${CONTROL_REAL}")" != "700" \
        || "$(stat -c '%u' -- "${CONTROL_REAL}")" != "$(id -u)" \
        || "$(stat -c '%g' -- "${CONTROL_REAL}")" != "$(id -g)" ]]; then
        echo "error: Watch & Learn control directory failed private ownership validation" >&2
        exit 78
    fi
    WATCH_LEARN_CONTROL_ARGS=(
        -i
        -v "${CONTROL_REAL}:/app/watch-learn-control:rw"
        -e "WATCH_LEARN_CONTROL_DIR=/app/watch-learn-control"
        -e "WATCH_LEARN_CONTROL_OWNER_UID=$(stat -c '%u' -- "${CONTROL_REAL}")"
        -e "WATCH_LEARN_CONTROL_OWNER_GID=$(stat -c '%g' -- "${CONTROL_REAL}")"
        -e "WATCH_LEARN_SELF_TEST=${WATCH_LEARN_SELF_TEST}"
    )
    case "$(basename -- "${ENGINE}")" in
        docker|podman) WATCH_LEARN_ENGINE_ARGS=(--pull=never) ;;
        *)
            echo "error: unsupported engine for explicit Watch & Learn no-pull semantics" >&2
            exit 78
            ;;
    esac
fi

CONTAINER_NAME_ARGS=()
if [[ -n "${ORCHESTRATOR_CONTAINER_NAME}" ]]; then
    if [[ ! "${ORCHESTRATOR_CONTAINER_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; then
        echo "error: invalid project runner container name" >&2
        exit 64
    fi
    CONTAINER_NAME_ARGS=(--name "${ORCHESTRATOR_CONTAINER_NAME}")
fi

resolve_regular_file() {
    local candidate
    for candidate in "$@"; do
        [[ -n "${candidate}" ]] || continue
        if [[ -d "${candidate}" && -f "${candidate}/credentials" ]]; then
            candidate="${candidate}/credentials"
        fi
        if [[ -f "${candidate}" ]]; then
            realpath -e -- "${candidate}"
            return 0
        fi
    done
    return 1
}

# Prefer an explicit operator override, then the SDK's configured file, then standard and
# legacy per-user locations.  Only the path is resolved here; credential material is never
# read or logged by the host launcher.
AWS_CREDENTIALS_FILE_HOST="$(
    resolve_regular_file \
        "${ORCHESTRATOR_AWS_CREDENTIALS_FILE:-}" \
        "${HOME}/aws/credentials" \
        "${HOME}/aws/credentials/credentials" \
        "${AWS_SHARED_CREDENTIALS_FILE:-}" \
        "${HOME}/.aws/credentials" \
        2>/dev/null || true
)"

AWS_CONFIG_FILE_HOST=""
if [[ -n "${AWS_CREDENTIALS_FILE_HOST}" \
    && "${ORCHESTRATOR_AWS_CONFIG_DISABLED:-0}" != "1" ]]; then
    AWS_CONFIG_FILE_HOST="$(
        resolve_regular_file \
            "${ORCHESTRATOR_AWS_CONFIG_FILE:-}" \
            "${AWS_CONFIG_FILE:-}" \
            "$(dirname "${AWS_CREDENTIALS_FILE_HOST}")/config" \
            "${HOME}/.aws/config" \
            "${HOME}/aws/config" \
            "${HOME}/aws/credentials/config" \
            2>/dev/null || true
    )"
fi

AWS_AUTH_ARGS=()
if [[ "${WATCH_LEARN_SELF_TEST}" == "1" || "${WATCH_LEARN_CAPTURE}" == "1" \
    || "${ORCHESTRATOR_DISABLE_AWS_FORWARDING:-0}" == "1" ]]; then
    echo "[runner] AWS credential forwarding disabled for this bounded execution"
elif [[ -n "${AWS_CREDENTIALS_FILE_HOST}" ]]; then
    AWS_CREDENTIALS_DIR_HOST="$(dirname "${AWS_CREDENTIALS_FILE_HOST}")"
    AWS_CREDENTIALS_NAME_HOST="$(basename "${AWS_CREDENTIALS_FILE_HOST}")"
    AWS_AUTH_ARGS+=(
        -v "${AWS_CREDENTIALS_DIR_HOST}:/app/aws-credentials-source:ro"
        -e "ORCHESTRATOR_AWS_CREDENTIALS_SOURCE=/app/aws-credentials-source/${AWS_CREDENTIALS_NAME_HOST}"
        -e "AWS_SHARED_CREDENTIALS_FILE=/app/aws-runtime/credentials"
    )
    if [[ -n "${ORCHESTRATOR_AWS_PROFILE:-}" ]]; then
        AWS_AUTH_ARGS+=(
            -e "ORCHESTRATOR_AWS_PROFILE=${ORCHESTRATOR_AWS_PROFILE}"
            -e "AWS_PROFILE=${ORCHESTRATOR_AWS_PROFILE}"
        )
    fi
    if [[ -n "${AWS_CONFIG_FILE_HOST}" ]]; then
        AWS_CONFIG_DIR_HOST="$(dirname "${AWS_CONFIG_FILE_HOST}")"
        AWS_CONFIG_NAME_HOST="$(basename "${AWS_CONFIG_FILE_HOST}")"
        AWS_AUTH_ARGS+=(
            -v "${AWS_CONFIG_DIR_HOST}:/app/aws-config-source:ro"
            -e "ORCHESTRATOR_AWS_CONFIG_SOURCE=/app/aws-config-source/${AWS_CONFIG_NAME_HOST}"
            -e "AWS_CONFIG_FILE=/app/aws-runtime/config"
        )
    fi
    echo "[runner] AWS credentials: current on-disk file will be staged privately"
else
    # Preserve role/env deployments when no credentials file exists. On this workstation a
    # file is expected, so this warning is an actionable indication of a bad host path.
    AWS_AUTH_ARGS+=(
        -e AWS_ACCESS_KEY_ID
        -e AWS_SECRET_ACCESS_KEY
        -e AWS_SESSION_TOKEN
        -e AWS_BEARER_TOKEN_BEDROCK
    )
    echo "[runner] WARNING: no AWS credentials file found; using the inherited credential chain" >&2
fi

DISPLAY_SLOT="199"
DISPLAY_LOCK_FD=""
if [[ "${WATCH_LEARN_SELF_TEST}" != "1" ]]; then
    mkdir -p "${REPORTS_DIR}"
    mkdir -p "${DISPLAY_LOCK_DIR}"
    mkdir -p -m 0700 "${SECRETS_DIR}"

    if [[ -L "${SECRETS_DIR}" || ! -d "${SECRETS_DIR}" ]]; then
        echo "error: secret source must be a real directory: ${SECRETS_DIR}" >&2
        exit 78
    fi

    if ! command -v flock >/dev/null 2>&1; then
        echo "error: flock is required for collision-free X display allocation" >&2
        exit 69
    fi

    DISPLAY_SLOT=""
    for slot in $(seq "${DISPLAY_SLOT_MIN}" "${DISPLAY_SLOT_MAX}"); do
        lock_path="${DISPLAY_LOCK_DIR}/display-${slot}.lock"
        exec {candidate_fd}>"${lock_path}"
        if flock -n "${candidate_fd}"; then
            DISPLAY_SLOT="${slot}"
            DISPLAY_LOCK_FD="${candidate_fd}"
            break
        fi
        exec {candidate_fd}>&-
    done

    if [[ -z "${DISPLAY_SLOT}" ]]; then
        echo "error: no free X display slot in ${DISPLAY_SLOT_MIN}-${DISPLAY_SLOT_MAX}" >&2
        exit 75
    fi
fi

echo "[runner] allocated isolated X display :${DISPLAY_SLOT}"

# A host-app target is launched by a host-side manager, never by granting the
# container host PID/IPC/mount namespaces.  The project name is normally supplied
# by run_specs.sh; recover it from direct runner argv as a convenience.
RUN_PROJECT="${ORCHESTRATOR_RUN_PROJECT:-}"
if [[ -z "${RUN_PROJECT}" ]]; then
    RUN_ARGS=("$@")
    for ((i = 0; i + 1 < ${#RUN_ARGS[@]}; i++)); do
        if [[ "${RUN_ARGS[$i]}" == "--project" ]]; then
            RUN_PROJECT="${RUN_ARGS[$((i + 1))]}"
            break
        fi
    done
fi

HOST_BRIDGE_PID=""
HOST_BRIDGE_STATE_DIR=""
HOST_BRIDGE_ENV_ARGS=()
HOST_BRIDGE_X11_ARGS=()
RUNNER_HOSTS_FILE=""
BEDROCK_RELAY_STATE_FILE=""
BEDROCK_RELAY_PID=""
TARGET_RELAY_STATE_FILE=""
TARGET_RELAY_PID=""

cleanup_run() {
    rc=$?
    trap - EXIT

    if [[ -n "${TARGET_RELAY_PID}" ]] && kill -0 "${TARGET_RELAY_PID}" 2>/dev/null; then
        kill -TERM "${TARGET_RELAY_PID}" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "${TARGET_RELAY_PID}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${TARGET_RELAY_PID}" 2>/dev/null; then
            kill -KILL "${TARGET_RELAY_PID}" 2>/dev/null || true
        fi
    fi
    if [[ -n "${TARGET_RELAY_PID}" ]]; then
        wait "${TARGET_RELAY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${TARGET_RELAY_STATE_FILE}" ]]; then
        rm -f -- "${TARGET_RELAY_STATE_FILE}"
    fi

    if [[ -n "${BEDROCK_RELAY_PID}" ]] && kill -0 "${BEDROCK_RELAY_PID}" 2>/dev/null; then
        kill -TERM "${BEDROCK_RELAY_PID}" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "${BEDROCK_RELAY_PID}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${BEDROCK_RELAY_PID}" 2>/dev/null; then
            kill -KILL "${BEDROCK_RELAY_PID}" 2>/dev/null || true
        fi
    fi
    if [[ -n "${BEDROCK_RELAY_PID}" ]]; then
        wait "${BEDROCK_RELAY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${BEDROCK_RELAY_STATE_FILE}" ]]; then
        rm -f -- "${BEDROCK_RELAY_STATE_FILE}"
    fi

    if [[ -n "${HOST_BRIDGE_PID}" ]] && kill -0 "${HOST_BRIDGE_PID}" 2>/dev/null; then
        kill -TERM "${HOST_BRIDGE_PID}" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "${HOST_BRIDGE_PID}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${HOST_BRIDGE_PID}" 2>/dev/null; then
            kill -KILL "${HOST_BRIDGE_PID}" 2>/dev/null || true
        fi
    fi
    if [[ -n "${HOST_BRIDGE_PID}" ]]; then
        wait "${HOST_BRIDGE_PID}" 2>/dev/null || true
    fi

    if [[ -n "${HOST_BRIDGE_STATE_DIR}" ]]; then
        rm -f -- \
            "${HOST_BRIDGE_STATE_DIR}/display.ready" \
            "${HOST_BRIDGE_STATE_DIR}/Xauthority"
        rmdir -- "${HOST_BRIDGE_STATE_DIR}" 2>/dev/null || true
    fi

    if [[ -n "${RUNNER_HOSTS_FILE}" ]]; then
        rm -f -- "${RUNNER_HOSTS_FILE}"
    fi

    if [[ -n "${DISPLAY_LOCK_FD}" ]]; then
        flock -u "${DISPLAY_LOCK_FD}" 2>/dev/null || true
        exec {DISPLAY_LOCK_FD}>&- 2>/dev/null || true
    fi
    exit "${rc}"
}
trap cleanup_run EXIT

if [[ "${WATCH_LEARN_SELF_TEST}" != "1" && -n "${RUN_PROJECT}" ]]; then
    if [[ ! "${RUN_PROJECT}" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "error: invalid project name for host bridge: ${RUN_PROJECT}" >&2
        exit 64
    fi
    PROJECT_CONFIG="${SPECS_DIR}/${RUN_PROJECT}/project.yaml"
    BRIDGE_PYTHON="${DASHBOARD_PYTHON:-python3}"
    if [[ -f "${PROJECT_CONFIG}" ]] \
        && "${BRIDGE_PYTHON}" "${PROJECT_ROOT}/scripts/host_app_bridge.py" \
            --config "${PROJECT_CONFIG}" --is-host-app; then
        echo "error: host-app targets are not supported under the 0755 reports contract (CP45-I)" >&2
        exit 78
        READY_HOST="${HOST_BRIDGE_STATE_DIR}/display.ready"
        READY_CONTAINER="/app/reports/.host-app/$(basename "${HOST_BRIDGE_STATE_DIR}")/display.ready"
        XAUTHORITY_HOST="${HOST_BRIDGE_STATE_DIR}/Xauthority"
        XAUTHORITY_CONTAINER="/app/reports/.host-app/$(basename "${HOST_BRIDGE_STATE_DIR}")/Xauthority"
        "${BRIDGE_PYTHON}" "${PROJECT_ROOT}/scripts/xauthority_cookie.py" \
            --display ":${DISPLAY_SLOT}" \
            --output "${XAUTHORITY_HOST}"
        X11_PORT="$((6000 + DISPLAY_SLOT))"
        "${BRIDGE_PYTHON}" - "${X11_PORT}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    probe.bind(("127.0.0.1", port))
PY
        "${BRIDGE_PYTHON}" "${PROJECT_ROOT}/scripts/host_app_bridge.py" \
            --config "${PROJECT_CONFIG}" \
            --display "127.0.0.1:${DISPLAY_SLOT}" \
            --ready-file "${READY_HOST}" \
            --log "${REPORTS_DIR}/host-app.log" \
            --xauthority "${XAUTHORITY_HOST}" \
            --check
        "${BRIDGE_PYTHON}" "${PROJECT_ROOT}/scripts/host_app_bridge.py" \
            --config "${PROJECT_CONFIG}" \
            --display "127.0.0.1:${DISPLAY_SLOT}" \
            --ready-file "${READY_HOST}" \
            --log "${REPORTS_DIR}/host-app.log" \
            --xauthority "${XAUTHORITY_HOST}" &
        HOST_BRIDGE_PID=$!
        HOST_BRIDGE_ENV_ARGS=(
            -e "HOST_APP_BRIDGE_ACTIVE=1"
            -e "HOST_DISPLAY_READY_FILE=${READY_CONTAINER}"
            -e "HOST_APP_X11_BRIDGE=1"
            -e "XAUTHORITY=${XAUTHORITY_CONTAINER}"
        )
        HOST_BRIDGE_X11_ARGS=(
            -p "127.0.0.1:${X11_PORT}:${X11_PORT}/tcp"
        )
    fi
fi

NETWORK_ARGS=(--network=bridge)
CAPABILITY_ARGS=(
    --cap-drop ALL
    --cap-add NET_ADMIN
    --cap-add DAC_READ_SEARCH
    --cap-add CHOWN
    --cap-add SETUID
    --cap-add SETGID
)
SOURCE_MOUNT_ARGS=(
    -v "${REPORTS_DIR}:/app/reports:rw"
    -v "${SPECS_DIR}:/app/tests_specs:ro"
    -v "${MANUALS_DIR}:/app/tests_manuals:ro"
    -v "${SECRETS_DIR}:/app/secrets-source:ro"
)
RUNTIME_ENV_ARGS=(
    -e AWS_REGION
    -e AWS_DEFAULT_REGION
    -e ORCHESTRATOR_AWS_REFRESH_SECONDS
    -e BEDROCK_MODEL_ID
    -e ORCHESTRATOR_TRIGGER_ID
    -e ORCHESTRATOR_CONTROL_UID
    -e ORCHESTRATOR_RUN_TS
    -e ORCHESTRATOR_REPORT_PROJECT
    -e ORCHESTRATOR_REPORT_HANDOFF
    -e ORCHESTRATOR_LOG_LEVEL
    -e SSH_HOST_ALLOWLIST
    -e RDP_HOST_ALLOWLIST
    -e VNC_HOST_ALLOWLIST
)
if [[ -n "${RUN_PROJECT}" ]]; then
    RUNTIME_ENV_ARGS+=(
        -e "ORCHESTRATOR_EGRESS_PROJECT=${RUN_PROJECT}"
    )
fi
EGRESS_MODE="enforce"
if [[ "${WATCH_LEARN_SELF_TEST}" == "1" ]]; then
    NETWORK_ARGS=(--network=none)
    EGRESS_MODE="none"
    CAPABILITY_ARGS=(
        --cap-drop ALL
        --cap-add DAC_OVERRIDE
        --cap-add CHOWN
        --cap-add SETUID
        --cap-add SETGID
    )
    SOURCE_MOUNT_ARGS=()
    RUNTIME_ENV_ARGS=()
elif [[ "${WATCH_LEARN_CAPTURE}" == "1" ]]; then
    NETWORK_ARGS=(--network=none)
    EGRESS_MODE="none"
    CAPABILITY_ARGS=(
        --cap-drop ALL
        --cap-add DAC_OVERRIDE
        --cap-add DAC_READ_SEARCH
        --cap-add CHOWN
        --cap-add SETUID
        --cap-add SETGID
    )
    # Capture needs the selected project configuration, its required manual
    # root, and private login references. All remain read-only, while reports
    # and every AWS/model setting stay absent from this isolated worker.
    SOURCE_MOUNT_ARGS=(
        -v "${SPECS_DIR}:/app/tests_specs:ro"
        -v "${MANUALS_DIR}:/app/tests_manuals:ro"
        -v "${SECRETS_DIR}:/app/secrets-source:ro"
    )
    RUNTIME_ENV_ARGS=()
    if [[ "${WATCH_LEARN_NETWORK_MODE}" == "target" ]]; then
        [[ -n "${RUN_PROJECT}" ]] || {
            echo "error: target-network Watch & Learn requires one exact project" >&2
            exit 78
        }
        NETWORK_ARGS=(--network=bridge)
        EGRESS_MODE="enforce"
        CAPABILITY_ARGS=(
            --cap-drop ALL
            --cap-add NET_ADMIN
            --cap-add DAC_READ_SEARCH
            --cap-add CHOWN
            --cap-add SETUID
            --cap-add SETGID
        )
        RUNTIME_ENV_ARGS=(
            -e "ORCHESTRATOR_EGRESS_PROJECT=${RUN_PROJECT}"
            -e "ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1"
        )
    fi
fi

HOSTS_MOUNT_ARGS=()
BEDROCK_PROXY_ARGS=()
TARGET_RELAY_ARGS=()
if [[ "${EGRESS_MODE}" == "enforce" ]]; then
    [[ -n "${HOST_POLICY_PYTHON}" ]] || {
        echo "error: host Python is required for bounded egress resolution" >&2
        exit 69
    }
    TARGET_RELAY_KIND=""
    TARGET_RELAY_ENDPOINT=""
    TARGET_RELAY_DESTINATION_PORT=""
    if [[ "$(uname -s)" == "Linux" && -n "${RUN_PROJECT}" ]]; then
        if ! target_transport_text="$({
            TESTS_SPECS_DIR="${SPECS_DIR}" \
            PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
                "${HOST_RUNTIME_PYTHON}" -m orchestrator.target_relay describe \
                    --project "${RUN_PROJECT}" --specs-root "${SPECS_DIR}"
        })"; then
            echo "error: exact project target transport could not be described" >&2
            exit 69
        fi
        if [[ -n "${target_transport_text}" ]]; then
            mapfile -t target_transport_values <<<"${target_transport_text}"
            if [[ "${#target_transport_values[@]}" -ne 3 ]]; then
                echo "error: exact project target transport returned invalid data" >&2
                exit 69
            fi
            TARGET_RELAY_KIND="${target_transport_values[0]}"
            TARGET_RELAY_ENDPOINT="${target_transport_values[1]}"
            TARGET_RELAY_DESTINATION_PORT="${target_transport_values[2]}"
        fi
    fi

    EGRESS_POLICY_ARGS=()
    if [[ -n "${RUN_PROJECT}" ]]; then
        EGRESS_POLICY_ARGS=(--project "${RUN_PROJECT}")
    fi
    if [[ "${WATCH_LEARN_CAPTURE}" == "1" && "${WATCH_LEARN_NETWORK_MODE}" == "target" ]]; then
        EGRESS_POLICY_ARGS+=(--exclude-bedrock)
    elif [[ "${ORCHESTRATOR_DISABLE_AWS_FORWARDING:-0}" == "1" \
        && -n "${TARGET_RELAY_KIND}" ]]; then
        EGRESS_POLICY_ARGS+=(--exclude-bedrock)
        # Keep the in-container calculation identical to the private hosts
        # policy selected above. This carries no endpoint or credential and is
        # set only for the no-AWS-forwarding + active-target-relay branch.
        RUNTIME_ENV_ARGS+=(
            -e "ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1"
        )
    fi
    if ! RESOLVED_HOST_ENTRIES="$({
        AWS_REGION="${AWS_REGION:-us-west-2}" \
        TESTS_SPECS_DIR="${SPECS_DIR}" \
        PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
            "${HOST_POLICY_PYTHON}" -m orchestrator.egress --resolved-hosts "${EGRESS_POLICY_ARGS[@]}"
    })"; then
        echo "error: approved egress endpoints could not be resolved on the host" >&2
        exit 69
    fi
    [[ -n "${RESOLVED_HOST_ENTRIES}" ]] || {
        echo "error: host-side egress resolution returned no entries" >&2
        exit 69
    }

    RUNNER_HOSTS_FILE="$(mktemp "${TMPDIR:-/tmp}/orchestrator-cookie-hosts.XXXXXX")"
    chmod 0644 "${RUNNER_HOSTS_FILE}"
    printf '%s\n' \
        '127.0.0.1 localhost orchestrator-cookie-runner' \
        '::1 localhost ip6-localhost ip6-loopback' \
        >"${RUNNER_HOSTS_FILE}"
    BEDROCK_ENDPOINT="bedrock-runtime.${AWS_REGION:-us-west-2}.amazonaws.com"
    [[ "${BEDROCK_ENDPOINT}" =~ ^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$ ]] || {
        echo "error: invalid regional Bedrock endpoint" >&2
        exit 69
    }
    BEDROCK_ADDRESSES=()
    TARGET_RELAY_ADDRESSES=()
    while IFS=$'\t' read -r address host extra; do
        if [[ -n "${extra:-}" \
            || ! "${address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
            || ! "${host}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]]; then
            echo "error: host-side egress resolver returned invalid data" >&2
            exit 69
        fi
        IFS='.' read -r octet1 octet2 octet3 octet4 <<<"${address}"
        for octet in "${octet1}" "${octet2}" "${octet3}" "${octet4}"; do
            if (( 10#${octet} > 255 )); then
                echo "error: host-side egress resolver returned invalid IPv4 data" >&2
                exit 69
            fi
        done
        printf '%s %s\n' "${address}" "${host}" >>"${RUNNER_HOSTS_FILE}"
        if [[ "${host}" == "${BEDROCK_ENDPOINT}" ]]; then
            BEDROCK_ADDRESSES+=("${address}")
        fi
        if [[ -n "${TARGET_RELAY_ENDPOINT}" && "${host}" == "${TARGET_RELAY_ENDPOINT}" ]]; then
            TARGET_RELAY_ADDRESSES+=("${address}")
        fi
    done <<<"${RESOLVED_HOST_ENTRIES}"
    if [[ "${WATCH_LEARN_CAPTURE}" != "1" || "${WATCH_LEARN_NETWORK_MODE}" != "target" ]] \
        && [[ "${ORCHESTRATOR_DISABLE_AWS_FORWARDING:-0}" != "1" \
            || -z "${TARGET_RELAY_KIND}" ]]; then
        (( ${#BEDROCK_ADDRESSES[@]} > 0 )) || {
            echo "error: Bedrock endpoint returned no pinned address" >&2
            exit 69
        }
    fi
    echo "[egress] approved endpoints resolved and pinned by host launcher"
    HOSTS_MOUNT_ARGS=(
        -v "${RUNNER_HOSTS_FILE}:/etc/hosts:ro"
    )

    if [[ -n "${TARGET_RELAY_KIND}" ]]; then
        (( ${#TARGET_RELAY_ADDRESSES[@]} > 0 )) || {
            echo "error: project target endpoint returned no pinned address" >&2
            exit 69
        }
        TARGET_RELAY_STATE_FILE="$(mktemp "${TMPDIR:-/tmp}/orchestrator-cookie-target-relay.XXXXXX")"
        chmod 0600 "${TARGET_RELAY_STATE_FILE}"
        if [[ -n "${HOST_TARGET_RELAY_PROGRAM}" ]]; then
            [[ -x "${HOST_TARGET_RELAY_PROGRAM}" && ! -L "${HOST_TARGET_RELAY_PROGRAM}" ]] || {
                echo "error: configured target relay program is unsafe" >&2
                exit 69
            }
            target_relay_command=("${HOST_TARGET_RELAY_PROGRAM}")
        else
            target_relay_command=("${HOST_RUNTIME_PYTHON}" -m orchestrator.target_relay serve)
        fi
        target_relay_command+=(
            --engine "${ENGINE}"
            --kind "${TARGET_RELAY_KIND}"
            --endpoint "${TARGET_RELAY_ENDPOINT}"
            --destination-port "${TARGET_RELAY_DESTINATION_PORT}"
            --state-file "${TARGET_RELAY_STATE_FILE}"
        )
        for address in "${TARGET_RELAY_ADDRESSES[@]}"; do
            target_relay_command+=(--address "${address}")
        done
        PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
            "${target_relay_command[@]}" &
        TARGET_RELAY_PID=$!

        target_relay_ready=false
        for _ in $(seq 1 100); do
            if ! kill -0 "${TARGET_RELAY_PID}" 2>/dev/null; then
                break
            fi
            if TARGET_RELAY_STATE_FILE="${TARGET_RELAY_STATE_FILE}" \
                "${HOST_RUNTIME_PYTHON}" -c '
import json, os
value = json.load(open(os.environ["TARGET_RELAY_STATE_FILE"], encoding="utf-8"))
assert value["kind"]
assert value["endpoint"]
assert 1 <= int(value["destination_port"]) <= 65535
assert 1 <= int(value["port"]) <= 65535
assert len(value["token"]) >= 32
' >/dev/null 2>&1; then
                target_relay_ready=true
                break
            fi
            sleep 0.05
        done
        if [[ "${target_relay_ready}" != "true" ]]; then
            wait "${TARGET_RELAY_PID}" 2>/dev/null || true
            TARGET_RELAY_PID=""
            echo "error: authenticated target host relay did not become ready" >&2
            exit 69
        fi
        mapfile -t target_relay_values < <(
            TARGET_RELAY_STATE_FILE="${TARGET_RELAY_STATE_FILE}" \
                "${HOST_RUNTIME_PYTHON}" -c '
import json, os
value = json.load(open(os.environ["TARGET_RELAY_STATE_FILE"], encoding="utf-8"))
for key in ("kind", "endpoint", "destination_port", "bind_host", "port", "token"):
    print(value[key])
'
        )
        rm -f -- "${TARGET_RELAY_STATE_FILE}"
        TARGET_RELAY_STATE_FILE=""
        [[ "${#target_relay_values[@]}" -eq 6 \
            && "${target_relay_values[0]}" == "${TARGET_RELAY_KIND}" \
            && "${target_relay_values[1]}" == "${TARGET_RELAY_ENDPOINT}" \
            && "${target_relay_values[2]}" == "${TARGET_RELAY_DESTINATION_PORT}" \
            && "${target_relay_values[3]}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
            && "${target_relay_values[4]}" =~ ^[0-9]+$ \
            && "${target_relay_values[5]}" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || {
            echo "error: authenticated target host relay returned invalid state" >&2
            exit 69
        }
        TARGET_RELAY_ARGS=(
            -e "ORCHESTRATOR_TARGET_RELAY_KIND=${target_relay_values[0]}"
            -e "ORCHESTRATOR_TARGET_RELAY_ENDPOINT=${target_relay_values[1]}"
            -e "ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT=${target_relay_values[2]}"
            -e "ORCHESTRATOR_TARGET_RELAY_HOST=${target_relay_values[3]}"
            -e "ORCHESTRATOR_TARGET_RELAY_PORT=${target_relay_values[4]}"
            -e "ORCHESTRATOR_TARGET_RELAY_TOKEN=${target_relay_values[5]}"
        )
        unset target_relay_values
        echo "[target-relay] project-scoped host transport attached to private runner"
    fi

    if [[ "$(uname -s)" == "Linux" && ${#BEDROCK_ADDRESSES[@]} -gt 0 ]]; then
        BEDROCK_RELAY_STATE_FILE="$(mktemp "${TMPDIR:-/tmp}/orchestrator-cookie-relay.XXXXXX")"
        chmod 0600 "${BEDROCK_RELAY_STATE_FILE}"
        if [[ -n "${HOST_RELAY_PROGRAM}" ]]; then
            [[ -x "${HOST_RELAY_PROGRAM}" && ! -L "${HOST_RELAY_PROGRAM}" ]] || {
                echo "error: configured Bedrock relay program is unsafe" >&2
                exit 69
            }
            relay_command=("${HOST_RELAY_PROGRAM}")
        else
            relay_command=("${HOST_RUNTIME_PYTHON}" -m orchestrator.bedrock_relay)
        fi
        relay_command+=(
            --engine "${ENGINE}"
            --endpoint "${BEDROCK_ENDPOINT}"
            --state-file "${BEDROCK_RELAY_STATE_FILE}"
        )
        for address in "${BEDROCK_ADDRESSES[@]}"; do
            relay_command+=(--address "${address}")
        done
        PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
            "${relay_command[@]}" &
        BEDROCK_RELAY_PID=$!

        relay_ready=false
        for _ in $(seq 1 100); do
            if ! kill -0 "${BEDROCK_RELAY_PID}" 2>/dev/null; then
                break
            fi
            if RELAY_STATE_FILE="${BEDROCK_RELAY_STATE_FILE}" \
                "${HOST_RUNTIME_PYTHON}" -c '
import json, os
value = json.load(open(os.environ["RELAY_STATE_FILE"], encoding="utf-8"))
assert value["proxy_url"].startswith("http://runner:")
assert value["endpoint"]
assert 1 <= int(value["port"]) <= 65535
' >/dev/null 2>&1; then
                relay_ready=true
                break
            fi
            sleep 0.05
        done
        if [[ "${relay_ready}" != "true" ]]; then
            wait "${BEDROCK_RELAY_PID}" 2>/dev/null || true
            BEDROCK_RELAY_PID=""
            echo "error: authenticated Bedrock host relay did not become ready" >&2
            exit 69
        fi
        mapfile -t relay_values < <(
            RELAY_STATE_FILE="${BEDROCK_RELAY_STATE_FILE}" \
                "${HOST_RUNTIME_PYTHON}" -c '
import json, os
value = json.load(open(os.environ["RELAY_STATE_FILE"], encoding="utf-8"))
print(value["endpoint"])
print(value["bind_host"])
print(value["port"])
print(value["proxy_url"])
'
        )
        rm -f -- "${BEDROCK_RELAY_STATE_FILE}"
        BEDROCK_RELAY_STATE_FILE=""
        [[ "${#relay_values[@]}" -eq 4 \
            && "${relay_values[0]}" == "${BEDROCK_ENDPOINT}" \
            && "${relay_values[1]}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
            && "${relay_values[2]}" =~ ^[0-9]+$ \
            && "${relay_values[3]}" == http://runner:* ]] || {
            echo "error: authenticated Bedrock host relay returned invalid state" >&2
            exit 69
        }
        BEDROCK_PROXY_ARGS=(
            -e "ORCHESTRATOR_BEDROCK_ENDPOINT=${relay_values[0]}"
            -e "ORCHESTRATOR_BEDROCK_PROXY_HOST=${relay_values[1]}"
            -e "ORCHESTRATOR_BEDROCK_PROXY_PORT=${relay_values[2]}"
            -e "HTTPS_PROXY=${relay_values[3]}"
            -e "https_proxy=${relay_values[3]}"
            -e "HTTP_PROXY="
            -e "http_proxy="
            -e "ALL_PROXY="
            -e "all_proxy="
            -e "NO_PROXY="
            -e "no_proxy="
        )
        unset relay_values
        echo "[relay] bounded host transport attached to private runner"
    fi
fi

echo "WATCH_LEARN_STAGE=runner_invoked"
if "${ENGINE}" run --rm \
    "${WATCH_LEARN_ENGINE_ARGS[@]}" \
    "${CONTAINER_NAME_ARGS[@]}" \
    --user root \
    -e "DISPLAY=:${DISPLAY_SLOT}" \
    -e "SECRETS_SOURCE_DIR=/app/secrets-source" \
    -e "SECRETS_RUNTIME_DIR=/app/secrets" \
    -e "ORCHESTRATOR_EGRESS_MODE=${EGRESS_MODE}" \
    "${NETWORK_ARGS[@]}" \
    "${HOSTS_MOUNT_ARGS[@]}" \
    "${HOST_BRIDGE_X11_ARGS[@]}" \
    "${BEDROCK_PROXY_ARGS[@]}" \
    "${TARGET_RELAY_ARGS[@]}" \
    --read-only \
    "${CAPABILITY_ARGS[@]}" \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --tmpfs /home/orchestrator:rw,nosuid,nodev,size=64m,mode=1777 \
    --tmpfs /app/secrets:rw,nosuid,nodev,noexec,size=16m,mode=0700 \
    --tmpfs /app/aws-runtime:rw,nosuid,nodev,noexec,size=4m,mode=0700 \
    "${HOST_BRIDGE_ENV_ARGS[@]}" \
    "${AWS_AUTH_ARGS[@]}" \
    "${WATCH_LEARN_CONTROL_ARGS[@]}" \
    "${SOURCE_MOUNT_ARGS[@]}" \
    "${RUNTIME_ENV_ARGS[@]}" \
    "${IMAGE}" "$@"; then
    run_rc=0
else
    run_rc=$?
fi

exit "${run_rc}"
