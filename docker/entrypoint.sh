#!/usr/bin/env bash
# Phase 2 — container entrypoint (Phase 8: read-only-root-FS friendly).
# Starts Xvfb on the configured display, launches a light window manager, waits for the
# display to be ready, then hands off to the command (default: the scheduler).
#
# When run with a read-only root filesystem (the Phase 8 hardened default), the only
# writable paths are tmpfs mounts (/tmp, $HOME) and the reports/ volume. Xvfb's sockets and
# lock files live under /tmp, and fluxbox's runtime config under $HOME — both must be on a
# writable tmpfs. This script creates the runtime dirs it needs under those paths so it
# works identically whether or not the root FS is read-only.
set -euo pipefail

DISPLAY_NUM="${DISPLAY:-:1}"
SCREEN_W="${SCREEN_W:-1920}"
SCREEN_H="${SCREEN_H:-1080}"
SCREEN_DEPTH="${SCREEN_DEPTH:-24}"
SECRETS_SOURCE_DIR="${SECRETS_SOURCE_DIR:-/app/secrets-source}"
SECRETS_RUNTIME_DIR="${SECRETS_RUNTIME_DIR:-/app/secrets}"
AWS_CREDENTIALS_SOURCE="${ORCHESTRATOR_AWS_CREDENTIALS_SOURCE:-/app/aws-credentials-source/credentials}"
AWS_CONFIG_SOURCE="${ORCHESTRATOR_AWS_CONFIG_SOURCE:-}"
AWS_RUNTIME_DIR="${ORCHESTRATOR_AWS_RUNTIME_DIR:-/app/aws-runtime}"
RUNTIME_USER="${ORCHESTRATOR_RUNTIME_USER:-orchestrator}"

# Host secrets stay owner-only (0600). Start through a tightly bounded root bootstrap,
# copy them from the read-only bind into a private tmpfs, then permanently become the
# image's non-root user before Xvfb, target clients, Python, or model code starts.
if [[ "$(id -u)" -eq 0 ]]; then
    if [[ "${ORCHESTRATOR_PRIVILEGES_DROPPED:-0}" == "1" ]]; then
        echo "[entrypoint] FATAL: privilege-drop recursion remained root" >&2
        exit 78
    fi

    # CP45-G: hand the dashboard-precreated run paths to the runner uid (root phase, before the drop; CAP_CHOWN only). Failure is fatal and visible.
    if [[ "${ORCHESTRATOR_REPORT_HANDOFF:-0}" == "1" ]]; then
        python -m orchestrator.report_handoff --runtime-user "${RUNTIME_USER}" || {
            echo "[entrypoint] FATAL: report folder handoff failed" >&2
            exit 78
        }
    fi

    if [[ "${WATCH_LEARN_SELF_TEST:-0}" == "1" ]]; then
        [[ -n "${WATCH_LEARN_CONTROL_DIR:-}" ]] || {
            echo "[entrypoint] FATAL: self-test requires the private control mount" >&2
            exit 78
        }
        echo "[entrypoint] target-free self-test; credential and secret staging disabled"
    else
        python -m orchestrator.secret_stage \
            --source "${SECRETS_SOURCE_DIR}" \
            --destination "${SECRETS_RUNTIME_DIR}" \
            --user "${RUNTIME_USER}"
    fi

    if [[ "${WATCH_LEARN_SELF_TEST:-0}" != "1" && -f "${AWS_CREDENTIALS_SOURCE}" ]]; then
        AWS_SYNC_ARGS=(
            --credentials-source "${AWS_CREDENTIALS_SOURCE}"
            --destination "${AWS_RUNTIME_DIR}" \
            --user "${RUNTIME_USER}" \
            --interval "${ORCHESTRATOR_AWS_REFRESH_SECONDS:-2}"
        )
        if [[ -n "${AWS_CONFIG_SOURCE}" && -f "${AWS_CONFIG_SOURCE}" ]]; then
            AWS_SYNC_ARGS+=(--config-source "${AWS_CONFIG_SOURCE}")
        fi
        python -m orchestrator.credential_sync "${AWS_SYNC_ARGS[@]}" &
        AWS_CREDENTIAL_SYNC_PID=$!

        for _ in $(seq 1 50); do
            [[ -f "${AWS_RUNTIME_DIR}/credentials" ]] && break
            kill -0 "${AWS_CREDENTIAL_SYNC_PID}" 2>/dev/null || break
            sleep 0.1
        done
        if ! kill -0 "${AWS_CREDENTIAL_SYNC_PID}" 2>/dev/null \
            || [[ ! -f "${AWS_RUNTIME_DIR}/credentials" ]]; then
            wait "${AWS_CREDENTIAL_SYNC_PID}" 2>/dev/null || true
            echo "[credentials] FATAL: credential refresh bridge failed to initialize" >&2
            exit 78
        fi

        export AWS_SHARED_CREDENTIALS_FILE="${AWS_RUNTIME_DIR}/credentials"
        if [[ -f "${AWS_RUNTIME_DIR}/config" ]]; then
            export AWS_CONFIG_FILE="${AWS_RUNTIME_DIR}/config"
        else
            unset AWS_CONFIG_FILE
        fi

        # The AWS SDK gives environment keys precedence over shared credentials. Remove any
        # frozen values inherited from the dashboard so the newly staged file is authoritative.
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_BEARER_TOKEN_BEDROCK
        if [[ -n "${ORCHESTRATOR_AWS_PROFILE:-}" ]]; then
            export AWS_PROFILE="${ORCHESTRATOR_AWS_PROFILE}"
        else
            unset AWS_PROFILE AWS_DEFAULT_PROFILE
        fi
        echo "[credentials] current host AWS credential file is authoritative"
    fi

    case "${ORCHESTRATOR_EGRESS_MODE:-enforce}" in
        enforce)
            /app/docker/egress_firewall.sh
            ;;
        none)
            echo "[egress] network-disabled runtime; firewall bootstrap not required"
            ;;
        *)
            echo "[egress] FATAL: unsupported egress mode" >&2
            exit 78
            ;;
    esac

    echo "WATCH_LEARN_STAGE=container_bootstrap"

    EXPECTED_CONTROL_DIR='/app/watch-learn-control'
    if [[ "${WATCH_LEARN_ENTRYPOINT_HARNESS:-0}" == "1" \
        && "${WATCH_LEARN_SELF_TEST:-0}" == "1" ]]; then
        EXPECTED_CONTROL_DIR="${WATCH_LEARN_CONTROL_DIR}"
    fi
    DROP_ARGS=(
        --runtime-user "${RUNTIME_USER}"
        --control-dir "${WATCH_LEARN_CONTROL_DIR:-}"
        --expected-control-dir "${EXPECTED_CONTROL_DIR}"
    )
    if [[ -n "${WATCH_LEARN_CONTROL_DIR:-}" ]]; then
        DROP_ARGS+=(
            --owner-uid "${WATCH_LEARN_CONTROL_OWNER_UID:?}"
            --owner-gid "${WATCH_LEARN_CONTROL_OWNER_GID:?}"
        )
        DROP_COMMAND=(
            python -m orchestrator.watch_learn_runtime
            --display "${DISPLAY_NUM}"
            --screen-width "${SCREEN_W}"
            --screen-height "${SCREEN_H}"
            --screen-depth "${SCREEN_DEPTH}"
            -- "$@"
        )
    else
        DROP_COMMAND=("$0" "$@")
    fi
    export ORCHESTRATOR_PRIVILEGES_DROPPED=1
    # The module performs os.setuid(account.pw_uid) only after descriptor setup,
    # and verifies the resulting uid/gid/groups. Watch & Learn then uses a
    # bounded post-drop display handoff that closes the private descriptors in
    # Xvfb/xdpyinfo/fluxbox and restores inheritance only for the worker exec.
    exec python -m orchestrator.watch_learn_entrypoint \
        "${DROP_ARGS[@]}" -- "${DROP_COMMAND[@]}"
fi

if [[ "${ORCHESTRATOR_PRIVILEGES_DROPPED:-0}" != "1" ]]; then
    echo "[entrypoint] FATAL: secure secret staging was bypassed; use scripts/run_container.sh" >&2
    exit 78
fi

if [[ "$(id -u)" -eq 0 ]]; then
    echo "[entrypoint] FATAL: refusing to run agent workload as root" >&2
    exit 78
fi

echo "[entrypoint] runtime privileges dropped to uid=$(id -u) gid=$(id -g)"

export DISPLAY="${DISPLAY_NUM}"
# Keep all runtime state on writable tmpfs so a read-only root FS does not break startup.
export HOME="${HOME:-/home/orchestrator}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/runtime}"
mkdir -p /tmp/.X11-unix "${XDG_RUNTIME_DIR}" "${HOME}" 2>/dev/null || true
chmod 700 "${XDG_RUNTIME_DIR}" 2>/dev/null || true

cleanup() {
    [[ -n "${XVFB_PID:-}" ]] && kill "${XVFB_PID}" 2>/dev/null || true
    [[ -n "${WM_PID:-}" ]] && kill "${WM_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[entrypoint] starting Xvfb on ${DISPLAY_NUM} at ${SCREEN_W}x${SCREEN_H}x${SCREEN_DEPTH}"
XVFB_TRANSPORT_ARGS=(-nolisten tcp)
if [[ "${HOST_APP_X11_BRIDGE:-0}" == "1" ]]; then
    if [[ ! "${DISPLAY_NUM}" =~ ^:[0-9]+$ \
        || ! "${XAUTHORITY:-}" =~ ^/app/reports/\.host-app/run\.[A-Za-z0-9_-]+\.[0-9]+\.[A-Za-z0-9]+/Xauthority$ \
        || -L "${XAUTHORITY}" || ! -f "${XAUTHORITY}" ]]; then
        echo "[entrypoint] FATAL: host-app X11 authorization boundary is invalid" >&2
        exit 78
    fi
    XVFB_TRANSPORT_ARGS=(-listen tcp -auth "${XAUTHORITY}")
    echo "[entrypoint] authenticated loopback host-app X11 bridge enabled"
fi
Xvfb "${DISPLAY_NUM}" -screen 0 "${SCREEN_W}x${SCREEN_H}x${SCREEN_DEPTH}" \
    "${XVFB_TRANSPORT_ARGS[@]}" &
XVFB_PID=$!

# Wait for the X server to accept connections.
for _ in $(seq 1 50); do
    if ! kill -0 "${XVFB_PID}" 2>/dev/null; then
        wait "${XVFB_PID}" 2>/dev/null || true
        echo "[entrypoint] FATAL: Xvfb exited before display ${DISPLAY_NUM} became ready" >&2
        exit 1
    fi
    if xdpyinfo -display "${DISPLAY_NUM}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! kill -0 "${XVFB_PID}" 2>/dev/null || ! xdpyinfo -display "${DISPLAY_NUM}" >/dev/null 2>&1; then
    echo "[entrypoint] FATAL: Xvfb did not come up on ${DISPLAY_NUM}" >&2
    exit 1
fi

# A single-project host-app run has a host-side manager waiting for this file in
# the shared reports volume. Publish only after our own Xvfb is verifiably ready.
if [[ -n "${HOST_DISPLAY_READY_FILE:-}" ]]; then
    mkdir -p "$(dirname "${HOST_DISPLAY_READY_FILE}")"
    printf '%s\n' "${DISPLAY_NUM}" >"${HOST_DISPLAY_READY_FILE}"
    chmod 0644 "${HOST_DISPLAY_READY_FILE}" 2>/dev/null || true
    echo "[entrypoint] host display readiness published"
fi

echo "[entrypoint] launching window manager (fluxbox)"
fluxbox >/dev/null 2>&1 &
WM_PID=$!

echo "[entrypoint] display ready; handing off to: $*"
exec "$@"
