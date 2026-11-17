#!/usr/bin/env bash
# Run test specs inside the hardened container (scripts/run_container.sh).
#
#   scripts/run_specs.sh            # run every enabled project (all specs)
#   scripts/run_specs.sh mul        # run one project by name
#   scripts/run_specs.sh tests_specs/mul/connection_test.md   # run one spec file
#
# Specs need the in-container GUI stack (Xvfb + xdotool + xfreerdp), so this always runs
# through the container. It wires up the two things the run needs from the host:
#   - AWS credentials (exported from the standard chain into env for run_container.sh)
#   - an explicitly configured BEDROCK_MODEL_ID
#
# Set ORCHESTRATOR_LOG_LEVEL=DEBUG to surface the per-step planner context-size logs
# (defaults to INFO); it is forwarded into the container by run_container.sh.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

# Log verbosity for the in-container run; DEBUG reveals per-step planner context sizes.
export ORCHESTRATOR_LOG_LEVEL="${ORCHESTRATOR_LOG_LEVEL:-DEBUG}"

# A working model id is required; there is no baked-in account-specific fallback.
# Honour an explicit BEDROCK_MODEL_ID, else use the operator-configured Sonnet profile.
export BEDROCK_MODEL_ID="${BEDROCK_MODEL_ID:-${ANTHROPIC_DEFAULT_SONNET_MODEL:-}}"
if [[ -z "${BEDROCK_MODEL_ID}" ]]; then
    echo "error: set BEDROCK_MODEL_ID (or ANTHROPIC_DEFAULT_SONNET_MODEL) to a current Bedrock profile ARN" >&2
    exit 1
fi

# Resolve AWS credentials from the standard chain into env so run_container.sh can forward
# them (it passes creds by env only, never a mounted ~/.aws).
if creds="$(aws configure export-credentials --format env 2>/dev/null)"; then
    eval "${creds}"
fi

# ── Problem-2 fix: pre-warm RDP session before container launch ───────────────
# Prevents ACTIVATION_TIMEOUT when no disconnected session exists on the target.
# Non-fatal: set RDP_WARMUP_SKIP=1 to bypass. Some deployments provide the
# optional helper out-of-band; its absence must not block local/SSH/VNC runs.
RDP_PREWARM_SCRIPT="${PROJECT_ROOT}/scripts/rdp-prewarm.sh"
if [[ "${RDP_WARMUP_SKIP:-0}" != "1" ]]; then
    if [[ -x "${RDP_PREWARM_SCRIPT}" ]]; then
        "${RDP_PREWARM_SCRIPT}"
    else
        echo "[runner] WARNING: optional RDP pre-warm helper is unavailable; continuing without pre-warm" >&2
    fi
fi
unset RDP_PREWARM_SCRIPT
# ── end pre-warm ──────────────────────────────────────────────────────────────

# Build the in-container command.
export ORCHESTRATOR_RUN_PROJECT=""
if [[ $# -eq 0 ]]; then
    # No argument: run every enabled project once.
    set -- python -m orchestrator.scheduler --once
elif [[ "$1" == *.md || -f "$1" ]]; then
    # Argument is a spec file: pass its repo-relative path (= the container path under /app).
    spec_rel="${1#"${PROJECT_ROOT}/"}"
    if [[ ! -f "${PROJECT_ROOT}/${spec_rel}" ]]; then
        echo "error: spec file not found: $1" >&2
        exit 1
    fi
    set -- python -m orchestrator.runner "${spec_rel}"
else
    # Argument is a project name.
    export ORCHESTRATOR_RUN_PROJECT="$1"
    set -- python -m orchestrator.runner --project "$1"
fi

exec "${PROJECT_ROOT}/scripts/run_container.sh" "$@"
