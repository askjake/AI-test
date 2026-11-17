#!/usr/bin/env bash
# Phase 8 — egress allowlist (P8-2).
# Applies a default-DROP outbound policy so the container can reach ONLY the
# exact TCP ports for Bedrock and allowlisted SSH/RDP/VNC hosts. Names are
# resolved before the DROP policy is installed. Target destinations are pinned
# in /etc/hosts; Bedrock is reachable only through the authenticated host relay.
# The workload receives no general-purpose DNS egress.
# Everything else — including the banned Claude Cloud endpoint api.anthropic.com — is dropped.
#
# The allowed hostnames come from `python -m orchestrator.egress` (Bedrock + the union of every
# project's effective SSH/RDP/VNC allowlist). The host launcher pre-resolves those names into
# the private per-run hosts file; this bootstrap independently resolves only approved names from
# that file. Run this as root inside the container BEFORE dropping to the orchestrator user, or from an init sidecar that
# shares the container's network namespace. Requires NET_ADMIN (add only this capability;
# everything else stays dropped). loopback stays open for the local X server.
set -euo pipefail

IPTABLES="${IPTABLES:-iptables}"
IP6TABLES="${IP6TABLES:-ip6tables}"

command -v "${IPTABLES}" >/dev/null 2>&1 || {
    echo "[egress] FATAL: iptables is unavailable" >&2
    exit 1
}
command -v "${IP6TABLES}" >/dev/null 2>&1 || {
    echo "[egress] FATAL: ip6tables is unavailable" >&2
    exit 1
}

echo "[egress] computing allowlist via orchestrator.egress"
POLICY_ARGS=()
if [[ -n "${ORCHESTRATOR_EGRESS_PROJECT:-}" ]]; then
    POLICY_ARGS+=(--project "${ORCHESTRATOR_EGRESS_PROJECT}")
fi
if [[ "${ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK:-0}" == "1" ]]; then
    POLICY_ARGS+=(--exclude-bedrock)
fi
mapfile -t ENDPOINTS < <(python -m orchestrator.egress "${POLICY_ARGS[@]}")
if [[ ${#ENDPOINTS[@]} -eq 0 ]]; then
    echo "[egress] FATAL: empty allowlist" >&2
    exit 1
fi

BEDROCK_PROXY_HOST="${ORCHESTRATOR_BEDROCK_PROXY_HOST:-}"
BEDROCK_PROXY_PORT="${ORCHESTRATOR_BEDROCK_PROXY_PORT:-}"
BEDROCK_ENDPOINT="${ORCHESTRATOR_BEDROCK_ENDPOINT:-}"
BEDROCK_RELAY_ENABLED=false
if [[ -n "${BEDROCK_PROXY_HOST}${BEDROCK_PROXY_PORT}${BEDROCK_ENDPOINT}" ]]; then
    if [[ ! "${BEDROCK_PROXY_HOST}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
        || ! "${BEDROCK_PROXY_PORT}" =~ ^[0-9]+$ \
        || ! "${BEDROCK_ENDPOINT}" =~ ^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$ \
        || "${BEDROCK_PROXY_PORT}" -lt 1 \
        || "${BEDROCK_PROXY_PORT}" -gt 65535 ]]; then
        echo "[egress] FATAL: authenticated Bedrock relay contract is incomplete or invalid" >&2
        exit 1
    fi
    IFS='.' read -r proxy_octet1 proxy_octet2 proxy_octet3 proxy_octet4 <<<"${BEDROCK_PROXY_HOST}"
    for octet in "${proxy_octet1}" "${proxy_octet2}" "${proxy_octet3}" "${proxy_octet4}"; do
        if (( 10#${octet} > 255 )); then
            echo "[egress] FATAL: authenticated Bedrock relay address is invalid" >&2
            exit 1
        fi
    done
    BEDROCK_RELAY_ENABLED=true
fi

TARGET_RELAY_KIND="${ORCHESTRATOR_TARGET_RELAY_KIND:-}"
TARGET_RELAY_ENDPOINT="${ORCHESTRATOR_TARGET_RELAY_ENDPOINT:-}"
TARGET_RELAY_DESTINATION_PORT="${ORCHESTRATOR_TARGET_RELAY_DESTINATION_PORT:-}"
TARGET_RELAY_HOST="${ORCHESTRATOR_TARGET_RELAY_HOST:-}"
TARGET_RELAY_PORT="${ORCHESTRATOR_TARGET_RELAY_PORT:-}"
TARGET_RELAY_TOKEN="${ORCHESTRATOR_TARGET_RELAY_TOKEN:-}"
TARGET_RELAY_ENABLED=false
if [[ -n "${TARGET_RELAY_KIND}${TARGET_RELAY_ENDPOINT}${TARGET_RELAY_DESTINATION_PORT}${TARGET_RELAY_HOST}${TARGET_RELAY_PORT}${TARGET_RELAY_TOKEN}" ]]; then
    if [[ -z "${ORCHESTRATOR_EGRESS_PROJECT:-}" \
        || ! "${TARGET_RELAY_KIND}" =~ ^(rdp-direct|vnc-(direct|ssh-jump))$ \
        || ! "${TARGET_RELAY_ENDPOINT}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ \
        || ! "${TARGET_RELAY_DESTINATION_PORT}" =~ ^[0-9]+$ \
        || ! "${TARGET_RELAY_HOST}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
        || ! "${TARGET_RELAY_PORT}" =~ ^[0-9]+$ \
        || ! "${TARGET_RELAY_TOKEN}" =~ ^[A-Za-z0-9_-]{32,128}$ \
        || "${TARGET_RELAY_DESTINATION_PORT}" -lt 1 \
        || "${TARGET_RELAY_DESTINATION_PORT}" -gt 65535 \
        || "${TARGET_RELAY_PORT}" -lt 1 \
        || "${TARGET_RELAY_PORT}" -gt 65535 ]]; then
        echo "[egress] FATAL: authenticated target relay contract is incomplete or invalid" >&2
        exit 1
    fi
    if ! expected_target_transport="$(
        python -m orchestrator.target_relay describe \
            --project "${ORCHESTRATOR_EGRESS_PROJECT}" --specs-root /app/tests_specs
    )"; then
        echo "[egress] FATAL: exact project target transport could not be verified" >&2
        exit 1
    fi
    mapfile -t expected_target_values <<<"${expected_target_transport}"
    if [[ "${#expected_target_values[@]}" -ne 3 \
        || "${expected_target_values[0]}" != "${TARGET_RELAY_KIND}" \
        || "${expected_target_values[1]}" != "${TARGET_RELAY_ENDPOINT}" \
        || "${expected_target_values[2]}" != "${TARGET_RELAY_DESTINATION_PORT}" ]]; then
        echo "[egress] FATAL: target relay differs from the exact reviewed project transport" >&2
        exit 1
    fi
    IFS='.' read -r target_proxy_octet1 target_proxy_octet2 target_proxy_octet3 target_proxy_octet4 <<<"${TARGET_RELAY_HOST}"
    for octet in "${target_proxy_octet1}" "${target_proxy_octet2}" "${target_proxy_octet3}" "${target_proxy_octet4}"; do
        if (( 10#${octet} > 255 )); then
            echo "[egress] FATAL: authenticated target relay address is invalid" >&2
            exit 1
        fi
    done
    TARGET_RELAY_ENABLED=true
fi

# Resolve every approved name strictly from the host-seeded private hosts file
# before changing policy. A missing destination is a startup failure, never a
# DNS fallback or a silently weakened/partially applied policy.
RULES=()
bedrock_endpoint_count=0
target_endpoint_count=0
for endpoint in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r host ports extra <<<"${endpoint}"
    if [[ -n "${extra:-}" || ! "${host}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ \
        || ! "${ports}" =~ ^[0-9]+(:[0-9]+)?$ ]]; then
        echo "[egress] FATAL: invalid typed endpoint" >&2
        exit 1
    fi
    if [[ "${BEDROCK_RELAY_ENABLED}" == "true" && "${host}" == "${BEDROCK_ENDPOINT}" ]]; then
        if [[ "${ports}" != "443" ]]; then
            echo "[egress] FATAL: Bedrock relay endpoint has an invalid port policy" >&2
            exit 1
        fi
        bedrock_endpoint_count=$((bedrock_endpoint_count + 1))
        continue
    fi
    if [[ "${TARGET_RELAY_ENABLED}" == "true" && "${host}" == "${TARGET_RELAY_ENDPOINT}" ]]; then
        target_endpoint_count=$((target_endpoint_count + 1))
        continue
    fi
    ips="$(
        awk -v approved="${host}" '
            {
                for (field_index = 2; field_index <= NF; field_index += 1) {
                    if ($field_index == approved) {
                        print $1
                    }
                }
            }
        ' /etc/hosts | sort -u
    )"
    if [[ -z "${ips}" ]]; then
        echo "[egress] FATAL: approved endpoint is absent from private hosts file: ${host}" >&2
        exit 1
    fi
    for ip in ${ips}; do
        if [[ ! "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "[egress] FATAL: private hosts file contains invalid IPv4 data" >&2
            exit 1
        fi
        IFS='.' read -r octet1 octet2 octet3 octet4 <<<"${ip}"
        for octet in "${octet1}" "${octet2}" "${octet3}" "${octet4}"; do
            if (( 10#${octet} > 255 )); then
                echo "[egress] FATAL: private hosts file contains invalid IPv4 data" >&2
                exit 1
            fi
        done
        RULES+=("${ip}" "${ports}")
    done
done
if [[ "${BEDROCK_RELAY_ENABLED}" == "true" ]]; then
    if [[ "${bedrock_endpoint_count}" -ne 1 ]]; then
        echo "[egress] FATAL: Bedrock relay endpoint does not match reviewed policy" >&2
        exit 1
    fi
    RULES+=("${BEDROCK_PROXY_HOST}" "${BEDROCK_PROXY_PORT}")
fi
if [[ "${TARGET_RELAY_ENABLED}" == "true" ]]; then
    if [[ "${target_endpoint_count}" -ne 1 ]]; then
        echo "[egress] FATAL: target relay endpoint does not match reviewed policy" >&2
        exit 1
    fi
    RULES+=("${TARGET_RELAY_HOST}" "${TARGET_RELAY_PORT}")
fi

echo "[egress] flushing OUTPUT chain and setting default DROP"
${IPTABLES} -F OUTPUT
${IPTABLES} -P OUTPUT DROP
${IP6TABLES} -F OUTPUT
${IP6TABLES} -P OUTPUT DROP

# Allow established return traffic and loopback. IPv6 has no destination
# exceptions, preventing a dual-stack bypass.
${IPTABLES} -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
${IPTABLES} -A OUTPUT -o lo -j ACCEPT
${IP6TABLES} -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
${IP6TABLES} -A OUTPUT -o lo -j ACCEPT

for ((index = 0; index < ${#RULES[@]}; index += 2)); do
    ip="${RULES[index]}"
    ports="${RULES[index + 1]}"
    echo "[egress] allow ${ip} tcp/${ports}"
    ${IPTABLES} -A OUTPUT -p tcp -d "${ip}" --dport "${ports}" -j ACCEPT
done

echo "[egress] egress allowlist applied (default DROP, DNS blocked, IPv6 default DROP)"
