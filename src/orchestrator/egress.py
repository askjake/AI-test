"""Computes the network egress allowlist for the hardened container (Phase 8, P8-2).

The container must only reach **Bedrock + the allowlisted SSH/RDP/VNC hosts** — nothing else.
This blocks data exfiltration and, critically, any accidental call to the banned Claude
Cloud endpoint (``api.anthropic.com``). The actual enforcement is an ``iptables`` default-
DROP egress policy applied by ``docker/egress_firewall.sh``; this module is the single,
unit-testable source of *what* that policy should allow, derived from config + the merged
project allowlists.

Endpoints are returned with their permitted TCP ports. The host resolves them before launch.
Target addresses are pinned in the container's private hosts file; Bedrock TLS traverses an
authenticated, destination-locked host CONNECT relay so a Docker bridge can use host VPN or
proxy reachability without receiving host networking. The workload has no general-purpose
DNS egress.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import re
import socket
import sys
from collections.abc import Callable, Sequence

from .config import settings
import os

from .projects import (
    RDP_CHAIN,
    ChainProjectError,
    discover_projects,
    explain_chain_project_error,
    project_slug,
    rdp_chain_outer_hop,
)


def bedrock_endpoint(region: str | None = None) -> str:
    """The Bedrock runtime hostname for ``region`` (the only AI transport, Phase 1)."""
    region = region or settings.aws_region
    return f"bedrock-runtime.{region}.amazonaws.com"


# Hosts that must NEVER be reachable — the banned Claude Cloud transport. Used by the gate
# to assert the allowlist never contains them.
BANNED_HOSTS = frozenset({"api.anthropic.com"})
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


class EgressResolutionError(RuntimeError):
    """An approved endpoint could not be safely resolved on the host."""


@dataclass(frozen=True)
class EgressPolicy:
    """The set of hostnames outbound traffic may reach. Everything else is dropped."""

    bedrock: str | None
    ssh_hosts: frozenset[str]
    rdp_hosts: frozenset[str]
    vnc_hosts: frozenset[str]

    @property
    def allowed_hosts(self) -> list[str]:
        """All allowed destination hostnames, sorted and de-duplicated."""
        return sorted({*([self.bedrock] if self.bedrock else []), *self.ssh_hosts, *self.rdp_hosts, *self.vnc_hosts})

    def is_allowed(self, host: str) -> bool:
        return host in set(self.allowed_hosts)

    @property
    def allowed_endpoints(self) -> list[tuple[str, str]]:
        """Return deterministic ``(host, iptables-port-spec)`` entries."""
        endpoints = {(self.bedrock, "443")} if self.bedrock else set()
        endpoints.update((host, "22") for host in self.ssh_hosts)
        endpoints.update((host, "3389") for host in self.rdp_hosts)
        endpoints.update((host, "5900:5999") for host in self.vnc_hosts)
        return sorted(endpoints)


def compute_policy(
    *,
    region: str | None = None,
    specs_root: str | None = None,
    ssh_hosts: list[str] | None = None,
    rdp_hosts: list[str] | None = None,
    vnc_hosts: list[str] | None = None,
    project_name: str | None = None,
    include_bedrock: bool = True,
) -> EgressPolicy:
    """Build the egress policy: Bedrock + every allowlisted SSH/RDP/VNC host across all projects.

    By default the SSH/RDP/VNC hosts are the **union** of every enabled project's *effective*
    (merged) allowlist, so a single firewall covers the whole scheduler. Explicit
    ``ssh_hosts``/``rdp_hosts``/``vnc_hosts`` override discovery (used by tests and
    single-project runs).
    """
    if project_name is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", project_name):
            raise EgressResolutionError("project name is invalid")
        matches = [item for item in discover_projects(specs_root, include_disabled=True) if project_slug(item) == project_name]
        if len(matches) != 1:
            detail = explain_chain_project_error(
                os.path.join(specs_root if specs_root is not None else settings.tests_specs_dir, project_name),
                specs_root if specs_root is not None else settings.tests_specs_dir,
            )
            raise EgressResolutionError(detail or "the exact project could not be resolved")
        config = matches[0].config
        ssh_hosts, rdp_hosts, vnc_hosts = [], [], []
        target = config.target
        if target.type == "ssh-terminal":
            route_type = target.params.get("route_type", "direct")
            ssh_hosts = [target.params.get("jump_host") or target.params.get("host")] if route_type == "ssh-jump" else [target.params.get("host")]
        elif target.type == "rdp":
            rdp_hosts = [target.params.get("host")]
        elif target.type == "vnc":
            if target.params.get("route_type", "direct") == "ssh-jump":
                ssh_hosts = [target.params.get("jump_host")]
            else:
                vnc_hosts = [target.params.get("host")]
        elif target.type == RDP_CHAIN:
            # Only hop 1 is a direct runner destination; hop 2.. are nested inside its desktop.
            try:
                rdp_hosts = [rdp_chain_outer_hop(target).host]
            except ChainProjectError as exc:
                raise EgressResolutionError(f"rdp-chain project transport is invalid: {exc}") from exc
        ssh_hosts = [item for item in ssh_hosts if item]
        rdp_hosts = [item for item in rdp_hosts if item]
        vnc_hosts = [item for item in vnc_hosts if item]
    elif ssh_hosts is None or rdp_hosts is None or vnc_hosts is None:
        discovered_ssh: set[str] = set()
        discovered_rdp: set[str] = set()
        discovered_vnc: set[str] = set()
        for project in discover_projects(specs_root):
            discovered_ssh.update(project.config.ssh_host_allowlist)
            discovered_rdp.update(project.config.rdp_host_allowlist)
            discovered_vnc.update(project.config.vnc_host_allowlist)
        # Fall back to global config when there are no projects at all.
        discovered_ssh.update(settings.ssh_host_allowlist)
        discovered_rdp.update(settings.rdp_host_allowlist)
        discovered_vnc.update(settings.vnc_host_allowlist)
        ssh_hosts = sorted(discovered_ssh) if ssh_hosts is None else ssh_hosts
        rdp_hosts = sorted(discovered_rdp) if rdp_hosts is None else rdp_hosts
        vnc_hosts = sorted(discovered_vnc) if vnc_hosts is None else vnc_hosts

    return EgressPolicy(
        bedrock=bedrock_endpoint(region) if include_bedrock else None,
        ssh_hosts=frozenset(ssh_hosts),
        rdp_hosts=frozenset(rdp_hosts),
        vnc_hosts=frozenset(vnc_hosts),
    )


def resolve_policy_ipv4(
    policy: EgressPolicy,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> list[tuple[str, str]]:
    """Resolve approved names to deterministic IPv4 hosts-file entries.

    Resolution happens in the trusted host launcher before the isolated
    container starts. The container independently recomputes the hostname and
    port policy, resolves those names from the private per-run hosts file, and
    installs the default-DROP firewall. Extra host-side results therefore do
    not widen the container firewall.
    """
    entries: set[tuple[str, str]] = set()
    for host in policy.allowed_hosts:
        if not _HOST_RE.fullmatch(host):
            raise EgressResolutionError("approved endpoint hostname is invalid")
        try:
            answers = resolver(
                host,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise EgressResolutionError(
                f"approved endpoint could not be resolved on the host: {host}"
            ) from exc
        addresses: set[str] = set()
        for answer in answers:
            try:
                address = ipaddress.IPv4Address(answer[4][0])
            except (IndexError, TypeError, ValueError):
                continue
            if address.is_unspecified or address.is_multicast:
                continue
            addresses.add(str(address))
        if not addresses:
            raise EgressResolutionError(
                f"approved endpoint returned no usable IPv4 address: {host}"
            )
        entries.update((address, host) for address in addresses)
    return sorted(entries, key=lambda value: (value[1], ipaddress.IPv4Address(value[0])))


def main(argv: Sequence[str] | None = None) -> int:
    """Print tab-delimited hostname/port entries for the firewall bootstrap."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--resolved-hosts",
        action="store_true",
        help="print host-resolved IPv4/hostname entries for a private hosts file",
    )
    parser.add_argument("--project", help="restrict target egress to one exact project")
    parser.add_argument(
        "--exclude-bedrock", action="store_true",
        help="omit Bedrock from a target-only capture policy",
    )
    args = parser.parse_args(argv)
    try:
        policy = compute_policy(
            project_name=args.project,
            include_bedrock=not args.exclude_bedrock,
        )
    except EgressResolutionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.resolved_hosts:
        try:
            entries = resolve_policy_ipv4(policy)
        except EgressResolutionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for address, host in entries:
            print(f"{address}\t{host}")
        return 0
    for host, ports in policy.allowed_endpoints:
        print(f"{host}\t{ports}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
