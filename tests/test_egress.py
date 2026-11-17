"""Phase 8 tests for orchestrator.egress (P8-2 allowlist computation)."""

from __future__ import annotations

import textwrap

import pytest

from orchestrator import egress
from orchestrator.egress import (
    BANNED_HOSTS,
    EgressPolicy,
    EgressResolutionError,
    bedrock_endpoint,
    compute_policy,
    resolve_policy_ipv4,
)


def test_bedrock_endpoint_uses_region():
    assert bedrock_endpoint("us-east-1") == "bedrock-runtime.us-east-1.amazonaws.com"


def test_policy_allows_bedrock_and_hosts():
    p = compute_policy(
        region="us-west-2", ssh_hosts=["build01"], rdp_hosts=["win01"], vnc_hosts=["vnc01"]
    )
    allowed = p.allowed_hosts
    assert "bedrock-runtime.us-west-2.amazonaws.com" in allowed
    assert "build01" in allowed
    assert "win01" in allowed
    assert "vnc01" in allowed
    assert p.is_allowed("build01")
    assert ("bedrock-runtime.us-west-2.amazonaws.com", "443") in p.allowed_endpoints
    assert ("build01", "22") in p.allowed_endpoints
    assert ("win01", "3389") in p.allowed_endpoints
    assert ("vnc01", "5900:5999") in p.allowed_endpoints


def test_policy_never_allows_banned_cloud_endpoint():
    p = compute_policy(region="us-west-2", ssh_hosts=["build01"], rdp_hosts=[], vnc_hosts=[])
    for banned in BANNED_HOSTS:
        assert not p.is_allowed(banned), f"{banned} must never be reachable"


def test_compute_policy_unions_project_allowlists(tmp_path, monkeypatch):
    """With no explicit hosts, the policy unions every project's merged allowlist."""
    def _manual(name):
        d = tmp_path.with_name(tmp_path.name + "-manuals") / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "manual.md").write_text("MASTER")
        return str(d)

    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "project.yaml").write_text(
        textwrap.dedent(f"""
        name: a
        manual_dir: {_manual("a")}
        ssh_host_allowlist: [build01]
        """)
    )
    (tmp_path / "a" / "t.md").write_text("# Test: T\n## Goal\nG\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "project.yaml").write_text(
        textwrap.dedent(f"""
        name: b
        manual_dir: {_manual("b")}
        rdp_host_allowlist: [win01]
        """)
    )
    (tmp_path / "b" / "t.md").write_text("# Test: T\n## Goal\nG\n")

    # No global allowlist contamination.
    monkeypatch.setattr(egress.settings, "ssh_host_allowlist", [])
    monkeypatch.setattr(egress.settings, "rdp_host_allowlist", [])
    monkeypatch.setattr(egress.settings, "vnc_host_allowlist", [])

    p = compute_policy(region="us-west-2", specs_root=str(tmp_path))
    assert "build01" in p.allowed_hosts
    assert "win01" in p.allowed_hosts


def test_target_only_vnc_jump_policy_allows_only_gateway_and_excludes_bedrock(tmp_path):
    manual = tmp_path / "manual"
    manual.mkdir()
    (manual / "manual.md").write_text("# Manual\n")
    project = tmp_path / "jump-vnc"
    project.mkdir()
    (project / "project.yaml").write_text(textwrap.dedent("""
        name: Jump VNC
        manual_dir: ./manual
        target:
          type: vnc
          host: vnc-private
          port: 5900
          route:
            type: ssh-jump
            host: jump-approved
            user: operator
            port: 22
            known_hosts_file: jump.known_hosts
        ssh_host_allowlist: [jump-approved]
        vnc_host_allowlist: [vnc-private]
    """))
    (project / "manual").mkdir()
    (project / "manual" / "manual.md").write_text("# Manual\n")
    (project / "test.md").write_text("# Test: T\n\n## Goal\nG\n")

    policy = compute_policy(
        specs_root=str(tmp_path), project_name="jump-vnc", include_bedrock=False
    )
    assert policy.bedrock is None
    assert policy.allowed_hosts == ["jump-approved"]
    assert policy.allowed_endpoints == [("jump-approved", "22")]


def test_resolve_policy_ipv4_returns_validated_deterministic_host_entries():
    policy = compute_policy(
        region="us-west-2",
        ssh_hosts=["build01"],
        rdp_hosts=[],
        vnc_hosts=[],
    )

    def resolver(host, _port, *, family, type):
        assert family == egress.socket.AF_INET
        assert type == egress.socket.SOCK_STREAM
        values = {
            "bedrock-runtime.us-west-2.amazonaws.com": ["192.0.2.20", "192.0.2.10"],
            "build01": ["10.0.0.8", "10.0.0.8"],
        }
        return [(family, type, 6, "", (address, 0)) for address in values[host]]

    assert resolve_policy_ipv4(policy, resolver=resolver) == [
        ("192.0.2.10", "bedrock-runtime.us-west-2.amazonaws.com"),
        ("192.0.2.20", "bedrock-runtime.us-west-2.amazonaws.com"),
        ("10.0.0.8", "build01"),
    ]


def test_resolve_policy_ipv4_fails_closed_on_invalid_or_missing_answer():
    invalid = EgressPolicy(
        bedrock="bedrock-runtime.us-west-2.amazonaws.com\nmalicious",
        ssh_hosts=frozenset(),
        rdp_hosts=frozenset(),
        vnc_hosts=frozenset(),
    )
    with pytest.raises(EgressResolutionError, match="hostname is invalid"):
        resolve_policy_ipv4(invalid, resolver=lambda *_a, **_kw: [])

    policy = compute_policy(
        region="us-west-2",
        ssh_hosts=[],
        rdp_hosts=[],
        vnc_hosts=[],
    )
    with pytest.raises(EgressResolutionError, match="no usable IPv4"):
        resolve_policy_ipv4(policy, resolver=lambda *_a, **_kw: [])
