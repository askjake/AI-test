"""b4r8: rdp-chain OUTER transport (egress policy + authenticated target relay + hop-1 adapter).

Defect (b4r7, run trig_20261030T202550_efb2cabb): ``egress.compute_policy`` and
``target_relay.describe_project_transport`` handled plain rdp/vnc only, so an rdp-chain run got no
target-relay lease, no hosts pin and no firewall allowance; FreeRDP dialled hop 1 directly into the
default-DROP policy and timed out (ERRCONNECT_CONNECT_FAILED).  Fictional hosts/credentials only.
"""
from __future__ import annotations

import json

import pytest

from orchestrator.chain import ChainHop
from orchestrator.egress import EgressResolutionError, compute_policy
from orchestrator.models import Target
from orchestrator.projects import ChainProjectError, RDP_CHAIN, rdp_chain_outer_hop
from orchestrator.target_relay import ProjectTransport, TargetRelayError, describe_project_transport
from orchestrator.targets import TargetError, TargetSpec, Targets

FP = "sha256:" + "ab" * 32
H1 = "10.70.115.36"
H2 = "172.20.33.215"


def chain_project(root, name="chain", *, h1=H1, port=3389, allow=None, hops2=True):
    project = root / name
    (project / "manual").mkdir(parents=True)
    (project / "manual" / "manual.md").write_text("# Manual\n")
    (project / "test.md").write_text("# Test: Chain\n\n## Goal\nConnect.\n")
    chain = [{"order": 1, "host": h1, "port": port, "user": "u1", "password_file": "ref1.rdp.pw",
              "certificate_name": "host1", "certificate_fingerprint": FP}]
    hosts = [h1]
    if hops2:
        chain.append({"order": 2, "host": H2, "user": "u2", "password_file": "ref2.rdp.pw"})
        hosts.append(H2)
    doc = {"name": "Chain", "manual_dir": "./manual", "enabled": True,
           "target": {"type": "rdp-chain", "chain": chain},
           "rdp_host_allowlist": allow if allow is not None else [h1], "chain_hosts": hosts}
    (project / "project.yaml").write_text(json.dumps(doc))
    return name


def test_policy_and_relay_are_derived_from_hop1_only_and_agree(tmp_path):
    chain_project(tmp_path, port=3390)
    policy = compute_policy(region="us-west-2", specs_root=str(tmp_path), project_name="chain")
    transport = describe_project_transport("chain", specs_root=str(tmp_path))
    assert policy.rdp_hosts == frozenset({H1})
    assert (H1, "3389") in policy.allowed_endpoints
    assert H2 not in policy.allowed_hosts and not policy.is_allowed(H2)       # hop 2 is never a runner destination
    assert transport == ProjectTransport("rdp-direct", H1, 3390)              # logical destination = reviewed hop 1
    assert transport.endpoint in policy.rdp_hosts                             # policy and relay cannot disagree
    assert not policy.ssh_hosts and not policy.vnc_hosts


def test_single_hop_chain_is_supported(tmp_path):
    chain_project(tmp_path, hops2=False)
    assert describe_project_transport("chain", specs_root=str(tmp_path)) == ProjectTransport("rdp-direct", H1, 3389)
    assert compute_policy(region="us-west-2", specs_root=str(tmp_path), project_name="chain").rdp_hosts == frozenset({H1})


def test_hop2_in_the_runner_allowlist_is_rejected_with_a_useful_error(tmp_path):
    chain_project(tmp_path, allow=[H1, H2])
    with pytest.raises(TargetRelayError, match="rdp-chain project transport is invalid"):
        describe_project_transport("chain", specs_root=str(tmp_path))
    with pytest.raises(EgressResolutionError, match="rdp-chain project transport is invalid"):
        compute_policy(region="us-west-2", specs_root=str(tmp_path), project_name="chain")


@pytest.mark.parametrize("kwargs,needle", [
    ({"h1": "bad host"}, "malformed"),
    ({"port": 0}, "port"),
    ({"port": 70000}, "port"),
])
def test_missing_or_malformed_hop1_transport_is_rejected_before_launch(tmp_path, kwargs, needle):
    chain_project(tmp_path, **kwargs)
    with pytest.raises(TargetRelayError, match=needle):
        describe_project_transport("chain", specs_root=str(tmp_path))
    with pytest.raises(EgressResolutionError, match=needle):
        compute_policy(region="us-west-2", specs_root=str(tmp_path), project_name="chain")


def test_outer_hop_helper_rejects_non_chain_and_empty_chain():
    with pytest.raises(ChainProjectError, match="not an rdp-chain"):
        rdp_chain_outer_hop(Target(type="rdp", params={"host": "x"}))
    with pytest.raises(ChainProjectError, match="no connections"):
        rdp_chain_outer_hop(Target(type=RDP_CHAIN, params={}, hops=[]))
    hop = ChainHop(order=1, host=H1, port=3390, user="u", password_file="r.pw",
                   certificate_name="h", certificate_fingerprint=FP)
    assert rdp_chain_outer_hop(Target(type=RDP_CHAIN, params={}, hops=[hop])) is hop


# ---------------------------------------------------------------- hop-1 adapter through the relay

class Proc:
    pid = 11
    def poll(self): return None
    def terminate(self): pass
    def kill(self): pass
    def wait(self, timeout=None): return 0


class Launcher:
    def __init__(self): self.calls = []
    def __call__(self, cmd, env=None, log_path=None, stdin_data=None):
        self.calls.append({"cmd": list(cmd), "stdin": stdin_data})
        return Proc()


def targets(tmp_path, launcher):
    (tmp_path / "ref.rdp.pw").write_text("Zq9-NOTREAL-pw-1\n")
    return Targets(display=":99", rdp_host_allowlist=[H1], secrets_dir=str(tmp_path),
                   runner=lambda cmd: "777\n" if len(cmd) > 1 and cmd[1] == "search" else "",
                   launcher=launcher, sleep=lambda _s: None)


def spec(port=None):
    params = {"host": H1, "user": "u1", "password_file": "ref.rdp.pw", "window": "w1",
              "password_transport": "stdin", "certificate_name": "host1", "certificate_fingerprint": FP}
    if port:
        params["port"] = str(port)
    return TargetSpec("rdp", params)


def relay_env(monkeypatch, *, endpoint=H1, port="3390"):
    for key, value in {"KIND": "rdp-direct", "ENDPOINT": endpoint, "DESTINATION_PORT": port,
                       "HOST": "127.0.0.1", "PORT": "9", "TOKEN": "t" * 40}.items():
        monkeypatch.setenv(f"ORCHESTRATOR_TARGET_RELAY_{key}", value)


def test_hop1_goes_through_the_loopback_relay_but_certificate_stays_bound_to_the_logical_target(tmp_path, monkeypatch):
    relay_env(monkeypatch)
    launcher = Launcher()
    handle = targets(tmp_path, launcher).open_target(spec(port=3390))
    try:
        cmd = launcher.calls[0]["cmd"]
        assert cmd[1].startswith("/v:127.0.0.1:") and H1 not in cmd[1]
        cert = next(a for a in cmd if a.startswith("/cert:"))
        assert cert.startswith("/cert:deny,name:host1,fingerprint:sha256:ab:ab")        # reviewed identity, not localhost
        assert "127.0.0.1" not in cert and "localhost" not in cert
        assert "/from-stdin" in cmd and not any(a.startswith("/p:") for a in cmd)
        assert H2 not in " ".join(cmd)
    finally:
        for item in getattr(handle, "extras", ()) or ():
            item.terminate()


@pytest.mark.parametrize("kwargs", [{"endpoint": "other-host"}, {"port": "3391"}])
def test_relay_bound_to_a_different_destination_stops_before_freerdp_or_credential(tmp_path, monkeypatch, kwargs):
    relay_env(monkeypatch, **kwargs)
    launcher = Launcher()
    with pytest.raises(TargetError):
        targets(tmp_path, launcher).open_target(spec(port=3390))
    assert launcher.calls == []            # FreeRDP never started, nothing written to its stdin
