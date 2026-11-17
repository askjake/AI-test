"""NRDP-1 S2b: procedure_project tests (mocked/local; fictional passwords)."""
from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace as NS

import pytest
import yaml

try:
    from dashboard import procedure_project as pp
except ImportError:  # pragma: no cover
    from src.dashboard import procedure_project as pp

PW1, PW2 = "Fict!onal-Hop1-Pw", "Fict!onal-Hop2-Pw"
FP = "sha256:" + "ab" * 32
DID = "0123456789abcdef0123456789abcdef"


def make_draft(**over):
    hops = [NS(order=1, host="10.70.115.36", port=3389, user="ops1", password_reference="procedure-x-hop-1.rdp.pw",
               opened_from="runner desktop", certificate_name="HOP1-CERT", certificate_fingerprint=FP),
            NS(order=2, host="172.20.33.215", port=3389, user="ops2", password_reference="procedure-x-hop-2.rdp.pw",
               opened_from="RDP desktop from hop 1", identity_policy="stop")]
    steps = [NS(order=1, title="Check elevation", kind="procedure-step", instructions="IsInRole check",
                completion_checks=["The current token is elevated: IsInRole(Administrator) returns True."]),
             NS(order=2, title="Stop service", kind="procedure-step", instructions="Stop-Service -Name Foo",
                completion_checks=["The named Windows service reaches Stopped before any hardware work."]),
             NS(order=3, title="Swap wires", kind="operator-checkpoint", instructions="physically swap COM3",
                completion_checks=["Operator completion is required."])]
    d = dict(id=DID, title="Foo service maintenance", connections=hops, steps=steps,
             manual="# Foo service maintenance\n\nUse saved reference only.\n")
    d.update(over)
    return NS(**d)


@pytest.fixture
def roots(tmp_path):
    specs, secrets = tmp_path / "specs", tmp_path / "secrets"
    specs.mkdir(); secrets.mkdir()
    (secrets / "procedure-x-hop-1.rdp.pw").write_text(PW1)
    (secrets / "procedure-x-hop-2.rdp.pw").write_text(PW2)
    return str(specs), str(secrets)


def _digest(d):
    return {n: hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest() for n in sorted(os.listdir(d))}


def test_render_full_example():
    files = pp.render_project_files(make_draft(), forbidden=[PW1, PW2])
    doc = yaml.safe_load(files["project.yaml"])
    assert doc["target"]["type"] == "rdp-chain"
    assert [h["host"] for h in doc["target"]["chain"]] == ["10.70.115.36", "172.20.33.215"]
    assert doc["rdp_host_allowlist"] == ["10.70.115.36"]
    assert doc["chain_hosts"] == ["10.70.115.36", "172.20.33.215"]
    assert doc["manual_dir"] == "./manual"      # the only project-relative form the runner's loader accepts
    assert doc["target"]["chain"][0]["certificate_fingerprint"] == FP
    assert doc["target"]["chain"][1]["identity_policy"] == "stop"
    assert "certificate_name" not in doc["target"]["chain"][1]
    p = doc["procedure"]
    assert p["draft_id"] == DID and p["final_hop"] == 2 and p["required_checkpoints"] == [3]
    assert p["steps"][1]["mutating"] is True and p["steps"][0]["read_only_ok"] is True
    assert p["steps"][2]["read_only_ok"] is False
    assert pp.validate_chain_yaml(doc) == []
    spec = files["procedure.md"]
    assert "INSIDE the final Windows desktop (hop 2)" in spec
    assert "must not run anything on the Linux host" in spec
    assert "IsInRole(Administrator) returns True." in spec
    for text in files.values():
        assert PW1 not in text and PW2 not in text


def test_create_idempotent_and_secrets_untouched(roots):
    specs, secrets = roots
    before = _digest(secrets)
    r1 = pp.create_project(make_draft(), specs_root=specs, secrets_root=secrets)
    r2 = pp.create_project(make_draft(), specs_root=specs, secrets_root=secrets)
    assert r1["project_name"] == r2["project_name"] == "foo-service-maintenance-01234567"
    proj = os.path.join(specs, r1["project_name"])
    assert os.path.isfile(os.path.join(proj, "manual", "manual.md"))
    assert os.path.isfile(os.path.join(proj, "procedure.md"))
    assert _digest(secrets) == before
    for base, _, fs in os.walk(proj):
        for f in fs:
            t = open(os.path.join(base, f)).read()
            assert PW1 not in t and PW2 not in t


def test_replace_backs_up(roots):
    specs, secrets = roots
    name = pp.create_project(make_draft(), specs_root=specs, secrets_root=secrets)["project_name"]
    r = pp.create_project(make_draft(title="Foo service maintenance"), specs_root=specs, secrets_root=secrets, replace=True)
    assert r["project_name"] == name
    backups = os.listdir(os.path.join(specs, ".replaced"))
    assert len(backups) == 1 and backups[0].startswith(name + ".")
    assert not [n for n in os.listdir(specs) if n.startswith(".nrdp-")]


def test_missing_credential_refused(roots):
    specs, secrets = roots
    os.unlink(os.path.join(secrets, "procedure-x-hop-2.rdp.pw"))
    with pytest.raises(pp.ProjectError) as e:
        pp.create_project(make_draft(), specs_root=specs, secrets_root=secrets)
    assert "connections[1].credential" in [x["field"] for x in e.value.errors]
    assert os.listdir(specs) == []


def test_missing_certificate_refused(roots):
    specs, secrets = roots
    d = make_draft(); d.connections[0].certificate_fingerprint = None; d.connections[0].certificate_name = ""
    with pytest.raises(pp.ProjectError) as e:
        pp.create_project(d, specs_root=specs, secrets_root=secrets)
    fields = [x["field"] for x in e.value.errors]
    assert "connections[0].certificate.name" in fields and "connections[0].certificate.fingerprint" in fields


def test_no_hops_bad_host_port_user_and_too_many(roots):
    specs, secrets = roots
    with pytest.raises(pp.ProjectError) as e:
        pp.create_project(make_draft(connections=[]), specs_root=specs, secrets_root=secrets)
    assert e.value.errors[0]["field"] == "connections"
    d = make_draft(); d.connections[1].host = "bad host!"; d.connections[1].port = 0; d.connections[1].user = "a b"
    with pytest.raises(pp.ProjectError) as e:
        pp.create_project(d, specs_root=specs, secrets_root=secrets)
    f = {x["field"] for x in e.value.errors}
    assert {"connections[1].host", "connections[1].port", "connections[1].user"} <= f
    many = [NS(order=i + 1, host=f"10.0.0.{i+1}", port=3389, user="u", password_reference="procedure-x-hop-1.rdp.pw",
               certificate_name="C", certificate_fingerprint=FP) for i in range(9)]
    with pytest.raises(pp.ProjectError):
        pp.create_project(make_draft(connections=many), specs_root=specs, secrets_root=secrets)


def test_validate_chain_yaml_rejects_extra_allowlist():
    doc = yaml.safe_load(pp.render_project_files(make_draft())["project.yaml"])
    doc["rdp_host_allowlist"].append("172.20.33.215")
    assert any(e["field"] == "rdp_host_allowlist" for e in pp.validate_chain_yaml(doc))
    doc = yaml.safe_load(pp.render_project_files(make_draft())["project.yaml"])
    doc["target"]["chain"][1]["password"] = PW2
    assert any(e["field"].endswith(".password") for e in pp.validate_chain_yaml(doc))
