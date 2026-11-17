"""NRDP-1 S1b-1: project loader support for ``target.type: rdp-chain`` (fictional values only)."""
from __future__ import annotations

import json
import os

import pytest

try:
    from orchestrator import projects
    from orchestrator.projects import ChainProjectError, load_project_config
except ImportError:  # pragma: no cover - layout fallback
    from src.orchestrator import projects  # type: ignore
    from src.orchestrator.projects import ChainProjectError, load_project_config  # type: ignore

HOP1 = {
    "order": 1, "host": "10.0.0.11", "port": 3389, "user": "alpha", "password_file": "ref-one.secret",
    "certificate_name": "jump-box", "certificate_fingerprint": "sha256:" + "ab" * 32,
}
HOP2 = {"order": 2, "host": "192.0.2.22", "port": 3389, "user": "beta", "password_file": "ref-two.secret",
        "identity_policy": "stop"}
PROCEDURE = {"draft_id": "0" * 32, "final_hop": 2, "required_checkpoints": [],
             "steps": [{"order": 1, "title": "Check", "kind": "procedure-step", "mutating": False,
                        "read_only_ok": True, "instructions": "look", "completion_checks": []}]}


def _project(tmp_path, doc, *, as_json=True, name="proj"):
    root = tmp_path / "specs"
    pdir = root / name
    (pdir / "manual").mkdir(parents=True)
    (pdir / "manual" / "manual.md").write_text("# Manual\n", encoding="utf-8")
    doc = {"name": name, "manual_dir": "./manual", **doc}
    if as_json:
        text = json.dumps(doc, indent=2)
    else:
        import yaml
        text = yaml.safe_dump(doc)
    (pdir / "project.yaml").write_text(text, encoding="utf-8")
    return str(pdir), str(root)


def _chain_doc(chain=None, allow=None, **extra):
    chain = chain if chain is not None else [dict(HOP1), dict(HOP2)]
    doc = {
        "target": {"type": "rdp-chain", "chain": chain},
        "rdp_host_allowlist": allow if allow is not None else [chain[0]["host"]] if chain else [],
        "chain_hosts": [h["host"] for h in chain],
        "procedure": PROCEDURE,
    }
    doc.update(extra)
    return doc


def test_two_hop_chain_loads_in_order(tmp_path):
    pdir, root = _project(tmp_path, _chain_doc())
    cfg = load_project_config(pdir, specs_root=root)
    assert cfg.target.type == "rdp-chain"
    assert cfg.target.params == {}
    assert [h.order for h in cfg.target.hops] == [1, 2]
    assert [h.host for h in cfg.target.hops] == ["10.0.0.11", "192.0.2.22"]
    assert cfg.target.hops[1].password_file == "ref-two.secret"
    assert cfg.rdp_host_allowlist == ["10.0.0.11"]


def test_procedure_and_chain_hosts_carried(tmp_path):
    pdir, root = _project(tmp_path, _chain_doc())
    cfg = load_project_config(pdir, specs_root=root)
    assert cfg.procedure == PROCEDURE
    assert cfg.chain_hosts == ["10.0.0.11", "192.0.2.22"]


def test_hop2_host_in_allowlist_refused(tmp_path):
    pdir, root = _project(tmp_path, _chain_doc(allow=["10.0.0.11", "192.0.2.22"]))
    with pytest.raises(ChainProjectError, match="hop 2"):
        load_project_config(pdir, specs_root=root)


def test_allowlist_must_be_exactly_hop1(tmp_path):
    pdir, root = _project(tmp_path, _chain_doc(allow=["10.0.0.11", "198.51.100.9"]))
    with pytest.raises(ChainProjectError, match="exactly"):
        load_project_config(pdir, specs_root=root)


def test_missing_hop1_certificate_refused(tmp_path):
    hop1 = {k: v for k, v in HOP1.items() if k != "certificate_fingerprint"}
    pdir, root = _project(tmp_path, _chain_doc(chain=[hop1, dict(HOP2)]))
    with pytest.raises(ChainProjectError, match="certificate"):
        load_project_config(pdir, specs_root=root)


def test_more_than_eight_hops_refused(tmp_path):
    chain = [dict(HOP1)] + [
        {"order": i, "host": f"192.0.2.{i}", "user": "u", "password_file": f"r{i}.secret"} for i in range(2, 10)
    ]
    pdir, root = _project(tmp_path, _chain_doc(chain=chain))
    with pytest.raises(ChainProjectError, match="at most 8"):
        load_project_config(pdir, specs_root=root)


def test_unknown_hop_key_refused(tmp_path):
    hop2 = dict(HOP2, password="should-not-be-here")
    pdir, root = _project(tmp_path, _chain_doc(chain=[dict(HOP1), hop2]))
    with pytest.raises(ChainProjectError, match="unsupported keys") as info:
        load_project_config(pdir, specs_root=root)
    assert "should-not-be-here" not in str(info.value)


@pytest.mark.parametrize("ref", ["../etc/passwd", "/abs/path", "sub/dir.secret", ".hidden", ""])
def test_unsafe_password_reference_refused(tmp_path, ref):
    hop2 = dict(HOP2, password_file=ref)
    pdir, root = _project(tmp_path, _chain_doc(chain=[dict(HOP1), hop2]))
    with pytest.raises(ChainProjectError, match="password_file"):
        load_project_config(pdir, specs_root=root)


def test_chain_hosts_mismatch_refused(tmp_path):
    doc = _chain_doc()
    doc["chain_hosts"] = ["192.0.2.22", "10.0.0.11"]
    pdir, root = _project(tmp_path, doc)
    with pytest.raises(ChainProjectError, match="chain_hosts"):
        load_project_config(pdir, specs_root=root)


def test_invalid_chain_project_skipped_by_discovery_not_crash(tmp_path):
    pdir, root = _project(tmp_path, _chain_doc(allow=["10.0.0.11", "192.0.2.22"]))
    assert projects.discover_projects(root) == []


# ---------------------------------------------------------------- regressions (existing types)

REGRESSION = [
    ({"type": "rdp", "host": "h1", "user": "u", "password_file": "p.secret", "window": "w",
      "certificate_name": "c", "certificate_fingerprint": "sha256:" + "cd" * 32},
     {"host": "h1", "user": "u", "password_file": "p.secret", "window": "w",
      "certificate_name": "c", "certificate_fingerprint": "sha256:" + "cd" * 32}),
    ({"type": "vnc", "host": "h2", "port": 5901, "password_file": "v.secret", "window": "w",
      "route": {"type": "ssh-jump", "host": "j", "user": "ju", "port": 22, "known_hosts_file": "kh"}},
     {"host": "h2", "port": "5901", "password_file": "v.secret", "window": "w", "route_type": "ssh-jump",
      "jump_host": "j", "jump_user": "ju", "jump_port": "22", "jump_known_hosts_file": "kh"}),
    ({"type": "ssh-terminal", "host": "h3", "user": "u", "key": "k", "window": "w"},
     {"host": "h3", "user": "u", "key": "k", "window": "w"}),
    ({"type": "local-app", "app": "xterm", "window": "w"}, {"app": "xterm", "window": "w"}),
    ({"type": "host-app", "app": "a", "cwd": "/x", "window": "w", "startup_timeout": 30},
     {"app": "a", "cwd": "/x", "window": "w", "startup_timeout": "30"}),
]


@pytest.mark.parametrize("as_json", [True, False])
@pytest.mark.parametrize("target,expected", REGRESSION, ids=[t["type"] for t, _ in REGRESSION])
def test_existing_target_types_unchanged(tmp_path, target, expected, as_json):
    pdir, root = _project(tmp_path, {"target": target, "rdp_host_allowlist": ["h1"]}, as_json=as_json)
    cfg = load_project_config(pdir, specs_root=root)
    assert cfg.target.type == target["type"]
    assert cfg.target.params == expected
    assert cfg.target.hops == []
    assert cfg.procedure is None
    assert cfg.chain_hosts == []
    # Same serialised base shape as before plus only the two additive keys.
    dumped = cfg.model_dump()
    assert dumped["target"] == {"type": target["type"], "params": expected, "hops": []}
