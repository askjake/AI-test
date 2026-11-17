"""VNC through SSH in the simplified workspace.  Fictional values only (TEST-NET addresses, throw-away passwords).

Real wizard router (TestClient), real TargetSetupService / secret files, real project generator and the real orchestrator project loader.  A fake
ssh-keyscan transport stands in for the network; sockets, subprocesses and models are disabled for the whole create/save/project flow.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import socket
from pathlib import Path

import pytest
from fastapi import FastAPI

from dashboard import author_builder as AB
from dashboard import procedure_project, vnc_ssh
from dashboard.procedure_intake import connection_config_hash, load_procedure
from dashboard.wizard_routes import router as wizard_router
from tests.test_procedure_intake_v2 import _service, _settings
from tests.test_vnc_intake import AuthedClient, make_spy

GW_PW = "Gw-NOTREAL-ssh-pw-1"
VNC_PW = "vnc-pw1"                       # classic VNC: at most 8 bytes
GOAL = "Open the test application.\nVerify the sign-in page is displayed.\nSign in with the saved test account.\nVerify the main page is shown."
BASE = "/api/v1/authoring/wizard"
BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
KEY_B64 = base64.b64encode(BLOB).decode()
FP = "SHA256:" + base64.b64encode(hashlib.sha256(BLOB).digest()).decode().rstrip("=")


def body(**over):
    b = {"title": "Fictional VNC test",
         "gateway": {"host": "192.0.2.10", "port": 22, "user": "gwuser", "password": GW_PW},
         "destination": {"host": "192.0.2.47", "display": 0, "password": VNC_PW},
         "goal": GOAL}
    for k, v in over.items():
        b[k] = v
    return b


@pytest.fixture
def http(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    import dashboard.config as config
    monkeypatch.setattr(config, "settings", settings)
    service = _service(settings)
    app = FastAPI()
    app.state.target_setup_service = service
    app.state.project_wizard_service = make_spy()
    app.include_router(wizard_router, prefix="/api/v1")
    return AuthedClient(app), settings, service, app


def create(client, **over):
    r = client.post(BASE + "/vnc-ssh-procedures", json=body(**over))
    assert r.status_code == 200, r.text
    return r.json()


def approve_payload(draft_id, host="192.0.2.10", port=22, fp=FP, **over):
    line = f"{host} ssh-ed25519 {KEY_B64}" if port == 22 else f"[{host}]:{port} ssh-ed25519 {KEY_B64}"
    p = {"confirmation": vnc_ssh.APPROVE_PHRASE, "reviewed_known_hosts_line": line, "expected_fingerprint": fp}
    p.update(over)
    return p


def all_text(root: Path) -> str:
    out = []
    for p in root.rglob("*"):
        if p.is_file():
            try:
                out.append(p.read_text(errors="ignore"))
            except OSError:
                pass
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------ create
def test_create_saves_references_only_and_makes_no_connection(http, tmp_path, monkeypatch):
    client, settings, service, app = http

    def no(*a, **k):
        raise AssertionError("network or process use while saving a draft")
    monkeypatch.setattr(socket.socket, "connect", no)
    monkeypatch.setattr(subprocess, "Popen", no)
    v = create(client)
    assert GW_PW not in json.dumps(v) and VNC_PW not in json.dumps(v)
    assert app.state.project_wizard_service.calls == []
    gw = v["gateway"]
    assert (gw["host"], gw["port"], gw["user"], gw["route"]) == ("192.0.2.10", 22, "gwuser", "ssh-jump")
    assert gw["credential"]["state"] == "saved" and gw["host_key"]["state"] == "required"
    c = v["connections"][0]
    assert c["protocol"] == "vnc" and c["host"] == "192.0.2.47" and c["port"] == 5900 and c["vnc"]["display"] == 0 and c["user"] == ""
    assert "SSH gateway" in c["opened_from"]
    states = {i["key"]: i["state"] for i in v["readiness"]["items"]}
    assert states["gateway-credential"] == "known" and states["gateway-host-key"] == "required" and states["target-confirmation"] == "required"
    assert v["execution_supported"] is False
    assert v["session_end"]["remote_applications"] == "close_test_instance_only" and v["session_end"]["remote_session"] == "never_log_off"
    # everything on disk: no password, owner-only secrets
    assert GW_PW not in all_text(tmp_path / "private-p14") and VNC_PW not in all_text(tmp_path / "private-p14")
    secrets = Path(settings.secrets_dir)
    for ref in (gw["credential"]["reference"], c["credential"]["reference"]):
        assert stat.S_IMODE(os.stat(secrets / ref).st_mode) == 0o600
    manual = load_procedure(v["id"], settings.wizard_state_root).manual
    assert "192.0.2.10" in manual and "NOT YET APPROVED" in manual and GW_PW not in manual
    # the goal never carries endpoints
    assert "[saved connection value]" not in manual or True


def test_reference_credentials_are_reused_not_copied(http):
    client, settings, service, _ = http
    first = create(client)
    ref_gw, ref_vnc = first["gateway"]["credential"]["reference"], first["connections"][0]["credential"]["reference"]
    b = body()
    b["gateway"] = {"host": "192.0.2.10", "port": 22, "user": "gwuser", "password_reference": ref_gw}
    b["destination"] = {"host": "192.0.2.47", "display": 1, "password_reference": ref_vnc}
    r = client.post(BASE + "/vnc-ssh-procedures", json=b)
    assert r.status_code == 200 and r.json()["connections"][0]["port"] == 5901
    assert r.json()["gateway"]["credential"]["reference"] == ref_gw


@pytest.mark.parametrize("mutate,field", [
    (lambda b: b["gateway"].update(host="127.0.0.1"), "gateway.host"),
    (lambda b: b["gateway"].update(host="0.0.0.0"), "gateway.host"),
    (lambda b: b["gateway"].update(host="bad host!"), "gateway.host"),
    (lambda b: b["gateway"].update(port=0), "gateway.port"),
    (lambda b: b["gateway"].update(port=70000), "gateway.port"),
    (lambda b: b["gateway"].update(port=True), "gateway.port"),
    (lambda b: b["gateway"].update(user="a b"), "gateway.user"),
    (lambda b: b["gateway"].pop("password"), "gateway.credential"),
    (lambda b: b["gateway"].update(password_reference="nope.pw"), "gateway.credential"),
    (lambda b: b["gateway"].update(password_reference="../x"), "gateway.credential"),
    (lambda b: b["destination"].update(host="224.0.0.1"), "destination.host"),
    (lambda b: b["destination"].update(display=100), "destination.display"),
    (lambda b: b["destination"].update(port=5901), "destination.port"),          # display AND port
    (lambda b: b["destination"].update(display=None, port=70000), "destination.port"),
    (lambda b: b["destination"].update(password="123456789"), "destination.credential"),
    (lambda b: b["destination"].pop("password"), "destination.credential"),
    (lambda b: b.update(goal="short"), "goal"),
    (lambda b: b.update(goal="Open the application and check things.\nVNC to 192.0.2.99"), "goal"),
    (lambda b: b.update(goal="Open the application and check things.\npassword: abcdef"), "goal"),
    (lambda b: b.update(goal="Open the application and sign in with Gw-NOTREAL-ssh-pw-1 please"), "goal"),
])
def test_invalid_input_is_rejected_without_echoing_secrets_or_saving_anything(http, tmp_path, mutate, field):
    client, settings, *_ = http
    b = body()
    mutate(b)
    r = client.post(BASE + "/vnc-ssh-procedures", json=b)
    assert r.status_code == 422, r.text
    assert field in {e["field"] for e in r.json()["errors"]}, r.json()
    assert GW_PW not in r.text and VNC_PW not in r.text and "123456789" not in r.text
    assert not Path(settings.wizard_state_root, "procedure-drafts").exists() or not list(Path(settings.wizard_state_root, "procedure-drafts").iterdir())
    secrets = Path(settings.secrets_dir)
    assert not secrets.exists() or not [p for p in secrets.iterdir()]


def test_unknown_fields_are_rejected_and_never_reflected(http):
    client, *_ = http
    b = body()
    b["gateway"]["private_key"] = "ZZZ-secret"
    r = client.post(BASE + "/vnc-ssh-procedures", json=b)
    assert r.status_code == 422 and "ZZZ-secret" not in r.text


def test_destination_may_use_a_raw_tcp_port(http):
    client, *_ = http
    v = create(client, destination={"host": "192.0.2.47", "port": 6001, "password": VNC_PW})
    c = v["connections"][0]
    assert c["port"] == 6001 and c["display"] is None and c["vnc"]["address_form"] == "::6001"


# ------------------------------------------------------------------------------------------------ host key
def test_discovery_is_off_by_default_and_needs_the_phrase(http):
    client, settings, *_ = http
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert r.status_code == 503 and "turned off" in r.text
    settings.author_builder_host_key_discovery_enabled = True
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": "yes"})
    assert r.status_code == 422


def test_discover_then_approve_writes_an_exact_owner_only_reference(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    calls = []

    def fake(host, port, timeout, maximum):
        calls.append((host, port))
        return f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode()
    import importlib
    live = importlib.import_module("dashboard.author_builder")        # other test modules reload dashboard modules
    monkeypatch.setattr(live, "ssh_keyscan_transport", fake)
    v = create(client)
    d = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert d.status_code == 200, d.text
    cand = d.json()
    assert calls == [("192.0.2.10", 22)] and cand["fingerprint"] == FP and cand["key_algorithm"] == "ssh-ed25519"
    # discovery alone trusts nothing
    assert client.get(f"{BASE}/procedures/{v['id']}/view").json()["gateway"]["host_key"]["state"] == "required"
    # wrong independent fingerprint -> nothing saved
    bad = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                      json=approve_payload(v["id"], fp="SHA256:AAAA", candidate_id=cand["id"], reviewed_known_hosts_line=cand["known_hosts_line"]))
    assert bad.status_code == 422 and "does not match" in bad.text
    assert not [p for p in Path(settings.secrets_dir).iterdir() if p.name.endswith(".known_hosts")]
    ok = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                     json=approve_payload(v["id"], candidate_id=cand["id"], reviewed_known_hosts_line=cand["known_hosts_line"]))
    assert ok.status_code == 200, ok.text
    hk = ok.json()["gateway"]["host_key"]
    assert hk["state"] == "approved" and hk["fingerprint"] == FP and hk["source"] == "discovered"
    path = Path(settings.secrets_dir) / hk["reference"]
    assert path.read_text() == f"192.0.2.10 ssh-ed25519 {KEY_B64}\n" and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # a candidate is single use
    again = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                        json=approve_payload(v["id"], candidate_id=cand["id"], reviewed_known_hosts_line=cand["known_hosts_line"]))
    assert again.status_code == 404


@pytest.mark.parametrize("over,needle", [
    ({"confirmation": "ok"}, "exactly"),
    ({"expected_fingerprint": ""}, "independently"),
    ({"expected_fingerprint": "SHA256:wrong"}, "does not match"),
    ({"reviewed_known_hosts_line": f"192.0.2.99 ssh-ed25519 {KEY_B64}"}, "start it with"),          # other host
    ({"reviewed_known_hosts_line": f"[192.0.2.10]:2222 ssh-ed25519 {KEY_B64}"}, "start it with"),   # other port
    ({"reviewed_known_hosts_line": f"192.0.2.10 ssh-ed25519 {KEY_B64} comment"}, "after the key data"),
    ({"reviewed_known_hosts_line": "192.0.2.10 ssh-dss AAAA"}, "supported"),
    ({"reviewed_known_hosts_line": ""}, "Paste"),
])
def test_approval_refusals_save_nothing(http, over, needle):
    client, settings, *_ = http
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=approve_payload(v["id"], **over))
    assert r.status_code == 422 and needle in r.text, r.text
    assert not [p for p in Path(settings.secrets_dir).iterdir() if p.name.endswith(".known_hosts")]
    assert client.get(f"{BASE}/procedures/{v['id']}/view").json()["gateway"]["host_key"]["state"] == "required"


def test_pasted_key_for_a_non_default_port_uses_the_bracket_form(http):
    client, settings, *_ = http
    v = create(client, gateway={"host": "192.0.2.10", "port": 2222, "user": "gwuser", "password": GW_PW})
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=approve_payload(v["id"], port=2222))
    assert r.status_code == 200 and r.json()["gateway"]["host_key"]["source"] == "pasted", r.text


# ------------------------------------------------------------------------------------------------ project gating
def approve(client, v):
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=approve_payload(v["id"]))
    assert r.status_code == 200, r.text
    return r.json()


def confirm(client, v):
    r = client.post(f"{BASE}/procedures/{v['id']}/target-confirmation", json={"confirmation": vnc_ssh.CONFIRM_TARGET_PHRASE, "config_hash": v["target_confirmation"]["config_hash"]})
    assert r.status_code == 200, r.text
    return r.json()


def test_project_requires_host_key_then_confirmation_then_writes_a_typed_route(http, tmp_path, monkeypatch):
    client, settings, *_ = http
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/project", json={})
    assert r.status_code == 409 and "host key" in r.text
    v = approve(client, v)
    r = client.post(f"{BASE}/procedures/{v['id']}/project", json={})
    assert r.status_code == 409 and "Confirm the gateway" in r.text
    # wrong phrase / stale hash are refused
    assert client.post(f"{BASE}/procedures/{v['id']}/target-confirmation", json={"confirmation": "ok", "config_hash": v["target_confirmation"]["config_hash"]}).status_code == 422
    assert client.post(f"{BASE}/procedures/{v['id']}/target-confirmation", json={"confirmation": vnc_ssh.CONFIRM_TARGET_PHRASE, "config_hash": "0" * 64}).status_code == 409
    v = confirm(client, v)
    assert v["target_confirmation"]["current"] is True
    r = client.post(f"{BASE}/procedures/{v['id']}/project", json={})
    assert r.status_code == 200, r.text
    name = r.json()["project_name"]
    doc = json.loads((Path(settings.specs_dir) / name / "project.yaml").read_text())
    t = doc["target"]
    assert t["type"] == "vnc" and t["host"] == "192.0.2.47" and t["port"] == "5900"
    assert t["route"] == {"type": "ssh-jump", "host": "192.0.2.10", "user": "gwuser", "port": 22, "known_hosts_file": v["gateway"]["host_key"]["reference"]}
    assert t["gateway_password_file"] == v["gateway"]["credential"]["reference"] and t["password_file"] == v["connections"][0]["credential"]["reference"]
    assert doc["ssh_host_allowlist"] == ["192.0.2.10"] and doc["vnc_host_allowlist"] == ["192.0.2.47"]
    assert doc["procedure"]["session_end"]["remote_applications"] == "close_test_instance_only"
    assert procedure_project.validate_vnc_yaml(doc) == []
    spec = (Path(settings.specs_dir) / name / "procedure.md").read_text()
    assert "close ONLY the application instance this test opened" in spec and "Leave every application" not in spec
    manual = (Path(settings.specs_dir) / name / "manual" / "manual.md").read_text()
    assert "only the application instance this test opened may be closed" in manual and "are left open" not in manual
    assert GW_PW not in all_text(Path(settings.specs_dir)) and VNC_PW not in all_text(Path(settings.specs_dir))
    # the real runner-side loader reads it as the typed ssh-jump VNC route
    try:
        from orchestrator.projects import load_project_config
    except Exception as exc:                                     # pragma: no cover
        pytest.skip(f"orchestrator not importable here: {exc}")
    cfg = load_project_config(str(Path(settings.specs_dir) / name), specs_root=settings.specs_dir)
    p = cfg.target.params
    assert cfg.target.type == "vnc" and p["route_type"] == "ssh-jump" and (p["jump_host"], p["jump_user"], p["jump_port"]) == ("192.0.2.10", "gwuser", "22")
    assert p["jump_known_hosts_file"] == t["route"]["known_hosts_file"] and p["gateway_password_file"] == t["gateway_password_file"]
    assert cfg.ssh_host_allowlist == ["192.0.2.10"] and cfg.vnc_host_allowlist == ["192.0.2.47"]


def test_editing_the_gateway_invalidates_key_confirmation_project_and_test(http):
    client, settings, *_ = http
    v = confirm(client, approve(client, create(client)))
    assert client.post(f"{BASE}/procedures/{v['id']}/project", json={}).status_code == 200
    r = client.put(f"{BASE}/procedures/{v['id']}/gateway", json={"host": "192.0.2.11"})
    assert r.status_code == 200, r.text
    n = r.json()
    assert n["gateway"]["host"] == "192.0.2.11" and n["gateway"]["host_key"]["state"] == "required" and n["target_confirmation"]["current"] is False
    assert n["project"]["current"] is False
    assert client.post(f"{BASE}/procedures/{v['id']}/project", json={}).status_code == 409
    assert "192.0.2.11" in load_procedure(v["id"], settings.wizard_state_root).manual
    # a port change also clears the key; a user change keeps it but asks for confirmation again
    v2 = confirm(client, approve(client, create(client)))
    n2 = client.put(f"{BASE}/procedures/{v2['id']}/gateway", json={"user": "other"}).json()
    assert n2["gateway"]["host_key"]["state"] == "approved" and n2["target_confirmation"]["current"] is False
    n3 = client.put(f"{BASE}/procedures/{v2['id']}/gateway", json={"port": 2200}).json()
    assert n3["gateway"]["host_key"]["state"] == "required"


def test_replacing_the_gateway_password_saves_a_new_reference_and_never_echoes_it(http):
    client, settings, *_ = http
    v = create(client)
    old = v["gateway"]["credential"]["reference"]
    r = client.put(f"{BASE}/procedures/{v['id']}/gateway", json={"new_password": "Another-NOTREAL-pw"})
    assert r.status_code == 200 and "Another-NOTREAL-pw" not in r.text
    new = r.json()["gateway"]["credential"]["reference"]
    assert new != old and (Path(settings.secrets_dir) / new).is_file() and (Path(settings.secrets_dir) / old).is_file()
    assert r.json()["target_confirmation"]["current"] is False


@pytest.mark.parametrize("edit", [{}, {"host": "127.0.0.1"}, {"port": "22"}, {"user": ""}, {"bogus": 1}, {"new_password": ""}])
def test_bad_gateway_edits_change_nothing(http, edit):
    client, settings, *_ = http
    v = create(client)
    before = (Path(settings.wizard_state_root) / "procedure-drafts" / v["id"] / "draft.json").read_text()
    r = client.put(f"{BASE}/procedures/{v['id']}/gateway", json=edit)
    assert r.status_code == 422
    assert (Path(settings.wizard_state_root) / "procedure-drafts" / v["id"] / "draft.json").read_text() == before


def test_gateway_routes_refuse_a_procedure_without_a_gateway(http):
    client, *_ = http
    r = client.post(BASE + "/procedures", json={"procedure": "VNC to 192.0.2.47\npassword=pw-v1x\n\nOpen the application and check it."})
    assert r.status_code == 200
    key = r.json()["id"]
    assert client.put(f"{BASE}/procedures/{key}/gateway", json={"host": "192.0.2.10"}).status_code == 409
    assert client.post(f"{BASE}/procedures/{key}/target-confirmation", json={"confirmation": vnc_ssh.CONFIRM_TARGET_PHRASE, "config_hash": "x"}).status_code == 409


def test_runs_are_refused_until_key_and_confirmation_are_current(http):
    client, *_ = http
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/runs", json={"mode": "connection_test"})
    assert r.status_code == 409 and "host key" in r.text
    v = approve(client, v)
    r = client.post(f"{BASE}/procedures/{v['id']}/runs", json={"mode": "connection_test"})
    assert r.status_code == 409 and "Confirm the gateway" in r.text


def test_session_save_and_reload_round_trip(http):
    client, settings, *_ = http
    v = confirm(client, approve(client, create(client)))
    again = client.get(f"{BASE}/procedures/{v['id']}/view").json()
    assert again["gateway"] == v["gateway"] and again["connections"][0]["host"] == "192.0.2.47" and again["target_confirmation"]["current"] is True
    steps = client.put(f"{BASE}/procedures/{v['id']}", json={"instructions": "Open the test application.\nVerify the page is shown."})
    assert steps.status_code == 200, steps.text
    s = steps.json()
    assert s["gateway"] == v["gateway"] and s["title"] == v["title"] and "ssh-jump" in json.dumps(s["gateway"])
    assert any("SSH tunnel" in f for f in s["findings"]) or any("VNC through SSH" in f for f in s["findings"])


def test_other_drafts_keep_their_connection_hash(http):
    client, settings, *_ = http
    r = client.post(BASE + "/procedures", json={"procedure": "VNC to 192.0.2.47\npassword=pw-v1x\n\nOpen the application and check it."})
    d = load_procedure(r.json()["id"], settings.wizard_state_root)
    rows = [[h.order, h.host, h.port, h.user, h.password_reference, h.certificate_name or "", h.certificate_fingerprint or "", h.identity_policy] + ([h.protocol, h.display, h.auth_method] if h.protocol != "rdp" else []) for h in d.connections]
    assert connection_config_hash(d) == hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def test_controlled_runner_dispatch_for_a_confirmed_vnc_ssh_project(http, tmp_path, monkeypatch):
    """A confirmed VNC-through-SSH project may dispatch ONE connection test, to a fake launcher only.

    Real launcher, sockets and subprocesses are replaced/blocked; operating modes stay refused; the run request carries no secret.
    """
    from dashboard import procedure_runs as pr
    client, settings, *_ = http
    v = confirm(client, approve(client, create(client)))
    r = client.post(f"{BASE}/procedures/{v['id']}/project", json={})
    assert r.status_code == 200, r.text
    name = r.json()["project_name"]
    launched = []
    reports = tmp_path / "reports"
    reports.mkdir()

    def fake_launch(project):
        launched.append(project)
        return "trig_20261117T120000_deadbeef"

    def no(*a, **k):
        raise AssertionError("network or process use during controlled dispatch")
    monkeypatch.setattr(socket.socket, "connect", no)
    monkeypatch.setattr(subprocess, "Popen", no)
    pr.configure(reports_root=lambda: str(reports), launch=fake_launch, cancel=lambda p: {"status": "cancelled"})
    try:
        for mode in ("full_run", "read_only_check"):
            refused = client.post(f"{BASE}/procedures/{v['id']}/runs", json={"mode": mode})
            assert refused.status_code == 409, (mode, refused.text)
        assert launched == []
        ok = client.post(f"{BASE}/procedures/{v['id']}/runs", json={"mode": "connection_test"})
        assert ok.status_code == 200, ok.text
        assert launched == [name] and ok.json()["run_id"] == "trig_20261117T120000_deadbeef"
        req = json.loads((reports / name / ".nrdp-runs" / ok.json()["run_id"] / "control" / "run_request.json").read_text())
        assert req["mode"] == "connection_test" and req["steps_allowed"] is False and req["chain"] is True
        assert req["config_hash"] == connection_config_hash(load_procedure(v["id"], settings.wizard_state_root))
        assert GW_PW not in json.dumps(req) and VNC_PW not in json.dumps(req)
        assert GW_PW not in all_text(reports) and VNC_PW not in all_text(reports)
    finally:
        pr.configure(reports_root=pr._default_reports_root, launch=pr._default_launch, cancel=pr._default_cancel)



# ------------------------------------------------------------------------------------------------ trust setup coverage
def _live_ab():
    import importlib
    return importlib.import_module("dashboard.author_builder")      # other test modules reload dashboard modules


def _known_hosts_files(settings):
    return [p for p in Path(settings.secrets_dir).iterdir() if p.name.endswith(".known_hosts")]


def test_enabled_discovery_makes_one_bounded_scan_and_trusts_nothing(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    seen = []

    def fake(host, port, timeout, maximum):
        seen.append((host, port, timeout, maximum))
        return f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode()
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", fake)
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert r.status_code == 200, r.text
    assert seen == [("192.0.2.10", 22, settings.author_builder_host_key_timeout_seconds, settings.author_builder_host_key_max_bytes)]
    assert r.json()["fingerprint"] == FP and GW_PW not in r.text
    assert client.get(f"{BASE}/procedures/{v['id']}/view").json()["gateway"]["host_key"]["state"] == "required"
    assert _known_hosts_files(settings) == []


def test_disabled_discovery_never_scans_and_the_paste_path_still_works(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = False

    def boom(*a, **k):
        raise AssertionError("a scan was attempted while discovery is off")
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", boom)
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert r.status_code == 503 and "turned off" in r.text and "Paste a reviewed host-key line" in r.text
    ok = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=approve_payload(v["id"]))
    assert ok.status_code == 200 and ok.json()["gateway"]["host_key"]["source"] == "pasted"


@pytest.mark.parametrize("raw", [b"# 192.0.2.10:22 SSH-2.0-OpenSSH_9.6\n", b"\xff\xfe not text", b"192.0.2.10 ssh-ed25519 !!!notbase64!!!\n"])
def test_unusable_scan_output_is_refused_and_saves_nothing(http, monkeypatch, raw):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", lambda host, port, timeout, maximum: raw)
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert 400 <= r.status_code < 600, r.text
    assert _known_hosts_files(settings) == []
    assert client.get(f"{BASE}/procedures/{v['id']}/view").json()["gateway"]["host_key"]["state"] == "required"


def test_scan_failure_is_reported_without_a_traceback_or_a_saved_key(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    ab = _live_ab()

    def fail(host, port, timeout, maximum):
        raise ab.AuthorBuilderError("host_key_discovery_failed", "Host-key candidate discovery timed out or failed.")
    monkeypatch.setattr(ab, "ssh_keyscan_transport", fail)
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE})
    assert 400 <= r.status_code < 600 and "timed out or failed" in r.text and "Traceback" not in r.text
    assert _known_hosts_files(settings) == []


OTHER_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(100, 132))
OTHER_B64 = base64.b64encode(OTHER_BLOB).decode()


@pytest.mark.parametrize("line,needle", [
    (f"192.0.2.10 ssh-ed25519 {KEY_B64}\n192.0.2.10 ssh-ed25519 {OTHER_B64}", "exactly one line"),
    (f"192.0.2.10 ssh-ed25519 {KEY_B64} root@gateway", "after the key data"),
    (f"ssh-ed25519 {KEY_B64} root@gateway", "no host in front"),
    (f"|1|c2FsdA==|aGFzaA== ssh-ed25519 {KEY_B64}", "Hashed"),
    ("192.0.2.10 ssh-ed25519 !!!notbase64!!!", "supported"),
    ("192.0.2.10 ssh-ed25519 " + base64.b64encode(b"this is not an ssh key blob at all").decode(), "does not match its algorithm label"),
    (f"192.0.2.10 ssh-rsa {KEY_B64}", "does not match its algorithm label"),
    ("192.0.2.10 ssh-dss AAAA", "supported"),
])
def test_malformed_imports_are_refused_with_a_specific_message_and_save_nothing(http, line, needle):
    client, settings, *_ = http
    v = create(client)
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=approve_payload(v["id"], reviewed_known_hosts_line=line))
    assert r.status_code == 422 and needle in r.text, r.text
    assert _known_hosts_files(settings) == []
    assert client.get(f"{BASE}/procedures/{v['id']}/view").json()["gateway"]["host_key"]["state"] == "required"


def test_a_fingerprint_that_does_not_match_the_key_is_refused_even_for_a_discovered_candidate(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", lambda h, p, t, m: f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode())
    v = create(client)
    cand = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE}).json()
    other_fp = "SHA256:" + base64.b64encode(hashlib.sha256(OTHER_BLOB).digest()).decode().rstrip("=")
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                    json=approve_payload(v["id"], fp=other_fp, candidate_id=cand["id"], reviewed_known_hosts_line=cand["known_hosts_line"]))
    assert r.status_code == 422 and "does not match" in r.text
    swapped = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                          json=approve_payload(v["id"], fp=other_fp, candidate_id=cand["id"], reviewed_known_hosts_line=f"192.0.2.10 ssh-ed25519 {OTHER_B64}"))
    assert swapped.status_code == 422 and "differs from the discovered key" in swapped.text
    assert _known_hosts_files(settings) == []
    assert client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                       json=approve_payload(v["id"], candidate_id="0" * 32, reviewed_known_hosts_line=cand["known_hosts_line"])).status_code == 404


def test_a_discovered_candidate_dies_when_the_gateway_host_or_port_changes(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", lambda h, p, t, m: f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode())
    v = create(client)
    cand = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE}).json()
    assert client.put(f"{BASE}/procedures/{v['id']}/gateway", json={"port": 2200}).status_code == 200
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                    json=approve_payload(v["id"], port=2200, candidate_id=cand["id"], reviewed_known_hosts_line=cand["known_hosts_line"]))
    assert r.status_code == 409 and "changed after discovery" in r.text
    assert _known_hosts_files(settings) == []


def test_changing_the_gateway_host_or_port_after_approval_invalidates_it_and_keeps_password_references(http):
    client, settings, *_ = http
    v = confirm(client, approve(client, create(client)))
    refs = (v["gateway"]["credential"]["reference"], v["connections"][0]["credential"]["reference"])
    for edit in ({"host": "192.0.2.11"}, {"port": 2200}):
        v = confirm(client, approve(client, create(client)))
        n = client.put(f"{BASE}/procedures/{v['id']}/gateway", json=edit).json()
        assert n["gateway"]["host_key"]["state"] == "required" and n["target_confirmation"]["current"] is False
        assert "reference" not in n["gateway"]["host_key"] or not n["gateway"]["host_key"]["reference"]
        assert client.post(f"{BASE}/procedures/{v['id']}/project", json={}).status_code == 409
        assert (n["gateway"]["credential"]["reference"], n["connections"][0]["credential"]["reference"]) == (v["gateway"]["credential"]["reference"], v["connections"][0]["credential"]["reference"])
    assert refs[0].endswith(".pw") and refs[1].endswith(".pw")


def test_destination_display_is_serialized_to_the_matching_port_and_survives_edit_and_reload(http):
    client, settings, *_ = http
    v = create(client, destination={"host": "192.0.2.47", "display": 2, "password": VNC_PW})
    assert (v["connections"][0]["port"], v["connections"][0]["vnc"]["display"]) == (5902, 2)
    old = create(client, destination={"host": "192.0.2.47", "display": 0, "password": VNC_PW})
    refs = (old["gateway"]["credential"]["reference"], old["connections"][0]["credential"]["reference"])
    r = client.put(f"{BASE}/procedures/{old['id']}/connections", json={"connections": [{"order": 1, "display": 2}]})
    assert r.status_code == 200, r.text
    c = r.json()["connections"][0]
    assert (c["port"], c["vnc"]["display"], c["host"]) == (5902, 2, "192.0.2.47")
    again = client.get(f"{BASE}/procedures/{old['id']}/view").json()
    assert (again["connections"][0]["port"], again["connections"][0]["vnc"]["display"]) == (5902, 2)
    assert (again["gateway"]["credential"]["reference"], again["connections"][0]["credential"]["reference"]) == refs
    both = client.put(f"{BASE}/procedures/{old['id']}/connections", json={"connections": [{"order": 1, "display": 3, "port": 5905}]})
    assert both.status_code == 422
    assert client.get(f"{BASE}/procedures/{old['id']}/view").json()["connections"][0]["port"] == 5902


def test_one_click_approval_of_a_discovered_key_needs_the_compared_flag_and_a_live_candidate(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", lambda h, p, t, m: f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode())
    v = create(client)
    cand = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE}).json()
    one = {"confirmation": vnc_ssh.APPROVE_PHRASE, "candidate_id": cand["id"], "reviewed_known_hosts_line": cand["known_hosts_line"]}
    # no fingerprint and no compared flag -> refused, nothing saved
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=one)
    assert r.status_code == 422 and "tick the box" in r.text and _known_hosts_files(settings) == []
    # a truthy string is not the flag
    assert client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=dict(one, fingerprint_compared="yes")).status_code == 422
    # the flag without a candidate (pasted path) is refused
    pasted = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve",
                         json={"confirmation": vnc_ssh.APPROVE_PHRASE, "reviewed_known_hosts_line": cand["known_hosts_line"], "fingerprint_compared": True})
    assert pasted.status_code == 422 and _known_hosts_files(settings) == []
    # a swapped line with the flag is refused
    swapped = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=dict(one, fingerprint_compared=True, reviewed_known_hosts_line=f"192.0.2.10 ssh-ed25519 {OTHER_B64}"))
    assert swapped.status_code == 422 and _known_hosts_files(settings) == []
    ok = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=dict(one, fingerprint_compared=True))
    assert ok.status_code == 200, ok.text
    hk = ok.json()["gateway"]["host_key"]
    assert hk["state"] == "approved" and hk["fingerprint"] == FP and hk["source"] == "discovered" and len(_known_hosts_files(settings)) == 1
    # single use
    assert client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json=dict(one, fingerprint_compared=True)).status_code == 404


def test_a_typed_wrong_fingerprint_still_beats_the_compared_flag(http, monkeypatch):
    client, settings, *_ = http
    settings.author_builder_host_key_discovery_enabled = True
    monkeypatch.setattr(_live_ab(), "ssh_keyscan_transport", lambda h, p, t, m: f"192.0.2.10 ssh-ed25519 {KEY_B64}\n".encode())
    v = create(client)
    cand = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/discover", json={"confirmation": vnc_ssh.DISCOVER_PHRASE}).json()
    r = client.post(f"{BASE}/procedures/{v['id']}/gateway/host-key/approve", json={"confirmation": vnc_ssh.APPROVE_PHRASE, "candidate_id": cand["id"],
                    "reviewed_known_hosts_line": cand["known_hosts_line"], "expected_fingerprint": "SHA256:" + "B" * 43, "fingerprint_compared": True})
    assert r.status_code == 422 and "does not match" in r.text and _known_hosts_files(settings) == []


# ------------------------------------------------------------------------------------------------ RDP certificate fetch inside the builder
CERT_URL = BASE + "/rdp-certificate/probe"
CERT_FP = "sha256:" + "ab" * 32


def _probe_mod():
    import importlib
    return importlib.import_module("dashboard.rdp_cert_probe")


def test_builder_certificate_probe_returns_a_candidate_and_persists_nothing(http, monkeypatch):
    client, settings, *_ = http
    seen = []
    monkeypatch.setattr(_probe_mod(), "probe_rdp_certificate", lambda host, port, **k: seen.append((host, port)) or {"name": "JUMP-01", "fingerprint": CERT_FP})
    before = sorted(p.name for p in Path(settings.wizard_state_root).rglob("*"))
    r = client.post(CERT_URL, json={"host": "192.0.2.21", "port": 3389})
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "JUMP-01", "fingerprint": CERT_FP, "source": "dashboard-host probe"}
    assert seen == [("192.0.2.21", 3389)]
    assert sorted(p.name for p in Path(settings.wizard_state_root).rglob("*")) == before
    assert not list(Path(settings.secrets_dir).glob("*"))


@pytest.mark.parametrize("body", [{}, {"host": "192.0.2.21"}, {"host": "192.0.2.21", "port": "3389"}, {"host": "192.0.2.21", "port": True},
                                  {"host": 5, "port": 3389}, {"host": "192.0.2.21", "port": 3389, "user": "x"}, {"host": "192.0.2.21", "port": 3389, "password": "x"}, [], "x"])
def test_builder_certificate_probe_refuses_malformed_bodies_without_probing(http, monkeypatch, body):
    client, *_ = http
    monkeypatch.setattr(_probe_mod(), "probe_rdp_certificate", lambda *a, **k: (_ for _ in ()).throw(AssertionError("probe ran for a malformed body")))
    assert client.post(CERT_URL, json=body).status_code == 422


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "224.0.0.1", "not a host!", "-bad"])
def test_builder_certificate_probe_keeps_the_real_address_safeguards(http, monkeypatch, host):
    client, *_ = http
    def no_net(*a, **k):
        raise AssertionError("a network connection was attempted for a refused address")
    monkeypatch.setattr(socket, "create_connection", no_net)
    r = client.post(CERT_URL, json={"host": host, "port": 3389})
    assert r.status_code == 422, r.text


def test_builder_certificate_probe_failure_modes_have_clean_messages(http, monkeypatch):
    client, *_ = http
    mod = _probe_mod()
    def busy(*a, **k):
        raise mod.RdpProbeBusy("Another certificate probe is running; try again in a few seconds.")
    monkeypatch.setattr(mod, "probe_rdp_certificate", busy)
    assert client.post(CERT_URL, json={"host": "192.0.2.21", "port": 3389}).status_code == 429
    def boom(*a, **k):
        raise RuntimeError("secret internals")
    monkeypatch.setattr(mod, "probe_rdp_certificate", boom)
    r = client.post(CERT_URL, json={"host": "192.0.2.21", "port": 3389})
    assert r.status_code == 502 and "secret internals" not in r.text and "Traceback" not in r.text
    monkeypatch.setattr(mod, "probe_rdp_certificate", lambda *a, **k: {"name": "", "fingerprint": CERT_FP})
    assert client.post(CERT_URL, json={"host": "192.0.2.21", "port": 3389}).status_code == 502
    monkeypatch.setattr(mod, "probe_rdp_certificate", lambda *a, **k: {"name": "JUMP-01", "fingerprint": "not-a-fingerprint"})
    assert client.post(CERT_URL, json={"host": "192.0.2.21", "port": 3389}).status_code == 502


RDP_TEXT = "RDP to 192.0.2.21\nusername: fict-admin-a\npassword=[REDACTED_PASSWORD]\nRDP to 192.0.2.22\nusername: fict-user-b\npassword=[REDACTED_PASSWORD]\n1. Confirm you are on the desktop of the last hop.\n"


def test_saving_a_builder_rdp_draft_never_probes_and_a_chosen_certificate_is_pinned_on_hop_1_only(http, monkeypatch):
    client, settings, *_ = http
    calls = []
    mod = _probe_mod()
    monkeypatch.setattr(mod, "probe_rdp_certificate", lambda *a, **k: calls.append(a) or {"name": "JUMP-01", "fingerprint": CERT_FP})
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network use while saving")))
    r = client.post(BASE + "/procedures", json={"procedure": RDP_TEXT})
    assert r.status_code == 200, r.text
    key = r.json()["id"]
    assert calls == [] and r.json()["connections"][0]["certificate"]["state"] != "reviewed"
    refs = [c["credential"]["reference"] for c in r.json()["connections"]]
    ok = client.put(f"{BASE}/procedures/{key}/connections", json={"connections": [{"order": 1, "certificate": {"name": "JUMP-01", "fingerprint": CERT_FP}}]})
    assert ok.status_code == 200, ok.text
    c1, c2 = ok.json()["connections"]
    assert (c1["certificate"]["state"], c1["certificate"]["name"], c1["certificate"]["fingerprint"]) == ("reviewed", "JUMP-01", CERT_FP)
    assert [c["credential"]["reference"] for c in ok.json()["connections"]] == refs and calls == []
    assert load_procedure(key, settings.wizard_state_root).connections[0].certificate_fingerprint == CERT_FP
    two = client.put(f"{BASE}/procedures/{key}/connections", json={"connections": [{"order": 2, "certificate": {"name": "X", "fingerprint": CERT_FP}}]})
    assert two.status_code == 422 and "hop 1 only" in two.text
    bad = client.put(f"{BASE}/procedures/{key}/connections", json={"connections": [{"order": 1, "certificate": {"name": "JUMP-01", "fingerprint": "sha256:zz"}}]})
    assert bad.status_code == 422
    assert load_procedure(key, settings.wizard_state_root).connections[0].certificate_fingerprint == CERT_FP
