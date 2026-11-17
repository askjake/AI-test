"""VNC connection intake: local extraction, typed configuration, saved-credential handling, model isolation.  Fictional values only.

Executed here with the real parser, the real TargetSetupService (real VNC password encoding), the real wizard router (TestClient) and the real
project generator.  No model, AWS, VNC server or remote desktop is contacted.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dashboard import connection_intake as CI
from dashboard import procedure_project, procedure_routes_v2  # noqa: F401
from dashboard.procedure_intake import (ConnectionEditError, IntakeError, build_procedure, connection_config_hash, load_procedure, public_view, update_connections,
                                        update_procedure)
from dashboard.target_setup import _vnc_password_file
from dashboard.wizard_routes import router as wizard_router
from tests.test_procedure_intake_v2 import PW1, _service, _settings
from tests.test_p14_wizard import _context_draft

VNC_PW = "pw-v1x"          # <= 8 bytes, fictional
GOAL = f"""VNC to 192.0.2.47
username: example-user
password={VNC_PW}

Open Chrome on that desktop.
Go to http://127.0.0.1:5004/.
Expand the browser to cover the desktop.
Verify active video streams.
Leave the browser open and finish the automation.
"""


GOAL_NUMBERED = GOAL.replace("Open Chrome on that desktop.", "1. Open Chrome on that desktop.").replace("Go to http", "2. Go to http").replace(
    "Expand the browser", "3. Expand the browser").replace("Verify active", "4. Verify active").replace("Leave the browser", "5. Leave the browser")


def lines(text):
    return text.replace("\r\n", "\n").splitlines()


# ---------------------------------------------------------------------------------------------- address syntax
@pytest.mark.parametrize("address,expected", [
    (None, (5900, 0)), (":0", (5900, 0)), (":1", (5901, 1)), (":99", (5999, 99)),
    ("::5901", (5901, 1)), ("::5900", (5900, 0)), ("::5999", (5999, 99)), ("::6000", (6000, None)), ("::443", (443, None)), ("::65535", (65535, None)),
])
def test_address_syntax_is_unambiguous(address, expected):
    assert CI.parse_vnc_address(address) == expected


@pytest.mark.parametrize("address", [":100", ":5901", ":5900", ":65535", "::0", "::65536", "::99999"])
def test_ambiguous_or_out_of_range_addresses_are_rejected_with_the_two_valid_spellings(address):
    with pytest.raises(CI.ConnectionBlockError) as err:
        CI.parse_vnc_address(address)
    assert err.value.field == "vnc.port"
    if address.startswith(":") and not address.startswith("::"):
        assert "ambiguous" in err.value.message and "::" in err.value.message


# ---------------------------------------------------------------------------------------------- block parsing
def test_the_user_goal_parses_into_a_typed_block():
    block = CI.parse_vnc_block(lines(GOAL), 0)
    assert (block.host, block.port, block.display, block.user, block.password) == ("192.0.2.47", 5900, 0, "example-user", VNC_PW)
    assert block.consumed == (0, 1, 2)


def test_username_is_optional_and_password_may_come_first():
    for text in ("VNC to host.example\npassword=abc\n", "VNC to host.example\npassword=abc\nusername: bob\n", "vnc to host.example:2\nPassword: abc\n"):
        block = CI.parse_vnc_block(lines(text), 0)
        assert block.password == "abc" and block.host == "host.example"
    assert CI.parse_vnc_block(lines("VNC to h.example\npassword=abc"), 0).user is None
    assert CI.parse_vnc_block(lines("VNC to h.example\npassword=abc\nusername: bob"), 0).user == "bob"
    assert CI.parse_vnc_block(lines("VNC to h.example:3\npassword=abc"), 0).port == 5903


@pytest.mark.parametrize("text,field", [
    ("VNC to 192.0.2.47\nOpen Chrome", "vnc.password"),
    ("VNC to 192.0.2.47\nusername: bob\nOpen Chrome", "vnc.password"),
    ("VNC to 192.0.2.47\npassword=", "vnc.password"),
    ("VNC to 192.0.2.47\npassword=" + "x" * 9, "vnc.password"),
    ("VNC to 192.0.2.47\npassword=pässwörd", "vnc.password"),     # > 8 UTF-8 bytes
    ("VNC to 192.0.2.47:5901\npassword=abc", "vnc.port"),
    ("VNC to 192.0.2.47::0\npassword=abc", "vnc.port"),
    ("VNC to [::1]\npassword=abc", "vnc.host"),
])
def test_ambiguous_or_incomplete_credential_blocks_are_rejected_locally_with_a_field(text, field):
    with pytest.raises(CI.ConnectionBlockError) as err:
        CI.parse_vnc_block(lines(text), 0)
    assert err.value.field == field
    assert "abc" not in err.value.message and VNC_PW not in err.value.message


def test_non_connection_text_is_not_mistaken_for_a_block():
    for text in ("Verify the VNC viewer shows the desktop", "Use VNC to inspect the box", "Copy the vnc to-do list"):
        assert CI.find_connection_lines(lines(text)) == ([], [])


# ---------------------------------------------------------------------------------------------- guard
@pytest.mark.parametrize("text", [
    "Log in with password=hunter22 and open the page",
    "password: hunter22",
    "token = abcdef123456",
    "Open https://admin:hunter22@10.0.0.5/ and continue",
    "VNC to 192.0.2.47\nexample-user\nhunter22\nOpen Chrome",
    "RDP to 192.0.2.10\nexample-user\nhunter22\nOpen Notepad",
])
def test_the_model_guard_refuses_credential_bearing_text(text):
    message = CI.credential_guard_message(text)
    assert message and "hunter22" not in message


@pytest.mark.parametrize("text", [
    "Verify that the video wall shows four active streams and leave the browser open.",
    "Explain how VNC to a display works.",
    "Open the password manager help page and read the section about passwords.",
    "RDP to a jump host is described in the manual.",
])
def test_the_model_guard_leaves_plain_goals_alone(text):
    assert CI.credential_guard_message(text) is None


# ---------------------------------------------------------------------------------------------- service
@pytest.fixture
def env(tmp_path):
    settings = _settings(tmp_path)
    service = _service(settings)
    return settings, service


def _all_text(settings):
    out = []
    for path in Path(settings.wizard_state_root).rglob("*"):
        if path.is_file():
            try:
                out.append(path.read_text())
            except (UnicodeDecodeError, OSError):
                pass
    return "\n".join(out)


def test_intake_builds_a_typed_vnc_draft_and_saves_the_password_in_the_vnc_encoding(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    hop = draft.connections[0]
    assert (hop.protocol, hop.host, hop.port, hop.display, hop.user, hop.auth_method) == ("vnc", "192.0.2.47", 5900, 0, "example-user", "vnc-password")
    assert len(draft.connections) == 1 and draft.final_hop == 1 and draft.title == "VNC desktop operating procedure"
    assert hop.password_reference.endswith(".vnc.pw")
    stored = (Path(service._secrets_root()) / hop.password_reference).read_bytes()
    assert stored == _vnc_password_file(VNC_PW.encode()) and len(stored) == 8 and VNC_PW.encode() not in stored      # not a plaintext RDP-style file
    assert [s.order for s in draft.steps] == [1]                                  # unnumbered text is one step (same rule as RDP)
    assert all(line in draft.steps[0].instructions for line in ("Open Chrome on that desktop.", "Verify active video streams.", "Leave the browser open"))
    numbered = build_procedure(GOAL_NUMBERED, service, settings.wizard_state_root)
    assert [s.order for s in numbered.steps] == [1, 2, 3, 4, 5]
    everything = _all_text(settings) + draft.model_dump_json() + draft.manual
    assert VNC_PW not in everything and "example-user" in everything          # the username is a reference value, the password never is


def test_connection_values_do_not_leak_into_the_steps_or_manual(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    steps_text = "\n".join(s.instructions + s.title for s in draft.steps)
    assert VNC_PW not in steps_text and VNC_PW not in draft.manual and "192.0.2.47" not in steps_text
    assert "192.0.2.47" in draft.manual and "is not sent" in draft.manual           # connection section only


def test_readiness_has_no_certificate_requirement_and_states_what_a_test_proves(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    view = public_view(draft, service._secrets_root())
    keys = {i["key"]: i for i in view["readiness"]["items"]}
    assert "certificate-hop-1" not in keys and keys["credential-hop-1"]["state"] == "known" and keys["auth-method"]["state"] == "known"
    assert "no machine/account identity" in keys["identity"]["detail"] and "never" in keys["session-end"]["detail"]
    assert view["execution_supported"] is True and view["connections"][0]["certificate"]["state"] == "not_applicable"
    assert view["connections"][0]["vnc"] == {"display": 0, "tcp_port": 5900, "auth_method": "vnc-password", "username_sent": False, "address_form": ":0"}
    assert view["session_end"] == CI.SESSION_END_DEFAULT


def test_display_and_port_forms_are_stored_distinctly(env):
    settings, service = env
    d1 = build_procedure(GOAL.replace("192.0.2.47", "192.0.2.47:2"), service, settings.wizard_state_root).connections[0]
    d2 = build_procedure(GOAL.replace("192.0.2.47", "192.0.2.47::5902"), service, settings.wizard_state_root).connections[0]
    d3 = build_procedure(GOAL.replace("192.0.2.47", "192.0.2.47::6001"), service, settings.wizard_state_root).connections[0]
    assert (d1.port, d1.display) == (5902, 2) and (d2.port, d2.display) == (5902, 2) and (d3.port, d3.display) == (6001, None)


def test_password_only_vnc_needs_no_username(env):
    settings, service = env
    draft = build_procedure("VNC to 192.0.2.47\npassword=abc\n1. Open Chrome.", service, settings.wizard_state_root)
    assert draft.connections[0].user == "" and "not sent" not in " ".join(draft.findings)


@pytest.mark.parametrize("goal,fragment", [
    ("VNC to 192.0.2.47\nOpen Chrome and go to the page", "labelled password"),
    ("VNC to 192.0.2.47\npassword=" + "x" * 12 + "\n1. Open Chrome", "at most 8 bytes"),
    ("VNC to 192.0.2.47:5901\npassword=abc", "ambiguous"),
    ("VNC to 192.0.2.47\npassword=abc\nVNC to 192.0.2.48\npassword=def", "Only one VNC connection"),
    ("RDP to 192.0.2.10\nu\nSomething-Long-1\nVNC to 192.0.2.47\npassword=abc", "mixes RDP and VNC"),
    ("VNC to 192.0.2.47\npassword=abc\n1. Open Chrome.\npassword: leaked-1", "not part of the VNC connection block"),
])
def test_rejections_name_the_problem_and_save_nothing(env, goal, fragment):
    settings, service = env
    with pytest.raises(IntakeError) as err:
        build_procedure(goal, service, settings.wizard_state_root)
    assert fragment in str(err.value)
    root = Path(service._secrets_root())
    assert not (root.exists() and list(root.glob("*")))                           # nothing was saved
    for secret in ("leaked-1", "x" * 12, "def"):
        assert secret not in str(err.value)


def test_rdp_intake_is_unchanged_next_to_vnc(env):
    settings, service = env
    rdp = build_procedure(f"RDP to 10.70.115.36\nusername: operator1\npassword: {PW1}\n1. Open Notepad.", service, settings.wizard_state_root)
    hop = rdp.connections[0]
    assert (hop.protocol, hop.port, hop.password_reference.endswith(".rdp.pw")) == ("rdp", 3389, True)
    assert "certificate-hop-1" in {i["key"] for i in public_view(rdp, service._secrets_root())["readiness"]["items"]}
    assert connection_config_hash(rdp) == connection_config_hash(rdp.model_copy(update={}))


def test_rdp_hash_is_independent_of_the_new_vnc_fields(env):
    """RDP drafts saved before this change keep their connection hash (so passed tests / projects stay current)."""
    import hashlib
    settings, service = env
    rdp = build_procedure(f"RDP to 10.70.115.36\nusername: operator1\npassword: {PW1}\n1. Open Notepad.", service, settings.wizard_state_root)
    h = rdp.connections[0]
    legacy = hashlib.sha256(json.dumps([[h.order, h.host, h.port, h.user, h.password_reference, h.certificate_name or "", h.certificate_fingerprint or "",
                                         h.identity_policy]], separators=(",", ":")).encode()).hexdigest()
    assert connection_config_hash(rdp) == legacy


def test_editing_a_vnc_connection_validates_and_invalidates_a_prior_test(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    draft = draft.model_copy(update={"last_test": {"status": "passed", "config_hash": connection_config_hash(draft)}})
    from dashboard.procedure_intake import persist_draft
    persist_draft(draft.id, settings.wizard_state_root, draft)
    for edit, field in (({"order": 1, "display": 100}, "display"), ({"order": 1, "display": 1, "port": 5999}, "port"),
                        ({"order": 1, "identity_policy": "stop"}, "identity_policy"), ({"order": 1, "new_password": "123456789"}, "new_password"),
                        ({"order": 1, "auth_method": "kerberos"}, "auth_method")):
        with pytest.raises(ConnectionEditError) as err:
            update_connections(draft.id, [edit], settings.wizard_state_root, service)
        assert any(field in e["field"] for e in err.value.errors), edit
    updated = update_connections(draft.id, [{"order": 1, "display": 2}], settings.wizard_state_root, service)
    assert (updated.connections[0].display, updated.connections[0].port) == (2, 5902) and updated.last_test is None
    updated = update_connections(draft.id, [{"order": 1, "port": 6001}], settings.wizard_state_root, service)
    assert (updated.connections[0].display, updated.connections[0].port) == (None, 6001)
    old_ref = updated.connections[0].password_reference
    replaced = update_connections(draft.id, [{"order": 1, "new_password": "newpw"}], settings.wizard_state_root, service)
    assert replaced.connections[0].password_reference != old_ref and replaced.connections[0].password_reference.endswith(".vnc.pw")
    assert (Path(service._secrets_root()) / old_ref).exists()                      # the old saved password is never deleted
    assert (Path(service._secrets_root()) / replaced.connections[0].password_reference).read_bytes() == _vnc_password_file(b"newpw")


def test_unsupported_auth_method_blocks_execution_with_a_reason(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    updated = update_connections(draft.id, [{"order": 1, "auth_method": "username-password"}], settings.wizard_state_root, service)
    view = public_view(updated, service._secrets_root())
    item = next(i for i in view["readiness"]["items"] if i["key"] == "auth-method")
    assert item["state"] == "required" and "cannot be executed" in item["detail"] and view["execution_supported"] is False
    errs = procedure_project.validate_draft(updated, secrets_root=service._secrets_root())
    assert any(e["field"].endswith("auth_method") for e in errs)


def test_resume_keeps_the_typed_configuration_without_asking_for_the_password_again(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    again = load_procedure(draft.id, settings.wizard_state_root)
    view = public_view(again, service._secrets_root())
    assert view["connections"][0]["credential"]["state"] == "saved" and view["execution_supported"] is True and view["session_end"]["remote_session"] == "never_log_off"


def test_operating_steps_can_be_replaced_without_touching_connection_or_password(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    ref = draft.connections[0].password_reference
    updated = update_procedure(draft.id, "1. Open Chrome.\n2. Leave it open.", settings.wizard_state_root)
    assert [s.order for s in updated.steps] == [1, 2] and updated.connections[0].password_reference == ref and updated.connections[0].protocol == "vnc"
    with pytest.raises(IntakeError):
        update_procedure(draft.id, "VNC to 192.0.2.99\npassword=zzz", settings.wizard_state_root)
    with pytest.raises(IntakeError):
        update_procedure(draft.id, "password=zzz", settings.wizard_state_root)


# ---------------------------------------------------------------------------------------------- project generation
def test_project_generation_writes_a_typed_vnc_target_and_no_credentials(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    files = procedure_project.render_project_files(draft, forbidden=[VNC_PW])
    doc = json.loads(files["project.yaml"])
    assert doc["target"] == {"type": "vnc", "host": "192.0.2.47", "port": "5900", "password_file": draft.connections[0].password_reference}
    assert doc["vnc_host_allowlist"] == ["192.0.2.47"] and doc["procedure"]["protocol"] == "vnc" and doc["procedure"]["final_hop"] == 1
    assert doc["procedure"]["session_end"] == {"remote_applications": "leave_open", "automation_client": "disconnect", "remote_session": "never_log_off"}
    assert "user" not in doc["target"] and "example-user" not in files["project.yaml"]                # username never reaches project.yaml
    assert procedure_project.validate_vnc_yaml(doc) == []
    spec = files["procedure.md"]
    assert "Leave every application the steps opened" in spec and "never log off, lock or shut down" in spec
    made = procedure_project.create_project(draft, specs_root=settings.specs_dir, secrets_root=service._secrets_root())
    assert made["project_name"].startswith("vnc-desktop-operating-procedure-")
    again = procedure_project.create_project(draft, specs_root=settings.specs_dir, secrets_root=service._secrets_root())
    assert again["project_name"] == made["project_name"]


def test_mixed_chains_are_not_creatable(env):
    settings, service = env
    draft = build_procedure(GOAL, service, settings.wizard_state_root)
    rdp = build_procedure(f"RDP to 10.70.115.36\nusername: operator1\npassword: {PW1}\n1. Open Notepad.", service, settings.wizard_state_root)
    mixed = draft.model_copy(update={"connections": [rdp.connections[0], draft.connections[0].model_copy(update={"order": 2})]})
    errs = procedure_project.validate_draft(mixed, secrets_root=None)
    assert errs and "mixed RDP/VNC" in errs[0]["message"]


# ---------------------------------------------------------------------------------------------- HTTP: no model contact
def _planner_base():
    """The ProjectWizardService class the ROUTES check against (other tests reload dashboard modules, so never trust an import-time binding)."""
    endpoint = next(r.endpoint for r in wizard_router.routes if hasattr(r, "endpoint"))
    return endpoint.__globals__["ProjectWizardService"]          # the exact binding the route's _service() checks against


def make_spy():
    class SpyPlanner(_planner_base()):
        """A real ProjectWizardService type whose model-facing methods record the call and stop (no model exists here)."""

        def __init__(self):
            self.calls = []

        def preview_context(self, body):
            self.calls.append("preview_context")
            raise ValueError("reached")

        def create_job(self, body):
            self.calls.append("create_job")
            raise ValueError("reached")

    return SpyPlanner()


OP = {"Authorization": "Bearer operator"}


class AuthedClient(TestClient):
    """TestClient that always sends the operator bearer token (real auth path, same idiom as test_procedure_intake_v2)."""

    def request(self, method, url, **kwargs):
        if kwargs.get("headers") is None:                 # httpx passes headers=None explicitly
            kwargs["headers"] = OP
        return super().request(method, url, **kwargs)


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


def test_the_intake_endpoint_reads_the_block_locally_and_returns_no_secret(http):
    client, settings, service, app = http
    r = client.post("/api/v1/authoring/wizard/procedures", json={"procedure": GOAL})
    assert r.status_code == 200, r.text
    assert VNC_PW not in r.text and r.json()["connections"][0]["protocol"] == "vnc" and r.json()["connections"][0]["credential"]["state"] == "saved"
    assert app.state.project_wizard_service.calls == []
    got = client.get("/api/v1/authoring/wizard/procedures/" + r.json()["id"] + "/view")
    assert got.status_code == 200 and VNC_PW not in got.text and got.json()["connections"][0]["vnc"]["tcp_port"] == 5900


def test_the_intake_endpoint_reports_a_field_error_and_never_contacts_the_model(http):
    client, settings, service, app = http
    r = client.post("/api/v1/authoring/wizard/procedures", json={"procedure": "VNC to 192.0.2.47\nOpen Chrome\n" + "x" * 20})
    assert r.status_code == 422 and r.json()["detail"]["field"] == "vnc.password" and "labelled password" in r.json()["detail"]["message"]
    assert app.state.project_wizard_service.calls == []


@pytest.mark.parametrize("intent", [
    GOAL, "VNC to 192.0.2.47\nexample-user\nhunter22\nOpen Chrome", "Please log in with password=hunter22", "open https://u:hunter22@10.0.0.5/",
])
def test_the_model_planning_routes_refuse_credential_bearing_goals_before_the_model(http, intent):
    client, settings, service, app = http
    body = {"intent": intent, "draft": _context_draft().model_dump(), "blueprint_ids": [], "guidance_ids": []}
    for path in ("/api/v1/authoring/wizard/context-preview", "/api/v1/authoring/wizard/plan-jobs"):
        payload = dict(body, fingerprint="0" * 64) if path.endswith("plan-jobs") else body
        r = client.post(path, json=payload)
        assert r.status_code == 422, (path, r.text)
        assert "Nothing was sent to the model" in json.dumps(r.json()) and "hunter22" not in r.text and VNC_PW not in r.text
    assert app.state.project_wizard_service.calls == []


def test_an_ordinary_goal_still_reaches_the_planner(http):
    client, settings, service, app = http
    body = {"intent": "Verify that the video wall shows four active streams.", "draft": _context_draft().model_dump(), "blueprint_ids": [], "guidance_ids": []}
    r = client.post("/api/v1/authoring/wizard/context-preview", json=body)
    assert app.state.project_wizard_service.calls == ["preview_context"]          # reached: the guard does not block a plain goal
    assert r.status_code != 503


BYPASSES = ["p\u0430ssword: hunter22", "pass\u200bword: x1y2", "PASSWORD\uff1ahunter22", "my password is hunter2", "password - hunter2", "pw: x1y2z3", "passcode: 1234",
            "password\n: hunter2", "Use credentials: admin:hunter2", "the token=abc123", "VNC to h.example\nadmin\nhunter 22"]
PROSE_OK = ["Verify the Password: field is shown", "Check that the password is required", "Open the password manager and take a screenshot",
            "Leave the browser open and finish the automation.", "VNC to h.example\nOpen Chrome and verify four streams"]


@pytest.mark.parametrize("text", BYPASSES)
def test_guard_refuses_normalised_bypass_attempts(text):
    message = CI.credential_guard_message(text)
    assert message and "hunter" not in message


@pytest.mark.parametrize("text", PROSE_OK)
def test_guard_does_not_refuse_ordinary_prose_about_passwords(text):
    assert CI.credential_guard_message(text) is None


def test_server_guard_covers_every_draft_field_not_only_the_intent(http):
    client, settings, service, app = http
    base = _context_draft().model_dump()
    for field, value in (("goal", "Log in with password: hunter22"), ("display_name", "pw: hunter22"), ("manual_outline", ["step one", "token=abc123"])):
        draft = dict(base, **{field: value})
        for path in ("/api/v1/authoring/wizard/context-preview", "/api/v1/authoring/wizard/plan-jobs"):
            payload = {"intent": "Verify four streams.", "draft": draft, "blueprint_ids": [], "guidance_ids": []}
            if path.endswith("plan-jobs"):
                payload["fingerprint"] = "0" * 64
            r = client.post(path, json=payload)
            assert r.status_code == 422 and "hunter22" not in r.text and "abc123" not in r.text, (field, path, r.status_code, r.text[:200])
    assert app.state.project_wizard_service.calls == []


def test_vnc_manual_does_not_repeat_the_username_and_odd_passwords_get_a_warning(env):
    settings, service = env
    draft = build_procedure("VNC to 192.0.2.47\nusername: example-user\npassword=ab pw \n1. Open Chrome.", service, settings.wizard_state_root)
    assert "example-user" not in draft.manual and "recorded in the draft" in draft.manual
    assert any("trailing spaces" in f for f in draft.findings)
    d2 = build_procedure("VNC to 192.0.2.47\npassword=\u00e9\u00e8\n1. Open Chrome.", service, settings.wizard_state_root)
    assert any("non-ASCII" in f for f in d2.findings)


TESTER_D1 = ["Connect VNC to h.example, the pass" + "word is hunter22, then open Chrome", "VNC to h.example\nusername: bob\nhunter22", "VNC to h.example\npass" + "word - hunter22",
             "VNC to h.example\n\"pass" + "word\": \"hunter22\"", "VNC to h.example\npasscode: 12345678", "VNC to h.example\nkennwort: hunter22", "Log in to the box as bob / hunter22 and open Chrome"]


@pytest.mark.parametrize("text", TESTER_D1)
def test_tester_d1_guard_probes_are_all_refused(text):
    message = CI.credential_guard_message(text)
    assert message and "hunter22" not in message


def test_tester_d2_a_credential_in_the_username_field_is_rejected_with_a_field_error():
    for text in ("VNC to h.example\nusername: pass" + "word: Zq9hunter\npass" + "word=x1\n", "VNC to h.example\nusername: my pass" + "word is Zq9hunter\npass" + "word=x1\n"):
        with pytest.raises(CI.ConnectionBlockError) as err:
            CI.parse_vnc_block(lines(text), 0)
        assert err.value.field == "vnc.user" and "Zq9hunter" not in err.value.message


@pytest.mark.parametrize("host", ["fe80::1", "abcd::5901", "2001::1"])
def test_tester_d4_a_bare_ipv6_literal_is_a_host_error_not_a_misparse(host):
    with pytest.raises(CI.ConnectionBlockError) as err:
        CI.parse_vnc_block(lines("VNC to " + host + "\npass" + "word=ab\n"), 0)
    assert err.value.field == "vnc.host" and "IPv6" in err.value.message


def test_a_hostname_with_a_double_colon_port_still_works():
    assert CI.parse_vnc_block(lines("VNC to video-wall.example::5902\npass" + "word=ab\n"), 0).port == 5902
    assert CI.parse_vnc_block(lines("VNC to 10.0.0.5::5902\npass" + "word=ab\n"), 0).port == 5902
