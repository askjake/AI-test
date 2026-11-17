"""Control-message authenticity (SECURITY F1): a sticky bit alone proves nothing, ownership does.

These tests present POSIX stat results through an injected ``lstat`` so the permission logic is
exercised on any OS.  The real-filesystem variant runs on the 3090 gate (see
tests/test_chain_runtime.py::test_forged_run_request_is_not_trusted).
"""
import json
import stat
import threading
from types import SimpleNamespace as NS

import pytest

from orchestrator import chain_runtime as cr

DASH, RUNNER, OTHER = 1000, 10001, 2000
FILE = stat.S_IFREG | 0o644
DIR = stat.S_IFDIR | 0o755
PATH = "/reports/p/.nrdp-runs/trig_1_abcd/control/run_request.json"
FOLDER = "/reports/p/.nrdp-runs/trig_1_abcd/control"


def table(*, f_mode=FILE, f_uid=DASH, f_nlink=1, d_mode=DIR, d_uid=DASH):
    def lstat(path):
        if path == PATH:
            return NS(st_mode=f_mode, st_uid=f_uid, st_nlink=f_nlink)
        if path == FOLDER:
            return NS(st_mode=d_mode, st_uid=d_uid, st_nlink=2)
        raise OSError(2, "missing")
    return lstat


PIN = {"ORCHESTRATOR_CONTROL_UID": str(DASH)}


def trusted(lstat, environ=None):
    return cr.trusted_control_file(PATH, lstat=lstat, environ=PIN if environ is None else environ)


def test_dashboard_owned_file_in_dashboard_owned_folder_is_trusted():
    assert trusted(table())
    # SECURITY M2: on POSIX the pin is now REQUIRED.  "same owner" alone is no longer enough,
    # because any single local account satisfies it inside a folder it owns itself.
    assert not cr.trusted_control_file(PATH, lstat=table(), environ={}, posix=True)
    # Off POSIX there is no meaningful uid, so the owner rule still applies.
    assert cr.trusted_control_file(PATH, lstat=table(), environ={}, posix=False)


@pytest.mark.parametrize("kwargs,why", [
    ({"f_uid": OTHER}, "file owned by another local user"),
    ({"f_uid": RUNNER}, "file owned by the runner itself"),
    ({"d_uid": OTHER}, "control folder owned by another local user"),
    ({"f_mode": stat.S_IFREG | 0o664}, "group-writable file"),
    ({"f_mode": stat.S_IFREG | 0o666}, "world-writable file"),
    ({"d_mode": stat.S_IFDIR | 0o777}, "world-writable folder"),
    ({"d_mode": stat.S_IFDIR | 0o1777}, "sticky world-writable folder: sticky bit is NOT authenticity"),
    ({"d_mode": stat.S_IFDIR | 0o775}, "group-writable folder"),
    ({"f_nlink": 2}, "hard-linked file"),
    ({"f_mode": stat.S_IFLNK | 0o777}, "symlink"),
])
def test_forged_or_unsafe_control_files_are_not_trusted(kwargs, why):
    assert not trusted(table(**kwargs)), why


def test_without_a_pin_a_file_owned_by_someone_else_than_its_folder_owner_is_rejected():
    assert not cr.trusted_control_file(PATH, lstat=table(f_uid=OTHER), environ={})
    assert not cr.trusted_control_file(PATH, lstat=table(f_uid=OTHER), environ={}, posix=False)


def test_pin_must_be_numeric_and_missing_files_are_not_trusted():
    # SECURITY M2: a non-numeric pin is not a pin.  On POSIX that is now a refusal, not a
    # silent downgrade to the weaker owner rule.
    assert not cr.trusted_control_file(PATH, lstat=table(), environ={"ORCHESTRATOR_CONTROL_UID": "abc"}, posix=True)
    assert cr.trusted_control_file(PATH, lstat=table(), environ={"ORCHESTRATOR_CONTROL_UID": "abc"}, posix=False)
    assert not cr.trusted_control_file("/reports/missing.json", lstat=table(), environ=PIN)


def test_m2_posix_without_a_pin_refuses_even_a_perfectly_owned_control_file():
    """The whole point: an unattributable request is refused, however tidy its permissions are."""
    for environ in ({}, {"ORCHESTRATOR_CONTROL_UID": ""}, {"ORCHESTRATOR_CONTROL_UID": "not-a-uid"}):
        assert not cr.trusted_control_file(PATH, lstat=table(), environ=environ, posix=True)


def test_m2_pin_mismatch_is_refused():
    assert not cr.trusted_control_file(
        PATH, lstat=table(), environ={"ORCHESTRATOR_CONTROL_UID": str(OTHER)}, posix=True)


def _setup(tmp_path, monkeypatch, scenario):
    d = tmp_path / "p1" / ".nrdp-runs" / "trig_1_abcd" / "control"
    d.mkdir(parents=True)
    # run_id is stamped by the dashboard in production (security M2), so model that here.
    body = {"mode": "full_run", "project": "p1", "chain": True, "confirm_recorded": True,
            "run_id": "trig_1_abcd"}
    (d / "run_request.json").write_text(json.dumps(body))

    def fake(path):
        path = str(path)
        if path.endswith("run_request.json") or path.endswith("checkpoint_ack.json") or path.endswith("cancel_request.json"):
            return NS(st_mode=scenario["f_mode"], st_uid=scenario["f_uid"], st_nlink=1)
        return NS(st_mode=DIR, st_uid=scenario["d_uid"], st_nlink=2)

    monkeypatch.setattr(cr, "_LSTAT", fake)
    monkeypatch.setenv("ORCHESTRATOR_CONTROL_UID", str(DASH))
    return str(tmp_path), d


def test_forged_full_run_request_stays_connection_test(tmp_path, monkeypatch):
    scenario = {"f_mode": FILE, "f_uid": OTHER, "d_uid": DASH}        # an attacker's file in the dashboard's folder
    root, _ = _setup(tmp_path, monkeypatch, scenario)
    forged = cr.read_run_request(root, "p1", "trig_1_abcd")
    assert forged.mode == cr.CONNECTION_TEST and "not trusted" in forged.reason
    scenario["f_uid"] = DASH
    genuine = cr.read_run_request(root, "p1", "trig_1_abcd")
    # A GENUINE, dashboard-owned, confirmed, run-id-bound full run is still refused by the
    # connection-only qualification -- and for a different, distinguishable reason than the forgery.
    assert genuine.mode == cr.CONNECTION_TEST and genuine.requested_mode == cr.FULL_RUN
    assert "connection-only" in genuine.reason and "not trusted" not in genuine.reason


def test_forged_checkpoint_ack_is_ignored_then_genuine_ack_is_accepted(tmp_path, monkeypatch):
    scenario = {"f_mode": FILE, "f_uid": OTHER, "d_uid": DASH}
    root, ctl = _setup(tmp_path, monkeypatch, scenario)
    (ctl / "checkpoint_ack.json").write_text(json.dumps({"id": "cp-3-aaaa0001", "acknowledged_by": "attacker"}))
    clock = {"t": 0.0}

    def sleep(seconds):
        clock["t"] += seconds
        if clock["t"] >= 3:
            scenario["f_uid"] = DASH          # the dashboard (re)writes the real acknowledgement

    gate = cr.CheckpointGate(str(ctl), clock=lambda: clock["t"], sleep=sleep, timeout=50, poll=1,
                             new_id=lambda: "aaaa0001")
    ack = gate.request({"order": 3, "title": "cable", "instructions": "plug"})
    assert ack is not None and clock["t"] >= 3          # waited while the forged ack was on disk
    assert (tmp_path / "p1" / ".nrdp-runs" / "trig_1_abcd" / "checkpoint.json").exists()   # runner request is in the run folder


def test_cancel_watcher_ignores_an_untrusted_request_until_it_is_trusted(tmp_path, monkeypatch):
    scenario = {"f_mode": FILE, "f_uid": OTHER, "d_uid": DASH}
    _, ctl = _setup(tmp_path, monkeypatch, scenario)
    (ctl / "cancel_request.json").write_text("{}")
    event = threading.Event()
    ticks = []

    def sleep(_s):
        ticks.append(1)
        if len(ticks) == 4:
            scenario["f_uid"] = DASH
        if len(ticks) > 60:
            raise RuntimeError("watcher did not stop")

    stop = cr.start_cancel_watcher(str(ctl), event, poll=0.0, sleep=sleep)
    for _ in range(2000):
        if event.is_set():
            break
        threading.Event().wait(0.005)
    stop()
    assert event.is_set() and len(ticks) >= 4


# ----------------------------------------------------------------- M2: pin parsing
#
# The pin comes from the host launcher (scripts/run_container.sh L21, ORCHESTRATOR_CONTROL_UID
# = "$(id -u)", passed into the container at L399).  Anything that is not a plain ASCII decimal
# uid cannot be attributed to the dashboard and must REFUSE trust -- never raise, and never
# alias a different uid.
@pytest.mark.parametrize("pin", [
    "-1",                    # negative: not a uid
    "-1000",                 # negative form of the real dashboard uid
    "+1000",                 # signed
    "1000.5",                # non-integer
    "1e3",                   # exponent form
    "0x3e8",                 # hex form
    "1000 2000",             # two values
    "nan",
    "\u00b2",                # superscript two: str.isdigit() is True but int() RAISES on it
    "\u0661\u0662\u0663",    # Arabic-Indic digits: str.isdigit() is True and int() -> 123
])
def test_m2_a_pin_that_is_not_a_plain_decimal_uid_refuses_control_trust(pin):
    environ = {"ORCHESTRATOR_CONTROL_UID": pin}
    assert cr._control_uid(environ) is None            # parsed as "no usable pin"
    # and the trust check refuses rather than propagating an exception
    assert not cr.trusted_control_file(PATH, lstat=table(), environ=environ, posix=True)


def test_m2_a_nonascii_digit_pin_cannot_alias_a_real_uid():
    """"\u0661\u0662\u0663" would int() to 123, so a file owned by 123 must still be refused."""
    environ = {"ORCHESTRATOR_CONTROL_UID": "\u0661\u0662\u0663"}
    assert not cr.trusted_control_file(
        PATH, lstat=table(f_uid=123, d_uid=123), environ=environ, posix=True)


def test_m2_a_valid_pin_still_trusts_the_dashboards_own_file():
    """Guard against the parsing fix over-tightening: the production shape still passes."""
    assert cr.trusted_control_file(PATH, lstat=table(), environ=PIN, posix=True)
    assert cr._control_uid({"ORCHESTRATOR_CONTROL_UID": " 1000 "}) == DASH   # launcher whitespace
