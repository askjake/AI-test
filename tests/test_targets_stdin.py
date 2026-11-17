"""Hop-1 FreeRDP password transport: the password must never be in the process arguments or environment.

The pinned FreeRDP 2.11.7 has NO ``/args-from``; its supported channel is ``/from-stdin`` with the password as ONE
line on stdin (client/common/client.c, libfreerdp/utils/passphrase.c).  These tests use an injected launcher/runner
(no X display, FreeRDP binary or network) plus one REAL subprocess through the real launcher.  Proof against the
actual packaged binary lives in harness/b4r7 (qualification harness, not unit tests).  Fictional password only.
"""
from __future__ import annotations

import hashlib
import os
import sys

import pytest

from orchestrator.targets import TargetError, TargetSpec, Targets, _default_launcher

PW = "Zq9-NOTREAL-pw-1"
CERT = {"certificate_name": "WINHOST", "certificate_fingerprint": "sha256:" + "a" * 64}


class Proc:
    def __init__(self, exit_code=None):
        self.pid = 11
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code

    def terminate(self):
        self.exit_code = 0

    def kill(self):
        self.exit_code = 0

    def wait(self, timeout=None):
        return 0


class Launcher:
    """Records argv, env and stdin; the n-th launch can be made to exit immediately (client rejected its input)."""

    def __init__(self, early_exit_attempts=(), log_text=None):
        self.calls = []
        self.early = set(early_exit_attempts)
        self.log_text = log_text

    def __call__(self, cmd, env=None, log_path=None, stdin_data=None):
        self.calls.append({"cmd": list(cmd), "stdin": stdin_data, "env": dict(env or {}), "log_path": log_path})
        if self.log_text is not None and log_path:
            with open(log_path, "w") as fh:
                fh.write(self.log_text)
        return Proc(2 if len(self.calls) in self.early else None)


def make(tmp_path, launcher, runner_out=None):
    (tmp_path / "ref.rdp.pw").write_text(PW + "\n")

    def runner(cmd):
        verb = cmd[1] if len(cmd) > 1 else ""
        return (runner_out or {"search": "777\n"}).get(verb, "")

    return Targets(display=":99", rdp_host_allowlist=["winhost"], secrets_dir=str(tmp_path), runner=runner,
                   launcher=launcher, sleep=lambda _s: None)


def spec(**extra):
    params = {"host": "winhost", "user": "hop1user", "password_file": "ref.rdp.pw", "window": "w1", **CERT, **extra}
    return TargetSpec("rdp", params)


def test_stdin_transport_keeps_the_password_out_of_argv_and_env(tmp_path):
    launcher = Launcher()
    make(tmp_path, launcher).open_target(spec(password_transport="stdin"))
    assert len(launcher.calls) == 1
    call = launcher.calls[0]
    cmd = call["cmd"]
    assert cmd[0] == "xfreerdp" and cmd[-1] == "/from-stdin"                    # the supported channel
    assert not any("args-from" in part for part in cmd)                          # the option 2.11.7 does not have
    assert all(PW not in part and not part.startswith("/p:") for part in cmd)
    assert "/u:hop1user" in cmd and "/v:winhost" in cmd and "/timeout:30000" in cmd
    assert any(part.startswith("/cert:deny,name:WINHOST,fingerprint:sha256:") for part in cmd)   # pinning intact
    assert all(PW not in str(v) for v in call["env"].values())                  # nothing secret in the environment
    assert call["stdin"] == (PW + "\n").encode()                                 # EXACTLY one line: password + LF


def test_argv_transport_is_unchanged_for_single_target_projects(tmp_path):
    launcher = Launcher()
    make(tmp_path, launcher).open_target(spec())
    call = launcher.calls[0]
    assert f"/p:{PW}" in call["cmd"] and call["stdin"] is None and "/from-stdin" not in call["cmd"]


def test_client_that_exits_at_once_is_a_failure_with_a_code_and_no_secret(tmp_path):
    launcher = Launcher(early_exit_attempts={1}, log_text="[ERROR] x\n... ERRCONNECT_LOGON_FAILURE [0x00020014]\n")
    t = make(tmp_path, launcher)
    t.log_dir = str(tmp_path)
    with pytest.raises(TargetError) as err:
        t.open_target(spec(password_transport="stdin"))
    msg = str(err.value)
    assert len(launcher.calls) == 1                                              # no second "form" to retry
    assert "ERRCONNECT_LOGON_FAILURE" in msg and "status 2" in msg
    assert PW not in msg and "/p:" not in msg


def test_client_that_exits_at_once_without_a_log_still_fails_cleanly(tmp_path):
    launcher = Launcher(early_exit_attempts={1})
    with pytest.raises(TargetError) as err:
        make(tmp_path, launcher).open_target(spec(password_transport="stdin"))
    assert "exited at once" in str(err.value) and PW not in str(err.value)


def test_client_that_exits_after_the_probe_reports_the_error_code(tmp_path):
    class LateExit(Launcher):
        def __call__(self, cmd, env=None, log_path=None, stdin_data=None):
            super().__call__(cmd, env=env, log_path=log_path, stdin_data=stdin_data)
            self.proc = Proc(None)
            return self.proc
    launcher = LateExit(log_text="ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]\n")
    t = make(tmp_path, launcher, runner_out={"search": ""})        # no window ever appears
    t.log_dir = str(tmp_path)
    ticks = {"n": 0}

    def sleeper(_s):
        ticks["n"] += 1
        if ticks["n"] == 2:                    # the probe pause passed with the client still up; it dies afterwards
            launcher.proc.exit_code = 1
    t._sleep = sleeper
    with pytest.raises(TargetError) as err:
        t.open_target(spec(password_transport="stdin"))
    assert "exited with status 1" in str(err.value) and "ERRCONNECT_CONNECT_TRANSPORT_FAILED" in str(err.value)
    assert PW not in str(err.value)


@pytest.mark.parametrize("bad, fragment", [("a\nb", "line break"), ("a\rb", "line break"), ("a\x00b", "NUL")])
def test_password_that_cannot_travel_as_one_line_is_refused(tmp_path, bad, fragment):
    t = make(tmp_path, Launcher())
    (tmp_path / "ref.rdp.pw").write_text(bad)
    with pytest.raises(TargetError) as err:
        t.open_target(spec(password_transport="stdin"))
    assert fragment in str(err.value) and bad not in str(err.value)


def test_password_length_limit_matches_freerdp_buffer(tmp_path):
    ok, too_long = "p" * 511, "p" * 512
    launcher = Launcher()
    t = make(tmp_path, launcher)
    (tmp_path / "ref.rdp.pw").write_text(ok)               # written AFTER make(), which seeds a different password
    t.open_target(spec(password_transport="stdin"))
    assert launcher.calls[0]["stdin"] == ok.encode() + b"\n"
    t2 = make(tmp_path, Launcher())
    (tmp_path / "ref.rdp.pw").write_text(too_long)
    with pytest.raises(TargetError) as err:
        t2.open_target(spec(password_transport="stdin"))
    assert "too long" in str(err.value) and too_long not in str(err.value)


def test_non_ascii_password_is_sent_as_utf8(tmp_path):
    launcher = Launcher()
    t = make(tmp_path, launcher)
    (tmp_path / "ref.rdp.pw").write_text("pässwörd-\u20ac")
    t.open_target(spec(password_transport="stdin"))
    assert launcher.calls[0]["stdin"] == "pässwörd-\u20ac\n".encode("utf-8")


def test_stdin_transport_requires_a_user_and_a_saved_password(tmp_path):
    with pytest.raises(TargetError) as err:
        make(tmp_path, Launcher()).open_target(spec(password_transport="stdin", user=""))
    assert "user name" in str(err.value)
    params = {"host": "winhost", "user": "hop1user", "window": "w1", **CERT, "password_transport": "stdin"}
    with pytest.raises(TargetError) as err2:
        make(tmp_path, Launcher()).open_target(TargetSpec("rdp", params))
    assert "saved password" in str(err2.value)


def test_unknown_transport_is_refused(tmp_path):
    with pytest.raises(TargetError):
        make(tmp_path, Launcher()).open_target(spec(password_transport="env"))


def test_extra_args_still_cannot_smuggle_a_password_or_change_the_credential_channel(tmp_path):
    with pytest.raises(TargetError):
        make(tmp_path, Launcher()).open_target(spec(password_transport="stdin", extra_args="/p:other"))
    launcher = Launcher()
    make(tmp_path, launcher).open_target(spec(password_transport="stdin", extra_args="/from-stdin:force /sound"))
    cmd = launcher.calls[0]["cmd"]
    assert cmd.count("/from-stdin") == 1 and not any(part.startswith("/from-stdin:") for part in cmd)
    assert "/sound" in cmd                                                         # ordinary extra args still pass


def test_default_launcher_writes_stdin_and_closes_it(monkeypatch):
    written = {}

    class FakePipe:
        def write(self, data):
            written["data"] = data

        def close(self):
            written["closed"] = True

    class FakePopen:
        def __init__(self, args=None, env=None, stdin=None, **kw):
            written["args"] = args
            written["stdin_mode"] = stdin
            self.stdin = FakePipe()
            self.pid = 5

    import orchestrator.targets as targets_module
    monkeypatch.setattr(targets_module.subprocess, "Popen", FakePopen)
    _default_launcher(":99")(["xfreerdp", "/from-stdin"], stdin_data=b"secret\n")
    assert written["data"] == b"secret\n" and written["closed"] is True
    assert written["stdin_mode"] == targets_module.subprocess.PIPE
    assert written["args"] == ["xfreerdp", "/from-stdin"]


def test_default_launcher_survives_a_client_that_already_exited(monkeypatch):
    class BrokenPipe:
        def write(self, data):
            raise BrokenPipeError

        def close(self):
            raise BrokenPipeError

    class FakePopen:
        def __init__(self, **kw):
            self.stdin = BrokenPipe()
            self.pid = 6

    import orchestrator.targets as targets_module
    monkeypatch.setattr(targets_module.subprocess, "Popen", FakePopen)
    assert _default_launcher(":99")(["x"], stdin_data=b"pw\n").pid == 6        # no exception: the caller sees the exit status


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipes")
def test_real_process_receives_the_password_only_on_stdin_one_line_then_eof(tmp_path):
    """REAL subprocess through the REAL launcher (a stand-in for xfreerdp): what it can observe is only its stdin."""
    out = tmp_path / "observed.txt"
    child = (
        "import os, sys, hashlib\n"
        "line = b''\n"
        "while True:\n"                         # raw read(0) byte by byte until LF, exactly like freerdp_passphrase_read
        "    c = os.read(0, 1)\n"
        "    if not c or c == b'\\n': break\n"
        "    line += c\n"
        "again = os.read(0, 16)\n"              # a second prompt would read EOF immediately (the pipe was closed)
        f"open({str(out)!r}, 'w').write(repr({{'sha': hashlib.sha256(line).hexdigest(), 'eof_after': again == b'',\n"
        "  'argv_has_pw': any(line.decode() in a for a in sys.argv[1:]) if line else None,\n"
        "  'env_has_pw': any(line.decode() in v for v in os.environ.values()) if line else None}))\n"
    )
    proc = _default_launcher(":99")([sys.executable, "-c", child, "/from-stdin"], stdin_data=(PW + "\n").encode())
    assert proc.wait(timeout=20) == 0
    seen = eval(out.read_text())               # noqa: S307 - our own literal written a moment ago
    assert seen == {"sha": hashlib.sha256(PW.encode()).hexdigest(), "eof_after": True,
                    "argv_has_pw": False, "env_has_pw": False}


def test_window_covers_display_measurement(tmp_path):
    def runner_for(geometry, display="1280 800"):
        def run(cmd):
            if cmd[1] == "getwindowgeometry":
                return geometry
            if cmd[1] == "getdisplaygeometry":
                return display
            return "777\n"
        return run

    class H:
        window_id = "777"

    full = "WINDOW=777\nX=0\nY=0\nWIDTH=1280\nHEIGHT=800\nSCREEN=0\n"
    small = "WINDOW=777\nX=300\nY=200\nWIDTH=640\nHEIGHT=480\nSCREEN=0\n"
    t = Targets(display=":99", runner=runner_for(full), launcher=Launcher(), secrets_dir=str(tmp_path), sleep=lambda _s: None)
    assert t.window_covers_display(H()) is True
    t = Targets(display=":99", runner=runner_for(small), launcher=Launcher(), secrets_dir=str(tmp_path), sleep=lambda _s: None)
    assert t.window_covers_display(H()) is False
    t = Targets(display=":99", runner=runner_for("garbage"), launcher=Launcher(), secrets_dir=str(tmp_path), sleep=lambda _s: None)
    assert t.window_covers_display(H()) is None


# --- b4r8 FULLSCREEN_NOT_ESTABLISHED regression -------------------------------------------------------------
# Observed live (project fa68099b, hop 1): the windowed client at the configured 1280x800 sat on a 1920x1080
# runner display, so window_covers_display() (correctly) refused it.  Hop 1 now asks for full screen at the
# MEASURED display size; the coverage safeguard itself is unchanged.
DISPLAY_1080 = {"search": "777\n", "getdisplaygeometry": "1920 1080\n"}


def _flag(cmd, prefix):
    return [a for a in cmd if a.startswith(prefix)]


def test_fullscreen_hop_requests_f_at_the_measured_display_size_and_keeps_every_guard(tmp_path):
    launcher = Launcher()
    make(tmp_path, launcher, DISPLAY_1080).open_target(spec(password_transport="stdin", fullscreen="true"))
    cmd = launcher.calls[0]["cmd"]
    assert "/f" in cmd and "/w:1920" in cmd and "/h:1080" in cmd
    assert "/w:1280" not in cmd and "/h:800" not in cmd
    assert _flag(cmd, "/cert:") == ["/cert:deny,name:WINHOST,fingerprint:sha256:" + ":".join(["aa"] * 32)]
    assert cmd[-1] == "/from-stdin" and launcher.calls[0]["stdin"] == (PW + "\n").encode()
    assert not any(PW in a for a in cmd) and not any(a.startswith(("/p:", "/password:")) for a in cmd)


def test_without_the_fullscreen_param_the_launch_is_unchanged(tmp_path):
    launcher = Launcher()
    make(tmp_path, launcher, DISPLAY_1080).open_target(spec(password_transport="stdin"))
    cmd = launcher.calls[0]["cmd"]
    assert "/f" not in cmd and "/w:1280" in cmd and "/h:800" in cmd


@pytest.mark.parametrize("value", ["false", "0", "", "no", "maybe"])
def test_only_an_explicit_true_value_enables_fullscreen(tmp_path, value):
    launcher = Launcher()
    make(tmp_path, launcher, DISPLAY_1080).open_target(spec(password_transport="stdin", fullscreen=value))
    assert "/f" not in launcher.calls[0]["cmd"]


@pytest.mark.parametrize("display", ["", "garbage", "0 0", "99999 99999", "1920"])
def test_unmeasurable_display_falls_back_to_configured_size_still_with_f(tmp_path, display):
    launcher = Launcher()
    make(tmp_path, launcher, {"search": "777\n", "getdisplaygeometry": display}).open_target(
        spec(password_transport="stdin", fullscreen="true"))
    cmd = launcher.calls[0]["cmd"]
    assert "/f" in cmd and "/w:1280" in cmd and "/h:800" in cmd      # the coverage check still decides afterwards


def test_the_observed_failure_geometry_is_still_refused_and_a_full_window_is_accepted(tmp_path):
    """The safeguard stays meaningful: 1280x800 on 1920x1080 (what the live run showed) is NOT 'covers display'."""
    def covers(geometry):
        def run(cmd):
            return geometry if cmd[1] == "getwindowgeometry" else "1920 1080"
        t = Targets(display=":99", runner=run, launcher=Launcher(), secrets_dir=str(tmp_path), sleep=lambda _s: None)

        class H:
            window_id = "777"
        return t.window_covers_display(H())

    g = "WINDOW=777\nX={x}\nY={y}\nWIDTH={w}\nHEIGHT={h}\nSCREEN=0\n"
    assert covers(g.format(x=0, y=13, w=1280, h=800)) is False       # observed: windowed, configured size
    assert covers(g.format(x=855, y=0, w=1280, h=800)) is False      # offset window
    assert covers(g.format(x=0, y=0, w=1920, h=1080)) is True        # real full screen
    assert covers(g.format(x=0, y=0, w=1920, h=1050)) is True        # >=95% area (unchanged tolerance)
    assert covers(g.format(x=0, y=0, w=1500, h=1080)) is False       # tolerance not relaxed
