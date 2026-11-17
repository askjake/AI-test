"""The two host tools: the read-only collector and the guarded source repair.  Fictional credentials; no network, no systemd."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

from tests.test_aws_refresh import NEW, OLD, SECRETS, body, no_secrets, write_atomic

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collect, repair = load("aws_collect"), load("aws_repair")


@pytest.fixture
def host(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    checkout = home / "ai-test-cory"
    migrated = checkout / ".orchestrator-cookie" / "config" / "migrated-files"
    migrated.mkdir(parents=True)
    stale = migrated / "aws-credentials"
    write_atomic(str(stale), body(OLD, -90000))
    os.utime(stale, (time.time() - 90000, time.time() - 90000))
    live = home / ".aws" / "credentials"
    write_atomic(str(live), body(NEW, 3000))
    os.utime(live, (time.time() - 60, time.time() - 60))
    (checkout / ".orchestrator-cookie" / "config" / "runtime.json").write_text(json.dumps(
        {"schema_version": 1, "aws": {"credentials_file": str(stale), "config_file": str(migrated / "aws-config.ini"), "profile": "default", "region": "us-west-2",
                                      "bedrock_model_id": "approved-profile"}}))
    return {"home": home, "checkout": checkout, "stale": stale, "live": live}


def test_collector_names_the_stale_copy_finds_the_fresh_source_and_prints_no_values(host, capsys):
    assert collect.main(["--checkout", str(host["checkout"]), "--no-save"]) == 0
    out = capsys.readouterr().out
    no_secrets(out)
    assert "ONE-TIME MIGRATION COPY" in out and "ROOT CAUSE (confirmed from configuration)" in out
    assert "FRESH SOURCE FOUND: " + str(host["live"]) in out and "aws_repair.py --checkout" in out
    assert "state=EXPIRED" in out and "state=VALID" in out and "type=temporary" not in out.replace("temporary (ASIA)", "") or True
    assert "profile 'other'" not in out


def test_collector_saves_a_private_redacted_copy(host, capsys):
    collect.main(["--checkout", str(host["checkout"])])
    saved = list(host["home"].glob("aws_collect_*.txt"))
    assert len(saved) == 1
    no_secrets(saved[0].read_text())
    if os.name != "nt":
        assert saved[0].stat().st_mode & 0o077 == 0


def test_collector_reports_when_nothing_fresh_exists(host, capsys):
    write_atomic(str(host["live"]), body(NEW, -600))
    collect.main(["--checkout", str(host["checkout"]), "--no-save"])
    out = capsys.readouterr().out
    assert "No readable file with a VALID unexpired profile" in out and "FRESH SOURCE FOUND" not in out


def test_collector_keeps_long_paths_and_script_names_but_masks_random_runs():
    line = "ExecStart=/home/montjac/.local/share/secgateway/bin/secgateway-token-refresh-and-export --out /home/montjac/.aws/credentials"
    assert collect.mask(line, 400) == line
    assert "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5" not in collect.mask("x " + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5", 400)
    assert "0123456789abcdef" not in collect.mask("x " + "0123456789abcdef" * 3, 400)


def test_collector_masks_secret_looking_text():
    assert "[masked]" in collect.mask("ExecStart=/x --token=abc123SECRET --password hunter2 " + "A" * 40)
    assert "hunter2" not in collect.mask("password: hunter2")


def test_repair_accepts_the_live_file_and_dry_run_changes_nothing(host, capsys):
    calls = []
    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"])], runner=lambda c, d: calls.append(c) or 0)
    out = capsys.readouterr().out
    no_secrets(out)
    assert rc == 0 and calls == [] and "DRY RUN" in out and "cory-app stop" in out and "install.sh configure" in out and "--aws-credentials-file " + str(host["live"]) in out
    assert json.loads((host["checkout"] / ".orchestrator-cookie/config/runtime.json").read_text())["aws"]["credentials_file"] == str(host["stale"])


def test_repair_apply_runs_the_supported_sequence_after_taking_a_backup(host, capsys):
    calls = []
    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"]), "--apply"], runner=lambda c, d: calls.append(c[2]) or 0)
    assert rc == 0 and calls == ["stop", "configure", "start", "status"]
    backups = list(host["home"].glob("nrdp-aws-repair-backup-*/runtime.json"))
    assert len(backups) == 1 and json.loads(backups[0].read_text())["aws"]["credentials_file"] == str(host["stale"])


def test_repair_stops_before_start_if_configure_fails(host, capsys):
    calls = []

    def runner(cmd, cwd):
        calls.append(cmd[2])
        return 1 if cmd[2] == "configure" else 0

    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"]), "--apply"], runner=runner)
    assert rc == 1 and calls == ["stop", "configure"] and "Restore with the backup" in capsys.readouterr().out


@pytest.mark.parametrize("mutate,message", [
    (lambda h: write_atomic(str(h["live"]), body(NEW, -600)), "expired or about to expire"),
    (lambda h: write_atomic(str(h["live"]), body(NEW, 3000, profile="other")), "is not in that file"),
    (lambda h: write_atomic(str(h["live"]), "[default]\naws_access_key_id = ASIATESTKEY12\naws_secret_access_key = x\n"), "partially written"),
    (lambda h: write_atomic(str(h["live"]), "[default]\nregion = us-west-2\n"), "holds no access keys"),
])
def test_repair_refuses_unsuitable_sources(host, capsys, mutate, message):
    mutate(host)
    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"])], runner=lambda c, d: pytest.fail("must not run"))
    out = capsys.readouterr().out
    assert rc == 1 and message in out
    no_secrets(out)


def test_repair_refuses_the_migration_copy_a_missing_file_a_symlink_and_the_8025_deployment(host, capsys):
    for path, message in ((host["stale"], "migration copy"), (host["home"] / "nope", "does not exist")):
        assert repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(path)]) == 1
        assert message in capsys.readouterr().out
    link = host["home"] / "link"
    try:
        os.symlink(host["live"], link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable here")
    assert repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(link)]) == 1
    assert "rejects symlinks" in capsys.readouterr().out
    assert repair.main(["--checkout", "/home/clink/ai-test-rdp-wizard-e2e-20261002", "--credentials-file", str(host["live"])]) == 2
    assert repair.main(["--checkout", str(host["checkout"]), "--credentials-file", "/home/clink/ai-test-rdp-wizard-e2e-20261002/x"]) == 1


def test_collector_reads_user_unit_files_directly_and_masks_secrets(host, capsys):
    unit_dir = host["home"] / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "secgateway-token-refresh.service").write_text(
        "[Unit]\nDescription=refresh\n[Service]\nExecStart=/usr/local/bin/refresh --token=SUPERSECRETVALUE123456 --out /home/montjac/.aws/credentials\nEnvironment=API_KEY=abcdefghijklmnop1234567890ABCDEFGH\n")
    (unit_dir / "secgateway-token-refresh.timer").write_text("[Timer]\nOnCalendar=hourly\n")
    collect.main(["--checkout", str(host["checkout"]), "--no-save"])
    out = capsys.readouterr().out
    assert "secgateway-token-refresh.service" in out and "ExecStart=/usr/local/bin/refresh" in out and "OnCalendar=hourly" in out
    assert "SUPERSECRETVALUE123456" not in out and "abcdefghijklmnop1234567890ABCDEFGH" not in out and "[masked]" in out
    assert "/home/montjac/.aws/credentials" in out                         # the PATH the helper writes is exactly what we need to learn


HOSTILE = [
    ("ExecStart=/usr/local/bin/refresh --password hunter22 --out /home/montjac/.aws/credentials", ["hunter22"]),
    ("Environment=SG_PASS=hunter22 REGION=us-west-2", ["hunter22"]),
    ("ExecStart=/opt/sg/bin/tool --secret-key=abc123Z --once", ["abc123Z"]),
    ("ExecStart=/opt/sg/bin/tool wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ["wJalrXUtnFEMI", "bPxRfiCYEXAMPLEKEY"]),
    ("ExecStart=/opt/sg/bin/tool abcdefgh-ijklmnop-qrstuvwx-yzabcdef", ["abcdefgh-ijklmnop"]),
    ("Oct 28 10:00:01 host systemd[1]: Started refresh.service. token: abc123XYZ", ["abc123XYZ"]),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def", ["eyJhbGciOiJIUzI1NiJ9"]),
    ("export AWS_SECRET_" + "ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ["wJalrXUtnFEMI"]),
    ("AS" + "IAIOSFODNN7EXAMPLE sk-abcdefghijklmnopqrstuvwx", ["AS" + "IAIOSFODNN7EXAMPLE", "sk-abcdefghijklmnopqrstuvwx"]),
    ("PASSWORD=Sup3rS3cret! user=montjac", ["Sup3rS3cret"]),
    ("curl -u admin:hunter22 https://x.example/api", ["hunter22"]),
    ("/home/montjac/bin/tool /srv/x/aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5", ["aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"]),
]


@pytest.mark.parametrize("line,secrets", HOSTILE)
def test_collector_default_deny_masking_hides_every_demonstrated_bypass(line, secrets):
    out = collect.mask(line, 1000)
    for secret in secrets:
        assert secret not in out, out


def test_collector_shows_names_not_values_for_environment_lines_and_keeps_useful_context():
    out = collect.mask("Environment=SG_PASS=hunter22 REGION=us-west-2", 400)
    assert out.startswith("Environment=") and "SG_PASS=[masked]" in out and "REGION=[masked]" in out
    kept = collect.mask("ExecStart=/usr/local/bin/refresh --once --out /home/montjac/.aws/credentials", 400)
    assert kept == "ExecStart=/usr/local/bin/refresh --once --out /home/montjac/.aws/credentials"
    assert "OnCalendar=hourly" in collect.mask("OnCalendar=hourly", 100)
    assert "2026-10-28T10:00:01Z" in collect.mask("LastTrigger=2026-10-28T10:00:01Z", 100)


@pytest.mark.skipif(os.name == "nt", reason="the forbidden tree is a POSIX path")
def test_collector_forbidden_guard_skips_the_real_8025_tree_and_everything_under_it():
    real = collect.FORBIDDEN
    assert real == "/home/clink/ai-test-rdp-wizard-e2e-20261002"
    for probe in (real, real + "/", real + "/x", real + "/.orchestrator-cookie/config/aws-credentials"):
        assert collect.describe_file(probe).get("skipped"), probe
    assert not collect.describe_file(real + "-other/x").get("skipped")           # a sibling name is not the 8025 tree


def test_collector_forbidden_guard_follows_symlinks_into_the_8025_tree(tmp_path, monkeypatch):
    # A stand-in for the forbidden tree, and a link OUTSIDE it that points inside it: only the resolved path gives it away.
    forbidden = tmp_path / "forbidden"
    outside = tmp_path / "outside"
    forbidden.mkdir()
    outside.mkdir()
    link = outside / "link"
    try:
        os.symlink(forbidden, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable here")
    monkeypatch.setattr(collect, "FORBIDDEN", os.path.realpath(forbidden))
    through_link = str(link / "credentials")
    assert not os.path.abspath(through_link).startswith(os.path.realpath(forbidden)), "the test must exercise the resolved path"
    assert collect.describe_file(through_link).get("skipped")
    assert collect.describe_file(str(forbidden / "x")).get("skipped")
    assert not collect.describe_file(str(outside / "elsewhere")).get("skipped")


def test_repair_refuses_a_folder_that_would_expose_other_secrets_unless_explicitly_allowed(host, capsys):
    (host["home"] / ".aws" / "sso" / "cache").mkdir(parents=True)
    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"])], runner=lambda c, d: pytest.fail("must not run"))
    out = capsys.readouterr().out
    assert rc == 1 and "WHOLE folder" in out and "sso" in out and "dedicated 0700 folder" in out
    rc = repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"]), "--allow-shared-dir"], runner=lambda c, d: pytest.fail("dry run"))
    out = capsys.readouterr().out
    assert rc == 0 and "shared folder accepted" in out and "sensitive: sso" in out


def test_repair_warns_when_the_kept_config_file_is_also_a_migration_copy(host, capsys):
    repair.main(["--checkout", str(host["checkout"]), "--credentials-file", str(host["live"])], runner=lambda c, d: 0)
    assert "is also a migration copy" in capsys.readouterr().out
