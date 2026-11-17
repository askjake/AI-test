#!/usr/bin/env python3
"""NRDP-1: narrow repair of the AWS credential SOURCE for one checkout (repoint away from a stale one-time copy).

DRY RUN BY DEFAULT.  It validates a candidate credentials file and shows exactly what would change.  With --apply it uses the checkout's own
supported commands (`cory-app stop` -> `install.sh configure --aws-credentials-file ...` -> `cory-app start`), after saving a 0700 backup of
runtime.json.  It never copies, rewrites, renews or reads out credential values, never touches the helper that renews them, never touches
saved passwords / tokens / projects / drafts, and refuses the untouched 8025 deployment.

    python3 aws_repair.py --checkout /home/montjac/ai-test-cory --credentials-file /home/montjac/.aws/credentials [--config-file ...] [--profile default] [--apply]

Why a restart here is legitimate: the managed CLI will not change configuration while the dashboard runs, and the dashboard reads its configured
source path at start.  After this one-time repoint, credential ROTATION never needs a restart again (the source is re-read on change).
Standard library only.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

FORBIDDEN = "/home/clink/ai-test-rdp-wizard-e2e-20261002"
RUNTIME = ".orchestrator-cookie"
EXPIRY_KEYS = ("aws_session_expiration", "aws_credential_expiration", "x_security_token_expires", "expiration", "expires", "expiry")


class RepairError(Exception):
    pass


def parse_expiry(value: str):
    text = (value or "").strip().strip('"').replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            when = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return None


def find_aws_block(node):
    if isinstance(node, dict):
        if isinstance(node.get("aws"), dict):
            return node["aws"]
        for v in node.values():
            found = find_aws_block(v)
            if found is not None:
                return found
    return None


def forbidden(path: str) -> bool:
    for candidate in {os.path.abspath(path), os.path.realpath(path)}:
        if candidate.rstrip("/") == FORBIDDEN or candidate.startswith(FORBIDDEN + "/"):
            return True
    return False


def validate_candidate(path: str, profile: str, *, now: datetime | None = None, min_valid_seconds: int = 300, allow_shared_dir: bool = False) -> list[str]:
    """Raise RepairError on a blocking problem; return human-readable notes (never values)."""
    now = now or datetime.now(timezone.utc)
    notes: list[str] = []
    if forbidden(path):
        raise RepairError("that path belongs to the untouched 8025 deployment")
    if not os.path.isabs(path):
        raise RepairError("use an absolute path")
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        raise RepairError("the credentials file does not exist") from None
    except OSError as exc:
        raise RepairError(f"the credentials file cannot be examined ({exc.__class__.__name__})") from None
    import stat as _stat
    if _stat.S_ISLNK(lst.st_mode):
        raise RepairError("the runner's credential bridge rejects symlinks: configure the REAL file path (the file your refresh mechanism rewrites)")
    if not _stat.S_ISREG(lst.st_mode):
        raise RepairError("not a regular file")
    if not os.access(path, os.R_OK):
        raise RepairError("this user cannot read the file")
    if "/migrated-files/" in path.replace("\\", "/"):
        raise RepairError("that is a migration copy - choose the live file")
    folder = os.path.dirname(path)
    try:
        entries = sorted(os.listdir(folder))
    except OSError:
        entries = []
    expected = {os.path.basename(path), "config", "credentials"}
    extras = [e for e in entries if e not in expected]
    sensitive = [e for e in extras if e in ("sso", "cli", "boto", "models") or e.endswith((".pem", ".key", ".json"))]
    if extras and not allow_shared_dir:
        raise RepairError(
            "the runner container would get this WHOLE folder read-only (%s) - it also holds: %s%s. Put the file the refresher writes in a dedicated 0700 folder "
            "(for example ~/.config/nrdp-aws/) and point at that, or re-run with --allow-shared-dir if you accept that exposure."
            % (folder, ", ".join(extras[:8]), " (+%d more)" % (len(extras) - 8) if len(extras) > 8 else ""))
    if extras:
        notes.append("shared folder accepted by --allow-shared-dir; the runner container can read: " + ", ".join(extras[:8]) + (" (sensitive: %s)" % ", ".join(sensitive) if sensitive else ""))
    if os.name == "posix" and (os.lstat(folder).st_mode & 0o077):
        notes.append("the folder mode is %s; a dedicated folder should be 0700" % oct(os.lstat(folder).st_mode & 0o777))
    if lst.st_mode & 0o077:
        notes.append(f"file mode is {oct(lst.st_mode & 0o777)}; credentials should be 0600 (not changed by this tool)")
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, configparser.Error):
        raise RepairError("the file could not be parsed as an AWS credentials file") from None
    if not parser.has_section(profile):
        raise RepairError(f"profile [{profile}] is not in that file (profiles: {', '.join(parser.sections()) or 'none'})")
    values = {k.lower(): v.strip() for k, v in parser.items(profile)}
    if not values.get("aws_access_key_id") or not values.get("aws_secret_access_key"):
        raise RepairError(f"profile [{profile}] holds no access keys (another provider such as credential_process would be needed)")
    if values.get("aws_access_key_id", "").startswith("ASIA") and not (values.get("aws_session_token") or values.get("aws_security_token")):
        raise RepairError("temporary keys without a session token - the file looks partially written")
    expiry = next((parse_expiry(values[k]) for k in EXPIRY_KEYS if values.get(k)), None)
    age = now.timestamp() - lst.st_mtime
    if expiry is None:
        notes.append("the profile has no expiration marker, so expiry cannot be shown ('unknown'); freshness is judged only by the file's write time "
                     f"({int(age // 60)} min ago)")
    else:
        left = (expiry - now).total_seconds()
        if left < min_valid_seconds:
            raise RepairError(f"profile [{profile}] is expired or about to expire ({int(left // 60)} min): this file is not being renewed, or its upstream login has expired")
        notes.append(f"profile [{profile}] valid for about {int(left // 60)} more minutes; file last written {int(age // 60)} min ago")
    return notes


def main(argv: list[str] | None = None, runner=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checkout", required=True)
    ap.add_argument("--credentials-file", required=True)
    ap.add_argument("--config-file")
    ap.add_argument("--profile")
    ap.add_argument("--region")
    ap.add_argument("--allow-shared-dir", action="store_true", help="accept that the whole folder holding the credentials file is exposed read-only to the runner container")
    ap.add_argument("--apply", action="store_true", help="stop, reconfigure with the supported CLI, start (default: show the plan only)")
    ap.add_argument("--no-restart", action="store_true", help="with --apply: stop and reconfigure only; start it yourself")
    args = ap.parse_args(argv)
    run = runner or (lambda cmd, cwd: subprocess.run(cmd, cwd=cwd, shell=False, stdin=subprocess.DEVNULL, check=False).returncode)
    checkout = Path(args.checkout).resolve()
    if forbidden(str(checkout)):
        print("REFUSED: that is the untouched 8025 deployment")
        return 2
    runtime_file = checkout / RUNTIME / "config/runtime.json"
    try:
        runtime = json.loads(runtime_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("REFUSED: cannot read this checkout's runtime.json")
        return 2
    aws = find_aws_block(runtime) or {}
    profile = args.profile or aws.get("profile") or "default"
    try:
        notes = validate_candidate(args.credentials_file, profile, allow_shared_dir=args.allow_shared_dir)
    except RepairError as exc:
        print(f"NOT SUITABLE: {exc}")
        return 1
    if args.config_file:
        if forbidden(args.config_file) or not Path(args.config_file).is_file() or not os.access(args.config_file, os.R_OK):
            print("NOT SUITABLE: the config file is missing, unreadable, or forbidden")
            return 1
    print("Candidate source is suitable:")
    for note in notes:
        print("  -", note)
    print("\nCurrent  : credentials_file =", aws.get("credentials_file"), "| config_file =", aws.get("config_file"), "| profile =", aws.get("profile"))
    print("Proposed : credentials_file =", args.credentials_file, "| config_file =", args.config_file or aws.get("config_file"), "| profile =", profile)
    cur_conf = aws.get("config_file") or ""
    if not args.config_file and "/migrated-files/" in cur_conf.replace("\\", "/"):
        print("Warning  : the CURRENT config_file (%s) is also a migration copy and will be kept. Pass --config-file with the live config (or the same folder's config) if profiles/regions matter." % cur_conf)
    print("Warning  : the runner mounts the FOLDER", os.path.dirname(args.credentials_file), "read-only into its container (existing behaviour); only the credentials/config files are copied.")
    cmd = ["bash", "./install.sh", "configure", "--non-interactive", "--aws-credentials-file", args.credentials_file, "--aws-profile", profile]
    if args.config_file:
        cmd += ["--aws-config-file", args.config_file]
    if args.region:
        cmd += ["--aws-region", args.region]
    plan = [["bash", "./cory-app", "stop"], cmd, ["bash", "./cory-app", "start"], ["bash", "./cory-app", "status"]]
    print("\nPlan (nothing else is touched - saved passwords, tokens, projects, drafts, the helper that renews credentials):")
    for step in plan:
        print("  $", " ".join(step))
    if not args.apply:
        print("\nDRY RUN - nothing changed. Re-run with --apply to execute the plan.")
        return 0
    backup = Path.home() / f"nrdp-aws-repair-backup-{time.strftime('%Y%m%dT%H%M%S')}"
    backup.mkdir(mode=0o700)
    shutil.copy2(runtime_file, backup / "runtime.json")
    print(f"\nBackup saved: {backup}/runtime.json  (restore: stop, copy it back to {runtime_file}, start)")
    for step in plan[:2] + ([] if args.no_restart else plan[2:]):
        rc = run(step, str(checkout))
        print(f"  [{rc}] {' '.join(step[:4])}")
        if rc != 0 and step is not plan[0]:
            print("FAILED. Restore with the backup above, then run: bash ./cory-app start")
            return 1
    print("\nDone. Verify (no model call):  python3 scripts/aws_collect.py --checkout", checkout, "  or open the AWS badge in the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
