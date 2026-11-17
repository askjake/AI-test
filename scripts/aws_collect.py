#!/usr/bin/env python3
"""NRDP-1: ONE read-only collector that finds where the AWS credentials are really renewed and why the app is not consuming them.

Run as the OS user that owns the checkout (montjac).  It prints a redacted report and saves a copy (mode 0600) next to your home folder.

    python3 aws_collect.py [--checkout /home/montjac/ai-test-cory] [--old-checkout /home/clink/ai-test-cory-usability-test-d0ARPr54]

It NEVER prints or stores an access key, secret, session token, helper secret, or raw credential file: only paths, owners, modes, sizes,
timestamps, profile NAMES, booleans ("has token"), the expiry TIME and state, key TYPE prefix (ASIA = temporary, AKIA = long-lived), unit/timer names,
and masked command lines.  It makes no AWS or network call, runs no refresh helper, and changes nothing (systemctl is used read-only).
Standard library only.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:                                    # Linux/macOS only; the collector's logic is also unit-tested on Windows
    import pwd
except ImportError:                     # pragma: no cover
    pwd = None

RUNTIME = ".orchestrator-cookie"
EXPIRY_KEYS = ("aws_session_expiration", "aws_credential_expiration", "x_security_token_expires", "expiration", "expires", "expiry")
FORBIDDEN = "/home/clink/ai-test-rdp-wizard-e2e-20261002"
NOW = datetime.now(timezone.utc)
OUT: list[str] = []


def say(text: str = "") -> None:
    OUT.append(text)
    print(text)


SECRETISH = re.compile(r"(?i)(?:AKIA|ASIA)[0-9A-Z]{12,}")           # kept for the key-id shape; the real filter below is default-deny
SECRET_NAME = re.compile(r"(?i)(pass|pwd|secret|token|key|auth|bearer|cred|session|signature|salt)")
SAFE_PATH_PREFIXES = ("/home/", "/etc/", "/usr/", "/opt/", "/var/", "/run/", "/tmp/", "/srv/", "/bin/", "/sbin/", "~/")
_TOKEN = re.compile(r"\S+")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$")
_SAFE_SIMPLE = re.compile(r"^(?:[A-Za-z]{1,14}|\d{1,6}|[a-z]{1,10}(?:-[a-z]{1,10})?|[A-Za-z]+\.(?:service|timer|target|socket|sh|py))$")


def _segment_looks_random(segment: str) -> bool:
    return len(segment) >= 24 and bool(re.search(r"[A-Z]", segment)) and bool(re.search(r"[a-z]", segment)) and bool(re.search(r"\d", segment))


def _safe_path(token: str) -> bool:
    """A filesystem path under a well-known prefix whose segments do not look like random key material."""
    if not token.startswith(SAFE_PATH_PREFIXES) or not re.fullmatch(r"[A-Za-z0-9._/~@+:-]+", token):
        return False
    return not any(_segment_looks_random(seg) for seg in token.split("/"))


def _safe_value(token: str) -> bool:
    return bool(_ISO.match(token) or _SAFE_SIMPLE.match(token) or _safe_path(token))


def _mask_token(token: str, *, name_is_secret: bool = False) -> str:
    """Default deny: show a token only when it is a known-harmless shape; everything else becomes [masked]."""
    if name_is_secret:
        return "[masked]"
    if _SAFE_SIMPLE.match(token) or _ISO.match(token) or _safe_path(token):
        return token
    if token.startswith("--") and re.fullmatch(r"--[a-z][a-z0-9-]{0,30}", token):
        return token
    if token.startswith("-") and re.fullmatch(r"-[A-Za-z]", token):
        return token
    return "[masked]"


def mask(text: str, limit: int = 220) -> str:
    """Redact for a report that people send to others.  Rules (all default-deny):
    * ``Environment=`` / ``EnvironmentFile=`` lines show variable NAMES only;
    * the value after ANY flag or key whose name looks secret-ish (pass, pwd, secret, token, key, auth, bearer, cred, session) is masked, whatever the separator;
    * every other token is shown only if it is a number, a short plain word, a timestamp or a path under a well-known prefix without random-looking segments;
    * key-id shapes (AKIA/ASIA...) are always masked.
    """
    out_lines = []
    for raw in str(text).splitlines() or [""]:
        line = SECRETISH.sub("[masked]", raw)
        env = re.match(r"^(\s*)(Environment|EnvironmentFile|PassEnvironment|SetCredential|LoadCredential)\s*=(.*)$", line)
        if env:
            names = []
            for item in re.findall(r"""(?:"[^"]*"|'[^']*'|\S+)""", env.group(3)):
                item = item.strip("\"'")
                names.append((item.split("=", 1)[0] if "=" in item else item) + ("=[masked]" if "=" in item else ""))
            out_lines.append(f"{env.group(1)}{env.group(2)}=" + " ".join(names) if env.group(2) == "Environment" else f"{env.group(1)}{env.group(2)}=[path hidden]")
            continue
        pieces, secret_next = [], False
        for tok in _TOKEN.findall(line):
            if secret_next:
                pieces.append("[masked]")
                secret_next = False
                continue
            if "=" in tok and not tok.startswith("=") and not _safe_path(tok):
                key, _, value = tok.partition("=")
                shown_key = key if re.fullmatch(r"[-A-Za-z0-9_.\[\]]{1,60}", key) else "[masked]"
                secretish = bool(SECRET_NAME.search(key))
                pieces.append(f"{shown_key}={_mask_token(value, name_is_secret=secretish) if value else ''}")
                continue
            if ":" in tok and not _safe_path(tok) and not _ISO.match(tok) and not re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", tok):
                key, _, value = tok.partition(":")
                if value and SECRET_NAME.search(key):
                    pieces.append(f"{key}:[masked]")
                    continue
            if tok.startswith("-") and SECRET_NAME.search(tok) and "=" not in tok:
                pieces.append(tok if re.fullmatch(r"--?[a-z][a-z0-9-]{0,30}", tok) else "[masked]")
                secret_next = True                      # "--password hunter22": the NEXT token is the value
                continue
            pieces.append(_mask_token(tok))
        out_lines.append(re.match(r"^\s*", line).group(0) + " ".join(pieces))
    return "\n".join(out_lines)[:limit] if limit else "\n".join(out_lines)


def parse_expiry(value: str):
    text = (value or "").strip().strip('"').replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            when = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    if text.replace(".", "", 1).isdigit():
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    return None


def age(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 0:
        return "in the future"
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}min"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def describe_file(path: str) -> dict:
    info = {"path": path, "exists": False}
    if any(c.rstrip("/") == FORBIDDEN or c.startswith(FORBIDDEN + "/") for c in {os.path.abspath(path), os.path.realpath(path)}):
        info["skipped"] = "belongs to the untouched 8025 deployment"
        return info
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return info
    except OSError as exc:
        info["error"] = exc.__class__.__name__
        return info
    info["exists"] = True
    info["symlink"] = os.path.islink(path)
    if info["symlink"]:
        info["link_target"] = os.readlink(path)
    try:
        st = os.stat(path)
    except OSError as exc:
        info["error"] = exc.__class__.__name__
        return info
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name if pwd else str(st.st_uid)
    except KeyError:
        owner = str(st.st_uid)
    info.update({"size": st.st_size, "mode": oct(st.st_mode & 0o777), "owner": owner, "inode": st.st_ino,
                 "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
                 "age_seconds": int(NOW.timestamp() - st.st_mtime), "readable": os.access(path, os.R_OK)})
    return info


def inspect_credentials(path: str, wanted_profile: str | None = None) -> list[dict]:
    """Per-profile facts from a credentials file (names, booleans, expiry time/state, key TYPE only)."""
    rows: list[dict] = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return [{"error": exc.__class__.__name__}]
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return [{"error": "not an ini file"}]
    for section in parser.sections():
        values = {k.lower(): v.strip() for k, v in parser.items(section)}
        key_id = values.get("aws_access_key_id", "")
        expiry = None
        marker = None
        for k in EXPIRY_KEYS:
            if values.get(k):
                expiry, marker = parse_expiry(values[k]), k
                break
        row = {"profile": section, "has_access_key": bool(key_id), "has_secret": bool(values.get("aws_secret_access_key")),
               "has_session_token": bool(values.get("aws_session_token") or values.get("aws_security_token")),
               "key_type": ("temporary (ASIA)" if key_id.startswith("ASIA") else "long-lived (AKIA)" if key_id.startswith("AKIA") else "unknown") if key_id else "none",
               "expiry_marker": marker, "keys_present": sorted(k for k in values if not k.startswith("aws_secret") and k not in ("aws_access_key_id", "aws_session_token"))[:8]}
        if expiry:
            left = (expiry - NOW).total_seconds()
            row.update({"expires_utc": expiry.strftime("%Y-%m-%d %H:%M:%SZ"), "state": "VALID" if left > 60 else "EXPIRED",
                        "left": age(left) if left > 0 else f"expired {age(-left)} ago"})
        else:
            row["state"] = "no expiry marker" if row["has_access_key"] else "no keys in this profile"
        if wanted_profile and section == wanted_profile:
            row["configured_profile"] = True
        rows.append(row)
    return rows


def user_bus_env() -> dict:
    """`systemctl --user` over plain SSH often lacks these; set them only if the user's runtime directory exists."""
    env = dict(os.environ)
    uid = os.getuid() if hasattr(os, "getuid") else None
    runtime = f"/run/user/{uid}" if uid is not None else ""
    if runtime and os.path.isdir(runtime):
        env.setdefault("XDG_RUNTIME_DIR", runtime)
        if os.path.exists(runtime + "/bus"):
            env.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + runtime + "/bus")
    return env


def run(argv: list[str], timeout: float = 8.0) -> str:
    if not shutil.which(argv[0]):
        return f"({argv[0]} not available)"
    try:
        proc = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, text=True, check=False, env=user_bus_env())
        return proc.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return f"({exc.__class__.__name__})"


def find_aws_block(node):
    if isinstance(node, dict):
        if isinstance(node.get("aws"), dict):
            return node["aws"]
        for v in node.values():
            found = find_aws_block(v)
            if found is not None:
                return found
    return None


def show_file(label: str, path: str, profile: str | None) -> None:
    f = describe_file(path)
    say(f"  {label}: {path}")
    if f.get("skipped"):
        say(f"    skipped: {f['skipped']}")
        return
    if not f["exists"]:
        say("    MISSING" + (f"  ({f['error']})" if f.get("error") else ""))
        return
    say(f"    owner={f.get('owner')} mode={f.get('mode')} size={f.get('size')} inode={f.get('inode')} last_written={f.get('mtime_utc')} ({age(f.get('age_seconds', 0))} ago)"
        f" readable_by_me={f.get('readable')}" + (f" symlink->{f['link_target']}" if f.get("symlink") else ""))
    if "/migrated-files/" in path.replace("\\", "/"):
        say("    >>> THIS IS A ONE-TIME MIGRATION COPY. Nothing renews it.")
    if f.get("readable"):
        for row in inspect_credentials(path, profile):
            if row.get("error"):
                say(f"    ! {row['error']}")
                continue
            tag = "  <== configured profile" if row.get("configured_profile") else ""
            say(f"    profile [{row['profile']}]: keys={row['has_access_key']} secret={row['has_secret']} token={row['has_session_token']} type={row['key_type']} "
                f"state={row['state']}" + (f" expires={row['expires_utc']} ({row['left']})" if row.get("expires_utc") else "") + tag)


def main(argv: list[str] | None = None) -> int:
    global NOW
    NOW = datetime.now(timezone.utc)
    del OUT[:]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checkout", default=str(Path.home() / "ai-test-cory"))
    ap.add_argument("--old-checkout", default="/home/clink/ai-test-cory-usability-test-d0ARPr54")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args(argv)
    me = pwd.getpwuid(os.getuid()).pw_name if pwd and hasattr(os, 'getuid') else os.environ.get('USERNAME', 'unknown')
    home = Path.home()
    checkout = Path(args.checkout)
    say(f"NRDP AWS collector  {NOW.strftime('%Y-%m-%d %H:%M:%SZ')}  user={me} home={home}")
    say("(read-only; no values printed; no AWS/network call; nothing modified)")
    say("(default-deny masking is applied, but READ THIS REPORT before you send it: unknown words and numbers are masked, plain words are shown)")

    say("\n[1] CONFIGURED AWS SOURCE (what the app uses today)")
    runtime = {}
    try:
        runtime = json.loads((checkout / RUNTIME / "config/runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        say(f"  runtime.json unreadable: {exc.__class__.__name__}")
    aws = find_aws_block(runtime) or {}
    profile = aws.get("profile")
    say(f"  profile={profile!r} region={aws.get('region')!r} model={aws.get('bedrock_model_id')!r}")
    cred_path, conf_path = aws.get("credentials_file"), aws.get("config_file")
    configured = []
    for label, path in (("credentials_file", cred_path), ("config_file", conf_path)):
        if path:
            show_file(label, path, profile)
            configured.append(path)
        else:
            say(f"  {label}: (not set)")
    if cred_path:
        folder = os.path.dirname(cred_path)
        try:
            names = sorted(os.listdir(folder))[:40]
            say(f"  runner mounts this FOLDER read-only: {folder}  entries={names}")
        except OSError as exc:
            say(f"  folder listing failed: {exc.__class__.__name__}")
    for rel in ("config/aws-refresh.json",):
        f = describe_file(str(checkout / RUNTIME / rel))
        say(f"  optional {rel}: {'present' if f['exists'] else 'absent'}")
    old = Path(args.old_checkout)
    oldcfg = {}
    try:
        oldcfg = json.loads((old / RUNTIME / "config/runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    old_aws = find_aws_block(oldcfg) or {}
    if old_aws:
        say(f"  (original deployment used) credentials_file={old_aws.get('credentials_file')!r} config_file={old_aws.get('config_file')!r} profile={old_aws.get('profile')!r}")

    say("\n[2] CANDIDATE SOURCES (files that might be what your refresh mechanism writes)")
    candidates = []
    for path in [home / ".aws/credentials", home / ".aws/config", Path(old_aws.get("credentials_file") or "/nonexistent"), Path(old_aws.get("config_file") or "/nonexistent"),
                 Path("/home/clink/.aws/credentials")]:
        if str(path) in configured or str(path) in candidates:
            continue
        candidates.append(str(path))
        show_file("candidate", str(path), profile)
    sso = home / ".aws/sso/cache"
    if sso.is_dir():
        say(f"  SSO cache folder present ({len(list(sso.glob('*.json')))} files; contents not read)")
    recent = []
    for base in (home / ".aws", home / ".config", home / ".secgateway", home / "secgateway"):
        if base.is_dir():
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in ("sso", "cache", "node_modules", ".git")][:20]
                if root.count(os.sep) - str(base).count(os.sep) > 3:
                    dirs[:] = []
                for name in files:
                    if re.search(r"(?i)cred|token|aws", name):
                        p = os.path.join(root, name)
                        try:
                            recent.append((os.stat(p).st_mtime, p))
                        except OSError:
                            pass
    recent.sort(reverse=True)
    say("  most recently written credential-like files under ~/.aws, ~/.config, secgateway folders:")
    for mtime, p in recent[:8]:
        say(f"    {datetime.fromtimestamp(mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} ({age(NOW.timestamp() - mtime)} ago)  {p}")

    say("\n[3] REFRESH MECHANISM (systemd user units, cron; commands masked)")
    say("  " + mask(run(["systemctl", "--user", "list-timers", "--all", "--no-pager"]), 1800).replace("\n", "\n  "))
    for unit in ("secgateway-token-refresh.timer", "secgateway-token-refresh.service"):
        text = run(["systemctl", "--user", "cat", unit, "--no-pager"])
        say(f"  --- {unit}")
        for line in text.splitlines():
            if re.match(r"\s*(\[|ExecStart|ExecStartPre|ExecStartPost|WorkingDirectory|OnCalendar|OnUnitActiveSec|OnBootSec|Unit=|Environment|EnvironmentFile|User=|Description)", line):
                say("    " + mask(line))
        status = run(["systemctl", "--user", "show", unit, "-p", "ActiveState,SubState,Result,ExecMainStatus,LastTriggerUSec,NextElapseUSecRealtime,ExecMainExitTimestamp", "--no-pager"])
        for line in status.splitlines():
            say("    " + mask(line))
    jtext = run(["journalctl", "--user", "-u", "secgateway-token-refresh.service", "-n", "12", "--no-pager", "-o", "short-iso"])
    say("  recent service log (masked):")
    for line in jtext.splitlines()[-12:]:
        say("    " + mask(line, 200))
    unit_dir = home / ".config" / "systemd" / "user"
    if unit_dir.is_dir():
        found = sorted(p for p in unit_dir.glob("*") if p.is_file() and re.search(r"(?i)secgateway|token|aws|cred|refresh", p.name))[:6]
        say("  user unit files (%s): %s" % (unit_dir, [p.name for p in found] or "none matching"))
        for p in found:
            say(f"  --- {p.name} (file contents, masked)")
            try:
                for line in p.read_text(errors="replace").splitlines()[:40]:
                    if re.match(r"\s*(\[|Exec|Working|OnCalendar|OnUnit|OnBoot|Unit=|Environment|User=|Description)", line):
                        say("    " + mask(line))
            except OSError as exc:
                say(f"    unreadable ({exc.__class__.__name__})")
    cron = run(["crontab", "-l"])
    say("  crontab: " + ("none" if "no crontab" in cron.lower() or not cron.strip() else "\n    ".join(mask(l) for l in cron.splitlines()[:10])))
    # paths mentioned by the unit's ExecStart script
    exec_lines = [l for l in run(["systemctl", "--user", "cat", "secgateway-token-refresh.service", "--no-pager"]).splitlines() if l.strip().startswith("ExecStart")]
    for line in exec_lines[:2]:
        for token in re.findall(r"(/[^\s'\";]+)", line):
            p = Path(token)
            if p.is_file() and p.stat().st_size < 200_000 and p.suffix in ("", ".sh", ".py", ".bash"):
                hits = []
                try:
                    for n, l in enumerate(p.read_text(errors="replace").splitlines(), 1):
                        if re.search(r"\.aws|credentials|AWS_SHARED|AWS_CONFIG|migrated|/home/", l) and not l.strip().startswith("#"):
                            hits.append(f"      {p.name}:{n}: {mask(l.strip(), 160)}")
                except OSError:
                    pass
                if hits:
                    say(f"  paths mentioned in {p}:")
                    for h in hits[:14]:
                        say(h)

    say("\n[4] WHAT THE RUNNING DASHBOARD / SHELL SEE (names only)")
    present = sorted(k for k in os.environ if k.startswith("AWS_") or k in ("AWS_PROFILE",))
    say(f"  this shell exports: {present or 'no AWS_* variables'}")
    pid = None
    for candidate in sorted((checkout / RUNTIME).glob("**/*dashboard*.json"))[:6]:
        try:
            data = json.loads(candidate.read_text())
            if isinstance(data, dict) and isinstance(data.get("pid"), int):
                pid = data["pid"]
                break
        except (OSError, ValueError):
            continue
    if pid:
        try:
            names = sorted(k.decode(errors="replace").split("=", 1)[0] for k in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0") if k.startswith(b"AWS_") or k.startswith(b"DASHBOARD_AUTHORING") or k.startswith(b"ORCHESTRATOR_AWS"))
            say(f"  dashboard pid {pid} environment (names only): {names}")
            vals = {}
            for entry in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
                if entry.startswith(b"DASHBOARD_AUTHORING_SHARED_CREDENTIALS_FILE=") or entry.startswith(b"ORCHESTRATOR_AWS_CREDENTIALS_FILE="):
                    k, v = entry.decode(errors="replace").split("=", 1)
                    vals[k] = v
            for k, v in vals.items():
                say(f"    {k} = {v}")
        except OSError as exc:
            say(f"  dashboard environment unreadable ({exc.__class__.__name__})")
    else:
        say("  dashboard pid not found in runtime state")

    say("\n[5] VERDICT")
    best = None
    for path in configured[:1] + candidates:
        f = describe_file(path)
        if not f.get("exists") or not f.get("readable"):
            continue
        for row in inspect_credentials(path, profile):
            if row.get("profile") == (profile or "default") and row.get("state") == "VALID":
                if best is None or f["age_seconds"] < best[1]:
                    best = (path, f["age_seconds"], row)
    if cred_path and "/migrated-files/" in cred_path.replace("\\", "/"):
        say("  ROOT CAUSE (confirmed from configuration): the app is configured to read the one-time migration copy, which nothing renews.")
    if best:
        say(f"  FRESH SOURCE FOUND: {best[0]}  (written {age(best[1])} ago, profile {profile or 'default'} valid {best[2].get('left')})")
        say("  Suggested next step (dry run, changes nothing):")
        say(f"    python3 aws_repair.py --checkout {checkout} --credentials-file {best[0]}")
    else:
        say("  No readable file with a VALID unexpired profile was found. Either the refresh mechanism writes somewhere not listed above (see [3]),")
        say("  or it is not running / its upstream login has expired. Send this report back; do not copy credentials anywhere.")
    if not args.no_save:
        target = home / f"aws_collect_{NOW.strftime('%Y%m%dT%H%M%SZ')}.txt"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(OUT) + "\n")
        print(f"\nsaved (redacted, mode 0600): {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
