"""Credential FILE source: stable, validated, secret-safe reads.  Standard library only."""
from __future__ import annotations

import configparser
import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

EXPIRY_KEYS = ("aws_session_expiration", "aws_credential_expiration", "x_security_token_expires", "expiration", "expires", "expiry")
MAX_BYTES = 1_000_000


class SourceError(Exception):
    """Safe to show: ``code`` is stable, ``message`` never contains file content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Signature:
    dev: int
    ino: int
    mtime_ns: int
    size: int


def signature_of(st: os.stat_result) -> Signature:
    return Signature(int(st.st_dev), int(st.st_ino), int(st.st_mtime_ns), int(st.st_size))


def stat_signature(path: str) -> Signature:
    try:
        return signature_of(os.stat(path))              # follows symlinks: replacing the TARGET is noticed too
    except FileNotFoundError:
        raise SourceError("missing", "The AWS credential file does not exist.") from None
    except OSError:
        raise SourceError("unreadable", "The AWS credential file cannot be read by this process.") from None


@dataclass(frozen=True)
class Loaded:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str | None = field(repr=False)
    expiry: datetime | None
    signature: Signature
    loaded_at: datetime
    identity: str = field(repr=False)            # internal change detector; never exported


def parse_expiry(value: str) -> datetime | None:
    text = (value or "").strip().strip('"')
    if not text:
        return None
    if text.replace(".", "", 1).isdigit():           # epoch seconds
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    text = text.replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            when = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return None


def credential_state(expiry: datetime | None, now: datetime, near_seconds: float = 90.0) -> str:
    if expiry is None:
        return "unknown"
    left = (expiry - now).total_seconds()
    if left <= 0:
        return "expired"
    return "expiring" if left < near_seconds else "valid"


def check_trust(path: str) -> None:
    """POSIX trust check for the credential source: a real (non-symlink) file owned by this user or root that nobody else can write, in a directory
    nobody else can write (sticky dirs excepted).  A source another local user can modify would let them substitute THEIR AWS identity.
    Skipped on platforms without POSIX ownership semantics (Windows relies on the per-user profile ACLs)."""
    if os.name != "posix" or not hasattr(os, "getuid"):
        return
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        raise SourceError("missing", "The AWS credential file does not exist.") from None
    except OSError:
        raise SourceError("unreadable", "The AWS credential file cannot be read by this process.") from None
    import stat as _stat
    if _stat.S_ISLNK(lst.st_mode):
        raise SourceError("unsafe_permissions", "The AWS credential source is a symlink; configure the real file the refresher writes.")
    if lst.st_uid not in (os.getuid(), 0):
        raise SourceError("unsafe_permissions", "The AWS credential file is owned by another user.")
    if lst.st_mode & 0o022:
        raise SourceError("unsafe_permissions", "The AWS credential file is writable by group or others (chmod 600 it).")
    parent = os.lstat(os.path.dirname(os.path.abspath(path)) or ".")
    if parent.st_mode & 0o022 and not parent.st_mode & _stat.S_ISVTX:
        raise SourceError("unsafe_permissions", "The folder holding the AWS credential file is writable by group or others.")
    if parent.st_uid not in (os.getuid(), 0):
        raise SourceError("unsafe_permissions", "The folder holding the AWS credential file is owned by another user.")


def parse_profile(raw: bytes, profile: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise SourceError("incomplete", "The AWS credential file is not valid text.") from None
    parser = configparser.RawConfigParser(strict=True, interpolation=None)          # duplicate sections/keys (e.g. two concatenated files) are refused
    try:
        parser.read_string(text)
    except configparser.Error:
        raise SourceError("incomplete", "The AWS credential file could not be parsed (or has duplicate sections or keys).") from None
    if not parser.has_section(profile):
        raise SourceError("profile_missing", f"Profile {profile!r} is not in the AWS credential file.")
    return {k.lower(): v.strip().strip('"') for k, v in parser.items(profile)}


def load_credentials(path: str, profile: str, *, now: datetime | None = None, settle_seconds: float = 0.2, attempts: int = 4,
                     sleep=time.sleep, previous_had_token: bool = False, previous_had_expiry: bool = False) -> Loaded:
    """Read, validate and return one COMPLETE credential set, or raise SourceError (never a partial result)."""
    last = SourceError("unstable", "The AWS credential file kept changing while it was read.")
    check_trust(path)
    for _ in range(max(1, attempts)):
        sig1 = stat_signature(path)
        try:
            with open(path, "rb") as fh:
                fd_sig = signature_of(os.fstat(fh.fileno()))
                raw = fh.read(MAX_BYTES + 1)
        except FileNotFoundError:
            raise SourceError("missing", "The AWS credential file does not exist.") from None
        except OSError:
            raise SourceError("unreadable", "The AWS credential file cannot be read by this process.") from None
        sig2 = stat_signature(path)
        if len(raw) > MAX_BYTES:
            raise SourceError("incomplete", "The AWS credential file is unexpectedly large.")
        if not (sig1 == fd_sig == sig2):
            last = SourceError("unstable", "The AWS credential file was replaced or modified while it was read.")
            sleep(0.1)
            continue
        wall = time.time() if now is None else now.timestamp()
        age = wall - sig2.mtime_ns / 1e9
        if 0 <= age < settle_seconds:                  # a writer may still be mid-write: let it settle, then re-read
            last = SourceError("unstable", "The AWS credential file was written moments ago.")
            sleep(settle_seconds - age + 0.02)
            continue
        values = parse_profile(raw, profile)
        access, secret = values.get("aws_access_key_id", ""), values.get("aws_secret_access_key", "")
        if not access and not secret:
            raise SourceError("no_static_keys", f"Profile {profile!r} holds no access keys (another credential provider is configured).")
        if not access or not secret or any(c.isspace() for c in access + secret):
            raise SourceError("incomplete", "The AWS credential profile is incomplete.")
        has_token_key = "aws_session_token" in values or "aws_security_token" in values
        token = values.get("aws_session_token") or values.get("aws_security_token") or None
        if has_token_key and not token:
            raise SourceError("incomplete", "The AWS session token is empty (file may be partially written).")
        if access.startswith("ASIA") and token is None:
            raise SourceError("incomplete", "Temporary access keys without a session token (file may be partially written).")
        stable_for = age if age >= 0 else 0.0
        if previous_had_token and token is None and stable_for < 30.0:
            raise SourceError("incomplete", "The new credential file lost its session token (file may be partially written).")   # accepted once it has been stable 30 s
        expiry = None
        for key in EXPIRY_KEYS:
            if values.get(key):
                expiry = parse_expiry(values[key])
                break
        if previous_had_expiry and token and expiry is None and stable_for < 30.0:
            raise SourceError("incomplete", "The new credential file lost its expiration marker (file may be partially written).")
        when = datetime.now(timezone.utc) if now is None else now
        identity = hashlib.sha256(f"{access}\0{token or ''}\0{expiry.isoformat() if expiry else ''}".encode()).hexdigest()[:20]
        return Loaded(access, secret, token, expiry, sig2, when, identity)
    raise last
