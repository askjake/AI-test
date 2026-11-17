"""Privately mirror a rotating host AWS credential file into the runtime tmpfs.

The dashboard is deliberately long lived, while workstation STS credentials are not.  A
spawned container must therefore avoid both the dashboard's frozen AWS environment and a
one-time credential snapshot.  This helper is launched by the root bootstrap with a narrow,
fixed purpose: monitor the read-only bind-mounted credentials/config files and atomically
refresh private copies readable by the uid-10001 runtime account.

It never parses, prints, or transmits credential values.  The helper retains only
``CAP_CHOWN`` and ``CAP_DAC_READ_SEARCH``; target, agent, and model code remains non-root.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import pwd
import shutil
import stat
import time
from pathlib import Path


MAX_POSTPONES = 10
_POSTPONED: dict[str, int] = {}


class CredentialSyncError(RuntimeError):
    """The credential source or runtime destination violates the bridge contract."""


_CAP_CHOWN = 0
_CAP_DAC_READ_SEARCH = 2
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _limit_capabilities() -> None:
    """Reduce a root sync helper to the two filesystem capabilities it needs."""
    if os.geteuid() != 0:
        return
    try:
        os.setgroups([])
        libc = ctypes.CDLL(None, use_errno=True)
        header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
        data = (_CapData * 2)()
        for capability in (_CAP_CHOWN, _CAP_DAC_READ_SEARCH):
            index = capability // 32
            bit = 1 << (capability % 32)
            data[index].effective |= bit
            data[index].permitted |= bit
        if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
    except OSError as exc:
        raise CredentialSyncError("could not reduce credential-sync capabilities") from exc


def _validated_source(path: Path) -> os.stat_result:
    try:
        source_stat = path.lstat()
    except OSError as exc:
        raise CredentialSyncError("AWS credential source is unavailable") from exc
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
        raise CredentialSyncError("AWS credential source must be a regular non-symlink file")
    return source_stat


def _signature_of(st: os.stat_result) -> tuple[int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)


def _copy_atomic(source: Path, destination: Path, *, uid: int, gid: int) -> None:
    before = _signature_of(_validated_source(source))
    temporary = destination.with_name(f".{destination.name}.tmp.{os.getpid()}")
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd = destination_fd = None
    try:
        source_fd = os.open(source, source_flags)
        destination_fd = os.open(temporary, destination_flags, 0o400)
        if _signature_of(os.fstat(source_fd)) != before:
            raise CredentialSyncError("AWS credential source was replaced while it was being opened")
        with os.fdopen(source_fd, "rb", closefd=False) as source_fh:
            with os.fdopen(destination_fd, "wb", closefd=False) as destination_fh:
                shutil.copyfileobj(source_fh, destination_fh)
                destination_fh.flush()
                os.fsync(destination_fd)
        # A non-atomic writer may have been mid-write: never publish a copy of a file that changed while it was read.
        if _signature_of(os.fstat(source_fd)) != before:
            raise CredentialSyncError("AWS credential source changed while it was being copied; the next poll retries")
        os.fchmod(destination_fd, 0o400)
        if os.geteuid() == 0:
            os.fchown(destination_fd, uid, gid)
        elif uid != os.geteuid() or gid != os.getegid():
            raise CredentialSyncError(
                "non-root credential sync cannot assign a different runtime identity"
            )
        os.close(destination_fd)                       # publish only a fully written, closed file (also required on platforms that cannot rename an open file)
        destination_fd = None
        os.replace(temporary, destination)
    except OSError as exc:
        raise CredentialSyncError("could not refresh the private AWS credential copy") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def sync_once(
    credentials_source: str,
    destination_dir: str,
    *,
    config_source: str | None = None,
    uid: int,
    gid: int,
    previous: dict[str, tuple[int, int, int, int]] | None = None,
    settle_seconds: float = 0.0,
) -> tuple[int, dict[str, tuple[int, int, int, int]]]:
    """Refresh changed AWS files and return their count plus source signatures.

    ``settle_seconds`` (the poll loop uses 0.5) postpones a source that was modified that recently, so a non-atomic writer is not
    copied half-written.  It never applies to the first staging pass, which must produce a file.
    """
    credentials_path = Path(credentials_source)
    config_path = Path(config_source) if config_source else None
    destination_root = Path(destination_dir)

    destination_root.mkdir(mode=0o710, parents=True, exist_ok=True)
    os.chmod(destination_root, 0o710, follow_symlinks=False)
    if os.geteuid() == 0:
        # Production: keep the refresh directory root-owned and group-traversable by the
        # runtime account so the capability-limited root bridge can replace files atomically.
        os.chown(destination_root, 0, gid, follow_symlinks=False)
    elif uid != os.geteuid() or gid != os.getegid():
        # Unit tests and library callers may exercise the pure sync primitive without root,
        # but may not use that path to manufacture files for another identity.
        raise CredentialSyncError(
            "non-root credential sync requires the current uid and gid"
        )

    signatures = dict(previous or {})
    refreshed = 0
    sources = [("credentials", credentials_path), ("config", config_path)]
    for name, source in sources:
        if source is None or not source.exists():
            continue
        source_stat = _validated_source(source)
        signature = (
            source_stat.st_dev,
            source_stat.st_ino,
            source_stat.st_mtime_ns,
            source_stat.st_size,
        )
        destination = destination_root / name
        if signatures.get(name) == signature and destination.is_file():
            continue
        if settle_seconds > 0 and previous is not None and destination.is_file() and 0 <= time.time() - source_stat.st_mtime < settle_seconds:
            _POSTPONED[name] = _POSTPONED.get(name, 0) + 1
            if _POSTPONED[name] <= MAX_POSTPONES:
                continue                              # recently written: wait for the next poll (the signature is not recorded)
            # A writer that keeps touching the file must not starve publication: the post-copy signature check in _copy_atomic still guarantees
            # that only a copy of a file that did not change while it was read is published.
        _POSTPONED.pop(name, None)
        _copy_atomic(source, destination, uid=uid, gid=gid)
        signatures[name] = signature
        refreshed += 1
    if "credentials" not in signatures:
        raise CredentialSyncError("AWS credentials file is missing from the source mount")
    return refreshed, signatures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials-source", required=True)
    parser.add_argument("--config-source")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--user", default="orchestrator")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args(argv)
    if not 0.25 <= args.interval <= 60:
        print("[credentials] FATAL: sync interval must be between 0.25 and 60 seconds", flush=True)
        return 78

    account = pwd.getpwnam(args.user)
    try:
        refreshed, signatures = sync_once(
            args.credentials_source,
            args.destination,
            config_source=args.config_source,
            uid=account.pw_uid,
            gid=account.pw_gid,
        )
        _limit_capabilities()
    except CredentialSyncError as exc:
        print(f"[credentials] FATAL: {exc}", flush=True)
        return 78

    print(
        f"[credentials] staged {refreshed} current AWS file(s); refresh bridge active",
        flush=True,
    )
    while True:
        time.sleep(args.interval)
        try:
            refreshed, signatures = sync_once(
                args.credentials_source,
                args.destination,
                config_source=args.config_source,
                uid=account.pw_uid,
                gid=account.pw_gid,
                previous=signatures,
                settle_seconds=0.5,
            )
        except CredentialSyncError as exc:
            print(f"[credentials] refresh warning: {exc}", flush=True)
            continue
        if refreshed:
            print(f"[credentials] refreshed {refreshed} AWS file(s)", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
