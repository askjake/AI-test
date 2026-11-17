"""Stage host-owned secret files into a private container tmpfs.

Host secret files deliberately remain mode ``0600`` and owned by the operator. A bind
mount preserves that ownership, so the image's uid-10001 ``orchestrator`` account cannot
read them directly. The container therefore starts a very small root-only bootstrap:

1. mount the host directory read-only at ``/app/secrets-source``;
2. copy regular files into the tmpfs at ``/app/secrets``;
3. make directories ``0700`` and files ``0400`` owned by ``orchestrator``; and
4. permanently drop privileges before any target or agent code runs.

No source permissions are weakened. Symlinks and special files are rejected so the staging
copy cannot escape the mounted directory or smuggle devices/sockets into the runtime view.
"""

from __future__ import annotations

import argparse
import os
import pwd
import shutil
import stat
from pathlib import Path


class SecretStageError(RuntimeError):
    """The source or destination violates the runtime secret contract."""


def _chown_chmod_directory(path: Path, uid: int, gid: int) -> None:
    # The bootstrap has CAP_CHOWN but intentionally not CAP_FOWNER. Apply the mode while
    # root still owns the directory, then transfer ownership as the final operation.
    os.chmod(path, 0o700, follow_symlinks=False)
    os.chown(path, uid, gid, follow_symlinks=False)


def stage_secrets(source: str, destination: str, *, uid: int, gid: int) -> int:
    """Copy a secret tree without following links; return the number of files staged."""
    source_root = Path(source)
    destination_root = Path(destination)

    try:
        source_stat = source_root.lstat()
    except OSError as exc:
        raise SecretStageError("secret source directory is unavailable") from exc
    if not stat.S_ISDIR(source_stat.st_mode) or source_root.is_symlink():
        raise SecretStageError("secret source must be a real directory, not a symlink")

    if destination_root.exists():
        if destination_root.is_symlink() or not destination_root.is_dir():
            raise SecretStageError("runtime secret destination must be a real directory")
        if any(destination_root.iterdir()):
            raise SecretStageError("runtime secret tmpfs is not empty")
    else:
        destination_root.mkdir(parents=True, mode=0o700)
    # Keep destination directories root-owned until every file exists. The bootstrap has
    # CAP_DAC_READ_SEARCH (to read 0600 host files) and CAP_CHOWN, but deliberately does not
    # have broad CAP_DAC_OVERRIDE. Chowning a 0700 directory early would prevent the bounded
    # bootstrap itself from creating later children inside it.
    os.chmod(destination_root, 0o700, follow_symlinks=False)

    staged = 0
    for current, directories, files in os.walk(source_root, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source_root)
        destination_dir = destination_root / relative_dir
        destination_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(destination_dir, 0o700, follow_symlinks=False)

        for name in list(directories):
            candidate = current_path / name
            candidate_stat = candidate.lstat()
            if stat.S_ISLNK(candidate_stat.st_mode):
                raise SecretStageError("symlinks are forbidden in the secret source")
            if not stat.S_ISDIR(candidate_stat.st_mode):
                raise SecretStageError("special entries are forbidden in the secret source")

        for name in files:
            source_file = current_path / name
            source_file_stat = source_file.lstat()
            if stat.S_ISLNK(source_file_stat.st_mode):
                raise SecretStageError("symlinks are forbidden in the secret source")
            if not stat.S_ISREG(source_file_stat.st_mode):
                raise SecretStageError("special entries are forbidden in the secret source")

            destination_file = destination_dir / name
            source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            destination_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                source_fd = os.open(source_file, source_flags)
                try:
                    destination_fd = os.open(destination_file, destination_flags, 0o400)
                    try:
                        with os.fdopen(source_fd, "rb", closefd=False) as source_fh:
                            with os.fdopen(destination_fd, "wb", closefd=False) as destination_fh:
                                shutil.copyfileobj(source_fh, destination_fh)
                                destination_fh.flush()
                        os.fchmod(destination_fd, 0o400)
                        os.fchown(destination_fd, uid, gid)
                    finally:
                        os.close(destination_fd)
                finally:
                    os.close(source_fd)
            except OSError as exc:
                raise SecretStageError("could not stage a runtime secret") from exc
            staged += 1

    # Ownership moves only after the complete tree is present. Walk bottom-up so no parent
    # becomes inaccessible to the intentionally capability-limited bootstrap too early.
    for current, _directories, _files in os.walk(destination_root, topdown=False):
        # Each directory appears once as ``current``. Do not touch children again from
        # their parent after ownership has already moved to the runtime account.
        _chown_chmod_directory(Path(current), uid, gid)

    return staged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--user", default="orchestrator")
    args = parser.parse_args(argv)

    account = pwd.getpwnam(args.user)
    try:
        count = stage_secrets(
            args.source,
            args.destination,
            uid=account.pw_uid,
            gid=account.pw_gid,
        )
    except SecretStageError as exc:
        print(f"[secrets] FATAL: {exc}", flush=True)
        return 78

    print(f"[secrets] staged {count} file(s) into private runtime tmpfs", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
