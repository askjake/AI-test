"""Root-only entrypoint bootstrap for the private Watch & Learn descriptors.

The container shell entrypoint invokes this module before any agent workload.
It validates and creates the private FIFO pair, opens inheritable descriptors,
then permanently drops supplementary groups, gid, and uid before exec.  The
module never reads the channel capability and never creates a listening socket.
"""
from __future__ import annotations

import argparse
import os
import pwd
import stat
from typing import Sequence


FIXED_CONTROL_DIR = "/app/watch-learn-control"


def _validate_control_directory(
    control_dir: str,
    *,
    expected_control_dir: str,
    owner_uid: int,
    owner_gid: int,
) -> None:
    if control_dir != expected_control_dir or not os.path.isabs(control_dir):
        raise ValueError("invalid Watch & Learn control mount")
    if owner_uid < 1 or owner_gid < 1:
        raise ValueError("unsafe Watch & Learn control owner")
    info = os.lstat(control_dir)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
    ):
        raise ValueError("unsafe Watch & Learn control mount")


def prepare_control_descriptors(
    control_dir: str,
    *,
    expected_control_dir: str,
    owner_uid: int,
    owner_gid: int,
) -> tuple[int, int]:
    """Create and open the validated private endpoints, cleaning partial failure."""
    _validate_control_directory(
        control_dir,
        expected_control_dir=expected_control_dir,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    paths = (
        os.path.join(control_dir, "requests.fifo"),
        os.path.join(control_dir, "responses.fifo"),
    )
    if any(os.path.lexists(path) for path in paths):
        raise ValueError("Watch & Learn control endpoint already exists")
    created: list[str] = []
    opened: list[int] = []
    try:
        for path in paths:
            os.mkfifo(path, 0o600)
            created.append(path)
            os.chmod(path, 0o600)
            os.chown(path, owner_uid, owner_gid)
            info = os.lstat(path)
            if (
                not stat.S_ISFIFO(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != owner_uid
                or info.st_gid != owner_gid
            ):
                raise ValueError("private control endpoint validation failed")
        for path in paths:
            descriptor = os.open(path, os.O_RDWR)
            os.set_inheritable(descriptor, True)
            opened.append(descriptor)
        return opened[0], opened[1]
    except BaseException:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for path in reversed(created):
            try:
                os.unlink(path)
            except OSError:
                pass
        raise


def drop_and_exec(
    *,
    runtime_user: str,
    command: Sequence[str],
    control_dir: str = "",
    expected_control_dir: str = FIXED_CONTROL_DIR,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> None:
    if os.getuid() != 0:
        raise PermissionError("entrypoint privilege bootstrap requires root")
    if not command or not command[0]:
        raise ValueError("entrypoint workload command is required")
    account = pwd.getpwnam(runtime_user)
    if account.pw_uid < 1 or account.pw_gid < 1:
        raise ValueError("entrypoint runtime user must be non-root")

    descriptors: tuple[int, int] | None = None
    if control_dir:
        if owner_uid is None or owner_gid is None:
            raise ValueError("Watch & Learn control ownership is required")
        descriptors = prepare_control_descriptors(
            control_dir,
            expected_control_dir=expected_control_dir,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        os.environ["WATCH_LEARN_REQUEST_FD"] = str(descriptors[0])
        os.environ["WATCH_LEARN_RESPONSE_FD"] = str(descriptors[1])
        print("WATCH_LEARN_STAGE=fifo_bootstrap", flush=True)

    os.environ["HOME"] = account.pw_dir
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.getuid() == 0 or os.getgid() == 0 or os.getgroups():
        raise PermissionError("entrypoint privilege drop did not become permanent")
    os.execvpe(command[0], list(command), os.environ)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-user", required=True)
    parser.add_argument("--control-dir", default="")
    parser.add_argument("--expected-control-dir", default=FIXED_CONTROL_DIR)
    parser.add_argument("--owner-uid", type=int)
    parser.add_argument("--owner-gid", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    drop_and_exec(
        runtime_user=arguments.runtime_user,
        command=command,
        control_dir=arguments.control_dir,
        expected_control_dir=arguments.expected_control_dir,
        owner_uid=arguments.owner_uid,
        owner_gid=arguments.owner_gid,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
