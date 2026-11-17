"""CP45-G (G2): hand dashboard-precreated report paths to the runner uid, BEFORE the privilege drop.

Contract (see docs/G2_PERMISSION_CONTRACT.md): the reports root and every project directory stay dashboard-owned 0755.  For one run the dashboard
precreates exactly three paths and this module (root phase of docker/entrypoint.sh) chowns them to the runner account:
  reports/<project>/.nrdp-runs/<trigger_id>/   run folder (its ``control/`` child stays dashboard-owned; chown is NOT recursive)
  reports/<project>/<run_ts>/                  report folder (run_ts is chosen by the dashboard and forwarded as ORCHESTRATOR_RUN_TS)
  reports/<project>/index.html                 project index file (rewritten in place by the runner)
Needs only CAP_CHOWN (+ search access), both already granted to the runner launcher; no DAC_OVERRIDE, no ACL, no group membership
(the entrypoint's drop clears supplementary groups on purpose).  Every step is strict and failure exits non-zero: a missing, foreign, linked or
group/world-writable path is a visible launch failure, never a silent fallback.
"""
from __future__ import annotations

import argparse
import os
import pwd
import re
import stat
import sys
from typing import Callable, Sequence

PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
TRIGGER_RE = re.compile(r"^trig_[A-Za-z0-9_-]+$")
RUN_TS_RE = re.compile(r"^\d{8}T\d{6}Z$")
REPORTS_ROOT = "/app/reports"
RUNS_SUBDIR = ".nrdp-runs"


class HandoffError(RuntimeError):
    """A path cannot be handed to the runner safely."""


def targets(project: str, trigger_id: str, run_ts: str) -> list[tuple[tuple[str, ...], str]]:
    if not (isinstance(project, str) and PROJECT_RE.fullmatch(project)):
        raise HandoffError("invalid project name")
    if not (isinstance(trigger_id, str) and TRIGGER_RE.fullmatch(trigger_id)):
        raise HandoffError("invalid trigger id")
    if not (isinstance(run_ts, str) and RUN_TS_RE.fullmatch(run_ts)):
        raise HandoffError("invalid run timestamp")
    return [((project, RUNS_SUBDIR, trigger_id), "dir"), ((project, run_ts), "dir"), ((project, "index.html"), "file")]


def _flags(directory: bool) -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | (getattr(os, "O_DIRECTORY", 0) if directory else 0)


def hand_off(reports_root: str, project: str, trigger_id: str, run_ts: str, *, dashboard_uid: int, uid: int, gid: int,
             fchown: Callable[[int, int, int], None] = os.fchown) -> list[str]:
    handed: list[str] = []
    try:
        root_fd = os.open(reports_root, _flags(True))
    except OSError as exc:
        raise HandoffError("reports root is not usable: %s" % (exc.strerror or type(exc).__name__)) from exc
    try:
        for parts, kind in targets(project, trigger_id, run_ts):
            shown = "/".join(parts)
            opened: list[int] = []
            try:
                current = root_fd
                for name in parts[:-1]:
                    current = os.open(name, _flags(True), dir_fd=current)
                    opened.append(current)
                    info = os.fstat(current)
                    if info.st_uid != dashboard_uid or info.st_mode & 0o022:
                        raise HandoffError("parent of %s is not a dashboard-owned, non-shared directory" % shown)
                leaf = os.open(parts[-1], _flags(kind == "dir"), dir_fd=current)
                opened.append(leaf)
                info = os.fstat(leaf)
                if not (stat.S_ISDIR(info.st_mode) if kind == "dir" else stat.S_ISREG(info.st_mode)):
                    raise HandoffError("%s is not a %s" % (shown, "directory" if kind == "dir" else "regular file"))
                if info.st_mode & 0o022:
                    raise HandoffError("%s is group- or world-writable" % shown)
                if kind == "file" and info.st_nlink != 1:
                    raise HandoffError("%s has more than one link" % shown)
                if not (info.st_uid == uid and info.st_gid == gid):
                    if info.st_uid != dashboard_uid:
                        raise HandoffError("%s is owned by neither the dashboard nor the runner" % shown)
                    fchown(leaf, uid, gid)
                handed.append(shown)
            except OSError as exc:
                raise HandoffError("cannot hand off %s: %s" % (shown, exc.strerror or type(exc).__name__)) from exc
            finally:
                for fd in opened:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
    finally:
        os.close(root_fd)
    return handed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-user", required=True)
    parser.add_argument("--reports-root", default=REPORTS_ROOT)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise HandoffError("must run as root before the privilege drop")
        account = pwd.getpwnam(args.runtime_user)
        if account.pw_uid < 1 or account.pw_gid < 1:
            raise HandoffError("runtime user must be non-root")
        raw = env.get("ORCHESTRATOR_CONTROL_UID", "")
        if not raw.isdigit() or int(raw) < 1 or int(raw) == account.pw_uid:
            raise HandoffError("ORCHESTRATOR_CONTROL_UID must be the dashboard's non-root uid, different from the runner's")
        done = hand_off(args.reports_root, env.get("ORCHESTRATOR_REPORT_PROJECT", ""), env.get("ORCHESTRATOR_TRIGGER_ID", ""),
                        env.get("ORCHESTRATOR_RUN_TS", ""), dashboard_uid=int(raw), uid=account.pw_uid, gid=account.pw_gid)
    except (HandoffError, KeyError) as exc:
        print("[report-handoff] FATAL: %s" % exc, file=sys.stderr)
        return 78
    print("[report-handoff] handed %d path(s) to uid=%d gid=%d: %s" % (len(done), account.pw_uid, account.pw_gid, ", ".join(done)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
