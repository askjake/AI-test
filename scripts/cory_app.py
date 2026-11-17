"""Local dashboard lifecycle convenience; preserves configuration and identity."""
from __future__ import annotations
import argparse
try:  # POSIX only; the native Windows lineage uses the `nrdp` command instead
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def port_available(host, port):
    """True when a dashboard may bind (free, or no listener is detected).

    A live listener is never available.  Raises RuntimeError when the port cannot
    be tested at all (permission, bad address) instead of retrying a hopeless check.
    """
    from orchestrator_cookie.portcheck import PortProbeError, port_available as probe
    try:
        return probe(host, port)
    except PortProbeError as exc:
        raise RuntimeError(str(exc)) from exc.original


def archive_dead_metadata(repo, cfg):
    from orchestrator_cookie.config import runtime_root, PROCESS_RELATIVE
    from orchestrator_cookie.lifecycle import dashboard_status
    path = runtime_root(repo) / PROCESS_RELATIVE
    if not path.exists():
        return
    if dashboard_status(repo, cfg).running:
        return
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Dashboard metadata is not a regular file.')
    raw = path.read_bytes()
    metadata = json.loads(raw)
    pid = metadata.get('pid')
    if type(pid) is not int or pid < 2:
        raise RuntimeError('Invalid recorded PID; metadata retained for inspection.')
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise RuntimeError('Recorded PID is still present but cannot be authenticated; no process was signalled.')
    host, port = metadata.get('bind_host'), metadata.get('port')
    if host != cfg.bind_host or type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError('Recorded endpoint differs from configuration; metadata retained.')
    if not port_available(host, port):
        raise RuntimeError('Recorded dashboard port is occupied; metadata retained.')
    if path.read_bytes() != raw:
        raise RuntimeError('Dashboard metadata changed during recovery; retry status.')
    backup = Path(tempfile.mkdtemp(prefix='stale-dashboard-', dir=path.parent))
    path.rename(backup / path.name)
    print('STALE_METADATA_ARCHIVED=' + str(backup), flush=True)


def _port_evidence(port):
    try:
        from orchestrator_cookie.portcheck import format_port_report, port_socket_report
        return format_port_report(port_socket_report(port))
    except Exception as exc:  # evidence must never mask the real error
        return 'socket evidence unavailable (' + type(exc).__name__ + ')'


def wait_for_port(cfg, timeout=90, *, probe=None, sleep=time.sleep, clock=time.monotonic, evidence=None):
    """Wait (bounded) until the dashboard port may be bound.

    * free                       -> return
    * no listener detected       -> report it and return (the server binds with SO_REUSEADDR)
    * live listener              -> keep polling until `timeout`, then refuse.
    Nothing is killed or signalled.  A KeyboardInterrupt/SystemExit propagates untouched.
    """
    if probe is None:
        from orchestrator_cookie.portcheck import probe_port as probe_impl, PortProbeError

        def probe(host, port):
            try:
                return probe_impl(host, port)
            except PortProbeError as exc:
                raise RuntimeError(str(exc)) from exc.original
    deadline = clock() + timeout
    while True:
        result = probe(cfg.bind_host, cfg.preferred_port)
        if result.bindable:
            if result.state != 'free':
                print('CORY_APP_PORT=no-listener-detected on ' + str(cfg.bind_host) + ':' + str(cfg.preferred_port)
                      + ' (plain bind refused, SO_REUSEADDR bind ok, no connection accepted); continuing', flush=True)
            return
        remaining = deadline - clock()
        if remaining <= 0:
            note = (evidence or _port_evidence)(cfg.preferred_port)
            raise RuntimeError('Dashboard port ' + str(cfg.bind_host) + ':' + str(cfg.preferred_port)
                               + ' is still held by a listener or an unidentified socket after ' + str(timeout)
                               + ' s. Run ./cory-app status; this check did not stop or signal any process,'
                               + ' and no unrelated process was stopped. Evidence: ' + note)
        sleep(min(1.0, remaining))


def acquire_lock(lock):
    """Single controlled lifecycle command per checkout; a concurrent one is refused, not queued."""
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another cory-app command is already running for this checkout; nothing was changed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'stop', 'restart', 'status'])
    args = parser.parse_args()
    if fcntl is None:
        raise RuntimeError('cory-app is the POSIX launcher; on native Windows use the nrdp command.')
    repo = Path(__file__).resolve().parents[1]
    from orchestrator_cookie.config import load_config, runtime_root
    if args.action in ('start', 'restart'):
        # CP45-S D2: refuse BEFORE the lifecycle lock, state directory, configuration read, stop or any other file is touched (stop and status are never guarded: recovery needs them)
        from dashboard.switch_guard import require_resolved
        require_resolved(runtime_root(repo) / 'reports')
    from orchestrator_cookie.lifecycle import dashboard_status
    cfg = load_config(repo)
    lockpath = runtime_root(repo) / 'state' / 'cory-app.lock'
    lockpath.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    with lockpath.open('a') as lock:
        acquire_lock(lock)
        def command(action):
            subprocess.run(['bash', str(repo / 'install.sh'), action], cwd=repo, check=True)
        if args.action == 'status':
            command('status')
            return
        archive_dead_metadata(repo, cfg)
        if args.action in ('stop', 'restart'):
            command('stop')
        if args.action in ('start', 'restart'):
            if not dashboard_status(repo, cfg).running:
                wait_for_port(cfg)
            command('start')
        command('status')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit('CORY_APP: ' + str(exc))
