from __future__ import annotations

import os
import stat

import pytest

from orchestrator import credential_sync
from orchestrator.credential_sync import CredentialSyncError, sync_once


def test_sync_once_creates_private_runtime_copy(tmp_path):
    source = tmp_path / "host" / "credentials"
    source.parent.mkdir()
    source.write_text("[default]\naws_session_token=first\n")
    source.chmod(0o600)
    runtime = tmp_path / "runtime"

    count, signatures = sync_once(
        str(source),
        str(runtime),
        uid=os.getuid(),
        gid=os.getgid(),
    )

    copied = runtime / "credentials"
    assert count == 1
    assert copied.read_text() == source.read_text()
    assert stat.S_IMODE(copied.stat().st_mode) == 0o400
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o710
    assert "credentials" in signatures


def test_sync_once_observes_atomic_host_replacement(tmp_path):
    host = tmp_path / "host"
    host.mkdir()
    source = host / "credentials"
    source.write_text("[default]\naws_session_token=first\n")
    source.chmod(0o600)
    runtime = tmp_path / "runtime"

    _count, signatures = sync_once(
        str(source), str(runtime), uid=os.getuid(), gid=os.getgid()
    )
    replacement = host / "credentials.new"
    replacement.write_text("[default]\naws_session_token=second\n")
    replacement.chmod(0o600)
    replacement.replace(source)

    count, signatures = sync_once(
        str(source),
        str(runtime),
        uid=os.getuid(),
        gid=os.getgid(),
        previous=signatures,
    )

    assert count == 1
    assert "second" in (runtime / "credentials").read_text()


def test_sync_once_skips_unchanged_source(tmp_path):
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=stable\n")
    runtime = tmp_path / "runtime"
    _count, signatures = sync_once(
        str(source), str(runtime), uid=os.getuid(), gid=os.getgid()
    )

    count, _signatures = sync_once(
        str(source),
        str(runtime),
        uid=os.getuid(),
        gid=os.getgid(),
        previous=signatures,
    )
    assert count == 0


def test_sync_once_non_root_does_not_attempt_ownership_changes(tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=nonroot\n")
    runtime = tmp_path / "runtime"

    monkeypatch.setattr(credential_sync.os, "geteuid", lambda: 1003)
    monkeypatch.setattr(credential_sync.os, "getegid", lambda: 1004)

    def reject_chown(*_args, **_kwargs):
        raise AssertionError("non-root sync attempted a root-only ownership change")

    monkeypatch.setattr(credential_sync.os, "chown", reject_chown)
    monkeypatch.setattr(credential_sync.os, "fchown", reject_chown)

    count, _signatures = sync_once(
        str(source), str(runtime), uid=1003, gid=1004
    )

    assert count == 1
    assert "nonroot" in (runtime / "credentials").read_text()


def test_sync_once_non_root_rejects_a_different_runtime_identity(tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=nonroot\n")

    monkeypatch.setattr(credential_sync.os, "geteuid", lambda: 1003)
    monkeypatch.setattr(credential_sync.os, "getegid", lambda: 1004)

    with pytest.raises(CredentialSyncError, match="current uid and gid"):
        sync_once(
            str(source),
            str(tmp_path / "runtime"),
            uid=10001,
            gid=10001,
        )


def test_sync_once_does_not_publish_a_copy_of_a_file_that_changed_while_it_was_read(tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=first\n")
    runtime = tmp_path / "runtime"
    _count, signatures = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid())
    published = (runtime / "credentials").read_text()
    source.write_text("[default]\naws_session_token=second-but-longer\n")
    real = credential_sync.shutil.copyfileobj

    def racing_copy(src, dst, *args):
        real(src, dst, *args)
        with open(source, "a") as handle:                    # the writer is still going while we copy
            handle.write("# more\n")

    monkeypatch.setattr(credential_sync.shutil, "copyfileobj", racing_copy)
    with pytest.raises(CredentialSyncError, match="changed while it was being copied"):
        sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), previous=signatures)
    assert (runtime / "credentials").read_text() == published          # the previous good copy is untouched
    assert not [p for p in runtime.iterdir() if ".tmp." in p.name]       # and no partial temporary file remains


def test_sync_loop_postpones_a_just_written_source_but_the_first_pass_never_does(tmp_path):
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=first\n")
    runtime = tmp_path / "runtime"
    count, signatures = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), settle_seconds=5.0)
    assert count == 1                                                    # first staging pass ignores the settle window
    source.write_text("[default]\naws_session_token=second\n")
    count, signatures2 = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), previous=signatures, settle_seconds=5.0)
    assert count == 0 and "first" in (runtime / "credentials").read_text() and signatures2 == signatures
    os.utime(source, (os.stat(source).st_atime, os.stat(source).st_mtime - 10))
    count, _s = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), previous=signatures, settle_seconds=5.0)
    assert count == 1 and "second" in (runtime / "credentials").read_text()


def test_a_writer_that_keeps_touching_the_source_cannot_starve_publication(tmp_path):
    credential_sync._POSTPONED.clear()
    source = tmp_path / "credentials"
    source.write_text("[default]\naws_session_token=first\n")
    runtime = tmp_path / "runtime"
    _count, signatures = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), settle_seconds=5.0)
    source.write_text("[default]\naws_session_token=second\n")
    counts = []
    for _ in range(credential_sync.MAX_POSTPONES + 2):
        count, signatures = sync_once(str(source), str(runtime), uid=os.getuid(), gid=os.getgid(), previous=signatures, settle_seconds=5.0)
        counts.append(count)
    assert counts[:credential_sync.MAX_POSTPONES] == [0] * credential_sync.MAX_POSTPONES and sum(counts) == 1
    assert "second" in (runtime / "credentials").read_text()
