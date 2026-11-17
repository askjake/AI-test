from __future__ import annotations

import os
import stat

import pytest

from orchestrator.secret_stage import SecretStageError, stage_secrets


def test_owner_only_host_secret_is_staged_private_and_readable(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "runtime"
    source.mkdir(mode=0o700)
    secret = source / "rdp.pass"
    secret.write_text("correct horse battery staple\n")
    secret.chmod(0o600)

    count = stage_secrets(
        str(source),
        str(destination),
        uid=os.getuid(),
        gid=os.getgid(),
    )

    staged = destination / "rdp.pass"
    assert count == 1
    assert staged.read_text() == "correct horse battery staple\n"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(staged.stat().st_mode) == 0o400
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600


def test_nested_secret_directories_are_private(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "runtime"
    nested = source / "gateway" / "prod"
    nested.mkdir(parents=True)
    (nested / "ssh.key").write_bytes(b"private-key-placeholder")

    stage_secrets(
        str(source),
        str(destination),
        uid=os.getuid(),
        gid=os.getgid(),
    )

    assert stat.S_IMODE((destination / "gateway").stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "gateway" / "prod").stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "gateway" / "prod" / "ssh.key").stat().st_mode) == 0o400


def test_secret_source_symlink_is_rejected(tmp_path):
    real_source = tmp_path / "real"
    real_source.mkdir()
    source_link = tmp_path / "source"
    source_link.symlink_to(real_source, target_is_directory=True)

    with pytest.raises(SecretStageError, match="real directory"):
        stage_secrets(
            str(source_link),
            str(tmp_path / "runtime"),
            uid=os.getuid(),
            gid=os.getgid(),
        )


def test_secret_entry_symlink_is_rejected_without_copying_target(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("must-not-be-copied")
    (source / "escape.pass").symlink_to(outside)

    with pytest.raises(SecretStageError, match="symlinks are forbidden"):
        stage_secrets(
            str(source),
            str(tmp_path / "runtime"),
            uid=os.getuid(),
            gid=os.getgid(),
        )


def test_nonempty_runtime_destination_is_rejected(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "runtime"
    source.mkdir()
    destination.mkdir()
    (destination / "unexpected").write_text("stale")

    with pytest.raises(SecretStageError, match="not empty"):
        stage_secrets(
            str(source),
            str(destination),
            uid=os.getuid(),
            gid=os.getgid(),
        )
