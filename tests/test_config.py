"""Phase 0 tests for orchestrator.config (P0-3..P0-5)."""

from __future__ import annotations

import pytest

from orchestrator.config import Settings


def test_loads_with_defaults(monkeypatch):
    """P0-3: config loads with safe defaults, no exception."""
    # A developer shell may legitimately export any runtime setting. This test
    # verifies model defaults, so isolate every Settings-owned environment key
    # instead of depending on the caller's login environment.
    for field_name in Settings.model_fields:
        monkeypatch.delenv(field_name.upper(), raising=False)
    s = Settings()
    assert s.aws_region
    assert s.bedrock_model_id is None
    assert s.max_steps >= 1
    assert s.ssh_host_allowlist == []
    assert s.rdp_host_allowlist == []
    assert s.computer_use_tool_type == "computer_20251124"
    assert s.computer_use_beta == "computer-use-2025-11-24"


def test_env_overrides(monkeypatch):
    """P0-4: values come from env, not hard-coded defaults."""
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "custom-arn")
    monkeypatch.setenv("MAX_STEPS", "7")
    s = Settings()
    assert s.aws_region == "eu-west-1"
    assert s.bedrock_model_id == "custom-arn"
    assert s.max_steps == 7


def test_allowlist_csv(monkeypatch):
    monkeypatch.setenv("SSH_HOST_ALLOWLIST", "build01, build02 ,build03")
    s = Settings()
    assert s.ssh_host_allowlist == ["build01", "build02", "build03"]


def test_allowlist_json(monkeypatch):
    monkeypatch.setenv("RDP_HOST_ALLOWLIST", '["win01", "win02"]')
    s = Settings()
    assert s.rdp_host_allowlist == ["win01", "win02"]


def test_allowlist_empty(monkeypatch):
    monkeypatch.setenv("SSH_HOST_ALLOWLIST", "")
    s = Settings()
    assert s.ssh_host_allowlist == []


def test_no_secret_fields():
    """P0-5: no secret-bearing fields exist in config."""
    fields = set(Settings.model_fields)
    forbidden = {"ssh_key", "ssh_private_key", "rdp_password", "password",
                 "aws_secret_access_key", "aws_access_key_id", "secret"}
    assert not (fields & forbidden)


@pytest.mark.parametrize(
    ("tool_type", "beta"),
    [
        ("computer_20250124", "computer-use-2025-01-24"),
        ("computer_20251124", "computer-use-2025-11-24"),
    ],
)
def test_reviewed_computer_use_pairs(tool_type, beta):
    settings = Settings(
        computer_use_tool_type=tool_type,
        computer_use_beta=beta,
    )
    assert settings.computer_use_tool_type == tool_type
    assert settings.computer_use_beta == beta


def test_mismatched_computer_use_pair_fails_closed():
    with pytest.raises(ValueError, match="reviewed matching pair"):
        Settings(
            computer_use_tool_type="computer_20251124",
            computer_use_beta="computer-use-2025-01-24",
        )


def test_unreviewed_computer_use_tool_type_fails_closed():
    with pytest.raises(ValueError, match="not a reviewed native tool type"):
        Settings(
            computer_use_tool_type="computer_unreviewed",
            computer_use_beta="computer-use-unreviewed",
        )
