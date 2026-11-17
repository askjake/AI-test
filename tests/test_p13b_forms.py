"""Static contract tests for the Phase 13B guided dashboard forms.

The dashboard is intentionally a single server-rendered template.  These
checks keep its typed API wiring, security boundaries, accessibility signals,
and form-first entry points from regressing without requiring a browser, a
display, a target, or live credentials.
"""
from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (REPO_ROOT / "templates" / "dashboard" / "index.html").read_text()


def test_guided_authoring_is_the_primary_editor_and_legacy_source_is_secondary():
    assert "Phase 13B: form-first typed authoring workspace" in TEMPLATE
    assert 'data-tab="project"' in TEMPLATE
    assert "Project authoring" in TEMPLATE
    assert "Advanced / legacy source" in TEMPLATE
    assert "use the guided Project and Specifications forms for ordinary work" in TEMPLATE
    assert 'async function openEditor(name)' in TEMPLATE
    assert 'function openNewProjectDialog()' in TEMPLATE
    assert "Create project" in TEMPLATE


def test_guided_forms_cover_typed_targets_allowlists_and_write_only_password_saving():
    for target in ("local-app", "host-app", "ssh-terminal", "rdp", "vnc"):
        assert 'data-target-section="' + target + '"' in TEMPLATE
    for field in (
        "pa-local-app",
        "pa-host-cwd",
        "pa-ssh-key",
        "pa-rdp-password-file",
        "pa-rdp-certificate-name",
        "pa-rdp-certificate-fingerprint",
        "pa-connection-path",
        "pa-jump-known-hosts",
        "pa-jump-known-hosts-value",
        "pa-ssh-allowlist",
        "pa-rdp-allowlist",
        "pa-vnc-allowlist",
    ):
        assert 'id="' + field + '"' in TEMPLATE
    assert 'id="pa-vnc-gateway-password-file"' in TEMPLATE
    assert "saveTargetPassword(\\'gateway\\')" in TEMPLATE
    assert "saveJumpKnownHosts()" in TEMPLATE
    assert "/authoring/wizard/known-hosts" in TEMPLATE
    assert "Automatic key discovery is deliberately not used" in TEMPLATE
    assert "VNC uses an explicit loopback-only SSH local forward" in TEMPLATE
    assert "Reference name only; never enter a key value." in TEMPLATE
    assert "verified through an approved out-of-band process" in TEMPLATE
    for field in (
        "pa-rdp-password",
        "pa-vnc-password",
    ):
        match = re.search(r'<input id="' + field + r'"[^>]*>', TEMPLATE)
        assert match
        assert 'type="password"' in match.group(0)
        assert "data-project-input" not in match.group(0)
    for field in (
        "pa-rdp-password-confirm",
        "pa-vnc-password-confirm",
        "pa-gateway-password-confirm",
    ):
        assert f'id="{field}"' not in TEMPLATE
    assert "ids.confirm" not in TEMPLATE
    assert "two password entries" not in TEMPLATE
    assert "never kept in the wizard draft or project file" in TEMPLATE
    assert "/authoring/wizard/passwords" in TEMPLATE
    assert 'id="pa-manual-dir"' not in TEMPLATE
    assert "managed manual location" in TEMPLATE


def test_guided_forms_use_typed_validate_preview_apply_and_conflict_routes():
    for route in (
        "/authoring/project/validate",
        "/authoring/project",
        "/authoring/specs/validate",
        "/authoring/specs",
        "/authoring/wizard/validate",
        "/projects/authoring",
    ):
        assert route in TEMPLATE
    assert "base_revision" in TEMPLATE
    assert "Validation passed. Apply is now available" in TEMPLATE
    assert "Revision conflict. Your local form was retained." in TEMPLATE
    assert "Reload latest" in TEMPLATE
    assert "Compare" in TEMPLATE
    assert "Canonical YAML preview" in TEMPLATE
    assert "Canonical Markdown preview" in TEMPLATE
    assert "boundedAuthoringDiff" in TEMPLATE


def test_structured_assertions_are_accessible_and_not_drag_only():
    assert 'id="sa-assertions"' in TEMPLATE
    assert "addAuthoringAssertion" in TEMPLATE
    assert "moveAuthoringAssertion" in TEMPLATE
    assert "Delete assertion" in TEMPLATE
    assert 'aria-label", "Assertion "' in TEMPLATE
    assert "Discard local, unsaved authoring changes?" in TEMPLATE
    assert 'summary.focus()' in TEMPLATE


def test_authoring_does_not_add_target_activity_and_keeps_passwords_out_of_drafts():
    assert "never launches a target" in TEMPLATE
    assert "target type never changes an allowlist" in TEMPLATE
    assert "apiOp" in TEMPLATE
    assert "EventSource(url + \"?token=\"" not in TEMPLATE
    draft = TEMPLATE[TEMPLATE.index("function saveWizardDraft()") : TEMPLATE.index("function restoreWizardDraft()")]
    assert "pa-rdp-password" not in draft
    assert "pa-vnc-password" not in draft
    assert "pa-jump-known-hosts-value" not in draft
