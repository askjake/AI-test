# Project-folder import verification and handoff

Date: 2026-09-08 UTC

## Source and prerequisite gate

- Authoritative source archive manifest: 255 of 255 files matched.
- Handoff manifest: 4 of 4 files matched.
- Owner evidence recorded the local OIDC patch as commit `4e8eab5`, with only the
  expected 12 OIDC files in that commit.
- Owner evidence recorded safety tag
  `safety/pre-project-folder-import-4e8eab5-20260908` and clean feature worktree
  `/tmp/ai-test-project-folder-import-20260908` on
  `feature/project-folder-import-20260908`.
- The original `/tmp/ai-test` worktree retained an unrelated untracked
  `tests_manuals/test/manual.md`. It was not copied into, deleted from, committed with,
  or otherwise used by this feature.
- Owner baseline suite: `535 passed, 1 skipped, 30 warnings`.

## Observed gates

| Gate | Exact command | Observed result |
|---|---|---|
| Managed environment | `./install.sh init --with-test` | Success; pinned runtime, dashboard, and test profiles installed |
| Import adversarial suite | `PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q tests/test_project_import.py` | `40 passed in 1.50s` |
| Affected regression surface | `PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q tests/test_projects.py tests/test_p13a_authoring.py tests/test_p13b_forms.py tests/test_p14_1_guided_validation.py tests/test_p14_wizard.py tests/test_phase15_installer.py tests/test_phase16_auth.py tests/test_phase16r_reconciliation.py tests/test_local_oidc.py tests/test_phase17_watch_learn.py tests/test_project_import.py` | `265 passed, 1 skipped in 5.99s` |
| Installer/project focus | `PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q tests/test_project_import.py tests/test_projects.py tests/test_p13a_authoring.py tests/test_phase15_installer.py` | `123 passed in 2.38s` |
| Python compilation | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m compileall -q src` | Success |
| Dashboard JavaScript parse | `node -e '<read index.html script and compile with new Function>'` | `dashboard JavaScript parses` |
| POSIX shell parse | `sh -n install.sh scripts/*.sh docker/*.sh` | Success |
| Diff whitespace | `git diff --check` | Success |
| Authoritative full suite | `PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q` | `575 passed, 1 skipped, 30 warnings in 16.23s` |
| Live local acceptance | `.orchestrator-cookie/venv/bin/python /workspace/scratch/879046ea23ae/ai-test-live-acceptance/run_acceptance.py` | All shell/API statuses 200 on port 8025; preview no-write true; source unchanged true; absolute path redacted true; one spec and two manual pages imported; destination slug present in refreshed list |

The 30 full-suite warnings are the same count as the owner baseline: existing pytest
collection warnings plus existing Pillow and `datetime.utcnow` deprecations. The one skip
is the existing platform-dependent test.

The first live attempt exposed that the established project-list API displays directory
slugs rather than YAML display names. The acceptance gate stopped after import, the UI was
corrected to select `result.destination_slug`, the focused suite was rerun, and a second
synthetic slug completed the live gate. No real project, target, model, AWS endpoint, OIDC
provider, runner image, firewall, remote, or registry was contacted or changed.

PowerShell parsing was not run because `pwsh` is unavailable on this Linux host. The
existing, unchanged `install.ps1` wrapper is exercised indirectly by the shared CLI tests;
a native Windows parser run remains required before Windows release acceptance.

## Security test coverage

The new suite covers default-disabled and malformed configuration; CLI replacement and
clear behavior; doctor/environment export; operator, viewer, unauthenticated, and cookie
CSRF gates for every route class; empty/unknown roots; labels, root-relative navigation,
breadcrumbs, and browse truncation; traversal, absolute paths, Windows drives,
backslashes, sibling-prefix attempts, root replacement, symlinks, nested and broken
links, reparse classification, FIFO/socket/device classification, unsafe and secret-like
names; missing/malformed metadata, specs, and manuals; depth/count/file/total bounds;
preview non-publication and prohibited process/network sentinels; one-use expiry, actor
binding, destination binding, stale fingerprints, copy-time mutation; existing and
publish-race collisions; atomic success; injected copy/validation/publish/audit failures;
owned-inode cleanup; linked destination store denial; source-byte/mode immutability;
redacted audit fields; project discovery; and modal accessibility/error/success hooks.

Split-layout compatibility additionally covers root-contained relative legacy manuals,
copy/rebase behavior, persisted runner-equivalent window defaults, absent-schedule
retention, absolute/parent/Windows/backslash rejection, linked manual denial, partial
portable-manual ambiguity, and preview invalidation when an external manual changes.

The host sandbox did not permit creation of a real Unix socket node. The scanner processed
a real FIFO, while socket and character/block-device modes were covered through the same
explicit special-entry classifier. Windows reparse attributes and the fail-closed
no-follow capability were covered synthetically; native Windows junction tests remain a
release-platform gate.

## Retained-functionality matrix

| Surface | Evidence | Result |
|---|---|---|
| Dashboard shell and Projects list | Full suite; live authenticated shell and refreshed list | Retained; imported slug selected after success |
| Viewer/operator/CSRF authorization | Existing Phase 16 suite plus every new endpoint | Retained; viewers receive `operator_required` with no root metadata |
| Local and organization OIDC behavior | `test_local_oidc.py`, `test_phase16_auth.py`, reconciliation suite | Retained; no OIDC configuration changed |
| Project creation, editing, clone, typed validation | Phase 13A/13B, Phase 14/14.1, import portable-manual tests | Retained |
| Runner discovery and manuals | `test_projects.py`, runner/full suite, live discovery | Retained; exact `./manual` form added without changing legacy paths |
| Trigger, cancellation, scheduler, target routing | Authoritative full suite | Retained; import has no run side effect |
| Watch & Learn eligibility and lifecycle | Phase 17 suite | Retained |
| Installer, doctor, shell entrypoints | Phase 15 plus import CLI/doctor tests and `sh -n` | Retained; import disabled by default |
| Audit/redaction | Existing mutation/auth audit plus import audit and response tests | Retained and extended |
| Linux/macOS/Windows posture | Linux live and full tests; macOS no-replace implementation; Windows safe denial | Linux accepted; native macOS/Windows release runs still required |

## Review series and application

Implementation commit:

```text
d69d820 feat: add allowlisted project folder import
```

The accompanying documentation commit contains this architecture, operator, and test
handoff. Use the generated two-message patch series rather than assuming these local
scratch commit ids exist in the owner repository.

On the already clean owner feature worktree:

```bash
cd /tmp/ai-test-project-folder-import-20260908
git status --short
git am --3way /absolute/path/to/0001-feat-add-allowlisted-project-folder-import.patch \
  /absolute/path/to/0002-docs-document-project-folder-import.patch
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
```

If apply fails, inspect the conflict without touching the original worktree. To return only
the in-progress patch application to its pre-apply state:

```bash
git am --abort
```

After local review and only after explicit merge authorization:

```bash
cd /tmp/ai-test
git merge --ff-only feature/project-folder-import-20260908
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
./install.sh doctor
./install.sh start
./install.sh status
```

Verify the status URL remains on the owner-configured port 8025. Configure approved roots
with the operator guide before smoke testing. Do not run a project during import smoke.

For an authorized post-merge rollback, stop the dashboard, revert the feature commits in
newest-first order, rerun the full suite, and restart. Do not reset the repository, remove
the owner safety tag, delete managed projects, or alter the preserved untracked manual.
