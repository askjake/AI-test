# Project-folder import operator guide

## Configure approved roots

Project import is disabled by default. Each root must be an existing absolute directory
whose full component chain contains no symlink, junction, or reparse point. Give each root
a stable non-secret id and a friendly label. Configuring roots replaces the complete
current list, so repeat the option for every root to retain.

macOS/Linux:

```bash
./install.sh configure --non-interactive \
  --project-import-root incoming "Incoming projects" /srv/ai-test-imports \
  --project-import-root qa-share "QA approved projects" /srv/qa-approved
./install.sh doctor
```

Windows PowerShell:

```powershell
.\install.ps1 configure --non-interactive `
  --project-import-root incoming "Incoming projects" 'D:\AI-Test-Imports' `
  --project-import-root qa-share "QA approved projects" 'D:\QA-Approved'
.\install.ps1 doctor
```

To disable the feature and remove all configured roots:

```bash
./install.sh configure --non-interactive --clear-project-import-roots
```

```powershell
.\install.ps1 configure --non-interactive --clear-project-import-roots
```

The managed configuration contains root paths; it remains private under
`.orchestrator-cookie/config/`. Browser responses and the project-import audit expose only
the configured id and label.

## Prepare a source folder

Use a synthetic or separately sanitized copy for acceptance. The selected folder needs:

- one top-level `project.yaml` valid under current typed authoring rules;
- one or more valid specification Markdown files outside `manual/`;
- either `manual/manual.md` with a non-empty level-one heading, or a legacy
  root-relative `manual_dir` whose directory contains `manual.md`;
- optional additional Markdown manual pages and safe image assets below `manual/`.

Do not place secrets or runtime state in the folder. `.git`,
`.orchestrator-cookie`, environment files, credential/token/key-like names, caches,
reports, screenshots, generated artifacts, dependency trees, and build outputs are never
imported. Sensitive-looking or unsafe names, links, and special nodes make validation fail.
A legacy `manual_dir` is followed only when it is normalized, relative, and contained by
the same configured root as the selected project. Every path component and file receives
the normal no-follow, identity, size, and preview-freshness checks. The browser and audit
receive only generic copy/rebase warnings, never the relative or absolute source path.

Legacy projects that omitted `target.window` retain the exact deterministic fallback the
runner already used, persisted during import. A missing schedule remains missing, so an
explicitly run legacy project does not silently become scheduled. A legacy VNC `via`
value is migrated to the typed, strict-host-key SSH local-forward route; the destination
VNC host and SSH gateway must already be in their project allowlists. The imported project
stores only generated reference names for the gateway password and reviewed known-hosts
file. Supply those values with the write-only Project Builder controls before preflight.

## Use the dashboard

1. Sign in with an Operator session.
2. In Projects, choose **Import project folder**.
3. Select an approved location. Choose a detected logical project; this combines a legacy
   `tests_specs/<slug>` folder with its separate `tests_manuals/<slug>` tree. The advanced
   folder browser remains available for portable or unusual layouts.
4. Confirm the intended folder and new destination slug, then choose **Preview**.
5. Review the project name, spec/manual counts, bytes, excluded entries, destination, and
   all diagnostics. Preview does not write the managed project store.
6. If valid, select the confirmation checkbox and choose **Import**.

Success closes the modal, reloads the project list, selects the imported project, and
shows a short result. Import never starts a run, target, or model call. Cancel, a validation
error, a stale preview, or a collision leaves source and destination unchanged.

Windows version 1 safely denies preview/apply with `safe_read_unavailable`. Directory
browsing still denies junction/reparse entries, but source file import remains disabled
until the Windows no-follow handle implementation is separately proven and reviewed.

## Local acceptance on port 8025

Use the already configured exact dashboard port. Do not change OIDC, AWS, target, model,
or runner image configuration. Create a temporary root and synthetic portable project,
configure that root, then start the dashboard normally:

```bash
./install.sh stop
./install.sh configure --non-interactive \
  --project-import-root acceptance "Import acceptance" /absolute/path/to/synthetic-root
./install.sh doctor
./install.sh start
./install.sh status
```

Confirm the status URL uses port `8025`. Sign in through the already configured route and
exercise browse, preview, cancel, and one import. Do not select a real production project.
After acceptance, restore the owner's intended root list or disable import explicitly.

## Developer and release gates

```bash
./install.sh init --with-test
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q tests/test_project_import.py
sh -n install.sh scripts/*.sh docker/*.sh
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
```

PowerShell syntax validation on Windows:

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\install.ps1), [ref]$tokens, [ref]$errors
) | Out-Null
if ($errors.Count) { $errors | Format-List; exit 1 }
```

## Recovery and rollback

A failed operation owns and removes only its random `.project_import_*` staging directory.
It never deletes, renames, chmods, chowns, or edits the selected source.

Before merge, restore the feature worktree to its branch tip or delete that separate
worktree; do not touch the owner's safety tag or original worktree. After an authorized
merge, rollback with a normal revert of the feature commits:

```bash
git switch <integration-branch>
git revert --no-edit <newest-feature-commit> <older-feature-commit>
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
```

Then stop/start the managed dashboard so the previous code and configuration are active.
Do not reset the repository, delete the managed project store, or move the source root as
part of rollback.
