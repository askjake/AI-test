# Phase 15.1 rollback runbook

Each successful application prints a backup ID. Rollback is independently
runnable from the extracted release package and touches only manifest-declared
source files.

## Before rollback

Rollback does not control processes. During an approved activation/rollback
window, explicitly stop a running managed dashboard first:

```text
install status
install stop
```

## Restore the latest applied backup

From the extracted package directory:

```bash
./rollback.sh --target /absolute/path/to/the/clone
```

Or select the exact ID printed by apply:

```bash
./rollback.sh --target /absolute/path/to/the/clone --backup-id BACKUP_ID
```

PowerShell uses `.\rollback.ps1` with the same arguments.

Rollback validates that every declared current file still matches the applied
payload. If any declared file has since diverged, it prints `STOP:` and changes
nothing. It also validates each captured baseline checksum before restoring.
Pre-existing files are restored atomically; only files introduced by this
release are removed.

Rollback does not delete or rewrite the managed environment, configuration,
tokens, projects, reports, manuals, logs, secrets, backups, firewall state, or
image-engine state. Restart the prior dashboard only as a separate explicit
operator action.
