# Phase 16 rollback runbook

Rollback changes only declared source files. It preserves clone-local tokens,
OIDC secret files, projects, reports, logs, credentials, and unrelated files.

## Package rollback

From the extracted release directory:

```sh
ROOT=/home/montjac/orchestrator-cookie/orchestrator-cookie/orchestrator-cookie
/tmp/orchestrator-cookie-phase16/orchestrator-cookie-phase16/rollback.sh \
  --target "$ROOT"
```

To select a specific package backup:

```sh
/tmp/orchestrator-cookie-phase16/orchestrator-cookie-phase16/rollback.sh \
  --target "$ROOT" --backup-id 'BACKUP_ID'
```

The rollback command validates that the current declared files match the Phase
16 payload before restoring. It refuses ambiguous or modified source rather
than overwriting it.

The apply step may have added the pinned Phase 16 packages to the clone-local
test environment before source mutation. Rollback does not remove those
compatible packages; it restores declared source and leaves runtime data alone.

## Configuration-only OIDC disable

If source is healthy but corporate OIDC is not ready, stop the managed
dashboard and disable only OIDC. Bootstrap sign-in remains available:

```sh
cd "$ROOT"
./install.sh stop
./install.sh configure --non-interactive --disable-oidc
```

Restart only with separate approval.

## Post-rollback verification

```sh
cd "$ROOT"
./install.sh init --with-test
PYTHONPATH="$ROOT/src" "$ROOT/.orchestrator-cookie/venv/bin/python" -m pytest -q
git status --short
```

Do not delete `.orchestrator-cookie`, rotate credentials, reset Git, or remove
the client-secret file as part of source rollback.
