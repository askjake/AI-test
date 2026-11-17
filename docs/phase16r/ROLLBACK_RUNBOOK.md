# Phase 16R rollback runbook

Rollback restores only package-declared source paths and preserves
`.orchestrator-cookie` configuration, credentials, tokens, projects, reports,
logs, and unrelated files.

```sh
ROOT=/home/montjac/orchestrator-cookie/orchestrator-cookie/orchestrator-cookie
/tmp/orchestrator-cookie-phase16r/orchestrator-cookie-phase16r/rollback.sh \
  --target "$ROOT"
```

Choose the exact printed backup when required:

```sh
/tmp/orchestrator-cookie-phase16r/orchestrator-cookie-phase16r/rollback.sh \
  --target "$ROOT" --backup-id 'BACKUP_ID'
```

Windows uses `rollback.ps1` with the same options. Rollback refuses a diverged
payload, ambiguous backup, unsafe path, or active/stale dashboard metadata. It
does not reset Git or remove runtime data.

If only OIDC configuration must be disabled, first obtain activation approval,
authenticate the managed dashboard identity, stop it, and run:

```sh
./install.sh configure --non-interactive --disable-oidc
```

After source rollback:

```sh
cd "$ROOT"
./install.sh init --with-test
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
git status --short
```

Dependency packages compatible with both releases may remain in the generated
managed environment; source rollback does not delete or rotate anything.
