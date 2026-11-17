# Phase 15.1 deployment and activation runbook

The release archive is an offline source overlay. Applying it never starts,
stops, or restarts a dashboard and never calls a model/target, touches secrets,
changes firewall state, or mutates an image engine.

## 1. Verify from any transfer directory

Keep the archive and its `.sha256` sidecar together. The sidecar contains only
the archive basename, so verification is independent of the directory:

```bash
cd /directory/containing/the/downloads
sha256sum -c orchestrator-cookie-phase15.1-overlay.tar.gz.sha256
```

On macOS use `shasum -a 256 -c ...`. On Windows PowerShell compare
`(Get-FileHash -Algorithm SHA256 .\orchestrator-cookie-phase15.1-overlay.tar.gz).Hash`
to the digest in the sidecar.

## 2. Extract and run default preflight/apply

```bash
tar -xzf orchestrator-cookie-phase15.1-overlay.tar.gz
cd orchestrator-cookie-phase15.1
./apply.sh --target /absolute/path/to/the/clone
```

PowerShell:

```powershell
tar -xzf .\orchestrator-cookie-phase15.1-overlay.tar.gz
Set-Location .\orchestrator-cookie-phase15.1
.\apply.ps1 --target C:\absolute\path\to\the\clone
```

The target must match the exact supplied Phase 15 baseline for every declared
file. Unrelated tracked/untracked files and dirty worktree changes are not
examined or overwritten. Payload hashes are checked before target inspection.

Default preflight does not install anything. If it prints `STOP:` because the
managed test profile is missing or incompatible, either repair from the clone
first with `install init --with-test`, or explicitly authorize package repair:

```bash
./apply.sh --target /absolute/path/to/the/clone --repair-test-env
```

Only that flag permits dependency installation. The source remains untouched
until the repaired environment passes exact-version, import, `pip check`, and
TestClient request validation.

## 3. Transaction and verification

Apply performs these steps in order:

1. validate package hashes and exact target baseline;
2. validate the managed full-test environment;
3. back up every declared pre-existing file beneath
   `.orchestrator-cookie/patch-backups/phase15.1/<backup-id>/`;
4. atomically write only declared payload files;
5. verify post-copy SHA-256 values;
6. run the focused Phase 15.1 suite;
7. run the full supported suite.

Any failure after mutation automatically restores the declared baseline files
and removes only newly introduced declared files. Every failure is prefixed
with `STOP:`. The printed backup ID is retained after success for independent
rollback.

## 4. Safe activation is separate

Do not activate until an approved window. Inspect current state first:

```text
install status
install doctor
```

If a managed dashboard is running, explicitly stop it during the window, then
start the updated process:

```text
install stop
install start
install status
```

Start prefers the configured port (normally 8080). If occupied, it scans upward
on the same bind host and prints the actual authenticated URL. It does not stop,
adopt, identify, or otherwise change the occupant. For explicit LAN mode, only
the port changes; the configured bind address and authentication policy do not.

## 5. Configure a new preferred start port

Stop the managed dashboard before configuration, then run:

```text
install configure --port 8090 --non-interactive
```

That resets both the current and preferred start port to 8090. A later fallback
does not replace the preference; the next start again begins at 8090.
