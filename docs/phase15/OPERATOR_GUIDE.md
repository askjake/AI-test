# Phase 15.1 concise operator guide

Use `./install.sh` on Linux/macOS or `.\install.ps1` on Windows. `install.cmd`
is an optional CMD bridge to PowerShell.

## Initialize and repair

```text
install init                 production runtime
install init --with-test     production plus release/full-test tools
install doctor               read-only layered readiness
```

`init` creates or repairs only the clone-local managed environment and missing
runtime scaffolding. Existing configuration, tokens, projects, reports,
manuals, logs, and secrets are preserved. Doctor distinguishes dashboard
runtime readiness from optional developer/full-test readiness and never contacts
a model or target.

## Configure the preferred port

```text
install configure --loopback --port 8080 --non-interactive
```

Loopback is the safe default. Non-loopback binding still requires explicit
`--lan`, valid authentication, and local policy approval. Configuration is
blocked while managed process metadata is active.

## Start, fallback, and inspect

```text
install start
install status
install logs --lines 200
install stop
```

Start is idempotent. It begins at the preferred port and scans sequentially
upward on the same bind host. Occupants are not identified or changed. Only an
immediate bind collision is retried; unrelated startup failures stop and name
the redacted log. The actual port is persisted only after the authenticated
runtime identity matches the new instance and PID. Start and status print the
actual URL without tokens.

`start --foreground` selects a locally available candidate and stays attached.
It deliberately does not create managed PID/port state; after it exits, status
continues to describe only background managed state.

Stop signals only the PID whose authenticated identity matches actual-port
metadata. If that proof fails, stop refuses.

## Apply, activate, and roll back

Verify the portable sidecar, extract the overlay, then run its `apply` wrapper
with an absolute `--target`. Apply validates a compatible managed test profile
before source backup/mutation. Use `--repair-test-env` only when you deliberately
authorize dependency installation. Focused and full tests run automatically.

Apply never activates code. During a separate approved window, use
`status`, `stop`, `start`, and `status`. To revert, stop explicitly and run the
package's independent rollback wrapper, optionally with the printed backup ID.

Tokens remain in the private local token file and are never printed or placed
in URLs. Image acquisition, target preflight/run, model/refinement activity, and
firewall changes remain separate explicit actions.
