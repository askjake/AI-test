# Phase 16R architecture

## Reconciled baseline

Phase 16R is based on the verified Git object
`c4514676c3fa0d9c12db191924ea705ceedb348a` on
`feature/phase15-installer-stabilization-20260825T203216Z`. It carries the
accepted Phase 16 sign-in/session/OIDC implementation forward while retaining
the approved Bedrock application-inference-profile default in both runtime
configuration modules. Clone-local state remains under `.orchestrator-cookie`.

## Interpreter selection

Before installer code runs, platform wrappers select a supported CPython in a
fixed order. An explicit `ORCHESTRATOR_PYTHON` is authoritative and never falls
back when invalid. Otherwise versioned 3.13, 3.12, and 3.11 commands precede
generic commands; Windows also tries the corresponding `py` launcher forms.
Python 3.14 is reported by exact version and rejected.

`init` creates the managed environment with `sys.executable`, which is the
wrapper-selected interpreter. Later commands use that managed interpreter, so
doctor and dependency installation cannot drift. Environment state records the
non-secret bootstrap interpreter path and Python minor version.

Doctor exposes separate dashboard-bootstrap, container-engine, runner-image,
target-reachability, and AWS/model findings. A missing engine blocks project
execution, not dashboard-only authoring and sign-in.

## Sign-in and authorization

The Phase 16 architecture remains authoritative: `/sign-in`, server-derived
Viewer/Operator actors, opaque HttpOnly sessions, per-session CSRF, protected
reports, credential-free mutation audit, clone-owner bootstrap recovery, and
disabled-by-default OIDC Authorization Code with PKCE. The browser never
selects its role and every mutation route enforces Operator server-side.

## Typed connection routes

Remote target documents now contain a typed route:

```yaml
target:
  type: ssh-terminal
  host: target.internal
  user: target-user
  key: target-key
  window: SSH
  route:
    type: ssh-jump
    host: approved-jump.internal
    user: jump-user
    port: 22
    known_hosts_file: approved_known_hosts
```

`direct` is the migration-compatible default. `ssh-jump` is supported for SSH terminal
and VNC targets. An SSH terminal target and its jump host must be in the SSH allowlist.
A VNC endpoint must be in the VNC allowlist while its gateway must be in the SSH allowlist.
The known-hosts field is a filename reference into clone-local,
owner-only secret storage; project YAML never contains key material,
passphrases, or passwords.

The runtime converts the nested route into bounded typed parameters and builds
one literal OpenSSH argv with `ProxyJump`, `StrictHostKeyChecking=yes`, an explicit
known-hosts file, and no shell. VNC uses a separate literal `sshpass -f` plus OpenSSH
local-forward argv bound to `127.0.0.1`, then points TigerVNC only at that loopback port.
On Linux, the selected VNC transport may traverse an authenticated host relay when a Docker
bridge cannot use the host VPN route. Direct VNC locks that relay to the VNC socket. A jump
route locks it only to the jump-host SSH socket and uses a fixed OpenSSH `ProxyCommand`, so
OpenSSH still validates the original host and port against the reviewed known-hosts file.
RDP jump routes are rejected and never fall back to Direct. The former shell-oriented
VNC `via` route is migrated during project-folder import and is no longer executable.

Route fields and clone-local reference metadata are part of the target
revision. Preflight remains explicit, bounded, TTL-scoped, and process-memory
only. Opening, editing, validating, or saving the UI does not contact a target.

## Deployment boundary

The dashboard deploys on the engineer's local machine. The reported internal
system is a future target, not a dashboard host. It must not be probed or
represented as reachable until the approved jump hostname,
identity, port, authentication method, pinned host-key data, protocol, and
authorization are supplied and an Operator explicitly runs preflight.
