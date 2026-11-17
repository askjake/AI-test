# Author-mode Project Builder operator/release handoff

## Status

This is a source candidate only. No branch was pushed, no pull request or deployment was created, no
image was built or repinned, no service/runtime configuration was changed, and no target, SSH host,
AWS endpoint, model, or secret value was contacted or read.

The R1 corrective source was based on exact Author Builder candidate tree
`7448534ab7550cc50a4d6cb88935199e1a9a2be0`. That candidate was itself reconstructed from earlier
attested tree `b35e5060df21bf1bbbc7f7c65ad667f0aa74ee7b`. Synthetic local commits do not prove or claim the
unavailable parents or remote lineage of `bc924ec7be89c074a938e7ae0c48d1dd9b9b4775`.

## Release configuration to review

All settings use the existing `DASHBOARD_` environment prefix:

- `DASHBOARD_AUTHOR_BUILDER_STATE_ROOT`: private durable clone-local state. Back up and permission it
  with the same care as other private dashboard state.
- `DASHBOARD_AUTHOR_BUILDER_GRANTS_FILE`: optional administrator-owned YAML map from project slug to
  exact OIDC subjects for legacy projects. Keep it a regular, non-symlink file with private ownership.
- `DASHBOARD_AUTHOR_BUILDER_MAX_FILES`, `...MAX_FILE_BYTES`, and `...MAX_TOTAL_BYTES`: inventory and
  candidate copy caps.
- `DASHBOARD_AUTHOR_BUILDER_HISTORY_MAX_ITEMS`: hard retained-item cap in addition to each owner's
  age policy.
- `DASHBOARD_AUTHOR_BUILDER_HOST_KEY_DISCOVERY_ENABLED`: defaults false. Enable only after approving
  the exact `ssh-keyscan` operational boundary and ensuring the executable is available.
- `DASHBOARD_AUTHOR_BUILDER_HOST_KEY_TIMEOUT_SECONDS`, `...TTL_SECONDS`, and `...MAX_BYTES`: discovery
  timeout, ephemeral candidate lifetime, and output limit.

Example grant-file shape (identities are illustrative, not defaults):

```yaml
legacy-project:
  - oidc:exact-subject-from-provider
```

Project composition continues to use only configured `DASHBOARD_PROJECT_IMPORT_ROOTS`; it does not
introduce a general filesystem browser. Review root labels/paths and their filesystem permissions.

## Suggested release gates

1. Review the architecture/threat note and the exact source diff from the recovered tree.
2. Re-run the focused and full source commands documented in `TEST_REPORT.md` in a disposable build.
3. Exercise OIDC subject/grant behavior in a non-production environment without shared bootstrap
   credentials and verify backup/restore of the private state root.
4. Keep host-key discovery disabled while validating that only persisted project policy can make a
   route eligible; an unsaved browser draft must remain unable to authorize discovery.
5. If enabling discovery later, use a controlled test SSH endpoint, independently verify the shown
   fingerprint, confirm new-only `0600` save behavior, and verify runtime strict known-host use.
6. Verify the narrow relay/Bedrock source diff, then build/re-pin only under separate release authority.
7. Treat offline validation honestly: it validates static project structure and syntax; target
   preflight and project execution remain separate existing runner/Watch & Learn actions.

## Separate unresolved VNC relay gate

The prior live `mul-autotest` stopped before any VNC connection:

```text
[target-relay] ... ready
[egress] FATAL: approved endpoint is absent from private hosts file: bedrock-runtime.us-west-2.amazonaws.com
```

R1 contains the narrow source correction: when AWS forwarding is disabled and an active target relay
is selected, `ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1` is passed into the container so its firewall
calculation matches the private hosts file. Source tests cover the positive and negative launcher
branches and the existing consumer. No image was built or repinned and no live route was exercised.
The next authorized release must build the reviewed tree, repeat target-free proofs, then separately
run the live gate. Until that happens, the live VNC gate is still failed/unproven—not green.

## Rollback and evidence handling

Keep rollout and rollback separate from this source-development work. Before activation, capture the
deployed commit/tree, configuration fingerprints (not secret contents), image digest, and exact gate
results. Roll back using the release system's normal immutable artifact procedure. Do not copy private
builder history or known-host contents into general release logs.
