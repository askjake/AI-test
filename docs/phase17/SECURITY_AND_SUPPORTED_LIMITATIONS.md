# Phase 17 Watch & Learn security boundary and supported limitations

Phase 17 supports only the `local-app` target shape in the capture-adapter
allowlist. Connect is enabled only when all of these independent gates pass:

1. the owner is an Operator with a unique OIDC subject;
2. the project and privacy revisions still match the reviewed capability data;
3. static policy, local client-runtime, and fixed-region pre-relay redaction
   checks pass;
4. a reviewed digest-pinned runner image is already present; and
5. `target.watch_learn_ready_window` contains the exact title expected only
   after application login/readiness.

The ordinary local-app preflight remains non-launching, so its
`authentication-session` result is `unsupported`. That result no longer creates
a deadlock: the independent launch gates may authorize **Connect paused**. The
runner starts with no network and no AWS/model environment. Recording is still
blocked in `connected_unauthenticated_paused` until a separate runner request
finds and focuses the configured ready-window title and returns a redacted
proof frame.

## Login secret boundary

An Operator may save an `application` password reference through the existing
write-only secret-staging endpoint. Saving sends the value once from the
dashboard to private host storage. Capture sends only the safe reference name
to the worker. The worker validates an owner-only, same-UID, regular file,
reads a bounded UTF-8 value without following symlinks, and passes it to
`xdotool` on stdin. The value is never placed in process arguments, action
journals, receipts, screenshots, learned drafts, or model context.

Secret entry is available only while the target is connected and recording is
paused. It produces an audited generic event but no evidence. A secret event
cannot be annotated or used as learned/model provenance.

The ready-window check proves only that the configured application UI state is
present. It is not a cryptographic authentication assertion. Use a title that
is specific to the intended post-login state, and keep the target isolated.

## Learning and optional model input

Deterministic analysis remains mandatory and local. Owner annotations may add a
visible control label, expected visible result, and safe variable name to make
the resulting draft actionable. The draft is still review-required and has no
run, target, or promotion authority.

Model enrichment is optional. It is text-only unless both of these gates are
true:

- the deployment sets `DASHBOARD_WATCH_LEARN_VISUAL_ENRICHMENT_ENABLED=true`;
- the Operator checks the per-job visual-evidence opt-in.

Only available, integrity-checked, already-redacted PNG evidence referenced by
deterministic observations is sent. Image count and total bytes are bounded by
`DASHBOARD_WATCH_LEARN_VISUAL_ENRICHMENT_MAX_IMAGES` and
`DASHBOARD_WATCH_LEARN_VISUAL_ENRICHMENT_MAX_BYTES`. The model still receives a
forced response schema and cannot invoke tools or promote/run a draft.

## Remaining limitations

- Capture supports `local-app` and typed VNC projects. Host app, SSH-terminal, RDP, and
  legacy VNC `via` remain denied.
- Local-app capture retains `--network=none`. Direct VNC capture receives only an
  authenticated destination-locked relay to the selected VNC endpoint; VNC-over-SSH capture
  receives only a destination-locked relay to the selected project's SSH gateway on its
  configured port. Bedrock, general DNS, unrelated targets, and AWS credential forwarding
  remain absent.
- VNC-over-SSH requires an owner-only gateway password reference and a separately reviewed
  known-hosts line saved through Project Builder. The worker creates a loopback-only local
  forward and the VNC viewer sees only that loopback endpoint.
- The controlled canvas provides fit, bounded zoom, expanded-workspace, and browser
  fullscreen modes. These are view-only transformations and do not alter recorded coordinates.
- Browser text entry is intentionally not a general capture action. Non-secret
  text remains a semantic intent for later owner review.
- Native container/GUI acceptance requires a disposable Linux host with X11
  tooling and the exact reviewed runner-image digest. Source tests do not
  substitute for that gate.

At every Watch & Learn service boundary, an eligible owner must be an Operator
authenticated with OIDC and have a subject of the form
`oidc:<nonempty-subject>`. Shared bootstrap identities and the bare `oidc:` value
remain denied.
