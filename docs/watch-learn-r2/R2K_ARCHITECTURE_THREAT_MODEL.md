# R2K architecture and threat-model update

R2K inserts one fail-closed preparation boundary between revision/preflight/
privacy validation and capture-adapter contact.

The dashboard remains the only component allowed to adjust host project
metadata. The runner and worker remain non-root consumers of read-only bind
mounts. The new boundary grants filesystem readability, not target authority:
it does not activate a project, contact a target, start a container, reveal a
secret, or authorize direct input.

## Preserved boundaries

- The worker permanently drops to UID/GID 10001 with no supplementary groups.
- Local-app capture remains `network=none`, with no published ports, host
  networking, privilege, Docker socket, AWS credentials, or model access.
- Project and manual mounts remain read-only; secrets remain a separate private
  mount and are never normalized by this operation.
- Fixed-region redaction remains worker-side and precedes every returned frame.
- OIDC/operator, CSRF, activation, revision, preflight, ready-window,
  idempotency, rate, emergency-pause, stuck-input, and frame-lifecycle checks
  are unchanged.
- Browser/API failure text remains generic. Only bounded allowlisted fields are
  written to the dashboard log; arbitrary runner output remains in the private
  mode-0600 diagnostic file.

## New controls

- Project selection is limited to one immediate slug-valid child of the exact
  configured specs root.
- The specs root and project root must be real directories, not symlinks.
- Recursive traversal uses open directory descriptors, `O_NOFOLLOW`, and
  device/inode comparisons before changing a mode.
- Directory symlinks and file symlinks are ignored without following their
  targets.
- Only regular `.yaml`, `.yml`, and `.md` files become 0644. Arbitrary project
  content remains byte- and mode-unchanged.
- Preparation failures occur before `adapter.connect` and produce a typed,
  path-free diagnostic.

## Residual operational requirement

The source repair must still be exercised on the validation host with the
corrected R2K synthetic fixture and a reviewed shallow image. R2J host evidence
proves the full runtime path under the corrected permissions, while this
development environment proves the R2K source contract only. No release or
live-target acceptance follows from source tests alone.
