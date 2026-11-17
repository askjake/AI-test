# R2B imported-project Watch & Learn readiness design

## Current model and completeness finding

Project-folder import copies validated `project.yaml`, runnable Markdown
specifications, `manual/manual.md`, other portable manual Markdown/assets, and
generates a source-import manifest. Runtime artifacts, hidden files, links,
credentials, caches, reports, and unsupported file types are excluded.

The bundled `mul-autotest` comparison has one limited connection specification
and a stub manual. Its source target declares a VNC destination and legacy jump
route, but it does not establish a complete Watch & Learn policy: there is no
fixed-region redaction, frame contract, post-login ready-window rule, selected
runner-controlled adapter, target password reference, strict route-known-hosts
reference, readiness receipt, or target-contact activation. The purpose-built
ready project described in the operator evidence was not present in the supplied
source tree, so none of its values were inspected or copied.

“Imported” and “live-capable” are intentionally separate states. R2B reports
these components independently:

| Component | Meaning |
|---|---|
| Source import | A generated R2B manifest or an existing private successful-import audit identifies the project as imported. |
| Specifications/manual | Runnable Markdown and `manual/manual.md` exist independently. |
| Target/destination | Existing typed target and exact destination policy remain read-only. |
| Adapter | The operator explicitly selects the one adapter allowlisted for the target type. |
| Static/client policy | Typed policy, secret-file metadata, and local client capability pass without target contact. |
| Ready window | An exact bounded post-login window title is configured. |
| Redaction/frame contract | Explicit regions fit explicit frame dimensions; every accepted target frame must match those dimensions. |
| Secret references | Required bounded reference names resolve to private regular files; values are never read by readiness. |
| Readiness receipt | The saved configuration and effective target revision passed the target-free check. |
| Target-contact activation | A separate explicit confirmation grants a short-lived activation. |
| Connect | Activation plus the existing revision-bound bounded target preflight, privacy, session-proof, and adapter gates pass. |

## Workflow

The owner selects an imported project, inspects structured requirements,
enters every security-relevant value, previews, validates target-free, saves to
private clone-local state, runs the target-free check, and explicitly activates
target contact for a bounded interval. Activation itself does not contact the
target. Only the separately labelled target-preflight endpoint may do so.

Save never updates `project.yaml`. The owner overlay can set only the approved
adapter identity, ready-window rule, frame/redaction contract, and applicable
secret-reference names. Host, port, route, identity, certificates, allowlists,
application command, and network policy are absent from the request schema.

The saved record is bound to owner, project name, project revision, base target
revision, and a canonical configuration revision. Its readiness receipt is also
bound to the effective target revision, including secret-file metadata. A save
invalidates check and activation. Project or destination changes hide the stale
record. Effective target changes invalidate both the check and activation.

## Persistence and compatibility

State is atomically replaced under a mode-0700 owner directory with a mode-0600
record. It contains timestamps and revisions but no secret values. A generated
`support/project-import-manifest.json` marks all future folder imports. Existing
imports are recognized through their private, mode-safe successful-import audit
entry, so an R2B upgrade does not require rewriting their project trees.

Purpose-built and other non-imported projects retain the pre-R2B capability and
Connect flow. They neither receive nor require the readiness overlay.

## Authority boundary

Preview, validation, save, inspection, and readiness check are target-free.
No route runs a project, invokes a model, accesses AWS, reads credential bytes,
or activates a raw VNC/noVNC channel. No source test or reconstruction step may
call the target-preflight endpoint.
