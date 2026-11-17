# Phase 16R change report

## Reconciliation

- Rebased the accepted 23-file Phase 16 authentication payload onto the exact
  `c451467` Git tree rather than the earlier imported snapshot.
- Preserved the approved Bedrock application-inference-profile default in both
  tracked configuration modules.
- Preserved private token/runtime compatibility, loopback default, explicit
  LAN policy, authenticated lifecycle identity, and upward-only port fallback.

## Cross-platform onboarding

- Added deterministic Python 3.13/3.12/3.11 selection policy and wrapper probes.
- Added authoritative `ORCHESTRATOR_PYTHON`, exact 3.14 rejection, actionable
  macOS/Windows remediation, managed-interpreter provenance, and repair of an
  unsupported generated environment during explicit `init`.
- Added a dashboard-bootstrap doctor layer independent from container engine,
  image, target, and model gates.
- Separated normal-user and developer install instructions.

## Target routes

- Added typed Direct and SSH jump route models to project authoring.
- Added explicit Connection path UX, route-state explanations, allowlist
  retention, and confirmation before route-specific values are discarded.
- Added shared safe SSH argv construction with ProxyJump and strict host keys.
- Bound target revision/preflight to route and clone-local reference metadata.
- Disabled legacy VNC `via` execution and rejected RDP/VNC jump routes without
  direct fallback.

## Tests and documentation

- Added deterministic interpreter, wrapper, doctor-layer, typed-route,
  revision, explicit-preflight, and safe-argv acceptance tests.
- Updated inherited form/target expectations for the safer VNC behavior.
- Added Phase 16R architecture, operator, deployment, rollback, security,
  change, and test documentation.
