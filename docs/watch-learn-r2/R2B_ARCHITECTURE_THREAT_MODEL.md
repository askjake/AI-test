# R2B architecture and threat model

## Trust boundaries

- The managed project remains the sole destination/network-policy authority.
- Owner readiness state is private overlay data, not runnable project source.
- Strict API models accept reference names but no secret values or destination
  fields.
- The target-free check uses typed linting, secret file metadata, local runtime
  discovery, and the existing adapter registry. A bounded fixed client-version
  command may run locally; it performs no DNS, socket, target/application
  launch, authentication, project run, model call, or AWS access.
- The activated target-preflight route is the only new onboarding route allowed
  to call the existing bounded `TargetProbeService.run()` path.
- Connect still passes through unique OIDC identity, CSRF, project/session owner,
  revision, privacy, adapter, preflight, paused-connect, and session-proof gates.

## Threats and controls

| Threat | R2B control |
|---|---|
| Import silently becomes target-enabled | Import generates provenance only; readiness state, check, activation, and preflight remain absent. |
| Values copied from another ready project | There is no copy endpoint or template containing destination, redaction, identity, or secret reference values. |
| Destination widened through onboarding | Host, port, command, route, identity, certificate, and allowlist fields are absent; strict schemas reject extras. |
| Arbitrary adapter selected | The schema allowlists runner-local-app/runner-vnc and the target type fixes which one is valid. |
| Secret bytes enter project/UI state | Only sanitized reference names are accepted and persisted; checks inspect file metadata only. |
| Redaction does not match pixels | Bounds must fit the declared frame contract; Connect, session proof, and action evidence reject any mismatched frame dimensions. |
| Stale project policy is saved | Save and preview require exact current project and base-target revisions. |
| Old check authorizes changed state | Save clears receipts; checks bind the effective target revision; target/secret metadata change invalidates check and activation. |
| Another owner reuses configuration | Storage path and record bind an opaque stable OIDC owner principal and project name. |
| Shared bootstrap operator gains private state | Readiness inspection and mutation require a unique OIDC identity. |
| CSRF triggers activation or preflight | Existing cookie mutation CSRF dependency covers POST and PUT routes. |
| Preview contacts target | Preview/validate call only typed overlay validation and target-free static checks. |
| Activation contacts target automatically | Activation records a short-lived confirmation only; target preflight remains a separate explicit action. |
| Import marker is supplied by untrusted source | The importer discards a source-supplied marker and generates its own after staged validation. |

## Residual operational gates

Source tests cannot prove the installed candidate image, relay/firewall runtime,
browser behavior, or a real target. Management must reconstruct exact trees,
build and pin an independently verified candidate image, run the localhost
browser gate, perform controlled cutover, and separately opt in to live
acceptance. This package makes no live or release-readiness claim.
