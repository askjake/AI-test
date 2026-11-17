# Phase 16R test report

Date: 2026-08-26

## Baseline

- Verified source branch:
  `feature/phase15-installer-stabilization-20260825T203216Z`.
- Verified source HEAD:
  `c4514676c3fa0d9c12db191924ea705ceedb348a`.
- Verified tree: `b191f2e0564b48894ebfea98207bb4803d2a0f96`.
- Source evidence reported clean status, 262 archive members, approved profile
  in both configuration modules, and zero tracked bootstrap-token matches.
- Native baseline: CPython 3.12.13, `pip check` PASS, `408 passed, 31 warnings`.

## Reconciled acceptance

- Phase 16 auth plus inherited Phase 15 focused suite: `58 passed`.
- Phase 16R focused interpreter/route suite: `14 passed`.
- Full supported suite: `440 passed, 31 warnings`.
- Managed dependency check and test-profile smoke: PASS.
- Approved profile preserved in both configuration modules: PASS.

Coverage includes bootstrap/OIDC/session/CSRF/audit privacy, Viewer/Operator
authorization, token rotation and clipboard failure, lifecycle identity and
port fallback, Python resolution/3.14 rejection, wrapper-selected venv
creation, optional engine separation, direct/jump schemas, strict ProxyJump
argv, route revision changes, allowlist retention, unsupported RDP/VNC routes,
and no implicit preflight.

## External-action boundary

No dashboard was started/stopped/deployed. No target, jumpbox, Bedrock model,
real IdP, container engine/image, firewall, DNS, TLS endpoint, proxy, or tunnel
was contacted or changed. PowerShell/Windows and macOS behavior is covered by
deterministic abstraction/source tests only; native-platform acceptance remains
required and is not claimed.

Transactional package apply/idempotency/rollback/failure/metadata/private-state
evidence is recorded in the package acceptance handoff generated with the final
archive.
