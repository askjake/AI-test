# Phase 16 test report

Date: 2026-08-25

## Intake and baseline

- Attached ZIP SHA-256:
  `5c54fdcdca378e641c7b8d2c59a623e999fae9d3cd74ded8a958f42a82392a82`.
- 262 archive members, one safe root, no traversal, symlink, or `.git` entry.
- Attachment matched the previously verified Phase 15.1 code, apart from two
  restored empty `.gitkeep` files and whitespace in one report line.
- Imported baseline branch:
  `feature/phase15-installer-stabilization-20260825T203216Z`.
- Imported local baseline commit: `5b9bdfce561585ab096bba63ad4ca9a84f2538bd`.
- Baseline managed dependency check: PASS.
- Baseline full suite: `408 passed, 31 warnings`.

The ZIP had no Git metadata, so remote commit `c451467` could not be
cryptographically verified. It also omitted clone-local runtime state, so the
reported live `0.0.0.0:8083` selection could not be inspected. The approved
Bedrock ARN stated in the handoff was not present in tracked attachment bytes.

## Focused acceptance

The combined Phase 16 authentication and Phase 15 installer/lifecycle focused
suite passed: `58 passed`.

The complete supported suite passed: `426 passed, 31 warnings`.

Coverage includes unauthenticated access, Viewer/Operator separation, bootstrap bearer
compatibility, session CSRF, opaque SSE cookies, token rotation, clipboard
failure privacy, audit privacy, OIDC PKCE and claim mapping, state/nonce/issuer/
audience/expiration/signature/JWKS failures, error-response state consumption,
client-secret permissions, secure
cookies, trusted proxies, migration, frontend token absence, and inherited
Phase 15 lifecycle safeguards.

## Transactional package acceptance

- Manifest: 23 exact source/documentation files with baseline and payload
  SHA-256 values and modes.
- Archive inspection: 41 members; zero traversal paths, links, runtime-state
  entries, caches, or bytecode.
- Clean Phase 15 baseline apply: focused `58 passed`; full
  `426 passed, 31 warnings`; no activation.
- Applied-state idempotency: PASS without file mutation.
- Explicit rollback: all 23 declared paths restored to exact baseline
  content/modes; new paths removed.
- Forced-test-failure rollback: all declared paths restored automatically.
- Dashboard metadata guard: blocked before source mutation.
- Clone-local private state preservation: PASS across apply and both rollback
  paths, excluding the documented test environment and package backup area.
- Credential-output scan: zero clone-local viewer/operator token matches.

## Platform boundary

Executed on Linux with CPython 3.12 in the repository-managed environment.
PowerShell/Windows and macOS paths are statically and deterministically tested;
native platform acceptance remains required. No real IdP, Bedrock, target,
dashboard deployment, image engine, firewall, tunnel, merge, or push was used.
