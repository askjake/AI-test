# Phase 16 change report

## Product changes

- Replaced the raw Dashboard Authentication popup and browser token storage
  with a dedicated Sign in route.
- Added organization sign-in, local owner bootstrap, role descriptions, and
  denied/expired/unavailable states.
- Added server-derived Actor records and opaque HttpOnly sessions.
- Added per-session CSRF enforcement for cookie-authenticated mutations.
- Kept existing bearer tokens compatible for lifecycle/API use.
- Added role-aware controls and Viewer escalation guidance.
- Protected report and screenshot files behind viewer authorization.
- Added credential-free mutation auditing.

## Installer and configuration changes

- Added `install access --role viewer|operator --copy`.
- Added `install access --show-path` and token rotation.
- Added typed, migration-compatible OIDC, role-claim, TLS, trusted-proxy,
  signing-algorithm, and session-lifetime configuration.
- Added safe proxy-header argv behavior and clone-local audit path propagation.
- Added pinned PyJWT and cryptographic signature dependencies.

## OIDC changes

- Added authorization code with PKCE S256.
- Added discovery issuer and endpoint validation.
- Added fixed asymmetric algorithm, JWKS, signature, issuer, audience,
  expiration, nonce, `azp`, and role-claim checks.
- Added optional owner-only client-secret file support.
- Added deterministic fake-provider acceptance coverage; no real IdP was used.

## Preserved behavior

- Loopback installation default.
- Phase 15 preferred-port fallback and authenticated lifecycle identity.
- Separate runner image, target, model, and refinement gates.
- Existing token-file schema and existing installer commands.
- No automatic service activation, target/model contact, firewall, tunnel,
  merge, or push.
