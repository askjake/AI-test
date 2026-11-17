# Phase 16 sign-in and authorization architecture

## Outcome

Phase 16 replaces browser-managed bearer tokens with an application sign-in
experience. Existing clone-local viewer and operator tokens remain compatible
for lifecycle checks and API clients, but the browser exchanges them for an
opaque server-side session. OIDC uses authorization code with PKCE and remains
disabled until the clone owner supplies a complete, valid configuration.

## Trust boundaries

1. The clone owner controls `.orchestrator-cookie`, bootstrap credentials, the
   optional OIDC client-secret file, and installer configuration.
2. The browser receives only an opaque session identifier in an HttpOnly
   cookie. It receives its server-derived role and a per-session CSRF value.
3. Every API dependency derives the actor and role from a validated bearer
   credential or server-side session. Browser-supplied role values are ignored.
4. Corporate identity is accepted only after discovery issuer, PKCE state,
   nonce, signature, fixed algorithm allowlist, issuer, audience, expiration,
   and optional multi-audience `azp` checks pass.
5. OIDC access tokens, refresh tokens, ID tokens, authorization codes, and
   client secrets are not retained in session records or audit events.

## Capability matrix

| Capability | Viewer | Operator | Clone owner |
| --- | --- | --- | --- |
| Dashboard, reports, live display, screenshots, logs | Allowed | Allowed | Allowed through a signed-in role |
| Create/edit/save authoring content | Denied | Allowed | Configure an operator identity |
| Guarded model refinement | Denied | Allowed | Configure model prerequisites separately |
| Target preflight | Denied | Allowed | Configure target prerequisites separately |
| Start/stop authorized project work | Denied | Allowed | Configure runtime prerequisites separately |
| Rotate bootstrap credentials | Denied | Denied | Local installer command only |
| Configure OIDC/TLS/trusted proxies | Denied | Denied | Local installer command only |

Every application mutation route retains a server-side operator dependency;
session and logout routes require an authenticated session. The UI's role state
changes presentation and explanations, not authorization decisions.

## Session and CSRF flow

- `POST /api/v1/auth/bootstrap/session` validates a clone-local credential and
  creates an opaque session.
- `GET /api/v1/auth/oidc/start` creates single-use state, nonce, and a high
  entropy PKCE verifier. Only the S256 challenge enters the authorization URL.
- `GET /api/v1/auth/oidc/callback` consumes the state transaction, exchanges
  the code, validates the ID token, maps the configured claim values, and then
  creates an opaque session.
- Provider-denied callbacks also validate and consume their state transaction,
  preventing replay even when no authorization code is returned.
- The primary cookie is HttpOnly, SameSite=Lax, scoped to `/`, and Secure when
  the validated TLS-termination posture is enabled.
- Cookie-authenticated non-safe requests require the matching `X-CSRF-Token`.
- EventSource receives a separate opaque, HttpOnly, path-scoped session cookie;
  no bearer credential is placed in a URL or cookie.
- Sessions are process-local and intentionally expire on dashboard restart.

## OIDC provider boundary

Discovery and token operations are behind an injectable transport so tests use
deterministic fakes. Application startup never contacts the provider. The first
provider call occurs only after the user selects organization sign-in.

The implementation requires:

- HTTPS issuer and discovered endpoints;
- exact configured/discovered issuer match;
- advertised PKCE S256 support;
- fixed asymmetric signing algorithms configured alongside the provider;
- JWKS `kid` selection with one bounded refresh for key rotation;
- required `exp`, `iat`, `iss`, `aud`, `sub`, and `nonce` claims;
- exact nonce and optional authorization-response issuer validation;
- configured role-claim values mapped to Viewer or Operator.

## Network and lifecycle invariants

Loopback remains the default. LAN OIDC configuration is rejected unless the
redirect URI is HTTPS, TLS termination is explicit, and at least one bounded
trusted-proxy network is configured. Uvicorn proxy-header handling is disabled
unless those networks are present. Phase 15's preferred-port scan, authenticated
runtime identity, actual-port persistence, status, and stop rules are unchanged.

## Mutation audit

Successful, denied, and failed mutations append owner-only JSON Lines records
containing timestamp, bounded actor identity, role, authentication method,
route-template action, and outcome. Request bodies, cookies, headers, query
values, and credential material are never recorded.
