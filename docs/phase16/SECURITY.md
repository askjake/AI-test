# Phase 16 security model

## Credential handling

- Bootstrap viewer and operator values remain in the existing owner-only
  `.orchestrator-cookie/config/dashboard_tokens.json` file.
- `install access --role ... --copy` sends a credential to a local clipboard
  process over stdin. It never places the value in argv or output.
- The Sign in page clears its bootstrap input before processing the response
  and does not use local storage, session storage, URLs, or console logging.
- Browser cookies contain random session identifiers, never bootstrap, OIDC,
  or AWS credentials.
- An OIDC client secret is optional. When used, runtime JSON contains only its
  absolute path. The value is read from an owner-only, regular, non-symlink
  local file during the explicit code exchange.
- OIDC access, refresh, and ID tokens are validated in memory and discarded.

## Authorization

Viewer and Operator roles are derived on the server. An operator is also a
viewer. Viewers receive a structured `operator_required` denial for every
operator dependency, while unauthenticated and expired sessions receive
distinct structured states. There is no browser endpoint for bootstrap or OIDC
administration.

## Browser protections

- Primary session: HttpOnly, SameSite=Lax, path `/`, bounded lifetime.
- EventSource session: opaque, HttpOnly, SameSite=Strict, run-route path only.
- Secure cookie policy is based on validated owner configuration, never on an
  untrusted forwarded header.
- All cookie-authenticated POST, PUT, PATCH, and DELETE requests require a
  per-session CSRF header.
- Reports and screenshots under `/reports` require viewer authorization.
- Redirects expose only bounded state labels such as `denied` or `expired`.

## Proxy and TLS rules

Uvicorn starts with `--no-proxy-headers` unless explicit trusted proxy CIDRs
exist. Wildcard networks are rejected. A reverse proxy must remove inbound
forwarded headers and set its own values. LAN OIDC is blocked unless the public
redirect URI is HTTPS and TLS termination is explicitly declared.

The application does not create certificates, configure a proxy, open a
firewall, or create a tunnel. Those are separately approved infrastructure
actions.

## Audit privacy

Mutation audit records contain only actor, role, authentication method, route
template, outcome, and UTC timestamp. They never include request bodies, token
values, passwords, cookies, authorization codes, model credentials, target
credentials, or full URLs.

## Deliberate limitations

- Sessions and OIDC transactions are in-memory for the single managed
  dashboard process. A restart signs users out, which is fail-safe.
- The current confidential-client adapter sends the optional client secret as
  a form field. Confirm the corporate provider permits `client_secret_post`, or
  extend the provider abstraction for an approved method before activation.
- Native Windows PowerShell and macOS clipboard/runtime execution require
  platform acceptance on those systems. The implementation has deterministic
  command-selection and failure tests on Linux.
- Corporate discovery metadata, redirect registration, TLS endpoint, and role
  group names are external dependencies and are not invented by this release.

## Standards basis

- OpenID Connect Core 1.0: <https://openid.net/specs/openid-connect-core-1_0-18.html>
- OAuth 2.0 PKCE: <https://www.rfc-editor.org/rfc/rfc7636.html>
- OAuth 2.0 Security Best Current Practice: <https://www.rfc-editor.org/rfc/rfc9700.html>
- Authorization Server Metadata: <https://www.rfc-editor.org/rfc/rfc8414.html>
