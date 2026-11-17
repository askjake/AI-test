# Phase 16R deployment runbook

Applying source is not activation. These commands do not start/stop a dashboard,
contact a target/IdP/model, create a tunnel, or change network policy.

## Verify the live baseline

```sh
ROOT=/home/montjac/orchestrator-cookie/orchestrator-cookie/orchestrator-cookie
cd "$ROOT"
git branch --show-current
git rev-parse HEAD
git status --porcelain --untracked-files=all
./install.sh status
```

Expected baseline branch is
`feature/phase15-installer-stabilization-20260825T203216Z`; expected baseline
HEAD is `c4514676c3fa0d9c12db191924ea705ceedb348a`. Stop if identity differs,
source is dirty, or dashboard metadata cannot be authenticated. Do not stash,
reset, adopt, or stop an unrelated process.

## Apply without activation

After verifying the supplied SHA-256 sidecar and extracting the package:

```sh
./install.sh init --with-test
/tmp/orchestrator-cookie-phase16r/orchestrator-cookie-phase16r/apply.sh \
  --target "$ROOT"
```

Windows:

```powershell
.\install.ps1 init --with-test
C:\Temp\orchestrator-cookie-phase16r\apply.ps1 --target $Root
```

The package verifies every baseline and payload hash, refuses active/stale
dashboard metadata, backs up declared source files, applies atomically, and
runs focused plus full tests. A test failure restores the declared baseline.

## Configure OIDC using owner-only files

Obtain approved issuer metadata, client ID, redirect URI, TLS endpoint, role
claim/groups, signing algorithms, and trusted proxy networks. For a
confidential client:

```sh
install -d -m 700 "$ROOT/.orchestrator-cookie/secrets"
umask 077
"${EDITOR:-vi}" "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret"
chmod 600 "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret"
cd "$ROOT"
./install.sh configure --non-interactive \
  --enable-oidc \
  --oidc-issuer 'https://APPROVED-ISSUER' \
  --oidc-client-id 'APPROVED_CLIENT_ID' \
  --oidc-client-secret-file "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret" \
  --oidc-redirect-uri 'https://APPROVED-DASHBOARD/api/v1/auth/oidc/callback' \
  --oidc-role-claim 'groups' \
  --oidc-viewer-value 'APPROVED_VIEWER_GROUP' \
  --oidc-operator-value 'APPROVED_OPERATOR_GROUP' \
  --oidc-tls-terminated \
  --oidc-trusted-proxy 'APPROVED_PROXY_CIDR'
```

Use `--oidc-public-client` instead of a secret file only when the corporate
registration approves a public PKCE client. Windows owners must remove
inherited ACLs from the secret file and grant only their identity.

## LAN/TLS posture

Only after an approved reverse proxy and HTTPS endpoint exist:

```sh
./install.sh configure --non-interactive --lan --bind 0.0.0.0
./install.sh doctor
```

The proxy must strip client-supplied forwarded headers, set its own, and connect
from an explicitly trusted CIDR. This project does not create DNS, certificates,
proxy rules, firewall rules, or tunnels.

## Future MUL jump route

The dashboard remains on the local engineer machine. Do not configure or test
the reported internal target until the approved MUL jump hostname, user, SSH
port, authentication method, pinned host-key records, final target protocol,
and authorization are supplied. Generic RDP/VNC jumps are unsupported. For an
approved SSH route, stage key/known-host references under clone-local owner-only
storage, author the route, validate, and run preflight only with separate
authorization.

## Activation

Only in a separately approved window:

```sh
./install.sh start
./install.sh status
```

Do not combine sign-in activation with target preflight, project execution,
Bedrock refinement, image acquisition, IdP changes, or network changes.
