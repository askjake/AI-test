# Phase 16 deployment runbook

No deployment or service restart was performed while building this release.
Use a separately approved activation window.

## 1. Verify the real clone

```sh
ROOT=/home/montjac/orchestrator-cookie/orchestrator-cookie/orchestrator-cookie
cd "$ROOT"
git branch --show-current
git rev-parse --short=12 HEAD
git status --short
./install.sh status
```

Expected pre-apply branch and commit from the handoff are
`feature/phase15-installer-stabilization-20260825T203216Z` and `c451467`.
Stop if identity differs or tracked changes are present. The source ZIP used to
build this release contained no `.git` or clone-local runtime state, so these
facts require verification on the real clone.

Also verify, without printing credential values, that the real private runtime
still contains the intended LAN/fallback-port and approved Bedrock profile.
The attachment itself could not prove either private-state claim.

## 2. Verify and extract the release

```sh
cd /tmp
sha256sum -c Orchestrator_Cookie_Phase16_SignIn_Role_Aware_20260825_v1.tar.gz.sha256
mkdir -p /tmp/orchestrator-cookie-phase16
tar -xzf Orchestrator_Cookie_Phase16_SignIn_Role_Aware_20260825_v1.tar.gz \
  -C /tmp/orchestrator-cookie-phase16
```

## 3. Apply transactionally without activation

```sh
/tmp/orchestrator-cookie-phase16/orchestrator-cookie-phase16/apply.sh \
  --target "$ROOT"
```

The package verifies the exact baseline, backs up only declared files, applies
atomically, installs the pinned test profile, and runs focused plus full tests.
Failure automatically restores the declared baseline. It does not start or
stop a dashboard, contact an IdP/model/target, modify a firewall, merge, or push.

## 4. Configure OIDC as the clone owner

Obtain the approved issuer, client ID, exact redirect URI, role claim, Viewer
values, Operator values, TLS endpoint, and trusted proxy ranges from the
corporate identity/platform owners.

For a confidential client, create the secret file without putting its value in
shell history:

```sh
install -d -m 700 "$ROOT/.orchestrator-cookie/secrets"
umask 077
"${EDITOR:-vi}" "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret"
chmod 600 "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret"
```

Configure metadata and mappings. Replace every example value with approved
data; repeat `--oidc-viewer-value` or `--oidc-operator-value` for multiple
values:

```sh
cd "$ROOT"
./install.sh configure --non-interactive \
  --enable-oidc \
  --oidc-issuer 'https://IDENTITY.EXAMPLE' \
  --oidc-client-id 'APPROVED_CLIENT_ID' \
  --oidc-client-secret-file "$ROOT/.orchestrator-cookie/secrets/oidc-client-secret" \
  --oidc-redirect-uri 'https://DASHBOARD.EXAMPLE/api/v1/auth/oidc/callback' \
  --oidc-role-claim 'groups' \
  --oidc-viewer-value 'APPROVED_VIEWER_GROUP' \
  --oidc-operator-value 'APPROVED_OPERATOR_GROUP' \
  --oidc-tls-terminated \
  --oidc-trusted-proxy '127.0.0.1/32'
```

For an approved public PKCE client, substitute `--oidc-public-client` for the
secret-file option.

On Windows, create the file under `.orchestrator-cookie\secrets`, remove
inherited ACLs with `icacls`, grant only the clone owner, and pass its absolute
path to `install.ps1 configure`.

## 5. LAN and TLS posture

Only after the reverse proxy and HTTPS endpoint are approved and ready:

```sh
./install.sh configure --non-interactive --lan --bind 0.0.0.0
./install.sh doctor
```

The proxy must terminate TLS, remove client-supplied forwarded headers, set its
own forwarding headers, and connect from an explicitly configured trusted
network. This release does not configure the proxy, certificate, DNS, tunnel,
or firewall.

## 6. Explicit activation

After separate approval:

```sh
./install.sh start
./install.sh status
```

Open the reported actual URL and accept:

1. unauthenticated navigation reaches Sign in;
2. Viewer can read and receives an operator explanation on mutation;
3. Operator can perform a harmless authoring validation;
4. organization sign-in maps the approved test identities correctly;
5. local bootstrap works as recovery;
6. status and stop authenticate the managed runtime on its actual selected port.

Do not run a project, refinement, target preflight, Bedrock call, image action,
or network change as part of sign-in activation unless separately approved.
