# Packaged local OIDC test identity

The packaged local OIDC profile provides distinct Viewer and Operator identities for
functional testing of role-aware features, including Watch & Learn ownership. It is a
test identity provider, not a DISH corporate identity provider and not a production
authentication service.

The profile recreates the previously proven Keycloak/Nginx topology without retaining
its hidden container state:

- the dashboard has the exact backend binding `0.0.0.0:8025`;
- a TLS proxy publishes the application, preferring port `8443`;
- the same proxy publishes the local Keycloak realm, preferring port `9443`;
- Keycloak's HTTP port is private to a dedicated per-clone container network;
- Keycloak retains the image-owned non-root UID 1000 required by its Quarkus
  runtime, while a group-private umask and the host owner's primary group provide
  bounded access to the bind-mounted persistent data;
- a declarative realm import creates the confidential PKCE client, `viewers` and
  `operators` groups, and one generated test account for each role;
- all passwords, private keys, the realm import, and the client secret are generated
  below the ignored owner-only `.orchestrator-cookie` runtime directory;
- the Keycloak and Nginx images are addressed only by reviewed immutable digests.

Keycloak development mode is intentionally used for this bounded local test profile.
Do not expose this profile to the internet or represent it as corporate authentication.

## Provision

Initialize the clone and stop its authenticated managed dashboard before provisioning:

```bash
./install.sh init --with-test
./install.sh stop
./install.sh local-oidc provision --public-host '<dashboard-host-or-ip>' --yes
```

`--yes` explicitly authorizes the pinned image pulls, private Docker network and
container creation, generated TLS/identity material, and runtime configuration change.
No password, client secret, or private key is printed.

Port 8025 is exact and fails closed if occupied. The HTTPS ports prefer 8443 and 9443;
provisioning scans upward when either is occupied and persists the selected ports in the
OIDC issuer and callback configuration. Later starts reuse those exact persisted ports.

Provisioning is idempotent for the same clone, host, dashboard port, and platform. It
does not silently replace an existing realm with different immutable settings.

## Trust the generated local CA

Provisioning prints the generated CA certificate path. Import that public certificate
into the test browser or workstation trust store using the organization's approved
certificate-management route. Private keys must remain under `.orchestrator-cookie`.

The dashboard's server-side OIDC client uses the configured CA file directly, so it does
not disable TLS verification. Browser trust remains an explicit workstation decision.

## Start and sign in

The normal start command verifies and starts the packaged identity containers before it
starts the dashboard:

```bash
./install.sh start
./install.sh status
```

Open the printed `OIDC URL`, not the backend HTTP URL. The sign-in screen labels this
provider as a **local test identity** so it cannot be confused with corporate SSO.

Copy a generated test password without printing it:

```bash
./install.sh local-oidc access --role operator --copy
./install.sh local-oidc access --role viewer --copy
```

The usernames are `local-operator` and `local-viewer`. Each account receives its role
from a signed `groups` claim. Watch & Learn continues to require an OIDC-authenticated,
unique subject; bootstrap sessions are not promoted or treated as equivalent identities.

If a clipboard utility is unavailable, owner recovery can display only the private file
path:

```bash
./install.sh local-oidc access --role operator --show-path
```

## Read-only checks

```bash
./install.sh doctor
./install.sh local-oidc status
```

Doctor inspects configuration, owner-only secret-file metadata, pinned container state,
and the exact port. It does not contact the OIDC provider, a test target, AWS, or a model.
The explicit start action performs bounded, CA-verified OIDC discovery and confirms PKCE
S256 before reporting the local identity stack ready.

## Stop

```bash
./install.sh stop
```

The managed stop command first authenticates and stops the dashboard process, then stops
only the two containers carrying this clone's ownership label. Realm data and generated
credentials remain available for the next start. It does not remove unrelated containers,
networks, images, firewall rules, or user data.

To stop the stack and restore the owner-only runtime configuration captured immediately
before the first provisioning attempt:

```bash
./install.sh stop
./install.sh local-oidc deactivate
```

This is non-destructive: local realm data, generated credentials, and pinned images are
retained. Re-running `local-oidc provision` with the same immutable settings reactivates
the profile.

## Corporate OIDC

Corporate OIDC remains an external-administrator integration. Configure the approved
issuer, client, redirect URI, role values, CA trust, TLS termination, and exact proxy CIDRs
with `install configure`; never copy the local realm's credentials or `test_only` identity
into a corporate deployment.
