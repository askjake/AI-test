# Phase 16 operator guide

Run commands from the clone root. On Windows, replace `./install.sh` with
`./install.ps1` in PowerShell or `install.cmd` in Command Prompt.

## Normal sign in

Open the dashboard URL and use **Sign in with organization account**. The
identity provider and server assign Viewer or Operator access. If organization
sign-in is not configured, the button explains that state without exposing
configuration or file paths.

## Local owner bootstrap

Copy a role-specific credential without displaying it:

```sh
./install.sh access --role viewer --copy
./install.sh access --role operator --copy
```

Expand **Local bootstrap access** on the Sign in page, paste the credential,
and continue. This path is for clone-owner setup/recovery, not normal users.

If no supported clipboard utility is available, the command stops without
printing the credential. Owner recovery may display only the private file path:

```sh
./install.sh access --show-path
```

Rotate both bootstrap credentials only while the authenticated managed
dashboard is stopped:

```sh
./install.sh stop
./install.sh access --regenerate-tokens
```

Rotation does not print either value. Dashboard restart clears all prior
opaque sessions.

## Access behavior

Viewer access supports projects, run history, live display, reports,
screenshots, and logs. Operator controls remain visibly role-aware; a Viewer
who selects one receives a clear explanation and a sign-in/escalation action.
The server independently rejects the mutation.

## Diagnose without external actions

```sh
./install.sh doctor
./install.sh status
./install.sh logs --lines 200
```

These commands do not call Bedrock, contact targets, acquire images, alter the
firewall, or configure an identity provider.
