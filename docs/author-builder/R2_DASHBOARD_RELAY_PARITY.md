# Author Builder R2: Dashboard Relay Parity and Runner Mode Hardening

## Scope and source identity

This narrow corrective revision starts from the exact R1 tracked source tree
`c594d8c56f253486ba9f26d38746ea1820e26dcb`. The isolated repository uses a
synthetic root commit only as a content anchor. It does not claim missing parent
history, remote ancestry, or branch lineage.

The correction does not change Author Builder authorization, host-key trust,
candidate isolation, history, composition, target parsing, or model policy.

## Live failure evidence

After a local runner image mode repair, normal dashboard containers successfully
re-executed the entrypoint as UID 10001. Two local GUI health projects completed
22 of 22 assertions. A bounded `mul-autotest` dashboard run then failed before
the first captured step:

- TigerVNC started but did not create its window within 15 seconds;
- the viewer remained alive until the runner sent SIGTERM;
- the run produced zero planner steps and zero model tokens;
- a separate host-side probe had already received a valid RFB banner from the
  exact managed VNC endpoint;
- the dashboard spawn log contained no target-relay readiness or attachment
  event and allowed the VNC destination directly from the container.

The failure therefore established a launcher-parity defect, not a renewed
entrypoint failure and not a model failure.

## Corrective design

The dashboard spawn backend uses `orchestrator.runtime_runner`, while the native
shell launcher already had the destination-locked target relay. R2 gives the
dashboard path the same transport boundary:

1. The host derives the transport only from the exact managed project through
   `describe_project_transport`.
2. The host resolves the already-approved endpoint into the private per-run
   hosts file and recovers only those pinned addresses for the relay.
3. On Linux, a `DestinationLockedTargetRelay` binds to the inspected container
   bridge gateway, accepts only the bridge subnet, requires a random per-run
   credential, and can open only the preselected endpoint and port.
4. The dashboard passes the established `ORCHESTRATOR_TARGET_RELAY_*` contract
   to the container. `docker/egress_firewall.sh` independently re-derives the
   project transport, removes direct target access, and allows only the relay
   socket.
5. Direct VNC connects through the in-container loopback client. VNC over an SSH
   jump retains strict verification of the declared jump host while its TCP leg
   traverses the relay.
6. Target and Bedrock relay lifetimes enclose only the one container run and are
   closed on normal completion or failure.

R2 also passes `ORCHESTRATOR_EGRESS_PROJECT` for dashboard project runs. This
changes the previous union-of-all-projects firewall calculation into the same
exact-project policy already used by the native launcher.

## Executable-mode correction

The Dockerfile previously used `chmod +x` for the entrypoint and firewall. If a
source snapshot arrived with mode 0700, that operation produced mode 0711. Bash
could execute the entrypoint initially as root but could not reopen it after the
drop to UID 10001, causing exit status 126.

The image build now assigns explicit mode 0755 to both files. Tests reject a
return to the relative `chmod +x` operation.

## Security properties retained

- No host networking is granted to the runner.
- The target destination comes from the managed project, not browser input.
- The relay cannot accept a client-selected destination.
- The target endpoint is omitted from the container's effective direct-egress
  rules whenever the target relay is active.
- Bedrock remains reachable only through its separately authenticated relay.
- No target or model contact is required for source validation.
- No credential or secret content is written to reports or source artifacts.

## Remaining live acceptance gate

Source tests cannot prove the host VPN, Docker bridge, or real VNC service. After
review, image build, immutable local-registry publication, and controlled repin,
run only `mul-autotest`. Acceptance requires:

- a target-relay ready/attached event;
- no direct VNC destination rule in the runner firewall;
- a TigerVNC window and first captured step;
- normal assertion/report completion;
- target, AWS, and model contact limited to that explicitly triggered run.

Do not describe R2 as live-VNC accepted until that gate passes.
