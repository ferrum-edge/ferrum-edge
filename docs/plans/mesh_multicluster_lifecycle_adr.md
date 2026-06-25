# Mesh Multicluster Lifecycle ADR

## Status

Accepted for the M5 hardening track.

## Context

Multicluster federation and endpoint discovery originally preserved last-good
runtime state indefinitely after poll failures. That was useful during early
bring-up, but it created two production risks:

- a remote trust bundle could remain active long after the federation endpoint
  stopped serving fresh material;
- remote endpoints could remain in the local registry after the remote control
  plane became unreachable.

The existing reconcilers already fail closed on explicit config withdrawal:
removing a `RemoteCluster`, changing its poll identity, or withdrawing trust
stops the poller and removes cached state. Poll failure staleness needs a
different lifecycle: remove the cached state once it exceeds a bounded window,
but keep the poller generation alive so a recovered peer can reinstall without
waiting for a new mesh slice.

## Decision

Ferrum uses separate bounded-staleness windows for the two M5 runtime caches:

- `FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS` defaults to `3600`.
- `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` defaults to `300`.

On each failed poll, the relevant poll loop compares the current time with the
last successful fetch timestamp. If age is greater than the configured window:

- federation removes the polled trust bundle from the active federation
  snapshot and wakes slice apply so outbound mTLS and inbound SPIFFE
  verification recompute the effective trust set;
- remote discovery removes the remote endpoints and clears their
  success/last-success/age metrics while keeping the discovery poller alive.

Expiration does not retire the poll generation. A later successful poll from
the same configured `RemoteCluster` can reinstall fresh trust or endpoints.
Explicit config withdrawal still retires the generation and blocks in-flight
polls from reinstalling removed state.

`0` keeps the pre-hardening indefinite retention posture for development and
tests only. When `FERRUM_MESH_PRODUCTION_MODE=true`, validation rejects `0`
while the corresponding poller is enabled.

Remote discovery also enforces production transport posture:

- production mode accepts only `https://` and `grpcs://` remote
  `control_plane_url` values;
- plaintext `http://` and `grpc://` remain available for local/dev/test;
- `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` is refused in production when remote
  discovery is enabled.

HTTPS with system roots remains valid. Operators can still supply
`FERRUM_DP_GRPC_TLS_CA_CERT_PATH` and client certificate/key material when
private PKI or remote-control-plane mTLS is required.

## Follow-Up

Per-remote credential references are now **implemented**: `RemoteCluster.discovery_credential_ref`
names a credential resolved data-plane-side against
`FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` (a ref -> secret map, itself
resolvable through the external-secret backends), so each remote cluster
authenticates to its own control plane with a distinct JWT secret rather than a
single shared one — and the raw secret is never embedded in or serialized from a
mesh slice. A reference that does not resolve fails that cluster's discovery
closed (it is not polled); an unset reference falls back to the shared CP/DP
secret, a posture now warned-as-deprecated in production multi-cluster. Because
the remote CP validates the HS256 signature with its own secret, a token issued
for one cluster cannot authenticate to another.

The remaining auth hardening step is **explicit JWT audience-claim binding**:
minting the discovery token with an `aud` scoped to the target cluster plus
remote-CP-side audience validation, as defense-in-depth layered on top of the
per-remote secret isolation (the per-remote secret already provides the cluster
binding). The minted-token issuer continues to follow the shared
`FERRUM_CP_DP_GRPC_JWT_ISSUER` because the remote CP pins the issuer, not a
per-remote one.
