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

Explicit JWT **audience-claim binding** is now **implemented** (issue #2475),
as defense-in-depth layered on top of — never instead of — the per-remote
secret isolation. The minted-token issuer continues to follow the shared
`FERRUM_CP_DP_GRPC_JWT_ISSUER` because the remote CP pins the issuer, not a
per-remote one.

## Decision — Remote-Discovery Audience Binding

Signature, issuer, and expiry bind a discovery token to a *credential*, not to
a *destination*. Under the supported (deprecated) shared-secret fallback, two
clusters sharing `FERRUM_CP_DP_GRPC_JWT_SECRET` and the same issuer accepted
each other's discovery tokens. Ferrum binds each token to its target cluster:

- The **target-cluster identifier** is stable, operator-visible, and
  deliberately independent of the mutable `control_plane_url`: the polling data
  plane uses `RemoteCluster.name`, and the receiving control plane declares the
  same identifier as `FERRUM_MESH_CLUSTER_AUDIENCE`. Neither value is a secret
  and neither is derived from one, so nothing credential-bearing is added to
  `RemoteCluster` or serialized into a mesh slice.
- The poller mints `aud = "ferrum-mesh-discovery:<RemoteCluster.name>"` as a
  **single-valued string** claim and marks the subscription
  `MeshSubscribeRequest.remote_discovery = true`.
- The receiving control plane requires exactly one `aud` equal to
  `ferrum-mesh-discovery:<FERRUM_MESH_CLUSTER_AUDIENCE>`. Missing, malformed,
  multiple/ambiguous, and mismatched audiences are refused, and a control plane
  with **no** `FERRUM_MESH_CLUSTER_AUDIENCE` refuses every cross-cluster
  subscription rather than accepting an unbound one.

**Token-purpose separation.** Ordinary local mesh `MeshSubscribe` tokens carry
the stable fixed audience `ferrum-mesh-subscribe:local`; discovery tokens carry
the target-specific `ferrum-mesh-discovery:<cluster>` audience. The server
requires the exact audience selected by the request class, so clearing
`remote_discovery` cannot downgrade a discovery token, setting it cannot
upgrade a local token, and the false/default branch cannot admit a legacy
no-audience token. Ordinary CP↔DP `ConfigSync` and xDS ADS remain unchanged:
their tokens carry **no** audience and their verifiers refuse every
audience-bearing token, preserving `jsonwebtoken`'s strict `validate_aud`
posture.

Every other check is unchanged and still applies first: HS256 signature against
the per-remote or shared secret, required `exp`/`iat`/`sub`/`iss`, pinned
issuer, the `ns` namespace claim, TLS/production transport posture, and
fail-closed per-remote credential resolution. (DP tokens still *mint* a
`role: data_plane` claim for operator/tooling conventions; the CP gRPC
verifier does not authorize on it.) A refused subscription fails the whole poll, so the data
plane keeps that cluster's last-good endpoints under the existing
`FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` window. Refusals are counted
as `ferrum_mesh_subscribe_audience_rejections_total{subscription,reason}` with
compile-time-constant labels and audited as
`audit.event="mesh_subscribe_audience_rejected"`; no token, claim value, or
expected audience is ever logged or exported.

### Compatibility

This decision intentionally breaks mixed-version native `MeshSubscribe`.
Pre-change local clients and pre-#3202 remote pollers both present
`remote_discovery=false` with no `aud`; a new receiver cannot distinguish those
wire shapes and refuses both. New local clients present
`ferrum-mesh-subscribe:local`, and new remote pollers present a
`ferrum-mesh-discovery:<cluster>` audience; an old receiver refuses either
audience-bearing token. Control planes and all native local/remote
MeshSubscribe clients must therefore be upgraded as one compatibility unit.
Ordinary ConfigSync and xDS remain audience-less and are not part of this
breaking change.

### Residual

`RemoteCluster.name` is reused as the target-cluster identifier rather than
introducing a separate per-cluster audience override field. That requires the
name to be the identifier the peer knows itself by (the Istio cluster-id
convention) instead of a local-only alias. An explicit override on
`RemoteCluster` can be added later without changing the wire contract or the
verifier.
