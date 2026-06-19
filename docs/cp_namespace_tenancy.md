# Multi-namespace control plane (MESH-T2-A)

Before T2-A, every Ferrum Edge control plane (CP) instance served exactly one
namespace. Multi-tenant Kubernetes deployments had to run one CP per
namespace, multiplying the operational footprint. T2-A lifts that
restriction with three coordinated changes:

1. A CP **scope** abstraction (`FERRUM_CP_NAMESPACES`) that declares which
   namespaces the CP serves.
2. Per-namespace **broadcast partitioning** in the CP gRPC server so each
   DP only ever receives its own namespace's config.
3. An optional **JWT tenancy claim** (`ns`) that pins which namespaces a
   token bearer is authorised to subscribe to, independent of the CP scope.

This document is the operator guide for adopting it. The pre-T2-A
single-namespace deployment path is the default and remains byte-identical
when neither new env var is set.

## Env var reference

| Variable | Default | Description |
|---|---|---|
| `FERRUM_CP_NAMESPACES` | unset | Scope. Empty/unset = back-compat single namespace (`FERRUM_NAMESPACE`). `*` = cluster-wide CP (discovers namespaces dynamically). CSV (`prod,staging`) = explicit set. |
| `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` | `false` | When `true`, every DP `ConfigSync.Subscribe` and mesh `MeshConfigSync.MeshSubscribe` JWT must carry an `ns` claim authorising the subscribe namespace; tokens without it are rejected. |

Both vars live in `[cp_dp]` of `ferrum.conf` next to
`FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`. The scope is also surfaced in the
CP startup logs (`CP mode: serving N namespaces: [...]`).

## Scope resolution

`FERRUM_CP_NAMESPACES` parses to one of three internal shapes:

- **`Single(ns)`** — back-compat default. CP loads `FERRUM_NAMESPACE` from
  the database and serves only that namespace. DPs in other namespaces are
  rejected at subscribe time with `FAILED_PRECONDITION` and an error
  message naming both namespaces.

- **`Set({ns_a, ns_b, ...})`** — multi-tenant explicit set. CP loads each
  namespace independently and partitions deltas per namespace at broadcast
  time. DPs in unlisted namespaces are rejected. New namespaces require a
  CP rolling restart.

- **`All`** — cluster-wide. CP discovers namespaces from the database on
  every poll tick (`list_namespaces()`), so new tenants are picked up
  automatically. Combine with `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` for
  meaningful tenancy isolation; otherwise any DP that knows the shared
  CP/DP JWT secret can subscribe to any tenant by changing its
  `FERRUM_NAMESPACE`.

Whitespace is trimmed; duplicates are deduplicated; `*` cannot be combined
with explicit entries (validation error).

## Per-namespace broadcast partitioning

Pre-T2-A the CP used one `tokio::broadcast::Sender<ConfigUpdate>` shared by
every subscribed DP, and DPs ignored cross-namespace rows after receiving
them. That was acceptable for a single-namespace CP but leaks resources
once the CP serves multiple namespaces.

T2-A replaces the single sender with a per-namespace `DashMap` of senders.
Each subscriber connects to exactly one channel (its own namespace), so a
delta written into namespace A is invisible to subscribers in namespace B.
The initial snapshot is filtered to the DP's namespace before serialisation
— the wire never carries cross-namespace data.

The DP-side `dp_client::filter_config_to_namespace` filter still runs as a
defense-in-depth backstop: if a future CP regression were to bypass the
per-namespace filter, the DP would still drop the cross-namespace rows
before applying them. Both filters use the canonical
`config.proxies[i].namespace == requested_namespace` check.

### Memory footprint

Each per-namespace channel is sized at `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`
(default 128). With N served namespaces, the upper bound on broadcast
memory is roughly `capacity * N * sizeof(ConfigUpdate)`. For typical
mid-sized config snapshots (hundreds of KiB) this is well under 1 GiB even
for hundreds of namespaces. Operators running `*` scope against thousands
of tenants should tune `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY` down (e.g.
to 32) to keep the per-namespace channel small.

## JWT tenancy claim

DP `ConfigSync.Subscribe` and mesh `MeshConfigSync.MeshSubscribe` JWTs may
carry an optional `ns` claim that pins which namespaces the bearer is
authorised to subscribe to. The claim accepts:

- a single string: `"ns": "prod"`
- an array of strings: `"ns": ["prod","staging"]`

The CP authorisation order is:

1. **Standard JWT validation**: HS256 signature with
   `FERRUM_CP_DP_GRPC_JWT_SECRET`, `iss == FERRUM_CP_DP_GRPC_JWT_ISSUER`,
   `exp`/`iat` present, `exp` not expired.

2. **`ns` claim presence policy** (T2-A): when
   `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` and the token has no `ns`
   claim, reject with `PERMISSION_DENIED`. When the policy is `false`
   (default) and there is no claim, skip to step 4.

3. **`ns` claim authorisation** (T2-A): if the token has an `ns` claim and
   the requested DP namespace is NOT in it, reject with
   `PERMISSION_DENIED`. This is the most-restrictive gate — even if the CP
   scope would otherwise allow the namespace, a restrictive claim wins.

4. **CP scope authorisation**: if the requested DP namespace is not
   covered by `FERRUM_CP_NAMESPACES` (or `FERRUM_NAMESPACE` in
   single-namespace mode), reject with `FAILED_PRECONDITION`.

Self-minted DP tokens (the `connect_and_subscribe` path in
`src/grpc/dp_client.rs`) and native mesh-client tokens
(`src/modes/mesh/config_consumer/native_client.rs`) embed a single-string
`ns` claim from the process' own `FERRUM_NAMESPACE`, so data planes and mesh
nodes continue to work out of the box even when the CP runs with
`FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`. Operator-minted tokens that should
grant access to multiple namespaces should embed the claim as an array.

## Migration steps

1. **Inventory**: enumerate the namespaces you want the CP to serve.
   `kubectl get ns -l ferrum-tenant=true -o name | sed 's|namespace/||'`
   is a typical pattern.

2. **Roll CPs first**: deploy the new binary with the existing
   `FERRUM_NAMESPACE` and `FERRUM_CP_NAMESPACES` unset. Behavior is
   byte-identical to the pre-T2-A path; verify via the existing
   single-namespace CP smoke tests.

3. **Expand scope incrementally**: set `FERRUM_CP_NAMESPACES="ns-a,ns-b"`
   on one CP at a time. The CP startup log will print the resolved scope.
   DPs in `ns-b` (previously rejected) can now subscribe; existing `ns-a`
   subscribers continue to receive only `ns-a` config.

4. **(Optional) Switch to `*`**: once you're comfortable with the explicit
   set, set `FERRUM_CP_NAMESPACES=*` so new namespaces are picked up
   automatically. Required for `helm install`-style provisioning where the
   CP doesn't know the tenant list ahead of time.

5. **(Optional) Tighten tenancy**: deploy operator-minted DP tokens with
   `ns` claims, then set `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`. This
   prevents a compromised DP for tenant A from subscribing to tenant B by
   changing only its `FERRUM_NAMESPACE` value.

6. **Decommission per-namespace CP fleet**: once the multi-namespace CP is
   serving all tenants, drain DPs from the old CPs and tear them down.

## What is out of scope for T2-A

- xDS ADS continues to use the legacy single-namespace path. Native
  `MeshConfigSync.MeshSubscribe` shares the ConfigSync CP-scope and `ns`
  claim admission gates, but still uses one CP-wide mesh update channel and
  computes each subscriber's namespace slice from the current config shadow.
  xDS multi-namespace support is tracked separately.
- Per-namespace gateway trust bundles. The CP currently loads
  `load_gateway_trust_bundles` from `FERRUM_NAMESPACE` only; multi-tenant
  CPs share the same trust material across all served namespaces. Splitting
  this is straightforward but deferred to a follow-up so this PR stays
  reviewable.
- K8s controller's broadcast hook (`start_k8s_controller(... update_tx ...)`).
  It still consumes the back-compat single sender; T2-B will revisit
  alongside the K8s controller default-on flip.
