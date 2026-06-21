# Multi-namespace control plane (MESH-T2-A)

Before T2-A, every Ferrum Edge control plane (CP) instance served exactly one
namespace. Multi-tenant Kubernetes deployments had to run one CP per
namespace, multiplying the operational footprint. T2-A lifts that
restriction with three coordinated changes:

1. A CP **scope** abstraction (`FERRUM_CP_NAMESPACES`) that declares which
   namespaces the CP serves.
2. Per-namespace **broadcast partitioning** in the CP gRPC server so each
   DP only ever receives its own namespace's config.
3. A **JWT tenancy claim** (`ns`) that pins which namespaces a token bearer
   is authorised to subscribe to, independent of the CP scope. The claim is
   automatically required for `Set` and `All` scopes.

This document is the operator guide for adopting it. The pre-T2-A
single-namespace deployment path is the default and remains byte-identical
when neither new env var is set.

## Env var reference

| Variable | Default | Description |
|---|---|---|
| `FERRUM_CP_NAMESPACES` | unset | Scope. Empty/unset = back-compat single namespace (`FERRUM_NAMESPACE`). `*` = cluster-wide CP (discovers namespaces dynamically). CSV (`prod,staging`) = explicit set. |
| `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` | `false` | When `true`, every CP/DP configuration JWT must carry an `ns` claim. This remains optional only for `Single` scope; `Set` and `All` scopes require `ns` claims automatically even when this flag is `false`. |

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
  automatically. Because this is multi-tenant, every configuration surface
  requires an authenticated `ns` claim before serialising a snapshot.

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

DP configuration JWTs carry an `ns` claim that pins which namespaces the
bearer is authorised to subscribe to. The claim accepts:

- a single string: `"ns": "prod"`
- an array of strings: `"ns": ["prod","staging"]`

The CP authorisation order is:

1. **Standard JWT validation**: HS256 signature with
   `FERRUM_CP_DP_GRPC_JWT_SECRET`, `iss == FERRUM_CP_DP_GRPC_JWT_ISSUER`,
   `exp`/`iat` present, `exp` not expired.

2. **`ns` claim presence policy**: when the CP scope is `Set` or `All`, or
   when `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`, a token with no `ns`
   claim is rejected with `PERMISSION_DENIED`. Missing claims remain
   compatible only for `Single` scope with the flag unset.

3. **`ns` claim authorisation**: if the token has an `ns` claim and the
   requested namespace is NOT in it, reject with
   `PERMISSION_DENIED`. This is the most-restrictive gate — even if the CP
   scope would otherwise allow the namespace, a restrictive claim wins.

4. **CP scope authorisation**: if the requested DP namespace is not
   covered by `FERRUM_CP_NAMESPACES` (or `FERRUM_NAMESPACE` in
   single-namespace mode), reject with `FAILED_PRECONDITION`.

Malformed `ns` claims are rejected as authentication failures. Empty
strings, non-string values, or arrays containing non-strings are not treated
as "missing" because that would let ambiguous tokens fall back to legacy
single-namespace compatibility.

Self-minted DP tokens (the `connect_and_subscribe` path in
`src/grpc/dp_client.rs`) embed a single-string `ns` claim from the DP's own
`FERRUM_NAMESPACE`. Operator-minted tokens that should grant access to
multiple namespaces should embed the claim as an array. xDS ADS has no
explicit namespace request field, so multi-tenant xDS accepts only a
single-namespace `ns` claim; a multi-namespace xDS token is ambiguous and
is rejected.

## Migration steps

1. **Inventory**: enumerate the namespaces you want the CP to serve.
   `kubectl get ns -l ferrum-tenant=true -o name | sed 's|namespace/||'`
   is a typical pattern.

2. **Roll CPs first**: deploy the new binary with the existing
   `FERRUM_NAMESPACE` and `FERRUM_CP_NAMESPACES` unset. Behavior is
   byte-identical to the pre-T2-A path; verify via the existing
   single-namespace CP smoke tests.

3. **Mint tenant-scoped CP/DP tokens**: confirm every DP or mesh node that
   will talk to a multi-namespace CP presents an `ns` claim. Prefer one
   credential per tenant, or an asymmetric token issuer with tenant-scoped
   subjects, over one fleet-wide HS256 secret. If you must keep the shared
   HS256 secret during migration, keep token TTLs short and use `ns` claims.

4. **Expand scope incrementally**: set `FERRUM_CP_NAMESPACES="ns-a,ns-b"`
   on one CP at a time. The CP startup log will print the resolved scope.
   DPs whose tokens carry matching `ns` claims can now subscribe; missing
   or wrong claims fail before snapshot serialisation.

5. **(Optional) Switch to `*`**: once you're comfortable with the explicit
   set, set `FERRUM_CP_NAMESPACES=*` so new namespaces are picked up
   automatically. Required for `helm install`-style provisioning where the
   CP doesn't know the tenant list ahead of time.

6. **(Optional) Tighten single-namespace CPs**: set
   `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` on single-namespace CPs after
   all DPs carry `ns` claims. Multi-namespace CPs already enforce this
   automatically.

7. **Decommission per-namespace CP fleet**: once the multi-namespace CP is
   serving all tenants, drain DPs from the old CPs and tear them down.

## Threat model and validation evidence

The attacker is a compromised tenant A DP, mesh node, or xDS client that
knows a valid CP/DP JWT signing secret and tries to receive tenant B data by
changing local environment, subscription request namespace, xDS node
metadata, reconnect timing, resume resource versions, or failover target.
The attacker must not receive tenant B gateway resources, mesh resources, or
trust material on the wire.

Pre-fix validation was run at commit
`1252246777bdaa8fcbe6b401ffdc9020d7f71e11`. A temporary SQLite CP database
was seeded with tenant-tagged proxies, consumers, and plugin markers for
`tenant-a` and `tenant-b`; CP startup was exercised with
`FERRUM_CP_NAMESPACES=tenant-a,tenant-b` and `FERRUM_CP_NAMESPACES=*` while
`FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` was unset. Existing integration tests
confirmed that `Set` and `All` scopes accepted a shared no-claim JWT and
returned whichever namespace was requested. Source review also found that
native `MeshConfigSync`, xDS ADS, K8s controller broadcasts, and gateway
trust bundles were not consistently namespace-authorised.

Post-fix CI gates this with `tests/integration/cp_multi_namespace_tests.rs`:
missing, malformed, wrong, and ambiguous claims fail before the first
snapshot; tenant A mesh wire JSON contains only tenant A services; and
multi-tenant trust bundle side channels serialise as `null`.

## Protocol matrix

| Surface | Authenticated namespace source | Multi-namespace behaviour |
|---|---|---|
| `ConfigSync.Subscribe` | `SubscribeRequest.namespace` authorised by JWT `ns` | Missing/wrong/malformed claims fail before initial snapshot serialisation. Full snapshots, deltas, lag recovery, and K8s-triggered broadcasts are namespace-filtered. |
| `ConfigSync.GetFullConfig` | `FullConfigRequest.namespace` authorised by JWT `ns` | Same authorisation and filtering as `Subscribe`; wrong claims fail before response serialisation. |
| Native `MeshConfigSync.MeshSubscribe` | `MeshSubscribeRequest.namespace` authorised by JWT `ns` | Same authorisation as ConfigSync. Full, delta, and lag recovery slices are built from a namespace-filtered config. |
| xDS ADS | Single namespace from JWT `ns` | Multi-tenant streams require exactly one `ns` value because ADS has no namespace request field. Node metadata and resume resource versions cannot change tenant identity. |
| Kubernetes controller broadcast | Reconciled config namespaces | ConfigSync broadcasts fan out via `NamespaceBroadcasts`; each namespace is serialised independently. |
| Gateway trust bundles | Single-namespace CP only | Top-level gateway trust bundles and mesh trust bundles are withheld in `Set` and `All` scopes until a namespaced trust-bundle store is available. |
