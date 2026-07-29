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
| `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` | unset | **CP side.** Path to the namespace-bound verification credentials described in [Trust binding](#trust-binding-ghsa-3f2j-wwqw-grmg). **Required for `Set` and `All` scopes** — a multi-namespace CP refuses to start with only `FERRUM_CP_DP_GRPC_JWT_SECRET`. |
| `FERRUM_CP_DP_GRPC_JWT_KEY_ID` | unset | **DP / mesh / xDS client side.** JWS `kid` stamped on self-minted tokens, selecting which trust-bundle credential verifies them. |
| `FERRUM_DP_CP_GRPC_TOKEN_FILE` | unset | **DP / mesh / xDS client side.** Path to an externally issued bearer token presented instead of minting one. The node then holds no signing key at all. |
| `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` | `false` | REST-plane counterpart (issue #2120): when `true`, namespace-scoped **admin API** routes require the admin JWT (signed with `FERRUM_ADMIN_JWT_SECRET`) to carry an `ns` claim authorizing the `X-Ferrum-Namespace` value; violations are 403. Same claim shapes as the gRPC plane. Without it, admin JWTs are global and the namespace header is only a routing selector — set both flags for tenancy enforcement on both planes. See `docs/admin_api.md`. |

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

DP, native mesh, and xDS configuration JWTs carry an `ns` claim that pins
which namespaces the bearer is authorised to subscribe to. The claim accepts:

- a single string: `"ns": "prod"`
- an array of strings: `"ns": ["prod","staging"]`

The CP authorisation order is:

1. **Credential selection**: the JWS `kid` header selects which trusted
   verification credential must check the signature. `kid` is a *selector*,
   never a grant — naming another tenant's `kid` without holding that key
   fails step 2. A CP running a trust bundle rejects a token with no `kid`
   (`missing_key_id` — actionable for migration), an unknown one
   (`unknown_key_id`), or one whose `alg` is not the algorithm that credential
   was provisioned for (`algorithm_mismatch`). Unknown-key, algorithm-mismatch,
   and signature/claims-validation failures share one fixed outward
   `UNAUTHENTICATED` message so response text cannot enumerate the trusted
   inventory; internal diagnostics use the closed reason labels above.

2. **Standard JWT validation**: signature under the selected credential,
   `iss == FERRUM_CP_DP_GRPC_JWT_ISSUER`, `exp`/`iat`/`sub` present, `exp`
   not expired. Single-namespace CPs may still use the legacy fleet-wide
   HS256 secret here.

3. **Namespace resolution (server-derived)**: the authorised set is the
   intersection of
   - the credential's `namespaces` allow-list from *CP configuration* (the
     ceiling — absent only for the legacy shared secret),
   - the namespace encoded in the authenticated mTLS peer's SPIFFE identity,
     when the connection presents one, and
   - the token's own `ns` claim, when present.

   Every input can only remove namespaces. An empty intersection is
   `PERMISSION_DENIED` (`no_authorized_namespace`) at authentication time,
   before any tenant state is read.

4. **`ns` claim presence policy**: when the CP scope is `Set` or `All`, or
   when `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`, a JWT that does not carry an
   `ns` claim is rejected with `PERMISSION_DENIED` — even if a trust-bundle
   credential or SPIFFE peer already produced a non-empty effective set. A
   server-derived ceiling must never make a missing claim look present.
   Missing claims remain compatible only for `Single` scope with the flag
   unset; in that case the effective credential ∩ peer bound still applies.

5. **Requested-namespace authorisation**: if the requested namespace is NOT in
   the resolved (effective) set, reject with `PERMISSION_DENIED`. This is the
   most-restrictive gate — even if the CP scope would otherwise allow the
   namespace, a restrictive credential or claim wins.

6. **CP scope authorisation**: if the requested DP namespace is not
   covered by `FERRUM_CP_NAMESPACES` (or `FERRUM_NAMESPACE` in
   single-namespace mode), reject with `FAILED_PRECONDITION`.

Malformed `ns` claims are rejected as authentication failures. Empty
strings, non-string values, or arrays containing non-strings are not treated
as "missing" because that would let ambiguous tokens fall back to legacy
single-namespace compatibility.

Self-minted DP tokens (the `connect_and_subscribe` path in
`src/grpc/dp_client.rs`) and native mesh-client tokens
(`src/modes/mesh/config_consumer/native_client.rs`) embed a single-string
`ns` claim from the process' own `FERRUM_NAMESPACE`, so data planes and mesh
nodes continue to work out of the box even when the CP runs with
`FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`. Operator-minted tokens that should
grant access to multiple namespaces should embed the claim as an array. xDS
ADS has no explicit namespace request field, so multi-tenant xDS accepts only
a single resolved namespace; an ambiguous multi-namespace resolution is
rejected.

**The `ns` claim is not, by itself, an authorization boundary.** It is
whatever the token's signer wrote. It becomes a boundary only once the signing
authority is bound to a namespace set the signer cannot change — which is what
the next section describes.

## Trust binding (GHSA-3f2j-wwqw-grmg)

### The problem

`FERRUM_CP_DP_GRPC_JWT_SECRET` is symmetric and fleet-wide. Every data plane,
mesh node, and xDS client that *presents* a token also holds the key that
*mints* one. Verifying that signature proves possession of a key every tenant
already has; it cannot establish that the signer was entitled to the namespace
it wrote into `ns`. A compromised tenant-A node could re-sign
`ns = "tenant-b"` and subscribe to tenant B's ConfigSync, native mesh, or xDS
configuration. Issuer pinning, short expiries, and requiring the `ns` claim do
not help — the attacker is a valid signing authority for all of them.

### The binding

Authorization is now derived from control-plane configuration, not from the
token. `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` points at a JSON document:

```json
{
  "version": 1,
  "keys": [
    {
      "kid": "tenant-a",
      "algorithm": "ES256",
      "public_key_path": "/etc/ferrum/trust/tenant-a.pub",
      "namespaces": ["tenant-a"]
    },
    {
      "kid": "tenant-b",
      "algorithm": "HS256",
      "secret_env": "FERRUM_TENANT_B_CP_DP_SECRET",
      "namespaces": ["tenant-b", "tenant-b-stage"]
    }
  ]
}
```

- `kid` is matched against the JWS header and selects **which key verifies the
  signature**. It authorizes nothing on its own.
- `namespaces` is the **ceiling**, fixed by CP configuration. A token's `ns`
  claim intersects it; the bearer can only narrow.
- Material comes from exactly one of `public_key_pem`, `public_key_path`,
  `secret`, `secret_env`, or `secret_path`. Asymmetric algorithms
  (`RS256`/`RS384`/`RS512`/`PS256`/`PS384`/`PS512`/`ES256`/`ES384`/`EdDSA`) are
  strongly preferred: the CP then holds only public material, and **no data
  plane is a signing authority at all**.
- The symmetric (`HS*`) path remains supported for migration, but only because
  each secret is per-credential and bound CP-side. It requires at least 32
  bytes. Do not reuse one `HS*` secret across tenants — that reintroduces the
  original defect.
- **In particular, never back a credential with `FERRUM_CP_DP_GRPC_JWT_SECRET`**
  — not inline, not via `"secret_env": "FERRUM_CP_DP_GRPC_JWT_SECRET"`, and not
  via a `secret_path` pointing at the same material. Every data plane in the
  fleet already holds that value, so any of them could name that credential's
  `kid` and reach its namespaces: the bundle would be structurally valid and
  semantically identical to the pre-advisory posture. **Startup refuses it.**
  `"secret_env": "FERRUM_CP_DP_GRPC_JWT_SECRET"` is rejected by variable name
  before the read, and an inline `secret` or a `secret_path` whose contents
  equal the effective fleet secret is rejected by resolved bytes. The
  diagnostic names only the bundle path, the `kid`, and the variable name —
  never key material. Generate one fresh secret per credential — or, better,
  use an asymmetric key so the data plane cannot sign at all.
- Startup refuses duplicate `kid`s (ambiguous key selection), unknown
  algorithms, algorithm/material mismatches, empty namespace lists, and
  unreadable material.

### mTLS / SPIFFE intersection

When the CP gRPC listener terminates mTLS and the peer's leaf certificate
carries a SPIFFE URI SAN of the Istio shape
`spiffe://<trust-domain>/ns/<namespace>/sa/<sa>`, that namespace is intersected
into the resolved set as well. It is computed once at handshake completion and
travels with the connection.

Certificate validation alone is **not** namespace authorization: a peer whose
certificate encodes no SPIFFE namespace contributes no evidence, and a
shared-CA certificate can never *widen* what a credential permits. Two tenants
issued leaves by one CA are separated by their credentials and (when present)
by their SPIFFE namespaces — never by the fact that both chains validate.

**Upgrade note — align the two namespace keyspaces.** This intersection is new
behavior: before it, a CP/DP mTLS peer certificate contributed nothing to
authorization. A SPIFFE namespace is the *workload's* namespace (in Kubernetes,
the pod's), while `SubscribeRequest.namespace` / `FERRUM_NAMESPACE` is the
*Ferrum configuration* namespace. Mesh data planes align by construction. A
plain `dp`-mode gateway does not have to: if it presents a SPIFFE client
certificate from, say, `ns/ferrum-system` while subscribing to configuration
namespace `ferrum`, the intersection is empty and the CP now answers
`PermissionDenied` ("not authorized for any namespace"). Fix it by aligning the
Ferrum namespace with the workload namespace, or by presenting a CP/DP gRPC
client certificate that carries no SPIFFE URI SAN (which contributes no
evidence, leaving the credential binding as the only ceiling). Do not "fix" it
by widening the credential's `namespaces` list — that grants the bearer the
extra namespaces for real.

### Fail-closed startup

A CP whose scope is `Set` or `All` refuses to start when the only configured
credential is `FERRUM_CP_DP_GRPC_JWT_SECRET`. There is no unsafe override and
no legacy shim. `Single` scope keeps working with the shared secret because it
is security-equivalent: there is no second tenant on that control plane for a
forged claim to reach, and the scope check refuses everything else anyway.

### Data-plane side

Two client-side options, both applying equally to DP ConfigSync, native
`MeshSubscribe`, and xDS ADS:

- **Externally issued token (preferred)** — `FERRUM_DP_CP_GRPC_TOKEN_FILE`
  points at a token minted by a trusted issuer. The node presents it and holds
  no signing key, so it cannot mint an authorization for any namespace,
  including its own. The file is re-read on every connection attempt, so a
  short-lived rotated token needs no restart.

  The issuer — not the node — decides what the token asserts, so it must mint
  to Ferrum's CP/DP token contract exactly. The CP requires:

  | Claim | Requirement |
  |---|---|
  | `kid` (JWS header) | the trust-bundle credential to verify under; required on a trust-bundle CP |
  | `iss` | exactly `FERRUM_CP_DP_GRPC_JWT_ISSUER` (default `ferrum-edge-cp-dp`) |
  | `sub` | required (present; the node id by convention) |
  | `iat` | required |
  | `exp` | required and unexpired |
  | `ns` | required by `Set`/`All` scope and by `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`; narrows the credential's allow-list |
  | `aud` | **must be absent** on DP `ConfigSync` and xDS ADS; **must be exactly `ferrum-mesh-subscribe:local`** on native `MeshSubscribe` |

  The `aud` rule is the easy one to get wrong, and it is enforced strictly:
  `ConfigSync`/ADS run `ReservedForbidden`, so a token carrying *any* audience
  is refused. A raw Kubernetes projected ServiceAccount token is therefore
  **not** usable as-is — projected tokens always carry an `aud`, and they carry
  the cluster's `iss` rather than Ferrum's. Mint a purpose-built token (a
  short-lived one, refreshed into the file) instead. One token file also cannot
  serve both a `ConfigSync` node and a native-mesh node, because their audience
  requirements are mutually exclusive.
- **Per-tenant self-mint (migration)** — the node keeps a *per-tenant* secret
  and sets `FERRUM_CP_DP_GRPC_JWT_KEY_ID` so its token names the credential the
  CP has bound to that tenant.

Cross-cluster mesh remote discovery still self-mints, because it needs a
per-target audience no external issuer can be asked for. It signs with either a
per-`RemoteCluster` credential (`discovery_credential_ref` resolved against
`FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` — the recommended posture, since a
credential for one cluster then cannot authenticate to another) or, failing
that, the shared `FERRUM_CP_DP_GRPC_JWT_SECRET`. `FERRUM_CP_DP_GRPC_JWT_KEY_ID`
rides on **both** paths, so a peer control plane running a trust bundle can
select the credential it bound to this cluster either way.

### Rotate after upgrading

Every data plane deployed before this change possesses fleet-wide signing
authority. Rotate `FERRUM_CP_DP_GRPC_JWT_SECRET` (or retire it) as part of the
rollout; upgrading the control plane alone does not revoke keys already
distributed.

## Migration steps

1. **Inventory**: enumerate the namespaces you want the CP to serve.
   `kubectl get ns -l ferrum-tenant=true -o name | sed 's|namespace/||'`
   is a typical pattern.

2. **Roll CPs first**: deploy the new binary with the existing
   `FERRUM_NAMESPACE` and `FERRUM_CP_NAMESPACES` unset. Behavior is
   byte-identical to the pre-T2-A path; verify via the existing
   single-namespace CP smoke tests.

3. **Build the trust bundle**: create one verification credential per tenant
   and write `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` (see
   [Trust binding](#trust-binding-ghsa-3f2j-wwqw-grmg)). Asymmetric keys are
   strongly preferred — the CP then stores only public material. This step is
   mandatory before step 4: a multi-namespace CP will not start without it.

4. **Point data planes at their credential**: give each DP/mesh node either
   `FERRUM_DP_CP_GRPC_TOKEN_FILE` (an externally issued short-lived token, so
   the node holds no signing key) or its own per-tenant secret plus
   `FERRUM_CP_DP_GRPC_JWT_KEY_ID`. A token with no `kid` is rejected by a
   trust-bundle CP, so roll data planes before flipping CP scope.

5. **Expand scope incrementally**: set `FERRUM_CP_NAMESPACES="ns-a,ns-b"`
   on one CP at a time. The CP startup log will print the resolved scope and
   the namespace-authorization source. DPs whose credentials are bound to a
   matching namespace can now subscribe; unbound credentials, missing `kid`s,
   and wrong claims fail before snapshot serialisation.

6. **Rotate the old secret**: every DP deployed before this change holds
   fleet-wide signing authority. Rotate or retire
   `FERRUM_CP_DP_GRPC_JWT_SECRET` once the trust bundle is serving.

7. **(Optional) Switch to `*`**: once you're comfortable with the explicit
   set, set `FERRUM_CP_NAMESPACES=*` so new namespaces are picked up
   automatically. Required for `helm install`-style provisioning where the
   CP doesn't know the tenant list ahead of time.

8. **(Optional) Tighten single-namespace CPs**: set
   `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` on single-namespace CPs after
   all DPs carry `ns` claims. Multi-namespace CPs already enforce this
   automatically.

9. **Decommission per-namespace CP fleet**: once the multi-namespace CP is
   serving all tenants, drain DPs from the old CPs and tear them down.

## Threat model and validation evidence

The attacker is a compromised tenant A DP, mesh node, or xDS client that
holds every credential actually installed in tenant A — including its JWT
signing material — and tries to receive tenant B data by changing local
environment, subscription request namespace, the self-asserted `ns` claim, xDS
node metadata, reconnect timing, resume resource versions, or failover target.
The attacker must not receive tenant B gateway resources, mesh resources, or
trust material on the wire.

GHSA-3f2j-wwqw-grmg found that a fleet-wide symmetric secret does not satisfy
this model: the attacker was a valid signing authority for the very claim used
to authorize it. The [trust binding](#trust-binding-ghsa-3f2j-wwqw-grmg) moves
the ceiling into control-plane configuration, so re-signing a claim for tenant
B now resolves to an empty namespace set and is refused at authentication —
before any tenant B configuration, mesh slice, trust material, or xDS resource
is serialized. A shared-CA client certificate does not change this: it is
authentication, not namespace authorization.

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
| `ConfigSync.Subscribe` | `SubscribeRequest.namespace` authorised by the resolved set (credential binding ∩ mTLS SPIFFE ∩ `ns`) | Missing/wrong/malformed claims fail before initial snapshot serialisation. Full snapshots, deltas, lag recovery, and K8s-triggered broadcasts are namespace-filtered. |
| `ConfigSync.GetFullConfig` | `FullConfigRequest.namespace` authorised by the resolved set | Same authorisation and filtering as `Subscribe`; wrong claims fail before response serialisation. |
| Native `MeshConfigSync.MeshSubscribe` | `MeshSubscribeRequest.namespace` authorised by the resolved set | Same authorisation as ConfigSync. Full, delta, and lag recovery slices are built from a namespace-filtered config. |
| xDS ADS | Single namespace from the resolved set | Multi-tenant streams require exactly one `ns` value because ADS has no namespace request field. Node metadata and resume resource versions cannot change tenant identity. |
| Kubernetes controller broadcast | Reconciled config namespaces | ConfigSync broadcasts fan out via `NamespaceBroadcasts`; each namespace is serialised independently. |
| Gateway trust bundles | Single-namespace CP only | Top-level gateway trust bundles and mesh trust bundles are withheld in `Set` and `All` scopes until a namespaced trust-bundle store is available. |
