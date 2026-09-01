# Control Plane / Data Plane Mode

Ferrum Edge supports a distributed CP/DP architecture where one Control Plane instance manages configuration and multiple Data Plane instances handle traffic. The CP pushes configuration to DPs via gRPC server-streaming, enabling centralized management with horizontally scaled traffic handling.

## Architecture

```
                          ┌──────────────────────┐
                          │    Control Plane      │
                          │                       │
                          │  ┌─────────────────┐  │
        ┌─────────────────┤  │   Database /     │  │
        │  Admin API      │  │   File Config    │  │
        │  (read/write)   │  └────────┬────────┘  │
        └─────────────────┤           │            │
                          │  ┌────────▼────────┐  │
                          │  │  gRPC Server     │  │
                          │  │  (ConfigSync)    │  │
                          │  └──┬─────────┬──┘  │
                          └─────┼─────────┼─────┘
                                │         │
                    gRPC Subscribe    gRPC Subscribe
                    (streaming)       (streaming)
                                │         │
                    ┌───────────▼──┐  ┌───▼───────────┐
                    │  Data Plane  │  │  Data Plane    │
                    │  Instance 1  │  │  Instance 2    │
                    │              │  │                │
                    │  ┌────────┐  │  │  ┌────────┐   │
                    │  │ Cached │  │  │  │ Cached │   │
                    │  │ Config │  │  │  │ Config │   │
                    │  └────┬───┘  │  │  └────┬───┘   │
                    │       │      │  │       │       │
                    │  Proxy Traffic│  │  Proxy Traffic│
                    │  (HTTP/S/H3) │  │  (HTTP/S/H3)  │
                    │              │  │               │
                    │  Admin API   │  │  Admin API    │
                    │  (read-only) │  │  (read-only)  │
                    └──────────────┘  └───────────────┘
```

## Communication Protocol

### gRPC with Protocol Buffers

CP and DP communicate via the `ConfigSync` gRPC service defined in `proto/ferrum.proto`:

- **`Subscribe(SubscribeRequest) -> stream ConfigUpdate`** — Server-streaming RPC. The DP subscribes and receives an initial full config snapshot followed by streaming updates whenever the CP detects config changes.
- **`GetFullConfig(FullConfigRequest) -> FullConfigResponse`** — Unary RPC for on-demand full config retrieval.

### Authentication

All gRPC calls are authenticated with JWT HS256 tokens:
- The CP validates the `authorization` header (Bearer token) on every RPC
- The DP sends its auth token in the gRPC metadata on every request
- Both CP and DP use the same shared secret for JWT signing/verification

### Transport Security (TLS/mTLS)

The gRPC channel between CP and DP carries **Data Plane authentication JWTs and
the full gateway configuration**. In plaintext both are exposed unencrypted and
unauthenticated against MITM, so Ferrum is **TLS-first and secure-by-default**:

- The CP **refuses to bind a plaintext gRPC listener on a non-loopback address**
  (e.g. `0.0.0.0:50051`) when no CP gRPC TLS is configured.
- The DP **refuses a non-loopback `http://` CP URL**.

Both refusals are lifted only by configuring TLS, by using a loopback address
(`127.0.0.1`/`::1`/`localhost`, intended for local development), or by the
explicit escape hatch `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true`. Even when
plaintext is explicitly permitted, a high-severity warning is logged on both the
CP and the DP every time the channel runs in plaintext.

The gRPC channel supports three security modes:

| Mode | CP Configuration | DP Configuration | Use Case |
|------|-----------------|-----------------|----------|
| **Plaintext** | No TLS env vars (loopback bind, or `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true`) | `http://` loopback URL, or `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` | Local development / trusted networks only |
| **One-way TLS** | `FERRUM_CP_GRPC_TLS_CERT_PATH` + `_KEY_PATH` | `https://` URL + `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | DP verifies CP identity (recommended minimum) |
| **Mutual TLS (mTLS)** | Above + `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | Above + `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` + `_KEY_PATH` | Both sides verify identity (recommended for production) |

**One-way TLS**: The CP presents a server certificate (`FERRUM_CP_GRPC_TLS_CERT_PATH` + `_KEY_PATH`); the DP verifies it against a trusted CA (`FERRUM_DP_GRPC_TLS_CA_CERT_PATH`, or the system roots for a publicly-trusted CP certificate). This encrypts the channel and prevents MITM attacks on the JWT token and config data. With one-way TLS the **bearer JWT is the only factor authenticating a DP to the CP** — the CP logs a high-severity warning when TLS is configured without `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH`.

**Mutual TLS (recommended for production)**: In addition to server verification, the CP requires a client certificate from the DP (`FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` + `_KEY_PATH`), verified against a trusted CA (`FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH`). This adds certificate-based DP identity on top of JWT authentication, so a leaked JWT secret alone cannot impersonate a DP.

The release-blocking `mesh-e2e-sidecar` native `MeshSubscribe` assertion proves this production posture end to end: the DP dials `https://ferrum-cp.<namespace>.svc.cluster.local:50051` so hostname/SAN verification is real Kubernetes Service DNS, the CP requires a client certificate, JWT remains required on the same stream, dedicated probe Deployments fail closed for omit-client / foreign-client / untrusted-server-CA / wrong-SAN / invalid-JWT, and a projected Secret generation swap proves the watched CP/DP gRPC TLS sources reconnect without a pod restart. That gate does not permit plaintext gRPC and does not skip server certificate verification.

> **`FERRUM_DP_GRPC_TLS_NO_VERIFY` is not supported** and is rejected at startup when `true`: disabling server certificate verification is unsafe. To test against a CP with a self-signed certificate, pin its CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH`.

### Pre-authentication connection admission

The CP gRPC listener bounds how many connections may exist before a peer has
authenticated. A permit from a single, process-wide limiter is taken in the
accept loop **before** the per-socket TLS/mTLS handshake task is created, and it
is released only when the served HTTP/2 session ends. Over-limit sockets are
closed immediately, with no task, TLS state machine, or cloned server
configuration allocated for them.

- `FERRUM_CP_GRPC_MAX_CONNECTIONS` (default `1024`) is the global bound.
- `FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP` (default `64`) bounds one source IP so
  a single host cannot consume the global budget. Raise it when many DPs reach
  the CP through one NAT/egress address; `0` disables per-IP limiting. A value
  greater than the global cap could never fire and is refused at startup.

The limiter is shared by the plaintext listener, the TLS/mTLS listener, and
every certificate-reload generation, so rotating the CP gRPC certificate neither
resets nor duplicates the pool. `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`
still bounds how long an individual handshake may take, but it is defense in
depth — it recycles permits, it is not the concurrency bound.

Both caps are observable on `/metrics` as `ferrum_cp_grpc_active_connections`,
`ferrum_cp_grpc_max_connections`, `ferrum_cp_grpc_max_connections_per_ip`, and
`ferrum_cp_grpc_rejected_connections_total{reason}`. No source-IP labels are
emitted.

### Authenticated stream lifetime

Every bearer-authenticated long-lived configuration stream is bound to the
credential and verified `exp` accepted at admission. ConfigSync Subscribe,
local and cross-cluster native MeshSubscribe, and xDS SotW/delta ADS terminate
at `exp` plus the verifier's 60-second leeway, or at the independent
`FERRUM_CP_GRPC_MAX_STREAM_LIFETIME_SECONDS` ceiling (default 3600, allowed
60..=86400), whichever comes first. Heartbeats and configuration traffic do not
renew either deadline. Expiry and maximum-lifetime closure use
`UNAUTHENTICATED`; removal of the exact accepted verification credential uses
`PERMISSION_DENIED`. This is deliberately distinct from initial admission:
missing, malformed, expired, unknown-key, wrong-signature, and wrong-algorithm
credentials all remain the same non-disclosing `UNAUTHENTICATED` class. If key
removal coincides with a deadline, removal takes precedence for an already
admitted stream.

`FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` is watched at
`FERRUM_SECRET_REFRESH_INTERVAL_SECONDS`. A valid replacement is installed
atomically. Adding an overlapping credential does not disrupt streams admitted
by a retained credential with the same namespace policy. Removing that
credential, or changing its trusted namespace ceiling, closes its existing
streams. Invalid reloads retain the last accepted verifier.

### Aggregate configuration-stream admission

Listener connection caps (`FERRUM_CP_GRPC_MAX_CONNECTIONS` /
`FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP`) and
`FERRUM_CP_GRPC_MAX_STREAM_LIFETIME_SECONDS` do not bound how many long-lived
ConfigSync, MeshSubscribe, or ADS streams an authenticated client may hold.
Those RPCs share the layered xDS admission budgets
(`FERRUM_XDS_MAX_TOTAL_STREAMS`, per-namespace, per-principal, per-node, and
distinct-node cardinality; issue #4432). The permit is acquired **before**
broadcast subscription, config filtering/serialization, registry insertion, or
response-channel allocation, and is released by an RAII guard on every
termination path. Capacity refusals are gRPC `RESOURCE_EXHAUSTED`.

The same budgets apply on a control plane even when `FERRUM_XDS_ENABLED=false`,
because native ConfigSync and MeshSubscribe still occupy the slots. Under
`FERRUM_MESH_PRODUCTION_MODE=true`, a `0` (unbounded) value is refused at
`ferrum-edge validate` and startup unless
`FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true`. See
[configuration.md](configuration.md) and
[mesh.md → xDS ADS admission budgets](mesh.md#xds-ads-admission-budgets).

Startup and that reload worker share one coherent-generation loader: the bundle
document and every `secret_path` / `public_key_path` it names are read from a
single filesystem generation, so a rotation can never pair one generation's
namespace ceiling with another generation's key material. A Kubernetes projected
mount is pinned by `..data` descriptor before the document is read; any path
outside a pinned generation must carry a `material_sha256`. A candidate that
cannot prove coherence is rejected with a closed reason label and retains the
entire prior verifier — it is never partially applied. Each referenced file and
the aggregate path-backed material retained for one candidate are limited to 1
MiB. See
[cp_namespace_tenancy.md](cp_namespace_tenancy.md#rotation-is-atomic-per-source-generation).

DPs and mesh/xDS clients use their existing bounded reconnect backoff and reread
`FERRUM_DP_CP_GRPC_TOKEN_FILE` (or mint a new short-lived token) on each attempt.
The fixed-cardinality
`ferrum_grpc_config_stream_terminations_total{surface,reason}` metric and
structured `grpc_config_stream_*` audit events distinguish `expired`,
`verification_key_removed`, `server_max_lifetime`, `trust_stale`, and
`transport_closed` without token, claim, key, node, or namespace labels.

A rejected trust-bundle reload retains the entire previous verifier, but only
for `FERRUM_CP_DP_TRUST_MAX_STALE_SECONDS` (default 900). The first refusal
marks trust reload degraded on authenticated `/health` and in the
`ferrum_cp_dp_trust_*` families; a stalled worker is immediately degraded and
`ferrum_cp_dp_trust_reload_worker_stalled` without failing readiness inside the
bound. At the bound the CP fails readiness, refuses new ConfigSync,
MeshSubscribe, and xDS streams, and ends established ones with `trust_stale`.
Admin-JWT-authenticated `/health`/`/status` also carry `active_generation`, a
keyed HMAC-SHA-256 identifier for replica convergence. Metrics bearer tokens
and metrics-allowlisted source addresses receive the remaining detailed trust
diagnostics with this field set to `null`. See
[cp_namespace_tenancy.md](cp_namespace_tenancy.md#retention-of-an-unrevalidatable-verifier-is-bounded-issue-3813).

### Config Sync Flow

1. DP connects to CP's gRPC endpoint with JWT authentication
2. CP sends an immediate `ConfigUpdate` with the full current config (type=FULL_SNAPSHOT)
3. CP polls the database incrementally at `FERRUM_DB_POLL_INTERVAL` seconds using indexed `updated_at` queries
4. When changes are detected, CP broadcasts a `ConfigUpdate` with type=DELTA containing only the added/modified/removed resources
5. If gateway-to-mesh trust bundles are configured, the CP includes them in the `trust_bundles_json` side channel on both stream updates and unary full snapshots so DPs can refresh mesh peer trust without placing trust material in the DP-facing `GatewayConfig` JSON
6. DPs apply the delta surgically — only affected caches (router, plugin, consumer, load balancer) are updated
7. If the incremental poll fails, CP falls back to a full database reload and broadcasts a FULL_SNAPSHOT

### Update Types

The `ConfigUpdate` proto message carries an `UpdateType` discriminator:

| Type | Value | When | Content |
|------|-------|------|---------|
| `FULL_SNAPSHOT` | 0 | Initial subscription, fallback | Entire `GatewayConfig` as JSON |
| `DELTA` | 1 | Incremental database changes | `IncrementalResult` with only changed resources |

`ConfigUpdate.trust_bundles_json` and `FullConfigResponse.trust_bundles_json` carry the serializable mesh `TrustBundleSet` used by gateway DPs for gateway-to-mesh SPIFFE TLS, or JSON `null` when the CP is explicitly clearing previously delivered trust material. An invalid Replace is never converted to `null`: initial Subscribe/GetFullConfig fails with a bounded internal error, and broadcast/recovery emits no partial generation, so subscribers retain their complete last-known-good config and trust. The CP strips `GatewayConfig.trust_bundles` from DP-facing full snapshot JSON and uses only this side channel, preserving compatibility with older DPs whose config deserializer rejects unknown fields. An empty or missing side channel is treated as "unchanged" for mixed-version CP/DP rollouts. New DPs hot-swap this trust material into the gateway SVID slot when an SVID is loaded, restore startup file trust when the CP clears it, and also retain CP-delivered bundles separately when no local SVID is configured. Older DPs ignore the field.

#### Trust-bundle config-store capabilities

This matrix covers persistence and change detection for the local, CP-authoritative top-level `GatewayConfig.trust_bundles` value. It does not describe the mesh federation runtime overlay discussed below.

| Configuration source | Supplies `GatewayConfig.trust_bundles`? | Detects a runtime change? | Namespace-partitioned? |
|---|---|---|---|
| File (YAML/JSON) | Yes, through serde deserialization | Full file reload only (`SIGHUP` on Unix); no narrow trust-bundle poll | No |
| PostgreSQL | Yes, from the `gateway_trust_bundles` resource | Yes, through `config_changes` | Yes, one record per namespace |
| MySQL | Yes, from the `gateway_trust_bundles` resource | Yes, through `config_changes` | Yes, one record per namespace |
| SQLite | Yes, from the `gateway_trust_bundles` resource | Yes, through `config_changes` | Yes, one record per namespace |
| MongoDB | Yes, from the `gateway_trust_bundles` collection | Yes, through `config_changes` | Yes, one record per namespace |

#### The `gateway_trust_bundles` resource (issue #3727)

Every database backend persists a first-class, **namespace-keyed** gateway
trust-bundle resource. It is a thin envelope around the same serializable
`TrustBundleSet` the mesh model and the `trust_bundles_json` side channel
already use — there is no second representation that can drift.

- **Singleton per namespace.** SQL makes `namespace` the primary key and MongoDB
  keys documents by `_id = <namespace>`, so a namespace's projected trust state
  is never ambiguous and a concurrent create from a second admin replica loses on
  a duplicate key rather than silently replacing another writer's roots.
- **Stored fields.** Resource `id`, `namespace`, `trust_domain` (must equal
  `bundle.local.trust_domain`), the bounded `bundle`, a backend-assigned
  `revision` (see *Incarnation-safe revisions* below),
  `updated_by` (the verified admin JWT subject — never a client-supplied value,
  at most 255 characters, never truncated),
  and `created_at` / `updated_at`.
- **Bounded, validated material.** Admission caps authority counts (16 X.509 and
  16 JWT per bundle, 256 federated bundles), per-authority size (16 KiB), and the
  encoded bundle as a whole (512 KiB) — see
  [How the trust bounds compose](#how-the-trust-bounds-compose). Count and cheap encoded/raw size bounds
  fail closed before `TrustDomain::new` or any deep parser (mesh validation,
  X.509 DER, JWT public keys, runtime conversion). Every `x509_authorities`
  entry must be valid base64 *and* parse as an X.509 certificate that consumes
  the complete entry (a certificate with appended bytes is refused); every JWT
  authority needs a unique non-empty `key_id` and a public key the JWT-SVID
  authority parser can actually use — the same `is_usable_public_key_material`
  gate the JWKS path uses, in either accepted encoding (SPKI `PUBLIC KEY` PEM or
  the SPIFFE-federation JWK form), so a PRIVATE KEY paste, a truncated body, or
  an unsupported key type is refused rather than stored and published. Duplicate
  trust domains are rejected. The same validation runs on write, on every full
  load, and again before publication.

##### How the trust bounds compose {#how-the-trust-bounds-compose}

The three families are checked in a fixed order and are deliberately not
redundant:

| Family | Values | What it is for |
| --- | --- | --- |
| Counts | 16 X.509 + 16 JWT authorities per bundle; **256** federated bundles | Make the documented inventory *representable*, and stop an unbounded collection walk before it starts |
| Per-entry size | 16 KiB per X.509 DER, 16 KiB per JWT PEM, 256 B per `key_id` | Stop one authority from being a blob |
| Total encoded | **512 KiB** for the whole `bundle` document | The **binding** resource bound — this is what a full inventory is measured against |

The federated-bundle count is *derived from* `MAX_MESH_REMOTE_CLUSTERS`, not
chosen independently. Mesh multi-cluster already accepts up to 256 remote
clusters and a federated deployment carries one federated trust domain per
remote cluster, so a smaller trust cap would make an already-admissible
cluster inventory unrepresentable — a 33rd trust domain would have rejected an
entire mesh generation or suppressed a CP broadcast. The two constants are now
tied together in code and cannot drift.

The count cap is **not** the resource cap: multiplied out, the counts describe
roughly 64 MiB of material, which is why the total ceiling exists and is
checked as well. The cheap raw-material sum runs first and short-circuits
before any deep parser, so the maximum material a hostile document can push
through base64/DER/PEM decoding is 512 KiB, not the product of the counts.

512 KiB is sized from the documented worst realistic federation: 256 remote
trust domains plus the local one, each carrying a rotation-overlap **pair** of
ordinary ECDSA P-256 roots (~600 base64 bytes each, so ≈330 KiB with JSON
framing), or one RSA-4096 root each. It deliberately does **not** admit every
trust domain simultaneously holding the per-bundle authority maximum: that
document is replicated through `config_changes` and into every subscriber
snapshot on every rotation, and the CP/DP `ConfigUpdate` carries it alongside
the full configuration inside one gRPC message. A document over the ceiling is
refused with a bounded size diagnostic and the previous generation stays live.

- **Fail-closed stored-row decoding.** Security-relevant stored fields are
  decoded strictly: a missing/non-integer/non-positive `revision`, an
  unreadable `namespace`/`id`/`trust_domain`/`bundle`, or an unparseable
  timestamp refuses the row (bounded `undecodable` failure reason) instead of
  defaulting to `1` or to `Utc::now()`. A corrupt row must not be able to win a
  compare-and-set or look like a fresh rotation on every load. Rejections never
  echo the stored value.
- **Change detection.** Writes record a `gateway_trust_bundle` row in
  `config_changes`, so ordinary incremental polling sees rotations and
  revocations. A trust change escalates that poll to a full reload
  (`IncrementalFullReloadReason::GatewayTrustBundleChanges`) — the same mechanism
  consumer mutations already use — so the resources and the trust side channel
  are always published from one authoritative read and a subscriber can never see
  new configuration paired with the previous generation's roots. Full loads read
  the trust record on the *same* snapshot transaction/session as the resources.
- **Validate before swap.** A stored bundle that no longer passes admission
  (oversized, malformed, identity mismatch, undecodable row) rejects the whole
  load. The control plane keeps its previous valid generation serving and
  surfaces a redacted diagnostic — messages name field, index, and size only.
- **Admin surface.** `GET/POST /gateway-trust-bundles`,
  `GET/PUT/DELETE /gateway-trust-bundles/{id}`, and `GET /gateway-trust/status`.
  Reads require `operator`, writes require `admin`. `PUT` takes the `revision`
  you read as an optimistic-concurrency expectation and returns `409` with
  `expected_revision` / `current_revision` on a lost race. `DELETE` is an
  explicit revocation and is distinguishable on the wire from "no change". A
  `POST` that omits `id` derives it from the authenticated
  `X-Ferrum-Namespace` value; neither the stored namespace nor the stored id
  can be influenced by the request body.
- **Atomic compare-and-set.** The revision guard is a predicate of the `UPDATE`
  statement itself (`... AND revision = ?`) on every SQL backend, and the
  revision is re-asserted in the MongoDB replace filter. A read-then-write would
  be safe only under a row lock or serializable isolation; under ordinary READ
  COMMITTED two admin replicas could both read revision N and both write N+1,
  destroying the first rotation. Restore/import states no client expectation but
  still compares against the revision read inside its own write transaction. The
  bundle write and its `config_changes` entry remain one transaction (SQL, and
  MongoDB with `FERRUM_MONGO_REPLICA_SET`).
- **Incarnation-safe revisions.** The revision a write stores is **not**
  `current + 1` and never restarts at 1. It is the durable, backend-assigned
  change sequence — SQL `config_changes.sequence`, MongoDB's global
  `config_change_counters` value — recorded by the same write that produces the
  poll signal. Every trust mutation advances it, *including the delete*, so a
  namespace singleton that is deleted and recreated always comes back strictly
  newer than the incarnation it replaced. Without that property the
  compare-and-set has an ABA hole: a client reads revision 1, another actor
  deletes and recreates the record (revision 1 again), and the first client's
  later `PUT` with expected revision 1 matches and overwrites trust material it
  never read. The namespace admission lease serializes individual writes but
  cannot cover the gap between a client's `GET` and its later `PUT`, so only a
  never-reused revision closes it. Every physical recreation goes through the
  same path — restore's create branch, and late-write delete compensation — so
  none of them can replay a stale revision out of a payload or snapshot.
  Conversions to signed 64-bit are checked and never clamped, and a source that
  fails to advance past the revision being replaced is refused rather than
  defaulted.
- **Authoritative write responses.** A successful `POST`/`PUT` body and the
  matching audit event both come from an authoritative post-write re-read of the
  committed record, taken while the namespace admission guard still applies, so
  they carry the revision the store assigned rather than the `0` a create body
  carries or the expectation a `PUT` body carries. If that re-read fails, the
  request is reported as failed — no fabricated revision, no cached fallback.
- **Standalone MongoDB contract.** Standalone MongoDB has no multi-document
  transaction, so for this resource the poll signal and the document mutation
  are two separate commits. The signal is written **first**, for two reasons —
  neither of which is a visibility guarantee. First, failure containment: if the
  change record fails, nothing was mutated at all, and if the document write
  then fails, a redundant change row costs one extra full reload and nothing
  else. Second, the revision source: the change sequence that write returns *is*
  the stored revision, so the monotonic, incarnation-safe revision and the poll
  signal are the same durable write.

  Ordering alone does **not** make a committed mutation visible to a running
  poller, and Ferrum does not claim it does. A poller can read sequence `N`,
  escalate to a full reload that still reads the *old* document, advance its
  cursor past `N`, and only then does the document commit — with no later signal
  to announce it. Reversing the order trades that for a crash between the
  document and the signal, and adding a second trailing signal still loses to a
  crash after the document commit. Every ordering has a boundary at which a
  committed trust mutation carries no unconsumed signal.

  Visibility on this topology is therefore established on the **read** side. A
  backend reports whether its trust write and change-log signal commit
  atomically (`true` for every SQL backend and for replica-set MongoDB, `false`
  for standalone mongod). When it reports `false`, every database-mode and CP
  poll tick performs an authoritative drift check: a projected, identity-only
  read of the namespace's stored trust document — `id`, `trust_domain`,
  `revision`, never the material — compared against the trust state the running
  configuration was actually built from. Any difference in either direction —
  a create or rotation that is stored but not published, or a **revocation**
  whose document is gone while the roots are still published — escalates that
  namespace to an authoritative full reload, which is the single path that
  republishes trust and its `trust_bundles_json` side channel from one read.
  The check runs *before* the tick's reload decision, so that full reload — and
  the publication that withdraws revoked roots — happens in the **same** poll
  tick that detected the drift, not the next one; a drifted tick never falls
  into incremental polling first. Because the check reads the document rather
  than the change log, it depends on neither write ordering nor on the writing
  process surviving.

  Cost and blast radius are bounded by construction: zero additional queries on
  transactional backends, at most one projected single-document read per polled
  namespace per tick on standalone mongod, every read predicated on its own
  namespace, and a failed read reported and skipped rather than converted into a
  reload or a withdrawal, so the last known good publication stands. Standalone
  MongoDB therefore guarantees "never invisible", not "never redundant"; a
  deployment that needs full multi-document atomicity for the *write* must still
  set `FERRUM_MONGO_REPLICA_SET`.
- **Backup/restore.** Database-backed exports always carry a
  `gateway_trust_bundles` section (possibly empty). Restore treats an **absent**
  section as "this backup says nothing about trust" and leaves existing roots
  alone; a **present** section is authoritative and reconciles exactly against
  the AUTHENTICATED target namespace, including the empty case, which revokes
  that namespace's record. The resource is a singleton, so a section carrying
  more than one record for the target namespace is refused with `400` *before*
  the destructive clear rather than silently reduced to whichever record came
  first. Server-owned fields survive the payload: `id` and `created_at` come
  from the stored record, `revision` is assigned by the store, and `updated_by`
  is the restoring admin's verified JWT subject (at most 255 characters; an overlong
  subject is rejected rather than truncated). The namespace clear that
  precedes an import deliberately does not touch trust, so restoring an older
  config backup can never silently revoke a namespace's roots.

##### Publication semantics

The `trust_bundles_json` side channel carries three distinct states, and the CP
now states exactly one of them per message:

| State | Wire value | Meaning |
|---|---|---|
| Unchanged | empty string | Say nothing; the subscriber keeps what it applied. |
| Clear | `null` | Withdraw previously delivered trust material. |
| Replace | serialized `TrustBundleSet` | Install this material. |

Full snapshots always state the complete current state (`Replace` when the
namespace has a record, `Clear` when it does not), so a reconnecting data plane
reconstructs trust from the snapshot alone. Resource deltas always state
`Unchanged`: before issue #3727 the delta path passed `None`, which encoded as
`null`, so **every** ordinary configuration change silently revoked the
subscriber's trust.

Every Replace crosses the same `config::gateway_trust` validator at admin/store
admission, CP encoding, DP decoding, and mesh/federation staging. It enforces
authority/federation counts, per-entry bounds, unique non-empty JWT key IDs,
duplicate trust-domain refusal, complete X.509 DER consumption, usable JWT
public keys, and the exact 512 KiB serialized document ceiling. The DP also
rejects a raw side-channel value over that ceiling before deserialization.
Diagnostics carry only fixed failure classes or bounded field/index metadata,
never certificate or key material. Invalid FULL_SNAPSHOT input terminates the
subscription; invalid DELTA input terminates and resyncs under the ordinary
ConfigSync rejection lifecycle without changing config, trust equivalence,
freshness, or received-config state.

##### Precedence and ambiguity

The database resource is the authority. If a namespace somehow presents *both* a
database record and a file-sourced `GatewayConfig.trust_bundles`, neither wins
and the publication is **refused**: the side channel says nothing (`Unchanged`),
so every subscriber keeps the last trust generation it accepted, while the CP
logs the redacted `AMBIGUOUS_TRUST_AUTHORITY_MESSAGE` and increments
`ferrum_gateway_trust_bundle_ambiguous_authority_total`. Preferring one silently
would let two replicas diverge if only one could see the file value — exactly the
failure this resource exists to remove — and converting the ambiguity into a
`Clear` would revoke a working fleet's roots over a leftover file value. The
behaviour is deterministic on every replica.

The two authorities are classified from the configuration as it exists *before*
namespace partitioning clears the unpartitioned slot
(`resolve_namespace_trust_projection`). Classifying afterwards would make a
record-plus-file deployment look database-only on a claim-requiring scope, and
the ambiguity would be silently resolved.

##### One coherent config/trust generation

A bundle update and the configuration that depends on it are two writes to two
lock-free slots, so publishing them independently leaves an interval where a
request pairs one generation's configuration with another generation's trust
roots. Published configuration-first, that interval is **fail-open**: a
revocation the accepted generation committed is not yet in the live verifier,
so a withdrawn peer still authenticates. Publishing trust first only inverts the
mismatch.

Ferrum removes the interval instead of choosing a side. The request-facing
gateway trust snapshot lives **inside `RequestEpoch`** (`GatewayTrustEpoch`), so
one `ArcSwap` load at admission yields configuration, routing/listener
admission, and gateway trust from the same generation, and the publication runs
as one fenced sequence
(`ProxyState::publish_request_epoch_with_gateway_trust`):

1. **Stage.** The candidate's exact effective trust (including live federation
   overlays) is validated and converted *before*
   anything is published. A candidate that cannot convert **rejects the whole
   configuration apply** — the complete previous generation (configuration and
   trust) stays live. `Unchanged` is resolved against the live override while
   the publication mutex is held, so an ordinary identical reload costs
   nothing without racing another writer.
2. **Fence.** A generation that changes the live verifier is published with its
   gateway-to-mesh admission CLOSED. For the whole install,
   `ProxyState::admits_gateway_mesh_identity` — the predicate every
   gateway-to-mesh admission gate reads (HBONE and sidecar-mTLS HTTP dispatch,
   native-gRPC mesh transport resolution, raw-TCP mesh egress, mesh UDP egress,
   HBONE capability probing) — is false, so those paths **fail closed** rather
   than authenticate against the generation this one replaced.
3. **Commit.** The material is installed, the **backend security generation** is
   advanced (below), and the admission is republished live, advancing the
   gateway trust generation. All three happen inside the fence, in that order,
   so there is no point at which admission is open while any of them is still
   pending. Status and `/metrics` are recorded last, after a verifier a request
   path can actually select is live.

Trust material is only ever advanced after the fence, so a request admitted
under an older generation can at worst use trust the operator has already
committed — the same forward-only contract gateway SVID rotation has always had
— and never trust the accepted generation withdrew.

##### Committed trust retires pooled entries for withdrawn roots

Installing the accepted verifier is only half of a rotation or revocation.
Every pooled backend and mesh entry was authenticated under the **outgoing**
roots, so a `Replace` or `Clear` that WITHDRAWS a root the live verifier
honoured also advances the shared backend security (SVID) generation and
removes those entries from the pool maps (and clears their generation-keyed
backend TLS config caches), in the same fenced publication:

- fresh dials and TLS-config construction key on the new generation
  (`|svidg=<n>` pool keys and backend TLS config caches partition on it), so an
  entry from the withdrawn generation cannot be selected;
- the outgoing generation's cached backend TLS configs are invalidated, its
  connection-pool / HTTP-2 / gRPC / H3 entries are drained, and active health
  checks are restarted;
- the HBONE and mesh-mTLS pool maps are cleared **whole**. Their keys embed the leaf
  SVID *fingerprint*, not the generation, and a trust-only change leaves the leaf
  alone — so every one of their keys is byte-identical across the commit and
  there is no key partition separating a pooled checkout verified against the
  withdrawn roots from one verified against the accepted roots. The cost is a
  one-time reconnect wave on the **next** mesh pool checkout for a committed
  withdrawal; the alternative would rest a revocation bound on lazily populated,
  capped per-pool fingerprint bookkeeping, which a withdrawal bound may not depend
  on.

None of this consults `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`. That window is
a grace period for an ordinary identity rotation and its default of `0` means
"no forced drain at all", so leaving a withdrawn root to it would make the
withdrawal unbounded. Documentation cannot make that safe, so pool retirement is
unconditional and runs on the publishing thread.

Both the advance and the pool retirement are **synchronous**, while the epoch is
still fenced and before gateway-to-mesh admission is republished live.
Publishing only on the rotation watch channel and leaving the work to the
asynchronous rotation consumer would let the fence lift before that task was
scheduled, and every request admitted in the gap would key its pool and
TLS-config lookups on the generation the publication had just withdrawn — or
check out a pooled mesh entry the withdrawn roots had admitted. The watch send
still happens (it drives the consumer's own cache invalidation and health-check
restart), but no request-visible decision waits on it, and nothing about the
trust event can be missed or coalesced.

An explicit removal or `Clear` of an installed override is therefore **not
usable for new validation, not discoverable for a new pool checkout, and not
usable by an already-issued gateway-to-mesh transport** the moment the commit
returns. The ownership registry synchronously marks and signals issued
`H2ConnectTunnel` and `MeshMtlsSender` handles plus active
WebSocket/datagram/raw-CONNECT bridges. A retired HBONE tunnel's next poll,
read, or write fails with the fixed material-free `gateway trust authority
withdrawn` error. A retired pooled mesh-mTLS sender consults the same gate in
`ready` / `send_request` and refuses the next stream synchronously, without
waiting for driver scheduling or socket-close propagation. In-flight streams
still terminate through driver/socket teardown.

###### The admission-refusal window, and what bounds it

Because the retirement is synchronous under the fence, gateway-to-mesh
admission is **closed for the duration of that work**. This is a real,
operator-visible window and is documented rather than hidden.

What runs inside it, in order, on the publishing thread — no `.await`, no I/O:

1. the request-facing gateway trust epoch is already fenced;
2. one `ArcSwap` store of the accepted trust material into every verifier slot it
   governs;
3. one ownership-registry generation advance, followed by a `retain` pass that
   marks and notifies every registered HBONE or mesh-mTLS physical transport in
   the outgoing generation;
4. one atomic advance of the backend security generation;
5. for each generation in the retired half-open span (normally exactly one, and
   never more than `MAX_COALESCED_ROTATION_DRAIN_GENERATIONS` = 8): one backend
   TLS config-cache drain plus one `retain` pass over each of the
   connection-pool, HTTP/2, gRPC and H3 `DashMap`s;
6. one `clear()` of each of the HBONE and mesh-mTLS pool maps (entries,
   creation locks, retired-fingerprint registries), followed by publication of
   the accepted trust as live.

Material is stored before the ownership generation advances so a dial that passed
the live check immediately before fencing cannot take a *new* registry ticket and
still load the *old* verifier. A ticket stamped before step 3 is refused at
registration; a ticket stamped after step 3 can only load the material already
stored in step 2.

So the window scales with the number of **registered live gateway-to-mesh
physical transports**, with **pooled occupancy** across the six pools, and,
linearly, with the **number of coalesced generations** in step 5. It does not
scale with trust-material size, with the number of federated trust domains,
with connected data planes, or with request rate. Signalling a registered
transport and dropping a pool entry wake or cancel their connection tasks; the
window does not wait for a socket close, a TLS shutdown, or a peer round trip.

What a client sees while the window is open is the ordinary fail-closed refusal
for its protocol, not a hang or a partial state: native gRPC gets a
Trailers-Only `UNAVAILABLE` with the fixed metadata-free
`GATEWAY_MESH_IDENTITY_NOT_LIVE` message, HTTP-family mesh dispatch and
mesh TCP/UDP egress refuse before any dial, and nothing is health-scored or
circuit-breaker-charged for the refusal. Requests that never touch a mesh-tagged
target are unaffected — the gate is consulted only on the gateway-to-mesh
admission path.

The window is entered only by a decision that actually **withdraws** an
installed authority (see the scoping rules below), so a steady-state gateway,
an additive overlap root, a reconnect-redelivered identical `Replace`, and a
redundant `Clear` never pay it. Observability for the event itself is the
existing label-free `ferrum_gateway_trust_bundle_*` family plus the
`Cleared pooled backend and mesh entries...` publication log, which names the
retired generation span; there is deliberately no per-namespace or per-pool
duration label, because namespace names are tenant-identifying and a
per-generation label is unbounded.

Retirement is scoped to an actual withdrawal, because it is expensive and
because a decision that removes no root leaves nothing to bound:

- **Adding** a root is overlap — a cross-signed root published alongside the one
  it will replace, or a newly federated trust domain. Every root that could have
  admitted a live transport is still a root, so the material is installed and
  nothing is retired from the pools.
- An unchanged `Replace` **re-delivered by a reconnect** removes no root. A DP
  re-subscribing must not clear every pooled mesh entry on the node.
- A `Clear` with **no override installed** removes no root. Every full snapshot
  of a gateway that uses no CP trust bundles carries exactly this decision.

`Unchanged` advances nothing and installs nothing, so an ordinary reload on a
gateway that has a trust record never churns a pool. The database serving-mode
startup install (`ProxyState::publish_gateway_trust_generation`) runs before any
listener binds. Mesh slice and federation changes stage their effective
Replace/Clear decision before config preparation and carry it through the same
request-epoch publication; there is no post-accept trust writer or two-generation
window. A failed trust stage rejects the complete mesh generation before
last-applied state, resolver, DNS, TLS, enforcement, or status side effects.

The gateway SVID slot (`ProxyState.gateway_svid_bundle`) remains the *material*
the mesh pools and the inbound resolver originate from. It is not the admission
predicate; gating dispatch on "is a bundle loaded" is exactly the split read
this design removes. Every writer of that slot
(`update_gateway_trust_bundles`, `clear_gateway_trust_bundles`,
`install_gateway_runtime_svid_bundle`) holds the same complete cold-path
publication mutex. Lock order is publication → request-epoch fence → SVID
material install → request-epoch commit, with each inner lock released before
the next is acquired and no lock held across `.await`. Replace/Clear fences;
source rotation atomically installs its new leaf/key while preserving the
latest authoritative override, then commits admission before releasing the
outer boundary. A source rotation and a config/trust publication are therefore
totally ordered, and neither can lift the other's fence.

##### Database serving mode applies its own record

A `database`-mode gateway is both the store's reader and a proxy, so it has no
side channel to deliver trust to itself. At the same publication boundary that
makes a configuration generation live — the fenced request-epoch sequence above,
plus one `ProxyState::publish_gateway_trust_generation` at startup for an
already-persisted record — it installs its configured namespace's singleton
record into the live gateway SVID verifier. An accepted rotation replaces
the live trust, and an explicit record deletion **withdraws** the database
override so the ordinary source-loaded gateway SVID trust becomes live again —
the same withdrawal the data plane performs on a `Clear`.

Precedence is the shared `resolve_trust_authority` resolver, not a second
model: an ambiguous namespace (record plus file-sourced `trust_bundles`) keeps
the last-known-good verifier state, and a file-only namespace is left to the
gateway SVID source loader. Only `database` mode does this; the CP→DP side
channel and the mesh apply loop remain the single writers of that slot in their
own modes, and a data plane's configuration never carries the resource at all.

The runtime update happens **before** the generation is recorded as published,
so status and `/metrics` can never report a database generation as live while
peers are still validated against the previous one. Stored material that cannot
be converted to runtime trust — an invariant admission validation is supposed to
guarantee — fails closed without panicking: the previous generation stays live,
`..._load_rejections_total` increments with the `invalid_material` reason, and
the candidate is not published. On a reload that failure happens at the staging
step, so the *configuration* apply is rejected too and the candidate never
becomes live beside the previous trust.

###### A backup bootstrap has no trust authority, and says so

Database mode can start on the externally provisioned on-disk snapshot at
`FERRUM_DB_CONFIG_BACKUP_PATH` when the database is unreachable or returns an
unusable snapshot. That snapshot carries **no** trust state and structurally
cannot: `GatewayConfig.gateway_trust_bundles` is `#[serde(skip)]` precisely so a
multi-namespace control plane cannot leak every served namespace's trust
material into one subscriber's `config_json`, so the field deserializes empty no
matter what the committed database generation held.

An empty vector there is therefore **"unknown"**, not "revoked", and
`resolve_trust_authority` cannot tell the two apart on its own. Left alone, the
process would resolve to the file/source authority and quietly authenticate
gateway-to-mesh peers with the source-loaded SVID trust — including a root the
committed database generation had *withdrawn*, for as long as the outage lasted.
Reading the trust state out of the backup file instead would not fix it: the
file is arbitrarily old, so trusting its trust section re-enables a stale root
by a different route.

The only sound state is unknown, and the only sound behaviour for an unknown
trust anchor is to refuse:

- the backup fallback marks the trust authority unresolved before any listener
  binds, and the startup trust publication is **skipped** rather than recording
  an empty generation that would clear the standing failure state and advertise
  a convergence this process never read;
- while it holds, `ProxyState::admits_gateway_mesh_identity` is false, so native
  gRPC mesh dispatch answers Trailers-Only `UNAVAILABLE` with the fixed
  metadata-free message and HTTP-family mesh dispatch and mesh TCP/UDP egress
  refuse before any dial. Ordinary non-mesh proxying is unaffected — the gate is
  only consulted on the gateway-to-mesh admission path;
- `GET /gateway-trust/status` reports `authority_unresolved: true`, which is a
  distinct signal from `configured: false` (that one means "published, and this
  namespace has no record");
- it clears at exactly one place: the single chokepoint through which an
  authoritative database **full** snapshot reaches the live runtime, and only
  after that generation's trust has already been staged, fenced, installed, and
  republished. An incremental delta may not clear it — a delta describes a
  change to a base this process never read, so it cannot establish whether a
  trust record exists — and a rejected candidate leaves the refusal standing.

A data plane's configuration never carries the resource, so its trust arrives on
the ConfigSync side channel — and it is handed to the snapshot/delta
publication (`update_config_off_thread_with_gateway_trust` /
`apply_incremental_with_gateway_trust`) rather than applied afterwards, so the
DP boundary is the same single fenced generation. An `Unchanged` side channel
changes nothing; explicit `Replace`/`Clear` semantics, cross-CP equivalence, and
snapshot/delta freshness fencing are unaffected, and a rejected apply discards
the trust decision with the configuration it arrived with.

##### Observability

`/metrics` exposes four process series, rendered with **no labels at all** —
`ferrum_gateway_trust_bundle_published_generations_total`,
`..._load_rejections_total`, `..._ambiguous_authority_total`, and
`ferrum_gateway_trust_bundle_last_published_unix_seconds`. Cardinality is fixed
by construction: there are no namespace, trust-domain, or resource-id labels.

`published_generations_total` counts generations that reached the **actual
publication boundary** — the `ArcSwap` store that makes a configuration
generation live — not candidates that merely loaded. A load still has
validation, overlay composition, the atomic swap, and broadcast ahead of it, so
counting there would report generations that were never published. A
publication carrying no database trust record is not counted at all, and neither
is one the **ambiguous-authority rule refuses**: the per-namespace projection
runs after the swap, during broadcast, so the swap consults the unpartitioned
file/overlay slot directly. That slot is a single value compared against every
namespace, so the refusal is all-or-nothing — an all-ambiguous generation
increments `..._ambiguous_authority_total` and leaves
`published_generations_total` alone, while a genuinely accepted generation
spanning several namespaces still counts exactly **once**, as one generation
reaching the swap.

The counter is incremented at the swap, never per subscriber, so a data plane
reconnecting and re-receiving the same generation does not inflate it.

`ambiguous_authority_total` counts **refusals, not withdrawals**. The projection
is `KeepPrevious`: the side channel says nothing and every subscriber retains
the trust generation it already accepted. Nothing is revoked, which is why the
refusal needs a counter and a bounded `last_failure_reason`
(`ambiguous_authority`) to be visible at all — by design it changes nothing on
the wire.

There is deliberately **no process-wide revision gauge**. Revisions are per
namespace, so a single process atomic would be last-writer-wins and actively
misleading on a multi-namespace CP. The namespace-scoped view is on the
authenticated `GET /gateway-trust/status`, which returns that namespace's
live-published revision, its authority counts, timestamps, a bounded failure-reason enum, and
a `generation` digest that is stable across replicas and changes on every
rotation or revocation — never PEM/DER/JWKS bytes, key ids, or secret/provider
URIs. The namespace value is captured at the same `ArcSwap` publication
boundary as the live configuration; status does not combine the newest
database row with a process-wide counter. A candidate that has not yet polled,
or that validation rejected, therefore cannot masquerade as converged and the
previous published generation remains visible.

##### Namespace isolation

`CpGrpcServer::filter_config_to_namespace_for_scope` prunes
`gateway_trust_bundles` to the subscribing namespace at the primary
authorization boundary, then projects that namespace's own record into the
unpartitioned slot the side channel reads. The pre-existing defense that clears
unpartitioned trust on a claim-requiring scope runs *before* the projection and
is preserved, not replaced: a namespace with no record still receives nothing.
The vector itself is `#[serde(skip)]` on `GatewayConfig`, so a multi-namespace
CP's full set of tenant records can never ride the ConfigSync `config_json`
wire.

Tenant-isolated roots no longer require separate CP and config-store instances.
See the [CP namespace-tenancy protocol matrix](cp_namespace_tenancy.md#protocol-matrix) and the enforcement coverage in [`cp_multi_namespace_tests.rs`](../tests/integration/cp_multi_namespace_tests.rs).

##### Acceptance coverage

The store contract, the admission validation, the publication accounting, and
the ConfigSync projection are asserted in-process by
[`gateway_trust_bundle_store_tests.rs`](../tests/integration/gateway_trust_bundle_store_tests.rs),
[`gateway_trust_bundle_admin_tests.rs`](../tests/integration/gateway_trust_bundle_admin_tests.rs),
and [`gateway_trust_bundle_tests.rs`](../tests/unit/config/gateway_trust_bundle_tests.rs).
Database serving mode's live-verifier installation (startup, rotation,
revocation, ambiguous authority, unconvertible material, and the non-database
no-op) is asserted in
[`gateway_trust_runtime_publication_tests.rs`](../tests/unit/gateway_core/gateway_trust_runtime_publication_tests.rs).

Live, backend-by-backend acceptance runs in the hosted `Functional Tests
(data-plane)` job through
[`functional_gateway_trust_bundle_ha_test.rs`](../tests/functional/functional_gateway_trust_bundle_ha_test.rs):

| Acceptance criterion | Where it is proved live |
|---|---|
| Create / read / rotate with overlap / explicit revoke on every provisioned backend | `test_gateway_trust_bundle_acceptance_{sqlite,postgres,mysql,mongodb_standalone,mongodb_replica_set}` |
| Optimistic concurrency (a stale expectation is a typed `409`, never an overwrite) | the same acceptance cells |
| A malformed or oversized candidate is refused before publication and the prior valid bundle survives | the same acceptance cells |
| A rotation reaches the publication boundary (`published_generations_total` advances at the swap) | the same acceptance cells |
| Namespace A cannot read, write, delete, list, or infer namespace B's record | the same acceptance cells |
| A restart reconstructs the identical generation, revision, and material from the database alone | the same acceptance cells, plus the CP restart in the HA cells |
| Two CP replicas observe and publish the same committed revision **without a restart** | `test_two_control_plane_replicas_converge_{postgres,mongodb}` |
| Concurrent writers racing from one read leave exactly one winner | the same HA cells |
| An interrupted MongoDB write never leaves a committed document whose revision no change row records | `test_mongodb_{standalone,replica_set}_leaves_no_unrecorded_trust_revision` |
| A committed create / rotation / revocation whose signal was already consumed is still detected by the next poll | `tests/unit/config/gateway_trust_bundle_tests.rs` drift-detection cells |
| Detected drift is repaired by the full-reload publication path in the same poll tick, with poll-completion accounting unchanged | `gateway_trust_drift_escalates_into_the_same_tick_full_reload` + `{database,control_plane}_poll_tick_records_on_every_normal_exit_without_async_wrapper` in `tests/unit/gateway_core/db_poll_supervision_tests.rs` |

The MongoDB interruption cells `SIGKILL` the control plane mid-rotation and then
read the collection directly: the committed document's `revision` must still be
a `config_changes` sequence that exists. That is a *crash-consistency* property
of the signal-first ordering, and it is deliberately narrower than visibility —
it proves a matching change row exists, not that the row was still unconsumed
when the document committed. A live poller can consume that row before the
document lands, which is why standalone visibility is proved on the read side
instead. A redundant change row is allowed by contract and costs one wasted full
reload.

The live suite cannot reproduce that interleaving deterministically, so the
poll-side repair is asserted against a store simulator that commits the change
signal and the document as two explicit, separately ordered steps: signal
committed → cursor advanced by a full reload against the old document →
document commits with no unconsumed signal left → the next poll's drift check
still escalates. Rotation, first-incarnation create, revocation, and
delete-then-recreate each have their own cell, alongside the bounded-cost,
namespace-isolation, and read-failure cells.

Two gaps remain, and are not claimed as covered: the CP still publishes a
rotation as a FULL_SNAPSHOT rather than a trust-carrying DELTA (deliberate — the
`IncrementalResult` body is a same-major.minor wire contract), and the DP-side
apply of `Replace`/`Clear` is exercised by the existing ConfigSync suites rather
than by a new end-to-end CP→DP datapath cell in this matrix.

DP persistence is memory-only on every path: received bundles are stored in lock-free `ArcSwap` runtime state and are not written to disk or a database. A restarted DP must reconnect and fetch the value from its CP again.

Federated remote-cluster roots have a separate runtime mechanism. The [mesh federation poller](../src/modes/mesh/federation.rs) fetches each configured federation endpoint at `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` and overlays the validated result onto the `TrustBundleSet.federated` subset. That poller is independent of this local/CP-authoritative config-store matrix and its `trust_bundles_json` delivery path.

DPs handle both types transparently: full snapshots replace the entire config; deltas are applied via `ProxyState::apply_incremental()` which patches the in-memory config and performs surgical cache updates.

### Namespace Pairing

By default a CP serves a single namespace. Every DP that connects MUST set `FERRUM_NAMESPACE` to a value the CP serves; the CP rejects `Subscribe` and `GetFullConfig` calls from DPs that advertise an unserved namespace with `FailedPrecondition` and an error message naming both namespaces.

This is a hard requirement, not a warning:

- In the default single-namespace mode the CP loads only its own namespace, so without this check it would silently serve `production` config to a DP that booted with `FERRUM_NAMESPACE=staging` — a multi-tenant security gap.
- A CP can serve **multiple** namespaces by setting `FERRUM_CP_NAMESPACES` (CSV set, or `*` for cluster-wide) with per-namespace broadcast partitioning and automatically required `ns` JWT tenancy claims — see [cp_namespace_tenancy.md](cp_namespace_tenancy.md). Operators who keep `FERRUM_CP_NAMESPACES` unset must run one CP per namespace.
- The DP also re-filters every received snapshot/delta locally (defense in depth) so a future CP regression cannot silently pollute a DP's `GatewayConfig` with cross-namespace resources. Filtered resources are logged as warnings.

### Resilience

The CP/DP architecture is designed so that data source outages are invisible to API consumers:

- **Auto-reconnect**: If the CP connection drops, the DP reconnects with jittered exponential backoff from 1 second to a 30-second cap. Connection errors and zero-message clean closes increase backoff; a clean close after at least one applied config message resets it. A transport/RPC failure after the attempt already accepted config also resets backoff to the initial delay (healthy progress) while still failing over. Multi-CP failover keeps accumulating backoff across CP switches so the 30s cap is reachable.
- **Stream liveness**: ConfigSync uses HTTP/2 PING keepalive (~30s interval / ~10s timeout, while-idle), TCP keepalive, and negotiated application heartbeat frames so silent partitions are detected without treating healthy idle streams as dead. Heartbeats are capability-negotiated: the DP advertises `SubscribeRequest.supports_heartbeat` and the CP confirms with `ConfigUpdate.heartbeat_negotiated` on the first message of the stream. The CP sends heartbeat frames only to advertising subscribers, and the DP arms the 150s application-silence watchdog only after that confirmation — so a mixed patch-version pair in either direction keeps serving without heartbeat-induced reconnect churn (see [upgrade_guide.md](upgrade_guide.md#mixed-version-wire-compatibility-patch-level-rollouts)). Transport keepalive still applies to unnegotiated streams.
- **Cached config**: DPs continue serving traffic with their last known config during CP outages, up to the operator-set bound described in [Bounded last-known-good configuration age](#bounded-last-known-good-configuration-age) (`FERRUM_DP_CONFIG_MAX_STALE_SECONDS`, default 1 hour; `0` restores unbounded serving). `last_config_received_at` is preserved across reconnect attempts until a newer config is applied.
- **Connect timeout**: DP uses a 10-second connect timeout per attempt
- **Stale failover fencing**: Freshness authority is the monotonic high-water mark of committed GatewayConfig timestamps (`loaded_at` / accepted resource-delta `poll_timestamp`). A DELTA whose committed `poll_timestamp` predates that watermark is refused before apply and terminates the stream (`evaluate_delta_authority` → `DpStreamEnd::InvalidDeltaFreshness`), including after an older content-equivalent fallback snapshot establishes a subscription base, so a lagging CP cannot replay an ABA history. The fence is deliberately source-blind: an accepted cross-source snapshot makes that CP the authority source, so exempting the authority's own source would make the fence inert in exactly the case it exists for. Empty and trust-only stale bodies are fenced the same way (a lagging trust-only replay is an anchor rollback) but, like every other empty body, do not raise sticky divergence. A refused DELTA applies nothing, advances no watermark, and does not mark config received. `ConfigUpdate.version` must reconcile with the corresponding body timestamp (`GatewayConfig.loaded_at` for FULL_SNAPSHOT and `IncrementalResult.poll_timestamp` for DELTA); inconsistent or unorderable inputs fail closed without fabricating timestamps. A committed stamp implausibly far in the DP's own future — more than a bounded clock-skew tolerance of 300 seconds (`CONFIGSYNC_MAX_FUTURE_SKEW_SECS`, matching the established Kerberos/JWT NTP-drift leeway) ahead of local wall time — is also refused fail-closed before apply, for both snapshots and deltas, so a CP whose clock runs ahead cannot poison the monotonic watermark and fence every correct-clock failover CP with genuinely newer config until wall time catches up; the untrusted timestamp is never clamped into authority. Same-source detection canonicalizes CP endpoint URLs to `(scheme, host, port)` so harmless equivalent spellings (a trailing slash) are not treated as cross-source, while distinct schemes/hosts/ports stay distinct and malformed URLs fall back to exact-string comparison (fail closed). A FULL_SNAPSHOT from a different CP URL whose committed stamp is older than the applied authority is refused, and the DP **terminates that ConfigSync stream and fails over** rather than staying on it. The one safe exception is a snapshot whose complete authoritative payload matches the currently applied payload: canonical `GatewayConfig` content excluding the CP-local `loaded_at`, plus the effective CP gateway-trust side-channel state (`trust_bundles_json` as present material or explicit `null` clear). Trust equivalence is order-insensitive and remembered on snapshot authority as `Unknown` until an accepted explicit Clear or Replace establishes Absent/Present; accepted trust-only deltas refresh that remembered trust view so a later older fallback cannot match against a stale or unestablished trust state. An empty/unchanged trust side channel leaves trust `Unknown` (or preserves prior `Unknown`) and cannot establish complete-payload equivalence — it must never invent Absent. The candidate is canonicalized the same way the applied config was before comparison (normalize, resolve upstream TLS, HMAC-credential quarantine, gateway workload-metrics identity injection), so a node-local pre-swap mutation — for example the gateway workload-metrics plugin a DP with a gateway SVID injects — cannot report a spurious mismatch and fence an otherwise-equivalent failover snapshot. Same-source recovery remains accepted without needing the exception. This avoids indefinitely fencing independently polling CPs that produced identical complete payloads with different timestamps, without allowing trust-anchor rollback from an unknown trust view. If older content or trust differs (or trust is still Unknown), refusal is deliberate: if the DP kept reading, the same stale fallback CP's next delta (removals and trust-only updates included) would apply against the newer active config. The refused stream never marks config as received, never advances `last_config_received_at`, and never updates snapshot authority; the DP keeps serving its last applied config and reconnects with accumulating backoff. Every fenced FULL_SNAPSHOT — stale/older, unorderable/inconsistent version, or implausibly-future clock skew — increments the fixed-cardinality `ferrum_configsync_fenced_full_snapshots_total` counter for operator visibility (fencing does not raise sticky `config_diverged`, which is reserved for delta rejections). An inconsistent, implausibly-future, or stale (pre-watermark) non-empty DELTA raises sticky divergence, is rejected before apply, and fails over with accumulating backoff. Same-source recovery snapshots remain accepted, and their watermark stays monotonic even when the recovery body is older. Each new subscription must commit a valid FULL_SNAPSHOT before any DELTA can apply — including library/test callers with no `startup_ready` flag (startup readiness is independent of subscription base gating). An unusable FULL_SNAPSHOT (parse, trust side-channel, field/host/path/reference validation, TLS staging, version reconciliation, freshness fence, or runtime apply rejection) always terminates the subscription so later deltas cannot apply against a base that missed the authoritative reload; when a prior base was already accepted the DP reconnects for a fresh snapshot while keeping last-known-good config. A pre-snapshot DELTA terminates with accumulating failure backoff. Decision seam: `configsync_lifecycle::full_snapshot_stream_disposition` / `evaluate_delta_against_subscription_base` / `evaluate_delta_authority` / `snapshot_failure_stream_disposition`.
- **Delta rejection resync**: After any non-empty DELTA parse/validation/apply rejection (or unclassifiable parse / invalid trust side-channel), the DP stops consuming that stream, raises sticky `config_diverged` on `GET /cluster`, increments `ferrum_configsync_delta_rejections_total`, and reconnects for an authoritative FULL_SNAPSHOT. Rejected resource config does not advance `last_config_received_at`. Divergence clears only after a FULL_SNAPSHOT is accepted (`ferrum_configsync_divergence_recoveries_total` / `config_divergence_recoveries_total`).
- **CP database outage**: If the CP's database goes offline, the CP continues serving its cached config to DPs via gRPC. It does not broadcast stale updates — DPs simply retain their last known config. When the database recovers, the next poll picks up any changes and broadcasts them.
- **Admin API fallback**: Both CP and DP admin API read endpoints fall back to the in-memory cached config when the database is unavailable. Responses served from cache include an `X-Data-Source: cached` header. Write operations require a live database and return `503` if unavailable.
- **Health visibility**: Authenticated `/health` detail reports `cached_config` status (available, loaded_at, proxy/consumer counts) so operators can see whether the node is running on cached data. Unauthenticated probes receive only `status` and `ready`.

### Bounded last-known-good configuration age

A DP that has accepted one snapshot keeps serving it while every control plane is unreachable. Without a bound, that is indefinite authority loss: the DP can no longer be told that a route was deleted, an authorization policy tightened, an endpoint withdrawn, or an identity/credential revoked, yet its readiness stays green and a load balancer or Kubernetes Service keeps sending it new traffic. `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` (default `3600`) bounds that window; `FERRUM_DP_CONFIG_STALE_ACTION` (default `fail_closed`) decides what happens to new traffic at the boundary. Setting the bound to `0` restores unbounded serving as an explicit, deliberately unsafe operator opt-in, and logs a startup warning.

**What the age is measured from.** The clock starts at the last snapshot or delta that was *validated and successfully applied*, and it runs on a monotonic clock (`Instant`), so a wall-clock step — NTP correction, an operator running `date`, a VM snapshot restore — can neither extend nor shorten the safety window. The following deliberately do **not** reset it:

| Event | Resets the age? |
|---|---|
| Applied FULL_SNAPSHOT or accepted DELTA | **Yes** — the only reset |
| ConfigSync heartbeat frame | No |
| Reconnect / CP failover / transport success | No |
| A pre-snapshot DELTA, or a DELTA refused for version/clock/authority freshness (empty body included) | No — counted once as `snapshot_rejected` |
| A DELTA that was admitted and then failed to apply (empty body included) | No — counted once as `snapshot_apply_failed` |
| Fenced FULL_SNAPSHOT (stale, unorderable, clock-skewed) | No — counted as `snapshot_rejected` |
| Rejected non-empty DELTA | No — counted as `snapshot_rejected` |
| Snapshot admitted but rejected during apply | No — counted as `snapshot_apply_failed` |

**When the DP degrades.** The configured maximum **is** the boundary — nothing is added to it. Staleness requires the applied snapshot to have reached the bound **and** the DP to have actually lost its authoritative source. That second condition is a state the reconnect loop owns (`cp_authority`), not a time window:

| `cp_authority` | Meaning | Can latch the bound? |
|---|---|---|
| `connected` | A ConfigSync stream to some CP is established | No |
| `reconnecting` | An intentional primary-retry or TLS-rotation reconnect, or a healthy session that had delivered config, is being re-established | No |
| `lost` | A connect/subscribe attempt failed, or a stream ended without delivering usable authoritative config | Yes |

- *Partial CP loss.* Losing one CP while another remains authoritative never marks the DP stale — the failed stream leaves the DP `reconnecting`, the handoff completes, and a connected DP is still receiving revocations. A configuration that is simply quiet for longer than the bound is not stale, and a successful failover does not blip traffic even when the applied snapshot is already older than the bound.
- *Intentional reconnects.* A primary-retry reconnect (`FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`) and a CP/DP TLS rotation are deliberate disconnects, never authority loss.
- *Total CP loss.* With no CP reachable, the first failed attempt moves the DP to `lost`, and it degrades exactly when the applied snapshot reaches the bound — immediately, if it was already older. The only detection latency is the transport/failover attempt itself, which is unavoidable; it is not a configurable or hidden grace, and repeated failed CP cycles cannot postpone the boundary, because the boundary is the applied-snapshot age and not an outage duration.

**What degrading does.** `stale` is sticky once raised:

1. `/health` (and `/status`) report `ready: false` with `status: "unavailable"` and return `503`, so orchestrators stop steering new traffic at the pod. `/live` is unaffected — the process is alive, its configuration is not current.
2. Under `fail_closed`, new admissions are refused on every protocol family the DP serves:

   | Family | Refusal at the boundary |
   |---|---|
   | HTTP/1.1, HTTP/2 (including gRPC and gRPC-Web) | `503` / gRPC `UNAVAILABLE`, checked **before** the ACME HTTP-01 early return — a CP-controlled challenge or route may not be the one request shape that walks past the fence — and independently of the overload carve-out that deliberately still lets ACME outrun load shedding |
   | HTTP/3 | `503` / gRPC `UNAVAILABLE` on the request stream |
   | TCP / TCP+TLS stream listeners | New connection dropped at accept (RST) |
   | UDP stream listeners | Datagrams from sources with **no established session** are dropped; UDP has no handshake but it does have a real new-session boundary, and it is enforced on every receive path (`recvmmsg` batch, PKTINFO batch, and the non-Linux `try_recv_from` drain) |
   | DTLS stream listeners | New associations refused at both the pre-allocation gate (`allow_new_session`) and the post-accept gate, so no race path admits one |

   Already-accepted connections, established UDP/DTLS sessions, and in-flight requests are untouched and drain under the normal timeouts; graceful shutdown draining is unchanged.
3. Under `readiness_only`, only step 1 applies. This is the named compatibility mode for deployments that would rather keep serving stale policy than shed traffic.

**Recovery.** The stale state clears only when a snapshot passes every normal validation, freshness-authority, and monotonic-version check *and* applies successfully. Reconnecting, negotiating heartbeats, or receiving a snapshot that is then fenced or fails to apply does not restore readiness or admission.

**Startup and restarts.** The DP holds no persisted or on-disk configuration cache — it starts with an empty `GatewayConfig` and fetches everything from a CP — so a restart always begins with no applied snapshot. In that state readiness is already `false` (`startup_ready` waits for the first applied snapshot and backend-capability classification), and the same bound applies with the age measured from process start: a DP that never reaches a CP is stale after `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`, reported as `awaiting_first_snapshot` until then. Restart behavior is therefore identical with or without a prior outage.

**Diagnostics.** Authenticated `/health` includes a fixed-cardinality `dp_config` object (`stale`, `reason`, `stale_action`, `new_traffic_blocked`, `cp_connected`, `cp_authority`, `cp_disconnected_seconds`, `max_stale_seconds`, `applied_snapshot`, `snapshot_age_seconds`, and the `applied`/`rejected`/`apply_failed`/`stale_transitions` counters). `reason` is a closed set that distinguishes `cp_disconnected`, `snapshot_stale`, `snapshot_rejected`, and `snapshot_apply_failed` (plus `ok` and `awaiting_first_snapshot`). The same state is exported as fixed-cardinality Prometheus series: `ferrum_dp_config_snapshot_age_seconds`, `ferrum_dp_config_max_stale_seconds`, `ferrum_dp_config_stale`, `ferrum_dp_config_new_traffic_blocked`, `ferrum_dp_config_cp_connected`, `ferrum_dp_config_stale_transitions_total`, `ferrum_dp_config_snapshots_applied_total`, `ferrum_dp_config_snapshots_rejected_total`, and `ferrum_dp_config_snapshot_apply_failures_total`. `namespace` is the only standard metric label; CP endpoint, credential, node id, and configuration content are not exposed.


## DP Multi-CP Failover

Data Planes can be configured with a priority-ordered list of Control Plane URLs for automatic failover. When the primary CP is unreachable, the DP fails over to the next CP in the list.

### How It Works

1. The DP connects to the first (primary) CP URL
2. If the connection fails, the DP moves to the next URL while retaining accumulated backoff
3. After exhausting all URLs, the DP loops back to the primary with accumulated backoff
4. When connected to a fallback CP, the DP periodically retries the primary (configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`, default: 300s). Applies finish before that timer can cancel them.
5. On clean stream disconnect from a fallback CP after receiving config, the DP always tries the primary first

### Behavior Summary

| Scenario | Behavior |
|----------|----------|
| Primary CP down on startup | Try primary, fail, try secondary with accumulated backoff |
| Primary CP drops mid-stream | Stream ends → try primary first after clean close with config |
| All CPs exhausted | Cycle back to primary; keep accumulated backoff |
| Connected to fallback, primary comes back | After retry interval, disconnect from fallback and retry primary |
| Single URL configured | Treated as a one-entry priority list |
| Stream listener bind conflict on DP | Logged as local bind issue; stream stays connected and readiness proceeds |

### Configuration

```bash
# Priority-ordered list of CP URLs (highest priority first)
FERRUM_DP_CP_GRPC_URLS=https://cp1.example.com:50051,https://cp2.example.com:50051,https://cp3.example.com:50051

# How often to retry the primary while connected to a fallback (default: 300s)
FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS=300
```

**TLS config is shared** across all CP URLs — the same `FERRUM_DP_GRPC_TLS_*` settings apply to every CP connection. SNI is extracted per-URL automatically. In DP mode, file/provider/Kubernetes-backed `FERRUM_DP_GRPC_TLS_*` sources are watched; when the CP CA or DP client cert/key bytes change, the active CP stream reconnects and new connections use the rotated material. In CP mode, file/provider/Kubernetes-backed `FERRUM_CP_GRPC_TLS_*` sources update the active server TLS slot so new gRPC handshakes use rotated cert/key/client-CA material without a process restart.

Use `FERRUM_DP_CP_GRPC_URLS` for both single-CP and multi-CP deployments.

For multi-region high-availability patterns using this feature, see [Multi-Region High Availability](multi_region_ha.md).

### Shared real-IP header ownership

`FERRUM_REAL_IP_HEADER` is a cluster ownership setting in CP/DP deployments.
Configure the same effective value on every CP and DP, including leaving it
unset everywhere when no authoritative header is used. A DP advertises its
effective value on `ConfigSync.Subscribe` and `GetFullConfig`; the CP rejects a
missing or mismatched advertisement before returning configuration. This keeps
CP admin admission for `correlation_id.header_name` aligned with the serving
DP's client-attribution ownership and prevents partial fleet reloads. All CPs
in a failover set must use the same value.

## Environment Variables

### Control Plane

| Variable | Required | Description |
|----------|----------|-------------|
| `FERRUM_MODE` | Yes | Set to `cp` |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | Yes | gRPC listen address (e.g., `0.0.0.0:50051`). Set port to `0` to disable the gRPC listener. A non-loopback **plaintext** bind (no CP gRPC TLS) is refused at startup unless `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` |
| `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT` | No | Permit plaintext gRPC config sync on a non-loopback address (default `false`). Loopback (`127.0.0.1`/`::1`/`localhost`) plaintext is always allowed; even when permitted, plaintext logs a high-severity warning on both CP and DP |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` | Yes | Shared JWT secret for CP/DP gRPC auth |
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | No | PEM certificate for gRPC TLS |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | No | PEM private key for gRPC TLS |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | No | PEM CA for verifying DP client certs (mTLS) |
| `FERRUM_CP_GRPC_MAX_CONNECTIONS` | No | Max concurrent CP gRPC connections, admitted **before** any TLS/mTLS handshake work is allocated and held through the served HTTP/2 session (default `1024`; `0` = unlimited) |
| `FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP` | No | Max concurrent CP gRPC connections from one source IP (default `64`; `0` disables). Must not exceed `FERRUM_CP_GRPC_MAX_CONNECTIONS` |
| `FERRUM_CP_GRPC_MAX_STREAM_LIFETIME_SECONDS` | No | Finite maximum bearer-authenticated configuration-stream lifetime (default `3600`; range `60..=86400`; cannot be disabled). The verified token deadline may close the stream earlier |
| `FERRUM_XDS_MAX_TOTAL_STREAMS` | No | Shared process ceiling for concurrent ConfigSync, MeshSubscribe, and ADS streams (default `1024`). Enforced on the CP even when ADS is disabled. `0` is unbounded and refused under production posture without `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true` |
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the Admin API |
| `FERRUM_DB_TYPE` | Yes | Database type (`postgres`, `mysql`, `sqlite`, or `mongodb`) |
| `FERRUM_DB_URL` | Yes | Database connection URL |
| `FERRUM_DB_POLL_INTERVAL` | No | Config poll interval in seconds (default: 30) |
| `FERRUM_REAL_IP_HEADER` | No | Cluster-wide authoritative client-IP header; must match every DP and peer CP |

### Data Plane

| Variable | Required | Description |
|----------|----------|-------------|
| `FERRUM_MODE` | Yes | Set to `dp` |
| `FERRUM_DP_CP_GRPC_URLS` | Yes | Comma-separated priority-ordered CP URLs (`http://` or `https://`). A non-loopback `http://` (plaintext) URL is refused at startup unless `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` |
| `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT` | No | Permit a non-loopback `http://` (plaintext) CP URL (default `false`). Loopback URLs are always allowed; even when permitted, plaintext logs a high-severity warning |
| `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` | No | Retry primary CP interval when on fallback (default: 300) |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` | Yes | Shared JWT secret for CP/DP gRPC auth (same value as CP) |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | No | PEM CA cert for verifying CP server cert |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | No | PEM client cert for mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | No | PEM client key for mTLS |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | No | **Not supported — rejected at startup when `true`.** Disabling server certificate verification is unsafe; pin the CP CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` for self-signed test certs instead |
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the read-only Admin API |
| `FERRUM_PROXY_HTTP_PORT` | No | HTTP proxy port (default: 8000). Set to `0` to disable the plaintext HTTP proxy listener |
| `FERRUM_PROXY_HTTPS_PORT` | No | HTTPS proxy port (default: 8443) |
| `FERRUM_REAL_IP_HEADER` | No | Cluster-wide authoritative client-IP header; must match every CP and peer DP |

## Example Deployment

### Shared JWT Secret

The CP and DP must use the same `FERRUM_CP_DP_GRPC_JWT_SECRET` value. The DP automatically generates short-lived JWTs (59-minute TTL) from this secret on each connection attempt, and the CP validates them with the same secret. No manual JWT generation is required.

The examples below use SQLite for local development and PostgreSQL for the TLS
deployment path. CP mode supports the same database backends as database mode:
PostgreSQL, MySQL, SQLite, and MongoDB. See
[configuration.md](configuration.md#database) for the canonical
`FERRUM_DB_TYPE` reference and [mongodb.md](mongodb.md) for MongoDB-specific
connection and pooling behavior.

### Control Plane (Plaintext — local development only)

Plaintext is permitted only on a loopback bind address. For a networked CP, use
the TLS/mTLS examples below, or set `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` to
intentionally run plaintext on a non-loopback address (trusted network only).

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL=sqlite://ferrum.db \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_DB_POLL_INTERVAL=10 \
./ferrum-edge run
```

### Data Plane (Plaintext — local development only)

The CP URL must be loopback for plaintext. For a remote CP, use the TLS/mTLS
examples below, or set `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` (trusted network
only).

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS=http://localhost:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_PROXY_HTTPS_PORT=8443 \
./ferrum-edge run
```

### Control Plane (mTLS)

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL=postgres://user:pass@db:5432/ferrum \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem \
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem \
FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH=/certs/ca.pem \
./ferrum-edge run
```

### Data Plane (mTLS)

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS=https://cp-host:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem \
FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH=/certs/dp-client.pem \
FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH=/certs/dp-client-key.pem \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
./ferrum-edge run
```

## Cluster Status Monitoring

The `GET /cluster` admin endpoint (JWT-authenticated) provides live CP/DP connection visibility.

### From the CP

```bash
curl -H "Authorization: Bearer $TOKEN" http://cp-host:9000/cluster
```

Returns all connected DP nodes and Mesh nodes (each in its own array — `data_planes` and `mesh_nodes`) with metadata: `node_id`, `version`, `namespace`, `status`, `connected_at`, and `last_sync_at`. Mesh node entries also include `last_heartbeat_at`. Disconnected nodes are automatically removed from their respective registries — only currently connected nodes appear. The `last_sync_at` timestamp updates on every config broadcast (delta or full snapshot) to that registry. MeshSubscribe streams also emit lightweight heartbeat frames; the CP reaps mesh registry entries that stop producing stream activity for 5 minutes.

### From a DP

```bash
curl -H "Authorization: Bearer $TOKEN" http://dp-host:9000/cluster
```

Returns the DP's connection state to its CP: `url` (which CP it is connected to), `status` (`online`/`offline`), `is_primary` (whether this is the primary or a fallback CP), `connected_since`, `last_config_received_at`, and sticky ConfigSync divergence fields (`config_diverged`, `config_diverged_since`, `config_divergence_recoveries_total`). When the DP is disconnected and retrying, `status` is `offline` and `connected_since` is `null`.

See [admin_api.md](admin_api.md#cluster-status) for full response schemas.

## DP Admin API

The Data Plane exposes a read-only Admin API for monitoring:
- All write operations (create/update/delete proxies, consumers, plugins) return `403 Forbidden`
- Read operations (list proxies, consumers, plugin configs, health checks) are served from the DP's in-memory cached config
- Responses include `X-Data-Source: cached` header to indicate the data comes from the cache rather than a live database
- Authenticated `/health` detail includes `cached_config` (availability, loaded_at, proxy/consumer counts); unauthenticated probes receive only `status` and `ready`
- `GET /cluster` shows CP connection status including whether the DP is on its primary or fallback CP
- The admin API always reflects the DP's currently cached config received from the CP
