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

> **`FERRUM_DP_GRPC_TLS_NO_VERIFY` is not supported** and is rejected at startup when `true`: the tonic-managed gRPC client exposes no hook to skip server certificate verification, so the flag only ever provided false confidence. To test against a CP with a self-signed certificate, pin its CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH`.

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
streams. Invalid reloads retain the last accepted verifier. DPs and mesh/xDS
clients use their existing bounded reconnect backoff and reread
`FERRUM_DP_CP_GRPC_TOKEN_FILE` (or mint a new short-lived token) on each attempt.
The fixed-cardinality
`ferrum_grpc_config_stream_terminations_total{surface,reason}` metric and
structured `grpc_config_stream_*` audit events distinguish `expired`,
`verification_key_removed`, `server_max_lifetime`, and `transport_closed`
without token, claim, key, node, or namespace labels.

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

`ConfigUpdate.trust_bundles_json` and `FullConfigResponse.trust_bundles_json` carry the serializable mesh `TrustBundleSet` used by gateway DPs for gateway-to-mesh SPIFFE TLS, or JSON `null` when the CP is explicitly clearing previously delivered trust material. The CP also emits `null` instead of "unchanged" when configured trust bundles fail semantic validation, so DPs revoke stale CP trust anchors rather than preserving them. The CP strips `GatewayConfig.trust_bundles` from DP-facing full snapshot JSON and uses only this side channel, preserving compatibility with older DPs whose config deserializer rejects unknown fields. An empty or missing side channel is treated as "unchanged" for mixed-version CP/DP rollouts. New DPs hot-swap this trust material into the gateway SVID slot when an SVID is loaded, restore startup file trust when the CP clears it, and also retain CP-delivered bundles separately when no local SVID is configured. Older DPs ignore the field.

#### Trust-bundle config-store capabilities

This matrix covers persistence and change detection for the local, CP-authoritative top-level `GatewayConfig.trust_bundles` value. It does not describe the mesh federation runtime overlay discussed below.

| Configuration source | Supplies `GatewayConfig.trust_bundles`? | Detects a runtime change? | Namespace-partitioned? |
|---|---|---|---|
| File (YAML/JSON) | Yes, through serde deserialization | Full file reload only (`SIGHUP` on Unix); no narrow trust-bundle poll | No |
| PostgreSQL | No | No | No |
| MySQL | No | No | No |
| SQLite | No | No | No |
| MongoDB | No | No | No |

The built-in SQL and MongoDB stores persist gateway resources separately and have no storage shape or change detector for the top-level trust-bundle value. The former `GatewayTrustBundlePoll::Current` consumer was therefore unreachable and has been removed together with the unused database-backend poll hook. A future backend may reintroduce runtime updates only with dedicated persistence and a narrow query or change detector that can identify trust-bundle-only changes during ordinary incremental polling. It must return the authoritative current value, including an explicit clear, without performing a full gateway-config reload; validate before swapping; and broadcast the accepted value through `trust_bundles_json`. Namespace-aware distribution also requires a partitioned storage key and lookup rather than one CP-wide value.

Trust bundles are currently CP-level and non-partitioned. A single-namespace CP can distribute its configured value to its DPs, but CPs in `Set` or `All` multi-namespace scope force the side channel to JSON `null` so trust roots cannot cross tenant boundaries. Tenant-isolated roots require separate CP and config-store instances. See the [CP namespace-tenancy protocol matrix](cp_namespace_tenancy.md#protocol-matrix) and the enforcement coverage in [`cp_multi_namespace_tests.rs`](../tests/integration/cp_multi_namespace_tests.rs).

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
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | No | **Not supported — rejected at startup when `true`.** The client cannot skip server verification; pin the CP CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` for self-signed test certs instead |
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
