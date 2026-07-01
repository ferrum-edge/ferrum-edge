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

Gateway trust bundles are CP-level trust roots, not namespace-scoped resources. They are sent to every DP connected to that CP namespace; deployments that need tenant-isolated mesh trust roots should run separate CP/config-store instances. Built-in SQL and MongoDB config stores do not yet persist top-level `GatewayConfig.trust_bundles`, so their narrow trust-bundle poll reports `Unchanged` and preserves trust material supplied by the initial config load. Backends that add a dedicated trust-bundle storage shape must implement `load_gateway_trust_bundles()` with a narrow query or change detector rather than relying on full config reloads.

DPs handle both types transparently: full snapshots replace the entire config; deltas are applied via `ProxyState::apply_incremental()` which patches the in-memory config and performs surgical cache updates.

### Namespace Pairing

By default a CP serves a single namespace. Every DP that connects MUST set `FERRUM_NAMESPACE` to a value the CP serves; the CP rejects `Subscribe` and `GetFullConfig` calls from DPs that advertise an unserved namespace with `FailedPrecondition` and an error message naming both namespaces.

This is a hard requirement, not a warning:

- In the default single-namespace mode the CP loads only its own namespace, so without this check it would silently serve `production` config to a DP that booted with `FERRUM_NAMESPACE=staging` — a multi-tenant security gap.
- A CP can serve **multiple** namespaces by setting `FERRUM_CP_NAMESPACES` (CSV set, or `*` for cluster-wide) with per-namespace broadcast partitioning and automatically required `ns` JWT tenancy claims — see [cp_namespace_tenancy.md](cp_namespace_tenancy.md). Operators who keep `FERRUM_CP_NAMESPACES` unset must run one CP per namespace.
- The DP also re-filters every received snapshot/delta locally (defense in depth) so a future CP regression cannot silently pollute a DP's `GatewayConfig` with cross-namespace resources. Filtered resources are logged as warnings.

### Resilience

The CP/DP architecture is designed so that data source outages are invisible to API consumers:

- **Auto-reconnect**: If the CP connection drops, the DP reconnects with jittered exponential backoff from 1 second to a 30-second cap. A clean stream end resets the next delay to 1 second; connection errors increase it.
- **Cached config**: DPs continue serving traffic with their last known config indefinitely during CP outages
- **Connect timeout**: DP uses a 10-second connect timeout per attempt
- **CP database outage**: If the CP's database goes offline, the CP continues serving its cached config to DPs via gRPC. It does not broadcast stale updates — DPs simply retain their last known config. When the database recovers, the next poll picks up any changes and broadcasts them.
- **Admin API fallback**: Both CP and DP admin API read endpoints fall back to the in-memory cached config when the database is unavailable. Responses served from cache include an `X-Data-Source: cached` header. Write operations require a live database and return `503` if unavailable.
- **Health visibility**: The `/health` endpoint reports `cached_config` status (available, loaded_at, proxy/consumer counts) so operators can see whether the node is running on cached data.

## DP Multi-CP Failover

Data Planes can be configured with a priority-ordered list of Control Plane URLs for automatic failover. When the primary CP is unreachable, the DP fails over to the next CP in the list.

### How It Works

1. The DP connects to the first (primary) CP URL
2. If the connection fails, the DP moves to the next URL with a fresh backoff
3. After exhausting all URLs, the DP loops back to the primary with accumulated backoff
4. When connected to a fallback CP, the DP periodically retries the primary (configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`, default: 300s)
5. On clean stream disconnect from a fallback CP, the DP always tries the primary first

### Behavior Summary

| Scenario | Behavior |
|----------|----------|
| Primary CP down on startup | Try primary, fail, try secondary immediately (fresh backoff) |
| Primary CP drops mid-stream | Stream ends → try primary first (clean disconnect) |
| All CPs exhausted | Cycle back to primary; keep accumulated backoff |
| Connected to fallback, primary comes back | After retry interval, disconnect from fallback and retry primary |
| Single URL configured | Treated as a one-entry priority list |

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
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the Admin API |
| `FERRUM_DB_TYPE` | Yes | Database type (`postgres`, `mysql`, `sqlite`, or `mongodb`) |
| `FERRUM_DB_URL` | Yes | Database connection URL |
| `FERRUM_DB_POLL_INTERVAL` | No | Config poll interval in seconds (default: 30) |

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
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-shared-secret \
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
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_PROXY_HTTPS_PORT=8443 \
./ferrum-edge run
```

### Control Plane (mTLS)

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL=postgres://user:pass@db:5432/ferrum \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem \
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem \
FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH=/certs/ca.pem \
./ferrum-edge run
```

### Data Plane (mTLS)

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS=https://cp-host:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem \
FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH=/certs/dp-client.pem \
FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH=/certs/dp-client-key.pem \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
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

Returns the DP's connection state to its CP: `url` (which CP it is connected to), `status` (`online`/`offline`), `is_primary` (whether this is the primary or a fallback CP), `connected_since`, and `last_config_received_at`. When the DP is disconnected and retrying, `status` is `offline` and `connected_since` is `null`.

See [admin_api.md](admin_api.md#cluster-status) for full response schemas.

## DP Admin API

The Data Plane exposes a read-only Admin API for monitoring:
- All write operations (create/update/delete proxies, consumers, plugins) return `403 Forbidden`
- Read operations (list proxies, consumers, plugin configs, health checks) are served from the DP's in-memory cached config
- Responses include `X-Data-Source: cached` header to indicate the data comes from the cache rather than a live database
- The `/health` endpoint includes `cached_config` details (availability, loaded_at, proxy/consumer counts)
- `GET /cluster` shows CP connection status including whether the DP is on its primary or fallback CP
- The admin API always reflects the DP's currently cached config received from the CP
