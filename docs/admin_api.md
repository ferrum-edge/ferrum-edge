# Admin API Reference

The Admin API provides full CRUD operations for managing Ferrum Edge configuration at runtime. It is available in **Database** and **Control Plane** modes (read/write) and **Data Plane** mode (read-only).

See also:
- [admin_read_only_mode.md](admin_read_only_mode.md) — Read-only mode configuration
- [admin_backup_restore.md](admin_backup_restore.md) — Backup and restore details
- [admin_batch_api.md](admin_batch_api.md) — Batch operations
- [admin_metrics.md](admin_metrics.md) — Metrics endpoint details
- [OpenAPI specification](../openapi.yaml) — Full API schema

## Authentication

All endpoints (except `/health`, `/status`, `/overload`, and exact `/metrics`) require a valid HS256 JWT in the `Authorization: Bearer <token>` header, verified against `FERRUM_ADMIN_JWT_SECRET` (must be at least 32 characters). `/metrics/runtime` requires JWT authentication because it exposes process and host diagnostics. `/charges` also requires JWT authentication because it exposes customer and billing data.

Admin JWTs must include a string `role` claim:

| Role | Access |
| --- | --- |
| `viewer` | Read-only endpoints |
| `operator` | Read-only endpoints plus proxy, upstream, plugin config, backend capability refresh, and mesh egress-scope test operations |
| `admin` | Full access, including consumers, credentials, API specs, batch/restore, and audit logs |

Tokens without a valid `role` claim are rejected.

Generate a token:
```bash
# Using any JWT library; include an explicit role
# Example using Node.js jsonwebtoken:
node -e "console.log(require('jsonwebtoken').sign({sub:'admin', role:'admin'}, 'my-super-secret-jwt-key'))"
```

## Health Check (Unauthenticated)

```bash
curl http://localhost:9000/health
# or equivalently:
curl http://localhost:9000/status
# Returns: {"status": "ok", "timestamp": "...", "mode": "database"}
```

Both endpoints return the same response and do not require JWT authentication, making them suitable for load balancer health probes.

## Proxies

```bash
# List all proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "/new-api",
    "backend_scheme": "http",
    "backend_host": "backend",
    "backend_port": 3000,
    "strip_listen_path": true
  }' \
  http://localhost:9000/proxies

# Get a proxy
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}

# Update a proxy
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/new-api", "backend_host": "new-backend", "backend_port": 4000, "backend_scheme": "http"}' \
  http://localhost:9000/proxies/{proxy_id}

# Delete a proxy
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}
```

### Stream Proxy (TCP/UDP)

Stream proxies use `listen_port` instead of `listen_path`:

```bash
# Create a TCP stream proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "",
    "listen_port": 5432,
    "backend_scheme": "tcp",
    "backend_host": "db.internal",
    "backend_port": 5432
  }' \
  http://localhost:9000/proxies
```

The Admin API validates `listen_port` at creation and update time:
- **409 Conflict** if the port is already used by another stream proxy
- **409 Conflict** if the port conflicts with a gateway reserved port (proxy HTTP/HTTPS, admin HTTP/HTTPS, or CP gRPC)
- **409 Conflict** if the port is already bound by another process on the host (OS-level probe)

In **CP mode**, the gateway reserved port and OS-level checks are skipped since stream proxies run on remote Data Plane nodes.

## Consumers

```bash
# List consumers
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/consumers

# Create consumer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "credentials": {"keyauth": {"key": "my-key"}}}' \
  http://localhost:9000/consumers

# Replace all credentials of a type (PUT replaces entirely)
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "new-api-key"}' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Append a credential for zero-downtime rotation (POST adds to array)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "rotated-api-key"}' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Delete a specific credential by index (0-based)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth/0

# Delete all credentials of a type
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth
```

Credential rotation workflow:
1. `POST .../credentials/keyauth` with the new key — both old and new are now active
2. Roll out the new key to all clients
3. `DELETE .../credentials/keyauth/0` to remove the old key

Max credentials per type is controlled by `FERRUM_MAX_CREDENTIALS_PER_TYPE` (default: 2).

## Plugin Configs

```bash
# List available plugin types
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins

# List all plugin configs
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins/config

# Create plugin config
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "rate_limiting",
    "config": {"limit_by": "ip", "limits": [{"scope": "default", "requests_per_minute": 60}]},
    "scope": "global",
    "enabled": true
  }' \
  http://localhost:9000/plugins/config
```

## Upstreams

```bash
# List all upstreams
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams

# Create an upstream (load-balanced backend group)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend2.example.com", "port": 8080, "weight": 3}
    ],
    "algorithm": "weighted_round_robin",
    "health_checks": {
      "active": {
        "http_path": "/health",
        "interval_seconds": 10,
        "healthy_threshold": 3,
        "unhealthy_threshold": 3
      }
    }
  }' \
  http://localhost:9000/upstreams

# Get an upstream
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}

# Update an upstream
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend3.example.com", "port": 8080, "weight": 2}
    ],
    "algorithm": "round_robin"
  }' \
  http://localhost:9000/upstreams/{upstream_id}

# Delete an upstream
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}
```

Supported algorithms: `round_robin`, `weighted_round_robin`, `least_connections`, `least_latency`, `consistent_hashing`, `random`.

To use an upstream with a proxy, set the proxy's `upstream_id` field. When set, the upstream's targets override the proxy's `backend_host`/`backend_port`. Each target may also specify an optional `path` field which overrides the proxy's `backend_path` when that target is selected.

## Backup & Restore

```bash
# Full backup — exports all proxies, consumers, plugins, upstreams (unredacted)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup > ferrum-backup.json

# Partial backup — only proxies and upstreams
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/backup?resources=proxies,upstreams" > partial-backup.json

# Restore from backup (destructive — replaces all existing config)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @ferrum-backup.json \
  "http://localhost:9000/restore?confirm=true"
```

The backup output is directly compatible with `POST /batch` (additive) and `POST /restore` (full replacement). Database inserts are chunked into 1,000-record transactions for large-scale imports.

See [admin_backup_restore.md](admin_backup_restore.md) for details.

## Audit Log

When `FERRUM_ADMIN_AUDIT_ENABLED=true`, successful admin mutations enqueue a database-backed audit event before the mutation response is returned. The response waits only for bounded queue enqueue, not durable database persistence. Audit persistence is best-effort after the mutation commits: if enqueue or persistence fails, Ferrum logs the failure and still returns the mutation result so operators do not retry an already-applied write. Partial `POST /batch` and `POST /restore` mutations that return `207 Multi-Status` emit an audit event when at least one resource was changed. Each event includes an ID, timestamp, actor (`sub` claim), action, resource type, resource ID, namespace, and a JSON `diff` object with redacted consumer credentials.

`GET /audit` requires an `admin` role token and supports `actor`, `action`, `resource_type`, `resource_id`, `start`, `end`, `limit`, and `offset` query parameters.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/audit?resource_type=proxy&resource_id=PROXY_ID"
```

## Cluster Status

The `/cluster` endpoint provides live CP/DP connection state. Available in all modes, but most useful in CP and DP modes.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/cluster
```

### CP Mode Response

Returns all currently connected Data Plane nodes and Mesh nodes. Each registry is independent: a node that subscribes to both `ConfigSync.Subscribe` (DP) and `MeshConfigSync.MeshSubscribe` (mesh) appears in both arrays with separate `connected_at` timestamps.

```json
{
  "mode": "cp",
  "connected_data_planes": 2,
  "data_planes": [
    {
      "node_id": "abc-123",
      "version": "0.9.0",
      "namespace": "ferrum",
      "status": "online",
      "connected_at": "2025-01-15T10:30:00Z",
      "last_sync_at": "2025-01-15T10:35:00Z"
    }
  ],
  "connected_mesh_nodes": 1,
  "mesh_nodes": [
    {
      "node_id": "mesh-789",
      "version": "0.9.0",
      "namespace": "ferrum",
      "status": "online",
      "connected_at": "2025-01-15T10:32:00Z",
      "last_heartbeat_at": "2025-01-15T10:34:30Z",
      "last_sync_at": "2025-01-15T10:35:00Z"
    }
  ]
}
```

- **`status`** is always `online` — disconnected DPs and mesh nodes are automatically removed from their registries when their gRPC stream drops. Mesh nodes also send lightweight `MeshSubscribe` heartbeats; the CP reaps entries that stop producing stream activity for 5 minutes.
- **`last_sync_at`** updates whenever the CP broadcasts a config update (full snapshot or delta) to that registry. DP and mesh broadcasts share the same database polling cycle, so the timestamps converge on every successful poll.
- **`last_heartbeat_at`** is mesh-only and updates whenever the CP produces a mesh stream item for that node: the initial snapshot, a config delta/full snapshot, or a heartbeat.

### DP Mode Response

Returns the connection status to the Control Plane:

```json
{
  "mode": "dp",
  "control_plane": {
    "url": "http://cp-host:50051",
    "status": "online",
    "is_primary": true,
    "connected_since": "2025-01-15T10:30:00Z",
    "last_config_received_at": "2025-01-15T10:35:00Z"
  }
}
```

- **`status`**: `online` when the gRPC stream to the CP is active, `offline` when disconnected (e.g., CP is down, DP is in backoff retry).
- **`is_primary`**: `true` when connected to the primary (first) CP URL, `false` when connected to a fallback CP (multi-CP failover).
- **`last_config_received_at`**: Timestamp of the last successfully applied config update (full snapshot or delta) from the CP. `null` if no config has been received yet on the current connection.

### Database/File Mode Response

```json
{
  "mode": "database",
  "message": "Cluster status is only available in cp or dp modes"
}
```

## Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/admin/metrics
```

Returns:
```json
{
  "mode": "database",
  "config_last_updated_at": "2025-01-15T10:30:00Z",
  "config_source_status": "online",
  "proxy_count": 5,
  "consumer_count": 10,
  "total_requests": 523401,
  "status_codes_total": {"200": 520000, "404": 2891, "429": 510},
  "requests_per_second": 150,
  "status_codes_per_second": {"200": 145, "404": 3, "429": 2},
  "metrics_window_seconds": 30
}
```

See [admin_metrics.md](admin_metrics.md) for the full metrics reference.

The unauthenticated exact `/metrics` endpoint returns Prometheus text exposition for scrapers. In mesh mode it includes `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_config_last_received_timestamp_seconds`, and `ferrum_mesh_mtls_handshake_failures_total` alongside request RED metrics. Mesh RED and certificate series include SPIFFE identity labels, so expose `/metrics` only on trusted scrape networks; in Kubernetes, put it behind a `NetworkPolicy` or a scrape-side reverse proxy when workload identity inventory is sensitive.

### Runtime Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/metrics/runtime
```

Returns one process-global JSON snapshot for host and gateway triage: process CPU and memory, file descriptors, ephemeral-port pressure, HTTP status windows, error classes, DNS outcomes, backend pool churn, TCP reset counts, bounded log counters, and overload state.

The response is cached briefly (`FERRUM_METRICS_RUNTIME_CACHE_MS`, default `1000`) to avoid amplifying sampler work under polling. Log counters count Ferrum project tracing events allowed by the output `FERRUM_LOG_LEVEL` / `RUST_LOG` filter, and the 1m/5m HTTP status windows can be disabled with `FERRUM_METRICS_STATUS_TRACKING_ENABLED=false` for maximum hot-path throughput.

## Charges

The `/charges` endpoint exposes per-consumer API usage charges tracked by the `api_chargeback` plugin. It requires the same admin JWT authentication as other sensitive admin endpoints.

```bash
# Prometheus text format (default)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/charges

# JSON format
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/charges?format=json
```

**Prometheus format** returns counter families:
- `ferrum_api_chargeable_calls_total` — HTTP call counts with labels `consumer`, `proxy_id`, `proxy_name`, `status_code` (HTTP-family proxies only)
- `ferrum_api_charges_total` — HTTP per-call monetary charges with an additional `currency` label
- `ferrum_api_stream_connections_total` — stream session counts (TCP/TCP+TLS/UDP/DTLS proxies)
- `ferrum_api_stream_connection_charges_total` — stream per-session monetary charges
- `ferrum_api_bytes_sent_total` / `ferrum_api_bytes_received_total` — bandwidth byte counters aggregated per `consumer`/`proxy_id`/`protocol_family`
- `ferrum_api_bandwidth_charges_total` — bandwidth monetary charges, labelled with `direction="sent"`/`"received"` and `protocol_family="http"`/`"stream"`

All families include a `namespace` label.

**JSON format** returns a nested breakdown:
```json
{
  "currency": "USD",
  "generated_at": "2025-01-15T10:30:00Z",
  "consumers": {
    "alice": {
      "total_charges": 1.55,
      "total_calls": 150042,
      "per_call_charges": 1.50,
      "stream_connection_charges": 0.021,
      "bandwidth_charges": 0.029,
      "proxies": {
        "proxy-abc": {
          "proxy_name": "Payments API",
          "protocol_family": "http",
          "total_charges": 1.5105,
          "total_calls": 150000,
          "by_status": {
            "200": { "calls": 145000, "charges": 1.45 },
            "201": { "calls": 5000, "charges": 0.05 }
          },
          "bandwidth": {
            "bytes_sent": 1500000,
            "bytes_received": 4500000,
            "charge_sent": 0.0015,
            "charge_received": 0.009
          }
        },
        "tcp-edge": {
          "proxy_name": "TCP Edge",
          "protocol_family": "stream",
          "total_charges": 0.0397,
          "total_calls": 42,
          "by_status": {},
          "bandwidth": {
            "bytes_sent": 95000,
            "bytes_received": 184000,
            "charge_sent": 0.0095,
            "charge_received": 0.0092
          },
          "stream": {
            "connections": 42,
            "connection_charges": 0.021
          }
        }
      }
    }
  }
}
```

**Multi-node deployments**: Each gateway node accumulates charges independently in memory. In CP/DP topologies, scrape `/charges` from every DP node with admin JWT credentials and aggregate externally. See [plugins.md](plugins.md#api_chargeback) for Prometheus scrape configuration examples.

## API Spec Management

Ferrum Edge can ingest an OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, or 3.2.x specification document and atomically provision a proxy, optional upstream, and proxy-scoped plugins as a single bundle. This is an admin-only feature; specs are stored as compressed metadata and the gateway runtime never reads them — submitting or updating a spec has no effect on in-flight requests. See [docs/api_specs.md](api_specs.md) for the full extension contract, worked examples, and curl recipes.

**Endpoints at a glance:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api-specs` | Submit new spec; create proxy + upstream + plugins |
| `GET` | `/api-specs` | List spec metadata (paginated, no content) |
| `GET` | `/api-specs/{id}` | Retrieve spec document (content negotiation + ETag) |
| `PUT` | `/api-specs/{id}` | Replace spec; recreate spec-owned resources |
| `DELETE` | `/api-specs/{id}` | Delete spec; cascade proxy + plugins + upstream |
| `GET` | `/api-specs/by-proxy/{proxy_id}` | Look up spec by proxy ID |

### `POST /api-specs`

Submit an OpenAPI or Swagger document. The spec must include a `x-ferrum-proxy` extension at the root. Optional `x-ferrum-upstream` and `x-ferrum-plugins` extensions create additional resources. All created resources are tagged with the spec's `api_spec_id`.

```bash
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @orders-api.yaml
```

Returns **201** with `{ id, proxy_id, content_hash, spec_version }` on success. The `Location` header points to the new spec. Returns **400** for parse failures, **409** if a spec already exists for the same proxy, **422** if resources fail validation, **413** if the body exceeds `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (default 25 MiB).

### `GET /api-specs`

Returns paginated spec summaries (no spec content). The list includes Tier 1 metadata fields extracted at submit time (`description`, `contact_name`, `contact_email`, `license_name`, `license_identifier`, `tags`, `server_urls`, `operation_count`). The internal `resource_hash` is excluded.

Response shape: `{ "items": [...], "limit": N, "offset": N, "next_offset": N|null, "total": N }`. The `total` field is the count of all matching rows ignoring pagination — use it to render "showing X–Y of Z" in UIs.

Supports filter and sort query parameters: `proxy_id` (exact), `spec_version` (prefix), `title_contains` (case-insensitive substring), `updated_since` (ISO-8601), `has_tag` (exact tag membership), `sort_by` (`updated_at`, `title`, `operation_count`, `created_at`; default `updated_at`), and `order` (`asc`/`desc`; default `desc`). Unknown `sort_by` or `order` values return 400.

```bash
curl "https://gateway/api-specs?limit=20&offset=0" \
  -H "Authorization: Bearer $JWT"

curl "https://gateway/api-specs?has_tag=public&spec_version=3.1&sort_by=title&order=asc" \
  -H "Authorization: Bearer $JWT"
```

### `GET /api-specs/{id}` and `GET /api-specs/by-proxy/{proxy_id}`

Return the raw spec document. Supports `Accept` header content negotiation (`application/json` ↔ `application/yaml`) and conditional GET via `If-None-Match` using the `ETag` (SHA-256 hex content hash). Returns **304 Not Modified** when the ETag matches.

```bash
# Retrieve as YAML (regardless of stored format)
curl https://gateway/api-specs/SPEC_ID \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/yaml"

# Conditional GET
curl https://gateway/api-specs/SPEC_ID \
  -H "Authorization: Bearer $JWT" \
  -H "If-None-Match: \"abc123...\""

# Look up by proxy ID
curl https://gateway/api-specs/by-proxy/orders-proxy \
  -H "Authorization: Bearer $JWT"
```

### `PUT /api-specs/{id}`

Replaces the spec and recreates all **spec-owned** resources (those with `api_spec_id` matching this spec). Resources added manually to the same proxy via direct admin endpoints (`api_spec_id = null`) are not touched. `created_at` is preserved; `updated_at` and `content_hash` reflect the new document.

**Idempotent PUT**: if the submitted bundle produces the same resource hash as the stored one (e.g. only `info.description` changed), the proxy/upstream/plugin rows are left untouched — their `updated_at` does not advance and no polling or DP broadcast fires. The `api_specs` row is always updated. This makes PUT safe to call on every CI/CD deploy cycle.

### `DELETE /api-specs/{id}`

Deletes the spec and cascades:

- Spec-owned **proxy** is deleted → FK cascade removes its plugins (including any added manually after import).
- Spec-owned **upstream** is deleted if present. Upstreams without `api_spec_id` survive.
- Calling `DELETE /proxies/{id}` directly also removes the spec row via the `ON DELETE CASCADE` FK constraint.

### Cascade and ownership summary

| Operation | Spec-owned resources | Hand-added resources |
|---|---|---|
| `POST /api-specs` | Created; tagged with `api_spec_id` | — |
| `PUT /api-specs/{id}` | Replaced (deleted + re-inserted) | Survive unchanged |
| `DELETE /api-specs/{id}` | Proxy + plugins deleted; spec-owned upstream deleted | Non-spec upstreams survive |
| `DELETE /proxies/{id}` | Spec row deleted by FK cascade | — |

### Mode behavior

| Mode | Write (`POST`/`PUT`/`DELETE`) | Read (`GET`) |
|---|---|---|
| `database` | Supported | Supported |
| `cp` | Supported — resources distributed to DPs via gRPC; spec stays on CP | Supported |
| `dp` | 503 (no database) | 503 (no database) |
| `file` | 403 (read-only) | 503 (no database) |

For the full extension contract, supported versions, validation rules, and worked examples, see [docs/api_specs.md](api_specs.md).

## Backend Capability Registry

Ferrum Edge classifies each HTTP-family backend target's protocol support (HTTP/1.1, HTTP/2 over TLS, HTTP/3, gRPC-over-TLS, h2c) at startup and on a periodic background refresh (`FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS`, default 24h). The hot path consults this registry to decide whether to route plain HTTPS traffic through the native H3 pool, the direct HTTP/2 pool, or the generic reqwest path without per-request probing. See [CLAUDE.md — Backend Capability Registry](../CLAUDE.md) and [docs/http3.md](http3.md) for the underlying design.

Two JWT-authenticated endpoints let operators inspect and force-refresh the registry at runtime.

### `GET /backend-capabilities`

Returns every cached entry keyed by the deduplicated backend-target identity the registry uses internally (scheme + host + port + `dns_override` + CA + mTLS cert + mTLS key + verify flag, plus HBONE sidecar port for targets tagged `mesh.hbone=true`).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backend-capabilities
```

Response:

```json
{
  "entries": [
    {
      "key": "https|api.example.internal|443||/etc/ferrum/ca.pem|||1",
      "plain_http": {
        "h1": "supported",
        "h2_tls": "supported",
        "h3": "supported"
      },
      "grpc_transport": {
        "h2_tls": "supported",
        "h2c": "unknown"
      },
      "hbone": "unsupported",
      "last_probe_at_unix_secs": 1714003200,
      "last_probe_error": null
    },
    {
      "key": "https|legacy.example.internal|443||||0",
      "plain_http": {
        "h1": "supported",
        "h2_tls": "unsupported",
        "h3": "unsupported"
      },
      "grpc_transport": {
        "h2_tls": "unsupported",
        "h2c": "unknown"
      },
      "hbone": "unknown",
      "last_probe_at_unix_secs": 1714003200,
      "last_probe_error": "H2/TLS downgraded after ALPN-negotiated HTTP/1.1 on request path"
    }
  ]
}
```

Field semantics:

- **`key`** — stable identity used by the router to look up the entry. Safe to match across responses to detect churn.
- **`plain_http.{h1, h2_tls, h3}`** — whether the native dispatch path for plain HTTP traffic may use HTTP/1.1 (always true for reachable HTTPS backends), the direct HTTP/2 pool (`h2_tls`), or the native HTTP/3 pool (`h3`). Values: `"supported"`, `"unsupported"`, or `"unknown"` (not yet probed). `"unknown"` and `"unsupported"` both cause the hot path to fall back through the reqwest HTTP/1.1+HTTP/2 client.
- **`grpc_transport.{h2_tls, h2c}`** — same semantics for gRPC. `h2c` is native gRPC over plaintext HTTP/2 prior-knowledge; rarely deployed.
- **`hbone`** — gateway-to-mesh HBONE support for upstream targets tagged `mesh.hbone=true`. `"supported"` means the gateway can open HTTP/2 CONNECT over SPIFFE mTLS to the sidecar port, `"unsupported"` skips the tunnel, and `"unknown"` is used when the target is not HBONE-tagged, the gateway has no SVID, or the probe has not completed.
- **`last_probe_at_unix_secs`** — epoch seconds of the most recent probe or live-traffic downgrade. Updates on every refresh AND on each live `mark_h2_tls_unsupported` / `mark_h3_unsupported` / `mark_hbone_unsupported` invocation.
- **`last_probe_error`** — human-readable error string set when the last classification update came from a live-traffic downgrade (ALPN mismatch, QUIC failure, HBONE capability-establishment failure) or from a genuine probe failure (TLS config error, connection error on an HTTPS backend). `null` when the most recent update classified the backend cleanly. Expected-unsupported outcomes (h2c on plaintext HTTP, H3 on most HTTPS backends, untagged HBONE, per-request HBONE CONNECT rejection) do NOT populate this field — only genuine errors / live downgrades do.

Use cases:

- **Routing-decision debugging**: "Why did this H3-capable backend just fall back to reqwest?" → check `last_probe_error`.
- **Protocol-rollout monitoring**: poll after enabling H3 on a backend fleet to verify every target flipped to `h3: "supported"`.
- **Stale-cache auditing**: verify `last_probe_at_unix_secs` is within your expected refresh interval.

### `POST /backend-capabilities/refresh`

Force an immediate, synchronous classification pass over every HTTP-family backend in the current config. Blocks until every probe completes (bounded by `FERRUM_POOL_WARMUP_CONCURRENCY` parallelism + per-probe timeout).

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9000/backend-capabilities/refresh
```

Response:

```json
{
  "status": "refreshed"
}
```

Use after:

- Deliberately toggling a backend's H3 / H2 support without waiting for the 24h timer.
- Rotating backend TLS material that the previous probe didn't see.
- Manually resolving an incident where the cache is known stale (e.g., backend came back online after a QUIC failure downgraded `h3` or an HBONE capability-establishment failure downgraded `hbone` to `unsupported`).

Because this endpoint is **synchronous**, callers can assert on the post-refresh state by immediately issuing `GET /backend-capabilities` afterward. Request body is ignored; no fields are required.

### No payload data exposed

The registry stores only protocol classifications and probe timestamps — never request bodies, credentials, TLS keys, or anything resembling user payload. Both endpoints are safe to expose in any environment where admin JWTs are issued.

### Related environment variables

- `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` — periodic refresh cadence (default `86400`).
- `FERRUM_POOL_WARMUP_ENABLED` — when `true`, the initial classification runs synchronously during startup; when `false`, the gateway issues the first refresh in the background and reports ready before it completes (DP mode always gates readiness on first-refresh completion regardless).
- `FERRUM_POOL_WARMUP_CONCURRENCY` — parallelism cap for both startup and refresh probe passes.

## Node-Waypoint Identities (mesh `NodeWaypoint` topology)

The node-waypoint topology accepts traffic on behalf of many pods on the same node. Each pod's identity is enrolled into a per-resolver index keyed by Kubernetes pod UID; the eBPF data path records the socket cookie and original destination per outbound connection. `GET /node-waypoint/identities` exposes the live snapshot of that index so operators can answer "which pods is this waypoint actually serving?" without scraping eBPF maps.

The endpoint returns `404 Not Found` when the node-waypoint resolver is not installed on `ProxyState` — including all non-mesh modes and mesh modes other than `NodeWaypoint` topology. This avoids surfacing an empty stub list that could be mistaken for "no pods enrolled yet" on a sidecar/ambient/east-west/egress-gateway DP.

### `GET /node-waypoint/identities`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/node-waypoint/identities
```

Response:

```json
{
  "identity_count": 2,
  "cookies": {
    "orig_dst4": 17,
    "orig_dst6": 0
  },
  "identities": [
    {
      "pod_uid": "11111111-1111-1111-1111-111111111111",
      "spiffe_id": "spiffe://cluster.local/ns/default/sa/api",
      "workload_spiffe_hash": 12345678901234567890,
      "orig_dst4_cookies": 5,
      "orig_dst6_cookies": 0,
      "has_policy_scope": true
    },
    {
      "pod_uid": "22222222-2222-2222-2222-222222222222",
      "spiffe_id": "spiffe://cluster.local/ns/default/sa/billing",
      "workload_spiffe_hash": 9876543210987654321,
      "orig_dst4_cookies": 12,
      "orig_dst6_cookies": 0,
      "has_policy_scope": false
    }
  ]
}
```

Field semantics:

- `pod_uid` — hyphenated lowercase UUID matching the Kubernetes `metadata.uid` operators see in `kubectl get pod -o yaml`.
- `spiffe_id` — SPIFFE ID assigned to that pod's service account (`spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}` by convention).
- `workload_spiffe_hash` — first 8 bytes of SHA-256 over the SPIFFE ID, big-endian as `u64`. Matches the value the eBPF `OrigDst{4,6}` map carries for cross-correlation with `node_agent` telemetry.
- `orig_dst4_cookies` / `orig_dst6_cookies` — number of socket cookies currently mapped to this pod via the IPv4 / IPv6 original-destination map. `0` means the pod is enrolled but has no in-flight outbound connection on that family.
- `has_policy_scope` — `true` iff a per-pod `PolicyScopeCache` is installed for this pod from the accepted mesh slice's workload metadata. When `false`, mesh-authz retains mesh-wide policies only for this pod; namespace-scoped and selector-scoped policies are withheld until the resolver has the pod's workload scope.

`identities` is sorted by `pod_uid` so polling produces stable output. Entries with zero cookies are kept — enrolled-but-idle pods are operationally interesting (the cookie count answers "is this pod taking traffic?").

The endpoint is cold-path: it iterates the unified cookie-record map and identity map, then reads the policy-scope snapshot. Don't poll faster than a few times per second on a busy node.

## Service-Waypoint Services (mesh `ServiceWaypoint` topology)

The service-waypoint topology accepts HBONE traffic for services bound to one GAMMA waypoint. `GET /service-waypoint/services` exposes the currently installed slice projection so operators can answer "which services is this waypoint actually serving?" without inspecting raw Gateway API resources.

The endpoint returns `404 Not Found` when service-waypoint topology is not active, when no mesh slice has been installed yet, or when the installed slice has no `waypoint_name`. This avoids surfacing an empty stub list on unrelated sidecar/ambient/node-waypoint/east-west/egress DPs.

### `GET /service-waypoint/services`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/service-waypoint/services
```

Response:

```json
{
  "waypoint_name": "api-waypoint",
  "namespace": "default",
  "service_count": 2,
  "services": [
    {
      "namespace": "default",
      "name": "reviews",
      "ports": [8080],
      "workload_count": 3
    },
    {
      "namespace": "default",
      "name": "ratings",
      "ports": [8081],
      "workload_count": 1
    }
  ]
}
```

Field semantics:

- `waypoint_name` — the `FERRUM_MESH_WAYPOINT_NAME` / native `MeshSubscribe` binding name used to build this slice.
- `namespace` — the namespace of the installed mesh slice.
- `service_count` — number of services admitted into the slice for this waypoint.
- `services[].ports` — service ports from the admitted `MeshService`; port protocol metadata is intentionally omitted from this compact operability view.
- `services[].workload_count` — number of workload SPIFFE references behind that service in the installed slice.

`services` are returned in slice order. The payload exposes service names, namespaces, ports, and workload counts, but no request bodies, credentials, or backend TLS material.

## Mesh Service Graph (mesh mode)

`GET /mesh/service-graph` returns the live HTTP-family mesh service graph aggregated from the auto-injected `workload_metrics` plugin. It is JWT-authenticated and contains only identity, workload, protocol, and RED-counter metadata; request bodies, headers, and credentials are never stored.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/mesh/service-graph
```

Response:

```json
{
  "generated_at": "2026-05-17T16:30:00Z",
  "generated_at_unix_ms": 1779035400000,
  "edge_count": 1,
  "edges": [
    {
      "source_principal": "spiffe://cluster.local/ns/default/sa/frontend",
      "source_workload": "frontend",
      "source_namespace": "default",
      "source_app": "frontend",
      "source_service": "frontend",
      "destination_principal": "spiffe://cluster.local/ns/default/sa/reviews",
      "destination_workload": "reviews",
      "destination_namespace": "default",
      "destination_app": "reviews",
      "destination_service": "reviews",
      "request_protocol": "http",
      "connection_security_policy": "mutual_tls",
      "requests_total": 1250,
      "errors_total": 3,
      "duration_ms_total": 8420.5,
      "duration_ms_avg": 6.7364,
      "last_seen": "2026-05-17T16:29:58Z",
      "last_seen_unix_ms": 1779035398000
    }
  ]
}
```

The graph is node-local. In CP/DP or multi-replica mesh deployments, query each data plane and aggregate externally. The admin read path serves an `ArcSwap` snapshot, so frequent polling does not iterate live request counters.

## Mesh Egress Scope (mesh mode)

Two JWT-authenticated endpoints expose the live Sidecar egress scope for operability and pre-enforcement validation. They are mesh-only: requests return `404 Not Found` when no mesh slice has been installed (for example, during DP startup before the first CP push or when running on a non-mesh mode).

### `GET /mesh/egress-scope`

Returns the current workload's resolved egress scope: namespace, admitted services, admitted service-entries, admitted destination-rules, the deduplicated `known_destinations` host list used by the outbound registry, dry-run status, and admit/deny service and DestinationRule counts.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/mesh/egress-scope
```

Response (truncated):

```json
{
  "namespace": "alpha",
  "scope": {
    "sidecar_enforced": false,
    "dry_run": true,
    "sidecar_applied": false,
    "sidecar_admitted_services": 1,
    "sidecar_denied_services": 1,
    "sidecar_admitted_destination_rules": 1,
    "sidecar_denied_destination_rules": 0,
    "services": [
      {
        "namespace": "alpha",
        "name": "reviews",
        "hosts": ["reviews.alpha.svc.cluster.local"],
        "ports": [8080]
      }
    ],
    "destination_rules": [
      {"namespace": "alpha", "name": "reviews", "hosts": ["reviews.alpha.svc.cluster.local"], "ports": []}
    ],
    "known_destinations": ["reviews.alpha.svc.cluster.local:8080"]
  },
  "health": {
    "sidecar_admitted_services": 1,
    "sidecar_denied_services": 1
  }
}
```

**Disclosure surface**: the payload reveals the mesh topology shape the current workload can reach — service names, namespaces, hosts, ports, FQDN aliases. This is not secret traffic data (no bodies, headers, or credentials), but operators wiring this into long-running scrapers should still scope JWT issuance accordingly.

Returns `503 Service Unavailable` when proxy state is not yet available, `404 Not Found` when no active mesh egress scope has been installed.

### `POST /mesh/egress-scope/test`

Dry-runs a candidate destination against the current scope. Accepts a JSON object with `host` (required) and `port` (optional). Returns whether the destination is admitted by the resolved scope. Never mutates slice state.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"reviews.alpha.svc.cluster.local","port":8080}' \
  http://localhost:9000/mesh/egress-scope/test
```

Response:

```json
{
  "allowed": true,
  "decision": "admit",
  "host": "reviews.alpha.svc.cluster.local",
  "port": 8080,
  "dry_run": true
}
```

The handler memoises the resolved `OutboundRegistry` against the installed snapshot, so repeated calls do not re-parse `known_destinations` on every request.

Returns `503` when proxy state is unavailable, `404` when no active mesh egress scope, `400` when the body is not valid JSON / `host` is missing or empty / `port` is `0`.

### Related environment variables

- `FERRUM_MESH_SIDECAR_ENFORCED` — gates the slice-narrowing pass (default `false`).
- `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` — computes the scope and exposes it through these endpoints while leaving the slice unenforced.
