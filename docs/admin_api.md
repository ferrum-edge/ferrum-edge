# Admin API Reference

The Admin API provides full CRUD operations for managing Ferrum Edge configuration at runtime. It is available in **Database** and **Control Plane** modes (read/write) and **Data Plane** mode (read-only).

See also:
- [admin_read_only_mode.md](admin_read_only_mode.md) — Read-only mode configuration
- [admin_backup_restore.md](admin_backup_restore.md) — Backup and restore details
- [admin_batch_api.md](admin_batch_api.md) — Batch operations
- [admin_metrics.md](admin_metrics.md) — Metrics endpoint details
- [OpenAPI specification](../openapi.yaml) — Full API schema

## Authentication

All endpoints (except `/health`, `/status`, `/overload`, `/metrics`, and `/charges`) require a valid HS256 JWT in the `Authorization: Bearer <token>` header, verified against `FERRUM_ADMIN_JWT_SECRET` (must be at least 32 characters).

Generate a token:
```bash
# Using any JWT library; payload can be minimal
# Example using Node.js jsonwebtoken:
node -e "console.log(require('jsonwebtoken').sign({sub:'admin'}, 'my-super-secret-jwt-key'))"
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
    "config": {"limit_by": "ip", "requests_per_minute": 60},
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

## Cluster Status

The `/cluster` endpoint provides live CP/DP connection state. Available in all modes, but most useful in CP and DP modes.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/cluster
```

### CP Mode Response

Returns all connected Data Plane nodes:

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
  ]
}
```

- **`status`** is always `online` — disconnected DPs are automatically removed from the registry when their gRPC stream drops.
- **`last_sync_at`** updates whenever the CP broadcasts a config update (full snapshot or delta) to connected DPs.

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

## Charges

The `/charges` endpoint exposes per-consumer API usage charges tracked by the `api_chargeback` plugin. It is unauthenticated (like `/metrics` and `/health`) to allow Prometheus scraping without credentials.

```bash
# Prometheus text format (default)
curl http://localhost:9000/charges

# JSON format
curl http://localhost:9000/charges?format=json
```

**Prometheus format** returns two counter families:
- `ferrum_api_chargeable_calls_total` — call counts with labels `consumer`, `proxy_id`, `proxy_name`, `status_code`
- `ferrum_api_charges_total` — monetary charges with an additional `currency` label

**JSON format** returns a nested breakdown:
```json
{
  "currency": "USD",
  "generated_at": "2025-01-15T10:30:00Z",
  "consumers": {
    "alice": {
      "total_charges": 1.50,
      "total_calls": 150000,
      "proxies": {
        "proxy-abc": {
          "proxy_name": "Payments API",
          "total_charges": 1.50,
          "total_calls": 150000,
          "by_status": {
            "200": { "calls": 145000, "charges": 1.45 },
            "201": { "calls": 5000, "charges": 0.05 }
          }
        }
      }
    }
  }
}
```

**Multi-node deployments**: Each gateway node accumulates charges independently in memory. In CP/DP topologies, scrape `/charges` from every DP node and aggregate externally. See [plugins.md](plugins.md#api_chargeback) for Prometheus scrape configuration examples.

## Backend Capability Registry

Ferrum Edge classifies each HTTP-family backend target's protocol support (HTTP/1.1, HTTP/2 over TLS, HTTP/3, gRPC-over-TLS, h2c) at startup and on a periodic background refresh (`FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS`, default 24h). The hot path consults this registry to decide whether to route plain HTTPS traffic through the native H3 pool, the direct HTTP/2 pool, or the generic reqwest path without per-request probing. See [CLAUDE.md — Backend Capability Registry](../CLAUDE.md) and [docs/http3.md](http3.md) for the underlying design.

Two JWT-authenticated endpoints let operators inspect and force-refresh the registry at runtime.

### `GET /backend-capabilities`

Returns every cached entry keyed by the deduplicated backend-target identity the registry uses internally (scheme + host + port + `dns_override` + CA + mTLS cert + mTLS key + verify flag).

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
- **`last_probe_at_unix_secs`** — epoch seconds of the most recent probe or live-traffic downgrade. Updates on every refresh AND on each live `mark_h2_tls_unsupported` / `mark_h3_unsupported` invocation.
- **`last_probe_error`** — human-readable error string set when the last classification update came from a live-traffic downgrade (ALPN mismatch, QUIC failure) or from a genuine probe failure (TLS config error, connection error on an HTTPS backend). `null` when the most recent update classified the backend cleanly. Expected-unsupported outcomes (h2c on plaintext HTTP, H3 on most HTTPS backends) do NOT populate this field — only genuine errors / live downgrades do.

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
- Manually resolving an incident where the cache is known stale (e.g., backend came back online after a QUIC failure downgraded `h3` to `unsupported`).

Because this endpoint is **synchronous**, callers can assert on the post-refresh state by immediately issuing `GET /backend-capabilities` afterward. Request body is ignored; no fields are required.

### No payload data exposed

The registry stores only protocol classifications and probe timestamps — never request bodies, credentials, TLS keys, or anything resembling user payload. Both endpoints are safe to expose in any environment where admin JWTs are issued.

### Related environment variables

- `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` — periodic refresh cadence (default `86400`).
- `FERRUM_POOL_WARMUP_ENABLED` — when `true`, the initial classification runs synchronously during startup; when `false`, the gateway issues the first refresh in the background and reports ready before it completes (DP mode always gates readiness on first-refresh completion regardless).
- `FERRUM_POOL_WARMUP_CONCURRENCY` — parallelism cap for both startup and refresh probe passes.
