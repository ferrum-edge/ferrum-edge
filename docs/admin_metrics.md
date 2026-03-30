# Admin API: Runtime Metrics

The Ferrum Edge Admin API exposes a comprehensive runtime metrics endpoint that provides a real-time snapshot of the gateway's internal state. This endpoint is designed for building dashboards, monitoring integrations, and operational visibility.

## Overview

| Endpoint | Method | Auth | Cache | Description |
|----------|--------|------|-------|-------------|
| `/admin/metrics` | GET | JWT required | 5-second TTL | Comprehensive runtime metrics (JSON) |
| `/metrics` | GET | None | None | Prometheus exposition format (plugin-based) |
| `/health` | GET | None | None | Health check (DB connectivity, config status) |

### Metrics vs Prometheus vs Health

- **`/admin/metrics`** — Rich JSON with connection pools, circuit breakers, health checks, cache stats, load balancer state, consumer index breakdown, and rate limiter counters. Ideal for custom dashboards.
- **`/metrics`** — Prometheus text format with per-proxy request counters and latency histograms. Requires the `prometheus_metrics` plugin to be enabled. Best for Prometheus/Grafana scraping.
- **`/health`** — Lightweight health probe for load balancers and orchestrators (Kubernetes liveness/readiness).

## Endpoint: `GET /admin/metrics`

### Authentication

Requires a valid JWT in the `Authorization: Bearer <token>` header. This endpoint is behind the same JWT auth gate as all other admin CRUD operations.

### Caching

The response is cached for **5 seconds** to avoid performance overhead from frequent polling. The `X-Cache` response header indicates whether the response was served from cache:

- `X-Cache: hit` — Served from the 5-second cache
- `X-Cache: miss` — Freshly computed (first request or cache expired)

This means polling more frequently than every 5 seconds will return the same data. For dashboards, a 5–10 second refresh interval is recommended.

### Example Request

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/admin/metrics | jq .
```

### Response Format

```json
{
  "gateway": {
    "mode": "database",
    "uptime_seconds": 86472,
    "requests_per_second_current": 1342,
    "status_codes_last_second": {
      "200": 1105,
      "201": 42,
      "204": 18,
      "301": 15,
      "400": 23,
      "401": 47,
      "403": 12,
      "404": 38,
      "429": 31,
      "500": 6,
      "502": 3,
      "503": 2
    },
    "config_last_updated_at": "2026-03-29T14:23:07.482Z",
    "config_source_status": "online",
    "proxy_count": 47,
    "consumer_count": 215,
    "upstream_count": 12,
    "plugin_config_count": 83
  },
  "connection_pools": {
    "http": {
      "total_pools": 23,
      "max_idle_per_host": 32,
      "idle_timeout_seconds": 90,
      "entries_per_host": {
        "api-users.internal:8080:false": 1,
        "api-users.internal:8080:true": 1,
        "api-orders.internal:8080:true": 1,
        "api-payments.internal:443:true": 1,
        "auth-service.internal:443:true": 1,
        "search-cluster.internal:9200:true": 1
      }
    },
    "grpc": {
      "total_connections": 6
    },
    "http2": {
      "total_connections": 14
    },
    "http3": {
      "total_connections": 0
    }
  },
  "circuit_breakers": [
    {
      "proxy_id": "proxy-payments-v2",
      "state": "closed",
      "failure_count": 0,
      "success_count": 0
    },
    {
      "proxy_id": "proxy-legacy-billing",
      "target": "10.0.2.1:8080",
      "state": "open",
      "failure_count": 5,
      "success_count": 0
    },
    {
      "proxy_id": "proxy-legacy-billing",
      "target": "10.0.2.2:8080",
      "state": "closed",
      "failure_count": 0,
      "success_count": 0
    },
    {
      "proxy_id": "proxy-search",
      "state": "half_open",
      "failure_count": 3,
      "success_count": 1
    }
  ],
  "health_check": {
    "unhealthy_target_count": 2,
    "unhealthy_targets": [
      {
        "target": "10.0.3.12:8080",
        "since_epoch_ms": 1711720800000
      },
      {
        "target": "10.0.5.7:8080",
        "since_epoch_ms": 1711720920000
      }
    ]
  },
  "load_balancers": {
    "active_connections": {
      "upstream-users": {
        "10.0.1.1:8080": 24,
        "10.0.1.2:8080": 19,
        "10.0.1.3:8080": 22
      },
      "upstream-orders": {
        "10.0.2.1:8080": 8,
        "10.0.2.2:8080": 11
      }
    }
  },
  "caches": {
    "router": {
      "prefix_cache_entries": 312,
      "regex_cache_entries": 47,
      "prefix_eviction_count": 0,
      "regex_eviction_count": 0,
      "max_cache_entries": 10000
    },
    "dns": {
      "cache_entries": 19
    }
  },
  "consumer_index": {
    "total_consumers": 215,
    "key_auth_credentials": 142,
    "basic_auth_credentials": 38,
    "mtls_credentials": 9
  },
  "rate_limiting": {
    "tracked_key_count": 4217
  }
}
```

## Field Reference

### `gateway`

Top-level gateway info and throughput counters.

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | Operating mode: `database`, `file`, `cp`, or `dp` |
| `uptime_seconds` | integer | Seconds since the gateway process started |
| `requests_per_second_current` | integer | Requests processed in the most recent 1-second window |
| `status_codes_last_second` | object | Map of HTTP status code (string key) to count. Only codes seen in the window appear |
| `config_last_updated_at` | string (RFC 3339) | Timestamp of the last successful config load/reload. `null` in CP mode without proxy state |
| `config_source_status` | string | `"online"` when a database is configured and reachable, `"n/a"` for file mode or when no database is used |
| `proxy_count` | integer | Number of proxy routes in the active config |
| `consumer_count` | integer | Number of consumers in the active config |
| `upstream_count` | integer | Number of upstreams (load-balanced target groups) |
| `plugin_config_count` | integer | Number of plugin configurations |

### `connection_pools`

Connection pool sizes for all four protocol pools. Each pool reuses connections to avoid TCP/TLS handshake overhead per request.

| Pool | Description |
|------|-------------|
| `http` | HTTP/1.1 connection pool (reqwest-based). Handles both plaintext HTTP and HTTPS backends. The `entries_per_host` map shows pool keys in `host:port:tls` format |
| `grpc` | gRPC HTTP/2 connection pool with trailer support. Uses sharded connections per backend for concurrency |
| `http2` | HTTP/2 connection pool for HTTPS backends with proper stream multiplexing |
| `http3` | HTTP/3 (QUIC) connection pool. Distributes across multiple QUIC connections per backend |

The `http` pool has additional detail fields:

| Field | Description |
|-------|-------------|
| `total_pools` | Distinct backend pool entries |
| `max_idle_per_host` | Max idle connections kept per host (`FERRUM_POOL_MAX_IDLE_PER_HOST`) |
| `idle_timeout_seconds` | Seconds before idle connections are evicted |
| `entries_per_host` | Map of pool key to connection count |

### `circuit_breakers`

Array of circuit breaker states. For proxies with upstream targets, each target has its own independent breaker (per-target). For direct-backend proxies (no upstream), the breaker is per-proxy. Only proxies that have a `circuit_breaker` config and have been accessed appear in this list.

| Field | Type | Description |
|-------|------|-------------|
| `proxy_id` | string | ID of the proxy this circuit breaker protects |
| `target` | string | *(optional)* Upstream target `host:port` this breaker is scoped to. Absent for direct-backend proxies |
| `state` | string | Current state: `closed` (normal), `open` (rejecting with 503), or `half_open` (probing for recovery) |
| `failure_count` | integer | Consecutive failures in the current state. In `closed`, this increments toward the failure threshold. In `open`, it reflects the count that triggered the opening |
| `success_count` | integer | Consecutive successes during `half_open`. When this reaches `success_threshold`, the circuit closes and the proxy recovers |

**Reading circuit breaker state:**

- **`closed` with `failure_count: 0`** — Healthy, no recent failures
- **`closed` with `failure_count: 3`** — Working but accumulating failures (watch this)
- **`open`** — Backend is failing. Requests are short-circuited with 503 to prevent cascading failures. Will transition to `half_open` after `timeout_seconds`
- **`half_open` with `success_count: 1`** — Recovery in progress. Probe requests are being sent to test the backend. Once `success_threshold` successes are seen, the circuit closes

### `health_check`

Health check state showing which upstream targets are currently marked unhealthy and excluded from load balancing.

| Field | Type | Description |
|-------|------|-------------|
| `unhealthy_target_count` | integer | Number of targets currently unhealthy |
| `unhealthy_targets[].target` | string | Target in `host:port` format |
| `unhealthy_targets[].since_epoch_ms` | integer | Unix epoch milliseconds when the target was marked unhealthy |

Targets are marked unhealthy by either **passive** health checks (monitoring proxied request failures) or **active** health checks (periodic HTTP/TCP/UDP probes). Once healthy again, they are removed from this list and re-included in load balancing.

### `load_balancers`

Active connection counts per upstream target. Only useful when using the `least_connections` load balancing algorithm, but tracked for all algorithms.

| Field | Type | Description |
|-------|------|-------------|
| `active_connections` | object | Nested map: `upstream_id` → `{ "host:port": count }`. Only targets with `count > 0` are included. Empty upstreams (no active requests) are omitted |

**What to look for:**

- Even distribution across targets indicates healthy load balancing
- One target with significantly more connections may indicate a hot target or slow backend (requests pile up)
- A target appearing here but also in `unhealthy_targets` means it was recently marked unhealthy — existing connections are draining

### `caches`

#### `caches.router`

The router cache stores `(host, path) → proxy` lookups in bounded DashMaps for O(1) repeated hits. Prefix routes and regex routes use separate cache partitions to prevent high-cardinality regex paths from evicting frequently-hit prefix entries.

| Field | Type | Description |
|-------|------|-------------|
| `prefix_cache_entries` | integer | Current entries in the prefix route cache |
| `regex_cache_entries` | integer | Current entries in the regex route cache |
| `prefix_eviction_count` | integer | Total eviction sweeps for the prefix cache since startup |
| `regex_eviction_count` | integer | Total eviction sweeps for the regex cache since startup |
| `max_cache_entries` | integer | Maximum entries per partition before random-sample eviction triggers (default 10,000) |

**What to look for:**

- `prefix_cache_entries` near `max_cache_entries` with rising `prefix_eviction_count` indicates the cache is under pressure — many unique paths are being requested. This is normal for APIs with path parameters but may indicate scanner traffic if unexpected
- `regex_cache_entries` growing rapidly suggests high-cardinality regex routes (e.g., UUID path segments)

#### `caches.dns`

| Field | Type | Description |
|-------|------|-------------|
| `cache_entries` | integer | Number of hostname entries currently cached. Includes both fresh and stale-while-revalidate entries |

### `consumer_index`

Pre-built hash map indexes for O(1) credential lookup during authentication. The counts show how many credentials are indexed per authentication type.

| Field | Type | Description |
|-------|------|-------------|
| `total_consumers` | integer | Total consumers loaded |
| `key_auth_credentials` | integer | API key credentials indexed (for `key_auth` plugin) |
| `basic_auth_credentials` | integer | Username credentials indexed (for `basic_auth` plugin) |
| `mtls_credentials` | integer | mTLS identity credentials indexed (for `mtls_auth` plugin) |

Note: JWT and OAuth2 consumers are looked up via the identity index (by username, ID, or custom_id) rather than a dedicated credential index, so they don't appear as a separate count here.

### `rate_limiting`

| Field | Type | Description |
|-------|------|-------------|
| `tracked_key_count` | integer | Total rate-limit keys currently tracked across all `rate_limiting` plugin instances. Each key represents a unique client (by IP or consumer identity) with an active rate-limit window. Bounded to 100K entries per plugin instance with automatic stale entry eviction |

**What to look for:**

- A `tracked_key_count` approaching 100K may indicate a DDoS or scanner generating many unique source IPs
- Under normal traffic, this count should correlate with the number of unique clients in your active window duration

## Dashboard Tips

### Key Indicators to Monitor

1. **`gateway.requests_per_second_current`** — Primary throughput gauge. Sudden drops may indicate upstream failures or config issues.

2. **`gateway.status_codes_last_second`** — Watch the ratio of 5xx to 2xx. A spike in 429s means rate limiting is actively protecting your backends. A spike in 503s combined with open circuit breakers indicates a backend outage.

3. **`circuit_breakers[].state`** — Any circuit breaker in `open` state is actively rejecting traffic. Alert on this.

4. **`health_check.unhealthy_target_count`** — Alert when this rises above zero. Cross-reference with `unhealthy_targets` to identify which backends are down.

5. **`connection_pools.http.total_pools`** — Should be stable. Rapid growth may indicate pool key fragmentation or misconfigured backends.

6. **`caches.router.prefix_eviction_count`** — Should stay low. Rapid increase indicates cache thrashing from high-cardinality traffic.

### Polling Interval

The endpoint caches responses for 5 seconds, so polling faster than every 5 seconds wastes bandwidth without gaining fresher data. A **10-second interval** is a good default for dashboards.

### CP Mode

In Control Plane (`cp`) mode, the gateway has no proxy state (it only manages config and distributes it to Data Planes). The response will return zero values for all runtime fields while still reporting the gateway mode and config counts.
