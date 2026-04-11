# Cache Management

Ferrum Edge uses several in-memory caches to achieve lock-free, zero-allocation request processing. All caches are bounded to prevent unbounded memory growth under adversarial or high-cardinality traffic patterns.

## Table of Contents

- [Overview](#overview)
- [Gateway Core Caches](#gateway-core-caches)
  - [Router Cache](#router-cache)
  - [DNS Cache](#dns-cache)
  - [Status Code Counters](#status-code-counters)
  - [Per-IP Request Counters](#per-ip-request-counters)
  - [Circuit Breaker Cache](#circuit-breaker-cache)
  - [Health Check State](#health-check-state)
- [Plugin Caches](#plugin-caches)
  - [Rate Limiting](#rate-limiting)
  - [AI Rate Limiter](#ai-rate-limiter)
  - [WebSocket Rate Limiting](#websocket-rate-limiting)
  - [UDP Rate Limiting](#udp-rate-limiting)
  - [GraphQL Rate Limiting](#graphql-rate-limiting)
  - [gRPC Method Router Rate Limiting](#grpc-method-router-rate-limiting)
  - [Response Caching](#response-caching)
  - [AI Semantic Cache](#ai-semantic-cache)
  - [Request Deduplication](#request-deduplication)
  - [SOAP WS-Security Nonce Cache](#soap-ws-security-nonce-cache)
  - [LDAP Auth Cache](#ldap-auth-cache)
  - [JWKS Cache](#jwks-cache)
  - [TCP Connection Throttle](#tcp-connection-throttle)
  - [API Chargeback](#api-chargeback)
  - [Prometheus Metrics](#prometheus-metrics)
- [Environment Variable Summary](#environment-variable-summary)
- [Plugin Config Field Summary](#plugin-config-field-summary)

## Overview

Every in-memory cache in the gateway has at least one of the following protections:

1. **Hard cap** -- a maximum entry count that rejects or evicts entries when reached.
2. **TTL-based expiration** -- entries expire after a configured duration.
3. **Periodic cleanup** -- a background task or piggyback sweep removes stale entries.
4. **Config-reload pruning** -- entries for removed proxies/upstreams/targets are pruned when the gateway reloads configuration.

Caches are divided into two categories: **gateway core caches** (controlled by `FERRUM_*` environment variables) and **plugin caches** (controlled by per-plugin JSON config fields).

## Gateway Core Caches

### Router Cache

**What it stores:** Resolved `(host, path) -> proxy` lookup results, including negative lookups (no route matched). Separate partitions for prefix and regex matches.

**Default limit:** Auto-scales as `max(10_000, proxies x 3)`.

**Env var:** `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (set to 0 for auto-scaling, or an explicit value to cap memory).

**Cleanup mechanism:** When the cache exceeds the max, a `DashMap::retain()` sweep evicts the oldest entries. The cache is rebuilt entirely on config reload.

### DNS Cache

**What it stores:** Resolved IP addresses for backend hostnames, upstream targets, and plugin endpoints.

**Default limit:** 10,000 entries.

**Env var:** `FERRUM_DNS_CACHE_MAX_SIZE`.

**Cleanup mechanism:** TTL-based expiration (`FERRUM_DNS_CACHE_TTL_SECONDS`), stale-while-revalidate (serves old IP while refreshing in background), and a background refresh task that keeps entries warm.

### Status Code Counters

**What it stores:** Per-status-code request counters exposed via the admin `/status` endpoint. Common HTTP status codes (200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504) are pre-populated at startup so the hot path uses DashMap read locks.

**Default limit:** 200 entries.

**Env var:** `FERRUM_STATUS_COUNTS_MAX_ENTRIES`.

**Cleanup mechanism:** Rare status codes create entries on first occurrence up to the configured cap. Once the cap is reached, new status codes that are not already tracked are silently dropped from the counter map (they are still proxied normally). The pre-populated common codes are never evicted.

### Per-IP Request Counters

**What it stores:** Active concurrent request count per resolved client IP address. Only active when `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP > 0`.

**Default limit:** No hard entry cap -- bounded by the number of unique client IPs with active requests.

**Env var:** `FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS` (default 60s).

**Cleanup mechanism:** A periodic background sweep removes entries where the counter has reached zero (client has no active requests). The RAII `Drop` guard on each request ensures counters are always decremented, even across early returns and error paths.

### Circuit Breaker Cache

**What it stores:** Circuit breaker state (Closed/Open/Half-Open) per `proxy_id::host:port` combination. Tracks connection errors and status code failures independently.

**Default limit:** 10,000 entries.

**Env var:** `FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES`.

**Cleanup mechanism:** Stale entries for targets that no longer exist in the configuration are pruned on every config reload. When the cache reaches the max entry count, new circuit breaker entries for previously-unseen targets are not created (the request proceeds without circuit breaker protection for that target). This prevents unbounded growth from target churn in environments with dynamic upstreams.

### Health Check State

**What it stores:** Active probe results (shared per-upstream) and passive failure counters (isolated per-proxy). See the Health Check Architecture section in CLAUDE.md for the full two-layer design.

**Default limit:** No hard entry cap -- bounded by the number of configured upstreams and proxies.

**Cleanup mechanism:** `remove_stale_targets()` runs on config reload and removes entries for targets that no longer appear in any upstream. The passive recovery timer iterates all proxies' inner maps in a background task.

## Plugin Caches

### Rate Limiting

**What it stores:** Per-key (IP or consumer) rate counters with sliding window timestamps or token bucket state.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Stale entries (where all windows have expired) are evicted on a piggyback sweep triggered during normal request processing. When the entry count exceeds 100,000, eviction runs unconditionally. When using `sync_mode: "redis"`, counters are stored in Redis with TTL-based key expiration and the local DashMap is only used as a fallback.

### AI Rate Limiter

**What it stores:** Per-key token usage counters for AI/LLM rate limiting.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Same as rate limiting -- stale entry eviction on piggyback sweep.

### WebSocket Rate Limiting

**What it stores:** Per-connection frame rate counters using token bucket algorithm.

**Default limit:** 50,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Capacity-triggered eviction when exceeding 50,000 entries, plus stale entry cleanup.

### UDP Rate Limiting

**What it stores:** Per-client-IP datagram and byte rate counters.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Capacity-triggered eviction when exceeding 100,000 entries.

### GraphQL Rate Limiting

**What it stores:** Per-key rate counters for GraphQL per-operation rate limiting.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Stale entry eviction on piggyback sweep.

### gRPC Method Router Rate Limiting

**What it stores:** Per-key rate counters for gRPC per-method rate limiting.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Stale entry eviction on piggyback sweep.

### Response Caching

**What it stores:** Cached backend response bodies with headers, keyed by request path and cache key rules.

**Default limit:** 10,000 entries.

**Config field:** `max_entries` (in plugin config JSON).

**Cleanup mechanism:** TTL-based expiration. When the cache exceeds `max_entries`, expired entries are evicted first, then oldest entries are removed to bring the count below the limit.

### AI Semantic Cache

**What it stores:** Cached LLM responses keyed by normalized prompt text.

**Default limit:** 10,000 entries.

**Config field:** `max_entries` (in plugin config JSON).

**Cleanup mechanism:** TTL-based expiration (`ttl_seconds` config field). When the cache exceeds `max_entries`, oldest entries are evicted.

### Request Deduplication

**What it stores:** Idempotency keys with cached responses for POST/PUT/PATCH deduplication.

**Default limit:** 10,000 entries.

**Config field:** `max_entries` (in plugin config JSON, default 10,000).

**Cleanup mechanism:** TTL-based expiration (`ttl_seconds` config field). When the cache exceeds `max_entries`, expired entries are evicted first, then oldest entries are removed. When using `sync_mode: "redis"`, entries are stored in Redis with TTL-based key expiration.

### SOAP WS-Security Nonce Cache

**What it stores:** Used nonces for replay protection in WS-Security authentication.

**Default limit:** 10,000 entries.

**Config field:** `nonce_replay_protection.max_cache_size` (default 10,000) and `nonce_replay_protection.cache_ttl_seconds` (default 300s).

**Cleanup mechanism:** TTL-based expiration. When the cache reaches `max_cache_size`, expired entries are purged first. If still at capacity after purging, the oldest 10% of entries are forcibly evicted to make room.

### LDAP Auth Cache

**What it stores:** Successful LDAP bind results (username hash -> expiry timestamp) to avoid repeated LDAP round-trips.

**Default limit:** 1,000 entries.

**Config field:** `cache_ttl_seconds` (default 300s, set to 0 to disable) and `max_cache_entries` (default 1,000).

**Cleanup mechanism:** TTL-based expiration checked on lookup. When the cache reaches `max_cache_entries`, expired entries are purged. If still at capacity, the insert is skipped (the next request will re-authenticate against LDAP).

### JWKS Cache

**What it stores:** JWKS key sets fetched from remote JWKS endpoints, shared across all `jwks_auth` plugin instances.

**Default limit:** No hard entry cap -- bounded by the number of configured JWKS provider URLs (typically 1-3 per plugin instance).

**Config field:** N/A (entry count equals configured provider count).

**Cleanup mechanism:** TTL-based refresh (`cache_ttl_seconds` config field, default 3600s). Entries are refreshed in the background before expiry. The global JWKS store is keyed by provider URL, so duplicate URLs across plugin instances share a single cache entry.

### TCP Connection Throttle

**What it stores:** Active TCP connection counts per consumer or client IP.

**Default limit:** No hard entry cap -- bounded by unique clients with active connections.

**Config field:** `max_connections_per_key` (required, controls the per-key connection limit, not the map size).

**Cleanup mechanism:** Entries use `Arc<AtomicU64>` counters decremented on connection close. Zero-count entries remain in the map but consume minimal memory (a DashMap entry with an atomic counter).

### API Chargeback

**What it stores:** Per-consumer charge accumulators with nanosecond-precision timestamps for staleness detection.

**Default limit:** No hard entry cap -- bounded by the number of active consumers.

**Config field:** N/A.

**Cleanup mechanism:** Background eviction task runs periodically and removes entries that have not been updated within the configured staleness window. The rendered Prometheus/JSON output is cached with a configurable TTL (`render_cache_ttl_seconds`, default 60s).

### Prometheus Metrics

**What it stores:** Per-proxy, per-status-code metric counters and a cached rendered output string.

**Default limit:** No hard entry cap -- bounded by proxy count multiplied by observed status codes.

**Config field:** N/A.

**Cleanup mechanism:** Piggyback eviction on cache miss (at most once per `render_cache_ttl_seconds`). Stale proxy entries (for proxies removed from config) are evicted during the render sweep.

## Environment Variable Summary

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_ROUTER_CACHE_MAX_ENTRIES` | `0` (auto) | Router lookup cache size. `0` = auto-scale as `max(10_000, proxies x 3)` |
| `FERRUM_DNS_CACHE_MAX_SIZE` | `10000` | Maximum DNS cache entries |
| `FERRUM_DNS_CACHE_TTL_SECONDS` | `300` | DNS cache entry TTL |
| `FERRUM_STATUS_COUNTS_MAX_ENTRIES` | `200` | Maximum HTTP status code counter entries |
| `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` | `0` | Per-IP concurrent request limit (`0` = disabled) |
| `FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS` | `60` | Cleanup interval for per-IP zero-count entries |
| `FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES` | `10000` | Maximum circuit breaker state entries |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Connection pool cleanup sweep interval |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup sweep interval |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |

## Plugin Config Field Summary

| Plugin | Config Field | Default | Description |
|--------|-------------|---------|-------------|
| `response_caching` | `max_entries` | `10000` | Maximum cached responses |
| `ai_semantic_cache` | `max_entries` | `10000` | Maximum cached LLM responses |
| `request_deduplication` | `max_entries` | `10000` | Maximum tracked idempotency keys |
| `soap_ws_security` | `nonce_replay_protection.max_cache_size` | `10000` | Maximum tracked nonces |
| `soap_ws_security` | `nonce_replay_protection.cache_ttl_seconds` | `300` | Nonce expiry TTL |
| `ldap_auth` | `max_cache_entries` | `1000` | Maximum cached LDAP bind results |
| `ldap_auth` | `cache_ttl_seconds` | `300` | LDAP cache entry TTL (`0` = disabled) |
| `jwks_auth` | `cache_ttl_seconds` | `3600` | JWKS key set refresh interval |
| `api_chargeback` | `render_cache_ttl_seconds` | `60` | Rendered output cache TTL |
| `prometheus_metrics` | `render_cache_ttl_seconds` | `60` | Rendered output cache TTL |

Rate limiting plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, `udp_rate_limiting`, `graphql`, `grpc_method_router`) use hardcoded maximum entry constants (50,000-100,000) and are not configurable via plugin config. These limits are intentionally high to avoid false rejections under normal traffic patterns while still preventing unbounded growth from IP/key churn.
