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

**Cleanup mechanism:** TTL-based expiration (each record's native TTL by default, or `FERRUM_DNS_TTL_OVERRIDE_SECONDS` when set), stale-while-revalidate (serves old IP while refreshing in background), a background refresh task that keeps entries warm, and a failed DNS retry task that re-attempts resolution of error-cached entries with exponential error-TTL backoff, age eviction at `FERRUM_DNS_STALE_TTL`, per-cycle concurrency bound (`FERRUM_DNS_MAX_CONCURRENT_REFRESHES`), and over-capacity eviction that prefers error entries over live success entries.

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

**What it stores:** Per-key (IP or consumer) rate counters with sliding window timestamps or token bucket state. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Sampled piggyback sweeps during normal request processing (every 1,024 requests, cooldown-gated to at most once per second) prune idle keys even while the map is below the 100,000 hard cap. When the entry count exceeds 100,000, over-cap force eviction runs immediately (no sample/cooldown gate) and reclaims space after that stale prune. When using `sync_mode: "redis"`, counters are stored in Redis with TTL-based key expiration and the local DashMap is only used as a fallback (subject to the same below-cap stale prune / over-cap force-eviction rules). `sync_mode` supports only `local` and `redis`; database-backed counters are intentionally unsupported.

### AI Rate Limiter

**What it stores:** Per-key token usage counters for AI/LLM rate limiting. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Same as rate limiting — sampled below-cap stale pruning (every 1,024 requests, cooldown-gated to at most once per second) plus immediate over-cap force eviction after prune. When using `sync_mode: "redis"`, token counters are stored in Redis and the local DashMap is only used as a fallback.

### WebSocket Rate Limiting

**What it stores:** Per-connection frame rate counters using token bucket algorithm. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 50,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Sampled periodic sweeps (every 100,000 frame hooks, cooldown-gated to at most once per second) prune idle connection state below the 50,000 hard cap; exceeding the cap force-evicts immediately after that prune. When using `sync_mode: "redis"`, frame counters are stored in Redis and the local DashMap is only used as a fallback.

### UDP Rate Limiting

**What it stores:** Per-client-IP datagram and byte rate counters. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Sampled periodic sweeps (every 100,000 datagram hooks, cooldown-gated to once per second) prune idle client state below the 100,000 hard cap. An over-cap observation keeps strict new-IP admission closed and may force-evict after pruning, but the shared atomic gate permits at most one full-map scan per second. When using `sync_mode: "redis"`, datagram and byte counters are stored in Redis and the local DashMap is only used as a fallback.

### GraphQL Rate Limiting

**What it stores:** Per-key rate counters for GraphQL per-operation rate limiting. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Sampled piggyback sweeps (every 1,024 rate checks, cooldown-gated to at most once per second) prune idle keys below the hard cap; exceeding 100,000 force-evicts immediately after that prune. When using `sync_mode: "redis"`, counters are stored in Redis with TTL-based key expiration and the local DashMap is only used as a fallback.

### gRPC Method Router Rate Limiting

**What it stores:** Per-key rate counters for gRPC per-method rate limiting. The local (and Redis-fallback) DashMap uses the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 100,000 entries (hardcoded `MAX_STATE_ENTRIES`).

**Config field:** N/A (hardcoded constant).

**Cleanup mechanism:** Sampled piggyback sweeps (every 1,024 rate checks, cooldown-gated to at most once per second) prune idle keys below the hard cap; exceeding 100,000 force-evicts immediately after that prune. When using `sync_mode: "redis"`, counters are stored in Redis with TTL-based key expiration and the local DashMap is only used as a fallback.

### Response Caching

**What it stores:** Cached backend response bodies with headers, keyed by request path and cache key rules. The cache, Vary-index, and uncacheable-predictor DashMaps use the normalized `FERRUM_POOL_SHARD_AMOUNT`.

**Default limit:** 10,000 entries and 100 MiB retained response-entry bytes.

**Config fields:** `max_entries`, `max_entry_size_bytes`, and `max_total_size_bytes` (in plugin config JSON).

**Cleanup mechanism:** Freshness-based expiration (`ttl_seconds` fallback plus backend `Cache-Control`, `Age`, and `Date`). Cache hits emit a current `Age` header. Stores hold a narrow admission/accounting lock so `max_total_size_bytes` is an exact upper bound across concurrent stores and replacements. When a store would exceed `max_total_size_bytes`, expired entries are reclaimed first and the store is skipped only if it still does not fit. When the cache exceeds `max_entries`, expired entries are evicted first, then oldest entries are removed to bring the count below the limit.

### AI Semantic Cache

**What it stores:** Cached LLM responses keyed by family-correct prompt text (exact keys preserve LLM-significant case and whitespace; structural canonicalization remains for JSON key order and numeric sampling params). When `semantic_similarity_enabled` is true, local cache entries can also carry prompt embeddings and are indexed in a local HNSW vector snapshot for semantic lookup after exact misses.

**Default limit:** 10,000 entries. In semantic mode, HNSW snapshot memory and periodic full-index rebuild CPU also scale with this count and are charged against `max_total_size_bytes`.

**Config fields:** `ttl_seconds`, `max_entries`, `max_entry_size_bytes`, `max_total_size_bytes`, `include_model_in_key`, `include_params_in_key`, `scope_by_consumer`, and the optional semantic/Redis settings documented in [Plugins](plugins.md#ai_semantic_cache).

**Cleanup mechanism:** TTL-based expiration (`ttl_seconds` config field). Expired-entry sweep and max-entries eviction (oldest-first) run off the request hot path in throttled, non-overlapping lifecycle-owned workers (at most once every 30 seconds), so no single request pays the full-map scan or oldest-entry selection. The optional semantic vector snapshot is rebuilt by the same lifecycle owner after local semantic entries are inserted or evicted, at most once every 30 seconds after the first indexed semantic entry. Generation drop/reload cooperatively cancels these workers; blocking-pool work already scheduled may finish before releasing its bounded reservation. `max_total_size_bytes` is a hard retained-byte budget covering response bodies, headers, scope keys, embeddings, published HNSW generations, and in-flight rebuild workspace via lock-free leases, enforced synchronously on the store path (independent of the background eviction); failed/superseded/cancelled rebuilds release candidate reservations promptly. Concurrent stores that cannot reserve are skipped; same-key replacement drops the displaced entry's lease so overwritten bytes release immediately. Redis is treated as an untrusted trust boundary: every hit is byte-bounded before allocation, schema-versioned, authenticated with a seal timestamp, and re-validated against the same TTL/status/content-type/size/JSON/header admission contract as a local store, with stale, invalid, or cross-version entries quarantined rather than served.

### Request Deduplication

**What it stores:** Idempotency keys with cached responses for POST/PUT/PATCH deduplication.

**Default limit:** 10,000 entries, 1 MiB per completed response entry, and 100 MiB retained completed response-entry bytes.

**Config fields:** `max_entries`, `max_entry_size_bytes`, and `max_total_size_bytes` (in plugin config JSON).

**Cleanup mechanism:** TTL-based expiration (`ttl_seconds` config field). Completed-response retention is bounded by `max_entry_size_bytes` and exact local `max_total_size_bytes` accounting; oversized or over-cap responses return normally and are not retained. In local mode, skipped responses clear their local in-flight marker immediately. Streamed non-buffered responses are not retained; their in-flight marker is released on a clean stream completion and is otherwise retained until `inflight_ttl_seconds` when the stream is interrupted (client disconnect or backend error). When the local cache exceeds `max_entries`, expired entries are evicted first, then oldest completed entries are removed. Active in-flight markers are not evicted while live. When using `sync_mode: "redis"`, completed responses are stored in Redis with TTL-based key expiration only after retained-response and serialized-payload per-entry size admission; oversized responses are not written. Responses skipped only by the local total cap still attempt Redis publication, and local plus distributed in-flight locks are released only when that publication succeeds, is skipped by per-entry admission, or a streamed non-buffered response completes cleanly; an interrupted streamed response leaves its locks to expire under `inflight_ttl_seconds`.

### SOAP WS-Security Nonce Cache

**What it stores:** Used nonces for replay protection in WS-Security authentication.

**Default limit:** 10,000 entries.

**Config field:** `nonce_replay_protection.max_cache_size` (default 10,000) and `nonce_replay_protection.cache_ttl_seconds` (default 300s).

**Cleanup mechanism:** TTL-based expiration. When the cache reaches `max_cache_size`, expired entries are purged first. If still at capacity after purging, the oldest 10% of entries are forcibly evicted to make room.

### LDAP Auth Cache

**What it stores:** Successful LDAP bind results (a process-random HMAC over the presented username/password -> canonical identity and expiry timestamp) to avoid repeated LDAP round-trips. The HMAC prevents a cache-only disclosure from exposing a reusable fast password verifier; a full process-memory compromise can still recover the in-process HMAC key.

**Default limit:** 10,000 entries. Caching is disabled by default.

**Config field:** `cache_ttl_seconds` (default `0`, disabled; maximum `86,400` seconds / 24 hours) and `max_cache_entries` (default `10,000`).

**Cleanup mechanism:** TTL-based expiration is checked on lookup. Admission uses atomic entry accounting to preserve the hard cap during concurrent authentication. At capacity, one existing entry is replaced for each new admission; the request path never performs a full-cache scan.

### JWKS Cache

**What it stores:** JWKS key sets fetched from remote JWKS endpoints, shared across all `jwks_auth` plugin instances.

**Default limit:** No hard entry cap -- bounded by the number of configured JWKS provider URLs (typically 1-3 per plugin instance).

**Config field:** N/A (entry count equals configured provider count).

**Cleanup mechanism:** Periodic background refresh (`jwks_refresh_interval_secs`, default `900` seconds). The global JWKS store is keyed by provider URL, so duplicate URLs across plugin instances share a single cache entry and use the minimum interval requested by active consumers. See the [`jwks_auth` plugin reference](plugins.md#jwks_auth).

### TCP Connection Throttle

**What it stores:** Active TCP/TCP+TLS connection counts per consumer or canonical client IP. Accounting is process-local, and the map uses the normalized `FERRUM_POOL_SHARD_AMOUNT`. Every replica has an independent map, so aggregate deployment capacity is the configured per-key limit multiplied by the number of replicas receiving that key's connections.

**Default limit:** No hard entry cap -- bounded by unique clients with active connections.

**Config fields:** `max_connections_per_key` (required, controls the per-key connection limit, not the map size) and `cleanup_interval_seconds` (default `60`, `0` disables only the residual sweep).

**Cleanup mechanism:** Each admission owns an opaque permit bound to the exact counter entry it incremented. Permit release decrements and removes a zero-count entry inline while holding the same DashMap entry guard used by admission. A configurable background sweep removes only residual zero-count entries; it cannot repair a missed positive decrement. `cleanup_interval_seconds: 0` disables only that residual sweep, not inline release/removal. Accounting state is shared across compatible cache generations by plugin namespace/config ID. Removing the policy stops its sweep and removes the state from the cache registry; old connection permits retain only that retired state until they release.

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
| `FERRUM_DNS_TTL_OVERRIDE_SECONDS` | Disabled | Global DNS TTL override (native record TTL used by default) |
| `FERRUM_DNS_MIN_TTL_SECONDS` | `5` | Minimum TTL floor for DNS records |
| `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS` | `10` | Failed DNS retry interval (`0` = disabled) |
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
| `response_caching` | `max_entry_size_bytes` | `1048576` | Maximum single cached response body |
| `response_caching` | `max_total_size_bytes` | `104857600` | Exact maximum retained response-entry bytes |
| `ai_semantic_cache` | `max_entries` | `10000` | Maximum cached LLM responses |
| `request_deduplication` | `max_entries` | `10000` | Maximum tracked idempotency keys |
| `request_deduplication` | `max_entry_size_bytes` | `1048576` | Maximum retained completed response entry |
| `request_deduplication` | `max_total_size_bytes` | `104857600` | Exact maximum retained local completed response-entry bytes |
| `soap_ws_security` | `nonce_replay_protection.max_cache_size` | `10000` | Maximum tracked nonces |
| `soap_ws_security` | `nonce_replay_protection.cache_ttl_seconds` | `300` | Nonce expiry TTL |
| `ldap_auth` | `max_cache_entries` | `10000` | Maximum cached LDAP bind results |
| `ldap_auth` | `cache_ttl_seconds` | `0` | LDAP cache entry TTL (`0` = disabled; maximum `86400`) |
| `jwks_auth` | `jwks_refresh_interval_secs` | `900` | JWKS key set refresh interval |
| `api_chargeback` | `render_cache_ttl_seconds` | `60` | Rendered output cache TTL |
| `prometheus_metrics` | `render_cache_ttl_seconds` | `60` | Rendered output cache TTL |

Rate limiting plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, `udp_rate_limiting`, `graphql`, `grpc_method_router`) use hardcoded maximum entry constants (50,000-100,000) and are not configurable via plugin config. These limits are intentionally high to avoid false rejections under normal traffic patterns while still preventing unbounded growth from IP/key churn. Counter storage supports only local memory and Redis; there is no database-backed counter policy.
