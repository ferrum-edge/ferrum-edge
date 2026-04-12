# DNS Resolver Configuration

Ferrum Edge includes a full-featured DNS resolver built on [hickory-resolver](https://github.com/hickory-dns/hickory-dns), providing configurable nameservers, hosts file support, record type ordering, native TTL respect, stale-while-revalidate caching, error caching, and automatic failed lookup retries — all designed to keep DNS resolution off the hot request path.

## Native TTL Respect

By default, the DNS cache respects each record's **native TTL** from the DNS response. No global TTL override is applied — short-TTL records (e.g., 30s for service discovery) refresh quickly while long-TTL records (e.g., 3600s for stable services) persist longer. A minimum TTL floor (`FERRUM_DNS_MIN_TTL_SECONDS`, default 5s) prevents extremely short TTLs from causing excessive DNS queries.

**TTL priority** (highest to lowest):

1. **Per-proxy TTL** (`dns_cache_ttl_seconds` on the proxy config) — overrides everything for that proxy's backend
2. **Global TTL override** (`FERRUM_DNS_TTL_OVERRIDE_SECONDS`) — forces a fixed TTL on all records
3. **Native record TTL** — the TTL from the DNS response itself (default behavior)

The final TTL is always clamped to at least `FERRUM_DNS_MIN_TTL_SECONDS`.

## Environment Variables

### Core DNS Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_DNS_OVERRIDES` | JSON map | `{}` | Global static hostname-to-IP overrides. Format: `{"host":"ip","host2":"ip2"}`. These bypass DNS entirely. |

### Resolver Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_DNS_RESOLVER_ADDRESS` | `String` | System resolv.conf | Comma-separated nameserver addresses (`ip[:port]`). Supports IPv4 and IPv6. Port defaults to 53 if omitted. |
| `FERRUM_DNS_RESOLVER_HOSTS_FILE` | `String` | `/etc/hosts` | Path to a custom hosts file. Entries in this file take priority over DNS queries. |
| `FERRUM_DNS_ORDER` | `String` | `CACHE,SRV,A,CNAME` | Comma-separated, case-insensitive list of DNS record types to query, in order. See [DNS Order](#dns-order) below. |

### TTL Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_DNS_TTL_OVERRIDE_SECONDS` | `u64` | Disabled | Global TTL override (seconds) for all positive DNS records. When set, all cached entries use this fixed TTL regardless of the native DNS response TTL. Disabled by default — the cache respects each record's native TTL. |
| `FERRUM_DNS_MIN_TTL_SECONDS` | `u64` | `5` | Minimum TTL floor (seconds) for cached DNS records. Prevents 0-TTL or very short TTLs from causing excessive DNS queries. Applied after all other TTL computations. |
| `FERRUM_DNS_STALE_TTL` | `u64` | `3600` | How long (seconds) stale cached data can be served while a background refresh is in progress. See [Stale-While-Revalidate](#stale-while-revalidate). |
| `FERRUM_DNS_ERROR_TTL` | `u64` | `5` | TTL (seconds) for caching DNS errors and empty responses. Prevents hammering DNS for known-bad hostnames. |
| `FERRUM_DNS_CACHE_MAX_SIZE` | `usize` | `10000` | Maximum number of entries in the DNS cache. Expired entries are evicted automatically; if the cache still exceeds this limit, oldest entries are removed. |
| `FERRUM_DNS_WARMUP_CONCURRENCY` | `usize` | `500` | Maximum number of concurrent DNS resolutions during startup/config warmup. Higher values reduce warmup time for large configs but increase burst load on upstream resolvers. |
| `FERRUM_DNS_SLOW_THRESHOLD_MS` | `u64` | Disabled | Threshold in milliseconds above which DNS resolutions are logged as slow (`warn` level). Useful for diagnosing upstream DNS latency. When unset, no timing overhead is added. |
| `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT` | `u8` | `90` | Percentage of TTL elapsed before the background refresh task proactively re-resolves an entry (1-99). At 90%, a 60s-TTL entry refreshes after 54s. Lower values add safety margin at the cost of more DNS queries. |
| `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS` | `u64` | `10` | Interval (seconds) for the background task that retries failed DNS lookups. Error-cached entries whose error TTL has expired are re-attempted at this interval. Logs at `warn` level for each retry attempt and outcome. Set to `0` to disable. |

### System-Level DNS Settings

Ferrum Edge respects the following system-level environment variables, as parsed from `/etc/resolv.conf`:

| Variable | Description |
|----------|-------------|
| `RES_OPTIONS` | Space-separated resolver options: `rotate` (round-robin nameservers), `ndots:N` (minimum dots before absolute lookup), `timeout:N` (query timeout seconds), `attempts:N` (retry count). |
| `LOCALDOMAIN` | Space-separated search domains for unqualified hostnames. |

These are automatically applied unless explicitly overridden by `FERRUM_DNS_RESOLVER_ADDRESS` (which replaces nameservers) or `FERRUM_DNS_TTL_OVERRIDE_SECONDS` / `FERRUM_DNS_ERROR_TTL` (which override TTL behavior).

## DNS Order

The `FERRUM_DNS_ORDER` setting controls which DNS record types are queried and in what order. The resolver tries each type sequentially and returns the first successful result.

Valid values (case-insensitive):

| Value | Description |
|-------|-------------|
| `CACHE` | Use the record type that succeeded on the **last** lookup for this hostname. Skipped if no cached type exists. |
| `A` | Query A records (IPv4 addresses). |
| `AAAA` | Query AAAA records (IPv6 addresses). |
| `SRV` | Query SRV records (service discovery). SRV targets are resolved to IP addresses automatically. |
| `CNAME` | Query CNAME records (canonical names). CNAME chains are followed to resolve to IP addresses. |

**Default order:** `CACHE,SRV,A,CNAME`

This means: first try the record type that worked last time (for speed), then try SRV, then A, then CNAME.

## Stale-While-Revalidate

When a cached DNS entry expires (past its TTL), Ferrum Edge doesn't block the request waiting for a fresh DNS lookup. Instead:

1. **Fresh** (within TTL): Return cached result immediately.
2. **Stale** (past TTL, within `stale_ttl`): Return the stale cached result immediately and trigger a **background refresh** task. The next request will get the fresh result.
3. **Expired** (past both TTL and `stale_ttl`): Perform a synchronous DNS lookup (blocking the request).

This ensures that DNS resolution almost never blocks the hot request path, even when entries expire.

**Example:** With a DNS record that has a native 60s TTL and `FERRUM_DNS_STALE_TTL=3600`:
- For the first 60 seconds: cached result served directly.
- From 60 seconds to ~60 minutes: stale result served while a background refresh runs.
- After ~60 minutes: full re-resolution required.

## Error Caching

When DNS resolution fails (NXDOMAIN, timeout, empty response), the error is cached for `FERRUM_DNS_ERROR_TTL` seconds. During this time, subsequent lookups for the same hostname return the cached error immediately without hitting DNS again. This prevents:

- Flooding DNS servers with repeated queries for non-existent domains.
- Latency spikes from repeated timeouts on unreachable nameservers.

## Failed DNS Retry Task

A dedicated background task automatically retries DNS lookups that previously failed. It scans the cache for error entries whose error TTL has expired and re-attempts resolution at the interval configured by `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS` (default: every 10 seconds).

- Each retry attempt and outcome is logged at `warn` level, e.g.:
  - `DNS failed retry: re-attempting resolution for 'db.internal'`
  - `DNS failed retry: 'db.internal' resolved successfully -> 10.0.0.5 (ttl=30s)`
  - `DNS failed retry: 'db.internal' still failing: NXDOMAIN`
- On successful retry, the entry is promoted from error to a healthy cached entry with the record's native TTL.
- Set `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS=0` to disable this task.

## Background Refresh

A background task proactively refreshes cache entries before they expire. By default, entries are refreshed when 90% of their TTL has elapsed (configurable via `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT`). This keeps the cache warm and prevents any request from hitting DNS directly.

Since each record has its own native TTL, the background refresh task uses each entry's individual applied TTL for threshold computation — not a single global value. The scan runs every 5 seconds to handle short-TTL records promptly.

## DNS Warmup

On startup, Ferrum Edge resolves all configured hostnames asynchronously before accepting traffic. This includes:

- **Proxy backend hostnames** (`backend_host` on each proxy)
- **Upstream target hostnames** (`host` on each upstream target, when [load balancing](load_balancing.md) is configured)
- **Plugin endpoint hostnames** — extracted from plugin configurations (e.g., `http_logging` endpoint URLs, `tcp_logging` host, `jwks_auth` JWKS URIs)

Hostnames are **deduplicated** before resolution — if multiple proxies or plugins share the same hostname, only one DNS lookup is performed. Warmup remains parallel, but concurrency is bounded by `FERRUM_DNS_WARMUP_CONCURRENCY` to avoid unbounded task bursts on very large configs. This ensures no cold-cache DNS lookups on the first request, whether the proxy uses a single backend, a load-balanced upstream pool, or a plugin with an outbound endpoint.

After DNS warmup completes, the gateway optionally **warms connection pools** for all HTTP-family backends (HTTP, HTTPS, gRPC, HTTP/2, HTTP/3) — pre-establishing TCP/TLS/QUIC connections so the first request to each backend avoids handshake latency. This is controlled by `FERRUM_POOL_WARMUP_ENABLED` (default: `true`). See [connection_pooling.md](connection_pooling.md#connection-pool-warmup) for details.

## Transparent DNS Cache for HTTP Clients

All outbound HTTP clients (proxy traffic, health check probes, plugin outbound calls) use a custom DNS resolver that transparently routes DNS lookups through the gateway's central DNS cache. This is set via `reqwest::ClientBuilder::dns_resolver()` on every client, ensuring that:

- **No DNS in the hot path**: Hostname resolution is always served from the in-memory cache, never from the network.
- **Per-proxy `dns_override`**: When a proxy has a static `dns_override` IP, it is applied as a `resolve()` hint on the HTTP client, taking priority over the DNS cache for that specific hostname.
- **Unified caching**: Proxy backends, upstream targets, health check probes, and plugin outbound calls (http_logging, tcp_logging, jwks_auth, etc.) all share the same DNS cache, benefiting from warmup and background refresh.

Plugins declare their endpoint hostnames by implementing the `warmup_hostnames()` method on the `Plugin` trait. This allows the warmup phase to pre-resolve plugin endpoints alongside backend hostnames.

## Resolution Priority

For each incoming request, DNS resolution follows this priority:

1. **Per-proxy static override** (`dns_override` on the proxy config) — highest priority
2. **Global static overrides** (`FERRUM_DNS_OVERRIDES`) — checked next
3. **Cache** (fresh or stale-while-revalidate)
4. **Hosts file** (system or custom via `FERRUM_DNS_RESOLVER_HOSTS_FILE`)
5. **DNS query** via configured nameservers — lowest priority

## Example Configurations

### Custom Nameservers

```bash
# Use Cloudflare and Google DNS
FERRUM_DNS_RESOLVER_ADDRESS="1.1.1.1,8.8.8.8"

# Use custom DNS with non-standard port
FERRUM_DNS_RESOLVER_ADDRESS="10.0.0.53:5353"

# IPv6 nameserver
FERRUM_DNS_RESOLVER_ADDRESS="[2606:4700:4700::1111]:53"
```

### Global TTL Override

```bash
# Force all DNS entries to use 60-second TTL regardless of native record TTL
FERRUM_DNS_TTL_OVERRIDE_SECONDS=60
```

### Aggressive Caching with Override

```bash
# 10 minute TTL override, 2 hour stale window, 30 second error cache
FERRUM_DNS_TTL_OVERRIDE_SECONDS=600
FERRUM_DNS_STALE_TTL=7200
FERRUM_DNS_ERROR_TTL=30
```

### Service Discovery (Short TTL)

```bash
# Let native TTLs drive caching (default) with a 1-second minimum floor
# Short-TTL records from Consul/CoreDNS will refresh quickly
FERRUM_DNS_MIN_TTL_SECONDS=1
```

### IPv4-Only Resolution

```bash
# Only query A records (skip AAAA, SRV, CNAME)
FERRUM_DNS_ORDER="A"
```

### Custom Hosts File for Development

```bash
# Use a project-specific hosts file
FERRUM_DNS_RESOLVER_HOSTS_FILE="/etc/ferrum/hosts"
```

### Slow Resolution Alerting

```bash
# Log a warning when any DNS resolution takes longer than 50ms
FERRUM_DNS_SLOW_THRESHOLD_MS=50
```

### Custom Refresh Threshold

```bash
# Refresh entries when 80% of TTL has elapsed (more conservative, more DNS queries)
FERRUM_DNS_REFRESH_THRESHOLD_PERCENT=80

# Refresh entries when 95% of TTL has elapsed (aggressive, fewer DNS queries)
# Only recommended with stale-while-revalidate as a safety net
FERRUM_DNS_REFRESH_THRESHOLD_PERCENT=95
```

### Failed DNS Retry Configuration

```bash
# Retry failed DNS lookups every 5 seconds (more aggressive than default)
FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS=5

# Disable automatic retry of failed DNS lookups
FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS=0
```

### System Resolver Options

```bash
# Set ndots to 1, timeout to 3 seconds, 4 retry attempts, round-robin nameservers
RES_OPTIONS="ndots:1 timeout:3 attempts:4 rotate"

# Set search domain
LOCALDOMAIN="internal.mycompany.com"
```

## Per-Proxy DNS Settings

In addition to global DNS settings, each proxy can override DNS behavior:

| Proxy Field | Description |
|-------------|-------------|
| `dns_override` | Static IP address override for this proxy's backend. Bypasses all DNS resolution. |
| `dns_cache_ttl_seconds` | Per-proxy TTL override for cache entries. Takes precedence over both the native record TTL and `FERRUM_DNS_TTL_OVERRIDE_SECONDS`. |

These are configured in the proxy definition (YAML/JSON config file or database).
