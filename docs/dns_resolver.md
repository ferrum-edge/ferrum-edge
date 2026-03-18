# DNS Resolver Configuration

Ferrum Gateway includes a full-featured DNS resolver built on [hickory-resolver](https://github.com/hickory-dns/hickory-dns), providing configurable nameservers, hosts file support, record type ordering, TTL management, stale-while-revalidate caching, and error caching — all designed to keep DNS resolution off the hot request path.

## Environment Variables

### Core DNS Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_DNS_CACHE_TTL_SECONDS` | `u64` | `300` | Default TTL (seconds) for cached DNS entries when the response doesn't provide one or `FERRUM_DNS_VALID_TTL` is not set. |
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
| `FERRUM_DNS_VALID_TTL` | `u64` | Response TTL | Override TTL (seconds) for positive DNS records. When set, all successful lookups use this fixed TTL regardless of the DNS response TTL. |
| `FERRUM_DNS_STALE_TTL` | `u64` | `3600` | How long (seconds) stale cached data can be served while a background refresh is in progress. See [Stale-While-Revalidate](#stale-while-revalidate). |
| `FERRUM_DNS_ERROR_TTL` | `u64` | `1` | TTL (seconds) for caching DNS errors and empty responses. Prevents hammering DNS for known-bad hostnames. |

### System-Level DNS Settings

Ferrum Gateway respects the following system-level environment variables, as parsed from `/etc/resolv.conf`:

| Variable | Description |
|----------|-------------|
| `RES_OPTIONS` | Space-separated resolver options: `rotate` (round-robin nameservers), `ndots:N` (minimum dots before absolute lookup), `timeout:N` (query timeout seconds), `attempts:N` (retry count). |
| `LOCALDOMAIN` | Space-separated search domains for unqualified hostnames. |

These are automatically applied unless explicitly overridden by `FERRUM_DNS_RESOLVER_ADDRESS` (which replaces nameservers) or `FERRUM_DNS_VALID_TTL` / `FERRUM_DNS_ERROR_TTL` (which override TTL behavior).

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

When a cached DNS entry expires (past its TTL), Ferrum Gateway doesn't block the request waiting for a fresh DNS lookup. Instead:

1. **Fresh** (within TTL): Return cached result immediately.
2. **Stale** (past TTL, within `stale_ttl`): Return the stale cached result immediately and trigger a **background refresh** task. The next request will get the fresh result.
3. **Expired** (past both TTL and `stale_ttl`): Perform a synchronous DNS lookup (blocking the request).

This ensures that DNS resolution almost never blocks the hot request path, even when entries expire.

**Example:** With `FERRUM_DNS_CACHE_TTL_SECONDS=300` and `FERRUM_DNS_STALE_TTL=3600`:
- For the first 5 minutes: cached result served directly.
- From 5 minutes to 65 minutes: stale result served while a background refresh runs.
- After 65 minutes: full re-resolution required.

## Error Caching

When DNS resolution fails (NXDOMAIN, timeout, empty response), the error is cached for `FERRUM_DNS_ERROR_TTL` seconds. During this time, subsequent lookups for the same hostname return the cached error immediately without hitting DNS again. This prevents:

- Flooding DNS servers with repeated queries for non-existent domains.
- Latency spikes from repeated timeouts on unreachable nameservers.

## Background Refresh

A background task proactively refreshes cache entries when they reach 75% of their TTL. This keeps the cache warm and prevents any request from hitting DNS directly. The background task runs every `max(TTL/4, 5 seconds)`.

## DNS Warmup

On startup, Ferrum Gateway resolves all configured backend hostnames asynchronously before accepting traffic. This ensures no cold-cache DNS lookups on the first request.

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

### Aggressive Caching

```bash
# 10 minute TTL, 2 hour stale window, 30 second error cache
FERRUM_DNS_CACHE_TTL_SECONDS=600
FERRUM_DNS_STALE_TTL=7200
FERRUM_DNS_ERROR_TTL=30
```

### Fixed TTL Override

```bash
# Force all DNS entries to use 60-second TTL regardless of response
FERRUM_DNS_VALID_TTL=60
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
| `dns_cache_ttl_seconds` | Per-proxy TTL override for cache entries. Takes precedence over `FERRUM_DNS_CACHE_TTL_SECONDS`. |

These are configured in the proxy definition (YAML/JSON config file or database).
