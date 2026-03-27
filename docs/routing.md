# Request Routing

Ferrum Gateway routes incoming requests to backend proxies using a combination of **host matching**, **path prefix matching**, and **regex path matching**. This document describes the full routing algorithm, priority rules, and caching behavior.

## Routing Algorithm

When a request arrives, the gateway extracts the **host** (from the `Host` header or HTTP/2 `:authority` pseudo-header, lowercased, port stripped) and the **request path** (from the URI).

### Step 1: Cache Lookup (O(1))

Before any route table scanning, the router checks two bounded caches keyed by `(host, path)`:

1. **Prefix cache** — stores prefix route matches and negative (no-match) entries
2. **Regex cache** — stores regex route matches (separate partition)

If either cache contains an entry for the `(host, path)` pair, the result is returned immediately. This makes repeated requests O(1) regardless of how the match was originally computed.

When no regex routes are configured, the regex cache check is skipped entirely via a pre-computed `has_regex_routes` flag.

### Step 2: Route Table Scan (cache miss)

On a cache miss, the router scans the pre-built route table. Routes are organized into **three host tiers**, searched in priority order:

| Tier | Description | Lookup Cost |
|------|-------------|-------------|
| **Exact host** | Proxy's `hosts` list contains the request host verbatim | O(1) HashMap lookup |
| **Wildcard host** | Proxy's `hosts` list contains `*.domain.tld` matching the request host | O(wildcard patterns) linear scan |
| **Catch-all** | Proxy has empty `hosts` (matches any host) | Direct access |

Within **each** host tier, two path matching strategies are tried in order:

| Priority | Match Type | Description |
|----------|-----------|-------------|
| **1st** | Prefix | Longest-prefix match against `listen_path` (pre-sorted by length descending) |
| **2nd** | Regex | First regex pattern match against `listen_path` starting with `~` (in config order) |

**Prefix routes always beat regex routes within the same host tier.** This ensures backward compatibility and optimal performance since prefix matching is cheaper than regex evaluation.

### Step 3: Cache the Result

After scanning, the result is cached for future O(1) lookups:

- **Prefix match** is stored in the prefix cache
- **Regex match** is stored in the regex cache (separate partition)
- **No match** is stored as a negative entry in the prefix cache (prevents repeated O(n) scans from scanner/bot traffic)

## Priority Rules (Most to Least Specific)

```
1. Host specificity
   exact host  >  wildcard host (*.domain)  >  catch-all (no hosts)

2. Path match type (within the same host tier)
   prefix route  >  regex route

3. Prefix tiebreaker
   longest prefix wins (pre-sorted at config load time)

4. Regex tiebreaker
   first match in config order wins
```

### Example

Given these proxy routes:

```yaml
proxies:
  - id: exact-api
    hosts: ["api.example.com"]
    listen_path: "/api/v1"

  - id: wildcard-api
    hosts: ["*.example.com"]
    listen_path: "/api"

  - id: catchall
    listen_path: "/"

  - id: user-orders-regex
    listen_path: "~/users/(?P<user_id>[^/]+)/orders"
```

| Request Host | Request Path | Matched Proxy | Reason |
|---|---|---|---|
| `api.example.com` | `/api/v1/users` | `exact-api` | Exact host + longest prefix `/api/v1` |
| `api.example.com` | `/api/health` | `wildcard-api` | No exact-host prefix match for `/api/health`, wildcard `*.example.com` + prefix `/api` |
| `other.example.com` | `/api/data` | `wildcard-api` | Wildcard host match + prefix `/api` |
| `other.org` | `/anything` | `catchall` | No exact/wildcard match, catch-all `/` |
| `other.org` | `/users/42/orders/pending` | `user-orders-regex` | No prefix match, catch-all regex matches |
| `api.example.com` | `/users/42/orders` | `exact-api`? No. `wildcard-api`? No. `catchall` prefix `/`? Yes. | `catchall` | Catch-all prefix `/` beats catch-all regex |

Note the last row: the catch-all prefix route `/` matches `/users/42/orders` before the regex route is checked, because **prefix always beats regex within the same host tier**. To use the regex route for this path, either remove the catch-all or assign the regex route to a more specific host tier.

## Regex Path Routing

### Configuration

Prefix a `listen_path` with `~` to use regex matching:

```yaml
proxies:
  - id: user-orders
    listen_path: "~/users/(?P<user_id>[^/]+)/orders/(?P<order_id>[^/]+)"
    backend_host: orders-service
    backend_port: 8080
    strip_listen_path: true
```

### Pattern Rules

- The `~` prefix signals regex mode (it is not part of the pattern)
- Patterns are **auto-anchored** with `^` if not already anchored (matching always starts from the beginning of the path)
- Patterns are **pre-compiled** at config load time using the Rust `regex` crate — invalid patterns are caught during config validation, not at request time
- Named capture groups use `(?P<name>pattern)` syntax

### Named Capture Extraction

Named captures are extracted on match and forwarded to backends and plugins:

- **Request headers**: `X-Path-Param-{name}: value` (e.g., `X-Path-Param-User-Id: 42`)
- **Plugin context**: `ctx.metadata["path_param.user_id"]`

### Path Stripping with Regex Routes

When `strip_listen_path: true`, the **matched portion** of the path is stripped (not the literal pattern text). The remaining path is forwarded to the backend:

| Request Path | Regex Pattern | Matched Portion | Remaining (to backend) |
|---|---|---|---|
| `/users/42/orders/pending` | `/users/[^/]+/orders` | `/users/42/orders` | `/pending` |
| `/users/42/orders` | `/users/[^/]+/orders` | `/users/42/orders` | `/` |

Combined with `backend_path`, this works the same as prefix routes:

```yaml
listen_path: "~/users/[^/]+/orders"
strip_listen_path: true
backend_path: "/internal"
# /users/42/orders/pending → backend receives /internal/pending
```

## Cache Architecture

The router uses **two separate DashMap cache partitions**:

| Cache | Contents | Purpose |
|-------|----------|---------|
| **Prefix cache** | Prefix matches + negative (no-match) entries | Protect high-hit prefix entries from eviction |
| **Regex cache** | Regex matches only | Isolate high-cardinality regex paths (e.g., `/users/{uuid}/...`) |

This separation prevents regex routes with highly variable path segments (UUIDs, timestamps) from filling the cache and evicting frequently-hit prefix route entries.

Both caches are bounded (default 10,000 entries each) with ~25% random-sample eviction when full. Cache entries are invalidated surgically on config changes — only affected paths are evicted, preserving the hot 99% of cache entries.

## Performance Characteristics

| Scenario | Cost |
|----------|------|
| Cache hit (any route type) | O(1) DashMap lookup |
| Prefix-only deployment (no regex routes) | Zero regex overhead (`has_regex_routes` flag skips all regex code) |
| Cache miss, prefix match found | O(prefix routes in tier) — early exit on first match |
| Cache miss, regex match found | O(prefix routes) + O(regex routes) — result cached for future O(1) |
| Cache miss, no match (404) | O(all routes in all tiers) — negative entry cached for future O(1) |
| Config reload | Route table rebuilt atomically via ArcSwap; caches surgically invalidated |

All route table operations (sorting, regex compilation, host partitioning) happen at config load time, never on the request hot path. The request path uses only lock-free reads (`ArcSwap::load()`, `DashMap::get()`).
