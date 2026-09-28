# Request Routing

Ferrum Edge routes incoming requests to backend proxies using a combination of **host matching**, **path prefix matching**, and **regex path matching**. This document describes the full routing algorithm, priority rules, and caching behavior.

## Protocol family selection

Routing is the first half of the request path; protocol dispatch is the second. Once a proxy is matched, the gateway inspects two inputs to decide how to reach the backend:

- **`proxy.backend_scheme`** (`http`, `https`, `tcp`, `tcps`, `udp`, `dtls`) — the wire transport. HTTP family proxies (`http`, `https`) default to `https` when omitted. Stream family proxies must set a scheme explicitly.
- **Runtime `HttpFlavor`** — `Plain`, `Grpc`, or `WebSocket`, classified per-request by `detect_http_flavor()` from the request's content-type and upgrade headers.

The gateway does **not** pin gRPC or WebSocket in config — a single `https` proxy transparently serves a mix of REST, gRPC, and WebSocket traffic on the same backend pool. There are no gRPC-, WebSocket-, or HTTP/3-specific scheme values.

HTTP/3 clients work against any `backend_scheme` — see [docs/http3.md](http3.md) for the dispatch model, the cross-protocol bridge, and why WebSocket upgrades on the H3 listener return 501.

## Routing Algorithm

When a request arrives, the gateway first validates protocol authority fields, then extracts the **host** and **request path** for routing. HTTP/1 uses `Host`; HTTP/2 and HTTP/3 use `:authority`, and if a `Host` header is also present it must match `:authority` after ASCII case normalization, trailing-dot normalization, and scheme-default port normalization (`http`/`ws`: 80, `https`/`wss`: 443). Mismatches are rejected before routing so plugins and backends cannot observe different authorities.

Host normalization strips a valid port suffix, preserves bracketed IPv6 literals, rejects unbracketed IPv6 literals, strips a DNS trailing dot, and lowercases ASCII hostnames. Invalid authority syntax is rejected instead of being routed ambiguously.

The request path used for routing is the **canonical policy path**, derived once at the frontend boundary before route lookup and shared by every policy surface and by the backend request line. Percent-escapes of characters that are legal literally in a path are decoded (`/%61dmin` routes as `/admin`); every other escape is rejected with `400` before routing — encoded separators, double encodings, encoded control characters, invalid escapes, and escapes of bytes outside that `pchar` decode set (`%20`, `%7B`, and any percent-encoded non-ASCII byte), which the gateway can neither retain nor decode without forwarding a different string than policy read. Dot segments and backslashes are rejected in both spellings, literal and encoded: `/a/../b`, `/a/./b`, `/a/%2e%2e/b`, `/a\b`, and `/a%5Cb` all receive `400`, because the URL parser that builds the backend request line removes dot segments and reads `\` as a separator, so forwarding one would resolve a different path than routing matched. A `.` inside a segment (`/v1.0/users`) is an ordinary path character and is unaffected. No percent escape survives into the routed path. Because the same value is used for `strip_listen_path` offsets and for the forwarded path, a route decision can never desync from what the backend executes. Configured literal `listen_path` values must be written in that same canonical form and are rejected at admission otherwise; a `~regex` `listen_path` is a pattern, so only the percent-escape rules apply to it (`\` and `.` are regex syntax there). See [docs/request_path_canonicalization.md](request_path_canonicalization.md).

### Step 1: Cache Lookup (O(1))

Before any route table scanning, the router checks two bounded caches keyed by `(host, path)` plus the frontend port and TLS flag:

1. **Prefix cache** — stores prefix route matches and negative (no-match) entries
2. **Regex/exact cache** — stores regex, exact-path, and path-param route matches (separate partition)

If either cache contains an entry for the `(host, path)` pair, the result is returned immediately. This makes repeated requests O(1) regardless of how the match was originally computed.

When no regex routes are configured, the route-table regex scan is skipped entirely via a pre-computed `has_regex_routes` flag. The regex/exact cache partition is still checked on cache lookup because exact-path positives are stored there too.

### Step 2: Route Table Scan (cache miss)

On a cache miss, the router scans the pre-built route table. Routes are organized into **three host tiers**, searched in priority order:

| Tier | Description | Lookup Cost |
|------|-------------|-------------|
| **Exact host** | Proxy's `hosts` list contains the request host verbatim | O(1) HashMap lookup |
| **Wildcard host** | Proxy's `hosts` list contains `*.domain.tld` matching the request host | O(wildcard patterns) linear scan |
| **Catch-all** | Proxy has empty `hosts` (matches any host) | Direct access |

Within **each** host tier, four path matching strategies are tried in order:

| Priority | Match Type | Description |
|----------|-----------|-------------|
| **1st** | Exact path | Exact whole-path match against `listen_path` starting with `=` |
| **2nd** | Prefix | Longest-prefix match against `listen_path` (pre-sorted by length descending) |
| **3rd** | Regex | First regex pattern match against `listen_path` starting with `~` (in config order) |
| **4th** | Host-only fallback | Proxies with `hosts` set AND `listen_path` omitted — match ANY path under the host when the prefix and regex tiers miss |

**Exact path routes beat prefix routes, prefix routes beat regex routes, and all three beat the host-only fallback.** Exact paths are O(1) hash lookups and are used by Kubernetes `Exact` route translations so they cannot be shadowed by a broad prefix such as `/`.

**The host-only tier never appears in the catch-all host bucket.** A proxy with `hosts: []` AND no `listen_path` is rejected at config validation — it would mean "match literally every request on every host" and conflicts with every other catch-all route.

### Step 3: Cache the Result

After scanning, the result is cached for future O(1) lookups:

- **Prefix or host-only match** is stored in the prefix cache
- **Regex or exact-path match** is stored in the regex/exact cache (separate partition)
- **No match** is stored as a negative entry in the prefix cache (prevents repeated O(n) scans from scanner/bot traffic)

## Priority Rules (Most to Least Specific)

```
1. Host specificity
   exact host  >  wildcard host (*.domain)  >  catch-all (no hosts)

2. Path match type (within the same host tier)
   exact path  >  prefix route  >  regex route  >  host-only fallback

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

Host wildcards are DNS suffix matches: `*.example.com` matches `other.example.com`
and `deep.other.example.com`, but not `example.com` itself.

| Request Host | Request Path | Matched Proxy | Reason |
|---|---|---|---|
| `api.example.com` | `/api/v1/users` | `exact-api` | Exact host + longest prefix `/api/v1` |
| `api.example.com` | `/api/health` | `wildcard-api` | No exact-host prefix match for `/api/health`, wildcard `*.example.com` + prefix `/api` |
| `other.example.com` | `/api/data` | `wildcard-api` | Wildcard host match + prefix `/api` |
| `other.org` | `/anything` | `catchall` | No exact/wildcard match, catch-all `/` |
| `other.org` | `/users/42/orders` | `catchall` | Catch-all prefix `/` beats catch-all regex |
| `other.org` | `/users/42/orders/pending` | `catchall` | Catch-all prefix `/` (the regex would not match anyway: it is anchored with `$`) |
| `api.example.com` | `/users/42/orders` | `catchall` | No exact-host or wildcard match; catch-all prefix `/` beats catch-all regex |

In this example `user-orders-regex` never wins: the catch-all prefix route `/` matches every path before the regex route is checked, because **prefix always beats regex within the same host tier**. To use the regex route, either remove the catch-all `/` or give the regex route a more specific host tier.

## Host-only Routing

Set `hosts` without a `listen_path` to route **every request on that host** to one backend:

```yaml
proxies:
  - id: api-public
    hosts: ["api.example.com"]
    backend_host: api-backend
    backend_port: 8080
```

Behavior:

- Every request whose Host header matches `api.example.com` routes to `api-backend:8080`, regardless of path.
- An HTTP/1.1 **absolute-form** request-target (`GET http://host/path HTTP/1.1`) whose authority disagrees with the `Host` field is rejected with **400** before routing, matching the HTTP/2 / HTTP/3 `Host`/`:authority` agreement rule. RFC 9112 §3.2.1 has a recipient route on the request-target authority and ignore `Host`, while Ferrum routes on `Host`, so a disagreeing pair would let an upstream hop authorize one host tier while Ferrum selects another. Absolute-form *without* a `Host` field is still accepted and routes on the target authority; HTTP/1.0 is unaffected (RFC 9112 §3.2.2 does not require `Host` on 1.0).
- Request path is forwarded **unchanged** (there is no prefix to strip). `strip_listen_path: true` is a silent no-op.
- `backend_path`, if set, still prepends to the forwarded path.
- Host-only is the **last** tier within a host group — any exact path or regex match wins first. This lets you pin `/api/v2/*` to one backend and everything else on the same host to a different backend:

```yaml
proxies:
  - id: path-pinned
    hosts: ["api.example.com"]
    listen_path: "/api/v2"
    backend_host: v2-service
    backend_port: 9000

  - id: host-fallback
    hosts: ["api.example.com"]
    backend_host: legacy-service
    backend_port: 8000
```

| Request | Matched proxy |
|---|---|
| `GET api.example.com/api/v2/items` | `path-pinned` |
| `GET api.example.com/anything-else` | `host-fallback` |

### Validation rules

- HTTP-family proxies MUST set at least one of `hosts` or `listen_path`. A proxy with neither is rejected at admission (400 from the admin API, config load failure in file mode).
- Optional HTTP-family `listen_port` scopes the route to that frontend port. In `file`/`database`/`dp` mode the gateway binds a real socket for every declared HTTP-family `listen_port` (see `docs/gateway_api_conformance.md`), in addition to `FERRUM_PROXY_HTTP_PORT`/`FERRUM_PROXY_HTTPS_PORT`. When the whole table declares exactly one listen port of the request's protocol class, the global process bind also serves it (the Service-fronted projection of `:80`/`:443`); with two or more same-class ports only an exact listener match serves. Distinct ports do not conflict on the same hosts+path. Omit `listen_port` for port-agnostic matching.
- Stream proxies (`tcp`/`tcps`/`udp`/`dtls`) MUST NOT set `listen_path` — they route on `listen_port` only. A populated `listen_path` is rejected.
- Two host-only proxies whose `hosts` overlap on the same effective `listen_port` are rejected (409 from admin API).

## Outbound Host header

The `Host` Ferrum sends to the backend is **not** the client's `Host` by default. On every backend
transport — the reqwest HTTP/1.1 and HTTP/2 path, the direct-HTTP/2 pool, native gRPC, and native
HTTP/3 — the outbound `Host` is the **full authority of the load-balanced target that was actually
selected**, with a default port omitted:

| Selected target | Backend scheme | Outbound `Host` |
|---|---|---|
| `api-backend:8080` | `http` | `api-backend:8080` |
| `api-backend:80` | `http` | `api-backend` |
| `api-backend:443` | `https` | `api-backend` |
| `api-backend:8443` | `https` | `api-backend:8443` |
| `::1` port `8443` (IPv6 literal) | `https` | `[::1]:8443` |

Carrying the port matters for two reasons:

- **Backend virtual-host selection and absolute redirects.** A backend listening on a non-default
  port needs the port to pick the right virtual host and to build correct absolute `Location`
  values.
- **HTTP/2 protocol correctness.** On HTTP/2 the outbound `:authority` is derived from the backend
  URL, which carries the port. RFC 9113 §8.3.1 requires `Host` and `:authority` to be the same
  string; a hostname-only `Host` beside `:authority: api-backend:8443` is a protocol error that
  strict backends answer with a stream reset (surfacing as a 502). On HTTP/1.1 the same mismatch
  violates RFC 9112 §3.2.

Set `preserve_host_header: true` on a proxy to forward the **client's** `Host` verbatim instead. In
that mode Ferrum does not consult the selected target at all, and the backend sees exactly what the
client sent.

## Exact Path Routing

Prefix a `listen_path` with `=` to require a whole-path match:

```yaml
proxies:
  - id: healthz
    listen_path: "=/healthz"
    backend_host: health-service
    backend_port: 8080
    strip_listen_path: false
```

Exact paths compare against the request path without the query string, so `=/healthz` matches `/healthz?ready=true` but not `/healthz/live`.

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
- Patterns are **auto-anchored for full-path matching**: the operator pattern is wrapped in a non-capturing group and matched as `^(?:pattern)$`. This means the pattern must match the **entire** request path, not just a prefix — preventing ambiguous overlaps between regex routes while preserving top-level alternation such as `/api|/admin`
- To allow sub-path matching (prefix-style regex), end your pattern with `.*` (e.g., `~/api/v[0-9]+/.*`)
- Patterns are **pre-compiled** at config load time using the Rust `regex` crate — invalid patterns are caught during config validation, not at request time
- Named capture groups use `(?P<name>pattern)` syntax

### Named Capture Extraction

Named captures are extracted on match and forwarded to backends and plugins:

- **Request headers**: `x-path-param-{name}: value` (e.g., `x-path-param-user_id: 42`). Header names are case-insensitive, and the capture name is preserved verbatim after the prefix
- **Plugin context**: `ctx.metadata["path_param.user_id"]`

### Path Overrides

A plugin path rewrite replaces the routed path and invalidates its strip offset.
The rewritten path is not stripped again, even when `strip_listen_path` is true.
Ordinary rewrites still compose with the selected target's `path`, or the proxy's
`backend_path` when the target omits one. A prefix rewrite preserves the unmatched
suffix: rewriting `/public` to `/users` sends `/public/list` as `/users/list`
before backend base-path composition. Absolute provider overrides additionally
clear the proxy base path through the existing route-override contract.

URL construction refuses offsets outside the path or inside a UTF-8 character;
it does not clamp them to a different forwarded path. Rejection diagnostics use
the router's matched offset (or zero after a rewrite), just like dispatch.

### Path Stripping with Regex Routes

When `strip_listen_path: true`, the **matched portion** of the path is stripped (not the literal pattern text). With full-path anchoring, the entire path is the matched portion:

| Request Path | Regex Pattern | Match? | Remaining (to backend) |
|---|---|---|---|
| `/users/42/orders` | `/users/[^/]+/orders` | Yes | `/` |
| `/users/42/orders/pending` | `/users/[^/]+/orders` | **No** (blocked by `$`) | — |
| `/users/42/orders/pending` | `/users/[^/]+/orders(/.*)?` | Yes | `/` |

To match a prefix-shaped route and strip the full dynamic match, use an optional trailing group:

```yaml
listen_path: "~/users/[^/]+/orders(/.*)?"
strip_listen_path: true
backend_path: "/internal"
# /users/42/orders → backend receives /internal/
# /users/42/orders/pending → backend receives /internal/
```

Because regex routes strip the whole matched range, the example above does not preserve `/pending` for the backend. If the backend needs the dynamic suffix, set `strip_listen_path: false` and let the backend consume the full request path, or model the suffix as separate routes.

For exact-path proxying (the default with full-path anchoring):

```yaml
listen_path: "~/users/[^/]+/orders"
strip_listen_path: true
backend_path: "/internal"
# /users/42/orders → backend receives /internal/
# /users/42/orders/pending → no match (404)
```

## Cache Architecture

The router uses **two separate DashMap cache partitions**:

| Cache | Contents | Purpose |
|-------|----------|---------|
| **Prefix cache** | Prefix matches + negative (no-match) entries | Protect high-hit prefix entries from eviction |
| **Regex/exact cache** | Regex matches, exact-path matches, and regex path-param matches | Isolate high-cardinality regex paths (e.g., `/users/{uuid}/...`) |

This separation prevents regex routes with highly variable path segments (UUIDs, timestamps) from filling the cache and evicting frequently-hit prefix route entries.

Both caches are bounded by `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (default `0`, auto-resolved to at least 10,000 entries) and use frequency-aware sample eviction when a partition reaches the threshold. Config changes publish the route table, its generation, and generation-bound Gateway-listener admission in one request epoch. A new epoch starts listener admission pending, so listener-scoped routes fail closed until the exact config generation is reconciled; acknowledging that decision advances the route-cache generation so neither positive nor negative entries survive the admission transition.

## Performance Characteristics

| Scenario | Cost |
|----------|------|
| Cache hit (any route type) | O(1) DashMap lookup |
| Prefix-only deployment (no regex routes) | Regex route-table scan is skipped by `has_regex_routes` |
| Cache miss, exact path match found | O(1) HashMap lookup within the matched host tier |
| Cache miss, prefix match found | O(path depth) segment-boundary HashMap walk within the matched host tier |
| Cache miss, regex match found | Prefix/exact checks plus one `RegexSet` pass for the matched host tier; captures run only for the winning regex |
| Cache miss, no match (404) | O(all routes in all tiers) — negative entry cached for future O(1) |
| Config reload | Route table, generation, and pending listener admission published as one RequestEpoch; matching admission acknowledgement advances cache generation |

All route table operations (sorting, regex compilation, host partitioning) happen at config load time, never on the request hot path. The request path uses one lock-free `RequestEpoch` load for the route table and its listener admission, followed by `DashMap::get()` for cached lookups.

## HTTP method admission

After a proxy is matched, `allowed_methods` (when configured) rejects any other method with **405 Method Not Allowed**. RFC 9110 §15.5.6 requires an `Allow` header listing the methods the resource currently supports. The gateway sets `Allow` to the proxy's configured methods, uppercased, in config order (stable, not sorted). Surrounding whitespace is trimmed at file/runtime and Admin normalize so a validated `" GET "` both admits GET and advertises `Allow: GET`. HTTP/1.1, HTTP/2, and HTTP/3 share that formatting and admission comparison. Response-header plugins may decorate the 405, but they cannot remove or replace that gateway-owned `Allow` value.

Two protocol-level filters run **before** route match and also return 405:

| Request | Reason |
|---------|--------|
| `TRACE` | Cross-Site Tracing (XST) prevention |
| Non-WebSocket `CONNECT` | No tunnel is established that would bypass proxy routing. On HTTP/3 this is plain CONNECT with no `:protocol`, or a registered `:protocol` this gateway does not implement (for example `webtransport`). RFC 9298 CONNECT-UDP is a separate profile (501 when disabled). |

Those 405s carry a static `Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`. TRACE and CONNECT are omitted because the same filter rejected them. There is no matched proxy yet, so `allowed_methods` cannot supply the list.

### Max-Forwards on OPTIONS

RFC 9110 §7.6.2 requires an intermediary that forwards `OPTIONS` to process the client's `Max-Forwards` hop budget. The gateway takes one checked decision per inbound request, shared by the HTTP/1.1, HTTP/2, native HTTP/3, and HTTP/3-to-HTTP/1.1/2 bridge frontends. It runs after authentication, authorization, the `cors` plugin's local preflight answer, and every `before_proxy` transform, and before any backend transport is dialed:

| `OPTIONS` request field | Gateway behaviour |
|---|---|
| absent | Forwarded unchanged (existing behaviour). |
| `Max-Forwards: 0` | The gateway is the final recipient: it responds **204 No Content** with an `Allow` field and never contacts the origin. |
| `Max-Forwards: N`, N ≥ 1 | Forwarded with `Max-Forwards: N-1`. |
| malformed (`abc`, `-1`, `1.0`, empty) or repeated field lines (`1, 1`) | **400 Bad Request** with `{"error":"Invalid Max-Forwards header"}`; the origin is never contacted. |

- The value is parsed as `1*DIGIT` into an unsigned 32-bit integer with saturation, so no digit count can overflow or panic. A value above 4294967295 is treated as that maximum (RFC 9110 §7.6.2 lets an intermediary forward the greatest value it can process) and goes out as 4294967294.
- `Max-Forwards` is not a list-based field (RFC 9110 §5.3). Repeated field lines are refused rather than combined or picked from, even when their values agree: a request whose hop budget cannot be read unambiguously is not forwarded with a reset or guessed budget.
- The decrement happens exactly once per inbound request, not once per retry attempt. Retries reuse the same outbound header map, and every transport (reqwest, direct HTTP/2, the HTTP/3 client, HBONE, and mesh-mTLS replay) layers that map over any raw header snapshot, so the client's original value cannot reappear on the wire.
- `Allow` on the 204 lists the proxy's `allowed_methods` (uppercased, config order) when configured, otherwise the static protocol-level list above.
- A protected route still returns its normal 401/403 before the hop budget is consulted, a CORS preflight carrying `Max-Forwards: 0` is still answered by the `cors` plugin, and response-phase plugins decorate the 204/400 exactly as they decorate any other gateway-local rejection. Transaction logs record `metadata.rejection_phase = "max_forwards"`.
- Only `OPTIONS` is processed. Every other method keeps its existing behaviour and forwards the field unchanged; `TRACE` stays rejected with 405 before routing.

## WebSocket Origin admission

Browsers do not apply the CORS protocol to WebSocket upgrade handshakes. The `cors`
plugin runs only on HTTP and gRPC (including gRPC-Web) request-policy chains, so a
strict `cors.allowed_origins` list does **not** automatically protect WebSocket
upgrades on the same proxy.

Cross-Site WebSocket Hijacking (CSWSH) is enforced separately through the per-proxy
`allowed_ws_origins` field (RFC 6455 §10.2). When `allowed_ws_origins` is **non-empty**,
every WebSocket upgrade — HTTP/1.1 `Upgrade: websocket`, HTTP/2 Extended CONNECT, and
HTTP/3 Extended CONNECT — must carry an `Origin` header that matches one of the listed
values (case-insensitive; default ports normalized). Missing or disallowed origins
receive **403 Forbidden** with body `{"error":"WebSocket Origin not allowed"}` before
backend dispatch. When `allowed_ws_origins` is **empty** (the default), no Origin check
runs and any browser origin may upgrade. Entries are literal origins of the form
`scheme://host[:port]`. The opaque origin `null` and `*` are rejected by Admin API
create/update (POST/PUT/PATCH proxies, batch, restore) and `ferrum-edge validate` because
unrelated sandboxed and local documents can all produce `Origin: null`, while `*` is not
a wildcard. The validation error states empty list = allow all origins. Existing
file/database/CP rows that still contain unsupported entries keep loading and emit one
warning per proxy; neither `null` nor `*` authorizes an origin at runtime.

Operators who configure a strict `cors` allowlist on a proxy that also serves WebSocket
traffic should set `allowed_ws_origins` to the same origin set. The gateway logs a
composition warning at config load when a proxy has strict CORS but an empty
`allowed_ws_origins` list. See [cors_plugin.md](cors_plugin.md#websocket-upgrades-and-cswsh).

Example:

```yaml
proxies:
  - id: api
    listen_path: /api
    backend_scheme: https
    backend_host: backend.internal
    allowed_ws_origins:
      - https://app.example.com
plugin_configs:
  - id: cors-prod
    plugin_name: cors
    config:
      allowed_origins:
        - https://app.example.com
      allow_credentials: true
    scope: global
    enabled: true
```

## WebSocket compression (`permessage-deflate`)

By default the gateway strips the client's `Sec-WebSocket-Extensions` offer before
the backend handshake, so RFC 7692 `permessage-deflate` is never negotiated end to
end and every message stays inspectable by WebSocket frame plugins
(`websocket_permessage_deflate: strip`). Two opt-in modes enable compression:
`passthrough` (below) and gateway-terminated `terminate`
([below](#gateway-terminated-compression-terminate)).

A proxy can opt into `websocket_permessage_deflate: passthrough`. The client's
`permessage-deflate` offer elements then reach the backend unchanged, and the
backend's `permessage-deflate` answer reaches the client unchanged, on HTTP/1.1,
HTTP/2 Extended CONNECT, and HTTP/3 Extended CONNECT. Any other extension token in
the offer or answer is still stripped. A session that actually negotiates the
extension is relayed as raw bytes (the gateway frame parser cannot decode
compressed frames), so `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` and the
incomplete-message bounds do not apply to it — idle, lifetime, drain, and
connection limits still do. A session whose backend declines the offer keeps the
normal relay.

Passthrough is refused by config validation (Admin API 400, file-mode startup,
database / CP load) on any proxy that has a plugin requiring the parsed WebSocket
relay — `waf`, `ws_frame_logging`, `ws_message_size_limiting`, `ws_rate_limiting`,
or a custom plugin whose `requires_websocket_framing()` returns `true` — whether it
is attached directly, through a proxy group, or inherited from a global plugin
config. As a second guard, the runtime keeps stripping the offer whenever the
proxy's live plugin chain requires framing. Stream proxies (`tcp`/`tcps`/`udp`/
`dtls`) must keep `strip`.

In CP/DP deployments, upgrade every DP before enabling passthrough on the CP. A
proxy rejects unknown fields, so a DP that predates `websocket_permessage_deflate`
rejects the whole namespace snapshot from a CP that sends it.

### Gateway-terminated compression (`terminate`)

`websocket_permessage_deflate: terminate` keeps compression and inspection on the
same route. The gateway is an RFC 7692 endpoint on each leg, and the two legs
negotiate independently, on HTTP/1.1, HTTP/2 Extended CONNECT, and HTTP/3
Extended CONNECT alike:

- **Client leg.** The gateway answers the first valid `permessage-deflate`
  element of the client's offer itself. It honors `server_no_context_takeover`
  and `server_max_window_bits` (echoing them in its answer) and never asks the
  client to limit its own window. Elements with unknown or duplicate parameters,
  or window bits outside 8–15, are declined; other extension tokens are dropped.
  A client that does not offer the extension gets an uncompressed leg.
- **Backend leg.** The backend receives the gateway's own offer,
  `Sec-WebSocket-Extensions: permessage-deflate`, whatever the client offered.
  The whole `Sec-WebSocket-Extensions` answer (every field line) must be one
  valid `permessage-deflate` element without `client_max_window_bits` (which the
  gateway did not offer); anything else — a foreign extension, a second element,
  a malformed list, or a non-ASCII value — fails the upgrade with 502
  (`rejection_phase: websocket_permessage_deflate`). A backend that sends no
  extension answer gets an uncompressed leg.

Every message is inflated before the shared frame relay parses it, so every frame
and body-inspecting plugin — the WAF WebSocket scanner, `ws_message_size_limiting`,
`ws_rate_limiting`, `ws_frame_logging`, custom `on_ws_frame` hooks — sees
plaintext, and none is refused on a `terminate` proxy. After the plugins run, the
gateway re-deflates each Text or Binary message toward a leg that negotiated
compression, with that leg's context-takeover choice. Control frames are never
compressed, and a compressed message may arrive fragmented (RSV1 on its first
frame only). RSV1 on a control or continuation frame, or on a leg that did not
negotiate the extension, fails the connection exactly as without it.

Decompression is bounded per leg:

- a compressed wire frame may not exceed the frame ceiling
  (`FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES`, or a lower `ws_message_size_limiting`
  `max_frame_bytes`), and one frame may not inflate past it;
- a message may not inflate past
  `FERRUM_WEBSOCKET_PERMESSAGE_DEFLATE_MAX_MESSAGE_BYTES` (default 1 MiB, never
  above the reassembled-message ceiling of 4x the frame ceiling or a lower
  `max_message_bytes`; `0` explicitly opts into that ceiling);
- inflation stops one byte past a limit and the session closes with 1009 in both
  directions; corrupt compressed data closes with 1007;
- buffers grow only with bytes that arrived: a compressed frame's declared length
  reserves nothing, and an inflated frame never holds more than its limit plus
  one byte;
- the LZ77 window is the RFC 7692 maximum of 32 KiB. Each negotiated leg holds a
  DEFLATE decompressor (about 50 KiB) and a 16 KiB read buffer from the start,
  and a compressor (about 240 KiB) from the first message the gateway compresses
  toward it, for the life of the session. A session with both legs negotiated
  therefore holds about 0.6 MB, plus buffers bounded by the frame and message
  ceilings. Size connection limits with that in mind.

The message bound is also the amplification bound. DEFLATE expands up to about
1032:1, so a peer can make the gateway inflate, inspect (every frame and body
plugin, the WAF included), and re-compress a whole message for about 1/1000 of
its size on the wire, and repeat that for every message. With the 1 MiB default
that is about 1 KiB of wire data per 1 MiB of work. Setting the bound to `0`
raises it to the reassembled-message ceiling — 64 MiB with the default 16 MiB
frame size — where about 64 KiB of compressed data forces 64 MiB of memory and
on the order of a second of CPU per message. Keep the bound as low as the
application's largest legitimate message allows.

Frame and message ceilings, fragment metering, and the incomplete-message bounds
all apply to the decompressed messages the plugins see, and the wire
fragmentation is preserved. Terminate costs CPU on both legs; a session whose
peers both decline compression uses the ordinary relay (including
`FERRUM_WEBSOCKET_TUNNEL_MODE`), while a negotiated session always uses the parsed
relay. Byte counters and `ws_frame_logging` sizes are decompressed sizes. As with
`passthrough`, upgrade every DP, and every database-mode node sharing the DB,
before enabling `terminate`: a DP that predates the value rejects the namespace
snapshot, and a database-mode node that predates it rejects the proxy row.

```yaml
proxies:
  - id: chat
    listen_path: /chat
    backend_scheme: http
    backend_host: chat.internal
    backend_port: 8080
    websocket_permessage_deflate: terminate
```

```yaml
proxies:
  - id: chat
    listen_path: /chat
    backend_scheme: http
    backend_host: chat.internal
    backend_port: 8080
    websocket_permessage_deflate: passthrough
```
