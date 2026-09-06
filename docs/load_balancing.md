# Load Balancing

Ferrum Edge provides built-in load balancing to distribute traffic across multiple backend targets. This feature allows you to define **upstreams** — groups of backend servers — and attach them to proxy routes for automatic traffic distribution, health checking, and failover.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Upstreams](#upstreams)
- [Targets](#targets)
- [Subset Routing](#subset-routing)
- [Load Balancing Algorithms](#load-balancing-algorithms)
  - [Round Robin](#round-robin)
  - [Weighted Round Robin](#weighted-round-robin)
  - [Least Connections](#least-connections)
  - [Least Latency](#least-latency)
  - [Consistent Hashing](#consistent-hashing)
  - [Random](#random)
  - [Passthrough](#passthrough)
- [Health Checks](#health-checks)
  - [Active Health Checks](#active-health-checks)
  - [Passive Health Checks](#passive-health-checks)
  - [Combined Health Checks](#combined-health-checks)
  - [Fallback When All Unhealthy](#fallback-when-all-unhealthy)
- [Client Observability Headers](#client-observability-headers)
- [Retry Logic](#retry-logic)
- [Circuit Breaker](#circuit-breaker)
- [Configuration Reference](#configuration-reference)
- [Examples](#examples)

## Overview

The load balancing architecture consists of:

1. **Upstreams** — Named groups of backend targets with a load balancing algorithm.
2. **Targets** — Individual backend servers within an upstream, each with a host, port, optional weight, and optional path override. Stored internally as `Arc<UpstreamTarget>` so that per-request target selection is a cheap pointer bump (~5ns atomic increment) instead of cloning the full struct.
3. **Health Checks** — Active (periodic probes) and passive (response monitoring) checks that automatically exclude unhealthy targets.
4. **Retry Logic** — Automatic retries to alternative targets when a request fails.
5. **Circuit Breaker** — Prevents cascading failures by temporarily stopping requests to failing backends.

Load balancers are rebuilt atomically on configuration changes (file reload via SIGHUP, database polling, or control plane push) — no requests are dropped during reconfiguration. `TargetSelection.target` is `Arc<UpstreamTarget>`, so callers access fields via auto-deref without cloning.

### DNS Integration

Upstream target hostnames are automatically resolved through the gateway's [central DNS cache](dns_resolver.md). This means:

- **Startup warmup**: All upstream target hostnames are pre-resolved alongside proxy backend hostnames before the gateway accepts traffic — no cold-cache DNS lookups on the first request. After DNS warmup, [connection pool warmup](connection_pooling.md#connection-pool-warmup) pre-establishes backend connections to each upstream target for HTTP-family pools.
- **Hot-path efficiency**: DNS resolution never happens in the request hot path. All HTTP clients use a custom `DnsCacheResolver` that transparently routes lookups through the in-memory cache.
- **Background refresh**: DNS entries for upstream targets are proactively refreshed at a configurable TTL threshold (default 90%, tunable via `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT`), just like proxy backend hostnames.

## Quick Start

Add an `upstreams` section to your configuration and reference it from a proxy via `upstream_id`:

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"   # fallback if upstream not found
    backend_port: 8080
    strip_listen_path: true
    upstream_id: "api-servers"  # links to the upstream below

upstreams:
  - id: "api-servers"
    name: "API Server Pool"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
      - host: "10.0.1.3"
        port: 8080
```

When `upstream_id` is set on a proxy, the gateway selects a target from the upstream instead of using `backend_host`/`backend_port` directly. If the upstream is not found, the proxy falls back to `backend_host`/`backend_port`.

## Upstreams

An upstream defines a group of backend targets with load balancing configuration.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | — | Unique identifier for the upstream |
| `name` | string | No | — | Human-readable name |
| `targets` | array | Yes | — | List of backend targets |
| `algorithm` | string | No | `round_robin` | Load balancing algorithm |
| `hash_on` | string | No | `ip` | Hash key source for consistent hashing: `ip`, `header:<name>`, or `cookie:<name>` |
| `hash_on_cookie_config` | object | No | — | Cookie attributes for `cookie:<name>` sticky sessions (see [Consistent Hashing](#consistent-hashing)) |
| `health_checks` | object | No | — | Health check configuration |
| `subsets` | array | No | — | Named target subsets selected by a proxy's `upstream_subset` |

## Targets

Each target represents a single backend server within an upstream.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | Yes | — | Backend server hostname or IP |
| `port` | integer | Yes | — | Backend server port |
| `weight` | integer | No | `1` | Relative weight for weighted algorithms |
| `tags` | object | No | `{}` | Key-value metadata tags |
| `path` | string | No | — | Path prefix that overrides the proxy's `backend_path` when this target is selected |

### Weight

The `weight` field controls how much traffic a target receives relative to others in weighted algorithms. A target with `weight: 5` receives 5x the traffic of a target with `weight: 1`. Weights are ignored by non-weighted algorithms (round robin, least connections, random).

```yaml
targets:
  - host: "10.0.1.1"
    port: 8080
    weight: 5    # receives 5/6 of traffic
  - host: "10.0.1.2"
    port: 8080
    weight: 1    # receives 1/6 of traffic
```

### Path

The optional `path` field on a target overrides the proxy's `backend_path` when that target is selected by the load balancer. This allows different targets within the same upstream to serve different backend path prefixes.

## Subset Routing

Upstreams can define named `subsets` for Istio DestinationRule-style routing. A proxy selects a subset with `upstream_subset`; the referenced name must exist on the proxy's `upstream_id`, and the gateway rejects invalid references during config/admin validation.

Subset matching is exact label matching: a target belongs to a subset when its `tags` contain every key/value pair from the subset's `labels`. Subsets can optionally override the parent upstream's load-balancing algorithm with `traffic_policy.load_balancer_algorithm`, and subset-scoped consistent hashing can set `traffic_policy.hash_on` using the same `ip`, `header:<name>`, or `cookie:<name>` syntax as upstream-level `hash_on`. Weighted round-robin state and consistent-hash rings are isolated per subset, so subset traffic does not perturb parent or sibling subset selection.

If all targets in a defined subset are unhealthy, Ferrum falls back to the parent upstream and marks the selection degraded. Unknown subset names never silently fall through to the full upstream.

```yaml
proxies:
  - id: "reviews-canary"
    listen_path: "/reviews"
    upstream_id: "reviews"
    upstream_subset: "v2"

upstreams:
  - id: "reviews"
    algorithm: round_robin
    targets:
      - host: "reviews-v1.default.svc"
        port: 8080
        tags: {version: "v1"}
      - host: "reviews-v2.default.svc"
        port: 8080
        tags: {version: "v2"}
    subsets:
      - name: "v2"
        labels: {version: "v2"}
        traffic_policy:
          load_balancer_algorithm: consistent_hashing
          hash_on: "header:x-session"
```

```yaml
upstreams:
  - id: "versioned-api"
    algorithm: weighted_round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
        path: "/v2/api"    # requests to this target use /v2/api as the path prefix
        weight: 9
      - host: "10.0.1.2"
        port: 8080
        path: "/v1/api"    # requests to this target use /v1/api as the path prefix
        weight: 1
```

When `path` is not set on a target, the proxy's `backend_path` is used as the path prefix (or no prefix if `backend_path` is also unset). When `path` is set, it fully replaces `backend_path` — the two are not concatenated.

## Load Balancing Algorithms

### Round Robin

**Algorithm:** `round_robin` (default)

Distributes requests evenly across all healthy targets in sequential order. Each target gets an equal share of traffic regardless of weight.

**Concurrency model:** Parent, port-override, and locality-distribute selection counters reuse the same 16 cache-line-padded per-thread shards as WRR (`wrr_counter_shard`). Each worker advances its own shard, so small healthy sets no longer bounce a single shared cache line on every pick. Shards are initialized with distinct golden-ratio phase offsets (same stride family as non-zero WRR schedules) so a synchronized first wave does not lockstep onto one RR target, random seed, or distribute bucket. Workers do not share one global interleaving; each shard is itself a full round-robin (or random / warm-up RR) walk, so long-run ratios stay even and a single worker's ticket stream remains deterministic within its shard.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
      - host: "10.0.1.3"
        port: 8080
```

With 3 targets and 30 requests, each target receives exactly 10 requests.

**Best for:** Homogeneous backends with equal capacity.

### Weighted Round Robin

**Algorithm:** `weighted_round_robin`

Uses the smooth weighted round-robin algorithm (the same algorithm used by NGINX) to distribute traffic proportionally based on target weights. This produces a well-interleaved distribution rather than burst patterns.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: weighted_round_robin
    targets:
      - host: "large-server.example.com"
        port: 8080
        weight: 5
      - host: "small-server.example.com"
        port: 8080
        weight: 1
```

With weights 5:1 and 60 requests, `large-server` receives 50 requests and `small-server` receives 10.

The smooth WRR algorithm ensures the distribution is interleaved. For example, with weights 5:1, the sequence is approximately: `L, L, L, L, S, L, L, L, L, L, S, L, ...` rather than `L, L, L, L, L, S, L, L, L, L, L, S, ...`.

**Concurrency model:** Each WRR lane (parent upstream, subset, or port override) keeps a **bounded multi-fingerprint cache** of precomputed smooth-WRR orders behind `ArcSwap` slots (8 slots). Every cached healthy set owns an independent set of 16 cache-line-padded `AtomicU64` selection-counter shards, preventing alternating per-proxy health or retry fingerprints from aliasing onto one counter parity and preventing small healthy sets from bouncing a single shared cache line under concurrency. Threads are assigned across a fixed 16-shard bound, so high worker counts may share shards without growing per-lane memory. Steady-state picks are wait-free across Tokio workers (slot scan + sharded atomic counter). Each shard walks the same precomputed smooth-WRR order, so uncapped cached periods match configured weights without a per-request blocking mutex; workers intentionally do **not** share one global interleaving. On a cache miss, a publisher uses `try_lock` to fill empty slots immediately and to rate-sample replacements once the cache is full; contending missers and unsampled misses never build an ephemeral smooth schedule — they take an allocation-free O(candidate) weighted lottery (or all-zero round-robin) over eligible positive-weight targets. That miss fallback preserves reachability and unhealthy/excluded-target safety but does **not** claim exact smooth-WRR interleaving. Smooth schedule construction is additionally bounded by an explicit work budget (`schedule_steps × positive_candidates`, capped at 8192 × 128): when a pathological candidate × period product would exceed that budget, the publisher stores an exact-key lottery-only sentinel so the same fingerprint does not repeatedly attempt the quadratic NGINX build; matching hits then reuse the allocation-free lottery / all-zero RR path. Schedules are a pure function of exact healthy-set membership and immutable target weights on the current `LoadBalancer` generation (config reload swaps the balancer `Arc`), so no invalidate flag is required and the >128-target path cannot reuse a schedule after a hash collision. Each shard counter wraps with `% order.len()` and does not bias ratios. Exact normalized periods up to 8192 entries are retained; larger periods are proportionally apportioned into 8192 entries while reserving at least one entry for every positive-weight target, then smoothed over that complete bounded period when the work budget allows. Those capped schedules are bounded approximations of pathological exact periods (they retain every positive-weight target but do not claim exact configured ratios when the uncapped period would exceed 8192). At most a fixed number of healthy-set schedules are retained per lane. Hosted CI's WRR contention microbenchmark therefore applies its mandatory parallel-throughput floor to mid/large cardinalities (32/129): a skewed 4-target 5:1:1:1 fixture still runs, but concurrent clone/drop of the heavy `Arc<UpstreamTarget>` is an output-refcount hotspot rather than a schedule-mutex detector.

Subset and port WRR lanes remain isolated from each other and from the parent lane.

**Best for:** Backends with unequal capacity (e.g., different hardware, different resources).

### Least Connections

**Algorithm:** `least_connections`

Routes each request to the target with the fewest active connections. Connection counts are tracked per target and updated atomically as connections open and close.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: least_connections
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
```

**Best for:** Long-lived connections or backends with variable response times.

#### Stream-family proxies (TCP / UDP / DTLS)

`least_connections` is fully accounted on the stream family. A `tcp` / `tcp_tls`
connection holds the balancer's active-connection guard from backend selection
until the relay ends (including across connect-phase retry rotation, which moves
the count to the new target rather than leaving a residue on the abandoned one),
and a `udp` / `dtls` session holds it for the session lifetime, releasing it on
idle expiry, authorization-lifetime expiry, and listener shutdown.

One consequence of the strict lowest-index tie-break: a cold upstream whose
connections are opened and closed strictly one at a time sees every target at
zero active connections at selection time, so it keeps starting from the first
healthy target. Concurrent or long-lived connections — the workload this
algorithm exists for — distribute normally.

`least_latency` on stream proxies is fed by active health-check probe RTT and,
on TCP, by the backend connect RTT (a failed dial records the same synthetic
penalty sample the HTTP path uses). Connect RTT is a **passive** sample and
follows the same precedence rule as HTTP TTFB: when active health-check probes
are running for the upstream, their controlled RTTs win and passive samples are
not recorded. UDP/DTLS has no per-request round-trip
sample, so per-port DestinationRule `LEAST_LATENCY` overrides remain refused on
stream proxies with an explicit `UnsupportedStreamPolicy` error rather than
degrading silently. Per-port `LEAST_CONN` overrides are supported.

### Least Latency

**Algorithm:** `least_latency`

Routes each request to the target with the lowest observed response latency, using an Exponentially Weighted Moving Average (EWMA) to smooth out noise and adapt to changing conditions. This algorithm automatically discovers which backend is "closest" (lowest round-trip time) and sends the majority of traffic there, while keeping other targets as fallbacks.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: least_latency
    targets:
      - host: "us-east.backend.internal"
        port: 8080
      - host: "us-west.backend.internal"
        port: 8080
      - host: "eu-west.backend.internal"
        port: 8080
```

**How it works:**

1. **Warm-up phase**: When the upstream is first loaded (or after a config reload), the algorithm uses round-robin to distribute traffic evenly across all healthy targets. Each healthy target must accumulate at least 5 latency samples before latency-based selection begins for that target. Successful responses record real TTFB/probe RTT; **failed dispatches** (connection errors and 5xx, when passive latency recording is active) also count toward the warm-up threshold using a synthetic high-latency penalty sample so a target that fails every request exits warm-up instead of remaining permanently preferred. If a target is unhealthy at startup, warm-up proceeds with the healthy targets only — the unhealthy target does not block the algorithm from advancing.

2. **Steady-state**: After warm-up, each request is routed to the target with the lowest EWMA latency. The EWMA is updated after every successful backend response using the formula:

   ```
   ewma = 0.3 × new_sample + 0.7 × previous_ewma
   ```

   The smoothing factor (alpha = 0.3) means recent measurements account for ~30% of the average, providing a good balance between responsiveness to latency changes and stability against transient spikes.

3. **Latency sources**: Latency is measured from one of two sources, with active taking precedence:
   - **Active (health check probes)**: When active health checks are configured, the RTT of each successful probe is used as the latency signal. Active probes provide consistent, controlled measurements that reflect pure network round-trip time without variable application processing overhead. **When active health checks are configured, passive latency recording is disabled.**
   - **Passive (proxy traffic)**: When no active health checks are configured, time-to-first-byte (TTFB) from each proxied request is used instead. This requires no configuration but includes application processing time in the measurement.

   Successful, non-error responses record real TTFB. Connection errors, timeouts, and 5xx responses do not record real TTFB (they would skew the EWMA toward fast-failing backends) but **do** count as warm-up samples with a penalty latency so persistently failing targets cannot monopolize selection.

4. **Mixed warm-up / late joiners**: When some healthy targets are warmed and others are not (late joiners, or targets that have not yet reached 5 samples), the algorithm **bounds exploration** of sub-threshold targets to a fixed fraction of selections (round-robin among unwarmed peers) instead of giving every unsampled target an unconditional score better than every warmed peer. This preserves fair warm-up for healthy late joiners without pinning all traffic onto a never-sampled or persistently failing target. Once every healthy candidate is warmed, selection is pure lowest-EWMA.

5. **Recovery**: When a target recovers from unhealthy status (via active or passive health checks), its EWMA is reset to the current minimum across all healthy targets and its sample count is set to the warm-up threshold. This means the recovered target immediately participates in latency-based selection (with an optimistic starting point) rather than forcing the entire upstream back into round-robin warm-up mode — and rather than re-entering the biased unsampled state. As real latency samples arrive, the EWMA converges to the target's true latency. The same seeding applies to passive timer recovery and active-probe recovery.

**Example: multi-region with automatic proximity routing**

```yaml
upstreams:
  - id: "global-api"
    algorithm: least_latency
    targets:
      - host: "api-us-east.internal"
        port: 8080
      - host: "api-us-west.internal"
        port: 8080
      - host: "api-eu.internal"
        port: 8080
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 5
        unhealthy_threshold: 3
      passive:
        unhealthy_status_codes: [500, 502, 503]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 30
```

In this setup, a gateway deployed in `us-east` will naturally route most traffic to `api-us-east.internal` (lowest latency), with `us-west` and `eu` as fallbacks. If `us-east` becomes slow or unhealthy, traffic automatically shifts to the next-lowest-latency target.

**Best for:** Multi-region deployments, backends with heterogeneous performance, latency-sensitive APIs, and scenarios where you want automatic proximity-based routing without manual weight tuning.

### Consistent Hashing

**Algorithm:** `consistent_hashing`

Routes requests to a target determined by a hash of a configurable key. The same key always maps to the same target, providing session affinity without server-side session state.

Uses 150 virtual nodes per target on a hash ring for uniform distribution.

#### Hash Key Sources

The `hash_on` field controls what value is used as the hash key. Header and
cookie names must use ASCII HTTP token syntax; whitespace, control bytes, and
separators such as `;`, `=`, and `:` are rejected at config admission.

| `hash_on` value | Description | Cookie injection |
|---|---|---|
| `ip` (default) | Hash on the client IP address | No |
| `header:<name>` | Hash on the value of a request header (e.g., `header:x-user-id`) | No |
| `cookie:<name>` | Hash on the value of a request cookie (e.g., `cookie:session`) | Yes — `Set-Cookie` is injected when the cookie is absent |

When the specified header or cookie is not present in the request, the gateway falls back to the client IP.

#### IP-based (default)

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: consistent_hashing
    hash_on: "ip"
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
```

#### Header-based

Route based on an arbitrary request header — useful for tenant-aware routing or gRPC metadata:

```yaml
upstreams:
  - id: "tenant-pool"
    algorithm: consistent_hashing
    hash_on: "header:x-tenant-id"
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
```

#### Cookie-based (sticky sessions)

When `hash_on` is `cookie:<name>`, the gateway establishes sticky sessions automatically:

1. **First request** (no cookie): The gateway selects a target using the client IP as a fallback key, then injects a `Set-Cookie` response header carrying an **opaque token bound to the target that served that response**. The token is an HMAC-SHA-256 authentication tag over the namespace-qualified upstream identity and the selected target's **sticky identity** (below), so predictable route and endpoint metadata cannot be used to forge a backend binding. The key is process-local and survives config reloads. After a process restart, or when a request reaches another replica, an old token is treated as stale and the client is transparently re-pinned through ordinary selection.
2. **Subsequent requests** (cookie present): The token is resolved through a per-upstream binding index that is materialized at config reload, returning the client to that **exact** target — not merely to a deterministic one.
3. **Fallback**: a cookie value that is malformed, oversized, scoped to another upstream (Gateway API materializes one route-scoped upstream per persistent route rule, so a token cannot steer across routes, Services, namespaces, or policies), stale after the backend was removed, outside the selected subset/port lane, or currently unhealthy is treated as **no session**: the request falls through to ordinary load-balanced selection and a fresh, correctly bound cookie is issued on the response. Health, subset, port, TLS, authorization, retry, and connection-limit semantics are never bypassed.
4. **Selected-port policy precedence**: the binding is resolved before the target is known, so it is validated against the initial dispatch port's lane. If the resolved target's own `dispatch_policy_port()` lane is a *different* policy lane whose effective algorithm is not consistent hashing, or whose `hash_on` names a different cookie, the binding **fails closed** to ordinary selection and reissue — a token can never reach past the per-port policy that governs the endpoint it names.
5. **Retry rotation**: an honored binding is normally not re-issued. But retry may rotate off the bound backend after selection already decided, and rotation does not necessarily eject the failed endpoint. Whenever the backend that actually served the response is not the one the request was bound to, the response carries a **fresh cookie for the serving backend**, so the next request does not go back to the endpoint that just failed. Gateway-synthesized rejections that dialed no backend (mesh-transport or egress screens on a rotated candidate) issue no cookie at all. This holds on HTTP/1.1 and HTTP/2, direct gRPC, WebSocket (including HTTP/2 extended CONNECT), native HTTP/3, the HTTP/3→HTTP and HTTP/3→gRPC cross-protocol bridges, and HTTP/3 WebSocket.

If the configured cryptographic provider cannot initialize the process-local authentication key, Ferrum fails closed for persistence: it builds no token bindings and emits no sticky `Set-Cookie`, while requests continue through ordinary load-balanced selection. The gateway emits one fixed `sticky_session_auth_disabled` diagnostic without key material or client-controlled values.

##### Sticky target identity

One route Upstream can legitimately contain the same network endpoint more than once — Gateway API fans several `backendRefs` into a single rule, so two entries can share a pod IP and dial port while naming **different Services**, **different declared Service ports** (and therefore different per-port policy lanes), or different subset labels. The binding must not collapse those, so the digest covers every stable target field that can change routing, policy, authorization, TLS selection, or target meaning:

| Field | Why it is part of the identity |
|-------|-------------------------------|
| `host`, `port` | The dial destination |
| declared Service port (internal `service_port_policy_key`) | Selects the per-port policy lane — its algorithm, `hash_on`, passive-health policy and TLS overlay — and records which Service port owns the target |
| `tags` | Subset membership (`subsets[].labels`), Service identity, and mesh provenance / HBONE dial facts |
| `locality` | Locality-LB tier and cross-cluster provenance |
| `path` | Per-target override of the proxy's `backend_path` |

`weight` is deliberately **not** part of the identity: it only sizes a target's share of *unbound* selections, so two entries differing solely in weight are interchangeable for an already-pinned session — and including it would make an ordinary canary weight shift invalidate every outstanding session cookie on the route. Transient health, ejection, and counter state are excluded so routine runtime state changes do not invalidate bindings within the serving process.

The encoding is canonical — tags are sorted by key, variable-length fields are length-prefixed, and optional fields carry a presence marker — so it never depends on map iteration order and no rearrangement of two fields can produce the same digest. Two targets that are identical in *all* of the above fields share one binding, which is safe because dispatching to either is indistinguishable. Digests are materialized when the balancer is built (config reload / service-discovery update), not per request.

##### Wildcard-hosted targets: configured identity vs. dial target

A target may be configured with a wildcard host (`*.example.com`) — mesh egress wildcard `ServiceEntry`s with `DNS`/`NONE` resolution are the common case. Such a target is **dialed** through a per-request copy whose host is the concrete request authority that matched the route, because connection, DNS resolution, SNI, and pool keying all need the real name. That per-request copy is a *dial target*, not an identity: it exists for one request and is not an entry the balancer was built from.

Session persistence is expressed in the **configured** selection identity. A response served through a wildcard target's dial copy mints the cookie for the configured `*.example.com` entry, so a returning client resolves that entry through the binding index and the request is re-concretized for its own dial. (Minting from the dial copy instead would emit a token that is not an index key at all: the client would miss on every return and be issued a new cookie forever, with no stickiness.)

Retry selection uses the same configured-vs-dial distinction for HTTP/H3. After a failed attempt the shared retry helper reconciles the just-tried dial clone back to its configured identity for exclusion (full routing/policy field set, not merely `host:port`), selects the next configured candidate, and re-concretizes it with the same validated inbound authority before returning — so callers receive a dial-ready target and never attempt DNS/SNI/pool use of a literal `*.example.com`. Missing or non-matching authority fails closed (no retry) rather than inventing a host. This mapping is independent of whether the upstream mints sticky cookies. TCP/stream connect-retry is separate: it never retained the selected `UpstreamTarget`, so it excludes by effective `(host, dial port, policy lane)` and drops every configured entry on that lane.

The mapping back to the configured entry matches the served target's host against configured wildcard patterns and requires **every other identity field above to be equal**, so two `backendRefs` sharing a wildcard suffix but naming different Services, policy lanes, subsets, localities, or path overrides keep separate bindings. A concrete configured entry always wins over a wildcard that also matches it, and a request authority that matches no configured wildcard is never handed another target's binding. Upstreams with no wildcard target — that is, nearly all of them — skip this entirely on the ordinary path.

```yaml
upstreams:
  - id: "session-pool"
    algorithm: consistent_hashing
    hash_on: "cookie:srv"
    hash_on_cookie_config:
      path: "/"
      ttl_seconds: 3600
      http_only: true
      secure: true
      same_site: "Lax"
    targets:
      - host: "app-1.internal"
        port: 8080
      - host: "app-2.internal"
        port: 8080
```

##### `hash_on_cookie_config` fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `"/"` | Cookie `Path` attribute; must start with `/` and cannot contain control bytes or `;` |
| `ttl_seconds` | integer | `3600` | Cookie `Max-Age` in seconds (1 hour default). Ignored when `session_cookie` is true |
| `session_cookie` | boolean | `false` | Omit `Max-Age` so the cookie is a browser session cookie (Gateway API `lifetimeType: Session`) |
| `domain` | string | — | Optional ASCII domain name (an optional leading dot is accepted) |
| `http_only` | boolean | `true` | Set the `HttpOnly` flag |
| `secure` | boolean | `false` | Set the `Secure` flag |
| `same_site` | string | — | `SameSite` attribute: `Strict`, `Lax`, or `None` |

If `hash_on_cookie_config` is omitted, sensible defaults are used (path `/`, 1 hour TTL, `HttpOnly` enabled).

The sticky session cookie is injected on HTTP, gRPC, and WebSocket (101 Upgrade) responses. For gRPC this covers both the buffered response path and the fully-streaming fast path (a server-streaming RPC with no response-body-buffering plugin), where the cookie is written into the initial HEADERS frame before it is committed.

When a target is removed or added, only a fraction of *unbound* keys are remapped — this minimizes cache invalidation across backends. Sessions already bound to a surviving target keep their exact target; sessions bound to the removed target re-select and are re-issued a cookie.

**Best for:** Session affinity, caching backends, stateful applications, multi-tenant routing.

### Random

**Algorithm:** `random`

Selects a target pseudo-randomly for each request using a counter-based hash. Provides statistical uniformity over large request volumes without requiring any state.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: random
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
```

**Best for:** Simple use cases where no specific distribution pattern is needed.

### Passthrough

**Algorithm:** `passthrough`

Dials the request's captured original destination instead of load balancing, mirroring Istio's `loadBalancer.simple=PASSTHROUGH`. This is only meaningful on the **service-mesh capture data path**, where the original destination is captured via `SO_ORIGINAL_DST` (TCP REDIRECT). When the captured destination matches a target in the upstream's pool, that target is dialed directly (bypassing the load balancer); the selected target still respects active and passive health, so an ejected original-destination target falls back to round-robin among healthy targets. When no original destination is available (any non-mesh / non-captured path, including HTTP/3) or it matches no pool target, selection falls back to round-robin (with a warning).

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: passthrough
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
```

**Best for:** Mesh upstreams whose clients address concrete pod IPs and expect the proxy to preserve that destination. Outside the mesh capture path it behaves as `round_robin`. See [mesh DestinationRule translation](mesh.md) for the Istio `PASSTHROUGH` mapping.

## Health Checks

Health checks automatically detect and exclude unhealthy targets so traffic is only routed to healthy backends. Ferrum Edge supports both active and passive health checks, which can be used independently or together.

### Active Health Checks

Active health checks periodically send HTTP probes to each target and track consecutive successes/failures against configurable thresholds.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 10
        timeout_ms: 5000
        healthy_threshold: 3
        unhealthy_threshold: 3
        healthy_status_codes: [200, 302]
        use_tls: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_path` | string | `/health` | HTTP path for health probe requests |
| `interval_seconds` | integer | `10` | Seconds between health check probes |
| `timeout_ms` | integer | `5000` | Per-probe timeout in milliseconds |
| `healthy_threshold` | integer | `3` | Consecutive successes before marking healthy |
| `unhealthy_threshold` | integer | `3` | Consecutive failures before marking unhealthy |
| `healthy_status_codes` | array | `[200, 302]` | HTTP status codes considered healthy |
| `use_tls` | boolean | `false` | Use HTTPS for health probe requests instead of HTTP |

**How it works:**

1. A background task is spawned for each target in the upstream.
2. Every `interval_seconds`, the task sends an HTTP GET to `http://<host>:<port><http_path>` (or `https://` when `use_tls: true`).
3. If the response status code is in `healthy_status_codes`, it counts as a success.
4. After `unhealthy_threshold` consecutive failures (bad status code, timeout, or connection error), the target is marked **unhealthy** and excluded from load balancing.
5. After `healthy_threshold` consecutive successes, the target is marked **healthy** again and re-included.

**Connection pooling:** Active health check probes share a single HTTP client configured with the gateway's global connection pool settings (keep-alive, idle timeout, HTTP/2, TCP keep-alive). This means health check connections behave like regular proxy traffic and benefit from connection reuse.

**TLS:** Health probes accept self-signed certificates by default since backends in internal environments often use self-signed certs.

### Passive Health Checks

Passive health checks monitor the HTTP response status codes from actual proxied requests. No additional probe traffic is generated.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
    health_checks:
      passive:
        unhealthy_status_codes: [500, 502, 503, 504]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 30
        healthy_after_seconds: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `unhealthy_status_codes` | array | `[500, 502, 503, 504]` | Status codes that count as failures |
| `unhealthy_threshold` | integer | `3` | Windowed failures, or consecutive failures when `consecutive_error_mode=true`, required to mark unhealthy |
| `unhealthy_window_seconds` | integer | `30` | Time window for windowed failure counting; not consulted in consecutive mode |
| `healthy_after_seconds` | integer | `30` | Seconds before an unhealthy target is automatically restored (0 to disable) |
| `max_ejection_percent` | integer/null | `null` | Maximum percentage of targets that may remain passively ejected; uses Envoy's integer prospective-ejection gate, which can permit zero ejections in a small pool; null is uncapped |
| `gateway_error_codes` | array/null | `null` | Reserved DestinationRule gateway-error bucket; validated and persisted but not yet applied |
| `split_external_local_origin_errors` | boolean/null | `null` | Reserved separate local/external-origin buckets; validated and persisted but not yet applied |
| `consecutive_error_mode` | boolean | `false` | Evaluate the threshold against a consecutive failure streak; one success resets it |
| `consecutive_5xx_ejection_disabled` | boolean | `false` | Ignore configured unhealthy status codes and connection errors for this detector (Istio `consecutive5xxErrors: 0` sentinel) |

**How it works:**

1. After each proxied request, the response status code is reported to the health checker.
2. Unless `consecutive_5xx_ejection_disabled=true`, a failure is recorded when
   **either** condition is true:
   - The status code is in `unhealthy_status_codes` (e.g., backend returned 500)
   - The request was a **connection error** — TCP connection refused, read timeout, DNS resolution failure, or TLS handshake error. These always count as failures regardless of `unhealthy_status_codes`.
3. In the default windowed mode, old failures outside
   `unhealthy_window_seconds` are cleaned up. With
   `consecutive_error_mode=true`, the timestamp ring is not touched; the
   consecutive streak resets to zero on one success.
4. The target is marked **unhealthy** when the active mode's count reaches
   `unhealthy_threshold`. If `max_ejection_percent` is set, selection keeps
   a prospective next ejection only when
   `(currently_ejected + 1) × 100 / total_targets <= max_ejection_percent`
   (integer division), and re-admits the earliest excess ejections first.
   Active-health failures are never re-admitted by this passive cap.
5. Recovery happens via two mechanisms:
   - **Automatic recovery timer**: After `healthy_after_seconds`, the target is automatically restored to the rotation with a clean slate — similar to a circuit breaker's half-open state. If it immediately fails again, passive checks will re-mark it unhealthy. The recovery deadline is captured on the **ejection entry itself** from the **effective** passive policy that caused the ejection (per-port override, then subset overlay, then upstream). That deadline is honored across config reloads, applies only to the owning proxy's map (two proxies sharing one `host:port` keep independent cooldowns), and covers targets introduced only through service discovery — not merely the static `upstream.targets` list at timer spawn.
   - **On-success recovery**: If a request to the target succeeds (e.g., via the all-unhealthy fallback path), it is immediately restored.

> **Connection errors vs. status codes:** Connection-level failures (TCP refused, timeout, DNS failure) are **always** counted as passive health check failures, even if you customize `unhealthy_status_codes`. You don't need to add 502 to your list to catch connection failures — they are handled separately.

> **Why `healthy_after_seconds` matters:** Without it (or with active health checks disabled), passively-marked unhealthy targets can only recover via the all-unhealthy fallback path — and if even one target remains healthy, the unhealthy targets never receive traffic and can never recover. The automatic recovery timer prevents this "stuck unhealthy" scenario.

**Trade-offs vs. active checks:**

| | Active | Passive |
|---|---|---|
| Extra network traffic | Yes (probes) | No |
| Detects failures before user impact | Yes | No (requires user traffic) |
| Can detect connectivity issues | Yes | Only for in-flight requests |
| Works with no traffic | Yes | No |

### Combined Health Checks

You can enable both active and passive health checks simultaneously for the most robust health monitoring:

```yaml
health_checks:
  active:
    http_path: "/health"
    interval_seconds: 5
    unhealthy_threshold: 3
    healthy_threshold: 2
  passive:
    unhealthy_status_codes: [500, 502, 503]
    unhealthy_threshold: 3
    unhealthy_window_seconds: 30
```

Both checks write to the same shared `unhealthy_targets` set. Either check can mark a target as unhealthy, and either check can restore it:

- Active checks can restore a passively-marked-unhealthy target when their probes succeed.
- A successful proxied response can restore an actively-marked-unhealthy target.
- The passive recovery timer (`healthy_after_seconds`) can restore a target regardless of which check marked it.

> **Best practice:** When using passive-only health checks, always keep `healthy_after_seconds` enabled (the default is 30s). When using combined active + passive checks, active probes provide the primary recovery mechanism and the timer acts as an additional safety net.

### Fallback When All Unhealthy

If all targets in an upstream are marked unhealthy, the load balancer **falls back to routing to all targets** rather than returning errors. This ensures the gateway continues to serve traffic even in degraded conditions — some targets may still be partially functional. If the fallback request succeeds, the target is immediately restored to the healthy rotation via passive health check recovery.

For subset routing, if the selected subset has no healthy targets, the load balancer falls back to the parent upstream and marks the selection degraded. This mirrors DestinationRule fail-open behavior while preserving validation for unknown subset names.

When operating in fallback mode, the gateway sets the `X-Gateway-Upstream-Status: degraded` response header so clients and monitoring systems can detect degraded routing. See [Client Observability Headers](#client-observability-headers) for details.

## Client Observability Headers

When proxying to upstream targets, the gateway adds response headers that help clients and ops teams distinguish between different failure modes. These headers are **only** set on error responses (5xx) or degraded routing — successful 2xx/3xx/4xx responses do not include them.

### `X-Gateway-Error`

Set on 5xx responses to categorize the failure. This is the **stable
client-facing contract** — a closed set of seven `&'static str` tokens.
Access-log `error_class` and `ferrum_requests_total{error_class}` use the
**granular** `ErrorClass::as_str` spelling when a class exists
(`dns_lookup_error`, `connection_refused`, `tls_error`, …) plus the four
gateway-authored tokens below when the rejection has no `ErrorClass`. Map
each granular class to its header token in
[error_classification.md](error_classification.md#http-observability-vocabulary-x-gateway-error).
The header is omitted on 2xx/3xx/4xx.

| Value | Meaning |
|-------|---------|
| `connection_failure` | TCP connection refused, DNS resolution failure, TLS handshake error, or connect timeout — the gateway could not reach the backend at all |
| `backend_timeout` | The backend accepted the connection but did not respond in time (504 Gateway Timeout) |
| `backend_error` | The backend returned a 5xx error response (500, 502, 503, etc.) |
| `circuit_breaker_open` | The circuit breaker is open; the gateway returned 503 without contacting a backend |
| `overload` | Overload manager or drain `reject_new_requests`; the gateway returned 503 without contacting a backend |
| `config_stale` | Data-plane stale-config fence; the gateway returned 503 without contacting a backend |
| `concurrency_limit` | `adaptive_concurrency` admission shed; the gateway returned 503 without contacting a backend |

`circuit_breaker_open`, `overload`, `config_stale`, and `concurrency_limit` are
distinct from `backend_error`. Those 503s never reached a backend, so reusing
`backend_error` would make alert rules unable to tell a local shed from a
backend that actually returned 5xx. HTTP/1.1, HTTP/2, HTTP/3 (native and
H3→HTTP cross-protocol), and HBONE all emit the same vocabulary on HTTP-family
JSON 5xx. gRPC H1/H2 UNAVAILABLE trailers-only siblings of the overload and
stale-config fences are unchanged (they do not carry `X-Gateway-Error`).

### `X-Gateway-Upstream-Status`

| Value | Meaning |
|-------|---------|
| `degraded` | All targets in the upstream were marked unhealthy. The request was routed via the all-unhealthy fallback path — the selected target may still be failing |

**Example: connection failure**
```
HTTP/1.1 502 Bad Gateway
X-Gateway-Error: connection_failure
```

**Example: backend timeout during degraded routing**
```
HTTP/1.1 504 Gateway Timeout
X-Gateway-Error: backend_timeout
X-Gateway-Upstream-Status: degraded
```

**Example: circuit breaker open**
```
HTTP/1.1 503 Service Unavailable
X-Gateway-Error: circuit_breaker_open
```

**Example: overload / drain reject**
```
HTTP/1.1 503 Service Unavailable
X-Gateway-Error: overload
```

**Example: stale configuration**
```
HTTP/1.1 503 Service Unavailable
X-Gateway-Error: config_stale
```

**Example: adaptive concurrency shed**
```
HTTP/1.1 503 Service Unavailable
X-Gateway-Error: concurrency_limit
```

**Example: successful response (no error headers)**
```
HTTP/1.1 200 OK
```

### Use Cases

- **Alerting**: Alert on `X-Gateway-Error: connection_failure` to detect backends that are completely down vs. backends that are slow (`backend_timeout`). Alert on `circuit_breaker_open` to detect a tripped breaker rather than a live backend 5xx (`backend_error`). Alert on `overload`, `config_stale`, and `concurrency_limit` to distinguish gateway-authored sheds from backend 503s. PromQL on `ferrum_requests_total{error_class}` uses the granular spelling (`dns_lookup_error` vs `connection_refused` vs `read_write_timeout`) plus the five gateway-authored tokens; it does **not** emit `connection_failure` or `backend_timeout`, and it emits `backend_error` only for a backend 5xx the gateway never classified.
- **Client-side retry**: Clients can decide whether to retry based on the error type — connection failures may resolve quickly, while backend errors suggest the service itself is unhealthy.
- **Dashboards**: Track `X-Gateway-Upstream-Status: degraded` to monitor when upstreams are operating in fallback mode.
- **Distinguishing gateway vs. backend issues**: A `backend_error` means the backend returned a 5xx — the issue is with the backend. A `connection_failure` means the gateway couldn't reach the backend — the issue may be network, DNS, or the backend process is down. A `circuit_breaker_open`, `overload`, `config_stale`, or `concurrency_limit` means the gateway short-circuited the request locally.

## Retry Logic

When a request to a backend target fails, the retry system can automatically retry to a **different** target in the upstream. This provides automatic failover without client-side retry logic.

> For comprehensive retry documentation including configuration reference, backoff strategies, protocol support, and examples, see [Retry Logic](retry.md).

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-servers"
    retry:
      max_retries: 3
      retryable_status_codes: [502, 503, 504]
      retry_on_connect_failure: true
      backoff: !exponential
        base_ms: 100
        max_ms: 5000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_retries` | integer | `3` | Maximum number of retry attempts |
| `retryable_status_codes` | array | `[]` (empty) | HTTP status codes that trigger a retry — empty by default (connection-failure-only) |
| `retryable_methods` | array | `["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]` | HTTP methods eligible for status-code retries (connection failure retries ignore this) |
| `retry_on_connect_failure` | boolean | `true` | Retry on TCP/connection failures (refused, timeout, DNS, TLS) |
| `backoff` | tagged enum | `!fixed { delay_ms: 100 }` | Backoff strategy between retries |

### Key Behaviors

- **Connection failures** (TCP refused, DNS, TLS, timeout) are retried for **all HTTP methods** — the request never reached the backend so idempotency is not a concern.
- **HTTP status-code failures** (e.g., 502, 503) are only retried for methods in `retryable_methods` — `POST` and `PATCH` are excluded by default.
- **Status-code retries are opt-in** — `retryable_status_codes` defaults to empty. Set it explicitly to enable (e.g., `[502, 503, 504]`).
- When combined with an upstream, retries **exclude the previously tried target** so each attempt goes to a different backend. HTTP/H3 exclusion uses the full configured routing/policy identity (`host`, `port`, declared Service port / policy lane, tags, locality, path) — not merely `host:port` — so two `backendRefs` that share a network endpoint but differ by Service, subset, or path stay distinct. For wildcard-hosted targets the shared retry helper reconciles the just-tried dial clone back to that configured identity, then returns the next candidate already re-concretized with the request's validated authority (failing closed if that authority is missing or unmatched). TCP/stream connect-retry retains only the live `(host, dial port, policy lane)` tuple, so it uses a separate endpoint-lane exclude contract: every configured entry on that effective lane is dropped (including ordinary targets whose `service_port_policy_key` is `None` but whose `dispatch_policy_port()` equals the dial port), and ambiguous same-lane identity siblings are not reselected.
- Retries apply to HTTP/1.1, HTTP/2, HTTP/3, gRPC, and WebSocket protocols. TCP stream proxies rotate to an alternate target only for connection-phase failures when `retry_on_connect_failure` is enabled; UDP stream proxies do not use retry logic.

## Circuit Breaker

The circuit breaker pattern prevents cascading failures by temporarily stopping requests to a backend that is experiencing high failure rates. When a proxy uses an upstream with multiple targets, each target gets its own independent circuit breaker — a failing target's breaker opens without affecting healthy targets in the same upstream group. For direct-backend proxies (no upstream), the breaker is scoped to the proxy.

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-servers"
    circuit_breaker:
      failure_threshold: 5
      success_threshold: 3
      timeout_seconds: 30
      failure_status_codes: [500, 502, 503, 504]
      half_open_max_requests: 1
      trip_on_connection_errors: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | integer | `5` | Failures before opening the circuit |
| `success_threshold` | integer | `3` | Successes in half-open to close the circuit |
| `timeout_seconds` | integer | `30` | How long the circuit stays open before half-open |
| `failure_status_codes` | array | `[500, 502, 503, 504]` | HTTP status codes from real backend responses that count as failures |
| `half_open_max_requests` | integer | `1` | Max concurrent requests in half-open state |
| `trip_on_connection_errors` | boolean | `true` | Whether connection-level errors trip the breaker independently of `failure_status_codes` |

**States:**

- **Closed** (normal) — Requests pass through. Responses with status codes in `failure_status_codes` increment the failure counter; connection-level errors also increment it when `trip_on_connection_errors` is enabled. All other responses reset the counter to zero. When the failure counter reaches `failure_threshold`, the circuit opens.
- **Open** — All requests immediately return `503 Service Unavailable` with `X-Gateway-Error: circuit_breaker_open` without contacting the backend. After `timeout_seconds`, the circuit transitions to Half-Open.
- **Half-Open** — The circuit allows up to `half_open_max_requests` concurrent probe requests. Successful responses count toward `success_threshold`; when reached, the circuit closes (recovered). Any failure immediately reopens the circuit.

**Failure detection:**

The circuit breaker counts failures from two independent sources:

1. **HTTP response status codes** — backend responses with a status code in `failure_status_codes` are counted as failures. These are real HTTP responses from the backend.
2. **Connection-level errors** — TCP connection refused, connection timeout, DNS resolution failure, and TLS handshake errors. These are controlled by `trip_on_connection_errors` (default: `true`) independently of `failure_status_codes`.

This separation means you can configure the breaker to trip on connection errors only, status code errors only, or both:

- **Both (default)**: `trip_on_connection_errors: true` with `failure_status_codes: [500, 502, 503, 504]`
- **Connection errors only**: `trip_on_connection_errors: true` with `failure_status_codes: []`
- **Status codes only**: `trip_on_connection_errors: false` with `failure_status_codes: [500, 503]`

**Cache bound (`FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES`):**

Breakers are cached per `proxy_id` (direct backend) or `proxy_id::host:port` (upstream/target). Concurrent callers for the same key and config share one breaker instance. When the cache is at capacity, requests for **new** keys still proceed with a transient (uncached) breaker that does not retain state across requests and does not grow the map; entries already in the cache remain replaceable when their config changes.

Entries are reclaimed on config reload **and** on every service-discovery publication: when a discovery provider retires a target, the breakers for that target are released for every proxy routing to the discovered upstream, in the same pass that reclaims its health-check state. Pod/endpoint churn therefore no longer accumulates dead entries between config changes.

A transient breaker never accumulates failures, so it can never open. `ferrum_circuit_breaker_cache_admission_refused_total` (see `docs/prometheus_metrics.md`) counts every request that was handed one; a non-zero and rising value means circuit breaking is silently degraded for newly seen keys and `FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES` should be raised.

## Configuration Reference

### Complete YAML Example

```yaml
proxies:
  - id: "api-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    strip_listen_path: true
    upstream_id: "api-pool"
    retry:
      max_retries: 3
      retryable_status_codes: [502, 503, 504]
      retry_on_connect_failure: true
      backoff: !exponential
        base_ms: 100
        max_ms: 5000
    circuit_breaker:
      failure_threshold: 10
      success_threshold: 3
      timeout_seconds: 30
      failure_status_codes: [500, 502, 503, 504]
      trip_on_connection_errors: true

  - id: "static-proxy"
    listen_path: "/static"
    backend_scheme: http
    backend_host: "10.0.2.1"
    backend_port: 80
    strip_listen_path: true
    upstream_id: "static-pool"

upstreams:
  - id: "api-pool"
    name: "API Server Pool"
    algorithm: weighted_round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
        weight: 5
        tags:
          region: "us-east"
          tier: "primary"
      - host: "10.0.1.2"
        port: 8080
        weight: 3
        tags:
          region: "us-east"
          tier: "secondary"
      - host: "10.0.1.3"
        port: 8080
        weight: 1
        tags:
          region: "us-west"
          tier: "fallback"
    health_checks:
      active:
        http_path: "/healthz"
        interval_seconds: 5
        timeout_ms: 3000
        healthy_threshold: 2
        unhealthy_threshold: 3
        healthy_status_codes: [200]
      passive:
        unhealthy_status_codes: [500, 502, 503, 504]
        unhealthy_threshold: 5
        unhealthy_window_seconds: 60

  - id: "static-pool"
    name: "Static Content Servers"
    algorithm: round_robin
    targets:
      - host: "10.0.2.1"
        port: 80
      - host: "10.0.2.2"
        port: 80
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 10
        unhealthy_threshold: 3

consumers: []
plugin_configs: []
```

### Upstream Configuration via Config Reload

Upstream targets can be updated at runtime by modifying the configuration file and sending a `SIGHUP` signal to the gateway process (in file mode), or by updating the database (in database mode). The load balancer cache is rebuilt atomically on config changes — no requests are dropped.

```bash
# Update the config file with new targets
vim /etc/ferrum/config.yaml

# Reload configuration without restart
kill -HUP $(pidof ferrum-edge)
```

## Examples

### Blue-Green Deployment

Use weighted round robin to gradually shift traffic from old to new deployment:

```yaml
upstreams:
  - id: "app-pool"
    algorithm: weighted_round_robin
    targets:
      - host: "blue-server.internal"
        port: 8080
        weight: 9     # 90% of traffic
        tags:
          version: "v1.2.0"
      - host: "green-server.internal"
        port: 8080
        weight: 1     # 10% of traffic (canary)
        tags:
          version: "v1.3.0"
```

Gradually increase the green weight and decrease the blue weight as confidence grows.

### Session Affinity with Consistent Hashing

Route the same client to the same backend for session-based applications. Three approaches are available:

**IP-based** — simplest, no cookies, works behind a single NAT/proxy:

```yaml
upstreams:
  - id: "session-pool"
    algorithm: consistent_hashing
    hash_on: "ip"
    targets:
      - host: "app-1.internal"
        port: 8080
      - host: "app-2.internal"
        port: 8080
      - host: "app-3.internal"
        port: 8080
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 5
        unhealthy_threshold: 3
```

**Cookie-based** — true sticky sessions that survive NAT/proxy changes:

```yaml
upstreams:
  - id: "session-pool"
    algorithm: consistent_hashing
    hash_on: "cookie:srv"
    hash_on_cookie_config:
      path: "/"
      ttl_seconds: 7200
      http_only: true
      secure: true
      same_site: "Lax"
    targets:
      - host: "app-1.internal"
        port: 8080
      - host: "app-2.internal"
        port: 8080
      - host: "app-3.internal"
        port: 8080
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 5
        unhealthy_threshold: 3
```

**Header-based** — route by tenant, user ID, or any custom header:

```yaml
upstreams:
  - id: "tenant-pool"
    algorithm: consistent_hashing
    hash_on: "header:x-tenant-id"
    targets:
      - host: "app-1.internal"
        port: 8080
      - host: "app-2.internal"
        port: 8080
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 5
        unhealthy_threshold: 3
```

### High-Availability with Full Protection

Combine load balancing, health checks, retry, and circuit breaker for maximum resilience:

```yaml
proxies:
  - id: "critical-api"
    listen_path: "/critical"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "critical-pool"
    retry:
      max_retries: 2
      retryable_status_codes: [502, 503]
      retry_on_connect_failure: true
      backoff: !exponential
        base_ms: 50
        max_ms: 1000
    circuit_breaker:
      failure_threshold: 10
      success_threshold: 3
      timeout_seconds: 15

upstreams:
  - id: "critical-pool"
    algorithm: least_connections
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
      - host: "10.0.1.3"
        port: 8080
    health_checks:
      active:
        http_path: "/healthz"
        interval_seconds: 3
        timeout_ms: 2000
        healthy_threshold: 2
        unhealthy_threshold: 2
      passive:
        unhealthy_status_codes: [500, 502, 503]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 30
```

### Multiple Upstream Groups

Route different paths to different server pools:

```yaml
proxies:
  - id: "api-v1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-v1-pool"

  - id: "api-v2"
    listen_path: "/api/v2"
    backend_scheme: http
    backend_host: "10.0.2.1"
    backend_port: 8080
    upstream_id: "api-v2-pool"

upstreams:
  - id: "api-v1-pool"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080

  - id: "api-v2-pool"
    algorithm: weighted_round_robin
    targets:
      - host: "10.0.2.1"
        port: 8080
        weight: 3
      - host: "10.0.2.2"
        port: 8080
        weight: 1
```

HTTP/3 client responses also expose `X-Gateway-Upstream-Status: degraded` when
selection uses the all-unhealthy fallback. With `FERRUM_ADD_VIA_HEADER=true`,
HTTP/3 responses append the configured Via pseudonym using the backend hop's
protocol (`1.1`, `2.0`, or `3.0`), including cross-protocol bridges and buffered
responses. Existing Via hops are retained. Buffered mesh responses retain the
shared H1/H2 convention of reporting `1.1` when their retained body has no wire
version metadata.
