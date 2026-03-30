# Load Balancing

Ferrum Gateway provides built-in load balancing to distribute traffic across multiple backend targets. This feature allows you to define **upstreams** — groups of backend servers — and attach them to proxy routes for automatic traffic distribution, health checking, and failover.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Upstreams](#upstreams)
- [Targets](#targets)
- [Load Balancing Algorithms](#load-balancing-algorithms)
  - [Round Robin](#round-robin)
  - [Weighted Round Robin](#weighted-round-robin)
  - [Least Connections](#least-connections)
  - [Least Latency](#least-latency)
  - [Consistent Hashing](#consistent-hashing)
  - [Random](#random)
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
2. **Targets** — Individual backend servers within an upstream, each with a host, port, optional weight, and optional path override.
3. **Health Checks** — Active (periodic probes) and passive (response monitoring) checks that automatically exclude unhealthy targets.
4. **Retry Logic** — Automatic retries to alternative targets when a request fails.
5. **Circuit Breaker** — Prevents cascading failures by temporarily stopping requests to failing backends.

Load balancers are rebuilt atomically on configuration changes (file reload via SIGHUP, database polling, or control plane push) — no requests are dropped during reconfiguration.

### DNS Integration

Upstream target hostnames are automatically resolved through the gateway's [central DNS cache](dns_resolver.md). This means:

- **Startup warmup**: All upstream target hostnames are pre-resolved alongside proxy backend hostnames before the gateway accepts traffic — no cold-cache DNS lookups on the first request.
- **Hot-path efficiency**: DNS resolution never happens in the request hot path. All HTTP clients use a custom `DnsCacheResolver` that transparently routes lookups through the in-memory cache.
- **Background refresh**: DNS entries for upstream targets are proactively refreshed at 75% TTL, just like proxy backend hostnames.

## Quick Start

Add an `upstreams` section to your configuration and reference it from a proxy via `upstream_id`:

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
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

1. **Warm-up phase**: When the upstream is first loaded (or after a config reload), the algorithm uses round-robin to distribute traffic evenly across all healthy targets. Each healthy target must receive at least 5 successful responses before latency-based selection begins. This ensures every target gets a fair baseline measurement. If a target is unhealthy at startup, warm-up proceeds with the healthy targets only — the unhealthy target does not block the algorithm from advancing.

2. **Steady-state**: After warm-up, each request is routed to the target with the lowest EWMA latency. The EWMA is updated after every successful backend response using the formula:

   ```
   ewma = 0.3 × new_sample + 0.7 × previous_ewma
   ```

   The smoothing factor (alpha = 0.3) means recent measurements account for ~30% of the average, providing a good balance between responsiveness to latency changes and stability against transient spikes.

3. **Latency sources**: Latency is measured from one of two sources, with active taking precedence:
   - **Active (health check probes)**: When active health checks are configured, the RTT of each successful probe is used as the latency signal. Active probes provide consistent, controlled measurements that reflect pure network round-trip time without variable application processing overhead. **When active health checks are configured, passive latency recording is disabled.**
   - **Passive (proxy traffic)**: When no active health checks are configured, time-to-first-byte (TTFB) from each proxied request is used instead. This requires no configuration but includes application processing time in the measurement.

   Only successful, non-error responses are recorded — connection errors, timeouts, and 5xx responses are excluded. Connection errors and timeouts don't reflect real network latency, and 5xx responses may have artificially low latency from fast-failing backends which would skew the EWMA toward broken targets.

4. **Recovery / late joiners**: When a target recovers from unhealthy status (via active or passive health checks), its EWMA is reset to the current minimum across all healthy targets and its sample count is set to the warm-up threshold. This means the recovered target immediately participates in latency-based selection (with an optimistic starting point) rather than forcing the entire upstream back into round-robin warm-up mode. As real latency samples arrive, the EWMA converges to the target's true latency. Similarly, if a target was unhealthy at startup and later becomes healthy, it joins latency-based selection with an optimistic EWMA estimate equal to the current minimum, ensuring it gets a fair share of traffic without disrupting established routing for other targets.

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

The `hash_on` field controls what value is used as the hash key:

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

1. **First request** (no cookie): The gateway selects a target using the client IP as a fallback key, then injects a `Set-Cookie` response header with the selected target's identifier.
2. **Subsequent requests** (cookie present): The cookie value is used as the hash key, routing the request to the same target.

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
| `path` | string | `"/"` | Cookie `Path` attribute |
| `ttl_seconds` | integer | `3600` | Cookie `Max-Age` in seconds (1 hour default) |
| `domain` | string | — | Optional `Domain` attribute |
| `http_only` | boolean | `true` | Set the `HttpOnly` flag |
| `secure` | boolean | `false` | Set the `Secure` flag |
| `same_site` | string | — | `SameSite` attribute: `Strict`, `Lax`, or `None` |

If `hash_on_cookie_config` is omitted, sensible defaults are used (path `/`, 1 hour TTL, `HttpOnly` enabled).

The sticky session cookie is injected on HTTP, gRPC, and WebSocket (101 Upgrade) responses.

When a target is removed or added, only a fraction of keys are remapped — this minimizes cache invalidation across backends.

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

## Health Checks

Health checks automatically detect and exclude unhealthy targets so traffic is only routed to healthy backends. Ferrum Gateway supports both active and passive health checks, which can be used independently or together.

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
| `unhealthy_threshold` | integer | `3` | Failures within window to mark unhealthy |
| `unhealthy_window_seconds` | integer | `30` | Time window for failure counting |
| `healthy_after_seconds` | integer | `30` | Seconds before an unhealthy target is automatically restored (0 to disable) |

**How it works:**

1. After each proxied request, the response status code is reported to the health checker.
2. A failure is recorded (with a timestamp) when **either** condition is true:
   - The status code is in `unhealthy_status_codes` (e.g., backend returned 500)
   - The request was a **connection error** — TCP connection refused, read timeout, DNS resolution failure, or TLS handshake error. These always count as failures regardless of `unhealthy_status_codes`.
3. Old failures outside the `unhealthy_window_seconds` window are cleaned up.
4. If the number of failures within the window reaches `unhealthy_threshold`, the target is marked **unhealthy**.
5. Recovery happens via two mechanisms:
   - **Automatic recovery timer**: After `healthy_after_seconds`, the target is automatically restored to the rotation with a clean slate — similar to a circuit breaker's half-open state. If it immediately fails again, passive checks will re-mark it unhealthy.
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

When operating in fallback mode, the gateway sets the `X-Gateway-Upstream-Status: degraded` response header so clients and monitoring systems can detect degraded routing. See [Client Observability Headers](#client-observability-headers) for details.

## Client Observability Headers

When proxying to upstream targets, the gateway adds response headers that help clients and ops teams distinguish between different failure modes. These headers are **only** set on error responses (5xx) or degraded routing — successful 2xx/3xx/4xx responses do not include them.

### `X-Gateway-Error`

Set on 5xx responses to categorize the failure:

| Value | Meaning |
|-------|---------|
| `connection_failure` | TCP connection refused, DNS resolution failure, TLS handshake error, or connect timeout — the gateway could not reach the backend at all |
| `backend_timeout` | The backend accepted the connection but did not respond in time (504 Gateway Timeout) |
| `backend_error` | The backend returned a 5xx error response (500, 502, 503, etc.) |

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

**Example: successful response (no error headers)**
```
HTTP/1.1 200 OK
```

### Use Cases

- **Alerting**: Alert on `X-Gateway-Error: connection_failure` to detect backends that are completely down vs. backends that are slow (`backend_timeout`).
- **Client-side retry**: Clients can decide whether to retry based on the error type — connection failures may resolve quickly, while backend errors suggest the service itself is unhealthy.
- **Dashboards**: Track `X-Gateway-Upstream-Status: degraded` to monitor when upstreams are operating in fallback mode.
- **Distinguishing gateway vs. backend issues**: A `backend_error` means the backend returned a 5xx — the issue is with the backend. A `connection_failure` means the gateway couldn't reach the backend — the issue may be network, DNS, or the backend process is down.

## Retry Logic

When a request to a backend target fails, the retry system can automatically retry to a **different** target in the upstream. This provides automatic failover without client-side retry logic.

> For comprehensive retry documentation including configuration reference, backoff strategies, protocol support, and examples, see [Retry Logic](retry.md).

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
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
- When combined with an upstream, retries **exclude the previously tried target** so each attempt goes to a different backend.
- Retries apply to HTTP/1.1, HTTP/2, HTTP/3, gRPC, and WebSocket protocols. TCP and UDP stream proxies do not use retry logic.

## Circuit Breaker

The circuit breaker pattern prevents cascading failures by temporarily stopping requests to a backend that is experiencing high failure rates. When a proxy uses an upstream with multiple targets, each target gets its own independent circuit breaker — a failing target's breaker opens without affecting healthy targets in the same upstream group. For direct-backend proxies (no upstream), the breaker is scoped to the proxy.

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-servers"
    circuit_breaker:
      failure_threshold: 5
      success_threshold: 3
      timeout_seconds: 30
      failure_status_codes: [500, 502, 503, 504]
      half_open_max_requests: 1
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | integer | `5` | Failures before opening the circuit |
| `success_threshold` | integer | `3` | Successes in half-open to close the circuit |
| `timeout_seconds` | integer | `30` | How long the circuit stays open before half-open |
| `failure_status_codes` | array | `[500, 502, 503, 504]` | Status codes that count as failures |
| `half_open_max_requests` | integer | `1` | Max concurrent requests in half-open state |

**States:**

- **Closed** (normal) — Requests pass through. Responses with status codes in `failure_status_codes` increment the failure counter; all other responses reset it to zero. When the failure counter reaches `failure_threshold`, the circuit opens.
- **Open** — All requests immediately return `503 Service Unavailable` without contacting the backend. After `timeout_seconds`, the circuit transitions to Half-Open.
- **Half-Open** — The circuit allows up to `half_open_max_requests` concurrent probe requests. Successful responses count toward `success_threshold`; when reached, the circuit closes (recovered). Any failure immediately reopens the circuit.

## Configuration Reference

### Complete YAML Example

```yaml
proxies:
  - id: "api-proxy"
    listen_path: "/api"
    backend_protocol: http
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

  - id: "static-proxy"
    listen_path: "/static"
    backend_protocol: http
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
kill -HUP $(pidof ferrum-gateway)
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
    backend_protocol: http
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
    backend_protocol: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-v1-pool"

  - id: "api-v2"
    listen_path: "/api/v2"
    backend_protocol: http
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
