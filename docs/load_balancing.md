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
  - [Consistent Hashing](#consistent-hashing)
  - [Random](#random)
- [Health Checks](#health-checks)
  - [Active Health Checks](#active-health-checks)
  - [Passive Health Checks](#passive-health-checks)
  - [Combined Health Checks](#combined-health-checks)
  - [Fallback When All Unhealthy](#fallback-when-all-unhealthy)
- [Retry Logic](#retry-logic)
- [Circuit Breaker](#circuit-breaker)
- [Configuration Reference](#configuration-reference)
- [Examples](#examples)

## Overview

The load balancing architecture consists of:

1. **Upstreams** — Named groups of backend targets with a load balancing algorithm.
2. **Targets** — Individual backend servers within an upstream, each with a host, port, and optional weight.
3. **Health Checks** — Active (periodic probes) and passive (response monitoring) checks that automatically exclude unhealthy targets.
4. **Retry Logic** — Automatic retries to alternative targets when a request fails.
5. **Circuit Breaker** — Prevents cascading failures by temporarily stopping requests to failing backends.

Load balancers are rebuilt atomically on configuration changes (file reload via SIGHUP, database polling, or control plane push) — no requests are dropped during reconfiguration.

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
| `hash_on` | string | No | — | Key for consistent hashing (e.g., `ip`, `header:X-User-Id`) |
| `health_checks` | object | No | — | Health check configuration |

## Targets

Each target represents a single backend server within an upstream.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | Yes | — | Backend server hostname or IP |
| `port` | integer | Yes | — | Backend server port |
| `weight` | integer | No | `1` | Relative weight for weighted algorithms |
| `tags` | object | No | `{}` | Key-value metadata tags |

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

### Consistent Hashing

**Algorithm:** `consistent_hashing`

Routes requests to a target determined by a hash of a context key (by default, the client IP address). The same key always maps to the same target, providing session affinity without server-side session state.

Uses 150 virtual nodes per target on a hash ring for uniform distribution.

```yaml
upstreams:
  - id: "my-upstream"
    algorithm: consistent_hashing
    hash_on: "ip"                  # optional: hash key source
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
      - host: "10.0.1.3"
        port: 8080
```

When a target is removed or added, only a fraction of keys are remapped — this minimizes cache invalidation across backends.

**Best for:** Session affinity, caching backends, stateful applications.

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
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_path` | string | `/health` | HTTP path for health probe requests |
| `interval_seconds` | integer | `10` | Seconds between health check probes |
| `timeout_ms` | integer | `5000` | Per-probe timeout in milliseconds |
| `healthy_threshold` | integer | `3` | Consecutive successes before marking healthy |
| `unhealthy_threshold` | integer | `3` | Consecutive failures before marking unhealthy |
| `healthy_status_codes` | array | `[200, 302]` | HTTP status codes considered healthy |

**How it works:**

1. A background task is spawned for each target in the upstream.
2. Every `interval_seconds`, the task sends an HTTP GET to `http://<host>:<port><http_path>`.
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

## Retry Logic

When a request to a backend target fails, the retry system can automatically retry to a **different** target in the upstream. This provides automatic failover without client-side retry logic.

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
      retryable_methods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_retries` | integer | `3` | Maximum number of retry attempts |
| `retryable_status_codes` | array | `[502, 503, 504]` | HTTP status codes that trigger a retry |
| `retryable_methods` | array | `["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]` | HTTP methods eligible for retry |
| `retry_on_connect_failure` | boolean | `true` | Retry on TCP/connection failures |
| `backoff` | tagged enum | `!fixed { delay_ms: 100 }` | Backoff strategy between retries |

### Backoff Strategies

Backoff strategies use YAML tags to select the variant:

**Fixed backoff:**
```yaml
backoff: !fixed
  delay_ms: 100    # wait 100ms between each retry
```

**Exponential backoff:**
```yaml
backoff: !exponential
  base_ms: 100     # first retry after 100ms
  max_ms: 5000     # cap at 5 seconds
```

With exponential backoff, delays are: 100ms, 200ms, 400ms, 800ms, 1600ms, ..., capped at `max_ms`.

### Connection Failures vs. HTTP Failures

The retry system distinguishes between two types of failures:

1. **Connection failures** — TCP connect refused, DNS resolution failure, TLS handshake error, connect timeout. These are retried when `retry_on_connect_failure: true`, regardless of `retryable_status_codes`.

2. **HTTP status failures** — Actual HTTP responses with status codes like 502, 503. These are retried only when the status code is in `retryable_status_codes`.

This distinction prevents situations where a proxy upstream returns a real HTTP 502 but you've removed 502 from `retryable_status_codes` — connection-level failures are still retried.

### Retry with Load Balancing

When retry is combined with an upstream, retries use `select_next_target()` which **excludes the previously tried target**. This ensures retries go to a different backend, maximizing the chance of success.

### Non-retryable Methods

By default, `POST` and `PATCH` are **not** retried because they are typically non-idempotent. You can override this by adding them to `retryable_methods` if your backend handles duplicate requests safely.

## Circuit Breaker

The circuit breaker pattern prevents cascading failures by temporarily stopping requests to a proxy that is experiencing high failure rates.

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

- **Closed** (normal) — Requests pass through. Failures are counted.
- **Open** — After `failure_threshold` failures, the circuit opens. All requests immediately return `503 Service Unavailable`.
- **Half-Open** — After `timeout_seconds`, the circuit allows `half_open_max_requests` probe requests. If they succeed (`success_threshold` times), the circuit closes. If they fail, it reopens.

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
      retryable_methods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]
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

Route the same client to the same backend for session-based applications:

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
