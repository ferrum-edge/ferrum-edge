# Retry Logic

Ferrum Edge provides configurable retry logic for failed backend requests. Retries are configured per-proxy and support both connection-level and HTTP status-code-level failure detection with fixed or exponential backoff strategies.

## Table of Contents

- [Overview](#overview)
- [Protocol Support](#protocol-support)
- [Configuration](#configuration)
- [Retry Behavior](#retry-behavior)
  - [Connection Failures](#connection-failures)
  - [HTTP Status Code Failures](#http-status-code-failures)
  - [Method Filtering](#method-filtering)
- [Backoff Strategies](#backoff-strategies)
  - [Fixed Backoff](#fixed-backoff)
  - [Exponential Backoff with Jitter](#exponential-backoff-with-jitter)
- [Retry with Load Balancing](#retry-with-load-balancing)
- [Interaction with Circuit Breaker](#interaction-with-circuit-breaker)
- [Request Body Handling](#request-body-handling)
- [Examples](#examples)
- [Configuration Reference](#configuration-reference)

## Overview

Retry logic is **opt-in per proxy** — add a `retry` block to a proxy's configuration to enable it. Without a `retry` block, failed requests are returned immediately to the client with no retry attempts.

By default, a retry configuration only retries **connection failures** (TCP refused, DNS resolution failure, TLS handshake error, connect timeout). HTTP status-code retries (e.g., retry on 502/503/504) must be explicitly enabled by setting `retryable_status_codes`.

## Protocol Support

Retry logic applies to the following proxy protocols:

| Protocol | Retries Supported | Notes |
|---|:---:|---|
| HTTP/1.1 | Yes | Full retry support with body replay |
| HTTP/2 | Yes | Full retry support with body replay |
| HTTP/3 (QUIC) | Yes | Full retry support with body replay |
| gRPC / gRPCs | Yes | Connection failure retries with body replay and upstream target rotation |
| WebSocket / WSS | Yes | Connection failure retries on initial backend connection with upstream target rotation |
| TCP / TCP+TLS | Yes (connect-phase only) | Target rotation on connection-setup failures when `retry_on_connect_failure` is enabled and `upstream_id` is set; no mid-stream byte replay. See [Load Balancing — Retry Logic](load_balancing.md#retry-logic). |
| UDP / DTLS | No | Datagram-based protocol, no connect-phase retry or target rotation |

HTTP-family protocols (HTTP/1.1, HTTP/2, HTTP/3) share the same retry loop in the proxy core and support both connection failure and HTTP status code retries.

For H1/H2 frontend requests, that loop is transport-neutral across mixed plain, HBONE, and Sidecar mesh-mTLS target sets. Selection/rotation runs first; the exact target's effective port policy, timeout, connection limits, TLS identity/SNI/trust domain, pool partition, and plain/mesh transport are then re-resolved for every attempt. The HTTP/3 frontend shares the same HBONE and Sidecar mesh-mTLS egress pools for plain HTTP and WebSocket (and already for gRPC): mesh-tagged targets ride those secured transports, Unix-socket candidates are filtered from H3 retry rotation because H3 has no Unix dialer, and the attempt fails closed when no eligible secured or plain transport remains.

gRPC retries handle connection-level failures (connect refused, timeout, DNS, TLS, and pooled-sender dispatch cancellations where hyper proves the request never left the client) by buffering the request body and replaying it against alternative upstream targets. Read timeouts and gRPC application-level errors (e.g., UNAVAILABLE status in trailers) are not retried because the request was already sent to the backend.

A client `grpc-timeout` is anchored once at request receipt into an absolute monotonic deadline (independent of whether the `grpc_deadline` plugin is installed). Plugins, request-body collection, pool/client acquisition, backoff, response headers, and body reads all consume that same Instant. Native gRPC and pass-through gRPC-Web dispatch each forward a decremented remaining `grpc-timeout` on every attempt rather than re-arming the original relative header. Retry attempts also reuse the real collected `HeaderMap` so duplicate metadata lines and opaque field values stay byte-identical to attempt 1.

WebSocket retries handle connection-level failures during the initial backend connection attempt (before the upgrade response — 101 Switching Protocols for HTTP/1.1, 200 OK for HTTP/2 Extended CONNECT). Once the WebSocket connection is established, retries no longer apply — the bidirectional stream is managed by the application layer.

Ambient HBONE WebSocket establishment shares one `backend_connect_timeout_ms` budget from before byte-tunnel acquisition through the inner HTTP/1.1 101 response. A timeout of an unknown tunnel phase, and a timeout of the inner upgrade wait (the RFC 6455 request is written before awaiting 101), classify as reached-wire protocol failures (`HbonePoolError::ConnectStream`) and are not retried under `retry_on_connect_failure`.

TCP and TCP+TLS stream proxies retry only during connection setup. When a `retry` block has `retry_on_connect_failure: true` (the default) and the proxy uses an `upstream_id`, connect-phase failures — DNS resolution errors, circuit-breaker-open targets, `maxConnections` rejections, and backend TCP or TLS handshake failures — can rotate to a different upstream target via the endpoint-lane exclude contract (`select_next_target_*_excluding_endpoint_lane_from`). `max_retries` caps how many additional connect attempts run after the first; backoff between attempts honors the configured `backoff` strategy. Once the backend connection is established and the bidirectional relay begins, no further retries are possible because application bytes may already have been exchanged. HTTP status-code retries and `retryable_methods` do not apply to stream proxies. Proxies without an `upstream_id` do not rotate on TCP connect failure — there is no alternate target to select. See [Load Balancing — Retry Logic](load_balancing.md#retry-logic) for the shared rotation semantics.

## Configuration

Add a `retry` block to any proxy to enable retries:

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    retry:
      max_retries: 3
      retry_on_connect_failure: true
```

This minimal configuration retries up to 3 times on connection failures only. To also retry on specific HTTP status codes:

```yaml
    retry:
      max_retries: 3
      retryable_status_codes: [502, 503, 504]
      retryable_methods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 100
```

## Retry Behavior

The retry system evaluates two independent failure categories on each backend response:

### Connection Failures

Connection failures are TCP/transport-level problems where the request **never reached the backend**:

- TCP connection refused (port not listening, firewall RST)
- TCP connect timeout (SYN sent, no response)
- DNS resolution failure (hostname unresolvable)
- TLS handshake failure (certificate error, protocol mismatch)
- Pooled HTTP/2 sender cancellation before dispatch (hyper `is_canceled` on a buffered/replayable body — typical backend GOAWAY / connection-age race)

These are retried when `retry_on_connect_failure: true` (the default). Because the request never reached the backend, **all HTTP methods are retried** — idempotency is not a concern since nothing was processed.

Note that `is_canceled` is a statement about hyper's own wire boundary, not about the request-body carrier: a fully collected upload that Ferrum writes through the `backend_write_timeout_ms` upload pump is still the same caller-retained `Bytes`, so it keeps the pre-wire classification. Only genuinely unreplayable streaming / channel uploads are downgraded to post-wire on `is_canceled`.

### Reqwest Protocol NACKs (HTTP/2, buffered uploads)

Independently of the Ferrum retry policy above, reqwest replays a request **once per protocol NACK** (up to two replays) when the backend proves it did not process it: a remote `GOAWAY` with `NO_ERROR` (RFC 9113 §6.8) or a remote `RST_STREAM` with `REFUSED_STREAM` (RFC 9113 §8.7). Reqwest can only do this for a body it holds in full.

A live `backend_write_timeout_ms` (default `30000`) makes Ferrum hand reqwest a *streaming* carrier for buffered uploads, which would silently disable that replay. Ferrum therefore reproduces it at its own dispatch layer — same two shapes, same budget of two replays, a fresh upload pump per attempt, and one absolute response-header bound across all attempts. This is typed (`h2::Reason`), never substring-matched: a mis-detected NACK would replay a non-idempotent request the backend may already have processed. It requires no `retry` configuration and is independent of `retryable_methods`, exactly as reqwest's own behavior was.

### HTTP Status Code Failures

HTTP status-code failures are real HTTP responses from the backend (e.g., 502 Bad Gateway from an upstream load balancer, 503 during deployment). These are retried only when:

1. The response status code is in `retryable_status_codes`
2. The request method is in `retryable_methods`

By default, `retryable_status_codes` is **empty** — no status-code retries occur unless you explicitly configure them. This means a default retry configuration only retries connection failures.

Gateway-local terminal outcomes are never retried even when their synthetic
status appears in `retryable_status_codes`. This includes request/response body
limits, client disconnects, dispatch-policy rejections, and pre-dispatch final
request-body hook rejections such as marker-sanitation worker exhaustion.

### Method Filtering

The `retryable_methods` filter applies **only to HTTP status-code retries**, not to connection failure retries:

| Failure Type | Method Filter Applied? | Reason |
|---|:---:|---|
| Connection failure | No | Request never reached the backend — safe to retry any method |
| HTTP status code | Yes | Backend may have processed the request — non-idempotent methods (POST, PATCH) could cause duplicates |

By default, `retryable_methods` includes `GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`. `POST` and `PATCH` are excluded because they are typically non-idempotent. Add them to `retryable_methods` if your backend handles duplicate requests safely (e.g., idempotency keys).

## Backoff Strategies

The backoff strategy controls the delay between retry attempts. Configure it using YAML tags:

### Fixed Backoff

A constant delay between each retry attempt.

```yaml
backoff: !fixed
  delay_ms: 100    # wait 100ms between each retry
```

| Field | Type | Default | Description |
|---|---|---|---|
| `delay_ms` | integer | `100` | Milliseconds to wait between retries |

### Exponential Backoff with Jitter

Delay doubles on each attempt, capped at a maximum, with decorrelated jitter to prevent thundering herd effects when multiple clients retry against the same failing backend.

```yaml
backoff: !exponential
  base_ms: 100     # first retry after ~100ms
  max_ms: 5000     # cap at 5 seconds
```

| Field | Type | Default | Description |
|---|---|---|---|
| `base_ms` | integer | — | Base delay in milliseconds |
| `max_ms` | integer | — | Maximum delay cap in milliseconds |

The delay formula is: `base_ms * 2^attempt`, capped at `max_ms`, with jitter applied in the range `[delay/2, delay*3/2)`.

**Example progression** (base_ms=100, max_ms=5000):

| Attempt | Base Delay | Jitter Range |
|---|---|---|
| 0 | 100ms | 50–150ms |
| 1 | 200ms | 100–300ms |
| 2 | 400ms | 200–600ms |
| 3 | 800ms | 400–1200ms |
| 4 | 1600ms | 800–2400ms |
| 5+ | 3200ms+ | capped at 5000ms |

The default backoff strategy (when `backoff` is not specified) is `!fixed { delay_ms: 100 }`.

## Retry with Load Balancing

When a proxy has both `retry` and `upstream_id` configured, retries automatically select a **different target** from the upstream on each attempt. HTTP/H3 retry loops call `select_next_target()` with the previous **configured** sticky/routing identity excluded. TCP/stream `retry_on_connect_failure` rotation retains only the live `(host, dial port, policy lane)` and excludes through the endpoint-lane contract instead, so it never reselects that effective lane.

Rotation honors health state across **all protocols**: candidates that are actively unhealthy or passive-ejected (the `maxEjectionPercent` cap is evaluated against the post-exclusion candidate pool) are skipped. When every remaining candidate is unhealthy or ejected, rotation returns no alternate rather than synthesizing a dial to a known-unhealthy target — HTTP-family retries then re-attempt the previously tried target, and TCP `retry_on_connect_failure` rotation stops looking for an alternate.

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "10.0.1.1"
    backend_port: 8080
    upstream_id: "api-servers"
    retry:
      max_retries: 2
      retryable_status_codes: [502, 503]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 50

upstreams:
  - id: "api-servers"
    algorithm: round_robin
    targets:
      - host: "10.0.1.1"
        port: 8080
      - host: "10.0.1.2"
        port: 8080
      - host: "10.0.1.3"
        port: 8080
```

With this configuration, if `10.0.1.1` returns 502, the retry goes to `10.0.1.2`. If that also fails, the second retry goes to `10.0.1.3`.

For proxies without an upstream (direct backend), retries go to the same backend host.

Mesh-tagged and plain targets may coexist in one upstream. Rotation never inherits the previous target's transport: a retry selected for `mesh.hbone` uses HBONE, one selected for `mesh.mtls` uses the SVID-mTLS pool, and an ordinary target uses its direct H3/H2/H1 transport. Secured transports fail closed when identity, capability, SNI, trust-domain, or authorization checks cannot be satisfied; there is no direct-dial fallback. All attempts within one request use the request's atomic configuration snapshot, while live SVID/capability state is checked again at each attempt boundary.

## Interaction with Circuit Breaker

When both `retry` and `circuit_breaker` are configured on the same proxy, they work together:

1. Each failed retry attempt is recorded as a failure against the target's circuit breaker **before** the next retry.
2. If the circuit breaker opens for a target during retries, subsequent retry attempts route to different targets (via load balancing).
3. The circuit breaker uses per-target tracking when an upstream is configured — a single target's breaker opening does not affect other targets.

```yaml
retry:
  max_retries: 3
  retryable_status_codes: [502, 503]
  backoff: !exponential
    base_ms: 100
    max_ms: 2000
circuit_breaker:
  failure_threshold: 5
  timeout_seconds: 30
```

## Request Body Handling

The retry system handles request bodies as follows:

- **One-time preparation**: When a retry can fire, the client upload is fully drained under its size/deadline limits before the first attempt. Request-body transforms and final-body hooks run once, and immutable bytes are retained for dispatch. Streaming uploads are never copied from one in-flight backend request into another.
- **Protocol-faithful replay**: Secured mesh attempts retain the pristine `HeaderMap` alongside the body and merge the authoritative post-plugin header view onto it for every attempt. Unchanged repeated fields and native gRPC `-bin` metadata therefore stay as separate field lines; plugin replacements/removals, reserved-assertion stripping, hop-by-hop stripping, forwarding-header regeneration, gRPC `te: trailers`, and framing repair are still applied at the outbound boundary. Validated gRPC-Web request trailers use their staged native representation. Buffered mesh requests (retry retain or body-policy buffering) carrying native request trailers fail closed before backend admission because the generic intake path cannot validate or forward those trailers; streaming native requests are unchanged.
- **Connection failures**: Only failures classified as pre-wire (DNS, connect, TLS/pool/handshake) bypass the method filter. The retained body is safe to replay because the application received no request bytes.
- **HTTP status and post-wire failures**: Replay requires both a configured retryable status/error and a method in `retryable_methods`; this is the explicit side-effect/idempotency gate.
- **Per-attempt phases**: Target selection, health/circuit-breaker checks, backend admission and adaptive-concurrency reservation, DNS, mesh identity/authorization, pool acquisition, and passive-health/outcome recording run for each attempt. Request transforms/finalization do not.
- **Response streaming**: The retry decision is made from response headers alone (status code, connection-error flag, error class, method), so a proxy configured for streaming streams on *every* attempt, not just the last one. An attempt selected for retry drops its undrained response before any byte reaches the client. See [Interaction with Retry Logic](response_body_streaming.md#interaction-with-retry-logic).

## Examples

### Connection-Failure-Only Retries (Default Behavior)

Retry only when the backend is unreachable — no retries on HTTP error responses:

```yaml
retry:
  max_retries: 3
  retry_on_connect_failure: true
```

### Full Retry with Exponential Backoff

Retry on both connection failures and specific HTTP status codes with exponential backoff:

```yaml
retry:
  max_retries: 3
  retryable_status_codes: [502, 503, 504]
  retryable_methods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]
  retry_on_connect_failure: true
  backoff: !exponential
    base_ms: 100
    max_ms: 5000
```

### Aggressive Retry for Critical Idempotent APIs

Higher retry count with fast fixed backoff for APIs that must succeed:

```yaml
retry:
  max_retries: 5
  retryable_status_codes: [502, 503, 504]
  retryable_methods: ["GET"]
  retry_on_connect_failure: true
  backoff: !fixed
    delay_ms: 50
```

### Including POST in Retries

If your API uses idempotency keys and POST requests are safe to retry:

```yaml
retry:
  max_retries: 2
  retryable_status_codes: [502, 503]
  retryable_methods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "POST"]
  retry_on_connect_failure: true
  backoff: !fixed
    delay_ms: 200
```

### Connection-Failure Retries with Status-Code Retries Disabled

Useful when you want to retry transport-level failures but trust all HTTP responses from the backend:

```yaml
retry:
  max_retries: 3
  retryable_status_codes: []
  retry_on_connect_failure: true
```

This is equivalent to the minimal configuration since `retryable_status_codes` defaults to empty.

## Configuration Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `max_retries` | integer | `3` | Maximum number of retry attempts (not counting the initial request). Range: 0–100. |
| `retryable_status_codes` | array of integers | `[]` (empty) | HTTP status codes that trigger a retry. Empty means no status-code retries. |
| `retryable_methods` | array of strings | `["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]` | HTTP methods eligible for status-code retries. Connection failure retries ignore this filter. Case-insensitive. |
| `retry_on_connect_failure` | boolean | `true` | Whether to retry on TCP/connection-level failures (refused, timeout, DNS, TLS). |
| `backoff` | tagged enum | `!fixed { delay_ms: 100 }` | Backoff strategy between retries. Either `!fixed { delay_ms }` or `!exponential { base_ms, max_ms }`. |

### Validation Rules

- `max_retries` must be between 0 and 100
- `retryable_status_codes` must contain valid HTTP status codes (100–599)
- `retryable_methods` must contain valid HTTP methods (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE)
- For exponential backoff, `base_ms` must not exceed `max_ms`
- `delay_ms` (fixed) and `max_ms` (exponential) must not exceed 300,000ms (5 minutes)

### TCP passthrough connection retries

TCP passthrough honors `retry_on_connect_failure` and `max_retries` for DNS, circuit-breaker admission, per-target connection-cap admission, and plain TCP connect failures. Each retry uses the existing healthy-target selection and mesh enforcement, preserves the original stream authorization deadline, and updates connection accounting for the selected target. ClientHello peeking and stream-connect plugins run once; outbound PROXY framing and encrypted client bytes are forwarded only after connection setup succeeds. No retry occurs after outbound framing or relay begins.
