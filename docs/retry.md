# Retry Logic

Ferrum Gateway provides configurable retry logic for failed backend requests. Retries are configured per-proxy and support both connection-level and HTTP status-code-level failure detection with fixed or exponential backoff strategies.

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
| TCP / TCP+TLS | No | Stream-based protocol, no request/response retry semantics |
| UDP / DTLS | No | Datagram-based protocol, application-level retry responsibility |

HTTP-family protocols (HTTP/1.1, HTTP/2, HTTP/3) share the same retry loop in the proxy core and support both connection failure and HTTP status code retries.

gRPC retries handle connection-level failures (connect refused, timeout, DNS, TLS) by buffering the request body and replaying it against alternative upstream targets. Read timeouts and gRPC application-level errors (e.g., UNAVAILABLE status in trailers) are not retried because the request was already sent to the backend.

WebSocket retries handle connection-level failures during the initial backend connection attempt (before the 101 Switching Protocols response). Once the WebSocket connection is established, retries no longer apply — the bidirectional stream is managed by the application layer.

## Configuration

Add a `retry` block to any proxy to enable retries:

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
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

These are retried when `retry_on_connect_failure: true` (the default). Because the request never reached the backend, **all HTTP methods are retried** — idempotency is not a concern since nothing was processed.

### HTTP Status Code Failures

HTTP status-code failures are real HTTP responses from the backend (e.g., 502 Bad Gateway from an upstream load balancer, 503 during deployment). These are retried only when:

1. The response status code is in `retryable_status_codes`
2. The request method is in `retryable_methods`

By default, `retryable_status_codes` is **empty** — no status-code retries occur unless you explicitly configure them. This means a default retry configuration only retries connection failures.

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

When a proxy has both `retry` and `upstream_id` configured, retries automatically select a **different target** from the upstream on each attempt. The retry loop calls `select_next_target()` with the previous target excluded, maximizing the chance of reaching a healthy backend.

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
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

- **Connection failures**: The request body was never sent to the backend, so it is safely replayed on retry.
- **HTTP status failures**: The request body is retained (buffered) and replayed on each retry attempt.
- **Final attempt**: On the last retry attempt, the response streams directly to the client if the proxy is configured for streaming (no additional buffering).

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
