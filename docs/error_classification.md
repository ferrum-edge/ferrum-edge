# Error Classification

This document describes the unified error-classification taxonomy used across every protocol path in the gateway (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP, TCP+TLS, UDP, DTLS) and how it flows into the transaction summary fields consumed by logging plugins.

The goal is **one taxonomy, one boundary, one set of typed downcasts** — operators grep the same labels regardless of which dispatcher emitted the failure, and dashboards key off enum variants, not substring matches.

Classification runs only on the error path — successful requests never execute it, so there is zero hot-path overhead.

## Canonical taxonomy (`ErrorClass`)

Every classifier funnels its result into [`crate::retry::ErrorClass`](../src/retry.rs). Variants serialize as `snake_case` strings (`"connection_timeout"`, `"tls_error"`, …).

| Variant | Meaning | `request_reached_wire`? |
|---|---|---|
| `ConnectionRefused` | TCP connect refused (port not listening, firewall RST). Includes connect-phase RSTs (functionally indistinguishable from ECONNREFUSED). | `false` (pre-wire) |
| `ConnectionTimeout` | TCP connect did not complete before the configured timeout. | `false` (pre-wire) |
| `ConnectionReset` | Mid-stream RST received after the connection was established. | `true` (post-wire) |
| `ConnectionClosed` | Peer sent FIN before a response was completed; broken pipe; aborted connection. | `true` (post-wire) |
| `DnsLookupError` | Hostname could not be resolved. | `false` (pre-wire) |
| `TlsError` | TLS or DTLS handshake failed (certificate, ALPN, alert). | `false` (pre-wire) |
| `ReadWriteTimeout` | Backend read or write exceeded the per-direction watermark. | `true` (post-wire) |
| `ProtocolError` | HTTP/2 or HTTP/3 protocol-level error (stream reset, GOAWAY, h2c handshake), or RFC 6455 WebSocket protocol violation. | `true` (post-wire) |
| `ResponseBodyTooLarge` | Backend response exceeded the configured maximum size. | `true` (post-wire) |
| `RequestBodyTooLarge` | Request body exceeded the configured maximum size. | `true` (post-wire) |
| `ConnectionPoolError` | Could not acquire or create an HTTP client from the pool. | `false` (pre-wire) |
| `PortExhaustion` | EADDRNOTAVAIL — all ephemeral ports in use. | `false` (pre-wire) |
| `ClientDisconnect` | Client gave up before the gateway could complete the response. | `true` (post-wire) |
| `GracefulRemoteClose` | Peer closed the session cleanly: HTTP/3 `H3_NO_ERROR`/GOAWAY at the response read boundary, or RFC 6455 Close frame on a WebSocket. Excluded from H3 capability downgrades so a backend that closes after every response stays on H3. | `true` (post-wire) |
| `RequestError` | Catch-all for unclassified gateway-side rejections (plugin denials, unknown failure modes). | `true` (post-wire) |

Two helpers live with the enum:

- [`request_reached_wire(class)`](../src/retry.rs) — the single boundary that decides whether `BackendResponse::connection_error` is `true` (the body never went on the wire, so retry-on-connect-failure can fire regardless of method idempotency) or `false` (the body may have been processed, so retries must respect `retryable_methods`). Every classifier funnels through this; per-classifier `connection_error: bool` fields are intentionally absent so the predicate cannot drift.
- [`error_class_log_kind(class)`](../src/retry.rs) — stable short labels (`"connect_failure"`, `"tls_error"`, `"graceful_remote_close"`, …) emitted as the `error_kind` field on `tracing::error!` lines from every dispatcher. Operators grep one set of strings across protocols.

## Per-protocol classifiers

Each dispatcher hands its native error type to a classifier; every classifier returns `ErrorClass`. **Typed source-chain walking is preferred to substring matching** — string fallbacks remain only as defence-in-depth for legacy error types that don't expose typed sources.

| Protocol | Classifier | Input | Technique |
|---|---|---|---|
| HTTP/1.1 (reqwest) | [`classify_reqwest_error`](../src/retry.rs) | `&reqwest::Error` | `is_connect()` / `is_timeout()` typed methods → typed source-chain walk for io/TLS/DNS → bounded substring fallback inside the `is_connect()` branch |
| HTTP/2 (direct pool) | [`classify_http2_pool_error`](../src/proxy/http2_pool.rs) | `&Http2PoolError` (typed enum) | Pattern match on typed variants → typed source-chain walk (io/hyper/rustls) → minimal Display fallback |
| HTTP/3 (native pool) | [`classify_http3_error`](../src/http3/client.rs) | `&dyn Error` | Typed walk for `quinn::ConnectionError` / `quinn::ConnectError` / `io::Error` → anchored substring fallback for `h3::Error` Display |
| gRPC | [`classify_grpc_proxy_error`](../src/retry.rs) | `&GrpcProxyError` (typed enum with kinds) | Pattern match on `BackendUnavailable.kind: GrpcBackendUnavailableKind` → typed `is_port_exhaustion` source walk → no message substring matching |
| WebSocket / generic boxed | [`classify_boxed_error`](../src/retry.rs) | `&dyn Error` | Typed walk: `StreamSetupError` (TCP/UDP setup) → `tokio_tungstenite::tungstenite::Error` (RFC 6455 ConnectionClosed/AlreadyClosed/Protocol) → `io::Error` → `hyper::Error` → bounded Display/Debug fallback |
| TCP relay (stream) | [`classify_stream_error`](../src/proxy/tcp_proxy.rs) | `&anyhow::Error` | Thin wrapper over `classify_boxed_error` — same typed walk |
| Streaming response body | [`classify_body_error`](../src/retry.rs) | `&dyn Error` | Typed walk for io/hyper, returns `(ErrorClass, client_disconnected: bool)` |

The H3 pool returns a typed [`H3PoolError`](../src/http3/client.rs) whose `request_on_wire()` flag is the **authoritative** body-on-wire signal — `connection_error` is derived directly from `!e.request_on_wire()` at H3 dispatch sites, NOT from the class. See [docs/http3.md](http3.md) for that contract.

## Stream-family typed errors (`StreamSetupError`)

TCP and UDP relays previously classified their setup-phase failures by `.contains()`-matching shared error-message prefixes (`STREAM_ERR_FRONTEND_TLS_HANDSHAKE_FAILED`, etc.) to disambiguate frontend vs backend TLS, plugin rejects, and load-balancer failures. That mechanism was fragile: a typo at a construction site or a reworded `format!()` silently broke cause attribution.

[`StreamSetupError`](../src/proxy/stream_error.rs) replaces the substring approach with a typed kind:

```rust
pub enum StreamSetupKind {
    FrontendTlsHandshake,   // client → gateway TLS failed (client-side)
    BackendTlsHandshake,    // gateway → backend TCP-TLS failed (backend-side)
    BackendDtlsHandshake,   // gateway → backend DTLS failed (backend-side)
    RejectedByPlugin,       // umbrella for ACL/policy/throttle rejections (client-side)
    NoHealthyTargets,       // load-balancer pool empty / all circuit-broken (backend-side)
}
```

`StreamSetupKind::tls_side()`, `is_client_side()`, and `direction()` derive cause/direction attribution **directly from the typed kind**. The `Display` impl reproduces the legacy `STREAM_ERR_*` prefix verbatim (a regression test enforces this) so log consumers and dashboards keying on the wording continue to work.

Construction-site idiom:

```rust
return Err(StreamSetupError::with_source(
    StreamSetupKind::BackendTlsHandshake,
    format!("to {addr}: {e}"),
    e, // typed io::Error / rustls::Error preserved on `source()`
).into()); // boxes into anyhow::Error
```

The cause/direction mappers walk the chain via `find_stream_setup_error()` — `.context()`, `.into()`, and intermediate wrappers do not break the typed lookup.

## gRPC typed errors

`GrpcProxyError::BackendUnavailable` carries a [`GrpcBackendUnavailableKind`](../src/proxy/grpc_proxy.rs) so the classifier reads the failure mode from the typed kind:

| Kind | Class | Notes |
|---|---|---|
| `DnsResolution` | `DnsLookupError` | `dns_cache.resolve()` failure (pre-wire) |
| `Connect` | `ConnectionRefused` | TCP connect failed, post-DNS (pre-wire) |
| `TlsHandshake` | `TlsError` | rustls handshake (pre-wire) |
| `H2Handshake` | `TlsError` | HTTP/2 handshake over TLS (pre-wire) |
| `H2cHandshake` | `ConnectionRefused` | HTTP/2 cleartext handshake — fails before any stream is opened, so request bytes never reach the application layer (pre-wire) |
| `InvalidServerName` | `DnsLookupError` | rustls rejected the SNI name (pre-wire) |
| `BackendRequest` | `ConnectionReset` | hyper `send_request` failed post-handshake — request bytes may already be on the wire, so this is **post-wire** by definition. Excluded from `is_connect_class()` so `retry_on_connect_failure` cannot bypass `retry_on_methods` and replay non-idempotent POSTs |

`GrpcBackendUnavailableKind::is_connect_class()` enumerates the pre-wire kinds; the gRPC and H3→gRPC retry loops use it to decide whether `retry_on_connect_failure` is eligible for a given failure. A regression test (`test_every_connect_class_kind_classifies_as_pre_wire`) enforces the invariant that every connect-class kind classifies to `!request_reached_wire(class)` so the retry-loop predicate and the canonical wire boundary cannot drift.

Construction sites attach a typed `source` so [`is_port_exhaustion`](../src/retry.rs)'s typed `io::Error::raw_os_error == EADDRNOTAVAIL` walk works on every gRPC dispatch path — not just the message-substring fallback.

## WebSocket graceful close

[`classify_boxed_error`](../src/retry.rs) downcasts `tokio_tungstenite::tungstenite::Error::ConnectionClosed` and `Error::AlreadyClosed` to `ErrorClass::GracefulRemoteClose`. These represent an orderly RFC 6455 close (the peer sent a Close frame, or we wrote after observing one) and must NOT inflate transport-failure metrics. `Error::Protocol(_)` maps to `ErrorClass::ProtocolError`.

`GracefulRemoteClose` is shared with the HTTP/3 graceful-close path: operators see one label whether the peer closed an H3 connection with `H3_NO_ERROR` or a WS connection with a normal Close frame.

## Transaction summary integration

Two summary types in [`src/plugins/mod.rs`](../src/plugins/mod.rs) carry classification fields:

### `TransactionSummary` (HTTP / gRPC / WebSocket)

| Field | Source | When populated |
|---|---|---|
| `error_class: Option<ErrorClass>` | per-protocol classifier | gateway-side failure reaching the backend |
| `body_error_class: Option<ErrorClass>` | `classify_body_error` | error during streaming-response-body delivery |
| `client_disconnected: bool` | `classify_body_error` returns `(_, true)` | client gave up after headers were sent |

### `StreamTransactionSummary` (TCP / UDP / DTLS)

| Field | Source | When populated |
|---|---|---|
| `error_class: Option<ErrorClass>` | `classify_stream_error` / `classify_boxed_error` | session-level failure |
| `disconnect_cause: Option<DisconnectCause>` | `pre_copy_disconnect_cause` (TCP) / `dtls_disconnect_cause` (UDP) | typed `StreamSetupKind` first, class fallback otherwise |
| `disconnect_direction: Option<Direction>` | `pre_copy_disconnect_direction` (TCP) / `dtls_disconnect_direction` (UDP) | typed `StreamSetupKind` first, class fallback otherwise — populated for UDP/DTLS sessions on the same terms as TCP, so operators can tell which side tore down a DTLS session |
| `connection_error: Option<String>` | `error.to_string()` | preserves the original message text alongside the typed class |

`disconnect_cause` and `disconnect_direction` agree by construction: both consult the same typed kind (when present) and apply the same class-driven fallback (when absent). Adding a new `ErrorClass` variant requires updating both class-fallback arms in lockstep — the exhaustive `match` on `ErrorClass` makes this a compile error rather than a silent miscategorisation.

## Adding a new error path

When you add a dispatcher or a new failure mode:

1. **Reuse `ErrorClass`.** Add a new variant only if the failure is genuinely orthogonal to every existing one (and update `request_reached_wire`, `error_class_log_kind`, and the per-protocol exhaustive matches in lockstep).
2. **Return typed errors at the construction site.** For stream-family proxies, prefer `StreamSetupError`. For gRPC, extend `GrpcBackendUnavailableKind`. Avoid bare `anyhow!()` for new paths that need cause/direction attribution.
3. **Walk `source()` in the classifier**, not the Display string. Add a typed downcast for the new error type before extending the substring fallback.
4. **Test the typed kind, not the message.** A regression test that wraps the typed error in `.context()` and re-derives the class is more robust than asserting the human-readable message format.

## Example log output

When a backend connection times out, the `TransactionSummary` JSON includes the proxy identity (so dashboards can attribute the failure to the right route) plus the typed `error_class`. `proxy_id` / `proxy_name` use the same JSON keys here as on `StreamTransactionSummary`, so log queries don't need to branch on protocol family:

```json
{
  "timestamp_received": "2026-04-28T12:00:00.000Z",
  "client_ip": "10.0.0.1",
  "http_method": "GET",
  "request_path": "/api/v1/users",
  "proxy_id": "abc123",
  "proxy_name": "users-api",
  "backend_target_url": "https://upstream.internal:8443/api/v1/users",
  "backend_resolved_ip": "10.0.2.10",
  "response_status_code": 502,
  "error_class": "connection_timeout",
  "latency_total_ms": 30000.0
}
```

For a successful request, `error_class` is omitted entirely (skipped via `#[serde(skip_serializing_if = "Option::is_none")]`).

For a TCP/DTLS session that the backend tore down mid-relay — same `proxy_id` / `proxy_name` keys as the HTTP example, plus the stream-only fields (`backend_target`, `protocol`, `listen_port`, `disconnect_*`):

```json
{
  "proxy_id": "abc123",
  "proxy_name": "redis-tls",
  "client_ip": "10.0.0.1",
  "backend_target": "10.0.2.10:6379",
  "backend_resolved_ip": "10.0.2.10",
  "protocol": "tcps",
  "listen_port": 6379,
  "duration_ms": 1234.5,
  "bytes_sent": 65536,
  "bytes_received": 0,
  "connection_error": "Backend TLS handshake failed to 10.0.2.10:6379: alert: bad_certificate",
  "error_class": "tls_error",
  "disconnect_direction": "backend_to_client",
  "disconnect_cause": "backend_error"
}
```

## Debugging guide

Refer to the canonical-taxonomy table above for what each class means. A few class-specific operational notes:

- **`ConnectionPoolError`** — pool exhaustion. Increase `FERRUM_POOL_MAX_IDLE_PER_HOST` or per-proxy `pool_idle_timeout`.
- **`PortExhaustion`** — EADDRNOTAVAIL. Widen the port range with `sysctl net.ipv4.ip_local_port_range="1024 65535"`, enable `net.ipv4.tcp_tw_reuse=1`, and reduce idle pool timeouts (`FERRUM_POOL_IDLE_TIMEOUT_SECONDS`). Monitor via the `port_exhaustion_events` counter on `GET /overload`.
- **`TlsError`** — for self-signed certs in development, set `FERRUM_TLS_NO_VERIFY=true`. For mTLS backends, verify the client certificate and CA chain. The typed `StreamSetupKind::FrontendTlsHandshake` vs `BackendTlsHandshake`/`BackendDtlsHandshake` tells you which side failed without inspecting the message.
- **`GracefulRemoteClose`** — informational, not an error. The peer closed the session cleanly. Do not alert on this.
- **`ClientDisconnect`** — the client (not the backend) dropped the connection. Often benign (user navigated away). High rates may indicate aggressive client-side timeouts.

## Reading material

- [`src/retry.rs`](../src/retry.rs) — `ErrorClass`, `request_reached_wire`, `error_class_log_kind`, `classify_*` functions
- [`src/proxy/stream_error.rs`](../src/proxy/stream_error.rs) — typed stream-family error wrapper
- [`src/proxy/grpc_proxy.rs`](../src/proxy/grpc_proxy.rs) — `GrpcProxyError`, `GrpcBackendUnavailableKind`
- [`src/proxy/tcp_proxy.rs`](../src/proxy/tcp_proxy.rs) — `pre_copy_disconnect_cause`, `pre_copy_disconnect_direction`
- [`src/proxy/udp_proxy.rs`](../src/proxy/udp_proxy.rs) — `dtls_disconnect_cause`, `dtls_disconnect_direction`
- [`src/http3/client.rs`](../src/http3/client.rs) — typed `H3PoolError` with `request_on_wire()` body-on-wire signal
- [`src/proxy/http2_pool.rs`](../src/proxy/http2_pool.rs) — `Http2PoolError` typed classifier (exemplary template)
