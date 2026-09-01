# Error Classification

This document describes the unified error-classification taxonomy used across every protocol path in the gateway (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP, TCP+TLS, UDP, DTLS) and how it flows into the transaction summary fields consumed by logging plugins.

The goal is **one taxonomy, one boundary, one set of typed downcasts** — operators grep the same labels regardless of which dispatcher emitted the failure, and dashboards key off enum variants, not substring matches.

Classification runs only on the error path — successful requests never execute it, so there is zero hot-path overhead.

## Canonical taxonomy (`ErrorClass`)

Every classifier funnels its result into [`crate::retry::ErrorClass`](../src/retry.rs). Variants serialize as `snake_case` strings (`"connection_timeout"`, `"tls_error"`, …).

| Variant | Meaning | `request_reached_wire`? |
|---|---|---|
| `ConnectionRefused` | TCP connect refused (port not listening, firewall RST). Includes connect-phase RSTs (functionally indistinguishable from ECONNREFUSED). A TLS handshake that fails *after* TCP connect — including `rustls::Error` wrapped as `io::Error` with `ConnectionReset` — is **not** this class; that is `TlsError`. | `false` (pre-wire) |
| `ConnectionTimeout` | TCP connect did not complete before the configured timeout. | `false` (pre-wire) |
| `ConnectionReset` | Mid-stream RST received after the connection was established **and** (for TLS) after the handshake completed. A handshake-phase reset that carries a typed rustls handshake/alert/certificate error is `TlsError`, not this class. An origin that RSTs during handshake with **no** rustls error in the chain is indistinguishable from a mid-stream RST and stays here. | `true` (post-wire) |
| `ConnectionClosed` | Peer sent FIN before a response was completed; broken pipe; aborted connection; post-connect `UnexpectedEof` / hyper incomplete message (truncated HTTP body). | `true` (post-wire) |
| `DnsLookupError` | Hostname could not be resolved. | `false` (pre-wire) |
| `TlsError` | TLS or DTLS handshake failed (certificate, ALPN, handshake alert, rustls error under an `io::Error` after TCP connected) **when a typed `rustls::Error` is in the chain**. Missing `close_notify` is teardown, not this class. | `false` (pre-wire) |
| `ReadWriteTimeout` | Backend read or write exceeded the per-direction watermark. | `true` (post-wire) |
| `ProtocolError` | HTTP/2 or HTTP/3 protocol-level error after a stream is opened (stream reset, GOAWAY, RST_STREAM), or RFC 6455 WebSocket protocol violation. NOTE: gRPC h2c handshake failure classifies as `ConnectionRefused` (pre-wire), NOT `ProtocolError` — see the gRPC kind table below. | `true` (post-wire) |
| `ResponseBodyTooLarge` | Backend response exceeded the configured maximum size. | `true` (post-wire) |
| `GatewayBufferCapacity` | The gateway's process-wide budget for *retained* (buffered) response bodies could not admit this response (`FERRUM_RESPONSE_BUFFER_MAX_TOTAL_BYTES`). The backend answered correctly and within every per-response ceiling, so this is gateway-local transient capacity, not a backend fault: it is non-retryable and backend-health-neutral (`client_side_no_backend_signal`), and surfaces as HTTP `503` / gRPC `RESOURCE_EXHAUSTED`. | `true` (gateway-local terminal) |
| `RequestBodyTooLarge` | Request body exceeded the configured maximum size. | `true` (post-wire) |
| `ConnectionPoolError` | Could not acquire or create an HTTP client from the pool. Also the reqwest/HTTP/1 mapping of hyper `is_canceled()` (the request was never dispatched — issue #3578). A backend that requires a client certificate can land here on the reqwest path when rustls is not in the request chain (issue #4406). | `false` (pre-wire) |
| `PortExhaustion` | EADDRNOTAVAIL — all ephemeral ports in use. | `false` (pre-wire) |
| `ClientDisconnect` | Client gave up before the gateway could complete the response. | `true` (post-wire) |
| `GracefulRemoteClose` | Peer closed the session cleanly: HTTP/3 `H3_NO_ERROR`/GOAWAY at the response read boundary, or RFC 6455 Close frame on a WebSocket. Excluded from H3 capability downgrades so a backend that closes after every response stays on H3. | `true` (post-wire) |
| `DispatchPolicyRejected` | Terminal gateway decision before a backend dial, including egress/SNI policy, admission overflow, and final request-body hook rejection. It is non-retryable and backend-health-neutral. | `true` (gateway-local terminal) |
| `BackendConnectionLimit` | The gateway refused to open a NEW physical backend connection because the destination is already at its DestinationRule `connectionPool.tcp.maxConnections` ceiling (`src/backend_conn_limit.rs`). Emitted by direct H2, gRPC, native H3, HBONE, and Sidecar mesh-mTLS. With `TrustWithdrawn` (the other gateway-side policy refusal) it is one of only two classes that are simultaneously pre-wire (so `retry_on_connect_failure` may rotate to another target with its own admission lane) and backend-health-neutral (`client_side_no_backend_signal`) — a saturated operator-configured ceiling is gateway policy, not evidence about the backend, so it must not trip the circuit breaker, ding passive health, penalize the load balancer, or shrink the adaptive-concurrency permit. The raw-TCP over-cap path records `cb.record_neutral()` for the same reason. The reqwest/HTTP-1.1 and WebSocket lanes instead answer `503` / `DispatchPolicyRejected` because they do not rotate. | `false` (pre-wire) |
| `TrustWithdrawn` | An accepted gateway trust publication withdrew an authority, so a gateway-to-mesh TLS transport was refused (`src/proxy/mesh_trust_registry.rs`, issue #3859): either the connection was dialed under the outgoing trust generation and refused at registration, or a checked-out HBONE tunnel / mesh-mTLS sender was retired before it could open the next stream. Emitted by the HBONE and Sidecar mesh-mTLS pools and by native gRPC over either. Like `BackendConnectionLimit` it is simultaneously pre-wire (so `retry_on_connect_failure` may re-dial — and the redial succeeds, because the accepted generation is already published) and backend-health-neutral (`client_side_no_backend_signal`) — withdrawing a root is gateway policy, not evidence about the destination workload, so it must not trip the circuit breaker, ding passive health, penalize the load balancer, or shrink the adaptive-concurrency permit. The generic `ConnectionPoolError` would open breakers across every mesh destination live at the instant of a revocation. | `false` (pre-wire) |
| `RequestError` | Catch-all for unclassified gateway-side rejections and unknown failure modes. | `true` (post-wire) |

Two helpers live with the enum:

- [`request_reached_wire(class)`](../src/retry.rs) — the single boundary that decides whether `BackendResponse::connection_error` is `true` (the body never went on the wire, so retry-on-connect-failure can fire regardless of method idempotency) or `false` (the body may have been processed, so retries must respect `retryable_methods`). Every classifier funnels through this; per-classifier `connection_error: bool` fields are intentionally absent so the predicate cannot drift.
- [`error_class_log_kind(class)`](../src/retry.rs) — stable short labels (`"connect_failure"`, `"tls_error"`, `"graceful_remote_close"`, …) emitted as the `error_kind` field on `tracing::error!` lines from every dispatcher. Operators grep one set of strings across protocols.

## Connect / handshake / cancel / reset boundary (HTTP reqwest)

`reqwest::Error::is_connect()` is TCP-only. After the SYN completes, a TLS handshake failure is a **third** case, distinct from a connect-phase RST and from a mid-stream RST. When rustls is **not** in the request chain, hyper `is_canceled()` is a **fourth** case (pre-wire pool cancel):

| Case | Evidence | Class | `request_reached_wire` |
|---|---|---|---|
| (1) Connect-phase TCP | `is_connect() = true`, no rustls in the chain; RST / refused | `ConnectionRefused` | `false` |
| (2) Handshake-phase | Typed `rustls::Error` handshake / certificate / ALPN / handshake alert (`CertificateRequired`, `HandshakeFailure`, `InvalidCertificate`, `HandshakeNotComplete`, …), including rustls in `io::Error::get_ref()` after TCP connected | `TlsError` | `false` |
| (3) Pool cancel | `hyper::Error::is_canceled()` (no rustls). Live backend-mTLS on reqwest HTTP/1: hyper-util returns the connection, the handshake failure then kills the connection future, and the queued request is canceled with no rustls in the chain (issue #4406) | `ConnectionPoolError` | `false` |
| (4) Post-handshake mid-stream | RST with no handshake rustls and not canceled, or post-handshake rustls (`DecryptError`, oversized record, mid-stream alert) | `ConnectionReset` | `true` |

Handshake `TlsError` evidence is the **typed** rustls variant (and `io::Error::get_ref()` so `source()` cannot skip the payload). Display text is not used when a typed source is reachable. Do **not** classify by matching `"connection was not ready"`: that label also covers every other reason a pooled connection was not ready; the typed `is_canceled` flag is the evidence. An origin that RSTs during handshake **without** rustls and **without** `is_canceled` is indistinguishable from case (4) and stays `ConnectionReset`.

Omitted TLS `close_notify` is teardown (#4051): `UnexpectedEof` whose Display contains `without sending TLS close_notify` is matched **before** rustls so it cannot become `TlsError`. HTTPS-to-plaintext remains `TlsError` (#4053).

Because `TlsError` and `ConnectionPoolError` are pre-wire, a backend mTLS failure on this path is replayable under `retry_on_connect_failure` regardless of method — nothing reached the origin's application layer. Circuit-breaker charging follows the **connect-error** path (`trip_on_connection_errors`, default on) instead of the post-wire `ConnectionReset` / 502-status path. Passive health still records a backend failure (`connection_error` is true). The public `X-Gateway-Error` token is `connection_failure`, not `backend_error`.

`PluginHttpClient` (`FERRUM_PLUGIN_HTTP_MAX_RETRIES`) has a separate safe-method transport-retry list. It is not `!request_reached_wire()`: GET/HEAD/OPTIONS also replay some post-wire classes (`ConnectionReset`, `ConnectionClosed`, `ProtocolError`, `RequestError`, `ReadWriteTimeout`). After issue #4406 that list includes `ConnectionPoolError` so a hyper `is_canceled` drop still retries. It still omits `TlsError` (handshake misconfig rarely recovers on replay) and the health-neutral policy classes. Gateway backend dispatch continues to use `request_reached_wire` / `retry_on_connect_failure`.

## Per-protocol classifiers

Each dispatcher hands its native error type to a classifier; every classifier returns `ErrorClass`. **Typed source-chain walking is preferred to substring matching** — string fallbacks remain only as defence-in-depth for legacy error types that don't expose typed sources.

| Protocol | Classifier | Input | Technique |
|---|---|---|---|
| HTTP/1.1 (reqwest) | [`classify_reqwest_error`](../src/retry.rs) | `&reqwest::Error` | `is_connect()` / `is_timeout()` typed methods → typed source-chain walk for io/TLS/DNS. **Four-way boundary:** (1) connect-phase RST/refused with no rustls → `ConnectionRefused`; (2) typed handshake rustls (`CertificateRequired`, `HandshakeFailure`, `InvalidCertificate`, …) → `TlsError` even when `is_connect()` is false (reqwest's flag is TCP-only); (3) hyper `is_canceled()` with no rustls → `ConnectionPoolError` (issue #4406 live reqwest path; issue #3578); (4) mid-stream RST with no handshake rustls → `ConnectionReset`. Missing `close_notify` is matched *before* rustls so it stays `ConnectionClosed` (#4051). Post-connect `UnexpectedEof` / incomplete message → `ConnectionClosed`. Bounded substring fallback inside the `is_connect()` branch |
| HTTP/2 (direct pool acquisition) | [`classify_http2_pool_error`](../src/proxy/http2_pool.rs) | `&Http2PoolError` (typed enum) | Pattern match on typed variants. `BackendUnavailableSource::Tls` is a construction-site handshake-phase signal and classifies as `TlsError` (except TimedOut → `ConnectionTimeout` and port exhaustion). Other io walks peek rustls via `io::Error::get_ref()` before the connect-phase RST collapse. |
| HTTP/2 (pooled request send) | [`classify_pooled_h2_send_request_error`](../src/proxy/http2_pool.rs) | `&hyper::Error` | Hyper typed predicates → post-wire io source-chain walk → conservative `ProtocolError` fallback |
| HTTP/3 (native pool) | [`classify_http3_error`](../src/http3/client.rs) | `&dyn Error` | Typed walk for `quinn::ConnectionError` / `quinn::ConnectError` / `io::Error` → anchored substring fallback for `h3::Error` Display |
| gRPC | [`classify_grpc_proxy_error`](../src/retry.rs) | `&GrpcProxyError` (typed enum with kinds) | Pattern match on `BackendUnavailable.kind: GrpcBackendUnavailableKind` → typed `is_port_exhaustion` source walk → no message substring matching |
| WebSocket / generic boxed | [`classify_boxed_error`](../src/retry.rs) | `&dyn Error` | Typed walk: `StreamSetupError` (TCP/UDP setup) → `tokio_tungstenite::tungstenite::Error` (RFC 6455 ConnectionClosed/AlreadyClosed/Protocol) → `io::Error` → `hyper::Error` → bounded Display/Debug fallback |
| TCP relay (stream) | [`classify_stream_error`](../src/proxy/tcp_proxy.rs) | `&anyhow::Error` | Thin wrapper over `classify_boxed_error` — same typed walk |
| Streaming response body | [`classify_body_error`](../src/retry.rs) | `&dyn Error` | Typed walk for io/hyper, returns `(ErrorClass, client_disconnected: bool)` |

The H3 pool returns a typed [`H3PoolError`](../src/http3/client.rs) whose `request_on_wire()` flag is the **authoritative** body-on-wire signal — `connection_error` is derived directly from `!e.request_on_wire()` at H3 dispatch sites, NOT from the class. See [docs/http3.md](http3.md) for that contract.

Direct-H2 pool acquisition and pooled request dispatch have different phase boundaries. Acquisition errors are pre-wire. Once a pooled sender is acquired, `hyper::Error::is_canceled()` is the only typed proof that dispatch never occurred; every other known or unknown send failure is post-wire. In particular, a connect-only class inferred from an inner I/O source is normalized to `ProtocolError`, because an inner `ConnectionRefused` or port-exhaustion errno cannot prove that an already-pooled request was never sent.

## Stream-family typed errors (`StreamSetupError`)

TCP and UDP relays previously classified their setup-phase failures by `.contains()`-matching shared error-message prefixes (`STREAM_ERR_FRONTEND_TLS_HANDSHAKE_FAILED`, etc.) to disambiguate frontend vs backend TLS, plugin rejects, and load-balancer failures. That mechanism was fragile: a typo at a construction site or a reworded `format!()` silently broke cause attribution.

[`StreamSetupError`](../src/proxy/stream_error.rs) replaces the substring approach with a typed kind:

```rust
pub enum StreamSetupKind {
    FrontendTlsHandshake,   // client → gateway TLS failed (client-side)
    BackendTlsHandshake,    // gateway → backend TCP-TLS failed (backend-side)
    BackendDtlsHandshake,   // gateway → backend DTLS failed (backend-side)
    RejectedByPlugin,       // umbrella for ACL/policy/throttle rejections (client-side)
    DnsLookup,              // backend hostname did not resolve (backend-side, pre-wire)
    NoHealthyTargets,       // LB pool empty, empty subset, or no family-matching backends (backend-side)
    CircuitBreakerOpen,     // per-proxy passive-health circuit breaker is open (backend-side)
    BackendMaxConnectionsExceeded, // DestinationRule connectionPool.tcp.maxConnections cap hit at backend dial (backend-side)
}
```

`DnsLookup` maps to `ErrorClass::DnsLookupError` so TCP/UDP/DTLS setup DNS
failures grep the same class as HTTP and gRPC. Construction sites go through
`stream_error::stream_dns_setup_error(host, source)`, whose Display keeps the
legacy `"DNS resolution failed for {host}: {source}"` wording.

One resolve failure is deliberately **not** typed as `DnsLookup`: a target
refused by the backend egress policy. No query was answered and no backend was
consulted, so it stays `DispatchPolicyRejected` — non-retryable and neutral to
backend health, matching the `record_neutral` circuit-breaker accounting the
same call sites already perform. Typing it would let the typed walk override
that classification.

### UDP setup failures that never publish a session

A UDP setup attempt emits exactly one `StreamTransactionSummary`, and which
side emits it is decided by the operation itself (`UdpSetupProgress`), never by
probing the session map afterwards:

- **Setup owns** every failure observed before `sessions.insert` — DNS, empty
  pool, plugin reject, circuit breaker, backend bind/connect, backend DTLS
  handshake. The summary carries the epoch the attempt was *admitted* under:
  that generation's stream plugin slice, the proxy lifecycle generation, the
  connect-time execution-trigger decisions, and the `StreamConnectionContext`
  identity/auth/SNI/metadata. The backend target is the one selection actually
  chose (load balancer or mesh preselection), not the proxy's configured
  default.
- **The published session owns** everything after that insert, including an
  error the spawned setup task observes later — even if the session has already
  been removed by idle expiry, shutdown, or reload. A removed session does not
  hand ownership back to setup; doing so would produce a duplicate summary
  alongside the session's own disconnect summary.
- A failure *before* any epoch view resolved (for example the proxy was
  withdrawn between listener dispatch and setup) has no admitted plugin slice
  and no admitted generation. It records the transaction with no proxy name, no
  backend target, and `proxy_lifecycle_generation` unset, and notifies **no**
  plugins — invoking the current generation's plugins would attribute the
  failure to a configuration that never admitted it.

`NoHealthyTargets` and `CircuitBreakerOpen` are intentionally split: the former
fires from LB target selection when **no candidate exists** (empty pool, empty
subset, or no backend shares the session destination's address family). The
latter fires from the per-proxy circuit-breaker check (passive health,
failure-rate threshold). An upstream whose targets are all failing **active**
health checks still selects a target via the shared all-unhealthy fallback
documented in [load_balancing.md](load_balancing.md) ("Fallback When All
Unhealthy"); that degraded dial is a later connect failure
(`connection_refused` / `connection_timeout`), not `NoHealthyTargets`.
`max_ejection_percent` only re-admits **passive** ejections. Operators can
distinguish "no candidate exists" from "candidates exist but the gateway is
shedding traffic away from them" without joining across log streams.

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
| `TrustWithdrawn` | `TrustWithdrawn` | An accepted gateway trust publication withdrew an authority while a mesh transport was being established, or after a pooled transport was checked out but before it opened a stream (issue #3859). Pre-wire and backend-health-neutral — see the taxonomy table above |
| `DispatchCanceled` | `ConnectionPoolError` | Pooled H2 `send_request` returned hyper `is_canceled` for a **fully collected, caller-retained** outbound body — hyper's contract that the request was **never dispatched**. Pre-wire / connect-class so `retry_on_connect_failure` can redial after invalidating the stale sender. The criterion is REPLAYABILITY, not the carrier shape: a buffered body written through the `backend_write_timeout_ms` upload pump (issue #4055) is still the same caller-owned `Bytes`, so it keeps this kind. Only genuinely unreplayable streaming / channel bodies keep `BackendRequest` on `is_canceled` |

`GrpcBackendUnavailableKind::is_connect_class()` enumerates the pre-wire kinds; the gRPC and H3→gRPC retry loops use it to decide whether `retry_on_connect_failure` is eligible for a given failure. A regression test (`test_every_connect_class_kind_classifies_as_pre_wire`) enforces the invariant that every connect-class kind classifies to `!request_reached_wire(class)` so the retry-loop predicate and the canonical wire boundary cannot drift.

Construction sites attach a typed `source` so [`is_port_exhaustion`](../src/retry.rs)'s typed `io::Error::raw_os_error == EADDRNOTAVAIL` walk works on every gRPC dispatch path — not just the message-substring fallback.

## Response body-read failures

A body-read failure after the response headers arrived is always post-wire: `connection_error` stays `false` and `retry_on_connect_failure` can never replay a request the backend already processed.

The same mapping applies when the backend never produces response headers at all. Live HTTP-family dispatch (reqwest streaming and retry, H3 cross-protocol reqwest, direct H2 send, native H3, and the dedicated H2/HBONE/sidecar/unix header-wait and body-collect timeout arms) classifies through `ErrorClass` and then [`http_backend_failure_status_and_body`](../src/proxy/mod.rs) / [`http_backend_dispatch_error_response`](../src/proxy/mod.rs). `ReadWriteTimeout` is **504** with `{"error":"Backend timeout"}` (and `X-Gateway-Error: backend_timeout`); connect/refused/unavailable classes stay **502** with `{"error":"Backend unavailable"}` (and `X-Gateway-Error: connection_failure` when `connection_error` is set). That is the public pair README Troubleshooting documents.

The eager-buffer path (`buffered_backend_response_from_eager_collect` in [`src/proxy/mod.rs`](../src/proxy/mod.rs)) classifies through `classify_reqwest_error` rather than hardcoding one class. Idle `backend_read_timeout_ms` between buffered chunks (`next_reqwest_chunk_idle`) surfaces here as `ReadWriteTimeout` and uses the same 504 mapping as the dispatch-level helper, matching the direct-H2 arm's `HyperBodyCollectError::ReadTimeout` and the native-H3 read-timeout arm. Every other class keeps the 502. Identical backend behavior therefore produces the same status and `error_class` on every transport, so `TransactionSummary`, operator dashboards, and circuit-breaker `failure_status_codes` matching cannot diverge by dispatch path.

A pre-wire class is impossible on the eager-buffer path (response headers have already arrived, so a handshake failure cannot appear here), but one is coerced to `ConnectionReset` anyway so the documented `connection_error == !request_reached_wire(error_class)` boundary holds even if the classifier changes. Dispatch-level failures keep their classified pre-wire label so `retry_on_connect_failure` can still rotate to another target.

A backend FIN (or `UnexpectedEof`) before a complete HTTP body is `ConnectionClosed`. That class is post-wire, the same as the previous `RequestError` catch-all: `request_reached_wire` is `true` for both, so `BackendResponse::connection_error` stays `false` and `retry_on_connect_failure` does not replay the request. Non-idempotent methods are therefore not retried via the connect-failure path. Circuit-breaker accounting *does* change: `error_class_is_post_wire_backend_failure` includes `ConnectionClosed` and not `RequestError`, so a truncated body that had been a phantom success (HTTP 200 + catch-all class) now trips the breaker as a backend failure. When the public status is already 502 and 502 is in `failure_status_codes`, the breaker already trips via status.

## WebSocket graceful close

[`classify_boxed_error`](../src/retry.rs) downcasts `tokio_tungstenite::tungstenite::Error::ConnectionClosed` and `Error::AlreadyClosed` to `ErrorClass::GracefulRemoteClose`. These represent an orderly RFC 6455 close (the peer sent a Close frame, or we wrote after observing one) and must NOT inflate transport-failure metrics. `Error::Protocol(_)` maps to `ErrorClass::ProtocolError`.

A `Capacity` / `FrameTooLong` / `MessageTooLong` error is always a size-policy violation, mapped directionally to `RequestBodyTooLarge` (client→backend) or `ResponseBodyTooLarge` (backend→client) with an RFC 6455 Close 1009. That holds even for a valid 63-bit payload length above `u32::MAX`: RFC 6455 §5.2 permits any 63-bit length — only the most-significant bit of the 64-bit extended length must be zero — so a large advertised length is not itself malformed. Genuine protocol junk (for example issue #4058's stray continuation frame, whose well-formed 63-bit length masks an invalid Continue opcode with no fragmented message in progress) is parsed as `Error::Protocol`, so `classify_boxed_error` reports `ProtocolError`.

Handshake failures already populate `TransactionSummary.error_class` on the HTTP `log()` row. After a successful upgrade, in-session faults are classified into `WsDisconnectContext.error_class`. `stdout_logging` implements `on_ws_disconnect` and writes a second HTTP-family `TransactionSummary` JSON line using the admission-time handshake (`GET`/`101` for HTTP/1.1, `CONNECT`/`200` for RFC 8441/9220 Extended CONNECT, original client `request_path`) plus `error_class` from the disconnect context (BASE schema) so operators grepping access logs for `error_class` see the session-end class. `filter.errors_only` matches because `is_terminal_failure` is true when `error_class` is set. This is not the `websocket_disconnect` capability family used by `ws_logging`.

`GracefulRemoteClose` is shared with the HTTP/3 graceful-close path: operators see one label whether the peer closed an H3 connection with `H3_NO_ERROR` or a WS connection with a normal Close frame.

## HTTP/1.1 parse-layer 400 contract

Hyper rejects some HTTP/1.1 wire shapes during header parsing before Ferrum's
`handle_proxy_request` / `check_protocol_headers()` run. For the three shapes
the inbound `h1_framing_guard` can name with confidence — conflicting
`Content-Length` values, HTTP/1.0 + `Transfer-Encoding`, and an invalid UTF-8
request-target — the guard writes a static `400 Bad Request` directly on the
connection and closes it. Hyper never sees those requests and does not generate
its empty-bodied automatic `400`. The response uses the same JSON envelope
handler-layer protocol rejects use: `Content-Type: application/json`, a fixed
`{"error":"..."}` body matching `check_protocol_headers()`,
`X-Gateway-Error: request_error`, and `Connection: close`.

Admitted (well-formed) HTTP/1 requests keep the existing in-place observe path
and the same vectored writes as on `main`; the connection I/O type Hyper is
handed does not change.

Other Hyper parse failures the scanner cannot identify (for example a
non-numeric `Content-Length` that Hyper rejects at parse time, a truncated
head, or other httparse failures) stay Hyper's empty-bodied `400`. That gap is
intentional: a documented narrower miss is preferred over inspecting every
outbound HTTP/1 response on the hot path. Duplicate `Host` and combined
`Content-Length` + `Transfer-Encoding` still reach the handler and keep their
existing JSON bodies.

The envelope is armed only before the connection's first response byte. It is
written straight to the socket from the read path, bypassing Hyper's write
buffer, and Hyper's HTTP/1 server reads the next request head while an earlier
response is still being written — so on a keep-alive connection under write
backpressure a *pipelined* malformed request would otherwise splice the
envelope into the middle of the previous response. A malformed request
pipelined behind a response therefore falls back to Hyper's empty-bodied
`400`, exactly like the unnameable parse failures above. The common case — one
malformed request on a fresh connection — always gets the JSON envelope.

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
  "backend_target": "https://upstream.internal:8443/api/v1/users",
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

- **`ConnectionPoolError`** — pool exhaustion, or a reqwest/H1 send that hyper canceled before dispatch (`is_canceled`; issue #3578). A backend mTLS misconfig (origin requires a client certificate, gateway presents none) lands here on the reqwest HTTP/1 path when rustls is not in the request chain (issue #4406). Increase `FERRUM_POOL_MAX_IDLE_PER_HOST` or per-proxy `pool_idle_timeout` for genuine pool exhaustion; for the mTLS case configure `backend_tls_client_cert_path` / `backend_tls_client_key_path`.
- **`PortExhaustion`** — EADDRNOTAVAIL. Widen the port range with `sysctl net.ipv4.ip_local_port_range="1024 65535"`, enable `net.ipv4.tcp_tw_reuse=1`, and reduce idle pool timeouts (`FERRUM_POOL_IDLE_TIMEOUT_SECONDS`). Monitor via the `port_exhaustion_events` counter on authenticated `GET /overload` detail (unauthenticated callers receive only `{"level": ...}`).
- **`TlsError`** — for self-signed certs in development, set
  `FERRUM_TLS_NO_VERIFY=true`. For mTLS backends, verify the client certificate
  and CA chain. An origin that **requires** a client certificate when the
  gateway presents none is this class **when a typed rustls handshake error
  is in the chain**; on the reqwest HTTP/1 path that error is often missing
  and the class is `connection_pool_error` instead (issue #4406). Neither
  is `connection_reset`. The typed `StreamSetupKind::FrontendTlsHandshake` vs
  `BackendTlsHandshake`/`BackendDtlsHandshake` tells you which side failed
  without inspecting the message. Do **not** key alerts on `tls_error` for
  omitted `close_notify`: userspace rustls reports that as `UnexpectedEof`
  ("without sending TLS close_notify"). Two shapes are operator-visible and both
  are intentional: the TCP direction-tracking relay and the DTLS session outcome
  treat it as clean teardown and omit `error_class` entirely, while the
  all-bounds-disabled `copy_bidirectional` fast path (which stringifies its
  error and loses the typed chain) reports `connection_closed`. Neither is
  `tls_error`. kTLS still treats a bare FIN without an authenticated
  `close_notify` as truncation.
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
