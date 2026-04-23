# HTTP/3 (QUIC) Frontend & Backend

Ferrum Edge accepts HTTP/3 client traffic on a dedicated QUIC listener and proxies it to backends of any supported protocol family — HTTP/1.1, HTTP/2, HTTP/3, or gRPC. The listener is fully decoupled from the backend scheme: an HTTP/3 client can hit an `https://` backend that speaks HTTP/1.1, or a `grpc://` backend, or an H3-preferred backend, and the gateway bridges all three transparently.

## Table of Contents

- [Listener and enablement](#listener-and-enablement)
- [Dispatch model](#dispatch-model)
- [Native H3 fast path](#native-h3-fast-path)
- [Cross-protocol bridge](#cross-protocol-bridge)
- [Buffering policy](#buffering-policy)
- [Coalescing and frame cadence](#coalescing-and-frame-cadence)
- [gRPC trailers over H3](#grpc-trailers-over-h3)
- [WebSocket over HTTP/3 — not supported](#websocket-over-http3--not-supported)
- [QUIC connection migration](#quic-connection-migration)
- [Header size limits](#header-size-limits)
- [Environment variables](#environment-variables)

## Listener and enablement

HTTP/3 is a separate QUIC listener alongside the main hyper HTTP server. QUIC mandates TLS 1.3 (RFC 9001), so the server forces TLS 1.3 regardless of `FERRUM_TLS_*` settings and advertises `h3` in ALPN. Stateless session tickets are always enabled (saves 1 RTT on reconnects). Early data (0-RTT) is controlled by `FERRUM_TLS_EARLY_DATA_METHODS` — when configured, `quinn::Connection::into_0rtt()` detects early data and the gateway enforces per-method filtering.

Enable the listener with:

```bash
FERRUM_ENABLE_HTTP3=true
FERRUM_PROXY_HTTPS_PORT=8443   # H3 shares the HTTPS port by convention
FERRUM_FRONTEND_TLS_CERT_PATH=/path/to/cert.pem
FERRUM_FRONTEND_TLS_KEY_PATH=/path/to/key.pem
```

## Dispatch model

Every H3 request goes through the same plugin lifecycle as H1/H2 (route match → `on_request_received` → `authenticate` → `authorize` → `before_proxy`), runs circuit-breaker and load-balancer decisions, then branches on the matched proxy's pre-computed `DispatchKind` plus the startup-refreshed backend capability registry:

| Dispatch input | Request flavor | Backend path |
|---|---|---|
| `HttpsPool` + target classified as `h3` | `Plain` | **Native H3 pool** (quinn/h3 → QUIC upstream) |
| `HttpsPool` + target not classified as `h3` | `Plain` | Cross-protocol bridge → reqwest / direct H2 as needed |
| `HttpsPool` | `Grpc` | Cross-protocol bridge → `GrpcConnectionPool` (HTTP/2 + trailers) |
| `HttpsPool` | `WebSocket` | 501 — see [WebSocket over HTTP/3](#websocket-over-http3--not-supported) |
| `HttpPool` | any | Cross-protocol bridge → plaintext reqwest (`Plain`) / gRPC h2c (`Grpc`) / 501 (`WebSocket`) |
| `TcpRaw` / `TcpTls` / `UdpRaw` / `UdpDtls` | — | Never routed here (stream proxies route on `listen_port`) |

The `HttpFlavor` is computed once per request by `detect_http_flavor()` in `src/proxy/backend_dispatch.rs` — the same helper H1/H2 uses — so classification is identical on both fronts:

- `application/grpc*` content-type → `Grpc`
- HTTP/1.1 `Upgrade: websocket` or H2 Extended CONNECT `:protocol=websocket` → `WebSocket`
- Everything else → `Plain`

## Native H3 fast path

When the matched proxy has `backend_scheme: https`, the concrete backend target has already been classified as H3-capable, and the request flavor is `Plain`, the gateway keeps the request entirely on QUIC:

- Request body: streamed frame-by-frame via `Http3ConnectionPool::request_streaming_body()`, reading from `RequestStream::recv_data()` on the frontend and `send_data()` on the backend-side stream. No buffering.
- Response body: streamed back via `CoalescingH3Body` / `DirectH3Body` with the coalesce knobs below.
- Zero copies of the body to userspace at either end; h3's chunks are `Bytes` pass-throughs.

Use this path when the backend is known to speak QUIC. When startup or background refresh has not classified the target as H3-capable, the gateway routes via the cross-protocol bridge instead — this prevents the common failure mode of pointing H3 frontend traffic at an HTTP/2-only backend and seeing opaque QUIC connect errors on live requests.

## Cross-protocol bridge

Module: [src/http3/cross_protocol.rs](../src/http3/cross_protocol.rs).

For every dispatch case that is **not** `Plain + target classified as h3`, the H3 listener delegates to `cross_protocol::run()`, which reuses the same backend infrastructure as the H1/H2 proxy path — `state.connection_pool` (reqwest) for Plain flavor and `state.grpc_pool` (hyper H2 direct) for Grpc flavor. This is the decoupling that lets a single `https://backend` serve H1, H2, and H3 clients uniformly.

Flow:

1. **Pre-dispatch plugin phases + LB + circuit breaker** already ran in the H3 listener; the bridge receives the resolved `backend_url`, `upstream_target`, `cb_target_key`, the already-processed `proxy_headers`, the prebuffered request body (if any plugin phase collected it), plus `&mut ctx`, the pre-resolved plugin list, and the sticky-cookie flag so the bridge can run the response-side hook pipeline.
2. **`on_final_request_body`** — when the caller prebuffered the body, the bridge runs `apply_request_body_plugins` (transforms) then `run_final_request_body_hooks` (validators). A reject here short-circuits without ever calling the backend — Plain emits a JSON error, Grpc emits a trailers-only gRPC error.
3. **Request dispatch** — Plain flavor opens a reqwest request with a streaming body (see [buffering policy](#buffering-policy)) and honors `backend_read_timeout_ms`; Grpc flavor calls `proxy_grpc_request_from_bytes()` with a buffered `Bytes` and streams the response when no retry / body-buffering plugin forces buffering.
4. **`after_proxy` + sticky cookie** — once response headers arrive, the bridge runs `run_after_proxy_hooks` so response-transformer, CORS-response, compression-advertise, etc. see the cross-protocol path. A reject aborts the backend response and writes the plugin's body instead. Then `inject_sticky_cookie` adds the LB sticky-session cookie when the selection requested it.
5. **`on_response_body` + `on_final_response_body`** — run on the collected gRPC buffered body (unary RPCs) so response-transformer and body-validator can modify / validate it before it flows to the client. Streaming responses (Plain, server-streaming gRPC) skip these hooks because the full body isn't in memory — same limitation as the H1/H2 streaming path.
6. **Response write** — response headers are mapped onto `http::Response<()>` and sent via `stream.send_response()`. The body is streamed into `stream.send_data()` with the same coalescing window the native H3 writer uses (see [Coalescing](#coalescing-and-frame-cadence)).
7. **gRPC trailers** — forwarded via `stream.send_trailers()` so `grpc-status` / `grpc-message` survive the cross-protocol hop. See [gRPC trailers](#grpc-trailers-over-h3). Backend failures map to DEADLINE_EXCEEDED / RESOURCE_EXHAUSTED / UNAVAILABLE / INTERNAL based on `GrpcProxyError` variant — not collapsed to UNAVAILABLE.
8. **Outcome** — `record_backend_outcome()` updates the circuit breaker, passive health, and least-latency LB signals exactly as the H1/H2 path does.
9. **Transaction summary** — the H3 listener builds the same `TransactionSummary` shape that the native H3 path emits and calls `log_with_mirror()`, so log plugins (http_logging, statsd, prometheus, …) see a consistent record regardless of dispatch kind.

**Early-response cancellation**: in the streaming-request path, the bridge drives the H3 recv reader and `reqwest::send()` concurrently via `tokio::select!` biased toward the send future. If the backend produces a final response before the client finishes uploading (auth reject, early 413, etc.), the bridge breaks out and drops the reader — no stranded task on `recv_data()`.

## Buffering policy

Mirrors the H1/H2 proxy path's plugin-driven decision (see `ClientRequestBody::{Streaming, Buffered}` in `src/proxy/mod.rs`): stream the request body by default, buffer only when a plugin explicitly demands the body pre-`before_proxy` or when the caller pre-buffered it upstream.

**Plain flavor — request body streamed via an mpsc bridge.** `reqwest::Body::wrap_stream` requires a `'static + Send + Sync` stream, which cannot directly hold the `&mut RequestStream` borrow the H3 listener already has on the shared request stream. The bridge uses a bounded `tokio::sync::mpsc` channel:

- One task (inlined via `tokio::join!`) reads `RequestStream::recv_data()` and pushes `Bytes` chunks into the `Sender`.
- The `Receiver` is wrapped via `stream::unfold` and handed to `Body::wrap_stream`; the Receiver owns its own state and satisfies the `'static` bound.
- Channel capacity is `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` (default 32). Memory is bounded by `capacity × average_h3_chunk_size`.
- `max_request_body_size_bytes` is enforced inline — if exceeded, the reader pushes an `io::Error` onto the channel so reqwest aborts with a reset stream rather than forwarding a truncated body.
- When the receiver is dropped (backend canceled or body fully read), the next `tx.send()` errors and the reader exits cleanly; no dangling task.

If the caller pre-buffered the body (a plugin collected it during `before_proxy`), the bridge is skipped and the `Vec<u8>` is handed to reqwest directly — one allocation, no channel overhead.

**Grpc flavor — request body buffered, response streamed when safe.** `proxy_grpc_request_from_bytes()` takes `Bytes` for retry-safe framing and trailer handling, so the request body is collected up-front (unary gRPC request bodies are small and this is a cross-protocol fallback path; streaming gRPC request bodies through the bridge would require a new `GrpcBody` variant in `GrpcConnectionPool` and is tracked as future optimization). The RESPONSE is streamed whenever no retry is configured AND no plugin forces response-body buffering — server-streaming / bidi gRPC RPCs flow frame-by-frame through the bridge rather than accumulating fully in memory before the first byte reaches the H3 client. When retries or body-buffering plugins are configured, the response is buffered so the retry/plugin layer can inspect it before forwarding.

**Response body — always streamed with coalescing.** See below.

## Coalescing and frame cadence

Both the native H3 path and the cross-protocol bridge use the same response-side coalescing window:

| Env var | Default | Purpose |
|---|---|---|
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | 32,768 | Flush target — buffer reaches this size on chunk arrival, flush |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | 32,768 | Buffer `with_capacity` + clamp for `min_bytes` |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | 200 | Time-based flush when the buffer has data but isn't full |

The coalesce loop is identical across the two paths — source of bytes differs (`RequestStream::recv_data()` for native H3 vs `reqwest::Response::chunk()` or hyper `Incoming::frame()` for cross-protocol), but the output QUIC DATA frame cadence is identical. Operators running mixed workloads see the same per-stream write pattern regardless of dispatch kind.

## gRPC trailers over H3

`grpc-status` and `grpc-message` are mandatory gRPC signalling carried in HTTP trailers (RFC 9110 §6.5). The H3 crate supports trailers via `RequestStream::send_trailers(HeaderMap)` at the client-facing end. On the backend side:

- **Buffered gRPC response** — the gRPC pool extracts trailers into a `HashMap<String, String>` before returning; the bridge converts them to a `HeaderMap` and sends via `send_trailers()` after the data frames.
- **Streaming gRPC response** — the bridge polls hyper `Incoming::frame()`; when a `Frame::trailers()` variant is seen, the `HeaderMap` is stashed, the data loop exits cleanly, and the stashed trailers are forwarded via `send_trailers()`.

Either way, `grpc-status` reaches the H3 client intact.

## WebSocket over HTTP/3 — not supported

Requests that arrive on the H3 listener as RFC 9220 Extended CONNECT WebSocket handshakes (`CONNECT` with `:protocol=websocket`) receive an explicit **501 Not Implemented** with a JSON body advising the operator to send the upgrade over HTTP/1.1 or HTTP/2.

### Why

RFC 9220 does define "WebSockets over HTTP/3 via Extended CONNECT" — the client sends a `CONNECT` request with `:protocol=websocket` on a single QUIC stream, the server responds 2xx, and the bidirectional stream becomes a WebSocket data channel. But:

1. **Client adoption is effectively zero.** Chrome, Firefox, and Safari all send WebSocket upgrades over HTTP/1.1 or HTTP/2 today, not H3. The browser `WebSocket` constructor and `fetch()`-level upgrade helpers all downgrade the connection for the WebSocket handshake. Node's `ws` library and the common browser-side shims do not issue H3 Extended CONNECT for WS.
2. **Backend adoption is also effectively zero.** Nginx, HAProxy, Envoy, Traefik, and Caddy do not accept WebSocket over H3 Extended CONNECT today. So even if the H3 frontend accepted it, there would be no supported backend to bridge to.
3. **Bridging would be non-trivial.** The h3 crate exposes Extended CONNECT detection, but the backend side would need a separate pool (H3 → H2 Extended CONNECT, or H3 → HTTP/1.1 Upgrade) plus frame-level translation between the QUIC bidirectional stream and WebSocket framing. That is a dedicated subsystem for near-zero real-world traffic.
4. **Operators already have a working path.** The 501 response advises "send the upgrade over HTTP/1.1 or HTTP/2" — which is what every WebSocket client does by default anyway.

### Future

If real-world H3-WS traffic ever materializes (tracked in browser bug trackers but no ETA), adding a backend bridge is a straightforward follow-up. Until then, the 501 is an explicit operator signal rather than a silent failure.

## QUIC connection migration

The H3 connection loop detects QUIC connection migration (RFC 9000 §9) — a client that changes its local address mid-connection (common on mobile network handoffs between Wi-Fi and cellular) continues the same connection with a new 4-tuple. The loop compares `quinn::Connection::remote_address()` against a cached `SocketAddr` before each request dispatch; the comparison is two integer fields (IP + port) so the zero-allocation path is the common case. The formatted IP string (`Arc<str>`) is only re-created when the address actually changes.

This ensures IP-based rate-limit keys and access logs reflect the client's current IP after migration, not the stale IP from connection establishment. Earlier code cached the address once per connection — that was a security issue where migrated clients bypassed per-IP rate limits, now fixed.

## Header size limits

The H3 listener enforces its own per-header and total-header size limits:

| Env var | Purpose |
|---|---|
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | Max bytes per individual header value |
| `FERRUM_MAX_HEADER_SIZE_BYTES` | Max bytes across all headers combined |

These are enforced separately from hyper's built-in validation because the H3 listener parses headers via the `h3` crate, not via hyper. The `Host` value used for routing is extracted from an already-validated header, so separate host-length validation is unnecessary.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FERRUM_ENABLE_HTTP3` | `false` | Enable the QUIC listener |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | `30` | QUIC idle timeout (seconds) |
| `FERRUM_HTTP3_MAX_STREAMS` | `1000` | Max concurrent streams per QUIC connection |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | `8,388,608` | Per-stream QUIC flow-control window (8 MiB) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | `33,554,432` | Connection-level QUIC flow-control window (32 MiB) |
| `FERRUM_HTTP3_SEND_WINDOW` | `8,388,608` | Connection-level send window (8 MiB) |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | H3 backend pool connections per target |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 backend connection idle eviction |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | `32,768` | Response coalesce flush target |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | `32,768` | Response coalesce buffer capacity |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | `200` | Response coalesce time-based flush interval |
| `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` | `32` | Cross-protocol bridge mpsc capacity (range: 1–1024) |
| `FERRUM_HTTP3_INITIAL_MTU` | `1500` | Initial QUIC path MTU (quinn clamps 1200–65527) |
