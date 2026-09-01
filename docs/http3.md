# HTTP/3 (QUIC) Frontend & Backend

Ferrum Edge accepts HTTP/3 client traffic on a dedicated QUIC listener and proxies it to backends of any supported protocol family — HTTP/1.1, HTTP/2, HTTP/3, or gRPC. The listener is fully decoupled from the backend scheme: an HTTP/3 client can hit an `https://` backend that speaks HTTP/1.1, or a `grpc://` backend, or an H3-preferred backend, and the gateway bridges all three transparently.

## Table of Contents

- [Listener and enablement](#listener-and-enablement)
- [Graceful shutdown and GOAWAY](#graceful-shutdown-and-goaway)
- [Dispatch model](#dispatch-model)
- [Native H3 fast path](#native-h3-fast-path)
- [Cross-protocol bridge](#cross-protocol-bridge)
  - [Mesh transport dispatch for the H3→gRPC bridge](#mesh-transport-dispatch-for-the-h3grpc-bridge)
- [Buffering policy](#buffering-policy)
- [Coalescing and frame cadence](#coalescing-and-frame-cadence)
- [gRPC trailers over H3](#grpc-trailers-over-h3)
- [Backend trailers and response header policy](#backend-trailers-and-response-header-policy)
  - [Native gRPC terminal metadata](#native-grpc-terminal-metadata)
- [WebSocket over HTTP/3 (RFC 9220 Extended CONNECT)](#websocket-over-http3-rfc-9220-extended-connect)
- [CONNECT-UDP over HTTP/3 (RFC 9298)](#connect-udp-over-http3-rfc-9298)
- [QUIC connection migration](#quic-connection-migration)
- [Header size limits](#header-size-limits)
  - [Declared frame-length bound and SETTINGS alignment (issue #4261)](#declared-frame-length-bound-and-settings-alignment-issue-4261)
- [Flow-control window tuning](#flow-control-window-tuning)
- [Environment variables](#environment-variables)

## Listener and enablement

HTTP/3 is a separate QUIC listener alongside the main hyper HTTP server. QUIC mandates TLS 1.3 (RFC 9001), so the server forces TLS 1.3 regardless of `FERRUM_TLS_*` settings and advertises `h3` in ALPN. Session resumption is enabled by default: ordinary listeners use stateless rotating tickets, while a non-mTLS listener with early data enabled uses the bounded stateful cache required by rustls for server 0-RTT. The narrow exception is an mTLS listener with `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`: tickets and the stateful cache are disabled so a resumed session cannot bypass fresh client-certificate verification after a client-CA or CRL withdrawal. Early data (0-RTT) is controlled by `FERRUM_TLS_EARLY_DATA_METHODS` — when configured on a non-mTLS listener, the QUIC rustls config sets `max_early_data_size = u32::MAX` (the only enabled value quinn/rustls accept; a finite TLS early-data byte cap is not expressible on QUIC), `quinn::Connection::into_0rtt()` detects early data, and the gateway enforces per-method filtering. 0-RTT is **not** used when the H3 listener is configured for frontend mTLS (`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`): QUIC rustls `max_early_data_size` is set to `0`, and the 0.5-RTT accept path that precedes client authentication is refused. Ordinary 1-RTT mTLS is unaffected; a startup warning records that early data is inert on that listener.

Enable the listener with:

```bash
FERRUM_ENABLE_HTTP3=true
FERRUM_PROXY_HTTPS_PORT=8443   # H3 shares the HTTPS port by convention
FERRUM_FRONTEND_TLS_CERT_PATH=/path/to/cert.pem
FERRUM_FRONTEND_TLS_KEY_PATH=/path/to/key.pem
```

Under `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`, an mTLS H3 listener owns
its own client-trust generation (`proxy_h3`). Because the QUIC endpoint applies a
reload out of band, it adopts one whole accepted candidate — `ServerConfig`,
client-certificate verifier, and the identity of the exact client-CA bytes and
CRLs behind it — so the generation it publishes always describes what it is
enforcing. When the operator withdraws that trust, established
client-certificate-authenticated QUIC connections are closed with
`H3_REQUEST_REJECTED` (`0x010B`) and an already-ready request stream is refused
before its task is spawned. A listener with no client-CA bundle authenticates no
client and stays unarmed, so nothing is tracked and 0-RTT admission is unchanged.
See [frontend_tls.md](frontend_tls.md#client-trust-generations-and-established-transport-retirement).

In DP mode, CP-delivered Gateway TLS owns the active server certificate while
operator live reload still owns client trust. HTTP/3 adopts a single paired
candidate (CP server config + accepted operator verifier/identity) rather than
rebuilding trust from a startup CRL clone beside the CP certificate. Clearing
CP material restores that latest accepted operator candidate.

Gateway API TLS-class listener ports follow the same convention: each gets its
own QUIC socket beside its TCP HTTPS listener when HTTP/3 is enabled. If a raw
UDP or DTLS stream proxy claims that numeric UDP port in the same config, Ferrum
keeps the HTTPS TCP/H1/H2 listener and disables only QUIC/H3 for that port —
`Alt-Svc` is omitted until a live QUIC task exists again. See
[gateway_api_conformance.md](gateway_api_conformance.md) (HTTP/3 on Gateway
listener ports).

## Graceful shutdown and GOAWAY

HTTP/3 now matches H1/H2 graceful shutdown (issue #4429). The QUIC listener
still stops accepting new handshakes when the process shutdown watch fires,
but each already-accepted connection is spawned with a clone of that watch.

On drain the connection task calls the vendored
`h3::server::Connection::shutdown(0)` API, which writes an HTTP/3 GOAWAY whose
last stream ID is the last request already accepted. The peer therefore:

- learns that the gateway is going away (GOAWAY, not a silent QUIC reset)
- has new request streams refused with `H3_REQUEST_REJECTED`
- can finish already-accepted streams, including gRPC trailers, RFC 9220
  WebSocket close frames, and RFC 9298 CONNECT-UDP capsule relays

The accept loop keeps polling after GOAWAY until `accept()` returns `Ok(None)`
or `FERRUM_SHUTDOWN_DRAIN_SECONDS` expires. Only then does the listener close
remaining QUIC connections with the canonical HTTP/3 no-error code
`H3_NO_ERROR` (`0x0100`) and reason `shutdown`. The previous
`CONNECTION_CLOSE` with application code `0` is gone: that QUIC transport
close reset remaining work instead of completing GOAWAY.

Which of those two terminals a connection takes depends on the peer:

- A peer that reacts to GOAWAY — by closing, sending its own GOAWAY, or trying
  to open a stream past `max_id` — lets `accept()` return `Ok(None)` as soon as
  its in-flight streams finish. The connection task ends, quinn's
  `open_connections()` falls, and drain completes early.
- A peer that simply goes idle after GOAWAY leaves `accept()` pending. The
  vendored `h3` server gates its `Ok(None)` on having *received* a GOAWAY, not
  on having sent one, so an in-flight-free but silent connection is not
  self-terminating. It is bounded by the drain deadline rather than leaked:
  the listener logs `HTTP/3 drain timeout — forcing endpoint close` and closes
  the endpoint with `H3_NO_ERROR`. Expect planned restarts to spend the full
  `FERRUM_SHUTDOWN_DRAIN_SECONDS` when such peers are connected.

`FERRUM_SHUTDOWN_DRAIN_SECONDS` semantics are unchanged. The H3 listener still
bounds its own `endpoint.open_connections()` wait with that budget, then the
serving mode's `begin_shutdown_drain` / `wait_for_drain` waits on
`OverloadState` (`ConnectionGuard` / `RequestGuard`). Each H3 Incoming is
registered with exactly one `ConnectionGuard` in the accept-loop spawn
wrapper; handshake refuse, handshake timeout, GOAWAY completion, peer reset,
and deadline force-close all drop that guard once. H3 WebSocket sessions still
take a fresh session `ConnectionGuard` after the request guard is released,
and they observe the cloned process shutdown watch so drain can emit Close
`1001` (`Away`, `"gateway draining"`) rather than dropping the close frame.

CONNECT-UDP tunnels that were already accepted keep relaying for the H3
listener drain window. New CONNECT-UDP streams after GOAWAY are refused.
`src/http3/connect_udp.rs` is otherwise unchanged.

## Dispatch model

Every H3 request goes through the same plugin lifecycle as H1/H2 (route match → `on_request_received` → `authenticate` → `authorize` → `before_proxy`), runs circuit-breaker and load-balancer decisions, then branches on the matched proxy's pre-computed `DispatchKind` plus the startup-refreshed backend capability registry:

| Dispatch input | Request flavor | Backend path |
|---|---|---|
| `HttpsPool` + target classified as `h3` | `Plain` | **Native H3 pool** (quinn/h3 → QUIC upstream) |
| `HttpsPool` + target not classified as `h3` | `Plain` | Cross-protocol bridge → reqwest / direct H2 as needed |
| `HttpsPool` + target classified as `h3` | `Grpc` | **Native H3 pool** (`dispatch_grpc_native_h3` → QUIC upstream), FULL DUPLEX, when the body can stream (no retry / body-plugin buffering, no reqwest-forcing plugin) — the only path that reaches an **H3-only** gRPC backend |
| `HttpsPool` + target not classified as `h3` (or buffering forced) | `Grpc` | Cross-protocol bridge → `GrpcConnectionPool` (HTTP/2 + trailers) |
| `HttpsPool` | `WebSocket` | [H3 WebSocket bridge](#websocket-over-http3-rfc-9220-extended-connect) → H1.1 / H2 backend WebSocket |
| `HttpPool` | `Plain` / `Grpc` | Cross-protocol bridge → plaintext reqwest (`Plain`) / gRPC h2c (`Grpc`) |
| `HttpPool` | `WebSocket` | [H3 WebSocket bridge](#websocket-over-http3-rfc-9220-extended-connect) (`ws://` backend over plaintext H1.1) |
| `TcpRaw` / `TcpTls` / `UdpRaw` / `UdpDtls` | — | Never routed here (stream proxies route on `listen_port`) |

The original wire `HttpFlavor` is computed once per request by `detect_http_flavor()` in `src/proxy/backend_dispatch.rs` — the same helper H1/H2 uses:

- native `application/grpc` content types (excluding gRPC-Web) → `Grpc`
- HTTP/1.1 `Upgrade: websocket`, H2 Extended CONNECT `:protocol=websocket` (RFC 8441), or H3 Extended CONNECT `:protocol=websocket` (RFC 9220) → `WebSocket`
- Everything else → `Plain`

The strict gRPC-Web media-type classifier recognizes only `application/grpc-web` and `application/grpc-web-text`, with an optional `+subtype` and optional media-type parameters. The shared wire classifier deliberately leaves those requests `Plain` so the `grpc_web` plugin retains ownership of binary/text request-body translation. The H3 frontend immediately promotes a recognized gRPC-Web request to an effective `Grpc` **policy** flavor while retaining both its `Http` plugin-cache key and original gRPC-Web response content type. Its precomputed request view contains the ordinary priority-ordered HTTP chain plus only `grpc_method_router` and `grpc_deadline` from the native-gRPC chain, without duplicate instances. POST validation, request limits, and fail-closed method/deadline policy consume the effective flavor; early and later rejections use the retained content type to emit the browser-facing gRPC-Web trailer-frame representation. Backend transport is promoted to native gRPC only when the `grpc_web` plugin stamps its trusted translation marker after rewriting the request. Without that plugin, the original `Plain` transport and gRPC-Web content type pass through to the backend, preserving existing deployments while policy recognition remains fail closed. When that pass-through request has an absolute RPC deadline, both H3 frontends and H1/H2 frontends bypass the native backend-H3 pool and use the deadline-aware reqwest bridge; the deadline covers client-pool acquisition, dispatch, upload, response headers, and response-body collection so the browser can receive the canonical status-4 trailer frame. Extended CONNECT classification takes precedence, so a WebSocket request cannot be promoted by a spoofed gRPC-Web content type.

The native-gRPC composition is limited to the deadline and method-policy parity described here; it does not opt every gRPC-only plugin into gRPC-Web. Issue #2499 and advisory GHSA-m7x6-wqw2-3mvm remain the broader protocol-classification follow-up, and this deadline work does not claim or close either one.

## Native H3 fast path

When the matched proxy has `backend_scheme: https`, the concrete backend target has already been classified as H3-capable, and the request flavor is `Plain`, the gateway keeps the request entirely on QUIC:

- Request body: streamed frame-by-frame via `Http3ConnectionPool::request_streaming_body()`, reading from `RequestStream::recv_data()` on the frontend and `send_data()` on the backend-side stream. No buffering.
- Response body: streamed back via `CoalescingH3Body` / `DirectH3Body` with the coalesce knobs below.
- Zero copies of the body to userspace at either end; h3's chunks are `Bytes` pass-throughs.

The same native QUIC fast path now also serves **`Grpc`** flavor via `dispatch_grpc_native_h3()`, and it is **fully bidirectional**. The response body streams back through the shared QUIC coalescer, and the terminal `grpc-status` / `grpc-message` trailer is forwarded after response-direction hop-by-hop stripping and response-header-policy reconciliation of its application metadata (the reserved status fields always survive — see [Native gRPC terminal metadata](#native-grpc-terminal-metadata)). This is the **only** path that can reach an H3-only gRPC backend, because the gRPC pool (`GrpcConnectionPool`) speaks only HTTP/2 (h2 TLS / h2c). It is gated to the streamable case (no retry / body-plugin buffering, no reqwest-forcing plugin); unary, server-streaming, client-streaming, and bidirectional RPCs are all supported. Retry / body-buffering gRPC still falls through to the H2 gRPC bridge. Every downstream DATA/coalescer write is deadline-biased: expiry before the first client-visible DATA completes with `grpc-status: 4`, including simultaneous readiness, while expiry after any visible DATA resets because a length-prefixed message may be partial. CB / passive-health key off the HTTP transport status (gRPC failures ride on HTTP 200); the adaptive-concurrency sample maps a non-OK backend `grpc-status` to a 5xx, matching the H2 streaming gRPC bridge.

### Committed streaming responses always reset on a non-clean exit (issue #4112 / #4363)

`quinn::SendStream::drop` implicitly `finish()`es a send half that was neither
finished nor reset. Once a streaming response's HEADERS have committed, any way
the native-H3 relay can stop writing without landing its own FIN therefore hands
the client a well-formed end of response: an authorization-lifetime expiry, a
backend body fault, a downstream write failure, an early exit added later
between the header commit and the finish sites, or the request task being
dropped while parked in `send_data`. RFC 9114 has no in-band way to retract a
response whose HEADERS are already on the wire, so `RESET_STREAM` is the only
honest terminal for all of them — a stalled client must be able to tell an
authorization failure from a complete response.

The inline native-H3 streaming relay in `handle_h3_request` therefore holds its
committed send half in `stream_util::CommittedH3ResponseStream`. The predicate
is inverted relative to `stream_util::committed_response_requires_reset` (the
conditional post-relay re-assertion the cross-protocol relays apply): the
terminal is a **reset unless the relay proved a `finish()` returned `Ok` and
the stream was not already forced to reset**, so a branch that stops writing
without latching an error class is still fail closed, and `Drop` covers a task
that never reaches the post-relay settle at all. Same shape as
`ConnectUdpSendHalf` (issue #4072). The relay calls
`settle_committed_terminal()` immediately after its loop so the reset reaches
the wire before the response-termination hooks and transaction logging await;
`Drop` is only the backstop.

`abort_committed()` latches `force_reset` and applies `stop_stream` immediately.
That latch is authorization-first: a later `finish()` that returns `Ok` cannot
disarm it. Settle skips the reset only for a proven clean authorized FIN
(`clean_finish && !force_reset`); otherwise it always retries `stop_stream`.
A previous `reset_applied` flag set *before* a no-op abort skipped the Drop
retry, and `quinn::SendStream::drop` then FINned — which is how a stalled
client observed `recv_data() == Ok(None)` after the credential had already been
counted as expired (issue #4363). `h3-quinn`'s `reset` ignores Quinn errors and
does not clear a cancelled `send_data`'s `writing` buffer, so the first abort
while a write is parked can be a no-op; Drop retries after that future is gone.
`stop_stream` is idempotent, matching `ConnectUdpSendHalf`.

Native **plain** relays (`handle_h3_request`, `stream_h3_open_response_to_client`,
`proxy_to_backend_h3_streaming`) use a **biased** `select!` with the
authorization arm first, so a simultaneously-ready backend EOS cannot proceed
to `finish()`. `h3-quinn`'s `poll_finish` calls Quinn `finish()` synchronously
and does not park on a stalled client, so reaching that call after expiry would
present a clean FIN. Backend EOS (`recv_data` `Ok(None)` or a graceful-close
treated as complete) also consults the **captured** authorization Instant
before any client FIN; a spent plan aborts rather than finishing. The post-body
trailer read in `finish_h3_response_with_backend_trailers` races the same
captured plan through `await_deadline_first`, so an operator
`backend_read_timeout_ms` longer than the credential cannot outlive it. A
response that genuinely completes before expiry still FINs cleanly.

The sibling relays `stream_h3_open_response_to_client` and
`proxy_to_backend_h3_streaming` receive their send half as a `&mut` from the H3
request handler, so they cannot move it into the owning guard. They hold it in
`stream_util::BorrowedCommittedH3ResponseStream` instead (issue #4125) — the
same inverted predicate, the same `force_reset` latch, the same `Drop`
backstop, the same explicit settle after the relay loop, differing only in that
the guard borrows rather than owns. Every reset site in the committed region
goes through `abort_committed()` so a write can no longer reach the send half
around the guard and a no-op abort cannot skip Drop's retry.

In both borrowing relays the disarm is a SINGLE site, and the invariant that
makes that safe is stronger than the native relay's: inside the committed region
neither has an inline `finish()` at all. The only client-facing FIN comes from
`finish_h3_response_with_backend_trailers`, which returns `Ok(())` exactly when
its `h3_stream.finish()` produced `H3AuthorizedWrite::Written`, and that one
match arm is also the relay's only `body_completed = true`. One disarm per
relay, coinciding with one clean-completion latch, is therefore the complete
set — locked by
`committed_borrowed_h3_streaming_responses_reset_unless_a_finish_landed` and
`native_plain_h3_streaming_relays_are_authorization_first_at_backend_eos` in
`tests/unit/gateway_core/http3_server_dispatch_tests.rs`.

As with the native relay, the behaviour change beyond the drop hazard is that
the `H3TrailerFinishError::Client` and header-commit `ClientWriteFailed` exits
now RESET instead of implicitly finishing. The client's stream is already gone
in those cases, so it is not observable; it matches what `cross_protocol.rs`
already ships.

### Full-duplex native H3 gRPC (issue #3283)

The relay takes OWNERSHIP of the frontend QUIC stream and `split()`s it, and opens the backend stream already split through `Http3ConnectionPool::open_bidi_backend_stream()` / `open_bidi_backend_stream_with_target()`:

- A spawned **request-upload pump** owns the frontend receive half plus the backend send half. It forwards request DATA frame by frame, enforces the effective gRPC receive ceiling incrementally, sanitizes and forwards client trailing metadata, then FINs the backend send side. QUIC flow control is the backpressure; there is no queue between the directions, so at most one in-flight chunk is held.
- The **response relay** (the request task) owns the frontend send half plus the backend receive half and runs the deadline-biased coalescer loop.

Because the two directions progress concurrently, a server that answers before the client half-closes completes normally instead of deadlocking. Ordering and accounting properties worth keeping:

- **One deadline domain.** Opening the backend stream and waiting for response headers share a single absolute `dispatch_deadline_at` (the client `grpc-timeout`, else `backend_read_timeout_ms`) — the same total budget the drain-then-read path used. A header-wait expiry is attributed by **who the gateway was waiting on at expiry**. `classify_h3_grpc_header_wait_expiry` charges the BACKEND (504 + `ReadWriteTimeout`, so CB / passive health / adaptive concurrency / LB fallback all see it) after a clean upload FIN, when the backend itself halted the upload, or while the pump is parked on a backend write/FIN. An incomplete upload currently waiting on the client stays health-neutral even if earlier DATA was forwarded: a valid client-streaming backend may wait for request EOF, and client-controlled historical progress must not let a stalled or hostile client poison shared circuit-breaker/passive-health state. The configured deadline still terminates that request; only backend health attribution is neutralized.
- **One cancellation domain.** Every pump await races a shutdown signal, and the relay owns the pump's `JoinHandle` through an RAII guard (`H3GrpcUploadPumpGuard`), so retirement is true by construction rather than by call-site discipline. The ordinary exits — completion, `after_proxy` reject, oversized response, header-write failure, and header-wait failure — retire explicitly (publish cancellation, then *join*, so the forwarded-byte count is final before the bookkeeping reads it); `Drop` is the backstop that cancels and aborts on a structural early return, so the spawned task can never outlive the RPC and its only shutdown notifier can never be dropped while it is parked. An upload that never reached a clean FIN resets the backend request direction with `H3_REQUEST_CANCELLED`.
- **Response before teardown.** Every failure/reject arm writes the client's trailers-only gRPC response FIRST and only then retires the pump (or, pre-split, halts the still-unpolled receive half). Tearing the request direction down first lets a client observe the reset instead of the gRPC status.
- **Terminating upload faults end the RPC.** A client upload abort, undecodable trailing metadata, or an oversized upload wakes the relay immediately and terminates with `UNAVAILABLE` / `INVALID_ARGUMENT` / `RESOURCE_EXHAUSTED` respectively — mapped exactly like the pre-headers dispatch-failure path and the H2 streaming bridge. The first fault latches. The clean-status-vs-reset rule is the deadline arm's: a terminal status is appended only while no body bytes are client-visible.
- **A backend that stops reading the request is NOT a fault.** A gRPC server may legitimately STOP_SENDING / reset the request direction once it has everything it needs, so that condition is recorded but never terminates a still-streaming response, and it never decorates a completed RPC.
- **No new health signals.** Every terminating upload fault is client-caused and health-neutral (`ClientDisconnect`); a gateway-authored fault status is never latched as the backend's terminal `grpc-status`, so it cannot train the adaptive-concurrency limiter.
- **A cancelled receive half is always closed with `STOP_SENDING(H3_NO_ERROR)`.** Retiring a pump routinely cancels a frontend `recv_data` / `recv_trailers` mid-poll — that *is* the headline bidi shape, where the backend's terminal trailers arrive while the client is still uploading — and the client's request direction must then be halted gracefully. Stock `h3-quinn` 0.0.10 cannot do it: it moves its `quinn::RecvStream` into a `ReusableBoxFuture` while the read is `Pending`, leaving its own slot as `None`, so `stop_sending` unwraps that `None` and aborts the process under `panic = "abort"`. Skipping the call is not a fix either — dropping the half falls through to `quinn::RecvStream::drop`, which emits `STOP_SENDING(0)`, and `0x0` is not an HTTP/3 error code (RFC 9114 §8.1 defines `H3_NO_ERROR = 0x0100`), so clients log a spurious remote reset on an RPC that *succeeded*. Ferrum therefore carries a scoped vendored `h3-quinn` patch that keeps the stream owned inline (`vendor/h3-quinn-0.0.10-ferrum-patched`, retirement plan in `docs/upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/`), and both request-upload pumps — the native one and the cross-protocol H3→H2 pump in `dispatch_grpc_streaming` — call `halt_request_body` unconditionally. Nothing about cancellation, the request-body ceiling, or the backend reset is relaxed to achieve this.
- **Opening is pre-wire.** `open_bidi_backend_stream` writes only the request HEADERS and polls no frontend body, so a stale cached connection is always safe to replace. After it returns, nothing is replayable.

The streaming request-body pool path retries a stale cached H3 connection only when `H3PoolError::request_on_wire()` is false. At that boundary `send_request` did not open a backend stream and the borrowed frontend body has not been polled, so reconnecting to the same target is safe. Post-wire failures are never replayed: body bytes may already have reached the backend, and automatically retrying a gRPC `POST` could execute it twice. The same pre-wire reconnect covers the hyper-`Incoming` streaming variants used by the H1/H2 frontend → H3 backend path (`request_streaming_incoming_body` / `request_with_target_streaming_incoming_body`): because the `Incoming` body is moved into the request, a pre-wire failure hands the still-unpolled body back to the pool caller alongside the error, and the caller replays it once on a fresh connection under the same `request_on_wire()` gate. The full-duplex gRPC opener satisfies the same gate trivially: it is pre-wire up to and including `send_request`, so a cached-connection failure has consumed nothing.

Use this path when the backend is known to speak QUIC. When startup or background refresh has not classified the target as H3-capable, the gateway routes via the cross-protocol bridge instead — this prevents the common failure mode of pointing H3 frontend traffic at an HTTP/2-only backend and seeing opaque QUIC connect errors on live requests.

Retry-enabled requests normally keep native-H3 responses buffered so status-based retries and body plugins run before downstream commitment. A response plugin may explicitly declare that an inherently streaming response can be released after headers under retries (for example, `mcp_gateway` for `text/event-stream`). The native H3 header-first path applies the shared retry-marked content-type decision before draining the body, while retryable statuses and pre-header dispatch failures remain buffered for the retry loop.

### Stale capability recovery

A backend that was H3-capable at refresh time may later lose its QUIC listener — rollback, UDP block, infrastructure change. Without live invalidation, every request keeps taking the native H3 path and 502s until the next periodic refresh (default 24 h).

Every H3 backend failure path — H1/H2 frontend→H3 backend (`proxy_to_backend`, `proxy_to_backend_http3_retry`) and H3 frontend→H3 backend (`http3/server.rs` streaming-body / streaming-response / buffered) — classifies the error via `is_h3_transport_error_class` (ConnectionRefused / Timeout / Reset / Closed / TlsError / ProtocolError / DnsLookupError / PortExhaustion / ConnectionPoolError). The classifier looks at `error_class` only, NOT `connection_error`: `classify_h3_error` flags GOAWAY / stream reset as `connection_error=false`, but they are still H3 transport failures that warrant a downgrade. Backend response read deadlines classify as `ReadWriteTimeout` for retry/LB/accounting, but are intentionally excluded from H3 capability downgrade because a stalled response does not prove the target has lost QUIC/H3 support. The pool carries a typed `H3PoolError::is_read_timeout()` signal for these (set when `backend_read_timeout_ms` expires around `recv_response()` or the buffered `recv_data` drain), and every gateway H3 dispatch site maps it to **504** `{"error":"Backend timeout"}` with `connection_error=false` — the same client-visible outcome as the direct-H2 / HBONE / sidecar-mTLS read-timeout arms — instead of the generic 502. On a transport-class failure the registry entry is Arc-swapped so `plain_http.h3 = Unsupported` via `BackendCapabilityRegistry::mark_h3_unsupported`, with an operator-visible `last_probe_error`. Subsequent requests see `Unsupported`, skip the native H3 pool, and route via the cross-protocol bridge. The next periodic refresh re-probes; if the backend recovered, `Supported` is restored.

**Refresh must not undo a proven classification.** The periodic refresh builds a fresh record per target, so a probe that fails for reachability reasons alone would otherwise wipe a working `Supported` entry for a whole refresh interval (default 24 h). `probe_h3` / `probe_h2_tls` therefore merge against the previous record via `merge_protocol_probe_classification`: a transient class (`DnsLookupError`, `ConnectionTimeout`, `ConnectionRefused`, `PortExhaustion`) or a TLS-config build failure carries the prior verdict forward, mirroring the HBONE probe's preserve-on-non-capability-failure contract, while ALPN/protocol evidence still downgrades. A **first** probe has no verdict to protect, so it still classifies definitively — a QUIC connect timeout is indistinguishable from "no QUIC listener", and preserving `Unknown` there would leave every non-QUIC HTTPS backend permanently unclassified. A probe failure against a target previously classified `Supported` always stamps `last_probe_error`, so both a real downgrade and a preserved-but-stale record are visible in `GET /backend-capabilities`; expected "no QUIC here" outcomes stay silent so healthy backends do not report a phantom error every cycle. The plaintext h2c capability probe follows the same operator-noise rule at the tracing layer: an expected HTTP/1.1 h2c miss is debug-only (see [Backend Capability Registry](admin_api.md#backend-capability-registry)), while request-time gRPC failures, probe dial timeouts, port exhaustion, and unexpected candidate connection/handshake failures stay at WARN/ERROR.

**Refresh write-back is compare-and-commit, not a blind overwrite.** A probe spans an `await`, so a request-path downgrade (`mark_h3_unsupported`, `mark_h2_tls_unsupported`, `mark_hbone_unsupported`) can land in the middle of it. The refresh therefore takes exactly ONE pre-probe observation — `BackendCapabilityRegistry::snapshot_for_probe` — and uses it for both roles: it is the `previous` input to `merge_protocol_probe_classification` AND the compare expectation handed back to `commit_probe`. Two independent reads would leave the merge reasoning about one version while the write compared against another, which is the race itself.

`commit_probe` takes the key's `DashMap` shard entry lock (cold path only; ordinary request lookup through `get()` stays lock-light and allocation-free) and lands the write only while the entry is still the exact version the probe merged against — compared by `Arc::ptr_eq`, because every registry mutation publishes a freshly allocated `Arc` and the snapshot holds a strong reference that keeps the old allocation alive, so pointer identity cannot be recycled (no ABA). Outcomes: same `Arc` → `Committed`; replaced or inserted mid-probe → `RejectedStale`; pruned by `retain_keys` mid-probe → `RejectedEvicted`. A vacant expectation commits only while the key is still vacant, so a cold-start live insert (`mark_hbone_unsupported`, or the SNI-override arm of `mark_h2_tls_unsupported`) beats a first probe. A live-learning call that changes nothing — e.g. `mark_h3_unsupported` on an already-`Unsupported` entry — leaves the `Arc` in place and does not strand the probe, so a recovered backend can still be re-promoted to `Supported`.

Rejection is fail-closed and terminal for that cycle: the newer live record survives, the probe result is dropped rather than retried (the transport failure is strictly more recent evidence), and the next refresh re-classifies from the new baseline. Because the token is the whole record, an H3-only probe cannot clobber a concurrent HBONE or H2/TLS downgrade it never observed. Operator-facing accounting follows the commit, not the proposal: the `h2_tls` / `h3` / `h2c` / `hbone` tallies and the "supported protocol changed to unavailable" warning are computed from the record that was actually published, and discarded probes are reported separately in the refresh summary line rather than folded into the classification counts.

**Typed classifier**: `classify_h3_error` in `src/proxy/mod.rs` is a thin wrapper over `http3::client::classify_http3_error` — both walk `std::error::Error::source()` for typed `quinn::ConnectionError` / `quinn::ConnectError` / `io::Error` first, falling back to anchored substring matches on `h3::Error` Display strings only when the typed chain doesn't expose a recognizable cause. The proxy wrapper returns just `(error_kind_label, ErrorClass)`; the `connection_error: bool` is derived separately via `H3PoolError::request_on_wire()` (the pool's typed body-on-wire signal — see [Stale capability recovery](#stale-capability-recovery) above) and `retry::request_reached_wire(class)` for paths that don't go through the pool. The buffered consumer in `proxy_to_backend_http3` calls `drain_h3_response_body`, which returns `Result<Vec<u8>, h3::error::StreamError>` so the typed `StreamError` reaches the classifier directly — and graceful recoveries (`H3_NO_ERROR` / `GOAWAY` after a complete body) are caught at the `recv_data` boundary inside the drain helper itself and never produce an error in the first place.

### Graceful close handling at recv_response

`drain_h3_response_body` (above) covers the recv_data boundary: a graceful close AFTER a complete body silently produces a successful response. The complementary boundary is `recv_response` itself — quinn surfaces `CONNECTION_CLOSE(H3_NO_ERROR)` (or `GOAWAY`/`RemoteClosing`) before h3 parses the buffered HEADERS frame, so the in-flight request 502s with no headers to forward. That close is still spec-legal per [RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#name-http-3-error-codes), not a transport-level capability failure: treating it as one would mean every backend that races FIN with `CONNECTION_CLOSE` (especially on Linux + io_uring's UDP coalescing) gets H3 disabled forever.

The four `recv_response` `.map_err` sites in [src/http3/client.rs](../src/http3/client.rs) reuse the same `is_h3_graceful_close(&e)` helper that powers `drain_h3_response_body` and route the result through a dedicated `H3PoolError::graceful_close` constructor. The flag is preserved by `promote_on_wire_if`, so the pool's internal sticky-promotion chain doesn't lose the signal. The classifier wrappers — `classify_h3_error` (`http3/server.rs`) and `classify_h3_pool_error` (`proxy/mod.rs`) — short-circuit on `is_graceful_close()` and surface `ErrorClass::GracefulRemoteClose`. Because that class is intentionally absent from `is_h3_transport_error_class`, every `mark_h3_unsupported` call site (server.rs streaming-body / streaming-response / buffered, and proxy/mod.rs `current_dispatch_h3 && is_h3_transport_failure(&result)` / inner H3 dispatch branch) suppresses the downgrade automatically. The next request stays on H3.

Out of scope: the `recv_data` Err path is recovered by `drain_h3_response_body` only when the body was already complete — a close mid-body produces a truncated response, which IS a real protocol fault from the backend's perspective and stays on the transport-failure path so the registry downgrades.

**Why the recv_response 502 is unavoidable here (and how to remove it).** The 502 itself is a symptom of an h3-crate bug, not a gateway design choice. `FrameStream::try_recv` propagates a QUIC connection error before the frame decoder gets a chance to consume bytes that may already be buffered in `BufRecvStream::buf` from a previous wake — exactly the case when a coalesced UDP datagram delivers HEADERS + CONNECTION_CLOSE in the same recv batch. Tracked as `docs/upstream-h3-patches/001-recv-frame-drain-on-quic-close/` with a drafted issue, PR description, and unified diff against `h3 0.0.8`. When the upstream fix merges (or we vendor the patch ourselves per the lifecycle README in that directory), `recv_response` will return the buffered HEADERS frame instead of erroring — the 502 disappears, but the gateway-side suppression in this section is still correct on its own merits and stays.

**Retry semantics for graceful-close 502s.** `GracefulRemoteClose` is post-wire by construction: the request reached the backend (and may have been processed) before the close arrived. The synthetic 502 it produces therefore reports `connection_error=false`, which means the gateway-level retry loop respects `retryable_methods` instead of treating it as a free idempotent replay. In practice:

- **Idempotent methods (GET / HEAD / OPTIONS) with `retry_on_connect_failure: true`**: NOT retried — these requests reached the wire, so `retry_on_connect_failure` does not apply. To retry them on a graceful-close 502, add `502` to `retryable_status_codes` (and ensure GET is in `retryable_methods`).
- **Non-idempotent methods (POST / PUT / DELETE / PATCH)**: NOT retried under any default config — replaying a request the backend may have processed risks duplicate side effects. Operators who want retry-on-502 for POST must explicitly opt in via both `retryable_status_codes: [502]` AND adding the method to `retryable_methods`.
- **Pre-wire failures (DNS / TLS / connect refused)** continue to honor `retry_on_connect_failure` regardless of method, exactly as before this PR.

The same `request_reached_wire`-derived predicate drives the circuit breaker (`record_failure(connection_error=false)`) and the load-balancer outcome reporting in `record_backend_outcome`, so a graceful close does not trip `failure_threshold` counters as a transport fault and the target's least-latency EWMA receives its real backend-processing latency. The buffered-response path's pre-fix predicate (`err_class.is_some()`) over-reported every post-wire class — `ConnectionReset`, `ConnectionClosed`, `ProtocolError`, `ReadWriteTimeout` included — as a connection error; the new `h3_class_implies_connection_error` helper corrects all of them, not just `GracefulRemoteClose`.

**Per-target dispatch contract**: The retry loop in `proxy_to_backend_inner` (see [src/proxy/mod.rs](../src/proxy/mod.rs)) captures the dispatch decision per current target and threads it through every attempt:

- **Same target across attempts** → reuse the captured `current_dispatch_h3`. An H3 retry against the same backend that just failed at the H3 layer must stay on H3 — switching to reqwest mid-attempt would replay the same body to the same backend across protocols, and the failed H3 attempt may already have flushed headers / body before the reset / timeout / protocol error surfaced. That cross-protocol same-target replay would bypass `proxy.retry.retry_on_methods` and could duplicate non-idempotent requests. Same-protocol replay (H3 → H3) is fine and is the retry loop's normal job, gated by `retry_on_methods`.
- **Load-balancer rotation to a different upstream target** → recompute `current_dispatch_h3 = supports_native_http3_backend(&state, &proxy, current_target)` for the new target. The registry's per-target classification is the source of truth: mixed-capability upstreams (target A speaks H3, target B is H1-only) MUST switch transports here, otherwise the snapshot from target A's classification would force `proxy_to_backend_http3_retry` against B's H1-only backend → 502 forever. Per-target lookup is O(1) (`DashMap` + thread-local key buffer), so the recompute is cheap; `Unknown` and `Unsupported` both gracefully fall to reqwest, so an un-pre-warmed target degrades safely until the periodic refresh classifies it.

The dispatch decision is captured by the OUTER code and threaded into `proxy_to_backend` as `dispatch_h3` (rather than re-read inside it) so a concurrent `mark_h3_unsupported` / refresh between the outer capture and the inner async DNS resolve cannot split a single attempt's dispatch in half. `mark_h3_unsupported` still fires on every H3 transport failure, but its effect is scoped to the NEXT decision (next attempt's recompute, or the next request).

**The H3 frontend's buffered retry loop follows the identical contract.** `handle_h3_request` reaches that loop only when the first target was already proven H3-capable, so `current_dispatch_h3` starts locked at `true`; it is recomputed by `supports_native_http3_backend` only when LB rotation hands the loop a different `host:port`. An attempt whose rotated target is `Unknown` / `Unsupported` bridges through `proxy_to_backend_retry` (buffered reqwest, converted back by `h3_buffered_result_from_backend_response`) instead of dialing QUIC, so a mixed-capability upstream cannot burn a full `backend_connect_timeout_ms` per attempt on a target with no QUIC listener. Same-target retries keep the locked decision — no cross-protocol same-target replay. Reqwest responses carry no H3 trailers, so a bridged attempt forwards none.

**Streaming downgrade parity.** Mid-body and trailer-boundary transport faults on the *plain* native-H3 streaming relays (inline `handle_h3_request` streaming, `stream_h3_open_response_to_client`, `proxy_to_backend_h3_streaming`) call `mark_h3_unsupported` exactly like the native gRPC streaming path, so a backend that accepts headers and then RSTs every response body is downgraded once instead of failing every request until the next refresh. All of these sites keep the graceful-close exclusion explicit: `is_h3_graceful_close` (`H3_NO_ERROR` / GOAWAY) suppresses the downgrade even when the body was left incomplete, because the raw stream classifier maps a graceful teardown to `ConnectionClosed` (only the pool's `classify_h3_error` carries the typed `GracefulRemoteClose`).

For faster recovery than "one failed attempt to detect H3 broke", the right tool is connection-establishment happy-eyeballs (try QUIC with a short deadline, fall back to TCP+TLS before any request is sent) — not silent same-attempt transport switching. Tracked as a future Phase-9 candidate.

Pool-key identity must stay aligned with the capability registry for this to work correctly. Direct backend keys include `scheme|host|port|dns_override|CA|mTLS cert|mTLS key|verify`, so two proxies with different resolver pinning or mTLS material never share a classified / pooled QUIC connection. HBONE-capable targets add the sidecar HBONE port to the capability key so tunnel probes and downgrades do not bleed across targets that share the same application host/port. `Http3ConnectionPool::pool_key_for_target` takes `&Proxy` (not just host/port) for the same reason, and `create_connection_to_target` honors `proxy.dns_override` / `dns_cache_ttl_seconds`.

### Graceful close handling (`H3_NO_ERROR` / GOAWAY after the response)

Two spec-legal signals can land on the response read path **after** the body is complete and look indistinguishable from an error to a naive consumer:

- `CONNECTION_CLOSE(H3_NO_ERROR)` (RFC 9114 §5.1) — the backend sent the full response and is tearing down its end of the QUIC connection.
- `GOAWAY` (RFC 9114 §5.2) — the backend is asking clients to stop opening new streams; in-flight streams must complete normally.

When the stream FIN and the connection-level frame coalesce into the same UDP datagram (common with io_uring on Linux), `recv_data()` surfaces the close *before* h3 propagates `Ok(None)`. Without recovery this becomes a 502 plus an `is_h3_transport_error_class` capability downgrade — silently disabling H3 for the backend until the next 24 h refresh.

`drain_h3_response_body` (`src/http3/client.rs`) handles this at the `recv_data` boundary in every buffered H3 response read site (`Http3ConnectionPool::do_request`, `Http3Client::request`, the buffered branch of `proxy_to_backend_http3`). When the error matches `is_h3_graceful_close` (typed `is_h3_no_error()` for `H3_NO_ERROR`, Display string for the `non_exhaustive` `RemoteClosing` variant) AND the body is `is_response_body_complete` (Content-Length exact match, or HEAD / 204 / 304 with empty body — RFC 9110 §6.4.1, §15.3.5, §15.4.5), the loop breaks normally and returns the buffered body. Stream-level resets (`StreamError::RemoteTerminate { code: H3_NO_ERROR }`) are intentionally NOT recovered — a stream reset means the server aborted *this stream*, which doesn't tell us the response was complete.

The two H3 streaming forwarders in `http3/server.rs` (`handle_h3_request`, `proxy_to_backend_h3_streaming`) apply the same predicates inline. Both now count received bytes unconditionally — the prior gating on `state.max_response_body_size_bytes > 0` left the counter at zero when operators set `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0` to disable the limit, which broke the `received == content_length` completeness check exactly for the deployments most likely to see the race.

Tests: `h3_buffered_response_survives_graceful_close_race`, `h3_goaway_after_complete_body_is_treated_as_graceful`, `h3_stream_reset_after_partial_body_is_not_treated_as_graceful` (`tests/integration/http3_integration_tests.rs`). The scripted backend skips `stream.finish()` and emits `CloseConnectionWithCode(0x100)` / `SendGoaway(0)` / `SendStreamReset(0x100)` directly so the recovery path is deterministic on every platform — no FIN/close race to win.

## Cross-protocol bridge

Module: [src/http3/cross_protocol.rs](../src/http3/cross_protocol.rs).

For every dispatch case that is **not** served by a native H3 path — i.e. anything other than `Plain + target classified as h3` or `Grpc + target classified as h3 + streamable` (see [Native H3 fast path](#native-h3-fast-path)) — the H3 listener delegates to `cross_protocol::run()`, which reuses the same backend infrastructure as the H1/H2 proxy path — `state.connection_pool` (reqwest) for Plain flavor and `state.grpc_pool` (hyper H2 direct) for Grpc flavor. This is the decoupling that lets a single `https://backend` serve H1, H2, and H3 clients uniformly. A `Grpc` request to a backend that does **not** speak QUIC (or that needs retry / body-plugin buffering) still uses this bridge to the HTTP/2 gRPC pool.

Flow:

1. **Pre-dispatch plugin phases + LB + circuit breaker** already ran in the H3 listener; the bridge receives the resolved `backend_url`, `upstream_target`, `cb_target_key`, the already-processed `proxy_headers`, the prebuffered request body (if any plugin phase collected it), plus `&mut ctx`, the pre-resolved plugin list, and the sticky-cookie flag so the bridge can run the response-side hook pipeline.
2. **`on_final_request_body`** — when the caller prebuffered the body, the bridge runs `apply_request_body_plugins` (transforms) then `run_final_request_body_hooks` (validators). A reject here short-circuits without ever calling the backend — ordinary Plain emits a JSON error, native Grpc emits a trailers-only gRPC error, and recognized gRPC-Web emits its client-facing trailer frame in both translated and pass-through configurations.
3. **Request dispatch** — Plain flavor opens a reqwest request with a streaming body (see [buffering policy](#buffering-policy)) and honors `backend_read_timeout_ms`. Streamable Grpc flavor splits the QUIC stream and calls `proxy_grpc_request_streaming_channel()`, so the H2 backend receives DATA and request trailers incrementally while its response is relayed concurrently. Retry/body-plugin/pre-buffered Grpc requests call `proxy_grpc_request_from_bytes()` with the retained replayable representation.
4. **`after_proxy` + sticky cookie** — once response headers arrive, the bridge runs `run_after_proxy_hooks` so response-transformer, CORS-response, compression-advertise, etc. see the cross-protocol path. A reject aborts the backend response and writes the plugin's body instead. Then `inject_sticky_cookie` adds the LB sticky-session cookie when the selection requested it.
5. **Response normalization + body hooks** — buffered native-H3 and cross-protocol responses first run provider/protocol normalization, then `on_response_body`, ordinary response transforms, and `on_final_response_body`. This is the same order as H1/H2, so policy plugins inspect the client-visible representation (for example OpenAI-shaped SSE rather than provider-native Anthropic events). Streaming responses use the staged `ResponseStreamInspector` chain; protocol normalizers run before policy inspectors.
6. **Response write** — response headers are mapped onto `http::Response<()>` and sent via `stream.send_response()`. The body is streamed into `stream.send_data()` with the same coalescing window the native H3 writer uses (see [Coalescing](#coalescing-and-frame-cadence)).
7. **gRPC trailers** — forwarded via `stream.send_trailers()` for native gRPC, or embedded by the `grpc_web` plugin in the client-facing response-body trailer frame, so `grpc-status` / `grpc-message` survive the cross-protocol hop. See [gRPC trailers](#grpc-trailers-over-h3). Backend failures map to DEADLINE_EXCEEDED / RESOURCE_EXHAUSTED / UNAVAILABLE / INTERNAL based on `GrpcProxyError` variant — not collapsed to UNAVAILABLE.
8. **Outcome** — `record_backend_outcome()` updates the circuit breaker, passive health, and least-latency LB signals exactly as the H1/H2 path does.
9. **Transaction summary** — the H3 listener builds the same `TransactionSummary` shape that the native H3 path emits and calls `log_with_mirror()`, so log plugins (http_logging, statsd, prometheus, …) see a consistent record regardless of dispatch kind.

**Early-response cancellation**: both Plain header waits — prebuffered/no-body `reqwest::send()` and the streaming-request path that drives the H3 recv reader and `reqwest::send()` concurrently via `tokio::select!` — race peer cancellation of the individual request/response stream. Peer `STOP_SENDING` on the gateway response direction is observed through the vendored `h3::quic::SendStreamStopped` primitive — a `&self` + `'static` return-position `impl Future` that does not take exclusive send-stream access and does not box. Request-stream reset on a still-open upload is a `recv_data()` error; the streaming select treats that flag as client disconnect even if biased polling sees `send()` become ready in the same cycle. Cancelling one multiplexed H3 stream therefore releases destination-admission, pending, circuit-breaker probe, load-balancer, and request-lifetime accounting without closing the QUIC connection. Whole-connection close (`PeerConnectionSignal`) and the gRPC-Web absolute deadline remain additional races. Downstream cancellation is recorded as `ClientDisconnect` and is not a backend health failure. The native-gRPC H3-to-H2 path instead gives the recv half to a pump task and relays the H2 response concurrently on the send half; every bounded DATA/trailer channel send and the trailer read races a shutdown notification. For recognized gRPC-Web, the absolute RPC deadline is the first biased arm, so a withheld upload or response headers cannot retain the backend request, admission permit, or half-open probe. A backend final response before the client finishes uploading (auth reject, early 413, completed bidi response, etc.) therefore stops the appropriate reader/pump — no stranded task on `recv_data()`, `recv_trailers()`, or a full channel.

### Mesh transport dispatch for the H3→gRPC bridge

The bridge does **not** always dial `target.host:target.port` directly. Before
reading the request body or dialing, both `dispatch_grpc` (buffered/retryable)
and `dispatch_grpc_streaming` (channel-backed) resolve the LB-selected target
through `proxy::resolve_grpc_dispatch_transport` →
`grpc_proxy::GrpcDispatchTransport::for_target`, which materializes exactly one
transport and never falls back to a direct dial for a mesh-tagged target. That
resolver is SHARED with the standard HTTP/1.1+HTTP/2 native-gRPC branch (issue
#3728), so the `mesh.hbone` rows below describe both frontends and their target
validation, dial planning, and refusal behavior cannot drift:

| Selected target | Transport | Notes |
|---|---|---|
| No mesh tag | `state.grpc_pool` (direct h2c / TLS) | Unchanged behavior. |
| `mesh.mtls`, same-cluster | `state.mesh_mtls_pool` (SVID-mTLS HTTP/2) | Destination identity pinned from `mesh.spiffe_id`. |
| `mesh.mtls`, cross-cluster | same pool, east-west branch | East-west gateway dial + destination-FQDN SNI override (`mesh.eastwest_sni`) + trust-domain-scoped verification (`mesh.trust_domain`). |
| `mesh.hbone`, same-cluster | nested HTTP/2 over `state.hbone_pool`'s CONNECT byte tunnel | Materialized mesh targets pin the destination identity. An operator-supplied target that deliberately omits the optional peer tag retains HBONE's existing **any-federated** verification — the peer SVID must chain to *some* trust domain present in this gateway's own bundle, but is NOT narrowed to one, so it is strictly weaker than the trust-domain-scoped verification the two cross-cluster rows describe; a present but invalid tag fails closed. The peer's HBONE relay byte-copies the tunnel to the app socket, so the inner connection is ordinary h2c. |
| `mesh.hbone`, cross-cluster | same, over the cross-cluster dial | Remote east-west gateway (`mesh.hbone_dial_host` / `mesh.hbone_port`), SNI override, trust-domain scope; the CONNECT authority is the real remote pod from `mesh.hbone_authority_host`. |

Both mesh transports are HTTP/2 end to end, so gRPC framing, `grpc-status` /
`grpc-message` trailers, flow control, `grpc-timeout` deadline propagation, and
client cancellation behave exactly as they do on the direct gRPC pool. The
shared `GrpcBody` is handed through unchanged, so the channel-backed streaming
path still commits request DATA incrementally and a peer can answer before the
H3 client half-closes (true bidirectional streaming).

HBONE sender acquisition, including the inner HTTP/2 handshake after CONNECT,
is bounded by the destination policy port's effective backend connect timeout.
The successful CONNECT only proves the destination's relay reached the app
socket, and the nested connection is cleartext (no ALPN), so the sender is
admitted only once the app's **own** HTTP/2 connection preface — a complete,
structurally valid initial SETTINGS frame — has been observed. This is the same
admission the direct-dial h2c gRPC pool applies, and it gives the two failure
shapes their honest classifications: an app that answers the nested preface with
something other than HTTP/2 is a distinct h2c-handshake failure (not an outer
TLS/mesh failure), and a relayed app that accepts TCP but never sends settings
cannot retain the RPC indefinitely when the client supplied no `grpc-timeout` —
it is refused by that connect budget. The outer HBONE hop is SVID-authenticated,
while the nested application connection is h2c and carries `:scheme: http`; the
gateway does not misrepresent the tunnel's outer TLS as end-to-end TLS to the
application.

Everything undispatchable **fails closed** with a Trailers-Only gRPC
`UNAVAILABLE`, before any dial:

- a cross-cluster target with no mesh transport tag;
- a cross-cluster `mesh.mtls` target missing its SNI override or trust domain;
- a corrupted target declaring **both** `mesh.mtls` and `mesh.hbone` (the
  topologies are mutually exclusive, so picking either hop would be a guess);
- any target whose pinned `mesh.spiffe_id`, HBONE dial host, or CONNECT
  authority host tag is present but unusable.

Refusal messages name the failed contract and never echo the target's SPIFFE
ID, SNI, trust domain, or dial address.

Retry rotation re-resolves the transport **per attempt**: rotating onto a
mesh-tagged target re-dials over that target's own dial plan (never the previous
target's session), and rotating onto an undispatchable one fails closed. The
half-open circuit-breaker probe slot a refusal consumes is released.

The H3→HTTP plain bridge and the H3 WebSocket bridge share the same HBONE /
Sidecar mesh-mTLS egress pools the H1/H2 paths use (issue #3620). Mesh-tagged
targets are forced off the native QUIC pool onto those bridges; Unix-socket
targets remain refused because H3 has no Unix dialer. Mixed-upstream retry
rotation skips H3-ineligible candidates (Unix) and fails closed when no
eligible secured or plain transport remains — there is never a plaintext
fallback for a mesh-tagged target.

The mesh egress pools return an already-buffered response rather than a live
backend body, but that response re-enters the **same** client-facing plain
pipeline as an ordinary bridged response: `after_proxy`, body normalization,
`on_response_body`, the representation transform gate, `on_final_response_body`,
`response_committed`, sticky-cookie provenance, exact `Content-Length` framing,
and one backend/admission outcome record. Response inspection and security
policy never depend on whether the selected target happened to be mesh-tagged.
Because the mesh dispatch is buffered-mode, a streaming response body is
structurally impossible there; if one appears the bridge fails closed with a
`502` instead of publishing an uninspected or fabricated body under the
backend's status.

## Buffering policy

Mirrors the H1/H2 proxy path's plugin-driven decision (see `ClientRequestBody::{Streaming, Buffered}` in `src/proxy/mod.rs`): stream the request body by default, buffer only when a plugin explicitly demands the body pre-`before_proxy` or when the caller pre-buffered it upstream.

Every buffered upload drain — including bodies required before `authenticate`, `authorize`, or `before_proxy` — is bounded by the earliest of the proxy's `backend_read_timeout_ms` whole-upload operator bound and any configured client RPC absolute deadline (`grpc-timeout`); `0` explicitly disables the operator timeout while a present RPC deadline still caps the drain. The drain future owns the accumulating buffer, so timeout, deadline, disconnect, or size-limit cancellation drops partial upload bytes instead of retaining them across rejection work. On cancel, the gateway writes the protocol-appropriate rejection (Plain `408` / gRPC trailers-only `DEADLINE_EXCEEDED`) first. Already-selected post-cancel terminal writes are not re-raced against the expired absolute deadline (that would cancel on the first `Pending` poll before HEADERS are visible); instead they use the shared fixed post-deadline grace (`H3_POST_DEADLINE_TERMINAL_WRITE_GRACE`, 1s) so a ready peer can observe the rejection while a flow-control-blocked client cannot retain the request task indefinitely. After that bounded write settles, the full-stream path emits canonical `STOP_SENDING(H3_NO_ERROR)` even when the drain was cancelled mid-`recv_data`; the vendored h3-quinn transport keeps the receive stream reachable in that state. Grace expiry first aborts/resets the response send half and then halts the request direction, so neither half can retain the task. Split-stream paths leave the halt to their receive-owning upload pump. When an absolute RPC deadline expires during any buffered upload phase, the result follows the ordinary finalized rejection lifecycle before that bounded write: immediately-ready rejection decorators and committed observers see the canonical result, gRPC-Web translation preserves their synchronous headers (including CORS), and rejection logging plus permit/probe accounting complete. A hook still pending at expiry continues with later eligible cleanup hooks on owned state under a detached bound and cannot retain the terminal write. Plain HTTP operator timeouts return `408`, while gRPC request timeouts complete with trailers-only `DEADLINE_EXCEEDED`, matching the H1/H2 paths.

**Plain flavor — request body streamed via an mpsc bridge.** `reqwest::Body::wrap_stream` requires a `'static + Send + Sync` stream, which cannot directly hold the `&mut RequestStream` borrow the H3 listener already has on the shared request stream. The bridge uses a bounded `tokio::sync::mpsc` channel:

- One task (inlined via `tokio::join!`) reads `RequestStream::recv_data()` and pushes `Bytes` chunks into the `Sender`.
- The `Receiver` is wrapped via `stream::unfold` and handed to `Body::wrap_stream`; the Receiver owns its own state and satisfies the `'static` bound.
- Channel capacity is `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` (default 32). Memory is bounded by `capacity × average_h3_chunk_size`.
- `max_request_body_size_bytes` is enforced inline — if exceeded, the reader pushes an `io::Error` onto the channel so reqwest aborts with a reset stream rather than forwarding a truncated body.
- When the receiver is dropped (backend canceled or body fully read), the next `tx.send()` errors and the reader exits cleanly; no dangling task.

If the caller pre-buffered the body (a plugin collected it during `before_proxy`), the bridge is skipped and the `Vec<u8>` is handed to reqwest directly — one allocation, no channel overhead.

**Grpc flavor — duplex request/response streaming when safe.** When no retry is configured, no request or response body plugin requires buffering, and the request was not already pre-buffered, the bridge splits the QUIC stream. A pump reads each H3 DATA frame and the terminal request-trailer block into a bounded channel; `GrpcBody::Channel` exposes those frames directly to hyper's H2 sender. Channel capacity is `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY`, so a slow backend stops the H3 reader and QUIC flow control backpressures the client without accumulating the whole RPC. Request DATA remains in gRPC's original length-prefixed representation, application request trailers are preserved, and hop-by-hop or client-forged gateway-assertion trailers are removed before the H2 boundary.

This streaming representation is deliberately non-replayable. The server selects it only after the selected target's effective retry policy and plugin requirements are known; it contains no retry loop, and a failure after the outbound request is handed to hyper is classified post-wire. Retry/body-plugin/pre-buffered cases retain the complete body (and any separately represented trailers) and use `proxy_grpc_request_from_bytes()`, preserving replay safety and existing plugin behavior. Configuration reload/update/delete swaps the same precomputed proxy/plugin-cache snapshots used to make this decision; an in-flight stream keeps its starting snapshot, while the next request observes the new buffering/retry policy. No new public configuration or OpenAPI surface is introduced.

The request pump and response relay run concurrently, so client-streaming and H3-to-H2 bidirectional RPCs can receive backend DATA before downstream EOF. The bounded sends race bridge shutdown: a backend early response/error, client reset, deadline, completed response, or parent-task cancellation marks the H2 body failed before notifying the pump to halt the H3 receive half. Publishing cancellation before the wakeup prevents DATA already queued by the pump from crossing the backend boundary after shutdown. The backend therefore receives a reset rather than a truncated clean END_STREAM, and no detached pump remains blocked on H3 DATA, trailers, or channel capacity. `max_grpc_recv_size_bytes` and any narrower route body ceiling are counted incrementally on DATA only; an overflow errors the H2 body (RST rather than a truncated clean END_STREAM) and is reported as `RESOURCE_EXHAUSTED`, neutral to backend health.

The relay consumes the request-scoped absolute gRPC deadline across pool acquisition, upload, response headers, response DATA/trailers, downstream H3 flow control, and FIN. Expiry before client-visible response DATA can complete with status-4 trailers; expiry after partial response DATA resets because a length-prefixed message may be incomplete. Without a client deadline, the operator read timeout remains the fallback. A zero-DATA terminal status gets one immediate write opportunity; if flow control would block, the gateway resets the response and drops/cancels the upstream body. Backend `Content-Length` is removed before committing a deadline-capable streaming response.

**Response body — streamed with coalescing when policy permits.** See below. Retry/body-plugin cases retain their existing bounded buffered response behavior.

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

- **Streaming request trailers** — after H3 request DATA reaches EOF, the H3-to-H2 pump reads the optional request trailer block and emits it as `Frame::trailers` through `GrpcBody::Channel` before clean H2 END_STREAM. The native H3 relay uses the same sanitizer, and since issue #4148 so do the HTTP/1.1 and HTTP/2 request paths — see [Backend Request Trailers](plugin_execution_order.md#backend-request-trailers). Hop-by-hop names, reserved gateway assertions, credentials, forwarding identity, the initial-section-only `Via` intermediary chain, and the gateway-owned `Early-Data` marker are removed; malformed trailer blocks fail the upload closed rather than being converted into a clean truncated request. Application metadata such as request checksums remains eligible for forwarding.

- **Buffered gRPC response** — the gRPC pool extracts trailers into a `HashMap<String, String>` before returning; the bridge converts them to a `HeaderMap` and sends via `send_trailers()` after the data frames.
- **Streaming gRPC response** — the bridge polls hyper `Incoming::frame()`; when a `Frame::trailers()` variant is seen, the `HeaderMap` is stashed, the data loop exits cleanly, and the stashed trailers are forwarded via `send_trailers()` — after response-direction hop-by-hop stripping and response-header-policy reconciliation of the section's application metadata. `grpc-status`, `grpc-message`, and `grpc-status-details-bin` are reserved and always survive that reconciliation; see [Native gRPC terminal metadata](#native-grpc-terminal-metadata).

Buffered response hooks receive a compatibility view containing both initial
headers and trailers. Before the H3 response is written, Ferrum restores the
original provenance, reapplies the prefiltered `security_headers` policy to the
initial header map, and keeps `grpc-status`, `grpc-message`, status details, and
application metadata on the trailer channel whenever the backend supplied a
real trailers frame, including split responses with an empty DATA body. A final
security-policy removal is authoritative across both compatibility copies: it
also suppresses trailer-only or header-shadowed application metadata, and runs
after any hook-mutated trailer cookie is rehomed. A final policy set/override
remains initial-header policy and preserves the backend's application trailer.
A backend Trailers-Only response that already carries terminal status in its
END_STREAM initial HEADERS and has no trailers frame keeps that status there;
Ferrum snapshots the reserved terminal fields from the pristine backend
headers before response hooks run, then restores that authoritative snapshot,
so policy replay cannot remove or replace it. This is also the path used after
gRPC-Web binary or text response framing, so security policy cannot disappear
with the native trailer map.

When an absolute deadline instead replaces an uncommitted buffered response,
the H3 native and cross-protocol paths use the same gateway-header provenance
boundary as H1/H2. The pristine backend view is captured before response hooks;
only non-terminal-owned output from completed gateway hooks (including
configurable correlation fields, exact-value `update` writes and fired `rename`
destinations a hook declares it owns, and a gateway hook's own `Set-Cookie`),
plus exact `Vary: Origin`, can cross into the terminal response. The
sticky-affinity `Set-Cookie` that proxy core injects on buffered H3 and
cross-protocol responses is recorded as gateway output before committed hooks
run, so a committed-hook deadline cannot strip it and break client stickiness.
That injection APPENDS, so it records its mutation without claiming ownership:
ownership means a whole-value replacement and retires the backend cookie
baseline, which here would credit a co-present backend cookie as gateway output.
The occurrence partition credits the affinity line even when it is byte-identical
to a backend cookie.
Because ownership is declared rather than inferred from a value diff, a backend
cannot suppress an owned gateway write by pre-populating the identical
key/value. If a completed decorator chain is followed by a later hook that
itself exhausts the deadline, the terminal rejection keeps the gateway output
already recorded rather than restarting from the deadline error headers. Cache
state, discarded-representation metadata, transport framing, and prior gRPC
terminal fields are removed even when a gateway hook wrote them.
Backend-supplied safe-looking trace/CORS names, arbitrary metadata, cookies,
credentials, and discarded-representation fields do not become trusted by
name — every backend-supplied `Set-Cookie` occurrence is dropped, and only the
surplus a trusted phase added crosses. H3 gateway-error paths that reach a
committed hook directly, without the shared rejection decorator pipeline,
establish the same boundary, so their gateway-authored headers survive a
committed-hook deadline instead of being stripped for lack of provenance.
Native gRPC and binary/text gRPC-Web framing are regenerated after this
sanitation, then deterministic initial-response policy is reapplied.

After route resolution, HTTP/3 method-filter errors and native-gRPC gateway
errors (including request deadlines, size limits, backend unavailability, and
mesh fail-closed responses) also apply the route's precomputed initial-response
policy before the initial HEADERS write. gRPC status/message, content type, and
transport framing are restored after policy. Errors rejected before a route is
resolved have no plugin configuration and therefore remain outside this policy
boundary.

Either way, `grpc-status` reaches the H3 client intact.

When the representation gate decodes a buffered response from `gzip`/`br` to
identity, that decode counts as a body rewrite even if no configured rule later
changes the document. Native H3 drops trailers for the discarded encoded
representation. On the buffered gRPC bridge, application trailers and their
merged header-view copies are retired while reserved gRPC completion metadata
stays terminal. If the gate instead synthesizes an `INTERNAL` rejection, that
new status/message is snapshotted as authoritative before split finalization;
the stale backend terminal status cannot return and the synthesized status is
not duplicated between initial and terminal metadata.

## Backend trailers and response header policy

Plain (non-gRPC) native-H3 responses forward the backend's trailers after the
DATA frames (issue #1630) — on the buffered send path and on the streaming
relays alike. Every response-header phase on those paths — `after_proxy`,
sticky-cookie injection, committed hooks — sees only the **initial** header map,
so a backend trailer repeating a governed field name would arrive after the
policy boundary and undo it. Before the trailers are written, Ferrum reconciles
them against the response-header policy actually in force for the request:

- **Declared policy names.** Plugins classify their reach with
  `Plugin::response_trailer_policy()`, and the plugin cache unions the names and
  any declared ASCII prefixes once per reload so the request path reads
  precomputed lists instead of scanning the chain. Exact names are the only
  signal that can bind the two mutation shapes the per-request witness below
  cannot see: a **removal that was a no-op on the initial map** (the backend
  sent the field only as a trailer), and an **idempotent write** (the gateway
  wrote a value the backend already sent verbatim). Prefixes close open-ended
  sanitizer families a finite write list cannot enumerate (CORS
  `access-control-`). Built-in coverage:

  | Plugin | Declared names |
  | --- | --- |
  | `security_headers` | every configured `set` / `remove` name |
  | `sse` | `content-type` (when relabeling), `cache-control`, `x-accel-buffering` (when enabled), `content-length` (when `strip_content_length`) |
  | `compression` | `content-encoding`, `content-length`, `vary` |
  | `grpc_web` | the two internal bridge headers, `content-type`, `x-grpc-web`, `vary`, `access-control-expose-headers` |
  | `cors` (and its cache-internal finalizer) | open-ended `access-control-` prefix (mirrors `remove_access_control_headers`) plus `vary` |
  | `correlation_id` | the configured header name, when `echo_downstream` |
  | `otel_tracing`, `workload_metrics` | `traceparent` |
  | `response_caching` | `x-cache-status`, when `add_cache_status_header` |
  | `ai_semantic_cache` | `x-ai-cache-status` |
  | `rate_limiting`, `ai_rate_limiter` | the exposed `x-*ratelimit-*` fields, when `expose_headers` |

  Plugins that only observe, log, authenticate, or authorize declare nothing.
- **Observed mutation.** Independently, the path witnesses the backend's
  pre-policy value for each field name the trailer section carries and drops any
  trailer whose header counterpart the chain added, changed, or removed. This
  covers plugins that declare nothing at all, including custom plugins and
  transforms published at request time. It also covers the gateway's own core
  response-header writes — sticky-session cookie injection, and the default
  `content-type: application/json` a relay synthesizes when the backend sent
  none.
- **Fail-closed arm.** A plugin whose governed field set is not enumerable at
  config time declares `ResponseTrailerPolicy::Unbounded` and the whole trailer
  section is dropped. One built-in is in this class:

  | Plugin | Why the set is not enumerable |
  | --- | --- |
  | `response_transformer` | `after_proxy` also applies `mesh_route_dispatch` route overrides whose field names do not exist until the request runs |

  `ai_stream_router` does not need this arm: Anthropic SSE normalization
  declares the shared finite representation-metadata inventory plus the
  `x-amz-checksum-*` / `x-checksum-*` prefixes through
  `NamesAndPrefixes`, so unrelated application trailers remain intact.

**On a plain response no field name is exempt, `grpc-*` included.** Reserved-field
handling is selected *structurally* by the dispatch the gateway already
committed to (`TrailerSectionKind`), never from the trailer's own name. On a
plain-flavor path — the buffered native-H3 send path, the plain native/refined
H3 streaming relays, and the plain [direct-H2 streaming
relay](#direct-http2-streaming) — a `grpc-status` trailer is an ordinary
backend-supplied field, and exempting it by name would let any non-gRPC backend
bypass an observed or fail-closed response-header policy with a single
well-chosen trailer name.

**On a native gRPC terminal section, exactly three fields are reserved.**
`grpc-status`, `grpc-message`, and `grpc-status-details-bin` carry the RPC
outcome and survive governance unconditionally, so a generic header rule can
never corrupt or suppress valid terminal status. That is an exact three-name
inventory, not a `grpc-` prefix: `grpc-encoding`, `grpc-accept-encoding`, and
every other field in the section are gRPC **application metadata** and are
governed exactly like a plain trailer field, fail-closed `Unbounded` arm
included. See [Native gRPC terminal metadata](#native-grpc-terminal-metadata).

An auth/logging-only chain — `key_auth`, `stdout_logging`, ACLs, or a rate
limiter with response-header exposure disabled — declares no names and mutates
no response headers, so its backend trailers are forwarded untouched (issue
#2941). Chain **presence** is deliberately not the gate: that would strip valid
trailers from every proxy that merely authenticates.
A response-body plugin phase that actually processes the response body still
clears the trailers wholesale, because those hooks cannot inspect or transform a
trailer at all.

### Streaming relays

The plain native/refined H3 streaming relays cross the same boundary later: the
initial HEADERS frame is on the wire before the backend's trailer section even
exists. They therefore reconcile at the trailer frame, inside the shared
trailer-finish helper and immediately before `send_trailers`, using the same
three signals. Three details differ from the buffered path:

- **Evidence shape.** The set of trailer field names is unknown when the headers
  go out, so a streaming relay retains the backend's **pre-policy header map**
  for the response and derives the per-trailer witness once the trailers arrive.
  That is one snapshot per streaming *response* — never per body frame — and it
  is skipped entirely when no response-header phase can run for the request (no
  plugins, no sticky-cookie injection, and the backend already supplied a
  `content-type`), or when the chain already fails closed under
  `ResponseTrailerPolicy::Unbounded`.
- **Wire parity of the final header map.** Each relay writes its synthesized
  default `content-type` into the response-header map before building the
  response, not onto the response builder alone, so the map the reconciliation
  treats as "the final headers" is exactly the field set the client received. A
  builder-only default would let a backend `content-type` trailer reconcile as
  absent-to-absent and land on the wire contradicting a header the gateway
  itself sent. Synthesizing that field also counts as a response-header phase
  for the evidence decision above, so the parity holds even for an
  auth/logging-only chain. The special native-gRPC content-type path is
  untouched: `dispatch_grpc_native_h3` never synthesizes a default
  `content-type`, because gRPC carries its own.
- **Ambiguous duplicates fail closed.** A plugin may synthesize several case
  variants of one field name (`x-name` beside `X-Name`) in the string header
  map. A field counts as untouched only when the pre-policy and final maps each
  hold exactly zero matches, or exactly one match with the same value; duplicate
  case variants on either side are ambiguous and the trailer is dropped. The
  buffered path applies the identical rule.

Everything else is unchanged: the trailer read timeout and its error
classification, connection/accounting release, H3 capability downgrade on
trailer-boundary transport faults, and client-disconnect semantics all behave
exactly as before. Native gRPC over H3 inlines its own trailer finish and
reconciles there instead, as a gRPC terminal section — see
[Native gRPC terminal metadata](#native-grpc-terminal-metadata).

Both the buffered and streaming paths strip response-direction hop-by-hop
trailer names **before** reconciling. Either order drops the same fields from
the wire, but reconciling first would count a hop-by-hop name as a
policy-governed removal and inflate the `removed` telemetry.

### Direct HTTP/2 streaming

The plain direct-H2 streaming relay (`ResponseBody::StreamingH2`) crosses the
identical boundary and applies the identical governance signals — see
[docs/response_body_streaming.md → Backend trailers on the direct-HTTP/2
streaming path](response_body_streaming.md#backend-trailers-on-the-direct-http2-streaming-path).
Its only structural difference is ownership: the body is handed to hyper and the
handler returns, so the boundary travels with the body as an owned
`StreamingResponseTrailerGovernor` instead of borrowing the handler's locals.
That owned form also carries an allocation-free per-response
`gateway_owned_headers` bitset for the end-to-end builder writes (`via`,
`alt-svc`, `X-Gateway-*`) so an exact-value pre-seed cannot bypass them. Native
gRPC (the mesh-mTLS relay) on that arm is governed as a gRPC terminal section,
and so is translated gRPC-Web — see
[Translated gRPC-Web terminal frames](#translated-grpc-web-terminal-frames).

### Native HTTP/3 backend streaming (H1/H2 frontend)

`ResponseBody::StreamingH3` — an HTTP/1.1 or HTTP/2 client in front of an
H3-capable backend — commits its initial header block before the backend's
TRAILERS frame is read, exactly like the direct-H2 relay, and forwards that
trailer section to the client as HTTP/1.1 chunked trailers or an H2 TRAILERS
frame. It carries the same owned `StreamingResponseTrailerGovernor`, built from
the same capture, and `body::H3FrameSource` applies it to the TRAILERS frame
immediately after the hop-by-hop trailer strip. All three body constructors
(`direct_streaming_h3_body`, `size_limited_streaming_h3_body`,
`coalescing_h3_body`) install it.

This relay has **two** routes out of the trailer phase and the governor binds
both. The ordinary route is the TRAILERS frame `poll_recv_trailers` yields once
the terminal stream FIN arrives. The second is the delayed-FIN route: h3 can
have the TRAILERS frame fully received while still withholding it pending that
FIN, so `H3FrameSource` peeks the buffered map (`peek_recv_trailers`, a vendored
h3 patch) and stores it in `H3ReadProgress.pending_trailers`; if the outer
`IdleReadTimeoutBody` trailer-phase deadline then fires, that wrapper forwards
the stored map as the response's trailer section instead of collapsing to a bare
EOS. The wrapper carries no governor of its own, so the peek path strips
hop-by-hop names and reconciles **before** storing — the slot only ever holds a
map that is safe to put on the wire. Once a peek returns a trailer map, that map
is stored and governed at most once per response, so a long trailer wait neither
re-clones it nor double-counts the removal telemetry; the two routes are
distinguished in the debug line by a static `route` field (`fin` /
`timeout_peek`). gRPC-flavored native-H3 dispatch is owned by
`dispatch_grpc_native_h3`, so this relay is a plain-response section in
practice; the section is still chosen structurally from the dispatch, never from
a trailer's own name.

### Native gRPC terminal metadata

Advisory GHSA-r78v-rc86-6r86: a streaming gRPC response runs `after_proxy` on
the **initial** header map only, commits its HEADERS frame, and forwards the
backend's terminal metadata later. A `response_transformer` rule that removes or
redacts `x-internal-debug` is therefore a no-op when the backend sends that field
only as a trailer — the operator's trust boundary is crossed by streaming alone,
since forcing the same response to buffer applies the rule correctly.

Every native streaming gRPC relay now applies the same three governance signals
to its terminal metadata, at the trailer frame and before the trailers reach the
client:

| Relay | Where it reconciles |
| --- | --- |
| Direct HTTP/2 gRPC pool (`GrpcResponseKind::Streaming`) | owned `StreamingResponseTrailerGovernor` inside `proxy::body::StripHopByHopTrailers`, installed on all three body constructors |
| Mesh-mTLS `StreamingH2` relay | the same owned governor on the plain streaming-H2 arm |
| H3 client → H2 gRPC backend bridge | inline in `handle_h3_grpc_streaming_response`, before `send_trailers` |
| Native H3 gRPC backend (`dispatch_grpc_native_h3`) | inline, before `send_h3_grpc_trailers_and_finish_before_deadline` |

Reserved-field behavior is uniform across all four: `grpc-status`,
`grpc-message`, and `grpc-status-details-bin` are never dropped or rewritten, so
status classification, deadline handling, backend-health accounting, and
gRPC-Web translation are unaffected — each relay latches the backend
`grpc-status` from the pristine trailer block *before* reconciling. Everything
else in the section is application metadata: it is dropped when a plugin
declared its name (or prefix), when the per-request witness proves the chain
mutated the matching header, or — for an `Unbounded` chain such as
`response_transformer`, whose governed names do not exist until the request runs
— unconditionally. The response plugin chain is **not** re-run at trailer time:
`after_proxy` has side effects and `response_transformer` consumes
request-scoped route overrides, so each relay carries a precomputed,
request-scoped boundary to the trailer frame instead.

An auth/logging-only chain still forwards gRPC application trailers untouched,
exactly as before (issue #2941).

### Translated gRPC-Web terminal frames

A translated gRPC-Web response adapts the backend's terminal metadata into a
final DATA frame instead of a TRAILERS frame. That changes the **encoding**, not
the boundary, and the two cases must not be conflated:

- **Genuine Trailers-Only.** The backend put its terminal metadata in the
  initial END_STREAM HEADERS block. `after_proxy` and the pristine Trailers-Only
  snapshot already governed exactly that block, so the adapted frame inherits
  their result and needs nothing further.
- **A non-empty streaming response.** The terminal metadata arrives in a later
  TRAILERS frame, long after the header boundary closed — the same crossing
  GHSA-r78v-rc86-6r86 reports. Reconciliation therefore runs on that trailer
  block **before** any of it is collected and encoded, on the same
  request-scoped boundary the native trailer-forwarding branch uses, as a
  `NativeGrpcTerminal` section (so `grpc-status`, `grpc-message`, and
  `grpc-status-details-bin` survive and still drive the frame's status).

| Relay | Where it reconciles |
| --- | --- |
| Direct HTTP/2 gRPC pool + gRPC-Web | owned governor inside `StripHopByHopTrailers`, which `proxy::body::GrpcWebStreamingBody` wraps from the outside — the trailer frame is already reconciled when the adapter encodes it |
| Mesh-mTLS `StreamingH2` + gRPC-Web | the same owned governor on the plain streaming-H2 arm, likewise inside the gRPC-Web adapter |
| H3 client → H2 gRPC backend, translated | inline in `handle_h3_grpc_streaming_response`, before `collect_buffered_grpc_trailers` / `build_streaming_trailer_data` |

`dispatch_grpc_native_h3` performs no gRPC-Web conversion and cannot receive a
translated request: translation forces request-body buffering, which clears
`can_stream_request_body` and so clears the `use_native_h3_grpc` gate. Its
forwarded trailer section is governed by the native rules above regardless.

Each relay latches the pristine backend `grpc-status` before reconciling, so
backend health, admission, deadline, and observability classification are
decided by what the backend sent. Binary and text modes share one governed
frame — text mode base64-encodes the same reconciled bytes — and clean EOF,
Trailers-Only, disconnect, and deadline terminal frames are unchanged.

## WebSocket over HTTP/3 (RFC 9220 Extended CONNECT)

The H3 listener accepts WebSocket Extended CONNECT requests per
[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) (the HTTP/3 mirror of
RFC 8441's HTTP/2 mechanism). A client sends `CONNECT` with
`:protocol = "websocket"` on a fresh bidirectional QUIC stream; the
gateway authenticates, authorizes, runs the `before_proxy` plugin chain,
opens a backend WebSocket connection, replies `:status = 200`, and then
bridges WebSocket frames between the QUIC stream and the backend
WebSocket for the lifetime of the session.

The `security_headers` initial-response policy runs on the RFC 9220 `200`
handshake and on gateway-generated H3 WebSocket failures. Transport-managed
fields are stripped at the final emission boundary after response hooks; JSON
failures default `Content-Type: application/json` there when no intentional
content type survives. The backend-negotiated `Sec-WebSocket-Protocol` is then
restored on success. H3 never emits the HTTP/1.1-only `Upgrade`, `Connection`,
or `Sec-WebSocket-Accept` fields.

### Wire-level handshake

```
H3 client                              Gateway                      Backend
──────────                             ───────                      ───────
:method = CONNECT
:scheme = https            ─────►
:authority = example.com               authenticate + authorize
:path = /chat                          plugin pipeline
:protocol = websocket                  → WsBackendHandshake Direct/Mesh
sec-websocket-protocol = chat                            Upgrade: websocket  ─────►
                                                         Sec-WebSocket-Key: ...
                                                                              ◄──── 101
                           ◄────       :status = 200
DATA = ws frame bytes      ────►       ws framer / plugin hooks  ────► ws frame
DATA = ws frame bytes      ◄────       ws framer                 ◄──── ws frame
...
```

### Backend strategy

The gateway does NOT speak WebSocket over H3 to the backend. Common
WebSocket backends (Node `ws`, browsers acting as servers, Nginx,
HAProxy, Envoy when configured as a forward proxy) still bootstrap
WebSockets over HTTP/1.1 Upgrade or HTTP/2 Extended CONNECT — RFC 9220
adoption on the server side is still emerging. The H3 frontend therefore
bridges through the same `WsBackendHandshake` Direct/Mesh enum the H1/H2
frontends dispatch: plaintext targets use `connect_websocket_backend()`,
and `mesh.hbone` / `mesh.mtls` targets use `connect_mesh_websocket_backend()`.
From the backend's perspective, a WebSocket arriving via H3 is
indistinguishable from one arriving via any other frontend.

### Frame relay and plugins

The split QUIC stream halves are bridged to a tokio `DuplexStream` by a
pair of pump tasks (see `src/http3/websocket.rs`). The duplex half on
the WebSocket-framer side is wrapped in
`tokio_tungstenite::WebSocketStream` and handed to the generic
`run_websocket_proxy` function — the same function the H1/H2 path uses.
Per established H3 WebSocket session the bridge reserves a 64 KiB
duplex buffer plus a 16 KiB send-pump scratch buffer; protocol frame
size remains governed separately by
`FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES`.
This means every WebSocket plugin works on H3 sessions unchanged:

- parser-level actual-frame/message limits (`ws_message_size_limiting`) and
  `on_ws_frame` inspection/transformation after continuation reassembly
  (`ws_rate_limiting`), plus delivery-accurate frame observation
  (`ws_frame_logging` via post-send `prepare_ws_frame_delivery` /
  `emit_ws_frame_delivery`, including peer Close)
- physical-fragment metering (`on_ws_reassembly_frames`) and the parser's
  incomplete-message frame/duration bounds
  (`FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_FRAMES` /
  `FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_SECONDS`), installed on both framers
  by the shared relay. H3 client frames are unmasked per RFC 9220 §5; the
  bridge validates that rule before bytes reach the framer, so fragment
  accounting sees exactly the same frame sequence on H1, H2, and H3
- `on_ws_disconnect` (end-of-session bookkeeping with success-only frame/byte
  counts, direction, and `io_side` attribution)
- `prometheus_metrics` WebSocket session count/duration and directional
  byte/frame totals (the shared disconnect hook gives H1 Upgrade, H2 Extended
  CONNECT, and H3 Extended CONNECT identical completion accounting)
- Connection-admission via `FERRUM_WEBSOCKET_MAX_CONNECTIONS` and `FERRUM_WEBSOCKET_MAX_CONNECTIONS_PER_IP` (shared with H1/H2)
- All authentication, authorization, and `before_proxy` plugins (run BEFORE the bridge accepts the upgrade)
- Sticky-session cookies on the 200 response (same as H1/H2)
- All logging plugins (the `TransactionSummary` emitted at upgrade time carries `http_method = "CONNECT"`, mirroring the H2 Extended CONNECT path)

### Frame masking — RFC 9220 §5 vs RFC 6455

RFC 6455 / RFC 8441 require client-to-server WebSocket frames to be
masked. RFC 9220 §5 REVERSES this: WebSocket frames over HTTP/3 MUST
be unmasked because QUIC already provides packet-level authentication.
The gateway's H3 path:

- **Emits unmasked frames to the client** — `tokio_tungstenite`'s
  `Role::Server` doesn't mask outgoing frames, so this is correct
  on default settings.
- **Accepts unmasked frames from the client** —
  `accept_unmasked_frames = true` is set on the H3 path's
  WebSocketConfig (it's `false` on the H1/H2 path).
- **Rejects masked client frames** — the H3 receive pump pre-validates
  WebSocket frame headers before bytes reach tungstenite's permissive
  `accept_unmasked_frames` mode. A non-compliant H3 client that sends a
  masked frame receives a WebSocket close frame with code `1002`
  (protocol error), and the frame is not bridged to the backend.

### Tunnel mode

`FERRUM_WEBSOCKET_TUNNEL_MODE` (raw bidirectional TCP copy) does NOT
apply to H3 sessions. The H3 frontend has no raw TCP underneath QUIC to
splice; bytes always pass through the pump tasks. Operators who set
tunnel mode for H1/H2 throughput automatically get frame-parsing
semantics on H3 — frame-level plugins continue to work regardless.
The generic `run_websocket_proxy` carries a `debug_assert!` enforcing
this invariant (`websocket_tunnel_mode` and `accept_unmasked_client_frames`
are mutually exclusive) so a future refactor that wires a non-TCP
transport into the raw-copy fast path fails loudly in debug builds.

### Circuit breaker, load balancer, graceful drain

H3 WebSocket sessions participate in the same backend-isolation +
session-accounting infrastructure the H1/H2 path uses:

- **Circuit breaker** — backend connect failure records
  `record_failure(502, is_pre_wire, is_half_open_probe)` against
  the resolved target, where `is_pre_wire` follows the unified
  `retry::request_reached_wire` boundary (a backend that received the
  upgrade and rejected it post-wire does NOT charge the breaker's
  connect-error counter). Successful 200 upgrades record
  `record_success(is_half_open_probe)` so a half-open probe that
  bootstraps a WebSocket counts as a recovery sample.
- **Load balancer** — `LoadBalancerConnectionGuard` increments the
  final selected target's connection count on construction (just before
  the 200 is sent) and decrements on drop, so a long-lived H3 WebSocket
  session correctly weights least-connection load balancing.
- **Graceful drain** — a fresh `ConnectionGuard` is captured for the
  session lifetime; `SIGTERM` drain waits for in-flight H3 WebSocket
  sessions before exit, honoring `FERRUM_SHUTDOWN_DRAIN_SECONDS`.
- **Retry / target rotation** — pre-wire backend setup failures honor
  `retry_on_connect_failure` and rotate upstream targets using the same
  load-balancer snapshot as H1/H2 WebSockets. Backend-side upgrade
  rejections are post-wire and are not replayed.

### Pump task teardown

The recv pump (QUIC → WS framer) is `abort()`ed after
`run_websocket_proxy` returns, before joining. The send pump (WS framer
→ QUIC) is awaited normally — it exits on EOF when the framer drops
its sink half, and the await ensures `finish()` runs so the peer sees
a clean FIN. Aborting the recv pump prevents a non-cooperative client
(one that exchanges close frames without closing the QUIC stream) from
pinning the recv task for the QUIC idle-timeout window.

### 0-RTT (TLS 1.3 early data)

RFC 9220 Extended CONNECT can in principle be carried in QUIC 0-RTT
early data, but `FERRUM_TLS_EARLY_DATA_METHODS` does NOT list `CONNECT`
by default — operators who want WebSocket upgrades via 0-RTT must opt
in explicitly. **CONNECT-UDP is never admitted in early data**, even
when that allowlist includes `CONNECT`: UDP has no `Early-Data: 1`
header boundary for a target to make its own replay-safety decision, so
the handler rejects every 0-RTT `connect-udp` stream with `425 Too Early`
before routing, plugins, or any socket work. When early data is enabled for
HTTP/3 without frontend mTLS, the
QUIC TLS layer advertises `max_early_data_size = u32::MAX` because quinn/rustls
reject every other non-zero value; Ferrum's method allowlist is the
application-layer admission control (there is no finite QUIC TLS byte cap). On
accepted 0-RTT requests the gateway forwards `Early-Data: 1` to the backend
(same shim as plain H3 / cross-protocol bridge) so origins can apply their own
replay-safety policy.

Peer identity and early data are published as one per-connection snapshot
(`http3::peer_identity::H3ConnectionIdentity`, an `ArcSwap` slot read once
per accepted request stream). The slot starts with `is_early_data = true`
and **no** client certificate, and is republished exactly once — when the
handshake-completion future resolves successfully and after the accept loop
has snapshotted every already-ready request stream — with whatever peer
certificate quinn can then report and `is_early_data = false`. Accept polling
is biased ahead of handshake publication so a buffered early-data request
cannot be reclassified as 1-RTT merely because both events become ready in the
same scheduler turn. An early-data request therefore can never gain an mTLS
identity, and a handshake that fails, times out, or is cancelled leaves the
slot empty and early-data-gated. Because slots are per connection, no other
connection's identity can be observed through them.

On a listener with a frontend client-certificate verifier the QUIC TLS
early-data size is `0` and the 0.5-RTT accept path is refused entirely, so
`peer_identity()` is only ever read after the handshake completes and
`mtls_auth` / `spiffe_identity` see the presented certificate exactly as they
do without early data configured.

### Disabling H3 WebSocket

Set `FERRUM_HTTP3_WEBSOCKET_ENABLED=false` to disable the bridge. With
this off the H3 server does NOT advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`,
so compliant H3 clients won't attempt Extended CONNECT. As defense in
depth, the bridge itself also returns 501 if a client somehow sends
Extended CONNECT anyway. Plain H3, gRPC over H3, and the native H3
backend pool keep working — only the WebSocket bridge is gated.

### Testing

Unit tests in `tests/unit/gateway_core/http3_websocket_tests.rs` cover:

- `detect_http_flavor` classifies H3 Extended CONNECT with
  `:protocol=websocket` as `HttpFlavor::WebSocket`.
- Other `:protocol` values (`webtransport`, `connect-udp`) are NOT
  classified as WebSocket.
- The vendored h3 patch (`docs/upstream-h3-patches/002-extended-connect-websocket-protocol/`)
  exposes `h3::ext::Protocol::WEB_SOCKET` so the wire-level pseudo-header
  decoder accepts `:protocol=websocket` instead of rejecting the entire
  HEADERS frame as malformed.
- Env-config parsing of `FERRUM_HTTP3_WEBSOCKET_ENABLED` (defaults to
  true, parses `true` / `false` correctly).

End-to-end functional coverage lives in
`tests/functional/functional_websocket_test.rs`. The tree ships a small
h3-quinn-based RFC 9220 client because common off-the-shelf clients
(curl 8.x, h2load, tungstenite) still focus on WebSocket over HTTP/1.1
/ HTTP/2. The functional shard covers H3 text/binary frame relay,
masked-frame permissiveness, subprotocol forwarding and the no-subprotocol
case, backend retry target rotation, failed backend upgrade responses,
per-IP request-slot release after the 200 CONNECT response, and
`FERRUM_HTTP3_WEBSOCKET_ENABLED=false` rejecting Extended CONNECT while
plain H3 requests continue to route.

## CONNECT-UDP over HTTP/3 (RFC 9298)

Implementation: `src/http3/connect_udp.rs`. Off by default; enable with
`FERRUM_HTTP3_CONNECT_UDP_ENABLED=true`.

**Warning — process-wide enablement.** Setting
`FERRUM_HTTP3_CONNECT_UDP_ENABLED=true` admits RFC 9298 Extended CONNECT on
**every** HTTP/3 HTTP route whose routing and `allowed_methods` policy already
allow `CONNECT`. There is no per-route CONNECT-UDP schema. An ordinary route
with no method filter can match a suffix such as `/udp/host/port/` (the RFC
9298 template expansion, including under `/.well-known/masque/`). Deploy a
**dedicated MASQUE route** (distinct `hosts` and/or `listen_path`), require
authentication and authorization on that route, and set explicit
`allowed_methods` on every other H3 route that must not expose CONNECT.

### Interoperability profile

This is the complete profile. Anything outside it is refused; there is no
private Ferrum framing.

| Aspect | Behavior |
| --- | --- |
| Bootstrap | RFC 9298 §3 over HTTP/3: `:method=CONNECT`, `:protocol=connect-udp`, `:scheme=https`, `:authority` = gateway authority |
| URI Template | RFC 9298 §2. The default `https://$HOST:$PORT/.well-known/masque/udp/{target_host}/{target_port}/` works verbatim. Any operator prefix is accepted as long as the expanded path ends with `udp/{target_host}/{target_port}/`, trailing slash included. The `udp` segment is a case-sensitive URI path literal (`UDP` / `Udp` are refused) |
| 0-RTT | CONNECT-UDP in TLS 1.3 early data is **always** `425 Too Early`, even when `CONNECT` is listed in `FERRUM_TLS_EARLY_DATA_METHODS`. UDP has no `Early-Data: 1` header for a target to make its own replay-safety decision. Ordinary 1-RTT CONNECT-UDP is unchanged; operator-enabled H3 WebSocket 0-RTT is unchanged |
| Success response | `200` with `Capsule-Protocol: ?1` (RFC 9297 §3.4), written after response-header policy so no plugin can remove or forge it. `Content-Length` and `Content-Type` are force-removed at the same boundary (RFC 9297 §3.2 forbids them; the hop-by-hop strip already removes `Transfer-Encoding`) |
| Payload encoding | HTTP Datagrams as RFC 9297 **DATAGRAM capsules** (`Capsule Type = 0x00`) on the CONNECT stream |
| `SETTINGS_H3_DATAGRAM` | Never negotiated. QUIC DATAGRAM frames are not used in either direction |
| Datagram payload | RFC 9298 §5: Context ID varint + unmodified UDP payload. Only Context ID `0` is registered |
| Unknown context IDs | Well-formed but unregistered contexts are dropped (RFC 9298 §4), never proxied |
| Unknown capsule types | Silently dropped and skipped (RFC 9297 §3.1) at **any** declared length, including lengths above the UDP payload ceiling. The skip is streaming: the value is never buffered or allocated, the declared length is counted down as a `u64` so no `usize` conversion can overflow, and the capsule that follows decodes exactly. The configured ceiling applies only to DATAGRAM capsules, whose values the gateway materializes |

RFC 9297 §3.5 states that HTTP Datagrams sent in a DATAGRAM capsule "have the
same semantics as those sent in QUIC DATAGRAM frames", and a compliant RFC 9298
client that has not received `SETTINGS_H3_DATAGRAM = 1` uses exactly this
encoding. The capsule profile is therefore an interoperable encoding of the
same HTTP Datagrams, not an alternative wire format.

### Routing, policy, and destination admission

A CONNECT-UDP request is an ordinary Ferrum request up to the point of
dispatch. Routing (`hosts` + `listen_path`), authentication, authorization,
overload admission, per-IP limits, rate limiting, `before_proxy` plugins,
`TransactionSummary` access logging, and the request/status metrics all run
first and unchanged. The tunnel is dispatched at the same point in
`handle_h3_request` as the RFC 9220 WebSocket bridge.

RFC 9298 lets the *client* name the destination, so the destination is
**admitted, not load balanced**: the requested `target_host:target_port` must
already be configured for the matched proxy — its `backend_host:backend_port`,
or one of the referenced upstream's targets. Anything else is refused with 403
before a socket exists, so a CONNECT-UDP route can never reach further than the
ordinary HTTP route on the same proxy. Operators express the allow-list simply
by pointing the proxy's upstream at the destinations they intend to expose.

"Not load balanced" is structural, not incidental: the HTTP/3 handler runs no
upstream selection at all for a CONNECT-UDP request
(`UpstreamSelection::unselected()`), so no member the client did not name can
authorize, refuse, or describe the tunnel. Concretely, an unrelated member's
health, circuit-breaker state, or transport tags never decide a requested
destination, no round-robin / least-connections cursor is advanced for a
request that dials no HTTP backend, and no load-balancer connection is charged.
The circuit breaker is not consulted at all — a tunnel is not a probe outcome,
and an HTTP backend's failure history is not evidence about a UDP destination
(the handler still releases any probe slot it is handed, as defence in depth).

Admission is bound to the exact requested member, which is what makes the
transport screening sound: the matched target must be one a **direct UDP dial**
may reach. A destination tagged for HBONE, sidecar mTLS, cross-cluster
east-west, or Unix-socket dispatch is refused, even when another member of the
same upstream is directly dialable, and even when the same `host:port` also
appears untagged — the whole matching set is screened, so a duplicate cannot
launder a transport-constrained sibling. Both refusal kinds return the same 403
and the same body, so the response discloses neither the configured destination
set nor which of its members are directly dialable. The backend egress policy
is likewise evaluated against the requested host and this route's effective
`dns_override`, not against a selected backend.

The live generation re-check re-runs this same admission, transport screening
included, so a reload that newly requires another transport for the destination
withdraws the tunnel instead of letting it outlive the policy.

Target resolution goes through the dial-time, policy-screened resolver, so the
same backend IP policy that guards ordinary backend dialling guards the tunnel;
a mixed DNS answer containing a denied address fails the whole lookup. The
effective per-proxy `dns_override` is honoured with the same highest precedence
ordinary dispatch gives it, so a route that pins its destination address does
not dial a different one through the tunnel — and a denied override still fails
the lookup instead of becoming an unscreened dial.

### Bounds and lifecycle

| Bound | Source |
| --- | --- |
| Concurrent tunnels | `FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS` (503 over the limit) |
| Idle lifetime | `FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS`, which also raises the frontend QUIC idle floor (below) |
| Datagram payload | `FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES`, itself capped at the RFC 9298 §5 ceiling of 65527 |
| DATAGRAM capsule length | payload ceiling + 8 bytes of Context ID slack |
| Unknown capsule length | unbounded on the wire; zero bytes retained (streaming skip) |
| Buffered partial capsule | the decoder's documented hard ceiling, twice one maximum capsule plus header |
| Authorization lifetime | for an **authenticated** tunnel, the earlier of the admitted credential's own expiry and `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` (below) |

#### Authorization lifetime of an authenticated tunnel

A CONNECT-UDP tunnel opened by an **authenticated** principal is bounded by the
shared, protocol-neutral authorization lifetime that governs every other
admitted stream (see `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` in
[configuration.md](configuration.md)). Without it, the tunnel's own idle timer
would be refreshed by every relayed datagram, so a client holding a short-TTL
JWT or an mTLS certificate near `notAfter` could keep a privileged UDP tunnel
for the lifetime of the QUIC connection rather than for the lifetime of the
authorization that admitted it.

The effective deadline is the **earlier** of the accepted credential's own
authoritative expiry and the configured maximum, and it is anchored once, at
the request-receipt instant, before the tunnel exists:

- **Before commitment.** The deadline is derived once, as a single captured
  `StreamAuthDeadline`, before the session permit, the DNS lookup, the UDP
  socket, and the `200`. An already-elapsed deadline is a fixed, redacted
  authorization refusal — the same terminal every other protocol emits
  pre-commitment — and no session permit is consumed, no address is resolved,
  and no UDP socket is created or connected.
- **Pre-commitment waits.** DNS resolution and the tunnel-socket connect are
  raced with that same captured plan through `ComposedAuthBound`.
  Authorization wins a tie; a strictly earlier protocol bound (the existing
  connect-budget DNS timeout) keeps its existing 504 behaviour. The last
  instant before a `200` is offered re-checks the captured plan, so a
  credential that expired during that work still cannot commit a tunnel.
- **HEADERS write.** The H3 response-header write is bounded by
  `await_authorized_headers_write` against the same plan. A successful `200`
  is counted only after that write actually succeeds. If authorization expires
  while the write is parked in QUIC flow control or QPACK, the termination is
  recorded once, the stream is aborted/reset, and the socket, session permit,
  and guards are released — no second blocking terminal write is attempted.
- **After commitment.** The relay supervisor arms one exact
  `sleep_until(deadline)`, biased ahead of its other arms so an expiry that
  races the idle tick, a route withdrawal, a drain, or a relay halt is the
  outcome that is reported. Relayed datagrams in either direction can neither
  refresh nor recompute it.
- **Terminal shape.** The tunnel ends by **resetting** the capsule stream
  (`H3_INTERNAL_ERROR`), never by a clean FIN: a client must be able to tell an
  authorization termination from a tunnel that ran to completion.
- **Teardown.** A client that stops reading parks the client-bound relay in QUIC
  send flow control. That write is raced with the supervisor close command so
  `stop_stream` can land. If it still never returns, the existing bounded close
  grace aborts and joins both relay tasks so the socket, session permit, and
  connection guard are released on time. Quinn would implicitly `finish()` a
  send stream dropped without `finish()`/`reset()`, so the send half RESETS on
  drop unless a close was already applied — the abort must not present a clean
  FIN. That designed abort stays classified as the authorization expiry only
  when the send half was cancelled after the grace timeout; a panic or any
  unrelated cancellation is reported as an internal relay failure.
- **Accounting.** Exactly one termination is recorded, through the request's
  shared once-only latch, on the fixed-cardinality `authorization_lifetime`
  counters under the existing closed `stream_udp` protocol family. No route,
  target, or credential label is created, and no new family is published. The
  established-tunnel `TransactionSummary` is emitted once, after the `200`
  HEADERS write succeeds; a pre-commitment refusal logs through the ordinary
  rejection path instead, never both.

An **unauthenticated** tunnel admitted no principal, so it has no authorization
lifetime: no timer is registered for it and every bound above applies exactly as
before.

#### The tunnel idle timeout and the QUIC connection idle timeout

A CONNECT-UDP tunnel is a stream of one QUIC connection, and a tunnel carrying
no datagram generates no QUIC activity either — so a connection idle limit
below the tunnel's idle limit closes the tunnel first, and the configured
tunnel bound is never reached. With the shipped defaults that gap was real:
`FERRUM_HTTP3_IDLE_TIMEOUT` is 30 seconds while
`FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS` is the 120 seconds RFC 9298
§3.2 asks for.

When the profile is enabled, the HTTP/3 **frontend**'s QUIC `max_idle_timeout`
is therefore raised to at least the configured tunnel idle timeout. The
derivation only ever raises:

- a larger `FERRUM_HTTP3_IDLE_TIMEOUT` still wins and is never shortened;
- `FERRUM_HTTP3_IDLE_TIMEOUT=0` keeps its "the idle timer is disabled" meaning
  (RFC 9000 §10.1) and is left alone — raising it would *shorten* the
  connection;
- with the profile disabled nothing is derived at all;
- H3 **backend** connection pools keep the configured value verbatim; they
  carry no tunnels.

The raise is logged at listener construction (`configured_idle_timeout_seconds`
→ `effective_idle_timeout_seconds`) rather than applied silently, so an
operator who deliberately set a shorter QUIC idle timeout can see that enabling
CONNECT-UDP extended it and can lower
`FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS` if that is what they meant.

There is no *queue* between the directions. The client-bound relay awaits
`send_data` (QUIC stream flow control is the backpressure) and the target-bound
relay awaits `UdpSocket::send`; excess is dropped by the kernel socket buffer,
which is the correct behaviour for a UDP tunnel.

That is not the same as one buffer per session. Writing `P` for the configured
payload ceiling, a live tunnel can concurrently hold the decoder's transient
buffer (bounded at `2 × (P + 8 + 16)` — the ceiling above, not one capsule),
the `P + 1`-byte target receive buffer, and the client-bound framing scratch
plus a framed capsule still owned by a `send_data` future that QUIC send flow
control has blocked (about `2 × (P + 9)`). The conservative per-session bound is
therefore about `5 × P` — roughly 320 KiB at the 65527-byte default, or roughly
80 MiB across the 256-session default. Lower
`FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES` to scale every term down.

Each tunnel uses one *connected* UDP socket (RFC 9298 §3.1), so the kernel
enforces the 5-tuple and off-path packets never enter the session. The socket is
built through `socket2` so the platform do-not-fragment / path-MTU-discovery
option is installed **before** it is handed to Tokio and before any datagram can
leave it — `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` = `PMTUDISC_DO` on
Linux/Android, `IP_DONTFRAG` / `IPV6_DONTFRAG` on Apple.

RFC 9298 §3.1 states that the proxy **MUST NOT** introduce IP fragmentation and
that IPv4 DF **MUST** be set if possible. That is not a best-effort
requirement, so there is **no fragmenting fallback**:

- On a target that exposes the option, a `setsockopt` failure **refuses the
  tunnel** (502) rather than opening one without the guarantee.
- On a target that exposes none (Windows, where Ferrum links no Winsock
  binding; other BSDs, which this repository neither builds nor tests), the
  whole profile is **unavailable**, not degraded.
  `FERRUM_HTTP3_CONNECT_UDP_ENABLED=true` is a startup validation error there,
  `SETTINGS_ENABLE_CONNECT_PROTOCOL` is not advertised on account of
  CONNECT-UDP, and a `connect-udp` request is refused `501` — the same answer
  as a disabled profile, because the profile genuinely is not offered.

A datagram from the target larger than the configured ceiling is silently
dropped rather than fragmented or truncated. Socket errors are classified in
**both** directions from one shared judgement, because on a *connected* UDP
socket the kernel reports an ICMP error for an earlier datagram on whichever
syscall runs next — `send` or `recv`:

- `EMSGSIZE` (the expected result of the DF policy for an over-path datagram)
  and genuinely transient local conditions (`EINTR`, `ENOBUFS`, send-side
  `WouldBlock`) drop that datagram and keep the tunnel. ICMP Fragmentation
  Needed / Packet Too Big is the one Destination Unreachable code that maps
  here: RFC 9298 §3.1 independently requires dropping the oversized datagram
  rather than fragmenting.
- ICMP-derived destination-unreachable, refused, reset, unreachable, down, and
  protocol-unreachable conditions (`ECONNREFUSED`, `ECONNRESET` /
  Windows `WSAECONNRESET`, `EHOSTUNREACH`, `ENETUNREACH`, `ENETDOWN`,
  `EHOSTDOWN`, Linux `ENOPROTOOPT`) mean the OS has reported the connected
  socket unusable. RFC 9298 §3.1 requires closing the request stream; they are
  not ordinary per-datagram loss.
- A `recv` reporting "not ready" sends the relay back to awaiting readability
  rather than retrying the syscall; Tokio resolves readiness internally so this
  is defensive, and a bounded run of consecutive not-ready rounds ends the
  tunnel instead of spinning.
- Anything else indicating the socket itself is unusable tears the request
  stream down with `H3_INTERNAL_ERROR` rather than presenting a live tunnel
  that silently discards traffic.

A tunnel ends — sockets closed, both relay tasks **joined**, and only then the
session permit and connection guard released — on any of: client FIN or stream
error, target socket error, idle expiry, capsule protocol fault, gateway drain
(`SIGTERM`), or **route withdrawal**. Teardown aborts each relay and then joins
its handle within a bounded grace, so an aborted task can never still own the
QUIC stream half or the UDP socket while the gateway advertises the slot as
free.

How the stream is closed depends on why:

- An ordinary end of tunnel FINs the capsule stream.
- A capsule protocol fault — a malformed capsule, a capsule over the ceiling, or
  a client FIN **in the middle of a capsule** — is a malformed HTTP message per
  RFC 9297 §3.3/§3.5 and RFC 9114 §4.1.2, so the receive half is halted with
  `STOP_SENDING(H3_MESSAGE_ERROR)` and the send half is reset with
  `H3_MESSAGE_ERROR`. It is never a clean EOF.
- A tunnel the gateway can no longer honour resets with `H3_INTERNAL_ERROR`.
  That covers the tunnel socket failing in **either** direction: a terminal
  client-to-target `send` fault and a terminal target-to-client `recv` failure
  are the same condition, and neither may present a clean FIN. The relay task
  that owns the QUIC send half classifies its own terminal outcomes through the
  single `SessionEnd::close_kind` mapping, because the supervisor cannot change
  a send half after that task has already returned. The close command carries
  the supervisor `SessionEnd`; if the send-half task consumes it, that is the
  outcome it applies and returns. If the task reaches its own halt first, teardown
  keeps the joined self-decided outcome rather than a stale supervisor verdict.
- A relay task that fails to **join** — it panicked, or it was cancelled by
  something other than this session's own teardown — is likewise an internal
  failure (`SessionEnd::RelayTaskFailed`), never a client FIN. The supervisor
  reaches that classification only for a handle it has not aborted, so it
  cannot mistake its own requested cancellation for a fault. A panic, or a
  `CLOSE_GRACE` abort of the send-half task whose `finish()`/`reset` did not
  complete, downgrades the reported outcome to the same internal failure,
  because the client then sees a reset rather than the close the supervisor
  decided. The request additionally returns an error to the H3 request loop so
  the failure is visible instead of indistinguishable from a clean close.

Route withdrawal is checked against the currently published config generation,
not the one the request was admitted under: a reload that deletes the proxy or
removes the destination from its upstream tears live tunnels down within one
supervisor tick rather than grandfathering them. When the request was admitted
against a **plugin route override** (`mesh_route_dispatch` and friends), the
live lookup by `(namespace, id)` recovers only the unoverridden base route, so
the exact effective authorization cannot be reconstructed — a generation change
then closes the tunnel outright instead of re-admitting it against a route it
was never admitted against.

The same re-check also compares the route's **effective `dns_override`** against
the one the session was admitted with. A tunnel owns one *connected* UDP socket,
fixed at establishment to the address admission resolved, so "the requested
`host:port` is still configured" does not mean the tunnel still points where the
live route says: an override that changed — in either direction, including
`Some` → `None` and `None` → `Some` — leaves the socket pinned to the address
the route has stopped naming. There is no re-pin; the session ends. The
comparison is exact and resolves nothing, so it performs no lookup and neither
logs nor returns any target material, and a merely re-spelled override fails
closed. This is deliberately not general policy reauthentication.

### Refusals

| Condition | Status |
| --- | --- |
| Profile disabled, or unavailable because this build target cannot enforce RFC 9298 §3.1 non-fragmentation | `501` (the latter is additionally a startup validation error) |
| Unregistered `:protocol` token | h3 resets the stream with `H3_MESSAGE_ERROR` before the gateway sees it |
| Registered but unimplemented `:protocol` (e.g. `webtransport`), or CONNECT with no `:protocol` | `405` |
| `:scheme` absent, empty, or not the listener's HTTPS scheme; `:authority` absent | `400` with a field-specific body — a tunnel is never established on an assumed scheme |
| `Content-Length`, `Content-Type`, or `Transfer-Encoding` present (RFC 9297 §3.2), on the client request **or** on the plugin/policy-finalized outbound headers | `400`, before a socket exists |
| Path is not an RFC 9298 template expansion, or `target_host` / `target_port` is empty, oversized, or malformed | `400` with a field-specific body |
| Destination not configured for the matched proxy; configured but requiring a non-direct transport (HBONE, sidecar mTLS, cross-cluster, Unix socket); or denied by the backend egress policy | `403` — one status and one body for all three, so the configured set and its dialability are never echoed |
| Session limit reached | `503` |
| DNS failure / policy refusal | `502` with `Proxy-Status: ferrum-edge; error=dns_error` |
| DNS timeout | `504` |
| Socket bind/connect failure | `502` |

### Testing

- `tests/unit/gateway_core/http3_connect_udp_tests.rs` — URI-template parsing
  and hostile-input rejection, the RFC 9298 §3 pseudo-header shape, the RFC 9297
  §3.2 forbidden-field boundary in both directions, destination admission,
  capsule decoding (context IDs, oversize, truncation, split frames, and a FIN
  mid-capsule), the RFC 9297 §3.1 unknown-capsule skip (one ten times the UDP
  ceiling, one split at every byte boundary, and one declaring the maximum QUIC
  varint — each proving zero retained bytes and exact resumption at the next
  capsule, while the DATAGRAM ceiling still refuses an over-size Context ID 0
  capsule), capsule encoding, `:protocol` classification, the UDP send-error
  **and** receive-error classifiers (including that ICMP destination-unreachable
  is terminal in both directions while `EMSGSIZE` remains a one-datagram drop
  and `WouldBlock` on recv awaits readability), the do-not-fragment socket
  option installing on a real UDP socket and failing closed where it does not
  exist, the session-end → stream-close classification (which outcomes may FIN
  and which must reset, over the closed set of session ends), the relay-join
  classification (a cancelled task — induced without any panic — is an internal
  failure, and a completed relay keeps its own verdict), and the live re-check's
  effective-`dns_override` address-pin comparison.
- `tests/unit/gateway_core/dns_tests.rs` — the fresh all-candidates dial path
  honouring a per-proxy `dns_override` and still screening a denied one.
- `tests/unit/config/cp_grpc_conn_limit_tests.rs` — the CONNECT-UDP session cap
  at and above the semaphore ceiling, the frontend QUIC idle-timeout floor
  (raised to the tunnel bound, never lowering a larger operator value, never
  disturbing the `0`-disables semantic, and never touching the backend pools'
  value), and the startup refusal on a target that cannot enforce RFC 9298 §3.1.
- `tests/functional/functional_http3_connect_udp_test.rs` — live H3
  CONNECT-UDP traffic against a real UDP echo server, plus spoofed-destination,
  malformed-template, non-HTTPS-`:scheme`, forbidden-field,
  unknown-`:protocol`, oversize-capsule, FIN-mid-capsule, disabled-profile,
  and reload-withdrawal coverage, plus a mixed upstream whose HBONE-tagged
  member is refused while its directly dialable sibling relays, and an open
  backend circuit breaker that does not govern the tunnel. The stream-end
  assertions distinguish a clean FIN from a reset; neither accepts "either".

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

### Declared frame-length bound and SETTINGS alignment (issue #4261)

Header size limits are also the HTTP/3 *receive-side* bound on what one QUIC
stream can make the frame decoder buffer, on both untrusted frontend clients and
untrusted H3 backend peers.

Every HTTP/3 frame other than `DATA` — HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE,
and every unknown type, which RFC 9114 §7.2.8 says to ignore but which still has
to be buffered before it can be skipped — has to be accumulated whole before it
can be interpreted. The frame decoder learns the payload length from a QUIC
varint in the frame header, so an unbounded declared length is an unbounded
buffer.

QUIC flow control does **not** bound that. `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW`
and `FERRUM_HTTP3_RECEIVE_WINDOW` cap the bytes *in flight*; the decoder
consumes from the stream on every poll, which re-grants credit. `max_idle_timeout`
does not help either — a peer streaming payload for a frame it over-declared is
active, not idle.

The gateway therefore derives two values from `FERRUM_MAX_HEADER_SIZE_BYTES`,
the same policy the HTTP/1.1 and HTTP/2 frontends derive their parser limits
from. It installs both at `h3::server::builder()` for untrusted frontend
clients. Every production pooled H3 backend connection installs the declared
frame ceiling through `h3::client::builder()` as well; `h3::client::new` keeps
the unbounded upstream default and is not used on those constructors. A
malicious or compromised H3 backend can declare an enormous HEADERS, unknown,
CONTROL, or PUSH frame the same way a frontend client can; QUIC flow control
does not bound accumulation on either side. Backend clients deliberately do
not set `max_field_section_size`: `FERRUM_MAX_HEADER_SIZE_BYTES` is documented
as a request-header policy, not an H3-only backend response-header limit.

| Value | Source | Effect |
|---|---|---|
| Frontend `SETTINGS_MAX_FIELD_SECTION_SIZE` | `FERRUM_MAX_HEADER_SIZE_BYTES`, floored at 16 KiB, clamped into the QUIC varint range | Advertised to the client, and enforced by frontend QPACK decoding. Before this the listener advertised `VarInt::MAX` (2^62-1) while enforcing the configured limit only after a complete decode. |
| Buffered non-`DATA` frame ceiling | 2x the frontend field-section size | On frontend and pooled backend connections, a frame whose **declared** payload length exceeds it is refused before a single payload byte is buffered. |

**Failure posture.** The refusal happens as soon as the frame's type and length
varints are decoded — before the payload is stored and before the decoder arms
an accumulation target — and is a *connection* error of type
`H3_EXCESSIVE_LOAD` (`0x0107`, RFC 9114 §8.1). An over-declared length is a
resource-exhaustion attempt, not a malformed frame, so `H3_FRAME_ERROR` would
misreport it. The declared length is compared against the raw `u64` varint
before any `usize` conversion, so a `2^32 + n` declaration cannot truncate into
a short frame on a 32-bit target and slip under the ceiling; a length the
platform cannot address is refused the same way whatever the ceiling is.

Both the request streams and the peer's unidirectional control and push streams
decode under the same ceiling.

**The `DATA` exception.** `DATA` frame lengths are *never* bounded by this
ceiling. Their payload is streamed to the proxy path rather than accumulated by
the decoder, and request bodies legitimately exceed any header-sized limit.
Request bodies stay bounded by Ferrum's existing body-size policy
(`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` and the per-proxy equivalents).

**Why 2x, and what still returns 431.** The ceiling sits above the advertised
policy on purpose. A QPACK-encoded field section is smaller than the RFC 9114
field-section accounting of the same headers (which adds 32 bytes per field), so
a request that merely overshoots `FERRUM_MAX_HEADER_SIZE_BYTES` still decodes
and is answered with a graceful `431 Request Header Fields Too Large` rather
than a connection abort. Only a declaration far beyond the policy — the attack
shape — reaches the connection-level refusal. The listener's own post-decode
total-header check remains in place as defence in depth. On the backend client,
the same 2x declared-frame ceiling bounds encoded response HEADERS and the
peer's unidirectional control and push frames without adding a decoded response
header policy that H1/H2 backends do not share.

**Configuration admission.** Both derived values travel the wire as QUIC
varints. `EnvConfig::validate` refuses a `FERRUM_MAX_HEADER_SIZE_BYTES` whose
derived ceiling would not fit in one, rather than silently clamping the policy
into a bound the operator never configured (which would also make the H3
frontend disagree with H1 and H2 about the same setting).

This bound lives in the vendored `h3` crate; see
[`docs/upstream-h3-patches/005-max-buffered-frame-len/`](upstream-h3-patches/005-max-buffered-frame-len/README.md)
for the upstream retirement plan.

## Flow-control window tuning

The default QUIC flow-control windows are conservative because the H3 listener serves untrusted clients: 256 KiB per stream, 2 MiB receive budget per connection, and 2 MiB send budget per connection. The connection-level receive window is the aggregate governor, so active per-stream receive windows cannot exceed the connection receive budget in total. Memory budget per QUIC connection scales with `FERRUM_HTTP3_RECEIVE_WINDOW + FERRUM_HTTP3_SEND_WINDOW`; raise these values only after benchmarking a workload that benefits from larger windows. Explicit env values continue to override these defaults. Note: the H3 *backend* pool (gateway-to-upstream) uses larger windows internally (8 MiB stream / 32 MiB connection / 8 MiB send) — these are not exposed as env vars. Larger windows do **not** replace the declared-frame-length bound: pooled backend connections still install `max_buffered_frame_len` from `FERRUM_MAX_HEADER_SIZE_BYTES`, because an H3 backend is a hostile network boundary.

The frontend HTTP/2 listener applies the same conservative-by-default philosophy via `FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE` (256 KiB), `FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE` (2 MiB), and `FERRUM_FRONTEND_H2_MAX_FRAME_SIZE` (16 KiB). These are independent of the backend pool `FERRUM_POOL_HTTP2_*` env vars. For benchmarking or trusted-network deployments, raise the frontend H2 values to match the backend pool defaults (8 MiB stream / 32 MiB connection / 1 MiB frame).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FERRUM_ENABLE_HTTP3` | `false` | Enable the QUIC listener |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | `30` | QUIC idle timeout (seconds). `0` disables the idle timer (RFC 9000 §10.1). When `FERRUM_HTTP3_CONNECT_UDP_ENABLED=true` the **frontend** listener raises this to at least `FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS` (never lowers it, and never raises `0`); the raise is logged. H3 backend pools keep the configured value. See [the tunnel/connection idle note](#the-tunnel-idle-timeout-and-the-quic-connection-idle-timeout). |
| `FERRUM_HTTP3_MAX_STREAMS` | `1000` | Max concurrent streams per QUIC connection |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | `262,144` | Per-stream QUIC flow-control window (256 KiB — frontend default; raise for high-throughput workloads) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | `2,097,152` | Connection-level QUIC flow-control window (2 MiB — frontend default; raise for high-throughput workloads) |
| `FERRUM_HTTP3_SEND_WINDOW` | `2,097,152` | Connection-level send window (2 MiB — frontend default) |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | H3 backend pool connections per target |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 backend connection idle eviction |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | `32,768` | Response coalesce flush target. Clamped to `[H3_COALESCE_MIN_FLOOR=1 KiB, H3_COALESCE_MAX_CAP=1 MiB]`. |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | `32,768` | Response coalesce buffer capacity. Same H3-specific bounds — see [docs/response_body_streaming.md](response_body_streaming.md#response-body-coalescing) for the cross-protocol coalescing architecture. |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | `200` | Response coalesce time-based flush interval. H3-specific (the H1/H2-via-reqwest path uses opportunistic Pending-flush instead, so it has no flush-interval knob). |
| `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` | `32` | Cross-protocol bridge mpsc capacity (range: 1–1024) |
| `FERRUM_HTTP3_WEBSOCKET_ENABLED` | `true` | Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accept RFC 9220 Extended CONNECT WebSocket. See [WebSocket over HTTP/3](#websocket-over-http3-rfc-9220-extended-connect). |
| `FERRUM_HTTP3_CONNECT_UDP_ENABLED` | `false` | Accept RFC 9298 UDP proxying Extended CONNECT (`:protocol=connect-udp`). Off by default; `501` while disabled. **Process-wide:** every H3 HTTP route whose routing and `allowed_methods` policy admits CONNECT can match a `/udp/host/port/` suffix — use a dedicated MASQUE route/host/path, authentication/authorization, and explicit method filters on routes that must not expose CONNECT. Requires a build target with a do-not-fragment socket option (Linux/Android, macOS) because RFC 9298 §3.1 forbids introducing IP fragmentation — elsewhere `true` is a startup validation error. CONNECT-UDP in TLS 1.3 early data is always `425`, even when `CONNECT` is in `FERRUM_TLS_EARLY_DATA_METHODS`. See [CONNECT-UDP over HTTP/3](#connect-udp-over-http3-rfc-9298). |
| `FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS` | `256` | Maximum concurrent CONNECT-UDP tunnels for this process; `503` over the limit. `0` disables the limit. A value above the tokio semaphore permit ceiling is a startup validation error, never a silent clamp or a silent "unlimited". |
| `FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS` | `120` | Seconds a tunnel may carry no datagram in either direction (clamped 1–86400). The default is the two minutes RFC 9298 §3.2 says a UDP proxy SHOULD NOT go below. This value is also the floor for the frontend QUIC connection idle timeout while the profile is enabled, so the advertised tunnel lifetime is the one that actually holds. |
| `FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES` | `65,527` | Largest relayed UDP payload (clamped 1–65527, the RFC 9298 §5 Context ID 0 ceiling). Scales every per-session buffer — see [Bounds and lifecycle](#bounds-and-lifecycle). |
| `FERRUM_HTTP3_INITIAL_MTU` | `1500` | Initial QUIC path MTU (quinn clamps 1200–65527) |
