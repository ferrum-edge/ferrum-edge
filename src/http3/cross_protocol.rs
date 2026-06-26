//! HTTP/3 frontend → non-H3 backend dispatch with streaming responses +
//! coalescing.
//!
//! When an HTTP/3 client lands on a proxy whose backend is not currently
//! classified as H3-capable — or because the request is gRPC/WebSocket that
//! doesn't benefit from the native backend H3 pool — the H3 server bridges
//! the request to the same HTTP/1.1 + HTTP/2 backend infrastructure the main
//! proxy path uses.
//!
//! ## Buffering policy
//!
//! Mirrors the H1/H2 proxy path's plugin-driven decision (see
//! `ClientRequestBody::Streaming|Buffered` in `src/proxy/mod.rs`): stream
//! the request body by default, buffer only when a plugin explicitly
//! demands the body pre-before_proxy or when the caller has already
//! pre-buffered it upstream.
//!
//! - **Plain flavor — request body streamed via an mpsc bridge.**
//!   `reqwest::Body::wrap_stream` requires a `'static + Send + Sync`
//!   stream, which cannot directly hold a `&mut RequestStream` borrow.
//!   The bridge uses a `tokio::sync::mpsc` channel: one task (inlined via
//!   `tokio::join!`) reads `RequestStream::recv_data()` and pushes `Bytes`
//!   chunks into the Sender; the `Receiver` is wrapped via
//!   `stream::unfold` and handed to `Body::wrap_stream` (the Receiver
//!   owns its own state and is `'static`). Backpressure is provided by
//!   the bounded channel (capacity sized to
//!   `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY`, default 32). When the H3
//!   recv half is drained OR the backend cancels, both sides unwind
//!   cleanly without a dangling task. If the caller pre-buffered the
//!   body (plugin phase already collected it), the buffered bytes are
//!   passed to reqwest directly via `Body::from(Vec<u8>)` — one
//!   allocation, no bridge.
//!
//! - **gRPC flavor — request body buffered, response streamed when safe.**
//!   The gRPC pool's `proxy_grpc_request_from_bytes` API takes `Bytes` for
//!   retry-safe framing and trailer handling, so the request body is
//!   collected up-front (unary gRPC request bodies are small and this is a
//!   cross-protocol fallback path). The RESPONSE is streamed whenever no
//!   retry is configured AND no plugin forces response-body buffering;
//!   server-streaming / bidi gRPC RPCs flow frame-by-frame through the
//!   bridge rather than accumulating fully in memory before the first byte
//!   reaches the H3 client. When retries or body-buffering plugins are
//!   configured, the response is buffered so the retry/plugin layer can
//!   inspect it before forwarding.
//!
//! - **Size limits.** The Plain path enforces `max_request_body_size_bytes`
//!   inline in the streaming reader (413 on overflow mid-stream — a shared
//!   `AtomicBool` signals the post-join branch so the reqwest stream error
//!   isn't misclassified as 502). The gRPC path enforces
//!   `max_grpc_recv_size_bytes` inside `drain_h3_body` so H3 gRPC matches
//!   the H1/H2 gRPC ceiling (a single `https` proxy serves any HTTP
//!   version uniformly rather than diverging by frontend).
//!
//! - **Error responses are flavor-aware.** Plain failures emit HTTP error
//!   payloads (502 JSON, 413 JSON, etc.). gRPC failures emit trailers-only
//!   gRPC responses (HTTP 200 + `grpc-status` + `grpc-message` in the
//!   header block) so gRPC clients see `UNAVAILABLE`/`RESOURCE_EXHAUSTED`/
//!   `INVALID_ARGUMENT`/`UNIMPLEMENTED` rather than a transport error.
//!
//! - **Response body — streamed frame-by-frame with coalescing.** Identical
//!   coalescing configuration (`http3_coalesce_min_bytes`,
//!   `http3_coalesce_max_bytes`, `http3_flush_interval_micros`) to the
//!   native H3 pool path, so both produce the same QUIC frame cadence.
//!   Reqwest responses are polled via `chunk().await`; hyper gRPC responses
//!   are polled via `frame().await` so trailers can be separated from data
//!   and forwarded via `send_trailers`. Size ceilings
//!   (`max_response_body_size_bytes`) are enforced inline in the loop so a
//!   malicious backend cannot evade the limit by withholding
//!   `Content-Length`.
//!
//! - **gRPC trailers** — mandatory `grpc-status` / `grpc-message`
//!   signalling is preserved via H3 trailers (`send_trailers`). For
//!   buffered gRPC responses the pool extracts trailers into a `HashMap`;
//!   for streaming gRPC responses we pull them out of hyper's trailer
//!   frame during the DATA-loop exit.
//!
//! - **WebSocket over HTTP/3** — handled separately by
//!   `crate::http3::websocket::handle_h3_websocket` (RFC 9220 Extended
//!   CONNECT). The dispatcher in `src/http3/server.rs::handle_h3_request`
//!   intercepts `HttpFlavor::WebSocket` BEFORE the cross-protocol path
//!   so the dedicated handler can take ownership of the QUIC stream
//!   (split into independent send/recv halves for full-duplex frame
//!   relay). The `HttpFlavor::WebSocket` arm in `run()` below remains
//!   as defense in depth: if a refactor accidentally routes WebSocket
//!   here, it returns 501 rather than misbehaving silently. Controlled
//!   by `FERRUM_HTTP3_WEBSOCKET_ENABLED` (default true).
//!
//! ## Outcome reporting
//!
//! `CrossProtocolOutcome` captures everything the H3 listener needs to
//! build a `TransactionSummary` identical to the one the native H3 pool
//! path emits — response status, bytes streamed, body completion state,
//! client-disconnected flag, and error classifications.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{RecvStream, SendStream};
use h3::server::RequestStream;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use tracing::{debug, error, warn};

use crate::config::types::{HttpFlavor, Proxy, UpstreamTarget};
use crate::load_balancer::LoadBalancer;
use crate::plugins::{
    BackendAdmissionOutcome, BackendAdmissionPermitSet, Plugin, PluginResult, ProxyProtocol,
    RequestContext, ResponseStreamAction, ResponseStreamInspector,
};
use crate::proxy::ProxyState;
use crate::proxy::backend_dispatch::{record_backend_outcome, record_backend_outcome_no_conn_end};
use crate::proxy::grpc_proxy::{self, GrpcResponseKind, proxy_grpc_request_from_bytes};
use crate::proxy::headers::{
    is_backend_response_strip_header, parse_connection_listed_headers,
    strip_response_hop_by_hop_trailers,
};
use crate::request_epoch::RequestEpoch;
use crate::retry::ErrorClass;

/// Outcome reported back to the H3 listener so it can update request
/// counters, build the `TransactionSummary` for log plugins, and record
/// whether the client disconnected mid-stream.
pub struct CrossProtocolOutcome {
    pub response_status: u16,
    pub bytes_streamed: u64,
    pub bytes_sent: u64,
    pub backend_target: Option<String>,
    pub backend_resolved_ip: Option<String>,
    pub body_completed: bool,
    pub client_disconnected: bool,
    pub connection_error: bool,
    pub error_class: Option<ErrorClass>,
    pub body_error_class: Option<ErrorClass>,
    pub backend_total_ms: f64,
}

/// Per-dispatch coalescing tunables. Copied out of `ProxyState` once at
/// dispatch entry so the streaming loop doesn't re-load env config per
/// iteration.
#[derive(Clone, Copy)]
struct CoalesceConfig {
    min_bytes: usize,
    max_bytes: usize,
    flush_interval: Duration,
}

impl CoalesceConfig {
    fn from_state(state: &ProxyState) -> Self {
        Self {
            min_bytes: state.env_config.http3_coalesce_min_bytes,
            max_bytes: state.env_config.http3_coalesce_max_bytes,
            flush_interval: Duration::from_micros(state.env_config.http3_flush_interval_micros),
        }
    }
}

pub(crate) struct CrossProtocolRequest<'a, S>
where
    S: RecvStream + SendStream<Bytes>,
{
    pub state: &'a ProxyState,
    pub epoch: &'a RequestEpoch,
    pub proxy: &'a Proxy,
    pub stream: &'a mut RequestStream<S, Bytes>,
    pub method: &'a str,
    pub proxy_headers: &'a HashMap<String, String>,
    pub path: &'a str,
    pub query_string: &'a str,
    pub backend_url: &'a str,
    pub lb_hash_key: Option<&'a str>,
    pub upstream_target: Option<&'a UpstreamTarget>,
    pub upstream_balancer: Option<&'a Arc<LoadBalancer>>,
    pub cb_target_key: Option<&'a str>,
    pub cb_is_half_open_probe: bool,
    pub flavor: HttpFlavor,
    pub prebuffered_body: Option<Vec<u8>>,
    pub client_ip: &'a str,
    /// Immediate QUIC peer address — appended to X-Forwarded-For so the H3
    /// bridge matches the H1/H2 peer-append semantics (`build_xff_value`).
    pub xff_append_ip: &'a str,
    pub ctx: &'a mut RequestContext,
    pub plugins: &'a [Arc<dyn Plugin>],
    pub backend_admission_plugins: &'a [Arc<dyn Plugin>],
    pub requires_response_body_buffering: bool,
    pub sticky_cookie_needed: bool,
}

fn record_cross_protocol_connection_start(
    selected_balancer: Option<&Arc<LoadBalancer>>,
    upstream_target: Option<&UpstreamTarget>,
) {
    if let (Some(target), Some(balancer)) = (upstream_target, selected_balancer) {
        balancer.record_connection_start(target);
    }
}

fn cross_protocol_proxy_protocol(flavor: HttpFlavor) -> ProxyProtocol {
    match flavor {
        HttpFlavor::Plain => ProxyProtocol::Http,
        HttpFlavor::Grpc => ProxyProtocol::Grpc,
        HttpFlavor::WebSocket => ProxyProtocol::WebSocket,
    }
}

fn record_cross_protocol_backend_admission_outcome(
    permits: &mut Option<BackendAdmissionPermitSet>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    backend_elapsed: Duration,
) {
    if let Some(permits) = permits.take() {
        permits.record_backend_outcome(BackendAdmissionOutcome {
            response_status,
            connection_error,
            error_class,
            backend_elapsed,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn record_cross_protocol_header_write_disconnect(
    state: &ProxyState,
    proxy: &Proxy,
    epoch: &RequestEpoch,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&Arc<UpstreamTarget>>,
    cb_target_key: Option<&str>,
    backend_outcome_status: u16,
    admission_status: u16,
    cb_is_half_open_probe: bool,
    backend_start: Instant,
    backend_admission_permits: &mut Option<BackendAdmissionPermitSet>,
    backend_admission_elapsed: Duration,
) {
    record_backend_outcome(
        state,
        proxy,
        &epoch.load_balancer,
        upstream_balancer,
        current_target.map(|target| target.as_ref()),
        cb_target_key,
        backend_outcome_status,
        false,
        Some(ErrorClass::ClientDisconnect),
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
    record_cross_protocol_backend_admission_outcome(
        backend_admission_permits,
        admission_status,
        false,
        Some(ErrorClass::ClientDisconnect),
        backend_admission_elapsed,
    );
}

fn cross_protocol_header_write_disconnect_outcome(
    response_status: u16,
    bytes_sent: u64,
    backend_start: Instant,
    backend_target: Option<String>,
    backend_resolved_ip: Option<String>,
) -> CrossProtocolOutcome {
    CrossProtocolOutcome {
        response_status,
        bytes_streamed: 0,
        bytes_sent,
        backend_target,
        backend_resolved_ip,
        body_completed: false,
        client_disconnected: true,
        connection_error: false,
        error_class: None,
        body_error_class: Some(ErrorClass::ClientDisconnect),
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn release_cross_protocol_circuit_breaker_probe_on_admission_reject(
    state: &ProxyState,
    proxy: &Proxy,
    target_key: Option<&str>,
    is_half_open_probe: bool,
) {
    if !is_half_open_probe {
        return;
    }
    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state
            .circuit_breaker_cache
            .get_or_create(&proxy.id, target_key, cb_config);
        cb.record_neutral(true);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_cross_protocol_backend_admission_or_reject<S>(
    backend_admission_plugins: &[Arc<dyn Plugin>],
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    flavor: HttpFlavor,
    stream: &mut RequestStream<S, Bytes>,
    backend_start: Instant,
    bytes_sent: u64,
    state: &ProxyState,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    pending_slot_to_release_before_reject: Option<
        &mut Option<crate::backend_pending_limit::BackendPendingGuard>,
    >,
) -> Result<Result<Option<BackendAdmissionPermitSet>, CrossProtocolOutcome>, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    match crate::proxy::backend_dispatch::run_backend_admission_plugins(
        backend_admission_plugins,
        ctx,
        proxy,
        upstream_target,
        cross_protocol_proxy_protocol(flavor),
    ) {
        Ok(permits) => Ok(Ok(permits)),
        Err(rejection) => {
            // Release any reserved CB HALF_OPEN probe BEFORE writing the reject:
            // the writes below use `await?`, so an H3 client closing mid-write
            // returns early. The callers release only on the `Err(outcome)` arm,
            // so releasing here guarantees the slot is freed even on write error.
            release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                state,
                proxy,
                cb_target_key,
                cb_is_half_open_probe,
            );
            if let Some(slot) = pending_slot_to_release_before_reject {
                drop(slot.take());
            }
            let mut headers = rejection.headers;
            crate::proxy::apply_after_proxy_hooks_to_rejection(
                plugins,
                ctx,
                rejection.status_code,
                &mut headers,
            )
            .await;
            let http_status = StatusCode::from_u16(rejection.status_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            let mut outcome = if matches!(flavor, HttpFlavor::Grpc) {
                let normalized = normalize_h3_grpc_reject(http_status, &rejection.body, &headers);
                apply_h3_grpc_reject_metadata(ctx, &normalized);
                write_normalized_grpc_reject(stream, &normalized, backend_start, bytes_sent).await?
            } else {
                write_reject_with_headers(
                    stream,
                    http_status,
                    &rejection.body,
                    &headers,
                    backend_start,
                    bytes_sent,
                )
                .await?
            };
            outcome.error_class = Some(ErrorClass::DispatchPolicyRejected);
            Ok(Err(outcome))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record_cross_protocol_retry_failure(
    state: &ProxyState,
    proxy: &Proxy,
    selected_balancer: Option<&Arc<LoadBalancer>>,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
    is_half_open_probe: bool,
) {
    if let (Some(target), Some(balancer)) = (upstream_target, selected_balancer) {
        balancer.record_connection_end(target);
    }

    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state
            .circuit_breaker_cache
            .get_or_create(&proxy.id, cb_target_key, cb_config);
        cb.record_failure(response_status, connection_error, is_half_open_probe);
    }
}

#[allow(clippy::too_many_arguments)]
fn select_next_cross_protocol_retry_target(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    lb_hash_key: Option<&str>,
    current_target: Option<&Arc<UpstreamTarget>>,
    path: &str,
    query_string: &str,
    client_ip: &str,
    proxy_headers: &HashMap<String, String>,
) -> Option<(Arc<UpstreamTarget>, String, String)> {
    let (prev_target, hash_key) = (current_target?, lb_hash_key?);

    // Centralised in `backend_dispatch::select_next_retry_target` —
    // see that helper for the per-port `hash_on` recomputation contract
    // shared with the HTTP/H2/gRPC/WS retry sites.
    let next = crate::proxy::backend_dispatch::select_next_retry_target(
        state,
        epoch,
        proxy,
        prev_target,
        hash_key,
        client_ip,
        proxy_headers,
    )?;

    let strip_len = proxy.listen_path.as_deref().map(str::len).unwrap_or(0);
    let next_url = crate::proxy::build_backend_url_with_target(
        proxy,
        path,
        query_string,
        &next.host,
        next.port,
        strip_len,
        next.path.as_deref(),
    );
    let next_cb_target_key = crate::circuit_breaker::target_key(&next.host, next.port);
    Some((next, next_cb_target_key, next_url))
}

async fn resolve_cross_protocol_backend_ip(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
) -> Option<String> {
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(proxy.backend_host.as_str());
    state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string())
}

fn strip_query_from_backend_url(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

/// Entry point — routes the cross-protocol dispatch by flavor. Called from
/// the H3 server when the concrete backend target is not classified as
/// H3-capable or the flavor is not Plain.
///
/// `ctx` / `plugins` / `sticky_cookie_needed` are threaded through so the
/// bridge can run the same plugin pipeline as the native H3 path:
/// `apply_request_body_plugins` + `on_final_request_body` on the
/// prebuffered request body (transform + validate), `after_proxy` on the
/// backend response headers (modify / reject), `inject_sticky_cookie`
/// (sticky LB cookie), and buffered-response hooks
/// (`on_response_body` / `transform_response_body` /
/// `on_final_response_body`) on plain and gRPC responses when buffering is
/// active. Without these, H3 clients on non-H3 backends would silently skip
/// body validators, response transformers, sticky sessions, etc.
pub(crate) async fn run<S>(
    request: CrossProtocolRequest<'_, S>,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let CrossProtocolRequest {
        state,
        epoch,
        proxy,
        stream,
        method,
        proxy_headers,
        path,
        query_string,
        backend_url,
        lb_hash_key,
        upstream_target,
        upstream_balancer,
        cb_target_key,
        cb_is_half_open_probe,
        flavor,
        prebuffered_body,
        client_ip,
        xff_append_ip,
        ctx,
        plugins,
        backend_admission_plugins,
        requires_response_body_buffering,
        sticky_cookie_needed,
    } = request;
    let backend_start = Instant::now();
    let raw_prebuffered_body_bytes = prebuffered_body
        .as_ref()
        .map(|body| body.len() as u64)
        .unwrap_or(0);

    // If an earlier plugin phase pre-buffered the request body, run the
    // post-before_proxy body-transform + body-validation hooks on it
    // before we send to the backend. Mirrors the H1/H2 path's behavior in
    // `proxy_to_backend_retry` / `proxy_grpc_request_core`. An empty body
    // or plugins that don't opt in are zero-cost — see
    // `apply_request_body_plugins`.
    let prebuffered_body = match prebuffered_body {
        Some(body) if !plugins.is_empty() => {
            let transformed =
                crate::proxy::apply_request_body_plugins(plugins, proxy_headers, body).await;
            // Run validators. Reject = emit a trailers-only gRPC error
            // (Grpc flavor) or a plain JSON error (everything else) and
            // return early WITHOUT dispatching to the backend.
            match crate::proxy::run_final_request_body_hooks(
                plugins,
                Some(ctx),
                proxy_headers,
                &transformed,
            )
            .await
            {
                PluginResult::Continue => Some(transformed),
                reject => {
                    // This is a client/request-body policy outcome before any
                    // backend dispatch. Release a HALF_OPEN probe neutrally so
                    // a client-fault rejection cannot wedge the breaker.
                    release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                        state,
                        proxy,
                        cb_target_key,
                        cb_is_half_open_probe,
                    );
                    return write_final_body_reject(
                        stream,
                        flavor,
                        plugins,
                        ctx,
                        reject,
                        backend_start,
                        raw_prebuffered_body_bytes,
                    )
                    .await;
                }
            }
        }
        other => other,
    };

    match flavor {
        HttpFlavor::Plain => {
            dispatch_plain(
                state,
                epoch,
                proxy,
                stream,
                method,
                proxy_headers,
                path,
                query_string,
                backend_url,
                lb_hash_key,
                upstream_target,
                upstream_balancer,
                cb_target_key,
                cb_is_half_open_probe,
                prebuffered_body,
                raw_prebuffered_body_bytes,
                client_ip,
                xff_append_ip,
                backend_start,
                ctx,
                plugins,
                backend_admission_plugins,
                requires_response_body_buffering,
                sticky_cookie_needed,
            )
            .await
        }
        HttpFlavor::Grpc => {
            dispatch_grpc(
                state,
                epoch,
                proxy,
                stream,
                method,
                proxy_headers,
                path,
                query_string,
                backend_url,
                lb_hash_key,
                upstream_target,
                upstream_balancer,
                cb_target_key,
                cb_is_half_open_probe,
                prebuffered_body,
                raw_prebuffered_body_bytes,
                client_ip,
                xff_append_ip,
                backend_start,
                ctx,
                plugins,
                backend_admission_plugins,
                requires_response_body_buffering,
                sticky_cookie_needed,
            )
            .await
        }
        HttpFlavor::WebSocket => {
            // Defense in depth. The H3 dispatcher in
            // `src/http3/server.rs::handle_h3_request` intercepts
            // WebSocket flavor BEFORE cross_protocol::run and routes
            // it to `crate::http3::websocket::handle_h3_websocket`,
            // which implements RFC 9220 Extended CONNECT bridging.
            // Reaching this arm means a refactor accidentally fell
            // through; emit 501 rather than silently misbehave.
            warn!(
                proxy_id = %proxy.id,
                "Unexpected WebSocket flavor reached cross_protocol::run; \
                 should have been routed to handle_h3_websocket. Returning 501."
            );
            write_error(
                stream,
                StatusCode::NOT_IMPLEMENTED,
                r#"{"error":"WebSocket over HTTP/3 routing error"}"#,
                backend_start,
                0,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Plain flavor — reqwest + streaming response with coalescing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_plain_request_builder(
    client: &reqwest::Client,
    state: &ProxyState,
    proxy: &Proxy,
    req_method: reqwest::Method,
    proxy_headers: &HashMap<String, String>,
    backend_url: &str,
    effective_host: &str,
    client_ip: &str,
    xff_append_ip: &str,
    is_early_data: bool,
) -> reqwest::RequestBuilder {
    let mut req_builder = client.request(req_method, backend_url);

    // Per-request timeout overrides. The shared `reqwest::Client` has no
    // client-level connect or read timeout, so each request must apply its
    // own. The connect-timeout API is provided by a vendored copy of reqwest
    // patched with seanmonstar/reqwest#3017.
    if proxy.backend_connect_timeout_ms > 0 {
        req_builder =
            req_builder.connect_timeout(Duration::from_millis(proxy.backend_connect_timeout_ms));
    }
    if proxy.backend_read_timeout_ms > 0 {
        req_builder = req_builder.timeout(Duration::from_millis(proxy.backend_read_timeout_ms));
    }

    let original_host_header = proxy_headers.get("host").map(|s| s.as_str());
    let original_xff = proxy_headers.get("x-forwarded-for").map(|s| s.as_str());
    for (k, v) in proxy_headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    req_builder = req_builder.header("Host", effective_host);
                }
            }
            // RFC 8470 §5.2: strip any client-supplied `Early-Data` header
            // — only the gateway is permitted to set it on a forwarded
            // request, and only when the inbound request actually arrived
            // over TLS 1.3 0-RTT. See the matching strip in
            // `build_h3_backend_headers` (native H3 backend path).
            _ if k.as_str() == "early-data" => {}
            _ if should_skip_cross_protocol_backend_header(k.as_str()) => {}
            _ => {
                req_builder = req_builder.header(k, v);
            }
        }
    }

    let xff_val = crate::proxy::build_xff_value(
        original_xff,
        client_ip,
        xff_append_ip,
        &state.trusted_proxies,
    );
    req_builder = req_builder.header("X-Forwarded-For", xff_val);
    req_builder = req_builder.header("X-Forwarded-Proto", "https");
    if let Some(host) = original_host_header {
        req_builder = req_builder.header("X-Forwarded-Host", host);
    }
    if let Some(ref via) = state.via_header_http3 {
        req_builder = req_builder.header("Via", via.as_str());
    }
    if state.add_forwarded_header {
        req_builder = req_builder.header(
            "Forwarded",
            crate::proxy::build_forwarded_value(client_ip, "https", original_host_header),
        );
    }
    // RFC 8470 §5.2: signal to the origin that this request was carried
    // over TLS 1.3 0-RTT so the backend can apply its own replay-safety
    // policy (return 425 Too Early, defer the response, etc.). The
    // gateway has already gated by `state.early_data_methods`, but the
    // backend may have stricter policy than the gateway's allow-list.
    if is_early_data {
        req_builder = req_builder.header("Early-Data", "1");
    }

    req_builder
}

fn reqwest_error_response_for_cross_protocol(
    state: &ProxyState,
    e: &reqwest::Error,
    backend_resolved_ip: Option<String>,
) -> crate::retry::BackendResponse {
    let error_class = crate::retry::classify_reqwest_error(e);
    if error_class == crate::retry::ErrorClass::PortExhaustion {
        state.overload.record_port_exhaustion();
    }
    let error_body = if error_class == crate::retry::ErrorClass::DnsLookupError {
        r#"{"error":"DNS resolution for backend failed"}"#
    } else {
        r#"{"error":"Backend unavailable"}"#
    };
    crate::retry::BackendResponse {
        status_code: 502,
        body: crate::retry::ResponseBody::Buffered(error_body.as_bytes().to_vec()),
        headers: HashMap::new(),
        // Funnel through `request_reached_wire` instead of
        // `e.is_connect() || e.is_timeout()` — the predicate-pair misses
        // TLS-handshake failures and reqwest-level timeouts that landed on
        // the connect side without surfacing as `is_connect()=true`. Every
        // dispatch path in the gateway must agree on the wire boundary
        // (see `retry::request_reached_wire`).
        connection_error: !crate::retry::request_reached_wire(error_class),
        backend_resolved_ip,
        error_class: Some(error_class),
    }
}

async fn collect_reqwest_response_body_with_limit(
    mut response: reqwest::Response,
    max_response_body_size_bytes: usize,
) -> Result<Vec<u8>, (Vec<u8>, Option<ErrorClass>)> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if max_response_body_size_bytes > 0
                    && body.len() + chunk.len() > max_response_body_size_bytes
                {
                    return Err((
                        r#"{"error":"Backend response body exceeds maximum size"}"#
                            .as_bytes()
                            .to_vec(),
                        Some(ErrorClass::ResponseBodyTooLarge),
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(error) => {
                warn!("cross-protocol H3→HTTP: failed to read buffered response body: {error}");
                return Err((
                    r#"{"error":"Backend response body read failed"}"#.as_bytes().to_vec(),
                    Some(crate::retry::classify_reqwest_error(&error)),
                ));
            }
        }
    }
}

/// Acquire the shared reqwest client for one H3→HTTP plain-bridge attempt,
/// resolved from this attempt's effective (per-port) proxy. On pool failure it
/// records the 502 backend outcome and writes the Bad-Gateway response, then
/// hands the caller the outcome to return (mirrors the original single-shot
/// client fetch, now invoked per attempt so a retry that rotated to a different
/// port gets that port's TLS/ALPN/idle client). Returns `Ok(Ok(client))` on
/// success, `Ok(Err(outcome))` when the caller should return the written
/// error, or `Err(_)` only on a stream-write failure.
///
/// Both callers run backend admission AND
/// `record_cross_protocol_connection_start` for the selected target BEFORE this
/// helper, so a client-build/pool failure here must take the FULL normal outcome
/// path, exactly like the `http1MaxPendingRequests` overflow shed below: (1)
/// record the backend-admission outcome (so the 502 connection failure feeds
/// adaptive concurrency and the permits are released), and (2) END the
/// least-connections connection via `record_backend_outcome` (conn_end = true)
/// to BALANCE the connection-start. Using `record_backend_outcome_no_conn_end`
/// instead would leave the connection-start unended — permanently inflating the
/// target's active-connection count — and drop the admission permits unrecorded.
#[allow(clippy::too_many_arguments)]
async fn get_cross_protocol_client<S>(
    state: &ProxyState,
    dispatch_proxy: &Proxy,
    epoch: &RequestEpoch,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&UpstreamTarget>,
    current_cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    backend_start: Instant,
    backend_admission_permits: &mut Option<BackendAdmissionPermitSet>,
    backend_admission_elapsed: Duration,
    stream: &mut RequestStream<S, Bytes>,
    pending_slot_to_release_before_error: Option<
        &mut Option<crate::backend_pending_limit::BackendPendingGuard>,
    >,
) -> Result<Result<reqwest::Client, CrossProtocolOutcome>, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    match state.connection_pool.get_client(dispatch_proxy).await {
        Ok(c) => Ok(Ok(c)),
        Err(e) => {
            error!(
                proxy_id = %dispatch_proxy.id,
                "cross-protocol H3→HTTP: failed to get client from pool: {}", e
            );
            record_cross_protocol_client_acquire_failure(
                state,
                dispatch_proxy,
                epoch,
                upstream_balancer,
                current_target,
                current_cb_target_key,
                cb_is_half_open_probe,
                backend_start,
                backend_admission_permits,
                backend_admission_elapsed,
            );
            if let Some(slot) = pending_slot_to_release_before_error {
                drop(slot.take());
            }
            let mut outcome = write_error(
                stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Bad Gateway"}"#,
                backend_start,
                0,
            )
            .await?;
            outcome.connection_error = true;
            Ok(Err(outcome))
        }
    }
}

/// Record the observability accounting for an H3→HTTP plain-bridge client-acquire
/// (pool/build) failure, BEFORE the Bad-Gateway response is written. Stream-free
/// so the accounting is unit-testable in isolation.
///
/// Both callers run backend admission AND
/// `record_cross_protocol_connection_start` for the selected target BEFORE the
/// client acquire, so this failure must take the FULL normal outcome path,
/// exactly like the `http1MaxPendingRequests` overflow shed: (1) record the
/// backend-admission outcome (so the 502 connection failure feeds adaptive
/// concurrency and the permits are released), and (2) END the least-connections
/// connection via `record_backend_outcome` (conn_end = true) to BALANCE the
/// connection-start. Using `record_backend_outcome_no_conn_end` instead would
/// leave the connection-start unended — permanently inflating the target's
/// active-connection count — and drop the admission permits unrecorded.
#[allow(clippy::too_many_arguments)]
fn record_cross_protocol_client_acquire_failure(
    state: &ProxyState,
    dispatch_proxy: &Proxy,
    epoch: &RequestEpoch,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&UpstreamTarget>,
    current_cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    backend_start: Instant,
    backend_admission_permits: &mut Option<BackendAdmissionPermitSet>,
    backend_admission_elapsed: Duration,
) {
    // Feed the 502 connection failure to adaptive concurrency and release the
    // admission permits acquired by the caller for this attempt.
    record_cross_protocol_backend_admission_outcome(
        backend_admission_permits,
        502,
        true,
        None,
        backend_admission_elapsed,
    );
    // END the least-connections connection (conn_end = true) to balance the
    // `record_cross_protocol_connection_start` the caller issued for this target,
    // and feed the 502 connection failure to the backend circuit breaker /
    // passive health / adaptive concurrency — mirroring the H1/H2 reqwest path's
    // connection-start/connection-end balance and the pending-overflow shed.
    record_backend_outcome(
        state,
        dispatch_proxy,
        &epoch.load_balancer,
        upstream_balancer,
        current_target,
        current_cb_target_key,
        502,
        true,
        None,
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
}

/// Run gateway-local dispatch-policy checks that must happen before backend
/// admission for one H3→HTTP plain-bridge attempt.
#[allow(clippy::too_many_arguments)]
async fn run_plain_attempt_local_policy_or_reject<S>(
    state: &ProxyState,
    epoch: &RequestEpoch,
    dispatch_proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&UpstreamTarget>,
    current_cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    backend_start: Instant,
    current_url: &str,
    effective_host: &str,
    dispatch_port: u16,
    bytes_sent: u64,
    halt_request_body_before_reject: bool,
) -> Result<
    Result<Option<crate::backend_pending_limit::BackendPendingGuard>, CrossProtocolOutcome>,
    anyhow::Error,
>
where
    S: RecvStream + SendStream<Bytes>,
{
    if dispatch_proxy.resolved_tls.sni.is_some() {
        warn!(
            proxy_id = %dispatch_proxy.id,
            backend_tls_sni = ?dispatch_proxy.resolved_tls.sni,
            reason = crate::proxy::BACKEND_TLS_SNI_REQUIRES_DIRECT_H2_REASON,
            "cross-protocol H3→HTTP bridge cannot honor backend TLS SNI override; returning 502"
        );
        record_backend_outcome_no_conn_end(
            state,
            dispatch_proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target,
            current_cb_target_key,
            502,
            false,
            Some(ErrorClass::DispatchPolicyRejected),
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        if halt_request_body_before_reject {
            crate::http3::stream_util::halt_request_body(stream);
        }
        let mut outcome = write_error_with_header(
            stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Bad Gateway"}"#,
            Some((
                "gateway-error-reason",
                crate::proxy::BACKEND_TLS_SNI_REQUIRES_DIRECT_H2_REASON,
            )),
            backend_start,
            bytes_sent,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(current_url));
        outcome.error_class = Some(ErrorClass::DispatchPolicyRejected);
        return Ok(Err(outcome));
    }

    let pending_cap =
        crate::proxy::resolve_backend_http1_max_pending_requests(dispatch_proxy, dispatch_port)
            .filter(|_| {
                crate::proxy::reqwest_dispatch_is_http1_only(state, dispatch_proxy, current_target)
            });
    match state
        .backend_pending_limit
        .try_acquire(effective_host, dispatch_port, pending_cap)
    {
        Ok(slot) => Ok(Ok(slot)),
        Err(limit) => {
            warn!(
                proxy_id = %dispatch_proxy.id,
                backend_host = %effective_host,
                backend_port = dispatch_port,
                pending_requests = limit.current,
                max_pending_requests = limit.cap,
                "Shedding cross-protocol H3→HTTP request: DestinationRule http1MaxPendingRequests reached for backend (upstream overflow)"
            );
            record_backend_outcome_no_conn_end(
                state,
                dispatch_proxy,
                &epoch.load_balancer,
                upstream_balancer,
                current_target,
                current_cb_target_key,
                503,
                false,
                Some(ErrorClass::DispatchPolicyRejected),
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            if halt_request_body_before_reject {
                crate::http3::stream_util::halt_request_body(stream);
            }
            let mut outcome = write_error(
                stream,
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Upstream pending request queue full"}"#,
                backend_start,
                bytes_sent,
            )
            .await?;
            outcome.backend_target = Some(strip_query_from_backend_url(current_url));
            outcome.error_class = Some(ErrorClass::DispatchPolicyRejected);
            Ok(Err(outcome))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_plain<S>(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    path: &str,
    query_string: &str,
    backend_url: &str,
    lb_hash_key: Option<&str>,
    upstream_target: Option<&UpstreamTarget>,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    prebuffered_body: Option<Vec<u8>>,
    raw_prebuffered_body_bytes: u64,
    client_ip: &str,
    xff_append_ip: &str,
    backend_start: Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    requires_response_body_buffering: bool,
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    // Honor DestinationRule per-port `connectionPool.http` effective-proxy
    // overrides for the LB-selected target, mirroring the H1/H2 plain dispatch
    // path (`proxy_to_backend` / `proxy_to_backend_retry`). The effective proxy
    // (per-port `idleTimeout` / `http2MaxRequests` / TLS / `h2UpgradePolicy` /
    // `connectTimeout`, plus the service-discovery top-level fallback) is
    // RE-RESOLVED per attempt INSIDE the retry loop below (against the failed
    // attempt's `current_target`), so a retry that rotates to a different port
    // gets THAT port's policy — the shared reqwest client (`get_client`), the
    // per-request `connectTimeout` (`build_plain_request_builder`), the SNI
    // reject, and the `http1MaxPendingRequests` gate all see the selected port's
    // posture (codex r1 #1806, mirrors how the H1/H2 path re-enters
    // `resolve_effective_proxy_for_target` per `proxy_to_backend_retry` call).
    //
    // The entry-level resolution (against the FIRST `upstream_target`) backs the
    // proxy-LEVEL decisions below (retry policy / response buffering — both
    // port-independent) and the post-dispatch outcome recording. The per-ATTEMPT
    // re-resolution inside the loop (`attempt_effective_proxy` /
    // `dispatch_proxy`) drives the actual dial. `base_proxy` is the unresolved
    // route proxy used to re-resolve each attempt's port. Borrowed (zero-alloc)
    // when no override applies.
    let base_proxy = proxy;
    let entry_effective_proxy =
        crate::proxy::resolve_effective_proxy_for_target(base_proxy, upstream_target);
    let proxy: &Proxy = entry_effective_proxy.as_ref();

    let req_method = match parse_reqwest_method(method) {
        Some(m) => m,
        None => {
            return write_error(
                stream,
                StatusCode::METHOD_NOT_ALLOWED,
                r#"{"error":"Method Not Allowed"}"#,
                backend_start,
                0,
            )
            .await;
        }
    };

    let mut current_target = upstream_target.cloned().map(Arc::new);
    let mut current_cb_target_key = cb_target_key.map(str::to_owned);
    let mut current_url = backend_url.to_string();
    let mut cb_retry_probe_slot_available = cb_is_half_open_probe;
    let retry_config = if crate::retry::has_effective_http_retries(proxy.retry.as_ref(), method) {
        proxy.retry.as_ref()
    } else {
        None
    };
    let should_buffer_response = retry_config.is_some()
        || !crate::proxy::should_stream_response_body(
            proxy,
            plugins,
            ctx,
            requires_response_body_buffering,
        );

    let (response, bytes_sent, mut backend_admission_permits, backend_admission_elapsed) =
        match prebuffered_body {
            Some(buffered_body) => {
                let bytes_sent = raw_prebuffered_body_bytes;
                let mut attempt = 0u32;
                let final_backend_admission_permits: Option<BackendAdmissionPermitSet>;
                let final_backend_admission_elapsed: Duration;

                let response = loop {
                    // Re-resolve the effective proxy for THIS attempt's target
                    // port (finding 5): a retry that rotated to a different port
                    // must dial with that port's TLS / `h2UpgradePolicy` ALPN /
                    // `idleTimeout` / `connectTimeout` / pending-cap DR policy.
                    // This has to run before backend admission so local
                    // dispatch-policy rejections cannot be masked by admission
                    // plugins at their own limit.
                    let attempt_effective_proxy = crate::proxy::resolve_effective_proxy_for_target(
                        base_proxy,
                        current_target.as_deref(),
                    );
                    let dispatch_proxy: &Proxy = attempt_effective_proxy.as_ref();

                    let effective_host = current_target
                        .as_deref()
                        .map(|t| t.host.as_str())
                        .unwrap_or(dispatch_proxy.backend_host.as_str());
                    let dispatch_port = current_target
                        .as_deref()
                        .map(|t| t.port)
                        .unwrap_or(dispatch_proxy.backend_port);

                    let mut pending_slot = match run_plain_attempt_local_policy_or_reject(
                        state,
                        epoch,
                        dispatch_proxy,
                        stream,
                        upstream_balancer,
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                        backend_start,
                        &current_url,
                        effective_host,
                        dispatch_port,
                        bytes_sent,
                        false,
                    )
                    .await?
                    {
                        Ok(slot) => slot,
                        Err(outcome) => return Ok(outcome),
                    };

                    let backend_admission_start = Instant::now();
                    let mut backend_admission_permits =
                        match run_cross_protocol_backend_admission_or_reject(
                            backend_admission_plugins,
                            plugins,
                            ctx,
                            dispatch_proxy,
                            current_target.as_deref(),
                            HttpFlavor::Plain,
                            stream,
                            backend_start,
                            bytes_sent,
                            state,
                            current_cb_target_key.as_deref(),
                            cb_retry_probe_slot_available,
                            Some(&mut pending_slot),
                        )
                        .await?
                        {
                            Ok(permits) => permits,
                            // Probe release happens inside the helper, before the reject write.
                            Err(outcome) => return Ok(outcome),
                        };
                    record_cross_protocol_connection_start(
                        upstream_balancer,
                        current_target.as_deref(),
                    );

                    let client = match get_cross_protocol_client(
                        state,
                        dispatch_proxy,
                        epoch,
                        upstream_balancer,
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                        backend_start,
                        &mut backend_admission_permits,
                        backend_admission_start.elapsed(),
                        stream,
                        Some(&mut pending_slot),
                    )
                    .await?
                    {
                        Ok(client) => client,
                        Err(outcome) => return Ok(outcome),
                    };

                    let send_result = build_plain_request_builder(
                        &client,
                        state,
                        dispatch_proxy,
                        req_method.clone(),
                        proxy_headers,
                        &current_url,
                        effective_host,
                        client_ip,
                        xff_append_ip,
                        ctx.is_early_data,
                    )
                    .body(buffered_body.clone())
                    .send()
                    .await;
                    drop(pending_slot);
                    match send_result {
                        Ok(response) => {
                            let attempt_result = crate::retry::BackendResponse {
                                status_code: response.status().as_u16(),
                                body: crate::retry::ResponseBody::Buffered(Vec::new()),
                                headers: HashMap::new(),
                                connection_error: false,
                                backend_resolved_ip: None,
                                error_class: None,
                            };
                            if let Some(retry_config) = retry_config
                                && crate::retry::should_retry(
                                    retry_config,
                                    method,
                                    &attempt_result,
                                    attempt,
                                )
                            {
                                record_cross_protocol_backend_admission_outcome(
                                    &mut backend_admission_permits,
                                    attempt_result.status_code,
                                    false,
                                    None,
                                    backend_admission_start.elapsed(),
                                );
                                record_cross_protocol_retry_failure(
                                    state,
                                    proxy,
                                    upstream_balancer,
                                    current_target.as_deref(),
                                    current_cb_target_key.as_deref(),
                                    attempt_result.status_code,
                                    false,
                                    cb_retry_probe_slot_available,
                                );
                                cb_retry_probe_slot_available = false;
                                let delay = crate::retry::retry_delay(retry_config, attempt);
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                if let Some((next_target, next_cb_target_key, next_url)) =
                                    select_next_cross_protocol_retry_target(
                                        state,
                                        epoch,
                                        proxy,
                                        lb_hash_key,
                                        current_target.as_ref(),
                                        path,
                                        query_string,
                                        client_ip,
                                        proxy_headers,
                                    )
                                {
                                    current_target = Some(next_target);
                                    current_cb_target_key = Some(next_cb_target_key);
                                    current_url = next_url;
                                }
                                warn!(
                                    proxy_id = %proxy.id,
                                    attempt = attempt,
                                    max_retries = retry_config.max_retries,
                                    connection_error = false,
                                    "Retrying cross-protocol H3→HTTP backend request"
                                );
                                continue;
                            }
                            final_backend_admission_elapsed = backend_admission_start.elapsed();
                            final_backend_admission_permits = backend_admission_permits;
                            break response;
                        }
                        Err(e) => {
                            let attempt_result =
                                reqwest_error_response_for_cross_protocol(state, &e, None);
                            warn!(
                                proxy_id = %proxy.id,
                                error = %e,
                                class = ?attempt_result.error_class,
                                "cross-protocol H3→HTTP: backend request failed"
                            );
                            if let Some(retry_config) = retry_config
                                && crate::retry::should_retry(
                                    retry_config,
                                    method,
                                    &attempt_result,
                                    attempt,
                                )
                            {
                                record_cross_protocol_backend_admission_outcome(
                                    &mut backend_admission_permits,
                                    attempt_result.status_code,
                                    attempt_result.connection_error,
                                    attempt_result.error_class,
                                    backend_admission_start.elapsed(),
                                );
                                record_cross_protocol_retry_failure(
                                    state,
                                    proxy,
                                    upstream_balancer,
                                    current_target.as_deref(),
                                    current_cb_target_key.as_deref(),
                                    attempt_result.status_code,
                                    attempt_result.connection_error,
                                    cb_retry_probe_slot_available,
                                );
                                cb_retry_probe_slot_available = false;
                                let delay = crate::retry::retry_delay(retry_config, attempt);
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                if let Some((next_target, next_cb_target_key, next_url)) =
                                    select_next_cross_protocol_retry_target(
                                        state,
                                        epoch,
                                        proxy,
                                        lb_hash_key,
                                        current_target.as_ref(),
                                        path,
                                        query_string,
                                        client_ip,
                                        proxy_headers,
                                    )
                                {
                                    current_target = Some(next_target);
                                    current_cb_target_key = Some(next_cb_target_key);
                                    current_url = next_url;
                                }
                                warn!(
                                    proxy_id = %proxy.id,
                                    attempt = attempt,
                                    max_retries = retry_config.max_retries,
                                    connection_error = attempt_result.connection_error,
                                    "Retrying cross-protocol H3→HTTP backend request"
                                );
                                continue;
                            }

                            let final_backend_resolved_ip = resolve_cross_protocol_backend_ip(
                                state,
                                proxy,
                                current_target.as_deref(),
                            )
                            .await;
                            record_cross_protocol_backend_admission_outcome(
                                &mut backend_admission_permits,
                                attempt_result.status_code,
                                attempt_result.connection_error,
                                attempt_result.error_class,
                                backend_admission_start.elapsed(),
                            );
                            record_backend_outcome(
                                state,
                                proxy,
                                &epoch.load_balancer,
                                upstream_balancer,
                                current_target.as_deref(),
                                current_cb_target_key.as_deref(),
                                attempt_result.status_code,
                                attempt_result.connection_error,
                                attempt_result.error_class,
                                cb_retry_probe_slot_available,
                                false,
                                backend_start.elapsed(),
                            );
                            let mut outcome = write_error(
                                stream,
                                StatusCode::BAD_GATEWAY,
                                r#"{"error":"Bad Gateway"}"#,
                                backend_start,
                                bytes_sent,
                            )
                            .await?;
                            outcome.backend_target =
                                Some(strip_query_from_backend_url(&current_url));
                            outcome.connection_error = attempt_result.connection_error;
                            outcome.error_class = attempt_result.error_class;
                            outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                            return Ok(outcome);
                        }
                    }
                };
                (
                    response,
                    bytes_sent,
                    final_backend_admission_permits,
                    final_backend_admission_elapsed,
                )
            }
            None => {
                // 413 on an oversized declared Content-Length BEFORE admission, so a
                // saturated limiter cannot mask the size violation as a 503. The
                // streaming reader below enforces the limit mid-body (recording the
                // admission outcome as a client-side overflow there), but admission
                // runs before the first read — mirror the reqwest/direct-H2/H3/HBONE
                // ordering so an oversized H3 upload still gets the local 413. No
                // admission permits exist yet, but the initial circuit-breaker check
                // may have reserved a HALF_OPEN probe, so neutralize it here (the
                // reader-loop 413 below does the same) or one oversized body wedges
                // the breaker's half-open slot.
                if state.max_request_body_size_bytes > 0
                    && let Some(content_length) = proxy_headers.get("content-length")
                    && let Ok(len) = content_length.parse::<usize>()
                    && len > state.max_request_body_size_bytes
                {
                    release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                        state,
                        proxy,
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                    );
                    return write_error(
                        stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        backend_start,
                        0,
                    )
                    .await;
                }
                // Re-resolve the effective proxy for this (single-attempt)
                // streaming dispatch's target port — same per-target resolution
                // the buffered retry loop performs (findings 4 & 5). Resolve
                // before backend admission so local dispatch-policy rejects
                // preserve H1/H2 ordering on the H3 bridge too.
                let attempt_effective_proxy = crate::proxy::resolve_effective_proxy_for_target(
                    base_proxy,
                    current_target.as_deref(),
                );
                let dispatch_proxy: &Proxy = attempt_effective_proxy.as_ref();

                let effective_host = current_target
                    .as_deref()
                    .map(|t| t.host.as_str())
                    .unwrap_or(dispatch_proxy.backend_host.as_str());
                let dispatch_port = current_target
                    .as_deref()
                    .map(|t| t.port)
                    .unwrap_or(dispatch_proxy.backend_port);

                let mut pending_slot = match run_plain_attempt_local_policy_or_reject(
                    state,
                    epoch,
                    dispatch_proxy,
                    stream,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                    backend_start,
                    &current_url,
                    effective_host,
                    dispatch_port,
                    0,
                    true,
                )
                .await?
                {
                    Ok(slot) => slot,
                    Err(outcome) => return Ok(outcome),
                };

                let backend_admission_start = Instant::now();
                let mut backend_admission_permits =
                    match run_cross_protocol_backend_admission_or_reject(
                        backend_admission_plugins,
                        plugins,
                        ctx,
                        dispatch_proxy,
                        current_target.as_deref(),
                        HttpFlavor::Plain,
                        stream,
                        backend_start,
                        0,
                        state,
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                        Some(&mut pending_slot),
                    )
                    .await?
                    {
                        Ok(permits) => permits,
                        // Probe release happens inside the helper, before the reject write.
                        Err(outcome) => return Ok(outcome),
                    };
                record_cross_protocol_connection_start(
                    upstream_balancer,
                    current_target.as_deref(),
                );

                let client = match get_cross_protocol_client(
                    state,
                    dispatch_proxy,
                    epoch,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                    backend_start,
                    &mut backend_admission_permits,
                    backend_admission_start.elapsed(),
                    stream,
                    Some(&mut pending_slot),
                )
                .await?
                {
                    Ok(client) => client,
                    Err(outcome) => return Ok(outcome),
                };

                let req_builder = build_plain_request_builder(
                    &client,
                    state,
                    dispatch_proxy,
                    req_method,
                    proxy_headers,
                    &current_url,
                    effective_host,
                    client_ip,
                    xff_append_ip,
                    ctx.is_early_data,
                );

                let max_req_bytes = state.max_request_body_size_bytes;
                let capacity = state.env_config.http3_request_body_channel_capacity;
                let (tx, rx) =
                    tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(capacity);
                // `tx` is borrowed by `reader_future` below, so the receiver cannot
                // rely on sender drop to observe EOF. Signal completion explicitly
                // once H3 DATA is drained so reqwest emits the final chunk marker.
                let reader_finished = Arc::new(AtomicBool::new(false));
                let reader_done_notify = Arc::new(tokio::sync::Notify::new());
                let body_stream_reader_finished = Arc::clone(&reader_finished);
                let body_stream_reader_done_notify = Arc::clone(&reader_done_notify);
                let body_stream = futures_util::stream::unfold(
                    (
                        rx,
                        body_stream_reader_finished,
                        body_stream_reader_done_notify,
                    ),
                    |(mut rx, reader_finished, reader_done_notify)| async move {
                        loop {
                            if reader_finished.load(Ordering::Acquire) && rx.is_empty() {
                                return None;
                            }
                            tokio::select! {
                                item = rx.recv() => {
                                    return item.map(|item| (item, (rx, reader_finished, reader_done_notify)));
                                }
                                _ = reader_done_notify.notified() => {}
                            }
                        }
                    },
                );
                let req_body = reqwest::Body::wrap_stream(body_stream);
                let send_future = req_builder.body(req_body).send();

                let bytes_read = Arc::new(AtomicU64::new(0));
                let reader_bytes = Arc::clone(&bytes_read);
                let oversized = Arc::new(AtomicBool::new(false));
                let reader_oversized = Arc::clone(&oversized);
                // When the backend resolves first, the outer `select!`
                // notifies the reader, which halts the recv half
                // (STOP_SENDING + H3_NO_ERROR) and exits. Without this,
                // dropping `reader_future` would close the mpsc sender
                // mid-stream — reqwest surfaces it as a connection error
                // AND the H3 recv half is left dangling, which the peer
                // observes as RESET_STREAM(0x0).
                let halt_notify = Arc::new(tokio::sync::Notify::new());
                let reader_halt = Arc::clone(&halt_notify);
                // The reader_future loops on (halt | recv_data). After it
                // receives a chunk it has to push it through the bounded mpsc
                // — and that `tx.send().await` is its own await point that
                // does NOT observe `halt_notify`. If the backend wins the
                // race while the channel is full (reqwest already saw the
                // response and stopped draining), the reader stays parked in
                // tx.send(); the outer drain + halt timeouts elapse without
                // progress and `reader_future` is dropped. To make sure the
                // halt is observable in that backpressure window, every
                // tx.send() is wrapped in its own select against
                // `reader_halt.notified()`. The unconditional
                // `halt_request_body` call after the bridge (below) is the
                // final safety net for any await that remains uncancellable.
                let reader_finished_for_reader = Arc::clone(&reader_finished);
                let reader_done_notify_for_reader = Arc::clone(&reader_done_notify);
                let reader_future = async {
                    let finish_reader = || {
                        reader_finished_for_reader.store(true, Ordering::Release);
                        reader_done_notify_for_reader.notify_waiters();
                    };
                    let mut total: usize = 0;
                    loop {
                        tokio::select! {
                            biased;
                            _ = reader_halt.notified() => {
                                crate::http3::stream_util::halt_request_body(stream);
                                finish_reader();
                                return;
                            }
                            chunk = stream.recv_data() => {
                                match chunk {
                                    Ok(Some(mut chunk)) => {
                                        let len = chunk.remaining();
                                        if max_req_bytes > 0 && total + len > max_req_bytes {
                                            reader_oversized.store(true, Ordering::Relaxed);
                                            crate::http3::stream_util::halt_request_body(stream);
                                            tokio::select! {
                                                biased;
                                                _ = reader_halt.notified() => {}
                                                _ = tx.send(Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidData,
                                                    "request body exceeds max_request_body_size_bytes",
                                                ))) => {}
                                            }
                                            finish_reader();
                                            return;
                                        }
                                        total += len;
                                        reader_bytes.store(total as u64, Ordering::Relaxed);
                                        // `Buf::copy_to_bytes` is zero-copy when the
                                        // underlying buffer is already `bytes::Bytes`
                                        // (always true with h3-quinn). Mirrors the
                                        // pattern used by the native H3 backend pool
                                        // in `src/http3/client.rs`.
                                        let body_bytes = chunk.copy_to_bytes(len);
                                        let send_outcome = tokio::select! {
                                            biased;
                                            _ = reader_halt.notified() => {
                                                crate::http3::stream_util::halt_request_body(stream);
                                                finish_reader();
                                                return;
                                            }
                                            res = tx.send(Ok(body_bytes)) => res,
                                        };
                                        if send_outcome.is_err() {
                                            finish_reader();
                                            return;
                                        }
                                    }
                                    Ok(None) => {
                                        finish_reader();
                                        return;
                                    }
                                    Err(e) => {
                                        tokio::select! {
                                            biased;
                                            _ = reader_halt.notified() => {}
                                            _ = tx.send(Err(std::io::Error::other(format!(
                                                "H3 recv_data failed: {}",
                                                e
                                            )))) => {}
                                        }
                                        finish_reader();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                };

                // Race resolution: the reader_future MUST stay polled until
                // it exits cleanly, otherwise dropping it closes the mpsc
                // sender mid-stream and reqwest surfaces the aborted body as
                // a connection error — AND the H3 recv half is left
                // dangling, which the peer observes as RESET_STREAM(0x0).
                // When the backend resolves first (common for early errors
                // and small 2xx responses while the client is still
                // uploading) we notify the reader so it halts the recv
                // half itself and exits naturally. A short grace deadline
                // caps the time we wait for the reader after the backend
                // has already answered.
                //
                // The drain budget only applies on backend success — error
                // responses (Bad Gateway, transport failure) halt
                // immediately, matching the explicit ferrum.conf promise
                // for FERRUM_H3_REQUEST_BODY_DRAIN_MS.
                let drain_ms = state.env_config.h3_request_body_drain_ms;
                let send_result = {
                    tokio::pin!(send_future);
                    tokio::pin!(reader_future);
                    let mut reader_done = false;
                    loop {
                        tokio::select! {
                            result = &mut send_future => {
                                drop(pending_slot.take());
                                if !reader_done {
                                    let backend_succeeded = result.is_ok();
                                    if backend_succeeded && drain_ms > 0 {
                                        let drain_deadline = Duration::from_millis(drain_ms);
                                        if let Ok(()) =
                                            tokio::time::timeout(drain_deadline, &mut reader_future)
                                                .await
                                        {
                                            reader_done = true;
                                        }
                                    }
                                    if !reader_done {
                                        halt_notify.notify_one();
                                        let halt_deadline = Duration::from_millis(100);
                                        let _ = tokio::time::timeout(halt_deadline, &mut reader_future)
                                            .await;
                                    }
                                }
                                break result;
                            }
                            _ = &mut reader_future, if !reader_done => {
                                reader_done = true;
                            }
                        }
                    }
                };
                // Final safety net: regardless of how the reader exited
                // (notified, naturally, oversized, recv error, or dropped
                // because the halt_notify never reached an uncancellable
                // await), call STOP_SENDING on the recv half before any
                // success path proceeds to write the response. Without
                // this, a reader parked in `tx.send()` under backpressure
                // would have its future dropped after the halt deadline
                // and the recv half would surface as RESET_STREAM(0x0) on
                // the wire — the exact failure mode this PR removes from
                // the early-response paths. STOP_SENDING is idempotent in
                // h3-quinn (subsequent calls return ClosedStream which is
                // ignored), so any inner halts already issued by the
                // reader cost only one extra frame.
                crate::http3::stream_util::halt_request_body(stream);
                let bytes_sent = bytes_read.load(Ordering::Relaxed);
                if oversized.load(Ordering::Relaxed) {
                    record_cross_protocol_backend_admission_outcome(
                        &mut backend_admission_permits,
                        413,
                        false,
                        Some(ErrorClass::ClientDisconnect),
                        backend_admission_start.elapsed(),
                    );
                    record_backend_outcome(
                        state,
                        proxy,
                        &epoch.load_balancer,
                        upstream_balancer,
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        413,
                        false,
                        None,
                        cb_retry_probe_slot_available,
                        false,
                        backend_start.elapsed(),
                    );
                    return write_error(
                        stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        backend_start,
                        bytes_sent,
                    )
                    .await;
                }

                match send_result {
                    Ok(response) => (
                        response,
                        bytes_sent,
                        backend_admission_permits,
                        backend_admission_start.elapsed(),
                    ),
                    Err(e) => {
                        let final_backend_resolved_ip = resolve_cross_protocol_backend_ip(
                            state,
                            proxy,
                            current_target.as_deref(),
                        )
                        .await;
                        let attempt_result = reqwest_error_response_for_cross_protocol(
                            state,
                            &e,
                            final_backend_resolved_ip.clone(),
                        );
                        record_cross_protocol_backend_admission_outcome(
                            &mut backend_admission_permits,
                            attempt_result.status_code,
                            attempt_result.connection_error,
                            attempt_result.error_class,
                            backend_admission_start.elapsed(),
                        );
                        warn!(
                            proxy_id = %proxy.id,
                            error = %e,
                            class = ?attempt_result.error_class,
                            "cross-protocol H3→HTTP: backend request failed"
                        );
                        record_backend_outcome(
                            state,
                            proxy,
                            &epoch.load_balancer,
                            upstream_balancer,
                            current_target.as_deref(),
                            current_cb_target_key.as_deref(),
                            attempt_result.status_code,
                            attempt_result.connection_error,
                            attempt_result.error_class,
                            cb_retry_probe_slot_available,
                            false,
                            backend_start.elapsed(),
                        );
                        let mut outcome = write_error(
                            stream,
                            StatusCode::BAD_GATEWAY,
                            r#"{"error":"Bad Gateway"}"#,
                            backend_start,
                            bytes_sent,
                        )
                        .await?;
                        outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
                        outcome.connection_error = attempt_result.connection_error;
                        outcome.error_class = attempt_result.error_class;
                        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                        return Ok(outcome);
                    }
                }
            }
        };

    let status = response.status().as_u16();
    let mut response_headers = collect_reqwest_response_headers(&response);
    let final_backend_resolved_ip =
        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref()).await;

    // Content-Length fast-path limit (mirrors the H3 pool path).
    if state.max_response_body_size_bytes > 0
        && let Some(len) = response_headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        && len > state.max_response_body_size_bytes
    {
        record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            502,
            false,
            None,
            cb_retry_probe_slot_available,
            false,
            backend_start.elapsed(),
        );
        record_cross_protocol_backend_admission_outcome(
            &mut backend_admission_permits,
            502,
            false,
            Some(ErrorClass::ResponseBodyTooLarge),
            backend_admission_elapsed,
        );
        let mut outcome = write_error(
            stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
            backend_start,
            bytes_sent,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        outcome.body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
        return Ok(outcome);
    }

    // Capture original response invariants before `after_proxy` rewrites the
    // headers below. On this H3 cross-protocol path the body is later either
    // streamed or buffered, so a response transformer that strips `Content-Range`
    // or `Cache-Control` ahead of compression would otherwise let compression
    // mislabel or rewrite a representation it must preserve.
    crate::http3::server::stamp_h3_original_response_metadata(ctx, status, &response_headers);

    // Run `after_proxy` hooks so response-transformer, CORS, compression-
    // advertise, and other hooks that modify response headers see the
    // cross-protocol path. A rejection here cancels the backend response
    // before we buffer or stream the body — matches
    // `run_after_proxy_hooks` semantics in `proxy/mod.rs`.
    if !plugins.is_empty()
        && let Some(reject) =
            crate::proxy::run_after_proxy_hooks(plugins, ctx, status, &mut response_headers).await
    {
        record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            status,
            false,
            None,
            cb_retry_probe_slot_available,
            false,
            backend_start.elapsed(),
        );
        record_cross_protocol_backend_admission_outcome(
            &mut backend_admission_permits,
            status,
            false,
            None,
            backend_admission_elapsed,
        );
        let mut outcome = write_reject_with_headers(
            stream,
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &reject.body,
            &reject.headers,
            backend_start,
            bytes_sent,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        return Ok(outcome);
    }

    // Sticky session cookie injection — only runs if the LB selected a
    // sticky target.
    crate::http3::server::inject_sticky_cookie(
        epoch,
        proxy,
        current_target.as_deref(),
        sticky_cookie_needed,
        &mut response_headers,
    );

    // Refine the pre-header buffer/stream decision now that the content-type is
    // known — same downgrade the H1/H2 path applies. `inspect` mode buffers by
    // default (so a JSON response is inspected via `on_response_body`); this
    // downgrades only an `text/event-stream` response to the windowed streaming
    // path. Retries must stay buffered for replay (pass `None`, which leaves the
    // decision unchanged).
    let has_retry = crate::retry::has_effective_http_retries(proxy.retry.as_ref(), method);
    let should_buffer_response = !crate::proxy::refine_stream_response_for_content_type(
        !should_buffer_response,
        proxy,
        plugins,
        if has_retry { None } else { Some(&*ctx) },
        status,
        &response_headers,
    );

    if should_buffer_response {
        let mut response_status = status;
        let mut response_body = match collect_reqwest_response_body_with_limit(
            response,
            state.max_response_body_size_bytes,
        )
        .await
        {
            Ok(body) => body,
            Err((error_body, error_class)) => {
                record_backend_outcome(
                    state,
                    proxy,
                    &epoch.load_balancer,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    502,
                    false,
                    error_class,
                    cb_retry_probe_slot_available,
                    false,
                    backend_start.elapsed(),
                );
                record_cross_protocol_backend_admission_outcome(
                    &mut backend_admission_permits,
                    502,
                    error_class.is_some_and(|class| class != ErrorClass::ClientDisconnect),
                    error_class,
                    backend_admission_elapsed,
                );
                let empty_headers = HashMap::new();
                let mut outcome = write_reject_with_headers(
                    stream,
                    StatusCode::BAD_GATEWAY,
                    &error_body,
                    &empty_headers,
                    backend_start,
                    bytes_sent,
                )
                .await?;
                outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                outcome.error_class = error_class;
                return Ok(outcome);
            }
        };

        if !plugins.is_empty() {
            for plugin in plugins {
                let result = plugin
                    .on_response_body(ctx, response_status, &response_headers, &response_body)
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        apply_buffered_plain_plugin_reject(
                            plugins,
                            ctx,
                            reject,
                            &mut response_status,
                            &mut response_headers,
                            &mut response_body,
                        )
                        .await;
                        break;
                    }
                }
            }

            for plugin in plugins {
                if let Some(transformed) = plugin
                    .transform_response_body_with_context(
                        &mut *ctx,
                        &response_body,
                        content_type_of(&response_headers),
                        &response_headers,
                    )
                    .await
                {
                    response_headers
                        .insert("content-length".to_string(), transformed.len().to_string());
                    response_body = transformed;
                }
            }

            for plugin in plugins {
                let result = plugin
                    .on_final_response_body(ctx, response_status, &response_headers, &response_body)
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        apply_buffered_plain_plugin_reject(
                            plugins,
                            ctx,
                            reject,
                            &mut response_status,
                            &mut response_headers,
                            &mut response_body,
                        )
                        .await;
                        break;
                    }
                }
            }
        }

        if let Err(error) = send_response_headers(stream, response_status, &response_headers).await
        {
            debug!("cross-protocol H3 buffered response header write failed: {error}");
            record_cross_protocol_header_write_disconnect(
                state,
                proxy,
                epoch,
                upstream_balancer,
                current_target.as_ref(),
                current_cb_target_key.as_deref(),
                response_status,
                status,
                cb_retry_probe_slot_available,
                backend_start,
                &mut backend_admission_permits,
                backend_admission_elapsed,
            );
            return Ok(cross_protocol_header_write_disconnect_outcome(
                response_status,
                bytes_sent,
                backend_start,
                Some(strip_query_from_backend_url(&current_url)),
                final_backend_resolved_ip.clone(),
            ));
        }
        let bytes_streamed = response_body.len() as u64;
        let mut body_completed = true;
        let mut client_disconnected = false;
        if !response_body.is_empty()
            && let Err(error) = stream.send_data(Bytes::from(response_body)).await
        {
            debug!("cross-protocol H3 buffered body send_data failed: {error}");
            client_disconnected = true;
            body_completed = false;
        }
        if body_completed && let Err(error) = stream.finish().await {
            debug!("cross-protocol H3 buffered finish failed: {error}");
            client_disconnected = true;
            body_completed = false;
        }

        record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            response_status,
            false,
            None,
            cb_retry_probe_slot_available,
            false,
            backend_start.elapsed(),
        );
        // Feed the limiter the ORIGINAL backend `status`, not `response_status`:
        // response-body/final-body plugin rejects above may have rewritten
        // `response_status` to a gateway policy code (e.g. a 503/4xx reject of a
        // healthy backend 200). Recording the policy status would make the
        // adaptive limiter shrink/grow on a signal that does not reflect backend
        // health. Matches the streaming path below and the H1/H2 path, which
        // capture the backend status before response-body hooks run.
        record_cross_protocol_backend_admission_outcome(
            &mut backend_admission_permits,
            status,
            false,
            if body_completed {
                None
            } else {
                Some(ErrorClass::ClientDisconnect)
            },
            backend_admission_elapsed,
        );

        return Ok(CrossProtocolOutcome {
            response_status,
            bytes_streamed,
            bytes_sent,
            backend_target: Some(strip_query_from_backend_url(&current_url)),
            backend_resolved_ip: final_backend_resolved_ip.clone(),
            body_completed,
            client_disconnected,
            connection_error: false,
            error_class: None,
            body_error_class: if body_completed {
                None
            } else {
                Some(ErrorClass::ClientDisconnect)
            },
            backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
        });
    }

    // Resolve a response-stream inspector (e.g. ai_semantic_firewall `inspect`)
    // for this H3-client → non-H3-backend response. Without this, an H3 client
    // hitting an HTTP/1/2 SSE backend would stream uninspected. Chain every
    // opted-in plugin, gated to the response status.
    let response_inspector = if plugins.iter().any(|p| p.requires_response_stream_hooks()) {
        let content_type = response_headers.get("content-type").map(String::as_str);
        let inspectors: Vec<_> = plugins
            .iter()
            .filter_map(|p| p.response_stream_inspector(&*ctx, status, content_type))
            .collect();
        crate::plugins::chain_response_stream_inspectors(inspectors)
    } else {
        None
    };
    // Strip Content-Length when inspecting — the inspector transforms the body, so
    // the backend's declared length no longer matches what we send.
    if response_inspector.is_some() {
        response_headers.remove("content-length");
    }

    // Send response headers, then stream the body.
    if let Err(error) = send_response_headers(stream, status, &response_headers).await {
        debug!("cross-protocol H3 streaming response header write failed: {error}");
        record_cross_protocol_header_write_disconnect(
            state,
            proxy,
            epoch,
            upstream_balancer,
            current_target.as_ref(),
            current_cb_target_key.as_deref(),
            status,
            status,
            cb_retry_probe_slot_available,
            backend_start,
            &mut backend_admission_permits,
            backend_admission_elapsed,
        );
        return Ok(cross_protocol_header_write_disconnect_outcome(
            status,
            bytes_sent,
            backend_start,
            Some(strip_query_from_backend_url(&current_url)),
            final_backend_resolved_ip.clone(),
        ));
    }

    let coalesce = CoalesceConfig::from_state(state);
    let max_resp_bytes = state.max_response_body_size_bytes;
    let (bytes_streamed, body_completed, client_disconnected, body_error_class) =
        if let Some(inspector) = response_inspector {
            stream_inspected_reqwest_response(stream, response, inspector, max_resp_bytes).await
        } else {
            stream_reqwest_response(stream, response, coalesce, max_resp_bytes).await
        };

    record_backend_outcome(
        state,
        proxy,
        &epoch.load_balancer,
        upstream_balancer,
        current_target.as_deref(),
        current_cb_target_key.as_deref(),
        status,
        false,
        None,
        cb_retry_probe_slot_available,
        false,
        backend_start.elapsed(),
    );
    let backend_admission_connection_error = match body_error_class {
        Some(ErrorClass::ClientDisconnect) => false,
        Some(_) => true,
        None => false,
    };
    record_cross_protocol_backend_admission_outcome(
        &mut backend_admission_permits,
        status,
        backend_admission_connection_error,
        body_error_class,
        backend_admission_elapsed,
    );

    Ok(CrossProtocolOutcome {
        response_status: status,
        bytes_streamed,
        bytes_sent,
        backend_target: Some(strip_query_from_backend_url(&current_url)),
        backend_resolved_ip: final_backend_resolved_ip.clone(),
        body_completed,
        client_disconnected,
        connection_error: false,
        error_class: None,
        body_error_class,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

// ---------------------------------------------------------------------------
// gRPC flavor — HTTP/2 gRPC pool + streaming response + trailers
// ---------------------------------------------------------------------------

/// Build the backend-facing header map for an H3→gRPC dispatch. Mirrors the
/// H1/H2 gRPC path in `src/proxy/mod.rs::proxy_grpc_request_core` so gRPC
/// backends behind an H3 frontend see the same forwarding metadata
/// (X-Forwarded-For, -Proto, -Host, Via, Forwarded) as they would over H1/H2.
/// Hop-by-hop headers (RFC 9110 §7.6.1) plus client-supplied forwarding headers
/// are stripped before the canonical forwarding set is re-synthesized. Shared
/// by the buffered (`dispatch_grpc`) and streaming (`dispatch_grpc_streaming`)
/// request paths so they cannot drift.
///
/// Hot-path note: the HOST and X-FORWARDED-FOR lookups use the hyper
/// pre-interned HeaderName constants when we know the key — but here the source
/// is a `HashMap<String, String>` so we use `.get()` on the lowercase literal
/// (single string compare, no alloc). Forwarding header *insertion* below uses
/// the pre-interned constants to skip the name-parse on the hot path.
fn build_h3_grpc_backend_headers(
    state: &ProxyState,
    proxy_headers: &HashMap<String, String>,
    client_ip: &str,
    xff_append_ip: &str,
    is_early_data: bool,
) -> HeaderMap {
    let original_host_header = proxy_headers.get("host").map(|s| s.as_str());
    let original_xff = proxy_headers.get("x-forwarded-for").map(|s| s.as_str());
    // Pre-size the HeaderMap — each source entry produces at most one output
    // and we add up to 5 forwarding headers; `HeaderMap::with_capacity`
    // clamps to the power-of-two bucket count so extra slack is cheap.
    let mut hmap = HeaderMap::with_capacity(proxy_headers.len() + 5);
    for (k, v) in proxy_headers {
        if should_skip_cross_protocol_backend_header(k.as_str()) {
            continue;
        }
        // RFC 8470 §5.2: `Early-Data` is set by the intermediary that
        // forwarded the request over 0-RTT, never by the originating
        // client. Strip any client-supplied value and let the
        // `is_early_data` injection below produce the canonical form.
        if k.as_str() == "early-data" {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            hmap.append(name, val);
        }
    }
    let xff_val = crate::proxy::build_xff_value(
        original_xff,
        client_ip,
        xff_append_ip,
        &state.trusted_proxies,
    );
    if let Ok(val) = HeaderValue::from_str(&xff_val) {
        hmap.insert("x-forwarded-for", val);
    }
    // `x-forwarded-proto=https` is identical across H3 requests (H3 is
    // always TLS) — use `from_static` to skip the header-value parse.
    hmap.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Some(host) = original_host_header
        && let Ok(val) = HeaderValue::from_str(host)
    {
        hmap.insert("x-forwarded-host", val);
    }
    if let Some(ref via) = state.via_header_http3
        && let Ok(val) = HeaderValue::from_str(via)
    {
        hmap.insert(hyper::header::VIA, val);
    }
    if state.add_forwarded_header {
        let fwd = crate::proxy::build_forwarded_value(client_ip, "https", original_host_header);
        if let Ok(val) = HeaderValue::from_str(&fwd) {
            hmap.insert(hyper::header::FORWARDED, val);
        }
    }
    // RFC 8470 §5.2: signal to the origin that this request was carried
    // over TLS 1.3 0-RTT so the gRPC backend can apply its own
    // replay-safety policy (e.g. reject with `UNAVAILABLE` on a
    // non-idempotent unary call). The gateway has already gated by
    // `state.early_data_methods`; the backend may apply additional policy.
    if is_early_data {
        hmap.insert("early-data", HeaderValue::from_static("1"));
    }
    hmap
}

/// Stream a live gRPC backend response (`GrpcResponseKind::Streaming`) onto an
/// H3 send half: run `after_proxy` + sticky-cookie on the headers, send the
/// response head, stream the body frame-by-frame through the coalescer, then
/// strip + forward the gRPC trailers — recording the backend / admission
/// outcome from the `grpc-status` trailer. Shared by the buffered-request
/// (`dispatch_grpc`, full bidi stream) and streaming-request
/// (`dispatch_grpc_streaming`, split send half) paths so the trailer handling
/// and health accounting cannot drift. Bounded `S: SendStream<Bytes>` so it
/// accepts both the full `RequestStream` and a `split()` send half.
#[allow(clippy::too_many_arguments)]
async fn handle_h3_grpc_streaming_response<S>(
    stream: &mut RequestStream<S, Bytes>,
    mut streaming: grpc_proxy::GrpcStreamingResponse,
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&Arc<UpstreamTarget>>,
    current_cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    backend_start: Instant,
    backend_admission_permits: &mut Option<BackendAdmissionPermitSet>,
    backend_admission_start: Instant,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    sticky_cookie_needed: bool,
    bytes_sent: u64,
    backend_target_url: &str,
    final_backend_resolved_ip: Option<String>,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    let current_target_ref: Option<&UpstreamTarget> = current_target.map(|t| t.as_ref());
    // Streaming variant: pool returned a live hyper Incoming. Run
    // after_proxy + sticky cookie on headers BEFORE streaming
    // begins — body-level hooks (`on_response_body`,
    // `on_final_response_body`) cannot run on streaming gRPC
    // responses because we don't hold the full body; the main
    // proxy path has the same limitation.
    if !plugins.is_empty()
        && let Some(reject) = crate::proxy::run_after_proxy_hooks(
            plugins,
            ctx,
            streaming.status,
            &mut streaming.headers,
        )
        .await
    {
        let reject_status = reject.status_code;
        let mut outcome = match write_final_grpc_body_reject_send(
            stream,
            plugins,
            ctx,
            PluginResult::RejectBinary {
                status_code: reject.status_code,
                body: Bytes::from(reject.body),
                headers: reject.headers,
            },
            backend_start,
            bytes_sent,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                debug!(
                    "cross-protocol H3 gRPC streaming after_proxy reject header write failed: {error}"
                );
                record_cross_protocol_header_write_disconnect(
                    state,
                    proxy,
                    epoch,
                    upstream_balancer,
                    current_target,
                    current_cb_target_key,
                    reject_status,
                    streaming.status,
                    cb_is_half_open_probe,
                    backend_start,
                    backend_admission_permits,
                    backend_admission_start.elapsed(),
                );
                return Ok(cross_protocol_header_write_disconnect_outcome(
                    reject_status,
                    bytes_sent,
                    backend_start,
                    Some(strip_query_from_backend_url(backend_target_url)),
                    final_backend_resolved_ip.clone(),
                ));
            }
        };
        record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target_ref,
            current_cb_target_key,
            outcome.response_status,
            false,
            None,
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        // Backend status, not the gateway policy reject (see the buffered
        // reject path above): a locally-rejected response must not train the
        // limiter as a backend failure.
        record_cross_protocol_backend_admission_outcome(
            backend_admission_permits,
            streaming.status,
            false,
            None,
            backend_admission_start.elapsed(),
        );
        outcome.backend_target = Some(strip_query_from_backend_url(backend_target_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        return Ok(outcome);
    }
    crate::http3::server::inject_sticky_cookie(
        epoch,
        proxy,
        current_target_ref,
        sticky_cookie_needed,
        &mut streaming.headers,
    );

    if let Err(error) = send_response_headers(stream, streaming.status, &streaming.headers).await {
        debug!("cross-protocol H3 gRPC streaming response header write failed: {error}");
        record_cross_protocol_header_write_disconnect(
            state,
            proxy,
            epoch,
            upstream_balancer,
            current_target,
            current_cb_target_key,
            streaming.status,
            streaming.status,
            cb_is_half_open_probe,
            backend_start,
            backend_admission_permits,
            backend_admission_start.elapsed(),
        );
        return Ok(cross_protocol_header_write_disconnect_outcome(
            streaming.status,
            bytes_sent,
            backend_start,
            Some(strip_query_from_backend_url(backend_target_url)),
            final_backend_resolved_ip.clone(),
        ));
    }
    let coalesce = CoalesceConfig::from_state(state);
    let max_resp_bytes = state.max_response_body_size_bytes;
    let (bytes_streamed, body_completed, client_disconnected, body_error_class, trailers) =
        stream_hyper_incoming(stream, streaming.body, coalesce, max_resp_bytes).await;

    let mut final_body_completed = body_completed;
    let mut final_client_disconnected = client_disconnected;
    // Capture the backend gRPC outcome from the trailers before they are
    // stripped/forwarded, so the admission sample below reflects a backend
    // gRPC failure (e.g. 14 -> 503) instead of the HTTP 200 status line.
    let mut grpc_trailer_status: Option<u32> = None;
    if body_completed && let Some(mut trailers) = trailers {
        grpc_trailer_status = trailers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u32>().ok());
        // Strip RFC 9110 §7.6.1 response-direction hop-by-hop names from
        // the backend gRPC trailers before forwarding to the H3 client,
        // via the shared helper so this site, the buffered path
        // (collect_buffered_grpc_trailers), and the H2 streaming wrapper
        // (body::StripHopByHopTrailers) cannot drift. Otherwise a
        // misbehaving/malicious backend can leak `trailer` /
        // `proxy-authenticate` / `connection` / `keep-alive` etc. to the
        // client through the TRAILERS frame.
        let had_trailers = !trailers.is_empty();
        strip_response_hop_by_hop_trailers(&mut trailers);
        if !trailers.is_empty() {
            if let Err(e) = stream.send_trailers(trailers).await {
                warn!("H3 gRPC streaming send_trailers failed: {}", e);
                final_client_disconnected = true;
                final_body_completed = false;
            }
        } else if had_trailers && let Err(e) = stream.finish().await {
            // Every trailer was hop-by-hop and got stripped to empty. The
            // map was non-empty on return, so stream_hyper_incoming left
            // the QUIC stream open for the caller to finalize (its
            // contract: it only finish()es when it returns None/empty
            // trailers). FIN it here — mirroring the buffered path's
            // `else { finish() }` above — so the stream is cleanly closed
            // instead of left open until the client times out (only RESET
            // on drop). The had_trailers guard avoids a double-finish when
            // the backend sent an already-empty trailer frame that
            // stream_hyper_incoming already finished.
            debug!("H3 gRPC streaming finish after trailer strip failed: {}", e);
            final_client_disconnected = true;
            final_body_completed = false;
        }
    }

    record_backend_outcome(
        state,
        proxy,
        &epoch.load_balancer,
        upstream_balancer,
        current_target_ref,
        current_cb_target_key,
        streaming.status,
        false,
        None,
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
    let backend_admission_connection_error = match body_error_class {
        Some(ErrorClass::ClientDisconnect) => false,
        Some(_) => true,
        None => false,
    };
    // On a clean completion the backend health rides in the grpc-status
    // trailer (HTTP 200) — map a non-OK status to 5xx so the limiter shrinks;
    // a mid-stream body error already drives `connection_error`/error_class.
    let admission_status = match grpc_trailer_status {
        Some(code) if code != 0 => crate::proxy::grpc_proxy::grpc_status_to_http_status(code),
        _ => streaming.status,
    };
    record_cross_protocol_backend_admission_outcome(
        backend_admission_permits,
        admission_status,
        backend_admission_connection_error,
        body_error_class,
        backend_admission_start.elapsed(),
    );
    Ok(CrossProtocolOutcome {
        response_status: streaming.status,
        bytes_streamed,
        bytes_sent,
        backend_target: Some(strip_query_from_backend_url(backend_target_url)),
        backend_resolved_ip: final_backend_resolved_ip.clone(),
        body_completed: final_body_completed,
        client_disconnected: final_client_disconnected,
        connection_error: false,
        error_class: None,
        body_error_class,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_grpc<S>(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    path: &str,
    query_string: &str,
    backend_url: &str,
    lb_hash_key: Option<&str>,
    upstream_target: Option<&UpstreamTarget>,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    prebuffered_body: Option<Vec<u8>>,
    raw_prebuffered_body_bytes: u64,
    client_ip: &str,
    xff_append_ip: &str,
    backend_start: Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    requires_response_body_buffering: bool,
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let hyper_method = match hyper::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return write_grpc_error(
                stream,
                grpc_proxy::grpc_status::UNIMPLEMENTED,
                "Method Not Allowed",
                backend_start,
                0,
            )
            .await;
        }
    };
    let mut current_target = upstream_target.cloned().map(Arc::new);
    let mut current_cb_target_key = cb_target_key.map(str::to_owned);
    let mut current_url = backend_url.to_string();
    let mut cb_retry_probe_slot_available = cb_is_half_open_probe;

    // gRPC request body: the pool API takes `Bytes` for retry-safe framing
    // and trailer handling. Buffer the H3 recv half here (unary gRPC bodies
    // are small; streaming gRPC request bodies over the cross-protocol
    // bridge would require a new GrpcBody variant in GrpcConnectionPool —
    // future optimization). Size ceiling uses `max_grpc_recv_size_bytes`
    // (not `max_request_body_size_bytes`) so H3 gRPC matches the H1/H2 gRPC
    // limit — an `https` proxy serves any client HTTP version uniformly.
    let body_was_prebuffered = prebuffered_body.is_some();
    let body = if let Some(buffered) = prebuffered_body {
        buffered
    } else {
        match drain_h3_body(stream, state.max_grpc_recv_size_bytes).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                    state,
                    proxy,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                );
                return write_grpc_error(
                    stream,
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    backend_start,
                    0,
                )
                .await;
            }
            Err(e) => {
                warn!(
                    proxy_id = %proxy.id,
                    error = %e,
                    "cross-protocol H3→gRPC: request body read failed"
                );
                release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                    state,
                    proxy,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                );
                return write_grpc_error(
                    stream,
                    grpc_proxy::grpc_status::INVALID_ARGUMENT,
                    "Request body read error",
                    backend_start,
                    0,
                )
                .await;
            }
        }
    };
    let bytes_sent = if body_was_prebuffered {
        raw_prebuffered_body_bytes
    } else {
        body.len() as u64
    };

    // Build the backend-facing header map (X-Forwarded-*, Via, Forwarded,
    // Early-Data) via the shared helper so the buffered and streaming H3 gRPC
    // paths cannot drift on forwarding-header synthesis.
    let hmap = build_h3_grpc_backend_headers(
        state,
        proxy_headers,
        client_ip,
        xff_append_ip,
        ctx.is_early_data,
    );

    // Stream the response whenever the per-request streaming policy
    // permits it. The previous `!grpc_has_retry &&` gate forced buffering
    // any time retry was configured, even though the retry loop below
    // only fires on CONNECTION errors that surface BEFORE any response
    // headers arrive (`BackendUnavailable` / `BackendTimeout::Connect`).
    // Once a response begins flowing the loop breaks out and never has to
    // inspect the body, so the streaming-vs-buffering choice for the
    // RESPONSE is orthogonal to whether the REQUEST body needs to be
    // replayable. Coupling them silently downgraded server-streaming /
    // bidi gRPC responses to "wait for the whole body" — the same
    // trailer-stall PR #497 fixed on the H1/H2 path.
    let grpc_has_retry = crate::retry::can_retry_connection_failures(proxy.retry.as_ref());
    let stream_grpc_response = crate::proxy::should_stream_response_body(
        proxy,
        plugins,
        ctx,
        requires_response_body_buffering,
    );
    let body_bytes = Bytes::from(body);
    let (initial_hmap, initial_body, retry_hmap, retry_body) = if grpc_has_retry {
        (
            hmap.clone(),
            body_bytes.clone(),
            Some(hmap),
            Some(body_bytes),
        )
    } else {
        (hmap, body_bytes, None, None)
    };
    let mut backend_admission_start = Instant::now();
    let mut backend_admission_permits = match run_cross_protocol_backend_admission_or_reject(
        backend_admission_plugins,
        plugins,
        ctx,
        proxy,
        current_target.as_deref(),
        HttpFlavor::Grpc,
        stream,
        backend_start,
        bytes_sent,
        state,
        current_cb_target_key.as_deref(),
        cb_retry_probe_slot_available,
        None,
    )
    .await?
    {
        Ok(permits) => permits,
        // Probe release happens inside the helper, before the reject write.
        Err(outcome) => return Ok(outcome),
    };
    record_cross_protocol_connection_start(upstream_balancer, current_target.as_deref());
    // `hmap` already contains the complete backend-bound header set
    // (plugin-transformed end-to-end headers + canonical forwarding
    // headers synthesized by this bridge). Passing the original
    // `proxy_headers` again would let the shared gRPC core overwrite
    // canonical forwarding values (`x-forwarded-*`, `via`, `forwarded`).
    let empty_proxy_headers: HashMap<String, String> = HashMap::new();
    let mut result = proxy_grpc_request_from_bytes(
        hyper_method.clone(),
        initial_hmap,
        initial_body,
        proxy,
        &current_url,
        &state.grpc_pool,
        &state.dns_cache,
        &empty_proxy_headers,
        stream_grpc_response,
        state.max_response_body_size_bytes,
    )
    .await;

    if grpc_has_retry
        && let Some(retry_config) = &proxy.retry
        && let (Some(hmap), Some(body_bytes)) = (retry_hmap, retry_body)
    {
        let mut attempt = 0u32;
        loop {
            // Pre-wire predicate for the H3→gRPC retry loop, derived from
            // the typed kind (NOT a wildcard match on `BackendUnavailable`).
            // The retry-on-connect-failure path bypasses `retry_on_methods`,
            // which is only safe when the request bytes never reached the
            // backend's application layer — i.e. when the kind is in the
            // `is_connect_class()` set (DNS / TCP connect / TLS handshake /
            // H2 handshake / H2c handshake / InvalidServerName).
            // `BackendUnavailable::BackendRequest` is post-wire by definition
            // (emitted from `sender.send_request().await` after H2 / ALPN)
            // and MUST be excluded so non-idempotent gRPC POSTs aren't
            // silently replayed on a mid-stream failure. `BackendTimeout::Connect`
            // is the connect-timeout timer — pre-wire by construction.
            // A regression test
            // (`test_every_connect_class_kind_classifies_as_pre_wire`)
            // structurally enforces that every kind in `is_connect_class()`
            // also satisfies `request_reached_wire(class) == false`, so the
            // predicate here cannot drift from the unified wire boundary in
            // [`crate::retry::request_reached_wire`].
            let is_connection_error = match &result {
                Err(grpc_proxy::GrpcProxyError::BackendUnavailable { kind, .. }) => {
                    kind.is_connect_class()
                }
                Err(grpc_proxy::GrpcProxyError::BackendTimeout {
                    kind: grpc_proxy::GrpcTimeoutKind::Connect,
                    ..
                }) => true,
                _ => false,
            };
            if !is_connection_error
                || !retry_config.retry_on_connect_failure
                || attempt >= retry_config.max_retries
            {
                break;
            }

            let retry_error_class = result
                .as_ref()
                .err()
                .map(crate::retry::classify_grpc_proxy_error);
            record_cross_protocol_backend_admission_outcome(
                &mut backend_admission_permits,
                502,
                true,
                retry_error_class,
                backend_admission_start.elapsed(),
            );
            record_cross_protocol_retry_failure(
                state,
                proxy,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                true,
                cb_retry_probe_slot_available,
            );
            cb_retry_probe_slot_available = false;

            let delay = crate::retry::retry_delay(retry_config, attempt);
            tokio::time::sleep(delay).await;
            attempt += 1;

            if let Some((next_target, next_cb_target_key, next_url)) =
                select_next_cross_protocol_retry_target(
                    state,
                    epoch,
                    proxy,
                    lb_hash_key,
                    current_target.as_ref(),
                    path,
                    query_string,
                    client_ip,
                    proxy_headers,
                )
            {
                current_target = Some(next_target);
                current_cb_target_key = Some(next_cb_target_key);
                current_url = next_url;
            }

            warn!(
                proxy_id = %proxy.id,
                attempt = attempt,
                max_retries = retry_config.max_retries,
                "Retrying cross-protocol H3→gRPC backend request"
            );
            backend_admission_start = Instant::now();
            backend_admission_permits = match run_cross_protocol_backend_admission_or_reject(
                backend_admission_plugins,
                plugins,
                ctx,
                proxy,
                current_target.as_deref(),
                HttpFlavor::Grpc,
                stream,
                backend_start,
                bytes_sent,
                state,
                current_cb_target_key.as_deref(),
                cb_retry_probe_slot_available,
                None,
            )
            .await?
            {
                Ok(permits) => permits,
                // Probe release happens inside the helper, before the reject write.
                Err(outcome) => return Ok(outcome),
            };
            record_cross_protocol_connection_start(upstream_balancer, current_target.as_deref());

            // Stream the retry response under the same conditions as the
            // initial attempt. Hard-coding `false` here would silently
            // downgrade a server-streaming RPC to fully buffered the
            // moment a transient TCP RST hit the very first attempt —
            // exactly the trailer-stall PR #497 fixed on the H1/H2 path.
            // Safe because this loop only retries pre-headers connection
            // errors; once a response begins it breaks out untouched.
            result = proxy_grpc_request_from_bytes(
                hyper_method.clone(),
                hmap.clone(),
                body_bytes.clone(),
                proxy,
                &current_url,
                &state.grpc_pool,
                &state.dns_cache,
                &empty_proxy_headers,
                stream_grpc_response,
                state.max_response_body_size_bytes,
            )
            .await;
        }
    }

    let final_backend_resolved_ip =
        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref()).await;

    match result {
        Ok(GrpcResponseKind::Buffered(resp)) => {
            // Buffered variant: pool extracted trailers up front. Run the full
            // response-hook pipeline (after_proxy, sticky cookie,
            // on_response_body, transform, on_final_response_body) on a merged
            // header+trailer VIEW, exactly like the main gRPC buffered path, so
            // a response hook that edits or removes a (header-shadowed or
            // trailer-only) gRPC trailer is reconciled onto the wire identically
            // on H1/H2 and H3 (#1614). `resp.headers` is left untouched as the
            // pristine backend initial-header reference for that reconciliation.
            //
            // Capture the backend's true gRPC terminal status for the
            // admission/adaptive-concurrency sample BEFORE building the plugin
            // view or running ANY response hook — exactly like the main gRPC
            // buffered path (`proxy::handle_proxy_request`, which snapshots
            // `grpc_backend_dispatch_status` before its merge/writeback). gRPC
            // application failures ride in the `grpc-status` trailer under
            // HTTP 200, and a sanitizing/rejecting hook may later rewrite, drop,
            // or reject on that trailer; sampling the limiter from post-hook
            // output (or the raw HTTP 200) would mislabel an UNAVAILABLE/INTERNAL
            // backend as healthy. `resp.trailers` / `resp.headers` are the
            // untouched backend maps here, so this is the backend result, not
            // plugin output.
            let grpc_backend_dispatch_status =
                crate::proxy::grpc_proxy::grpc_admission_status_from_maps(
                    &resp.trailers,
                    &resp.headers,
                    resp.status,
                );
            let (mut plugin_response_headers, header_shadowed_trailer_keys) =
                crate::proxy::grpc_proxy::build_grpc_plugin_header_view(
                    &resp.headers,
                    &resp.trailers,
                );
            if !plugins.is_empty()
                && let Some(reject) = crate::proxy::run_after_proxy_hooks(
                    plugins,
                    ctx,
                    resp.status,
                    &mut plugin_response_headers,
                )
                .await
            {
                let reject_status = reject.status_code;
                let mut outcome = match write_final_body_reject(
                    stream,
                    HttpFlavor::Grpc,
                    plugins,
                    ctx,
                    PluginResult::RejectBinary {
                        status_code: reject.status_code,
                        body: Bytes::from(reject.body),
                        headers: reject.headers,
                    },
                    backend_start,
                    bytes_sent,
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        debug!(
                            "cross-protocol H3 gRPC buffered after_proxy reject header write failed: {error}"
                        );
                        record_cross_protocol_header_write_disconnect(
                            state,
                            proxy,
                            epoch,
                            upstream_balancer,
                            current_target.as_ref(),
                            current_cb_target_key.as_deref(),
                            reject_status,
                            resp.status,
                            cb_retry_probe_slot_available,
                            backend_start,
                            &mut backend_admission_permits,
                            backend_admission_start.elapsed(),
                        );
                        return Ok(cross_protocol_header_write_disconnect_outcome(
                            reject_status,
                            bytes_sent,
                            backend_start,
                            Some(strip_query_from_backend_url(&current_url)),
                            final_backend_resolved_ip.clone(),
                        ));
                    }
                };
                record_backend_outcome(
                    state,
                    proxy,
                    &epoch.load_balancer,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    outcome.response_status,
                    false,
                    None,
                    cb_retry_probe_slot_available,
                    false,
                    backend_start.elapsed(),
                );
                // Feed the limiter the BACKEND result, not the gateway policy reject
                // in `outcome.response_status`: an after_proxy hook rejected locally,
                // so training on the policy status would wrongly shrink the backend
                // limit. But the backend result is the gRPC terminal status, not the
                // raw HTTP 200 — gRPC failures ride on HTTP 200, and a hook can reject
                // *because* of a backend `grpc-status: 14`. Use the pre-hook
                // `grpc_backend_dispatch_status` (mapped from the untouched backend
                // trailers) so a failing backend still shrinks, matching the main path.
                record_cross_protocol_backend_admission_outcome(
                    &mut backend_admission_permits,
                    grpc_backend_dispatch_status,
                    false,
                    None,
                    backend_admission_start.elapsed(),
                );
                outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                return Ok(outcome);
            }
            // Run the buffered response-body hook pipeline in the same order as
            // the main gRPC proxy path so reject/transform semantics stay
            // transport-independent. Hooks operate on the merged view; the wire
            // `response_headers` is assembled from it after trailer
            // reconciliation below, and the sticky-affinity cookie is injected
            // onto those final initial headers (matching the main path) so a
            // trailer-only backend `set-cookie` cannot divert it into the wire
            // trailers.
            let mut response_status = resp.status;
            let mut response_body = resp.body;
            let mut response_trailers = resp.trailers;
            for plugin in plugins.iter() {
                let result = plugin
                    .on_response_body(
                        ctx,
                        response_status,
                        &plugin_response_headers,
                        &response_body,
                    )
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        debug!(
                            plugin = plugin.name(),
                            "Plugin rejected buffered H3 gRPC response body"
                        );
                        apply_buffered_grpc_plugin_reject(
                            plugins,
                            ctx,
                            reject,
                            &mut response_status,
                            &mut plugin_response_headers,
                            &mut response_body,
                            &mut response_trailers,
                        )
                        .await;
                        break;
                    }
                }
            }
            // A response-body transform like grpc_web reads the gRPC status from
            // the headers map it is handed. The merged view already carries the
            // gRPC trailers (grpc-status / grpc-message and any trailer-only
            // keys; a trailer never overrides a real header), so the transform
            // sees the true terminal status instead of synthesizing UNKNOWN(2),
            // while the wire trailers stay separate for the split H3 wire shape.
            // content-length updates land on the view and flow into the wire
            // headers after reconciliation below.
            for plugin in plugins.iter() {
                if let Some(transformed) = plugin
                    .transform_response_body_with_context(
                        &mut *ctx,
                        &response_body,
                        content_type_of(&plugin_response_headers),
                        &plugin_response_headers,
                    )
                    .await
                {
                    plugin_response_headers
                        .insert("content-length".to_string(), transformed.len().to_string());
                    response_body = transformed;
                }
            }
            for plugin in plugins.iter() {
                let result = plugin
                    .on_final_response_body(
                        ctx,
                        response_status,
                        &plugin_response_headers,
                        &response_body,
                    )
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        debug!(
                            plugin = plugin.name(),
                            "Plugin rejected finalized buffered H3 gRPC response body"
                        );
                        apply_buffered_grpc_plugin_reject(
                            plugins,
                            ctx,
                            reject,
                            &mut response_status,
                            &mut plugin_response_headers,
                            &mut response_body,
                            &mut response_trailers,
                        )
                        .await;
                        break;
                    }
                }
            }

            // Reconcile hook edits/removals from the merged view back into the
            // wire trailers, then assemble the initial HEADERS frame from the
            // view. H3 always uses the split wire shape — real initial headers
            // plus a real TRAILERS frame, never a Trailers-Only collapse — so
            // plain gRPC-over-H3 keeps real trailers. `resp.headers` still holds
            // the pristine backend initial headers for the shadowed-key edit
            // detection. Strip the merged trailer copies (and any trailer-only
            // keys) out of the initial headers; header-shadowed keys stay real
            // headers whose true trailing value rides the wire trailer.
            //
            // Capture the backend's original trailer `set-cookie` (issue #1638)
            // before reconciliation overwrites it, mirroring the main gRPC path.
            let original_trailer_set_cookie = response_trailers.get("set-cookie").cloned();
            crate::proxy::grpc_proxy::reconcile_grpc_trailers_from_view(
                &mut response_trailers,
                &plugin_response_headers,
                &resp.headers,
                &header_shadowed_trailer_keys,
            );
            let mut response_headers = plugin_response_headers;
            for k in response_trailers.keys() {
                if !header_shadowed_trailer_keys.contains(k) {
                    response_headers.remove(k);
                }
            }
            // Re-home a hook-mutated trailer-only `set-cookie` onto the initial
            // HEADERS (issue #1638) so browsers / gRPC-Web clients can store it,
            // identically to the main gRPC path. Runs after the strip loop and
            // before sticky-cookie injection and the gRPC-Web trailer-clear
            // guard below.
            crate::proxy::grpc_proxy::rehome_hook_mutated_trailer_set_cookie(
                &mut response_headers,
                &mut response_trailers,
                original_trailer_set_cookie.as_deref(),
            );
            // Inject the sticky-affinity cookie onto the final initial headers,
            // matching the main gRPC path's ordering. Doing it here rather than on
            // the merged view ensures it lands in the wire HEADERS frame even when
            // the backend sent a trailer-only `set-cookie` (a non-shadowed trailer
            // key that the strip loop above just removed from the headers).
            crate::http3::server::inject_sticky_cookie(
                epoch,
                proxy,
                current_target.as_deref(),
                sticky_cookie_needed,
                &mut response_headers,
            );
            // The backend's true gRPC terminal status for the admission sample was
            // captured as `grpc_backend_dispatch_status` at the top of this arm,
            // before any hook could rewrite/drop `grpc-status` and before the
            // grpc_web trailer-clear just below — adaptive concurrency trains on the
            // backend result, not plugin output (matching the main gRPC path).
            //
            // A transform that converted away from native gRPC (grpc_web appends
            // a gRPC-Web trailer frame to the body and relabels the content-type)
            // must not ALSO emit native H3 trailers, or terminal status would be
            // double-signalled — mirror the main gRPC path's guard.
            if !response_trailers.is_empty()
                && response_headers.get("content-type").is_some_and(|ct| {
                    !crate::proxy::backend_dispatch::is_native_grpc_content_type(ct.as_bytes())
                })
            {
                response_trailers.clear();
            }

            if let Err(error) =
                send_response_headers(stream, response_status, &response_headers).await
            {
                debug!("cross-protocol H3 gRPC buffered response header write failed: {error}");
                record_cross_protocol_header_write_disconnect(
                    state,
                    proxy,
                    epoch,
                    upstream_balancer,
                    current_target.as_ref(),
                    current_cb_target_key.as_deref(),
                    response_status,
                    response_status,
                    cb_retry_probe_slot_available,
                    backend_start,
                    &mut backend_admission_permits,
                    backend_admission_start.elapsed(),
                );
                return Ok(cross_protocol_header_write_disconnect_outcome(
                    response_status,
                    bytes_sent,
                    backend_start,
                    Some(strip_query_from_backend_url(&current_url)),
                    final_backend_resolved_ip.clone(),
                ));
            }
            let bytes_total = response_body.len() as u64;
            let mut body_completed = true;
            let mut client_disconnected = false;
            if !response_body.is_empty()
                && let Err(e) = stream.send_data(Bytes::from(response_body)).await
            {
                debug!("cross-protocol H3 gRPC body send_data failed: {}", e);
                client_disconnected = true;
                body_completed = false;
            }
            if body_completed && !response_trailers.is_empty() {
                let trailer_map = headers_to_header_map(&response_trailers);
                if let Err(e) = stream.send_trailers(trailer_map).await {
                    warn!("H3 gRPC send_trailers failed: {}", e);
                    client_disconnected = true;
                    body_completed = false;
                }
            } else if body_completed && let Err(e) = stream.finish().await {
                debug!("H3 stream finish failed: {}", e);
                client_disconnected = true;
                body_completed = false;
            }
            record_backend_outcome(
                state,
                proxy,
                &epoch.load_balancer,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                response_status,
                false,
                None,
                cb_retry_probe_slot_available,
                false,
                backend_start.elapsed(),
            );
            // A completed buffered gRPC response carries its backend outcome in the
            // grpc-status trailer (HTTP 200), captured pre-hook as
            // `grpc_backend_dispatch_status`, so an UNAVAILABLE/INTERNAL backend must
            // shrink, not look healthy. An incomplete stream stays a client
            // disconnect (ignored), matching H1/H2.
            let admission_status = if body_completed {
                grpc_backend_dispatch_status
            } else {
                response_status
            };
            record_cross_protocol_backend_admission_outcome(
                &mut backend_admission_permits,
                admission_status,
                false,
                if body_completed {
                    None
                } else {
                    Some(ErrorClass::ClientDisconnect)
                },
                backend_admission_start.elapsed(),
            );
            Ok(CrossProtocolOutcome {
                response_status,
                bytes_streamed: bytes_total,
                bytes_sent,
                backend_target: Some(strip_query_from_backend_url(&current_url)),
                backend_resolved_ip: final_backend_resolved_ip.clone(),
                body_completed,
                client_disconnected,
                connection_error: false,
                error_class: None,
                body_error_class: if body_completed {
                    None
                } else {
                    Some(ErrorClass::ClientDisconnect)
                },
                backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
            })
        }
        Ok(GrpcResponseKind::Streaming(streaming)) => {
            handle_h3_grpc_streaming_response(
                stream,
                streaming,
                state,
                epoch,
                proxy,
                upstream_balancer,
                current_target.as_ref(),
                current_cb_target_key.as_deref(),
                cb_retry_probe_slot_available,
                backend_start,
                &mut backend_admission_permits,
                backend_admission_start,
                plugins,
                ctx,
                sticky_cookie_needed,
                bytes_sent,
                &current_url,
                final_backend_resolved_ip.clone(),
            )
            .await
        }
        Err(err) => {
            // Preserve DEADLINE_EXCEEDED / RESOURCE_EXHAUSTED / INTERNAL
            // semantics from the main gRPC path rather than collapsing
            // every failure to UNAVAILABLE. Also call the shared
            // `classify_grpc_proxy_error` so `body_error_class` on the
            // outcome matches what the H1/H2 gRPC path would emit for
            // the same failure mode (timeout vs connect-refused vs TLS).
            let error_class = crate::retry::classify_grpc_proxy_error(&err);
            let (grpc_status_code, grpc_message): (u32, &str) = match &err {
                grpc_proxy::GrpcProxyError::BackendTimeout { .. } => (
                    grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    "Backend deadline exceeded",
                ),
                grpc_proxy::GrpcProxyError::ResourceExhausted(_) => (
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request payload exceeded backend limit",
                ),
                grpc_proxy::GrpcProxyError::ResponseTooLarge(_) => (
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Response payload exceeded limit",
                ),
                grpc_proxy::GrpcProxyError::Internal(_) => {
                    (grpc_proxy::grpc_status::INTERNAL, "Internal gateway error")
                }
                grpc_proxy::GrpcProxyError::BackendUnavailable { .. } => {
                    (grpc_proxy::grpc_status::UNAVAILABLE, "Service unavailable")
                }
            };
            // Derive `connection_error` from the unified
            // `request_reached_wire` boundary instead of hard-coding `true`.
            // Hard-coding it tripped the circuit breaker / passive-health
            // counter as a connect-class failure for post-wire errors
            // (BackendRequest now `ConnectionReset`, read timeouts,
            // ResourceExhausted/Internal where the request bytes already
            // crossed the wire). Mirrors the H1/H2 gRPC path so a single
            // predicate governs `connection_error` everywhere.
            let connection_error = !crate::retry::request_reached_wire(error_class);
            warn!(
                proxy_id = %proxy.id,
                error = %err,
                class = ?error_class,
                grpc_status = grpc_status_code,
                connection_error,
                "cross-protocol H3→gRPC backend call failed"
            );
            record_backend_outcome(
                state,
                proxy,
                &epoch.load_balancer,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                connection_error,
                Some(error_class),
                cb_retry_probe_slot_available,
                false,
                backend_start.elapsed(),
            );
            record_cross_protocol_backend_admission_outcome(
                &mut backend_admission_permits,
                502,
                connection_error,
                Some(error_class),
                backend_admission_start.elapsed(),
            );
            let mut outcome = write_grpc_error(
                stream,
                grpc_status_code,
                grpc_message,
                backend_start,
                bytes_sent,
            )
            .await?;
            outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
            outcome.connection_error = connection_error;
            outcome.error_class = Some(error_class);
            outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
            Ok(outcome)
        }
    }
}

/// HTTP/3 → non-H3 gRPC backend with a STREAMING request body.
///
/// The streaming-safe counterpart to [`dispatch_grpc`] (which buffers the H3
/// request body before dispatch via `drain_h3_body`). Taken when the request is
/// gRPC and `can_stream_request_body` holds (no retry, no request/response body
/// buffering, no pre-buffered body — see `src/http3/server.rs`), so true
/// client-streaming / bidi RPCs forward request DATA to the backend
/// incrementally instead of waiting for the client half-close.
///
/// Owns the concrete `RequestStream` so it can `split()` into independent
/// send/recv halves (mirrors the H3 WebSocket bridge): a spawned pump owns the
/// recv half and feeds request DATA into a bounded channel that backs a
/// [`grpc_proxy::GrpcBody::Channel`] (hyper drives the upload from the channel
/// in the background), while this task streams the backend response onto the
/// send half. There is NO retry path — the request body is consumed on the wire
/// and cannot be replayed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_grpc_streaming(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    backend_url: &str,
    upstream_target: Option<&UpstreamTarget>,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    client_ip: &str,
    xff_append_ip: &str,
    backend_start: Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error> {
    let mut stream = stream;
    let current_target = upstream_target.cloned().map(Arc::new);
    let current_cb_target_key = cb_target_key.map(str::to_owned);

    let hyper_method = match hyper::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return write_grpc_error(
                &mut stream,
                grpc_proxy::grpc_status::UNIMPLEMENTED,
                "Method Not Allowed",
                backend_start,
                0,
            )
            .await;
        }
    };

    // Forwarding headers — shared with the buffered path so an `https` proxy
    // forwards identical metadata regardless of the request-body mode.
    let hmap = build_h3_grpc_backend_headers(
        state,
        proxy_headers,
        client_ip,
        xff_append_ip,
        ctx.is_early_data,
    );

    // Backend admission runs on the FULL stream (a reject write needs the send
    // half and a clean recv halt) BEFORE we split — mirrors `dispatch_grpc`.
    // `bytes_sent` is 0 here; the true request-byte count is tracked by the pump
    // and read when the response completes.
    let backend_admission_start = Instant::now();
    let mut backend_admission_permits = match run_cross_protocol_backend_admission_or_reject(
        backend_admission_plugins,
        plugins,
        ctx,
        proxy,
        current_target.as_deref(),
        HttpFlavor::Grpc,
        &mut stream,
        backend_start,
        0,
        state,
        current_cb_target_key.as_deref(),
        cb_is_half_open_probe,
        None,
    )
    .await?
    {
        Ok(permits) => permits,
        // Probe release happens inside the helper, before the reject write.
        Err(outcome) => return Ok(outcome),
    };
    record_cross_protocol_connection_start(upstream_balancer, current_target.as_deref());

    // Split the QUIC stream so request DATA (recv half) and response DATA (send
    // half) flow concurrently — required for bidi, where the backend responds
    // before the client half-closes.
    let (mut send_half, mut recv_half) = stream.split();

    // Bounded channel bridges the H3 recv half to the gRPC pool's streaming
    // body. The capacity provides upload backpressure (same env knob the plain
    // bridge uses). `Err(())` signals a frontend upload failure so the backend
    // is RST rather than handed a truncated-but-clean END_STREAM.
    let capacity = state.env_config.http3_request_body_channel_capacity.max(1);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ()>>(capacity);
    let request_bytes_seen = Arc::new(AtomicU64::new(0));
    let pump_bytes = Arc::clone(&request_bytes_seen);
    // Lets the response side terminate the pump promptly once the RPC is over
    // (e.g. a bidi server that sends its status before the client half-closes),
    // so the recv half is closed via STOP_SENDING(H3_NO_ERROR) instead of
    // lingering parked on `recv_data()`.
    let pump_shutdown = Arc::new(tokio::sync::Notify::new());
    let pump_shutdown_signal = Arc::clone(&pump_shutdown);
    let pump = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = pump_shutdown_signal.notified() => break,
                recv = recv_half.recv_data() => {
                    match recv {
                        Ok(Some(mut chunk)) => {
                            let len = chunk.remaining();
                            if len == 0 {
                                continue;
                            }
                            // `Buf::copy_to_bytes` is zero-copy when the buffer is
                            // already `bytes::Bytes` (always true with h3-quinn).
                            let body_bytes = chunk.copy_to_bytes(len);
                            pump_bytes.fetch_add(len as u64, Ordering::Relaxed);
                            if tx.send(Ok(body_bytes)).await.is_err() {
                                // Backend dropped the request body (RPC done / RST):
                                // nothing left to feed.
                                break;
                            }
                        }
                        // Clean client half-close: drop `tx` so the channel body
                        // observes END_STREAM and forwards the FIN to the backend.
                        Ok(None) => break,
                        Err(_e) => {
                            // Frontend upload failure: tell the channel body to RST
                            // the backend instead of sending a clean END_STREAM.
                            let _ = tx.send(Err(())).await;
                            break;
                        }
                    }
                }
            }
        }
        // STOP_SENDING(H3_NO_ERROR): a bare recv-half drop surfaces as
        // RESET_STREAM(0x0) and makes clients log a spurious "Remote reset".
        crate::http3::stream_util::halt_request_body(&mut recv_half);
    });

    // Dispatch with the channel-backed streaming body. No retry: the request
    // body is consumed on the wire. `hmap` already carries the canonical
    // forwarding headers, so pass empty proxy_headers — otherwise the shared
    // gRPC core would re-merge them and overwrite the canonical values.
    let body_size_exceeded = Arc::new(AtomicBool::new(false));
    let empty_proxy_headers: HashMap<String, String> = HashMap::new();
    let result = grpc_proxy::proxy_grpc_request_streaming_channel(
        hyper_method,
        hmap,
        rx,
        proxy,
        backend_url,
        &state.grpc_pool,
        &empty_proxy_headers,
        state.max_grpc_recv_size_bytes,
        Arc::clone(&body_size_exceeded),
        None,
    )
    .await;

    let final_backend_resolved_ip =
        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref()).await;

    let outcome = match result {
        Ok(GrpcResponseKind::Streaming(streaming)) => {
            let bytes_sent = request_bytes_seen.load(Ordering::Relaxed);
            handle_h3_grpc_streaming_response(
                &mut send_half,
                streaming,
                state,
                epoch,
                proxy,
                upstream_balancer,
                current_target.as_ref(),
                current_cb_target_key.as_deref(),
                cb_is_half_open_probe,
                backend_start,
                &mut backend_admission_permits,
                backend_admission_start,
                plugins,
                ctx,
                sticky_cookie_needed,
                bytes_sent,
                backend_url,
                final_backend_resolved_ip.clone(),
            )
            .await
        }
        // The channel entry always streams the response; a Buffered result is
        // unreachable, but handle it as an internal error rather than panicking.
        Ok(GrpcResponseKind::Buffered(_)) => {
            let bytes_sent = request_bytes_seen.load(Ordering::Relaxed);
            record_backend_outcome(
                state,
                proxy,
                &epoch.load_balancer,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                500,
                false,
                Some(ErrorClass::ProtocolError),
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            record_cross_protocol_backend_admission_outcome(
                &mut backend_admission_permits,
                500,
                false,
                Some(ErrorClass::ProtocolError),
                backend_admission_start.elapsed(),
            );
            let mut outcome = write_grpc_error_send(
                &mut send_half,
                grpc_proxy::grpc_status::INTERNAL,
                "Internal gateway error",
                backend_start,
                bytes_sent,
            )
            .await?;
            outcome.backend_target = Some(strip_query_from_backend_url(backend_url));
            outcome.error_class = Some(ErrorClass::ProtocolError);
            outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
            Ok(outcome)
        }
        Err(err) => {
            let bytes_sent = request_bytes_seen.load(Ordering::Relaxed);
            // Same gRPC-status mapping + wire-boundary `connection_error`
            // derivation as the buffered path's Err arm, so an H3-streaming gRPC
            // failure trains the breaker / limiter identically.
            let error_class = crate::retry::classify_grpc_proxy_error(&err);
            let (grpc_status_code, grpc_message): (u32, &str) = match &err {
                grpc_proxy::GrpcProxyError::BackendTimeout { .. } => (
                    grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    "Backend deadline exceeded",
                ),
                grpc_proxy::GrpcProxyError::ResourceExhausted(_) => (
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request payload exceeded backend limit",
                ),
                grpc_proxy::GrpcProxyError::ResponseTooLarge(_) => (
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Response payload exceeded limit",
                ),
                grpc_proxy::GrpcProxyError::Internal(_) => {
                    (grpc_proxy::grpc_status::INTERNAL, "Internal gateway error")
                }
                grpc_proxy::GrpcProxyError::BackendUnavailable { .. } => {
                    (grpc_proxy::grpc_status::UNAVAILABLE, "Service unavailable")
                }
            };
            let connection_error = !crate::retry::request_reached_wire(error_class);
            warn!(
                proxy_id = %proxy.id,
                error = %err,
                class = ?error_class,
                grpc_status = grpc_status_code,
                connection_error,
                "cross-protocol H3→gRPC streaming backend call failed"
            );
            record_backend_outcome(
                state,
                proxy,
                &epoch.load_balancer,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                connection_error,
                Some(error_class),
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            record_cross_protocol_backend_admission_outcome(
                &mut backend_admission_permits,
                502,
                connection_error,
                Some(error_class),
                backend_admission_start.elapsed(),
            );
            let mut outcome = write_grpc_error_send(
                &mut send_half,
                grpc_status_code,
                grpc_message,
                backend_start,
                bytes_sent,
            )
            .await?;
            outcome.backend_target = Some(strip_query_from_backend_url(backend_url));
            outcome.connection_error = connection_error;
            outcome.error_class = Some(error_class);
            outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
            Ok(outcome)
        }
    };

    // The RPC is over (response fully delivered, or we wrote a gRPC error). Stop
    // the pump and let it cleanly STOP_SENDING the recv half. `notify_one`
    // stores a permit if the pump is between selects, so there is no lost
    // wakeup; awaiting the join handle guarantees the recv-half teardown ran.
    pump_shutdown.notify_one();
    let _ = pump.await;

    outcome
}

async fn apply_buffered_plain_plugin_reject(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
) {
    let Some(reject) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("buffered plain reject helper received a non-reject plugin result");
        return;
    };
    let mut headers = reject.headers;
    crate::proxy::apply_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        reject.status_code,
        &mut headers,
    )
    .await;
    if !headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("content-type"))
    {
        headers.insert("content-type".to_string(), "application/json".to_string());
    }
    *response_status = reject.status_code;
    *response_headers = headers;
    *response_body = reject.body;
}

async fn apply_buffered_grpc_plugin_reject(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
    response_trailers: &mut HashMap<String, String>,
) {
    let Some(reject) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("buffered gRPC reject helper received a non-reject plugin result");
        return;
    };
    let mut headers = reject.headers;
    crate::proxy::apply_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        reject.status_code,
        &mut headers,
    )
    .await;
    let normalized = normalize_h3_grpc_reject(
        StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY),
        &reject.body,
        &headers,
    );
    apply_h3_grpc_reject_metadata(ctx, &normalized);
    *response_status = normalized.http_status.as_u16();
    *response_headers = normalized.headers;
    *response_body = normalized.body;
    response_trailers.clear();
}

// ---------------------------------------------------------------------------
// Streaming response writers — one per backend body type. Both implement
// the same coalesce-min / coalesce-max / flush-interval window as the
// native H3 pool write loop (server.rs:1339-1418), so operators see the
// same QUIC-level frame cadence across H3-pool and cross-protocol paths.
// ---------------------------------------------------------------------------

/// Stream a reqwest response body into the H3 stream with coalescing.
/// Returns `(bytes_streamed, body_completed, client_disconnected, body_error_class)`.
async fn stream_reqwest_response<S>(
    stream: &mut RequestStream<S, Bytes>,
    mut response: reqwest::Response,
    coalesce: CoalesceConfig,
    max_response_body_size_bytes: usize,
) -> (u64, bool, bool, Option<ErrorClass>)
where
    S: RecvStream + SendStream<Bytes>,
{
    let mut coalesce_buf = BytesMut::with_capacity(coalesce.max_bytes);
    let mut total_streamed: usize = 0;
    let flush_timer = tokio::time::sleep(coalesce.flush_interval);
    tokio::pin!(flush_timer);
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut client_disconnected = false;
    let mut body_error_class: Option<ErrorClass> = None;

    'outer: loop {
        tokio::select! {
            chunk_result = response.chunk(), if !stream_done => {
                match chunk_result {
                    Ok(Some(chunk)) => {
                        if max_response_body_size_bytes > 0 {
                            total_streamed += chunk.len();
                            if total_streamed > max_response_body_size_bytes {
                                warn!(
                                    "Backend response exceeded {} byte limit during cross-protocol H3 stream",
                                    max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break 'outer;
                            }
                        }
                        let chunk_len = chunk.len();
                        if crate::http3::config::should_direct_send_response_chunk(
                            coalesce_buf.len(),
                            chunk_len,
                            coalesce.min_bytes,
                        ) {
                            if stream.send_data(chunk).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += chunk_len as u64;
                            flush_timer
                                .as_mut()
                                .reset(tokio::time::Instant::now() + coalesce.flush_interval);
                            continue;
                        }

                        coalesce_buf.extend_from_slice(&chunk);
                        if coalesce_buf.len() >= coalesce.min_bytes {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if stream.send_data(data).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += data_len;
                            flush_timer
                                .as_mut()
                                .reset(tokio::time::Instant::now() + coalesce.flush_interval);
                        }
                    }
                    Ok(None) => { stream_done = true; }
                    Err(e) => {
                        let class = crate::retry::classify_reqwest_error(&e);
                        coalesce_buf.clear();
                        crate::http3::stream_util::abort_response_stream(stream);
                        body_error_class = Some(class);
                        break 'outer;
                    }
                }
            }
            _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += data_len;
                flush_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + coalesce.flush_interval);
            }
        }
        if stream_done {
            if !coalesce_buf.is_empty() {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    break;
                }
                bytes_streamed += data_len;
            }
            if let Err(_e) = stream.finish().await {
                client_disconnected = true;
                body_error_class = Some(ErrorClass::ClientDisconnect);
            }
            break;
        }
    }

    let body_completed = body_error_class.is_none() && !client_disconnected;
    (
        bytes_streamed,
        body_completed,
        client_disconnected,
        body_error_class,
    )
}

fn inspected_emitted_response_limit_exceeded(
    bytes_streamed: u64,
    next_len: usize,
    max_response_body_size_bytes: usize,
) -> bool {
    max_response_body_size_bytes > 0
        && bytes_streamed.saturating_add(next_len as u64) > max_response_body_size_bytes as u64
}

/// Drive a response-stream [`ResponseStreamInspector`] over a reqwest backend
/// response, writing released bytes to the H3 client stream. The cross-protocol
/// (H3 client → HTTP/1/2 backend) counterpart of the native-H3 inspected loop and
/// the H1/H2 [`crate::proxy::body::run_response_inspection`].
///
/// No coalescing — the inspector already releases coherent windows. A policy
/// `Terminate` ends the stream cleanly (the optional terminal SSE event, then
/// FIN); `body_completed` is gated on a successful finish, so a client that has
/// already disconnected is recorded as a disconnect, not a clean completion.
/// Returns `(bytes_streamed, body_completed, client_disconnected, body_error_class)`.
async fn stream_inspected_reqwest_response<S>(
    stream: &mut RequestStream<S, Bytes>,
    mut response: reqwest::Response,
    mut inspector: Box<dyn ResponseStreamInspector>,
    max_response_body_size_bytes: usize,
) -> (u64, bool, bool, Option<ErrorClass>)
where
    S: RecvStream + SendStream<Bytes>,
{
    let mut bytes_streamed: u64 = 0;
    let mut total_streamed: usize = 0;
    let mut client_disconnected = false;
    let mut body_error_class: Option<ErrorClass> = None;
    let mut finished = false;

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if max_response_body_size_bytes > 0 {
                    total_streamed += chunk.len();
                    if total_streamed > max_response_body_size_bytes {
                        warn!(
                            "Backend response exceeded {} byte limit during inspected cross-protocol H3 stream",
                            max_response_body_size_bytes
                        );
                        crate::http3::stream_util::abort_response_stream(stream);
                        body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                        break;
                    }
                }
                match inspector.on_chunk(&chunk).await {
                    ResponseStreamAction::Forward(out) => {
                        if !out.is_empty() {
                            if inspected_emitted_response_limit_exceeded(
                                bytes_streamed,
                                out.len(),
                                max_response_body_size_bytes,
                            ) {
                                warn!(
                                    "Inspected response exceeded {} byte emitted limit during cross-protocol H3 stream",
                                    max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break;
                            }
                            let out_len = out.len() as u64;
                            if stream.send_data(out).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(ErrorClass::ClientDisconnect);
                                break;
                            }
                            bytes_streamed += out_len;
                        }
                    }
                    ResponseStreamAction::Terminate(final_bytes) => {
                        if let Some(fb) = final_bytes
                            && !fb.is_empty()
                        {
                            if inspected_emitted_response_limit_exceeded(
                                bytes_streamed,
                                fb.len(),
                                max_response_body_size_bytes,
                            ) {
                                warn!(
                                    "Inspected response exceeded {} byte emitted limit during cross-protocol H3 stream termination",
                                    max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break;
                            }
                            let fb_len = fb.len() as u64;
                            if stream.send_data(fb).await.is_ok() {
                                bytes_streamed += fb_len;
                            }
                        }
                        if stream.finish().await.is_err() {
                            client_disconnected = true;
                            body_error_class = Some(ErrorClass::ClientDisconnect);
                        }
                        finished = true;
                        break;
                    }
                }
            }
            Ok(None) => {
                match inspector.on_end().await {
                    ResponseStreamAction::Forward(out) => {
                        if !out.is_empty() {
                            if inspected_emitted_response_limit_exceeded(
                                bytes_streamed,
                                out.len(),
                                max_response_body_size_bytes,
                            ) {
                                warn!(
                                    "Inspected response exceeded {} byte emitted limit at end of cross-protocol H3 stream",
                                    max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break;
                            }
                            let out_len = out.len() as u64;
                            if stream.send_data(out).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(ErrorClass::ClientDisconnect);
                                break;
                            }
                            bytes_streamed += out_len;
                        }
                    }
                    ResponseStreamAction::Terminate(final_bytes) => {
                        if let Some(fb) = final_bytes
                            && !fb.is_empty()
                        {
                            if inspected_emitted_response_limit_exceeded(
                                bytes_streamed,
                                fb.len(),
                                max_response_body_size_bytes,
                            ) {
                                warn!(
                                    "Inspected response exceeded {} byte emitted limit during end-of-stream termination",
                                    max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break;
                            }
                            let fb_len = fb.len() as u64;
                            if stream.send_data(fb).await.is_ok() {
                                bytes_streamed += fb_len;
                            }
                        }
                    }
                }
                if stream.finish().await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                }
                finished = true;
                break;
            }
            Err(e) => {
                body_error_class = Some(crate::retry::classify_reqwest_error(&e));
                crate::http3::stream_util::abort_response_stream(stream);
                break;
            }
        }
    }

    let body_completed = finished && body_error_class.is_none() && !client_disconnected;
    (
        bytes_streamed,
        body_completed,
        client_disconnected,
        body_error_class,
    )
}

/// Stream a hyper `Incoming` body into the H3 stream, separating trailer
/// frames for `send_trailers`. Returns
/// `(bytes_streamed, body_completed, client_disconnected, body_error_class, trailers)`.
async fn stream_hyper_incoming<S>(
    stream: &mut RequestStream<S, Bytes>,
    mut incoming: Incoming,
    coalesce: CoalesceConfig,
    max_response_body_size_bytes: usize,
) -> (u64, bool, bool, Option<ErrorClass>, Option<HeaderMap>)
where
    // Send-only: this loop writes the response (`send_data` / `finish` /
    // `abort_response_stream`) and never reads the request half, so it accepts
    // both the full bidi `RequestStream` (buffered-request gRPC path) and a
    // `split()` send half (streaming-request gRPC path).
    S: SendStream<Bytes>,
{
    let mut coalesce_buf = BytesMut::with_capacity(coalesce.max_bytes);
    let mut total_streamed: usize = 0;
    let flush_timer = tokio::time::sleep(coalesce.flush_interval);
    tokio::pin!(flush_timer);
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut client_disconnected = false;
    let mut body_error_class: Option<ErrorClass> = None;
    let mut trailers: Option<HeaderMap> = None;

    'outer: loop {
        tokio::select! {
            frame_result = incoming.frame(), if !stream_done => {
                match frame_result {
                    Some(Ok(frame)) => {
                        if frame.is_data() {
                            let data = match frame.into_data() {
                                Ok(d) => d,
                                Err(_) => {
                                    body_error_class = Some(ErrorClass::ProtocolError);
                                    crate::http3::stream_util::abort_response_stream(stream);
                                    break 'outer;
                                }
                            };
                            if data.is_empty() { continue; }
                            if max_response_body_size_bytes > 0 {
                                total_streamed += data.len();
                                if total_streamed > max_response_body_size_bytes {
                                    warn!(
                                        "Backend response exceeded {} byte limit during cross-protocol H3 gRPC stream",
                                        max_response_body_size_bytes
                                    );
                                    crate::http3::stream_util::abort_response_stream(stream);
                                    body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                    break 'outer;
                                }
                            }
                            let data_len = data.len();
                            if crate::http3::config::should_direct_send_response_chunk(
                                coalesce_buf.len(),
                                data_len,
                                coalesce.min_bytes,
                            ) {
                                if stream.send_data(data).await.is_err() {
                                    client_disconnected = true;
                                    body_error_class = Some(ErrorClass::ClientDisconnect);
                                    break 'outer;
                                }
                                bytes_streamed += data_len as u64;
                                flush_timer
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + coalesce.flush_interval);
                                continue;
                            }

                            coalesce_buf.extend_from_slice(&data);
                            if coalesce_buf.len() >= coalesce.min_bytes {
                                let out = coalesce_buf.split().freeze();
                                let out_len = out.len() as u64;
                                if stream.send_data(out).await.is_err() {
                                    client_disconnected = true;
                                    body_error_class = Some(ErrorClass::ClientDisconnect);
                                    break 'outer;
                                }
                                bytes_streamed += out_len;
                                flush_timer
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + coalesce.flush_interval);
                            }
                        } else if frame.is_trailers() {
                            match frame.into_trailers() {
                                Ok(t) => trailers = Some(t),
                                Err(_) => body_error_class = Some(ErrorClass::ProtocolError),
                            }
                            stream_done = true;
                        }
                    }
                    Some(Err(e)) => {
                        body_error_class = Some(classify_hyper_error(&e));
                        coalesce_buf.clear();
                        crate::http3::stream_util::abort_response_stream(stream);
                        break 'outer;
                    }
                    None => { stream_done = true; }
                }
            }
            _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                let out = coalesce_buf.split().freeze();
                let out_len = out.len() as u64;
                if stream.send_data(out).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += out_len;
                flush_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + coalesce.flush_interval);
            }
        }
        if stream_done {
            if !coalesce_buf.is_empty() {
                let out = coalesce_buf.split().freeze();
                let out_len = out.len() as u64;
                if stream.send_data(out).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    break;
                }
                bytes_streamed += out_len;
            }
            // When trailers are present, the caller finishes the stream
            // via `send_trailers`. Empty trailers are equivalent to absent
            // here: no trailers frame is needed, but the QUIC stream still
            // must be closed with FIN.
            if should_finish_h3_stream_without_trailers(trailers.as_ref())
                && let Err(_e) = stream.finish().await
            {
                client_disconnected = true;
                body_error_class = Some(ErrorClass::ClientDisconnect);
            }
            break;
        }
    }

    let body_completed = body_error_class.is_none() && !client_disconnected;
    (
        bytes_streamed,
        body_completed,
        client_disconnected,
        body_error_class,
        trailers,
    )
}

fn should_finish_h3_stream_without_trailers(trailers: Option<&HeaderMap>) -> bool {
    match trailers {
        None => true,
        Some(trailers) => trailers.is_empty(),
    }
}

fn classify_hyper_error(e: &hyper::Error) -> ErrorClass {
    if e.is_timeout() {
        ErrorClass::ReadWriteTimeout
    } else if e.is_incomplete_message() {
        ErrorClass::ConnectionClosed
    } else if e.is_canceled() {
        ErrorClass::ClientDisconnect
    } else {
        ErrorClass::ProtocolError
    }
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

fn collect_reqwest_response_headers(response: &reqwest::Response) -> HashMap<String, String> {
    let mut headers: HashMap<String, String> =
        HashMap::with_capacity(response.headers().keys_len());
    // RFC 9110 §7.6.1 also requires removing every header NAMED in the
    // response's `Connection` field. Snapshot the listed names before
    // iterating so we can strip them in the same pass as the canonical
    // predicate.
    let connection_listed = parse_connection_listed_headers(response.headers());
    for (k, v) in response.headers() {
        let name = k.as_str();
        // Strip hop-by-hop response headers per RFC 9110 §7.6.1 — see
        // `proxy::headers` for the canonical predicate. Response-direction
        // set differs from the request-direction set.
        if is_backend_response_strip_header(name) {
            continue;
        }
        if connection_listed.iter().any(|n| n == k) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            // `get_mut(name)` borrows the key as &str — no String alloc on
            // the multi-value case. Only the insert branch allocates the
            // owned key. Matches the H1/H2 path's pattern (see CLAUDE.md).
            match headers.get_mut(name) {
                Some(existing) => {
                    existing.push_str(if name == "set-cookie" { "\n" } else { ", " });
                    existing.push_str(val);
                }
                None => {
                    headers.insert(name.to_string(), val.to_string());
                }
            }
        }
    }
    headers
}

fn headers_to_header_map(map: &HashMap<String, String>) -> HeaderMap {
    let mut hmap = HeaderMap::new();
    for (k, v) in map {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            hmap.append(name, val);
        }
    }
    hmap
}

// ---------------------------------------------------------------------------
// H3 body drain + response writers
// ---------------------------------------------------------------------------

/// Drain the H3 stream body into a `Vec<u8>` with a size ceiling. Returns
/// `Ok(None)` when the limit is exceeded (caller emits 413).
async fn drain_h3_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, h3::error::StreamError>
where
    S: RecvStream + SendStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let bytes = chunk.chunk();
        if max_bytes > 0 && body.len() + bytes.len() > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(bytes);
    }
    Ok(Some(body))
}

async fn send_response_headers<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: u16,
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error>
where
    // Send-only: emits `send_response` and nothing on the recv half, so it
    // accepts both the full bidi stream and a `split()` send half.
    S: SendStream<Bytes>,
{
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_builder = Response::builder().status(status_code);
    for (k, v) in headers {
        if k == "set-cookie" {
            // Multiple Set-Cookie values are stored newline-separated by
            // `collect_reqwest_response_headers` to avoid RFC-violating
            // comma folding. Newlines are invalid inside a single
            // HeaderValue, so split and emit each cookie as its own header
            // line — mirrors the H1/H2 path in `src/proxy/mod.rs`. Fast
            // path: most responses have a single Set-Cookie, so skip the
            // split when there's no embedded newline.
            if !v.contains('\n') {
                if let Ok(val) = HeaderValue::from_str(v) {
                    // Pre-interned constant — zero parse, zero alloc.
                    resp_builder = resp_builder.header(hyper::header::SET_COOKIE, val);
                }
            } else {
                for cookie_val in v.split('\n') {
                    if let Ok(val) = HeaderValue::from_str(cookie_val) {
                        resp_builder = resp_builder.header(hyper::header::SET_COOKIE, val);
                    }
                }
            }
        } else if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            resp_builder = resp_builder.header(name, val);
        }
    }
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 response: {}", e))?;
    stream.send_response(resp).await?;
    Ok(())
}

async fn write_error<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &'static str,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    write_error_with_header(stream, status, body, None, backend_start, bytes_sent).await
}

async fn write_error_with_header<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &'static str,
    extra_header: Option<(&'static str, &'static str)>,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some((name, value)) = extra_header {
        builder = builder.header(name, value);
    }
    let resp = builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 error response: {}", e))?;
    stream.send_response(resp).await?;
    let bytes = Bytes::from_static(body.as_bytes());
    let len = bytes.len() as u64;
    let _ = stream.send_data(bytes).await;
    let _ = stream.finish().await;
    crate::http3::stream_util::halt_request_body(stream);
    Ok(CrossProtocolOutcome {
        response_status: status.as_u16(),
        bytes_streamed: len,
        bytes_sent,
        backend_target: None,
        backend_resolved_ip: None,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

/// Write a plugin-driven rejection response (dynamic body + custom
/// headers). Used when `after_proxy` or `on_final_request_body` returns
/// `PluginResult::Reject` — the plugin's body/headers win over the
/// backend's response.
async fn write_reject_with_headers<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let mut resp_builder = Response::builder().status(status);
    let mut has_content_type = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            resp_builder = resp_builder.header(name, val);
        }
    }
    if !has_content_type {
        resp_builder = resp_builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 reject response: {}", e))?;
    stream.send_response(resp).await?;
    let len = body.len() as u64;
    if !body.is_empty() {
        let _ = stream.send_data(Bytes::copy_from_slice(body)).await;
    }
    let _ = stream.finish().await;
    crate::http3::stream_util::halt_request_body(stream);
    Ok(CrossProtocolOutcome {
        response_status: status.as_u16(),
        bytes_streamed: len,
        bytes_sent,
        backend_target: None,
        backend_resolved_ip: None,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

/// Handle a `PluginResult::Reject` from `on_final_request_body` by
/// emitting the right wire format for the flavor: trailers-only gRPC for
/// Grpc, HTTP + headers for Plain, 501 is never reached (WebSocket is
/// rejected upstream).
async fn write_final_body_reject<S>(
    stream: &mut RequestStream<S, Bytes>,
    flavor: HttpFlavor,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let Some(parts) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("final body reject helper received a non-reject plugin result");
        return if matches!(flavor, HttpFlavor::Grpc) {
            write_grpc_error(
                stream,
                grpc_proxy::h3_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
                "Plugin rejection normalization failed",
                backend_start,
                bytes_sent,
            )
            .await
        } else {
            write_error(
                stream,
                StatusCode::BAD_GATEWAY,
                "{\"error\":\"Plugin rejection normalization failed\"}",
                backend_start,
                bytes_sent,
            )
            .await
        };
    };
    let http_status = StatusCode::from_u16(parts.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    let mut headers = parts.headers;
    crate::proxy::apply_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        http_status.as_u16(),
        &mut headers,
    )
    .await;
    if matches!(flavor, HttpFlavor::Grpc) {
        let normalized = normalize_h3_grpc_reject(http_status, &parts.body, &headers);
        apply_h3_grpc_reject_metadata(ctx, &normalized);
        write_normalized_grpc_reject(stream, &normalized, backend_start, bytes_sent).await
    } else {
        write_reject_with_headers(
            stream,
            http_status,
            &parts.body,
            &headers,
            backend_start,
            bytes_sent,
        )
        .await
    }
}

fn normalize_h3_grpc_reject(
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
) -> crate::proxy::NormalizedRejectResponse {
    crate::proxy::normalize_reject_response(status, body, headers, true)
}

fn apply_h3_grpc_reject_metadata(
    ctx: &mut RequestContext,
    reject: &crate::proxy::NormalizedRejectResponse,
) {
    if let Some(grpc_status) = reject.grpc_status {
        crate::proxy::insert_grpc_error_metadata(
            &mut ctx.metadata,
            grpc_status,
            reject.grpc_message.as_deref().unwrap_or(""),
        );
    }
}

async fn write_normalized_grpc_reject<S>(
    stream: &mut RequestStream<S, Bytes>,
    reject: &crate::proxy::NormalizedRejectResponse,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let outcome =
        write_normalized_grpc_reject_send(stream, reject, backend_start, bytes_sent).await?;
    // Full-stream caller: STOP_SENDING the recv half. The send-only streaming
    // path halts the recv half from its pump instead.
    crate::http3::stream_util::halt_request_body(stream);
    Ok(outcome)
}

/// Send-only core of [`write_normalized_grpc_reject`]: writes the trailers-only
/// gRPC reject and FINs the send half WITHOUT touching the recv half. Bounded
/// `S: SendStream<Bytes>` so it accepts both the full `RequestStream` and a
/// `split()` send half.
async fn write_normalized_grpc_reject_send<S>(
    stream: &mut RequestStream<S, Bytes>,
    reject: &crate::proxy::NormalizedRejectResponse,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    debug_assert!(
        reject.body.is_empty(),
        "normalized gRPC rejects should be trailers-only"
    );
    let mut resp_builder = Response::builder().status(reject.http_status);
    for (key, value) in &reject.headers {
        let sanitized_grpc_message;
        let header_value = if key.eq_ignore_ascii_case("grpc-message") {
            sanitized_grpc_message = sanitize_h3_grpc_message_for_header(value);
            if sanitized_grpc_message.is_empty() {
                continue;
            }
            sanitized_grpc_message.as_str()
        } else {
            value.as_str()
        };
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(header_value),
        ) {
            resp_builder = resp_builder.header(name, val);
        }
    }
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 gRPC reject response: {}", e))?;
    stream.send_response(resp).await?;
    let _ = stream.finish().await;
    Ok(CrossProtocolOutcome {
        response_status: reject.http_status.as_u16(),
        bytes_streamed: 0,
        bytes_sent,
        backend_target: None,
        backend_resolved_ip: None,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

/// Send-only gRPC variant of [`write_final_body_reject`]: normalize a plugin
/// reject (`after_proxy` on streaming gRPC response headers) into a
/// trailers-only gRPC error and write it on the send half WITHOUT halting the
/// recv half. Used by [`handle_h3_grpc_streaming_response`] so it works on both
/// the full `RequestStream` (buffered-request path) and a `split()` send half
/// (streaming-request path). gRPC-only because that helper is gRPC-only.
async fn write_final_grpc_body_reject_send<S>(
    stream: &mut RequestStream<S, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    let Some(parts) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("final body reject helper received a non-reject plugin result");
        return write_grpc_error_send(
            stream,
            grpc_proxy::h3_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
            "Plugin rejection normalization failed",
            backend_start,
            bytes_sent,
        )
        .await;
    };
    let http_status = StatusCode::from_u16(parts.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    let mut headers = parts.headers;
    crate::proxy::apply_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        http_status.as_u16(),
        &mut headers,
    )
    .await;
    let normalized = normalize_h3_grpc_reject(http_status, &parts.body, &headers);
    apply_h3_grpc_reject_metadata(ctx, &normalized);
    write_normalized_grpc_reject_send(stream, &normalized, backend_start, bytes_sent).await
}

/// Borrow the `content-type` value for body-transform plugin dispatch
/// without re-allocating.
fn content_type_of(headers: &HashMap<String, String>) -> Option<&str> {
    headers.get("content-type").map(|s| s.as_str())
}

/// Extract a plugin reject body into a gRPC-safe header value for the H3
/// test path. Reuses the shared H1/H2 JSON/body extraction logic, then
/// strips bytes `HeaderValue::from_str` rejects on this response path.
#[cfg(test)]
fn reject_body_as_h3_grpc_message(body: &[u8], status: StatusCode) -> String {
    crate::proxy::extract_grpc_reject_message(body)
        .map(|message| sanitize_h3_grpc_message_for_header(&message))
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| {
            sanitize_h3_grpc_message_for_header(
                status.canonical_reason().unwrap_or("Request rejected"),
            )
        })
}

/// Keep H3 `grpc-message` header values builder-safe by normalizing CR/LF
/// to spaces and dropping NUL bytes before trim. `HeaderValue::from_str`
/// accepts UTF-8 here, so we do not strip non-ASCII.
fn sanitize_h3_grpc_message_for_header(message: &str) -> String {
    let trimmed = message.trim();
    if !trimmed.contains(['\0', '\r', '\n']) {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .filter_map(|c| match c {
            '\r' | '\n' => Some(' '),
            '\0' => None,
            _ => Some(c),
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Write a trailers-only gRPC error response (HTTP 200 + grpc-status +
/// grpc-message as response headers, empty body). Used for
/// gRPC-flavor bridge failures so the client receives a valid gRPC error
/// instead of a raw HTTP error payload.
async fn write_grpc_error<S>(
    stream: &mut RequestStream<S, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let outcome =
        write_grpc_error_send(stream, grpc_status, grpc_message, backend_start, bytes_sent).await?;
    // Full-stream caller: STOP_SENDING the recv half so a bare drop is not seen
    // as RESET_STREAM(0x0). The send-only streaming-request path
    // (`dispatch_grpc_streaming`) calls `write_grpc_error_send` directly because
    // its spawned pump owns and halts the recv half.
    crate::http3::stream_util::halt_request_body(stream);
    Ok(outcome)
}

/// Send-only core of [`write_grpc_error`]: writes the trailers-only gRPC error
/// (HTTP 200 + `grpc-status` / `grpc-message`) and FINs the send half WITHOUT
/// touching the recv half. Bounded `S: SendStream<Bytes>` so it accepts both
/// the full `RequestStream` and a `split()` send half.
async fn write_grpc_error_send<S>(
    stream: &mut RequestStream<S, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    let grpc_message = sanitize_h3_grpc_message_for_header(grpc_message);
    let mut resp_builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", grpc_status.to_string());
    if !grpc_message.is_empty() {
        resp_builder = resp_builder.header("grpc-message", grpc_message.as_str());
    }
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 gRPC error response: {}", e))?;
    stream.send_response(resp).await?;
    let _ = stream.finish().await;
    Ok(CrossProtocolOutcome {
        response_status: 200,
        bytes_streamed: 0,
        bytes_sent,
        backend_target: None,
        backend_resolved_ip: None,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
}

/// Small helper duplicated from `proxy/mod.rs::parse_reqwest_method` to
/// keep this module self-contained without promoting the original to
/// `pub(crate)` (it's a hot-path leaf function that benefits from being
/// inlined inside its home module).
fn parse_reqwest_method(method: &str) -> Option<reqwest::Method> {
    match method {
        "GET" => Some(reqwest::Method::GET),
        "POST" => Some(reqwest::Method::POST),
        "PUT" => Some(reqwest::Method::PUT),
        "DELETE" => Some(reqwest::Method::DELETE),
        "PATCH" => Some(reqwest::Method::PATCH),
        "HEAD" => Some(reqwest::Method::HEAD),
        "OPTIONS" => Some(reqwest::Method::OPTIONS),
        other => reqwest::Method::from_bytes(other.as_bytes()).ok(),
    }
}

/// Headers the H3 cross-protocol bridge must never forward to non-H3
/// backends. This is the shared filter for both the plain and gRPC
/// bridge paths so the two cannot drift.
fn should_skip_cross_protocol_backend_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host"
            | "via"
            | "forwarded"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;

    use super::{
        apply_buffered_grpc_plugin_reject, apply_buffered_plain_plugin_reject,
        apply_h3_grpc_reject_metadata, build_plain_request_builder,
        cross_protocol_header_write_disconnect_outcome, inspected_emitted_response_limit_exceeded,
        normalize_h3_grpc_reject, record_cross_protocol_client_acquire_failure,
        record_cross_protocol_connection_start, reject_body_as_h3_grpc_message,
        release_cross_protocol_circuit_breaker_probe_on_admission_reject,
        sanitize_h3_grpc_message_for_header, should_finish_h3_stream_without_trailers,
        should_skip_cross_protocol_backend_header,
    };
    use crate::config::EnvConfig;
    use crate::config::types::{CircuitBreakerConfig, GatewayConfig, Proxy, UpstreamTarget};
    use crate::dns::{DnsCache, DnsConfig};
    use crate::plugins::{Plugin, PluginResult, RequestContext, security_headers::SecurityHeaders};
    use crate::proxy::ProxyState;
    use crate::retry::ErrorClass;
    use hyper::{HeaderMap, StatusCode};

    #[test]
    fn header_write_disconnect_outcome_marks_client_disconnect_without_backend_error() {
        let outcome = cross_protocol_header_write_disconnect_outcome(
            200,
            42,
            Instant::now(),
            Some("https://backend.example/path".to_string()),
            Some("192.0.2.10".to_string()),
        );

        assert_eq!(outcome.response_status, 200);
        assert_eq!(outcome.bytes_streamed, 0);
        assert_eq!(outcome.bytes_sent, 42);
        assert_eq!(
            outcome.backend_target.as_deref(),
            Some("https://backend.example/path")
        );
        assert_eq!(outcome.backend_resolved_ip.as_deref(), Some("192.0.2.10"));
        assert!(!outcome.body_completed);
        assert!(outcome.client_disconnected);
        assert!(!outcome.connection_error);
        assert_eq!(outcome.error_class, None);
        assert_eq!(outcome.body_error_class, Some(ErrorClass::ClientDisconnect));
    }

    #[test]
    fn cross_protocol_backend_header_filter_strips_hop_by_hop_and_forwarding_headers() {
        for name in [
            "connection",
            "content-length",
            "transfer-encoding",
            "keep-alive",
            "te",
            "trailer",
            "proxy-authorization",
            "proxy-connection",
            "upgrade",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "via",
            "forwarded",
        ] {
            assert!(
                should_skip_cross_protocol_backend_header(name),
                "{name} should be stripped"
            );
        }

        for name in [
            "content-type",
            "grpc-timeout",
            "grpc-encoding",
            "user-agent",
        ] {
            assert!(
                !should_skip_cross_protocol_backend_header(name),
                "{name} should be forwarded"
            );
        }
    }

    #[test]
    fn h3_grpc_message_sanitizer_strips_invalid_header_bytes() {
        assert_eq!(
            sanitize_h3_grpc_message_for_header("  bad\r\n\0message  "),
            "bad  message"
        );
    }

    #[test]
    fn h3_grpc_reject_body_message_is_header_safe() {
        let body = br#"{"message":"bad\r\n\u0000message"}"#;
        assert_eq!(
            reject_body_as_h3_grpc_message(body, StatusCode::BAD_REQUEST),
            "bad  message"
        );
    }

    #[test]
    fn empty_h3_trailers_finish_stream_like_absent_trailers() {
        let empty = HeaderMap::new();
        let mut non_empty = HeaderMap::new();
        non_empty.insert("grpc-status", "0".parse().unwrap());

        assert!(should_finish_h3_stream_without_trailers(None));
        assert!(should_finish_h3_stream_without_trailers(Some(&empty)));
        assert!(!should_finish_h3_stream_without_trailers(Some(&non_empty)));
    }

    #[test]
    fn inspected_emitted_response_limit_tracks_transformed_output() {
        assert!(!inspected_emitted_response_limit_exceeded(900, 200, 0));
        assert!(!inspected_emitted_response_limit_exceeded(900, 100, 1_000));
        assert!(inspected_emitted_response_limit_exceeded(900, 101, 1_000));
        assert!(inspected_emitted_response_limit_exceeded(
            u64::MAX - 1,
            10,
            1_024
        ));
    }

    #[tokio::test]
    async fn buffered_grpc_plugin_reject_normalizes_and_clears_backend_trailers() {
        let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/grpc.Service/Method".to_string(),
        );
        let mut response_status = 200;
        let mut response_headers =
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        let mut response_body = b"backend-body".to_vec();
        let mut response_trailers = HashMap::from([("grpc-status".to_string(), "0".to_string())]);

        apply_buffered_grpc_plugin_reject(
            &plugins,
            &mut ctx,
            PluginResult::Reject {
                status_code: 429,
                body: r#"{"error":"Rate limit exceeded"}"#.to_string(),
                headers: HashMap::from([("x-ratelimit-limit".to_string(), "5".to_string())]),
            },
            &mut response_status,
            &mut response_headers,
            &mut response_body,
            &mut response_trailers,
        )
        .await;

        assert_eq!(response_status, 200);
        assert!(response_body.is_empty());
        assert!(response_trailers.is_empty());
        assert_eq!(
            response_headers
                .get("content-type")
                .map(|value| value.as_str()),
            Some("application/grpc")
        );
        assert_eq!(
            response_headers
                .get("grpc-status")
                .map(|value| value.as_str()),
            Some("8")
        );
        assert_eq!(
            response_headers
                .get("grpc-message")
                .map(|value| value.as_str()),
            Some("Rate limit exceeded")
        );
        assert_eq!(
            response_headers
                .get("x-ratelimit-limit")
                .map(|value| value.as_str()),
            Some("5")
        );
        assert_eq!(
            ctx.metadata.get("grpc_status").map(|value| value.as_str()),
            Some("8")
        );
        assert_eq!(
            ctx.metadata.get("grpc_message").map(|value| value.as_str()),
            Some("Rate limit exceeded")
        );
    }

    #[tokio::test]
    async fn buffered_grpc_plugin_reject_runs_reject_aware_security_headers() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(
            SecurityHeaders::new(&serde_json::json!({})).unwrap(),
        )];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/grpc.Service/Method".to_string(),
        );
        let mut response_status = 200;
        let mut response_headers =
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        let mut response_body = b"backend-body".to_vec();
        let mut response_trailers = HashMap::from([("grpc-status".to_string(), "0".to_string())]);

        apply_buffered_grpc_plugin_reject(
            &plugins,
            &mut ctx,
            PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Forbidden"}"#.to_string(),
                headers: HashMap::new(),
            },
            &mut response_status,
            &mut response_headers,
            &mut response_body,
            &mut response_trailers,
        )
        .await;

        assert_eq!(response_status, 200);
        assert_eq!(
            response_headers
                .get("x-content-type-options")
                .map(|value| value.as_str()),
            Some("nosniff")
        );
        assert_eq!(
            response_headers
                .get("x-frame-options")
                .map(|value| value.as_str()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            response_headers
                .get("grpc-status")
                .map(|value| value.as_str()),
            Some("7")
        );
    }

    #[tokio::test]
    async fn buffered_plain_plugin_reject_runs_reject_aware_security_headers() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(
            SecurityHeaders::new(&serde_json::json!({})).unwrap(),
        )];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/plain".to_string(),
        );
        let mut response_status = 200;
        let mut response_headers =
            HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
        let mut response_body = b"backend-body".to_vec();

        apply_buffered_plain_plugin_reject(
            &plugins,
            &mut ctx,
            PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Forbidden"}"#.to_string(),
                headers: HashMap::new(),
            },
            &mut response_status,
            &mut response_headers,
            &mut response_body,
        )
        .await;

        assert_eq!(response_status, 403);
        assert_eq!(response_body, br#"{"error":"Forbidden"}"#);
        assert_eq!(
            response_headers
                .get("content-type")
                .map(|value| value.as_str()),
            Some("application/json")
        );
        assert_eq!(
            response_headers
                .get("x-content-type-options")
                .map(|value| value.as_str()),
            Some("nosniff")
        );
        assert_eq!(
            response_headers
                .get("x-frame-options")
                .map(|value| value.as_str()),
            Some("SAMEORIGIN")
        );
    }

    /// Regression test for the cross-protocol `select!` race: when the
    /// backend resolves before the request-body reader finishes, the
    /// reader must be notified (not dropped mid-stream). This mirrors
    /// the `halt_notify` + drain + timeout loop in `dispatch_plain`.
    #[tokio::test(flavor = "current_thread")]
    async fn backend_early_response_notifies_reader_instead_of_dropping_it() {
        use std::pin::pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tokio::sync::Notify;

        let halt_notify = Arc::new(Notify::new());
        let reader_halted = Arc::new(AtomicBool::new(false));

        let reader_halt = Arc::clone(&halt_notify);
        let reader_flag = Arc::clone(&reader_halted);
        let reader_future = async move {
            tokio::select! {
                biased;
                _ = reader_halt.notified() => {
                    reader_flag.store(true, Ordering::Release);
                }
                () = std::future::pending::<()>() => {}
            }
        };

        // Simulates `send_future` completing first (backend responded
        // while the client was still uploading). Kept at 1 ms so the
        // reader_future loses the race deterministically on the same
        // runtime without needing `tokio::test(start_paused)`.
        let send_future = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            "ok"
        };

        let drain_ms = 5_u64;
        let result: &str = {
            let mut send_future = pin!(send_future);
            let mut reader_future = pin!(reader_future);
            let mut reader_done = false;
            loop {
                tokio::select! {
                    result = &mut send_future => {
                        if !reader_done {
                            if drain_ms > 0 {
                                let drain_deadline = Duration::from_millis(drain_ms);
                                if let Ok(()) = tokio::time::timeout(
                                    drain_deadline,
                                    &mut reader_future,
                                ).await {
                                    reader_done = true;
                                }
                            }
                            if !reader_done {
                                halt_notify.notify_one();
                                let halt_deadline = Duration::from_millis(100);
                                let _ = tokio::time::timeout(
                                    halt_deadline,
                                    &mut reader_future,
                                ).await;
                            }
                        }
                        break result;
                    }
                    _ = &mut reader_future, if !reader_done => {
                        reader_done = true;
                    }
                }
            }
        };

        assert_eq!(result, "ok");
        assert!(
            reader_halted.load(Ordering::Acquire),
            "reader must be notified and halted when backend wins the race"
        );
    }

    /// Regression test for the backpressure-parked reader: even when
    /// the reader is wedged inside an uncancellable region (modelling
    /// `tx.send().await` blocking on a full mpsc channel after reqwest
    /// stopped draining once the backend response arrived), the
    /// bridge must still call `halt_request_body` after dropping the
    /// reader future. Without the post-bridge halt the recv half
    /// surfaces as RESET_STREAM(0x0) on the QUIC wire — the exact
    /// failure mode this PR removes from the early-response paths.
    ///
    /// Real time (no `start_paused`) — the dev-dependency tokio is
    /// pinned without `test-util`. Drain + halt deadlines are kept
    /// short (10 ms each) so the test runs in well under 100 ms while
    /// still giving the reader_future a deterministic chance to
    /// stay wedged.
    #[tokio::test(flavor = "current_thread")]
    async fn parked_reader_still_halts_after_reader_future_dropped() {
        use std::pin::pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        // 1 s sleep with no halt-observing branch — guaranteed to
        // outlast the 10 + 10 ms drain + halt deadlines and not
        // short-circuit on halt_notify. This is what a `tx.send()`
        // parked on a full mpsc channel looks like to the bridge:
        // an opaque, uncancellable await.
        let reader_future = async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        let send_future = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok::<&'static str, &'static str>("ok")
        };

        let post_bridge_halted = Arc::new(AtomicBool::new(false));
        let post_bridge_halted_clone = Arc::clone(&post_bridge_halted);
        let halt_notify = Arc::new(tokio::sync::Notify::new());
        let drain_ms = 10_u64;
        let halt_deadline_ms = 10_u64;
        let result = {
            let mut send_future = pin!(send_future);
            let mut reader_future = pin!(reader_future);
            let mut reader_done = false;
            let outcome = loop {
                tokio::select! {
                    result = &mut send_future => {
                        if !reader_done {
                            let backend_succeeded = result.is_ok();
                            if backend_succeeded && drain_ms > 0 {
                                let drain_deadline = Duration::from_millis(drain_ms);
                                if let Ok(()) = tokio::time::timeout(
                                    drain_deadline,
                                    &mut reader_future,
                                ).await {
                                    reader_done = true;
                                }
                            }
                            if !reader_done {
                                halt_notify.notify_one();
                                let halt_deadline = Duration::from_millis(halt_deadline_ms);
                                let _ = tokio::time::timeout(
                                    halt_deadline,
                                    &mut reader_future,
                                ).await;
                            }
                        }
                        break result;
                    }
                    _ = &mut reader_future, if !reader_done => {
                        reader_done = true;
                    }
                }
            };
            // Models the post-bridge `halt_request_body(stream)` call.
            // Reachable only after the pinned reader_future is dropped
            // — i.e. after stream's mutable borrow is released.
            post_bridge_halted_clone.store(true, Ordering::Release);
            outcome
        };

        assert_eq!(result, Ok("ok"));
        assert!(
            post_bridge_halted.load(Ordering::Acquire),
            "halt_request_body must run after the reader future is dropped, \
             even when the reader was wedged in an uncancellable region"
        );
    }

    /// Regression test for the doc promise that error responses halt
    /// immediately. When `send_future` returns Err, the bridge must
    /// skip the FERRUM_H3_REQUEST_BODY_DRAIN_MS courtesy window and
    /// notify halt right away — otherwise backend transport failures
    /// pay up to the configured drain budget in extra latency before
    /// the 502 is written. The witness flag captures whether the
    /// drain branch ran; timing is intentionally not asserted because
    /// the dev-dependency tokio omits `test-util` and real time would
    /// make the comparison flaky.
    #[tokio::test(flavor = "current_thread")]
    async fn backend_error_skips_drain_window() {
        use std::pin::pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tokio::sync::Notify;

        let halt_notify = Arc::new(Notify::new());
        let drain_was_applied = Arc::new(AtomicBool::new(false));

        // Reader that responds to halt_notify promptly so the halt
        // deadline can resolve cleanly inside the test.
        let reader_halt = Arc::clone(&halt_notify);
        let reader_future = async move {
            reader_halt.notified().await;
        };

        // send_future immediately returns an Err — backend transport
        // failure case (BAD_GATEWAY).
        let send_future = async { Err::<&'static str, &'static str>("backend down") };

        // Use a generous drain budget so we'd notice if it ran.
        let drain_ms = 500_u64;
        let drain_witness = Arc::clone(&drain_was_applied);
        let result = {
            let mut send_future = pin!(send_future);
            let mut reader_future = pin!(reader_future);
            let mut reader_done = false;
            loop {
                tokio::select! {
                    result = &mut send_future => {
                        if !reader_done {
                            let backend_succeeded = result.is_ok();
                            if backend_succeeded && drain_ms > 0 {
                                drain_witness.store(true, Ordering::Release);
                                let drain_deadline = Duration::from_millis(drain_ms);
                                if let Ok(()) = tokio::time::timeout(
                                    drain_deadline,
                                    &mut reader_future,
                                ).await {
                                    reader_done = true;
                                }
                            }
                            if !reader_done {
                                halt_notify.notify_one();
                                let halt_deadline = Duration::from_millis(50);
                                let _ = tokio::time::timeout(
                                    halt_deadline,
                                    &mut reader_future,
                                ).await;
                            }
                        }
                        break result;
                    }
                    _ = &mut reader_future, if !reader_done => {
                        reader_done = true;
                    }
                }
            }
        };

        assert_eq!(result, Err("backend down"));
        assert!(
            !drain_was_applied.load(Ordering::Acquire),
            "drain window must be skipped when backend returns Err"
        );
    }

    #[test]
    fn h3_grpc_reject_normalization_preserves_custom_headers_and_metadata() {
        let normalized = normalize_h3_grpc_reject(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"error":"Rate limit exceeded"}"#,
            &HashMap::from([("x-ratelimit-limit".to_string(), "5".to_string())]),
        );
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/grpc.Service/Method".to_string(),
        );

        apply_h3_grpc_reject_metadata(&mut ctx, &normalized);

        assert_eq!(normalized.http_status, StatusCode::OK);
        assert!(normalized.body.is_empty());
        assert_eq!(
            normalized
                .headers
                .get("content-type")
                .map(|value| value.as_str()),
            Some("application/grpc")
        );
        assert_eq!(
            normalized
                .headers
                .get("grpc-status")
                .map(|value| value.as_str()),
            Some("8")
        );
        assert_eq!(
            normalized
                .headers
                .get("grpc-message")
                .map(|value| value.as_str()),
            Some("Rate limit exceeded")
        );
        assert_eq!(
            normalized
                .headers
                .get("x-ratelimit-limit")
                .map(|value| value.as_str()),
            Some("5")
        );
        assert_eq!(
            ctx.metadata.get("grpc_status").map(|value| value.as_str()),
            Some("8")
        );
        assert_eq!(
            ctx.metadata.get("grpc_message").map(|value| value.as_str()),
            Some("Rate limit exceeded")
        );
    }

    /// Regression guard: the H3 cross-protocol gRPC dispatch must compute
    /// the streaming-response decision independently of `grpc_has_retry`.
    ///
    /// Background (mirrors PR #497 on the H1/H2 path): the cross-protocol
    /// retry loop only re-fires on CONNECTION errors that surface BEFORE
    /// any response headers (`BackendUnavailable` /
    /// `BackendTimeout::Connect`). Once a response begins flowing the
    /// loop breaks out and never inspects the body, so the streaming-or-
    /// not choice for the response has no bearing on whether the request
    /// can be retried. The OLD pattern coupled the two:
    ///
    /// ```ignore
    /// let stream_grpc_response = !grpc_has_retry
    ///     && crate::proxy::should_stream_response_body(...);
    /// ```
    ///
    /// which silently downgraded server-streaming / bidi gRPC responses
    /// to fully buffered — the same trailer-stall PR #497 fixed on the
    /// H1/H2 path.
    #[test]
    fn h3_cross_protocol_grpc_stream_decision_does_not_gate_on_retry() {
        let src = include_str!("cross_protocol.rs");
        let assignment_marker = "let stream_grpc_response =";
        let assignment_idx = src
            .find(assignment_marker)
            .expect("assignment of stream_grpc_response not found");
        let tail = &src[assignment_idx..];
        let assignment_end = tail
            .find(";\n")
            .expect("end of stream_grpc_response assignment not found");
        let assignment = &tail[..assignment_end];

        assert!(
            !assignment.contains("!grpc_has_retry"),
            "regression: `stream_grpc_response` is gated on `!grpc_has_retry`. \
             Drop the gate — retry replay only needs the request body \
             preserved (which `body_bytes` already is), not the response \
             buffered. Offending assignment:\n{}",
            assignment
        );
    }

    /// Regression guard: the H3 cross-protocol gRPC retry loop must
    /// propagate the original streaming-response decision into each
    /// retry attempt.
    ///
    /// Same rationale as the H1/H2-path guard added in PR #497 (commit
    /// d09e776): hard-coding `false` on retry reintroduces the trailer
    /// stall on the very first transient connection error, since the
    /// successful retry response would then be fully buffered before any
    /// frame reaches the H3 client.
    #[test]
    fn h3_cross_protocol_grpc_retry_passes_streaming_decision_through() {
        let src = include_str!("cross_protocol.rs");
        let loop_start_marker =
            "&& let (Some(hmap), Some(body_bytes)) = (retry_hmap, retry_body)\n    {";
        let loop_start = src
            .find(loop_start_marker)
            .expect("cross-protocol gRPC retry loop start not found");
        let tail = &src[loop_start..];

        // Retry-call marker — the second `proxy_grpc_request_from_bytes(`
        // call lives inside the retry loop. We scope the search to the
        // loop body to be unambiguous.
        let call_marker = "proxy_grpc_request_from_bytes(";
        let call_idx = tail
            .find(call_marker)
            .expect("retry-loop call to proxy_grpc_request_from_bytes not found");
        let call_tail = &tail[call_idx..];
        let call_end = call_tail
            .find(")\n            .await")
            .expect("end of retry-loop call not found");
        let call_args = &call_tail[..call_end];

        for (i, line) in call_args.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            assert!(
                trimmed != "false," && trimmed != "false",
                "regression at relative line {} of H3 cross-protocol gRPC \
                 retry call: `proxy_grpc_request_from_bytes` is invoked \
                 with a hard-coded `false` streaming flag. Pass \
                 `stream_grpc_response` instead so successful retries \
                 keep the trailer-stall fix active. Offending line:\n  {}",
                i + 1,
                line
            );
        }
        assert!(
            call_args.contains("stream_grpc_response"),
            "expected `stream_grpc_response` to be threaded into the H3 \
             cross-protocol retry call; argument list was:\n{}",
            call_args
        );
    }

    // -----------------------------------------------------------------
    // RFC 8470 §5.2 `Early-Data: 1` injection on the H3→non-H3 plain
    // bridge (`build_plain_request_builder`). Tests cover:
    //   - injection when ctx.is_early_data == true
    //   - no injection when ctx.is_early_data == false
    //   - client-supplied Early-Data header is always stripped
    //
    // The gRPC bridge uses an inline `HeaderMap` rather than a shared
    // builder, so its injection is exercised end-to-end via the
    // integration / functional test suite alongside the rest of the
    // gRPC dispatch path.
    // -----------------------------------------------------------------

    fn minimal_proxy_state() -> ProxyState {
        let dns_cache = DnsCache::new(DnsConfig::default());
        let config = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![],
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            loaded_at: chrono::Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
        };
        ProxyState::new(config, dns_cache, EnvConfig::default(), None, None)
            .expect("minimal ProxyState should construct")
            .0
    }

    fn minimal_proxy() -> Proxy {
        serde_json::from_value(serde_json::json!({
            "backend_host": "backend.example",
            "backend_port": 443,
        }))
        .expect("minimal proxy should deserialize")
    }

    fn test_circuit_breaker_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 1,
            trip_on_connection_errors: true,
        }
    }

    #[tokio::test]
    async fn client_fault_release_frees_half_open_probe_slot() {
        let state = minimal_proxy_state();
        let mut proxy = minimal_proxy();
        proxy.id = "h3-grpc-proxy".to_string();
        let config = test_circuit_breaker_config();
        proxy.circuit_breaker = Some(config.clone());
        let target_key = Some("backend.example:443");
        let cb = state
            .circuit_breaker_cache
            .get_or_create(&proxy.id, target_key, &config);

        cb.record_failure(500, false, false);
        assert_eq!(cb.state_name(), "open");

        let (_, is_half_open_probe) = state
            .circuit_breaker_cache
            .can_execute(&proxy.id, target_key, &config)
            .expect("half-open probe should be admitted");
        assert!(is_half_open_probe);
        assert_eq!(cb.half_open_in_flight(), 1);
        assert!(
            state
                .circuit_breaker_cache
                .can_execute(&proxy.id, target_key, &config)
                .is_err(),
            "single probe slot should be occupied before neutral release"
        );

        release_cross_protocol_circuit_breaker_probe_on_admission_reject(
            &state,
            &proxy,
            target_key,
            is_half_open_probe,
        );

        assert_eq!(cb.half_open_in_flight(), 0);
        assert_eq!(cb.state_name(), "half_open");
        assert!(
            state
                .circuit_breaker_cache
                .can_execute(&proxy.id, target_key, &config)
                .is_ok(),
            "neutral client-fault release must allow the next half-open probe"
        );
    }

    fn target_for_test(port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: "backend.example".to_string(),
            port,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }
    }

    /// #1806 codex r2 finding 1: both H3→HTTP plain-bridge callers run backend
    /// admission AND `record_cross_protocol_connection_start` for the selected
    /// target BEFORE acquiring the reqwest client. A client-build/pool failure
    /// must therefore END the least-connections connection (balancing the start —
    /// no active-count leak) AND feed the 502 connection failure to the backend
    /// outcome path. Previously this path used `record_backend_outcome_no_conn_end`
    /// and skipped the admission outcome, permanently inflating the target's
    /// active-connection count and never feeding the 502 to adaptive concurrency.
    #[tokio::test]
    async fn client_acquire_failure_balances_connection_start_and_records_outcome() {
        let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "version": "1",
            "consumers": [],
            "plugin_configs": [],
            "proxies": [{
                "id": "lc-proxy",
                "listen_path": "/",
                "backend_scheme": "http",
                "backend_host": "unused.local",
                "backend_port": 0,
                "upstream_id": "lc-upstream"
            }],
            "upstreams": [{
                "id": "lc-upstream",
                "targets": [{"host": "10.0.0.1", "port": 8080}],
                "algorithm": "least_connections"
            }]
        }))
        .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = DnsCache::new(DnsConfig::default());
        let (state, _) = ProxyState::new(config, dns_cache, EnvConfig::default(), None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];

        let selection = crate::proxy::backend_dispatch::select_upstream_target(
            proxy,
            &state,
            &epoch,
            "192.0.2.10",
            &HashMap::new(),
            None,
        );
        let balancer = selection
            .balancer
            .clone()
            .expect("least-connections upstream proxy should resolve a balancer");
        let target = selection
            .target
            .clone()
            .expect("a target should be selected");

        let active = || {
            balancer
                .active_connections
                .iter()
                .map(|entry| entry.value().load(std::sync::atomic::Ordering::Relaxed))
                .sum::<i64>()
        };

        // The caller issues the connection-start before the client acquire.
        record_cross_protocol_connection_start(Some(&balancer), Some(target.as_ref()));
        assert_eq!(active(), 1, "connection-start increments the gauge");

        // No admission permits in this minimal setup, but the outcome path must
        // still balance the connection-start (conn_end = true).
        let mut permits = None;
        record_cross_protocol_client_acquire_failure(
            &state,
            proxy,
            &epoch,
            Some(&balancer),
            Some(target.as_ref()),
            None,
            false,
            Instant::now(),
            &mut permits,
            std::time::Duration::ZERO,
        );

        assert_eq!(
            active(),
            0,
            "client-acquire failure must END the connection to balance the start (no active-count leak)"
        );
    }

    /// #1806: the H3→HTTP plain bridge resolves the per-target effective proxy
    /// (the same `resolve_effective_proxy_for_target` the H1/H2 plain path uses)
    /// before building its reqwest client and request, so every
    /// `connectionPool.http` DR override applies on the bridge. This asserts the
    /// resolution `dispatch_plain` performs at entry: a per-port override wins
    /// for its port; a port with no explicit entry picks up the
    /// service-discovery top-level fallback.
    #[test]
    fn h3_plain_bridge_resolves_effective_proxy_for_selected_target() {
        let mut proxy = minimal_proxy();
        proxy.backend_connect_timeout_ms = 5_000;
        proxy.upstream_id = Some("u1".to_string());
        proxy.dispatch_port_overrides = Some(HashMap::from([(
            8080u16,
            crate::config::types::ResolvedPortOverride {
                connect_timeout_ms: Some(750),
                h2_max_concurrent_streams: Some(32),
                ..Default::default()
            },
        )]));
        proxy.dispatch_port_override_fallback = Some(crate::config::types::ResolvedPortOverride {
            connect_timeout_ms: Some(1_500),
            ..Default::default()
        });

        // Selected port 8080 → explicit per-port override applied.
        let target = target_for_test(8080);
        let effective = crate::proxy::resolve_effective_proxy_for_target(&proxy, Some(&target));
        assert_eq!(
            effective.backend_connect_timeout_ms, 750,
            "the bridge must apply the per-port connectTimeout that build_plain_request_builder reads"
        );
        assert_eq!(effective.pool_http2_max_concurrent_streams, Some(32));

        // A port with no explicit entry → service-discovery top-level fallback.
        let sd_target = target_for_test(9090);
        let effective_sd =
            crate::proxy::resolve_effective_proxy_for_target(&proxy, Some(&sd_target));
        assert_eq!(
            effective_sd.backend_connect_timeout_ms, 1_500,
            "the bridge must apply the SD top-level fallback on a runtime-resolved port"
        );
    }

    /// Count occurrences of a header (lowercase compare) in a built
    /// reqwest `Request`. reqwest header names are already lowercased
    /// by the http crate.
    fn count_header(req: &reqwest::Request, name: &str) -> usize {
        req.headers()
            .iter()
            .filter(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .count()
    }

    fn header_value<'a>(req: &'a reqwest::Request, name: &str) -> Option<&'a [u8]> {
        req.headers()
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_bytes())
    }

    #[tokio::test]
    async fn build_plain_request_builder_injects_early_data_header_when_zero_rtt() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("user-agent".to_string(), "test-client".to_string());

        let builder = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            /* is_early_data = */ true,
        );

        let req = builder.build().expect("request should build");
        assert_eq!(
            header_value(&req, "early-data"),
            Some(&b"1"[..]),
            "RFC 8470 §5.2: Early-Data: 1 must be injected when ctx.is_early_data is true"
        );
        assert_eq!(
            count_header(&req, "early-data"),
            1,
            "exactly one Early-Data header expected"
        );
    }

    #[tokio::test]
    async fn build_plain_request_builder_does_not_inject_early_data_header_for_normal_request() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("user-agent".to_string(), "test-client".to_string());

        let builder = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            /* is_early_data = */ false,
        );

        let req = builder.build().expect("request should build");
        assert_eq!(
            count_header(&req, "early-data"),
            0,
            "Early-Data must NOT be injected when the request is not 0-RTT"
        );
    }

    #[tokio::test]
    async fn build_plain_request_builder_strips_client_supplied_early_data_when_zero_rtt() {
        // RFC 8470 §5.2: clients never set Early-Data; only intermediaries
        // do. The gateway must strip and re-inject so the value is
        // authoritative regardless of what the client sent.
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("early-data".to_string(), "0".to_string());

        let builder = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            /* is_early_data = */ true,
        );

        let req = builder.build().expect("request should build");
        assert_eq!(
            count_header(&req, "early-data"),
            1,
            "client-supplied Early-Data must not duplicate or survive — \
             expected exactly one Early-Data: 1 from the gateway"
        );
        assert_eq!(
            header_value(&req, "early-data"),
            Some(&b"1"[..]),
            "client's `0` must be replaced with the gateway's `1`"
        );
    }

    #[tokio::test]
    async fn build_plain_request_builder_strips_client_supplied_early_data_when_not_zero_rtt() {
        // Even when is_early_data is false, the gateway must strip a
        // client-supplied Early-Data header. A bogus client cannot
        // trick the backend into believing the request was 0-RTT.
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("early-data".to_string(), "1".to_string());

        let builder = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            /* is_early_data = */ false,
        );

        let req = builder.build().expect("request should build");
        assert_eq!(
            count_header(&req, "early-data"),
            0,
            "client-supplied Early-Data must be stripped, and no value \
             injected when is_early_data == false"
        );
    }

    /// H1/H2/H3 XFF parity on the cross-protocol bridge: append the
    /// immediate QUIC peer to an existing inbound chain, and seed a
    /// generated chain with the resolved client when it differs from the
    /// peer (real-IP-header deployments). See `proxy::build_xff_value`.
    #[tokio::test]
    async fn build_plain_request_builder_xff_appends_peer_and_seeds_resolved_client() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();

        // Trusted LB sent XFF: append the peer, never the resolved client.
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());
        let req = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "198.51.100.7", // resolved client (already in the chain)
            "10.0.0.7",     // immediate QUIC peer (the LB)
            false,
        )
        .build()
        .expect("request should build");
        assert_eq!(
            header_value(&req, "x-forwarded-for"),
            Some(&b"198.51.100.7, 10.0.0.7"[..]),
            "inbound chain + appended QUIC peer; resolved client must not duplicate"
        );

        // Trusted LB sent only a real-IP header (no XFF): seed with the
        // resolved client, then the peer.
        let headers: HashMap<String, String> = HashMap::new();
        let req = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.9", // resolved from FERRUM_REAL_IP_HEADER
            "10.0.0.7",    // immediate QUIC peer (the LB)
            false,
        )
        .build()
        .expect("request should build");
        assert_eq!(
            header_value(&req, "x-forwarded-for"),
            Some(&b"203.0.113.9, 10.0.0.7"[..]),
            "generated chain must carry the resolved real client before the peer"
        );

        // Direct client (no proxy in front): client == peer, single entry.
        let req = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            false,
        )
        .build()
        .expect("request should build");
        assert_eq!(
            header_value(&req, "x-forwarded-for"),
            Some(&b"203.0.113.1"[..]),
            "direct connections must not duplicate the peer"
        );
    }

    #[test]
    fn h3_cross_protocol_grpc_initial_dispatch_does_not_clone_without_retry() {
        let src = include_str!("cross_protocol.rs");
        assert!(
            src.contains(
                "let (initial_hmap, initial_body, retry_hmap, retry_body) = if grpc_has_retry"
            ),
            "retry replay buffers must be split from the initial dispatch inputs"
        );
        assert!(
            src.contains(
                "proxy_grpc_request_from_bytes(\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20hyper_method.clone(),\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20initial_hmap,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20initial_body,"
            ),
            "initial gRPC dispatch must move the prepared headers/body instead of cloning them"
        );
        let forbidden_retry_hmap = ["retry_hmap", ".expect("].concat();
        let forbidden_retry_body = ["retry_body", ".expect("].concat();
        assert!(
            !src.contains(&forbidden_retry_hmap) && !src.contains(&forbidden_retry_body),
            "H3 gRPC retry replay buffers must not use panic-based extraction"
        );
    }

    /// Regression guard: the streaming-request gRPC bridge must forward the H3
    /// request body to the backend via the channel-backed streaming entry
    /// (`proxy_grpc_request_streaming_channel`) over a `split()` send/recv pair
    /// — NOT buffer it first via `drain_h3_body`. Request buffering is exactly
    /// the gap this path closes: client-streaming / bidi RPCs need the request
    /// DATA to reach the backend before the client half-closes.
    #[test]
    fn h3_grpc_streaming_dispatch_uses_channel_not_drain() {
        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("pub(crate) async fn dispatch_grpc_streaming")
            .expect("dispatch_grpc_streaming not found");
        let tail = &src[start..];
        // Bound the search to the function body (up to the next free fn).
        let end = tail
            .find("\nasync fn apply_buffered_plain_plugin_reject")
            .expect("end of dispatch_grpc_streaming not found");
        let body = &tail[..end];

        assert!(
            body.contains("proxy_grpc_request_streaming_channel("),
            "dispatch_grpc_streaming must dispatch via the channel-backed streaming entry"
        );
        assert!(
            body.contains("stream.split()"),
            "dispatch_grpc_streaming must split the QUIC stream for concurrent upload + response"
        );
        assert!(
            !body.contains("drain_h3_body"),
            "regression: dispatch_grpc_streaming must NOT buffer the request via drain_h3_body — \
             that reintroduces the client-streaming/bidi stall this path fixes"
        );
        assert!(
            !body.contains("proxy_grpc_request_from_bytes"),
            "regression: the streaming path must not fall back to the buffered-bytes dispatch"
        );
    }

    /// Regression guard: the H3 server must route streaming-safe gRPC requests
    /// (gRPC flavor + `can_stream_request_body`) to the streaming-request bridge
    /// rather than the buffering `cross_protocol::run`. `can_stream_request_body`
    /// already excludes retry / request-body plugins / response buffering / a
    /// pre-buffered body, so this gate is exactly the streaming-safe set.
    #[test]
    fn h3_server_routes_streaming_safe_grpc_to_streaming_dispatch() {
        let src = include_str!("server.rs");
        assert!(
            src.contains("if matches!(http_flavor, HttpFlavor::Grpc) && can_stream_request_body"),
            "H3 server must gate the streaming gRPC bridge on flavor + can_stream_request_body"
        );
        assert!(
            src.contains("cross_protocol::dispatch_grpc_streaming("),
            "H3 server must dispatch streaming-safe gRPC through dispatch_grpc_streaming"
        );
    }
}
