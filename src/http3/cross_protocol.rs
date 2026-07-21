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
//! - **Error responses are flavor-aware.** Ordinary Plain failures emit HTTP
//!   error payloads (502 JSON, 413 JSON, etc.). Recognized gRPC-Web requests
//!   that intentionally retain Plain backend transport still receive a
//!   browser-safe trailer frame. Native gRPC failures emit trailers-only gRPC
//!   responses (HTTP 200 + `grpc-status` + `grpc-message` in the header block)
//!   so clients see `UNAVAILABLE`/`RESOURCE_EXHAUSTED`/`INVALID_ARGUMENT`/
//!   `UNIMPLEMENTED` rather than a transport error.
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
    normalize_response_body_for_inspection,
};
use crate::proxy::ProxyState;
use crate::proxy::backend_dispatch::{record_backend_outcome, record_backend_outcome_no_conn_end};
use crate::proxy::grpc_proxy::{
    self, GATEWAY_DEADLINE_EXCEEDED_MESSAGE, GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
    GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER, GrpcResponseKind, proxy_grpc_request_from_bytes,
};
use crate::proxy::headers::{
    apply_response_headers, has_client_response_hop_by_hop_headers,
    is_backend_response_strip_header, parse_connection_listed_headers,
    strip_client_response_hop_by_hop_headers, strip_response_hop_by_hop_trailers,
};
use crate::request_epoch::RequestEpoch;
use crate::retry::ErrorClass;

/// Outcome reported back to the H3 listener so it can update request
/// counters, build the `TransactionSummary` for log plugins, and record
/// whether the client disconnected mid-stream.
pub struct CrossProtocolOutcome {
    pub response_status: u16,
    pub response_streamed: bool,
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
    /// The bridge already emitted the finalized rejection transaction through
    /// `log_rejected_request`; the H3 frontend must not emit a duplicate generic
    /// transaction summary for the same request.
    pub rejection_logged: bool,
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
    pub strip_len: usize,
    pub backend_path_is_policy_bound: bool,
    pub lb_hash_key: Option<&'a str>,
    pub upstream_target: Option<&'a UpstreamTarget>,
    pub upstream_balancer: Option<&'a Arc<LoadBalancer>>,
    pub cb_target_key: Option<&'a str>,
    pub cb_is_half_open_probe: bool,
    pub flavor: HttpFlavor,
    pub prebuffered_body: Option<Vec<u8>>,
    /// The request body was already transformed and passed through final-body
    /// hooks before transport selection in the H3 frontend.
    pub request_body_prepared: bool,
    /// Original client-visible byte count when `request_body_prepared` is true.
    pub raw_prebuffered_body_bytes: Option<u64>,
    pub client_ip: &'a str,
    /// Immediate QUIC peer address — appended to X-Forwarded-For so the H3
    /// bridge matches the H1/H2 peer-append semantics (`build_xff_value`).
    pub xff_append_ip: &'a str,
    pub ctx: &'a mut RequestContext,
    pub plugins: &'a [Arc<dyn Plugin>],
    pub initial_response_header_policy_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    pub initial_response_header_policy_names: Arc<Vec<String>>,
    pub backend_admission_plugins: &'a [Arc<dyn Plugin>],
    pub preacquired_backend_admission: crate::proxy::PreacquiredBackendAdmission,
    pub requires_response_body_buffering: bool,
    pub response_committed_plugins: &'a [Arc<dyn Plugin>],
    pub requires_response_stream_hooks: bool,
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
    response_streamed: bool,
    bytes_sent: u64,
    backend_start: Instant,
    backend_target: Option<String>,
    backend_resolved_ip: Option<String>,
) -> CrossProtocolOutcome {
    // `response_streamed` describes the selected response path, not whether any
    // body bytes reached the client. A disconnect before response HEADERS on a
    // streaming path still needs streamed-response terminal hooks to run.
    CrossProtocolOutcome {
        response_status,
        response_streamed,
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
        rejection_logged: false,
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
            let mut rejection = rejection;
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
            crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
                plugins,
                ctx,
                &mut rejection.status_code,
                &mut rejection.body,
                &mut headers,
            )
            .await;
            let http_status = StatusCode::from_u16(rejection.status_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            let (mut normalized, mut translated) = normalize_reject_for_client(
                ctx,
                http_status,
                &rejection.body,
                &headers,
                matches!(flavor, HttpFlavor::Grpc),
            );
            run_cross_protocol_reject_committed_hooks(
                plugins,
                ctx,
                matches!(flavor, HttpFlavor::Grpc),
                &mut normalized,
                &mut translated,
            )
            .await;
            let mut outcome = if let Some(translated) = translated {
                write_reject_with_headers(
                    stream,
                    StatusCode::OK,
                    &translated.body,
                    &translated.headers,
                    backend_start,
                    bytes_sent,
                )
                .await?
            } else if matches!(flavor, HttpFlavor::Grpc) {
                write_normalized_grpc_reject(stream, &normalized, backend_start, bytes_sent).await?
            } else {
                write_reject_with_headers(
                    stream,
                    normalized.http_status,
                    &normalized.body,
                    &normalized.headers,
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

enum CrossProtocolRetryTarget {
    Unchanged,
    Selected(Arc<UpstreamTarget>, String, String),
    BackendPathMismatch,
}

#[allow(clippy::too_many_arguments)]
fn select_next_cross_protocol_retry_target(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    lb_hash_key: Option<&str>,
    current_target: Option<&Arc<UpstreamTarget>>,
    strip_len: usize,
    backend_path_is_policy_bound: bool,
    path: &str,
    query_string: &str,
    client_ip: &str,
    proxy_headers: &HashMap<String, String>,
) -> CrossProtocolRetryTarget {
    let (Some(prev_target), Some(hash_key)) = (current_target, lb_hash_key) else {
        return CrossProtocolRetryTarget::Unchanged;
    };

    // Centralised in `backend_dispatch::select_next_retry_target` —
    // see that helper for the per-port `hash_on` recomputation contract
    // shared with the HTTP/H2/gRPC/WS retry sites.
    let Some(next) = crate::proxy::backend_dispatch::select_next_retry_target(
        state,
        epoch,
        proxy,
        prev_target,
        hash_key,
        client_ip,
        proxy_headers,
    ) else {
        return CrossProtocolRetryTarget::Unchanged;
    };

    if !crate::proxy::retry_target_preserves_backend_path(
        backend_path_is_policy_bound,
        proxy,
        path,
        strip_len,
        prev_target,
        &next,
    ) {
        warn!(
            proxy_id = %proxy.id,
            "Aborting cross-protocol retry because the candidate would change the authorized backend method path"
        );
        return CrossProtocolRetryTarget::BackendPathMismatch;
    }

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
    CrossProtocolRetryTarget::Selected(next, next_cb_target_key, next_url)
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
/// `on_final_response_body` / `on_response_committed`) on plain and gRPC
/// responses when buffering is active. Without these, H3 clients on non-H3
/// backends would silently skip body validators, response transformers,
/// exporters, sticky sessions, etc.
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
        strip_len,
        backend_path_is_policy_bound,
        lb_hash_key,
        upstream_target,
        upstream_balancer,
        cb_target_key,
        cb_is_half_open_probe,
        flavor,
        prebuffered_body,
        request_body_prepared,
        raw_prebuffered_body_bytes,
        client_ip,
        xff_append_ip,
        ctx,
        plugins,
        initial_response_header_policy_plugins,
        initial_response_header_policy_names,
        backend_admission_plugins,
        preacquired_backend_admission,
        requires_response_body_buffering,
        response_committed_plugins,
        requires_response_stream_hooks,
        sticky_cookie_needed,
    } = request;
    let backend_start = Instant::now();
    let raw_prebuffered_body_bytes = raw_prebuffered_body_bytes.unwrap_or_else(|| {
        prebuffered_body
            .as_ref()
            .map(|body| body.len() as u64)
            .unwrap_or(0)
    });

    // If an earlier plugin phase pre-buffered the request body, run the
    // post-before_proxy body-transform + body-validation hooks on it
    // before we send to the backend. Mirrors the H1/H2 path's behavior in
    // `proxy_to_backend_retry` / `proxy_grpc_request_core`. An empty body
    // or plugins that don't opt in are zero-cost — see
    // `apply_request_body_plugins`.
    let prebuffered_body = match prebuffered_body {
        Some(body) if !request_body_prepared && !plugins.is_empty() => {
            // Use the context-aware variant so body transforms that depend on
            // `before_proxy` decisions in `ctx.metadata` (e.g.
            // `ai_stream_router`'s provider-specific translation) and
            // method-sensitive body plugins (e.g. `ai_prompt_compressor`, which
            // gates on the real request method) run on the H3 bridge exactly as
            // they do on the H1/H2 dispatch path. This bridge path has no
            // `:method` pseudo-header for the no-context hook to consult.
            let grpc_deadline_at = ctx.grpc_deadline_at();
            let transformed = crate::proxy::apply_request_body_plugins_with_context(
                plugins,
                Some(&mut *ctx),
                grpc_deadline_at,
                proxy_headers,
                body,
            )
            .await;
            // Run validators. Reject = emit a trailers-only native gRPC error,
            // a gRPC-Web trailer frame when that client representation was
            // retained, or a plain JSON error otherwise, then return early
            // WITHOUT dispatching to the backend.
            match crate::proxy::run_final_request_body_hooks(
                plugins,
                Some(ctx),
                grpc_deadline_at,
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
                        response_committed_plugins,
                        initial_response_header_policy_plugins.as_ref(),
                        RejectWriteAccounting {
                            backend_start,
                            bytes_sent: raw_prebuffered_body_bytes,
                        },
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
                strip_len,
                backend_path_is_policy_bound,
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
                initial_response_header_policy_plugins.as_ref(),
                backend_admission_plugins,
                preacquired_backend_admission,
                requires_response_body_buffering,
                response_committed_plugins,
                requires_response_stream_hooks,
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
                strip_len,
                backend_path_is_policy_bound,
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
                initial_response_header_policy_plugins.as_ref(),
                initial_response_header_policy_names,
                backend_admission_plugins,
                preacquired_backend_admission,
                requires_response_body_buffering,
                response_committed_plugins,
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
    request_is_secure: bool,
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
    let request_scheme = if request_is_secure { "https" } else { "http" };
    req_builder = req_builder.header("X-Forwarded-For", xff_val);
    req_builder = req_builder.header("X-Forwarded-Proto", request_scheme);
    if let Some(host) = original_host_header {
        req_builder = req_builder.header("X-Forwarded-Host", host);
    }
    if let Some(ref via) = state.via_header_http3 {
        req_builder = req_builder.header("Via", via.as_str());
    }
    if state.add_forwarded_header {
        req_builder = req_builder.header(
            "Forwarded",
            crate::proxy::build_forwarded_value(client_ip, request_scheme, original_host_header),
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
    ctx: &mut RequestContext,
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
            let mut outcome = write_plain_gateway_error(
                stream,
                ctx,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Bad Gateway"}"#,
                None,
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
    ctx: &mut RequestContext,
) -> Result<
    Result<Option<crate::backend_pending_limit::BackendPendingGuard>, CrossProtocolOutcome>,
    anyhow::Error,
>
where
    S: RecvStream + SendStream<Bytes>,
{
    // The H3 plain bridge has no HBONE / mesh-mTLS / east-west dispatch path.
    // A direct dial to a mesh-tagged target would bypass the secured mesh
    // transport, so fail closed before backend admission or body relay.
    if let Some(reason) =
        crate::proxy::backend_dispatch::direct_http_mesh_transport_refusal(current_target)
    {
        warn!(
            proxy_id = %dispatch_proxy.id,
            target_host = current_target.map(|target| target.host.as_str()).unwrap_or(""),
            target_port = current_target.map(|target| target.port).unwrap_or(0),
            reason,
            "cross-protocol H3→HTTP: refusing direct dial to a mesh-transport-tagged target"
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
        let mut outcome = write_plain_gateway_error(
            stream,
            ctx,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Bad Gateway","message":"Mesh transport dispatch required for this backend target"}"#,
            Some(("gateway-error-reason", reason)),
            backend_start,
            bytes_sent,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(current_url));
        outcome.error_class = Some(ErrorClass::DispatchPolicyRejected);
        return Ok(Err(outcome));
    }

    // Enforce the backend egress policy for a literal-IP backend on this
    // (possibly LB-rotated) cross-protocol attempt before dialing — reqwest and
    // the H2 pool skip the DnsCacheResolver for IP literals. The handler screens
    // the first target before entering the bridge, but a retry rotation lands
    // here with a fresh `effective_host`. Fail-closed, non-retryable, neutral to
    // backend health (no backend was dialed).
    if let Some(reason) =
        crate::proxy::denied_literal_backend_ip(effective_host, &state.env_config.backend_allow_ips)
    {
        warn!(
            proxy_id = %dispatch_proxy.id,
            backend = %effective_host,
            reason,
            "Backend egress policy denied literal-IP H3 cross-protocol backend; not dialing"
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
        let mut outcome = write_plain_gateway_error(
            stream,
            ctx,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"backend address blocked by egress policy"}"#,
            Some(("gateway-error-reason", "backend-egress-policy-denied")),
            backend_start,
            bytes_sent,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(current_url));
        outcome.error_class = Some(ErrorClass::DispatchPolicyRejected);
        return Ok(Err(outcome));
    }

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
        let mut outcome = write_plain_gateway_error(
            stream,
            ctx,
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
            let mut outcome = write_plain_gateway_error(
                stream,
                ctx,
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Upstream pending request queue full"}"#,
                None,
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
fn record_plain_grpc_web_client_deadline(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    upstream_balancer: Option<&Arc<LoadBalancer>>,
    current_target: Option<&UpstreamTarget>,
    current_cb_target_key: Option<&str>,
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
        current_target,
        current_cb_target_key,
        StatusCode::OK.as_u16(),
        false,
        Some(ErrorClass::ClientDisconnect),
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
    record_cross_protocol_backend_admission_outcome(
        backend_admission_permits,
        StatusCode::OK.as_u16(),
        false,
        Some(ErrorClass::ClientDisconnect),
        backend_admission_elapsed,
    );
}

#[allow(clippy::too_many_arguments)]
async fn write_plain_grpc_web_client_deadline<S>(
    stream: &mut RequestStream<S, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_committed_plugins: &[Arc<dyn Plugin>],
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    backend_start: Instant,
    bytes_sent: u64,
    backend_target_url: &str,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    ctx.mark_gateway_deadline_response_selected();
    let mut outcome = write_final_body_reject(
        stream,
        HttpFlavor::Grpc,
        plugins,
        ctx,
        crate::plugins::grpc_deadline_exceeded_plugin_result(),
        response_committed_plugins,
        initial_response_header_policy_plugins,
        RejectWriteAccounting {
            backend_start,
            bytes_sent,
        },
    )
    .await?;
    outcome.backend_target = Some(strip_query_from_backend_url(backend_target_url));
    outcome.body_error_class = Some(ErrorClass::ClientDisconnect);
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
async fn write_plain_grpc_web_client_deadline_without_hooks<S>(
    stream: &mut RequestStream<S, Bytes>,
    ctx: &mut RequestContext,
    backend_start: Instant,
    bytes_sent: u64,
    backend_target_url: &str,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    ctx.mark_gateway_deadline_response_selected();
    let deadline = normalized_h3_grpc_deadline();
    let (_, translated) = normalize_reject_for_client(
        ctx,
        deadline.http_status,
        &deadline.body,
        &deadline.headers,
        false,
    );
    let Some(translated) = translated else {
        crate::http3::stream_util::abort_response_stream(stream);
        crate::http3::stream_util::halt_request_body(stream);
        return Ok(terminal_deadline_write_aborted_outcome(
            StatusCode::OK.as_u16(),
            0,
            backend_start,
            bytes_sent,
            false,
        ));
    };
    let write = write_reject_with_headers(
        stream,
        StatusCode::OK,
        &translated.body,
        &translated.headers,
        backend_start,
        bytes_sent,
    );
    let mut outcome =
        match crate::http3::stream_util::await_terminal_response_write_before_deadline(
            ctx.grpc_deadline_at(),
            write,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                terminal_deadline_write_aborted_outcome(
                    StatusCode::OK.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    true,
                )
            }
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                terminal_deadline_write_aborted_outcome(
                    StatusCode::OK.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    false,
                )
            }
        };
    outcome.backend_target = Some(strip_query_from_backend_url(backend_target_url));
    outcome.body_error_class = Some(ErrorClass::ClientDisconnect);
    Ok(outcome)
}

async fn append_plain_grpc_web_client_deadline<S>(
    stream: &mut RequestStream<S, Bytes>,
    ctx: &mut RequestContext,
) -> (u64, bool)
where
    S: SendStream<Bytes>,
{
    ctx.mark_gateway_deadline_response_selected();
    let deadline = normalized_h3_grpc_deadline();
    let (_, translated) = normalize_reject_for_client(
        ctx,
        deadline.http_status,
        &deadline.body,
        &deadline.headers,
        false,
    );
    let Some(translated) = translated else {
        crate::http3::stream_util::abort_response_stream(stream);
        return (0, false);
    };
    let bytes = translated.body.len() as u64;
    let write = async {
        if !translated.body.is_empty() {
            stream.send_data(Bytes::from(translated.body)).await?;
        }
        stream.finish().await
    };
    match crate::http3::stream_util::await_terminal_response_write_before_deadline(
        ctx.grpc_deadline_at(),
        write,
    )
    .await
    {
        Ok(()) => (bytes, true),
        Err(_) => {
            crate::http3::stream_util::abort_response_stream(stream);
            (0, false)
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
    strip_len: usize,
    backend_path_is_policy_bound: bool,
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
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    mut preacquired_backend_admission: crate::proxy::PreacquiredBackendAdmission,
    requires_response_body_buffering: bool,
    response_committed_plugins: &[Arc<dyn Plugin>],
    requires_response_stream_hooks: bool,
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
    let policy_flavor = if crate::plugins::grpc_web::client_uses_grpc_web(ctx) {
        HttpFlavor::Grpc
    } else {
        HttpFlavor::Plain
    };
    let grpc_web_deadline_at = if matches!(policy_flavor, HttpFlavor::Grpc) {
        ctx.grpc_deadline_at()
    } else {
        None
    };

    let req_method = match parse_reqwest_method(method) {
        Some(m) => m,
        None => {
            return write_plain_gateway_error(
                stream,
                ctx,
                StatusCode::METHOD_NOT_ALLOWED,
                r#"{"error":"Method Not Allowed"}"#,
                None,
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
                        ctx,
                    )
                    .await?
                    {
                        Ok(slot) => slot,
                        Err(outcome) => return Ok(outcome),
                    };

                    let backend_admission_start = Instant::now();
                    let mut backend_admission_permits =
                        if let Some(permits) = preacquired_backend_admission.take_if_acquired() {
                            permits
                        } else {
                            match run_cross_protocol_backend_admission_or_reject(
                                backend_admission_plugins,
                                plugins,
                                ctx,
                                dispatch_proxy,
                                current_target.as_deref(),
                                policy_flavor,
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
                            }
                        };
                    record_cross_protocol_connection_start(
                        upstream_balancer,
                        current_target.as_deref(),
                    );

                    let client_result = match crate::plugins::await_grpc_deadline(
                        grpc_web_deadline_at,
                        get_cross_protocol_client(
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
                            ctx,
                            Some(&mut pending_slot),
                        ),
                    )
                    .await
                    {
                        Ok(result) => result?,
                        Err(()) => {
                            drop(pending_slot);
                            record_plain_grpc_web_client_deadline(
                                state,
                                epoch,
                                proxy,
                                upstream_balancer,
                                current_target.as_deref(),
                                current_cb_target_key.as_deref(),
                                cb_retry_probe_slot_available,
                                backend_start,
                                &mut backend_admission_permits,
                                backend_admission_start.elapsed(),
                            );
                            return write_plain_grpc_web_client_deadline(
                                stream,
                                plugins,
                                ctx,
                                response_committed_plugins,
                                initial_response_header_policy_plugins,
                                backend_start,
                                bytes_sent,
                                &current_url,
                            )
                            .await;
                        }
                    };
                    let client = match client_result {
                        Ok(client) => client,
                        Err(outcome) => return Ok(outcome),
                    };

                    let send_result = match crate::plugins::await_grpc_deadline(
                        grpc_web_deadline_at,
                        build_plain_request_builder(
                            &client,
                            state,
                            dispatch_proxy,
                            req_method.clone(),
                            proxy_headers,
                            &current_url,
                            effective_host,
                            client_ip,
                            xff_append_ip,
                            ctx.request_is_secure,
                            ctx.is_early_data,
                        )
                        .body(buffered_body.clone())
                        .send(),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(()) => {
                            drop(pending_slot);
                            record_plain_grpc_web_client_deadline(
                                state,
                                epoch,
                                proxy,
                                upstream_balancer,
                                current_target.as_deref(),
                                current_cb_target_key.as_deref(),
                                cb_retry_probe_slot_available,
                                backend_start,
                                &mut backend_admission_permits,
                                backend_admission_start.elapsed(),
                            );
                            return write_plain_grpc_web_client_deadline(
                                stream,
                                plugins,
                                ctx,
                                response_committed_plugins,
                                initial_response_header_policy_plugins,
                                backend_start,
                                bytes_sent,
                                &current_url,
                            )
                            .await;
                        }
                    };
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
                                let retry_target = select_next_cross_protocol_retry_target(
                                    state,
                                    epoch,
                                    proxy,
                                    lb_hash_key,
                                    current_target.as_ref(),
                                    strip_len,
                                    backend_path_is_policy_bound,
                                    path,
                                    query_string,
                                    client_ip,
                                    proxy_headers,
                                );
                                if !matches!(
                                    &retry_target,
                                    CrossProtocolRetryTarget::BackendPathMismatch
                                ) {
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
                                    if crate::plugins::await_grpc_deadline(
                                        grpc_web_deadline_at,
                                        tokio::time::sleep(delay),
                                    )
                                    .await
                                    .is_err()
                                    {
                                        return write_plain_grpc_web_client_deadline(
                                            stream,
                                            plugins,
                                            ctx,
                                            response_committed_plugins,
                                            initial_response_header_policy_plugins,
                                            backend_start,
                                            bytes_sent,
                                            &current_url,
                                        )
                                        .await;
                                    }
                                    attempt += 1;
                                    if let CrossProtocolRetryTarget::Selected(
                                        next_target,
                                        next_cb_target_key,
                                        next_url,
                                    ) = retry_target
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
                                let retry_target = select_next_cross_protocol_retry_target(
                                    state,
                                    epoch,
                                    proxy,
                                    lb_hash_key,
                                    current_target.as_ref(),
                                    strip_len,
                                    backend_path_is_policy_bound,
                                    path,
                                    query_string,
                                    client_ip,
                                    proxy_headers,
                                );
                                if !matches!(
                                    &retry_target,
                                    CrossProtocolRetryTarget::BackendPathMismatch
                                ) {
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
                                    if crate::plugins::await_grpc_deadline(
                                        grpc_web_deadline_at,
                                        tokio::time::sleep(delay),
                                    )
                                    .await
                                    .is_err()
                                    {
                                        return write_plain_grpc_web_client_deadline(
                                            stream,
                                            plugins,
                                            ctx,
                                            response_committed_plugins,
                                            initial_response_header_policy_plugins,
                                            backend_start,
                                            bytes_sent,
                                            &current_url,
                                        )
                                        .await;
                                    }
                                    attempt += 1;
                                    if let CrossProtocolRetryTarget::Selected(
                                        next_target,
                                        next_cb_target_key,
                                        next_url,
                                    ) = retry_target
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
                            let mut outcome = write_plain_gateway_error(
                                stream,
                                ctx,
                                StatusCode::BAD_GATEWAY,
                                r#"{"error":"Bad Gateway"}"#,
                                None,
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
                    return write_plain_gateway_error(
                        stream,
                        ctx,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        None,
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
                    ctx,
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
                        policy_flavor,
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

                let client_result = match crate::plugins::await_grpc_deadline(
                    grpc_web_deadline_at,
                    get_cross_protocol_client(
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
                        ctx,
                        Some(&mut pending_slot),
                    ),
                )
                .await
                {
                    Ok(result) => result?,
                    Err(()) => {
                        drop(pending_slot);
                        crate::http3::stream_util::halt_request_body(stream);
                        record_plain_grpc_web_client_deadline(
                            state,
                            epoch,
                            proxy,
                            upstream_balancer,
                            current_target.as_deref(),
                            current_cb_target_key.as_deref(),
                            cb_is_half_open_probe,
                            backend_start,
                            &mut backend_admission_permits,
                            backend_admission_start.elapsed(),
                        );
                        return write_plain_grpc_web_client_deadline(
                            stream,
                            plugins,
                            ctx,
                            response_committed_plugins,
                            initial_response_header_policy_plugins,
                            backend_start,
                            0,
                            &current_url,
                        )
                        .await;
                    }
                };
                let client = match client_result {
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
                    ctx.request_is_secure,
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
                    let grpc_web_deadline_active = grpc_web_deadline_at.is_some();
                    let grpc_web_deadline =
                        tokio::time::sleep_until(grpc_web_deadline_at.unwrap_or_else(|| {
                            tokio::time::Instant::now() + Duration::from_secs(86_400)
                        }));
                    tokio::pin!(grpc_web_deadline);
                    let mut reader_done = false;
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut grpc_web_deadline, if grpc_web_deadline_active => {
                                // The absolute RPC ceiling owns the whole streaming
                                // dispatch, including an upload that never finishes
                                // and a backend that withholds response headers.
                                // Drop both borrowed futures immediately; the
                                // unconditional STOP_SENDING below closes the H3
                                // receive half without delaying the status-4 writer.
                                drop(pending_slot.take());
                                break None;
                            }
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
                                break Some(result);
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
                let Some(send_result) = send_result else {
                    record_plain_grpc_web_client_deadline(
                        state,
                        epoch,
                        proxy,
                        upstream_balancer,
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                        backend_start,
                        &mut backend_admission_permits,
                        backend_admission_start.elapsed(),
                    );
                    return write_plain_grpc_web_client_deadline(
                        stream,
                        plugins,
                        ctx,
                        response_committed_plugins,
                        initial_response_header_policy_plugins,
                        backend_start,
                        bytes_sent,
                        &current_url,
                    )
                    .await;
                };
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
                    return write_plain_gateway_error(
                        stream,
                        ctx,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        None,
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
                        let mut outcome = write_plain_gateway_error(
                            stream,
                            ctx,
                            StatusCode::BAD_GATEWAY,
                            r#"{"error":"Bad Gateway"}"#,
                            None,
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
        let mut outcome = write_plain_gateway_error(
            stream,
            ctx,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
            None,
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
        let reject_status =
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let (mut normalized, mut translated) =
            normalize_reject_for_client(ctx, reject_status, &reject.body, &reject.headers, false);
        run_cross_protocol_reject_committed_hooks(
            response_committed_plugins,
            ctx,
            false,
            &mut normalized,
            &mut translated,
        )
        .await;
        let mut outcome = if let Some(translated) = translated {
            write_reject_with_headers(
                stream,
                StatusCode::OK,
                &translated.body,
                &translated.headers,
                backend_start,
                bytes_sent,
            )
            .await?
        } else {
            write_reject_with_headers(
                stream,
                normalized.http_status,
                &normalized.body,
                &normalized.headers,
                backend_start,
                bytes_sent,
            )
            .await?
        };
        outcome.backend_target = Some(strip_query_from_backend_url(&current_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        return Ok(outcome);
    }

    // Sticky session cookie injection — only runs if the LB selected a
    // sticky target.
    // `run_after_proxy_hooks` above already armed deadline provenance, so the
    // buffered variant can claim the affinity cookie as gateway-owned. The
    // buffered branch below hands this response to `response_committed` hooks
    // under `grpc_web_deadline_at`; a deadline rebuild there keeps gateway-owned
    // headers only, and an unrecorded cookie would be dropped.
    crate::http3::server::inject_sticky_cookie_with_deadline_provenance(
        ctx,
        epoch,
        proxy,
        current_target.as_deref(),
        sticky_cookie_needed,
        &mut response_headers,
    );

    // Refine the pre-header buffer/stream decision now that the content-type is
    // known — same downgrade the H1/H2 path applies. `inspect` mode buffers by
    // default (so a JSON response is inspected via `on_response_body`); this
    // downgrades only a response every active body plugin can release to the
    // windowed streaming path. Retry-enabled requests use the same marked
    // decision context as H1/H2, allowing inherently streaming responses such
    // as MCP SSE to opt out conservatively after headers arrive.
    let has_retry = crate::retry::has_effective_http_retries(proxy.retry.as_ref(), method);
    let retry_ctx = has_retry.then(|| crate::proxy::retry_response_decision_context(&*ctx));
    let response_decision_ctx = retry_ctx.as_ref().unwrap_or(&*ctx);
    let should_buffer_response = !crate::proxy::refine_stream_response_for_content_type(
        !should_buffer_response,
        proxy,
        plugins,
        Some(response_decision_ctx),
        status,
        &response_headers,
    );

    if should_buffer_response {
        let mut response_status = status;
        let mut response_body = match crate::plugins::await_grpc_deadline(
            grpc_web_deadline_at,
            collect_reqwest_response_body_with_limit(response, state.max_response_body_size_bytes),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err((error_body, error_class))) => {
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
                let mut outcome = write_plain_gateway_reject(
                    stream,
                    ctx,
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
            Err(()) => {
                record_plain_grpc_web_client_deadline(
                    state,
                    epoch,
                    proxy,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                    backend_start,
                    &mut backend_admission_permits,
                    backend_admission_elapsed,
                );
                return write_plain_grpc_web_client_deadline(
                    stream,
                    plugins,
                    ctx,
                    response_committed_plugins,
                    initial_response_header_policy_plugins,
                    backend_start,
                    bytes_sent,
                    &current_url,
                )
                .await;
            }
        };

        let plugin_pipeline = async {
            if !plugins.is_empty() {
                normalize_response_body_for_inspection(
                    plugins,
                    ctx,
                    response_status,
                    &mut response_headers,
                    &mut response_body,
                    initial_response_header_policy_plugins,
                )
                .await;
                // Set once an earlier body phase selects a gateway-authored
                // terminal response. Transforms still run so presentation and
                // protocol encoding stays correct, but final-body validators
                // must not replace the selected error.
                let mut response_body_rejected = false;
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
                            response_body_rejected = true;
                            break;
                        }
                    }
                }

                // Shared representation gate — identical to H1/H2 and native H3.
                // An H3 client bridged to an H1/H2 backend must not receive a
                // protected representation this gateway could not inspect just
                // because the frontend protocol differs.
                let grpc_web_response_content_type =
                    crate::plugins::grpc_web::retained_response_content_type(ctx);
                let admission = crate::proxy::admit_buffered_response_body_transforms(
                    plugins,
                    ctx,
                    crate::proxy::buffered_response_representation_origin(response_body_rejected),
                    &mut response_status,
                    &mut response_headers,
                    &mut response_body,
                    grpc_web_response_content_type,
                    crate::proxy::InitialResponseHeaderPolicySource::Prefiltered(
                        initial_response_header_policy_plugins,
                    ),
                    true,
                )
                .await;
                response_body_rejected |= matches!(
                    admission,
                    crate::proxy::BufferedTransformAdmission::Rejected
                );
                if matches!(
                    admission,
                    crate::proxy::BufferedTransformAdmission::Proceed {
                        rewrite_allowed: true,
                        ..
                    }
                ) {
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
                            response_headers.insert(
                                "content-length".to_string(),
                                transformed.len().to_string(),
                            );
                            response_body = transformed;
                            crate::plugins::finalize_response_body_transformation(
                                plugin.as_ref(),
                                ctx,
                                &mut response_headers,
                            );
                        }
                        ctx.record_deadline_response_header_plugin(
                            plugin.as_ref(),
                            &response_headers,
                        );
                    }
                }

                if !response_body_rejected {
                    for plugin in plugins {
                        let result = plugin
                            .on_final_response_body(
                                ctx,
                                response_status,
                                &response_headers,
                                &response_body,
                            )
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

                if !response_committed_plugins.is_empty() {
                    crate::proxy::run_deadline_bounded_response_committed_hooks(
                        response_committed_plugins,
                        ctx,
                        &mut response_status,
                        &mut response_headers,
                        &mut response_body,
                        initial_response_header_policy_plugins,
                    )
                    .await;
                }
            }
        };
        if crate::plugins::await_grpc_deadline(grpc_web_deadline_at, plugin_pipeline)
            .await
            .is_err()
        {
            record_plain_grpc_web_client_deadline(
                state,
                epoch,
                proxy,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                cb_retry_probe_slot_available,
                backend_start,
                &mut backend_admission_permits,
                backend_admission_elapsed,
            );
            return write_plain_grpc_web_client_deadline(
                stream,
                plugins,
                ctx,
                response_committed_plugins,
                initial_response_header_policy_plugins,
                backend_start,
                bytes_sent,
                &current_url,
            )
            .await;
        }

        if let Err(error) = crate::http3::stream_util::await_response_write_before_deadline(
            grpc_web_deadline_at,
            send_response_headers(stream, response_status, &response_headers),
        )
        .await
        {
            if matches!(
                error,
                crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
            ) {
                record_plain_grpc_web_client_deadline(
                    state,
                    epoch,
                    proxy,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                    backend_start,
                    &mut backend_admission_permits,
                    backend_admission_elapsed,
                );
                return write_plain_grpc_web_client_deadline_without_hooks(
                    stream,
                    ctx,
                    backend_start,
                    bytes_sent,
                    &current_url,
                )
                .await;
            }
            debug!(
                ?error,
                "cross-protocol H3 buffered response header write failed"
            );
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
                false,
                bytes_sent,
                backend_start,
                Some(strip_query_from_backend_url(&current_url)),
                final_backend_resolved_ip.clone(),
            ));
        }
        let bytes_streamed = response_body.len() as u64;
        let buffered_write = async {
            if !response_body.is_empty() {
                stream.send_data(Bytes::from(response_body)).await?;
            }
            stream.finish().await
        };
        let (body_completed, client_disconnected) =
            match crate::http3::stream_util::await_response_write_before_deadline(
                grpc_web_deadline_at,
                buffered_write,
            )
            .await
            {
                Ok(()) => (true, false),
                Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => {
                    debug!("cross-protocol H3 buffered body write failed: {error}");
                    (false, true)
                }
                Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                    record_plain_grpc_web_client_deadline(
                        state,
                        epoch,
                        proxy,
                        upstream_balancer,
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        cb_retry_probe_slot_available,
                        backend_start,
                        &mut backend_admission_permits,
                        backend_admission_elapsed,
                    );
                    let (deadline_bytes, deadline_written) =
                        append_plain_grpc_web_client_deadline(stream, ctx).await;
                    return Ok(CrossProtocolOutcome {
                        response_status: StatusCode::OK.as_u16(),
                        response_streamed: false,
                        bytes_streamed: bytes_streamed.saturating_add(deadline_bytes),
                        bytes_sent,
                        backend_target: Some(strip_query_from_backend_url(&current_url)),
                        backend_resolved_ip: final_backend_resolved_ip.clone(),
                        body_completed: deadline_written,
                        client_disconnected: false,
                        connection_error: false,
                        error_class: None,
                        body_error_class: Some(ErrorClass::ClientDisconnect),
                        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
                        rejection_logged: false,
                    });
                }
            };

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
            response_streamed: false,
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
            rejection_logged: false,
        });
    }

    // Resolve a response-stream inspector (e.g. ai_semantic_firewall `inspect`)
    // for this H3-client → non-H3-backend response. Without this, an H3 client
    // hitting an HTTP/1/2 SSE backend would stream uninspected. Chain every
    // opted-in plugin, gated to the response status.
    let response_inspector = if requires_response_stream_hooks {
        let content_type = response_headers.get("content-type").map(String::as_str);
        crate::plugins::create_response_stream_inspector_for_enabled_plugins(
            plugins,
            ctx,
            status,
            content_type,
        )
    } else {
        None
    };
    // Strip Content-Length when inspecting — the inspector transforms the body, so
    // the backend's declared length no longer matches what we send.
    if response_inspector.is_some() {
        response_headers.remove("content-length");
    }

    // Send response headers, then stream the body.
    if let Err(error) = crate::http3::stream_util::await_response_write_before_deadline(
        grpc_web_deadline_at,
        send_response_headers(stream, status, &response_headers),
    )
    .await
    {
        if matches!(
            error,
            crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
        ) {
            record_plain_grpc_web_client_deadline(
                state,
                epoch,
                proxy,
                upstream_balancer,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                cb_retry_probe_slot_available,
                backend_start,
                &mut backend_admission_permits,
                backend_admission_elapsed,
            );
            return write_plain_grpc_web_client_deadline_without_hooks(
                stream,
                ctx,
                backend_start,
                bytes_sent,
                &current_url,
            )
            .await;
        }
        debug!(
            ?error,
            "cross-protocol H3 streaming response header write failed"
        );
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
            true,
            bytes_sent,
            backend_start,
            Some(strip_query_from_backend_url(&current_url)),
            final_backend_resolved_ip.clone(),
        ));
    }

    let coalesce = CoalesceConfig::from_state(state);
    let max_resp_bytes = state.max_response_body_size_bytes;
    let stream_response = async {
        if let Some(inspector) = response_inspector {
            stream_inspected_reqwest_response(stream, response, inspector, max_resp_bytes).await
        } else {
            stream_reqwest_response(stream, response, coalesce, max_resp_bytes).await
        }
    };
    let (bytes_streamed, body_completed, client_disconnected, body_error_class) =
        match crate::plugins::await_grpc_deadline(grpc_web_deadline_at, stream_response).await {
            Ok(result) => result,
            Err(()) => {
                record_plain_grpc_web_client_deadline(
                    state,
                    epoch,
                    proxy,
                    upstream_balancer,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                    backend_start,
                    &mut backend_admission_permits,
                    backend_admission_elapsed,
                );
                let (deadline_bytes, deadline_written) =
                    append_plain_grpc_web_client_deadline(stream, ctx).await;
                return Ok(CrossProtocolOutcome {
                    response_status: StatusCode::OK.as_u16(),
                    response_streamed: true,
                    bytes_streamed: deadline_bytes,
                    bytes_sent,
                    backend_target: Some(strip_query_from_backend_url(&current_url)),
                    backend_resolved_ip: final_backend_resolved_ip.clone(),
                    body_completed: deadline_written,
                    client_disconnected: false,
                    connection_error: false,
                    error_class: None,
                    body_error_class: Some(ErrorClass::ClientDisconnect),
                    backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
                    rejection_logged: false,
                });
            }
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
        response_streamed: true,
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
        rejection_logged: false,
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
    request_is_secure: bool,
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
    let request_scheme = if request_is_secure { "https" } else { "http" };
    hmap.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(request_scheme),
    );
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
        let fwd =
            crate::proxy::build_forwarded_value(client_ip, request_scheme, original_host_header);
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

/// Extract the gateway-trusted plugin assertions (`x-consumer-username`,
/// `x-consumer-custom-id`, and `x-geo-country`) from the materialised
/// `proxy_headers` into a minimal map.
///
/// The H3 gRPC dispatch builds its backend header set up-front
/// ([`build_h3_grpc_backend_headers`]) and passes empty `proxy_headers` to the
/// gRPC core so the canonical forwarding headers it synthesised
/// (`x-forwarded-*`, `via`, `forwarded`) are not re-merged. But the core's
/// `merge_proxy_headers_and_strip_for_grpc` strips reserved identity headers
/// from the base map and re-adds them ONLY from its `proxy_headers` arg (so a
/// client cannot forge a principal). An empty arg therefore drops the
/// gateway-verified assertions that `build_h3_grpc_backend_headers` copied in,
/// hiding the authenticated principal or geo result from the backend. Passing
/// this minimal map preserves those trusted assertions while still keeping the
/// forwarding headers from being re-merged. Empty when no assertion was
/// produced — the merge then strips any client-forged value and adds nothing,
/// preserving the spoof protection.
fn trusted_plugin_assertion_proxy_headers(
    proxy_headers: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut assertions = HashMap::new();
    // The H3 server injects these post-auth as `X-Consumer-Username` /
    // `X-Consumer-Custom-Id` (capitalised — see `src/http3/server.rs`), so match
    // CASE-INSENSITIVELY: a case-sensitive lowercase lookup would miss them and
    // still drop the authenticated principal (codex P2). Stored lowercase — the
    // gRPC core's merge re-parses the name via `HeaderName` (which lowercases)
    // regardless. The reserved set mirrors
    // `proxy::headers::strip_reserved_gateway_assertion_headers`.
    for (key, value) in proxy_headers {
        if key.eq_ignore_ascii_case("x-consumer-username")
            || key.eq_ignore_ascii_case("x-consumer-custom-id")
            || key.eq_ignore_ascii_case("x-geo-country")
        {
            assertions.insert(key.to_ascii_lowercase(), value.clone());
        }
    }
    assertions
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
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    sticky_cookie_needed: bool,
    bytes_sent: u64,
    backend_target_url: &str,
    final_backend_resolved_ip: Option<String>,
    // Set by the streaming-request pump when the H3 client resets its upload; used
    // to classify a resulting response-body error as a CLIENT abort rather than a
    // backend fault (codex P2). `None` on the buffered-request path (no pump).
    frontend_upload_failed: Option<&Arc<AtomicBool>>,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    let current_target_ref: Option<&UpstreamTarget> = current_target.map(|t| t.as_ref());
    // Pre-head late-overflow guard (codex P2): if the client upload already tripped
    // `max_grpc_recv_size_bytes` by the time the backend response is ready — e.g. a
    // trailers-only success whose `grpc-status` rides the HEADER block — do NOT
    // forward that success: emit RESOURCE_EXHAUSTED before any response head reaches
    // the client. The post-body check further down covers overflows that trip while
    // the response body streams; a success already delivered in the header block
    // before the overflow trips cannot be retracted (accepted narrow-race limit).
    if streaming
        .request_body_exceeded
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Acquire))
    {
        ctx.metadata.insert(
            "grpc_status".to_string(),
            grpc_proxy::grpc_status::RESOURCE_EXHAUSTED.to_string(),
        );
        record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            current_target_ref,
            current_cb_target_key,
            200,
            false,
            Some(ErrorClass::RequestBodyTooLarge),
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        record_cross_protocol_backend_admission_outcome(
            backend_admission_permits,
            200,
            false,
            Some(ErrorClass::RequestBodyTooLarge),
            backend_admission_start.elapsed(),
        );
        let mut outcome = write_grpc_error_send_with_policy(
            stream,
            grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Request payload exceeded backend limit",
            backend_start,
            bytes_sent,
            initial_response_header_policy_plugins,
        )
        .await?;
        outcome.backend_target = Some(strip_query_from_backend_url(backend_target_url));
        outcome.error_class = Some(ErrorClass::RequestBodyTooLarge);
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        return Ok(outcome);
    }
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
                    true,
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
    // Hooks may rewrite/remove a Trailers-Only status. Record their final
    // client-visible header result now; a real terminal trailer wins below.
    let client_header_grpc_status = streaming
        .headers
        .get("grpc-status")
        .map(|status| crate::proxy::grpc_proxy::parse_grpc_status_value(status));
    crate::proxy::grpc_proxy::refresh_grpc_status_metadata(
        &mut ctx.metadata,
        &HashMap::new(),
        &streaming.headers,
    );

    // The body relay may replace an empty backend stream with terminal
    // deadline trailers. Do not commit the backend's declared length across
    // that protocol-level replacement.
    crate::proxy::strip_content_length_for_streaming_grpc_deadline(
        &mut streaming.headers,
        streaming.grpc_deadline_at,
    );

    if let Err(error) = crate::http3::stream_util::await_response_write_before_deadline(
        streaming.grpc_deadline_at,
        send_response_headers(stream, streaming.status, &streaming.headers),
    )
    .await
    {
        if matches!(
            error,
            crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
        ) {
            crate::proxy::insert_grpc_error_metadata(
                &mut ctx.metadata,
                grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
            );
            crate::http3::stream_util::abort_response_stream(stream);
        } else {
            debug!("cross-protocol H3 gRPC streaming response header write failed");
        }
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
            true,
            bytes_sent,
            backend_start,
            Some(strip_query_from_backend_url(backend_target_url)),
            final_backend_resolved_ip.clone(),
        ));
    }
    let coalesce = CoalesceConfig::from_state(state);
    let max_resp_bytes = state.max_response_body_size_bytes;
    let (
        bytes_streamed,
        body_completed,
        client_disconnected,
        body_error_class,
        trailers,
        mut client_deadline_expired,
    ) = stream_hyper_incoming(
        stream,
        streaming.body,
        coalesce,
        max_resp_bytes,
        streaming.response_read_timeout_ms,
        streaming.grpc_deadline_at,
    )
    .await;

    let mut final_body_completed = body_completed;
    let mut final_client_disconnected = client_disconnected;
    // Late client-upload overflow (codex P2): on a bidi/early-response RPC the
    // channel body can trip `max_grpc_recv_size_bytes` AFTER the response headers
    // were forwarded, so `proxy_grpc_request_streaming_channel` could not surface
    // it. An oversized upload must NOT be delivered to the client as a successful
    // gRPC response: when the flag tripped, RST the H3 response (withholding the
    // backend's possibly-`grpc-status: 0` trailer) so the client observes an
    // aborted RPC rather than success. HEADERS/DATA already on the wire cannot be
    // unsent, but the success status is suppressed. Metrics below reclassify the
    // overrun as a client-side `RequestBodyTooLarge` (neutral for backend health
    // and adaptive concurrency, even if the backend finished first). No-op for the
    // buffered-request path, which size-checks before dispatch.
    let request_overflowed_late = streaming
        .request_body_exceeded
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Acquire));
    // Capture the backend gRPC outcome from the trailers before they are
    // stripped/forwarded, so the admission sample below reflects a backend
    // gRPC failure (e.g. 14 -> 503) instead of the HTTP 200 status line.
    let mut grpc_trailer_status: Option<u32> = None;
    if request_overflowed_late {
        // Suppress the (possibly successful) backend status on an oversized upload.
        crate::http3::stream_util::abort_response_stream(stream);
        final_body_completed = false;
    } else if body_completed && let Some(mut trailers) = trailers {
        grpc_trailer_status = trailers.get("grpc-status").map(|value| {
            value.to_str().map_or(u32::MAX, |value| {
                crate::proxy::grpc_proxy::parse_grpc_status_value(value)
            })
        });
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
            let trailer_write = if client_deadline_expired {
                // The timer already selected these canonical status-4 trailers.
                // Give an immediately-writable terminal frame one chance, but
                // still cancel it if QUIC flow control would block.
                crate::http3::stream_util::await_terminal_response_write_before_deadline(
                    streaming.grpc_deadline_at,
                    stream.send_trailers(trailers),
                )
                .await
            } else {
                crate::http3::stream_util::await_response_write_before_deadline(
                    streaming.grpc_deadline_at,
                    stream.send_trailers(trailers),
                )
                .await
            };
            let trailer_and_finish = match trailer_write {
                Ok(()) if client_deadline_expired => {
                    crate::http3::stream_util::await_terminal_response_write_before_deadline(
                        streaming.grpc_deadline_at,
                        stream.finish(),
                    )
                    .await
                }
                Ok(()) => {
                    crate::http3::stream_util::await_response_write_before_deadline(
                        streaming.grpc_deadline_at,
                        stream.finish(),
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = trailer_and_finish {
                if matches!(
                    error,
                    crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
                ) {
                    client_deadline_expired = true;
                    crate::http3::stream_util::abort_response_stream(stream);
                } else {
                    final_client_disconnected = true;
                    warn!("H3 gRPC streaming send_trailers failed");
                }
                final_body_completed = false;
            }
        } else if had_trailers
            && let Err(error) = crate::http3::stream_util::await_response_write_before_deadline(
                streaming.grpc_deadline_at,
                stream.finish(),
            )
            .await
        {
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
            if matches!(
                error,
                crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
            ) {
                client_deadline_expired = true;
                crate::http3::stream_util::abort_response_stream(stream);
            } else {
                final_client_disconnected = true;
                debug!("H3 gRPC streaming finish after trailer strip failed");
            }
            final_body_completed = false;
        }
    }

    // A client upload reset (recv-half error) makes the pump set
    // `frontend_upload_failed`; the backend then sees an RST and the response body
    // surfaces a hyper error here. That is a CLIENT abort, not a backend fault — so
    // classify it as ClientDisconnect (neutral for backend health / adaptive
    // concurrency) rather than the protocol/timeout class hyper reports (codex P2).
    let frontend_aborted = frontend_upload_failed.is_some_and(|flag| flag.load(Ordering::Acquire));
    let outcome_error_class = if request_overflowed_late {
        Some(ErrorClass::RequestBodyTooLarge)
    } else if client_deadline_expired || (frontend_aborted && body_error_class.is_some()) {
        Some(ErrorClass::ClientDisconnect)
    } else {
        body_error_class
    };
    // The backend-health sample (circuit breaker / passive health / least-latency)
    // must reflect the TRUE gRPC outcome, not just the HTTP 200 status line
    // (codex P2): a non-OK `grpc-status` trailer or a mid-stream body error is a
    // backend failure, while a client-side terminal (disconnect / oversized upload)
    // is neutral. Response headers already arrived here, so `connection_error` is
    // always false (no pre-wire connect failure) — the failure signal rides the
    // mapped status + error class. The adaptive-concurrency sample uses the same
    // triple so circuit-breaker / passive-health and admission cannot drift.
    let outcome_status = match grpc_trailer_status {
        Some(code) if code != 0 => crate::proxy::grpc_proxy::grpc_status_to_http_status(code),
        _ => streaming.status,
    };
    record_backend_outcome(
        state,
        proxy,
        &epoch.load_balancer,
        upstream_balancer,
        current_target_ref,
        current_cb_target_key,
        outcome_status,
        false,
        outcome_error_class,
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
    record_cross_protocol_backend_admission_outcome(
        backend_admission_permits,
        outcome_status,
        false,
        outcome_error_class,
        backend_admission_start.elapsed(),
    );
    let terminal_grpc_status = if request_overflowed_late {
        grpc_proxy::grpc_status::RESOURCE_EXHAUSTED
    } else if client_deadline_expired {
        grpc_proxy::grpc_status::DEADLINE_EXCEEDED
    } else {
        grpc_trailer_status
            .or(client_header_grpc_status)
            .unwrap_or(grpc_proxy::grpc_status::UNKNOWN)
    };
    ctx.metadata
        .insert("grpc_status".to_string(), terminal_grpc_status.to_string());
    Ok(CrossProtocolOutcome {
        response_status: streaming.status,
        response_streamed: true,
        bytes_streamed,
        bytes_sent,
        backend_target: Some(strip_query_from_backend_url(backend_target_url)),
        backend_resolved_ip: final_backend_resolved_ip.clone(),
        body_completed: final_body_completed,
        client_disconnected: final_client_disconnected,
        connection_error: false,
        error_class: None,
        body_error_class: outcome_error_class,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
        rejection_logged: false,
    })
}

/// Mesh-transport fail-closed guard for the H3→gRPC bridge (issue #2003).
///
/// Both `dispatch_grpc` and `dispatch_grpc_streaming` dial the LB-selected
/// `target.host:target.port` directly via `GrpcConnectionPool`, and the H3
/// cross-protocol bridge has NO HBONE / mesh-mTLS dispatch path. A
/// mesh-transport-tagged target must therefore fail closed with a clear gRPC
/// UNAVAILABLE — a direct dial would silently bypass the secured mesh
/// transport (unauthenticated under PERMISSIVE PeerAuthentication, a
/// confusing capture-listener failure under STRICT). The H1/H2 frontend path
/// routes same-cluster `mesh.mtls` gRPC over the mesh-mTLS pool; extending
/// that to the H3 bridge is a documented residual (docs/mesh.md).
fn grpc_mesh_transport_refusal(target: Option<&UpstreamTarget>) -> Option<&'static str> {
    let target = target?;
    match grpc_proxy::classify_grpc_mesh_dispatch(target) {
        grpc_proxy::GrpcMeshDispatch::Direct => None,
        // The H3 bridge has no mesh-mTLS dispatch path, so BOTH the same-cluster
        // and cross-cluster sidecar mesh-mTLS classes fail closed here — gRPC
        // over cross-cluster east-west is supported only on the H1/H2 frontend
        // (issue #2010); H3 mesh dispatch is a separate documented residual.
        grpc_proxy::GrpcMeshDispatch::MeshMtls
        | grpc_proxy::GrpcMeshDispatch::MeshMtlsCrossCluster => Some(
            "gRPC over the sidecar mesh mTLS transport is not supported on the HTTP/3 frontend",
        ),
        grpc_proxy::GrpcMeshDispatch::RefuseCrossCluster => Some(
            "gRPC over cross-cluster Ambient HBONE east-west routing is not supported \
             (HBONE inner protocol cannot carry gRPC trailers)",
        ),
        grpc_proxy::GrpcMeshDispatch::RefuseCrossClusterMalformed => Some(
            "gRPC over cross-cluster east-west routing requires a destination SNI \
             override and a remote trust domain",
        ),
        grpc_proxy::GrpcMeshDispatch::RefuseCrossClusterNoTransport => {
            Some("gRPC over cross-cluster east-west routing requires a mesh transport tag")
        }
        grpc_proxy::GrpcMeshDispatch::RefuseHbone => Some(
            "gRPC over the Ambient HBONE mesh transport is not supported \
             (HBONE inner protocol cannot carry gRPC trailers)",
        ),
    }
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
    strip_len: usize,
    backend_path_is_policy_bound: bool,
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
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    initial_response_header_policy_names: Arc<Vec<String>>,
    backend_admission_plugins: &[Arc<dyn Plugin>],
    mut preacquired_backend_admission: crate::proxy::PreacquiredBackendAdmission,
    requires_response_body_buffering: bool,
    response_committed_plugins: &[Arc<dyn Plugin>],
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let hyper_method = match hyper::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return write_grpc_error_for_request(
                stream,
                ctx,
                grpc_proxy::grpc_status::UNIMPLEMENTED,
                "Method Not Allowed",
                backend_start,
                0,
                initial_response_header_policy_plugins,
            )
            .await;
        }
    };
    let mut current_target = upstream_target.cloned().map(Arc::new);
    let mut current_cb_target_key = cb_target_key.map(str::to_owned);
    let mut current_url = backend_url.to_string();
    let mut cb_retry_probe_slot_available = cb_is_half_open_probe;

    // FAIL CLOSED on a mesh-transport-tagged target BEFORE reading the request
    // body or dialing (issue #2003, see `grpc_mesh_transport_refusal`). The
    // probe slot a HALF_OPEN breaker may have admitted is released, mirroring
    // the pre-dispatch rejects below.
    if let Some(message) = grpc_mesh_transport_refusal(current_target.as_deref()) {
        warn!(
            proxy_id = %proxy.id,
            target_host = current_target.as_deref().map(|t| t.host.as_str()).unwrap_or(""),
            message,
            "cross-protocol H3→gRPC: refusing direct dial to a mesh-transport-tagged target; \
             failing closed with gRPC UNAVAILABLE"
        );
        release_cross_protocol_circuit_breaker_probe_on_admission_reject(
            state,
            proxy,
            current_cb_target_key.as_deref(),
            cb_retry_probe_slot_available,
        );
        return write_grpc_error_for_request(
            stream,
            ctx,
            grpc_proxy::grpc_status::UNAVAILABLE,
            message,
            backend_start,
            0,
            initial_response_header_policy_plugins,
        )
        .await;
    }

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
        match super::server::collect_h3_request_body_with_deadline(
            drain_h3_body(stream, state.max_grpc_recv_size_bytes),
            ctx.grpc_deadline_at(),
            proxy.backend_read_timeout_ms,
        )
        .await
        {
            Ok(Some(b)) => b,
            Ok(None) => {
                release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                    state,
                    proxy,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                );
                return write_grpc_error_for_request(
                    stream,
                    ctx,
                    grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    backend_start,
                    0,
                    initial_response_header_policy_plugins,
                )
                .await;
            }
            Err(super::server::H3RequestBodyReadError::Read(e)) => {
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
                return write_grpc_error_for_request(
                    stream,
                    ctx,
                    grpc_proxy::grpc_status::INVALID_ARGUMENT,
                    "Request body read error",
                    backend_start,
                    0,
                    initial_response_header_policy_plugins,
                )
                .await;
            }
            Err(super::server::H3RequestBodyReadError::TimedOut) => {
                release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                    state,
                    proxy,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                );
                return write_grpc_error_for_request(
                    stream,
                    ctx,
                    grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    "Request body read timed out",
                    backend_start,
                    0,
                    initial_response_header_policy_plugins,
                )
                .await;
            }
            Err(super::server::H3RequestBodyReadError::DeadlineExceeded) => {
                ctx.mark_gateway_deadline_response_selected();
                release_cross_protocol_circuit_breaker_probe_on_admission_reject(
                    state,
                    proxy,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                );
                let mut outcome = write_final_body_reject(
                    stream,
                    HttpFlavor::Grpc,
                    plugins,
                    ctx,
                    crate::plugins::grpc_deadline_exceeded_plugin_result(),
                    response_committed_plugins,
                    initial_response_header_policy_plugins,
                    RejectWriteAccounting {
                        backend_start,
                        bytes_sent: 0,
                    },
                )
                .await?;
                crate::proxy::log_rejected_request(
                    plugins,
                    ctx,
                    outcome.response_status,
                    backend_start,
                    "grpc_deadline_buffered_h3_bridge_upload",
                    0,
                )
                .await;
                outcome.rejection_logged = true;
                return Ok(outcome);
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
        ctx.request_is_secure,
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
    let mut backend_admission_permits =
        if let Some(permits) = preacquired_backend_admission.take_if_acquired() {
            permits
        } else {
            match run_cross_protocol_backend_admission_or_reject(
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
            }
        };
    record_cross_protocol_connection_start(upstream_balancer, current_target.as_deref());
    // `hmap` already contains the complete backend-bound header set
    // (plugin-transformed end-to-end headers + canonical forwarding
    // headers synthesized by this bridge). Passing the original
    // `proxy_headers` again would let the shared gRPC core overwrite
    // canonical forwarding values (`x-forwarded-*`, `via`, `forwarded`), so
    // pass ONLY the gateway-trusted plugin assertions: the core's merge strips
    // reserved `x-consumer-*` and `x-geo-country` from `hmap` and re-adds them
    // solely from this arg, so an empty map would drop the authenticated
    // principal and authoritative geo result.
    let trusted_assertion_headers = trusted_plugin_assertion_proxy_headers(proxy_headers);
    let grpc_connection_proxy =
        crate::proxy::resolve_backend_connection_proxy_for_target(proxy, current_target.as_deref());
    let grpc_dispatch_proxy = grpc_connection_proxy.as_ref();
    let mut result = proxy_grpc_request_from_bytes(
        hyper_method.clone(),
        initial_hmap,
        initial_body,
        grpc_dispatch_proxy,
        &current_url,
        &state.grpc_pool,
        &state.dns_cache,
        &trusted_assertion_headers,
        stream_grpc_response,
        state.max_response_body_size_bytes,
        ctx.grpc_deadline_at(),
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

            let retry_target = select_next_cross_protocol_retry_target(
                state,
                epoch,
                proxy,
                lb_hash_key,
                current_target.as_ref(),
                strip_len,
                backend_path_is_policy_bound,
                path,
                query_string,
                client_ip,
                proxy_headers,
            );
            if matches!(&retry_target, CrossProtocolRetryTarget::BackendPathMismatch) {
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
            if let Some(deadline) = ctx.grpc_deadline_at() {
                if tokio::time::timeout_at(deadline, tokio::time::sleep(delay))
                    .await
                    .is_err()
                {
                    result = Err(grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(
                        "gRPC deadline exceeded during retry backoff".to_string(),
                    ));
                    break;
                }
            } else {
                tokio::time::sleep(delay).await;
            }
            attempt += 1;

            if let CrossProtocolRetryTarget::Selected(next_target, next_cb_target_key, next_url) =
                retry_target
            {
                current_target = Some(next_target);
                current_cb_target_key = Some(next_cb_target_key);
                current_url = next_url;
            }

            // Re-screen the rotated target for mesh transport tags (issue
            // #2003): the pre-dispatch guard above only classified the FIRST
            // selected target, and a rotation onto a mesh-tagged target (mixed
            // mesh/non-mesh upstream) must fail closed, never direct-dial past
            // the secured transport. The prior attempt's failure was already
            // recorded and the probe slot released above, so only the refusal
            // is written here.
            if let Some(message) = grpc_mesh_transport_refusal(current_target.as_deref()) {
                warn!(
                    proxy_id = %proxy.id,
                    target_host = current_target.as_deref().map(|t| t.host.as_str()).unwrap_or(""),
                    message,
                    "cross-protocol H3→gRPC: retry rotated onto a mesh-transport-tagged target; \
                     refusing the direct dial and failing closed with gRPC UNAVAILABLE"
                );
                return write_grpc_error_for_request(
                    stream,
                    ctx,
                    grpc_proxy::grpc_status::UNAVAILABLE,
                    message,
                    backend_start,
                    bytes_sent,
                    initial_response_header_policy_plugins,
                )
                .await;
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
            let grpc_retry_connection_proxy =
                crate::proxy::resolve_backend_connection_proxy_for_target(
                    proxy,
                    current_target.as_deref(),
                );
            let grpc_retry_dispatch_proxy = grpc_retry_connection_proxy.as_ref();
            result = proxy_grpc_request_from_bytes(
                hyper_method.clone(),
                hmap.clone(),
                body_bytes.clone(),
                grpc_retry_dispatch_proxy,
                &current_url,
                &state.grpc_pool,
                &state.dns_cache,
                &trusted_assertion_headers,
                stream_grpc_response,
                state.max_response_body_size_bytes,
                ctx.grpc_deadline_at(),
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
            if let Some(grpc_status) =
                crate::proxy::grpc_proxy::grpc_status_from_maps(&resp.trailers, &resp.headers)
            {
                ctx.metadata
                    .insert("grpc_status".to_string(), grpc_status.to_string());
            }
            let (mut plugin_response_headers, header_shadowed_trailer_keys) =
                crate::proxy::grpc_proxy::build_grpc_plugin_header_view(
                    &resp.headers,
                    &resp.trailers,
                );
            // Same gRPC-Web trailer-frame provenance as the H1/H2 buffered path:
            // record backend trailer names so the body frame does not copy
            // initial-header-only fields from the merged plugin view.
            if crate::plugins::grpc_web::request_is_grpc_web_translated(ctx) {
                crate::plugins::grpc_web::record_backend_trailer_names_for_frame(
                    &mut ctx.metadata,
                    &resp.trailers,
                );
            }
            let mut authoritative_trailers_only_terminal_metadata = (resp.body.is_empty()
                && resp.trailers.is_empty())
            .then(|| {
                crate::proxy::grpc_proxy::GrpcTerminalMetadataSnapshot::from_headers(&resp.headers)
            });
            // A gRPC-Web client's terminal metadata rides in the BODY trailer
            // frame, and the gateway-authored replacements below empty the
            // header/trailer maps of `grpc-status` on purpose because that is the
            // shape the client must receive. Track when that happened so the
            // metadata refresh does not read the emptied maps as a hook-removed
            // status and overwrite the status the replacement recorded with the
            // synthesized UNKNOWN(2). Same rule, same reason, as the buffered
            // H1/H2 gRPC path in `proxy::handle_proxy_request`.
            let client_terminal_metadata_is_body_framed =
                crate::plugins::grpc_web::client_uses_grpc_web(ctx);
            let mut terminal_metadata_is_body_framed = false;
            // Capture original response invariants before `after_proxy` rewrites
            // the header view below, exactly as `dispatch_plain` and the native
            // H3 path do. `resp.headers` is the untouched backend initial header
            // map, so the shared representation gate can prove this response's
            // original content coding and range/delta state instead of reading a
            // header map a hook may already have rewritten.
            crate::http3::server::stamp_h3_original_response_metadata(
                ctx,
                resp.status,
                &resp.headers,
            );
            ctx.begin_buffered_initial_response_header_policy(
                initial_response_header_policy_names,
                &resp.headers,
                &plugin_response_headers,
            );
            let after_proxy_reject = if !plugins.is_empty() {
                crate::proxy::run_after_proxy_hooks(
                    plugins,
                    ctx,
                    resp.status,
                    &mut plugin_response_headers,
                )
                .await
            } else {
                None
            };
            let mut buffered_initial_response_header_policy_state =
                ctx.take_buffered_initial_response_header_policy();
            if let Some(reject) = after_proxy_reject {
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
                    response_committed_plugins,
                    initial_response_header_policy_plugins,
                    RejectWriteAccounting {
                        backend_start,
                        bytes_sent,
                    },
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
                            false,
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
            if normalize_response_body_for_inspection(
                plugins,
                ctx,
                response_status,
                &mut plugin_response_headers,
                &mut response_body,
                initial_response_header_policy_plugins,
            )
            .await
            {
                if ctx.gateway_deadline_response_selected() {
                    crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
                        &plugin_response_headers,
                        &mut response_trailers,
                        &mut authoritative_trailers_only_terminal_metadata,
                    );
                    terminal_metadata_is_body_framed |= client_terminal_metadata_is_body_framed;
                } else {
                    // Same ordering contract as the transform phase below: the
                    // decode-only normalize rewrite must not let the trailer
                    // retirement masquerade as a policy-owned header removal.
                    if let Some(policy_state) =
                        buffered_initial_response_header_policy_state.as_mut()
                    {
                        Arc::make_mut(policy_state)
                            .record_later_response_header_mutations(&mut plugin_response_headers);
                    }
                    crate::proxy::grpc_proxy::discard_grpc_application_trailers_after_body_rewrite(
                        &mut plugin_response_headers,
                        &mut response_trailers,
                        &header_shadowed_trailer_keys,
                    );
                }
            }
            // Set once an earlier body phase selects a gateway-authored terminal
            // response. Transforms still run so gRPC-Web can emit the correct
            // client wire shape, but final-body validators must not replace the
            // selected error.
            let mut response_body_rejected = false;
            for plugin in plugins.iter() {
                let result = match crate::plugins::await_grpc_deadline(
                    ctx.grpc_deadline_at(),
                    plugin.on_response_body(
                        ctx,
                        response_status,
                        &plugin_response_headers,
                        &response_body,
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(()) => {
                        ctx.mark_gateway_deadline_response_selected();
                        crate::plugins::grpc_deadline_exceeded_plugin_result()
                    }
                };
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
                        crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
                            &plugin_response_headers,
                            &mut response_trailers,
                            &mut authoritative_trailers_only_terminal_metadata,
                        );
                        buffered_initial_response_header_policy_state = None;
                        response_body_rejected = true;
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
            //
            // The shared representation gate runs first, on the same merged view
            // the transforms see. A rejection here replaces the response, so the
            // backend trailers no longer describe the bytes being sent and are
            // dropped — the same rule the deadline replacement below follows.
            let grpc_web_response_content_type =
                crate::plugins::grpc_web::retained_response_content_type(ctx);
            let admission = crate::proxy::admit_buffered_response_body_transforms(
                plugins,
                ctx,
                crate::proxy::buffered_response_representation_origin(response_body_rejected),
                &mut response_status,
                &mut plugin_response_headers,
                &mut response_body,
                grpc_web_response_content_type,
                crate::proxy::InitialResponseHeaderPolicySource::Prefiltered(
                    initial_response_header_policy_plugins,
                ),
                true,
            )
            .await;
            if matches!(
                admission,
                crate::proxy::BufferedTransformAdmission::Rejected
            ) {
                crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
                    &plugin_response_headers,
                    &mut response_trailers,
                    &mut authoritative_trailers_only_terminal_metadata,
                );
                buffered_initial_response_header_policy_state = None;
                terminal_metadata_is_body_framed |= grpc_web_response_content_type.is_some();
                response_body_rejected = true;
            }
            let mut representation_rewritten = matches!(
                admission,
                crate::proxy::BufferedTransformAdmission::Proceed {
                    representation_rewritten: true,
                    ..
                }
            );
            if matches!(
                admission,
                crate::proxy::BufferedTransformAdmission::Proceed {
                    rewrite_allowed: true,
                    ..
                }
            ) {
                for plugin in plugins.iter() {
                    let transformed = match crate::plugins::await_grpc_deadline(
                        ctx.grpc_deadline_at(),
                        plugin.transform_response_body_with_context(
                            &mut *ctx,
                            &response_body,
                            content_type_of(&plugin_response_headers),
                            &plugin_response_headers,
                        ),
                    )
                    .await
                    {
                        Ok(transformed) => transformed,
                        Err(()) => {
                            replace_buffered_grpc_response_with_deadline(
                                ctx,
                                &mut response_status,
                                &mut plugin_response_headers,
                                &mut response_body,
                                &mut response_trailers,
                                initial_response_header_policy_plugins,
                            );
                            crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
                                &plugin_response_headers,
                                &mut response_trailers,
                                &mut authoritative_trailers_only_terminal_metadata,
                            );
                            terminal_metadata_is_body_framed |=
                                client_terminal_metadata_is_body_framed;
                            response_body_rejected = true;
                            break;
                        }
                    };
                    if let Some(transformed) = transformed {
                        plugin_response_headers
                            .insert("content-length".to_string(), transformed.len().to_string());
                        response_body = transformed;
                        crate::plugins::finalize_response_body_transformation(
                            plugin.as_ref(),
                            ctx,
                            &mut plugin_response_headers,
                        );
                        representation_rewritten = true;
                    }
                    ctx.record_deadline_response_header_plugin(
                        plugin.as_ref(),
                        &plugin_response_headers,
                    );
                }
            }
            // Mirror the main buffered gRPC path: record genuine transform-phase
            // edits before retiring stale compatibility-view trailers, so a
            // policy-owned initial header the backend also sent as a trailer is
            // not mistaken for a later intentional removal.
            if let Some(policy_state) = buffered_initial_response_header_policy_state.as_mut() {
                Arc::make_mut(policy_state)
                    .record_later_response_header_mutations(&mut plugin_response_headers);
            }
            if representation_rewritten {
                crate::proxy::grpc_proxy::discard_grpc_application_trailers_after_body_rewrite(
                    &mut plugin_response_headers,
                    &mut response_trailers,
                    &header_shadowed_trailer_keys,
                );
            }
            if !response_body_rejected {
                for plugin in plugins.iter() {
                    let result = match crate::plugins::await_grpc_deadline(
                        ctx.grpc_deadline_at(),
                        plugin.on_final_response_body(
                            ctx,
                            response_status,
                            &plugin_response_headers,
                            &response_body,
                        ),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(()) => {
                            ctx.mark_gateway_deadline_response_selected();
                            crate::plugins::grpc_deadline_exceeded_plugin_result()
                        }
                    };
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
                            crate::proxy::grpc_proxy::select_buffered_grpc_terminal_response(
                                &plugin_response_headers,
                                &mut response_trailers,
                                &mut authoritative_trailers_only_terminal_metadata,
                            );
                            buffered_initial_response_header_policy_state = None;
                            break;
                        }
                    }
                }
            }

            // Reconcile hook edits/removals from the merged view back into the
            // wire trailers, then assemble the initial HEADERS frame from the
            // view. H3 keeps the split wire shape whenever the backend supplied
            // real trailers. A backend Trailers-Only response instead already
            // carries terminal metadata in an END_STREAM initial HEADERS block;
            // when the body and trailer map are empty, preserve those existing
            // terminal fields across policy replay. `resp.headers` still holds
            // the pristine backend initial headers for the shadowed-key edit
            // detection. Strip merged trailer copies (and any trailer-only keys)
            // out of the initial headers; header-shadowed keys stay real headers
            // whose true trailing value rides the wire trailer.
            //
            // Capture the backend's original trailer `set-cookie` (issue #1638)
            // before reconciliation overwrites it, mirroring the main gRPC path.
            let original_trailer_set_cookie = response_trailers.get("set-cookie").cloned();
            crate::proxy::grpc_proxy::reconcile_grpc_trailers_from_view(
                &mut response_trailers,
                &plugin_response_headers,
                &resp.headers,
                &header_shadowed_trailer_keys,
                buffered_initial_response_header_policy_state.as_deref(),
            );
            // Admission retains the pristine backend status; transaction
            // metadata follows the post-hook status that the H3 client sees.
            crate::proxy::grpc_proxy::refresh_grpc_status_metadata_with_body_framed_terminal(
                &mut ctx.metadata,
                &response_trailers,
                &plugin_response_headers,
                terminal_metadata_is_body_framed,
            );
            let mut response_headers = plugin_response_headers;
            let authoritative_terminal_metadata =
                if response_body.is_empty() && response_trailers.is_empty() {
                    authoritative_trailers_only_terminal_metadata.as_ref()
                } else {
                    None
                };
            crate::proxy::grpc_proxy::finalize_buffered_grpc_split_response(
                &mut response_headers,
                &mut response_trailers,
                &header_shadowed_trailer_keys,
                buffered_initial_response_header_policy_state.as_deref(),
                authoritative_terminal_metadata,
                original_trailer_set_cookie.as_deref(),
            );
            // Inject the sticky-affinity cookie onto the final initial headers,
            // matching the main gRPC path's ordering. Doing it here rather than on
            // the merged view ensures it lands in the wire HEADERS frame even when
            // the backend sent a trailer-only `set-cookie` (a non-shadowed trailer
            // key that the strip loop above just removed from the headers).
            // The buffered variant also records the affinity cookie as
            // gateway-owned before the `response_committed` hooks below can
            // rebuild this response as a gRPC deadline error, which retains
            // gateway-owned headers only.
            crate::http3::server::inject_sticky_cookie_with_deadline_provenance(
                ctx,
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

            if !response_committed_plugins.is_empty()
                && crate::proxy::run_deadline_bounded_response_committed_hooks(
                    response_committed_plugins,
                    ctx,
                    &mut response_status,
                    &mut response_headers,
                    &mut response_body,
                    initial_response_header_policy_plugins,
                )
                .await
            {
                response_trailers.clear();
            }

            let grpc_deadline_at = ctx.grpc_deadline_at();
            let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
            let header_write = if terminal_gateway_deadline {
                crate::http3::stream_util::await_terminal_response_write_before_deadline(
                    grpc_deadline_at,
                    send_response_headers(stream, response_status, &response_headers),
                )
                .await
            } else {
                crate::http3::stream_util::await_response_write_before_deadline(
                    grpc_deadline_at,
                    send_response_headers(stream, response_status, &response_headers),
                )
                .await
            };
            if let Err(error) = header_write {
                if matches!(
                    error,
                    crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
                ) {
                    crate::proxy::insert_grpc_error_metadata(
                        &mut ctx.metadata,
                        grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                        GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                    );
                    crate::http3::stream_util::abort_response_stream(stream);
                } else {
                    debug!("cross-protocol H3 gRPC buffered response header write failed");
                }
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
                    false,
                    bytes_sent,
                    backend_start,
                    Some(strip_query_from_backend_url(&current_url)),
                    final_backend_resolved_ip.clone(),
                ));
            }
            let mut bytes_streamed = 0;
            let mut body_completed = true;
            let mut client_disconnected = false;
            if !response_body.is_empty() {
                let body_len = response_body.len() as u64;
                let body_write = if terminal_gateway_deadline {
                    crate::http3::stream_util::await_terminal_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.send_data(Bytes::from(response_body)),
                    )
                    .await
                } else {
                    crate::http3::stream_util::await_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.send_data(Bytes::from(response_body)),
                    )
                    .await
                };
                match body_write {
                    Ok(()) => bytes_streamed = body_len,
                    Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                        crate::proxy::insert_grpc_error_metadata(
                            &mut ctx.metadata,
                            grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                        );
                        crate::http3::stream_util::abort_response_stream(stream);
                        body_completed = false;
                    }
                    Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                        debug!("cross-protocol H3 gRPC body send_data failed");
                        client_disconnected = true;
                        body_completed = false;
                    }
                }
            }
            if body_completed && !response_trailers.is_empty() {
                let trailer_map = headers_to_header_map(&response_trailers);
                let trailer_write = if terminal_gateway_deadline {
                    crate::http3::stream_util::await_terminal_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.send_trailers(trailer_map),
                    )
                    .await
                } else {
                    crate::http3::stream_util::await_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.send_trailers(trailer_map),
                    )
                    .await
                };
                let trailer_and_finish = match trailer_write {
                    Ok(()) if terminal_gateway_deadline => {
                        crate::http3::stream_util::await_terminal_response_write_before_deadline(
                            grpc_deadline_at,
                            stream.finish(),
                        )
                        .await
                    }
                    Ok(()) => {
                        crate::http3::stream_util::await_response_write_before_deadline(
                            grpc_deadline_at,
                            stream.finish(),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                if let Err(error) = trailer_and_finish {
                    if matches!(
                        error,
                        crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
                    ) {
                        crate::proxy::insert_grpc_error_metadata(
                            &mut ctx.metadata,
                            grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                        );
                        crate::http3::stream_util::abort_response_stream(stream);
                    } else {
                        warn!("H3 gRPC trailer or FIN write failed");
                        client_disconnected = true;
                    }
                    body_completed = false;
                }
            } else if body_completed {
                let finish = if terminal_gateway_deadline {
                    crate::http3::stream_util::await_terminal_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.finish(),
                    )
                    .await
                } else {
                    crate::http3::stream_util::await_response_write_before_deadline(
                        grpc_deadline_at,
                        stream.finish(),
                    )
                    .await
                };
                if let Err(error) = finish {
                    if matches!(
                        error,
                        crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
                    ) {
                        crate::proxy::insert_grpc_error_metadata(
                            &mut ctx.metadata,
                            grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                        );
                        crate::http3::stream_util::abort_response_stream(stream);
                    } else {
                        debug!("H3 stream finish failed");
                        client_disconnected = true;
                    }
                    body_completed = false;
                }
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
                response_streamed: false,
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
                rejection_logged: false,
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
                initial_response_header_policy_plugins,
                ctx,
                sticky_cookie_needed,
                bytes_sent,
                &current_url,
                final_backend_resolved_ip.clone(),
                // Buffered-request path: the body was fully drained + size-checked
                // before dispatch, so there is no streaming pump / client-abort flag.
                None,
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
                grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_) => (
                    grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                ),
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
            let connection_error =
                !matches!(&err, grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_))
                    && !crate::retry::request_reached_wire(error_class);
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
            let mut outcome = write_grpc_error_for_request(
                stream,
                ctx,
                grpc_status_code,
                grpc_message,
                backend_start,
                bytes_sent,
                initial_response_header_policy_plugins,
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
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error> {
    let mut stream = stream;
    let current_target = upstream_target.cloned().map(Arc::new);
    let current_cb_target_key = cb_target_key.map(str::to_owned);

    // FAIL CLOSED on a mesh-transport-tagged target BEFORE dialing (issue
    // #2003, see `grpc_mesh_transport_refusal`). No retry / rotation exists on
    // this path, so the single pre-dispatch check covers it. The probe slot a
    // HALF_OPEN breaker may have admitted is released, mirroring the buffered
    // path's pre-dispatch rejects.
    if let Some(message) = grpc_mesh_transport_refusal(current_target.as_deref()) {
        warn!(
            proxy_id = %proxy.id,
            target_host = current_target.as_deref().map(|t| t.host.as_str()).unwrap_or(""),
            message,
            "cross-protocol H3→gRPC streaming: refusing direct dial to a \
             mesh-transport-tagged target; failing closed with gRPC UNAVAILABLE"
        );
        release_cross_protocol_circuit_breaker_probe_on_admission_reject(
            state,
            proxy,
            current_cb_target_key.as_deref(),
            cb_is_half_open_probe,
        );
        return write_grpc_error_for_request(
            &mut stream,
            ctx,
            grpc_proxy::grpc_status::UNAVAILABLE,
            message,
            backend_start,
            0,
            initial_response_header_policy_plugins,
        )
        .await;
    }

    let hyper_method = match hyper::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return write_grpc_error_for_request(
                &mut stream,
                ctx,
                grpc_proxy::grpc_status::UNIMPLEMENTED,
                "Method Not Allowed",
                backend_start,
                0,
                initial_response_header_policy_plugins,
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
        ctx.request_is_secure,
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
    // Set by the pump when the H3 recv half errors (the client reset its upload).
    // The resulting backend RST must be recorded as a CLIENT abort, not a backend
    // fault (codex P2) — read in the dispatch Err arm below.
    let frontend_upload_failed = Arc::new(AtomicBool::new(false));
    let pump_frontend_failed = Arc::clone(&frontend_upload_failed);
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
                            // The send MUST stay cancellable (codex P1): on
                            // bounded-channel backpressure, a bidi backend that
                            // finished its response and stopped polling the request
                            // body would otherwise park us forever inside
                            // `tx.send(...).await`, and the post-response
                            // `pump_shutdown.notify_one()` (observed only by this
                            // select) could never unblock the awaited `pump`.
                            let send_result = tokio::select! {
                                biased;
                                _ = pump_shutdown_signal.notified() => break,
                                res = tx.send(Ok(body_bytes)) => res,
                            };
                            if send_result.is_err() {
                                // Backend dropped the request body (RPC done / RST):
                                // nothing left to feed.
                                break;
                            }
                        }
                        // Clean client half-close: drop `tx` so the channel body
                        // observes END_STREAM and forwards the FIN to the backend.
                        Ok(None) => break,
                        Err(_e) => {
                            // Frontend upload failure: flag it (so the dispatch Err
                            // arm records a client abort, not a backend fault) and
                            // best-effort signal the channel body to RST the backend
                            // instead of sending a clean END_STREAM. The send stays
                            // cancellable for the same reason as the data send above.
                            pump_frontend_failed.store(true, Ordering::Release);
                            tokio::select! {
                                biased;
                                _ = pump_shutdown_signal.notified() => {}
                                _ = tx.send(Err(())) => {}
                            }
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
    // forwarding headers, so don't re-pass the full `proxy_headers` (the core
    // would re-merge and overwrite them) — pass only the gateway-trusted plugin
    // assertions, since the core's merge strips reserved `x-consumer-*` and
    // `x-geo-country` from `hmap` and re-adds them solely from this arg. An empty
    // map would drop the authenticated principal and authoritative geo result.
    let body_size_exceeded = Arc::new(AtomicBool::new(false));
    let trusted_assertion_headers = trusted_plugin_assertion_proxy_headers(proxy_headers);
    let grpc_connection_proxy =
        crate::proxy::resolve_backend_connection_proxy_for_target(proxy, current_target.as_deref());
    let grpc_dispatch_proxy = grpc_connection_proxy.as_ref();
    // Retain an unread channel upload across pre-wire dispatch failures so the
    // H3 Trailers-Only error is written before the upload side is dropped
    // (#2057 ordering contract, mirrored from the H2 streaming path).
    let mut held_frontend_grpc_upload = None;
    let result = grpc_proxy::proxy_grpc_request_streaming_channel(
        hyper_method,
        hmap,
        rx,
        grpc_dispatch_proxy,
        backend_url,
        &state.grpc_pool,
        &trusted_assertion_headers,
        state.max_grpc_recv_size_bytes,
        Arc::clone(&body_size_exceeded),
        None,
        ctx.grpc_deadline_at(),
        &mut held_frontend_grpc_upload,
    )
    .await;

    let final_backend_resolved_ip =
        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref()).await;

    let outcome_result: Result<CrossProtocolOutcome, anyhow::Error> = match result {
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
                initial_response_header_policy_plugins,
                ctx,
                sticky_cookie_needed,
                bytes_sent,
                backend_url,
                final_backend_resolved_ip.clone(),
                Some(&frontend_upload_failed),
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
            write_grpc_error_send_with_policy(
                &mut send_half,
                grpc_proxy::grpc_status::INTERNAL,
                "Internal gateway error",
                backend_start,
                bytes_sent,
                initial_response_header_policy_plugins,
            )
            .await
            .map(|mut outcome| {
                outcome.backend_target = Some(strip_query_from_backend_url(backend_url));
                outcome.error_class = Some(ErrorClass::ProtocolError);
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                outcome
            })
        }
        Err(err) => {
            let bytes_sent = request_bytes_seen.load(Ordering::Relaxed);
            let (grpc_status_code, grpc_message): (u32, &str) = match &err {
                grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_) => (
                    grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                ),
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
            // Two pre-headers failures on this path are CLIENT/gateway-side, not
            // backend faults, and must train neither backend health nor adaptive
            // concurrency (both neutralized by `client_side_no_backend_signal`):
            //   * `ResourceExhausted` — the gateway rejected an oversized client
            //     upload (the channel body tripped `max_grpc_recv_size_bytes`).
            //   * a frontend upload abort — the H3 recv half errored, so the pump
            //     set `frontend_upload_failed` and RST the backend; the resulting
            //     `BackendUnavailable` is a consequence of the client reset.
            // Both mirror the buffered H3 path, which releases the probe without
            // training backend health (codex P2). Every other error keeps the
            // wire-boundary derivation so a real backend failure still trains the
            // limiter.
            let request_overflow = matches!(&err, grpc_proxy::GrpcProxyError::ResourceExhausted(_));
            let frontend_aborted = frontend_upload_failed.load(Ordering::Acquire);
            let client_deadline =
                matches!(&err, grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_));
            let error_class = if request_overflow {
                ErrorClass::RequestBodyTooLarge
            } else if frontend_aborted {
                ErrorClass::ClientDisconnect
            } else {
                crate::retry::classify_grpc_proxy_error(&err)
            };
            let connection_error = !client_deadline
                && !request_overflow
                && !frontend_aborted
                && !crate::retry::request_reached_wire(error_class);
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
            // Drop the held upload only after the Trailers-Only error is queued
            // on the H3 send half (#2057).
            let grpc_error_write = write_grpc_error_send_with_policy(
                &mut send_half,
                grpc_status_code,
                grpc_message,
                backend_start,
                bytes_sent,
                initial_response_header_policy_plugins,
            )
            .await
            .map(|mut outcome| {
                outcome.backend_target = Some(strip_query_from_backend_url(backend_url));
                outcome.connection_error = connection_error;
                outcome.error_class = Some(error_class);
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                outcome
            });
            drop(held_frontend_grpc_upload.take());
            grpc_error_write
        }
    };

    // Pump cleanup ALWAYS runs — even if the response / error write above failed
    // (the `?` is deferred until after this). `notify_one` stores a permit so
    // there is no lost wakeup, and the pump's data/abort sends are cancellable
    // (codex P1), so the join cannot hang on a full channel.
    pump_shutdown.notify_one();
    let _ = pump.await;

    let mut outcome = outcome_result?;
    // Final upload byte count (codex P2): in bidi/client-streaming the pump can
    // forward request DATA while the response is streaming, so re-read after the
    // pump terminates rather than trusting the header-time snapshot.
    outcome.bytes_sent = request_bytes_seen.load(Ordering::Relaxed);
    Ok(outcome)
}

async fn apply_buffered_plain_plugin_reject(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
) {
    let Some(mut reject) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("buffered plain reject helper received a non-reject plugin result");
        return;
    };
    let mut headers = reject.headers;
    crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        &mut reject.status_code,
        &mut reject.body,
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
    let Some(mut reject) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("buffered gRPC reject helper received a non-reject plugin result");
        return;
    };
    let mut headers = reject.headers;
    crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        &mut reject.status_code,
        &mut reject.body,
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

fn normalized_h3_grpc_deadline() -> crate::proxy::NormalizedRejectResponse {
    normalize_h3_grpc_reject(
        StatusCode::OK,
        &[],
        &HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            (
                "grpc-status".to_string(),
                GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER.to_string(),
            ),
            (
                "grpc-message".to_string(),
                GATEWAY_DEADLINE_EXCEEDED_MESSAGE.to_string(),
            ),
        ]),
    )
}

fn replace_buffered_grpc_response_with_deadline(
    ctx: &mut RequestContext,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
    response_trailers: &mut HashMap<String, String>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) {
    let grpc_web_response_content_type =
        crate::plugins::grpc_web::retained_response_content_type(ctx).or_else(|| {
            response_headers
                .get("content-type")
                .filter(|content_type| {
                    crate::plugins::grpc_web::is_grpc_web_content_type(content_type)
                })
                .map(|content_type| crate::plugins::grpc_web::response_content_type(content_type))
        });
    *response_status = crate::http3::server::replace_buffered_h3_response_with_grpc_deadline(
        ctx,
        grpc_web_response_content_type,
        response_headers,
        response_body,
        initial_response_header_policy_plugins,
    )
    .as_u16();
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
/// `(bytes_streamed, body_completed, client_disconnected, body_error_class,
/// trailers, client_deadline_expired)`.
async fn stream_hyper_incoming<S>(
    stream: &mut RequestStream<S, Bytes>,
    mut incoming: Incoming,
    coalesce: CoalesceConfig,
    max_response_body_size_bytes: usize,
    response_read_timeout_ms: u64,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> (u64, bool, bool, Option<ErrorClass>, Option<HeaderMap>, bool)
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
    let mut clean_deadline_completion = false;
    let mut client_deadline_expired = false;
    let read_timeout_active = response_read_timeout_ms > 0 && grpc_deadline_at.is_none();
    let read_deadline = tokio::time::sleep(std::time::Duration::from_millis(
        response_read_timeout_ms.max(1),
    ));
    tokio::pin!(read_deadline);
    let mut just_received_backend_frame = false;
    let grpc_deadline_active = grpc_deadline_at.is_some();
    let grpc_deadline = tokio::time::sleep_until(
        grpc_deadline_at
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400)),
    );
    tokio::pin!(grpc_deadline);

    // Every downstream write remains cancellable by the same absolute RPC
    // deadline. `send_data`/`finish` can otherwise park forever waiting for
    // QUIC flow-control credit, preventing the select loop from polling its
    // timer and retaining the upstream H2 body indefinitely.
    macro_rules! await_downstream_write {
        ($write:expr) => {{
            match crate::http3::stream_util::await_response_write_before_deadline(
                grpc_deadline_at,
                $write,
            )
            .await
            {
                Ok(()) => true,
                Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                    client_deadline_expired = true;
                    coalesce_buf.clear();
                    if crate::http3::stream_util::grpc_deadline_can_send_terminal_status(
                        bytes_streamed,
                    ) {
                        let mut deadline_trailers = HeaderMap::new();
                        deadline_trailers.insert(
                            "grpc-status",
                            HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER),
                        );
                        deadline_trailers.insert(
                            "grpc-message",
                            HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER),
                        );
                        trailers = Some(deadline_trailers);
                        clean_deadline_completion = true;
                    } else {
                        trailers = None;
                        crate::http3::stream_util::abort_response_stream(stream);
                    }
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    false
                }
                Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                    client_disconnected = true;
                    body_error_class = Some(ErrorClass::ClientDisconnect);
                    false
                }
            }
        }};
    }

    'outer: loop {
        if read_timeout_active && just_received_backend_frame && coalesce_buf.is_empty() {
            read_deadline.as_mut().reset(
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(response_read_timeout_ms),
            );
            just_received_backend_frame = false;
        }
        tokio::select! {
            biased;
            // The absolute RPC ceiling owns a tie with a newly-ready backend
            // frame. Otherwise a continuously-ready backend could forward DATA
            // after the client deadline and change a clean trailers-only expiry
            // into a partial-body reset.
            _ = &mut grpc_deadline, if grpc_deadline_active && !stream_done => {
                client_deadline_expired = true;
                coalesce_buf.clear();
                if crate::http3::stream_util::grpc_deadline_can_send_terminal_status(
                    bytes_streamed,
                ) {
                    let mut deadline_trailers = HeaderMap::new();
                    deadline_trailers.insert(
                        "grpc-status",
                        HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER),
                    );
                    deadline_trailers.insert(
                        "grpc-message",
                        HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER),
                    );
                    trailers = Some(deadline_trailers);
                    clean_deadline_completion = true;
                } else {
                    crate::http3::stream_util::abort_response_stream(stream);
                }
                body_error_class = Some(ErrorClass::ClientDisconnect);
                break 'outer;
            }
            frame_result = incoming.frame(), if !stream_done => {
                match frame_result {
                    Some(Ok(frame)) => {
                        just_received_backend_frame = true;
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
                                if !await_downstream_write!(stream.send_data(data)) {
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
                                if !await_downstream_write!(stream.send_data(out)) {
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
                if !await_downstream_write!(stream.send_data(out)) {
                    break 'outer;
                }
                bytes_streamed += out_len;
                flush_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + coalesce.flush_interval);
            }
            _ = &mut read_deadline, if read_timeout_active && !stream_done && coalesce_buf.is_empty() => {
                warn!(
                    "Backend read timeout ({}ms) during cross-protocol H3 gRPC response body; aborting",
                    response_read_timeout_ms
                );
                crate::http3::stream_util::abort_response_stream(stream);
                body_error_class = Some(ErrorClass::ReadWriteTimeout);
                break 'outer;
            }
        }
        if stream_done {
            if !coalesce_buf.is_empty() {
                let out = coalesce_buf.split().freeze();
                let out_len = out.len() as u64;
                if !await_downstream_write!(stream.send_data(out)) {
                    break 'outer;
                }
                bytes_streamed += out_len;
            }
            // When trailers are present, the caller writes the trailing
            // HEADERS and FIN. Empty trailers are equivalent to absent here:
            // no trailers frame is needed, but the QUIC stream still must be
            // closed with FIN.
            if should_finish_h3_stream_without_trailers(trailers.as_ref())
                && let Err(error) = crate::http3::stream_util::await_response_write_before_deadline(
                    grpc_deadline_at,
                    stream.finish(),
                )
                .await
            {
                if matches!(
                    error,
                    crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded
                ) {
                    client_deadline_expired = true;
                    crate::http3::stream_util::abort_response_stream(stream);
                } else {
                    client_disconnected = true;
                }
                body_error_class = Some(ErrorClass::ClientDisconnect);
            }
            break;
        }
    }

    let body_completed =
        clean_deadline_completion || (body_error_class.is_none() && !client_disconnected);
    (
        bytes_streamed,
        body_completed,
        client_disconnected,
        body_error_class,
        trailers,
        client_deadline_expired,
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
    // Final hop-by-hop strip after after_proxy: connection-specific fields are
    // malformed on HTTP/3 (RFC 9114 §4.2). Clone only when stripping is needed
    // so the common clean map stays allocation-free on this path.
    let mut owned_headers;
    let headers = if has_client_response_hop_by_hop_headers(headers) {
        owned_headers = headers.clone();
        strip_client_response_hop_by_hop_headers(&mut owned_headers);
        &owned_headers
    } else {
        headers
    };
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_builder = crate::proxy::headers::apply_response_headers(
        Response::builder().status(status_code),
        headers,
    );
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
        response_streamed: false,
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
        rejection_logged: false,
    })
}

fn normalize_reject_for_client(
    ctx: &mut RequestContext,
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
    native_grpc: bool,
) -> (
    crate::proxy::NormalizedRejectResponse,
    Option<crate::plugins::grpc_web::GrpcWebErrorResponse>,
) {
    let grpc_web = crate::plugins::grpc_web::client_uses_grpc_web(ctx);
    let normalized =
        crate::proxy::normalize_reject_response(status, body, headers, native_grpc || grpc_web);
    if native_grpc || grpc_web {
        apply_h3_grpc_reject_metadata(ctx, &normalized);
    }
    let translated = if grpc_web {
        normalized.grpc_status.and_then(|grpc_status| {
            let mut translated = crate::plugins::grpc_web::translated_error_response(
                ctx,
                grpc_status,
                normalized.grpc_message.as_deref().unwrap_or(""),
            )?;
            crate::proxy::finalize_grpc_web_error_response_headers(
                &mut translated,
                &[],
                Some(&normalized.headers),
            );
            Some(translated)
        })
    } else {
        None
    };
    (normalized, translated)
}

fn reject_committed_response_view<'a>(
    normalized: &'a crate::proxy::NormalizedRejectResponse,
    translated: Option<&'a crate::plugins::grpc_web::GrpcWebErrorResponse>,
) -> (u16, &'a HashMap<String, String>, &'a [u8]) {
    if let Some(translated) = translated {
        (
            StatusCode::OK.as_u16(),
            &translated.headers,
            &translated.body,
        )
    } else {
        (
            normalized.http_status.as_u16(),
            &normalized.headers,
            &normalized.body,
        )
    }
}

async fn run_cross_protocol_reject_committed_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    native_grpc: bool,
    normalized: &mut crate::proxy::NormalizedRejectResponse,
    translated: &mut Option<crate::plugins::grpc_web::GrpcWebErrorResponse>,
) -> bool {
    for (index, plugin) in plugins.iter().enumerate() {
        if !plugin.requires_response_committed_hook() {
            continue;
        }
        let (status, headers, body) =
            reject_committed_response_view(normalized, translated.as_ref());
        let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
        let Some(pending_hook) = crate::proxy::run_response_committed_hook_until_deadline(
            Arc::clone(plugin),
            ctx,
            status,
            headers,
            body,
            terminal_gateway_deadline,
        )
        .await
        else {
            continue;
        };

        let deadline_replaced = !terminal_gateway_deadline;
        if deadline_replaced {
            ctx.mark_gateway_deadline_response_selected();
            let deadline = normalized_h3_grpc_deadline();
            (*normalized, *translated) = normalize_reject_for_client(
                ctx,
                deadline.http_status,
                &deadline.body,
                &deadline.headers,
                native_grpc,
            );
        }
        let (status, headers, body) =
            reject_committed_response_view(normalized, translated.as_ref());
        crate::proxy::spawn_detached_response_committed_hooks(
            pending_hook,
            plugins[index + 1..].to_vec(),
            status,
            Arc::new(headers.clone()),
            Arc::new(body.to_vec()),
        );
        return deadline_replaced;
    }
    false
}

async fn write_plain_gateway_error<S>(
    stream: &mut RequestStream<S, Bytes>,
    ctx: &mut RequestContext,
    status: StatusCode,
    body: &'static str,
    extra_header: Option<(&'static str, &'static str)>,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let headers = extra_header
        .map(|(name, value)| HashMap::from([(name.to_string(), value.to_string())]))
        .unwrap_or_default();
    write_plain_gateway_reject(
        stream,
        ctx,
        status,
        body.as_bytes(),
        &headers,
        backend_start,
        bytes_sent,
    )
    .await
}

async fn write_plain_gateway_reject<S>(
    stream: &mut RequestStream<S, Bytes>,
    ctx: &mut RequestContext,
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
    backend_start: Instant,
    bytes_sent: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let (normalized, translated) = normalize_reject_for_client(ctx, status, body, headers, false);
    if let Some(translated) = translated {
        return write_reject_with_headers(
            stream,
            StatusCode::OK,
            &translated.body,
            &translated.headers,
            backend_start,
            bytes_sent,
        )
        .await;
    }
    write_reject_with_headers(
        stream,
        normalized.http_status,
        &normalized.body,
        &normalized.headers,
        backend_start,
        bytes_sent,
    )
    .await
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
    let mut headers = headers.clone();
    strip_client_response_hop_by_hop_headers(&mut headers);
    let mut resp_builder = Response::builder().status(status);
    let mut has_content_type = false;
    for (k, v) in &headers {
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
        response_streamed: false,
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
        rejection_logged: false,
    })
}

/// Handle a `PluginResult::Reject` from `on_final_request_body` by
/// emitting the right wire format for the flavor: trailers-only gRPC for
/// Grpc, HTTP + headers for Plain, 501 is never reached (WebSocket is
/// rejected upstream).
struct RejectWriteAccounting {
    backend_start: Instant,
    bytes_sent: u64,
}

fn terminal_deadline_write_aborted_outcome(
    response_status: u16,
    bytes_streamed: u64,
    backend_start: Instant,
    bytes_sent: u64,
    client_disconnected: bool,
) -> CrossProtocolOutcome {
    CrossProtocolOutcome {
        response_status,
        response_streamed: false,
        bytes_streamed,
        bytes_sent,
        backend_target: None,
        backend_resolved_ip: None,
        body_completed: false,
        client_disconnected,
        connection_error: false,
        error_class: None,
        body_error_class: client_disconnected.then_some(ErrorClass::ClientDisconnect),
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
        rejection_logged: false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_final_body_reject<S>(
    stream: &mut RequestStream<S, Bytes>,
    flavor: HttpFlavor,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    reject: PluginResult,
    response_committed_plugins: &[Arc<dyn Plugin>],
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    accounting: RejectWriteAccounting,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let RejectWriteAccounting {
        backend_start,
        bytes_sent,
    } = accounting;
    let Some(mut parts) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("final body reject helper received a non-reject plugin result");
        return if matches!(flavor, HttpFlavor::Grpc) {
            write_grpc_error_for_request(
                stream,
                ctx,
                grpc_proxy::h3_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
                "Plugin rejection normalization failed",
                backend_start,
                bytes_sent,
                initial_response_header_policy_plugins,
            )
            .await
        } else {
            write_plain_gateway_error(
                stream,
                ctx,
                StatusCode::BAD_GATEWAY,
                "{\"error\":\"Plugin rejection normalization failed\"}",
                None,
                backend_start,
                bytes_sent,
            )
            .await
        };
    };
    let mut headers = parts.headers;
    crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        &mut parts.status_code,
        &mut parts.body,
        &mut headers,
    )
    .await;
    let http_status = StatusCode::from_u16(parts.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    let (mut normalized, mut grpc_web_reject) = normalize_reject_for_client(
        ctx,
        http_status,
        &parts.body,
        &headers,
        matches!(flavor, HttpFlavor::Grpc),
    );
    run_cross_protocol_reject_committed_hooks(
        response_committed_plugins,
        ctx,
        matches!(flavor, HttpFlavor::Grpc),
        &mut normalized,
        &mut grpc_web_reject,
    )
    .await;
    // Pending committed observers continue on owned state under a post-response
    // bound, while the downstream terminal write remains best-effort: it must
    // not park forever on exhausted QUIC flow-control credit. Give the complete
    // HEADERS/DATA/FIN writer one immediate poll after expiry and reset the
    // stream if any constituent write would block.
    let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
    if let Some(translated) = grpc_web_reject {
        let write = write_reject_with_headers(
            stream,
            StatusCode::OK,
            &translated.body,
            &translated.headers,
            backend_start,
            bytes_sent,
        );
        if !terminal_gateway_deadline {
            return write.await;
        }
        match crate::http3::stream_util::await_terminal_response_write_before_deadline(
            ctx.grpc_deadline_at(),
            write,
        )
        .await
        {
            Ok(outcome) => Ok(outcome),
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                Ok(terminal_deadline_write_aborted_outcome(
                    StatusCode::OK.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    true,
                ))
            }
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                Ok(terminal_deadline_write_aborted_outcome(
                    StatusCode::OK.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    false,
                ))
            }
        }
    } else if matches!(flavor, HttpFlavor::Grpc) {
        let write = write_normalized_grpc_reject(stream, &normalized, backend_start, bytes_sent);
        if !terminal_gateway_deadline {
            return write.await;
        }
        match crate::http3::stream_util::await_terminal_response_write_before_deadline(
            ctx.grpc_deadline_at(),
            write,
        )
        .await
        {
            Ok(outcome) => Ok(outcome),
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                Ok(terminal_deadline_write_aborted_outcome(
                    normalized.http_status.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    true,
                ))
            }
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                crate::http3::stream_util::halt_request_body(stream);
                Ok(terminal_deadline_write_aborted_outcome(
                    normalized.http_status.as_u16(),
                    0,
                    backend_start,
                    bytes_sent,
                    false,
                ))
            }
        }
    } else {
        write_reject_with_headers(
            stream,
            normalized.http_status,
            &normalized.body,
            &normalized.headers,
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
    let mut headers = reject.headers.clone();
    strip_client_response_hop_by_hop_headers(&mut headers);
    let mut resp_builder = Response::builder().status(reject.http_status);
    for (key, value) in &headers {
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
        response_streamed: false,
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
        rejection_logged: false,
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
    let Some(mut parts) = crate::proxy::plugin_result_into_reject_parts(reject) else {
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
    let mut headers = parts.headers;
    crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        &mut parts.status_code,
        &mut parts.body,
        &mut headers,
    )
    .await;
    let http_status = StatusCode::from_u16(parts.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    let mut normalized = normalize_h3_grpc_reject(http_status, &parts.body, &headers);
    apply_h3_grpc_reject_metadata(ctx, &normalized);
    for (index, plugin) in plugins.iter().enumerate() {
        if !plugin.requires_response_committed_hook() {
            continue;
        }
        let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
        let Some(pending_hook) = crate::proxy::run_response_committed_hook_until_deadline(
            Arc::clone(plugin),
            ctx,
            normalized.http_status.as_u16(),
            &normalized.headers,
            &normalized.body,
            terminal_gateway_deadline,
        )
        .await
        else {
            continue;
        };
        if !terminal_gateway_deadline {
            ctx.mark_gateway_deadline_response_selected();
            normalized = normalized_h3_grpc_deadline();
            apply_h3_grpc_reject_metadata(ctx, &normalized);
        }
        crate::proxy::spawn_detached_response_committed_hooks(
            pending_hook,
            plugins[index + 1..].to_vec(),
            normalized.http_status.as_u16(),
            Arc::new(normalized.headers.clone()),
            Arc::new(normalized.body.clone()),
        );
        break;
    }
    let write = write_normalized_grpc_reject_send(stream, &normalized, backend_start, bytes_sent);
    if !ctx.gateway_deadline_response_selected() {
        return write.await;
    }
    match crate::http3::stream_util::await_terminal_response_write_before_deadline(
        ctx.grpc_deadline_at(),
        write,
    )
    .await
    {
        Ok(outcome) => Ok(outcome),
        Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => Err(error),
        Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
            crate::http3::stream_util::abort_response_stream(stream);
            Ok(terminal_deadline_write_aborted_outcome(
                normalized.http_status.as_u16(),
                0,
                backend_start,
                bytes_sent,
                false,
            ))
        }
    }
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

async fn write_grpc_error_with_policy<S>(
    stream: &mut RequestStream<S, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    backend_start: Instant,
    bytes_sent: u64,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let outcome = write_grpc_error_send_with_policy(
        stream,
        grpc_status,
        grpc_message,
        backend_start,
        bytes_sent,
        initial_response_header_policy_plugins,
    )
    .await?;
    // Full-stream caller: STOP_SENDING the recv half so a bare drop is not seen
    // as RESET_STREAM(0x0). The send-only streaming-request path
    // (`dispatch_grpc_streaming`) calls `write_grpc_error_send` directly because
    // its spawned pump owns and halts the recv half.
    crate::http3::stream_util::halt_request_body(stream);
    Ok(outcome)
}

/// Write a pre-response gRPC failure using the original client representation.
/// A translated gRPC-Web request keeps native gRPC framing toward the backend,
/// but browser clients require the terminal status in a gRPC-Web trailer frame
/// carried by the response body. Native gRPC keeps the trailers-only shape.
async fn write_grpc_error_for_request<S>(
    stream: &mut RequestStream<S, Bytes>,
    ctx: &mut RequestContext,
    grpc_status: u32,
    grpc_message: &str,
    backend_start: Instant,
    bytes_sent: u64,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    if let Some(mut translated) =
        crate::plugins::grpc_web::translated_error_response(ctx, grpc_status, grpc_message)
    {
        crate::proxy::finalize_grpc_web_error_response_headers(
            &mut translated,
            initial_response_header_policy_plugins,
            None,
        );
        crate::proxy::insert_grpc_error_metadata(&mut ctx.metadata, grpc_status, grpc_message);
        return write_reject_with_headers(
            stream,
            StatusCode::OK,
            &translated.body,
            &translated.headers,
            backend_start,
            bytes_sent,
        )
        .await;
    }

    write_grpc_error_with_policy(
        stream,
        grpc_status,
        grpc_message,
        backend_start,
        bytes_sent,
        initial_response_header_policy_plugins,
    )
    .await
}

/// Send-only gRPC error writer: writes the trailers-only gRPC error
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
    write_grpc_error_send_with_policy(
        stream,
        grpc_status,
        grpc_message,
        backend_start,
        bytes_sent,
        &[],
    )
    .await
}

async fn write_grpc_error_send_with_policy<S>(
    stream: &mut RequestStream<S, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    backend_start: Instant,
    bytes_sent: u64,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: SendStream<Bytes>,
{
    let grpc_message = sanitize_h3_grpc_message_for_header(grpc_message);
    let mut headers = HashMap::new();
    grpc_proxy::finalize_grpc_error_response_headers(
        &mut headers,
        grpc_status,
        &grpc_message,
        initial_response_header_policy_plugins,
    );
    strip_client_response_hop_by_hop_headers(&mut headers);
    let resp = apply_response_headers(Response::builder().status(StatusCode::OK), &headers)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 gRPC error response: {}", e))?;
    stream.send_response(resp).await?;
    let _ = stream.finish().await;
    Ok(CrossProtocolOutcome {
        response_status: 200,
        response_streamed: false,
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
        rejection_logged: false,
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
        apply_h3_grpc_reject_metadata, build_h3_grpc_backend_headers, build_plain_request_builder,
        cross_protocol_header_write_disconnect_outcome, inspected_emitted_response_limit_exceeded,
        normalize_h3_grpc_reject, record_cross_protocol_client_acquire_failure,
        record_cross_protocol_connection_start, reject_body_as_h3_grpc_message,
        release_cross_protocol_circuit_breaker_probe_on_admission_reject,
        replace_buffered_grpc_response_with_deadline, sanitize_h3_grpc_message_for_header,
        should_finish_h3_stream_without_trailers, should_skip_cross_protocol_backend_header,
    };
    use crate::config::EnvConfig;
    use crate::config::types::{CircuitBreakerConfig, GatewayConfig, Proxy, UpstreamTarget};
    use crate::dns::{DnsCache, DnsConfig};
    use crate::plugins::{Plugin, PluginResult, RequestContext, security_headers::SecurityHeaders};
    use crate::proxy::ProxyState;
    use crate::proxy::grpc_proxy::GATEWAY_DEADLINE_EXCEEDED_MESSAGE;
    use crate::retry::ErrorClass;
    use hyper::{HeaderMap, StatusCode};

    #[test]
    fn header_write_disconnect_outcome_marks_client_disconnect_without_backend_error() {
        let outcome = cross_protocol_header_write_disconnect_outcome(
            200,
            false,
            42,
            Instant::now(),
            Some("https://backend.example/path".to_string()),
            Some("192.0.2.10".to_string()),
        );

        assert_eq!(outcome.response_status, 200);
        assert!(!outcome.response_streamed);
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
    fn buffered_grpc_deadline_replacement_clears_body_and_backend_trailers() {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test.Service/Call".to_string(),
        );
        let mut status = 503;
        let mut headers =
            HashMap::from([("content-type".to_string(), "application/json".to_string())]);
        let mut body = b"backend response".to_vec();
        let mut trailers = HashMap::from([("grpc-status".to_string(), "0".to_string())]);

        replace_buffered_grpc_response_with_deadline(
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            &mut trailers,
            &[],
        );

        assert_eq!(status, 200);
        assert_eq!(headers.len(), 3);
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc")
        );
        assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
        assert_eq!(
            headers.get("grpc-message").map(String::as_str),
            Some(GATEWAY_DEADLINE_EXCEEDED_MESSAGE)
        );
        assert!(body.is_empty());
        assert!(trailers.is_empty());
        assert_eq!(
            ctx.metadata.get("grpc_status").map(String::as_str),
            Some("4")
        );
    }

    #[test]
    fn header_write_disconnect_outcome_preserves_streamed_response_path() {
        let outcome = cross_protocol_header_write_disconnect_outcome(
            200,
            true,
            7,
            Instant::now(),
            None,
            None,
        );

        assert!(outcome.response_streamed);
        assert_eq!(outcome.bytes_streamed, 0);
        assert!(!outcome.body_completed);
        assert!(outcome.client_disconnected);
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
        assert!(
            tail[..call_idx].contains("resolve_backend_connection_proxy_for_target(\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20proxy,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20current_target.as_deref(),"),
            "retry attempt must resolve the backend connection proxy after target rotation"
        );
        assert!(
            call_args.contains("grpc_retry_dispatch_proxy"),
            "retry attempt must pass the target-effective backend connection proxy; \
             argument list was:\n{}",
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
    async fn h3_cross_protocol_forwarding_uses_effective_request_scheme() {
        let mut state = minimal_proxy_state();
        state.add_forwarded_header = true;
        let proxy = minimal_proxy();
        let client = reqwest::Client::new();
        let headers = HashMap::from([("host".to_string(), "api.example".to_string())]);

        let request = build_plain_request_builder(
            &client,
            &state,
            &proxy,
            reqwest::Method::GET,
            &headers,
            "https://backend.example/path",
            "backend.example",
            "203.0.113.1",
            "203.0.113.1",
            /* request_is_secure = */ false,
            /* is_early_data = */ false,
        )
        .build()
        .expect("request should build");
        assert_eq!(
            header_value(&request, "x-forwarded-proto"),
            Some(&b"http"[..])
        );
        assert_eq!(
            header_value(&request, "forwarded"),
            Some(&b"for=203.0.113.1;proto=http;host=api.example"[..])
        );

        let grpc_headers = build_h3_grpc_backend_headers(
            &state,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            /* request_is_secure = */ false,
            /* is_early_data = */ false,
        );
        assert_eq!(
            grpc_headers
                .get("x-forwarded-proto")
                .map(|value| value.as_bytes()),
            Some(&b"http"[..])
        );
        assert_eq!(
            grpc_headers.get("forwarded").map(|value| value.as_bytes()),
            Some(&b"for=203.0.113.1;proto=http;host=api.example"[..])
        );
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
            /* request_is_secure = */ true,
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
            /* request_is_secure = */ true,
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
            /* request_is_secure = */ true,
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
            /* request_is_secure = */ true,
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
            true,
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
            true,
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
            true,
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
                 \x20\x20\x20\x20\x20\x20\x20\x20initial_body,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20grpc_dispatch_proxy,"
            ),
            "initial gRPC dispatch must move the prepared headers/body and use the \
             target-effective backend connection proxy"
        );
        assert!(
            src.contains("let grpc_connection_proxy =\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20crate::proxy::resolve_backend_connection_proxy_for_target(proxy, current_target.as_deref());"),
            "initial gRPC dispatch must resolve the backend connection proxy for the current target"
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
            body.contains("let grpc_connection_proxy =\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20crate::proxy::resolve_backend_connection_proxy_for_target(proxy, current_target.as_deref());"),
            "dispatch_grpc_streaming must resolve the backend connection proxy for the selected target"
        );
        assert!(
            body.contains(
                "proxy_grpc_request_streaming_channel(\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20hyper_method,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20hmap,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20rx,\n\
                 \x20\x20\x20\x20\x20\x20\x20\x20grpc_dispatch_proxy,"
            ),
            "dispatch_grpc_streaming must pass the selected-target effective proxy to the gRPC pool"
        );
        assert!(
            body.contains("&mut held_frontend_grpc_upload"),
            "dispatch_grpc_streaming must retain unread uploads across pre-wire failures (#2057)"
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

    /// Regression guard (codex P2): an oversized CLIENT upload on the streaming
    /// path must be recorded as a client-side terminal (`RequestBodyTooLarge`),
    /// not a synthetic backend 502, so it can never trip the circuit breaker or
    /// shrink adaptive concurrency for a healthy backend.
    #[test]
    fn h3_grpc_streaming_request_overflow_is_client_side_not_backend_fault() {
        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("pub(crate) async fn dispatch_grpc_streaming")
            .expect("dispatch_grpc_streaming not found");
        let tail = &src[start..];
        let end = tail
            .find("\nasync fn apply_buffered_plain_plugin_reject")
            .expect("end of dispatch_grpc_streaming not found");
        let body = &tail[..end];
        assert!(
            body.contains("ErrorClass::RequestBodyTooLarge"),
            "request-size overflow on the streaming path must classify as \
             RequestBodyTooLarge (client-side, neutralized by client_side_no_backend_signal) \
             so it trains neither backend health nor adaptive concurrency"
        );
        // A frontend upload abort must be recorded as a client disconnect, not a
        // backend fault (codex P2).
        assert!(
            body.contains("ErrorClass::ClientDisconnect"),
            "a frontend upload abort on the streaming path must classify as \
             ClientDisconnect so a client reset cannot poison backend health"
        );
    }

    /// Regression guard (codex P1): the request-body pump's channel send must be
    /// cancellable via the shutdown signal. A bare `tx.send(...).await` outside
    /// the `select!` lets a bidi backend that stops polling the request body while
    /// the bounded channel is full hang `pump.await` (and the request task) forever.
    #[test]
    fn h3_grpc_streaming_pump_send_is_shutdown_cancellable() {
        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("pub(crate) async fn dispatch_grpc_streaming")
            .expect("dispatch_grpc_streaming not found");
        let tail = &src[start..];
        let end = tail
            .find("\nasync fn apply_buffered_plain_plugin_reject")
            .expect("end of dispatch_grpc_streaming not found");
        let body = &tail[..end];
        assert!(
            !body.contains("tx.send(Ok(body_bytes)).await"),
            "regression: the pump's data send is a bare await — it must be cancellable \
             via pump_shutdown or `pump.await` can hang on a full channel"
        );
        assert!(
            body.contains("res = tx.send(Ok(body_bytes)) => res"),
            "the pump's data send must be a cancellable select arm racing pump_shutdown"
        );
    }

    /// Regression guard: the H3 gRPC dispatch must forward gateway-trusted
    /// consumer identity and geo assertions to the backend. The shared gRPC
    /// core's `merge_proxy_headers_and_strip_for_grpc` strips these reserved
    /// headers from the pre-built map and re-adds them ONLY from its
    /// proxy_headers arg, so passing an empty map drops the assertions. Both the
    /// buffered and streaming paths must pass the trusted-assertion map instead.
    #[test]
    fn h3_grpc_dispatch_preserves_trusted_plugin_assertions() {
        let src = include_str!("cross_protocol.rs");
        assert!(
            src.contains("fn trusted_plugin_assertion_proxy_headers"),
            "the trusted-assertion extraction helper must exist"
        );
        // Build the forbidden pattern from parts so this assertion's own source
        // text does not trip the `include_str!` self-scan.
        let forbidden_empty = ["let empty", "_proxy_headers"].concat();
        assert!(
            !src.contains(&forbidden_empty),
            "regression: an H3 gRPC dispatch declares an empty proxy_headers map for the \
             gRPC core, whose merge would then DROP the trusted x-consumer-* and \
             x-geo-country assertions"
        );
    }

    /// The H3 server and plugins may materialise trusted assertions with
    /// capitalised names, so extraction must match case-insensitively.
    #[test]
    fn trusted_plugin_assertion_headers_match_case_insensitively() {
        let mut proxy_headers = HashMap::new();
        proxy_headers.insert("X-Consumer-Username".to_string(), "alice".to_string());
        proxy_headers.insert("X-Consumer-Custom-Id".to_string(), "cid-1".to_string());
        proxy_headers.insert("X-Geo-Country".to_string(), "SE".to_string());
        proxy_headers.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());

        let assertions = super::trusted_plugin_assertion_proxy_headers(&proxy_headers);

        assert_eq!(
            assertions.get("x-consumer-username").map(String::as_str),
            Some("alice"),
            "capitalised X-Consumer-Username must be matched case-insensitively"
        );
        assert_eq!(
            assertions.get("x-consumer-custom-id").map(String::as_str),
            Some("cid-1")
        );
        assert_eq!(
            assertions.get("x-geo-country").map(String::as_str),
            Some("SE")
        );
        assert!(
            !assertions.contains_key("x-forwarded-for"),
            "only reserved plugin assertions are extracted"
        );
        assert_eq!(assertions.len(), 3);
    }

    #[test]
    fn trusted_plugin_assertion_headers_empty_without_assertions() {
        // No resolved assertion: the merge strips client-forged values and
        // re-adds nothing, preserving the spoof protection.
        let mut proxy_headers = HashMap::new();
        proxy_headers.insert("host".to_string(), "example.test".to_string());
        assert!(super::trusted_plugin_assertion_proxy_headers(&proxy_headers).is_empty());
    }

    /// Regression guard (codex P2): a late client-upload overflow on the streaming
    /// path must abort the H3 response rather than forward the backend's
    /// (possibly successful) gRPC status to the client.
    #[test]
    fn h3_grpc_streaming_late_overflow_aborts_response() {
        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("async fn handle_h3_grpc_streaming_response")
            .expect("handle_h3_grpc_streaming_response not found");
        let tail = &src[start..];
        let end = tail
            .find("\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>")
            .expect("end of handle_h3_grpc_streaming_response not found");
        let body = &tail[..end];
        assert!(
            body.contains("if request_overflowed_late {")
                && body.contains("abort_response_stream(stream)"),
            "a late request overflow must RST the response (abort_response_stream) \
             instead of forwarding the backend's success trailer"
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
            src.contains(
                "matches!(backend_http_flavor, HttpFlavor::Grpc) && can_stream_request_body"
            ),
            "H3 server must gate the streaming gRPC bridge on flavor + can_stream_request_body"
        );
        assert!(
            src.contains("cross_protocol::dispatch_grpc_streaming("),
            "H3 server must dispatch streaming-safe gRPC through dispatch_grpc_streaming"
        );
    }

    /// Retry-enabled H3-to-HTTP dispatch must pass the marked response decision
    /// context used by the H1/H2 path. Passing `None` here pins an MCP SSE
    /// response to buffering until EOF even though every active plugin permits
    /// header-time release.
    #[test]
    fn h3_plain_retry_response_refinement_uses_retry_context() {
        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("async fn dispatch_plain<S>")
            .expect("dispatch_plain not found");
        let tail = &src[start..];
        let end = tail
            .find("\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>")
            .expect("end of dispatch_plain not found");
        let body = &tail[..end];

        assert!(
            body.contains("crate::proxy::retry_response_decision_context(&*ctx)"),
            "retry-enabled H3 plain dispatch must construct the shared marked context"
        );
        assert!(
            body.contains("let response_decision_ctx = retry_ctx.as_ref().unwrap_or(&*ctx)"),
            "H3 plain dispatch must select the marked retry context after response headers"
        );
        assert!(
            body.contains("Some(response_decision_ctx)"),
            "H3 plain response refinement must receive the marked retry context"
        );
        assert!(
            !body.contains("if has_retry { None } else { Some(&*ctx) }"),
            "retry-enabled H3 plain dispatch must not suppress content-type refinement"
        );
    }

    #[test]
    fn h3_plain_grpc_web_pass_through_uses_the_absolute_rpc_deadline() {
        let server = include_str!("server.rs");
        assert!(server.contains("deadline_bound_grpc_web_pass_through"));

        let src = include_str!("cross_protocol.rs");
        let start = src
            .find("async fn dispatch_plain<S>")
            .expect("dispatch_plain not found");
        let tail = &src[start..];
        let end = tail
            .find("\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>")
            .expect("end of dispatch_plain not found");
        let body = &tail[..end];

        for required in [
            "let grpc_web_deadline_at",
            "build_plain_request_builder(",
            "tokio::time::sleep(delay)",
            "collect_reqwest_response_body_with_limit(",
            "stream_response",
            "await_response_write_before_deadline(",
            "write_plain_grpc_web_client_deadline(",
            "append_plain_grpc_web_client_deadline(",
        ] {
            assert!(
                body.contains(required),
                "missing deadline guard: {required}"
            );
        }
    }
}
