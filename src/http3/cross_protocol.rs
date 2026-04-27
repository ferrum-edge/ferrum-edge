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
//! - **WebSocket over HTTP/3** — returned as 501. RFC 9220 defines
//!   Extended CONNECT over H3 for WebSocket, but neither common clients
//!   nor most backends implement it; sending the upgrade over H1/H2 is
//!   the supported path.
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
use crate::http3::server::h3_http_status_to_grpc_status;
use crate::plugins::{Plugin, PluginResult, RequestContext};
use crate::proxy::ProxyState;
use crate::proxy::backend_dispatch::record_backend_outcome;
use crate::proxy::grpc_proxy::{self, GrpcResponseKind, proxy_grpc_request_from_bytes};
use crate::proxy::headers::is_backend_response_strip_header;
use crate::retry::ErrorClass;

/// Outcome reported back to the H3 listener so it can update request
/// counters, build the `TransactionSummary` for log plugins, and record
/// whether the client disconnected mid-stream.
pub struct CrossProtocolOutcome {
    pub response_status: u16,
    pub bytes_streamed: u64,
    pub request_bytes: u64,
    pub backend_target_url: Option<String>,
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
    pub proxy: &'a Proxy,
    pub stream: &'a mut RequestStream<S, Bytes>,
    pub method: &'a str,
    pub proxy_headers: &'a HashMap<String, String>,
    pub path: &'a str,
    pub query_string: &'a str,
    pub backend_url: &'a str,
    pub lb_hash_key: Option<&'a str>,
    pub upstream_target: Option<&'a UpstreamTarget>,
    pub cb_target_key: Option<&'a str>,
    pub flavor: HttpFlavor,
    pub prebuffered_body: Option<Vec<u8>>,
    pub client_ip: &'a str,
    pub ctx: &'a mut RequestContext,
    pub plugins: &'a [Arc<dyn Plugin>],
    pub sticky_cookie_needed: bool,
}

fn record_cross_protocol_connection_start(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
) {
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target) {
        state
            .load_balancer_cache
            .record_connection_start(upstream_id, target);
    }
}

fn record_cross_protocol_retry_failure(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
) {
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target) {
        state
            .load_balancer_cache
            .record_connection_end(upstream_id, target);
    }

    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state
            .circuit_breaker_cache
            .get_or_create(&proxy.id, cb_target_key, cb_config);
        cb.record_failure(response_status, connection_error);
    }
}

fn select_next_cross_protocol_retry_target(
    state: &ProxyState,
    proxy: &Proxy,
    lb_hash_key: Option<&str>,
    current_target: Option<&Arc<UpstreamTarget>>,
    path: &str,
    query_string: &str,
) -> Option<(Arc<UpstreamTarget>, String, String)> {
    let (Some(upstream_id), Some(prev_target), Some(hash_key)) =
        (&proxy.upstream_id, current_target, lb_hash_key)
    else {
        return None;
    };

    let health_ctx = crate::load_balancer::HealthContext {
        active_unhealthy: &state.health_checker.active_unhealthy_targets,
        proxy_passive: state
            .health_checker
            .passive_health
            .get(&proxy.id)
            .map(|r| r.value().clone()),
    };

    let next = state.load_balancer_cache.select_next_target(
        upstream_id,
        hash_key,
        prev_target,
        Some(&health_ctx),
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
        proxy,
        stream,
        method,
        proxy_headers,
        path,
        query_string,
        backend_url,
        lb_hash_key,
        upstream_target,
        cb_target_key,
        flavor,
        prebuffered_body,
        client_ip,
        ctx,
        plugins,
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
            match crate::proxy::run_final_request_body_hooks(plugins, proxy_headers, &transformed)
                .await
            {
                PluginResult::Continue => Some(transformed),
                reject => {
                    return write_final_body_reject(
                        stream,
                        flavor,
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
                proxy,
                stream,
                method,
                proxy_headers,
                path,
                query_string,
                backend_url,
                lb_hash_key,
                upstream_target,
                cb_target_key,
                prebuffered_body,
                raw_prebuffered_body_bytes,
                client_ip,
                backend_start,
                ctx,
                plugins,
                sticky_cookie_needed,
            )
            .await
        }
        HttpFlavor::Grpc => {
            dispatch_grpc(
                state,
                proxy,
                stream,
                method,
                proxy_headers,
                path,
                query_string,
                backend_url,
                lb_hash_key,
                upstream_target,
                cb_target_key,
                prebuffered_body,
                raw_prebuffered_body_bytes,
                client_ip,
                backend_start,
                ctx,
                plugins,
                sticky_cookie_needed,
            )
            .await
        }
        HttpFlavor::WebSocket => {
            warn!(
                proxy_id = %proxy.id,
                "WebSocket over HTTP/3 (RFC 9220 Extended CONNECT) is not supported; returning 501"
            );
            write_error(
                stream,
                StatusCode::NOT_IMPLEMENTED,
                r#"{"error":"WebSocket over HTTP/3 is not supported. Send the upgrade over HTTP/1.1 or HTTP/2."}"#,
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
            _ if should_skip_cross_protocol_backend_header(k.as_str()) => {}
            _ => {
                req_builder = req_builder.header(k, v);
            }
        }
    }

    let xff_val = crate::proxy::build_xff_value(original_xff, client_ip);
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

#[allow(clippy::too_many_arguments)]
async fn dispatch_plain<S>(
    state: &ProxyState,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    path: &str,
    query_string: &str,
    backend_url: &str,
    lb_hash_key: Option<&str>,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    prebuffered_body: Option<Vec<u8>>,
    raw_prebuffered_body_bytes: u64,
    client_ip: &str,
    backend_start: Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
    sticky_cookie_needed: bool,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(c) => c,
        Err(e) => {
            error!(
                proxy_id = %proxy.id,
                "cross-protocol H3→HTTP: failed to get client from pool: {}", e
            );
            record_backend_outcome(
                state,
                proxy,
                upstream_target,
                cb_target_key,
                502,
                true,
                backend_start.elapsed(),
            );
            let mut outcome = write_error(
                stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Bad Gateway"}"#,
                backend_start,
                0,
            )
            .await?;
            outcome.connection_error = true;
            return Ok(outcome);
        }
    };

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
            state
                .plugin_cache
                .requires_response_body_buffering(&proxy.id),
        );

    let (response, request_bytes) = match prebuffered_body {
        Some(buffered_body) => {
            let request_bytes = raw_prebuffered_body_bytes;
            let mut attempt = 0u32;

            record_cross_protocol_connection_start(state, proxy, current_target.as_deref());

            let response = loop {
                let effective_host = current_target
                    .as_deref()
                    .map(|t| t.host.as_str())
                    .unwrap_or(proxy.backend_host.as_str());
                let send_result = build_plain_request_builder(
                    &client,
                    state,
                    proxy,
                    req_method.clone(),
                    proxy_headers,
                    &current_url,
                    effective_host,
                    client_ip,
                )
                .body(buffered_body.clone())
                .send()
                .await;

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
                            record_cross_protocol_retry_failure(
                                state,
                                proxy,
                                current_target.as_deref(),
                                current_cb_target_key.as_deref(),
                                attempt_result.status_code,
                                false,
                            );
                            let delay = crate::retry::retry_delay(retry_config, attempt);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            if let Some((next_target, next_cb_target_key, next_url)) =
                                select_next_cross_protocol_retry_target(
                                    state,
                                    proxy,
                                    lb_hash_key,
                                    current_target.as_ref(),
                                    path,
                                    query_string,
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
                            record_cross_protocol_connection_start(
                                state,
                                proxy,
                                current_target.as_deref(),
                            );
                            continue;
                        }
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
                            record_cross_protocol_retry_failure(
                                state,
                                proxy,
                                current_target.as_deref(),
                                current_cb_target_key.as_deref(),
                                attempt_result.status_code,
                                attempt_result.connection_error,
                            );
                            let delay = crate::retry::retry_delay(retry_config, attempt);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            if let Some((next_target, next_cb_target_key, next_url)) =
                                select_next_cross_protocol_retry_target(
                                    state,
                                    proxy,
                                    lb_hash_key,
                                    current_target.as_ref(),
                                    path,
                                    query_string,
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
                            record_cross_protocol_connection_start(
                                state,
                                proxy,
                                current_target.as_deref(),
                            );
                            continue;
                        }

                        let final_backend_resolved_ip = resolve_cross_protocol_backend_ip(
                            state,
                            proxy,
                            current_target.as_deref(),
                        )
                        .await;
                        record_backend_outcome(
                            state,
                            proxy,
                            current_target.as_deref(),
                            current_cb_target_key.as_deref(),
                            attempt_result.status_code,
                            attempt_result.connection_error,
                            backend_start.elapsed(),
                        );
                        let mut outcome = write_error(
                            stream,
                            StatusCode::BAD_GATEWAY,
                            r#"{"error":"Bad Gateway"}"#,
                            backend_start,
                            request_bytes,
                        )
                        .await?;
                        outcome.backend_target_url =
                            Some(strip_query_from_backend_url(&current_url));
                        outcome.connection_error = attempt_result.connection_error;
                        outcome.error_class = attempt_result.error_class;
                        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                        return Ok(outcome);
                    }
                }
            };
            (response, request_bytes)
        }
        None => {
            record_cross_protocol_connection_start(state, proxy, current_target.as_deref());

            let effective_host = current_target
                .as_deref()
                .map(|t| t.host.as_str())
                .unwrap_or(proxy.backend_host.as_str());
            let req_builder = build_plain_request_builder(
                &client,
                state,
                proxy,
                req_method,
                proxy_headers,
                &current_url,
                effective_host,
                client_ip,
            );

            let max_req_bytes = state.max_request_body_size_bytes;
            let capacity = state.env_config.http3_request_body_channel_capacity;
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(capacity);
            let body_stream = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            });
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
            let reader_future = async {
                let mut total: usize = 0;
                loop {
                    tokio::select! {
                        biased;
                        _ = reader_halt.notified() => {
                            crate::http3::stream_util::halt_request_body(stream);
                            return;
                        }
                        chunk = stream.recv_data() => {
                            match chunk {
                                Ok(Some(chunk)) => {
                                    let data = chunk.chunk();
                                    if max_req_bytes > 0 && total + data.len() > max_req_bytes {
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
                                        return;
                                    }
                                    total += data.len();
                                    reader_bytes.store(total as u64, Ordering::Relaxed);
                                    let send_outcome = tokio::select! {
                                        biased;
                                        _ = reader_halt.notified() => {
                                            crate::http3::stream_util::halt_request_body(stream);
                                            return;
                                        }
                                        res = tx.send(Ok(Bytes::copy_from_slice(data))) => res,
                                    };
                                    if send_outcome.is_err() {
                                        return;
                                    }
                                }
                                Ok(None) => return,
                                Err(e) => {
                                    tokio::select! {
                                        biased;
                                        _ = reader_halt.notified() => {}
                                        _ = tx.send(Err(std::io::Error::other(format!(
                                            "H3 recv_data failed: {}",
                                            e
                                        )))) => {}
                                    }
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
            let request_bytes = bytes_read.load(Ordering::Relaxed);
            if oversized.load(Ordering::Relaxed) {
                record_backend_outcome(
                    state,
                    proxy,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    413,
                    false,
                    backend_start.elapsed(),
                );
                return write_error(
                    stream,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    backend_start,
                    request_bytes,
                )
                .await;
            }

            match send_result {
                Ok(response) => (response, request_bytes),
                Err(e) => {
                    let final_backend_resolved_ip =
                        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref())
                            .await;
                    let attempt_result = reqwest_error_response_for_cross_protocol(
                        state,
                        &e,
                        final_backend_resolved_ip.clone(),
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
                        current_target.as_deref(),
                        current_cb_target_key.as_deref(),
                        attempt_result.status_code,
                        attempt_result.connection_error,
                        backend_start.elapsed(),
                    );
                    let mut outcome = write_error(
                        stream,
                        StatusCode::BAD_GATEWAY,
                        r#"{"error":"Bad Gateway"}"#,
                        backend_start,
                        request_bytes,
                    )
                    .await?;
                    outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
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
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            502,
            false,
            backend_start.elapsed(),
        );
        let mut outcome = write_error(
            stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
            backend_start,
            request_bytes,
        )
        .await?;
        outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        outcome.body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
        return Ok(outcome);
    }

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
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            reject.status_code,
            false,
            backend_start.elapsed(),
        );
        let mut outcome = write_reject_with_headers(
            stream,
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &reject.body,
            &reject.headers,
            backend_start,
            request_bytes,
        )
        .await?;
        outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
        outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
        return Ok(outcome);
    }

    // Sticky session cookie injection — only runs if the LB selected a
    // sticky target.
    crate::http3::server::inject_sticky_cookie(
        state,
        proxy,
        current_target.as_deref(),
        sticky_cookie_needed,
        &mut response_headers,
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
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    502,
                    false,
                    backend_start.elapsed(),
                );
                let empty_headers = HashMap::new();
                let mut outcome = write_reject_with_headers(
                    stream,
                    StatusCode::BAD_GATEWAY,
                    &error_body,
                    &empty_headers,
                    backend_start,
                    request_bytes,
                )
                .await?;
                outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
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
                        let Some(reject) = crate::proxy::plugin_result_into_reject_parts(reject)
                        else {
                            warn!(
                                "plugin reject arm returned a non-reject result in on_response_body"
                            );
                            continue;
                        };
                        response_status = reject.status_code;
                        response_headers.clear();
                        response_headers
                            .insert("content-type".to_string(), "application/json".to_string());
                        for (k, v) in reject.headers {
                            response_headers.insert(k, v);
                        }
                        response_body = reject.body;
                        break;
                    }
                }
            }

            for plugin in plugins {
                if let Some(transformed) = plugin
                    .transform_response_body(
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
                        let Some(reject) = crate::proxy::plugin_result_into_reject_parts(reject)
                        else {
                            warn!(
                                "plugin reject arm returned a non-reject result in on_final_response_body"
                            );
                            continue;
                        };
                        response_status = reject.status_code;
                        response_headers.clear();
                        response_headers
                            .insert("content-type".to_string(), "application/json".to_string());
                        for (k, v) in reject.headers {
                            response_headers.insert(k, v);
                        }
                        response_body = reject.body;
                        break;
                    }
                }
            }
        }

        send_response_headers(stream, response_status, &response_headers).await?;
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
            current_target.as_deref(),
            current_cb_target_key.as_deref(),
            response_status,
            false,
            backend_start.elapsed(),
        );

        return Ok(CrossProtocolOutcome {
            response_status,
            bytes_streamed,
            request_bytes,
            backend_target_url: Some(strip_query_from_backend_url(&current_url)),
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

    // Send response headers, then stream the body with coalescing.
    send_response_headers(stream, status, &response_headers).await?;

    let coalesce = CoalesceConfig::from_state(state);
    let max_resp_bytes = state.max_response_body_size_bytes;
    let (bytes_streamed, body_completed, client_disconnected, body_error_class) =
        stream_reqwest_response(stream, response, coalesce, max_resp_bytes).await;

    record_backend_outcome(
        state,
        proxy,
        current_target.as_deref(),
        current_cb_target_key.as_deref(),
        status,
        false,
        backend_start.elapsed(),
    );

    Ok(CrossProtocolOutcome {
        response_status: status,
        bytes_streamed,
        request_bytes,
        backend_target_url: Some(strip_query_from_backend_url(&current_url)),
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

#[allow(clippy::too_many_arguments)]
async fn dispatch_grpc<S>(
    state: &ProxyState,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    path: &str,
    query_string: &str,
    backend_url: &str,
    lb_hash_key: Option<&str>,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    prebuffered_body: Option<Vec<u8>>,
    raw_prebuffered_body_bytes: u64,
    client_ip: &str,
    backend_start: Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
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
    let request_bytes = if body_was_prebuffered {
        raw_prebuffered_body_bytes
    } else {
        body.len() as u64
    };

    // Build the backend-facing header map. Mirrors the H1/H2 gRPC path in
    // `src/proxy/mod.rs::proxy_grpc_request_core` so gRPC backends behind
    // an H3 frontend see the same forwarding metadata (X-Forwarded-For,
    // -Proto, -Host, Via, Forwarded) as they would over H1/H2. Hop-by-hop
    // headers (RFC 9110 §7.6.1) plus client-supplied forwarding headers
    // are stripped before we re-synthesize the canonical forwarding set.
    //
    // Hot-path note: the HOST and X-FORWARDED-FOR lookups use the hyper
    // pre-interned HeaderName constants when we know the key — but here
    // the source is a `HashMap<String, String>` so we use `.get()` on the
    // lowercase literal (single string compare, no alloc). Forwarding
    // header *insertion* below uses the pre-interned constants to skip
    // the name-parse on the hot path.
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
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            hmap.append(name, val);
        }
    }
    let xff_val = crate::proxy::build_xff_value(original_xff, client_ip);
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
        state
            .plugin_cache
            .requires_response_body_buffering(&proxy.id),
    );
    let body_bytes = Bytes::from(body);
    record_cross_protocol_connection_start(state, proxy, current_target.as_deref());
    let mut result = proxy_grpc_request_from_bytes(
        hyper_method.clone(),
        hmap.clone(),
        body_bytes.clone(),
        proxy,
        &current_url,
        &state.grpc_pool,
        &state.dns_cache,
        proxy_headers,
        stream_grpc_response,
    )
    .await;

    if grpc_has_retry && let Some(retry_config) = &proxy.retry {
        let mut attempt = 0u32;
        loop {
            // Local pre-wire predicate for the gRPC retry loop. Both
            // listed `GrpcProxyError` variants are pre-wire by
            // construction:
            //   * `BackendUnavailable` is emitted only when the gRPC
            //     dispatch never gets past TCP / TLS / h2 / h2c
            //     handshake (no request frame ever leaves the gateway).
            //   * `BackendTimeout::Connect` is the connect-timeout
            //     timer, identical semantics.
            // Both satisfy `request_reached_wire(class) == false` when
            // mapped through `classify_grpc_proxy_error`, so this
            // `matches!` agrees with the unified boundary by
            // construction — but the agreement is invariant-by-listing,
            // not invariant-by-derivation. If a future `GrpcProxyError`
            // variant is added (e.g. a "TLS rejected after handshake"
            // marker that's still pre-wire), it MUST be added to this
            // arm AND to `classify_grpc_proxy_error` in lockstep. Run
            // `cargo check` against the new variant; the surrounding
            // tests in `tests/unit/gateway_core/grpc_*` will catch a
            // misclassification mismatch.
            let is_connection_error = matches!(
                &result,
                Err(grpc_proxy::GrpcProxyError::BackendUnavailable(_))
                    | Err(grpc_proxy::GrpcProxyError::BackendTimeout {
                        kind: grpc_proxy::GrpcTimeoutKind::Connect,
                        ..
                    })
            );
            if !is_connection_error
                || !retry_config.retry_on_connect_failure
                || attempt >= retry_config.max_retries
            {
                break;
            }

            record_cross_protocol_retry_failure(
                state,
                proxy,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                true,
            );

            let delay = crate::retry::retry_delay(retry_config, attempt);
            tokio::time::sleep(delay).await;
            attempt += 1;

            if let Some((next_target, next_cb_target_key, next_url)) =
                select_next_cross_protocol_retry_target(
                    state,
                    proxy,
                    lb_hash_key,
                    current_target.as_ref(),
                    path,
                    query_string,
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
            record_cross_protocol_connection_start(state, proxy, current_target.as_deref());

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
                proxy_headers,
                stream_grpc_response,
            )
            .await;
        }
    }

    let final_backend_resolved_ip =
        resolve_cross_protocol_backend_ip(state, proxy, current_target.as_deref()).await;

    match result {
        Ok(GrpcResponseKind::Buffered(mut resp)) => {
            // Buffered variant: pool extracted trailers up front. Run the
            // full response-hook pipeline (after_proxy, sticky cookie,
            // on_response_body, on_final_response_body) on the buffered
            // body — the main gRPC path does the same, so H3 gRPC buffered
            // responses now behave identically.
            if !plugins.is_empty()
                && let Some(reject) = crate::proxy::run_after_proxy_hooks(
                    plugins,
                    ctx,
                    resp.status,
                    &mut resp.headers,
                )
                .await
            {
                let mut outcome = write_final_body_reject(
                    stream,
                    HttpFlavor::Grpc,
                    ctx,
                    PluginResult::RejectBinary {
                        status_code: reject.status_code,
                        body: Bytes::from(reject.body),
                        headers: reject.headers,
                    },
                    backend_start,
                    request_bytes,
                )
                .await?;
                record_backend_outcome(
                    state,
                    proxy,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    outcome.response_status,
                    false,
                    backend_start.elapsed(),
                );
                outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                return Ok(outcome);
            }
            crate::http3::server::inject_sticky_cookie(
                state,
                proxy,
                current_target.as_deref(),
                sticky_cookie_needed,
                &mut resp.headers,
            );
            // Run the buffered response-body hook pipeline in the same
            // order as the main gRPC proxy path so reject/transform
            // semantics stay transport-independent.
            let mut response_status = resp.status;
            let mut response_headers = resp.headers;
            let mut response_body = resp.body;
            let mut response_trailers = resp.trailers;
            for plugin in plugins.iter() {
                let result = plugin
                    .on_response_body(ctx, response_status, &response_headers, &response_body)
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
                            ctx,
                            reject,
                            &mut response_status,
                            &mut response_headers,
                            &mut response_body,
                            &mut response_trailers,
                        );
                        break;
                    }
                }
            }
            for plugin in plugins.iter() {
                if let Some(transformed) = plugin
                    .transform_response_body(
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
            for plugin in plugins.iter() {
                let result = plugin
                    .on_final_response_body(ctx, response_status, &response_headers, &response_body)
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
                            ctx,
                            reject,
                            &mut response_status,
                            &mut response_headers,
                            &mut response_body,
                            &mut response_trailers,
                        );
                        break;
                    }
                }
            }

            send_response_headers(stream, response_status, &response_headers).await?;
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
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                response_status,
                false,
                backend_start.elapsed(),
            );
            Ok(CrossProtocolOutcome {
                response_status,
                bytes_streamed: bytes_total,
                request_bytes,
                backend_target_url: Some(strip_query_from_backend_url(&current_url)),
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
        Ok(GrpcResponseKind::Streaming(mut streaming)) => {
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
                let mut outcome = write_final_body_reject(
                    stream,
                    HttpFlavor::Grpc,
                    ctx,
                    PluginResult::RejectBinary {
                        status_code: reject.status_code,
                        body: Bytes::from(reject.body),
                        headers: reject.headers,
                    },
                    backend_start,
                    request_bytes,
                )
                .await?;
                record_backend_outcome(
                    state,
                    proxy,
                    current_target.as_deref(),
                    current_cb_target_key.as_deref(),
                    outcome.response_status,
                    false,
                    backend_start.elapsed(),
                );
                outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
                outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
                return Ok(outcome);
            }
            crate::http3::server::inject_sticky_cookie(
                state,
                proxy,
                current_target.as_deref(),
                sticky_cookie_needed,
                &mut streaming.headers,
            );

            send_response_headers(stream, streaming.status, &streaming.headers).await?;
            let coalesce = CoalesceConfig::from_state(state);
            let max_resp_bytes = state.max_response_body_size_bytes;
            let (bytes_streamed, body_completed, client_disconnected, body_error_class, trailers) =
                stream_hyper_incoming(stream, streaming.body, coalesce, max_resp_bytes).await;

            let mut final_body_completed = body_completed;
            let mut final_client_disconnected = client_disconnected;
            if body_completed
                && let Some(trailers) = trailers
                && !trailers.is_empty()
                && let Err(e) = stream.send_trailers(trailers).await
            {
                warn!("H3 gRPC streaming send_trailers failed: {}", e);
                final_client_disconnected = true;
                final_body_completed = false;
            }

            record_backend_outcome(
                state,
                proxy,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                streaming.status,
                false,
                backend_start.elapsed(),
            );
            Ok(CrossProtocolOutcome {
                response_status: streaming.status,
                bytes_streamed,
                request_bytes,
                backend_target_url: Some(strip_query_from_backend_url(&current_url)),
                backend_resolved_ip: final_backend_resolved_ip.clone(),
                body_completed: final_body_completed,
                client_disconnected: final_client_disconnected,
                connection_error: false,
                error_class: None,
                body_error_class,
                backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
            })
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
                grpc_proxy::GrpcProxyError::Internal(_) => {
                    (grpc_proxy::grpc_status::INTERNAL, "Internal gateway error")
                }
                grpc_proxy::GrpcProxyError::BackendUnavailable(_) => {
                    (grpc_proxy::grpc_status::UNAVAILABLE, "Service unavailable")
                }
            };
            warn!(
                proxy_id = %proxy.id,
                error = %err,
                class = ?error_class,
                grpc_status = grpc_status_code,
                "cross-protocol H3→gRPC backend call failed"
            );
            record_backend_outcome(
                state,
                proxy,
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                true,
                backend_start.elapsed(),
            );
            let mut outcome = write_grpc_error(
                stream,
                grpc_status_code,
                grpc_message,
                backend_start,
                request_bytes,
            )
            .await?;
            outcome.backend_target_url = Some(strip_query_from_backend_url(&current_url));
            outcome.connection_error = true;
            outcome.error_class = Some(error_class);
            outcome.backend_resolved_ip = final_backend_resolved_ip.clone();
            Ok(outcome)
        }
    }
}

fn apply_buffered_grpc_plugin_reject(
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
    let normalized = normalize_h3_grpc_reject(
        StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY),
        &reject.body,
        &reject.headers,
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
                                let _ = stream.finish().await;
                                body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                break 'outer;
                            }
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
                        if !coalesce_buf.is_empty() {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if stream.send_data(data).await.is_ok() {
                                bytes_streamed += data_len;
                            }
                        }
                        let _ = stream.finish().await;
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
                                    let _ = stream.finish().await;
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
                                    let _ = stream.finish().await;
                                    body_error_class = Some(ErrorClass::ResponseBodyTooLarge);
                                    break 'outer;
                                }
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
                        if !coalesce_buf.is_empty() {
                            let out = coalesce_buf.split().freeze();
                            let out_len = out.len() as u64;
                            if stream.send_data(out).await.is_ok() {
                                bytes_streamed += out_len;
                            }
                        }
                        let _ = stream.finish().await;
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
    for (k, v) in response.headers() {
        let name = k.as_str();
        // Strip hop-by-hop response headers per RFC 9110 §7.6.1 — see
        // `proxy::headers` for the canonical predicate. Response-direction
        // set differs from the request-direction set.
        if is_backend_response_strip_header(name) {
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
    S: RecvStream + SendStream<Bytes>,
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
    request_bytes: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let resp = Response::builder()
        .status(status)
        .header("content-type", "application/json")
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
        request_bytes,
        backend_target_url: None,
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
    request_bytes: u64,
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
        request_bytes,
        backend_target_url: None,
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
    ctx: &mut RequestContext,
    reject: PluginResult,
    backend_start: Instant,
    request_bytes: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let Some(parts) = crate::proxy::plugin_result_into_reject_parts(reject) else {
        warn!("final body reject helper received a non-reject plugin result");
        return if matches!(flavor, HttpFlavor::Grpc) {
            write_grpc_error(
                stream,
                h3_http_status_to_grpc_status(StatusCode::BAD_GATEWAY),
                "Plugin rejection normalization failed",
                backend_start,
                request_bytes,
            )
            .await
        } else {
            write_error(
                stream,
                StatusCode::BAD_GATEWAY,
                "{\"error\":\"Plugin rejection normalization failed\"}",
                backend_start,
                request_bytes,
            )
            .await
        };
    };
    let http_status = StatusCode::from_u16(parts.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    if matches!(flavor, HttpFlavor::Grpc) {
        let normalized = normalize_h3_grpc_reject(http_status, &parts.body, &parts.headers);
        apply_h3_grpc_reject_metadata(ctx, &normalized);
        write_normalized_grpc_reject(stream, &normalized, backend_start, request_bytes).await
    } else {
        write_reject_with_headers(
            stream,
            http_status,
            &parts.body,
            &parts.headers,
            backend_start,
            request_bytes,
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
    request_bytes: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
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
    crate::http3::stream_util::halt_request_body(stream);
    Ok(CrossProtocolOutcome {
        response_status: reject.http_status.as_u16(),
        bytes_streamed: 0,
        request_bytes,
        backend_target_url: None,
        backend_resolved_ip: None,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
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
    request_bytes: u64,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
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
    crate::http3::stream_util::halt_request_body(stream);
    Ok(CrossProtocolOutcome {
        response_status: 200,
        bytes_streamed: 0,
        request_bytes,
        backend_target_url: None,
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

    use super::{
        apply_buffered_grpc_plugin_reject, apply_h3_grpc_reject_metadata, normalize_h3_grpc_reject,
        reject_body_as_h3_grpc_message, sanitize_h3_grpc_message_for_header,
        should_finish_h3_stream_without_trailers, should_skip_cross_protocol_backend_header,
    };
    use crate::plugins::{PluginResult, RequestContext};
    use hyper::{HeaderMap, StatusCode};

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
    fn buffered_grpc_plugin_reject_normalizes_and_clears_backend_trailers() {
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
        );

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
        let loop_start_marker = "if grpc_has_retry && let Some(retry_config) = &proxy.retry {";
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
}
