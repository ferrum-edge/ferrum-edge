//! HTTP/3 frontend → non-H3 backend dispatch with streaming responses +
//! coalescing.
//!
//! When an HTTP/3 client lands on a proxy whose backend cannot be reached
//! via QUIC — either because the operator didn't opt in
//! (`backend_prefer_h3 = false`) or because the request is gRPC/WebSocket
//! that doesn't benefit from H3 — the H3 server bridges the request to the
//! same HTTP/1.1 + HTTP/2 backend infrastructure the main proxy path uses.
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
//!   `FERRUM_H3_REQUEST_BODY_CHANNEL_CAPACITY`, default 8). When the H3
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
use crate::proxy::ProxyState;
use crate::proxy::backend_dispatch::record_backend_outcome;
use crate::proxy::grpc_proxy::{self, GrpcResponseKind, proxy_grpc_request_from_bytes};
use crate::retry::ErrorClass;

/// Outcome reported back to the H3 listener so it can update request
/// counters, build the `TransactionSummary` for log plugins, and record
/// whether the client disconnected mid-stream.
pub struct CrossProtocolOutcome {
    pub response_status: u16,
    pub bytes_streamed: u64,
    pub request_bytes: u64,
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

/// Entry point — routes the cross-protocol dispatch by flavor. Called from
/// the H3 server when `proxy.dispatch_kind` is not `HttpsH3Preferred` OR
/// the flavor is not Plain.
#[allow(clippy::too_many_arguments)]
pub async fn run<S>(
    state: &ProxyState,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    backend_url: &str,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    flavor: HttpFlavor,
    prebuffered_body: Option<Vec<u8>>,
    client_ip: &str,
) -> Result<CrossProtocolOutcome, anyhow::Error>
where
    S: RecvStream + SendStream<Bytes>,
{
    let backend_start = Instant::now();

    match flavor {
        HttpFlavor::Plain => {
            dispatch_plain(
                state,
                proxy,
                stream,
                method,
                proxy_headers,
                backend_url,
                upstream_target,
                cb_target_key,
                prebuffered_body,
                client_ip,
                backend_start,
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
                backend_url,
                upstream_target,
                cb_target_key,
                prebuffered_body,
                client_ip,
                backend_start,
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
async fn dispatch_plain<S>(
    state: &ProxyState,
    proxy: &Proxy,
    stream: &mut RequestStream<S, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    backend_url: &str,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    prebuffered_body: Option<Vec<u8>>,
    client_ip: &str,
    backend_start: Instant,
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
            return write_error(
                stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Bad Gateway"}"#,
                backend_start,
                0,
            )
            .await;
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

    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(proxy.backend_host.as_str());

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers. Host is rewritten to the effective backend unless
    // `preserve_host_header` is set — matches `proxy_to_backend_retry`'s
    // policy. Hop-by-hop headers per RFC 9110 §7.6.1 are stripped. The
    // standard forwarding headers (X-Forwarded-*, Via, Forwarded) are
    // emitted after this loop so we can honor any existing XFF value
    // the client sent while guaranteeing the gateway appends its own
    // resolved client IP — identical to the H1/H2 path.
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
            // Skipped: hop-by-hop (RFC 9110 §7.6.1) and the forwarding
            // headers we re-synthesize below so a client-sent value cannot
            // override the gateway's canonical view.
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
            | "forwarded" => {}
            _ => {
                req_builder = req_builder.header(k, v);
            }
        }
    }

    // Standard forwarding header set — mirrors `proxy_to_backend_retry` in
    // `src/proxy/mod.rs` so backends see identical forwarding metadata
    // regardless of whether the client arrived via H1/H2 or H3. H3 clients
    // always arrive over TLS so proto is always "https".
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

    // Request body dispatch — streams by default, buffers only when the
    // caller pre-buffered (plugin phase already collected the body). This
    // mirrors `ClientRequestBody::{Streaming, Buffered}` in the H1/H2 path
    // (src/proxy/mod.rs:231).
    let max_req_bytes = state.max_request_body_size_bytes;
    let (send_result, request_bytes) = match prebuffered_body {
        Some(buffered) => {
            // Fast path — body is already in memory. One allocation passed
            // to reqwest; no mpsc, no bridge.
            let n = buffered.len() as u64;
            let send_future = req_builder.body(buffered).send();
            (send_future.await, n)
        }
        None => {
            // Streaming path — wire the H3 recv half to reqwest via a
            // bounded mpsc channel. Reader + send() are driven concurrently
            // with `tokio::join!` so the body flows end-to-end without any
            // intermediate Vec<u8>. See module doc comment for design
            // rationale.
            let capacity = state.env_config.http3_request_body_channel_capacity;
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(capacity);
            // Receiver is 'static (owns its own state) — satisfies the
            // `Body::wrap_stream` bound without capturing the &mut borrow.
            let body_stream = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            });
            let req_body = reqwest::Body::wrap_stream(body_stream);
            let send_future = req_builder.body(req_body).send();

            let bytes_read = Arc::new(AtomicU64::new(0));
            let reader_bytes = Arc::clone(&bytes_read);
            // Signals that the reader detected an oversized request body and
            // aborted the bridge. Used after `join!` to emit 413 rather than
            // the generic 502 that a reqwest stream error would produce.
            let oversized = Arc::new(AtomicBool::new(false));
            let reader_oversized = Arc::clone(&oversized);
            let reader_future = async {
                let mut total: usize = 0;
                loop {
                    match stream.recv_data().await {
                        Ok(Some(chunk)) => {
                            let data = chunk.chunk();
                            if max_req_bytes > 0 && total + data.len() > max_req_bytes {
                                reader_oversized.store(true, Ordering::Relaxed);
                                let _ = tx
                                    .send(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "request body exceeds max_request_body_size_bytes",
                                    )))
                                    .await;
                                return;
                            }
                            total += data.len();
                            reader_bytes.store(total as u64, Ordering::Relaxed);
                            // Bytes::copy_from_slice is unavoidable here —
                            // h3's `chunk.chunk()` returns &[u8] borrowed
                            // from the Bytes holder it won't release to us.
                            if tx.send(Ok(Bytes::copy_from_slice(data))).await.is_err() {
                                // Receiver dropped (backend closed body
                                // stream early or send_future finished) —
                                // stop reading.
                                return;
                            }
                        }
                        Ok(None) => return, // clean EOF; tx drops on exit
                        Err(e) => {
                            let _ = tx
                                .send(Err(std::io::Error::other(format!(
                                    "H3 recv_data failed: {}",
                                    e
                                ))))
                                .await;
                            return;
                        }
                    }
                }
            };

            let (_, send_result) = tokio::join!(reader_future, send_future);
            let request_bytes = bytes_read.load(Ordering::Relaxed);
            // Oversized request body: emit 413 directly, skipping the
            // generic backend-error branch below (which would surface the
            // reqwest stream error as 502).
            if oversized.load(Ordering::Relaxed) {
                record_backend_outcome(
                    state,
                    proxy,
                    upstream_target,
                    cb_target_key,
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
            (send_result, request_bytes)
        }
    };

    let response = match send_result {
        Ok(r) => r,
        Err(e) => {
            let error_class = crate::retry::classify_reqwest_error(&e);
            warn!(
                proxy_id = %proxy.id,
                error = %e,
                class = ?error_class,
                "cross-protocol H3→HTTP: backend request failed"
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
                request_bytes,
            )
            .await?;
            outcome.connection_error = true;
            outcome.error_class = Some(error_class);
            return Ok(outcome);
        }
    };

    let status = response.status().as_u16();
    let response_headers = collect_reqwest_response_headers(&response);

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
            upstream_target,
            cb_target_key,
            502,
            false,
            backend_start.elapsed(),
        );
        return write_error(
            stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
            backend_start,
            request_bytes,
        )
        .await;
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
        upstream_target,
        cb_target_key,
        status,
        false,
        backend_start.elapsed(),
    );

    Ok(CrossProtocolOutcome {
        response_status: status,
        bytes_streamed,
        request_bytes,
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
    backend_url: &str,
    upstream_target: Option<&UpstreamTarget>,
    cb_target_key: Option<&str>,
    prebuffered_body: Option<Vec<u8>>,
    client_ip: &str,
    backend_start: Instant,
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

    // gRPC request body: the pool API takes `Bytes` for retry-safe framing
    // and trailer handling. Buffer the H3 recv half here (unary gRPC bodies
    // are small; streaming gRPC request bodies over the cross-protocol
    // bridge would require a new GrpcBody variant in GrpcConnectionPool —
    // future optimization). Size ceiling uses `max_grpc_recv_size_bytes`
    // (not `max_request_body_size_bytes`) so H3 gRPC matches the H1/H2 gRPC
    // limit — an `https` proxy serves any client HTTP version uniformly.
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
    let request_bytes = body.len() as u64;

    // Build the backend-facing header map. Mirrors the H1/H2 gRPC path in
    // `src/proxy/mod.rs::proxy_grpc_request_core` so gRPC backends behind
    // an H3 frontend see the same forwarding metadata (X-Forwarded-For,
    // -Proto, -Host, Via, Forwarded) as they would over H1/H2.
    let original_host_header = proxy_headers.get("host").map(|s| s.as_str());
    let original_xff = proxy_headers.get("x-forwarded-for").map(|s| s.as_str());
    let mut hmap = HeaderMap::new();
    for (k, v) in proxy_headers {
        let k_lower = k.as_str();
        // Skip the forwarding headers we re-synthesize below so a
        // client-sent value cannot override the gateway's canonical view.
        if matches!(
            k_lower,
            "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "via" | "forwarded"
        ) {
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
    if let Ok(val) = HeaderValue::from_str("https") {
        hmap.insert("x-forwarded-proto", val);
    }
    if let Some(host) = original_host_header
        && let Ok(val) = HeaderValue::from_str(host)
    {
        hmap.insert("x-forwarded-host", val);
    }
    if let Some(ref via) = state.via_header_http3
        && let Ok(val) = HeaderValue::from_str(via)
    {
        hmap.insert("via", val);
    }
    if state.add_forwarded_header {
        let fwd = crate::proxy::build_forwarded_value(client_ip, "https", original_host_header);
        if let Ok(val) = HeaderValue::from_str(&fwd) {
            hmap.insert("forwarded", val);
        }
    }

    // Stream the response when no retry is configured and no plugin needs
    // the response body buffered. Retries force buffering because the retry
    // layer must inspect status/body to decide; buffering plugins force
    // buffering because they need the full body for validation/transform.
    // Without this, server-streaming / bidi gRPC responses would accumulate
    // fully in memory before the first byte flows to the H3 client.
    let stream_grpc_response = proxy.retry.is_none()
        && !state
            .plugin_cache
            .requires_response_body_buffering(&proxy.id);
    let body_bytes = Bytes::from(body);
    let result = proxy_grpc_request_from_bytes(
        hyper_method,
        hmap,
        body_bytes,
        proxy,
        backend_url,
        &state.grpc_pool,
        &state.dns_cache,
        proxy_headers,
        stream_grpc_response,
    )
    .await;

    match result {
        Ok(GrpcResponseKind::Buffered(resp)) => {
            // Buffered variant: pool extracted trailers up front. Stream
            // body in a single send_data (gRPC unary responses are small),
            // then emit trailers.
            send_response_headers(stream, resp.status, &resp.headers).await?;
            let bytes_total = resp.body.len() as u64;
            let mut body_completed = true;
            let mut client_disconnected = false;
            if !resp.body.is_empty()
                && let Err(e) = stream.send_data(Bytes::from(resp.body)).await
            {
                debug!("cross-protocol H3 gRPC body send_data failed: {}", e);
                client_disconnected = true;
                body_completed = false;
            }
            if body_completed && !resp.trailers.is_empty() {
                let trailer_map = headers_to_header_map(&resp.trailers);
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
                upstream_target,
                cb_target_key,
                resp.status,
                false,
                backend_start.elapsed(),
            );
            Ok(CrossProtocolOutcome {
                response_status: resp.status,
                bytes_streamed: bytes_total,
                request_bytes,
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
            // Streaming variant: pool returned a live hyper Incoming. Read
            // frames, coalesce DATA into H3 send_data, and emit trailers
            // via send_trailers when the body ends cleanly.
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
                upstream_target,
                cb_target_key,
                streaming.status,
                false,
                backend_start.elapsed(),
            );
            Ok(CrossProtocolOutcome {
                response_status: streaming.status,
                bytes_streamed,
                request_bytes,
                body_completed: final_body_completed,
                client_disconnected: final_client_disconnected,
                connection_error: false,
                error_class: None,
                body_error_class,
                backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
            })
        }
        Err(err) => {
            warn!(
                proxy_id = %proxy.id,
                error = %err,
                "cross-protocol H3→gRPC backend call failed"
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
            // Trailers-only gRPC error — HTTP 200 + grpc-status UNAVAILABLE
            // rather than an HTTP 502 JSON payload, so clients see a valid
            // gRPC transport error.
            let mut outcome = write_grpc_error(
                stream,
                grpc_proxy::grpc_status::UNAVAILABLE,
                "Service unavailable",
                backend_start,
                request_bytes,
            )
            .await?;
            outcome.connection_error = true;
            outcome.error_class = Some(ErrorClass::ConnectionRefused);
            Ok(outcome)
        }
    }
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
            // via `send_trailers`. When absent, finish here.
            if trailers.is_none()
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
        // Strip hop-by-hop response headers per RFC 9110 §7.6.1 so nothing
        // leaks across the proxy boundary.
        if matches!(
            name,
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            headers
                .entry(name.to_string())
                .and_modify(|existing| {
                    existing.push_str(if name == "set-cookie" { "\n" } else { ", " });
                    existing.push_str(val);
                })
                .or_insert_with(|| val.to_string());
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
            // line — mirrors the H1/H2 path in `src/proxy/mod.rs`.
            if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
                for cookie_val in v.split('\n') {
                    if let Ok(val) = HeaderValue::from_str(cookie_val) {
                        resp_builder = resp_builder.header(name.clone(), val);
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
    Ok(CrossProtocolOutcome {
        response_status: status.as_u16(),
        bytes_streamed: len,
        request_bytes,
        body_completed: true,
        client_disconnected: false,
        connection_error: false,
        error_class: None,
        body_error_class: None,
        backend_total_ms: backend_start.elapsed().as_secs_f64() * 1000.0,
    })
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
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", grpc_status.to_string())
        .header("grpc-message", grpc_message)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 gRPC error response: {}", e))?;
    stream.send_response(resp).await?;
    let _ = stream.finish().await;
    Ok(CrossProtocolOutcome {
        response_status: 200,
        bytes_streamed: 0,
        request_bytes,
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
