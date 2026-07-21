//! HTTP/3 WebSocket bridging — RFC 9220 Extended CONNECT.
//!
//! [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) bootstraps a
//! WebSocket session over HTTP/3 using Extended CONNECT, the same
//! mechanism RFC 8441 defines for HTTP/2:
//!
//! 1. Server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`
//!    (controlled by `FERRUM_HTTP3_WEBSOCKET_ENABLED`, default on; wired
//!    in `src/http3/server.rs::handle_h3_connection`).
//! 2. Client sends `:method = CONNECT` + `:protocol = "websocket"` +
//!    `:scheme = "https"` + `:authority = ...` + `:path = ...` on a
//!    new bidirectional QUIC stream.
//! 3. Server replies with `:status = 200` (no Upgrade / Sec-WebSocket-Accept
//!    headers — those are HTTP/1.1 only). The HTTP/3 DATA frames on the
//!    same stream now carry WebSocket protocol bytes.
//!
//! ## Architecture
//!
//! The gateway does not speak HTTP/3 to WebSocket *backends* (browsers,
//! Node `ws`, and every common backend library still bootstrap WebSocket
//! over HTTP/1.1 or HTTP/2). Instead the H3 frontend bridges to the same
//! HTTP/1.1-Upgrade backend code the H1/H2 frontends use — same
//! `connect_websocket_backend`, same `WebSocketStream` over
//! `MaybeTlsStream<TcpStream>`, same per-frame plugin pipeline, same
//! disconnect bookkeeping. Only the bytes-on-the-wire transport on the
//! *frontend* differs.
//!
//! The H3 RequestStream halves (after `.split()`) are bridged to a
//! tokio `DuplexStream` via two pump tasks:
//!
//! ```text
//!   QUIC stream (h3 frontend)         WebSocket backend (H1 Upgrade)
//!   ─────────────────────────         ──────────────────────────────
//!   RequestStream::send_data    ◄──── h3_send pump ◄── DuplexStream::write
//!   RequestStream::recv_data    ────► h3_recv pump ──► DuplexStream::read
//!                                                       │
//!                                                       ▼
//!                                  WebSocketStream<DuplexStream>
//!                                  (parses WS frames, runs plugin pipeline)
//!                                                       │
//!                                                       ▼
//!                                  run_websocket_proxy (generic over C)
//!                                                       │
//!                                                       ▼
//!                                  WebSocketStream<MaybeTlsStream<TcpStream>>
//! ```
//!
//! `run_websocket_proxy` (in `src/proxy/mod.rs`) is generic over the
//! client transport `C: AsyncRead + AsyncWrite + Unpin + Send + 'static`.
//! The H1/H2 path passes `TokioIo::new(upgraded)`; this module passes
//! the duplex half. Everything downstream — frame parsing, `on_ws_frame`
//! hooks, `on_ws_disconnect` hooks, cancellation, first-failure
//! attribution, frame counting — is identical to the H1/H2 path.
//!
//! ## Buffer sizing
//!
//! The duplex bridge uses a 64 KiB internal buffer
//! (`H3_WS_DUPLEX_BUFFER_BYTES`) plus a 16 KiB scratch buffer on the
//! send pump (`H3_WS_SEND_PUMP_READ_BUFFER_BYTES`). The duplex is large
//! enough that small WebSocket frames don't cause excessive context
//! switching on the pump tasks; the scratch buffer is intentionally
//! smaller because bytes are copied into `Bytes` immediately before
//! `send_data()`. Frame size is independently bounded by
//! `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` enforced by the WebSocket
//! framer, not the bridge buffers.
//!
//! ## Tunnel mode
//!
//! `FERRUM_WEBSOCKET_TUNNEL_MODE` does not apply to H3 — there is no raw
//! TCP underneath QUIC, and the H3-side bytes already pass through the
//! pump tasks regardless. This module always passes
//! `websocket_tunnel_mode = false` to `run_websocket_proxy`. Operators
//! who enabled tunnel mode for H1/H2 throughput get H3 frame-parsing
//! semantics automatically — frame-level plugins (`on_ws_frame`,
//! `ws_rate_limit`, `ws_message_size_limiting`, `ws_frame_logging`) work
//! on H3 sessions whether or not tunnel mode is set globally.
//!
//! ## Circuit breaker + load balancer accounting
//!
//! The H3 path applies the same circuit-breaker + load-balancer
//! accounting as the H1/H2 path so backend isolation and target-level
//! connection counts stay consistent across frontends:
//!
//! - Backend connect failure → `record_failure(502, is_pre_wire, is_half_open_probe)`
//!   using the same `request_reached_wire` boundary as the H1/H2 retry
//!   loop. A backend that received the upgrade and rejected it (post-wire)
//!   does NOT charge passive health as a connect-class failure.
//! - Successful 200 upgrade response → `record_success(is_half_open_probe)`
//!   so a half-open probe that bootstraps a WebSocket counts as a
//!   recovery sample.
//! - Pre-wire backend connect failures honor the proxy retry policy and
//!   rotate upstream targets using the same load-balancer snapshot as the
//!   H1/H2 WebSocket path. Backend-side upgrade rejections are post-wire
//!   and are not retried.
//! - `LoadBalancerConnectionGuard` is captured for the session lifetime;
//!   it increments the final selected target's connection counter on
//!   construction and decrements on drop, so a long-lived H3 WebSocket
//!   session correctly weights least-connection load balancing.
//!
//! ## Graceful shutdown
//!
//! The caller transfers its request-side `RequestGuard` to this module.
//! After WebSocket connection-limit admission succeeds, the H3 WS session
//! captures a fresh `ConnectionGuard` (the same RAII type the H1/H2 path
//! uses for its long-lived sessions) and then drops the request guard.
//! That handoff keeps backend handshake failures visible to overload
//! pressure and `SIGTERM` drain while avoiding counting an established,
//! long-lived upgraded socket as an active request.
//!
//! ## 0-RTT
//!
//! Extended CONNECT is NOT a default 0-RTT method — operators who
//! enable QUIC early data via `FERRUM_TLS_EARLY_DATA_METHODS` must
//! opt in by listing `CONNECT` explicitly. The gateway forwards
//! `Early-Data: 1` to the backend on 0-RTT replays as documented in
//! the global H3 architecture section; backends decide whether to
//! honor or reject WebSocket upgrades carried in early data.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use chrono::Utc;
use h3::server::RequestStream;
use http::{Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::config::types::{Proxy, UpstreamTarget};
use crate::load_balancer::LoadBalancer;
use crate::plugins::{
    BackendAdmissionOutcome, BackendAdmissionPermitSet, Plugin, ProxyProtocol, RequestContext,
    TransactionSummary,
};
use crate::proxy::{ProxyState, WsSessionMeta};
use crate::request_epoch::RequestEpoch;
use crate::retry;

/// Internal buffer size for the H3 ↔ WebSocket-framer duplex bridge.
/// See module-level docs for rationale.
const H3_WS_DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Scratch read buffer for the send pump. This is deliberately smaller
/// than the duplex capacity because each read is immediately copied into
/// an h3 DATA `Bytes`; keeping it at 16 KiB caps per-session bridge memory
/// while still batching small frames.
const H3_WS_SEND_PUMP_READ_BUFFER_BYTES: usize = 16 * 1024;
const H3_WS_PUMP_DRAIN_GRACE: Duration = Duration::from_secs(30);
const H3_WS_PROTOCOL_ERROR_CLOSE_CODE: u16 = 1002;
const H3_WS_MASKED_FRAME_CLOSE_REASON: &str = "masked frame over HTTP/3";

struct H3WsMaskValidator {
    header: Vec<u8>,
    remaining_payload: u64,
}

impl H3WsMaskValidator {
    fn new() -> Self {
        Self {
            header: Vec::with_capacity(10),
            remaining_payload: 0,
        }
    }

    fn validate(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            if self.remaining_payload > 0 {
                let skipped = bytes
                    .len()
                    .min(usize::try_from(self.remaining_payload).unwrap_or(usize::MAX));
                self.remaining_payload -= skipped as u64;
                bytes = &bytes[skipped..];
                continue;
            }

            let needed = self.needed_header_bytes();
            let take = bytes.len().min(needed);
            self.header.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];

            if self.header.len() >= 2 && (self.header[1] & 0x80) != 0 {
                return Err(());
            }

            if self.header_complete() {
                self.remaining_payload = self.payload_len();
                self.header.clear();
            }
        }

        Ok(())
    }

    fn needed_header_bytes(&self) -> usize {
        let target: usize = match self.header.get(1).map(|byte| byte & 0x7f) {
            Some(126) => 4,
            Some(127) => 10,
            Some(_) => 2,
            None => 2,
        };
        target.saturating_sub(self.header.len())
    }

    fn header_complete(&self) -> bool {
        self.needed_header_bytes() == 0 && self.header.len() >= 2
    }

    fn payload_len(&self) -> u64 {
        match self.header[1] & 0x7f {
            len @ 0..=125 => u64::from(len),
            126 => u64::from(u16::from_be_bytes([self.header[2], self.header[3]])),
            127 => u64::from_be_bytes([
                self.header[2],
                self.header[3],
                self.header[4],
                self.header[5],
                self.header[6],
                self.header[7],
                self.header[8],
                self.header[9],
            ]),
            _ => 0,
        }
    }
}

fn h3_ws_close_frame(code: u16, reason: &str) -> Bytes {
    let reason_bytes = reason.as_bytes();
    let reason_len = reason_bytes.len().min(123);
    let payload_len = 2 + reason_len;
    let mut frame = Vec::with_capacity(2 + payload_len);
    frame.push(0x88);
    frame.push(payload_len as u8);
    frame.extend_from_slice(&code.to_be_bytes());
    frame.extend_from_slice(&reason_bytes[..reason_len]);
    Bytes::from(frame)
}

struct AbortOnDropJoinHandle {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AbortOnDropJoinHandle {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }

    async fn abort_and_wait(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

async fn wait_for_h3_ws_send_pump(
    proxy_id: &str,
    mut send_pump: AbortOnDropJoinHandle,
    drain_grace: Duration,
) {
    let Some(mut handle) = send_pump.handle.take() else {
        return;
    };
    if tokio::time::timeout(drain_grace, &mut handle)
        .await
        .is_err()
    {
        warn!(
            proxy_id = %proxy_id,
            drain_grace_seconds = drain_grace.as_secs(),
            "H3 WS send pump drain grace expired; aborting pump"
        );
        handle.abort();
        let _ = handle.await;
    }
}

impl Drop for AbortOnDropJoinHandle {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// Listen-port label for the `WsSessionMeta` that backs on_ws_disconnect.
/// H3 always lands on the HTTPS port (port 0 disables H3 entirely; the
/// listener wouldn't be running).
fn h3_listen_port(state: &ProxyState) -> u16 {
    state.env_config.proxy_https_port
}

/// Convert any `h3::quic::RecvStream` `impl Buf` chunk into an owned
/// `Bytes` value. The h3 API returns `Result<Option<impl Buf>, ...>` —
/// `impl Buf` is opaque, so we materialise it before crossing the
/// task / channel boundary.
#[inline]
fn buf_into_bytes<B: Buf>(mut buf: B) -> Bytes {
    let len = buf.remaining();
    buf.copy_to_bytes(len)
}

/// Strip hop-by-hop headers and HTTP/1.1 WebSocket handshake artefacts
/// before forwarding the WebSocket request to the backend. Identical
/// list to `crate::proxy::collect_forwardable_headers` — duplicated
/// here because the H3 frontend has `proxy_headers: HashMap` while the
/// H1/H2 path has `hyper::HeaderMap` and the same predicate doesn't
/// directly reuse.
fn collect_forwardable_h3_headers(
    headers: &HashMap<String, String>,
    is_early_data: bool,
) -> Vec<(String, String)> {
    /// hop-by-hop per RFC 9110 §7.6.1 + WS handshake.
    const SKIP_HEADERS: &[&str] = &[
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-accept",
        // The WebSocket bridge cannot encode/decode permessage-deflate, so the
        // client's extension offer must not reach the backend (it would set
        // rsv1 and the session would be torn down). Mirrors the H1/H2 strip in
        // proxy::is_websocket_backend_strip_header.
        "sec-websocket-extensions",
        "host",
        "transfer-encoding",
        "te",
        "trailer",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        // RFC 8470 §5.2: clients do not set this. The gateway strips any
        // inbound value and injects its authoritative value below.
        "early-data",
        // H3 pseudo-headers that may still be present in the
        // header map produced upstream — never forward.
        ":method",
        ":scheme",
        ":authority",
        ":path",
        ":protocol",
        ":status",
        // Reserved gateway assertion headers. Strip the mutable map so the
        // authenticated principal and private GeoIP value can be re-injected
        // below with single-value override semantics.
        "x-consumer-username",
        "x-consumer-custom-id",
        "x-geo-country",
    ];

    let mut out: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            if SKIP_HEADERS.contains(&lower.as_str()) {
                return None;
            }
            Some((lower, value.clone()))
        })
        .collect();

    if is_early_data {
        out.push(("early-data".to_string(), "1".to_string()));
    }

    out
}

/// Insert or replace a header in the forwardable list, removing any existing
/// case-insensitive match first so a reserved name cannot appear twice. Mirrors
/// `proxy::push_forwardable_header_override` on the H1/H2 path.
fn push_h3_forwardable_header_override(
    headers: &mut Vec<(String, String)>,
    name: &str,
    value: String,
) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value));
}

/// Write a small JSON error body on the H3 stream and finish.
pub(crate) async fn send_h3_error_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &'static str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    send_h3_reject_body(
        stream,
        status,
        body.as_bytes(),
        HashMap::new(),
        initial_response_header_policy_plugins,
    )
    .await;
}

async fn send_h3_reject_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &[u8],
    mut headers: HashMap<String, String>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    ensure_h3_reject_content_type(&mut headers);
    crate::plugins::apply_initial_response_header_policies(
        initial_response_header_policy_plugins,
        &mut headers,
    );
    write_h3_finalized_reject_body(stream, status, body, headers).await;
}

/// Finalize a failed RFC 9220 handshake immediately before its HEADERS frame is
/// built. Response hooks and policy overlays run before this boundary, so none
/// can leak H1 Upgrade or WebSocket negotiation fields onto a non-upgrade H3
/// response. Content-Type is seeded before those hooks run, so its absence here
/// is an authoritative policy removal and must not be defaulted back.
pub(crate) fn finalize_h3_websocket_reject_headers(headers: &mut HashMap<String, String>) {
    crate::proxy::strip_websocket_transport_managed_response_header_map(headers);
}

fn ensure_h3_reject_content_type(headers: &mut HashMap<String, String>) {
    if !headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("content-type"))
    {
        headers.insert("content-type".to_string(), "application/json".to_string());
    }
}

async fn write_h3_finalized_reject_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &[u8],
    mut headers: HashMap<String, String>,
) where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    finalize_h3_websocket_reject_headers(&mut headers);
    let builder =
        crate::proxy::headers::apply_response_headers(Response::builder().status(status), &headers);
    let resp = match builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            error!("H3 WS: failed to build reject response: {}", e);
            return;
        }
    };
    if let Err(e) = stream.send_response(resp).await {
        debug!("H3 WS: failed to send reject response: {}", e);
        return;
    }
    if !body.is_empty()
        && let Err(e) = stream.send_data(Bytes::copy_from_slice(body)).await
    {
        debug!("H3 WS: failed to send reject body: {}", e);
    }
    if let Err(e) = stream.finish().await {
        debug!("H3 WS: failed to finish stream after reject: {}", e);
    }
    crate::http3::stream_util::halt_request_body(stream);
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_backend_admission_rejection<S>(
    stream: &mut RequestStream<S, Bytes>,
    rejection: crate::proxy::backend_dispatch::BackendAdmissionRejection,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    state: &ProxyState,
    start_time: Instant,
    plugin_execution_ns: u64,
    original_request_path: &str,
) where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    let mut rejection = rejection;
    let mut headers = rejection.headers;
    ensure_h3_reject_content_type(&mut headers);
    crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
        plugins,
        ctx,
        &mut rejection.status_code,
        &mut rejection.body,
        &mut headers,
    )
    .await;
    let status =
        StatusCode::from_u16(rejection.status_code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    crate::proxy::log_rejected_request_with_path(
        plugins,
        ctx,
        status.as_u16(),
        start_time,
        &rejection.plugin_name,
        plugin_execution_ns,
        Some(original_request_path),
    )
    .await;
    crate::proxy::record_request(state, status.as_u16());
    write_h3_finalized_reject_body(stream, status, &rejection.body, headers).await;
}

pub(crate) fn release_h3_ws_circuit_breaker_probe_on_admission_reject(
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

/// H3 WebSocket entry point. Called from `handle_h3_request` when
/// `HttpFlavor::WebSocket` is detected on an HTTP/3 request and
/// `FERRUM_HTTP3_WEBSOCKET_ENABLED` is true.
///
/// Consumes the full `RequestStream` because we need to `split()` it
/// into independent send/recv halves to drive the bridge pumps from
/// separate tasks.
///
/// Authentication, authorization, and `before_proxy` plugin phases
/// have already run by the time this function is called — the caller
/// has the full plugin chain and the resolved `RequestContext`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_h3_websocket(
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: Arc<ProxyState>,
    request_guard: crate::overload::RequestGuard,
    per_ip_guard: Option<crate::proxy::PerIpRequestGuard>,
    epoch: Arc<RequestEpoch>,
    proxy: Arc<Proxy>,
    ctx: RequestContext,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    initial_response_header_policy_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    backend_admission_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    plugin_execution_ns: u64,
    upstream_target: Option<Arc<UpstreamTarget>>,
    upstream_balancer: Option<Arc<LoadBalancer>>,
    lb_hash_key: Option<String>,
    sticky_cookie_needed: bool,
    start_time: Instant,
    cb_target_key: Option<String>,
    cb_is_half_open_probe: bool,
    backend_url: String,
    query_string: String,
    proxy_headers: HashMap<String, String>,
    requires_websocket_framing: bool,
    is_early_data: bool,
    strip_len: usize,
    backend_path_is_policy_bound: bool,
    // The client-requested path before any VirtualService `rewrite.uri` was
    // applied. Used for `request_path` in transaction logs so that access
    // logs record what the client sent, not the backend-rewritten path in
    // `ctx.path`.
    original_request_path: String,
) -> Result<(), anyhow::Error> {
    // Defense in depth: dispatcher already checked this. If the flag
    // got toggled mid-flight, return 501 rather than half-bridging.
    if !state.env_config.http3_websocket_enabled {
        warn!(
            proxy_id = %proxy.id,
            "H3 WebSocket is disabled but request was dispatched here; returning 501"
        );
        send_h3_error_body(
            &mut stream,
            StatusCode::NOT_IMPLEMENTED,
            r#"{"error":"WebSocket over HTTP/3 is disabled on this gateway"}"#,
            &initial_response_header_policy_plugins,
        )
        .await;
        crate::proxy::record_request(&state, 501);
        // Gateway-side reject after the caller's CB check — release a claimed
        // HALF_OPEN probe slot so the breaker doesn't wedge.
        release_h3_ws_circuit_breaker_probe_on_admission_reject(
            &state,
            &proxy,
            cb_target_key.as_deref(),
            cb_is_half_open_probe,
        );
        return Ok(());
    }

    info!(
        proxy_id = %proxy.id,
        client_ip = %ctx.client_ip,
        "H3 WebSocket (RFC 9220) upgrade request received"
    );
    let mut ctx = ctx;

    // ── Connection admission ─────────────────────────────────────────
    let ws_connection_permit = match crate::proxy::try_acquire_websocket_connection_permit(
        state.websocket_conn_limit.as_ref(),
    ) {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                proxy_id = %proxy.id,
                client_ip = %ctx.client_ip,
                websocket_limit = state.env_config.websocket_max_connections,
                "Rejecting H3 WebSocket upgrade: connection limit reached"
            );
            // Log the rejection through the same `log_rejected_request_with_path`
            // helper the H1/H2 path uses so transaction logs are uniform
            // across frontends (rejection_phase = "websocket_connection_limit",
            // metadata redaction, log_with_mirror, etc.). Supply the original
            // client path so the log records what the client requested, not the
            // VirtualService-rewritten backend path stored in ctx.path.
            crate::proxy::log_rejected_request_with_path(
                &plugins,
                &ctx,
                503,
                start_time,
                "websocket_connection_limit",
                plugin_execution_ns,
                Some(&original_request_path),
            )
            .await;
            crate::proxy::record_request(&state, 503);
            send_h3_error_body(
                &mut stream,
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"WebSocket connection limit exceeded"}"#,
                &initial_response_header_policy_plugins,
            )
            .await;
            // Gateway-side reject after the caller's CB check — release a
            // claimed HALF_OPEN probe slot so the breaker doesn't wedge.
            release_h3_ws_circuit_breaker_probe_on_admission_reject(
                &state,
                &proxy,
                cb_target_key.as_deref(),
                cb_is_half_open_probe,
            );
            return Ok(());
        }
    };

    // Handoff overload accounting from "active request/stream" to
    // "long-lived WebSocket connection" before the backend handshake. This
    // keeps slow or failing backend connects visible to graceful drain and
    // connection pressure, while avoiding request-count double accounting for
    // the established session lifetime.
    let ws_session_guard = crate::overload::ConnectionGuard::new(&state.overload);
    drop(request_guard);

    // ── Build forwardable header list for the backend handshake ─────
    let mut client_headers = collect_forwardable_h3_headers(&proxy_headers, is_early_data);
    // Override semantics (not append): collect_forwardable_h3_headers already
    // strips any reserved identity headers from the forwarded map, but use the
    // override helper anyway so a single authoritative value is guaranteed even
    // if a future change reintroduces one of these names upstream.
    if let Some(username) = ctx.backend_consumer_username() {
        push_h3_forwardable_header_override(
            &mut client_headers,
            "x-consumer-username",
            username.to_string(),
        );
    }
    if let Some(custom_id) = ctx.backend_consumer_custom_id() {
        push_h3_forwardable_header_override(
            &mut client_headers,
            "x-consumer-custom-id",
            custom_id.to_string(),
        );
    }
    if let Some(country) = ctx.backend_geo_country() {
        push_h3_forwardable_header_override(
            &mut client_headers,
            "x-geo-country",
            country.to_string(),
        );
    }
    crate::modes::mesh::hbone::strip_egress_baggage_in_vec(
        &mut client_headers,
        &state.mesh_egress_strip_baggage_keys,
    );

    // ── Backend WebSocket handshake (reuses H1.1 Upgrade path) ──────
    //
    // H3 mirrors H1/H2 WebSocket retry semantics: retry only pre-wire
    // setup failures when `retry_on_connect_failure` is enabled, and rotate
    // upstream targets through the same load-balancer cache. Backend-side
    // upgrade rejections are post-wire and must not be replayed.
    let ws_size_limits = crate::proxy::EffectiveWsSizeLimits::from_plugins(
        state.max_websocket_frame_size_bytes,
        &plugins,
    );
    let mut current_backend_url = backend_url;
    let mut current_target = upstream_target;
    let mut current_cb_target_key = cb_target_key;
    let mut backend_admission_permits: Option<BackendAdmissionPermitSet>;
    let mut backend_admission_start: Instant;
    let mut ws_cb_probe_slot_available = cb_is_half_open_probe;
    let mut ws_attempt = 0u32;

    // Connection-wide idle tracker created BEFORE the backend dial so the
    // byte-level activity adapter can be installed under the backend framer
    // inside `connect_websocket_backend`; the same tracker is later wired
    // under the client framer by `run_websocket_proxy`. `None` disables the
    // idle bound entirely.
    //
    // NOTE (H3): this is NOT the only idle bound on the QUIC path. Quinn's
    // `max_idle_timeout` (from `FERRUM_HTTP3_IDLE_TIMEOUT`, default 30s; see
    // `http3::server`) closes an idle QUIC connection independently. A
    // WebSocket idle value larger than the QUIC idle timeout — including `0`
    // (disabled) — cannot guarantee that an otherwise-idle H3 connection stays
    // open past the connection idle timeout. Multiplexed H3 connections with
    // other active streams can remain alive. Startup/reload config warnings
    // surface this interaction only when an H3 WebSocket listener is actually
    // reachable.
    let ws_idle_tracker = crate::proxy::WsIdleTracker::from_timeout_seconds(
        proxy.effective_websocket_idle_timeout_seconds(
            state.env_config.websocket_idle_timeout_seconds,
        ),
    );
    // The backend WebSocket connection acquired below is held for the full
    // session lifetime (the inline relay below, until this function returns),
    // so this guard's slot releases exactly when the dedicated backend
    // connection closes. Captured out of the loop alongside the handshake.
    let backend_conn_guard;
    let backend_handshake = loop {
        // The H3 WebSocket bridge has no `websocket_mesh_egress` fork —
        // `connect_websocket_backend` is a plain TCP/TLS dial. A direct dial to
        // a mesh-tagged target would bypass the secured mesh transport, so fail
        // closed BEFORE dialing (issue #2007). Sits at the loop top so the
        // initial target AND every retry-rotated target re-entering the loop
        // are screened.
        if let Some(reason) = crate::proxy::backend_dispatch::direct_http_mesh_transport_refusal(
            current_target.as_deref(),
        ) {
            warn!(
                proxy_id = %proxy.id,
                target_host = current_target.as_deref().map(|target| target.host.as_str()).unwrap_or(""),
                target_port = current_target.as_deref().map(|target| target.port).unwrap_or(0),
                reason,
                "H3 WebSocket: refusing direct dial to a mesh-transport-tagged target"
            );
            // Gateway-side dispatch-policy shed with no backend dialed: neutral
            // to the breaker (releases a claimed HALF_OPEN probe slot) and to
            // passive health / latency, matching the H3 plain bridge's refusal
            // arm. No conn slot, admission permits, or LB connection start are
            // held at the loop top, so nothing else needs releasing.
            crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
                &state,
                &proxy,
                &epoch.load_balancer,
                upstream_balancer.as_ref(),
                current_target.as_deref(),
                current_cb_target_key.as_deref(),
                502,
                false,
                Some(retry::ErrorClass::DispatchPolicyRejected),
                ws_cb_probe_slot_available,
                false,
                start_time.elapsed(),
            );
            crate::proxy::record_request(&state, 502);
            emit_failed_upgrade_summary(
                &state,
                &proxy,
                &ctx,
                &proxy_headers,
                &plugins,
                plugin_execution_ns,
                start_time,
                &current_backend_url,
                crate::proxy::websocket_dns_resolution_host(&proxy, current_target.as_deref()),
                retry::ErrorClass::DispatchPolicyRejected,
                &original_request_path,
            )
            .await;
            let reason_headers =
                HashMap::from([("gateway-error-reason".to_string(), reason.to_string())]);
            send_h3_reject_body(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                br#"{"error":"Bad Gateway","message":"Mesh transport dispatch required for this backend target"}"#,
                reason_headers,
                &initial_response_header_policy_plugins,
            )
            .await;
            drop(ws_connection_permit);
            return Ok(());
        }

        // Enforce DestinationRule `connectionPool.tcp.maxConnections` for this
        // destination policy port BEFORE dialing — same semantics and ordering
        // as the H1/H2 path in `src/proxy/mod.rs`. No cap => `Ok(None)`, a
        // single check with no map touch.
        let (ws_dial_host, ws_dial_port, ws_policy_port) = match &current_target {
            Some(target) => (
                target.host.as_str(),
                target.port,
                target.dispatch_policy_port(),
            ),
            None => (
                proxy.backend_host.as_str(),
                proxy.backend_port,
                proxy.backend_port,
            ),
        };
        let ws_max_connections =
            crate::proxy::resolve_backend_max_connections(&proxy, ws_policy_port);
        let conn_slot = match state.backend_conn_limit.try_acquire(
            ws_dial_host,
            ws_policy_port,
            ws_max_connections,
        ) {
            Ok(slot) => slot,
            Err(limit) => {
                warn!(
                    proxy_id = %proxy.id,
                    client_ip = %ctx.client_ip,
                    backend_host = %ws_dial_host,
                    backend_port = ws_dial_port,
                    open_connections = limit.current,
                    max_connections = limit.cap,
                    "Rejecting H3 WebSocket upgrade: DestinationRule maxConnections reached for backend"
                );
                crate::proxy::log_rejected_request_with_path(
                    &plugins,
                    &ctx,
                    503,
                    start_time,
                    "backend_max_connections",
                    plugin_execution_ns,
                    Some(&original_request_path),
                )
                .await;
                crate::proxy::record_request(&state, 503);
                send_h3_error_body(
                    &mut stream,
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"error":"Backend connection limit exceeded"}"#,
                    &initial_response_header_policy_plugins,
                )
                .await;
                // Gateway-side reject after the CB check — release a claimed
                // HALF_OPEN probe slot so the breaker doesn't wedge.
                release_h3_ws_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    current_cb_target_key.as_deref(),
                    ws_cb_probe_slot_available,
                );
                drop(ws_connection_permit);
                return Ok(());
            }
        };

        backend_admission_start = Instant::now();
        backend_admission_permits =
            match crate::proxy::backend_dispatch::run_backend_admission_plugins(
                backend_admission_plugins.as_ref(),
                &ctx,
                &proxy,
                current_target.as_deref(),
                ProxyProtocol::WebSocket,
            ) {
                Ok(permits) => permits,
                Err(rejection) => {
                    drop(conn_slot);
                    release_h3_ws_circuit_breaker_probe_on_admission_reject(
                        &state,
                        &proxy,
                        current_cb_target_key.as_deref(),
                        ws_cb_probe_slot_available,
                    );
                    send_h3_backend_admission_rejection(
                        &mut stream,
                        rejection,
                        &plugins,
                        &mut ctx,
                        &state,
                        start_time,
                        plugin_execution_ns,
                        &original_request_path,
                    )
                    .await;
                    drop(ws_connection_permit);
                    return Ok(());
                }
            };

        let ws_connection_proxy = crate::proxy::resolve_backend_connection_proxy_for_target(
            &proxy,
            current_target.as_deref(),
        );
        let ws_dial_proxy = ws_connection_proxy.as_ref();
        match crate::proxy::connect_websocket_backend(
            &current_backend_url,
            ws_dial_proxy,
            &state.env_config,
            &client_headers,
            state.tls_policy.as_deref(),
            &state.crls,
            ws_size_limits.max_frame_bytes,
            ws_size_limits.max_message_bytes,
            state.websocket_write_buffer_size,
            ws_idle_tracker.clone(),
            Some(&state.dns_cache),
        )
        .await
        {
            Ok(handshake) => {
                backend_conn_guard = conn_slot;
                break handshake;
            }
            Err(e) => {
                // Connect/handshake failed: free this destination's slot before
                // a retry so a rotated target acquires its own slot and a
                // failed attempt never leaks a count.
                drop(conn_slot);
                // `connect_websocket_backend` covers more than TCP+TLS setup:
                // it ALSO sends the WebSocket upgrade request and reads the
                // backend's response. Use the same unified
                // `request_reached_wire` boundary as the H1/H2 path so a
                // backend-side upgrade rejection (post-wire) does NOT retry
                // and does NOT charge the breaker as a connect-class failure.
                let ws_error_class = retry::classify_boxed_setup_error(e.as_ref());
                let is_ws_dns_error = ws_error_class == retry::ErrorClass::DnsLookupError;
                let ws_is_pre_wire = !retry::request_reached_wire(ws_error_class);
                // A gateway-side egress-policy denial (denied literal/rebound H3
                // WebSocket backend) never reached a backend: non-retryable AND
                // neutral to backend health (no CB trip, no backend-admission
                // failure), matching the H1/H2 path.
                let ws_egress_denied =
                    matches!(ws_error_class, retry::ErrorClass::DispatchPolicyRejected);
                let retry_delay = proxy.retry.as_ref().and_then(|retry_config| {
                    (ws_attempt < retry_config.max_retries
                        && retry_config.retry_on_connect_failure
                        && ws_is_pre_wire
                        && !ws_egress_denied)
                        .then(|| retry::retry_delay(retry_config, ws_attempt))
                });

                let mut cb_failure_already_recorded = false;
                let mut backend_outcome_already_recorded = false;

                if let Some(delay) = retry_delay {
                    if let Some(permits) = backend_admission_permits.take() {
                        permits.record_backend_outcome(BackendAdmissionOutcome {
                            response_status: 502,
                            connection_error: ws_is_pre_wire,
                            error_class: Some(ws_error_class),
                            backend_elapsed: backend_admission_start.elapsed(),
                        });
                        backend_outcome_already_recorded = true;
                    }
                    if let Some(cb_config) = &proxy.circuit_breaker {
                        let cb = state.circuit_breaker_cache.get_or_create(
                            &proxy.id,
                            current_cb_target_key.as_deref(),
                            cb_config,
                        );
                        cb.record_failure(502, ws_is_pre_wire, ws_cb_probe_slot_available);
                        ws_cb_probe_slot_available = false;
                        cb_failure_already_recorded = true;
                    }

                    let mut retry_backend_url = current_backend_url.clone();
                    let mut retry_target = current_target.clone();
                    let mut retry_cb_target_key = current_cb_target_key.clone();
                    let mut retry_path_mismatch = false;

                    if let (Some(_upstream_id), Some(prev_target), Some(hash_key)) =
                        (&proxy.upstream_id, &current_target, lb_hash_key.as_deref())
                        && let Some(next) = crate::proxy::backend_dispatch::select_next_retry_target(
                            &state,
                            &epoch,
                            &proxy,
                            prev_target,
                            hash_key,
                            &ctx.client_ip,
                            &proxy_headers,
                        )
                    {
                        if !crate::proxy::retry_target_preserves_backend_path(
                            backend_path_is_policy_bound,
                            &proxy,
                            &ctx.path,
                            strip_len,
                            prev_target,
                            &next,
                        ) {
                            retry_path_mismatch = true;
                            warn!(
                                proxy_id = %proxy.id,
                                "Aborting H3 WebSocket retry because the candidate would change the authorized backend method path"
                            );
                        } else {
                            retry_backend_url =
                                crate::proxy::build_websocket_backend_url_with_target(
                                    &proxy,
                                    &ctx.path,
                                    &query_string,
                                    &next.host,
                                    next.port,
                                    strip_len,
                                    next.path.as_deref(),
                                );
                            retry_cb_target_key =
                                Some(crate::circuit_breaker::target_key(&next.host, next.port));
                            retry_target = Some(next);
                        }
                    }

                    if !retry_path_mismatch {
                        tokio::time::sleep(delay).await;
                        ws_attempt += 1;
                    }

                    let mut retry_admitted_by_cb = true;
                    if !retry_path_mismatch && let Some(cb_config) = &proxy.circuit_breaker {
                        match state.circuit_breaker_cache.can_execute(
                            &proxy.id,
                            retry_cb_target_key.as_deref(),
                            cb_config,
                        ) {
                            Ok((_cb, is_half_open_probe)) => {
                                ws_cb_probe_slot_available = is_half_open_probe;
                            }
                            Err(_) => {
                                retry_admitted_by_cb = false;
                                warn!(
                                    proxy_id = %proxy.id,
                                    attempt = ws_attempt,
                                    "H3 WebSocket retry target rejected by circuit breaker"
                                );
                            }
                        }
                    }

                    if retry_admitted_by_cb && !retry_path_mismatch {
                        current_backend_url = retry_backend_url;
                        current_target = retry_target;
                        current_cb_target_key = retry_cb_target_key;

                        warn!(
                            proxy_id = %proxy.id,
                            attempt = ws_attempt,
                            max_retries = proxy.retry.as_ref().map(|r| r.max_retries).unwrap_or(0),
                            error_class = %ws_error_class,
                            "Retrying H3 WebSocket backend connection"
                        );
                        continue;
                    }
                }

                error!(
                    proxy_id = %proxy.id,
                    backend_url = %current_backend_url,
                    error_kind = retry::error_class_log_kind(ws_error_class),
                    error_class = %ws_error_class,
                    error = %e,
                    "H3 WebSocket backend connection failed"
                );
                if !backend_outcome_already_recorded
                    && !ws_egress_denied
                    && let Some(permits) = backend_admission_permits.take()
                {
                    permits.record_backend_outcome(BackendAdmissionOutcome {
                        response_status: 502,
                        connection_error: ws_is_pre_wire,
                        error_class: Some(ws_error_class),
                        backend_elapsed: backend_admission_start.elapsed(),
                    });
                }

                if !cb_failure_already_recorded && let Some(cb_config) = &proxy.circuit_breaker {
                    let cb = state.circuit_breaker_cache.get_or_create(
                        &proxy.id,
                        current_cb_target_key.as_deref(),
                        cb_config,
                    );
                    if ws_egress_denied {
                        // Gateway-side egress denial dialed no backend: release any
                        // admitted HALF_OPEN probe slot NEUTRALLY so the breaker can
                        // recover, rather than leaking it by skipping the record.
                        cb.record_neutral(ws_cb_probe_slot_available);
                    } else {
                        cb.record_failure(502, ws_is_pre_wire, ws_cb_probe_slot_available);
                    }
                }

                crate::proxy::record_request(&state, 502);

                // Emit the TransactionSummary for the failed upgrade so
                // log plugins see the rejection.
                if !plugins.is_empty() {
                    emit_failed_upgrade_summary(
                        &state,
                        &proxy,
                        &ctx,
                        &proxy_headers,
                        &plugins,
                        plugin_execution_ns,
                        start_time,
                        &current_backend_url,
                        crate::proxy::websocket_dns_resolution_host(
                            &proxy,
                            current_target.as_deref(),
                        ),
                        ws_error_class,
                        &original_request_path,
                    )
                    .await;
                }

                let ws_body = if is_ws_dns_error {
                    r#"{"error":"DNS resolution for backend failed"}"#
                } else {
                    r#"{"error":"Backend WebSocket connection failed"}"#
                };
                send_h3_error_body(
                    &mut stream,
                    StatusCode::BAD_GATEWAY,
                    ws_body,
                    &initial_response_header_policy_plugins,
                )
                .await;
                drop(ws_connection_permit);
                return Ok(());
            }
        }
    };

    // Backend handshake succeeded. If this request was admitted as a
    // half-open probe, record the success so the breaker can close.
    // Matches the H1/H2 path's behavior on the successful upgrade hop.
    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state.circuit_breaker_cache.get_or_create(
            &proxy.id,
            current_cb_target_key.as_deref(),
            cb_config,
        );
        cb.record_success(ws_cb_probe_slot_available);
    }

    // Capture the LB connection guard NOW — before the 200 is sent — so
    // a panic anywhere below still releases the per-target connection
    // count. The guard is moved into the session task below.
    let ws_lb_guard = crate::proxy::LoadBalancerConnectionGuard::new(
        current_target.clone(),
        upstream_balancer.clone(),
    );
    if let Some(permits) = backend_admission_permits.as_ref() {
        // The permit is held for the full session (moved into the task below),
        // so record the handshake latency without growing the limit — matching
        // the H1/H2 WebSocket path. Growing here would ratchet the limit up on
        // every concurrent session and defeat the in-flight session cap.
        permits.record_backend_outcome_holding(BackendAdmissionOutcome {
            response_status: 200,
            connection_error: false,
            error_class: None,
            backend_elapsed: backend_admission_start.elapsed(),
        });
    }
    let _backend_admission_permits = backend_admission_permits;

    // ── Send 200 OK response on the H3 stream (RFC 9220 §4) ─────────
    //
    // No Upgrade / Connection / Sec-WebSocket-Accept headers (those
    // are HTTP/1.1 only). The QUIC stream becomes the WebSocket
    // transport as soon as the client sees the 200.
    let mut response_headers = HashMap::new();
    crate::proxy::finalize_successful_websocket_response_headers(
        &plugins,
        &ctx,
        StatusCode::OK.as_u16(),
        &mut response_headers,
    );

    // Sticky session cookie on the WS upgrade response, mirroring the
    // H1/H2 path. Gateway affinity is injected after operator response
    // policy so the selected-target cookie cannot be removed or replaced.
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &current_target)
    {
        let strategy = crate::proxy::backend_dispatch::hash_on_strategy_for_selected_target(
            &proxy,
            &epoch.load_balancer,
            upstream_id,
            target,
        );
        if let crate::load_balancer::HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = crate::load_balancer::LoadBalancerCache::get_upstream_from(
                &epoch.load_balancer,
                upstream_id,
            );
            let default_cc = crate::config::types::HashOnCookieConfig::default();
            let cookie_config = upstream
                .as_ref()
                .and_then(|u| u.hash_on_cookie_config.as_ref())
                .unwrap_or(&default_cc);
            let cookie_val =
                crate::proxy::build_sticky_cookie_header(cookie_name, target, cookie_config);
            crate::proxy::headers::append_set_cookie_header(&mut response_headers, cookie_val);
        }
    }
    let mut response_builder = crate::proxy::headers::apply_response_headers(
        Response::builder().status(StatusCode::OK),
        &response_headers,
    );

    // Forward the backend's negotiated subprotocol (RFC 6455 §11.3.4,
    // applicable to RFC 9220 Extended CONNECT via RFC 8441 §5.2). Add this
    // transport-owned field after policy enforcement so policy cannot invent
    // or remove the backend-negotiated value.
    if let Some(proto) = backend_handshake.negotiated_subprotocol.clone() {
        response_builder = response_builder.header("sec-websocket-protocol", proto);
    }
    let response = match response_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            error!(proxy_id = %proxy.id, "H3 WS: failed to build 200 response: {}", e);
            return Err(anyhow::anyhow!("failed to build H3 WebSocket 200: {}", e));
        }
    };
    crate::proxy::record_request(&state, 200);

    if let Err(e) = stream.send_response(response).await {
        error!(proxy_id = %proxy.id, "H3 WS: failed to send 200 response: {}", e);
        return Err(anyhow::anyhow!("H3 WebSocket send_response: {}", e));
    }

    // Per-IP request accounting handoff: the upgrade is complete and the
    // session is now a long-lived "connection" tracked by
    // `ws_session_guard` (overload `active_connections`) and the WebSocket
    // connection permit. Dropping the per-IP REQUEST guard here matches
    // the H1/H2 path — there, `handle_websocket_request_authenticated`
    // returns the upgrade response and the caller's `_per_ip_guard`
    // drops as the function unwinds, BEFORE the spawned WS session
    // continues. Keeping it for the full session lifetime would let one
    // long-lived H3 WebSocket block normal H1/H2/H3 requests from the
    // same IP for the entire session duration.
    drop(per_ip_guard);

    let backend_ws_stream = backend_handshake.stream;

    // Emit the successful-upgrade TransactionSummary now — same shape
    // the H1/H2 path emits at upgrade time.
    emit_successful_upgrade_summary(
        &state,
        &proxy,
        &ctx,
        &proxy_headers,
        &plugins,
        plugin_execution_ns,
        start_time,
        &current_backend_url,
        crate::proxy::websocket_dns_resolution_host(&proxy, current_target.as_deref()),
        &original_request_path,
    )
    .await;

    // ── Split the H3 stream and spawn pump tasks ────────────────────
    let (mut h3_send, mut h3_recv) = stream.split();
    let (client_io, pump_io) = tokio::io::duplex(H3_WS_DUPLEX_BUFFER_BYTES);
    let (mut pump_read, mut pump_write) = tokio::io::split(pump_io);
    let (forced_close_tx, mut forced_close_rx) = tokio::sync::mpsc::channel::<Bytes>(1);

    let proxy_id_for_pumps = proxy.id.clone();

    // h3_recv → pump_write : client-frame bytes flow to the WS parser
    let recv_pump = AbortOnDropJoinHandle::new(tokio::spawn(async move {
        let mut mask_validator = H3WsMaskValidator::new();
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(chunk)) => {
                    let bytes = buf_into_bytes(chunk);
                    if bytes.is_empty() {
                        continue;
                    }
                    if mask_validator.validate(&bytes).is_err() {
                        warn!(
                            proxy_id = %proxy_id_for_pumps,
                            close_code = H3_WS_PROTOCOL_ERROR_CLOSE_CODE,
                            "H3 WS recv pump: rejecting masked client frame"
                        );
                        let _ = forced_close_tx.try_send(h3_ws_close_frame(
                            H3_WS_PROTOCOL_ERROR_CLOSE_CODE,
                            H3_WS_MASKED_FRAME_CLOSE_REASON,
                        ));
                        break;
                    }
                    if let Err(e) = pump_write.write_all(&bytes).await {
                        debug!(
                            proxy_id = %proxy_id_for_pumps,
                            "H3 WS recv pump: duplex write closed: {}",
                            e
                        );
                        break;
                    }
                }
                Ok(None) => {
                    debug!(
                        proxy_id = %proxy_id_for_pumps,
                        "H3 WS recv pump: end of stream"
                    );
                    break;
                }
                Err(e) => {
                    debug!(
                        proxy_id = %proxy_id_for_pumps,
                        "H3 WS recv pump: stream error: {}",
                        e
                    );
                    break;
                }
            }
        }
        // Dropping pump_write signals EOF to the WS framer reading
        // from the other duplex half.
    }));

    let proxy_id_for_send_pump = proxy.id.clone();

    // pump_read → h3_send : WS framer's encoded bytes flow back over QUIC
    let send_pump = AbortOnDropJoinHandle::new(tokio::spawn(async move {
        let mut buf = vec![0u8; H3_WS_SEND_PUMP_READ_BUFFER_BYTES];
        let mut forced_close_open = true;
        loop {
            let n = tokio::select! {
                biased;
                forced_close = forced_close_rx.recv(), if forced_close_open => {
                    match forced_close {
                        Some(close_frame) => {
                            if let Err(e) = h3_send.send_data(close_frame).await {
                                debug!(
                                    proxy_id = %proxy_id_for_send_pump,
                                    "H3 WS send pump: h3 forced close send_data error: {}",
                                    e
                                );
                            }
                            break;
                        }
                        None => {
                            forced_close_open = false;
                            continue;
                        }
                    }
                }
                read_result = pump_read.read(&mut buf) => {
                    match read_result {
                        Ok(0) => break, // EOF — WS framer dropped its sink half
                        Ok(n) => n,
                        Err(e) => {
                            debug!(
                                proxy_id = %proxy_id_for_send_pump,
                                "H3 WS send pump: duplex read error: {}",
                                e
                            );
                            break;
                        }
                    }
                }
            };
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            if let Err(e) = h3_send.send_data(chunk).await {
                debug!(
                    proxy_id = %proxy_id_for_send_pump,
                    "H3 WS send pump: h3 send_data error: {}",
                    e
                );
                break;
            }
        }
        if let Err(e) = h3_send.finish().await {
            debug!(
                proxy_id = %proxy_id_for_send_pump,
                "H3 WS send pump: h3 finish error: {}",
                e
            );
        }
    }));

    // ── Collect parsed-relay and disconnect plugin lists ────────────
    let (ws_framing_plugins, ws_frame_plugins) =
        crate::proxy::collect_websocket_relay_plugins(&plugins, requires_websocket_framing);
    let ws_disconnect_plugins: Vec<Arc<dyn Plugin>> = plugins
        .iter()
        .filter(|p| p.requires_ws_disconnect_hooks())
        .cloned()
        .collect();

    let session_meta = WsSessionMeta {
        namespace: proxy.namespace.clone(),
        proxy_name: proxy.name.clone(),
        client_ip: ctx.client_ip.clone(),
        backend_target: crate::proxy::strip_query_params(&current_backend_url).to_string(),
        listen_port: h3_listen_port(&state),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        metadata: crate::proxy::clone_log_metadata(&ctx),
        session_start: Utc::now(),
        session_start_mono: std::time::Instant::now(),
    };

    let proxy_id_for_relay = proxy.id.clone();
    let ws_conn_id = state.ws_connection_counter.fetch_add(1, Ordering::Relaxed);
    let max_ws_frame = state.max_websocket_frame_size_bytes;
    let ws_write_buf = state.websocket_write_buffer_size;
    let adaptive_buf = state.adaptive_buffer.clone();

    // ── Run the shared frame-relay code (same as H1/H2) ─────────────
    //
    // tunnel mode is forced off — QUIC ≠ TCP, there is no raw socket to
    // splice. The same shared `run_websocket_proxy` handles per-frame
    // plugins, cancellation, and on_ws_disconnect bookkeeping.
    let relay_result = crate::proxy::run_websocket_proxy(
        client_io,
        backend_ws_stream,
        &proxy_id_for_relay,
        ws_conn_id,
        ws_framing_plugins,
        ws_frame_plugins,
        ws_disconnect_plugins,
        session_meta,
        ws_connection_permit,
        max_ws_frame,
        ws_write_buf,
        false, // H3 always frame-parses; tunnel mode is H1-only
        crate::proxy::WS_DRAIN_GRACE,
        // RFC 9220 §5: WebSocket frames over HTTP/3 are NOT masked. The H3
        // receive pump rejects masked client frames with close code 1002 before
        // tungstenite's permissive accept-unmasked mode can normalize them.
        true,
        ws_idle_tracker,
        &adaptive_buf,
    )
    .await;

    if let Err(e) = relay_result {
        error!(
            proxy_id = %proxy_id_for_relay,
            "H3 WebSocket relay error: {}",
            e
        );
    }

    // ── Tear down pump tasks ─────────────────────────────────────────
    //
    // The send pump exits naturally when its duplex half (`pump_read`)
    // sees EOF — which happens as soon as `run_websocket_proxy`
    // returns and drops `client_io` (the other end of the duplex
    // pair). Awaiting it ensures the H3 send side calls `finish()` so
    // the peer sees a clean FIN rather than a force-drop / protocol
    // abort.
    //
    // The recv pump, however, is blocked in
    // `h3_recv.recv_data().await`. For a cooperative client this
    // unblocks promptly when the client closes its sending half after
    // the WebSocket close handshake — but a non-cooperative client
    // that exchanges close frames without closing the QUIC stream
    // would leave the recv pump pinned until quinn's idle timeout
    // expires (worst case: tens of seconds). We have no more user
    // data to forward (the WS framer is gone), so abort the pump
    // explicitly to release the QUIC stream resources promptly.
    // `JoinHandle::abort()` is safe — the task owns only the recv
    // half of the QUIC stream + the duplex write half; both will be
    // dropped cleanly.
    recv_pump.abort();
    recv_pump.abort_and_wait().await;
    wait_for_h3_ws_send_pump(&proxy.id, send_pump, H3_WS_PUMP_DRAIN_GRACE).await;

    // Drop guards explicitly so their `Drop` impl runs before the
    // info!() below — keeps the "session ended" log adjacent to the
    // accounting release in interleaved tracing output. The backend
    // connection slot (DestinationRule `maxConnections`) releases here too,
    // exactly when the dedicated backend connection closes — `None` when no
    // cap is configured for the destination port.
    drop(ws_session_guard);
    drop(ws_lb_guard);
    drop(backend_conn_guard);

    info!(
        proxy_id = %proxy.id,
        "H3 WebSocket session ended"
    );

    Ok(())
}

/// Emit a `TransactionSummary` describing the successful WebSocket
/// upgrade. Mirrors the H1/H2 path at `proxy/mod.rs` line ~4300 so log
/// plugins see a consistent shape across frontends.
///
/// `proxy_headers` is the source of truth for the backend-bound header
/// view. The H3 dispatcher in `handle_h3_request` populates it by either
/// cloning `ctx.headers` (when identity headers need injection) or
/// `std::mem::take`-ing it (the common case), so `ctx.headers` cannot be
/// read from here for diagnostic fields like `user-agent` — it may be
/// empty by the time we get called. Every other H3 path in
/// `src/http3/server.rs` reads `user-agent` from `proxy_headers` for the
/// same reason; keep this in sync.
#[allow(clippy::too_many_arguments)]
async fn emit_successful_upgrade_summary(
    state: &ProxyState,
    proxy: &Proxy,
    ctx: &RequestContext,
    proxy_headers: &HashMap<String, String>,
    plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: u64,
    start_time: Instant,
    backend_url: &str,
    resolve_host: &str,
    // The client-requested path before any VirtualService `rewrite.uri` was
    // applied. Logged as `request_path` so access logs record what the client
    // sent, not the backend-rewritten path in `ctx.path`.
    original_request_path: &str,
) {
    if plugins.is_empty() {
        return;
    }
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);

    let resolved_ip = state
        .dns_cache
        .resolve(
            resolve_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        // RFC 9220 Extended CONNECT uses :method=CONNECT, mirroring the
        // H2 RFC 8441 path's "CONNECT" label.
        http_method: "CONNECT".to_string(),
        // Record the path the client sent, not the VirtualService-rewritten
        // backend path stored in ctx.path after the rewrite in the caller.
        request_path: original_request_path.to_owned(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target: Some(crate::proxy::strip_query_params(backend_url).to_string()),
        backend_resolved_ip: resolved_ip,
        response_status_code: 200,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: proxy_headers.get("user-agent").cloned(),
        metadata: crate::proxy::clone_log_metadata(ctx),
        ai_usage_export: ctx.ai_usage_export.clone(),
        ..TransactionSummary::default()
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}

/// Emit a `TransactionSummary` describing a failed upgrade (backend
/// rejected, connect timeout, TLS handshake failure, etc.). The
/// `rejection_phase` metadata field labels which gateway phase recorded
/// the failure — useful for SRE dashboards keying on
/// `metadata.rejection_phase = "websocket_backend_error"`.
///
/// `proxy_headers` is the source of truth for diagnostic header fields
/// (`user-agent`). See `emit_successful_upgrade_summary` for the
/// rationale on why this is not read from `ctx.headers`.
#[allow(clippy::too_many_arguments)]
async fn emit_failed_upgrade_summary(
    state: &ProxyState,
    proxy: &Proxy,
    ctx: &RequestContext,
    proxy_headers: &HashMap<String, String>,
    plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: u64,
    start_time: Instant,
    backend_url: &str,
    resolve_host: &str,
    error_class: retry::ErrorClass,
    // The client-requested path before any VirtualService `rewrite.uri` was
    // applied. Logged as `request_path` so access logs record what the client
    // sent, not the backend-rewritten path in `ctx.path`.
    original_request_path: &str,
) {
    if plugins.is_empty() {
        return;
    }
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);

    let resolved_ip = state
        .dns_cache
        .resolve(
            resolve_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let mut metadata = crate::proxy::clone_log_metadata(ctx);
    metadata.insert(
        "rejection_phase".to_string(),
        "websocket_backend_error".to_string(),
    );

    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        http_method: "CONNECT".to_string(),
        // Record the path the client sent, not the VirtualService-rewritten
        // backend path stored in ctx.path after the rewrite in the caller.
        request_path: original_request_path.to_owned(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target: Some(crate::proxy::strip_query_params(backend_url).to_string()),
        backend_resolved_ip: resolved_ip,
        response_status_code: 502,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: -1.0,
        latency_backend_total_ms: -1.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: proxy_headers.get("user-agent").cloned(),
        error_class: Some(error_class),
        metadata,
        ai_usage_export: ctx.ai_usage_export.clone(),
        ..TransactionSummary::default()
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn has_key(out: &[(String, String)], key: &str) -> bool {
        out.iter().any(|(k, _)| k == key)
    }

    fn value_for<'a>(out: &'a [(String, String)], key: &str) -> Option<&'a str> {
        out.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn collect_strips_hop_by_hop_headers() {
        // RFC 9110 §7.6.1 hop-by-hop list — none of these should be
        // forwarded to a backend even on an Extended CONNECT upgrade.
        let headers = make_headers(&[
            ("connection", "upgrade, close"),
            ("upgrade", "websocket"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
            ("trailer", "Expires"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "Bearer xyz"),
            ("proxy-connection", "keep-alive"),
            ("host", "example.com"),
            ("x-custom", "passthrough"),
        ]);
        let out = collect_forwardable_h3_headers(&headers, false);
        for stripped in [
            "connection",
            "upgrade",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "host",
        ] {
            assert!(
                !has_key(&out, stripped),
                "hop-by-hop header `{}` must be stripped",
                stripped,
            );
        }
        assert_eq!(value_for(&out, "x-custom"), Some("passthrough"));
    }

    #[test]
    fn collect_strips_websocket_handshake_artefacts() {
        // RFC 6455 client → server handshake bits that have no meaning
        // on the backend H1.1 Upgrade — the backend client (tungstenite)
        // synthesises its own `Sec-WebSocket-Key` and the server's
        // `Sec-WebSocket-Accept` is computed there too.
        let headers = make_headers(&[
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
            ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("sec-websocket-protocol", "chat"),
            ("sec-websocket-extensions", "permessage-deflate"),
        ]);
        let out = collect_forwardable_h3_headers(&headers, false);
        for stripped in [
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-accept",
            "sec-websocket-extensions",
        ] {
            assert!(
                !has_key(&out, stripped),
                "WS handshake header `{}` must be stripped",
                stripped,
            );
        }
        // Subprotocol IS forwarded — the backend WS client re-negotiates it
        // with the upstream server. Extensions (e.g. permessage-deflate) are
        // NOT forwarded: the gateway's WebSocket bridge cannot encode/decode
        // compressed frames, so a deflate-capable backend that accepted the
        // offer would set rsv1 and the session would be torn down with a
        // protocol error. Mirrors the H1/H2 strip in
        // proxy::is_websocket_backend_strip_header.
        assert_eq!(value_for(&out, "sec-websocket-protocol"), Some("chat"));
    }

    #[test]
    fn collect_strips_h3_pseudo_headers() {
        // The h3 server surfaces `:method`/`:scheme`/`:authority`/`:path`/
        // `:protocol` on the request, and upstream code may also bake them
        // into the raw header map. They are never valid as HTTP/1.1
        // request-line / header fields.
        let headers = make_headers(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/ws"),
            (":protocol", "websocket"),
            (":status", "200"),
            ("content-type", "text/plain"),
        ]);
        let out = collect_forwardable_h3_headers(&headers, false);
        for stripped in [
            ":method",
            ":scheme",
            ":authority",
            ":path",
            ":protocol",
            ":status",
        ] {
            assert!(
                !has_key(&out, stripped),
                "H3 pseudo-header `{}` must be stripped",
                stripped,
            );
        }
        assert_eq!(value_for(&out, "content-type"), Some("text/plain"));
    }

    #[test]
    fn collect_lowercases_header_names() {
        // HTTP/3 already requires lowercase header names on the wire, but
        // the input map type doesn't enforce that — guard against an
        // upstream that supplies mixed-case keys.
        let headers = make_headers(&[("X-Trace-Id", "abc123"), ("Authorization", "Bearer token")]);
        let out = collect_forwardable_h3_headers(&headers, false);
        assert_eq!(value_for(&out, "x-trace-id"), Some("abc123"));
        assert_eq!(value_for(&out, "authorization"), Some("Bearer token"));
    }

    #[test]
    fn collect_strips_client_supplied_early_data_header() {
        let headers = make_headers(&[("early-data", "1"), ("x-trace-id", "abc123")]);
        let out = collect_forwardable_h3_headers(&headers, false);
        assert!(
            !has_key(&out, "early-data"),
            "client-supplied Early-Data must be stripped when the QUIC request was not 0-RTT"
        );
        assert_eq!(value_for(&out, "x-trace-id"), Some("abc123"));
    }

    #[test]
    fn collect_injects_gateway_early_data_header_for_zero_rtt() {
        let headers = make_headers(&[("early-data", "0"), ("x-trace-id", "abc123")]);
        let out = collect_forwardable_h3_headers(&headers, true);
        let early_data_count = out.iter().filter(|(k, _)| k == "early-data").count();
        assert_eq!(
            early_data_count, 1,
            "client-supplied Early-Data must be replaced by exactly one gateway value"
        );
        assert_eq!(value_for(&out, "early-data"), Some("1"));
        assert_eq!(value_for(&out, "x-trace-id"), Some("abc123"));
    }

    #[test]
    fn user_agent_lookup_lives_on_proxy_headers_not_ctx() {
        // Regression guard: the H3 dispatcher in `src/http3/server.rs`
        // builds `proxy_headers` by either cloning `ctx.headers` (when
        // identity injection is needed) or `std::mem::take`-ing it (the
        // common case). In the take-path `ctx.headers` is empty by the
        // time `handle_h3_websocket` runs, so the TransactionSummary
        // helpers MUST read `request_user_agent` from `proxy_headers`,
        // not from `ctx.headers`. This test pins the expected source of
        // truth so a future refactor doesn't silently re-introduce the
        // bug (which was caught in PR 784 review).
        let proxy_headers = make_headers(&[("user-agent", "ferrum-test/1.0")]);
        let ctx_headers_after_take: HashMap<String, String> = HashMap::new();
        assert_eq!(
            proxy_headers.get("user-agent").map(String::as_str),
            Some("ferrum-test/1.0"),
            "proxy_headers must carry user-agent (the post-take source)"
        );
        assert!(
            !ctx_headers_after_take.contains_key("user-agent"),
            "ctx.headers is moved-out and empty in the common dispatch path"
        );
    }

    #[test]
    fn h3_ws_send_pump_buffer_is_smaller_than_duplex_capacity() {
        assert_eq!(H3_WS_DUPLEX_BUFFER_BYTES, 64 * 1024);
        assert_eq!(H3_WS_SEND_PUMP_READ_BUFFER_BYTES, 16 * 1024);
    }

    #[test]
    fn direct_backend_retry_resolves_proxy_for_current_target() {
        let source = include_str!("websocket.rs");
        let loop_start = source
            .find("let backend_handshake = loop {")
            .expect("H3 WebSocket backend handshake loop must remain present");
        let loop_body = &source[loop_start..];
        let resolve_idx = loop_body
            .find("resolve_backend_connection_proxy_for_target(\n            &proxy,\n            current_target.as_deref(),")
            .expect("H3 WebSocket dial must resolve an effective proxy for the current target");
        let dial_idx = loop_body
            .find("connect_websocket_backend(\n            &current_backend_url,\n            ws_dial_proxy,")
            .expect("H3 WebSocket direct dial must use the target-effective proxy");

        assert!(
            resolve_idx < dial_idx,
            "H3 WebSocket retry attempts must resolve the backend policy after target rotation"
        );
    }

    #[tokio::test]
    async fn abort_on_drop_join_handle_aborts_detached_task() {
        struct DropMarker(std::sync::Arc<std::sync::atomic::AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_in_task = dropped.clone();
        let handle = tokio::spawn(async move {
            let _marker = DropMarker(dropped_in_task);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let guard = AbortOnDropJoinHandle::new(handle);
        started_rx.await.expect("task started");
        drop(guard);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            if dropped.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("dropping AbortOnDropJoinHandle should abort and drop the task future");
    }

    #[tokio::test]
    async fn h3_ws_send_pump_wait_timeout_aborts_pending_task() {
        struct DropMarker(std::sync::Arc<std::sync::atomic::AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_in_task = dropped.clone();
        let handle = tokio::spawn(async move {
            let _marker = DropMarker(dropped_in_task);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let guard = AbortOnDropJoinHandle::new(handle);
        started_rx.await.expect("task started");

        wait_for_h3_ws_send_pump("test-proxy", guard, Duration::from_millis(5)).await;

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            if dropped.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("send pump wait timeout should abort and drop the task future");
    }

    #[test]
    fn collect_strips_reserved_gateway_assertion_headers() {
        let headers = make_headers(&[
            ("X-Consumer-Username", "spoofed-or-injected"),
            ("X-Consumer-Custom-Id", "spoofed-or-injected-id"),
            ("X-Geo-Country", "ATTACKER"),
            ("x-trace-id", "keepme"),
        ]);
        let out = collect_forwardable_h3_headers(&headers, false);
        assert!(
            !has_key(&out, "x-consumer-username"),
            "reserved x-consumer-username must be stripped from the forwarded map"
        );
        assert!(
            !has_key(&out, "x-consumer-custom-id"),
            "reserved x-consumer-custom-id must be stripped from the forwarded map"
        );
        assert!(
            !has_key(&out, "x-geo-country"),
            "reserved x-geo-country must be stripped from the forwarded map"
        );
        assert_eq!(value_for(&out, "x-trace-id"), Some("keepme"));
    }

    #[test]
    fn override_helper_yields_single_authoritative_gateway_assertions() {
        let headers = make_headers(&[
            ("X-Consumer-Username", "mixed-case-leftover"),
            ("x-trace-id", "keepme"),
        ]);
        let mut out = collect_forwardable_h3_headers(&headers, false);
        // Defensively re-introduce a stray case variant to prove the override
        // collapses it rather than appending a second value.
        out.push(("X-Consumer-Username".to_string(), "stray".to_string()));
        out.push(("X-Geo-Country".to_string(), "ATTACKER".to_string()));
        push_h3_forwardable_header_override(
            &mut out,
            "x-consumer-username",
            "authenticated-user".to_string(),
        );
        push_h3_forwardable_header_override(&mut out, "x-geo-country", "SE".to_string());
        let count = out
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-consumer-username"))
            .count();
        assert_eq!(
            count, 1,
            "exactly one x-consumer-username must reach the backend handshake"
        );
        assert_eq!(
            value_for(&out, "x-consumer-username"),
            Some("authenticated-user")
        );
        assert_eq!(
            out.iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("x-geo-country"))
                .count(),
            1
        );
        assert_eq!(value_for(&out, "x-geo-country"), Some("SE"));
        assert_eq!(value_for(&out, "x-trace-id"), Some("keepme"));
    }
}
