//! HTTP/3 server listener using Quinn (QUIC) and h3.
//!
//! Runs as a standalone QUIC server alongside the main hyper-based HTTP server.
//! Handles its own request lifecycle (route matching, plugin phases, auth) and
//! uses the `Http3ConnectionPool` (h3+quinn) for backend communication.
//!
//! QUIC requires TLS 1.3 exclusively (RFC 9001), so the server forces TLS 1.3
//! and uses a separate ALPN advertisement (`h3`). 0-RTT is controlled by
//! `FERRUM_TLS_EARLY_DATA_METHODS` — when configured, quinn's `into_0rtt()` is
//! used to detect early data connections and enforce per-method filtering.
//! The 0.5-RTT accept path is refused when the listener is configured for
//! frontend client-certificate authentication, because materializing the
//! connection before the peer's `Certificate` flight would leave
//! `peer_identity()` unknowable (see [`crate::http3::peer_identity`]).
//! Session resumption is always enabled (saves 1 RTT on reconnects). Ordinary
//! listeners use stateless rotating tickets; non-mTLS listeners with early data
//! enabled use the bounded stateful cache rustls requires for server 0-RTT.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{RecvStream, SendStream};
use h3::server::RequestStream;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{debug, error, info, warn};

use super::config::Http3ServerConfig;
use super::peer_identity::{
    H3ConnectionIdentity, quic_max_early_data_size, server_0rtt_handshake_succeeded,
    zero_rtt_admitted,
};
use crate::config::types::{HttpFlavor, Proxy, UpstreamTarget};
use crate::consumer_index::ConsumerIndex;
use crate::load_balancer::LoadBalancerCache;
use crate::plugins::{
    BackendAdmissionOutcome, BackendAdmissionPermitSet, Plugin, PluginResult, ProxyProtocol,
    RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY, RequestContext, ResponseStreamAction,
    TransactionSummary, normalize_response_body_for_inspection,
};
use crate::proxy::deferred_log::{BodyOutcome, run_response_stream_termination_hooks};
use crate::proxy::grpc_proxy::{
    GATEWAY_DEADLINE_EXCEEDED_MESSAGE, GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
};
use crate::proxy::headers::{
    ClientResponseFraming, GatewayOwnedResponseHeaders, PrePolicyResponseHeaders,
    RejectBodyDisposition, ResponseTrailerGovernance, ResponseTrailerPolicyWitness,
    TrailerSectionKind, apply_response_headers, is_backend_request_strip_header,
    is_proxy_owned_forwarding_header, parse_connection_listed_from_str_map,
    preserved_response_content_length, reconcile_backend_trailers_with_response_policy,
    reconcile_streaming_backend_trailers, remove_content_length_header,
    sanitize_client_response_headers_for_wire, strip_client_response_hop_by_hop_headers,
    strip_response_hop_by_hop_trailers,
};
use crate::proxy::{
    ProxyState, apply_plugin_rejection_response, apply_reject_after_proxy_and_synthetic_body_hooks,
    log_pre_backend_rejected_request, log_rejected_request, log_rejected_request_with_path,
    plugin_result_into_reject_parts, run_after_proxy_hooks, run_authentication_phase,
};
use crate::tls::{CrlList, TlsPolicy};

/// Canonical mesh dispatch-required gateway reject body. Shared by the header
/// finalizer, the committed-hook boundary, rejection logging, and the wire
/// sender so all four observe one static payload and the `Bytes` handed to QUIC
/// is `from_static` rather than a per-reject copy.
pub(crate) const MESH_DISPATCH_REQUIRED_REJECT_BODY: &[u8] =
    br#"{"error":"Bad Gateway","message":"Mesh transport dispatch required for this backend target"}"#;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum H3RequestBodyReadError<E> {
    Read(E),
    TimedOut,
    DeadlineExceeded,
}

pub(crate) async fn collect_h3_request_body_with_timeout<F, T, E>(
    collect: F,
    request_body_read_timeout_ms: u64,
) -> Result<T, H3RequestBodyReadError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    if request_body_read_timeout_ms == 0 {
        return collect.await.map_err(H3RequestBodyReadError::Read);
    }

    tokio::time::timeout(Duration::from_millis(request_body_read_timeout_ms), collect)
        .await
        .map_err(|_| H3RequestBodyReadError::TimedOut)?
        .map_err(H3RequestBodyReadError::Read)
}

pub(crate) async fn collect_h3_request_body_with_deadline<F, T, E>(
    collect: F,
    deadline: Option<tokio::time::Instant>,
    request_body_read_timeout_ms: u64,
) -> Result<T, H3RequestBodyReadError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    // Preserve both timeout regimes via the shared earliest-of composer: the
    // absolute RPC deadline bounds the whole call, and the operator read
    // timeout still caps a stalled client upload even when grpc-timeout is
    // very large. Operator timeout `0` disables only that fresh bound.
    match crate::proxy::compose_early_upload_bound(deadline, request_body_read_timeout_ms) {
        Some((effective_deadline, crate::proxy::EarlyUploadBoundKind::OperatorTimeout)) => {
            tokio::time::timeout_at(effective_deadline, collect)
                .await
                .map_err(|_| H3RequestBodyReadError::TimedOut)?
                .map_err(H3RequestBodyReadError::Read)
        }
        Some((effective_deadline, crate::proxy::EarlyUploadBoundKind::RpcDeadline)) => {
            tokio::time::timeout_at(effective_deadline, collect)
                .await
                .map_err(|_| H3RequestBodyReadError::DeadlineExceeded)?
                .map_err(H3RequestBodyReadError::Read)
        }
        None => collect_h3_request_body_with_timeout(collect, request_body_read_timeout_ms).await,
    }
}

/// Drain an H3 request-body recv half into an owned buffer.
///
/// The buffer lives inside this future so timeout/deadline cancellation and
/// stream-read failures drop any partial upload instead of retaining it across
/// rejection hooks or response writes. Returns `Ok(None)` when `max_bytes`
/// would be exceeded (also dropping the partial buffer).
pub(crate) async fn drain_h3_request_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, h3::error::StreamError>
where
    S: RecvStream,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let bytes = chunk.chunk();
        if max_bytes > 0 && body.len().saturating_add(bytes.len()) > max_bytes {
            return Ok(None);
        }
        body.extend_from_slice(bytes);
    }
    Ok(Some(body))
}

/// Promptly stop a cancelled or rejected H3 upload from pushing further DATA.
///
/// Call this **after** protocol-appropriate response HEADERS (and body /
/// trailers / FIN) are written whenever a drain ends without forwarding the
/// body. Issuing `STOP_SENDING` before the response is observable can panic
/// inside h3-quinn after a cancelled mid-`recv_data` poll and lets Quinn's
/// `SendStream` Drop FIN the response half with no HEADERS
/// (`H3_FRAME_UNEXPECTED` at the client). The helper itself is idempotent.
#[inline]
fn halt_cancelled_h3_upload<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: RecvStream,
{
    crate::http3::stream_util::halt_request_body(stream);
}

fn h3_request_body_timeout_contract<E>(
    error: &H3RequestBodyReadError<E>,
) -> (&'static str, &'static str) {
    match error {
        H3RequestBodyReadError::DeadlineExceeded => (
            r#"{"error":"Request deadline exceeded"}"#,
            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
        ),
        H3RequestBodyReadError::TimedOut | H3RequestBodyReadError::Read(_) => (
            r#"{"error":"Request body read timed out"}"#,
            "Request body read timed out",
        ),
    }
}

struct FinalizedH3TerminalBodyRejection {
    http_status: StatusCode,
    headers: HashMap<String, String>,
    body: Bytes,
}

/// Commit an H3 terminal request-body failure before provider/backend I/O.
/// The shared committed-response hook then releases any exact local/Redis
/// request ownership once, even when the client reset prevents writing the
/// already-decided rejection back to the stream.
#[allow(clippy::too_many_arguments)]
async fn finalize_h3_terminal_body_read_rejection(
    state: &ProxyState,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    http_flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    status: StatusCode,
    body: Bytes,
    start_time: std::time::Instant,
    plugin_execution_ns: &mut u64,
    request_path: &str,
) -> FinalizedH3TerminalBodyRejection {
    ctx.metadata.insert(
        RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut response_status = status.as_u16();
    let mut headers = HashMap::new();
    // Owned already: a cached synthetic `RejectBinary` payload reaches this
    // finalizer as shared `Bytes` and must keep that allocation identity.
    let mut body = body;
    let rejection_hook_start = std::time::Instant::now();
    apply_reject_after_proxy_and_synthetic_body_hooks(
        plugins,
        ctx,
        &mut response_status,
        &mut headers,
        &mut body,
        matches!(http_flavor, HttpFlavor::Grpc),
        false,
    )
    .await;
    let http_status = StatusCode::from_u16(response_status).unwrap_or(status);
    run_h3_reject_response_committed_hooks(
        plugins,
        ctx,
        http_flavor,
        grpc_web_response_content_type,
        http_status,
        body.clone(),
        &headers,
    )
    .await;
    *plugin_execution_ns += rejection_hook_start.elapsed().as_nanos() as u64;
    let log_status =
        h3_reject_log_status_and_metadata(ctx, http_flavor, http_status, &body, &headers);
    log_rejected_request_with_path(
        plugins,
        ctx,
        log_status,
        start_time,
        "on_final_request_body",
        *plugin_execution_ns,
        Some(request_path),
    )
    .await;
    record_request(state, log_status);
    FinalizedH3TerminalBodyRejection {
        http_status,
        headers,
        body,
    }
}

/// Optional HTTP/3 listener settings that don't affect the core bind contract.
#[derive(Default)]
pub struct Http3ListenerOptions {
    pub client_ca_bundle_path: Option<String>,
    /// Loaded CRLs for client certificate revocation checking. When non-empty
    /// and `client_ca_bundle_path` is set, the H3 mTLS verifier checks revocation
    /// with the same policy as H1/H2/DTLS frontend mTLS:
    /// `allow_unknown_revocation_status` + `only_check_end_entity_revocation`.
    pub client_crls: CrlList,
    pub started_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Optional opt-in frontend TLS live-reload inputs. When `Some`, the H3
    /// listener subscribes to `revision_rx` and, on a bump, reloads the latest
    /// `Arc<rustls::ServerConfig>` from `tls_slot`, rebuilds the
    /// `quinn::ServerConfig` (forcing TLS 1.3, reapplying H3 transport
    /// tuning), and calls `Endpoint::set_server_config(Some(..))`. Existing
    /// QUIC connections keep serving. A rebuild that fails (e.g., the new
    /// cert won't bind to QUIC) keeps the previous server config and emits a
    /// `warn!`.
    pub frontend_tls_reload: Option<Http3FrontendTlsReload>,
}

/// Frontend TLS live-reload inputs for the H3 listener. This may be populated
/// by operator file reload or by a DP CP-delivered Gateway TLS overlay.
pub struct Http3FrontendTlsReload {
    /// Shared frontend TLS slot. The proxy HTTPS / H2 / H3 listeners read
    /// from the same slot so they observe the same rotated cert/key pair.
    pub tls_slot: crate::tls::SharedFrontendTls,
    /// Revision counter bumped by the file-watch task after every successful
    /// reload. The H3 listener subscribes so it doesn't poll the slot.
    pub revision_rx: tokio::sync::watch::Receiver<u64>,
}

/// Start the HTTP/3 (QUIC) proxy listener.
///
/// HTTP/3 (QUIC) mandates TLS 1.3. If the provided TLS policy does not include
/// TLS 1.3, this function will override it to force TLS 1.3 for the QUIC listener
/// and log a warning.
#[allow(dead_code)] // Used by library consumers and tests; binary startup uses the signaled variant.
#[allow(clippy::too_many_arguments)]
pub async fn start_http3_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Arc<rustls::ServerConfig>,
    h3_config: Http3ServerConfig,
    tls_policy: &TlsPolicy,
    client_ca_bundle_path: Option<String>,
    client_crls: CrlList,
) -> Result<(), anyhow::Error> {
    start_http3_listener_with_signal(
        addr,
        state,
        shutdown,
        tls_config,
        h3_config,
        tls_policy,
        Http3ListenerOptions {
            client_ca_bundle_path,
            client_crls,
            started_tx: None,
            frontend_tls_reload: None,
        },
    )
    .await
}

/// Build a fresh `quinn::ServerConfig` from a rustls server config, the
/// shared TLS policy, and the H3 transport tuning. Used at startup AND on
/// every successful frontend TLS cert/key reload.
///
/// Forces TLS 1.3 (RFC 9001), carries forward client-cert mTLS if configured,
/// applies 0-RTT and session-ticket resumption from the gateway policy, and
/// stamps the H3-only ALPN advertisement.
fn build_h3_quinn_server_config(
    tls_config: &Arc<rustls::ServerConfig>,
    tls_policy: &TlsPolicy,
    client_ca_bundle_path: Option<&str>,
    client_crls: &CrlList,
    h3_config: &Http3ServerConfig,
) -> Result<quinn::ServerConfig, anyhow::Error> {
    // HTTP/3 (QUIC) requires TLS 1.3 — rebuild the server config with TLS 1.3 forced.
    // Filter cipher suites to TLS 1.3 only and force TLS 1.3 protocol version.
    let has_tls13 = tls_policy
        .protocol_versions
        .iter()
        .any(|v| std::ptr::eq(*v, &rustls::version::TLS13));

    if !has_tls13 {
        warn!(
            "HTTP/3 (QUIC) requires TLS 1.3, but FERRUM_TLS_MAX_VERSION excludes it. \
               Forcing TLS 1.3 for the QUIC listener."
        );
    }

    // Build an H3-specific crypto provider with only TLS 1.3 cipher suites
    let tls13_suites: Vec<rustls::SupportedCipherSuite> = tls_policy
        .crypto_provider
        .cipher_suites
        .iter()
        .filter(|s| s.tls13().is_some())
        .copied()
        .collect();

    // If user didn't configure any TLS 1.3 suites, use defaults
    let h3_suites = if tls13_suites.is_empty() {
        vec![
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
    } else {
        tls13_suites
    };

    let base_provider = rustls::crypto::ring::default_provider();
    let h3_provider = rustls::crypto::CryptoProvider {
        cipher_suites: h3_suites,
        kx_groups: tls_policy.crypto_provider.kx_groups.clone(),
        ..base_provider
    };

    // Rebuild server config with TLS 1.3 only for QUIC
    let h3_builder = rustls::ServerConfig::builder_with_provider(Arc::new(h3_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("Failed to set TLS 1.3 for HTTP/3: {}", e))?;

    // Reuse the cert chain and key from the original config.
    // Carry forward mTLS (client cert verification) if configured.
    //
    // FAIL CLOSED: when a client CA bundle IS configured but the client-cert
    // verifier cannot be built (missing / unreadable / invalid / empty CA
    // bundle, or a transient read fault), return an error instead of silently
    // downgrading to `with_no_client_auth()`. Silently dropping client auth
    // would let HTTP/3 clients present no certificate to a listener the
    // operator configured for mTLS. At startup the error aborts the H3
    // listener; on a frontend TLS reload the caller keeps the previous,
    // still-mTLS-protected server config (see the `Err` arm of the reload
    // handler). This mirrors the fail-closed contract of the H1/H2 frontend
    // path (`crate::tls::load_tls_config_with_client_auth*`) and the mesh
    // inbound verifier — only an explicitly *unconfigured* client CA (the
    // `else` branch) yields no client auth.
    let mut server_tls_config = if let Some(ca_path) = client_ca_bundle_path {
        // Do NOT interpolate `ca_path` into the error: a client CA bundle can be
        // configured as inline PEM (`CertSource::InlinePem`), so the "path" may
        // itself be secret material (e.g. a pasted private key in a malformed
        // bundle). `build_client_cert_verifier` already surfaces the redacted
        // source id (`CertSource::source_id()` -> `inline-pem:<redacted>`) in
        // `e`, so the wrapper only adds operator-facing context.
        let verifier =
            crate::tls::build_client_cert_verifier(ca_path, client_crls).map_err(|e| {
                anyhow::anyhow!(
                    "HTTP/3 mTLS is configured but the client certificate verifier could not \
                     be built: {}. Refusing to serve HTTP/3 without client authentication.",
                    e
                )
            })?;
        h3_builder
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(tls_config.cert_resolver.clone())
    } else {
        h3_builder
            .with_no_client_auth()
            .with_cert_resolver(tls_config.cert_resolver.clone())
    };

    server_tls_config.alpn_protocols = vec![b"h3".to_vec()];
    // 0-RTT early data: controlled by FERRUM_TLS_EARLY_DATA_METHODS.
    // When the policy reports 0 (default), 0-RTT is disabled — early data is
    // replayable, which is dangerous for non-idempotent operations proxied
    // through an API gateway. When the policy reports any non-zero value
    // (methods configured) on a non-mTLS listener, QUIC/rustls requires
    // max_early_data_size to be exactly u32::MAX (2^32-1). A finite TLS
    // early-data byte cap is not expressible on QUIC; Ferrum's method allowlist
    // in handle_h3_connection() remains the application-layer admission
    // control. Client-authenticated listeners use 0 so the TLS advertisement
    // and the 0.5-RTT application accept path are both disabled. Mapping here
    // keeps startup and live reload fail-closed: quinn rejects any other size,
    // so we never pass the policy's finite aspirational value through.
    server_tls_config.max_early_data_size = quic_max_early_data_size(
        tls_policy.early_data_max_size > 0,
        client_ca_bundle_path.is_some(),
    );

    // Rustls accepts server early data only with stateful resumption, because
    // the stored session record carries the freshness/anti-replay inputs. Keep
    // that cache bounded by FERRUM_TLS_SESSION_CACHE_SIZE. When early data is
    // disabled (including every mTLS listener), prefer the ordinary stateless
    // rotating ticketer; if construction fails, the same bounded stateful cache
    // remains as the fail-safe resumption fallback.
    if server_tls_config.max_early_data_size == 0 {
        match rustls::crypto::ring::Ticketer::new() {
            Ok(ticketer) => {
                server_tls_config.ticketer = ticketer;
            }
            Err(e) => {
                warn!(
                    "Failed to create QUIC session ticket rotator, resumption will use stateful cache only: {}",
                    e
                );
            }
        }
    }
    server_tls_config.session_storage =
        rustls::server::ServerSessionMemoryCache::new(tls_policy.session_cache_size);

    let quic_server_config = QuicServerConfig::try_from(server_tls_config)
        .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.initial_mtu(h3_config.initial_mtu);
    transport_config.max_idle_timeout(Some(
        h3_config
            .idle_timeout
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid idle timeout: {}", e))?,
    ));
    transport_config.max_concurrent_bidi_streams(h3_config.max_concurrent_streams.into());

    // QUIC flow-control tuning — conservative defaults for untrusted clients.
    transport_config.stream_receive_window(crate::http3::config::quic_varint_or_default(
        h3_config.stream_receive_window,
        crate::http3::config::H3_FRONTEND_STREAM_RECEIVE_WINDOW,
    ));
    transport_config.receive_window(crate::http3::config::quic_varint_or_default(
        h3_config.receive_window,
        crate::http3::config::H3_FRONTEND_RECEIVE_WINDOW,
    ));
    transport_config.send_window(h3_config.send_window);

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport_config));
    Ok(server_config)
}

/// Everything the trailer-finish phase needs to re-apply the response-header
/// policy boundary to a STREAMING relay's trailer section.
///
/// A streaming relay sends its initial HEADERS frame before the backend's
/// trailers exist, so `after_proxy`, sticky-cookie injection, and the final
/// hop-by-hop strip have all already run and gone on the wire by the time the
/// trailers are read. Without this, a backend trailer repeating a governed
/// field name lands AFTER the policy boundary and undoes it — the same gap the
/// buffered native-H3 send path closes inline. See `docs/http3.md`
/// ("Backend trailers and response header policy").
struct H3StreamingTrailerPolicy<'a> {
    /// The response headers exactly as they went on the wire, after every
    /// response-header phase for this path.
    ///
    /// This map is the WIRE header set, not a subset of it: each relay writes
    /// its synthesized default `content-type` into the map before building the
    /// response, so reconciliation can never report absent->absent for a field
    /// the gateway actually sent.
    final_headers: &'a std::collections::HashMap<String, String>,
    /// Evidence captured before the first response-header phase ran.
    pre_policy: &'a PrePolicyResponseHeaders,
    /// Config-time declarations plus the fail-closed unbounded arm.
    governance: ResponseTrailerGovernance<'a>,
    /// Plain response trailers, or a native gRPC terminal section. Selected by
    /// the relay from the dispatch it committed to, never from a trailer name.
    section: TrailerSectionKind,
}

/// Failure side for [`finish_h3_response_with_backend_trailers`].
///
/// The trailer-finish phase touches both ends of the relay: reading
/// trailers from the BACKEND recv stream and sending trailers/FIN to the
/// CLIENT send stream. Call sites must not conflate the two — a backend
/// trailer-read fault is a backend transport error (classified via
/// `classify_http3_error`, reported to circuit breaker / passive health),
/// while a client send/finish failure is a genuine `ClientDisconnect`.
enum H3TrailerFinishError {
    /// `recv_trailers()` on the backend stream failed non-gracefully.
    Backend(h3::error::StreamError),
    /// `recv_trailers()` on the backend stream exceeded the per-proxy
    /// `backend_read_timeout_ms`. A stalled trailer read is a backend transport
    /// fault classified as `ReadWriteTimeout` (504), not a `ClientDisconnect`.
    BackendTimeout,
    /// `send_trailers()` / `finish()` toward the client failed. The
    /// underlying error is intentionally dropped — call sites uniformly
    /// classify this side as `ClientDisconnect`.
    Client,
}

async fn finish_h3_response_with_backend_trailers<S>(
    h3_stream: &mut RequestStream<S, Bytes>,
    recv_stream: &mut crate::http3::client::H3RequestStream,
    backend_read_timeout_ms: u64,
    trailer_policy: H3StreamingTrailerPolicy<'_>,
) -> Result<(), H3TrailerFinishError>
where
    S: SendStream<Bytes>,
{
    // Bound the post-body trailer read by `backend_read_timeout_ms`. A backend
    // that completes the body but then stalls before sending the TRAILERS/FIN
    // frame would otherwise pin the H3 stream + request/admission guards
    // indefinitely. Matches the buffered/`recv_response` deadlines in
    // `http3/client.rs`. `0` keeps the unbounded opt-out behavior.
    let trailers_result = if backend_read_timeout_ms > 0 {
        match tokio::time::timeout(
            std::time::Duration::from_millis(backend_read_timeout_ms),
            recv_stream.recv_trailers(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => match recv_stream.peek_recv_trailers() {
                Ok(Some(trailers)) => Ok(Some(trailers)),
                Ok(None) => return Err(H3TrailerFinishError::BackendTimeout),
                Err(err) => return Err(H3TrailerFinishError::Backend(err)),
            },
        }
    } else {
        recv_stream.recv_trailers().await
    };
    let trailers = match trailers_result {
        Ok(trailers) => trailers,
        Err(err) if crate::http3::client::is_h3_graceful_close(&err) => None,
        Err(err) => return Err(H3TrailerFinishError::Backend(err)),
    };

    match trailers {
        Some(mut trailers) => {
            strip_response_hop_by_hop_trailers(&mut trailers);
            // Last point on a streaming relay where the response-header policy
            // boundary can still bind the trailer section: the initial HEADERS
            // frame, sticky-cookie injection, and the final hop-by-hop strip all
            // happened before the first body frame. Runs once per response, on
            // the trailer frame only — never per body frame — and an
            // auth/logging-only chain contributes no governance, so its trailers
            // pass through untouched (issue #2941).
            let removed = reconcile_streaming_backend_trailers(
                &mut trailers,
                trailer_policy.final_headers,
                trailer_policy.pre_policy,
                trailer_policy.governance,
                GatewayOwnedResponseHeaders::default(),
                trailer_policy.section,
            );
            if removed > 0 {
                debug!(
                    removed,
                    "streaming H3: dropped backend trailer fields governed by response header policy"
                );
            }
            if !trailers.is_empty() {
                h3_stream
                    .send_trailers(trailers)
                    .await
                    .map_err(|_| H3TrailerFinishError::Client)?;
            }
            h3_stream
                .finish()
                .await
                .map_err(|_| H3TrailerFinishError::Client)
        }
        None => h3_stream
            .finish()
            .await
            .map_err(|_| H3TrailerFinishError::Client),
    }
}

/// Start the HTTP/3 listener and optionally emit a startup signal after bind.
pub async fn start_http3_listener_with_signal(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Arc<rustls::ServerConfig>,
    h3_config: Http3ServerConfig,
    tls_policy: &TlsPolicy,
    options: Http3ListenerOptions,
) -> Result<(), anyhow::Error> {
    let Http3ListenerOptions {
        client_ca_bundle_path,
        client_crls,
        started_tx,
        frontend_tls_reload,
    } = options;

    // DP mode binds the H3 socket while it waits for CP to deliver frontend TLS
    // material — the reload slot is empty at boot. Create the endpoint with NO
    // server config so it is disabled from the very first datagram. This avoids
    // ever installing a no-client-auth throwaway config when mTLS is configured:
    // building a real client-CA verifier needs the (possibly transiently
    // unreadable) CA bundle, and a post-bind `set_server_config(None)` would
    // still leave a window in which Quinn could admit an Initial under a
    // certificate-less config. The real, fail-closed config — including the
    // configured client-CA verifier — is installed only on the reload path when
    // material arrives; a reload whose verifier fails keeps the previous (here,
    // disabled) config. Every H3 config that actually serves a handshake is
    // built fail-closed.
    let start_disabled = frontend_tls_reload
        .as_ref()
        .is_some_and(|reload| reload.tls_slot.load_full().as_ref().is_none());

    let endpoint = if start_disabled {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("HTTP/3 listener requires a Tokio runtime"))?;
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
        info!("HTTP/3 listener started disabled until frontend TLS material is available");
        endpoint
    } else {
        let server_config = build_h3_quinn_server_config(
            &tls_config,
            tls_policy,
            client_ca_bundle_path.as_deref(),
            &client_crls,
            &h3_config,
        )?;
        quinn::Endpoint::server(server_config, addr)?
    };
    let bound_addr = endpoint.local_addr().ok();
    let local_addr = bound_addr.unwrap_or(addr);
    let frontend_listen_port = bound_addr.map(|addr| addr.port());
    info!("HTTP/3 (QUIC) listener started on {}", local_addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }

    let mut shutdown_rx = shutdown;
    // Wrap the ~60-Arc ProxyState in a single Arc once at listener start so
    // per-connection and per-request-stream handoffs cost one refcount bump
    // instead of a full field-by-field clone (issue #1570 sub-item 1; same
    // treatment as the H1/H2 service_fn path).
    let state = Arc::new(state);
    // Captured before the accept loop so each spawned connection task can apply
    // the same QUIC handshake bound without reading `state.env_config` per-conn.
    // `Duration::ZERO` preserves the documented "0 disables" semantic.
    let handshake_timeout = h3_config.handshake_timeout;
    // Frontend client-certificate authentication is a property of the listener,
    // not of an individual connection: `build_h3_quinn_server_config` installs a
    // client-cert verifier exactly when `client_ca_bundle_path` is set, and the
    // reload path rebuilds with the same path. When it is set, the 0.5-RTT
    // accept path is refused for every connection so peer identity is only ever
    // read after handshake completion (issue #2938).
    let client_auth_configured = client_ca_bundle_path.is_some();
    if client_auth_configured && !state.early_data_methods.is_empty() {
        warn!(
            "HTTP/3 0-RTT is disabled on this listener because frontend mTLS \
             (FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH) is configured. QUIC TLS early data and \
             the pre-authentication 0.5-RTT accept path are both disabled, so \
             FERRUM_TLS_EARLY_DATA_METHODS has no effect for HTTP/3 here; ordinary 1-RTT mTLS \
             requests are unaffected."
        );
    }
    let drain_seconds = state.env_config.shutdown_drain_seconds;
    let overload_state = state.overload.clone();

    // Capture inputs needed to rebuild the QUIC server config on a frontend
    // TLS reload. `tls_policy` is borrowed by the outer function, so clone the
    // few fields we need into owned values that live as long as the accept
    // loop. The reload path is opt-in — when `frontend_tls_reload` is `None`
    // the loop ignores the disabled branch entirely.
    let reload_policy = tls_policy.clone();
    let reload_client_ca_bundle_path = client_ca_bundle_path.clone();
    let reload_client_crls = client_crls.clone();
    let reload_h3_config = h3_config.clone();

    // Decompose the optional reload input into local state. When `None` the
    // select branch is gated off by `reload_active=false`, but we still need
    // a valid `reload_rx` value for the macro to expand. The sentinel sender
    // is held for the loop's lifetime so the sentinel receiver's `.changed()`
    // never wakes — combined with the `reload_active=false` gate the branch
    // is effectively dead.
    let (sentinel_tx, sentinel_rx) = tokio::sync::watch::channel(0u64);
    let (mut reload_rx, reload_slot, reload_active) = match frontend_tls_reload {
        Some(Http3FrontendTlsReload {
            tls_slot,
            revision_rx,
        }) => (revision_rx, Some(tls_slot), true),
        None => (sentinel_rx, None, false),
    };
    // Tie the sentinel sender's lifetime to the loop so a `None` reload
    // input cannot accidentally trigger `.changed()` via channel close.
    let _sentinel_tx_keep_alive = sentinel_tx;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                match incoming {
                    Some(connecting) => {
                        // Reject under critical overload
                        if state.overload.reject_new_connections.load(
                            std::sync::atomic::Ordering::Relaxed,
                        ) {
                            connecting.refuse();
                            continue;
                        }
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _conn_guard =
                                crate::overload::ConnectionGuard::new(&state.overload);
                            if let Err(e) = handle_h3_connection(
                                connecting,
                                state,
                                handshake_timeout,
                                frontend_listen_port,
                                client_auth_configured,
                            )
                            .await
                            {
                                debug!("HTTP/3 connection error: {}", e);
                            }
                        });
                    }
                    None => {
                        info!("HTTP/3 endpoint closed");
                        break;
                    }
                }
            }
            reload_change = reload_rx.changed(), if reload_active => {
                if reload_change.is_err() {
                    // Sender dropped — reload pipeline is gone. The H3
                    // listener keeps serving with the last good config.
                    continue;
                }
                let revision = *reload_rx.borrow();
                let Some(slot) = reload_slot.as_ref() else {
                    continue;
                };
                let new_tls = slot.load_full().as_ref().clone();
                let Some(new_tls) = new_tls else {
                    endpoint.set_server_config(None);
                    info!(
                        revision,
                        "HTTP/3 listener disabled because frontend TLS slot is empty"
                    );
                    continue;
                };
                match build_h3_quinn_server_config(
                    &new_tls,
                    &reload_policy,
                    reload_client_ca_bundle_path.as_deref(),
                    &reload_client_crls,
                    &reload_h3_config,
                ) {
                    Ok(server_config) => {
                        endpoint.set_server_config(Some(server_config));
                        info!(
                            revision,
                            "HTTP/3 listener server config swapped after frontend TLS reload"
                        );
                    }
                    Err(error) => {
                        warn!(
                            revision,
                            error = %error,
                            "HTTP/3 listener could not rebuild quinn ServerConfig after frontend TLS reload; keeping previous config"
                        );
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("HTTP/3 listener shutting down — refusing new connections, draining in-flight");
                // Stop accepting new server-side QUIC handshakes. Existing
                // connections continue to serve in-flight streams. Without
                // this, an immediate `endpoint.close()` would abort live
                // requests with a CONNECTION_CLOSE frame mid-stream.
                endpoint.set_server_config(None);
                break;
            }
        }
    }

    // Wait for in-flight HTTP/3 connections to drain, bounded by
    // FERRUM_SHUTDOWN_DRAIN_SECONDS. Without this, any subsequent
    // `endpoint.close()` call would forcefully terminate active streams the
    // moment the listener task exited — exactly the abrupt-abort behaviour
    // the soft-shutdown sequence is here to avoid.
    if drain_seconds > 0 {
        let drain_timeout = Duration::from_secs(drain_seconds);
        let drained = tokio::time::timeout(drain_timeout, async {
            loop {
                if endpoint.open_connections() == 0 {
                    break;
                }
                // Poll active connections via overload state's notify
                // signal — the same mechanism the central drain helper
                // uses, so notifications are coherent across listeners.
                tokio::select! {
                    _ = overload_state.drain_complete.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        })
        .await
        .is_ok();

        if drained {
            info!(
                phase = "drain",
                listener = "http3",
                "HTTP/3 in-flight connections drained"
            );
        } else {
            warn!(
                phase = "drain",
                listener = "http3",
                remaining_connections = endpoint.open_connections(),
                "HTTP/3 drain timeout — forcing endpoint close"
            );
        }
    }

    // Finally, close any remaining connections cleanly. wait_idle() lets
    // peers receive the CONNECTION_CLOSE frame before the socket is
    // dropped — without it some clients see a transport-layer abort.
    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    endpoint.wait_idle().await;

    Ok(())
}

/// Await `fut` while bounding the wait by `timeout`. Passing `Duration::ZERO`
/// disables the bound — used so `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0`
/// matches the "0 disables" semantic shared by the TCP/TLS and DTLS frontends.
async fn await_with_optional_timeout<F, T>(
    fut: F,
    timeout: Duration,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    if timeout.is_zero() {
        Ok(fut.await)
    } else {
        tokio::time::timeout(timeout, fut).await
    }
}

/// Extract the peer certificate chain from a fully handshaken QUIC connection.
///
/// Quinn returns `peer_identity()` as `Box<dyn Any>` containing
/// `Vec<rustls::pki_types::CertificateDer>`. Only meaningful **after** the TLS
/// handshake has completed — during the 0.5-RTT window it always yields `None`,
/// which is exactly why the H3 accept path must not snapshot it there.
fn quinn_peer_cert_chain(connection: &quinn::Connection) -> Option<Vec<Vec<u8>>> {
    connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
}

/// Derive the HTTP/3 client-identity pair for a QUIC peer address.
///
/// Returns the canonical typed peer and the pre-formatted canonical IP string
/// that every stream on the connection shares. Both come from one fold of the
/// same address, so an IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`) and the same
/// host arriving natively over IPv4 are one principal for per-IP request
/// limits, IP/GeoIP policy, and logs (GHSA-vjwj-657f-5w9g).
///
/// Called once per connection and again on every observed QUIC connection
/// migration, so a client that migrates onto a dual-stack path cannot acquire a
/// second identity mid-connection.
pub(crate) fn h3_client_identity(addr: SocketAddr) -> (SocketAddr, Arc<str>) {
    (
        crate::util::client_identity::canonical_socket_addr(addr),
        crate::util::client_identity::canonical_ip_arc(addr.ip()),
    )
}

/// Handle a single HTTP/3 connection (may carry multiple streams/requests).
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    state: Arc<ProxyState>,
    handshake_timeout: Duration,
    frontend_listen_port: Option<u16>,
    client_auth_configured: bool,
) -> Result<(), anyhow::Error> {
    // 0-RTT is opt-in via `FERRUM_TLS_EARLY_DATA_METHODS` *and* is refused
    // outright when this listener does frontend client-certificate
    // authentication: the 0.5-RTT accept path would materialize the connection
    // before the peer's certificate is known (issue #2938), and the TLS builder
    // disables client early data for the same listener posture.
    let early_data_enabled =
        zero_rtt_admitted(!state.early_data_methods.is_empty(), client_auth_configured);

    // Single coherent per-connection identity slot. Requests take one lock-free
    // snapshot, so the early-data flag and the peer certificate can never be
    // observed out of step. Starts with NO identity and `is_early_data = true`;
    // the post-handshake identity is published exactly once after successful
    // handshake completion and after already-ready early streams are accepted.
    let peer_identity = Arc::new(H3ConnectionIdentity::pre_handshake());
    // On the 0.5-RTT branch the completion task reports handshake outcome back
    // to the request accept loop. That loop polls ready request streams first,
    // so buffered early data is snapshotted before a successful handshake can
    // publish the established identity and clear replay gating.
    let mut handshake_completion_rx = None;

    // Bound the QUIC handshake so a peer that completes the UDP path-MTU
    // probe / Initial packets but never finishes TLS 1.3 cannot hold a
    // connection slot indefinitely. `quinn::TransportConfig::max_idle_timeout`
    // is a post-handshake idle bound and is NOT a handshake bound — so without
    // this `tokio::time::timeout`, the gateway has no admission-control
    // ceiling on QUIC handshake cost. Aligns HTTP/3 with the TCP/TLS
    // (`accept_with_optional_timeout`) and DTLS (`DtlsServerLimits.handshake_timeout`)
    // frontends, all gated by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`.
    let connection = if early_data_enabled {
        let connecting = connecting.accept()?.into_0rtt();
        match connecting {
            Ok((conn, zero_rtt_accepted)) => {
                let remote =
                    crate::util::client_identity::canonical_socket_addr(conn.remote_address());
                debug!("HTTP/3 0-RTT connection accepted from {}", remote);
                // Spawn a task that waits for the handshake to complete, then
                // reports the outcome to the accept loop. The accept loop owns
                // identity publication so it can drain every already-ready
                // early request before clearing the replay flag. Requests
                // dispatched after publication see `is_early_data = false`
                // together with the established identity; requests dispatched
                // before it keep seeing the pre-handshake snapshot, which
                // carries no identity at all.
                // The handshake bound also applies here: if the peer never
                // completes TLS, the ZeroRttAccepted future never resolves and
                // the connection would otherwise sit consuming a slot forever.
                // Closing the connection on timeout fails any in-flight 0.5-RTT
                // streams and deliberately leaves the slot pre-handshake — a
                // failed or cancelled handshake must never expose an identity.
                let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
                handshake_completion_rx = Some(completion_rx);
                let conn_for_close = conn.clone();
                tokio::spawn(async move {
                    let handshake_succeeded =
                        match await_with_optional_timeout(zero_rtt_accepted, handshake_timeout)
                            .await
                        {
                            Ok(zero_rtt_accepted) => server_0rtt_handshake_succeeded(
                                zero_rtt_accepted,
                                conn_for_close.close_reason().is_none(),
                            ),
                            Err(_elapsed) => {
                                warn!(
                                    "HTTP/3 handshake timed out from {} after {:?} (0-RTT path)",
                                    remote, handshake_timeout
                                );
                                conn_for_close
                                    .close(quinn::VarInt::from_u32(0), b"handshake timeout");
                                false
                            }
                        };
                    let _ = completion_tx.send(handshake_succeeded);
                    if !handshake_succeeded {
                        debug!(
                            "HTTP/3 handshake did not complete from {} (0-RTT path)",
                            remote
                        );
                    }
                });
                conn
            }
            Err(connecting) => {
                // No 0-RTT — fall back to full handshake.
                match await_with_optional_timeout(connecting, handshake_timeout).await {
                    Ok(result) => result?,
                    Err(_elapsed) => {
                        warn!("HTTP/3 handshake timed out after {:?}", handshake_timeout);
                        return Err(anyhow::anyhow!(
                            "HTTP/3 handshake timed out after {:?}",
                            handshake_timeout
                        ));
                    }
                }
            }
        }
    } else {
        // `quinn::Incoming` is `IntoFuture` (yielding a `Connecting`); the
        // explicit `.accept()?` here both surfaces address-validation errors
        // synchronously and gives us a typed `Connecting` future that
        // `tokio::time::timeout` can wrap directly.
        let connecting = connecting.accept()?;
        match await_with_optional_timeout(connecting, handshake_timeout).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                warn!("HTTP/3 handshake timed out after {:?}", handshake_timeout);
                return Err(anyhow::anyhow!(
                    "HTTP/3 handshake timed out after {:?}",
                    handshake_timeout
                ));
            }
        }
    };

    let remote_addr = connection.remote_address();
    debug!(
        "HTTP/3 connection established from {}",
        crate::util::client_identity::canonical_socket_addr(remote_addr)
    );

    // Publish the peer certificate and chain from the QUIC connection (mTLS).
    // Every branch that reaches here except the 0-RTT one has already awaited
    // handshake completion, so `peer_identity()` is meaningful now and the
    // established snapshot (identity + `is_early_data = false`) is installed
    // before the accept loop can hand a single stream to a request task. The
    // 0-RTT branch deliberately does NOT publish here — its completion signal
    // is consumed in the accept loop after already-ready early streams.
    if handshake_completion_rx.is_none() {
        peer_identity.publish_handshake_result(true, quinn_peer_cert_chain(&connection));
    }
    let frontend_sni_hostname = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name.as_deref().map(str::to_ascii_lowercase));

    // Keep a handle to the quinn connection so we can detect QUIC connection
    // migration (RFC 9000 §9). When a client migrates to a new IP (e.g., mobile
    // network handoff), quinn updates remote_address() internally. We compare
    // the SocketAddr per-request (cheap integer comparison) and only re-format
    // the IP string on the rare occasion it changes. This prevents stale IPs
    // from poisoning rate-limit keys and access logs after migration.
    let quinn_conn = connection.clone();
    // Built once per QUIC connection and cloned (one `Arc` bump) into each
    // accepted request stream. Watching connection close needs no access to
    // the request stream, so nothing here can race the proxy path for request
    // bytes or mask a stream-accounting failure.
    let peer_connection =
        crate::plugins::PeerConnectionSignal::new(std::sync::Arc::new(QuicPeerConnectionWatch {
            connection: connection.clone(),
        }));
    // RFC 9220: advertise SETTINGS_ENABLE_CONNECT_PROTOCOL so H3 clients can
    // bootstrap a WebSocket via Extended CONNECT (:method=CONNECT,
    // :protocol=websocket). Mirrors the H2 listener's `enable_connect_protocol()`
    // call. Gated by `FERRUM_HTTP3_WEBSOCKET_ENABLED` so operators can disable
    // the path without disabling HTTP/3 entirely; the dispatch site still
    // returns 501 if a client manages to send the Extended CONNECT anyway.
    let mut h3_conn = h3::server::builder()
        .enable_extended_connect(state.env_config.http3_websocket_enabled)
        .build(h3_quinn::Connection::new(connection))
        .await?;

    // Pre-format socket IP string once per connection — shared across all streams
    // to avoid per-request String allocation from SocketAddr::ip().to_string().
    // Updated in-place when QUIC connection migration is detected.
    // `cached_addr` stays RAW: it is only ever compared against
    // `quinn_conn.remote_address()` to detect migration, and folding one side of
    // that comparison would report a migration on every request from a mapped
    // peer. The identity pair derived from it is refreshed as a unit whenever it
    // changes, so the typed peer and its string always describe the same address
    // (GHSA-vjwj-657f-5w9g).
    let mut cached_addr = quinn_conn.remote_address();
    let (mut canonical_peer, mut socket_ip) = h3_client_identity(cached_addr);

    loop {
        // A QUIC early-data request and the TLS Connected event can become
        // ready in the same scheduler turn. Poll request acceptance first so a
        // buffered replayable stream snapshots the pre-handshake state. Only
        // after accept is Pending may successful handshake completion publish
        // the established identity for later 1-RTT streams.
        let (accepted, handshake_succeeded) =
            if let Some(completion_rx) = handshake_completion_rx.as_mut() {
                tokio::select! {
                    biased;
                    accepted = h3_conn.accept() => (Some(accepted), None),
                    completed = completion_rx => {
                        (None, Some(completed.unwrap_or_default()))
                    }
                }
            } else {
                (Some(h3_conn.accept().await), None)
            };

        if let Some(handshake_succeeded) = handshake_succeeded {
            handshake_completion_rx = None;
            let peer_certs = if handshake_succeeded {
                quinn_peer_cert_chain(&quinn_conn)
            } else {
                None
            };
            peer_identity.publish_handshake_result(handshake_succeeded, peer_certs);
            continue;
        }

        let Some(accepted) = accepted else {
            continue;
        };
        match accepted {
            Ok(Some(resolver)) => {
                // Detect QUIC connection migration: compare SocketAddr (two integer
                // fields) — zero allocation. Only re-format the IP string when the
                // address actually changes, which is rare (mobile network handoff).
                let current_addr = quinn_conn.remote_address();
                if current_addr != cached_addr {
                    let previous_peer = canonical_peer;
                    cached_addr = current_addr;
                    // The post-migration address is a fresh identity boundary and is
                    // folded on the same terms as the initial one — a client that
                    // migrates onto a mapped IPv4 path keeps one per-IP budget and one
                    // GeoIP principal (GHSA-vjwj-657f-5w9g).
                    (canonical_peer, socket_ip) = h3_client_identity(current_addr);
                    info!(
                        "HTTP/3 connection migration detected: {} -> {}",
                        previous_peer, canonical_peer
                    );
                }

                let state = Arc::clone(&state);
                let frontend_sni_hostname = frontend_sni_hostname.clone();
                let socket_ip = Arc::clone(&socket_ip);
                // Take ONE lock-free identity snapshot NOW — before spawning
                // the task — so the early-data flag and the peer certificate
                // this stream sees come from the same point in the connection
                // lifecycle. A single `ArcSwap::load_full()`: no lock, no
                // allocation beyond the refcount bumps the per-request cert
                // handles already cost.
                let identity = peer_identity.snapshot();
                let cert = identity.client_cert_der.clone();
                let chain = identity.client_cert_chain_der.clone();
                let mtls_auth_connection_cache = identity.mtls_auth_connection_cache.clone();
                let peer_spiffe_extraction_cache = identity.peer_spiffe_extraction_cache.clone();
                let is_early_data = identity.is_early_data;
                let peer_connection = peer_connection.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(
                                req,
                                stream,
                                state,
                                canonical_peer,
                                &socket_ip,
                                frontend_listen_port,
                                frontend_sni_hostname,
                                cert,
                                chain,
                                mtls_auth_connection_cache,
                                peer_spiffe_extraction_cache,
                                is_early_data,
                                peer_connection,
                            )
                            .await
                            {
                                error!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("HTTP/3 request resolution error: {}", e);
                        }
                    }
                });
            }
            Ok(None) => {
                debug!("HTTP/3 connection closed from {}", canonical_peer);
                break;
            }
            Err(e) => {
                warn!("HTTP/3 connection error from {}: {}", canonical_peer, e);
                break;
            }
        }
    }

    Ok(())
}

/// Peer-gone watch backed by QUIC connection close.
///
/// Resolves on any connection termination the peer can cause — CONNECTION_CLOSE
/// (graceful or error), idle timeout, or path failure — and on local close.
/// It deliberately observes only connection state: the request stream stays
/// exclusively owned by the request task, so this never competes for request
/// bytes and never suppresses a stream-accounting error. A per-stream
/// RESET_STREAM that leaves the connection open is not observable through the
/// public `h3` API and is therefore bounded by the fault-delay ceiling and the
/// process-wide delayed-work budget instead.
struct QuicPeerConnectionWatch {
    connection: quinn::Connection,
}

impl crate::plugins::PeerConnectionWatch for QuicPeerConnectionWatch {
    fn closed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // `Connection::closed()` is cancel-safe and resolves with the
            // termination reason; the reason itself is irrelevant here.
            let _ = self.connection.closed().await;
        })
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/// Handle a single HTTP/3 request stream.
///
/// `remote_addr` is the connection's current (post-migration) QUIC peer already
/// folded through `client_identity::canonical_socket_addr`, and `socket_ip` is
/// the pre-formatted string for that same address — so the typed and textual
/// client identities always describe one principal (GHSA-vjwj-657f-5w9g).
#[allow(clippy::too_many_arguments)]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: Arc<ProxyState>,
    remote_addr: SocketAddr,
    socket_ip: &str,
    frontend_listen_port: Option<u16>,
    frontend_sni_hostname: Option<String>,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    mtls_auth_connection_cache: Option<Arc<crate::plugins::mtls_auth::MtlsAuthConnectionCache>>,
    peer_spiffe_extraction_cache: Option<
        Arc<crate::plugins::mesh::spiffe_identity::SpiffeIdentityConnectionCache>,
    >,
    is_early_data: bool,
    peer_connection: crate::plugins::PeerConnectionSignal,
) -> Result<(), anyhow::Error> {
    let start_time = std::time::Instant::now();

    // Detect the HTTP flavor (Plain / gRPC / WebSocket) once from the incoming
    // H3 request. This runs first so every admission rejection below can be
    // flavor-aware (trailers-only gRPC errors for gRPC requests, JSON for
    // everything else). WebSocket over H3 requires Extended CONNECT
    // (RFC 9220) and is handled by a dedicated bridge below. gRPC over H3
    // dispatches via the native H3 backend pool (`dispatch_grpc_native_h3`)
    // when the concrete backend is proven H3-capable and the request can
    // stream — the only path that reaches an H3-only gRPC backend; otherwise it
    // falls through the cross-protocol bridge to the H2 gRPC pool. Keeping the
    // flavor around lets every dispatch and rejection stay flavor-aware
    // (trailers-only gRPC status vs JSON).
    let detected_http_flavor = crate::proxy::backend_dispatch::detect_http_flavor(&req);
    // Enforce configured HTTP/3 header limits before deriving any gRPC-Web
    // response encoding from request headers. gRPC-Web media negotiation may
    // preserve custom +suffix values in owned response Content-Type strings,
    // so oversized hostile headers must fail closed before that parsing runs.
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_h3_flavor_aware_reject(&state, detected_http_flavor, 431);
            let body = format!(
                r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                name.as_str(),
                state.max_single_header_size_bytes
            );
            send_h3_error_flavor_aware(
                &mut stream,
                detected_http_flavor,
                None,
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                &body,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Request header exceeds maximum size",
            )
            .await?;
            return Ok(());
        }
        total_header_size += header_size;
    }
    if total_header_size > state.max_header_size_bytes {
        record_h3_flavor_aware_reject(&state, detected_http_flavor, 431);
        send_h3_error_flavor_aware(
            &mut stream,
            detected_http_flavor,
            None,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Total request headers exceed maximum size",
        )
        .await?;
        return Ok(());
    }
    if state.max_header_count > 0 && req.headers().len() > state.max_header_count {
        record_h3_flavor_aware_reject(&state, detected_http_flavor, 431);
        let body = format!(
            r#"{{"error":"Request header count ({}) exceeds maximum of {}"}}"#,
            req.headers().len(),
            state.max_header_count
        );
        send_h3_error_flavor_aware(
            &mut stream,
            detected_http_flavor,
            None,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &body,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Request header count exceeds maximum",
        )
        .await?;
        return Ok(());
    }

    // Extended CONNECT classification takes precedence over Content-Type.
    // Besides selecting the WebSocket plugin chain below, suppress gRPC-Web
    // rejection shaping so a spoofed header cannot turn a WS policy reject
    // into a gRPC-Web response.
    let grpc_web_response_content_type_owned = if detected_http_flavor == HttpFlavor::WebSocket {
        None
    } else {
        req.headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|content_type| {
                if !crate::plugins::grpc_web::is_grpc_web_content_type(content_type) {
                    return None;
                }
                let negotiated =
                    crate::plugins::grpc_web::negotiate_response_media_type_from_headers(
                        content_type,
                        req.headers(),
                        state.max_header_size_bytes,
                    );
                Some(negotiated.unwrap_or_else(|_| {
                    crate::plugins::grpc_web::response_content_type(content_type)
                }))
            })
    };
    let grpc_web_response_content_type = grpc_web_response_content_type_owned.as_deref();
    // gRPC-Web remains Plain in the shared wire classifier so the grpc_web
    // plugin retains ownership of body translation. Once its content type is
    // recognized here, however, every request-side decision must treat it as
    // effective gRPC: POST validation, plugin selection, body limits, and
    // fail-closed method policy all need the same answer. Backend transport is
    // selected separately after request hooks, once the translator's trusted
    // marker is known. The separate response content type above preserves
    // binary/text + format-suffix encoding for client-facing rejection and
    // response shaping after Accept negotiation.
    let http_flavor = if grpc_web_response_content_type.is_some() {
        HttpFlavor::Grpc
    } else {
        detected_http_flavor
    };

    // Global request admission control (HTTP/3). Single atomic load (~1ns).
    if state
        .overload
        .reject_new_requests
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        record_h3_flavor_aware_reject(&state, http_flavor, 503);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            http::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"Service overloaded"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
            "Service overloaded",
        )
        .await?;
        return Ok(());
    }

    // Track this request for overload monitoring and graceful drain.
    let request_guard = crate::overload::RequestGuard::new(&state.overload);

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    // Build request context (client_ip resolved below after headers are parsed)
    let mut ctx = RequestContext::new(socket_ip.to_owned(), method.clone(), path.clone());
    // Carry the operator's response-body ceiling so the buffered representation
    // gate bounds its decompression by the same limit the wire path enforces.
    ctx.max_response_body_size_bytes = state.max_response_body_size_bytes;
    let mut request_scheme = "https";
    ctx.request_is_secure = true;
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    if let Some(content_type) = grpc_web_response_content_type {
        crate::plugins::grpc_web::retain_negotiated_response_content_type(&mut ctx, content_type);
    }
    // Use the actual UDP listener port so port-scoped plugins such as mesh
    // outbound registry and mesh authz see the same frontend port that accepted
    // the H3 request. Fall back to the configured HTTPS port only if Quinn
    // cannot report the bound local address.
    ctx.frontend_listen_port = frontend_listen_port.or(Some(state.env_config.proxy_https_port));
    ctx.frontend_sni_hostname = frontend_sni_hostname;
    ctx.tls_client_cert_der = tls_client_cert_der;
    ctx.tls_client_cert_chain_der = tls_client_cert_chain_der;
    ctx.mtls_auth_connection_cache = mtls_auth_connection_cache;
    ctx.peer_spiffe_extraction_cache = peer_spiffe_extraction_cache;
    // Lets deliberately parked work (injected fault delays) observe QUIC
    // connection close instead of holding this stream, its `RequestGuard`, and
    // its plugin snapshot until the timer expires.
    ctx.peer_connection = Some(peer_connection);

    // Store raw headers for deferred materialization.
    ctx.set_raw_headers(req.headers().clone());
    crate::proxy::stamp_original_request_metadata(&mut ctx);

    // Validate URL length (path + query string)
    if state.max_url_length_bytes > 0 {
        let url_len = path.len()
            + if query_string.is_empty() {
                0
            } else {
                1 + query_string.len()
            };
        if url_len > state.max_url_length_bytes {
            record_h3_flavor_aware_reject(&state, http_flavor, 414);
            let body = format!(
                r#"{{"error":"Request URL length ({} bytes) exceeds maximum of {} bytes"}}"#,
                url_len, state.max_url_length_bytes
            );
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::URI_TOO_LONG,
                &body,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Request URL too long",
            )
            .await?;
            return Ok(());
        }
    }

    // Validate query parameter count (skip empty segments from consecutive '&').
    // Keep this in sync with the H1/H2 proxy path so `?a=1&&b=2` counts as
    // two parameters across all frontend protocols.
    if state.max_query_params > 0 && !query_string.is_empty() {
        let param_count = crate::proxy::count_query_params(&query_string);
        if param_count > state.max_query_params {
            record_h3_flavor_aware_reject(&state, http_flavor, 400);
            let body = format!(
                r#"{{"error":"Query parameter count ({}) exceeds maximum of {}"}}"#,
                param_count, state.max_query_params
            );
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::BAD_REQUEST,
                &body,
                crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
                "Too many query parameters",
            )
            .await?;
            return Ok(());
        }
    }

    // Protocol-level header validation (HTTP/3-applicable subset).
    // HTTP/3 carries authority in `:authority`, but a Host field can still be
    // present during translation. Validate both before routing so backend
    // dispatch cannot key on a different authority than route/plugin checks.
    if let Some(error_body) =
        crate::proxy::check_protocol_headers(req.headers(), http::Version::HTTP_3)
    {
        warn!("Rejected HTTP/3 request: {}", error_body);
        record_h3_flavor_aware_reject(&state, http_flavor, 400);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_REQUEST,
            error_body,
            crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
            "Protocol header violation",
        )
        .await?;
        return Ok(());
    }
    if let Some(error_body) = crate::proxy::check_host_authority_consistency(
        req.headers(),
        req.uri(),
        http::Version::HTTP_3,
    ) {
        warn!("Rejected HTTP/3 request: {}", error_body);
        record_h3_flavor_aware_reject(&state, http_flavor, 400);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_REQUEST,
            error_body,
            crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
            "Host and authority mismatch",
        )
        .await?;
        return Ok(());
    }

    // Canonical policy path (advisory GHSA-69xf-42xm-4w4f). Placed at exactly
    // the same point in the ordering as the HTTP/1.1 + HTTP/2 handler — after
    // the transport-level checks, before routing, plugins, and backend
    // dispatch — so all three frontend protocols accept and reject the same
    // set of request targets. Both the local `path` and `ctx.path` are
    // rebound: the H3 backend URL builders read the local value while plugins
    // read the context.
    // `None` means the target was already canonical, so nothing is rebound and
    // nothing is allocated — the case for the overwhelming majority of traffic.
    let canonicalized_path = match crate::policy_path::canonicalize_policy_path(&path) {
        Ok(std::borrow::Cow::Borrowed(_)) => None,
        Ok(std::borrow::Cow::Owned(canonical)) => Some(canonical),
        Err(rejection) => {
            warn!(
                reason = rejection.reason(),
                "Rejected HTTP/3 request: ambiguous percent-encoded request path"
            );
            record_h3_flavor_aware_reject(&state, http_flavor, 400);
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::BAD_REQUEST,
                rejection.client_error_body(),
                crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
                rejection.grpc_message(),
            )
            .await?;
            return Ok(());
        }
    };
    let path = match canonicalized_path {
        Some(canonical) => {
            let raw_path = std::mem::replace(&mut ctx.path, canonical.clone());
            ctx.set_raw_path_for_hmac(raw_path);
            canonical
        }
        None => path,
    };

    // Block TRACE method to prevent Cross-Site Tracing (XST) attacks.
    if method == "TRACE" {
        warn!("Rejected HTTP/3 TRACE request");
        record_h3_flavor_aware_reject(&state, http_flavor, 405);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"TRACE method is not allowed"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNIMPLEMENTED,
            "TRACE method is not allowed",
        )
        .await?;
        return Ok(());
    }

    // Block non-WebSocket CONNECT requests. HTTP/3 Extended CONNECT for
    // WebSocket (RFC 9220) is classified above as `HttpFlavor::WebSocket`
    // and falls through to the dedicated bridge later in this handler. Other
    // CONNECT-style protocols (for example CONNECT-UDP) are not supported by
    // this proxy and must be rejected to prevent tunnel establishment that
    // bypasses proxy routing.
    if method == "CONNECT" && http_flavor != HttpFlavor::WebSocket {
        warn!("Rejected non-WebSocket HTTP/3 CONNECT request");
        record_h3_flavor_aware_reject(&state, http_flavor, 405);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"CONNECT method is not allowed"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNIMPLEMENTED,
            "CONNECT method is not allowed",
        )
        .await?;
        return Ok(());
    }

    // Reject disallowed methods on 0-RTT early data connections (RFC 8470).
    // Early data is replayable, so only operator-configured safe methods are
    // permitted. Clients receive 425 Too Early and should retry after handshake.
    if is_early_data && !state.early_data_methods.contains(&method) {
        warn!(
            "Rejected HTTP/3 0-RTT request: method {} not in allowed early data methods",
            method
        );
        record_h3_flavor_aware_reject(&state, http_flavor, 425);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::TOO_EARLY,
            r#"{"error":"Method not allowed in 0-RTT early data"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
            "Method not allowed in 0-RTT early data",
        )
        .await?;
        return Ok(());
    }

    // Set the early data flag on the request context for plugin visibility.
    ctx.is_early_data = is_early_data;

    // Resolve real client IP using trusted proxy configuration.
    // Parse socket IP once upfront to avoid redundant parsing in each branch.
    // Uses the raw header accessors to read specific headers without
    // materializing the full HashMap — only 2-3 targeted lookups on the raw
    // HeaderMap. Parity with the H1/H2 path: the configured real-IP header is
    // read as ALL of its field lines so duplicate lines cannot hide a competing
    // attacker-supplied value (advisory GHSA-fx4w-68hx-mj7r).
    if !state.trusted_proxies.is_empty() {
        let socket_addr: std::net::IpAddr = remote_addr.ip();
        if let Some(forwarded_scheme) = crate::proxy::apply_trusted_forwarded_request_scheme(
            &mut ctx,
            &socket_addr,
            &state.trusted_proxies,
        ) {
            request_scheme = forwarded_scheme;
        }
        let xff_chain = {
            let mut values = ctx.raw_header_values("x-forwarded-for");
            values.next().map(|first| {
                let mut combined = String::from(first);
                for value in values {
                    combined.push(',');
                    combined.push_str(value);
                }
                combined
            })
        };
        // Bound the immutable borrow of `ctx` (held by the field-line iterator)
        // to this statement so the assignment below can take a mutable borrow.
        let resolved = crate::proxy::client_ip::resolve_forwarded_client_ip(
            socket_ip,
            &socket_addr,
            state
                .env_config
                .real_ip_header
                .as_deref()
                // real_ip_header is already lowercase from env config parsing
                .map(|name| ctx.header_field_lines(name))
                .into_iter()
                .flatten(),
            xff_chain.as_deref(),
            &state.trusted_proxies,
        )
        .unwrap_or_else(|| socket_ip.to_string());
        ctx.client_ip = resolved;
    }

    // Per-IP concurrent request limiting (same as HTTP/1.1 and HTTP/2 paths).
    let per_ip_guard = if let Some(ref counts) = state.per_ip_request_counts {
        let current = {
            let count = counts
                .entry(ctx.client_ip.clone())
                .or_insert_with(|| std::sync::atomic::AtomicU64::new(0));
            count
                .value()
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1
        };
        let guard = Some(crate::proxy::PerIpRequestGuard {
            ip: ctx.client_ip.clone(),
            counts: counts.clone(),
        });
        if current > state.max_concurrent_requests_per_ip {
            drop(guard);
            warn!(
                client_ip = %ctx.client_ip,
                concurrent = current,
                limit = state.max_concurrent_requests_per_ip,
                "Per-IP concurrent request limit exceeded (HTTP/3)"
            );
            record_h3_flavor_aware_reject(&state, http_flavor, 429);
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                http::StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"Too many concurrent requests from this IP"}"#,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Too many concurrent requests from this IP",
            )
            .await?;
            return Ok(());
        }
        guard
    } else {
        None
    };

    // Store raw query string for lazy parsing (deferred until plugins need it).
    ctx.set_raw_query_string(query_string.clone());

    // Extract request host for host-based routing.
    // HTTP/3 uses the :authority pseudo-header (from URI authority).
    // Also check the host header as a fallback. Strip port and lowercase.
    // Uses raw_header_get() to avoid materializing the full HashMap.
    let raw_host = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| ctx.raw_header_get("host"));
    let request_host: Option<String> = match raw_host {
        Some(h) => match crate::proxy::normalize_request_host_for_routing(h) {
            Some(normalized) => Some(normalized),
            None => {
                warn!("Rejected HTTP/3 request: malformed Host/authority value");
                record_h3_flavor_aware_reject(&state, http_flavor, 400);
                send_h3_error_flavor_aware(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"Request contains malformed Host or authority"}"#,
                    crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
                    "Malformed Host or authority",
                )
                .await?;
                return Ok(());
            }
        },
        None => None,
    };
    let request_authority = raw_host.and_then(|authority| {
        crate::proxy::normalize_request_authority_for_signing(authority, Some(request_scheme))
    });
    ctx.request_authority = request_authority;

    let epoch = state.request_epoch.load();
    ctx.lb_generation = epoch.lb_generation;

    // Route: host + longest prefix match via router cache
    let route_match = state.router_cache.find_proxy_in_snapshot(
        &epoch.route_table,
        epoch.route_generation,
        request_host.as_deref(),
        &path,
    );

    // Materialized mesh routes (`__mesh-inbound-*` / `__mesh-outbound-*`) are
    // direction-scoped (see the H1/H2 handler). The H3 frontend is never a mesh
    // capture listener, so `ctx.mesh_direction` is `None` here and any matched
    // mesh route is wrong-direction: re-resolve keeping only matching-direction
    // routes so an H3 request is never shortcut to a loopback/HBONE mesh route.
    let route_match = match route_match {
        Some(rm)
            if crate::modes::mesh::mesh_route_direction(&rm.proxy.id)
                .is_some_and(|route_dir| Some(route_dir) != ctx.mesh_direction) =>
        {
            state.router_cache.resolve_route_excluding_wrong_direction(
                &epoch.route_table,
                request_host.as_deref(),
                &path,
                ctx.mesh_direction,
            )
        }
        other => other,
    };

    let (proxy, strip_len) = match route_match {
        Some(rm) => {
            // Materialize headers now — path param injection writes to ctx.headers,
            // and all subsequent code (plugins, backend dispatch) needs the HashMap.
            ctx.materialize_headers();

            // Synthesize a `Host` entry from the H3 `:authority` pseudo-header
            // when the client did not send an explicit `Host` header. Real H3
            // clients (curl, Chromium, Firefox) typically send only
            // `:authority`, which the h3 crate parks in `req.uri().authority()`
            // and explicitly does NOT add to `req.headers()`. Without this
            // backfill, every downstream codepath that reads
            // `headers.get("host")` — `build_h3_backend_headers`,
            // `build_plain_request_builder`, the gRPC cross-protocol header
            // map, X-Forwarded-Host, RFC 7239 `Forwarded`, and any plugin
            // that gates on the inbound host — sees `None` and either
            // forwards no Host to the backend or omits the forwarding
            // header entirely. RFC 9114 §4.3.1 and RFC 9113 §8.3.1 both
            // treat the H2/H3 `:authority` pseudo-header as the Host
            // equivalent for forwarding purposes, so this is the canonical
            // back-translation. Routing already runs above against
            // `req.uri().authority()` directly, so it is unaffected.
            //
            // When `preserve_host_header == false`, the per-route Host
            // override fires later in `build_plain_request_builder` (plain
            // HTTP cross-protocol bridge) and `proxy_grpc_request_core` /
            // `proxy_grpc_request_streaming` (gRPC dispatch — covers both
            // the H1/H2 frontend gRPC path and the H3 cross-protocol gRPC
            // map, since the cross-protocol path delegates to those
            // functions) and replaces this synthetic value with the upstream
            // target's host. The existing semantics for non-preserve mode
            // are preserved.
            if !ctx.headers.contains_key("host")
                && let Some(authority) = req.uri().authority()
            {
                ctx.headers
                    .insert("host".to_string(), authority.as_str().to_string());
            }

            // Inject regex path parameters into context metadata and headers
            for (name, value) in &rm.path_params {
                ctx.metadata
                    .insert(format!("path_param.{}", name), value.clone());
                ctx.headers
                    .insert(format!("x-path-param-{}", name), value.clone());
            }
            (rm.proxy, rm.matched_prefix_len)
        }
        None => {
            record_h3_flavor_aware_reject(&state, http_flavor, 404);
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::NOT_FOUND,
                r#"{"error":"Not Found"}"#,
                crate::proxy::grpc_proxy::grpc_status::NOT_FOUND,
                "Not Found",
            )
            .await?;
            return Ok(());
        }
    };

    ctx.matched_proxy = Some(Arc::clone(&proxy));
    ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);

    // Keep recognized gRPC-Web on its ordinary HTTP protocol key. The request
    // view below composes only grpc_method_router and grpc_deadline into that
    // base chain, preserving every configured HTTP-only guardrail and avoiding
    // duplicate plugin instances/hooks. Method-filtered Extended CONNECT
    // requests still require WebSocket-scoped initial response policy and
    // transport-managed header stripping.
    let request_protocol = h3_plugin_protocol_for_request(
        detected_http_flavor,
        grpc_web_response_content_type.is_some(),
    );
    // Fault shaping must retain the immutable wire flavor: recognized
    // gRPC-Web is promoted only for gRPC policy selection above and must not
    // become native gRPC merely because its policy chain is gRPC-scoped.
    ctx.set_request_http_flavor(detected_http_flavor);
    // Namespace-composed lookup: the protocol snapshot is keyed by
    // `namespace|proxy_id`, so a bare `proxy.id` would miss every proxy entry
    // and fall back to the global policy chain.
    let initial_response_header_policy_plugins = epoch
        .plugin_cache
        .initial_response_header_policy_plugins(&proxy.namespace, &proxy.id, request_protocol);

    // Per-proxy HTTP method filtering (checked before plugins to save work).
    // Ordinary request hooks stay skipped, but terminal transaction logging
    // still runs from the protocol-filtered plugin-cache view so sinks can
    // attribute the matched-proxy 405.
    if let Some(ref allowed) = proxy.allowed_methods
        && !allowed.iter().any(|m| m.eq_ignore_ascii_case(&method))
    {
        record_h3_flavor_aware_reject(&state, http_flavor, 405);
        let allow_header = allowed.join(", ");
        let mut headers = HashMap::new();
        headers.insert("allow".to_string(), allow_header.clone());
        finalize_h3_gateway_error_headers(
            http_flavor,
            StatusCode::METHOD_NOT_ALLOWED,
            br#"{"error":"Method Not Allowed"}"#,
            &mut headers,
            initial_response_header_policy_plugins.as_ref(),
        );
        crate::proxy::restore_authoritative_allow_header(&mut headers, &allow_header);
        // Empty plugin list on the response path: do not run after_proxy /
        // request hooks merely to shape the 405. Logging uses a separate
        // immutable cache view below.
        if let Some(content_type) = grpc_web_response_content_type {
            send_h3_grpc_web_reject(
                &mut stream,
                &[],
                &mut ctx,
                content_type,
                StatusCode::METHOD_NOT_ALLOWED,
                Bytes::from_static(br#"{"error":"Method Not Allowed"}"#),
                &headers,
            )
            .await?;
        } else {
            send_h3_finalized_reject_flavor_aware(
                &mut stream,
                http_flavor,
                StatusCode::METHOD_NOT_ALLOWED,
                Bytes::from_static(br#"{"error":"Method Not Allowed"}"#),
                &headers,
                RejectBodyDisposition::for_request(
                    &ctx.method,
                    StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                ),
            )
            .await?;
        }
        let logging_view = if grpc_web_response_content_type.is_some() {
            epoch
                .plugin_cache
                .grpc_web_request_view(&proxy.namespace, &proxy.id)
        } else {
            epoch
                .plugin_cache
                .request_view(&proxy.namespace, &proxy.id, request_protocol)
        };
        let logging_plugins = logging_view.plugins();
        log_pre_backend_rejected_request(
            &logging_plugins,
            &ctx,
            StatusCode::METHOD_NOT_ALLOWED.as_u16(),
            start_time,
            "allowed_methods",
            0,
        )
        .await;
        return Ok(());
    }

    // gRPC spec mandates POST. Route first so this synthesized trailers-only
    // response receives the matched route's initial-header policy, matching
    // the H1/H2 dispatch contract.
    if matches!(http_flavor, HttpFlavor::Grpc) && method != "POST" {
        warn!(method = %method, "Rejected HTTP/3 gRPC request: method must be POST");
        record_h3_flavor_aware_reject(&state, http_flavor, 400);
        send_h3_error_flavor_aware_with_policy(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_REQUEST,
            r#"{"error":"gRPC requires POST method"}"#,
            crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
            "gRPC requires POST method",
            initial_response_header_policy_plugins.as_ref(),
        )
        .await?;
        return Ok(());
    }

    if matches!(http_flavor, HttpFlavor::Grpc) {
        ctx.metadata
            .entry("request_protocol".to_string())
            .or_insert_with(|| "grpc".to_string());
    }
    let allows_request_body_buffering =
        crate::proxy::http_flavor_allows_request_body_buffering(http_flavor);

    // Load plugin-cache values once for this request. Every plugin list,
    // capability bitset, and buffering flag below is derived from the same
    // cache generation without retaining the full cache across awaits.
    let plugin_cache_view = if grpc_web_response_content_type.is_some() {
        epoch
            .plugin_cache
            .grpc_web_request_view(&proxy.namespace, &proxy.id)
    } else {
        epoch
            .plugin_cache
            .request_view(&proxy.namespace, &proxy.id, request_protocol)
    };

    // Get pre-resolved plugins filtered by protocol (O(1) lookup)
    let plugins = plugin_cache_view.plugins();
    // Publish this route's client-facing body ceilings before any request DATA
    // frame is read or any response byte is retained, so native H3 and the H3
    // cross-protocol bridge bound themselves at the route limit rather than only
    // at the global one (`GHSA-xrfj-852f-645j`).
    ctx.route_request_body_limit_bytes = plugin_cache_view.enforced_request_body_limit();
    ctx.route_response_body_limit_bytes = plugin_cache_view.enforced_response_body_limit();
    // Folded once for this request. `0` still means unlimited, and an absent
    // route ceiling leaves each global knob exactly as configured, so a proxy
    // without a size-limiting plugin is byte-for-byte unchanged.
    let route_request_body_limit = ctx.route_request_body_limit();
    let route_response_body_limit = ctx.route_response_body_limit();
    let effective_max_request_body_size_bytes = crate::proxy::effective_request_body_limit(
        state.max_request_body_size_bytes,
        route_request_body_limit,
    );
    let effective_max_grpc_recv_size_bytes = crate::proxy::effective_request_body_limit(
        state.max_grpc_recv_size_bytes,
        route_request_body_limit,
    );
    let effective_max_response_body_size_bytes = crate::proxy::effective_request_body_limit(
        state.max_response_body_size_bytes,
        route_response_body_limit,
    );
    ctx.set_request_headers_to_redact(plugin_cache_view.request_headers_to_redact());
    // Same cache generation as `plugins` above: replay provenance must describe
    // exactly the response-side rules this request will run.
    ctx.set_response_presentation_policy_digest(
        plugin_cache_view.response_presentation_policy_digest(),
    );
    // Resolve the effective gRPC policy before any plugin/body await. Native
    // H3 and the H3→H2 bridge both consume this same monotonic absolute instant
    // instead of reconstructing a fresh timer from a rewritten header.
    if matches!(http_flavor, HttpFlavor::Grpc) {
        let prepared = crate::plugins::grpc_deadline::prepare_request_deadline(
            plugin_cache_view.grpc_deadline_plugins(),
            &mut ctx,
        );
        if let reject @ (PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }) = prepared
        {
            let Some(reject) = plugin_result_into_reject_parts(reject) else {
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from_static(b"Internal Server Error"),
                    &HashMap::new(),
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"Internal Server Error",
                    &HashMap::new(),
                );
                record_request(&state, log_status_code);
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from_static(b"Internal Server Error"),
                    &HashMap::new(),
                )
                .await?;
                return Ok(());
            };
            let mut headers = reject.headers;
            let mut reject_status = reject.status_code;
            let mut reject_body = reject.body;
            apply_reject_after_proxy_and_synthetic_body_hooks(
                &plugins,
                &mut ctx,
                &mut reject_status,
                &mut headers,
                &mut reject_body,
                true,
                false,
            )
            .await;
            let mut http_status =
                StatusCode::from_u16(reject_status).unwrap_or(StatusCode::BAD_REQUEST);
            let deadline_replaced = run_h3_deadline_bounded_reject_committed_hooks(
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                http_status,
                reject_body.clone(),
                &headers,
                initial_response_header_policy_plugins.as_ref(),
            )
            .await;
            if deadline_replaced {
                http_status = replace_buffered_h3_response_with_grpc_deadline(
                    &mut ctx,
                    grpc_web_response_content_type,
                    &mut headers,
                    &mut reject_body,
                    initial_response_header_policy_plugins.as_ref(),
                );
            }
            let log_status_code = if deadline_replaced {
                StatusCode::OK.as_u16()
            } else {
                h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject_body,
                    &headers,
                )
            };
            record_request(&state, log_status_code);
            log_rejected_request(
                &plugins,
                &ctx,
                log_status_code,
                start_time,
                "grpc_deadline_preflight",
                0,
            )
            .await;
            if deadline_replaced && grpc_web_response_content_type.is_some() {
                // gRPC-Web deadline frame: gateway-generated body written
                // verbatim, so its length is authoritative.
                send_h3_finalized_reject_response(
                    &mut stream,
                    StatusCode::OK,
                    reject_body.clone(),
                    &headers,
                    RejectBodyDisposition::WireBody,
                )
                .await?;
            } else {
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
            }
            return Ok(());
        }
    }
    // Pre-computed capability bitset — avoids per-request iter().any() scans.
    let capabilities = plugin_cache_view.capabilities();
    let backend_path_plugins = plugin_cache_view.backend_path_plugins();
    let backend_path_is_policy_bound = !backend_path_plugins.is_empty();
    let stream_hooks_enabled = plugin_cache_view.requires_response_stream_hooks();
    let maybe_requires_response_body_buffering =
        plugin_cache_view.requires_response_body_buffering();
    let mut plugin_execution_ns: u64 = 0;

    // Execute on_request_received hooks
    let phase_start = std::time::Instant::now();
    for plugin in plugins.iter() {
        let deadline = ctx.grpc_deadline_at();
        match crate::plugins::await_request_plugin_deadline_with_provenance(
            deadline,
            plugin.on_request_received(&mut ctx),
        )
        .await
        .into_plugin_result(&mut ctx)
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(reject) = plugin_result_into_reject_parts(reject) else {
                    tracing::error!("Plugin result could not be converted to rejection parts");
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(&state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                let mut reject_status = reject.status_code;
                let mut reject_body = reject.body;
                // Run after_proxy reject hooks AND the synthetic response-body
                // guardrail/transform pipeline over 2xx short-circuit bodies so
                // H3 matches the H1/H2 rejection path. An `on_request_received`
                // short-circuit (e.g. `request_termination` returning a non-empty
                // 2xx body) must see the same AI response guard / body hooks as
                // every other reject phase — keeping the advertised H3 parity from
                // holding only for `before_proxy` short-circuits.
                apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject_status,
                    &mut headers,
                    &mut reject_body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                let http_status = StatusCode::from_u16(reject_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject_body,
                    &headers,
                );
                // Record the normalized wire status: a gRPC reject is sent as
                // HTTP 200 + grpc-status, so runtime status metrics must match
                // the logged/served status (not the plugin's HTTP-style code),
                // consistent across every H3 reject phase.
                record_request(&state, log_status_code);
                log_rejected_request(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "on_request_received",
                    plugin_execution_ns,
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
    }
    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;

    // Recognition and policy selection are intentionally unconditional for a
    // valid gRPC-Web media type, even when no translator is installed. Backend
    // transport promotion is different: only the grpc_web plugin stamps the
    // trusted translated marker after rewriting the request to native gRPC.
    // Without that marker retain the original Plain wire flavor so existing H3
    // pass-through deployments are not silently moved onto the H2 gRPC pool.
    let backend_http_flavor = if grpc_web_response_content_type.is_some()
        && !crate::plugins::grpc_web::request_is_grpc_web_translated(&ctx)
    {
        detected_http_flavor
    } else {
        http_flavor
    };

    // Materialize query params before authentication. HTTP/3 historically
    // exposed raw, non-percent-decoded values to plugins; keep that default
    // so enabling this PR does not silently change auth/cache keys. Plugins
    // with query-param semantics that require H1/H2 parity opt in via the
    // capability bit below.
    if capabilities.has(crate::plugin_cache::PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS) {
        ctx.materialize_query_params();
    } else {
        ctx.materialize_query_params_raw();
    }

    // Some auth plugins (for example `hmac_auth`) verify request body integrity
    // at authenticate time. Buffer the body before the auth phase runs so those
    // plugins can read `ctx.request_body_bytes`.
    // WebSocket Extended CONNECT is excluded: DATA frames after the H3 200 are
    // WebSocket bytes, not a request body that can be drained before upgrade.
    let consumer_index = ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index));
    let authenticate_body_requirements = if allows_request_body_buffering
        && capabilities.has(crate::plugin_cache::PluginCapabilities::HAS_BODY_BEFORE_AUTHENTICATE)
    {
        crate::proxy::request_body_requirements_before_authenticate(&plugins, &ctx, &consumer_index)
    } else {
        crate::proxy::RequestBodyPhaseRequirements::default()
    };

    let mut prebuffered_body_data: Option<Vec<u8>> = if authenticate_body_requirements.required {
        let protocol_max_body = if matches!(http_flavor, HttpFlavor::Grpc) {
            effective_max_grpc_recv_size_bytes
        } else {
            effective_max_request_body_size_bytes
        };
        let max_body = crate::proxy::effective_request_body_limit(
            protocol_max_body,
            authenticate_body_requirements.plugin_limit,
        );
        let body_data = match collect_h3_request_body_with_deadline(
            drain_h3_request_body(&mut stream, max_body),
            ctx.grpc_deadline_at(),
            proxy.backend_read_timeout_ms,
        )
        .await
        {
            Ok(Some(body_data)) => body_data,
            Ok(None) => {
                record_h3_flavor_aware_reject(&state, http_flavor, 413);
                send_h3_error_flavor_aware_with_policy(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await?;
                return Ok(());
            }
            Err(H3RequestBodyReadError::Read(error)) => {
                halt_cancelled_h3_upload(&mut stream);
                return Err(error.into());
            }
            Err(H3RequestBodyReadError::DeadlineExceeded) => {
                finalize_h3_upload_deadline_rejection(
                    &mut stream,
                    &state,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    start_time,
                    "grpc_deadline_upload_before_authenticate",
                    plugin_execution_ns,
                )
                .await?;
                return Ok(());
            }
            Err(timeout) => {
                let (error_body, grpc_message) = h3_request_body_timeout_contract(&timeout);
                record_request(
                    &state,
                    if matches!(http_flavor, HttpFlavor::Grpc) {
                        StatusCode::OK.as_u16()
                    } else {
                        StatusCode::REQUEST_TIMEOUT.as_u16()
                    },
                );
                send_h3_error_flavor_aware_with_policy_and_recv_halt(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::REQUEST_TIMEOUT,
                    error_body,
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    grpc_message,
                    initial_response_header_policy_plugins.as_ref(),
                    false,
                )
                .await?;
                return Ok(());
            }
        };
        crate::proxy::store_request_body_metadata(
            &mut ctx,
            &body_data,
            authenticate_body_requirements.needs_text,
            authenticate_body_requirements.needs_bytes,
            authenticate_body_requirements.needs_digests,
        );
        ctx.bytes_sent_observed
            .fetch_max(body_data.len() as u64, std::sync::atomic::Ordering::Release);
        Some(body_data)
    } else {
        None
    };

    // Authentication phase (pre-computed auth plugin list — zero allocation).
    // Native gRPC uses the gRPC view. Recognized gRPC-Web uses the composed
    // HTTP view so existing browser-facing HTTP auth/guardrails remain active
    // while the two compatible native-gRPC policies participate.
    let auth_plugins = plugin_cache_view.auth_plugins();

    let auth_phase_start = std::time::Instant::now();
    if let Some((status_code, body, mut headers)) = run_authentication_phase(
        proxy.auth_mode.clone(),
        &auth_plugins,
        &mut ctx,
        &consumer_index,
    )
    .await
    {
        let mut reject_status = status_code;
        let mut reject_body = body;
        // Run after_proxy reject hooks AND the synthetic response-body
        // guardrail/transform pipeline over 2xx short-circuit bodies so an
        // authentication-phase short-circuit on H3 sees the same AI response
        // guard / body hooks as the H1/H2 rejection path and every other H3
        // reject phase.
        apply_reject_after_proxy_and_synthetic_body_hooks(
            &plugins,
            &mut ctx,
            &mut reject_status,
            &mut headers,
            &mut reject_body,
            matches!(http_flavor, HttpFlavor::Grpc),
            false,
        )
        .await;
        plugin_execution_ns += auth_phase_start.elapsed().as_nanos() as u64;
        let http_status = StatusCode::from_u16(reject_status).unwrap_or(StatusCode::UNAUTHORIZED);
        run_h3_reject_response_committed_hooks(
            &plugins,
            &mut ctx,
            http_flavor,
            grpc_web_response_content_type,
            http_status,
            reject_body.clone(),
            &headers,
        )
        .await;
        let log_status_code = h3_reject_log_status_and_metadata(
            &mut ctx,
            http_flavor,
            http_status,
            &reject_body,
            &headers,
        );
        // Record the normalized wire status: gRPC rejects go out as HTTP 200 +
        // grpc-status, so recording the raw `status_code` (e.g. 401/403) here
        // would make /metrics/runtime disagree with the logged and served
        // status. Must run AFTER `h3_reject_log_status_and_metadata`, matching
        // every other H3 reject phase.
        record_request(&state, log_status_code);
        log_rejected_request(
            &plugins,
            &ctx,
            log_status_code,
            start_time,
            "authenticate",
            plugin_execution_ns,
        )
        .await;
        send_h3_plugin_reject_flavor_aware(
            &mut stream,
            &plugins,
            &mut ctx,
            http_flavor,
            grpc_web_response_content_type,
            http_status,
            reject_body.clone(),
            &headers,
        )
        .await?;
        return Ok(());
    }
    plugin_execution_ns += auth_phase_start.elapsed().as_nanos() as u64;

    // Authorization plugins that inspect bodies buffer only after
    // authentication succeeds. This avoids collecting unauthenticated H3
    // uploads solely for a later authorization decision.
    let authorize_plugins = plugin_cache_view.authorize_plugins();
    let authorize_body_requirements =
        if capabilities.has(crate::plugin_cache::PluginCapabilities::HAS_BODY_BEFORE_AUTHORIZE) {
            crate::proxy::request_body_requirements_before_authorize(&authorize_plugins, &ctx)
        } else {
            crate::proxy::RequestBodyPhaseRequirements::default()
        };
    if authorize_body_requirements.required && allows_request_body_buffering {
        let global_body_limit = if matches!(http_flavor, HttpFlavor::Grpc) {
            effective_max_grpc_recv_size_bytes
        } else {
            effective_max_request_body_size_bytes
        };
        let body_limit = crate::proxy::effective_request_body_limit(
            global_body_limit,
            authorize_body_requirements.plugin_limit,
        );
        if crate::proxy::early_upload_phase_needs_fresh_drain(&prebuffered_body_data) {
            let body_data = match collect_h3_request_body_with_deadline(
                drain_h3_request_body(&mut stream, body_limit),
                ctx.grpc_deadline_at(),
                proxy.backend_read_timeout_ms,
            )
            .await
            {
                Ok(Some(body_data)) => body_data,
                Ok(None) => {
                    record_h3_flavor_aware_reject(&state, http_flavor, 413);
                    send_h3_error_flavor_aware_with_policy(
                        &mut stream,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                        "Request body exceeds maximum size",
                        initial_response_header_policy_plugins.as_ref(),
                    )
                    .await?;
                    return Ok(());
                }
                Err(H3RequestBodyReadError::Read(error)) => {
                    halt_cancelled_h3_upload(&mut stream);
                    return Err(error.into());
                }
                Err(H3RequestBodyReadError::DeadlineExceeded) => {
                    finalize_h3_upload_deadline_rejection(
                        &mut stream,
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        start_time,
                        "grpc_deadline_upload_before_authorize",
                        plugin_execution_ns,
                    )
                    .await?;
                    return Ok(());
                }
                Err(timeout) => {
                    let (error_body, grpc_message) = h3_request_body_timeout_contract(&timeout);
                    record_request(
                        &state,
                        if matches!(http_flavor, HttpFlavor::Grpc) {
                            StatusCode::OK.as_u16()
                        } else {
                            StatusCode::REQUEST_TIMEOUT.as_u16()
                        },
                    );
                    send_h3_error_flavor_aware_with_policy_and_recv_halt(
                        &mut stream,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::REQUEST_TIMEOUT,
                        error_body,
                        crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                        grpc_message,
                        initial_response_header_policy_plugins.as_ref(),
                        false,
                    )
                    .await?;
                    return Ok(());
                }
            };
            prebuffered_body_data = Some(body_data);
        }

        if let Some(body_data) = prebuffered_body_data.as_ref() {
            if body_limit > 0 && body_data.len() > body_limit {
                record_h3_flavor_aware_reject(&state, http_flavor, 413);
                send_h3_error_flavor_aware_with_policy(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await?;
                return Ok(());
            }
            crate::proxy::store_request_body_metadata(
                &mut ctx,
                body_data,
                authorize_body_requirements.needs_text,
                authorize_body_requirements.needs_bytes,
                authorize_body_requirements.needs_digests,
            );
            ctx.bytes_sent_observed
                .fetch_max(body_data.len() as u64, std::sync::atomic::Ordering::Release);
        }
    }

    // Authorization phase (pre-computed authorize plugin list — zero allocation).
    if !authorize_plugins.is_empty() {
        let phase_start = std::time::Instant::now();
        for plugin in authorize_plugins.iter() {
            let deadline = ctx.grpc_deadline_at();
            match crate::plugins::await_request_plugin_deadline_with_provenance(
                deadline,
                plugin.authorize(&mut ctx),
            )
            .await
            .into_plugin_result(&mut ctx)
            {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let Some(reject) = plugin_result_into_reject_parts(reject) else {
                        tracing::error!("Plugin result could not be converted to rejection parts");
                        run_h3_reject_response_committed_hooks(
                            &plugins,
                            &mut ctx,
                            http_flavor,
                            grpc_web_response_content_type,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Bytes::from_static(b"Internal Server Error"),
                            &HashMap::new(),
                        )
                        .await;
                        let log_status_code = h3_reject_log_status_and_metadata(
                            &mut ctx,
                            http_flavor,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            b"Internal Server Error",
                            &HashMap::new(),
                        );
                        record_request(&state, log_status_code);
                        send_h3_plugin_reject_flavor_aware(
                            &mut stream,
                            &plugins,
                            &mut ctx,
                            http_flavor,
                            grpc_web_response_content_type,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Bytes::from_static(b"Internal Server Error"),
                            &HashMap::new(),
                        )
                        .await?;
                        return Ok(());
                    };
                    let mut headers = reject.headers;
                    let mut reject_status = reject.status_code;
                    let mut reject_body = reject.body;
                    // Run after_proxy reject hooks AND the synthetic response-body
                    // guardrail/transform pipeline over 2xx short-circuit bodies so
                    // an authorization-phase short-circuit on H3 sees the same AI
                    // response guard / body hooks as the H1/H2 rejection path and
                    // every other H3 reject phase.
                    apply_reject_after_proxy_and_synthetic_body_hooks(
                        &plugins,
                        &mut ctx,
                        &mut reject_status,
                        &mut headers,
                        &mut reject_body,
                        matches!(http_flavor, HttpFlavor::Grpc),
                        false,
                    )
                    .await;
                    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                    let http_status =
                        StatusCode::from_u16(reject_status).unwrap_or(StatusCode::FORBIDDEN);
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        http_status,
                        reject_body.clone(),
                        &headers,
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        http_status,
                        &reject_body,
                        &headers,
                    );
                    // Record the normalized wire status (gRPC rejects go out as
                    // HTTP 200 + grpc-status); keeps runtime metrics consistent
                    // with the logged/served status across every H3 reject phase.
                    record_request(&state, log_status_code);
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        log_status_code,
                        start_time,
                        "authorize",
                        plugin_execution_ns,
                    )
                    .await;
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        http_status,
                        reject_body.clone(),
                        &headers,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    let maybe_needs_request_buffering = plugin_cache_view.requires_request_body_buffering();
    let request_may_need_plugin_buffering =
        allows_request_body_buffering && maybe_needs_request_buffering;
    let has_terminal_body_dispatch = capabilities
        .has(crate::plugin_cache::PluginCapabilities::FINAL_BODY_BEFORE_BACKEND_DISPATCH);
    let has_contextual_final_body_hook =
        capabilities.has(crate::plugin_cache::PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT);
    // A finalized-request-egress plugin must observe the exact backend-visible
    // request, so a buffered H3 request finalizes before dispatch rather than
    // inside the backend bridge (GHSA-4vr5-4wm3-x5xv).
    let has_finalized_request_egress = capabilities
        .has(crate::plugin_cache::PluginCapabilities::DISPATCHES_FINALIZED_REQUEST_EGRESS);
    let (
        initial_plugin_needs_request_buffering,
        initial_final_body_before_backend_dispatch,
        initial_needs_ctx_headers_for_body_hooks,
    ) = crate::proxy::final_request_body_requirements(
        &plugins,
        &ctx,
        request_may_need_plugin_buffering,
        has_terminal_body_dispatch,
        has_contextual_final_body_hook,
        has_finalized_request_egress,
    );
    let before_proxy_body_requirements = if initial_plugin_needs_request_buffering
        && capabilities.has(crate::plugin_cache::PluginCapabilities::HAS_BODY_BEFORE_BEFORE_PROXY)
    {
        crate::proxy::request_body_requirements_before_before_proxy(&plugins, &ctx)
    } else {
        crate::proxy::RequestBodyPhaseRequirements::default()
    };
    let protocol_body_limit = if matches!(http_flavor, HttpFlavor::Grpc) {
        effective_max_grpc_recv_size_bytes
    } else {
        effective_max_request_body_size_bytes
    };
    let before_proxy_body_limit = crate::proxy::effective_request_body_limit(
        protocol_body_limit,
        before_proxy_body_requirements.plugin_limit,
    );

    // If we already buffered above for the body-before-authenticate path, the
    // body is already drained from the stream — no extra recv_data work here.
    if before_proxy_body_requirements.required
        && crate::proxy::early_upload_phase_needs_fresh_drain(&prebuffered_body_data)
    {
        let body_data = match collect_h3_request_body_with_deadline(
            drain_h3_request_body(&mut stream, before_proxy_body_limit),
            ctx.grpc_deadline_at(),
            proxy.backend_read_timeout_ms,
        )
        .await
        {
            Ok(Some(body_data)) => body_data,
            Ok(None) => {
                record_h3_flavor_aware_reject(&state, http_flavor, 413);
                send_h3_error_flavor_aware_with_policy(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await?;
                return Ok(());
            }
            Err(H3RequestBodyReadError::Read(error)) => {
                halt_cancelled_h3_upload(&mut stream);
                return Err(error.into());
            }
            Err(H3RequestBodyReadError::DeadlineExceeded) => {
                finalize_h3_upload_deadline_rejection(
                    &mut stream,
                    &state,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    start_time,
                    "grpc_deadline_upload_before_before_proxy",
                    plugin_execution_ns,
                )
                .await?;
                return Ok(());
            }
            Err(timeout) => {
                let (error_body, grpc_message) = h3_request_body_timeout_contract(&timeout);
                record_request(
                    &state,
                    if matches!(http_flavor, HttpFlavor::Grpc) {
                        StatusCode::OK.as_u16()
                    } else {
                        StatusCode::REQUEST_TIMEOUT.as_u16()
                    },
                );
                send_h3_error_flavor_aware_with_policy_and_recv_halt(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::REQUEST_TIMEOUT,
                    error_body,
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    grpc_message,
                    initial_response_header_policy_plugins.as_ref(),
                    false,
                )
                .await?;
                return Ok(());
            }
        };
        prebuffered_body_data = Some(body_data);
    }
    if before_proxy_body_requirements.required
        && let Some(body_data) = prebuffered_body_data.as_ref()
    {
        if before_proxy_body_limit > 0 && body_data.len() > before_proxy_body_limit {
            record_h3_flavor_aware_reject(&state, http_flavor, 413);
            send_h3_error_flavor_aware_with_policy(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"Request body exceeds maximum size"}"#,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Request body exceeds maximum size",
                initial_response_header_policy_plugins.as_ref(),
            )
            .await?;
            return Ok(());
        }
        crate::proxy::store_request_body_metadata(
            &mut ctx,
            body_data,
            before_proxy_body_requirements.needs_text,
            before_proxy_body_requirements.needs_bytes,
            before_proxy_body_requirements.needs_digests,
        );
    }

    // Pre-`before_proxy` buffered-body phases — same fixed order and same
    // contract as the shared H1/H2 path: opt-in gateway-owned normalization
    // (configured request decompression), then the distinct client-request-
    // contract decision over the ORIGINAL client representation before any
    // `before_proxy` / `transform_request_body` hook can reshape it
    // (`GHSA-896v-jx23-9g6p`).
    let runs_pre_before_proxy_body_phase = capabilities
        .has(crate::plugin_cache::PluginCapabilities::NORMALIZES_BUFFERED_REQUEST_BODY_BEFORE_BEFORE_PROXY)
        || before_proxy_body_requirements.validates_client_contract;
    if runs_pre_before_proxy_body_phase && let Some(body_data) = prebuffered_body_data.as_mut() {
        let phase_start = std::time::Instant::now();
        let mut rejected: Option<(PluginResult, &'static str)> = None;
        if capabilities
            .has(crate::plugin_cache::PluginCapabilities::NORMALIZES_BUFFERED_REQUEST_BODY_BEFORE_BEFORE_PROXY)
        {
            let mut tmp_headers = std::mem::take(&mut ctx.headers);
            let normalize_result =
                crate::proxy::apply_buffered_request_body_normalization_before_before_proxy(
                    &plugins,
                    &mut ctx,
                    &mut tmp_headers,
                    body_data,
                    before_proxy_body_requirements.needs_text,
                    before_proxy_body_requirements.needs_bytes,
                )
                .await;
            ctx.headers = tmp_headers;
            if !matches!(normalize_result, PluginResult::Continue) {
                rejected = Some((normalize_result, "normalize_buffered_request_body"));
            }
        }
        if rejected.is_none() && before_proxy_body_requirements.validates_client_contract {
            let contract_result = crate::proxy::apply_client_request_contract_validation(
                &plugins, &mut ctx, body_data,
            )
            .await;
            if !matches!(contract_result, PluginResult::Continue) {
                rejected = Some((contract_result, crate::proxy::CLIENT_REQUEST_CONTRACT_PHASE));
            }
        }
        if let Some((rejection, reject_phase)) = rejected {
            let Some(reject) = plugin_result_into_reject_parts(rejection) else {
                tracing::error!(
                    phase = reject_phase,
                    "pre-before_proxy body-phase rejection could not be normalized"
                );
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from_static(b"Internal Server Error"),
                    &HashMap::new(),
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"Internal Server Error",
                    &HashMap::new(),
                );
                record_request(&state, log_status_code);
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from_static(b"Internal Server Error"),
                    &HashMap::new(),
                )
                .await?;
                return Ok(());
            };
            let mut headers = reject.headers;
            let mut reject_status = reject.status_code;
            let mut reject_body = reject.body;
            apply_reject_after_proxy_and_synthetic_body_hooks(
                &plugins,
                &mut ctx,
                &mut reject_status,
                &mut headers,
                &mut reject_body,
                matches!(http_flavor, HttpFlavor::Grpc),
                false,
            )
            .await;
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
            let http_status =
                StatusCode::from_u16(reject_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            run_h3_reject_response_committed_hooks(
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                http_status,
                reject_body.clone(),
                &headers,
            )
            .await;
            let log_status_code = h3_reject_log_status_and_metadata(
                &mut ctx,
                http_flavor,
                http_status,
                &reject_body,
                &headers,
            );
            record_request(&state, log_status_code);
            log_rejected_request(
                &plugins,
                &ctx,
                log_status_code,
                start_time,
                reject_phase,
                plugin_execution_ns,
            )
            .await;
            send_h3_plugin_reject_flavor_aware(
                &mut stream,
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                http_status,
                reject_body.clone(),
                &headers,
            )
            .await?;
            return Ok(());
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // Native H3 has no trustworthy header-only empty-body signal: a GET/HEAD
    // stream may still deliver DATA. Replay lookup is eligible only after this
    // phase drained the complete upload and any early normalizer left the
    // final pre-before_proxy representation empty.
    ctx.set_replay_request_body_empty_proven(
        before_proxy_body_requirements.required
            && prebuffered_body_data.as_ref().is_some_and(Vec::is_empty),
    );

    // before_proxy hooks — only clone headers if at least one plugin modifies them.
    // When no plugin modifies headers, use std::mem::take to avoid a per-request HashMap clone.
    let needs_header_clone =
        capabilities.has(crate::plugin_cache::PluginCapabilities::MODIFIES_REQUEST_HEADERS);
    let mut owned_proxy_headers: Option<HashMap<String, String>> = None;
    if needs_header_clone {
        let phase_start = std::time::Instant::now();
        let mut cloned = ctx.headers.clone();
        match crate::proxy::run_before_proxy_hooks_for_backend_path_policy(
            &plugins,
            &mut ctx,
            &mut cloned,
            backend_path_is_policy_bound,
            crate::proxy::BackendPathBeforeProxyPass::Initial,
        )
        .await
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(reject) = plugin_result_into_reject_parts(reject) else {
                    tracing::error!("Plugin result could not be converted to rejection parts");
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(&state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                let mut reject_status = reject.status_code;
                let mut reject_body = reject.body;
                // Run after_proxy reject hooks AND the synthetic response-body
                // guardrail/transform pipeline over 2xx short-circuit bodies
                // (e.g. ai_federation / ai_semantic_cache hits) so H3 matches
                // the H1/H2 rejection path — keeping AI guardrails from being
                // bypassed over HTTP/3.
                apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject_status,
                    &mut headers,
                    &mut reject_body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                let http_status = StatusCode::from_u16(reject_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject_body,
                    &headers,
                );
                // Record the normalized wire status (gRPC rejects go out as
                // HTTP 200 + grpc-status); keeps runtime metrics consistent
                // with the logged/served status across every H3 reject phase.
                record_request(&state, log_status_code);
                log_rejected_request(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "before_proxy",
                    plugin_execution_ns,
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        owned_proxy_headers = Some(cloned);
    } else if !plugins.is_empty() {
        // No plugin modifies headers — swap headers out of ctx temporarily to
        // satisfy the borrow checker without cloning (zero allocation hot path).
        let phase_start = std::time::Instant::now();
        let mut tmp_headers = std::mem::take(&mut ctx.headers);
        match crate::proxy::run_before_proxy_hooks_for_backend_path_policy(
            &plugins,
            &mut ctx,
            &mut tmp_headers,
            backend_path_is_policy_bound,
            crate::proxy::BackendPathBeforeProxyPass::Initial,
        )
        .await
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(reject) = plugin_result_into_reject_parts(reject) else {
                    tracing::error!("Plugin result could not be converted to rejection parts");
                    ctx.headers = tmp_headers;
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(&state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(());
                };
                ctx.headers = tmp_headers;
                let mut headers = reject.headers;
                let mut reject_status = reject.status_code;
                let mut reject_body = reject.body;
                // Run after_proxy reject hooks AND the synthetic response-body
                // guardrail/transform pipeline over 2xx short-circuit bodies
                // (e.g. ai_federation / ai_semantic_cache hits) so H3 matches
                // the H1/H2 rejection path — keeping AI guardrails from being
                // bypassed over HTTP/3.
                apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject_status,
                    &mut headers,
                    &mut reject_body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                let http_status = StatusCode::from_u16(reject_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject_body,
                    &headers,
                );
                // Record the normalized wire status (gRPC rejects go out as
                // HTTP 200 + grpc-status); keeps runtime metrics consistent
                // with the logged/served status across every H3 reject phase.
                record_request(&state, log_status_code);
                log_rejected_request(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "before_proxy",
                    plugin_execution_ns,
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        ctx.headers = tmp_headers;
    }

    // Keep H3 body-plugin applicability aligned with the H1/H2 path: a
    // before_proxy header transformer can expose a JSON request that a
    // terminal provider plugin must own. Swap maps temporarily so the
    // request-time predicates see the effective headers without another clone.
    let (
        plugin_needs_request_buffering,
        final_body_before_backend_dispatch,
        needs_ctx_headers_for_body_hooks,
    ) = if let Some(transformed_headers) = owned_proxy_headers.as_mut() {
        std::mem::swap(&mut ctx.headers, transformed_headers);
        let requirements = crate::proxy::final_request_body_requirements(
            &plugins,
            &ctx,
            request_may_need_plugin_buffering,
            has_terminal_body_dispatch,
            has_contextual_final_body_hook,
            has_finalized_request_egress,
        );
        std::mem::swap(&mut ctx.headers, transformed_headers);
        requirements
    } else {
        (
            initial_plugin_needs_request_buffering,
            initial_final_body_before_backend_dispatch,
            initial_needs_ctx_headers_for_body_hooks,
        )
    };
    // Reserved gateway assertions — consumer identity AND the private GeoIP
    // lookup result — are never sourced from mutable plugin headers. Strip any
    // client- OR plugin-supplied value UNCONDITIONALLY before backend dispatch,
    // then inject the authenticated principal and the authoritative country
    // only after a successful lookup/allow decision. `materialize_headers`
    // only removed the RAW client header BEFORE plugins ran, so an unauthenticated
    // route where a `before_proxy` transformer adds `x-consumer-*` or
    // `x-geo-country` would otherwise forward that plugin value to the backend —
    // the exact spoofing path. The strip is case-insensitive (the gateway
    // injects mixed-case keys; the H3 wire and plugins use lowercase). To
    // preserve the zero-alloc hot path, only materialize/scrub when an
    // assertion must be injected OR a reserved header is actually present in
    // the effective source.
    let source_has_reserved_assertion = owned_proxy_headers
        .as_ref()
        .unwrap_or(&ctx.headers)
        .keys()
        .any(|k| {
            k.eq_ignore_ascii_case("x-consumer-username")
                || k.eq_ignore_ascii_case("x-consumer-custom-id")
                || k.eq_ignore_ascii_case("x-geo-country")
        });
    if ctx.backend_consumer_username().is_some()
        || ctx.backend_geo_country().is_some()
        || source_has_reserved_assertion
    {
        let headers = owned_proxy_headers.get_or_insert_with(|| ctx.headers.clone());
        crate::proxy::refresh_backend_gateway_assertion_headers(&ctx, headers);
    }
    // Resolve proxy_headers into an owned HashMap to avoid borrowing
    // ctx.headers while ctx is passed as &mut to proxy functions downstream.
    //
    // When a plugin needs the real request context in final request-body
    // hooks (`needs_final_request_body_context` capability — e.g. WAF), the
    // helper clones so the body hook can still read `ctx.headers` for
    // content-type/content-length gates. Otherwise it falls back to
    // `std::mem::take(&mut ctx.headers)` — the zero-alloc hot path that the
    // H3 server has used since before the WAF plugin landed.
    let mut proxy_headers: HashMap<String, String> = own_h3_proxy_headers(
        owned_proxy_headers,
        &mut ctx,
        needs_ctx_headers_for_body_hooks,
    );

    // Egress baggage strip — see `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`. The
    // native HTTP/3 frontend builds its own `proxy_headers` map separately
    // from the H1/H2 dispatch path in `proxy/mod.rs`, so the strip must be
    // applied here too. Keep this call in sync with the H1/H2 site and the
    // WebSocket handshake collector.
    crate::modes::mesh::hbone::strip_egress_baggage_in_map(
        &mut proxy_headers,
        &state.mesh_egress_strip_baggage_keys,
    );
    // Backend-boundary header policy over the finalized H3 outbound map, after
    // every generic `before_proxy` header transform, the gateway-assertion
    // refresh, and the baggage strip (`GHSA-xhp5-hqj8-3mwg`). Keep this in sync
    // with the H1/H2 site in `proxy/mod.rs`; the deferred passes below re-run it.
    if capabilities
        .has(crate::plugin_cache::PluginCapabilities::ENFORCES_FINAL_BACKEND_HEADER_POLICY)
    {
        crate::proxy::run_final_backend_header_policy_hooks(&plugins, &ctx, &mut proxy_headers);
    }
    let effective_query_string =
        crate::proxy::effective_backend_query_string_with_raw(&ctx, &query_string);

    // Apply plugin-set route overrides (e.g., `mesh_route_dispatch` from an
    // Istio VirtualService header/method match). When no overrides are set,
    // this is an `Arc::clone` — no per-request allocation. When overrides
    // are set, the override values are baked into a fresh `Arc<Proxy>` so
    // downstream pool keys, capability-registry lookups, URL construction,
    // and circuit-breaker target keys all derive from the effective
    // destination. Keep in sync with the H1/H2 dispatch path in
    // `src/proxy/mod.rs::handle_proxy_request_inner`.
    let proxy = ctx.apply_route_overrides_with_upstreams(proxy, epoch.load_balancer.upstreams());
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);

    // Preserve the client's original request path for access logging — the
    // transaction summaries below source `request_path` from this, not the
    // rewritten backend path. Mirrors `handle_proxy_request_inner`.
    let original_request_path = path.clone();

    // Istio `VirtualService.http[].rewrite.uri`: mirror the H1/H2 dispatch
    // contract by rebasing the request path used to build the backend URL when
    // `mesh_route_dispatch` set `ctx.route_override_path`. Keep in sync with
    // `src/proxy/mod.rs::handle_proxy_request_inner`.
    // Preserve the private override for finalized-egress plugins. The shared
    // helper also keeps H3 path selection in lockstep with H1/H2.
    let path = crate::proxy::rebase_route_override_path(&mut ctx, path);

    // Enforce request body size limit via Content-Length fast path. Apply
    // the gRPC-specific ceiling to gRPC requests so H3 matches H1/H2.
    let content_length_limit = if matches!(http_flavor, HttpFlavor::Grpc) {
        effective_max_grpc_recv_size_bytes
    } else {
        effective_max_request_body_size_bytes
    };
    // Parsed per comma-folded member so a standards-valid repeated identical
    // declaration is compared against the ceiling instead of failing to parse
    // and skipping this fast path (`GHSA-xrfj-852f-645j`). An unusable
    // declaration falls through to the bounded stream/collect paths, which never
    // trust a declared length.
    if content_length_limit > 0
        && crate::proxy::declared_request_content_length_over_limit(
            &proxy_headers,
            content_length_limit,
        )
    {
        if final_body_before_backend_dispatch {
            let rejection = finalize_h3_terminal_body_read_rejection(
                &state,
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::PAYLOAD_TOO_LARGE,
                Bytes::from_static(br#"{"error":"Request body exceeds maximum size"}"#),
                start_time,
                &mut plugin_execution_ns,
                &original_request_path,
            )
            .await;
            send_h3_plugin_reject_flavor_aware(
                &mut stream,
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                rejection.http_status,
                rejection.body.clone(),
                &rejection.headers,
            )
            .await?;
        } else {
            record_h3_flavor_aware_reject(&state, http_flavor, 413);
            send_h3_error_flavor_aware_with_policy(
                &mut stream,
                http_flavor,
                grpc_web_response_content_type,
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"Request body exceeds maximum size"}"#,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Request body exceeds maximum size",
                initial_response_header_policy_plugins.as_ref(),
            )
            .await?;
        }
        return Ok(());
    }

    // Finalize a body that can affect response streaming before transport and
    // buffer/stream classification. This path exists only when request-body
    // buffering is already required and PluginCache says a response buffer or
    // stream hook is configured; ordinary H3 requests do no additional work.
    // Compute terminal-dispatch applicability before route ownership moves
    // headers out of the context. The provider hook itself runs only after the
    // selected backend-effective path is authorized below.
    let reevaluate_response_policy_after_request_body =
        matches!(backend_http_flavor, HttpFlavor::Plain)
            && plugin_needs_request_buffering
            && (maybe_requires_response_body_buffering || stream_hooks_enabled);
    let mut request_body_prepared = false;
    let mut prepared_raw_request_body_bytes: Option<u64> = None;

    // --- Upstream target selection and circuit breaker ---
    // DestinationRule-derived HTTP connectionPool/TLS knobs are projected below
    // once the selected target's policy port is known. Per-port maxConnections,
    // tcpKeepalive, and LB/outlier knobs stay protocol-scope-specific:
    // maxConnections applies to H3 WebSocket sessions, tcpKeepalive is N/A for
    // QUIC, and LB/outlier selection is handled by select_upstream_target.
    // PASSTHROUGH orig-dst is `None` on H3: mesh capture is TCP-only
    // (SO_ORIGINAL_DST/REDIRECT; H3/UDP are out of mesh scope), so an H3
    // frontend never carries a captured original destination. A Passthrough
    // upstream therefore round-robins here (with the existing warn).
    let routing_proxy = Arc::clone(&proxy);
    let selection = crate::proxy::backend_dispatch::select_upstream_target(
        &proxy,
        &state,
        &epoch,
        &ctx.client_ip,
        &proxy_headers,
        None,
    );
    let lb_hash_key = selection.lb_hash_key;
    let upstream_target = crate::proxy::backend_dispatch::concretize_wildcard_target_for_request(
        selection.target,
        request_host.as_deref(),
    );
    let upstream_balancer = selection.balancer;
    // Mirror H1/H2 selected-target policy: cap per-request retries, then build
    // an effective proxy carrying per-target DestinationRule-derived
    // connectionPool/TLS overrides for the FIRST selected target. That
    // effective proxy backs the single-target dispatch decisions below
    // (retry-dependent buffering, native-H3 capability, streaming dispatch).
    // Every dispatch loop that can rotate retry targets — the buffered
    // native-H3 retry loop, the H3->plain and H3->gRPC bridges, and the H3
    // WebSocket dial loop — re-resolves the effective proxy per attempt from
    // the capped but UNRESOLVED base proxy, so a later target does not inherit
    // the first target's port-level TLS/SNI/H1 policy.
    let selected_base_proxy = crate::proxy::cap_proxy_retry_for_target(
        Arc::clone(&routing_proxy),
        upstream_target.as_deref(),
    );
    let effective_proxy = crate::proxy::resolve_effective_proxy_for_target(
        &selected_base_proxy,
        upstream_target.as_deref(),
    );
    let proxy = match effective_proxy {
        std::borrow::Cow::Borrowed(_) => Arc::clone(&selected_base_proxy),
        std::borrow::Cow::Owned(owned) => Arc::new(owned),
    };
    // Plugins/logging see the retry-capped BASE proxy, matching the H1/H2 path
    // (`handle_proxy_request_inner` assigns `ctx.matched_proxy` right after
    // `cap_proxy_retry_for_target`). Per-port TLS/timeout overrides are a
    // dispatch-time concern and must not appear baked into the plugin-visible
    // proxy on H3 only.
    ctx.matched_proxy = Some(Arc::clone(&selected_base_proxy));
    ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&selected_base_proxy.namespace, &selected_base_proxy.id);

    let has_deferred_routing_header_hooks = backend_path_is_policy_bound
        && capabilities
            .has(crate::plugin_cache::PluginCapabilities::HAS_DEFERRED_ROUTING_HEADER_HOOKS);
    let mut deferred_result = PluginResult::Continue;
    // The target is already pinned, so enforce backend-path policy before a
    // deferred routing-header hook can invoke an external service.
    if backend_path_is_policy_bound {
        let backend_path = crate::proxy::build_backend_effective_path(
            &proxy,
            &path,
            strip_len,
            upstream_target
                .as_ref()
                .and_then(|target| target.path.as_deref()),
        );
        if !run_h3_backend_path_plugins_or_send_reject(
            backend_path_plugins,
            &plugins,
            &mut ctx,
            &backend_path,
            &original_request_path,
            http_flavor,
            &mut stream,
            &state,
            start_time,
            &mut plugin_execution_ns,
            grpc_web_response_content_type,
        )
        .await?
        {
            return Ok(());
        }
        ctx.bind_authorized_backend_path(backend_path);
    }

    if has_deferred_routing_header_hooks {
        // Deferral changes authorization order, not the client-path view that
        // before_proxy hooks received before a mesh backend rewrite.
        let backend_ctx_path = std::mem::replace(&mut ctx.path, original_request_path.clone());
        let phase_start = std::time::Instant::now();
        deferred_result = crate::proxy::run_before_proxy_hooks_for_backend_path_policy(
            &plugins,
            &mut ctx,
            &mut proxy_headers,
            true,
            crate::proxy::BackendPathBeforeProxyPass::RoutingHeaderDeferred,
        )
        .await;
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        ctx.path = backend_ctx_path;
        if matches!(deferred_result, PluginResult::Continue) {
            // Re-establish gateway assertions and egress baggage
            // policy before a deferred function's headers reach a backend.
            crate::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut proxy_headers);
            crate::modes::mesh::hbone::strip_egress_baggage_in_map(
                &mut proxy_headers,
                &state.mesh_egress_strip_baggage_keys,
            );
            // A deferred pass can add or rename headers again, so re-assert the
            // backend-boundary header policy over the new map.
            if capabilities
                .has(crate::plugin_cache::PluginCapabilities::ENFORCES_FINAL_BACKEND_HEADER_POLICY)
            {
                crate::proxy::run_final_backend_header_policy_hooks(
                    &plugins,
                    &ctx,
                    &mut proxy_headers,
                );
            }
        }
    }

    if backend_path_is_policy_bound {
        if matches!(deferred_result, PluginResult::Continue) {
            // Deferred hooks retain the original client path; request_mirror
            // separately consumes the private path that passed final policy.
            let backend_ctx_path = std::mem::replace(&mut ctx.path, original_request_path.clone());
            let phase_start = std::time::Instant::now();
            deferred_result = crate::proxy::run_before_proxy_hooks_for_backend_path_policy(
                &plugins,
                &mut ctx,
                &mut proxy_headers,
                true,
                crate::proxy::BackendPathBeforeProxyPass::RemainingDeferred,
            )
            .await;
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
            ctx.path = backend_ctx_path;
        }
        if matches!(deferred_result, PluginResult::Continue) {
            crate::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut proxy_headers);
            crate::modes::mesh::hbone::strip_egress_baggage_in_map(
                &mut proxy_headers,
                &state.mesh_egress_strip_baggage_keys,
            );
            // A deferred pass can add or rename headers again, so re-assert the
            // backend-boundary header policy over the new map.
            if capabilities
                .has(crate::plugin_cache::PluginCapabilities::ENFORCES_FINAL_BACKEND_HEADER_POLICY)
            {
                crate::proxy::run_final_backend_header_policy_hooks(
                    &plugins,
                    &ctx,
                    &mut proxy_headers,
                );
            }
        }
        match deferred_result {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(reject) = plugin_result_into_reject_parts(reject) else {
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(&state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                let mut reject_status = reject.status_code;
                let mut reject_body = reject.body;
                apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject_status,
                    &mut headers,
                    &mut reject_body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                let http_status = StatusCode::from_u16(reject_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject_body,
                    &headers,
                );
                record_request(&state, log_status_code);
                log_rejected_request_with_path(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "before_proxy",
                    plugin_execution_ns,
                    Some(&original_request_path),
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Terminal final-body hooks may perform provider egress. Run them only
    // after the selected backend-effective path has been authorized and all
    // deferred before_proxy hooks have completed, while preserving #2651's
    // placement ahead of backend-only admission, circuit breaking, and dial.
    if final_body_before_backend_dispatch {
        let body_was_prebuffered = prebuffered_body_data.is_some();
        let mut body_data = prebuffered_body_data.take().unwrap_or_default();
        if !body_was_prebuffered {
            body_data = match collect_h3_request_body_with_deadline(
                drain_h3_request_body(&mut stream, content_length_limit),
                ctx.grpc_deadline_at(),
                proxy.backend_read_timeout_ms,
            )
            .await
            {
                Ok(Some(body_data)) => body_data,
                Ok(None) => {
                    let rejection = finalize_h3_terminal_body_read_rejection(
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Bytes::from_static(br#"{"error":"Request body exceeds maximum size"}"#),
                        start_time,
                        &mut plugin_execution_ns,
                        &original_request_path,
                    )
                    .await;
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        rejection.http_status,
                        rejection.body.clone(),
                        &rejection.headers,
                    )
                    .await?;
                    return Ok(());
                }
                Err(H3RequestBodyReadError::Read(error)) => {
                    halt_cancelled_h3_upload(&mut stream);
                    let status = StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST);
                    let _ = finalize_h3_terminal_body_read_rejection(
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        status,
                        Bytes::from_static(br#"{"error":"Client disconnected"}"#),
                        start_time,
                        &mut plugin_execution_ns,
                        &original_request_path,
                    )
                    .await;
                    return Err(error.into());
                }
                Err(H3RequestBodyReadError::TimedOut) => {
                    let rejection = finalize_h3_terminal_body_read_rejection(
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::REQUEST_TIMEOUT,
                        Bytes::from_static(br#"{"error":"Request body read timed out"}"#),
                        start_time,
                        &mut plugin_execution_ns,
                        &original_request_path,
                    )
                    .await;
                    send_h3_plugin_reject_flavor_aware_with_recv_halt(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        rejection.http_status,
                        rejection.body.clone(),
                        &rejection.headers,
                        false,
                    )
                    .await?;
                    return Ok(());
                }
                Err(H3RequestBodyReadError::DeadlineExceeded) => {
                    ctx.metadata.insert(
                        RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY.to_string(),
                        "true".to_string(),
                    );
                    finalize_h3_upload_deadline_rejection(
                        &mut stream,
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        start_time,
                        "grpc_deadline_terminal_h3_upload",
                        plugin_execution_ns,
                    )
                    .await?;
                    return Ok(());
                }
            };
        }

        let raw_request_body_bytes = body_data.len() as u64;
        prepared_raw_request_body_bytes = Some(raw_request_body_bytes);
        ctx.bytes_sent_observed
            .fetch_max(raw_request_body_bytes, std::sync::atomic::Ordering::Release);

        let mut hook_headers = proxy_headers.clone();
        hook_headers
            .entry(":method".to_string())
            .or_insert_with(|| method.clone());
        let terminal_hook_start = std::time::Instant::now();
        let grpc_deadline_at = ctx.grpc_deadline_at();
        let transformed = crate::proxy::apply_request_body_plugins_with_context(
            &plugins,
            Some(&mut ctx),
            grpc_deadline_at,
            &hook_headers,
            body_data,
        )
        .await;
        let final_body_result = crate::proxy::run_final_request_body_hooks(
            &plugins,
            Some(&mut ctx),
            grpc_deadline_at,
            &hook_headers,
            &transformed,
        )
        .await;
        plugin_execution_ns += terminal_hook_start.elapsed().as_nanos() as u64;
        match final_body_result {
            PluginResult::Continue => {
                prebuffered_body_data = Some(transformed);
                request_body_prepared = true;
            }
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(mut reject) = plugin_result_into_reject_parts(reject) else {
                    record_request(&state, 500);
                    let mut body = Bytes::from_static(b"Internal Server Error");
                    let mut headers = HashMap::new();
                    if crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire(
                        &ctx.method,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        &mut headers,
                        body.len(),
                    ) {
                        // HEAD/204/205/304: drop capacity, no DATA frame.
                        body = Bytes::new();
                    }
                    send_h3_reject_flavor_aware(
                        &mut stream,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        body,
                        &headers,
                        RejectBodyDisposition::for_request(
                            &ctx.method,
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        ),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                let rejection_hook_start = std::time::Instant::now();
                crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject.status_code,
                    &mut headers,
                    &mut reject.body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                let http_status =
                    StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_REQUEST);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject.body.clone(),
                    &headers,
                )
                .await;
                plugin_execution_ns += rejection_hook_start.elapsed().as_nanos() as u64;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject.body,
                    &headers,
                );
                record_request(&state, log_status_code);
                log_rejected_request_with_path(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "on_final_request_body",
                    plugin_execution_ns,
                    Some(&original_request_path),
                )
                .await;
                send_h3_reject_flavor_aware(
                    &mut stream,
                    http_flavor,
                    http_status,
                    reject.body.clone(),
                    &headers,
                    RejectBodyDisposition::for_request(&ctx.method, http_status.as_u16()),
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Finalized-request-egress boundary for HTTP/3 (GHSA-4vr5-4wm3-x5xv).
    //
    // A buffered H3 request always reaches the terminal-finalization block
    // above (a configured egress plugin forces `final_body_before_backend_
    // dispatch`), so `prebuffered_body_data` here is the transformed,
    // backend-visible body that every final request-policy hook has already
    // accepted. A request that never buffers has no transform and no final
    // policy hook, so its client representation is already final and the empty
    // slice is the faithful body view. Either way, no mirror, function, or
    // provider has been contacted before this point.
    if capabilities
        .has(crate::plugin_cache::PluginCapabilities::DISPATCHES_FINALIZED_REQUEST_EGRESS)
    {
        let phase_start = std::time::Instant::now();
        let egress_headers = proxy_headers.clone();
        let egress_body: &[u8] = prebuffered_body_data.as_deref().unwrap_or(&[]);
        let egress = crate::proxy::run_finalized_request_egress_hooks(
            &plugins,
            &mut ctx,
            &original_request_path,
            &egress_headers,
            egress_body,
        )
        .await;
        crate::proxy::apply_finalized_request_egress_header_overlay_in_map(
            &plugins,
            &ctx,
            &mut proxy_headers,
            egress.backend_header_overlay,
            &state.mesh_egress_strip_baggage_keys,
        );
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        match egress.result {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(mut reject) = plugin_result_into_reject_parts(reject) else {
                    record_request(&state, 500);
                    let mut body = Bytes::from_static(b"Internal Server Error");
                    let mut headers = HashMap::new();
                    if crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire(
                        &ctx.method,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        &mut headers,
                        body.len(),
                    ) {
                        // HEAD/204/205/304: drop capacity, no DATA frame.
                        body = Bytes::new();
                    }
                    send_h3_reject_flavor_aware(
                        &mut stream,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        body,
                        &headers,
                        RejectBodyDisposition::for_request(
                            &ctx.method,
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        ),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                let rejection_hook_start = std::time::Instant::now();
                crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject.status_code,
                    &mut headers,
                    &mut reject.body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                let http_status =
                    StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_REQUEST);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject.body.clone(),
                    &headers,
                )
                .await;
                plugin_execution_ns += rejection_hook_start.elapsed().as_nanos() as u64;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject.body,
                    &headers,
                );
                record_request(&state, log_status_code);
                log_rejected_request_with_path(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    crate::proxy::FINALIZED_REQUEST_EGRESS_PHASE,
                    plugin_execution_ns,
                    Some(&original_request_path),
                )
                .await;
                send_h3_reject_flavor_aware(
                    &mut stream,
                    http_flavor,
                    http_status,
                    reject.body.clone(),
                    &headers,
                    RejectBodyDisposition::for_request(&ctx.method, http_status.as_u16()),
                )
                .await?;
                return Ok(());
            }
        }
    }

    let backend_admission_plugins = plugin_cache_view.backend_admission_plugins();
    let mut backend_admission_permits: Option<BackendAdmissionPermitSet>;
    let mut preacquired_backend_admission = crate::proxy::PreacquiredBackendAdmission::default();
    let mut backend_admission_start: std::time::Instant;

    // H3 records the circuit-breaker outcome at header time (it does not defer the
    // dispatch outcome like the direct-H2 path), so the admission open-epoch is
    // unused here.
    let (cb_target_key, cb_is_half_open_probe, _cb_admission_open_epoch) =
        match crate::proxy::backend_dispatch::check_circuit_breaker(
            &proxy,
            &state,
            upstream_target.as_deref(),
        ) {
            Ok(result) => result,
            Err(()) => {
                let phase_start = std::time::Instant::now();
                let mut reject_status = 503;
                let mut reject_body = Bytes::from_static(
                    br#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#,
                );
                let mut rej_headers = HashMap::new();
                crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
                    &plugins,
                    &mut ctx,
                    &mut reject_status,
                    &mut reject_body,
                    &mut rej_headers,
                )
                .await;
                let mut reject_status =
                    StatusCode::from_u16(reject_status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                let deadline_replaced = run_h3_deadline_bounded_reject_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    reject_status,
                    reject_body.clone(),
                    &rej_headers,
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await;
                if deadline_replaced {
                    reject_status = replace_buffered_h3_response_with_grpc_deadline(
                        &mut ctx,
                        grpc_web_response_content_type,
                        &mut rej_headers,
                        &mut reject_body,
                        initial_response_header_policy_plugins.as_ref(),
                    );
                }
                let log_status_code = if deadline_replaced {
                    StatusCode::OK.as_u16()
                } else {
                    h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        reject_status,
                        &reject_body,
                        &rej_headers,
                    )
                };
                plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                record_request(&state, log_status_code);
                log_rejected_request(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "circuit_breaker",
                    plugin_execution_ns,
                )
                .await;
                if deadline_replaced && grpc_web_response_content_type.is_some() {
                    // gRPC-Web deadline frame: gateway-generated body written
                    // verbatim, so its length is authoritative.
                    send_h3_finalized_reject_response(
                        &mut stream,
                        StatusCode::OK,
                        reject_body.clone(),
                        &rej_headers,
                        RejectBodyDisposition::WireBody,
                    )
                    .await?;
                } else {
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        reject_status,
                        reject_body.clone(),
                        &rej_headers,
                    )
                    .await?;
                }
                return Ok(());
            }
        };

    // Preserve fail-fast breaker behavior for ordinary request-body plugins:
    // only drain/transform their H3 body after the selected target's breaker
    // admits it. Terminal provider dispatch above intentionally precedes that
    // backend-only gate. Every local failure below releases a HALF_OPEN probe
    // before writing the client response.
    let preparation_backend_host = upstream_target
        .as_deref()
        .map(|target| target.host.as_str())
        .unwrap_or(proxy.backend_host.as_str());
    let preparation_has_backend_tls_sni = reevaluate_response_policy_after_request_body
        && crate::proxy::resolve_backend_connection_proxy_for_target(
            &proxy,
            upstream_target.as_deref(),
        )
        .resolved_tls
        .sni
        .is_some();
    let preparation_blocked_by_dispatch_policy = preparation_has_backend_tls_sni
        || crate::proxy::denied_literal_backend_or_dns_override(
            preparation_backend_host,
            &proxy,
            &state.env_config.backend_allow_ips,
        )
        .is_some()
        || crate::proxy::backend_dispatch::direct_http_mesh_transport_refusal(
            upstream_target.as_deref(),
        )
        .is_some();
    if reevaluate_response_policy_after_request_body
        && !request_body_prepared
        && !preparation_blocked_by_dispatch_policy
    {
        if !backend_admission_plugins.is_empty() {
            let permits = match run_h3_backend_admission_or_send_reject(
                backend_admission_plugins.as_ref(),
                &plugins,
                &mut ctx,
                &proxy,
                upstream_target.as_deref(),
                http_flavor,
                grpc_web_response_content_type,
                initial_response_header_policy_plugins.as_ref(),
                &mut stream,
                &state,
                start_time,
                plugin_execution_ns,
                cb_target_key.as_deref(),
                cb_is_half_open_probe,
            )
            .await?
            {
                Ok(permits) => permits,
                Err(()) => return Ok(()),
            };
            preacquired_backend_admission =
                crate::proxy::PreacquiredBackendAdmission::acquired(permits);
        }
        let body_was_prebuffered = prebuffered_body_data.is_some();
        let mut body_data = prebuffered_body_data.take().unwrap_or_default();
        if !body_was_prebuffered {
            body_data = match collect_h3_request_body_with_deadline(
                drain_h3_request_body(&mut stream, content_length_limit),
                ctx.grpc_deadline_at(),
                proxy.backend_read_timeout_ms,
            )
            .await
            {
                Ok(Some(body_data)) => body_data,
                Ok(None) => {
                    release_h3_circuit_breaker_probe_on_admission_reject(
                        &state,
                        &proxy,
                        cb_target_key.as_deref(),
                        cb_is_half_open_probe,
                    );
                    drop(preacquired_backend_admission.take_if_acquired());
                    let metric_status = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        br#"{"error":"Request body exceeds maximum size"}"#,
                        &HashMap::new(),
                    );
                    record_request(&state, metric_status);
                    send_h3_error_flavor_aware_with_policy(
                        &mut stream,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                        crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                        "Request body exceeds maximum size",
                        initial_response_header_policy_plugins.as_ref(),
                    )
                    .await?;
                    return Ok(());
                }
                Err(H3RequestBodyReadError::Read(error)) => {
                    halt_cancelled_h3_upload(&mut stream);
                    release_h3_circuit_breaker_probe_on_admission_reject(
                        &state,
                        &proxy,
                        cb_target_key.as_deref(),
                        cb_is_half_open_probe,
                    );
                    return Err(error.into());
                }
                Err(H3RequestBodyReadError::DeadlineExceeded) => {
                    release_h3_circuit_breaker_probe_on_admission_reject(
                        &state,
                        &proxy,
                        cb_target_key.as_deref(),
                        cb_is_half_open_probe,
                    );
                    drop(preacquired_backend_admission.take_if_acquired());
                    finalize_h3_upload_deadline_rejection(
                        &mut stream,
                        &state,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        start_time,
                        "grpc_deadline_upload_before_dispatch",
                        plugin_execution_ns,
                    )
                    .await?;
                    return Ok(());
                }
                Err(timeout) => {
                    let (error_body, grpc_message) = h3_request_body_timeout_contract(&timeout);
                    release_h3_circuit_breaker_probe_on_admission_reject(
                        &state,
                        &proxy,
                        cb_target_key.as_deref(),
                        cb_is_half_open_probe,
                    );
                    // Admission capacity is no longer protecting backend work;
                    // release it before an awaited client write can stall.
                    drop(preacquired_backend_admission.take_if_acquired());
                    record_request(
                        &state,
                        if matches!(http_flavor, HttpFlavor::Grpc) {
                            StatusCode::OK.as_u16()
                        } else {
                            StatusCode::REQUEST_TIMEOUT.as_u16()
                        },
                    );
                    send_h3_error_flavor_aware_with_policy_and_recv_halt(
                        &mut stream,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::REQUEST_TIMEOUT,
                        error_body,
                        crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                        grpc_message,
                        initial_response_header_policy_plugins.as_ref(),
                        false,
                    )
                    .await?;
                    return Ok(());
                }
            };
        }
        let raw_request_body_bytes = body_data.len() as u64;
        prepared_raw_request_body_bytes = Some(raw_request_body_bytes);
        ctx.bytes_sent_observed
            .fetch_max(raw_request_body_bytes, std::sync::atomic::Ordering::Release);

        let mut hook_headers = proxy_headers.clone();
        hook_headers
            .entry(":method".to_string())
            .or_insert_with(|| method.clone());
        let grpc_deadline_at = ctx.grpc_deadline_at();
        let transformed = crate::proxy::apply_request_body_plugins_with_context(
            &plugins,
            Some(&mut ctx),
            grpc_deadline_at,
            &hook_headers,
            body_data,
        )
        .await;
        match crate::proxy::run_final_request_body_hooks(
            &plugins,
            Some(&mut ctx),
            grpc_deadline_at,
            &hook_headers,
            &transformed,
        )
        .await
        {
            PluginResult::Continue => {
                prebuffered_body_data = Some(transformed);
                request_body_prepared = true;
            }
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                release_h3_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                let Some(mut reject) = plugin_result_into_reject_parts(reject) else {
                    run_h3_reject_response_committed_hooks(
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        &mut ctx,
                        http_flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(&state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        &mut stream,
                        &plugins,
                        &mut ctx,
                        http_flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(());
                };
                let mut headers = reject.headers;
                crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
                    &plugins,
                    &mut ctx,
                    &mut reject.status_code,
                    &mut headers,
                    &mut reject.body,
                    matches!(http_flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                let http_status =
                    StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_REQUEST);
                run_h3_reject_response_committed_hooks(
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject.body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    http_status,
                    &reject.body,
                    &headers,
                );
                record_request(&state, log_status_code);
                log_rejected_request_with_path(
                    &plugins,
                    &ctx,
                    log_status_code,
                    start_time,
                    "on_final_request_body",
                    plugin_execution_ns,
                    Some(&original_request_path),
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    &mut stream,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject.body.clone(),
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Determine streaming vs buffered mode from the finalized request context.
    // This remains after selected-target retry capping and now also after the
    // fail-fast breaker admission above.
    let has_retry = match backend_http_flavor {
        HttpFlavor::Plain => {
            crate::retry::has_effective_http_retries(proxy.retry.as_ref(), &method)
        }
        HttpFlavor::Grpc => crate::retry::can_retry_connection_failures(proxy.retry.as_ref()),
        HttpFlavor::WebSocket => false,
    };
    let should_stream_response = crate::proxy::should_stream_response_body(
        &proxy,
        &plugins,
        &ctx,
        maybe_requires_response_body_buffering,
    );
    // Response-trailer governance, resolved once here and threaded into every
    // plain native/refined H3 STREAMING relay below. Those relays send initial
    // HEADERS before the backend's trailers exist, so the trailer frame is a
    // second crossing of the same response-header policy boundary the buffered
    // send path reconciles inline.
    //
    // The name/prefix unions are config-time, but the fail-closed `unbounded`
    // arm can be request-conditional (`waf` governs only the requests it
    // actually inspects, and `global_exemptions` can key on the authenticated
    // consumer). So it is resolved HERE — the same finalized-request-context
    // point `should_stream_response_body` above uses for
    // `requires_buffered_grpc_web_trailer_policy` — and deliberately not at
    // intake, before authentication could populate the identity it may depend
    // on. Every consumer of this value is below this line.
    let response_trailer_governance = ResponseTrailerGovernance {
        policy_names: plugin_cache_view.response_trailer_policy_names(),
        policy_prefixes: plugin_cache_view.response_trailer_policy_prefixes(),
        unbounded: plugin_cache_view.unbounded_response_trailer_policy_applies(&ctx),
    };
    // A recognized gRPC-Web request can intentionally retain Plain backend
    // transport when no translator is configured. Once deadline policy has
    // installed an absolute RPC deadline, buffer that pass-through upload so
    // cancellation in the plain bridge cannot strand its inlined reqwest body
    // pump while the bridge emits the terminal gRPC-Web status-4 frame.
    let deadline_bound_grpc_web_pass_through = grpc_web_response_content_type.is_some()
        && matches!(backend_http_flavor, HttpFlavor::Plain)
        && ctx.grpc_deadline_at().is_some();
    let needs_request_buffering =
        has_retry || plugin_needs_request_buffering || deadline_bound_grpc_web_pass_through;
    let needs_response_buffering = has_retry || !should_stream_response;
    let forces_reqwest_dispatch = stream_hooks_enabled
        && plugins
            .iter()
            .any(|plugin| plugin.forces_reqwest_dispatch(&ctx));
    let backend_supports_native_h3 =
        crate::proxy::supports_native_http3_backend(&state, &proxy, upstream_target.as_deref());
    let retry_response_needs_header_refinement =
        has_retry && crate::proxy::plugins_may_release_response_body_under_retries(&plugins, &ctx);
    let use_native_h3_pool = backend_http_flavor == HttpFlavor::Plain
        && !deadline_bound_grpc_web_pass_through
        && !forces_reqwest_dispatch
        && backend_supports_native_h3;

    let backend_url = build_h3_backend_url_for_flavor(
        &proxy,
        backend_http_flavor,
        &path,
        effective_query_string.as_ref(),
        strip_len,
        upstream_target.as_deref(),
    );
    let backend_start = std::time::Instant::now();
    let sticky_cookie_needed = selection.sticky_cookie_needed;

    // Resolve backend IP once from DNS cache (O(1) cached lookup) before dispatch.
    // Shared across all response paths for TransactionSummary logging.
    let effective_host = upstream_target
        .as_ref()
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);

    // Enforce the backend egress policy for a literal-IP H3 backend BEFORE any
    // dispatch. This sits ahead of the native-H3 / cross-protocol branch, both
    // of which skip the DnsCacheResolver for an IP literal — so without it an H3
    // client could still dial a denied literal (e.g. a DB row load only warned
    // about) that H1/H2 clients are already blocked from. Hostname backends are
    // screened by the resolver at dial time on every H3 dispatch path.
    if let Some(reason) = crate::proxy::denied_literal_backend_or_dns_override(
        effective_host,
        &proxy,
        &state.env_config.backend_allow_ips,
    ) {
        warn!(
            proxy_id = %proxy.id,
            backend = %effective_host,
            reason,
            "Backend egress policy denied literal-IP H3 backend; not dialing"
        );
        // Release any HALF_OPEN probe slot the circuit-breaker check above
        // admitted so the breaker doesn't wedge (mirrors the WS-origin reject).
        crate::http3::websocket::release_h3_ws_circuit_breaker_probe_on_admission_reject(
            &state,
            &proxy,
            cb_target_key.as_deref(),
            cb_is_half_open_probe,
        );
        // `send_h3_error_flavor_aware` emits a gRPC error as HTTP 200 + trailers
        // (gRPC errors ride 200), so the recorded request status must match the
        // wire — 200 for gRPC, 502 otherwise — to agree with the H1/H2 gRPC
        // egress reject path.
        let reject_metric_status = if matches!(http_flavor, HttpFlavor::Grpc) {
            200
        } else {
            502
        };
        record_request(&state, reject_metric_status);
        send_h3_error_flavor_aware_with_policy(
            &mut stream,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"backend address blocked by egress policy"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
            "backend address blocked by egress policy",
            initial_response_header_policy_plugins.as_ref(),
        )
        .await?;
        return Ok(());
    }

    let backend_resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    // Determine if we can stream the request body directly to the backend
    // without buffering into Vec<u8>. Conditions:
    //   1. No plugins need request body inspection/transformation
    //   2. No retries configured (can't replay a consumed stream)
    //   3. Body wasn't already prebuffered by an earlier plugin phase
    //   4. Streaming response path (buffered response path needs retries = needs buffered body)
    let can_stream_request_body =
        !needs_request_buffering && !needs_response_buffering && prebuffered_body_data.is_none();

    // Native H3 gRPC dispatch: a gRPC request whose concrete backend is proven
    // H3-capable, whose body can stream (no retry/body-plugin buffering, nothing
    // prebuffered), and which is not forced onto the reqwest path is sent over
    // the native H3 backend pool instead of the H2-only gRPC pool. This is the
    // ONLY path that can reach an H3-only gRPC backend (the H2 gRPC pool speaks
    // h2/h2c, never QUIC); every other gRPC case still falls through the
    // cross-protocol bridge to the H2 gRPC pool — see `dispatch_grpc_native_h3`.
    let use_native_h3_grpc = backend_http_flavor == HttpFlavor::Grpc
        && can_stream_request_body
        && !forces_reqwest_dispatch
        && backend_supports_native_h3;

    // Native-H3 pool branches (Plain + gRPC flavor, backend probed H3-capable)
    // are direct QUIC dials with no HBONE / mesh-mTLS / east-west path, so fail
    // closed on a mesh-transport-tagged target BEFORE either native branch can
    // open the H3 backend pool.
    let native_h3_direct_dispatch = use_native_h3_pool || use_native_h3_grpc;
    if native_h3_direct_dispatch
        && let Some(reason) = crate::proxy::backend_dispatch::direct_http_mesh_transport_refusal(
            upstream_target.as_deref(),
        )
    {
        warn!(
            proxy_id = %proxy.id,
            target_host = upstream_target.as_deref().map(|target| target.host.as_str()).unwrap_or(""),
            target_port = upstream_target.as_deref().map(|target| target.port).unwrap_or(0),
            reason,
            "native H3 dispatch: refusing direct dial to a mesh-transport-tagged target"
        );
        // Neutral to the breaker (releases a claimed HALF_OPEN probe slot) and
        // to passive health / latency — same recording as the H3 plain bridge's
        // refusal arm. No admission permits or LB connection start exist yet.
        crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
            &state,
            &proxy,
            &epoch.load_balancer,
            upstream_balancer.as_ref(),
            upstream_target.as_deref(),
            cb_target_key.as_deref(),
            502,
            false,
            Some(crate::retry::ErrorClass::DispatchPolicyRejected),
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        let mut reason_headers =
            HashMap::from([("gateway-error-reason".to_string(), reason.to_string())]);
        finalize_h3_gateway_error_headers(
            http_flavor,
            StatusCode::BAD_GATEWAY,
            MESH_DISPATCH_REQUIRED_REJECT_BODY,
            &mut reason_headers,
            initial_response_header_policy_plugins.as_ref(),
        );
        run_h3_reject_response_committed_hooks(
            &plugins,
            &mut ctx,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_GATEWAY,
            Bytes::from_static(MESH_DISPATCH_REQUIRED_REJECT_BODY),
            &reason_headers,
        )
        .await;
        let reject_metric_status = h3_reject_log_status_and_metadata(
            &mut ctx,
            http_flavor,
            StatusCode::BAD_GATEWAY,
            MESH_DISPATCH_REQUIRED_REJECT_BODY,
            &reason_headers,
        );
        record_request(&state, reject_metric_status);
        send_h3_plugin_reject_flavor_aware(
            &mut stream,
            &plugins,
            &mut ctx,
            http_flavor,
            grpc_web_response_content_type,
            StatusCode::BAD_GATEWAY,
            Bytes::from_static(MESH_DISPATCH_REQUIRED_REJECT_BODY),
            &reason_headers,
        )
        .await?;
        return Ok(());
    }

    // ========================================================================
    // Cross-protocol bridge: H3 client → non-H3 backend.
    //
    // The native H3 pool paths (the gRPC branch above and the Plain path below
    // this block) only fire when startup classification has already proved the
    // concrete backend target supports H3 AND the request can stream natively:
    // Plain via `use_native_h3_pool`, gRPC via `use_native_h3_grpc`
    // (`dispatch_grpc_native_h3`). Every other combination — HttpPool, HttpsPool
    // without proven H3 support, WebSocket, or gRPC that needs retry/body-plugin
    // buffering or forces reqwest — falls through the
    // `crate::http3::cross_protocol::run` bridge, which reuses the same reqwest /
    // HTTP/2 / gRPC backend infrastructure the H1/H2 proxy path uses. Response
    // bodies are streamed with the same coalescing window (`http3_coalesce_*` env
    // vars) so QUIC frame cadence is identical across paths. See
    // `src/http3/cross_protocol.rs` for the buffering policy (request buffered,
    // response streamed) and why that matches the rest of the codebase's two-tier
    // buffering logic. A non-H3-capable gRPC backend (h2/h2c only) still routes
    // through this bridge to the H2 gRPC pool.
    // RFC 9220: HTTP/3 Extended CONNECT for WebSocket. The request was
    // classified as `HttpFlavor::WebSocket` by `detect_http_flavor` (which
    // accepts both H2 and H3 Extended CONNECT). Dispatch into the
    // dedicated H3 WebSocket bridge: it takes ownership of the QUIC
    // stream so it can `.split()` into independent send/recv halves
    // for full-duplex frame relay. Plugin pipeline (authn / authz /
    // before_proxy) has already run by this point — same contract as
    // the H1/H2 path's `handle_websocket_request_authenticated`.
    //
    // When `FERRUM_HTTP3_WEBSOCKET_ENABLED=false` the H3 server's
    // `enable_extended_connect(false)` setting prevents most clients
    // from reaching this branch, but the dedicated handler also emits
    // a 501 itself as defense in depth.
    if http_flavor == HttpFlavor::WebSocket {
        // CSWSH protection (RFC 6455 §10.2): reject WS upgrades from
        // origins not on the allow-list BEFORE dispatching into the
        // bridge. Mirrors the H1/H2 check in
        // `src/proxy/mod.rs::handle_proxy_request_inner`; without this,
        // any proxy relying on `allowed_ws_origins` can be bypassed via
        // HTTP/3. `proxy_headers` keys were already lowercased by the
        // H3 header-materialization path.
        if !proxy.allowed_ws_origins.is_empty() {
            let origin = proxy_headers
                .get("origin")
                .map(String::as_str)
                .unwrap_or("");
            if !crate::proxy::websocket_origin_allowed(&proxy.allowed_ws_origins, origin) {
                warn!(
                    "H3 WebSocket upgrade rejected: Origin '{}' not in allowed_ws_origins for proxy {}",
                    origin, proxy.id
                );
                record_request(&state, 403);
                // Gateway-side reject after the CB check above — release a
                // claimed HALF_OPEN probe slot so the breaker doesn't wedge.
                crate::http3::websocket::release_h3_ws_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                crate::http3::websocket::send_h3_error_body(
                    &mut stream,
                    StatusCode::FORBIDDEN,
                    r#"{"error":"WebSocket Origin not allowed"}"#,
                    &initial_response_header_policy_plugins,
                )
                .await;
                return Ok(());
            }
        }

        let requires_websocket_framing = plugin_cache_view.requires_ws_frame_hooks();
        crate::proxy::apply_effective_backend_scheme_headers(
            &mut proxy_headers,
            &ctx.client_ip,
            ctx.request_is_secure,
            state.add_forwarded_header,
        );
        // Transfer request-side accounting to the H3 WebSocket bridge. The
        // bridge starts its long-lived `ConnectionGuard` before dropping this
        // `RequestGuard`, so backend handshakes stay visible to overload
        // pressure and graceful drain while the established session is not
        // double-counted as both a request and a connection. The per-IP
        // request guard is also transferred so the bridge can release the
        // per-IP request slot at the 200 boundary, matching how the H1/H2
        // path drops its `_per_ip_guard` when the upgrade response unwinds.
        return crate::http3::websocket::handle_h3_websocket(
            stream,
            state,
            request_guard,
            per_ip_guard,
            epoch,
            Arc::clone(&selected_base_proxy),
            ctx,
            plugins,
            initial_response_header_policy_plugins,
            backend_admission_plugins,
            plugin_execution_ns,
            upstream_target,
            upstream_balancer,
            lb_hash_key,
            sticky_cookie_needed,
            start_time,
            cb_target_key,
            cb_is_half_open_probe,
            backend_url,
            effective_query_string.to_string(),
            proxy_headers,
            requires_websocket_framing,
            is_early_data,
            strip_len,
            backend_path_is_policy_bound,
            original_request_path.clone(),
        )
        .await;
    }

    // Native H3 gRPC: stream the request and response directly over the QUIC
    // backend pool (the only transport that can reach an H3-only gRPC backend).
    // Gated above to the streamable, non-reqwest-forced, H3-capable case; all
    // other gRPC requests fall through to the cross-protocol H2 gRPC bridge.
    if use_native_h3_grpc {
        let grpc_client_ip = ctx.client_ip.clone();
        let grpc_is_early_data = ctx.is_early_data;
        return dispatch_grpc_native_h3(
            &state,
            &epoch,
            &proxy,
            &mut stream,
            &method,
            &proxy_headers,
            &backend_url,
            &original_request_path,
            upstream_target.as_deref(),
            upstream_balancer.as_ref(),
            cb_target_key.as_deref(),
            cb_is_half_open_probe,
            &grpc_client_ip,
            socket_ip,
            backend_resolved_ip.as_deref(),
            sticky_cookie_needed,
            grpc_is_early_data,
            backend_start,
            start_time,
            &mut ctx,
            &plugins,
            backend_admission_plugins.as_ref(),
            &mut plugin_execution_ns,
            initial_response_header_policy_plugins.as_ref(),
            response_trailer_governance,
        )
        .await;
    }

    if !use_native_h3_pool {
        // STREAMING-REQUEST gRPC bridge: H3 client → H2/h2c gRPC backend,
        // forwarding request DATA incrementally (true client-streaming / bidi)
        // instead of draining the full H3 body first. `can_stream_request_body`
        // already excludes retry, request/response body buffering, and
        // pre-buffered bodies — exactly the streaming-safe set — so the buffered
        // `cross_protocol::run` still handles every other gRPC case. Hands the
        // OWNED QUIC stream to the bridge so it can `.split()` into independent
        // send/recv halves for concurrent request-upload + response-stream.
        let stream_grpc_request =
            matches!(backend_http_flavor, HttpFlavor::Grpc) && can_stream_request_body;
        let outcome = if stream_grpc_request {
            let client_ip_owned = ctx.client_ip.clone();
            crate::http3::cross_protocol::dispatch_grpc_streaming(
                &state,
                &epoch,
                &selected_base_proxy,
                stream,
                &method,
                &proxy_headers,
                &backend_url,
                upstream_target.as_deref(),
                upstream_balancer.as_ref(),
                cb_target_key.as_deref(),
                cb_is_half_open_probe,
                &client_ip_owned,
                socket_ip,
                backend_start,
                &mut ctx,
                &plugins,
                initial_response_header_policy_plugins.as_ref(),
                backend_admission_plugins.as_ref(),
                sticky_cookie_needed,
                response_trailer_governance,
            )
            .await?
        } else {
            let prebuffered = if needs_request_buffering {
                let body_was_prebuffered = prebuffered_body_data.is_some();
                let mut body_data = prebuffered_body_data.take().unwrap_or_default();
                if !body_was_prebuffered {
                    body_data = match collect_h3_request_body_with_deadline(
                        drain_h3_request_body(&mut stream, content_length_limit),
                        ctx.grpc_deadline_at(),
                        proxy.backend_read_timeout_ms,
                    )
                    .await
                    {
                        Ok(Some(body_data)) => body_data,
                        Ok(None) => {
                            let metric_status = h3_reject_log_status_and_metadata(
                                &mut ctx,
                                http_flavor,
                                StatusCode::PAYLOAD_TOO_LARGE,
                                br#"{"error":"Request body exceeds maximum size"}"#,
                                &HashMap::new(),
                            );
                            record_request(&state, metric_status);
                            crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
                                &state,
                                &proxy,
                                &epoch.load_balancer,
                                upstream_balancer.as_ref(),
                                upstream_target.as_deref(),
                                cb_target_key.as_deref(),
                                413,
                                false,
                                Some(crate::retry::ErrorClass::ClientDisconnect),
                                cb_is_half_open_probe,
                                false,
                                backend_start.elapsed(),
                            );
                            send_h3_error_flavor_aware_with_policy(
                                &mut stream,
                                http_flavor,
                                grpc_web_response_content_type,
                                StatusCode::PAYLOAD_TOO_LARGE,
                                r#"{"error":"Request body exceeds maximum size"}"#,
                                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                                "Request body exceeds maximum size",
                                initial_response_header_policy_plugins.as_ref(),
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(H3RequestBodyReadError::Read(error)) => {
                            halt_cancelled_h3_upload(&mut stream);
                            // This path returns before cross_protocol::run can
                            // release an admitted HALF_OPEN probe.
                            crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
                                &state,
                                &proxy,
                                &epoch.load_balancer,
                                upstream_balancer.as_ref(),
                                upstream_target.as_deref(),
                                cb_target_key.as_deref(),
                                0,
                                false,
                                Some(crate::retry::ErrorClass::ClientDisconnect),
                                cb_is_half_open_probe,
                                false,
                                backend_start.elapsed(),
                            );
                            return Err(error.into());
                        }
                        Err(H3RequestBodyReadError::DeadlineExceeded) => {
                            crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
                                &state,
                                &proxy,
                                &epoch.load_balancer,
                                upstream_balancer.as_ref(),
                                upstream_target.as_deref(),
                                cb_target_key.as_deref(),
                                StatusCode::REQUEST_TIMEOUT.as_u16(),
                                false,
                                Some(crate::retry::ErrorClass::ClientDisconnect),
                                cb_is_half_open_probe,
                                false,
                                backend_start.elapsed(),
                            );
                            finalize_h3_upload_deadline_rejection(
                                &mut stream,
                                &state,
                                &plugins,
                                &mut ctx,
                                http_flavor,
                                grpc_web_response_content_type,
                                start_time,
                                "grpc_deadline_upload_before_cross_protocol_dispatch",
                                plugin_execution_ns,
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(timeout) => {
                            let (error_body, grpc_message) =
                                h3_request_body_timeout_contract(&timeout);
                            crate::proxy::backend_dispatch::record_backend_outcome_no_conn_end(
                                &state,
                                &proxy,
                                &epoch.load_balancer,
                                upstream_balancer.as_ref(),
                                upstream_target.as_deref(),
                                cb_target_key.as_deref(),
                                StatusCode::REQUEST_TIMEOUT.as_u16(),
                                false,
                                Some(crate::retry::ErrorClass::ClientDisconnect),
                                cb_is_half_open_probe,
                                false,
                                backend_start.elapsed(),
                            );
                            record_request(
                                &state,
                                if matches!(http_flavor, HttpFlavor::Grpc) {
                                    StatusCode::OK.as_u16()
                                } else {
                                    StatusCode::REQUEST_TIMEOUT.as_u16()
                                },
                            );
                            send_h3_error_flavor_aware_with_policy_and_recv_halt(
                                &mut stream,
                                http_flavor,
                                grpc_web_response_content_type,
                                StatusCode::REQUEST_TIMEOUT,
                                error_body,
                                crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                                grpc_message,
                                initial_response_header_policy_plugins.as_ref(),
                                false,
                            )
                            .await?;
                            return Ok(());
                        }
                    };
                }
                Some(body_data)
            } else {
                prebuffered_body_data.take()
            };
            // Pass the pre-resolved plugin list + mutable context so the
            // bridge can run the same after_proxy / on_final_request_body /
            // on_response_body / on_final_response_body / sticky-cookie
            // pipeline as the native H3 path. Without these, H3 clients on
            // non-H3 backends silently skip the response-transform /
            // body-validator / sticky-session phases.
            let client_ip_owned = ctx.client_ip.clone();
            let initial_response_header_policy_names =
                plugin_cache_view.initial_response_header_policy_names();
            crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest {
                state: &state,
                epoch: &epoch,
                // Only Plain and Grpc flavors reach this bridge (WebSocket
                // returned via its dedicated bridge above), and both resolve
                // the per-target effective proxy per attempt inside their own
                // dispatch loops — so hand them the retry-capped but otherwise
                // UNRESOLVED base proxy. Passing the first target's effective
                // proxy would bake its port-level TLS/SNI/H1 policy into every
                // retry attempt.
                proxy: selected_base_proxy.as_ref(),
                stream: &mut stream,
                method: &method,
                proxy_headers: &proxy_headers,
                path: &path,
                query_string: effective_query_string.as_ref(),
                backend_url: &backend_url,
                strip_len,
                backend_path_is_policy_bound,
                lb_hash_key: lb_hash_key.as_deref(),
                upstream_target: upstream_target.as_deref(),
                upstream_balancer: upstream_balancer.as_ref(),
                cb_target_key: cb_target_key.as_deref(),
                cb_is_half_open_probe,
                flavor: backend_http_flavor,
                prebuffered_body: prebuffered,
                request_body_prepared,
                raw_prebuffered_body_bytes: prepared_raw_request_body_bytes,
                client_ip: &client_ip_owned,
                xff_append_ip: socket_ip,
                ctx: &mut ctx,
                plugins: &plugins,
                initial_response_header_policy_plugins: Arc::clone(
                    &initial_response_header_policy_plugins,
                ),
                initial_response_header_policy_names,
                backend_admission_plugins: backend_admission_plugins.as_ref(),
                preacquired_backend_admission,
                requires_response_body_buffering: maybe_requires_response_body_buffering,
                response_committed_plugins: plugin_cache_view.response_committed_plugins(),
                requires_response_stream_hooks: stream_hooks_enabled,
                sticky_cookie_needed,
                response_trailer_governance,
            })
            .await?
        };

        record_request(&state, outcome.response_status);

        // Build the same TransactionSummary shape the native H3 pool path
        // emits so log plugins see a consistent record across dispatch
        // kinds. Streamed responses use the shared unknown-backend-total
        // contract: concurrent backend-body / client-delivery lifetime must
        // not be labeled as gateway work.
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let backend_ttfb_ms = outcome.backend_ttfb_ms;
        let backend_total_ms = if outcome.response_streamed {
            crate::plugins::LATENCY_UNKNOWN_MS
        } else {
            outcome.backend_total_ms
        };
        let (gateway_processing_ms, gateway_overhead_ms) =
            TransactionSummary::derive_gateway_latencies(
                total_ms,
                backend_total_ms,
                plugin_execution_ms,
                outcome.response_streamed,
            );
        if outcome.response_streamed {
            let stream_outcome = BodyOutcome {
                body_completed: outcome.body_completed,
                body_error_class: outcome.body_error_class,
                bytes_streamed: outcome.bytes_streamed,
                client_disconnected: outcome.client_disconnected,
                grpc_status: None,
            };
            run_response_stream_termination_hooks(
                &plugins,
                &mut ctx,
                outcome.response_status,
                &stream_outcome,
            )
            .await;
        }
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            auth_method: ctx.auth_method,
            http_method: method.to_string(),
            request_path: original_request_path.clone(),
            proxy_id: Some(proxy.id.clone()),
            proxy_name: proxy.name.clone(),
            backend_target: outcome
                .backend_target
                .clone()
                .or_else(|| Some(strip_query_params(&backend_url).to_string())),
            backend_resolved_ip: outcome
                .backend_resolved_ip
                .clone()
                .or_else(|| backend_resolved_ip.clone()),
            response_status_code: outcome.response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: outcome.response_streamed,
            client_disconnected: outcome.client_disconnected,
            body_error_class: outcome.body_error_class,
            body_completed: outcome.body_completed,
            bytes_sent: outcome.bytes_sent,
            bytes_received: outcome.bytes_streamed,
            error_class: outcome.error_class,
            mirror: false,
            metadata: crate::proxy::clone_log_metadata(&ctx),
            ai_usage_export: ctx.ai_usage_export.clone(),
            proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
        };
        if !outcome.rejection_logged {
            crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
        }

        return Ok(());
    }

    if can_stream_request_body {
        // ===== STREAMING REQUEST + RESPONSE PATH =====
        // Stream both the request body (frontend → backend) and response body
        // (backend → frontend) without buffering either into memory.

        backend_admission_start = std::time::Instant::now();
        backend_admission_permits = match run_h3_backend_admission_or_send_reject(
            backend_admission_plugins.as_ref(),
            &plugins,
            &mut ctx,
            &proxy,
            upstream_target.as_deref(),
            http_flavor,
            grpc_web_response_content_type,
            initial_response_header_policy_plugins.as_ref(),
            &mut stream,
            &state,
            start_time,
            plugin_execution_ns,
            cb_target_key.as_deref(),
            cb_is_half_open_probe,
        )
        .await?
        {
            Ok(permits) => permits,
            // Probe release happens inside the helper, before the reject write.
            Err(()) => return Ok(()),
        };

        // Track connection for least-connections LB (after all pre-dispatch rejects)
        if let (Some(_upstream_id), Some(target), Some(balancer)) = (
            &proxy.upstream_id,
            &upstream_target,
            upstream_balancer.as_ref(),
        ) {
            balancer.record_connection_start(target);
        }

        let client_ip_owned = ctx.client_ip.clone();
        let h3_headers = build_h3_backend_headers(
            &proxy,
            upstream_target.as_deref(),
            &proxy_headers,
            &client_ip_owned,
            socket_ip,
            &state,
            ctx.request_is_secure,
            ctx.is_early_data,
        );
        let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(&proxy);
        let request_body_bytes_seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // The plain native H3 path awaits dispatch directly (no outer `timeout_at`
        // wrapper), so it classifies pre-/post-wire from the returned
        // `H3PoolError::request_on_wire()` and does not consult this flag — unlike the
        // gRPC dispatch, which reads it on deadline expiry. Pass local throwaways to
        // satisfy the shared signature.
        let request_stream_opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let request_upload_complete = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let streaming_resp = if let Some(target) = upstream_target.as_deref() {
            state
                .h3_pool
                .request_with_target_streaming_body(
                    &proxy,
                    &target.host,
                    target.port,
                    &method,
                    &backend_url,
                    &h3_headers,
                    &mut stream,
                    effective_max_request_body_size_bytes,
                    Arc::clone(&request_body_bytes_seen),
                    proxy.backend_read_timeout_ms,
                    Arc::clone(&request_stream_opened),
                    Arc::clone(&request_upload_complete),
                    tls_config_fn,
                )
                .await
        } else {
            state
                .h3_pool
                .request_streaming_body(
                    &proxy,
                    &method,
                    &backend_url,
                    &h3_headers,
                    &mut stream,
                    effective_max_request_body_size_bytes,
                    Arc::clone(&request_body_bytes_seen),
                    proxy.backend_read_timeout_ms,
                    Arc::clone(&request_stream_opened),
                    Arc::clone(&request_upload_complete),
                    tls_config_fn,
                )
                .await
        };

        let mut h3_resp = match streaming_resp {
            Ok(r) => r,
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("exceeds maximum size") {
                    record_request(&state, 413);
                    // Do NOT propagate a send error: record_backend_outcome
                    // below releases the LB active-connection count, so a `?`
                    // here would skip it and leak the count when the client
                    // disconnects during the 413 write.
                    let _ = send_h3_response(
                        &mut stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                    )
                    .await;
                    // Balance the record_connection_start above: this early
                    // return was the only exit from this branch that did not
                    // flow through record_backend_outcome, so the
                    // least-connections gauge leaked one count for the selected
                    // target on every oversized streaming upload. An oversized
                    // client body is client-caused, which drives the two flags
                    // below:
                    //   * connection_error=false — accurate: no transport error
                    //     occurred; we chose to emit a 413 for a too-large body.
                    //     The ClientDisconnect class centrally suppresses the
                    //     least-latency TTFB sample (a synthetic 413 reflects no
                    //     real backend latency) AND the passive-health report (no
                    //     phantom <500 success that would reset failure tracking
                    //     and re-admit an unhealthy target, and no failure even if
                    //     413 sat in unhealthy_status_codes), so we no longer need
                    //     connection_error=true to force that suppression — the
                    //     class does it more accurately.
                    //   * skip_circuit_breaker_record=false — release any
                    //     half-open probe slot via the state-neutral
                    //     record_neutral() (ErrorClass::ClientDisconnect takes
                    //     that arm before connection_error is considered, so the
                    //     breaker is never tripped) instead of leaking the slot
                    //     and permanently wedging the breaker. Mirrors the
                    //     sibling 502 / oversized-response / after_proxy-reject
                    //     early returns below.
                    crate::proxy::backend_dispatch::record_backend_outcome(
                        &state,
                        &proxy,
                        &epoch.load_balancer,
                        upstream_balancer.as_ref(),
                        upstream_target.as_deref(),
                        cb_target_key.as_deref(),
                        413,
                        false,
                        Some(crate::retry::ErrorClass::ClientDisconnect),
                        cb_is_half_open_probe,
                        false,
                        backend_start.elapsed(),
                    );
                    record_h3_backend_admission_outcome(
                        &mut backend_admission_permits,
                        413,
                        false,
                        Some(crate::retry::ErrorClass::ClientDisconnect),
                        backend_admission_start.elapsed(),
                    );
                    return Ok(());
                }
                error!("Backend request failed (HTTP/3 streaming body): {}", e);
                let h3_error_class = classify_h3_error(&e);
                crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
                let is_client_request_body_disconnect =
                    is_h3_client_request_body_disconnect(&err_msg);
                // H3 frontend → H3 backend path: QUIC failure here means the
                // cached H3 capability lied (backend probably lost UDP), so
                // downgrade the classification. The next H3 request is free
                // to retry — by then `supports_native_http3_backend` returns
                // false and the cross-protocol bridge handles it.
                if !is_client_request_body_disconnect
                    && crate::proxy::is_h3_transport_error_class(h3_error_class)
                {
                    state
                        .backend_capabilities
                        .mark_h3_unsupported(&proxy, upstream_target.as_deref());
                }
                // A malformed client request-trailer block is a bad CLIENT request,
                // not backend unavailability — surface 400 so the client does not
                // retry it as a server outage. Read timeouts surface as 504 Backend
                // timeout (matching the direct-H2 / HBONE read-timeout arms);
                // everything else keeps the generic 502.
                let (reject_status, reject_body) =
                    if err_msg.contains("malformed client request trailers") {
                        (
                            StatusCode::BAD_REQUEST,
                            r#"{"error":"Malformed request trailers"}"#,
                        )
                    } else {
                        h3_backend_failure_status_body(&e)
                    };
                let reject_status_code = reject_status.as_u16();
                // Do NOT propagate a send error: record_backend_outcome below
                // releases the LB active-connection count, so a `?` here would
                // skip it and leak the count when the client disconnects during
                // the reject write.
                let _ = send_h3_response(&mut stream, reject_status, reject_body).await;

                // Record outcome for CB/health even on failure.
                // Frontend client aborts while uploading request bodies are
                // client-caused and must not poison backend CB/passive health:
                // h3_streaming_body_failure_outcome maps that case to
                // (connection_error=false, ClientDisconnect), and the
                // ClientDisconnect class is centrally suppressed in
                // record_backend_outcome_inner — it routes the breaker to
                // record_neutral() and skips both the least-latency sample and
                // the passive-health report (so this 502 no longer records a
                // passive failure even when 502 sits in unhealthy_status_codes).
                let (outcome_connection_error, outcome_error_class) =
                    h3_streaming_body_failure_outcome(
                        is_client_request_body_disconnect,
                        e.is_read_timeout(),
                        h3_error_class,
                    );
                crate::proxy::backend_dispatch::record_backend_outcome(
                    &state,
                    &proxy,
                    &epoch.load_balancer,
                    upstream_balancer.as_ref(),
                    upstream_target.as_deref(),
                    cb_target_key.as_deref(),
                    reject_status_code,
                    outcome_connection_error,
                    outcome_error_class,
                    cb_is_half_open_probe,
                    false,
                    backend_start.elapsed(),
                );
                record_h3_backend_admission_outcome(
                    &mut backend_admission_permits,
                    reject_status_code,
                    outcome_connection_error,
                    outcome_error_class,
                    backend_admission_start.elapsed(),
                );

                let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
                let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
                let plugin_external_io_ms =
                    ctx.plugin_http_call_ns
                        .load(std::sync::atomic::Ordering::Relaxed) as f64
                        / 1_000_000.0;

                let gateway_processing_ms = total_ms - backend_total_ms;
                let summary = TransactionSummary {
                    namespace: proxy.namespace.clone(),
                    timestamp_received: ctx.timestamp_received.to_rfc3339(),
                    client_ip: ctx.client_ip.clone(),
                    consumer_username: ctx.effective_identity().map(str::to_owned),
                    auth_method: ctx.auth_method,
                    http_method: method.to_string(),
                    request_path: original_request_path.clone(),
                    proxy_id: Some(proxy.id.clone()),
                    proxy_name: proxy.name.clone(),
                    backend_target: Some(strip_query_params(&backend_url).to_string()),
                    backend_resolved_ip: backend_resolved_ip.clone(),
                    response_status_code: reject_status_code,
                    latency_total_ms: total_ms,
                    latency_gateway_processing_ms: gateway_processing_ms,
                    latency_backend_ttfb_ms: backend_total_ms,
                    latency_backend_total_ms: backend_total_ms,
                    latency_plugin_execution_ms: plugin_execution_ms,
                    latency_plugin_external_io_ms: plugin_external_io_ms,
                    latency_gateway_overhead_ms: (gateway_processing_ms - plugin_execution_ms)
                        .max(0.0),
                    request_user_agent: proxy_headers.get("user-agent").cloned(),
                    // Native H3 backend dispatch failed; the reject response
                    // body (502 generic, 504 for a backend read timeout) is
                    // built and sent synchronously above. This branch covers
                    // both pre-wire failures (connect/handshake — zero request
                    // bytes forwarded) and post-wire failures (send_data failed
                    // mid-stream, recv_response read timeout, or the client
                    // disconnected while sending the request body), where
                    // request_body_bytes_seen is non-zero. Loading it here
                    // reports the bytes actually forwarded before the failure
                    // rather than assuming zero.
                    error_class: Some(h3_error_class),
                    bytes_sent: request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
                    metadata: crate::proxy::clone_log_metadata(&ctx),
                    ai_usage_export: ctx.ai_usage_export.clone(),
                    proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
                    ..TransactionSummary::default()
                };
                crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                record_request(&state, reject_status_code);
                return Ok(());
            }
        };

        let backend_admission_response_elapsed = backend_admission_start.elapsed();
        let response_status = h3_resp.status;
        let mut response_headers = h3_resp.headers;

        // Hop-by-hop headers already filtered during collection in the H3 pool.

        // Capture original response invariants before `after_proxy` runs on this
        // default native-H3 streaming path; `compression.after_proxy` honors the
        // marker so a streamed body is never mislabeled if a transformer strips
        // `Content-Range` or `Cache-Control` first.
        stamp_h3_original_response_metadata(&mut ctx, response_status, &response_headers);

        // Enforce response body size limit via Content-Length fast path
        if let Some(len) = crate::proxy::declared_response_length_exceeds_limit(
            &response_headers,
            effective_max_response_body_size_bytes,
        ) {
            warn!(
                proxy_id = %proxy.id,
                response_body_bytes = len,
                max_response_body_size_bytes = effective_max_response_body_size_bytes,
                "HTTP/3 backend response body exceeds configured size limit"
            );
            // Do NOT propagate a send error: record_backend_outcome below
            // releases the LB active-connection count, so a `?` here would skip
            // it and leak the count when the client disconnects during the
            // reject write.
            let _ = send_h3_response(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Backend response body exceeds maximum size"}"#,
            )
            .await;

            crate::proxy::backend_dispatch::record_backend_outcome(
                &state,
                &proxy,
                &epoch.load_balancer,
                upstream_balancer.as_ref(),
                upstream_target.as_deref(),
                cb_target_key.as_deref(),
                // The backend did respond (headers received) before we found
                // the body too large; CB/passive-health must see the real
                // backend status, not the gateway-synthesized 502. Mirrors the
                // buffered/streamed-response path in
                // `proxy_to_backend_h3_streaming` so the same scenario can't
                // penalize the backend on one native-H3 path but not the other.
                response_status,
                false,
                None,
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            // Unlike the circuit-breaker/passive-health record above (which sees
            // the real backend status), the adaptive-concurrency sample must
            // treat an oversized backend response as a failure: the gateway
            // sends a 502 and the low-latency 2xx/4xx status would otherwise be
            // counted as a fast success and grow the limit. Mirrors the reqwest
            // path, which tags the admission outcome `ResponseBodyTooLarge`.
            record_h3_backend_admission_outcome(
                &mut backend_admission_permits,
                response_status,
                false,
                Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                backend_admission_response_elapsed,
            );
            record_request(&state, 502);
            return Ok(());
        }

        // Retain the backend's pre-policy response headers before the first
        // response-header phase can rewrite them, so the trailer frame at the
        // end of this relay can still tell a policy mutation from an untouched
        // backend field. One clone per streaming RESPONSE, skipped entirely
        // when no response-header phase can run or when the chain already fails
        // closed; never touched per body frame.
        //
        // The default `content-type` this relay synthesizes below is a
        // gateway-authored wire mutation just like a plugin write, so it counts
        // as a header phase for the capture decision. Without it an
        // auth/logging-only chain would keep the no-clone #2941 pass-through
        // AND forward a backend `content-type` TRAILER that contradicts the
        // media type the gateway itself put on the wire. Costs one map lookup
        // and retains evidence only when the backend actually omitted the field.
        let gateway_synthesizes_content_type = !response_headers.contains_key("content-type");
        let pre_policy_response_headers = PrePolicyResponseHeaders::capture_for_streaming(
            &response_headers,
            response_trailer_governance,
            !plugins.is_empty() || sticky_cookie_needed || gateway_synthesizes_content_type,
        );

        // after_proxy hooks run before streaming begins so headers can be
        // modified or the response rejected before any downstream bytes are
        // committed. A reject here (e.g. a WAF response-header-inspection
        // reject, which does not buffer the body) MUST be honored on this
        // native-H3 streaming path exactly as on the buffered/H1/H2 paths —
        // this is the default native-H3 path, so discarding the reject would
        // silently bypass response-policy plugins for the common case.
        if let Some(reject) = run_h3_streaming_after_proxy_hooks(
            &plugins,
            &mut ctx,
            response_status,
            &mut response_headers,
            &mut plugin_execution_ns,
        )
        .await
        {
            let reject_status =
                StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
            // Cheap `Bytes` handle clone: the reject payload keeps its shared
            // allocation identity (no copy) while `reject.body` stays live for
            // the byte accounting below.
            let reject_body = reject.body.clone();
            let reject_sent = send_h3_reject_response(
                &mut stream,
                reject_status,
                reject_body,
                &reject.headers,
                RejectBodyDisposition::for_request(&ctx.method, reject_status.as_u16()),
            )
            .await
            .is_ok();

            // CB / passive-health must see the TRUE backend status: the plugin
            // override is a gateway policy decision and must neither penalize a
            // healthy backend nor mask a real backend failure.
            crate::proxy::backend_dispatch::record_backend_outcome(
                &state,
                &proxy,
                &epoch.load_balancer,
                upstream_balancer.as_ref(),
                upstream_target.as_deref(),
                cb_target_key.as_deref(),
                response_status,
                false,
                None,
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            record_h3_backend_admission_outcome(
                &mut backend_admission_permits,
                response_status,
                false,
                None,
                backend_admission_response_elapsed,
            );

            let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
            let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
            let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
            let plugin_external_io_ms =
                ctx.plugin_http_call_ns
                    .load(std::sync::atomic::Ordering::Relaxed) as f64
                    / 1_000_000.0;
            let gateway_processing_ms = total_ms - backend_total_ms;
            let gateway_overhead_ms = (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);

            let summary = TransactionSummary {
                namespace: proxy.namespace.clone(),
                timestamp_received: ctx.timestamp_received.to_rfc3339(),
                client_ip: ctx.client_ip.clone(),
                consumer_username: ctx.effective_identity().map(str::to_owned),
                auth_method: ctx.auth_method,
                http_method: method.to_string(),
                request_path: path.clone(),
                proxy_id: Some(proxy.id.clone()),
                proxy_name: proxy.name.clone(),
                backend_target: Some(strip_query_params(&backend_url).to_string()),
                backend_resolved_ip: backend_resolved_ip.clone(),
                // Client-facing status is the plugin's reject status, not the
                // backend's (which CB/health recorded above).
                response_status_code: reject.status_code,
                latency_total_ms: total_ms,
                latency_gateway_processing_ms: gateway_processing_ms,
                latency_backend_ttfb_ms: backend_total_ms,
                latency_backend_total_ms: backend_total_ms,
                latency_plugin_execution_ms: plugin_execution_ms,
                latency_plugin_external_io_ms: plugin_external_io_ms,
                latency_gateway_overhead_ms: gateway_overhead_ms,
                request_user_agent: proxy_headers.get("user-agent").cloned(),
                response_streamed: true,
                client_disconnected: !reject_sent,
                error_class: None,
                body_error_class: None,
                body_completed: reject_sent,
                bytes_sent: 0,
                bytes_received: if reject_sent {
                    reject.body.len() as u64
                } else {
                    0
                },
                mirror: false,
                metadata: crate::proxy::clone_log_metadata(&ctx),
                ai_usage_export: ctx.ai_usage_export.clone(),
                proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
            };
            crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
            record_request(&state, reject.status_code);
            return Ok(());
        }

        // Sticky session cookie injection
        inject_sticky_cookie(
            &epoch,
            &proxy,
            upstream_target.as_deref(),
            sticky_cookie_needed,
            &mut response_headers,
        );

        // Streaming response inspection (e.g. ai_semantic_firewall `inspect` mode):
        // if a plugin opts in for this event-stream response it returns a stateful
        // inspector the loop drives chunk-by-chunk (Forward releases bytes,
        // Terminate cuts). Computed BEFORE the headers are sent so Content-Length
        // can be stripped — the inspector transforms the body, so the backend's
        // length no longer applies and would make a cut look like a truncated body.
        // Gated once per response; the common case (no opt-in) skips it entirely.
        let mut response_inspector = if stream_hooks_enabled {
            let content_type = response_headers.get("content-type").map(String::as_str);
            crate::plugins::create_response_stream_inspector_for_enabled_plugins(
                &plugins,
                &mut ctx,
                response_status,
                content_type,
            )
        } else {
            None
        };
        // Capture the backend's declared length BEFORE stripping it for the
        // client — the graceful-close recovery below still needs it to tell a
        // complete body from a truncated one (an inspected response strips
        // Content-Length because the inspector transforms the body).
        let declared_content_length =
            preserved_response_content_length(&response_headers, response_status);
        if response_inspector.is_some() {
            // Ordinary Streaming framing removes the wire field anyway; this
            // case-insensitive omit additionally covers `HEAD`, where `Head`
            // framing would otherwise preserve a representation length the
            // inspector has invalidated.
            remove_content_length_header(&mut response_headers);
        }

        // Final protocol-aware strip after after_proxy: plugins must not
        // reintroduce connection-specific or framing fields onto the H3 wire
        // (RFC 9114 §4.2). Ordinary streaming framing removes Content-Length —
        // nothing here can verify a hook-authored value against the DATA frames
        // still to be written; only HEAD keeps a valid representation length.
        // The internal completeness check below uses `declared_content_length`,
        // captured above.
        sanitize_client_response_headers_for_wire(
            &mut response_headers,
            ClientResponseFraming::for_streaming_response(&ctx.method, response_status),
        );

        // Send response headers on the H3 stream.
        //
        // The default `content-type` is a real gateway mutation of the response
        // header set, so it is written into `response_headers` BEFORE the
        // builder rather than onto the builder alone. That keeps the map the
        // trailer boundary later treats as "the final headers" identical to the
        // field set the client actually received; otherwise a backend
        // `content-type` TRAILER would reconcile absent->absent and land on the
        // wire contradicting a header the gateway itself synthesized. The
        // lookup stays case-sensitive on the already-lowercased H3 header map,
        // exactly as the previous builder-side check was.
        response_headers
            .entry("content-type".to_string())
            .or_insert_with(|| "application/json".to_string());
        let status_code = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
        let resp_builder =
            apply_response_headers(Response::builder().status(status_code), &response_headers);
        let resp = resp_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
        // Do NOT `?`-propagate a send_response failure: `record_connection_start`
        // already ran above, so bailing out here would leak the least-connections
        // count, a CB HALF_OPEN probe slot, the admission outcome, and the
        // transaction summary (the same client-disconnect case the sibling
        // relays in `proxy_to_backend_h3_streaming` /
        // `stream_h3_open_response_to_client` handle explicitly). Fall through
        // to the outcome-recording block below instead.
        let mut client_disconnected = false;
        let mut body_error_class: Option<crate::retry::ErrorClass> = None;
        if let Err(e) = stream.send_response(resp).await {
            debug!(
                "HTTP/3 client disconnected before streaming response headers: {}",
                e
            );
            client_disconnected = true;
            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
        }

        // Stream response body from backend h3 recv_stream to frontend h3 stream.
        // Uses a pinned Sleep that is reset in-place to avoid allocating a new
        // timer wheel entry on every select! iteration. `response_inspector` was
        // resolved above (before the headers were sent).
        let coalesce_min_bytes = state.env_config.http3_coalesce_min_bytes;
        let coalesce_max_bytes = state.env_config.http3_coalesce_max_bytes;
        let flush_interval =
            std::time::Duration::from_micros(state.env_config.http3_flush_interval_micros);
        let mut coalesce_buf = BytesMut::with_capacity(coalesce_max_bytes);
        let mut total_streamed: usize = 0;
        let flush_timer = tokio::time::sleep(flush_interval);
        tokio::pin!(flush_timer);
        // Per-frame backend read deadline: abort if the backend stalls for
        // `backend_read_timeout_ms` between response-body frames after the
        // headers were sent. Reset on each received frame; inert (the select!
        // arm guard is off) when the timeout is 0. Without it a backend that
        // sends headers then stalls pins the H3 stream + request/admission
        // guards + LB count until QUIC idle timeout (or forever for a
        // trickling-but-never-completing peer).
        let backend_read_timeout_ms = proxy.backend_read_timeout_ms;
        let read_timeout_active = backend_read_timeout_ms > 0;
        let read_deadline = tokio::time::sleep(std::time::Duration::from_millis(
            backend_read_timeout_ms.max(1),
        ));
        tokio::pin!(read_deadline);
        let mut stream_done = false;
        let mut bytes_streamed: u64 = 0;
        let mut body_completed = false;

        // Set when the recv_data arm consumed a backend frame; the loop head
        // re-arms `read_deadline` on the NEXT iteration so the deadline only
        // ever measures the wait for the next backend frame and never charges
        // the time spent sending the previous frame downstream (slow-client H2
        // backpressure) to the backend. Mirrors `IdleReadTimeoutBody`'s
        // `waiting` flag on the H2 path.
        let mut just_received_backend_frame = false;
        // Skipped entirely when send_response already failed above — the
        // relay loop would only rediscover the dead stream on its first
        // send_data and there is no backend data worth pulling for it.
        'outer: while !client_disconnected {
            // Re-arm the read deadline only once the previous backend frame has
            // actually been flushed downstream (`coalesce_buf` empty), so neither
            // the direct send NOR a slow flush of a buffered sub-target chunk is
            // charged to the backend. A coalesced chunk buffered below the
            // coalesce-min threshold keeps `just_received_backend_frame` set but
            // does NOT re-arm until `flush_timer` (or the next threshold flush)
            // drains the buffer — otherwise a slow client holding that flush
            // longer than `backend_read_timeout_ms` would expire the deadline
            // against a healthy backend.
            if read_timeout_active && just_received_backend_frame && coalesce_buf.is_empty() {
                read_deadline.as_mut().reset(
                    tokio::time::Instant::now()
                        + std::time::Duration::from_millis(backend_read_timeout_ms),
                );
                just_received_backend_frame = false;
            }
            tokio::select! {
                chunk_result = h3_resp.recv_stream.recv_data(), if !stream_done => {
                    match chunk_result {
                        Ok(Some(mut chunk)) => {
                            // Defer the deadline re-arm to the loop head so the
                            // downstream send below is excluded from the budget.
                            just_received_backend_frame = true;
                            let chunk_len = chunk.remaining();
                            // Always count received bytes — the graceful-close
                            // recovery below uses this to decide if the body is
                            // semantically complete, even when the body-size
                            // limit is disabled (FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0).
                            total_streamed += chunk_len;
                            if effective_max_response_body_size_bytes > 0
                                && total_streamed > effective_max_response_body_size_bytes
                            {
                                warn!(
                                    "Backend response exceeded {} byte limit during streaming",
                                    effective_max_response_body_size_bytes
                                );
                                crate::http3::stream_util::abort_response_stream(&mut stream);
                                body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                                break 'outer;
                            }
                            // Windowed inspection (bypasses coalescing): the
                            // inspector holds raw bytes until a window is cleared,
                            // then releases them verbatim, or cuts the stream.
                            if let Some(inspector) = response_inspector.as_mut() {
                                let chunk_bytes =
                                    crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                                match inspector.on_chunk(&chunk_bytes).await {
                                    ResponseStreamAction::Forward(out) => {
                                        if !out.is_empty() {
                                            let out_len = out.len() as u64;
                                            if stream.send_data(out).await.is_err() {
                                                client_disconnected = true;
                                                body_error_class =
                                                    Some(crate::retry::ErrorClass::ClientDisconnect);
                                                break 'outer;
                                            }
                                            bytes_streamed += out_len;
                                            flush_timer.as_mut().reset(
                                                tokio::time::Instant::now() + flush_interval,
                                            );
                                        }
                                    }
                                    ResponseStreamAction::Terminate(final_bytes) => {
                                        // Policy cut: emit the optional terminal event,
                                        // end the stream. A clean cut is a NORMAL
                                        // completion (no backend fault, no LB/capability
                                        // penalty) — but only if the client is still
                                        // there; a failed send/finish is a disconnect,
                                        // not a clean completion.
                                        if let Some(fb) = final_bytes
                                            && !fb.is_empty()
                                        {
                                            let fb_len = fb.len() as u64;
                                            if stream.send_data(fb).await.is_ok() {
                                                bytes_streamed += fb_len;
                                            }
                                        }
                                        if stream.finish().await.is_ok() {
                                            body_completed = true;
                                        } else {
                                            client_disconnected = true;
                                            body_error_class =
                                                Some(crate::retry::ErrorClass::ClientDisconnect);
                                        }
                                        break 'outer;
                                    }
                                }
                                continue;
                            }
                            if crate::http3::config::should_direct_send_response_chunk(
                                coalesce_buf.len(),
                                chunk_len,
                                coalesce_min_bytes,
                            ) {
                                let data =
                                    crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                                if stream.send_data(data).await.is_err() {
                                    client_disconnected = true;
                                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                    break 'outer;
                                }
                                bytes_streamed += chunk_len as u64;
                                flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                                continue;
                            }

                            let chunk_bytes =
                                crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                            coalesce_buf.extend_from_slice(&chunk_bytes);
                            if coalesce_buf.len() >= coalesce_min_bytes {
                                let data = coalesce_buf.split().freeze();
                                let data_len = data.len() as u64;
                                if stream.send_data(data).await.is_err() {
                                    client_disconnected = true;
                                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                    break 'outer;
                                }
                                bytes_streamed += data_len;
                                flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                            }
                        }
                        Ok(None) => { stream_done = true; }
                        Err(e) => {
                            let cl: Option<u64> = declared_content_length;
                            let received = total_streamed as u64;
                            if crate::http3::client::is_h3_graceful_close(&e)
                                && crate::http3::client::is_response_body_complete(
                                    received, &method, response_status, cl,
                                )
                            {
                                debug!(
                                    bytes_received = received,
                                    "H3 streaming recv_data hit graceful close after complete body; treating as success"
                                );
                                stream_done = true;
                            } else {
                                error!("Error reading backend h3 response during streaming: {}", e);
                                coalesce_buf.clear();
                                crate::http3::stream_util::abort_response_stream(&mut stream);
                                let class = crate::http3::client::classify_http3_error(&e);
                                // Mid-stream QUIC/H3 transport failure is a
                                // capability-downgrade signal — same rule as the
                                // native gRPC streaming and refined-buffered
                                // paths. Excludes client disconnect, size
                                // errors, and read timeouts by class, plus
                                // `H3_NO_ERROR` / GOAWAY explicitly: a graceful
                                // teardown before the declared body completed
                                // still fails the request, but it is never
                                // evidence the backend lost QUIC.
                                if !crate::http3::client::is_h3_graceful_close(&e)
                                    && crate::proxy::is_h3_transport_error_class(class)
                                {
                                    state
                                        .backend_capabilities
                                        .mark_h3_unsupported(&proxy, upstream_target.as_deref());
                                }
                                body_error_class = Some(class);
                                break 'outer;
                            }
                        }
                    }
                }
                _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                    let data = coalesce_buf.split().freeze();
                    let data_len = data.len() as u64;
                    if stream.send_data(data).await.is_err() {
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        break 'outer;
                    }
                    bytes_streamed += data_len;
                    flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                }
                _ = &mut read_deadline, if read_timeout_active && !stream_done && coalesce_buf.is_empty() => {
                    warn!(
                        "Backend read timeout ({}ms) during HTTP/3 streaming response body; aborting",
                        backend_read_timeout_ms
                    );
                    coalesce_buf.clear();
                    crate::http3::stream_util::abort_response_stream(&mut stream);
                    body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                    break 'outer;
                }
            }
            if stream_done {
                if let Some(inspector) = response_inspector.as_mut() {
                    // Flush / inspect the trailing partial window at end of stream.
                    match inspector.on_end().await {
                        ResponseStreamAction::Forward(out) => {
                            if !out.is_empty() {
                                let out_len = out.len() as u64;
                                if stream.send_data(out).await.is_ok() {
                                    bytes_streamed += out_len;
                                }
                            }
                        }
                        ResponseStreamAction::Terminate(final_bytes) => {
                            if let Some(fb) = final_bytes
                                && !fb.is_empty()
                            {
                                let fb_len = fb.len() as u64;
                                if stream.send_data(fb).await.is_ok() {
                                    bytes_streamed += fb_len;
                                }
                            }
                        }
                    }
                } else if !coalesce_buf.is_empty() {
                    let data = coalesce_buf.split().freeze();
                    let data_len = data.len() as u64;
                    if stream.send_data(data).await.is_err() {
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        break 'outer;
                    }
                    bytes_streamed += data_len;
                }
                let finish_result = if response_inspector.is_some() {
                    stream
                        .finish()
                        .await
                        .map_err(|_| H3TrailerFinishError::Client)
                } else {
                    finish_h3_response_with_backend_trailers(
                        &mut stream,
                        &mut h3_resp.recv_stream,
                        backend_read_timeout_ms,
                        H3StreamingTrailerPolicy {
                            final_headers: &response_headers,
                            pre_policy: &pre_policy_response_headers,
                            governance: response_trailer_governance,
                            // Plain-flavor relay: `use_native_h3_pool` requires
                            // `HttpFlavor::Plain`, so no field name is exempt here.
                            section: TrailerSectionKind::PlainResponse,
                        },
                    )
                    .await
                };
                match finish_result {
                    Ok(_) => body_completed = true,
                    Err(H3TrailerFinishError::Backend(err)) => {
                        error!(
                            "Error reading backend h3 response trailers during streaming: {}",
                            err
                        );
                        crate::http3::stream_util::abort_response_stream(&mut stream);
                        let class = crate::http3::client::classify_http3_error(&err);
                        // Trailer-boundary transport faults are the same
                        // capability signal as mid-body resets (issue #2939),
                        // and carry the same graceful-close exclusion.
                        if !crate::http3::client::is_h3_graceful_close(&err)
                            && crate::proxy::is_h3_transport_error_class(class)
                        {
                            state
                                .backend_capabilities
                                .mark_h3_unsupported(&proxy, upstream_target.as_deref());
                        }
                        body_error_class = Some(class);
                    }
                    Err(H3TrailerFinishError::BackendTimeout) => {
                        warn!(
                            "Backend trailer read timeout ({}ms) during HTTP/3 streaming response",
                            backend_read_timeout_ms
                        );
                        crate::http3::stream_util::abort_response_stream(&mut stream);
                        body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                    }
                    Err(H3TrailerFinishError::Client) => {
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    }
                }
                break;
            }
        }

        // Record outcome.
        //
        // A streaming body that reached this point already delivered its
        // response headers, so any terminal `body_error_class` is post-wire.
        // Mirror the refined/cross-protocol streaming consumer's predicate (see
        // the `(h3_error_class, body_error_class)` match further below) so the
        // native and refined H3 streaming paths classify identically:
        //   * `ReadWriteTimeout` — post-wire read timeout, NOT a connect failure
        //     (matches the H2 `IdleReadTimeoutBody` path and the buffered H3
        //     path); previously hard-coded `(false, None)` hid it from passive
        //     health entirely.
        //   * `ClientDisconnect` — a client-side signal; feeding the class
        //     through instead of `None` lets the circuit breaker / passive
        //     health treat it as neutral rather than a phantom backend success.
        //   * any other body fault (mid-stream reset/close, `ResponseBodyTooLarge`)
        //     — a backend fault, consistent with the refined-streaming consumer.
        let body_outcome_connection_error = match body_error_class {
            None
            | Some(crate::retry::ErrorClass::ReadWriteTimeout)
            | Some(crate::retry::ErrorClass::ClientDisconnect) => false,
            Some(_) => true,
        };
        // When the backend itself returned a failure status (a 5xx, or any status
        // the proxy configured as a circuit-breaker failure), a concurrent client
        // disconnect during the response send must NOT mask it: `ClientDisconnect`
        // is client-side and skips CB / passive-health entirely, so a real backend
        // failure would be neutralized. Drop the body class in that case so the
        // failure status drives the recorded outcome. Provenance matters and only
        // the caller has it — `record_backend_outcome` cannot tell this backend
        // status apart from a synthetic 5xx emitted on a client upload-abort, so
        // this stays caller-side. Mirrors the refined/cross-protocol consumer.
        let backend_failure_status = response_status >= 500
            || proxy
                .circuit_breaker
                .as_ref()
                .is_some_and(|cb| cb.failure_status_codes.contains(&response_status));
        let body_outcome_error_class = match body_error_class {
            Some(crate::retry::ErrorClass::ClientDisconnect) if backend_failure_status => None,
            other => other,
        };
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            &epoch.load_balancer,
            upstream_balancer.as_ref(),
            upstream_target.as_deref(),
            cb_target_key.as_deref(),
            response_status,
            body_outcome_connection_error,
            body_outcome_error_class,
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            response_status,
            body_outcome_connection_error,
            body_outcome_error_class,
            backend_admission_response_elapsed,
        );

        let backend_ttfb_ms = backend_admission_response_elapsed.as_secs_f64() * 1000.0;
        // Concurrent backend-body / client-delivery lifetime cannot be split on
        // the synchronous H3 streaming pipe — emit the shared unknown sentinel
        // rather than labeling the residual as backend total or gateway work.
        let backend_total_ms = crate::plugins::LATENCY_UNKNOWN_MS;
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let (gateway_processing_ms, gateway_overhead_ms) =
            TransactionSummary::derive_gateway_latencies(
                total_ms,
                backend_total_ms,
                plugin_execution_ms,
                true,
            );

        // Native H3 drives the inspector in this task rather than a detached
        // body task. Drop it explicitly so the shared completion signal is set
        // before terminal hooks wait and drain metadata.
        drop(response_inspector);
        let stream_outcome = BodyOutcome {
            body_completed,
            body_error_class,
            bytes_streamed,
            client_disconnected,
            grpc_status: None,
        };
        run_response_stream_termination_hooks(&plugins, &mut ctx, response_status, &stream_outcome)
            .await;
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            auth_method: ctx.auth_method,
            http_method: method.to_string(),
            request_path: original_request_path.clone(),
            proxy_id: Some(proxy.id.clone()),
            proxy_name: proxy.name.clone(),
            backend_target: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip: backend_resolved_ip.clone(),
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: true,
            client_disconnected,
            error_class: None,
            body_error_class,
            body_completed,
            bytes_sent: request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
            // Response bytes delivered to the client — tracked by the
            // streaming loop above as `bytes_streamed`.
            bytes_received: bytes_streamed,
            mirror: false,
            metadata: crate::proxy::clone_log_metadata(&ctx),
            ai_usage_export: ctx.ai_usage_export.clone(),
            proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
        };

        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
        record_request(&state, response_status);
        return Ok(());
    }

    // --- Collect request body (buffered path) ---
    // Body must be collected when plugins need inspection/transformation or
    // retries are configured (need to replay on connection failures).
    let body_was_prebuffered = prebuffered_body_data.is_some();
    let mut body_data = prebuffered_body_data.take().unwrap_or_default();
    if !body_was_prebuffered {
        body_data = match collect_h3_request_body_with_deadline(
            drain_h3_request_body(&mut stream, effective_max_request_body_size_bytes),
            ctx.grpc_deadline_at(),
            proxy.backend_read_timeout_ms,
        )
        .await
        {
            Ok(Some(body_data)) => body_data,
            Ok(None) => {
                release_h3_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                let metric_status = h3_reject_log_status_and_metadata(
                    &mut ctx,
                    http_flavor,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    br#"{"error":"Request body exceeds maximum size"}"#,
                    &HashMap::new(),
                );
                record_request(&state, metric_status);
                send_h3_error_flavor_aware_with_policy(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await?;
                return Ok(());
            }
            Err(H3RequestBodyReadError::Read(error)) => {
                halt_cancelled_h3_upload(&mut stream);
                release_h3_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                return Err(error.into());
            }
            Err(H3RequestBodyReadError::DeadlineExceeded) => {
                release_h3_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                finalize_h3_upload_deadline_rejection(
                    &mut stream,
                    &state,
                    &plugins,
                    &mut ctx,
                    http_flavor,
                    grpc_web_response_content_type,
                    start_time,
                    "grpc_deadline_buffered_h3_upload",
                    plugin_execution_ns,
                )
                .await?;
                return Ok(());
            }
            Err(timeout) => {
                let (error_body, grpc_message) = h3_request_body_timeout_contract(&timeout);
                release_h3_circuit_breaker_probe_on_admission_reject(
                    &state,
                    &proxy,
                    cb_target_key.as_deref(),
                    cb_is_half_open_probe,
                );
                record_request(
                    &state,
                    if matches!(http_flavor, HttpFlavor::Grpc) {
                        StatusCode::OK.as_u16()
                    } else {
                        StatusCode::REQUEST_TIMEOUT.as_u16()
                    },
                );
                send_h3_error_flavor_aware_with_policy_and_recv_halt(
                    &mut stream,
                    http_flavor,
                    grpc_web_response_content_type,
                    StatusCode::REQUEST_TIMEOUT,
                    error_body,
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    grpc_message,
                    initial_response_header_policy_plugins.as_ref(),
                    false,
                )
                .await?;
                return Ok(());
            }
        };
    }

    // Capture the on-wire request body length BEFORE plugin transforms run.
    // The buffered-response summary and the streaming-response `bytes_sent`
    // field both use this value, so `bytes_sent` reflects bytes actually
    // received from the client — consistent with the pre-transform semantics
    // of the HTTP/1.1, HTTP/2, and gRPC paths.
    let raw_request_body_bytes = prepared_raw_request_body_bytes.unwrap_or(body_data.len() as u64);

    // Transform request body via plugins when buffering is active
    let mut body_data = if !request_body_prepared
        && needs_request_buffering
        && !body_data.is_empty()
        && capabilities.has(crate::plugin_cache::PluginCapabilities::MODIFIES_REQUEST_BODY)
    {
        // Expose the request method as a `:method` pseudo-header so
        // method-sensitive plugins that only override the plain
        // `transform_request_body` (e.g. `ai_prompt_compressor` skips non-POST
        // bodies) can still gate on it through the default context-aware
        // delegation. This mirrors the gRPC path's hook-only header map and is
        // never forwarded to the backend (dispatch uses `proxy_headers`).
        let mut hook_headers = proxy_headers.clone();
        hook_headers
            .entry(":method".to_string())
            .or_insert_with(|| method.clone());
        let grpc_deadline_at = ctx.grpc_deadline_at();
        crate::proxy::apply_request_body_plugins_with_context(
            &plugins,
            Some(&mut ctx),
            grpc_deadline_at,
            &hook_headers,
            body_data,
        )
        .await
    } else {
        body_data
    };

    // Skip the per-plugin context-aware dispatch when no plugin opted in via
    // `needs_final_request_body_context`. The default impl of
    // `on_final_request_body_with_context` would just delegate back to
    // `on_final_request_body`; passing `None` keeps us on the direct path.
    let final_body_result = if request_body_prepared {
        PluginResult::Continue
    } else {
        let grpc_deadline_at = ctx.grpc_deadline_at();
        if needs_ctx_headers_for_body_hooks {
            crate::proxy::run_final_request_body_hooks(
                &plugins,
                Some(&mut ctx),
                grpc_deadline_at,
                &proxy_headers,
                &body_data,
            )
            .await
        } else {
            crate::proxy::run_final_request_body_hooks_with_provenance(
                &plugins,
                None,
                grpc_deadline_at,
                &proxy_headers,
                &body_data,
            )
            .await
            .into_plugin_result(&mut ctx)
        }
    };
    match final_body_result {
        crate::plugins::PluginResult::Continue => {}
        reject @ crate::plugins::PluginResult::Reject { .. }
        | reject @ crate::plugins::PluginResult::RejectBinary { .. } => {
            // Gateway-side reject before backend dispatch. The CB check above may
            // have reserved a HALF_OPEN probe; release it before any client-facing
            // reject write (the sends below use `?` and can exit early on client
            // reset), matching run_h3_backend_admission_or_send_reject. Placed
            // before the destructure so it also covers the 500 conversion-failure
            // fallback below.
            release_h3_circuit_breaker_probe_on_admission_reject(
                &state,
                &proxy,
                cb_target_key.as_deref(),
                cb_is_half_open_probe,
            );
            let Some(mut reject) = plugin_result_into_reject_parts(reject) else {
                tracing::error!("Plugin result could not be converted to rejection parts");
                record_request(&state, 500);
                let mut body = Bytes::from_static(b"Internal Server Error");
                let mut headers = HashMap::new();
                if crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire(
                    &ctx.method,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    &mut headers,
                    body.len(),
                ) {
                    // HEAD/204/205/304: drop capacity, no DATA frame.
                    body = Bytes::new();
                }
                send_h3_reject_response(
                    &mut stream,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    body,
                    &headers,
                    RejectBodyDisposition::for_request(
                        &ctx.method,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    ),
                )
                .await?;
                return Ok(());
            };
            let mut headers = reject.headers;
            crate::proxy::apply_reject_after_proxy_and_synthetic_body_hooks(
                &plugins,
                &mut ctx,
                &mut reject.status_code,
                &mut headers,
                &mut reject.body,
                matches!(http_flavor, HttpFlavor::Grpc),
                false,
            )
            .await;
            let http_status =
                StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::PAYLOAD_TOO_LARGE);
            run_h3_reject_response_committed_hooks(
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                http_status,
                reject.body.clone(),
                &headers,
            )
            .await;
            let log_status_code = h3_reject_log_status_and_metadata(
                &mut ctx,
                http_flavor,
                http_status,
                &reject.body,
                &headers,
            );
            record_request(&state, log_status_code);
            log_rejected_request(
                &plugins,
                &ctx,
                log_status_code,
                start_time,
                "on_final_request_body",
                plugin_execution_ns,
            )
            .await;
            send_h3_plugin_reject_flavor_aware(
                &mut stream,
                &plugins,
                &mut ctx,
                http_flavor,
                grpc_web_response_content_type,
                http_status,
                reject.body.clone(),
                &headers,
            )
            .await?;
            return Ok(());
        }
    }

    backend_admission_start = std::time::Instant::now();
    backend_admission_permits =
        if let Some(permits) = preacquired_backend_admission.take_if_acquired() {
            permits
        } else {
            match run_h3_backend_admission_or_send_reject(
                backend_admission_plugins.as_ref(),
                &plugins,
                &mut ctx,
                &proxy,
                upstream_target.as_deref(),
                http_flavor,
                grpc_web_response_content_type,
                initial_response_header_policy_plugins.as_ref(),
                &mut stream,
                &state,
                start_time,
                plugin_execution_ns,
                cb_target_key.as_deref(),
                cb_is_half_open_probe,
            )
            .await?
            {
                Ok(permits) => permits,
                // Probe release happens inside the helper, before the reject write.
                Err(()) => return Ok(()),
            }
        };

    // Track connection for least-connections LB (after all pre-dispatch rejects).
    // Placed here so the streaming-request path above handles its own tracking,
    // and early returns from body collection/plugin rejects don't leak counts.
    if let (Some(_upstream_id), Some(target), Some(balancer)) = (
        &proxy.upstream_id,
        &upstream_target,
        upstream_balancer.as_ref(),
    ) {
        balancer.record_connection_start(target);
    }

    let can_refine_h3_response_buffering = needs_response_buffering
        && (!has_retry || retry_response_needs_header_refinement)
        && matches!(
            proxy.response_body_mode,
            crate::config::types::ResponseBodyMode::Stream
        )
        && maybe_requires_response_body_buffering;
    let mut refined_buffered_response = None;
    let refined_streaming_response = if can_refine_h3_response_buffering {
        let client_ip_for_refined = ctx.client_ip.clone();
        let is_early_data = ctx.is_early_data;
        // A retryable first response falls back into the native-H3 retry loop,
        // which must retain the transformed request bytes for replay. The
        // non-retry path can keep the allocation-free move.
        let refined_body_data = if has_retry {
            body_data.clone()
        } else {
            std::mem::take(&mut body_data)
        };
        match proxy_to_backend_h3_refined_response(
            &state,
            &proxy,
            &backend_url,
            &method,
            &proxy_headers,
            refined_body_data,
            &client_ip_for_refined,
            socket_ip,
            upstream_target.as_deref(),
            &epoch,
            sticky_cookie_needed,
            &mut stream,
            &plugins,
            &mut ctx,
            &mut plugin_execution_ns,
            is_early_data,
            backend_admission_start,
            if has_retry {
                proxy.retry.as_ref()
            } else {
                None
            },
            response_trailer_governance,
        )
        .await?
        {
            H3RefinedResponse::Streamed(result) => Some(result),
            H3RefinedResponse::Buffered(result) => {
                refined_buffered_response = Some(result);
                None
            }
        }
    } else {
        None
    };

    if !needs_response_buffering || refined_streaming_response.is_some() {
        // ===== STREAMING RESPONSE PATH (buffered request body) =====
        // Response body is streamed, but request body was collected because
        // plugins needed it or it was prebuffered.
        let client_ip_owned = ctx.client_ip.clone();
        // Use the pre-transform length captured before the plugin
        // `transform_request_body` loop ran. `body_data` at this point may
        // have been rewritten by a request-body plugin; logging its current
        // length would misreport the on-wire size. `raw_request_body_bytes`
        // is the canonical `bytes_sent` value for the H3 buffered-request
        // path on both the streaming and buffered response branches.
        let request_body_bytes = raw_request_body_bytes;
        let h3_stream_result = if let Some(result) = refined_streaming_response {
            result
        } else {
            let streaming_result = proxy_to_backend_h3_streaming(
                &state,
                &proxy,
                &backend_url,
                &method,
                &proxy_headers,
                body_data,
                &client_ip_owned,
                socket_ip,
                upstream_target.as_deref(),
                &epoch,
                sticky_cookie_needed,
                &mut stream,
                &plugins,
                &mut ctx,
                &mut plugin_execution_ns,
                backend_admission_start,
                response_trailer_governance,
            )
            .await;

            match streaming_result {
                Ok(result) => result,
                Err(e) => {
                    // Stream may already have partial data sent — log and return
                    debug!("HTTP/3 streaming proxy error: {}", e);
                    return Err(e);
                }
            }
        };

        let response_status = h3_stream_result.status;
        // True backend status for CB / passive-health (diverges from
        // `response_status` only on an after_proxy reject or size-limit
        // rejection, where `response_status` is the gateway's policy status).
        let backend_status = h3_stream_result.backend_status;
        let h3_error_class = h3_stream_result.error_class;

        // Record outcome across CB, passive health, latency, and connection
        // tracking.
        //
        // Discriminator: `body_error_class` — set ONLY when something went
        // wrong DURING body streaming (after headers were flushed). This
        // separates pre-headers dispatch failures (where the typed
        // `request_on_wire` signal is authoritative) from body-phase
        // aborts (where the request demonstrably reached the wire and
        // truncation is always a backend fault, regardless of HTTP status).
        //
        // Pre-fix iterations went through three wrong predicates:
        //
        //   1. `err_class.is_some()` — over-reported every post-wire class
        //      including graceful close as connection_error=true, tripping
        //      CB / passive-health for the exact case the PR aims to suppress.
        //
        //   2. Helper-derived (`request_reached_wire(class)`) — couldn't
        //      tell a connect-phase QUIC reset (string-classified as
        //      `ConnectionReset`, "post-wire" by class but pre-wire by reality)
        //      from a real post-wire reset. The typed pool signal disambiguates.
        //
        //   3. `(error_class, status)` shape match (status>=500 → dispatch,
        //      status<500 → body abort) — failed when the BACKEND emitted a
        //      5xx status and THEN the body truncated mid-stream
        //      (`H3StreamResult { status: 503, error_class: Some(_),
        //      body_error_class: Some(_), request_on_wire: true }`). The
        //      status-based shape detector mis-classified that as a dispatch
        //      failure and reported `!request_on_wire=false` — letting CB
        //      see only the 503 status and skipping passive-health
        //      transport-failure accounting.
        //
        // Current predicate driven by `(error_class, body_error_class)`:
        //
        //   * `(None, None)` — clean response. Not a connection error.
        //   * `(_, Some(ReadWriteTimeout))` — streaming read timeout. Post-wire
        //     (headers already delivered), so NOT a connection error — matches
        //     the H2 `IdleReadTimeoutBody` path, the buffered H3 path, and the
        //     native-H3 streaming loop. The read-deadline arm records
        //     ReadWriteTimeout on BOTH the terminal and body class, so intercept
        //     it here before the generic backend-fault arms below.
        //   * `(None, Some(ClientDisconnect))` — client gave up between
        //     headers and end-of-body. Not a backend fault.
        //   * `(None, Some(_))` — body-phase issue with no terminal
        //     dispatch error: e.g. mid-stream `ResponseBodyTooLarge` set
        //     only on `body_error_class`. Treat as backend fault.
        //   * `(Some(_), Some(_))` — recv_data error after non-graceful
        //     close (terminal + body classes both set), or mid-stream
        //     ResponseBodyTooLarge with both set. Always a backend fault
        //     regardless of HTTP status (covers the reviewer's specific
        //     case: backend 5xx + body abort).
        //   * `(Some(_), None)` — pre-headers dispatch failure; the typed
        //     `request_on_wire` signal is authoritative. Graceful close at
        //     `recv_response` reports `request_on_wire=true` →
        //     `connection_error=false`, matching the buffered path and
        //     achieving the PR's primary goal.
        let connection_error = match (h3_error_class, h3_stream_result.body_error_class) {
            (None, None) => false,
            (_, Some(crate::retry::ErrorClass::ReadWriteTimeout)) => false,
            (None, Some(crate::retry::ErrorClass::ClientDisconnect)) => false,
            (None, Some(_)) => true,
            (Some(_), Some(_)) => true,
            (Some(_), None) => h3_connection_error(
                h3_stream_result.request_on_wire,
                h3_stream_result.error_class,
            ),
        };
        // Prefer the body class so a body-only ClientDisconnect is recognized as
        // a client-side (non-backend) signal by passive health / the breaker
        // instead of a phantom success (the terminal `h3_error_class` is None for
        // a mid-body client disconnect). EXCEPTION: when the backend itself
        // returned a failure status (a 5xx, or any status the proxy configured as
        // a circuit-breaker failure), a concurrent client disconnect during the
        // response send must NOT neutralize that backend failure — client-side
        // classes skip CB / passive-health entirely — so fall back to the dispatch
        // class (or None) and let the failure status drive the recorded outcome.
        // Shared with the admission outcome below.
        let backend_failure_status = backend_status >= 500
            || proxy
                .circuit_breaker
                .as_ref()
                .is_some_and(|cb| cb.failure_status_codes.contains(&backend_status));
        let backend_outcome_error_class = match h3_stream_result.body_error_class {
            Some(crate::retry::ErrorClass::ClientDisconnect) if backend_failure_status => {
                h3_error_class
            }
            other => other.or(h3_error_class),
        };
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            &epoch.load_balancer,
            upstream_balancer.as_ref(),
            upstream_target.as_deref(),
            cb_target_key.as_deref(),
            backend_status,
            connection_error,
            backend_outcome_error_class,
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            backend_status,
            connection_error,
            backend_outcome_error_class,
            h3_stream_result.backend_admission_elapsed,
        );

        // Admission elapsed above still drives adaptive concurrency. TTFB is
        // only concrete when response headers were observed — pre-header
        // dispatch failures report LATENCY_UNKNOWN_MS (mirrors native-H3 gRPC).
        let backend_ttfb_ms = h3_stream_backend_ttfb_ms(&h3_stream_result);
        let backend_total_ms = crate::plugins::LATENCY_UNKNOWN_MS;

        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let (gateway_processing_ms, gateway_overhead_ms) =
            TransactionSummary::derive_gateway_latencies(
                total_ms,
                backend_total_ms,
                plugin_execution_ms,
                true,
            );

        let stream_outcome = BodyOutcome {
            body_completed: h3_stream_result.body_completed,
            body_error_class: h3_stream_result.body_error_class,
            bytes_streamed: h3_stream_result.bytes_streamed,
            client_disconnected: h3_stream_result.client_disconnected,
            grpc_status: None,
        };
        run_response_stream_termination_hooks(&plugins, &mut ctx, response_status, &stream_outcome)
            .await;
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            auth_method: ctx.auth_method,
            http_method: method,
            request_path: original_request_path.clone(),
            proxy_id: Some(proxy.id.clone()),
            proxy_name: proxy.name.clone(),
            backend_target: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip: backend_resolved_ip.clone(),
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: true,
            client_disconnected: h3_stream_result.client_disconnected,
            error_class: h3_error_class,
            body_error_class: h3_stream_result.body_error_class,
            body_completed: h3_stream_result.body_completed,
            bytes_sent: request_body_bytes,
            // `bytes_streamed` from the H3 streaming helper is the final
            // count of body bytes pushed to the client's h3 stream. Mirror
            // it into the unified `bytes_received` field.
            bytes_received: h3_stream_result.bytes_streamed,
            mirror: false,
            metadata: crate::proxy::clone_log_metadata(&ctx),
            ai_usage_export: ctx.ai_usage_export.clone(),
            proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
        };

        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;

        record_request(&state, response_status);
    } else {
        // ===== BUFFERED RESPONSE PATH =====
        // Collect full response for plugin body inspection/transformation and retries.
        // When retries are configured, wrap in a retry loop with target switching.
        //
        // `connection_error` at every consumer site below is driven by the
        // typed [`H3PoolError::request_on_wire`] signal that
        // `proxy_to_backend_h3` carries on `H3BufferedDispatchResult`.
        // We do NOT re-derive it from `error_class` via
        // `request_reached_wire`: the string-heuristic fallback in
        // `classify_http3_error` can label a connect-phase QUIC reset as
        // `ConnectionReset` (post-wire) when the typed pool signal
        // correctly reports `false` (no commitment) — that mismatch
        // would suppress `retry_on_connect_failure` and mis-account a
        // pre-wire failure as a 502 status fault on CB / passive health.
        let mut cb_retry_probe_slot_available = cb_is_half_open_probe;
        let (
            mut response_status,
            response_body,
            mut response_headers,
            mut response_trailers,
            h3_error_class,
            h3_request_on_wire,
            final_cb_target_key,
            final_target,
        ) = if let Some(retry_config) = &proxy.retry {
            let mut attempt = 0u32;
            let mut current_target = upstream_target.clone();
            let mut current_cb_target_key = cb_target_key.clone();
            let mut current_url = backend_url.clone();
            // Locked for the first (already-selected H3-capable) target.
            // Recomputed only when LB rotation hands us a different host:port,
            // mirroring `current_dispatch_h3` in the H1/H2 retry loop so
            // mixed-capability upstreams switch to the cross-protocol bridge
            // instead of burning a doomed QUIC connect timeout.
            let mut current_dispatch_h3 = true;

            // Resolve the dispatch proxy for THIS attempt's target from the
            // retry-capped BASE proxy — never from the first target's effective
            // proxy — mirroring the per-attempt re-resolution the H3->plain
            // bridge (`dispatch_plain`) and the H1/H2 retry path
            // (`proxy_to_backend_retry`) perform. Rotation is port-lane-pinned
            // only when the failed target's policy port has a live per-port
            // override, so a rotation can cross from the SD fallback into a
            // policy port that carries its own `portLevelSettings` (TLS/SNI/
            // connectTimeout); dialing with a stale first-target proxy would
            // use the wrong TLS identity for the rotated target.
            let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(
                &selected_base_proxy,
                current_target.as_deref(),
            );
            let mut result = match refined_buffered_response {
                Some(result) => result,
                None => {
                    proxy_to_backend_h3(
                        &state,
                        attempt_dispatch_proxy.as_ref(),
                        &current_url,
                        &method,
                        &proxy_headers,
                        &body_data,
                        &ctx.client_ip,
                        socket_ip,
                        current_target.as_deref(),
                        ctx.request_is_secure,
                        ctx.is_early_data,
                        effective_max_response_body_size_bytes,
                    )
                    .await
                }
            };

            // Build a lightweight BackendResponse for should_retry — only
            // status_code and connection_error are read. Use empty body/headers
            // to avoid cloning the full response on every retry check.
            while crate::retry::should_retry(
                retry_config,
                &method,
                &crate::retry::BackendResponse {
                    status_code: result.status,
                    connection_error: h3_connection_error(
                        result.request_on_wire,
                        result.error_class,
                    ),
                    body: crate::retry::ResponseBody::buffered(Vec::new()),
                    headers: HashMap::new(),
                    backend_resolved_ip: None,
                    error_class: result.error_class,
                },
                attempt,
            ) {
                // Resolve and validate the retry target before charging this
                // failure as an intermediate attempt or entering backoff. An
                // incompatible path terminates here, leaving the ordinary
                // final-outcome path to record the failed attempt exactly once.
                let next_retry_target = if let (Some(_upstream_id), Some(prev_target)) =
                    (&proxy.upstream_id, &current_target)
                    && let Some(ref hash_key) = lb_hash_key
                    && let Some(next) = crate::proxy::backend_dispatch::select_next_retry_target(
                        &state,
                        &epoch,
                        &proxy,
                        prev_target,
                        hash_key,
                        &ctx.client_ip,
                        &proxy_headers,
                    ) {
                    if !crate::proxy::retry_target_preserves_backend_path(
                        backend_path_is_policy_bound,
                        &proxy,
                        &path,
                        strip_len,
                        prev_target,
                        &next,
                    ) {
                        warn!(
                            proxy_id = %proxy.id,
                            "Aborting H3 retry because the candidate would change the authorized backend method path"
                        );
                        break;
                    }
                    Some(next)
                } else {
                    None
                };

                record_h3_backend_admission_outcome(
                    &mut backend_admission_permits,
                    result.status,
                    h3_connection_error(result.request_on_wire, result.error_class),
                    result.error_class,
                    backend_admission_start.elapsed(),
                );
                // Record failure against current target's circuit breaker.
                // Same typed signal as the retry decision: a graceful close
                // (or any other post-`send_request` fault) does not count
                // as a transport-level failure for CB tripping.
                if let Some(cb_config) = &proxy.circuit_breaker {
                    let cb = state.circuit_breaker_cache.get_or_create(
                        &proxy.namespace,
                        &proxy.id,
                        current_cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(
                        result.status,
                        h3_connection_error(result.request_on_wire, result.error_class),
                        cb_retry_probe_slot_available,
                    );
                    cb_retry_probe_slot_available = false;
                }

                let delay = crate::retry::retry_delay(retry_config, attempt);
                tokio::time::sleep(delay).await;
                attempt += 1;

                if let Some(next) = next_retry_target {
                    let target_changed = current_target.as_ref().is_some_and(|prev_target| {
                        next.host != prev_target.host || next.port != prev_target.port
                    });
                    current_url = crate::proxy::build_backend_url_with_target(
                        &proxy,
                        &path,
                        effective_query_string.as_ref(),
                        &next.host,
                        next.port,
                        strip_len,
                        next.path.as_deref(),
                    );
                    current_cb_target_key =
                        Some(crate::circuit_breaker::target_key(&next.host, next.port));
                    current_target = Some(next);
                    if target_changed {
                        // Per-target capability lookup is O(1). Unknown /
                        // Unsupported both fall through to the buffered
                        // cross-protocol bridge so mixed-capability
                        // upstreams do not burn a doomed QUIC timeout.
                        current_dispatch_h3 = crate::proxy::supports_native_http3_backend(
                            &state,
                            &selected_base_proxy,
                            current_target.as_deref(),
                        );
                    }
                }

                // Re-screen the rotated retry target BEFORE admission/dispatch:
                // the native-H3 pool's cached resolver accepts IP literals, so a
                // rotated denied literal / `dns_override` target (e.g. a warn-only
                // DB/DP config carrying `169.254.169.254`) would otherwise be
                // admitted and dialed here, bypassing the pre-loop screen that only
                // covered the first target. Break with a synthetic
                // `DispatchPolicyRejected` result so no backend is dialed and the
                // post-loop `record_backend_outcome` (which skips the
                // adaptive-concurrency / passive-health charge for that class via
                // `client_side_no_backend_signal`) stays health/breaker-neutral.
                if let Some(reason) = current_target.as_deref().and_then(|t| {
                    crate::proxy::denied_literal_backend_or_dns_override(
                        &t.host,
                        &proxy,
                        &state.env_config.backend_allow_ips,
                    )
                }) {
                    warn!(
                        proxy_id = %proxy.id,
                        reason,
                        "Backend egress policy denied rotated H3 retry target; not dialing"
                    );
                    result = H3BufferedDispatchResult {
                        status: 502,
                        body: Bytes::from_static(
                            br#"{"error":"backend address blocked by egress policy"}"#,
                        ),
                        headers: HashMap::new(),
                        trailers: None,
                        error_class: Some(crate::retry::ErrorClass::DispatchPolicyRejected),
                        request_on_wire: false,
                    };
                    break;
                }

                backend_admission_start = std::time::Instant::now();
                backend_admission_permits = match run_h3_backend_admission_or_send_reject(
                    backend_admission_plugins.as_ref(),
                    &plugins,
                    &mut ctx,
                    &proxy,
                    current_target.as_deref(),
                    http_flavor,
                    grpc_web_response_content_type,
                    initial_response_header_policy_plugins.as_ref(),
                    &mut stream,
                    &state,
                    start_time,
                    plugin_execution_ns,
                    current_cb_target_key.as_deref(),
                    cb_retry_probe_slot_available,
                )
                .await?
                {
                    Ok(permits) => permits,
                    // Probe release happens inside the helper, before the reject write.
                    Err(()) => return Ok(()),
                };

                warn!(
                    proxy_id = %proxy.id,
                    attempt = attempt,
                    max_retries = retry_config.max_retries,
                    connection_error = h3_connection_error(result.request_on_wire, result.error_class),
                    native_h3 = current_dispatch_h3,
                    "Retrying backend request (HTTP/3 frontend)"
                );

                // Re-resolve the effective proxy for the (possibly rotated)
                // retry target from the retry-capped BASE proxy, so this
                // attempt dials with ITS policy port's TLS/SNI/connectTimeout
                // posture instead of inheriting the first target's (see the
                // pre-loop resolution comment above).
                let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(
                    &selected_base_proxy,
                    current_target.as_deref(),
                );
                result = if current_dispatch_h3 {
                    proxy_to_backend_h3(
                        &state,
                        attempt_dispatch_proxy.as_ref(),
                        &current_url,
                        &method,
                        &proxy_headers,
                        &body_data,
                        &ctx.client_ip,
                        socket_ip,
                        current_target.as_deref(),
                        ctx.request_is_secure,
                        ctx.is_early_data,
                        effective_max_response_body_size_bytes,
                    )
                    .await
                } else {
                    // Rotated onto an Unknown/Unsupported H3 target — bridge
                    // via the buffered reqwest path rather than a doomed QUIC
                    // dial. Same-target retries keep `current_dispatch_h3`
                    // locked (no cross-protocol same-target replay).
                    h3_buffered_result_from_backend_response(
                        crate::proxy::proxy_to_backend_retry(
                            &state,
                            selected_base_proxy.as_ref(),
                            &current_url,
                            &method,
                            &proxy_headers,
                            current_target.as_deref(),
                            Some(body_data.as_slice()),
                            false,
                            &plugins,
                            &ctx,
                            &ctx.client_ip,
                            socket_ip,
                            ctx.request_is_secure,
                            hyper::Version::HTTP_3,
                        )
                        .await,
                    )
                };
            }

            (
                result.status,
                result.body,
                result.headers,
                result.trailers,
                result.error_class,
                result.request_on_wire,
                current_cb_target_key,
                current_target,
            )
        } else if let Some(result) = refined_buffered_response {
            (
                result.status,
                result.body,
                result.headers,
                result.trailers,
                result.error_class,
                result.request_on_wire,
                cb_target_key,
                upstream_target.clone(),
            )
        } else {
            // No retry configured — single attempt
            let result = proxy_to_backend_h3(
                &state,
                &proxy,
                &backend_url,
                &method,
                &proxy_headers,
                &body_data,
                &ctx.client_ip,
                socket_ip,
                upstream_target.as_deref(),
                ctx.request_is_secure,
                ctx.is_early_data,
                effective_max_response_body_size_bytes,
            )
            .await;
            (
                result.status,
                result.body,
                result.headers,
                result.trailers,
                result.error_class,
                result.request_on_wire,
                cb_target_key,
                upstream_target.clone(),
            )
        };

        // Record outcome against the final target (may differ from initial after retries).
        // `connection_error` shares the same typed body-on-wire signal as the
        // retry decision and CB above so passive-health / least-latency LB
        // accounting treats a graceful close (or any other post-`send_request`
        // fault) as a successful (post-wire) request for latency purposes —
        // the request did reach the backend.
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            &epoch.load_balancer,
            upstream_balancer.as_ref(),
            final_target.as_deref(),
            final_cb_target_key.as_deref(),
            response_status,
            !h3_request_on_wire,
            h3_error_class,
            cb_retry_probe_slot_available,
            false,
            backend_start.elapsed(),
        );
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            response_status,
            !h3_request_on_wire,
            h3_error_class,
            backend_admission_start.elapsed(),
        );

        let backend_ttfb_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
        let mut response_body = response_body;

        // Capture original response invariants before `after_proxy` runs on this
        // buffered native-H3 path. Unlike the streamed paths, the body here IS
        // buffered, so `compression.transform_response_body` would actually
        // compress it; a response transformer that strips `Content-Range` or
        // `Cache-Control` before compression would otherwise let compression
        // rewrite a representation it must preserve.
        stamp_h3_original_response_metadata(&mut ctx, response_status, &response_headers);

        // Witness the backend's pre-policy value for exactly the field names it
        // also sent as trailers, before the first response-header phase can
        // rewrite them. Allocated only when the backend actually sent trailers,
        // and sized by the trailer count — never by the header count. A response
        // with no trailers gets the unproven witness and never reaches the
        // reconciliation below; that value proves nothing, so any future caller
        // that does reach it fails closed.
        let trailer_policy_witness = match response_trailers.as_ref() {
            Some(trailers) => ResponseTrailerPolicyWitness::capture(trailers, &response_headers),
            None => ResponseTrailerPolicyWitness::Unproven,
        };

        // after_proxy hooks
        let mut after_proxy_rejected = false;
        {
            let phase_start = std::time::Instant::now();
            if let Some(reject) =
                run_after_proxy_hooks(&plugins, &mut ctx, response_status, &mut response_headers)
                    .await
            {
                response_status = reject.status_code;
                response_headers = reject.headers;
                response_headers
                    .entry("content-type".to_string())
                    .or_insert_with(|| "application/json".to_string());
                response_body = reject.body;
                after_proxy_rejected = true;
                // The body/headers are now gateway-synthesized; the backend's
                // trailers no longer describe this response, so drop them
                // (issue #1630).
                response_trailers = None;
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // Sticky session cookie injection. The buffered variant also records the
        // cookie as gateway-owned so a committed-hook deadline cannot strip it.
        if !after_proxy_rejected {
            inject_sticky_cookie_with_deadline_provenance(
                &mut ctx,
                &epoch,
                &proxy,
                upstream_target.as_deref(),
                sticky_cookie_needed,
                &mut response_headers,
            );
        }

        // Set once an earlier body phase selects a gateway-authored terminal
        // response. The transform phase still runs so presentation/protocol
        // transforms can emit the correct wire shape, but final-body validators
        // must not replace the selected error. While this is first set by
        // `on_response_body`, it also records a representation-gate or deadline
        // replacement below. A retained-response capacity terminal is already
        // protocol-correct and skips those later mutating phases entirely.
        let mut response_body_rejected = false;

        // Response-body plugins cannot inspect or transform trailers today, so
        // a chain that actually processes this response body must not forward
        // backend-controlled trailer fields it never saw. The gate is the same
        // two-tier response-body-buffering predicate that chose this path — NOT
        // chain-emptiness: an auth/logging-only proxy never reads the body and
        // keeps the backend's trailers (issue #2941). Body-mutating phases
        // below additionally clear the trailers when they replace the bytes,
        // and surviving trailers are still reconciled field-by-field against
        // the response-header policy before they reach the wire.
        if crate::proxy::response_body_plugins_process_body(&plugins, &ctx) {
            response_trailers = None;
        }

        // on_response_body hooks — only for buffered responses when plugins exist.
        // Mirrors the HTTP/1.1 path in proxy/mod.rs.
        if !after_proxy_rejected && !plugins.is_empty() {
            let phase_start = std::time::Instant::now();
            if normalize_response_body_for_inspection(
                &plugins,
                &mut ctx,
                &mut response_status,
                &mut response_headers,
                &mut response_body,
                initial_response_header_policy_plugins.as_ref(),
            )
            .await
            {
                // Normalization replaced the backend representation, so its
                // body-specific trailers no longer describe the bytes on wire.
                response_trailers = None;
            }
            response_body_rejected = ctx.gateway_capacity_response_selected();
            let mut response_body_reject = None;
            if !response_body_rejected {
                for plugin in plugins.iter() {
                    let deadline = ctx.grpc_deadline_at();
                    let result = match crate::plugins::await_grpc_deadline(
                        deadline,
                        plugin.on_response_body(
                            &mut ctx,
                            response_status,
                            &mut response_headers,
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
                        PluginResult::Continue => {
                            if crate::proxy::install_pending_buffered_response_capacity_refusal(
                                &mut ctx,
                                &mut response_status,
                                &mut response_headers,
                                &mut response_body,
                                crate::proxy::InitialResponseHeaderPolicySource::Prefiltered(
                                    initial_response_header_policy_plugins.as_ref(),
                                ),
                            ) {
                                response_body_rejected = true;
                                response_trailers = None;
                                break;
                            }
                            ctx.record_deadline_response_header_plugin(
                                plugin.as_ref(),
                                &response_headers,
                            );
                        }
                        reject @ PluginResult::Reject { .. }
                        | reject @ PluginResult::RejectBinary { .. } => {
                            let Some(reject) = plugin_result_into_reject_parts(reject) else {
                                tracing::error!(
                                    "Plugin result could not be converted to rejection parts"
                                );
                                response_status = 500;
                                response_headers.clear();
                                response_headers.insert(
                                    "content-type".to_string(),
                                    "application/json".to_string(),
                                );
                                response_body = Bytes::from_static(b"Internal Server Error");
                                // Synthesized error body — backend trailers no
                                // longer apply (issue #1630).
                                response_trailers = None;
                                response_body_rejected = true;
                                break;
                            };
                            debug!(
                                plugin = plugin.name(),
                                status_code = reject.status_code,
                                "Plugin rejected response body (HTTP/3)"
                            );
                            response_body_reject = Some(reject);
                            break;
                        }
                    }
                }
            }
            if let Some(reject) = response_body_reject {
                response_body = apply_plugin_rejection_response(
                    &plugins,
                    &mut ctx,
                    &mut response_status,
                    &mut response_headers,
                    reject,
                )
                .await;
                // Backend trailers no longer describe this (rejected) response.
                response_trailers = None;
                response_body_rejected = true;
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // transform_response_body hooks — only for buffered responses.
        // A capacity terminal is already protocol-correct; do not reopen
        // transforms against it.
        if !after_proxy_rejected && !ctx.gateway_capacity_response_selected() && !plugins.is_empty()
        {
            let phase_start = std::time::Instant::now();
            let (response_replaced, body_transformed) =
                crate::proxy::transform_buffered_response_body_with_deadline(
                    &plugins,
                    &mut ctx,
                    crate::proxy::buffered_response_representation_origin(response_body_rejected),
                    &mut response_status,
                    &mut response_headers,
                    &mut response_body,
                    grpc_web_response_content_type,
                    initial_response_header_policy_plugins.as_ref(),
                )
                .await;
            if response_replaced || body_transformed {
                // A transform or deadline replacement changes the bytes sent to
                // the client. Backend trailers describing the original body no
                // longer apply (issue #1630).
                response_trailers = None;
            }
            response_body_rejected |= response_replaced;
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        if !after_proxy_rejected && !response_body_rejected && !plugins.is_empty() {
            let phase_start = std::time::Instant::now();
            let mut response_body_reject = None;
            for plugin in plugins.iter() {
                let deadline = ctx.grpc_deadline_at();
                let result = match crate::plugins::await_grpc_deadline(
                    deadline,
                    plugin.on_final_response_body(
                        &mut ctx,
                        response_status,
                        &response_headers,
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
                        let Some(reject) = plugin_result_into_reject_parts(reject) else {
                            tracing::error!(
                                "Plugin result could not be converted to rejection parts"
                            );
                            response_status = 500;
                            response_headers.clear();
                            response_headers
                                .insert("content-type".to_string(), "application/json".to_string());
                            response_body = Bytes::from_static(b"Internal Server Error");
                            // Synthesized error body — backend trailers no
                            // longer apply (issue #1630).
                            response_trailers = None;
                            break;
                        };
                        debug!(
                            plugin = plugin.name(),
                            status_code = reject.status_code,
                            "Plugin rejected finalized response body (HTTP/3)"
                        );
                        response_body_reject = Some(reject);
                        break;
                    }
                }
            }
            if let Some(reject) = response_body_reject {
                response_body = apply_plugin_rejection_response(
                    &plugins,
                    &mut ctx,
                    &mut response_status,
                    &mut response_headers,
                    reject,
                )
                .await;
                // Backend trailers no longer describe this (rejected) response.
                response_trailers = None;
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        response_headers
            .entry("content-type".to_string())
            .or_insert_with(|| "application/json".to_string());

        if capabilities.has(crate::plugin_cache::PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK) {
            let phase_start = std::time::Instant::now();
            if crate::proxy::run_deadline_bounded_response_committed_hooks(
                plugin_cache_view.response_committed_plugins(),
                &mut ctx,
                &mut response_status,
                &mut response_headers,
                &mut response_body,
                initial_response_header_policy_plugins.as_ref(),
            )
            .await
            {
                response_trailers = None;
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // Final protocol-aware strip after after_proxy / committed hooks
        // (RFC 9114 §4.2): hop-by-hop / Connection-listed fields plus
        // Content-Length derived from the buffered body (HEAD preserves a
        // valid representation length instead of inventing 0). Shared with the
        // H3 cross-protocol bridge's buffered writer so the two cannot drift.
        let framing = ClientResponseFraming::for_buffered_response(
            &ctx.method,
            response_status,
            response_body.len(),
        );
        sanitize_client_response_headers_for_wire(&mut response_headers, framing);

        // Reconcile surviving backend trailers with the response-header policy
        // this path already applied. Every response-header phase — `after_proxy`,
        // sticky-cookie injection, committed hooks — sees only the INITIAL header
        // map, so a backend trailer repeating a governed field name would land on
        // the wire after the policy boundary and undo it. Runs once, after the
        // last header phase, against the precomputed per-proxy policy-name union;
        // an auth/logging-only chain contributes no names and mutates no headers,
        // so its trailers pass through untouched.
        // Same request-aware resolution the streaming relays received, reused so
        // buffered and streaming H3 cannot disagree about whether the
        // fail-closed arm is armed for this request.
        let unbounded_trailer_policy = response_trailer_governance.unbounded;
        if let Some(trailers) = response_trailers.as_mut() {
            // Strip hop-by-hop trailer names BEFORE reconciling, matching the
            // streaming helper's order (`finish_h3_response_with_backend_trailers`).
            // A hop-by-hop field is dropped either way, so the wire outcome is
            // identical, but reconciling first would count it as a
            // policy-governed removal and inflate the telemetry below.
            strip_response_hop_by_hop_trailers(trailers);
            let removed = reconcile_backend_trailers_with_response_policy(
                trailers,
                &response_headers,
                &trailer_policy_witness,
                plugin_cache_view.response_trailer_policy_names(),
                plugin_cache_view.response_trailer_policy_prefixes(),
                GatewayOwnedResponseHeaders::default(),
                // Buffered native-H3 send path: plain flavor only (a native gRPC
                // dispatch goes to `dispatch_grpc_native_h3`), so no exemption.
                TrailerSectionKind::PlainResponse,
                unbounded_trailer_policy,
            );
            if removed > 0 {
                debug!(
                    proxy_id = %proxy.id,
                    removed,
                    "buffered H3: dropped backend trailer fields governed by response header policy"
                );
            }
        }

        // Build and send buffered response
        let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
        let resp_builder =
            apply_response_headers(Response::builder().status(status), &response_headers);

        let resp = resp_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 proxy response: {}", e))?;
        let grpc_deadline_at = ctx.grpc_deadline_at();
        let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
        let response_body_bytes = response_body.len() as u64;
        let mut bytes_received = 0;
        let mut body_completed = true;
        let mut client_disconnected = false;
        let mut body_error_class = None;
        let mut downstream_write_error: Option<anyhow::Error> = None;
        macro_rules! await_buffered_h3_write {
            ($write:expr) => {{
                match if terminal_gateway_deadline {
                    crate::http3::stream_util::await_terminal_response_write_before_deadline(
                        grpc_deadline_at,
                        $write,
                    )
                    .await
                } else {
                    crate::http3::stream_util::await_response_write_before_deadline(
                        grpc_deadline_at,
                        $write,
                    )
                    .await
                } {
                    Ok(()) => true,
                    Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => {
                        body_completed = false;
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        downstream_write_error = Some(error.into());
                        false
                    }
                    Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                        crate::proxy::insert_grpc_error_metadata(
                            &mut ctx.metadata,
                            crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                        );
                        crate::http3::stream_util::abort_response_stream(&mut stream);
                        crate::http3::stream_util::halt_request_body(&mut stream);
                        body_completed = false;
                        false
                    }
                }
            }};
        }
        let response_headers_sent = await_buffered_h3_write!(stream.send_response(resp));
        if response_headers_sent
            && !response_body.is_empty()
            && await_buffered_h3_write!(stream.send_data(response_body))
        {
            bytes_received = response_body_bytes;
        }

        // Backend trailers survive to here only when no response-body plugin
        // phase processed this response (gate above), no mutation / reject /
        // normalize arm replaced the bytes, and the response-policy
        // reconciliation above kept the remaining fields.
        // Auth/logging-only plugins must not wipe trailers merely because the
        // plugin chain is nonempty (#2941).

        // Forward backend response trailers, if any (issue #1630).
        // Response-direction hop-by-hop trailer names (RFC 9110 §7.6.1) were
        // already stripped above, with the same helper the streaming path's
        // `finish_h3_response_with_backend_trailers` uses, immediately before
        // the policy reconciliation. Send what survived before FIN. An empty
        // map is skipped — emit a bare `finish()` exactly as before.
        if body_completed {
            match response_trailers {
                Some(trailers) => {
                    if !trailers.is_empty() {
                        let trailer_write = if terminal_gateway_deadline {
                            crate::http3::stream_util::await_terminal_response_write_before_deadline(
                                grpc_deadline_at,
                                stream.send_trailers(trailers),
                            )
                            .await
                        } else {
                            crate::http3::stream_util::await_response_write_before_deadline(
                                grpc_deadline_at,
                                stream.send_trailers(trailers),
                            )
                            .await
                        };
                        match trailer_write {
                            Ok(()) => {}
                            Err(crate::http3::stream_util::H3ResponseWriteError::Write(err)) => {
                                // The trailers are valid for the backend but the H3
                                // client could not accept them (e.g. HeaderTooBig).
                                // The body was sent, so drop the trailers and still
                                // try a clean FIN, preserving issue #1630 behavior.
                                debug!(
                                    error = %err,
                                    "H3 send_trailers failed on buffered response; dropping trailers and finishing cleanly"
                                );
                            }
                            Err(
                                crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded,
                            ) => {
                                crate::proxy::insert_grpc_error_metadata(
                                    &mut ctx.metadata,
                                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                                );
                                crate::http3::stream_util::abort_response_stream(&mut stream);
                                crate::http3::stream_util::halt_request_body(&mut stream);
                                body_completed = false;
                            }
                        }
                    }
                    if body_completed {
                        let _ = await_buffered_h3_write!(stream.finish());
                    }
                }
                None => {
                    let _ = await_buffered_h3_write!(stream.finish());
                }
            }
        }

        // Transaction logging follows downstream response completion so a
        // deadline-triggered reset cannot be reported as a full successful
        // buffered response. `raw_request_body_bytes` remains the pre-transform
        // wire size, while `bytes_received` advances only after DATA completes.
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let gateway_processing_ms = total_ms - backend_total_ms;
        let gateway_overhead_ms = (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            auth_method: ctx.auth_method,
            http_method: method,
            request_path: original_request_path.clone(),
            proxy_id: Some(proxy.id.clone()),
            proxy_name: proxy.name.clone(),
            backend_target: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip,
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            error_class: h3_error_class,
            client_disconnected,
            body_error_class,
            body_completed,
            bytes_sent: raw_request_body_bytes,
            bytes_received,
            metadata: crate::proxy::clone_log_metadata(&ctx),
            ai_usage_export: ctx.ai_usage_export.clone(),
            proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
            ..TransactionSummary::default()
        };
        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
        record_request(&state, response_status);
        if let Some(error) = downstream_write_error {
            return Err(error);
        }
    }

    Ok(())
}

pub(crate) fn h3_plugin_protocol_for_request(
    flavor: HttpFlavor,
    _grpc_web_request: bool,
) -> ProxyProtocol {
    h3_plugin_protocol_for_flavor(flavor)
}

fn h3_plugin_protocol_for_flavor(flavor: HttpFlavor) -> ProxyProtocol {
    match flavor {
        HttpFlavor::Plain => ProxyProtocol::Http,
        HttpFlavor::Grpc => ProxyProtocol::Grpc,
        HttpFlavor::WebSocket => ProxyProtocol::WebSocket,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_h3_backend_path_plugins_or_send_reject(
    backend_path_plugins: &[Arc<dyn Plugin>],
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    backend_path: &str,
    original_request_path: &str,
    flavor: HttpFlavor,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: &ProxyState,
    start_time: std::time::Instant,
    plugin_execution_ns: &mut u64,
    grpc_web_response_content_type: Option<&str>,
) -> Result<bool, anyhow::Error> {
    let phase_start = std::time::Instant::now();
    for plugin in backend_path_plugins {
        let deadline = ctx.grpc_deadline_at();
        match crate::plugins::await_request_plugin_deadline_with_provenance(
            deadline,
            plugin.on_backend_path_resolved(ctx, backend_path),
        )
        .await
        .into_plugin_result(ctx)
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let Some(reject) = plugin_result_into_reject_parts(reject) else {
                    error!(
                        plugin = plugin.name(),
                        "H3 backend-path plugin rejection could not be normalized"
                    );
                    run_h3_reject_response_committed_hooks(
                        plugins,
                        ctx,
                        flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await;
                    let log_status_code = h3_reject_log_status_and_metadata(
                        ctx,
                        flavor,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"Internal Server Error",
                        &HashMap::new(),
                    );
                    record_request(state, log_status_code);
                    send_h3_plugin_reject_flavor_aware(
                        stream,
                        plugins,
                        ctx,
                        flavor,
                        grpc_web_response_content_type,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(b"Internal Server Error"),
                        &HashMap::new(),
                    )
                    .await?;
                    return Ok(false);
                };
                let mut headers = reject.headers;
                let mut reject_status = reject.status_code;
                let mut reject_body = reject.body;
                apply_reject_after_proxy_and_synthetic_body_hooks(
                    plugins,
                    ctx,
                    &mut reject_status,
                    &mut headers,
                    &mut reject_body,
                    matches!(flavor, HttpFlavor::Grpc),
                    false,
                )
                .await;
                *plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
                let http_status = StatusCode::from_u16(reject_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                run_h3_reject_response_committed_hooks(
                    plugins,
                    ctx,
                    flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await;
                let log_status_code = h3_reject_log_status_and_metadata(
                    ctx,
                    flavor,
                    http_status,
                    &reject_body,
                    &headers,
                );
                record_request(state, log_status_code);
                log_rejected_request_with_path(
                    plugins,
                    ctx,
                    log_status_code,
                    start_time,
                    "on_backend_path_resolved",
                    *plugin_execution_ns,
                    Some(original_request_path),
                )
                .await;
                send_h3_plugin_reject_flavor_aware(
                    stream,
                    plugins,
                    ctx,
                    flavor,
                    grpc_web_response_content_type,
                    http_status,
                    reject_body.clone(),
                    &headers,
                )
                .await?;
                return Ok(false);
            }
        }
    }
    *plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn run_h3_backend_admission_or_send_reject(
    backend_admission_plugins: &[Arc<dyn Plugin>],
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: &ProxyState,
    start_time: std::time::Instant,
    plugin_execution_ns: u64,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
) -> Result<Result<Option<BackendAdmissionPermitSet>, ()>, anyhow::Error> {
    match crate::proxy::backend_dispatch::run_backend_admission_plugins(
        backend_admission_plugins,
        ctx,
        proxy,
        upstream_target,
        h3_plugin_protocol_for_flavor(flavor),
    ) {
        Ok(permits) => Ok(Ok(permits)),
        Err(rejection) => {
            let mut rejection = rejection;
            // Release any reserved circuit-breaker HALF_OPEN probe BEFORE writing
            // the reject body: the write below propagates errors with `?`, so if
            // the H3 client resets mid-write this returns early. The caller frees
            // the probe only on the `Ok(Err(()))` arm, so releasing here guarantees
            // the slot is freed even when the reject write fails.
            release_h3_circuit_breaker_probe_on_admission_reject(
                state,
                proxy,
                cb_target_key,
                cb_is_half_open_probe,
            );
            let mut headers = rejection.headers;
            crate::proxy::apply_replaceable_after_proxy_hooks_to_rejection(
                plugins,
                ctx,
                &mut rejection.status_code,
                &mut rejection.body,
                &mut headers,
            )
            .await;
            let mut http_status = StatusCode::from_u16(rejection.status_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            let deadline_replaced = run_h3_deadline_bounded_reject_committed_hooks(
                plugins,
                ctx,
                flavor,
                grpc_web_response_content_type,
                http_status,
                rejection.body.clone(),
                &headers,
                initial_response_header_policy_plugins,
            )
            .await;
            if deadline_replaced {
                http_status = replace_buffered_h3_response_with_grpc_deadline(
                    ctx,
                    grpc_web_response_content_type,
                    &mut headers,
                    &mut rejection.body,
                    initial_response_header_policy_plugins,
                );
            }
            let log_status_code = if deadline_replaced {
                StatusCode::OK.as_u16()
            } else {
                h3_reject_log_status_and_metadata(
                    ctx,
                    flavor,
                    http_status,
                    &rejection.body,
                    &headers,
                )
            };
            record_request(state, log_status_code);
            log_rejected_request(
                plugins,
                ctx,
                log_status_code,
                start_time,
                &rejection.plugin_name,
                plugin_execution_ns,
            )
            .await;
            if deadline_replaced && grpc_web_response_content_type.is_some() {
                // gRPC-Web deadline frame: gateway-generated body written
                // verbatim, so its length is authoritative.
                send_h3_finalized_reject_response(
                    stream,
                    StatusCode::OK,
                    rejection.body.clone(),
                    &headers,
                    RejectBodyDisposition::WireBody,
                )
                .await?;
            } else {
                send_h3_plugin_reject_flavor_aware(
                    stream,
                    plugins,
                    ctx,
                    flavor,
                    grpc_web_response_content_type,
                    http_status,
                    rejection.body.clone(),
                    &headers,
                )
                .await?;
            }
            Ok(Err(()))
        }
    }
}

fn release_h3_circuit_breaker_probe_on_admission_reject(
    state: &ProxyState,
    proxy: &Proxy,
    target_key: Option<&str>,
    is_half_open_probe: bool,
) {
    if !is_half_open_probe {
        return;
    }
    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state.circuit_breaker_cache.get_or_create(
            &proxy.namespace,
            &proxy.id,
            target_key,
            cb_config,
        );
        cb.record_neutral(true);
    }
}

fn record_h3_backend_admission_outcome(
    permits: &mut Option<BackendAdmissionPermitSet>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<crate::retry::ErrorClass>,
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

fn build_h3_backend_url_for_flavor(
    proxy: &Proxy,
    flavor: HttpFlavor,
    path: &str,
    query_string: &str,
    strip_len: usize,
    upstream_target: Option<&UpstreamTarget>,
) -> String {
    if flavor == HttpFlavor::WebSocket {
        let (effective_host, effective_port, target_path) = if let Some(target) = upstream_target {
            (target.host.as_str(), target.port, target.path.as_deref())
        } else {
            (proxy.backend_host.as_str(), proxy.backend_port, None)
        };
        return crate::proxy::build_websocket_backend_url_with_target(
            proxy,
            path,
            query_string,
            effective_host,
            effective_port,
            strip_len,
            target_path,
        );
    }

    if let Some(target) = upstream_target {
        crate::proxy::build_backend_url_with_target(
            proxy,
            path,
            query_string,
            &target.host,
            target.port,
            strip_len,
            target.path.as_deref(),
        )
    } else {
        crate::proxy::build_backend_url(proxy, path, query_string, strip_len)
    }
}

/// Build the h3 backend header list from proxy request headers.
///
/// Strips hop-by-hop headers per RFC 7230 §6.1, handles Host/preserve_host_header,
/// and adds X-Forwarded-*, Via, and Forwarded proxy headers. Shared between the
/// streaming and buffered backend dispatch paths.
///
/// `upstream_target` carries the load-balanced backend selection. When the
/// proxy is upstream-backed and `preserve_host_header == false`, the Host
/// header is rewritten to **the selected target's host** — not
/// `proxy.backend_host`. Without this, the H3 connection routes to
/// `upstream_target.host` while the synthesized Host points at the proxy's
/// template `backend_host`, producing a Host/authority mismatch that strict
/// backends reject and that breaks virtual-host routing on the upstream.
/// Falls back to `proxy.backend_host` only when no upstream selection is
/// available (single-target proxies).
#[allow(clippy::too_many_arguments)]
fn build_h3_backend_headers(
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    headers: &HashMap<String, String>,
    client_ip: &str,
    xff_append_ip: &str,
    state: &ProxyState,
    request_is_secure: bool,
    is_early_data: bool,
) -> Vec<(http::header::HeaderName, http::header::HeaderValue)> {
    let mut h3_headers = Vec::with_capacity(headers.len() + 5);

    let effective_backend_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(proxy.backend_host.as_str());

    let connection_listed_strip = parse_connection_listed_from_str_map(headers);
    for (k, v) in headers {
        match k.as_str() {
            "host" | ":authority" => {
                let host_val = if proxy.preserve_host_header {
                    v.as_str()
                } else {
                    effective_backend_host
                };
                if let Ok(val) = http::header::HeaderValue::from_str(host_val) {
                    h3_headers.push((http::header::HOST, val));
                }
            }
            // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
            n if is_backend_request_strip_header(n) => continue,
            // Ferrum regenerates X-Forwarded-* (always) and Forwarded when
            // `add_forwarded_header` is set. Copying the inbound value too
            // would duplicate the header (reqwest appends; this Vec push
            // path would leave the spoofed element first).
            n if is_proxy_owned_forwarding_header(n, state.add_forwarded_header) => continue,
            // RFC 9110 §7.6.1 Connection-listed strip — see
            // `parse_connection_listed_from_str_map`.
            n if connection_listed_strip.iter().any(|s| s == n) => continue,
            // RFC 8470 §5.2: `Early-Data` is set by the intermediary that
            // forwarded the request over 0-RTT, never by the originating
            // client. Strip any client-supplied value here so a malicious
            // or buggy client cannot trick the backend into believing the
            // request was carried over 0-RTT (or, conversely, suppress our
            // own injection of `Early-Data: 1` below). Treated as a
            // hop-by-hop-style header on the request path: gateway
            // re-injects the correct value only when the request actually
            // arrived as 0-RTT early data.
            "early-data" => continue,
            k if k.starts_with(':') => continue,
            _ => {
                if let (Ok(name), Ok(val)) = (
                    http::header::HeaderName::from_bytes(k.as_bytes()),
                    http::header::HeaderValue::from_str(v),
                ) {
                    h3_headers.push((name, val));
                }
            }
        }
    }

    // RFC 8470 §5.2: when this request arrived over TLS 1.3 0-RTT early data
    // and the gateway forwards it to the backend, advertise `Early-Data: 1`
    // so the origin server can apply its own replay-safety policy (return
    // 425 Too Early, defer the response, etc.). The gateway has already
    // gated by `state.early_data_methods`, but the backend may have
    // stricter policy than the gateway's allow-list.
    if is_early_data {
        h3_headers.push((
            http::header::HeaderName::from_static("early-data"),
            http::header::HeaderValue::from_static("1"),
        ));
    }

    // X-Forwarded-For — same append-the-immediate-peer (+ resolved-client
    // seeding) semantics as the H1/H2 paths; see `proxy::build_xff_value`.
    let xff = crate::proxy::build_xff_value(
        headers.get("x-forwarded-for").map(String::as_str),
        client_ip,
        xff_append_ip,
        &state.trusted_proxies,
    );
    if let Ok(val) = http::header::HeaderValue::from_str(&xff) {
        h3_headers.push((
            http::header::HeaderName::from_static("x-forwarded-for"),
            val,
        ));
    }

    let request_scheme = if request_is_secure { "https" } else { "http" };

    // X-Forwarded-Proto
    h3_headers.push((
        http::header::HeaderName::from_static("x-forwarded-proto"),
        http::header::HeaderValue::from_static(request_scheme),
    ));

    // X-Forwarded-Host
    if let Some(host) = headers.get("host").or_else(|| headers.get(":authority"))
        && let Ok(val) = http::header::HeaderValue::from_str(host)
    {
        h3_headers.push((
            http::header::HeaderName::from_static("x-forwarded-host"),
            val,
        ));
    }

    // Via
    if let Some(ref via) = state.via_header_http3
        && let Ok(val) = http::header::HeaderValue::from_str(via)
    {
        h3_headers.push((http::header::HeaderName::from_static("via"), val));
    }

    // Forwarded (RFC 7239)
    if state.add_forwarded_header {
        let host = headers
            .get("host")
            .or_else(|| headers.get(":authority"))
            .map(|s| s.as_str());
        let fwd = crate::proxy::build_forwarded_value(client_ip, request_scheme, host);
        if let Ok(val) = http::header::HeaderValue::from_str(&fwd) {
            h3_headers.push((http::header::HeaderName::from_static("forwarded"), val));
        }
    }

    h3_headers
}

/// Classify an h3/quinn error into an `ErrorClass` for retry and CB recording.
/// Inject a sticky-session `Set-Cookie` header when the LB strategy is cookie-based
/// and the cookie was not present in the original request.
///
/// Returns whether a cookie was actually injected. Buffered callers use this to
/// record `set-cookie` as gateway-owned in gRPC-deadline provenance before
/// `response_committed` hooks run — mirroring the H1/H2 gRPC and plain buffered
/// paths. Without that record, a committed hook that exhausts the RPC deadline
/// rebuilds the response from gateway-owned headers only, and the freshly
/// injected affinity cookie is stripped, silently breaking stickiness for the
/// client. Streaming callers may ignore the result: their headers are already on
/// the wire before any deadline rebuild can run.
pub(crate) fn inject_sticky_cookie(
    epoch: &crate::request_epoch::RequestEpoch,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    sticky_cookie_needed: bool,
    response_headers: &mut HashMap<String, String>,
) -> bool {
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target)
    {
        let strategy = crate::proxy::backend_dispatch::hash_on_strategy_for_selected_target(
            proxy,
            &epoch.load_balancer,
            upstream_id,
            target,
        );
        if let crate::load_balancer::HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = LoadBalancerCache::get_upstream_from(
                &epoch.load_balancer,
                &proxy.namespace,
                upstream_id,
            );
            let default_cc = crate::config::types::HashOnCookieConfig::default();
            let cookie_config = upstream
                .as_ref()
                .and_then(|u| u.hash_on_cookie_config.as_ref())
                .unwrap_or(&default_cc);
            let cookie_val =
                crate::proxy::build_sticky_cookie_header(cookie_name, target, cookie_config);
            response_headers
                .entry("set-cookie".to_string())
                .and_modify(|v| {
                    v.push('\n');
                    v.push_str(&cookie_val);
                })
                .or_insert(cookie_val);
            return true;
        }
    }
    false
}

/// Inject the sticky-affinity cookie on a BUFFERED H3 response and, when one was
/// written, declare it gateway-owned in gRPC-deadline provenance.
///
/// Every buffered H3 path must use this instead of calling
/// [`inject_sticky_cookie`] directly. A `response_committed` hook that exhausts
/// the RPC deadline rebuilds the response from gateway-owned headers only, so an
/// unrecorded affinity cookie is stripped and the client silently loses
/// stickiness. Recording here — before any committed hook runs — mirrors the
/// H1/H2 gRPC and plain buffered paths in `src/proxy/mod.rs`.
///
/// Streaming paths deliberately keep calling [`inject_sticky_cookie`]: their
/// headers reach the wire before a deadline can rebuild anything.
pub(crate) fn inject_sticky_cookie_with_deadline_provenance(
    ctx: &mut RequestContext,
    epoch: &crate::request_epoch::RequestEpoch,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    sticky_cookie_needed: bool,
    response_headers: &mut HashMap<String, String>,
) -> bool {
    if !inject_sticky_cookie(
        epoch,
        proxy,
        upstream_target,
        sticky_cookie_needed,
        response_headers,
    ) {
        return false;
    }
    // The injection APPENDS onto any co-present backend cookie, so it records
    // mutations rather than declaring ownership — ownership means whole-value
    // replacement and retires the backend cookie baseline, which would credit a
    // backend cookie as gateway output. `record_deadline_response_header_…`
    // returns immediately when no deadline provenance is being tracked, so
    // ordinary sticky traffic pays nothing here (same shape as the H1/H2
    // buffered sites in `src/proxy/mod.rs`).
    ctx.record_deadline_response_header_mutations(response_headers);
    true
}

/// Whether an H3 dispatch failure counts as a connect-class (pre-wire) backend
/// failure for circuit-breaker / adaptive-concurrency accounting.
///
/// `request_on_wire` is the authoritative H3 signal — `connection_error` is its
/// negation — for every *transport* class. The one exception is a gateway-side
/// egress denial (`DispatchPolicyRejected`): it dialed no backend, so it must be
/// neutral even though `request_on_wire` is false, otherwise adaptive concurrency
/// shrinks the limit and the breaker trips for a policy denial. This is the same
/// narrow override the native-H3 dispatch sites apply inline; `DispatchPolicyRejected`
/// is a gateway class, not a transport class that could disagree with the signal.
fn h3_connection_error(
    request_on_wire: bool,
    error_class: Option<crate::retry::ErrorClass>,
) -> bool {
    !request_on_wire
        && !matches!(
            error_class,
            Some(crate::retry::ErrorClass::DispatchPolicyRejected)
        )
}

fn classify_h3_error(e: &crate::http3::client::H3PoolError) -> crate::retry::ErrorClass {
    // Graceful remote close (`H3_NO_ERROR` ApplicationClose / GOAWAY) at
    // the response read boundary is the peer's spec-legal teardown
    // signal — see RFC 9114 §8.1. Surface it as a distinct class so
    // `is_h3_transport_error_class` returns false and the gateway
    // suppresses `mark_h3_unsupported`. The 502 still propagates because
    // we have no headers to forward, but the next request stays on H3.
    if e.is_graceful_close() {
        return crate::retry::ErrorClass::GracefulRemoteClose;
    }
    // Typed `backend_read_timeout_ms` deadline signal from the pool —
    // classify deterministically instead of relying on the "timeout"
    // substring fallback. `ReadWriteTimeout` is excluded from
    // `is_h3_transport_error_class`, so this never drives
    // `mark_h3_unsupported`.
    if e.is_read_timeout() {
        return crate::retry::ErrorClass::ReadWriteTimeout;
    }
    // Delegate to the shared HTTP/3 classifier, which walks the source chain
    // for typed quinn::ConnectionError / quinn::ConnectError / io::Error
    // variants before falling back to string heuristics. This gives more
    // accurate classifications (e.g., distinguishing ApplicationClosed from
    // a generic "closed" match) than the previous string-only approach.
    //
    // `H3PoolError` carries the body-on-wire signal alongside the anyhow
    // chain; classification looks only at the chain. Callers that need to
    // override `connection_error` based on whether any internal pool
    // attempt committed the body should consult `e.request_on_wire()`
    // separately rather than re-deriving it from `error_class`.
    crate::http3::client::classify_http3_error(e.as_error().as_ref())
}

/// Select the client-facing status + JSON body for a native-H3 backend
/// dispatch failure. A `backend_read_timeout_ms` deadline expiry maps to
/// 504 `{"error":"Backend timeout"}` — matching the direct-H2 / HBONE /
/// sidecar-mTLS read-timeout arms in `crate::proxy` — while every other
/// failure keeps the generic 502 `{"error":"Backend unavailable"}`.
/// The canonical H3 backend-failure body. Deliberately `&'static str`: the
/// `send_h3_response` consumers want a string, and the buffered-dispatch
/// consumers can reach `Bytes::from_static(..)` from the same static lifetime,
/// so neither side has to copy the literal.
fn h3_backend_failure_status_body(
    e: &crate::http3::client::H3PoolError,
) -> (StatusCode, &'static str) {
    if e.is_read_timeout() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            r#"{"error":"Backend timeout"}"#,
        )
    } else {
        (
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend unavailable"}"#,
        )
    }
}

fn is_h3_client_request_body_disconnect(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    // A malformed/undecodable client request-trailer block is a client-side
    // request fault, not a backend failure — account it neutrally (like a body
    // disconnect) so it never trips CB / passive health. See the trailer-forward
    // arm in `client.rs::do_request_streaming_body`.
    lower.contains("client disconnected while sending request body")
        || lower.contains("malformed client request trailers")
}

fn h3_streaming_body_failure_outcome(
    is_client_request_body_disconnect: bool,
    is_read_timeout: bool,
    h3_error_class: crate::retry::ErrorClass,
) -> (bool, Option<crate::retry::ErrorClass>) {
    if is_client_request_body_disconnect {
        (false, Some(crate::retry::ErrorClass::ClientDisconnect))
    } else if is_read_timeout {
        // `backend_read_timeout_ms` expired after the request was committed
        // to the backend (post-wire). Report `connection_error=false` so
        // CB / passive health / adaptive concurrency see a 504 status fault
        // — matching the direct-H2 / HBONE read-timeout arms — rather than
        // a transport-level connection failure.
        (false, Some(h3_error_class))
    } else {
        (true, Some(h3_error_class))
    }
}

/// Outcome of a streaming H3 proxy operation.
///
/// Carries pre-stream fields (status/error_class) and body-streaming outcome
/// fields so the transaction log at the call site reflects the actual
/// client-visible result, including mid-stream disconnects and partial byte
/// counts. Response headers are flushed to the client before this struct is
/// constructed, so they are intentionally not stored here — the call sites
/// that need them already hold a local copy via `response_headers`.
///
/// # Why H3 does not use `DeferredTransactionLogger`
///
/// HTTP/1.1, HTTP/2, and gRPC proxies return a `ProxyBody` to hyper and let
/// hyper drive the body to completion AFTER the handler function has
/// returned. A deferred-log mechanism (fires when the body reaches a
/// terminal state) is therefore necessary to capture the real outcome.
///
/// The H3 path is different: `proxy_to_backend_h3_streaming` drives the
/// QUIC send stream to completion synchronously within its own scope (the
/// `'outer` loop above). By the time the function returns, body_completed /
/// bytes_streamed / client_disconnected / body_error_class are already
/// known — the caller just reads them off `H3StreamResult` and populates
/// the summary synchronously. No deferred logger, no `Arc<StreamingMetrics>`,
/// no `Drop` safety net.
///
/// This means H3 summary sites are the only HTTP-family sites that populate
/// terminal body outcome fields at the same synchronous point in the code.
/// Streamed responses still follow the shared unknown-backend-total contract
/// (`LATENCY_UNKNOWN_MS` for backend total / gateway fields) because concurrent
/// backend-body and client-delivery lifetime cannot be separated on the pipe;
/// only `latency_total_ms` is always concrete. `latency_backend_ttfb_ms` is
/// concrete from `backend_admission_elapsed` only when response headers were
/// observed; pre-header dispatch failures report `LATENCY_UNKNOWN_MS`.
struct H3StreamResult {
    /// Client-facing HTTP status (what was/will be sent downstream). On an
    /// `after_proxy` reject or a gateway-side size-limit rejection this is the
    /// gateway's policy status, NOT the backend's — use [`Self::backend_status`]
    /// for circuit-breaker / passive-health accounting.
    status: u16,
    /// True backend response status (or the synthesized status when no backend
    /// response was received). Circuit-breaker and passive-health accounting
    /// must key off this, never `status`: a plugin rejecting a healthy 200 with
    /// a 5xx must not penalize the backend, and a plugin masking a backend 503
    /// behind a 4xx must not hide the failure. Mirrors the buffered/H1/H2 paths,
    /// which record the backend status before applying the after-proxy override.
    backend_status: u16,
    error_class: Option<crate::retry::ErrorClass>,
    body_completed: bool,
    bytes_streamed: u64,
    client_disconnected: bool,
    body_error_class: Option<crate::retry::ErrorClass>,
    /// Mirrors [`crate::http3::client::H3PoolError::request_on_wire`] —
    /// `false` only when a pre-headers dispatch failure occurred where
    /// no internal pool attempt committed the request to the backend's
    /// application layer (DNS / TLS / connect / pre-`send_request`).
    /// `true` for every other case: success, mid-body abort,
    /// post-`send_request` dispatch failure, graceful close at
    /// `recv_response`, ResponseBodyTooLarge, client disconnect.
    ///
    /// This is the typed signal the streaming-path
    /// `record_backend_outcome` site uses to drive `connection_error`
    /// for dispatch failures. See the call site comment block for why
    /// re-deriving from `error_class` is wrong (a connect-phase QUIC
    /// reset can string-classify as `ConnectionReset` even though no
    /// request reached the backend).
    request_on_wire: bool,
    /// Elapsed time from backend-admission acquisition until the backend
    /// produced response headers or a pre-headers dispatch error. Streaming
    /// callers reuse this after downstream body relay completes so adaptive
    /// concurrency samples backend health rather than client backpressure.
    backend_admission_elapsed: std::time::Duration,
}

enum H3RefinedResponse {
    Streamed(H3StreamResult),
    Buffered(H3BufferedDispatchResult),
}

/// Build the `H3StreamResult` for a pre-headers backend-dispatch failure on the
/// H3 streaming / refined paths.
///
/// `status` is the gateway-synthesized reject status already written to the
/// client (502 generic, or 504 for a `backend_read_timeout_ms` expiry — see
/// [`h3_backend_failure_status_body`]). `reject_sent` is whether that write
/// reached the client. A failed write is reported as `client_disconnected`
/// rather than propagated as an error: these dispatch functions start
/// least-connections LB tracking before dispatch and their caller releases
/// the active-connection count via `record_backend_outcome` off the returned
/// result, so returning `Err` on a failed reject write would skip that
/// accounting and leak the count. The backend never produced a response here,
/// so `backend_status` is the same gateway-synthesized status.
fn h3_backend_unavailable_stream_result(
    status: u16,
    error_class: crate::retry::ErrorClass,
    request_on_wire: bool,
    reject_sent: bool,
    backend_admission_elapsed: std::time::Duration,
) -> H3StreamResult {
    H3StreamResult {
        status,
        backend_status: status,
        error_class: Some(error_class),
        body_completed: false,
        bytes_streamed: 0,
        client_disconnected: !reject_sent,
        body_error_class: None,
        request_on_wire,
        backend_admission_elapsed,
    }
}

/// Backend TTFB for a completed native-H3 stream result.
///
/// `backend_admission_elapsed` is always preserved for adaptive-concurrency
/// sampling. TTFB itself requires observed response headers:
/// * pre-header dispatch failure (`error_class` set, `body_error_class` unset,
///   via [`h3_backend_unavailable_stream_result`]) → `LATENCY_UNKNOWN_MS`
/// * content-length `ResponseBodyTooLarge` reject after headers → real TTFB
/// * success / body-phase outcomes → real TTFB from admission elapsed
fn h3_stream_backend_ttfb_ms(result: &H3StreamResult) -> f64 {
    match (result.error_class, result.body_error_class) {
        (Some(crate::retry::ErrorClass::ResponseBodyTooLarge), None) => {
            // Headers were received before the gateway size-limit reject.
            result.backend_admission_elapsed.as_secs_f64() * 1000.0
        }
        (Some(_), None) => crate::plugins::LATENCY_UNKNOWN_MS,
        _ => result.backend_admission_elapsed.as_secs_f64() * 1000.0,
    }
}

/// Record original backend response invariants before any `after_proxy` hook can
/// rewrite response headers, mirroring the H1/H2 stamp in `proxy/mod.rs`.
/// Compression preserves these markers even if a response transformer removes
/// `Content-Range` or `Cache-Control` before compression's own header hook.
pub(crate) fn stamp_h3_original_response_metadata(
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &HashMap<String, String>,
) {
    crate::proxy::stamp_original_response_metadata(ctx, response_status, response_headers);
}

async fn run_h3_streaming_after_proxy_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &mut HashMap<String, String>,
    plugin_execution_ns: &mut u64,
) -> Option<crate::proxy::AfterProxyReject> {
    let phase_start = std::time::Instant::now();
    let mut reject = run_after_proxy_hooks(plugins, ctx, response_status, response_headers).await;
    if let Some(reject) = reject.as_mut()
        && crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire(
            &ctx.method,
            reject.status_code,
            &mut reject.headers,
            reject.body.len(),
        )
    {
        reject.body = Bytes::new();
    }
    *plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    reject
}

#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_h3_refined_response(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body_bytes: Vec<u8>,
    client_ip: &str,
    xff_append_ip: &str,
    upstream_target: Option<&UpstreamTarget>,
    epoch: &crate::request_epoch::RequestEpoch,
    sticky_cookie_needed: bool,
    h3_stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    plugin_execution_ns: &mut u64,
    is_early_data: bool,
    backend_admission_start: std::time::Instant,
    retry_config: Option<&crate::config::types::RetryConfig>,
    trailer_governance: ResponseTrailerGovernance<'_>,
) -> Result<H3RefinedResponse, anyhow::Error> {
    // Effective response ceiling for this request: the global knob narrowed by
    // any active route ceiling (`GHSA-xrfj-852f-645j`).
    let effective_max_response_body_size_bytes = ctx.effective_max_response_body_size_bytes();
    let h3_headers = build_h3_backend_headers(
        proxy,
        upstream_target,
        headers,
        client_ip,
        xff_append_ip,
        state,
        ctx.request_is_secure,
        is_early_data,
    );
    let body = Bytes::from(body_bytes);
    let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(proxy);

    let streaming_resp = if let Some(target) = upstream_target {
        state
            .h3_pool
            .request_with_target_streaming(
                proxy,
                &target.host,
                target.port,
                method,
                backend_url,
                &h3_headers,
                body,
                tls_config_fn,
            )
            .await
    } else {
        state
            .h3_pool
            .request_streaming(proxy, method, backend_url, &h3_headers, body, tls_config_fn)
            .await
    };

    let h3_resp = match streaming_resp {
        Ok(response) => response,
        Err(error) => {
            error!("Backend request failed (HTTP/3 refined): {}", error);
            let request_on_wire = error.request_on_wire();
            let h3_error_class = classify_h3_error(&error);
            crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            let (reject_status, reject_body) = h3_backend_failure_status_body(&error);
            if retry_config.is_some() {
                // Nothing has been committed downstream yet. Preserve this
                // failure as a buffered result so the native-H3 retry loop can
                // apply retry_on_connect_failure / status policy and rotate the
                // target. The final exhausted failure is emitted by the normal
                // buffered response path.
                return Ok(H3RefinedResponse::Buffered(H3BufferedDispatchResult {
                    status: reject_status.as_u16(),
                    body: Bytes::from_static(reject_body.as_bytes()),
                    headers: HashMap::new(),
                    trailers: None,
                    error_class: Some(h3_error_class),
                    request_on_wire,
                }));
            }
            // Do NOT propagate a send error here: this refined path already
            // started least-connections LB tracking before dispatch, so
            // returning `Err` would skip the caller's `record_backend_outcome`
            // and leak the active-connection count for the selected target when
            // the client disconnects during the reject write. Report the
            // disconnect in the result so the caller still records the outcome
            // and releases the connection — mirrors the size-limit / after_proxy
            // reject paths in `stream_h3_open_response_to_client`.
            let reject_sent = send_h3_response(h3_stream, reject_status, reject_body)
                .await
                .is_ok();
            return Ok(H3RefinedResponse::Streamed(
                h3_backend_unavailable_stream_result(
                    reject_status.as_u16(),
                    h3_error_class,
                    request_on_wire,
                    reject_sent,
                    backend_admission_start.elapsed(),
                ),
            ));
        }
    };

    let backend_admission_elapsed = backend_admission_start.elapsed();
    let response_status = h3_resp.status;
    let mut response_headers = h3_resp.headers;
    strip_client_response_hop_by_hop_headers(&mut response_headers);

    let response_is_retryable = retry_config.is_some_and(|retry_config| {
        crate::retry::should_retry(
            retry_config,
            method,
            &crate::retry::BackendResponse {
                status_code: response_status,
                body: crate::retry::ResponseBody::buffered(Vec::new()),
                headers: HashMap::new(),
                connection_error: false,
                backend_resolved_ip: None,
                error_class: None,
            },
            0,
        )
    });
    if !response_is_retryable {
        // Stamp original response invariants before the buffer/stream refine and
        // before any `after_proxy` hook can strip `Content-Range` or
        // `Cache-Control`. Retryable responses skip this because their body is
        // discarded by the retry loop; stale first-attempt invariants must not
        // leak into the final attempt's plugin decisions.
        stamp_h3_original_response_metadata(ctx, response_status, &response_headers);
        let retry_ctx = retry_config.map(|_| crate::proxy::retry_response_decision_context(&*ctx));
        let response_decision_ctx = retry_ctx.as_ref().unwrap_or(&*ctx);
        if crate::proxy::refine_stream_response_for_content_type(
            false,
            proxy,
            plugins,
            Some(response_decision_ctx),
            response_status,
            &response_headers,
        ) {
            let result = stream_h3_open_response_to_client(
                state,
                proxy,
                method,
                response_status,
                response_headers,
                h3_resp.recv_stream,
                epoch,
                upstream_target,
                sticky_cookie_needed,
                h3_stream,
                plugins,
                ctx,
                plugin_execution_ns,
                backend_admission_elapsed,
                trailer_governance,
            )
            .await?;
            return Ok(H3RefinedResponse::Streamed(result));
        }
    }

    Ok(H3RefinedResponse::Buffered(
        collect_h3_open_response_body(
            state,
            proxy,
            method,
            response_status,
            response_headers,
            h3_resp.recv_stream,
            upstream_target,
            effective_max_response_body_size_bytes,
        )
        .await,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn collect_h3_open_response_body(
    state: &ProxyState,
    proxy: &Proxy,
    method: &str,
    response_status: u16,
    response_headers: HashMap<String, String>,
    mut recv_stream: crate::http3::client::H3RequestStream,
    upstream_target: Option<&UpstreamTarget>,
    // Already-folded effective response ceiling (global ∧ route), `0` meaning
    // unlimited. Passed in because this helper has no request context to derive
    // it from (`GHSA-xrfj-852f-645j`).
    effective_max_response_body_size_bytes: usize,
) -> H3BufferedDispatchResult {
    // Parsed per comma-folded member so a repeated identical declaration is
    // honored by both the ceiling check and the preallocation hint below
    // (`GHSA-xrfj-852f-645j`).
    let content_length = crate::proxy::canonical_header_content_length_from_map(&response_headers);
    if effective_max_response_body_size_bytes > 0
        && content_length.is_some_and(|len| len > effective_max_response_body_size_bytes as u64)
    {
        return H3BufferedDispatchResult {
            status: 502,
            body: Bytes::from_static(br#"{"error":"Backend response body exceeds maximum size"}"#),
            headers: HashMap::new(),
            trailers: None,
            error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            request_on_wire: true,
        };
    }

    let mut response_body = Vec::new();
    loop {
        // Bound every buffered body-frame wait by `backend_read_timeout_ms`
        // — mirrors `drain_h3_response_body` in the H3 pool. Without this,
        // a backend that sends headers and then stalls mid-body pins the
        // request (and its guards/permits) indefinitely on the refined
        // buffered path.
        let recv_result = if proxy.backend_read_timeout_ms > 0 {
            match tokio::time::timeout(
                Duration::from_millis(proxy.backend_read_timeout_ms),
                recv_stream.recv_data(),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        proxy_id = %proxy.id,
                        timeout_ms = proxy.backend_read_timeout_ms,
                        "HTTP/3 backend buffered response read timed out (refined path)"
                    );
                    // Read timeout: 504 Backend timeout (matching the
                    // direct-H2 / HBONE read-timeout arms), classified as
                    // ReadWriteTimeout. No capability downgrade — a stalled
                    // backend has not proved it lost H3 support.
                    return H3BufferedDispatchResult {
                        status: 504,
                        body: Bytes::from_static(br#"{"error":"Backend timeout"}"#),
                        headers: HashMap::new(),
                        trailers: None,
                        error_class: Some(crate::retry::ErrorClass::ReadWriteTimeout),
                        request_on_wire: true,
                    };
                }
            }
        } else {
            recv_stream.recv_data().await
        };
        match recv_result {
            Ok(Some(mut chunk)) => {
                let chunk_bytes = crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                if effective_max_response_body_size_bytes > 0
                    && response_body.len() + chunk_bytes.len()
                        > effective_max_response_body_size_bytes
                {
                    return H3BufferedDispatchResult {
                        status: 502,
                        body: Bytes::from_static(
                            br#"{"error":"Backend response body exceeds maximum size"}"#,
                        ),
                        headers: HashMap::new(),
                        trailers: None,
                        error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                        request_on_wire: true,
                    };
                }
                response_body.extend_from_slice(&chunk_bytes);
            }
            Ok(None) => {
                let received = response_body.len() as u64;
                if !crate::http3::client::is_response_body_complete_after_fin(
                    received,
                    method,
                    response_status,
                    content_length,
                ) {
                    error!(
                        proxy_id = %proxy.id,
                        received,
                        declared = ?content_length,
                        "HTTP/3 backend refined buffered response truncated (FIN before declared Content-Length)"
                    );
                    return H3BufferedDispatchResult {
                        status: 502,
                        body: Bytes::from_static(
                            br#"{"error":"HTTP/3 backend response truncated"}"#,
                        ),
                        headers: HashMap::new(),
                        trailers: None,
                        error_class: Some(crate::retry::ErrorClass::ConnectionClosed),
                        request_on_wire: true,
                    };
                }
                break;
            }
            Err(error) => {
                let received = response_body.len() as u64;
                if crate::http3::client::is_h3_graceful_close(&error)
                    && crate::http3::client::is_response_body_complete(
                        received,
                        method,
                        response_status,
                        content_length,
                    )
                {
                    break;
                }

                error!(
                    "Error reading backend h3 response during refined buffering: {}",
                    error
                );
                let h3_error_class = crate::http3::client::classify_http3_error(&error);
                crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
                if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                    state
                        .backend_capabilities
                        .mark_h3_unsupported(proxy, upstream_target);
                }
                return H3BufferedDispatchResult {
                    status: 502,
                    body: Bytes::from_static(br#"{"error":"Backend unavailable"}"#),
                    headers: HashMap::new(),
                    trailers: None,
                    error_class: Some(h3_error_class),
                    request_on_wire: true,
                };
            }
        }
    }

    // Body fully drained (FIN or a recoverable graceful close). Read any
    // backend trailers so the buffered native-H3 send path can forward them
    // (issue #1630), bounded by the same `backend_read_timeout_ms` deadline as
    // the body frames above. Trailers are optional: a read timeout, a graceful
    // close at the trailer phase, or no trailers each yield `Ok(None)` rather
    // than failing an otherwise-complete response — mirrors
    // `drain_h3_response_body` in the H3 pool. A genuine non-graceful trailer
    // error is a backend protocol violation: surface it as a 502 backend
    // failure (with capability downgrade) exactly like the body-read error
    // branch above, rather than swallowing it and serving a response that hides
    // the violation.
    let response_trailers = match read_refined_h3_trailers(proxy, &mut recv_stream).await {
        Ok(trailers) => trailers,
        Err(error) => {
            error!(
                "Error reading backend h3 trailers during refined buffering: {}",
                error
            );
            let h3_error_class = crate::http3::client::classify_http3_error(&error);
            crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            return H3BufferedDispatchResult {
                status: 502,
                body: Bytes::from_static(br#"{"error":"Backend unavailable"}"#),
                headers: HashMap::new(),
                trailers: None,
                error_class: Some(h3_error_class),
                request_on_wire: true,
            };
        }
    };

    H3BufferedDispatchResult {
        status: response_status,
        body: Bytes::from(response_body),
        headers: response_headers,
        trailers: response_trailers,
        error_class: None,
        request_on_wire: true,
    }
}

/// Read backend response trailers for the refined-buffered H3 path, bounded by
/// `proxy.backend_read_timeout_ms`.
///
/// Returns `Ok(None)` for the benign trailer-absence cases — a read timeout, a
/// graceful close at the trailer phase, or simply no trailers — because
/// trailers are optional and their absence must not fail an otherwise-complete
/// buffered response. A genuine non-graceful `recv_trailers()` error
/// (malformed/oversized trailers, invalid post-body frame) propagates as
/// `Err(StreamError)` so the caller can surface it as a backend failure (502 +
/// capability downgrade), mirroring `drain_h3_response_body` in the H3 pool and
/// the streaming path's `H3TrailerFinishError::Backend(...)`. Swallowing it to
/// `None` would hide the protocol violation and keep an unhealthy H3 backend in
/// rotation.
async fn read_refined_h3_trailers(
    proxy: &Proxy,
    recv_stream: &mut crate::http3::client::H3RequestStream,
) -> Result<Option<http::HeaderMap>, h3::error::StreamError> {
    let recv_result = if proxy.backend_read_timeout_ms > 0 {
        match tokio::time::timeout(
            Duration::from_millis(proxy.backend_read_timeout_ms),
            recv_stream.recv_trailers(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                debug!(
                    proxy_id = %proxy.id,
                    timeout_ms = proxy.backend_read_timeout_ms,
                    "HTTP/3 backend trailer read timed out (refined path); forwarding response without trailers"
                );
                return Ok(None);
            }
        }
    } else {
        recv_stream.recv_trailers().await
    };

    match recv_result {
        Ok(trailers) => Ok(trailers),
        Err(error) if crate::http3::client::is_h3_graceful_close(&error) => Ok(None),
        Err(error) => {
            debug!(
                proxy_id = %proxy.id,
                error = %error,
                "HTTP/3 backend trailer read failed non-gracefully (refined path); propagating as backend failure"
            );
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_h3_open_response_to_client(
    state: &ProxyState,
    proxy: &Proxy,
    method: &str,
    response_status: u16,
    mut response_headers: HashMap<String, String>,
    mut recv_stream: crate::http3::client::H3RequestStream,
    epoch: &crate::request_epoch::RequestEpoch,
    upstream_target: Option<&UpstreamTarget>,
    sticky_cookie_needed: bool,
    h3_stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    plugin_execution_ns: &mut u64,
    backend_admission_elapsed: std::time::Duration,
    trailer_governance: ResponseTrailerGovernance<'_>,
) -> Result<H3StreamResult, anyhow::Error> {
    // Effective response ceiling for this request: the global knob narrowed by
    // any active route ceiling (`GHSA-xrfj-852f-645j`). Hoisted so the streaming
    // chunk loop below compares against a plain local.
    let effective_max_response_body_size_bytes = ctx.effective_max_response_body_size_bytes();
    // Parsed per comma-folded member so a repeated identical declaration is
    // honored instead of skipping this reject (`GHSA-xrfj-852f-645j`).
    if let Some(len) = crate::proxy::declared_response_length_exceeds_limit(
        &response_headers,
        effective_max_response_body_size_bytes,
    ) {
        warn!(
            proxy_id = %proxy.id,
            response_body_bytes = len,
            max_response_body_size_bytes = effective_max_response_body_size_bytes,
            "HTTP/3 backend response body exceeds configured size limit"
        );
        let size_reject_sent = send_h3_response(
            h3_stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
        )
        .await
        .is_ok();
        return Ok(H3StreamResult {
            status: 502,
            backend_status: response_status,
            error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: !size_reject_sent,
            body_error_class: None,
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    // Same pre-policy capture as the inline native-H3 streaming relay: this
    // path also commits its initial HEADERS before the backend's trailers
    // exist, so the trailer frame needs evidence of what the response-header
    // phases actually changed — including the default `content-type` this relay
    // synthesizes below, which is a gateway-authored wire mutation.
    let gateway_synthesizes_content_type = !response_headers.contains_key("content-type");
    let pre_policy_response_headers = PrePolicyResponseHeaders::capture_for_streaming(
        &response_headers,
        trailer_governance,
        !plugins.is_empty() || sticky_cookie_needed || gateway_synthesizes_content_type,
    );

    if let Some(reject) = run_h3_streaming_after_proxy_hooks(
        plugins,
        ctx,
        response_status,
        &mut response_headers,
        plugin_execution_ns,
    )
    .await
    {
        let reject_status =
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
        let reject_sent = send_h3_reject_response(
            h3_stream,
            reject_status,
            // Shared-allocation handle clone, not a payload copy; `reject.body`
            // stays live for the streamed-byte accounting below.
            reject.body.clone(),
            &reject.headers,
            RejectBodyDisposition::for_request(&ctx.method, reject_status.as_u16()),
        )
        .await
        .is_ok();
        return Ok(H3StreamResult {
            status: reject.status_code,
            backend_status: response_status,
            error_class: None,
            body_completed: reject_sent,
            bytes_streamed: if reject_sent {
                reject.body.len() as u64
            } else {
                0
            },
            client_disconnected: !reject_sent,
            body_error_class: if reject_sent {
                None
            } else {
                Some(crate::retry::ErrorClass::ClientDisconnect)
            },
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    inject_sticky_cookie(
        epoch,
        proxy,
        upstream_target,
        sticky_cookie_needed,
        &mut response_headers,
    );

    // Final protocol-aware strip after after_proxy (RFC 9114 §4.2). Ordinary
    // streaming framing removes Content-Length; only HEAD keeps a valid
    // representation length. Capture the declared length first — the
    // graceful-close completeness gate in the relay loop below still needs it to
    // tell a complete body from a truncated one.
    let declared_content_length = crate::proxy::headers::preserved_response_content_length(
        &response_headers,
        response_status,
    );
    sanitize_client_response_headers_for_wire(
        &mut response_headers,
        ClientResponseFraming::for_streaming_response(method, response_status),
    );

    // Default `content-type` goes into the header MAP, not just the builder, so
    // the map handed to the trailer boundary below is the field set the client
    // actually received. See the matching note in the inline native-H3 relay.
    response_headers
        .entry("content-type".to_string())
        .or_insert_with(|| "application/json".to_string());
    let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_builder =
        apply_response_headers(Response::builder().status(status), &response_headers);
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
    if h3_stream.send_response(resp).await.is_err() {
        return Ok(H3StreamResult {
            status: response_status,
            backend_status: response_status,
            error_class: None,
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: true,
            body_error_class: Some(crate::retry::ErrorClass::ClientDisconnect),
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    let coalesce_min_bytes = state.env_config.http3_coalesce_min_bytes;
    let coalesce_max_bytes = state.env_config.http3_coalesce_max_bytes;
    let flush_interval =
        std::time::Duration::from_micros(state.env_config.http3_flush_interval_micros);
    let mut coalesce_buf = BytesMut::with_capacity(coalesce_max_bytes);
    let mut total_streamed: usize = 0;
    let flush_timer = tokio::time::sleep(flush_interval);
    tokio::pin!(flush_timer);
    // Per-frame backend read deadline (mirrors the inline native-H3 streaming
    // path): abort if the backend stalls for `backend_read_timeout_ms` between
    // response-body frames after the headers were sent. Reset on each received
    // frame; inert (the select! arm guard is off) when the timeout is 0.
    let backend_read_timeout_ms = proxy.backend_read_timeout_ms;
    let read_timeout_active = backend_read_timeout_ms > 0;
    let read_deadline = tokio::time::sleep(std::time::Duration::from_millis(
        backend_read_timeout_ms.max(1),
    ));
    tokio::pin!(read_deadline);
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut client_disconnected = false;
    let mut body_completed = false;
    let mut body_error_class: Option<crate::retry::ErrorClass> = None;
    let mut terminal_error_class: Option<crate::retry::ErrorClass> = None;
    // See `just_received_backend_frame` in the native H3 streaming loop: the
    // deadline is re-armed at the loop head AFTER the prior frame's downstream
    // send, so slow-client backpressure is never charged to the backend.
    let mut just_received_backend_frame = false;

    'outer: loop {
        if read_timeout_active && just_received_backend_frame && coalesce_buf.is_empty() {
            read_deadline.as_mut().reset(
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(backend_read_timeout_ms),
            );
            just_received_backend_frame = false;
        }
        tokio::select! {
            chunk_result = recv_stream.recv_data(), if !stream_done => {
                match chunk_result {
                    Ok(Some(mut chunk)) => {
                        // Defer the deadline re-arm to the loop head.
                        just_received_backend_frame = true;
                        let chunk_len = chunk.remaining();
                        total_streamed += chunk_len;
                        if effective_max_response_body_size_bytes > 0
                            && total_streamed > effective_max_response_body_size_bytes
                        {
                            crate::http3::stream_util::abort_response_stream(h3_stream);
                            terminal_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                            body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                            break 'outer;
                        }
                        if crate::http3::config::should_direct_send_response_chunk(
                            coalesce_buf.len(),
                            chunk_len,
                            coalesce_min_bytes,
                        ) {
                            let data =
                                crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                            if h3_stream.send_data(data).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += chunk_len as u64;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                            continue;
                        }

                        let chunk_bytes =
                            crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                        coalesce_buf.extend_from_slice(&chunk_bytes);
                        if coalesce_buf.len() >= coalesce_min_bytes {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if h3_stream.send_data(data).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += data_len;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                        }
                    }
                    Ok(None) => stream_done = true,
                    Err(error) => {
                        // Captured before the final wire boundary stripped it.
                        let content_length = declared_content_length;
                        let received = total_streamed as u64;
                        if crate::http3::client::is_h3_graceful_close(&error)
                            && crate::http3::client::is_response_body_complete(
                                received,
                                method,
                                response_status,
                                content_length,
                            )
                        {
                            stream_done = true;
                        } else {
                            error!("Error reading backend h3 response during refined streaming: {}", error);
                            coalesce_buf.clear();
                            crate::http3::stream_util::abort_response_stream(h3_stream);
                            let class = crate::http3::client::classify_http3_error(&error);
                            // Mid-stream transport fault → capability downgrade
                            // (parity with gRPC / refined-buffered; issue #2939).
                            // `H3_NO_ERROR` / GOAWAY is never that signal.
                            if !crate::http3::client::is_h3_graceful_close(&error)
                                && crate::proxy::is_h3_transport_error_class(class)
                            {
                                state
                                    .backend_capabilities
                                    .mark_h3_unsupported(proxy, upstream_target);
                            }
                            terminal_error_class = Some(class);
                            body_error_class = Some(class);
                            break 'outer;
                        }
                    }
                }
            }
            _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if h3_stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += data_len;
                flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
            }
            _ = &mut read_deadline, if read_timeout_active && !stream_done && coalesce_buf.is_empty() => {
                warn!(
                    "Backend read timeout ({}ms) during HTTP/3 refined streaming response body; aborting",
                    backend_read_timeout_ms
                );
                coalesce_buf.clear();
                crate::http3::stream_util::abort_response_stream(h3_stream);
                terminal_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                break 'outer;
            }
        }
        if stream_done {
            if !coalesce_buf.is_empty() {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if h3_stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += data_len;
            }
            match finish_h3_response_with_backend_trailers(
                h3_stream,
                &mut recv_stream,
                backend_read_timeout_ms,
                H3StreamingTrailerPolicy {
                    final_headers: &response_headers,
                    pre_policy: &pre_policy_response_headers,
                    governance: trailer_governance,
                    // Plain-flavor relay: no field name is exempt here.
                    section: TrailerSectionKind::PlainResponse,
                },
            )
            .await
            {
                Ok(_) => body_completed = true,
                Err(H3TrailerFinishError::Backend(err)) => {
                    error!(
                        "Error reading backend h3 response trailers during refined streaming: {}",
                        err
                    );
                    crate::http3::stream_util::abort_response_stream(h3_stream);
                    let class = crate::http3::client::classify_http3_error(&err);
                    // Trailer-boundary transport faults downgrade like mid-body
                    // resets (issue #2939), with the same graceful-close
                    // exclusion.
                    if !crate::http3::client::is_h3_graceful_close(&err)
                        && crate::proxy::is_h3_transport_error_class(class)
                    {
                        state
                            .backend_capabilities
                            .mark_h3_unsupported(proxy, upstream_target);
                    }
                    terminal_error_class = Some(class);
                    body_error_class = Some(class);
                }
                Err(H3TrailerFinishError::BackendTimeout) => {
                    warn!(
                        "Backend trailer read timeout ({}ms) during HTTP/3 refined streaming response",
                        backend_read_timeout_ms
                    );
                    crate::http3::stream_util::abort_response_stream(h3_stream);
                    terminal_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                    body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                }
                Err(H3TrailerFinishError::Client) => {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                }
            }
            break;
        }
    }

    Ok(H3StreamResult {
        status: response_status,
        backend_status: response_status,
        error_class: terminal_error_class,
        body_completed,
        bytes_streamed,
        client_disconnected,
        body_error_class,
        request_on_wire: true,
        backend_admission_elapsed,
    })
}

/// Dispatch a gRPC request received over HTTP/3 to a **native HTTP/3** backend.
///
/// The gRPC sibling of the inline native-H3 streaming path in
/// `handle_h3_request`. Selected only when the capability registry has proven
/// the concrete target speaks H3 (`supports_native_http3_backend`), the request
/// body can stream (no retry / body-plugin buffering, nothing prebuffered), and
/// no plugin forces reqwest dispatch — see the `use_native_h3_grpc` gate at the
/// call site. Every other gRPC-over-H3 case still falls through
/// `cross_protocol::run` to the H2 gRPC pool.
///
/// This closes the gap where an **H3-only** gRPC backend was unreachable: the
/// H2 gRPC pool (`grpc_proxy`) speaks only HTTP/2 (h2 TLS / h2c), so a backend
/// offering gRPC over HTTP/3 alone previously surfaced as `UNAVAILABLE`/`502`.
/// gRPC request frames are streamed unchanged; the response body is relayed with
/// the shared QUIC coalescer; and the terminal `grpc-status` / `grpc-message`
/// trailer is forwarded verbatim after response-direction hop-by-hop stripping
/// (`finish_h3_response_with_backend_trailers` semantics, inlined here so the
/// backend `grpc-status` can also feed the adaptive-concurrency sample — exactly
/// like the H2 streaming gRPC bridge in `cross_protocol`).
///
/// Request-body streaming drains the client request stream before the backend
/// response is read (`do_request_streaming_body`), so unary, server-streaming,
/// and client-streaming RPCs work. Full bidirectional streaming is not supported
/// on this path — identical to the H2 cross-protocol bridge, which buffers the
/// request; such a stream with neither retries nor body plugins would deadlock
/// here exactly as it would on the H2 bridge (accepted limitation).
#[allow(clippy::too_many_arguments)]
async fn dispatch_grpc_native_h3(
    state: &ProxyState,
    epoch: &crate::request_epoch::RequestEpoch,
    proxy: &Proxy,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    method: &str,
    proxy_headers: &HashMap<String, String>,
    backend_url: &str,
    original_request_path: &str,
    upstream_target: Option<&UpstreamTarget>,
    upstream_balancer: Option<&Arc<crate::load_balancer::LoadBalancer>>,
    cb_target_key: Option<&str>,
    cb_is_half_open_probe: bool,
    client_ip: &str,
    xff_append_ip: &str,
    backend_resolved_ip: Option<&str>,
    sticky_cookie_needed: bool,
    is_early_data: bool,
    backend_start: std::time::Instant,
    start_time: std::time::Instant,
    ctx: &mut RequestContext,
    plugins: &[Arc<dyn Plugin>],
    backend_admission_plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: &mut u64,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    // Config-time response-trailer governance, precomputed per reload. Native
    // gRPC terminal metadata crosses the response-header policy boundary exactly
    // like a plain streaming relay's trailer section (GHSA-r78v-rc86-6r86): the
    // initial HEADERS frame commits before the trailers exist, so `after_proxy`
    // and sticky-cookie injection have already gone on the wire. Only the three
    // RESERVED terminal fields are exempt — see `TrailerSectionKind`.
    response_trailer_governance: ResponseTrailerGovernance<'_>,
) -> Result<(), anyhow::Error> {
    // Effective response ceiling for this request: the global knob narrowed by
    // any active route ceiling (`GHSA-xrfj-852f-645j`). Hoisted so the streaming
    // chunk loop below compares against a plain local.
    let effective_max_response_body_size_bytes = ctx.effective_max_response_body_size_bytes();
    // Same fold for the native-gRPC receive ceiling, applied to the streaming
    // upload below so an unbuffered H3 gRPC request is bounded at the route
    // limit rather than only at `FERRUM_MAX_GRPC_RECV_SIZE_BYTES`.
    let effective_max_grpc_recv_size_bytes = crate::proxy::effective_request_body_limit(
        state.max_grpc_recv_size_bytes,
        ctx.route_request_body_limit(),
    );
    // Backend admission (gRPC rejects are emitted as trailers-only errors).
    let mut backend_admission_permits = match run_h3_backend_admission_or_send_reject(
        backend_admission_plugins,
        plugins,
        ctx,
        proxy,
        upstream_target,
        HttpFlavor::Grpc,
        None,
        initial_response_header_policy_plugins,
        stream,
        state,
        start_time,
        *plugin_execution_ns,
        cb_target_key,
        cb_is_half_open_probe,
    )
    .await?
    {
        Ok(permits) => permits,
        // Probe release happens inside the helper, before the reject write.
        Err(()) => return Ok(()),
    };
    let backend_admission_start = std::time::Instant::now();

    // Least-connections LB tracking (after all pre-dispatch rejects).
    if let (Some(_upstream_id), Some(target), Some(balancer)) =
        (&proxy.upstream_id, upstream_target, upstream_balancer)
    {
        balancer.record_connection_start(target);
    }

    // Stream the gRPC request body to the native H3 backend. gRPC frames are
    // forwarded unchanged; the ceiling is the gRPC-specific recv limit so H3
    // matches the H1/H2 gRPC path.
    let mut h3_headers = build_h3_backend_headers(
        proxy,
        upstream_target,
        proxy_headers,
        client_ip,
        xff_append_ip,
        state,
        ctx.request_is_secure,
        is_early_data,
    );
    // Re-add `te: trailers`. `build_h3_backend_headers` strips `te` as a
    // hop-by-hop header (RFC 9110 §7.6.1), but gRPC backends that enforce the
    // TE check require it on the request — the H1/H2 gRPC header path re-inserts
    // it for exactly this reason. In HTTP/3 the only permitted `te` value is
    // `trailers` (RFC 9114 §4.2), which is precisely what gRPC needs. The strip
    // above guarantees no client-supplied `te` remains, so this is the single
    // authoritative value.
    h3_headers.push((
        http::header::TE,
        http::header::HeaderValue::from_static("trailers"),
    ));
    let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(proxy);
    let request_body_bytes_seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Flipped to `true` the instant `do_request_streaming_body` opens the backend
    // stream (`send_request` returns). The dispatch `timeout_at` below reads THIS —
    // not `request_body_bytes_seen` — to choose pre-wire vs post-wire on expiry: a
    // valid zero-message / trailers-only client-streaming RPC opens the stream
    // without sending any body bytes, so a byte-count test would wrongly downgrade a
    // healthy backend on a slow-upload timeout.
    let request_stream_opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Flipped to `true` once the client upload is fully forwarded and the backend
    // stream is FINished. With `request_stream_opened` this gives the dispatch
    // `timeout_at` three phases: connecting (not opened), uploading (opened, not
    // complete), and waiting-on-headers (complete) — so an upload-phase stall is
    // accounted as a neutral client fault, not a backend read timeout.
    let request_upload_complete = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Honor the client gRPC deadline (`grpc-timeout`) as an ABSOLUTE end-to-end
    // RPC deadline anchored at request receipt — exactly like the H2 /
    // cross-protocol gRPC path, which enforces it via `TotalDeadlineBody`. Without
    // it an H3-only backend that ignores the header could keep streaming or stall
    // past the client's deadline, holding the request/admission guards. The
    // post-plugin value rides in the forwarded headers.
    // The preflight pass established one typed receipt-anchored deadline before
    // plugin/body awaits. Reuse it directly: the upstream header may now be a
    // remaining duration, so parsing and receipt-anchoring it again would deduct
    // elapsed gateway time twice.
    let grpc_deadline_at = ctx.grpc_deadline_at();
    let client_deadline_present = grpc_deadline_at.is_some();

    // Bound the request upload + response-header wait. WITH a parseable client
    // deadline that is the absolute deadline; WITHOUT one (absent or malformed —
    // see the grammar check above), fall back to `backend_read_timeout_ms` so a
    // stalled upload can't pin admission / LB / QUIC state indefinitely (matching
    // the H2 path's fallback around `send_request`).
    let dispatch_deadline_at = if client_deadline_present {
        grpc_deadline_at
    } else if proxy.backend_read_timeout_ms > 0 {
        tokio::time::Instant::now()
            .checked_add(Duration::from_millis(proxy.backend_read_timeout_ms))
    } else {
        None
    };

    // The H3 pool's internal response-header wait normally uses
    // `proxy.backend_read_timeout_ms`; under a client `grpc-timeout` pass `0`
    // (unbounded inner) so the outer `dispatch_deadline_at` (the absolute client
    // deadline) governs the header wait instead of the shorter read timeout — a
    // legitimately slow-header H3 backend must not be failed before the client
    // deadline (the inner timeout would otherwise win).
    let grpc_header_read_timeout_ms = if client_deadline_present {
        0
    } else {
        proxy.backend_read_timeout_ms
    };

    let dispatch_fut = async {
        if let Some(target) = upstream_target {
            state
                .h3_pool
                .request_with_target_streaming_body(
                    proxy,
                    &target.host,
                    target.port,
                    method,
                    backend_url,
                    &h3_headers,
                    stream,
                    effective_max_grpc_recv_size_bytes,
                    Arc::clone(&request_body_bytes_seen),
                    grpc_header_read_timeout_ms,
                    Arc::clone(&request_stream_opened),
                    Arc::clone(&request_upload_complete),
                    tls_config_fn,
                )
                .await
        } else {
            state
                .h3_pool
                .request_streaming_body(
                    proxy,
                    method,
                    backend_url,
                    &h3_headers,
                    stream,
                    effective_max_grpc_recv_size_bytes,
                    Arc::clone(&request_body_bytes_seen),
                    grpc_header_read_timeout_ms,
                    Arc::clone(&request_stream_opened),
                    Arc::clone(&request_upload_complete),
                    tls_config_fn,
                )
                .await
        }
    };
    // Bound the request upload + response-header wait by the deadline (client
    // grpc-timeout, else the backend_read_timeout fallback); on expiry map to a
    // read-timeout error so the failure branch emits DEADLINE_EXCEEDED (post-wire,
    // no capability downgrade — see `H3PoolError::read_timeout`).
    let streaming_resp = match dispatch_deadline_at {
        Some(at) => match tokio::time::timeout_at(at, dispatch_fut).await {
            Ok(r) => r,
            Err(_) => {
                // This `timeout_at` wraps the COLD connect (QUIC/TLS/H3) + the
                // request upload + the response-header wait. The two atomics split it
                // into three phases so the failure is attributed correctly:
                //
                //   * NOT opened — the connect / pre-wire phase was still in flight.
                //     If this was the operator `backend_read_timeout_ms` FALLBACK
                //     (no client deadline) the backend connect was too slow: a genuine
                //     PRE-WIRE connect failure (`connection_error=true` + capability
                //     downgrade). But if the CLIENT's `grpc-timeout` drove the expiry,
                //     the client simply chose a deadline too tight to even connect —
                //     NOT a backend capability/health signal; surface a neutral
                //     DEADLINE_EXCEEDED with no downgrade.
                //   * opened but upload NOT complete — the client request upload is
                //     still streaming; a stalled client, neutral for backend health.
                //   * opened AND upload complete — the backend is slow returning
                //     response headers: a real post-wire read timeout (504, no
                //     downgrade).
                //
                // Byte count is NOT used: a valid zero-message / trailers-only
                // client-streaming RPC opens the stream with no body bytes.
                let opened = request_stream_opened.load(std::sync::atomic::Ordering::Acquire);
                let uploaded = request_upload_complete.load(std::sync::atomic::Ordering::Acquire);
                if !opened {
                    if client_deadline_present {
                        // Client-chosen deadline expired before the stream opened —
                        // neutral, no capability downgrade (see the failure branch's
                        // `is_client_side_neutral_timeout` mapping).
                        Err(crate::http3::client::H3PoolError::read_timeout(
                            anyhow::anyhow!(
                                "client grpc-timeout deadline exceeded before the backend stream opened"
                            ),
                        ))
                    } else {
                        state
                            .backend_capabilities
                            .mark_h3_unsupported(proxy, upstream_target);
                        Err(crate::http3::client::H3PoolError::pre_wire(
                            anyhow::anyhow!(
                                "gRPC backend connect/dispatch timed out before the request reached the wire"
                            ),
                        ))
                    }
                } else if !uploaded {
                    // Stalled client upload after the stream opened — client-side,
                    // neutral for backend health (see `is_client_side_neutral_timeout`).
                    Err(crate::http3::client::H3PoolError::read_timeout(
                        anyhow::anyhow!("client request upload stalled past the dispatch deadline"),
                    ))
                } else {
                    Err(crate::http3::client::H3PoolError::read_timeout(
                        anyhow::anyhow!(
                            "gRPC backend dispatch timed out before response headers (grpc-timeout / backend_read_timeout)"
                        ),
                    ))
                }
            }
        },
        None => dispatch_fut.await,
    };

    let mut h3_resp = match streaming_resp {
        Ok(r) => r,
        Err(e) => {
            let err_msg = e.to_string();
            let h3_error_class = classify_h3_error(&e);
            crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
            let is_client_request_body_disconnect = is_h3_client_request_body_disconnect(&err_msg);
            let is_oversize = err_msg.contains("exceeds maximum size");
            let is_read_timeout = e.is_read_timeout();
            // A malformed/undecodable client request-trailer block is a bad CLIENT
            // request, not backend unavailability — surface INVALID_ARGUMENT so the
            // caller does not retry it as a server outage.
            let is_malformed_request_trailers =
                err_msg.contains("malformed client request trailers");
            // Deadline expiries the dispatch attributed to the CLIENT (a grpc-timeout
            // too tight to even connect, or a stalled client upload) are neutral for
            // backend health: the backend is not at fault. Both arrive as
            // `read_timeout` (DEADLINE_EXCEEDED on the wire) but must NOT poison
            // CB / passive health / adaptive concurrency.
            let is_client_side_neutral_timeout = err_msg
                .contains("client grpc-timeout deadline exceeded before")
                || err_msg.contains("client request upload stalled");

            // gRPC error signalling mirrors the cross-protocol bridge's
            // dispatch-failure mapping: oversized upload -> RESOURCE_EXHAUSTED,
            // malformed client trailers -> INVALID_ARGUMENT, read timeout / client
            // deadline -> DEADLINE_EXCEEDED, everything else -> UNAVAILABLE.
            let (grpc_status, grpc_message) = if is_oversize {
                (
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                )
            } else if is_malformed_request_trailers {
                (
                    crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
                    "Malformed request trailers",
                )
            } else if is_client_side_neutral_timeout {
                (
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                )
            } else if is_read_timeout {
                (
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    "Backend deadline exceeded",
                )
            } else {
                (
                    crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
                    "Service unavailable",
                )
            };

            // A cached H3 capability that fails with a transport error means the
            // backend probably lost UDP/QUIC; downgrade so the next gRPC request
            // takes the cross-protocol bridge. A client upload abort or an
            // oversized upload is client-caused, not a backend-capability signal.
            if !is_client_request_body_disconnect
                && !is_oversize
                && crate::proxy::is_h3_transport_error_class(h3_error_class)
            {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }

            // Do NOT `?`-propagate a send error: record_backend_outcome below
            // releases the LB active-connection count, so bailing here would leak
            // it on a client disconnect during the error write. Capture whether the
            // gRPC error actually reached the client so the transaction log's
            // `client_disconnected` stays accurate when the client already reset.
            let error_sent = send_h3_grpc_error(
                stream,
                grpc_status,
                grpc_message,
                initial_response_header_policy_plugins,
            )
            .await
            .is_ok();

            // Split the WIRE status from the backend-HEALTH status, exactly like
            // the H1/H2 and cross-protocol gRPC paths (`write_grpc_error` returns
            // `response_status: 200`). The wire response is a trailers-only gRPC
            // error (HTTP 200 + `grpc-status`), so logs / the runtime status
            // counter record 200 and carry the gRPC status in metadata; CB /
            // passive-health / adaptive concurrency use the HTTP-equivalent health
            // status (504 on read timeout, 502 otherwise). An oversized client
            // upload is client-caused and stays NEUTRAL — 413 + `ClientDisconnect`,
            // matching the plain native-H3 streaming 413 path — so it never
            // poisons the breaker / passive health / adaptive concurrency.
            let (health_status, outcome_error_class) = if is_oversize {
                (413, Some(crate::retry::ErrorClass::ClientDisconnect))
            } else if is_malformed_request_trailers {
                // Bad client request — wire is INVALID_ARGUMENT; neutral for backend
                // health (`ClientDisconnect` skips CB / passive health / admission).
                (400, Some(crate::retry::ErrorClass::ClientDisconnect))
            } else if is_client_side_neutral_timeout {
                // Client-chosen deadline expired before connect, or stalled client
                // upload — neutral for backend health even though the wire status is
                // DEADLINE_EXCEEDED. Without this the `read_timeout` would fall through
                // to the 504 / `ReadWriteTimeout` arm and wrongly trip the breaker /
                // passive health for a healthy backend.
                (504, Some(crate::retry::ErrorClass::ClientDisconnect))
            } else {
                let status = if is_read_timeout { 504 } else { 502 };
                let (_, error_class) = h3_streaming_body_failure_outcome(
                    is_client_request_body_disconnect,
                    is_read_timeout,
                    h3_error_class,
                );
                (status, error_class)
            };
            // `H3PoolError::request_on_wire()` is authoritative for H3
            // `connection_error` (proxy-protocols rules: do not AND it with generic
            // error-class labels). Only a pre-wire failure (connect / TLS / DNS /
            // pre-`send_request`) is a connection error; a post-wire reset, read
            // timeout, or oversized / aborted upload already reached the backend
            // wire and must NOT be recorded as a connect-class failure.
            let outcome_connection_error =
                h3_connection_error(e.request_on_wire(), outcome_error_class);
            crate::proxy::backend_dispatch::record_backend_outcome(
                state,
                proxy,
                &epoch.load_balancer,
                upstream_balancer,
                upstream_target,
                cb_target_key,
                health_status,
                outcome_connection_error,
                outcome_error_class,
                cb_is_half_open_probe,
                false,
                backend_start.elapsed(),
            );
            record_h3_backend_admission_outcome(
                &mut backend_admission_permits,
                health_status,
                outcome_connection_error,
                outcome_error_class,
                backend_admission_start.elapsed(),
            );
            // Wire/log status is HTTP 200 (gRPC errors ride on 200); stash the
            // gRPC status/message in metadata so observability still reflects the
            // failure, matching the H1/H2 + cross-protocol gRPC error paths.
            crate::proxy::insert_grpc_error_metadata(&mut ctx.metadata, grpc_status, grpc_message);
            let wire_status = StatusCode::OK.as_u16();
            log_h3_grpc_transaction(
                proxy,
                ctx,
                plugins,
                method,
                original_request_path,
                backend_url,
                backend_resolved_ip,
                proxy_headers,
                wire_status,
                request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
                0,
                error_sent,
                !error_sent,
                Some(h3_error_class),
                None,
                start_time,
                // No response headers / first byte were observed on this
                // pre-headers failure path, so TTFB is unknown rather than
                // admission elapsed time.
                crate::plugins::LATENCY_UNKNOWN_MS,
                *plugin_execution_ns,
            )
            .await;
            record_request(state, wire_status);
            return Ok(());
        }
    };

    // Backend produced response headers.
    let backend_admission_response_elapsed = backend_admission_start.elapsed();
    let response_status = h3_resp.status;
    let mut response_headers = h3_resp.headers;
    stamp_h3_original_response_metadata(ctx, response_status, &response_headers);

    // Snapshot reserved Trailers-Only metadata from pristine INITIAL headers
    // before response hooks can rewrite/remove it. The status drives backend
    // health, while status/message/details are the authoritative fallback if
    // the backend ends without a trailers frame. A normal response supplies a
    // real terminal trailer below, which wins over this fallback.
    let pristine_initial_terminal_metadata =
        crate::proxy::grpc_proxy::GrpcTerminalMetadataSnapshot::from_headers(&response_headers);
    let backend_header_grpc_status = pristine_initial_terminal_metadata
        .grpc_status()
        .map(str::to_owned);

    // Response-trailer policy boundary for the NATIVE H3 gRPC relay
    // (GHSA-r78v-rc86-6r86). Captured HERE, on the pristine backend header map,
    // because every response-header phase below — `after_proxy`, sticky-cookie
    // injection, the `content-length` strip, the reserved-terminal-metadata
    // strip, and the final hop-by-hop strip — runs afterwards and is on the wire
    // long before the backend's TRAILERS frame arrives.
    //
    // The gate mirrors the plain relays: with no plugin able to touch response
    // headers, no sticky cookie, and no `content-length` for the gateway to
    // strip, nothing on this path can mutate a header, so the snapshot would be
    // compared against itself and the #2941 pass-through stands. `content-length`
    // is in the gate because the gateway removes it unconditionally below, which
    // is exactly the present->absent shape a backend `content-length` TRAILER
    // would undo. Hop-by-hop names need no gate entry: they are stripped from
    // the trailer section before reconciliation, so they can never reach it.
    // Reserved terminal metadata needs none either — it is exempt by section.
    let grpc_pre_policy_response_headers = PrePolicyResponseHeaders::capture_for_streaming(
        &response_headers,
        response_trailer_governance,
        !plugins.is_empty()
            || sticky_cookie_needed
            || response_headers.contains_key("content-length"),
    );

    // Response body size ceiling (Content-Length fast path). Backend RESPONSE
    // bytes are bounded by `max_response_body_size_bytes` — the same limit the
    // plain native-H3 streaming path and the cross-protocol streaming gRPC bridge
    // apply — NOT the request-side gRPC receive cap, so a large-but-valid gRPC
    // response is not spuriously rejected.
    if let Some(len) = crate::proxy::declared_response_length_exceeds_limit(
        &response_headers,
        effective_max_response_body_size_bytes,
    ) {
        warn!(
            proxy_id = %proxy.id,
            response_body_bytes = len,
            max_response_body_size_bytes = effective_max_response_body_size_bytes,
            "HTTP/3 gRPC backend response body exceeds configured size limit"
        );
        let error_sent = send_h3_grpc_error(
            stream,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Backend response exceeds maximum size",
            initial_response_header_policy_plugins,
        )
        .await
        .is_ok();
        // CB/passive-health see the real backend status (the backend responded
        // before we found the body too large) but with `ResponseBodyTooLarge` so
        // the post-wire backend-failure path counts it — matching the streaming
        // overrun path below; the adaptive limiter likewise treats it as a failure.
        crate::proxy::backend_dispatch::record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            upstream_target,
            cb_target_key,
            response_status,
            false,
            Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            response_status,
            false,
            Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            backend_admission_response_elapsed,
        );
        // The wire response is a trailers-only gRPC error (HTTP 200 +
        // RESOURCE_EXHAUSTED), so the runtime status counter records 200 with the
        // gRPC status in metadata — matching the cross-protocol gRPC
        // ResponseTooLarge path and the dispatch-failure branch above.
        crate::proxy::insert_grpc_error_metadata(
            &mut ctx.metadata,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Backend response exceeds maximum size",
        );
        // Emit a TransactionSummary so log/mirror plugins see this oversized
        // response, like the dispatch-failure, after_proxy-reject, and success
        // branches. Request bytes were forwarded; no response body was relayed.
        log_h3_grpc_transaction(
            proxy,
            ctx,
            plugins,
            method,
            original_request_path,
            backend_url,
            backend_resolved_ip,
            proxy_headers,
            StatusCode::OK.as_u16(),
            request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
            0,
            error_sent,
            !error_sent,
            Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            None,
            start_time,
            backend_admission_response_elapsed.as_secs_f64() * 1000.0,
            *plugin_execution_ns,
        )
        .await;
        record_request(state, StatusCode::OK.as_u16());
        return Ok(());
    }

    // after_proxy hooks run before streaming begins (header-only on streaming
    // gRPC, matching the H2 bridge). A reject is emitted as a trailers-only gRPC
    // error preserving any plugin headers.
    if let Some(reject) = run_h3_streaming_after_proxy_hooks(
        plugins,
        ctx,
        response_status,
        &mut response_headers,
        plugin_execution_ns,
    )
    .await
    {
        let reject_status =
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
        let reject_sent = send_h3_reject_flavor_aware(
            stream,
            HttpFlavor::Grpc,
            reject_status,
            reject.body.clone(),
            &reject.headers,
            RejectBodyDisposition::for_request(&ctx.method, reject_status.as_u16()),
        )
        .await
        .is_ok();
        // CB / passive-health must see the TRUE backend status, not the gateway
        // policy override.
        crate::proxy::backend_dispatch::record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            upstream_target,
            cb_target_key,
            response_status,
            false,
            None,
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        // Train the adaptive limiter on the BACKEND's terminal gRPC status (a
        // Trailers-Only status rode in the initial headers, snapshotted pre-hook),
        // not the gateway policy reject — a failing backend must still shrink the
        // limiter even when a hook rejected locally. Mirrors the cross-protocol
        // bridge's use of the pre-hook `grpc_backend_dispatch_status`.
        let reject_admission_status = {
            let mut header_view: HashMap<String, String> = HashMap::new();
            if let Some(code) = backend_header_grpc_status.as_deref() {
                header_view.insert("grpc-status".to_string(), code.to_string());
            }
            crate::proxy::grpc_proxy::grpc_admission_status_from_maps(
                &HashMap::new(),
                &header_view,
                response_status,
            )
        };
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            reject_admission_status,
            false,
            None,
            backend_admission_response_elapsed,
        );
        // Normalize the reject for logging/metrics: `send_h3_reject_flavor_aware`
        // wrote a trailers-only gRPC response (HTTP 200 + `grpc-status`), so the
        // access log and runtime status counter must record 200 with the gRPC
        // status in metadata — matching the earlier H3 gRPC reject phases
        // (`run_h3_backend_admission_or_send_reject`). The reject body becomes the
        // `grpc-message`, not a wire DATA frame, so no response body bytes are sent.
        let log_status = h3_reject_log_status_and_metadata(
            ctx,
            HttpFlavor::Grpc,
            reject_status,
            &reject.body,
            &reject.headers,
        );
        log_h3_grpc_transaction(
            proxy,
            ctx,
            plugins,
            method,
            original_request_path,
            backend_url,
            backend_resolved_ip,
            proxy_headers,
            log_status,
            // Request body was already streamed to the backend before the
            // response returned and was rejected, so report the forwarded bytes
            // (chargeback/audit parity with the success/failure branches). The
            // gRPC reject is trailers-only, so no response DATA bytes are sent.
            request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
            0,
            reject_sent,
            !reject_sent,
            None,
            None,
            start_time,
            backend_admission_response_elapsed.as_secs_f64() * 1000.0,
            *plugin_execution_ns,
        )
        .await;
        record_request(state, log_status);
        return Ok(());
    }

    inject_sticky_cookie(
        epoch,
        proxy,
        upstream_target,
        sticky_cookie_needed,
        &mut response_headers,
    );

    // gRPC streaming completes via the terminal `grpc-status` trailer, NOT
    // `Content-Length` — and the gateway may synthesize an EARLY terminal trailer
    // (`grpc-status: 4`) on a mid-stream deadline, sending fewer DATA bytes than a
    // backend-advertised Content-Length. An H3 client enforcing Content-Length
    // would treat that truncated body as malformed before surfacing the gRPC
    // status, so strip it from the client-facing headers (captured first for the
    // internal graceful-close completeness check in the relay loop below).
    let declared_content_length =
        preserved_response_content_length(&response_headers, response_status);
    // Ordinary Streaming framing removes the wire field; omit case-insensitively
    // here so no later reader of this map treats the backend length as
    // authoritative across an early terminal trailer.
    remove_content_length_header(&mut response_headers);

    // gRPC carries its terminal status in the TRAILERS frame; the initial HEADERS
    // must NOT also carry `grpc-status` / `grpc-message` for a non-empty response
    // (a backend that copies them there is malformed, and the client could observe
    // an early or conflicting terminal status before the real trailers). Strip the
    // reserved terminal metadata from the wire headers so the trailer is
    // authoritative — capturing it first so a genuine Trailers-Only response
    // (status only in the headers, no body, no trailers) is re-emitted as a
    // synthesized trailer in the relay loop below.
    let wire_grpc_status = pristine_initial_terminal_metadata
        .grpc_status()
        .map(str::to_owned);
    let wire_grpc_message = pristine_initial_terminal_metadata
        .grpc_message()
        .map(str::to_owned);
    // Rich error details (`grpc-status-details-bin`) also live in the Trailers-Only
    // header block and must survive the synthesized trailer, not just status/message.
    let wire_grpc_status_details = pristine_initial_terminal_metadata
        .grpc_status_details()
        .map(str::to_owned);
    response_headers
        .retain(|k, _| !crate::proxy::grpc_proxy::is_reserved_grpc_terminal_metadata(k.as_str()));

    // Final protocol-aware response-header boundary — hop-by-hop /
    // Connection-listed fields plus Content-Length repair. The plain native H3
    // streaming path applies the same sanitizer; the gRPC response path must
    // too, since `response_headers` here comes straight from the backend /
    // after_proxy hooks. Trailer *frames* are untouched.
    //
    // Ordinary Streaming framing: gRPC has no HEAD and never frames with
    // Content-Length, so the field is removed outright rather than deriving a
    // representation-length exemption from the request method.
    sanitize_client_response_headers_for_wire(
        &mut response_headers,
        ClientResponseFraming::Streaming,
    );

    // Send response headers. gRPC carries its own `content-type`
    // (`application/grpc`); never override it with the plain JSON default.
    let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_builder =
        apply_response_headers(Response::builder().status(status), &response_headers);
    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC response: {}", e))?;
    let response_header_write = crate::http3::stream_util::await_response_write_before_deadline(
        grpc_deadline_at,
        stream.send_response(resp),
    )
    .await;
    if let Err(write_error) = response_header_write {
        let (response_header_deadline_expired, response_header_client_disconnected) =
            match write_error {
                crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded => (true, false),
                crate::http3::stream_util::H3ResponseWriteError::Write(_) => (false, true),
            };
        if response_header_deadline_expired {
            crate::proxy::insert_grpc_error_metadata(
                &mut ctx.metadata,
                crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
            );
            crate::http3::stream_util::abort_response_stream(stream);
        }
        // A client disconnect at the header-write boundary must not mask a real
        // backend failure: when the backend returned a failure status (a raw HTTP
        // 5xx, or a configured breaker-failure status), clear the neutral
        // `ClientDisconnect` class for CB/passive-health/admission so the failure
        // is recorded — same guard the body/trailer path applies.
        let backend_failure_status = response_status >= 500
            || proxy
                .circuit_breaker
                .as_ref()
                .is_some_and(|cb| cb.failure_status_codes.contains(&response_status));
        let health_error_class = if backend_failure_status {
            None
        } else {
            Some(crate::retry::ErrorClass::ClientDisconnect)
        };
        crate::proxy::backend_dispatch::record_backend_outcome(
            state,
            proxy,
            &epoch.load_balancer,
            upstream_balancer,
            upstream_target,
            cb_target_key,
            response_status,
            false,
            health_error_class,
            cb_is_half_open_probe,
            false,
            backend_start.elapsed(),
        );
        record_h3_backend_admission_outcome(
            &mut backend_admission_permits,
            response_status,
            false,
            health_error_class,
            backend_admission_response_elapsed,
        );
        if !response_header_deadline_expired {
            let grpc_status = wire_grpc_status.as_deref().map_or(
                crate::proxy::grpc_proxy::grpc_status::UNKNOWN,
                crate::proxy::grpc_proxy::parse_grpc_status_value,
            );
            ctx.metadata
                .insert("grpc_status".to_string(), grpc_status.to_string());
        }
        log_h3_grpc_transaction(
            proxy,
            ctx,
            plugins,
            method,
            original_request_path,
            backend_url,
            backend_resolved_ip,
            proxy_headers,
            response_status,
            request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
            0,
            false,
            response_header_client_disconnected,
            None,
            response_header_client_disconnected
                .then_some(crate::retry::ErrorClass::ClientDisconnect),
            start_time,
            backend_admission_response_elapsed.as_secs_f64() * 1000.0,
            *plugin_execution_ns,
        )
        .await;
        record_request(state, response_status);
        return Ok(());
    }

    // Stream the response body with the shared QUIC coalescer (same window as
    // the plain native-H3 streaming path; no response inspectors — a streaming
    // inspector forces reqwest dispatch and never reaches this path).
    let coalesce_min_bytes = state.env_config.http3_coalesce_min_bytes;
    let coalesce_max_bytes = state.env_config.http3_coalesce_max_bytes;
    let flush_interval =
        std::time::Duration::from_micros(state.env_config.http3_flush_interval_micros);
    let mut coalesce_buf = BytesMut::with_capacity(coalesce_max_bytes);
    let flush_timer = tokio::time::sleep(flush_interval);
    tokio::pin!(flush_timer);
    let backend_read_timeout_ms = proxy.backend_read_timeout_ms;
    // Per-frame idle guard, DISABLED when the client set a `grpc-timeout`: in that
    // regime the absolute `grpc_deadline_sleep` is the only response-phase bound,
    // so a server-streaming RPC may idle up to the client deadline rather than
    // being aborted after the shorter `backend_read_timeout_ms` (matching the H2
    // path's switch to `TotalDeadlineBody`).
    let read_timeout_active = backend_read_timeout_ms > 0 && !client_deadline_present;
    let read_deadline = tokio::time::sleep(std::time::Duration::from_millis(
        backend_read_timeout_ms.max(1),
    ));
    tokio::pin!(read_deadline);
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut total_streamed: usize = 0;
    let mut client_disconnected = false;
    let mut body_completed = false;
    let mut body_error_class: Option<crate::retry::ErrorClass> = None;
    let mut client_deadline_expired = false;
    let mut just_received_backend_frame = false;
    // Backend gRPC terminal status, captured from the trailer (or trailers-only
    // header) for the adaptive-concurrency sample below.
    let mut grpc_trailer_status: Option<u32> = None;
    // Absolute gRPC deadline (`grpc-timeout`) for the response body + trailers —
    // fires once even if the backend keeps trickling frames just under the
    // per-frame `backend_read_timeout_ms`. Gated off (far-future sleep) when the
    // client set no deadline. `tokio::time::Instant` is `Copy`, so reusing
    // `grpc_deadline_at` here does not consume it.
    let grpc_deadline_active = grpc_deadline_at.is_some();
    let grpc_deadline_sleep = tokio::time::sleep_until(
        grpc_deadline_at
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400)),
    );
    tokio::pin!(grpc_deadline_sleep);

    macro_rules! await_downstream_grpc_write {
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
                        if send_h3_grpc_terminal_trailers(
                            stream,
                            crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                            GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
                            grpc_deadline_at,
                        )
                        .await
                        {
                            grpc_trailer_status =
                                Some(crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED);
                            body_completed = true;
                        } else {
                            crate::http3::stream_util::abort_response_stream(stream);
                        }
                    } else {
                        crate::http3::stream_util::abort_response_stream(stream);
                    }
                    crate::proxy::insert_grpc_error_metadata(
                        &mut ctx.metadata,
                        crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                        GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                    );
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    false
                }
                Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    false
                }
            }
        }};
    }

    'outer: loop {
        if read_timeout_active && just_received_backend_frame && coalesce_buf.is_empty() {
            read_deadline.as_mut().reset(
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(backend_read_timeout_ms),
            );
            just_received_backend_frame = false;
        }
        tokio::select! {
            biased;
            // Absolute deadline: unlike `read_deadline` this is NOT gated on an
            // empty coalesce buffer — once the client's RPC deadline passes we stop
            // regardless of buffered/in-flight frames. It comes first in this
            // biased select so simultaneous backend DATA cannot cross the deadline.
            // Headers (HTTP 200 + content-type) are already on the wire.
            //
            // If NO body bytes have been flushed yet, complete the RPC with a clean
            // terminal `grpc-status: 4` trailer (an empty-body deadline) so the
            // client surfaces gRPC DEADLINE_EXCEEDED instead of a transport failure
            // — clearing any buffered-but-unflushed tail is safe because the client
            // never saw a partial message. But once ANY body bytes are on the wire,
            // a length-prefixed gRPC message may be mid-frame (H3 DATA chunk
            // boundaries are independent of gRPC message boundaries), so dropping
            // the buffered remainder and synthesizing clean trailers would hand the
            // client a TRUNCATED message it surfaces as a protocol/internal error.
            // In that case RESET instead: the client sees a transport abort and its
            // own (equal) RPC deadline fires. Either way this client-owned expiry is
            // health-neutral (`ClientDisconnect`) and the gRPC status lands in the
            // metadata.
            _ = &mut grpc_deadline_sleep, if grpc_deadline_active && !stream_done => {
                client_deadline_expired = true;
                coalesce_buf.clear();
                if crate::http3::stream_util::grpc_deadline_can_send_terminal_status(
                    bytes_streamed,
                ) {
                    warn!(
                        "gRPC deadline (grpc-timeout) exceeded before any response body; \
                         completing with grpc-status DEADLINE_EXCEEDED"
                    );
                    if send_h3_grpc_terminal_trailers(
                        stream,
                        crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                        GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
                        grpc_deadline_at,
                    )
                    .await
                    {
                        grpc_trailer_status =
                            Some(crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED);
                        body_completed = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    } else {
                        crate::http3::stream_util::abort_response_stream(stream);
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    }
                } else {
                    warn!(
                        "gRPC deadline (grpc-timeout) exceeded mid-body; resetting the stream \
                         (a partial gRPC message would be truncated by synthesized trailers)"
                    );
                    crate::http3::stream_util::abort_response_stream(stream);
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                }
                // Record the gRPC status in metadata so observability reflects the
                // deadline on both the clean-trailer and reset paths.
                crate::proxy::insert_grpc_error_metadata(
                    &mut ctx.metadata,
                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                );
                break 'outer;
            }
            chunk_result = h3_resp.recv_stream.recv_data(), if !stream_done => {
                match chunk_result {
                    Ok(Some(mut chunk)) => {
                        just_received_backend_frame = true;
                        let chunk_len = chunk.remaining();
                        total_streamed += chunk_len;
                        // Backend RESPONSE bytes are bounded by the response-body
                        // limit (matching the plain native-H3 streaming path), not
                        // the request-side gRPC receive cap.
                        if effective_max_response_body_size_bytes > 0
                            && total_streamed > effective_max_response_body_size_bytes
                        {
                            crate::http3::stream_util::abort_response_stream(stream);
                            body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                            break 'outer;
                        }
                        if crate::http3::config::should_direct_send_response_chunk(
                            coalesce_buf.len(),
                            chunk_len,
                            coalesce_min_bytes,
                        ) {
                            let data =
                                crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                            if !await_downstream_grpc_write!(stream.send_data(data)) {
                                break 'outer;
                            }
                            bytes_streamed += chunk_len as u64;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                            continue;
                        }
                        let chunk_bytes =
                            crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                        coalesce_buf.extend_from_slice(&chunk_bytes);
                        if coalesce_buf.len() >= coalesce_min_bytes {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if !await_downstream_grpc_write!(stream.send_data(data)) {
                                break 'outer;
                            }
                            bytes_streamed += data_len;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                        }
                    }
                    Ok(None) => stream_done = true,
                    Err(error) => {
                        // `declared_content_length` was captured before the
                        // Content-Length header was stripped from the wire response.
                        if crate::http3::client::is_h3_graceful_close(&error)
                            && crate::http3::client::is_response_body_complete(
                                total_streamed as u64,
                                method,
                                response_status,
                                declared_content_length,
                            )
                        {
                            stream_done = true;
                        } else {
                            error!("Error reading backend h3 gRPC response during streaming: {}", error);
                            coalesce_buf.clear();
                            crate::http3::stream_util::abort_response_stream(stream);
                            let class = crate::http3::client::classify_http3_error(&error);
                            // A mid-stream QUIC/H3 transport failure (reset /
                            // protocol error) is a capability-downgrade signal —
                            // otherwise subsequent gRPC requests keep taking the
                            // native H3 path and repeat the failure until the next
                            // refresh. `is_h3_transport_error_class` excludes client
                            // disconnects, size errors, and read timeouts; graceful
                            // close needs the explicit check because the raw stream
                            // classifier maps an `H3_NO_ERROR` teardown to
                            // `ConnectionClosed` (only the pool's `classify_h3_error`
                            // has the typed `GracefulRemoteClose` signal).
                            if !crate::http3::client::is_h3_graceful_close(&error)
                                && crate::proxy::is_h3_transport_error_class(class)
                            {
                                state
                                    .backend_capabilities
                                    .mark_h3_unsupported(proxy, upstream_target);
                            }
                            body_error_class = Some(class);
                            break 'outer;
                        }
                    }
                }
            }
            _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if !await_downstream_grpc_write!(stream.send_data(data)) {
                    break 'outer;
                }
                bytes_streamed += data_len;
                flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
            }
            _ = &mut read_deadline, if read_timeout_active && !stream_done && coalesce_buf.is_empty() => {
                warn!(
                    "Backend read timeout ({}ms) during HTTP/3 gRPC streaming response body; aborting",
                    backend_read_timeout_ms
                );
                coalesce_buf.clear();
                crate::http3::stream_util::abort_response_stream(stream);
                body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                break 'outer;
            }
        }
        if stream_done {
            if !coalesce_buf.is_empty() {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if !await_downstream_grpc_write!(stream.send_data(data)) {
                    break 'outer;
                }
                bytes_streamed += data_len;
            }
            // Terminal trailers carry the gRPC status. Capture `grpc-status`
            // for the admission sample BEFORE stripping hop-by-hop names, then
            // forward the sanitized trailers (or FIN if none survive). The wait is
            // bounded by whichever is sooner: the per-frame `backend_read_timeout_ms`
            // (like the plain trailer-finish helper) or the absolute gRPC deadline.
            // Per-frame backend read timeout for the trailer wait — DISABLED under
            // a client `grpc-timeout` so only the absolute deadline bounds it (same
            // regime switch as the body loop's `read_timeout_active`).
            let trailer_read_at =
                (backend_read_timeout_ms > 0 && !client_deadline_present).then(|| {
                    tokio::time::Instant::now() + Duration::from_millis(backend_read_timeout_ms)
                });
            let trailer_wait_at: Option<tokio::time::Instant> =
                match (grpc_deadline_at, trailer_read_at) {
                    (Some(deadline), Some(read)) => Some(deadline.min(read)),
                    (Some(deadline), None) => Some(deadline),
                    (None, Some(read)) => Some(read),
                    (None, None) => None,
                };
            // Whether the bound firing first is the client's gRPC deadline (vs a
            // per-frame backend read timeout) — decides whether a timeout completes
            // the RPC with grpc-status: 4 or is treated as a backend read-timeout.
            let trailer_timeout_is_deadline = match (grpc_deadline_at, trailer_read_at) {
                (Some(deadline), Some(read)) => deadline <= read,
                (Some(_), None) => true,
                _ => false,
            };
            let trailers_result = match trailer_wait_at {
                Some(at) => {
                    match tokio::time::timeout_at(at, h3_resp.recv_stream.recv_trailers()).await {
                        Ok(result) => result,
                        Err(_) if trailer_timeout_is_deadline => {
                            client_deadline_expired = true;
                            // `stream_done` only proves the H3 DATA stream reached
                            // FIN — NOT that the last length-prefixed gRPC message
                            // ended on a frame boundary (a backend can FIN mid-frame).
                            // So only append a clean `grpc-status: 4` trailer when no
                            // body bytes were forwarded (empty-body deadline); once
                            // any body is on the wire, reset instead so a
                            // possibly-truncated message isn't capped with a clean
                            // status the client surfaces as a protocol error. Same
                            // rule as the mid-body deadline arm.
                            if crate::http3::stream_util::grpc_deadline_can_send_terminal_status(
                                bytes_streamed,
                            ) {
                                warn!(
                                    "gRPC deadline (grpc-timeout) exceeded while awaiting trailers \
                                     (empty body); completing with grpc-status DEADLINE_EXCEEDED"
                                );
                                if send_h3_grpc_terminal_trailers(
                                    stream,
                                    crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
                                    grpc_deadline_at,
                                )
                                .await
                                {
                                    grpc_trailer_status = Some(
                                        crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                                    );
                                    body_completed = true;
                                    body_error_class =
                                        Some(crate::retry::ErrorClass::ClientDisconnect);
                                } else {
                                    crate::http3::stream_util::abort_response_stream(stream);
                                    client_disconnected = true;
                                    body_error_class =
                                        Some(crate::retry::ErrorClass::ClientDisconnect);
                                }
                            } else {
                                warn!(
                                    "gRPC deadline (grpc-timeout) exceeded while awaiting trailers \
                                     after body bytes; resetting (gRPC frame completeness unverified)"
                                );
                                crate::http3::stream_util::abort_response_stream(stream);
                                body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                            }
                            crate::proxy::insert_grpc_error_metadata(
                                &mut ctx.metadata,
                                crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                                GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
                            );
                            break;
                        }
                        Err(_) => {
                            warn!(
                                "Backend trailer read timed out ({}ms) during HTTP/3 gRPC streaming response",
                                backend_read_timeout_ms
                            );
                            crate::http3::stream_util::abort_response_stream(stream);
                            body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                            break;
                        }
                    }
                }
                None => h3_resp.recv_stream.recv_trailers().await,
            };
            match trailers_result {
                Ok(Some(mut trailers)) => {
                    grpc_trailer_status = trailers.get("grpc-status").map(|value| {
                        value.to_str().map_or(u32::MAX, |value| {
                            crate::proxy::grpc_proxy::parse_grpc_status_value(value)
                        })
                    });
                    strip_response_hop_by_hop_trailers(&mut trailers);
                    // Last point where the response-header policy boundary can
                    // still bind this RPC's terminal metadata. `grpc_trailer_status`
                    // above is already latched from the pristine trailer block, so
                    // backend-health classification is unaffected either way — and
                    // the reserved status/message/details fields are exempt by
                    // section, so a governed drop can never truncate the RPC
                    // outcome. Runs once, on the trailer frame only.
                    let removed = reconcile_streaming_backend_trailers(
                        &mut trailers,
                        &response_headers,
                        &grpc_pre_policy_response_headers,
                        response_trailer_governance,
                        GatewayOwnedResponseHeaders::default(),
                        TrailerSectionKind::NativeGrpcTerminal,
                    );
                    if removed > 0 {
                        debug!(
                            removed,
                            "native H3 gRPC: dropped trailer application metadata \
                             governed by response header policy"
                        );
                    }
                    let finish_outcome = if !trailers.is_empty() {
                        // `send_trailers` only writes the trailer HEADERS frame;
                        // `finish()` is required to FIN the QUIC send side so the
                        // client sees end-of-response (the shared
                        // `finish_h3_response_with_backend_trailers` helper does the
                        // same). Skipping it leaves the stream open until timeout.
                        send_h3_grpc_trailers_and_finish_before_deadline(
                            stream,
                            trailers,
                            grpc_deadline_at,
                        )
                        .await
                    } else {
                        // Real trailers were all hop-by-hop: if the backend put its
                        // terminal status only in the (stripped) initial headers,
                        // re-emit it as a synthesized trailer.
                        finish_h3_grpc_stream_trailers_only(
                            stream,
                            wire_grpc_status.as_deref(),
                            wire_grpc_message.as_deref(),
                            wire_grpc_status_details.as_deref(),
                            grpc_deadline_at,
                        )
                        .await
                    };
                    match finish_outcome {
                        H3GrpcResponseFinish::Complete => body_completed = true,
                        H3GrpcResponseFinish::DeadlineExceeded => {
                            client_deadline_expired = true;
                            crate::http3::stream_util::abort_response_stream(stream);
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                        H3GrpcResponseFinish::WriteFailed => {
                            crate::http3::stream_util::abort_response_stream(stream);
                            client_disconnected = true;
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                    }
                }
                Ok(None) => {
                    // No terminal TRAILERS frame — a Trailers-Only response carries
                    // its status in the (stripped) initial headers; re-emit it.
                    match finish_h3_grpc_stream_trailers_only(
                        stream,
                        wire_grpc_status.as_deref(),
                        wire_grpc_message.as_deref(),
                        wire_grpc_status_details.as_deref(),
                        grpc_deadline_at,
                    )
                    .await
                    {
                        H3GrpcResponseFinish::Complete => body_completed = true,
                        H3GrpcResponseFinish::DeadlineExceeded => {
                            client_deadline_expired = true;
                            crate::http3::stream_util::abort_response_stream(stream);
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                        H3GrpcResponseFinish::WriteFailed => {
                            crate::http3::stream_util::abort_response_stream(stream);
                            client_disconnected = true;
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                    }
                }
                Err(err) if crate::http3::client::is_h3_graceful_close(&err) => {
                    match finish_h3_grpc_stream_trailers_only(
                        stream,
                        wire_grpc_status.as_deref(),
                        wire_grpc_message.as_deref(),
                        wire_grpc_status_details.as_deref(),
                        grpc_deadline_at,
                    )
                    .await
                    {
                        H3GrpcResponseFinish::Complete => body_completed = true,
                        H3GrpcResponseFinish::DeadlineExceeded => {
                            client_deadline_expired = true;
                            crate::http3::stream_util::abort_response_stream(stream);
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                        H3GrpcResponseFinish::WriteFailed => {
                            crate::http3::stream_util::abort_response_stream(stream);
                            client_disconnected = true;
                            body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        }
                    }
                }
                Err(err) => {
                    error!(
                        "Error reading backend h3 gRPC trailers during streaming: {}",
                        err
                    );
                    crate::http3::stream_util::abort_response_stream(stream);
                    let class = crate::http3::client::classify_http3_error(&err);
                    // Same capability-downgrade signal as the body-relay error arm:
                    // a transport-class failure at the trailer boundary should stop
                    // routing subsequent gRPC requests to this H3 target.
                    if crate::proxy::is_h3_transport_error_class(class) {
                        state
                            .backend_capabilities
                            .mark_h3_unsupported(proxy, upstream_target);
                    }
                    body_error_class = Some(class);
                }
            }
            break;
        }
    }

    // Record outcome. CB / passive-health key off the HTTP transport status:
    // gRPC application failures ride on HTTP 200 and must not trip the breaker
    // or passive health (matching the H2 gRPC bridge). Every fault reaching this
    // point is POST-HEADER — the backend's response headers were already received
    // and forwarded, so the request reached the backend application layer and
    // `connection_error` is always false. The specific mid-response fault (reset,
    // malformed trailers, ResponseBodyTooLarge) rides in `body_outcome_error_class`
    // so the post-wire error-class breaker path counts it; recording
    // `connection_error=true` here would instead be filtered for proxies with
    // `trip_on_connection_errors=false`. ReadWriteTimeout / ClientDisconnect stay
    // neutral via their classes.
    let body_outcome_connection_error = false;
    // When the backend itself returned a failure status (a raw HTTP 5xx instead of
    // a gRPC response, or a status the proxy configured as a breaker failure), a
    // concurrent client disconnect during the body/trailer forward must NOT mask
    // it: `ClientDisconnect` is client-side and skips CB / passive-health entirely,
    // so the real backend failure would be neutralized. Drop the body class in that
    // case so the failure status drives the recorded outcome — mirrors the plain
    // native-H3 streaming path. (gRPC application failures still ride on HTTP 200
    // and are not failure statuses here.)
    let backend_failure_status = response_status >= 500
        || proxy
            .circuit_breaker
            .as_ref()
            .is_some_and(|cb| cb.failure_status_codes.contains(&response_status));
    let body_outcome_error_class = match body_error_class {
        Some(crate::retry::ErrorClass::ClientDisconnect) if backend_failure_status => None,
        other => other,
    };
    crate::proxy::backend_dispatch::record_backend_outcome(
        state,
        proxy,
        &epoch.load_balancer,
        upstream_balancer,
        upstream_target,
        cb_target_key,
        response_status,
        body_outcome_connection_error,
        body_outcome_error_class,
        cb_is_half_open_probe,
        false,
        backend_start.elapsed(),
    );
    // The adaptive-concurrency limiter samples the backend gRPC terminal status:
    // a non-OK `grpc-status` (trailer or trailers-only header) maps to a 5xx so the
    // limiter shrinks, while a client-side status stays healthy. Mirrors the H2
    // streaming gRPC bridge. Gate on whether a backend terminal status was actually
    // RECEIVED — NOT on `body_completed` (the client-side `send_trailers`/`finish`
    // succeeding): if an H3-only backend returns `grpc-status: 14` and the downstream
    // client then disconnects while we write the trailers, `body_completed` is false
    // but the backend still failed, and recording HTTP 200 would make a failing
    // backend look healthy to the limiter.
    let admission_status = if grpc_trailer_status.is_some() || backend_header_grpc_status.is_some()
    {
        let mut trailer_view: HashMap<String, String> = HashMap::new();
        if let Some(code) = grpc_trailer_status {
            trailer_view.insert("grpc-status".to_string(), code.to_string());
        }
        // Use the PRE-HOOK Trailers-Only `grpc-status` snapshot, not the
        // (possibly plugin-mutated) `response_headers`, so an after_proxy hook
        // that rewrites/removes `grpc-status` cannot make a failing backend look
        // healthy to the limiter.
        let mut header_view: HashMap<String, String> = HashMap::new();
        if let Some(code) = backend_header_grpc_status.as_deref() {
            header_view.insert("grpc-status".to_string(), code.to_string());
        }
        crate::proxy::grpc_proxy::grpc_admission_status_from_maps(
            &trailer_view,
            &header_view,
            response_status,
        )
    } else {
        response_status
    };
    record_h3_backend_admission_outcome(
        &mut backend_admission_permits,
        admission_status,
        body_outcome_connection_error,
        body_outcome_error_class,
        backend_admission_response_elapsed,
    );
    if client_deadline_expired {
        crate::proxy::insert_grpc_error_metadata(
            &mut ctx.metadata,
            crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
        );
    } else {
        let grpc_status = grpc_trailer_status
            .or_else(|| {
                wire_grpc_status
                    .as_deref()
                    .map(crate::proxy::grpc_proxy::parse_grpc_status_value)
            })
            .unwrap_or(crate::proxy::grpc_proxy::grpc_status::UNKNOWN);
        ctx.metadata
            .insert("grpc_status".to_string(), grpc_status.to_string());
    }
    log_h3_grpc_transaction(
        proxy,
        ctx,
        plugins,
        method,
        original_request_path,
        backend_url,
        backend_resolved_ip,
        proxy_headers,
        response_status,
        request_body_bytes_seen.load(std::sync::atomic::Ordering::Acquire),
        bytes_streamed,
        body_completed,
        client_disconnected,
        None,
        body_error_class,
        start_time,
        backend_admission_response_elapsed.as_secs_f64() * 1000.0,
        *plugin_execution_ns,
    )
    .await;
    record_request(state, response_status);
    Ok(())
}

/// Build and emit the `TransactionSummary` for a native-H3 gRPC dispatch.
///
/// Factored out of [`dispatch_grpc_native_h3`] so the failure, reject, and
/// success branches share one summary shape (the inline native-H3 paths inline
/// this; the gRPC path has enough branches to warrant a helper).
#[allow(clippy::too_many_arguments)]
async fn log_h3_grpc_transaction(
    proxy: &Proxy,
    ctx: &RequestContext,
    plugins: &[Arc<dyn Plugin>],
    method: &str,
    request_path: &str,
    backend_url: &str,
    backend_resolved_ip: Option<&str>,
    proxy_headers: &HashMap<String, String>,
    response_status_code: u16,
    bytes_sent: u64,
    bytes_received: u64,
    body_completed: bool,
    client_disconnected: bool,
    error_class: Option<crate::retry::ErrorClass>,
    body_error_class: Option<crate::retry::ErrorClass>,
    start_time: std::time::Instant,
    backend_ttfb_ms: f64,
    plugin_execution_ns: u64,
) {
    let backend_total_ms = crate::plugins::LATENCY_UNKNOWN_MS;
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms = ctx
        .plugin_http_call_ns
        .load(std::sync::atomic::Ordering::Relaxed) as f64
        / 1_000_000.0;
    let (gateway_processing_ms, gateway_overhead_ms) = TransactionSummary::derive_gateway_latencies(
        total_ms,
        backend_total_ms,
        plugin_execution_ms,
        true,
    );
    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        http_method: method.to_string(),
        request_path: request_path.to_string(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target: Some(strip_query_params(backend_url).to_string()),
        backend_resolved_ip: backend_resolved_ip.map(str::to_owned),
        response_status_code,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: gateway_processing_ms,
        latency_backend_ttfb_ms: backend_ttfb_ms,
        latency_backend_total_ms: backend_total_ms,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: proxy_headers.get("user-agent").cloned(),
        response_streamed: true,
        client_disconnected,
        body_error_class,
        body_completed,
        bytes_sent,
        bytes_received,
        error_class,
        mirror: false,
        metadata: crate::proxy::clone_log_metadata(ctx),
        ai_usage_export: ctx.ai_usage_export.clone(),
        proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}

/// Streaming proxy path: sends backend response chunks directly to the H3 client
/// as they arrive, without collecting the full body in memory. Returns the status,
/// final response headers, error class, and body-streaming outcome after the
/// stream completes.
///
/// Uses the native h3+quinn connection pool instead of reqwest.
/// Response headers and `after_proxy` hooks are processed before streaming begins.
/// The response body is forwarded chunk-by-chunk with coalescing for QUIC efficiency.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_h3_streaming(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body_bytes: Vec<u8>,
    client_ip: &str,
    xff_append_ip: &str,
    upstream_target: Option<&UpstreamTarget>,
    epoch: &crate::request_epoch::RequestEpoch,
    sticky_cookie_needed: bool,
    h3_stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    plugin_execution_ns: &mut u64,
    backend_admission_start: std::time::Instant,
    trailer_governance: ResponseTrailerGovernance<'_>,
) -> Result<H3StreamResult, anyhow::Error> {
    // Effective response ceiling for this request: the global knob narrowed by
    // any active route ceiling (`GHSA-xrfj-852f-645j`). Hoisted so the streaming
    // chunk loop below compares against a plain local.
    let effective_max_response_body_size_bytes = ctx.effective_max_response_body_size_bytes();
    let h3_headers = build_h3_backend_headers(
        proxy,
        upstream_target,
        headers,
        client_ip,
        xff_append_ip,
        state,
        ctx.request_is_secure,
        ctx.is_early_data,
    );
    let body = bytes::Bytes::from(body_bytes);

    // Dispatch via the h3+quinn connection pool
    let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(proxy);
    let streaming_resp = if let Some(target) = upstream_target {
        state
            .h3_pool
            .request_with_target_streaming(
                proxy,
                &target.host,
                target.port,
                method,
                backend_url,
                &h3_headers,
                body,
                tls_config_fn,
            )
            .await
    } else {
        state
            .h3_pool
            .request_streaming(proxy, method, backend_url, &h3_headers, body, tls_config_fn)
            .await
    };

    let mut h3_resp = match streaming_resp {
        Ok(r) => r,
        Err(e) => {
            error!("Backend request failed (HTTP/3 streaming): {}", e);
            // Capture the typed body-on-wire signal BEFORE classifying so
            // the streaming-path `record_backend_outcome` can drive
            // `connection_error` from `H3PoolError::request_on_wire()`
            // rather than re-deriving from `error_class`. The class is a
            // string-heuristic-friendly label; the typed bool is
            // ground-truth for "did any internal pool attempt commit the
            // request to the backend?". A connect-phase QUIC reset can
            // string-classify as `ConnectionReset` (post-wire by
            // `request_reached_wire`) even though no request reached the
            // backend — the typed signal correctly reports `false` for
            // that case.
            let request_on_wire = e.request_on_wire();
            let h3_error_class = classify_h3_error(&e);
            crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            let (reject_status, reject_body) = h3_backend_failure_status_body(&e);
            // Do NOT propagate a send error here: this path already started
            // least-connections LB tracking before dispatch, so returning `Err`
            // would skip the caller's `record_backend_outcome` and leak the
            // active-connection count for the selected target when the client
            // disconnects during the reject write. Report the disconnect so the
            // caller still records the outcome and releases the connection —
            // same contract as the size-limit / after_proxy reject paths below.
            let reject_sent = send_h3_response(h3_stream, reject_status, reject_body)
                .await
                .is_ok();
            // No backend response was received (pre-headers dispatch failure),
            // so backend_status is the gateway-synthesized reject status
            // (502 generic, 504 for a backend read timeout).
            return Ok(h3_backend_unavailable_stream_result(
                reject_status.as_u16(),
                h3_error_class,
                request_on_wire,
                reject_sent,
                backend_admission_start.elapsed(),
            ));
        }
    };

    let backend_admission_elapsed = backend_admission_start.elapsed();
    let response_status = h3_resp.status;
    let mut response_headers = h3_resp.headers;

    // Strip hop-by-hop response headers per RFC 9110 §7.6.1 — see
    // `proxy::headers` for the canonical predicate. Response-direction
    // set differs from the request-direction set.
    strip_client_response_hop_by_hop_headers(&mut response_headers);

    // Capture original response invariants before `after_proxy` below can let a
    // response transformer strip `Content-Range` or `Cache-Control`; compression
    // honors these markers before committing response coding headers.
    stamp_h3_original_response_metadata(ctx, response_status, &response_headers);

    // Enforce response body size limit via Content-Length fast path
    if let Some(len) = crate::proxy::declared_response_length_exceeds_limit(
        &response_headers,
        effective_max_response_body_size_bytes,
    ) {
        warn!(
            "Backend response body ({} bytes) exceeds limit ({} bytes)",
            len, effective_max_response_body_size_bytes
        );
        // Same connection-accounting contract as the after_proxy reject below:
        // never propagate a send error, or the caller's `record_backend_outcome`
        // is skipped and the LB active-connection count leaks for a client that
        // disconnected during the reject write.
        let size_reject_sent = send_h3_response(
            h3_stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
        )
        .await
        .is_ok();
        return Ok(H3StreamResult {
            status: 502,
            // The backend did respond (headers received) before we found the
            // body too large; CB/passive-health should see the real backend
            // status, not the gateway-synthesized 502.
            backend_status: response_status,
            error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: !size_reject_sent,
            body_error_class: None,
            // Headers were already received from the backend before we
            // discovered the body exceeded our limit, so the request
            // reached the wire. The 502 we synthesize is a gateway-side
            // policy rejection, not a transport failure.
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    // Same pre-policy capture as the inline native-H3 streaming relay: the
    // initial HEADERS frame is committed before the backend's trailers exist,
    // so the trailer frame needs evidence of what the response-header phases
    // actually changed — including the default `content-type` this relay
    // synthesizes below, which is a gateway-authored wire mutation.
    let gateway_synthesizes_content_type = !response_headers.contains_key("content-type");
    let pre_policy_response_headers = PrePolicyResponseHeaders::capture_for_streaming(
        &response_headers,
        trailer_governance,
        !plugins.is_empty() || sticky_cookie_needed || gateway_synthesizes_content_type,
    );

    // after_proxy hooks run before streaming begins so headers can be modified
    // or the response can be rejected before any downstream bytes are committed.
    if let Some(reject) = run_h3_streaming_after_proxy_hooks(
        plugins,
        ctx,
        response_status,
        &mut response_headers,
        plugin_execution_ns,
    )
    .await
    {
        let reject_status =
            StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
        // Do NOT propagate a send error here: this path already started
        // least-connections LB tracking before dispatch, so returning `Err`
        // would skip the caller's `record_backend_outcome` and leak the
        // active-connection count for the selected target. Report the
        // disconnect in the result so the caller still records the (true
        // backend) outcome and releases the connection.
        let reject_sent = send_h3_reject_response(
            h3_stream,
            reject_status,
            // Shared-allocation handle clone, not a payload copy; `reject.body`
            // stays live for the streamed-byte accounting below.
            reject.body.clone(),
            &reject.headers,
            RejectBodyDisposition::for_request(&ctx.method, reject_status.as_u16()),
        )
        .await
        .is_ok();
        return Ok(H3StreamResult {
            status: reject.status_code,
            // The backend already returned `response_status`; the after_proxy
            // plugin override is a gateway policy decision. CB/passive-health
            // must see the true backend status so a plugin neither penalizes a
            // healthy backend nor masks a real backend failure.
            backend_status: response_status,
            error_class: None,
            body_completed: reject_sent,
            bytes_streamed: if reject_sent {
                reject.body.len() as u64
            } else {
                0
            },
            client_disconnected: !reject_sent,
            body_error_class: if reject_sent {
                None
            } else {
                Some(crate::retry::ErrorClass::ClientDisconnect)
            },
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    // Sticky session cookie injection
    inject_sticky_cookie(
        epoch,
        proxy,
        upstream_target,
        sticky_cookie_needed,
        &mut response_headers,
    );

    // Final protocol-aware strip after after_proxy (RFC 9114 §4.2). Ordinary
    // streaming framing removes Content-Length; only HEAD keeps a valid
    // representation length. Capture the declared length first for the
    // graceful-close completeness gate in the relay loop below.
    let declared_content_length = crate::proxy::headers::preserved_response_content_length(
        &response_headers,
        response_status,
    );
    sanitize_client_response_headers_for_wire(
        &mut response_headers,
        ClientResponseFraming::for_streaming_response(method, response_status),
    );

    // Send response headers on the H3 stream. Default `content-type` goes into
    // the header MAP, not just the builder, so the map handed to the trailer
    // boundary below is the field set the client actually received. See the
    // matching note in the inline native-H3 relay.
    response_headers
        .entry("content-type".to_string())
        .or_insert_with(|| "application/json".to_string());
    let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_builder =
        apply_response_headers(Response::builder().status(status), &response_headers);

    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
    if h3_stream.send_response(resp).await.is_err() {
        // Client QUIC stream is already gone — nothing streamed.
        return Ok(H3StreamResult {
            status: response_status,
            backend_status: response_status,
            error_class: None,
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: true,
            body_error_class: Some(crate::retry::ErrorClass::ClientDisconnect),
            // Headers came back from the backend; the request reached
            // the wire. The client gave up on us between then and now.
            request_on_wire: true,
            backend_admission_elapsed,
        });
    }

    // Stream response body chunks from the h3 backend recv_stream with adaptive
    // coalescing and time-based flushing. Uses a pinned Sleep to avoid
    // allocating a new timer wheel entry on every select! iteration.
    let coalesce_min_bytes = state.env_config.http3_coalesce_min_bytes;
    let coalesce_max_bytes = state.env_config.http3_coalesce_max_bytes;
    let flush_interval =
        std::time::Duration::from_micros(state.env_config.http3_flush_interval_micros);
    let mut coalesce_buf = BytesMut::with_capacity(coalesce_max_bytes);
    let mut total_streamed: usize = 0;
    let flush_timer = tokio::time::sleep(flush_interval);
    tokio::pin!(flush_timer);
    // Per-frame backend read deadline (mirrors the inline native-H3 streaming
    // path): abort if the backend stalls for `backend_read_timeout_ms` between
    // response-body frames after the headers were sent. Reset on each received
    // frame; inert (the select! arm guard is off) when the timeout is 0.
    let backend_read_timeout_ms = proxy.backend_read_timeout_ms;
    let read_timeout_active = backend_read_timeout_ms > 0;
    let read_deadline = tokio::time::sleep(std::time::Duration::from_millis(
        backend_read_timeout_ms.max(1),
    ));
    tokio::pin!(read_deadline);
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut client_disconnected = false;
    let mut body_completed = false;
    let mut body_error_class: Option<crate::retry::ErrorClass> = None;
    let mut terminal_error_class: Option<crate::retry::ErrorClass> = None;
    // See `just_received_backend_frame` in the native H3 streaming loop: the
    // deadline is re-armed at the loop head AFTER the prior frame's downstream
    // send, so slow-client backpressure is never charged to the backend.
    let mut just_received_backend_frame = false;

    'outer: loop {
        if read_timeout_active && just_received_backend_frame && coalesce_buf.is_empty() {
            read_deadline.as_mut().reset(
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(backend_read_timeout_ms),
            );
            just_received_backend_frame = false;
        }
        tokio::select! {
            chunk_result = h3_resp.recv_stream.recv_data(), if !stream_done => {
                match chunk_result {
                    Ok(Some(mut chunk)) => {
                        // Defer the deadline re-arm to the loop head.
                        just_received_backend_frame = true;
                        let chunk_len = chunk.remaining();
                        // Always count received bytes — the graceful-close
                        // recovery below uses this to decide if the body is
                        // semantically complete, even when the body-size
                        // limit is disabled (FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0).
                        total_streamed += chunk_len;
                        if effective_max_response_body_size_bytes > 0
                            && total_streamed > effective_max_response_body_size_bytes
                        {
                            warn!(
                                "Backend response exceeded {} byte limit during streaming",
                                effective_max_response_body_size_bytes
                            );
                            crate::http3::stream_util::abort_response_stream(h3_stream);
                            terminal_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                            body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                            break 'outer;
                        }

                        if crate::http3::config::should_direct_send_response_chunk(
                            coalesce_buf.len(),
                            chunk_len,
                            coalesce_min_bytes,
                        ) {
                            let data =
                                crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                            if h3_stream.send_data(data).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += chunk_len as u64;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                            continue;
                        }

                        let chunk_bytes =
                            crate::http3::config::copy_remaining_response_chunk(&mut chunk);
                        coalesce_buf.extend_from_slice(&chunk_bytes);

                        if coalesce_buf.len() >= coalesce_min_bytes {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if h3_stream.send_data(data).await.is_err() {
                                client_disconnected = true;
                                body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                                break 'outer;
                            }
                            bytes_streamed += data_len;
                            flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
                        }
                    }
                    Ok(None) => {
                        stream_done = true;
                    }
                    Err(e) => {
                        // Captured before the final wire boundary stripped it.
                        let cl: Option<u64> = declared_content_length;
                        let received = total_streamed as u64;
                        if crate::http3::client::is_h3_graceful_close(&e)
                            && crate::http3::client::is_response_body_complete(
                                received, method, response_status, cl,
                            )
                        {
                            debug!(
                                bytes_received = received,
                                "H3 streaming recv_data hit graceful close after complete body; treating as success"
                            );
                            stream_done = true;
                        } else {
                            error!("Error reading backend h3 response during streaming: {}", e);
                            coalesce_buf.clear();
                            crate::http3::stream_util::abort_response_stream(h3_stream);
                            let class = crate::http3::client::classify_http3_error(&e);
                            // Mid-stream transport fault → capability downgrade
                            // (parity with gRPC streaming; issue #2939).
                            // `H3_NO_ERROR` / GOAWAY is never that signal.
                            if !crate::http3::client::is_h3_graceful_close(&e)
                                && crate::proxy::is_h3_transport_error_class(class)
                            {
                                state
                                    .backend_capabilities
                                    .mark_h3_unsupported(proxy, upstream_target);
                            }
                            terminal_error_class = Some(class);
                            body_error_class = Some(class);
                            break 'outer;
                        }
                    }
                }
            }

            _ = &mut flush_timer, if !coalesce_buf.is_empty() && !stream_done => {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if h3_stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += data_len;
                flush_timer.as_mut().reset(tokio::time::Instant::now() + flush_interval);
            }
            _ = &mut read_deadline, if read_timeout_active && !stream_done && coalesce_buf.is_empty() => {
                warn!(
                    "Backend read timeout ({}ms) during HTTP/3 streaming response body; aborting",
                    backend_read_timeout_ms
                );
                coalesce_buf.clear();
                crate::http3::stream_util::abort_response_stream(h3_stream);
                terminal_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                break 'outer;
            }
        }

        if stream_done {
            if !coalesce_buf.is_empty() {
                let data = coalesce_buf.split().freeze();
                let data_len = data.len() as u64;
                if h3_stream.send_data(data).await.is_err() {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    break 'outer;
                }
                bytes_streamed += data_len;
            }
            match finish_h3_response_with_backend_trailers(
                h3_stream,
                &mut h3_resp.recv_stream,
                backend_read_timeout_ms,
                H3StreamingTrailerPolicy {
                    final_headers: &response_headers,
                    pre_policy: &pre_policy_response_headers,
                    governance: trailer_governance,
                    // Plain-flavor relay: no field name is exempt here.
                    section: TrailerSectionKind::PlainResponse,
                },
            )
            .await
            {
                Ok(_) => body_completed = true,
                Err(H3TrailerFinishError::Backend(err)) => {
                    error!(
                        "Error reading backend h3 response trailers during streaming: {}",
                        err
                    );
                    crate::http3::stream_util::abort_response_stream(h3_stream);
                    let class = crate::http3::client::classify_http3_error(&err);
                    // Trailer-boundary transport faults downgrade like mid-body
                    // resets (issue #2939), with the same graceful-close
                    // exclusion.
                    if !crate::http3::client::is_h3_graceful_close(&err)
                        && crate::proxy::is_h3_transport_error_class(class)
                    {
                        state
                            .backend_capabilities
                            .mark_h3_unsupported(proxy, upstream_target);
                    }
                    terminal_error_class = Some(class);
                    body_error_class = Some(class);
                }
                Err(H3TrailerFinishError::BackendTimeout) => {
                    warn!(
                        "Backend trailer read timeout ({}ms) during HTTP/3 streaming response",
                        backend_read_timeout_ms
                    );
                    crate::http3::stream_util::abort_response_stream(h3_stream);
                    terminal_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                    body_error_class = Some(crate::retry::ErrorClass::ReadWriteTimeout);
                }
                Err(H3TrailerFinishError::Client) => {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                }
            }
            break;
        }
    }

    Ok(H3StreamResult {
        status: response_status,
        backend_status: response_status,
        error_class: terminal_error_class,
        body_completed,
        bytes_streamed,
        client_disconnected,
        body_error_class,
        // Reached this point only after `request_streaming` returned
        // `Ok(_)`, which means the H3 pool committed the request and
        // produced response headers. Mid-stream aborts are post-wire
        // by construction — we already have headers from the backend.
        request_on_wire: true,
        backend_admission_elapsed,
    })
}

/// Outcome of a buffered HTTP/3 backend request.
///
/// Carries the typed [`crate::http3::client::H3PoolError::request_on_wire`]
/// signal alongside the conventional response fields so call sites can
/// drive `connection_error` directly from the pool's body-on-wire bool
/// rather than re-deriving it from `error_class` via
/// [`crate::retry::request_reached_wire`]. The latter is fragile for
/// H3 because the string-heuristic fallback in `classify_http3_error`
/// can label a connect-phase QUIC reset as `ConnectionReset`
/// (post-wire by `request_reached_wire`) when the typed signal would
/// correctly report it as `request_on_wire=false` (no commitment).
///
/// `request_on_wire` semantics:
/// - `true` for success and for any error path where the H3 pool
///   committed the request to the backend on at least one internal
///   attempt (post-`send_request`, including graceful-close at
///   `recv_response`, mid-body abort, ResponseBodyTooLarge).
/// - `false` only for pre-commitment dispatch failures: DNS / TLS /
///   connect / pre-`send_request`. Drives
///   `BackendResponse::connection_error = true` so
///   `retry_on_connect_failure` can fire regardless of HTTP method.
struct H3BufferedDispatchResult {
    status: u16,
    body: Bytes,
    headers: HashMap<String, String>,
    /// Backend response trailers (issue #1630), still unsanitized. The buffered
    /// native-H3 send path forwards them only when no response-body plugin
    /// phase processed the response and no phase replaced the bytes
    /// (auth/logging-only plugins keep trailers; body-inspecting, mutating,
    /// rejecting, and normalizing phases drop them). Surviving trailers are
    /// reconciled field-by-field against the response-header policy in force
    /// (`reconcile_backend_trailers_with_response_policy`) so a trailer cannot
    /// reintroduce a field that policy removed, then get response-direction
    /// hop-by-hop names stripped before forwarding. `None` on every
    /// gateway-synthesized error/reject below (no backend trailers to forward),
    /// and `None` for a successful response that carried no trailers.
    trailers: Option<http::HeaderMap>,
    error_class: Option<crate::retry::ErrorClass>,
    request_on_wire: bool,
}

/// Convert a buffered cross-protocol (`proxy_to_backend_retry`) response into
/// the H3 buffered retry loop's result shape.
///
/// Used when LB rotation moves onto an Unknown/Unsupported H3 target so the
/// attempt bridges via H1/H2 instead of burning a doomed QUIC connect timeout
/// (issue #2937). Reqwest responses do not carry HTTP/3 trailers.
fn h3_buffered_result_from_backend_response(
    response: crate::retry::BackendResponse,
) -> H3BufferedDispatchResult {
    let request_on_wire = !response.connection_error;
    let body = match response.body {
        crate::retry::ResponseBody::Buffered(bytes) => bytes,
        // `proxy_to_backend_retry(..., stream_response = false)` always returns
        // `Buffered`. Treat any streaming variant as a bridge programming
        // fault rather than panicking on the proxy path.
        crate::retry::ResponseBody::Streaming { .. }
        | crate::retry::ResponseBody::StreamingH2(_)
        | crate::retry::ResponseBody::StreamingH3(_) => {
            return H3BufferedDispatchResult {
                status: 502,
                body: Bytes::from_static(br#"{"error":"Backend unavailable"}"#),
                headers: HashMap::new(),
                trailers: None,
                error_class: Some(crate::retry::ErrorClass::ProtocolError),
                request_on_wire,
            };
        }
    };
    H3BufferedDispatchResult {
        status: response.status_code,
        body,
        headers: response.headers,
        trailers: None,
        error_class: response.error_class,
        request_on_wire,
    }
}

/// Proxy a request to the backend (buffered path — collects full response body).
///
/// Uses the native h3+quinn connection pool instead of reqwest.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_h3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body_bytes: &[u8],
    client_ip: &str,
    xff_append_ip: &str,
    upstream_target: Option<&UpstreamTarget>,
    request_is_secure: bool,
    is_early_data: bool,
    // Already-folded effective response ceiling (global ∧ route), `0` meaning
    // unlimited. Passed in because this helper has no request context to derive
    // it from (`GHSA-xrfj-852f-645j`).
    effective_max_response_body_size_bytes: usize,
) -> H3BufferedDispatchResult {
    let h3_headers = build_h3_backend_headers(
        proxy,
        upstream_target,
        headers,
        client_ip,
        xff_append_ip,
        state,
        request_is_secure,
        is_early_data,
    );
    let body = bytes::Bytes::copy_from_slice(body_bytes);

    let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(proxy);
    let result = if let Some(target) = upstream_target {
        state
            .h3_pool
            .request_with_target(
                proxy,
                &target.host,
                target.port,
                method,
                backend_url,
                &h3_headers,
                body,
                tls_config_fn,
            )
            .await
    } else {
        state
            .h3_pool
            .request(proxy, method, backend_url, &h3_headers, body, tls_config_fn)
            .await
    };

    match result {
        Ok(response) => {
            // Hop-by-hop headers already filtered during collection in the H3 pool.
            let crate::http3::client::H3BufferedResponse {
                status,
                body: resp_body,
                headers: resp_headers,
                trailers: resp_trailers,
            } = response;

            // Enforce response body size limit
            if effective_max_response_body_size_bytes > 0
                && resp_body.len() > effective_max_response_body_size_bytes
            {
                warn!(
                    "Backend response body ({} bytes) exceeds limit ({} bytes)",
                    resp_body.len(),
                    effective_max_response_body_size_bytes
                );
                return H3BufferedDispatchResult {
                    status: 502,
                    body: Bytes::from_static(
                        br#"{"error":"Backend response body exceeds maximum size"}"#,
                    ),
                    headers: HashMap::new(),
                    trailers: None,
                    error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                    // We received the full response from the backend before
                    // discovering the size violation; the request reached
                    // the wire. The 502 we synthesize here is a gateway-
                    // side policy rejection.
                    request_on_wire: true,
                };
            }

            H3BufferedDispatchResult {
                status,
                body: resp_body,
                headers: resp_headers,
                // Forward backend trailers verbatim; the buffered send path
                // strips response-direction hop-by-hop names before emitting
                // them to the client (issue #1630).
                trailers: resp_trailers,
                error_class: None,
                // Successful response — the request was committed and
                // the response was received. `request_on_wire=true` means
                // `connection_error=false` at every consumer site.
                request_on_wire: true,
            }
        }
        Err(e) => {
            error!(
                "Backend request failed (HTTP/3 frontend): connection error details: {}",
                e
            );
            // Capture the typed body-on-wire signal BEFORE classifying
            // the error: it is the authoritative input to
            // `connection_error` at every consumer site (retry decision,
            // CB record_failure, warn log, record_backend_outcome).
            // Re-deriving from `error_class` via `request_reached_wire`
            // is fragile because the string-heuristic fallback in
            // `classify_http3_error` can label a connect-phase QUIC
            // reset as `ConnectionReset` (post-wire) when the typed
            // signal correctly reports `false` (no commitment).
            let request_on_wire = e.request_on_wire();
            let h3_error_class = classify_h3_error(&e);
            crate::proxy::record_port_exhaustion_if_class(&state.overload, h3_error_class);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            // Read timeouts surface as 504 Backend timeout (matching the
            // direct-H2 / HBONE read-timeout arms); everything else keeps
            // the generic 502.
            let (reject_status, reject_body) = h3_backend_failure_status_body(&e);
            H3BufferedDispatchResult {
                status: reject_status.as_u16(),
                body: Bytes::from_static(reject_body.as_bytes()),
                headers: HashMap::new(),
                trailers: None,
                error_class: Some(h3_error_class),
                request_on_wire,
            }
        }
    }
}

/// Send an HTTP/3 response with a body. Halts the request-body recv half
/// before returning so an in-flight client upload does not surface as
/// `RESET_STREAM(0x0)` when this `RequestStream` is later dropped.
async fn send_h3_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: &str,
) -> Result<(), anyhow::Error> {
    send_h3_response_with_recv_halt(stream, status, body, true).await
}

async fn send_h3_response_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: &str,
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    let resp = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 response: {}", e))?;
    stream.send_response(resp).await?;
    stream
        .send_data(Bytes::copy_from_slice(body.as_bytes()))
        .await?;
    stream.finish().await?;
    if halt_recv {
        crate::http3::stream_util::halt_request_body(stream);
    }
    Ok(())
}

/// Send an HTTP/3 rejection response with custom headers. Same recv-half
/// halt contract as `send_h3_response`.
/// Whether an `after_proxy` reject already carries a `Content-Type` header
/// (case-insensitive). When it does, `send_h3_reject_response` must not add its
/// own default, because `http::response::Builder::header` *appends* rather than
/// replaces — a second `content-type` would be a duplicate header, which is
/// undefined for clients. Pulled out as a pure function so the dedup decision is
/// unit-testable without a live QUIC stream.
fn reject_response_sets_content_type(headers: &HashMap<String, String>) -> bool {
    headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-type"))
}

fn finalize_h3_gateway_error_headers(
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: &[u8],
    headers: &mut HashMap<String, String>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) {
    if !matches!(flavor, HttpFlavor::Grpc) {
        headers
            .entry("content-type".to_string())
            .or_insert_with(|| "application/json".to_string());
    }
    if matches!(flavor, HttpFlavor::Grpc) {
        let (grpc_status, grpc_message) = h3_grpc_reject_signal(http_status, http_body, headers);
        crate::proxy::grpc_proxy::finalize_grpc_error_response_headers(
            headers,
            grpc_status,
            grpc_message.as_ref(),
            initial_response_header_policy_plugins,
        );
    } else if matches!(flavor, HttpFlavor::WebSocket) {
        crate::proxy::finalize_websocket_response_headers(
            initial_response_header_policy_plugins,
            headers,
        );
    } else {
        crate::proxy::finalize_plain_gateway_error_response_headers(
            initial_response_header_policy_plugins,
            headers,
        );
    }
}

async fn send_h3_reject_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    disposition: RejectBodyDisposition,
) -> Result<(), anyhow::Error> {
    if reject_response_sets_content_type(headers) {
        return send_h3_finalized_reject_response(stream, status, body, headers, disposition).await;
    }
    let mut headers = headers.clone();
    headers.insert("content-type".to_string(), "application/json".to_string());
    send_h3_finalized_reject_response(stream, status, body, &headers, disposition).await
}

/// Write a rejection whose header map has already completed response policy.
/// Unlike [`send_h3_reject_response`], an absent Content-Type is authoritative:
/// a policy removal must survive the final HTTP/3 wire boundary.
async fn send_h3_finalized_reject_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    disposition: RejectBodyDisposition,
) -> Result<(), anyhow::Error> {
    send_h3_finalized_reject_response_with_recv_halt(
        stream,
        status,
        body,
        headers,
        true,
        disposition,
    )
    .await
}

async fn send_h3_finalized_reject_response_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    halt_recv: bool,
    disposition: RejectBodyDisposition,
) -> Result<(), anyhow::Error> {
    let mut headers = headers.clone();
    // Body emptiness is NOT the discriminator: an ordinary empty HTTP reject
    // has an authoritative length of exactly zero and must overwrite any
    // plugin-authored `Content-Length`. Only the trusted `disposition` (HEAD /
    // no-body status, derived from the request method by the caller) preserves
    // the representation length that `prepare_synthetic_response_wire` set.
    let framing = ClientResponseFraming::for_final_reject(status.as_u16(), body.len(), disposition);
    sanitize_client_response_headers_for_wire(&mut headers, framing);
    send_h3_pre_sanitized_reject_response_with_recv_halt(stream, status, body, &headers, halt_recv)
        .await
}

/// Send an already protocol-sanitized reject. Callers that must strip
/// additional transport-owned fields (failed H3 WebSocket handshake) run that
/// strip *before* length repair and invoke this helper, so only the
/// gateway-derived `Content-Length` reaches the wire.
async fn send_h3_pre_sanitized_reject_response_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    let mut builder = Response::builder().status(status);
    builder = apply_response_headers(builder, headers);
    let resp = builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 reject response: {}", e))?;
    stream.send_response(resp).await?;
    // Callers that flow through `apply_reject_after_proxy_and_synthetic_body_hooks`
    // already applied shared HEAD/204/205/304 no-body preparation. Skip DATA
    // entirely when there is nothing to send so HEAD and no-body statuses never
    // emit an empty DATA frame before FIN.
    //
    // GHSA-5fp3-pp5p-c4gh: `body` is owned `Bytes`, moved straight into
    // `send_data`. A cached synthetic `RejectBinary` payload keeps the shared
    // allocation identity it carries through `RejectedResponseParts` and
    // `apply_reject_after_proxy_and_synthetic_body_hooks` all the way to QUIC —
    // no per-hit full-body copy at this boundary. Any slice-copying or
    // owned-Vec conversion reintroduced here (or on a caller in this chain)
    // restores the advisory; `h3_native_reject_bytes_share_tests` pins it.
    if !body.is_empty() {
        stream.send_data(body).await?;
    }
    stream.finish().await?;
    if halt_recv {
        crate::http3::stream_util::halt_request_body(stream);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_grpc_web_reject(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _plugins: &[Arc<dyn Plugin>],
    _ctx: &mut RequestContext,
    response_content_type: &str,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    send_h3_grpc_web_reject_with_recv_halt(
        stream,
        _plugins,
        _ctx,
        response_content_type,
        http_status,
        body,
        headers,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_grpc_web_reject_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_content_type: &str,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    // Accept negotiation failures must stay HTTP 406 JSON on H3, matching
    // H1/H2 `normalize_reject_response`. Do not rewrite them into a gRPC-Web
    // trailer-frame response with HTTP 200.
    if crate::plugins::grpc_web::reject_headers_mark_accept_not_acceptable(headers) {
        let normalized = crate::proxy::normalize_reject_response(http_status, body, headers, true);
        return send_h3_finalized_reject_response_with_recv_halt(
            stream,
            normalized.http_status,
            normalized.body,
            &normalized.headers,
            halt_recv,
            RejectBodyDisposition::for_request(&ctx.method, normalized.http_status.as_u16()),
        )
        .await;
    }

    let (grpc_status, grpc_message) = h3_grpc_reject_signal(http_status, &body, headers);
    let mut translated = crate::plugins::grpc_web::error_response_for_content_type(
        response_content_type,
        grpc_status,
        grpc_message.as_ref(),
    );
    crate::proxy::finalize_grpc_web_error_response_headers(&mut translated, &[], Some(headers));
    // The gRPC-Web translator produced freshly framed bytes; move them (no copy
    // of the original cached payload, which the translator never touched). That
    // regenerated frame is what actually reaches the wire, so its length is
    // authoritative regardless of the request method — hence `WireBody`.
    let translated_body = Bytes::from(translated.body);
    send_h3_finalized_reject_response_with_recv_halt(
        stream,
        StatusCode::OK,
        translated_body,
        &translated.headers,
        halt_recv,
        RejectBodyDisposition::WireBody,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_h3_reject_response_committed_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
) -> bool {
    run_h3_deadline_bounded_reject_committed_hooks_with_policy(
        plugins,
        ctx,
        flavor,
        grpc_web_response_content_type,
        http_status,
        body,
        headers,
        &[],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_h3_deadline_bounded_reject_committed_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> bool {
    run_h3_deadline_bounded_reject_committed_hooks_with_policy(
        plugins,
        ctx,
        flavor,
        grpc_web_response_content_type,
        http_status,
        body,
        headers,
        initial_response_header_policy_plugins,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_h3_deadline_bounded_reject_committed_hooks_with_policy(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> bool {
    if !plugins
        .iter()
        .any(|plugin| plugin.requires_response_committed_hook())
    {
        ctx.metadata
            .remove(crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);
        return false;
    }

    // Seed gateway-rejection provenance for every H3 reject path that can reach
    // a committed hook, not just the ones routed through
    // `apply_reject_after_proxy_and_synthetic_body_hooks`. Direct gateway-error
    // callers (notably the mesh dispatch-required 502 emitted straight after
    // `finalize_h3_gateway_error_headers`) otherwise hand gateway-authored
    // headers to a committed hook with no provenance at all; if that hook
    // exhausts the RPC deadline, `replace_buffered_h3_response_with_grpc_deadline`
    // below rebuilds from an empty gateway map and strips them. These headers are
    // the rejection the gateway itself synthesized, so declaring them
    // gateway-owned adds no backend surface. Seeding here (after the
    // no-committed-hook early return, and on the same `headers` the deadline
    // rebuild clones) covers the shared wrapper and the direct delegate callers
    // in one place; on paths that already seeded, this folds through
    // `adopt_gateway_rejection` rather than restarting provenance.
    ctx.begin_rejection_deadline_response_header_provenance(headers);

    let (committed_status, committed_headers, committed_body) = if let Some(content_type) =
        grpc_web_response_content_type
    {
        // Keep Accept negotiation 406s on the HTTP/JSON wire contract for
        // committed observers (chargeback, exporters), matching the sender.
        if crate::plugins::grpc_web::reject_headers_mark_accept_not_acceptable(headers) {
            let normalized =
                crate::proxy::normalize_reject_response(http_status, body.clone(), headers, true);
            (normalized.http_status, normalized.headers, normalized.body)
        } else {
            let (grpc_status, grpc_message) = h3_grpc_reject_signal(http_status, &body, headers);
            let mut translated = crate::plugins::grpc_web::error_response_for_content_type(
                content_type,
                grpc_status,
                grpc_message.as_ref(),
            );
            crate::proxy::finalize_grpc_web_error_response_headers(
                &mut translated,
                &[],
                Some(headers),
            );
            (
                StatusCode::OK,
                translated.headers,
                Bytes::from(translated.body),
            )
        }
    } else {
        // Committed observers must see what the sender writes, so the
        // framed unary terminate representation is authorized here on
        // exactly the same provenance the writer uses.
        let normalized = crate::proxy::normalize_reject_response_with_provenance(
            http_status,
            body.clone(),
            headers,
            matches!(flavor, HttpFlavor::Grpc),
            crate::proxy::FramedGrpcUnaryProvenance::from_context(ctx),
        );
        (normalized.http_status, normalized.headers, normalized.body)
    };

    for (index, plugin) in plugins.iter().enumerate() {
        if !plugin.requires_response_committed_hook() {
            continue;
        }
        let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
        let Some(pending_hook) = crate::proxy::run_response_committed_hook_until_deadline(
            Arc::clone(plugin),
            ctx,
            committed_status.as_u16(),
            &committed_headers,
            committed_body.clone(),
            terminal_gateway_deadline,
        )
        .await
        else {
            continue;
        };

        if terminal_gateway_deadline {
            ctx.metadata
                .remove(crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);
            crate::proxy::spawn_detached_response_committed_hooks(
                pending_hook,
                plugins[index + 1..].to_vec(),
                committed_status.as_u16(),
                Arc::new(committed_headers.clone()),
                committed_body.clone(),
            );
            return false;
        }

        let mut deadline_headers = headers.clone();
        let mut deadline_body = body.clone();
        let deadline_http_status = replace_buffered_h3_response_with_grpc_deadline(
            ctx,
            grpc_web_response_content_type,
            &mut deadline_headers,
            &mut deadline_body,
            initial_response_header_policy_plugins,
        );
        let (deadline_status, deadline_headers, deadline_body) =
            if grpc_web_response_content_type.is_some() {
                // The buffered replacement already emitted the complete gRPC-Web
                // wire contract, including the terminal trailer frame. Translating
                // it again would lose the typed status-4 provenance.
                (StatusCode::OK, deadline_headers, deadline_body)
            } else {
                let normalized = crate::proxy::normalize_reject_response(
                    deadline_http_status,
                    deadline_body.clone(),
                    &deadline_headers,
                    matches!(flavor, HttpFlavor::Grpc),
                );
                (normalized.http_status, normalized.headers, normalized.body)
            };
        ctx.metadata
            .remove(crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);
        crate::proxy::spawn_detached_response_committed_hooks(
            pending_hook,
            plugins[index + 1..].to_vec(),
            deadline_status.as_u16(),
            Arc::new(deadline_headers),
            deadline_body,
        );
        return true;
    }
    ctx.metadata
        .remove(crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY);
    false
}

/// Finalize and emit a client RPC deadline discovered while buffering an H3
/// upload. The body wait is over, but the rejection lifecycle is not:
/// immediately-ready decorators and committed observers run before rejection
/// logging and the stream write, while pending cleanup transfers to bounded
/// owned state. This is also the point where synchronous gRPC-Web CORS headers
/// are folded into the translated body-trailer response.
#[allow(clippy::too_many_arguments)]
async fn finalize_h3_upload_deadline_rejection(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: &ProxyState,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    start_time: std::time::Instant,
    rejection_phase: &str,
    plugin_execution_ns: u64,
) -> Result<(), anyhow::Error> {
    ctx.mark_gateway_deadline_response_selected();
    let Some(mut reject) =
        plugin_result_into_reject_parts(crate::plugins::grpc_deadline_exceeded_plugin_result())
    else {
        return Err(anyhow::anyhow!(
            "canonical gRPC deadline rejection could not be normalized"
        ));
    };
    apply_reject_after_proxy_and_synthetic_body_hooks(
        plugins,
        ctx,
        &mut reject.status_code,
        &mut reject.headers,
        &mut reject.body,
        true,
        false,
    )
    .await;
    let http_status = StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::BAD_REQUEST);
    run_h3_reject_response_committed_hooks(
        plugins,
        ctx,
        flavor,
        grpc_web_response_content_type,
        http_status,
        reject.body.clone(),
        &reject.headers,
    )
    .await;
    let log_status =
        h3_reject_log_status_and_metadata(ctx, flavor, http_status, &reject.body, &reject.headers);
    log_rejected_request(
        plugins,
        ctx,
        log_status,
        start_time,
        rejection_phase,
        plugin_execution_ns,
    )
    .await;
    record_request(state, log_status);
    // The upload drain already expired. Do not race this already-selected
    // rejection against the same absolute deadline: a Pending QUIC write would
    // lose immediately and abort before response HEADERS become observable.
    // Bound the terminal write with the shared post-deadline grace instead so a
    // flow-control-blocked client cannot retain the task indefinitely.
    send_h3_plugin_reject_flavor_aware(
        stream,
        plugins,
        ctx,
        flavor,
        grpc_web_response_content_type,
        http_status,
        reject.body.clone(),
        &reject.headers,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_plugin_reject_flavor_aware(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    send_h3_plugin_reject_flavor_aware_with_recv_halt(
        stream,
        plugins,
        ctx,
        flavor,
        grpc_web_response_content_type,
        http_status,
        body,
        headers,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_plugin_reject_flavor_aware_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    body: Bytes,
    headers: &HashMap<String, String>,
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    // Trusted body-omission signal for every writer below: derived from the
    // request method the frontend recorded plus the gateway-selected status,
    // never from the plugin-authored response header map.
    let disposition = RejectBodyDisposition::for_request(&ctx.method, http_status.as_u16());
    let terminal_gateway_deadline = ctx.gateway_deadline_response_selected();
    if terminal_gateway_deadline {
        let mut deadline_headers = headers.clone();
        let mut deadline_body = body;
        let deadline_status = replace_buffered_h3_response_with_grpc_deadline(
            ctx,
            grpc_web_response_content_type,
            &mut deadline_headers,
            &mut deadline_body,
            &[],
        );
        let deadline_disposition =
            RejectBodyDisposition::for_request(&ctx.method, deadline_status.as_u16());
        // Gateway already selected the deadline rejection; give HEADERS a real
        // opportunity under the shared post-deadline grace (not the expired
        // absolute deadline). Skip STOP_SENDING after mid-recv_data cancel —
        // h3-quinn would unwrap-abort under panic=abort. Grace expiry aborts
        // only the send half.
        let write = async {
            if grpc_web_response_content_type.is_some() {
                send_h3_finalized_reject_response_with_recv_halt(
                    stream,
                    StatusCode::OK,
                    deadline_body,
                    &deadline_headers,
                    false,
                    deadline_disposition,
                )
                .await
            } else {
                // The gateway deadline response replaced the plugin rejection
                // wholesale; no terminate provenance survives it.
                send_h3_reject_flavor_aware_with_recv_halt(
                    stream,
                    flavor,
                    deadline_status,
                    deadline_body,
                    &deadline_headers,
                    false,
                    deadline_disposition,
                    crate::proxy::FramedGrpcUnaryProvenance::NONE,
                )
                .await
            }
        };
        return match crate::http3::stream_util::await_post_deadline_terminal_response_write(write)
            .await
        {
            Ok(()) => Ok(()),
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => Err(error),
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                Ok(())
            }
        };
    }

    // Snapshot the `serverless_function` terminate provenance before the write
    // future borrows `ctx` mutably. A gRPC-Web client never receives a native
    // framed unary body, so that branch is deliberately not authorized.
    let authored_grpc_terminate_frame = ctx.serverless_grpc_terminate_frame.clone();
    let write = async {
        if let Some(content_type) = grpc_web_response_content_type {
            return send_h3_grpc_web_reject_with_recv_halt(
                stream,
                plugins,
                ctx,
                content_type,
                http_status,
                body,
                headers,
                halt_recv,
            )
            .await;
        }

        send_h3_reject_flavor_aware_with_recv_halt(
            stream,
            flavor,
            http_status,
            body,
            headers,
            halt_recv,
            disposition,
            crate::proxy::FramedGrpcUnaryProvenance::from_authored_frame(
                authored_grpc_terminate_frame.as_deref(),
            ),
        )
        .await
    };
    // Operator timeout / mid-recv cancel paths pass halt_recv=false; bound the
    // same way so flow-control cannot retain the task after the upload bound.
    if !halt_recv {
        return match crate::http3::stream_util::await_post_deadline_terminal_response_write(write)
            .await
        {
            Ok(()) => Ok(()),
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => Err(error),
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                Ok(())
            }
        };
    }
    write.await
}

/// Send a trailers-only gRPC error response over H3. The response is
/// HTTP 200 with `grpc-status` and `grpc-message` in the header block and
/// an empty body. Used when a gRPC request is rejected before dispatch so
/// the client sees a valid gRPC error instead of a raw HTTP/JSON payload.
/// Same recv-half halt contract as `send_h3_response`.
async fn send_h3_grpc_error(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> Result<(), anyhow::Error> {
    send_h3_grpc_error_with_recv_halt(
        stream,
        grpc_status,
        grpc_message,
        initial_response_header_policy_plugins,
        true,
    )
    .await
}

async fn send_h3_grpc_error_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    let mut headers = HashMap::new();
    crate::proxy::grpc_proxy::finalize_grpc_error_response_headers(
        &mut headers,
        grpc_status,
        grpc_message,
        initial_response_header_policy_plugins,
    );
    sanitize_client_response_headers_for_wire(&mut headers, ClientResponseFraming::TrailersOnly);
    let resp = apply_response_headers(Response::builder().status(StatusCode::OK), &headers)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC error response: {}", e))?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    if halt_recv {
        crate::http3::stream_util::halt_request_body(stream);
    }
    Ok(())
}

/// Send a terminal gRPC status as TRAILERS on an **already-open** H3 response
/// stream (response headers — and possibly some body DATA — were already sent),
/// then FIN the stream. Used when a deadline expires mid-stream so the client
/// receives a proper gRPC terminal status (`grpc-status: 4`) instead of an H3
/// transport reset. Returns `true` if both the trailers and FIN reached the
/// client. Unlike [`send_h3_grpc_error`] this does NOT send a response head —
/// the `:status`/`content-type` are already on the wire.
async fn send_h3_grpc_terminal_trailers(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    grpc_status: u32,
    grpc_message: &str,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> bool {
    let mut trailers = http::HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_str(&grpc_status.to_string()) {
        trailers.insert("grpc-status", value);
    }
    if let Ok(value) = http::HeaderValue::from_str(grpc_message) {
        trailers.insert("grpc-message", value);
    }
    crate::http3::stream_util::await_terminal_response_write_before_deadline(
        grpc_deadline_at,
        stream.send_trailers(trailers),
    )
    .await
    .is_ok()
        && crate::http3::stream_util::await_terminal_response_write_before_deadline(
            grpc_deadline_at,
            stream.finish(),
        )
        .await
        .is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H3GrpcResponseFinish {
    Complete,
    WriteFailed,
    DeadlineExceeded,
}

async fn send_h3_grpc_trailers_and_finish_before_deadline(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    trailers: http::HeaderMap,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> H3GrpcResponseFinish {
    match crate::http3::stream_util::await_response_write_before_deadline(
        grpc_deadline_at,
        stream.send_trailers(trailers),
    )
    .await
    {
        Ok(()) => {}
        Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
            return H3GrpcResponseFinish::WriteFailed;
        }
        Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
            return H3GrpcResponseFinish::DeadlineExceeded;
        }
    }
    match crate::http3::stream_util::await_response_write_before_deadline(
        grpc_deadline_at,
        stream.finish(),
    )
    .await
    {
        Ok(()) => H3GrpcResponseFinish::Complete,
        Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
            H3GrpcResponseFinish::WriteFailed
        }
        Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
            H3GrpcResponseFinish::DeadlineExceeded
        }
    }
}

/// FIN an already-open native-H3 gRPC response stream that produced NO terminal
/// TRAILERS frame. When the backend carried its terminal status only in the
/// initial HEADERS (a genuine Trailers-Only response — which the dispatch path
/// strips from the wire so the trailer is authoritative), re-emit it as a
/// synthesized TRAILERS frame so the client still receives `grpc-status` in the
/// canonical location; otherwise just FIN. The result preserves whether the
/// absolute RPC deadline or a transport write failure prevented completion.
/// `grpc_status` / `grpc_message` are the raw stripped header values.
async fn finish_h3_grpc_stream_trailers_only(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    grpc_status: Option<&str>,
    grpc_message: Option<&str>,
    grpc_status_details: Option<&str>,
    grpc_deadline_at: Option<tokio::time::Instant>,
) -> H3GrpcResponseFinish {
    match grpc_status {
        Some(status) => {
            let mut trailers = http::HeaderMap::new();
            if let Ok(value) = http::HeaderValue::from_str(status) {
                trailers.insert("grpc-status", value);
            }
            if let Some(message) = grpc_message
                && let Ok(value) = http::HeaderValue::from_str(message)
            {
                trailers.insert("grpc-message", value);
            }
            // Preserve rich error details (base64 binary trailer) on the
            // synthesized Trailers-Only frame.
            if let Some(details) = grpc_status_details
                && let Ok(value) = http::HeaderValue::from_str(details)
            {
                trailers.insert("grpc-status-details-bin", value);
            }
            send_h3_grpc_trailers_and_finish_before_deadline(stream, trailers, grpc_deadline_at)
                .await
        }
        None => match crate::http3::stream_util::await_response_write_before_deadline(
            grpc_deadline_at,
            stream.finish(),
        )
        .await
        {
            Ok(()) => H3GrpcResponseFinish::Complete,
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(_)) => {
                H3GrpcResponseFinish::WriteFailed
            }
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                H3GrpcResponseFinish::DeadlineExceeded
            }
        },
    }
}

/// Flavor-aware rejection for H3. When the request is gRPC, emits a
/// trailers-only gRPC error so the client receives a valid
/// `grpc-status` / `grpc-message` response. Otherwise emits the standard
/// HTTP/JSON error body. `grpc_message` is used only for the gRPC path;
/// `http_body` is used only for the Plain/WebSocket path.
async fn send_h3_error_flavor_aware(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    http_body: &str,
    grpc_status: u32,
    grpc_message: &str,
) -> Result<(), anyhow::Error> {
    send_h3_error_flavor_aware_with_policy(
        stream,
        flavor,
        grpc_web_response_content_type,
        http_status,
        http_body,
        grpc_status,
        grpc_message,
        &[],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_error_flavor_aware_with_policy(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    http_body: &str,
    grpc_status: u32,
    grpc_message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> Result<(), anyhow::Error> {
    send_h3_error_flavor_aware_with_policy_and_recv_halt(
        stream,
        flavor,
        grpc_web_response_content_type,
        http_status,
        http_body,
        grpc_status,
        grpc_message,
        initial_response_header_policy_plugins,
        true,
    )
    .await
}

/// `halt_recv = false` after a mid-`recv_data` timeout/deadline cancel so
/// h3-quinn's `stop_sending` cannot abort under `panic = "abort"`. When
/// `halt_recv` is false the write is also bounded by the shared post-deadline
/// grace so a flow-control-blocked client cannot retain the task indefinitely.
#[allow(clippy::too_many_arguments)]
async fn send_h3_error_flavor_aware_with_policy_and_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    grpc_web_response_content_type: Option<&str>,
    http_status: StatusCode,
    http_body: &str,
    grpc_status: u32,
    grpc_message: &str,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    halt_recv: bool,
) -> Result<(), anyhow::Error> {
    let write = async {
        if let Some(content_type) = grpc_web_response_content_type {
            let mut translated = crate::plugins::grpc_web::error_response_for_content_type(
                content_type,
                grpc_status,
                grpc_message,
            );
            crate::proxy::finalize_grpc_web_error_response_headers(
                &mut translated,
                initial_response_header_policy_plugins,
                None,
            );
            // Gateway-generated frame, moved (not copied) and written verbatim:
            // exact length always, so `WireBody` is the correct disposition.
            let translated_body = Bytes::from(translated.body);
            send_h3_finalized_reject_response_with_recv_halt(
                stream,
                StatusCode::OK,
                translated_body,
                &translated.headers,
                halt_recv,
                RejectBodyDisposition::WireBody,
            )
            .await
        } else if matches!(flavor, HttpFlavor::Grpc) {
            send_h3_grpc_error_with_recv_halt(
                stream,
                grpc_status,
                grpc_message,
                initial_response_header_policy_plugins,
                halt_recv,
            )
            .await
        } else if initial_response_header_policy_plugins.is_empty() {
            send_h3_response_with_recv_halt(stream, http_status, http_body, halt_recv).await
        } else {
            let mut headers = HashMap::new();
            finalize_h3_gateway_error_headers(
                flavor,
                http_status,
                http_body.as_bytes(),
                &mut headers,
                initial_response_header_policy_plugins,
            );
            // Gateway-generated body, written verbatim: exact length always.
            send_h3_finalized_reject_response_with_recv_halt(
                stream,
                http_status,
                Bytes::copy_from_slice(http_body.as_bytes()),
                &headers,
                halt_recv,
                RejectBodyDisposition::WireBody,
            )
            .await
        }
    };
    if !halt_recv {
        return match crate::http3::stream_util::await_post_deadline_terminal_response_write(write)
            .await
        {
            Ok(()) => Ok(()),
            Err(crate::http3::stream_util::H3ResponseWriteError::Write(error)) => Err(error),
            Err(crate::http3::stream_util::H3ResponseWriteError::DeadlineExceeded) => {
                crate::http3::stream_util::abort_response_stream(stream);
                Ok(())
            }
        };
    }
    write.await
}

/// Flavor-aware rejection for H3 with custom response headers (used on the
/// plugin/auth/CB reject paths). For gRPC requests, headers supplied by the
/// plugin are converted alongside the mandatory `grpc-status` /
/// `grpc-message` signalling. Plain/WebSocket uses the standard JSON body.
///
/// gRPC status + message are derived INSIDE this helper (not at every call
/// site) so Plain-flavor rejects — the overwhelming majority on an H3
/// listener — never pay for the JSON body parse or the message String
/// allocation. `reject_body_as_grpc_message` only runs when flavor is
/// actually Grpc.
async fn send_h3_reject_flavor_aware(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: Bytes,
    headers: &HashMap<String, String>,
    disposition: RejectBodyDisposition,
) -> Result<(), anyhow::Error> {
    send_h3_reject_flavor_aware_with_recv_halt(
        stream,
        flavor,
        http_status,
        http_body,
        headers,
        true,
        disposition,
        crate::proxy::FramedGrpcUnaryProvenance::NONE,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_reject_flavor_aware_with_recv_halt(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: Bytes,
    headers: &HashMap<String, String>,
    halt_recv: bool,
    disposition: RejectBodyDisposition,
    framed_unary_provenance: crate::proxy::FramedGrpcUnaryProvenance<'_>,
) -> Result<(), anyhow::Error> {
    send_h3_reject_flavor_aware_with_header_state(
        stream,
        flavor,
        http_status,
        http_body,
        headers,
        false,
        halt_recv,
        disposition,
        framed_unary_provenance,
    )
    .await
}

/// Flavor-aware writer for a header map that has already completed initial
/// response policy. This preserves intentional removals at the final H3 HEADERS
/// boundary while retaining mandatory gRPC signalling.
async fn send_h3_finalized_reject_flavor_aware(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: Bytes,
    headers: &HashMap<String, String>,
    disposition: RejectBodyDisposition,
) -> Result<(), anyhow::Error> {
    send_h3_reject_flavor_aware_with_header_state(
        stream,
        flavor,
        http_status,
        http_body,
        headers,
        true,
        true,
        disposition,
        crate::proxy::FramedGrpcUnaryProvenance::NONE,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_h3_reject_flavor_aware_with_header_state(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: Bytes,
    headers: &HashMap<String, String>,
    headers_finalized: bool,
    halt_recv: bool,
    disposition: RejectBodyDisposition,
    framed_unary_provenance: crate::proxy::FramedGrpcUnaryProvenance<'_>,
) -> Result<(), anyhow::Error> {
    if !matches!(flavor, HttpFlavor::Grpc) {
        if matches!(flavor, HttpFlavor::WebSocket) {
            let mut finalized_headers = headers.clone();
            if !headers_finalized && !reject_response_sets_content_type(&finalized_headers) {
                finalized_headers
                    .insert("content-type".to_string(), "application/json".to_string());
            }
            // Final protocol-aware boundary for a failed Extended CONNECT
            // handshake: remove transport-owned handshake fields (and any
            // policy-authored Content-Length) first, then apply the hop-by-hop /
            // Connection-listed strip and derive the authoritative body length.
            // A failed handshake is an ordinary HTTP response, so it keeps that
            // length — including an authoritative zero for an empty body; only
            // the negotiation metadata is forbidden. Extended CONNECT is never
            // HEAD, so the wire body is always the representation here.
            crate::http3::websocket::finalize_h3_websocket_reject_headers(&mut finalized_headers);
            let framing = ClientResponseFraming::ExactBody {
                status: http_status.as_u16(),
                len: http_body.len() as u64,
            };
            sanitize_client_response_headers_for_wire(&mut finalized_headers, framing);
            return send_h3_pre_sanitized_reject_response_with_recv_halt(
                stream,
                http_status,
                http_body,
                &finalized_headers,
                halt_recv,
            )
            .await;
        }
        if headers_finalized {
            return send_h3_finalized_reject_response_with_recv_halt(
                stream,
                http_status,
                http_body,
                headers,
                halt_recv,
                disposition,
            )
            .await;
        }
        if reject_response_sets_content_type(headers) {
            return send_h3_finalized_reject_response_with_recv_halt(
                stream,
                http_status,
                http_body,
                headers,
                halt_recv,
                disposition,
            )
            .await;
        }
        let mut headers = headers.clone();
        headers.insert("content-type".to_string(), "application/json".to_string());
        return send_h3_finalized_reject_response_with_recv_halt(
            stream,
            http_status,
            http_body,
            &headers,
            halt_recv,
            disposition,
        )
        .await;
    }

    // gRPC flavor only — strip plugin-synthesized connection-specific and
    // framing fields at the final H3 boundary before they can affect
    // signalling or reach the wire. Trailers-only framing removes
    // Content-Length outright: never invent `0`, never keep a plugin-authored
    // value on a response that carries no DATA frames.
    let mut sanitized_headers = headers.clone();
    sanitize_client_response_headers_for_wire(
        &mut sanitized_headers,
        ClientResponseFraming::TrailersOnly,
    );
    let headers = &sanitized_headers;

    // A rejection that carries byte-exact `serverless_function` terminate
    // provenance is emitted as HEADERS + one uncompressed unary DATA frame +
    // terminal trailers. Everything else — including a body that merely looks
    // like a gRPC frame — normalizes to trailers-only below. Only authorizing
    // provenance can produce framed parts, so skip the full normalizer on the
    // ordinary H3 gRPC reject flood. The `Bytes` clone is a refcount bump; the
    // authorized frame that reaches `send_data` is the caller's own buffer,
    // never a copy of it.
    if framed_unary_provenance.is_authorizing() {
        let normalized = crate::proxy::normalize_reject_response_with_provenance(
            http_status,
            http_body.clone(),
            headers,
            true,
            framed_unary_provenance,
        );
        if let Some((framed_body, framed_trailers)) =
            crate::proxy::framed_unary_reject_parts(&normalized)
        {
            let framed_body = framed_body.clone();
            let resp = h3_framed_unary_initial_response(&normalized.headers)
                .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC framed reject: {}", e))?;
            stream.send_response(resp).await?;
            stream.send_data(framed_body).await?;
            let trailers =
                crate::proxy::grpc_proxy::buffered_grpc_trailers_to_header_map(framed_trailers);
            stream.send_trailers(trailers).await?;
            stream.finish().await?;
            if halt_recv {
                crate::http3::stream_util::halt_request_body(stream);
            }
            return Ok(());
        }
    }

    // This writer uses H3's status-mapping table rather than the H1/H2
    // normalizer's table, but shares the complete provenance correction with H3
    // transaction logging so observability cannot disagree with the wire.
    // Everything below is inspection only — the trailers-only gRPC reject drops
    // the body, so these borrows never force the owned `Bytes` to be copied.
    //
    // 1. An UNCHANGED status-only terminate contract is legitimately
    //    trailers-only, and its terminal metadata is the contract's own — not
    //    whatever the decorated reject header map now says.
    // 2. Otherwise, reaching here while still HOLDING terminate authorization
    //    means the authored representation was invalidated, and the contract's
    //    `grpc-status: 0` must not be emitted as an empty Trailers-Only success.
    // 3. The status-only contract's `grpc-message` is OPTIONAL, so an omitted
    //    one is emitted as no field at all — never as a synthesized reason and
    //    never as an empty value.
    let status_only =
        crate::proxy::status_only_grpc_signal(framed_unary_provenance, http_status, &http_body);
    let (grpc_status, grpc_message) = h3_non_framed_grpc_reject_signal_with_provenance(
        http_status,
        &http_body,
        headers,
        framed_unary_provenance,
    );

    // Build a trailers-only gRPC error that preserves any custom headers
    // the plugin attached (e.g., rate-limit metadata), while forcing the
    // gRPC signalling headers to match.
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/grpc");
    for (k, v) in headers {
        // `eq_ignore_ascii_case` avoids the `to_ascii_lowercase` String
        // allocation that was previously executed per header.
        // `content-length` is dropped for the same reason the H1/H2 normalizer
        // drops it: this branch emits no DATA, so any surviving value describes
        // bytes that are not being sent. The framed serverless-terminate
        // representation runs the shared response-body lifecycle, whose
        // transforms set `content-length` on the reject header map, so a stale
        // nonzero value can reach here once that authorization is invalidated.
        if k.eq_ignore_ascii_case("content-type")
            || k.eq_ignore_ascii_case("grpc-status")
            || k.eq_ignore_ascii_case("grpc-message")
            || k.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        // Same eviction the H1/H2 normalizer performs: while a terminate
        // contract is authorizing, no terminal metadata survives out of the
        // mutable reject header map — neither what the contract authored nor a
        // `grpc-status-details-bin` a decorator injected. Intact status-only
        // restores the authoritative copies from provenance below; an
        // invalidated contract emits none of them, so the replacement status
        // can never ride out beside the original contract's details or
        // custom trailers.
        if framed_unary_provenance.evicts_terminal_metadata(k) {
            continue;
        }
        if k.eq_ignore_ascii_case("set-cookie") {
            // Newline-separated cookies must each become their own header line.
            for cookie_val in v.split('\n') {
                if let Ok(val) = hyper::header::HeaderValue::from_str(cookie_val) {
                    builder = builder.header(hyper::header::SET_COOKIE, val);
                }
            }
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, val);
        }
    }
    // Restore the intact status-only contract's remaining terminal metadata from
    // the validated provenance, so decorators can add initial response headers
    // but cannot alter, drop, or inject what the contract terminated with.
    if let Some(ref authored) = status_only {
        for (name, value) in &authored.additional {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(name.as_bytes()),
                hyper::header::HeaderValue::from_str(value),
            ) {
                builder = builder.header(name, val);
            }
        }
    }
    builder = builder.header("grpc-status", grpc_status.to_string());
    if let Some(message) = grpc_message.as_deref().filter(|value| !value.is_empty()) {
        builder = builder.header("grpc-message", message);
    }
    let resp = builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC reject response: {}", e))?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    if halt_recv {
        crate::http3::stream_util::halt_request_body(stream);
    }
    Ok(())
}

/// Build the initial HEADERS block for an authorized framed unary gRPC reject.
///
/// Route through the shared response-header emitter so HTTP/3 preserves the
/// proxy's newline-joined repeated-cookie representation exactly like H1/H2.
pub(crate) fn h3_framed_unary_initial_response(
    headers: &HashMap<String, String>,
) -> Result<Response<()>, http::Error> {
    apply_response_headers(Response::builder().status(StatusCode::OK), headers).body(())
}

pub(crate) fn h3_reject_log_status_and_metadata(
    ctx: &mut RequestContext,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: &[u8],
    headers: &HashMap<String, String>,
) -> u16 {
    if ctx.gateway_deadline_response_selected() {
        crate::proxy::insert_grpc_error_metadata(
            &mut ctx.metadata,
            crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
            GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
        );
        return StatusCode::OK.as_u16();
    }

    // Accept negotiation failures remain HTTP 406 on the wire; do not collapse
    // their logged/runtime status into the trailers-only HTTP 200 shape.
    if crate::plugins::grpc_web::reject_headers_mark_accept_not_acceptable(headers) {
        return http_status.as_u16();
    }

    if !matches!(flavor, HttpFlavor::Grpc) {
        return http_status.as_u16();
    }

    let provenance = crate::proxy::FramedGrpcUnaryProvenance::from_context(ctx);
    let (grpc_status, grpc_message) = if provenance.is_authorizing() {
        // Borrowed inspection only: share the exact intact-framed predicates
        // with the owned normalizer so log and wire cannot drift, without a
        // full-body copy of an authorized (up to multi-MiB) frame merely to
        // read grpc-status/message for transaction metadata.
        if let Some((status, message, _)) = crate::proxy::intact_framed_unary_terminate_signal(
            provenance,
            http_status,
            http_body,
            headers,
        ) {
            (status, message.map(std::borrow::Cow::Owned))
        } else {
            h3_non_framed_grpc_reject_signal_with_provenance(
                http_status,
                http_body,
                headers,
                provenance,
            )
        }
    } else {
        let (status, message) = h3_grpc_reject_signal(http_status, http_body, headers);
        (status, Some(message))
    };
    crate::proxy::insert_grpc_error_metadata(
        &mut ctx.metadata,
        grpc_status,
        grpc_message.as_deref().unwrap_or(""),
    );
    StatusCode::OK.as_u16()
}

/// Replace a buffered H3 response that will be written directly as HEADERS +
/// DATA. Unlike the rejection paths, this response does not pass through the
/// flavor-aware sender, so gRPC-Web must be encoded here before the caller
/// writes it to the QUIC stream.
pub(crate) fn replace_buffered_h3_response_with_grpc_deadline(
    ctx: &mut RequestContext,
    grpc_web_response_content_type: Option<&str>,
    headers: &mut HashMap<String, String>,
    body: &mut Bytes,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> StatusCode {
    crate::proxy::replace_buffered_grpc_response_with_deadline(
        ctx,
        grpc_web_response_content_type,
        headers,
        body,
        initial_response_header_policy_plugins,
    )
}

fn h3_grpc_reject_signal(
    http_status: StatusCode,
    http_body: &[u8],
    headers: &HashMap<String, String>,
) -> (u32, std::borrow::Cow<'static, str>) {
    let grpc_status = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("grpc-status"))
        .and_then(|(_, value)| value.parse::<u32>().ok())
        .unwrap_or_else(|| {
            crate::proxy::grpc_proxy::h3_http_reject_status_to_grpc_status(http_status)
        });
    let grpc_message: std::borrow::Cow<'static, str> = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("grpc-message"))
        .map(|(_, value)| std::borrow::Cow::<str>::Owned(sanitize_grpc_message(value)))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| reject_body_as_grpc_message(http_body, http_status));
    (grpc_status, grpc_message)
}

/// H3 trailers-only signal after applying the request-scoped serverless
/// terminate provenance contract.
///
/// Kept separate from [`h3_grpc_reject_signal`] because H3 intentionally uses
/// a distinct HTTP-status mapping table. Both the direct writer and transaction
/// logging call this helper after ruling out an intact framed response, so the
/// logged status/message exactly match the wire: an intact status-only contract
/// restores its optional authored message, while an invalidated authorization
/// fails closed and cannot be logged as success.
fn h3_non_framed_grpc_reject_signal_with_provenance(
    http_status: StatusCode,
    http_body: &[u8],
    headers: &HashMap<String, String>,
    framed_unary_provenance: crate::proxy::FramedGrpcUnaryProvenance<'_>,
) -> (u32, Option<std::borrow::Cow<'static, str>>) {
    let (derived_status, derived_message) = h3_grpc_reject_signal(http_status, http_body, headers);
    if let Some(authored) =
        crate::proxy::status_only_grpc_signal(framed_unary_provenance, http_status, http_body)
    {
        return (
            authored.grpc_status,
            authored.grpc_message.map(std::borrow::Cow::Owned),
        );
    }

    let mapped_status = crate::proxy::grpc_proxy::h3_http_reject_status_to_grpc_status(http_status);
    match crate::proxy::invalidated_grpc_terminate_fail_closed_signal(
        framed_unary_provenance,
        derived_status,
        mapped_status,
    ) {
        Some((status, message)) => (status, Some(std::borrow::Cow::Borrowed(message))),
        None => (derived_status, Some(derived_message)),
    }
}

/// Extract a grpc-message string from a plugin/auth reject body, which is
/// typically JSON (`{"error":"..."}`). Falls back to a status-derived
/// default when the body isn't parseable JSON.
///
/// Returns `Cow<str>` so the common case (canonical status reason, or body
/// already free of `\r`/`\n`) avoids the String allocation entirely. Only
/// bodies that contain control characters pay for the sanitized copy.
/// Mirrors `proxy/mod.rs::extract_grpc_reject_message` behavior at a high
/// level but is intentionally inlined — the H3 listener is latency-sensitive.
fn reject_body_as_grpc_message(body: &[u8], status: StatusCode) -> std::borrow::Cow<'static, str> {
    // Try common JSON shapes first.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        for key in ["grpc_message", "message", "error", "details"] {
            if let Some(msg) = value.get(key).and_then(|v| v.as_str()) {
                let sanitized = sanitize_grpc_message(msg);
                if !sanitized.is_empty() {
                    return std::borrow::Cow::Owned(sanitized);
                }
            }
        }
    }
    // Fall back to raw body-as-utf8.
    if let Ok(text) = std::str::from_utf8(body)
        && !text.trim().is_empty()
    {
        let sanitized = sanitize_grpc_message(text);
        if !sanitized.is_empty() {
            return std::borrow::Cow::Owned(sanitized);
        }
    }
    // Final fallback — static canonical reason, zero alloc.
    std::borrow::Cow::Borrowed(
        status
            .canonical_reason()
            .unwrap_or("Gateway rejected request"),
    )
}

/// Replace `\r` / `\n` with space (illegal inside a single HeaderValue) and
/// trim. Returns an empty String when the input is empty-after-trim; the
/// caller checks for that and falls back to the canonical reason.
///
/// Fast path: if the input has no control characters, returns a trimmed
/// clone in a single pass instead of re-collecting char-by-char.
fn sanitize_grpc_message(message: &str) -> String {
    let trimmed = message.trim();
    if !trimmed.contains(['\r', '\n']) {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .map(|c| if matches!(c, '\r' | '\n') { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

fn strip_query_params(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

/// Resolve the per-request `proxy_headers` map for the H3 dispatch path.
///
/// When `needs_ctx_headers` is `false` (the common case: no context-aware
/// final request-body hooks active), the headers are *moved* out of
/// `ctx.headers` via `std::mem::take`, matching the pre-existing zero-alloc
/// hot path. Downstream H3 code after this point does not read
/// `ctx.headers`, so leaving the map empty is safe.
///
/// When `needs_ctx_headers` is `true` (e.g. WAF or another plugin that
/// overrides `needs_final_request_body_context`), the map is cloned so the
/// body hook can still read `ctx.headers` for content-type/content-length
/// gates and rule conditions.
fn own_h3_proxy_headers(
    owned_proxy_headers: Option<HashMap<String, String>>,
    ctx: &mut RequestContext,
    needs_ctx_headers: bool,
) -> HashMap<String, String> {
    match owned_proxy_headers {
        Some(headers) => headers,
        None if needs_ctx_headers => ctx.headers.clone(),
        None => std::mem::take(&mut ctx.headers),
    }
}

fn record_request(state: &ProxyState, status: u16) {
    use std::sync::atomic::{AtomicU64, Ordering};
    state.request_count.fetch_add(1, Ordering::Relaxed);
    // Fast path: try read lock first — common status codes (200, 404, etc.)
    // are pre-populated at startup. Only fall back to write lock for rare codes.
    if let Some(counter) = state.status_counts.get(&status) {
        counter.fetch_add(1, Ordering::Relaxed);
    } else {
        state
            .status_counts
            .entry(status)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
    crate::runtime_metrics::global_ref().record_http_status(status);
}

/// Record the HTTP status actually emitted by a flavor-aware H3 rejection.
/// Native gRPC and gRPC-Web errors carry their status in trailers (or a
/// gRPC-Web trailer frame) and therefore use HTTP 200 on the wire.
#[inline]
fn record_h3_flavor_aware_reject(state: &ProxyState, flavor: HttpFlavor, http_status: u16) {
    record_request(
        state,
        if matches!(flavor, HttpFlavor::Grpc) {
            StatusCode::OK.as_u16()
        } else {
            http_status
        },
    );
}

#[cfg(test)]
mod h3_request_body_timeout_tests {
    use crate::proxy::grpc_proxy::GATEWAY_DEADLINE_EXCEEDED_MESSAGE;
    use bytes::Bytes;

    #[tokio::test]
    async fn completed_pre_policy_upload_returns_without_timeout() {
        let upload = std::future::ready::<Result<usize, &'static str>>(Ok(7));
        let result = super::collect_h3_request_body_with_timeout(upload, 100).await;
        assert_eq!(result, Ok(7));
    }

    #[tokio::test]
    async fn zero_disables_pre_policy_upload_deadline() {
        let upload = std::future::ready::<Result<usize, &'static str>>(Ok(11));
        let result = super::collect_h3_request_body_with_timeout(upload, 0).await;
        assert_eq!(result, Ok(11));
    }

    #[tokio::test]
    async fn pre_policy_upload_preserves_stream_read_errors() {
        let upload = std::future::ready::<Result<(), &'static str>>(Err("reset"));
        let result = super::collect_h3_request_body_with_timeout(upload, 100).await;
        assert_eq!(result, Err(super::H3RequestBodyReadError::Read("reset")));
    }

    #[tokio::test]
    async fn rpc_deadline_bounds_upload_when_operator_fallback_is_disabled() {
        let deadline = tokio::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("one second before now is representable");
        let upload = std::future::pending::<Result<(), ()>>();
        let result = super::collect_h3_request_body_with_deadline(upload, Some(deadline), 0).await;
        assert_eq!(result, Err(super::H3RequestBodyReadError::DeadlineExceeded));
    }

    #[tokio::test]
    async fn operator_upload_timeout_caps_a_long_rpc_deadline() {
        let deadline = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(60))
            .expect("one minute after now is representable");
        let upload = std::future::pending::<Result<(), ()>>();

        let result = super::collect_h3_request_body_with_deadline(upload, Some(deadline), 10).await;

        assert_eq!(result, Err(super::H3RequestBodyReadError::TimedOut));
    }

    #[test]
    fn committed_deadline_replaces_h3_response_with_canonical_grpc_error() {
        let mut ctx = crate::plugins::RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test.Service/Call".to_string(),
        );
        let mut headers = std::collections::HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("x-correlation-id".to_string(), "request-123".to_string()),
        ]);
        let mut body = Bytes::from_static(b"backend response");
        ctx.mark_gateway_deadline_response_selected();
        ctx.begin_rejection_deadline_response_header_provenance(&headers);

        let status = super::replace_buffered_h3_response_with_grpc_deadline(
            &mut ctx,
            None,
            &mut headers,
            &mut body,
            &[],
        );

        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(headers.len(), 4);
        assert_eq!(
            headers.get("x-correlation-id").map(String::as_str),
            Some("request-123"),
            "deadline replacement must preserve existing decorator headers"
        );
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
        assert_eq!(
            ctx.metadata.get("grpc_status").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            ctx.metadata.get("grpc_message").map(String::as_str),
            Some(GATEWAY_DEADLINE_EXCEEDED_MESSAGE)
        );
    }

    #[tokio::test]
    async fn stalled_buffered_probe_times_out_and_releases_slot_neutral() {
        use crate::circuit_breaker::CircuitBreaker;
        use crate::config::types::CircuitBreakerConfig;

        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 1,
            trip_on_connection_errors: true,
        });
        cb.record_failure(500, false, false);
        assert!(
            cb.can_execute().unwrap(),
            "the H3 request claims the probe slot"
        );
        assert_eq!(cb.half_open_in_flight(), 1);

        let stalled_upload = std::future::pending::<Result<(), ()>>();
        let result = super::collect_h3_request_body_with_timeout(stalled_upload, 10).await;
        assert_eq!(result, Err(super::H3RequestBodyReadError::TimedOut));

        cb.record_neutral(true);
        assert_eq!(cb.half_open_in_flight(), 0);
        assert_eq!(cb.state_name(), "half_open");
        assert!(
            cb.can_execute().unwrap(),
            "the released H3 probe slot admits the next recovery probe"
        );
    }
}

#[cfg(test)]
mod native_h3_retry_refinement_tests {
    #[test]
    fn retry_release_keeps_native_h3_and_uses_marked_header_refinement() {
        let src = include_str!("server.rs");
        let handler_start = src
            .find("async fn handle_h3_request(")
            .expect("handle_h3_request not found");
        let handler_tail = &src[handler_start..];
        let handler_end = handler_tail
            .find("\nfn build_h3_backend_url_for_flavor")
            .expect("end of handle_h3_request not found");
        let handler = &handler_tail[..handler_end];
        assert!(handler.contains("(!has_retry || retry_response_needs_header_refinement)"));
        assert!(handler.contains("backend_http_flavor == HttpFlavor::Plain"));
        assert!(handler.contains("&& !forces_reqwest_dispatch"));
        assert!(handler.contains("&& backend_supports_native_h3;"));
        assert!(handler.contains("let refined_body_data = if has_retry"));
        assert!(handler.contains("body_data.clone()"));

        let refine_start = src
            .find("async fn proxy_to_backend_h3_refined_response(")
            .expect("proxy_to_backend_h3_refined_response not found");
        let refine_tail = &src[refine_start..];
        let refine_end = refine_tail
            .find("\nasync fn collect_h3_open_response_body")
            .expect("end of proxy_to_backend_h3_refined_response not found");
        let refine = &refine_tail[..refine_end];
        assert!(refine.contains("retry_response_decision_context(&*ctx)"));
        assert!(refine.contains("if !response_is_retryable"));
        assert!(refine.contains("if retry_config.is_some()"));
        assert!(refine.contains("H3RefinedResponse::Buffered(H3BufferedDispatchResult"));
    }
}

#[cfg(test)]
mod h3_proxy_header_tests {
    use super::own_h3_proxy_headers;
    use crate::plugins::RequestContext;
    use std::collections::HashMap;

    #[test]
    fn body_hook_context_required_clones_ctx_headers() {
        // When a plugin opts into `needs_final_request_body_context`, the
        // helper must clone so the body hook can still read `ctx.headers`
        // for content-type / content-length gates.
        let mut ctx = RequestContext::new(
            "203.0.113.10".to_string(),
            "POST".to_string(),
            "/submit".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());

        let proxy_headers = own_h3_proxy_headers(None, &mut ctx, true);

        assert_eq!(
            proxy_headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            ctx.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn body_hook_context_not_required_takes_ctx_headers() {
        // When no plugin needs the body-hook context, the helper falls back
        // to the original `std::mem::take` zero-alloc path. The H3 dispatch
        // path beyond this point does not read `ctx.headers`, so leaving
        // the map empty is safe.
        let mut ctx = RequestContext::new(
            "203.0.113.10".to_string(),
            "POST".to_string(),
            "/submit".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());

        let proxy_headers = own_h3_proxy_headers(None, &mut ctx, false);

        assert_eq!(
            proxy_headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert!(
            ctx.headers.is_empty(),
            "ctx.headers should be moved into proxy_headers when no body hook needs it"
        );
    }

    #[test]
    fn explicit_owned_proxy_headers_win_without_mutating_context() {
        // `owned_proxy_headers` short-circuits both branches: identity-header
        // injection / mesh egress strip have already built the outbound map,
        // and `ctx.headers` is untouched whether or not body hooks need it.
        let mut ctx = RequestContext::new(
            "203.0.113.10".to_string(),
            "POST".to_string(),
            "/submit".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        let owned = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

        let proxy_headers = own_h3_proxy_headers(Some(owned), &mut ctx, true);

        assert_eq!(
            proxy_headers.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        assert_eq!(
            ctx.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }
}

#[cfg(test)]
mod h3_streaming_after_proxy_tests {
    use super::run_h3_streaming_after_proxy_hooks;
    use crate::plugins::{Plugin, PluginResult, RequestContext};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct RejectingAfterProxy;

    #[async_trait]
    impl Plugin for RejectingAfterProxy {
        fn name(&self) -> &str {
            "rejecting_after_proxy"
        }

        async fn after_proxy(
            &self,
            _ctx: &mut RequestContext,
            _status_code: u16,
            _response_headers: &mut HashMap<String, String>,
        ) -> PluginResult {
            PluginResult::Reject {
                status_code: 451,
                body: "blocked by response policy".to_string(),
                headers: HashMap::from([("x-policy".to_string(), "blocked".to_string())]),
            }
        }
    }

    #[tokio::test]
    async fn streaming_after_proxy_returns_reject_before_downstream_commit() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RejectingAfterProxy)];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/stream".to_string(),
        );
        let mut response_headers =
            HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
        let mut plugin_execution_ns = 0;

        let reject = run_h3_streaming_after_proxy_hooks(
            &plugins,
            &mut ctx,
            200,
            &mut response_headers,
            &mut plugin_execution_ns,
        )
        .await
        .expect("after_proxy rejection should be surfaced");

        assert_eq!(reject.status_code, 451);
        assert_eq!(&*reject.body, b"blocked by response policy");
        assert_eq!(
            reject.headers.get("x-policy").map(String::as_str),
            Some("blocked")
        );
        // The wrapper's sole job beyond delegating is to accumulate elapsed
        // plugin time; pin that it actually does so.
        assert!(
            plugin_execution_ns > 0,
            "after_proxy hook execution time must be accumulated"
        );
    }

    struct ContinuingAfterProxy;

    #[async_trait]
    impl Plugin for ContinuingAfterProxy {
        fn name(&self) -> &str {
            "continuing_after_proxy"
        }

        async fn after_proxy(
            &self,
            _ctx: &mut RequestContext,
            _status_code: u16,
            _response_headers: &mut HashMap<String, String>,
        ) -> PluginResult {
            PluginResult::Continue
        }
    }

    #[tokio::test]
    async fn streaming_after_proxy_continue_returns_none_and_times_hooks() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(ContinuingAfterProxy)];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/stream".to_string(),
        );
        let mut response_headers = HashMap::new();
        let mut plugin_execution_ns = 0;

        let result = run_h3_streaming_after_proxy_hooks(
            &plugins,
            &mut ctx,
            200,
            &mut response_headers,
            &mut plugin_execution_ns,
        )
        .await;

        assert!(
            result.is_none(),
            "a Continue from every after_proxy hook must not surface a reject"
        );
        assert!(
            plugin_execution_ns > 0,
            "hook execution time must be accumulated even when no plugin rejects"
        );
    }

    #[test]
    fn reject_default_content_type_only_added_when_absent() {
        // `send_h3_reject_response` defaults Content-Type only when the reject
        // didn't supply one — otherwise `Builder::header` (which appends) would
        // emit a duplicate. Pin the dedup decision as a pure unit.
        let empty: HashMap<String, String> = HashMap::new();
        assert!(
            !super::reject_response_sets_content_type(&empty),
            "no reject-supplied content-type → caller must add the default"
        );

        for key in ["content-type", "Content-Type", "CONTENT-TYPE"] {
            let headers = HashMap::from([(key.to_string(), "application/grpc".to_string())]);
            assert!(
                super::reject_response_sets_content_type(&headers),
                "{key:?}: a reject-supplied content-type must suppress the default \
                 so no duplicate Content-Type header is emitted"
            );
        }
    }
}

#[cfg(test)]
mod h3_streaming_outcome_tests {
    //! Regression tests for the streaming-path `record_backend_outcome`
    //! predicate that drives CB / passive-health / latency reporting.
    //!
    //! See the comment block at the call site for the full prose; this
    //! test module enumerates every `(error_class, body_error_class)`
    //! shape `H3StreamResult` can produce and pins down the expected
    //! `connection_error` for each.
    //!
    //! The predicate has been through THREE wrong iterations (each
    //! producing its own review finding); the current shape uses
    //! `body_error_class` as the discriminator between dispatch failures
    //! and body-phase aborts so that "backend 5xx + body truncates"
    //! is reported as a transport failure for CB regardless of the
    //! HTTP status the backend chose.
    use crate::retry::ErrorClass;

    #[test]
    fn request_body_upload_client_disconnect_maps_to_neutral_outcome() {
        let (connection_error, error_class) =
            super::h3_streaming_body_failure_outcome(true, false, ErrorClass::ConnectionClosed);

        assert!(
            !connection_error,
            "H3 frontend upload aborts are client-caused and must not count \
             as backend connection failures"
        );
        assert_eq!(error_class, Some(ErrorClass::ClientDisconnect));
    }

    #[test]
    fn request_body_upload_backend_failure_keeps_original_class() {
        let (connection_error, error_class) =
            super::h3_streaming_body_failure_outcome(false, false, ErrorClass::ProtocolError);

        assert!(
            connection_error,
            "non-client H3 streaming-body failures still represent backend \
             connection failures"
        );
        assert_eq!(error_class, Some(ErrorClass::ProtocolError));
    }

    #[test]
    fn request_body_upload_backend_read_timeout_is_not_a_connection_error() {
        // `backend_read_timeout_ms` expiry is post-wire: the request reached
        // the backend, which then stalled. It must be recorded as a 504
        // status fault (connection_error=false), matching the direct-H2 /
        // HBONE read-timeout arms — not as a transport connection failure.
        let (connection_error, error_class) =
            super::h3_streaming_body_failure_outcome(false, true, ErrorClass::ReadWriteTimeout);

        assert!(
            !connection_error,
            "post-wire H3 backend read timeouts must not count as backend \
             connection failures"
        );
        assert_eq!(error_class, Some(ErrorClass::ReadWriteTimeout));
    }

    #[test]
    fn request_body_upload_client_disconnect_detection_is_case_insensitive() {
        for err_msg in [
            "client disconnected while sending request body: stream closed",
            "Client disconnected while sending request body: stream closed",
        ] {
            assert!(
                super::is_h3_client_request_body_disconnect(err_msg),
                "{err_msg:?} must be recognized as a client upload abort"
            );
        }
    }

    /// Mirrors the predicate in `handle_h3_request`'s streaming branch.
    /// Kept as a free function so the test can assert against it
    /// without setting up the full handler harness.
    fn streaming_path_connection_error(
        error_class: Option<ErrorClass>,
        body_error_class: Option<ErrorClass>,
        request_on_wire: bool,
    ) -> bool {
        match (error_class, body_error_class) {
            (None, None) => false,
            (None, Some(ErrorClass::ClientDisconnect)) => false,
            (None, Some(_)) => true,
            (Some(_), Some(_)) => true,
            (Some(_), None) => !request_on_wire,
        }
    }

    #[test]
    fn dispatch_graceful_close_is_not_connection_error() {
        // The PR's primary goal. Dispatch failure shape:
        //   error_class = Some(GracefulRemoteClose)
        //   body_error_class = None  (no body — request never got that far)
        //   request_on_wire = true   (post-`send_request` close)
        //
        // Pre-fix `is_some()` said true; helper-derived predicate said
        // true via ConnectionClosed string-matching; only the typed
        // signal correctly says false.
        assert!(
            !streaming_path_connection_error(
                Some(ErrorClass::GracefulRemoteClose),
                /* body_error_class = */ None,
                /* request_on_wire = */ true,
            ),
            "graceful close at recv_response (post-`send_request`) must NOT \
             trip CB / passive-health"
        );
    }

    #[test]
    fn dispatch_pre_wire_failure_is_connection_error() {
        // DNS / TLS / connect failures: the request never reached the
        // backend. error_class set, body_error_class None (no body
        // streamed), request_on_wire false.
        for class in [
            ErrorClass::DnsLookupError,
            ErrorClass::TlsError,
            ErrorClass::ConnectionRefused,
            ErrorClass::ConnectionTimeout,
            ErrorClass::PortExhaustion,
            ErrorClass::ConnectionPoolError,
        ] {
            assert!(
                streaming_path_connection_error(
                    Some(class),
                    /* body_error_class = */ None,
                    /* request_on_wire = */ false,
                ),
                "{class:?}: pre-wire dispatch failure must record connection_error=true"
            );
        }
    }

    #[test]
    fn dispatch_post_wire_non_graceful_uses_typed_signal() {
        // A connect-phase QUIC reset can string-classify as
        // ConnectionReset (post-wire by `request_reached_wire`) when no
        // request actually reached the backend. The typed signal —
        // `H3PoolError::request_on_wire()` plumbed through to
        // `H3StreamResult::request_on_wire` — disambiguates correctly.
        // Note `body_error_class` is None on dispatch-failure paths, so
        // the typed signal arm fires.
        assert!(
            streaming_path_connection_error(
                Some(ErrorClass::ConnectionReset),
                /* body_error_class = */ None,
                /* request_on_wire = */ false,
            ),
            "connect-phase ConnectionReset (typed signal=false) must record \
             connection_error=true regardless of class string heuristics"
        );
        assert!(
            !streaming_path_connection_error(
                Some(ErrorClass::ConnectionReset),
                /* body_error_class = */ None,
                /* request_on_wire = */ true,
            ),
            "post-`send_request` ConnectionReset (typed signal=true) must \
             record connection_error=false — matches buffered-path semantics"
        );
    }

    #[test]
    fn mid_body_abort_is_connection_error_regardless_of_status() {
        // Headers were flushed (status from backend, anywhere from 2xx
        // to 5xx); body then aborted, setting both terminal_error_class
        // AND body_error_class. The body_error_class is the
        // discriminator — covers the case where the BACKEND emitted a
        // 5xx status and then truncated the body, which the previous
        // status-shape predicate mis-classified as a dispatch failure
        // and let through as connection_error=false.
        //
        // Both arms `(Some(_), Some(_))` and `(None, Some(non-ClientDisconnect))`
        // collapse to true; this test exercises the former.
        for class in [
            ErrorClass::ProtocolError,
            ErrorClass::ReadWriteTimeout,
            ErrorClass::ConnectionReset,
            ErrorClass::ConnectionClosed,
            ErrorClass::ResponseBodyTooLarge,
        ] {
            for status in [200u16, 503, 504] {
                assert!(
                    streaming_path_connection_error(
                        Some(class),
                        Some(class),
                        /* request_on_wire = */ true,
                    ),
                    "{class:?} mid-body abort at status={status} must report \
                     connection_error=true (body_error_class set is the \
                     discriminator regardless of HTTP status)"
                );
            }
        }
    }

    #[test]
    fn backend_5xx_with_body_abort_is_connection_error() {
        // Reviewer's specific finding: backend returns 503, headers flush
        // to the client, then the stream truncates mid-body.
        // `H3StreamResult { status: 503, error_class: Some(ProtocolError),
        // body_error_class: Some(ProtocolError), request_on_wire: true }`.
        //
        // Pre-fix (status>=500 shape): mis-treated as dispatch failure;
        // `!request_on_wire = false` → CB saw only the 503 status, no
        // transport-failure accounting.
        // Post-fix: `body_error_class = Some(_)` is the discriminator;
        // arm `(Some(_), Some(_)) => true` fires regardless of status.
        assert!(
            streaming_path_connection_error(
                Some(ErrorClass::ProtocolError),
                Some(ErrorClass::ProtocolError),
                /* request_on_wire = */ true,
            ),
            "backend-emitted 5xx + body abort: body_error_class is the signal; \
             must report connection_error=true so passive-health / outlier \
             detection account for the transport fault, not just rely on \
             `failure_status_codes` capturing the 5xx"
        );
    }

    #[test]
    fn body_only_issue_without_terminal_class_is_connection_error() {
        // Mid-stream `ResponseBodyTooLarge` discovered by the byte
        // counter sets `body_error_class` but NOT `terminal_error_class`
        // — covers the `(None, Some(ResponseBodyTooLarge))` arm.
        assert!(
            streaming_path_connection_error(
                /* error_class = */ None,
                Some(ErrorClass::ResponseBodyTooLarge),
                /* request_on_wire = */ true,
            ),
            "mid-stream ResponseBodyTooLarge (body-only) must report \
             connection_error=true — backend misbehavior"
        );
    }

    #[test]
    fn client_disconnect_during_streaming_is_not_connection_error() {
        // `body_error_class = Some(ClientDisconnect)` on multiple paths
        // (send_response failed, mid-stream send_data failed, finish
        // failed). The client gave up; not a backend fault.
        assert!(
            !streaming_path_connection_error(
                /* error_class = */ None,
                Some(ErrorClass::ClientDisconnect),
                /* request_on_wire = */ true,
            ),
            "client disconnect must NOT record as connection_error — the \
             client gave up, not a backend fault"
        );
    }

    #[test]
    fn clean_streaming_response_is_not_connection_error() {
        assert!(
            !streaming_path_connection_error(None, None, /* request_on_wire = */ true,),
            "successful streaming response (both classes None) must record \
             connection_error=false so latency is sampled and CB sees a success"
        );
        // Even a 5xx STATUS from the backend with both classes None is a
        // legitimate response that the backend chose to send. Not a
        // transport-level failure; CB sees the 5xx via its
        // `failure_status_codes` config, not via `connection_error`.
        // Note this case wouldn't actually arise in practice — a 5xx
        // status comes back via the success path in
        // `proxy_to_backend_h3_streaming` only when no body issue
        // surfaced — but the predicate handles it cleanly.
        assert!(
            !streaming_path_connection_error(None, None, /* request_on_wire = */ true,),
            "backend-emitted 5xx without any error class is a status failure, \
             not a connection failure"
        );
    }

    #[test]
    fn backend_unavailable_reject_write_failure_is_recorded_not_propagated() {
        // Regression for the LB active-connection leak: the H3 backend-dispatch
        // failure paths (`proxy_to_backend_h3_refined_response` and
        // `proxy_to_backend_h3_streaming`) must report a failed 502 reject write
        // as `client_disconnected` and STILL return a recordable result, so the
        // caller runs `record_backend_outcome` and releases the active-connection
        // count. Propagating the send error with `?` (the old behavior) skipped
        // that accounting and leaked one count per backend-failure + client
        // disconnect. The inline native-H3 reject paths share the same contract
        // by swallowing the send error instead of returning a result.
        let disconnected = super::h3_backend_unavailable_stream_result(
            502,
            ErrorClass::ProtocolError,
            /* request_on_wire = */ true,
            /* reject_sent = */ false,
            std::time::Duration::from_millis(7),
        );
        assert!(
            disconnected.client_disconnected,
            "a failed 502 reject write must be reported as a client disconnect"
        );
        assert_eq!(disconnected.status, 502);
        assert_eq!(
            disconnected.backend_status, 502,
            "no backend response was received, so backend_status is the synthesized 502"
        );
        assert_eq!(disconnected.error_class, Some(ErrorClass::ProtocolError));
        assert!(disconnected.request_on_wire);
        assert_eq!(
            disconnected.backend_admission_elapsed,
            std::time::Duration::from_millis(7)
        );

        let delivered = super::h3_backend_unavailable_stream_result(
            502,
            ErrorClass::ProtocolError,
            /* request_on_wire = */ false,
            /* reject_sent = */ true,
            std::time::Duration::from_millis(11),
        );

        let timed_out = super::h3_backend_unavailable_stream_result(
            504,
            ErrorClass::ReadWriteTimeout,
            /* request_on_wire = */ true,
            /* reject_sent = */ true,
            std::time::Duration::from_millis(13),
        );
        assert_eq!(
            timed_out.status, 504,
            "backend read timeouts surface as 504 Backend timeout"
        );
        assert_eq!(timed_out.backend_status, 504);
        assert_eq!(timed_out.error_class, Some(ErrorClass::ReadWriteTimeout));
        assert!(
            !delivered.client_disconnected,
            "a delivered 502 reject write is not a client disconnect"
        );
        assert!(!delivered.request_on_wire);
        assert_eq!(
            delivered.backend_admission_elapsed,
            std::time::Duration::from_millis(11)
        );
    }

    #[test]
    fn pre_header_failure_reports_unknown_backend_ttfb() {
        // Plain native-H3 completion must not label admission elapsed as TTFB
        // when response headers never arrived. Adaptive concurrency still sees
        // the real admission duration via record_h3_backend_admission_outcome.
        let failed = super::h3_backend_unavailable_stream_result(
            502,
            ErrorClass::ConnectionRefused,
            /* request_on_wire = */ false,
            /* reject_sent = */ true,
            std::time::Duration::from_millis(42),
        );
        assert_eq!(
            failed.backend_admission_elapsed,
            std::time::Duration::from_millis(42),
            "admission elapsed must remain available for adaptive concurrency"
        );
        assert_eq!(
            super::h3_stream_backend_ttfb_ms(&failed),
            crate::plugins::LATENCY_UNKNOWN_MS,
            "pre-header failure must report TTFB as unavailable"
        );

        let headers_ok = super::H3StreamResult {
            status: 200,
            backend_status: 200,
            error_class: None,
            body_completed: true,
            bytes_streamed: 64,
            client_disconnected: false,
            body_error_class: None,
            request_on_wire: true,
            backend_admission_elapsed: std::time::Duration::from_millis(7),
        };
        assert!(
            (super::h3_stream_backend_ttfb_ms(&headers_ok) - 7.0).abs() < f64::EPSILON,
            "successful first-header timing must remain intact"
        );

        // Content-length ResponseBodyTooLarge rejects after headers arrive —
        // TTFB is a real first-header observation (matches native-H3 gRPC).
        let oversized = super::H3StreamResult {
            status: 502,
            backend_status: 200,
            error_class: Some(ErrorClass::ResponseBodyTooLarge),
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: false,
            body_error_class: None,
            request_on_wire: true,
            backend_admission_elapsed: std::time::Duration::from_millis(11),
        };
        assert!(
            (super::h3_stream_backend_ttfb_ms(&oversized) - 11.0).abs() < f64::EPSILON,
            "post-header size reject must keep real TTFB"
        );

        let body_abort = super::H3StreamResult {
            status: 200,
            backend_status: 200,
            error_class: None,
            body_completed: false,
            bytes_streamed: 16,
            client_disconnected: true,
            body_error_class: Some(ErrorClass::ClientDisconnect),
            request_on_wire: true,
            backend_admission_elapsed: std::time::Duration::from_millis(5),
        };
        assert!(
            (super::h3_stream_backend_ttfb_ms(&body_abort) - 5.0).abs() < f64::EPSILON,
            "body-phase abort after headers must keep real TTFB"
        );
    }
}

#[cfg(test)]
mod h3_plugin_protocol_tests {
    use super::{
        h3_grpc_reject_signal, h3_plugin_protocol_for_flavor, h3_reject_log_status_and_metadata,
    };
    use crate::config::types::HttpFlavor;
    use crate::plugins::ProxyProtocol;
    use crate::plugins::RequestContext;
    use http::StatusCode;
    use std::collections::HashMap;

    #[test]
    fn maps_websocket_flavor_to_websocket_plugin_protocol() {
        assert_eq!(
            h3_plugin_protocol_for_flavor(HttpFlavor::WebSocket),
            ProxyProtocol::WebSocket
        );
    }

    #[test]
    fn maps_grpc_flavor_to_grpc_plugin_protocol() {
        assert_eq!(
            h3_plugin_protocol_for_flavor(HttpFlavor::Grpc),
            ProxyProtocol::Grpc
        );
    }

    #[test]
    fn maps_plain_flavor_to_http_plugin_protocol() {
        assert_eq!(
            h3_plugin_protocol_for_flavor(HttpFlavor::Plain),
            ProxyProtocol::Http
        );
    }

    #[test]
    fn grpc_reject_logging_uses_wire_status_and_grpc_metadata() {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/pkg.Service/Call".to_string(),
        );

        let log_status = h3_reject_log_status_and_metadata(
            &mut ctx,
            HttpFlavor::Grpc,
            StatusCode::UNAUTHORIZED,
            br#"{"error":"missing token"}"#,
            &HashMap::new(),
        );

        assert_eq!(log_status, StatusCode::OK.as_u16());
        assert_eq!(
            ctx.metadata.get("grpc_status").map(String::as_str),
            Some("16")
        );
        assert_eq!(
            ctx.metadata.get("grpc_message").map(String::as_str),
            Some("missing token")
        );
    }

    #[test]
    fn grpc_reject_logging_prefers_explicit_grpc_headers() {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/pkg.Service/Call".to_string(),
        );
        let headers = HashMap::from([
            ("grpc-status".to_string(), "9".to_string()),
            (
                "grpc-message".to_string(),
                "failed precondition".to_string(),
            ),
        ]);

        let log_status = h3_reject_log_status_and_metadata(
            &mut ctx,
            HttpFlavor::Grpc,
            StatusCode::BAD_REQUEST,
            b"ignored",
            &headers,
        );

        assert_eq!(log_status, StatusCode::OK.as_u16());
        assert_eq!(
            ctx.metadata.get("grpc_status").map(String::as_str),
            Some("9")
        );
        assert_eq!(
            ctx.metadata.get("grpc_message").map(String::as_str),
            Some("failed precondition")
        );
    }

    #[test]
    fn grpc_reject_signal_prefers_explicit_headers_for_wire_and_logs() {
        let headers = HashMap::from([
            ("grpc-status".to_string(), "4".to_string()),
            ("grpc-message".to_string(), "deadline exceeded".to_string()),
        ]);

        let (grpc_status, grpc_message) =
            h3_grpc_reject_signal(StatusCode::OK, b"ignored", &headers);

        assert_eq!(grpc_status, 4);
        assert_eq!(grpc_message.as_ref(), "deadline exceeded");
    }

    #[test]
    fn plain_reject_logging_keeps_http_status_without_grpc_metadata() {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );

        let log_status = h3_reject_log_status_and_metadata(
            &mut ctx,
            HttpFlavor::Plain,
            StatusCode::FORBIDDEN,
            br#"{"error":"blocked"}"#,
            &HashMap::new(),
        );

        assert_eq!(log_status, StatusCode::FORBIDDEN.as_u16());
        assert!(!ctx.metadata.contains_key("grpc_status"));
        assert!(!ctx.metadata.contains_key("grpc_message"));
    }
}

#[cfg(test)]
mod h3_backend_url_tests {
    use super::build_h3_backend_url_for_flavor;
    use crate::config::types::{BackendScheme, DispatchKind, HttpFlavor, Proxy};

    fn proxy_with_scheme(scheme: BackendScheme) -> Proxy {
        let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
            "backend_host": "backend.example",
            "backend_port": 8443,
        }))
        .expect("minimal proxy should deserialize");
        proxy.backend_scheme = Some(scheme);
        proxy.dispatch_kind = match scheme {
            BackendScheme::Http => DispatchKind::HttpPool,
            BackendScheme::Https => DispatchKind::HttpsPool,
            _ => proxy.dispatch_kind,
        };
        proxy
    }

    #[test]
    fn websocket_backend_url_uses_wss_scheme_for_https_backends() {
        let proxy = proxy_with_scheme(BackendScheme::Https);
        let url = build_h3_backend_url_for_flavor(
            &proxy,
            HttpFlavor::WebSocket,
            "/ws",
            "token=1",
            0,
            None,
        );
        assert_eq!(url, "wss://backend.example:8443/ws?token=1");
    }

    #[test]
    fn websocket_backend_url_uses_ws_scheme_for_http_backends() {
        let proxy = proxy_with_scheme(BackendScheme::Http);
        let url = build_h3_backend_url_for_flavor(
            &proxy,
            HttpFlavor::WebSocket,
            "/ws",
            "token=1",
            0,
            None,
        );
        assert_eq!(url, "ws://backend.example:8443/ws?token=1");
    }

    #[test]
    fn plain_backend_url_keeps_http_family_scheme() {
        let proxy = proxy_with_scheme(BackendScheme::Https);
        let url = build_h3_backend_url_for_flavor(&proxy, HttpFlavor::Plain, "/api", "", 0, None);
        assert_eq!(url, "https://backend.example:8443/api");
    }
}

#[cfg(test)]
mod handshake_timeout_helper_tests {
    //! Regression tests for `await_with_optional_timeout`. The helper backs
    //! the QUIC frontend handshake bound that aligns HTTP/3 admission control
    //! with the TCP/TLS and DTLS frontends — see the comment block above the
    //! `let connection = if early_data_enabled { ... }` arm in
    //! `handle_h3_connection`.

    use std::time::Duration;

    use super::await_with_optional_timeout;

    #[tokio::test]
    async fn zero_duration_skips_timeout_and_resolves_when_future_completes() {
        // `Duration::ZERO` is the documented "0 disables" knob shared with
        // TCP/TLS and DTLS frontends. The future must run to completion
        // without being wrapped in `tokio::time::timeout`.
        let result = await_with_optional_timeout(async { 42_u32 }, Duration::ZERO).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn nonzero_duration_returns_ok_when_future_completes_first() {
        // Future resolves well before the deadline — the helper must surface
        // the inner value via `Ok(...)`.
        let result = await_with_optional_timeout(async { "ok" }, Duration::from_secs(60)).await;
        assert_eq!(result.unwrap(), "ok");
    }

    #[tokio::test]
    async fn nonzero_duration_returns_elapsed_when_future_stalls() {
        // The handshake bound *only* fires when the future never resolves
        // within the deadline. A pending future + a tiny real timeout keeps
        // the assertion deterministic without needing tokio's `test-util`
        // feature on the dev-dependency.
        let pending = std::future::pending::<()>();
        let result = await_with_optional_timeout(pending, Duration::from_millis(50)).await;
        assert!(result.is_err(), "expected Elapsed when the future stalls");
    }
}

#[cfg(test)]
mod build_h3_backend_headers_tests {
    //! Regression tests for `build_h3_backend_headers` covering the RFC
    //! 8470 §5.2 `Early-Data: 1` injection on the native H3 backend
    //! dispatch path. The function is `fn` (module-private) so these
    //! tests must live inline.
    //!
    //! Notes on test fixture:
    //! - `ProxyState::new` requires a tokio runtime (it spawns health
    //!   check tasks); empty `GatewayConfig` keeps the spawn list empty.
    //! - The tests use `via_header_http3 = None` and
    //!   `add_forwarded_header = false` (default `EnvConfig`) so the
    //!   output vector contains only host + XFF + XFP + maybe XFH +
    //!   the `Early-Data` header under test.
    use std::collections::HashMap;

    use super::build_h3_backend_headers;
    use crate::config::EnvConfig;
    use crate::config::types::{GatewayConfig, Proxy};
    use crate::dns::{DnsCache, DnsConfig};
    use crate::proxy::ProxyState;

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
            mesh_revision: None,
            k8s_mesh_overlay: Default::default(),
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

    fn header_present(
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        name: &str,
    ) -> bool {
        headers
            .iter()
            .any(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
    }

    fn header_value<'a>(
        headers: &'a [(http::header::HeaderName, http::header::HeaderValue)],
        name: &str,
    ) -> Option<&'a http::header::HeaderValue> {
        headers
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    #[tokio::test]
    async fn native_h3_forwarded_proto_uses_uri_scheme_not_alpn_token() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        assert_eq!(
            header_value(&out, "x-forwarded-proto").map(|v| v.as_bytes()),
            Some(&b"https"[..]),
            "X-Forwarded-Proto must carry the URI scheme, not the H3 ALPN token"
        );

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ false,
            /* is_early_data = */ false,
        );
        assert_eq!(
            header_value(&out, "x-forwarded-proto").map(|v| v.as_bytes()),
            Some(&b"http"[..]),
            "a trusted original HTTP scheme must override the H3 transport scheme"
        );
    }

    #[tokio::test]
    async fn native_h3_forwarded_header_uses_effective_request_scheme() {
        let mut state = minimal_proxy_state();
        state.add_forwarded_header = true;
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        assert_eq!(
            header_value(&out, "forwarded").and_then(|v| v.to_str().ok()),
            Some("for=203.0.113.1;proto=https;host=api.example"),
            "Forwarded proto must be the URI scheme, not the H3 ALPN token"
        );

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ false,
            /* is_early_data = */ false,
        );
        assert_eq!(
            header_value(&out, "forwarded").and_then(|v| v.to_str().ok()),
            Some("for=203.0.113.1;proto=http;host=api.example"),
            "Forwarded must carry a trusted original HTTP scheme"
        );
    }

    #[tokio::test]
    async fn native_h3_strips_client_forwarded_when_regenerating() {
        // Issue #2952: when FERRUM_ADD_FORWARDED_HEADER is on, client-supplied
        // Forwarded must not survive beside the gateway-owned value.
        let mut state = minimal_proxy_state();
        state.add_forwarded_header = true;
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example".to_string());
        headers.insert(
            "forwarded".to_string(),
            "for=10.0.0.1;proto=https".to_string(),
        );

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        let forwarded: Vec<&str> = out
            .iter()
            .filter(|(n, _)| n.as_str() == "forwarded")
            .filter_map(|(_, v)| v.to_str().ok())
            .collect();
        assert_eq!(
            forwarded,
            vec!["for=203.0.113.1;proto=https;host=api.example"],
            "only the gateway-owned Forwarded element may reach the H3 backend"
        );
    }

    #[tokio::test]
    async fn native_h3_strips_mixed_case_and_duplicate_forwarded_when_regenerating() {
        // Hostile / plugin-injected mixed-case keys and folded duplicates must
        // fail closed to a single gateway-owned element.
        let mut state = minimal_proxy_state();
        state.add_forwarded_header = true;
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example".to_string());
        headers.insert(
            "Forwarded".to_string(),
            "for=10.0.0.1;proto=https, for=198.51.100.7".to_string(),
        );

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        let forwarded: Vec<&str> = out
            .iter()
            .filter(|(n, _)| n.as_str().eq_ignore_ascii_case("forwarded"))
            .filter_map(|(_, v)| v.to_str().ok())
            .collect();
        assert_eq!(
            forwarded,
            vec!["for=203.0.113.1;proto=https;host=api.example"],
            "mixed-case / duplicate client Forwarded must not survive regeneration"
        );
    }

    #[tokio::test]
    async fn native_h3_passes_client_forwarded_when_not_regenerating() {
        let state = minimal_proxy_state();
        assert!(
            !state.add_forwarded_header,
            "default fixture must leave regeneration off"
        );
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example".to_string());
        headers.insert(
            "forwarded".to_string(),
            "for=10.0.0.1;proto=https".to_string(),
        );

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        assert_eq!(
            header_value(&out, "forwarded").and_then(|v| v.to_str().ok()),
            Some("for=10.0.0.1;proto=https"),
            "client Forwarded passes through when Ferrum is not regenerating it"
        );
    }

    #[tokio::test]
    async fn injects_early_data_header_when_request_is_zero_rtt() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "test-client".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ true,
        );

        assert!(
            header_present(&out, "early-data"),
            "Early-Data must be injected on outbound H3 backend request when ctx.is_early_data is true"
        );
        assert_eq!(
            header_value(&out, "early-data").map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "RFC 8470 §5.2 mandates the value `1`"
        );
    }

    #[tokio::test]
    async fn does_not_inject_early_data_header_for_normal_request() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "test-client".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        assert!(
            !header_present(&out, "early-data"),
            "Early-Data must NOT be injected when the request is not 0-RTT"
        );
    }

    #[tokio::test]
    async fn strips_client_supplied_early_data_header_when_zero_rtt() {
        // RFC 8470 §5.2: clients never set `Early-Data`; only intermediaries
        // do. The gateway must strip and re-inject so the value is
        // authoritative regardless of what the client sent.
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("early-data".to_string(), "0".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ true,
        );

        let early_data_count = out
            .iter()
            .filter(|(n, _)| n.as_str() == "early-data")
            .count();
        assert_eq!(
            early_data_count, 1,
            "client-supplied Early-Data must not duplicate or survive — \
             expected exactly one Early-Data: 1 from the gateway, got {early_data_count}"
        );
        assert_eq!(
            header_value(&out, "early-data").map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "client's `0` must be replaced with the gateway's `1`"
        );
    }

    #[tokio::test]
    async fn strips_client_supplied_early_data_header_when_not_zero_rtt() {
        // Even when `is_early_data == false`, the gateway must strip a
        // client-supplied `Early-Data` header. A bogus client cannot
        // trick the backend into believing the request was 0-RTT.
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();
        let mut headers = HashMap::new();
        headers.insert("early-data".to_string(), "1".to_string());

        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            /* request_is_secure = */ true,
            /* is_early_data = */ false,
        );

        assert!(
            !header_present(&out, "early-data"),
            "client-supplied Early-Data must be stripped, and no value injected when is_early_data == false"
        );
    }

    /// H1/H2/H3 XFF parity: the native H3 backend path must append the
    /// immediate QUIC peer to an existing inbound chain (not the resolved
    /// client, which is already in the chain) and seed a generated chain
    /// with the resolved client when it differs from the peer
    /// (real-IP-header deployments). See `proxy::build_xff_value`.
    #[tokio::test]
    async fn xff_appends_quic_peer_and_seeds_resolved_client() {
        let state = minimal_proxy_state();
        let proxy = minimal_proxy();

        // Trusted LB sent XFF: append the peer, never the resolved client.
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());
        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "198.51.100.7", // resolved client (already in the chain)
            "10.0.0.7",     // immediate QUIC peer (the LB)
            &state,
            true,
            false,
        );
        assert_eq!(
            header_value(&out, "x-forwarded-for").map(|v| v.as_bytes()),
            Some(&b"198.51.100.7, 10.0.0.7"[..]),
            "inbound chain + appended QUIC peer; resolved client must not duplicate"
        );

        // Trusted LB sent only a real-IP header (no XFF): seed with the
        // resolved client, then the peer.
        let headers = HashMap::new();
        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.9", // resolved from FERRUM_REAL_IP_HEADER
            "10.0.0.7",    // immediate QUIC peer (the LB)
            &state,
            true,
            false,
        );
        assert_eq!(
            header_value(&out, "x-forwarded-for").map(|v| v.as_bytes()),
            Some(&b"203.0.113.9, 10.0.0.7"[..]),
            "generated chain must carry the resolved real client before the peer"
        );

        // Direct client (no proxy in front): client == peer, single entry.
        let out = build_h3_backend_headers(
            &proxy,
            None,
            &headers,
            "203.0.113.1",
            "203.0.113.1",
            &state,
            true,
            false,
        );
        assert_eq!(
            header_value(&out, "x-forwarded-for").map(|v| v.as_bytes()),
            Some(&b"203.0.113.1"[..]),
            "direct connections must not duplicate the peer"
        );
    }
}

#[cfg(test)]
mod build_h3_quinn_server_config_mtls_tests {
    //! Regression tests for the HTTP/3 mTLS fail-CLOSED contract in
    //! `build_h3_quinn_server_config` (module-private `fn`, so the tests must
    //! live inline).
    //!
    //! Before the fix, a *configured* client CA bundle that could not be
    //! loaded/parsed into a verifier (missing / invalid / empty / truncated
    //! during rotation) caused this function to `warn!` and silently rebuild
    //! the QUIC `ServerConfig` with `with_no_client_auth()`, returning `Ok`.
    //! Because the frontend-TLS reload handler only keeps the previous config
    //! when this function returns `Err`, that silent downgrade let a reload
    //! swap a previously mTLS-protected H3 listener for one that accepts
    //! clients presenting no certificate. The function must now FAIL CLOSED:
    //! a configured-but-unloadable client CA returns `Err`; only an explicitly
    //! *unconfigured* client CA (`None`) yields no client auth.
    use std::sync::{Arc, Once};

    use super::build_h3_quinn_server_config;
    use crate::config::EnvConfig;
    use crate::http3::config::Http3ServerConfig;
    use crate::tls::{CrlList, TlsPolicy};

    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Minimal frontend `ServerConfig`. The only field the H3 rebuild path
    /// reads from it is `cert_resolver`, which `with_single_cert` populates.
    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        let cert_pem = cert.pem();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(Result::ok)
            .collect();
        let key_pem = key_pair.serialize_pem();
        let private_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .expect("read private key")
            .expect("private key present");
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .expect("server cert"),
        )
    }

    /// Write a valid self-signed CA bundle and return its path.
    fn write_valid_ca(dir: &std::path::Path) -> String {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Client CA");
        params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let cert = params.self_signed(&key_pair).expect("self-sign ca");
        let ca_path = dir.join("client-ca.pem");
        std::fs::write(&ca_path, cert.pem()).expect("write ca");
        ca_path.to_string_lossy().into_owned()
    }

    /// Drive `build_h3_quinn_server_config` with the given client CA bundle.
    fn build(client_ca: Option<&str>) -> Result<quinn::ServerConfig, anyhow::Error> {
        ensure_crypto_provider();
        let tls_config = test_server_config();
        let tls_policy = TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy");
        let crls: CrlList = Arc::new(Vec::new());
        let h3_config = Http3ServerConfig::default();
        build_h3_quinn_server_config(&tls_config, &tls_policy, client_ca, &crls, &h3_config)
    }

    #[test]
    fn invalid_client_ca_fails_closed() {
        // A corrupted/non-PEM CA bundle (e.g. truncated mid-rotation) must NOT
        // silently downgrade H3 to no-client-auth.
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("garbage-ca.pem");
        std::fs::write(&ca_path, b"this file is not a PEM certificate at all\n").expect("write");
        let result = build(Some(ca_path.to_str().expect("utf8 path")));
        assert!(
            result.is_err(),
            "configured-but-invalid H3 client CA must fail closed (Err), not silently disable mTLS"
        );
    }

    #[test]
    fn missing_client_ca_fails_closed() {
        let result = build(Some("/nonexistent/path/to/client-ca.pem"));
        assert!(
            result.is_err(),
            "configured-but-missing H3 client CA must fail closed (Err)"
        );
    }

    #[test]
    fn empty_client_ca_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("empty-ca.pem");
        std::fs::write(&ca_path, b"").expect("write");
        let result = build(Some(ca_path.to_str().expect("utf8 path")));
        assert!(
            result.is_err(),
            "configured-but-empty H3 client CA must fail closed (Err)"
        );
    }

    #[test]
    fn valid_client_ca_builds_with_mtls() {
        // The happy path: a valid client CA bundle still yields a usable QUIC
        // server config (now with client-cert verification wired in).
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = write_valid_ca(dir.path());
        let result = build(Some(&ca_path));
        assert!(
            result.is_ok(),
            "valid H3 client CA must build successfully: {:?}",
            result.err()
        );
    }

    #[test]
    fn no_client_ca_builds_without_client_auth() {
        // The only path that legitimately yields no client auth is an
        // explicitly *unconfigured* client CA bundle.
        let result = build(None);
        assert!(
            result.is_ok(),
            "H3 without a configured client CA must build (no client auth): {:?}",
            result.err()
        );
    }
}
