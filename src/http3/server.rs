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
//! Stateless session ticket resumption is always enabled (saves 1 RTT on
//! reconnects).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use h3::server::RequestStream;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{debug, error, info, warn};

use super::config::Http3ServerConfig;
use crate::config::types::{HttpFlavor, Proxy, UpstreamTarget};
use crate::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext, TransactionSummary};
use crate::proxy::{
    ProxyState, apply_after_proxy_hooks_to_rejection, plugin_result_into_reject_parts,
    run_after_proxy_hooks, run_authentication_phase,
};
use crate::tls::TlsPolicy;

/// Optional HTTP/3 listener settings that don't affect the core bind contract.
#[derive(Default)]
pub struct Http3ListenerOptions {
    pub client_ca_bundle_path: Option<String>,
    pub started_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Start the HTTP/3 (QUIC) proxy listener.
///
/// HTTP/3 (QUIC) mandates TLS 1.3. If the provided TLS policy does not include
/// TLS 1.3, this function will override it to force TLS 1.3 for the QUIC listener
/// and log a warning.
#[allow(dead_code)] // Used by library consumers and tests; binary startup uses the signaled variant.
pub async fn start_http3_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Arc<rustls::ServerConfig>,
    h3_config: Http3ServerConfig,
    tls_policy: &TlsPolicy,
    client_ca_bundle_path: Option<String>,
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
            started_tx: None,
        },
    )
    .await
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
        started_tx,
    } = options;

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
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
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
    let mut server_tls_config = if let Some(ref ca_path) = client_ca_bundle_path {
        match crate::tls::build_client_cert_verifier(ca_path) {
            Ok(verifier) => h3_builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(tls_config.cert_resolver.clone()),
            Err(e) => {
                warn!(
                    "Failed to build client cert verifier for HTTP/3, disabling mTLS: {}",
                    e
                );
                h3_builder
                    .with_no_client_auth()
                    .with_cert_resolver(tls_config.cert_resolver.clone())
            }
        }
    } else {
        h3_builder
            .with_no_client_auth()
            .with_cert_resolver(tls_config.cert_resolver.clone())
    };

    server_tls_config.alpn_protocols = vec![b"h3".to_vec()];
    // 0-RTT early data: controlled by FERRUM_TLS_EARLY_DATA_METHODS.
    // When 0 (default), 0-RTT is disabled — early data is replayable, which is
    // dangerous for non-idempotent operations proxied through an API gateway.
    // When non-zero, the gateway accepts 0-RTT and enforces per-method filtering
    // via quinn's into_0rtt() detection in handle_h3_connection().
    server_tls_config.max_early_data_size = tls_policy.early_data_max_size;

    // Enable TLS 1.3 session resumption for QUIC connections.
    // Stateless tickets allow clients to resume sessions without a full handshake,
    // saving 1 RTT on reconnections. This is safe (no replay risk — 0-RTT is still
    // disabled separately via max_early_data_size=0).
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

    // QUIC flow-control tuning — larger windows improve throughput on modern networks.
    transport_config.stream_receive_window(
        quinn::VarInt::from_u64(h3_config.stream_receive_window)
            .unwrap_or(quinn::VarInt::from_u32(8_388_608)),
    );
    transport_config.receive_window(
        quinn::VarInt::from_u64(h3_config.receive_window)
            .unwrap_or(quinn::VarInt::from_u32(33_554_432)),
    );
    transport_config.send_window(h3_config.send_window);

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("HTTP/3 (QUIC) listener started on {}", addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }

    let mut shutdown_rx = shutdown;

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
                        let state = state.clone();
                        tokio::spawn(async move {
                            let _conn_guard =
                                crate::overload::ConnectionGuard::new(&state.overload);
                            if let Err(e) = handle_h3_connection(connecting, state).await {
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
            _ = shutdown_rx.changed() => {
                info!("HTTP/3 listener shutting down");
                endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 connection (may carry multiple streams/requests).
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    state: ProxyState,
) -> Result<(), anyhow::Error> {
    let early_data_enabled = !state.early_data_methods.is_empty();

    // When 0-RTT is enabled in the TLS config, attempt to accept early data
    // via quinn's into_0rtt(). This returns the connection immediately if the
    // client sent 0-RTT data (before the handshake completes).
    //
    // IMPORTANT: Only requests arriving BEFORE the TLS handshake completes are
    // 0-RTT early data. Once ZeroRttAccepted resolves (handshake done), new
    // requests on the same connection are NOT early data. We use an AtomicBool
    // that starts true and flips to false when the handshake completes, so each
    // request checks the current state — not the connection-level flag.
    let in_early_data = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let connection = if early_data_enabled {
        let connecting = connecting.accept()?.into_0rtt();
        match connecting {
            Ok((conn, zero_rtt_accepted)) => {
                debug!(
                    "HTTP/3 0-RTT connection accepted from {}",
                    conn.remote_address()
                );
                in_early_data.store(true, std::sync::atomic::Ordering::Release);
                // Spawn a task that waits for the handshake to complete, then
                // clears the early-data flag. Requests dispatched after this
                // point will see is_early_data = false.
                let flag = in_early_data.clone();
                tokio::spawn(async move {
                    zero_rtt_accepted.await;
                    flag.store(false, std::sync::atomic::Ordering::Release);
                });
                conn
            }
            Err(connecting) => {
                // No 0-RTT — fall back to full handshake
                connecting.await?
            }
        }
    } else {
        connecting.await?
    };

    let remote_addr = connection.remote_address();
    debug!("HTTP/3 connection established from {}", remote_addr);

    // Extract peer certificate and chain from the QUIC connection (mTLS).
    // Quinn returns peer_identity() as Box<dyn Any> containing Vec<rustls::pki_types::CertificateDer>.
    // Arc-shared so multiplexed streams avoid per-request cert cloning.
    let peer_certs: Option<Vec<Vec<u8>>> = connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .map(|certs| certs.iter().map(|c| c.to_vec()).collect());
    let client_cert_der: Option<Arc<Vec<u8>>> = peer_certs
        .as_ref()
        .and_then(|certs| certs.first())
        .map(|cert| Arc::new(cert.clone()));
    // Capture intermediate/CA certs (index 1+) for per-proxy CA filtering in mtls_auth.
    let client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>> = peer_certs
        .as_ref()
        .filter(|certs| certs.len() > 1)
        .map(|certs| Arc::new(certs[1..].to_vec()));

    // Keep a handle to the quinn connection so we can detect QUIC connection
    // migration (RFC 9000 §9). When a client migrates to a new IP (e.g., mobile
    // network handoff), quinn updates remote_address() internally. We compare
    // the SocketAddr per-request (cheap integer comparison) and only re-format
    // the IP string on the rare occasion it changes. This prevents stale IPs
    // from poisoning rate-limit keys and access logs after migration.
    let quinn_conn = connection.clone();
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    // Pre-format socket IP string once per connection — shared across all streams
    // to avoid per-request String allocation from SocketAddr::ip().to_string().
    // Updated in-place when QUIC connection migration is detected.
    let mut cached_addr = quinn_conn.remote_address();
    let mut socket_ip: Arc<str> = Arc::from(cached_addr.ip().to_string());

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                // Detect QUIC connection migration: compare SocketAddr (two integer
                // fields) — zero allocation. Only re-format the IP string when the
                // address actually changes, which is rare (mobile network handoff).
                let current_addr = quinn_conn.remote_address();
                if current_addr != cached_addr {
                    info!(
                        "HTTP/3 connection migration detected: {} -> {}",
                        cached_addr, current_addr
                    );
                    cached_addr = current_addr;
                    socket_ip = Arc::from(current_addr.ip().to_string());
                }

                let state = state.clone();
                let cert = client_cert_der.clone();
                let chain = client_cert_chain_der.clone();
                let socket_ip = Arc::clone(&socket_ip);
                // Snapshot the early-data flag NOW — before spawning the task.
                // This captures whether the handshake has completed at the moment
                // this request stream was accepted. Single atomic load (~1ns).
                let is_early_data = in_early_data.load(std::sync::atomic::Ordering::Acquire);
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(
                                req,
                                stream,
                                state,
                                current_addr,
                                &socket_ip,
                                cert,
                                chain,
                                is_early_data,
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
                debug!("HTTP/3 connection closed from {}", remote_addr);
                break;
            }
            Err(e) => {
                warn!("HTTP/3 connection error from {}: {}", remote_addr, e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 request stream.
#[allow(clippy::too_many_arguments)]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: ProxyState,
    remote_addr: SocketAddr,
    socket_ip: &str,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    is_early_data: bool,
) -> Result<(), anyhow::Error> {
    let start_time = std::time::Instant::now();

    // Detect the HTTP flavor (Plain / gRPC / WebSocket) once from the incoming
    // H3 request — performed FIRST so every admission rejection below can be
    // flavor-aware (trailers-only gRPC errors for gRPC requests, JSON for
    // everything else). WebSocket over H3 requires Extended CONNECT
    // (RFC 9220) and is not currently supported by this listener; gRPC over
    // H3 is legal but the backend-side decoupling below intentionally does
    // not dispatch it via the H3 pool (the pool only speaks QUIC → QUIC
    // backends). Keeping the flavor around lets the dispatch guard emit a
    // precise 502 instead of forwarding non-Plain traffic to an H3 backend
    // that does not expect it.
    let http_flavor = crate::proxy::backend_dispatch::detect_http_flavor(&req);

    // Global request admission control (HTTP/3). Single atomic load (~1ns).
    if state
        .overload
        .reject_new_requests
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        record_request(&state, 503);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            http::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"Service overloaded"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
            "Service overloaded",
        )
        .await?;
        return Ok(());
    }

    // Track this request for overload monitoring and graceful drain.
    let _request_guard = crate::overload::RequestGuard::new(&state.overload);

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    // Build request context (client_ip resolved below after headers are parsed)
    let mut ctx = RequestContext::new(socket_ip.to_owned(), method.clone(), path.clone());
    ctx.tls_client_cert_der = tls_client_cert_der;
    ctx.tls_client_cert_chain_der = tls_client_cert_chain_der;

    // Validate header sizes without materializing headers into owned Strings.
    // The raw HeaderMap is stored on ctx for deferred materialization.
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_request(&state, 431);
            let body = format!(
                r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                name.as_str(),
                state.max_single_header_size_bytes
            );
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
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
        record_request(&state, 431);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Total request headers exceed maximum size",
        )
        .await?;
        return Ok(());
    }
    if state.max_header_count > 0 && req.headers().len() > state.max_header_count {
        record_request(&state, 431);
        let body = format!(
            r#"{{"error":"Request header count ({}) exceeds maximum of {}"}}"#,
            req.headers().len(),
            state.max_header_count
        );
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &body,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Request header count exceeds maximum",
        )
        .await?;
        return Ok(());
    }

    // Store raw headers for deferred materialization.
    ctx.set_raw_headers(req.headers().clone());

    // Validate URL length (path + query string)
    if state.max_url_length_bytes > 0 {
        let url_len = path.len()
            + if query_string.is_empty() {
                0
            } else {
                1 + query_string.len()
            };
        if url_len > state.max_url_length_bytes {
            record_request(&state, 414);
            let body = format!(
                r#"{{"error":"Request URL length ({} bytes) exceeds maximum of {} bytes"}}"#,
                url_len, state.max_url_length_bytes
            );
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
                StatusCode::URI_TOO_LONG,
                &body,
                crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                "Request URL too long",
            )
            .await?;
            return Ok(());
        }
    }

    // Validate query parameter count
    if state.max_query_params > 0 && !query_string.is_empty() {
        let param_count = query_string.split('&').count();
        if param_count > state.max_query_params {
            record_request(&state, 400);
            let body = format!(
                r#"{{"error":"Query parameter count ({}) exceeds maximum of {}"}}"#,
                param_count, state.max_query_params
            );
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
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
    // HTTP/3 has no Transfer-Encoding or Host header concerns (uses :authority),
    // but multiple Content-Length with mismatched values is still a protocol violation.
    if let Some(error_body) =
        crate::proxy::check_protocol_headers(req.headers(), http::Version::HTTP_3)
    {
        warn!("Rejected HTTP/3 request: {}", error_body);
        record_request(&state, 400);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::BAD_REQUEST,
            error_body,
            crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
            "Protocol header violation",
        )
        .await?;
        return Ok(());
    }

    // Block TRACE method to prevent Cross-Site Tracing (XST) attacks.
    if method == "TRACE" {
        warn!("Rejected HTTP/3 TRACE request");
        record_request(&state, 405);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
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
    // and falls through to the shared unsupported-WebSocket path, which
    // returns the documented 501 response. Other CONNECT-style protocols
    // (for example CONNECT-UDP) are not supported by this proxy and must be
    // rejected to prevent tunnel establishment that bypasses proxy routing.
    if method == "CONNECT" && http_flavor != HttpFlavor::WebSocket {
        warn!("Rejected non-WebSocket HTTP/3 CONNECT request");
        record_request(&state, 405);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"CONNECT method is not allowed"}"#,
            crate::proxy::grpc_proxy::grpc_status::UNIMPLEMENTED,
            "CONNECT method is not allowed",
        )
        .await?;
        return Ok(());
    }

    // gRPC spec mandates POST — reject non-POST gRPC with a trailers-only
    // error before any routing work so the H3 listener matches the H1/H2
    // dispatch contract.
    if matches!(http_flavor, HttpFlavor::Grpc) && method != "POST" {
        warn!(method = %method, "Rejected HTTP/3 gRPC request: method must be POST");
        record_request(&state, 400);
        send_h3_grpc_error(
            &mut stream,
            crate::proxy::grpc_proxy::grpc_status::INVALID_ARGUMENT,
            "gRPC requires POST method",
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
        record_request(&state, 425);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
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
    // Uses raw_header_get() to read specific headers without materializing the
    // full HashMap — only 2-3 targeted lookups on the raw HeaderMap.
    if !state.trusted_proxies.is_empty() {
        let socket_addr: std::net::IpAddr = remote_addr.ip();
        let xff = ctx.raw_header_get("x-forwarded-for");
        let resolved = if let Some(ref real_ip_header) = state.env_config.real_ip_header {
            // real_ip_header is already lowercase from env config parsing
            let header_val = ctx.raw_header_get(real_ip_header.as_str());
            if let Some(val) = header_val
                && state.trusted_proxies.contains(&socket_addr)
            {
                val.trim().to_string()
            } else {
                crate::proxy::client_ip::resolve_client_ip_parsed(
                    socket_ip,
                    &socket_addr,
                    xff,
                    &state.trusted_proxies,
                )
            }
        } else {
            crate::proxy::client_ip::resolve_client_ip_parsed(
                socket_ip,
                &socket_addr,
                xff,
                &state.trusted_proxies,
            )
        };
        ctx.client_ip = resolved;
    }

    // Per-IP concurrent request limiting (same as HTTP/1.1 and HTTP/2 paths).
    let _per_ip_guard = if let Some(ref counts) = state.per_ip_request_counts {
        let count = counts
            .entry(ctx.client_ip.clone())
            .or_insert_with(|| std::sync::atomic::AtomicU64::new(0));
        let current = count
            .value()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
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
            record_request(&state, 429);
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
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
    let request_host: Option<String> = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| ctx.raw_header_get("host"))
        .map(|h| {
            let without_port = h.split(':').next().unwrap_or(h);
            // Strip trailing dot from FQDN (e.g., "example.com." → "example.com").
            // DNS treats "example.com." and "example.com" as identical, so routing
            // must normalize to prevent host-matching bypasses.
            let normalized = without_port.strip_suffix('.').unwrap_or(without_port);
            normalized.to_lowercase()
        });

    // Route: host + longest prefix match via router cache
    let route_match = state
        .router_cache
        .find_proxy(request_host.as_deref(), &path);

    let proxy = match route_match {
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
            rm.proxy
        }
        None => {
            record_request(&state, 404);
            send_h3_error_flavor_aware(
                &mut stream,
                http_flavor,
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

    // Per-proxy HTTP method filtering (checked before plugins to save work)
    if let Some(ref allowed) = proxy.allowed_methods
        && !allowed.iter().any(|m| m.eq_ignore_ascii_case(&method))
    {
        record_request(&state, 405);
        let mut headers = HashMap::new();
        headers.insert("allow".to_string(), allowed.join(", "));
        send_h3_reject_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"Method Not Allowed"}"#.as_bytes(),
            &headers,
        )
        .await?;
        return Ok(());
    }

    // Map runtime HTTP flavor to the plugin-cache protocol key so H3 gRPC
    // requests load the gRPC plugin/auth/capability sets rather than the
    // HTTP-only sets. WebSocket-over-H3 already returns 501 earlier, so we
    // only need to distinguish gRPC from everything else here.
    let request_protocol = match http_flavor {
        HttpFlavor::Grpc => ProxyProtocol::Grpc,
        _ => ProxyProtocol::Http,
    };

    // Get pre-resolved plugins filtered by protocol (O(1) lookup)
    let plugins = state
        .plugin_cache
        .get_plugins_for_protocol(&proxy.id, request_protocol);
    // Pre-computed capability bitset — avoids per-request iter().any() scans.
    let capabilities = state
        .plugin_cache
        .get_capabilities(&proxy.id, request_protocol);

    let mut plugin_execution_ns: u64 = 0;

    // Execute on_request_received hooks
    let phase_start = std::time::Instant::now();
    for plugin in plugins.iter() {
        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                let reject = plugin_result_into_reject_parts(reject)
                    .expect("reject result should convert to rejection parts");
                record_request(&state, reject.status_code);
                let mut headers = reject.headers;
                apply_after_proxy_hooks_to_rejection(
                    &plugins,
                    &mut ctx,
                    reject.status_code,
                    &mut headers,
                )
                .await;
                let http_status = StatusCode::from_u16(reject.status_code)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                send_h3_reject_flavor_aware(
                    &mut stream,
                    http_flavor,
                    http_status,
                    &reject.body,
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
    }
    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;

    // Materialize query params before authentication (raw, no percent-decoding
    // for HTTP/3 — preserves existing behavior).
    ctx.materialize_query_params_raw();

    // Authentication phase (pre-computed auth plugin list — zero allocation).
    // `request_protocol` matches the HTTP/1.1 + HTTP/2 path so H3 gRPC
    // requests load the gRPC auth plugin set (not the HTTP-only set) —
    // same proxy serves all three client versions uniformly.
    let auth_plugins = state
        .plugin_cache
        .get_auth_plugins(&proxy.id, request_protocol);

    let auth_phase_start = std::time::Instant::now();
    if let Some((status_code, body, mut headers)) = run_authentication_phase(
        proxy.auth_mode.clone(),
        &auth_plugins,
        &mut ctx,
        &state.consumer_index,
    )
    .await
    {
        record_request(&state, status_code);
        apply_after_proxy_hooks_to_rejection(&plugins, &mut ctx, status_code, &mut headers).await;
        let http_status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED);
        send_h3_reject_flavor_aware(&mut stream, http_flavor, http_status, &body, &headers).await?;
        return Ok(());
    }
    plugin_execution_ns += auth_phase_start.elapsed().as_nanos() as u64;

    // Authorization phase
    {
        let phase_start = std::time::Instant::now();
        for plugin in plugins.iter() {
            if plugin.name() == "access_control" {
                match plugin.authorize(&mut ctx).await {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        let reject = plugin_result_into_reject_parts(reject)
                            .expect("reject result should convert to rejection parts");
                        record_request(&state, reject.status_code);
                        let mut headers = reject.headers;
                        apply_after_proxy_hooks_to_rejection(
                            &plugins,
                            &mut ctx,
                            reject.status_code,
                            &mut headers,
                        )
                        .await;
                        let http_status = StatusCode::from_u16(reject.status_code)
                            .unwrap_or(StatusCode::FORBIDDEN);
                        send_h3_reject_flavor_aware(
                            &mut stream,
                            http_flavor,
                            http_status,
                            &reject.body,
                            &headers,
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    let maybe_needs_request_buffering = state
        .plugin_cache
        .requires_request_body_buffering(&proxy.id);
    let plugin_needs_request_buffering = maybe_needs_request_buffering
        && plugins
            .iter()
            .any(|plugin| plugin.should_buffer_request_body(&ctx));
    let needs_request_body_before_before_proxy = plugin_needs_request_buffering
        && capabilities.has(crate::plugin_cache::PluginCapabilities::HAS_BODY_BEFORE_BEFORE_PROXY)
        && plugins.iter().any(|plugin| {
            plugin.requires_request_body_before_before_proxy()
                && plugin.should_buffer_request_body(&ctx)
        });
    let h3_needs_body_bytes = needs_request_body_before_before_proxy
        && capabilities.has(crate::plugin_cache::PluginCapabilities::NEEDS_REQUEST_BODY_BYTES);

    let mut prebuffered_body_data = if needs_request_body_before_before_proxy {
        let mut body_data = Vec::new();
        // For gRPC requests, enforce the gRPC-specific recv ceiling (matches
        // H1/H2 gRPC). Other flavors use the shared HTTP body limit.
        let max_body = if matches!(http_flavor, HttpFlavor::Grpc) {
            state.max_grpc_recv_size_bytes
        } else {
            state.max_request_body_size_bytes
        };
        while let Some(chunk) = stream.recv_data().await? {
            let bytes = chunk.chunk();
            if max_body > 0 && body_data.len() + bytes.len() > max_body {
                record_request(&state, 413);
                send_h3_error_flavor_aware(
                    &mut stream,
                    http_flavor,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                    "Request body exceeds maximum size",
                )
                .await?;
                return Ok(());
            }
            body_data.extend_from_slice(bytes);
        }
        crate::proxy::store_request_body_metadata(&mut ctx, &body_data, h3_needs_body_bytes);
        Some(body_data)
    } else {
        None
    };

    // before_proxy hooks — only clone headers if at least one plugin modifies them.
    // When no plugin modifies headers, use std::mem::take to avoid a per-request HashMap clone.
    let needs_header_clone =
        capabilities.has(crate::plugin_cache::PluginCapabilities::MODIFIES_REQUEST_HEADERS);
    let mut owned_proxy_headers: Option<HashMap<String, String>> = None;
    if needs_header_clone {
        let phase_start = std::time::Instant::now();
        let mut cloned = ctx.headers.clone();
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut cloned).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    record_request(&state, reject.status_code);
                    let mut headers = reject.headers;
                    apply_after_proxy_hooks_to_rejection(
                        &plugins,
                        &mut ctx,
                        reject.status_code,
                        &mut headers,
                    )
                    .await;
                    let http_status = StatusCode::from_u16(reject.status_code)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    send_h3_reject_flavor_aware(
                        &mut stream,
                        http_flavor,
                        http_status,
                        &reject.body,
                        &headers,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        owned_proxy_headers = Some(cloned);
    } else if !plugins.is_empty() {
        // No plugin modifies headers — swap headers out of ctx temporarily to
        // satisfy the borrow checker without cloning (zero allocation hot path).
        let phase_start = std::time::Instant::now();
        let mut tmp_headers = std::mem::take(&mut ctx.headers);
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut tmp_headers).await {
                PluginResult::Continue => {}
                reject @ PluginResult::Reject { .. }
                | reject @ PluginResult::RejectBinary { .. } => {
                    let reject = plugin_result_into_reject_parts(reject)
                        .expect("reject result should convert to rejection parts");
                    ctx.headers = tmp_headers;
                    record_request(&state, reject.status_code);
                    let mut headers = reject.headers;
                    apply_after_proxy_hooks_to_rejection(
                        &plugins,
                        &mut ctx,
                        reject.status_code,
                        &mut headers,
                    )
                    .await;
                    let http_status = StatusCode::from_u16(reject.status_code)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    send_h3_reject_flavor_aware(
                        &mut stream,
                        http_flavor,
                        http_status,
                        &reject.body,
                        &headers,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
        plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        ctx.headers = tmp_headers;
    }
    // Inject identity headers when authentication resolved a principal.
    if let Some(username) = ctx.backend_consumer_username() {
        let headers = owned_proxy_headers.get_or_insert_with(|| ctx.headers.clone());
        headers.insert("X-Consumer-Username".to_string(), username.to_string());
        if let Some(custom_id) = ctx.backend_consumer_custom_id() {
            headers.insert("X-Consumer-Custom-Id".to_string(), custom_id.to_string());
        }
    }
    // Resolve proxy_headers into an owned HashMap to avoid borrowing ctx.headers
    // while ctx is passed as &mut to proxy functions downstream.
    let proxy_headers: HashMap<String, String> =
        owned_proxy_headers.unwrap_or_else(|| std::mem::take(&mut ctx.headers));

    // Enforce request body size limit via Content-Length fast path. Apply
    // the gRPC-specific ceiling to gRPC requests so H3 matches H1/H2.
    let content_length_limit = if matches!(http_flavor, HttpFlavor::Grpc) {
        state.max_grpc_recv_size_bytes
    } else {
        state.max_request_body_size_bytes
    };
    if content_length_limit > 0
        && let Some(content_length) = proxy_headers.get("content-length")
        && let Ok(len) = content_length.parse::<usize>()
        && len > content_length_limit
    {
        record_request(&state, 413);
        send_h3_error_flavor_aware(
            &mut stream,
            http_flavor,
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"{"error":"Request body exceeds maximum size"}"#,
            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
            "Request body exceeds maximum size",
        )
        .await?;
        return Ok(());
    }

    // Determine streaming vs buffered mode — same logic as the H1/H2 paths.
    // Stream by default; buffer when plugins / response_body_mode need body
    // access or when the current request has effective retries (needs replay).
    let has_retry = match http_flavor {
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
        state
            .plugin_cache
            .requires_response_body_buffering(&proxy.id),
    );
    let needs_request_buffering = has_retry || plugin_needs_request_buffering;
    let needs_response_buffering = has_retry || !should_stream_response;

    // --- Upstream target selection and circuit breaker ---
    let selection = crate::proxy::backend_dispatch::select_upstream_target(
        &proxy,
        &state,
        &ctx.client_ip,
        &proxy_headers,
    );
    let lb_hash_key = selection.lb_hash_key;
    let upstream_target = selection.target;

    let cb_target_key = match crate::proxy::backend_dispatch::check_circuit_breaker(
        &proxy,
        &state,
        upstream_target.as_deref(),
    ) {
        Ok(key) => key,
        Err(()) => {
            record_request(&state, 503);
            let mut rej_headers = HashMap::new();
            apply_after_proxy_hooks_to_rejection(&plugins, &mut ctx, 503, &mut rej_headers).await;
            send_h3_reject_flavor_aware(
                &mut stream,
                http_flavor,
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#,
                &rej_headers,
            )
            .await?;
            return Ok(());
        }
    };

    // Build backend URL — target-aware when upstream is configured.
    // Host-only proxies (listen_path None) have no prefix to strip; use 0.
    let strip_len = proxy.listen_path.as_deref().map(str::len).unwrap_or(0);
    let backend_url = if let Some(ref target) = upstream_target {
        crate::proxy::build_backend_url_with_target(
            &proxy,
            &path,
            &query_string,
            &target.host,
            target.port,
            strip_len,
            target.path.as_deref(),
        )
    } else {
        crate::proxy::build_backend_url(&proxy, &path, &query_string, strip_len)
    };
    let backend_start = std::time::Instant::now();
    let sticky_cookie_needed = selection.sticky_cookie_needed;

    // Resolve backend IP once from DNS cache (O(1) cached lookup) before dispatch.
    // Shared across all response paths for TransactionSummary logging.
    let effective_host = upstream_target
        .as_ref()
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);
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

    // ========================================================================
    // Cross-protocol bridge: H3 client → non-H3 backend.
    //
    // The native H3 pool path (below this block) only fires when startup
    // classification has already proved that this concrete backend target
    // supports H3 and the request flavor benefits from H3 (Plain). Every
    // other combination — HttpPool, HttpsPool without proven H3 support, or
    // gRPC/WebSocket — falls through the `crate::http3::cross_protocol::run`
    // bridge, which reuses the same reqwest / HTTP/2 / gRPC backend
    // infrastructure the H1/H2 proxy path uses. Response bodies are streamed
    // with the same coalescing window (`http3_coalesce_*` env vars) so QUIC
    // frame cadence is identical across paths. See
    // `src/http3/cross_protocol.rs` for the buffering policy (request
    // buffered, response streamed) and why that matches the rest of the
    // codebase's two-tier buffering logic. gRPC still uses this bridge
    // because the native H3 pool is plain-HTTP only today.
    let use_native_h3_pool = http_flavor == HttpFlavor::Plain
        && crate::proxy::supports_native_http3_backend(&state, &proxy, upstream_target.as_deref());
    if !use_native_h3_pool {
        let prebuffered = if needs_request_buffering {
            let body_was_prebuffered = prebuffered_body_data.is_some();
            let mut body_data = prebuffered_body_data.take().unwrap_or_default();
            if !body_was_prebuffered {
                while let Some(chunk) = stream.recv_data().await? {
                    let bytes = chunk.chunk();
                    if content_length_limit > 0
                        && body_data.len() + bytes.len() > content_length_limit
                    {
                        record_request(&state, 413);
                        send_h3_error_flavor_aware(
                            &mut stream,
                            http_flavor,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            r#"{"error":"Request body exceeds maximum size"}"#,
                            crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED,
                            "Request body exceeds maximum size",
                        )
                        .await?;
                        return Ok(());
                    }
                    body_data.extend_from_slice(bytes);
                }
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
        let outcome =
            crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest {
                state: &state,
                proxy: &proxy,
                stream: &mut stream,
                method: &method,
                proxy_headers: &proxy_headers,
                path: &path,
                query_string: &query_string,
                backend_url: &backend_url,
                lb_hash_key: lb_hash_key.as_deref(),
                upstream_target: upstream_target.as_deref(),
                cb_target_key: cb_target_key.as_deref(),
                flavor: http_flavor,
                prebuffered_body: prebuffered,
                client_ip: &client_ip_owned,
                ctx: &mut ctx,
                plugins: &plugins,
                sticky_cookie_needed,
            })
            .await?;

        record_request(&state, outcome.response_status);

        // Build the same TransactionSummary shape the native H3 pool path
        // emits so log plugins see a consistent record across dispatch
        // kinds. `latency_backend_total_ms` is populated (not -1.0) because
        // the bridge returns once the response is fully delivered — no
        // deferred completion signal is needed.
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let gateway_processing_ms = total_ms - outcome.backend_total_ms;
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            http_method: method.to_string(),
            request_path: path.clone(),
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: outcome
                .backend_target_url
                .clone()
                .or_else(|| Some(strip_query_params(&backend_url).to_string())),
            backend_resolved_ip: outcome
                .backend_resolved_ip
                .clone()
                .or_else(|| backend_resolved_ip.clone()),
            response_status_code: outcome.response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: outcome.backend_total_ms,
            latency_backend_total_ms: outcome.backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: (gateway_processing_ms - plugin_execution_ms).max(0.0),
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: true,
            client_disconnected: outcome.client_disconnected,
            body_error_class: outcome.body_error_class,
            body_completed: outcome.body_completed,
            bytes_streamed_to_client: outcome.bytes_streamed,
            request_bytes: outcome.request_bytes,
            response_bytes: outcome.bytes_streamed,
            error_class: outcome.error_class,
            mirror: false,
            metadata: ctx.metadata.clone(),
        };
        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;

        return Ok(());
    }

    if can_stream_request_body {
        // ===== STREAMING REQUEST + RESPONSE PATH =====
        // Stream both the request body (frontend → backend) and response body
        // (backend → frontend) without buffering either into memory.

        // Track connection for least-connections LB (after all pre-dispatch rejects)
        if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target) {
            state
                .load_balancer_cache
                .record_connection_start(upstream_id, target);
        }

        let client_ip_owned = ctx.client_ip.clone();
        let h3_headers = build_h3_backend_headers(
            &proxy,
            upstream_target.as_deref(),
            &proxy_headers,
            &client_ip_owned,
            &state,
        );
        let tls_config_fn = || state.connection_pool.get_tls_config_for_backend(&proxy);

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
                    state.max_request_body_size_bytes,
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
                    state.max_request_body_size_bytes,
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
                    send_h3_response(
                        &mut stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"Request body exceeds maximum size"}"#,
                    )
                    .await?;
                    return Ok(());
                }
                error!("Backend request failed (HTTP/3 streaming body): {}", e);
                let h3_error_class = classify_h3_error(&e);
                // H3 frontend → H3 backend path: QUIC failure here means the
                // cached H3 capability lied (backend probably lost UDP), so
                // downgrade the classification. The next H3 request is free
                // to retry — by then `supports_native_http3_backend` returns
                // false and the cross-protocol bridge handles it.
                if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                    state
                        .backend_capabilities
                        .mark_h3_unsupported(&proxy, upstream_target.as_deref());
                }
                let h3_error_body = if h3_error_class == crate::retry::ErrorClass::DnsLookupError {
                    r#"{"error":"DNS resolution for backend failed"}"#
                } else {
                    r#"{"error":"Backend unavailable"}"#
                };
                send_h3_response(&mut stream, StatusCode::BAD_GATEWAY, h3_error_body).await?;

                // Record outcome for CB/health even on failure
                crate::proxy::backend_dispatch::record_backend_outcome(
                    &state,
                    &proxy,
                    upstream_target.as_deref(),
                    cb_target_key.as_deref(),
                    502,
                    true,
                    backend_start.elapsed(),
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
                    http_method: method.to_string(),
                    request_path: path.clone(),
                    matched_proxy_id: Some(proxy.id.clone()),
                    matched_proxy_name: proxy.name.clone(),
                    backend_target_url: Some(strip_query_params(&backend_url).to_string()),
                    backend_resolved_ip: backend_resolved_ip.clone(),
                    response_status_code: 502,
                    latency_total_ms: total_ms,
                    latency_gateway_processing_ms: gateway_processing_ms,
                    latency_backend_ttfb_ms: backend_total_ms,
                    latency_backend_total_ms: backend_total_ms,
                    latency_plugin_execution_ms: plugin_execution_ms,
                    latency_plugin_external_io_ms: plugin_external_io_ms,
                    latency_gateway_overhead_ms: (gateway_processing_ms - plugin_execution_ms)
                        .max(0.0),
                    request_user_agent: proxy_headers.get("user-agent").cloned(),
                    // Backend connection failed before any streaming began — the 502
                    // response body is built and sent synchronously below.
                    error_class: Some(h3_error_class),
                    metadata: ctx.metadata.clone(),
                    ..TransactionSummary::default()
                };
                crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;
                record_request(&state, 502);
                return Ok(());
            }
        };

        let response_status = h3_resp.status;
        let mut response_headers = h3_resp.headers;

        // Hop-by-hop headers already filtered during collection in the H3 pool.

        // Enforce response body size limit via Content-Length fast path
        if state.max_response_body_size_bytes > 0
            && let Some(len) = response_headers
                .get("content-length")
                .and_then(|v| v.parse::<usize>().ok())
            && len > state.max_response_body_size_bytes
        {
            send_h3_response(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Backend response body exceeds maximum size"}"#,
            )
            .await?;

            crate::proxy::backend_dispatch::record_backend_outcome(
                &state,
                &proxy,
                upstream_target.as_deref(),
                cb_target_key.as_deref(),
                502,
                false,
                backend_start.elapsed(),
            );
            record_request(&state, 502);
            return Ok(());
        }

        // after_proxy hooks (run before streaming begins so headers can be modified)
        {
            let phase_start = std::time::Instant::now();
            for plugin in plugins.iter() {
                let _ = plugin
                    .after_proxy(&mut ctx, response_status, &mut response_headers)
                    .await;
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // Sticky session cookie injection
        inject_sticky_cookie(
            &state,
            &proxy,
            upstream_target.as_deref(),
            sticky_cookie_needed,
            &mut response_headers,
        );

        // Send response headers on the H3 stream
        let status_code = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut resp_builder = Response::builder().status(status_code);
        for (k, v) in &response_headers {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                resp_builder = resp_builder.header(name, val);
            }
        }
        if !response_headers.contains_key("content-type") {
            resp_builder = resp_builder.header("content-type", "application/json");
        }
        let resp = resp_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
        stream.send_response(resp).await?;

        // Stream response body from backend h3 recv_stream to frontend h3 stream.
        // Uses a pinned Sleep that is reset in-place to avoid allocating a new
        // timer wheel entry on every select! iteration.
        let coalesce_min_bytes = state.env_config.http3_coalesce_min_bytes;
        let coalesce_max_bytes = state.env_config.http3_coalesce_max_bytes;
        let flush_interval =
            std::time::Duration::from_micros(state.env_config.http3_flush_interval_micros);
        let mut coalesce_buf = BytesMut::with_capacity(coalesce_max_bytes);
        let mut total_streamed: usize = 0;
        let flush_timer = tokio::time::sleep(flush_interval);
        tokio::pin!(flush_timer);
        let mut stream_done = false;
        let mut bytes_streamed: u64 = 0;
        let mut client_disconnected = false;
        let mut body_completed = false;
        let mut body_error_class: Option<crate::retry::ErrorClass> = None;

        'outer: loop {
            tokio::select! {
                chunk_result = h3_resp.recv_stream.recv_data(), if !stream_done => {
                    match chunk_result {
                        Ok(Some(chunk)) => {
                            let chunk_bytes = chunk.chunk();
                            if state.max_response_body_size_bytes > 0 {
                                total_streamed += chunk_bytes.len();
                                if total_streamed > state.max_response_body_size_bytes {
                                    warn!(
                                        "Backend response exceeded {} byte limit during streaming",
                                        state.max_response_body_size_bytes
                                    );
                                    let _ = stream.finish().await;
                                    body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                                    break 'outer;
                                }
                            }
                            coalesce_buf.extend_from_slice(chunk_bytes);
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
                            error!("Error reading backend h3 response during streaming: {}", e);
                            if !coalesce_buf.is_empty() {
                                let data = coalesce_buf.split().freeze();
                                let data_len = data.len() as u64;
                                if stream.send_data(data).await.is_ok() {
                                    bytes_streamed += data_len;
                                }
                            }
                            let _ = stream.finish().await;
                            body_error_class = Some(crate::http3::client::classify_http3_error(&e));
                            break 'outer;
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
            }
            if stream_done {
                if !coalesce_buf.is_empty() {
                    let data = coalesce_buf.split().freeze();
                    let data_len = data.len() as u64;
                    if stream.send_data(data).await.is_err() {
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                        break 'outer;
                    }
                    bytes_streamed += data_len;
                }
                match stream.finish().await {
                    Ok(_) => body_completed = true,
                    Err(_) => {
                        client_disconnected = true;
                        body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                    }
                }
                break;
            }
        }

        // Record outcome
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            upstream_target.as_deref(),
            cb_target_key.as_deref(),
            response_status,
            false,
            backend_start.elapsed(),
        );

        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
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
            http_method: method.to_string(),
            request_path: path.clone(),
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip: backend_resolved_ip.clone(),
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_total_ms,
            latency_backend_total_ms: -1.0, // Streaming — total unknown at log time
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: true,
            client_disconnected,
            error_class: None,
            body_error_class,
            body_completed,
            bytes_streamed_to_client: bytes_streamed,
            // Request body was streamed frame-by-frame via the H3 pool
            // (`request_streaming_body`) — the exact byte count is not
            // currently surfaced back from the pool. Populating this would
            // require threading an `Arc<AtomicU64>` through the H3 request
            // API; deferred to a follow-up. For streaming-request flows,
            // `request_bytes` may be 0 even when a non-empty body was sent.
            request_bytes: 0,
            // Response bytes delivered to the client — tracked by the
            // streaming loop above as `bytes_streamed`, identical to
            // `bytes_streamed_to_client`. Populated here for the unified
            // (buffered+streaming) response-size field.
            response_bytes: bytes_streamed,
            mirror: false,
            metadata: ctx.metadata.clone(),
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
        while let Some(chunk) = stream.recv_data().await? {
            let bytes = chunk.chunk();
            if state.max_request_body_size_bytes > 0
                && body_data.len() + bytes.len() > state.max_request_body_size_bytes
            {
                record_request(&state, 413);
                send_h3_response(
                    &mut stream,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Request body exceeds maximum size"}"#,
                )
                .await?;
                return Ok(());
            }
            body_data.extend_from_slice(bytes);
        }
    }

    // Capture the on-wire request body length BEFORE plugin transforms run.
    // The buffered-response summary and the streaming-response `request_bytes`
    // field both use this value, so `request_bytes` reflects bytes actually
    // received from the client — consistent with the pre-transform semantics
    // of the HTTP/1.1, HTTP/2, and gRPC paths.
    let raw_request_body_bytes = body_data.len() as u64;

    // Transform request body via plugins when buffering is active
    let body_data = if needs_request_buffering
        && !body_data.is_empty()
        && capabilities.has(crate::plugin_cache::PluginCapabilities::MODIFIES_REQUEST_BODY)
    {
        let content_type = proxy_headers.get("content-type").map(|s| s.as_str());
        let mut current = body_data;
        for plugin in plugins.iter() {
            if plugin.modifies_request_body()
                && let Some(transformed) = plugin
                    .transform_request_body(&current, content_type, &proxy_headers)
                    .await
            {
                current = transformed;
            }
        }
        current
    } else {
        body_data
    };

    match crate::proxy::run_final_request_body_hooks(&plugins, &proxy_headers, &body_data).await {
        crate::plugins::PluginResult::Continue => {}
        reject @ crate::plugins::PluginResult::Reject { .. }
        | reject @ crate::plugins::PluginResult::RejectBinary { .. } => {
            let reject = plugin_result_into_reject_parts(reject)
                .expect("reject result should convert to rejection parts");
            record_request(&state, reject.status_code);
            let mut headers = reject.headers;
            apply_after_proxy_hooks_to_rejection(
                &plugins,
                &mut ctx,
                reject.status_code,
                &mut headers,
            )
            .await;
            send_h3_reject_response(
                &mut stream,
                StatusCode::from_u16(reject.status_code).unwrap_or(StatusCode::PAYLOAD_TOO_LARGE),
                &reject.body,
                &headers,
            )
            .await?;
            return Ok(());
        }
    }

    // Track connection for least-connections LB (after all pre-dispatch rejects).
    // Placed here so the streaming-request path above handles its own tracking,
    // and early returns from body collection/plugin rejects don't leak counts.
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target) {
        state
            .load_balancer_cache
            .record_connection_start(upstream_id, target);
    }

    if !needs_response_buffering {
        // ===== STREAMING RESPONSE PATH (buffered request body) =====
        // Response body is streamed, but request body was collected because
        // plugins needed it or it was prebuffered.
        let client_ip_owned = ctx.client_ip.clone();
        // Use the pre-transform length captured before the plugin
        // `transform_request_body` loop ran. `body_data` at this point may
        // have been rewritten by a request-body plugin; logging its current
        // length would misreport the on-wire size. `raw_request_body_bytes`
        // is the canonical `request_bytes` value for the H3 buffered-request
        // path on both the streaming and buffered response branches.
        let request_body_bytes = raw_request_body_bytes;
        let streaming_result = proxy_to_backend_h3_streaming(
            &state,
            &proxy,
            &backend_url,
            &method,
            &proxy_headers,
            body_data,
            &client_ip_owned,
            upstream_target.as_deref(),
            sticky_cookie_needed,
            &mut stream,
            &plugins,
            &mut ctx,
            &mut plugin_execution_ns,
        )
        .await;

        let h3_stream_result = match streaming_result {
            Ok(result) => result,
            Err(e) => {
                // Stream may already have partial data sent — log and return
                debug!("HTTP/3 streaming proxy error: {}", e);
                return Err(e);
            }
        };

        let response_status = h3_stream_result.status;
        let h3_error_class = h3_stream_result.error_class;

        // Record outcome across CB, passive health, latency, and connection tracking
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            upstream_target.as_deref(),
            cb_target_key.as_deref(),
            response_status,
            h3_error_class.is_some(),
            backend_start.elapsed(),
        );

        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
        let backend_ttfb_ms = backend_total_ms; // Approximation for streaming

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
            http_method: method,
            request_path: path,
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
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
            bytes_streamed_to_client: h3_stream_result.bytes_streamed,
            request_bytes: request_body_bytes,
            // `bytes_streamed` from the H3 streaming helper is the final
            // count of body bytes pushed to the client's h3 stream. Mirror
            // it into the unified `response_bytes` field.
            response_bytes: h3_stream_result.bytes_streamed,
            mirror: false,
            metadata: ctx.metadata.clone(),
        };

        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;

        record_request(&state, response_status);
    } else {
        // ===== BUFFERED RESPONSE PATH =====
        // Collect full response for plugin body inspection/transformation and retries.
        // When retries are configured, wrap in a retry loop with target switching.
        let (
            mut response_status,
            response_body,
            mut response_headers,
            h3_error_class,
            final_cb_target_key,
            final_target,
        ) = if let Some(retry_config) = &proxy.retry {
            let mut attempt = 0u32;
            let mut current_target = upstream_target.clone();
            let mut current_cb_target_key = cb_target_key.clone();
            let mut current_url = backend_url.clone();

            let (mut status, mut resp_body, mut resp_headers, mut err_class) = proxy_to_backend_h3(
                &state,
                &proxy,
                &current_url,
                &method,
                &proxy_headers,
                &body_data,
                &ctx.client_ip,
                current_target.as_deref(),
            )
            .await;

            // Build a lightweight BackendResponse for should_retry — only
            // status_code and connection_error are read. Use empty body/headers
            // to avoid cloning the full response on every retry check.
            while crate::retry::should_retry(
                retry_config,
                &method,
                &crate::retry::BackendResponse {
                    status_code: status,
                    connection_error: err_class.is_some(),
                    body: crate::retry::ResponseBody::Buffered(Vec::new()),
                    headers: HashMap::new(),
                    backend_resolved_ip: None,
                    error_class: err_class,
                },
                attempt,
            ) {
                // Record failure against current target's circuit breaker
                if let Some(cb_config) = &proxy.circuit_breaker {
                    let cb = state.circuit_breaker_cache.get_or_create(
                        &proxy.id,
                        current_cb_target_key.as_deref(),
                        cb_config,
                    );
                    cb.record_failure(status, err_class.is_some());
                }

                let delay = crate::retry::retry_delay(retry_config, attempt);
                tokio::time::sleep(delay).await;
                attempt += 1;

                // Try a different target on retry if load balancing is configured
                if let (Some(upstream_id), Some(prev_target)) =
                    (&proxy.upstream_id, &current_target)
                    && let Some(ref hash_key) = lb_hash_key
                    && let Some(next) = state.load_balancer_cache.select_next_target(
                        upstream_id,
                        hash_key,
                        prev_target,
                        Some(&crate::load_balancer::HealthContext {
                            active_unhealthy: &state.health_checker.active_unhealthy_targets,
                            proxy_passive: state
                                .health_checker
                                .passive_health
                                .get(&proxy.id)
                                .map(|r| r.value().clone()),
                        }),
                    )
                {
                    current_url = crate::proxy::build_backend_url_with_target(
                        &proxy,
                        &path,
                        &query_string,
                        &next.host,
                        next.port,
                        strip_len,
                        next.path.as_deref(),
                    );
                    current_cb_target_key =
                        Some(crate::circuit_breaker::target_key(&next.host, next.port));
                    current_target = Some(next);
                }

                warn!(
                    proxy_id = %proxy.id,
                    attempt = attempt,
                    max_retries = retry_config.max_retries,
                    connection_error = err_class.is_some(),
                    "Retrying backend request (HTTP/3 frontend)"
                );

                let retry_result = proxy_to_backend_h3(
                    &state,
                    &proxy,
                    &current_url,
                    &method,
                    &proxy_headers,
                    &body_data,
                    &ctx.client_ip,
                    current_target.as_deref(),
                )
                .await;
                status = retry_result.0;
                resp_body = retry_result.1;
                resp_headers = retry_result.2;
                err_class = retry_result.3;
            }

            (
                status,
                resp_body,
                resp_headers,
                err_class,
                current_cb_target_key,
                current_target,
            )
        } else {
            // No retry configured — single attempt
            let (status, resp_body, resp_headers, err_class) = proxy_to_backend_h3(
                &state,
                &proxy,
                &backend_url,
                &method,
                &proxy_headers,
                &body_data,
                &ctx.client_ip,
                upstream_target.as_deref(),
            )
            .await;
            (
                status,
                resp_body,
                resp_headers,
                err_class,
                cb_target_key,
                upstream_target.clone(),
            )
        };

        // Record outcome against the final target (may differ from initial after retries)
        crate::proxy::backend_dispatch::record_backend_outcome(
            &state,
            &proxy,
            final_target.as_deref(),
            final_cb_target_key.as_deref(),
            response_status,
            h3_error_class.is_some(),
            backend_start.elapsed(),
        );

        let backend_ttfb_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
        let mut response_body = response_body;

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
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // Sticky session cookie injection
        if !after_proxy_rejected {
            inject_sticky_cookie(
                &state,
                &proxy,
                upstream_target.as_deref(),
                sticky_cookie_needed,
                &mut response_headers,
            );
        }

        // on_response_body hooks — only for buffered responses when plugins exist.
        // Mirrors the HTTP/1.1 path in proxy/mod.rs.
        if !after_proxy_rejected && !plugins.is_empty() {
            let phase_start = std::time::Instant::now();
            for plugin in plugins.iter() {
                let result = plugin
                    .on_response_body(&mut ctx, response_status, &response_headers, &response_body)
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        let reject = plugin_result_into_reject_parts(reject)
                            .expect("reject result should convert to rejection parts");
                        debug!(
                            plugin = plugin.name(),
                            status_code = reject.status_code,
                            "Plugin rejected response body (HTTP/3)"
                        );
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
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        // transform_response_body hooks — only for buffered responses.
        if !after_proxy_rejected && !plugins.is_empty() {
            let phase_start = std::time::Instant::now();
            let content_type = response_headers.get("content-type").cloned();
            let ct_ref = content_type.as_deref();
            for plugin in plugins.iter() {
                if let Some(transformed) = plugin
                    .transform_response_body(&response_body, ct_ref, &response_headers)
                    .await
                {
                    response_headers
                        .insert("content-length".to_string(), transformed.len().to_string());
                    response_body = transformed;
                }
            }
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        if !after_proxy_rejected && !plugins.is_empty() {
            let phase_start = std::time::Instant::now();
            for plugin in plugins.iter() {
                let result = plugin
                    .on_final_response_body(
                        &mut ctx,
                        response_status,
                        &response_headers,
                        &response_body,
                    )
                    .await;
                match result {
                    PluginResult::Continue => {}
                    reject @ PluginResult::Reject { .. }
                    | reject @ PluginResult::RejectBinary { .. } => {
                        let reject = plugin_result_into_reject_parts(reject)
                            .expect("reject result should convert to rejection parts");
                        debug!(
                            plugin = plugin.name(),
                            status_code = reject.status_code,
                            "Plugin rejected finalized response body (HTTP/3)"
                        );
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
            plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
        }

        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms = ctx
            .plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let gateway_processing_ms = total_ms - backend_total_ms;
        let gateway_overhead_ms = (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);

        // Request bytes: `raw_request_body_bytes` captured the on-wire size
        // before plugin `transform_request_body` ran, so the summary reflects
        // bytes actually received from the client rather than the possibly
        // rewritten `body_data.len()`. Response bytes: the H3 buffered-response
        // path has `response_body` in scope — its `Vec<u8>` length is what
        // will flow to the client.
        let summary = TransactionSummary {
            namespace: proxy.namespace.clone(),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            http_method: method,
            request_path: path,
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
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
            request_bytes: raw_request_body_bytes,
            response_bytes: response_body.len() as u64,
            metadata: ctx.metadata.clone(),
            ..TransactionSummary::default()
        };

        crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;

        record_request(&state, response_status);

        // Build and send buffered response
        let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut resp_builder = Response::builder().status(status);

        for (k, v) in &response_headers {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                resp_builder = resp_builder.header(name, val);
            }
        }

        if !response_headers.contains_key("content-type") {
            resp_builder = resp_builder.header("content-type", "application/json");
        }

        let resp = resp_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 proxy response: {}", e))?;
        stream.send_response(resp).await?;
        stream.send_data(Bytes::from(response_body)).await?;
        stream.finish().await?;
    }

    Ok(())
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
fn build_h3_backend_headers(
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    headers: &HashMap<String, String>,
    client_ip: &str,
    state: &ProxyState,
) -> Vec<(http::header::HeaderName, http::header::HeaderValue)> {
    let mut h3_headers = Vec::with_capacity(headers.len() + 5);

    let effective_backend_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(proxy.backend_host.as_str());

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
            "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
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

    // X-Forwarded-For
    let xff = if let Some(existing) = headers.get("x-forwarded-for") {
        format!("{}, {}", existing, client_ip)
    } else {
        client_ip.to_string()
    };
    if let Ok(val) = http::header::HeaderValue::from_str(&xff) {
        h3_headers.push((
            http::header::HeaderName::from_static("x-forwarded-for"),
            val,
        ));
    }

    // X-Forwarded-Proto
    h3_headers.push((
        http::header::HeaderName::from_static("x-forwarded-proto"),
        http::header::HeaderValue::from_static("h3"),
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
        let fwd = crate::proxy::build_forwarded_value(client_ip, "h3", host);
        if let Ok(val) = http::header::HeaderValue::from_str(&fwd) {
            h3_headers.push((http::header::HeaderName::from_static("forwarded"), val));
        }
    }

    h3_headers
}

/// Classify an h3/quinn error into an `ErrorClass` for retry and CB recording.
/// Inject a sticky-session `Set-Cookie` header when the LB strategy is cookie-based
/// and the cookie was not present in the original request.
pub(crate) fn inject_sticky_cookie(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    sticky_cookie_needed: bool,
    response_headers: &mut HashMap<String, String>,
) {
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target)
    {
        let strategy = state.load_balancer_cache.get_hash_on_strategy(upstream_id);
        if let crate::load_balancer::HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = state.load_balancer_cache.get_upstream(upstream_id);
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
        }
    }
}

fn classify_h3_error(e: &crate::http3::client::H3PoolError) -> crate::retry::ErrorClass {
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
/// all outcome fields at the same synchronous point in the code — no
/// re-derivation of latency fields is needed because the "now" at summary
/// construction time already coincides with body completion.
struct H3StreamResult {
    status: u16,
    error_class: Option<crate::retry::ErrorClass>,
    body_completed: bool,
    bytes_streamed: u64,
    client_disconnected: bool,
    body_error_class: Option<crate::retry::ErrorClass>,
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
    upstream_target: Option<&UpstreamTarget>,
    sticky_cookie_needed: bool,
    h3_stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    plugin_execution_ns: &mut u64,
) -> Result<H3StreamResult, anyhow::Error> {
    let h3_headers = build_h3_backend_headers(proxy, upstream_target, headers, client_ip, state);
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
            let h3_error_class = classify_h3_error(&e);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            let h3_error_body = if h3_error_class == crate::retry::ErrorClass::DnsLookupError {
                r#"{"error":"DNS resolution for backend failed"}"#
            } else {
                r#"{"error":"Backend unavailable"}"#
            };
            send_h3_response(h3_stream, StatusCode::BAD_GATEWAY, h3_error_body).await?;
            return Ok(H3StreamResult {
                status: 502,
                error_class: Some(h3_error_class),
                body_completed: false,
                bytes_streamed: 0,
                client_disconnected: false,
                body_error_class: None,
            });
        }
    };

    let response_status = h3_resp.status;
    let mut response_headers = h3_resp.headers;

    // Strip hop-by-hop headers from backend responses per RFC 9110 §7.6.1
    for key in &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        response_headers.remove(*key);
    }

    // Enforce response body size limit via Content-Length fast path
    if state.max_response_body_size_bytes > 0
        && let Some(len) = response_headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        && len > state.max_response_body_size_bytes
    {
        warn!(
            "Backend response body ({} bytes) exceeds limit ({} bytes)",
            len, state.max_response_body_size_bytes
        );
        send_h3_response(
            h3_stream,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"Backend response body exceeds maximum size"}"#,
        )
        .await?;
        return Ok(H3StreamResult {
            status: 502,
            error_class: Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: false,
            body_error_class: None,
        });
    }

    // after_proxy hooks (run before streaming begins so headers can be modified)
    {
        let phase_start = std::time::Instant::now();
        for plugin in plugins.iter() {
            let _ = plugin
                .after_proxy(ctx, response_status, &mut response_headers)
                .await;
        }
        *plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;
    }

    // Sticky session cookie injection
    inject_sticky_cookie(
        state,
        proxy,
        upstream_target,
        sticky_cookie_needed,
        &mut response_headers,
    );

    // Send response headers on the H3 stream
    let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_builder = Response::builder().status(status);
    for (k, v) in &response_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            resp_builder = resp_builder.header(name, val);
        }
    }
    if !response_headers.contains_key("content-type") {
        resp_builder = resp_builder.header("content-type", "application/json");
    }

    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
    if h3_stream.send_response(resp).await.is_err() {
        // Client QUIC stream is already gone — nothing streamed.
        return Ok(H3StreamResult {
            status: response_status,
            error_class: None,
            body_completed: false,
            bytes_streamed: 0,
            client_disconnected: true,
            body_error_class: Some(crate::retry::ErrorClass::ClientDisconnect),
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
    let mut stream_done = false;
    let mut bytes_streamed: u64 = 0;
    let mut client_disconnected = false;
    let mut body_completed = false;
    let mut body_error_class: Option<crate::retry::ErrorClass> = None;
    let mut terminal_error_class: Option<crate::retry::ErrorClass> = None;

    'outer: loop {
        tokio::select! {
            chunk_result = h3_resp.recv_stream.recv_data(), if !stream_done => {
                match chunk_result {
                    Ok(Some(chunk)) => {
                        let chunk_bytes = chunk.chunk();
                        if state.max_response_body_size_bytes > 0 {
                            total_streamed += chunk_bytes.len();
                            if total_streamed > state.max_response_body_size_bytes {
                                warn!(
                                    "Backend response exceeded {} byte limit during streaming",
                                    state.max_response_body_size_bytes
                                );
                                let _ = h3_stream.finish().await;
                                terminal_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                                body_error_class = Some(crate::retry::ErrorClass::ResponseBodyTooLarge);
                                break 'outer;
                            }
                        }

                        coalesce_buf.extend_from_slice(chunk_bytes);

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
                        error!("Error reading backend h3 response during streaming: {}", e);
                        if !coalesce_buf.is_empty() {
                            let data = coalesce_buf.split().freeze();
                            let data_len = data.len() as u64;
                            if h3_stream.send_data(data).await.is_ok() {
                                bytes_streamed += data_len;
                            }
                        }
                        let _ = h3_stream.finish().await;
                        let class = crate::http3::client::classify_http3_error(&e);
                        terminal_error_class = Some(class);
                        body_error_class = Some(class);
                        break 'outer;
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
            match h3_stream.finish().await {
                Ok(_) => body_completed = true,
                Err(_) => {
                    client_disconnected = true;
                    body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect);
                }
            }
            break;
        }
    }

    Ok(H3StreamResult {
        status: response_status,
        error_class: terminal_error_class,
        body_completed,
        bytes_streamed,
        client_disconnected,
        body_error_class,
    })
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
    upstream_target: Option<&UpstreamTarget>,
) -> (
    u16,
    Vec<u8>,
    HashMap<String, String>,
    Option<crate::retry::ErrorClass>,
) {
    let h3_headers = build_h3_backend_headers(proxy, upstream_target, headers, client_ip, state);
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
        Ok((status, resp_body, resp_headers)) => {
            // Hop-by-hop headers already filtered during collection in the H3 pool.

            // Enforce response body size limit
            if state.max_response_body_size_bytes > 0
                && resp_body.len() > state.max_response_body_size_bytes
            {
                warn!(
                    "Backend response body ({} bytes) exceeds limit ({} bytes)",
                    resp_body.len(),
                    state.max_response_body_size_bytes
                );
                return (
                    502,
                    r#"{"error":"Backend response body exceeds maximum size"}"#
                        .as_bytes()
                        .to_vec(),
                    HashMap::new(),
                    Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                );
            }

            (status, resp_body, resp_headers, None)
        }
        Err(e) => {
            error!(
                "Backend request failed (HTTP/3 frontend): connection error details: {}",
                e
            );
            let h3_error_class = classify_h3_error(&e);
            if crate::proxy::is_h3_transport_error_class(h3_error_class) {
                state
                    .backend_capabilities
                    .mark_h3_unsupported(proxy, upstream_target);
            }
            let error_body: &[u8] = if h3_error_class == crate::retry::ErrorClass::DnsLookupError {
                br#"{"error":"DNS resolution for backend failed"}"#
            } else {
                br#"{"error":"Backend unavailable"}"#
            };
            (
                502,
                error_body.to_vec(),
                HashMap::new(),
                Some(h3_error_class),
            )
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
    crate::http3::stream_util::halt_request_body(stream);
    Ok(())
}

/// Send an HTTP/3 rejection response with custom headers. Same recv-half
/// halt contract as `send_h3_response`.
async fn send_h3_reject_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: &[u8],
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, val);
        }
    }
    let resp = builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 reject response: {}", e))?;
    stream.send_response(resp).await?;
    stream.send_data(Bytes::copy_from_slice(body)).await?;
    stream.finish().await?;
    crate::http3::stream_util::halt_request_body(stream);
    Ok(())
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
) -> Result<(), anyhow::Error> {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", grpc_status.to_string())
        .header("grpc-message", grpc_message)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC error response: {}", e))?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    crate::http3::stream_util::halt_request_body(stream);
    Ok(())
}

/// Flavor-aware rejection for H3. When the request is gRPC, emits a
/// trailers-only gRPC error so the client receives a valid
/// `grpc-status` / `grpc-message` response. Otherwise emits the standard
/// HTTP/JSON error body. `grpc_message` is used only for the gRPC path;
/// `http_body` is used only for the Plain/WebSocket path.
async fn send_h3_error_flavor_aware(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    flavor: HttpFlavor,
    http_status: StatusCode,
    http_body: &str,
    grpc_status: u32,
    grpc_message: &str,
) -> Result<(), anyhow::Error> {
    if matches!(flavor, HttpFlavor::Grpc) {
        send_h3_grpc_error(stream, grpc_status, grpc_message).await
    } else {
        send_h3_response(stream, http_status, http_body).await
    }
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
    http_body: &[u8],
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    if !matches!(flavor, HttpFlavor::Grpc) {
        return send_h3_reject_response(stream, http_status, http_body, headers).await;
    }

    // gRPC flavor only — derive signalling now.
    let grpc_status = h3_http_status_to_grpc_status(http_status);
    let grpc_message = reject_body_as_grpc_message(http_body, http_status);

    // Build a trailers-only gRPC error that preserves any custom headers
    // the plugin attached (e.g., rate-limit metadata), while forcing the
    // gRPC signalling headers to match.
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/grpc");
    for (k, v) in headers {
        // `eq_ignore_ascii_case` avoids the `to_ascii_lowercase` String
        // allocation that was previously executed per header.
        if k.eq_ignore_ascii_case("content-type")
            || k.eq_ignore_ascii_case("grpc-status")
            || k.eq_ignore_ascii_case("grpc-message")
        {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, val);
        }
    }
    let resp = builder
        .header("grpc-status", grpc_status.to_string())
        .header("grpc-message", grpc_message.as_ref())
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 gRPC reject response: {}", e))?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    crate::http3::stream_util::halt_request_body(stream);
    Ok(())
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

/// Map an HTTP status we would have emitted (e.g., 413, 404, 400) to the
/// matching gRPC status code. Duplicated from `proxy/mod.rs::map_http_reject_status_to_grpc_status`
/// to avoid promoting the original across module boundaries — this is a
/// pure, trivial mapping and the H3 server needs a local version anyway
/// because it's called from the admission path, not the dispatch path.
pub(crate) fn h3_http_status_to_grpc_status(status: StatusCode) -> u32 {
    use crate::proxy::grpc_proxy::grpc_status;
    match status {
        StatusCode::BAD_REQUEST => grpc_status::INVALID_ARGUMENT,
        StatusCode::METHOD_NOT_ALLOWED => grpc_status::UNIMPLEMENTED,
        StatusCode::UNAUTHORIZED => grpc_status::UNAUTHENTICATED,
        StatusCode::FORBIDDEN => grpc_status::PERMISSION_DENIED,
        StatusCode::NOT_FOUND => grpc_status::NOT_FOUND,
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => grpc_status::DEADLINE_EXCEEDED,
        StatusCode::CONFLICT => grpc_status::ABORTED,
        StatusCode::PRECONDITION_FAILED => grpc_status::FAILED_PRECONDITION,
        StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::URI_TOO_LONG
        | StatusCode::TOO_MANY_REQUESTS => grpc_status::RESOURCE_EXHAUSTED,
        StatusCode::NOT_IMPLEMENTED => grpc_status::UNIMPLEMENTED,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => grpc_status::UNAVAILABLE,
        StatusCode::TOO_EARLY => grpc_status::UNAVAILABLE,
        _ => grpc_status::INTERNAL,
    }
}

fn strip_query_params(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
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
}
