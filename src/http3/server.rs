//! HTTP/3 server listener using Quinn (QUIC) and h3.
//!
//! Runs as a standalone QUIC server alongside the main hyper-based HTTP server.
//! Handles its own request lifecycle (route matching, plugin phases, auth) but
//! uses **reqwest** (not the `Http3ConnectionPool`) for backend communication.
//! This is intentional — reqwest auto-negotiates HTTP/2 via ALPN which outperforms
//! QUIC for small payloads due to lower per-request crypto overhead and more
//! mature connection pooling.
//!
//! QUIC requires TLS 1.3 exclusively (RFC 9001), so the server forces TLS 1.3
//! and uses a separate ALPN advertisement (`h3`). 0-RTT is disabled for replay
//! safety, but stateless session ticket resumption is enabled (saves 1 RTT on
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
use crate::config::types::Proxy;
use crate::dns::DnsCacheResolver;
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
    // 0-RTT is disabled for security: early data is replayable, which is dangerous
    // for non-idempotent operations proxied through an API gateway.
    server_tls_config.max_early_data_size = 0;

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
                        let state = state.clone();
                        tokio::spawn(async move {
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
    let connection = connecting.await?;
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

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    // Pre-format socket IP string once per connection — shared across all streams
    // to avoid per-request String allocation from SocketAddr::ip().to_string().
    let socket_ip: Arc<str> = Arc::from(remote_addr.ip().to_string());

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                let cert = client_cert_der.clone();
                let chain = client_cert_chain_der.clone();
                let socket_ip = Arc::clone(&socket_ip);
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(
                                req,
                                stream,
                                state,
                                remote_addr,
                                &socket_ip,
                                cert,
                                chain,
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
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: ProxyState,
    remote_addr: SocketAddr,
    socket_ip: &str,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
) -> Result<(), anyhow::Error> {
    let start_time = std::time::Instant::now();

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    // Build request context (client_ip resolved below after headers are parsed)
    let mut ctx = RequestContext::new(socket_ip.to_owned(), method.clone(), path.clone());
    ctx.tls_client_cert_der = tls_client_cert_der;
    ctx.tls_client_cert_chain_der = tls_client_cert_chain_der;

    // Validate and extract headers with size limits
    ctx.headers.reserve(req.headers().keys_len());
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_request(&state, 431);
            send_h3_response(
                &mut stream,
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                &format!(
                    r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                    name.as_str(),
                    state.max_single_header_size_bytes
                ),
            )
            .await?;
            return Ok(());
        }
        total_header_size += header_size;
        if let Ok(v) = value.to_str() {
            // http::HeaderName stores names in lowercase already (per HTTP/2+3 spec),
            // so .as_str() returns lowercase — no need for .to_lowercase().
            ctx.headers.insert(name.as_str().to_owned(), v.to_string());
        }
    }
    if total_header_size > state.max_header_size_bytes {
        record_request(&state, 431);
        send_h3_response(
            &mut stream,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
        )
        .await?;
        return Ok(());
    }
    if state.max_header_count > 0 && req.headers().len() > state.max_header_count {
        record_request(&state, 431);
        send_h3_response(
            &mut stream,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &format!(
                r#"{{"error":"Request header count ({}) exceeds maximum of {}"}}"#,
                req.headers().len(),
                state.max_header_count
            ),
        )
        .await?;
        return Ok(());
    }

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
            send_h3_response(
                &mut stream,
                StatusCode::URI_TOO_LONG,
                &format!(
                    r#"{{"error":"Request URL length ({} bytes) exceeds maximum of {} bytes"}}"#,
                    url_len, state.max_url_length_bytes
                ),
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
            send_h3_response(
                &mut stream,
                StatusCode::BAD_REQUEST,
                &format!(
                    r#"{{"error":"Query parameter count ({}) exceeds maximum of {}"}}"#,
                    param_count, state.max_query_params
                ),
            )
            .await?;
            return Ok(());
        }
    }

    // Resolve real client IP using trusted proxy configuration.
    // Parse socket IP once upfront to avoid redundant parsing in each branch.
    if !state.trusted_proxies.is_empty() {
        let socket_addr: std::net::IpAddr = remote_addr.ip();
        let xff = ctx.headers.get("x-forwarded-for").map(|s| s.as_str());
        let resolved = if let Some(ref real_ip_header) = state.env_config.real_ip_header {
            // real_ip_header is already lowercase from env config parsing
            let header_val = ctx.headers.get(real_ip_header.as_str());
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

    // Parse query params
    if !query_string.is_empty() {
        for pair in query_string.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                ctx.query_params.insert(k.to_string(), v.to_string());
            }
        }
    }

    // Extract request host for host-based routing.
    // HTTP/3 uses the :authority pseudo-header (from URI authority).
    // Also check the host header as a fallback. Strip port and lowercase.
    let request_host: Option<String> = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| ctx.headers.get("host").map(|h| h.as_str()))
        .map(|h| {
            let without_port = h.split(':').next().unwrap_or(h);
            without_port.to_lowercase()
        });

    // Route: host + longest prefix match via router cache
    let route_match = state
        .router_cache
        .find_proxy(request_host.as_deref(), &path);

    let proxy = match route_match {
        Some(rm) => {
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
            send_h3_response(
                &mut stream,
                StatusCode::NOT_FOUND,
                r#"{"error":"Not Found"}"#,
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
        send_h3_reject_response(
            &mut stream,
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"Method Not Allowed"}"#.as_bytes(),
            &headers,
        )
        .await?;
        return Ok(());
    }

    // Get pre-resolved plugins filtered for HTTP protocol (O(1) lookup)
    let plugins = state
        .plugin_cache
        .get_plugins_for_protocol(&proxy.id, ProxyProtocol::Http);

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
                send_h3_reject_response(
                    &mut stream,
                    StatusCode::from_u16(reject.status_code)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &reject.body,
                    &headers,
                )
                .await?;
                return Ok(());
            }
        }
    }
    plugin_execution_ns += phase_start.elapsed().as_nanos() as u64;

    // Authentication phase
    let auth_plugins: Vec<&Arc<dyn Plugin>> =
        plugins.iter().filter(|p| p.is_auth_plugin()).collect();

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
        send_h3_reject_response(
            &mut stream,
            StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
            &body,
            &headers,
        )
        .await?;
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
                        send_h3_reject_response(
                            &mut stream,
                            StatusCode::from_u16(reject.status_code)
                                .unwrap_or(StatusCode::FORBIDDEN),
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
        && plugins.iter().any(|plugin| {
            plugin.requires_request_body_before_before_proxy()
                && plugin.should_buffer_request_body(&ctx)
        });

    let mut prebuffered_body_data = if needs_request_body_before_before_proxy {
        let mut body_data = Vec::new();
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
        crate::proxy::store_request_body_metadata(&mut ctx, &body_data);
        Some(body_data)
    } else {
        None
    };

    // before_proxy hooks — only clone headers if at least one plugin modifies them.
    // When no plugin modifies headers, use std::mem::take to avoid a per-request HashMap clone.
    let needs_header_clone =
        !plugins.is_empty() && plugins.iter().any(|p| p.modifies_request_headers());
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
                    send_h3_reject_response(
                        &mut stream,
                        StatusCode::from_u16(reject.status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
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
                    send_h3_reject_response(
                        &mut stream,
                        StatusCode::from_u16(reject.status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
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

    // Enforce request body size limit via Content-Length fast path
    if state.max_request_body_size_bytes > 0
        && let Some(content_length) = proxy_headers.get("content-length")
        && let Ok(len) = content_length.parse::<usize>()
        && len > state.max_request_body_size_bytes
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

    // Determine streaming vs buffered mode — same logic as HTTP/1.1 and gRPC paths.
    // Stream by default; buffer only when plugins need to inspect/modify the body
    // or when retries are configured (need to replay the request body).
    let has_retry = proxy.retry.is_some();
    let needs_request_buffering = has_retry || plugin_needs_request_buffering;
    let needs_response_buffering = has_retry
        || state
            .plugin_cache
            .requires_response_body_buffering(&proxy.id);

    // Build backend URL
    let backend_url =
        crate::proxy::build_backend_url(&proxy, &path, &query_string, proxy.listen_path.len());
    let backend_start = std::time::Instant::now();

    // --- Collect request body (always needed; stream to backend when possible) ---
    // When request buffering is needed, we collect into Vec<u8> for plugin transforms
    // and potential retry replay. Otherwise we still collect for reqwest but avoid
    // plugin body transforms.
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

    // Transform request body via plugins when buffering is active
    let body_data = if needs_request_buffering
        && !body_data.is_empty()
        && plugins.iter().any(|p| p.modifies_request_body())
    {
        let content_type = proxy_headers.get("content-type").map(|s| s.as_str());
        let mut current = body_data;
        for plugin in plugins.iter() {
            if plugin.modifies_request_body()
                && let Some(transformed) =
                    plugin.transform_request_body(&current, content_type).await
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

    if !needs_response_buffering {
        // ===== STREAMING RESPONSE PATH =====
        // Stream response body chunks from backend directly to the H3 client
        // without collecting them in memory. This is the fast path.
        let client_ip_owned = ctx.client_ip.clone();
        let streaming_result = proxy_to_backend_h3_streaming(
            &state,
            &proxy,
            &backend_url,
            &method,
            &proxy_headers,
            body_data,
            &client_ip_owned,
            &mut stream,
            &plugins,
            &mut ctx,
            &mut plugin_execution_ns,
        )
        .await;

        let (response_status, _response_headers, h3_error_class) = match streaming_result {
            Ok(result) => result,
            Err(e) => {
                // Stream may already have partial data sent — log and return
                debug!("HTTP/3 streaming proxy error: {}", e);
                return Err(e);
            }
        };

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

        let h3_resolved_ip = state
            .dns_cache
            .resolve(
                &proxy.backend_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .ok()
            .map(|ip| ip.to_string());

        let summary = TransactionSummary {
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            http_method: method,
            request_path: path,
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip: h3_resolved_ip,
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
            client_disconnected: false,
            error_class: h3_error_class,
            metadata: ctx.metadata.clone(),
        };

        for plugin in plugins.iter() {
            plugin.log(&summary).await;
        }

        record_request(&state, response_status);
    } else {
        // ===== BUFFERED RESPONSE PATH =====
        // Collect full response for plugin body inspection/transformation and retries.
        let (mut response_status, response_body, mut response_headers, h3_error_class) =
            proxy_to_backend_h3(
                &state,
                &proxy,
                &backend_url,
                &method,
                &proxy_headers,
                body_data,
                &ctx.client_ip,
            )
            .await;

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
                if let Some(transformed) =
                    plugin.transform_response_body(&response_body, ct_ref).await
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

        let h3_resolved_ip = state
            .dns_cache
            .resolve(
                &proxy.backend_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .ok()
            .map(|ip| ip.to_string());

        let summary = TransactionSummary {
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            http_method: method,
            request_path: path,
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip: h3_resolved_ip,
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: proxy_headers.get("user-agent").cloned(),
            response_streamed: false,
            client_disconnected: false,
            error_class: h3_error_class,
            metadata: ctx.metadata.clone(),
        };

        for plugin in plugins.iter() {
            plugin.log(&summary).await;
        }

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

/// Minimum coalescing threshold for QUIC DATA frames. Small frames add per-frame
/// overhead (QUIC packet headers, HTTP/3 frame headers). Buffering until we have
/// at least this many bytes amortises the overhead. 8 KiB is the lower bound of
/// the optimal 8–32 KiB range for typical QUIC path MTUs (~1200 bytes).
const H3_COALESCE_MIN_BYTES: usize = 8_192;

/// Maximum coalescing buffer size. Even if data arrives fast, we flush at this
/// threshold to bound per-stream memory and avoid introducing latency.
const H3_COALESCE_MAX_BYTES: usize = 32_768;

/// Time-based flush interval. If the coalescing buffer has data but hasn't
/// reached the size threshold, flush after this duration to avoid stalling
/// small or tail responses. 2ms balances latency vs frame efficiency.
const H3_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);

/// Streaming proxy path: sends backend response chunks directly to the H3 client
/// as they arrive, without collecting the full body in memory. Returns the status,
/// final response headers, and error class after the stream completes.
///
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
    h3_stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    plugin_execution_ns: &mut u64,
) -> Result<
    (
        u16,
        HashMap<String, String>,
        Option<crate::retry::ErrorClass>,
    ),
    anyhow::Error,
> {
    // Build the backend request (same client/header logic as buffered path)
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            let resolver = DnsCacheResolver::new(state.dns_cache.clone());
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(
                    proxy.backend_connect_timeout_ms,
                ))
                .timeout(std::time::Duration::from_millis(
                    proxy.backend_read_timeout_ms,
                ))
                .danger_accept_invalid_certs(
                    !proxy.backend_tls_verify_server_cert || state.env_config.tls_no_verify,
                )
                .dns_resolver(Arc::new(resolver))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        }
    };

    let req_method = match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("HTTP/3: Unsupported HTTP method: {}", other);
                // Send 405 error directly on the h3 stream
                send_h3_response(
                    h3_stream,
                    StatusCode::METHOD_NOT_ALLOWED,
                    r#"{"error":"Method not allowed"}"#,
                )
                .await?;
                return Ok((405, HashMap::new(), None));
            }
        },
    };

    let mut req_builder = client.request(req_method, backend_url);

    for (k, v) in headers {
        match k.as_str() {
            "host" | ":authority" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    req_builder = req_builder.header("Host", &proxy.backend_host);
                }
            }
            "connection" | "content-length" | "transfer-encoding" => continue,
            k if k.starts_with(':') => continue,
            _ => {
                req_builder = req_builder.header(k, v.as_str());
            }
        }
    }

    if let Some(xff) = headers.get("x-forwarded-for") {
        req_builder = req_builder.header("X-Forwarded-For", format!("{}, {}", xff, client_ip));
    } else {
        req_builder = req_builder.header("X-Forwarded-For", client_ip);
    }
    req_builder = req_builder.header("X-Forwarded-Proto", "h3");
    if let Some(host) = headers.get("host").or_else(|| headers.get(":authority")) {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    let response = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Backend request failed (HTTP/3 streaming): {}", e);
            let h3_error_class = crate::retry::classify_reqwest_error(&e);
            let h3_error_body = if h3_error_class == crate::retry::ErrorClass::DnsLookupError {
                r#"{"error":"DNS resolution for backend failed"}"#
            } else {
                r#"{"error":"Backend unavailable"}"#
            };
            send_h3_response(h3_stream, StatusCode::BAD_GATEWAY, h3_error_body).await?;
            return Ok((502, HashMap::new(), Some(h3_error_class)));
        }
    };

    let response_status = response.status().as_u16();
    let mut response_headers = HashMap::with_capacity(response.headers().keys_len());
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            response_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    // Enforce response body size limit via Content-Length fast path
    if state.max_response_body_size_bytes > 0
        && let Some(len) = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
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
        return Ok((
            502,
            HashMap::new(),
            Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
        ));
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
    // Remove content-length for streaming — we don't know final size
    // (backend may use chunked encoding or we may not have Content-Length)

    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 streaming response: {}", e))?;
    h3_stream.send_response(resp).await?;

    // Stream response body chunks with adaptive coalescing and time-based flushing.
    //
    // Design (backpressure-aware):
    //   Backend stream → adaptive coalescing buffer (BytesMut)
    //     → flush policy: size threshold | time threshold | FIN
    //       → send_data() (await respects QUIC flow control / backpressure)
    //         → QUIC stream
    //
    // Key properties:
    //   - send_data().await blocks when QUIC stream/connection window is exhausted,
    //     which naturally stops us from reading more upstream data (backpressure).
    //   - Time-based flush (H3_FLUSH_INTERVAL) prevents latency stalls on small
    //     or tail chunks that don't reach the size threshold.
    //   - Adaptive threshold: flush at H3_COALESCE_MIN_BYTES normally, but cap
    //     at H3_COALESCE_MAX_BYTES to bound per-stream memory.
    use futures_util::StreamExt as _;
    let mut byte_stream = response.bytes_stream();
    let mut coalesce_buf = BytesMut::with_capacity(H3_COALESCE_MAX_BYTES);
    let mut total_streamed: usize = 0;
    let mut flush_deadline = tokio::time::Instant::now() + H3_FLUSH_INTERVAL;
    let mut stream_done = false;

    loop {
        // Backpressure-aware: we only read from upstream when we can send.
        // send_data().await blocks on QUIC flow control, which naturally
        // pauses our reads from the backend — no unbounded buffering.
        tokio::select! {
            chunk_opt = byte_stream.next(), if !stream_done => {
                match chunk_opt {
                    Some(Ok(chunk)) => {
                        // Enforce size limit during streaming
                        if state.max_response_body_size_bytes > 0 {
                            total_streamed += chunk.len();
                            if total_streamed > state.max_response_body_size_bytes {
                                warn!(
                                    "Backend response exceeded {} byte limit during streaming",
                                    state.max_response_body_size_bytes
                                );
                                h3_stream.finish().await?;
                                return Ok((
                                    response_status,
                                    response_headers,
                                    Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                                ));
                            }
                        }

                        coalesce_buf.extend_from_slice(&chunk);

                        // Flush when buffer reaches size threshold (adaptive: min to max range)
                        if coalesce_buf.len() >= H3_COALESCE_MIN_BYTES {
                            // split().freeze() is zero-copy: BytesMut → Bytes without realloc
                            let data = coalesce_buf.split().freeze();
                            h3_stream.send_data(data).await?;
                            flush_deadline = tokio::time::Instant::now() + H3_FLUSH_INTERVAL;
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading backend response during streaming: {}", e);
                        if !coalesce_buf.is_empty() {
                            let data = coalesce_buf.split().freeze();
                            let _ = h3_stream.send_data(data).await;
                        }
                        h3_stream.finish().await?;
                        return Ok((response_status, response_headers, None));
                    }
                    None => {
                        // Backend stream ended (FIN) — flush remaining and finish
                        stream_done = true;
                    }
                }
            }

            // Time-based flush: prevent latency stalls on small/tail chunks
            // that haven't reached the size threshold yet.
            _ = tokio::time::sleep_until(flush_deadline), if !coalesce_buf.is_empty() && !stream_done => {
                let data = coalesce_buf.split().freeze();
                h3_stream.send_data(data).await?;
                flush_deadline = tokio::time::Instant::now() + H3_FLUSH_INTERVAL;
            }
        }

        // After stream ends, flush any remaining bytes and send FIN
        if stream_done {
            if !coalesce_buf.is_empty() {
                let data = coalesce_buf.split().freeze();
                h3_stream.send_data(data).await?;
            }
            h3_stream.finish().await?;
            break;
        }
    }

    Ok((response_status, response_headers, None))
}

/// Proxy a request to the backend (buffered path — collects full response body).
async fn proxy_to_backend_h3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &std::collections::HashMap<String, String>,
    body_bytes: Vec<u8>,
    client_ip: &str,
) -> (
    u16,
    Vec<u8>,
    std::collections::HashMap<String, String>,
    Option<crate::retry::ErrorClass>,
) {
    // Get client from connection pool (uses DnsCacheResolver for DNS lookups)
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            let resolver = DnsCacheResolver::new(state.dns_cache.clone());
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(
                    proxy.backend_connect_timeout_ms,
                ))
                .timeout(std::time::Duration::from_millis(
                    proxy.backend_read_timeout_ms,
                ))
                .danger_accept_invalid_certs(
                    !proxy.backend_tls_verify_server_cert || state.env_config.tls_no_verify,
                )
                .dns_resolver(Arc::new(resolver))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        }
    };

    let req_method = match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("HTTP/3: Unsupported HTTP method: {}", other);
                return (
                    405,
                    r#"{"error":"Method not allowed"}"#.as_bytes().to_vec(),
                    HashMap::new(),
                    None,
                );
            }
        },
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers
    for (k, v) in headers {
        match k.as_str() {
            "host" | ":authority" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    req_builder = req_builder.header("Host", &proxy.backend_host);
                }
            }
            "connection" | "content-length" | "transfer-encoding" => continue,
            k if k.starts_with(':') => continue, // Skip HTTP/3 pseudo-headers
            _ => {
                req_builder = req_builder.header(k, v.as_str());
            }
        }
    }

    // Add proxy headers
    if let Some(xff) = headers.get("x-forwarded-for") {
        req_builder = req_builder.header("X-Forwarded-For", format!("{}, {}", xff, client_ip));
    } else {
        req_builder = req_builder.header("X-Forwarded-For", client_ip);
    }
    req_builder = req_builder.header("X-Forwarded-Proto", "h3");
    if let Some(host) = headers.get("host").or_else(|| headers.get(":authority")) {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers =
                std::collections::HashMap::with_capacity(response.headers().keys_len());
            for (k, v) in response.headers() {
                if let Ok(vs) = v.to_str() {
                    resp_headers.insert(k.as_str().to_string(), vs.to_string());
                }
            }

            // Enforce response body size limit
            if state.max_response_body_size_bytes > 0 {
                // Fast path: check Content-Length header from backend
                let content_length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());

                if let Some(len) = content_length
                    && len > state.max_response_body_size_bytes
                {
                    warn!(
                        "Backend response body ({} bytes) exceeds limit ({} bytes)",
                        len, state.max_response_body_size_bytes
                    );
                    return (
                        502,
                        r#"{"error":"Backend response body exceeds maximum size"}"#
                            .as_bytes()
                            .to_vec(),
                        std::collections::HashMap::new(),
                        Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                    );
                }

                // Stream-collect with size limit
                let max_size = state.max_response_body_size_bytes;
                match collect_response_with_limit_h3(response, max_size).await {
                    Ok((resp_body, _)) => (status, resp_body, resp_headers, None),
                    Err(err_body) => (
                        502,
                        err_body,
                        std::collections::HashMap::new(),
                        Some(crate::retry::ErrorClass::ResponseBodyTooLarge),
                    ),
                }
            } else {
                let body = match response.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!("Failed to read backend response body (HTTP/3): {}", e);
                        Vec::new()
                    }
                };
                (status, body, resp_headers, None)
            }
        }
        Err(e) => {
            error!(
                "Backend request failed (HTTP/3 frontend): connection error details: {}",
                e
            );
            let h3_error_class = crate::retry::classify_reqwest_error(&e);
            let error_text = if h3_error_class == crate::retry::ErrorClass::DnsLookupError {
                "DNS resolution for backend failed"
            } else {
                "Backend unavailable"
            };
            let error_msg = serde_json::json!({"error": error_text});
            (
                502,
                error_msg.to_string().into_bytes(),
                std::collections::HashMap::new(),
                Some(h3_error_class),
            )
        }
    }
}

/// Send an HTTP/3 response with a body.
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
    stream.send_data(Bytes::from(body.to_string())).await?;
    stream.finish().await?;
    Ok(())
}

/// Send an HTTP/3 rejection response with custom headers.
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
    Ok(())
}

fn strip_query_params(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn record_request(state: &ProxyState, status: u16) {
    use std::sync::atomic::{AtomicU64, Ordering};
    state.request_count.fetch_add(1, Ordering::Relaxed);
    state
        .status_counts
        .entry(status)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Collect a response body with a size limit, returning Err with error body if exceeded.
async fn collect_response_with_limit_h3(
    response: reqwest::Response,
    max_size: usize,
) -> Result<(Vec<u8>, usize), Vec<u8>> {
    use futures_util::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                if body.len() + chunk.len() > max_size {
                    warn!(
                        "Backend response truncated: exceeded {} byte limit",
                        max_size
                    );
                    return Err(r#"{"error":"Backend response body exceeds maximum size"}"#
                        .as_bytes()
                        .to_vec());
                }
                body.extend_from_slice(&chunk);
            }
            Err(e) => {
                error!("Error reading backend response: {}", e);
                let error_msg = serde_json::json!({"error": format!("Backend error: {}", e)});
                return Err(error_msg.to_string().into_bytes());
            }
        }
    }
    let len = body.len();
    Ok((body, len))
}
