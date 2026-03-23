//! HTTP/3 server listener using Quinn (QUIC) and h3

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{debug, error, info, warn};

use super::config::Http3ServerConfig;
use crate::config::types::{AuthMode, Proxy};
use crate::plugins::{Plugin, PluginResult, RequestContext, TransactionSummary};
use crate::proxy::ProxyState;
use crate::tls::TlsPolicy;

/// Start the HTTP/3 (QUIC) proxy listener.
///
/// HTTP/3 (QUIC) mandates TLS 1.3. If the provided TLS policy does not include
/// TLS 1.3, this function will override it to force TLS 1.3 for the QUIC listener
/// and log a warning.
pub async fn start_http3_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Arc<rustls::ServerConfig>,
    h3_config: Http3ServerConfig,
    tls_policy: &TlsPolicy,
) -> Result<(), anyhow::Error> {
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

    // Reuse the cert chain and key from the original config
    // We need to clone the certified key from the original config
    let mut server_tls_config = h3_builder
        .with_no_client_auth()
        .with_cert_resolver(tls_config.cert_resolver.clone());

    server_tls_config.alpn_protocols = vec![b"h3".to_vec()];
    // 0-RTT is disabled for security: early data is replayable, which is dangerous
    // for non-idempotent operations proxied through an API gateway.
    server_tls_config.max_early_data_size = 0;

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

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("HTTP/3 (QUIC) listener started on {}", addr);

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

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, state, remote_addr).await
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
) -> Result<(), anyhow::Error> {
    let start_time = std::time::Instant::now();

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    let socket_ip = remote_addr.ip().to_string();

    // Build request context (client_ip resolved below after headers are parsed)
    let mut ctx = RequestContext::new(socket_ip.clone(), method.clone(), path.clone());

    // Validate and extract headers with size limits
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
            ctx.headers
                .insert(name.as_str().to_lowercase(), v.to_string());
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

    // Resolve real client IP using trusted proxy configuration
    if !state.trusted_proxies.is_empty() {
        let resolved = if let Some(ref real_ip_header) = state.env_config.real_ip_header {
            let header_val = ctx.headers.get(&real_ip_header.to_lowercase());
            if let Some(val) = header_val {
                let socket_addr: Option<std::net::IpAddr> = socket_ip.parse().ok();
                if socket_addr.is_some_and(|ip| state.trusted_proxies.contains(&ip)) {
                    val.trim().to_string()
                } else {
                    crate::proxy::client_ip::resolve_client_ip(
                        &socket_ip,
                        ctx.headers.get("x-forwarded-for").map(|s| s.as_str()),
                        &state.trusted_proxies,
                    )
                }
            } else {
                crate::proxy::client_ip::resolve_client_ip(
                    &socket_ip,
                    ctx.headers.get("x-forwarded-for").map(|s| s.as_str()),
                    &state.trusted_proxies,
                )
            }
        } else {
            crate::proxy::client_ip::resolve_client_ip(
                &socket_ip,
                ctx.headers.get("x-forwarded-for").map(|s| s.as_str()),
                &state.trusted_proxies,
            )
        };
        ctx.client_ip = resolved;
    }

    // Parse query params
    for pair in query_string.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            ctx.query_params.insert(k.to_string(), v.to_string());
        }
    }

    // Route: longest prefix match via router cache
    let matched_proxy = state.router_cache.find_proxy(&path);

    let proxy = match matched_proxy {
        Some(p) => p,
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

    // Get pre-resolved plugins from cache (O(1) lookup)
    let plugins = state.plugin_cache.get_plugins(&proxy.id);

    // Execute on_request_received hooks
    for plugin in plugins.iter() {
        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                record_request(&state, status_code);
                send_h3_reject_response(
                    &mut stream,
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                    &headers,
                )
                .await?;
                return Ok(());
            }
            PluginResult::Continue => {}
        }
    }

    // Authentication phase
    let auth_plugins: Vec<&Arc<dyn Plugin>> =
        plugins.iter().filter(|p| p.is_auth_plugin()).collect();

    match proxy.auth_mode {
        AuthMode::Multi => {
            // Multi auth mode: try each auth plugin, first success wins
            let mut any_success = false;
            for auth_plugin in &auth_plugins {
                match auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await
                {
                    PluginResult::Continue => {
                        any_success = true;
                        break;
                    }
                    PluginResult::Reject { .. } => continue,
                }
            }
            if !any_success && !auth_plugins.is_empty() {
                // All auth plugins rejected — deny access
                record_request(&state, 401);
                let status = StatusCode::UNAUTHORIZED;
                let mut resp_builder = Response::builder().status(status);
                resp_builder = resp_builder.header("content-type", "application/json");
                let resp = match resp_builder.body(()) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to build HTTP/3 response: {}", e);
                        return Ok(());
                    }
                };
                stream.send_response(resp).await?;
                stream
                    .send_data(Bytes::from(r#"{"error":"Unauthorized"}"#.as_bytes()))
                    .await?;
                stream.finish().await?;
                return Ok(());
            }
        }
        AuthMode::Single => {
            for auth_plugin in &auth_plugins {
                match auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await
                {
                    PluginResult::Reject {
                        status_code,
                        body,
                        headers,
                    } => {
                        record_request(&state, status_code);
                        send_h3_reject_response(
                            &mut stream,
                            StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
                            &body,
                            &headers,
                        )
                        .await?;
                        return Ok(());
                    }
                    PluginResult::Continue => {}
                }
            }
        }
    }

    // Authorization phase
    for plugin in plugins.iter() {
        if plugin.name() == "access_control" {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    record_request(&state, status_code);
                    send_h3_reject_response(
                        &mut stream,
                        StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN),
                        &body,
                        &headers,
                    )
                    .await?;
                    return Ok(());
                }
                PluginResult::Continue => {}
            }
        }
    }

    // before_proxy hooks
    let mut proxy_headers = ctx.headers.clone();
    for plugin in plugins.iter() {
        match plugin.before_proxy(&mut ctx, &mut proxy_headers).await {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                record_request(&state, status_code);
                send_h3_reject_response(
                    &mut stream,
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                    &headers,
                )
                .await?;
                return Ok(());
            }
            PluginResult::Continue => {}
        }
    }

    // Enforce request body size limit via Content-Length fast path
    if state.max_body_size_bytes > 0
        && let Some(content_length) = ctx.headers.get("content-length")
        && let Ok(len) = content_length.parse::<usize>()
        && len > state.max_body_size_bytes
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

    // Collect request body from the H3 stream with size limit
    let mut body_data = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let bytes = chunk.chunk();
        if state.max_body_size_bytes > 0
            && body_data.len() + bytes.len() > state.max_body_size_bytes
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

    // Build backend URL and proxy
    let backend_url = crate::proxy::build_backend_url(&proxy, &path, &query_string);
    let backend_start = std::time::Instant::now();

    let (response_status, response_body, mut response_headers) = proxy_to_backend_h3(
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

    // after_proxy hooks
    for plugin in plugins.iter() {
        let _ = plugin
            .after_proxy(&mut ctx, response_status, &mut response_headers)
            .await;
    }

    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let gateway_processing_ms = total_ms - backend_total_ms;

    // Build transaction summary for logging
    let summary = TransactionSummary {
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.identified_consumer.as_ref().map(|c| c.username.clone()),
        http_method: method,
        request_path: path,
        matched_proxy_id: Some(proxy.id.clone()),
        matched_proxy_name: proxy.name.clone(),
        backend_target_url: Some(strip_query_params(&backend_url)),
        response_status_code: response_status,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: gateway_processing_ms,
        latency_backend_ttfb_ms: backend_ttfb_ms,
        latency_backend_total_ms: backend_total_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: false,
        client_disconnected: false,
        metadata: ctx.metadata.clone(),
    };

    // Log phase
    for plugin in plugins.iter() {
        plugin.log(&summary).await;
    }

    record_request(&state, response_status);

    // Build and send response
    let status = StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_builder = Response::builder().status(status);

    for (k, v) in &response_headers {
        resp_builder = resp_builder.header(k.as_str(), v.as_str());
    }

    // Only add content-type if backend didn't provide one
    if !response_headers.contains_key("content-type") {
        resp_builder = resp_builder.header("content-type", "application/json");
    }

    let resp = resp_builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 proxy response: {}", e))?;
    stream.send_response(resp).await?;
    stream.send_data(Bytes::from(response_body)).await?;
    stream.finish().await?;

    Ok(())
}

/// Proxy a request to the backend (adapted for HTTP/3 — uses collected body bytes).
async fn proxy_to_backend_h3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &std::collections::HashMap<String, String>,
    body_bytes: Vec<u8>,
    client_ip: &str,
) -> (u16, Vec<u8>, std::collections::HashMap<String, String>) {
    // Get client from connection pool (uses DnsCacheResolver for DNS lookups)
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(
                    proxy.backend_connect_timeout_ms,
                ))
                .timeout(std::time::Duration::from_millis(
                    proxy.backend_read_timeout_ms,
                ))
                .danger_accept_invalid_certs(!proxy.backend_tls_verify_server_cert)
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
            "connection" | "transfer-encoding" => continue,
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
            let mut resp_headers = std::collections::HashMap::new();
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
                    );
                }

                // Stream-collect with size limit
                let max_size = state.max_response_body_size_bytes;
                match collect_response_with_limit_h3(response, max_size).await {
                    Ok((resp_body, _)) => (status, resp_body, resp_headers),
                    Err(err_body) => (502, err_body, std::collections::HashMap::new()),
                }
            } else {
                let body = response.bytes().await.unwrap_or_default().to_vec();
                (status, body, resp_headers)
            }
        }
        Err(e) => {
            error!(
                "Backend request failed (HTTP/3 frontend): connection error details: {}",
                e
            );
            let error_msg = serde_json::json!({"error": "Backend unavailable"});
            (
                502,
                error_msg.to_string().into_bytes(),
                std::collections::HashMap::new(),
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
    body: &str,
    headers: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 reject response: {}", e))?;
    stream.send_response(resp).await?;
    stream.send_data(Bytes::from(body.to_string())).await?;
    stream.finish().await?;
    Ok(())
}

fn strip_query_params(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
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
