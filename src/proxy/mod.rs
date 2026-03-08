use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, upgrade::OnUpgrade, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio_tungstenite::{tungstenite::handshake::derive_accept_key, WebSocketStream};
use tokio_tungstenite::tungstenite::protocol::{Message};
use tokio_tungstenite::connect_async;
use futures_util::{SinkExt, StreamExt};
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use crate::config::PoolConfig;
use crate::connection_pool::ConnectionPool;
use crate::dns::DnsCache;
use crate::plugins::{
    create_plugin, Plugin, PluginResult, RequestContext, TransactionSummary,
};

/// Check if the request is a WebSocket upgrade request
fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    let connection = headers.get("connection").and_then(|v| v.to_str().ok());
    let upgrade = headers.get("upgrade").and_then(|v| v.to_str().ok());
    let sec_key = headers.get("sec-websocket-key").and_then(|v| v.to_str().ok());
    let sec_version = headers.get("sec-websocket-version").and_then(|v| v.to_str().ok());

    connection.map_or(false, |conn| conn.to_lowercase().contains("upgrade"))
        && upgrade.map_or(false, |up| up.to_lowercase() == "websocket")
        && sec_key.is_some()
        && sec_version.map_or(false, |v| v == "13")
}

/// Shared state for the proxy engine.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub connection_pool: Arc<ConnectionPool>,
    pub request_count: Arc<AtomicU64>,
    pub status_counts: Arc<dashmap::DashMap<u16, AtomicU64>>,
}

impl ProxyState {
    pub fn new(config: GatewayConfig, dns_cache: DnsCache, env_config: crate::config::EnvConfig) -> Self {
        // Create connection pool with global configuration from environment
        let global_pool_config = PoolConfig::from_env();
        let connection_pool = Arc::new(ConnectionPool::new(global_pool_config, env_config));
        
        Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            dns_cache,
            connection_pool,
            request_count: Arc::new(AtomicU64::new(0)),
            status_counts: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn update_config(&self, new_config: GatewayConfig) {
        self.config.store(Arc::new(new_config));
        info!("Proxy configuration updated atomically");
    }

    pub fn current_config(&self) -> Arc<GatewayConfig> {
        self.config.load_full()
    }
}

/// Handle a TCP connection and route to appropriate handler
async fn handle_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use TokioIo to adapt the TCP stream for hyper
    let io = TokioIo::new(stream);
    
    // Create a service function that can handle both HTTP and WebSocket
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move {
            // Check if this is a WebSocket upgrade request
            if is_websocket_upgrade(&req) {
                debug!("Detected WebSocket upgrade request, routing to WebSocket handler");
                // For WebSocket, we need to handle it differently
                handle_websocket_request(req, state, addr).await
            } else {
                // For regular HTTP requests, use the normal handler
                handle_proxy_request(req, state, addr).await
            }
        }
    });
    
    // Use hyper's upgrade support to handle WebSocket upgrades properly
    if let Err(e) = http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        debug!("Connection error: {}", e);
    }
    
    Ok(())
}

/// Handle WebSocket requests with proper connection takeover
async fn handle_websocket_request(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    info!("WebSocket upgrade request for proxy routing from {}", remote_addr.ip());
    
    // Find matching proxy for WebSocket request
    let config = state.current_config();
    let path = req.uri().path().to_string();
    let matched_proxy = find_matching_proxy(&config, &path);
    
    let proxy = match matched_proxy {
        Some(p) => p,
        None => {
            state.request_count.fetch_add(1, Ordering::Relaxed);
            record_status(&state, 404);
            return Ok(build_response(StatusCode::NOT_FOUND, r#"{"error":"Not Found"}"#));
        }
    };
    
    // Verify this proxy supports WebSocket
    if !matches!(proxy.backend_protocol, BackendProtocol::Ws | BackendProtocol::Wss) {
        error!("Proxy {} does not support WebSocket protocol", proxy.id);
        return Ok(build_response(
            StatusCode::BAD_GATEWAY,
            r#"{"error":"This proxy does not support WebSocket connections"}"#,
        ));
    }
    
    // Record WebSocket connection attempt
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(&state, 101); // Switching Protocols
    
    // Get backend URL
    let backend_url = match proxy.backend_protocol {
        BackendProtocol::Ws => format!("ws://{}:{}", proxy.backend_host, proxy.backend_port),
        BackendProtocol::Wss => format!("wss://{}:{}", proxy.backend_host, proxy.backend_port),
        _ => unreachable!(), // We already checked this above
    };
    
    // Get the upgrade parts from the request
    let (mut parts, _body) = req.into_parts();
    
    // Extract the OnUpgrade future
    let on_upgrade = match parts.extensions.remove::<OnUpgrade>() {
        Some(on_upgrade) => on_upgrade,
        None => {
            error!("No upgrade extension found in request");
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"No upgrade extension found"}"#,
            ));
        }
    };
    
    // Log connection details
    let ws_key = parts.headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    
    let ws_version = parts.headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    debug!("WebSocket handshake details - Key: {}, Version: {}, Backend: {}", 
           ws_key, ws_version, backend_url);

    // Generate accept key
    let accept_key = derive_accept_key(ws_key.as_bytes());
    
    // Spawn a task to handle the WebSocket connection after upgrade
    let proxy_id = proxy.id.clone();
    let backend_url_clone = backend_url.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                info!("WebSocket connection upgraded successfully for: {}", proxy_id);
                if let Err(e) = handle_websocket_proxying(upgraded, &backend_url_clone, &proxy_id).await {
                    error!("WebSocket proxying error: {}", e);
                }
            }
            Err(e) => {
                error!("WebSocket upgrade failed: {}", e);
            }
        }
    });

    // Build upgrade response
    let upgrade_response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", accept_key)
        .header("x-websocket-proxy", "ferrum-gateway")
        .header("x-websocket-backend", backend_url.clone())
        .body(Full::new(Bytes::from("")))
        .unwrap();

    info!("WebSocket upgrade response sent for: {} -> {}", proxy.id, backend_url);
    
    Ok(upgrade_response)
}

/// Handle actual WebSocket proxying after connection upgrade
async fn handle_websocket_proxying(
    upgraded: Upgraded,
    backend_url: &str,
    proxy_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting WebSocket proxying for {} to backend: {}", proxy_id, backend_url);
    
    // Convert the upgraded connection to a WebSocket stream
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    
    // Connect to backend WebSocket server
    let (backend_ws_stream, backend_response) = connect_async(backend_url).await?;
    info!("Connected to backend WebSocket server: {}", backend_url);
    debug!("Backend response status: {}", backend_response.status());

    // Split streams for bidirectional communication
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut backend_sink, mut backend_stream) = backend_ws_stream.split();

    // Forward messages from client to backend
    let client_to_backend = async move {
        info!("Starting client -> backend message forwarding");
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    debug!("Client -> Backend: Text({})", text);
                    if let Err(e) = backend_sink.send(Message::Text(text)).await {
                        error!("Failed to send text to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    debug!("Client -> Backend: Binary({} bytes)", data.len());
                    if let Err(e) = backend_sink.send(Message::Binary(data)).await {
                        error!("Failed to send binary to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Ping(data)) => {
                    debug!("Client -> Backend: Ping");
                    if let Err(e) = backend_sink.send(Message::Ping(data)).await {
                        error!("Failed to send ping to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Close(close_frame)) => {
                    info!("Client sent close frame");
                    if let Err(e) = backend_sink.send(Message::Close(close_frame)).await {
                        error!("Failed to send close to backend: {}", e);
                    }
                    break;
                }
                Ok(Message::Pong(_data)) => {
                    debug!("Client -> Backend: Pong");
                }
                Ok(Message::Frame(_)) => {
                    debug!("Client -> Backend: Frame");
                }
                Err(e) => {
                    error!("Error receiving from client: {}", e);
                    break;
                }
            }
        }
        info!("Client -> backend forwarding completed");
    };

    // Forward messages from backend to client
    let backend_to_client = async move {
        info!("Starting backend -> client message forwarding");
        while let Some(msg) = backend_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    debug!("Backend -> Client: Text({})", text);
                    if let Err(e) = ws_sink.send(Message::Text(text)).await {
                        error!("Failed to send text to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    debug!("Backend -> Client: Binary({} bytes)", data.len());
                    if let Err(e) = ws_sink.send(Message::Binary(data)).await {
                        error!("Failed to send binary to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Ping(data)) => {
                    debug!("Backend -> Client: Ping");
                    if let Err(e) = ws_sink.send(Message::Ping(data)).await {
                        error!("Failed to send ping to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Close(close_frame)) => {
                    info!("Backend sent close frame");
                    if let Err(e) = ws_sink.send(Message::Close(close_frame)).await {
                        error!("Failed to send close to client: {}", e);
                    }
                    break;
                }
                Ok(Message::Pong(_data)) => {
                    debug!("Backend -> Client: Pong");
                }
                Ok(Message::Frame(_)) => {
                    debug!("Backend -> Client: Frame");
                }
                Err(e) => {
                    error!("Error receiving from backend: {}", e);
                    break;
                }
            }
        }
        info!("Backend -> client forwarding completed");
    };

    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_backend => {
            info!("Client to backend stream completed first");
        }
        _ = backend_to_client => {
            info!("Backend to client stream completed first");
        }
    }

    info!("WebSocket proxy connection closed for {}", proxy_id);
    Ok(())
}

/// Start the proxy HTTP listener with dual-path handling.
pub async fn start_proxy_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Proxy listener started on {}", addr);

    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, remote_addr, state).await {
                                debug!("Connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Proxy listener shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single proxy request.
async fn handle_proxy_request(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = Instant::now();
    let config = state.current_config();

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    // Build request context
    let mut ctx = RequestContext::new(
        remote_addr.ip().to_string(),
        method.clone(),
        path.clone(),
    );

    // Extract headers
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            ctx.headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    // Parse query params
    for pair in query_string.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            ctx.query_params.insert(k.to_string(), v.to_string());
        }
    }

    // Route: longest prefix match
    let matched_proxy = find_matching_proxy(&config, &path);

    let proxy = match matched_proxy {
        Some(p) => p,
        None => {
            state.request_count.fetch_add(1, Ordering::Relaxed);
            record_status(&state, 404);
            return Ok(build_response(StatusCode::NOT_FOUND, r#"{"error":"Not Found"}"#));
        }
    };

    // Check if this is a WebSocket upgrade request and the proxy supports WebSocket
    if is_websocket_upgrade(&req) && matches!(proxy.backend_protocol, BackendProtocol::Ws | BackendProtocol::Wss) {
        return handle_websocket_request(req, state, remote_addr).await;
    }

    ctx.matched_proxy = Some(proxy.clone());

    // Resolve plugins for this proxy
    let plugins = resolve_plugins(&config, &proxy);

    // Execute on_request_received hooks
    for plugin in &plugins {
        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Reject { status_code, body } => {
                record_request(&state, status_code);
                return Ok(build_response(
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                ));
            }
            PluginResult::Continue => {}
        }
    }

    // Authentication phase
    let auth_plugins: Vec<&Arc<dyn Plugin>> = plugins
        .iter()
        .filter(|p| {
            matches!(
                p.name(),
                "jwt_auth" | "key_auth" | "basic_auth" | "oauth2_auth"
            )
        })
        .collect();

    let consumers = &config.consumers;

    match proxy.auth_mode {
        AuthMode::Multi => {
            // Execute ALL auth plugins; first success sets consumer
            for auth_plugin in &auth_plugins {
                let _ = auth_plugin.authenticate(&mut ctx, consumers).await;
                // In multi mode, we don't reject on individual failure
            }
            // After all auth plugins, check if any consumer was identified
            // This is handled by the access_control plugin below
        }
        AuthMode::Single => {
            // Execute auth plugins sequentially; first failure rejects
            for auth_plugin in &auth_plugins {
                match auth_plugin.authenticate(&mut ctx, consumers).await {
                    PluginResult::Reject { status_code, body } => {
                        record_request(&state, status_code);
                        return Ok(build_response(
                            StatusCode::from_u16(status_code)
                                .unwrap_or(StatusCode::UNAUTHORIZED),
                            &body,
                        ));
                    }
                    PluginResult::Continue => {}
                }
            }
        }
    }

    // Authorization phase (access_control)
    for plugin in &plugins {
        if plugin.name() == "access_control" {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Reject { status_code, body } => {
                    record_request(&state, status_code);
                    return Ok(build_response(
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::FORBIDDEN),
                        &body,
                    ));
                }
                PluginResult::Continue => {}
            }
        }
    }

    // before_proxy hooks
    let mut proxy_headers = ctx.headers.clone();
    for plugin in &plugins {
        match plugin.before_proxy(&mut ctx, &mut proxy_headers).await {
            PluginResult::Reject { status_code, body } => {
                record_request(&state, status_code);
                return Ok(build_response(
                    StatusCode::from_u16(status_code)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                ));
            }
            PluginResult::Continue => {}
        }
    }

    // Build backend URL
    let backend_url = build_backend_url(&proxy, &path, &query_string);
    let backend_start = Instant::now();

    // Perform the backend request
    let (response_status, response_body, mut response_headers) =
        proxy_to_backend(&state, &proxy, &backend_url, &method, &proxy_headers, req).await;

    let backend_ttfb_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
    let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;

    // after_proxy hooks
    for plugin in &plugins {
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
        metadata: ctx.metadata.clone(),
    };

    // Log phase
    for plugin in &plugins {
        plugin.log(&summary).await;
    }

    record_request(&state, response_status);

    // Build final response
    let mut resp_builder = Response::builder().status(
        StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY),
    );

    for (k, v) in &response_headers {
        resp_builder = resp_builder.header(k.as_str(), v.as_str());
    }

    Ok(resp_builder
        .body(Full::new(Bytes::from(response_body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap()
        }))
}

/// Find the matching proxy using longest prefix match with optimized route table.
pub fn find_matching_proxy(config: &GatewayConfig, path: &str) -> Option<Proxy> {
    let route_table = config.build_route_table();
    
    // Route table is already sorted by path length descending for longest prefix match
    for (listen_path, proxy_id) in route_table {
        if path.starts_with(&listen_path) {
            // Find the proxy by ID
            return config.proxies.iter().find(|p| p.id == proxy_id).cloned();
        }
    }
    
    None
}

/// Resolve which plugins apply to this proxy request.
fn resolve_plugins(config: &GatewayConfig, proxy: &Proxy) -> Vec<Arc<dyn Plugin>> {
    let mut plugins: Vec<Arc<dyn Plugin>> = Vec::new();

    // Global plugins
    for pc in &config.plugin_configs {
        if !pc.enabled {
            continue;
        }
        if pc.scope == crate::config::types::PluginScope::Global {
            if let Some(plugin) = create_plugin(&pc.plugin_name, &pc.config) {
                plugins.push(plugin);
            }
        }
    }

    // Proxy-scoped plugins (override globals of same name)
    let proxy_plugin_ids: Vec<&str> = proxy
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();

    // Only process plugin configs that are assigned to this proxy
    for pc in &config.plugin_configs {
        if !pc.enabled {
            continue;
        }
        if pc.scope == crate::config::types::PluginScope::Proxy
            && pc.proxy_id.as_deref() == Some(&proxy.id)
            && proxy_plugin_ids.contains(&pc.id.as_str())
        {
            if let Some(plugin) = create_plugin(&pc.plugin_name, &pc.config) {
                // Remove any global plugin of the same name
                plugins.retain(|p| p.name() != plugin.name());
                plugins.push(plugin);
            }
        }
    }

    plugins
}

/// Build the backend URL based on proxy config and path forwarding logic.
pub fn build_backend_url(proxy: &Proxy, incoming_path: &str, query_string: &str) -> String {
    let scheme = match proxy.backend_protocol {
        BackendProtocol::Http | BackendProtocol::Ws => "http",
        BackendProtocol::Https | BackendProtocol::Wss => "https",
        BackendProtocol::Grpc => "http", // gRPC over HTTP/2
    };

    let remaining_path = if proxy.strip_listen_path {
        incoming_path
            .strip_prefix(&proxy.listen_path)
            .unwrap_or("")
    } else {
        incoming_path
    };

    let backend_path = proxy.backend_path.as_deref().unwrap_or("");
    let full_path = format!("{}{}", backend_path, remaining_path);
    let full_path = if full_path.is_empty() {
        "/".to_string()
    } else if !full_path.starts_with('/') {
        format!("/{}", full_path)
    } else {
        full_path
    };

    let base = format!(
        "{}://{}:{}{}",
        scheme, proxy.backend_host, proxy.backend_port, full_path
    );

    if query_string.is_empty() {
        base
    } else {
        format!("{}?{}", base, query_string)
    }
}

/// Proxy the request to the backend.
async fn proxy_to_backend(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    original_req: Request<Incoming>,
) -> (u16, Vec<u8>, HashMap<String, String>) {
    // Resolve backend hostname
    let resolved_ip = state
        .dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await;

    // Get client from connection pool
    let client = match state.connection_pool.get_client(proxy, resolved_ip.ok()).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            // Fallback to creating new client
            let fallback_client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(proxy.backend_connect_timeout_ms))
                .timeout(std::time::Duration::from_millis(proxy.backend_read_timeout_ms))
                .danger_accept_invalid_certs(!proxy.backend_tls_verify_server_cert)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            fallback_client
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
        _ => reqwest::Method::GET,
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    req_builder = req_builder.header("Host", &proxy.backend_host);
                }
            }
            "connection" | "transfer-encoding" => continue, // hop-by-hop
            _ => {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }
        }
    }

    // Add proxy headers
    if let Some(xff) = headers.get("x-forwarded-for") {
        req_builder =
            req_builder.header("X-Forwarded-For", format!("{}, {}", xff, "client_ip"));
    }
    req_builder = req_builder.header("X-Forwarded-Proto", "http");
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    // Collect and forward body
    let body_bytes = match original_req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            Vec::new()
        }
    };

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    // Send
    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers = HashMap::new();
            for (k, v) in response.headers() {
                if let Ok(vs) = v.to_str() {
                    resp_headers.insert(k.as_str().to_string(), vs.to_string());
                }
            }
            let body = response.bytes().await.unwrap_or_default().to_vec();
            (status, body, resp_headers)
        }
        Err(e) => {
            error!("Backend request failed: {}", e);
            let body = format!(r#"{{"error":"Backend unavailable: {}"}}"#, e);
            (502, body.into_bytes(), HashMap::new())
        }
    }
}

fn strip_query_params(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn record_status(state: &ProxyState, status: u16) {
    state
        .status_counts
        .entry(status)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

fn record_request(state: &ProxyState, status: u16) {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(state, status);
}

fn build_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
