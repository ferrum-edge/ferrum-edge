use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, upgrade::OnUpgrade, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{WebSocketStream, tungstenite::handshake::derive_accept_key};
use tracing::{debug, error, info, warn};

use crate::config::PoolConfig;
use crate::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use crate::connection_pool::ConnectionPool;
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::http3::client::Http3Client;
use crate::plugin_cache::PluginCache;
use crate::plugins::{Plugin, PluginResult, RequestContext, TransactionSummary};
use crate::router_cache::RouterCache;

/// Check if the request is a WebSocket upgrade request
fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    let connection = headers.get("connection").and_then(|v| v.to_str().ok());
    let upgrade = headers.get("upgrade").and_then(|v| v.to_str().ok());
    let sec_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok());
    let sec_version = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok());

    connection.is_some_and(|conn| conn.to_lowercase().contains("upgrade"))
        && upgrade.is_some_and(|up| up.to_lowercase() == "websocket")
        && sec_key.is_some()
        && (sec_version == Some("13"))
}

/// Shared state for the proxy engine.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub connection_pool: Arc<ConnectionPool>,
    pub router_cache: Arc<RouterCache>,
    pub plugin_cache: Arc<PluginCache>,
    pub consumer_index: Arc<ConsumerIndex>,
    pub request_count: Arc<AtomicU64>,
    pub status_counts: Arc<dashmap::DashMap<u16, AtomicU64>>,
    /// Whether HTTP/3 is enabled (used for Alt-Svc header advertisement)
    pub enable_http3: bool,
    /// The HTTPS port (shared by HTTP/3 QUIC listener)
    pub proxy_https_port: u16,
    // Size limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    pub max_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,
}

impl ProxyState {
    pub fn new(
        config: GatewayConfig,
        dns_cache: DnsCache,
        env_config: crate::config::EnvConfig,
    ) -> Self {
        let enable_http3 = env_config.enable_http3;
        let proxy_https_port = env_config.proxy_https_port;
        let max_header_size_bytes = env_config.max_header_size_bytes;
        let max_single_header_size_bytes = env_config.max_single_header_size_bytes;
        let max_body_size_bytes = env_config.max_body_size_bytes;
        let max_response_body_size_bytes = env_config.max_response_body_size_bytes;
        // Create connection pool with global configuration from environment
        let global_pool_config = PoolConfig::from_env();
        let connection_pool = Arc::new(ConnectionPool::new(global_pool_config, env_config));
        // Build router cache with pre-sorted route table for fast prefix matching
        let router_cache = Arc::new(RouterCache::new(&config, 10_000));
        // Pre-resolve plugins per proxy (fixes rate_limiting state persistence bug)
        let plugin_cache = Arc::new(PluginCache::new(&config));
        // Build credential-indexed consumer lookup for O(1) auth
        let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));

        Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            dns_cache,
            connection_pool,
            router_cache,
            plugin_cache,
            consumer_index,
            request_count: Arc::new(AtomicU64::new(0)),
            status_counts: Arc::new(dashmap::DashMap::new()),
            enable_http3,
            proxy_https_port,
            max_header_size_bytes,
            max_single_header_size_bytes,
            max_body_size_bytes,
            max_response_body_size_bytes,
        }
    }

    pub fn update_config(&self, new_config: GatewayConfig) {
        self.router_cache.rebuild(&new_config);
        self.plugin_cache.rebuild(&new_config);
        self.consumer_index.rebuild(&new_config.consumers);
        self.config.store(Arc::new(new_config));
        info!("Proxy configuration updated atomically (router + plugins + consumers rebuilt)");
    }

    pub fn current_config(&self) -> Arc<GatewayConfig> {
        self.config.load_full()
    }
}

/// Handle a plain HTTP TCP connection (HTTP/1.1 only for cleartext).
async fn handle_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set TCP keepalive on inbound connection to detect stale clients
    set_tcp_keepalive(&stream);

    // Use TokioIo to adapt the TCP stream for hyper
    let io = TokioIo::new(stream);

    // Plain HTTP uses HTTP/1.1 only (HTTP/2 cleartext requires prior knowledge
    // or upgrade which is rarely used; HTTP/2 is negotiated via ALPN on TLS)
    let mut http1_builder = hyper::server::conn::http1::Builder::new();
    http1_builder.max_buf_size(state.max_header_size_bytes);

    // Create a service function that can handle both HTTP and WebSocket
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move {
            if is_websocket_upgrade(&req) {
                debug!("Detected WebSocket upgrade request, routing to WebSocket handler");
                handle_websocket_request(req, state, addr).await
            } else {
                handle_proxy_request(req, state, addr).await
            }
        }
    });
    if let Err(e) = http1_builder
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        debug!("Connection error: {}", e);
    }

    Ok(())
}

/// Set TCP keepalive on a stream to detect dead connections.
fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use std::os::fd::AsFd;
    let fd = stream.as_fd();
    let socket = socket2::SockRef::from(&fd);
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("Failed to set TCP keepalive: {}", e);
    }
}

/// Handle WebSocket requests with proper connection takeover
async fn handle_websocket_request(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    info!(
        "WebSocket upgrade request for proxy routing from {}",
        remote_addr.ip()
    );

    // Find matching proxy for WebSocket request via router cache
    let path = req.uri().path().to_string();
    let matched_proxy = state.router_cache.find_proxy(&path);

    let proxy = match matched_proxy {
        Some(p) => (*p).clone(),
        None => {
            state.request_count.fetch_add(1, Ordering::Relaxed);
            record_status(&state, 404);
            return Ok(build_response(
                StatusCode::NOT_FOUND,
                r#"{"error":"Not Found"}"#,
            ));
        }
    };

    // Verify this proxy supports WebSocket
    if !matches!(
        proxy.backend_protocol,
        BackendProtocol::Ws | BackendProtocol::Wss
    ) {
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
    let ws_key = parts
        .headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");

    let ws_version = parts
        .headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    debug!(
        "WebSocket handshake details - Key: {}, Version: {}, Backend: {}",
        ws_key, ws_version, backend_url
    );

    // Generate accept key
    let accept_key = derive_accept_key(ws_key.as_bytes());

    // Spawn a task to handle the WebSocket connection after upgrade
    let proxy_id = proxy.id.clone();
    let backend_url_clone = backend_url.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                info!(
                    "WebSocket connection upgraded successfully for: {}",
                    proxy_id
                );
                if let Err(e) =
                    handle_websocket_proxying(upgraded, &backend_url_clone, &proxy_id).await
                {
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

    info!(
        "WebSocket upgrade response sent for: {} -> {}",
        proxy.id, backend_url
    );

    Ok(upgrade_response)
}

/// Handle WebSocket requests AFTER authentication and authorization plugins have run
async fn handle_websocket_request_authenticated(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    proxy: Proxy,
    ctx: RequestContext,
    plugins: Vec<Arc<dyn Plugin>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    info!(
        "WebSocket upgrade request authenticated for proxy: {} from: {}",
        proxy.id,
        remote_addr.ip()
    );

    // Record successful WebSocket connection attempt
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(&state, 101); // Switching Protocols

    // Get backend URL
    let backend_url = match proxy.backend_protocol {
        BackendProtocol::Ws => format!("ws://{}:{}", proxy.backend_host, proxy.backend_port),
        BackendProtocol::Wss => format!("wss://{}:{}", proxy.backend_host, proxy.backend_port),
        _ => unreachable!(), // We already checked this above
    };

    // Log the WebSocket connection attempt
    let start_time = std::time::Instant::now();
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;

    // Build transaction summary for logging
    let summary = TransactionSummary {
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.identified_consumer.as_ref().map(|c| c.username.clone()),
        http_method: "GET".to_string(), // WebSocket upgrades are always GET
        request_path: ctx.path.clone(),
        matched_proxy_id: Some(proxy.id.clone()),
        matched_proxy_name: proxy.name.clone(),
        backend_target_url: Some(strip_query_params(&backend_url)),
        response_status_code: 101, // Switching Protocols
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0, // Not applicable for WebSocket upgrade
        latency_backend_total_ms: 0.0, // Not applicable for WebSocket upgrade
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        metadata: ctx.metadata.clone(),
    };

    // Log the successful WebSocket connection (after auth)
    for plugin in &plugins {
        plugin.log(&summary).await;
    }

    // Get the upgrade parts from the request
    let (mut parts, _body) = req.into_parts();

    // Extract the OnUpgrade future
    let on_upgrade = match parts.extensions.remove::<OnUpgrade>() {
        Some(on_upgrade) => on_upgrade,
        None => {
            error!("Failed to extract OnUpgrade extension from WebSocket request");
            return Ok(build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error during WebSocket upgrade"}"#,
            ));
        }
    };

    // Create the upgrade response with proper headers
    let upgrade_response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header(
            "sec-websocket-accept",
            derive_accept_key(
                parts
                    .headers
                    .get("sec-websocket-key")
                    .and_then(|k| k.to_str().ok())
                    .unwrap_or("")
                    .as_bytes(),
            ),
        )
        .body(Full::new(Bytes::from("")))
        .unwrap();

    // Spawn the WebSocket proxying task
    let proxy_id = proxy.id.clone();
    let backend_url_for_spawn = backend_url.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) =
                    handle_websocket_proxying(upgraded, &backend_url_for_spawn, &proxy_id).await
                {
                    error!("WebSocket proxying error for {}: {}", proxy_id, e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to upgrade WebSocket connection for {}: {}",
                    proxy_id, e
                );
            }
        }
    });

    info!(
        "WebSocket upgrade response sent for authenticated connection: {} -> {}",
        proxy.id, backend_url
    );

    Ok(upgrade_response)
}

/// Handle actual WebSocket proxying after connection upgrade
async fn handle_websocket_proxying(
    upgraded: Upgraded,
    backend_url: &str,
    proxy_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "Starting WebSocket proxying for {} to backend: {}",
        proxy_id, backend_url
    );

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
    start_proxy_listener_with_tls(addr, state, shutdown, None).await
}

/// Start the proxy listener with optional TLS and client certificate verification.
pub async fn start_proxy_listener_with_tls(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
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
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            let result = if let Some(tls_config) = tls_config {
                                // Handle TLS connection with client certificate verification
                                handle_tls_connection(stream, remote_addr, state, tls_config).await
                            } else {
                                // Handle plain HTTP connection
                                handle_connection(stream, remote_addr, state).await
                            };

                            if let Err(e) = result {
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
                return Ok(());
            }
        }
    }
}

/// Handle TLS connections with HTTP/1.1 and HTTP/2 auto-negotiation via ALPN.
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::TlsAcceptor;

    // Set TCP keepalive on inbound connection
    set_tcp_keepalive(&stream);

    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => {
            info!("TLS connection established from {}", remote_addr.ip());
            stream
        }
        Err(e) => {
            warn!("TLS handshake failed from {}: {}", remote_addr.ip(), e);
            return Err(e.into());
        }
    };

    // Convert TLS stream to TokioIo for hyper
    let io = hyper_util::rt::TokioIo::new(tls_stream);

    // Use hyper-util's auto builder which negotiates HTTP/1.1 or HTTP/2 via ALPN.
    // HTTP/2 clients get multiplexed streams; HTTP/1.1 clients get upgrade support.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder.http1().max_buf_size(state.max_header_size_bytes);
    builder
        .http2()
        .max_header_list_size(state.max_header_size_bytes as u32);

    // Use the same HTTP service function
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move {
            if is_websocket_upgrade(&req) {
                debug!("Detected WebSocket upgrade request over TLS, routing to WebSocket handler");
                handle_websocket_request(req, state, addr).await
            } else {
                handle_proxy_request(req, state, addr).await
            }
        }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        error!("HTTP connection error over TLS: {}", e);
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

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    // Build request context
    let mut ctx = RequestContext::new(remote_addr.ip().to_string(), method.clone(), path.clone());

    // Validate and extract headers with size limits
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_request(&state, 431);
            return Ok(build_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                &format!(
                    r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                    name.as_str(),
                    state.max_single_header_size_bytes
                ),
            ));
        }
        total_header_size += header_size;
        if let Ok(v) = value.to_str() {
            ctx.headers
                .insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    if total_header_size > state.max_header_size_bytes {
        record_request(&state, 431);
        return Ok(build_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
        ));
    }

    // Parse query params
    for pair in query_string.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            ctx.query_params.insert(k.to_string(), v.to_string());
        }
    }

    // Route: longest prefix match via router cache (O(1) cache hit, pre-sorted fallback)
    let matched_proxy = state.router_cache.find_proxy(&path);

    let proxy = match matched_proxy {
        Some(p) => (*p).clone(),
        None => {
            state.request_count.fetch_add(1, Ordering::Relaxed);
            record_status(&state, 404);
            return Ok(build_response(
                StatusCode::NOT_FOUND,
                r#"{"error":"Not Found"}"#,
            ));
        }
    };

    ctx.matched_proxy = Some(proxy.clone());

    // Get pre-resolved plugins from cache (O(1) lookup, no per-request allocation)
    let plugins = state.plugin_cache.get_plugins(&proxy.id);

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

    match proxy.auth_mode {
        AuthMode::Multi => {
            // Execute ALL auth plugins; first success sets consumer
            for auth_plugin in &auth_plugins {
                let _ = auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await;
                // In multi mode, we don't reject on individual failure
            }
            // After all auth plugins, check if any consumer was identified
            // This is handled by the access_control plugin below
        }
        AuthMode::Single => {
            // Execute auth plugins sequentially; first failure rejects
            for auth_plugin in &auth_plugins {
                match auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await
                {
                    PluginResult::Reject { status_code, body } => {
                        record_request(&state, status_code);
                        return Ok(build_response(
                            StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
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
                        StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN),
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
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                ));
            }
            PluginResult::Continue => {}
        }
    }

    // Check if this is a WebSocket upgrade request and the proxy supports WebSocket
    // This check happens AFTER authentication and authorization plugins have run
    if is_websocket_upgrade(&req)
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Ws | BackendProtocol::Wss
        )
    {
        return handle_websocket_request_authenticated(
            req,
            state,
            remote_addr,
            proxy,
            ctx,
            plugins,
        )
        .await;
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
    let mut resp_builder = Response::builder()
        .status(StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY));

    for (k, v) in &response_headers {
        resp_builder = resp_builder.header(k.as_str(), v.as_str());
    }

    // Advertise HTTP/3 availability via Alt-Svc header
    if state.enable_http3 {
        resp_builder = resp_builder.header(
            "alt-svc",
            format!("h3=\":{}\"; ma=86400", state.proxy_https_port),
        );
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

/// Find the matching proxy using longest prefix match.
/// Iterates proxies directly to avoid per-request allocation.
#[allow(dead_code)]
pub fn find_matching_proxy(config: &GatewayConfig, path: &str) -> Option<Proxy> {
    let mut best_match: Option<&Proxy> = None;
    let mut best_len = 0;

    for proxy in &config.proxies {
        let lp = &proxy.listen_path;
        if lp.len() > best_len && path.starts_with(lp.as_str()) {
            best_match = Some(proxy);
            best_len = lp.len();
        }
    }

    best_match.cloned()
}

/// Build the backend URL based on proxy config and path forwarding logic.
pub fn build_backend_url(proxy: &Proxy, incoming_path: &str, query_string: &str) -> String {
    let scheme = match proxy.backend_protocol {
        BackendProtocol::Http | BackendProtocol::Ws => "http",
        BackendProtocol::Https | BackendProtocol::Wss | BackendProtocol::H3 => "https",
        BackendProtocol::Grpc => "http", // gRPC over HTTP/2
    };

    let remaining_path = if proxy.strip_listen_path {
        incoming_path.strip_prefix(&proxy.listen_path).unwrap_or("")
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

    // Handle HTTP/3 backend requests differently
    if matches!(proxy.backend_protocol, BackendProtocol::H3) {
        return proxy_to_backend_http3(state, proxy, backend_url, method, headers, original_req)
            .await;
    }

    // Get client from connection pool for HTTP/1.1 and HTTP/2
    let client = match state
        .connection_pool
        .get_client(proxy, resolved_ip.ok())
        .await
    {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            // Fallback to creating new client
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
        req_builder = req_builder.header("X-Forwarded-For", format!("{}, {}", xff, "client_ip"));
    }
    req_builder = req_builder.header("X-Forwarded-Proto", "http");
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    // Enforce request body size limit via Content-Length fast path
    if state.max_body_size_bytes > 0
        && let Some(content_length) = headers.get("content-length")
        && let Ok(len) = content_length.parse::<usize>()
        && len > state.max_body_size_bytes
    {
        return (
            413,
            r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
            HashMap::new(),
        );
    }

    // Collect and forward body with size limit
    let body_bytes = if state.max_body_size_bytes > 0 {
        let limited =
            http_body_util::Limited::new(original_req.into_body(), state.max_body_size_bytes);
        match limited.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(_) => {
                return (
                    413,
                    r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                    HashMap::new(),
                );
            }
        }
    } else {
        match original_req.into_body().collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(e) => {
                warn!("Failed to read request body: {}", e);
                Vec::new()
            }
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
                        HashMap::new(),
                    );
                }

                // Stream-collect with size limit using chunk_with_limit
                let max_size = state.max_response_body_size_bytes;
                match collect_response_with_limit(response, max_size).await {
                    Ok((resp_body, _)) => (status, resp_body, resp_headers),
                    Err(err_body) => (502, err_body, HashMap::new()),
                }
            } else {
                let body = response.bytes().await.unwrap_or_default().to_vec();
                (status, body, resp_headers)
            }
        }
        Err(e) => {
            error!("Backend request failed: {}", e);
            let body = format!(r#"{{"error":"Backend unavailable: {}"}}"#, e);
            (502, body.into_bytes(), HashMap::new())
        }
    }
}

/// Collect a response body with a size limit, returning Err with error body if exceeded.
async fn collect_response_with_limit(
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
                return Err(format!(r#"{{"error":"Backend error: {}"}}"#, e).into_bytes());
            }
        }
    }
    let len = body.len();
    Ok((body, len))
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

/// Proxy the request to an HTTP/3 backend.
async fn proxy_to_backend_http3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    original_req: Request<Incoming>,
) -> (u16, Vec<u8>, HashMap<String, String>) {
    info!("Proxying request to HTTP/3 backend: {}", backend_url);

    // Create HTTP/3 client with TLS configuration
    let tls_config = state.connection_pool.get_tls_config_for_backend(proxy);
    let http3_client = match Http3Client::new(tls_config) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create HTTP/3 client: {}", e);
            let body = r#"{"error":"HTTP/3 client creation failed"}"#;
            return (502, body.as_bytes().to_vec(), HashMap::new());
        }
    };

    // Read request body with size limit
    let (_parts, body) = original_req.into_parts();
    let request_body = if state.max_body_size_bytes > 0 {
        // Check Content-Length fast path
        if let Some(content_length) = headers.get("content-length")
            && let Ok(len) = content_length.parse::<usize>()
            && len > state.max_body_size_bytes
        {
            return (
                413,
                r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                HashMap::new(),
            );
        }
        let limited = http_body_util::Limited::new(body, state.max_body_size_bytes);
        match limited.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return (
                    413,
                    r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                    HashMap::new(),
                );
            }
        }
    } else {
        match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read request body: {}", e);
                Bytes::new()
            }
        }
    };

    // Convert headers to HTTP/3 format
    let mut http3_headers = Vec::new();
    for (name, value) in headers {
        http3_headers.push((
            name.parse()
                .unwrap_or_else(|_| http::header::HeaderName::from_static("x-custom")),
            value.parse().unwrap(),
        ));
    }

    // Make HTTP/3 request
    match http3_client
        .request(proxy, method, backend_url, http3_headers, request_body)
        .await
    {
        Ok(response) => {
            info!("HTTP/3 backend request successful");
            (response.0, response.1, response.2)
        }
        Err(e) => {
            error!("HTTP/3 backend request failed: {}", e);
            let body = format!(r#"{{"error":"HTTP/3 backend request failed: {}"}}"#, e);
            (502, body.into_bytes(), HashMap::new())
        }
    }
}
