//! Admin API for Ferrum Edge.

mod backup;
pub(crate) mod crud;
pub mod jwt_auth;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::admin::backup::{
    BackupCounts, BackupPayload, RestorePayload, check_legacy_proxy_fields,
    filter_config_by_namespace, parse_backup_resources, parse_restore_confirm,
};
use crate::admin::jwt_auth::{JwtError, JwtManager};
use crate::config::db_backend::DatabaseBackend;
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream, max_credentials_per_type,
};
use crate::config::validation_pipeline::{ValidationAction, ValidationPipeline};
use crate::grpc::cp_server::DpNodeRegistry;
use crate::grpc::dp_client::DpCpConnectionState;
use crate::plugins;
use crate::proxy::ProxyState;
use arc_swap::ArcSwap;
use serde::Serialize;

/// Cached result of the database health check to avoid hitting the DB on every
/// `/health` request. The result is reused for `DB_HEALTH_CACHE_TTL` seconds.
#[derive(Clone)]
pub struct CachedDbHealthResult {
    connected: bool,
    checked_at: Instant,
}

/// Duration for which a DB health check result is reused.
const DB_HEALTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(15);

/// Admin API state.
#[derive(Clone)]
pub struct AdminState {
    pub db: Option<Arc<dyn DatabaseBackend>>,
    pub jwt_manager: JwtManager,
    pub proxy_state: Option<ProxyState>,
    /// In-memory cached config for resilient reads when DB is unavailable.
    /// Falls back to this when database queries fail or no DB is configured.
    pub cached_config: Option<Arc<ArcSwap<GatewayConfig>>>,
    pub mode: String,
    pub read_only: bool,
    /// Startup readiness flag flipped by the mode once listeners are bound and
    /// the gateway has finished its initial loading work.
    pub startup_ready: Option<Arc<AtomicBool>>,
    /// Dynamic flag set by the DB polling loop. When `false`, write operations
    /// are rejected early to preserve the cached config until the DB recovers.
    pub db_available: Option<Arc<AtomicBool>>,
    /// Max request body size in MiB for POST /restore.
    pub admin_restore_max_body_size_mib: usize,
    /// Ports reserved by the gateway's own listeners (proxy, admin, gRPC).
    /// Stream proxy `listen_port` values must not collide with these.
    pub reserved_ports: std::collections::HashSet<u16>,
    /// Bind address used for stream proxy listeners (for OS port availability checks).
    pub stream_proxy_bind_address: String,
    /// Parsed admin API IP allowlist. When non-empty, only connections from
    /// matching IPs are accepted. Checked at the TCP level before any processing.
    pub admin_allowed_cidrs: Arc<crate::proxy::client_ip::TrustedProxies>,
    /// Cached DB health check result to avoid hitting the database on every
    /// `/health` request. Shared across clones via `Arc<ArcSwap<_>>`.
    pub cached_db_health: Arc<ArcSwap<Option<CachedDbHealthResult>>>,
    /// Registry of connected DP nodes (CP mode only).
    pub dp_registry: Option<Arc<DpNodeRegistry>>,
    /// Connection state to the CP (DP mode only).
    pub cp_connection_state: Option<Arc<ArcSwap<DpCpConnectionState>>>,
}

impl AdminState {
    /// Get the current cached config if available.
    fn cached_gateway_config(&self) -> Option<Arc<GatewayConfig>> {
        self.cached_config.as_ref().map(|c| c.load_full())
    }

    /// Check whether write operations are allowed. Returns an error response
    /// if the admin API is read-only or the database is currently unavailable.
    pub fn check_write_allowed(&self) -> Option<Response<Full<Bytes>>> {
        if self.read_only {
            return Some(json_response(
                StatusCode::FORBIDDEN,
                &json!({"error": "Admin API is in read-only mode"}),
            ));
        }
        if let Some(ref flag) = self.db_available
            && !flag.load(Ordering::Relaxed)
        {
            return Some(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "Database is currently unavailable — admin API is temporarily read-only"}),
            ));
        }
        None
    }
}

/// Start the Admin API listener with dual-path handling.
pub async fn start_admin_listener(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    start_admin_listener_with_tls(addr, state, shutdown, None).await
}

/// Start the Admin API listener with optional TLS support.
pub async fn start_admin_listener_with_tls(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Admin API listener started on {}", addr);
    serve_admin_on_listener(listener, state, shutdown, tls_config).await
}

/// Run the Admin API accept loop on a pre-bound `TcpListener`.
///
/// Useful for tests that allocate an ephemeral port up front: passing the
/// listener through avoids the bind→drop→rebind window where another process
/// can steal the port between releasing it and the listener task re-binding.
/// Production callers go through [`start_admin_listener`] /
/// [`start_admin_listener_with_tls`], which bind internally.
pub async fn serve_admin_on_listener(
    listener: TcpListener,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        // Admin IP allowlist: reject connections from non-allowed IPs
                        // at the TCP level, before TLS handshake or request processing.
                        if !state.admin_allowed_cidrs.is_empty()
                            && !state.admin_allowed_cidrs.contains(&remote_addr.ip())
                        {
                            debug!(
                                remote_addr = %remote_addr.ip(),
                                "Admin connection rejected: IP not in FERRUM_ADMIN_ALLOWED_CIDRS"
                            );
                            drop(stream);
                            continue;
                        }

                        let state = state.clone();
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            let result = if let Some(tls_config) = tls_config {
                                // Handle TLS connection
                                handle_admin_tls_connection(stream, remote_addr, state, tls_config).await
                            } else {
                                // Handle plain HTTP connection
                                handle_admin_connection(stream, remote_addr, state).await
                            };

                            if let Err(e) = result {
                                debug!("Admin connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept admin connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Admin API listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Handle TLS connections for Admin API.
async fn handle_admin_tls_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: AdminState,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::TlsAcceptor;

    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => {
            info!("Admin TLS connection established from {}", remote_addr.ip());
            stream
        }
        Err(e) => {
            warn!(
                "Admin TLS handshake failed from {}: {}",
                remote_addr.ip(),
                e
            );
            return Err(e.into());
        }
    };

    // Convert TLS stream to TokioIo for hyper
    let io = hyper_util::rt::TokioIo::new(tls_stream);

    // Use the same HTTP service function
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        async move { handle_admin_request(req, state).await }
    });

    // Use auto builder to support both HTTP/1.1 and HTTP/2 via ALPN negotiation.
    // The TLS config advertises both h2 and http/1.1, so clients can negotiate
    // either protocol.
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let conn = builder.serve_connection(io, svc);

    if let Err(e) = conn.await {
        error!("Admin HTTP connection error over TLS: {}", e);
    }

    Ok(())
}

/// Handle a single admin connection.
async fn handle_admin_connection(
    stream: tokio::net::TcpStream,
    _remote_addr: SocketAddr,
    state: AdminState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_admin_request(req, state).await }
    });

    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
        error!("Admin HTTP connection error: {}", e);
    }

    Ok(())
}

/// Pagination parameters parsed from query string.
pub(crate) struct PaginationParams {
    offset: usize,
    limit: usize,
    /// True when caller explicitly provided `limit` or `offset` query params.
    is_paginated: bool,
}

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

fn parse_pagination(uri: &hyper::Uri) -> PaginationParams {
    let mut offset = 0usize;
    let mut limit = DEFAULT_PAGE_SIZE;
    let mut is_paginated = false;
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                match key {
                    "offset" => {
                        offset = val.parse().unwrap_or(0);
                        is_paginated = true;
                    }
                    "limit" => {
                        limit = val.parse().unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
                        if limit == 0 {
                            limit = DEFAULT_PAGE_SIZE;
                        }
                        is_paginated = true;
                    }
                    _ => {}
                }
            }
        }
    }
    PaginationParams {
        offset,
        limit,
        is_paginated,
    }
}

/// Apply pagination to a serializable collection.
/// When pagination params are present, wraps the response in an envelope with metadata.
/// Otherwise returns the plain array for backward compatibility.
fn paginate_response(items: &Value, pagination: &PaginationParams) -> Value {
    if !pagination.is_paginated {
        return items.clone();
    }
    let arr = match items.as_array() {
        Some(a) => a,
        None => return items.clone(),
    };
    let total = arr.len();
    let paginated: Vec<_> = arr
        .iter()
        .skip(pagination.offset)
        .take(pagination.limit)
        .collect();
    json!({
        "data": paginated,
        "pagination": {
            "offset": pagination.offset,
            "limit": pagination.limit,
            "total": total
        }
    })
}

/// Build pagination envelope from database-paginated results.
/// When pagination params are present, wraps items with metadata.
/// Otherwise returns a plain array for backward compatibility.
fn paginate_db_response<T: Serialize>(
    items: &[T],
    total: i64,
    pagination: &PaginationParams,
) -> Value {
    if !pagination.is_paginated {
        return json!(items);
    }
    json!({
        "data": items,
        "pagination": {
            "offset": pagination.offset,
            "limit": pagination.limit,
            "total": total
        }
    })
}

/// Extract namespace from the X-Ferrum-Namespace header, defaulting to "ferrum".
#[allow(clippy::result_large_err)]
fn extract_namespace(headers: &hyper::HeaderMap) -> Result<String, Response<Full<Bytes>>> {
    let ns = headers
        .get("x-ferrum-namespace")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(crate::config::types::DEFAULT_NAMESPACE);
    if let Err(e) = crate::config::types::validate_namespace(ns) {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid X-Ferrum-Namespace: {}", e)}),
        ));
    }
    Ok(ns.to_string())
}

/// Handle an admin API request.
pub async fn handle_admin_request(
    req: Request<Incoming>,
    state: AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let pagination = parse_pagination(req.uri());

    // Health check (unauthenticated)
    if path == "/health" || path == "/status" {
        let mut health_status = json!({
            "status": "ok",
            "timestamp": Utc::now().to_rfc3339(),
            "mode": state.mode
        });

        // Check database connectivity if available (cached for 15s)
        if let Some(db) = &state.db {
            let cached = state.cached_db_health.load();
            let db_connected = if let Some(ref entry) = **cached {
                if entry.checked_at.elapsed() < DB_HEALTH_CACHE_TTL {
                    // Cache hit — reuse the previous result
                    entry.connected
                } else {
                    // Cache expired — re-check
                    let connected = match db.health_check().await {
                        Ok(()) => true,
                        Err(e) => {
                            warn!("Health check database query failed: {}", e);
                            false
                        }
                    };
                    state
                        .cached_db_health
                        .store(Arc::new(Some(CachedDbHealthResult {
                            connected,
                            checked_at: Instant::now(),
                        })));
                    connected
                }
            } else {
                // No cached result yet — first call
                let connected = match db.health_check().await {
                    Ok(()) => true,
                    Err(e) => {
                        warn!("Health check database query failed: {}", e);
                        false
                    }
                };
                state
                    .cached_db_health
                    .store(Arc::new(Some(CachedDbHealthResult {
                        connected,
                        checked_at: Instant::now(),
                    })));
                connected
            };

            if db_connected {
                let mut db_info = json!({
                    "status": "connected",
                    "type": db.db_type()
                });
                if let Some(stats) = db.pool_stats() {
                    db_info["pool"] = serde_json::to_value(&stats).unwrap_or_else(|_| json!(null));
                }
                health_status["database"] = db_info;
            } else {
                health_status["status"] = json!("degraded");
                health_status["database"] = json!({
                    "status": "disconnected"
                });
            }
        }

        // Report whether admin writes are enabled (read_only flag + db_available)
        let writes_blocked = state.check_write_allowed().is_some();
        health_status["admin_writes_enabled"] = json!(!writes_blocked);
        if writes_blocked && !state.read_only {
            // DB-driven read-only — mark as degraded if not already
            health_status["status"] = json!("degraded");
        }

        let startup_ready = state
            .startup_ready
            .as_ref()
            .is_none_or(|flag| flag.load(Ordering::Relaxed));
        health_status["ready"] = json!(startup_ready);

        // Report cached config availability for resilience visibility
        if let Some(config) = state.cached_gateway_config() {
            health_status["cached_config"] = json!({
                "available": true,
                "loaded_at": config.loaded_at.to_rfc3339(),
                "proxy_count": config.proxies.len(),
                "consumer_count": config.consumers.len(),
            });
        } else {
            health_status["cached_config"] = json!({
                "available": false
            });
        }

        if !startup_ready {
            health_status["status"] = json!("starting");
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &health_status,
            ));
        }

        return Ok(json_response(StatusCode::OK, &health_status));
    }

    // Overload status (unauthenticated — for load balancer / monitoring probes)
    if path == "/overload" && method == Method::GET {
        if let Some(ref proxy_state) = state.proxy_state {
            let snapshot = proxy_state.overload.snapshot();
            let status = match snapshot.level {
                crate::overload::OverloadLevel::Normal => StatusCode::OK,
                crate::overload::OverloadLevel::Pressure => StatusCode::OK,
                crate::overload::OverloadLevel::Critical => StatusCode::SERVICE_UNAVAILABLE,
            };
            return Ok(json_response(
                status,
                &serde_json::to_value(&snapshot).unwrap_or_default(),
            ));
        }
        return Ok(json_response(
            StatusCode::OK,
            &json!({"level": "normal", "message": "No proxy state available"}),
        ));
    }

    // Prometheus metrics endpoint (unauthenticated for scraping)
    if path == "/metrics" && method == Method::GET {
        let registry = crate::plugins::prometheus_metrics::global_registry();
        let metrics_output = registry.render();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .header("X-Content-Type-Options", "nosniff")
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::from(metrics_output)))
            .unwrap_or_else(|_| {
                Response::new(Full::new(Bytes::from("# error rendering metrics\n")))
            });
        return Ok(resp);
    }

    // API chargeback endpoint (unauthenticated for scraping, like /metrics)
    if path == "/charges" && method == Method::GET {
        let registry = crate::plugins::api_chargeback::global_registry();
        // Support ?format=json for JSON output, default to Prometheus text format
        let query = req.uri().query().unwrap_or("");
        let use_json = query.contains("format=json");
        if use_json {
            let json_output = registry.render_json();
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-Content-Type-Options", "nosniff")
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::from(json_output)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
            return Ok(resp);
        } else {
            let prom_output = registry.render_prometheus();
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .header("X-Content-Type-Options", "nosniff")
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::from(prom_output)))
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from("# error rendering charges\n")))
                });
            return Ok(resp);
        }
    }

    // Authenticate
    match state.jwt_manager.verify_request(
        req.headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok()),
    ) {
        Ok(_) => {
            // Token is valid, continue processing
        }
        Err(JwtError::MissingHeader) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Missing Authorization header"}),
            ));
        }
        Err(JwtError::InvalidHeaderFormat) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Invalid Authorization header format"}),
            ));
        }
        Err(JwtError::VerificationFailed(msg)) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": format!("Token verification failed: {}", msg)}),
            ));
        }
    }

    // Extract namespace from X-Ferrum-Namespace header (defaults to "ferrum")
    let namespace = match extract_namespace(req.headers()) {
        Ok(ns) => ns,
        Err(resp) => return Ok(resp),
    };

    // Read body with size limit.
    // /restore gets a configurable limit (default 100 MiB) for large-scale
    // backups (30K+ proxies / 90K+ plugins can reach ~80 MB);
    // all other endpoints use the standard 1 MiB limit.
    let restore_max_mib: usize = if path == "/restore" {
        state.admin_restore_max_body_size_mib
    } else {
        1
    };
    let max_body_size = restore_max_mib * 1024 * 1024;
    let body_bytes = match Limited::new(req.into_body(), max_body_size).collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("length limit exceeded") {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &json!({"error": format!("Request body too large (max {} MiB)", restore_max_mib)}),
                ));
            }
            Vec::new()
        }
    };

    // Route
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // Proxies CRUD
        (Method::GET, ["proxies"]) => {
            crud::handle_list::<Proxy>(&state, &pagination, &namespace).await
        }
        (Method::POST, ["proxies"]) => {
            crud::handle_create::<Proxy>(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["proxies", id]) => crud::handle_get::<Proxy>(&state, id, &namespace).await,
        (Method::PUT, ["proxies", id]) => {
            crud::handle_update::<Proxy>(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["proxies", id]) => {
            crud::handle_delete::<Proxy>(&state, id, &namespace).await
        }

        // Consumers CRUD
        (Method::GET, ["consumers"]) => {
            crud::handle_list::<Consumer>(&state, &pagination, &namespace).await
        }
        (Method::POST, ["consumers"]) => {
            crud::handle_create::<Consumer>(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["consumers", id]) => {
            crud::handle_get::<Consumer>(&state, id, &namespace).await
        }
        (Method::PUT, ["consumers", id]) => {
            crud::handle_update::<Consumer>(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["consumers", id]) => {
            crud::handle_delete::<Consumer>(&state, id, &namespace).await
        }

        // Consumer credentials
        (Method::PUT, ["consumers", consumer_id, "credentials", cred_type]) => {
            handle_update_credentials(&state, consumer_id, cred_type, &body_bytes, &namespace).await
        }
        (Method::POST, ["consumers", consumer_id, "credentials", cred_type]) => {
            handle_append_credential(&state, consumer_id, cred_type, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["consumers", consumer_id, "credentials", cred_type, index]) => {
            handle_delete_credential_by_index(&state, consumer_id, cred_type, index, &namespace)
                .await
        }
        (Method::DELETE, ["consumers", consumer_id, "credentials", cred_type]) => {
            handle_delete_credentials(&state, consumer_id, cred_type, &namespace).await
        }

        // Plugins
        (Method::GET, ["plugins"]) => handle_list_plugin_types().await,
        (Method::GET, ["plugins", "config"]) => {
            crud::handle_list::<PluginConfig>(&state, &pagination, &namespace).await
        }
        (Method::POST, ["plugins", "config"]) => {
            crud::handle_create::<PluginConfig>(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["plugins", "config", id]) => {
            crud::handle_get::<PluginConfig>(&state, id, &namespace).await
        }
        (Method::PUT, ["plugins", "config", id]) => {
            crud::handle_update::<PluginConfig>(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["plugins", "config", id]) => {
            crud::handle_delete::<PluginConfig>(&state, id, &namespace).await
        }

        // Upstreams CRUD
        (Method::GET, ["upstreams"]) => {
            crud::handle_list::<Upstream>(&state, &pagination, &namespace).await
        }
        (Method::POST, ["upstreams"]) => {
            crud::handle_create::<Upstream>(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["upstreams", id]) => {
            crud::handle_get::<Upstream>(&state, id, &namespace).await
        }
        (Method::PUT, ["upstreams", id]) => {
            crud::handle_update::<Upstream>(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["upstreams", id]) => {
            crud::handle_delete::<Upstream>(&state, id, &namespace).await
        }

        // Batch create
        (Method::POST, ["batch"]) => handle_batch_create(&state, &body_bytes, &namespace).await,

        // Backup & Restore
        (Method::GET, ["backup"]) => handle_backup(&state, query.as_deref(), &namespace).await,
        (Method::POST, ["restore"]) => {
            handle_restore(&state, &body_bytes, query.as_deref(), &namespace).await
        }

        // Namespaces
        (Method::GET, ["namespaces"]) => handle_list_namespaces(&state).await,

        // Metrics
        (Method::GET, ["admin", "metrics"]) => handle_metrics(&state).await,

        // Cluster status (CP/DP connection info)
        (Method::GET, ["cluster"]) => handle_cluster_status(&state).await,

        // Backend capability registry introspection + refresh.
        //
        // JWT-authenticated (falls through the admin auth gate above).
        // The registry stores only protocol classifications (h1 / h2_tls
        // / h3 / h2c) per deduplicated backend target identity — no
        // secrets, credentials, or payload data — so it's safe to
        // expose permanently in dev, staging, and production. Operators
        // use `GET /backend-capabilities` for routing-decision debugging
        // (why did this H3-capable backend fall back to reqwest?) and
        // `POST /backend-capabilities/refresh` to force an out-of-band
        // reclassification after a deliberate backend change. The
        // scripted-backend test framework also asserts on these
        // endpoints in its H3 acceptance tests.
        (Method::GET, ["backend-capabilities"]) => handle_backend_capabilities_get(&state).await,
        (Method::POST, ["backend-capabilities", "refresh"]) => {
            handle_backend_capabilities_refresh(&state).await
        }

        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Not Found"}),
        )),
    }
}

// ---- Consumer CRUD ----

fn require_db(state: &AdminState) -> Result<&Arc<dyn DatabaseBackend>, Box<Response<Full<Bytes>>>> {
    state.db.as_ref().ok_or_else(|| {
        Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database"}),
        ))
    })
}

fn consumer_not_found_response() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": "Consumer not found"}),
    )
}

fn invalid_credential_type_response(cred_type: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": format!(
            "Unknown credential type '{}'. Allowed types: {:?}",
            cred_type, ALLOWED_CREDENTIAL_TYPES
        )}),
    )
}

fn invalid_credential_fields_response(field_errors: &[String]) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": format!(
            "Invalid credential fields: {}",
            field_errors.join("; ")
        )}),
    )
}

fn parse_json_value(body: &[u8]) -> Result<Value, Box<Response<Full<Bytes>>>> {
    serde_json::from_slice(body).map_err(|e| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid body: {}", e)}),
        ))
    })
}

fn extend_prefixed_errors(
    validation_errors: &mut Vec<String>,
    kind: &str,
    id: &str,
    errors: Vec<String>,
) {
    validation_errors.extend(
        errors
            .into_iter()
            .map(|error| format!("{} '{}': {}", kind, id, error)),
    );
}

fn prepare_batch_items<R: crud::AdminResource>(
    items: &mut [R],
    kind: &str,
    namespace: &str,
    now: chrono::DateTime<Utc>,
    validation_ctx: &crud::ValidationCtx<'_>,
    validation_errors: &mut Vec<String>,
) {
    for item in items {
        if let Err(errors) = crud::prepare_batch_resource(item, namespace, now, validation_ctx) {
            extend_prefixed_errors(validation_errors, kind, item.id(), errors);
        }
    }
}

async fn load_consumer_in_namespace(
    db: &dyn DatabaseBackend,
    consumer_id: &str,
    namespace: &str,
) -> Result<Consumer, Box<Response<Full<Bytes>>>> {
    match db.get_consumer(consumer_id).await {
        Ok(Some(consumer)) if consumer.namespace == namespace => Ok(consumer),
        Ok(Some(_)) | Ok(None) => Err(Box::new(consumer_not_found_response())),
        Err(e) => Err(Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&e),
        ))),
    }
}

fn hash_credential_if_needed(
    cred_type: &str,
    cred_value: &mut Value,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    if cred_type == "basicauth"
        && let Err(e) = crud::hash_basic_auth_credentials(cred_value)
    {
        return Err(Box::new(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": e}),
        )));
    }
    Ok(())
}

async fn ensure_credential_unique(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer_id: &str,
    cred_type: &str,
    cred_value: &Value,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    match crud::check_credential_value_uniqueness(
        db,
        namespace,
        cred_type,
        cred_value,
        Some(consumer_id),
    )
    .await
    {
        Ok(Some(message)) => Err(Box::new(json_response(
            StatusCode::CONFLICT,
            &json!({"error": message}),
        ))),
        Ok(None) => Ok(()),
        Err(e) => Err(Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&e),
        ))),
    }
}

async fn persist_consumer_update(
    db: &dyn DatabaseBackend,
    mut consumer: Consumer,
    success_status: StatusCode,
) -> Response<Full<Bytes>> {
    consumer.updated_at = Utc::now();
    match db.update_consumer(&consumer).await {
        Ok(_) if success_status == StatusCode::NO_CONTENT => {
            json_response(StatusCode::NO_CONTENT, &json!({}))
        }
        Ok(_) => {
            let body = crud::consumer_response_body(&consumer);
            json_response(success_status, &body)
        }
        Err(e) => crud::consumer_persist_error_response(&e),
    }
}

fn apply_payload_namespace(payload: &mut RestorePayload, namespace: &str) {
    for proxy in &mut payload.proxies {
        proxy.namespace = namespace.to_string();
    }
    for consumer in &mut payload.consumers {
        consumer.namespace = namespace.to_string();
    }
    for plugin_config in &mut payload.plugin_configs {
        plugin_config.namespace = namespace.to_string();
    }
    for upstream in &mut payload.upstreams {
        upstream.namespace = namespace.to_string();
    }
}

fn hash_payload_consumers(consumers: &mut [Consumer], errors: &mut Vec<String>) {
    for consumer in consumers {
        if let Err(e) = crud::hash_consumer_credentials(consumer) {
            errors.push(format!("consumer {} secret hashing: {}", consumer.id, e));
        }
    }
}

#[derive(Default)]
struct PersistCounts {
    proxies: usize,
    consumers: usize,
    plugin_configs: usize,
    upstreams: usize,
}

async fn persist_payload_resources(
    db: &dyn DatabaseBackend,
    payload: &RestorePayload,
    halt_on_error: bool,
) -> (PersistCounts, Vec<String>) {
    let mut counts = PersistCounts::default();
    let mut errors = Vec::new();
    let should_continue = |errors: &[String]| !halt_on_error || errors.is_empty();

    if should_continue(&errors) && !payload.consumers.is_empty() {
        match db.batch_create_consumers(&payload.consumers).await {
            Ok(n) => counts.consumers = n,
            Err(e) => errors.push(format!("consumers: {}", e)),
        }
    }
    if should_continue(&errors) && !payload.upstreams.is_empty() {
        match db.batch_create_upstreams(&payload.upstreams).await {
            Ok(n) => counts.upstreams = n,
            Err(e) => errors.push(format!("upstreams: {}", e)),
        }
    }
    if should_continue(&errors) && !payload.proxies.is_empty() {
        match db
            .batch_create_proxies_without_plugins(&payload.proxies)
            .await
        {
            Ok(n) => counts.proxies = n,
            Err(e) => errors.push(format!("proxies: {}", e)),
        }
    }
    if should_continue(&errors) && !payload.plugin_configs.is_empty() {
        match db
            .batch_create_plugin_configs(&payload.plugin_configs)
            .await
        {
            Ok(n) => counts.plugin_configs = n,
            Err(e) => errors.push(format!("plugin_configs: {}", e)),
        }
    }
    if should_continue(&errors)
        && !payload.proxies.is_empty()
        && let Err(e) = db.batch_attach_proxy_plugins(&payload.proxies).await
    {
        errors.push(format!("proxy_plugins: {}", e));
    }

    (counts, errors)
}

/// Allowed credential types for consumer authentication plugins.
pub const ALLOWED_CREDENTIAL_TYPES: &[&str] =
    &["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];

async fn handle_update_credentials(
    state: &AdminState,
    consumer_id: &str,
    cred_type: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    let mut cred_value = match parse_json_value(body) {
        Ok(value) => value,
        Err(resp) => return Ok(*resp),
    };
    if let Err(resp) = hash_credential_if_needed(cred_type, &mut cred_value) {
        return Ok(*resp);
    }
    if let Err(resp) =
        ensure_credential_unique(db.as_ref(), namespace, consumer_id, cred_type, &cred_value).await
    {
        return Ok(*resp);
    }

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    consumer
        .credentials
        .insert(cred_type.to_string(), cred_value);

    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(invalid_credential_fields_response(&field_errors));
    }

    Ok(persist_consumer_update(db.as_ref(), consumer, StatusCode::OK).await)
}

async fn handle_delete_credentials(
    state: &AdminState,
    consumer_id: &str,
    cred_type: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    consumer.credentials.remove(cred_type);
    Ok(persist_consumer_update(db.as_ref(), consumer, StatusCode::NO_CONTENT).await)
}

/// POST /consumers/:id/credentials/:type — Append a credential entry for zero-downtime rotation.
async fn handle_append_credential(
    state: &AdminState,
    consumer_id: &str,
    cred_type: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    let mut new_cred = match parse_json_value(body) {
        Ok(value) => value,
        Err(resp) => return Ok(*resp),
    };
    if !new_cred.is_object() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential entry must be a JSON object"}),
        ));
    }
    if let Err(resp) = hash_credential_if_needed(cred_type, &mut new_cred) {
        return Ok(*resp);
    }
    if let Err(resp) =
        ensure_credential_unique(db.as_ref(), namespace, consumer_id, cred_type, &new_cred).await
    {
        return Ok(*resp);
    }

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    let new_value = match consumer.credentials.get(cred_type) {
        Some(Value::Array(arr)) => {
            let mut new_arr = arr.clone();
            new_arr.push(new_cred);
            Value::Array(new_arr)
        }
        Some(existing) if existing.is_object() => Value::Array(vec![existing.clone(), new_cred]),
        _ => new_cred,
    };

    let limit = max_credentials_per_type();
    if let Value::Array(ref arr) = new_value
        && arr.len() > limit
    {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "Cannot exceed {} credentials per type (currently {})",
                limit, arr.len()
            )}),
        ));
    }
    consumer
        .credentials
        .insert(cred_type.to_string(), new_value);

    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(invalid_credential_fields_response(&field_errors));
    }

    Ok(persist_consumer_update(db.as_ref(), consumer, StatusCode::OK).await)
}

/// DELETE /consumers/:id/credentials/:type/:index — Remove a specific credential entry by index.
///
/// When the array has one remaining element after removal, it is collapsed back to a single object.
async fn handle_delete_credential_by_index(
    state: &AdminState,
    consumer_id: &str,
    cred_type: &str,
    index_str: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let index: usize = match index_str.parse() {
        Ok(i) => i,
        Err(_) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Invalid credential index — must be a non-negative integer"}),
            ));
        }
    };

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    let cred_value = match consumer.credentials.get_mut(cred_type) {
        Some(value) => value,
        None => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": format!("No '{}' credentials found", cred_type)}),
            ));
        }
    };

    match cred_value {
        Value::Array(arr) => {
            if index >= arr.len() {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": format!(
                        "Credential index {} out of range (have {} entries)",
                        index, arr.len()
                    )}),
                ));
            }
            arr.remove(index);
            if arr.len() == 1 {
                let single = arr.remove(0);
                consumer.credentials.insert(cred_type.to_string(), single);
            } else if arr.is_empty() {
                consumer.credentials.remove(cred_type);
            }
        }
        Value::Object(_) => {
            if index != 0 {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": format!(
                        "Credential index {} out of range (have 1 entry)",
                        index
                    )}),
                ));
            }
            consumer.credentials.remove(cred_type);
        }
        _ => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": format!("No '{}' credentials found", cred_type)}),
            ));
        }
    }

    Ok(persist_consumer_update(db.as_ref(), consumer, StatusCode::OK).await)
}

// ---- Plugin CRUD ----

async fn handle_list_plugin_types() -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(json_response(
        StatusCode::OK,
        &json!(plugins::available_plugins()),
    ))
}

fn validate_plugin_config_definition(pc: &PluginConfig) -> Result<(), String> {
    match plugins::create_plugin(&pc.plugin_name, &pc.config) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("Unknown plugin name '{}'", pc.plugin_name)),
        Err(err) => Err(err),
    }
}

// ---- Metrics ----

use std::sync::OnceLock;
use std::time::Duration;

/// Process-global cache for the metrics JSON response.
static METRICS_CACHE: OnceLock<arc_swap::ArcSwap<Option<(Instant, Bytes)>>> = OnceLock::new();

fn metrics_cache() -> &'static arc_swap::ArcSwap<Option<(Instant, Bytes)>> {
    METRICS_CACHE.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(None)))
}

/// Cache TTL for the metrics response.
const METRICS_CACHE_TTL: Duration = Duration::from_secs(5);

async fn handle_metrics(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let cache = metrics_cache();
    let cached = cache.load();
    if let Some((cached_at, ref bytes)) = **cached
        && cached_at.elapsed() < METRICS_CACHE_TTL
    {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("X-Cache", "hit")
            .header("X-Content-Type-Options", "nosniff")
            .header("Cache-Control", "no-store")
            .header("X-Frame-Options", "DENY")
            .body(Full::new(bytes.clone()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
        return Ok(resp);
    }

    let metrics = build_metrics(state);
    let body_str = serde_json::to_string(&metrics).unwrap_or_else(|_| "{}".into());
    let body_bytes = Bytes::from(body_str);

    cache.store(Arc::new(Some((Instant::now(), body_bytes.clone()))));

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("X-Cache", "miss")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(body_bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
    Ok(resp)
}

fn build_metrics(state: &AdminState) -> Value {
    if let Some(ref ps) = state.proxy_state {
        let config = ps.current_config();
        let rps = ps.request_count.load(Ordering::Relaxed);
        let uptime_seconds = ps.started_at.elapsed().as_secs();

        // Status codes
        let mut status_codes = serde_json::Map::new();
        for entry in ps.status_counts.iter() {
            status_codes.insert(
                entry.key().to_string(),
                json!(entry.value().load(Ordering::Relaxed)),
            );
        }

        // Connection pools
        let http_pool_stats = ps.connection_pool.get_stats();
        let grpc_pool_size = ps.grpc_pool.pool_size();
        let http2_pool_size = ps.http2_pool.pool_size();
        let h3_pool_size = ps.h3_pool.pool_size();

        // Circuit breakers
        let cb_snapshot = ps.circuit_breaker_cache.snapshot();
        let circuit_breakers: Vec<Value> = cb_snapshot
            .iter()
            .map(|(key, state, failures, successes)| {
                // Keys are "proxy_id" (direct backend) or "proxy_id::host:port" (upstream target)
                if let Some((proxy_id, target)) = key.split_once("::") {
                    json!({
                        "proxy_id": proxy_id,
                        "target": target,
                        "state": state,
                        "failure_count": failures,
                        "success_count": successes,
                    })
                } else {
                    json!({
                        "proxy_id": key,
                        "state": state,
                        "failure_count": failures,
                        "success_count": successes,
                    })
                }
            })
            .collect();

        // Health check — merge active (upstream-scoped) and passive (proxy-scoped) maps
        let mut unhealthy_targets: Vec<Value> = ps
            .health_checker
            .active_unhealthy_targets
            .iter()
            .map(|entry| {
                json!({
                    "target": entry.key().clone(),
                    "type": "active",
                    "since_epoch_ms": *entry.value(),
                })
            })
            .collect();
        for proxy_entry in ps.health_checker.passive_health.iter() {
            let proxy_id = proxy_entry.key();
            for target_entry in proxy_entry.value().unhealthy.iter() {
                unhealthy_targets.push(json!({
                    "proxy_id": proxy_id.clone(),
                    "target": target_entry.key().clone(),
                    "type": "passive",
                    "since_epoch_ms": *target_entry.value(),
                }));
            }
        }

        // Load balancers
        let lb_snapshot = ps.load_balancer_cache.active_connections_snapshot();
        let mut lb_map = serde_json::Map::new();
        for (upstream_id, targets) in &lb_snapshot {
            let mut target_map = serde_json::Map::new();
            for (target, count) in targets {
                target_map.insert(target.clone(), json!(count));
            }
            lb_map.insert(upstream_id.clone(), Value::Object(target_map));
        }

        // Router cache
        let (prefix_entries, regex_entries, prefix_evictions, regex_evictions, max_entries) =
            ps.router_cache.cache_stats();

        // DNS cache
        let dns_cache_size = ps.dns_cache.cache_len();

        // Consumer index
        let (
            keyauth_count,
            basic_count,
            mtls_count,
            jwt_count,
            hmac_count,
            identity_count,
            total_consumers,
        ) = ps.consumer_index.auth_type_counts();

        // Rate limiter keys
        let rate_limiter_keys = ps.plugin_cache.total_rate_limiter_keys();

        // Config source
        let config_source_status = if state.db.is_some() { "online" } else { "n/a" };

        // Windowed per-second status code rates
        let mut sc_per_second = serde_json::Map::new();
        for entry in ps.windowed_metrics.status_codes_per_second.iter() {
            sc_per_second.insert(
                entry.key().to_string(),
                json!(entry.value().load(Ordering::Relaxed)),
            );
        }

        json!({
            "gateway": {
                "mode": state.mode,
                "ferrum_version": crate::FERRUM_VERSION,
                "uptime_seconds": uptime_seconds,
                "total_requests": rps,
                "status_codes_total": status_codes,
                "requests_per_second": ps.windowed_metrics.requests_per_second.load(Ordering::Relaxed),
                "status_codes_per_second": Value::Object(sc_per_second),
                "metrics_window_seconds": ps.windowed_metrics.window_seconds,
                "config_last_updated_at": config.loaded_at.to_rfc3339(),
                "config_source_status": config_source_status,
                "proxy_count": config.proxies.len(),
                "consumer_count": config.consumers.len(),
                "upstream_count": config.upstreams.len(),
                "plugin_config_count": config.plugin_configs.len(),
            },
            "connection_pools": {
                "http": {
                    "total_pools": http_pool_stats.total_pools,
                    "max_idle_per_host": http_pool_stats.max_idle_per_host,
                    "idle_timeout_seconds": http_pool_stats.idle_timeout_seconds,
                    "entries_per_host": http_pool_stats.entries_per_host,
                },
                "grpc": {
                    "total_connections": grpc_pool_size,
                },
                "http2": {
                    "total_connections": http2_pool_size,
                },
                "http3": {
                    "total_connections": h3_pool_size,
                },
            },
            "circuit_breakers": circuit_breakers,
            "health_check": {
                "unhealthy_target_count": unhealthy_targets.len(),
                "unhealthy_targets": unhealthy_targets,
            },
            "load_balancers": {
                "active_connections": Value::Object(lb_map),
            },
            "caches": {
                "router": {
                    "prefix_cache_entries": prefix_entries,
                    "regex_cache_entries": regex_entries,
                    "prefix_eviction_count": prefix_evictions,
                    "regex_eviction_count": regex_evictions,
                    "max_cache_entries": max_entries,
                },
                "dns": {
                    "cache_entries": dns_cache_size,
                },
            },
            "consumer_index": {
                "total_consumers": total_consumers,
                "key_auth_credentials": keyauth_count,
                "basic_auth_credentials": basic_count,
                "mtls_credentials": mtls_count,
                "jwt_credentials": jwt_count,
                "hmac_credentials": hmac_count,
                "identity_credentials": identity_count,
            },
            "rate_limiting": {
                "tracked_key_count": rate_limiter_keys,
            },
        })
    } else {
        // CP mode or no proxy state
        json!({
            "gateway": {
                "mode": state.mode,
                "ferrum_version": crate::FERRUM_VERSION,
                "uptime_seconds": 0,
                "total_requests": 0,
                "status_codes_total": {},
                "requests_per_second": 0,
                "status_codes_per_second": {},
                "metrics_window_seconds": 0,
                "config_last_updated_at": null,
                "config_source_status": "n/a",
                "proxy_count": 0,
                "consumer_count": 0,
                "upstream_count": 0,
                "plugin_config_count": 0,
            },
            "connection_pools": {},
            "circuit_breakers": [],
            "health_check": {"unhealthy_target_count": 0, "unhealthy_targets": []},
            "load_balancers": {"active_connections": {}},
            "caches": {},
            "consumer_index": {"total_consumers": 0, "key_auth_credentials": 0, "basic_auth_credentials": 0, "mtls_credentials": 0, "jwt_credentials": 0, "hmac_credentials": 0, "identity_credentials": 0},
            "rate_limiting": {"tracked_key_count": 0},
        })
    }
}

// ---- Batch Create ----

/// Batch create endpoint for proxies, consumers, plugin configs, and upstreams.
async fn handle_batch_create(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    if let Err(message) = check_legacy_proxy_fields(body) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let mut batch: RestorePayload = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid JSON body: {}", e)}),
            ));
        }
    };

    let now = Utc::now();
    let validation_ctx = crud::ValidationCtx::from_state(state);
    let known_plugins = crate::plugins::available_plugins();
    let mut validation_errors: Vec<String> = Vec::new();

    prepare_batch_items(
        &mut batch.consumers,
        "Consumer",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    );
    prepare_batch_items(
        &mut batch.upstreams,
        "Upstream",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    );
    prepare_batch_items(
        &mut batch.proxies,
        "Proxy",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    );
    prepare_batch_items(
        &mut batch.plugin_configs,
        "PluginConfig",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    );

    for plugin_config in &batch.plugin_configs {
        if !known_plugins.contains(&plugin_config.plugin_name.as_str()) {
            validation_errors.push(format!(
                "PluginConfig '{}': unknown plugin name '{}'",
                plugin_config.id, plugin_config.plugin_name
            ));
        }
        if let Err(err) = validate_plugin_config_definition(plugin_config) {
            validation_errors.push(format!(
                "PluginConfig '{}': invalid config: {}",
                plugin_config.id, err
            ));
        }
    }

    // Cross-resource validations require a GatewayConfig view over the batch.
    // Individual items are already normalized and field-validated above, so skip
    // normalize_fields() and validate_all_fields() to avoid redundant work.
    let mut batch_config = GatewayConfig {
        version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: batch.proxies.clone(),
        consumers: batch.consumers.clone(),
        plugin_configs: batch.plugin_configs.clone(),
        upstreams: batch.upstreams.clone(),
        loaded_at: now,
        known_namespaces: Vec::new(),
    };

    match ValidationPipeline::new(&mut batch_config)
        .validate_unique_resource_ids(ValidationAction::Collect)
        .validate_unique_consumer_identities(ValidationAction::Collect)
        .validate_unique_consumer_credentials(ValidationAction::Collect)
        .validate_unique_upstream_names(ValidationAction::Collect)
        .validate_unique_proxy_names(ValidationAction::Collect)
        .validate_hosts(ValidationAction::Collect)
        .validate_regex_listen_paths(ValidationAction::Collect)
        .validate_unique_listen_paths(ValidationAction::Collect)
        .validate_stream_proxies(ValidationAction::Collect)
        .run()
    {
        Ok(errs) => validation_errors.extend(errs),
        Err(err) => validation_errors.push(err.to_string()),
    }

    let batch_proxy_ids: HashSet<&str> = batch
        .proxies
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    let batch_upstream_ids: HashSet<&str> = batch
        .upstreams
        .iter()
        .map(|upstream| upstream.id.as_str())
        .collect();
    let batch_plugin_configs: std::collections::HashMap<&str, &PluginConfig> = batch
        .plugin_configs
        .iter()
        .map(|plugin_config| (plugin_config.id.as_str(), plugin_config))
        .collect();

    for proxy in &batch.proxies {
        if let Some(upstream_id) = proxy.upstream_id.as_deref()
            && !batch_upstream_ids.contains(upstream_id)
        {
            match db.check_upstream_exists(upstream_id).await {
                Ok(true) => {}
                Ok(false) => validation_errors.push(format!(
                    "Proxy '{}' references non-existent upstream_id '{}'",
                    proxy.id, upstream_id
                )),
                Err(err) => validation_errors.push(format!(
                    "Proxy '{}' upstream reference check failed: {}",
                    proxy.id, err
                )),
            }
        }

        let mut unresolved = Vec::new();

        for assoc in &proxy.plugins {
            match batch_plugin_configs.get(assoc.plugin_config_id.as_str()) {
                Some(plugin_config) => match plugin_config.scope {
                    PluginScope::Global => {
                        validation_errors.push(format!(
                            "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped or proxy_group-scoped plugin configs",
                            proxy.id, plugin_config.id
                        ));
                        continue;
                    }
                    PluginScope::Proxy => {
                        if plugin_config.proxy_id.as_deref() != Some(proxy.id.as_str()) {
                            validation_errors.push(format!(
                                "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                proxy.id,
                                plugin_config.id,
                                plugin_config.proxy_id.as_deref().unwrap_or("<none>")
                            ));
                        }
                    }
                    PluginScope::ProxyGroup => {
                        // ProxyGroup plugins have no proxy_id — any proxy can
                        // reference them via its plugins association list.
                    }
                },
                None => unresolved.push(assoc.clone()),
            }
        }

        if !unresolved.is_empty() {
            match db
                .validate_proxy_plugin_associations(&proxy.id, &unresolved)
                .await
            {
                Ok(errs) => validation_errors.extend(errs),
                Err(err) => validation_errors.push(format!(
                    "Proxy '{}' plugin association check failed: {}",
                    proxy.id, err
                )),
            }
        }
    }

    for plugin_config in &batch.plugin_configs {
        if let Some(proxy_id) = plugin_config.proxy_id.as_deref()
            && !batch_proxy_ids.contains(proxy_id)
        {
            match db.check_proxy_exists(proxy_id).await {
                Ok(true) => {}
                Ok(false) => validation_errors.push(format!(
                    "PluginConfig '{}' references non-existent proxy_id '{}'",
                    plugin_config.id, proxy_id
                )),
                Err(err) => validation_errors.push(format!(
                    "PluginConfig '{}' proxy reference check failed: {}",
                    plugin_config.id, err
                )),
            }
        }
    }

    if !validation_errors.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": "Batch validation failed",
                "validation_errors": validation_errors
            }),
        ));
    }

    let (created, errors) = persist_payload_resources(db.as_ref(), &batch, true).await;

    let mut response = json!({
        "created": {
            "proxies": created.proxies,
            "consumers": created.consumers,
            "plugin_configs": created.plugin_configs,
            "upstreams": created.upstreams,
        }
    });

    if !errors.is_empty() {
        response["errors"] = json!(errors);
        return Ok(json_response(StatusCode::MULTI_STATUS, &response));
    }

    Ok(json_response(StatusCode::CREATED, &response))
}

// ---- Backup & Restore ----

/// Export the current gateway config as a JSON backup payload.
async fn handle_backup(
    state: &AdminState,
    query: Option<&str>,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let resource_filter = parse_backup_resources(query);

    // Try database first, then cached config
    let (config, source) = if let Some(ref db) = state.db {
        match db.load_full_config(namespace).await {
            Ok(config) => (config, "database"),
            Err(e) => {
                warn!("Backup: database load failed, trying cached config: {}", e);
                match state.cached_gateway_config() {
                    Some(c) => (filter_config_by_namespace(&c, namespace), "cached"),
                    None => {
                        return Ok(json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &json!({"error": "Database unavailable and no cached config"}),
                        ));
                    }
                }
            }
        }
    } else {
        match state.cached_gateway_config() {
            Some(c) => (filter_config_by_namespace(&c, namespace), "cached"),
            None => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": "No database configured and no cached config available"}),
                ));
            }
        }
    };

    // Determine which resource types to include
    let include_proxies = resource_filter
        .as_ref()
        .is_none_or(|f| f.contains("proxies"));
    let include_consumers = resource_filter
        .as_ref()
        .is_none_or(|f| f.contains("consumers"));
    let include_plugin_configs = resource_filter
        .as_ref()
        .is_none_or(|f| f.contains("plugin_configs"));
    let include_upstreams = resource_filter
        .as_ref()
        .is_none_or(|f| f.contains("upstreams"));

    let empty_proxies: Vec<Proxy> = Vec::new();
    let empty_consumers: Vec<Consumer> = Vec::new();
    let empty_plugin_configs: Vec<PluginConfig> = Vec::new();
    let empty_upstreams: Vec<Upstream> = Vec::new();

    let proxies = if include_proxies {
        config.proxies.as_slice()
    } else {
        empty_proxies.as_slice()
    };
    let consumers = if include_consumers {
        config.consumers.as_slice()
    } else {
        empty_consumers.as_slice()
    };
    let plugin_configs = if include_plugin_configs {
        config.plugin_configs.as_slice()
    } else {
        empty_plugin_configs.as_slice()
    };
    let upstreams = if include_upstreams {
        config.upstreams.as_slice()
    } else {
        empty_upstreams.as_slice()
    };

    let backup = BackupPayload {
        version: &config.version,
        ferrum_version: crate::FERRUM_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        source,
        counts: BackupCounts {
            proxies: proxies.len(),
            consumers: consumers.len(),
            plugin_configs: plugin_configs.len(),
            upstreams: upstreams.len(),
        },
        proxies,
        consumers,
        plugin_configs,
        upstreams,
    };

    // Serialize directly to bytes — no intermediate Value allocation.
    let body_bytes = serde_json::to_vec(&backup).unwrap_or_else(|_| b"{}".to_vec());
    info!(
        "Backup: {} proxies, {} consumers, {} plugin_configs, {} upstreams ({} bytes)",
        proxies.len(),
        consumers.len(),
        plugin_configs.len(),
        upstreams.len(),
        body_bytes.len()
    );

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header(
            "Content-Disposition",
            "attachment; filename=\"ferrum-backup.json\"",
        )
        .header("X-Data-Source", source)
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        });
    Ok(resp)
}

/// Restore the gateway configuration from a backup payload.
async fn handle_restore(
    state: &AdminState,
    body: &[u8],
    query: Option<&str>,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };

    if !parse_restore_confirm(query) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": "Restore is a destructive operation that replaces all existing configuration. Pass ?confirm=true to proceed."
            }),
        ));
    }

    // Pre-check: reject legacy `backend_protocol` keys before we touch any
    // existing config. `/restore` is destructive (deletes before re-inserting)
    // and the scheme refactor makes `backend_protocol` a silent default
    // otherwise — operators restoring an old backup would get a different
    // config shape than the one they exported.
    if let Err(message) = check_legacy_proxy_fields(body) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    // Phase 1: Parse all resources directly into typed structs before deleting
    // anything. This avoids an intermediate serde_json::Value copy (~50% less
    // peak memory at scale).
    let payload: RestorePayload = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid JSON body: {}", e)}),
            ));
        }
    };

    // Validate config version compatibility when present
    if !payload.version.is_empty()
        && payload.version != crate::config::types::CURRENT_CONFIG_VERSION
    {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": format!(
                    "Incompatible config version '{}'. This gateway expects version '{}'",
                    payload.version,
                    crate::config::types::CURRENT_CONFIG_VERSION
                )
            }),
        ));
    }

    info!(
        "Restore: parsed payload — {} proxies, {} consumers, {} plugin_configs, {} upstreams ({} bytes)",
        payload.proxies.len(),
        payload.consumers.len(),
        payload.plugin_configs.len(),
        payload.upstreams.len(),
        body.len()
    );

    // Phase 2: Validate payload BEFORE deleting anything.
    // Assemble a temporary GatewayConfig and run the same validations as file mode.
    {
        let mut temp_config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies: payload.proxies.clone(),
            consumers: payload.consumers.clone(),
            plugin_configs: payload.plugin_configs.clone(),
            upstreams: payload.upstreams.clone(),
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
        };
        temp_config.normalize_fields();
        // Set namespace on all resources
        for p in &mut temp_config.proxies {
            p.namespace = namespace.to_string();
        }
        for c in &mut temp_config.consumers {
            c.namespace = namespace.to_string();
        }
        for pc in &mut temp_config.plugin_configs {
            pc.namespace = namespace.to_string();
        }
        for u in &mut temp_config.upstreams {
            u.namespace = namespace.to_string();
        }
        let mut validation_errors: Vec<String> = Vec::new();

        let cert_expiry_days = state
            .proxy_state
            .as_ref()
            .map(|ps| ps.env_config.tls_cert_expiry_warning_days)
            .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS);
        match ValidationPipeline::new(&mut temp_config)
            .validate_all_fields(cert_expiry_days, ValidationAction::Collect)
            .validate_unique_resource_ids(ValidationAction::Collect)
            .validate_unique_consumer_identities(ValidationAction::Collect)
            .validate_unique_consumer_credentials(ValidationAction::Collect)
            .validate_hosts(ValidationAction::Collect)
            .validate_regex_listen_paths(ValidationAction::Collect)
            .validate_unique_listen_paths(ValidationAction::Collect)
            .validate_stream_proxies(ValidationAction::Collect)
            .validate_upstream_references(ValidationAction::Collect)
            .validate_plugin_references(ValidationAction::Collect)
            .run()
        {
            Ok(errs) => validation_errors.extend(errs),
            Err(err) => validation_errors.push(err.to_string()),
        }
        if !validation_errors.is_empty() {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({
                    "error": "Restore payload validation failed — existing config was NOT deleted",
                    "validation_errors": validation_errors
                }),
            ));
        }
    }

    // Phase 3: Delete all existing resources in the namespace (safe: payload is validated)
    if let Err(e) = db.delete_all_resources(namespace).await {
        error!("Restore: failed to delete existing resources: {}", e);
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("Failed to clear existing config: {}", e)}),
        ));
    }

    info!("Restore: cleared existing config, beginning import");

    // Phase 3: Import resources in dependency order.
    // Each batch_create_* method internally chunks into 1,000-record
    // transactions to keep WAL/redo size bounded.
    let mut payload = payload;
    let mut errors = Vec::new();
    apply_payload_namespace(&mut payload, namespace);
    hash_payload_consumers(&mut payload.consumers, &mut errors);
    let (created, mut persist_errors) =
        persist_payload_resources(db.as_ref(), &payload, false).await;
    errors.append(&mut persist_errors);

    info!(
        "Restore: imported {} proxies, {} consumers, {} plugin_configs, {} upstreams",
        created.proxies, created.consumers, created.plugin_configs, created.upstreams
    );

    let mut response = json!({
        "restored": {
            "proxies": created.proxies,
            "consumers": created.consumers,
            "plugin_configs": created.plugin_configs,
            "upstreams": created.upstreams,
        }
    });

    if !errors.is_empty() {
        response["errors"] = json!(errors);
        return Ok(json_response(StatusCode::MULTI_STATUS, &response));
    }

    Ok(json_response(StatusCode::OK, &response))
}

// ---- Namespaces ----

async fn handle_list_namespaces(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match db.list_namespaces().await {
            Ok(namespaces) => Ok(json_response(StatusCode::OK, &json!(namespaces))),
            Err(e) => Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": format!("Failed to list namespaces: {}", e)}),
            )),
        }
    } else if let Some(config) = state.cached_gateway_config() {
        // File mode: return namespaces captured at load time (before namespace filtering)
        Ok(json_response(
            StatusCode::OK,
            &json!(config.known_namespaces),
        ))
    } else {
        Ok(json_response(
            StatusCode::OK,
            &json!([crate::config::types::DEFAULT_NAMESPACE]),
        ))
    }
}

// ---- Helpers ----

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body_str)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
}

/// JSON response with X-Data-Source: cached header to indicate stale/cached data.
fn json_response_with_stale(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("X-Data-Source", "cached")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body_str)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
}

/// Log a database error internally and return a generic error body for the client.
/// Avoids leaking database schema details in API responses.
fn db_error_response(e: &dyn std::fmt::Display) -> Value {
    warn!("Database error in admin API: {}", e);
    json!({"error": "Database unavailable — operation failed"})
}

/// Check if a database error message indicates a unique constraint violation.
///
/// Covers SQLite ("UNIQUE constraint failed"), PostgreSQL ("duplicate key value
/// violates unique constraint"), and MySQL ("Duplicate entry").
fn is_unique_constraint_violation(error_msg: &str) -> bool {
    let lower = error_msg.to_lowercase();
    lower.contains("unique constraint")
        || lower.contains("duplicate key")
        || lower.contains("duplicate entry")
}

/// Create a copy of the consumer with sensitive credential values redacted
/// for safe inclusion in API responses.
pub fn redact_consumer_credentials(consumer: &Consumer) -> Consumer {
    crate::config::types::redact_consumer_credentials(consumer)
}

fn hash_consumer_secrets(consumer: &mut Consumer) -> Result<(), String> {
    crate::config::types::hash_consumer_secrets(consumer)
}

/// Hash passwords in a basicauth credential value (single object or array).
/// Used by `handle_update_credentials()` where the credential type is already known.
fn hash_credential_passwords(cred: &mut serde_json::Value) -> Result<(), String> {
    crate::config::types::hash_credential_passwords(cred)
}

/// Best-effort OS-level port availability check for stream proxy listeners.
async fn check_port_available(port: u16, bind_address: &str, udp: bool) -> Result<(), String> {
    let ip: std::net::IpAddr = bind_address
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let addr = std::net::SocketAddr::new(ip, port);

    if udp {
        if let Err(e) = tokio::net::UdpSocket::bind(addr).await {
            return Err(format!("UDP bind failed: {}", e));
        }
    } else {
        if let Err(e) = tokio::net::TcpListener::bind(addr).await {
            return Err(format!("TCP bind failed: {}", e));
        }
    }
    Ok(())
}

// ---- Cluster Status ----

async fn handle_cluster_status(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match state.mode.as_str() {
        "cp" => {
            if let Some(ref registry) = state.dp_registry {
                let nodes = registry.snapshot();
                let connected_count = nodes.len();
                let node_details: Vec<serde_json::Value> = nodes
                    .iter()
                    .map(|n| {
                        json!({
                            "node_id": n.node_id,
                            "version": n.version,
                            "namespace": n.namespace,
                            "status": "online",
                            "connected_at": n.connected_at.to_rfc3339(),
                            "last_sync_at": n.last_update_at.to_rfc3339(),
                        })
                    })
                    .collect();
                Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "mode": "cp",
                        "connected_data_planes": connected_count,
                        "data_planes": node_details,
                    }),
                ))
            } else {
                Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "mode": "cp",
                        "connected_data_planes": 0,
                        "data_planes": [],
                    }),
                ))
            }
        }
        "dp" => {
            if let Some(ref cs) = state.cp_connection_state {
                let snap = cs.load();
                let status = if snap.connected { "online" } else { "offline" };
                Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "mode": "dp",
                        "control_plane": {
                            "url": snap.cp_url,
                            "status": status,
                            "is_primary": snap.is_primary,
                            "connected_since": snap.connected_since.map(|t| t.to_rfc3339()),
                            "last_config_received_at": snap.last_config_received_at.map(|t| t.to_rfc3339()),
                        },
                    }),
                ))
            } else {
                Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "mode": "dp",
                        "control_plane": null,
                    }),
                ))
            }
        }
        _ => Ok(json_response(
            StatusCode::OK,
            &json!({
                "mode": state.mode,
                "message": "Cluster status is only available in cp or dp modes",
            }),
        )),
    }
}

// ---- Backend Capability Registry ----
//
// JWT-authenticated handlers exposing the per-backend-target protocol
// classification cache documented in `src/proxy/backend_capabilities.rs`.
// See `docs/admin_api.md` for operator-facing semantics and
// `openapi.yaml` for the request / response schemas.

async fn handle_backend_capabilities_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let proxy_state = match &state.proxy_state {
        Some(ps) => ps,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "proxy_state unavailable in this mode"}),
            ));
        }
    };
    let snapshot = proxy_state.backend_capabilities.snapshot();
    let entries: Vec<serde_json::Value> = snapshot
        .into_iter()
        .map(|(key, record)| {
            json!({
                "key": key,
                "plain_http": {
                    "h1": protocol_support_label(record.plain_http.h1),
                    "h2_tls": protocol_support_label(record.plain_http.h2_tls),
                    "h3": protocol_support_label(record.plain_http.h3),
                },
                "grpc_transport": {
                    "h2_tls": protocol_support_label(record.grpc_transport.h2_tls),
                    "h2c": protocol_support_label(record.grpc_transport.h2c),
                },
                "last_probe_at_unix_secs": record.last_probe_at_unix_secs,
                "last_probe_error": record.last_probe_error.clone(),
            })
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "entries": entries,
        }),
    ))
}

async fn handle_backend_capabilities_refresh(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let proxy_state = match &state.proxy_state {
        Some(ps) => ps,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "proxy_state unavailable in this mode"}),
            ));
        }
    };
    // Run synchronously so the caller can assert on the post-refresh
    // snapshot immediately. The request handler is already on a tokio
    // worker task so .await is fine.
    proxy_state.refresh_backend_capabilities().await;
    Ok(json_response(
        StatusCode::OK,
        &json!({"status": "refreshed"}),
    ))
}

fn protocol_support_label(
    support: crate::proxy::backend_capabilities::ProtocolSupport,
) -> &'static str {
    use crate::proxy::backend_capabilities::ProtocolSupport;
    match support {
        ProtocolSupport::Unknown => "unknown",
        ProtocolSupport::Supported => "supported",
        ProtocolSupport::Unsupported => "unsupported",
    }
}
