//! Admin API for Ferrum Edge
//!
//! Provides REST API for managing proxies, consumers, and plugins
//! with JWT-based authentication and authorization.

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
use uuid::Uuid;

use crate::admin::jwt_auth::{JwtError, JwtManager};
use crate::config::db_backend::DatabaseBackend;
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream, max_credentials_per_type,
    validate_resource_id,
};
use crate::grpc::cp_server::DpNodeRegistry;
use crate::grpc::dp_client::DpCpConnectionState;
use crate::plugins;
use crate::proxy::ProxyState;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

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
struct PaginationParams {
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
                health_status["database"] = json!({
                    "status": "connected",
                    "type": db.db_type()
                });
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
        (Method::GET, ["proxies"]) => handle_list_proxies(&state, &pagination, &namespace).await,
        (Method::POST, ["proxies"]) => handle_create_proxy(&state, &body_bytes, &namespace).await,
        (Method::GET, ["proxies", id]) => handle_get_proxy(&state, id, &namespace).await,
        (Method::PUT, ["proxies", id]) => {
            handle_update_proxy(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["proxies", id]) => handle_delete_proxy(&state, id, &namespace).await,

        // Consumers CRUD
        (Method::GET, ["consumers"]) => {
            handle_list_consumers(&state, &pagination, &namespace).await
        }
        (Method::POST, ["consumers"]) => {
            handle_create_consumer(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["consumers", id]) => handle_get_consumer(&state, id, &namespace).await,
        (Method::PUT, ["consumers", id]) => {
            handle_update_consumer(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["consumers", id]) => handle_delete_consumer(&state, id, &namespace).await,

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
            handle_list_plugin_configs(&state, &pagination, &namespace).await
        }
        (Method::POST, ["plugins", "config"]) => {
            handle_create_plugin_config(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["plugins", "config", id]) => {
            handle_get_plugin_config(&state, id, &namespace).await
        }
        (Method::PUT, ["plugins", "config", id]) => {
            handle_update_plugin_config(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["plugins", "config", id]) => {
            handle_delete_plugin_config(&state, id, &namespace).await
        }

        // Upstreams CRUD
        (Method::GET, ["upstreams"]) => {
            handle_list_upstreams(&state, &pagination, &namespace).await
        }
        (Method::POST, ["upstreams"]) => {
            handle_create_upstream(&state, &body_bytes, &namespace).await
        }
        (Method::GET, ["upstreams", id]) => handle_get_upstream(&state, id, &namespace).await,
        (Method::PUT, ["upstreams", id]) => {
            handle_update_upstream(&state, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["upstreams", id]) => handle_delete_upstream(&state, id, &namespace).await,

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

        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Not Found"}),
        )),
    }
}

// ---- Proxy CRUD ----

async fn handle_list_proxies(
    state: &AdminState,
    pagination: &PaginationParams,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database-level pagination first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db
            .list_proxies_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
            .await
        {
            Ok(result) => {
                let body = paginate_db_response(&result.items, result.total, pagination);
                return Ok(json_response(StatusCode::OK, &body));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for list proxies, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: serve from in-memory cached config
    if let Some(config) = state.cached_gateway_config() {
        let filtered: Vec<&Proxy> = config
            .proxies
            .iter()
            .filter(|p| p.namespace == namespace)
            .collect();
        let body = paginate_response(&json!(filtered), pagination);
        Ok(json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_create_proxy(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    // Validate and normalize allowed_methods
    if let Some(ref mut methods) = proxy.allowed_methods {
        for m in methods.iter_mut() {
            *m = m.to_uppercase();
        }
    }

    proxy.normalize_fields();
    proxy.namespace = namespace.to_string();

    // Validate field lengths, numeric ranges, and nested config objects.
    if let Err(field_errors) = proxy.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid proxy fields: {}", field_errors.join("; "))}),
        ));
    }

    // Validate host entries directly (no GatewayConfig wrapper needed for single-proxy paths).
    for host in &proxy.hosts {
        if let Err(msg) = crate::config::types::validate_host_entry(host) {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid proxy hosts: {}", msg)}),
            ));
        }
    }
    if !proxy.backend_protocol.is_stream_proxy() && proxy.listen_path.starts_with('~') {
        let pattern = &proxy.listen_path[1..];
        if !pattern.is_empty() {
            let anchored = crate::config::types::anchor_regex_pattern(pattern);
            if let Err(e) = regex::Regex::new(&anchored) {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("Invalid proxy listen_path: invalid regex '{}': {}", proxy.listen_path, e)}),
                ));
            }
        }
    }

    if proxy.id.is_empty() {
        proxy.id = Uuid::new_v4().to_string();
    } else if let Err(msg) = validate_resource_id(&proxy.id) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": msg}),
        ));
    }
    proxy.created_at = Utc::now();
    proxy.updated_at = Utc::now();

    // Check ID uniqueness
    match db.get_proxy(&proxy.id).await {
        Ok(Some(_)) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": format!("Proxy with ID '{}' already exists", proxy.id)}),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Check host+listen_path uniqueness for HTTP-style routes.
    if !proxy.backend_protocol.is_stream_proxy() {
        match db
            .check_listen_path_unique(namespace, &proxy.listen_path, &proxy.hosts, None)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": "A proxy with overlapping hosts and listen_path already exists"}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    // Check proxy name uniqueness (when present)
    if let Some(ref name) = proxy.name {
        match db.check_proxy_name_unique(namespace, name, None).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!("Proxy name '{}' already exists", name)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    // Validate upstream_id references an existing upstream
    if let Some(ref uid) = proxy.upstream_id {
        match db.check_upstream_exists(uid).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("upstream_id '{}' does not exist", uid)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    match db
        .validate_proxy_plugin_associations(&proxy.id, &proxy.plugins)
        .await
    {
        Ok(errors) if !errors.is_empty() => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid proxy plugin associations: {}", errors.join("; "))}),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Validate stream proxy configuration
    if proxy.backend_protocol.is_stream_proxy() {
        match proxy.listen_port {
            None => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!(
                        "Stream proxy (protocol {}) must have a listen_port",
                        proxy.backend_protocol
                    )}),
                ));
            }
            Some(port) if port < 1 => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("listen_port {} must be >= 1", port)}),
                ));
            }
            _ => {}
        }
        if proxy.response_body_mode != crate::config::types::ResponseBodyMode::Stream {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Stream proxies (TCP/UDP) must use response_body_mode 'stream'"}),
            ));
        }
        // Check listen_port uniqueness across all stream proxies
        if let Some(port) = proxy.listen_port {
            match db.check_listen_port_unique(namespace, port, None).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is already in use by another proxy",
                            port
                        )}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
            // In CP mode the proxy runs on remote DPs, not this host — skip
            // local port checks since they would test the wrong machine.
            if state.mode != "cp" {
                // Check against gateway reserved ports (proxy/admin/gRPC listeners)
                if state.reserved_ports.contains(&port) {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} conflicts with a gateway reserved port (proxy/admin/gRPC listener)",
                            port
                        )}),
                    ));
                }
                // Check OS-level port availability (best-effort TOCTOU check).
                // Only probe the transport the proxy will actually bind.
                if let Err(e) = check_port_available(
                    port,
                    &state.stream_proxy_bind_address,
                    proxy.backend_protocol.is_udp(),
                )
                .await
                {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is not available on the host: {}",
                            port, e
                        )}),
                    ));
                }
            }
        }
    } else if proxy.listen_port.is_some() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "HTTP proxy (protocol {}) must not set listen_port",
                proxy.backend_protocol
            )}),
        ));
    }

    match db.create_proxy(&proxy).await {
        Ok(_) => Ok(json_response(StatusCode::CREATED, &json!(proxy))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_get_proxy(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_proxy(id).await {
            Ok(Some(proxy)) => {
                if proxy.namespace != namespace {
                    return Ok(json_response(
                        StatusCode::NOT_FOUND,
                        &json!({"error": "Proxy not found"}),
                    ));
                }
                return Ok(json_response(StatusCode::OK, &json!(proxy)));
            }
            Ok(None) => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Proxy not found"}),
                ));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for get proxy, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: search in cached config
    if let Some(config) = state.cached_gateway_config() {
        match config
            .proxies
            .iter()
            .find(|p| p.id == id && p.namespace == namespace)
        {
            Some(proxy) => Ok(json_response_with_stale(StatusCode::OK, &json!(proxy))),
            None => Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Proxy not found"}),
            )),
        }
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_update_proxy(
    state: &AdminState,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    // Validate and normalize allowed_methods
    if let Some(ref mut methods) = proxy.allowed_methods {
        for m in methods.iter_mut() {
            *m = m.to_uppercase();
        }
    }

    proxy.normalize_fields();
    proxy.namespace = namespace.to_string();

    // Validate field lengths, numeric ranges, and nested config objects.
    if let Err(field_errors) = proxy.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid proxy fields: {}", field_errors.join("; "))}),
        ));
    }

    proxy.id = id.to_string();
    proxy.updated_at = Utc::now();

    // Validate host entries directly (no GatewayConfig wrapper needed for single-proxy paths).
    for host in &proxy.hosts {
        if let Err(msg) = crate::config::types::validate_host_entry(host) {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid proxy hosts: {}", msg)}),
            ));
        }
    }
    if !proxy.backend_protocol.is_stream_proxy() && proxy.listen_path.starts_with('~') {
        let pattern = &proxy.listen_path[1..];
        if !pattern.is_empty() {
            let anchored = crate::config::types::anchor_regex_pattern(pattern);
            if let Err(e) = regex::Regex::new(&anchored) {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("Invalid proxy listen_path: invalid regex '{}': {}", proxy.listen_path, e)}),
                ));
            }
        }
    }

    // Check host+listen_path uniqueness (excluding self) for HTTP-style routes.
    if !proxy.backend_protocol.is_stream_proxy() {
        match db
            .check_listen_path_unique(namespace, &proxy.listen_path, &proxy.hosts, Some(id))
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": "A proxy with overlapping hosts and listen_path already exists"}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("{}", e)}),
                ));
            }
        }
    }

    // Check proxy name uniqueness excluding self (when present)
    if let Some(ref name) = proxy.name {
        match db.check_proxy_name_unique(namespace, name, Some(id)).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!("Proxy name '{}' already exists", name)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    // Validate upstream_id references an existing upstream
    if let Some(ref uid) = proxy.upstream_id {
        match db.check_upstream_exists(uid).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("upstream_id '{}' does not exist", uid)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    match db
        .validate_proxy_plugin_associations(id, &proxy.plugins)
        .await
    {
        Ok(errors) if !errors.is_empty() => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid proxy plugin associations: {}", errors.join("; "))}),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Validate stream proxy configuration
    if proxy.backend_protocol.is_stream_proxy() {
        match proxy.listen_port {
            None => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!(
                        "Stream proxy (protocol {}) must have a listen_port",
                        proxy.backend_protocol
                    )}),
                ));
            }
            Some(port) if port < 1 => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("listen_port {} must be >= 1", port)}),
                ));
            }
            _ => {}
        }
        if proxy.response_body_mode != crate::config::types::ResponseBodyMode::Stream {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Stream proxies (TCP/UDP) must use response_body_mode 'stream'"}),
            ));
        }
        // Check listen_port uniqueness across all stream proxies (excluding self)
        if let Some(port) = proxy.listen_port {
            match db.check_listen_port_unique(namespace, port, Some(id)).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is already in use by another proxy",
                            port
                        )}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
            // In CP mode the proxy runs on remote DPs, not this host — skip
            // local port checks since they would test the wrong machine.
            if state.mode != "cp" {
                // Check against gateway reserved ports (proxy/admin/gRPC listeners)
                if state.reserved_ports.contains(&port) {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} conflicts with a gateway reserved port (proxy/admin/gRPC listener)",
                            port
                        )}),
                    ));
                }
                // Check OS-level port availability (best-effort TOCTOU check).
                // For updates, the port may already be bound by the existing listener
                // for this proxy — that's OK, unless the transport changed (e.g.
                // TCP→UDP on the same port), in which case we must re-probe.
                let (old_port, old_protocol) = match db.get_proxy(id).await {
                    Ok(Some(old)) => (old.listen_port, Some(old.backend_protocol)),
                    _ => (None, None),
                };
                let port_changed = old_port != Some(port);
                let transport_changed = old_protocol
                    .map(|p| p.is_udp() != proxy.backend_protocol.is_udp())
                    .unwrap_or(false);
                if (port_changed || transport_changed)
                    && let Err(e) = check_port_available(
                        port,
                        &state.stream_proxy_bind_address,
                        proxy.backend_protocol.is_udp(),
                    )
                    .await
                {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is not available on the host: {}",
                            port, e
                        )}),
                    ));
                }
            }
        }
    } else if proxy.listen_port.is_some() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "HTTP proxy (protocol {}) must not set listen_port",
                proxy.backend_protocol
            )}),
        ));
    }

    // Capture the old upstream_id before update so we can clean up if it changes
    let old_upstream_id: Option<String> = match db.get_proxy(id).await {
        Ok(Some(old_proxy)) => old_proxy.upstream_id,
        _ => None,
    };

    match db.update_proxy(&proxy).await {
        Ok(_) => {
            // If upstream_id changed, clean up the old upstream if it became orphaned
            if let Some(ref old_uid) = old_upstream_id
                && proxy.upstream_id.as_deref() != Some(old_uid.as_str())
                && let Err(e) = db.cleanup_orphaned_upstream(old_uid).await
            {
                warn!("Failed to clean up orphaned upstream {}: {}", old_uid, e);
            }
            Ok(json_response(StatusCode::OK, &json!(proxy)))
        }
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_delete_proxy(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    // Verify the proxy belongs to the requested namespace before deleting
    match db.get_proxy(id).await {
        Ok(Some(proxy)) if proxy.namespace != namespace => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Proxy not found"}),
            ));
        }
        Ok(None) => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Proxy not found"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ));
        }
        _ => {}
    }

    match db.delete_proxy(id).await {
        Ok(true) => Ok(json_response(StatusCode::NO_CONTENT, &json!({}))),
        Ok(false) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Proxy not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

// ---- Consumer CRUD ----

async fn handle_list_consumers(
    state: &AdminState,
    pagination: &PaginationParams,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database-level pagination first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db
            .list_consumers_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
            .await
        {
            Ok(result) => {
                let redacted: Vec<_> = result
                    .items
                    .iter()
                    .map(redact_consumer_credentials)
                    .collect();
                let body = paginate_db_response(&redacted, result.total, pagination);
                return Ok(json_response(StatusCode::OK, &body));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for list consumers, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: serve from in-memory cached config
    if let Some(config) = state.cached_gateway_config() {
        let redacted: Vec<_> = config
            .consumers
            .iter()
            .filter(|c| c.namespace == namespace)
            .map(redact_consumer_credentials)
            .collect();
        let body = paginate_response(&json!(redacted), pagination);
        Ok(json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_create_consumer(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut consumer: Consumer = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    if consumer.id.is_empty() {
        consumer.id = Uuid::new_v4().to_string();
    } else if let Err(msg) = validate_resource_id(&consumer.id) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": msg}),
        ));
    }

    consumer.normalize_fields();
    consumer.namespace = namespace.to_string();

    // Validate field lengths, credential sizes, and control characters
    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid consumer fields: {}", field_errors.join("; "))}),
        ));
    }

    consumer.created_at = Utc::now();
    consumer.updated_at = Utc::now();

    // Check ID uniqueness
    match db.get_consumer(&consumer.id).await {
        Ok(Some(_)) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": format!("Consumer with ID '{}' already exists", consumer.id)}),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    match db
        .check_consumer_identity_unique(
            namespace,
            &consumer.username,
            consumer.custom_id.as_deref(),
            None,
        )
        .await
    {
        Ok(Some(msg)) => {
            return Ok(json_response(StatusCode::CONFLICT, &json!({"error": msg})));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Hash any secrets in credentials
    if let Err(e) = hash_consumer_secrets(&mut consumer) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": e}),
        ));
    }

    // Check keyauth API key uniqueness for all entries (supports arrays)
    for key_creds in consumer.credential_entries("keyauth") {
        if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
            match db.check_keyauth_key_unique(namespace, key, None).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": "A consumer with this API key already exists"}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
        }
    }

    // Check mTLS identity uniqueness for all entries (supports arrays)
    for mtls_creds in consumer.credential_entries("mtls_auth") {
        if let Some(identity) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
            match db
                .check_mtls_identity_unique(namespace, identity, None)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": "A consumer with this mTLS identity already exists"}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
        }
    }

    match db.create_consumer(&consumer).await {
        Ok(_) => Ok(json_response(
            StatusCode::CREATED,
            &json!(redact_consumer_credentials(&consumer)),
        )),
        Err(e) => {
            let msg = format!("{}", e);
            let status = if is_unique_constraint_violation(&msg) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(json_response(status, &json!({"error": msg})))
        }
    }
}

async fn handle_get_consumer(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_consumer(id).await {
            Ok(Some(c)) => {
                if c.namespace != namespace {
                    return Ok(json_response(
                        StatusCode::NOT_FOUND,
                        &json!({"error": "Consumer not found"}),
                    ));
                }
                return Ok(json_response(
                    StatusCode::OK,
                    &json!(redact_consumer_credentials(&c)),
                ));
            }
            Ok(None) => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Consumer not found"}),
                ));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for get consumer, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: search in cached config
    if let Some(config) = state.cached_gateway_config() {
        match config
            .consumers
            .iter()
            .find(|c| c.id == id && c.namespace == namespace)
        {
            Some(consumer) => Ok(json_response_with_stale(
                StatusCode::OK,
                &json!(redact_consumer_credentials(consumer)),
            )),
            None => Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Consumer not found"}),
            )),
        }
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_update_consumer(
    state: &AdminState,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut consumer: Consumer = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    consumer.id = id.to_string();
    consumer.updated_at = Utc::now();
    consumer.normalize_fields();
    consumer.namespace = namespace.to_string();

    // Validate field lengths, credential sizes, and control characters
    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid consumer fields: {}", field_errors.join("; "))}),
        ));
    }

    if let Err(e) = hash_consumer_secrets(&mut consumer) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": e}),
        ));
    }

    match db
        .check_consumer_identity_unique(
            namespace,
            &consumer.username,
            consumer.custom_id.as_deref(),
            Some(id),
        )
        .await
    {
        Ok(Some(msg)) => {
            return Ok(json_response(StatusCode::CONFLICT, &json!({"error": msg})));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Check keyauth API key uniqueness excluding self for all entries (supports arrays)
    for key_creds in consumer.credential_entries("keyauth") {
        if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
            match db.check_keyauth_key_unique(namespace, key, Some(id)).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": "A consumer with this API key already exists"}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
        }
    }

    // Check mTLS identity uniqueness excluding self for all entries (supports arrays)
    for mtls_creds in consumer.credential_entries("mtls_auth") {
        if let Some(identity) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
            match db
                .check_mtls_identity_unique(namespace, identity, Some(id))
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": "A consumer with this mTLS identity already exists"}),
                    ));
                }
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &db_error_response(&e),
                    ));
                }
            }
        }
    }

    match db.update_consumer(&consumer).await {
        Ok(_) => Ok(json_response(
            StatusCode::OK,
            &json!(redact_consumer_credentials(&consumer)),
        )),
        Err(e) => {
            let msg = format!("{}", e);
            let status = if is_unique_constraint_violation(&msg) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(json_response(status, &json!({"error": msg})))
        }
    }
}

async fn handle_delete_consumer(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    // Verify the consumer belongs to the requested namespace before deleting
    match db.get_consumer(id).await {
        Ok(Some(c)) if c.namespace != namespace => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Consumer not found"}),
            ));
        }
        Ok(None) => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Consumer not found"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ));
        }
        _ => {}
    }

    match db.delete_consumer(id).await {
        Ok(true) => Ok(json_response(StatusCode::NO_CONTENT, &json!({}))),
        Ok(false) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Consumer not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
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

    // Validate credential type against whitelist
    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "Unknown credential type '{}'. Allowed types: {:?}",
                cred_type, ALLOWED_CREDENTIAL_TYPES
            )}),
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let cred_value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    match db.get_consumer(consumer_id).await {
        Ok(Some(mut consumer)) => {
            if consumer.namespace != namespace {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Consumer not found"}),
                ));
            }
            let mut hashed_cred = cred_value.clone();
            // Hash password if basicauth (supports both single object and array)
            if cred_type == "basicauth"
                && let Err(e) = hash_credential_passwords(&mut hashed_cred)
            {
                return Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": e}),
                ));
            }
            // Check keyauth API key uniqueness for all entries before updating
            if cred_type == "keyauth" {
                let entries: Vec<&serde_json::Value> = match &hashed_cred {
                    serde_json::Value::Array(arr) => arr.iter().filter(|v| v.is_object()).collect(),
                    val if val.is_object() => vec![val],
                    _ => vec![],
                };
                for entry in entries {
                    if let Some(key) = entry.get("key").and_then(|k| k.as_str()) {
                        match db
                            .check_keyauth_key_unique(namespace, key, Some(consumer_id))
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                return Ok(json_response(
                                    StatusCode::CONFLICT,
                                    &json!({"error": "A consumer with this API key already exists"}),
                                ));
                            }
                            Err(e) => {
                                return Ok(json_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    &db_error_response(&e),
                                ));
                            }
                        }
                    }
                }
            }
            // Check mTLS identity uniqueness for all entries before updating
            if cred_type == "mtls_auth" {
                let entries: Vec<&serde_json::Value> = match &hashed_cred {
                    serde_json::Value::Array(arr) => arr.iter().filter(|v| v.is_object()).collect(),
                    val if val.is_object() => vec![val],
                    _ => vec![],
                };
                for entry in entries {
                    if let Some(identity) = entry.get("identity").and_then(|i| i.as_str()) {
                        match db
                            .check_mtls_identity_unique(namespace, identity, Some(consumer_id))
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                return Ok(json_response(
                                    StatusCode::CONFLICT,
                                    &json!({"error": "A consumer with this mTLS identity already exists"}),
                                ));
                            }
                            Err(e) => {
                                return Ok(json_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    &db_error_response(&e),
                                ));
                            }
                        }
                    }
                }
            }

            consumer
                .credentials
                .insert(cred_type.to_string(), hashed_cred);

            // Validate credential field lengths and sizes after modification
            if let Err(field_errors) = consumer.validate_fields() {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("Invalid credential fields: {}", field_errors.join("; "))}),
                ));
            }

            consumer.updated_at = Utc::now();
            match db.update_consumer(&consumer).await {
                Ok(_) => Ok(json_response(
                    StatusCode::OK,
                    &json!(redact_consumer_credentials(&consumer)),
                )),
                Err(e) => Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": format!("{}", e)}),
                )),
            }
        }
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Consumer not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
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

    // Validate credential type against whitelist
    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "Unknown credential type '{}'. Allowed types: {:?}",
                cred_type, ALLOWED_CREDENTIAL_TYPES
            )}),
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    match db.get_consumer(consumer_id).await {
        Ok(Some(mut consumer)) => {
            if consumer.namespace != namespace {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Consumer not found"}),
                ));
            }
            consumer.credentials.remove(cred_type);
            consumer.updated_at = Utc::now();
            match db.update_consumer(&consumer).await {
                Ok(_) => Ok(json_response(StatusCode::NO_CONTENT, &json!({}))),
                Err(e) => Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": format!("{}", e)}),
                )),
            }
        }
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Consumer not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

/// POST /consumers/:id/credentials/:type — Append a credential entry for zero-downtime rotation.
///
/// Converts existing single-object credential to an array if needed, then appends the new entry.
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
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "Unknown credential type '{}'. Allowed types: {:?}",
                cred_type, ALLOWED_CREDENTIAL_TYPES
            )}),
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut new_cred: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    if !new_cred.is_object() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential entry must be a JSON object"}),
        ));
    }

    match db.get_consumer(consumer_id).await {
        Ok(Some(mut consumer)) => {
            if consumer.namespace != namespace {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Consumer not found"}),
                ));
            }
            // Hash password if basicauth
            if cred_type == "basicauth"
                && let Err(e) = hash_credential_passwords(&mut new_cred)
            {
                return Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": e}),
                ));
            }

            // Check uniqueness for the new entry
            if cred_type == "keyauth"
                && let Some(key) = new_cred.get("key").and_then(|k| k.as_str())
            {
                match db
                    .check_keyauth_key_unique(namespace, key, Some(consumer_id))
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(json_response(
                            StatusCode::CONFLICT,
                            &json!({"error": "A consumer with this API key already exists"}),
                        ));
                    }
                    Err(e) => {
                        return Ok(json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &db_error_response(&e),
                        ));
                    }
                }
            }
            if cred_type == "mtls_auth"
                && let Some(identity) = new_cred.get("identity").and_then(|i| i.as_str())
            {
                match db
                    .check_mtls_identity_unique(namespace, identity, Some(consumer_id))
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(json_response(
                            StatusCode::CONFLICT,
                            &json!({"error": "A consumer with this mTLS identity already exists"}),
                        ));
                    }
                    Err(e) => {
                        return Ok(json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &db_error_response(&e),
                        ));
                    }
                }
            }

            // Build the new credential array
            let new_value = match consumer.credentials.get(cred_type) {
                Some(Value::Array(arr)) => {
                    let mut new_arr = arr.clone();
                    new_arr.push(new_cred);
                    Value::Array(new_arr)
                }
                Some(existing) if existing.is_object() => {
                    Value::Array(vec![existing.clone(), new_cred])
                }
                _ => {
                    // No existing credential — store as single object for backward compat
                    new_cred
                }
            };

            // Check max entries per type
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
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("Invalid credential fields: {}", field_errors.join("; "))}),
                ));
            }

            consumer.updated_at = Utc::now();
            match db.update_consumer(&consumer).await {
                Ok(_) => Ok(json_response(
                    StatusCode::OK,
                    &json!(redact_consumer_credentials(&consumer)),
                )),
                Err(e) => Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": format!("{}", e)}),
                )),
            }
        }
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Consumer not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
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
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!(
                "Unknown credential type '{}'. Allowed types: {:?}",
                cred_type, ALLOWED_CREDENTIAL_TYPES
            )}),
        ));
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

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    match db.get_consumer(consumer_id).await {
        Ok(Some(mut consumer)) => {
            if consumer.namespace != namespace {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Consumer not found"}),
                ));
            }
            let cred_value = match consumer.credentials.get_mut(cred_type) {
                Some(v) => v,
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
                    // Collapse single-element array back to a plain object
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

            consumer.updated_at = Utc::now();
            match db.update_consumer(&consumer).await {
                Ok(_) => Ok(json_response(
                    StatusCode::OK,
                    &json!(redact_consumer_credentials(&consumer)),
                )),
                Err(e) => Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": format!("{}", e)}),
                )),
            }
        }
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Consumer not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

// ---- Plugin CRUD ----

async fn handle_list_plugin_types() -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(json_response(
        StatusCode::OK,
        &json!(plugins::available_plugins()),
    ))
}

async fn handle_list_plugin_configs(
    state: &AdminState,
    pagination: &PaginationParams,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database-level pagination first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db
            .list_plugin_configs_paginated(
                namespace,
                pagination.limit as i64,
                pagination.offset as i64,
            )
            .await
        {
            Ok(result) => {
                let body = paginate_db_response(&result.items, result.total, pagination);
                return Ok(json_response(StatusCode::OK, &body));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for list plugin configs, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: serve from in-memory cached config
    if let Some(config) = state.cached_gateway_config() {
        let filtered: Vec<&PluginConfig> = config
            .plugin_configs
            .iter()
            .filter(|pc| pc.namespace == namespace)
            .collect();
        let body = paginate_response(&json!(filtered), pagination);
        Ok(json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

fn validate_plugin_config_definition(pc: &PluginConfig) -> Result<(), String> {
    match plugins::create_plugin(&pc.plugin_name, &pc.config) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("Unknown plugin name '{}'", pc.plugin_name)),
        Err(err) => Err(err),
    }
}

async fn handle_create_plugin_config(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut pc: PluginConfig = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    pc.normalize_fields();
    pc.namespace = namespace.to_string();

    if pc.id.is_empty() {
        pc.id = Uuid::new_v4().to_string();
    } else if let Err(msg) = validate_resource_id(&pc.id) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": msg}),
        ));
    }

    // Check ID uniqueness
    match db.get_plugin_config(&pc.id).await {
        Ok(Some(_)) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": format!("PluginConfig with ID '{}' already exists", pc.id)}),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    // Validate plugin name is a known plugin
    let known_plugins = crate::plugins::available_plugins();
    if !known_plugins.contains(&pc.plugin_name.as_str()) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Unknown plugin name '{}'. Available plugins: {:?}", pc.plugin_name, known_plugins)}),
        ));
    }

    // Validate field lengths, config JSON size, and nesting depth
    if let Err(field_errors) = pc.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid plugin config fields: {}", field_errors.join("; "))}),
        ));
    }

    // Validate proxy_id references an existing proxy
    if let Some(ref proxy_id) = pc.proxy_id {
        match db.check_proxy_exists(proxy_id).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("proxy_id '{}' does not exist", proxy_id)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    if let Err(err) = validate_plugin_config_definition(&pc) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid plugin config: {}", err)}),
        ));
    }

    pc.created_at = Utc::now();
    pc.updated_at = Utc::now();

    match db.create_plugin_config(&pc).await {
        Ok(_) => Ok(json_response(StatusCode::CREATED, &json!(pc))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_get_plugin_config(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_plugin_config(id).await {
            Ok(Some(pc)) => {
                if pc.namespace != namespace {
                    return Ok(json_response(
                        StatusCode::NOT_FOUND,
                        &json!({"error": "Plugin config not found"}),
                    ));
                }
                return Ok(json_response(StatusCode::OK, &json!(pc)));
            }
            Ok(None) => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Plugin config not found"}),
                ));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for get plugin config, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: search in cached config
    if let Some(config) = state.cached_gateway_config() {
        match config
            .plugin_configs
            .iter()
            .find(|pc| pc.id == id && pc.namespace == namespace)
        {
            Some(pc) => Ok(json_response_with_stale(StatusCode::OK, &json!(pc))),
            None => Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Plugin config not found"}),
            )),
        }
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_update_plugin_config(
    state: &AdminState,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut pc: PluginConfig = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    pc.id = id.to_string();
    pc.updated_at = Utc::now();
    pc.normalize_fields();
    pc.namespace = namespace.to_string();

    // Validate plugin name is known
    let known_plugins = crate::plugins::available_plugins();
    if !known_plugins.contains(&pc.plugin_name.as_str()) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Unknown plugin name '{}'. Available plugins: {:?}", pc.plugin_name, known_plugins)}),
        ));
    }

    // Validate field lengths, config JSON size, and nesting depth
    if let Err(field_errors) = pc.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid plugin config fields: {}", field_errors.join("; "))}),
        ));
    }

    // Validate proxy_id references an existing proxy
    if let Some(ref proxy_id) = pc.proxy_id {
        match db.check_proxy_exists(proxy_id).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!("proxy_id '{}' does not exist", proxy_id)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    if let Err(err) = validate_plugin_config_definition(&pc) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid plugin config: {}", err)}),
        ));
    }

    match db.update_plugin_config(&pc).await {
        Ok(_) => Ok(json_response(StatusCode::OK, &json!(pc))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_delete_plugin_config(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    // Verify the plugin config belongs to the requested namespace before deleting
    match db.get_plugin_config(id).await {
        Ok(Some(pc)) if pc.namespace != namespace => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Plugin config not found"}),
            ));
        }
        Ok(None) => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Plugin config not found"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ));
        }
        _ => {}
    }

    match db.delete_plugin_config(id).await {
        Ok(true) => Ok(json_response(StatusCode::NO_CONTENT, &json!({}))),
        Ok(false) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Plugin config not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

// ---- Upstream CRUD ----

async fn handle_list_upstreams(
    state: &AdminState,
    pagination: &PaginationParams,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database-level pagination first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db
            .list_upstreams_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
            .await
        {
            Ok(result) => {
                let body = paginate_db_response(&result.items, result.total, pagination);
                return Ok(json_response(StatusCode::OK, &body));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for list upstreams, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: serve from in-memory cached config
    if let Some(config) = state.cached_gateway_config() {
        let filtered: Vec<&Upstream> = config
            .upstreams
            .iter()
            .filter(|u| u.namespace == namespace)
            .collect();
        let body = paginate_response(&json!(filtered), pagination);
        Ok(json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_create_upstream(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut upstream: Upstream = match serde_json::from_slice(body) {
        Ok(u) => u,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    if upstream.id.is_empty() {
        upstream.id = Uuid::new_v4().to_string();
    } else if let Err(msg) = validate_resource_id(&upstream.id) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": msg}),
        ));
    }
    upstream.created_at = Utc::now();
    upstream.updated_at = Utc::now();

    // Check ID uniqueness
    match db.get_upstream(&upstream.id).await {
        Ok(Some(_)) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": format!("Upstream with ID '{}' already exists", upstream.id)}),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &db_error_response(&e),
            ));
        }
    }

    upstream.normalize_fields();
    upstream.namespace = namespace.to_string();

    if upstream.targets.is_empty() && upstream.service_discovery.is_none() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "At least one target is required (or configure service_discovery)"}),
        ));
    }

    // Validate field lengths, target hosts/ports/weights, and nested configs
    if let Err(field_errors) = upstream.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid upstream fields: {}", field_errors.join("; "))}),
        ));
    }

    // Check upstream name uniqueness (when present)
    if let Some(ref name) = upstream.name {
        match db.check_upstream_name_unique(namespace, name, None).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!("Upstream name '{}' already exists", name)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    match db.create_upstream(&upstream).await {
        Ok(_) => Ok(json_response(StatusCode::CREATED, &json!(upstream))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_get_upstream(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_upstream(id).await {
            Ok(Some(upstream)) => {
                if upstream.namespace != namespace {
                    return Ok(json_response(
                        StatusCode::NOT_FOUND,
                        &json!({"error": "Upstream not found"}),
                    ));
                }
                return Ok(json_response(StatusCode::OK, &json!(upstream)));
            }
            Ok(None) => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    &json!({"error": "Upstream not found"}),
                ));
            }
            Err(e) => {
                warn!(
                    "Database unavailable for get upstream, falling back to cached config: {}",
                    e
                );
            }
        }
    }

    // Fallback: search in cached config
    if let Some(config) = state.cached_gateway_config() {
        match config
            .upstreams
            .iter()
            .find(|u| u.id == id && u.namespace == namespace)
        {
            Some(upstream) => Ok(json_response_with_stale(StatusCode::OK, &json!(upstream))),
            None => Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Upstream not found"}),
            )),
        }
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_update_upstream(
    state: &AdminState,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    let mut upstream: Upstream = match serde_json::from_slice(body) {
        Ok(u) => u,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    upstream.id = id.to_string();
    upstream.updated_at = Utc::now();
    upstream.normalize_fields();
    upstream.namespace = namespace.to_string();

    if upstream.targets.is_empty() && upstream.service_discovery.is_none() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "At least one target is required (or configure service_discovery)"}),
        ));
    }

    // Validate field lengths, target hosts/ports/weights, and nested configs
    if let Err(field_errors) = upstream.validate_fields() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid upstream fields: {}", field_errors.join("; "))}),
        ));
    }

    // Check upstream name uniqueness excluding self (when present)
    if let Some(ref name) = upstream.name {
        match db
            .check_upstream_name_unique(namespace, name, Some(id))
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!("Upstream name '{}' already exists", name)}),
                ));
            }
            Err(e) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &db_error_response(&e),
                ));
            }
        }
    }

    match db.update_upstream(&upstream).await {
        Ok(_) => Ok(json_response(StatusCode::OK, &json!(upstream))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_delete_upstream(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    // Verify the upstream belongs to the requested namespace before deleting
    match db.get_upstream(id).await {
        Ok(Some(u)) if u.namespace != namespace => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Upstream not found"}),
            ));
        }
        Ok(None) => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Upstream not found"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ));
        }
        _ => {}
    }

    match db.delete_upstream(id).await {
        Ok(true) => Ok(json_response(StatusCode::NO_CONTENT, &json!({}))),
        Ok(false) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Upstream not found"}),
        )),
        Err(e) if e.to_string().contains("referenced by one or more proxies") => Ok(json_response(
            StatusCode::CONFLICT,
            &json!({"error": format!("{}", e)}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

// ---- Metrics ----

use std::sync::OnceLock;
use std::time::Duration;

/// Process-global cache for the metrics JSON response.
/// Uses a static to avoid adding a field to AdminState (which has 30+ construction sites).
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

/// Batch create endpoint — accepts multiple resources in a single request,
/// persists them in a single database transaction per resource type.
///
/// Request body format:
/// ```json
/// {
///   "proxies": [...],
///   "consumers": [...],
///   "plugin_configs": [...],
///   "upstreams": [...]
/// }
/// ```
/// All fields are optional. Returns counts of created resources.
async fn handle_batch_create(
    state: &AdminState,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

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
    let known_plugins = crate::plugins::available_plugins();
    let mut validation_errors: Vec<String> = Vec::new();

    for consumer in &mut batch.consumers {
        if consumer.id.is_empty() {
            consumer.id = Uuid::new_v4().to_string();
        } else if let Err(msg) = validate_resource_id(&consumer.id) {
            validation_errors.push(format!("Consumer '{}': {}", consumer.id, msg));
        }
        consumer.normalize_fields();
        if let Err(field_errs) = consumer.validate_fields() {
            for err in field_errs {
                validation_errors.push(format!("Consumer '{}': {}", consumer.id, err));
            }
        }
        consumer.namespace = namespace.to_string();
        consumer.created_at = now;
        consumer.updated_at = now;
        if let Err(err) = hash_consumer_secrets(consumer) {
            validation_errors.push(format!("Consumer '{}': {}", consumer.id, err));
        }
    }

    for upstream in &mut batch.upstreams {
        if upstream.id.is_empty() {
            upstream.id = Uuid::new_v4().to_string();
        } else if let Err(msg) = validate_resource_id(&upstream.id) {
            validation_errors.push(format!("Upstream '{}': {}", upstream.id, msg));
        }
        upstream.normalize_fields();
        upstream.namespace = namespace.to_string();
        if let Err(field_errs) = upstream.validate_fields() {
            for err in field_errs {
                validation_errors.push(format!("Upstream '{}': {}", upstream.id, err));
            }
        }
        upstream.created_at = now;
        upstream.updated_at = now;
    }

    for proxy in &mut batch.proxies {
        if proxy.id.is_empty() {
            proxy.id = Uuid::new_v4().to_string();
        } else if let Err(msg) = validate_resource_id(&proxy.id) {
            validation_errors.push(format!("Proxy '{}': {}", proxy.id, msg));
        }
        if let Some(ref mut methods) = proxy.allowed_methods {
            for method in methods.iter_mut() {
                *method = method.to_uppercase();
            }
        }
        proxy.normalize_fields();
        proxy.namespace = namespace.to_string();
        if let Err(field_errs) = proxy.validate_fields() {
            for err in field_errs {
                validation_errors.push(format!("Proxy '{}': {}", proxy.id, err));
            }
        }
        proxy.created_at = now;
        proxy.updated_at = now;
    }

    for plugin_config in &mut batch.plugin_configs {
        if plugin_config.id.is_empty() {
            plugin_config.id = Uuid::new_v4().to_string();
        } else if let Err(msg) = validate_resource_id(&plugin_config.id) {
            validation_errors.push(format!("PluginConfig '{}': {}", plugin_config.id, msg));
        }
        plugin_config.normalize_fields();
        plugin_config.namespace = namespace.to_string();
        if !known_plugins.contains(&plugin_config.plugin_name.as_str()) {
            validation_errors.push(format!(
                "PluginConfig '{}': unknown plugin name '{}'",
                plugin_config.id, plugin_config.plugin_name
            ));
        }
        if let Err(field_errs) = plugin_config.validate_fields() {
            for err in field_errs {
                validation_errors.push(format!("PluginConfig '{}': {}", plugin_config.id, err));
            }
        }
        if let Err(err) = validate_plugin_config_definition(plugin_config) {
            validation_errors.push(format!(
                "PluginConfig '{}': invalid config: {}",
                plugin_config.id, err
            ));
        }
        plugin_config.created_at = now;
        plugin_config.updated_at = now;
    }

    // Cross-resource validations require a GatewayConfig view over the batch.
    // Individual items are already normalized and field-validated above, so skip
    // normalize_fields() and validate_all_fields() to avoid redundant work.
    let batch_config = GatewayConfig {
        version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: batch.proxies.clone(),
        consumers: batch.consumers.clone(),
        plugin_configs: batch.plugin_configs.clone(),
        upstreams: batch.upstreams.clone(),
        loaded_at: now,
        known_namespaces: Vec::new(),
    };

    if let Err(errs) = batch_config.validate_unique_resource_ids() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_unique_consumer_identities() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_unique_consumer_credentials() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_unique_upstream_names() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_unique_proxy_names() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_hosts() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_regex_listen_paths() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_unique_listen_paths() {
        validation_errors.extend(errs);
    }
    if let Err(errs) = batch_config.validate_stream_proxies() {
        validation_errors.extend(errs);
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

    let mut created_proxies = 0usize;
    let mut created_consumers = 0usize;
    let mut created_plugin_configs = 0usize;
    let mut created_upstreams = 0usize;
    let mut errors: Vec<String> = Vec::new();

    if !batch.consumers.is_empty() {
        match db.batch_create_consumers(&batch.consumers).await {
            Ok(n) => created_consumers = n,
            Err(e) => errors.push(format!("consumers: {}", e)),
        }
    }

    if errors.is_empty() && !batch.upstreams.is_empty() {
        match db.batch_create_upstreams(&batch.upstreams).await {
            Ok(n) => created_upstreams = n,
            Err(e) => errors.push(format!("upstreams: {}", e)),
        }
    }

    if errors.is_empty() && !batch.proxies.is_empty() {
        match db
            .batch_create_proxies_without_plugins(&batch.proxies)
            .await
        {
            Ok(n) => created_proxies = n,
            Err(e) => errors.push(format!("proxies: {}", e)),
        }
    }

    if errors.is_empty() && !batch.plugin_configs.is_empty() {
        match db.batch_create_plugin_configs(&batch.plugin_configs).await {
            Ok(n) => created_plugin_configs = n,
            Err(e) => errors.push(format!("plugin_configs: {}", e)),
        }
    }

    if errors.is_empty()
        && !batch.proxies.is_empty()
        && let Err(e) = db.batch_attach_proxy_plugins(&batch.proxies).await
    {
        errors.push(format!("proxy_plugins: {}", e));
    }

    let mut response = json!({
        "created": {
            "proxies": created_proxies,
            "consumers": created_consumers,
            "plugin_configs": created_plugin_configs,
            "upstreams": created_upstreams,
        }
    });

    if !errors.is_empty() {
        response["errors"] = json!(errors);
        return Ok(json_response(StatusCode::MULTI_STATUS, &response));
    }

    Ok(json_response(StatusCode::CREATED, &response))
}

// ---- Backup & Restore ----

/// Parse the `resources` query parameter into a set of included resource types.
/// Returns `None` when no filter is specified (include all).
fn parse_backup_resources(query: Option<&str>) -> Option<std::collections::HashSet<&str>> {
    let query = query?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "resources"
        {
            return Some(val.split(',').collect());
        }
    }
    None
}

/// Typed backup payload — serializes directly from config structs without an
/// intermediate `serde_json::Value` tree. At 30K proxies / 90K plugins this
/// saves ~80 MB of peak heap vs the `json!()` macro approach.
#[derive(Serialize)]
struct BackupPayload<'a> {
    version: &'a str,
    ferrum_version: &'a str,
    exported_at: String,
    source: &'a str,
    counts: BackupCounts,
    proxies: &'a [Proxy],
    consumers: &'a [Consumer],
    plugin_configs: &'a [PluginConfig],
    upstreams: &'a [Upstream],
}

#[derive(Serialize)]
struct BackupCounts {
    proxies: usize,
    consumers: usize,
    plugin_configs: usize,
    upstreams: usize,
}

/// Export the full gateway configuration as a JSON backup.
///
/// Returns the complete config (proxies, consumers, plugin_configs, upstreams)
/// in the same format accepted by `POST /batch` and `POST /restore`, so the
/// output can be directly used to restore the gateway.
///
/// Consumer credentials are included **unredacted** (this is a backup endpoint).
///
/// Supports `?resources=proxies,consumers` to export only specific resource types.
///
/// Reads from the database first; falls back to the in-memory cached config
/// when the database is unavailable.
///
/// Memory: serializes directly from the config structs (no intermediate
/// `serde_json::Value` copy), so peak memory is config + output buffer.
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

/// Check whether `confirm=true` is present in the query string.
fn parse_restore_confirm(query: Option<&str>) -> bool {
    let query = match query {
        Some(q) => q,
        None => return false,
    };
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "confirm"
            && val == "true"
        {
            return true;
        }
    }
    false
}

/// Typed restore payload — deserializes directly into typed structs without an
/// intermediate `serde_json::Value` tree. This halves peak memory usage vs the
/// two-pass `Value → from_value` approach.
///
/// Extra fields from `GET /backup` (version, exported_at, source, counts) are
/// silently ignored via `#[serde(default)]`.
#[derive(Deserialize)]
struct RestorePayload {
    #[serde(default)]
    version: String,
    #[serde(default)]
    proxies: Vec<Proxy>,
    #[serde(default)]
    consumers: Vec<Consumer>,
    #[serde(default)]
    plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    upstreams: Vec<Upstream>,
}

/// Restore the gateway configuration from a backup payload.
///
/// This is a **destructive** operation that replaces all existing configuration:
/// 1. Parses and validates the entire payload (fail-fast before any deletion)
/// 2. Deletes ALL existing resources (proxies, consumers, plugin_configs, upstreams)
/// 3. Imports the provided resources in dependency order using chunked transactions
///
/// Requires `?confirm=true` query parameter to prevent accidental invocation.
///
/// Memory: deserializes directly into typed structs (no intermediate
/// `serde_json::Value` copy), so peak memory is body bytes + parsed structs.
/// Database inserts are chunked into 1,000-record transactions to keep WAL
/// size bounded and avoid prolonged lock holds.
async fn handle_restore(
    state: &AdminState,
    body: &[u8],
    query: Option<&str>,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    if !parse_restore_confirm(query) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": "Restore is a destructive operation that replaces all existing configuration. Pass ?confirm=true to proceed."
            }),
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
        if let Err(errs) = temp_config.validate_all_fields(cert_expiry_days) {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_unique_resource_ids() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_unique_consumer_identities() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_unique_consumer_credentials() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_hosts() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_regex_listen_paths() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_unique_listen_paths() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_stream_proxies() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_upstream_references() {
            validation_errors.extend(errs);
        }
        if let Err(errs) = temp_config.validate_plugin_references() {
            validation_errors.extend(errs);
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
    let mut errors: Vec<String> = Vec::new();
    let mut created_consumers = 0usize;
    let mut created_upstreams = 0usize;
    let mut created_proxies = 0usize;
    let mut created_plugin_configs = 0usize;

    // Set namespace on all payload resources before persisting
    let mut payload = payload;
    for p in &mut payload.proxies {
        p.namespace = namespace.to_string();
    }
    for c in &mut payload.consumers {
        c.namespace = namespace.to_string();
    }
    for pc in &mut payload.plugin_configs {
        pc.namespace = namespace.to_string();
    }
    for u in &mut payload.upstreams {
        u.namespace = namespace.to_string();
    }

    // Consumers first (no dependencies) — hash secrets before persisting
    if !payload.consumers.is_empty() {
        let mut consumers = payload.consumers.clone();
        for consumer in &mut consumers {
            if let Err(e) = hash_consumer_secrets(consumer) {
                errors.push(format!("consumer {} secret hashing: {}", consumer.id, e));
            }
        }
        match db.batch_create_consumers(&consumers).await {
            Ok(n) => created_consumers = n,
            Err(e) => errors.push(format!("consumers: {}", e)),
        }
    }

    // Upstreams (no dependencies)
    if !payload.upstreams.is_empty() {
        match db.batch_create_upstreams(&payload.upstreams).await {
            Ok(n) => created_upstreams = n,
            Err(e) => errors.push(format!("upstreams: {}", e)),
        }
    }

    // Proxies (may reference upstreams). Persist rows first; proxy/plugin
    // associations are attached after plugin configs exist.
    if !payload.proxies.is_empty() {
        match db
            .batch_create_proxies_without_plugins(&payload.proxies)
            .await
        {
            Ok(n) => created_proxies = n,
            Err(e) => errors.push(format!("proxies: {}", e)),
        }
    }

    // Plugin configs (may reference proxies)
    if !payload.plugin_configs.is_empty() {
        match db
            .batch_create_plugin_configs(&payload.plugin_configs)
            .await
        {
            Ok(n) => created_plugin_configs = n,
            Err(e) => errors.push(format!("plugin_configs: {}", e)),
        }
    }

    if errors.is_empty()
        && !payload.proxies.is_empty()
        && let Err(e) = db.batch_attach_proxy_plugins(&payload.proxies).await
    {
        errors.push(format!("proxy_plugins: {}", e));
    }

    info!(
        "Restore: imported {} proxies, {} consumers, {} plugin_configs, {} upstreams",
        created_proxies, created_consumers, created_plugin_configs, created_upstreams
    );

    let mut response = json!({
        "restored": {
            "proxies": created_proxies,
            "consumers": created_consumers,
            "plugin_configs": created_plugin_configs,
            "upstreams": created_upstreams,
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

/// Filter a GatewayConfig to only include resources matching the given namespace.
fn filter_config_by_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
    GatewayConfig {
        version: config.version.clone(),
        proxies: config
            .proxies
            .iter()
            .filter(|p| p.namespace == namespace)
            .cloned()
            .collect(),
        consumers: config
            .consumers
            .iter()
            .filter(|c| c.namespace == namespace)
            .cloned()
            .collect(),
        plugin_configs: config
            .plugin_configs
            .iter()
            .filter(|pc| pc.namespace == namespace)
            .cloned()
            .collect(),
        upstreams: config
            .upstreams
            .iter()
            .filter(|u| u.namespace == namespace)
            .cloned()
            .collect(),
        loaded_at: config.loaded_at,
        known_namespaces: config.known_namespaces.clone(),
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
    json!({"error": "Database operation failed"})
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
    let mut redacted = consumer.clone();

    /// Redact a secret field in a credential value, handling both single-object
    /// and array-of-objects formats.
    fn redact_field(cred_value: &mut serde_json::Value, field: &str) {
        match cred_value {
            serde_json::Value::Array(arr) => {
                for entry in arr.iter_mut() {
                    if let Some(obj) = entry.as_object_mut()
                        && obj.contains_key(field)
                    {
                        obj.insert(field.to_string(), json!("[REDACTED]"));
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                if obj.contains_key(field) {
                    obj.insert(field.to_string(), json!("[REDACTED]"));
                }
            }
            _ => {}
        }
    }

    if let Some(basic) = redacted.credentials.get_mut("basicauth") {
        redact_field(basic, "password_hash");
    }
    if let Some(hmac) = redacted.credentials.get_mut("hmac_auth") {
        redact_field(hmac, "secret");
    }
    if let Some(jwt) = redacted.credentials.get_mut("jwt") {
        redact_field(jwt, "secret");
    }
    redacted
}

fn hash_consumer_secrets(consumer: &mut Consumer) -> Result<(), String> {
    // Hash basicauth passwords — supports both single-object and array formats
    if let Some(basic) = consumer.credentials.get_mut("basicauth") {
        match basic {
            serde_json::Value::Array(arr) => {
                for entry in arr.iter_mut() {
                    if let Some(pass) = entry.get("password").and_then(|p| p.as_str()) {
                        let hash = hash_basic_auth_password(pass).map_err(|e| {
                            format!(
                                "Failed to hash password for consumer {}: {}",
                                consumer.id, e
                            )
                        })?;
                        entry["password_hash"] = json!(hash);
                        if let Some(obj) = entry.as_object_mut() {
                            obj.remove("password");
                        }
                    }
                }
            }
            _ => {
                if let Some(pass) = basic.get("password").and_then(|p| p.as_str()) {
                    let hash = hash_basic_auth_password(pass).map_err(|e| {
                        format!(
                            "Failed to hash password for consumer {}: {}",
                            consumer.id, e
                        )
                    })?;
                    basic["password_hash"] = json!(hash);
                    if let Some(obj) = basic.as_object_mut() {
                        obj.remove("password");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Hash a plaintext password for basic_auth storage.
///
/// Uses HMAC-SHA256 with the configured secret (or default) for ~1μs verification.
/// Falls back to bcrypt ($2b$, ~100ms) only if HMAC instance creation fails.
fn hash_basic_auth_password(password: &str) -> Result<String, String> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let secret = crate::config::conf_file::resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::plugins::basic_auth::DEFAULT_HMAC_SECRET.to_string());

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC instance: {}", e))?;
    mac.update(password.as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    Ok(format!("hmac_sha256:{}", hash))
}

/// Hash passwords in a basicauth credential value (single object or array).
/// Used by `handle_update_credentials()` where the credential type is already known.
fn hash_credential_passwords(cred: &mut serde_json::Value) -> Result<(), String> {
    match cred {
        serde_json::Value::Array(arr) => {
            for entry in arr.iter_mut() {
                if let Some(pass) = entry.get("password").and_then(|p| p.as_str()) {
                    let hash = hash_basic_auth_password(pass)?;
                    entry["password_hash"] = json!(hash);
                    if let Some(obj) = entry.as_object_mut() {
                        obj.remove("password");
                    }
                }
            }
        }
        _ => {
            if let Some(pass) = cred.get("password").and_then(|p| p.as_str()) {
                let hash = hash_basic_auth_password(pass)?;
                cred["password_hash"] = json!(hash);
                if let Some(obj) = cred.as_object_mut() {
                    obj.remove("password");
                }
            }
        }
    }
    Ok(())
}

/// Best-effort OS-level port availability check.
///
/// Probes only the transport that the stream proxy will actually bind (TCP or
/// UDP), matching the runtime behavior in `stream_listener.rs`. This avoids
/// false positives where an unrelated service on a different transport occupies
/// the same numeric port.
///
/// There is an inherent TOCTOU race (the port could be taken between the check
/// and the actual listener bind), but this catches the vast majority of real
/// conflicts and provides a clear error at the admin API level rather than a
/// silent startup failure.
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
