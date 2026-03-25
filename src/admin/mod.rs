//! Admin API for Ferrum Gateway
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::admin::jwt_auth::{JwtError, JwtManager};
use crate::config::db_loader::DatabaseStore;
use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::plugins;
use crate::proxy::ProxyState;
use arc_swap::ArcSwap;

/// Admin API state.
#[derive(Clone)]
pub struct AdminState {
    pub db: Option<Arc<DatabaseStore>>,
    pub jwt_manager: JwtManager,
    pub proxy_state: Option<ProxyState>,
    /// In-memory cached config for resilient reads when DB is unavailable.
    /// Falls back to this when database queries fail or no DB is configured.
    pub cached_config: Option<Arc<ArcSwap<GatewayConfig>>>,
    pub mode: String,
    pub read_only: bool,
}

impl AdminState {
    /// Get the current cached config if available.
    fn cached_gateway_config(&self) -> Option<Arc<GatewayConfig>> {
        self.cached_config.as_ref().map(|c| c.load_full())
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

    // Serve the HTTP service over TLS
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);

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

/// Handle an admin API request.
pub async fn handle_admin_request(
    req: Request<Incoming>,
    state: AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Health check (unauthenticated)
    if path == "/health" || path == "/status" {
        let mut health_status = json!({
            "status": "ok",
            "timestamp": Utc::now().to_rfc3339(),
            "mode": state.mode
        });

        // Check database connectivity if available
        if let Some(db) = &state.db {
            match sqlx::query("SELECT 1").fetch_one(db.pool()).await {
                Ok(_) => {
                    health_status["database"] = json!({
                        "status": "connected",
                        "type": db.db_type()
                    });
                }
                Err(e) => {
                    health_status["status"] = json!("degraded");
                    health_status["database"] = json!({
                        "status": "disconnected",
                        "type": db.db_type(),
                        "error": e.to_string()
                    });
                }
            }
        }

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

        return Ok(json_response(StatusCode::OK, &health_status));
    }

    // Prometheus metrics endpoint (unauthenticated for scraping)
    if path == "/metrics" && method == Method::GET {
        let registry = crate::plugins::prometheus_metrics::global_registry();
        let metrics_output = registry.render();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(metrics_output)))
            .unwrap_or_else(|_| {
                Response::new(Full::new(Bytes::from("# error rendering metrics\n")))
            });
        return Ok(resp);
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

    // Read body with 1 MiB size limit
    const MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MiB
    let body_bytes = match Limited::new(req.into_body(), MAX_BODY_SIZE).collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("length limit exceeded") {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &json!({"error": "Request body too large (max 1 MiB)"}),
                ));
            }
            Vec::new()
        }
    };

    // Route
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // Proxies CRUD
        (Method::GET, ["proxies"]) => handle_list_proxies(&state).await,
        (Method::POST, ["proxies"]) => handle_create_proxy(&state, &body_bytes).await,
        (Method::GET, ["proxies", id]) => handle_get_proxy(&state, id).await,
        (Method::PUT, ["proxies", id]) => handle_update_proxy(&state, id, &body_bytes).await,
        (Method::DELETE, ["proxies", id]) => handle_delete_proxy(&state, id).await,

        // Consumers CRUD
        (Method::GET, ["consumers"]) => handle_list_consumers(&state).await,
        (Method::POST, ["consumers"]) => handle_create_consumer(&state, &body_bytes).await,
        (Method::GET, ["consumers", id]) => handle_get_consumer(&state, id).await,
        (Method::PUT, ["consumers", id]) => handle_update_consumer(&state, id, &body_bytes).await,
        (Method::DELETE, ["consumers", id]) => handle_delete_consumer(&state, id).await,

        // Consumer credentials
        (Method::PUT, ["consumers", consumer_id, "credentials", cred_type]) => {
            handle_update_credentials(&state, consumer_id, cred_type, &body_bytes).await
        }
        (Method::DELETE, ["consumers", consumer_id, "credentials", cred_type]) => {
            handle_delete_credentials(&state, consumer_id, cred_type).await
        }

        // Plugins
        (Method::GET, ["plugins"]) => handle_list_plugin_types().await,
        (Method::GET, ["plugins", "config"]) => handle_list_plugin_configs(&state).await,
        (Method::POST, ["plugins", "config"]) => {
            handle_create_plugin_config(&state, &body_bytes).await
        }
        (Method::GET, ["plugins", "config", id]) => handle_get_plugin_config(&state, id).await,
        (Method::PUT, ["plugins", "config", id]) => {
            handle_update_plugin_config(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["plugins", "config", id]) => {
            handle_delete_plugin_config(&state, id).await
        }

        // Upstreams CRUD
        (Method::GET, ["upstreams"]) => handle_list_upstreams(&state).await,
        (Method::POST, ["upstreams"]) => handle_create_upstream(&state, &body_bytes).await,
        (Method::GET, ["upstreams", id]) => handle_get_upstream(&state, id).await,
        (Method::PUT, ["upstreams", id]) => handle_update_upstream(&state, id, &body_bytes).await,
        (Method::DELETE, ["upstreams", id]) => handle_delete_upstream(&state, id).await,

        // Metrics
        (Method::GET, ["admin", "metrics"]) => handle_metrics(&state).await,

        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Not Found"}),
        )),
    }
}

// ---- Proxy CRUD ----

async fn handle_list_proxies(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db.load_full_config().await {
            Ok(config) => return Ok(json_response(StatusCode::OK, &json!(config.proxies))),
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
        Ok(json_response_with_stale(
            StatusCode::OK,
            &json!(config.proxies),
        ))
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    // Validate proxy fields
    if proxy.listen_path.is_empty() || !proxy.listen_path.starts_with('/') {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "listen_path must be non-empty and start with '/'"}),
        ));
    }
    if proxy.backend_host.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "backend_host must be non-empty"}),
        ));
    }
    if proxy.backend_port == 0 {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "backend_port must be greater than 0"}),
        ));
    }

    if proxy.id.is_empty() {
        proxy.id = Uuid::new_v4().to_string();
    }
    proxy.created_at = Utc::now();
    proxy.updated_at = Utc::now();

    // Check listen_path uniqueness
    match db.check_listen_path_unique(&proxy.listen_path, None).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": "listen_path already exists"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("Database error: {}", e)}),
            ));
        }
    }

    // Check proxy name uniqueness (when present)
    if let Some(ref name) = proxy.name {
        match db.check_proxy_name_unique(name, None).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
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
                    &json!({"error": format!("Database error: {}", e)}),
                ));
            }
        }
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_proxy(id).await {
            Ok(Some(proxy)) => return Ok(json_response(StatusCode::OK, &json!(proxy))),
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
        match config.proxies.iter().find(|p| p.id == id) {
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    // Validate proxy fields
    if proxy.listen_path.is_empty() || !proxy.listen_path.starts_with('/') {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "listen_path must be non-empty and start with '/'"}),
        ));
    }
    if proxy.backend_host.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "backend_host must be non-empty"}),
        ));
    }
    if proxy.backend_port == 0 {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "backend_port must be greater than 0"}),
        ));
    }

    proxy.id = id.to_string();
    proxy.updated_at = Utc::now();

    // Check listen_path uniqueness (excluding self)
    match db
        .check_listen_path_unique(&proxy.listen_path, Some(id))
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": "listen_path already exists"}),
            ));
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ));
        }
    }

    // Check proxy name uniqueness excluding self (when present)
    if let Some(ref name) = proxy.name {
        match db.check_proxy_name_unique(name, Some(id)).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
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
                    &json!({"error": format!("Database error: {}", e)}),
                ));
            }
        }
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

async fn handle_list_consumers(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db.load_full_config().await {
            Ok(config) => {
                let redacted: Vec<_> = config
                    .consumers
                    .iter()
                    .map(redact_consumer_credentials)
                    .collect();
                return Ok(json_response(StatusCode::OK, &json!(redacted)));
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
            .map(redact_consumer_credentials)
            .collect();
        Ok(json_response_with_stale(StatusCode::OK, &json!(redacted)))
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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
    }

    // Validate username is non-empty
    if consumer.username.trim().is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Consumer username must not be empty"}),
        ));
    }

    // Normalize custom_id: treat empty string as None
    if let Some(ref cid) = consumer.custom_id
        && cid.trim().is_empty()
    {
        consumer.custom_id = None;
    }

    consumer.created_at = Utc::now();
    consumer.updated_at = Utc::now();

    // Hash any secrets in credentials
    if let Err(e) = hash_consumer_secrets(&mut consumer) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": e}),
        ));
    }

    // Check keyauth API key uniqueness (if present in credentials)
    if let Some(key_creds) = consumer.credentials.get("keyauth")
        && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
    {
        match db.check_keyauth_key_unique(key, None).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
                ));
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_consumer(id).await {
            Ok(Some(c)) => {
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
        match config.consumers.iter().find(|c| c.id == id) {
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

    // Normalize custom_id: treat empty string as None
    if let Some(ref cid) = consumer.custom_id
        && cid.trim().is_empty()
    {
        consumer.custom_id = None;
    }

    if let Err(e) = hash_consumer_secrets(&mut consumer) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": e}),
        ));
    }

    // Check keyauth API key uniqueness excluding self (if present)
    if let Some(key_creds) = consumer.credentials.get("keyauth")
        && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
    {
        match db.check_keyauth_key_unique(key, Some(id)).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
                ));
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

async fn handle_update_credentials(
    state: &AdminState,
    consumer_id: &str,
    cred_type: &str,
    body: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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
            let mut hashed_cred = cred_value.clone();
            // Hash password if basicauth
            if cred_type == "basicauth"
                && let Some(pass) = hashed_cred.get("password").and_then(|p| p.as_str())
            {
                let hash = match hash_basic_auth_password(pass) {
                    Ok(h) => h,
                    Err(e) => {
                        return Ok(json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &json!({"error": e}),
                        ));
                    }
                };
                hashed_cred["password_hash"] = json!(hash);
                // Remove plaintext
                if let Some(obj) = hashed_cred.as_object_mut() {
                    obj.remove("password");
                }
            }
            // Check keyauth API key uniqueness before updating
            if cred_type == "keyauth"
                && let Some(key) = hashed_cred.get("key").and_then(|k| k.as_str())
            {
                match db.check_keyauth_key_unique(key, Some(consumer_id)).await {
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
                            &json!({"error": format!("Database error: {}", e)}),
                        ));
                    }
                }
            }

            consumer
                .credentials
                .insert(cred_type.to_string(), hashed_cred);
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

// ---- Plugin CRUD ----

async fn handle_list_plugin_types() -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(json_response(
        StatusCode::OK,
        &json!(plugins::available_plugins()),
    ))
}

async fn handle_list_plugin_configs(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db.load_full_config().await {
            Ok(config) => return Ok(json_response(StatusCode::OK, &json!(config.plugin_configs))),
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
        Ok(json_response_with_stale(
            StatusCode::OK,
            &json!(config.plugin_configs),
        ))
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

async fn handle_create_plugin_config(
    state: &AdminState,
    body: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

    let mut pc: PluginConfig = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ));
        }
    };

    if pc.id.is_empty() {
        pc.id = Uuid::new_v4().to_string();
    }

    // Validate plugin name is a known plugin
    let known_plugins = crate::plugins::available_plugins();
    if !known_plugins.contains(&pc.plugin_name.as_str()) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Unknown plugin name '{}'. Available plugins: {:?}", pc.plugin_name, known_plugins)}),
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_plugin_config(id).await {
            Ok(Some(pc)) => return Ok(json_response(StatusCode::OK, &json!(pc))),
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
        match config.plugin_configs.iter().find(|pc| pc.id == id) {
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

async fn handle_list_upstreams(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first, fall back to cached config for resilience
    if let Some(ref db) = state.db {
        match db.load_full_config().await {
            Ok(config) => return Ok(json_response(StatusCode::OK, &json!(config.upstreams))),
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
        Ok(json_response_with_stale(
            StatusCode::OK,
            &json!(config.upstreams),
        ))
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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
    }
    upstream.created_at = Utc::now();
    upstream.updated_at = Utc::now();

    if upstream.targets.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "At least one target is required"}),
        ));
    }

    // Check upstream name uniqueness (when present)
    if let Some(ref name) = upstream.name {
        match db.check_upstream_name_unique(name, None).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Try database first
    if let Some(ref db) = state.db {
        match db.get_upstream(id).await {
            Ok(Some(upstream)) => return Ok(json_response(StatusCode::OK, &json!(upstream))),
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
        match config.upstreams.iter().find(|u| u.id == id) {
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

    if upstream.targets.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "At least one target is required"}),
        ));
    }

    // Check upstream name uniqueness excluding self (when present)
    if let Some(ref name) = upstream.name {
        match db.check_upstream_name_unique(name, Some(id)).await {
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
                    &json!({"error": format!("Database error: {}", e)}),
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"}),
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

async fn handle_metrics(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut status_codes = serde_json::Map::new();

    if let Some(ref ps) = state.proxy_state {
        for entry in ps.status_counts.iter() {
            status_codes.insert(
                entry.key().to_string(),
                json!(entry.value().load(Ordering::Relaxed)),
            );
        }

        let config = ps.current_config();
        let rps = ps.request_count.load(Ordering::Relaxed);

        let config_source_status = match &state.db {
            Some(_) => "online",
            None => "n/a",
        };

        let metrics = json!({
            "mode": state.mode,
            "config_last_updated_at": config.loaded_at.to_rfc3339(),
            "config_source_status": config_source_status,
            "proxy_count": config.proxies.len(),
            "consumer_count": config.consumers.len(),
            "requests_per_second_current": rps,
            "status_codes_last_second": status_codes,
        });

        Ok(json_response(StatusCode::OK, &metrics))
    } else {
        let metrics = json!({
            "mode": state.mode,
            "config_last_updated_at": null,
            "config_source_status": "n/a",
            "proxy_count": 0,
            "consumer_count": 0,
            "requests_per_second_current": 0,
            "status_codes_last_second": {},
        });

        Ok(json_response(StatusCode::OK, &metrics))
    }
}

// ---- Helpers ----

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
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
        .body(Full::new(Bytes::from(body_str)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
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
fn redact_consumer_credentials(consumer: &Consumer) -> Consumer {
    let mut redacted = consumer.clone();
    if let Some(basic) = redacted.credentials.get_mut("basicauth")
        && let Some(obj) = basic.as_object_mut()
        && obj.contains_key("password_hash")
    {
        obj.insert("password_hash".to_string(), json!("[REDACTED]"));
    }
    redacted
}

fn hash_consumer_secrets(consumer: &mut Consumer) -> Result<(), String> {
    // Hash basicauth passwords
    if let Some(basic) = consumer.credentials.get_mut("basicauth")
        && let Some(pass) = basic.get("password").and_then(|p| p.as_str())
    {
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
    Ok(())
}

/// Hash a plaintext password for basic_auth storage.
///
/// When `FERRUM_BASIC_AUTH_HMAC_SECRET` is set, produces an `hmac_sha256:<hex>` hash
/// (~1μs verification). Otherwise falls back to bcrypt ($2b$, ~100ms verification).
fn hash_basic_auth_password(password: &str) -> Result<String, String> {
    if let Ok(secret) = std::env::var("FERRUM_BASIC_AUTH_HMAC_SECRET")
        && !secret.is_empty()
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("Failed to create HMAC instance: {}", e))?;
        mac.update(password.as_bytes());
        let hash = hex::encode(mac.finalize().into_bytes());
        return Ok(format!("hmac_sha256:{}", hash));
    }

    // Fallback to bcrypt
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| format!("Failed to hash password: {}", e))
}
