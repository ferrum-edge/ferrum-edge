//! Admin API for Ferrum Gateway
//! 
//! Provides REST API for managing proxies, consumers, and plugins
//! with JWT-based authentication and authorization.

pub mod jwt_auth;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::admin::jwt_auth::{JwtManager, JwtError};
use crate::config::db_loader::DatabaseStore;
use crate::config::types::{Consumer, PluginConfig, Proxy};
use crate::plugins;
use crate::proxy::ProxyState;

/// Admin API state.
#[derive(Clone)]
pub struct AdminState {
    pub db: Option<Arc<DatabaseStore>>,
    pub jwt_manager: JwtManager,
    pub proxy_state: Option<ProxyState>,
    pub mode: String,
    pub read_only: bool,
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
            warn!("Admin TLS handshake failed from {}: {}", remote_addr.ip(), e);
            return Err(e.into());
        }
    };
    
    // Convert TLS stream to TokioIo for hyper
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    
    // Use the same HTTP service function
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        async move {
            handle_admin_request(req, state).await
        }
    });

    // Serve the HTTP service over TLS
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc);
    
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
        async move {
            handle_admin_request(req, state).await
        }
    });
    
    if let Err(e) = http1::Builder::new()
        .serve_connection(io, svc)
        .await
    {
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

        return Ok(json_response(StatusCode::OK, &health_status));
    }

    // Authenticate
    match state.jwt_manager.verify_request(req.headers().get("authorization").and_then(|h| h.to_str().ok())) {
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
        Err(JwtError::TokenExpired) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Token expired"}),
            ));
        }
        Err(JwtError::TokenNotYetValid) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Token not yet valid"}),
            ));
        }
        Err(JwtError::InvalidTokenIssuer) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Invalid token issuer"}),
            ));
        }
        Err(JwtError::InvalidTokenSignature) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": "Invalid token signature"}),
            ));
        }
        Err(JwtError::VerificationFailed(msg)) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({"error": format!("Token verification failed: {}", msg)}),
            ));
        }
    }

    // Read body
    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => Vec::new(),
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
        (Method::PUT, ["consumers", id]) => {
            handle_update_consumer(&state, id, &body_bytes).await
        }
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
        (Method::GET, ["plugins", "config", id]) => {
            handle_get_plugin_config(&state, id).await
        }
        (Method::PUT, ["plugins", "config", id]) => {
            handle_update_plugin_config(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["plugins", "config", id]) => {
            handle_delete_plugin_config(&state, id).await
        }

        // Metrics
        (Method::GET, ["admin", "metrics"]) => handle_metrics(&state).await,

        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Not Found"}),
        )),
    }
}

// ---- Proxy CRUD ----

async fn handle_list_proxies(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match db.load_full_config().await {
            Ok(config) => Ok(json_response(StatusCode::OK, &json!(config.proxies))),
            Err(e) => Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("Database error: {}", e)}),
            )),
        }
    } else {
        Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database configured"}),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    if proxy.id.is_empty() {
        proxy.id = Uuid::new_v4().to_string();
    }
    proxy.created_at = Utc::now();
    proxy.updated_at = Utc::now();

    // Check uniqueness
    match db.check_listen_path_unique(&proxy.listen_path, None).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": "listen_path already exists"}),
            ))
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("Database error: {}", e)}),
            ))
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
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    match db.get_proxy(id).await {
        Ok(Some(proxy)) => Ok(json_response(StatusCode::OK, &json!(proxy))),
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Proxy not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut proxy: Proxy = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    proxy.id = id.to_string();
    proxy.updated_at = Utc::now();

    // Check uniqueness (excluding self)
    match db
        .check_listen_path_unique(&proxy.listen_path, Some(id))
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(json_response(
                StatusCode::CONFLICT,
                &json!({"error": "listen_path already exists"}),
            ))
        }
        Err(e) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("{}", e)}),
            ))
        }
    }

    match db.update_proxy(&proxy).await {
        Ok(_) => Ok(json_response(StatusCode::OK, &json!(proxy))),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
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

async fn handle_list_consumers(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    match db.load_full_config().await {
        Ok(config) => Ok(json_response(StatusCode::OK, &json!(config.consumers))),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut consumer: Consumer = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    if consumer.id.is_empty() {
        consumer.id = Uuid::new_v4().to_string();
    }
    consumer.created_at = Utc::now();
    consumer.updated_at = Utc::now();

    // Hash any secrets in credentials
    hash_consumer_secrets(&mut consumer);

    match db.create_consumer(&consumer).await {
        Ok(_) => Ok(json_response(StatusCode::CREATED, &json!(consumer))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
    }
}

async fn handle_get_consumer(
    state: &AdminState,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    match db.get_consumer(id).await {
        Ok(Some(c)) => Ok(json_response(StatusCode::OK, &json!(c))),
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

async fn handle_update_consumer(
    state: &AdminState,
    id: &str,
    body: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check if admin API is in read-only mode
    if state.read_only {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut consumer: Consumer = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    consumer.id = id.to_string();
    consumer.updated_at = Utc::now();
    hash_consumer_secrets(&mut consumer);

    match db.update_consumer(&consumer).await {
        Ok(_) => Ok(json_response(StatusCode::OK, &json!(consumer))),
        Err(e) => Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("{}", e)}),
        )),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
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
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let cred_value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    match db.get_consumer(consumer_id).await {
        Ok(Some(mut consumer)) => {
            let mut hashed_cred = cred_value.clone();
            // Hash password if basicauth
            if cred_type == "basicauth"
                && let Some(pass) = hashed_cred.get("password").and_then(|p| p.as_str())
            {
                let hash = bcrypt::hash(pass, bcrypt::DEFAULT_COST).unwrap_or_default();
                hashed_cred["password_hash"] = json!(hash);
                // Remove plaintext
                if let Some(obj) = hashed_cred.as_object_mut() {
                    obj.remove("password");
                }
            }
            consumer.credentials.insert(cred_type.to_string(), hashed_cred);
            consumer.updated_at = Utc::now();
            match db.update_consumer(&consumer).await {
                Ok(_) => Ok(json_response(StatusCode::OK, &json!(consumer))),
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
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
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
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    match db.load_full_config().await {
        Ok(config) => Ok(json_response(StatusCode::OK, &json!(config.plugin_configs))),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut pc: PluginConfig = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
        }
    };

    if pc.id.is_empty() {
        pc.id = Uuid::new_v4().to_string();
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
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    match db.get_plugin_config(id).await {
        Ok(Some(pc)) => Ok(json_response(StatusCode::OK, &json!(pc))),
        Ok(None) => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Plugin config not found"}),
        )),
        Err(e) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("{}", e)}),
        )),
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
        }
    };

    let mut pc: PluginConfig = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", e)}),
            ))
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
            &json!({"error": "Admin API is in read-only mode"})
        ));
    }

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ))
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

// ---- Metrics ----

async fn handle_metrics(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
        .unwrap()
}

fn hash_consumer_secrets(consumer: &mut Consumer) {
    // Hash basicauth passwords
    if let Some(basic) = consumer.credentials.get_mut("basicauth")
        && let Some(pass) = basic.get("password").and_then(|p| p.as_str())
    {
        let hash = bcrypt::hash(pass, bcrypt::DEFAULT_COST).unwrap_or_default();
        basic["password_hash"] = json!(hash);
        if let Some(obj) = basic.as_object_mut() {
            obj.remove("password");
        }
    }
}
