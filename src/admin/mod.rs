//! Admin API for Ferrum Edge.

pub mod api_specs;
pub mod audit;
mod backup;
pub(crate) mod crud;
pub mod jwt_auth;
pub mod mesh_config_drift;
pub mod mesh_remote_clusters;
pub mod spec_codec;
mod tls_management;

use bytes::Bytes;
use chrono::{DateTime, Utc};
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
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::admin::audit::AuditActor;
use crate::admin::backup::{
    BackupCounts, BackupPayload, RestorePayload, filter_config_by_namespace,
    parse_backup_resources, parse_restore_confirm,
};
use crate::admin::jwt_auth::{AdminRole, JwtError, JwtManager};
use crate::config::db_backend::DatabaseBackend;
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream, max_credentials_per_type,
};
use crate::config::validation_pipeline::{ValidationAction, ValidationPipeline};
use crate::grpc::cp_server::DpNodeRegistry;
use crate::grpc::dp_client::DpCpConnectionState;
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::plugins;
use crate::proxy::ProxyState;
use crate::tls::managed::ManagedTlsMaterialKind;
use crate::util::body_limit::is_length_limit_error;
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
    /// Enables database-backed audit events for successful admin mutations.
    pub admin_audit_enabled: bool,
    /// Startup readiness flag — flipped once by the mode after the initial config
    /// is loaded, all caches are built, DNS/pools are warmed, and every listener
    /// (proxy, admin, stream) is bound and accepting connections.
    ///
    /// While `false`, `/health` returns 503 `"starting"`. Once `true`, `/health`
    /// returns 200 (possibly `"degraded"` if DB is unreachable).
    ///
    /// **Intentionally set before the DB polling loop starts** in database and CP
    /// modes. Two paths apply in database mode:
    ///
    ///   1. Normal — `load_full_config()` succeeded, proving DB connectivity.
    ///   2. Backup — `load_full_config()` failed but `FERRUM_DB_CONFIG_BACKUP_PATH`
    ///      was set, so config was restored from the on-disk backup. `db_available`
    ///      starts `false`, `/health` reports `"degraded"`, and admin writes are
    ///      blocked until the polling loop reconnects to the DB.
    ///
    /// CP mode always requires a live DB (no backup path).
    ///
    /// The polling loop handles *ongoing incremental updates*, not initial
    /// readiness. `/health` independently validates DB connectivity via a
    /// `SELECT 1` check (cached 15 s via `cached_db_health`), so DB failures
    /// surface in the health response regardless of polling state. Deferring
    /// readiness until the first poll tick would add an unnecessary
    /// `FERRUM_DB_POLL_INTERVAL_SECONDS` (default 30 s) startup delay.
    ///
    /// DP mode differs: it starts with an empty config and defers `startup_ready`
    /// until the first CP snapshot is applied + backend capabilities are classified.
    pub startup_ready: Option<Arc<AtomicBool>>,
    /// Dynamic flag set by the DB polling loop. When `false`, write operations
    /// are rejected early to preserve the cached config until the DB recovers.
    /// This flag is orthogonal to `startup_ready` — a gateway can be ready to
    /// serve traffic (`startup_ready=true`) while admin writes are blocked
    /// (`db_available=false`) during a transient DB outage.
    pub db_available: Option<Arc<AtomicBool>>,
    /// Max request body size in MiB for POST /restore.
    pub admin_restore_max_body_size_mib: usize,
    /// Max request body size in MiB for POST/PUT /api-specs.
    pub admin_spec_max_body_size_mib: usize,
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
    /// Registry of connected mesh config-stream nodes (CP mode only).
    pub mesh_registry: Option<Arc<MeshNodeRegistry>>,
    /// Connection state to the CP (DP mode only).
    pub cp_connection_state: Option<Arc<ArcSwap<DpCpConnectionState>>>,
    /// Live mesh runtime state (mesh mode only). Carries the per-runtime egress
    /// scope snapshot/counters powering `/mesh/egress-scope` and `/health`.
    pub mesh_runtime_state: Option<crate::modes::mesh::runtime::MeshRuntimeState>,
    /// Admin HTTP header read timeout (seconds). 0 disables.
    pub admin_http_header_read_timeout_seconds: u64,
    /// Admin TLS handshake timeout (seconds). 0 disables.
    pub admin_tls_handshake_timeout_seconds: u64,
    /// Configured backend IP egress policy (`FERRUM_BACKEND_ALLOW_IPS`). Used to
    /// validate plugin endpoint IPs at the admin boundary in modes without a
    /// `ProxyState` (e.g. control plane), so CP-accepted configs match what data
    /// planes will accept.
    pub backend_allow_ips: crate::config::BackendAllowIps,
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
    start_admin_listener_with_tls_and_signal(addr, state, shutdown, None, None).await
}

/// Start the Admin API listener with optional TLS support.
pub async fn start_admin_listener_with_tls(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    start_admin_listener_with_tls_and_signal(addr, state, shutdown, tls_config, None).await
}

/// Start the Admin API listener with optional TLS support and signal readiness
/// after the TCP socket binds successfully.
pub async fn start_admin_listener_with_tls_and_signal(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Admin API listener started on {}", addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }
    serve_admin_on_listener(listener, state, shutdown, tls_config).await
}

/// Start the Admin API HTTPS listener with a hot-swappable frontend TLS
/// slot. Used when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`. The
/// frontend TLS watch task swaps the underlying `ArcSwap` after a validated
/// cert/key reload; subsequent accepts pick up the new config without
/// restarting the listener. Existing in-flight admin connections keep their
/// original `ServerConfig`.
pub async fn start_admin_listener_with_dynamic_tls(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_slot: crate::tls::SharedFrontendTls,
) -> Result<(), anyhow::Error> {
    start_admin_listener_with_dynamic_tls_and_signal(addr, state, shutdown, tls_slot, None).await
}

/// Start the Admin API HTTPS listener with a hot-swappable frontend TLS slot
/// and signal readiness after the TCP socket binds successfully.
pub async fn start_admin_listener_with_dynamic_tls_and_signal(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_slot: crate::tls::SharedFrontendTls,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Admin API listener started on {}", addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }
    serve_admin_on_listener_with_dynamic_tls(listener, state, shutdown, tls_slot).await
}

/// Run the Admin API accept loop on a pre-bound `TcpListener`.
///
/// Useful for tests that allocate an ephemeral port up front: passing the
/// listener through avoids the bind→drop→rebind window where another process
/// can steal the port between releasing it and the listener task re-binding.
/// Production callers go through [`start_admin_listener`] /
/// [`start_admin_listener_with_tls`], which bind internally.
///
/// `file::serve` (the in-process gateway entry point) also calls this
/// directly when a `ServeOptions::admin_http` / `admin_https` listener is
/// supplied, so the in-process harness shares one accept loop with the
/// binary path.
pub async fn serve_admin_on_listener(
    listener: TcpListener,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    let mut shutdown_rx = shutdown;
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
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
                        // Bound the log rate independently of the backoff: an
                        // abort/reset flood is not backed off, so emit the
                        // first error then one summary per second with the
                        // suppressed count.
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            error!(suppressed, "Failed to accept admin connection: {}", e);
                        }
                        // Back off on a sustained fd-exhaustion run so accept()
                        // cannot busy-spin a core (abort/reset floods make
                        // progress and are not throttled; see AcceptBackoff).
                        if let Some(delay) = accept_backoff.on_error(e.kind()) {
                            tokio::time::sleep(delay).await;
                        }
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

/// Admin HTTPS accept loop that reads the active `Arc<rustls::ServerConfig>`
/// from a shared `ArcSwap` slot on every new connection, allowing the
/// frontend TLS file-watch task to atomically swap in a rotated cert/key
/// pair without restarting the listener.
///
/// In-flight admin connections keep their original `ServerConfig` (rustls
/// consults the config only during the handshake; swapping it does not tear
/// down live sessions). When the slot holds `None` (e.g., live reload was
/// turned on with no cert/key configured), the connection is dropped with
/// a debug log — the admin listener cannot serve TLS without a config and
/// must not silently downgrade to plaintext.
pub async fn serve_admin_on_listener_with_dynamic_tls(
    listener: TcpListener,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_slot: crate::tls::SharedFrontendTls,
) -> Result<(), anyhow::Error> {
    let mut shutdown_rx = shutdown;
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
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

                        let tls_config = tls_slot.load().as_ref().clone();
                        let state = state.clone();

                        tokio::spawn(async move {
                            let Some(tls_config) = tls_config else {
                                debug!(
                                    remote_addr = %remote_addr.ip(),
                                    "Admin HTTPS connection dropped: TLS slot is empty (live-reload race or misconfiguration)"
                                );
                                drop(stream);
                                return;
                            };
                            if let Err(e) =
                                handle_admin_tls_connection(stream, remote_addr, state, tls_config)
                                    .await
                            {
                                debug!("Admin connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        // Bound the log rate independently of the backoff: an
                        // abort/reset flood is not backed off, so emit the
                        // first error then one summary per second with the
                        // suppressed count.
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            error!(suppressed, "Failed to accept admin connection: {}", e);
                        }
                        // Back off on a sustained fd-exhaustion run so accept()
                        // cannot busy-spin a core (abort/reset floods make
                        // progress and are not throttled; see AcceptBackoff).
                        if let Some(delay) = accept_backoff.on_error(e.kind()) {
                            tokio::time::sleep(delay).await;
                        }
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
    let tls_handshake_timeout = state.admin_tls_handshake_timeout_seconds;
    let header_read_timeout = state.admin_http_header_read_timeout_seconds;
    let tls_stream = crate::tls::accept_with_optional_timeout(
        &acceptor,
        stream,
        tls_handshake_timeout,
        &remote_addr,
        false,
    )
    .await?;
    info!("Admin TLS connection established from {}", remote_addr.ip());

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
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    // This header timer only applies to the HTTP/1 admin path; this builder
    // does not expose an equivalent HTTP/2 admin header deadline.
    if header_read_timeout > 0 {
        let mut http1 = builder.http1();
        http1.timer(hyper_util::rt::TokioTimer::new());
        http1.header_read_timeout(Duration::from_secs(header_read_timeout));
    }
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
    let header_read_timeout_seconds = state.admin_http_header_read_timeout_seconds;
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_admin_request(req, state).await }
    });

    let mut builder = http1::Builder::new();
    if header_read_timeout_seconds > 0 {
        builder.timer(hyper_util::rt::TokioTimer::new());
        builder.header_read_timeout(Duration::from_secs(header_read_timeout_seconds));
    }

    if let Err(e) = builder.serve_connection(io, svc).await {
        error!("Admin HTTP connection error: {}", e);
    }

    Ok(())
}

/// Pagination parameters parsed from query string.
pub(crate) struct PaginationParams {
    offset: usize,
    limit: Option<usize>,
}

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

impl PaginationParams {
    fn in_memory_limit(&self) -> usize {
        self.limit.unwrap_or(usize::MAX)
    }

    pub(crate) fn query_limit_i64(&self) -> i64 {
        self.limit.map(|limit| limit as i64).unwrap_or(i64::MAX)
    }

    fn response_limit(&self, total: usize) -> usize {
        self.limit
            .unwrap_or_else(|| total.saturating_sub(self.offset))
    }
}

fn parse_pagination(uri: &hyper::Uri) -> PaginationParams {
    let mut offset = 0usize;
    let mut limit = None;
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                match key {
                    "offset" => {
                        offset = val.parse().unwrap_or(0);
                    }
                    "limit" => {
                        let parsed = val.parse().unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
                        limit = Some(if parsed == 0 {
                            DEFAULT_PAGE_SIZE
                        } else {
                            parsed
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    PaginationParams { offset, limit }
}

fn require_admin_role(actor: &AuditActor, required: AdminRole) -> Option<Response<Full<Bytes>>> {
    if actor.role.allows(required) {
        return None;
    }
    Some(json_response(
        StatusCode::FORBIDDEN,
        &json!({
            "error": format!(
                "Admin role '{}' cannot access this endpoint; required role is '{}'",
                actor.role.as_str(),
                required.as_str()
            )
        }),
    ))
}

pub(crate) fn log_audit_enqueue_failure(error: &anyhow::Error) {
    warn!(
        error = %error,
        "Admin mutation persisted but audit event was not enqueued"
    );
}

/// Apply pagination to a serializable collection.
/// Always wraps the response in an envelope with metadata.
fn paginate_response(items: &Value, pagination: &PaginationParams) -> Value {
    let arr = match items.as_array() {
        Some(a) => a,
        None => return items.clone(),
    };
    let total = arr.len();
    let paginated: Vec<_> = arr
        .iter()
        .skip(pagination.offset)
        .take(pagination.in_memory_limit())
        .collect();
    json!({
        "data": paginated,
        "pagination": {
            "offset": pagination.offset,
            "limit": pagination.response_limit(total),
            "total": total
        }
    })
}

/// Build pagination envelope from database-paginated results.
fn paginate_db_response<T: Serialize>(
    items: &[T],
    total: i64,
    pagination: &PaginationParams,
) -> Value {
    json!({
        "data": items,
        "pagination": {
            "offset": pagination.offset,
            "limit": pagination.response_limit(total.max(0) as usize),
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

        // Acquire pairs with the Release store in each mode's startup path
        // (dp_client, file, database, control_plane). On x86 this is free;
        // on ARM it ensures cross-task visibility of the readiness flip.
        let startup_ready = state
            .startup_ready
            .as_ref()
            .is_none_or(|flag| flag.load(Ordering::Acquire));
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

        if state.mode == "database"
            && let Some(snapshot) = crate::plugins::prometheus_metrics::global_registry()
                .database_delta_poll_metrics_snapshot()
        {
            if let Some(degraded) = snapshot.degraded {
                health_status["status"] = json!("degraded");
                health_status["database_polling"] = json!({
                    "status": "degraded",
                    "reason": degraded.reason,
                    "resource_category": degraded.resource_category,
                    "validation_category": degraded.validation_category,
                    "consecutive_identical_rejections": degraded.consecutive_identical_rejections,
                    "current_backoff_bucket": degraded.current_backoff_bucket,
                    "current_backoff_seconds": degraded.current_backoff_seconds,
                    "escalated": degraded.escalated,
                });
            } else {
                health_status["database_polling"] = json!({
                    "status": "ok",
                    "consecutive_identical_rejections": snapshot.consecutive_identical_rejections,
                    "current_backoff_bucket": snapshot.current_backoff_bucket,
                    "current_backoff_seconds": snapshot.current_backoff_seconds,
                });
            }
        }

        if state
            .proxy_state
            .as_ref()
            .is_some_and(|ps| ps.config.load_full().mesh.is_some())
            || state.mode == "mesh"
        {
            let egress_health = state
                .mesh_runtime_state
                .as_ref()
                .map(|rt| rt.egress_scope_state().health())
                .unwrap_or_default();
            health_status["mesh"] = json!({
                "egress_scope": egress_health
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
            let mut snapshot_value = serde_json::to_value(&snapshot).unwrap_or_default();
            if let Some(obj) = snapshot_value.as_object_mut() {
                obj.insert(
                    "stream_listeners".to_string(),
                    serde_json::to_value(proxy_state.stream_listener_manager.overload_snapshot())
                        .unwrap_or_default(),
                );
            }
            return Ok(json_response(status, &snapshot_value));
        }
        return Ok(json_response(
            StatusCode::OK,
            &json!({"level": "normal", "message": "No proxy state available"}),
        ));
    }

    // Prometheus metrics endpoint (unauthenticated for scraping)
    if path == "/metrics" && method == Method::GET {
        let registry = crate::plugins::prometheus_metrics::global_registry();
        let inventory = tls_management::collect_inventory(&state);
        registry.refresh_tls_certificate_inventory(&inventory);
        let mut metrics_output = registry.render();
        metrics_output.push_str(&crate::plugins::api_chargeback_sink::render_prometheus());
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

    // Authenticate
    let auth = match state.jwt_manager.verify_request(
        req.headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok()),
    ) {
        Ok(token_data) => match AuditActor::from_claims(&token_data.claims) {
            Ok(actor) => actor,
            Err(message) => {
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    &json!({"error": message}),
                ));
            }
        },
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
    };

    // API chargeback endpoint. Chargeback output contains customer/business data,
    // so it stays behind the standard admin JWT gate even though it is scrapeable.
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

    if path == "/charges/sink/status" && method == Method::GET {
        let status_output = crate::plugins::api_chargeback_sink::render_status_json();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("X-Content-Type-Options", "nosniff")
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::from(status_output)))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
        return Ok(resp);
    }

    // Extract namespace from X-Ferrum-Namespace header (defaults to "ferrum")
    let namespace = match extract_namespace(req.headers()) {
        Ok(ns) => ns,
        Err(resp) => return Ok(resp),
    };

    // api-specs routes manage their own body reading (configurable limit,
    // content-type inspection, binary blob).  Dispatch them BEFORE the
    // shared body-read below so we don't consume `req` prematurely.
    let segments_peek: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method.clone(), segments_peek.as_slice()) {
        (Method::POST, ["api-specs"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            return api_specs::handlers::handle_post_api_spec(req, &state, &auth, &namespace).await;
        }
        (Method::PUT, ["api-specs", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            if let Err(e) = crate::config::types::validate_resource_id(id) {
                return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": e})));
            }
            let id = id.to_string();
            return api_specs::handlers::handle_put_api_spec(req, &state, &auth, &namespace, &id)
                .await;
        }
        (Method::GET, ["api-specs"]) => {
            return api_specs::handlers::handle_list_api_specs(req, &state, &namespace).await;
        }
        (Method::GET, ["api-specs", "by-proxy", proxy_id]) => {
            if let Err(e) = crate::config::types::validate_resource_id(proxy_id) {
                return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": e})));
            }
            let proxy_id = proxy_id.to_string();
            return api_specs::handlers::handle_get_api_spec_by_proxy(
                req, &state, &namespace, &proxy_id,
            )
            .await;
        }
        (Method::GET, ["api-specs", id]) => {
            if let Err(e) = crate::config::types::validate_resource_id(id) {
                return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": e})));
            }
            let id = id.to_string();
            return api_specs::handlers::handle_get_api_spec(req, &state, &namespace, &id).await;
        }
        (Method::DELETE, ["api-specs", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            if let Err(e) = crate::config::types::validate_resource_id(id) {
                return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": e})));
            }
            let id = id.to_string();
            // DELETE should have no body. Drop the receiver so hyper discards
            // any remaining bytes via Drop without buffering them in userspace.
            drop(req.into_body());
            return api_specs::handlers::handle_delete_api_spec(&state, &auth, &namespace, &id)
                .await;
        }
        _ => {}
    }

    if method == Method::POST
        && matches!(segments_peek.as_slice(), ["restore"] | ["batch"])
        && let Some(resp) = require_admin_role(&auth, AdminRole::Admin)
    {
        drop(req.into_body());
        return Ok(resp);
    }

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
            if is_length_limit_error(e.as_ref()) {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &json!({"error": format!("Request body too large (max {} MiB)", restore_max_mib)}),
                ));
            }
            warn!(
                path = %path,
                error = %e,
                "Admin request body collection failed"
            );
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Failed to read request body"}),
            ));
        }
    };

    // Route
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // Proxies CRUD
        (Method::GET, ["proxies"]) => {
            crud::handle_list::<Proxy>(&state, &pagination, auth.role, &namespace).await
        }
        (Method::GET, ["proxies", id]) => {
            crud::handle_get::<Proxy>(&state, id, auth.role, &namespace).await
        }
        (Method::POST, ["proxies"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_create::<Proxy>(&state, &auth, &body_bytes, &namespace).await
        }
        (Method::PUT, ["proxies", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_update::<Proxy>(&state, &auth, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["proxies", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_delete::<Proxy>(&state, &auth, id, &namespace).await
        }

        // Consumers CRUD
        (Method::GET, ["consumers"]) => {
            crud::handle_list::<Consumer>(&state, &pagination, auth.role, &namespace).await
        }
        (Method::POST, ["consumers"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            crud::handle_create::<Consumer>(&state, &auth, &body_bytes, &namespace).await
        }
        (Method::GET, ["consumers", id]) => {
            crud::handle_get::<Consumer>(&state, id, auth.role, &namespace).await
        }
        (Method::PUT, ["consumers", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            crud::handle_update::<Consumer>(&state, &auth, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["consumers", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            crud::handle_delete::<Consumer>(&state, &auth, id, &namespace).await
        }

        // Consumer credentials
        (Method::PUT, ["consumers", consumer_id, "credentials", cred_type]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_update_credentials(
                &state,
                &auth,
                consumer_id,
                cred_type,
                &body_bytes,
                &namespace,
            )
            .await
        }
        (Method::POST, ["consumers", consumer_id, "credentials", cred_type]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_append_credential(
                &state,
                &auth,
                consumer_id,
                cred_type,
                &body_bytes,
                &namespace,
            )
            .await
        }
        (Method::DELETE, ["consumers", consumer_id, "credentials", cred_type, index]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_delete_credential_by_index(
                &state,
                &auth,
                consumer_id,
                cred_type,
                index,
                &namespace,
            )
            .await
        }
        (Method::DELETE, ["consumers", consumer_id, "credentials", cred_type]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_delete_credentials(&state, &auth, consumer_id, cred_type, &namespace).await
        }

        // Plugins
        (Method::GET, ["plugins"]) => handle_list_plugin_types().await,
        (Method::GET, ["plugins", "config"]) => {
            crud::handle_list::<PluginConfig>(&state, &pagination, auth.role, &namespace).await
        }
        (Method::POST, ["plugins", "config"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_create::<PluginConfig>(&state, &auth, &body_bytes, &namespace).await
        }
        (Method::GET, ["plugins", "config", id]) => {
            crud::handle_get::<PluginConfig>(&state, id, auth.role, &namespace).await
        }
        (Method::PUT, ["plugins", "config", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_update::<PluginConfig>(&state, &auth, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["plugins", "config", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_delete::<PluginConfig>(&state, &auth, id, &namespace).await
        }

        // Upstreams CRUD
        (Method::GET, ["upstreams"]) => {
            crud::handle_list::<Upstream>(&state, &pagination, auth.role, &namespace).await
        }
        (Method::POST, ["upstreams"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_create::<Upstream>(&state, &auth, &body_bytes, &namespace).await
        }
        (Method::GET, ["upstreams", id]) => {
            crud::handle_get::<Upstream>(&state, id, auth.role, &namespace).await
        }
        (Method::PUT, ["upstreams", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_update::<Upstream>(&state, &auth, id, &body_bytes, &namespace).await
        }
        (Method::DELETE, ["upstreams", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            crud::handle_delete::<Upstream>(&state, &auth, id, &namespace).await
        }

        // Batch create
        (Method::POST, ["batch"]) => {
            // Role check happens before body buffering (see pre-buffer gate above).
            handle_batch_create(&state, &auth, &body_bytes, &namespace).await
        }

        // Backup & Restore
        (Method::GET, ["backup"]) => {
            // Backup returns unredacted credentials and consul tokens — Admin only.
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_backup(&state, query.as_deref(), &namespace).await
        }
        (Method::POST, ["restore"]) => {
            // Role check happens before body buffering (see pre-buffer gate above).
            handle_restore(&state, &auth, &body_bytes, query.as_deref(), &namespace).await
        }

        // Audit log
        (Method::GET, ["audit"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            handle_audit_list(&state, &pagination, query.as_deref(), &namespace).await
        }

        // Namespaces
        (Method::GET, ["namespaces"]) => handle_list_namespaces(&state).await,

        // Metrics
        (Method::GET, ["metrics", "runtime"]) => handle_metrics_runtime(&state).await,
        (Method::GET, ["admin", "metrics"]) => handle_metrics(&state).await,

        // TLS certificate lifecycle helpers.
        (Method::GET, ["admin", "tls", "inventory"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_inventory(&state, &pagination).await
        }
        (Method::GET, ["admin", "tls", "events"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_events(&pagination, query.as_deref()).await
        }
        (Method::GET, ["admin", "tls", "acme", "certificates"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_acme_certificates(&pagination).await
        }
        (Method::POST, ["admin", "tls", "acme", "certificates"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_acme_certificate(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "acme", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_acme_certificate(id).await
        }
        (Method::PUT, ["admin", "tls", "acme", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_acme_certificate(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "acme", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_acme_certificate(&state, id).await
        }
        (Method::GET, ["admin", "tls", "acme", "accounts"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_acme_accounts(&pagination).await
        }
        (Method::POST, ["admin", "tls", "acme", "renew", certificate_id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_renew_acme_certificate(&state, certificate_id, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "acme", "orders"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_acme_orders(&pagination).await
        }
        (Method::POST, ["admin", "tls", "acme", "orders"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_acme_order(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "acme", "orders", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_acme_order(id).await
        }
        (Method::POST, ["admin", "tls", "acme", "orders", id, "finalize"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_finalize_acme_order(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "acme", "orders", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_acme_order(&state, id).await
        }
        (Method::GET, ["admin", "tls", "certificates"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_managed(ManagedTlsMaterialKind::Certificate, &pagination)
                .await
        }
        (Method::POST, ["admin", "tls", "certificates"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_certificate(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_managed(ManagedTlsMaterialKind::Certificate, id).await
        }
        (Method::PUT, ["admin", "tls", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_certificate(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_managed(&state, ManagedTlsMaterialKind::Certificate, id)
                .await
        }
        (Method::GET, ["admin", "tls", "ca-bundles"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_managed(ManagedTlsMaterialKind::CaBundle, &pagination).await
        }
        (Method::POST, ["admin", "tls", "ca-bundles"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_ca_bundle(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "ca-bundles", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_managed(ManagedTlsMaterialKind::CaBundle, id).await
        }
        (Method::PUT, ["admin", "tls", "ca-bundles", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_ca_bundle(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "ca-bundles", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_managed(&state, ManagedTlsMaterialKind::CaBundle, id)
                .await
        }
        (Method::GET, ["admin", "tls", "crls"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_managed(ManagedTlsMaterialKind::Crl, &pagination).await
        }
        (Method::POST, ["admin", "tls", "crls"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_crl(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "crls", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_managed(ManagedTlsMaterialKind::Crl, id).await
        }
        (Method::PUT, ["admin", "tls", "crls", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_crl(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "crls", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_managed(&state, ManagedTlsMaterialKind::Crl, id).await
        }
        (Method::GET, ["admin", "tls", "ocsp-responses"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_managed(ManagedTlsMaterialKind::OcspResponse, &pagination)
                .await
        }
        (Method::POST, ["admin", "tls", "ocsp-responses"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_ocsp_response(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "ocsp-responses", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_managed(ManagedTlsMaterialKind::OcspResponse, id).await
        }
        (Method::PUT, ["admin", "tls", "ocsp-responses", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_ocsp_response(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "ocsp-responses", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_managed(&state, ManagedTlsMaterialKind::OcspResponse, id)
                .await
        }
        (Method::GET, ["admin", "tls", "jwks"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_list_managed(ManagedTlsMaterialKind::Jwks, &pagination).await
        }
        (Method::POST, ["admin", "tls", "jwks"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_create_jwks(&state, &body_bytes).await
        }
        (Method::GET, ["admin", "tls", "jwks", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_get_managed(ManagedTlsMaterialKind::Jwks, id).await
        }
        (Method::PUT, ["admin", "tls", "jwks", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_update_jwks(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "jwks", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_delete_managed(&state, ManagedTlsMaterialKind::Jwks, id).await
        }
        (Method::POST, ["admin", "tls", "rotate", surface]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_rotate(&state, surface).await
        }
        (Method::POST, ["admin", "tls", "validate"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            tls_management::handle_validate(&body_bytes).await
        }

        // Mesh service graph
        (Method::GET, ["mesh", "service-graph"]) => handle_mesh_service_graph_get(&state).await,

        // Mesh egress-scope operability
        (Method::GET, ["mesh", "egress-scope"]) => handle_mesh_egress_scope_get(&state).await,
        (Method::POST, ["mesh", "egress-scope", "test"]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            handle_mesh_egress_scope_test(&state, &body_bytes).await
        }

        // Mesh trust-bundle federation status (GAP-3C).
        (Method::GET, ["mesh", "federation"]) => handle_mesh_federation_get(&state).await,

        // GAP-3E: xDS RTDS overlay inspection. Read-only operator view of the
        // runtime knobs the CP has shipped via RTDS. 404 outside mesh mode or
        // before the first slice — same shape as `/mesh/egress-scope`.
        (Method::GET, ["mesh", "runtime-overlay"]) => handle_mesh_runtime_overlay_get(&state).await,

        // MESH-T6-C: per-DP config drift introspection. Read-only operator
        // view of the last-applied slice content fingerprint, age, and RTDS
        // overlay summary. 404 outside mesh mode — same shape as the other
        // `/mesh/*` endpoints. Optional `?include_overlay=false` to omit the
        // overlay block.
        (Method::GET, ["mesh", "config-drift"]) => {
            handle_mesh_config_drift_get(&state, query.as_deref()).await
        }

        // F7.2: remote-cluster discovery introspection. Read-only operator
        // view of the DP's multicluster east-west state — clusters it has
        // actually fetched endpoints from (with per-cluster workload/service
        // counts + fetch age) and the remote clusters declared in the accepted
        // slice. 404 outside mesh mode — same shape as the other `/mesh/*`
        // endpoints.
        (Method::GET, ["mesh", "remote-clusters"]) => handle_mesh_remote_clusters_get(&state).await,

        // MESH-T6-D: aggregated recent mesh_authz denies for ad-hoc triage.
        // The recorder is process-singleton and exception-path only — only
        // `mesh_authz` rejects touch it, and they record under a single
        // `std::sync::Mutex`. The endpoint reads the same recorder via a
        // bounded snapshot and groups by `(rule, source, destination, reason)`.
        // 404 outside mesh mode mirrors the other `/mesh/...` endpoints.
        (Method::GET, ["mesh", "policy-denies", "recent"]) => {
            handle_mesh_policy_denies_recent_get(&state, query.as_deref()).await
        }

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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Operator) {
                return Ok(resp);
            }
            handle_backend_capabilities_refresh(&state).await
        }

        // Node-waypoint enrolled identities (GAP-2M).
        //
        // JWT-authenticated (falls through the admin auth gate above). The
        // resolver is only constructed in mesh-mode `NodeWaypoint` topology;
        // other modes return 404 so unrelated operators don't see a stub
        // empty list and assume node-waypoint is active.
        (Method::GET, ["node-waypoint", "identities"]) => {
            handle_node_waypoint_identities_get(&state).await
        }

        // GAMMA Service-Waypoint resolved binding (GAP-GAMMA-WP).
        //
        // JWT-authenticated. Returns the services bound to this waypoint in
        // the active mesh slice. 404 outside `ServiceWaypoint` topology (the
        // waypoint name and the bound-services projection only exist there).
        (Method::GET, ["service-waypoint", "services"]) => {
            handle_service_waypoint_services_get(&state).await
        }

        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "Not Found"}),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct MeshEgressScopeTestRequest {
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

async fn handle_mesh_egress_scope_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(proxy_state) = state.proxy_state.as_ref() else {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No proxy state available"}),
        ));
    };
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh egress scope"}),
        ));
    };
    let egress = mesh_runtime.egress_scope_state();
    let Some(scope) = egress.snapshot() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh egress scope"}),
        ));
    };
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "namespace": proxy_state.env_config.namespace,
            "scope": scope,
            "health": egress.health(),
        }),
    ))
}

async fn handle_mesh_federation_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh federation"}),
        ));
    };
    let store = mesh_runtime.federation_store();
    if !store.has_first_success() {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No mesh federation bundles cached yet"}),
        ));
    }
    let snapshot = store.snapshot();
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let mut bundles: Vec<serde_json::Value> = snapshot
        .bundles
        .values()
        .map(|fed| {
            json!({
                "cluster": fed.cluster_name,
                "trust_domain": fed.bundle.trust_domain.as_str(),
                "endpoint": fed.endpoint,
                "fetched_at_unix_seconds": fed.fetched_at_unix_seconds,
                "bundle_age_seconds": now.saturating_sub(fed.fetched_at_unix_seconds),
                "x509_authorities": fed.bundle.x509_authorities.len(),
                "jwt_authorities": fed.bundle.jwt_authorities.len(),
                "refresh_hint_seconds": fed.bundle.refresh_hint_seconds,
            })
        })
        .collect();
    // Deterministic ordering for tooling / human reads — `HashMap` iteration
    // order isn't stable across restarts. Cheap on cold paths.
    bundles.sort_by(|a, b| {
        a.get("trust_domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("trust_domain").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "bundles": bundles,
        }),
    ))
}

async fn handle_mesh_service_graph_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh service graph"}),
        ));
    };
    if !mesh_runtime.has_first_slice() {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh service graph"}),
        ));
    }
    let snapshot = crate::plugins::mesh::service_graph::global_service_graph().snapshot();
    Ok(json_response(StatusCode::OK, &json!(snapshot.as_ref())))
}

async fn handle_mesh_runtime_overlay_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh runtime overlay"}),
        ));
    };
    // Read the lock-free accepted-slice snapshot once; consumers (fault
    // injection, transformer gates, log level) read the same overlay via
    // `runtime_overlay_consumers::apply_overlay` after proxy config acceptance.
    // Returning 404 before the first accepted slice mirrors `/mesh/egress-scope`
    // so operators can distinguish "not converged yet" from "slice carries an
    // empty overlay".
    let slice = mesh_runtime.applied_snapshot();
    let Some(slice) = slice.as_ref().as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh runtime overlay"}),
        ));
    };
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "namespace": slice.namespace,
            "version": slice.version,
            "runtime_overlay": &slice.runtime_overlay,
        }),
    ))
}

/// MESH-T6-C: per-DP config drift introspection.
///
/// Returns a structured "where is this DP relative to the CP's last push?"
/// view. Sees only what this DP has accepted into the proxy runtime — cross-DP comparison is
/// done by operator tooling that walks `/mesh/config-drift` on every
/// member of a deployment and diffs the fingerprints.
///
/// Returns 404 outside mesh mode (no `mesh_runtime_state` wired in).
/// Returns 200 with `last_received_at: null` and zeroed `resources` when
/// mesh runtime is wired but no slice has been accepted yet — operators
/// rely on the difference between "404 (wrong mode)" and "200 with
/// `last_received_at: null` (mesh mode, not converged yet)".
async fn handle_mesh_config_drift_get(
    state: &AdminState,
    query: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh runtime state"}),
        ));
    };

    let include_overlay = mesh_config_drift::parse_include_overlay(query);

    // `source_protocol` / `source_cp_url` come from the DP's own env config
    // so the response is populated even before the first slice arrives. The
    // proxy state is the only place we have `EnvConfig` available — mesh
    // mode always sets `proxy_state: Some(...)`, but treat `None` as
    // "fields blank" rather than 503 because the slice/overlay halves of
    // the response are still useful for debugging unwired test states.
    let (source_protocol, source_cp_url) = state
        .proxy_state
        .as_ref()
        .map(|ps| {
            let proto = ps.env_config.mesh_config_protocol.as_str();
            let cp_url = ps
                .env_config
                .resolved_dp_cp_grpc_urls()
                .first()
                .cloned()
                .unwrap_or_default();
            (proto.to_string(), cp_url)
        })
        .unwrap_or_default();

    // Lock-free read of the last proxy-accepted slice and timestamp; received
    // but rejected updates must not appear as the DP's applied fingerprint.
    let slice_snapshot = mesh_runtime.applied_snapshot();
    let last_install_at = mesh_runtime.last_applied_at();

    let resp = mesh_config_drift::build_response(mesh_config_drift::MeshConfigDriftInputs {
        slice: slice_snapshot.as_ref().as_ref(),
        last_install_at,
        now: chrono::Utc::now(),
        source_protocol: &source_protocol,
        source_cp_url: &source_cp_url,
        include_overlay,
        // xDS-mode only; native mode leaves this `None` and the block is omitted.
        convergence: mesh_runtime.xds_convergence(),
    });

    // `MeshConfigDriftResponse` is fully serde-derived; treat a serialize
    // error as a 500 rather than crashing — the admin path has the same
    // "never `.unwrap()` on the request side" rule as the proxy hot path.
    match serde_json::to_value(&resp) {
        Ok(value) => Ok(json_response(StatusCode::OK, &value)),
        Err(err) => {
            error!(error = %err, "failed to serialize mesh config-drift response");
            Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Failed to serialize mesh config-drift response"}),
            ))
        }
    }
}

/// `GET /mesh/remote-clusters` (F7.2): the DP's view of multicluster east-west
/// discovery. JWT-authenticated (falls through the admin auth gate); `404`
/// outside mesh mode like the other `/mesh/*` introspection endpoints. The
/// payload surfaces remote-cluster provenance + per-cluster endpoint counts —
/// never raw workload addresses, SPIFFE IDs, or control-plane URLs.
async fn handle_mesh_remote_clusters_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh runtime state"}),
        ));
    };

    // Lock-free read of the live discovered-remote-cluster snapshot.
    let snapshot = mesh_runtime.remote_endpoint_store().snapshot();

    // The configured remote clusters come from the proxy-accepted slice — a
    // received-but-rejected slice must not appear as the DP's effective
    // multicluster config, matching `/mesh/config-drift`'s accepted-slice read.
    let applied_slice = mesh_runtime.applied_snapshot();
    let multi_cluster = applied_slice
        .as_ref()
        .as_ref()
        .and_then(|slice| slice.multi_cluster.as_ref());
    let trust_bundles = applied_slice
        .as_ref()
        .as_ref()
        .and_then(|slice| slice.trust_bundles.as_ref());
    let federation = mesh_runtime.federation_store().snapshot();

    // Discovery is enabled only when the poll interval is positive. Read from
    // the DP's own env config so the flag is populated even before the first
    // slice / poll. `proxy_state` is always `Some(...)` in mesh mode, but treat
    // `None` as "disabled" rather than 503 — the discovered/configured views
    // are still meaningful for debugging unwired test states.
    let discovery_enabled = state
        .proxy_state
        .as_ref()
        .is_some_and(|ps| ps.env_config.mesh_remote_discovery_poll_interval_seconds > 0);
    let federation_poll_enabled = state
        .proxy_state
        .as_ref()
        .is_some_and(|ps| ps.env_config.mesh_federation_poll_interval_seconds > 0);
    let federation_fail_open = state
        .proxy_state
        .as_ref()
        .is_some_and(|ps| ps.env_config.mesh_federation_fail_open);
    let inbound_spiffe_verifier_configured = state.proxy_state.as_ref().is_some_and(|ps| {
        ps.mesh_inbound_spiffe_verifier_active
            .load(Ordering::Acquire)
    });

    let resp =
        mesh_remote_clusters::build_response(mesh_remote_clusters::MeshRemoteClustersInputs {
            snapshot: snapshot.as_ref(),
            multi_cluster,
            federation: &federation,
            trust_bundles,
            discovery_enabled,
            federation_poll_enabled,
            federation_fail_open,
            inbound_spiffe_verifier_configured,
            // `timestamp()` is non-negative for any realistic wall clock; clamp the
            // theoretical pre-epoch case to 0 rather than casting a negative i64.
            now_unix_seconds: chrono::Utc::now().timestamp().max(0) as u64,
        });

    // `MeshRemoteClustersResponse` is fully serde-derived; treat a serialize
    // error as a 500 rather than `.unwrap()`-ing on the admin path.
    match serde_json::to_value(&resp) {
        Ok(value) => Ok(json_response(StatusCode::OK, &value)),
        Err(err) => {
            error!(error = %err, "failed to serialize mesh remote-clusters response");
            Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Failed to serialize mesh remote-clusters response"}),
            ))
        }
    }
}

/// Maximum `window` query value accepted by `/mesh/policy-denies/recent`.
/// One hour bounds the snapshot the handler walks; longer windows should
/// scrape the Prometheus deny counters instead.
const MESH_POLICY_DENIES_MAX_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Default `window` when the query param is absent.
const MESH_POLICY_DENIES_DEFAULT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Maximum `limit` query value accepted by `/mesh/policy-denies/recent`. The
/// recorder's ring already caps total cardinality, but a per-call cap keeps
/// pathological clients from forcing a 10,000-entry grouped response into
/// every poll.
const MESH_POLICY_DENIES_MAX_LIMIT: usize = 1000;

/// Default `limit` when the query param is absent.
const MESH_POLICY_DENIES_DEFAULT_LIMIT: usize = 50;

async fn handle_mesh_policy_denies_recent_get(
    state: &AdminState,
    query: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // 404 outside mesh mode so non-mesh deployments don't expose a stub
    // empty list and confuse operators about whether mesh_authz is active.
    if state.mesh_runtime_state.is_none() {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh policy-deny recorder"}),
        ));
    }
    let (window, limit) = match parse_mesh_policy_denies_query(query) {
        Ok(parsed) => parsed,
        Err(message) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": message}),
            ));
        }
    };
    let recorder = crate::modes::mesh::policy_deny_log::global();
    let window_chrono = match chrono::Duration::from_std(window) {
        Ok(d) => d,
        Err(e) => {
            // Should be unreachable — `parse_mesh_policy_denies_query` clamps
            // to MESH_POLICY_DENIES_MAX_WINDOW which is well under the
            // chrono limit — but treat overflow defensively rather than
            // panic in production.
            return Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": format!("window overflow: {e}")}),
            ));
        }
    };
    let cutoff = Utc::now() - window_chrono;
    let aggregate = recorder.aggregate_recent(cutoff, limit);
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "window_seconds": window.as_secs(),
            "limit": limit,
            "total_denies": aggregate.total_denies,
            "grouped": aggregate.grouped,
        }),
    ))
}

/// Parse `?window=<dur>&limit=<n>` from the admin query string.
///
/// `window` accepts the compact duration suffixes `s`/`m`/`h` (e.g. `30s`,
/// `5m`, `1h`) as well as bare integer seconds. `limit` is a base-10
/// integer. Both fall back to their `MESH_POLICY_DENIES_DEFAULT_*` constants
/// when absent. Anything else returns `Err(...)` for a 4xx.
fn parse_mesh_policy_denies_query(query: Option<&str>) -> Result<(Duration, usize), String> {
    let mut window = MESH_POLICY_DENIES_DEFAULT_WINDOW;
    let mut limit = MESH_POLICY_DENIES_DEFAULT_LIMIT;
    let Some(raw) = query else {
        return Ok((window, limit));
    };
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match key {
            "window" => {
                window = parse_short_duration(value).map_err(|e| format!("invalid window: {e}"))?;
                if window > MESH_POLICY_DENIES_MAX_WINDOW {
                    return Err(format!(
                        "window exceeds maximum of {} seconds",
                        MESH_POLICY_DENIES_MAX_WINDOW.as_secs()
                    ));
                }
                if window.is_zero() {
                    return Err("window must be > 0".to_string());
                }
            }
            "limit" => {
                let parsed: usize = value
                    .parse()
                    .map_err(|_| "limit must be a non-negative integer".to_string())?;
                if parsed > MESH_POLICY_DENIES_MAX_LIMIT {
                    return Err(format!(
                        "limit exceeds maximum of {MESH_POLICY_DENIES_MAX_LIMIT}"
                    ));
                }
                limit = parsed;
            }
            // Silently ignore unknown query params so future extensions
            // (e.g., `?rule=`) don't 4xx older deployments mid-rollout.
            _ => {}
        }
    }
    Ok((window, limit))
}

/// Parse a short duration string like `30s`, `5m`, `1h`, or a bare integer
/// number of seconds. Rejects empty input, mixed units, fractional values,
/// and overflow.
fn parse_short_duration(raw: &str) -> Result<Duration, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty value".to_string());
    }
    let (number_part, unit_seconds): (&str, u64) = match trimmed.as_bytes().last() {
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 3600),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'0'..=b'9') => (trimmed, 1),
        _ => return Err(format!("unrecognised suffix in '{trimmed}'")),
    };
    if number_part.is_empty() {
        return Err(format!("missing number in '{trimmed}'"));
    }
    let value: u64 = number_part
        .parse()
        .map_err(|_| format!("not a non-negative integer: '{number_part}'"))?;
    let total = value
        .checked_mul(unit_seconds)
        .ok_or_else(|| format!("duration overflow for '{trimmed}'"))?;
    Ok(Duration::from_secs(total))
}

async fn handle_mesh_egress_scope_test(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if state.proxy_state.as_ref().is_none() {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No proxy state available"}),
        ));
    }
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh egress scope"}),
        ));
    };
    let egress = mesh_runtime.egress_scope_state();
    let Some(scope) = egress.snapshot() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "No active mesh egress scope"}),
        ));
    };
    let candidate: MeshEgressScopeTestRequest = match serde_json::from_slice(body_bytes) {
        Ok(candidate) => candidate,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid JSON body: {e}")}),
            ));
        }
    };
    let host = candidate.host.trim();
    if host.is_empty() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "host is required"}),
        ));
    }

    let (host, parsed_port) = crate::plugins::mesh::outbound_registry::split_host_header(host);
    let port = candidate.port.or(parsed_port);
    if port.is_some_and(|port| port == 0) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "port must be between 1 and 65535"}),
        ));
    }
    // Memoized — rebuilt only after proxy config accepts a slice. Repeated
    // admin calls reuse the same `Arc<OutboundRegistry>` so we don't re-parse /
    // re-normalise the full registry on every request.
    let registry = match egress.test_registry() {
        Some(registry) => registry,
        None => {
            tracing::error!("mesh egress-scope test registry unavailable");
            return Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Failed to build mesh egress-scope registry"}),
            ));
        }
    };
    let allowed = registry.contains(host, port);
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "allowed": allowed,
            "decision": if allowed { "admit" } else { "deny" },
            "host": host,
            "port": port,
            "dry_run": scope.dry_run,
        }),
    ))
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

fn normalize_restore_payload_timestamps(payload: &mut RestorePayload, restored_at: DateTime<Utc>) {
    for proxy in &mut payload.proxies {
        proxy.updated_at = restored_at;
    }
    for consumer in &mut payload.consumers {
        consumer.updated_at = restored_at;
    }
    for plugin_config in &mut payload.plugin_configs {
        plugin_config.updated_at = restored_at;
    }
    for upstream in &mut payload.upstreams {
        upstream.updated_at = restored_at;
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

impl PersistCounts {
    fn any(&self) -> bool {
        self.proxies > 0 || self.consumers > 0 || self.plugin_configs > 0 || self.upstreams > 0
    }
}

/// Reject a retry-enabled batch proxy whose `mesh_route_dispatch` rules route
/// matched traffic to a mesh-tagged upstream (`mesh.hbone` / `mesh.mtls`) — the
/// batch-import equivalent of the route-override conflict check in
/// `Proxy::after_validate`.
///
/// The candidate plugin set mirrors the runtime plugin cache: the batch's own
/// proxy-scoped/proxy_group `mesh_route_dispatch` instances the proxy attaches,
/// plus enabled DB globals (excluded when a batch local instance shadows them by
/// name). Override-destination upstreams resolve from the batch payload first,
/// then the DB. Redirect rules and same-upstream rules that leave retry untouched
/// are skipped (the latter is covered by the default-upstream check).
async fn validate_batch_route_override_conflicts(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
    batch_upstreams: &std::collections::HashMap<&str, &crate::config::types::Upstream>,
    batch_plugin_configs: &std::collections::HashMap<&str, &PluginConfig>,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
    validation_errors: &mut Vec<String>,
) -> anyhow::Result<()> {
    use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

    let attached_ids: HashSet<&str> = proxy
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();

    // Proxy-scoped/proxy_group mesh_route_dispatch instances this proxy attaches,
    // resolved from the batch payload first then the DB (a batch proxy can attach
    // a pre-existing DB plugin). A local instance shadows DB globals of the same
    // name.
    let mut candidates: Vec<PluginConfig> = Vec::new();
    let mut shadows_global = false;
    for id in &attached_ids {
        let pc = if let Some(pc) = batch_plugin_configs.get(*id) {
            Some((*pc).clone())
        } else {
            match db.get_plugin_config(id).await? {
                Some(pc) if pc.namespace == namespace => Some(pc),
                _ => None,
            }
        };
        if let Some(pc) = pc
            && pc.enabled
            && pc.plugin_name == "mesh_route_dispatch"
        {
            shadows_global = true;
            candidates.push(pc);
        }
    }

    if !shadows_global {
        // A `scope=global` `mesh_route_dispatch` submitted IN THIS SAME BATCH needs
        // no proxy association to run, and it is not yet in the DB — so the DB-global
        // page below would miss it. Enumerate the batch's own enabled global
        // dispatch plugins first (deduping by id against the DB fetch) so a batch
        // that creates the whole conflicting graph (retry proxy + mesh upstream +
        // global route override) is rejected before persist instead of 502ing.
        let mut seen_global_ids: HashSet<String> = HashSet::new();
        for pc in batch_plugin_configs.values() {
            if pc.scope == PluginScope::Global
                && pc.namespace == namespace
                && pc.enabled
                && pc.plugin_name == "mesh_route_dispatch"
                && seen_global_ids.insert(pc.id.clone())
            {
                candidates.push((*pc).clone());
            }
        }
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;
        loop {
            let page = db
                .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
                .await?;
            let items_len = page.items.len() as i64;
            for plugin in page.items {
                if plugin.scope == PluginScope::Global
                    && plugin.enabled
                    && plugin.plugin_name == "mesh_route_dispatch"
                    && seen_global_ids.insert(plugin.id.clone())
                {
                    candidates.push(plugin);
                }
            }
            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }
    }

    let default_uid = proxy.upstream_id.as_deref().unwrap_or("");
    for pc in &candidates {
        let Ok(dispatch) = MeshRouteDispatchConfig::from_value(&pc.config) else {
            continue;
        };
        for rule in &dispatch.rules {
            if rule.redirect.is_some() {
                continue;
            }
            let Some(override_uid) = rule.destination.upstream_id.as_deref() else {
                continue;
            };
            let rule_changes_retry = rule.retry.is_some() || rule.retry_disabled;
            if override_uid == default_uid && !rule_changes_retry {
                continue;
            }
            let effective_retry = if rule.retry.is_some() {
                rule.retry.clone()
            } else if rule.retry_disabled {
                None
            } else {
                proxy.retry.clone()
            };
            // Runtime preserves `proxy.upstream_subset` only for a same-upstream
            // rule; a different-upstream override drops it.
            let selected_subset = if override_uid == default_uid {
                proxy.upstream_subset.as_deref()
            } else {
                None
            };
            let resolved = if let Some(u) = batch_upstreams.get(override_uid) {
                Some((*u).clone())
            } else {
                match db.get_upstream(override_uid).await {
                    Ok(Some(u)) if u.namespace == namespace => Some(u),
                    Ok(_) => None,
                    Err(e) => return Err(e),
                }
            };
            if let Some(upstream) = resolved
                && let Some(conflict) =
                    crate::config::types::first_effective_mesh_transport_conflict_with_mesh(
                        &crate::config::types::proxy_with_resolved_port_caps(proxy, &upstream),
                        &upstream,
                        selected_subset,
                        effective_retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        mesh_model,
                    )
            {
                validation_errors.push(
                    crate::config::types::mesh_transport_retry_conflict_message(
                        &proxy.id,
                        override_uid,
                        &conflict,
                    ),
                );
            }
        }
    }
    Ok(())
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
    actor: &AuditActor,
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
    if !cred_value.is_array() {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential set must be an array of JSON objects"}),
        ));
    }
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
    let before = consumer.clone();
    consumer
        .credentials
        .insert(cred_type.to_string(), cred_value);

    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(invalid_credential_fields_response(&field_errors));
    }

    let response = persist_consumer_update(db.as_ref(), consumer.clone(), StatusCode::OK).await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "update_credentials",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::update_diff(
                crud::consumer_response_body(&before),
                crud::consumer_response_body(&consumer),
            ),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
    }
    Ok(response)
}

async fn handle_delete_credentials(
    state: &AdminState,
    actor: &AuditActor,
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
    let before = consumer.clone();
    consumer.credentials.remove(cred_type);
    let response =
        persist_consumer_update(db.as_ref(), consumer.clone(), StatusCode::NO_CONTENT).await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "delete_credentials",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::update_diff(
                crud::consumer_response_body(&before),
                crud::consumer_response_body(&consumer),
            ),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
    }
    Ok(response)
}

/// POST /consumers/:id/credentials/:type — Append a credential entry for zero-downtime rotation.
async fn handle_append_credential(
    state: &AdminState,
    actor: &AuditActor,
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
    let uniqueness_probe = Value::Array(vec![new_cred.clone()]);
    if let Err(resp) = ensure_credential_unique(
        db.as_ref(),
        namespace,
        consumer_id,
        cred_type,
        &uniqueness_probe,
    )
    .await
    {
        return Ok(*resp);
    }

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    let before = consumer.clone();
    let new_value = match consumer.credentials.get(cred_type) {
        Some(Value::Array(arr)) => {
            let mut new_arr = arr.clone();
            new_arr.push(new_cred);
            Value::Array(new_arr)
        }
        _ => Value::Array(vec![new_cred]),
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

    let response = persist_consumer_update(db.as_ref(), consumer.clone(), StatusCode::OK).await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "append_credential",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::update_diff(
                crud::consumer_response_body(&before),
                crud::consumer_response_body(&consumer),
            ),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
    }
    Ok(response)
}

/// DELETE /consumers/:id/credentials/:type/:index — Remove a specific credential entry by index.
///
async fn handle_delete_credential_by_index(
    state: &AdminState,
    actor: &AuditActor,
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
    let before = consumer.clone();
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
            if arr.is_empty() {
                consumer.credentials.remove(cred_type);
            }
        }
        _ => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": format!("No '{}' credentials found", cred_type)}),
            ));
        }
    }

    let response = persist_consumer_update(db.as_ref(), consumer.clone(), StatusCode::OK).await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "delete_credential",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::update_diff(
                crud::consumer_response_body(&before),
                crud::consumer_response_body(&consumer),
            ),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
    }
    Ok(response)
}

// ---- Plugin CRUD ----

async fn handle_list_plugin_types() -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(json_response(
        StatusCode::OK,
        &json!(plugins::available_plugins()),
    ))
}

fn plugin_validation_http_client(state: &AdminState) -> plugins::PluginHttpClient {
    state
        .proxy_state
        .as_ref()
        .map(|proxy_state| proxy_state.plugin_http_client.clone())
        .unwrap_or_else(|| {
            // No ProxyState (e.g. control plane): build a validation client that
            // still carries the configured backend IP policy, so a plugin whose
            // endpoint resolves to a denied literal IP is rejected at the admin
            // boundary instead of being accepted here and rejected later by DPs.
            plugins::PluginHttpClient::default_with_backend_allow_ips(
                state.backend_allow_ips.clone(),
            )
        })
}

fn validate_plugin_config_definition(
    pc: &PluginConfig,
    http_client: plugins::PluginHttpClient,
) -> Result<(), String> {
    match plugins::create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("Unknown plugin name '{}'", pc.plugin_name)),
        Err(err) => Err(err),
    }
}

// ---- Metrics ----

use std::sync::OnceLock;

/// Process-global cache for the metrics JSON response.
static METRICS_CACHE: OnceLock<arc_swap::ArcSwap<Option<(Instant, Bytes)>>> = OnceLock::new();
static RUNTIME_METRICS_CACHE: OnceLock<arc_swap::ArcSwap<Option<(Instant, Bytes)>>> =
    OnceLock::new();

fn metrics_cache() -> &'static arc_swap::ArcSwap<Option<(Instant, Bytes)>> {
    METRICS_CACHE.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(None)))
}

fn runtime_metrics_cache() -> &'static arc_swap::ArcSwap<Option<(Instant, Bytes)>> {
    RUNTIME_METRICS_CACHE.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(None)))
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

async fn handle_metrics_runtime(state: &AdminState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let ttl_ms = state
        .proxy_state
        .as_ref()
        .map(|ps| ps.env_config.runtime_metrics_cache_ttl_ms)
        .unwrap_or_else(|| crate::runtime_metrics::global_ref().cache_ttl_ms());
    let cache = runtime_metrics_cache();
    let cached = cache.load();
    if let Some((cached_at, ref bytes)) = **cached
        && cached_at.elapsed() < Duration::from_millis(ttl_ms)
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

    let snapshot = crate::runtime_metrics::build_snapshot(&state.mode, state.proxy_state.as_ref());
    let body_str = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into());
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

        let mut metrics = json!({
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
        });
        if state.mode == "database"
            && let Some(snapshot) = crate::plugins::prometheus_metrics::global_registry()
                .database_delta_poll_metrics_snapshot()
        {
            metrics["database_polling"] =
                serde_json::to_value(snapshot).unwrap_or_else(|_| json!(null));
        }
        metrics
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
    actor: &AuditActor,
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
        if let Err(err) =
            validate_plugin_config_definition(plugin_config, plugin_validation_http_client(state))
        {
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
        mesh: state
            .cached_gateway_config()
            .and_then(|config| config.mesh.clone()),
        ..Default::default()
    };

    match ValidationPipeline::new(&mut batch_config)
        .validate_unique_resource_ids(ValidationAction::Collect)
        .validate_unique_consumer_identities(ValidationAction::Collect)
        .validate_unique_consumer_credentials(ValidationAction::Collect)
        .validate_unique_upstream_names(ValidationAction::Collect)
        .validate_unique_proxy_names(ValidationAction::Collect)
        .validate_hosts(ValidationAction::Collect)
        .validate_regex_listen_paths(ValidationAction::Collect)
        .validate_listen_path_encodings(ValidationAction::Collect)
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
    let batch_upstreams: std::collections::HashMap<&str, &crate::config::types::Upstream> = batch
        .upstreams
        .iter()
        .map(|upstream| (upstream.id.as_str(), upstream))
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
            match db.check_upstream_exists(upstream_id, namespace).await {
                Ok(true) => {}
                Ok(false) => {
                    // Distinguish "missing" from "wrong namespace" so the
                    // operator's diagnostic points at the real problem.
                    let message = match db.get_upstream(upstream_id).await {
                        Ok(Some(other)) => format!(
                            "Proxy '{}' references upstream_id '{}' from namespace '{}' (proxy is in namespace '{}'); cross-namespace references are forbidden",
                            proxy.id, upstream_id, other.namespace, namespace
                        ),
                        _ => format!(
                            "Proxy '{}' references non-existent upstream_id '{}'",
                            proxy.id, upstream_id
                        ),
                    };
                    validation_errors.push(message);
                }
                Err(err) => validation_errors.push(format!(
                    "Proxy '{}' upstream reference check failed: {}",
                    proxy.id, err
                )),
            }
        }
        if let (Some(upstream_id), Some(subset_name)) = (
            proxy.upstream_id.as_deref(),
            proxy.upstream_subset.as_deref(),
        ) {
            let subset_exists = if let Some(upstream) = batch_upstreams.get(upstream_id) {
                upstream
                    .subsets
                    .as_ref()
                    .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name))
            } else {
                match db.get_upstream(upstream_id).await {
                    Ok(Some(upstream)) if upstream.namespace == namespace => upstream
                        .subsets
                        .as_ref()
                        .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name)),
                    Ok(Some(_)) | Ok(None) => false,
                    Err(err) => {
                        validation_errors.push(format!(
                            "Proxy '{}' upstream subset reference check failed: {}",
                            proxy.id, err
                        ));
                        false
                    }
                }
            };
            if !subset_exists {
                validation_errors.push(format!(
                    "Proxy '{}' references upstream_subset '{}' that is not defined on upstream_id '{}'",
                    proxy.id, subset_name, upstream_id
                ));
            }
        }

        // Reject a retry-enabled proxy whose selected default-upstream targets
        // require a mesh transport (`mesh.hbone` / `mesh.mtls`): retry forces that
        // transport off at runtime and the request 502s (issue #1669). The
        // per-resource CRUD paths reject this, so the batch import must too rather
        // than persist a config the next load rejects. The upstream is resolved
        // from the batch payload first, then the DB. Route-dispatch override
        // destinations are checked separately below
        // (`validate_batch_route_override_conflicts`).
        if let Some(upstream_id) = proxy.upstream_id.as_deref() {
            let resolved_upstream = if let Some(upstream) = batch_upstreams.get(upstream_id) {
                Some((*upstream).clone())
            } else {
                match db.get_upstream(upstream_id).await {
                    Ok(Some(upstream)) if upstream.namespace == namespace => Some(upstream),
                    Ok(_) => None,
                    Err(err) => {
                        validation_errors.push(format!(
                            "Proxy '{}' upstream mesh-transport check failed: {}",
                            proxy.id, err
                        ));
                        None
                    }
                }
            };
            if let Some(upstream) = resolved_upstream
                && let Some(conflict) =
                    crate::config::types::first_effective_mesh_transport_conflict_with_mesh(
                        // Per-resource batch proxies arrive without their
                        // `#[serde(skip)]` `dispatch_port_overrides` resolved;
                        // derive them from the referenced upstream so a
                        // `maxRetries = 0` mesh-port cap is honored as the runtime
                        // applies it.
                        &crate::config::types::proxy_with_resolved_port_caps(proxy, &upstream),
                        &upstream,
                        proxy.upstream_subset.as_deref(),
                        proxy.retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        batch_config.mesh.as_deref(),
                    )
            {
                validation_errors.push(
                    crate::config::types::mesh_transport_retry_conflict_message(
                        &proxy.id,
                        upstream_id,
                        &conflict,
                    ),
                );
            }
        }

        // Spec/route overrides: an enabled `mesh_route_dispatch` plugin in this
        // batch (proxy-scoped/proxy_group association) or an existing DB global can
        // route matched traffic to a mesh-tagged upstream even when the proxy's
        // default upstream is plain — the same 502 path. The per-resource CRUD
        // proxy write rejects this; the batch must too rather than persist a config
        // the next config load rejects (which silently stalls applying the batch).
        if let Err(err) = validate_batch_route_override_conflicts(
            db.as_ref(),
            namespace,
            proxy,
            &batch_upstreams,
            &batch_plugin_configs,
            batch_config.mesh.as_deref(),
            &mut validation_errors,
        )
        .await
        {
            validation_errors.push(format!(
                "Proxy '{}' route-override mesh-transport check failed: {}",
                proxy.id, err
            ));
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
                        if plugin_config.proxy_id.is_some() {
                            validation_errors.push(format!(
                                "Proxy '{}' references proxy_group plugin_config '{}' with proxy_id '{}'",
                                proxy.id,
                                plugin_config.id,
                                plugin_config.proxy_id.as_deref().unwrap_or("<none>")
                            ));
                        }
                    }
                },
                None => unresolved.push(assoc.clone()),
            }
        }

        if !unresolved.is_empty() {
            match db
                .validate_proxy_plugin_associations(&proxy.id, namespace, &unresolved)
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
            match db.check_proxy_exists(proxy_id, namespace).await {
                Ok(true) => {}
                Ok(false) => {
                    // Distinguish "missing" from "wrong namespace" — the
                    // referenced proxy may exist in another namespace, in
                    // which case the operator must move or recreate it.
                    let message = match db.get_proxy(proxy_id).await {
                        Ok(Some(other)) => format!(
                            "PluginConfig '{}' references proxy_id '{}' from namespace '{}' (plugin_config is in namespace '{}'); cross-namespace references are forbidden",
                            plugin_config.id, proxy_id, other.namespace, namespace
                        ),
                        _ => format!(
                            "PluginConfig '{}' references non-existent proxy_id '{}'",
                            plugin_config.id, proxy_id
                        ),
                    };
                    validation_errors.push(message);
                }
                Err(err) => validation_errors.push(format!(
                    "PluginConfig '{}' proxy reference check failed: {}",
                    plugin_config.id, err
                )),
            }
        }

        match crud::validate_mesh_route_dispatch_plugin_upstream_references(
            db.as_ref(),
            namespace,
            plugin_config,
            Some(&batch_upstream_ids),
        )
        .await
        {
            Ok(errs) => validation_errors.extend(errs),
            Err(err) => validation_errors.push(format!(
                "PluginConfig '{}' mesh_route_dispatch upstream reference check failed: {}",
                plugin_config.id, err
            )),
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
        if created.any() {
            let event = audit::AuditEvent::new(
                actor,
                "batch_create",
                "gateway_config",
                namespace,
                namespace,
                audit::create_diff(response["created"].clone()),
            );
            if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
                log_audit_enqueue_failure(&error);
            }
        }
        return Ok(json_response(StatusCode::MULTI_STATUS, &response));
    }

    if created.any() {
        let event = audit::AuditEvent::new(
            actor,
            "batch_create",
            "gateway_config",
            namespace,
            namespace,
            audit::create_diff(response["created"].clone()),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
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
    actor: &AuditActor,
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
            mesh: state
                .cached_gateway_config()
                .and_then(|config| config.mesh.clone()),
            ..Default::default()
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
            .validate_listen_path_encodings(ValidationAction::Collect)
            .validate_unique_listen_paths(ValidationAction::Collect)
            .validate_stream_proxies(ValidationAction::Collect)
            .validate_plugin_configs(ValidationAction::Collect)
            .validate_upstream_references(ValidationAction::Collect)
            .validate_mesh_route_dispatch_references(ValidationAction::Collect)
            .validate_plugin_references(ValidationAction::Collect)
            .run()
        {
            Ok(errs) => validation_errors.extend(errs),
            Err(err) => validation_errors.push(err.to_string()),
        }
        // Restore is an operator-provided admin write, so reject mesh-PROJECTED
        // upstream fields the same way direct POST/PUT does. This check is
        // intentionally NOT part of the shared `validate_all_fields` step (that
        // step also runs on the mesh slice-apply path, where mesh-projected
        // upstreams legitimately carry these fields); operator paths invoke it
        // explicitly.
        for u in &temp_config.upstreams {
            if let Err(errs) = u.validate_operator_provided_fields() {
                for e in errs {
                    validation_errors.push(format!("Upstream '{}': {}", u.id, e));
                }
            }
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
    normalize_restore_payload_timestamps(&mut payload, Utc::now());
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
        // Restore always wipes the namespace before re-inserting (Phase 3 above),
        // so even a zero-success-count restore must produce an audit row — the
        // namespace state has already changed regardless of which inserts failed.
        let event = audit::AuditEvent::new(
            actor,
            "restore",
            "gateway_config",
            namespace,
            namespace,
            audit::update_diff(
                json!({"replaced_namespace": namespace}),
                response["restored"].clone(),
            ),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
            log_audit_enqueue_failure(&error);
        }
        return Ok(json_response(StatusCode::MULTI_STATUS, &response));
    }

    let event = audit::AuditEvent::new(
        actor,
        "restore",
        "gateway_config",
        namespace,
        namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            response["restored"].clone(),
        ),
    );
    if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
        log_audit_enqueue_failure(&error);
    }

    Ok(json_response(StatusCode::OK, &response))
}

fn parse_audit_filter(
    query: Option<&str>,
    pagination: &PaginationParams,
) -> Result<audit::AuditListFilter, Box<Response<Full<Bytes>>>> {
    let offset = u32::try_from(pagination.offset).map_err(|_| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Audit offset exceeds supported range"}),
        ))
    })?;
    let mut filter = audit::AuditListFilter {
        limit: pagination
            .limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE) as u32,
        offset,
        ..Default::default()
    };

    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "actor" => filter.actor = Some(value.into_owned()),
                "action" => filter.action = Some(value.into_owned()),
                "resource_type" => filter.resource_type = Some(value.into_owned()),
                "resource_id" => filter.resource_id = Some(value.into_owned()),
                "start" => {
                    filter.start = Some(
                        chrono::DateTime::parse_from_rfc3339(&value)
                            .map_err(|e| {
                                Box::new(json_response(
                                    StatusCode::BAD_REQUEST,
                                    &json!({"error": format!("Invalid audit start timestamp: {}", e)}),
                                ))
                            })?
                            .with_timezone(&Utc),
                    );
                }
                "end" => {
                    filter.end = Some(
                        chrono::DateTime::parse_from_rfc3339(&value)
                            .map_err(|e| {
                                Box::new(json_response(
                                    StatusCode::BAD_REQUEST,
                                    &json!({"error": format!("Invalid audit end timestamp: {}", e)}),
                                ))
                            })?
                            .with_timezone(&Utc),
                    );
                }
                "limit" => {
                    let parsed = value.parse::<usize>().map_err(|_| {
                        Box::new(json_response(
                            StatusCode::BAD_REQUEST,
                            &json!({"error": "Invalid audit limit"}),
                        ))
                    })?;
                    filter.limit = parsed.clamp(1, MAX_PAGE_SIZE) as u32;
                }
                "offset" => {}
                _ => {}
            }
        }
    }

    Ok(filter)
}

async fn handle_audit_list(
    state: &AdminState,
    pagination: &PaginationParams,
    query: Option<&str>,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };
    let filter = match parse_audit_filter(query, pagination) {
        Ok(filter) => filter,
        Err(resp) => return Ok(*resp),
    };

    match db.list_audit_events(namespace, &filter).await {
        Ok(result) => {
            let next_offset = if (filter.offset as i64 + result.items.len() as i64) < result.total {
                Some(filter.offset + result.items.len() as u32)
            } else {
                None
            };
            Ok(json_response(
                StatusCode::OK,
                &json!({
                    "items": result.items,
                    "limit": filter.limit,
                    "offset": filter.offset,
                    "next_offset": next_offset,
                    "total": result.total,
                }),
            ))
        }
        Err(error) => Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&error),
        )),
    }
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

pub(in crate::admin) fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
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

/// Hash passwords in basicauth credential payloads where the credential type is known.
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
            let data_planes = state
                .dp_registry
                .as_ref()
                .map(|registry| registry.snapshot())
                .unwrap_or_default();
            let data_plane_details: Vec<serde_json::Value> = data_planes
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
            let mesh_nodes = state
                .mesh_registry
                .as_ref()
                .map(|registry| registry.snapshot())
                .unwrap_or_default();
            let mesh_node_details: Vec<serde_json::Value> = mesh_nodes
                .iter()
                .map(|n| {
                    json!({
                        "node_id": n.node_id,
                        "version": n.version,
                        "namespace": n.namespace,
                        "status": "online",
                        "connected_at": n.connected_at.to_rfc3339(),
                        "last_heartbeat_at": n.last_heartbeat_at.to_rfc3339(),
                        "last_sync_at": n.last_update_at.to_rfc3339(),
                    })
                })
                .collect();
            Ok(json_response(
                StatusCode::OK,
                &json!({
                    "mode": "cp",
                    "connected_data_planes": data_planes.len(),
                    "data_planes": data_plane_details,
                    "connected_mesh_nodes": mesh_nodes.len(),
                    "mesh_nodes": mesh_node_details,
                }),
            ))
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
                "hbone": protocol_support_label(record.hbone),
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

async fn handle_service_waypoint_services_get(
    state: &AdminState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let Some(mesh_runtime) = state.mesh_runtime_state.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "service-waypoint topology not enabled"}),
        ));
    };
    let snapshot = mesh_runtime.snapshot();
    let Some(slice) = snapshot.as_ref() else {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "no mesh slice available yet"}),
        ));
    };
    let Some(waypoint_name) = slice.waypoint_name.as_deref() else {
        // Slice has no waypoint binding — DP is in a non-service-waypoint
        // topology. Return 404 so unrelated operators don't see a stub.
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "service-waypoint topology not enabled"}),
        ));
    };
    let services: Vec<serde_json::Value> = slice
        .services
        .iter()
        .map(|svc| {
            let ports: Vec<u16> = svc.ports.iter().map(|p| p.port).collect();
            json!({
                "namespace": svc.namespace,
                "name": svc.name,
                "ports": ports,
                "workload_count": svc.workloads.len(),
            })
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "waypoint_name": waypoint_name,
            "namespace": slice.namespace,
            "service_count": services.len(),
            "services": services,
        }),
    ))
}

async fn handle_node_waypoint_identities_get(
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
    let Some(resolver) = proxy_state.node_waypoint_identity_resolver.as_ref() else {
        // 404 (not 503) because node-waypoint topology is opt-in. Other
        // mesh topologies and non-mesh modes don't have a resolver and the
        // endpoint is meaningless there.
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "node-waypoint topology not enabled"}),
        ));
    };
    // Single pass over `cookie_records` returns both the per-identity
    // summaries and the (v4, v6) totals; this honors the documented
    // "iterates each shard of three DashMaps once" cold-path contract.
    let (snapshot, (cookies_v4, cookies_v6)) = resolver.identities_snapshot_with_cookie_totals();
    let entries: Vec<serde_json::Value> = snapshot
        .iter()
        .map(|summary| {
            json!({
                "pod_uid": summary.pod_uid_string(),
                "spiffe_id": summary.spiffe_id,
                "workload_spiffe_hash": summary.workload_spiffe_hash,
                "orig_dst4_cookies": summary.orig_dst4_cookies,
                "orig_dst6_cookies": summary.orig_dst6_cookies,
                "has_policy_scope": summary.has_policy_scope,
            })
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "identity_count": entries.len(),
            "cookies": {
                "orig_dst4": cookies_v4,
                "orig_dst6": cookies_v6,
            },
            "identities": entries,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpaginated_response_returns_all_items() {
        let uri: hyper::Uri = "/proxies".parse().unwrap();
        let pagination = parse_pagination(&uri);
        let items = json!((0..150).collect::<Vec<_>>());

        let response = paginate_response(&items, &pagination);

        assert_eq!(response["data"].as_array().unwrap().len(), 150);
        assert_eq!(response["pagination"]["limit"], 150);
        assert_eq!(pagination.query_limit_i64(), i64::MAX);
    }

    #[test]
    fn explicit_limit_still_caps_response() {
        let uri: hyper::Uri = "/proxies?limit=25&offset=10".parse().unwrap();
        let pagination = parse_pagination(&uri);
        let items = json!((0..150).collect::<Vec<_>>());

        let response = paginate_response(&items, &pagination);

        assert_eq!(response["data"].as_array().unwrap().len(), 25);
        assert_eq!(response["pagination"]["offset"], 10);
        assert_eq!(response["pagination"]["limit"], 25);
        assert_eq!(pagination.query_limit_i64(), 25);
    }

    #[test]
    fn parse_short_duration_accepts_suffix_units() {
        assert_eq!(
            parse_short_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_short_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_short_duration("1h").unwrap(),
            Duration::from_secs(3600)
        );
        // Bare integer is treated as seconds — keeps backwards compatibility
        // with `?window=300`-style queries.
        assert_eq!(parse_short_duration("42").unwrap(), Duration::from_secs(42));
    }

    #[test]
    fn parse_short_duration_rejects_bad_input() {
        assert!(parse_short_duration("").is_err());
        assert!(parse_short_duration("m").is_err());
        assert!(parse_short_duration("5x").is_err());
        // Fractional seconds — operator should pick a coarser bucket.
        assert!(parse_short_duration("1.5s").is_err());
        assert!(parse_short_duration("abc").is_err());
    }

    #[test]
    fn parse_mesh_policy_denies_query_defaults_when_absent() {
        let (window, limit) = parse_mesh_policy_denies_query(None).unwrap();
        assert_eq!(window, MESH_POLICY_DENIES_DEFAULT_WINDOW);
        assert_eq!(limit, MESH_POLICY_DENIES_DEFAULT_LIMIT);
    }

    #[test]
    fn parse_mesh_policy_denies_query_honours_overrides() {
        let (window, limit) = parse_mesh_policy_denies_query(Some("window=15m&limit=200")).unwrap();
        assert_eq!(window, Duration::from_secs(15 * 60));
        assert_eq!(limit, 200);
    }

    #[test]
    fn parse_mesh_policy_denies_query_rejects_window_over_cap() {
        let err =
            parse_mesh_policy_denies_query(Some("window=2h")).expect_err("2h must exceed cap");
        assert!(err.contains("window exceeds"));
    }

    #[test]
    fn parse_mesh_policy_denies_query_rejects_zero_window() {
        let err =
            parse_mesh_policy_denies_query(Some("window=0s")).expect_err("zero window not allowed");
        assert!(err.contains("window must be > 0"));
    }

    #[test]
    fn parse_mesh_policy_denies_query_rejects_limit_over_cap() {
        let err =
            parse_mesh_policy_denies_query(Some("limit=99999")).expect_err("99999 must exceed cap");
        assert!(err.contains("limit exceeds"));
    }

    #[test]
    fn parse_mesh_policy_denies_query_ignores_unknown_params() {
        // Future-proof: a new `rule=` filter must not 4xx older deployments.
        let (window, limit) = parse_mesh_policy_denies_query(Some("rule=foo&window=10m")).unwrap();
        assert_eq!(window, Duration::from_secs(600));
        assert_eq!(limit, MESH_POLICY_DENIES_DEFAULT_LIMIT);
    }

    #[test]
    fn normalize_restore_payload_timestamps_sets_uniform_updated_at() {
        // `Proxy`, `Consumer`, `PluginConfig`, `Upstream`, and `RestorePayload`
        // do not impl `Default`, so build the test payload through serde — the
        // domain structs already carry `#[serde(default)]` on every field we
        // don't care about for this test.
        let old = Utc::now() - chrono::Duration::days(90);
        let restored_at = Utc::now();
        let old_ts = old.to_rfc3339();
        let payload_json = serde_json::json!({
            "proxies": [{
                "id": "p1",
                "updated_at": old_ts,
                "backend_host": "example.test",
                "backend_port": 8080,
            }],
            "consumers": [{
                "id": "c1",
                "username": "alice",
                "updated_at": old_ts,
            }],
            "plugin_configs": [{
                "id": "pc1",
                "plugin_name": "noop",
                "scope": "global",
                "updated_at": old_ts,
            }],
            "upstreams": [{
                "id": "u1",
                "name": "u1",
                "targets": [],
                "updated_at": old_ts,
            }],
        });
        let mut payload: RestorePayload = serde_json::from_value(payload_json)
            .expect("test RestorePayload deserializes from minimal JSON");

        normalize_restore_payload_timestamps(&mut payload, restored_at);

        assert_eq!(payload.proxies[0].updated_at, restored_at);
        assert_eq!(payload.consumers[0].updated_at, restored_at);
        assert_eq!(payload.plugin_configs[0].updated_at, restored_at);
        assert_eq!(payload.upstreams[0].updated_at, restored_at);
    }
}
