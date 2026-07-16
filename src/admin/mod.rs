//! Admin API for Ferrum Edge.

pub mod api_specs;
pub mod audit;
mod backup;
pub mod conn_limit;
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
use crate::config::db_backend::{
    AtomicClearVerification, DatabaseBackend, NamespaceResourceCounts, SnapshotDataIntegrityError,
    classify_atomic_clear_verification,
};
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

pub use conn_limit::AdminConnLimiter;

/// Cached result of the database health check to avoid hitting the DB on every
/// `/health` request. The result is reused for `DB_HEALTH_CACHE_TTL` seconds.
#[derive(Clone)]
pub struct CachedDbHealthResult {
    connected: bool,
    checked_at: Instant,
}

/// Duration for which a DB health check result is reused.
const DB_HEALTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(15);

/// Authorization policy for the observability scrape surfaces — `/metrics`, and
/// the *detailed* views of `/health` and `/overload`.
///
/// These surfaces are **not** unauthenticated by default. A caller is granted
/// the detailed/scrape view only when one of the following holds:
///   1. a valid admin JWT is presented (`Authorization: Bearer <jwt>`), or
///   2. a dedicated metrics bearer token is configured and matches, or
///   3. the request originates from an operator-allowlisted CIDR.
///
/// When none apply, `/metrics` returns `401` and `/health` / `/overload`
/// fall back to a minimal, LB-safe projection that reveals no operational
/// internals. The liveness endpoint `/live` is always unauthenticated and
/// minimal and does not consult this policy.
#[derive(Debug, Clone)]
pub struct MetricsAuthPolicy {
    /// Source ranges permitted to scrape / see detail without any credential.
    /// Empty (the default) disables unauthenticated scraping entirely.
    pub allowed_cidrs: crate::proxy::client_ip::TrustedProxies,
    /// Dedicated metrics bearer token. When `Some`, a request whose
    /// `Authorization: Bearer <token>` matches (constant-time) is authorized.
    /// `None` disables this path.
    pub bearer_token: Option<String>,
}

impl Default for MetricsAuthPolicy {
    fn default() -> Self {
        // Secure default: no allowlisted CIDRs and no token ⇒ scraping requires
        // a valid admin JWT.
        Self {
            allowed_cidrs: crate::proxy::client_ip::TrustedProxies::none(),
            bearer_token: None,
        }
    }
}

impl MetricsAuthPolicy {
    /// Build the policy from environment config, validating any configured CIDR
    /// list (invalid entries are a hard error, mirroring `admin_allowed_cidrs`).
    pub fn from_env(env: &crate::config::EnvConfig) -> Result<Self, String> {
        let allowed_cidrs =
            crate::proxy::client_ip::TrustedProxies::parse_strict(&env.metrics_allowed_cidrs)
                .map_err(|e| format!("FERRUM_METRICS_ALLOWED_CIDRS: {e}"))?;
        let bearer_token = env
            .metrics_bearer_token
            .as_ref()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        Ok(Self {
            allowed_cidrs,
            bearer_token,
        })
    }

    /// True when the request's client IP is in the unauthenticated allowlist.
    fn ip_allowed(&self, client_ip: &std::net::IpAddr) -> bool {
        !self.allowed_cidrs.is_empty() && self.allowed_cidrs.contains(client_ip)
    }

    /// True when a configured bearer token matches the request's
    /// `Authorization` header (constant-time compare).
    fn token_matches(&self, auth_header: Option<&str>) -> bool {
        let Some(expected) = self.bearer_token.as_deref() else {
            return false;
        };
        let Some(provided) = auth_header.and_then(JwtManager::extract_token_from_header) else {
            return false;
        };
        crate::plugins::utils::auth_flow::constant_time_eq(provided.as_bytes(), expected.as_bytes())
    }
}

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
    /// When `true` (`FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`), namespace-scoped
    /// admin routes require the admin JWT to carry an `ns` claim authorizing
    /// the `X-Ferrum-Namespace` value (mirrors the CP↔DP gRPC plane's
    /// `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`). Default `false`: the namespace
    /// header stays a routing selector and any valid admin JWT may address
    /// any namespace, matching pre-existing behavior.
    pub admin_require_namespace_claim: bool,
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
    /// Sticky serving-degradation signal (set in CP/DP/mesh modes, which
    /// supervise post-start listener/server tasks). Set once — and never unset —
    /// by [`crate::startup::flip_ready_off_on_listener_failure`] when a serving
    /// task (CP gRPC server; DP proxy/admin listeners) exits with an error after
    /// startup. `/health` reports not-ready when this is `true` OR
    /// `startup_ready` is `false`. Unlike `startup_ready` — which CP stores
    /// `true` once after the gRPC start signal and DP re-stores `true` on every
    /// CP-reconnect snapshot — this flag is monotonic, so a post-start serve
    /// failure stays visible even after a later readiness restore. `None` in
    /// modes without post-start listener supervision (file/database/node_agent),
    /// where readiness is governed by `startup_ready` alone.
    pub serving_degraded: Option<Arc<AtomicBool>>,
    /// Durable sanitized details for post-start listener failures. Populated by
    /// mesh mode and exposed only on authenticated observability responses.
    pub serving_listener_failures: Option<Arc<crate::startup::ServingListenerFailures>>,
    /// Dynamic flag set by the DB polling loop. When `false`, write operations
    /// are rejected early to preserve the cached config until the DB recovers.
    /// This flag is orthogonal to `startup_ready` — a gateway can be ready to
    /// serve traffic (`startup_ready=true`) while admin writes are blocked
    /// (`db_available=false`) during a transient DB outage.
    pub db_available: Option<Arc<AtomicBool>>,
    /// Set by the database- or CP-mode poll loop when the latest full config
    /// load was rejected by the shared runtime-config *validation* contract (a
    /// reachable backend served a semantically-invalid snapshot) rather than
    /// failing on connectivity. Orthogonal to `db_available`: on a validation
    /// rejection the backend is reachable and admin writes are the in-band repair
    /// tool, so `db_available` stays `true` while this flag rises. Cleared only by
    /// the next accepted authoritative full reload. Surfaced only in the
    /// authenticated `/health` detail (`config_rejected`) and coarsely as a
    /// `"degraded"` status; `None` in modes without a writable poll loop.
    ///
    /// The stored flag is deliberately sticky across a later connectivity outage;
    /// the `/health` handler suppresses the detailed `config_rejected` field while
    /// `db_available=false` so it never advertises the writable repair path when
    /// admin writes are actually blocked. See issue #2158.
    pub config_rejected: Option<Arc<AtomicBool>>,
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
    /// Authorization policy gating the observability scrape surfaces
    /// (`/metrics` and the detailed `/health` / `/overload` views). See
    /// [`MetricsAuthPolicy`]. Defaults to "require admin JWT".
    pub metrics_auth: Arc<MetricsAuthPolicy>,
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
    pub backend_allow_ips: crate::config::BackendEgressPolicy,
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

/// Start the Admin API listener with optional TLS support and signal readiness
/// after the TCP socket binds successfully.
pub async fn start_admin_listener_with_tls_and_signal(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
    conn_limiter: Arc<conn_limit::AdminConnLimiter>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Admin API listener started on {}", addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }
    serve_admin_on_listener(listener, state, shutdown, tls_config, conn_limiter).await
}

/// Start the Admin API HTTPS listener with a hot-swappable frontend TLS slot
/// and signal readiness after the TCP socket binds successfully.
pub async fn start_admin_listener_with_dynamic_tls_and_signal(
    addr: SocketAddr,
    state: AdminState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_slot: crate::tls::SharedFrontendTls,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
    conn_limiter: Arc<conn_limit::AdminConnLimiter>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Admin API listener started on {}", addr);
    if let Some(started_tx) = started_tx {
        let _ = started_tx.send(());
    }
    serve_admin_on_listener_with_dynamic_tls(listener, state, shutdown, tls_slot, conn_limiter)
        .await
}

/// Run the Admin API accept loop on a pre-bound `TcpListener`.
///
/// Useful for tests that allocate an ephemeral port up front: passing the
/// listener through avoids the bind→drop→rebind window where another process
/// can steal the port between releasing it and the listener task re-binding.
/// Production callers go through [`start_admin_listener_with_tls_and_signal`],
/// which binds internally and signals startup readiness.
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
    conn_limiter: Arc<conn_limit::AdminConnLimiter>,
) -> Result<(), anyhow::Error> {
    // Publish the limiter so `/metrics` can render its gauge/counters.
    crate::plugins::prometheus_metrics::global_registry()
        .set_admin_conn_metrics(conn_limiter.clone());
    let mut shutdown_rx = shutdown;
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    let mut reject_log = crate::util::accept_backoff::LogRateLimiter::new();

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

                        // Admin connection cap: acquire a permit before spawning
                        // a per-connection task. Over-limit connections are
                        // dropped (TCP RST) with zero task/TLS-handshake overhead.
                        let conn_permit = match conn_limiter.try_acquire(remote_addr.ip()) {
                            Ok(permit) => permit,
                            Err(reason) => {
                                if let Some(suppressed) =
                                    reject_log.on_event(crate::socket_opts::monotonic_now_ms())
                                {
                                    warn!(
                                        suppressed,
                                        remote_addr = %remote_addr.ip(),
                                        reason = reason.as_label(),
                                        "Admin connection rejected: connection limit reached"
                                    );
                                }
                                drop(stream);
                                continue;
                            }
                        };

                        let state = state.clone();
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            // Hold the permit for the connection lifetime; it is
                            // released on every exit path when this drops.
                            let _conn_permit = conn_permit;
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
    conn_limiter: Arc<conn_limit::AdminConnLimiter>,
) -> Result<(), anyhow::Error> {
    // Publish the limiter so `/metrics` can render its gauge/counters.
    crate::plugins::prometheus_metrics::global_registry()
        .set_admin_conn_metrics(conn_limiter.clone());
    let mut shutdown_rx = shutdown;
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    let mut reject_log = crate::util::accept_backoff::LogRateLimiter::new();

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

                        // Admin connection cap (see `serve_admin_on_listener`):
                        // acquire before spawning / before the TLS handshake.
                        let conn_permit = match conn_limiter.try_acquire(remote_addr.ip()) {
                            Ok(permit) => permit,
                            Err(reason) => {
                                if let Some(suppressed) =
                                    reject_log.on_event(crate::socket_opts::monotonic_now_ms())
                                {
                                    warn!(
                                        suppressed,
                                        remote_addr = %remote_addr.ip(),
                                        reason = reason.as_label(),
                                        "Admin connection rejected: connection limit reached"
                                    );
                                }
                                drop(stream);
                                continue;
                            }
                        };

                        let tls_config = tls_slot.load().as_ref().clone();
                        let state = state.clone();

                        tokio::spawn(async move {
                            // Hold the permit for the connection lifetime.
                            let _conn_permit = conn_permit;
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
    let client_ip = remote_addr.ip();
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        async move { handle_admin_request(req, state, client_ip).await }
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
    remote_addr: SocketAddr,
    state: AdminState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let header_read_timeout_seconds = state.admin_http_header_read_timeout_seconds;
    let client_ip = remote_addr.ip();
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_admin_request(req, state, client_ip).await }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChargebackFormat {
    Prometheus,
    Json,
}

fn parse_chargeback_format(
    query: Option<&str>,
) -> Result<ChargebackFormat, Box<Response<Full<Bytes>>>> {
    let mut format = ChargebackFormat::Prometheus;
    let Some(query) = query else {
        return Ok(format);
    };

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key.as_ref() != "format" {
            continue;
        }
        format = match value.as_ref() {
            "prometheus" => ChargebackFormat::Prometheus,
            "json" => ChargebackFormat::Json,
            other => {
                return Err(Box::new(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": format!(
                        "Unsupported charges format '{}'; expected 'prometheus' or 'json'",
                        other
                    )}),
                )));
            }
        };
    }

    Ok(format)
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

fn tls_route_required_role(method: &Method, segments: &[&str]) -> Option<AdminRole> {
    match (method, segments) {
        (
            method,
            ["admin", "tls", "inventory"]
            | ["admin", "tls", "events"]
            | ["admin", "tls", "acme", "certificates"]
            | ["admin", "tls", "acme", "certificates", _]
            | ["admin", "tls", "acme", "accounts"]
            | ["admin", "tls", "acme", "orders"]
            | ["admin", "tls", "acme", "orders", _]
            | ["admin", "tls", "certificates"]
            | ["admin", "tls", "certificates", _]
            | ["admin", "tls", "ca-bundles"]
            | ["admin", "tls", "ca-bundles", _]
            | ["admin", "tls", "crls"]
            | ["admin", "tls", "crls", _]
            | ["admin", "tls", "ocsp-responses"]
            | ["admin", "tls", "ocsp-responses", _]
            | ["admin", "tls", "jwks"]
            | ["admin", "tls", "jwks", _],
        ) if method == Method::GET => Some(AdminRole::Operator),
        (method, ["admin", "tls", "rotate", _] | ["admin", "tls", "validate"])
            if method == Method::POST =>
        {
            Some(AdminRole::Operator)
        }
        (
            method,
            ["admin", "tls", "acme", "certificates"]
            | ["admin", "tls", "acme", "orders"]
            | ["admin", "tls", "certificates"]
            | ["admin", "tls", "ca-bundles"]
            | ["admin", "tls", "crls"]
            | ["admin", "tls", "ocsp-responses"]
            | ["admin", "tls", "jwks"],
        ) if method == Method::POST => Some(AdminRole::Admin),
        (
            method,
            ["admin", "tls", "acme", "certificates", _]
            | ["admin", "tls", "certificates", _]
            | ["admin", "tls", "ca-bundles", _]
            | ["admin", "tls", "crls", _]
            | ["admin", "tls", "ocsp-responses", _]
            | ["admin", "tls", "jwks", _],
        ) if method == Method::PUT => Some(AdminRole::Admin),
        (
            method,
            ["admin", "tls", "acme", "certificates", _]
            | ["admin", "tls", "acme", "orders", _]
            | ["admin", "tls", "certificates", _]
            | ["admin", "tls", "ca-bundles", _]
            | ["admin", "tls", "crls", _]
            | ["admin", "tls", "ocsp-responses", _]
            | ["admin", "tls", "jwks", _],
        ) if method == Method::DELETE => Some(AdminRole::Admin),
        (method, ["admin", "tls", "acme", "renew", _]) if method == Method::POST => {
            Some(AdminRole::Admin)
        }
        (method, ["admin", "tls", "acme", "orders", _, "finalize"]) if method == Method::POST => {
            Some(AdminRole::Admin)
        }
        _ => None,
    }
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

/// Whether an admin route operates on namespace-scoped resources selected via
/// `X-Ferrum-Namespace`. Used by the opt-in per-namespace `ns`-claim gate
/// (`FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`); global admin surfaces (TLS
/// management, `/cluster`, `/namespaces`, metrics, backend capabilities, mesh
/// introspection, `/plugins` type listing) are exempt because the namespace
/// header does not select a tenant there.
fn is_namespace_scoped_route(segments: &[&str]) -> bool {
    match segments.first().copied() {
        Some(
            "proxies" | "consumers" | "upstreams" | "api-specs" | "batch" | "backup" | "restore"
            | "audit",
        ) => true,
        // `GET /plugins` lists available plugin *types* (global metadata);
        // `/plugins/config[...]` is the namespace-scoped PluginConfig CRUD.
        Some("plugins") => segments.len() > 1,
        _ => false,
    }
}

/// Enforce the admin JWT `ns` claim against the requested namespace. Returns
/// `Some(403)` when the token does not authorize `namespace`; `None` when
/// authorized. Claim shapes are identical to the CP↔DP gRPC plane (single
/// string or array of strings); a token without an `ns` claim is rejected
/// outright when enforcement is on — tenancy intent must be explicit.
fn enforce_namespace_claim(
    auth: &AuditActor,
    namespace: &str,
    path: &str,
) -> Option<Response<Full<Bytes>>> {
    if auth.allowed_namespaces.is_present() {
        if auth.allowed_namespaces.allows(namespace) {
            return None;
        }
        warn!(
            audit.event = "admin_namespace_authz",
            actor = %auth.sub,
            namespace = %namespace,
            path = %path,
            result = "denied",
            "Admin request rejected: JWT `ns` claim does not authorize the requested namespace"
        );
        return Some(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": format!(
                "JWT `ns` claim does not authorize namespace '{}'; the bearer may only \
                 address the namespaces listed in its token",
                namespace
            )}),
        ));
    }
    warn!(
        audit.event = "admin_namespace_authz",
        actor = %auth.sub,
        namespace = %namespace,
        path = %path,
        result = "denied",
        "Admin request rejected: FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true but the JWT has no `ns` claim"
    );
    Some(json_response(
        StatusCode::FORBIDDEN,
        &json!({"error": "FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true on this instance: the admin \
             JWT must include an `ns` claim (string or array) listing the namespaces it may manage"}),
    ))
}

/// Whether the caller may see the detailed observability views (`/metrics`
/// scrape body, full `/health`, full `/overload`). Granted on any of: a valid
/// admin JWT, a matching metrics bearer token, or an allowlisted source IP.
///
/// `/metrics` turns a `false` here into `401`; `/health` and `/overload` turn
/// it into a minimal, LB-safe projection instead.
fn observability_detail_allowed(
    state: &AdminState,
    auth_header: Option<&str>,
    client_ip: &std::net::IpAddr,
) -> bool {
    state
        .jwt_manager
        .verify_request(auth_header)
        .ok()
        .and_then(|token_data| AuditActor::from_claims(&token_data.claims).ok())
        .is_some()
        || state.metrics_auth.token_matches(auth_header)
        || state.metrics_auth.ip_allowed(client_ip)
}

/// `401` response for `/metrics` when the caller is not authorized to scrape.
/// Advertises the supported credential scheme so well-behaved scrapers can
/// retry with a token.
fn metrics_unauthorized_response() -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&json!({
        "error": "Unauthorized: /metrics requires a valid admin JWT or metrics bearer token, \
    or the client must be in FERRUM_METRICS_ALLOWED_CIDRS"
    }))
    .unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .header("WWW-Authenticate", "Bearer")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))))
}

/// Handle an admin API request. `client_ip` is the peer address of the admin
/// connection (admin uses the socket peer directly — it never trusts forwarded
/// headers), used to evaluate [`MetricsAuthPolicy`] CIDR allowlists.
pub async fn handle_admin_request(
    req: Request<Incoming>,
    state: AdminState,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let pagination = parse_pagination(req.uri());
    // Extracted once: used both for observability-detail tiering below and the
    // main admin JWT gate further down.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Liveness probe — always unauthenticated and minimal. Never reveals any
    // operational internals; safe to expose to load balancers / orchestrators.
    if path == "/live" {
        return Ok(json_response(StatusCode::OK, &json!({"status": "ok"})));
    }

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
        // Sticky serving-degradation overrides a readiness restore (issue
        // #2117): once a CP/DP/mesh serving task dies after startup, `/health` stays
        // not-ready even though the mode's main task (CP) or a CP reconnect (DP)
        // later stores `startup_ready = true`. Only CP/DP populate this flag.
        let serving_degraded = state
            .serving_degraded
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        let ready = startup_ready && !serving_degraded;
        health_status["ready"] = json!(ready);

        if let Some(failures) = state.serving_listener_failures.as_ref() {
            let snapshot = failures.snapshot();
            if snapshot.failures_total > 0 {
                health_status["listener_failures"] =
                    serde_json::to_value(snapshot).unwrap_or_default();
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

        // Config-rejection signal (issue #2158): the latest full config load was
        // rejected by the runtime-config validation contract while the backend
        // stayed reachable. Admin writes remain ENABLED (they are the in-band
        // repair path — `db_available` is left `true`), so surface the condition
        // as a coarse `"degraded"` status plus a `config_rejected` detail flag.
        // The boolean detail is authenticated-only: it is added to
        // `health_status`, which the minimal unauthenticated body below does not
        // echo. The coarse status is consistent with the other DB-driven
        // degradations above. Cleared by the next accepted full reload.
        //
        // The stored flag is intentionally STICKY across a later connectivity
        // outage (it clears only on an accepted authoritative full reload). But
        // while `db_available=false` the writable in-band repair path is gone
        // (`admin_writes_enabled=false`), so surfacing `config_rejected=true`
        // would falsely advertise that path. Suppress the detailed field during
        // an outage — without touching the sticky stored flag — so the two
        // authenticated details stay mutually honest (issue #2158).
        let config_rejected = state
            .config_rejected
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed));
        let db_reachable = state
            .db_available
            .as_ref()
            .is_none_or(|flag| flag.load(Ordering::Relaxed));
        if config_rejected && db_reachable {
            health_status["status"] = json!("degraded");
            health_status["config_rejected"] = json!(true);
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

        let response_code = if !ready {
            // Distinguish "never became ready" (still starting up) from "was
            // ready, then a serving listener died after startup" (degraded).
            // `serving_degraded` is the authoritative signal: the flip helper
            // sets it true AND best-effort clears `startup_ready`, so keying the
            // status off `!startup_ready` would mislabel a post-start
            // degradation as "starting". Use the sticky flag instead.
            health_status["status"] = json!(if serving_degraded {
                "unavailable"
            } else {
                "starting"
            });
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };

        // Detailed diagnostics (DB type/pool stats, cached-config proxy/consumer
        // counts, polling-degradation detail, mesh state) are gated. An
        // unauthenticated caller — e.g. a load-balancer / orchestrator probe —
        // receives only liveness + readiness, which is enough to drive health
        // checks without leaking operational internals. Authorized callers
        // (admin JWT / metrics token / allowlisted CIDR) get the full body.
        if observability_detail_allowed(&state, auth_header.as_deref(), &client_ip) {
            return Ok(json_response(response_code, &health_status));
        }
        let minimal = json!({
            "status": health_status["status"],
            "ready": health_status["ready"],
        });
        return Ok(json_response(response_code, &minimal));
    }

    // Overload status. Unauthenticated callers (load balancers / monitoring
    // probes) get a coarse, LB-safe `{level}` plus the correct status code
    // (503 at critical); the full pressure/counter snapshot is gated behind
    // observability auth so resource internals are not exposed by default.
    if path == "/overload" && method == Method::GET {
        let detailed = observability_detail_allowed(&state, auth_header.as_deref(), &client_ip);
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
                if let Some(failures) = state.serving_listener_failures.as_ref() {
                    obj.insert(
                        "listener_failures".to_string(),
                        serde_json::to_value(failures.snapshot()).unwrap_or_default(),
                    );
                }
            }
            if detailed {
                return Ok(json_response(status, &snapshot_value));
            }
            let level = snapshot_value
                .get("level")
                .cloned()
                .unwrap_or_else(|| json!("normal"));
            return Ok(json_response(status, &json!({ "level": level })));
        }
        return Ok(json_response(StatusCode::OK, &json!({"level": "normal"})));
    }

    // Prometheus metrics endpoint. Gated by default — a scraper must present a
    // valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, or originate
    // from `FERRUM_METRICS_ALLOWED_CIDRS`. Unauthenticated scraping is an
    // explicit operator opt-in (token or CIDR), not the default.
    if path == "/metrics" && method == Method::GET {
        if !observability_detail_allowed(&state, auth_header.as_deref(), &client_ip) {
            return Ok(metrics_unauthorized_response());
        }
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
    let auth = match state.jwt_manager.verify_request(auth_header.as_deref()) {
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
        match parse_chargeback_format(req.uri().query()) {
            Ok(ChargebackFormat::Json) => {
                let json_output = registry.render_json();
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("Cache-Control", "no-store")
                    .body(Full::new(Bytes::from(json_output)))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
                return Ok(resp);
            }
            Ok(ChargebackFormat::Prometheus) => {
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
            Err(resp) => return Ok(*resp),
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

    // Per-namespace tenancy enforcement on the REST admin plane (issue #2120,
    // option B). Opt-in via FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM; mirrors the
    // CP↔DP gRPC `ns` claim so a staging-scoped operator token cannot address
    // prod by swapping X-Ferrum-Namespace. Applies only to namespace-scoped
    // resource routes — global admin surfaces (TLS management, /cluster,
    // /namespaces, metrics, mesh introspection) are not tenant-selected.
    if state.admin_require_namespace_claim
        && is_namespace_scoped_route(segments_peek.as_slice())
        && let Some(resp) = enforce_namespace_claim(&auth, &namespace, &path)
    {
        drop(req.into_body());
        return Ok(resp);
    }
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
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
    if let Some(required) = tls_route_required_role(&method, segments.as_slice())
        && let Some(resp) = require_admin_role(&auth, required)
    {
        return Ok(resp);
    }

    let response = match (method.clone(), segments.as_slice()) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_acme_certificate(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "acme", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_finalize_acme_order(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "acme", "orders", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_certificate(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "certificates", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_ca_bundle(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "ca-bundles", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_crl(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "crls", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_ocsp_response(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "ocsp-responses", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
                return Ok(resp);
            }
            tls_management::handle_update_jwks(&state, id, &body_bytes).await
        }
        (Method::DELETE, ["admin", "tls", "jwks", id]) => {
            if let Some(resp) = require_admin_role(&auth, AdminRole::Admin) {
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
    };
    if state.admin_audit_enabled
        && let (Ok(http_response), Some(db)) = (response.as_ref(), state.db.as_ref())
        && http_response.status().is_success()
        && tls_mutation_audit_descriptor(&method, segments.as_slice(), None).is_some()
    {
        let response_body = if method == Method::POST
            && matches!(
                segments.as_slice(),
                ["admin", "tls", _] | ["admin", "tls", "acme", _] | ["admin", "tls", "rotate", _]
            ) {
            http_response
                .body()
                .clone()
                .collect()
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<Value>(&body.to_bytes()).ok())
        } else {
            None
        };
        if let Some((action, resource_type, resource_id)) =
            tls_mutation_audit_descriptor(&method, segments.as_slice(), response_body.as_ref())
        {
            let event = audit::AuditEvent::new(
                &auth,
                action,
                resource_type,
                resource_id,
                &namespace,
                json!({"path": path}),
            );
            if let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event) {
                log_audit_enqueue_failure(&error);
            }
        }
    }
    response
}

fn tls_mutation_audit_descriptor(
    method: &Method,
    segments: &[&str],
    response_body: Option<&Value>,
) -> Option<(&'static str, &'static str, String)> {
    if !matches!(segments, ["admin", "tls", ..])
        || (method != Method::POST && method != Method::PUT && method != Method::DELETE)
        || matches!(segments, ["admin", "tls", "validate"])
    {
        return None;
    }
    let action = match segments {
        ["admin", "tls", "acme", "orders", _, "finalize"] if method == Method::POST => "finalize",
        ["admin", "tls", "acme", "renew", _] if method == Method::POST => "renew",
        ["admin", "tls", "rotate", _] if method == Method::POST => "rotate",
        _ if method == Method::POST => "create",
        _ if method == Method::PUT => "update",
        _ if method == Method::DELETE => "delete",
        _ => return None,
    };
    let resource_type = match segments.get(2).copied() {
        Some("certificates") => "tls_certificate",
        Some("private-keys") => "tls_private_key",
        Some("ca-bundles") => "tls_ca_bundle",
        Some("crls") => "tls_crl",
        Some("ocsp-responses") => "tls_ocsp_response",
        Some("jwks") => "tls_jwks",
        Some("acme") => "tls_acme",
        Some("rotate") => "tls_rotation",
        _ => "tls_material",
    };
    let resource_id = match segments {
        ["admin", "tls", "acme", "orders", id, "finalize"] => (*id).to_string(),
        ["admin", "tls", "acme", "renew", certificate_id] => (*certificate_id).to_string(),
        // Prefer the normalized surface from the handler's response body so
        // documented aliases (e.g. /rotate/frontend vs the canonical watcher
        // name) audit under the surface that was actually rotated.
        ["admin", "tls", "rotate", surface] => response_body
            .and_then(|body| body.get("surface"))
            .and_then(Value::as_str)
            .unwrap_or(surface)
            .to_string(),
        // Every 4-segment ACME path is a collection (accounts/orders/
        // certificates), so creates take the created resource's id from the
        // response body — this arm must come before the generic
        // `["admin", "tls", _, id]` arm, which would otherwise bind the
        // collection name as the id.
        ["admin", "tls", _] | ["admin", "tls", "acme", _] => response_body
            .and_then(|body| body.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("new")
            .to_string(),
        ["admin", "tls", _, id] | ["admin", "tls", "acme", _, id] => (*id).to_string(),
        _ => segments.last().copied().unwrap_or("new").to_string(),
    };
    Some((action, resource_type, resource_id))
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

fn validate_path_resource_id(id: &str) -> Result<(), Box<Response<Full<Bytes>>>> {
    crate::config::types::validate_resource_id(id).map_err(|error| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": error}),
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
) -> Result<(), String> {
    for item in items {
        match crud::prepare_batch_resource(item, namespace, now, validation_ctx) {
            Ok(()) => {}
            Err(crud::BatchPreparationError::Validation(errors)) => {
                extend_prefixed_errors(validation_errors, kind, item.id(), errors);
            }
            Err(crud::BatchPreparationError::Internal(error)) => {
                return Err(format!("{} '{}': {}", kind, item.id(), error));
            }
        }
    }
    Ok(())
}

async fn load_consumer_in_namespace(
    db: &dyn DatabaseBackend,
    consumer_id: &str,
    namespace: &str,
) -> Result<Consumer, Box<Response<Full<Bytes>>>> {
    match db.get_consumer(namespace, consumer_id).await {
        Ok(Some(consumer)) => Ok(consumer),
        Ok(None) => Err(Box::new(consumer_not_found_response())),
        Err(e) => Err(Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&e),
        ))),
    }
}

pub(crate) fn basic_auth_credential_error_status(
    error: &crate::config::types::BasicAuthCredentialPreparationError,
) -> StatusCode {
    match error {
        crate::config::types::BasicAuthCredentialPreparationError::InvalidCredential(_) => {
            StatusCode::BAD_REQUEST
        }
        crate::config::types::BasicAuthCredentialPreparationError::ServerConfiguration(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub(crate) fn hash_credential_if_needed(
    cred_type: &str,
    cred_value: &mut Value,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    if cred_type == "basicauth"
        && let Err(e) = crud::hash_basic_auth_credentials(cred_value)
    {
        let status = basic_auth_credential_error_status(&e);
        return Err(Box::new(json_response(
            status,
            &json!({"error": e.to_string()}),
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

async fn ensure_mtls_consumer_candidate(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    match crud::mtls_consumer_candidate_errors(db, namespace, consumer).await {
        Ok(errors) if errors.is_empty() => Ok(()),
        Ok(errors) => Err(Box::new(json_response(
            StatusCode::CONFLICT,
            &json!({"error": errors.join("; ")}),
        ))),
        Err(error) => Err(Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&error),
        ))),
    }
}

async fn ensure_hmac_consumer_candidate(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    match crud::hmac_consumer_candidate_errors(db, namespace, consumer).await {
        Ok(errors) if errors.is_empty() => Ok(()),
        Ok(errors) => Err(Box::new(json_response(
            StatusCode::CONFLICT,
            &json!({"error": errors.join("; ")}),
        ))),
        Err(error) => Err(Box::new(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &db_error_response(&error),
        ))),
    }
}

async fn persist_consumer_update(
    db: Arc<dyn DatabaseBackend>,
    admission_guard: &mut crud::NamespaceConfigAdmissionGuard,
    mut consumer: Consumer,
    success_status: StatusCode,
) -> Response<Full<Bytes>> {
    // Every credential endpoint rewrites the complete Consumer and rebuilds
    // its credential index entries. Revalidate retained HMAC credentials even
    // when the requested mutation targets another credential type, so stale or
    // out-of-band duplicates fail before the datastore uniqueness backstop.
    if !consumer.credential_entries("hmac_auth").is_empty()
        && let Err(response) =
            ensure_hmac_consumer_candidate(db.as_ref(), &consumer.namespace, &consumer).await
    {
        return *response;
    }
    if let Err(error) = admission_guard.ensure_held() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("Config admission unavailable: {error}")}),
        );
    }
    consumer.updated_at = Utc::now();
    let persistence_db = db.clone();
    let persistence_consumer = consumer.clone();
    let update_result = match admission_guard
        .run_persistence(async move {
            persistence_db
                .update_consumer(&persistence_consumer)
                .await
        })
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("Config admission unavailable: {error}")}),
            );
        }
    };
    match update_result {
        // The consumer vanished between the namespace-scoped load and the
        // write (concurrent delete) — not-found, not a phantom success.
        Ok(false) => consumer_not_found_response(),
        Ok(true) if success_status == StatusCode::NO_CONTENT => {
            empty_response(StatusCode::NO_CONTENT)
        }
        Ok(true) => {
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

fn restore_payload_from_config(config: GatewayConfig) -> RestorePayload {
    RestorePayload {
        version: config.version,
        proxies: config.proxies,
        consumers: config.consumers,
        plugin_configs: config.plugin_configs,
        upstreams: config.upstreams,
    }
}

/// Snapshot of a namespace captured before a destructive restore so a failed
/// import — or a failed clear — can be compensated back to the prior state on
/// every database backend.
struct RestoreSnapshot {
    /// Prior config resources (proxies/consumers/plugin_configs/upstreams).
    payload: RestorePayload,
    /// Authoritative count of `api_specs` in the namespace at snapshot time.
    api_specs_total: usize,
}

impl RestoreSnapshot {
    fn resource_counts(&self) -> NamespaceResourceCounts {
        NamespaceResourceCounts {
            proxies: u64::try_from(self.payload.proxies.len()).unwrap_or(u64::MAX),
            consumers: u64::try_from(self.payload.consumers.len()).unwrap_or(u64::MAX),
            plugin_configs: u64::try_from(self.payload.plugin_configs.len()).unwrap_or(u64::MAX),
            upstreams: u64::try_from(self.payload.upstreams.len()).unwrap_or(u64::MAX),
            api_specs: u64::try_from(self.api_specs_total).unwrap_or(u64::MAX),
        }
    }
}

/// Capture an authoritative snapshot of `namespace` for restore rollback.
///
/// It does not fail semantic validation of an invalid-but-present config, but
/// it does fail closed for either database unavailability or row/document
/// integrity errors that prevent an exact rollback snapshot.
///
/// Both the config resources and the `api_specs` count are read from the
/// PRIMARY (never a lagging read replica) so the recovery report is authoritative.
async fn snapshot_namespace_for_rollback(
    db: &dyn DatabaseBackend,
    namespace: &str,
) -> Result<RestoreSnapshot, anyhow::Error> {
    // Non-validating raw load from the primary. Invalid-but-present config still
    // snapshots; a real DB error propagates so the caller aborts.
    let config = db.load_namespace_snapshot(namespace).await?;
    let payload = restore_payload_from_config(config);

    // `api_specs` are not part of `GatewayConfig`. Capture only their
    // authoritative count from the PRIMARY: recovery requires the original
    // documents to be re-submitted, and enumerating identities with OFFSET
    // pagination adds no recovery value while introducing ordering hazards.
    let api_specs_total =
        usize::try_from(db.count_api_specs(namespace).await?).unwrap_or(usize::MAX);

    Ok(RestoreSnapshot {
        payload,
        api_specs_total,
    })
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
            db.get_plugin_config(namespace, id).await?
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
                match db.get_upstream(namespace, override_uid).await {
                    Ok(u) => u,
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
            Err(e) => errors.push(format!(
                "consumers: {}",
                crud::consumer_persist_error_message(&e)
            )),
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

async fn rollback_failed_restore(
    db: &dyn DatabaseBackend,
    namespace: &str,
    snapshot: &RestorePayload,
) -> Result<(), Vec<String>> {
    if let Err(error) = db.delete_all_resources(namespace).await {
        return Err(vec![format!(
            "failed to clear partially imported config: {}",
            error
        )]);
    }

    let (_, errors) = persist_payload_resources(db, snapshot, false).await;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Finalize a failed restore. Attempts a best-effort rollback to the pre-restore
/// snapshot, records the audit event, and builds the operator-facing `500`
/// response. Shared by the delete-failure and import-failure paths so both roll
/// back identically. The caller always holds a snapshot here — restore aborts
/// with `503` before touching durable state when one cannot be captured — so
/// there is no "rollback unavailable" branch.
async fn finish_failed_restore(
    admin_audit_enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    actor: &AuditActor,
    namespace: &str,
    restore_errors: Vec<String>,
    snapshot: &RestoreSnapshot,
) -> Response<Full<Bytes>> {
    let (rollback_status, rollback_errors) =
        match rollback_failed_restore(db.as_ref(), namespace, &snapshot.payload).await {
            Ok(()) => ("completed", None),
            Err(errors) => {
                error!(
                    "Restore: rollback failed for namespace '{}': {}",
                    namespace,
                    errors.join("; ")
                );
                ("incomplete", Some(errors))
            }
        };

    let event = audit::AuditEvent::new(
        actor,
        "restore",
        "gateway_config",
        namespace,
        namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            json!({"rollback": rollback_status}),
        ),
    );
    if let Err(error) = audit::record(admin_audit_enabled, db.clone(), event) {
        log_audit_enqueue_failure(&error);
    }

    let error_message = match rollback_status {
        "completed" => "Restore failed; restore rolled back and prior config retained",
        // "incomplete"
        _ => "Restore failed and rollback of prior config was incomplete; manual recovery required",
    };

    let mut response = json!({
        "error": error_message,
        "restore_errors": restore_errors,
        "rollback": rollback_status,
    });
    if let Some(rollback_errors) = rollback_errors {
        response["rollback_errors"] = json!(rollback_errors);
    }

    // A config rollback restores proxies/consumers/plugin_configs/upstreams but
    // NOT `api_specs` (admin-only metadata outside `GatewayConfig`). When the
    // prior namespace carried specs, give the operator a genuinely usable
    // recovery path: report the authoritative number removed and direct the
    // operator to list the currently stored specs and re-submit the originals.
    if snapshot.api_specs_total > 0 {
        // Preserve the authoritative affected count.
        let total = snapshot.api_specs_total;
        warn!(
            namespace = %namespace,
            api_spec_count = total,
            "Restore: rollback restored config resources but NOT api_specs; operator must re-submit affected API specs"
        );
        response["api_specs_not_restored"] = json!(total);
        let note = format!(
            "{total} API spec(s) were removed and are not part of config restore or rollback. Re-submit the original documents via POST /api-specs; list specs currently stored in the namespace with GET /api-specs."
        );
        response["api_specs_note"] = json!(note);
    }

    json_response(StatusCode::INTERNAL_SERVER_ERROR, &response)
}

/// Finalize a restore whose atomic clear definitively aborted.
async fn finish_atomic_delete_failure(
    admin_audit_enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    actor: &AuditActor,
    namespace: &str,
    delete_error: String,
) -> Response<Full<Bytes>> {
    let event = audit::AuditEvent::new(
        actor,
        "restore",
        "gateway_config",
        namespace,
        namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            json!({"rollback": "not_needed"}),
        ),
    );
    if let Err(error) = audit::record(admin_audit_enabled, db.clone(), event) {
        log_audit_enqueue_failure(&error);
    }

    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({
            "error": "Restore failed while clearing existing config; the clear is atomic, so the prior config was retained",
            "restore_errors": [format!("failed to clear existing config: {}", delete_error)],
            "rollback": "not_needed",
        }),
    )
}

async fn finish_unknown_atomic_delete_failure(
    admin_audit_enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    actor: &AuditActor,
    namespace: &str,
    delete_error: String,
) -> Response<Full<Bytes>> {
    let event = audit::AuditEvent::new(
        actor,
        "restore",
        "gateway_config",
        namespace,
        namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            json!({"rollback": "unknown_outcome"}),
        ),
    );
    if let Err(error) = audit::record(admin_audit_enabled, db, event) {
        log_audit_enqueue_failure(&error);
    }

    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({
            "error": "Restore failed while clearing existing config; the atomic clear outcome could not be verified. Manual recovery is required.",
            "restore_errors": [format!("failed to clear existing config: {}", delete_error)],
            "rollback": "unknown_outcome",
        }),
    )
}

/// Run the destructive restore, any compensating rollback, and its durable
/// audit enqueue as one owned persistence future. The admission guard executes
/// this helper in a detached task, so disconnect/cancellation cannot release
/// the namespace while an SQL transaction, MongoDB transaction, or standalone
/// MongoDB compensation sequence still has an unknown outcome.
async fn persist_restore_after_validation(
    db: Arc<dyn DatabaseBackend>,
    admin_audit_enabled: bool,
    actor: AuditActor,
    namespace: String,
    payload: RestorePayload,
    snapshot: RestoreSnapshot,
) -> Response<Full<Bytes>> {
    if let Err(error) = db.delete_all_resources(&namespace).await {
        error!("Restore: failed to delete existing resources: {}", error);
        if error.mode().is_atomic() {
            if error.has_unknown_commit_result() {
                let verification = db.count_namespace_resources(&namespace).await;
                if let Err(verification_error) = &verification {
                    error!(
                        namespace = %namespace,
                        error = %verification_error,
                        "Restore: failed to verify ambiguous atomic clear outcome"
                    );
                }
                return match classify_atomic_clear_verification(
                    snapshot.resource_counts(),
                    verification,
                ) {
                    AtomicClearVerification::ClearCommitted => {
                        finish_failed_restore(
                            admin_audit_enabled,
                            db,
                            &actor,
                            &namespace,
                            vec![format!("failed to clear existing config: {error}")],
                            &snapshot,
                        )
                        .await
                    }
                    AtomicClearVerification::PriorConfigIntact => {
                        finish_atomic_delete_failure(
                            admin_audit_enabled,
                            db,
                            &actor,
                            &namespace,
                            error.to_string(),
                        )
                        .await
                    }
                    AtomicClearVerification::UnknownOutcome => {
                        finish_unknown_atomic_delete_failure(
                            admin_audit_enabled,
                            db,
                            &actor,
                            &namespace,
                            error.to_string(),
                        )
                        .await
                    }
                };
            }
            return finish_atomic_delete_failure(
                admin_audit_enabled,
                db,
                &actor,
                &namespace,
                error.to_string(),
            )
            .await;
        }
        return finish_failed_restore(
            admin_audit_enabled,
            db,
            &actor,
            &namespace,
            vec![format!("failed to clear existing config: {error}")],
            &snapshot,
        )
        .await;
    }

    info!("Restore: cleared existing config, beginning import");

    let (created, errors) = persist_payload_resources(db.as_ref(), &payload, false).await;

    info!(
        "Restore: imported {} proxies, {} consumers, {} plugin_configs, {} upstreams",
        created.proxies, created.consumers, created.plugin_configs, created.upstreams
    );

    let response = json!({
        "restored": {
            "proxies": created.proxies,
            "consumers": created.consumers,
            "plugin_configs": created.plugin_configs,
            "upstreams": created.upstreams,
        }
    });

    if !errors.is_empty() {
        error!(
            "Restore: import failed; rolling back namespace '{}': {}",
            namespace,
            errors.join("; ")
        );
        return finish_failed_restore(
            admin_audit_enabled,
            db,
            &actor,
            &namespace,
            errors,
            &snapshot,
        )
        .await;
    }

    let event = audit::AuditEvent::new(
        &actor,
        "restore",
        "gateway_config",
        &namespace,
        &namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            response["restored"].clone(),
        ),
    );
    if let Err(error) = audit::record(admin_audit_enabled, db, event) {
        log_audit_enqueue_failure(&error);
    }

    json_response(StatusCode::OK, &response)
}

/// Allowed credential types for consumer authentication plugins.
pub const ALLOWED_CREDENTIAL_TYPES: &[&str] =
    &["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];

fn normalize_credential_set(cred_value: Value) -> Result<Value, Box<Response<Full<Bytes>>>> {
    match cred_value {
        Value::Object(_) => Ok(Value::Array(vec![cred_value])),
        Value::Array(entries) if entries.is_empty() => Err(Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential set must contain at least one entry"}),
        ))),
        Value::Array(entries) if entries.iter().all(Value::is_object) => Ok(Value::Array(entries)),
        Value::Array(_) => Err(Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential set entries must be JSON objects"}),
        ))),
        _ => Err(Box::new(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Credential set must be a JSON object or array of JSON objects"}),
        ))),
    }
}

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

    if let Err(resp) = validate_path_resource_id(consumer_id) {
        return Ok(*resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
                ));
            }
        };

    let mut cred_value = match parse_json_value(body) {
        Ok(value) => value,
        Err(resp) => return Ok(*resp),
    };
    cred_value = match normalize_credential_set(cred_value) {
        Ok(value) => value,
        Err(resp) => return Ok(*resp),
    };
    if let Err(resp) = hash_credential_if_needed(cred_type, &mut cred_value) {
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
    consumer.normalize_fields();

    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(invalid_credential_fields_response(&field_errors));
    }
    if let Some(normalized_credential) = consumer.credentials.get(cred_type)
        && let Err(resp) = ensure_credential_unique(
            db.as_ref(),
            namespace,
            consumer_id,
            cred_type,
            normalized_credential,
        )
        .await
    {
        return Ok(*resp);
    }
    if cred_type == "mtls_auth"
        && let Err(resp) = ensure_mtls_consumer_candidate(db.as_ref(), namespace, &consumer).await
    {
        return Ok(*resp);
    }
    let response = persist_consumer_update(
        db.clone(),
        &mut namespace_config_admission_guard,
        consumer.clone(),
        StatusCode::OK,
    )
    .await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "update_credentials",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::credential_update_diff(
                cred_type,
                crud::consumer_audit_body(&before),
                crud::consumer_audit_body(&consumer),
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

    if let Err(resp) = validate_path_resource_id(consumer_id) {
        return Ok(*resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
                ));
            }
        };

    let mut consumer = match load_consumer_in_namespace(db.as_ref(), consumer_id, namespace).await {
        Ok(consumer) => consumer,
        Err(resp) => return Ok(*resp),
    };
    let before = consumer.clone();
    consumer.credentials.remove(cred_type);
    let response = persist_consumer_update(
        db.clone(),
        &mut namespace_config_admission_guard,
        consumer.clone(),
        StatusCode::NO_CONTENT,
    )
    .await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "delete_credentials",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::credential_update_diff(
                cred_type,
                crud::consumer_audit_body(&before),
                crud::consumer_audit_body(&consumer),
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

    if let Err(resp) = validate_path_resource_id(consumer_id) {
        return Ok(*resp);
    }

    if !ALLOWED_CREDENTIAL_TYPES.contains(&cred_type) {
        return Ok(invalid_credential_type_response(cred_type));
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(resp) => return Ok(*resp),
    };
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
                ));
            }
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
    consumer.normalize_fields();

    if let Err(field_errors) = consumer.validate_fields() {
        return Ok(invalid_credential_fields_response(&field_errors));
    }
    if let Some(normalized_credential) = consumer.credentials.get(cred_type)
        && let Err(resp) = ensure_credential_unique(
            db.as_ref(),
            namespace,
            consumer_id,
            cred_type,
            normalized_credential,
        )
        .await
    {
        return Ok(*resp);
    }
    if cred_type == "mtls_auth"
        && let Err(resp) = ensure_mtls_consumer_candidate(db.as_ref(), namespace, &consumer).await
    {
        return Ok(*resp);
    }
    let response = persist_consumer_update(
        db.clone(),
        &mut namespace_config_admission_guard,
        consumer.clone(),
        StatusCode::OK,
    )
    .await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "append_credential",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::credential_update_diff(
                cred_type,
                crud::consumer_audit_body(&before),
                crud::consumer_audit_body(&consumer),
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

    if let Err(resp) = validate_path_resource_id(consumer_id) {
        return Ok(*resp);
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
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
                ));
            }
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

    let response = persist_consumer_update(
        db.clone(),
        &mut namespace_config_admission_guard,
        consumer.clone(),
        StatusCode::OK,
    )
    .await;
    if response.status().is_success() {
        let event = audit::AuditEvent::new(
            actor,
            "delete_credential",
            "consumer_credentials",
            consumer_id,
            namespace,
            audit::credential_update_diff(
                cred_type,
                crud::consumer_audit_body(&before),
                crud::consumer_audit_body(&consumer),
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

pub(crate) fn validate_plugin_config_definition(
    pc: &PluginConfig,
    http_client: plugins::PluginHttpClient,
) -> Result<(), String> {
    let known_plugins = plugins::available_plugins();
    if !known_plugins.contains(&pc.plugin_name.as_str()) {
        return Err(format!(
            "Unknown plugin name '{}'. Available plugins: {:?}",
            pc.plugin_name, known_plugins
        ));
    }
    if !pc.enabled {
        return Ok(());
    }
    plugins::validate_plugin_config_with_http_client(&pc.plugin_name, &pc.config, http_client)
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
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
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
    let validation_ctx = crud::ValidationCtx::from_state(state);
    let known_plugins = crate::plugins::available_plugins();
    let mut validation_errors: Vec<String> = Vec::new();

    if let Err(error) = prepare_batch_items(
        &mut batch.consumers,
        "Consumer",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    ) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": error}),
        ));
    }
    if let Err(error) = prepare_batch_items(
        &mut batch.upstreams,
        "Upstream",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    ) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": error}),
        ));
    }
    if let Err(error) = prepare_batch_items(
        &mut batch.proxies,
        "Proxy",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    ) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": error}),
        ));
    }
    if let Err(error) = prepare_batch_items(
        &mut batch.plugin_configs,
        "PluginConfig",
        namespace,
        now,
        &validation_ctx,
        &mut validation_errors,
    ) {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": error}),
        ));
    }

    for plugin_config in &batch.plugin_configs {
        if !known_plugins.contains(&plugin_config.plugin_name.as_str()) {
            validation_errors.push(format!(
                "PluginConfig '{}': unknown plugin name '{}'",
                plugin_config.id, plugin_config.plugin_name
            ));
        }
        if crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(
            plugin_config,
        ) {
            if let Err(err) = crate::plugins::validate_plugin_config_policy_only(
                &plugin_config.plugin_name,
                &plugin_config.config,
                &state.backend_allow_ips,
            ) {
                validation_errors.push(format!(
                    "PluginConfig '{}': invalid config: {}",
                    plugin_config.id, err
                ));
            }
        } else if let Err(err) =
            validate_plugin_config_definition(plugin_config, plugin_validation_http_client(state))
        {
            validation_errors.push(format!(
                "PluginConfig '{}': invalid config: {}",
                plugin_config.id, err
            ));
        }
    }

    if batch
        .plugin_configs
        .iter()
        .any(crate::plugins::transaction_log_schema::is_enabled_config_graph_participant)
    {
        match crud::validate_transaction_log_schema_candidates(
            db.as_ref(),
            state,
            namespace,
            &batch.plugin_configs,
            None,
        )
        .await
        {
            Ok(()) => {}
            Err(crud::AfterValidateError::BadRequest(errors)) => {
                validation_errors.extend(errors);
            }
            Err(crud::AfterValidateError::Db(error)) => validation_errors.push(format!(
                "Failed to load config for transaction-log schema candidate validation: {}",
                error
            )),
            Err(crud::AfterValidateError::Response(_)) => validation_errors.push(
                "Transaction-log schema candidate validation returned an unexpected response"
                    .to_string(),
            ),
        }
    }

    let enabled_prometheus_configs: Vec<&str> = batch
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.enabled && plugin.plugin_name == "prometheus_metrics")
        .map(|plugin| plugin.id.as_str())
        .collect();
    if enabled_prometheus_configs.len() > 1 {
        validation_errors.push(format!(
            "prometheus_metrics permits at most one enabled global instance; batch contains: {}",
            enabled_prometheus_configs.join(", ")
        ));
    } else if let Some(submitted_id) = enabled_prometheus_configs.first() {
        match crud::enabled_prometheus_metrics_owner_exists(db.as_ref(), namespace, None).await {
            Ok(true) => validation_errors.push(format!(
                "PluginConfig '{}': prometheus_metrics permits at most one enabled global instance; another config already owns the process registry",
                submitted_id
            )),
            Ok(false) => {}
            Err(err) => validation_errors.push(format!(
                "PluginConfig '{}': prometheus_metrics uniqueness check failed: {}",
                submitted_id, err
            )),
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

    match db.load_namespace_snapshot(namespace).await {
        Ok(mut candidate_config) => {
            for consumer in &batch.consumers {
                if let Some(existing) = candidate_config
                    .consumers
                    .iter_mut()
                    .find(|item| item.id == consumer.id)
                {
                    *existing = consumer.clone();
                } else {
                    candidate_config.consumers.push(consumer.clone());
                }
            }
            for proxy in &batch.proxies {
                if let Some(existing) = candidate_config
                    .proxies
                    .iter_mut()
                    .find(|item| item.id == proxy.id)
                {
                    *existing = proxy.clone();
                } else {
                    candidate_config.proxies.push(proxy.clone());
                }
            }
            for plugin in &batch.plugin_configs {
                if let Some(existing) = candidate_config
                    .plugin_configs
                    .iter_mut()
                    .find(|item| item.id == plugin.id)
                {
                    *existing = plugin.clone();
                } else {
                    candidate_config.plugin_configs.push(plugin.clone());
                }
            }
            if let Err(errors) = candidate_config.validate_mtls_auth_compatibility() {
                validation_errors.extend(errors);
            }
            if let Err(errors) = candidate_config.validate_unique_mtls_credentials() {
                validation_errors.extend(errors);
            }
            // Match single-resource admission: legacy duplicates are already
            // quarantined at load time and must not block unrelated batch
            // writes. Re-evaluate the authoritative candidate only when this
            // batch submits a Consumer that carries HMAC credentials.
            if batch
                .consumers
                .iter()
                .any(|consumer| !consumer.credential_entries("hmac_auth").is_empty())
                && let Err(errors) = candidate_config.validate_unique_hmac_credentials()
            {
                validation_errors.extend(errors);
            }
        }
        Err(error) => validation_errors.push(format!(
            "Failed to load namespace config for credential candidate validation: {}",
            error
        )),
    }

    if !batch.proxies.is_empty() || !batch.plugin_configs.is_empty() {
        match crud::validate_hmac_request_transform_candidates(
            db.as_ref(),
            state,
            namespace,
            &batch.proxies,
            &batch.plugin_configs,
            None,
        )
        .await
        {
            Ok(()) => {}
            Err(crud::AfterValidateError::BadRequest(errors)) => {
                validation_errors.extend(errors);
            }
            Err(crud::AfterValidateError::Db(error)) => validation_errors.push(format!(
                "Failed to load config for HMAC request-transform candidate validation: {}",
                error
            )),
            Err(crud::AfterValidateError::Response(_)) => validation_errors.push(
                "HMAC request-transform candidate validation returned an unexpected response"
                    .to_string(),
            ),
        }
    }

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
                    // Upstream reads are namespace-predicated (issue #2122
                    // DB-M1): an upstream in another namespace reports as
                    // missing, so cross-namespace references are rejected
                    // without disclosing other tenants' resources.
                    validation_errors.push(format!(
                        "Proxy '{}' references upstream_id '{}' that does not exist in namespace '{}'",
                        proxy.id, upstream_id, namespace
                    ));
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
                match db.get_upstream(namespace, upstream_id).await {
                    Ok(Some(upstream)) => upstream
                        .subsets
                        .as_ref()
                        .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name)),
                    Ok(None) => false,
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
                match db.get_upstream(namespace, upstream_id).await {
                    Ok(upstream) => upstream,
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
                    // Proxy reads are namespace-predicated (issue #2122
                    // DB-M1): a proxy in another namespace reports as
                    // missing, so cross-namespace references are rejected
                    // without disclosing other tenants' resources.
                    validation_errors.push(format!(
                        "PluginConfig '{}' references proxy_id '{}' that does not exist in namespace '{}'",
                        plugin_config.id, proxy_id, namespace
                    ));
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

    if let Err(error) = namespace_config_admission_guard.ensure_held() {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("Config admission unavailable: {error}")}),
        ));
    }

    let persistence_db = db.clone();
    let persistence_batch = batch;
    let (created, errors) = match namespace_config_admission_guard
        .run_persistence(async move {
            persist_payload_resources(persistence_db.as_ref(), &persistence_batch, true).await
        })
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": format!("Config admission unavailable: {error}")}),
            ));
        }
    };

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

async fn validate_restore_candidate_on_blocking_pool(
    mut candidate: GatewayConfig,
    cert_expiry_days: u64,
    backend_allow_ips: crate::config::BackendEgressPolicy,
) -> Result<(GatewayConfig, Vec<String>), anyhow::Error> {
    let (candidate, result) = tokio::task::spawn_blocking(move || {
        let result = ValidationPipeline::new(&mut candidate)
            .validate_all_fields_with_ip_policy(
                cert_expiry_days,
                &backend_allow_ips,
                ValidationAction::Collect,
            )
            .validate_unique_resource_ids(ValidationAction::Collect)
            .validate_unique_consumer_identities(ValidationAction::Collect)
            .validate_unique_consumer_credentials(ValidationAction::Collect)
            .validate_hosts(ValidationAction::Collect)
            .validate_regex_listen_paths(ValidationAction::Collect)
            .validate_listen_path_encodings(ValidationAction::Collect)
            .validate_unique_listen_paths(ValidationAction::Collect)
            .validate_stream_proxies(ValidationAction::Collect)
            .validate_plugin_configs(&backend_allow_ips, ValidationAction::Collect)
            .validate_upstream_references(ValidationAction::Collect)
            .validate_mesh_route_dispatch_references(ValidationAction::Collect)
            .validate_plugin_references(ValidationAction::Collect)
            .run();
        (candidate, result)
    })
    .await
    .map_err(|error| anyhow::anyhow!("restore validation task failed: {error}"))?;

    let errors = match result {
        Ok(errors) => errors,
        Err(error) => vec![error.to_string()],
    };
    Ok((candidate, errors))
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
    let mut namespace_config_admission_guard =
        match crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(error) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"error": format!("Config admission unavailable: {error}")}),
                ));
            }
        };

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
        let cert_expiry_days = state
            .proxy_state
            .as_ref()
            .map(|ps| ps.env_config.tls_cert_expiry_warning_days)
            .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS);
        let (temp_config, mut validation_errors) =
            match validate_restore_candidate_on_blocking_pool(
                temp_config,
                cert_expiry_days,
                state.backend_allow_ips.clone(),
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &json!({
                            "error": format!(
                                "Restore aborted: payload validation could not complete: {}. Existing config was NOT deleted.",
                                error
                            )
                        }),
                    ));
                }
            };
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
        if temp_config
            .plugin_configs
            .iter()
            .any(|plugin| plugin.enabled && plugin.plugin_name == "prometheus_metrics")
        {
            match crud::enabled_prometheus_metrics_owner_exists_outside_namespace(
                db.as_ref(),
                namespace,
            )
            .await
            {
                Ok(true) => validation_errors.push(
                    "prometheus_metrics permits at most one enabled global instance; another namespace already owns the process registry"
                        .to_string(),
                ),
                Ok(false) => {}
                Err(error) => {
                    return Ok(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &json!({
                            "error": format!(
                                "Restore aborted: prometheus_metrics ownership could not be validated: {}. Existing config was NOT deleted.",
                                error
                            )
                        }),
                    ));
                }
            }
        }
        match crud::validate_hmac_request_transform_restore_candidate(state, &temp_config) {
            Ok(()) => {}
            Err(crud::AfterValidateError::BadRequest(errors)) => {
                validation_errors.extend(errors);
            }
            Err(crud::AfterValidateError::Db(error)) => {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({
                        "error": format!(
                            "Restore aborted: HMAC request-transform composition could not be validated: {}. Existing config was NOT deleted.",
                            error
                        )
                    }),
                ));
            }
            Err(crud::AfterValidateError::Response(_)) => validation_errors.push(
                "HMAC request-transform candidate validation returned an unexpected response"
                    .to_string(),
            ),
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

    // Complete all fallible payload preparation before changing durable state.
    let mut payload = payload;
    let mut preparation_errors = Vec::new();
    normalize_restore_payload_timestamps(&mut payload, Utc::now());
    apply_payload_namespace(&mut payload, namespace);
    hash_payload_consumers(&mut payload.consumers, &mut preparation_errors);
    if !preparation_errors.is_empty() {
        return Ok(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({
                "error": "Restore preparation failed; existing config was not changed and prior config retained",
                "restore_errors": preparation_errors,
            }),
        ));
    }

    // Snapshot the namespace before deletion so a failure in any independently
    // committed import chunk (or a partial clear) can be compensated on every
    // database backend. The snapshot loads RAW rows from the primary without the
    // fatal validation pipeline, so an invalid-but-present config (exactly what
    // restore is used to repair) still snapshots and keeps rollback available.
    //
    // Fail-safe: abort before delete if either the primary is unavailable or a
    // corrupt row/document prevents an exact rollback snapshot.
    let snapshot = match snapshot_namespace_for_rollback(db.as_ref(), namespace).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let data_integrity = error
                .downcast_ref::<SnapshotDataIntegrityError>()
                .map(ToString::to_string);
            error!(
                namespace = %namespace,
                error = %error,
                "Restore: aborting — prior config could not be snapshotted for rollback; existing config NOT deleted"
            );
            if let Some(integrity_error) = data_integrity {
                return Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({
                        "error": "Restore aborted: the prior configuration contains a data-integrity error and could not be snapshotted for rollback. Existing config was NOT deleted; repair the identified stored resource before retrying.",
                        "restore_errors": [integrity_error],
                        "failure_class": "data_integrity",
                    }),
                ));
            }
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({
                    "error": "Restore aborted: the prior configuration could not be snapshotted for rollback (database unavailable). Existing config was NOT deleted; retry once the database is reachable.",
                    "restore_errors": [format!("failed to snapshot prior config for rollback: {}", error)],
                    "failure_class": "connectivity",
                }),
            ));
        }
    };

    if let Err(error) = namespace_config_admission_guard.ensure_held() {
        return Ok(json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("Config admission unavailable: {error}")}),
        ));
    }

    // Phase 3 runs in an owned task. Its SQL/Mongo transactions, standalone
    // compensation, and rollback all settle before guard cleanup can release
    // durable ownership or unlock the next local writer.
    let persistence_db = db.clone();
    let persistence_actor = actor.clone();
    let persistence_audit_enabled = state.admin_audit_enabled;
    let persistence_namespace = namespace.to_string();
    let response = match namespace_config_admission_guard
        .run_persistence(async move {
            persist_restore_after_validation(
                persistence_db,
                persistence_audit_enabled,
                persistence_actor,
                persistence_namespace,
                payload,
                snapshot,
            )
            .await
        })
        .await
    {
        Ok(response) => response,
        Err(error) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": format!("Config admission unavailable: {error}")}),
        ),
    };

    Ok(response)
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

pub(in crate::admin) fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
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

fn redact_consumer_credentials_for_audit(consumer: &Consumer) -> Consumer {
    crate::config::types::redact_consumer_credentials_for_audit(consumer)
}

fn hash_consumer_secrets(
    consumer: &mut Consumer,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
    crate::config::types::hash_consumer_secrets(consumer)
}

/// Hash passwords in basicauth credential payloads where the credential type is known.
fn hash_credential_passwords(
    cred: &mut serde_json::Value,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
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
    fn consumer_unique_conflict_response_redacts_mongo_credential_metadata() {
        let secret = "must-not-escape-hmac-secret-at-least-32-characters";
        let error = anyhow::anyhow!(
            "E11000 duplicate key error dup key: {{ namespace: ferrum, credentials.hmac_auth.secret: {} }}",
            secret
        );

        let message = crud::consumer_persist_error_message(&error);
        assert!(message.contains("conflicts with another Consumer"));
        assert!(!message.contains(secret));
        assert!(!message.contains("credentials.hmac_auth.secret"));
    }

    #[test]
    fn namespace_scoped_routes_cover_tenant_resources_only() {
        // Tenant-scoped: subject to FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM.
        for segs in [
            vec!["proxies"],
            vec!["proxies", "p1"],
            vec!["consumers"],
            vec!["consumers", "c1", "credentials", "keyauth"],
            vec!["upstreams", "u1"],
            vec!["plugins", "config"],
            vec!["plugins", "config", "pc1"],
            vec!["api-specs"],
            vec!["api-specs", "s1"],
            vec!["batch"],
            vec!["backup"],
            vec!["restore"],
            vec!["audit"],
        ] {
            assert!(
                is_namespace_scoped_route(&segs),
                "/{} should be namespace-scoped",
                segs.join("/")
            );
        }

        // Global admin surfaces: never gated on the ns claim.
        for segs in [
            vec!["plugins"], // plugin *type* listing — global metadata
            vec!["namespaces"],
            vec!["cluster"],
            vec!["backend-capabilities"],
            vec!["metrics", "runtime"],
            vec!["admin", "tls", "inventory"],
            vec!["admin", "metrics"],
            vec!["mesh", "service-graph"],
            vec!["health"],
            vec!["overload"],
        ] {
            assert!(
                !is_namespace_scoped_route(&segs),
                "/{} should NOT be namespace-scoped",
                segs.join("/")
            );
        }
    }

    #[test]
    fn enforce_namespace_claim_rejects_missing_and_unlisted_namespaces() {
        use crate::grpc::auth::AllowedNamespaces;

        let actor = |allowed: AllowedNamespaces| AuditActor {
            sub: "tester".to_string(),
            role: AdminRole::Admin,
            allowed_namespaces: allowed,
        };

        // No claim → denied when enforcement is on.
        let denied =
            enforce_namespace_claim(&actor(AllowedNamespaces::empty()), "prod", "/proxies");
        assert_eq!(
            denied.map(|resp| resp.status()),
            Some(StatusCode::FORBIDDEN)
        );

        // Claimed namespace → allowed; unlisted → denied.
        let mut set = std::collections::HashSet::new();
        set.insert("staging".to_string());
        let scoped = AllowedNamespaces(Some(set));
        assert!(enforce_namespace_claim(&actor(scoped.clone()), "staging", "/proxies").is_none());
        let denied = enforce_namespace_claim(&actor(scoped), "prod", "/proxies");
        assert_eq!(
            denied.map(|resp| resp.status()),
            Some(StatusCode::FORBIDDEN)
        );

        // Present-but-empty claim (operator assigned no namespaces) denies all.
        let empty_set = AllowedNamespaces(Some(std::collections::HashSet::new()));
        let denied = enforce_namespace_claim(&actor(empty_set), "ferrum", "/proxies");
        assert_eq!(
            denied.map(|resp| resp.status()),
            Some(StatusCode::FORBIDDEN)
        );
    }

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
    fn parse_chargeback_format_requires_exact_format_parameter() {
        assert_eq!(
            parse_chargeback_format(Some("xformat=json")).expect("xformat must be ignored"),
            ChargebackFormat::Prometheus
        );
        assert_eq!(
            parse_chargeback_format(Some("format=json")).expect("json accepted"),
            ChargebackFormat::Json
        );
        assert!(
            parse_chargeback_format(Some("format=jsonish")).is_err(),
            "unsupported format values must be rejected"
        );
    }

    #[test]
    fn normalize_credential_set_accepts_object_or_object_array() {
        assert_eq!(
            normalize_credential_set(json!({"key": "one"})).unwrap(),
            json!([{"key": "one"}])
        );
        assert_eq!(
            normalize_credential_set(json!([{"key": "one"}, {"key": "two"}])).unwrap(),
            json!([{"key": "one"}, {"key": "two"}])
        );
        assert!(normalize_credential_set(json!([])).is_err());
        assert!(normalize_credential_set(json!(["not-object"])).is_err());
        assert!(normalize_credential_set(json!("not-object")).is_err());
    }

    #[test]
    fn tls_route_required_role_preserves_tls_security_boundary() {
        let operator_allowed = [
            (Method::GET, vec!["admin", "tls", "inventory"]),
            (Method::GET, vec!["admin", "tls", "events"]),
            (Method::GET, vec!["admin", "tls", "certificates"]),
            (
                Method::GET,
                vec!["admin", "tls", "certificates", "edge-cert"],
            ),
            (Method::POST, vec!["admin", "tls", "validate"]),
            (Method::POST, vec!["admin", "tls", "rotate", "backend_tls"]),
        ];
        for (method, route) in operator_allowed {
            assert_eq!(
                tls_route_required_role(&method, &route),
                Some(AdminRole::Operator),
                "{method} /{} should allow operator role",
                route.join("/")
            );
        }

        let admin_only = [
            (Method::POST, vec!["admin", "tls", "certificates"]),
            (
                Method::PUT,
                vec!["admin", "tls", "certificates", "edge-cert"],
            ),
            (
                Method::DELETE,
                vec!["admin", "tls", "certificates", "edge-cert"],
            ),
            (Method::POST, vec!["admin", "tls", "ca-bundles"]),
            (
                Method::PUT,
                vec!["admin", "tls", "ca-bundles", "internal-ca"],
            ),
            (
                Method::DELETE,
                vec!["admin", "tls", "ca-bundles", "internal-ca"],
            ),
            (Method::POST, vec!["admin", "tls", "crls"]),
            (Method::PUT, vec!["admin", "tls", "crls", "edge-crl"]),
            (Method::DELETE, vec!["admin", "tls", "crls", "edge-crl"]),
            (Method::POST, vec!["admin", "tls", "ocsp-responses"]),
            (
                Method::PUT,
                vec!["admin", "tls", "ocsp-responses", "edge-ocsp"],
            ),
            (
                Method::DELETE,
                vec!["admin", "tls", "ocsp-responses", "edge-ocsp"],
            ),
            (Method::POST, vec!["admin", "tls", "jwks"]),
            (Method::PUT, vec!["admin", "tls", "jwks", "edge-jwks"]),
            (Method::DELETE, vec!["admin", "tls", "jwks", "edge-jwks"]),
            (Method::POST, vec!["admin", "tls", "acme", "certificates"]),
            (
                Method::PUT,
                vec!["admin", "tls", "acme", "certificates", "edge-cert"],
            ),
            (
                Method::DELETE,
                vec!["admin", "tls", "acme", "certificates", "edge-cert"],
            ),
            (Method::POST, vec!["admin", "tls", "acme", "orders"]),
            (
                Method::POST,
                vec!["admin", "tls", "acme", "orders", "edge-order", "finalize"],
            ),
            (
                Method::DELETE,
                vec!["admin", "tls", "acme", "orders", "edge-order"],
            ),
            (
                Method::POST,
                vec!["admin", "tls", "acme", "renew", "edge-cert"],
            ),
        ];
        let operator = AuditActor {
            sub: "operator".to_string(),
            role: AdminRole::Operator,
            allowed_namespaces: crate::grpc::auth::AllowedNamespaces::empty(),
        };
        let admin = AuditActor {
            sub: "admin".to_string(),
            role: AdminRole::Admin,
            allowed_namespaces: crate::grpc::auth::AllowedNamespaces::empty(),
        };
        for (method, route) in admin_only {
            let required = tls_route_required_role(&method, &route);
            assert_eq!(
                required,
                Some(AdminRole::Admin),
                "{method} /{} should require admin role",
                route.join("/")
            );
            assert_eq!(
                require_admin_role(&operator, required.unwrap()).map(|response| response.status()),
                Some(StatusCode::FORBIDDEN),
                "operator must be forbidden for {method} /{}",
                route.join("/")
            );
            assert!(
                require_admin_role(&admin, required.unwrap()).is_none(),
                "admin must pass the role gate for {method} /{}",
                route.join("/")
            );
        }
    }

    #[test]
    fn tls_audit_descriptor_uses_acted_on_and_created_resource_ids() {
        let created = json!({"id": "generated-order"});
        let (_, _, create_id) = tls_mutation_audit_descriptor(
            &Method::POST,
            &["admin", "tls", "acme", "orders"],
            Some(&created),
        )
        .expect("ACME order create should be audited");
        assert_eq!(create_id, "generated-order");

        let (_, _, finalize_id) = tls_mutation_audit_descriptor(
            &Method::POST,
            &["admin", "tls", "acme", "orders", "edge-order", "finalize"],
            None,
        )
        .expect("ACME order finalize should be audited");
        assert_eq!(finalize_id, "edge-order");

        let rotated =
            json!({"accepted": true, "requested_surface": "frontend", "surface": "frontend_tls"});
        let (_, _, rotate_id) = tls_mutation_audit_descriptor(
            &Method::POST,
            &["admin", "tls", "rotate", "frontend"],
            Some(&rotated),
        )
        .expect("TLS rotation should be audited");
        assert_eq!(rotate_id, "frontend_tls");
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
