//! Control Plane mode — config broker with no proxy.
//!
//! The CP polls the database using the same incremental strategy as database
//! mode, but instead of proxying traffic, it broadcasts config deltas to
//! connected Data Planes and mesh nodes via dedicated tokio `broadcast`
//! channels → gRPC streams. On incremental poll failure, it falls back to a
//! full reload and broadcasts fresh snapshots to all subscribers.
//!
//! The admin API is read/write (same as database mode). The CP validates
//! DP client JWT tokens using `FERRUM_CP_DP_GRPC_JWT_SECRET` and enforces
//! `major.minor` version compatibility between CP and DP.

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tracing::{debug, error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::db_backend::{self, DatabaseBackend, FullConfigLoadPurpose, IncrementalResult};
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::config::incremental_apply::apply_incremental_to_config_snapshot as apply_incremental_to_config;
use crate::config::types::GatewayConfig;
use crate::config::validation_pipeline::{
    ConfigValidationRejection, collect_rejecting_runtime_config_errors,
};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::cp_server::{CpGrpcServer, CpScope};
use crate::grpc::mesh_registry::{
    MESH_NODE_REGISTRY_REAPER_INTERVAL, mesh_node_registry_stale_ttl,
};
use crate::grpc::mesh_server::MeshGrpcServer;
use crate::k8s_controller::{
    CpPublicationGate, K8sOverlaySlot, compose_db_with_k8s_overlay, empty_k8s_overlay_slot,
};
use crate::modes::file::ListenerJoinHandle;
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};
use crate::util::conn_limit::{ConnLimiter, ConnPermit};
use crate::xds::XdsAdsServer;

#[cfg(test)]
use crate::config::incremental_apply::upsert_by_id;

/// Stream of admitted CP gRPC connections handed to tonic's
/// `serve_with_incoming_shutdown`.
pub type CpGrpcIncomingStream =
    Pin<Box<dyn Stream<Item = Result<CpGrpcIo, std::io::Error>> + Send + 'static>>;

async fn reconcile_plugin_migrations_after_cp_reconnect(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    auto_apply: bool,
    needs_reconcile: &mut bool,
    context: &str,
) -> bool {
    if !*needs_reconcile {
        return true;
    }
    match crate::modes::handle_recovery_plugin_migrations(db, auto_apply, "cp-recovery").await {
        Ok(()) => {
            *needs_reconcile = false;
            true
        }
        Err(error) => {
            db_available.store(false, Ordering::Relaxed);
            warn!(
                "Control-plane custom-plugin migration reconciliation failed after {}: {}. \
                 Admin writes and recovered configuration publication remain blocked.",
                context, error
            );
            false
        }
    }
}

/// One admitted CP gRPC connection.
///
/// Each variant owns a [`ConnPermit`] from the shared CP gRPC
/// [`ConnLimiter`]. The permit is acquired in the accept loop *before* any
/// per-socket handshake work is allocated and is dropped with this value —
/// i.e. when tonic finishes with the connection — so one permit bounds the
/// pre-authentication handshake **and** the completed (possibly idle) HTTP/2
/// session. See [`run_cp_grpc_tls_accept_loop`].
///
/// Public so external regression tests can drive the listener; all fields
/// remain private.
pub enum CpGrpcIo {
    /// Plaintext connection (loopback or explicit `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT`).
    Plain(Box<CpGrpcPlainIo>),
    /// TLS/mTLS connection with a completed handshake.
    Tls(Box<CpGrpcTlsIo>),
}

/// Plaintext CP gRPC connection plus its admission permit.
pub struct CpGrpcPlainIo {
    inner: TcpStream,
    /// Released when this value drops; see [`CpGrpcIo`].
    _permit: ConnPermit,
}

/// TLS/mTLS CP gRPC connection plus its admission permit.
pub struct CpGrpcTlsIo {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    /// Released when this value drops; see [`CpGrpcIo`].
    _permit: ConnPermit,
}

impl AsyncRead for CpGrpcIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(&mut stream.inner).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for CpGrpcIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(&mut stream.inner).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(&mut stream.inner).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(&mut stream.inner).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_shutdown(cx),
        }
    }
}

impl Connected for CpGrpcIo {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            Self::Plain(stream) => TcpConnectInfo {
                local_addr: stream.inner.local_addr().ok(),
                remote_addr: stream.inner.peer_addr().ok(),
            },
            Self::Tls(stream) => TcpConnectInfo {
                local_addr: stream.local_addr,
                remote_addr: stream.remote_addr,
            },
        }
    }
}

/// Plaintext CP gRPC incoming stream, gated by the same shared
/// [`ConnLimiter`] as the TLS listener.
///
/// A plaintext socket allocates no handshake task, but tonic still holds one
/// connection (file descriptor + HTTP/2 state) per accepted socket for its
/// whole lifetime, so the same bound applies. Admission is non-blocking: a
/// refused socket is dropped and the stream continues, never stalling the
/// accept path.
pub fn cp_grpc_plain_incoming(
    listener: tokio::net::TcpListener,
    conn_limiter: Arc<ConnLimiter>,
) -> CpGrpcIncomingStream {
    let reject_log = Arc::new(std::sync::Mutex::new(
        crate::util::accept_backoff::LogRateLimiter::new(),
    ));
    let admitted = TcpListenerStream::new(listener).filter_map(move |accepted| {
        let conn_limiter = Arc::clone(&conn_limiter);
        let reject_log = Arc::clone(&reject_log);
        async move {
            let stream = match accepted {
                Ok(stream) => stream,
                // Surface accept errors to tonic unchanged.
                Err(error) => return Some(Err(error)),
            };
            // A socket whose peer address cannot be read cannot be accounted
            // per-IP; it is already broken, so fail closed.
            let Ok(remote_addr) = stream.peer_addr() else {
                debug!("Dropping CP gRPC connection: peer address unavailable");
                return None;
            };
            match conn_limiter.try_acquire(remote_addr.ip()) {
                Ok(permit) => Some(Ok(CpGrpcIo::Plain(Box::new(CpGrpcPlainIo {
                    inner: stream,
                    _permit: permit,
                })))),
                Err(reason) => {
                    log_cp_grpc_admission_rejection(&reject_log, remote_addr, reason);
                    // Dropping the socket closes it immediately.
                    None
                }
            }
        }
    });
    Box::pin(admitted)
}

/// TLS/mTLS CP gRPC incoming stream.
///
/// The accept loop runs in its own task and forwards completed handshakes over
/// a bounded channel; `conn_limiter` bounds how many sockets may be in that
/// pipeline at once. The limiter is created once per process and shared across
/// every certificate-reload generation (the cert rotates inside `tls_slot`, the
/// listener and limiter do not), so a reload cannot reset or duplicate the cap.
pub fn cp_grpc_tls_incoming(
    listener: tokio::net::TcpListener,
    tls_slot: crate::tls::SharedFrontendTls,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    handshake_timeout_seconds: u64,
    conn_limiter: Arc<ConnLimiter>,
) -> CpGrpcIncomingStream {
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(run_cp_grpc_tls_accept_loop(
        listener,
        tls_slot,
        shutdown_rx,
        handshake_timeout_seconds,
        tx,
        conn_limiter,
    ));
    Box::pin(ReceiverStream::new(rx))
}

/// Log one admission rejection, rate-limited to the first event plus a
/// per-second summary so a flood cannot itself become the DoS.
///
/// Only the source IP and a fixed rejection label are recorded — never
/// certificate material, JWTs, or any peer-supplied bytes (the peer is
/// unauthenticated and has sent nothing at this point).
fn log_cp_grpc_admission_rejection(
    reject_log: &std::sync::Mutex<crate::util::accept_backoff::LogRateLimiter>,
    remote_addr: SocketAddr,
    reason: crate::util::conn_limit::ConnRejectReason,
) {
    let suppressed = {
        let mut guard = match reject_log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.on_event(crate::socket_opts::monotonic_now_ms())
    };
    if let Some(suppressed) = suppressed {
        warn!(
            suppressed,
            remote_addr = %remote_addr.ip(),
            reason = reason.as_label(),
            "CP gRPC connection rejected: connection limit reached"
        );
    }
}

/// CP gRPC TLS accept loop with bounded pre-authentication admission
/// (advisory GHSA-2xqr-7j7p-77qp).
///
/// A permit is acquired from `conn_limiter` **before** the per-socket
/// handshake task is spawned. An unauthenticated client that opens sockets and
/// withholds the TLS ClientHello therefore cannot allocate tasks, TLS state
/// machines, or cloned server configurations beyond the configured bound: the
/// excess socket is dropped (closed) in the accept loop itself. Acquisition is
/// `try_acquire`, so a saturated limiter never blocks the accept loop — it
/// fails closed and keeps accepting so legitimate peers are served as soon as
/// permits free.
///
/// The permit moves into the spawned task and, on a successful handshake, into
/// the [`CpGrpcTlsIo`] handed to tonic — so one permit covers the handshake and
/// the served HTTP/2 session, and is released exactly once (RAII) on every exit
/// path: handshake error, handshake timeout, empty TLS slot, channel-send
/// failure, listener shutdown, or connection close.
///
/// `handshake_timeout_seconds`
/// (`FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`) is retained as defense in
/// depth: it retires slow handshakes so permits recycle, but it is not the
/// concurrency bound.
async fn run_cp_grpc_tls_accept_loop(
    listener: tokio::net::TcpListener,
    tls_slot: crate::tls::SharedFrontendTls,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    handshake_timeout_seconds: u64,
    tx: tokio::sync::mpsc::Sender<Result<CpGrpcIo, std::io::Error>>,
    conn_limiter: Arc<ConnLimiter>,
) {
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    let reject_log = std::sync::Mutex::new(crate::util::accept_backoff::LogRateLimiter::new());
    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
                        // Pre-authentication admission: bound the number of
                        // live handshakes before allocating any per-socket
                        // work. Over-limit sockets are closed here.
                        let permit = match conn_limiter.try_acquire(remote_addr.ip()) {
                            Ok(permit) => permit,
                            Err(reason) => {
                                log_cp_grpc_admission_rejection(&reject_log, remote_addr, reason);
                                drop(stream);
                                continue;
                            }
                        };
                        let tls_config = tls_slot.load().as_ref().clone();
                        let tx = tx.clone();
                        // `permit` is captured by this task and held for the
                        // handshake; on success it moves into the IO object so
                        // it also covers the served HTTP/2 session. Every other
                        // exit path drops it here, releasing the slot.
                        tokio::spawn(async move {
                            let Some(tls_config) = tls_config else {
                                debug!(
                                    remote_addr = %remote_addr.ip(),
                                    "Dropping CP gRPC TLS connection: TLS slot is empty"
                                );
                                drop(stream);
                                return;
                            };
                            let local_addr = stream.local_addr().ok();
                            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
                            match crate::tls::accept_with_optional_timeout(
                                &acceptor,
                                stream,
                                handshake_timeout_seconds,
                                &remote_addr,
                                false,
                            )
                            .await
                            {
                                Ok(inner) => {
                                    let io = CpGrpcIo::Tls(Box::new(CpGrpcTlsIo {
                                        inner,
                                        local_addr,
                                        remote_addr: Some(remote_addr),
                                        _permit: permit,
                                    }));
                                    let _ = tx.send(Ok(io)).await;
                                }
                                Err(error) => {
                                    debug!(
                                        remote_addr = %remote_addr.ip(),
                                        error = %error,
                                        "CP gRPC TLS handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(error) => {
                        // Bound the log rate independently of the backoff: an
                        // abort/reset flood is not backed off, so emit the
                        // first error then one summary per second with the
                        // suppressed count.
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            error!(error = %error, suppressed, "Failed to accept CP gRPC connection");
                        }
                        // Back off on a sustained fd-exhaustion run so accept()
                        // cannot busy-spin a core.
                        if let Some(delay) = accept_backoff.on_error(error.kind()) {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
        }
    }
}

/// Resolve which namespaces the CP polling loop should load on each tick.
///
/// `Single(ns)` / `Set({ns, ...})` return the explicit list directly; `All`
/// dynamically discovers namespaces from authoritative primary reads so the CP
/// picks up new tenants without a restart. Returns at least one namespace
/// — when `All` is configured but the database is empty, we still load the
/// gateway's `FERRUM_NAMESPACE` so the admin API works on a fresh cluster.
async fn resolve_polled_namespaces(
    db: &dyn DatabaseBackend,
    scope: &CpScope,
    fallback: &str,
    retain_on_success: &[String],
    previous_on_error: Option<&[String]>,
) -> Vec<String> {
    if let Some(explicit) = scope.explicit_namespaces() {
        return explicit;
    }
    // CpScope::All — discover dynamically.
    match db.list_namespaces_authoritative().await {
        Ok(ns) => merge_discovered_namespaces(ns, retain_on_success, fallback),
        Err(e) => {
            let retained = previous_on_error.unwrap_or(retain_on_success);
            let ns = normalize_namespace_list(retained);
            if !ns.is_empty() {
                warn!(
                    "CP scope=All: authoritative namespace discovery failed ({}); keeping previous {} namespace(s): [{}]",
                    e,
                    ns.len(),
                    ns.join(", ")
                );
                ns
            } else {
                warn!(
                    "CP scope=All: authoritative namespace discovery failed ({}); falling back to FERRUM_NAMESPACE='{}'",
                    e, fallback
                );
                vec![fallback.to_string()]
            }
        }
    }
}

fn merge_discovered_namespaces(
    discovered: Vec<String>,
    retain: &[String],
    fallback: &str,
) -> Vec<String> {
    let mut ns = normalize_namespace_list(&discovered);
    ns.extend(normalize_namespace_list(retain));
    ns.sort();
    ns.dedup();
    if ns.is_empty() {
        vec![fallback.to_string()]
    } else {
        ns
    }
}

fn normalize_namespace_list(namespaces: &[String]) -> Vec<String> {
    let mut ns: Vec<String> = namespaces
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    ns.sort();
    ns.dedup();
    ns
}

fn namespaces_referenced_by_config(config: &GatewayConfig) -> Vec<String> {
    let mut namespaces = Vec::new();
    namespaces.extend(config.known_namespaces.iter().cloned());
    namespaces.extend(config.proxies.iter().map(|p| p.namespace.clone()));
    namespaces.extend(config.consumers.iter().map(|c| c.namespace.clone()));
    namespaces.extend(config.plugin_configs.iter().map(|pc| pc.namespace.clone()));
    namespaces.extend(config.upstreams.iter().map(|u| u.namespace.clone()));
    normalize_namespace_list(&namespaces)
}

fn retained_polled_namespaces(config: &GatewayConfig) -> Vec<String> {
    namespaces_referenced_by_config(config)
}

/// Multi-namespace incremental poll. Calls `load_incremental_config` once
/// per namespace. Load failures for one namespace are isolated: other namespaces
/// continue and the failing namespace keeps its prior cursor (#2983).
///
/// Returns `Err` only when every namespace fails with a non-validation error
/// (connectivity / full-reload-required), so the poll loop can escalate to a
/// full fallback. A mix of successes and failures returns `Ok` with
/// `load_failures` populated.
async fn load_incremental_config_multi(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
    after_sequences: &HashMap<String, u64>,
) -> Result<IncrementalMultiLoad, anyhow::Error> {
    if namespaces.len() <= 1 {
        let ns = namespaces.first().map(|s| s.as_str()).unwrap_or("ferrum");
        let after_sequence = after_sequences.get(ns).copied().unwrap_or(0);
        let result = db.load_incremental_config(ns, after_sequence).await?;
        let mut next_sequences = HashMap::new();
        next_sequences.insert(ns.to_string(), result.sequence_cursor);
        return Ok(IncrementalMultiLoad {
            result,
            next_sequences,
            load_failures: Vec::new(),
        });
    }

    let mut next_sequences = HashMap::new();
    let mut load_failures = Vec::new();
    let mut combined = IncrementalResult {
        added_or_modified_proxies: Vec::new(),
        removed_proxy_ids: Vec::new(),
        added_or_modified_consumers: Vec::new(),
        removed_consumer_ids: Vec::new(),
        added_or_modified_plugin_configs: Vec::new(),
        removed_plugin_config_ids: Vec::new(),
        added_or_modified_upstreams: Vec::new(),
        removed_upstream_ids: Vec::new(),
        sequence_cursor: namespaces
            .iter()
            .filter_map(|ns| after_sequences.get(ns).copied())
            .max()
            .unwrap_or(0),
        poll_timestamp: chrono::Utc::now(),
    };
    let mut any_success = false;
    let mut last_hard_error: Option<anyhow::Error> = None;
    for ns in namespaces {
        let after_sequence = after_sequences.get(ns).copied().unwrap_or(0);
        match db.load_incremental_config(ns, after_sequence).await {
            Ok(mut delta) => {
                any_success = true;
                next_sequences.insert(ns.clone(), delta.sequence_cursor);
                combined
                    .added_or_modified_proxies
                    .append(&mut delta.added_or_modified_proxies);
                combined
                    .removed_proxy_ids
                    .append(&mut delta.removed_proxy_ids);
                combined
                    .added_or_modified_consumers
                    .append(&mut delta.added_or_modified_consumers);
                combined
                    .removed_consumer_ids
                    .append(&mut delta.removed_consumer_ids);
                combined
                    .added_or_modified_plugin_configs
                    .append(&mut delta.added_or_modified_plugin_configs);
                combined
                    .removed_plugin_config_ids
                    .append(&mut delta.removed_plugin_config_ids);
                combined
                    .added_or_modified_upstreams
                    .append(&mut delta.added_or_modified_upstreams);
                combined
                    .removed_upstream_ids
                    .append(&mut delta.removed_upstream_ids);
                combined.sequence_cursor = combined.sequence_cursor.max(delta.sequence_cursor);
                combined.poll_timestamp = combined.poll_timestamp.min(delta.poll_timestamp);
            }
            Err(error) => {
                // Consumer changes escalate to full reload for the whole CP —
                // credential rehydration is not safe to partition.
                if db_backend::is_incremental_full_reload_required(&error) {
                    return Err(error);
                }
                error!(
                    namespace = %ns,
                    error = %error,
                    "CP incremental load failed for namespace; keeping last-known-good cursor and continuing other namespaces"
                );
                load_failures.push((ns.clone(), error.to_string()));
                last_hard_error = Some(error);
            }
        }
    }
    if !any_success {
        return Err(last_hard_error.unwrap_or_else(|| {
            anyhow::anyhow!("CP incremental multi-namespace load failed for every namespace")
        }));
    }
    Ok(IncrementalMultiLoad {
        result: combined,
        next_sequences,
        load_failures,
    })
}

/// Outcome of a multi-namespace incremental load with per-namespace isolation.
///
/// Deliberately not `Debug`: `IncrementalResult` carries consumer credentials
/// and intentionally omits a `Debug` impl so it can never be formatted into a
/// log line.
struct IncrementalMultiLoad {
    result: IncrementalResult,
    /// Cursors only for namespaces whose load succeeded.
    next_sequences: HashMap<String, u64>,
    /// `(namespace, error)` for namespaces whose delta load failed outright
    /// (connectivity / decode). These keep their prior cursor and their
    /// last-known-good resources; they are NOT validation rejections.
    load_failures: Vec<(String, String)>,
}

/// Load and merge per-namespace `GatewayConfig`s into a single combined config.
///
/// The CP holds one in-memory `GatewayConfig` even when serving multiple
/// namespaces (so admin / observability paths still see the whole picture).
/// Per-DP broadcasts filter to a single namespace at send time, and the
/// DP-side namespace filter in `dp_client::filter_config_to_namespace` is a
/// defense-in-depth backstop.
///
/// Validation/decode failures for one namespace are isolated (#2983): the
/// failing namespace retains its last-known-good resources from `previous`,
/// other namespaces continue to refresh, and `rejected_namespaces` names the
/// failures for observability.
async fn load_full_config_multi(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
    previous: &GatewayConfig,
) -> Result<FullLoadMultiOutcome, anyhow::Error> {
    if namespaces.len() <= 1 {
        let ns = namespaces.first().map(|s| s.as_str()).unwrap_or("ferrum");
        let config = db
            .load_full_config_for_purpose(ns, FullConfigLoadPurpose::ControlPlane)
            .await?;
        let mut config = prepare_cp_full_snapshot(config)?;
        // `mesh` is owned by the K8s overlay slot, never by a DB snapshot; the
        // publication step re-merges it (#2982).
        config.mesh = None;
        return Ok(FullLoadMultiOutcome {
            config,
            rejected_namespaces: Vec::new(),
            refreshed_namespaces: vec![ns.to_string()],
            failed_namespaces: Vec::new(),
        });
    }

    let mut acc = MultiNsFullLoadAcc::new();
    let mut last_hard_error: Option<anyhow::Error> = None;

    for ns in namespaces {
        match db
            .load_full_config_for_purpose(ns, FullConfigLoadPurpose::ControlPlane)
            .await
        {
            Ok(raw) => match prepare_cp_full_snapshot(raw) {
                Ok(next) => {
                    acc.apply_success(ns, next);
                }
                Err(error) => {
                    error!(
                        namespace = %ns,
                        error = %error,
                        "CP full config rejected for namespace; retaining last-known-good resources"
                    );
                    acc.apply_rejected(previous, ns, error.to_string());
                }
            },
            Err(error) => {
                if crate::modes::is_poll_validation_rejection(&error) {
                    error!(
                        namespace = %ns,
                        error = %error,
                        "CP full config load rejected for namespace; retaining last-known-good resources"
                    );
                    acc.apply_rejected(previous, ns, error.to_string());
                } else {
                    error!(
                        namespace = %ns,
                        error = %error,
                        "CP full config load failed for namespace; retaining last-known-good resources"
                    );
                    acc.apply_failed(previous, ns);
                    last_hard_error = Some(error);
                }
            }
        }
    }

    acc.finish(previous, last_hard_error)
}

/// Pure accumulator for multi-namespace CP full loads. `load_full_config_multi`
/// feeds per-namespace outcomes here so stamp / LKG aggregation is unit-testable
/// without implementing `DatabaseBackend`.
///
/// Not `Debug`: the combined `GatewayConfig` carries consumer credentials.
struct MultiNsFullLoadAcc {
    combined: Option<GatewayConfig>,
    /// `loaded_at` of the first namespace that actually loaded. A published CP
    /// FULL_SNAPSHOT carries `ConfigUpdate.version = config.loaded_at`, which is
    /// the DP's monotonic ordering watermark and its cross-source staleness
    /// fence. When the first namespaces in the list fail, `combined` is seeded
    /// from `previous` — so without this the snapshot would be broadcast under
    /// the *already applied* stamp, leaving the DP watermark stuck behind
    /// content that did change. Taken from the load (not `Utc::now()`) so the
    /// stamp still precedes every query, preserving the full-load safety margin.
    fresh_loaded_at: Option<chrono::DateTime<chrono::Utc>>,
    rejected_namespaces: Vec<(String, String)>,
    refreshed_namespaces: Vec<String>,
    failed_namespaces: Vec<String>,
    any_success: bool,
}

impl MultiNsFullLoadAcc {
    fn new() -> Self {
        Self {
            combined: None,
            fresh_loaded_at: None,
            rejected_namespaces: Vec::new(),
            refreshed_namespaces: Vec::new(),
            failed_namespaces: Vec::new(),
            any_success: false,
        }
    }

    fn ensure_seeded(&mut self, previous: &GatewayConfig) -> &mut GatewayConfig {
        self.combined.get_or_insert_with(|| {
            // Seed metadata from the previous snapshot so trust_bundles /
            // version stay coherent while namespaced resources are rebuilt.
            let mut seed = previous.clone();
            clear_namespaced_resources(&mut seed);
            seed
        })
    }

    fn apply_success(&mut self, ns: &str, mut next: GatewayConfig) {
        self.any_success = true;
        self.refreshed_namespaces.push(ns.to_string());
        if self.fresh_loaded_at.is_none() {
            self.fresh_loaded_at = Some(next.loaded_at);
        }
        match &mut self.combined {
            None => self.combined = Some(next),
            Some(acc) => {
                acc.proxies.append(&mut next.proxies);
                acc.consumers.append(&mut next.consumers);
                acc.plugin_configs.append(&mut next.plugin_configs);
                acc.upstreams.append(&mut next.upstreams);
            }
        }
    }

    fn apply_rejected(&mut self, previous: &GatewayConfig, ns: &str, message: String) {
        self.rejected_namespaces.push((ns.to_string(), message));
        append_namespace_resources_from(self.ensure_seeded(previous), previous, ns);
    }

    fn apply_failed(&mut self, previous: &GatewayConfig, ns: &str) {
        self.failed_namespaces.push(ns.to_string());
        append_namespace_resources_from(self.ensure_seeded(previous), previous, ns);
    }

    fn finish(
        self,
        previous: &GatewayConfig,
        last_hard_error: Option<anyhow::Error>,
    ) -> Result<FullLoadMultiOutcome, anyhow::Error> {
        if !self.any_success {
            if !self.rejected_namespaces.is_empty() {
                // All namespaces failed validation — surface a typed rejection so
                // the poll loop raises config_rejected and keeps admin writable.
                let errors: Vec<String> = self
                    .rejected_namespaces
                    .iter()
                    .map(|(ns, msg)| format!("namespace '{ns}': {msg}"))
                    .collect();
                return Err(ConfigValidationRejection {
                    backend: "CP",
                    errors,
                }
                .into_anyhow());
            }
            return Err(last_hard_error.unwrap_or_else(|| {
                anyhow::anyhow!("CP full multi-namespace load failed for every namespace")
            }));
        }

        let mut config = self.combined.unwrap_or_else(|| previous.clone());
        // Stamp the snapshot with the first successful load's timestamp even when
        // the accumulator was seeded from `previous`, so the broadcast
        // `ConfigUpdate.version` advances with the content it describes.
        if let Some(loaded_at) = self.fresh_loaded_at {
            config.loaded_at = loaded_at;
        }
        // Preserve non-namespaced mesh overlay ownership: mesh comes from the
        // K8s overlay re-merge at publication time, not from DB full loads.
        config.mesh = None;
        Ok(FullLoadMultiOutcome {
            config,
            rejected_namespaces: self.rejected_namespaces,
            refreshed_namespaces: self.refreshed_namespaces,
            failed_namespaces: self.failed_namespaces,
        })
    }
}

/// Not `Debug`: `GatewayConfig` carries consumer credentials, so this outcome
/// must never be formattable into a log line.
struct FullLoadMultiOutcome {
    config: GatewayConfig,
    /// `(namespace, error)` for namespaces whose snapshot was REJECTED by the
    /// runtime validation contract (backend reachable, data invalid).
    rejected_namespaces: Vec<(String, String)>,
    /// Namespaces whose snapshot loaded and validated; only these advance a
    /// change-sequence cursor and only these are broadcast.
    refreshed_namespaces: Vec<String>,
    /// Namespaces whose snapshot load failed outright (connectivity / decode)
    /// rather than being rejected by validation.
    failed_namespaces: Vec<String>,
}

fn clear_namespaced_resources(config: &mut GatewayConfig) {
    config.proxies.clear();
    config.consumers.clear();
    config.plugin_configs.clear();
    config.upstreams.clear();
}

fn remove_namespace_resources(config: &mut GatewayConfig, namespace: &str) {
    config.proxies.retain(|p| p.namespace != namespace);
    config.consumers.retain(|c| c.namespace != namespace);
    config.plugin_configs.retain(|pc| pc.namespace != namespace);
    config.upstreams.retain(|u| u.namespace != namespace);
}

fn append_namespace_resources_from(
    target: &mut GatewayConfig,
    source: &GatewayConfig,
    namespace: &str,
) {
    target.proxies.extend(
        source
            .proxies
            .iter()
            .filter(|p| p.namespace == namespace)
            .cloned(),
    );
    target.consumers.extend(
        source
            .consumers
            .iter()
            .filter(|c| c.namespace == namespace)
            .cloned(),
    );
    target.plugin_configs.extend(
        source
            .plugin_configs
            .iter()
            .filter(|pc| pc.namespace == namespace)
            .cloned(),
    );
    target.upstreams.extend(
        source
            .upstreams
            .iter()
            .filter(|u| u.namespace == namespace)
            .cloned(),
    );
    if !target.known_namespaces.iter().any(|ns| ns == namespace) {
        target.known_namespaces.push(namespace.to_string());
    }
}

/// Replace one namespace's resources in `config` with the last-known-good copy
/// from `previous`. Used when a namespace loaded successfully but cannot be
/// published (e.g. its change-sequence cursor is unreadable): broadcasting is
/// skipped, so `config_arc` must not race ahead of what DPs still hold.
fn restore_namespace_last_known_good(
    config: &mut GatewayConfig,
    previous: &GatewayConfig,
    namespace: &str,
) {
    remove_namespace_resources(config, namespace);
    append_namespace_resources_from(config, previous, namespace);
}

async fn load_full_config_multi_with_sequence(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
    previous: &GatewayConfig,
) -> Result<(FullLoadMultiOutcome, HashMap<String, u64>), anyhow::Error> {
    let mut outcome = load_full_config_multi(db, namespaces, previous).await?;
    let mut sequences = HashMap::new();
    if namespaces.is_empty() {
        sequences.insert(
            "ferrum".to_string(),
            db.latest_change_sequence("ferrum").await?,
        );
    }
    // Only advance cursors for namespaces that successfully refreshed. A
    // cursor read that fails demotes just that namespace out of
    // `refreshed_namespaces` (it keeps its old cursor and is not broadcast);
    // it must not `?` and abort the reload for every other tenant (#2983).
    // The freshly loaded resources are also reverted to last-known-good so
    // `config_arc` / mesh full broadcasts cannot diverge from DPs that still
    // hold the prior snapshot for that tenant.
    let mut refreshed = Vec::with_capacity(outcome.refreshed_namespaces.len());
    for ns in std::mem::take(&mut outcome.refreshed_namespaces) {
        match db.latest_change_sequence(&ns).await {
            Ok(sequence) => {
                sequences.insert(ns.clone(), sequence);
                refreshed.push(ns);
            }
            Err(error) => {
                error!(
                    namespace = %ns,
                    error = %error,
                    "CP could not read the change-sequence cursor for namespace after a full \
                     reload; restoring last-known-good resources, leaving its cursor unchanged, \
                     and skipping its broadcast"
                );
                restore_namespace_last_known_good(&mut outcome.config, previous, &ns);
                outcome.failed_namespaces.push(ns);
            }
        }
    }
    outcome.refreshed_namespaces = refreshed;
    Ok((outcome, sequences))
}

/// CAS-publish a DB-authored snapshot after re-merging the independently owned
/// K8s overlay. Retries when a concurrent reconciler update lands in the
/// compose→store window (#2982 / #2984).
pub(crate) fn cas_publish_db_snapshot_with_k8s_overlay(
    config_arc: &ArcSwap<GatewayConfig>,
    overlay_slot: &K8sOverlaySlot,
    db_config: GatewayConfig,
) -> Arc<GatewayConfig> {
    let mut old_config = config_arc.load();
    loop {
        let composed = compose_db_with_k8s_overlay(&db_config, overlay_slot);
        let new_config = Arc::new(composed);
        let previous = config_arc.compare_and_swap(&*old_config, new_config.clone());
        if Arc::ptr_eq(&*old_config, &*previous) {
            return new_config;
        }
        old_config = previous;
    }
}

/// Apply per-namespace incremental partitions onto `base`, validating each
/// namespace independently so one invalid tenant cannot freeze the others
/// (#2983). Rejected namespaces keep their prior resources in the composed view.
///
/// Two-phase by design. The healthy path applies every partition to a single
/// candidate and runs the same combined rejecting contract the CP has always
/// used, so a normal poll tick still costs exactly one `GatewayConfig` clone.
/// Only when that combined view is rejected does the per-namespace isolation
/// pass run, which necessarily clones once per namespace.
pub(crate) fn compose_incremental_partitions(
    base: &GatewayConfig,
    partitions: &HashMap<String, IncrementalResult>,
) -> PartitionComposeOutcome {
    // Deterministic order for stable tests / logs.
    let mut namespaces: Vec<String> = partitions.keys().cloned().collect();
    namespaces.sort();

    // Scoped so the combined candidate is released before the isolation pass
    // starts cloning again.
    {
        let mut candidate = base.clone();
        for ns in &namespaces {
            if let Some(delta) = partitions.get(ns) {
                apply_incremental_to_config(&mut candidate, delta.clone());
            }
        }
        candidate.normalize_fields();
        candidate.resolve_upstream_tls();
        if collect_rejecting_cp_incremental_errors(&candidate, &namespaces).is_empty() {
            return PartitionComposeOutcome {
                config: candidate,
                accepted: partitions.clone(),
                rejected: Vec::new(),
            };
        }
    }

    // Isolation pass: a namespace's rejecting validators only ever read that
    // namespace's view, so applying one partition at a time and validating the
    // filtered view attributes the failure to the namespace that caused it.
    let mut working = base.clone();
    let mut accepted = HashMap::new();
    let mut rejected = Vec::new();
    for ns in &namespaces {
        let Some(delta) = partitions.get(ns) else {
            continue;
        };
        let mut candidate = working.clone();
        apply_incremental_to_config(&mut candidate, delta.clone());
        candidate.normalize_fields();
        candidate.resolve_upstream_tls();
        let namespace_view = CpGrpcServer::filter_config_to_namespace(&candidate, ns);
        let errors = collect_rejecting_runtime_config_errors(&namespace_view);
        if errors.is_empty() {
            working = candidate;
            accepted.insert(ns.clone(), delta.clone());
        } else {
            for message in &errors {
                error!(
                    namespace = %ns,
                    "CP incremental config rejected for namespace: {message}"
                );
            }
            rejected.push((ns.clone(), errors));
        }
    }

    PartitionComposeOutcome {
        config: working,
        accepted,
        rejected,
    }
}

/// Not `Debug`: holds `IncrementalResult` (consumer credentials) and a
/// `GatewayConfig`, neither of which may reach a log line.
pub(crate) struct PartitionComposeOutcome {
    pub config: GatewayConfig,
    pub accepted: HashMap<String, IncrementalResult>,
    pub rejected: Vec<(String, Vec<String>)>,
}

/// CAS-publish a composed incremental update. On CAS failure, re-compose from
/// the fresh base so a concurrent K8s reconciler overlay is not reverted
/// (#2984).
pub(crate) fn cas_publish_incremental_partitions(
    config_arc: &ArcSwap<GatewayConfig>,
    partitions: &HashMap<String, IncrementalResult>,
) -> PartitionComposeOutcome {
    let mut old_config = config_arc.load();
    loop {
        let outcome = compose_incremental_partitions(old_config.as_ref(), partitions);
        if outcome.accepted.is_empty() {
            return outcome;
        }
        let new_config = Arc::new(outcome.config.clone());
        let previous = config_arc.compare_and_swap(&*old_config, new_config);
        if Arc::ptr_eq(&*old_config, &*previous) {
            return outcome;
        }
        old_config = previous;
    }
}

fn merge_refreshed_change_sequences(
    last_change_sequences: &mut HashMap<String, u64>,
    refreshed: HashMap<String, u64>,
) {
    for (namespace, sequence) in refreshed {
        last_change_sequences.insert(namespace, sequence);
    }
}

/// Build the typed rejection marker for a set of per-namespace validation
/// rejections, or `None` when there are none.
///
/// Pure constructor: every caller already emits the per-namespace `error!`
/// line at the point of rejection, so this must not log again per poll tick.
fn namespace_rejection_error(rejected_namespaces: &[(String, String)]) -> Option<anyhow::Error> {
    if rejected_namespaces.is_empty() {
        return None;
    }
    let errors: Vec<String> = rejected_namespaces
        .iter()
        .map(|(namespace, message)| format!("namespace '{namespace}': {message}"))
        .collect();
    Some(
        ConfigValidationRejection {
            backend: "CP",
            errors,
        }
        .into_anyhow(),
    )
}

/// Settle the config-rejection signal after a CP full reload that may have
/// covered only some namespaces (#2983).
///
/// Only a reload that refreshed EVERY polled namespace may clear
/// `config_rejected` — issue #2158 keeps an accepted full reload as the single
/// clearing site precisely because it is the only thing that re-reads the whole
/// snapshot from the backend. A namespace rejected by validation raises the
/// typed rejection (backend reachable, admin stays writable for in-band
/// repair); a namespace whose load merely failed leaves any standing signal
/// untouched so a partial reload is never mistaken for proof of a clean
/// snapshot.
async fn settle_full_reload_rejection_state(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    config_rejected: &AtomicBool,
    rejected_namespaces: &[(String, String)],
    failed_namespaces: &[String],
    context: &str,
) {
    if let Some(rejection) = namespace_rejection_error(rejected_namespaces) {
        crate::modes::record_config_validation_rejection(
            db,
            db_available,
            config_rejected,
            &rejection,
            context,
        )
        .await;
        return;
    }
    if !failed_namespaces.is_empty() {
        warn!(
            context,
            failed_namespaces = %failed_namespaces.join(","),
            "CP full reload could not refresh every namespace; serving last-known-good for the \
             remainder and leaving any standing config-rejection signal in place"
        );
        return;
    }
    crate::modes::clear_config_rejected_after_accepted_full_reload(config_rejected, context);
}

/// Publish a DB full-reload snapshot with K8s overlay re-merge + CAS, then
/// broadcast only namespaces that successfully refreshed (#2982 / #2983 / #2984).
///
/// Commit and emissions run inside one [`CpPublicationGate`] section so a
/// concurrent K8s reconcile can neither observe a committed-but-unbroadcast
/// snapshot nor slip its own newer full snapshot in front of this one's
/// broadcasts.
///
/// When `refreshed_namespaces` is empty, nothing is committed or broadcast —
/// callers still settle rejection/failure state from the load outcome, and
/// subscribers keep last-known-good.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_cp_full_reload(
    publication_gate: &CpPublicationGate,
    config_arc: &ArcSwap<GatewayConfig>,
    overlay_slot: &K8sOverlaySlot,
    db_config: GatewayConfig,
    refreshed_namespaces: &[String],
    broadcasts: &crate::grpc::cp_server::NamespaceBroadcasts,
    dp_registry: &crate::grpc::cp_server::DpNodeRegistry,
    cp_scope: &CpScope,
    mesh_update_tx: &tokio::sync::broadcast::Sender<crate::grpc::mesh_server::MeshConfigBroadcast>,
    mesh_registry: &crate::grpc::mesh_registry::MeshNodeRegistry,
) {
    if refreshed_namespaces.is_empty() {
        return;
    }
    publication_gate.publish(move || {
        let published =
            cas_publish_db_snapshot_with_k8s_overlay(config_arc, overlay_slot, db_config);
        for namespace in refreshed_namespaces {
            CpGrpcServer::broadcast_namespace_update(
                broadcasts,
                namespace,
                published.as_ref(),
                dp_registry,
                cp_scope,
            );
        }
        MeshGrpcServer::broadcast_full_with_registry(mesh_update_tx, published, mesh_registry);
    });
}

/// Union of exactly the accepted per-namespace deltas.
///
/// Mesh subscribers are not namespace-partitioned, so they receive one merged
/// delta — never a rejected namespace's rows.
fn union_accepted_deltas(
    outcome: &PartitionComposeOutcome,
    sequence_cursor: u64,
    poll_timestamp: chrono::DateTime<chrono::Utc>,
) -> IncrementalResult {
    let mut union = IncrementalResult {
        added_or_modified_proxies: Vec::new(),
        removed_proxy_ids: Vec::new(),
        added_or_modified_consumers: Vec::new(),
        removed_consumer_ids: Vec::new(),
        added_or_modified_plugin_configs: Vec::new(),
        removed_plugin_config_ids: Vec::new(),
        added_or_modified_upstreams: Vec::new(),
        removed_upstream_ids: Vec::new(),
        sequence_cursor,
        poll_timestamp,
    };
    for delta in outcome.accepted.values() {
        let delta = delta.clone();
        union
            .added_or_modified_proxies
            .extend(delta.added_or_modified_proxies);
        union.removed_proxy_ids.extend(delta.removed_proxy_ids);
        union
            .added_or_modified_consumers
            .extend(delta.added_or_modified_consumers);
        union
            .removed_consumer_ids
            .extend(delta.removed_consumer_ids);
        union
            .added_or_modified_plugin_configs
            .extend(delta.added_or_modified_plugin_configs);
        union
            .removed_plugin_config_ids
            .extend(delta.removed_plugin_config_ids);
        union
            .added_or_modified_upstreams
            .extend(delta.added_or_modified_upstreams);
        union
            .removed_upstream_ids
            .extend(delta.removed_upstream_ids);
    }
    union
}

/// CAS-publish the accepted incremental partitions and emit their per-namespace
/// DP deltas plus the mesh union delta inside one [`CpPublicationGate`] section.
///
/// This is the dangerous half of the ordering problem: the commit here is a
/// *delta* while the reconciler's publication is a *full* snapshot. If a
/// reconciler full computed before this commit were emitted after these deltas,
/// subscribers would apply it last and silently erase the delta they had just
/// accepted, even though `config_arc` still contains it.
///
/// Emissions are skipped exactly when nothing was committed: an all-rejected
/// compose leaves the `ArcSwap` untouched, so there is no publication to order.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_cp_incremental(
    publication_gate: &CpPublicationGate,
    config_arc: &ArcSwap<GatewayConfig>,
    partitions: &HashMap<String, IncrementalResult>,
    version: &str,
    sequence_cursor: u64,
    poll_timestamp: chrono::DateTime<chrono::Utc>,
    broadcasts: &crate::grpc::cp_server::NamespaceBroadcasts,
    dp_registry: &crate::grpc::cp_server::DpNodeRegistry,
    cp_scope: &CpScope,
    mesh_update_tx: &tokio::sync::broadcast::Sender<crate::grpc::mesh_server::MeshConfigBroadcast>,
    mesh_registry: &crate::grpc::mesh_registry::MeshNodeRegistry,
) -> PartitionComposeOutcome {
    publication_gate.publish(|| {
        let outcome = cas_publish_incremental_partitions(config_arc, partitions);
        if outcome.accepted.is_empty() {
            return outcome;
        }

        // Broadcast only accepted partitions (#2983).
        for (namespace, namespace_delta) in &outcome.accepted {
            CpGrpcServer::broadcast_namespace_delta(
                broadcasts,
                namespace,
                namespace_delta,
                version,
                dp_registry,
                None,
                cp_scope,
            );
        }

        let mesh_delta = union_accepted_deltas(&outcome, sequence_cursor, poll_timestamp);
        MeshGrpcServer::broadcast_delta_with_registry(
            mesh_update_tx,
            mesh_delta,
            version,
            mesh_registry,
        );
        outcome
    })
}

fn prepare_cp_full_snapshot(mut config: GatewayConfig) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.resolve_upstream_tls();
    reject_invalid_cp_full_snapshot(&config)?;
    Ok(config)
}

fn reject_invalid_cp_full_snapshot(config: &GatewayConfig) -> Result<(), anyhow::Error> {
    let validation_errors = collect_rejecting_runtime_config_errors(config);
    if validation_errors.is_empty() {
        return Ok(());
    }

    for message in &validation_errors {
        error!("CP full config rejected: {}", message);
    }
    // Return the typed marker (not a bare `anyhow::bail!`) so the CP poll loop
    // can distinguish this reachable-but-invalid snapshot from a connectivity
    // failure and keep the admin API writable for in-band repair (issue #2158).
    Err(ConfigValidationRejection {
        backend: "CP",
        errors: validation_errors,
    }
    .into_anyhow())
}

/// Run the rejecting runtime validators with the same namespace boundaries as
/// CP full loads. The CP keeps a merged snapshot in memory, but configuration
/// uniqueness is defined per namespace.
fn collect_rejecting_cp_incremental_errors(
    config: &GatewayConfig,
    namespaces: &[String],
) -> Vec<String> {
    let mut validation_namespaces = namespaces.to_vec();
    validation_namespaces.extend(namespaces_referenced_by_config(config));
    let validation_namespaces = normalize_namespace_list(&validation_namespaces);
    if validation_namespaces.len() <= 1 {
        return collect_rejecting_runtime_config_errors(config);
    }

    let mut errors = Vec::new();
    for namespace in validation_namespaces {
        let namespace_config = CpGrpcServer::filter_config_to_namespace(config, &namespace);
        errors.extend(
            collect_rejecting_runtime_config_errors(&namespace_config)
                .into_iter()
                .map(|error| format!("namespace '{namespace}': {error}")),
        );
    }
    errors
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpRejectedDeltaDecision {
    consecutive: u64,
    should_escalate: bool,
}

/// Tracks repeated CP delta rejections so validator asymmetries cannot wedge
/// distribution indefinitely. Sequence maps identify the effective batch:
/// when new durable changes arrive, at least one namespace cursor changes and
/// the rejection count restarts.
struct CpRejectedDeltaTracker {
    rejected_sequences: Option<HashMap<String, u64>>,
    consecutive: u64,
    full_reload_threshold: u64,
}

impl CpRejectedDeltaTracker {
    fn new(full_reload_threshold: u64) -> Self {
        Self {
            rejected_sequences: None,
            consecutive: 0,
            full_reload_threshold: full_reload_threshold.max(1),
        }
    }

    fn record_rejection(
        &mut self,
        next_sequences: &HashMap<String, u64>,
    ) -> CpRejectedDeltaDecision {
        if self.rejected_sequences.as_ref() == Some(next_sequences) {
            self.consecutive = self.consecutive.saturating_add(1);
        } else {
            self.rejected_sequences = Some(next_sequences.clone());
            self.consecutive = 1;
        }

        CpRejectedDeltaDecision {
            consecutive: self.consecutive,
            should_escalate: self.consecutive >= self.full_reload_threshold
                && (self.consecutive - self.full_reload_threshold)
                    .is_multiple_of(self.full_reload_threshold),
        }
    }

    fn record_accepted(&mut self) {
        self.rejected_sequences = None;
        self.consecutive = 0;
    }
}

/// Partition an `IncrementalResult` by `namespace`, returning a delta for
/// each namespace that has at least one changed or removed resource.
///
/// Resources are matched by their `namespace` field. Removal keys carry
/// namespace end-to-end so deletions route without a pre-delete id lookup.
fn partition_incremental_by_namespace(
    result: IncrementalResult,
) -> std::collections::HashMap<String, IncrementalResult> {
    use std::collections::HashMap;

    let mut buckets: HashMap<String, IncrementalResult> = HashMap::new();
    let poll_timestamp = result.poll_timestamp;
    let sequence_cursor = result.sequence_cursor;

    let make_empty = |ts: chrono::DateTime<chrono::Utc>| IncrementalResult {
        added_or_modified_proxies: Vec::new(),
        removed_proxy_ids: Vec::new(),
        added_or_modified_consumers: Vec::new(),
        removed_consumer_ids: Vec::new(),
        added_or_modified_plugin_configs: Vec::new(),
        removed_plugin_config_ids: Vec::new(),
        added_or_modified_upstreams: Vec::new(),
        removed_upstream_ids: Vec::new(),
        sequence_cursor,
        poll_timestamp: ts,
    };

    for p in result.added_or_modified_proxies {
        buckets
            .entry(p.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .added_or_modified_proxies
            .push(p);
    }
    for c in result.added_or_modified_consumers {
        buckets
            .entry(c.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .added_or_modified_consumers
            .push(c);
    }
    for pc in result.added_or_modified_plugin_configs {
        buckets
            .entry(pc.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .added_or_modified_plugin_configs
            .push(pc);
    }
    for u in result.added_or_modified_upstreams {
        buckets
            .entry(u.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .added_or_modified_upstreams
            .push(u);
    }
    for key in result.removed_proxy_ids {
        buckets
            .entry(key.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .removed_proxy_ids
            .push(key);
    }
    for key in result.removed_consumer_ids {
        buckets
            .entry(key.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .removed_consumer_ids
            .push(key);
    }
    for key in result.removed_plugin_config_ids {
        buckets
            .entry(key.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .removed_plugin_config_ids
            .push(key);
    }
    for key in result.removed_upstream_ids {
        buckets
            .entry(key.namespace.clone())
            .or_insert_with(|| make_empty(poll_timestamp))
            .removed_upstream_ids
            .push(key);
    }

    buckets
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let failover_urls = env_config
        .effective_db_failover_urls()
        .map_err(anyhow::Error::msg)?;
    let effective_replica_url = env_config
        .effective_db_read_replica_url()
        .map_err(anyhow::Error::msg)?;
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    // Build the database backend — SQL (sqlx) or MongoDB depending on FERRUM_DB_TYPE
    let db: Box<dyn DatabaseBackend> = match db_type {
        "mongodb" => {
            let mut store = crate::config::mongo_store::MongoStore::connect_with_failover(
                &effective_url,
                &env_config.mongo_database,
                env_config.mongo_app_name.as_deref(),
                env_config.mongo_replica_set.as_deref(),
                env_config.mongo_auth_mechanism.as_deref(),
                env_config.mongo_server_selection_timeout_seconds,
                env_config.mongo_connect_timeout_seconds,
                env_config.db_tls_enabled(),
                env_config.db_tls_ca_cert_path.as_deref(),
                env_config.db_tls_client_cert_path.as_deref(),
                env_config.db_tls_client_key_path.as_deref(),
                env_config.mongodb_tls_allows_invalid_certs(),
                &failover_urls,
            )
            .await?;
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_full_load_page_size(env_config.db_full_load_page_size);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());
            let retention_policy = crate::admin::audit::AuditRetentionPolicy {
                retention_days: env_config.audit_retention_days,
                max_rows_per_namespace: env_config.audit_retention_max_rows,
            };
            retention_policy.log_if_enabled();
            store.set_audit_retention_policy(retention_policy);
            store.run_migrations().await?;
            Box::new(store)
        }
        _ => {
            let pool_config = DbPoolConfig {
                max_connections: env_config.db_pool_max_connections,
                min_connections: env_config.db_pool_min_connections,
                acquire_timeout_seconds: env_config.db_pool_acquire_timeout_seconds,
                idle_timeout_seconds: env_config.db_pool_idle_timeout_seconds,
                max_lifetime_seconds: env_config.db_pool_max_lifetime_seconds,
                connect_timeout_seconds: env_config.db_pool_connect_timeout_seconds,
                statement_timeout_seconds: env_config.db_pool_statement_timeout_seconds,
            };
            let mut store = DatabaseStore::connect_with_failover(
                db_type,
                &effective_url,
                &failover_urls,
                pool_config,
            )
            .await?;
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_full_load_page_size(env_config.db_full_load_page_size);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());
            let retention_policy = crate::admin::audit::AuditRetentionPolicy {
                retention_days: env_config.audit_retention_days,
                max_rows_per_namespace: env_config.audit_retention_max_rows,
            };
            retention_policy.log_if_enabled();
            store.set_audit_retention_policy(retention_policy);

            if let Some(ref replica_url) = effective_replica_url {
                match store.connect_read_replica(replica_url).await {
                    Ok(()) if store.read_replica_suppressed() => {
                        info!("Read replica configured but suppressed until primary failback")
                    }
                    Ok(()) => info!("Read replica connected for admin reads"),
                    Err(e) => {
                        let safe_error = db_backend::redact_error_text(&e, &[replica_url]);
                        warn!(
                            "Read replica connection failed for {}; admin reads will use primary until reconnect succeeds: {}",
                            db_backend::redact_url(replica_url),
                            safe_error
                        );
                    }
                }
            }
            Box::new(store)
        }
    };
    let db: Arc<dyn DatabaseBackend> = Arc::from(db);
    let db_tls_reload_handle = crate::modes::db_tls_reload::start_db_tls_reload_task(
        env_config.clone(),
        db.clone(),
        Some(shutdown_tx.subscribe()),
    );

    // Custom-plugin migrations: warn on pending, opt-in auto-apply.
    crate::modes::handle_startup_plugin_migrations(
        &db,
        env_config.auto_apply_plugin_migrations,
        "cp",
    )
    .await?;

    // Resolve the CP's namespace scope. Empty `FERRUM_CP_NAMESPACES` keeps
    // the pre-T2-A single-namespace behavior; `*` makes the CP cluster-wide;
    // a CSV pins it to an explicit set. The scope determines which DPs may
    // subscribe AND which namespaces the polling loop loads from the DB.
    let cp_scope = CpScope::from_env(&env_config.cp_namespaces, &env_config.namespace);
    info!("CP mode: serving {}", cp_scope.describe());
    if cp_scope.namespace_claim_required(env_config.cp_require_namespace_claim) {
        info!(
            "CP namespace authorization requires JWT `ns` claims for ConfigSync, MeshConfigSync, and xDS streams"
        );
    }

    // Discover the initial namespace list. For `Single`/`Set` this is the
    // explicit set; for `All` we query the DB and re-discover on every poll
    // cycle so newly created namespaces are picked up automatically.
    let polled_namespaces =
        resolve_polled_namespaces(db.as_ref(), &cp_scope, &env_config.namespace, &[], None).await;
    if matches!(cp_scope, CpScope::All) {
        info!(
            "CP scope=All: discovered {} namespace(s) at startup: [{}]",
            polled_namespaces.len(),
            polled_namespaces.join(", ")
        );
    }

    let empty_previous = GatewayConfig::default();
    let (full_load, initial_change_sequences) =
        load_full_config_multi_with_sequence(db.as_ref(), &polled_namespaces, &empty_previous)
            .await?;
    // Startup fails CLOSED. Per-namespace isolation (#2983) exists so a broken
    // tenant cannot freeze *distribution of a last-known-good snapshot* for the
    // others — at startup there is no last-known-good snapshot, so a namespace
    // that did not load would be published as an EMPTY tenant: every route 404s
    // and mesh subscribers see zero AuthorizationPolicies (mesh_authz allows
    // when no ALLOW rules exist). Refuse to start instead.
    if !full_load.rejected_namespaces.is_empty() || !full_load.failed_namespaces.is_empty() {
        let mut details: Vec<String> = full_load
            .rejected_namespaces
            .iter()
            .map(|(namespace, message)| format!("namespace '{namespace}' rejected: {message}"))
            .collect();
        details.extend(
            full_load
                .failed_namespaces
                .iter()
                .map(|namespace| format!("namespace '{namespace}': initial full load failed")),
        );
        anyhow::bail!(
            "CP startup aborted: {} of {} namespace(s) failed the initial full config load, and \
             there is no last-known-good snapshot to serve them from: {}",
            details.len(),
            polled_namespaces.len().max(1),
            details.join("; ")
        );
    }
    let config = full_load.config;
    info!(
        "CP mode: loaded {} proxies, {} consumers, {} plugins, {} upstreams across {} namespace(s)",
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len(),
        config.upstreams.len(),
        polled_namespaces.len(),
    );

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    // Independently owned K8s overlay slot shared by the reconciler (writer)
    // and the DB poll loop (reader/composer). Empty until the first accepted
    // reconcile; full DB reloads re-merge through this slot (#2982).
    let k8s_overlay_slot = empty_k8s_overlay_slot();
    // Shared by the two CP config writers (DB poll loop + K8s reconciler) so
    // commit order and DP/mesh broadcast order are the same order.
    let publication_gate = CpPublicationGate::new();
    crate::runtime_metrics::global().configure(
        env_config.status_counts_max_entries,
        env_config.runtime_metrics_pool_tracking_enabled,
        env_config.runtime_metrics_status_tracking_enabled,
        env_config.runtime_metrics_cache_ttl_ms,
    );

    let grpc_secret = match env_config.cp_dp_grpc_jwt_secret.clone() {
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            return Err(anyhow::anyhow!(
                "FERRUM_CP_DP_GRPC_JWT_SECRET must be set and non-empty in control plane mode. \
                 Without it, any client can forge valid gRPC authentication tokens."
            ));
        }
    };

    // Create gRPC server with shared DP node registry. The expected JWT
    // issuer and namespace are threaded in from EnvConfig: DPs must mint
    // tokens with the same `iss` value and advertise the same namespace, or
    // the CP rejects them before streaming any config.
    let dp_registry = Arc::new(crate::grpc::cp_server::DpNodeRegistry::new());
    let mesh_registry = Arc::new(crate::grpc::mesh_registry::MeshNodeRegistry::new());
    let (grpc_server, update_tx) = CpGrpcServer::builder(config_arc.clone(), grpc_secret.clone())
        .channel_capacity(env_config.cp_broadcast_channel_capacity)
        .registry(dp_registry.clone())
        .expected_issuer(env_config.cp_dp_grpc_jwt_issuer.clone())
        .scope(cp_scope.clone())
        .require_ns_claim(env_config.cp_require_namespace_claim)
        .real_ip_header(env_config.real_ip_header.clone())
        .build();
    let broadcasts = grpc_server.broadcasts();
    let (mesh_grpc_server, mesh_update_tx) =
        MeshGrpcServer::builder(config_arc.clone(), grpc_secret.clone())
            .channel_capacity(env_config.cp_broadcast_channel_capacity)
            .registry(mesh_registry.clone())
            .expected_issuer(env_config.cp_dp_grpc_jwt_issuer.clone())
            .namespace(env_config.namespace.clone())
            .scope(cp_scope.clone())
            .require_ns_claim(env_config.cp_require_namespace_claim)
            .sidecar_enforced(env_config.mesh_sidecar_enforced)
            .sidecar_enforced_dry_run(env_config.mesh_sidecar_enforced_dry_run)
            .sidecar_identity_narrowing(env_config.mesh_sidecar_identity_narrowing)
            .cluster_domain(env_config.k8s_cluster_domain.clone())
            .build();
    let xds_server = if env_config.xds_enabled {
        info!("FERRUM_XDS_ENABLED=true — mounting xDS ADS on the CP gRPC listener");
        Some(
            XdsAdsServer::with_sidecar_enforcement(
                config_arc.clone(),
                update_tx.clone(),
                grpc_secret,
                env_config.cp_dp_grpc_jwt_issuer.clone(),
                env_config.namespace.clone(),
                env_config.xds_stream_channel_capacity,
                env_config.mesh_sidecar_enforced,
            )
            .with_sidecar_enforcement_dry_run(env_config.mesh_sidecar_enforced_dry_run)
            .with_sidecar_identity_narrowing(env_config.mesh_sidecar_identity_narrowing)
            .with_cluster_domain(env_config.k8s_cluster_domain.clone())
            .with_scope(cp_scope.clone())
            .with_require_namespace_claim(env_config.cp_require_namespace_claim)
            .with_namespace_broadcasts(broadcasts.clone())
            .with_max_streams_per_node(env_config.xds_max_streams_per_node),
        )
    } else {
        None
    };

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(
            &env_config.admin_allowed_cidrs,
            "FERRUM_ADMIN_ALLOWED_CIDRS",
        )
        .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );
    let metrics_auth = Arc::new(
        crate::admin::MetricsAuthPolicy::from_env(&env_config).map_err(|e| anyhow::anyhow!(e))?,
    );

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers.
    let startup_ready = Arc::new(AtomicBool::new(false));
    // Sticky serving-degradation flag: set true (never unset) if the gRPC serve
    // future exits with an error after startup. `/health` reports not-ready when
    // this is set OR `startup_ready` is false, so a serve failure that lands
    // between the gRPC start signal and the main task's `startup_ready.store(true)`
    // below is not re-masked by that store.
    let serving_degraded = Arc::new(AtomicBool::new(false));
    let db_available = Arc::new(AtomicBool::new(true));
    // Raised by the poll loop when a full config load is rejected by the
    // runtime-config validation contract (reachable backend, invalid snapshot).
    // Distinct from `db_available`: the CP is a writer, so admin stays writable
    // to repair the offending resource in-band (issue #2158). Cleared only by an
    // accepted authoritative full reload. CP startup fails fast on an invalid
    // initial snapshot, so this starts `false`.
    let config_rejected = Arc::new(AtomicBool::new(false));

    let reserved_ports = env_config.reserved_gateway_ports();
    // Shared admin connection limiter (plaintext + HTTPS listeners share one
    // management-plane cap, independent of the data-plane FERRUM_MAX_CONNECTIONS).
    let admin_conn_limiter = Arc::new(admin::AdminConnLimiter::new(
        env_config.admin_max_connections,
        env_config.admin_max_connections_per_ip,
    ));
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(config_arc.clone()),
        proxy_state: None,
        mode: "cp".into(),
        read_only: env_config.admin_read_only,
        admin_audit_enabled: env_config.admin_audit_enabled,
        admin_require_namespace_claim: env_config.admin_require_namespace_claim,
        startup_ready: Some(startup_ready.clone()),
        serving_degraded: Some(serving_degraded.clone()),
        serving_listener_failures: None,
        db_available: Some(db_available.clone()),
        config_rejected: Some(config_rejected.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        metrics_auth: metrics_auth.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: Some(dp_registry.clone()),
        mesh_registry: Some(mesh_registry.clone()),
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        admin_request_limits: crate::admin::AdminRequestLimits::from_env_config(&env_config),
        backend_allow_ips: env_config.backend_allow_ips.clone(),
    };
    // Clone admin_state before the HTTP listener moves it, so we can reuse
    // the same JwtManager instance for the HTTPS listener (instead of calling
    // create_jwt_manager_from_env() a second time).
    let admin_state_for_https = admin_state.clone();
    let admin_shutdown = shutdown_tx.subscribe();
    let mut startup_signals = Vec::new();

    // Admin HTTP listener (disabled when port is 0)
    let admin_http_handle = if env_config.admin_http_port != 0 {
        let admin_http_limiter = admin_conn_limiter.clone();
        let (admin_http_started_tx, admin_http_started_rx) = tokio::sync::oneshot::channel();
        startup_signals.push(("CP admin HTTP listener".to_string(), admin_http_started_rx));
        let admin_http_startup_ready = startup_ready.clone();
        let admin_http_serving_degraded = serving_degraded.clone();
        Some(tokio::spawn(async move {
            info!(
                "Starting Admin HTTP listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTP_PORT",
                    &admin_http_addr.to_string()
                )
            );
            match admin::start_admin_listener_with_tls_and_signal(
                admin_http_addr,
                admin_state,
                admin_shutdown,
                None,
                Some(admin_http_started_tx),
                admin_http_limiter,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(e) => {
                    crate::startup::flip_ready_off_on_listener_failure(
                        &admin_http_startup_ready,
                        &admin_http_serving_degraded,
                        "CP admin HTTP listener",
                        &e,
                    );
                    Err(e.context("CP admin HTTP listener failed"))
                }
            }
        }))
    } else {
        info!(
            "{} — plaintext admin HTTP listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0")
        );
        None
    };

    // Admin HTTPS listener (only if TLS is configured and the port is not
    // disabled — port 0 is the repository-wide disable sentinel).
    let admin_https_handle = if env_config.admin_https_port == 0 {
        info!(
            "{} — admin HTTPS listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTPS_PORT", "0")
        );
        None
    } else if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_https_shutdown = shutdown_tx.subscribe();

        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth_and_ocsp(
            admin_cert_path,
            admin_key_path,
            admin_client_ca_bundle,
            env_config.admin_tls_ocsp_response_source.as_deref(),
            env_config.admin_tls_no_verify,
            &tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(config) => {
                if admin_client_ca_bundle.is_some() {
                    info!(
                        "Admin TLS configuration loaded with client certificate verification (HTTPS with mTLS available)"
                    );
                } else if env_config.admin_tls_no_verify {
                    warn!(
                        "Admin TLS configuration loaded with certificate verification DISABLED (testing mode)"
                    );
                } else {
                    info!(
                        "Admin TLS configuration loaded without client certificate verification (HTTPS available)"
                    );
                }
                config
            }
            Err(e) => {
                error!("Failed to load admin TLS configuration: {}", e);
                return Err(anyhow::anyhow!("Invalid admin TLS configuration: {}", e));
            }
        };

        let admin_reload_handles = crate::modes::tls_reload::prepare_admin_frontend_tls(
            admin_tls_config.clone(),
            &env_config,
            &tls_policy,
            &crls,
            Some(shutdown_tx.subscribe()),
        );
        if admin_reload_handles.watcher_handle.is_some() {
            info!("Frontend TLS live reload enabled for CP admin HTTPS");
        }
        let admin_tls_slot = admin_reload_handles.slot.clone();
        let admin_https_limiter = admin_conn_limiter.clone();
        let (admin_https_started_tx, admin_https_started_rx) = tokio::sync::oneshot::channel();
        startup_signals.push((
            "CP admin HTTPS listener".to_string(),
            admin_https_started_rx,
        ));
        let admin_https_startup_ready = startup_ready.clone();
        let admin_https_serving_degraded = serving_degraded.clone();

        Some(tokio::spawn(async move {
            info!(
                "Starting Admin HTTPS listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTPS_PORT",
                    &admin_https_addr.to_string()
                )
            );
            let result = if let Some(slot) = admin_tls_slot {
                admin::start_admin_listener_with_dynamic_tls_and_signal(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    slot,
                    Some(admin_https_started_tx),
                    admin_https_limiter,
                )
                .await
            } else {
                admin::start_admin_listener_with_tls_and_signal(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    Some(admin_tls_config),
                    Some(admin_https_started_tx),
                    admin_https_limiter,
                )
                .await
            };
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    crate::startup::flip_ready_off_on_listener_failure(
                        &admin_https_startup_ready,
                        &admin_https_serving_degraded,
                        "CP admin HTTPS listener",
                        &e,
                    );
                    Err(e.context("CP admin HTTPS listener failed"))
                }
            }
        }))
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
        None
    };
    if env_config.admin_http_port == 0 && !env_config.admin_https_listener_enabled() {
        warn!(
            "No admin API listeners are active — {} and admin HTTPS not configured or {}. The admin API is unreachable.",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0"),
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTPS_PORT", "0")
        );
    }

    // gRPC listener (with optional TLS/mTLS, disabled when port is 0).
    // Resolution is shared with EnvConfig::validate() so the secure-by-default
    // plaintext gate (validate_cp_dp_grpc_transport_security) reasons about the
    // exact address this binds.
    let grpc_addr: SocketAddr = env_config
        .cp_grpc_socket_addr()
        .map_err(anyhow::Error::msg)?;

    let grpc_handle = if grpc_addr.port() != 0 {
        // Pre-authentication admission for the CP gRPC listener (advisory
        // GHSA-2xqr-7j7p-77qp). Built once here and shared by the plaintext
        // listener, the TLS/mTLS accept loop, and every certificate-reload
        // generation, so the cap is a property of the CP gRPC surface rather
        // than of one listener instance or one certificate.
        let grpc_conn_limiter = Arc::new(ConnLimiter::new(
            env_config.cp_grpc_max_connections,
            env_config.cp_grpc_max_connections_per_ip,
        ));
        crate::plugins::prometheus_metrics::global_registry()
            .set_cp_grpc_conn_metrics(Arc::clone(&grpc_conn_limiter));
        if env_config.cp_grpc_max_connections == 0 {
            warn!(
                "SECURITY: {} disables the CP gRPC connection cap — an unauthenticated client can \
                 open sockets and withhold the TLS ClientHello until the process runs out of file \
                 descriptors. Set a positive bound in production.",
                crate::secrets::report_env_assignment("FERRUM_CP_GRPC_MAX_CONNECTIONS", "0")
            );
        } else {
            info!(
                max_connections = env_config.cp_grpc_max_connections,
                max_connections_per_ip = env_config.cp_grpc_max_connections_per_ip,
                "CP gRPC pre-authentication connection admission enabled"
            );
        }
        let grpc_tls_slot = if let (Some(_cert_path), Some(_key_path)) = (
            &env_config.cp_grpc_tls_cert_path,
            &env_config.cp_grpc_tls_key_path,
        ) {
            let tls_config = crate::modes::grpc_tls_reload::build_cp_grpc_server_tls_config(
                &env_config,
                &tls_policy,
                &crls,
            )
            .map_err(|e| anyhow::anyhow!("Invalid CP gRPC TLS configuration: {e}"))?;
            let reload_handles = crate::modes::grpc_tls_reload::prepare_cp_grpc_server_tls_reload(
                tls_config,
                Arc::new(env_config.clone()),
                tls_policy.clone(),
                crls.clone(),
                Some(shutdown_tx.subscribe()),
            );

            if reload_handles.watcher_handle.is_some() {
                info!("CP gRPC TLS live reload enabled");
            }
            if env_config.cp_grpc_tls_client_ca_path.is_some() {
                info!("CP gRPC TLS configured with mTLS; new handshakes use the active TLS slot");
            } else {
                warn!(
                    "SECURITY: CP gRPC TLS is configured WITHOUT client certificate verification \
                     (no FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH) — the only thing authenticating a Data \
                     Plane is its bearer JWT. Configure FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH to require \
                     DP client certificates (mTLS) for certificate-based DP identity in production."
                );
            }
            Some(reload_handles.slot)
        } else {
            if env_config.cp_grpc_tls_client_ca_path.is_some() {
                warn!(
                    "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH is set but cert/key are missing — ignoring client CA"
                );
            }
            // EnvConfig::validate() has already refused a non-loopback plaintext
            // bind unless FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true, so reaching here
            // means either a loopback bind or an explicit operator opt-in. Either
            // way, surface a high-severity warning — DP JWTs and the full gateway
            // config travel unencrypted.
            let grpc_addr_shown = crate::secrets::report_env_field(
                "FERRUM_CP_GRPC_LISTEN_ADDR",
                &grpc_addr.to_string(),
            );
            if grpc_addr.ip().is_loopback() {
                warn!(
                    "SECURITY: CP gRPC config sync is running in PLAINTEXT on loopback {grpc_addr_shown} \
                     — acceptable for local development only. DP authentication JWTs and the full \
                     gateway configuration are unencrypted. Configure FERRUM_CP_GRPC_TLS_CERT_PATH \
                     + FERRUM_CP_GRPC_TLS_KEY_PATH before exposing this CP off-host."
                );
            } else {
                warn!(
                    "SECURITY: CP gRPC config sync is running in PLAINTEXT on non-loopback \
                     {grpc_addr_shown} because FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true is set. DP \
                     authentication JWTs and the full gateway configuration are exposed UNENCRYPTED \
                     to the network and unprotected against MITM. Use TLS \
                     (FERRUM_CP_GRPC_TLS_CERT_PATH + FERRUM_CP_GRPC_TLS_KEY_PATH) in production."
                );
            }
            None
        };

        let grpc_listener = tokio::net::TcpListener::bind(grpc_addr).await?;
        info!(
            "CP gRPC server listening on {}",
            crate::secrets::report_env_field("FERRUM_CP_GRPC_LISTEN_ADDR", &grpc_addr.to_string())
        );
        let grpc_http2_max_concurrent_streams = env_config.server_http2_max_concurrent_streams;
        let grpc_http2_max_pending_accept_reset_streams =
            env_config.server_http2_max_pending_accept_reset_streams;
        let grpc_http2_max_local_error_reset_streams =
            env_config.server_http2_max_local_error_reset_streams;
        let (grpc_started_tx, grpc_started_rx) = tokio::sync::oneshot::channel();
        startup_signals.push(("CP gRPC listener".to_string(), grpc_started_rx));
        let mut grpc_shutdown = shutdown_tx.subscribe();
        let grpc_accept_shutdown = grpc_shutdown.clone();
        let grpc_tls_handshake_timeout_seconds = env_config.frontend_tls_handshake_timeout_seconds;
        let grpc_startup_ready = startup_ready.clone();
        let grpc_serving_degraded = serving_degraded.clone();
        let handle = tokio::spawn(async move {
            let mut builder = Server::builder()
                .max_concurrent_streams(Some(grpc_http2_max_concurrent_streams))
                .http2_max_pending_accept_reset_streams(Some(
                    grpc_http2_max_pending_accept_reset_streams,
                ))
                .http2_max_local_error_reset_streams(Some(grpc_http2_max_local_error_reset_streams))
                .http2_keepalive_interval(Some(std::time::Duration::from_secs(
                    crate::grpc::configsync_lifecycle::CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
                )))
                .http2_keepalive_timeout(Some(std::time::Duration::from_secs(
                    crate::grpc::configsync_lifecycle::CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS,
                )));
            let shutdown_signal = async move {
                while !*grpc_shutdown.borrow() {
                    if grpc_shutdown.changed().await.is_err() {
                        return;
                    }
                }
                info!("CP gRPC server shutting down");
            };
            let incoming = if let Some(tls_slot) = grpc_tls_slot {
                cp_grpc_tls_incoming(
                    grpc_listener,
                    tls_slot,
                    grpc_accept_shutdown,
                    grpc_tls_handshake_timeout_seconds,
                    grpc_conn_limiter,
                )
            } else {
                cp_grpc_plain_incoming(grpc_listener, grpc_conn_limiter)
            };
            let _ = grpc_started_tx.send(());
            let router = builder
                .add_service(grpc_server.into_service())
                .add_service(mesh_grpc_server.into_service());
            let result = if let Some(xds_server) = xds_server {
                router
                    .add_service(xds_server.into_service())
                    .serve_with_incoming_shutdown(incoming, shutdown_signal)
                    .await
            } else {
                router
                    .serve_with_incoming_shutdown(incoming, shutdown_signal)
                    .await
            };
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    // The gRPC serve future exited with an error, so this CP can no
                    // longer distribute config to data planes. Flip readiness back
                    // to not-ready so `/health` stops reporting `ready` instead of
                    // leaving a live-but-non-serving control plane. The CP listener
                    // monitor also observes this task exiting and triggers graceful
                    // shutdown; flipping readiness first keeps the probe honest
                    // during the teardown window. Returning Err surfaces the failure
                    // from control_plane::run so the process exits non-zero.
                    crate::startup::flip_ready_off_on_listener_failure(
                        &grpc_startup_ready,
                        &grpc_serving_degraded,
                        "CP gRPC server",
                        &e,
                    );
                    Err(anyhow::Error::new(e).context("CP gRPC server failed"))
                }
            }
        });

        Some(handle)
    } else {
        info!("CP gRPC listen port is 0 — gRPC listener disabled");
        drop(grpc_server); // consumed by the gRPC spawn when enabled
        drop(mesh_grpc_server); // consumed by the gRPC spawn when enabled
        drop(xds_server);
        None
    };
    wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
    // Mark CP as ready — same rationale as database mode: the initial
    // `load_full_config()` proved DB connectivity and loaded a complete config.
    // The polling loop handles ongoing incremental updates, not initial readiness.
    // If the gRPC serve future already errored (racing this store), the sticky
    // `serving_degraded` flag was set and keeps `/health` not-ready regardless of
    // this `store(true)`.
    startup_ready.store(true, Ordering::Release);
    info!("Control plane startup complete; /health now reports ready");

    // Kubernetes CRD controller (Layer 8) — defaults to ON inside a K8s pod
    // (T2-B), opt-in via FERRUM_K8S_CONTROLLER_ENABLED outside one. When
    // enabled, watches Istio + Gateway API CRDs and reconciles them into
    // Ferrum config via translate_k8s_objects(). Runs alongside DB polling.
    let _k8s_controller_handle = if env_config.k8s_controller_enabled {
        if env_config.k8s_node_locality_enabled && !env_config.k8s_pod_discovery_enabled {
            warn!(
                "FERRUM_K8S_NODE_LOCALITY_ENABLED=true has no effect because \
                 FERRUM_K8S_POD_DISCOVERY_ENABLED=false"
            );
        }
        // T2-B: when `FERRUM_K8S_WATCH_NAMESPACES` isn't set, fall back to the
        // CP's namespace scope (T2-A). `CpScope::Single`/`Set` produce an
        // explicit watch list; `CpScope::All` returns `None` here, which the
        // controller already interprets as a cluster-wide watch (requires
        // ClusterRole). Operators with an explicit `FERRUM_K8S_WATCH_NAMESPACES`
        // value still win — the explicit override is preserved for the
        // hand-tuned case where the K8s watch scope intentionally differs
        // from the CP scope (e.g. shadow-watching a tenant namespace).
        let watch_namespaces = if !env_config.k8s_watch_namespaces.is_empty() {
            env_config.k8s_watch_namespaces.clone()
        } else {
            match cp_scope.explicit_namespaces() {
                Some(namespaces) => {
                    info!(
                        scope = cp_scope.describe(),
                        namespaces = ?namespaces,
                        "FERRUM_K8S_WATCH_NAMESPACES unset — deriving watch scope from CP scope"
                    );
                    namespaces
                }
                None => {
                    // CpScope::All — empty Vec signals cluster-wide watch.
                    info!(
                        "FERRUM_K8S_WATCH_NAMESPACES unset and CP scope=All — \
                         using cluster-wide K8s CRD watch (requires ClusterRole)"
                    );
                    Vec::new()
                }
            }
        };
        let controller_config = crate::k8s_controller::K8sControllerConfig {
            namespace: env_config.namespace.clone(),
            controller_namespace: env_config.k8s_controller_namespace.clone(),
            trust_domain: env_config.k8s_trust_domain.clone(),
            cluster_domain: env_config.k8s_cluster_domain.clone(),
            istio_root_namespace: env_config.k8s_istio_root_namespace.clone(),
            watch_namespaces,
            watch_istio: env_config.k8s_watch_istio_crds,
            watch_mesh_config: env_config.k8s_watch_mesh_config,
            watch_gateway_api: env_config.k8s_watch_gateway_api_crds,
            pod_discovery_enabled: env_config.k8s_pod_discovery_enabled,
            watch_node_locality: env_config.k8s_node_locality_enabled,
            gateway_api_data_plane_service_namespace: env_config
                .gateway_api_data_plane_service_namespace
                .clone(),
            gateway_api_data_plane_service_name: env_config
                .gateway_api_data_plane_service_name
                .clone(),
            gateway_api_status_address: env_config.gateway_api_status_address.clone(),
            // Effective Sidecar ingress materialization gate (F6 §6.2): ingress
            // is materialized only when enforcement is on AND not dry-run,
            // mirroring the slice builder's `sidecar_enforced && !sidecar_dry_run`
            // ingress predicate. The status writer reports `ingress_modeled` only
            // under this gate so it never over-reports in the default dry-run /
            // disabled posture.
            mesh_sidecar_ingress_enforced: env_config.mesh_sidecar_enforced
                && !env_config.mesh_sidecar_enforced_dry_run,
            debounce_ms: env_config.k8s_reconcile_debounce_ms,
            full_sync_interval_secs: env_config.k8s_full_sync_interval_secs,
            kubeconfig_path: env_config.k8s_kubeconfig_path.clone(),
        };
        match crate::k8s_controller::start_k8s_controller(
            controller_config,
            config_arc.clone(),
            k8s_overlay_slot.clone(),
            broadcasts.clone(),
            cp_scope.clone(),
            dp_registry.clone(),
            mesh_update_tx.clone(),
            mesh_registry.clone(),
            publication_gate.clone(),
            shutdown_tx.subscribe(),
        )
        .await
        {
            Ok(handle) => {
                info!("Kubernetes CRD controller started");
                Some(handle)
            }
            Err(e) => {
                error!("Failed to start K8s controller: {}", e);
                warn!(
                    "Continuing without K8s CRD watching — DB-sourced config still active. \
                     Check FERRUM_K8S_KUBECONFIG_PATH or in-cluster configuration."
                );
                None
            }
        }
    } else {
        if env_config.k8s_pod_discovery_enabled {
            warn!(
                "FERRUM_K8S_POD_DISCOVERY_ENABLED=true has no effect because \
                 FERRUM_K8S_CONTROLLER_ENABLED=false"
            );
        }
        if env_config.k8s_node_locality_enabled {
            warn!(
                "FERRUM_K8S_NODE_LOCALITY_ENABLED=true has no effect because \
                 FERRUM_K8S_CONTROLLER_ENABLED=false"
            );
        }
        None
    };

    // Database polling loop -> push incremental deltas to DPs and mesh nodes (with shutdown).
    //
    // Uses the same incremental polling strategy as database mode: durable
    // change-log reads after the last accepted sequence cursor.
    // Deltas are broadcast as DELTA updates; DPs apply them via apply_incremental.
    // Falls back to FULL_SNAPSHOT on incremental poll failure.
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let config_poll = config_arc.clone();
    let overlay_poll = k8s_overlay_slot.clone();
    let publication_gate_poll = publication_gate.clone();
    let db_available_poll = db_available.clone();
    let config_rejected_poll = config_rejected.clone();
    let mut cp_poll_shutdown = shutdown_tx.subscribe();

    // DNS re-resolution for the database FQDN (same as database mode).
    // CP mode doesn't run a proxy, but still needs to detect DB IP changes.
    let db_hostname = db_backend::extract_db_hostname(&effective_url);
    let replica_hostname = effective_replica_url
        .as_deref()
        .and_then(db_backend::extract_db_hostname);
    let dns_cache_for_poll = DnsCache::new(DnsConfig {
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        ttl_override_seconds: env_config.dns_ttl_override,
        min_ttl_seconds: env_config.dns_min_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        warmup_concurrency: env_config.dns_warmup_concurrency,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
        refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
        failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
        try_tcp_on_error: env_config.dns_try_tcp_on_error,
        num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
        max_active_requests: env_config.dns_max_active_requests,
        max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
        shard_amount: env_config.pool_shard_amount,
    });
    let db_url_for_reconnect = effective_url.clone();
    let replica_url_for_reconnect = effective_replica_url.clone();
    let poll_fallback_namespace = env_config.namespace.clone();
    let dp_registry_poll = dp_registry.clone();
    let poll_cert_expiry_warning_days = env_config.tls_cert_expiry_warning_days;
    let poll_backend_allow_ips = env_config.backend_allow_ips.clone();
    let rejected_delta_full_reload_threshold = env_config.db_rejected_delta_full_reload_threshold;
    let mesh_registry_poll = mesh_registry.clone();
    let poll_scope = cp_scope.clone();
    let poll_broadcasts = broadcasts.clone();
    let initial_polled_namespaces = polled_namespaces;
    let poll_auto_apply_plugin_migrations = env_config.auto_apply_plugin_migrations;

    // Poll freshness + bounded rejection metrics (CP registers the same type as
    // database mode so authenticated `/health` and `/metrics` can expose
    // `last_poll_completed_at` — issue #2986).
    let database_delta_poll_metrics =
        Arc::new(crate::modes::database::DatabaseDeltaPollMetrics::default());
    crate::plugins::prometheus_metrics::global_registry()
        .set_database_delta_poll_metrics(database_delta_poll_metrics.clone());
    let database_delta_poll_metrics_for_poll = database_delta_poll_metrics.clone();

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        // Match database mode: never burst catch-up full polls after a slow cycle.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let last_replica_ips: crate::modes::AdminReadReplicaDnsWatermark =
            Arc::new(tokio::sync::Mutex::new(None));
        let mut force_full_reload = false;
        let mut last_polled_namespaces = initial_polled_namespaces;
        let replica_reconnect_in_flight = Arc::new(AtomicBool::new(false));
        let mut rejected_delta_tracker =
            CpRejectedDeltaTracker::new(rejected_delta_full_reload_threshold);
        // The poll task is the sole owner. Any pool topology swap resets this
        // gate; the first load from that pool must run the same custom-plugin
        // migration policy as startup before CP publishes or enables writes.
        let mut plugin_migrations_need_reconcile = false;

        let mut last_change_sequences = initial_change_sequences;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check if the database FQDN now resolves to different IPs
                    if let Some(ref hostname) = db_hostname
                        && let Ok(ips) = dns_cache_for_poll.resolve_all(hostname, None, None).await
                    {
                        let needs_reconnect = match &last_db_ips {
                            Some(prev) => {
                                let mut prev_sorted = prev.clone();
                                prev_sorted.sort();
                                let mut cur_sorted = ips.clone();
                                cur_sorted.sort();
                                prev_sorted != cur_sorted
                            }
                            None => false,
                        };
                        if needs_reconnect {
                            info!(
                                "Database DNS changed for '{}': {:?} -> {:?}, reconnecting pool",
                                hostname, last_db_ips.as_deref().unwrap_or(&[]), ips
                            );
                            match db_poll.reconnect(&db_url_for_reconnect).await {
                                Ok(_) => {
                                    last_db_ips = Some(ips);
                                    force_full_reload = true;
                                    plugin_migrations_need_reconcile = true;
                                    db_available_poll.store(false, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to reconnect database pool after DNS change for '{}': {}",
                                        hostname, e
                                    );
                                }
                            }
                        } else {
                            last_db_ips = Some(ips);
                        }
                    }

                    if let Some(ref replica_url) = replica_url_for_reconnect {
                        crate::modes::schedule_admin_read_replica_reconnect_if_needed(
                            db_poll.clone(),
                            Some(replica_url.as_str()),
                            replica_hostname.as_deref(),
                            &dns_cache_for_poll,
                            last_replica_ips.clone(),
                            replica_reconnect_in_flight.clone(),
                        )
                        .await;
                    }

                    if force_full_reload {
                        // Re-resolve the namespace list every full reload so
                        // CpScope::All picks up newly created namespaces
                        // without dropping namespaces still present in the
                        // current snapshot if discovery temporarily shrinks.
                        let current_snapshot = config_poll.load_full();
                        let retained_namespaces = retained_polled_namespaces(&current_snapshot);
                        let nslist = resolve_polled_namespaces(
                            db_poll.as_ref(),
                            &poll_scope,
                            &poll_fallback_namespace,
                            &retained_namespaces,
                            Some(&last_polled_namespaces),
                        )
                        .await;
                        match load_full_config_multi_with_sequence(
                            db_poll.as_ref(),
                            &nslist,
                            current_snapshot.as_ref(),
                        )
                        .await
                        {
                            Ok((outcome, sequences)) => {
                                if !reconcile_plugin_migrations_after_cp_reconnect(
                                    &db_poll,
                                    &db_available_poll,
                                    poll_auto_apply_plugin_migrations,
                                    &mut plugin_migrations_need_reconcile,
                                    "DB DNS reconnect",
                                )
                                .await
                                {
                                    database_delta_poll_metrics_for_poll.record_poll_completed();
                                    continue;
                                }
                                merge_refreshed_change_sequences(
                                    &mut last_change_sequences,
                                    sequences,
                                );
                                last_polled_namespaces = nslist.clone();
                                force_full_reload = false;
                                rejected_delta_tracker.record_accepted();
                                db_available_poll.store(true, Ordering::Relaxed);
                                publish_cp_full_reload(
                                    &publication_gate_poll,
                                    config_poll.as_ref(),
                                    &overlay_poll,
                                    outcome.config,
                                    &outcome.refreshed_namespaces,
                                    poll_broadcasts.as_ref(),
                                    &dp_registry_poll,
                                    &poll_scope,
                                    &mesh_update_tx,
                                    &mesh_registry_poll,
                                );
                                settle_full_reload_rejection_state(
                                    &db_poll,
                                    &db_available_poll,
                                    &config_rejected_poll,
                                    &outcome.rejected_namespaces,
                                    &outcome.failed_namespaces,
                                    "full reload after DB DNS reconnect",
                                )
                                .await;
                                debug!("Full config reload complete after DB DNS reconnect");
                            }
                            Err(e) => {
                                if crate::modes::is_poll_validation_rejection(&e) {
                                    if !reconcile_plugin_migrations_after_cp_reconnect(
                                        &db_poll,
                                        &db_available_poll,
                                        poll_auto_apply_plugin_migrations,
                                        &mut plugin_migrations_need_reconcile,
                                        "validation-rejected full load after DB DNS reconnect",
                                    )
                                    .await
                                    {
                                        database_delta_poll_metrics_for_poll.record_poll_completed();
                                        continue;
                                    }
                                    // Reachable backend, invalid snapshot: keep the
                                    // admin API writable (subject to the migration
                                    // gate) for in-band repair and do NOT flip
                                    // reachability closed (issue #2158).
                                    crate::modes::record_config_validation_rejection(
                                        &db_poll,
                                        &db_available_poll,
                                        &config_rejected_poll,
                                        &e,
                                        "full reload after DB DNS reconnect",
                                    )
                                    .await;
                                } else {
                                    error!(
                                        "Authoritative primary full config reload failed after DB DNS reconnect; keeping existing config and retrying: {}",
                                        e
                                    );
                                    db_available_poll.store(false, Ordering::Relaxed);
                                }
                                database_delta_poll_metrics_for_poll.record_poll_completed();
                                continue;
                            }
                        }
                    } else {
                        // Resolve the polled namespace list. For `Single`
                        // / `Set` this is the explicit list (no DB call).
                        // For `All`, authoritative namespace discovery runs
                        // once per tick — bounded cost vs. the per-resource
                        // queries that dominate poll time.
                        let current_snapshot = config_poll.load_full();
                        let retained_namespaces = retained_polled_namespaces(&current_snapshot);
                        let nslist = resolve_polled_namespaces(
                            db_poll.as_ref(),
                            &poll_scope,
                            &poll_fallback_namespace,
                            &retained_namespaces,
                            Some(&last_polled_namespaces),
                        )
                        .await;
                        // Incremental poll — only fetch changes since last poll
                        match load_incremental_config_multi(
                            db_poll.as_ref(),
                            &nslist,
                            &last_change_sequences,
                        )
                        .await
                        {
                            Ok(IncrementalMultiLoad {
                                result,
                                next_sequences,
                                load_failures,
                            }) => {
                                if !reconcile_plugin_migrations_after_cp_reconnect(
                                    &db_poll,
                                    &db_available_poll,
                                    poll_auto_apply_plugin_migrations,
                                    &mut plugin_migrations_need_reconcile,
                                    "incremental load after pool reconnect",
                                )
                                .await
                                {
                                    database_delta_poll_metrics_for_poll.record_poll_completed();
                                    continue;
                                }
                                db_available_poll.store(true, Ordering::Relaxed);
                                last_polled_namespaces = nslist.clone();

                                // Per-namespace delta-load failures are
                                // connectivity/decode faults, NOT validation
                                // rejections: they are already logged per
                                // namespace, their cursor is untouched so the
                                // next tick retries the same rows, and they must
                                // NOT be laundered through
                                // `record_config_validation_rejection` — that
                                // path asserts the backend proved itself
                                // reachable for this read and would re-derive
                                // `db_available` from a deferred-migration probe
                                // on every poll tick.
                                if !load_failures.is_empty() {
                                    warn!(
                                        failed_namespaces = %load_failures
                                            .iter()
                                            .map(|(ns, _)| ns.as_str())
                                            .collect::<Vec<_>>()
                                            .join(","),
                                        "CP incremental poll skipped namespace(s) after a load \
                                         failure; their cursors are unchanged and the remaining \
                                         namespaces continue"
                                    );
                                }

                                if result.is_empty() {
                                    // Advance cursors only for namespaces that
                                    // loaded successfully (possibly empty).
                                    merge_refreshed_change_sequences(
                                        &mut last_change_sequences,
                                        next_sequences,
                                    );
                                    rejected_delta_tracker.record_accepted();
                                    // An empty incremental does not re-validate
                                    // the whole snapshot (#2158). If a standing
                                    // rejection remains, schedule an
                                    // authoritative full reload so the flag can
                                    // clear once the full snapshot is clean —
                                    // otherwise a self-healed tenant would leave
                                    // `config_rejected` stuck with the tracker
                                    // reset and no escalation path.
                                    if config_rejected_poll.load(Ordering::Relaxed) {
                                        force_full_reload = true;
                                    }
                                    database_delta_poll_metrics_for_poll.record_poll_completed();
                                    continue;
                                }
                                let poll_ts = result.poll_timestamp;
                                let version = poll_ts.to_rfc3339();

                                // Partition-first: validate and publish each
                                // namespace independently so one bad tenant
                                // cannot freeze the others (#2983). CAS so a
                                // concurrent reconciler overlay is not lost
                                // (#2984).
                                // Removals carry NamespacedResourceId end-to-end
                                // (main's incremental-apply namespace keys), so
                                // partition needs no pre-delete id→ns lookup.
                                let partitions =
                                    partition_incremental_by_namespace(result.clone());

                                // Publication now flows THROUGH the partitions,
                                // so a non-empty delta that partitions to
                                // nothing (deletions for ids already absent
                                // from the CP snapshot, so their namespace
                                // cannot be resolved) has nothing to publish.
                                // The cursor must still advance or the same
                                // rows are re-read on every tick forever.
                                if partitions.is_empty() {
                                    warn!(
                                        "CP incremental delta contained no namespace-attributable \
                                         changes; advancing cursors for the namespaces that loaded"
                                    );
                                    merge_refreshed_change_sequences(
                                        &mut last_change_sequences,
                                        next_sequences,
                                    );
                                    rejected_delta_tracker.record_accepted();
                                    if config_rejected_poll.load(Ordering::Relaxed) {
                                        force_full_reload = true;
                                    }
                                    database_delta_poll_metrics_for_poll.record_poll_completed();
                                    continue;
                                }

                                // Commit + DP/mesh emission are one publication
                                // section, so a concurrent K8s reconcile full
                                // snapshot can never be emitted after these
                                // deltas and erase them in subscribers.
                                let compose = publish_cp_incremental(
                                    &publication_gate_poll,
                                    config_poll.as_ref(),
                                    &partitions,
                                    &version,
                                    result.sequence_cursor,
                                    poll_ts,
                                    poll_broadcasts.as_ref(),
                                    &dp_registry_poll,
                                    &poll_scope,
                                    &mesh_update_tx,
                                    &mesh_registry_poll,
                                );

                                // Warn-only validators (same set as
                                // `ProxyState::validate_full_config`) run on the
                                // composed view rather than on a second scratch
                                // clone, so they describe exactly what was
                                // published and the healthy path still pays for
                                // only one `GatewayConfig` clone per tick.
                                if let Err(errors) = compose
                                    .config
                                    .validate_all_fields_with_ip_policy(
                                        poll_cert_expiry_warning_days,
                                        &poll_backend_allow_ips,
                                    )
                                {
                                    for msg in &errors {
                                        warn!("CP config field validation: {}", msg);
                                    }
                                }
                                if let Err(errors) = compose.config.validate_hosts() {
                                    for msg in &errors {
                                        warn!("CP config validation: {}", msg);
                                    }
                                }

                                if !compose.rejected.is_empty() {
                                    let rejection_pairs: Vec<(String, String)> = compose
                                        .rejected
                                        .iter()
                                        .map(|(ns, errors)| (ns.clone(), errors.join("; ")))
                                        .collect();
                                    // Identify the stuck batch by the REJECTED
                                    // namespaces' cursors only. Keying on every
                                    // namespace would reset the counter on every
                                    // tick a healthy tenant advanced, so a
                                    // persistently invalid tenant would never
                                    // reach the escalation threshold and
                                    // `config_rejected` could never be cleared
                                    // by an accepted full reload.
                                    let rejected_sequences: HashMap<String, u64> = compose
                                        .rejected
                                        .iter()
                                        .filter_map(|(ns, _)| {
                                            next_sequences.get(ns).map(|seq| (ns.clone(), *seq))
                                        })
                                        .collect();
                                    let decision = rejected_delta_tracker
                                        .record_rejection(&rejected_sequences);
                                    // Only probe the deferred-migration gate on
                                    // the transition into the rejected state or
                                    // on an escalation tick, so a long-lived bad
                                    // tenant does not add a DB round trip to
                                    // every poll cycle.
                                    if (decision.should_escalate
                                        || !config_rejected_poll.load(Ordering::Relaxed))
                                        && let Some(rejection) =
                                            namespace_rejection_error(&rejection_pairs)
                                    {
                                        crate::modes::record_config_validation_rejection(
                                            &db_poll,
                                            &db_available_poll,
                                            &config_rejected_poll,
                                            &rejection,
                                            "incremental validation",
                                        )
                                        .await;
                                    }
                                    if decision.should_escalate {
                                        error!(
                                            consecutive_identical_rejections = decision.consecutive,
                                            "Repeated CP delta rejection reached threshold; attempting authoritative full reload"
                                        );
                                        match load_full_config_multi_with_sequence(
                                            db_poll.as_ref(),
                                            &nslist,
                                            config_poll.load_full().as_ref(),
                                        )
                                        .await
                                        {
                                            Ok((outcome, sequences)) => {
                                                merge_refreshed_change_sequences(
                                                    &mut last_change_sequences,
                                                    sequences,
                                                );
                                                last_polled_namespaces = nslist.clone();
                                                publish_cp_full_reload(
                                                    &publication_gate_poll,
                                                    config_poll.as_ref(),
                                                    &overlay_poll,
                                                    outcome.config,
                                                    &outcome.refreshed_namespaces,
                                                    poll_broadcasts.as_ref(),
                                                    &dp_registry_poll,
                                                    &poll_scope,
                                                    &mesh_update_tx,
                                                    &mesh_registry_poll,
                                                );
                                                rejected_delta_tracker.record_accepted();
                                                db_available_poll.store(true, Ordering::Relaxed);
                                                settle_full_reload_rejection_state(
                                                    &db_poll,
                                                    &db_available_poll,
                                                    &config_rejected_poll,
                                                    &outcome.rejected_namespaces,
                                                    &outcome.failed_namespaces,
                                                    "rejected-delta escalation full reload",
                                                )
                                                .await;
                                                info!(
                                                    "Rejected CP delta recovered by authoritative full reload and full-snapshot broadcast"
                                                );
                                            }
                                            Err(error) => {
                                                if crate::modes::is_poll_validation_rejection(
                                                    &error,
                                                ) {
                                                    crate::modes::record_config_validation_rejection(
                                                        &db_poll,
                                                        &db_available_poll,
                                                        &config_rejected_poll,
                                                        &error,
                                                        "rejected-delta escalation full reload",
                                                    )
                                                    .await;
                                                } else {
                                                    warn!(
                                                        "Authoritative full reload failed after repeated CP delta rejection; keeping the last accepted cursors and cached config: {}",
                                                        error
                                                    );
                                                }
                                            }
                                        }
                                        database_delta_poll_metrics_for_poll
                                            .record_poll_completed();
                                        continue;
                                    }
                                    if compose.accepted.is_empty() {
                                        warn!(
                                            consecutive_identical_rejections = decision.consecutive,
                                            "Incremental CP config update rejected by validation; leaving sequence cursors unchanged so the next poll retries the same rows"
                                        );
                                        database_delta_poll_metrics_for_poll
                                            .record_poll_completed();
                                        continue;
                                    }
                                }

                                // Deltas were already emitted with the commit
                                // above. Advance cursors only for the accepted
                                // namespaces (#2983).
                                info!(
                                    "Incremental config update validated and pushed to {} namespace(s) (version={})",
                                    compose.accepted.len(),
                                    version
                                );
                                // Advance the cursor for accepted namespaces and
                                // for namespaces that loaded with no changes at
                                // all. A REJECTED namespace is present in
                                // `partitions` and absent from `accepted`, so it
                                // keeps its cursor and the next poll retries the
                                // same rows (#2983).
                                for ns in compose.accepted.keys() {
                                    if let Some(seq) = next_sequences.get(ns) {
                                        last_change_sequences.insert(ns.clone(), *seq);
                                    }
                                }
                                for (ns, seq) in &next_sequences {
                                    if !partitions.contains_key(ns) {
                                        last_change_sequences.insert(ns.clone(), *seq);
                                    }
                                }
                                if compose.rejected.is_empty() {
                                    rejected_delta_tracker.record_accepted();
                                    // Per-tenant isolation can accept every
                                    // changed partition via incremental after a
                                    // prior rejection. That must not clear
                                    // `config_rejected` by itself (#2158: only a
                                    // full reload re-validates the whole
                                    // snapshot), but it also resets the
                                    // rejection tracker — so without a forced
                                    // full reload the standing signal would
                                    // never clear.
                                    if config_rejected_poll.load(Ordering::Relaxed) {
                                        force_full_reload = true;
                                    }
                                }
                            }
                            Err(e) => {
                                if db_backend::is_incremental_full_reload_required(&e) {
                                    info!(
                                        "Consumer change detected; using authoritative full reload for credential rehydration: {}",
                                        e
                                    );
                                } else {
                                    warn!(
                                        "Authoritative primary incremental poll failed, falling back to full reload: {}",
                                        e
                                    );
                                }
                                // Fallback to full config load + full snapshot broadcast
                                match load_full_config_multi_with_sequence(
                                    db_poll.as_ref(),
                                    &nslist,
                                    current_snapshot.as_ref(),
                                )
                                .await
                                {
                                    Ok((outcome, sequences)) => {
                                        if !reconcile_plugin_migrations_after_cp_reconnect(
                                            &db_poll,
                                            &db_available_poll,
                                            poll_auto_apply_plugin_migrations,
                                            &mut plugin_migrations_need_reconcile,
                                            "full fallback load after pool reconnect",
                                        )
                                        .await
                                        {
                                            database_delta_poll_metrics_for_poll.record_poll_completed();
                                            continue;
                                        }
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        last_polled_namespaces = nslist.clone();
                                        merge_refreshed_change_sequences(
                                            &mut last_change_sequences,
                                            sequences,
                                        );
                                        rejected_delta_tracker.record_accepted();
                                        publish_cp_full_reload(
                                            &publication_gate_poll,
                                            config_poll.as_ref(),
                                            &overlay_poll,
                                            outcome.config,
                                            &outcome.refreshed_namespaces,
                                            poll_broadcasts.as_ref(),
                                            &dp_registry_poll,
                                            &poll_scope,
                                            &mesh_update_tx,
                                            &mesh_registry_poll,
                                        );
                                        settle_full_reload_rejection_state(
                                            &db_poll,
                                            &db_available_poll,
                                            &config_rejected_poll,
                                            &outcome.rejected_namespaces,
                                            &outcome.failed_namespaces,
                                            "full fallback reload",
                                        )
                                        .await;
                                        info!("Configuration reloaded from database (full fallback) and pushed to DPs and mesh nodes");
                                    }
                                    Err(e2) => {
                                        // Classify the primary full-reload error before
                                        // failover: a validation rejection is identical
                                        // on every replica, so keep the last known-good
                                        // config + admin writable and skip failover
                                        // (issue #2158).
                                        if crate::modes::is_poll_validation_rejection(&e2) {
                                            if !reconcile_plugin_migrations_after_cp_reconnect(
                                                &db_poll,
                                                &db_available_poll,
                                                poll_auto_apply_plugin_migrations,
                                                &mut plugin_migrations_need_reconcile,
                                                "validation-rejected full fallback load after pool reconnect",
                                            )
                                            .await
                                            {
                                                database_delta_poll_metrics_for_poll.record_poll_completed();
                                                continue;
                                            }
                                            crate::modes::record_config_validation_rejection(
                                                &db_poll,
                                                &db_available_poll,
                                                &config_rejected_poll,
                                                &e2,
                                                "full fallback reload",
                                            )
                                            .await;
                                            database_delta_poll_metrics_for_poll.record_poll_completed();
                                            continue;
                                        }
                                        // Both incremental and full reload failed —
                                        // try failover URLs before giving up.
                                        match db_poll.try_failover_reconnect(&db_url_for_reconnect).await {
                                            Ok(_url) => {
                                                plugin_migrations_need_reconcile = true;
                                                db_available_poll.store(false, Ordering::Relaxed);
                                                match load_full_config_multi_with_sequence(
                                                    db_poll.as_ref(),
                                                    &nslist,
                                                    config_poll.load_full().as_ref(),
                                                )
                                                .await
                                                {
                                                    Ok((outcome, sequences)) => {
                                                        if !reconcile_plugin_migrations_after_cp_reconnect(
                                                            &db_poll,
                                                            &db_available_poll,
                                                            poll_auto_apply_plugin_migrations,
                                                            &mut plugin_migrations_need_reconcile,
                                                            "database failover",
                                                        )
                                                        .await
                                                        {
                                                            database_delta_poll_metrics_for_poll.record_poll_completed();
                                                            continue;
                                                        }
                                                        db_available_poll.store(true, Ordering::Relaxed);
                                                        last_polled_namespaces = nslist.clone();
                                                        merge_refreshed_change_sequences(
                                                            &mut last_change_sequences,
                                                            sequences,
                                                        );
                                                        rejected_delta_tracker.record_accepted();
                                                        publish_cp_full_reload(
                                                            &publication_gate_poll,
                                                            config_poll.as_ref(),
                                                            &overlay_poll,
                                                            outcome.config,
                                                            &outcome.refreshed_namespaces,
                                                            poll_broadcasts.as_ref(),
                                                            &dp_registry_poll,
                                                            &poll_scope,
                                                            &mesh_update_tx,
                                                            &mesh_registry_poll,
                                                        );
                                                        settle_full_reload_rejection_state(
                                                            &db_poll,
                                                            &db_available_poll,
                                                            &config_rejected_poll,
                                                            &outcome.rejected_namespaces,
                                                            &outcome.failed_namespaces,
                                                            "failover full reload",
                                                        )
                                                        .await;
                                                        info!("Configuration reloaded from database (failover) and pushed to DPs and mesh nodes");
                                                    }
                                                    Err(e3) => {
                                                        if crate::modes::is_poll_validation_rejection(&e3) {
                                                            if !reconcile_plugin_migrations_after_cp_reconnect(
                                                                &db_poll,
                                                                &db_available_poll,
                                                                poll_auto_apply_plugin_migrations,
                                                                &mut plugin_migrations_need_reconcile,
                                                                "validation-rejected database failover load",
                                                            )
                                                            .await
                                                            {
                                                                database_delta_poll_metrics_for_poll.record_poll_completed();
                                                                continue;
                                                            }
                                                            crate::modes::record_config_validation_rejection(
                                                                &db_poll,
                                                                &db_available_poll,
                                                                &config_rejected_poll,
                                                                &e3,
                                                                "failover full reload",
                                                            )
                                                            .await;
                                                        } else {
                                                            db_available_poll.store(false, Ordering::Relaxed);
                                                            warn!(
                                                                "Authoritative primary failover reload also failed (serving cached): {}",
                                                                e3
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                db_available_poll.store(false, Ordering::Relaxed);
                                                warn!(
                                                    "Authoritative primary full config reload also failed (serving cached): {}",
                                                    e2
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Normal fallthrough: success, empty, rejection, or handled error.
                    database_delta_poll_metrics_for_poll.record_poll_completed();
                }
                _ = cp_poll_shutdown.changed() => {
                    info!("CP database polling shutting down");
                    return;
                }
            }
        }
    });

    let db_poll_supervisor = {
        let startup_ready = startup_ready.clone();
        let serving_degraded = serving_degraded.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            crate::modes::db_poll_supervision::supervise_control_plane_poll_task(
                db_poll_handle,
                startup_ready,
                serving_degraded,
                shutdown_rx,
            )
            .await;
        })
    };

    let mesh_registry_reaper_handle = {
        let registry = mesh_registry.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MESH_NODE_REGISTRY_REAPER_INTERVAL);
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let removed = registry.remove_stale_heartbeats(
                            chrono::Utc::now(),
                            mesh_node_registry_stale_ttl(),
                        );
                        if removed > 0 {
                            warn!(
                                removed,
                                "Removed stale mesh nodes after heartbeat timeout"
                            );
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                    }
                }
            }
        })
    };
    let runtime_system_handle = crate::system_metrics::start_sampler(
        None,
        env_config.runtime_metrics_system_sample_interval_ms,
        shutdown_tx.subscribe(),
    );
    let runtime_window_handle = crate::runtime_metrics::start_window_rotator(
        env_config.runtime_metrics_window_1m_seconds,
        env_config.runtime_metrics_window_5m_seconds,
        shutdown_tx.subscribe(),
    );

    // Wait for ALL listener handles to exit, or the shutdown signal if no
    // listeners were spawned (e.g., admin_http=0, no admin TLS, gRPC port=0).
    //
    // CP listener supervision keeps a single drain budget per wake reason
    // (listener exit vs operator SIGINT/SIGTERM) so a monitor-originated
    // shutdown cannot be overwritten by an outer equal-timeout `Ok(())`:
    //
    // 1. On the shutdown signal, every listener observes it via its own
    //    `shutdown_tx.subscribe()` receiver and exits gracefully —
    //    `serve_with_incoming_shutdown` for gRPC (so tonic completes
    //    in-flight RPCs and `TrackedStream`'s `Drop` deregisters the DP
    //    from `DpNodeRegistry`), and the watch-driven shutdown loops for
    //    admin HTTP/HTTPS. Expected Ok exits after SIGINT/SIGTERM stay clean;
    //    a stuck sibling after operator stop still returns Ok after the
    //    configured drain timeout.
    // 2. If a listener returns a serve error, panics, or exits Ok without a
    //    prior shutdown request, the monitor preserves that first unexpected
    //    failure, fires shutdown so siblings drain under the same timeout
    //    bound, and propagates Err from `run()` so the process exits non-zero
    //    even when a sibling is still stuck at the deadline.
    let mut listener_handles: Vec<(String, ListenerJoinHandle)> = Vec::new();
    if let Some(handle) = admin_http_handle {
        listener_handles.push(("CP admin HTTP listener".to_string(), handle));
    }
    if let Some(handle) = grpc_handle {
        listener_handles.push(("CP gRPC server".to_string(), handle));
    }
    if let Some(handle) = admin_https_handle {
        listener_handles.push(("CP admin HTTPS listener".to_string(), handle));
    }

    let listener_result = wait_for_cp_listeners_until_shutdown_or_exit(
        listener_handles,
        shutdown_tx.clone(),
        Duration::from_secs(5),
    )
    .await;

    // Wait for background tasks to drain cleanly, with a timeout to prevent
    // hanging if a task is stuck (e.g., blocked on a DB query). Same 5 s
    // cap as the pre-refactor inline timeout — a stuck DB poll is never
    // allowed to wedge graceful shutdown.
    let mut background_handles = vec![
        db_poll_supervisor,
        mesh_registry_reaper_handle,
        runtime_system_handle,
        runtime_window_handle,
    ];
    if let Some(handle) = db_tls_reload_handle {
        background_handles.push(handle);
    }
    crate::modes::file::join_background_handles(background_handles, Duration::from_secs(5)).await;

    listener_result
}

pub(crate) async fn wait_for_cp_listeners_until_shutdown_or_exit(
    listener_handles: Vec<(String, ListenerJoinHandle)>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    drain_timeout: Duration,
) -> Result<(), anyhow::Error> {
    if listener_handles.is_empty() {
        wait_for_cp_shutdown(&shutdown_tx).await;
        info!("Shutdown signal received with no active listeners");
        return Ok(());
    }

    // Run supervision inline (no outer select + equal drain timeout). An earlier
    // shape raced a monitor-originated shutdown against an outer `drain_timeout`
    // that could abort the monitor and convert a preserved listener failure into
    // `Ok(())`. Provenance lives inside the monitor: listener-exit vs operator
    // shutdown each own a single drain budget and return their own result.
    monitor_cp_listener_handles_until_exit(listener_handles, shutdown_tx, drain_timeout).await
}

/// Wake reason for the first event observed while supervising CP listeners.
enum CpListenerMonitorWake {
    /// A listener task completed (Ok, Err, or panic/join failure).
    ListenerExit(
        String,
        Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
    ),
    /// Shared shutdown watch flipped before any listener exited (SIGINT/SIGTERM).
    OperatorShutdown,
}

async fn monitor_cp_listener_handles_until_exit(
    listener_handles: Vec<(String, ListenerJoinHandle)>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    drain_timeout: Duration,
) -> Result<(), anyhow::Error> {
    use futures_util::stream::{FuturesUnordered, StreamExt};

    // Dropping a JoinHandle detaches its task. Retain independent abort handles
    // so a listener that ignores shutdown cannot outlive the bounded drain.
    let abort_handles: Vec<tokio::task::AbortHandle> = listener_handles
        .iter()
        .map(|(_, handle)| handle.abort_handle())
        .collect();
    let mut futures: FuturesUnordered<_> = listener_handles
        .into_iter()
        .map(|(name, handle)| async move { (name, handle.await) })
        .collect();

    // Operator already requested stop before supervision began (e.g. SIGTERM
    // landed while listeners were still being spawned into the wait helper).
    if *shutdown_tx.borrow() {
        return drain_cp_listener_futures(
            &mut futures,
            &abort_handles,
            drain_timeout,
            "Timed out waiting for CP listeners to drain after shutdown",
        )
        .await;
    }

    let wake = tokio::select! {
        // Prefer a completed listener over a concurrent operator shutdown so an
        // unsolicited/error/panic exit is classified before the drain path can
        // treat a pre-shutdown Ok as an expected clean stop.
        biased;
        Some((name, join)) = futures.next() => {
            CpListenerMonitorWake::ListenerExit(name, join)
        }
        _ = wait_for_cp_shutdown(&shutdown_tx) => {
            CpListenerMonitorWake::OperatorShutdown
        }
    };

    match wake {
        CpListenerMonitorWake::OperatorShutdown => {
            // Explicit SIGINT/SIGTERM: one drain budget for every still-running
            // listener. Stuck siblings stay Ok; serve errors / panics still
            // surface because the drain loop preserves the first failure even
            // when the deadline expires afterward.
            drain_cp_listener_futures(
                &mut futures,
                &abort_handles,
                drain_timeout,
                "Timed out waiting for CP listeners to drain after shutdown",
            )
            .await
        }
        CpListenerMonitorWake::ListenerExit(first_name, first_join) => {
            let shutdown_already_requested = *shutdown_tx.borrow();
            let first_error =
                classify_cp_listener_exit(&first_name, first_join, shutdown_already_requested);

            info!(
                listener = %first_name,
                "CP listener task exited; triggering control-plane shutdown"
            );
            let _ = shutdown_tx.send(true);

            let remaining_result = drain_cp_listener_futures(
                &mut futures,
                &abort_handles,
                drain_timeout,
                "Timed out waiting for remaining CP listeners to drain after listener exit",
            )
            .await;

            match (first_error, remaining_result) {
                (Some(err), _) => Err(err),
                (None, Err(err)) => Err(err),
                (None, Ok(())) => Ok(()),
            }
        }
    }
}

/// Drain remaining CP listener join futures under a single deadline.
///
/// Failures observed before the deadline are preserved and returned even if a
/// sibling is still stuck when the timeout fires. On timeout, all retained
/// abort handles are fired (completed tasks are unaffected), then remaining
/// join futures are dropped. A prior clean operator stop stays `Ok` when no
/// failure was collected.
async fn drain_cp_listener_futures<Fut>(
    futures: &mut futures_util::stream::FuturesUnordered<Fut>,
    abort_handles: &[tokio::task::AbortHandle],
    drain_timeout: Duration,
    timeout_message: &str,
) -> Result<(), anyhow::Error>
where
    Fut: std::future::Future<
            Output = (
                String,
                Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
            ),
        >,
{
    use futures_util::stream::StreamExt;

    if futures.is_empty() {
        return Ok(());
    }

    let mut first_error: Option<anyhow::Error> = None;
    let deadline = tokio::time::Instant::now() + drain_timeout;

    loop {
        if futures.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, futures.next()).await {
            Ok(Some((name, join))) => {
                // Shutdown has been requested by this point (operator or a prior
                // listener exit), so Ok exits are expected. Errors/panics still
                // classify as failures.
                if let Some(err) = classify_cp_listener_exit(&name, join, true)
                    && first_error.is_none()
                {
                    first_error = Some(err);
                }
            }
            Ok(None) => break,
            Err(_) => {
                warn!("{timeout_message}");
                for abort_handle in abort_handles {
                    abort_handle.abort();
                }
                // Once abort has been requested, release the remaining join
                // futures without detaching still-running listeners.
                *futures = futures_util::stream::FuturesUnordered::new();
                break;
            }
        }
    }

    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn classify_cp_listener_exit(
    name: &str,
    join: Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
    shutdown_already_requested: bool,
) -> Option<anyhow::Error> {
    match join {
        Ok(Ok(())) if shutdown_already_requested => None,
        Ok(Ok(())) => Some(anyhow::anyhow!(
            "{name} exited unexpectedly without a shutdown request"
        )),
        Ok(Err(err)) => {
            error!("CP listener task '{name}' failed: {err:#}");
            Some(err.context(format!("{name} failed")))
        }
        Err(err) if err.is_panic() => {
            error!("CP listener task '{name}' failed: {err}");
            Some(anyhow::anyhow!("{name} panicked: {err}"))
        }
        Err(err) => {
            error!("CP listener task '{name}' failed: {err}");
            Some(anyhow::anyhow!("{name} failed to join: {err}"))
        }
    }
}

async fn wait_for_cp_shutdown(shutdown_tx: &tokio::sync::watch::Sender<bool>) {
    let mut wait_shutdown = shutdown_tx.subscribe();
    while !*wait_shutdown.borrow() {
        if wait_shutdown.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_backend::{IncrementalResult, NamespacedResourceId};
    use crate::config::types::*;
    use chrono::{TimeZone, Utc};
    use std::time::Instant;

    fn empty_incremental() -> IncrementalResult {
        IncrementalResult {
            added_or_modified_proxies: vec![],
            removed_proxy_ids: vec![],
            added_or_modified_consumers: vec![],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![],
            removed_upstream_ids: vec![],
            sequence_cursor: 0,
            poll_timestamp: Utc::now(),
        }
    }

    fn make_proxy(id: &str) -> Proxy {
        Proxy {
            id: id.to_string(),
            namespace: default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some(format!("/{id}")),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "localhost".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5000,
            backend_read_timeout_ms: 30000,
            backend_write_timeout_ms: 30000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: Default::default(),
            dispatch_port_overrides: None,
            dispatch_port_override_fallback: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_consumer(id: &str) -> Consumer {
        Consumer {
            id: id.to_string(),
            namespace: default_namespace(),
            username: format!("user_{id}"),
            custom_id: None,
            credentials: std::collections::HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn cp_full_snapshot_rejects_dangling_upstream_reference() {
        let mut proxy = make_proxy("dangling-upstream");
        proxy.upstream_id = Some("missing-upstream".to_string());
        let config = GatewayConfig {
            proxies: vec![proxy],
            ..Default::default()
        };

        let error = reject_invalid_cp_full_snapshot(&config)
            .expect_err("CP full snapshot must reject a dangling upstream reference");

        // Issue #2158: the rejection must carry the typed marker so the CP poll
        // loop classifies it as a reachable-but-invalid snapshot (keeping admin
        // writable) rather than a connectivity failure (which fails closed).
        assert!(
            crate::modes::is_poll_validation_rejection(&error),
            "CP full-snapshot rejection must be a typed ConfigValidationRejection: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("CP configuration validation failed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn partial_multi_ns_full_load_advances_loaded_at_from_first_success() {
        // Drive the same pure aggregator `load_full_config_multi` uses: an old
        // previous snapshot, a failed first namespace, then a successful later
        // namespace with a fixed fresh stamp. Failed-ns LKG is retained,
        // successful-ns resources are replaced, and the combined snapshot must
        // carry the fresh stamp (not previous.loaded_at).
        let old_loaded_at = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let fresh_loaded_at = Utc.with_ymd_and_hms(2026, 7, 26, 12, 0, 0).unwrap();

        let mut previous = GatewayConfig {
            loaded_at: old_loaded_at,
            ..Default::default()
        };
        let mut a_old = make_proxy("a-old");
        a_old.namespace = "ns-a".to_string();
        let mut b_old = make_proxy("b-old");
        b_old.namespace = "ns-b".to_string();
        previous.proxies.push(a_old);
        previous.proxies.push(b_old);

        let mut ns_b = GatewayConfig {
            loaded_at: fresh_loaded_at,
            ..Default::default()
        };
        let mut b_new = make_proxy("b-new");
        b_new.namespace = "ns-b".to_string();
        ns_b.proxies.push(b_new);

        let mut acc = MultiNsFullLoadAcc::new();
        acc.apply_failed(&previous, "ns-a");
        acc.apply_success("ns-b", ns_b);
        let outcome = acc
            .finish(&previous, None)
            .expect("partial reload must succeed when at least one namespace loads");

        assert_eq!(
            outcome.config.loaded_at, fresh_loaded_at,
            "combined snapshot must use the first successful namespace stamp, not previous.loaded_at"
        );
        assert_ne!(outcome.config.loaded_at, old_loaded_at);
        assert!(
            outcome.config.proxies.iter().any(|p| p.id == "a-old"),
            "failed first namespace must retain last-known-good resources from previous"
        );
        assert!(
            outcome.config.proxies.iter().any(|p| p.id == "b-new"),
            "later successful namespace must apply refreshed resources"
        );
        assert!(
            !outcome.config.proxies.iter().any(|p| p.id == "b-old"),
            "refreshed namespace must not keep stale resources"
        );
        assert_eq!(outcome.refreshed_namespaces, vec!["ns-b".to_string()]);
        assert_eq!(outcome.failed_namespaces, vec!["ns-a".to_string()]);
        assert!(outcome.rejected_namespaces.is_empty());
        assert!(
            outcome.config.mesh.is_none(),
            "DB multi full-load finalize must clear mesh for overlay re-merge"
        );
    }

    fn make_stream_proxy(id: &str, namespace: &str, listen_port: u16) -> Proxy {
        let mut proxy = make_proxy(id);
        proxy.namespace = namespace.to_string();
        proxy.backend_scheme = Some(BackendScheme::Tcp);
        proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
        proxy.listen_path = None;
        proxy.listen_port = Some(listen_port);
        proxy
    }

    #[test]
    fn cp_full_snapshot_allows_same_stream_port_in_different_namespaces() {
        for (id, namespace) in [("tcp-a", "tenant-a"), ("tcp-b", "tenant-b")] {
            let config = GatewayConfig {
                proxies: vec![make_stream_proxy(id, namespace, 15432)],
                ..Default::default()
            };

            prepare_cp_full_snapshot(config)
                .expect("each namespace slice must validate independently");
        }
    }

    #[test]
    fn cp_full_snapshot_rejects_same_stream_port_in_one_namespace() {
        let config = GatewayConfig {
            proxies: vec![
                make_stream_proxy("tcp-a", "tenant-a", 15432),
                make_stream_proxy("tcp-b", "tenant-a", 15432),
            ],
            ..Default::default()
        };

        prepare_cp_full_snapshot(config)
            .expect_err("same-namespace stream listen-port conflicts must be rejected");
    }

    #[test]
    fn cp_incremental_validation_allows_same_stream_port_across_namespaces() {
        let mut config = GatewayConfig {
            proxies: vec![make_stream_proxy("tcp-a", "tenant-a", 15432)],
            ..Default::default()
        };
        let mut delta = empty_incremental();
        delta.added_or_modified_proxies = vec![make_stream_proxy("tcp-b", "tenant-b", 15432)];
        apply_incremental_to_config(&mut config, delta);

        let errors = collect_rejecting_cp_incremental_errors(
            &config,
            &["tenant-a".to_string(), "tenant-b".to_string()],
        );

        assert!(
            errors.is_empty(),
            "cross-namespace stream ports must validate independently: {errors:?}"
        );
    }

    #[test]
    fn cp_incremental_validation_rejects_same_stream_port_in_one_namespace() {
        let config = GatewayConfig {
            proxies: vec![
                make_stream_proxy("tcp-a", "tenant-a", 15432),
                make_stream_proxy("tcp-b", "tenant-a", 15432),
            ],
            ..Default::default()
        };

        let errors = collect_rejecting_cp_incremental_errors(
            &config,
            &["tenant-a".to_string(), "tenant-b".to_string()],
        );

        assert!(
            errors
                .iter()
                .any(|error| error.contains("Duplicate listen_port 15432")),
            "same-namespace conflict must still be rejected: {errors:?}"
        );
    }

    #[test]
    fn cp_rejected_delta_escalates_and_resets_after_full_reload_recovery() {
        let mut tracker = CpRejectedDeltaTracker::new(3);
        let sequences = HashMap::from([("tenant-a".to_string(), 10), ("tenant-b".to_string(), 20)]);

        assert!(!tracker.record_rejection(&sequences).should_escalate);
        assert!(!tracker.record_rejection(&sequences).should_escalate);
        let escalation = tracker.record_rejection(&sequences);
        assert!(escalation.should_escalate);
        assert_eq!(escalation.consecutive, 3);

        // The poll loop calls this after an accepted authoritative full reload.
        tracker.record_accepted();
        let after_recovery = tracker.record_rejection(&sequences);
        assert!(!after_recovery.should_escalate);
        assert_eq!(after_recovery.consecutive, 1);
    }

    #[test]
    fn cp_pool_swaps_reconcile_plugin_migrations_before_publication() {
        // Issue #2802: a CP DNS reconnect or failover can land on a database
        // whose custom-plugin schema lags the process binary.
        let source = include_str!("control_plane.rs");
        assert!(
            source.contains("async fn reconcile_plugin_migrations_after_cp_reconnect(")
                && source.contains("handle_recovery_plugin_migrations("),
            "CP recovery must share the startup custom-plugin migration policy"
        );
        assert!(
            source
                .matches("plugin_migrations_need_reconcile = true;")
                .count()
                >= 2,
            "both DNS pool reconnect and failover must reset the migration gate"
        );
        for context in [
            "DB DNS reconnect",
            "validation-rejected full load after DB DNS reconnect",
            "incremental load after pool reconnect",
            "full fallback load after pool reconnect",
            "validation-rejected full fallback load after pool reconnect",
            "database failover",
            "validation-rejected database failover load",
        ] {
            assert!(
                source.contains(context),
                "missing CP migration gate for {context}"
            );
        }
    }

    #[test]
    fn merge_discovered_namespaces_retains_current_snapshot_namespaces() {
        let merged = merge_discovered_namespaces(
            vec!["tenant-a".to_string()],
            &["tenant-b".to_string()],
            "ferrum",
        );
        assert_eq!(merged, vec!["tenant-a", "tenant-b"]);
    }

    #[test]
    fn merge_discovered_namespaces_uses_fallback_only_when_nothing_known() {
        let merged = merge_discovered_namespaces(Vec::new(), &[], "ferrum");
        assert_eq!(merged, vec!["ferrum"]);
    }

    #[test]
    fn retained_polled_namespaces_includes_resources_and_known_namespaces() {
        let mut proxy = make_proxy("p1");
        proxy.namespace = "tenant-a".to_string();
        let config = GatewayConfig {
            proxies: vec![proxy],
            known_namespaces: vec!["tenant-b".to_string()],
            ..Default::default()
        };

        let retained = retained_polled_namespaces(&config);
        assert_eq!(retained, vec!["tenant-a", "tenant-b"]);
    }

    #[test]
    fn restore_namespace_last_known_good_replaces_only_that_tenant() {
        let mut previous = GatewayConfig::default();
        let mut old_a = make_proxy("a-old");
        old_a.namespace = "ns-a".to_string();
        let mut old_b = make_proxy("b-old");
        old_b.namespace = "ns-b".to_string();
        previous.proxies.extend([old_a, old_b]);

        let mut loaded = GatewayConfig::default();
        let mut new_a = make_proxy("a-new");
        new_a.namespace = "ns-a".to_string();
        let mut new_b = make_proxy("b-new");
        new_b.namespace = "ns-b".to_string();
        loaded.proxies.extend([new_a, new_b]);

        restore_namespace_last_known_good(&mut loaded, &previous, "ns-b");

        assert!(
            loaded.proxies.iter().any(|p| p.id == "a-new"),
            "sibling namespace must keep the freshly loaded resources"
        );
        assert!(
            loaded.proxies.iter().any(|p| p.id == "b-old"),
            "demoted namespace must revert to last-known-good"
        );
        assert!(
            !loaded.proxies.iter().any(|p| p.id == "b-new"),
            "demoted namespace must not retain the unpublished load"
        );
    }

    #[test]
    fn standing_rejection_forces_full_reload_after_clean_incremental() {
        // Pin the #2158 recovery contract under per-tenant isolation: once
        // an incremental tick accepts (or finds nothing to apply) while
        // `config_rejected` is still set, the poll loop must schedule a full
        // reload rather than clearing the rejection tracker and leaving the
        // standing signal permanently stuck.
        let source = include_str!("control_plane.rs");
        let marker = "if config_rejected_poll.load(Ordering::Relaxed) {\n                                        force_full_reload = true;";
        assert!(
            source.matches(marker).count() >= 3,
            "empty-result, empty-partition, and all-accepted incremental paths \
             must force a full reload while config_rejected is set"
        );
    }

    #[test]
    fn partition_incremental_routes_removed_ids_by_namespace_key() {
        let mut result = empty_incremental();
        result.removed_proxy_ids = vec![NamespacedResourceId::new("tenant-a", "p1")];

        let partitions = partition_incremental_by_namespace(result);
        let tenant_delta = partitions
            .get("tenant-a")
            .expect("removed proxy should be routed to its namespace");
        assert_eq!(
            tenant_delta.removed_proxy_ids,
            vec![NamespacedResourceId::new("tenant-a", "p1")]
        );
    }

    #[test]
    fn partition_incremental_routes_duplicate_consumer_ids_by_namespace() {
        let mut result = empty_incremental();
        result.removed_consumer_ids = vec![NamespacedResourceId::new("staging", "c1")];

        let partitions = partition_incremental_by_namespace(result);

        assert!(!partitions.contains_key("prod"));
        assert_eq!(
            partitions
                .get("staging")
                .expect("staging delete must retain its namespace")
                .removed_consumer_ids,
            vec![NamespacedResourceId::new("staging", "c1")]
        );
    }

    // ── upsert_by_id ───────────────────────────────────────────────────

    #[test]
    fn upsert_replaces_existing_by_id() {
        let mut items = vec![("a", 1), ("b", 2)];
        upsert_by_id(&mut items, vec![("b", 99)], |item| item.0);
        assert_eq!(items[1].1, 99);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn upsert_appends_new_items() {
        let mut items = vec![("a", 1)];
        upsert_by_id(&mut items, vec![("c", 3)], |item| item.0);
        assert_eq!(items.len(), 2);
        assert_eq!(items[1], ("c", 3));
    }

    #[test]
    fn upsert_mixed_replace_and_append() {
        let mut items = vec![("a", 1), ("b", 2)];
        upsert_by_id(&mut items, vec![("b", 20), ("c", 30)], |item| item.0);
        assert_eq!(items.len(), 3);
        assert_eq!(items[1].1, 20); // b replaced
        assert_eq!(items[2], ("c", 30)); // c appended
    }

    #[test]
    fn upsert_empty_updates_is_noop() {
        let mut items = vec![("a", 1)];
        upsert_by_id(&mut items, vec![], |item| item.0);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn upsert_into_empty_list() {
        let mut items: Vec<(&str, i32)> = vec![];
        upsert_by_id(&mut items, vec![("a", 1)], |item| item.0);
        assert_eq!(items.len(), 1);
    }

    // apply_incremental_to_config

    #[test]
    fn apply_incremental_empty_is_noop() {
        let mut config = GatewayConfig {
            proxies: vec![make_proxy("p1")],
            ..Default::default()
        };
        apply_incremental_to_config(&mut config, empty_incremental());
        assert_eq!(config.proxies.len(), 1);
    }

    #[test]
    fn apply_incremental_adds_proxy() {
        let mut config = GatewayConfig::default();
        let mut inc = empty_incremental();
        inc.added_or_modified_proxies = vec![make_proxy("new")];
        apply_incremental_to_config(&mut config, inc);
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].id, "new");
    }

    #[test]
    fn apply_incremental_removes_proxy() {
        let mut config = GatewayConfig {
            proxies: vec![make_proxy("p1"), make_proxy("p2")],
            ..Default::default()
        };
        let mut inc = empty_incremental();
        inc.removed_proxy_ids = vec![NamespacedResourceId::new("ferrum", "p1")];
        apply_incremental_to_config(&mut config, inc);
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].id, "p2");
    }

    #[test]
    fn apply_incremental_modifies_proxy() {
        let mut config = GatewayConfig {
            proxies: vec![make_proxy("p1")],
            ..Default::default()
        };
        let mut updated = make_proxy("p1");
        updated.backend_port = 9999;
        let mut inc = empty_incremental();
        inc.added_or_modified_proxies = vec![updated];
        apply_incremental_to_config(&mut config, inc);
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].backend_port, 9999);
    }

    #[test]
    fn apply_incremental_mixed_operations() {
        let mut config = GatewayConfig {
            proxies: vec![make_proxy("keep"), make_proxy("remove")],
            consumers: vec![make_consumer("c1")],
            ..Default::default()
        };
        let mut inc = empty_incremental();
        inc.removed_proxy_ids = vec![NamespacedResourceId::new("ferrum", "remove")];
        inc.added_or_modified_proxies = vec![make_proxy("added")];
        inc.removed_consumer_ids = vec![NamespacedResourceId::new("ferrum", "c1")];
        inc.added_or_modified_consumers = vec![make_consumer("c2")];
        apply_incremental_to_config(&mut config, inc);

        assert_eq!(config.proxies.len(), 2);
        assert!(config.proxies.iter().any(|p| p.id == "keep"));
        assert!(config.proxies.iter().any(|p| p.id == "added"));
        assert!(!config.proxies.iter().any(|p| p.id == "remove"));
        assert_eq!(config.consumers.len(), 1);
        assert_eq!(config.consumers[0].id, "c2");
    }

    #[test]
    fn apply_incremental_keys_consumers_by_namespace_and_id() {
        let mut prod = make_consumer("c1");
        prod.namespace = "prod".to_string();
        let mut staging = make_consumer("c1");
        staging.namespace = "staging".to_string();
        let mut updated_staging = staging.clone();
        updated_staging.username = "updated-staging".to_string();
        let mut config = GatewayConfig {
            consumers: vec![prod, staging],
            ..Default::default()
        };
        let mut inc = empty_incremental();
        inc.removed_consumer_ids = vec![NamespacedResourceId::new("staging", "c1")];
        inc.added_or_modified_consumers = vec![updated_staging];

        apply_incremental_to_config(&mut config, inc);

        assert_eq!(config.consumers.len(), 2);
        assert_eq!(
            config
                .consumers
                .iter()
                .find(|consumer| consumer.namespace == "prod")
                .expect("prod consumer must remain")
                .username,
            "user_c1"
        );
        assert_eq!(
            config
                .consumers
                .iter()
                .find(|consumer| consumer.namespace == "staging")
                .expect("staging consumer must be updated")
                .username,
            "updated-staging"
        );
    }

    #[test]
    fn apply_incremental_keys_proxies_by_namespace_and_id() {
        let mut prod = make_proxy("shared");
        prod.namespace = "prod".to_string();
        let mut staging = make_proxy("shared");
        staging.namespace = "staging".to_string();
        let mut updated_staging = staging.clone();
        updated_staging.backend_port = 9999;
        let mut config = GatewayConfig {
            proxies: vec![prod, staging],
            ..Default::default()
        };
        let mut inc = empty_incremental();
        inc.added_or_modified_proxies = vec![updated_staging];

        apply_incremental_to_config(&mut config, inc);

        assert_eq!(config.proxies.len(), 2);
        assert_eq!(
            config
                .proxies
                .iter()
                .find(|proxy| proxy.namespace == "prod")
                .expect("prod proxy must remain")
                .backend_port,
            8080
        );
        assert_eq!(
            config
                .proxies
                .iter()
                .find(|proxy| proxy.namespace == "staging")
                .expect("staging proxy must be updated")
                .backend_port,
            9999
        );
    }

    // Regression: prior to this fix, CP mode used `tokio::select!` over the
    // admin/HTTPS/gRPC listener handles. The first listener to exit (panic
    // or otherwise) short-circuited the select and dropped the inner
    // async blocks for the others. Those `JoinHandle`s were *moved* into
    // the cancelled inner blocks, so dropping them detached the still
    // serving listener tasks rather than aborting them. The function then
    // returned, the runtime tore down at the binary boundary, and the
    // detached listeners died abruptly mid-flight — DPs subscribing to
    // the gRPC stream saw their connections cut without a graceful
    // shutdown signal.
    //
    // The fix routes the listener handles through fallible CP supervision
    // (and file-mode's await helpers), which both:
    //   1. Awaits ALL handles concurrently so a single exit does not
    //      strand the others; and
    //   2. Fires shutdown on the first unexpected failure so the remaining
    //      listeners observe the shared shutdown watch channel via their
    //      own subscribers and exit promptly.
    //
    // This test models that with three fake CP listeners (admin_http,
    // grpc, admin_https). One panics; the other two must still drain
    // cleanly through the watch trigger. Bound the wait at 2 s — without
    // the trigger, the remaining listeners would block forever on their
    // watch receivers.
    #[tokio::test]
    async fn cp_shutdown_drains_remaining_listeners_when_one_panics() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            let _ = admin_http_rx.changed().await;
            Ok::<(), anyhow::Error>(())
        });

        let grpc = tokio::spawn(async {
            panic!("simulated gRPC listener crash");
        });

        let mut admin_https_rx = shutdown_tx.subscribe();
        let admin_https = tokio::spawn(async move {
            let _ = admin_https_rx.changed().await;
            Ok::<(), anyhow::Error>(())
        });

        let listener_handles = vec![
            ("CP admin HTTP listener".to_string(), admin_http),
            ("CP gRPC server".to_string(), grpc),
            ("CP admin HTTPS listener".to_string(), admin_https),
        ];

        let started = Instant::now();
        let result = wait_for_cp_listeners_until_shutdown_or_exit(
            listener_handles,
            shutdown_tx,
            Duration::from_secs(2),
        )
        .await;
        let elapsed = started.elapsed();

        let err = result.expect_err("the gRPC listener panicked, helper must return Err");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("panicked"),
            "error should report panic; got {rendered}",
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "remaining listeners should drain via shutdown trigger; took {elapsed:?}",
        );
    }

    // Sanity: when no listener fails and the shared shutdown watch is
    // simply set to true (the normal SIGTERM path), every listener's
    // own `.subscribe()` receiver fires `changed()` and supervision
    // returns Ok. This verifies the "happy path" is preserved end-to-end.
    #[tokio::test]
    async fn cp_shutdown_drains_all_listeners_on_signal() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            let _ = admin_http_rx.changed().await;
            Ok::<(), anyhow::Error>(())
        });
        let mut grpc_rx = shutdown_tx.subscribe();
        let grpc = tokio::spawn(async move {
            let _ = grpc_rx.changed().await;
            Ok::<(), anyhow::Error>(())
        });
        let mut admin_https_rx = shutdown_tx.subscribe();
        let admin_https = tokio::spawn(async move {
            let _ = admin_https_rx.changed().await;
            Ok::<(), anyhow::Error>(())
        });

        // Fire shutdown after spawning so the listeners are already
        // parked on changed() — models the SIGTERM path.
        shutdown_tx
            .send(true)
            .expect("watch send must succeed with live receivers");

        let result = wait_for_cp_listeners_until_shutdown_or_exit(
            vec![
                ("CP admin HTTP listener".to_string(), admin_http),
                ("CP gRPC server".to_string(), grpc),
                ("CP admin HTTPS listener".to_string(), admin_https),
            ],
            shutdown_tx,
            Duration::from_secs(2),
        )
        .await;
        result.expect("no listener failed; supervision must return Ok");
    }

    #[tokio::test]
    async fn cp_listener_wait_does_not_apply_drain_timeout_before_shutdown() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut listener_rx = shutdown_tx.subscribe();
        let listener = tokio::spawn(async move {
            while !*listener_rx.borrow() {
                if listener_rx.changed().await.is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        let wait_shutdown_tx = shutdown_tx.clone();
        let wait = tokio::spawn(wait_for_cp_listeners_until_shutdown_or_exit(
            vec![("CP admin HTTP listener".to_string(), listener)],
            wait_shutdown_tx,
            Duration::from_millis(20),
        ));

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            !wait.is_finished(),
            "CP listener wait must not return before shutdown just because the drain timeout elapsed",
        );

        shutdown_tx
            .send(true)
            .expect("watch send must succeed with live receivers");
        let result = tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("CP listener wait should complete after shutdown")
            .expect("CP listener wait task should not panic");
        result.expect("graceful shutdown must return Ok");
    }

    #[tokio::test]
    async fn cp_listener_exit_triggers_shutdown_and_drains_siblings() {
        let (shutdown_tx, mut observed_shutdown) = tokio::sync::watch::channel(false);

        let grpc = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            while !*admin_http_rx.borrow() {
                if admin_http_rx.changed().await.is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        let result = wait_for_cp_listeners_until_shutdown_or_exit(
            vec![
                ("CP admin HTTP listener".to_string(), admin_http),
                ("CP gRPC server".to_string(), grpc),
            ],
            shutdown_tx,
            Duration::from_secs(1),
        )
        .await;

        let err = result.expect_err("unsolicited listener exit must return Err");
        assert!(
            format!("{err:#}").contains("exited unexpectedly"),
            "error should report unsolicited exit; got {err:#}",
        );

        observed_shutdown
            .changed()
            .await
            .expect("listener exit should send shutdown");
        assert!(
            *observed_shutdown.borrow(),
            "CP listener exit must flip the shared shutdown watch"
        );
    }

    // Regression for the equal-deadline race: an unsolicited listener exit
    // must preserve `first_error` through the drain timeout even when a
    // sibling never observes shutdown. The prior outer `select!` could see
    // the monitor-originated shutdown, start an equal `drain_timeout`, abort
    // the monitor, and return `Ok(())` — losing the failure.
    #[tokio::test]
    async fn cp_listener_exit_applies_drain_timeout_to_stuck_sibling() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let stuck =
            tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
        let stuck_abort = stuck.abort_handle();
        let exited = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_cp_listeners_until_shutdown_or_exit(
                vec![
                    ("stuck listener".to_string(), stuck),
                    ("exited listener".to_string(), exited),
                ],
                shutdown_tx,
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("listener-triggered shutdown must not wait forever on stuck siblings");

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "listener-triggered drain should honor the configured timeout"
        );
        let err =
            result.expect_err("unsolicited exit must still surface as Err after drain timeout");
        assert!(
            format!("{err:#}").contains("exited unexpectedly"),
            "preserved failure must report unsolicited exit; got {err:#}",
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stuck_abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the stuck listener must be aborted at the drain deadline");
    }

    #[tokio::test]
    async fn cp_listener_error_with_stuck_sibling_returns_err_after_drain_timeout() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let stuck =
            tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
        let failing =
            tokio::spawn(async { Err::<(), anyhow::Error>(anyhow::anyhow!("accept loop failed")) });

        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_cp_listeners_until_shutdown_or_exit(
                vec![
                    ("stuck listener".to_string(), stuck),
                    ("failing listener".to_string(), failing),
                ],
                shutdown_tx,
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("listener failure must not wait forever on stuck siblings");

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "error-triggered drain should honor the configured timeout"
        );
        let err = result.expect_err("serve error must surface as Err after drain timeout");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("accept loop failed"),
            "preserved failure must include serve error; got {rendered}",
        );
    }

    #[tokio::test]
    async fn cp_operator_shutdown_with_stuck_listener_returns_ok_after_drain_timeout() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let stuck =
            tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
        let mut draining_rx = shutdown_tx.subscribe();
        let draining = tokio::spawn(async move {
            while !*draining_rx.borrow() {
                if draining_rx.changed().await.is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        shutdown_tx
            .send(true)
            .expect("watch send must succeed with live receivers");

        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_cp_listeners_until_shutdown_or_exit(
                vec![
                    ("stuck listener".to_string(), stuck),
                    ("draining listener".to_string(), draining),
                ],
                shutdown_tx,
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("operator shutdown must not wait forever on stuck listeners");

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "operator drain should honor the configured timeout"
        );
        result.expect("SIGINT/SIGTERM plus stuck listener must stay Ok");
    }

    #[tokio::test]
    async fn cp_operator_shutdown_preserves_listener_error_when_sibling_stuck() {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

        let stuck =
            tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
        let failing = tokio::spawn(async {
            Err::<(), anyhow::Error>(anyhow::anyhow!("failed during operator drain"))
        });

        shutdown_tx
            .send(true)
            .expect("watch send must succeed with live receivers");

        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_cp_listeners_until_shutdown_or_exit(
                vec![
                    ("stuck listener".to_string(), stuck),
                    ("failing listener".to_string(), failing),
                ],
                shutdown_tx,
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("operator shutdown must not wait forever on stuck listeners");

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "operator drain should honor the configured timeout"
        );
        let err = result.expect_err(
            "listener failure during operator shutdown must not be lost to drain timeout",
        );
        assert!(
            format!("{err:#}").contains("failed during operator drain"),
            "preserved failure must include serve error; got {err:#}",
        );
    }
}
