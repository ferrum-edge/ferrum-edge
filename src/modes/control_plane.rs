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
use futures_util::TryStreamExt;
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
use crate::config::db_backend::{self, DatabaseBackend, GatewayTrustBundlePoll, IncrementalResult};
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::config::incremental_apply::apply_incremental_to_config_snapshot as apply_incremental_to_config;
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::cp_server::{CpGrpcServer, CpScope};
use crate::grpc::mesh_registry::{
    MESH_NODE_REGISTRY_REAPER_INTERVAL, mesh_node_registry_stale_ttl,
};
use crate::grpc::mesh_server::MeshGrpcServer;
use crate::modes::mesh::config::TrustBundleSet as MeshTrustBundleSet;
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};
use crate::xds::XdsAdsServer;

#[cfg(test)]
use crate::config::incremental_apply::upsert_by_id;

type CpGrpcIncomingStream =
    Pin<Box<dyn Stream<Item = Result<CpGrpcIo, std::io::Error>> + Send + 'static>>;

enum CpGrpcIo {
    Plain(TcpStream),
    Tls(Box<CpGrpcTlsIo>),
}

struct CpGrpcTlsIo {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

impl AsyncRead for CpGrpcIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
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
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut stream.inner).poll_shutdown(cx),
        }
    }
}

impl Connected for CpGrpcIo {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            Self::Plain(stream) => TcpConnectInfo {
                local_addr: stream.local_addr().ok(),
                remote_addr: stream.peer_addr().ok(),
            },
            Self::Tls(stream) => TcpConnectInfo {
                local_addr: stream.local_addr,
                remote_addr: stream.remote_addr,
            },
        }
    }
}

fn cp_grpc_plain_incoming(listener: tokio::net::TcpListener) -> CpGrpcIncomingStream {
    Box::pin(TcpListenerStream::new(listener).map_ok(CpGrpcIo::Plain))
}

fn cp_grpc_tls_incoming(
    listener: tokio::net::TcpListener,
    tls_slot: crate::tls::SharedFrontendTls,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    handshake_timeout_seconds: u64,
) -> CpGrpcIncomingStream {
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(run_cp_grpc_tls_accept_loop(
        listener,
        tls_slot,
        shutdown_rx,
        handshake_timeout_seconds,
        tx,
    ));
    Box::pin(ReceiverStream::new(rx))
}

async fn run_cp_grpc_tls_accept_loop(
    listener: tokio::net::TcpListener,
    tls_slot: crate::tls::SharedFrontendTls,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    handshake_timeout_seconds: u64,
    tx: tokio::sync::mpsc::Sender<Result<CpGrpcIo, std::io::Error>>,
) {
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
                        let tls_config = tls_slot.load().as_ref().clone();
                        let tx = tx.clone();
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
/// per namespace, then concatenates the per-namespace results into a single
/// `IncrementalResult` so the rest of the polling loop's validate / apply /
/// partition pipeline stays the same.
async fn load_incremental_config_multi(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
    after_sequences: &HashMap<String, u64>,
) -> Result<(IncrementalResult, HashMap<String, u64>), anyhow::Error> {
    if namespaces.len() <= 1 {
        let ns = namespaces.first().map(|s| s.as_str()).unwrap_or("ferrum");
        let after_sequence = after_sequences.get(ns).copied().unwrap_or(0);
        let result = db.load_incremental_config(ns, after_sequence).await?;
        let mut next_sequences = after_sequences.clone();
        next_sequences.insert(ns.to_string(), result.sequence_cursor);
        return Ok((result, next_sequences));
    }

    let mut next_sequences = after_sequences.clone();
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
    for ns in namespaces {
        let after_sequence = after_sequences.get(ns).copied().unwrap_or(0);
        let mut delta = db.load_incremental_config(ns, after_sequence).await?;
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
    Ok((combined, next_sequences))
}

/// Load and merge per-namespace `GatewayConfig`s into a single combined config.
///
/// The CP holds one in-memory `GatewayConfig` even when serving multiple
/// namespaces (so admin / observability paths still see the whole picture).
/// Per-DP broadcasts filter to a single namespace at send time, and the
/// DP-side namespace filter in `dp_client::filter_config_to_namespace` is a
/// defense-in-depth backstop.
async fn load_full_config_multi(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
) -> Result<GatewayConfig, anyhow::Error> {
    if namespaces.len() <= 1 {
        let ns = namespaces.first().map(|s| s.as_str()).unwrap_or("ferrum");
        return db.load_full_config(ns).await;
    }

    // First namespace seeds the loaded_at / version / trust_bundles fields,
    // then we extend with the remaining namespaces' resource vectors.
    let first = namespaces.first().expect("namespaces is non-empty");
    let mut combined = db.load_full_config(first).await?;
    for ns in namespaces.iter().skip(1) {
        let mut next = db.load_full_config(ns).await?;
        combined.proxies.append(&mut next.proxies);
        combined.consumers.append(&mut next.consumers);
        combined.plugin_configs.append(&mut next.plugin_configs);
        combined.upstreams.append(&mut next.upstreams);
        // Per-namespace trust bundles are loaded via the dedicated
        // `load_gateway_trust_bundles` poll path; the combined snapshot
        // keeps the first namespace's value for back-compat with the
        // single-namespace CP. Multi-namespace trust-bundle distribution
        // is a future-work item tracked separately.
    }
    Ok(combined)
}

async fn load_full_config_multi_with_sequence(
    db: &dyn DatabaseBackend,
    namespaces: &[String],
) -> Result<(GatewayConfig, HashMap<String, u64>), anyhow::Error> {
    let mut sequences = HashMap::new();
    if namespaces.is_empty() {
        sequences.insert(
            "ferrum".to_string(),
            db.latest_change_sequence("ferrum").await?,
        );
    }
    for ns in namespaces {
        sequences.insert(ns.clone(), db.latest_change_sequence(ns).await?);
    }
    let config = load_full_config_multi(db, namespaces).await?;
    Ok((config, sequences))
}

/// Partition an `IncrementalResult` by `namespace`, returning a delta for
/// each namespace that has at least one changed or removed resource.
///
/// Resources are matched by their `namespace` field; removed IDs are
/// partitioned via a `(id → namespace)` lookup built from the CP's current
/// accepted config so deletions reach the right per-namespace channel.
fn partition_incremental_by_namespace(
    result: IncrementalResult,
    proxy_ns: &std::collections::HashMap<String, String>,
    consumer_ns: &std::collections::HashMap<String, String>,
    plugin_config_ns: &std::collections::HashMap<String, String>,
    upstream_ns: &std::collections::HashMap<String, String>,
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
    for id in result.removed_proxy_ids {
        if let Some(ns) = proxy_ns.get(&id) {
            buckets
                .entry(ns.clone())
                .or_insert_with(|| make_empty(poll_timestamp))
                .removed_proxy_ids
                .push(id);
        }
    }
    for id in result.removed_consumer_ids {
        if let Some(ns) = consumer_ns.get(&id) {
            buckets
                .entry(ns.clone())
                .or_insert_with(|| make_empty(poll_timestamp))
                .removed_consumer_ids
                .push(id);
        }
    }
    for id in result.removed_plugin_config_ids {
        if let Some(ns) = plugin_config_ns.get(&id) {
            buckets
                .entry(ns.clone())
                .or_insert_with(|| make_empty(poll_timestamp))
                .removed_plugin_config_ids
                .push(id);
        }
    }
    for id in result.removed_upstream_ids {
        if let Some(ns) = upstream_ns.get(&id) {
            buckets
                .entry(ns.clone())
                .or_insert_with(|| make_empty(poll_timestamp))
                .removed_upstream_ids
                .push(id);
        }
    }

    buckets
}

/// Build an `(id → namespace)` lookup from a full config snapshot. Used by
/// the multi-namespace incremental path so removal IDs (which don't carry
/// their own namespace) can still be routed to the right per-namespace
/// broadcast channel.
#[allow(clippy::type_complexity)]
fn build_namespace_lookups(
    config: &GatewayConfig,
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    let proxy_ns = config
        .proxies
        .iter()
        .map(|p| (p.id.clone(), p.namespace.clone()))
        .collect();
    let consumer_ns = config
        .consumers
        .iter()
        .map(|c| (c.id.clone(), c.namespace.clone()))
        .collect();
    let plugin_config_ns = config
        .plugin_configs
        .iter()
        .map(|pc| (pc.id.clone(), pc.namespace.clone()))
        .collect();
    let upstream_ns = config
        .upstreams
        .iter()
        .map(|u| (u.id.clone(), u.namespace.clone()))
        .collect();
    (proxy_ns, consumer_ns, plugin_config_ns, upstream_ns)
}

fn sanitize_gateway_trust_bundles_from_source(
    trust_bundles: Option<Box<MeshTrustBundleSet>>,
    context: &str,
) -> Option<Box<MeshTrustBundleSet>> {
    if let Some(ref trust_bundles) = trust_bundles {
        let errors = crate::modes::mesh::config::validate_mesh_config(
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            Some(trust_bundles),
        );
        if !errors.is_empty() {
            error!(
                "Clearing invalid gateway trust bundles from CP {}: {}",
                context,
                errors.join("; ")
            );
            return None;
        }
    }

    trust_bundles
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

            if let Some(ref replica_url) = effective_replica_url {
                match store.connect_read_replica(replica_url).await {
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

    let (config, initial_change_sequences) =
        load_full_config_multi_with_sequence(db.as_ref(), &polled_namespaces).await?;
    info!(
        "CP mode: loaded {} proxies, {} consumers, {} plugins, {} upstreams across {} namespace(s)",
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len(),
        config.upstreams.len(),
        polled_namespaces.len(),
    );

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
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
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers.
    let startup_ready = Arc::new(AtomicBool::new(false));
    let db_available = Arc::new(AtomicBool::new(true));

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
        startup_ready: Some(startup_ready.clone()),
        db_available: Some(db_available.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: Some(dp_registry.clone()),
        mesh_registry: Some(mesh_registry.clone()),
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
    };
    // Clone admin_state before the HTTP listener moves it, so we can reuse
    // the same JwtManager instance for the HTTPS listener (instead of calling
    // create_jwt_manager_from_env() a second time).
    let admin_state_for_https = admin_state.clone();
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (disabled when port is 0)
    let admin_http_handle = if env_config.admin_http_port != 0 {
        let admin_http_limiter = admin_conn_limiter.clone();
        Some(tokio::spawn(async move {
            info!("Starting Admin HTTP listener on {}", admin_http_addr);
            if let Err(e) = admin::start_admin_listener(
                admin_http_addr,
                admin_state,
                admin_shutdown,
                admin_http_limiter,
            )
            .await
            {
                error!("Admin HTTP listener error: {}", e);
            }
        }))
    } else {
        info!("FERRUM_ADMIN_HTTP_PORT=0 — plaintext admin HTTP listener disabled");
        None
    };

    // Admin HTTPS listener (only if TLS is configured)
    let admin_https_handle = if let (Some(admin_cert_path), Some(admin_key_path)) = (
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

        Some(tokio::spawn(async move {
            info!("Starting Admin HTTPS listener on {}", admin_https_addr);
            let result = if let Some(slot) = admin_tls_slot {
                admin::start_admin_listener_with_dynamic_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    slot,
                    admin_https_limiter,
                )
                .await
            } else {
                admin::start_admin_listener_with_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    Some(admin_tls_config),
                    admin_https_limiter,
                )
                .await
            };
            if let Err(e) = result {
                error!("Admin HTTPS listener error: {}", e);
            }
        }))
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
        None
    };
    if env_config.admin_http_port == 0 && env_config.admin_tls_cert_path.is_none() {
        warn!(
            "No admin API listeners are active — FERRUM_ADMIN_HTTP_PORT=0 and no admin TLS configured. The admin API is unreachable."
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
            if grpc_addr.ip().is_loopback() {
                warn!(
                    "SECURITY: CP gRPC config sync is running in PLAINTEXT on loopback {grpc_addr} \
                     — acceptable for local development only. DP authentication JWTs and the full \
                     gateway configuration are unencrypted. Configure FERRUM_CP_GRPC_TLS_CERT_PATH \
                     + FERRUM_CP_GRPC_TLS_KEY_PATH before exposing this CP off-host."
                );
            } else {
                warn!(
                    "SECURITY: CP gRPC config sync is running in PLAINTEXT on non-loopback \
                     {grpc_addr} because FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true is set. DP \
                     authentication JWTs and the full gateway configuration are exposed UNENCRYPTED \
                     to the network and unprotected against MITM. Use TLS \
                     (FERRUM_CP_GRPC_TLS_CERT_PATH + FERRUM_CP_GRPC_TLS_KEY_PATH) in production."
                );
            }
            None
        };

        let grpc_listener = tokio::net::TcpListener::bind(grpc_addr).await?;
        info!("CP gRPC server listening on {}", grpc_addr);
        let grpc_http2_max_concurrent_streams = env_config.server_http2_max_concurrent_streams;
        let grpc_http2_max_pending_accept_reset_streams =
            env_config.server_http2_max_pending_accept_reset_streams;
        let grpc_http2_max_local_error_reset_streams =
            env_config.server_http2_max_local_error_reset_streams;
        let (grpc_started_tx, grpc_started_rx) = tokio::sync::oneshot::channel();
        let mut grpc_shutdown = shutdown_tx.subscribe();
        let grpc_accept_shutdown = grpc_shutdown.clone();
        let grpc_tls_handshake_timeout_seconds = env_config.frontend_tls_handshake_timeout_seconds;
        let handle = tokio::spawn(async move {
            let mut builder = Server::builder()
                .max_concurrent_streams(Some(grpc_http2_max_concurrent_streams))
                .http2_max_pending_accept_reset_streams(Some(
                    grpc_http2_max_pending_accept_reset_streams,
                ))
                .http2_max_local_error_reset_streams(Some(
                    grpc_http2_max_local_error_reset_streams,
                ));
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
                )
            } else {
                cp_grpc_plain_incoming(grpc_listener)
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
            if let Err(e) = result {
                error!("gRPC server error: {}", e);
            }
        });

        wait_for_start_signals(
            vec![("CP gRPC listener".to_string(), grpc_started_rx)],
            Duration::from_secs(10),
        )
        .await?;

        Some(handle)
    } else {
        info!("CP gRPC listen port is 0 — gRPC listener disabled");
        drop(grpc_server); // consumed by the gRPC spawn when enabled
        drop(mesh_grpc_server); // consumed by the gRPC spawn when enabled
        drop(xds_server);
        None
    };
    // Mark CP as ready — same rationale as database mode: the initial
    // `load_full_config()` proved DB connectivity and loaded a complete config.
    // The polling loop handles ongoing incremental updates, not initial readiness.
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
            broadcasts.clone(),
            cp_scope.clone(),
            dp_registry.clone(),
            mesh_update_tx.clone(),
            mesh_registry.clone(),
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
    let db_available_poll = db_available.clone();
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
    let poll_namespace = env_config.namespace.clone();
    let poll_fallback_namespace = env_config.namespace.clone();
    let dp_registry_poll = dp_registry.clone();
    let poll_cert_expiry_warning_days = env_config.tls_cert_expiry_warning_days;
    let poll_backend_allow_ips = env_config.backend_allow_ips.clone();
    let mesh_registry_poll = mesh_registry.clone();
    let poll_scope = cp_scope.clone();
    let poll_broadcasts = broadcasts.clone();
    let initial_polled_namespaces = polled_namespaces;

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let last_replica_ips: crate::modes::AdminReadReplicaDnsWatermark =
            Arc::new(tokio::sync::Mutex::new(None));
        let mut force_full_reload = false;
        let mut last_polled_namespaces = initial_polled_namespaces;
        let replica_reconnect_in_flight = Arc::new(AtomicBool::new(false));

        let initial_config = config_poll.load_full();
        let mut last_gateway_trust_bundles = initial_config.trust_bundles.clone();
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
                        match load_full_config_multi_with_sequence(db_poll.as_ref(), &nslist).await {
                            Ok((new_config, sequences)) => {
                                // Treat pool swap as a new source snapshot.
                                last_gateway_trust_bundles = new_config.trust_bundles.clone();
                                last_change_sequences = sequences;
                                let new_config_arc = Arc::new(new_config.clone());
                                config_poll.store(new_config_arc.clone());
                                last_polled_namespaces = nslist.clone();
                                force_full_reload = false;
                                db_available_poll.store(true, Ordering::Relaxed);

                                // Per-namespace fan-out. For `Single` this
                                // is one channel; for `Set`/`All` each DP
                                // receives only its own namespace's
                                // resources.
                                for ns in &nslist {
                                    CpGrpcServer::broadcast_namespace_update(
                                        poll_broadcasts.as_ref(),
                                        ns,
                                        &new_config,
                                        &dp_registry_poll,
                                        &poll_scope,
                                    );
                                }
                                MeshGrpcServer::broadcast_full_with_registry(
                                    &mesh_update_tx,
                                    new_config_arc,
                                    &mesh_registry_poll,
                                );
                                debug!("Full config reload complete after DB DNS reconnect");
                            }
                            Err(e) => {
                                error!(
                                    "Authoritative primary full config reload failed after DB DNS reconnect; keeping existing config and retrying: {}",
                                    e
                                );
                                db_available_poll.store(false, Ordering::Relaxed);
                                continue;
                            }
                        }
                    } else {
                        // Resolve the polled namespace list. For `Single`
                        // / `Set` this is the explicit list (no DB call).
                        // For `All`, authoritative namespace discovery runs
                        // once per tick — bounded cost vs. the per-resource
                        // queries that dominate poll time. Snapshot the current
                        // config for per-namespace deletion routing.
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
                        let (
                            current_proxy_ns,
                            current_consumer_ns,
                            current_plugin_config_ns,
                            current_upstream_ns,
                        ) = build_namespace_lookups(&current_snapshot);
                        // Incremental poll — only fetch changes since last poll
                        match load_incremental_config_multi(
                            db_poll.as_ref(),
                            &nslist,
                            &last_change_sequences,
                        )
                        .await
                        {
                            Ok((result, next_change_sequences)) => {
                                db_available_poll.store(true, Ordering::Relaxed);
                                last_polled_namespaces = nslist.clone();
                                if result.is_empty() {
                                    let source_trust_bundles = match db_poll
                                        .load_gateway_trust_bundles(&poll_namespace)
                                        .await
                                    {
                                        Ok(GatewayTrustBundlePoll::Unchanged) => {
                                            last_change_sequences = next_change_sequences;
                                            continue;
                                        }
                                        Ok(GatewayTrustBundlePoll::Current(trust_bundles)) => {
                                            sanitize_gateway_trust_bundles_from_source(
                                                trust_bundles,
                                                "empty incremental poll",
                                            )
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to refresh gateway trust bundles after empty incremental poll; \
                                                 leaving the sequence cursor unchanged so the next poll retries: {}",
                                                e
                                            );
                                            continue;
                                        }
                                    };
                                    if source_trust_bundles != last_gateway_trust_bundles {
                                        let version = result.poll_timestamp.to_rfc3339();
                                        let mut refreshed_config = (*config_poll.load_full()).clone();
                                        refreshed_config.trust_bundles =
                                            source_trust_bundles.clone();
                                        refreshed_config.loaded_at = result.poll_timestamp;
                                        config_poll.store(Arc::new(refreshed_config));
                                        // Trust-bundle-only refreshes are
                                        // gateway-wide (one row), but the
                                        // broadcast is still per-namespace
                                        // because each subscribed channel
                                        // needs the empty-payload tick.
                                        for ns in poll_broadcasts.namespaces() {
                                            CpGrpcServer::broadcast_namespace_delta(
                                                poll_broadcasts.as_ref(),
                                                &ns,
                                                &result,
                                                &version,
                                                &dp_registry_poll,
                                                source_trust_bundles.as_deref(),
                                                &poll_scope,
                                            );
                                        }
                                        last_gateway_trust_bundles =
                                            source_trust_bundles;
                                    }
                                    last_change_sequences = next_change_sequences;
                                    continue;
                                }
                                let poll_ts = result.poll_timestamp;

                                // Apply delta to a cloned config, then validate
                                // before broadcasting or advancing the sequence cursor.
                                // Mirrors database mode's validate-before-swap
                                // contract via ProxyState::apply_incremental.
                                let mut new_config = (*config_poll.load_full()).clone();
                                apply_incremental_to_config(&mut new_config, result.clone());
                                new_config.normalize_fields();
                                new_config.resolve_upstream_tls();

                                // Warn-only validators (same as
                                // ProxyState::validate_full_config).
                                if let Err(errors) = new_config.validate_all_fields_with_ip_policy(
                                    poll_cert_expiry_warning_days,
                                    &poll_backend_allow_ips,
                                ) {
                                    for msg in &errors {
                                        warn!("CP config field validation: {}", msg);
                                    }
                                }
                                if let Err(errors) = new_config.validate_hosts() {
                                    for msg in &errors {
                                        warn!("CP config validation: {}", msg);
                                    }
                                }

                                // Rejecting validators — collect all failures so
                                // operators see every reason in a single poll cycle.
                                let mut validation_errors: Vec<String> = Vec::new();
                                if let Err(errs) = new_config.validate_regex_listen_paths() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) = new_config.validate_listen_path_encodings() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) = new_config.validate_unique_listen_paths() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) = new_config.validate_stream_proxies() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) = new_config.validate_upstream_references() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) = new_config.validate_plugin_references() {
                                    validation_errors.extend(errs);
                                }
                                if let Err(errs) =
                                    crate::proxy::validate_mesh_route_dispatch_upstream_references(
                                        &new_config,
                                    )
                                {
                                    validation_errors.extend(errs);
                                }
                                if !validation_errors.is_empty() {
                                    for msg in &validation_errors {
                                        error!("CP incremental config rejected: {}", msg);
                                    }
                                    warn!(
                                        "Incremental config update rejected by validation; \
                                         leaving the sequence cursor unchanged so the next poll \
                                         retries the same rows"
                                    );
                                    continue;
                                }

                                let mut trust_bundles_changed = false;
                                match db_poll.load_gateway_trust_bundles(&poll_namespace).await {
                                    Ok(GatewayTrustBundlePoll::Unchanged) => {}
                                    Ok(GatewayTrustBundlePoll::Current(trust_bundles)) => {
                                        let source_trust_bundles =
                                            sanitize_gateway_trust_bundles_from_source(
                                            trust_bundles,
                                            "incremental poll",
                                        );
                                        if source_trust_bundles != last_gateway_trust_bundles {
                                            new_config.trust_bundles =
                                                source_trust_bundles.clone();
                                            trust_bundles_changed = true;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to refresh gateway trust bundles during incremental poll; \
                                             applying resource delta with previous trust material: {}",
                                            e
                                        );
                                    }
                                }

                                // Validation passed — broadcast the delta to DPs
                                // and store the new config before advancing the cursor.
                                // Apply to CP's own in-memory config before broadcasting so
                                // subscribers that connect during this poll either receive the
                                // queued delta or load a snapshot that already contains it.
                                // The local apply needs to consume an `IncrementalResult`, so
                                // we clone exactly once for it; the CP broadcast borrows
                                // (serializes to JSON), and the mesh broadcast consumes the
                                // original — keeping the per-poll clone count to one.
                                let version = poll_ts.to_rfc3339();
                                let new_config = Arc::new(new_config);
                                config_poll.store(new_config.clone());

                                // Mesh streams render their per-subscriber slices from the
                                // same delta payload. DP and mesh broadcasts are intentionally
                                // coupled to the same polling cycle so both subscriber types
                                // converge on the same config version simultaneously.
                                //
                                // Per-namespace fan-out: partition the result
                                // by namespace and send each partition to
                                // its dedicated broadcast channel. For
                                // `Single` scope this collapses to one
                                // partition (= identical to pre-T2-A
                                // behavior). For `Set`/`All` each DP sees
                                // only its own namespace's resources.
                                let trust_bundles_for_broadcast = if trust_bundles_changed {
                                    new_config.trust_bundles.as_deref()
                                } else {
                                    None
                                };
                                let partitions = partition_incremental_by_namespace(
                                    result.clone(),
                                    &current_proxy_ns,
                                    &current_consumer_ns,
                                    &current_plugin_config_ns,
                                    &current_upstream_ns,
                                );
                                for (ns, ns_delta) in &partitions {
                                    CpGrpcServer::broadcast_namespace_delta(
                                        poll_broadcasts.as_ref(),
                                        ns,
                                        ns_delta,
                                        &version,
                                        &dp_registry_poll,
                                        trust_bundles_for_broadcast,
                                        &poll_scope,
                                    );
                                }
                                if trust_bundles_changed {
                                    last_gateway_trust_bundles = new_config.trust_bundles.clone();
                                }
                                MeshGrpcServer::broadcast_delta_with_registry(&mesh_update_tx, result, &version, &mesh_registry_poll);

                                info!(
                                    "Incremental config update validated and pushed to {} namespace(s) (version={})",
                                    partitions.len(),
                                    version
                                );
                                last_change_sequences = next_change_sequences;
                            }
                            Err(e) => {
                                warn!(
                                    "Authoritative primary incremental poll failed, falling back to full reload: {}",
                                    e
                                );
                                // Fallback to full config load + full snapshot broadcast
                                match load_full_config_multi_with_sequence(db_poll.as_ref(), &nslist).await {
                                    Ok((new_config, sequences)) => {
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        last_polled_namespaces = nslist.clone();
                                        last_change_sequences = sequences;
                                        last_gateway_trust_bundles = new_config.trust_bundles.clone();
                                        let new_config_arc = Arc::new(new_config.clone());
                                        config_poll.store(new_config_arc.clone());
                                        for ns in &nslist {
                                            CpGrpcServer::broadcast_namespace_update(
                                                poll_broadcasts.as_ref(),
                                                ns,
                                                &new_config,
                                                &dp_registry_poll,
                                                &poll_scope,
                                            );
                                        }
                                        MeshGrpcServer::broadcast_full_with_registry(&mesh_update_tx, new_config_arc, &mesh_registry_poll);
                                        info!("Configuration reloaded from database (full fallback) and pushed to DPs and mesh nodes");
                                    }
                                    Err(e2) => {
                                        // Both incremental and full reload failed —
                                        // try failover URLs before giving up.
                                        match db_poll.try_failover_reconnect(&db_url_for_reconnect).await {
                                            Ok(_url) => {
                                                match load_full_config_multi_with_sequence(db_poll.as_ref(), &nslist).await {
                                                    Ok((new_config, sequences)) => {
                                                        db_available_poll.store(true, Ordering::Relaxed);
                                                        last_polled_namespaces = nslist.clone();
                                                        last_change_sequences = sequences;
                                                        last_gateway_trust_bundles = new_config.trust_bundles.clone();
                                                        let new_config_arc = Arc::new(new_config.clone());
                                                        config_poll.store(new_config_arc.clone());
                                                        for ns in &nslist {
                                                            CpGrpcServer::broadcast_namespace_update(
                                                                poll_broadcasts.as_ref(),
                                                                ns,
                                                                &new_config,
                                                                &dp_registry_poll,
                                                                &poll_scope,
                                                            );
                                                        }
                                                        MeshGrpcServer::broadcast_full_with_registry(&mesh_update_tx, new_config_arc, &mesh_registry_poll);
                                                        info!("Configuration reloaded from database (failover) and pushed to DPs and mesh nodes");
                                                    }
                                                    Err(e3) => {
                                                        db_available_poll.store(false, Ordering::Relaxed);
                                                        warn!(
                                                            "Authoritative primary failover reload also failed (serving cached): {}",
                                                            e3
                                                        );
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

                }
                _ = cp_poll_shutdown.changed() => {
                    info!("CP database polling shutting down");
                    return;
                }
            }
        }
    });

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
    // Reuses `crate::modes::file::await_listener_handles` to mirror file/db
    // mode's shutdown shape:
    //
    // 1. On the shutdown signal, every listener observes it via its own
    //    `shutdown_tx.subscribe()` receiver and exits gracefully —
    //    `serve_with_incoming_shutdown` for gRPC (so tonic completes
    //    in-flight RPCs and `TrackedStream`'s `Drop` deregisters the DP
    //    from `DpNodeRegistry`), and the watch-driven shutdown loops for
    //    admin HTTP/HTTPS.
    // 2. If a listener panics, `await_listener_handles` fires the
    //    `shutdown_on_panic` trigger so the remaining listeners observe
    //    shutdown and exit promptly. The previous `tokio::select!`
    //    instead detached the still-serving handles (the inner async
    //    blocks were cancelled, dropping the moved `JoinHandle`s, which
    //    detaches rather than aborts) — those listeners then died
    //    abruptly when the runtime torn down at function return,
    //    cutting in-flight DP streams without graceful drain and
    //    yielding a partial-shutdown anomaly.
    let mut listener_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(handle) = admin_http_handle {
        listener_handles.push(handle);
    }
    if let Some(handle) = grpc_handle {
        listener_handles.push(handle);
    }
    if let Some(handle) = admin_https_handle {
        listener_handles.push(handle);
    }

    wait_for_cp_listeners_until_shutdown_or_exit(
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
        db_poll_handle,
        mesh_registry_reaper_handle,
        runtime_system_handle,
        runtime_window_handle,
    ];
    if let Some(handle) = db_tls_reload_handle {
        background_handles.push(handle);
    }
    crate::modes::file::join_background_handles(background_handles, Duration::from_secs(5)).await;

    Ok(())
}

async fn wait_for_cp_listeners_until_shutdown_or_exit(
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    drain_timeout: Duration,
) {
    if listener_handles.is_empty() {
        wait_for_cp_shutdown(&shutdown_tx).await;
        info!("Shutdown signal received with no active listeners");
        return;
    }

    let listener_shutdown_tx = shutdown_tx.clone();
    let mut listener_monitor = tokio::spawn(async move {
        monitor_cp_listener_handles_until_exit(
            listener_handles,
            listener_shutdown_tx,
            drain_timeout,
        )
        .await
    });
    tokio::select! {
        result = &mut listener_monitor => {
            log_cp_listener_monitor_result(result);
        }
        _ = wait_for_cp_shutdown(&shutdown_tx) => {
            match tokio::time::timeout(drain_timeout, &mut listener_monitor).await {
                Ok(result) => {
                    log_cp_listener_monitor_result(result);
                }
                Err(_) => {
                    warn!("Timed out waiting for CP listeners to drain after shutdown");
                    listener_monitor.abort();
                }
            }
        }
    }
}

async fn monitor_cp_listener_handles_until_exit(
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    drain_timeout: Duration,
) -> Result<(), tokio::task::JoinError> {
    let (first_result, _idx, remaining) = futures_util::future::select_all(listener_handles).await;
    info!("CP listener task exited; triggering control-plane shutdown");
    let _ = shutdown_tx.send(true);

    let remaining_result = if remaining.is_empty() {
        Ok(())
    } else {
        let shutdown_on_panic = {
            let shutdown_tx = shutdown_tx.clone();
            move || {
                let _ = shutdown_tx.send(true);
            }
        };
        let mut remaining_monitor = tokio::spawn(async move {
            crate::modes::file::await_listener_handles(remaining, shutdown_on_panic).await
        });
        match tokio::time::timeout(drain_timeout, &mut remaining_monitor).await {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => Err(err),
            Err(_) => {
                warn!("Timed out waiting for remaining CP listeners to drain after listener exit");
                remaining_monitor.abort();
                Ok(())
            }
        }
    };

    match (first_result, remaining_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
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

fn log_cp_listener_monitor_result(
    result: Result<Result<(), tokio::task::JoinError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!("CP listener task failed: {}", err);
        }
        Err(err) => {
            error!("CP listener monitor task failed: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_backend::IncrementalResult;
    use crate::config::types::*;
    use chrono::Utc;
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
    fn partition_incremental_routes_removed_ids_with_pre_delete_lookup() {
        let mut proxy = make_proxy("p1");
        proxy.namespace = "tenant-a".to_string();
        let current = GatewayConfig {
            proxies: vec![proxy],
            ..Default::default()
        };
        let (proxy_ns, consumer_ns, plugin_config_ns, upstream_ns) =
            build_namespace_lookups(&current);
        let mut result = empty_incremental();
        result.removed_proxy_ids = vec!["p1".to_string()];

        let partitions = partition_incremental_by_namespace(
            result,
            &proxy_ns,
            &consumer_ns,
            &plugin_config_ns,
            &upstream_ns,
        );
        let tenant_delta = partitions
            .get("tenant-a")
            .expect("removed proxy should be routed to its previous namespace");
        assert_eq!(tenant_delta.removed_proxy_ids, vec!["p1"]);
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
        inc.removed_proxy_ids = vec!["p1".to_string()];
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
        inc.removed_proxy_ids = vec!["remove".to_string()];
        inc.added_or_modified_proxies = vec![make_proxy("added")];
        inc.removed_consumer_ids = vec!["c1".to_string()];
        inc.added_or_modified_consumers = vec![make_consumer("c2")];
        apply_incremental_to_config(&mut config, inc);

        assert_eq!(config.proxies.len(), 2);
        assert!(config.proxies.iter().any(|p| p.id == "keep"));
        assert!(config.proxies.iter().any(|p| p.id == "added"));
        assert!(!config.proxies.iter().any(|p| p.id == "remove"));
        assert_eq!(config.consumers.len(), 1);
        assert_eq!(config.consumers[0].id, "c2");
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
    // The fix routes the listener handles through
    // `crate::modes::file::await_listener_handles`, which both:
    //   1. Awaits ALL handles concurrently so a single exit does not
    //      strand the others; and
    //   2. Fires `shutdown_on_panic` on the first panic so the remaining
    //      listeners observe the shared shutdown watch channel via their
    //      own subscribers and exit promptly.
    //
    // This test models that with three fake CP listeners (admin_http,
    // grpc, admin_https). One panics; the other two must still drain
    // cleanly through the watch trigger fired by `shutdown_on_panic`.
    // Bound the wait at 2 s — without the trigger, the remaining
    // listeners would block forever on their watch receivers.
    #[tokio::test]
    async fn cp_shutdown_drains_remaining_listeners_when_one_panics() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            let _ = admin_http_rx.changed().await;
        });

        let grpc = tokio::spawn(async {
            panic!("simulated gRPC listener crash");
        });

        let mut admin_https_rx = shutdown_tx.subscribe();
        let admin_https = tokio::spawn(async move {
            let _ = admin_https_rx.changed().await;
        });

        // Mirror the CP run() composition: collect Some-handles into a
        // Vec, then drive them through await_listener_handles with a
        // panic trigger that flips the shared shutdown watch.
        let listener_handles: Vec<tokio::task::JoinHandle<()>> =
            vec![admin_http, grpc, admin_https];

        let trigger_tx = shutdown_tx.clone();
        let started = Instant::now();
        let result = crate::modes::file::await_listener_handles(listener_handles, move || {
            let _ = trigger_tx.send(true);
        })
        .await;
        let elapsed = started.elapsed();

        // The panicking gRPC listener must surface as a JoinError…
        let err = result.expect_err("the gRPC listener panicked, helper must return Err");
        assert!(
            err.is_panic(),
            "JoinError should report `is_panic()` for a panicked listener; got {err:?}",
        );
        // …and the admin HTTP/HTTPS listeners must have observed the
        // shutdown trigger and exited promptly. Without the trigger
        // they would hang on their watch receivers forever.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "remaining listeners should drain via shutdown trigger; took {elapsed:?}",
        );
    }

    // Sanity: when no listener panics and the shared shutdown watch is
    // simply set to true (the normal SIGTERM path), every listener's
    // own `.subscribe()` receiver fires `changed()` and the helper
    // returns Ok without ever invoking the panic trigger. This verifies
    // the "happy path" is preserved end-to-end through the same
    // composition the CP mode uses.
    #[tokio::test]
    async fn cp_shutdown_drains_all_listeners_on_signal() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            let _ = admin_http_rx.changed().await;
        });
        let mut grpc_rx = shutdown_tx.subscribe();
        let grpc = tokio::spawn(async move {
            let _ = grpc_rx.changed().await;
        });
        let mut admin_https_rx = shutdown_tx.subscribe();
        let admin_https = tokio::spawn(async move {
            let _ = admin_https_rx.changed().await;
        });

        let triggered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        // Fire shutdown after spawning so the listeners are already
        // parked on changed() — models the SIGTERM path.
        shutdown_tx
            .send(true)
            .expect("watch send must succeed with live receivers");

        let result = crate::modes::file::await_listener_handles(
            vec![admin_http, grpc, admin_https],
            move || {
                triggered_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            },
        )
        .await;
        result.expect("no listener panicked; helper must return Ok");
        assert!(
            !triggered.load(std::sync::atomic::Ordering::SeqCst),
            "panic trigger must NOT fire on a clean shutdown",
        );
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
        });

        let wait_shutdown_tx = shutdown_tx.clone();
        let wait = tokio::spawn(wait_for_cp_listeners_until_shutdown_or_exit(
            vec![listener],
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
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("CP listener wait should complete after shutdown")
            .expect("CP listener wait task should not panic");
    }

    #[tokio::test]
    async fn cp_listener_exit_triggers_shutdown_and_drains_siblings() {
        let (shutdown_tx, mut observed_shutdown) = tokio::sync::watch::channel(false);

        let grpc = tokio::spawn(async {});

        let mut admin_http_rx = shutdown_tx.subscribe();
        let admin_http = tokio::spawn(async move {
            while !*admin_http_rx.borrow() {
                if admin_http_rx.changed().await.is_err() {
                    break;
                }
            }
        });

        wait_for_cp_listeners_until_shutdown_or_exit(
            vec![admin_http, grpc],
            shutdown_tx,
            Duration::from_secs(1),
        )
        .await;

        observed_shutdown
            .changed()
            .await
            .expect("listener exit should send shutdown");
        assert!(
            *observed_shutdown.borrow(),
            "CP listener exit must flip the shared shutdown watch"
        );
    }

    #[tokio::test]
    async fn cp_listener_exit_applies_drain_timeout_to_stuck_sibling() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let stuck = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let exited = tokio::spawn(async {});

        let started = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_cp_listeners_until_shutdown_or_exit(
                vec![stuck, exited],
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
    }
}
