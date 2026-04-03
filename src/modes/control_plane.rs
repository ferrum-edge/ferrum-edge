//! Control Plane mode — config broker with no proxy.
//!
//! The CP polls the database using the same incremental strategy as database
//! mode, but instead of proxying traffic, it broadcasts config deltas to
//! connected Data Planes via a tokio `broadcast` channel → gRPC `Subscribe`
//! stream. On incremental poll failure, it falls back to a full reload and
//! broadcasts a `FULL_SNAPSHOT` to all DPs.
//!
//! The admin API is read/write (same as database mode). The CP validates
//! DP client JWT tokens using `FERRUM_CP_GRPC_JWT_SECRET` and enforces
//! `major.minor` version compatibility between CP and DP.

use arc_swap::ArcSwap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::{Certificate, Identity};
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::cp_server::CpGrpcServer;
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let failover_urls = env_config.effective_db_failover_urls();
    let pool_config = DbPoolConfig {
        max_connections: env_config.db_pool_max_connections,
        min_connections: env_config.db_pool_min_connections,
        acquire_timeout_seconds: env_config.db_pool_acquire_timeout_seconds,
        idle_timeout_seconds: env_config.db_pool_idle_timeout_seconds,
        max_lifetime_seconds: env_config.db_pool_max_lifetime_seconds,
    };
    let mut db = DatabaseStore::connect_with_failover(
        env_config.db_type.as_deref().unwrap_or("sqlite"),
        &effective_url,
        &failover_urls,
        env_config.db_tls_enabled,
        env_config.db_tls_ca_cert_path.as_deref(),
        env_config.db_tls_client_cert_path.as_deref(),
        env_config.db_tls_client_key_path.as_deref(),
        env_config.db_tls_insecure,
        pool_config,
    )
    .await?;

    db.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);

    // Connect read replica for config polling (reduces primary load)
    let effective_replica_url = env_config.effective_db_read_replica_url();
    if let Some(ref replica_url) = effective_replica_url {
        match db
            .connect_read_replica(
                replica_url,
                env_config.db_tls_enabled,
                env_config.db_tls_ca_cert_path.as_deref(),
                env_config.db_tls_client_cert_path.as_deref(),
                env_config.db_tls_client_key_path.as_deref(),
                env_config.db_tls_insecure,
            )
            .await
        {
            Ok(()) => info!("Read replica connected for config polling"),
            Err(e) => warn!(
                "Read replica connection failed, polling will use primary: {}",
                e
            ),
        }
    }

    let config = db.load_full_config().await?;
    info!(
        "CP mode: loaded {} proxies, {} consumers",
        config.proxies.len(),
        config.consumers.len()
    );

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let db = Arc::new(db);

    let grpc_secret = match env_config.cp_grpc_jwt_secret.clone() {
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            return Err(anyhow::anyhow!(
                "FERRUM_CP_GRPC_JWT_SECRET must be set and non-empty in control plane mode. \
                 Without it, any client can forge valid gRPC authentication tokens."
            ));
        }
    };

    // Create gRPC server
    let (grpc_server, update_tx) = CpGrpcServer::new(config_arc.clone(), grpc_secret);

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;

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
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(config_arc.clone()),
        proxy_state: None,
        mode: "cp".into(),
        read_only: env_config.admin_read_only,
        startup_ready: Some(startup_ready.clone()),
        db_available: Some(db_available.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
    };
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (always enabled)
    let admin_http_handle = tokio::spawn(async move {
        info!("Starting Admin HTTP listener on {}", admin_http_addr);
        if let Err(e) =
            admin::start_admin_listener(admin_http_addr, admin_state, admin_shutdown).await
        {
            error!("Admin HTTP listener error: {}", e);
        }
    });

    // Admin HTTPS listener (only if TLS is configured)
    let admin_https_handle = if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_state_for_https = AdminState {
            db: Some(db.clone()),
            jwt_manager: create_jwt_manager_from_env()
                .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?,
            cached_config: Some(config_arc.clone()),
            proxy_state: None,
            mode: "cp".into(),
            read_only: env_config.admin_read_only,
            startup_ready: Some(startup_ready.clone()),
            db_available: Some(db_available.clone()),
            admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
            reserved_ports: reserved_ports.clone(),
            stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        };
        let admin_https_shutdown = shutdown_tx.subscribe();

        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth(
            admin_cert_path,
            admin_key_path,
            admin_client_ca_bundle,
            env_config.admin_tls_no_verify,
            &tls_policy,
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
                Some(config)
            }
            Err(e) => {
                error!("Failed to load admin TLS configuration: {}", e);
                return Err(anyhow::anyhow!("Invalid admin TLS configuration: {}", e));
            }
        };

        Some(tokio::spawn(async move {
            info!("Starting Admin HTTPS listener on {}", admin_https_addr);
            if let Err(e) = admin::start_admin_listener_with_tls(
                admin_https_addr,
                admin_state_for_https,
                admin_https_shutdown,
                admin_tls_config,
            )
            .await
            {
                error!("Admin HTTPS listener error: {}", e);
            }
        }))
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
        None
    };

    // gRPC listener (with optional TLS/mTLS)
    let grpc_addr: SocketAddr = if let Some(ref addr) = env_config.cp_grpc_listen_addr {
        addr.parse()?
    } else {
        env_config.admin_socket_addr(50051)
    };

    let grpc_tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.cp_grpc_tls_cert_path,
        &env_config.cp_grpc_tls_key_path,
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read CP gRPC TLS cert {}: {}", cert_path, e))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read CP gRPC TLS key {}: {}", key_path, e))?;

        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(&cert_pem, &key_pem));

        if let Some(client_ca_path) = &env_config.cp_grpc_tls_client_ca_path {
            let ca_pem = std::fs::read(client_ca_path).map_err(|e| {
                anyhow::anyhow!("Failed to read CP gRPC client CA {}: {}", client_ca_path, e)
            })?;
            tls = tls.client_ca_root(Certificate::from_pem(&ca_pem));
            info!(
                "CP gRPC TLS configured with mTLS (server cert: {}, client CA: {})",
                cert_path, client_ca_path
            );
        } else {
            info!(
                "CP gRPC TLS configured (server cert: {}, no client verification)",
                cert_path
            );
        }
        Some(tls)
    } else {
        if env_config.cp_grpc_tls_client_ca_path.is_some() {
            warn!(
                "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH is set but cert/key are missing — ignoring client CA"
            );
        }
        info!("CP gRPC server running in plaintext mode (no TLS configured)");
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
    let grpc_handle = tokio::spawn(async move {
        let mut builder = Server::builder()
            .max_concurrent_streams(Some(grpc_http2_max_concurrent_streams))
            .http2_max_pending_accept_reset_streams(Some(
                grpc_http2_max_pending_accept_reset_streams,
            ))
            .http2_max_local_error_reset_streams(Some(grpc_http2_max_local_error_reset_streams));
        if let Some(tls) = grpc_tls_config {
            builder = match builder.tls_config(tls) {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to configure gRPC TLS: {}", e);
                    return;
                }
            };
        }
        let shutdown_signal = async move {
            while !*grpc_shutdown.borrow() {
                if grpc_shutdown.changed().await.is_err() {
                    return;
                }
            }
            info!("CP gRPC server shutting down");
        };
        let incoming = TcpListenerStream::new(grpc_listener);
        let _ = grpc_started_tx.send(());
        if let Err(e) = builder
            .add_service(grpc_server.into_service())
            .serve_with_incoming_shutdown(incoming, shutdown_signal)
            .await
        {
            error!("gRPC server error: {}", e);
        }
    });

    wait_for_start_signals(
        vec![("CP gRPC listener".to_string(), grpc_started_rx)],
        Duration::from_secs(10),
    )
    .await?;
    startup_ready.store(true, Ordering::Relaxed);
    info!("Control plane startup complete; /health now reports ready");

    // Database polling loop -> push incremental deltas to DPs (with shutdown).
    //
    // Uses the same incremental polling strategy as database mode: indexed
    // `updated_at > ?` queries + lightweight ID queries for deletion detection.
    // Deltas are broadcast as DELTA updates; DPs apply them via apply_incremental.
    // Falls back to FULL_SNAPSHOT on incremental poll failure.
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let config_poll = config_arc.clone();
    let db_available_poll = db_available.clone();
    let mut cp_poll_shutdown = shutdown_tx.subscribe();

    // DNS re-resolution for the database FQDN (same as database mode).
    // CP mode doesn't run a proxy, but still needs to detect DB IP changes.
    let db_hostname = DatabaseStore::extract_db_hostname(&effective_url);
    let replica_hostname = effective_replica_url
        .as_deref()
        .and_then(DatabaseStore::extract_db_hostname);
    let dns_cache_for_poll = DnsCache::new(DnsConfig {
        default_ttl_seconds: env_config.dns_cache_ttl_seconds,
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        valid_ttl_override: env_config.dns_valid_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
    });
    let db_url_for_reconnect = effective_url.clone();
    let replica_url_for_reconnect = effective_replica_url.clone();
    let db_tls_enabled = env_config.db_tls_enabled;
    let db_tls_ca_cert = env_config.db_tls_ca_cert_path.clone();
    let db_tls_client_cert = env_config.db_tls_client_cert_path.clone();
    let db_tls_client_key = env_config.db_tls_client_key_path.clone();
    let db_tls_insecure = env_config.db_tls_insecure;

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let mut last_replica_ips: Option<Vec<IpAddr>> = None;

        // Seed incremental state from the initial config load
        let initial_config = config_poll.load_full();
        let (
            mut known_proxy_ids,
            mut known_consumer_ids,
            mut known_plugin_config_ids,
            mut known_upstream_ids,
        ) = DatabaseStore::extract_known_ids(&initial_config);
        let mut last_poll_at: Option<chrono::DateTime<chrono::Utc>> =
            Some(initial_config.loaded_at);

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
                            if let Err(e) = db_poll.reconnect(
                                &db_url_for_reconnect,
                                db_tls_enabled,
                                db_tls_ca_cert.as_deref(),
                                db_tls_client_cert.as_deref(),
                                db_tls_client_key.as_deref(),
                                db_tls_insecure,
                            ).await {
                                error!(
                                    "Failed to reconnect database pool after DNS change for '{}': {}",
                                    hostname, e
                                );
                            }
                        }
                        last_db_ips = Some(ips);
                    }

                    // Check if the read replica FQDN now resolves to different IPs
                    if let Some(ref replica_hostname) = replica_hostname
                        && let Some(ref replica_url) = replica_url_for_reconnect
                        && let Ok(ips) = dns_cache_for_poll.resolve_all(replica_hostname, None, None).await
                    {
                        let needs_reconnect = match &last_replica_ips {
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
                                "Read replica DNS changed for '{}': {:?} -> {:?}, reconnecting replica pool",
                                replica_hostname, last_replica_ips.as_deref().unwrap_or(&[]), ips
                            );
                            if let Err(e) = db_poll.reconnect_read_replica(
                                replica_url,
                                db_tls_enabled,
                                db_tls_ca_cert.as_deref(),
                                db_tls_client_cert.as_deref(),
                                db_tls_client_key.as_deref(),
                                db_tls_insecure,
                            ).await {
                                error!(
                                    "Failed to reconnect read replica pool after DNS change for '{}': {}",
                                    replica_hostname, e
                                );
                            }
                        }
                        last_replica_ips = Some(ips);
                    }

                    if let Some(since) = last_poll_at {
                        // Incremental poll — only fetch changes since last poll
                        match db_poll.load_incremental_config(
                            since,
                            &known_proxy_ids,
                            &known_consumer_ids,
                            &known_plugin_config_ids,
                            &known_upstream_ids,
                        ).await {
                            Ok(result) => {
                                db_available_poll.store(true, Ordering::Relaxed);
                                if result.is_empty() {
                                    last_poll_at = Some(result.poll_timestamp);
                                    continue;
                                }
                                let poll_ts = result.poll_timestamp;

                                // Update known IDs (add new, remove deleted)
                                update_known_ids(
                                    &mut known_proxy_ids,
                                    &result.added_or_modified_proxies.iter().map(|p| p.id.clone()).collect(),
                                    &result.removed_proxy_ids,
                                );
                                update_known_ids(
                                    &mut known_consumer_ids,
                                    &result.added_or_modified_consumers.iter().map(|c| c.id.clone()).collect(),
                                    &result.removed_consumer_ids,
                                );
                                update_known_ids(
                                    &mut known_plugin_config_ids,
                                    &result.added_or_modified_plugin_configs.iter().map(|pc| pc.id.clone()).collect(),
                                    &result.removed_plugin_config_ids,
                                );
                                update_known_ids(
                                    &mut known_upstream_ids,
                                    &result.added_or_modified_upstreams.iter().map(|u| u.id.clone()).collect(),
                                    &result.removed_upstream_ids,
                                );

                                // Broadcast delta to DPs before updating local config
                                // so that a DP calling GetFullConfig immediately after
                                // receives the new version.
                                let version = poll_ts.to_rfc3339();
                                CpGrpcServer::broadcast_delta(&update_tx, &result, &version);

                                // Apply to CP's own in-memory config (for GetFullConfig
                                // and the Admin API cached_config reads).
                                // Clone current config, apply incremental changes, store.
                                let mut new_config = (*config_poll.load_full()).clone();
                                apply_incremental_to_config(&mut new_config, result);
                                new_config.normalize_fields();
                                new_config.loaded_at = poll_ts;
                                config_poll.store(Arc::new(new_config));

                                info!("Incremental config update pushed to DPs");
                                last_poll_at = Some(poll_ts);
                            }
                            Err(e) => {
                                warn!(
                                    "Incremental poll failed, falling back to full reload: {}",
                                    e
                                );
                                // Fallback to full config load + full snapshot broadcast
                                match db_poll.load_full_config().await {
                                    Ok(new_config) => {
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        let (p, c, pc, u) = DatabaseStore::extract_known_ids(&new_config);
                                        known_proxy_ids = p;
                                        known_consumer_ids = c;
                                        known_plugin_config_ids = pc;
                                        known_upstream_ids = u;
                                        last_poll_at = Some(new_config.loaded_at);
                                        config_poll.store(Arc::new(new_config.clone()));
                                        CpGrpcServer::broadcast_update(&update_tx, &new_config);
                                        info!("Configuration reloaded from database (full fallback) and pushed to DPs");
                                    }
                                    Err(e2) => {
                                        // Both incremental and full reload failed —
                                        // try failover URLs before giving up.
                                        match db_poll.try_failover_reconnect(
                                            &db_url_for_reconnect,
                                            db_tls_enabled,
                                            db_tls_ca_cert.as_deref(),
                                            db_tls_client_cert.as_deref(),
                                            db_tls_client_key.as_deref(),
                                            db_tls_insecure,
                                        ).await {
                                            Ok(_url) => {
                                                match db_poll.load_full_config().await {
                                                    Ok(new_config) => {
                                                        db_available_poll.store(true, Ordering::Relaxed);
                                                        let (p, c, pc, u) = DatabaseStore::extract_known_ids(&new_config);
                                                        known_proxy_ids = p;
                                                        known_consumer_ids = c;
                                                        known_plugin_config_ids = pc;
                                                        known_upstream_ids = u;
                                                        last_poll_at = Some(new_config.loaded_at);
                                                        config_poll.store(Arc::new(new_config.clone()));
                                                        CpGrpcServer::broadcast_update(&update_tx, &new_config);
                                                        info!("Configuration reloaded from database (failover) and pushed to DPs");
                                                    }
                                                    Err(e3) => {
                                                        db_available_poll.store(false, Ordering::Relaxed);
                                                        warn!(
                                                            "Failover reload also failed (serving cached): {}",
                                                            e3
                                                        );
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                db_available_poll.store(false, Ordering::Relaxed);
                                                warn!(
                                                    "Full config reload also failed (serving cached): {}",
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

    // Wait for all listener handles (these exit when the shutdown signal fires)
    tokio::select! {
        _ = admin_http_handle => {}
        _ = grpc_handle => {}
        _ = async {
            if let Some(handle) = admin_https_handle {
                handle.await
            } else {
                std::future::pending().await
            }
        } => {}
    }

    // Wait for background tasks to drain cleanly, with a timeout to prevent
    // hanging if a task is stuck (e.g., blocked on a DB query).
    if tokio::time::timeout(Duration::from_secs(5), db_poll_handle)
        .await
        .is_err()
    {
        warn!("Background tasks did not drain within 5s, proceeding with shutdown");
    }

    Ok(())
}

/// Apply an incremental result to a config snapshot in-place.
///
/// Removes deleted resources by ID, then upserts added/modified resources.
/// This keeps the CP's in-memory config in sync without a full DB reload.
fn apply_incremental_to_config(
    config: &mut crate::config::types::GatewayConfig,
    result: crate::config::db_loader::IncrementalResult,
) {
    use std::collections::HashSet;

    // Remove deleted resources
    let removed_proxies: HashSet<&str> = result
        .removed_proxy_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_consumers: HashSet<&str> = result
        .removed_consumer_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_plugins: HashSet<&str> = result
        .removed_plugin_config_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_upstreams: HashSet<&str> = result
        .removed_upstream_ids
        .iter()
        .map(|s| s.as_str())
        .collect();

    config
        .proxies
        .retain(|p| !removed_proxies.contains(p.id.as_str()));
    config
        .consumers
        .retain(|c| !removed_consumers.contains(c.id.as_str()));
    config
        .plugin_configs
        .retain(|pc| !removed_plugins.contains(pc.id.as_str()));
    config
        .upstreams
        .retain(|u| !removed_upstreams.contains(u.id.as_str()));

    // Upsert added/modified resources using index for O(1) lookups
    upsert_by_id(&mut config.proxies, result.added_or_modified_proxies, |p| {
        p.id.clone()
    });
    upsert_by_id(
        &mut config.consumers,
        result.added_or_modified_consumers,
        |c| c.id.clone(),
    );
    upsert_by_id(
        &mut config.plugin_configs,
        result.added_or_modified_plugin_configs,
        |pc| pc.id.clone(),
    );
    upsert_by_id(
        &mut config.upstreams,
        result.added_or_modified_upstreams,
        |u| u.id.clone(),
    );
}

/// Upsert items into a vec by ID: replace existing entries, append new ones.
fn upsert_by_id<T>(existing: &mut Vec<T>, updates: Vec<T>, get_id: fn(&T) -> String) {
    let index: std::collections::HashMap<String, usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| (get_id(item), i))
        .collect();

    for item in updates {
        let id = get_id(&item);
        if let Some(&pos) = index.get(&id) {
            existing[pos] = item;
        } else {
            existing.push(item);
        }
    }
}

/// Update a known ID set by adding new IDs and removing deleted ones.
fn update_known_ids(
    known: &mut std::collections::HashSet<String>,
    added: &Vec<String>,
    removed: &[String],
) {
    for id in removed {
        known.remove(id);
    }
    for id in added {
        known.insert(id.clone());
    }
}
