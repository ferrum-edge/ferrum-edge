//! Database mode — single-instance gateway backed by PostgreSQL, MySQL, or SQLite.
//!
//! Lifecycle:
//! 1. Connect to the primary DB (with failover URL retry)
//! 2. Optionally connect a read replica for admin read offload
//! 3. Load full config from DB (falls back to on-disk JSON backup if DB is unreachable)
//! 4. Build all caches (router, plugin, consumer, load balancer, circuit breaker)
//! 5. Start proxy + admin listeners
//! 6. Enter the polling loop: incremental `WHERE updated_at > ?` queries every N seconds,
//!    with automatic fallback to full reload + DB failover on error
//!
//! The admin API is read/write in this mode. A `db_available` AtomicBool gates
//! write endpoints — when the DB is unreachable, the admin API becomes temporarily
//! read-only and returns 503 on mutations.

use anyhow::Context;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::config_backup::load_config_backup;
use crate::config::db_backend::{self, DatabaseBackend};
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::dns::{DnsCache, DnsConfig};
use crate::modes::file::{
    ListenerJoinHandle, await_fallible_listener_handles, join_background_handles,
};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

async fn shutdown_database_runtime_tasks(
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    proxy_state: &ProxyState,
    listener_handles: Vec<(String, ListenerJoinHandle)>,
    mut background_handles: Vec<JoinHandle<()>>,
) -> Result<(), anyhow::Error> {
    let _ = shutdown_tx.send(true);
    let listener_result = if listener_handles.is_empty() {
        Ok(())
    } else {
        await_fallible_listener_handles(listener_handles, || {}).await
    };
    proxy_state.stream_listener_manager.shutdown_all().await;
    background_handles.extend(proxy_state.health_checker.take_active_check_handles());
    join_background_handles(background_handles, Duration::from_secs(5)).await;
    listener_result
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
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    let effective_replica_url = env_config
        .effective_db_read_replica_url()
        .map_err(anyhow::Error::msg)?;

    // Tracks whether the initial connect succeeded. When `true`, the gateway
    // started via `FERRUM_DB_CONFIG_BACKUP_PATH` because every configured DB
    // URL was unreachable — polling will retry and flip this back to normal
    // operation once the database recovers.
    let mut bootstrap_from_backup = false;

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
            // SQL backends (postgres, mysql, sqlite)
            let pool_config = DbPoolConfig {
                max_connections: env_config.db_pool_max_connections,
                min_connections: env_config.db_pool_min_connections,
                acquire_timeout_seconds: env_config.db_pool_acquire_timeout_seconds,
                idle_timeout_seconds: env_config.db_pool_idle_timeout_seconds,
                max_lifetime_seconds: env_config.db_pool_max_lifetime_seconds,
                connect_timeout_seconds: env_config.db_pool_connect_timeout_seconds,
                statement_timeout_seconds: env_config.db_pool_statement_timeout_seconds,
            };
            let mut store = match DatabaseStore::connect_with_failover(
                db_type,
                &effective_url,
                &failover_urls,
                pool_config.clone(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    // Every URL failed. If the operator provided
                    // `FERRUM_DB_CONFIG_BACKUP_PATH`, build a lazy-pool store
                    // so the gateway can still come up serving from the
                    // on-disk backup. The polling loop will retry the primary
                    // URL and flip `db_available` to true when it recovers.
                    if env_config.db_config_backup_path.is_some() {
                        warn!(
                            "All database URLs failed ({}). \
                             FERRUM_DB_CONFIG_BACKUP_PATH is set — bootstrapping \
                             from backup with a lazy pool. Polling will retry \
                             primary and {} failover URL(s) in the background.",
                            e,
                            failover_urls.len()
                        );
                        bootstrap_from_backup = true;
                        // Pass `failover_urls` into the offline store so the
                        // polling loop's `try_failover_reconnect()` probes them
                        // — a primary that stays down must not prevent
                        // recovery when a configured failover DB is healthy.
                        DatabaseStore::connect_offline_with_pool_config(
                            db_type,
                            &effective_url,
                            &failover_urls,
                            pool_config,
                        )?
                    } else {
                        return Err(e);
                    }
                }
            };
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_full_load_page_size(env_config.db_full_load_page_size);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());

            // Connect read replica for admin-only read offload. Runtime
            // config polling remains primary-consistent.
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
    // Convert to Arc for sharing across tasks
    let db: Arc<dyn DatabaseBackend> = Arc::from(db);
    let db_tls_reload_handle = crate::modes::db_tls_reload::start_db_tls_reload_task(
        env_config.clone(),
        db.clone(),
        Some(shutdown_tx.subscribe()),
    );

    // If we used the offline-bootstrap path above, try to apply the deferred
    // migrations immediately. The DB may have been unreachable only during
    // the eager connect and become reachable by the time we query here; in
    // that case we must run the migrations now so `load_full_config` below
    // sees the expected schema AND the admin API can enable writes right
    // away. Leaving `bootstrap_from_backup=true` until the first polling
    // cycle would force `db_available=false` for up to one poll interval
    // even though the database has already recovered — causing false 503s.
    //
    // For non-offline stores this is a no-op (CAS fails, returns Ok(false)).
    if bootstrap_from_backup {
        match db.maybe_apply_deferred_migrations().await {
            Ok(true) => {
                info!(
                    "Backup-bootstrapped store: deferred migrations applied at startup — \
                     database became reachable during boot, admin writes enabled immediately"
                );
                bootstrap_from_backup = false;
            }
            Ok(false) => {
                // Flag already cleared — treat as if DB is available.
                // Shouldn't happen right after offline bootstrap, but
                // handling it avoids a stale `bootstrap_from_backup=true`
                // blocking admin writes unnecessarily.
                bootstrap_from_backup = false;
            }
            Err(e) => {
                warn!(
                    "Backup bootstrap: database still unreachable at startup migration \
                     attempt ({}); polling will retry in the background",
                    e
                );
            }
        }
    }

    // Custom-plugin migrations: warn on pending, opt-in auto-apply.
    // Skipped when bootstrap_from_backup is still true — the database is
    // unreachable so we can't probe migration state. The polling loop will
    // reconcile when the DB recovers; until then the operator's existing
    // schema is what matters anyway.
    if !bootstrap_from_backup {
        crate::modes::handle_startup_plugin_migrations(
            &db,
            env_config.auto_apply_plugin_migrations,
            "database",
        )
        .await?;
    }

    // Load initial config from database, falling back to backup file if configured
    let backup_path = env_config.db_config_backup_path.clone();
    let config = match db.load_full_config(&env_config.namespace).await {
        Ok(cfg) => {
            info!(
                "Database mode: loaded {} proxies, {} consumers",
                cfg.proxies.len(),
                cfg.consumers.len()
            );
            cfg
        }
        Err(e) => {
            // Database unreachable — try backup file for pod restart resilience
            if let Some(ref path) = backup_path {
                warn!(
                    "Database load failed ({}), attempting backup file: {}",
                    e, path
                );
                match load_config_backup(path) {
                    Some(cfg) => {
                        warn!(
                            "Starting with backup config ({} proxies, {} consumers). \
                             Database polling will retry and update when DB recovers.",
                            cfg.proxies.len(),
                            cfg.consumers.len()
                        );
                        cfg
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Database load failed and no usable backup at {}: {}",
                            path,
                            e
                        ));
                    }
                }
            } else {
                return Err(e);
            }
        }
    };

    // Validate stream proxy ports don't conflict with gateway reserved ports
    let reserved_ports = env_config.reserved_gateway_ports();
    if let Err(errors) = config.validate_stream_proxy_port_conflicts(&reserved_ports) {
        for msg in &errors {
            error!("{}", msg);
        }
        return Err(anyhow::anyhow!(
            "Stream proxy port conflicts with gateway reserved ports"
        ));
    }

    // DNS cache
    let dns_cache = DnsCache::new(DnsConfig {
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

    // DNS warmup — resolve all hostnames (proxy backends, upstream targets,
    // and plugin endpoints) before accepting requests. Hostnames are
    // deduplicated inside DnsCache::warmup() so shared hostnames across
    // proxies/plugins only trigger one DNS lookup.
    let mut hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|p| {
            (
                p.backend_host.clone(),
                p.dns_override.clone(),
                p.dns_cache_ttl_seconds,
            )
        })
        .collect();

    // Add upstream target hostnames for load-balanced proxies
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    // Build TLS hardening policy from environment (needed for both frontend
    // and backend TLS — cipher suites, protocol versions, key exchange groups).
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );

    // Build ProxyState first so the plugin cache exists with the shared DNS
    // cache, then collect plugin hostnames to include in warmup.
    let (proxy_state, health_check_handles) = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
        Some(shutdown_tx.subscribe()),
    )?;
    crate::runtime_metrics::global().configure(
        env_config.status_counts_max_entries,
        env_config.runtime_metrics_pool_tracking_enabled,
        env_config.runtime_metrics_status_tracking_enabled,
        env_config.runtime_metrics_cache_ttl_ms,
    );

    // Wire stream listeners (TCP/UDP/DTLS) to the global SIGTERM channel so
    // their accept loops exit promptly during graceful drain. Without this,
    // stream listeners would only react to per-listener (config-driven)
    // shutdown and keep accepting connections until the runtime is dropped.
    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

    // Collect plugin endpoint hostnames (http_logging, jwks_auth, etc.)
    let plugin_hosts = proxy_state.plugin_cache.collect_warmup_hostnames();
    for host in plugin_hosts {
        hostnames.push((host, None, None));
    }

    dns_cache.warmup(hostnames).await;

    // Connection pool warmup — pre-establish backend connections for HTTP-family
    // proxies so the first request to each backend avoids TCP/TLS/QUIC handshake
    // latency. Must run after DNS warmup (needs resolved IPs).
    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    // Kick off an initial capability probe when warmup is off — otherwise
    // the registry stays empty and HTTPS H2/H3 dispatch falls back to
    // reqwest until the first periodic tick (up to 24 h).
    proxy_state.start_backend_capability_refresh_task(
        !env_config.pool_warmup_enabled,
        Some(shutdown_tx.subscribe()),
    );

    // Start per-IP request counter cleanup (removes stale zero-count entries)
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));

    // Start background TTL refresh to keep cache warm (with shutdown)
    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Start background task to retry failed DNS lookups
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

    // Start service discovery background tasks
    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    // Start overload monitor background task
    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );

    // Start windowed metrics monitor background task
    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );
    let runtime_system_handle = crate::system_metrics::start_sampler(
        Some(proxy_state.clone()),
        env_config.runtime_metrics_system_sample_interval_ms,
        shutdown_tx.subscribe(),
    );
    let runtime_window_handle = crate::runtime_metrics::start_window_rotator(
        env_config.runtime_metrics_window_1m_seconds,
        env_config.runtime_metrics_window_5m_seconds,
        shutdown_tx.subscribe(),
    );
    let acme_renewal_handle =
        crate::modes::start_acme_renewal_scheduler(&env_config, shutdown_tx.subscribe());

    let mut background_handles: Vec<JoinHandle<()>> = vec![
        dns_handle,
        overload_handle,
        metrics_handle,
        runtime_system_handle,
        runtime_window_handle,
    ];
    if let Some(h) = dns_retry_handle {
        background_handles.push(h);
    }
    if let Some(h) = per_ip_cleanup_handle {
        background_handles.push(h);
    }
    if let Some(h) = db_tls_reload_handle {
        background_handles.push(h);
    }
    if let Some(h) = acme_renewal_handle {
        background_handles.push(h);
    }
    background_handles.extend(health_check_handles);

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.frontend_tls_cert_path,
        &env_config.frontend_tls_key_path,
    ) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth_and_ocsp(
            cert_path,
            key_path,
            client_ca_bundle_path,
            env_config.frontend_tls_ocsp_response_source.as_deref(),
            false,
            &tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(mut config) => {
                // Enable 0-RTT on the proxy frontend only (not admin).
                tls::enable_early_data(&mut config, &tls_policy);
                // Enable kTLS session-secret extraction on the proxy frontend
                // only (not admin) when kTLS could be used. Rustls gates
                // `dangerous_extract_secrets()` behind this flag.
                if env_config.ktls_enabled.could_be_enabled() {
                    tls::enable_secret_extraction_for_ktls(&mut config);
                }
                if client_ca_bundle_path.is_some() {
                    info!(
                        "TLS configuration loaded with client certificate verification (HTTPS with mTLS available)"
                    );
                } else {
                    info!(
                        "TLS configuration loaded without client certificate verification (HTTPS available)"
                    );
                }
                Some(config)
            }
            Err(e) => {
                let startup_err = anyhow::anyhow!("Invalid TLS configuration: {}", e);
                error!("TLS configuration validation failed: {}", e);
                if let Err(listener_err) = shutdown_database_runtime_tasks(
                    &shutdown_tx,
                    &proxy_state,
                    Vec::new(),
                    background_handles,
                )
                .await
                {
                    return Err(
                        listener_err.context(format!("Gateway startup failed: {startup_err}"))
                    );
                }
                return Err(startup_err);
            }
        }
    } else {
        info!("No TLS configuration provided (HTTP only)");
        None
    };

    // Wire opt-in frontend TLS live reload. When
    // `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=false` (the default) this
    // returns `slot=None` / `revision_rx=None` / `watcher_handle=None` and the
    // listeners use the startup-loaded config exactly as before. When opt-in
    // is set, a background watcher polls cert/key files and atomically swaps
    // the slot on validated changes; the HTTPS / H2 / H3 listeners read from
    // the slot on every new handshake.
    let mut proxy_frontend_reload_handles = tls_config.as_ref().map(|cfg| {
        crate::modes::tls_reload::prepare_proxy_frontend_tls(
            cfg.clone(),
            &env_config,
            &tls_policy,
            &crls,
            Some(shutdown_tx.subscribe()),
        )
    });
    if let Some(handles) = proxy_frontend_reload_handles.as_ref()
        && handles.watcher_handle.is_some()
    {
        info!(
            interval_secs = env_config.frontend_tls_watch_interval_seconds,
            "Frontend TLS live reload enabled for proxy HTTPS (H1/H2) and HTTP/3"
        );
    }
    if let Some(handles) = proxy_frontend_reload_handles.as_mut()
        && let Some(handle) = handles.watcher_handle.take()
    {
        background_handles.push(handle);
    }

    // Set TLS config on stream listener manager for TCP proxies with frontend_tls.
    // TCP+TLS / UDP+DTLS stream listeners do NOT participate in live reload —
    // they keep their startup config across rotations, matching the existing
    // mesh-mode behavior.
    if let Some(ref tls_cfg) = tls_config {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_cfg.clone()))
            .await;
    }

    // Set DTLS cert/key for UDP proxies with frontend_tls (DTLS termination).
    if let (Some(cert_path), Some(key_path)) =
        (&env_config.dtls_cert_path, &env_config.dtls_key_path)
    {
        if let Err(e) = tls::check_cert_expiry(
            cert_path,
            "DTLS frontend cert",
            env_config.tls_cert_expiry_warning_days,
        ) {
            let startup_err = e.context("Invalid DTLS frontend cert");
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                Vec::new(),
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
        if let Some(ref ca_path) = env_config.dtls_client_ca_cert_path
            && let Err(e) = tls::check_cert_expiry(
                ca_path,
                "DTLS client CA cert",
                env_config.tls_cert_expiry_warning_days,
            )
        {
            let startup_err = e.context("Invalid DTLS client CA cert");
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                Vec::new(),
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
        proxy_state
            .stream_listener_manager
            .set_frontend_dtls_cert_key(
                cert_path.clone(),
                key_path.clone(),
                env_config.dtls_client_ca_cert_path.clone(),
            )
            .await;
    }

    // Start separate listeners for HTTP and HTTPS
    let mut handles: Vec<(String, ListenerJoinHandle)> = Vec::new();
    let mut startup_signals = Vec::new();

    // HTTP listener (disabled when port is 0)
    if env_config.proxy_http_port != 0 {
        let http_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_http_port);
        let http_state = proxy_state.clone();
        let http_shutdown = shutdown_tx.subscribe();
        let (http_started_tx, http_started_rx) = tokio::sync::oneshot::channel();
        let http_handle = tokio::spawn(async move {
            info!("Starting HTTP proxy listener on {}", http_addr);
            proxy::start_proxy_listener_with_tls_and_signal(
                http_addr,
                http_state,
                http_shutdown,
                None,
                Some(http_started_tx),
            )
            .await
            .context("HTTP proxy listener failed")
        });
        handles.push(("HTTP proxy listener".to_string(), http_handle));
        startup_signals.push(("HTTP proxy listener".to_string(), http_started_rx));
    } else {
        info!("FERRUM_PROXY_HTTP_PORT=0 — plaintext HTTP proxy listener disabled");
    }

    // HTTPS listener (only if TLS is configured)
    if let Some(tls_config) = tls_config.clone() {
        if env_config.proxy_https_port == 0 {
            info!("FERRUM_PROXY_HTTPS_PORT=0 — HTTPS proxy listener disabled");
        } else {
            let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            let https_state = proxy_state.clone();
            let https_shutdown = shutdown_tx.subscribe();
            let (https_started_tx, https_started_rx) = tokio::sync::oneshot::channel();
            let reload_slot = proxy_frontend_reload_handles
                .as_ref()
                .and_then(|h| h.slot.clone());
            let https_handle = tokio::spawn(async move {
                info!("Starting HTTPS proxy listener on {}", https_addr);
                let result = if let Some(slot) = reload_slot {
                    proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                        https_addr,
                        https_state,
                        https_shutdown,
                        slot,
                        Some(https_started_tx),
                    )
                    .await
                } else {
                    proxy::start_proxy_listener_with_tls_and_signal(
                        https_addr,
                        https_state,
                        https_shutdown,
                        Some(tls_config),
                        Some(https_started_tx),
                    )
                    .await
                };
                result.context("HTTPS proxy listener failed")
            });
            handles.push(("HTTPS proxy listener".to_string(), https_handle));
            startup_signals.push(("HTTPS proxy listener".to_string(), https_started_rx));
        }
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener (only if enabled and TLS is configured)
    if env_config.enable_http3 {
        if let Some(tls_config) = tls_config.clone() {
            if env_config.proxy_https_port == 0 {
                info!("FERRUM_PROXY_HTTPS_PORT=0 — HTTP/3 proxy listener disabled");
            } else {
                let h3_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
                let h3_state = proxy_state.clone();
                let h3_shutdown = shutdown_tx.subscribe();
                let h3_config =
                    crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
                let h3_tls_policy = tls_policy.clone();
                let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
                let h3_client_crls = crls.clone();
                let (h3_started_tx, h3_started_rx) = tokio::sync::oneshot::channel();
                let h3_reload = crate::modes::tls_reload::build_h3_frontend_tls_reload(
                    proxy_frontend_reload_handles.as_ref(),
                );
                let h3_handle = tokio::spawn(async move {
                    info!("Starting HTTP/3 (QUIC) proxy listener on {}", h3_addr);
                    crate::http3::server::start_http3_listener_with_signal(
                        h3_addr,
                        h3_state,
                        h3_shutdown,
                        tls_config,
                        h3_config,
                        &h3_tls_policy,
                        crate::http3::server::Http3ListenerOptions {
                            client_ca_bundle_path: h3_client_ca,
                            client_crls: h3_client_crls,
                            started_tx: Some(h3_started_tx),
                            frontend_tls_reload: h3_reload,
                        },
                    )
                    .await
                    .context("HTTP/3 proxy listener failed")
                });
                handles.push(("HTTP/3 proxy listener".to_string(), h3_handle));
                startup_signals.push(("HTTP/3 proxy listener".to_string(), h3_started_rx));
            }
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }

    if env_config.proxy_http_port == 0 && (tls_config.is_none() || env_config.proxy_https_port == 0)
    {
        warn!(
            "No HTTP or HTTPS proxy listeners are active — FERRUM_PROXY_HTTP_PORT=0 and HTTPS is not configured or disabled. Only stream proxies (TCP/UDP) will serve traffic."
        );
    }

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(jwt_manager) => jwt_manager,
        Err(e) => {
            let startup_err = anyhow::anyhow!("Failed to create JWT manager: {}", e);
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                handles,
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
    };

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers. When we bootstrapped from a
    // backup file because every DB URL was down at startup, initialize to
    // `false` so `/health` and the admin API report the true state
    // immediately — before the first polling tick runs.
    let startup_ready = Arc::new(AtomicBool::new(false));
    let db_available = Arc::new(AtomicBool::new(!bootstrap_from_backup));

    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "database".into(),
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
        dp_registry: None,
        mesh_registry: None,
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
    if env_config.admin_http_port != 0 {
        let (admin_started_tx, admin_started_rx) = tokio::sync::oneshot::channel();
        let admin_http_handle = tokio::spawn(async move {
            info!("Starting Admin HTTP listener on {}", admin_http_addr);
            admin::start_admin_listener_with_tls_and_signal(
                admin_http_addr,
                admin_state,
                admin_shutdown,
                None,
                Some(admin_started_tx),
            )
            .await
            .context("Admin HTTP listener failed")
        });
        handles.push(("Admin HTTP listener".to_string(), admin_http_handle));
        startup_signals.push(("Admin HTTP listener".to_string(), admin_started_rx));
    } else {
        info!("FERRUM_ADMIN_HTTP_PORT=0 — plaintext admin HTTP listener disabled");
    }

    // Admin HTTPS listener (only if TLS is configured)
    if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        if env_config.admin_https_port == 0 {
            info!("FERRUM_ADMIN_HTTPS_PORT=0 — admin HTTPS listener disabled");
        } else {
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
                    let startup_err = anyhow::anyhow!("Invalid admin TLS configuration: {}", e);
                    error!("Failed to load admin TLS configuration: {}", e);
                    if let Err(listener_err) = shutdown_database_runtime_tasks(
                        &shutdown_tx,
                        &proxy_state,
                        handles,
                        background_handles,
                    )
                    .await
                    {
                        return Err(
                            listener_err.context(format!("Gateway startup failed: {startup_err}"))
                        );
                    }
                    return Err(startup_err);
                }
            };

            // Wire opt-in admin frontend TLS live reload (no early-data / no
            // kTLS — admin doesn't apply those opt-ins).
            let mut admin_reload_handles = crate::modes::tls_reload::prepare_admin_frontend_tls(
                admin_tls_config.clone(),
                &env_config,
                &tls_policy,
                &crls,
                Some(shutdown_tx.subscribe()),
            );
            if admin_reload_handles.watcher_handle.is_some() {
                info!("Frontend TLS live reload enabled for admin HTTPS");
            }
            if let Some(handle) = admin_reload_handles.watcher_handle.take() {
                background_handles.push(handle);
            }
            let admin_tls_slot = admin_reload_handles.slot.clone();

            let (admin_https_started_tx, admin_https_started_rx) = tokio::sync::oneshot::channel();
            let admin_https_handle = tokio::spawn(async move {
                info!("Starting Admin HTTPS listener on {}", admin_https_addr);
                let result = if let Some(slot) = admin_tls_slot {
                    admin::start_admin_listener_with_dynamic_tls_and_signal(
                        admin_https_addr,
                        admin_state_for_https,
                        admin_https_shutdown,
                        slot,
                        Some(admin_https_started_tx),
                    )
                    .await
                } else {
                    admin::start_admin_listener_with_tls_and_signal(
                        admin_https_addr,
                        admin_state_for_https,
                        admin_https_shutdown,
                        Some(admin_tls_config),
                        Some(admin_https_started_tx),
                    )
                    .await
                };
                result.context("Admin HTTPS listener failed")
            });
            handles.push(("Admin HTTPS listener".to_string(), admin_https_handle));
            startup_signals.push(("Admin HTTPS listener".to_string(), admin_https_started_rx));
        }
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
    }
    if env_config.admin_http_port == 0
        && !(env_config.admin_tls_cert_path.is_some()
            && env_config.admin_tls_key_path.is_some()
            && env_config.admin_https_port != 0)
    {
        warn!(
            "No admin API listeners are active — FERRUM_ADMIN_HTTP_PORT=0 and admin HTTPS is not configured or disabled. The admin API is unreachable."
        );
    }

    // Start stream proxy listeners (TCP/UDP) — bind failures are fatal in database mode.
    let startup_result: Result<(), anyhow::Error> = async {
        proxy_state.initial_reconcile_stream_listeners().await?;
        wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
        Ok(())
    }
    .await;

    if let Err(e) = startup_result {
        warn!(
            "Gateway startup failed after spawning listener / background tasks: {}; \
             draining spawned tasks before returning",
            e
        );
        if let Err(listener_err) =
            shutdown_database_runtime_tasks(&shutdown_tx, &proxy_state, handles, background_handles)
                .await
        {
            return Err(listener_err.context(format!("Gateway startup failed: {e}")));
        }
        return Err(e);
    }

    // Mark the gateway as ready to serve traffic. At this point:
    //   - Initial full config was loaded from DB (or backup)
    //   - All caches (router, plugin, consumer, LB, circuit breaker) are built
    //   - DNS is warmed and connection pools are pre-established
    //   - All listeners (proxy HTTP/HTTPS/H3, admin, stream) are bound
    //
    // This is intentionally set BEFORE the DB polling loop starts. Two paths
    // reach this point:
    //
    //   1. Normal — `load_full_config()` succeeded, proving DB connectivity
    //      and loading a complete config.
    //   2. Backup — `load_full_config()` failed but `FERRUM_DB_CONFIG_BACKUP_PATH`
    //      was set, so config was restored from the on-disk backup file. The
    //      gateway is serving stale-but-valid config; `db_available` starts
    //      `false`, `/health` reports `"degraded"`, and admin writes are
    //      blocked. The polling loop will retry the DB and flip
    //      `db_available` back to `true` once it recovers.
    //
    // In both cases the polling loop handles *ongoing incremental updates*,
    // not initial readiness. `/health` independently validates DB connectivity
    // via a `SELECT 1` check (cached 15s), so DB failures surface in the
    // health response regardless of polling state. `db_available` separately
    // gates admin writes when the DB becomes unreachable during operation.
    startup_ready.store(true, Ordering::Release);
    info!("Gateway startup complete; /health now reports ready");

    // Database polling loop (with shutdown) — uses incremental polling
    // to avoid full table scans on every cycle.
    //
    // First poll after startup seeds the known ID sets from the initial config.
    // Subsequent polls use `load_incremental_config()` which fetches only
    // rows with `updated_at > last_poll_at` and detects deletions via
    // lightweight `SELECT id` queries.
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let proxy_state_poll = proxy_state.clone();
    let db_available_poll = db_available.clone();
    let mut poll_shutdown = shutdown_tx.subscribe();

    // DNS re-resolution for the database FQDN: if the URL contains a hostname
    // (not an IP literal), resolve it via DnsCache on each poll cycle and
    // reconnect the pool when the IPs change.
    let db_hostname = db_backend::extract_db_hostname(&effective_url);
    let replica_hostname = effective_replica_url
        .as_deref()
        .and_then(db_backend::extract_db_hostname);
    let dns_cache_for_poll = dns_cache.clone();
    let db_url_for_reconnect = effective_url.clone();
    let replica_url_for_reconnect = effective_replica_url.clone();
    let poll_namespace = env_config.namespace.clone();

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        // Initialized lazily on the first successful resolution.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let mut last_replica_ips: Option<Vec<IpAddr>> = None;
        let mut force_full_reload = false;

        // Seed incremental state from the initial config load
        let initial_config = proxy_state_poll.current_config();
        let (
            mut known_proxy_ids,
            mut known_consumer_ids,
            mut known_plugin_config_ids,
            mut known_upstream_ids,
        ) = db_backend::extract_known_ids(&initial_config);
        // If startup used the on-disk backup fallback, force the first
        // successful poll path to do a full DB reload instead of seeding
        // incremental polling from `initial_config.loaded_at`.
        //
        // Why: backup JSON may omit `loaded_at` (serde defaults to "now"),
        // which can be newer than many existing DB rows. Starting incremental
        // from that timestamp can skip unchanged DB state indefinitely.
        let mut last_poll_at: Option<DateTime<Utc>> = if bootstrap_from_backup {
            None
        } else {
            Some(initial_config.loaded_at)
        };

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
                            None => false, // first resolution, just seed
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
                        if !db_poll.read_replica_available() {
                            if let Err(e) = db_poll.reconnect_read_replica(replica_url).await {
                                let safe_error =
                                    db_backend::redact_error_text(e.as_ref(), &[replica_url]);
                                warn!(
                                    "Read replica unavailable; admin-read replica reconnect attempt failed for {}: {}",
                                    db_backend::redact_url(replica_url),
                                    safe_error
                                );
                            }
                        } else if let Some(ref replica_hostname) = replica_hostname
                            && let Ok(ips) = dns_cache_for_poll
                                .resolve_all(replica_hostname, None, None)
                                .await
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
                                    "Read replica DNS changed for '{}': {:?} -> {:?}, reconnecting admin-read replica pool",
                                    replica_hostname, last_replica_ips.as_deref().unwrap_or(&[]), ips
                                );
                                if let Err(e) =
                                    db_poll.reconnect_read_replica(replica_url).await
                                {
                                    let safe_error = db_backend::redact_error_text(
                                        e.as_ref(),
                                        &[replica_url],
                                    );
                                    error!(
                                        "Failed to reconnect admin-read replica pool after DNS change for '{}' ({}): {}",
                                        replica_hostname,
                                        db_backend::redact_url(replica_url),
                                        safe_error
                                    );
                                }
                            }
                            last_replica_ips = Some(ips);
                        }
                    }

                    if force_full_reload {
                        match db_poll.load_full_config(&poll_namespace).await {
                            Ok(new_config) => {
                                let outcome = proxy_state_poll.update_config(new_config);
                                if commit_full_reload_poll_state(
                                    "after DB DNS reconnect",
                                    outcome,
                                    &proxy_state_poll,
                                    full_reload_poll_state(
                                        &mut known_proxy_ids,
                                        &mut known_consumer_ids,
                                        &mut known_plugin_config_ids,
                                        &mut known_upstream_ids,
                                        &mut last_poll_at,
                                    ),
                                ) {
                                    force_full_reload = false;
                                    db_available_poll.store(true, Ordering::Relaxed);
                                    debug!("Full config reload complete after DB DNS reconnect");
                                }
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
                    } else if let Some(since) = last_poll_at {
                        // Incremental poll — only fetch changes since last poll
                        match db_poll.load_incremental_config(
                            &poll_namespace,
                            since,
                            &known_proxy_ids,
                            &known_consumer_ids,
                            &known_plugin_config_ids,
                            &known_upstream_ids,
                        ).await {
                            Ok(result) => {
                                // Catch the lazy-pool-connects-directly case:
                                // if offline bootstrap left `migrations_pending`
                                // set, the query above succeeded without
                                // `reconnect()` ever firing. Run deferred
                                // migrations now before flipping
                                // `db_available` — otherwise admin writes
                                // could hit an outdated schema.
                                // No-op when nothing is pending.
                                match db_poll.maybe_apply_deferred_migrations().await {
                                    Ok(_) => db_available_poll.store(true, Ordering::Relaxed),
                                    Err(e) => {
                                        warn!(
                                            "Deferred migrations failed despite successful incremental poll: {}. \
                                             Admin writes remain blocked until schema is applied.",
                                            e
                                        );
                                        db_available_poll.store(false, Ordering::Relaxed);
                                    }
                                }
                                let poll_ts = result.poll_timestamp;
                                // Collect ID changes before moving result into apply_incremental
                                let added_proxy_ids: Vec<String> = result.added_or_modified_proxies.iter().map(|p| p.id.clone()).collect();
                                let removed_proxy_ids = result.removed_proxy_ids.clone();
                                let added_consumer_ids: Vec<String> = result.added_or_modified_consumers.iter().map(|c| c.id.clone()).collect();
                                let removed_consumer_ids = result.removed_consumer_ids.clone();
                                let added_plugin_config_ids: Vec<String> = result.added_or_modified_plugin_configs.iter().map(|pc| pc.id.clone()).collect();
                                let removed_plugin_config_ids = result.removed_plugin_config_ids.clone();
                                let added_upstream_ids: Vec<String> = result.added_or_modified_upstreams.iter().map(|u| u.id.clone()).collect();
                                let removed_upstream_ids = result.removed_upstream_ids.clone();

                                match proxy_state_poll.apply_incremental(result).await {
                                    proxy::ConfigApplyOutcome::Applied => {
                                        // Update known IDs only after successful apply to keep them
                                        // in sync with actual proxy state.
                                        update_known_ids(&mut known_proxy_ids, &added_proxy_ids, &removed_proxy_ids);
                                        update_known_ids(&mut known_consumer_ids, &added_consumer_ids, &removed_consumer_ids);
                                        update_known_ids(&mut known_plugin_config_ids, &added_plugin_config_ids, &removed_plugin_config_ids);
                                        update_known_ids(&mut known_upstream_ids, &added_upstream_ids, &removed_upstream_ids);
                                        debug!("Incremental config reload complete");
                                        last_poll_at = Some(poll_ts);
                                    }
                                    proxy::ConfigApplyOutcome::Unchanged => {
                                        // Nothing to apply this cycle. Advance the cursor
                                        // so the next poll only fetches truly newer rows.
                                        last_poll_at = Some(poll_ts);
                                        debug!("Incremental config poll valid but unchanged");
                                    }
                                    proxy::ConfigApplyOutcome::Rejected { .. } => {
                                        // Validation rejected the patched config (e.g. security
                                        // plugin / unique listen-path). Leave `last_poll_at`
                                        // unchanged so the next poll re-fetches the same rows
                                        // and tries again. Without this, a rejected resource
                                        // older than the 1-second `since_safe` margin would
                                        // silently disappear from the gateway's view of the
                                        // DB, leaving permanent divergence between DB state
                                        // and in-memory config until a full reload.
                                        //
                                        // Known follow-up: if the same poll timestamp keeps
                                        // failing validation (a malformed row stuck in the
                                        // DB), the loop will spin re-fetching it forever.
                                        // A future change should escalate after N consecutive
                                        // rejections at the same `poll_ts` — log an error and
                                        // trigger a full reload to recover (or mark the
                                        // offending IDs and skip them with operator alert).
                                        warn!(
                                            "Incremental config update rejected by validation; \
                                             leaving last_poll_at unchanged so the next poll \
                                             retries the same rows"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Authoritative primary incremental poll failed, falling back to full reload: {}",
                                    e
                                );
                                // Fallback to full config load
                                match db_poll.load_full_config(&poll_namespace).await {
                                    Ok(new_config) => {
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        let outcome = proxy_state_poll.update_config(new_config);
                                        commit_full_reload_poll_state(
                                            "full fallback",
                                            outcome,
                                            &proxy_state_poll,
                                            full_reload_poll_state(
                                                &mut known_proxy_ids,
                                                &mut known_consumer_ids,
                                                &mut known_plugin_config_ids,
                                                &mut known_upstream_ids,
                                                &mut last_poll_at,
                                            ),
                                        );
                                    }
                                    Err(e2) => {
                                        // Both incremental and full reload failed —
                                        // try failover URLs before giving up.
                                        match db_poll.try_failover_reconnect(&db_url_for_reconnect).await {
                                            Ok(_url) => {
                                                // Reconnected to a failover DB — try full reload
                                                match db_poll.load_full_config(&poll_namespace).await {
                                                    Ok(new_config) => {
                                                        db_available_poll.store(true, Ordering::Relaxed);
                                                        let outcome = proxy_state_poll.update_config(new_config);
                                                        commit_full_reload_poll_state(
                                                            "failover",
                                                            outcome,
                                                            &proxy_state_poll,
                                                            full_reload_poll_state(
                                                                &mut known_proxy_ids,
                                                                &mut known_consumer_ids,
                                                                &mut known_plugin_config_ids,
                                                                &mut known_upstream_ids,
                                                                &mut last_poll_at,
                                                            ),
                                                        );
                                                    }
                                                    Err(e3) => {
                                                        db_available_poll.store(false, Ordering::Relaxed);
                                                        warn!(
                                                            "Authoritative primary failover reload also failed (using cached): {}",
                                                            e3
                                                        );
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                db_available_poll.store(false, Ordering::Relaxed);
                                                warn!(
                                                    "Authoritative primary full config reload also failed (using cached): {}",
                                                    e2
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // First poll — full load to seed state. This path can
                        // fire when the startup `load_full_config` failed (we
                        // bootstrapped from backup) but the lazy pool is now
                        // reaching a live DB. Run deferred migrations if any
                        // before flipping `db_available` — see comment in the
                        // incremental-success branch above.
                        match db_poll.load_full_config(&poll_namespace).await {
                            Ok(new_config) => {
                                match db_poll.maybe_apply_deferred_migrations().await {
                                    Ok(_) => db_available_poll.store(true, Ordering::Relaxed),
                                    Err(e) => {
                                        warn!(
                                            "Deferred migrations failed despite successful full reload: {}. \
                                             Admin writes remain blocked until schema is applied.",
                                            e
                                        );
                                        db_available_poll.store(false, Ordering::Relaxed);
                                    }
                                }
                                let outcome = proxy_state_poll.update_config(new_config);
                                commit_full_reload_poll_state(
                                    "initial full poll",
                                    outcome,
                                    &proxy_state_poll,
                                    full_reload_poll_state(
                                        &mut known_proxy_ids,
                                        &mut known_consumer_ids,
                                        &mut known_plugin_config_ids,
                                        &mut known_upstream_ids,
                                        &mut last_poll_at,
                                    ),
                                );
                            }
                            Err(e) => {
                                db_available_poll.store(false, Ordering::Relaxed);
                                warn!(
                                    "Authoritative primary full config reload failed (using cached): {}",
                                    e
                                );
                            }
                        }
                    }
                }
                _ = poll_shutdown.changed() => {
                    info!("Database polling shutting down");
                    return;
                }
            }
        }
    });
    background_handles.push(db_poll_handle);

    // Wait for all listeners to complete (these exit when the shutdown signal fires).
    // If no listener handles were spawned (e.g., all plaintext ports disabled and no
    // TLS configured), block on the shutdown signal so stream proxies keep running.
    let listener_result = if handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        Ok(())
    } else {
        let shutdown_tx_on_failure = shutdown_tx.clone();
        await_fallible_listener_handles(handles, move || {
            let _ = shutdown_tx_on_failure.send(true);
        })
        .await
    };

    // Stop accepting new TCP/UDP/DTLS stream connections. The accept loops
    // also observe the global shutdown receiver wired above and will already
    // be exiting; firing each per-listener channel here clears the listener
    // map (releasing ports) and is a no-op if the loops have already exited.
    proxy_state.stream_listener_manager.shutdown_all().await;

    // Graceful connection drain: signal drain state to the proxy hot path
    // (Connection: close + reject new requests) unconditionally so the close
    // hint fires even when the operator has disabled the wait loop with
    // FERRUM_SHUTDOWN_DRAIN_SECONDS=0. Only the wait loop itself is gated.
    crate::overload::begin_drain(&proxy_state.overload);
    let drain_seconds = env_config.shutdown_drain_seconds;
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    // Wait for background tasks to drain cleanly, with a timeout to prevent
    // hanging if a task is stuck (e.g., blocked on a DB query or DNS lookup).
    // Active-health-check probes and the passive recovery timer observe the
    // shutdown watch channel via `tokio::select!` (see `start_with_shutdown`)
    // so they exit cleanly within the 5s cap rather than racing the
    // `Drop for HealthChecker` abort that fires at process exit.
    background_handles.extend(proxy_state.health_checker.take_active_check_handles());
    join_background_handles(background_handles, Duration::from_secs(5)).await;

    listener_result?;

    Ok(())
}

struct FullReloadPollState<'a> {
    known_proxy_ids: &'a mut HashSet<String>,
    known_consumer_ids: &'a mut HashSet<String>,
    known_plugin_config_ids: &'a mut HashSet<String>,
    known_upstream_ids: &'a mut HashSet<String>,
    last_poll_at: &'a mut Option<DateTime<Utc>>,
}

impl FullReloadPollState<'_> {
    fn commit_from_proxy_state(self, proxy_state: &ProxyState) {
        let published_config = proxy_state.current_config();
        let (
            next_known_proxy_ids,
            next_known_consumer_ids,
            next_known_plugin_config_ids,
            next_known_upstream_ids,
        ) = db_backend::extract_known_ids(&published_config);
        *self.known_proxy_ids = next_known_proxy_ids;
        *self.known_consumer_ids = next_known_consumer_ids;
        *self.known_plugin_config_ids = next_known_plugin_config_ids;
        *self.known_upstream_ids = next_known_upstream_ids;
        *self.last_poll_at = Some(published_config.loaded_at);
    }
}

fn full_reload_poll_state<'a>(
    known_proxy_ids: &'a mut HashSet<String>,
    known_consumer_ids: &'a mut HashSet<String>,
    known_plugin_config_ids: &'a mut HashSet<String>,
    known_upstream_ids: &'a mut HashSet<String>,
    last_poll_at: &'a mut Option<DateTime<Utc>>,
) -> FullReloadPollState<'a> {
    FullReloadPollState {
        known_proxy_ids,
        known_consumer_ids,
        known_plugin_config_ids,
        known_upstream_ids,
        last_poll_at,
    }
}

fn commit_full_reload_poll_state(
    context: &str,
    outcome: proxy::ConfigApplyOutcome,
    proxy_state: &ProxyState,
    poll_state: FullReloadPollState<'_>,
) -> bool {
    match outcome {
        proxy::ConfigApplyOutcome::Applied => {
            poll_state.commit_from_proxy_state(proxy_state);
            info!("Configuration applied from database ({})", context);
            true
        }
        proxy::ConfigApplyOutcome::Unchanged => {
            poll_state.commit_from_proxy_state(proxy_state);
            debug!("Database configuration valid but unchanged ({})", context);
            true
        }
        proxy::ConfigApplyOutcome::Rejected { .. } => {
            warn!(
                "Database configuration candidate rejected ({}); keeping previous runtime config, poll cursor, and known ID sets",
                context
            );
            false
        }
    }
}

/// Update a known ID set by adding new IDs and removing deleted ones.
fn update_known_ids(known: &mut HashSet<String>, added: &Vec<String>, removed: &[String]) {
    for id in removed {
        known.remove(id);
    }
    for id in added {
        known.insert(id.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_proxy_state_for_poll_tests() -> ProxyState {
        let dns_cache = DnsCache::new(DnsConfig::default());
        let env_config = EnvConfig::default();
        let (state, _health_check_handles) =
            ProxyState::new(Default::default(), dns_cache, env_config, None, None)
                .expect("default proxy state should build");
        state
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_reload_unchanged_commits_cursor_and_known_ids() {
        let state = empty_proxy_state_for_poll_tests();
        let previous_poll_at = Utc::now() - chrono::Duration::seconds(60);
        let mut last_poll_at = Some(previous_poll_at);
        let mut known_proxy_ids: HashSet<String> = HashSet::from(["stale-proxy".to_string()]);
        let mut known_consumer_ids: HashSet<String> = HashSet::from(["stale-consumer".to_string()]);
        let mut known_plugin_config_ids: HashSet<String> =
            HashSet::from(["stale-plugin".to_string()]);
        let mut known_upstream_ids: HashSet<String> = HashSet::from(["stale-upstream".to_string()]);

        let accepted = commit_full_reload_poll_state(
            "test unchanged",
            proxy::ConfigApplyOutcome::Unchanged,
            &state,
            full_reload_poll_state(
                &mut known_proxy_ids,
                &mut known_consumer_ids,
                &mut known_plugin_config_ids,
                &mut known_upstream_ids,
                &mut last_poll_at,
            ),
        );

        assert!(accepted);
        assert!(known_proxy_ids.is_empty());
        assert!(known_consumer_ids.is_empty());
        assert!(known_plugin_config_ids.is_empty());
        assert!(known_upstream_ids.is_empty());
        assert_eq!(last_poll_at, Some(state.current_config().loaded_at));
        assert_ne!(last_poll_at, Some(previous_poll_at));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_reload_rejected_preserves_cursor_and_known_ids() {
        let state = empty_proxy_state_for_poll_tests();
        let previous_poll_at = Utc::now() - chrono::Duration::seconds(60);
        let mut last_poll_at = Some(previous_poll_at);
        let mut known_proxy_ids: HashSet<String> = HashSet::from(["proxy-a".to_string()]);
        let mut known_consumer_ids: HashSet<String> = HashSet::from(["consumer-a".to_string()]);
        let mut known_plugin_config_ids: HashSet<String> = HashSet::from(["plugin-a".to_string()]);
        let mut known_upstream_ids: HashSet<String> = HashSet::from(["upstream-a".to_string()]);

        let accepted = commit_full_reload_poll_state(
            "test rejected",
            proxy::ConfigApplyOutcome::Rejected {
                errors: vec!["invalid candidate".to_string()],
            },
            &state,
            full_reload_poll_state(
                &mut known_proxy_ids,
                &mut known_consumer_ids,
                &mut known_plugin_config_ids,
                &mut known_upstream_ids,
                &mut last_poll_at,
            ),
        );

        assert!(!accepted);
        assert_eq!(known_proxy_ids, HashSet::from(["proxy-a".to_string()]));
        assert_eq!(
            known_consumer_ids,
            HashSet::from(["consumer-a".to_string()])
        );
        assert_eq!(
            known_plugin_config_ids,
            HashSet::from(["plugin-a".to_string()])
        );
        assert_eq!(
            known_upstream_ids,
            HashSet::from(["upstream-a".to_string()])
        );
        assert_eq!(last_poll_at, Some(previous_poll_at));
    }

    #[test]
    fn update_known_ids_adds_and_removes() {
        let mut known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        update_known_ids(&mut known, &vec!["d".to_string()], &["b".to_string()]);
        assert!(known.contains("a"));
        assert!(!known.contains("b"));
        assert!(known.contains("c"));
        assert!(known.contains("d"));
        assert_eq!(known.len(), 3);
    }

    #[test]
    fn update_known_ids_remove_nonexistent_is_noop() {
        let mut known: HashSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        update_known_ids(&mut known, &vec![], &["zzz".to_string()]);
        assert_eq!(known.len(), 1);
    }

    #[test]
    fn update_known_ids_duplicate_add_is_idempotent() {
        let mut known: HashSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        update_known_ids(&mut known, &vec!["a".to_string(), "a".to_string()], &[]);
        assert_eq!(known.len(), 1);
    }
}
