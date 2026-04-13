//! Database mode — single-instance gateway backed by PostgreSQL, MySQL, or SQLite.
//!
//! Lifecycle:
//! 1. Connect to the primary DB (with failover URL retry)
//! 2. Optionally connect a read replica for polling (reduces primary load)
//! 3. Load full config from DB (falls back to on-disk JSON backup if DB is unreachable)
//! 4. Build all caches (router, plugin, consumer, load balancer, circuit breaker)
//! 5. Start proxy + admin listeners
//! 6. Enter the polling loop: incremental `WHERE updated_at > ?` queries every N seconds,
//!    with automatic fallback to full reload + DB failover on error
//!
//! The admin API is read/write in this mode. A `db_available` AtomicBool gates
//! write endpoints — when the DB is unreachable, the admin API becomes temporarily
//! read-only and returns 503 on mutations.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use chrono::{DateTime, Utc};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::config_backup::load_config_backup;
use crate::config::db_backend::{self, DatabaseBackend};
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
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
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    let effective_replica_url = env_config.effective_db_read_replica_url();

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
                env_config.db_tls_enabled,
                env_config.db_tls_ca_cert_path.as_deref(),
                env_config.db_tls_client_cert_path.as_deref(),
                env_config.db_tls_client_key_path.as_deref(),
                env_config.db_tls_insecure,
                &failover_urls,
            )
            .await?;
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
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
            let mut store = DatabaseStore::connect_with_failover(
                db_type,
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
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());

            // Connect read replica for config polling (reduces primary load)
            if let Some(ref replica_url) = effective_replica_url {
                match store
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
            Box::new(store)
        }
    };
    // Convert to Arc for sharing across tasks
    let db: Arc<dyn DatabaseBackend> = Arc::from(db);

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
        backend_allow_ips: env_config.backend_allow_ips.clone(),
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
    let proxy_state = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
    )?;

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

    // Start per-IP request counter cleanup (removes stale zero-count entries)
    proxy_state.start_per_ip_cleanup_task();

    // Start background TTL refresh to keep cache warm (with shutdown)
    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Start background task to retry failed DNS lookups
    let _dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

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

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.frontend_tls_cert_path,
        &env_config.frontend_tls_key_path,
    ) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(
            cert_path,
            key_path,
            client_ca_bundle_path,
            env_config.tls_no_verify,
            &tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(config) => {
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
                error!("TLS configuration validation failed: {}", e);
                return Err(anyhow::anyhow!("Invalid TLS configuration: {}", e));
            }
        }
    } else {
        info!("No TLS configuration provided (HTTP only)");
        None
    };

    // Set TLS config on stream listener manager for TCP proxies with frontend_tls
    if let Some(ref tls_cfg) = tls_config {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_cfg.clone()));
    }

    // Set DTLS cert/key for UDP proxies with frontend_tls (DTLS termination).
    if let (Some(cert_path), Some(key_path)) =
        (&env_config.dtls_cert_path, &env_config.dtls_key_path)
    {
        // Check DTLS certificate expiration
        tls::check_cert_expiry(
            cert_path,
            "DTLS frontend cert",
            env_config.tls_cert_expiry_warning_days,
        )?;
        if let Some(ref ca_path) = env_config.dtls_client_ca_cert_path {
            tls::check_cert_expiry(
                ca_path,
                "DTLS client CA cert",
                env_config.tls_cert_expiry_warning_days,
            )?;
        }
        proxy_state
            .stream_listener_manager
            .set_frontend_dtls_cert_key(
                cert_path.clone(),
                key_path.clone(),
                env_config.dtls_client_ca_cert_path.clone(),
            );
    }

    // Start separate listeners for HTTP and HTTPS
    let mut handles = Vec::new();
    let mut startup_signals = Vec::new();

    // HTTP listener (disabled when port is 0)
    if env_config.proxy_http_port != 0 {
        let http_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_http_port);
        let http_state = proxy_state.clone();
        let http_shutdown = shutdown_tx.subscribe();
        let (http_started_tx, http_started_rx) = tokio::sync::oneshot::channel();
        let http_handle = tokio::spawn(async move {
            info!("Starting HTTP proxy listener on {}", http_addr);
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                http_addr,
                http_state,
                http_shutdown,
                None,
                Some(http_started_tx),
            )
            .await
            {
                error!("HTTP proxy listener error: {}", e);
            }
        });
        handles.push(http_handle);
        startup_signals.push(("HTTP proxy listener".to_string(), http_started_rx));
    } else {
        info!("FERRUM_PROXY_HTTP_PORT=0 — plaintext HTTP proxy listener disabled");
    }

    // HTTPS listener (only if TLS is configured)
    if let Some(tls_config) = tls_config.clone() {
        let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let (https_started_tx, https_started_rx) = tokio::sync::oneshot::channel();
        let https_handle = tokio::spawn(async move {
            info!("Starting HTTPS proxy listener on {}", https_addr);
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                https_addr,
                https_state,
                https_shutdown,
                Some(tls_config),
                Some(https_started_tx),
            )
            .await
            {
                error!("HTTPS proxy listener error: {}", e);
            }
        });
        handles.push(https_handle);
        startup_signals.push(("HTTPS proxy listener".to_string(), https_started_rx));
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener (only if enabled and TLS is configured)
    if env_config.enable_http3 {
        if let Some(tls_config) = tls_config.clone() {
            let h3_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            let h3_state = proxy_state.clone();
            let h3_shutdown = shutdown_tx.subscribe();
            let h3_config = crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
            let h3_tls_policy = tls_policy.clone();
            let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
            let (h3_started_tx, h3_started_rx) = tokio::sync::oneshot::channel();
            let h3_handle = tokio::spawn(async move {
                info!("Starting HTTP/3 (QUIC) proxy listener on {}", h3_addr);
                if let Err(e) = crate::http3::server::start_http3_listener_with_signal(
                    h3_addr,
                    h3_state,
                    h3_shutdown,
                    tls_config,
                    h3_config,
                    &h3_tls_policy,
                    crate::http3::server::Http3ListenerOptions {
                        client_ca_bundle_path: h3_client_ca,
                        started_tx: Some(h3_started_tx),
                    },
                )
                .await
                {
                    error!("HTTP/3 proxy listener error: {}", e);
                }
            });
            handles.push(h3_handle);
            startup_signals.push(("HTTP/3 proxy listener".to_string(), h3_started_rx));
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }

    if env_config.proxy_http_port == 0 && tls_config.is_none() {
        warn!(
            "No HTTP or HTTPS proxy listeners are active — FERRUM_PROXY_HTTP_PORT=0 and no TLS configured. Only stream proxies (TCP/UDP) will serve traffic."
        );
    }

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers.
    let startup_ready = Arc::new(AtomicBool::new(false));
    let db_available = Arc::new(AtomicBool::new(true));

    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "database".into(),
        read_only: env_config.admin_read_only,
        startup_ready: Some(startup_ready.clone()),
        db_available: Some(db_available.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        cp_connection_state: None,
    };
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (disabled when port is 0)
    if env_config.admin_http_port != 0 {
        let admin_http_handle = tokio::spawn(async move {
            info!("Starting Admin HTTP listener on {}", admin_http_addr);
            if let Err(e) =
                admin::start_admin_listener(admin_http_addr, admin_state, admin_shutdown).await
            {
                error!("Admin HTTP listener error: {}", e);
            }
        });
        handles.push(admin_http_handle);
    } else {
        info!("FERRUM_ADMIN_HTTP_PORT=0 — plaintext admin HTTP listener disabled");
    }

    // Admin HTTPS listener (only if TLS is configured)
    if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_state_for_https = AdminState {
            db: Some(db.clone()),
            jwt_manager: create_jwt_manager_from_env()
                .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?,
            cached_config: Some(proxy_state.config.clone()),
            proxy_state: Some(proxy_state.clone()),
            mode: "database".into(),
            read_only: env_config.admin_read_only,
            startup_ready: Some(startup_ready.clone()),
            db_available: Some(db_available.clone()),
            admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
            reserved_ports: reserved_ports.clone(),
            stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
            admin_allowed_cidrs: admin_allowed_cidrs.clone(),
            cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            dp_registry: None,
            cp_connection_state: None,
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
                Some(config)
            }
            Err(e) => {
                error!("Failed to load admin TLS configuration: {}", e);
                return Err(anyhow::anyhow!("Invalid admin TLS configuration: {}", e));
            }
        };

        let admin_https_handle = tokio::spawn(async move {
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
        });
        handles.push(admin_https_handle);
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
    }
    if env_config.admin_http_port == 0 && env_config.admin_tls_cert_path.is_none() {
        warn!(
            "No admin API listeners are active — FERRUM_ADMIN_HTTP_PORT=0 and no admin TLS configured. The admin API is unreachable."
        );
    }

    // Start stream proxy listeners (TCP/UDP) — bind failures are fatal in database mode.
    proxy_state.initial_reconcile_stream_listeners().await?;
    wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
    proxy_state
        .stream_listener_manager
        .wait_until_started(Duration::from_secs(10))
        .await?;
    startup_ready.store(true, Ordering::Relaxed);
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
    let db_tls_enabled = env_config.db_tls_enabled;
    let db_tls_ca_cert = env_config.db_tls_ca_cert_path.clone();
    let db_tls_client_cert = env_config.db_tls_client_cert_path.clone();
    let db_tls_client_key = env_config.db_tls_client_key_path.clone();
    let db_tls_insecure = env_config.db_tls_insecure;
    let poll_namespace = env_config.namespace.clone();

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        // Initialized lazily on the first successful resolution.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let mut last_replica_ips: Option<Vec<IpAddr>> = None;

        // Seed incremental state from the initial config load
        let initial_config = proxy_state_poll.current_config();
        let (
            mut known_proxy_ids,
            mut known_consumer_ids,
            mut known_plugin_config_ids,
            mut known_upstream_ids,
        ) = db_backend::extract_known_ids(&initial_config);
        let mut last_poll_at: Option<DateTime<Utc>> = Some(initial_config.loaded_at);

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
                            &poll_namespace,
                            since,
                            &known_proxy_ids,
                            &known_consumer_ids,
                            &known_plugin_config_ids,
                            &known_upstream_ids,
                        ).await {
                            Ok(result) => {
                                db_available_poll.store(true, Ordering::Relaxed);
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

                                if proxy_state_poll.apply_incremental(result).await {
                                    // Update known IDs only after successful apply to keep them
                                    // in sync with actual proxy state. If apply is rejected
                                    // (e.g. security plugin validation), known_ids stay unchanged
                                    // so the next poll re-fetches the same changes.
                                    update_known_ids(&mut known_proxy_ids, &added_proxy_ids, &removed_proxy_ids);
                                    update_known_ids(&mut known_consumer_ids, &added_consumer_ids, &removed_consumer_ids);
                                    update_known_ids(&mut known_plugin_config_ids, &added_plugin_config_ids, &removed_plugin_config_ids);
                                    update_known_ids(&mut known_upstream_ids, &added_upstream_ids, &removed_upstream_ids);
                                    debug!("Incremental config reload complete");
                                }
                                last_poll_at = Some(poll_ts);
                            }
                            Err(e) => {
                                warn!(
                                    "Incremental poll failed, falling back to full reload: {}",
                                    e
                                );
                                // Fallback to full config load
                                match db_poll.load_full_config(&poll_namespace).await {
                                    Ok(new_config) => {
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        let (p, c, pc, u) = db_backend::extract_known_ids(&new_config);
                                        known_proxy_ids = p;
                                        known_consumer_ids = c;
                                        known_plugin_config_ids = pc;
                                        known_upstream_ids = u;
                                        last_poll_at = Some(new_config.loaded_at);
                                        if proxy_state_poll.update_config(new_config) {
                                            info!("Configuration reloaded from database (full fallback)");
                                        }
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
                                                // Reconnected to a failover DB — try full reload
                                                match db_poll.load_full_config(&poll_namespace).await {
                                                    Ok(new_config) => {
                                                        db_available_poll.store(true, Ordering::Relaxed);
                                                        let (p, c, pc, u) = db_backend::extract_known_ids(&new_config);
                                                        known_proxy_ids = p;
                                                        known_consumer_ids = c;
                                                        known_plugin_config_ids = pc;
                                                        known_upstream_ids = u;
                                                        last_poll_at = Some(new_config.loaded_at);
                                                        if proxy_state_poll.update_config(new_config) {
                                                            info!("Configuration reloaded from database (failover)");
                                                        }
                                                    }
                                                    Err(e3) => {
                                                        db_available_poll.store(false, Ordering::Relaxed);
                                                        warn!(
                                                            "Failover reload also failed (using cached): {}",
                                                            e3
                                                        );
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                db_available_poll.store(false, Ordering::Relaxed);
                                                warn!(
                                                    "Full config reload also failed (using cached): {}",
                                                    e2
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // First poll — full load to seed state
                        match db_poll.load_full_config(&poll_namespace).await {
                            Ok(new_config) => {
                                db_available_poll.store(true, Ordering::Relaxed);
                                let (p, c, pc, u) = db_backend::extract_known_ids(&new_config);
                                known_proxy_ids = p;
                                known_consumer_ids = c;
                                known_plugin_config_ids = pc;
                                known_upstream_ids = u;
                                last_poll_at = Some(new_config.loaded_at);
                                if proxy_state_poll.update_config(new_config) {
                                    info!("Configuration reloaded from database");
                                }
                            }
                            Err(e) => {
                                db_available_poll.store(false, Ordering::Relaxed);
                                warn!(
                                    "Failed to reload config from database (using cached): {}",
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

    // Wait for all listeners to complete (these exit when the shutdown signal fires).
    // If no listener handles were spawned (e.g., all plaintext ports disabled and no
    // TLS configured), block on the shutdown signal so stream proxies keep running.
    if handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
    } else {
        for handle in handles {
            handle.await?;
        }
    }

    // Graceful connection drain: wait for in-flight requests to complete.
    let drain_seconds = env_config.shutdown_drain_seconds;
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    // Wait for background tasks to drain cleanly, with a timeout to prevent
    // hanging if a task is stuck (e.g., blocked on a DB query or DNS lookup).
    let bg_drain = async {
        let _ = dns_handle.await;
        let _ = db_poll_handle.await;
        let _ = overload_handle.await;
        let _ = metrics_handle.await;
    };
    if tokio::time::timeout(Duration::from_secs(5), bg_drain)
        .await
        .is_err()
    {
        warn!("Background tasks did not drain within 5s, proceeding with shutdown");
    }

    Ok(())
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
