//! Data Plane mode — proxy-only node that receives config from a Control Plane.
//!
//! The DP starts with an empty `GatewayConfig` and receives its first full
//! snapshot from the CP within seconds of establishing the gRPC `Subscribe`
//! stream. Subsequent updates arrive as incremental deltas (`update_type=1`).
//!
//! The DP has no direct database access. Its admin API is always read-only.
//! If the gRPC connection to the CP drops, the DP continues serving with
//! cached config and reconnects with a 5-second backoff loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    info!("DP mode: starting with empty config, waiting for CP");

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

    // Start DNS background refresh
    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Start background task to retry failed DNS lookups
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

    // Build TLS hardening policy from environment (needed for both frontend
    // and backend TLS — cipher suites, protocol versions, key exchange groups).
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );

    // Start with empty config; CP will push the real one via gRPC.
    // The empty initial config means `start_with_shutdown` spawns no
    // health-check tasks today, so `health_check_handles` is normally
    // empty here. Plumbed through the per-mode background drain anyway
    // for symmetry with file/db modes and for forward-compatibility:
    // if a future change starts health checks at DP startup or on the
    // first CP push, the drain phase already awaits them cleanly.
    let (proxy_state, health_check_handles) = ProxyState::new(
        GatewayConfig::default(),
        dns_cache,
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
    // DP starts with an empty config — the initial refresh has nothing
    // to probe. The first `apply_incremental` / `update_config` call from
    // the CP gRPC stream will trigger `spawn_backend_capability_refresh`,
    // which populates the registry before traffic starts flowing.
    proxy_state.start_backend_capability_refresh_task(false, Some(shutdown_tx.subscribe()));

    // Start per-IP request counter cleanup (removes stale zero-count entries)
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));

    // Start service discovery background tasks (initially no-op with empty config;
    // tasks are reconciled when CP pushes config via update_config)
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

    // Spawn the DP gRPC client to connect to CP and receive config updates
    let cp_urls = env_config.resolved_dp_cp_grpc_urls();
    if cp_urls.is_empty() {
        return Err(anyhow::anyhow!(
            "FERRUM_DP_CP_GRPC_URLS is required in dp mode"
        ));
    }
    if cp_urls.len() > 1 {
        info!(
            "DP mode configured with {} CP URLs for failover",
            cp_urls.len()
        );
    }
    let jwt_secret = crate::grpc::dp_client::GrpcJwtSecret::with_issuer(
        env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
            anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in dp mode")
        })?,
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    );

    // Build DP gRPC TLS config if any TLS settings are provided.
    let dp_grpc_tls =
        crate::grpc::dp_client::build_dp_grpc_tls_config(&env_config, &cp_urls, "DP")?;
    let dp_grpc_tls_reload_handle = crate::modes::grpc_tls_reload::start_dp_grpc_tls_reload_task(
        Arc::new(env_config.clone()),
        Arc::new(cp_urls.clone()),
        "DP",
        Some(shutdown_tx.subscribe()),
    );
    let (dp_grpc_tls_reload, dp_grpc_tls_reload_watcher) =
        if let Some(handle) = dp_grpc_tls_reload_handle {
            (
                Some(crate::grpc::dp_client::DpGrpcTlsReload {
                    env_config: Arc::new(env_config.clone()),
                    label: "DP",
                    revision_rx: handle.revision_rx,
                }),
                Some(handle.watcher_handle),
            )
        } else {
            (None, None)
        };

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.frontend_tls_cert_path,
        &env_config.frontend_tls_key_path,
    ) {
        info!("Loading TLS configuration...");
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
                error!("TLS configuration validation failed: {}", e);
                return Err(anyhow::anyhow!("Invalid TLS configuration: {}", e));
            }
        }
    } else {
        info!("No TLS configuration provided (HTTP only)");
        None
    };

    // Wire opt-in frontend TLS live reload (see modes/database.rs for full
    // rationale). DP-mode listeners participate identically: live reload is
    // opt-in via FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED and disabled by
    // default.
    let proxy_frontend_reload_handles = tls_config.as_ref().map(|cfg| {
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
            "Frontend TLS live reload enabled for DP proxy HTTPS (H1/H2) and HTTP/3"
        );
    }
    let operator_frontend_tls_slot = tls_config.as_ref().map(|cfg| {
        proxy_frontend_reload_handles
            .as_ref()
            .and_then(|handles| handles.slot.clone())
            .unwrap_or_else(|| tls::frontend_tls_slot_with(cfg.clone()))
    });
    let proxy_frontend_tls_slot = if env_config.proxy_https_port != 0 {
        proxy_frontend_tls_slot_from_operator(operator_frontend_tls_slot.as_ref())
    } else {
        None
    };
    let (proxy_frontend_tls_revision_tx, proxy_frontend_tls_revision_rx) =
        tokio::sync::watch::channel(0_u64);
    let cp_frontend_tls_materialized = Arc::new(AtomicBool::new(false));
    let dp_frontend_tls_runtime =
        proxy_frontend_tls_slot
            .clone()
            .map(|slot| crate::grpc::dp_client::DpFrontendTlsRuntime {
                listener_slot: slot,
                restore_source_slot: operator_frontend_tls_slot.clone(),
                h3_revision_tx: Some(proxy_frontend_tls_revision_tx.clone()),
                cp_materialized: cp_frontend_tls_materialized.clone(),
            });

    // Set TLS config on stream listener manager for TCP proxies with frontend_tls.
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
            )
            .await;
    }

    // Start separate listeners for HTTP and HTTPS
    let mut handles = Vec::new();
    let mut startup_signals = Vec::new();

    if let (Some(listener_slot), Some(operator_slot), Some(mut operator_revision_rx)) = (
        proxy_frontend_tls_slot.clone(),
        operator_frontend_tls_slot.clone(),
        proxy_frontend_reload_handles
            .as_ref()
            .and_then(|handles| handles.revision_rx.clone()),
    ) {
        let cp_materialized = cp_frontend_tls_materialized.clone();
        let revision_tx = proxy_frontend_tls_revision_tx.clone();
        let mut bridge_shutdown = shutdown_tx.subscribe();
        let bridge_proxy_state = proxy_state.clone();
        let bridge_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = operator_revision_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        if cp_materialized.load(Ordering::Acquire) {
                            continue;
                        }
                        let operator_tls = operator_slot.load_full().as_ref().clone();
                        listener_slot.store(Arc::new(operator_tls.clone()));
                        bridge_proxy_state
                            .stream_listener_manager
                            .set_frontend_tls_config(operator_tls)
                            .await;
                        revision_tx.send_modify(|revision| {
                            *revision = revision.saturating_add(1);
                        });
                    }
                    _ = bridge_shutdown.changed() => {
                        if *bridge_shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        handles.push(bridge_handle);
    }

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

    // HTTPS listener. DP mode can hot-swap CP-delivered Gateway TLS material,
    // but still requires either bootstrap or live-reload TLS material before
    // binding the HTTPS port. This preserves HTTP-only DP deployments.
    if let Some(tls_slot) = proxy_frontend_tls_slot.clone() {
        let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let (https_started_tx, https_started_rx) = tokio::sync::oneshot::channel();
        let https_handle = tokio::spawn(async move {
            info!("Starting HTTPS proxy listener on {}", https_addr);
            if let Err(e) = proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                https_addr,
                https_state,
                https_shutdown,
                tls_slot,
                Some(https_started_tx),
            )
            .await
            {
                error!("HTTPS proxy listener error: {}", e);
            }
        });
        handles.push(https_handle);
        startup_signals.push(("HTTPS proxy listener".to_string(), https_started_rx));
    } else if env_config.proxy_https_port == 0 {
        info!("FERRUM_PROXY_HTTPS_PORT=0 — HTTPS proxy listener disabled");
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener.
    if env_config.enable_http3 {
        if env_config.proxy_https_port == 0 {
            info!("FERRUM_PROXY_HTTPS_PORT=0 — HTTP/3 proxy listener disabled");
        } else if let Some(tls_config) = tls_config.clone() {
            let h3_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            let h3_state = proxy_state.clone();
            let h3_shutdown = shutdown_tx.subscribe();
            let h3_config = crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
            let h3_tls_policy = tls_policy.clone();
            let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
            let h3_client_crls = crls.clone();
            let (h3_started_tx, h3_started_rx) = tokio::sync::oneshot::channel();
            let h3_reload = proxy_frontend_tls_slot.clone().map(|tls_slot| {
                crate::http3::server::Http3FrontendTlsReload {
                    tls_slot,
                    revision_rx: proxy_frontend_tls_revision_rx.clone(),
                }
            });
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
                        client_crls: h3_client_crls,
                        started_tx: Some(h3_started_tx),
                        frontend_tls_reload: h3_reload,
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
            info!("TLS not configured - HTTP/3 proxy listener disabled");
        }
    }

    if env_config.proxy_http_port == 0 && proxy_frontend_tls_slot.is_none() {
        warn!(
            "No HTTP or HTTPS proxy listeners are active — FERRUM_PROXY_HTTP_PORT=0 and HTTPS is disabled or TLS is not configured. Only stream proxies (TCP/UDP) will serve traffic."
        );
    }

    // Create shared CP connection state for the /cluster endpoint
    let cp_connection_state = Arc::new(arc_swap::ArcSwap::new(Arc::new(
        crate::grpc::dp_client::DpCpConnectionState::new_disconnected(
            cp_urls.first().map(|s| s.as_str()).unwrap_or(""),
        ),
    )));

    // Start Admin API listeners (read-only in DP mode)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;
    let reserved_ports = env_config.reserved_gateway_ports();
    let startup_ready = Arc::new(AtomicBool::new(false));
    let admin_state = AdminState {
        db: None, // DP has no direct DB access
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "dp".into(),
        read_only: true, // DP admin API is always read-only
        admin_audit_enabled: env_config.admin_audit_enabled,
        startup_ready: Some(startup_ready.clone()),
        db_available: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(cp_connection_state.clone()),
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
            info!("Frontend TLS live reload enabled for admin HTTPS");
        }
        let admin_tls_slot = admin_reload_handles.slot.clone();

        let admin_https_handle = tokio::spawn(async move {
            info!("Starting Admin HTTPS listener on {}", admin_https_addr);
            let result = if let Some(slot) = admin_tls_slot {
                admin::start_admin_listener_with_dynamic_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    slot,
                )
                .await
            } else {
                admin::start_admin_listener_with_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    Some(admin_tls_config),
                )
                .await
            };
            if let Err(e) = result {
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

    // Start stream proxy listeners (TCP/UDP). In DP mode bind failures are non-fatal:
    // the DP doesn't control its own config (it comes from CP), so a port
    // conflict shouldn't prevent the DP from starting.
    let failures = proxy_state.stream_listener_manager.reconcile().await;
    for (proxy_id, port, err) in &failures {
        error!(
            proxy_id = %proxy_id,
            port = port,
            "Stream listener failed to bind at startup (non-fatal in DP mode): {}",
            err
        );
    }
    wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
    // wait_until_started is best-effort in DP mode — don't fail if some listeners couldn't bind
    if failures.is_empty() {
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
    }

    let dp_proxy_state = proxy_state.clone();
    let dp_shutdown = shutdown_tx.subscribe();
    let dp_startup_ready = startup_ready.clone();
    let dp_namespace = env_config.namespace.clone();
    let dp_primary_retry_secs = env_config.dp_cp_failover_primary_retry_secs;
    let dp_conn_state = cp_connection_state.clone();
    let dp_frontend_tls_runtime = dp_frontend_tls_runtime.clone();
    let dp_client_handle = tokio::spawn(async move {
        crate::grpc::dp_client::start_dp_client_with_shutdown_and_startup_ready(
            cp_urls,
            jwt_secret,
            dp_proxy_state,
            Some(dp_shutdown),
            dp_grpc_tls,
            dp_grpc_tls_reload,
            Some(dp_startup_ready),
            dp_namespace,
            dp_primary_retry_secs,
            Some(dp_conn_state),
            dp_frontend_tls_runtime,
        )
        .await;
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
    // hanging if a task is stuck (e.g., blocked on a gRPC stream read).
    // `health_check_handles` is normally empty in DP mode (empty initial
    // config — see comment at `ProxyState::new` call site) but plumbed
    // through anyway so a future change that starts health checks at DP
    // startup is already drained by this loop.
    let mut health_check_handles = health_check_handles;
    health_check_handles.extend(proxy_state.health_checker.take_active_check_handles());
    let bg_drain = async {
        let _ = dns_handle.await;
        if let Some(h) = dns_retry_handle {
            let _ = h.await;
        }
        let _ = dp_client_handle.await;
        if let Some(h) = dp_grpc_tls_reload_watcher {
            let _ = h.await;
        }
        let _ = overload_handle.await;
        let _ = metrics_handle.await;
        let _ = runtime_system_handle.await;
        let _ = runtime_window_handle.await;
        if let Some(h) = per_ip_cleanup_handle {
            let _ = h.await;
        }
        for h in health_check_handles {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), bg_drain)
        .await
        .is_err()
    {
        warn!("Background tasks did not drain within 5s, proceeding with shutdown");
    }

    Ok(())
}

fn proxy_frontend_tls_slot_from_operator(
    operator_frontend_tls_slot: Option<&tls::SharedFrontendTls>,
) -> Option<tls::SharedFrontendTls> {
    operator_frontend_tls_slot.map(|slot| {
        Arc::new(arc_swap::ArcSwap::new(Arc::new(
            slot.load_full().as_ref().clone(),
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dp_proxy_frontend_tls_slot_is_absent_without_operator_tls() {
        assert!(proxy_frontend_tls_slot_from_operator(None).is_none());
    }

    #[test]
    fn dp_proxy_frontend_tls_slot_clones_operator_tls_slot() {
        let operator_slot = tls::empty_frontend_tls_slot();
        let listener_slot =
            proxy_frontend_tls_slot_from_operator(Some(&operator_slot)).expect("slot");

        assert!(listener_slot.load_full().as_ref().is_none());
        operator_slot.store(Arc::new(Some(
            tls::temporary_disabled_listener_tls_config().expect("temporary test TLS config"),
        )));
        assert!(
            listener_slot.load_full().as_ref().is_none(),
            "listener slot should be a clone, not the same ArcSwap as the operator source"
        );
    }
}
