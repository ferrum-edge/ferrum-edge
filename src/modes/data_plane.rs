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
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::modes::startup_security;
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls;

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    info!("DP mode: starting with empty config, waiting for CP");

    // Open the observability delivery lifecycle for this serving cycle before
    // any plugin activation registers a queue worker. Re-running this mode in
    // one process after a completed drain otherwise targets the closed
    // generation of the previous cycle.
    crate::observability_delivery::begin_serving_cycle();

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
    // Shared with `ferrum-edge validate` so env TLS/security surfaces cannot
    // drift between the two commands (issue #2976).
    let tls_policy = startup_security::load_tls_policy(&env_config)?;
    let crls = startup_security::load_crls_from_env(&env_config)?;
    let admin_allowed_cidrs = Arc::new(startup_security::load_admin_allowed_cidrs(&env_config)?);
    let metrics_auth = Arc::new(startup_security::load_metrics_auth(&env_config)?);

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
    // Advisory GHSA-3f2j-wwqw-grmg: with `FERRUM_DP_CP_GRPC_TOKEN_FILE` this DP
    // presents an externally issued token and holds no signing key at all, so
    // the shared secret is optional. Otherwise it self-mints and stamps
    // `FERRUM_CP_DP_GRPC_JWT_KEY_ID` so a trust-bundle CP can select this
    // tenant's namespace-bound verification credential.
    let jwt_secret = crate::grpc::dp_client::GrpcJwtSecret::with_issuer(
        match env_config.cp_dp_grpc_jwt_secret.clone() {
            Some(secret) => secret,
            None if env_config.dp_cp_grpc_token_file.is_some() => String::new(),
            None => {
                return Err(anyhow::anyhow!(
                    "FERRUM_CP_DP_GRPC_JWT_SECRET is required in dp mode unless \
                     FERRUM_DP_CP_GRPC_TOKEN_FILE supplies an externally issued token"
                ));
            }
        },
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    )
    .with_key_id(env_config.cp_dp_grpc_jwt_key_id.clone())
    .with_token_file(env_config.dp_cp_grpc_token_file.clone());

    // Build DP gRPC TLS config if any TLS settings are provided.
    let dp_grpc_tls =
        crate::grpc::dp_client::build_dp_grpc_tls_config(&env_config, &cp_urls, "DP")?;

    // Secure-by-default: EnvConfig::validate() already refused a non-loopback
    // http:// CP URL unless FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true. Any plaintext
    // CP URL that reaches here is therefore loopback (dev) or an explicit opt-in;
    // surface a high-severity warning either way — the minted DP JWT and the
    // gateway config travel unencrypted and unauthenticated against MITM.
    let plaintext_cp_urls: Vec<&str> = cp_urls
        .iter()
        .filter(|u| u.starts_with("http://") || u.starts_with("grpc://"))
        .map(String::as_str)
        .collect();
    if !plaintext_cp_urls.is_empty() {
        warn!(
            "SECURITY: DP config sync will use PLAINTEXT gRPC for CP URL(s): {} — the DP \
             authentication JWT and gateway configuration travel unencrypted and unauthenticated \
             against MITM. Use https:// CP URLs with FERRUM_DP_GRPC_TLS_CA_CERT_PATH in production.",
            plaintext_cp_urls.join(", ")
        );
    }

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

    // Load TLS configuration if provided (shared with validate, issue #2976).
    let tls_config = match startup_security::try_load_frontend_tls(&env_config, &tls_policy, &crls)
    {
        Ok(Some(mut config)) => {
            info!("Loading TLS configuration...");
            // Enable 0-RTT on the proxy frontend only (not admin).
            tls::enable_early_data(&mut config, &tls_policy);
            // Enable kTLS session-secret extraction on the proxy frontend
            // only (not admin) when kTLS could be used. Rustls gates
            // `dangerous_extract_secrets()` behind this flag.
            if env_config.ktls_enabled.could_be_enabled() {
                tls::enable_secret_extraction_for_ktls(&mut config);
            }
            if env_config.frontend_tls_client_ca_bundle_path.is_some() {
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
        Ok(None) => {
            info!("No TLS configuration provided (HTTP only)");
            None
        }
        Err(e) => {
            error!("TLS configuration validation failed: {:#}", e);
            return Err(e);
        }
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
        Some(proxy_frontend_tls_slot_from_operator(
            operator_frontend_tls_slot.as_ref(),
        ))
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
    // Shared expiry gate with `ferrum-edge validate` (issue #2976).
    if let (Some(cert_path), Some(key_path)) =
        (&env_config.dtls_cert_path, &env_config.dtls_key_path)
    {
        startup_security::validate_dtls_material(&env_config)?;
        proxy_state
            .stream_listener_manager
            .set_frontend_dtls_cert_key(
                cert_path.clone(),
                key_path.clone(),
                env_config.dtls_client_ca_cert_path.clone(),
            )
            .await;
    }

    // Serving listener JoinHandles are supervised concurrently (see
    // `await_dp_listener_handles`). Long-lived bridge / background tasks are
    // kept separate so a pending TLS revision bridge cannot mask a later
    // listener panic (issue #2368).
    let mut listener_handles = Vec::new();
    let mut background_handles: Vec<JoinHandle<()>> = Vec::new();
    let mut startup_signals = Vec::new();

    // Shared readiness flag. DP defers flipping it to `true` until the DP client
    // applies the first CP snapshot (and classifies backend capabilities), but
    // it is created here so every serving listener task below can capture a
    // clone and flip it back to `false` if its serve future exits with an error
    // after startup — otherwise a dead proxy/admin listener would leave the
    // process reporting `ready` on `/health` while silently not serving.
    let startup_ready = Arc::new(AtomicBool::new(false));
    // Sticky serving-degradation flag: set true (never unset) if any serving
    // listener task exits with an error after startup. The DP client re-stores
    // `startup_ready = true` on every CP-reconnect snapshot, which would re-mask
    // a listener death; because `serving_degraded` is monotonic, `/health` stays
    // not-ready across those reconnect stores once a listener has failed.
    let serving_degraded = Arc::new(AtomicBool::new(false));

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
        // Bridge lives until shutdown; keep it out of fatal listener supervision.
        background_handles.push(bridge_handle);
    }

    // HTTP listener (disabled when port is 0)
    if env_config.proxy_http_port != 0 {
        let http_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_http_port);
        let http_state = proxy_state.clone();
        let http_shutdown = shutdown_tx.subscribe();
        let (http_started_tx, http_started_rx) = tokio::sync::oneshot::channel();
        let http_startup_ready = startup_ready.clone();
        let http_serving_degraded = serving_degraded.clone();
        let http_handle = tokio::spawn(async move {
            info!(
                "Starting HTTP proxy listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_PROXY_BIND_ADDRESS",
                    "FERRUM_PROXY_HTTP_PORT",
                    &http_addr.to_string()
                )
            );
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                http_addr,
                http_state,
                http_shutdown,
                None,
                Some(http_started_tx),
            )
            .await
            {
                crate::startup::flip_ready_off_on_listener_failure(
                    &http_startup_ready,
                    &http_serving_degraded,
                    "HTTP proxy listener",
                    &e,
                );
            }
        });
        listener_handles.push(http_handle);
        startup_signals.push(("HTTP proxy listener".to_string(), http_started_rx));
    } else {
        info!(
            "{} — plaintext HTTP proxy listener disabled",
            crate::secrets::report_env_assignment("FERRUM_PROXY_HTTP_PORT", "0")
        );
    }

    // HTTPS listener. DP mode can hot-swap CP-delivered Gateway TLS material,
    // so a HTTPS-enabled DP starts with an empty dynamic TLS slot when no
    // operator certificate was configured. Set FERRUM_PROXY_HTTPS_PORT=0 for
    // HTTP-only DP deployments.
    if let Some(tls_slot) = proxy_frontend_tls_slot.clone() {
        let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let (https_started_tx, https_started_rx) = tokio::sync::oneshot::channel();
        let https_startup_ready = startup_ready.clone();
        let https_serving_degraded = serving_degraded.clone();
        let https_handle = tokio::spawn(async move {
            info!(
                "Starting HTTPS proxy listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_PROXY_BIND_ADDRESS",
                    "FERRUM_PROXY_HTTPS_PORT",
                    &https_addr.to_string()
                )
            );
            if let Err(e) = proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                https_addr,
                https_state,
                https_shutdown,
                tls_slot,
                Some(https_started_tx),
            )
            .await
            {
                crate::startup::flip_ready_off_on_listener_failure(
                    &https_startup_ready,
                    &https_serving_degraded,
                    "HTTPS proxy listener",
                    &e,
                );
            }
        });
        listener_handles.push(https_handle);
        startup_signals.push(("HTTPS proxy listener".to_string(), https_started_rx));
    } else if env_config.proxy_https_port == 0 {
        info!(
            "{} — HTTPS proxy listener disabled",
            crate::secrets::report_env_assignment("FERRUM_PROXY_HTTPS_PORT", "0")
        );
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener.
    let mut h3_listener_started = false;
    if env_config.enable_http3 {
        if env_config.proxy_https_port == 0 {
            info!(
                "{} — HTTP/3 proxy listener disabled",
                crate::secrets::report_env_assignment("FERRUM_PROXY_HTTPS_PORT", "0")
            );
        } else if let Some(tls_config) =
            http3_startup_tls_config(tls_config.clone(), proxy_frontend_tls_slot.as_ref())?
        {
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
            let h3_startup_ready = startup_ready.clone();
            let h3_serving_degraded = serving_degraded.clone();
            let h3_handle = tokio::spawn(async move {
                info!(
                    "Starting HTTP/3 (QUIC) proxy listener on {}",
                    crate::secrets::report_listener_addr(
                        "FERRUM_PROXY_BIND_ADDRESS",
                        "FERRUM_PROXY_HTTPS_PORT",
                        &h3_addr.to_string()
                    )
                );
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
                    crate::startup::flip_ready_off_on_listener_failure(
                        &h3_startup_ready,
                        &h3_serving_degraded,
                        "HTTP/3 proxy listener",
                        &e,
                    );
                }
            });
            listener_handles.push(h3_handle);
            startup_signals.push(("HTTP/3 proxy listener".to_string(), h3_started_rx));
            h3_listener_started = true;
        } else {
            info!("TLS not configured - HTTP/3 proxy listener disabled");
        }
    }
    if env_config.proxy_http_port == 0 && proxy_frontend_tls_slot.is_none() {
        warn!(
            "No HTTP or HTTPS proxy listeners are active — {} and HTTPS is disabled or TLS is not configured. Only stream proxies (TCP/UDP) will serve traffic.",
            crate::secrets::report_env_assignment("FERRUM_PROXY_HTTP_PORT", "0")
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
    // Shared admin connection limiter (plaintext + HTTPS listeners share one
    // management-plane cap, independent of the data-plane FERRUM_MAX_CONNECTIONS).
    let admin_conn_limiter = Arc::new(admin::AdminConnLimiter::new(
        env_config.admin_max_connections,
        env_config.admin_max_connections_per_ip,
    ));
    let admin_state = AdminState {
        db: None, // DP has no direct DB access
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "dp".into(),
        read_only: true, // DP admin API is always read-only
        admin_audit_enabled: env_config.admin_audit_enabled,
        admin_require_namespace_claim: env_config.admin_require_namespace_claim,
        startup_ready: Some(startup_ready.clone()),
        serving_degraded: Some(serving_degraded.clone()),
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        metrics_auth: metrics_auth.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(cp_connection_state.clone()),
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

    // Admin HTTP listener (disabled when port is 0)
    if env_config.admin_http_port != 0 {
        let admin_http_limiter = admin_conn_limiter.clone();
        let (admin_http_started_tx, admin_http_started_rx) = tokio::sync::oneshot::channel();
        let admin_http_startup_ready = startup_ready.clone();
        let admin_http_serving_degraded = serving_degraded.clone();
        let admin_http_handle = tokio::spawn(async move {
            info!(
                "Starting Admin HTTP listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTP_PORT",
                    &admin_http_addr.to_string()
                )
            );
            // The admin listener is one of the DP's own operational inputs (its
            // port comes from env, not CP-pushed config), so a bind failure is
            // the operator's misconfiguration and is fatal at startup via the
            // start signal below — consistent with the proxy listeners. A serve
            // error after startup instead flips readiness to not-ready so the
            // admin API being dead surfaces on `/health`.
            if let Err(e) = admin::start_admin_listener_with_tls_and_signal(
                admin_http_addr,
                admin_state,
                admin_shutdown,
                None,
                Some(admin_http_started_tx),
                admin_http_limiter,
            )
            .await
            {
                crate::startup::flip_ready_off_on_listener_failure(
                    &admin_http_startup_ready,
                    &admin_http_serving_degraded,
                    "Admin HTTP listener",
                    &e,
                );
            }
        });
        listener_handles.push(admin_http_handle);
        startup_signals.push(("Admin HTTP listener".to_string(), admin_http_started_rx));
    } else {
        info!(
            "{} — plaintext admin HTTP listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0")
        );
    }

    // Admin HTTPS listener (only if TLS is configured and the port is not
    // disabled — port 0 is the repository-wide disable sentinel).
    if env_config.admin_https_port == 0 {
        info!(
            "{} — admin HTTPS listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTPS_PORT", "0")
        );
    } else if env_config.admin_https_listener_enabled() {
        let admin_https_addr: SocketAddr =
            env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_https_shutdown = shutdown_tx.subscribe();

        // Load admin TLS configuration (shared with validate, issue #2976).
        let admin_tls_config = match startup_security::load_admin_tls_material(
            &env_config,
            &tls_policy,
            &crls,
            "Invalid admin TLS configuration",
        ) {
            Ok(config) => {
                if env_config.admin_tls_client_ca_bundle_path.is_some() {
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
                error!("Failed to load admin TLS configuration: {:#}", e);
                return Err(e);
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
        let admin_https_limiter = admin_conn_limiter.clone();
        let (admin_https_started_tx, admin_https_started_rx) = tokio::sync::oneshot::channel();
        let admin_https_startup_ready = startup_ready.clone();
        let admin_https_serving_degraded = serving_degraded.clone();

        let admin_https_handle = tokio::spawn(async move {
            info!(
                "Starting Admin HTTPS listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTPS_PORT",
                    &admin_https_addr.to_string()
                )
            );
            // Bind failure is fatal at startup (start signal); a post-startup
            // serve error flips readiness to not-ready. Same rationale as the
            // plaintext admin listener above.
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
            if let Err(e) = result {
                crate::startup::flip_ready_off_on_listener_failure(
                    &admin_https_startup_ready,
                    &admin_https_serving_degraded,
                    "Admin HTTPS listener",
                    &e,
                );
            }
        });
        listener_handles.push(admin_https_handle);
        startup_signals.push(("Admin HTTPS listener".to_string(), admin_https_started_rx));
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
    }
    if env_config.admin_http_port == 0 && !env_config.admin_https_listener_enabled() {
        warn!(
            "No admin API listeners are active — {} and admin HTTPS not configured or {}. The admin API is unreachable.",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0"),
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTPS_PORT", "0")
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
    proxy_state.set_h3_websocket_listener_started(h3_listener_started);

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

    // Supervise serving listeners concurrently. A later listener panic must be
    // observed promptly even while an earlier listener remains pending; on
    // panic we fire shared shutdown so siblings drain (issue #2368). The TLS
    // revision bridge and other long-lived tasks stay in `background_handles`
    // so they cannot mask listener failures under sequential join.
    let listener_result = await_dp_listener_handles(listener_handles, shutdown_tx.clone()).await;

    // Stop accepting new TCP/UDP/DTLS stream connections. The accept loops
    // also observe the global shutdown receiver wired above and will already
    // be exiting; firing each per-listener channel here clears the listener
    // map (releasing ports) and is a no-op if the loops have already exited.
    proxy_state.stream_listener_manager.shutdown_all().await;

    // Graceful connection drain: signal drain state to the proxy hot path
    // (Connection: close + reject new requests) unconditionally so the close
    // hint fires even when the operator has disabled the wait loop with
    // FERRUM_SHUTDOWN_DRAIN_SECONDS=0. Only the wait loop itself is gated.
    crate::overload::begin_shutdown_drain(&proxy_state.overload);
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
    // startup is already drained by this loop. Includes the TLS revision
    // bridge (pushed above) so external shutdown still joins it.
    background_handles.push(dns_handle);
    if let Some(h) = dns_retry_handle {
        background_handles.push(h);
    }
    background_handles.push(dp_client_handle);
    if let Some(h) = dp_grpc_tls_reload_watcher {
        background_handles.push(h);
    }
    background_handles.push(overload_handle);
    background_handles.push(metrics_handle);
    background_handles.push(runtime_system_handle);
    background_handles.push(runtime_window_handle);
    if let Some(h) = per_ip_cleanup_handle {
        background_handles.push(h);
    }
    let mut health_check_handles = health_check_handles;
    health_check_handles.extend(proxy_state.health_checker.take_active_check_handles());
    background_handles.extend(health_check_handles);
    crate::modes::file::join_background_handles(background_handles, Duration::from_secs(5)).await;
    crate::observability_delivery::shutdown(Duration::from_millis(
        env_config.log_shutdown_drain_timeout_ms,
    ))
    .await;
    crate::plugins::api_chargeback_sink::finalize_all_snapshot_generations().await;
    crate::plugins::kafka_logging::finalize_all_generations().await;

    listener_result?;
    Ok(())
}

/// Await DP serving-listener handles concurrently and trigger shared shutdown
/// on the first panic so siblings can exit.
///
/// Mirrors mesh / file-mode listener supervision: empty handle sets wait on
/// the shutdown watch channel (stream-only deployments), and panics propagate
/// as `Err` after draining remaining listeners. Long-lived bridge tasks must
/// not be passed here — keep them on the background drain path so a pending
/// earlier handle cannot mask a later listener panic (issue #2368).
pub(crate) async fn await_dp_listener_handles(
    listener_handles: Vec<JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), tokio::task::JoinError> {
    if listener_handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    let shutdown_on_panic = move || {
        let _ = shutdown_tx.send(true);
    };
    crate::modes::file::await_listener_handles(listener_handles, shutdown_on_panic).await
}

fn proxy_frontend_tls_slot_from_operator(
    operator_frontend_tls_slot: Option<&tls::SharedFrontendTls>,
) -> tls::SharedFrontendTls {
    operator_frontend_tls_slot.map_or_else(tls::empty_frontend_tls_slot, |slot| {
        Arc::new(arc_swap::ArcSwap::new(Arc::new(
            slot.load_full().as_ref().clone(),
        )))
    })
}

fn http3_startup_tls_config(
    operator_tls_config: Option<Arc<rustls::ServerConfig>>,
    proxy_frontend_tls_slot: Option<&tls::SharedFrontendTls>,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    if operator_tls_config.is_some() {
        return Ok(operator_tls_config);
    }
    if proxy_frontend_tls_slot.is_some() {
        return tls::temporary_disabled_listener_tls_config().map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dp_proxy_frontend_tls_slot_is_empty_without_operator_tls() {
        let listener_slot = proxy_frontend_tls_slot_from_operator(None);

        assert!(listener_slot.load_full().as_ref().is_none());
    }

    #[test]
    fn dp_proxy_frontend_tls_slot_clones_operator_tls_slot() {
        let operator_slot = tls::empty_frontend_tls_slot();
        let listener_slot = proxy_frontend_tls_slot_from_operator(Some(&operator_slot));

        assert!(listener_slot.load_full().as_ref().is_none());
        operator_slot.store(Arc::new(Some(
            tls::temporary_disabled_listener_tls_config().expect("temporary test TLS config"),
        )));
        assert!(
            listener_slot.load_full().as_ref().is_none(),
            "listener slot should be a clone, not the same ArcSwap as the operator source"
        );
    }

    #[test]
    fn http3_startup_tls_config_uses_operator_tls() {
        let operator_tls =
            tls::temporary_disabled_listener_tls_config().expect("temporary test TLS config");

        let startup_tls =
            http3_startup_tls_config(Some(operator_tls.clone()), None).expect("startup TLS config");

        assert!(startup_tls.is_some_and(|tls| Arc::ptr_eq(&tls, &operator_tls)));
    }

    #[test]
    fn http3_startup_tls_config_bootstraps_dynamic_tls_slot() {
        let listener_slot = tls::empty_frontend_tls_slot();

        let startup_tls =
            http3_startup_tls_config(None, Some(&listener_slot)).expect("startup TLS config");

        assert!(
            startup_tls.is_some(),
            "HTTP/3 should bind and wait for CP-delivered frontend TLS"
        );
    }

    #[test]
    fn http3_startup_tls_config_is_absent_without_any_tls_source() {
        let startup_tls =
            http3_startup_tls_config(None, None).expect("startup TLS config decision");

        assert!(startup_tls.is_none());
    }
}
