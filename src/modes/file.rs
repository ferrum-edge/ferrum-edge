//! File mode — single-instance gateway backed by a YAML/JSON config file.
//!
//! Config is loaded once at startup. On Unix, sending SIGHUP triggers a
//! hot reload: the file is re-parsed, validated, and atomically swapped
//! into the running gateway without dropping connections.
//!
//! The admin API is always read-only in this mode (no database to write to).
//! If `FERRUM_ADMIN_JWT_SECRET` is not set, a random secret is generated —
//! any externally-crafted JWT will be rejected since nobody knows the secret.
//!
//! ## Public entry points
//!
//! - [`run`] — the binary entry point. Loads the YAML/JSON config from
//!   `FERRUM_FILE_CONFIG_PATH`, registers a SIGHUP reload handler, and runs
//!   forever until shutdown is signalled. This is what `ferrum-edge run`
//!   ultimately calls into.
//! - [`serve`] — an in-process entry point that takes an already-built
//!   `GatewayConfig`, optional pre-bound TCP listeners for the proxy and
//!   admin ports, and a shutdown receiver. Returns a [`ServeHandles`]
//!   struct that holds the `ProxyState` and JoinHandles for every spawned
//!   task. Used by the in-process variant of `tests/scaffolding/harness.rs`
//!   to spin up a real gateway in ~100ms without invoking a subprocess.
//!
//! `serve()` deliberately omits the SIGHUP handler — caller-driven config
//! updates go through `proxy_state.update_config()` directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::file_loader;
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

/// Pre-bound TCP listeners + admin overrides that callers of [`serve`] can
/// hand to the gateway instead of letting it bind ports / read env itself.
///
/// Each listener field is independent: leave a slot `None` to disable that
/// listener, pass `Some` to use the caller's socket. When a slot is `Some`,
/// the corresponding port in [`EnvConfig`] is ignored — the listener is
/// adopted as-is and its already-bound address is what clients connect to.
///
/// In-process tests reserve ports via `tests/scaffolding/ports.rs` and pass
/// the live listeners in here so the gateway adopts the same FD without
/// re-binding (which would be racy under parallel test load).
///
/// `admin_jwt_manager`, when provided, bypasses
/// [`crate::admin::jwt_auth::create_jwt_manager_from_env`] entirely. Tests
/// running in the same process can't share the global `FERRUM_ADMIN_JWT_*`
/// env vars without serialising — passing a manager directly avoids the
/// dance.
#[derive(Default)]
pub struct ServeOptions {
    /// Plaintext proxy port. `None` disables the plaintext proxy listener.
    pub proxy_http: Option<TcpListener>,
    /// TLS proxy port. `None` disables the HTTPS proxy listener even when
    /// TLS material is configured.
    pub proxy_https: Option<TcpListener>,
    /// Plaintext admin port. `None` disables the plaintext admin listener.
    pub admin_http: Option<TcpListener>,
    /// TLS admin port. `None` disables the HTTPS admin listener even when
    /// admin TLS material is configured.
    pub admin_https: Option<TcpListener>,
    /// Pre-built admin JWT manager. When `None`, `serve` reads the JWT
    /// secret/issuer/ttl from environment variables (same as the binary
    /// path does via `create_jwt_manager_from_env`).
    pub admin_jwt_manager: Option<crate::admin::jwt_auth::JwtManager>,
    /// When `true`, `serve` does not trigger the immediate
    /// backend-capability probe pass on startup; only the periodic refresh
    /// loop is started.
    ///
    /// The binary leaves this `false`: when warmup is also off, an
    /// immediate probe is the only thing that populates the registry
    /// before the first periodic tick (default 24 h), without which
    /// HTTPS dispatch falls back to reqwest for the entire window.
    ///
    /// In-process tests set this `true` to keep the harness "cold". The
    /// h2c probe that runs against HTTP backends opens a real connection
    /// to the (often scripted) backend, which would consume the first
    /// `ExpectRequest` step or perturb per-test connection counts.
    /// Tests that explicitly need the probe behaviour opt in via
    /// `pool_warmup_enabled(true)` instead — that path runs warmup first
    /// (which itself populates the registry) and is awaited before
    /// `serve()` returns, so the test gets a deterministic snapshot
    /// rather than racing the background refresh.
    pub skip_initial_capability_refresh: bool,
}

/// Handles returned by [`serve`].
///
/// The caller can:
/// 1. Drive requests through the gateway via the bound listeners' addresses.
/// 2. Read state out of [`ServeHandles::proxy_state`] (e.g. metrics,
///    capability registry, dispatch kind).
/// 3. Trigger shutdown by `send`-ing `true` on the [`tokio::sync::watch`]
///    channel passed to `serve()`.
/// 4. Await graceful drain by `await`ing [`ServeHandles::join`].
pub struct ServeHandles {
    /// Shared proxy state. Tests can read metrics, swap config, etc.
    pub proxy_state: ProxyState,
    /// Local addresses each listener is bound to (resolved from the pre-bound
    /// listener, **not** read from `EnvConfig`). Tests use this to build
    /// canonical proxy/admin URLs.
    #[allow(dead_code)] // The binary path drops this immediately; tests read it.
    pub bound: BoundAddresses,
    /// Listener task handles (proxy HTTP/HTTPS/H3 + admin HTTP/HTTPS).
    /// These exit cleanly when the shutdown signal fires, so [`Self::join`]
    /// awaits them unbounded.
    listener_handles: Vec<JoinHandle<()>>,
    /// Background task handles (DNS refresh, overload monitor, metrics).
    /// [`Self::join`] caps the wait on these at [`BACKGROUND_DRAIN_TIMEOUT`]
    /// so a stuck task can never wedge graceful shutdown indefinitely
    /// — the binary's pre-refactor `run()` had the same 5 s cap, and
    /// rolling-restart / test-teardown ergonomics rely on it.
    background_handles: Vec<JoinHandle<()>>,
    /// `FERRUM_SHUTDOWN_DRAIN_SECONDS` snapshot — bound on the in-flight
    /// request drain that runs between listener exit and background-task
    /// drain.
    drain_seconds: u64,
}

/// Hard cap on background-task drain (DNS refresh, overload monitor,
/// metrics) during shutdown. Mirrors the pre-refactor `run()`'s 5 s
/// timeout — without it, a stuck background task wedges the whole
/// shutdown.
const BACKGROUND_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolved listener addresses returned by [`serve`].
#[derive(Default, Clone, Debug)]
pub struct BoundAddresses {
    pub proxy_http: Option<SocketAddr>,
    pub proxy_https: Option<SocketAddr>,
    pub admin_http: Option<SocketAddr>,
    pub admin_https: Option<SocketAddr>,
}

impl ServeHandles {
    /// Wait for every spawned listener / background task to finish.
    ///
    /// Callers must trigger shutdown on the [`tokio::sync::watch::Sender`]
    /// they passed into [`serve`] before awaiting this future, otherwise
    /// `join()` will hang waiting for accept loops that never exit.
    ///
    /// Three phases — match the pre-refactor `run()`:
    ///
    /// 1. Listener handles awaited unbounded. These exit on the shutdown
    ///    watch channel; once all are gone no new connections arrive.
    /// 2. In-flight request drain bounded by `FERRUM_SHUTDOWN_DRAIN_SECONDS`.
    ///    Existing connections see `Connection: close` and finish their
    ///    current request-response cycle.
    /// 3. Background tasks (DNS refresh, overload monitor, metrics)
    ///    awaited with [`BACKGROUND_DRAIN_TIMEOUT`]. A stuck task logs a
    ///    warning instead of wedging shutdown — without this cap a
    ///    rolling restart could hang on a single misbehaving task.
    pub async fn join(self) {
        for handle in self.listener_handles {
            let _ = handle.await;
        }
        if self.drain_seconds > 0 {
            crate::overload::wait_for_drain(
                &self.proxy_state.overload,
                Duration::from_secs(self.drain_seconds),
            )
            .await;
        }
        join_background_handles(self.background_handles, BACKGROUND_DRAIN_TIMEOUT).await;
    }
}

/// Await every handle in `handles`, capped at `timeout`. On timeout we log
/// a single warning and return — a stuck task is not allowed to wedge
/// graceful shutdown. Pulled out of [`ServeHandles::join`] so the timeout
/// behaviour is unit-testable without constructing a `ProxyState`.
async fn join_background_handles(handles: Vec<JoinHandle<()>>, timeout: Duration) {
    let drain = async {
        for handle in handles {
            let _ = handle.await;
        }
    };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        warn!(
            "Background tasks did not drain within {}s, proceeding with shutdown",
            timeout.as_secs()
        );
    }
}

/// The binary entry point. Loads the YAML/JSON config from
/// `FERRUM_FILE_CONFIG_PATH`, then dispatches into [`serve`] with a
/// SIGHUP reload handler installed on top.
pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    info!(
        "Starting in file mode with log level: {}",
        env_config.log_level
    );
    if env_config.proxy_https_port != 8443 {
        info!(
            "Custom HTTPS port configured: {}",
            env_config.proxy_https_port
        );
    }
    if env_config.admin_https_port != 9443 {
        info!(
            "Custom admin HTTPS port configured: {}",
            env_config.admin_https_port
        );
    }
    if env_config.admin_tls_cert_path.is_some() || env_config.admin_tls_key_path.is_some() {
        info!("Admin API TLS certificates configured");
    }
    let config_path = env_config
        .file_config_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("FERRUM_FILE_CONFIG_PATH not set"))?;

    let config = file_loader::load_config_from_file(
        config_path,
        env_config.tls_cert_expiry_warning_days,
        &env_config.backend_allow_ips,
        &env_config.namespace,
    )?;

    // Hand off to serve(). It builds ProxyState, spawns listeners, and waits
    // until shutdown — exactly what run() used to do inline. The only extra
    // bit is the SIGHUP handler, registered alongside.
    let handles = serve(
        env_config.clone(),
        config,
        ServeOptions::default(),
        shutdown_tx.clone(),
    )
    .await?;

    // SIGHUP-driven config reload (Unix only). On non-Unix this future just
    // waits on shutdown so the join order is unchanged.
    let proxy_state_reload = handles.proxy_state.clone();
    let config_path_owned = config_path.to_string();
    let reload_cert_expiry_warning_days = env_config.tls_cert_expiry_warning_days;
    let reload_backend_allow_ips = env_config.backend_allow_ips.clone();
    let reload_namespace = env_config.namespace.clone();
    let mut sighup_shutdown = shutdown_tx.subscribe();
    let sighup_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to register SIGHUP handler: {}", e);
                    return;
                }
            };
            loop {
                tokio::select! {
                    _ = sighup.recv() => {
                        info!("SIGHUP received, reloading configuration...");
                        match file_loader::reload_config_from_file(&config_path_owned, reload_cert_expiry_warning_days, &reload_backend_allow_ips, &reload_namespace) {
                            Ok(new_config) => {
                                proxy_state_reload.update_config(new_config);
                                info!("Configuration reloaded successfully");
                            }
                            Err(e) => {
                                error!(
                                    "Configuration reload failed, keeping previous config: {}",
                                    e
                                );
                            }
                        }
                    }
                    _ = sighup_shutdown.changed() => {
                        info!("SIGHUP listener shutting down");
                        return;
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            warn!(
                "SIGHUP config reload is not available on this platform. Restart the process to apply config changes."
            );
            let _ = sighup_shutdown.changed().await;
        }
    });

    // Wait for serve()'s tasks to drain (proxy listeners + background tasks).
    handles.join().await;

    // SIGHUP listener exits via shutdown_rx — wait for it too with a timeout.
    let _ = tokio::time::timeout(Duration::from_secs(5), sighup_handle).await;

    Ok(())
}

/// In-process entry point.
///
/// Builds a [`ProxyState`] from `config`, spawns proxy and admin listeners
/// (using `prebound` listeners where provided, otherwise binding the ports
/// from `env_config`), and returns a [`ServeHandles`] without blocking.
///
/// Unlike [`run`], this function:
///
/// - Skips SIGHUP reload (caller drives reloads via
///   `handles.proxy_state.update_config(...)`).
/// - Skips the shutdown-signal handler — the caller already owns the
///   `shutdown_tx`.
/// - Returns once every listener has bound (or adopted its pre-bound socket)
///   — the gateway is ready to take traffic before this function returns.
///
/// Stream proxy bind failures are still fatal here: this matches `run()`'s
/// invariants and keeps tests honest about config typos.
pub async fn serve(
    env_config: EnvConfig,
    config: GatewayConfig,
    mut prebound: ServeOptions,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<ServeHandles, anyhow::Error> {
    info!(
        "file::serve: starting in-process gateway with {} proxies, {} consumers",
        config.proxies.len(),
        config.consumers.len()
    );

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
        backend_allow_ips: env_config.backend_allow_ips.clone(),
    });

    // DNS warmup — collect every hostname referenced in the config (proxy
    // backends, upstream targets, plugin endpoints) so the first request
    // doesn't pay the resolver round-trip.
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
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );

    let proxy_state = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
    )?;

    let plugin_hosts = proxy_state.plugin_cache.collect_warmup_hostnames();
    for host in plugin_hosts {
        hostnames.push((host, None, None));
    }

    dns_cache.warmup(hostnames).await;

    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    // Without warmup, the registry is otherwise empty until the first
    // periodic tick (24 h default) — pass `true` so `start_backend_*`
    // kicks off an immediate probe pass. In-process tests that want a
    // truly cold gateway set `skip_initial_capability_refresh` to opt
    // out of that probe (see `ServeOptions` docs).
    let run_initial_refresh =
        !env_config.pool_warmup_enabled && !prebound.skip_initial_capability_refresh;
    proxy_state
        .start_backend_capability_refresh_task(run_initial_refresh, Some(shutdown_tx.subscribe()));

    proxy_state.start_per_ip_cleanup_task();

    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));
    let _dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );

    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );

    // Validate frontend TLS config if provided (paths, expiry, key match).
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
            Ok(mut config) => {
                tls::enable_early_data(&mut config, &tls_policy);
                if env_config.ktls_enabled.could_be_enabled() {
                    tls::enable_secret_extraction_for_ktls(&mut config);
                }
                Some(config)
            }
            Err(e) => {
                error!("TLS configuration validation failed: {}", e);
                return Err(anyhow::anyhow!("Invalid TLS configuration: {}", e));
            }
        }
    } else {
        None
    };

    if let Some(ref tls_cfg) = tls_config {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_cfg.clone()));
    }

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
            );
    }

    // Listen for SIGHUP — only meaningful for run(); skipped here.
    let startup_ready = Arc::new(AtomicBool::new(false));
    let jwt_manager = if let Some(jm) = prebound.admin_jwt_manager.take() {
        // Caller (in-process harness) supplied its own — bypass env reads
        // entirely so parallel tests don't have to serialise on
        // `FERRUM_ADMIN_JWT_*` globals.
        jm
    } else {
        match create_jwt_manager_from_env() {
            Ok(jm) => jm,
            Err(e) => {
                warn!(
                    "Admin JWT not configured ({}), admin endpoints will reject requests",
                    e
                );
                let random_secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
                crate::admin::jwt_auth::JwtManager::new(crate::admin::jwt_auth::JwtConfig {
                    secret: random_secret,
                    ..Default::default()
                })
            }
        }
    };
    let admin_state = AdminState {
        db: None,
        jwt_manager,
        proxy_state: Some(proxy_state.clone()),
        cached_config: Some(proxy_state.config.clone()),
        mode: "file".to_string(),
        read_only: true,
        startup_ready: Some(startup_ready.clone()),
        db_available: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        reserved_ports,
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        cp_connection_state: None,
    };

    // Listener handles (proxy/admin HTTP/HTTPS/H3) — `join()` waits on
    // these unbounded; they exit promptly on the shutdown watch channel.
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    let mut bound = BoundAddresses::default();

    // ── Admin HTTP listener ──────────────────────────────────────────────
    if let Some(listener) = prebound.admin_http.take() {
        bound.admin_http = listener.local_addr().ok();
        let st = admin_state.clone();
        let sh = shutdown_tx.subscribe();
        let h = tokio::spawn(async move {
            if let Err(e) =
                admin::start_admin_listener_with_bound_listener(listener, st, sh, None).await
            {
                error!("Admin HTTP listener error: {}", e);
            }
        });
        handles.push(h);
    } else if env_config.admin_http_port != 0 {
        let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
        bound.admin_http = Some(admin_http_addr);
        let st = admin_state.clone();
        let sh = shutdown_tx.subscribe();
        let h = tokio::spawn(async move {
            info!("Starting admin HTTP listener on {}", admin_http_addr);
            if let Err(e) = admin::start_admin_listener(admin_http_addr, st, sh).await {
                error!("Admin HTTP listener error: {}", e);
            }
        });
        handles.push(h);
    } else {
        info!("FERRUM_ADMIN_HTTP_PORT=0 — plaintext admin HTTP listener disabled");
    }

    // ── Admin HTTPS listener ─────────────────────────────────────────────
    if let (Some(admin_cert), Some(admin_key)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_tls_policy = TlsPolicy::from_env_config(&env_config)?;
        let admin_client_ca = env_config.admin_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(
            admin_cert,
            admin_key,
            admin_client_ca,
            env_config.admin_tls_no_verify,
            &admin_tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(admin_tls_config) => {
                if let Some(listener) = prebound.admin_https.take() {
                    bound.admin_https = listener.local_addr().ok();
                    let st = admin_state.clone();
                    let sh = shutdown_tx.subscribe();
                    let cfg = Some(admin_tls_config);
                    let h = tokio::spawn(async move {
                        if let Err(e) =
                            admin::start_admin_listener_with_bound_listener(listener, st, sh, cfg)
                                .await
                        {
                            error!("Admin HTTPS listener error: {}", e);
                        }
                    });
                    handles.push(h);
                } else {
                    let admin_https_addr: SocketAddr =
                        env_config.admin_socket_addr(env_config.admin_https_port);
                    bound.admin_https = Some(admin_https_addr);
                    let st = admin_state.clone();
                    let sh = shutdown_tx.subscribe();
                    let cfg = Some(admin_tls_config);
                    let h = tokio::spawn(async move {
                        info!("Starting admin HTTPS listener on {}", admin_https_addr);
                        if let Err(e) =
                            admin::start_admin_listener_with_tls(admin_https_addr, st, sh, cfg)
                                .await
                        {
                            error!("Admin HTTPS listener error: {}", e);
                        }
                    });
                    handles.push(h);
                }
            }
            Err(e) => {
                warn!(
                    "Admin TLS configuration failed, HTTPS admin disabled: {}",
                    e
                );
            }
        }
    }
    if env_config.admin_http_port == 0
        && env_config.admin_tls_cert_path.is_none()
        && bound.admin_http.is_none()
        && bound.admin_https.is_none()
    {
        warn!(
            "No admin API listeners are active — FERRUM_ADMIN_HTTP_PORT=0 and no admin TLS configured. The admin API is unreachable."
        );
    }

    // ── Proxy HTTP listener ──────────────────────────────────────────────
    let mut startup_signals = Vec::new();

    if let Some(listener) = prebound.proxy_http.take() {
        bound.proxy_http = listener.local_addr().ok();
        let st = proxy_state.clone();
        let sh = shutdown_tx.subscribe();
        let h = tokio::spawn(async move {
            if let Err(e) =
                proxy::start_proxy_listener_with_bound_listener(listener, st, sh, None).await
            {
                error!("HTTP proxy listener error: {}", e);
            }
        });
        handles.push(h);
        // Pre-bound listener is already accepting — no startup signal needed.
    } else if env_config.proxy_http_port != 0 {
        let http_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_http_port);
        bound.proxy_http = Some(http_addr);
        let st = proxy_state.clone();
        let sh = shutdown_tx.subscribe();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let h = tokio::spawn(async move {
            info!("Starting HTTP proxy listener on {}", http_addr);
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                http_addr,
                st,
                sh,
                None,
                Some(started_tx),
            )
            .await
            {
                error!("HTTP proxy listener error: {}", e);
            }
        });
        handles.push(h);
        startup_signals.push(("HTTP proxy listener".to_string(), started_rx));
    } else {
        info!("FERRUM_PROXY_HTTP_PORT=0 — plaintext HTTP proxy listener disabled");
    }

    // ── Proxy HTTPS listener (TLS) ───────────────────────────────────────
    if let Some(tls_cfg_arc) = tls_config.clone() {
        if let Some(listener) = prebound.proxy_https.take() {
            bound.proxy_https = listener.local_addr().ok();
            let st = proxy_state.clone();
            let sh = shutdown_tx.subscribe();
            let cfg = Some(tls_cfg_arc.clone());
            let h = tokio::spawn(async move {
                if let Err(e) =
                    proxy::start_proxy_listener_with_bound_listener(listener, st, sh, cfg).await
                {
                    error!("HTTPS proxy listener error: {}", e);
                }
            });
            handles.push(h);
        } else {
            let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            bound.proxy_https = Some(https_addr);
            let st = proxy_state.clone();
            let sh = shutdown_tx.subscribe();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let cfg = Some(tls_cfg_arc.clone());
            let h = tokio::spawn(async move {
                info!("Starting HTTPS proxy listener on {}", https_addr);
                if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                    https_addr,
                    st,
                    sh,
                    cfg,
                    Some(started_tx),
                )
                .await
                {
                    error!("HTTPS proxy listener error: {}", e);
                }
            });
            handles.push(h);
            startup_signals.push(("HTTPS proxy listener".to_string(), started_rx));
        }
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // ── HTTP/3 (QUIC) listener ───────────────────────────────────────────
    // H3 always binds its own UDP socket — no pre-bound variant.
    if env_config.enable_http3 {
        if let Some(tls_cfg_arc) = tls_config.clone() {
            let h3_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            let st = proxy_state.clone();
            let sh = shutdown_tx.subscribe();
            let h3_config = crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
            let h3_tls_policy = tls_policy.clone();
            let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let h = tokio::spawn(async move {
                info!("Starting HTTP/3 (QUIC) proxy listener on {}", h3_addr);
                if let Err(e) = crate::http3::server::start_http3_listener_with_signal(
                    h3_addr,
                    st,
                    sh,
                    tls_cfg_arc,
                    h3_config,
                    &h3_tls_policy,
                    crate::http3::server::Http3ListenerOptions {
                        client_ca_bundle_path: h3_client_ca,
                        started_tx: Some(started_tx),
                    },
                )
                .await
                {
                    error!("HTTP/3 proxy listener error: {}", e);
                }
            });
            handles.push(h);
            startup_signals.push(("HTTP/3 proxy listener".to_string(), started_rx));
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }

    // Stream proxy listeners (TCP/UDP) — fatal if any binds fail in file mode.
    proxy_state.initial_reconcile_stream_listeners().await?;
    wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
    proxy_state
        .stream_listener_manager
        .wait_until_started(Duration::from_secs(10))
        .await?;
    startup_ready.store(true, Ordering::Relaxed);
    info!("Gateway startup complete; /health now reports ready");

    // Background-task handles tracked separately so `ServeHandles::join`
    // can apply a hard `BACKGROUND_DRAIN_TIMEOUT` cap to them. The
    // pre-refactor `run()` did the same with an explicit
    // `tokio::time::timeout(Duration::from_secs(5), bg_drain)` block —
    // mixing them in with listener handles loses that bound and lets a
    // stuck DNS / metrics task wedge shutdown indefinitely.
    let background_handles: Vec<JoinHandle<()>> = vec![dns_handle, overload_handle, metrics_handle];

    Ok(ServeHandles {
        proxy_state,
        bound,
        listener_handles: handles,
        background_handles,
        drain_seconds: env_config.shutdown_drain_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::time::Instant;

    // Regression: a stuck background task must not wedge graceful shutdown.
    // The pre-refactor `run()` capped the background drain at 5 s; the
    // codex review flagged that lifting this into `ServeHandles::join` lost
    // the bound. The helper takes the timeout as a parameter, so this test
    // uses a 100 ms cap to assert the semantics without burning real
    // seconds (`tokio::time::pause` would need the `test-util` feature
    // which isn't enabled here).
    #[tokio::test]
    async fn join_background_handles_caps_at_timeout_when_a_handle_hangs() {
        let well_behaved = tokio::spawn(async {});
        let stuck = tokio::spawn(async {
            pending::<()>().await;
        });

        let started = Instant::now();
        join_background_handles(vec![well_behaved, stuck], Duration::from_millis(100)).await;
        let elapsed = started.elapsed();

        // Must complete within ~timeout + slop — never wedge forever.
        assert!(
            elapsed >= Duration::from_millis(100),
            "join must wait for the timeout, not return early; got {elapsed:?}",
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "join must not exceed the timeout substantially; got {elapsed:?}",
        );
    }

    // Sanity: when every background handle resolves promptly, the helper
    // returns immediately instead of blocking until the timeout.
    #[tokio::test]
    async fn join_background_handles_returns_promptly_when_all_complete() {
        let h1 = tokio::spawn(async {});
        let h2 = tokio::spawn(async {});

        let started = Instant::now();
        join_background_handles(vec![h1, h2], Duration::from_secs(5)).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "well-behaved background handles should drain promptly; took {elapsed:?}",
        );
    }
}
