use std::net::SocketAddr;
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::file_loader;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    // Log configuration details
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

    let config = file_loader::load_config_from_file(config_path)?;
    info!(
        "File mode: loaded {} proxies, {} consumers",
        config.proxies.len(),
        config.consumers.len()
    );

    let dns_cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: env_config.dns_cache_ttl_seconds,
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        valid_ttl_override: env_config.dns_valid_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
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

    // Build ProxyState first so the plugin cache exists with the shared DNS
    // cache, then collect plugin hostnames to include in warmup.
    let proxy_state = ProxyState::new(config, dns_cache.clone(), env_config.clone())?;

    // Collect plugin endpoint hostnames (http_logging, oauth2_auth, etc.)
    let plugin_hosts = proxy_state.plugin_cache.collect_warmup_hostnames();
    for host in plugin_hosts {
        hostnames.push((host, None, None));
    }

    dns_cache.warmup(hostnames).await;

    // Start background TTL refresh to keep cache warm (with shutdown)
    dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;

    // Validate TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.proxy_tls_cert_path,
        &env_config.proxy_tls_key_path,
    ) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(
            cert_path,
            key_path,
            client_ca_bundle_path,
            env_config.backend_tls_no_verify,
            &tls_policy,
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

    // Log size limits if non-default
    if env_config.max_header_size_bytes != 32_768 {
        info!(
            "Custom max header size: {} bytes",
            env_config.max_header_size_bytes
        );
    }
    if env_config.max_body_size_bytes != 10_485_760 {
        info!(
            "Custom max body size: {} bytes",
            env_config.max_body_size_bytes
        );
    }

    // Listen for SIGHUP to reload config (with shutdown)
    let proxy_state_reload = proxy_state.clone();
    let config_path_owned = config_path.to_string();
    let mut sighup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
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
                        match file_loader::reload_config_from_file(&config_path_owned) {
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
    });

    // Start Admin API (read-only in file mode)
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(jm) => jm,
        Err(e) => {
            warn!(
                "Admin JWT not configured ({}), admin endpoints will reject requests",
                e
            );
            // Create a dummy JWT manager that will reject all requests
            crate::admin::jwt_auth::JwtManager::new(crate::admin::jwt_auth::JwtConfig {
                secret: "file-mode-no-jwt-configured".to_string(),
                ..Default::default()
            })
        }
    };
    let admin_state = AdminState {
        db: None,
        jwt_manager,
        proxy_state: Some(proxy_state.clone()),
        cached_config: Some(proxy_state.config.clone()),
        mode: "file".to_string(),
        read_only: true,
    };

    let mut handles = Vec::new();

    // Admin HTTP listener
    let admin_http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let admin_http_state = admin_state.clone();
    let admin_http_shutdown = shutdown_tx.subscribe();
    let admin_http_handle = tokio::spawn(async move {
        info!("Starting admin HTTP listener on {}", admin_http_addr);
        if let Err(e) =
            admin::start_admin_listener(admin_http_addr, admin_http_state, admin_http_shutdown)
                .await
        {
            error!("Admin HTTP listener error: {}", e);
        }
    });
    handles.push(admin_http_handle);

    // Admin HTTPS listener (if TLS is configured for admin)
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
        ) {
            Ok(admin_tls_config) => {
                let admin_https_addr: SocketAddr =
                    format!("0.0.0.0:{}", env_config.admin_https_port).parse()?;
                let admin_https_state = admin_state.clone();
                let admin_https_shutdown = shutdown_tx.subscribe();
                let admin_https_handle = tokio::spawn(async move {
                    info!("Starting admin HTTPS listener on {}", admin_https_addr);
                    if let Err(e) = admin::start_admin_listener_with_tls(
                        admin_https_addr,
                        admin_https_state,
                        admin_https_shutdown,
                        Some(admin_tls_config),
                    )
                    .await
                    {
                        error!("Admin HTTPS listener error: {}", e);
                    }
                });
                handles.push(admin_https_handle);
            }
            Err(e) => {
                warn!(
                    "Admin TLS configuration failed, HTTPS admin disabled: {}",
                    e
                );
            }
        }
    }

    // Start separate listeners for HTTP and HTTPS proxy

    // HTTP listener (always enabled)
    let http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let http_state = proxy_state.clone();
    let http_shutdown = shutdown_tx.subscribe();
    let http_handle = tokio::spawn(async move {
        info!("Starting HTTP proxy listener on {}", http_addr);
        if let Err(e) = proxy::start_proxy_listener(http_addr, http_state, http_shutdown).await {
            error!("HTTP proxy listener error: {}", e);
        }
    });
    handles.push(http_handle);

    // HTTPS listener (only if TLS is configured)
    if let Some(tls_config) = tls_config.clone() {
        let https_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_https_port).parse()?;
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let https_handle = tokio::spawn(async move {
            info!("Starting HTTPS proxy listener on {}", https_addr);
            if let Err(e) = proxy::start_proxy_listener_with_tls(
                https_addr,
                https_state,
                https_shutdown,
                Some(tls_config),
            )
            .await
            {
                error!("HTTPS proxy listener error: {}", e);
            }
        });
        handles.push(https_handle);
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener (only if enabled and TLS is configured)
    if env_config.enable_http3 {
        if let Some(tls_config) = tls_config.clone() {
            let h3_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_https_port).parse()?;
            let h3_state = proxy_state.clone();
            let h3_shutdown = shutdown_tx.subscribe();
            let h3_config = crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
            let h3_tls_policy = tls_policy.clone();
            let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
            let h3_handle = tokio::spawn(async move {
                info!("Starting HTTP/3 (QUIC) proxy listener on {}", h3_addr);
                if let Err(e) = crate::http3::server::start_http3_listener(
                    h3_addr,
                    h3_state,
                    h3_shutdown,
                    tls_config,
                    h3_config,
                    &h3_tls_policy,
                    h3_client_ca,
                )
                .await
                {
                    error!("HTTP/3 proxy listener error: {}", e);
                }
            });
            handles.push(h3_handle);
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }

    // Wait for all listeners to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
