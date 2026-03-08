use std::net::SocketAddr;
use tracing::{error, info};

use crate::config::file_loader;
use crate::config::EnvConfig;
use crate::dns::DnsCache;
use crate::proxy::{self, ProxyState};
use crate::tls;

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    // Log configuration details
    info!("Starting in file mode with log level: {}", env_config.log_level);
    if env_config.proxy_https_port != 8443 {
        info!("Custom HTTPS port configured: {}", env_config.proxy_https_port);
    }
    if env_config.admin_https_port != 9443 {
        info!("Custom admin HTTPS port configured: {}", env_config.admin_https_port);
    }
    if env_config.admin_tls_cert_path.is_some() || env_config.admin_tls_key_path.is_some() {
        info!("Admin API TLS certificates configured");
    }
    if env_config.db_incremental_polling {
        info!("Database incremental polling enabled");
    }
    if env_config.db_poll_check_interval != 5 {
        info!("Custom database poll check interval: {} seconds", env_config.db_poll_check_interval);
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

    let dns_cache = DnsCache::new(
        env_config.dns_cache_ttl_seconds,
        env_config.dns_overrides.clone(),
    );

    // DNS warmup
    let hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|p| (p.backend_host.clone(), p.dns_override.clone(), p.dns_cache_ttl_seconds))
        .collect();
    let dns_warmup = dns_cache.clone();
    tokio::spawn(async move {
        dns_warmup.warmup(hostnames).await;
    });

    let proxy_state = ProxyState::new(config, dns_cache, env_config.clone());

    // Validate TLS configuration if provided
    if let (Some(cert_path), Some(key_path)) = (&env_config.proxy_tls_cert_path, &env_config.proxy_tls_key_path) {
        info!("Validating TLS configuration...");
        match tls::load_tls_config(cert_path, key_path) {
            Ok(_) => {
                info!("TLS configuration is valid (HTTPS support available)");
            }
            Err(e) => {
                error!("TLS configuration validation failed: {}", e);
                return Err(anyhow::anyhow!("Invalid TLS configuration: {}", e));
            }
        }
    }

    // Log size limits if non-default
    if env_config.max_header_size_bytes != 8192 {
        info!("Custom max header size: {} bytes", env_config.max_header_size_bytes);
    }
    if env_config.max_body_size_bytes != 1048576 {
        info!("Custom max body size: {} bytes", env_config.max_body_size_bytes);
    }

    // Listen for SIGHUP to reload config
    let proxy_state_reload = proxy_state.clone();
    let config_path_owned = config_path.to_string();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
            loop {
                sighup.recv().await;
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
        }
    });

    // Proxy listener only (no Admin API)
    let proxy_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let proxy_shutdown = shutdown_tx.subscribe();

    info!("Starting proxy listener on {}", proxy_addr);
    proxy::start_proxy_listener(proxy_addr, proxy_state, proxy_shutdown).await?;

    Ok(())
}
