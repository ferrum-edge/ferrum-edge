use std::net::SocketAddr;
use tracing::{info, error, warn};

use crate::config::types::GatewayConfig;
use crate::config::EnvConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{ProxyState};
use crate::admin::AdminState;
use crate::tls;

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    info!("DP mode: starting with empty config, waiting for CP");

    let dns_cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: env_config.dns_cache_ttl_seconds,
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        valid_ttl_override: env_config.dns_valid_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
    });

    // Start with empty config; CP will push the real one
    let proxy_state = ProxyState::new(GatewayConfig::default(), dns_cache, env_config.clone());

    // Add admin API to DP mode (read-only)
    let admin_http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = match crate::admin::jwt_auth::create_jwt_manager_from_env() {
        Ok(manager) => manager,
        Err(_) => {
            error!("Failed to create JWT manager for admin API");
            return Err(anyhow::anyhow!("JWT configuration required for admin API"));
        }
    };
    let admin_state = AdminState {
        db: None,  // DP has no direct DB access
        jwt_manager,
        proxy_state: Some(proxy_state.clone()),
        mode: "dp".into(),
        read_only: true,  // DP admin API is always read-only
    };
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (always enabled)
    let admin_state_clone = admin_state.clone();
    let admin_http_handle = tokio::spawn(async move {
        info!("Starting Admin HTTP listener on {}", admin_http_addr);
        if let Err(e) = crate::admin::start_admin_listener(admin_http_addr, admin_state_clone, admin_shutdown).await {
            error!("Admin HTTP listener error: {}", e);
        }
    });

    // Admin HTTPS listener (only if TLS is configured)
    let admin_https_handle = if let (Some(admin_cert_path), Some(admin_key_path)) = (&env_config.admin_tls_cert_path, &env_config.admin_tls_key_path) {
        let admin_https_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_https_port).parse()?;
        let admin_state_for_https = AdminState {
            db: None,  // DP has no direct DB access
            jwt_manager: match crate::admin::jwt_auth::create_jwt_manager_from_env() {
                Ok(manager) => manager,
                Err(_) => {
                    error!("Failed to create JWT manager for admin API");
                    return Err(anyhow::anyhow!("JWT configuration required for admin API"));
                }
            },
            proxy_state: Some(proxy_state.clone()),
            mode: "dp".into(),
            read_only: true,  // DP admin API is always read-only
        };
        let admin_https_shutdown = shutdown_tx.subscribe();
        
        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth(
            admin_cert_path, 
            admin_key_path, 
            admin_client_ca_bundle,
            env_config.admin_tls_no_verify
        ) {
            Ok(config) => {
                if admin_client_ca_bundle.is_some() {
                    info!("Admin TLS configuration loaded with client certificate verification (HTTPS with mTLS available)");
                } else if env_config.admin_tls_no_verify {
                    warn!("Admin TLS configuration loaded with certificate verification DISABLED (testing mode)");
                } else {
                    info!("Admin TLS configuration loaded without client certificate verification (HTTPS available)");
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
            if let Err(e) = crate::admin::start_admin_listener_with_tls(admin_https_addr, admin_state_for_https.clone(), admin_https_shutdown, admin_tls_config).await {
                error!("Admin HTTPS listener error: {}", e);
            }
        }))
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
        None
    };

    let mut handles = Vec::new();
    handles.push(admin_http_handle);
    if let Some(handle) = admin_https_handle {
        handles.push(handle);
    }

    // Load TLS configuration if provided
    let _tls_config = if let (Some(cert_path), Some(key_path)) = (&env_config.proxy_tls_cert_path, &env_config.proxy_tls_key_path) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(cert_path, key_path, client_ca_bundle_path, env_config.backend_tls_no_verify) {
            Ok(config) => {
                if client_ca_bundle_path.is_some() {
                    info!("TLS configuration loaded with client certificate verification (HTTPS with mTLS available)");
                } else {
                    info!("TLS configuration loaded without client certificate verification (HTTPS available)");
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

    // Start admin and proxy listeners
    let admin_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        info!("Starting Admin HTTP listener on {}", admin_http_addr);
        if let Err(e) = crate::admin::start_admin_listener(admin_http_addr, admin_state, admin_shutdown.clone()).await {
            error!("Admin HTTP listener error: {}", e);
        }
    });

    // Admin HTTPS listener (only if TLS is configured)
    if let (Some(admin_cert_path), Some(admin_key_path)) = (&env_config.admin_tls_cert_path, &env_config.admin_tls_key_path) {
        let admin_https_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_https_port).parse()?;
        let admin_state_for_https = AdminState {
            db: None,  // DP has no direct DB access
            jwt_manager: match crate::admin::jwt_auth::create_jwt_manager_from_env() {
                Ok(manager) => manager,
                Err(_) => {
                    error!("Failed to create JWT manager for admin API");
                    return Err(anyhow::anyhow!("JWT configuration required for admin API"));
                }
            },
            proxy_state: Some(proxy_state.clone()),
            mode: "dp".into(),
            read_only: true,  // DP admin API is always read-only
        };
        let admin_https_shutdown = shutdown_tx.subscribe();
        
        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth(
            admin_cert_path, 
            admin_key_path, 
            admin_client_ca_bundle,
            env_config.admin_tls_no_verify
        ) {
            Ok(config) => {
                if admin_client_ca_bundle.is_some() {
                    info!("Admin TLS configuration loaded with client certificate verification (HTTPS with mTLS available)");
                } else if env_config.admin_tls_no_verify {
                    warn!("Admin TLS configuration loaded with certificate verification DISABLED (testing mode)");
                } else {
                    info!("Admin TLS configuration loaded without client certificate verification (HTTPS available)");
                }
                Some(config)
            }
            Err(e) => {
                error!("Failed to load admin TLS configuration: {}", e);
                return Err(anyhow::anyhow!("Invalid admin TLS configuration: {}", e));
            }
        };

        tokio::spawn(async move {
            info!("Starting Admin HTTPS listener on {}", admin_https_addr);
            if let Err(e) = crate::admin::start_admin_listener_with_tls(admin_https_addr, admin_state_for_https, admin_https_shutdown.clone(), admin_tls_config).await {
                error!("Admin HTTPS listener error: {}", e);
            }
        });
    }

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (&env_config.proxy_tls_cert_path, &env_config.proxy_tls_key_path) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(cert_path, key_path, client_ca_bundle_path, env_config.backend_tls_no_verify) {
            Ok(config) => {
                if client_ca_bundle_path.is_some() {
                    info!("TLS configuration loaded with client certificate verification (HTTPS with mTLS available)");
                } else {
                    info!("TLS configuration loaded without client certificate verification (HTTPS available)");
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

    // Start proxy listeners
    let http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let http_state = proxy_state.clone();
    let http_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        info!("Starting HTTP proxy listener on {}", http_addr);
        if let Err(e) = crate::proxy::start_proxy_listener(http_addr, http_state, http_shutdown.clone()).await {
            error!("HTTP proxy listener error: {}", e);
        }
    });

    // HTTPS listener (only if TLS is configured)
    if let Some(ref tls_config) = tls_config {
        let https_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_https_port).parse()?;
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let tls_cfg = tls_config.clone();
        tokio::spawn(async move {
            info!("Starting HTTPS proxy listener on {}", https_addr);
            if let Err(e) = crate::proxy::start_proxy_listener_with_tls(https_addr, https_state, https_shutdown.clone(), Some(tls_cfg)).await {
                error!("HTTPS proxy listener error: {}", e);
            }
        });
    }

    // HTTP/3 (QUIC) listener (only if enabled and TLS is configured)
    if env_config.enable_http3 {
        if let Some(tls_config) = tls_config {
            let h3_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_https_port).parse()?;
            let h3_state = proxy_state.clone();
            let h3_shutdown = shutdown_tx.subscribe();
            let h3_config = crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
            tokio::spawn(async move {
                info!("Starting HTTP/3 (QUIC) proxy listener on {}", h3_addr);
                if let Err(e) = crate::http3::server::start_http3_listener(
                    h3_addr, h3_state, h3_shutdown, tls_config, h3_config,
                ).await {
                    error!("HTTP/3 proxy listener error: {}", e);
                }
            });
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }

    Ok(())
}
