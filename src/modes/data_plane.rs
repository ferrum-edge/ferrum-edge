use std::net::SocketAddr;
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
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
        max_cache_size: env_config.dns_cache_max_size,
    });

    // Start DNS background refresh
    dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Start with empty config; CP will push the real one via gRPC
    let proxy_state = ProxyState::new(GatewayConfig::default(), dns_cache, env_config.clone())?;

    // Spawn the DP gRPC client to connect to CP and receive config updates
    let cp_url = env_config
        .dp_cp_grpc_url
        .clone()
        .ok_or_else(|| anyhow::anyhow!("FERRUM_DP_CP_GRPC_URL is required in dp mode"))?;
    let auth_token = env_config
        .dp_grpc_auth_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("FERRUM_DP_GRPC_AUTH_TOKEN is required in dp mode"))?;
    let dp_proxy_state = proxy_state.clone();
    let dp_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        crate::grpc::dp_client::start_dp_client_with_shutdown(
            cp_url,
            auth_token,
            dp_proxy_state,
            Some(dp_shutdown),
        )
        .await;
    });

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.proxy_tls_cert_path,
        &env_config.proxy_tls_key_path,
    ) {
        info!("Loading TLS configuration...");
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

    // Start separate listeners for HTTP and HTTPS
    let mut handles = Vec::new();

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

    // Start Admin API listeners (read-only in DP mode)
    let admin_http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;
    let admin_state = AdminState {
        db: None, // DP has no direct DB access
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "dp".into(),
        read_only: true, // DP admin API is always read-only
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
    handles.push(admin_http_handle);

    // Admin HTTPS listener (only if TLS is configured)
    if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            format!("0.0.0.0:{}", env_config.admin_https_port).parse()?;
        let admin_state_for_https = AdminState {
            db: None,
            jwt_manager: create_jwt_manager_from_env()
                .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?,
            cached_config: Some(proxy_state.config.clone()),
            proxy_state: Some(proxy_state.clone()),
            mode: "dp".into(),
            read_only: true,
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

    // Wait for all listeners to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
