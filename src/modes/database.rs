use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use chrono::{DateTime, Utc};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::db_loader::DatabaseStore;
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db = DatabaseStore::connect_with_tls_config(
        env_config.db_type.as_deref().unwrap_or("sqlite"),
        &effective_url,
        env_config.db_tls_enabled,
        env_config.db_tls_ca_cert_path.as_deref(),
        env_config.db_tls_client_cert_path.as_deref(),
        env_config.db_tls_client_key_path.as_deref(),
        env_config.db_tls_insecure,
    )
    .await?;

    // Load initial config
    let config = db.load_full_config().await?;
    info!(
        "Database mode: loaded {} proxies, {} consumers",
        config.proxies.len(),
        config.consumers.len()
    );

    // DNS cache
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
    let db = Arc::new(db);

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;

    // Load TLS configuration if provided
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

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "database".into(),
        read_only: env_config.admin_read_only,
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
            db: Some(db.clone()),
            jwt_manager: create_jwt_manager_from_env()
                .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?,
            cached_config: Some(proxy_state.config.clone()),
            proxy_state: Some(proxy_state.clone()),
            mode: "database".into(),
            read_only: env_config.admin_read_only,
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
    let mut poll_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Seed incremental state from the initial config load
        let initial_config = proxy_state_poll.current_config();
        let (
            mut known_proxy_ids,
            mut known_consumer_ids,
            mut known_plugin_config_ids,
            mut known_upstream_ids,
        ) = DatabaseStore::extract_known_ids(&initial_config);
        let mut last_poll_at: Option<DateTime<Utc>> = Some(initial_config.loaded_at);

        loop {
            tokio::select! {
                _ = interval.tick() => {
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
                                let poll_ts = result.poll_timestamp;
                                // Update known IDs before applying (add new, remove deleted)
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

                                if proxy_state_poll.apply_incremental(result) {
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
                                match db_poll.load_full_config().await {
                                    Ok(new_config) => {
                                        let (p, c, pc, u) = DatabaseStore::extract_known_ids(&new_config);
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
                                        warn!(
                                            "Full config reload also failed (using cached): {}",
                                            e2
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        // First poll — full load to seed state
                        match db_poll.load_full_config().await {
                            Ok(new_config) => {
                                let (p, c, pc, u) = DatabaseStore::extract_known_ids(&new_config);
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

    // Wait for all listeners to complete
    for handle in handles {
        handle.await?;
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
