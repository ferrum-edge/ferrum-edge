use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::admin::{self, AdminState};
use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::config::db_loader::DatabaseStore;
use crate::config::EnvConfig;
use crate::dns::DnsCache;
use crate::proxy::{self, ProxyState};

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    let db = DatabaseStore::connect(
        env_config.db_type.as_deref().unwrap_or("sqlite"),
        env_config.db_url.as_deref().unwrap_or("sqlite://ferrum.db"),
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

    let proxy_state = ProxyState::new(config, dns_cache);
    let db = Arc::new(db);

    // Proxy listener
    let proxy_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let proxy_shutdown = shutdown_tx.subscribe();
    let proxy_state_clone = proxy_state.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy::start_proxy_listener(proxy_addr, proxy_state_clone, proxy_shutdown).await {
            error!("Proxy listener error: {}", e);
        }
    });

    // Admin listener
    let admin_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        proxy_state: Some(proxy_state.clone()),
        mode: "database".into(),
    };
    let admin_shutdown = shutdown_tx.subscribe();
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = admin::start_admin_listener(admin_addr, admin_state, admin_shutdown).await {
            error!("Admin listener error: {}", e);
        }
    });

    // Database polling loop
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let proxy_state_poll = proxy_state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(poll_interval).await;
            match db_poll.load_full_config().await {
                Ok(new_config) => {
                    proxy_state_poll.update_config(new_config);
                    info!("Configuration reloaded from database");
                }
                Err(e) => {
                    warn!(
                        "Failed to reload config from database (using cached): {}",
                        e
                    );
                }
            }
        }
    });

    tokio::select! {
        _ = proxy_handle => {}
        _ = admin_handle => {}
    }

    Ok(())
}
