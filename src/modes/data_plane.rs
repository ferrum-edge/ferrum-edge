use std::net::SocketAddr;
use tracing::info;

use crate::config::types::GatewayConfig;
use crate::config::EnvConfig;
use crate::dns::DnsCache;
use crate::grpc::dp_client;
use crate::proxy::{self, ProxyState};

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    info!("DP mode: starting with empty config, waiting for CP");

    let dns_cache = DnsCache::new(
        env_config.dns_cache_ttl_seconds,
        env_config.dns_overrides.clone(),
    );

    // Start with empty config; CP will push the real one
    let proxy_state = ProxyState::new(GatewayConfig::default(), dns_cache, env_config.clone());

    // Start DP client to connect to CP
    let cp_url = env_config.dp_cp_grpc_url.clone().unwrap_or_default();
    let auth_token = env_config.dp_grpc_auth_token.clone().unwrap_or_default();
    let proxy_state_grpc = proxy_state.clone();
    tokio::spawn(async move {
        dp_client::start_dp_client(cp_url, auth_token, proxy_state_grpc).await;
    });

    // Proxy listener
    let proxy_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let proxy_shutdown = shutdown_tx.subscribe();

    info!("Starting proxy listener on {}", proxy_addr);
    proxy::start_proxy_listener(proxy_addr, proxy_state, proxy_shutdown).await?;

    Ok(())
}
