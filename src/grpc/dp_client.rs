use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{error, info, warn};

use super::proto::SubscribeRequest;
use super::proto::config_sync_client::ConfigSyncClient;
use crate::config::types::GatewayConfig;
use crate::proxy::ProxyState;

/// Connect to the Control Plane and receive config updates.
pub async fn start_dp_client(cp_url: String, auth_token: String, proxy_state: ProxyState) {
    let node_id = uuid::Uuid::new_v4().to_string();
    info!("DP client starting, connecting to CP at {}", cp_url);

    loop {
        match connect_and_subscribe(&cp_url, &auth_token, &node_id, &proxy_state).await {
            Ok(_) => {
                warn!("CP connection stream ended, will reconnect...");
            }
            Err(e) => {
                error!("CP connection error: {}, will retry in 5s", e);
            }
        }

        // Continue serving with cached config; retry connection
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn connect_and_subscribe(
    cp_url: &str,
    auth_token: &str,
    node_id: &str,
    proxy_state: &ProxyState,
) -> Result<(), anyhow::Error> {
    let channel = Channel::from_shared(cp_url.to_string())?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await?;

    let token: MetadataValue<_> = format!("Bearer {}", auth_token).parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        ConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    info!("Connected to CP, subscribing for config updates");

    let request = tonic::Request::new(SubscribeRequest {
        node_id: node_id.to_string(),
    });

    let mut stream = client.subscribe(request).await?.into_inner();

    while let Some(update) = stream.message().await? {
        info!(
            "Received config update (type={}, version={})",
            update.update_type, update.version
        );

        match serde_json::from_str::<GatewayConfig>(&update.config_json) {
            Ok(config) => {
                proxy_state.update_config(config);
                info!("Configuration updated from CP");
            }
            Err(e) => {
                error!("Failed to parse config update: {}", e);
            }
        }
    }

    Ok(())
}
