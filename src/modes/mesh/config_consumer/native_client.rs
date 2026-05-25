use std::collections::HashMap;
use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs,
    refresh_dp_grpc_tls_config_if_changed, tonic_tls_config, wait_for_shutdown,
    wait_optional_tls_reload,
};
use crate::grpc::dp_client::{
    DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret, check_cp_version_compatibility,
    generate_dp_jwt_with_issuer,
};
use crate::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
use crate::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::MeshSlice;

/// Phase B shell for Ferrum-native MeshSubscribe consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMeshClientConfig {
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub waypoint_name: Option<String>,
    pub labels: HashMap<String, String>,
}

impl NativeMeshClientConfig {
    pub fn subscribe_request(&self, ferrum_version: &str) -> MeshSubscribeRequest {
        MeshSubscribeRequest {
            node_id: self.node_id.clone(),
            ferrum_version: ferrum_version.to_string(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone().unwrap_or_default(),
            labels: self.labels.clone(),
            waypoint_name: self.waypoint_name.clone().unwrap_or_default(),
        }
    }
}

/// Maintain a live native `MeshSubscribe` stream with simple multi-CP failover.
pub async fn start_native_mesh_client_with_shutdown(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    config: NativeMeshClientConfig,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
) {
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start native mesh client");
        return;
    }

    let mut current_cp_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_urls = cp_urls.len(),
        "Native mesh client starting"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("Native mesh client shutting down");
            return;
        }
        refresh_dp_grpc_tls_config_if_changed(
            &mut tls_config,
            tls_reload.as_ref(),
            &cp_urls,
            &mut last_tls_revision,
        );

        let cp_url = &cp_urls[current_cp_index];
        let consumer = NativeMeshConfigConsumer::new(state.clone());
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let result = tokio::select! {
            result = connect_mesh_subscribe(
                cp_url,
                &jwt_secret,
                &config,
                &consumer,
                tls_config.as_ref(),
            ) => result,
            _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                info!("Native mesh client shutting down");
                return;
            }
            _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                info!("Mesh gRPC TLS source changed; reconnecting native MeshSubscribe stream");
                backoff_secs = BACKOFF_INITIAL_SECS;
                continue;
            }
        };

        let increase_backoff = match result {
            Ok(()) => {
                warn!(
                    cp_url = %cp_url,
                    "Native MeshSubscribe stream ended; will reconnect"
                );
                current_cp_index = 0;
                backoff_secs = BACKOFF_INITIAL_SECS;
                false
            }
            Err(e) => {
                error!(
                    cp_url = %cp_url,
                    error = %e,
                    "Native MeshSubscribe connection failed"
                );
                current_cp_index = (current_cp_index + 1) % cp_urls.len();
                true
            }
        };

        let sleep_duration = jittered_backoff(backoff_secs);
        let mut sleep_shutdown_rx = shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut sleep_shutdown_rx) => {
                info!("Native mesh client shutting down");
                return;
            }
            _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                backoff_secs = BACKOFF_INITIAL_SECS;
                continue;
            }
        }
        backoff_secs = next_backoff_secs(backoff_secs, increase_backoff);
    }
}

async fn connect_mesh_subscribe(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    config: &NativeMeshClientConfig,
    consumer: &NativeMeshConfigConsumer,
    tls_config: Option<&DpGrpcTlsConfig>,
) -> Result<(), anyhow::Error> {
    let mut endpoint =
        Channel::from_shared(cp_url.to_string())?.connect_timeout(Duration::from_secs(10));

    if let Some(tls) = tls_config {
        let mut client_tls = tonic_tls_config(tls);
        if let Ok(uri) = cp_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }
        endpoint = endpoint.tls_config(client_tls)?;
    }

    let channel = endpoint.connect().await?;
    let auth_token =
        generate_dp_jwt_with_issuer(jwt_secret.as_str(), &config.node_id, jwt_secret.issuer())?;
    let token: MetadataValue<_> = format!("Bearer {auth_token}").parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_url = %cp_url,
        "Connected to CP, subscribing for native mesh config"
    );

    let request = tonic::Request::new(config.subscribe_request(crate::FERRUM_VERSION));
    let mut stream = client.mesh_subscribe(request).await?.into_inner();

    while let Some(update) = stream.message().await? {
        if !update.ferrum_version.is_empty()
            && let Err(msg) = check_cp_version_compatibility(&update.ferrum_version)
        {
            return Err(anyhow::anyhow!(msg));
        }

        if update.heartbeat {
            tracing::debug!(
                version = %update.version,
                "Received native MeshSubscribe heartbeat"
            );
            continue;
        }

        let version = update.version.clone();
        match consumer.apply_update(update) {
            Ok(slice) => {
                info!(
                    node_id = %slice.node_id,
                    namespace = %slice.namespace,
                    version = %slice.version,
                    "Applied native MeshSubscribe update"
                );
            }
            Err(e) => {
                warn!(
                    version = %version,
                    error = %e,
                    "Ignoring invalid native MeshSubscribe update"
                );
            }
        }
    }

    Ok(())
}

/// Applies native `MeshSubscribe` updates into the shared mesh runtime state.
#[derive(Clone)]
pub struct NativeMeshConfigConsumer {
    state: MeshRuntimeState,
}

impl NativeMeshConfigConsumer {
    pub fn new(state: MeshRuntimeState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    pub fn apply_update(&self, update: MeshConfigUpdate) -> Result<MeshSlice, String> {
        let slice = serde_json::from_str::<MeshSlice>(&update.mesh_slice_json)
            .map_err(|e| format!("invalid MeshSubscribe slice JSON: {e}"))?;
        self.state.install_slice(slice.clone());
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_update_installs_mesh_slice() {
        let state = MeshRuntimeState::new();
        let consumer = NativeMeshConfigConsumer::new(state.clone());
        let update = MeshConfigUpdate {
            version: "v1".to_string(),
            timestamp: 1,
            mesh_slice_json: serde_json::to_string(&MeshSlice {
                node_id: "node-a".to_string(),
                version: "v1".to_string(),
                ..MeshSlice::default()
            })
            .expect("mesh slice serializes"),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            heartbeat: false,
        };

        let slice = consumer.apply_update(update).expect("update applies");

        assert_eq!(slice.node_id, "node-a");
        assert!(state.has_first_slice());
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v1")
        );
    }
}
