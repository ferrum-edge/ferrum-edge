use std::collections::HashMap;
use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE, jittered_backoff,
    next_backoff_secs, refresh_dp_grpc_tls_config_if_changed, tonic_tls_config, wait_for_shutdown,
    wait_optional_tls_reload,
};
use crate::grpc::dp_client::{
    DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret, check_cp_version_compatibility,
    generate_dp_jwt_with_issuer_and_namespace,
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
    /// Shared CP-failover primary-retry interval
    /// (`FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`). When > 0 and connected to a
    /// fallback CP after a first slice is installed, the client proactively
    /// reconnects to the primary CP — matching the xDS client and the documented
    /// HA failback model. `0` disables proactive failback (the prior behaviour).
    pub primary_retry_secs: u64,
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
        let is_fallback = current_cp_index != 0 && cp_urls.len() > 1;
        let should_retry_primary = is_fallback && config.primary_retry_secs > 0;
        // On a fallback CP, arm failback after a first slice is available. The
        // fallback stream may itself deliver that first slice and then stay open
        // indefinitely, so the timer must wait inside this select instead of
        // being decided only before `connect_mesh_subscribe` starts.
        let result = if should_retry_primary {
            tokio::select! {
                result = connect_mesh_subscribe(
                    cp_url,
                    &jwt_secret,
                    &config,
                    &consumer,
                    tls_config.as_ref(),
                ) => result,
                _ = wait_for_first_slice_then_primary_retry(
                    state.clone(),
                    Duration::from_secs(config.primary_retry_secs),
                ) => {
                    info!(
                        primary_retry_secs = config.primary_retry_secs,
                        cp_url = %cp_url,
                        "Native primary retry interval elapsed; reconnecting to primary CP"
                    );
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Native mesh client shutting down");
                    return;
                }
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    info!("Mesh gRPC TLS source changed; reconnecting native MeshSubscribe stream");
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            tokio::select! {
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
    let auth_token = generate_dp_jwt_with_issuer_and_namespace(
        jwt_secret.as_str(),
        &config.node_id,
        jwt_secret.issuer(),
        Some(&config.namespace),
    )?;
    let token: MetadataValue<_> = format!("Bearer {auth_token}").parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        })
        .max_decoding_message_size(MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_url = %cp_url,
        "Connected to CP, subscribing for native mesh config"
    );

    let request = tonic::Request::new(config.subscribe_request(crate::FERRUM_VERSION));
    let mut stream = client.mesh_subscribe(request).await?.into_inner();

    while let Some(update) = stream.message().await? {
        validate_mesh_update_ferrum_version(&update.ferrum_version)?;

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

fn validate_mesh_update_ferrum_version(ferrum_version: &str) -> Result<(), anyhow::Error> {
    if ferrum_version.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "native MeshSubscribe update is missing ferrum_version; refusing unversioned CP response"
        ));
    }
    check_cp_version_compatibility(ferrum_version).map_err(anyhow::Error::msg)
}

async fn wait_for_first_slice_then_primary_retry(state: MeshRuntimeState, interval: Duration) {
    state.wait_for_first_slice().await;
    tokio::time::sleep(interval).await;
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

    #[test]
    fn native_update_rejects_empty_ferrum_version() {
        let err = validate_mesh_update_ferrum_version("")
            .expect_err("empty ferrum_version must be rejected");

        assert!(
            err.to_string().contains("missing ferrum_version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn native_update_accepts_current_ferrum_version() {
        validate_mesh_update_ferrum_version(crate::FERRUM_VERSION)
            .expect("current ferrum_version should be compatible");
    }

    #[tokio::test]
    async fn primary_retry_waits_until_first_slice_on_fallback_stream() {
        let state = MeshRuntimeState::new();
        let retry = tokio::spawn(wait_for_first_slice_then_primary_retry(
            state.clone(),
            Duration::from_millis(1),
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !retry.is_finished(),
            "timer must not run before the first slice arrives"
        );

        state.install_slice(MeshSlice {
            version: "first".to_string(),
            ..MeshSlice::default()
        });

        tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("primary retry wait should complete after first slice")
            .expect("primary retry wait task should join");
    }

    #[test]
    fn native_config_carries_primary_retry_secs() {
        let config = NativeMeshClientConfig {
            node_id: "n".to_string(),
            namespace: "ferrum".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: HashMap::new(),
            primary_retry_secs: 300,
        };
        assert_eq!(config.primary_retry_secs, 300);
    }

    #[test]
    fn mesh_client_self_minted_token_carries_namespace_claim() {
        let token = generate_dp_jwt_with_issuer_and_namespace(
            "test-secret",
            "node-a",
            "ferrum-edge-cp-dp",
            Some("tenant-a"),
        )
        .expect("token should mint");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.set_issuer(&["ferrum-edge-cp-dp"]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            &validation,
        )
        .expect("token should decode");

        assert_eq!(
            decoded.claims.get("ns").and_then(|value| value.as_str()),
            Some("tenant-a")
        );
    }
}
