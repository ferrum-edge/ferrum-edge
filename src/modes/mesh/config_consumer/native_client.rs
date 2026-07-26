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
use super::update_validation::{
    MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejection, validate_mesh_config_update,
    validate_update_ferrum_version,
};
use crate::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE;
use crate::grpc::dp_client::{
    DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret, generate_dp_jwt_full,
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
    pub ambient_udp_source_scoping: bool,
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
            ambient_udp_source_scoping: self.ambient_udp_source_scoping,
            // Ordinary LOCAL mesh subscription: this data plane talks to its
            // own control plane and presents the distinct, fixed local-mesh
            // JWT audience. The CP rejects both missing audiences (legacy
            // clients) and remote-discovery audiences on this class.
            remote_discovery: false,
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
                    &state,
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
                    &state,
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
    state: &MeshRuntimeState,
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
    let auth_token = generate_dp_jwt_full(
        jwt_secret.as_str(),
        &config.node_id,
        jwt_secret.issuer(),
        Some(&config.namespace),
        Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
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

    let subscribe_request = config.subscribe_request(crate::FERRUM_VERSION);
    // Bind the consumer to the EXACT request this stream puts on the wire, so a
    // response can never be validated against a different subscription than the
    // one the CP was asked to serve.
    let consumer = NativeMeshConfigConsumer::new(
        state.clone(),
        MeshUpdateExpectation::from_subscribe_request(&subscribe_request),
    );
    let request = tonic::Request::new(subscribe_request);
    let mut stream = client.mesh_subscribe(request).await?.into_inner();

    while let Some(update) = stream.message().await? {
        // Heartbeats are handled explicitly: they carry no slice, so they are
        // bound only to the CP compatibility contract and never reach the
        // install path.
        let applied = if update.heartbeat {
            validate_update_ferrum_version(&update.ferrum_version, MeshUpdateConsumer::Native)
                .map(|()| None)
        } else {
            consumer.apply_update(&update).map(Some)
        };

        match applied {
            Ok(Some(slice)) => {
                info!(
                    node_id = %slice.node_id,
                    namespace = %slice.namespace,
                    version = %slice.version,
                    "Applied native MeshSubscribe update"
                );
            }
            Ok(None) => {
                tracing::debug!("Received native MeshSubscribe heartbeat");
            }
            Err(rejection) => {
                // The rejection site already emitted the reason-labelled metric
                // and the sanitized diagnostic; last-good state is untouched
                // either way. A response that is not bound to this subscription
                // means the whole stream is wrong, so drop it and let multi-CP
                // failover pick another control plane (the reconnect path logs
                // the failure with this CP's URL).
                if rejection.terminates_stream() {
                    return Err(anyhow::Error::new(rejection));
                }
                warn!(
                    cp_url = %cp_url,
                    reason = rejection.reason().as_metric_label(),
                    "Ignoring invalid native MeshSubscribe update; keeping last-good slice"
                );
            }
        }
    }

    Ok(())
}

async fn wait_for_first_slice_then_primary_retry(state: MeshRuntimeState, interval: Duration) {
    state.wait_for_first_slice().await;
    tokio::time::sleep(interval).await;
}

/// Applies native `MeshSubscribe` updates into the shared mesh runtime state.
///
/// The consumer carries the subscription context the CP was asked to serve, so
/// every update is bound to that exact request before it can reach
/// `install_slice`.
#[derive(Clone)]
pub struct NativeMeshConfigConsumer {
    state: MeshRuntimeState,
    expected: MeshUpdateExpectation,
}

impl NativeMeshConfigConsumer {
    pub fn new(state: MeshRuntimeState, expected: MeshUpdateExpectation) -> Self {
        Self { state, expected }
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    /// Validate a non-heartbeat update against the subscription and install it.
    ///
    /// Validation is fail-closed and runs to completion **before** any mutation:
    /// a rejected response leaves the previously installed slice serving
    /// untouched.
    pub fn apply_update(
        &self,
        update: &MeshConfigUpdate,
    ) -> Result<MeshSlice, MeshUpdateRejection> {
        let consumer = MeshUpdateConsumer::Native;
        let slice = validate_mesh_config_update(update, &self.expected, consumer)?;
        self.state.install_slice(slice.clone());
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config_consumer::update_validation::MeshUpdateRejectReason;

    fn test_client_config() -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: HashMap::new(),
            ambient_udp_source_scoping: false,
            primary_retry_secs: 0,
        }
    }

    /// A consumer bound to exactly what `test_client_config` subscribes with.
    fn test_consumer(state: MeshRuntimeState) -> NativeMeshConfigConsumer {
        let request = test_client_config().subscribe_request(crate::FERRUM_VERSION);
        let expected = MeshUpdateExpectation::from_subscribe_request(&request);
        NativeMeshConfigConsumer::new(state, expected)
    }

    fn update_for(slice: &MeshSlice) -> MeshConfigUpdate {
        MeshConfigUpdate {
            version: slice.version.clone(),
            timestamp: 1,
            mesh_slice_json: serde_json::to_string(slice).expect("mesh slice serializes"),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            heartbeat: false,
        }
    }

    #[test]
    fn apply_update_installs_mesh_slice() {
        let state = MeshRuntimeState::new();
        let consumer = test_consumer(state.clone());
        let update = update_for(&MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        let slice = consumer.apply_update(&update).expect("update applies");

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

    /// The subscription binding is enforced by the consumer itself: a slice
    /// built for another node never reaches `install_slice`, so a DP with no
    /// slice yet stays sliceless rather than adopting foreign state.
    #[test]
    fn apply_update_rejects_wrong_node_before_install() {
        let state = MeshRuntimeState::new();
        let consumer = test_consumer(state.clone());
        let update = update_for(&MeshSlice {
            node_id: "node-b".to_string(),
            namespace: "ferrum".to_string(),
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        let rejection = consumer
            .apply_update(&update)
            .expect_err("a slice for another node must be rejected");

        assert_eq!(rejection.reason(), MeshUpdateRejectReason::NodeIdMismatch);
        assert!(rejection.terminates_stream());
        assert!(!state.has_first_slice());
        assert!(state.snapshot().as_ref().is_none());
    }

    #[test]
    fn native_update_rejects_empty_ferrum_version() {
        let rejection = validate_update_ferrum_version("", MeshUpdateConsumer::Native)
            .expect_err("empty ferrum_version must be rejected");

        assert_eq!(
            rejection.reason(),
            MeshUpdateRejectReason::MissingFerrumVersion
        );
    }

    #[test]
    fn native_update_accepts_current_ferrum_version() {
        validate_update_ferrum_version(crate::FERRUM_VERSION, MeshUpdateConsumer::Native)
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
            ambient_udp_source_scoping: false,
            primary_retry_secs: 300,
        };
        assert_eq!(config.primary_retry_secs, 300);
    }

    #[test]
    fn mesh_client_self_minted_token_carries_namespace_and_local_audience() {
        let token = generate_dp_jwt_full(
            "test-secret",
            "node-a",
            "ferrum-edge-cp-dp",
            Some("tenant-a"),
            Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
        )
        .expect("token should mint");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.set_issuer(&["ferrum-edge-cp-dp"]);
        validation.set_audience(&[MESH_LOCAL_SUBSCRIBE_AUDIENCE]);
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
        assert_eq!(
            decoded.claims.get("aud").and_then(|value| value.as_str()),
            Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE)
        );
    }
}
