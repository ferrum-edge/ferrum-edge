use arc_swap::ArcSwap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{ConfigUpdate, FullConfigRequest, FullConfigResponse, SubscribeRequest};
use crate::config::types::GatewayConfig;

/// CP gRPC server state.
pub struct CpGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    jwt_secret: String,
    update_tx: broadcast::Sender<ConfigUpdate>,
}

impl CpGrpcServer {
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        let (tx, _) = broadcast::channel(128);
        let tx_clone = tx.clone();
        (
            Self {
                config,
                jwt_secret,
                update_tx: tx,
            },
            tx_clone,
        )
    }

    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let token = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        // Require standard claims to prevent minimal/forged tokens from authenticating.
        validation.required_spec_claims = {
            let mut claims = std::collections::HashSet::new();
            claims.insert("exp".to_string());
            claims.insert("iat".to_string());
            claims.insert("sub".to_string());
            claims
        };

        decode::<Value>(token, &key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        Ok(())
    }

    pub fn into_service(self) -> ConfigSyncServer<Self> {
        ConfigSyncServer::new(self)
    }

    /// Broadcast a full config snapshot to all connected DPs.
    pub fn broadcast_update(tx: &broadcast::Sender<ConfigUpdate>, config: &GatewayConfig) {
        let config_json = match serde_json::to_string(config) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize config for broadcast: {}", e);
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
        };
        let _ = tx.send(update);
    }

    /// Broadcast an incremental delta to all connected DPs.
    ///
    /// Sends only the resources that changed (added/modified/removed) instead
    /// of the full config. DPs apply the delta via `ProxyState::apply_incremental`.
    pub fn broadcast_delta(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
    ) {
        let config_json = match serde_json::to_string(result) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize delta for broadcast: {}", e);
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 1, // DELTA
            config_json,
            version: version.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };
        let _ = tx.send(update);
    }
}

#[tonic::async_trait]
impl ConfigSync for CpGrpcServer {
    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ConfigUpdate, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let node_id = request.into_inner().node_id;
        info!("DP node '{}' subscribed for config updates", node_id);

        // Send initial full config
        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).map_err(|e| {
            error!("Failed to serialize config in subscribe: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let initial = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        let rx = self.update_tx.subscribe();
        let config_for_recovery = self.config.clone();
        let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
            Ok(update) => Some(Ok(update)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(
                    "DP config stream lagged behind by {} updates — sending full snapshot to recover",
                    n
                );
                // Send a full config snapshot so the DP recovers from missed deltas.
                let current = config_for_recovery.load_full();
                match serde_json::to_string(current.as_ref()) {
                    Ok(config_json) => Some(Ok(ConfigUpdate {
                        update_type: 0, // FULL_SNAPSHOT
                        config_json,
                        version: current.loaded_at.to_rfc3339(),
                        timestamp: chrono::Utc::now().timestamp(),
                    })),
                    Err(e) => {
                        error!("Failed to serialize recovery snapshot: {}", e);
                        None
                    }
                }
            }
        });

        // Prepend initial config
        let initial_stream = tokio_stream::once(Ok(initial));
        let combined = initial_stream.chain(stream);

        Ok(Response::new(Box::pin(combined)))
    }

    async fn get_full_config(
        &self,
        request: Request<FullConfigRequest>,
    ) -> Result<Response<FullConfigResponse>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).map_err(|e| {
            error!("Failed to serialize config in get_full_config: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;

        Ok(Response::new(FullConfigResponse {
            config_json,
            version: config.loaded_at.to_rfc3339(),
        }))
    }
}
