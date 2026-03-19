use arc_swap::ArcSwap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::info;

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
    fn verify_jwt(&self, req: &Request<()>) -> Result<(), Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        decode::<Value>(token, &key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        Ok(())
    }

    pub fn into_service(self) -> ConfigSyncServer<Self> {
        ConfigSyncServer::new(self)
    }

    /// Broadcast a config update to all connected DPs.
    pub fn broadcast_update(tx: &broadcast::Sender<ConfigUpdate>, config: &GatewayConfig) {
        let config_json = serde_json::to_string(config).unwrap_or_default();
        let update = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
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
        // Verify JWT from metadata
        let mut meta_req = Request::new(());
        // Copy authorization metadata from original request
        if let Some(auth_header) = request.metadata().get("authorization") {
            meta_req
                .metadata_mut()
                .insert("authorization", auth_header.clone());
        }
        self.verify_jwt(&meta_req)?;

        let node_id = request.into_inner().node_id;
        info!("DP node '{}' subscribed for config updates", node_id);

        // Send initial full config
        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).unwrap_or_default();
        let initial = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        let rx = self.update_tx.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|result| match result {
            Ok(update) => Some(Ok(update)),
            Err(_) => None,
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
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        decode::<Value>(token, &key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).unwrap_or_default();

        Ok(Response::new(FullConfigResponse {
            config_json,
            version: config.loaded_at.to_rfc3339(),
        }))
    }
}
