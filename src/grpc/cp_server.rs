//! Control Plane gRPC server implementing the `ConfigSync` service.
//!
//! Provides two RPCs:
//! - `Subscribe` — server-streaming: DP connects and receives a `FULL_SNAPSHOT`
//!   (update_type=0), then incremental `DELTA` updates (update_type=1) as config changes.
//!   If a DP lags behind the broadcast channel (default capacity 128, configurable
//!   via `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`), it receives a fresh
//!   full snapshot instead of the missed deltas.
//! - `GetFullConfig` — unary: returns the current full config snapshot on demand.
//!
//! Authentication: HS256 JWT in the `authorization` gRPC metadata key.
//! Required claims: `exp`, `iat`, `sub`. The CP enforces `major.minor` version
//! compatibility — a DP running a different minor version is rejected.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Serialize;
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{ConfigUpdate, FullConfigRequest, FullConfigResponse, SubscribeRequest};
use crate::FERRUM_VERSION;
use crate::config::types::GatewayConfig;

/// Metadata about a connected Data Plane node.
#[derive(Clone, Serialize)]
pub struct DpNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

/// Registry of connected DP nodes. Shared between the gRPC server and the
/// admin API so that `GET /cluster` can report live connection state.
#[derive(Default)]
pub struct DpNodeRegistry {
    nodes: DashMap<String, DpNodeInfo>,
}

impl DpNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn insert(&self, info: DpNodeInfo) {
        self.nodes.insert(info.node_id.clone(), info);
    }

    pub fn remove(&self, node_id: &str) {
        self.nodes.remove(node_id);
    }

    /// Update `last_update_at` for all connected nodes (called after broadcast).
    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    /// Return a snapshot of all connected nodes.
    pub fn snapshot(&self) -> Vec<DpNodeInfo> {
        self.nodes.iter().map(|e| e.value().clone()).collect()
    }

    /// Number of connected DPs.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the registry has no connected DPs.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A stream wrapper that removes the DP node from the registry when the
/// gRPC stream is dropped (i.e. the DP disconnects).
struct TrackedStream<S> {
    inner: Pin<Box<S>>,
    registry: Arc<DpNodeRegistry>,
    node_id: String,
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        self.registry.remove(&self.node_id);
        info!("DP node '{}' disconnected (stream dropped)", self.node_id);
    }
}

impl<S> tokio_stream::Stream for TrackedStream<S>
where
    S: tokio_stream::Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// CP gRPC server state.
pub struct CpGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    jwt_secret: String,
    update_tx: broadcast::Sender<ConfigUpdate>,
    registry: Arc<DpNodeRegistry>,
}

impl CpGrpcServer {
    /// Create a new CP gRPC server with the default broadcast channel capacity (128).
    ///
    /// Used by tests. Production code calls `with_channel_capacity` directly
    /// to pass the operator-configured capacity from `EnvConfig`.
    #[allow(dead_code)]
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity(config, jwt_secret, 128)
    }

    pub fn with_channel_capacity(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity_and_registry(
            config,
            jwt_secret,
            channel_capacity,
            Arc::new(DpNodeRegistry::new()),
        )
    }

    pub fn with_channel_capacity_and_registry(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        let (tx, _) = broadcast::channel(channel_capacity.max(1));
        let tx_clone = tx.clone();
        (
            Self {
                config,
                jwt_secret,
                update_tx: tx,
                registry,
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

    /// Check whether the DP's reported version is compatible with this CP.
    ///
    /// Compatibility rule: major and minor versions must match. Patch-level
    /// differences are always allowed (bug-fix releases don't change the
    /// config schema or gRPC wire format).
    #[allow(clippy::result_large_err)]
    fn check_version_compatibility(dp_version: &str) -> Result<(), Status> {
        // Empty version means old DP that predates the version field — reject.
        if dp_version.is_empty() {
            return Err(Status::failed_precondition(format!(
                "DP did not report its version. CP is running Ferrum Edge v{}. \
                 Upgrade the DP to a version that supports version negotiation.",
                FERRUM_VERSION
            )));
        }

        let cp_parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        let dp_parts: Vec<&str> = dp_version.split('.').collect();

        if cp_parts.len() < 2 || dp_parts.len() < 2 {
            warn!(
                "Unable to parse version for compatibility check (CP={}, DP={}), allowing connection",
                FERRUM_VERSION, dp_version
            );
            return Ok(());
        }

        if cp_parts[0] != dp_parts[0] || cp_parts[1] != dp_parts[1] {
            return Err(Status::failed_precondition(format!(
                "Version mismatch: CP is v{} but DP is v{}. \
                 Major and minor versions must match. \
                 Upgrade the CP first, then upgrade DPs to the same major.minor version.",
                FERRUM_VERSION, dp_version
            )));
        }

        if cp_parts.get(2) != dp_parts.get(2) {
            info!(
                "DP v{} connected to CP v{} (patch difference OK)",
                dp_version, FERRUM_VERSION
            );
        }

        Ok(())
    }

    /// Broadcast a full config snapshot to all connected DPs.
    pub fn broadcast_update_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        config: &GatewayConfig,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_update(tx, config);
        registry.touch_all();
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
            ferrum_version: FERRUM_VERSION.to_string(),
        };
        let _ = tx.send(update);
    }

    /// Broadcast an incremental delta to all connected DPs (with registry update).
    pub fn broadcast_delta_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_delta(tx, result, version);
        registry.touch_all();
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
            ferrum_version: FERRUM_VERSION.to_string(),
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

        let inner = request.into_inner();
        let node_id = inner.node_id;
        let dp_version = inner.ferrum_version;
        let dp_namespace = inner.namespace;

        // Reject DPs with incompatible versions before streaming any config.
        Self::check_version_compatibility(&dp_version)?;

        info!(
            "DP node '{}' (v{}) subscribed for config updates (namespace='{}')",
            node_id, dp_version, dp_namespace
        );

        // Register the DP in the node registry (removed on stream drop).
        let now = Utc::now();
        self.registry.insert(DpNodeInfo {
            node_id: node_id.clone(),
            version: dp_version.clone(),
            namespace: dp_namespace.clone(),
            connected_at: now,
            last_update_at: now,
        });

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
            ferrum_version: FERRUM_VERSION.to_string(),
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
                        ferrum_version: FERRUM_VERSION.to_string(),
                    })),
                    Err(e) => {
                        error!("Failed to serialize recovery snapshot: {}", e);
                        None
                    }
                }
            }
        });

        // Prepend initial config, then wrap in TrackedStream so the DP is
        // automatically de-registered when the gRPC stream is dropped.
        let initial_stream = tokio_stream::once(Ok(initial));
        let combined = initial_stream.chain(stream);
        let tracked = TrackedStream {
            inner: Box::pin(combined),
            registry: self.registry.clone(),
            node_id,
        };

        Ok(Response::new(Box::pin(tracked)))
    }

    async fn get_full_config(
        &self,
        request: Request<FullConfigRequest>,
    ) -> Result<Response<FullConfigResponse>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let req = request.get_ref();
        let dp_version = &req.ferrum_version;
        Self::check_version_compatibility(dp_version)?;

        info!(
            "DP '{}' (v{}) requested full config (namespace='{}')",
            req.node_id, dp_version, req.namespace
        );

        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).map_err(|e| {
            error!("Failed to serialize config in get_full_config: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;

        Ok(Response::new(FullConfigResponse {
            config_json,
            version: config.loaded_at.to_rfc3339(),
            ferrum_version: FERRUM_VERSION.to_string(),
        }))
    }
}
