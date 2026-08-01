//! Mesh gRPC server implementing the `MeshConfigSync` service.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use futures_util::stream;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{Instant, interval_at};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::auth::{
    AllowedNamespaces, AudienceRejectReason, GrpcAudiencePolicy, MESH_LOCAL_SUBSCRIBE_AUDIENCE,
    remote_discovery_audience, verify_grpc_jwt_metadata_with_audience,
};
use super::cp_server::{CpGrpcServer, CpScope, DEFAULT_CP_DP_JWT_ISSUER};
use super::cp_trust::{CpDpVerifier, CpGrpcConnectInfo};
use super::mesh_registry::{MeshNodeInfo, MeshNodeRegistry};
use super::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use super::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use crate::FERRUM_VERSION;
use crate::config::incremental_apply::apply_incremental_to_config_snapshot;
use crate::config::types::{GatewayConfig, default_namespace};
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

pub const MESH_SUBSCRIBE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub enum MeshConfigBroadcast {
    Full(Arc<GatewayConfig>),
    Delta {
        result: Box<crate::config::db_loader::IncrementalResult>,
        version: String,
    },
}

struct TrackedMeshStream<S> {
    inner: Pin<Box<S>>,
    registry: Arc<MeshNodeRegistry>,
    node_id: String,
    connected_at: DateTime<Utc>,
}

impl<S> Drop for TrackedMeshStream<S> {
    fn drop(&mut self) {
        self.registry
            .remove_if_stale(&self.node_id, self.connected_at);
        info!("Mesh node '{}' disconnected (stream dropped)", self.node_id);
    }
}

impl<S> tokio_stream::Stream for TrackedMeshStream<S>
where
    S: tokio_stream::Stream,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.registry
                    .touch_heartbeat(&self.node_id, self.connected_at);
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

pub struct MeshGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    /// Shared with the ConfigSync and xDS servers so native MeshSubscribe
    /// enforces the same namespace-bound verification credentials
    /// (advisory GHSA-3f2j-wwqw-grmg).
    verifier: Arc<CpDpVerifier>,
    expected_issuer: String,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    registry: Arc<MeshNodeRegistry>,
    namespace: String,
    scope: CpScope,
    require_ns_claim: bool,
    /// Mirror of `EnvConfig.mesh_sidecar_enforced`. Threaded through every
    /// per-subscriber slice request so DP-facing slices honor the operator's
    /// rollout decision. Default `false` preserves existing CP behavior.
    sidecar_enforced: bool,
    /// Mirror of `EnvConfig.mesh_sidecar_enforced_dry_run`.
    sidecar_enforced_dry_run: bool,
    /// Mirror of `EnvConfig.mesh_sidecar_identity_narrowing`. Only takes
    /// effect when `sidecar_enforced` is also true.
    sidecar_identity_narrowing: bool,
    /// Cluster DNS suffix used when synthesizing MeshService FQDN aliases for
    /// Sidecar egress matching.
    cluster_domain: String,
    /// Mirror of `FERRUM_MESH_CLUSTER_AUDIENCE`: the stable, operator-visible
    /// identifier THIS cluster is known by to its multi-cluster peers (the
    /// value peers put in `RemoteCluster.name`). Cross-cluster remote-discovery
    /// subscriptions must present a JWT whose single `aud` is
    /// `remote_discovery_audience(this value)`. `None` means the operator has
    /// not enabled cross-cluster discovery serving here, and every
    /// `remote_discovery` subscription is refused (fail closed) — it is never
    /// a permissive posture. Issue #2475.
    ///
    /// Precomputed at build time into the full expected `aud` string so the
    /// per-subscription check is a borrow + compare, never a `format!`.
    expected_remote_discovery_audience: Option<String>,
}

pub struct MeshGrpcServerBuilder {
    config: Arc<ArcSwap<GatewayConfig>>,
    verifier: Arc<CpDpVerifier>,
    channel_capacity: usize,
    registry: Arc<MeshNodeRegistry>,
    expected_issuer: String,
    namespace: String,
    scope: CpScope,
    require_ns_claim: bool,
    sidecar_enforced: bool,
    sidecar_enforced_dry_run: bool,
    sidecar_identity_narrowing: bool,
    cluster_domain: String,
    cluster_audience: Option<String>,
}

impl MeshGrpcServerBuilder {
    fn new(config: Arc<ArcSwap<GatewayConfig>>, jwt_secret: String) -> Self {
        Self {
            config,
            verifier: Arc::new(CpDpVerifier::SharedSecret(jwt_secret)),
            channel_capacity: 128,
            registry: Arc::new(MeshNodeRegistry::new()),
            expected_issuer: DEFAULT_CP_DP_JWT_ISSUER.to_string(),
            namespace: default_namespace(),
            scope: CpScope::Single(default_namespace()),
            require_ns_claim: false,
            sidecar_enforced: false,
            sidecar_enforced_dry_run: false,
            sidecar_identity_narrowing: false,
            cluster_domain: crate::modes::mesh::dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            cluster_audience: None,
        }
    }

    pub fn channel_capacity(mut self, channel_capacity: usize) -> Self {
        self.channel_capacity = channel_capacity;
        self
    }

    pub fn registry(mut self, registry: Arc<MeshNodeRegistry>) -> Self {
        self.registry = registry;
        self
    }

    pub fn expected_issuer(mut self, expected_issuer: String) -> Self {
        self.expected_issuer = expected_issuer;
        self
    }

    /// Replace the seeded shared-secret verifier with the CP's configured
    /// namespace-bound trust bundle.
    pub fn verifier(mut self, verifier: Arc<CpDpVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn namespace(mut self, namespace: String) -> Self {
        self.scope = CpScope::Single(namespace.clone());
        self.namespace = namespace;
        self
    }

    pub fn scope(mut self, scope: CpScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn require_ns_claim(mut self, require: bool) -> Self {
        self.require_ns_claim = require;
        self
    }

    pub fn sidecar_enforced(mut self, sidecar_enforced: bool) -> Self {
        self.sidecar_enforced = sidecar_enforced;
        self
    }

    pub fn sidecar_enforced_dry_run(mut self, sidecar_enforced_dry_run: bool) -> Self {
        self.sidecar_enforced_dry_run = sidecar_enforced_dry_run;
        self
    }

    pub fn sidecar_identity_narrowing(mut self, sidecar_identity_narrowing: bool) -> Self {
        self.sidecar_identity_narrowing = sidecar_identity_narrowing;
        self
    }

    pub fn cluster_domain(mut self, cluster_domain: String) -> Self {
        self.cluster_domain = cluster_domain;
        self
    }

    /// Set this cluster's remote-discovery audience identity
    /// (`FERRUM_MESH_CLUSTER_AUDIENCE`). An empty/blank value is treated as
    /// unset, which keeps cross-cluster discovery refused rather than
    /// accepting an empty audience.
    pub fn cluster_audience(mut self, cluster_audience: Option<String>) -> Self {
        self.cluster_audience = cluster_audience
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self
    }

    pub fn build(self) -> (MeshGrpcServer, broadcast::Sender<MeshConfigBroadcast>) {
        let (tx, _) = broadcast::channel(self.channel_capacity.max(1));
        let tx_clone = tx.clone();
        (
            MeshGrpcServer {
                config: self.config,
                verifier: self.verifier,
                expected_issuer: self.expected_issuer,
                mesh_update_tx: tx,
                registry: self.registry,
                namespace: self.namespace,
                scope: self.scope,
                require_ns_claim: self.require_ns_claim,
                sidecar_enforced: self.sidecar_enforced,
                sidecar_enforced_dry_run: self.sidecar_enforced_dry_run,
                sidecar_identity_narrowing: self.sidecar_identity_narrowing,
                cluster_domain: self.cluster_domain,
                expected_remote_discovery_audience: self
                    .cluster_audience
                    .as_deref()
                    .map(remote_discovery_audience),
            },
            tx_clone,
        )
    }
}

impl MeshGrpcServer {
    pub fn builder(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> MeshGrpcServerBuilder {
        MeshGrpcServerBuilder::new(config, jwt_secret)
    }

    #[allow(dead_code)]
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> (Self, broadcast::Sender<MeshConfigBroadcast>) {
        Self::builder(config, jwt_secret).build()
    }

    #[allow(dead_code)]
    pub fn with_channel_capacity(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
    ) -> (Self, broadcast::Sender<MeshConfigBroadcast>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .build()
    }

    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_issuer_and_namespace(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<MeshNodeRegistry>,
        expected_issuer: String,
        namespace: String,
    ) -> (Self, broadcast::Sender<MeshConfigBroadcast>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .registry(registry)
            .expected_issuer(expected_issuer)
            .namespace(namespace)
            .build()
    }

    #[allow(dead_code)]
    pub fn with_cluster_domain(mut self, cluster_domain: String) -> Self {
        self.cluster_domain = cluster_domain;
        self
    }

    pub fn into_service(self) -> MeshConfigSyncServer<Self> {
        MeshConfigSyncServer::new(self)
    }

    fn check_namespace(
        &self,
        mesh_namespace: &str,
        allowed: &AllowedNamespaces,
    ) -> Result<(), Status> {
        CpGrpcServer::authorise_namespace_for_scope(
            &self.scope,
            self.require_ns_claim,
            allowed,
            mesh_namespace,
        )
        .map_err(|status| {
            if matches!(self.scope, CpScope::Single(_))
                && status.code() == tonic::Code::FailedPrecondition
            {
                return Status::failed_precondition(format!(
                    "Mesh namespace '{}' does not match CP namespace '{}'. \
                     A single CP serves a single namespace; deploy a separate CP \
                     instance per namespace.",
                    mesh_namespace, self.namespace
                ));
            }
            status
        })
    }

    /// Audience policy for one `MeshSubscribe` request.
    ///
    /// Both branches require distinct audiences and fail closed, which is why
    /// trusting the client-supplied `remote_discovery` flag is safe:
    ///
    /// - A cross-cluster poll (`remote_discovery = true`) must present exactly
    ///   one `aud` naming THIS cluster. A control plane with no
    ///   `FERRUM_MESH_CLUSTER_AUDIENCE` cannot state which cluster it is, so it
    ///   refuses outright ([`GrpcAudiencePolicy::Unconfigured`]).
    /// - An ordinary local subscription (`remote_discovery = false`) must
    ///   present the fixed local-mesh purpose audience. A legacy token with no
    ///   audience and a discovery token minted for cluster B both fail.
    fn audience_policy_for(&self, remote_discovery: bool) -> GrpcAudiencePolicy<'_> {
        if !remote_discovery {
            return GrpcAudiencePolicy::Required(MESH_LOCAL_SUBSCRIBE_AUDIENCE);
        }
        match self.expected_remote_discovery_audience.as_deref() {
            Some(expected) => GrpcAudiencePolicy::Required(expected),
            None => GrpcAudiencePolicy::Unconfigured,
        }
    }

    #[allow(clippy::result_large_err, clippy::type_complexity)]
    fn verify_jwt_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
        remote_discovery: bool,
    ) -> Result<AllowedNamespaces, (Status, Option<AudienceRejectReason>)> {
        verify_grpc_jwt_metadata_with_audience(
            metadata,
            &self.verifier,
            &self.expected_issuer,
            self.audience_policy_for(remote_discovery),
            extensions.get::<CpGrpcConnectInfo>(),
        )
    }

    fn filter_config_for_request(
        &self,
        config: &GatewayConfig,
        request: &MeshSliceRequest,
        bearer_namespaces: Option<&HashSet<String>>,
    ) -> GatewayConfig {
        CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
            config,
            request,
            &self.scope,
            bearer_namespaces,
        )
    }

    fn filter_config_for_request_and_scope(
        config: &GatewayConfig,
        request: &MeshSliceRequest,
        scope: &CpScope,
        bearer_namespaces: Option<&HashSet<String>>,
    ) -> GatewayConfig {
        CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
            config,
            request,
            scope,
            bearer_namespaces,
        )
    }

    #[allow(clippy::result_large_err)]
    fn build_mesh_config_update_from_slice(slice: MeshSlice) -> Result<MeshConfigUpdate, Status> {
        let version = slice.version.clone();
        // Duplicate the slice's own ordering revision onto the envelope
        // (issue #2473), exactly as `version` is duplicated. Consumers refuse a
        // frame whose two copies disagree, so both must be derived from the one
        // slice here rather than from any ambient CP state.
        let (config_authority, config_sequence) = slice
            .revision
            .as_ref()
            .filter(|revision| revision.is_well_formed())
            .map_or_else(
                || (String::new(), 0),
                |revision| (revision.authority.clone(), revision.sequence),
            );
        let mesh_slice_json = serde_json::to_string(&slice).map_err(|e| {
            error!("Failed to serialize mesh slice: {}", e);
            Status::internal("Failed to serialize mesh slice")
        })?;
        Ok(MeshConfigUpdate {
            version,
            timestamp: chrono::Utc::now().timestamp(),
            mesh_slice_json,
            ferrum_version: FERRUM_VERSION.to_string(),
            heartbeat: false,
            config_authority,
            config_sequence,
        })
    }

    fn build_mesh_subscribe_heartbeat(version: String) -> MeshConfigUpdate {
        MeshConfigUpdate {
            version,
            timestamp: chrono::Utc::now().timestamp(),
            mesh_slice_json: String::new(),
            ferrum_version: FERRUM_VERSION.to_string(),
            heartbeat: true,
            // Heartbeats carry no slice, so they carry no ordering revision:
            // they must never be able to advance (or be ordered against) the
            // subscriber's accepted revision.
            config_authority: String::new(),
            config_sequence: 0,
        }
    }

    #[allow(clippy::result_large_err)]
    fn build_mesh_config_update_if_changed(
        config: &GatewayConfig,
        slice_request: MeshSliceRequest,
        previous_slice: &MeshSlice,
    ) -> Result<(MeshSlice, Option<MeshConfigUpdate>), Status> {
        let next_slice = MeshSlice::from_gateway_config(config, slice_request);
        if previous_slice.content_eq(&next_slice) {
            return Ok((next_slice, None));
        }
        let update = Self::build_mesh_config_update_from_slice(next_slice.clone())?;
        Ok((next_slice, Some(update)))
    }

    fn apply_mesh_delta_to_stream_config(
        stream_config: &mut GatewayConfig,
        delta: crate::config::db_loader::IncrementalResult,
        slice_request: MeshSliceRequest,
        previous_slice: &MeshSlice,
        scope: &CpScope,
        bearer_namespaces: Option<&HashSet<String>>,
    ) -> Result<(MeshSlice, Option<MeshConfigUpdate>), Status> {
        let mut candidate = stream_config.clone();
        // Advance the authoritative revision from the delta's durable change
        // cursor before the slice is built (issue #2473). `max` guards a peer
        // that sent no cursor (0): the per-stream base must never move
        // backwards, or a subscriber would quarantine its own CP's frames.
        if let Some(revision) = candidate.mesh_revision.as_mut() {
            revision.sequence = revision.sequence.max(delta.sequence_cursor);
        }
        apply_incremental_to_config_snapshot(&mut candidate, delta);
        candidate = Self::filter_config_for_request_and_scope(
            &candidate,
            &slice_request,
            scope,
            bearer_namespaces,
        );
        candidate.normalize_fields();
        candidate.normalize_mesh_fields();
        // Advance the per-stream base BEFORE building the wire frame: the delta
        // is logically consumed regardless of whether THIS frame serializes.
        // Deferring this past the `?` below would drop the delta from the
        // accumulator on a serialization failure, so every subsequent delta
        // would apply onto a base missing this one — a persistent per-stream
        // config divergence. (The Full/Lagged arms always advance the snapshot;
        // the caller still gates `previous_slice` advancement on a built update
        // and drops the frame on Err, so the next delta converges cleanly.)
        *stream_config = candidate;
        let result = Self::build_mesh_config_update_if_changed(
            stream_config,
            slice_request,
            previous_slice,
        )?;
        Ok(result)
    }

    pub fn broadcast_full_with_registry(
        tx: &broadcast::Sender<MeshConfigBroadcast>,
        config: Arc<GatewayConfig>,
        registry: &MeshNodeRegistry,
    ) {
        let _ = tx.send(MeshConfigBroadcast::Full(config));
        registry.touch_all();
    }

    pub fn broadcast_delta_with_registry(
        tx: &broadcast::Sender<MeshConfigBroadcast>,
        result: crate::config::db_loader::IncrementalResult,
        version: &str,
        registry: &MeshNodeRegistry,
    ) {
        let _ = tx.send(MeshConfigBroadcast::Delta {
            result: Box::new(result),
            version: version.to_string(),
        });
        registry.touch_all();
    }
}

#[tonic::async_trait]
impl MeshConfigSync for MeshGrpcServer {
    type MeshSubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        let remote_discovery = request.get_ref().remote_discovery;
        let allowed = match self.verify_jwt_metadata(
            request.metadata(),
            request.extensions(),
            remote_discovery,
        ) {
            Ok(allowed) => allowed,
            Err((status, audience_reason)) => {
                let req = request.get_ref();
                if let Some(reason) = audience_reason {
                    // Fixed-cardinality diagnostics only: the subscription
                    // class and a closed-set reason label. The token, its
                    // claims, the expected audience, and the JWT secret are
                    // never rendered.
                    let subscription_class = if remote_discovery {
                        "remote_discovery"
                    } else {
                        "local"
                    };
                    crate::plugins::mesh::prometheus_helpers::increment_mesh_subscribe_audience_rejection(
                        subscription_class,
                        reason.as_metric_label(),
                    );
                    warn!(
                        audit.event = "mesh_subscribe_audience_rejected",
                        surface = "MeshConfigSync.MeshSubscribe",
                        subscription_class,
                        reason = reason.as_metric_label(),
                        "Refused MeshSubscribe: JWT audience does not match subscription purpose"
                    );
                }
                CpGrpcServer::audit_tenant_subscription(
                    "MeshConfigSync.MeshSubscribe",
                    &req.node_id,
                    &req.namespace,
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };

        let inner = request.into_inner();
        CpGrpcServer::check_version_compatibility(&inner.ferrum_version)?;
        if let Err(status) = self.check_namespace(&inner.namespace, &allowed) {
            CpGrpcServer::audit_tenant_subscription(
                "MeshConfigSync.MeshSubscribe",
                &inner.node_id,
                &inner.namespace,
                "failure",
                status.message(),
            );
            return Err(status);
        }
        if inner.node_id.is_empty() {
            return Err(Status::invalid_argument(
                "MeshSubscribe node_id is required",
            ));
        }
        CpGrpcServer::audit_tenant_subscription(
            "MeshConfigSync.MeshSubscribe",
            &inner.node_id,
            &inner.namespace,
            "success",
            "",
        );

        info!(
            "Mesh node '{}' (v{}) subscribed for mesh config (namespace='{}')",
            inner.node_id, inner.ferrum_version, inner.namespace
        );

        let waypoint_name = if inner.waypoint_name.trim().is_empty() {
            None
        } else {
            Some(inner.waypoint_name.clone())
        };
        let node_id = inner.node_id;
        let node_version = inner.ferrum_version;
        let node_namespace = inner.namespace;
        let bearer_namespaces = allowed.effective_namespaces().cloned();

        let slice_request = MeshSliceRequest::from_native(
            node_id.clone(),
            node_namespace.clone(),
            inner.workload_spiffe_id,
            inner.labels,
        )
        .with_waypoint_name(waypoint_name)
        .with_cluster_domain(self.cluster_domain.clone())
        .with_enforce_sidecar_egress(self.sidecar_enforced)
        .with_sidecar_egress_dry_run(self.sidecar_enforced_dry_run)
        .with_enforce_sidecar_identity_narrowing(self.sidecar_identity_narrowing);
        let slice_request = slice_request
            .with_ambient_udp_source_scoping(inner.ambient_udp_source_scoping)
            .with_node_waypoint_capture_scoping(inner.node_waypoint_capture_scoping);
        // Register the receiver before loading the initial snapshot so a
        // concurrent CP broadcast is either captured by this stream or already
        // reflected in the loaded snapshot.
        let rx = self.mesh_update_tx.subscribe();
        let config = self.config.load_full();
        let mut initial_config = self.filter_config_for_request(
            config.as_ref(),
            &slice_request,
            bearer_namespaces.as_ref(),
        );
        initial_config.normalize_fields();
        initial_config.normalize_mesh_fields();
        let initial_slice = MeshSlice::from_gateway_config(&initial_config, slice_request.clone());
        let initial = Self::build_mesh_config_update_from_slice(initial_slice.clone())?;

        let now = Utc::now();
        self.registry.insert(MeshNodeInfo {
            node_id: node_id.clone(),
            version: node_version,
            namespace: node_namespace,
            connected_at: now,
            last_heartbeat_at: now,
            last_update_at: now,
        });

        let mut stream_config = initial_config;
        let mut previous_slice = initial_slice;
        let config_for_recovery = self.config.clone();
        let stream_slice_request = slice_request.clone();
        let stream_scope = self.scope.clone();
        let stream_bearer_namespaces = bearer_namespaces;
        let stream = BroadcastStream::new(rx).filter_map(move |result| {
            let slice_request = stream_slice_request.clone();
            match result {
                Ok(MeshConfigBroadcast::Full(config)) => {
                    let mut config = Self::filter_config_for_request_and_scope(
                        config.as_ref(),
                        &slice_request,
                        &stream_scope,
                        stream_bearer_namespaces.as_ref(),
                    );
                    config.normalize_fields();
                    config.normalize_mesh_fields();
                    match Self::build_mesh_config_update_if_changed(
                        &config,
                        slice_request,
                        &previous_slice,
                    ) {
                        Ok((next_slice, Some(mesh_update))) => {
                            stream_config = config;
                            previous_slice = next_slice;
                            Some(Ok(mesh_update))
                        }
                        Ok((_, None)) => {
                            stream_config = config;
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
                Ok(MeshConfigBroadcast::Delta { result, version }) => {
                    match Self::apply_mesh_delta_to_stream_config(
                        &mut stream_config,
                        *result,
                        slice_request,
                        &previous_slice,
                        &stream_scope,
                        stream_bearer_namespaces.as_ref(),
                    ) {
                        Ok((next_slice, maybe_update)) => {
                            if maybe_update.is_some() {
                                previous_slice = next_slice;
                            }
                            maybe_update.map(Ok)
                        }
                        Err(e) => {
                            warn!(
                                version = %version,
                                error = %e,
                                "Failed to build mesh delta update"
                            );
                            None
                        }
                    }
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(
                        "Mesh config stream lagged behind by {} updates — sending full mesh slice to recover",
                        n
                    );
                    let current = config_for_recovery.load_full();
                    let mut current_config = Self::filter_config_for_request_and_scope(
                        current.as_ref(),
                        &slice_request,
                        &stream_scope,
                        stream_bearer_namespaces.as_ref(),
                    );
                    current_config.normalize_fields();
                    current_config.normalize_mesh_fields();
                    match Self::build_mesh_config_update_if_changed(
                        &current_config,
                        slice_request,
                        &previous_slice,
                    ) {
                        Ok((next_slice, Some(update))) => {
                            stream_config = current_config;
                            previous_slice = next_slice;
                            Some(Ok(update))
                        }
                        Ok((_, None)) => {
                            stream_config = current_config;
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
            }
        });

        let initial_stream = tokio_stream::once(Ok(initial));
        let heartbeat_config = self.config.clone();
        let heartbeat_stream = IntervalStream::new(interval_at(
            Instant::now() + MESH_SUBSCRIBE_HEARTBEAT_INTERVAL,
            MESH_SUBSCRIBE_HEARTBEAT_INTERVAL,
        ))
        .map(move |_| {
            let current = heartbeat_config.load_full();
            Ok(Self::build_mesh_subscribe_heartbeat(
                current.loaded_at.to_rfc3339(),
            ))
        });
        let combined = initial_stream.chain(stream::select(stream, heartbeat_stream));
        let tracked = TrackedMeshStream {
            inner: Box::pin(combined),
            registry: self.registry.clone(),
            node_id,
            connected_at: now,
        };
        Ok(Response::new(Box::pin(tracked)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_loader::{IncrementalResult, NamespacedResourceId};
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AppProtocol, MeshConfig, MeshService, NodeWaypointEndpoint, ServicePort, Workload,
        WorkloadSelector,
    };
    use chrono::{TimeZone, Utc};

    fn mesh_config_with_service(version_second: u32) -> GatewayConfig {
        mesh_config_with_named_service("api", version_second)
    }

    fn mesh_config_with_named_service(name: &str, version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![MeshService {
                    cluster_ips: Vec::new(),
                    name: name.to_string(),
                    namespace: "ferrum".to_string(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                        target_port: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: std::collections::HashMap::new(),
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

    fn node_waypoint_workload(
        namespace: &str,
        service_name: &str,
        waypoint_spiffe: &str,
        address: &str,
    ) -> Workload {
        Workload {
            spiffe_id: SpiffeId::new(format!(
                "spiffe://test.local/ns/{namespace}/sa/{service_name}"
            ))
            .expect("fixture SPIFFE ID should be valid"),
            selector: WorkloadSelector {
                labels: std::collections::HashMap::from([(
                    "app".to_string(),
                    service_name.to_string(),
                )]),
                namespace: Some(namespace.to_string()),
            },
            service_name: service_name.to_string(),
            addresses: vec![address.to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("test.local")
                .expect("fixture trust domain should be valid"),
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some(service_name.to_string()),
            pod_uid: None,
            node_waypoint: Some(NodeWaypointEndpoint {
                address: address.to_string(),
                hbone_port: 15008,
                spiffe_id: SpiffeId::new(waypoint_spiffe)
                    .expect("fixture waypoint SPIFFE ID should be valid"),
                node_name: None,
                node_uid: None,
                network: None,
                cluster: None,
            }),
            remote_provenance: false,
        }
    }

    fn mesh_server_with_scope(scope: CpScope, require_ns_claim: bool) -> MeshGrpcServer {
        let cfg = Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())));
        let (server, _tx) = MeshGrpcServer::builder(cfg, "test-secret".to_string())
            .scope(scope)
            .require_ns_claim(require_ns_claim)
            .build();
        server
    }

    fn allowed_namespaces(namespaces: &[&str]) -> AllowedNamespaces {
        AllowedNamespaces::claimed(namespaces.iter().map(|ns| ns.to_string()).collect())
    }

    #[test]
    fn mesh_subscribe_all_scope_rejects_missing_claim() {
        let server = mesh_server_with_scope(CpScope::All, false);
        let err = server
            .check_namespace("ferrum-ebpf-live", &AllowedNamespaces::empty())
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Multi-namespace CP scope"));
    }

    #[test]
    fn mesh_subscribe_all_scope_accepts_workload_namespace_with_claim() {
        let server = mesh_server_with_scope(CpScope::All, false);
        let allowed = allowed_namespaces(&["ferrum-ebpf-live"]);

        assert!(server.check_namespace("ferrum-ebpf-live", &allowed).is_ok());
    }

    #[test]
    fn mesh_subscribe_single_scope_rejects_other_namespace() {
        let server = mesh_server_with_scope(CpScope::Single("ferrum".to_string()), false);
        let err = server
            .check_namespace("ferrum-ebpf-live", &AllowedNamespaces::empty())
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("ferrum-ebpf-live"));
        assert!(err.message().contains("ferrum"));
    }

    #[test]
    fn mesh_subscribe_require_claim_rejects_missing_claim() {
        let server = mesh_server_with_scope(CpScope::Single("ferrum-ebpf-live".to_string()), true);
        let err = server
            .check_namespace("ferrum-ebpf-live", &AllowedNamespaces::empty())
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("FERRUM_CP_REQUIRE_NAMESPACE_CLAIM"));
    }

    #[test]
    fn mesh_subscribe_claim_must_allow_requested_namespace() {
        let server = mesh_server_with_scope(CpScope::All, false);
        let allowed = allowed_namespaces(&["prod"]);
        let err = server
            .check_namespace("ferrum-ebpf-live", &allowed)
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("ferrum-ebpf-live"));
    }

    #[test]
    fn mesh_delta_update_skips_unchanged_mesh_slice_content() {
        let mut stream_config = mesh_config_with_service(0);
        let poll_timestamp = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 42).unwrap();
        let delta = IncrementalResult {
            added_or_modified_proxies: Vec::new(),
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "stale-upstream")],
            sequence_cursor: 0,
            poll_timestamp,
        };
        let slice_request = MeshSliceRequest::from_native(
            "node-a".to_string(),
            "ferrum".to_string(),
            String::new(),
            std::collections::HashMap::new(),
        );
        let previous_slice = MeshSlice::from_gateway_config(&stream_config, slice_request.clone());
        let (next_slice, update) = MeshGrpcServer::apply_mesh_delta_to_stream_config(
            &mut stream_config,
            delta,
            slice_request,
            &previous_slice,
            &CpScope::Single("ferrum".to_string()),
            None,
        )
        .expect("mesh delta should build");

        assert!(update.is_none());
        assert_eq!(stream_config.loaded_at, poll_timestamp);
        assert_eq!(next_slice.version, poll_timestamp.to_rfc3339());
        assert_eq!(next_slice.services.len(), 1);
        // The base advanced: this delta is now baked into stream_config, so the
        // next delta applies on top of it rather than re-diverging. (The fix
        // makes this advancement unconditional — it no longer hinges on the wire
        // frame building successfully; see apply_mesh_delta_to_stream_config.)
    }

    #[test]
    fn mesh_delta_refilter_preserves_carried_node_waypoint_assertors() {
        let waypoint_alpha = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-alpha";
        let waypoint_beta = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-beta";
        let full_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![
                    node_waypoint_workload("alpha", "client", waypoint_alpha, "10.2.0.11"),
                    node_waypoint_workload("beta", "reviews", waypoint_beta, "10.2.0.12"),
                ],
                ..MeshConfig::default()
            })),
            loaded_at: Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            ..GatewayConfig::default()
        };
        let slice_request = MeshSliceRequest {
            namespace: "beta".to_string(),
            ..MeshSliceRequest::default()
        };
        let mut scope = std::collections::HashSet::new();
        scope.insert("alpha".to_string());
        scope.insert("beta".to_string());
        let scope = CpScope::Set(scope);
        let mut stream_config = MeshGrpcServer::filter_config_for_request_and_scope(
            &full_config,
            &slice_request,
            &scope,
            None,
        );
        let mesh = stream_config.mesh.as_ref().expect("mesh should remain");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].namespace, "beta");
        assert_eq!(
            mesh.node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta]
        );
        let previous_slice = MeshSlice::from_gateway_config(&stream_config, slice_request.clone());
        let poll_timestamp = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 42).unwrap();
        let delta = IncrementalResult {
            added_or_modified_proxies: Vec::new(),
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "unrelated-upstream")],
            sequence_cursor: 0,
            poll_timestamp,
        };

        let (next_slice, _update) = MeshGrpcServer::apply_mesh_delta_to_stream_config(
            &mut stream_config,
            delta,
            slice_request,
            &previous_slice,
            &scope,
            None,
        )
        .expect("mesh delta should build");

        assert_eq!(
            stream_config
                .mesh
                .as_ref()
                .expect("mesh should remain")
                .node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta],
            "incremental refiltering must not shrink carried source assertors"
        );
        assert_eq!(
            next_slice
                .node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta]
        );
    }

    #[test]
    fn mesh_full_update_emits_when_mesh_slice_content_changes() {
        let stream_config = mesh_config_with_named_service("stream-local", 0);
        let next_config = mesh_config_with_named_service("new-service", 43);
        let slice_request = MeshSliceRequest::from_native(
            "node-a".to_string(),
            "ferrum".to_string(),
            String::new(),
            std::collections::HashMap::new(),
        );
        let previous_slice = MeshSlice::from_gateway_config(&stream_config, slice_request.clone());
        let (_next_slice, update) = MeshGrpcServer::build_mesh_config_update_if_changed(
            &next_config,
            slice_request,
            &previous_slice,
        )
        .expect("mesh full update should build");
        let update = update.expect("changed mesh content should emit an update");
        let slice: MeshSlice =
            serde_json::from_str(&update.mesh_slice_json).expect("mesh slice should deserialize");

        assert_eq!(slice.version, next_config.loaded_at.to_rfc3339());
        assert_eq!(slice.services[0].name, "new-service");
        assert_eq!(
            stream_config.mesh.as_ref().unwrap().services[0].name,
            "stream-local"
        );
    }

    #[test]
    fn mesh_subscribe_heartbeat_is_lightweight() {
        let heartbeat = MeshGrpcServer::build_mesh_subscribe_heartbeat("v1".to_string());

        assert!(heartbeat.heartbeat);
        assert_eq!(heartbeat.version, "v1");
        assert!(heartbeat.mesh_slice_json.is_empty());
        assert_eq!(heartbeat.ferrum_version, crate::FERRUM_VERSION);
    }

    #[test]
    fn mesh_subscribe_sidecar_narrowing_survives_wire_serialization() {
        // Verifies that when `sidecar_enforced=true`, the slice the CP emits
        // on the wire is already narrowed: only the egress-admitted resources
        // survive, and the `sidecars` array itself is empty on the DP side
        // (DPs do not need the originals — the slice they receive is the
        // authoritative view).
        use crate::modes::mesh::config::{MeshSidecar, MeshSidecarEgress};

        let mut mesh = MeshConfig {
            services: vec![
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "reviews".to_string(),
                    namespace: "alpha".to_string(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                        target_port: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: std::collections::HashMap::new(),
                },
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "checkout".to_string(),
                    namespace: "alpha".to_string(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                        target_port: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: std::collections::HashMap::new(),
                },
            ],
            ..MeshConfig::default()
        };
        mesh.sidecars = vec![MeshSidecar {
            name: "default-sc".to_string(),
            namespace: "alpha".to_string(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: vec![MeshSidecarEgress {
                hosts: vec!["./reviews".to_string()],
                port: None,
            }],
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        }];
        let config = GatewayConfig {
            mesh: Some(Box::new(mesh)),
            loaded_at: Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            ..GatewayConfig::default()
        };
        let slice_request = MeshSliceRequest::from_native(
            "node-a".to_string(),
            "alpha".to_string(),
            String::new(),
            std::collections::HashMap::new(),
        )
        .with_enforce_sidecar_egress(true);
        let slice = MeshSlice::from_gateway_config(&config, slice_request);
        // The CP narrowed the slice before serialization — only `reviews`
        // should survive, and no Sidecar resource is carried on the wire.
        let update = MeshGrpcServer::build_mesh_config_update_from_slice(slice.clone())
            .expect("update builds");
        let parsed: MeshSlice = serde_json::from_str(&update.mesh_slice_json)
            .expect("mesh slice round-trips through JSON");
        assert_eq!(parsed.services.len(), 1);
        assert_eq!(parsed.services[0].name, "reviews");
    }
}
