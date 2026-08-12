use crate::fips::approved::Sha256;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use super::admission::{
    XdsAdmissionController, XdsAdmissionLimits, XdsAdmissionRejection, XdsStreamPermit,
    principal_key, redacted_identifier, xds_state_key,
};
use super::nonce::{AckOutcome, XdsNonceTracker};
use super::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use super::proto::{
    ControlPlane, DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest,
    DiscoveryResponse,
};
use super::snapshot::{XdsConfigFingerprint, XdsSnapshot, XdsSnapshotCache};
use super::translator::translate_mesh_slice_to_snapshot;
use crate::FERRUM_VERSION;
use crate::config::incremental_apply::apply_incremental_to_config_snapshot;
use crate::config::types::GatewayConfig;
use crate::grpc::auth::{
    AllowedNamespaces, GrpcAudiencePolicy, VerifiedGrpcIdentity,
    verify_grpc_jwt_metadata_with_audience,
};
use crate::grpc::cp_server::{CpGrpcServer, CpScope, NamespaceBroadcasts};
use crate::grpc::cp_trust::{CpDpVerifier, CpGrpcConnectInfo};
use crate::grpc::proto::ConfigUpdate;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::xds::carrier::XdsNodeScoping;

const MAX_SUBSCRIPTIONS_PER_STREAM: usize = 32;
const MAX_RESOURCE_NAMES_PER_REQUEST: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct XdsSubscription {
    node_id: String,
    type_url: String,
    resource_names: Vec<String>,
    wildcard: bool,
}

#[derive(Clone)]
struct XdsStreamConfig {
    config: GatewayConfig,
    fingerprint: XdsConfigFingerprint,
}

impl XdsStreamConfig {
    fn new(config: GatewayConfig) -> Self {
        let fingerprint = config_fingerprint(&config);
        Self {
            config,
            fingerprint,
        }
    }

    fn apply_update(&mut self, update: &ConfigUpdate) -> bool {
        if !XdsAdsServer::apply_update_to_stream_config(&mut self.config, update) {
            return false;
        }
        self.fingerprint = config_fingerprint(&self.config);
        true
    }
}

/// Envoy ADS implementation for Phase B.
#[derive(Clone)]
pub struct XdsAdsServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<ConfigUpdate>,
    namespace_broadcasts: Option<Arc<NamespaceBroadcasts>>,
    /// Shared with the ConfigSync and mesh servers so ADS enforces the same
    /// namespace-bound verification credentials, not a second authorization
    /// source (advisory GHSA-3f2j-wwqw-grmg).
    verifier: Arc<CpDpVerifier>,
    expected_issuer: String,
    namespace: String,
    scope: CpScope,
    require_ns_claim: bool,
    stream_channel_capacity: usize,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    /// Shared ADS admission accounting (issue #3741). One controller per CP
    /// process, cloned by reference into every SotW and Delta stream so the two
    /// methods draw from ONE aggregate budget and cannot be split against each
    /// other.
    admission: XdsAdmissionController,
    /// Per-node workload SPIFFE identities learned from the DP's `Node.metadata`
    /// on the ADS stream. The CP keys snapshots by state key (namespace +
    /// authenticated-principal digest + `Node.id`), so the workload SPIFFE —
    /// needed to compute Sidecar-aware narrowing and the un-narrowed
    /// local-inbound-service view — is recorded here when first seen and read
    /// at snapshot-build time. Cleared when the node's last stream ends.
    workload_identities: Arc<DashMap<String, String>>,
    waypoint_names: Arc<DashMap<String, String>>,
    /// Per-node cross-namespace inventory scoping learned from the DP's
    /// `Node.metadata`. One entry per node that asked for ANY of the
    /// cross-namespace inventories (Ambient UDP source evidence, NodeWaypoint
    /// capture destinations); absent means the node asked for none.
    node_scoping: Arc<DashMap<String, XdsNodeScoping>>,
    /// Per-stream bearer boundary. Network handlers set this on their cloned
    /// server after JWT verification; an explicit `ns` claim restricts the
    /// Ambient UDP source workload/policy superset to the claim's namespaces.
    ambient_udp_source_bearer_namespaces: Option<HashSet<String>>,
    /// Mirror of `EnvConfig.mesh_sidecar_enforced`. When `true`, the slice
    /// builder applies Istio `Sidecar` egress scope narrowing. Default
    /// `false` preserves existing CP behavior.
    sidecar_enforced: bool,
    /// Mirror of `EnvConfig.mesh_sidecar_enforced_dry_run`.
    sidecar_enforced_dry_run: bool,
    /// Mirror of `EnvConfig.mesh_sidecar_identity_narrowing`. Only takes
    /// effect when `sidecar_enforced` is also true.
    sidecar_identity_narrowing: bool,
    /// Cluster DNS suffix used when synthesizing MeshService FQDN aliases for
    /// Sidecar egress matching.
    cluster_domain: String,
}

/// Per-stream cleanup owner (issue #3741).
///
/// Holds the [`XdsStreamPermit`] that carries this stream's total /
/// namespace / principal reservation, and owns every node-scoped map entry the
/// stream created. Dropping the guard releases the node registration first
/// (cleaning node-scoped state when this was the node's last stream) and then
/// drops the permit, which releases the aggregate reservation exactly once.
///
/// The guard lives inside the spawned relay task, so an abort, a panic, a
/// client disconnect, a receiver drop, and process shutdown all unwind through
/// this `Drop` — no termination path needs an explicit release.
struct XdsStreamGuard {
    node_state_key: Option<String>,
    permit: XdsStreamPermit,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    workload_identities: Arc<DashMap<String, String>>,
    waypoint_names: Arc<DashMap<String, String>>,
    node_scoping: Arc<DashMap<String, XdsNodeScoping>>,
}

impl XdsStreamGuard {
    fn new(
        permit: XdsStreamPermit,
        snapshot_cache: Arc<XdsSnapshotCache>,
        nonce_tracker: Arc<XdsNonceTracker>,
        workload_identities: Arc<DashMap<String, String>>,
        waypoint_names: Arc<DashMap<String, String>>,
        node_scoping: Arc<DashMap<String, XdsNodeScoping>>,
    ) -> Self {
        Self {
            node_state_key: None,
            permit,
            snapshot_cache,
            nonce_tracker,
            workload_identities,
            waypoint_names,
            node_scoping,
        }
    }

    /// Register the stream's resolved node state key against the innermost
    /// (per-node) and distinct-node budgets.
    ///
    /// On `Err` nothing was registered, so no matching release is owed and the
    /// stream still holds only its aggregate reservation.
    fn set_node_state_key(&mut self, state_key: &str) -> Result<(), XdsAdmissionRejection> {
        if self.node_state_key.as_deref() == Some(state_key) {
            return Ok(());
        }
        self.clear_current();
        self.permit.register_node(state_key)?;
        self.node_state_key = Some(state_key.to_string());
        Ok(())
    }

    fn clear_current(&mut self) {
        let Some(state_key) = self.node_state_key.take() else {
            return;
        };
        let snapshot_cache = Arc::clone(&self.snapshot_cache);
        let nonce_tracker = Arc::clone(&self.nonce_tracker);
        let workload_identities = Arc::clone(&self.workload_identities);
        let waypoint_names = Arc::clone(&self.waypoint_names);
        let node_scoping = Arc::clone(&self.node_scoping);
        let _ = self.permit.release_node_with_cleanup(|| {
            snapshot_cache.remove(&state_key);
            nonce_tracker.remove_node(&state_key);
            workload_identities.remove(&state_key);
            waypoint_names.remove(&state_key);
            node_scoping.remove(&state_key);
        });
    }
}

impl Drop for XdsStreamGuard {
    fn drop(&mut self) {
        self.clear_current();
    }
}

impl XdsAdsServer {
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        update_tx: broadcast::Sender<ConfigUpdate>,
        jwt_secret: String,
        expected_issuer: String,
        namespace: String,
        stream_channel_capacity: usize,
    ) -> Self {
        Self::with_sidecar_enforcement(
            config,
            update_tx,
            jwt_secret,
            expected_issuer,
            namespace,
            stream_channel_capacity,
            false,
        )
    }

    pub fn with_sidecar_enforcement(
        config: Arc<ArcSwap<GatewayConfig>>,
        update_tx: broadcast::Sender<ConfigUpdate>,
        jwt_secret: String,
        expected_issuer: String,
        namespace: String,
        stream_channel_capacity: usize,
        sidecar_enforced: bool,
    ) -> Self {
        Self {
            config,
            update_tx,
            namespace_broadcasts: None,
            verifier: Arc::new(CpDpVerifier::SharedSecret(jwt_secret)),
            expected_issuer,
            namespace: namespace.clone(),
            scope: CpScope::Single(namespace),
            require_ns_claim: false,
            stream_channel_capacity: stream_channel_capacity.max(1),
            snapshot_cache: Arc::new(XdsSnapshotCache::new()),
            nonce_tracker: Arc::new(XdsNonceTracker::new()),
            admission: XdsAdmissionController::new(XdsAdmissionLimits::default()),
            workload_identities: Arc::new(DashMap::new()),
            waypoint_names: Arc::new(DashMap::new()),
            node_scoping: Arc::new(DashMap::new()),
            ambient_udp_source_bearer_namespaces: None,
            sidecar_enforced,
            sidecar_enforced_dry_run: false,
            sidecar_identity_narrowing: false,
            cluster_domain: crate::modes::mesh::dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
        }
    }

    pub fn with_sidecar_enforcement_dry_run(mut self, dry_run: bool) -> Self {
        self.sidecar_enforced_dry_run = dry_run;
        self
    }

    pub fn with_scope(mut self, scope: CpScope) -> Self {
        self.scope = scope;
        self
    }

    /// Replace the seeded shared-secret verifier with the CP's configured
    /// namespace-bound trust bundle.
    pub fn with_verifier(mut self, verifier: Arc<CpDpVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn with_require_namespace_claim(mut self, require: bool) -> Self {
        self.require_ns_claim = require;
        self
    }

    pub fn with_namespace_broadcasts(mut self, broadcasts: Arc<NamespaceBroadcasts>) -> Self {
        self.namespace_broadcasts = Some(broadcasts);
        self
    }

    pub fn with_sidecar_identity_narrowing(mut self, sidecar_identity_narrowing: bool) -> Self {
        self.sidecar_identity_narrowing = sidecar_identity_narrowing;
        self
    }

    pub fn with_cluster_domain(mut self, cluster_domain: String) -> Self {
        self.cluster_domain = cluster_domain;
        self
    }

    /// Override every ADS admission budget at once. Replaces the shared
    /// controller, so call this during setup before any stream is served.
    pub fn with_admission_limits(mut self, limits: XdsAdmissionLimits) -> Self {
        self.admission = XdsAdmissionController::new(limits);
        self
    }

    /// Override only the per-node concurrent ADS stream ceiling, keeping every
    /// other budget at its default. `0` disables that one cap (unbounded).
    /// Replaces the controller, so call this during setup before any stream is
    /// served.
    pub fn with_max_streams_per_node(self, max_streams_per_node: usize) -> Self {
        let limits = XdsAdmissionLimits {
            max_streams_per_node,
            ..*self.admission.limits()
        };
        self.with_admission_limits(limits)
    }

    /// The shared ADS admission controller. Exposed so operators' tests and the
    /// CP runtime can read current occupancy without reaching into internals.
    pub fn admission(&self) -> XdsAdmissionController {
        self.admission.clone()
    }

    /// Reserve an aggregate permit for the existing inline guard tests, which
    /// exercise node-scoped cleanup rather than the aggregate budget.
    #[cfg(test)]
    fn test_permit(&self) -> XdsStreamPermit {
        self.admission
            .reserve_stream(&self.namespace, "test-principal")
            .expect("default aggregate budget admits a test stream")
    }

    pub fn into_service(self) -> AggregatedDiscoveryServiceServer<Self> {
        AggregatedDiscoveryServiceServer::new(self)
    }

    pub fn snapshot_cache(&self) -> Arc<XdsSnapshotCache> {
        self.snapshot_cache.clone()
    }

    pub fn nonce_tracker(&self) -> Arc<XdsNonceTracker> {
        self.nonce_tracker.clone()
    }

    /// Verify the stream's bearer and return BOTH the tenant ceiling and the
    /// authenticated principal (JWT `sub`).
    ///
    /// The audience posture is unchanged from the previous
    /// `verify_grpc_jwt_metadata_with_claims` call
    /// ([`GrpcAudiencePolicy::ReservedForbidden`]); the only difference is that
    /// the subject is no longer discarded — ADS needs it to keep unrelated
    /// principals off one mutable state key and one quota (issue #3741).
    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<VerifiedGrpcIdentity, Status> {
        verify_grpc_jwt_metadata_with_audience(
            metadata,
            &self.verifier,
            &self.expected_issuer,
            GrpcAudiencePolicy::ReservedForbidden,
            extensions.get::<CpGrpcConnectInfo>(),
        )
        .map_err(|(status, _)| status)
    }

    /// Reserve total + namespace + principal ADS capacity for one stream.
    ///
    /// MUST be called before the relay task is spawned, before the per-stream
    /// response channel is allocated, and before the filtered `GatewayConfig`
    /// snapshot is built — those are exactly the allocations the aggregate
    /// budget exists to bound (issue #3741).
    #[allow(clippy::result_large_err)]
    fn reserve_stream_capacity(
        &self,
        method: &'static str,
        namespace: &str,
        principal_key: &str,
    ) -> Result<XdsStreamPermit, Status> {
        self.admission
            .reserve_stream(namespace, principal_key)
            .map_err(|rejection| {
                record_xds_admission_rejection(method, namespace, None, rejection);
                rejection.into_status()
            })
    }

    #[allow(clippy::result_large_err)]
    fn resolve_xds_namespace(&self, allowed: &AllowedNamespaces) -> Result<String, Status> {
        CpGrpcServer::resolve_stream_namespace_for_scope(
            &self.scope,
            self.require_ns_claim,
            allowed,
        )
    }

    fn filter_config_for_xds_request(
        &self,
        config: &GatewayConfig,
        namespace: &str,
        waypoint_name: Option<String>,
        scoping: XdsNodeScoping,
    ) -> GatewayConfig {
        let request = MeshSliceRequest {
            namespace: namespace.to_string(),
            waypoint_name,
            ..MeshSliceRequest::default()
        }
        .with_enforce_sidecar_egress(self.sidecar_enforced)
        .with_sidecar_egress_dry_run(self.sidecar_enforced_dry_run)
        .with_enforce_sidecar_identity_narrowing(self.sidecar_identity_narrowing)
        .with_ambient_udp_source_scoping(scoping.ambient_udp_source_scoping)
        .with_node_waypoint_capture_scoping(scoping.node_waypoint_capture_scoping);
        CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
            config,
            &request,
            &self.scope,
            self.ambient_udp_source_bearer_namespaces.as_ref(),
        )
    }

    fn replace_stream_config_if_changed(
        &self,
        stream_config: &mut XdsStreamConfig,
        config: GatewayConfig,
    ) -> bool {
        let fingerprint = config_fingerprint(&config);
        if stream_config.fingerprint == fingerprint {
            return false;
        }
        *stream_config = XdsStreamConfig {
            config,
            fingerprint,
        };
        true
    }

    fn refresh_stream_config_from_current(
        &self,
        stream_config: &mut XdsStreamConfig,
        namespace: &str,
        waypoint_name: Option<String>,
        scoping: XdsNodeScoping,
    ) -> bool {
        let current = self.config.load_full();
        let filtered =
            self.filter_config_for_xds_request(current.as_ref(), namespace, waypoint_name, scoping);
        self.replace_stream_config_if_changed(stream_config, filtered)
    }

    fn apply_xds_update_to_stream_config(
        &self,
        stream_config: &mut XdsStreamConfig,
        update: &ConfigUpdate,
        namespace: &str,
        waypoint_name: Option<String>,
        scoping: XdsNodeScoping,
    ) -> bool {
        if self.namespace_broadcasts.is_some() {
            // Multi-namespace broadcast payloads are ConfigSync-strict on purpose.
            // xDS needs the mesh request view, so treat the per-namespace event as
            // a wake-up and rebuild from the current shared config before serializing.
            return self.refresh_stream_config_from_current(
                stream_config,
                namespace,
                waypoint_name,
                scoping,
            );
        }
        let previous_fingerprint = stream_config.fingerprint.clone();
        if !stream_config.apply_update(update) {
            return false;
        }
        let filtered = self.filter_config_for_xds_request(
            &stream_config.config,
            namespace,
            waypoint_name,
            scoping,
        );
        *stream_config = XdsStreamConfig::new(filtered);
        stream_config.fingerprint != previous_fingerprint
    }

    fn apply_pre_node_xds_update_to_stream_config(
        &self,
        stream_config: &mut XdsStreamConfig,
        update: &ConfigUpdate,
        namespace: &str,
    ) {
        let _ = self.apply_xds_update_to_stream_config(
            stream_config,
            update,
            namespace,
            None,
            XdsNodeScoping::default(),
        );
    }

    fn updates_for_namespace(&self, namespace: &str) -> broadcast::Receiver<ConfigUpdate> {
        self.namespace_broadcasts
            .as_ref()
            .map(|broadcasts| broadcasts.sender_for(namespace).subscribe())
            .unwrap_or_else(|| self.update_tx.subscribe())
    }

    fn snapshot_namespace_for_config(&self, config: &GatewayConfig) -> String {
        if config.known_namespaces.len() == 1 {
            return config.known_namespaces[0].clone();
        }
        self.namespace.clone()
    }

    fn rebuild_snapshot(&self, node_id: &str) -> XdsSnapshot {
        let config = self.config.load_full();
        self.rebuild_snapshot_from_config(node_id, config.as_ref())
    }

    fn rebuild_snapshot_from_config(&self, node_id: &str, config: &GatewayConfig) -> XdsSnapshot {
        self.rebuild_snapshot_from_config_for_node(node_id, node_id, config)
    }

    fn rebuild_snapshot_from_config_for_node(
        &self,
        metadata_key: &str,
        node_id: &str,
        config: &GatewayConfig,
    ) -> XdsSnapshot {
        let namespace = self.snapshot_namespace_for_config(config);
        let scoping = self.node_scoping_for_state_key(metadata_key);
        let request = MeshSliceRequest::from_xds_node(node_id.to_string(), namespace)
            // The workload SPIFFE (from `Node.metadata`) takes precedence over
            // the `node_id`-derived one so Sidecar narrowing / the local-inbound
            // view are computed for the right workload even with a hostname node.
            .with_workload_spiffe_id(
                self.workload_identities
                    .get(metadata_key)
                    .map(|entry| entry.value().clone()),
            )
            .with_waypoint_name(
                self.waypoint_names
                    .get(metadata_key)
                    .map(|entry| entry.value().clone()),
            )
            .with_cluster_domain(self.cluster_domain.clone())
            .with_enforce_sidecar_egress(self.sidecar_enforced)
            .with_sidecar_egress_dry_run(self.sidecar_enforced_dry_run)
            .with_enforce_sidecar_identity_narrowing(self.sidecar_identity_narrowing)
            .with_ambient_udp_source_scoping(scoping.ambient_udp_source_scoping)
            .with_node_waypoint_capture_scoping(scoping.node_waypoint_capture_scoping);
        let mut config = config.clone();
        config.normalize_fields();
        config.normalize_mesh_fields();
        let slice = MeshSlice::from_gateway_config(&config, request);
        translate_mesh_slice_to_snapshot(&slice)
    }

    fn snapshot_for_config(&self, node_id: &str, config: &GatewayConfig) -> Arc<XdsSnapshot> {
        // Non-stream helper for tests and one-off callers. ADS streams carry
        // XdsStreamConfig so request/ACK cache hits do not rehash config.
        let fingerprint = config_fingerprint(config);
        self.snapshot_for_config_with_fingerprint(node_id, node_id, config, &fingerprint)
    }

    fn snapshot_for_stream_config(
        &self,
        node_id: &str,
        stream_config: &XdsStreamConfig,
    ) -> Arc<XdsSnapshot> {
        self.snapshot_for_stream_config_with_cache_key(node_id, node_id, stream_config)
    }

    fn snapshot_for_stream_config_with_cache_key(
        &self,
        cache_key: &str,
        node_id: &str,
        stream_config: &XdsStreamConfig,
    ) -> Arc<XdsSnapshot> {
        self.snapshot_for_config_with_fingerprint(
            cache_key,
            node_id,
            &stream_config.config,
            &stream_config.fingerprint,
        )
    }

    fn snapshot_for_config_with_fingerprint(
        &self,
        cache_key: &str,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
    ) -> Arc<XdsSnapshot> {
        if let Some(snapshot) = self
            .snapshot_cache
            .get_if_fingerprint(cache_key, fingerprint)
        {
            return snapshot;
        }

        let next = self.rebuild_snapshot_from_config_for_node(cache_key, node_id, config);
        self.snapshot_cache.insert_with_fingerprint_for_key(
            cache_key.to_string(),
            next,
            fingerprint.clone(),
        )
    }

    fn invalidate_snapshot_for_config_update(&self, node_id: &str) {
        self.snapshot_cache.remove(node_id);
    }

    fn reconcile_node_metadata(
        &self,
        state_key: &str,
        metadata: crate::xds::carrier::XdsNodeMetadata,
    ) -> bool {
        // Snapshot the scoping flags BEFORE the string fields are moved out of
        // `metadata` below.
        let next_scoping = XdsNodeScoping::from(&metadata);
        let identity_changed = Self::reconcile_optional_string_state(
            &self.workload_identities,
            state_key,
            metadata.workload_spiffe_id,
        );
        let waypoint_changed = Self::reconcile_optional_string_state(
            &self.waypoint_names,
            state_key,
            metadata.waypoint_name,
        );
        // Both cross-namespace inventory flags reconcile as ONE value: the two
        // select different inventories, so recording only one would leave the
        // other's snapshot stale (a NodeWaypoint would keep serving a slice
        // built with no capture inventory).
        let scoping_changed = if next_scoping.is_default() {
            self.node_scoping.remove(state_key).is_some()
        } else {
            self.node_scoping
                .insert(state_key.to_string(), next_scoping)
                != Some(next_scoping)
        };
        if identity_changed || waypoint_changed || scoping_changed {
            self.invalidate_snapshot_for_config_update(state_key);
        }
        identity_changed || waypoint_changed || scoping_changed
    }

    fn reconcile_optional_string_state(
        values: &DashMap<String, String>,
        key: &str,
        value: Option<String>,
    ) -> bool {
        match value.filter(|value| !value.trim().is_empty()) {
            Some(value) => {
                values.insert(key.to_string(), value.clone()).as_deref() != Some(value.as_str())
            }
            None => values.remove(key).is_some(),
        }
    }

    fn waypoint_name_for_state_key(&self, state_key: &str) -> Option<String> {
        self.waypoint_names
            .get(state_key)
            .map(|entry| entry.value().clone())
    }

    fn node_scoping_for_state_key(&self, state_key: &str) -> XdsNodeScoping {
        self.node_scoping
            .get(state_key)
            .map(|entry| *entry.value())
            .unwrap_or_default()
    }

    fn stream_guard(&self, permit: XdsStreamPermit) -> XdsStreamGuard {
        XdsStreamGuard::new(
            permit,
            self.snapshot_cache.clone(),
            self.nonce_tracker.clone(),
            self.workload_identities.clone(),
            self.waypoint_names.clone(),
            self.node_scoping.clone(),
        )
    }

    fn sotw_response(
        &self,
        snapshot: &XdsSnapshot,
        subscription: &XdsSubscription,
    ) -> DiscoveryResponse {
        self.sotw_response_with_nonce_key(snapshot, subscription, &snapshot.node_id)
    }

    fn sotw_response_with_nonce_key(
        &self,
        snapshot: &XdsSnapshot,
        subscription: &XdsSubscription,
        nonce_node_key: &str,
    ) -> DiscoveryResponse {
        let nonce = self.nonce_tracker.issue_nonce(
            nonce_node_key,
            &subscription.type_url,
            &snapshot.version,
        );
        DiscoveryResponse {
            version_info: snapshot.version.clone(),
            resources: snapshot
                .filtered_resources(
                    &subscription.type_url,
                    &subscription.resource_names,
                    subscription.wildcard,
                )
                .into_iter()
                .map(|resource| resource.to_any())
                .collect(),
            canary: false,
            type_url: subscription.type_url.clone(),
            nonce,
            control_plane: Some(ControlPlane {
                identifier: format!("ferrum-edge/{FERRUM_VERSION}"),
            }),
        }
    }

    fn delta_response(
        &self,
        snapshot: &XdsSnapshot,
        previous: Option<&XdsSnapshot>,
        subscription: &XdsSubscription,
        initial_resource_versions: &HashMap<String, String>,
        explicitly_subscribed_names: &[String],
        explicitly_unsubscribed_names: &[String],
    ) -> DeltaDiscoveryResponse {
        self.delta_response_with_nonce_key(
            snapshot,
            previous,
            subscription,
            initial_resource_versions,
            explicitly_subscribed_names,
            explicitly_unsubscribed_names,
            &snapshot.node_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn delta_response_with_nonce_key(
        &self,
        snapshot: &XdsSnapshot,
        previous: Option<&XdsSnapshot>,
        subscription: &XdsSubscription,
        initial_resource_versions: &HashMap<String, String>,
        explicitly_subscribed_names: &[String],
        explicitly_unsubscribed_names: &[String],
        nonce_node_key: &str,
    ) -> DeltaDiscoveryResponse {
        let nonce = self.nonce_tracker.issue_nonce(
            nonce_node_key,
            &subscription.type_url,
            &snapshot.version,
        );
        let candidates = snapshot.filtered_resources(
            &subscription.type_url,
            &subscription.resource_names,
            subscription.wildcard,
        );
        // True delta semantics — only include resources that have CHANGED
        // since the client's last-known state, plus any resource the client
        // explicitly re-subscribed to (so a re-subscribe always re-flows a
        // fresh copy even if unchanged). The wire-byte reduction is the
        // point of delta xDS; sending unchanged resources on every snapshot
        // turn defeats the protocol's purpose.
        //
        // "Client's last-known state" is either:
        //   1. `initial_resource_versions` — the client's per-resource
        //      version map, sent in the first delta request after a
        //      reconnect; or
        //   2. the server-side `previous` snapshot, when we know what the
        //      client ACKed last for this type URL over this stream.
        //
        // If neither source has the resource, treat it as new and include
        // it. `resource.version` is always server-computed (see
        // `per_resource_version`); a client-supplied version in
        // `initial_resource_versions` can only suppress its own delivery by
        // claiming a value that the server independently re-derives from
        // current bytes, so a spoofed claim is at worst a self-DoS. On the
        // previous-ACKed-snapshot path, the `value` byte-equality check is a
        // defensive guard against the 64-bit truncation in the per-resource
        // hash.
        let explicit_wildcard_subscribe =
            explicitly_subscribed_names.iter().any(|name| name == "*");
        let explicit_subscribe_set: HashSet<&str> = explicitly_subscribed_names
            .iter()
            .map(String::as_str)
            .filter(|name| *name != "*")
            .collect();
        let previous_resources_by_name =
            previous_resources_indexed(previous, &subscription.type_url);
        let resources: Vec<_> = candidates
            .into_iter()
            .filter(|resource| {
                if explicit_wildcard_subscribe
                    || explicit_subscribe_set.contains(resource.name.as_str())
                {
                    return true;
                }
                if let Some(client_version) = initial_resource_versions.get(&resource.name)
                    && client_version == &resource.version
                {
                    return false;
                }
                if let Some(prev_resource) = previous_resources_by_name.get(resource.name.as_str())
                    && prev_resource.version == resource.version
                    && prev_resource.value == resource.value
                {
                    return false;
                }
                true
            })
            .collect();
        let current_names: HashSet<String> = snapshot
            .resources(&subscription.type_url)
            .iter()
            .map(|r| r.name.clone())
            .collect();
        let mut removed_resources = if initial_resource_versions.is_empty() {
            previous
                .map(|prev| prev.removed_resource_names(snapshot, &subscription.type_url))
                .unwrap_or_default()
        } else {
            let mut removed: Vec<String> = initial_resource_versions
                .keys()
                .filter(|name| !current_names.contains(*name))
                .cloned()
                .collect();
            removed.sort();
            removed.dedup();
            removed
        };
        if !subscription.wildcard && !removed_resources.is_empty() {
            if subscription.resource_names.is_empty() {
                removed_resources.clear();
            } else {
                let wanted: HashSet<&str> = subscription
                    .resource_names
                    .iter()
                    .map(String::as_str)
                    .collect();
                removed_resources.retain(|name| wanted.contains(name.as_str()));
            }
        }
        let response_resource_names: HashSet<&str> = resources
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        for name in explicitly_subscribed_names
            .iter()
            .chain(explicitly_unsubscribed_names)
        {
            if name == "*" || response_resource_names.contains(name.as_str()) {
                continue;
            }
            removed_resources.push(name.clone());
        }
        removed_resources.sort();
        removed_resources.dedup();
        DeltaDiscoveryResponse {
            system_version_info: snapshot.version.clone(),
            resources: resources
                .into_iter()
                .map(|resource| resource.to_delta_resource())
                .collect(),
            type_url: subscription.type_url.clone(),
            nonce,
            removed_resources,
        }
    }

    fn sotw_responses_for_subscriptions(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
    ) -> Vec<DiscoveryResponse> {
        let config = self.config.load_full();
        self.sotw_responses_for_subscriptions_from_config(node_id, subscriptions, config.as_ref())
    }

    fn sotw_responses_for_subscriptions_from_config(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
    ) -> Vec<DiscoveryResponse> {
        let previous = self.snapshot_cache.get(node_id);
        self.sotw_responses_for_subscriptions_from_config_with_previous(
            node_id,
            subscriptions,
            config,
            previous.as_deref(),
        )
        .1
    }

    fn sotw_responses_for_subscriptions_from_config_with_previous(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DiscoveryResponse>) {
        let fingerprint = config_fingerprint(config);
        self.sotw_responses_for_subscriptions_from_config_with_fingerprint(
            node_id,
            node_id,
            subscriptions,
            config,
            &fingerprint,
            previous,
        )
    }

    fn sotw_responses_for_stream_config_with_previous(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DiscoveryResponse>) {
        self.sotw_responses_for_stream_config_with_previous_key(
            node_id,
            node_id,
            subscriptions,
            stream_config,
            previous,
        )
    }

    fn sotw_responses_for_stream_config_with_previous_key(
        &self,
        cache_key: &str,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DiscoveryResponse>) {
        self.sotw_responses_for_subscriptions_from_config_with_fingerprint(
            cache_key,
            node_id,
            subscriptions,
            &stream_config.config,
            &stream_config.fingerprint,
            previous,
        )
    }

    fn sotw_responses_for_subscriptions_from_config_with_fingerprint(
        &self,
        cache_key: &str,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DiscoveryResponse>) {
        let snapshot =
            self.snapshot_for_config_with_fingerprint(cache_key, node_id, config, fingerprint);
        let force_required_refresh = required_mesh_slice_resources_changed(previous, &snapshot);
        let responses = subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous, &snapshot, subscription)
                    || (force_required_refresh
                        && is_required_mesh_slice_sotw_type_url(&subscription.type_url))
            })
            .map(|subscription| {
                self.sotw_response_with_nonce_key(&snapshot, subscription, cache_key)
            })
            .collect();
        (snapshot, responses)
    }

    fn sotw_response_for_request(
        &self,
        node_id: &str,
        config: &GatewayConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<(Arc<XdsSnapshot>, DiscoveryResponse)> {
        let fingerprint = config_fingerprint(config);
        self.sotw_response_for_request_with_fingerprint(
            node_id,
            node_id,
            config,
            &fingerprint,
            subscriptions,
            request,
        )
    }

    fn sotw_response_for_stream_request(
        &self,
        node_id: &str,
        stream_config: &XdsStreamConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<(Arc<XdsSnapshot>, DiscoveryResponse)> {
        self.sotw_response_for_stream_request_key(
            node_id,
            node_id,
            stream_config,
            subscriptions,
            request,
        )
    }

    fn sotw_response_for_stream_request_key(
        &self,
        cache_key: &str,
        node_id: &str,
        stream_config: &XdsStreamConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<(Arc<XdsSnapshot>, DiscoveryResponse)> {
        self.sotw_response_for_request_with_fingerprint(
            cache_key,
            node_id,
            &stream_config.config,
            &stream_config.fingerprint,
            subscriptions,
            request,
        )
    }

    fn sotw_response_for_request_with_fingerprint(
        &self,
        cache_key: &str,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<(Arc<XdsSnapshot>, DiscoveryResponse)> {
        if !request.response_nonce.is_empty() {
            match self.record_sotw_ack(cache_key, request) {
                AckOutcome::Acked => debug!(
                    node = %redacted_identifier(node_id),
                    type_url = %request.type_url,
                    "xDS ACK accepted"
                ),
                AckOutcome::Nacked { message } => {
                    warn!(
                        node = %redacted_identifier(node_id),
                        type_url = %request.type_url,
                        error = %message,
                        "xDS NACK received"
                    );
                }
                outcome => {
                    warn!(
                        node = %redacted_identifier(node_id),
                        type_url = %request.type_url,
                        outcome = ?outcome,
                        "xDS ACK ignored"
                    );
                }
            }
        }

        let previous_subscription = subscriptions.get(&request.type_url).cloned();
        let subscription = build_sotw_subscription(
            previous_subscription.as_ref(),
            node_id,
            &request.type_url,
            &request.resource_names,
        );
        let resource_names_changed = previous_subscription
            .as_ref()
            .is_none_or(|previous| previous != &subscription);
        subscriptions.insert(request.type_url.clone(), subscription.clone());
        if should_send_sotw_response(request, resource_names_changed) {
            let snapshot =
                self.snapshot_for_config_with_fingerprint(cache_key, node_id, config, fingerprint);
            if !request.response_nonce.is_empty()
                && !subscription_change_affects_resources(
                    &snapshot,
                    previous_subscription.as_ref(),
                    &subscription,
                )
            {
                return None;
            }
            let response = self.sotw_response_with_nonce_key(&snapshot, &subscription, cache_key);
            Some((snapshot, response))
        } else {
            None
        }
    }

    fn delta_response_for_stream_request(
        &self,
        node_id: &str,
        stream_config: &XdsStreamConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DeltaDiscoveryRequest,
        previous: Option<&XdsSnapshot>,
    ) -> Option<(Arc<XdsSnapshot>, DeltaDiscoveryResponse)> {
        let _ = self.record_and_log_delta_ack(node_id, request);
        self.delta_response_for_stream_request_without_ack(
            node_id,
            stream_config,
            subscriptions,
            request,
            previous,
        )
    }

    fn delta_response_for_stream_request_without_ack(
        &self,
        node_id: &str,
        stream_config: &XdsStreamConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DeltaDiscoveryRequest,
        previous: Option<&XdsSnapshot>,
    ) -> Option<(Arc<XdsSnapshot>, DeltaDiscoveryResponse)> {
        self.delta_response_for_stream_request_without_ack_key(
            node_id,
            node_id,
            stream_config,
            subscriptions,
            request,
            previous,
        )
    }

    fn delta_response_for_stream_request_without_ack_key(
        &self,
        cache_key: &str,
        node_id: &str,
        stream_config: &XdsStreamConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DeltaDiscoveryRequest,
        previous: Option<&XdsSnapshot>,
    ) -> Option<(Arc<XdsSnapshot>, DeltaDiscoveryResponse)> {
        self.delta_response_for_request_with_fingerprint_without_ack(
            cache_key,
            node_id,
            &stream_config.config,
            &stream_config.fingerprint,
            subscriptions,
            request,
            previous,
        )
    }

    fn delta_response_for_request_with_fingerprint(
        &self,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DeltaDiscoveryRequest,
        previous: Option<&XdsSnapshot>,
    ) -> Option<(Arc<XdsSnapshot>, DeltaDiscoveryResponse)> {
        let _ = self.record_and_log_delta_ack(node_id, request);
        self.delta_response_for_request_with_fingerprint_without_ack(
            node_id,
            node_id,
            config,
            fingerprint,
            subscriptions,
            request,
            previous,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn delta_response_for_request_with_fingerprint_without_ack(
        &self,
        cache_key: &str,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DeltaDiscoveryRequest,
        previous: Option<&XdsSnapshot>,
    ) -> Option<(Arc<XdsSnapshot>, DeltaDiscoveryResponse)> {
        let previous_subscription = subscriptions.get(&request.type_url);
        let (subscription, resource_names_changed, explicit_subscription_request) =
            build_delta_subscription(
                previous_subscription,
                node_id,
                &request.type_url,
                &request.resource_names_subscribe,
                &request.resource_names_unsubscribe,
            );
        subscriptions.insert(request.type_url.clone(), subscription.clone());
        if should_send_delta_response(
            request,
            resource_names_changed,
            explicit_subscription_request,
        ) {
            let snapshot =
                self.snapshot_for_config_with_fingerprint(cache_key, node_id, config, fingerprint);
            let response = self.delta_response_with_nonce_key(
                &snapshot,
                previous,
                &subscription,
                &request.initial_resource_versions,
                &request.resource_names_subscribe,
                &request.resource_names_unsubscribe,
                cache_key,
            );
            Some((snapshot, response))
        } else {
            None
        }
    }

    fn record_and_log_delta_ack(
        &self,
        node_id: &str,
        request: &DeltaDiscoveryRequest,
    ) -> Option<AckOutcome> {
        if request.response_nonce.is_empty() {
            return None;
        }
        let outcome = self.record_delta_ack(node_id, request);
        match &outcome {
            AckOutcome::Acked | AckOutcome::VersionDrift { .. } => debug!(
                node = %redacted_identifier(node_id),
                type_url = %request.type_url,
                "xDS delta ACK accepted"
            ),
            AckOutcome::Nacked { message } => {
                warn!(
                    node = %redacted_identifier(node_id),
                    type_url = %request.type_url,
                    error = %message,
                    "xDS delta NACK received"
                );
            }
            outcome => {
                warn!(
                    node = %redacted_identifier(node_id),
                    type_url = %request.type_url,
                    outcome = ?outcome,
                    "xDS delta ACK ignored"
                );
            }
        }
        Some(outcome)
    }

    fn delta_responses_for_subscriptions(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
    ) -> Vec<DeltaDiscoveryResponse> {
        let config = self.config.load_full();
        self.delta_responses_for_subscriptions_from_config(node_id, subscriptions, config.as_ref())
    }

    fn delta_responses_for_subscriptions_from_config(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
    ) -> Vec<DeltaDiscoveryResponse> {
        let previous = self.snapshot_cache.get(node_id);
        self.delta_responses_for_subscriptions_from_config_with_previous(
            node_id,
            subscriptions,
            config,
            previous.as_deref(),
        )
        .1
    }

    fn delta_responses_for_subscriptions_from_config_with_previous(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        let fingerprint = config_fingerprint(config);
        self.delta_responses_for_subscriptions_from_config_with_fingerprint(
            node_id,
            node_id,
            subscriptions,
            config,
            &fingerprint,
            previous,
        )
    }

    fn delta_responses_for_stream_config_with_previous(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        self.delta_responses_for_stream_config_with_previous_key(
            node_id,
            node_id,
            subscriptions,
            stream_config,
            previous,
        )
    }

    fn delta_responses_for_stream_config_with_previous_key(
        &self,
        cache_key: &str,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        self.delta_responses_for_subscriptions_from_config_with_fingerprint(
            cache_key,
            node_id,
            subscriptions,
            &stream_config.config,
            &stream_config.fingerprint,
            previous,
        )
    }

    fn delta_responses_for_stream_config_with_previous_by_type(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous_by_type: &HashMap<String, Arc<XdsSnapshot>>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        self.delta_responses_for_stream_config_with_previous_by_type_key(
            node_id,
            node_id,
            subscriptions,
            stream_config,
            previous_by_type,
        )
    }

    fn delta_responses_for_stream_config_with_previous_by_type_key(
        &self,
        cache_key: &str,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        stream_config: &XdsStreamConfig,
        previous_by_type: &HashMap<String, Arc<XdsSnapshot>>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        let snapshot =
            self.snapshot_for_stream_config_with_cache_key(cache_key, node_id, stream_config);
        let responses = subscriptions
            .values()
            .filter_map(|subscription| {
                let previous = previous_by_type
                    .get(&subscription.type_url)
                    .map(Arc::as_ref);
                subscription_resources_changed(previous, &snapshot, subscription).then(|| {
                    self.delta_response_with_nonce_key(
                        &snapshot,
                        previous,
                        subscription,
                        &HashMap::new(),
                        &[],
                        &[],
                        cache_key,
                    )
                })
            })
            .collect();
        (snapshot, responses)
    }

    fn delta_responses_for_subscriptions_from_config_with_fingerprint(
        &self,
        cache_key: &str,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        let snapshot =
            self.snapshot_for_config_with_fingerprint(cache_key, node_id, config, fingerprint);
        let responses = subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous, &snapshot, subscription)
            })
            .map(|subscription| {
                self.delta_response_with_nonce_key(
                    &snapshot,
                    previous,
                    subscription,
                    &HashMap::new(),
                    &[],
                    &[],
                    cache_key,
                )
            })
            .collect();
        (snapshot, responses)
    }

    fn record_sotw_ack(&self, node_id: &str, request: &DiscoveryRequest) -> AckOutcome {
        let error_message = request
            .error_detail
            .as_ref()
            .filter(|detail| detail.code != 0 || !detail.message.is_empty())
            .map(|detail| detail.message.as_str());
        self.nonce_tracker.record_response(
            node_id,
            &request.type_url,
            &request.response_nonce,
            &request.version_info,
            error_message,
        )
    }

    fn record_delta_ack(&self, node_id: &str, request: &DeltaDiscoveryRequest) -> AckOutcome {
        let error_message = request
            .error_detail
            .as_ref()
            .filter(|detail| detail.code != 0 || !detail.message.is_empty())
            .map(|detail| detail.message.as_str());
        self.nonce_tracker.record_response(
            node_id,
            &request.type_url,
            &request.response_nonce,
            "",
            error_message,
        )
    }

    fn apply_update_to_stream_config(
        stream_config: &mut GatewayConfig,
        update: &ConfigUpdate,
    ) -> bool {
        match update.update_type {
            0 => match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                Ok(mut config) => {
                    config.normalize_fields();
                    *stream_config = config;
                    true
                }
                Err(err) => {
                    warn!("Failed to deserialize full config for xDS stream: {}", err);
                    false
                }
            },
            1 => match serde_json::from_str::<crate::config::db_loader::IncrementalResult>(
                &update.config_json,
            ) {
                Ok(delta) => {
                    apply_incremental_to_config_snapshot(stream_config, delta);
                    stream_config.normalize_fields();
                    true
                }
                Err(err) => {
                    warn!("Failed to deserialize delta config for xDS stream: {}", err);
                    false
                }
            },
            update_type => {
                warn!("Ignoring unknown xDS config update type: {}", update_type);
                false
            }
        }
    }

    fn catch_up_pending_updates(
        &self,
        updates: &mut broadcast::Receiver<ConfigUpdate>,
        stream_config: &mut XdsStreamConfig,
        namespace: &str,
        waypoint_name: Option<String>,
        scoping: XdsNodeScoping,
    ) {
        // Catch-up runs on the request path before a stream has emitted its
        // first response. We intentionally do not invalidate the per-node
        // snapshot cache here: the next snapshot lookup compares the updated
        // XdsStreamConfig fingerprint and rebuilds on mismatch. The live
        // update branches below still invalidate explicitly because they may
        // already have sent a cached snapshot to this node.
        loop {
            match updates.try_recv() {
                Ok(update) => {
                    self.apply_xds_update_to_stream_config(
                        stream_config,
                        &update,
                        namespace,
                        waypoint_name.clone(),
                        scoping,
                    );
                }
                Err(broadcast::error::TryRecvError::Empty) => return,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!(
                        "xDS ADS stream lagged by {} config updates while catching up; using current shared snapshot",
                        n
                    );
                    self.refresh_stream_config_from_current(
                        stream_config,
                        namespace,
                        waypoint_name.clone(),
                        scoping,
                    );
                }
                Err(broadcast::error::TryRecvError::Closed) => return,
            }
        }
    }
}

fn ensure_supported_type_url(type_url: &str) -> Result<(), Status> {
    if type_url.is_empty() {
        return Err(Status::invalid_argument("xDS type_url is required"));
    }
    if !super::translator::XDS_TYPE_URLS.contains(&type_url) {
        return Err(Status::invalid_argument(format!(
            "unsupported xDS type_url: {type_url}"
        )));
    }
    Ok(())
}

fn enforce_subscription_limits(
    subscriptions: &HashMap<String, XdsSubscription>,
    type_url: &str,
    resource_name_count: usize,
) -> Result<(), Status> {
    if !subscriptions.contains_key(type_url) && subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_STREAM
    {
        return Err(Status::resource_exhausted(format!(
            "xDS subscription limit exceeded (max {MAX_SUBSCRIPTIONS_PER_STREAM})"
        )));
    }
    if resource_name_count > MAX_RESOURCE_NAMES_PER_REQUEST {
        return Err(Status::resource_exhausted(format!(
            "xDS resource name limit exceeded (max {MAX_RESOURCE_NAMES_PER_REQUEST})"
        )));
    }
    Ok(())
}

/// Structured warning for a rejected ADS request.
///
/// The node id is redacted to a non-reversible digest: it is client-supplied,
/// so logging it raw would let an authenticated peer inject arbitrary bytes
/// into the CP's log stream and inflate log volume (issue #3741).
fn warn_xds_request_rejected(
    method: &'static str,
    namespace: &str,
    node_id: &str,
    type_url: &str,
    resource_name_count: usize,
    status: &Status,
) {
    warn!(
        method,
        namespace,
        node = %redacted_identifier(node_id),
        type_url,
        resource_name_count,
        status_code = ?status.code(),
        status_message = %status.message(),
        "xDS request rejected"
    );
}

fn config_fingerprint(config: &GatewayConfig) -> XdsConfigFingerprint {
    // This serializes the full GatewayConfig, including HashMap fields whose
    // iteration order is process-local. That is fine for the in-memory xDS
    // snapshot cache: fingerprints only need to be stable within one process
    // lifetime, and a restart starts with an empty cache anyway. Do not reuse
    // this helper for persisted cross-process cache keys without canonicalizing
    // map order first.
    let config_bytes = match serde_json::to_vec(config) {
        Ok(bytes) => bytes,
        Err(error) => {
            let error = error.to_string();
            return fingerprint_bytes([b"full-config-error".as_slice(), error.as_bytes()]);
        }
    };
    // `MeshConfig.node_waypoint_assertors` is deliberately `serde(skip)` so it
    // never rides raw ConfigSync `GatewayConfig` JSON, but xDS CP filtering
    // stores it in the in-process filtered config before snapshot translation.
    // Include it here so off-visible source-waypoint inventory changes still
    // invalidate the stream/snapshot cache.
    let assertor_bytes = match config
        .mesh
        .as_ref()
        .map(|mesh| serde_json::to_vec(&mesh.node_waypoint_assertors))
        .transpose()
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(error) => {
            let error = error.to_string();
            return fingerprint_bytes([b"full-config-runtime-error".as_slice(), error.as_bytes()]);
        }
    };
    fingerprint_bytes([
        b"full-config".as_slice(),
        config_bytes.as_slice(),
        b"node-waypoint-assertors".as_slice(),
        assertor_bytes.as_slice(),
    ])
}

fn fingerprint_bytes<const N: usize>(parts: [&[u8]; N]) -> XdsConfigFingerprint {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0xff]);
    }
    let digest = hex::encode(hasher.finalize());
    XdsConfigFingerprint::new(digest[..16].to_string())
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for XdsAdsServer {
    type StreamAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;

    async fn stream_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        let identity = match self.verify_jwt_metadata(request.metadata(), request.extensions()) {
            Ok(identity) => identity,
            Err(status) => {
                warn!(
                    method = "xDS.StreamAggregatedResources",
                    status_code = ?status.code(),
                    status_message = %status.message(),
                    "xDS stream authentication rejected"
                );
                CpGrpcServer::audit_tenant_subscription(
                    "xDS.StreamAggregatedResources",
                    "",
                    "",
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };
        let allowed = identity.allowed_namespaces;
        let stream_principal_key = principal_key(&identity.subject);
        let stream_namespace = match self.resolve_xds_namespace(&allowed) {
            Ok(namespace) => namespace,
            Err(status) => {
                warn!(
                    method = "xDS.StreamAggregatedResources",
                    status_code = ?status.code(),
                    status_message = %status.message(),
                    "xDS stream namespace resolution rejected"
                );
                CpGrpcServer::audit_tenant_subscription(
                    "xDS.StreamAggregatedResources",
                    "",
                    "",
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };
        // Reserve aggregate capacity BEFORE the relay task, the response
        // channel, the broadcast subscription, and the filtered config snapshot
        // exist. A refusal here allocates none of them (issue #3741).
        let permit = self.reserve_stream_capacity(
            "xDS.StreamAggregatedResources",
            &stream_namespace,
            &stream_principal_key,
        )?;

        CpGrpcServer::audit_tenant_subscription(
            "xDS.StreamAggregatedResources",
            "",
            &stream_namespace,
            "success",
            "",
        );

        let mut requests = request.into_inner();
        let mut server = self.clone();
        server.ambient_udp_source_bearer_namespaces = allowed.effective_namespaces().cloned();
        let mut updates = server.updates_for_namespace(&stream_namespace);
        let (tx, rx) = mpsc::channel(server.stream_channel_capacity);
        let max_node_id_bytes = server.admission.limits().max_node_id_bytes;
        let first_request_timeout = server.admission.limits().first_request_timeout;

        tokio::spawn(async move {
            // Owns the permit for the whole stream lifetime; its `Drop` is the
            // single release path for every normal, error, cancellation, abort,
            // and shutdown exit below.
            let mut stream_guard = server.stream_guard(permit);
            let first_request_deadline = tokio::time::sleep(first_request_timeout);
            tokio::pin!(first_request_deadline);
            let mut node_id: Option<String> = None;
            let mut node_state_key: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config = XdsStreamConfig::new(server.filter_config_for_xds_request(
                server.config.load_full().as_ref(),
                &stream_namespace,
                None,
                XdsNodeScoping::default(),
            ));
            let mut last_snapshot: Option<Arc<XdsSnapshot>> = None;
            loop {
                tokio::select! {
                    // Bounds a stalled stream that holds a task, a channel, a
                    // config snapshot, and a permit without ever identifying a
                    // node. Disabled the moment a node id is resolved, and
                    // disabled entirely when the deadline is configured to `0`.
                    _ = &mut first_request_deadline,
                        if node_id.is_none() && !first_request_timeout.is_zero() =>
                    {
                        record_xds_admission_rejection(
                            "xDS.StreamAggregatedResources",
                            &stream_namespace,
                            None,
                            XdsAdmissionRejection::FirstRequestTimeout,
                        );
                        let _ = tx
                            .send(Err(XdsAdmissionRejection::FirstRequestTimeout.into_status()))
                            .await;
                        return;
                    }
                    // The outbound response receiver is gone (tonic ended the
                    // RPC, or an in-process consumer dropped the stream):
                    // nothing can observe further work, so exit and let the
                    // guard release the permit, node-scoped state, broadcast
                    // receiver, and channel.
                    _ = tx.closed() => {
                        return;
                    }
                    maybe_request = requests.next() => {
                        let Some(request) = maybe_request else {
                            return;
                        };
                        let request = match request {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = tx.send(Err(Status::internal(format!("ADS request stream error: {err}")))).await;
                                return;
                            }
                        };
                        // Validate the client-supplied `Node.id` BEFORE it is
                        // cloned, stored in any map, folded into a state key, or
                        // reaches a log line.
                        let requested_id = match requested_node_id(
                            request.node.as_ref(),
                            max_node_id_bytes,
                        ) {
                            Ok(requested) => requested,
                            Err(rejection) => {
                                record_xds_admission_rejection(
                                    "xDS.StreamAggregatedResources",
                                    &stream_namespace,
                                    None,
                                    rejection,
                                );
                                let _ = tx.send(Err(rejection.into_status())).await;
                                return;
                            }
                        };
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            requested_id,
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                // First-message `Node` omission is the only
                                // resolve failure while no node is established
                                // yet. Route it through the same bounded
                                // rejection accounting as an explicitly present
                                // empty id (counted above via
                                // `requested_node_id`) — never double-count.
                                if node_id.is_none() {
                                    record_xds_admission_rejection(
                                        "xDS.StreamAggregatedResources",
                                        &stream_namespace,
                                        None,
                                        XdsAdmissionRejection::NodeIdEmpty,
                                    );
                                }
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        let current_state_key = node_state_key.clone().unwrap_or_else(|| {
                            xds_state_key(
                                &stream_namespace,
                                &stream_principal_key,
                                &current_node_id,
                            )
                        });
                        if node_id.is_none() {
                            if let Err(rejection) =
                                stream_guard.set_node_state_key(&current_state_key)
                            {
                                record_xds_admission_rejection(
                                    "xDS.StreamAggregatedResources",
                                    &stream_namespace,
                                    Some(&current_node_id),
                                    rejection,
                                );
                                let _ = tx.send(Err(rejection.into_status())).await;
                                return;
                            }
                            node_id = Some(current_node_id.clone());
                            node_state_key = Some(current_state_key.clone());
                        };

                        // Reconcile this node's workload identity from
                        // `Node.metadata` before any snapshot is built, so Sidecar
                        // narrowing / the local-inbound view are computed for the
                        // right workload. A snapshot is cached by (node id, config
                        // fingerprint) only, so any identity CHANGE must drop the
                        // cached slice. ACKs carry `node: None` and don't reach
                        // here, preserving the identity mid-stream.
                        if let Some(node) = request.node.as_ref()
                            && server.reconcile_node_metadata(
                                &current_state_key,
                                crate::xds::carrier::decode_node_metadata(&node.metadata),
                            )
                        {
                            server.refresh_stream_config_from_current(
                                &mut stream_config,
                                &stream_namespace,
                                server.waypoint_name_for_state_key(&current_state_key),
                                server.node_scoping_for_state_key(&current_state_key),
                            );
                        }

                        if let Err(status) = ensure_supported_type_url(&request.type_url) {
                            warn_xds_request_rejected(
                                "xDS.StreamAggregatedResources",
                                &stream_namespace,
                                &current_node_id,
                                &request.type_url,
                                request.resource_names.len(),
                                &status,
                            );
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if let Err(status) = enforce_subscription_limits(
                            &subscriptions,
                            &request.type_url,
                            request.resource_names.len(),
                        ) {
                            warn_xds_request_rejected(
                                "xDS.StreamAggregatedResources",
                                &stream_namespace,
                                &current_node_id,
                                &request.type_url,
                                request.resource_names.len(),
                                &status,
                            );
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(
                                &mut updates,
                                &mut stream_config,
                                &stream_namespace,
                                server.waypoint_name_for_state_key(&current_state_key),
                                server.node_scoping_for_state_key(&current_state_key),
                            );
                        }

                        let send_failed = if let Some((snapshot, response)) = server.sotw_response_for_stream_request_key(
                            &current_state_key,
                            &current_node_id,
                            &stream_config,
                            &mut subscriptions,
                            &request,
                        )
                        {
                            last_snapshot = Some(snapshot);
                            tx.send(Ok(response)).await.is_err()
                        } else {
                            false
                        };
                        if send_failed {
                            return;
                        }
                    }
                    update = updates.recv() => {
                        match update {
                            Ok(update) => {
                                let Some(current_node_id) = node_id.as_ref() else {
                                    server.apply_pre_node_xds_update_to_stream_config(
                                        &mut stream_config,
                                        &update,
                                        &stream_namespace,
                                    );
                                    continue;
                                };
                                let Some(current_state_key) = node_state_key.as_ref() else {
                                    server.apply_pre_node_xds_update_to_stream_config(
                                        &mut stream_config,
                                        &update,
                                        &stream_namespace,
                                    );
                                    continue;
                                };
                                if !server.apply_xds_update_to_stream_config(
                                    &mut stream_config,
                                    &update,
                                    &stream_namespace,
                                    server.waypoint_name_for_state_key(current_state_key),
                                    server.node_scoping_for_state_key(current_state_key),
                                ) {
                                    continue;
                                }
                                server.invalidate_snapshot_for_config_update(current_state_key);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.sotw_responses_for_stream_config_with_previous_key(
                                    current_state_key,
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                    last_snapshot.as_deref(),
                                );
                                last_snapshot = Some(snapshot);
                                for response in responses {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS ADS stream lagged by {} config updates; sending fresh snapshots", n);
                                let Some(current_node_id) = node_id.as_ref() else {
                                    server.refresh_stream_config_from_current(
                                        &mut stream_config,
                                        &stream_namespace,
                                        None,
                                        XdsNodeScoping::default(),
                                    );
                                    continue;
                                };
                                let Some(current_state_key) = node_state_key.as_ref() else {
                                    server.refresh_stream_config_from_current(
                                        &mut stream_config,
                                        &stream_namespace,
                                        None,
                                        XdsNodeScoping::default(),
                                    );
                                    continue;
                                };
                                server.refresh_stream_config_from_current(
                                    &mut stream_config,
                                    &stream_namespace,
                                    server.waypoint_name_for_state_key(current_state_key),
                                    server.node_scoping_for_state_key(current_state_key),
                                );
                                server.invalidate_snapshot_for_config_update(current_state_key);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.sotw_responses_for_stream_config_with_previous_key(
                                    current_state_key,
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                    last_snapshot.as_deref(),
                                );
                                last_snapshot = Some(snapshot);
                                for response in responses {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delta_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        let identity = match self.verify_jwt_metadata(request.metadata(), request.extensions()) {
            Ok(identity) => identity,
            Err(status) => {
                warn!(
                    method = "xDS.DeltaAggregatedResources",
                    status_code = ?status.code(),
                    status_message = %status.message(),
                    "xDS stream authentication rejected"
                );
                CpGrpcServer::audit_tenant_subscription(
                    "xDS.DeltaAggregatedResources",
                    "",
                    "",
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };
        let allowed = identity.allowed_namespaces;
        let stream_principal_key = principal_key(&identity.subject);
        let stream_namespace = match self.resolve_xds_namespace(&allowed) {
            Ok(namespace) => namespace,
            Err(status) => {
                warn!(
                    method = "xDS.DeltaAggregatedResources",
                    status_code = ?status.code(),
                    status_message = %status.message(),
                    "xDS stream namespace resolution rejected"
                );
                CpGrpcServer::audit_tenant_subscription(
                    "xDS.DeltaAggregatedResources",
                    "",
                    "",
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };
        // Delta reserves from the SAME controller as SotW, so splitting a flood
        // across the two ADS methods (or across connections) cannot double a
        // client's budget (issue #3741).
        let permit = self.reserve_stream_capacity(
            "xDS.DeltaAggregatedResources",
            &stream_namespace,
            &stream_principal_key,
        )?;

        CpGrpcServer::audit_tenant_subscription(
            "xDS.DeltaAggregatedResources",
            "",
            &stream_namespace,
            "success",
            "",
        );

        let mut requests = request.into_inner();
        let mut server = self.clone();
        server.ambient_udp_source_bearer_namespaces = allowed.effective_namespaces().cloned();
        let mut updates = server.updates_for_namespace(&stream_namespace);
        let (tx, rx) = mpsc::channel(server.stream_channel_capacity);
        let max_node_id_bytes = server.admission.limits().max_node_id_bytes;
        let first_request_timeout = server.admission.limits().first_request_timeout;

        tokio::spawn(async move {
            // Owns the permit for the whole stream lifetime; its `Drop` is the
            // single release path for every normal, error, cancellation, abort,
            // and shutdown exit below.
            let mut stream_guard = server.stream_guard(permit);
            let first_request_deadline = tokio::time::sleep(first_request_timeout);
            tokio::pin!(first_request_deadline);
            let mut node_id: Option<String> = None;
            let mut node_state_key: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config = XdsStreamConfig::new(server.filter_config_for_xds_request(
                server.config.load_full().as_ref(),
                &stream_namespace,
                None,
                XdsNodeScoping::default(),
            ));
            let mut last_sent_snapshot_by_type: HashMap<String, Arc<XdsSnapshot>> = HashMap::new();
            let mut last_accepted_snapshot_by_type: HashMap<String, Arc<XdsSnapshot>> =
                HashMap::new();
            loop {
                tokio::select! {
                    _ = &mut first_request_deadline,
                        if node_id.is_none() && !first_request_timeout.is_zero() =>
                    {
                        record_xds_admission_rejection(
                            "xDS.DeltaAggregatedResources",
                            &stream_namespace,
                            None,
                            XdsAdmissionRejection::FirstRequestTimeout,
                        );
                        let _ = tx
                            .send(Err(XdsAdmissionRejection::FirstRequestTimeout.into_status()))
                            .await;
                        return;
                    }
                    // The outbound response receiver is gone (tonic ended the
                    // RPC, or an in-process consumer dropped the stream):
                    // nothing can observe further work, so exit and let the
                    // guard release the permit, node-scoped state, broadcast
                    // receiver, and channel.
                    _ = tx.closed() => {
                        return;
                    }
                    maybe_request = requests.next() => {
                        let Some(request) = maybe_request else {
                            return;
                        };
                        let request = match request {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = tx.send(Err(Status::internal(format!("Delta ADS request stream error: {err}")))).await;
                                return;
                            }
                        };
                        let requested_id = match requested_node_id(
                            request.node.as_ref(),
                            max_node_id_bytes,
                        ) {
                            Ok(requested) => requested,
                            Err(rejection) => {
                                record_xds_admission_rejection(
                                    "xDS.DeltaAggregatedResources",
                                    &stream_namespace,
                                    None,
                                    rejection,
                                );
                                let _ = tx.send(Err(rejection.into_status())).await;
                                return;
                            }
                        };
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            requested_id,
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                // First-message `Node` omission is the only
                                // resolve failure while no node is established
                                // yet. Route it through the same bounded
                                // rejection accounting as an explicitly present
                                // empty id (counted above via
                                // `requested_node_id`) — never double-count.
                                if node_id.is_none() {
                                    record_xds_admission_rejection(
                                        "xDS.DeltaAggregatedResources",
                                        &stream_namespace,
                                        None,
                                        XdsAdmissionRejection::NodeIdEmpty,
                                    );
                                }
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        let current_state_key = node_state_key.clone().unwrap_or_else(|| {
                            xds_state_key(
                                &stream_namespace,
                                &stream_principal_key,
                                &current_node_id,
                            )
                        });
                        if node_id.is_none() {
                            if let Err(rejection) =
                                stream_guard.set_node_state_key(&current_state_key)
                            {
                                record_xds_admission_rejection(
                                    "xDS.DeltaAggregatedResources",
                                    &stream_namespace,
                                    Some(&current_node_id),
                                    rejection,
                                );
                                let _ = tx.send(Err(rejection.into_status())).await;
                                return;
                            }
                            node_id = Some(current_node_id.clone());
                            node_state_key = Some(current_state_key.clone());
                        };

                        // Reconcile this node's workload identity from
                        // `Node.metadata` before any snapshot is built, so Sidecar
                        // narrowing / the local-inbound view are computed for the
                        // right workload. A snapshot is cached by (node id, config
                        // fingerprint) only, so any identity CHANGE must drop the
                        // cached slice. ACKs carry `node: None` and don't reach
                        // here, preserving the identity mid-stream.
                        if let Some(node) = request.node.as_ref()
                            && server.reconcile_node_metadata(
                                &current_state_key,
                                crate::xds::carrier::decode_node_metadata(&node.metadata),
                            )
                        {
                            server.refresh_stream_config_from_current(
                                &mut stream_config,
                                &stream_namespace,
                                server.waypoint_name_for_state_key(&current_state_key),
                                server.node_scoping_for_state_key(&current_state_key),
                            );
                        }

                        if let Err(status) = ensure_supported_type_url(&request.type_url) {
                            warn_xds_request_rejected(
                                "xDS.DeltaAggregatedResources",
                                &stream_namespace,
                                &current_node_id,
                                &request.type_url,
                                request.resource_names_subscribe.len(),
                                &status,
                            );
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if let Err(status) = enforce_subscription_limits(
                            &subscriptions,
                            &request.type_url,
                            request.resource_names_subscribe.len(),
                        ) {
                            warn_xds_request_rejected(
                                "xDS.DeltaAggregatedResources",
                                &stream_namespace,
                                &current_node_id,
                                &request.type_url,
                                request.resource_names_subscribe.len(),
                                &status,
                            );
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(
                                &mut updates,
                                &mut stream_config,
                                &stream_namespace,
                                server.waypoint_name_for_state_key(&current_state_key),
                                server.node_scoping_for_state_key(&current_state_key),
                            );
                        }

                        let ack_outcome = server.record_and_log_delta_ack(&current_state_key, &request);
                        remember_delta_accepted_snapshot(
                            ack_outcome.as_ref(),
                            &request.type_url,
                            &last_sent_snapshot_by_type,
                            &mut last_accepted_snapshot_by_type,
                        );
                        let previous = last_accepted_snapshot_by_type
                            .get(&request.type_url)
                            .cloned();
                        if let Some((snapshot, response)) = server.delta_response_for_stream_request_without_ack_key(
                            &current_state_key,
                            &current_node_id,
                            &stream_config,
                            &mut subscriptions,
                            &request,
                            previous.as_deref(),
                        ) {
                            let response_type_url = response.type_url.clone();
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                            last_sent_snapshot_by_type.insert(response_type_url, snapshot);
                        }
                    }
                    update = updates.recv() => {
                        match update {
                            Ok(update) => {
                                let Some(current_node_id) = node_id.as_ref() else {
                                    server.apply_pre_node_xds_update_to_stream_config(
                                        &mut stream_config,
                                        &update,
                                        &stream_namespace,
                                    );
                                    continue;
                                };
                                let Some(current_state_key) = node_state_key.as_ref() else {
                                    server.apply_pre_node_xds_update_to_stream_config(
                                        &mut stream_config,
                                        &update,
                                        &stream_namespace,
                                    );
                                    continue;
                                };
                                if !server.apply_xds_update_to_stream_config(
                                    &mut stream_config,
                                    &update,
                                    &stream_namespace,
                                    server.waypoint_name_for_state_key(current_state_key),
                                    server.node_scoping_for_state_key(current_state_key),
                                ) {
                                    continue;
                                }
                                server.invalidate_snapshot_for_config_update(current_state_key);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.delta_responses_for_stream_config_with_previous_by_type_key(
                                    current_state_key,
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                    &last_accepted_snapshot_by_type,
                                );
                                for response in responses {
                                    let response_type_url = response.type_url.clone();
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                    last_sent_snapshot_by_type
                                        .insert(response_type_url, Arc::clone(&snapshot));
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS delta ADS stream lagged by {} config updates; sending fresh snapshots", n);
                                let Some(current_node_id) = node_id.as_ref() else {
                                    server.refresh_stream_config_from_current(
                                        &mut stream_config,
                                        &stream_namespace,
                                        None,
                                        XdsNodeScoping::default(),
                                    );
                                    continue;
                                };
                                let Some(current_state_key) = node_state_key.as_ref() else {
                                    server.refresh_stream_config_from_current(
                                        &mut stream_config,
                                        &stream_namespace,
                                        None,
                                        XdsNodeScoping::default(),
                                    );
                                    continue;
                                };
                                server.refresh_stream_config_from_current(
                                    &mut stream_config,
                                    &stream_namespace,
                                    server.waypoint_name_for_state_key(current_state_key),
                                    server.node_scoping_for_state_key(current_state_key),
                                );
                                server.invalidate_snapshot_for_config_update(current_state_key);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.delta_responses_for_stream_config_with_previous_by_type_key(
                                    current_state_key,
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                    &last_accepted_snapshot_by_type,
                                );
                                for response in responses {
                                    let response_type_url = response.type_url.clone();
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                    last_sent_snapshot_by_type
                                        .insert(response_type_url, Arc::clone(&snapshot));
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Extract and validate the `Node.id` carried on one ADS request.
///
/// Returns `Ok(None)` when the message carries no node (ACK/NACK follow-ups
/// legitimately omit it). An explicitly present empty id is rejected and
/// counted here. A **first-message** omission (`Ok(None)` while no node is
/// established yet) is rejected and counted at the resolve site in both SotW
/// and Delta relays, using the same `node_id_empty` reason without
/// double-counting this explicit-empty path. A **present** id is validated
/// against the configured contract before it is cloned, stored, keyed, or
/// logged, so a hostile value never reaches a map or a log line (issue #3741).
fn requested_node_id(
    node: Option<&super::proto::Node>,
    max_node_id_bytes: usize,
) -> Result<Option<&str>, XdsAdmissionRejection> {
    let Some(node) = node else {
        return Ok(None);
    };
    if node.id.is_empty() {
        return Err(XdsAdmissionRejection::NodeIdEmpty);
    }
    crate::xds::admission::validate_node_id(&node.id, max_node_id_bytes)?;
    Ok(Some(node.id.as_str()))
}

fn resolve_stream_node_id(
    current: Option<&str>,
    requested: Option<&str>,
) -> Result<String, Status> {
    match (current, requested) {
        (None, Some(requested)) => Ok(requested.to_string()),
        (None, None) => Err(Status::invalid_argument(
            XdsAdmissionRejection::NodeIdEmpty.status_message(),
        )),
        (Some(current), None) => Ok(current.to_string()),
        (Some(current), Some(requested)) if requested == current => Ok(requested.to_string()),
        // Never echo either id: both are client-supplied. The redacted digests
        // still let an operator correlate the two values across log lines.
        (Some(current), Some(requested)) => Err(Status::invalid_argument(format!(
            "xDS Node.id cannot change on an established stream: {} -> {}",
            redacted_identifier(current),
            redacted_identifier(requested)
        ))),
    }
}

/// Log and count one ADS admission rejection.
///
/// `namespace` is the CP-resolved tenant (server-side, bounded by CP
/// configuration), never caller-supplied text. The node id is reduced to a
/// non-reversible digest, and the metric carries only the bounded
/// [`XdsAdmissionRejection::metric_reason`] label — no node id, principal,
/// subject, token, or SPIFFE URI reaches `/metrics` or the log.
fn record_xds_admission_rejection(
    method: &'static str,
    namespace: &str,
    node_id: Option<&str>,
    rejection: XdsAdmissionRejection,
) {
    warn!(
        method,
        namespace,
        node = %node_id.map(redacted_identifier).unwrap_or_else(|| "unresolved".to_string()),
        reason = rejection.metric_reason(),
        "Rejecting xDS ADS stream at admission"
    );
    crate::plugins::mesh::prometheus_helpers::increment_xds_stream_rejected();
    crate::plugins::mesh::prometheus_helpers::increment_xds_stream_admission_rejection(
        rejection.metric_reason(),
    );
}

fn remember_delta_accepted_snapshot(
    ack_outcome: Option<&AckOutcome>,
    type_url: &str,
    last_sent_by_type: &HashMap<String, Arc<XdsSnapshot>>,
    last_accepted_by_type: &mut HashMap<String, Arc<XdsSnapshot>>,
) {
    if !matches!(
        ack_outcome,
        Some(AckOutcome::Acked | AckOutcome::VersionDrift { .. })
    ) {
        return;
    }
    if let Some(snapshot) = last_sent_by_type.get(type_url) {
        last_accepted_by_type.insert(type_url.to_string(), Arc::clone(snapshot));
    }
}

fn previous_resources_indexed<'a>(
    previous: Option<&'a XdsSnapshot>,
    type_url: &str,
) -> HashMap<&'a str, &'a super::snapshot::XdsResource> {
    previous
        .map(|prev| {
            prev.resources(type_url)
                .iter()
                .map(|resource| (resource.name.as_str(), resource))
                .collect()
        })
        .unwrap_or_default()
}

/// SotW type URLs that make up a coherent mesh slice on the DP. Mirrors the DP
/// client's `REQUIRED_MESH_SLICE_TYPE_URLS`; keep the two in sync.
const REQUIRED_MESH_SLICE_SOTW_TYPE_URLS: [&str; 5] = [
    super::translator::CDS_TYPE_URL,
    super::translator::EDS_TYPE_URL,
    super::translator::LDS_TYPE_URL,
    super::translator::RDS_TYPE_URL,
    super::translator::ECDS_TYPE_URL,
];

fn is_required_mesh_slice_sotw_type_url(type_url: &str) -> bool {
    REQUIRED_MESH_SLICE_SOTW_TYPE_URLS.contains(&type_url)
}

/// True when any required mesh-slice type's resources changed between the
/// previous and current snapshot, regardless of which types the DP currently
/// subscribes to.
///
/// Coherence is a property of the snapshot, not of the current subscription
/// set. A policy-only ECDS change — or any required-type change that lands
/// during a startup/reconnect race before the DP has registered its full
/// required subscription set — must still force every subscribed required type
/// to be re-sent at the new snapshot version. Filtering to the currently
/// subscribed types would miss an ECDS-only change while the DP has only CDS
/// subscribed, leaving the DP's coherent required-version gate stuck (e.g.
/// CDS=vN while a later ECDS request lands ECDS=vN+1) until an unrelated change
/// or reconnect, hanging `wait_for_first_slice()`.
fn required_mesh_slice_resources_changed(
    previous: Option<&XdsSnapshot>,
    snapshot: &XdsSnapshot,
) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    REQUIRED_MESH_SLICE_SOTW_TYPE_URLS.iter().any(|type_url| {
        !resources_equal_ignoring_version(
            previous.resources(type_url),
            snapshot.resources(type_url),
        )
    })
}

fn subscription_resources_changed(
    previous: Option<&XdsSnapshot>,
    snapshot: &XdsSnapshot,
    subscription: &XdsSubscription,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let previous_resources = previous.filtered_resources(
        &subscription.type_url,
        &subscription.resource_names,
        subscription.wildcard,
    );
    let next_resources = snapshot.filtered_resources(
        &subscription.type_url,
        &subscription.resource_names,
        subscription.wildcard,
    );
    !resources_equal_ignoring_version(&previous_resources, &next_resources)
}

fn subscription_change_affects_resources(
    snapshot: &XdsSnapshot,
    previous: Option<&XdsSubscription>,
    next: &XdsSubscription,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let previous_resources = snapshot.filtered_resources(
        &previous.type_url,
        &previous.resource_names,
        previous.wildcard,
    );
    let next_resources =
        snapshot.filtered_resources(&next.type_url, &next.resource_names, next.wildcard);
    !resources_equal_ignoring_version(&previous_resources, &next_resources)
}

fn resources_equal_ignoring_version(
    left: &[super::snapshot::XdsResource],
    right: &[super::snapshot::XdsResource],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.name == right.name && left.type_url == right.type_url && left.value == right.value
        })
}

fn build_sotw_subscription(
    previous: Option<&XdsSubscription>,
    node_id: &str,
    type_url: &str,
    resource_names: &[String],
) -> XdsSubscription {
    let has_wildcard = resource_names.iter().any(|name| name == "*")
        || (resource_names.is_empty() && previous.is_none_or(|subscription| subscription.wildcard));
    let mut resource_names = resource_names
        .iter()
        .filter(|name| name.as_str() != "*")
        .cloned()
        .collect::<Vec<_>>();
    resource_names.sort();
    resource_names.dedup();

    XdsSubscription {
        node_id: node_id.to_string(),
        type_url: type_url.to_string(),
        resource_names,
        wildcard: has_wildcard,
    }
}

fn build_delta_subscription(
    previous: Option<&XdsSubscription>,
    node_id: &str,
    type_url: &str,
    resource_names_subscribe: &[String],
    resource_names_unsubscribe: &[String],
) -> (XdsSubscription, bool, bool) {
    let explicit_subscription_request =
        !resource_names_subscribe.is_empty() || !resource_names_unsubscribe.is_empty();
    let mut resource_names = previous
        .map(|subscription| subscription.resource_names.clone())
        .unwrap_or_default();
    let mut wildcard = previous
        .map(|subscription| subscription.wildcard)
        .unwrap_or(resource_names_subscribe.is_empty() && resource_names_unsubscribe.is_empty());

    for name in resource_names_subscribe {
        if name == "*" {
            wildcard = true;
            continue;
        }
        if !resource_names.contains(name) {
            resource_names.push(name.clone());
        }
    }
    if !resource_names_subscribe.is_empty() {
        resource_names.sort();
    }
    if !resource_names_unsubscribe.is_empty() {
        let removed: HashSet<&str> = resource_names_unsubscribe
            .iter()
            .map(String::as_str)
            .collect();
        if removed.contains("*") {
            wildcard = false;
        }
        resource_names.retain(|name| !removed.contains(name.as_str()));
    }

    let subscription = XdsSubscription {
        node_id: node_id.to_string(),
        type_url: type_url.to_string(),
        resource_names,
        wildcard,
    };
    let changed = previous.is_none_or(|previous| previous != &subscription);
    (subscription, changed, explicit_subscription_request)
}

fn should_send_sotw_response(request: &DiscoveryRequest, resource_names_changed: bool) -> bool {
    request.response_nonce.is_empty() || resource_names_changed
}

fn should_send_delta_response(
    request: &DeltaDiscoveryRequest,
    resource_names_changed: bool,
    explicit_subscription_request: bool,
) -> bool {
    request.response_nonce.is_empty()
        || resource_names_changed
        || explicit_subscription_request
        || !request.initial_resource_versions.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_loader::IncrementalResult;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AppProtocol, MeshConfig, MeshPolicy, MeshService, MeshSidecar, MeshSidecarEgress,
        MeshWaypointBinding, MeshWaypointServiceRef, MtlsMode, PeerAuthentication, PolicyScope,
        ServicePort, Workload, WorkloadSelector,
    };
    use chrono::{TimeZone, Utc};
    use prost::Message;

    fn gateway_config_with_service(include_service: bool, version_second: u32) -> GatewayConfig {
        if include_service {
            gateway_config_with_named_service("api", version_second)
        } else {
            GatewayConfig {
                mesh: Some(Box::new(MeshConfig {
                    services: Vec::new(),
                    ..MeshConfig::default()
                })),
                loaded_at: Utc
                    .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                    .unwrap(),
                ..GatewayConfig::default()
            }
        }
    }

    fn gateway_config_with_named_service(name: &str, version_second: u32) -> GatewayConfig {
        gateway_config_with_services(&[name], version_second)
    }

    fn gateway_config_with_services(names: &[&str], version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: names.iter().map(|name| mesh_service(name)).collect(),
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

    fn gateway_config_with_service_and_peer_auth(version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![mesh_service("api")],
                peer_authentications: vec![PeerAuthentication {
                    name: "strict".to_string(),
                    namespace: "default".to_string(),
                    scope: None,
                    selector: None,
                    mtls_mode: MtlsMode::Strict,
                    port_overrides: HashMap::new(),
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

    fn mesh_service(name: &str) -> MeshService {
        mesh_service_in_namespace("default", name)
    }

    fn mesh_service_in_namespace(namespace: &str, name: &str) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn waypoint_gateway_config(service_name: &str, version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![mesh_service_in_namespace("default", service_name)],
                waypoint_bindings: vec![MeshWaypointBinding {
                    name: "waypoint".to_string(),
                    namespace: "infra".to_string(),
                    waypoint_for: "service".to_string(),
                    gateway_class_name: None,
                    services: vec![MeshWaypointServiceRef {
                        namespace: "default".to_string(),
                        name: service_name.to_string(),
                    }],
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

    fn cluster_names(response: &DiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                super::super::proto::Cluster::decode(resource.value.as_slice())
                    .expect("cluster resource should decode")
                    .name
            })
            .collect()
    }

    fn route_names(response: &DiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                super::super::proto::RouteConfiguration::decode(resource.value.as_slice())
                    .expect("route resource should decode")
                    .name
            })
            .collect()
    }

    fn delta_cluster_names(response: &DeltaDiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                let resource = resource
                    .resource
                    .as_ref()
                    .expect("delta resource should carry an Any payload");
                super::super::proto::Cluster::decode(resource.value.as_slice())
                    .expect("cluster resource should decode")
                    .name
            })
            .collect()
    }

    fn delta_route_names(response: &DeltaDiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                let resource = resource
                    .resource
                    .as_ref()
                    .expect("delta resource should carry an Any payload");
                super::super::proto::RouteConfiguration::decode(resource.value.as_slice())
                    .expect("route resource should decode")
                    .name
            })
            .collect()
    }

    fn snapshot_cluster_names(snapshot: &XdsSnapshot) -> Vec<String> {
        snapshot
            .resources(super::super::translator::CDS_TYPE_URL)
            .iter()
            .map(|resource| {
                super::super::proto::Cluster::decode(resource.value.as_slice())
                    .expect("cluster resource should decode")
                    .name
            })
            .collect()
    }

    fn empty_delta(version_second: u32) -> IncrementalResult {
        IncrementalResult {
            added_or_modified_proxies: Vec::new(),
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: Vec::new(),
            sequence_cursor: 0,
            poll_timestamp: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
        }
    }

    fn config_update(update_type: i32, config_json: String, version: String) -> ConfigUpdate {
        ConfigUpdate {
            update_type,
            config_json,
            version,
            timestamp: 0,
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            trust_bundles_json: String::new(),
            heartbeat: false,
            heartbeat_negotiated: false,
        }
    }

    fn full_config_update(config: &GatewayConfig) -> ConfigUpdate {
        config_update(
            0,
            serde_json::to_string(config).expect("full config should serialize"),
            config.loaded_at.to_rfc3339(),
        )
    }

    fn delta_config_update(delta: &IncrementalResult) -> ConfigUpdate {
        config_update(
            1,
            serde_json::to_string(delta).expect("delta config should serialize"),
            delta.poll_timestamp.to_rfc3339(),
        )
    }

    fn test_server(config: GatewayConfig) -> XdsAdsServer {
        let (tx, _) = broadcast::channel(1);
        XdsAdsServer::new(
            Arc::new(ArcSwap::from_pointee(config)),
            tx,
            "x".repeat(32),
            "issuer".to_string(),
            "default".to_string(),
            32,
        )
    }

    fn test_server_with_sidecar_enforcement(
        config: GatewayConfig,
        sidecar_enforced: bool,
    ) -> XdsAdsServer {
        let (tx, _) = broadcast::channel(1);
        XdsAdsServer::with_sidecar_enforcement(
            Arc::new(ArcSwap::from_pointee(config)),
            tx,
            "x".repeat(32),
            "issuer".to_string(),
            "default".to_string(),
            32,
            sidecar_enforced,
        )
    }

    fn cds_subscription() -> HashMap<String, XdsSubscription> {
        wildcard_subscription(super::super::translator::CDS_TYPE_URL)
    }

    fn wildcard_subscription(type_url: &str) -> HashMap<String, XdsSubscription> {
        HashMap::from([(
            type_url.to_string(),
            XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: type_url.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
        )])
    }

    fn required_core_and_ecds_subscriptions() -> HashMap<String, XdsSubscription> {
        let mut subscriptions = wildcard_subscription(super::super::translator::CDS_TYPE_URL);
        subscriptions.extend(wildcard_subscription(
            super::super::translator::ECDS_TYPE_URL,
        ));
        subscriptions
    }

    fn test_guard(
        controller: &XdsAdmissionController,
        snapshot_cache: Arc<XdsSnapshotCache>,
        nonce_tracker: Arc<XdsNonceTracker>,
    ) -> XdsStreamGuard {
        let permit = controller
            .reserve_stream("ferrum", "principal-a")
            .expect("aggregate capacity available");
        XdsStreamGuard::new(
            permit,
            snapshot_cache,
            nonce_tracker,
            Arc::new(DashMap::new()),
            Arc::new(DashMap::new()),
            Arc::new(DashMap::new()),
        )
    }

    #[test]
    fn stream_guard_set_node_state_key_propagates_ceiling_error() {
        let snapshot_cache = Arc::new(XdsSnapshotCache::new());
        let nonce_tracker = Arc::new(XdsNonceTracker::new());
        let controller = XdsAdmissionController::new(XdsAdmissionLimits {
            max_streams_per_node: 1,
            ..XdsAdmissionLimits::default()
        });

        let mut first = test_guard(&controller, snapshot_cache.clone(), nonce_tracker.clone());
        first
            .set_node_state_key("node-a")
            .expect("first stream for node admitted");

        let mut second = test_guard(&controller, snapshot_cache.clone(), nonce_tracker.clone());
        let rejection = second
            .set_node_state_key("node-a")
            .expect_err("second concurrent stream rejected by guard");
        assert_eq!(rejection, XdsAdmissionRejection::NodeStreams);
        assert_eq!(
            rejection.into_status().code(),
            tonic::Code::ResourceExhausted
        );

        // The rejected guard never registered, so dropping it must not free the
        // first stream's slot.
        drop(second);
        assert_eq!(
            controller.node_streams("node-a"),
            1,
            "a failed registration must neither consume nor free a slot"
        );

        // Releasing the first (registered) guard frees the only slot.
        drop(first);
        assert_eq!(controller.node_streams("node-a"), 0);
        assert_eq!(controller.active_nodes(), 0);
        assert_eq!(controller.active_streams(), 0);
        let mut third = test_guard(&controller, snapshot_cache, nonce_tracker);
        assert!(
            third.set_node_state_key("node-a").is_ok(),
            "after the registered stream drops, the slot is available"
        );
    }

    #[test]
    fn resolve_stream_node_id_rejects_mid_stream_mutation() {
        assert_eq!(
            resolve_stream_node_id(None, Some("node-a")).unwrap(),
            "node-a"
        );
        assert_eq!(
            resolve_stream_node_id(Some("node-a"), None).unwrap(),
            "node-a"
        );
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-a")).is_ok());
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-b")).is_err());
        let omitted = resolve_stream_node_id(None, None).expect_err("first-message Node omission");
        assert_eq!(omitted.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            omitted.message(),
            XdsAdmissionRejection::NodeIdEmpty.status_message()
        );
        assert!(
            !omitted.message().contains("node-"),
            "omission rejection must never echo caller data"
        );
    }

    #[test]
    fn ensure_supported_type_url_rejects_unknown_values() {
        assert!(ensure_supported_type_url(super::super::translator::CDS_TYPE_URL).is_ok());
        assert!(ensure_supported_type_url("type.googleapis.com/example.Unknown").is_err());
    }

    #[test]
    fn enforce_subscription_limits_rejects_new_type_url_beyond_limit() {
        let mut subscriptions = HashMap::new();
        for idx in 0..MAX_SUBSCRIPTIONS_PER_STREAM {
            subscriptions.insert(
                format!("type.googleapis.com/envoy.test.{idx}"),
                XdsSubscription {
                    node_id: "node-a".to_string(),
                    type_url: format!("type.googleapis.com/envoy.test.{idx}"),
                    resource_names: Vec::new(),
                    wildcard: true,
                },
            );
        }
        assert!(
            enforce_subscription_limits(&subscriptions, "type.googleapis.com/envoy.new", 0)
                .is_err()
        );
        assert!(
            enforce_subscription_limits(&subscriptions, "type.googleapis.com/envoy.test.0", 0)
                .is_ok()
        );
    }

    #[test]
    fn xds_sidecar_enforcement_filters_snapshot_services() {
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![mesh_service("api"), mesh_service("checkout")],
                sidecars: vec![MeshSidecar {
                    name: "default-scope".to_string(),
                    namespace: "default".to_string(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![MeshSidecarEgress {
                        hosts: vec!["./api".to_string()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: None,
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            ..GatewayConfig::default()
        };
        let server = test_server_with_sidecar_enforcement(config.clone(), true);

        let snapshot = server.snapshot_for_config("xds-node", &config);

        assert_eq!(
            snapshot_cluster_names(&snapshot),
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn xds_prefilter_preserves_sidecar_admitted_cross_namespace_services() {
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![
                    mesh_service("api"),
                    mesh_service_in_namespace("beta", "checkout"),
                    mesh_service_in_namespace("gamma", "payments"),
                ],
                sidecars: vec![MeshSidecar {
                    name: "beta-egress".to_string(),
                    namespace: "default".to_string(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![MeshSidecarEgress {
                        hosts: vec!["beta/*".to_string()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: None,
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            ..GatewayConfig::default()
        };
        let server = test_server_with_sidecar_enforcement(config.clone(), true);

        let filtered = server.filter_config_for_xds_request(
            &config,
            "default",
            None,
            XdsNodeScoping::default(),
        );
        let mesh = filtered.mesh.as_ref().expect("mesh should remain");
        assert!(
            mesh.services
                .iter()
                .any(|service| service.namespace == "beta" && service.name == "checkout"),
            "xDS prefilter must keep sidecar-admitted beta service before snapshot slicing"
        );
        assert!(
            !mesh
                .services
                .iter()
                .any(|service| service.namespace == "gamma"),
            "xDS prefilter must still drop namespaces not admitted by the Sidecar"
        );

        let snapshot = server.snapshot_for_config("xds-node", &filtered);
        assert_eq!(
            snapshot_cluster_names(&snapshot),
            vec!["cluster/beta/checkout/8080".to_string()]
        );
    }

    #[test]
    fn xds_config_fingerprint_includes_runtime_node_waypoint_assertors() {
        let mut left = gateway_config_with_service(true, 0);
        let mut right = left.clone();
        let waypoint_a =
            SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/node-waypoint-a").unwrap();
        let waypoint_b =
            SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/node-waypoint-b").unwrap();
        left.mesh
            .as_mut()
            .expect("mesh should exist")
            .node_waypoint_assertors = vec![waypoint_a];
        right
            .mesh
            .as_mut()
            .expect("mesh should exist")
            .node_waypoint_assertors = vec![waypoint_b];

        assert_eq!(
            serde_json::to_vec(&left).expect("serialized config"),
            serde_json::to_vec(&right).expect("serialized config"),
            "runtime-only assertors are intentionally skipped from raw GatewayConfig JSON"
        );
        assert_ne!(
            config_fingerprint(&left),
            config_fingerprint(&right),
            "xDS fingerprints must still invalidate when only runtime assertors change"
        );
    }

    #[test]
    fn xds_updates_subscribe_to_authenticated_namespace_channel() {
        let broadcasts = Arc::new(NamespaceBroadcasts::new(4));
        let server = test_server(gateway_config_with_service(true, 0))
            .with_namespace_broadcasts(broadcasts.clone());
        let mut tenant_a_updates = server.updates_for_namespace("tenant-a");
        let mut tenant_b_updates = server.updates_for_namespace("tenant-b");
        let update = full_config_update(&gateway_config_with_service(false, 1));

        broadcasts
            .sender_for("tenant-b")
            .send(update.clone())
            .expect("tenant-b update should broadcast");

        assert!(matches!(
            tenant_a_updates.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(
            tenant_b_updates
                .try_recv()
                .expect("tenant-b update should arrive")
                .version,
            update.version
        );
    }

    #[test]
    fn xds_state_keys_partition_same_node_id_by_namespace() {
        let server = test_server(gateway_config_with_service(true, 0));
        let stream_config = XdsStreamConfig::new(gateway_config_with_service(true, 0));
        let tenant_a_key = xds_state_key("tenant-a", "principal-a", "node-a");
        let tenant_b_key = xds_state_key("tenant-b", "principal-a", "node-a");

        let tenant_a_snapshot = server.snapshot_for_stream_config_with_cache_key(
            &tenant_a_key,
            "node-a",
            &stream_config,
        );
        let tenant_b_snapshot = server.snapshot_for_stream_config_with_cache_key(
            &tenant_b_key,
            "node-a",
            &stream_config,
        );

        assert_ne!(tenant_a_key, tenant_b_key);
        assert_eq!(tenant_a_snapshot.node_id, "node-a");
        assert_eq!(tenant_b_snapshot.node_id, "node-a");
        assert!(server.snapshot_cache.get(&tenant_a_key).is_some());
        assert!(server.snapshot_cache.get(&tenant_b_key).is_some());
        assert!(server.snapshot_cache.get("node-a").is_none());
    }

    #[test]
    fn xds_node_metadata_uses_authenticated_state_key_for_snapshot_build() {
        let config = waypoint_gateway_config("reviews", 0);
        let server = test_server(config.clone());
        let tenant_key = xds_state_key("infra", "principal-a", "node-a");
        let bare_node_key = "node-a";

        assert!(server.reconcile_node_metadata(
            &tenant_key,
            crate::xds::carrier::XdsNodeMetadata {
                workload_spiffe_id: None,
                waypoint_name: Some("waypoint".to_string()),
                ambient_udp_source_scoping: false,
                node_waypoint_capture_scoping: false,
            },
        ));
        assert!(server.waypoint_names.get(&tenant_key).is_some());
        assert!(server.waypoint_names.get(bare_node_key).is_none());

        let filtered = server.filter_config_for_xds_request(
            &config,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping::default(),
        );
        let stream_config = XdsStreamConfig::new(filtered);
        let snapshot = server.snapshot_for_stream_config_with_cache_key(
            &tenant_key,
            bare_node_key,
            &stream_config,
        );

        assert_eq!(snapshot.node_id, bare_node_key);
        assert_eq!(
            snapshot_cluster_names(&snapshot),
            vec!["cluster/default/reviews/8080".to_string()]
        );
    }

    #[test]
    fn xds_prefilter_preserves_waypoint_udp_source_policies_when_metadata_enables_scoping() {
        let mut config = waypoint_gateway_config("reviews", 0);
        let mesh = config.mesh.as_mut().expect("mesh should exist");
        mesh.workloads.push(Workload {
            spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/clients/sa/client")
                .expect("source SPIFFE ID"),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "client".to_string())]),
                namespace: Some("clients".to_string()),
            },
            service_name: "client".to_string(),
            service_namespace: None,
            addresses: vec!["10.2.0.11".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("source trust domain"),
            namespace: "clients".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("client".to_string()),
            pod_uid: Some("16b2c3d4-9dad-11d1-80b4-00c04fd430c8".to_string()),
            node_waypoint: None,
            remote_provenance: false,
        });
        mesh.mesh_policies.push(MeshPolicy {
            name: "clients-source-policy".to_string(),
            namespace: "clients".to_string(),
            scope: PolicyScope::Namespace {
                namespace: "clients".to_string(),
            },
            rules: Vec::new(),
        });
        let source_scope =
            CpScope::Set(HashSet::from(["infra".to_string(), "clients".to_string()]));
        let server = test_server(config.clone()).with_scope(source_scope.clone());
        let mut bearer_multi_namespace_server =
            test_server(config.clone()).with_scope(source_scope.clone());
        bearer_multi_namespace_server.ambient_udp_source_bearer_namespaces =
            Some(HashSet::from(["infra".to_string(), "clients".to_string()]));
        let mut bearer_restricted_server = test_server(config.clone()).with_scope(source_scope);
        bearer_restricted_server.ambient_udp_source_bearer_namespaces =
            Some(HashSet::from(["infra".to_string()]));

        let without_udp = server.filter_config_for_xds_request(
            &config,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping::default(),
        );
        let with_udp = server.filter_config_for_xds_request(
            &config,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping {
                ambient_udp_source_scoping: true,
                node_waypoint_capture_scoping: false,
            },
        );
        let bearer_restricted = bearer_restricted_server.filter_config_for_xds_request(
            &config,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping {
                ambient_udp_source_scoping: true,
                node_waypoint_capture_scoping: false,
            },
        );
        let bearer_multi_namespace = bearer_multi_namespace_server.filter_config_for_xds_request(
            &config,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping {
                ambient_udp_source_scoping: true,
                node_waypoint_capture_scoping: false,
            },
        );

        assert!(
            without_udp
                .mesh
                .expect("mesh should remain")
                .mesh_policies
                .is_empty()
        );
        assert_eq!(
            with_udp
                .mesh
                .expect("mesh should remain")
                .mesh_policies
                .len(),
            1,
            "xDS prefilter must retain source policies before snapshot slicing"
        );
        assert_eq!(
            bearer_multi_namespace
                .mesh
                .expect("mesh should remain")
                .mesh_policies
                .len(),
            1,
            "xDS prefilter must retain every bearer-authorized source namespace"
        );
        let restricted_mesh = bearer_restricted.mesh.expect("mesh should remain");
        assert!(restricted_mesh.workloads.is_empty());
        assert!(restricted_mesh.mesh_policies.is_empty());
    }

    #[test]
    fn xds_namespace_broadcast_refresh_preserves_waypoint_bound_services() {
        let config = waypoint_gateway_config("reviews", 0);
        let server = test_server(config.clone())
            .with_namespace_broadcasts(Arc::new(NamespaceBroadcasts::new(4)));
        let strict_payload = CpGrpcServer::filter_config_to_namespace(&config, "infra");
        let mut stream_config = XdsStreamConfig::new(strict_payload.clone());
        let update = full_config_update(&strict_payload);

        assert!(server.apply_xds_update_to_stream_config(
            &mut stream_config,
            &update,
            "infra",
            Some("waypoint".to_string()),
            XdsNodeScoping::default(),
        ));
        let state_key = xds_state_key("infra", "principal-a", "node-a");
        server.reconcile_node_metadata(
            &state_key,
            crate::xds::carrier::XdsNodeMetadata {
                workload_spiffe_id: None,
                waypoint_name: Some("waypoint".to_string()),
                ambient_udp_source_scoping: false,
                node_waypoint_capture_scoping: false,
            },
        );
        let snapshot =
            server.snapshot_for_stream_config_with_cache_key(&state_key, "node-a", &stream_config);

        assert_eq!(
            snapshot_cluster_names(&snapshot),
            vec!["cluster/default/reviews/8080".to_string()]
        );
    }

    #[test]
    fn sotw_lag_recovery_rebuilds_and_sends_current_snapshot() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].resources.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(false, 1)));
        let recovered = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].resources.len(), 0);
        assert_ne!(recovered[0].nonce, initial[0].nonce);
    }

    #[test]
    fn sotw_update_skips_resend_when_only_loaded_at_changes() {
        // A bare `loaded_at` re-stamp with byte-identical mesh content (e.g. a
        // no-op DB re-poll) leaves every resource's bytes unchanged, so
        // content-based change detection sends nothing — no redundant SOTW
        // response (incl. the large workloads/services ECDS carriers) is
        // re-sent.
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let refreshed = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert!(
            refreshed.is_empty(),
            "a loaded_at-only bump with identical content must not re-send required mesh-slice types"
        );
    }

    #[test]
    fn sotw_policy_only_update_resends_unchanged_required_cds_for_coherence() {
        // ECDS carries mesh security policy. When a policy-only update changes
        // ECDS, subscribed required core resources are force-re-sent with the
        // new snapshot version so the DP never applies a mixed routing/policy
        // slice.
        //
        // This also covers the startup/reconnect race: the DP here has only
        // subscribed to CDS (its ECDS request has not landed yet), so the change
        // detection must inspect the whole snapshot, not just the current
        // subscription set. If CDS were left at the old version, a later initial
        // ECDS response at the new version would strand the DP at CDS=old/
        // ECDS=new and hang `wait_for_first_slice()` until an unrelated change.
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        let initial_version = initial[0].version_info.clone();

        server
            .config
            .store(Arc::new(gateway_config_with_service_and_peer_auth(1)));
        let refreshed = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(refreshed.len(), 1);
        assert_eq!(
            refreshed[0].type_url,
            super::super::translator::CDS_TYPE_URL
        );
        assert_ne!(
            refreshed[0].version_info, initial_version,
            "force-re-sent CDS must advance to the new snapshot version so a \
             later ECDS at that version converges coherently"
        );
    }

    #[test]
    fn sotw_update_skips_unchanged_non_required_effective_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = wildcard_subscription(super::super::translator::SDS_TYPE_URL);

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        assert!(initial[0].resources.is_empty());

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let unchanged = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert!(unchanged.is_empty());
    }

    #[test]
    fn sotw_policy_only_update_resends_required_core_and_ecds() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = required_core_and_ecds_subscriptions();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 2);

        server
            .config
            .store(Arc::new(gateway_config_with_service_and_peer_auth(1)));
        let refreshed = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(
            refreshed.len(),
            2,
            "policy changes must refresh subscribed required types for coherent DP apply"
        );
        assert!(
            refreshed
                .iter()
                .any(|response| response.type_url == super::super::translator::ECDS_TYPE_URL)
        );
        assert!(
            refreshed
                .iter()
                .any(|response| response.type_url == super::super::translator::CDS_TYPE_URL)
        );
        assert_eq!(refreshed[0].version_info, refreshed[1].version_info);
    }

    #[test]
    fn sotw_update_uses_broadcast_payload_before_shared_config_swap() {
        let server = test_server(gateway_config_with_named_service("old", 0));
        let subscriptions = cds_subscription();
        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(
            cluster_names(&initial[0]),
            vec!["cluster/default/old/8080".to_string()]
        );

        let mut stream_config = gateway_config_with_named_service("old", 0);
        let update_config = gateway_config_with_named_service("new", 1);
        let update = full_config_update(&update_config);

        assert!(XdsAdsServer::apply_update_to_stream_config(
            &mut stream_config,
            &update
        ));
        let responses = server.sotw_responses_for_subscriptions_from_config(
            "node-a",
            &subscriptions,
            &stream_config,
        );

        assert_eq!(responses.len(), 1);
        assert_eq!(
            cluster_names(&responses[0]),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn sotw_stream_previous_snapshot_is_not_shared_between_streams() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();
        let previous = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let first_previous = Some(previous.clone());
        let second_previous = Some(previous);
        let next_config = gateway_config_with_service(false, 1);

        let (_, first_responses) = server
            .sotw_responses_for_subscriptions_from_config_with_previous(
                "node-a",
                &subscriptions,
                &next_config,
                first_previous.as_deref(),
            );
        let (_, second_responses) = server
            .sotw_responses_for_subscriptions_from_config_with_previous(
                "node-a",
                &subscriptions,
                &next_config,
                second_previous.as_deref(),
            );

        assert_eq!(first_responses.len(), 1);
        assert_eq!(second_responses.len(), 1);
        assert!(first_responses[0].resources.is_empty());
        assert!(second_responses[0].resources.is_empty());
    }

    #[test]
    fn stream_config_delta_update_uses_broadcast_payload_version() {
        let mut stream_config = gateway_config_with_service(true, 0);
        let delta = empty_delta(42);
        let update = delta_config_update(&delta);

        assert!(XdsAdsServer::apply_update_to_stream_config(
            &mut stream_config,
            &update
        ));

        assert_eq!(stream_config.loaded_at, delta.poll_timestamp);
    }

    #[test]
    fn pending_update_before_first_sotw_request_updates_stream_config() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let mut updates = server.update_tx.subscribe();
        let new_config = gateway_config_with_named_service("new", 1);
        server
            .update_tx
            .send(full_config_update(&new_config))
            .expect("pending update should send");
        let mut stream_config = XdsStreamConfig::new(old_config);
        server.catch_up_pending_updates(
            &mut updates,
            &mut stream_config,
            "default",
            None,
            XdsNodeScoping::default(),
        );
        let mut subscriptions = HashMap::new();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["*".to_string()],
            ..DiscoveryRequest::default()
        };

        let (_, response) = server
            .sotw_response_for_stream_request(
                "node-a",
                &stream_config,
                &mut subscriptions,
                &request,
            )
            .expect("first SotW request should receive the caught-up snapshot");

        assert_eq!(
            cluster_names(&response),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn recv_update_before_first_sotw_request_updates_stream_config() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let new_config = gateway_config_with_named_service("new", 1);
        let update = full_config_update(&new_config);
        let mut stream_config = XdsStreamConfig::new(old_config);

        server.apply_pre_node_xds_update_to_stream_config(&mut stream_config, &update, "default");

        let mut subscriptions = HashMap::new();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["*".to_string()],
            ..DiscoveryRequest::default()
        };
        let (_, response) = server
            .sotw_response_for_stream_request(
                "node-a",
                &stream_config,
                &mut subscriptions,
                &request,
            )
            .expect("first SotW request should receive the pre-node update snapshot");

        assert_eq!(
            cluster_names(&response),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn pending_update_before_first_delta_request_updates_stream_config() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let mut updates = server.update_tx.subscribe();
        let new_config = gateway_config_with_named_service("new", 1);
        server
            .update_tx
            .send(full_config_update(&new_config))
            .expect("pending update should send");
        let mut stream_config = XdsStreamConfig::new(old_config);
        server.catch_up_pending_updates(
            &mut updates,
            &mut stream_config,
            "default",
            None,
            XdsNodeScoping::default(),
        );
        let request = DeltaDiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names_subscribe: vec!["*".to_string()],
            ..DeltaDiscoveryRequest::default()
        };
        let (subscription, _, _) = build_delta_subscription(
            None,
            "node-a",
            &request.type_url,
            &request.resource_names_subscribe,
            &request.resource_names_unsubscribe,
        );
        let previous = server.snapshot_cache.get("node-a");
        let snapshot = server.snapshot_for_stream_config("node-a", &stream_config);

        let response = server.delta_response(
            &snapshot,
            previous.as_deref(),
            &subscription,
            &request.initial_resource_versions,
            &request.resource_names_subscribe,
            &request.resource_names_unsubscribe,
        );

        assert_eq!(
            delta_cluster_names(&response),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn sotw_subscription_change_skips_response_when_effective_resources_match() {
        let config = gateway_config_with_service(true, 0);
        let server = test_server(config.clone());
        let mut subscriptions = cds_subscription();
        let snapshot = server.snapshot_for_config("node-a", &config);
        assert_eq!(
            snapshot
                .resources(super::super::translator::CDS_TYPE_URL)
                .len(),
            1
        );
        let name = "cluster/default/api/8080".to_string();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            response_nonce: "stale-or-unknown".to_string(),
            resource_names: vec![name.clone()],
            ..DiscoveryRequest::default()
        };

        let response =
            server.sotw_response_for_request("node-a", &config, &mut subscriptions, &request);

        assert!(response.is_none());
        let subscription = subscriptions
            .get(super::super::translator::CDS_TYPE_URL)
            .expect("subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, vec![name]);
    }

    #[test]
    fn sotw_ack_outcome_still_applies_effective_subscription_change() {
        let config = gateway_config_with_services(&["api", "admin"], 0);
        let server = test_server(config.clone());
        let mut subscriptions = cds_subscription();
        let name = "cluster/default/api/8080".to_string();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            response_nonce: "stale-or-unknown".to_string(),
            resource_names: vec![name.clone()],
            ..DiscoveryRequest::default()
        };

        let (_, response) = server
            .sotw_response_for_request("node-a", &config, &mut subscriptions, &request)
            .expect("subscription update should send the requested resource");

        let subscription = subscriptions
            .get(super::super::translator::CDS_TYPE_URL)
            .expect("subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, vec![name]);
        assert_eq!(response.resources.len(), 1);
    }

    #[test]
    fn sotw_explicit_rds_subscription_returns_only_requested_route() {
        let config = gateway_config_with_services(&["api", "admin"], 0);
        let server = test_server(config.clone());
        let mut subscriptions = HashMap::new();
        let requested = "route/default/api".to_string();
        let request = DiscoveryRequest {
            type_url: super::super::translator::RDS_TYPE_URL.to_string(),
            resource_names: vec![requested.clone()],
            ..DiscoveryRequest::default()
        };

        let (_, response) = server
            .sotw_response_for_request("node-a", &config, &mut subscriptions, &request)
            .expect("explicit RDS request should receive a response");

        let subscription = subscriptions
            .get(super::super::translator::RDS_TYPE_URL)
            .expect("RDS subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, vec![requested]);
        assert_eq!(route_names(&response), subscription.resource_names);
    }

    #[test]
    fn delta_explicit_rds_subscription_returns_only_requested_route() {
        let config = gateway_config_with_services(&["api", "admin"], 0);
        let server = test_server(config.clone());
        let stream_config = XdsStreamConfig::new(config);
        let mut subscriptions = HashMap::new();
        let requested = "route/default/api".to_string();
        let request = DeltaDiscoveryRequest {
            type_url: super::super::translator::RDS_TYPE_URL.to_string(),
            resource_names_subscribe: vec![requested.clone()],
            ..DeltaDiscoveryRequest::default()
        };

        let (_, response) = server
            .delta_response_for_stream_request(
                "node-a",
                &stream_config,
                &mut subscriptions,
                &request,
                None,
            )
            .expect("explicit RDS delta request should receive a response");

        assert_eq!(delta_route_names(&response), vec![requested]);
        assert!(response.removed_resources.is_empty());
        let subscription = subscriptions
            .get(super::super::translator::RDS_TYPE_URL)
            .expect("RDS subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, delta_route_names(&response));
    }

    #[test]
    fn delta_explicit_rds_subscription_unsubscribe_removes_route() {
        let config = gateway_config_with_services(&["api", "admin"], 0);
        let server = test_server(config.clone());
        let stream_config = XdsStreamConfig::new(config);
        let mut subscriptions = HashMap::new();
        let requested = "route/default/api".to_string();

        let subscribe_request = DeltaDiscoveryRequest {
            type_url: super::super::translator::RDS_TYPE_URL.to_string(),
            resource_names_subscribe: vec![requested.clone()],
            ..DeltaDiscoveryRequest::default()
        };
        let (subscribe_snapshot, subscribe_response) = server
            .delta_response_for_stream_request(
                "node-a",
                &stream_config,
                &mut subscriptions,
                &subscribe_request,
                None,
            )
            .expect("initial RDS subscribe should produce a response");
        assert_eq!(
            delta_route_names(&subscribe_response),
            vec![requested.clone()]
        );

        let unsubscribe_request = DeltaDiscoveryRequest {
            type_url: super::super::translator::RDS_TYPE_URL.to_string(),
            resource_names_unsubscribe: vec![requested.clone()],
            ..DeltaDiscoveryRequest::default()
        };
        let (_, unsubscribe_response) = server
            .delta_response_for_stream_request(
                "node-a",
                &stream_config,
                &mut subscriptions,
                &unsubscribe_request,
                Some(subscribe_snapshot.as_ref()),
            )
            .expect("RDS unsubscribe should produce a response");

        assert!(
            !delta_route_names(&unsubscribe_response).contains(&requested),
            "unsubscribed route should not appear in response resources"
        );
        assert_eq!(unsubscribe_response.removed_resources, vec![requested]);
        let subscription = subscriptions
            .get(super::super::translator::RDS_TYPE_URL)
            .expect("RDS subscription should still be tracked");
        assert!(!subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn sotw_request_returns_exact_snapshot_for_stream_state() {
        let config = gateway_config_with_named_service("old", 0);
        let server = test_server(config.clone());
        let mut subscriptions = HashMap::new();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["*".to_string()],
            ..DiscoveryRequest::default()
        };

        let (last_sent_snapshot, initial_response) = server
            .sotw_response_for_request("node-a", &config, &mut subscriptions, &request)
            .expect("initial SotW request should send a snapshot");
        assert_eq!(
            cluster_names(&initial_response),
            vec!["cluster/default/old/8080".to_string()]
        );

        let next_config = gateway_config_with_named_service("new", 1);
        let shared_snapshot = server.snapshot_for_config("node-a", &next_config);
        assert!(
            shared_snapshot
                .version
                .starts_with(&format!("{}:", next_config.loaded_at.to_rfc3339()))
        );

        let (_, responses) = server.sotw_responses_for_subscriptions_from_config_with_previous(
            "node-a",
            &subscriptions,
            &next_config,
            Some(last_sent_snapshot.as_ref()),
        );

        assert_eq!(responses.len(), 1);
        assert_eq!(
            cluster_names(&responses[0]),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn snapshot_cache_rebuilds_when_same_timestamp_content_changes() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let old_snapshot = server.snapshot_for_config("node-a", &old_config);
        assert_eq!(
            old_snapshot.resources(super::super::translator::CDS_TYPE_URL)[0].name,
            "cluster/default/old/8080"
        );

        let new_config = gateway_config_with_named_service("new", 0);
        let new_snapshot = server.snapshot_for_config("node-a", &new_config);

        assert_eq!(
            new_snapshot.resources(super::super::translator::CDS_TYPE_URL)[0].name,
            "cluster/default/new/8080"
        );
        assert_ne!(old_snapshot.version, new_snapshot.version);
    }

    #[test]
    fn snapshot_cache_reuses_same_config_content_across_streams() {
        let config = gateway_config_with_named_service("api", 0);
        let server = test_server(config.clone());
        let first_stream = XdsStreamConfig::new(config.clone());
        let second_stream = XdsStreamConfig::new(config);

        let first = server.snapshot_for_stream_config("node-a", &first_stream);
        let second = server.snapshot_for_stream_config("node-a", &second_stream);

        assert!(std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn snapshot_cache_rebuilds_after_stream_config_update() {
        let old_config = gateway_config_with_named_service("old", 0);
        let new_config = gateway_config_with_named_service("new", 0);
        let server = test_server(old_config.clone());
        let mut stream_config = XdsStreamConfig::new(old_config);

        let old_snapshot = server.snapshot_for_stream_config("node-a", &stream_config);
        assert!(stream_config.apply_update(&full_config_update(&new_config)));
        server.invalidate_snapshot_for_config_update("node-a");
        let new_snapshot = server.snapshot_for_stream_config("node-a", &stream_config);

        assert_eq!(
            new_snapshot.resources(super::super::translator::CDS_TYPE_URL)[0].name,
            "cluster/default/new/8080"
        );
        assert_ne!(old_snapshot.version, new_snapshot.version);
    }

    #[test]
    fn delta_lag_recovery_reports_removed_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.delta_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].resources.len(), 1);
        assert!(initial[0].removed_resources.is_empty());

        server
            .config
            .store(Arc::new(gateway_config_with_service(false, 1)));
        let recovered = server.delta_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].resources.len(), 0);
        assert_eq!(
            recovered[0].removed_resources,
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn delta_update_skips_unchanged_effective_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.delta_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let unchanged = server.delta_responses_for_subscriptions("node-a", &subscriptions);

        assert!(unchanged.is_empty());
    }

    #[test]
    fn delta_stream_previous_snapshot_is_not_shared_between_streams() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();
        let previous = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let first_previous = Some(previous.clone());
        let second_previous = Some(previous);
        let next_config = gateway_config_with_service(false, 1);

        let (_, first_responses) = server
            .delta_responses_for_subscriptions_from_config_with_previous(
                "node-a",
                &subscriptions,
                &next_config,
                first_previous.as_deref(),
            );
        let (_, second_responses) = server
            .delta_responses_for_subscriptions_from_config_with_previous(
                "node-a",
                &subscriptions,
                &next_config,
                second_previous.as_deref(),
            );

        assert_eq!(first_responses.len(), 1);
        assert_eq!(second_responses.len(), 1);
        assert!(first_responses[0].resources.is_empty());
        assert_eq!(
            first_responses[0].removed_resources,
            vec!["cluster/default/api/8080".to_string()]
        );
        assert!(second_responses[0].resources.is_empty());
        assert_eq!(
            second_responses[0].removed_resources,
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn delta_initial_resource_versions_drive_removals_even_with_cached_snapshot() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot.clone());
        let cached_previous = server.snapshot_cache.get("node-a");
        let initial_resource_versions = HashMap::from([(
            "cluster/default/stale/8080".to_string(),
            "v-old".to_string(),
        )]);

        let response = server.delta_response(
            &snapshot,
            cached_previous.as_deref(),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &initial_resource_versions,
            &[],
            &[],
        );

        assert_eq!(
            response.removed_resources,
            vec!["cluster/default/stale/8080".to_string()]
        );
    }

    #[test]
    fn delta_explicit_empty_subscription_returns_no_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: false,
            },
            &HashMap::new(),
            &[],
            &[],
        );

        assert!(response.resources.is_empty());
        assert!(response.removed_resources.is_empty());
    }

    #[test]
    fn delta_subscription_resubscribe_is_explicit_without_state_change() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["cluster/default/api/8080".to_string()],
            wildcard: false,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
            &[],
        );

        assert_eq!(subscription, previous);
        assert!(!changed);
        assert!(explicit);

        let request = DeltaDiscoveryRequest {
            response_nonce: "stale-nonce".to_string(),
            resource_names_subscribe: vec!["cluster/default/api/8080".to_string()],
            ..DeltaDiscoveryRequest::default()
        };
        assert!(should_send_delta_response(&request, changed, explicit));
    }

    #[test]
    fn sotw_empty_after_explicit_subscription_is_not_wildcard() {
        let previous = build_sotw_subscription(
            None,
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
        );
        let subscription = build_sotw_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
        );

        assert!(!subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn sotw_initial_empty_subscription_is_wildcard() {
        let subscription =
            build_sotw_subscription(None, "node-a", super::super::translator::CDS_TYPE_URL, &[]);

        assert!(subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn sotw_empty_after_explicit_wildcard_preserves_wildcard() {
        let previous = build_sotw_subscription(
            None,
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["*".to_string()],
        );
        assert!(previous.wildcard);
        assert!(previous.resource_names.is_empty());

        let subscription = build_sotw_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
        );

        assert!(subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn delta_named_subscription_keeps_existing_wildcard_until_star_unsubscribed() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: Vec::new(),
            wildcard: true,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
            &[],
        );

        assert!(changed);
        assert!(explicit);
        assert!(subscription.wildcard);
        assert_eq!(
            subscription.resource_names,
            vec!["cluster/default/api/8080".to_string()]
        );

        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&subscription),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            &["*".to_string()],
        );

        assert!(changed);
        assert!(explicit);
        assert!(!subscription.wildcard);
        assert_eq!(
            subscription.resource_names,
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn delta_initial_empty_subscription_is_wildcard() {
        let (subscription, changed, explicit) = build_delta_subscription(
            None,
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            &[],
        );

        assert!(changed);
        assert!(!explicit);
        assert!(subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn delta_explicit_missing_subscription_returns_removed_resource() {
        let server = test_server(gateway_config_with_service(false, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        let subscribed = "cluster/default/missing/8080".to_string();
        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: vec![subscribed.clone()],
                wildcard: false,
            },
            &HashMap::new(),
            std::slice::from_ref(&subscribed),
            &[],
        );

        assert!(response.resources.is_empty());
        assert_eq!(response.removed_resources, vec![subscribed]);
    }

    #[test]
    fn delta_explicit_unsubscribe_returns_removed_when_absent_from_response() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        let unsubscribed = "cluster/default/missing/8080".to_string();
        let previous_subscription = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec![unsubscribed.clone()],
            wildcard: true,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous_subscription),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            std::slice::from_ref(&unsubscribed),
        );

        assert!(changed);
        assert!(explicit);
        assert!(subscription.wildcard);
        assert!(subscription.resource_names.is_empty());

        let response = server.delta_response(
            &snapshot,
            None,
            &subscription,
            &HashMap::new(),
            &[],
            std::slice::from_ref(&unsubscribed),
        );

        assert_eq!(
            delta_cluster_names(&response),
            vec!["cluster/default/api/8080".to_string()]
        );
        assert_eq!(response.removed_resources, vec![unsubscribed]);
    }

    #[test]
    fn delta_subscription_unsubscribe_all_is_empty_not_wildcard() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["cluster/default/api/8080".to_string()],
            wildcard: false,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            &["cluster/default/api/8080".to_string()],
        );

        assert!(changed);
        assert!(explicit);
        assert!(!subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn stream_guard_cleans_node_state_when_last_stream_exits() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot);
        server
            .nonce_tracker
            .issue_nonce("node-a", super::super::translator::CDS_TYPE_URL, "v1");

        {
            let mut guard = server.stream_guard(server.test_permit());
            guard
                .set_node_state_key("node-a")
                .expect("stream registers");
            assert!(server.snapshot_cache.get("node-a").is_some());
            assert_eq!(server.nonce_tracker.len(), 1);
        }

        assert!(server.snapshot_cache.get("node-a").is_none());
        assert!(server.nonce_tracker.is_empty());
    }

    #[test]
    fn stream_guard_keeps_node_state_until_all_streams_exit() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot);
        server
            .nonce_tracker
            .issue_nonce("node-a", super::super::translator::CDS_TYPE_URL, "v1");

        let mut first = server.stream_guard(server.test_permit());
        first
            .set_node_state_key("node-a")
            .expect("first stream registers");
        let mut second = server.stream_guard(server.test_permit());
        second
            .set_node_state_key("node-a")
            .expect("second stream within default cap registers");

        drop(first);
        assert!(server.snapshot_cache.get("node-a").is_some());
        assert_eq!(server.nonce_tracker.len(), 1);

        drop(second);
        assert!(server.snapshot_cache.get("node-a").is_none());
        assert!(server.nonce_tracker.is_empty());
    }

    // ── Delta wire-byte reduction (GAP-2L.2) ──
    //
    // True delta xDS only sends resources the client doesn't already have:
    // - Resources known via `initial_resource_versions` with a matching version
    //   are omitted (the client already has the same bytes).
    // - Resources whose previous snapshot version + value match are omitted
    //   (no change since the last ACKed response for this type URL).
    // - Explicit re-subscribes still re-flow a fresh copy of the resource.

    #[test]
    fn delta_response_skips_unchanged_resources_against_previous_snapshot() {
        let server = test_server(gateway_config_with_services(&["api", "admin"], 0));
        let previous = server.snapshot_for_config(
            "node-a",
            &gateway_config_with_services(&["api", "admin"], 0),
        );
        // Update only "admin"; keep "api" identical to provoke wire-byte
        // reduction on the unchanged resource.
        let mut next_config = gateway_config_with_services(&["api", "admin"], 1);
        if let Some(mesh) = next_config.mesh.as_mut() {
            for service in &mut mesh.services {
                if service.name == "admin"
                    && let Some(port) = service.ports.first_mut()
                {
                    port.port = 8081;
                }
            }
        }
        let next_snapshot = server.snapshot_for_config("node-a", &next_config);

        let response = server.delta_response(
            &next_snapshot,
            Some(&previous),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &HashMap::new(),
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert!(
            !names.iter().any(|n| n == "cluster/default/api/8080"),
            "unchanged resource should be omitted from delta response, got: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("cluster/default/admin/")),
            "changed resource should appear, got: {names:?}"
        );
    }

    #[test]
    fn delta_response_skips_unchanged_resources_against_initial_resource_versions() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let cluster_name = "cluster/default/api/8080".to_string();
        let cluster_version = snapshot
            .resources(super::super::translator::CDS_TYPE_URL)
            .iter()
            .find(|r| r.name == cluster_name)
            .map(|r| r.version.clone())
            .expect("CDS resource should be present");

        let initial_resource_versions = HashMap::from([(cluster_name.clone(), cluster_version)]);

        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &initial_resource_versions,
            &[],
            &[],
        );

        assert!(
            response.resources.is_empty(),
            "client-known resource should be omitted on initial delta sync, got: {:?}",
            response
                .resources
                .iter()
                .map(|r| &r.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn delta_response_includes_resource_with_changed_version_against_initial() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let cluster_name = "cluster/default/api/8080".to_string();
        let initial_resource_versions =
            HashMap::from([(cluster_name.clone(), "v-stale".to_string())]);

        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &initial_resource_versions,
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names,
            vec![cluster_name],
            "stale-version resource should be re-flowed on initial delta sync"
        );
    }

    #[test]
    fn delta_response_resends_explicitly_resubscribed_unchanged_resource() {
        let server = test_server(gateway_config_with_service(true, 0));
        let previous = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let next_snapshot =
            server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let cluster_name = "cluster/default/api/8080".to_string();

        let response = server.delta_response(
            &next_snapshot,
            Some(&previous),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: vec![cluster_name.clone()],
                wildcard: false,
            },
            &HashMap::new(),
            std::slice::from_ref(&cluster_name),
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names,
            vec![cluster_name],
            "explicit re-subscribe should re-flow the resource even when unchanged"
        );
    }

    #[test]
    fn delta_response_resends_explicit_wildcard_resubscribed_unchanged_resources() {
        let server = test_server(gateway_config_with_services(&["api", "admin"], 0));
        let previous = server.snapshot_for_config(
            "node-a",
            &gateway_config_with_services(&["api", "admin"], 0),
        );
        let next_snapshot = server.snapshot_for_config(
            "node-a",
            &gateway_config_with_services(&["api", "admin"], 0),
        );

        let response = server.delta_response(
            &next_snapshot,
            Some(&previous),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &HashMap::new(),
            &["*".to_string()],
            &[],
        );

        let mut names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "cluster/default/admin/8080".to_string(),
                "cluster/default/api/8080".to_string(),
            ],
            "explicit wildcard re-subscribe should re-flow unchanged resources"
        );
    }

    #[test]
    fn delta_ack_baseline_advances_on_ack_but_not_nack() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let type_url = super::super::translator::CDS_TYPE_URL.to_string();
        let last_sent = HashMap::from([(type_url.clone(), Arc::clone(&snapshot))]);
        let mut last_accepted = HashMap::new();

        remember_delta_accepted_snapshot(
            Some(&AckOutcome::Nacked {
                message: "invalid cluster".to_string(),
            }),
            &type_url,
            &last_sent,
            &mut last_accepted,
        );
        assert!(
            last_accepted.is_empty(),
            "NACKed delta responses must not become the skip baseline"
        );

        remember_delta_accepted_snapshot(
            Some(&AckOutcome::Acked),
            &type_url,
            &last_sent,
            &mut last_accepted,
        );
        let accepted = last_accepted
            .get(&type_url)
            .expect("ACK should promote the last sent snapshot");
        assert!(Arc::ptr_eq(accepted, &snapshot));
    }

    #[test]
    fn delta_response_includes_new_resource_not_in_previous_snapshot() {
        let server = test_server(gateway_config_with_services(&["api"], 0));
        let previous =
            server.snapshot_for_config("node-a", &gateway_config_with_services(&["api"], 0));
        let next_snapshot = server.snapshot_for_config(
            "node-a",
            &gateway_config_with_services(&["api", "billing"], 1),
        );

        let response = server.delta_response(
            &next_snapshot,
            Some(&previous),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &HashMap::new(),
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names,
            vec!["cluster/default/billing/8080".to_string()],
            "delta should ship the newly-introduced resource only"
        );
    }

    /// Edge case: client reports a malformed (empty-string) version for a known
    /// resource name in `initial_resource_versions`. The empty string cannot
    /// match any server-computed per-resource version (which is a non-empty hex
    /// hash), so the resource must be re-flowed. Spoofing the version field is
    /// a no-op attack — the client just won't get the resource skipped.
    #[test]
    fn delta_response_reflows_resource_when_initial_version_is_empty_string() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let cluster_name = "cluster/default/api/8080".to_string();
        let initial_resource_versions = HashMap::from([(cluster_name.clone(), String::new())]);

        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &initial_resource_versions,
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names,
            vec![cluster_name],
            "malformed (empty-string) client version must not skip the resource"
        );
    }

    /// Mixed scenario: one resource removed AND one unchanged across snapshots.
    /// The delta filter must skip the unchanged resource on the response while
    /// `removed_resources` still surfaces the dropped name — the two paths are
    /// orthogonal.
    #[test]
    fn delta_response_emits_removed_resource_and_skips_unchanged_resource() {
        let server = test_server(gateway_config_with_services(&["api", "admin"], 0));
        let previous = server.snapshot_for_config(
            "node-a",
            &gateway_config_with_services(&["api", "admin"], 0),
        );
        // Drop "admin" entirely; keep "api" identical so it stays unchanged.
        let next_snapshot =
            server.snapshot_for_config("node-a", &gateway_config_with_services(&["api"], 0));

        let response = server.delta_response(
            &next_snapshot,
            Some(&previous),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &HashMap::new(),
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert!(
            names.is_empty(),
            "unchanged resource must be omitted from delta, got: {names:?}"
        );
        assert_eq!(
            response.removed_resources,
            vec!["cluster/default/admin/8080".to_string()],
            "removed resource must still be surfaced alongside the delta filter"
        );
    }

    /// Defensive guard: even if a malicious or buggy client tries to spoof
    /// `initial_resource_versions` with a guessed hash that happens to match a
    /// stale server-computed version (functionally impossible with a 64-bit
    /// truncation, but check the contract anyway), the server's per-resource
    /// version is always recomputed from current resource bytes. A client
    /// claim is honored only when it byte-matches the server's current view,
    /// so a stale claim cannot suppress a real change.
    #[test]
    fn delta_response_reflows_resource_when_content_changes_even_if_client_spoofs_old_version() {
        let server = test_server(gateway_config_with_service(true, 0));
        let initial_snapshot =
            server.snapshot_for_config("node-a", &gateway_config_with_service(true, 0));
        let cluster_name = "cluster/default/api/8080".to_string();
        let old_version = initial_snapshot
            .resources(super::super::translator::CDS_TYPE_URL)
            .iter()
            .find(|r| r.name == cluster_name)
            .map(|r| r.version.clone())
            .expect("CDS resource should be present in initial snapshot");

        // Server-side content changes — port flips from 8080 to 8081, which
        // also renames the cluster. Build a fresh snapshot that carries a
        // cluster with name `cluster/default/api/8081` AND keep the client
        // claiming "I already have cluster/default/api/8080 at <old_version>".
        let mut next_config = gateway_config_with_service(true, 1);
        if let Some(mesh) = next_config.mesh.as_mut() {
            for service in &mut mesh.services {
                if let Some(port) = service.ports.first_mut() {
                    port.port = 8081;
                }
            }
        }
        let next_snapshot = server.snapshot_for_config("node-a", &next_config);
        let initial_resource_versions = HashMap::from([(cluster_name.clone(), old_version)]);

        let response = server.delta_response(
            &next_snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
            &initial_resource_versions,
            &[],
            &[],
        );

        let names: Vec<_> = response.resources.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names,
            vec!["cluster/default/api/8081".to_string()],
            "renamed resource must be shipped; client's stale claim for the old name only suppresses the old name (which no longer exists)"
        );
        assert_eq!(
            response.removed_resources,
            vec![cluster_name],
            "old name absent from current snapshot must be reported removed even when client claimed a version for it"
        );
    }
}
