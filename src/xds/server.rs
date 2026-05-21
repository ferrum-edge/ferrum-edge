use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

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
use crate::grpc::auth::verify_grpc_jwt_metadata;
use crate::grpc::proto::ConfigUpdate;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

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

    fn replace(&mut self, config: GatewayConfig) {
        *self = Self::new(config);
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
    jwt_secret: String,
    expected_issuer: String,
    namespace: String,
    stream_channel_capacity: usize,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    active_streams: Arc<XdsStreamRegistry>,
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

#[derive(Default)]
struct XdsStreamRegistry {
    // ADS stream counts are outside the proxy hot path and exist only when
    // FERRUM_XDS_ENABLED=true, so default DashMap sharding is intentional here.
    counts: DashMap<String, usize>,
}

impl XdsStreamRegistry {
    fn register(&self, node_id: &str) {
        // TODO(Phase C): enforce a per-node ADS stream ceiling once mesh
        // listeners can create large fleets of authenticated xDS clients.
        // Phase B keeps xDS opt-in/off by default and only tracks counts so
        // final stream teardown can drop per-node cache/nonce state.
        match self.counts.entry(node_id.to_string()) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
            }
            Entry::Vacant(entry) => {
                entry.insert(1);
            }
        }
    }

    fn unregister(&self, node_id: &str) -> bool {
        match self.counts.entry(node_id.to_string()) {
            Entry::Occupied(mut entry) => {
                if *entry.get() > 1 {
                    *entry.get_mut() -= 1;
                    false
                } else {
                    entry.remove();
                    true
                }
            }
            Entry::Vacant(_) => true,
        }
    }
}

struct XdsStreamGuard {
    node_id: Option<String>,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    active_streams: Arc<XdsStreamRegistry>,
}

impl XdsStreamGuard {
    fn new(
        snapshot_cache: Arc<XdsSnapshotCache>,
        nonce_tracker: Arc<XdsNonceTracker>,
        active_streams: Arc<XdsStreamRegistry>,
    ) -> Self {
        Self {
            node_id: None,
            snapshot_cache,
            nonce_tracker,
            active_streams,
        }
    }

    fn set_node_id(&mut self, node_id: &str) {
        if self.node_id.as_deref() == Some(node_id) {
            return;
        }
        self.clear_current();
        self.active_streams.register(node_id);
        self.node_id = Some(node_id.to_string());
    }

    fn clear_current(&mut self) {
        let Some(node_id) = self.node_id.take() else {
            return;
        };
        if self.active_streams.unregister(&node_id) {
            self.snapshot_cache.remove(&node_id);
            self.nonce_tracker.remove_node(&node_id);
        }
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
            jwt_secret,
            expected_issuer,
            namespace,
            stream_channel_capacity: stream_channel_capacity.max(1),
            snapshot_cache: Arc::new(XdsSnapshotCache::new()),
            nonce_tracker: Arc::new(XdsNonceTracker::new()),
            active_streams: Arc::new(XdsStreamRegistry::default()),
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

    pub fn with_sidecar_identity_narrowing(mut self, sidecar_identity_narrowing: bool) -> Self {
        self.sidecar_identity_narrowing = sidecar_identity_narrowing;
        self
    }

    pub fn with_cluster_domain(mut self, cluster_domain: String) -> Self {
        self.cluster_domain = cluster_domain;
        self
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

    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        verify_grpc_jwt_metadata(metadata, &self.jwt_secret, &self.expected_issuer)
    }

    fn rebuild_snapshot(&self, node_id: &str) -> XdsSnapshot {
        let config = self.config.load_full();
        self.rebuild_snapshot_from_config(node_id, config.as_ref())
    }

    fn rebuild_snapshot_from_config(&self, node_id: &str, config: &GatewayConfig) -> XdsSnapshot {
        let request = MeshSliceRequest::from_xds_node(node_id.to_string(), self.namespace.clone())
            .with_cluster_domain(self.cluster_domain.clone())
            .with_enforce_sidecar_egress(self.sidecar_enforced)
            .with_sidecar_egress_dry_run(self.sidecar_enforced_dry_run)
            .with_enforce_sidecar_identity_narrowing(self.sidecar_identity_narrowing);
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
        self.snapshot_for_config_with_fingerprint(node_id, config, &fingerprint)
    }

    fn snapshot_for_stream_config(
        &self,
        node_id: &str,
        stream_config: &XdsStreamConfig,
    ) -> Arc<XdsSnapshot> {
        self.snapshot_for_config_with_fingerprint(
            node_id,
            &stream_config.config,
            &stream_config.fingerprint,
        )
    }

    fn snapshot_for_config_with_fingerprint(
        &self,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
    ) -> Arc<XdsSnapshot> {
        if let Some(snapshot) = self.snapshot_cache.get_if_fingerprint(node_id, fingerprint) {
            return snapshot;
        }

        let next = self.rebuild_snapshot_from_config(node_id, config);
        self.snapshot_cache
            .insert_with_fingerprint(next, fingerprint.clone())
    }

    fn invalidate_snapshot_for_config_update(&self, node_id: &str) {
        self.snapshot_cache.remove(node_id);
    }

    fn stream_guard(&self) -> XdsStreamGuard {
        XdsStreamGuard::new(
            self.snapshot_cache.clone(),
            self.nonce_tracker.clone(),
            self.active_streams.clone(),
        )
    }

    fn sotw_response(
        &self,
        snapshot: &XdsSnapshot,
        subscription: &XdsSubscription,
    ) -> DiscoveryResponse {
        let nonce = self.nonce_tracker.issue_nonce(
            &snapshot.node_id,
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
        let nonce = self.nonce_tracker.issue_nonce(
            &snapshot.node_id,
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
        self.sotw_responses_for_subscriptions_from_config_with_fingerprint(
            node_id,
            subscriptions,
            &stream_config.config,
            &stream_config.fingerprint,
            previous,
        )
    }

    fn sotw_responses_for_subscriptions_from_config_with_fingerprint(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DiscoveryResponse>) {
        let snapshot = self.snapshot_for_config_with_fingerprint(node_id, config, fingerprint);
        let responses = subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous, &snapshot, subscription)
            })
            .map(|subscription| self.sotw_response(&snapshot, subscription))
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
        self.sotw_response_for_request_with_fingerprint(
            node_id,
            &stream_config.config,
            &stream_config.fingerprint,
            subscriptions,
            request,
        )
    }

    fn sotw_response_for_request_with_fingerprint(
        &self,
        node_id: &str,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<(Arc<XdsSnapshot>, DiscoveryResponse)> {
        if !request.response_nonce.is_empty() {
            match self.record_sotw_ack(node_id, request) {
                AckOutcome::Acked => debug!(
                    node_id = %node_id,
                    type_url = %request.type_url,
                    "xDS ACK accepted"
                ),
                AckOutcome::Nacked { message } => {
                    warn!(
                        node_id = %node_id,
                        type_url = %request.type_url,
                        error = %message,
                        "xDS NACK received"
                    );
                }
                outcome => {
                    warn!(
                        node_id = %node_id,
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
            let snapshot = self.snapshot_for_config_with_fingerprint(node_id, config, fingerprint);
            if !request.response_nonce.is_empty()
                && !subscription_change_affects_resources(
                    &snapshot,
                    previous_subscription.as_ref(),
                    &subscription,
                )
            {
                return None;
            }
            let response = self.sotw_response(&snapshot, &subscription);
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
        self.delta_response_for_request_with_fingerprint_without_ack(
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
            config,
            fingerprint,
            subscriptions,
            request,
            previous,
        )
    }

    fn delta_response_for_request_with_fingerprint_without_ack(
        &self,
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
            let snapshot = self.snapshot_for_config_with_fingerprint(node_id, config, fingerprint);
            let response = self.delta_response(
                &snapshot,
                previous,
                &subscription,
                &request.initial_resource_versions,
                &request.resource_names_subscribe,
                &request.resource_names_unsubscribe,
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
                node_id = %node_id,
                type_url = %request.type_url,
                "xDS delta ACK accepted"
            ),
            AckOutcome::Nacked { message } => {
                warn!(
                    node_id = %node_id,
                    type_url = %request.type_url,
                    error = %message,
                    "xDS delta NACK received"
                );
            }
            outcome => {
                warn!(
                    node_id = %node_id,
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
        self.delta_responses_for_subscriptions_from_config_with_fingerprint(
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
        let snapshot = self.snapshot_for_stream_config(node_id, stream_config);
        let responses = subscriptions
            .values()
            .filter_map(|subscription| {
                let previous = previous_by_type
                    .get(&subscription.type_url)
                    .map(Arc::as_ref);
                subscription_resources_changed(previous, &snapshot, subscription).then(|| {
                    self.delta_response(
                        &snapshot,
                        previous,
                        subscription,
                        &HashMap::new(),
                        &[],
                        &[],
                    )
                })
            })
            .collect();
        (snapshot, responses)
    }

    fn delta_responses_for_subscriptions_from_config_with_fingerprint(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
        fingerprint: &XdsConfigFingerprint,
        previous: Option<&XdsSnapshot>,
    ) -> (Arc<XdsSnapshot>, Vec<DeltaDiscoveryResponse>) {
        let snapshot = self.snapshot_for_config_with_fingerprint(node_id, config, fingerprint);
        let responses = subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous, &snapshot, subscription)
            })
            .map(|subscription| {
                self.delta_response(&snapshot, previous, subscription, &HashMap::new(), &[], &[])
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
                    stream_config.apply_update(&update);
                }
                Err(broadcast::error::TryRecvError::Empty) => return,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!(
                        "xDS ADS stream lagged by {} config updates while catching up; using current shared snapshot",
                        n
                    );
                    let current = self.config.load_full();
                    stream_config.replace(current.as_ref().clone());
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

fn config_fingerprint(config: &GatewayConfig) -> XdsConfigFingerprint {
    // This serializes the full GatewayConfig, including HashMap fields whose
    // iteration order is process-local. That is fine for the in-memory xDS
    // snapshot cache: fingerprints only need to be stable within one process
    // lifetime, and a restart starts with an empty cache anyway. Do not reuse
    // this helper for persisted cross-process cache keys without canonicalizing
    // map order first.
    match serde_json::to_vec(config) {
        Ok(bytes) => fingerprint_bytes([b"full-config".as_slice(), bytes.as_slice()]),
        Err(error) => {
            let error = error.to_string();
            fingerprint_bytes([b"full-config-error".as_slice(), error.as_bytes()])
        }
    }
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
        self.verify_jwt_metadata(request.metadata())?;

        let mut requests = request.into_inner();
        let server = self.clone();
        let mut updates = server.update_tx.subscribe();
        let (tx, rx) = mpsc::channel(server.stream_channel_capacity);

        tokio::spawn(async move {
            let mut stream_guard = server.stream_guard();
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config =
                XdsStreamConfig::new(server.config.load_full().as_ref().clone());
            let mut last_snapshot: Option<Arc<XdsSnapshot>> = None;
            loop {
                tokio::select! {
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
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            request.node.as_ref().and_then(|node| non_empty_string(&node.id)),
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        if node_id.is_none() {
                            stream_guard.set_node_id(&current_node_id);
                            node_id = Some(current_node_id.clone());
                        };

                        if let Err(status) = ensure_supported_type_url(&request.type_url) {
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if let Err(status) = enforce_subscription_limits(
                            &subscriptions,
                            &request.type_url,
                            request.resource_names.len(),
                        ) {
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(&mut updates, &mut stream_config);
                        }

                        let send_failed = if let Some((snapshot, response)) = server.sotw_response_for_stream_request(
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
                                if !stream_config.apply_update(&update) {
                                    continue;
                                }
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                server.invalidate_snapshot_for_config_update(current_node_id);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.sotw_responses_for_stream_config_with_previous(
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
                                let current = server.config.load_full();
                                stream_config.replace(current.as_ref().clone());
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                server.invalidate_snapshot_for_config_update(current_node_id);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.sotw_responses_for_stream_config_with_previous(
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
        self.verify_jwt_metadata(request.metadata())?;

        let mut requests = request.into_inner();
        let server = self.clone();
        let mut updates = server.update_tx.subscribe();
        let (tx, rx) = mpsc::channel(server.stream_channel_capacity);

        tokio::spawn(async move {
            let mut stream_guard = server.stream_guard();
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config =
                XdsStreamConfig::new(server.config.load_full().as_ref().clone());
            let mut last_sent_snapshot_by_type: HashMap<String, Arc<XdsSnapshot>> = HashMap::new();
            let mut last_accepted_snapshot_by_type: HashMap<String, Arc<XdsSnapshot>> =
                HashMap::new();
            loop {
                tokio::select! {
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
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            request.node.as_ref().and_then(|node| non_empty_string(&node.id)),
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        if node_id.is_none() {
                            stream_guard.set_node_id(&current_node_id);
                            node_id = Some(current_node_id.clone());
                        };

                        if let Err(status) = ensure_supported_type_url(&request.type_url) {
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if let Err(status) = enforce_subscription_limits(
                            &subscriptions,
                            &request.type_url,
                            request.resource_names_subscribe.len(),
                        ) {
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(&mut updates, &mut stream_config);
                        }

                        let ack_outcome = server.record_and_log_delta_ack(&current_node_id, &request);
                        remember_delta_accepted_snapshot(
                            ack_outcome.as_ref(),
                            &request.type_url,
                            &last_sent_snapshot_by_type,
                            &mut last_accepted_snapshot_by_type,
                        );
                        let previous = last_accepted_snapshot_by_type
                            .get(&request.type_url)
                            .cloned();
                        if let Some((snapshot, response)) = server.delta_response_for_stream_request_without_ack(
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
                                if !stream_config.apply_update(&update) {
                                    continue;
                                }
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                server.invalidate_snapshot_for_config_update(current_node_id);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.delta_responses_for_stream_config_with_previous_by_type(
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
                                let current = server.config.load_full();
                                stream_config.replace(current.as_ref().clone());
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                server.invalidate_snapshot_for_config_update(current_node_id);
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                let (snapshot, responses) = server.delta_responses_for_stream_config_with_previous_by_type(
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

fn non_empty_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn resolve_stream_node_id(
    current: Option<&str>,
    requested: Option<String>,
) -> Result<String, Status> {
    match (current, requested) {
        (None, Some(requested)) => Ok(requested),
        (None, None) => Err(Status::invalid_argument("xDS Node.id is required")),
        (Some(current), None) => Ok(current.to_string()),
        (Some(current), Some(requested)) if requested == current => Ok(requested),
        (Some(current), Some(requested)) => Err(Status::invalid_argument(format!(
            "xDS Node.id cannot change on an established stream: {current} -> {requested}"
        ))),
    }
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
    use crate::modes::mesh::config::{
        AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarEgress, ServicePort,
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

    fn mesh_service(name: &str) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
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
        HashMap::from([(
            super::super::translator::CDS_TYPE_URL.to_string(),
            XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
            },
        )])
    }

    #[test]
    fn resolve_stream_node_id_rejects_mid_stream_mutation() {
        assert_eq!(
            resolve_stream_node_id(None, Some("node-a".to_string())).unwrap(),
            "node-a"
        );
        assert_eq!(
            resolve_stream_node_id(Some("node-a"), None).unwrap(),
            "node-a"
        );
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-a".to_string())).is_ok());
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-b".to_string())).is_err());
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
    fn sotw_update_skips_unchanged_effective_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let unchanged = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert!(unchanged.is_empty());
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
        server.catch_up_pending_updates(&mut updates, &mut stream_config);
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
        server.catch_up_pending_updates(&mut updates, &mut stream_config);
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
            let mut guard = server.stream_guard();
            guard.set_node_id("node-a");
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

        let mut first = server.stream_guard();
        first.set_node_id("node-a");
        let mut second = server.stream_guard();
        second.set_node_id("node-a");

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
