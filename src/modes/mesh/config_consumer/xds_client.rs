use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE, jittered_backoff,
    next_backoff_secs, refresh_dp_grpc_tls_config_if_changed, should_race_primary_retry,
    tonic_tls_config, wait_for_shutdown, wait_optional_tls_reload,
};
use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret};
use crate::modes::mesh::config::{
    AppProtocol, MeshDestinationRule, MeshRuntimeOverlay, MeshService, ServicePort,
};
use crate::modes::mesh::revision::MeshRevisionRejection;
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall, XdsConvergenceSnapshot};
use crate::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};
use crate::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::proto::{self, DiscoveryRequest, Node, Status};
use crate::xds::runtime_proto;
use crate::xds::translator::{
    CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX,
    FERRUM_ECDS_DESTINATION_RULE_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL,
    XDS_TYPE_URLS, translate_rtds_layer,
};

const INITIAL_TYPE_URL_ORDER: [&str; 7] = [
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    SDS_TYPE_URL,
    // ECDS rides the same ADS stream as the standard xDS resources so the
    // GAP-2K DR-carrier path piggybacks on existing subscription lifecycles.
    // Kept after the baseline so DPs request the baseline first and treat
    // ECDS as a "richer-semantics" overlay rather than a hard dependency.
    ECDS_TYPE_URL,
    // RTDS is subscribed alongside the other xDS types; runtime knobs feed
    // fault-injection percentages, transformer gates, and the tracing log
    // level. Fault values bind to the candidate plugin cache; the remaining
    // process-wide consumers publish after slice acceptance.
    // Kept last so the baseline slice can apply even when the CP has no
    // Runtime layers to send.
    RTDS_TYPE_URL,
];
const REQUIRED_MESH_SLICE_TYPE_URLS: [&str; 5] = [
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    ECDS_TYPE_URL,
];
const XDS_APPLY_DEBOUNCE: Duration = Duration::from_millis(25);
const XDS_CONSECUTIVE_NACK_LIMIT: u32 = 5;
const XDS_APPLY_MAX_DELAY: Duration = Duration::from_millis(500);

type BearerToken = MetadataValue<tonic::metadata::Ascii>;

#[derive(Clone)]
struct AdsAuth {
    jwt_secret: GrpcJwtSecret,
    node_id: String,
    namespace: String,
}

impl AdsAuth {
    fn bearer_token(&self) -> Result<BearerToken, tonic::Status> {
        let auth_token = self
            .jwt_secret
            .mint(&self.node_id, Some(&self.namespace), None)
            .map_err(|e| {
                tonic::Status::unauthenticated(format!("failed to obtain xDS bearer token: {e}"))
            })?;
        format!("Bearer {auth_token}").parse().map_err(|e| {
            tonic::Status::internal(format!("failed to build authorization metadata: {e}"))
        })
    }
}

/// xDS ADS client settings for mesh mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsClientConfig {
    pub cp_urls: Vec<String>,
    pub node_id: String,
    pub cluster: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub waypoint_name: Option<String>,
    pub ambient_udp_source_scoping: bool,
    pub stream_channel_capacity: usize,
    pub primary_retry_secs: u64,
    /// Client connection timeout. `0` disables tonic's explicit connect timeout.
    pub connect_timeout_seconds: u64,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ClientSubscriptionState {
    subscriptions: HashMap<String, TypeSubscription>,
}

#[derive(Debug, Clone, Default)]
struct TypeSubscription {
    last_acked_version: Option<String>,
    last_received_version: Option<String>,
    last_received_nonce: Option<String>,
    /// Nonce of the most recent response the client fully processed (ACKed or
    /// NACKed) for this type URL on the current ADS stream. Server nonces are
    /// opaque (`n1:<sha256>`) and stream-scoped per the xDS spec, so duplicate
    /// detection — not numeric ordering — is the available staleness signal,
    /// and the signal is only meaningful within a single stream. An incoming
    /// response whose nonce equals `last_processed_nonce` is a stale retransmit
    /// (in-stream race / buggy CP) and must be ignored so we do not re-apply
    /// or re-ACK already-acted-on bytes. Cleared by
    /// `ClientSubscriptionState::reset_processed_nonces` at the start of every
    /// new ADS stream so a deterministic-nonce CP (e.g. one that resets its
    /// sequence counter on restart) is not blocked from delivering the first
    /// response of the new stream.
    last_processed_nonce: Option<String>,
    has_initial_response: bool,
}

/// Outcome of recording a received SotW response against the per-type nonce
/// state. Mirrors the receiving half of the server-side nonce machine.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponseNonceOutcome {
    /// First response carrying this nonce; process it normally.
    Fresh,
    /// The nonce matches the last fully-processed response for this type URL —
    /// a stale/duplicate retransmit that must be ignored.
    StaleDuplicate { nonce: String },
}

impl ClientSubscriptionState {
    fn new() -> Self {
        Self {
            subscriptions: XDS_TYPE_URLS
                .iter()
                .map(|type_url| ((*type_url).to_string(), TypeSubscription::default()))
                .collect(),
        }
    }

    fn build_initial_requests(
        &self,
        node_id: &str,
        cluster: &str,
        workload_spiffe_id: Option<&str>,
        waypoint_name: Option<&str>,
        ambient_udp_source_scoping: bool,
    ) -> Vec<DiscoveryRequest> {
        // Carry the workload SPIFFE in `Node.metadata` so a Ferrum CP can
        // identify this workload even when `node_id` is a hostname (the common
        // default). The CP needs it to compute Sidecar-aware narrowing and the
        // un-narrowed local-inbound-service view; without it a restrictive
        // Sidecar would narrow the local service out of the ECDS carriers.
        let node_metadata = crate::xds::carrier::encode_node_metadata_with_waypoint_and_udp_scope(
            workload_spiffe_id,
            waypoint_name,
            ambient_udp_source_scoping,
        );
        INITIAL_TYPE_URL_ORDER
            .iter()
            .map(|type_url| {
                let subscription = self.subscriptions.get(*type_url);
                DiscoveryRequest {
                    version_info: subscription
                        .and_then(|sub| sub.last_acked_version.clone())
                        .unwrap_or_default(),
                    node: Some(Node {
                        id: node_id.to_string(),
                        cluster: cluster.to_string(),
                        metadata: node_metadata.clone(),
                    }),
                    // Phase B subscribes wildcard-style to each supported type URL.
                    // Ferrum CP and Istio wildcard modes accept empty resource_names;
                    // explicit-resource subscriptions are a later xDS client mode.
                    resource_names: Vec::new(),
                    type_url: (*type_url).to_string(),
                    response_nonce: String::new(),
                    error_detail: None,
                }
            })
            .collect()
    }

    /// Record a received response's version/nonce and classify it as fresh or
    /// a stale duplicate of the last fully-processed response.
    ///
    /// A non-empty nonce equal to `last_processed_nonce` means the server
    /// re-sent a response we already ACKed/NACKed (a reconnect race or buggy
    /// CP). Such a response is reported as `StaleDuplicate` and the caller
    /// ignores it; the received version/nonce are intentionally NOT overwritten
    /// so the next genuine response is still compared against the correct
    /// baseline. An empty nonce is treated as fresh (the server chose not to
    /// supply one) and recorded normally.
    fn record_response(
        &mut self,
        type_url: &str,
        version_info: &str,
        nonce: &str,
    ) -> ResponseNonceOutcome {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        if !nonce.is_empty() && subscription.last_processed_nonce.as_deref() == Some(nonce) {
            return ResponseNonceOutcome::StaleDuplicate {
                nonce: nonce.to_string(),
            };
        }
        subscription.last_received_version = Some(version_info.to_string());
        subscription.last_received_nonce = Some(nonce.to_string());
        subscription.has_initial_response = true;
        ResponseNonceOutcome::Fresh
    }

    /// Mark the most recently received nonce for `type_url` as fully processed
    /// (ACKed or NACKed), so a subsequent response carrying the same nonce is
    /// detected as a stale duplicate.
    fn mark_processed(&mut self, type_url: &str) {
        if let Some(subscription) = self.subscriptions.get_mut(type_url) {
            subscription
                .last_processed_nonce
                .clone_from(&subscription.last_received_nonce);
        }
    }

    /// Clear `last_processed_nonce` on every type URL. xDS nonces are
    /// stream-scoped, so the duplicate-detection baseline must not carry across
    /// stream boundaries: a CP that resets its sequence counter on restart (or
    /// a load-balanced reconnect to a peer replica) can legitimately reissue a
    /// previously seen opaque nonce on a new stream, and the DP must accept it
    /// rather than treating the first response of the new stream as stale.
    /// `last_acked_version` is intentionally left alone so the new stream
    /// resumes the subscription from the last acknowledged version.
    fn reset_processed_nonces(&mut self) {
        for subscription in self.subscriptions.values_mut() {
            subscription.last_processed_nonce = None;
        }
    }

    fn build_ack(&self, type_url: &str) -> DiscoveryRequest {
        let subscription = self.subscriptions.get(type_url);
        DiscoveryRequest {
            version_info: subscription
                .and_then(|sub| sub.last_received_version.clone())
                .unwrap_or_default(),
            node: None,
            // Wildcard subscription: keep resource_names empty on ACKs too.
            resource_names: Vec::new(),
            type_url: type_url.to_string(),
            response_nonce: subscription
                .and_then(|sub| sub.last_received_nonce.clone())
                .unwrap_or_default(),
            error_detail: None,
        }
    }

    fn build_nack(&self, type_url: &str, error_msg: impl Into<String>) -> DiscoveryRequest {
        let subscription = self.subscriptions.get(type_url);
        DiscoveryRequest {
            version_info: subscription
                .and_then(|sub| sub.last_acked_version.clone())
                .unwrap_or_default(),
            node: None,
            // Wildcard subscription: keep resource_names empty on NACKs too.
            resource_names: Vec::new(),
            type_url: type_url.to_string(),
            response_nonce: subscription
                .and_then(|sub| sub.last_received_nonce.clone())
                .unwrap_or_default(),
            error_detail: Some(Status {
                code: 3,
                message: error_msg.into(),
                details: Vec::new(),
            }),
        }
    }

    fn mark_acked(&mut self, type_url: &str) {
        if let Some(subscription) = self.subscriptions.get_mut(type_url) {
            subscription.last_acked_version = subscription.last_received_version.clone();
        }
    }

    fn required_types_have_initial_response(&self) -> bool {
        REQUIRED_MESH_SLICE_TYPE_URLS.iter().all(|type_url| {
            self.subscriptions
                .get(*type_url)
                .is_some_and(|subscription| subscription.has_initial_response)
        })
    }
}

impl Default for ClientSubscriptionState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
struct XdsStreamState {
    subscriptions: ClientSubscriptionState,
    accumulator: ResourceAccumulator,
    nack_circuit_breaker: NackCircuitBreaker,
}

impl XdsStreamState {
    fn reset_for_new_control_plane(&mut self) {
        self.subscriptions = ClientSubscriptionState::new();
        self.accumulator = ResourceAccumulator::new();
        self.nack_circuit_breaker = NackCircuitBreaker::default();
    }

    /// Reset stream-scoped state that must not carry across ADS stream
    /// boundaries: today, the per-type `last_processed_nonce` duplicate-
    /// detection baseline. `last_acked_version`, the resource accumulator, and
    /// the NACK circuit breaker intentionally persist so the new stream
    /// resumes the subscription from the last acknowledged state instead of
    /// re-flowing every resource from scratch on every reconnect.
    fn reset_for_new_stream(&mut self) {
        self.subscriptions.reset_processed_nonces();
    }
}

#[derive(Debug, Clone, Default)]
struct NackCircuitBreaker {
    consecutive_nacks_by_type: HashMap<String, u32>,
}

impl NackCircuitBreaker {
    fn record_ack(&mut self, type_url: &str) {
        self.consecutive_nacks_by_type.remove(type_url);
    }

    fn consecutive_nacks(&self, type_url: &str) -> u32 {
        self.consecutive_nacks_by_type
            .get(type_url)
            .copied()
            .unwrap_or(0)
    }

    fn nacked_since(&self, type_url: &str, previous: u32) -> bool {
        self.consecutive_nacks(type_url) > previous
    }

    fn record_nack(&mut self, type_url: &str) -> u32 {
        let count = self
            .consecutive_nacks_by_type
            .entry(type_url.to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
        *count
    }
}

#[derive(Debug, Clone, Default)]
struct ResourceAccumulator {
    resources_by_type: HashMap<String, Vec<AccumulatedResource>>,
    versions_by_type: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccumulatedResource {
    name: String,
    /// Raw protobuf bytes of the resource. Captured only for type URLs whose
    /// reverse-translation needs the full payload (currently ECDS, where the
    /// inner `TypedExtensionConfig.typed_config.value` carries the
    /// operator's opaque DR JSON). The other type URLs only need the name
    /// for service-port reconstruction, so storing bytes there would be
    /// wasted memory under high resource cardinality.
    bytes: Vec<u8>,
}

impl ResourceAccumulator {
    fn new() -> Self {
        Self::default()
    }

    fn apply_sotw_response(
        &mut self,
        type_url: &str,
        resources: &[proto::Any],
        version: &str,
    ) -> Result<(), String> {
        if !is_known_type_url(type_url) {
            return Err(format!("unknown xDS type_url '{type_url}'"));
        }
        if version.trim().is_empty()
            && (is_required_mesh_slice_type(type_url) || !resources.is_empty())
        {
            return Err(format!(
                "xDS response for type_url '{type_url}' has empty version_info"
            ));
        }

        let mut accumulated = Vec::with_capacity(resources.len());
        let mut runtime_names = BTreeSet::new();
        for resource in resources {
            if !resource.type_url.is_empty() && resource.type_url != type_url {
                return Err(format!(
                    "resource type_url '{}' does not match response type_url '{}'",
                    resource.type_url, type_url
                ));
            }
            let name = decode_resource_name(type_url, &resource.value)?;
            if name.is_empty() {
                return Err(format!(
                    "xDS resource for type_url '{type_url}' has an empty name"
                ));
            }
            validate_resource_name_shape(type_url, &name)?;
            if type_url == RTDS_TYPE_URL && !runtime_names.insert(name.clone()) {
                return Err(format!(
                    "xDS RTDS response contains duplicate Runtime resource name '{name}'"
                ));
            }
            // ECDS reverse-translation reads the full bytes back to decode
            // its inner TypedExtensionConfig. RTDS reverse-translation does
            // the same to decode the layer struct. Other resource types
            // only carry routing names, so skip the allocation.
            let bytes = if type_url == ECDS_TYPE_URL || type_url == RTDS_TYPE_URL {
                resource.value.clone()
            } else {
                Vec::new()
            };
            let accumulated_resource = AccumulatedResource { name, bytes };
            if type_url == ECDS_TYPE_URL {
                validate_ecds_mesh_slice_carrier(&accumulated_resource)?;
                validate_ecds_destination_rule_carrier(&accumulated_resource)?;
            }
            accumulated.push(accumulated_resource);
        }

        // Envoy does not assign precedence semantics to SotW wire order.
        // Canonicalize RTDS layers by resource name so reconnects, CP map
        // iteration, and equivalent permutations always produce one overlay.
        // Reverse translation applies later entries last, so lexicographically
        // greater names have deterministic precedence on conflicting keys.
        if type_url == RTDS_TYPE_URL {
            accumulated.sort_by(|left, right| left.name.cmp(&right.name));
        }

        self.resources_by_type
            .insert(type_url.to_string(), accumulated);
        self.versions_by_type
            .insert(type_url.to_string(), version.to_string());
        Ok(())
    }

    fn resources(&self, type_url: &str) -> &[AccumulatedResource] {
        self.resources_by_type
            .get(type_url)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn has_required_types(&self) -> bool {
        REQUIRED_MESH_SLICE_TYPE_URLS
            .iter()
            .all(|type_url| self.versions_by_type.contains_key(*type_url))
    }

    /// Build a slice only after the required mesh-slice resource types are
    /// present at one coherent `version_info`.
    ///
    /// Ferrum carries security-critical mesh state (authz, PeerAuthentication,
    /// JWT request auth, trust bundles, workload labels, and policy context) in
    /// ECDS carriers. Applying CDS/EDS/LDS/RDS from a newer snapshot while ECDS
    /// remains on an older snapshot can expose newly reachable backends under
    /// stale policy. The CP therefore force-re-sends subscribed required types
    /// on any required mesh-slice change, and the DP waits until all required
    /// types report that same snapshot version before building.
    ///
    /// Dependency warming still avoids NACKing arrival-order skews inside a
    /// coherent snapshot: `reverse_translate` skips routes whose service has not
    /// arrived yet, while malformed ECDS carriers remain structural errors that
    /// NACK and roll the accumulator back.
    fn try_build_mesh_slice(&self, config: &XdsClientConfig) -> Result<Option<MeshSlice>, String> {
        if !self.has_coherent_required_versions() {
            return Ok(None);
        }
        reverse_translate(self, config).map(Some)
    }

    fn has_coherent_required_versions(&self) -> bool {
        let mut versions = REQUIRED_MESH_SLICE_TYPE_URLS
            .iter()
            .map(|type_url| self.versions_by_type.get(*type_url));
        let Some(Some(first)) = versions.next() else {
            return false;
        };
        versions.all(|version| version == Some(first))
    }

    /// True once all required types are present but their per-type versions are
    /// not all identical. Such a set is visible in convergence diagnostics but
    /// is not installed as a live slice, because ECDS may contain stale policy.
    fn required_versions_skewed(&self) -> bool {
        self.has_required_types() && !self.has_coherent_required_versions()
    }

    /// Build the convergence snapshot surfaced (JWT-authenticated) on
    /// `/mesh/config-drift`. Derived from the accumulator alone so a NACK that
    /// rolls back `versions_by_type` is correctly reflected as "type still
    /// missing" rather than prematurely converged.
    fn convergence_snapshot(&self) -> XdsConvergenceSnapshot {
        let per_type_versions = self
            .versions_by_type
            .iter()
            .map(|(type_url, version)| (xds_type_short_name(type_url).to_string(), version.clone()))
            .collect();
        let missing_required_types = REQUIRED_MESH_SLICE_TYPE_URLS
            .iter()
            .filter(|type_url| !self.versions_by_type.contains_key(**type_url))
            .map(|type_url| xds_type_short_name(type_url).to_string())
            .collect::<Vec<_>>();
        let version_skew = self.required_versions_skewed();
        XdsConvergenceSnapshot {
            per_type_versions,
            converged: missing_required_types.is_empty() && !version_skew,
            missing_required_types,
            version_skew,
        }
    }
}

/// Compose the slice version from the coherent per-type versions of the
/// required mesh-slice types. `try_build_mesh_slice` only calls
/// `reverse_translate` after all required versions match, so the maximum is the
/// shared snapshot version in normal use; returning the maximum keeps
/// diagnostics useful for partially converged accumulators.
///
/// Observability-only: `MeshSlice.version` is never used for change detection
/// (`MeshSlice::content_eq` ignores it) and `install_slice` never dedupes by it.
fn composite_required_version(accumulator: &ResourceAccumulator) -> String {
    REQUIRED_MESH_SLICE_TYPE_URLS
        .iter()
        .filter_map(|type_url| accumulator.versions_by_type.get(*type_url))
        .max()
        .cloned()
        .unwrap_or_default()
}

/// Maintain a live xDS ADS stream with simple multi-CP failover.
pub async fn start_xds_client_with_shutdown(
    jwt_secret: GrpcJwtSecret,
    config: XdsClientConfig,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
) {
    let cp_urls = config.cp_urls.clone();
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start xDS mesh client");
        return;
    }

    let mut current_cp_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut stream_state = XdsStreamState::default();
    let mut last_cp_url: Option<String> = None;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cluster = %config.cluster,
        cp_urls = cp_urls.len(),
        "xDS mesh client starting"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("xDS mesh client shutting down");
            return;
        }
        refresh_dp_grpc_tls_config_if_changed(
            &mut tls_config,
            tls_reload.as_ref(),
            &cp_urls,
            &mut last_tls_revision,
        );

        let cp_url = &cp_urls[current_cp_index];
        if last_cp_url.as_deref() != Some(cp_url.as_str()) {
            if let Some(previous_cp_url) = last_cp_url.as_deref() {
                info!(
                    previous_cp_url,
                    cp_url = %cp_url,
                    "xDS control plane changed; resetting ADS version state"
                );
                stream_state.reset_for_new_control_plane();
            }
            last_cp_url = Some(cp_url.clone());
        }
        let is_primary = current_cp_index == 0;
        let is_fallback = !is_primary && cp_urls.len() > 1;
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let should_race_primary = should_race_primary_retry(is_fallback, config.primary_retry_secs);
        let result = if should_race_primary {
            tokio::select! {
                result = connect_ads(
                    cp_url,
                    &jwt_secret,
                    &config,
                    state.clone(),
                    tls_config.as_ref(),
                    &mut stream_state,
                ) => result,
                _ = wait_for_first_slice_then_primary_retry(
                    state.clone(),
                    Duration::from_secs(config.primary_retry_secs),
                ) => {
                    info!(
                        primary_retry_secs = config.primary_retry_secs,
                        cp_url = %cp_url,
                        "xDS primary retry interval elapsed; reconnecting to primary CP"
                    );
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("xDS mesh client shutting down");
                    return;
                }
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    info!("Mesh gRPC TLS source changed; reconnecting xDS ADS stream");
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            tokio::select! {
                result = connect_ads(
                    cp_url,
                    &jwt_secret,
                    &config,
                    state.clone(),
                    tls_config.as_ref(),
                    &mut stream_state,
                ) => result,
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("xDS mesh client shutting down");
                    return;
                }
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    info!("Mesh gRPC TLS source changed; reconnecting xDS ADS stream");
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        };

        let increase_backoff = match result {
            Ok(()) => {
                warn!(
                    cp_url = %cp_url,
                    "xDS ADS stream ended; will reconnect"
                );
                if is_fallback {
                    current_cp_index = 0;
                }
                backoff_secs = BACKOFF_INITIAL_SECS;
                false
            }
            Err(e) => {
                error!(
                    cp_url = %cp_url,
                    error = %e,
                    "xDS ADS connection failed"
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
                info!("xDS mesh client shutting down");
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

async fn wait_for_first_slice_then_primary_retry(state: MeshRuntimeState, interval: Duration) {
    state.wait_for_first_slice().await;
    tokio::time::sleep(interval).await;
}

async fn connect_ads(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    config: &XdsClientConfig,
    state: MeshRuntimeState,
    tls_config: Option<&DpGrpcTlsConfig>,
    stream_state: &mut XdsStreamState,
) -> Result<(), anyhow::Error> {
    let mut endpoint = Channel::from_shared(cp_url.to_string())?;
    if config.connect_timeout_seconds > 0 {
        endpoint = endpoint.connect_timeout(Duration::from_secs(config.connect_timeout_seconds));
    }

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
    let auth = AdsAuth {
        jwt_secret: jwt_secret.clone(),
        node_id: config.node_id.clone(),
        namespace: config.namespace.clone(),
    };
    let consumer = XdsConfigConsumer::new(config.clone(), state);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cluster = %config.cluster,
        cp_url = %cp_url,
        "Connected to CP, subscribing for xDS ADS config"
    );

    run_ads_stream_with_auth(channel, Some(auth), config, &consumer, stream_state).await
}

async fn run_ads_stream_with_auth(
    channel: Channel,
    auth: Option<AdsAuth>,
    config: &XdsClientConfig,
    consumer: &XdsConfigConsumer,
    stream_state: &mut XdsStreamState,
) -> Result<(), anyhow::Error> {
    #[allow(clippy::result_large_err)]
    let mut client = AggregatedDiscoveryServiceClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            if let Some(auth) = auth.as_ref() {
                let token = auth.bearer_token()?;
                req.metadata_mut().insert("authorization", token);
            }
            Ok(req)
        },
    )
    .max_decoding_message_size(MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE);

    let (tx, rx) = mpsc::channel(config.stream_channel_capacity.max(1));
    let request_stream = ReceiverStream::new(rx);
    let mut response_stream = client
        .stream_aggregated_resources(request_stream)
        .await?
        .into_inner();

    // Nonce dedup is stream-scoped (per xDS spec). Clear the
    // per-type `last_processed_nonce` baseline so a deterministic-nonce CP
    // — one whose sequence counter resets on restart, or a load-balanced
    // reconnect to a peer replica — can legitimately reissue a previously
    // seen opaque nonce on this fresh stream without the DP discarding the
    // first response as a stale duplicate. `last_acked_version` and the
    // resource accumulator are intentionally NOT reset so the subscription
    // resumes from the last acknowledged state.
    stream_state.reset_for_new_stream();

    for request in stream_state.subscriptions.build_initial_requests(
        &config.node_id,
        &config.cluster,
        config.workload_spiffe_id.as_deref(),
        config.waypoint_name.as_deref(),
        config.ambient_udp_source_scoping,
    ) {
        tx.send(request)
            .await
            .map_err(|_| anyhow::anyhow!("xDS ADS request stream closed before initial request"))?;
    }

    let debounce = tokio::time::sleep(Duration::from_secs(60 * 60 * 24));
    tokio::pin!(debounce);
    let mut debounce_active = false;
    let mut pending_since: Option<tokio::time::Instant> = None;
    let mut pending_slice: Option<PendingXdsSlice> = None;

    loop {
        tokio::select! {
            response = response_stream.message() => {
                let Some(response) = response? else {
                    break;
                };
                let response_type_url = response.type_url.clone();
                let nack_count_before = stream_state
                    .nack_circuit_breaker
                    .consecutive_nacks(&response_type_url);
                match handle_ads_response(
                    response,
                    config,
                    &tx,
                    &mut stream_state.subscriptions,
                    &mut stream_state.accumulator,
                    &mut stream_state.nack_circuit_breaker,
                ).await {
                    Ok(Some(pending)) => {
                        pending_slice = Some(pending);
                        let now = tokio::time::Instant::now();
                        let first_pending_at = *pending_since.get_or_insert(now);
                        debounce
                            .as_mut()
                            .reset(next_xds_apply_deadline(now, first_pending_at));
                        debounce_active = true;
                    }
                    Ok(None) => {
                        if stream_state
                            .nack_circuit_breaker
                            .nacked_since(&response_type_url, nack_count_before)
                        {
                            discard_pending_xds_slice_after_nack(
                                config,
                                &mut pending_slice,
                                &response_type_url,
                            );
                            debounce_active = false;
                            pending_since = None;
                        }
                    }
                    Err(e) => {
                        if stream_state
                            .nack_circuit_breaker
                            .nacked_since(&response_type_url, nack_count_before)
                        {
                            discard_pending_xds_slice_after_nack(
                                config,
                                &mut pending_slice,
                                &response_type_url,
                            );
                            return Err(e);
                        }
                        return flush_pending_xds_slice_before_error(
                            consumer,
                            config,
                            &mut pending_slice,
                            e,
                        );
                    }
                }
                // Publish live warming-convergence state (per-type versions and
                // still-missing required types) for the JWT-authenticated
                // `/mesh/config-drift` endpoint. Reflects the accumulator after
                // this response, including a NACK rollback. The `Err` arms above
                // return before reaching here (the stream is being torn down).
                consumer
                    .state()
                    .set_xds_convergence(stream_state.accumulator.convergence_snapshot());
            }
            _ = &mut debounce, if debounce_active => {
                if let Some(pending) = pending_slice.take() {
                    apply_pending_xds_slice(consumer, config, pending)?;
                }
                debounce_active = false;
                pending_since = None;
            }
        }
    }

    if let Some(pending) = pending_slice.take() {
        apply_pending_xds_slice(consumer, config, pending)?;
    }

    Ok(())
}

fn discard_pending_xds_slice_after_nack(
    config: &XdsClientConfig,
    pending_slice: &mut Option<PendingXdsSlice>,
    nacked_type_url: &str,
) -> bool {
    let discarded = pending_slice.take().is_some();
    if discarded {
        warn!(
            node_id = %config.node_id,
            namespace = %config.namespace,
            type_url = %nacked_type_url,
            "Discarded debounced xDS slice after NACK to avoid applying mixed-version resources"
        );
    }
    discarded
}

fn flush_pending_xds_slice_before_error(
    consumer: &XdsConfigConsumer,
    config: &XdsClientConfig,
    pending_slice: &mut Option<PendingXdsSlice>,
    error: anyhow::Error,
) -> Result<(), anyhow::Error> {
    if let Some(pending) = pending_slice.take() {
        apply_pending_xds_slice(consumer, config, pending)?;
    }
    Err(error)
}

fn next_xds_apply_deadline(
    now: tokio::time::Instant,
    first_pending_at: tokio::time::Instant,
) -> tokio::time::Instant {
    std::cmp::min(
        now + XDS_APPLY_DEBOUNCE,
        first_pending_at + XDS_APPLY_MAX_DELAY,
    )
}

#[derive(Debug)]
struct PendingXdsSlice {
    slice: MeshSlice,
    type_url: String,
    all_types_ready: bool,
    /// True when this slice was built from a partial per-type update (required
    /// versions not all identical). Drives the `ferrum_xds_warming_partial_
    /// applies_total` counter at apply time.
    version_skew: bool,
}

async fn handle_ads_response(
    response: proto::DiscoveryResponse,
    config: &XdsClientConfig,
    tx: &mpsc::Sender<DiscoveryRequest>,
    subscriptions: &mut ClientSubscriptionState,
    accumulator: &mut ResourceAccumulator,
    nack_circuit_breaker: &mut NackCircuitBreaker,
) -> Result<Option<PendingXdsSlice>, anyhow::Error> {
    let type_url = response.type_url.clone();
    if !is_known_type_url(&type_url) {
        let message = format!("unknown xDS response type_url '{type_url}'");
        let mut nack = subscriptions.build_nack(&type_url, message.clone());
        nack.response_nonce = response.nonce.clone();
        send_ads_request(tx, nack).await?;
        warn!(
            node_id = %config.node_id,
            type_url = %type_url,
            "Received unknown xDS type_url; sent NACK"
        );
        return Ok(None);
    }

    debug!(
        node_id = %config.node_id,
        type_url = %type_url,
        version = %response.version_info,
        nonce = %response.nonce,
        resources = response.resources.len(),
        "Received xDS ADS response"
    );

    // Per-type nonce machine: ignore a server retransmit of a response we
    // already ACKed/NACKed instead of re-applying it and emitting a redundant
    // ACK (which the server would then treat as ACKing a stale nonce). This
    // mirrors the server-side `XdsNonceTracker` staleness handling on the
    // receiving side.
    if let ResponseNonceOutcome::StaleDuplicate { nonce } =
        subscriptions.record_response(&type_url, &response.version_info, &response.nonce)
    {
        debug!(
            node_id = %config.node_id,
            type_url = %type_url,
            nonce = %nonce,
            "Ignoring stale/duplicate xDS ADS response (nonce already processed)"
        );
        return Ok(None);
    }
    let snapshot = accumulator.clone();
    let apply_result =
        accumulator.apply_sotw_response(&type_url, &response.resources, &response.version_info);
    let slice_result = apply_result.and_then(|_| accumulator.try_build_mesh_slice(config));

    match slice_result {
        Ok(Some(slice)) => {
            send_ads_request(tx, subscriptions.build_ack(&type_url)).await?;
            subscriptions.mark_acked(&type_url);
            subscriptions.mark_processed(&type_url);
            nack_circuit_breaker.record_ack(&type_url);
            Ok(Some(PendingXdsSlice {
                slice,
                type_url,
                all_types_ready: subscriptions.required_types_have_initial_response(),
                version_skew: accumulator.required_versions_skewed(),
            }))
        }
        Ok(None) => {
            send_ads_request(tx, subscriptions.build_ack(&type_url)).await?;
            subscriptions.mark_acked(&type_url);
            subscriptions.mark_processed(&type_url);
            nack_circuit_breaker.record_ack(&type_url);
            debug!(
                node_id = %config.node_id,
                type_url = %type_url,
                "ACKed xDS ADS response while waiting for remaining resource types"
            );
            Ok(None)
        }
        Err(e) => {
            *accumulator = snapshot;
            let nack = subscriptions.build_nack(&type_url, e.clone());
            // First-slice NACK visibility: if a REQUIRED type is being NACKed
            // while the slice has not yet converged (the DP is still inside
            // `wait_for_first_slice()`), surface a clear operator signal. A
            // persistently malformed required type otherwise wedges startup
            // silently until the NACK circuit breaker trips.
            let blocking_first_slice =
                is_required_mesh_slice_type(&type_url) && !accumulator.has_required_types();
            let consecutive_after = nack_circuit_breaker.consecutive_nacks(&type_url) + 1;
            if blocking_first_slice {
                warn!(
                    node_id = %config.node_id,
                    namespace = %config.namespace,
                    type_url = %type_url,
                    consecutive_nacks = consecutive_after,
                    nack_limit = XDS_CONSECUTIVE_NACK_LIMIT,
                    error = %e,
                    "First mesh slice blocked: NACKing a required xDS type before initial convergence; \
                     repeated NACKs will trip the circuit breaker and force CP failover/reconnect"
                );
                crate::plugins::mesh::prometheus_helpers::increment_xds_first_slice_nack(
                    &config.namespace,
                    &type_url,
                );
            } else {
                warn!(
                    node_id = %config.node_id,
                    type_url = %type_url,
                    error = %e,
                    "NACKing invalid xDS ADS response"
                );
            }
            subscriptions.mark_processed(&type_url);
            let circuit_result =
                trip_nack_circuit_if_needed(config, nack_circuit_breaker, &type_url);
            send_ads_request(tx, nack).await?;
            circuit_result?;
            Ok(None)
        }
    }
}

fn is_required_mesh_slice_type(type_url: &str) -> bool {
    REQUIRED_MESH_SLICE_TYPE_URLS.contains(&type_url)
}

fn trip_nack_circuit_if_needed(
    config: &XdsClientConfig,
    nack_circuit_breaker: &mut NackCircuitBreaker,
    type_url: &str,
) -> Result<(), anyhow::Error> {
    let consecutive_nacks = nack_circuit_breaker.record_nack(type_url);
    if consecutive_nacks < XDS_CONSECUTIVE_NACK_LIMIT {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "xDS ADS NACK circuit breaker tripped for type_url '{}' after {} consecutive NACKs on node '{}'; closing stream to trigger reconnect/failover",
        type_url,
        consecutive_nacks,
        config.node_id
    ))
}

fn apply_pending_xds_slice(
    consumer: &XdsConfigConsumer,
    config: &XdsClientConfig,
    pending: PendingXdsSlice,
) -> Result<(), anyhow::Error> {
    let version = pending.slice.version.clone();
    let version_skew = pending.version_skew;
    consumer
        .apply_slice(pending.slice)
        .map_err(anyhow::Error::new)?;
    if version_skew {
        crate::plugins::mesh::prometheus_helpers::increment_xds_warming_partial_apply(
            &config.namespace,
        );
    }
    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        version = %version,
        type_url = %pending.type_url,
        all_types_ready = pending.all_types_ready,
        version_skew = version_skew,
        "Applied debounced xDS ADS update"
    );
    Ok(())
}

async fn send_ads_request(
    tx: &mpsc::Sender<DiscoveryRequest>,
    request: DiscoveryRequest,
) -> Result<(), anyhow::Error> {
    tx.send(request)
        .await
        .map_err(|_| anyhow::anyhow!("xDS ADS request stream closed"))
}

#[derive(Clone)]
pub struct XdsConfigConsumer {
    config: XdsClientConfig,
    state: MeshRuntimeState,
}

impl XdsConfigConsumer {
    pub fn new(config: XdsClientConfig, state: MeshRuntimeState) -> Self {
        // GAP-2K replaces the historical one-shot startup warning with a
        // per-slice debug emitted from `reverse_translate` when a slice has
        // CDS clusters but no ECDS DR-carrier resources. The constructor
        // intentionally stays quiet: it has no view into whether the CP
        // will ship the carrier path, and warning unconditionally would
        // spam every operator who DOES emit DR-carrier resources.
        Self { config, state }
    }

    pub fn config(&self) -> &XdsClientConfig {
        &self.config
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    /// Install a rebuilt slice, subject to the shared config-revision freshness
    /// gate (issue #2473).
    ///
    /// A quarantined slice returns its revision rejection so the ADS loop drops
    /// the stream and rotates to the next configured control plane. The
    /// previously installed slice keeps serving throughout.
    ///
    /// The ADS accumulator is deliberately NOT rewound. By the time the gate
    /// rules, the response has already been folded into the accumulator and
    /// ACKed (`handle_ads_response` rolls the accumulator back only for a
    /// NACK — a structurally invalid response). That is correct rather than
    /// leaky, because the accumulator is state-of-the-world state scoped to ONE
    /// control-plane URL: `XdsStreamState::reset_for_new_control_plane` clears
    /// it wholesale on failover, so a quarantined CP's resources can never mix
    /// into another CP's slice. Within one CP the retained resources are
    /// ordinary SotW resume state, and the required-type presence/version
    /// coherence gates still govern the next build — the freshness gate
    /// protects the serving generation, not the subscription. Rewinding the
    /// accumulator here would instead desynchronize it from the versions this
    /// client has already ACKed.
    ///
    /// The gate already recorded the reason-labelled metric and the sanitized
    /// diagnostic, so this only adds the xDS-side context.
    pub fn apply_slice(&self, slice: MeshSlice) -> Result<(), MeshRevisionRejection> {
        match self.state.install_slice(slice) {
            MeshSliceInstall::Installed => Ok(()),
            MeshSliceInstall::Quarantined(rejection) => {
                tracing::warn!(
                    reason = rejection.reason().as_metric_label(),
                    "Quarantined an xDS-built mesh slice on config-revision ordering; \
                     keeping the last-good slice and closing ADS for CP failover"
                );
                Err(rejection)
            }
        }
    }
}

fn reverse_translate(
    accumulator: &ResourceAccumulator,
    config: &XdsClientConfig,
) -> Result<MeshSlice, String> {
    let mut service_ports: BTreeMap<(String, String), BTreeSet<u16>> = BTreeMap::new();

    for type_url in [CDS_TYPE_URL, EDS_TYPE_URL] {
        for resource in accumulator.resources(type_url) {
            let parsed = parse_service_port_resource_name(&resource.name, "cluster")?;
            service_ports
                .entry((parsed.namespace, parsed.service))
                .or_default()
                .insert(parsed.port);
        }
    }

    for resource in accumulator.resources(LDS_TYPE_URL) {
        let parsed = parse_service_port_resource_name(&resource.name, "listener")?;
        service_ports
            .entry((parsed.namespace, parsed.service))
            .or_default()
            .insert(parsed.port);
    }

    for resource in accumulator.resources(RDS_TYPE_URL) {
        let parsed = parse_route_resource_name(&resource.name)?;
        if !service_ports.contains_key(&(parsed.namespace.clone(), parsed.service.clone())) {
            // Resource warming: xDS types arrive as independent responses, so a
            // route can legitimately land before the CDS/EDS/LDS response that
            // introduces its service. Treat a route referencing a not-yet-present
            // service as non-functional-for-now and SKIP it, rather than a
            // structural error. NACKing here would roll the accumulator back and
            // drop the new RDS — and the CP does not resend a NACKed SotW
            // resource until a reconnect or another RDS change, so the route
            // would be lost. Skipping keeps the RDS in the accumulator so it
            // validates cleanly once its service arrives; in Ferrum's name-only
            // model the route adds no slice content either way (services come
            // from CDS/EDS/LDS names or the ECDS Services carrier), so a
            // genuinely dangling route is simply inert (Envoy-aligned: a route
            // to an unknown cluster is ACKed, not NACKed) and never wedges
            // slice application for unrelated updates.
            debug!(
                node_id = %config.node_id,
                resource_name = %resource.name,
                namespace = %parsed.namespace,
                service = %parsed.service,
                "Skipping xDS route referencing a service not yet present in CDS/EDS/LDS (resource warming)"
            );
            continue;
        }
    }

    // GAP-2K: Recover full `MeshDestinationRule` semantics from ECDS resources
    // carrying the Ferrum-specific DR carrier type_url. Operators opt in
    // CP-side by wrapping the original DR JSON in a TypedExtensionConfig with
    // `inner.type_url == FERRUM_ECDS_DESTINATION_RULE_TYPE_URL`. Resources
    // with other inner type_urls are silently skipped — they belong to
    // unrelated extension configs.
    let mut destination_rules = Vec::new();
    let mut dr_carrier_seen = false;
    for resource in accumulator.resources(ECDS_TYPE_URL) {
        let reserved_dr_name = reserved_destination_rule_carrier_name(&resource.name)?;
        let typed_extension = match decode_ecds_typed_extension(resource) {
            Ok(value) => value,
            Err(e) => {
                if reserved_dr_name.is_some() {
                    return Err(e);
                }
                warn!(resource_name = %resource.name, error = %e, "xDS ECDS resource failed TypedExtensionConfig decode; skipping");
                continue;
            }
        };
        let Some(inner) = destination_rule_carrier_inner(resource, &typed_extension)? else {
            continue;
        };
        dr_carrier_seen = true;
        match serde_json::from_slice::<MeshDestinationRule>(&inner.value) {
            Ok(dr) => {
                if let Some((namespace, name)) = reserved_dr_name {
                    validate_reserved_destination_rule_carrier_name(
                        &resource.name,
                        namespace,
                        name,
                        &dr,
                    )?;
                } else if dr.namespace != config.namespace {
                    debug!(
                        name = %dr.name,
                        namespace = %dr.namespace,
                        workload_namespace = %config.namespace,
                        "Skipping xDS ECDS DR-carrier outside workload namespace"
                    );
                    continue;
                }
                debug!(
                    name = %dr.name,
                    namespace = %dr.namespace,
                    "Recovered MeshDestinationRule from xDS ECDS carrier"
                );
                destination_rules.push(dr);
            }
            Err(e) => {
                if reserved_dr_name.is_some() {
                    return Err(format!(
                        "xDS reserved DestinationRule ECDS carrier '{}' failed JSON decode: {e}",
                        typed_extension.name
                    ));
                }
                warn!(
                    resource_name = %typed_extension.name,
                    inner_type_url = %inner.type_url,
                    error = %e,
                    "xDS ECDS DR-carrier payload failed JSON decode; DR will be missing from slice"
                );
            }
        }
    }
    if !dr_carrier_seen && !accumulator.resources(CDS_TYPE_URL).is_empty() {
        // Per-DR diagnostic replaces the historical one-shot startup warning.
        // Operators using standard xDS without the carrier path see this once
        // per slice apply with the exact list of fields that cannot be
        // round-tripped from CDS/EDS. The carrier path silences this log.
        debug!(
            "xDS slice has no DR-carrier ECDS resources; per-cluster DR fields \
             (connectTimeout, loadBalancer, outlierDetection, subsets, tls.sni, \
             tls.subjectAltNames, tls.mode) are not recoverable from CDS/EDS alone. \
             Set FERRUM_MESH_CONFIG_PROTOCOL=native or have the CP emit Ferrum \
             DR-carrier ECDS resources to round-trip full DR semantics."
        );
    }

    // GAP-1a: recover the security- and policy-bearing slice fields from the
    // Ferrum mesh-slice ECDS carriers the CP emitted alongside CDS/EDS. These
    // carriers (one per non-empty field group) ride the same ECDS resource
    // list as the DR carrier above and are distinguished by their inner
    // `type_url`. Decoding them is what makes `FERRUM_MESH_CONFIG_PROTOCOL=xds`
    // functionally equivalent to native: without this pass the slice below
    // would have empty authz/PeerAuth/JWT/trust-bundle/ServiceEntry/
    // ProxyConfig/workload fields (an unprotected mesh).
    let recovered = recover_slice_carriers(accumulator)?;

    // Prefer the full `MeshService` shape recovered from the Services carrier
    // (protocol + per-service workload refs) over the name-only CDS/EDS
    // reconstruction. The reconstruction stays as the fallback for an older
    // Ferrum-shaped xDS CP that emits CDS/EDS but no Ferrum carrier.
    let services = if let Some(services) = recovered.services {
        services
    } else if recovered.slice_carrier_seen {
        Vec::new()
    } else {
        service_ports
            .into_iter()
            .map(|((namespace, name), ports)| MeshService {
                name,
                namespace,
                ports: ports
                    .into_iter()
                    .map(|port| ServicePort {
                        port,
                        protocol: AppProtocol::Unknown,
                        name: None,
                        target_port: None,
                    })
                    .collect(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
                // The name-only CDS/EDS reconstruction carries no Service
                // spec, so VIPs are unknown; the Ferrum Services carrier
                // (preferred branch above) round-trips them via serde.
                cluster_ips: Vec::new(),
            })
            .collect()
    };

    let mut trust_domains = Vec::new();
    let mut ignored_sds_names = Vec::new();
    for resource in accumulator.resources(SDS_TYPE_URL) {
        match parse_spiffe_bundle_secret_name(&resource.name) {
            Ok(trust_domain) => trust_domains.push(trust_domain),
            Err(e) => {
                debug!(
                    resource_name = %resource.name,
                    error = %e,
                    "Ignoring unsupported xDS SDS secret name"
                );
                ignored_sds_names.push(resource.name.clone());
            }
        }
    }
    log_omitted_sds_trust_domains(trust_domains);
    log_ignored_sds_resource_names(ignored_sds_names);

    // GAP-3E: merge RTDS layers into the slice's runtime overlay. The
    // accumulator canonicalizes resources by name independent of wire order;
    // lexicographically later names win on key conflicts. Layers
    // with empty `name` would have been rejected at name decode, so any
    // resource that reaches this point has a stable identity.
    let mut runtime_overlay = MeshRuntimeOverlay::default();
    for resource in accumulator.resources(RTDS_TYPE_URL) {
        match runtime_proto::Runtime::decode(resource.bytes.as_slice()) {
            Ok(layer) => {
                let overlay = translate_rtds_layer(&layer);
                for (key, value) in overlay.fields {
                    runtime_overlay.fields.insert(key, value);
                }
            }
            Err(e) => {
                warn!(
                    resource_name = %resource.name,
                    error = %e,
                    "xDS RTDS resource failed Runtime decode; skipping"
                );
            }
        }
    }

    Ok(MeshSlice {
        node_id: config.node_id.clone(),
        namespace: config.namespace.clone(),
        workload_spiffe_id: config.workload_spiffe_id.clone(),
        waypoint_name: config.waypoint_name.clone(),
        // A non-empty WorkloadLabels carrier is authoritative — the CP computed
        // real effective labels for this workload. An EMPTY carrier is NOT
        // treated as authoritative: a Ferrum CP always emits this carrier, and
        // it is empty whenever the CP could not compute labels for this DP (the
        // default non-SPIFFE `FERRUM_MESH_NODE_ID=HOSTNAME` plus the empty
        // `Node.metadata` the client sends give the CP nothing to derive from).
        // Overriding with an uninformed empty map would silently wipe the DP's
        // explicit `FERRUM_MESH_WORKLOAD_LABELS`, letting the workload evade
        // every selector-scoped PeerAuthentication / authz / telemetry policy
        // (a selector DENY or Strict-mTLS rule keyed on those labels would stop
        // matching). So fall back to the local labels when the carrier is empty
        // or absent; only a non-empty carrier replaces them.
        //
        // EXCEPTION (ambiguous shared-SPIFFE): when the CP marked the labels as
        // an ambiguous intersection (`LabelsAmbiguous` carrier), the non-empty
        // carrier is the intersection of several workloads sharing this SPIFFE,
        // NOT this DP's real labels. Treating it as authoritative would replace
        // the DP's own `FERRUM_MESH_WORKLOAD_LABELS` with a partial set and drop
        // the candidate-only selector policies the slice deliberately carried as
        // a superset — fail-open whenever the intersection is non-empty. So when
        // ambiguous AND the DP has its own local labels, prefer the DP's labels
        // so it re-filters the superset against its real identity. The DP keeps
        // the (informational) intersection only when it has no local labels at
        // all.
        labels: pick_recovered_labels(
            recovered.labels.filter(|l| !l.is_empty()),
            recovered.labels_ambiguous,
            &config.labels,
        ),
        // Clear the marker only when the recovered `labels` above are actually
        // authoritative for THIS DP: either the CP labels were unambiguous, or
        // the CP marked them ambiguous but the DP had its own local labels that
        // `pick_recovered_labels` preferred over the partial intersection. When
        // the CP marked them ambiguous AND the DP had no local labels, the
        // recovered `labels` are only the (partial/empty) intersection — NOT
        // authoritative — so the marker is PRESERVED. Clearing it there would
        // defeat the mesh_authz ambiguous-slice fail-closed check: the cold-path
        // retain would silently drop the candidate-only selector policies the
        // slice carried as a superset and fall back to allow-by-default
        // (fail-open). Downstream consumers (mesh_authz cold-path retain) treat
        // a still-set marker as "labels not final; fail closed for selectors
        // that the partial labels cannot satisfy".
        labels_ambiguous: recovered.labels_ambiguous
            && !recovered_labels_are_authoritative(recovered.labels_ambiguous, &config.labels),
        // Required xDS types are coherent before a slice is built, so this is
        // the shared observability version for the installed mesh slice.
        version: composite_required_version(accumulator),
        // Issue #2473: the authoritative ordering revision rides its own ECDS
        // carrier so an xDS-built slice materializes the same freshness
        // metadata a native-built one does and passes through the SAME
        // `MeshRuntimeState::install_slice` gate.
        revision: recovered.config_revision,
        // GAP-1a: workloads/endpoints recovered from the Workloads carrier.
        // Empty only when the CP emitted no carrier (older Ferrum-shaped xDS
        // CP) or the slice genuinely has no workloads.
        workloads: recovered.workloads,
        ambient_udp_source_workloads: recovered.ambient_udp_source_workloads,
        node_waypoint_assertors: recovered.node_waypoint_assertors,
        services,
        // Inbound-only un-narrowed local services recovered from the dedicated
        // carrier (kept separate from `services` so egress scope / the outbound
        // registry is never widened). Empty when the CP applied no Sidecar
        // narrowing; the materializer then falls back to `services`.
        local_inbound_services: recovered.local_inbound_services,
        // Local workload(s) preserved un-narrowed for inbound materialization
        // (Sidecar identity narrowing can drop the local pod from `workloads`).
        local_inbound_workloads: recovered.local_inbound_workloads,
        // F6 §6.2: resolved Sidecar ingress[] listeners recovered from the
        // LocalIngressListeners carrier. Empty when the CP modeled no custom
        // inbound listeners.
        local_ingress_listeners: recovered.local_ingress_listeners,
        // F6 §6.2 fail-closed marker: the applicable Sidecar declared a
        // non-empty `ingress[]`. Recovered from the dedicated carrier (emitted
        // even when `local_ingress_listeners` is empty), so an all-unsupported
        // `ingress[]` still suppresses the default inbound routes on the DP.
        sidecar_ingress_declared: recovered.sidecar_ingress_declared,
        // F6 §6.2: count of DISTINCT HTTP-family ingress[] listener ports the
        // workload declared, recovered from the dedicated carrier (emitted even
        // when it exceeds the resolved listener count). The DP router uses it to
        // keep a partially materialized ingress group ambiguous to an
        // orig-dst-less request rather than passing through to the survivor.
        declared_ingress_http_ports: recovered.declared_ingress_http_ports,
        // GAP-1a: authorization policies recovered from the MeshPolicies
        // carrier. Without this the xDS mesh had NO authz (implicit allow-all).
        mesh_policies: recovered.mesh_policies,
        virtual_service_cors_policies: recovered.virtual_service_cors_policies,
        // GAP-1a: PeerAuthentication mTLS posture recovered from the PeerAuth
        // carrier. Without this every port fell back to Permissive.
        peer_authentications: recovered.peer_authentications,
        // GAP-1a: JWT request-authentication rules recovered from the
        // RequestAuth carrier.
        request_authentications: recovered.request_authentications,
        telemetry_resources: recovered.telemetry_resources,
        // GAP-1a: full ServiceEntry shape recovered from the ServiceEntries
        // carrier. The name-only CDS/EDS path only reconstructed service
        // ports for routing; the carrier restores hosts/resolution/location/
        // endpoints needed for egress and outbound-policy behavior.
        service_entries: recovered.service_entries,
        // DestinationRule traffic policy is not exposed via standard xDS — its
        // semantics are baked into Envoy Cluster (LB algorithm, outlier
        // detection, connection pool) before the CP emits CDS, so we cannot
        // round-trip it back into a `MeshDestinationRule` directly.
        //
        // GAP-2K: when the CP wraps the original DR JSON in an ECDS
        // TypedExtensionConfig with `type_url ==
        // FERRUM_ECDS_DESTINATION_RULE_TYPE_URL`, the loop above recovers it
        // into `destination_rules`. Operators not running that carrier path
        // still need `FERRUM_MESH_CONFIG_PROTOCOL=native` for full DR
        // semantics; see docs/mesh.md ("DestinationRule support matrix").
        destination_rules,
        // GAP-1a: ProxyConfig recovered from the ProxyConfigs carrier.
        proxy_configs: recovered.proxy_configs,
        // GAP-1a: SPIFFE trust bundles recovered from the TrustBundles
        // carrier. Without this xDS inbound mTLS had no peer-cert authority
        // material. SDS resource names (the only standard-xDS signal) carry no
        // authority bytes, so the carrier is the sole round-trip path.
        trust_bundles: recovered.trust_bundles,
        multi_cluster: recovered.multi_cluster,
        // GAP-1a: mesh-wide outbound traffic policy recovered from the
        // OutboundTrafficPolicy carrier.
        outbound_traffic_policy: recovered.outbound_traffic_policy,
        sidecar_egress_scope: recovered.sidecar_egress_scope,
        // GAP-2L.3: xDS-only deployments don't round-trip operator-defined
        // ECDS resources back into the slice today. The carrier paths
        // (GAP-2K DR carrier, GAP-1a slice carriers) land their fields in the
        // dedicated slice fields above instead.
        extension_configs: Vec::new(),
        // GAP-3E: merged RTDS layers. Empty when no Runtime resources have
        // shipped on this stream.
        runtime_overlay,
    })
}

/// Resolve the recovered slice's effective labels for this DP.
///
/// `carrier_labels` is the non-empty `WorkloadLabels` carrier (already filtered
/// to `None` when empty/absent); `ambiguous` is the `LabelsAmbiguous` marker;
/// `local_labels` is the DP's own `FERRUM_MESH_WORKLOAD_LABELS`.
///
/// - Not ambiguous: a non-empty carrier is authoritative (the CP computed real
///   labels); otherwise fall back to the DP's local labels.
/// - Ambiguous: the carrier is a shared-SPIFFE INTERSECTION — the labels common
///   to every candidate sharing this SPIFFE, NOT this DP's full real label set.
///   That intersection is still AUTHORITATIVE for the keys it carries: the CP
///   proved every candidate has them, so a selector scoped on an intersection key
///   (e.g. `app=shared`) applies to this DP regardless of which candidate it is.
///   When the DP supplies its own local labels (e.g. the disambiguating
///   `role=api`), MERGE them ONTO the intersection rather than replacing it: the
///   merged set resolves the divergent keys via the DP's authoritative local
///   labels while preserving the common keys the CP proved apply, so a selector
///   DENY / PeerAuth STRICT / JWT rule scoped to a common key stays enforced
///   instead of being dropped (the wholesale-replace fail-open). Local labels win
///   on a key collision (the DP's own identity is final for keys it declares). If
///   the DP has no local labels either, keep the informational intersection.
fn pick_recovered_labels(
    carrier_labels: Option<BTreeMap<String, String>>,
    ambiguous: bool,
    local_labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    if ambiguous && !local_labels.is_empty() {
        // Start from the common intersection (authoritative per-key for the keys
        // every candidate shares) and overlay the DP's local labels so divergent
        // keys resolve to this workload's real values while the common keys
        // survive. `extend` makes `local_labels` win on collision.
        let mut merged = carrier_labels.unwrap_or_default();
        merged.extend(local_labels.iter().map(|(k, v)| (k.clone(), v.clone())));
        return merged;
    }
    carrier_labels.unwrap_or_else(|| local_labels.clone())
}

/// Whether the labels [`pick_recovered_labels`] produced are AUTHORITATIVE for
/// this DP, so the `labels_ambiguous` marker can be cleared in the recovered
/// slice.
///
/// Recovery is authoritative when the CP did not mark the labels ambiguous (the
/// non-empty carrier — or the DP's own local labels for an empty carrier — is
/// trustworthy), or when the CP marked them ambiguous but the DP supplied its
/// own local `FERRUM_MESH_WORKLOAD_LABELS` that [`pick_recovered_labels`] then
/// preferred over the partial intersection. When the CP marked the labels
/// ambiguous AND the DP had no local labels, `pick_recovered_labels` falls back
/// to the partial intersection (or empty), which is NOT this workload's real
/// label set: the candidate-only selector policies the slice carried as a
/// superset cannot be re-filtered here, so the marker MUST be preserved so the
/// mesh_authz ambiguous-slice fail-closed check still runs instead of letting
/// the cold-path `retain` silently drop those selector DENY/ALLOW/PeerAuth/JWT
/// rules and fall back to allow-by-default.
fn recovered_labels_are_authoritative(
    ambiguous: bool,
    local_labels: &BTreeMap<String, String>,
) -> bool {
    !ambiguous || !local_labels.is_empty()
}

/// Slice fields recovered from Ferrum mesh-slice ECDS carriers (GAP-1a).
///
/// `services` is `Option` so the caller can distinguish "the CP shipped a
/// Services carrier" (use it verbatim) from "no carrier; fall back to the
/// name-only CDS/EDS reconstruction". The other fields default to empty/`None`,
/// which matches both "carrier absent" and "carrier present but empty" — the
/// same indistinguishability native config has between an empty list and an
/// absent list.
#[derive(Debug, Default)]
struct RecoveredSliceCarriers {
    slice_carrier_seen: bool,
    services: Option<Vec<MeshService>>,
    local_inbound_services: Vec<MeshService>,
    local_inbound_workloads: Option<Vec<crate::modes::mesh::config::Workload>>,
    local_ingress_listeners: Vec<crate::modes::mesh::config::ResolvedIngressListener>,
    sidecar_ingress_declared: bool,
    declared_ingress_http_ports: usize,
    labels: Option<BTreeMap<String, String>>,
    labels_ambiguous: bool,
    /// Authoritative config revision (issue #2473) recovered from the
    /// `ConfigRevision` carrier. `None` when the CP's config authority is
    /// unordered (or predates the carrier) — the DP freshness gate then treats
    /// the rebuilt slice exactly like a native slice with no `revision`.
    config_revision: Option<crate::modes::mesh::revision::MeshConfigRevision>,
    workloads: Vec<crate::modes::mesh::config::Workload>,
    ambient_udp_source_workloads: Vec<crate::modes::mesh::config::Workload>,
    node_waypoint_assertors: Vec<crate::identity::spiffe::SpiffeId>,
    mesh_policies: Vec<crate::modes::mesh::config::MeshPolicy>,
    virtual_service_cors_policies: Vec<crate::modes::mesh::config::MeshVirtualServiceCorsPolicy>,
    peer_authentications: Vec<crate::modes::mesh::config::PeerAuthentication>,
    request_authentications: Vec<crate::modes::mesh::config::MeshRequestAuthentication>,
    service_entries: Vec<crate::modes::mesh::config::ServiceEntry>,
    telemetry_resources: Vec<crate::modes::mesh::config::MeshTelemetryResource>,
    proxy_configs: Vec<crate::modes::mesh::config::MeshProxyConfig>,
    trust_bundles: Option<crate::modes::mesh::config::TrustBundleSet>,
    outbound_traffic_policy: Option<crate::modes::mesh::config::OutboundTrafficPolicy>,
    multi_cluster: Option<crate::modes::mesh::config::MultiClusterConfig>,
    sidecar_egress_scope: Option<MeshEgressScopeSnapshot>,
}

/// Decode every Ferrum mesh-slice ECDS carrier in `accumulator` and fold it
/// into a [`RecoveredSliceCarriers`].
///
/// ECDS resources that are not Ferrum slice carriers (the DR carrier, or any
/// operator-defined extension config) are skipped. A recognized slice carrier
/// whose JSON fails to parse rejects the ECDS response so the client NACKs it
/// and retains the previous protected slice instead of clearing security fields
/// fail-open.
fn recover_slice_carriers(
    accumulator: &ResourceAccumulator,
) -> Result<RecoveredSliceCarriers, String> {
    use crate::xds::carrier::MeshSliceCarrier;

    let mut recovered = RecoveredSliceCarriers::default();
    for resource in accumulator.resources(ECDS_TYPE_URL) {
        let typed_extension = match decode_ecds_typed_extension(resource) {
            Ok(value) => value,
            // The DR-carrier loop already warned on this same resource; stay
            // quiet here to avoid double-logging the same decode failure.
            Err(_) => continue,
        };
        let Some(inner) = mesh_slice_carrier_inner(resource, &typed_extension, false)? else {
            continue;
        };
        match MeshSliceCarrier::decode(&inner.type_url, &inner.value) {
            Ok(Some(carrier)) => apply_recovered_carrier(&mut recovered, carrier),
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "xDS mesh-slice ECDS carrier '{}' failed JSON decode for '{}': {e}",
                    typed_extension.name, inner.type_url
                ));
            }
        }
    }
    Ok(recovered)
}

fn validate_ecds_mesh_slice_carrier(resource: &AccumulatedResource) -> Result<(), String> {
    let typed_extension = decode_ecds_typed_extension(resource)?;
    let Some(inner) = mesh_slice_carrier_inner(resource, &typed_extension, true)? else {
        return Ok(());
    };
    if let Err(e) = crate::xds::carrier::MeshSliceCarrier::decode(&inner.type_url, &inner.value) {
        return Err(format!(
            "xDS mesh-slice ECDS carrier '{}' failed JSON decode for '{}': {e}",
            typed_extension.name, inner.type_url
        ));
    }
    Ok(())
}

fn validate_ecds_destination_rule_carrier(resource: &AccumulatedResource) -> Result<(), String> {
    let Some((namespace, name)) = reserved_destination_rule_carrier_name(&resource.name)? else {
        return Ok(());
    };
    let typed_extension = decode_ecds_typed_extension(resource)?;
    let Some(inner) = destination_rule_carrier_inner(resource, &typed_extension)? else {
        return Ok(());
    };
    let dr = serde_json::from_slice::<MeshDestinationRule>(&inner.value).map_err(|e| {
        format!(
            "xDS reserved DestinationRule ECDS carrier '{}' failed JSON decode: {e}",
            typed_extension.name
        )
    })?;
    validate_reserved_destination_rule_carrier_name(&resource.name, namespace, name, &dr)
}

fn decode_ecds_typed_extension(
    resource: &AccumulatedResource,
) -> Result<proto::TypedExtensionConfig, String> {
    proto::TypedExtensionConfig::decode(resource.bytes.as_slice()).map_err(|e| {
        format!(
            "xDS ECDS resource '{}' failed TypedExtensionConfig decode: {e}",
            resource.name
        )
    })
}

fn reserved_destination_rule_carrier_name(name: &str) -> Result<Option<(&str, &str)>, String> {
    let Some(rest) = name.strip_prefix(FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX) else {
        return Ok(None);
    };
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!(
            "xDS ECDS resource '{name}' uses reserved Ferrum DestinationRule carrier name but must be named '{FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX}{{namespace}}/{{name}}'"
        ));
    }
    Ok(Some((parts[0], parts[1])))
}

fn validate_reserved_destination_rule_carrier_name(
    resource_name: &str,
    expected_namespace: &str,
    expected_name: &str,
    dr: &MeshDestinationRule,
) -> Result<(), String> {
    if dr.namespace == expected_namespace && dr.name == expected_name {
        return Ok(());
    }
    Err(format!(
        "xDS reserved DestinationRule ECDS carrier '{resource_name}' embeds DestinationRule '{}/{}' but reserved name targets '{}/{}'",
        dr.namespace, dr.name, expected_namespace, expected_name
    ))
}

fn destination_rule_carrier_inner<'a>(
    resource: &AccumulatedResource,
    typed_extension: &'a proto::TypedExtensionConfig,
) -> Result<Option<&'a proto::Any>, String> {
    let resource_name_is_reserved =
        reserved_destination_rule_carrier_name(&resource.name)?.is_some();
    let Some(inner) = typed_extension.typed_config.as_ref() else {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses reserved Ferrum DestinationRule carrier name without typed_config",
                resource.name
            ));
        }
        return Ok(None);
    };
    if inner.type_url != FERRUM_ECDS_DESTINATION_RULE_TYPE_URL {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses reserved Ferrum DestinationRule carrier name with non-DR type_url '{}'",
                resource.name, inner.type_url
            ));
        }
        return Ok(None);
    }
    Ok(Some(inner))
}

fn mesh_slice_carrier_inner<'a>(
    resource: &AccumulatedResource,
    typed_extension: &'a proto::TypedExtensionConfig,
    warn_on_non_reserved_name: bool,
) -> Result<Option<&'a proto::Any>, String> {
    use crate::xds::carrier::{
        FERRUM_CARRIER_RESOURCE_NAME_PREFIX, carrier_resource_name_for_type_url,
    };
    use crate::xds::translator::FERRUM_ECDS_DESTINATION_RULE_TYPE_URL;

    let resource_name_is_reserved = resource
        .name
        .starts_with(FERRUM_CARRIER_RESOURCE_NAME_PREFIX);
    let Some(inner) = typed_extension.typed_config.as_ref() else {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses reserved Ferrum mesh-slice carrier name without typed_config",
                resource.name
            ));
        }
        return Ok(None);
    };
    // The DR carrier rides the same ECDS stream but is handled by the
    // dedicated loop above; reject it if it tries to use a reserved slice
    // carrier name.
    if inner.type_url == FERRUM_ECDS_DESTINATION_RULE_TYPE_URL {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses reserved Ferrum mesh-slice carrier name with non-carrier type_url '{}'",
                resource.name, inner.type_url
            ));
        }
        return Ok(None);
    }
    let Some(expected_name) = carrier_resource_name_for_type_url(&inner.type_url) else {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses reserved Ferrum mesh-slice carrier name with non-carrier type_url '{}'",
                resource.name, inner.type_url
            ));
        }
        return Ok(None);
    };
    if resource.name != expected_name {
        if resource_name_is_reserved {
            return Err(format!(
                "xDS ECDS resource '{}' uses carrier type_url '{}' but must be named '{}'",
                resource.name, inner.type_url, expected_name
            ));
        }
        if warn_on_non_reserved_name {
            warn!(
                resource_name = %resource.name,
                expected_name = %expected_name,
                inner_type_url = %inner.type_url,
                "xDS ECDS resource used reserved Ferrum mesh-slice carrier type_url with non-reserved name; skipping"
            );
        }
        return Ok(None);
    }
    Ok(Some(inner))
}

fn apply_recovered_carrier(
    recovered: &mut RecoveredSliceCarriers,
    carrier: crate::xds::carrier::MeshSliceCarrier,
) {
    use crate::xds::carrier::MeshSliceCarrier;
    recovered.slice_carrier_seen = true;
    match carrier {
        MeshSliceCarrier::Services(value) => recovered.services = Some(value),
        MeshSliceCarrier::LocalInboundServices(value) => recovered.local_inbound_services = value,
        MeshSliceCarrier::LocalInboundWorkloads(value) => {
            recovered.local_inbound_workloads = Some(value)
        }
        MeshSliceCarrier::LocalIngressListeners(value) => recovered.local_ingress_listeners = value,
        MeshSliceCarrier::SidecarIngressDeclared(value) => {
            recovered.sidecar_ingress_declared = value
        }
        MeshSliceCarrier::SidecarIngressDeclaredPorts(value) => {
            recovered.declared_ingress_http_ports = value
        }
        MeshSliceCarrier::ConfigRevision(value) => recovered.config_revision = Some(value),
        MeshSliceCarrier::Workloads(value) => recovered.workloads = value,
        MeshSliceCarrier::AmbientUdpSourceWorkloads(value) => {
            recovered.ambient_udp_source_workloads = value
        }
        MeshSliceCarrier::NodeWaypointAssertors(value) => recovered.node_waypoint_assertors = value,
        MeshSliceCarrier::WorkloadLabels(value) => recovered.labels = Some(value),
        MeshSliceCarrier::LabelsAmbiguous(value) => recovered.labels_ambiguous = value,
        MeshSliceCarrier::MeshPolicies(value) => recovered.mesh_policies = value,
        MeshSliceCarrier::VirtualServiceCorsPolicies(value) => {
            recovered.virtual_service_cors_policies = value
        }
        MeshSliceCarrier::PeerAuthentications(value) => recovered.peer_authentications = value,
        MeshSliceCarrier::RequestAuthentications(value) => {
            recovered.request_authentications = value
        }
        MeshSliceCarrier::ServiceEntries(value) => recovered.service_entries = value,
        MeshSliceCarrier::TelemetryResources(value) => recovered.telemetry_resources = value,
        MeshSliceCarrier::ProxyConfigs(value) => recovered.proxy_configs = value,
        MeshSliceCarrier::TrustBundles(value) => recovered.trust_bundles = Some(value),
        MeshSliceCarrier::OutboundTrafficPolicy(value) => {
            recovered.outbound_traffic_policy = Some(value)
        }
        MeshSliceCarrier::MultiCluster(value) => recovered.multi_cluster = Some(value),
        MeshSliceCarrier::SidecarEgressScope(value) => recovered.sidecar_egress_scope = Some(value),
    }
}

fn decode_resource_name(type_url: &str, value: &[u8]) -> Result<String, String> {
    match type_url {
        CDS_TYPE_URL => proto::Cluster::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Cluster resource: {e}")),
        EDS_TYPE_URL => proto::ClusterLoadAssignment::decode(value)
            .map(|resource| resource.cluster_name)
            .map_err(|e| format!("failed to decode ClusterLoadAssignment resource: {e}")),
        LDS_TYPE_URL => proto::Listener::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Listener resource: {e}")),
        RDS_TYPE_URL => proto::RouteConfiguration::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode RouteConfiguration resource: {e}")),
        SDS_TYPE_URL => proto::Secret::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Secret resource: {e}")),
        ECDS_TYPE_URL => proto::TypedExtensionConfig::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode TypedExtensionConfig resource: {e}")),
        RTDS_TYPE_URL => runtime_proto::Runtime::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Runtime resource: {e}")),
        other => Err(format!("unknown xDS type_url '{other}'")),
    }
}

fn validate_resource_name_shape(type_url: &str, name: &str) -> Result<(), String> {
    match type_url {
        CDS_TYPE_URL | EDS_TYPE_URL => {
            parse_service_port_resource_name(name, "cluster").map(|_| ())
        }
        LDS_TYPE_URL => parse_service_port_resource_name(name, "listener").map(|_| ()),
        RDS_TYPE_URL => parse_route_resource_name(name).map(|_| ()),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServicePortResourceName {
    namespace: String,
    service: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceResourceName {
    namespace: String,
    service: String,
}

fn parse_service_port_resource_name(
    name: &str,
    expected_prefix: &str,
) -> Result<ServicePortResourceName, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 4 || parts[0] != expected_prefix {
        return Err(format!(
            "resource name '{name}' must use '{expected_prefix}/{{namespace}}/{{service}}/{{port}}'"
        ));
    }
    let namespace = parts[1];
    let service = parts[2];
    if namespace.is_empty() || service.is_empty() {
        return Err(format!(
            "resource name '{name}' must include non-empty namespace and service"
        ));
    }
    let port = parts[3].parse::<u16>().map_err(|e| {
        format!(
            "resource name '{name}' has invalid port '{}': {e}",
            parts[3]
        )
    })?;
    if port == 0 {
        return Err(format!("resource name '{name}' must use a non-zero port"));
    }
    Ok(ServicePortResourceName {
        namespace: namespace.to_string(),
        service: service.to_string(),
        port,
    })
}

fn parse_route_resource_name(name: &str) -> Result<ServiceResourceName, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 3 || parts[0] != "route" {
        return Err(format!(
            "resource name '{name}' must use 'route/{{namespace}}/{{service}}'"
        ));
    }
    let namespace = parts[1];
    let service = parts[2];
    if namespace.is_empty() || service.is_empty() {
        return Err(format!(
            "resource name '{name}' must include non-empty namespace and service"
        ));
    }
    Ok(ServiceResourceName {
        namespace: namespace.to_string(),
        service: service.to_string(),
    })
}

fn parse_spiffe_bundle_secret_name(name: &str) -> Result<String, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 3 || parts[0] != "secret" || parts[1] != "spiffe-bundle" {
        return Err(format!(
            "resource name '{name}' must use 'secret/spiffe-bundle/{{trust_domain}}'"
        ));
    }
    let trust_domain = parts[2];
    if trust_domain.is_empty() {
        return Err(format!(
            "resource name '{name}' must include a trust domain"
        ));
    }
    Ok(trust_domain.to_string())
}

fn log_omitted_sds_trust_domains(mut trust_domains: Vec<String>) {
    if trust_domains.is_empty() {
        return;
    }

    trust_domains.sort();
    trust_domains.dedup();

    debug!(
        trust_domains = ?trust_domains,
        "xDS SDS resource names do not include authority material; omitting trust bundles"
    );
}

fn log_ignored_sds_resource_names(mut names: Vec<String>) {
    if names.is_empty() {
        return;
    }

    names.sort();
    names.dedup();

    debug!(
        resource_names = ?names,
        "Ignored xDS SDS resources with unsupported secret names"
    );
}

fn is_known_type_url(type_url: &str) -> bool {
    XDS_TYPE_URLS.contains(&type_url)
}

/// Short, operator-friendly label for an xDS type URL, used as the key in the
/// convergence snapshot (`cds`/`eds`/`lds`/`rds`/`sds`/`ecds`/`rtds`). Falls
/// back to the full type URL for an unrecognized type.
fn xds_type_short_name(type_url: &str) -> &str {
    match type_url {
        CDS_TYPE_URL => "cds",
        EDS_TYPE_URL => "eds",
        LDS_TYPE_URL => "lds",
        RDS_TYPE_URL => "rds",
        SDS_TYPE_URL => "sds",
        ECDS_TYPE_URL => "ecds",
        RTDS_TYPE_URL => "rtds",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xds::translator::translate_mesh_slice_to_snapshot;

    fn test_config() -> XdsClientConfig {
        XdsClientConfig {
            cp_urls: vec!["http://cp:50051".to_string()],
            node_id: "node-a".to_string(),
            cluster: "default".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            stream_channel_capacity: 32,
            primary_retry_secs: 300,
            connect_timeout_seconds: 10,
            labels: BTreeMap::new(),
        }
    }

    fn any_resource(type_url: &str, name: &str) -> proto::Any {
        let value = match type_url {
            CDS_TYPE_URL => proto::Cluster {
                name: name.to_string(),
            }
            .encode_to_vec(),
            EDS_TYPE_URL => proto::ClusterLoadAssignment {
                cluster_name: name.to_string(),
            }
            .encode_to_vec(),
            LDS_TYPE_URL => proto::Listener {
                name: name.to_string(),
            }
            .encode_to_vec(),
            RDS_TYPE_URL => proto::RouteConfiguration {
                name: name.to_string(),
            }
            .encode_to_vec(),
            SDS_TYPE_URL => proto::Secret {
                name: name.to_string(),
            }
            .encode_to_vec(),
            ECDS_TYPE_URL => proto::TypedExtensionConfig {
                name: name.to_string(),
                typed_config: Some(proto::Any {
                    type_url: "type.googleapis.com/ferrum.test.Ecds".to_string(),
                    value: b"opaque".to_vec(),
                }),
            }
            .encode_to_vec(),
            RTDS_TYPE_URL => runtime_proto::Runtime {
                name: name.to_string(),
                layer: None,
            }
            .encode_to_vec(),
            other => panic!("unknown test type_url: {other}"),
        };
        proto::Any {
            type_url: type_url.to_string(),
            value,
        }
    }

    fn discovery_response(
        type_url: &str,
        version: &str,
        nonce: &str,
        resources: Vec<proto::Any>,
    ) -> proto::DiscoveryResponse {
        proto::DiscoveryResponse {
            version_info: version.to_string(),
            resources,
            canary: false,
            type_url: type_url.to_string(),
            nonce: nonce.to_string(),
            control_plane: None,
        }
    }

    fn apply_all_empty(accumulator: &mut ResourceAccumulator) {
        for type_url in XDS_TYPE_URLS {
            if !accumulator.versions_by_type.contains_key(type_url) {
                accumulator
                    .apply_sotw_response(type_url, &[], "v1")
                    .expect("empty response applies");
            }
        }
    }

    fn runtime_resource(name: &str, fields: &[(&str, runtime_proto::value::Kind)]) -> proto::Any {
        let fields = fields
            .iter()
            .map(|(key, kind)| {
                (
                    (*key).to_string(),
                    runtime_proto::Value {
                        kind: Some(kind.clone()),
                    },
                )
            })
            .collect();
        proto::Any {
            type_url: RTDS_TYPE_URL.to_string(),
            value: runtime_proto::Runtime {
                name: name.to_string(),
                layer: Some(runtime_proto::Struct { fields }),
            }
            .encode_to_vec(),
        }
    }

    fn coherent_accumulator_with_rtds(resources: &[proto::Any]) -> ResourceAccumulator {
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(ECDS_TYPE_URL, &[], "v1")
            .expect("ECDS apply");
        accumulator
            .apply_sotw_response(RTDS_TYPE_URL, resources, "rtds-v1")
            .expect("RTDS apply");
        accumulator
    }

    #[test]
    fn rtds_precedence_is_lexicographic_and_wire_order_independent() {
        use crate::modes::mesh::config::RuntimeValue;
        use runtime_proto::value::Kind;

        let base = runtime_resource(
            "10-base",
            &[
                (
                    "ferrum.fault_injection.checkout.abort_percent",
                    Kind::NumberValue(10.0),
                ),
                (
                    "ferrum.request_transformer.checkout.enabled",
                    Kind::BoolValue(false),
                ),
            ],
        );
        let override_layer = runtime_resource(
            "90-override",
            &[
                (
                    "ferrum.fault_injection.checkout.abort_percent",
                    Kind::NumberValue(75.0),
                ),
                (
                    "ferrum.request_transformer.checkout.enabled",
                    Kind::BoolValue(true),
                ),
            ],
        );

        for resources in [
            vec![base.clone(), override_layer.clone()],
            vec![override_layer.clone(), base.clone()],
        ] {
            let accumulator = coherent_accumulator_with_rtds(&resources);
            let names = accumulator
                .resources(RTDS_TYPE_URL)
                .iter()
                .map(|resource| resource.name.as_str())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["10-base", "90-override"]);

            let slice = accumulator
                .try_build_mesh_slice(&test_config())
                .expect("reverse translation")
                .expect("required types are coherent");
            assert_eq!(
                slice
                    .runtime_overlay
                    .fields
                    .get("ferrum.fault_injection.checkout.abort_percent"),
                Some(&RuntimeValue::Number(75.0))
            );
            assert_eq!(
                slice
                    .runtime_overlay
                    .fields
                    .get("ferrum.request_transformer.checkout.enabled"),
                Some(&RuntimeValue::Bool(true))
            );
        }
    }

    #[test]
    fn rtds_sotw_replacement_drops_removed_override_layer() {
        use crate::modes::mesh::config::RuntimeValue;
        use runtime_proto::value::Kind;

        let base = runtime_resource(
            "10-base",
            &[
                (
                    "ferrum.fault_injection.checkout.delay_percent",
                    Kind::NumberValue(10.0),
                ),
                (
                    "ferrum.request_transformer.checkout.enabled",
                    Kind::BoolValue(false),
                ),
            ],
        );
        let override_layer = runtime_resource(
            "90-override",
            &[
                (
                    "ferrum.fault_injection.checkout.delay_percent",
                    Kind::NumberValue(90.0),
                ),
                (
                    "ferrum.request_transformer.checkout.enabled",
                    Kind::BoolValue(true),
                ),
            ],
        );
        let mut accumulator = coherent_accumulator_with_rtds(&[override_layer, base.clone()]);
        accumulator
            .apply_sotw_response(RTDS_TYPE_URL, &[base], "rtds-v2")
            .expect("replacement applies");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translation")
            .expect("required types are coherent");
        assert_eq!(
            slice
                .runtime_overlay
                .fields
                .get("ferrum.fault_injection.checkout.delay_percent"),
            Some(&RuntimeValue::Number(10.0))
        );
        assert_eq!(
            slice
                .runtime_overlay
                .fields
                .get("ferrum.request_transformer.checkout.enabled"),
            Some(&RuntimeValue::Bool(false))
        );
    }

    #[test]
    fn duplicate_rtds_resource_name_is_rejected_without_replacing_prior_set() {
        use runtime_proto::value::Kind;

        let old = runtime_resource(
            "stable",
            &[("ferrum.log.level", Kind::StringValue("info".to_string()))],
        );
        let mut accumulator = coherent_accumulator_with_rtds(std::slice::from_ref(&old));
        let duplicate_a = runtime_resource(
            "duplicate",
            &[("ferrum.log.level", Kind::StringValue("debug".to_string()))],
        );
        let duplicate_b = runtime_resource(
            "duplicate",
            &[("ferrum.log.level", Kind::StringValue("warn".to_string()))],
        );
        let error = accumulator
            .apply_sotw_response(RTDS_TYPE_URL, &[duplicate_a, duplicate_b], "rtds-v2")
            .expect_err("duplicate Runtime names must NACK");

        assert!(error.contains("duplicate Runtime resource name 'duplicate'"));
        assert_eq!(accumulator.resources(RTDS_TYPE_URL).len(), 1);
        assert_eq!(accumulator.resources(RTDS_TYPE_URL)[0].name, "stable");
        assert_eq!(
            accumulator
                .versions_by_type
                .get(RTDS_TYPE_URL)
                .map(String::as_str),
            Some("rtds-v1")
        );
    }

    fn service_port_map(slice: &MeshSlice) -> BTreeMap<(String, String), Vec<u16>> {
        slice
            .services
            .iter()
            .map(|service| {
                let mut ports: Vec<u16> = service.ports.iter().map(|port| port.port).collect();
                ports.sort_unstable();
                ((service.namespace.clone(), service.name.clone()), ports)
            })
            .collect()
    }

    #[test]
    fn initial_requests_are_ordered_cds_first() {
        let requests = ClientSubscriptionState::new()
            .build_initial_requests("node-a", "default", None, None, false);
        let type_urls: Vec<&str> = requests
            .iter()
            .map(|request| request.type_url.as_str())
            .collect();

        assert_eq!(
            type_urls,
            vec![
                CDS_TYPE_URL,
                EDS_TYPE_URL,
                LDS_TYPE_URL,
                RDS_TYPE_URL,
                SDS_TYPE_URL,
                ECDS_TYPE_URL,
                RTDS_TYPE_URL,
            ]
        );
        assert!(requests.iter().all(|request| request.node.is_some()));
        assert!(
            requests
                .iter()
                .all(|request| request.resource_names.is_empty())
        );
    }

    #[test]
    fn initial_requests_carry_workload_spiffe_in_node_metadata() {
        // The CP needs the workload SPIFFE to compute Sidecar narrowing / the
        // local-inbound view; it travels in `Node.metadata` so a hostname
        // `node_id` still works.
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let requests = ClientSubscriptionState::new().build_initial_requests(
            "host-1",
            "default",
            Some(spiffe),
            Some("waypoint"),
            false,
        );
        let node = requests[0].node.as_ref().expect("node present");
        let metadata = crate::xds::carrier::decode_node_metadata(&node.metadata);
        assert_eq!(metadata.workload_spiffe_id.as_deref(), Some(spiffe));
        assert_eq!(metadata.waypoint_name.as_deref(), Some("waypoint"));
        // Without a workload SPIFFE, metadata stays empty (prior wire shape).
        let none = ClientSubscriptionState::new()
            .build_initial_requests("host-1", "default", None, None, false);
        assert!(none[0].node.as_ref().unwrap().metadata.is_empty());
    }

    #[test]
    fn initial_type_url_order_matches_supported_type_set() {
        let supported: BTreeSet<_> = XDS_TYPE_URLS.iter().copied().collect();
        let initial: BTreeSet<_> = INITIAL_TYPE_URL_ORDER.iter().copied().collect();

        assert_eq!(initial, supported);
    }

    #[test]
    fn primary_retry_races_on_fallback_when_configured() {
        assert!(should_race_primary_retry(true, 300));
        assert!(!should_race_primary_retry(false, 300));
        assert!(!should_race_primary_retry(true, 0));
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
    fn xds_apply_deadline_caps_debounce_bursts() {
        let first_pending_at = tokio::time::Instant::now();
        let early_burst = first_pending_at + Duration::from_millis(100);
        let late_burst = first_pending_at + Duration::from_millis(490);

        assert_eq!(
            next_xds_apply_deadline(early_burst, first_pending_at),
            early_burst + XDS_APPLY_DEBOUNCE
        );
        assert_eq!(
            next_xds_apply_deadline(late_burst, first_pending_at),
            first_pending_at + XDS_APPLY_MAX_DELAY
        );
    }

    #[test]
    fn ack_echoes_nonce_and_version() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");

        let ack = state.build_ack(CDS_TYPE_URL);

        assert_eq!(ack.type_url, CDS_TYPE_URL);
        assert_eq!(ack.version_info, "v1");
        assert_eq!(ack.response_nonce, "n1");
        assert!(ack.error_detail.is_none());
        assert!(ack.resource_names.is_empty());
        assert!(ack.node.is_none());
    }

    #[test]
    fn reconnect_initial_request_uses_last_acked_version() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");
        state.mark_acked(CDS_TYPE_URL);

        let requests = state.build_initial_requests("node-a", "default", None, None, false);
        let cds = requests
            .iter()
            .find(|request| request.type_url == CDS_TYPE_URL)
            .expect("CDS request");

        assert_eq!(cds.version_info, "v1");
        assert!(cds.response_nonce.is_empty());
    }

    #[test]
    fn control_plane_switch_resets_server_scoped_ads_state() {
        let mut state = XdsStreamState::default();
        state
            .subscriptions
            .record_response(CDS_TYPE_URL, "v1", "n1");
        state.subscriptions.mark_acked(CDS_TYPE_URL);
        state.nack_circuit_breaker.record_nack(CDS_TYPE_URL);
        state
            .accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");

        state.reset_for_new_control_plane();

        assert!(state.accumulator.resources(CDS_TYPE_URL).is_empty());
        assert!(state.accumulator.versions_by_type.is_empty());
        assert!(
            state
                .nack_circuit_breaker
                .consecutive_nacks_by_type
                .is_empty()
        );
        assert!(!state.subscriptions.required_types_have_initial_response());
        assert!(
            state
                .subscriptions
                .build_initial_requests("node-a", "default", None, None, false)
                .iter()
                .all(|request| request.version_info.is_empty())
        );
    }

    #[test]
    fn nack_preserves_old_version() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");
        state.mark_acked(CDS_TYPE_URL);
        state.record_response(CDS_TYPE_URL, "v2", "n2");

        let nack = state.build_nack(CDS_TYPE_URL, "bad config");

        assert_eq!(nack.version_info, "v1");
        assert_eq!(nack.response_nonce, "n2");
    }

    #[test]
    fn nack_includes_error_detail() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");

        let nack = state.build_nack(CDS_TYPE_URL, "bad config");
        let detail = nack.error_detail.expect("NACK includes error detail");

        assert_eq!(detail.code, 3);
        assert_eq!(detail.message, "bad config");
    }

    #[test]
    fn nack_circuit_breaker_resets_on_ack() {
        let mut breaker = NackCircuitBreaker::default();

        assert_eq!(breaker.record_nack(CDS_TYPE_URL), 1);
        assert_eq!(breaker.record_nack(CDS_TYPE_URL), 2);
        breaker.record_ack(CDS_TYPE_URL);

        assert_eq!(breaker.record_nack(CDS_TYPE_URL), 1);
    }

    #[tokio::test]
    async fn unknown_type_url_is_nacked_without_erroring_stream() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        let result = handle_ads_response(
            discovery_response(
                "type.googleapis.com/envoy.config.route.v3.ScopedRouteConfiguration",
                "v1",
                "n1",
                Vec::new(),
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("unknown type should be NACKed, not fail the stream");

        assert!(result.is_none());
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(
            nack.type_url,
            "type.googleapis.com/envoy.config.route.v3.ScopedRouteConfiguration"
        );
        assert_eq!(nack.response_nonce, "n1");
        assert!(nack.error_detail.is_some());
        assert!(
            !state
                .subscriptions
                .contains_key("type.googleapis.com/envoy.config.route.v3.ScopedRouteConfiguration")
        );
        assert!(nack_circuit_breaker.consecutive_nacks_by_type.is_empty());
    }

    #[test]
    fn accumulator_replaces_resources_on_sotw() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("first response applies");
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/admin/9090")],
                "v2",
            )
            .expect("second response applies");

        let resources = accumulator.resources(CDS_TYPE_URL);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "cluster/default/admin/9090");
        assert_eq!(
            accumulator.versions_by_type.get(CDS_TYPE_URL).unwrap(),
            "v2"
        );
    }

    #[tokio::test]
    async fn dependency_skewed_route_is_skipped_not_nacked() {
        // Resource warming: a route referencing a service not present in the
        // current CDS/EDS/LDS — a transient arrival-ordering skew, or a route
        // whose cluster has not shipped — must NOT be NACKed. NACK + rollback
        // would drop the new RDS, and the CP does not resend a NACKed SotW
        // resource until a reconnect or another RDS change, so the route would
        // be lost. Instead the route is skipped, the RDS is retained in the
        // accumulator, and an ACK is sent.
        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v2",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        apply_all_empty(&mut accumulator);
        for type_url in [EDS_TYPE_URL, LDS_TYPE_URL, ECDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v2")
                .expect("empty v2 response applies");
        }

        let result = handle_ads_response(
            discovery_response(
                RDS_TYPE_URL,
                "v2",
                "n2",
                vec![any_resource(RDS_TYPE_URL, "route/default/missing")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("a dependency-skewed route must not error the stream");

        assert!(
            result.is_some(),
            "the slice still builds; the dependency-skewed route is skipped, not fatal"
        );
        // The new RDS is RETAINED (not rolled back) so it validates once its
        // service arrives.
        assert_eq!(
            accumulator.resources(RDS_TYPE_URL)[0].name,
            "route/default/missing"
        );
        assert_eq!(
            accumulator.versions_by_type.get(RDS_TYPE_URL).unwrap(),
            "v2"
        );
        // ACK, not NACK — and nothing counted toward the circuit breaker.
        let ack = rx.recv().await.expect("ACK sent");
        assert_eq!(ack.type_url, RDS_TYPE_URL);
        assert_eq!(ack.version_info, "v2");
        assert!(ack.error_detail.is_none());
        assert_eq!(nack_circuit_breaker.consecutive_nacks(RDS_TYPE_URL), 0);
    }

    #[tokio::test]
    async fn route_arriving_before_its_service_converges_when_service_arrives() {
        // The reviewer's end-to-end scenario: in a multi-type change the RDS for
        // a new service arrives before the matching CDS. The route is skipped
        // (no NACK) and retained; when the CDS for that service arrives, the
        // route validates and the service is in the slice.
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        // Converge at v1 with one service (api).
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        apply_all_empty(&mut accumulator);

        // The CP has refreshed the other required types to v2, but CDS for the
        // new service has not arrived yet. RDS v2 adds a route for that NEW
        // service (web).
        for type_url in [EDS_TYPE_URL, LDS_TYPE_URL, ECDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v2")
                .expect("empty v2 response applies");
        }
        let rds_first = handle_ads_response(
            discovery_response(
                RDS_TYPE_URL,
                "v2",
                "n-rds",
                vec![
                    any_resource(RDS_TYPE_URL, "route/default/api"),
                    any_resource(RDS_TYPE_URL, "route/default/web"),
                ],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("RDS-before-CDS must not error");
        assert!(
            rds_first.is_none(),
            "slice waits for coherent CDS v2 instead of applying a mixed-version update"
        );
        let ack = rx.recv().await.expect("ACK for RDS");
        assert_eq!(ack.type_url, RDS_TYPE_URL);
        assert!(ack.error_detail.is_none());

        // Now CDS v2 introduces the web service.
        let cds_after = handle_ads_response(
            discovery_response(
                CDS_TYPE_URL,
                "v2",
                "n-cds",
                vec![
                    any_resource(CDS_TYPE_URL, "cluster/default/api/8080"),
                    any_resource(CDS_TYPE_URL, "cluster/default/web/8080"),
                ],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("CDS arrival must not error")
        .expect("slice builds with the new service");

        // route/web is retained and now references a present service.
        let route_names: Vec<&str> = accumulator
            .resources(RDS_TYPE_URL)
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        assert!(route_names.contains(&"route/default/web"));
        let services = service_port_map(&cds_after.slice);
        assert!(
            services.contains_key(&("default".to_string(), "web".to_string())),
            "web service is present in the slice once its CDS arrives"
        );
        let ack = rx.recv().await.expect("ACK for CDS");
        assert_eq!(ack.type_url, CDS_TYPE_URL);
        assert!(ack.error_detail.is_none());
        assert_eq!(nack_circuit_breaker.consecutive_nacks(RDS_TYPE_URL), 0);
    }

    #[tokio::test]
    async fn mixed_required_versions_wait_for_coherent_security_carriers() {
        // ECDS carries security policy. If CDS/RDS move to v2 while ECDS
        // remains at v1, the DP must ACK the response (so the CP can continue)
        // but must not build/apply a slice that mixes new routing with stale
        // policy.
        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        apply_all_empty(&mut accumulator);

        let pending = handle_ads_response(
            discovery_response(
                CDS_TYPE_URL,
                "v2",
                "n2",
                vec![any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("valid response should be ACKed while waiting for coherent required versions");

        assert!(
            pending.is_none(),
            "CDS v2 with ECDS still v1 must not build a stale-policy slice"
        );
        let ack = rx.recv().await.expect("ACK sent");
        assert_eq!(ack.type_url, CDS_TYPE_URL);
        assert_eq!(ack.version_info, "v2");
        assert_eq!(
            accumulator.versions_by_type.get(CDS_TYPE_URL).unwrap(),
            "v2"
        );
        assert_eq!(
            accumulator.versions_by_type.get(ECDS_TYPE_URL).unwrap(),
            "v1"
        );
        assert!(accumulator.required_versions_skewed());
    }

    #[tokio::test]
    async fn ecds_only_update_waits_for_required_type_refresh() {
        // A policy-only ECDS response at v2 is security-safe only once the
        // subscribed required core types have also refreshed to v2. The CP
        // force-sends those required types for coherent versioning.
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        apply_all_empty(&mut accumulator);
        assert!(accumulator.has_required_types());

        let pending = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v2",
                "n-ecds",
                vec![any_resource(ECDS_TYPE_URL, "ecds-extension")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("ECDS update should be ACKed");
        assert!(pending.is_none(), "ECDS v2 alone is not coherent yet");
        assert_eq!(rx.recv().await.expect("ACK sent").type_url, ECDS_TYPE_URL);

        for (type_url, resources) in [
            (
                CDS_TYPE_URL,
                vec![any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
            ),
            (EDS_TYPE_URL, Vec::new()),
            (LDS_TYPE_URL, Vec::new()),
            (
                RDS_TYPE_URL,
                vec![any_resource(RDS_TYPE_URL, "route/default/api")],
            ),
        ] {
            let pending = handle_ads_response(
                discovery_response(type_url, "v2", &format!("n-{type_url}"), resources),
                &test_config(),
                &tx,
                &mut state,
                &mut accumulator,
                &mut nack_circuit_breaker,
            )
            .await
            .expect("required refresh should be ACKed");
            let ack = rx.recv().await.expect("ACK sent");
            assert_eq!(ack.type_url, type_url);
            if type_url != RDS_TYPE_URL {
                assert!(
                    pending.is_none(),
                    "slice waits for every required type at v2"
                );
            } else {
                let pending = pending.expect("last required v2 response builds coherent slice");
                assert_eq!(pending.slice.version, "v2");
                assert_eq!(pending.slice.services.len(), 1);
                assert_eq!(pending.slice.services[0].name, "api");
                assert!(!pending.version_skew);
            }
        }
    }

    #[test]
    fn composite_required_version_uses_newest_per_type_version() {
        let mut accumulator = ResourceAccumulator::new();
        // No required type seen yet → empty.
        assert_eq!(composite_required_version(&accumulator), "");

        accumulator
            .apply_sotw_response(CDS_TYPE_URL, &[], "2026-05-01T00:00:00Z:aaaa")
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(EDS_TYPE_URL, &[], "2026-05-01T00:00:00Z:aaaa")
            .expect("EDS applies");
        accumulator
            .apply_sotw_response(LDS_TYPE_URL, &[], "2026-05-01T00:00:00Z:aaaa")
            .expect("LDS applies");
        accumulator
            .apply_sotw_response(RDS_TYPE_URL, &[], "2026-05-01T00:00:00Z:aaaa")
            .expect("RDS applies");
        // ECDS moved to a newer snapshot version (lexicographically greater).
        accumulator
            .apply_sotw_response(ECDS_TYPE_URL, &[], "2026-05-02T00:00:00Z:bbbb")
            .expect("ECDS applies");

        assert_eq!(
            composite_required_version(&accumulator),
            "2026-05-02T00:00:00Z:bbbb"
        );
    }

    #[test]
    fn convergence_snapshot_reports_missing_then_converged_with_skew() {
        let mut accumulator = ResourceAccumulator::new();
        // Only CDS so far → not converged; ECDS/EDS/LDS/RDS still missing.
        accumulator
            .apply_sotw_response(CDS_TYPE_URL, &[], "v1")
            .expect("CDS applies");
        let snap = accumulator.convergence_snapshot();
        assert!(!snap.converged);
        assert!(snap.missing_required_types.contains(&"ecds".to_string()));
        assert!(snap.missing_required_types.contains(&"eds".to_string()));
        assert!(
            !snap.version_skew,
            "skew is undefined/false until all required types are present"
        );
        assert_eq!(
            snap.per_type_versions.get("cds").map(String::as_str),
            Some("v1")
        );

        // Bring the rest in at v1, ECDS at a newer v2 → present but not converged.
        for type_url in [EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v1")
                .expect("applies");
        }
        accumulator
            .apply_sotw_response(ECDS_TYPE_URL, &[], "v2")
            .expect("applies");
        let snap = accumulator.convergence_snapshot();
        assert!(
            !snap.converged,
            "required types with mismatched versions must not report convergence"
        );
        assert!(snap.missing_required_types.is_empty());
        assert!(snap.version_skew, "ecds=v2 while others=v1 is skew");
        assert_eq!(
            snap.per_type_versions.get("ecds").map(String::as_str),
            Some("v2")
        );
    }

    #[test]
    fn convergence_snapshot_no_skew_when_all_required_versions_equal() {
        let mut accumulator = ResourceAccumulator::new();
        for type_url in REQUIRED_MESH_SLICE_TYPE_URLS {
            accumulator
                .apply_sotw_response(type_url, &[], "v9")
                .expect("applies");
        }
        let snap = accumulator.convergence_snapshot();
        assert!(snap.converged);
        assert!(!snap.version_skew);
        assert!(snap.missing_required_types.is_empty());
    }

    #[test]
    fn apply_increments_partial_metric_only_when_marked_skewed() {
        use crate::plugins::mesh::prometheus_helpers::xds_warming_partial_apply_count;

        // Unique namespace so the namespaced counter is isolated from parallel
        // tests touching the same metric.
        let namespace = format!("warm-apply-{}-{}", std::process::id(), line!());
        let config = XdsClientConfig {
            namespace: namespace.clone(),
            ..test_config()
        };
        let state = MeshRuntimeState::new();
        let consumer = XdsConfigConsumer::new(config.clone(), state);

        assert_eq!(xds_warming_partial_apply_count(&namespace), 0);
        apply_pending_xds_slice(
            &consumer,
            &config,
            PendingXdsSlice {
                slice: MeshSlice {
                    version: "v2".to_string(),
                    ..MeshSlice::default()
                },
                type_url: ECDS_TYPE_URL.to_string(),
                all_types_ready: true,
                version_skew: true,
            },
        )
        .expect("the skewed slice applies");
        assert_eq!(
            xds_warming_partial_apply_count(&namespace),
            1,
            "a defensive skewed apply marker must increment the partial-apply counter"
        );

        // A coherent (non-skewed) apply must NOT increment the counter.
        apply_pending_xds_slice(
            &consumer,
            &config,
            PendingXdsSlice {
                slice: MeshSlice {
                    version: "v3".to_string(),
                    ..MeshSlice::default()
                },
                type_url: CDS_TYPE_URL.to_string(),
                all_types_ready: true,
                version_skew: false,
            },
        )
        .expect("the coherent slice applies");
        assert_eq!(
            xds_warming_partial_apply_count(&namespace),
            1,
            "a coherent apply must not increment the partial-apply counter"
        );
    }

    #[test]
    fn stale_pending_slice_is_stream_terminal_and_not_counted_as_applied() {
        use crate::modes::mesh::revision::MeshConfigRevision;
        use crate::plugins::mesh::prometheus_helpers::xds_warming_partial_apply_count;

        let namespace = format!("stale-apply-{}-{}", std::process::id(), line!());
        let config = XdsClientConfig {
            namespace: namespace.clone(),
            ..test_config()
        };
        let state = MeshRuntimeState::new();
        let consumer = XdsConfigConsumer::new(config.clone(), state.clone());
        consumer
            .apply_slice(MeshSlice {
                version: "v100".to_string(),
                revision: Some(MeshConfigRevision::new("db", 100)),
                ..MeshSlice::default()
            })
            .expect("the fresh baseline applies");

        let before = xds_warming_partial_apply_count(&namespace);
        let error = apply_pending_xds_slice(
            &consumer,
            &config,
            PendingXdsSlice {
                slice: MeshSlice {
                    version: "v99".to_string(),
                    revision: Some(MeshConfigRevision::new("db", 99)),
                    ..MeshSlice::default()
                },
                type_url: ECDS_TYPE_URL.to_string(),
                all_types_ready: true,
                version_skew: true,
            },
        )
        .expect_err("a stale xDS slice closes ADS so the client can fail over");

        assert!(error.to_string().contains("stale_revision"));
        assert_eq!(
            xds_warming_partial_apply_count(&namespace),
            before,
            "a quarantined slice was never applied"
        );
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v100")
        );
    }

    #[tokio::test]
    async fn malformed_reserved_slice_carrier_is_nacked_and_rolled_back() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        apply_all_empty(&mut accumulator);

        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");
        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v2",
                "n2",
                vec![typed_extension_resource(
                    carrier_name,
                    FERRUM_ECDS_PEER_AUTH_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("bad Ferrum carrier should NACK without closing stream");

        assert!(result.is_none());
        assert!(
            accumulator.resources(ECDS_TYPE_URL).is_empty(),
            "NACK must roll ECDS back to the previous empty accepted response"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert_eq!(nack.response_nonce, "n2");
        let detail = nack.error_detail.expect("error detail");
        assert!(detail.message.contains("failed JSON decode"));
    }

    #[tokio::test]
    async fn invalid_ecds_nack_discards_existing_debounced_pending_slice() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();
        let mut pending_slice = Some(PendingXdsSlice {
            slice: MeshSlice {
                node_id: "node-a".to_string(),
                namespace: "default".to_string(),
                version: "pending".to_string(),
                ..MeshSlice::default()
            },
            type_url: CDS_TYPE_URL.to_string(),
            all_types_ready: true,
            version_skew: false,
        });
        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");
        let nack_count_before = nack_circuit_breaker.consecutive_nacks(ECDS_TYPE_URL);

        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v1",
                "n1",
                vec![typed_extension_resource(
                    carrier_name,
                    FERRUM_ECDS_PEER_AUTH_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("bad ECDS carrier should NACK without closing stream");

        assert!(result.is_none());
        assert!(nack_circuit_breaker.nacked_since(ECDS_TYPE_URL, nack_count_before));
        assert!(discard_pending_xds_slice_after_nack(
            &test_config(),
            &mut pending_slice,
            ECDS_TYPE_URL
        ));
        assert!(
            pending_slice.is_none(),
            "a known-type NACK must clear any debounced pending slice"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
    }

    #[tokio::test]
    async fn reserved_slice_carrier_missing_typed_config_is_nacked() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();
        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");

        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v1",
                "n1",
                vec![typed_extension_resource_without_config(carrier_name)],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("missing typed_config should NACK without closing stream");

        assert!(result.is_none());
        assert!(
            accumulator.resources(ECDS_TYPE_URL).is_empty(),
            "NACK must not store the malformed ECDS response"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert_eq!(nack.response_nonce, "n1");
        let detail = nack.error_detail.expect("error detail");
        assert!(detail.message.contains("without typed_config"));
    }

    #[tokio::test]
    async fn malformed_reserved_slice_carrier_is_nacked_before_required_types_ready() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();
        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");

        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v1",
                "n1",
                vec![typed_extension_resource(
                    carrier_name,
                    FERRUM_ECDS_PEER_AUTH_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("bad Ferrum carrier should NACK before first-slice readiness");

        assert!(result.is_none());
        assert!(
            accumulator.resources(ECDS_TYPE_URL).is_empty(),
            "validation happens at ECDS ingestion, before all required types are ready"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert_eq!(nack.response_nonce, "n1");
        let detail = nack.error_detail.expect("error detail");
        assert!(detail.message.contains("failed JSON decode"));
    }

    #[tokio::test]
    async fn malformed_reserved_destination_rule_carrier_is_nacked_before_required_types_ready() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();
        let carrier_name = format!("{FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX}default/api-dr");

        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v1",
                "n1",
                vec![typed_extension_resource(
                    &carrier_name,
                    FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("bad reserved DR carrier should NACK before first-slice readiness");

        assert!(result.is_none());
        assert!(
            accumulator.resources(ECDS_TYPE_URL).is_empty(),
            "reserved DR carriers are validated at ECDS ingestion"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert_eq!(nack.response_nonce, "n1");
        let detail = nack.error_detail.expect("error detail");
        assert!(detail.message.contains("DestinationRule"));
        assert!(detail.message.contains("failed JSON decode"));
    }

    #[tokio::test]
    async fn repeated_invalid_update_trips_nack_circuit_breaker() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        apply_all_empty(&mut accumulator);

        for attempt in 1..XDS_CONSECUTIVE_NACK_LIMIT {
            let result = handle_ads_response(
                discovery_response(
                    RDS_TYPE_URL,
                    &format!("v{}", attempt + 1),
                    &format!("n{}", attempt + 1),
                    vec![any_resource(RDS_TYPE_URL, "route/default")],
                ),
                &test_config(),
                &tx,
                &mut state,
                &mut accumulator,
                &mut nack_circuit_breaker,
            )
            .await
            .expect("below threshold should only NACK");

            assert!(result.is_none());
        }

        let err = handle_ads_response(
            discovery_response(
                RDS_TYPE_URL,
                "v-final",
                "n-final",
                vec![any_resource(RDS_TYPE_URL, "route/default")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect_err("threshold NACK should close the ADS stream");

        assert!(
            err.to_string()
                .contains("xDS ADS NACK circuit breaker tripped")
        );

        let mut nack_count = 0;
        while let Ok(nack) = rx.try_recv() {
            assert_eq!(nack.type_url, RDS_TYPE_URL);
            assert!(nack.error_detail.is_some());
            nack_count += 1;
        }
        assert_eq!(nack_count, XDS_CONSECUTIVE_NACK_LIMIT);
    }

    #[test]
    fn record_response_classifies_fresh_then_stale_duplicate() {
        let mut state = ClientSubscriptionState::new();

        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v1", "n1"),
            ResponseNonceOutcome::Fresh
        );
        // A different nonce is always fresh, even before marking processed.
        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v1", "n2"),
            ResponseNonceOutcome::Fresh
        );

        // Once the most-recent nonce is marked processed, a retransmit carrying
        // the same nonce is detected as a stale duplicate.
        state.mark_processed(CDS_TYPE_URL);
        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v1", "n2"),
            ResponseNonceOutcome::StaleDuplicate {
                nonce: "n2".to_string()
            }
        );

        // A stale duplicate must not advance the received baseline: the next
        // genuine (new) nonce is still classified fresh.
        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v2", "n3"),
            ResponseNonceOutcome::Fresh
        );
    }

    #[test]
    fn reset_processed_nonces_clears_dedup_baseline_per_stream() {
        let mut state = XdsStreamState::default();

        // First stream: process a response and mark its nonce as processed.
        assert_eq!(
            state
                .subscriptions
                .record_response(CDS_TYPE_URL, "v1", "n1"),
            ResponseNonceOutcome::Fresh
        );
        state.subscriptions.mark_processed(CDS_TYPE_URL);
        // Same-stream retransmit of `n1` is still detected as a stale duplicate.
        assert_eq!(
            state
                .subscriptions
                .record_response(CDS_TYPE_URL, "v1", "n1"),
            ResponseNonceOutcome::StaleDuplicate {
                nonce: "n1".to_string()
            }
        );

        // New stream: the CP legitimately reissues `n1` for the same node/type/
        // version (e.g. its sequence counter reset on restart, or this is a
        // load-balanced reconnect to a peer replica). `reset_for_new_stream`
        // must clear the dedup baseline so the response is processed.
        state.reset_for_new_stream();
        assert_eq!(
            state
                .subscriptions
                .record_response(CDS_TYPE_URL, "v1", "n1"),
            ResponseNonceOutcome::Fresh,
            "first response on a new stream must not be suppressed by a \
             stream-scoped nonce from a previous stream"
        );

        // The new stream still benefits from intra-stream dedup once the new
        // response is marked processed.
        state.subscriptions.mark_processed(CDS_TYPE_URL);
        assert_eq!(
            state
                .subscriptions
                .record_response(CDS_TYPE_URL, "v1", "n1"),
            ResponseNonceOutcome::StaleDuplicate {
                nonce: "n1".to_string()
            }
        );

        // `last_acked_version` (subscription resume baseline) is preserved
        // across `reset_for_new_stream` so the new stream does not have to
        // re-flow every resource from version 0.
        let mut state = XdsStreamState::default();
        state
            .subscriptions
            .record_response(CDS_TYPE_URL, "v7", "n7");
        state.subscriptions.mark_acked(CDS_TYPE_URL);
        state.reset_for_new_stream();
        let initial = state
            .subscriptions
            .build_initial_requests("node-a", "default", None, None, false);
        let cds = initial
            .iter()
            .find(|r| r.type_url == CDS_TYPE_URL)
            .expect("initial CDS request");
        assert_eq!(
            cds.version_info, "v7",
            "subscription resume version must survive stream reset"
        );
    }

    #[test]
    fn empty_nonce_response_is_always_fresh() {
        let mut state = ClientSubscriptionState::new();
        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v1", ""),
            ResponseNonceOutcome::Fresh
        );
        state.mark_processed(CDS_TYPE_URL);
        // An empty processed nonce must never match a later empty nonce as a
        // "duplicate" — empty means the server supplied none.
        assert_eq!(
            state.record_response(CDS_TYPE_URL, "v1", ""),
            ResponseNonceOutcome::Fresh
        );
    }

    #[tokio::test]
    async fn stale_duplicate_response_is_ignored_without_reack() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        // First valid CDS response: ACKed and marked processed.
        let first = handle_ads_response(
            discovery_response(
                CDS_TYPE_URL,
                "v1",
                "n1",
                vec![any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("first CDS response is processed");
        assert!(first.is_none(), "single CDS type cannot build a full slice");
        let ack = rx.recv().await.expect("ACK sent for first response");
        assert_eq!(ack.type_url, CDS_TYPE_URL);
        assert_eq!(ack.response_nonce, "n1");
        assert!(ack.error_detail.is_none());

        // Server retransmits the SAME nonce (reconnect race / buggy CP). The
        // client must ignore it: no re-ACK, accumulator untouched.
        let resources_before = accumulator.resources(CDS_TYPE_URL).to_vec();
        let duplicate = handle_ads_response(
            discovery_response(
                CDS_TYPE_URL,
                "v1",
                "n1",
                vec![any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
            ),
            &test_config(),
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("stale duplicate is ignored, not an error");
        assert!(duplicate.is_none());
        assert!(
            rx.try_recv().is_err(),
            "stale duplicate response must not emit a second ACK"
        );
        assert_eq!(
            accumulator.resources(CDS_TYPE_URL),
            resources_before.as_slice(),
            "stale duplicate must not mutate accumulated resources"
        );
    }

    #[tokio::test]
    async fn required_type_nack_before_first_slice_emits_visibility_signal() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        // Unique namespace so the process-global counter assertion is immune to
        // other tests incrementing the same series in parallel.
        let namespace = format!("nack-vis-{}-{}", std::process::id(), line!());
        let config = XdsClientConfig {
            namespace: namespace.clone(),
            ..test_config()
        };
        let before = crate::plugins::mesh::prometheus_helpers::xds_first_slice_nack_count(
            &namespace,
            ECDS_TYPE_URL,
        );

        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();
        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");

        // A malformed reserved ECDS carrier fails at ingestion. ECDS is a
        // required mesh-slice type and no required type has converged, so this
        // is a first-slice-blocking NACK.
        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v1",
                "n1",
                vec![typed_extension_resource(
                    carrier_name,
                    FERRUM_ECDS_PEER_AUTH_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &config,
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("first-slice NACK does not close the stream below the breaker limit");

        assert!(result.is_none());
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert!(nack.error_detail.is_some());

        let after = crate::plugins::mesh::prometheus_helpers::xds_first_slice_nack_count(
            &namespace,
            ECDS_TYPE_URL,
        );
        assert_eq!(
            after,
            before + 1,
            "a required-type NACK before first-slice convergence must increment the visibility counter"
        );
    }

    #[tokio::test]
    async fn nack_after_convergence_does_not_emit_first_slice_signal() {
        use crate::xds::carrier::{
            FERRUM_ECDS_PEER_AUTH_TYPE_URL, carrier_resource_name_for_type_url,
        };

        // Build a fully-converged accumulator (all required types present), so a
        // later NACK is a steady-state NACK, not a first-slice block.
        let namespace = format!("nack-conv-{}-{}", std::process::id(), line!());
        let config = XdsClientConfig {
            namespace: namespace.clone(),
            ..test_config()
        };
        let (tx, mut rx) = mpsc::channel(8);
        let mut state = ClientSubscriptionState::new();
        let mut accumulator = ResourceAccumulator::new();
        let mut nack_circuit_breaker = NackCircuitBreaker::default();

        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        accumulator
            .apply_sotw_response(
                RDS_TYPE_URL,
                &[any_resource(RDS_TYPE_URL, "route/default/api")],
                "v1",
            )
            .expect("RDS applies");
        // Includes a valid (empty) ECDS so every required type has converged.
        apply_all_empty(&mut accumulator);
        assert!(
            accumulator.has_required_types(),
            "precondition: all required types converged"
        );

        let before = crate::plugins::mesh::prometheus_helpers::xds_first_slice_nack_count(
            &namespace,
            ECDS_TYPE_URL,
        );

        // A subsequent malformed ECDS update NACKs, but convergence already
        // happened (the prior ECDS version survives the rollback), so the
        // first-slice signal must NOT fire.
        let carrier_name =
            carrier_resource_name_for_type_url(FERRUM_ECDS_PEER_AUTH_TYPE_URL).expect("name");
        let result = handle_ads_response(
            discovery_response(
                ECDS_TYPE_URL,
                "v2",
                "n2",
                vec![typed_extension_resource(
                    carrier_name,
                    FERRUM_ECDS_PEER_AUTH_TYPE_URL,
                    b"{not valid json}".to_vec(),
                )],
            ),
            &config,
            &tx,
            &mut state,
            &mut accumulator,
            &mut nack_circuit_breaker,
        )
        .await
        .expect("steady-state NACK below breaker limit");
        assert!(result.is_none());
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, ECDS_TYPE_URL);
        assert!(
            accumulator.has_required_types(),
            "the prior ECDS version survives the NACK rollback"
        );

        let after = crate::plugins::mesh::prometheus_helpers::xds_first_slice_nack_count(
            &namespace,
            ECDS_TYPE_URL,
        );
        assert_eq!(
            after, before,
            "a post-convergence NACK must not increment the first-slice visibility counter"
        );
    }

    #[test]
    fn pending_slice_is_flushed_before_ads_error_returns() {
        let config = test_config();
        let state = MeshRuntimeState::new();
        let consumer = XdsConfigConsumer::new(config.clone(), state.clone());
        let mut pending_slice = Some(PendingXdsSlice {
            slice: MeshSlice {
                version: "v-pending".to_string(),
                ..MeshSlice::default()
            },
            type_url: CDS_TYPE_URL.to_string(),
            all_types_ready: true,
            version_skew: false,
        });

        let err = flush_pending_xds_slice_before_error(
            &consumer,
            &config,
            &mut pending_slice,
            anyhow::anyhow!("breaker"),
        )
        .expect_err("error is preserved after flush");

        assert_eq!(err.to_string(), "breaker");
        assert!(pending_slice.is_none());
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v-pending")
        );
    }

    #[test]
    fn non_empty_response_requires_version_info() {
        let mut accumulator = ResourceAccumulator::new();
        let err = accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "",
            )
            .expect_err("non-empty response with empty version must be rejected");

        assert!(err.contains("empty version_info"));
    }

    #[test]
    fn empty_required_response_requires_version_info() {
        let mut accumulator = ResourceAccumulator::new();
        let err = accumulator
            .apply_sotw_response(CDS_TYPE_URL, &[], "")
            .expect_err("empty required response with empty version must be rejected");

        assert!(err.contains("empty version_info"));
    }

    #[test]
    fn empty_optional_response_may_omit_version_info() {
        let mut accumulator = ResourceAccumulator::new();

        accumulator
            .apply_sotw_response(SDS_TYPE_URL, &[], "")
            .expect("empty optional response can omit version");
    }

    #[test]
    fn accumulator_accepts_ecds_typed_extension_config_resources() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[any_resource(ECDS_TYPE_URL, "dr-carrier-api")],
                "v1",
            )
            .expect("ECDS response applies");

        let resources = accumulator.resources(ECDS_TYPE_URL);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "dr-carrier-api");
    }

    #[test]
    fn accumulator_requires_core_types_and_ecds_but_not_sds() {
        let mut accumulator = ResourceAccumulator::new();
        for type_url in [CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v1")
                .expect("response applies");
        }

        assert!(!accumulator.has_required_types());
        accumulator
            .apply_sotw_response(RDS_TYPE_URL, &[], "v1")
            .expect("response applies");
        assert!(!accumulator.has_required_types());
        accumulator
            .apply_sotw_response(ECDS_TYPE_URL, &[], "v1")
            .expect("response applies");
        assert!(accumulator.has_required_types());
    }

    #[test]
    fn reverse_translate_cluster_name() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "api");
        assert_eq!(slice.services[0].namespace, "default");
        assert_eq!(slice.services[0].ports[0].port, 8080);
    }

    #[test]
    fn reverse_translate_rejects_non_ferrum_cluster_name_shape() {
        let mut accumulator = ResourceAccumulator::new();
        let err = accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(
                    CDS_TYPE_URL,
                    "outbound|8080||api.default.svc.cluster.local",
                )],
                "v1",
            )
            .expect_err("non-Ferrum xDS names are not supported");

        assert!(err.contains("cluster/{namespace}/{service}/{port}"));
    }

    #[test]
    fn reverse_translate_deduplicates_services() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS response applies");
        accumulator
            .apply_sotw_response(
                LDS_TYPE_URL,
                &[any_resource(LDS_TYPE_URL, "listener/default/api/9090")],
                "v1",
            )
            .expect("LDS response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(
            service_port_map(&slice).get(&("default".to_string(), "api".to_string())),
            Some(&vec![8080, 9090])
        );
    }

    #[test]
    fn reverse_translate_sds_names_do_not_emit_empty_trust_bundles() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                SDS_TYPE_URL,
                &[any_resource(
                    SDS_TYPE_URL,
                    "secret/spiffe-bundle/cluster.local",
                )],
                "v1",
            )
            .expect("SDS response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert!(slice.trust_bundles.is_none());
    }

    #[test]
    fn reverse_translate_ignores_unknown_sds_secret_names() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                SDS_TYPE_URL,
                &[any_resource(SDS_TYPE_URL, "kubernetes://default/api-token")],
                "v1",
            )
            .expect("SDS response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("unknown SDS names are ignored")
            .expect("all types are present");

        assert!(slice.trust_bundles.is_none());
    }

    #[test]
    fn reverse_translate_does_not_wait_for_sds() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS response applies");
        for type_url in [EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, ECDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v1")
                .expect("empty response applies");
        }

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("required non-SDS types are present");

        assert_eq!(slice.services.len(), 1);
        assert!(slice.trust_bundles.is_none());
    }

    #[test]
    fn reverse_translate_handles_empty() {
        let accumulator = ResourceAccumulator::new();

        assert!(
            accumulator
                .try_build_mesh_slice(&test_config())
                .expect("empty accumulator is valid")
                .is_none()
        );
    }

    #[test]
    fn round_trip_through_translator() {
        let original = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            services: vec![MeshService {
                cluster_ips: Vec::new(),
                name: "api".to_string(),
                namespace: "default".to_string(),
                ports: vec![
                    ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                        target_port: None,
                    },
                    ServicePort {
                        port: 9090,
                        protocol: AppProtocol::Grpc,
                        name: Some("grpc".to_string()),
                        target_port: None,
                    },
                ],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&original);
        let mut accumulator = ResourceAccumulator::new();

        for type_url in XDS_TYPE_URLS {
            let resources: Vec<proto::Any> = snapshot
                .resources(type_url)
                .iter()
                .map(|resource| resource.to_any())
                .collect();
            accumulator
                .apply_sotw_response(type_url, &resources, &snapshot.version)
                .expect("snapshot resources apply");
        }

        let translated = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(service_port_map(&translated), service_port_map(&original));
    }

    // ── GAP-2K: ECDS DR-carrier path ──
    //
    // When the CP wraps the original DestinationRule JSON in an ECDS
    // TypedExtensionConfig with `type_url ==
    // FERRUM_ECDS_DESTINATION_RULE_TYPE_URL`, the DP reverse-translates the
    // payload back into a full `MeshDestinationRule` and adds it to
    // `slice.destination_rules`. Other ECDS payloads are silently skipped.

    fn dr_carrier_resource(name: &str, dr_json: &str) -> proto::Any {
        typed_extension_resource(
            name,
            FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
            dr_json.as_bytes().to_vec(),
        )
    }

    fn typed_extension_resource(
        name: &str,
        inner_type_url: &str,
        inner_value: Vec<u8>,
    ) -> proto::Any {
        use prost::Message;
        let typed_extension = proto::TypedExtensionConfig {
            name: name.to_string(),
            typed_config: Some(proto::Any {
                type_url: inner_type_url.to_string(),
                value: inner_value,
            }),
        };
        let mut value = Vec::new();
        typed_extension
            .encode(&mut value)
            .expect("TypedExtensionConfig encode");
        proto::Any {
            type_url: ECDS_TYPE_URL.to_string(),
            value,
        }
    }

    fn typed_extension_resource_without_config(name: &str) -> proto::Any {
        use prost::Message;
        let typed_extension = proto::TypedExtensionConfig {
            name: name.to_string(),
            typed_config: None,
        };
        proto::Any {
            type_url: ECDS_TYPE_URL.to_string(),
            value: typed_extension.encode_to_vec(),
        }
    }

    fn primed_accumulator() -> ResourceAccumulator {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[proto::Any {
                    type_url: CDS_TYPE_URL.to_string(),
                    value: prost::Message::encode_to_vec(&proto::Cluster {
                        name: "cluster/default/api/8080".to_string(),
                    }),
                }],
                "v1",
            )
            .expect("CDS apply");
        accumulator
            .apply_sotw_response(EDS_TYPE_URL, &[], "v1")
            .expect("EDS apply");
        accumulator
            .apply_sotw_response(LDS_TYPE_URL, &[], "v1")
            .expect("LDS apply");
        accumulator
            .apply_sotw_response(RDS_TYPE_URL, &[], "v1")
            .expect("RDS apply");
        accumulator
            .apply_sotw_response(SDS_TYPE_URL, &[], "v1")
            .expect("SDS apply");
        accumulator
    }

    #[test]
    fn ecds_dr_carrier_payload_recovers_destination_rule() {
        use crate::modes::mesh::config::{MeshLoadBalancer, MeshSimpleLb};
        let dr_json = r#"{
            "name": "api-dr",
            "namespace": "default",
            "host": "api.default.svc.cluster.local",
            "traffic_policy": {
                "load_balancer": {"simple": "ROUND_ROBIN"}
            }
        }"#;
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource("api-dr", dr_json)],
                "v1",
            )
            .expect("ECDS apply");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate")
            .expect("all required types present");
        assert_eq!(slice.destination_rules.len(), 1);
        let dr = &slice.destination_rules[0];
        assert_eq!(dr.name, "api-dr");
        assert_eq!(dr.namespace, "default");
        assert_eq!(dr.host, "api.default.svc.cluster.local");
        // Pin nested DR semantics round-trip — the whole point of the carrier
        // path is that fields baked out of CDS/EDS (LB algorithm, etc.) come
        // back intact. Without this assertion the test would pass even if the
        // inner JSON were silently truncated to {name, namespace, host}.
        let policy = dr
            .traffic_policy
            .as_ref()
            .expect("traffic_policy should round-trip from ECDS DR-carrier");
        match policy.load_balancer.as_ref() {
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)) => {}
            other => panic!("expected Simple(RoundRobin) load balancer, got {other:?}"),
        }
    }

    #[test]
    fn ecds_non_dr_carrier_payload_is_silently_skipped() {
        let mut accumulator = primed_accumulator();
        let other_type_url = "type.googleapis.com/some.unrelated.extension";
        let other_extension = proto::TypedExtensionConfig {
            name: "other-extension".to_string(),
            typed_config: Some(proto::Any {
                type_url: other_type_url.to_string(),
                value: b"opaque".to_vec(),
            }),
        };
        let mut value = Vec::new();
        prost::Message::encode(&other_extension, &mut value).expect("encode");
        let other_any = proto::Any {
            type_url: ECDS_TYPE_URL.to_string(),
            value,
        };
        accumulator
            .apply_sotw_response(ECDS_TYPE_URL, &[other_any], "v1")
            .expect("ECDS apply");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate")
            .expect("all required types present");
        assert!(slice.destination_rules.is_empty());
    }

    #[test]
    fn ecds_dr_carrier_invalid_json_skips_dr_without_failing_slice() {
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource("api-dr", "{not valid json}")],
                "v1",
            )
            .expect("ECDS apply");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate should not fail on bad inner JSON")
            .expect("all required types present");
        assert!(slice.destination_rules.is_empty());
    }

    #[test]
    fn ecds_dr_carrier_cross_namespace_is_skipped() {
        let dr_json = r#"{
            "name": "api-dr",
            "namespace": "other",
            "host": "api.default.svc.cluster.local"
        }"#;
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource("api-dr", dr_json)],
                "v1",
            )
            .expect("ECDS apply");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate")
            .expect("all required types present");
        assert!(slice.destination_rules.is_empty());
    }

    #[test]
    fn reserved_ecds_dr_carrier_cross_namespace_recovers_destination_rule() {
        let dr_json = r#"{
            "name": "api-dr",
            "namespace": "other",
            "host": "api.other.svc.cluster.local"
        }"#;
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource(
                    &format!("{FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX}other/api-dr"),
                    dr_json,
                )],
                "v1",
            )
            .expect("reserved ECDS DR carrier applies");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate")
            .expect("all required types present");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "api-dr");
        assert_eq!(slice.destination_rules[0].namespace, "other");
        assert_eq!(
            slice.destination_rules[0].host,
            "api.other.svc.cluster.local"
        );
    }

    #[test]
    fn reserved_ecds_dr_carrier_name_mismatch_is_rejected() {
        let dr_json = r#"{
            "name": "api-dr",
            "namespace": "other",
            "host": "api.other.svc.cluster.local"
        }"#;
        let mut accumulator = primed_accumulator();
        let err = accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource(
                    &format!("{FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX}default/api-dr"),
                    dr_json,
                )],
                "v1",
            )
            .expect_err("reserved carrier resource name must match embedded DR");
        assert!(err.contains("reserved name targets"));
    }

    #[test]
    fn ecds_mixed_resources_only_valid_carrier_makes_it_through() {
        // Mixed slice: one valid DR-carrier + one unrelated inner type_url
        // + one DR-carrier with invalid JSON. The valid DR must land in the
        // slice; the others are silently skipped / warned. This pins the
        // "bad payloads do not fail the whole slice" guarantee at the
        // boundary where multiple ECDS resources coexist on the same
        // response.
        let valid_dr_json = r#"{
            "name": "valid-dr",
            "namespace": "default",
            "host": "valid.default.svc.cluster.local"
        }"#;

        let other_extension = proto::TypedExtensionConfig {
            name: "unrelated-ext".to_string(),
            typed_config: Some(proto::Any {
                type_url: "type.googleapis.com/some.unrelated.extension".to_string(),
                value: b"opaque".to_vec(),
            }),
        };
        let mut other_value = Vec::new();
        prost::Message::encode(&other_extension, &mut other_value).expect("encode");
        let other_any = proto::Any {
            type_url: ECDS_TYPE_URL.to_string(),
            value: other_value,
        };

        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[
                    dr_carrier_resource("valid-dr", valid_dr_json),
                    other_any,
                    dr_carrier_resource("bad-json-dr", "{not valid json}"),
                ],
                "v1",
            )
            .expect("ECDS apply");

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate should not fail on mixed payloads")
            .expect("all required types present");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "valid-dr");
        assert_eq!(
            slice.destination_rules[0].host,
            "valid.default.svc.cluster.local"
        );
    }

    /// Pin the `docs/mesh.md` "ECDS DestinationRule carrier" worked example
    /// against the `MeshDestinationRule` schema so doc drift trips a test
    /// failure. The JSON below is byte-equivalent (whitespace aside) to the
    /// inner-`value` block under the "with the inner `value` bytes carrying
    /// the original DR as `MeshDestinationRule` JSON" heading in the doc.
    /// If the schema renames a field, removes a variant, or changes a serde
    /// representation, this test fails before the docs ship.
    #[test]
    fn ecds_dr_carrier_doc_worked_example_parses() {
        use crate::modes::mesh::config::{
            MeshLoadBalancer, MeshSimpleLb, MeshTrafficPolicyTls, MtlsMode,
        };
        let dr_json = r#"{
  "name": "api-dr",
  "namespace": "default",
  "host": "api.default.svc.cluster.local",
  "traffic_policy": {
    "connect_timeout_ms": 2000,
    "load_balancer": {"simple": "ROUND_ROBIN"},
    "outlier_detection": {"consecutive_errors": 5, "interval_seconds": 30},
    "tls": {"mode": "istio_mutual", "sni": "api.default.svc.cluster.local"}
  },
  "subsets": [{"name": "v1", "labels": {"version": "v1"}}]
}"#;
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[dr_carrier_resource("api-dr", dr_json)],
                "v1",
            )
            .expect("ECDS apply");
        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate")
            .expect("all required types present");
        assert_eq!(slice.destination_rules.len(), 1);
        let dr = &slice.destination_rules[0];
        assert_eq!(dr.name, "api-dr");
        assert_eq!(dr.namespace, "default");
        assert_eq!(dr.host, "api.default.svc.cluster.local");
        let policy = dr.traffic_policy.as_ref().expect("traffic_policy");
        assert_eq!(policy.connect_timeout_ms, Some(2000));
        assert!(matches!(
            policy.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin))
        ));
        let od = policy
            .outlier_detection
            .as_ref()
            .expect("outlier_detection");
        assert_eq!(od.consecutive_errors, Some(5));
        assert_eq!(od.interval_seconds, Some(30));
        let tls: &MeshTrafficPolicyTls = policy.tls.as_ref().expect("tls");
        assert_eq!(tls.mode, MtlsMode::IstioMutual);
        assert_eq!(tls.sni.as_deref(), Some("api.default.svc.cluster.local"));
        assert_eq!(dr.subsets.len(), 1);
        assert_eq!(dr.subsets[0].name, "v1");
        assert_eq!(
            dr.subsets[0].labels.get("version").map(String::as_str),
            Some("v1")
        );
    }

    // ── GAP-1a: full-parity slice carriers ──
    //
    // These tests pin the core GAP-1a guarantee: a slice carried over xDS is
    // functionally equivalent to one carried over `native` (same authz / mTLS /
    // JWT / trust-bundle / ServiceEntry / ProxyConfig / workload behavior). The
    // round trip drives the REAL production path: CP-side
    // `translate_mesh_slice_to_snapshot` → ECDS resources on the wire → DP-side
    // `ResourceAccumulator` → `reverse_translate`.

    /// Feed a CP-built snapshot into a DP accumulator exactly as the live ADS
    /// stream would (one SotW response per type URL).
    fn accumulator_from_snapshot(
        snapshot: &crate::xds::snapshot::XdsSnapshot,
    ) -> ResourceAccumulator {
        let mut accumulator = ResourceAccumulator::new();
        for type_url in XDS_TYPE_URLS {
            let resources: Vec<proto::Any> = snapshot
                .resources(type_url)
                .iter()
                .map(|resource| resource.to_any())
                .collect();
            accumulator
                .apply_sotw_response(type_url, &resources, &snapshot.version)
                .expect("snapshot resources apply");
        }
        accumulator
    }

    /// A representative protected slice: authz policy + PeerAuthentication +
    /// ServiceEntry + trust bundle + request auth + proxy config + workloads.
    fn representative_protected_slice() -> MeshSlice {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            MeshDestinationRule, MeshEndpoint, MeshJwtRule, MeshLoadBalancer, MeshPolicy,
            MeshProxyConfig, MeshRequestAuthentication, MeshRule, MeshSimpleLb, MeshTrafficPolicy,
            MtlsMode, OutboundTrafficPolicy, PeerAuthentication, PolicyAction, PolicyScope,
            Resolution, ServiceEntry, ServiceEntryLocation, TrustBundle, TrustBundleSet, Workload,
            WorkloadPort, WorkloadRef, WorkloadSelector,
        };
        use crate::modes::mesh::slice::{MeshEgressScopeResource, MeshEgressScopeSnapshot};

        let td = TrustDomain::new("cluster.local").expect("trust domain");
        let workload = Workload {
            spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/api".to_string())
                .expect("spiffe id"),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "api".to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: "api".to_string(),
            addresses: vec!["10.0.0.5".to_string()],
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: td.clone(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("api".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        };
        let service = MeshService {
            cluster_ips: Vec::new(),
            name: "api".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: workload.spiffe_id.clone(),
            }],
            protocol_overrides: HashMap::new(),
        };
        MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            workloads: vec![workload.clone()],
            ambient_udp_source_workloads: vec![workload.clone()],
            node_waypoint_assertors: vec![
                SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/node-waypoint")
                    .expect("node waypoint spiffe id"),
            ],
            services: vec![service.clone()],
            // Inbound-only un-narrowed views must round-trip via their dedicated
            // ECDS carriers independent of the egress-narrowed `services` /
            // identity-narrowed `workloads`.
            local_inbound_services: vec![service],
            local_inbound_workloads: Some(vec![workload]),
            // F6 §6.2: a resolved ingress listener AND the fail-closed declared
            // marker must round-trip via their dedicated ECDS carriers.
            local_ingress_listeners: vec![crate::modes::mesh::config::ResolvedIngressListener {
                port: 8443,
                endpoint_host: "127.0.0.1".to_string(),
                endpoint_port: 8080,
                owner_namespace: "default".to_string(),
                owner_service: "api".to_string(),
            }],
            sidecar_ingress_declared: true,
            // F6 §6.2 (codex round-4 P2): the DECLARED HTTP-family ingress port
            // count (here 2 > the 1 resolved listener) must round-trip via its
            // dedicated ECDS carrier so the DP router keeps the group ambiguous.
            declared_ingress_http_ports: 2,
            mesh_policies: vec![MeshPolicy {
                name: "allow-api".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::Namespace {
                    namespace: "default".to_string(),
                },
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            peer_authentications: vec![PeerAuthentication {
                name: "selector-strict".to_string(),
                namespace: "default".to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            }],
            request_authentications: vec![MeshRequestAuthentication {
                name: "jwt".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::Namespace {
                    namespace: "default".to_string(),
                },
                jwt_rules: vec![MeshJwtRule {
                    issuer: "https://issuer.example".to_string(),
                    audiences: vec!["api".to_string()],
                    jwks_uri: Some("https://issuer.example/jwks".to_string()),
                    jwks: None,
                    from_headers: Vec::new(),
                    from_params: Vec::new(),
                    forward_original_token: false,
                }],
            }],
            service_entries: vec![ServiceEntry {
                name: "external-api".to_string(),
                namespace: "default".to_string(),
                hosts: vec!["api.example.com".to_string()],
                endpoints: vec![MeshEndpoint {
                    address: "203.0.113.10".to_string(),
                    ports: HashMap::from([("https".to_string(), 443u16)]),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution: Resolution::Static,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                    target_port: None,
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            proxy_configs: vec![MeshProxyConfig {
                name: "default".to_string(),
                ..MeshProxyConfig::default()
            }],
            destination_rules: vec![MeshDestinationRule {
                name: "api-dr".to_string(),
                namespace: "default".to_string(),
                host: "api.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(250),
                    load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            trust_bundles: Some(TrustBundleSet {
                local: TrustBundle {
                    trust_domain: td,
                    x509_authorities: vec!["QUJD".to_string()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: Some(3600),
                },
                federated: Vec::new(),
            }),
            outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
            sidecar_egress_scope: Some(MeshEgressScopeSnapshot {
                sidecar_enforced: true,
                dry_run: true,
                sidecar_applied: true,
                sidecar_admitted_services: 1,
                sidecar_denied_services: 1,
                services: vec![MeshEgressScopeResource {
                    namespace: "default".to_string(),
                    name: "api".to_string(),
                    hosts: vec!["api.default.svc.cluster.local".to_string()],
                    ports: vec![8080],
                }],
                known_destinations: vec!["api.default.svc.cluster.local:8080".to_string()],
                ..MeshEgressScopeSnapshot::default()
            }),
            ..MeshSlice::default()
        }
    }

    #[test]
    fn xds_round_trip_preserves_protected_slice_fields() {
        let native = representative_protected_slice();
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        // Every security- and policy-bearing field must round-trip. Before
        // GAP-1a these were all empty after xDS reverse-translation.
        assert_eq!(recovered.mesh_policies, native.mesh_policies);
        assert_eq!(recovered.peer_authentications, native.peer_authentications);
        assert_eq!(
            recovered.request_authentications,
            native.request_authentications
        );
        assert_eq!(recovered.service_entries, native.service_entries);
        assert_eq!(recovered.destination_rules, native.destination_rules);
        assert_eq!(recovered.trust_bundles, native.trust_bundles);
        assert_eq!(recovered.proxy_configs, native.proxy_configs);
        assert_eq!(recovered.workloads, native.workloads);
        assert_eq!(
            recovered.ambient_udp_source_workloads,
            native.ambient_udp_source_workloads
        );
        assert_eq!(
            recovered.node_waypoint_assertors,
            native.node_waypoint_assertors
        );
        assert_eq!(recovered.labels, native.labels);
        assert_eq!(
            recovered.outbound_traffic_policy,
            native.outbound_traffic_policy
        );
        assert_eq!(recovered.sidecar_egress_scope, native.sidecar_egress_scope);
        // Services round-trip with full protocol + workload-ref shape via the
        // Services carrier (not the name-only CDS/EDS reconstruction).
        assert_eq!(recovered.services, native.services);
        // The inbound-only un-narrowed views round-trip via their own carriers.
        assert_eq!(
            recovered.local_inbound_services,
            native.local_inbound_services
        );
        assert_eq!(
            recovered.local_inbound_workloads,
            native.local_inbound_workloads
        );
        // F6 §6.2: resolved ingress listeners + the fail-closed declared marker
        // round-trip via their own carriers.
        assert_eq!(
            recovered.local_ingress_listeners,
            native.local_ingress_listeners
        );
        assert!(
            recovered.sidecar_ingress_declared,
            "the sidecar-ingress-declared marker must survive the xDS round trip"
        );
        assert_eq!(
            recovered.declared_ingress_http_ports, native.declared_ingress_http_ports,
            "the declared HTTP-family ingress port count must survive the xDS round trip"
        );
        assert_eq!(
            recovered.declared_ingress_http_ports, 2,
            "the declared count (2) exceeds the 1 resolved listener and must be preserved \
             so the DP router keeps the partially materialized group ambiguous"
        );

        // Resolved-behavior parity spot-checks: the recovered slice answers
        // the same mTLS-posture and outbound-policy questions native would.
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            native.resolve_effective_mtls_mode(8080)
        );
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            crate::modes::mesh::config::MtlsMode::Strict,
            "strict PeerAuthentication must survive the xDS round trip"
        );
    }

    #[test]
    fn xds_round_trip_service_entry_only_slice_does_not_invent_services() {
        use crate::modes::mesh::config::{
            MeshEndpoint, Resolution, ServiceEntry, ServiceEntryLocation,
        };

        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            services: Vec::new(),
            service_entries: vec![ServiceEntry {
                name: "external-api".to_string(),
                namespace: "default".to_string(),
                hosts: vec!["api.example.com".to_string()],
                endpoints: vec![MeshEndpoint {
                    address: "203.0.113.10".to_string(),
                    ports: HashMap::from([("https".to_string(), 443u16)]),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution: Resolution::Static,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                    target_port: None,
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert!(recovered.services.is_empty());
        assert_eq!(recovered.service_entries, native.service_entries);
    }

    #[test]
    fn xds_round_trip_empty_carrier_labels_fall_back_to_local_dp_labels() {
        use crate::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};

        // An empty WorkloadLabels carrier is NOT authoritative: a Ferrum CP
        // always emits the carrier, and it is empty whenever the CP could not
        // compute labels for this DP (default non-SPIFFE node id + empty
        // `Node.metadata`). Recovery must therefore keep the DP's explicit
        // local labels rather than wiping them, so selector-scoped policies
        // keep matching the workload's real labels.
        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::new(),
            peer_authentications: vec![PeerAuthentication {
                name: "selector-strict".to_string(),
                namespace: "default".to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();
        config.labels = BTreeMap::from([("app".to_string(), "api".to_string())]);

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert_eq!(
            recovered.labels,
            BTreeMap::from([("app".to_string(), "api".to_string())]),
            "an empty (uninformed) CP carrier must not wipe the DP's explicit local labels"
        );
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            MtlsMode::Strict,
            "the DP's retained local labels must keep matching the selector-scoped PeerAuthentication"
        );
    }

    #[test]
    fn xds_round_trip_nonempty_carrier_labels_override_local_dp_labels() {
        use crate::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};

        // A non-empty carrier IS authoritative: the CP computed real labels for
        // this workload, so they replace the DP's local labels. Here the carrier
        // labels (`app=web`) differ from the DP's local labels (`app=api`); the
        // selector-strict policy keyed on `app=web` must match the carrier
        // labels, proving the carrier — not the local config — won.
        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::from([("app".to_string(), "web".to_string())]),
            peer_authentications: vec![PeerAuthentication {
                name: "selector-strict".to_string(),
                namespace: "default".to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "web".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();
        config.labels = BTreeMap::from([("app".to_string(), "api".to_string())]);

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert_eq!(
            recovered.labels,
            BTreeMap::from([("app".to_string(), "web".to_string())]),
            "a non-empty carrier is authoritative and must override the local DP labels"
        );
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            MtlsMode::Strict,
            "the authoritative carrier labels must match the selector-scoped PeerAuthentication"
        );
    }

    #[test]
    fn xds_round_trip_ambiguous_carrier_labels_defer_to_local_dp_labels() {
        use crate::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};

        // Ambiguous shared-SPIFFE: the carrier labels are the INTERSECTION
        // (`app=shared`), the slice carries a candidate-any selector
        // PeerAuthentication keyed on the divergent `role=api`, and the
        // `labels_ambiguous` marker is set. The DP holds its real labels
        // (`app=shared, role=api`). Recovery must DEFER to the DP labels (not
        // the partial intersection), so the `role=api` STRICT policy still
        // matches — otherwise it would be dropped (the non-empty-intersection
        // fail-open this fix closes).
        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![PeerAuthentication {
                name: "role-api-strict".to_string(),
                namespace: "default".to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("role".to_string(), "api".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();
        config.labels = BTreeMap::from([
            ("app".to_string(), "shared".to_string()),
            ("role".to_string(), "api".to_string()),
        ]);

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert_eq!(
            recovered.labels,
            BTreeMap::from([
                ("app".to_string(), "shared".to_string()),
                ("role".to_string(), "api".to_string()),
            ]),
            "ambiguous intersection carrier must defer to the DP's authoritative local labels"
        );
        assert!(
            !recovered.labels_ambiguous,
            "the DP's recovered labels are authoritative; the marker is cleared after recovery"
        );
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            MtlsMode::Strict,
            "the candidate-only role=api PeerAuthentication must still match the DP's real labels"
        );
    }

    #[test]
    fn xds_round_trip_ambiguous_carrier_labels_merge_common_intersection_with_partial_local() {
        use crate::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};

        // Codex P1 (xds_client.rs:1487): the ambiguous-intersection carrier
        // labels common to every candidate (`app=shared`) are authoritative for
        // THOSE keys. When the DP supplies ONLY the disambiguating label
        // (`role=api`) and NOT the common one, recovery must MERGE the
        // intersection with the local labels rather than REPLACE the intersection
        // wholesale — otherwise a selector policy scoped to the common
        // `app=shared` (which the CP proved applies to every candidate) is dropped
        // (the wholesale-replace fail-open). The slice carries TWO candidate-any
        // selector PeerAuths: one on the common `app=shared` (must survive) and one
        // on the divergent `role=api` (resolved by the local label).
        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![
                PeerAuthentication {
                    name: "app-shared-strict".to_string(),
                    namespace: "default".to_string(),
                    scope: None,
                    selector: Some(WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "shared".to_string())]),
                        namespace: None,
                    }),
                    mtls_mode: MtlsMode::Strict,
                    port_overrides: HashMap::new(),
                },
                PeerAuthentication {
                    name: "role-api-permissive".to_string(),
                    namespace: "default".to_string(),
                    scope: None,
                    selector: Some(WorkloadSelector {
                        labels: HashMap::from([("role".to_string(), "api".to_string())]),
                        namespace: None,
                    }),
                    mtls_mode: MtlsMode::Permissive,
                    port_overrides: HashMap::new(),
                },
            ],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        // DP supplies ONLY the disambiguating label, NOT the common `app=shared`.
        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();
        config.labels = BTreeMap::from([("role".to_string(), "api".to_string())]);

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert_eq!(
            recovered.labels,
            BTreeMap::from([
                ("app".to_string(), "shared".to_string()),
                ("role".to_string(), "api".to_string()),
            ]),
            "the common intersection must be MERGED with the partial local labels, not replaced"
        );
        assert!(
            !recovered.labels_ambiguous,
            "the DP supplied local labels, so the merged set is authoritative and the marker clears"
        );
        // The WorkloadSelector tier wins; the more-restrictive Strict wins a
        // same-tier tie — so the common `app=shared` STRICT must still resolve.
        assert_eq!(
            recovered.resolve_effective_mtls_mode(8080),
            MtlsMode::Strict,
            "the common-key app=shared STRICT PeerAuthentication must survive the merge"
        );
    }

    #[test]
    fn xds_round_trip_preserves_ambiguous_marker_when_dp_has_no_local_labels() {
        use crate::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};

        // Ambiguous shared-SPIFFE slice with an EMPTY label intersection (the
        // candidates diverge with no common label), and the DP supplies NO local
        // `FERRUM_MESH_WORKLOAD_LABELS`. `pick_recovered_labels` then falls back
        // to the (empty) intersection, which is NOT authoritative, so the
        // recovered slice MUST keep `labels_ambiguous = true` — otherwise the
        // mesh_authz ambiguous-slice fail-closed check never runs and the
        // candidate-only selector policy is silently dropped (fail-open).
        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            labels: BTreeMap::new(),
            labels_ambiguous: true,
            peer_authentications: vec![PeerAuthentication {
                name: "role-api-strict".to_string(),
                namespace: "default".to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("role".to_string(), "api".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        // DP config: no local labels to make the intersection authoritative.
        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();
        config.labels = BTreeMap::new();

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert!(
            recovered.labels.is_empty(),
            "with no local DP labels the recovered labels stay the empty intersection"
        );
        assert!(
            recovered.labels_ambiguous,
            "the marker must be PRESERVED when the recovered labels are not authoritative"
        );
    }

    #[test]
    fn xds_round_trip_preserves_cross_namespace_destination_rule() {
        use crate::modes::mesh::config::MeshDestinationRule;

        let native = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            destination_rules: vec![MeshDestinationRule {
                name: "api-dr".to_string(),
                namespace: "other".to_string(),
                host: "api.other.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&native);
        let accumulator = accumulator_from_snapshot(&snapshot);

        let mut config = test_config();
        config.node_id = native.node_id.clone();
        config.namespace = native.namespace.clone();

        let recovered = accumulator
            .try_build_mesh_slice(&config)
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert_eq!(recovered.destination_rules, native.destination_rules);
    }

    #[test]
    fn xds_slice_carrier_requires_reserved_resource_name() {
        use crate::modes::mesh::config::{MeshPolicy, MeshRule, PolicyAction, PolicyScope};
        use crate::xds::carrier::FERRUM_ECDS_MESH_POLICIES_TYPE_URL;

        let malicious_policies = vec![MeshPolicy {
            name: "clear-or-replace-authz".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::Namespace {
                namespace: "default".to_string(),
            },
            rules: vec![MeshRule {
                action: PolicyAction::Deny,
                ..MeshRule::default()
            }],
        }];
        let payload = serde_json::to_vec(&malicious_policies).expect("policy json");
        let mut accumulator = primed_accumulator();
        accumulator
            .apply_sotw_response(
                ECDS_TYPE_URL,
                &[typed_extension_resource(
                    "operator-mesh-policies",
                    FERRUM_ECDS_MESH_POLICIES_TYPE_URL,
                    payload,
                )],
                "v1",
            )
            .expect("ECDS applies");

        let recovered = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all required types present");

        assert!(
            recovered.mesh_policies.is_empty(),
            "operator ECDS resources must not impersonate internal slice carriers"
        );
    }

    #[test]
    fn xds_round_trip_without_carriers_falls_back_to_name_only_services() {
        // Simulate an older Ferrum-shaped xDS CP: CDS/EDS names only, no
        // Ferrum carriers.
        // The DP must still reconstruct service ports (fail-open routing) but
        // with empty security fields — the documented degraded mode.
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS applies");
        for type_url in [
            EDS_TYPE_URL,
            LDS_TYPE_URL,
            RDS_TYPE_URL,
            ECDS_TYPE_URL,
            SDS_TYPE_URL,
        ] {
            accumulator
                .apply_sotw_response(type_url, &[], "v1")
                .expect("empty applies");
        }

        let recovered = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("required types present");

        assert_eq!(recovered.services.len(), 1);
        assert_eq!(recovered.services[0].name, "api");
        assert!(recovered.mesh_policies.is_empty());
        assert!(recovered.peer_authentications.is_empty());
        assert!(recovered.trust_bundles.is_none());
        assert!(recovered.workloads.is_empty());
    }
}
