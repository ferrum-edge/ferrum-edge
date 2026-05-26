use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs,
    refresh_dp_grpc_tls_config_if_changed, tonic_tls_config, wait_for_shutdown,
    wait_optional_tls_reload,
};
use crate::grpc::dp_client::{
    DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret, generate_dp_jwt_with_issuer,
};
use crate::modes::mesh::config::{AppProtocol, MeshRuntimeOverlay, MeshService, ServicePort};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::MeshSlice;
use crate::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::proto::{self, DiscoveryRequest, Node, Status};
use crate::xds::runtime_proto;
use crate::xds::translator::{
    CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL, LDS_TYPE_URL,
    RDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS, translate_rtds_layer,
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
    // level via `runtime_overlay_consumers::apply_overlay` at slice install.
    // Kept last so the baseline slice can apply even when the CP has no
    // Runtime layers to send.
    RTDS_TYPE_URL,
];
const REQUIRED_MESH_SLICE_TYPE_URLS: [&str; 4] =
    [CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL];
const XDS_APPLY_DEBOUNCE: Duration = Duration::from_millis(25);
const XDS_CONSECUTIVE_NACK_LIMIT: u32 = 5;
const XDS_APPLY_MAX_DELAY: Duration = Duration::from_millis(500);

type BearerToken = MetadataValue<tonic::metadata::Ascii>;

#[derive(Clone)]
struct AdsAuth {
    jwt_secret: GrpcJwtSecret,
    node_id: String,
}

impl AdsAuth {
    fn bearer_token(&self) -> Result<BearerToken, tonic::Status> {
        let auth_token = generate_dp_jwt_with_issuer(
            self.jwt_secret.as_str(),
            &self.node_id,
            self.jwt_secret.issuer(),
        )
        .map_err(|e| tonic::Status::unauthenticated(format!("failed to mint xDS JWT: {e}")))?;
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
    has_initial_response: bool,
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

    fn build_initial_requests(&self, node_id: &str, cluster: &str) -> Vec<DiscoveryRequest> {
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
                        metadata: Vec::new(),
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

    fn record_response(&mut self, type_url: &str, version_info: &str, nonce: &str) {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        subscription.last_received_version = Some(version_info.to_string());
        subscription.last_received_nonce = Some(nonce.to_string());
        subscription.has_initial_response = true;
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
}

#[derive(Debug, Clone, Default)]
struct NackCircuitBreaker {
    consecutive_nacks_by_type: HashMap<String, u32>,
}

impl NackCircuitBreaker {
    fn record_ack(&mut self, type_url: &str) {
        self.consecutive_nacks_by_type.remove(type_url);
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
        if !resources.is_empty() && version.trim().is_empty() {
            return Err(format!(
                "xDS response for type_url '{type_url}' has resources but empty version_info"
            ));
        }

        let mut accumulated = Vec::with_capacity(resources.len());
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
            // ECDS reverse-translation reads the full bytes back to decode
            // its inner TypedExtensionConfig. RTDS reverse-translation does
            // the same to decode the layer struct. Other resource types
            // only carry routing names, so skip the allocation.
            let bytes = if type_url == ECDS_TYPE_URL || type_url == RTDS_TYPE_URL {
                resource.value.clone()
            } else {
                Vec::new()
            };
            accumulated.push(AccumulatedResource { name, bytes });
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

    fn try_build_mesh_slice(&self, config: &XdsClientConfig) -> Result<Option<MeshSlice>, String> {
        if !self.has_required_types() {
            return Ok(None);
        }
        reverse_translate(self, config).map(Some)
    }
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
        let should_race_primary = should_race_primary_retry(
            is_fallback,
            config.primary_retry_secs,
            state.has_first_slice(),
        );
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
                _ = tokio::time::sleep(Duration::from_secs(config.primary_retry_secs)) => {
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

fn should_race_primary_retry(
    is_fallback: bool,
    primary_retry_secs: u64,
    has_first_slice: bool,
) -> bool {
    is_fallback && primary_retry_secs > 0 && has_first_slice
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
    );

    let (tx, rx) = mpsc::channel(config.stream_channel_capacity.max(1));
    let request_stream = ReceiverStream::new(rx);
    let mut response_stream = client
        .stream_aggregated_resources(request_stream)
        .await?
        .into_inner();

    for request in stream_state
        .subscriptions
        .build_initial_requests(&config.node_id, &config.cluster)
    {
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
                    Ok(None) => {}
                    Err(e) => {
                        return flush_pending_xds_slice_before_error(
                            consumer,
                            config,
                            &mut pending_slice,
                            e,
                        );
                    }
                }
            }
            _ = &mut debounce, if debounce_active => {
                if let Some(pending) = pending_slice.take() {
                    apply_pending_xds_slice(consumer, config, pending);
                }
                debounce_active = false;
                pending_since = None;
            }
        }
    }

    if let Some(pending) = pending_slice.take() {
        apply_pending_xds_slice(consumer, config, pending);
    }

    Ok(())
}

fn flush_pending_xds_slice_before_error(
    consumer: &XdsConfigConsumer,
    config: &XdsClientConfig,
    pending_slice: &mut Option<PendingXdsSlice>,
    error: anyhow::Error,
) -> Result<(), anyhow::Error> {
    if let Some(pending) = pending_slice.take() {
        apply_pending_xds_slice(consumer, config, pending);
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

    subscriptions.record_response(&type_url, &response.version_info, &response.nonce);
    let snapshot = accumulator.clone();
    let apply_result =
        accumulator.apply_sotw_response(&type_url, &response.resources, &response.version_info);
    let slice_result = apply_result.and_then(|_| accumulator.try_build_mesh_slice(config));

    match slice_result {
        Ok(Some(slice)) => {
            send_ads_request(tx, subscriptions.build_ack(&type_url)).await?;
            subscriptions.mark_acked(&type_url);
            nack_circuit_breaker.record_ack(&type_url);
            Ok(Some(PendingXdsSlice {
                slice,
                type_url,
                all_types_ready: subscriptions.required_types_have_initial_response(),
            }))
        }
        Ok(None) => {
            send_ads_request(tx, subscriptions.build_ack(&type_url)).await?;
            subscriptions.mark_acked(&type_url);
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
            warn!(
                node_id = %config.node_id,
                type_url = %type_url,
                error = %e,
                "NACKing invalid xDS ADS response"
            );
            send_ads_request(tx, subscriptions.build_nack(&type_url, e)).await?;
            trip_nack_circuit_if_needed(config, nack_circuit_breaker, &type_url)?;
            Ok(None)
        }
    }
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
) {
    let version = pending.slice.version.clone();
    consumer.apply_slice(pending.slice);
    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        version = %version,
        type_url = %pending.type_url,
        all_types_ready = pending.all_types_ready,
        "Applied debounced xDS ADS update"
    );
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

    pub fn apply_slice(&self, slice: MeshSlice) {
        self.state.install_slice(slice);
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
            return Err(format!(
                "route resource '{}' references service '{}/{}' with no cluster/listener resource",
                resource.name, parsed.namespace, parsed.service
            ));
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
        let typed_extension = match proto::TypedExtensionConfig::decode(resource.bytes.as_slice()) {
            Ok(value) => value,
            Err(e) => {
                warn!(
                    resource_name = %resource.name,
                    error = %e,
                    "xDS ECDS resource failed TypedExtensionConfig decode; skipping"
                );
                continue;
            }
        };
        let Some(inner) = typed_extension.typed_config else {
            continue;
        };
        if inner.type_url != FERRUM_ECDS_DESTINATION_RULE_TYPE_URL {
            continue;
        }
        dr_carrier_seen = true;
        match serde_json::from_slice::<crate::modes::mesh::config::MeshDestinationRule>(
            &inner.value,
        ) {
            Ok(dr) => {
                if dr.namespace != config.namespace {
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

    let services = service_ports
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
                })
                .collect(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        })
        .collect();

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

    // GAP-3E: merge RTDS layers into the slice's runtime overlay. Layers
    // arrive sorted by resource name on the wire; later fields win on key
    // conflicts so a higher-priority layer overrides a base layer. Layers
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
        labels: config.labels.clone(),
        version: accumulator
            .versions_by_type
            .get(CDS_TYPE_URL)
            .cloned()
            .unwrap_or_default(),
        workloads: Vec::new(),
        services,
        mesh_policies: Vec::new(),
        peer_authentications: Vec::new(),
        request_authentications: Vec::new(),
        telemetry_resources: Vec::new(),
        // Phase B reverse translation rebuilds service routing names only.
        // External ServiceEntry shape is not recoverable from the minimal
        // CDS/EDS names consumed here; richer xDS metadata will fill this in.
        service_entries: Vec::new(),
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
        // ProxyConfig is config-time and not exposed via standard xDS — the
        // CP would have already applied concurrency/image/env-var changes
        // before emitting CDS, so it cannot be round-tripped here. Operators
        // relying on ProxyConfig translation must use the native protocol.
        proxy_configs: Vec::new(),
        trust_bundles: None,
        multi_cluster: None,
        // MeshConfig outboundTrafficPolicy is not represented in the minimal
        // ADS resources consumed here. xDS deployments use the runtime env
        // fallback until MeshConfig translation is wired.
        outbound_traffic_policy: None,
        sidecar_egress_scope: None,
        // GAP-2L.3: xDS-only deployments don't round-trip ECDS resources back
        // into the slice today. The DR-carrier path (GAP-2K) lands them
        // alongside CDS via the same wire so this stays empty unless future
        // ADS-side recovery wires it.
        extension_configs: Vec::new(),
        // GAP-3E: merged RTDS layers. Empty when no Runtime resources have
        // shipped on this stream.
        runtime_overlay,
    })
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
        let requests = ClientSubscriptionState::new().build_initial_requests("node-a", "default");
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
    fn initial_type_url_order_matches_supported_type_set() {
        let supported: BTreeSet<_> = XDS_TYPE_URLS.iter().copied().collect();
        let initial: BTreeSet<_> = INITIAL_TYPE_URL_ORDER.iter().copied().collect();

        assert_eq!(initial, supported);
    }

    #[test]
    fn primary_retry_waits_for_initial_mesh_slice() {
        assert!(!should_race_primary_retry(true, 300, false));
        assert!(should_race_primary_retry(true, 300, true));
        assert!(!should_race_primary_retry(false, 300, true));
        assert!(!should_race_primary_retry(true, 0, true));
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

        let requests = state.build_initial_requests("node-a", "default");
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
                .build_initial_requests("node-a", "default")
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
    async fn invalid_cross_type_update_rolls_back_accumulator() {
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
        .expect("invalid cross-type update should NACK");

        assert!(result.is_none());
        assert_eq!(
            accumulator.resources(RDS_TYPE_URL)[0].name,
            "route/default/api"
        );
        assert_eq!(
            accumulator.versions_by_type.get(RDS_TYPE_URL).unwrap(),
            "v1"
        );
        let nack = rx.recv().await.expect("NACK sent");
        assert_eq!(nack.type_url, RDS_TYPE_URL);
        assert_eq!(nack.version_info, "");
        assert!(nack.error_detail.is_some());
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
                    vec![any_resource(RDS_TYPE_URL, "route/default/missing")],
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
                vec![any_resource(RDS_TYPE_URL, "route/default/missing")],
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
    fn accumulator_requires_core_types_but_not_sds() {
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
        for type_url in [EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL] {
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
                name: "api".to_string(),
                namespace: "default".to_string(),
                ports: vec![
                    ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                    },
                    ServicePort {
                        port: 9090,
                        protocol: AppProtocol::Grpc,
                        name: Some("grpc".to_string()),
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
        use prost::Message;
        let typed_extension = proto::TypedExtensionConfig {
            name: name.to_string(),
            typed_config: Some(proto::Any {
                type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
                value: dr_json.as_bytes().to_vec(),
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
}
