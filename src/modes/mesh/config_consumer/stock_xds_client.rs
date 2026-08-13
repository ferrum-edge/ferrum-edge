//! Stock Envoy / third-party Istio ADS consumer
//! (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`, issue #3317).
//!
//! This is a **separate protocol** from `FERRUM_MESH_CONFIG_PROTOCOL=xds`, not
//! a mode of it. The Ferrum-private xDS client in [`super::xds_client`] keeps
//! its name-only resource shapes, its `ferrum.config.extension.v3.*` ECDS
//! carriers, and its required-type version-coherence gate; nothing here reaches
//! into that path, and a stock control plane can never drive it.
//!
//! ## Split of authority
//!
//! * The stock control plane is a **discovery** authority. It supplies standard
//!   v3 CDS/EDS/LDS/RDS, which [`crate::xds::stock`] projects onto
//!   `MeshConfig.services` and `MeshConfig.workloads`.
//! * Ferrum's **local mesh policy document** (`FERRUM_MESH_FILE_CONFIG_PATH`)
//!   is the **policy** authority. Authorization policies, PeerAuthentication,
//!   RequestAuthentication, trust bundles, DestinationRules, Sidecar scope, and
//!   ProxyConfig all come from there and are re-read on SIGHUP.
//!
//! That split is the whole security story: a third-party CP that Ferrum does
//! not otherwise trust can add or remove *reachability*, but it can never
//! author or weaken Ferrum's enforcement posture. The startup check refuses a
//! policy document that declares `services` or `workloads` so the two
//! authorities cannot silently overlap.
//!
//! ## Protocol behaviour
//!
//! State-of-the-world ADS with per-type nonces, ACK/NACK with field-specific
//! error details, dependency-ordered subscriptions (EDS follows the accepted
//! CDS clusters, RDS follows the accepted LDS listeners), wholesale replacement
//! of the complete-state types (CDS/LDS) with subscription-pruned merging for
//! the by-name types (EDS/RDS, whose responses may be partial) so deletions
//! propagate without a partial push blackholing untouched services, debounced
//! make-before-break publication through `MeshRuntimeState::install_slice`, a
//! consecutive-NACK circuit breaker, jittered backoff, and multi-server
//! failover. Unlike the Ferrum profile there is no cross-type
//! version-coherence gate: a stock CP versions each type independently and
//! carries no Ferrum security carriers that a skew could leave stale.
//!
//! Ferrum NEVER mints a Ferrum CP/DP JWT for a stock control plane. The only
//! credential it will present is an externally issued bearer token the operator
//! points at with `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` (typically a projected
//! Kubernetes service-account token); with no token file configured the stream
//! carries no `authorization` metadata and relies on gRPC TLS alone.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prost::Message;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE, jittered_backoff,
    next_backoff_secs, refresh_dp_grpc_tls_config_if_changed, should_race_primary_retry,
    tonic_tls_config, wait_for_shutdown, wait_optional_tls_reload,
};
#[cfg(unix)]
use super::file_source::SignalReloadNotifier;
use super::file_source::{
    MeshLocalReloadApply, MeshLocalReloadResult, MeshLocalSourceRecovery, MeshReloadLoopMessages,
    mark_mesh_local_reload_rejected, normalized_mesh_gateway_config, read_mesh_config_document,
    run_mesh_local_reload_loop,
};
use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload};
use crate::modes::mesh::config::MeshConfig;
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall, XdsConvergenceSnapshot};
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::proto::{self, DiscoveryRequest, Node, Status};
use crate::xds::runtime_proto;
use crate::xds::stock::{
    StockDiscovery, StockRefusal, StockXdsAccumulator, StockXdsLimits, diagnostic_value,
    refuse_stock_secret,
};
use crate::xds::translator::{
    CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL,
};

/// Wildcard subscriptions opened as soon as the stream comes up. EDS and RDS
/// are subscribed later, by name, once their dependencies land.
const STOCK_INITIAL_TYPE_URL_ORDER: [&str; 2] = [CDS_TYPE_URL, LDS_TYPE_URL];

const STOCK_APPLY_DEBOUNCE: Duration = Duration::from_millis(25);
const STOCK_APPLY_MAX_DELAY: Duration = Duration::from_millis(500);
const STOCK_CONSECUTIVE_NACK_LIMIT: u32 = 5;
/// Bound the complete stock bearer-token admission attempt, including waiting
/// for an earlier timed-out reader to leave the kernel.
const STOCK_XDS_TOKEN_FILE_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum distinct refusals logged per apply. Refusals are bounded input from
/// the control plane, so the log line is capped rather than unbounded.
const STOCK_REFUSAL_LOG_LIMIT: usize = 12;

/// A timed-out mount read may keep its detached OS thread blocked. The permit
/// moves into that thread, so repeated ADS reconnects cannot accumulate more
/// blocked readers while the same credential source remains unavailable.
static STOCK_XDS_TOKEN_FILE_READ_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(crate) fn stock_xds_token_file_read_limit() -> Arc<Semaphore> {
    Arc::clone(STOCK_XDS_TOKEN_FILE_READ_LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))))
}

pub(crate) type BearerToken = MetadataValue<tonic::metadata::Ascii>;

/// Stock ADS client settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockXdsClientConfig {
    /// Third-party ADS endpoints, in failover order.
    pub xds_urls: Vec<String>,
    /// `DiscoveryRequest.node.id`, verbatim. A stock control plane derives the
    /// proxy's config from this, so Ferrum never invents or rewrites it.
    pub node_id: String,
    /// `DiscoveryRequest.node.cluster`.
    pub cluster: String,
    /// Ferrum mesh namespace this data plane serves.
    pub namespace: String,
    /// Flat string metadata encoded into `Node.metadata` as a
    /// `google.protobuf.Struct`.
    pub node_metadata: BTreeMap<String, String>,
    /// Path to an externally issued bearer token presented to the stock CP.
    /// `None` sends no `authorization` metadata.
    pub token_file: Option<String>,
    pub stream_channel_capacity: usize,
    pub primary_retry_secs: u64,
    /// Client connection timeout. `0` disables tonic's explicit connect timeout.
    pub connect_timeout_seconds: u64,
    pub limits: StockXdsLimits,
}

/// Load and validate the local mesh policy document that backs the stock
/// profile's enforcement posture.
///
/// Fail-closed at startup on two counts: an unreadable/invalid document refuses
/// startup exactly like `FERRUM_MESH_CONFIG_PROTOCOL=file`, and a document that
/// declares `services` or `workloads` is refused outright — discovery owns
/// those, and silently merging two authorities for the same field would make
/// "which endpoint is reachable" ambiguous.
pub fn load_stock_policy_baseline(path: &Path) -> Result<MeshConfig, anyhow::Error> {
    let mesh = read_mesh_config_document(path)?;
    if !mesh.services.is_empty() || !mesh.workloads.is_empty() {
        anyhow::bail!(
            "mesh policy document '{}' declares `services` or `workloads`, which the stock xDS \
             profile sources from the control plane. Remove them, or use \
             FERRUM_MESH_CONFIG_PROTOCOL=file for a fully local mesh.",
            path.display()
        );
    }
    // Prove the policy half alone normalizes and validates before any stream
    // opens, so a bad document cannot masquerade as a discovery problem later.
    normalized_mesh_gateway_config(mesh.clone())?;
    Ok(*mesh)
}

/// Async-runtime wrapper: bounded stable read + policy validation on a
/// blocking worker so Tokio core workers stay free (same contract as the
/// localized `file` protocol).
pub async fn load_stock_policy_baseline_off_thread(
    path: PathBuf,
) -> Result<MeshConfig, anyhow::Error> {
    tokio::task::spawn_blocking(move || load_stock_policy_baseline(&path))
        .await
        .map_err(|error| {
            anyhow::anyhow!("Stock xDS mesh policy validation worker failed: {error}")
        })?
}

/// One atomically published stock-policy generation.
///
/// The recovery epoch travels in the same watch value as the policy bytes so a
/// debounced slice built from an older baseline can never bind (and clear) a
/// newer recovery that began concurrently.
#[derive(Debug, Clone)]
pub struct StockPolicySnapshot {
    mesh: Arc<MeshConfig>,
    recovery_epoch: Option<u64>,
}

impl StockPolicySnapshot {
    pub fn initial(mesh: Arc<MeshConfig>) -> Self {
        Self {
            mesh,
            recovery_epoch: None,
        }
    }

    pub fn mesh(&self) -> &MeshConfig {
        &self.mesh
    }
}

/// Publish a stock policy reload candidate through the recovery handshake.
///
/// Failed loads raise the sticky degraded signal, cancel any older pending
/// recovery, and retain the last-good baseline in the watch channel. A valid
/// baseline is published to the channel and marks recovery pending, but does
/// **not** clear `config_rejected` — clearing waits for the stock client to
/// rebuild/install and the mesh apply task to accept that exact recovery.
pub fn apply_stock_policy_reload_candidate(
    policy_tx: &tokio::sync::watch::Sender<StockPolicySnapshot>,
    recovery: &MeshLocalSourceRecovery,
    candidate: Result<MeshConfig, anyhow::Error>,
) -> MeshLocalReloadApply {
    match candidate {
        Ok(mesh) => {
            let unchanged = policy_tx.borrow().mesh() == &mesh;
            // Create the recovery epoch before publishing, and carry it in the
            // same watch value. This closes both wake-before-registration and
            // old-baseline/new-recovery binding races.
            let recovery_epoch = recovery.begin_policy_recovery();
            if recovery_epoch == 0 {
                return MeshLocalReloadApply::Rejected;
            }
            if policy_tx
                .send(StockPolicySnapshot {
                    mesh: Arc::new(mesh),
                    recovery_epoch: Some(recovery_epoch),
                })
                .is_err()
            {
                warn!(
                    "Stock xDS policy reload has no live consumer; keeping sticky health degraded"
                );
                recovery.mark_rejected();
                return MeshLocalReloadApply::Rejected;
            }
            if unchanged {
                MeshLocalReloadApply::Unchanged
            } else {
                MeshLocalReloadApply::Applied
            }
        }
        Err(error) => {
            warn!(
                error = %error,
                "Failed to reload the stock xDS mesh policy document; keeping the last good \
                 policy baseline and raising config_rejected"
            );
            mark_mesh_local_reload_rejected(recovery);
            MeshLocalReloadApply::Rejected
        }
    }
}

/// Build the mesh slice for one discovery snapshot on top of the policy
/// baseline, through the SAME normalize → validate → project pipeline the
/// localized file source uses.
pub fn build_stock_mesh_slice(
    baseline: &MeshConfig,
    discovery: &StockDiscovery,
    request: &MeshSliceRequest,
    version: &str,
) -> Result<MeshSlice, anyhow::Error> {
    let mut mesh = baseline.clone();
    mesh.services.clone_from(&discovery.services);
    mesh.workloads.clone_from(&discovery.workloads);
    let config = normalized_mesh_gateway_config(Box::new(mesh))?;
    let mut slice = MeshSlice::from_gateway_config(&config, request.clone());
    // Observability-only (`MeshSlice::content_eq` ignores it); the stock CP
    // supplies no Ferrum ordering revision, so `revision` stays absent and the
    // freshness gate bootstraps and remains inert, matching a K8s-controller CP.
    slice.version = version.to_string();
    Ok(slice)
}

// ── per-type subscription state ──────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct StockSubscription {
    last_acked_version: Option<String>,
    last_received_version: Option<String>,
    last_received_nonce: Option<String>,
    /// Nonce of the last response fully processed (ACKed or NACKed) on the
    /// CURRENT stream. Cleared on every reconnect because xDS nonces are
    /// stream-scoped, so a CP that restarts its sequence counter is not
    /// mistaken for a retransmitter.
    last_processed_nonce: Option<String>,
    /// Explicit resource-name subscription. Empty means wildcard.
    resource_names: Vec<String>,
    node_sent: bool,
}

#[derive(Debug, Clone, Default)]
struct StockSubscriptionState {
    subscriptions: HashMap<String, StockSubscription>,
}

enum NonceOutcome {
    Fresh,
    StaleDuplicate,
}

impl StockSubscriptionState {
    fn record_response(&mut self, type_url: &str, version: &str, nonce: &str) -> NonceOutcome {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        if !nonce.is_empty() && subscription.last_processed_nonce.as_deref() == Some(nonce) {
            return NonceOutcome::StaleDuplicate;
        }
        subscription.last_received_version = Some(version.to_string());
        subscription.last_received_nonce = Some(nonce.to_string());
        NonceOutcome::Fresh
    }

    fn mark_processed(&mut self, type_url: &str) {
        if let Some(subscription) = self.subscriptions.get_mut(type_url) {
            subscription
                .last_processed_nonce
                .clone_from(&subscription.last_received_nonce);
        }
    }

    fn mark_acked(&mut self, type_url: &str) {
        if let Some(subscription) = self.subscriptions.get_mut(type_url) {
            subscription
                .last_acked_version
                .clone_from(&subscription.last_received_version);
        }
    }

    /// Reset every stream-scoped field for a fresh ADS stream.
    ///
    /// xDS nonces are scoped to ONE stream, so the first request on a new
    /// stream must carry an EMPTY `response_nonce` — replaying the previous
    /// stream's nonce is an expired-nonce signal a control plane may drop the
    /// request on. The received-version slot is rewound to the last version
    /// this client actually ACCEPTED for the same reason `build_request` uses
    /// it: a response that was NACKed must never be re-asserted as the client's
    /// state, or a version-comparing control plane will withhold the resource
    /// it already sent and the data plane never converges.
    fn reset_for_new_stream(&mut self) {
        for subscription in self.subscriptions.values_mut() {
            subscription.last_processed_nonce = None;
            subscription.last_received_nonce = None;
            subscription
                .last_received_version
                .clone_from(&subscription.last_acked_version);
            subscription.node_sent = false;
        }
    }

    /// Replace the explicit resource-name subscription for a type. Returns
    /// `true` when it changed and a new request must be sent.
    fn set_resource_names(&mut self, type_url: &str, names: Vec<String>) -> bool {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        if subscription.resource_names == names {
            return false;
        }
        subscription.resource_names = names;
        true
    }

    fn resource_names(&self, type_url: &str) -> Vec<String> {
        self.subscriptions
            .get(type_url)
            .map(|subscription| subscription.resource_names.clone())
            .unwrap_or_default()
    }

    fn take_node(&mut self, type_url: &str) -> bool {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        if subscription.node_sent {
            return false;
        }
        subscription.node_sent = true;
        true
    }

    fn build_request(
        &mut self,
        type_url: &str,
        config: &StockXdsClientConfig,
        error: Option<String>,
    ) -> DiscoveryRequest {
        let include_node = self.take_node(type_url);
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        // `version_info` is ALWAYS the last version this client actually
        // accepted — for an ACK, for a NACK, and for a plain subscription
        // update alike. The ACK path advances `last_acked_version` *before*
        // building its request (see `handle_stock_response`), so an ACK still
        // asserts the version it just accepted, while a NACK and any later
        // subscription change keep re-asserting the last good one.
        let version_info = subscription.last_acked_version.clone().unwrap_or_default();
        DiscoveryRequest {
            version_info,
            node: include_node.then(|| node_for(config)),
            resource_names: subscription.resource_names.clone(),
            type_url: type_url.to_string(),
            response_nonce: subscription.last_received_nonce.clone().unwrap_or_default(),
            error_detail: error.map(|message| Status {
                // google.rpc.Code::INVALID_ARGUMENT
                code: 3,
                message,
                details: Vec::new(),
            }),
        }
    }
}

fn node_for(config: &StockXdsClientConfig) -> Node {
    Node {
        id: config.node_id.clone(),
        cluster: config.cluster.clone(),
        metadata: encode_node_metadata(&config.node_metadata),
    }
}

/// Encode operator-declared node metadata as a `google.protobuf.Struct`.
///
/// `DiscoveryRequest.node.metadata` is a `Struct` upstream; Ferrum's minimal
/// discovery shim types it as `bytes`, and a message field and a `bytes` field
/// are the same length-delimited shape on the wire. The vendored RTDS `Struct`
/// projection already mirrors the well-known type's field numbers, so a stock
/// control plane decodes what Ferrum writes here. Empty metadata sends no
/// bytes at all rather than an empty struct.
fn encode_node_metadata(metadata: &BTreeMap<String, String>) -> Vec<u8> {
    if metadata.is_empty() {
        return Vec::new();
    }
    let fields = metadata
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                runtime_proto::Value {
                    kind: Some(runtime_proto::value::Kind::StringValue(value.clone())),
                },
            )
        })
        .collect();
    runtime_proto::Struct { fields }.encode_to_vec()
}

#[derive(Debug, Clone, Default)]
struct StockNackBreaker {
    consecutive_by_type: HashMap<String, u32>,
}

impl StockNackBreaker {
    fn record_ack(&mut self, type_url: &str) {
        self.consecutive_by_type.remove(type_url);
    }

    fn record_nack(&mut self, type_url: &str) -> u32 {
        let count = self
            .consecutive_by_type
            .entry(type_url.to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
        *count
    }
}

#[derive(Debug, Clone, Default)]
struct StockStreamState {
    subscriptions: StockSubscriptionState,
    breaker: StockNackBreaker,
}

// ── client entry point ───────────────────────────────────────────────────

/// Maintain a live stock ADS stream with multi-server failover.
#[allow(clippy::too_many_arguments)]
pub async fn start_stock_xds_client_with_shutdown(
    config: StockXdsClientConfig,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
    mut policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
) {
    let xds_urls = config.xds_urls.clone();
    if xds_urls.is_empty() {
        error!("No stock xDS URLs configured — cannot start stock xDS mesh client");
        return;
    }

    let mut current_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut accumulator = StockXdsAccumulator::new(config.limits);
    let mut stream_state = StockStreamState::default();
    let mut last_url: Option<String> = None;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cluster = %config.cluster,
        xds_urls = xds_urls.len(),
        authorization = config.token_file.is_some(),
        "Stock xDS mesh client starting (third-party control plane; discovery only)"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("Stock xDS mesh client shutting down");
            return;
        }
        refresh_dp_grpc_tls_config_if_changed(
            &mut tls_config,
            tls_reload.as_ref(),
            &xds_urls,
            &mut last_tls_revision,
        );
        // Pick up a SIGHUP-reloaded policy baseline before opening the stream so
        // the next slice already carries it.
        let baseline = policy_rx.borrow_and_update().clone();

        let xds_url = &xds_urls[current_index];
        if last_url.as_deref() != Some(xds_url.as_str()) {
            if let Some(previous) = last_url.as_deref() {
                info!(
                    previous_xds_url = previous,
                    xds_url = %xds_url,
                    "Stock xDS control plane changed; resetting accumulated discovery state"
                );
                // Discovery state is scoped to ONE control plane: never let a
                // quarantined or lagging server's clusters mix into another's.
                accumulator = StockXdsAccumulator::new(config.limits);
                stream_state = StockStreamState::default();
            }
            last_url = Some(xds_url.clone());
        }

        let is_primary = current_index == 0;
        let is_fallback = !is_primary && xds_urls.len() > 1;
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let should_race_primary = should_race_primary_retry(is_fallback, config.primary_retry_secs);

        let result = if should_race_primary {
            tokio::select! {
                result = connect_stock_ads(
                    xds_url,
                    &config,
                    baseline.clone(),
                    &request,
                    &state,
                    tls_config.as_ref(),
                    &mut accumulator,
                    &mut stream_state,
                    policy_rx.clone(),
                    recovery.clone(),
                ) => result,
                _ = wait_for_first_slice_then_primary_retry(
                    state.clone(),
                    Duration::from_secs(config.primary_retry_secs),
                ) => {
                    info!(
                        primary_retry_secs = config.primary_retry_secs,
                        xds_url = %xds_url,
                        "Stock xDS primary retry interval elapsed; reconnecting to primary server"
                    );
                    current_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Stock xDS mesh client shutting down");
                    return;
                }
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone())
                ) => {
                    info!("Mesh gRPC TLS source changed; reconnecting stock xDS ADS stream");
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            tokio::select! {
                result = connect_stock_ads(
                    xds_url,
                    &config,
                    baseline.clone(),
                    &request,
                    &state,
                    tls_config.as_ref(),
                    &mut accumulator,
                    &mut stream_state,
                    policy_rx.clone(),
                    recovery.clone(),
                ) => result,
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Stock xDS mesh client shutting down");
                    return;
                }
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone())
                ) => {
                    info!("Mesh gRPC TLS source changed; reconnecting stock xDS ADS stream");
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        };

        let increase_backoff = match result {
            Ok(()) => {
                warn!(xds_url = %xds_url, "Stock xDS ADS stream ended; will reconnect");
                if is_fallback {
                    current_index = 0;
                }
                backoff_secs = BACKOFF_INITIAL_SECS;
                false
            }
            Err(e) => {
                error!(xds_url = %xds_url, error = %e, "Stock xDS ADS connection failed");
                current_index = (current_index + 1) % xds_urls.len();
                true
            }
        };

        let sleep_duration = jittered_backoff(backoff_secs);
        let mut sleep_shutdown_rx = shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut sleep_shutdown_rx) => {
                info!("Stock xDS mesh client shutting down");
                return;
            }
            _ = wait_optional_tls_reload(
                tls_reload.as_ref().map(|reload| reload.revision_rx.clone())
            ) => {
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

#[allow(clippy::too_many_arguments)]
async fn connect_stock_ads(
    xds_url: &str,
    config: &StockXdsClientConfig,
    baseline: StockPolicySnapshot,
    request: &MeshSliceRequest,
    state: &MeshRuntimeState,
    tls_config: Option<&DpGrpcTlsConfig>,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
    policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
) -> Result<(), anyhow::Error> {
    let mut endpoint = Channel::from_shared(xds_url.to_string())?;
    if config.connect_timeout_seconds > 0 {
        endpoint = endpoint.connect_timeout(Duration::from_secs(config.connect_timeout_seconds));
    }
    if let Some(tls) = tls_config {
        let mut client_tls = tonic_tls_config(tls);
        if let Ok(uri) = xds_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }
        endpoint = endpoint.tls_config(client_tls)?;
    }

    // The bearer token is read per connection attempt so a rotated projected
    // service-account token is picked up on reconnect. It is never minted by
    // Ferrum and never logged.
    let token = match config.token_file.as_deref() {
        Some(path) => Some(read_bearer_token(path).await?),
        None => None,
    };

    let channel = endpoint.connect().await?;

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        xds_url = %xds_url,
        "Connected to stock xDS control plane; subscribing CDS + LDS"
    );

    run_stock_ads_stream(
        channel,
        token,
        config,
        baseline,
        request,
        state,
        accumulator,
        stream_state,
        policy_rx,
        recovery,
    )
    .await
}

pub(crate) async fn read_bearer_token(path: &str) -> Result<BearerToken, anyhow::Error> {
    use crate::secrets::credential_file::{
        CredentialTrim, DEFAULT_CREDENTIAL_FILE_MAX_BYTES, read_credential_file_detached_guarded,
    };

    let read = async {
        let permit = stock_xds_token_file_read_limit()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("stock xDS bearer-token reader is unavailable"))?;
        read_credential_file_detached_guarded(
            path,
            DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
            CredentialTrim::Ends,
            "ferrum-stock-xds-token-file",
            permit,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to read stock xDS bearer token: {error}"))
    };
    let token = match tokio::time::timeout(STOCK_XDS_TOKEN_FILE_READ_TIMEOUT, read).await {
        Ok(result) => result?,
        Err(_) => anyhow::bail!("timed out reading stock xDS bearer token"),
    };
    format!("Bearer {token}")
        .parse()
        // The parse error would echo the token, so it is deliberately dropped.
        .map_err(|_| anyhow::anyhow!("stock xDS bearer token is not valid ASCII metadata"))
}

struct PendingStockSlice {
    slice: MeshSlice,
    type_url: String,
    refusals: Vec<StockRefusal>,
    policy_recovery_epoch: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn run_stock_ads_stream(
    channel: Channel,
    token: Option<BearerToken>,
    config: &StockXdsClientConfig,
    mut baseline: StockPolicySnapshot,
    request: &MeshSliceRequest,
    state: &MeshRuntimeState,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
    mut policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
) -> Result<(), anyhow::Error> {
    #[allow(clippy::result_large_err)]
    let mut client = AggregatedDiscoveryServiceClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            if let Some(token) = token.as_ref() {
                req.metadata_mut().insert("authorization", token.clone());
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

    // Nonces are stream-scoped, and every new stream must re-send `Node`.
    stream_state.subscriptions.reset_for_new_stream();

    for type_url in STOCK_INITIAL_TYPE_URL_ORDER {
        let subscribe = stream_state
            .subscriptions
            .build_request(type_url, config, None);
        send_request(&tx, subscribe).await?;
    }
    // Resume any dependency-ordered subscription established on a previous
    // stream so a reconnect does not lose the EDS/RDS names already derived
    // from the retained accumulator.
    for type_url in [EDS_TYPE_URL, RDS_TYPE_URL] {
        if !stream_state
            .subscriptions
            .resource_names(type_url)
            .is_empty()
        {
            let subscribe = stream_state
                .subscriptions
                .build_request(type_url, config, None);
            send_request(&tx, subscribe).await?;
        }
    }

    let debounce = tokio::time::sleep(Duration::from_secs(60 * 60 * 24));
    tokio::pin!(debounce);
    let mut debounce_active = false;
    let mut pending_since: Option<tokio::time::Instant> = None;
    let mut pending: Option<Box<PendingStockSlice>> = None;
    let mut last_logged_refusals: Option<Vec<StockRefusal>> = None;
    let mut policy_watch_open = true;

    loop {
        tokio::select! {
            response = response_stream.message() => {
                let Some(response) = response? else {
                    break;
                };
                match handle_stock_response(
                    response,
                    config,
                    baseline.mesh(),
                    baseline.recovery_epoch,
                    request,
                    &tx,
                    accumulator,
                    stream_state,
                ).await? {
                    StockResponseOutcome::Pending(next) => {
                        pending = Some(next);
                        let now = tokio::time::Instant::now();
                        let first_pending_at = *pending_since.get_or_insert(now);
                        debounce.as_mut().reset(std::cmp::min(
                            now + STOCK_APPLY_DEBOUNCE,
                            first_pending_at + STOCK_APPLY_MAX_DELAY,
                        ));
                        debounce_active = true;
                    }
                    StockResponseOutcome::Acked => {}
                    StockResponseOutcome::Nacked => {
                        // A NACK rolled the accumulator back, so a slice built
                        // from the pre-NACK view is no longer the state this
                        // client has acknowledged. Drop it rather than publish
                        // a view the control plane will now contradict.
                        if pending.take().is_some() {
                            warn!(
                                node_id = %config.node_id,
                                namespace = %config.namespace,
                                "Discarded debounced stock xDS slice after NACK"
                            );
                        }
                        debounce_active = false;
                        pending_since = None;
                    }
                }
                state.set_xds_convergence(convergence_snapshot(accumulator));
            }
            _ = &mut debounce, if debounce_active => {
                if let Some(next) = pending.take() {
                    apply_pending(config, state, next, &mut last_logged_refusals, &recovery)?;
                }
                debounce_active = false;
                pending_since = None;
            }
            reloaded = next_policy_baseline(&mut policy_rx), if policy_watch_open => {
                let Some(next_baseline) = reloaded else {
                    // The watcher task is gone (non-Unix, or shutdown). Stop
                    // selecting on it and keep serving the last baseline
                    // instead of spinning on a closed channel.
                    policy_watch_open = false;
                    continue;
                };
                baseline = next_baseline;
                info!(
                    node_id = %config.node_id,
                    namespace = %config.namespace,
                    "Stock xDS mesh policy document reloaded; rebuilding slice from current discovery"
                );
                if accumulator.ready() {
                    let discovery = accumulator.discovery();
                    match build_stock_mesh_slice(
                        baseline.mesh(),
                        &discovery,
                        request,
                        &accumulator.composite_version(),
                    ) {
                        Ok(slice) => {
                            pending = Some(Box::new(PendingStockSlice {
                                slice,
                                type_url: "policy-reload".to_string(),
                                refusals: discovery.refusals,
                                policy_recovery_epoch: baseline.recovery_epoch,
                            }));
                            let now = tokio::time::Instant::now();
                            let first_pending_at = *pending_since.get_or_insert(now);
                            debounce.as_mut().reset(std::cmp::min(
                                now + STOCK_APPLY_DEBOUNCE,
                                first_pending_at + STOCK_APPLY_MAX_DELAY,
                            ));
                            debounce_active = true;
                        }
                        Err(e) => {
                            warn!(
                                node_id = %config.node_id,
                                error = %e,
                                "Reloaded mesh policy document failed slice construction; keeping \
                                 the last good slice and raising config_rejected"
                            );
                            recovery.mark_rejected();
                        }
                    }
                }
            }
        }
    }

    if let Some(next) = pending.take() {
        apply_pending(config, state, next, &mut last_logged_refusals, &recovery)?;
    }
    Ok(())
}

enum StockResponseOutcome {
    /// Boxed: a `MeshSlice` dwarfs the unit variants, and an unboxed payload
    /// would make every `Acked`/`Nacked` return move a slice-sized enum.
    Pending(Box<PendingStockSlice>),
    Acked,
    Nacked,
}

/// Await the next SIGHUP-reloaded policy baseline.
///
/// The borrow is taken and released entirely inside this helper so the
/// `tokio::select!` handler never has to touch the receiver again. `None` means
/// the watcher task is gone.
async fn next_policy_baseline(
    policy_rx: &mut tokio::sync::watch::Receiver<StockPolicySnapshot>,
) -> Option<StockPolicySnapshot> {
    policy_rx.changed().await.ok()?;
    Some(policy_rx.borrow_and_update().clone())
}

// This cold-path state transition deliberately keeps the immutable client
// inputs and the two mutable stream-state owners explicit. Bundling them would
// obscure which values may change while one ADS response is admitted.
#[allow(clippy::too_many_arguments)]
async fn handle_stock_response(
    response: proto::DiscoveryResponse,
    config: &StockXdsClientConfig,
    baseline: &MeshConfig,
    policy_recovery_epoch: Option<u64>,
    request: &MeshSliceRequest,
    tx: &mpsc::Sender<DiscoveryRequest>,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
) -> Result<StockResponseOutcome, anyhow::Error> {
    let type_url = response.type_url.clone();

    // Unsubscribed / unsupported types fail closed by terminating the stream.
    // Sending a NACK DiscoveryRequest for a type the client never requested
    // would itself create a wildcard subscription to that type under SotW
    // semantics. SDS gets a dedicated diagnostic because a stock CP
    // volunteering key material is a security-relevant event, and Ferrum
    // refuses it WITHOUT decoding the key fields or logging any payload.
    if !is_stock_type_url(&type_url) {
        // `type_url` is a control-plane-supplied string bounded only by the
        // gRPC message size, and it lands in both a log line and the
        // `error_detail` echoed back, so it is rendered before either use.
        let safe_url = diagnostic_value(&type_url);
        let reason = if type_url == SDS_TYPE_URL {
            // Bounded exactly like `log_refusals`: one volunteered SDS response
            // must not be able to amplify into an unbounded burst of log lines.
            for resource in response.resources.iter().take(STOCK_REFUSAL_LOG_LIMIT) {
                let refusal = refuse_stock_secret(&resource.value);
                warn!(
                    node_id = %config.node_id,
                    namespace = %config.namespace,
                    resource = %refusal.resource,
                    reason = refusal.reason,
                    detail = %refusal.detail,
                    "Refused an SDS secret pushed by the stock control plane; Ferrum never \
                     ingests control-plane-delivered key or trust material"
                );
            }
            if response.resources.len() > STOCK_REFUSAL_LOG_LIMIT {
                warn!(
                    node_id = %config.node_id,
                    suppressed = response.resources.len() - STOCK_REFUSAL_LOG_LIMIT,
                    "Additional refused SDS secrets suppressed by the per-response log bound"
                );
            }
            format!(
                "type_url '{safe_url}' is not consumed by the Ferrum stock xDS profile; workload \
                 identity and trust anchors come from Ferrum's own SPIFFE configuration"
            )
        } else {
            format!("type_url '{safe_url}' is not subscribed by the Ferrum stock xDS profile")
        };
        warn!(
            node_id = %config.node_id,
            type_url = %safe_url,
            reason = %reason,
            "Closing stock xDS stream after an unsolicited unsupported resource type"
        );
        return Err(anyhow::anyhow!(
            "stock xDS control plane sent unsolicited unsupported type_url '{safe_url}'; \
             closing the stream without subscribing to that type"
        ));
    }

    debug!(
        node_id = %config.node_id,
        type_url = %type_url,
        version = %diagnostic_value(&response.version_info),
        nonce = %diagnostic_value(&response.nonce),
        resources = response.resources.len(),
        "Received stock xDS ADS response"
    );

    if matches!(
        stream_state.subscriptions.record_response(
            &type_url,
            &response.version_info,
            &response.nonce
        ),
        NonceOutcome::StaleDuplicate
    ) {
        debug!(
            node_id = %config.node_id,
            type_url = %type_url,
            "Ignoring stale/duplicate stock xDS response (nonce already processed)"
        );
        return Ok(StockResponseOutcome::Acked);
    }

    let resources: Vec<(String, Vec<u8>)> = response
        .resources
        .iter()
        .map(|resource| (resource.type_url.clone(), resource.value.clone()))
        .collect();

    let rollback = accumulator.clone();
    if let Err(e) = accumulator.apply_sotw(&type_url, &resources, &response.version_info) {
        // Roll back so the accumulator matches exactly what this client has
        // ACKed. A NACKed state-of-the-world response is not resent until the
        // resource changes or the stream reconnects, so a partially applied
        // view here would be indistinguishable from a converged one.
        *accumulator = rollback;
        let blocking_first_slice = !accumulator.ready();
        let nack = stream_state
            .subscriptions
            .build_request(&type_url, config, Some(e.clone()));
        stream_state.subscriptions.mark_processed(&type_url);
        let consecutive = stream_state.breaker.record_nack(&type_url);
        send_request(tx, nack).await?;
        warn!(
            node_id = %config.node_id,
            namespace = %config.namespace,
            type_url = %type_url,
            consecutive_nacks = consecutive,
            blocking_first_slice,
            error = %e,
            "NACKing invalid stock xDS ADS response"
        );
        if blocking_first_slice {
            crate::plugins::mesh::prometheus_helpers::increment_xds_first_slice_nack(
                &config.namespace,
                &type_url,
            );
        }
        if consecutive >= STOCK_CONSECUTIVE_NACK_LIMIT {
            return Err(anyhow::anyhow!(
                "stock xDS NACK circuit breaker tripped for type_url '{}' after {} \
                 consecutive NACKs on node '{}'; closing stream to trigger reconnect/failover",
                type_url,
                consecutive,
                config.node_id
            ));
        }
        return Ok(StockResponseOutcome::Nacked);
    }

    // Advance the accepted version BEFORE building the ACK: `build_request`
    // always asserts the last accepted version, so this is what makes the ACK
    // carry the version it just applied while a later NACK or subscription
    // update still re-asserts the last good one.
    stream_state.subscriptions.mark_acked(&type_url);
    let ack = stream_state
        .subscriptions
        .build_request(&type_url, config, None);
    send_request(tx, ack).await?;
    stream_state.subscriptions.mark_processed(&type_url);
    stream_state.breaker.record_ack(&type_url);

    // Dependency ordering: a CDS update redefines which endpoint assignments
    // matter, and an LDS update redefines which route configurations matter.
    if type_url == CDS_TYPE_URL
        && stream_state
            .subscriptions
            .set_resource_names(EDS_TYPE_URL, accumulator.eds_subscriptions())
    {
        let names = stream_state.subscriptions.resource_names(EDS_TYPE_URL);
        debug!(
            node_id = %config.node_id,
            resources = names.len(),
            "Updating dependency-ordered EDS subscription after CDS update"
        );
        let subscribe = stream_state
            .subscriptions
            .build_request(EDS_TYPE_URL, config, None);
        send_request(tx, subscribe).await?;
    }
    if type_url == LDS_TYPE_URL
        && stream_state
            .subscriptions
            .set_resource_names(RDS_TYPE_URL, accumulator.rds_subscriptions())
    {
        let names = stream_state.subscriptions.resource_names(RDS_TYPE_URL);
        debug!(
            node_id = %config.node_id,
            resources = names.len(),
            "Updating dependency-ordered RDS subscription after LDS update"
        );
        let subscribe = stream_state
            .subscriptions
            .build_request(RDS_TYPE_URL, config, None);
        send_request(tx, subscribe).await?;
    }

    if !accumulator.ready() {
        debug!(
            node_id = %config.node_id,
            type_url = %type_url,
            pending = ?accumulator.pending_types(),
            "ACKed stock xDS response while waiting for the remaining gating types"
        );
        return Ok(StockResponseOutcome::Acked);
    }

    let discovery = accumulator.discovery();
    match build_stock_mesh_slice(
        baseline,
        &discovery,
        request,
        &accumulator.composite_version(),
    ) {
        Ok(slice) => Ok(StockResponseOutcome::Pending(Box::new(PendingStockSlice {
            slice,
            type_url,
            refusals: discovery.refusals,
            policy_recovery_epoch,
        }))),
        Err(e) => {
            // The discovery half validated structurally; a failure here means
            // the merged document is invalid. Keep the last good slice and
            // surface it rather than tearing the stream down.
            warn!(
                node_id = %config.node_id,
                namespace = %config.namespace,
                type_url = %type_url,
                error = %e,
                "Stock xDS discovery did not produce a valid mesh slice; keeping the last good slice"
            );
            Ok(StockResponseOutcome::Acked)
        }
    }
}

fn apply_pending(
    config: &StockXdsClientConfig,
    state: &MeshRuntimeState,
    pending: Box<PendingStockSlice>,
    last_logged_refusals: &mut Option<Vec<StockRefusal>>,
    recovery: &MeshLocalSourceRecovery,
) -> Result<(), anyhow::Error> {
    let PendingStockSlice {
        slice,
        type_url,
        refusals,
        policy_recovery_epoch,
    } = *pending;
    let version = slice.version.clone();
    let services = slice.services.len();
    let workloads = slice.workloads.len();
    // Bind the exact policy generation before `install_slice` wakes the proxy
    // apply task. A stale debounced slice carries its older epoch and therefore
    // cannot bind or clear a newer concurrent policy recovery. Binding BORROWS
    // the candidate — it is moved into `install_slice` immediately after, so
    // the recovery handshake must not force a full `MeshSlice` clone on this
    // path.
    if let Some(epoch) = policy_recovery_epoch {
        recovery.bind_installed_slice_if_policy_recovery(epoch, &slice);
    }
    match state.install_slice(slice) {
        MeshSliceInstall::Installed => {}
        MeshSliceInstall::Quarantined(rejection) => {
            warn!(
                reason = rejection.reason().as_metric_label(),
                "Quarantined a stock-xDS-built mesh slice on config-revision ordering; keeping \
                 the last-good slice and closing the stream for failover"
            );
            // Local policy recovery (or any install under a pending recovery)
            // that hits the revision gate must stay/set degraded. One critical
            // section: a separate `pending_epoch()` test would let the slot be
            // cleared or replaced before the raise landed.
            recovery.mark_rejected_if_pending();
            return Err(anyhow::anyhow!(
                "stock xDS mesh slice quarantined: {}",
                rejection.reason().as_metric_label()
            ));
        }
    }
    log_refusals(config, &refusals, last_logged_refusals);
    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        version = %version,
        type_url = %type_url,
        services,
        workloads,
        refused_resources = refusals.len(),
        "Applied debounced stock xDS update"
    );
    Ok(())
}

/// Emit the capability refusals for this apply, but only when the refusal set
/// CHANGED. A stock control plane re-sends the same unsupported resources on
/// every update, so logging unconditionally would flood the operator's log with
/// a static list.
fn log_refusals(
    config: &StockXdsClientConfig,
    refusals: &[StockRefusal],
    last_logged: &mut Option<Vec<StockRefusal>>,
) {
    if refusals.is_empty() {
        *last_logged = Some(Vec::new());
        return;
    }
    if last_logged.as_deref() == Some(refusals) {
        return;
    }
    *last_logged = Some(refusals.to_vec());

    let mut by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
    for refusal in refusals {
        *by_reason.entry(refusal.reason).or_insert(0) += 1;
    }
    warn!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        refused_resources = refusals.len(),
        reasons = ?by_reason,
        "Stock xDS control plane sent resources the Ferrum stock profile does not model; they \
         are excluded from routing and trust (see docs/mesh.md 'Stock xDS interoperability')"
    );
    for refusal in refusals.iter().take(STOCK_REFUSAL_LOG_LIMIT) {
        warn!(
            node_id = %config.node_id,
            type_url = refusal.type_label,
            resource = %refusal.resource,
            reason = refusal.reason,
            field = %refusal.detail,
            "Refused a stock xDS resource"
        );
    }
    if refusals.len() > STOCK_REFUSAL_LOG_LIMIT {
        warn!(
            node_id = %config.node_id,
            suppressed = refusals.len() - STOCK_REFUSAL_LOG_LIMIT,
            "Additional stock xDS refusals suppressed by the per-apply log bound"
        );
    }
}

fn convergence_snapshot(accumulator: &StockXdsAccumulator) -> XdsConvergenceSnapshot {
    XdsConvergenceSnapshot {
        per_type_versions: accumulator.per_type_versions(),
        missing_required_types: accumulator
            .pending_types()
            .into_iter()
            .map(str::to_string)
            .collect(),
        converged: accumulator.ready(),
        // The stock profile has no cross-type coherence requirement, so this
        // is structurally always false. Kept for `/mesh/config-drift` shape
        // parity with the Ferrum-private profile.
        version_skew: false,
    }
}

fn is_stock_type_url(type_url: &str) -> bool {
    matches!(
        type_url,
        CDS_TYPE_URL | EDS_TYPE_URL | LDS_TYPE_URL | RDS_TYPE_URL
    )
}

async fn send_request(
    tx: &mpsc::Sender<DiscoveryRequest>,
    request: DiscoveryRequest,
) -> Result<(), anyhow::Error> {
    tx.send(request)
        .await
        .map_err(|_| anyhow::anyhow!("stock xDS ADS request stream closed"))
}

// ── policy document watcher ──────────────────────────────────────────────

/// Re-read the local mesh policy document on SIGHUP (Unix) and publish it to
/// the stock ADS client, which rebuilds its slice from the current discovery.
///
/// Filesystem + parse work runs on `spawn_blocking` with the same coalesced
/// generation fencing as the localized `file` protocol. A failed reload keeps
/// the last good baseline and raises `config_rejected`; a later accepted
/// recovery clears it only after proxy apply. Watcher shutdown stops accepting
/// candidates promptly and does not await a started (non-cancellable) blocking
/// job. The select is `biased` with shutdown first so a simultaneous
/// completion cannot publish. On non-Unix targets the baseline is fixed at
/// startup.
pub async fn start_stock_policy_watcher_with_shutdown(
    path: String,
    policy_tx: tokio::sync::watch::Sender<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    #[cfg(unix)]
    {
        let hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to register SIGHUP handler for the stock xDS mesh policy \
                     document; it will not reload until restart"
                );
                wait_for_shutdown(&mut shutdown_rx).await;
                return;
            }
        };

        run_mesh_local_reload_loop(
            SignalReloadNotifier(hangup),
            &mut shutdown_rx,
            &path,
            &recovery,
            &STOCK_POLICY_RELOAD_MESSAGES,
            || spawn_stock_policy_reload(&path),
            |mesh| MeshLocalReloadResult {
                version: None,
                apply: apply_stock_policy_reload_candidate(&policy_tx, &recovery, Ok(mesh)),
            },
        )
        .await;
    }

    #[cfg(not(unix))]
    {
        info!(
            file_path = %path,
            "Stock xDS mesh policy document loaded; live reload is Unix-only (SIGHUP)"
        );
        let _ = &policy_tx;
        let _ = &recovery;
        wait_for_shutdown(&mut shutdown_rx).await;
    }
}

/// Log lines for the `stock_xds` policy watcher's reload loop.
pub const STOCK_POLICY_RELOAD_MESSAGES: MeshReloadLoopMessages = MeshReloadLoopMessages {
    shutdown: "Stock xDS mesh policy watcher shutting down",
    notifier_closed: "SIGHUP stream closed; the stock xDS mesh policy document will not reload \
                      until restart",
    stale_generation: "Discarding stale stock xDS mesh policy reload generation",
    reloaded: "Reloaded the stock xDS mesh policy document on SIGHUP",
    load_failed: "Failed to reload the stock xDS mesh policy document on SIGHUP; keeping the last \
                  good policy baseline",
    join_cancelled: "Stock xDS mesh policy reload join cancelled before publish",
    worker_panicked: "Stock xDS mesh policy reload worker panicked; keeping the last good policy \
                      baseline",
};

/// Spawn one stock-policy baseline load onto the blocking pool.
///
/// Public so tests can drive [`run_mesh_local_reload_loop`] with the exact
/// production loader instead of a stand-in.
pub fn spawn_stock_policy_reload(
    path: &str,
) -> tokio::task::JoinHandle<Result<MeshConfig, anyhow::Error>> {
    let load_path = PathBuf::from(path);
    tokio::task::spawn_blocking(move || load_stock_policy_baseline(&load_path))
}
