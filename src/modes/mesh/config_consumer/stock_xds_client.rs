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
//!
//! ## Transport and credential admission
//!
//! Two fail-closed boundaries wrap that credential:
//!
//! * [`super::stock_xds_transport`] (issue #3853) admits the COMPLETE
//!   primary/fallback endpoint set as one security posture before any socket is
//!   opened, and the `authorization` interceptor below re-checks the selected
//!   endpoint's classification at the insertion boundary so a bearer can never
//!   ride an unauthenticated channel even if top-level admission were bypassed.
//! * [`super::stock_xds_credential`] (issue #3852) gives the stream a finite
//!   local authorization lifetime: the source is watched for rotation and
//!   invalidation, and every stream carries a deadline derived from a bounded
//!   local `exp` hint or the operator-visible maximum stream lifetime.
//!
//! Attempt classification, endpoint rotation, backoff, and transport keepalive
//! are the shared [`super::stream_lifecycle`] policy (issue #3854).
//!
//! ## Log redaction
//!
//! A bearer-authenticated stock control plane sees the Authorization metadata
//! and can copy that bearer into any ADS response field. Ferrum logs on this
//! path therefore carry only closed-set type labels (`cds`/`eds`/`lds`/`rds`/
//! `sds`/`unsolicited`/`policy_reload`), fixed reason codes, counts, booleans,
//! endpoint indexes, and local node/namespace fields. Remote `type_url`,
//! `version_info`, `nonce`, resource names, NACK error text, and refusal
//! detail are omitted. Truncation is not redaction; NACK `error_detail` may
//! still return a bounded copy of the CP's own fields to that same CP.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
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
use super::pending_generation::{
    PendingGeneration, PendingGenerationAction, PendingGenerationEvent,
};
use super::stock_xds_credential::{
    StockBearerCredential, StockCredentialInvalidReason, StockCredentialObservation,
    StockCredentialReadEpoch, StockCredentialState, StockCredentialWatch, StockXdsCredentialSource,
};
use super::stock_xds_transport::{
    StockXdsTransport, StockXdsTransportPolicy, admit_stock_xds_endpoints,
    classify_stock_xds_endpoint,
};
use super::stream_lifecycle::{
    MeshStreamAttachment, MeshStreamAttempt, MeshStreamRetirement, MeshStreamTimings,
    MeshStreamTracker, configure_mesh_config_stream_endpoint, reconnect_backoff_after_attempt,
};
use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload};
use crate::modes::mesh::config::MeshConfig;
use crate::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall, XdsConvergenceSnapshot};
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::startup::sanitize_startup_scalar;
use crate::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::proto::{self, DiscoveryRequest, Node, Status};
use crate::xds::runtime_proto;
use crate::xds::stock::{StockDiscovery, StockRefusal, StockXdsAccumulator, StockXdsLimits};
use crate::xds::translator::{
    CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL,
};

/// Wildcard subscriptions opened as soon as the stream comes up. EDS and RDS
/// are subscribed later, by name, once their dependencies land.
const STOCK_INITIAL_TYPE_URL_ORDER: [&str; 2] = [CDS_TYPE_URL, LDS_TYPE_URL];

const STOCK_CONSECUTIVE_NACK_LIMIT: u32 = 5;
/// Maximum distinct refusals logged per apply. Refusals are bounded input from
/// the control plane, so the log line is capped rather than unbounded.
const STOCK_REFUSAL_LOG_LIMIT: usize = 12;

/// Fixed-cardinality protocol label for the shared stream lifecycle.
pub(crate) const STOCK_XDS_PROTOCOL_LABEL: &str = "stock_xds";

pub use super::stock_xds_credential::BearerToken;

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
    /// Externally issued bearer credential presented to the stock CP, with its
    /// finite authorization lifetime policy (issue #3852). An unconfigured
    /// source sends no `authorization` metadata.
    pub credential: StockXdsCredentialSource,
    /// `FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT` — the loopback-only development
    /// switch (issue #3853). Never compatible with a bearer credential and
    /// always refused under `FERRUM_MESH_PRODUCTION_MODE=true`.
    pub allow_loopback_plaintext: bool,
    pub stream_channel_capacity: usize,
    pub primary_retry_secs: u64,
    /// Client connection timeout. `0` disables tonic's explicit connect timeout.
    /// Transport keepalive is applied regardless — it is what bounds an already
    /// established stream.
    pub connect_timeout_seconds: u64,
    pub limits: StockXdsLimits,
    /// Per-invocation stream timing policy. Production uses
    /// [`MeshStreamTimings::production`]; tests may compress it.
    pub timings: MeshStreamTimings,
}

impl StockXdsClientConfig {
    fn transport_policy(&self) -> StockXdsTransportPolicy {
        StockXdsTransportPolicy::from_runtime(&self.credential, self.allow_loopback_plaintext)
    }
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
            "mesh policy document {:?} declares `services` or `workloads`, which the stock xDS \
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
            let reason = if error.is_cancelled() {
                "cancelled"
            } else {
                "panicked"
            };
            anyhow::anyhow!("Stock xDS mesh policy validation worker failed: {reason}")
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
                error = %crate::startup::sanitize_startup_cause(&error, &[]),
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

/// How one stock ADS attempt ended, with the diagnostic that produced it.
struct StockAttemptOutcome {
    attempt: MeshStreamAttempt,
    /// Bounded, closed-set diagnostic. NEVER a control-plane-supplied status
    /// message, a tonic transport error (which can echo the configured URI or
    /// host), a token, a claim, or a credential path.
    reason: Option<&'static str>,
    /// True when the accumulated discovery/subscription state this attempt
    /// touched must be thrown away before the next stream opens (issue #3852:
    /// nothing a retired credential produced may survive into the stream that
    /// replaces it).
    reset_discovery_state: bool,
    /// Whether THIS attempt installed usable configuration. Distinct from the
    /// runtime's last-good `has_first_slice`, which may be leftover from
    /// another stream.
    delivered_usable_state: bool,
}

impl StockAttemptOutcome {
    fn local(reason: MeshStreamRetirement) -> Self {
        Self {
            attempt: MeshStreamAttempt::LocalRetirement(reason),
            reason: None,
            reset_discovery_state: reason.is_credential_retirement(),
            delivered_usable_state: false,
        }
    }

    fn local_with_reason(retirement: MeshStreamRetirement, reason: &'static str) -> Self {
        Self {
            attempt: MeshStreamAttempt::LocalRetirement(retirement),
            reason: Some(reason),
            reset_discovery_state: retirement.is_credential_retirement(),
            delivered_usable_state: false,
        }
    }

    fn ended(attempt: MeshStreamAttempt, delivered_usable_state: bool) -> Self {
        Self {
            attempt,
            reason: None,
            reset_discovery_state: false,
            delivered_usable_state,
        }
    }

    fn failed(attempt: MeshStreamAttempt, reason: &'static str) -> Self {
        Self {
            attempt,
            reason: Some(reason),
            reset_discovery_state: false,
            delivered_usable_state: false,
        }
    }
}

/// A stock ADS stream failure, split by whether the ENDPOINT misbehaved or its
/// content was refused by a local fail-closed gate. Both rotate and back off,
/// but the distinction is what the operator-facing reason label reports.
///
/// The payload is a `&'static str` on purpose: a third-party control plane
/// controls `Status::message()` and could echo the bearer straight back into
/// it, and a tonic transport error can render the configured URI.
enum StockStreamError {
    /// The streaming RPC itself was refused; nothing was ever established.
    SubscriptionRefused(&'static str),
    /// An ESTABLISHED stream failed. Reported distinctly so `/health` can say
    /// `stream_liveness_failed` — this is the shape an HTTP/2 PING-ack failure
    /// against a blackholed transport takes.
    Transport(&'static str),
    /// A local fail-closed gate refused the content.
    Policy(&'static str),
    /// An already-observed or newly arriving credential retirement won over an
    /// awaited outbound enqueue. Must not be mislabelled as a transport
    /// failure: the next stream has to discard discovery state touched under
    /// the retired credential.
    Retirement(MeshStreamRetirement),
}

impl StockStreamError {
    fn into_outcome(self, delivered_usable_state: bool) -> StockAttemptOutcome {
        let mut outcome = match self {
            Self::SubscriptionRefused(reason) => StockAttemptOutcome::failed(
                MeshStreamAttempt::TransportFailure {
                    delivered_usable_state,
                    after_established: false,
                },
                reason,
            ),
            Self::Transport(reason) => StockAttemptOutcome::failed(
                MeshStreamAttempt::TransportFailure {
                    delivered_usable_state,
                    after_established: true,
                },
                reason,
            ),
            Self::Policy(reason) => {
                StockAttemptOutcome::failed(MeshStreamAttempt::PolicyRejected, reason)
            }
            Self::Retirement(retirement) => StockAttemptOutcome::local(retirement),
        };
        outcome.delivered_usable_state = delivered_usable_state;
        outcome
    }
}

/// Bounded, closed-set category for a gRPC status from a control plane Ferrum
/// does not own.
///
/// Only the canonical code reaches a log line or an error. `Status::message()`,
/// `Status::details()`, and the trailing metadata are all remote-authored: a
/// hostile (or merely careless) control plane could echo the bearer token back
/// in any of them, and Ferrum would then write the credential to its own logs.
fn grpc_status_category(status: &tonic::Status) -> &'static str {
    match status.code() {
        tonic::Code::Ok => "grpc_ok",
        tonic::Code::Cancelled => "grpc_cancelled",
        tonic::Code::Unknown => "grpc_unknown",
        tonic::Code::InvalidArgument => "grpc_invalid_argument",
        tonic::Code::DeadlineExceeded => "grpc_deadline_exceeded",
        tonic::Code::NotFound => "grpc_not_found",
        tonic::Code::AlreadyExists => "grpc_already_exists",
        tonic::Code::PermissionDenied => "grpc_permission_denied",
        tonic::Code::ResourceExhausted => "grpc_resource_exhausted",
        tonic::Code::FailedPrecondition => "grpc_failed_precondition",
        tonic::Code::Aborted => "grpc_aborted",
        tonic::Code::OutOfRange => "grpc_out_of_range",
        tonic::Code::Unimplemented => "grpc_unimplemented",
        tonic::Code::Internal => "grpc_internal",
        tonic::Code::Unavailable => "grpc_unavailable",
        tonic::Code::DataLoss => "grpc_data_loss",
        tonic::Code::Unauthenticated => "grpc_unauthenticated",
    }
}

/// The credential observation this attempt was opened under.
///
/// The fence is `(generation, deadline)`. `generation` advances only on a real
/// state change of the configured source, so comparing it answers "is the
/// credential I materialized still the current observation?" without retaining
/// a second copy of the secret. The generation bound here is the one captured
/// when *this* serialized read was admitted; it is never a later observation's
/// generation. `deadline` is absolute and was stamped at admission, so neither
/// dial latency nor application activity can move it.
#[derive(Clone)]
struct StockCredentialFence {
    generation: u64,
    deadline: Option<tokio::time::Instant>,
    /// Whether a credential source is configured at all. With none, only the
    /// (absent) deadline applies.
    configured: bool,
    /// The fence keeps its OWN receiver handle.
    ///
    /// The stream loop's `tokio::select!` holds a `&mut` borrow of the loop's
    /// receiver for its `changed()` arm for as long as that future lives, so
    /// every *other* arm — the debounce commit in particular — must be able to
    /// read the current observation without touching it. An independent handle
    /// on the same channel reads the identical shared value.
    observations: tokio::sync::watch::Receiver<StockCredentialObservation>,
}

impl StockCredentialFence {
    fn bind(
        watch: &StockCredentialWatch,
        generation: u64,
        deadline: Option<tokio::time::Instant>,
        configured: bool,
    ) -> Self {
        Self {
            generation,
            deadline,
            configured,
            observations: watch.receiver(),
        }
    }

    fn latest(&self) -> StockCredentialObservation {
        *self.observations.borrow()
    }

    fn retirement_from_observation(
        &self,
        observed: StockCredentialObservation,
    ) -> MeshStreamRetirement {
        if observed.state.is_invalid() {
            MeshStreamRetirement::CredentialSourceInvalid
        } else {
            MeshStreamRetirement::CredentialRotated
        }
    }

    /// Fail-closed check used on the async path (select pre-check, outbound
    /// enqueue). Copies the observation; the commit path must use
    /// [`Self::admit_commit`] so the watch read lock is held across install.
    ///
    /// Returning `Some` means the stream must be retired NOW and nothing it
    /// staged may be published.
    fn evaluate(&self) -> Option<MeshStreamRetirement> {
        self.admit_locked(&self.observations.borrow())
    }

    /// Generation validation plus the absolute deadline, evaluated while the
    /// caller holds a watch observation. The deadline is last so it is as
    /// close to the subsequent synchronous install as possible.
    fn admit_locked(&self, observed: &StockCredentialObservation) -> Option<MeshStreamRetirement> {
        if self.configured {
            if observed.generation != self.generation {
                return Some(if observed.state.is_invalid() {
                    MeshStreamRetirement::CredentialSourceInvalid
                } else {
                    MeshStreamRetirement::CredentialRotated
                });
            }
            if observed.state.is_invalid() {
                return Some(MeshStreamRetirement::CredentialSourceInvalid);
            }
        }
        if let Some(deadline) = self.deadline
            && tokio::time::Instant::now() >= deadline
        {
            return Some(MeshStreamRetirement::CredentialDeadline);
        }
        None
    }

    /// Fail-closed admission for a synchronous commit.
    ///
    /// The returned guard retains the watch observation lock, so the credential
    /// watcher cannot publish a new generation or invalid state until the
    /// caller drops it. `apply_pending` / `install_slice` must run before that
    /// drop: there is no async gap between this admission and the install.
    fn admit_commit(&self) -> Result<StockCredentialAdmission<'_>, MeshStreamRetirement> {
        let observed = self.observations.borrow();
        if let Some(retirement) = self.admit_locked(&observed) {
            return Err(retirement);
        }
        Ok(StockCredentialAdmission { _held: observed })
    }
}

/// Proof that the current watch generation was admitted. Holds the tokio watch
/// read lock, so a concurrent `publish` cannot land until this value is
/// dropped. Must not be held across an `.await`.
struct StockCredentialAdmission<'a> {
    _held: tokio::sync::watch::Ref<'a, StockCredentialObservation>,
}

/// Maintain a live stock ADS stream with multi-server failover.
///
/// Three fail-closed gates run before any socket is opened, in this order:
///
/// 1. The COMPLETE configured endpoint set is admitted as one transport
///    posture (issue #3853). A refusal stops the client rather than dialing a
///    weaker endpoint.
/// 2. The external bearer credential must be observed valid (issue #3852). An
///    invalid source *prevents* reconnection; there is no stale-token or
///    freshness-only fallback.
/// 3. The selected endpoint is re-classified at connect time as defense in
///    depth, and the `authorization` interceptor refuses to attach metadata to
///    anything not classified as authenticated TLS.
#[allow(clippy::too_many_arguments)]
pub async fn start_stock_xds_client_with_shutdown(
    config: StockXdsClientConfig,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut tls_config: Option<DpGrpcTlsConfig>,
    mut tls_reload: Option<DpGrpcTlsReload>,
    policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
    credential_watch: StockCredentialWatch,
) {
    let mut policy_rx = policy_rx;
    let xds_urls = config.xds_urls.clone();
    if xds_urls.is_empty() {
        error!("No stock xDS URLs configured — cannot start stock xDS mesh client");
        return;
    }

    // Issue #3853: admit the whole primary/fallback set as ONE posture. Startup
    // validation already ran this (`MeshRuntimeConfig::from_env_config`); this
    // is the defense-in-depth copy that keeps the client itself fail-closed.
    if let Err(refusal) = admit_stock_xds_endpoints(&xds_urls, config.transport_policy()) {
        error!(
            endpoint_index = refusal.index,
            scheme = refusal.scheme(),
            host = refusal.host_class(),
            refusal = refusal.refusal.as_metric_label(),
            "Refusing to start the stock xDS mesh client: the configured ADS endpoint set does \
             not satisfy the transport-security posture"
        );
        return;
    }

    let mut credential_rx = credential_watch.receiver();
    let mut current_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    // A credential source that will not read is not the endpoint's fault, so it
    // gets its own bounded delay instead of charging the endpoint backoff.
    let mut credential_backoff_secs = BACKOFF_INITIAL_SECS;
    let mut accumulator = StockXdsAccumulator::new(config.limits);
    let mut stream_state = StockStreamState::default();
    let mut last_url: Option<String> = None;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);
    let mut tracker = MeshStreamTracker::new(
        STOCK_XDS_PROTOCOL_LABEL,
        credential_watch.latest().state.health(),
        config.timings,
    );
    state.set_config_stream_status(tracker.status(state.has_first_slice()));

    info!(
        node_id = %sanitize_startup_scalar(config.node_id.as_str()),
        namespace = %sanitize_startup_scalar(config.namespace.as_str()),
        cluster = %sanitize_startup_scalar(config.cluster.as_str()),
        xds_urls = xds_urls.len(),
        authorization = config.credential.is_configured(),
        liveness_bound_secs = %sanitize_startup_scalar(config.timings.liveness_bound_seconds()),
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

        // ── issue #3852: fail-closed credential gate ──
        // An invalid source must PREVENT reconnection, not merely fail the next
        // read. The previously read token is never reused and no
        // freshness-only path exists.
        let observed = *credential_rx.borrow_and_update();
        tracker.set_credential(observed.state.health());
        if let StockCredentialState::Invalid { reason } = observed.state {
            warn!(
                reason = reason.as_metric_label(),
                "Stock xDS bearer-credential source is invalid; refusing to open an ADS stream \
                 until valid material is available"
            );
            state.set_config_stream_status(tracker.status(state.has_first_slice()));
            let sleep_duration = jittered_backoff(credential_backoff_secs);
            let mut credential_shutdown_rx = shutdown_rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {}
                _ = credential_rx.changed() => {}
                _ = wait_for_shutdown(&mut credential_shutdown_rx) => {
                    info!("Stock xDS mesh client shutting down");
                    return;
                }
            }
            credential_backoff_secs = next_backoff_secs(credential_backoff_secs, true);
            continue;
        }
        credential_backoff_secs = BACKOFF_INITIAL_SECS;

        // Pick up a SIGHUP-reloaded policy baseline before opening the stream so
        // the next slice already carries it.
        let baseline = policy_rx.borrow_and_update().clone();

        let xds_url = &xds_urls[current_index];
        if last_url.as_deref() != Some(xds_url.as_str()) {
            if last_url.is_some() {
                info!(
                    endpoint_index = current_index,
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
        tracker.set_endpoint_index(current_index);
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let should_race_primary = should_race_primary_retry(is_fallback, config.primary_retry_secs);

        let mut force_primary = false;
        // Shutdown is recorded as an intentional retirement rather than an
        // unobserved `return`, so `/metrics` distinguishes a clean stop from a
        // stream that simply vanished.
        //
        // The select is `biased`. Shutdown is first so a stop still terminates
        // promptly. The inner ADS future is next so a credential retirement
        // that is already ready cannot be masked by a simultaneously ready
        // TLS-reload or primary-retry arm — those would cancel the inner
        // future and return `reset_discovery_state=false`, letting the next
        // stream reuse accumulator/subscription/nonce state touched under the
        // retired credential. TLS/retry arms still coalesce any pending
        // credential observation the cancelled inner had not yet consumed.
        let mut shutting_down = false;
        let outcome = if should_race_primary {
            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Stock xDS mesh client shutting down");
                    shutting_down = true;
                    StockAttemptOutcome::local(MeshStreamRetirement::Shutdown)
                }
                outcome = connect_stock_ads(
                    xds_url,
                    current_index,
                    &config,
                    baseline.clone(),
                    &request,
                    &state,
                    tls_config.as_ref(),
                    &mut accumulator,
                    &mut stream_state,
                    policy_rx.clone(),
                    recovery.clone(),
                    &credential_watch,
                    &mut credential_rx,
                    &mut tracker,
                ) => outcome,
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                    last_tls_revision,
                ) => coalesce_outer_lifecycle(
                    MeshStreamRetirement::TlsReload,
                    &mut credential_rx,
                ),
                _ = wait_for_first_slice_then_primary_retry(
                    state.clone(),
                    Duration::from_secs(config.primary_retry_secs),
                ) => {
                    let outcome = coalesce_outer_lifecycle(
                        MeshStreamRetirement::PrimaryRetry,
                        &mut credential_rx,
                    );
                    force_primary = matches!(
                        outcome.attempt,
                        MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::PrimaryRetry)
                    );
                    outcome
                }
            }
        } else {
            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Stock xDS mesh client shutting down");
                    shutting_down = true;
                    StockAttemptOutcome::local(MeshStreamRetirement::Shutdown)
                }
                outcome = connect_stock_ads(
                    xds_url,
                    current_index,
                    &config,
                    baseline.clone(),
                    &request,
                    &state,
                    tls_config.as_ref(),
                    &mut accumulator,
                    &mut stream_state,
                    policy_rx.clone(),
                    recovery.clone(),
                    &credential_watch,
                    &mut credential_rx,
                    &mut tracker,
                ) => outcome,
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                    last_tls_revision,
                ) => coalesce_outer_lifecycle(
                    MeshStreamRetirement::TlsReload,
                    &mut credential_rx,
                ),
            }
        };

        let StockAttemptOutcome {
            attempt,
            reason,
            reset_discovery_state,
            delivered_usable_state,
        } = outcome;
        // A TLS revision that was already published is applied at the top of
        // the next loop via `refresh_dp_grpc_tls_config_if_changed`. Mark it
        // seen here so a credential retirement that won the simultaneous
        // select does not get immediately cancelled by the same TLS event.
        if (reset_discovery_state
            || matches!(
                attempt,
                MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::TlsReload)
            ))
            && let Some(reload) = tls_reload.as_mut()
        {
            let _ = reload.revision_rx.borrow_and_update();
        }
        // Endpoint identity stays out of these lines: the configured URL is
        // operator-authored but unbounded, so the index plus the closed-set
        // outcome and reason are what the operator gets here and on `/metrics`.
        // A remote `Status` message, a tonic transport error, a token, a claim,
        // and a credential path can never reach any of these fields.
        match (reason, attempt.is_endpoint_failure()) {
            (Some(reason), true) => error!(
                endpoint_index = current_index,
                outcome = attempt.as_metric_label(),
                reason,
                "Stock xDS ADS attempt failed"
            ),
            (Some(reason), false) => info!(
                outcome = attempt.as_metric_label(),
                reason, "Retiring the stock xDS ADS stream on a local lifecycle event"
            ),
            (None, true) => warn!(
                endpoint_index = current_index,
                outcome = attempt.as_metric_label(),
                "Stock xDS ADS stream ended; rotating to the next configured endpoint"
            ),
            (None, false) => info!(
                outcome = attempt.as_metric_label(),
                "Retiring the stock xDS ADS stream on a local lifecycle event"
            ),
        }

        // Issue #3852: a stream retired for credential rotation, invalidation,
        // or deadline must leave NOTHING behind. The ADS accumulator and the
        // per-type subscription/nonce state were both mutated by responses that
        // arrived under the retired credential, so they are discarded here; the
        // only thing that survives is the slice already installed in the
        // runtime, which was committed while the credential was still current.
        if reset_discovery_state {
            accumulator = StockXdsAccumulator::new(config.limits);
            stream_state = StockStreamState::default();
            last_url = None;
        }

        let disposition = tracker.record(attempt);
        if force_primary {
            current_index = 0;
        } else if disposition.advance_endpoint {
            current_index = (current_index + 1) % xds_urls.len();
        }
        state.set_config_stream_status(tracker.status(state.has_first_slice()));
        if shutting_down {
            return;
        }

        // An intentional local retirement reconnects immediately with the new
        // material and never charges the endpoint's backoff.
        if !attempt.is_endpoint_failure() {
            backoff_secs = BACKOFF_INITIAL_SECS;
            continue;
        }

        let (sleep_secs, next_secs) = reconnect_backoff_after_attempt(
            backoff_secs,
            disposition.increase_backoff,
            delivered_usable_state,
        );
        let sleep_duration = jittered_backoff(sleep_secs);
        let mut sleep_shutdown_rx = shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut sleep_shutdown_rx) => {
                info!("Stock xDS mesh client shutting down");
                return;
            }
            _ = wait_optional_tls_reload(
                tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                last_tls_revision,
            ) => {
                backoff_secs = BACKOFF_INITIAL_SECS;
                continue;
            }
        }
        backoff_secs = next_secs;
    }
}

async fn wait_for_first_slice_then_primary_retry(state: MeshRuntimeState, interval: Duration) {
    state.wait_for_first_slice().await;
    tokio::time::sleep(interval).await;
}

/// TLS-reload and primary-retry cancel the inner ADS future. If that future
/// already had a pending credential observation (rotation, invalidation) that
/// it had not yet consumed, the cancellation would otherwise report the
/// lifecycle event with `reset_discovery_state=false`. Peek the watch so the
/// credential retirement — and its required discovery-state reset — is
/// retained. Shutdown is not routed through here: it is selected first and
/// still terminates promptly.
fn coalesce_outer_lifecycle(
    fallback: MeshStreamRetirement,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
) -> StockAttemptOutcome {
    if credential_rx.has_changed().unwrap_or(false) {
        let observed = *credential_rx.borrow_and_update();
        return StockAttemptOutcome::local(if observed.state.is_invalid() {
            MeshStreamRetirement::CredentialSourceInvalid
        } else {
            MeshStreamRetirement::CredentialRotated
        });
    }
    StockAttemptOutcome::local(fallback)
}

#[allow(clippy::too_many_arguments)]
async fn connect_stock_ads(
    xds_url: &str,
    endpoint_index: usize,
    config: &StockXdsClientConfig,
    baseline: StockPolicySnapshot,
    request: &MeshSliceRequest,
    state: &MeshRuntimeState,
    tls_config: Option<&DpGrpcTlsConfig>,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
    policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
    credential_watch: &StockCredentialWatch,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
    tracker: &mut MeshStreamTracker,
) -> StockAttemptOutcome {
    // Defense in depth (issue #3853): re-classify the endpoint about to be
    // dialed. `admit_stock_xds_endpoints` already ran at startup and at client
    // start, so reaching a refusal here means an admission path was bypassed —
    // fail closed before a socket exists rather than trusting the earlier gate.
    let transport =
        match classify_stock_xds_endpoint(endpoint_index, xds_url, config.transport_policy()) {
            Ok(transport) => transport,
            Err(refusal) => {
                // The refusal type is already bounded and index-shaped, but
                // only its closed-set reason label is emitted here.
                return StockAttemptOutcome::failed(
                    MeshStreamAttempt::PolicyRejected,
                    refusal.refusal.as_metric_label(),
                );
            }
        };

    let mut endpoint = match Channel::from_shared(xds_url.to_string()) {
        Ok(endpoint) => configure_mesh_config_stream_endpoint(
            endpoint,
            config.connect_timeout_seconds,
            config.timings,
        ),
        // The tonic error renders the offending URI, so it is dropped.
        Err(_) => {
            return StockAttemptOutcome::failed(
                MeshStreamAttempt::TransportFailure {
                    delivered_usable_state: false,
                    after_established: false,
                },
                "endpoint_uri_invalid",
            );
        }
    };
    if let Some(tls) = tls_config {
        let mut client_tls = tonic_tls_config(tls);
        if let Ok(uri) = xds_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }
        endpoint = match endpoint.tls_config(client_tls) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return StockAttemptOutcome::failed(
                    MeshStreamAttempt::TransportFailure {
                        delivered_usable_state: false,
                        after_established: false,
                    },
                    "tls_config_rejected",
                );
            }
        };
    }

    // The bearer is materialized per connection attempt, so a failover or a
    // failback always presents the NEWEST material rather than a value captured
    // by an earlier endpoint's interceptor. Publication is last-completed-read:
    // the epoch stamped under the one-reader permit is what admits this
    // observation, so a delayed older read cannot overwrite a newer watcher
    // result or bind a fence to that stale generation.
    let read = config.credential.observe().await;
    let observed = read.observed_state();
    let generation =
        match admit_stock_credential_observation(credential_watch, read.epoch(), observed) {
            Ok(generation) => {
                // Mark our own publication seen so the live stream does not treat
                // it as a rotation on its very first poll.
                let _ = credential_rx.borrow_and_update();
                tracker.set_credential(observed.health());
                generation
            }
            Err(retirement) => {
                let _ = credential_rx.borrow_and_update();
                tracker.set_credential(credential_watch.latest().state.health());
                return StockAttemptOutcome::local(retirement);
            }
        };
    let credential = match read.into_outcome() {
        Ok(credential) => credential,
        Err(reason) => {
            return StockAttemptOutcome::local_with_reason(
                MeshStreamRetirement::CredentialSourceInvalid,
                reason.as_metric_label(),
            );
        }
    };

    // The fence this attempt is bound to. `generation` is the value captured
    // under the watch send lock when THIS observation was admitted — never
    // `latest()` after the lock is dropped, which could already be a newer
    // replacement. `deadline` is the absolute instant stamped at admission —
    // dial latency spends it rather than extending it.
    let fence = StockCredentialFence::bind(
        credential_watch,
        generation,
        credential.as_ref().map(StockBearerCredential::deadline),
        config.credential.is_configured(),
    );

    let channel = match endpoint.connect().await {
        Ok(channel) => channel,
        // The tonic transport error can render the configured URI/host, so the
        // attempt is reported by index and closed-set reason only.
        Err(_) => {
            return StockAttemptOutcome::failed(
                MeshStreamAttempt::TransportFailure {
                    delivered_usable_state: false,
                    after_established: false,
                },
                "connect_failed",
            );
        }
    };

    // Re-prove the credential is STILL the current observation, and still
    // inside its absolute deadline, before the streaming RPC is opened. Dialing
    // is unbounded in principle (DNS, TCP, TLS handshake), so a rotation or an
    // invalidation that landed during the dial must not be able to ride into
    // the new stream.
    if credential
        .as_ref()
        .is_some_and(StockBearerCredential::deadline_reached)
    {
        return StockAttemptOutcome::local_with_reason(
            MeshStreamRetirement::CredentialDeadline,
            StockCredentialInvalidReason::DeadlineReached.as_metric_label(),
        );
    }
    if let Some(retirement) = fence.evaluate() {
        let _ = credential_rx.borrow_and_update();
        tracker.set_credential(credential_watch.latest().state.health());
        return StockAttemptOutcome::local_with_reason(retirement, "observed_before_rpc_open");
    }

    info!(
        node_id = %sanitize_startup_scalar(config.node_id.as_str()),
        namespace = %sanitize_startup_scalar(config.namespace.as_str()),
        endpoint_index,
        transport = transport.as_label(),
        authorization = credential.is_some(),
        authorization_lifetime_secs = %sanitize_startup_scalar(
            credential
                .as_ref()
                .map(|credential| credential.lifetime().as_secs())
                .unwrap_or(0)
        ),
        authorization_deadline_basis = credential
            .as_ref()
            .map(|credential| credential.deadline_basis().as_metric_label())
            .unwrap_or("none"),
        "Connected to stock xDS control plane; subscribing CDS + LDS"
    );

    let mut delivered_usable_state = false;
    let attempt_started_at = tokio::time::Instant::now();
    let result = run_stock_ads_stream(
        channel,
        credential,
        transport,
        fence,
        config,
        baseline,
        request,
        state,
        accumulator,
        stream_state,
        policy_rx,
        recovery,
        credential_rx,
        tracker,
        &mut delivered_usable_state,
        attempt_started_at,
    )
    .await;
    tracker.set_attachment(MeshStreamAttachment::Detached);
    state.set_config_stream_status(tracker.status(state.has_first_slice()));

    match result {
        Ok(attempt) => {
            let mut outcome = StockAttemptOutcome::ended(attempt, delivered_usable_state);
            if let MeshStreamAttempt::LocalRetirement(retirement) = attempt {
                outcome.reset_discovery_state = retirement.is_credential_retirement();
            }
            outcome
        }
        Err(error) => error.into_outcome(delivered_usable_state),
    }
}

/// The `authorization`-metadata INSERTION boundary (issue #3853).
///
/// Top-level admission (`admit_stock_xds_endpoints`) and the connect-time
/// re-classification in `connect_stock_ads` both run before this point, so
/// reaching it with a non-TLS transport means an admission path was bypassed.
/// This is the last gate, and it fails closed: the bearer is never written onto
/// a request whose endpoint is not classified as authenticated TLS.
///
/// Extracted from the interceptor closure so the boundary can be exercised
/// DIRECTLY — a test that only configures a plaintext endpoint proves
/// connect-time classification, not this insertion check.
pub fn attach_stock_authorization(
    authorization: Option<&(BearerToken, StockXdsTransport)>,
    request: &mut tonic::Request<()>,
) -> Result<(), tonic::Status> {
    let Some((token, transport)) = authorization else {
        return Ok(());
    };
    if !transport.allows_authorization_metadata() {
        return Err(tonic::Status::failed_precondition(
            "refusing to attach stock xDS authorization metadata to an endpoint that is not \
             classified as authenticated TLS",
        ));
    }
    request
        .metadata_mut()
        .insert("authorization", token.clone());
    Ok(())
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
    credential: Option<StockBearerCredential>,
    transport: StockXdsTransport,
    fence: StockCredentialFence,
    config: &StockXdsClientConfig,
    mut baseline: StockPolicySnapshot,
    request: &MeshSliceRequest,
    state: &MeshRuntimeState,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
    mut policy_rx: tokio::sync::watch::Receiver<StockPolicySnapshot>,
    recovery: Arc<MeshLocalSourceRecovery>,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
    tracker: &mut MeshStreamTracker,
    delivered_usable_state: &mut bool,
    attempt_started_at: tokio::time::Instant,
) -> Result<MeshStreamAttempt, StockStreamError> {
    // The authorization metadata and the endpoint's admitted transport travel
    // together into the interceptor. This is the issue-#3853 defense in depth:
    // even if top-level admission were bypassed, a bearer can only be attached
    // to an endpoint classified as authenticated TLS.
    let authorization = credential
        .as_ref()
        .map(|credential| (credential.token().clone(), transport));
    #[allow(clippy::result_large_err)]
    let mut client = AggregatedDiscoveryServiceClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            attach_stock_authorization(authorization.as_ref(), &mut req)?;
            Ok(req)
        },
    )
    .max_decoding_message_size(MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE);

    let (tx, rx) = mpsc::channel(config.stream_channel_capacity.max(1));
    let request_stream = ReceiverStream::new(rx);
    // The interceptor attaches/sends the bearer as soon as this future is
    // polled. A control plane can accept that authenticated request and then
    // withhold response headers, so the RPC-open await itself must be raced
    // against credential generation/invalidation/deadline AND the absolute
    // first-frame bound. Already-observed or simultaneously-ready credential
    // retirement wins (biased) and still resets discovery state; first-frame
    // covers the no-bearer withhold case. Dropping the pending open cancels
    // it; nothing is detached. Remote Status text stays classified, never
    // echoed.
    let first_frame_at = attempt_started_at + config.timings.first_frame;
    let mut response_stream = match await_stock_ads_rpc_open_under_fence(
        client.stream_aggregated_resources(request_stream),
        &fence,
        credential_rx,
        first_frame_at,
    )
    .await
    {
        Ok(StockRpcOpen::Ready(response)) => response.into_inner(),
        Ok(StockRpcOpen::FirstFrameTimeout) => {
            return Ok(MeshStreamAttempt::FirstFrameTimeout);
        }
        Err(StockStreamError::Retirement(retirement)) => {
            return Ok(MeshStreamAttempt::LocalRetirement(retirement));
        }
        Err(error) => return Err(error),
    };

    // A retirement that became ready in the same poll as an open success was
    // already preferred by the biased select. Re-check before publishing
    // Established so `/health` cannot claim a stream we are about to drop.
    if let Some(retirement) = fence.evaluate() {
        return Ok(MeshStreamAttempt::LocalRetirement(retirement));
    }

    // The streaming RPC is open and this consumer is about to read it: that is
    // exactly what `/health` means by `connected` (issue #3854).
    tracker.set_attachment(MeshStreamAttachment::Established);
    state.set_config_stream_status(tracker.status(state.has_first_slice()));

    // Nonces are stream-scoped, and every new stream must re-send `Node`.
    stream_state.subscriptions.reset_for_new_stream();

    {
        let mut outbound = StockOutbound {
            tx: &tx,
            bound: config.timings.outbound,
            fence: &fence,
            credential_rx,
        };

        for type_url in STOCK_INITIAL_TYPE_URL_ORDER {
            let subscribe = stream_state
                .subscriptions
                .build_request(type_url, config, None);
            outbound
                .enqueue(subscribe)
                .await
                .map_err(StockOutboundError::into_stream_error)?;
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
                outbound
                    .enqueue(subscribe)
                    .await
                    .map_err(StockOutboundError::into_stream_error)?;
            }
        }
    }

    let debounce = tokio::time::sleep(Duration::from_secs(60 * 60 * 24));
    tokio::pin!(debounce);
    // Owns the debounce arming: the timer is polled only while a complete,
    // ACKed (or policy-rebuilt) generation is staged.
    let mut pending: PendingGeneration<Box<PendingStockSlice>> = PendingGeneration::NoPending;
    let mut last_logged_refusals: Option<Vec<StockRefusal>> = None;
    let mut policy_watch_open = true;

    // ── issue #3854: bounded liveness for an ESTABLISHED stream ──
    // HTTP/2 + TCP keepalive (applied on the endpoint) already fail a
    // blackholed transport. These two deadlines cover the other half: a control
    // plane that accepts the RPC and then supplies nothing usable. They are
    // the SAME absolute clocks that covered RPC-open: headers do not reset
    // them. Already-expired clocks are polled before debounce and before
    // `message()`, so a continuously ready incomplete frame cannot starve
    // them; debounce still outranks the next message.
    let first_frame_deadline = tokio::time::sleep_until(first_frame_at);
    tokio::pin!(first_frame_deadline);
    let mut awaiting_first_frame = true;
    let first_slice_deadline =
        tokio::time::sleep_until(attempt_started_at + config.timings.first_slice);
    tokio::pin!(first_slice_deadline);
    // Armed only while this data plane has never had a slice at all: a
    // converged proxy must not be torn down for a legitimately quiet CP.
    let mut awaiting_first_slice = !state.has_first_slice();

    // ── issue #3852: finite local authorization lifetime ──
    // The deadline is ABSOLUTE and was stamped at credential ADMISSION, before
    // the channel was dialed — see `StockBearerCredential::admit`. Deriving it
    // from stream-open time would silently extend a JWT past `exp` by the dial
    // and RPC-setup latency. Application activity never resets it either, which
    // is why nothing in this loop touches it.
    let credential_deadline = fence.deadline;
    let credential_deadline_sleep = tokio::time::sleep_until(
        credential_deadline
            .unwrap_or_else(|| attempt_started_at + Duration::from_secs(60 * 60 * 24)),
    );
    tokio::pin!(credential_deadline_sleep);
    let mut credential_watch_open = true;

    let ended = loop {
        // The select below is `biased`, so the credential branches are polled
        // before the response branch. That alone is not sufficient: a response
        // could already be buffered and a simultaneously-ready timer could lose
        // an unbiased draw, and — more importantly — the credential could have
        // changed while the previous iteration's handler was awaiting. This
        // explicit pre-check is the actual fence: no response may be admitted
        // in an iteration whose credential is no longer current.
        if let Some(retirement) = fence.evaluate() {
            break MeshStreamAttempt::LocalRetirement(retirement);
        }
        tokio::select! {
            biased;
            _ = &mut credential_deadline_sleep, if credential_deadline.is_some() => {
                break MeshStreamAttempt::LocalRetirement(
                    MeshStreamRetirement::CredentialDeadline,
                );
            }
            changed = credential_rx.changed(), if credential_watch_open => {
                if changed.is_err() {
                    // The watcher is gone (shutdown). Stop selecting on it
                    // rather than spinning; the absolute deadline above still
                    // bounds this stream's authorization lifetime.
                    credential_watch_open = false;
                    continue;
                }
                // Read through the fence's own handle: the `changed()` future
                // above still holds the `&mut` borrow of `credential_rx`.
                let observed = fence.latest();
                break MeshStreamAttempt::LocalRetirement(if observed.state.is_invalid() {
                    MeshStreamRetirement::CredentialSourceInvalid
                } else {
                    MeshStreamRetirement::CredentialRotated
                });
            }
            _ = &mut first_frame_deadline, if awaiting_first_frame => {
                break MeshStreamAttempt::FirstFrameTimeout;
            }
            _ = &mut first_slice_deadline, if awaiting_first_slice => {
                if state.has_first_slice() {
                    awaiting_first_slice = false;
                } else {
                    break MeshStreamAttempt::FirstSliceTimeout;
                }
            }
            _ = &mut debounce, if pending.is_staged() => {
                match pending.transition(PendingGenerationEvent::Commit) {
                    PendingGenerationAction::Commit(next) => {
                        // Re-check immediately before the commit, holding the watch
                        // observation across the synchronous install so a concurrent
                        // publish cannot land a retired generation between the
                        // check and `install_slice`.
                        match commit_pending(
                            &fence,
                            config,
                            state,
                            next,
                            &mut last_logged_refusals,
                            &recovery,
                        ) {
                            Ok(()) => {}
                            Err(StockCommitFailure::Retirement(retirement)) => {
                                break MeshStreamAttempt::LocalRetirement(retirement);
                            }
                            Err(StockCommitFailure::Policy(reason)) => {
                                return Err(StockStreamError::Policy(reason));
                            }
                        }
                        *delivered_usable_state = true;
                        awaiting_first_slice = false;
                        // This exact stream installed usable state: clear the
                        // consecutive-failure run and the sticky liveness flag.
                        tracker.record_usable_state();
                        state.set_config_stream_status(tracker.status(state.has_first_slice()));
                    }
                    // `Commit` never re-arms; `None` means nothing was staged.
                    PendingGenerationAction::None
                    | PendingGenerationAction::ArmDebounce { .. } => {}
                }
            }
            response = response_stream.message() => {
                let response = response
                    .map_err(|status| StockStreamError::Transport(grpc_status_category(&status)))?;
                let Some(response) = response else {
                    // A remote clean EOF is NOT success. The control plane hung
                    // up without being asked to, so the endpoint rotates and the
                    // bounded backoff grows (issue #3854).
                    break MeshStreamAttempt::RemoteEof;
                };
                awaiting_first_frame = false;
                match handle_stock_response(
                    response,
                    config,
                    baseline.mesh(),
                    baseline.recovery_epoch,
                    request,
                    &mut StockOutbound {
                        tx: &tx,
                        bound: config.timings.outbound,
                        fence: &fence,
                        credential_rx,
                    },
                    accumulator,
                    stream_state,
                ).await.map_err(StockResponseError::into_stream_error)? {
                    StockResponseOutcome::Pending(next) => {
                        let action = pending.transition(PendingGenerationEvent::Stage {
                            generation: next,
                            now: tokio::time::Instant::now(),
                        });
                        arm_stock_debounce(debounce.as_mut(), action, config.timings);
                    }
                    StockResponseOutcome::Acked => {}
                    StockResponseOutcome::Nacked => {
                        // The NACK rollback excludes only the NACKed response;
                        // the staged slice (or policy rebuild) remains a
                        // complete ACKed view and keeps its deadline. Dropping
                        // it would leave the previous slice serving until the
                        // next unrelated discovery push.
                        let action = pending.transition(PendingGenerationEvent::ResponseNacked);
                        arm_stock_debounce(debounce.as_mut(), action, config.timings);
                        if pending.is_staged() {
                            debug!(
                                node_id = %sanitize_startup_scalar(config.node_id.as_str()),
                                "Retaining the debounced stock xDS slice after a NACK of a \
                                 later response"
                            );
                        }
                    }
                }
                state.set_xds_convergence(convergence_snapshot(accumulator));
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
                    node_id = %sanitize_startup_scalar(config.node_id.as_str()),
                    namespace = %sanitize_startup_scalar(config.namespace.as_str()),
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
                            let action = pending.transition(PendingGenerationEvent::Stage {
                                generation: Box::new(PendingStockSlice {
                                    slice,
                                    type_url: "policy-reload".to_string(),
                                    refusals: discovery.refusals,
                                    policy_recovery_epoch: baseline.recovery_epoch,
                                }),
                                now: tokio::time::Instant::now(),
                            });
                            arm_stock_debounce(debounce.as_mut(), action, config.timings);
                        }
                        Err(_) => {
                            // Epoch-checked: a newer reload may have begun its
                            // own recovery while this older baseline was being
                            // rebuilt, and this failure must not cancel it.
                            // A baseline without an epoch is not a recovery
                            // candidate, so the failure is rejected outright.
                            let config_rejected_raised = match baseline.recovery_epoch {
                                Some(epoch) => recovery.mark_rejected_for_epoch(epoch),
                                None => {
                                    recovery.mark_rejected();
                                    true
                                }
                            };
                            warn!(
                                node_id = %crate::startup::sanitize_startup_cause(
                                    format!("{:?}", config.node_id.to_string()),
                                    &[]
                                ),
                                type_url = stock_log_type_label("policy-reload"),
                                config_rejected_raised,
                                "Reloaded mesh policy document failed slice construction; keeping \
                                 the last good slice (config_rejected is left to a newer pending \
                                 policy recovery when this baseline is stale)"
                            );
                        }
                    }
                }
            }
        }
    };

    // A debounced slice that is already complete is published on a clean end.
    // A partial ADS generation never reaches this point: `pending` is only ever
    // set once the accumulator's own required-type gate is satisfied, so an EOF
    // mid-convergence leaves the last good slice serving and fails over
    // (issue #3854 — no mixed generation is ever published).
    //
    // The fence is re-evaluated one final time while the watch observation is
    // held across the synchronous install: this flush is a COMMIT, and a
    // credential that rotated, was invalidated, or hit its deadline while the
    // slice sat in the debounce window must retire the stream WITHOUT
    // publishing anything it staged (issue #3852). The already-installed
    // last-good runtime slice is the only thing that survives.
    if matches!(ended, MeshStreamAttempt::RemoteEof)
        && let PendingGenerationAction::Commit(next) =
            pending.transition(PendingGenerationEvent::Commit)
    {
        match commit_pending(
            &fence,
            config,
            state,
            next,
            &mut last_logged_refusals,
            &recovery,
        ) {
            Ok(()) => {
                *delivered_usable_state = true;
                tracker.record_usable_state();
                state.set_config_stream_status(tracker.status(state.has_first_slice()));
            }
            Err(StockCommitFailure::Retirement(retirement)) => {
                warn!(
                    outcome = retirement.as_metric_label(),
                    "Discarding a staged stock xDS slice at stream end: the credential that \
                     produced it is no longer current"
                );
                return Ok(MeshStreamAttempt::LocalRetirement(retirement));
            }
            Err(StockCommitFailure::Policy(reason)) => {
                return Err(StockStreamError::Policy(reason));
            }
        }
    }
    Ok(ended)
}

/// Re-arm the stock debounce timer when a transition asks for it.
fn arm_stock_debounce(
    debounce: std::pin::Pin<&mut tokio::time::Sleep>,
    action: PendingGenerationAction<Box<PendingStockSlice>>,
    timings: MeshStreamTimings,
) {
    match action {
        PendingGenerationAction::ArmDebounce {
            now,
            first_staged_at,
        } => debounce.reset(timings.apply_deadline(now, first_staged_at)),
        PendingGenerationAction::None | PendingGenerationAction::Commit(_) => {}
    }
}

enum StockResponseOutcome {
    /// Boxed: a `MeshSlice` dwarfs the unit variants, and an unboxed payload
    /// would make every `Acked`/`Nacked` return move a slice-sized enum.
    Pending(Box<PendingStockSlice>),
    Acked,
    Nacked,
}

/// Why admitting one ADS response failed. The payload is always a closed-set
/// `&'static str`: a stock control plane authors the resource type URLs, the
/// status messages, and the error details, so none of them may be carried into
/// an operator-facing error string.
enum StockResponseError {
    /// The outbound request could not be enqueued in the bounded window.
    Transport(&'static str),
    /// A local fail-closed gate refused the content.
    Policy(&'static str),
    /// Credential retirement won while an ACK/NACK/dependency send was awaited.
    Retirement(MeshStreamRetirement),
}

impl StockResponseError {
    fn into_stream_error(self) -> StockStreamError {
        match self {
            Self::Transport(reason) => StockStreamError::Transport(reason),
            Self::Policy(reason) => StockStreamError::Policy(reason),
            Self::Retirement(reason) => StockStreamError::Retirement(reason),
        }
    }
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
    outbound: &mut StockOutbound<'_>,
    accumulator: &mut StockXdsAccumulator,
    stream_state: &mut StockStreamState,
) -> Result<StockResponseOutcome, StockResponseError> {
    let type_url = response.type_url.clone();
    let type_label = stock_log_type_label(&type_url);

    // Unsubscribed / unsupported types fail closed by terminating the stream.
    // Sending a NACK DiscoveryRequest for a type the client never requested
    // would itself create a wildcard subscription to that type under SotW
    // semantics. SDS gets a dedicated closed-set reason because a stock CP
    // volunteering key material is a security-relevant event. Ferrum refuses
    // it without decoding key fields and without logging any CP-authored
    // name, type URL, or payload.
    if !is_stock_type_url(&type_url) {
        let reason = if type_url == SDS_TYPE_URL {
            "unsolicited_sds"
        } else {
            "unsolicited_type_url"
        };
        if type_url == SDS_TYPE_URL {
            warn!(
                node_id = %crate::startup::sanitize_startup_cause(
                    format!("{:?}", config.node_id.to_string()),
                    &[]
                ),
                namespace = %crate::startup::sanitize_startup_cause(
                    format!("{:?}", config.namespace.to_string()),
                    &[]
                ),
                type_url = type_label,
                reason,
                refused_resources = response.resources.len(),
                "Refused SDS secrets pushed by the stock control plane; Ferrum never \
                 ingests control-plane-delivered key or trust material"
            );
        }
        warn!(
            node_id = %crate::startup::sanitize_startup_cause(
                format!("{:?}", config.node_id.to_string()),
                &[]
            ),
            type_url = type_label,
            reason,
            "Closing stock xDS stream after an unsolicited unsupported resource type"
        );
        return Err(StockResponseError::Policy(reason));
    }

    debug!(
        node_id = %sanitize_startup_scalar(config.node_id.as_str()),
        type_url = type_label,
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
            node_id = %sanitize_startup_scalar(config.node_id.as_str()),
            type_url = type_label,
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
        outbound
            .enqueue(nack)
            .await
            .map_err(StockOutboundError::into_response_error)?;
        warn!(
            node_id = %crate::startup::sanitize_startup_cause(
                format!("{:?}", config.node_id.to_string()),
                &[]
            ),
            namespace = %crate::startup::sanitize_startup_cause(
                format!("{:?}", config.namespace.to_string()),
                &[]
            ),
            type_url = type_label,
            consecutive_nacks = consecutive,
            blocking_first_slice,
            "NACKing invalid stock xDS ADS response"
        );
        if blocking_first_slice {
            crate::plugins::mesh::prometheus_helpers::increment_xds_first_slice_nack(
                &config.namespace,
                &type_url,
            );
        }
        if consecutive >= STOCK_CONSECUTIVE_NACK_LIMIT {
            warn!(
                node_id = %crate::startup::sanitize_startup_cause(
                    format!("{:?}", config.node_id.to_string()),
                    &[]
                ),
                type_url = type_label,
                consecutive_nacks = consecutive,
                "Stock xDS NACK circuit breaker tripped; closing the stream to trigger \
                 reconnect/failover"
            );
            return Err(StockResponseError::Policy("nack_circuit_breaker"));
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
    outbound
        .enqueue(ack)
        .await
        .map_err(StockOutboundError::into_response_error)?;
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
            node_id = %sanitize_startup_scalar(config.node_id.as_str()),
            type_url = "eds",
            resources = names.len(),
            "Updating dependency-ordered EDS subscription after CDS update"
        );
        let subscribe = stream_state
            .subscriptions
            .build_request(EDS_TYPE_URL, config, None);
        outbound
            .enqueue(subscribe)
            .await
            .map_err(StockOutboundError::into_response_error)?;
    }
    if type_url == LDS_TYPE_URL
        && stream_state
            .subscriptions
            .set_resource_names(RDS_TYPE_URL, accumulator.rds_subscriptions())
    {
        let names = stream_state.subscriptions.resource_names(RDS_TYPE_URL);
        debug!(
            node_id = %sanitize_startup_scalar(config.node_id.as_str()),
            type_url = "rds",
            resources = names.len(),
            "Updating dependency-ordered RDS subscription after LDS update"
        );
        let subscribe = stream_state
            .subscriptions
            .build_request(RDS_TYPE_URL, config, None);
        outbound
            .enqueue(subscribe)
            .await
            .map_err(StockOutboundError::into_response_error)?;
    }

    if !accumulator.ready() {
        debug!(
            node_id = %sanitize_startup_scalar(config.node_id.as_str()),
            type_url = type_label,
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
        Err(_) => {
            // The discovery half validated structurally; a failure here means
            // the merged document is invalid. Keep the last good slice and
            // surface it rather than tearing the stream down. The validation
            // error can echo remote resource names, so it is omitted from logs.
            warn!(
                node_id = %crate::startup::sanitize_startup_cause(
                    format!("{:?}", config.node_id.to_string()),
                    &[]
                ),
                namespace = %crate::startup::sanitize_startup_cause(
                    format!("{:?}", config.namespace.to_string()),
                    &[]
                ),
                type_url = type_label,
                "Stock xDS discovery did not produce a valid mesh slice; keeping the last good slice"
            );
            Ok(StockResponseOutcome::Acked)
        }
    }
}

enum StockCommitFailure {
    Retirement(MeshStreamRetirement),
    Policy(&'static str),
}

/// Admit the current credential generation and install while the watch
/// observation lock is held. There is no async gap between final admission and
/// `install_slice`; a concurrent watcher publish blocks until this returns.
fn commit_pending(
    fence: &StockCredentialFence,
    config: &StockXdsClientConfig,
    state: &MeshRuntimeState,
    pending: Box<PendingStockSlice>,
    last_logged_refusals: &mut Option<Vec<StockRefusal>>,
    recovery: &MeshLocalSourceRecovery,
) -> Result<(), StockCommitFailure> {
    let _admission = fence
        .admit_commit()
        .map_err(StockCommitFailure::Retirement)?;
    apply_pending(config, state, pending, last_logged_refusals, recovery)
        .map_err(StockCommitFailure::Policy)
}

fn apply_pending(
    config: &StockXdsClientConfig,
    state: &MeshRuntimeState,
    pending: Box<PendingStockSlice>,
    last_logged_refusals: &mut Option<Vec<StockRefusal>>,
    recovery: &MeshLocalSourceRecovery,
) -> Result<(), &'static str> {
    let PendingStockSlice {
        slice,
        type_url,
        refusals,
        policy_recovery_epoch,
    } = *pending;
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
            return Err(rejection.reason().as_metric_label());
        }
    }
    log_refusals(config, &refusals, last_logged_refusals);
    info!(
        node_id = %sanitize_startup_scalar(config.node_id.as_str()),
        namespace = %sanitize_startup_scalar(config.namespace.as_str()),
        type_url = stock_log_type_label(&type_url),
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
/// a static list. Only closed-set type labels, reason codes, and counts are
/// emitted — resource names and field details can carry CP-authored bytes.
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
        node_id = %crate::startup::sanitize_startup_cause(
            format!("{:?}", config.node_id.to_string()),
            &[]
        ),
        namespace = %crate::startup::sanitize_startup_cause(
            format!("{:?}", config.namespace.to_string()),
            &[]
        ),
        refused_resources = refusals.len(),
        reasons = ?by_reason,
        "Stock xDS control plane sent resources the Ferrum stock profile does not model; they \
         are excluded from routing and trust (see docs/mesh.md 'Stock xDS interoperability')"
    );
    for refusal in refusals.iter().take(STOCK_REFUSAL_LOG_LIMIT) {
        warn!(
            node_id = %crate::startup::sanitize_startup_cause(
                format!("{:?}", config.node_id.to_string()),
                &[]
            ),
            type_url = refusal.type_label,
            reason = refusal.reason,
            "Refused a stock xDS resource"
        );
    }
    if refusals.len() > STOCK_REFUSAL_LOG_LIMIT {
        warn!(
            node_id = %crate::startup::sanitize_startup_cause(
                format!("{:?}", config.node_id.to_string()),
                &[]
            ),
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

/// Closed-set type label for stock ADS diagnostics. Arbitrary remote
/// `type_url` strings collapse to `unsolicited`.
fn stock_log_type_label(type_url: &str) -> &'static str {
    match type_url {
        CDS_TYPE_URL => "cds",
        EDS_TYPE_URL => "eds",
        LDS_TYPE_URL => "lds",
        RDS_TYPE_URL => "rds",
        SDS_TYPE_URL => "sds",
        "policy-reload" => "policy_reload",
        _ => "unsolicited",
    }
}

/// Race one ADS RPC-open (response-headers) future against the credential
/// fence and the absolute first-frame bound. Mirrors the outbound enqueue
/// fence: already-observed retirement wins before the wait, the select is
/// `biased` so a simultaneously-ready generation, invalidation, or absolute
/// credential deadline wins over first-frame and over an open success, and
/// dropping this future is what cancels the in-flight open. No task is
/// detached. A closed credential watcher does not spin or invent a rotation;
/// the absolute credential deadline and the first-frame bound still apply.
enum StockRpcOpen<S> {
    Ready(tonic::Response<S>),
    FirstFrameTimeout,
}

async fn await_stock_ads_rpc_open_under_fence<S>(
    rpc_open: impl Future<Output = Result<tonic::Response<S>, tonic::Status>>,
    fence: &StockCredentialFence,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
    first_frame_at: tokio::time::Instant,
) -> Result<StockRpcOpen<S>, StockStreamError> {
    if let Some(retirement) = fence.evaluate() {
        return Err(StockStreamError::Retirement(retirement));
    }

    let deadline = fence.deadline;
    let deadline_sleep = tokio::time::sleep_until(
        deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60 * 60 * 24)),
    );
    tokio::pin!(deadline_sleep);
    let first_frame_deadline = tokio::time::sleep_until(first_frame_at);
    tokio::pin!(first_frame_deadline);
    tokio::pin!(rpc_open);

    tokio::select! {
        biased;
        _ = &mut deadline_sleep, if deadline.is_some() => {
            Err(StockStreamError::Retirement(
                MeshStreamRetirement::CredentialDeadline,
            ))
        }
        changed = credential_rx.changed() => {
            if changed.is_err() {
                // Watcher is gone (shutdown). Do not spin or mislabel that as
                // rotation; the absolute credential deadline and first-frame
                // bound still cover this open.
                tokio::select! {
                    biased;
                    _ = &mut deadline_sleep, if deadline.is_some() => {
                        Err(StockStreamError::Retirement(
                            MeshStreamRetirement::CredentialDeadline,
                        ))
                    }
                    _ = &mut first_frame_deadline => {
                        Ok(StockRpcOpen::FirstFrameTimeout)
                    }
                    result = &mut rpc_open => map_rpc_open_result(result),
                }
            } else {
                Err(StockStreamError::Retirement(
                    fence.retirement_from_observation(fence.latest()),
                ))
            }
        }
        _ = &mut first_frame_deadline => {
            Ok(StockRpcOpen::FirstFrameTimeout)
        }
        result = &mut rpc_open => map_rpc_open_result(result),
    }
}

fn map_rpc_open_result<S>(
    result: Result<tonic::Response<S>, tonic::Status>,
) -> Result<StockRpcOpen<S>, StockStreamError> {
    // Only the canonical gRPC code: the status message is remote-authored.
    result
        .map(StockRpcOpen::Ready)
        .map_err(|status| StockStreamError::SubscriptionRefused(grpc_status_category(&status)))
}

/// Enqueue one outbound `DiscoveryRequest`, bounded and credential-aware.
///
/// The bound is load-bearing (issue #3854). The outbound channel drains into
/// the gRPC request stream, so a control plane that accepts the RPC and then
/// stops reading — never opening its HTTP/2 receive window — leaves this send
/// pending forever. That would suspend the whole receive loop, and every
/// liveness and credential deadline in this module would stop being enforced by
/// an unrelated best-effort ACK. Timing out here converts that into an ordinary
/// bounded stream failure instead.
///
/// An already-observed or newly arriving generation/invalid/deadline event
/// outranks the send, including while the enqueue is blocked. Returning that
/// as a local retirement (not a transport failure) is what makes the next
/// stream discard accumulator/subscription/nonce state touched under the
/// retired credential. No task is detached; ACK/NACK ordering is preserved
/// because this waits on a single enqueue.
struct StockOutbound<'a> {
    tx: &'a mpsc::Sender<DiscoveryRequest>,
    bound: Duration,
    fence: &'a StockCredentialFence,
    credential_rx: &'a mut tokio::sync::watch::Receiver<StockCredentialObservation>,
}

impl StockOutbound<'_> {
    async fn enqueue(&mut self, request: DiscoveryRequest) -> Result<(), StockOutboundError> {
        send_request(
            self.tx,
            request,
            self.bound,
            self.fence,
            self.credential_rx,
            None,
        )
        .await
    }
}

enum StockOutboundError {
    Transport(&'static str),
    Retirement(MeshStreamRetirement),
}

impl StockOutboundError {
    fn into_stream_error(self) -> StockStreamError {
        match self {
            Self::Transport(reason) => StockStreamError::Transport(reason),
            Self::Retirement(reason) => StockStreamError::Retirement(reason),
        }
    }

    fn into_response_error(self) -> StockResponseError {
        match self {
            Self::Transport(reason) => StockResponseError::Transport(reason),
            Self::Retirement(reason) => StockResponseError::Retirement(reason),
        }
    }
}

/// Closed-set result of one credential-raced outbound enqueue. Exposed so
/// external tests can drive the production send path through a filled channel
/// without standing up a control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockOutboundAdmission {
    Sent,
    Closed,
    Timeout,
    Retired(MeshStreamRetirement),
}

async fn send_request(
    tx: &mpsc::Sender<DiscoveryRequest>,
    request: DiscoveryRequest,
    bound: Duration,
    fence: &StockCredentialFence,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
    parked: Option<&tokio::sync::watch::Sender<bool>>,
) -> Result<(), StockOutboundError> {
    // Already-observed retirement wins before any enqueue wait begins.
    if let Some(retirement) = fence.evaluate() {
        return Err(StockOutboundError::Retirement(retirement));
    }
    if let Some(parked) = parked {
        let _ = parked.send(true);
    }

    let deadline = fence.deadline;
    let deadline_sleep = tokio::time::sleep_until(
        deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60 * 60 * 24)),
    );
    tokio::pin!(deadline_sleep);
    let send = tokio::time::timeout(bound, tx.send(request));
    tokio::pin!(send);

    tokio::select! {
        biased;
        _ = &mut deadline_sleep, if deadline.is_some() => {
            Err(StockOutboundError::Retirement(
                MeshStreamRetirement::CredentialDeadline,
            ))
        }
        changed = credential_rx.changed() => {
            if changed.is_err() {
                // Watcher is gone (shutdown). Do not spin or mislabel that as
                // rotation; the absolute deadline and the outbound bound still
                // apply.
                tokio::select! {
                    biased;
                    _ = &mut deadline_sleep, if deadline.is_some() => {
                        Err(StockOutboundError::Retirement(
                            MeshStreamRetirement::CredentialDeadline,
                        ))
                    }
                    result = &mut send => map_send_result(result),
                }
            } else {
                Err(StockOutboundError::Retirement(
                    fence.retirement_from_observation(fence.latest()),
                ))
            }
        }
        result = &mut send => map_send_result(result),
    }
}

fn map_send_result(
    result: Result<
        Result<(), mpsc::error::SendError<DiscoveryRequest>>,
        tokio::time::error::Elapsed,
    >,
) -> Result<(), StockOutboundError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(StockOutboundError::Transport("request_stream_closed")),
        Err(_) => Err(StockOutboundError::Transport("request_enqueue_timeout")),
    }
}

/// Admit a serialized credential read onto the shared watch, or refuse it.
///
/// `Ok(generation)` is captured under the watch send lock for *this*
/// observation and is the only generation a connection fence may be bound to.
/// `Err` means a newer completed read already won; the caller must not dial or
/// open with the losing material. Retirement outcomes stay the existing
/// closed set: invalidation if the winner is unusable, rotation otherwise.
fn admit_stock_credential_observation(
    watch: &StockCredentialWatch,
    epoch: Option<StockCredentialReadEpoch>,
    state: StockCredentialState,
) -> Result<u64, MeshStreamRetirement> {
    match watch.admit_observation(epoch, state) {
        Ok(generation) => Ok(generation),
        Err(winning) => Err(if winning.is_invalid() {
            MeshStreamRetirement::CredentialSourceInvalid
        } else {
            MeshStreamRetirement::CredentialRotated
        }),
    }
}

/// Production reconnect admission: publish a serialized read, or refuse to
/// bind/open if a newer observation already won. Used by external tests to
/// prove an older credential cannot open a stream after a newer read.
pub fn admit_stock_credential_observation_for_test(
    watch: &StockCredentialWatch,
    epoch: Option<StockCredentialReadEpoch>,
    state: StockCredentialState,
) -> Result<u64, MeshStreamRetirement> {
    admit_stock_credential_observation(watch, epoch, state)
}

/// Drive the production credential-raced outbound enqueue with a caller-owned
/// channel, fence, and optional "parked" barrier. Used by external tests to
/// prove a blocked send cannot outrank rotation, invalidation, or deadline.
#[allow(clippy::too_many_arguments)]
pub async fn send_stock_outbound_racing_credential_for_test(
    tx: &mpsc::Sender<DiscoveryRequest>,
    request: DiscoveryRequest,
    bound: Duration,
    watch: &StockCredentialWatch,
    opened_generation: u64,
    deadline: Option<tokio::time::Instant>,
    configured: bool,
    credential_rx: &mut tokio::sync::watch::Receiver<StockCredentialObservation>,
    parked: Option<&tokio::sync::watch::Sender<bool>>,
) -> StockOutboundAdmission {
    let fence = StockCredentialFence::bind(watch, opened_generation, deadline, configured);
    match send_request(tx, request, bound, &fence, credential_rx, parked).await {
        Ok(()) => StockOutboundAdmission::Sent,
        Err(StockOutboundError::Transport("request_stream_closed")) => {
            StockOutboundAdmission::Closed
        }
        Err(StockOutboundError::Transport(_)) => StockOutboundAdmission::Timeout,
        Err(StockOutboundError::Retirement(retirement)) => {
            StockOutboundAdmission::Retired(retirement)
        }
    }
}

/// Run `commit` while the stock credential watch observation lock is held
/// after generation/deadline admission. A concurrent `publish` cannot become
/// visible until `commit` returns. There is no async gap.
pub fn run_under_stock_credential_commit_admission_for_test<R>(
    watch: &StockCredentialWatch,
    opened_generation: u64,
    deadline: Option<tokio::time::Instant>,
    configured: bool,
    commit: impl FnOnce() -> R,
) -> Result<R, MeshStreamRetirement> {
    let fence = StockCredentialFence::bind(watch, opened_generation, deadline, configured);
    let _admission = fence.admit_commit()?;
    Ok(commit())
}

/// Closed-set outcome of admitting one stock `DiscoveryResponse` through the
/// production handler. Used by external tests to capture log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockResponseAdmission {
    Acked,
    Nacked,
    Applied,
    Closed(&'static str),
}

/// Drive the production stock ADS response path (admit, ACK/NACK, apply) so
/// tests can capture tracing output without standing up a control plane.
pub struct StockAdsAdmissionProbe {
    accumulator: StockXdsAccumulator,
    stream_state: StockStreamState,
    last_logged_refusals: Option<Vec<StockRefusal>>,
    state: MeshRuntimeState,
}

impl Default for StockAdsAdmissionProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl StockAdsAdmissionProbe {
    pub fn new() -> Self {
        Self {
            accumulator: StockXdsAccumulator::default(),
            stream_state: StockStreamState::default(),
            last_logged_refusals: None,
            state: MeshRuntimeState::new(),
        }
    }

    pub fn accumulator(&self) -> &StockXdsAccumulator {
        &self.accumulator
    }

    pub async fn admit(
        &mut self,
        response: proto::DiscoveryResponse,
        config: &StockXdsClientConfig,
        baseline: &MeshConfig,
        request: &MeshSliceRequest,
    ) -> StockResponseAdmission {
        let watch = StockCredentialWatch::new(StockCredentialState::NotConfigured);
        let mut credential_rx = watch.receiver();
        let fence = StockCredentialFence::bind(&watch, watch.latest().generation, None, false);
        let (tx, mut rx) = mpsc::channel(32);
        let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
        // `StockOutbound` only borrows `tx`; ending that borrow by scope (not
        // `drop`) is what lets the sender close so the probe can drain.
        let result = {
            let mut outbound = StockOutbound {
                tx: &tx,
                bound: Duration::from_secs(5),
                fence: &fence,
                credential_rx: &mut credential_rx,
            };
            handle_stock_response(
                response,
                config,
                baseline,
                None,
                request,
                &mut outbound,
                &mut self.accumulator,
                &mut self.stream_state,
            )
            .await
        };
        drop(tx);
        while rx.try_recv().is_ok() {}
        match result {
            Ok(StockResponseOutcome::Acked) => StockResponseAdmission::Acked,
            Ok(StockResponseOutcome::Nacked) => StockResponseAdmission::Nacked,
            Ok(StockResponseOutcome::Pending(pending)) => {
                match apply_pending(
                    config,
                    &self.state,
                    pending,
                    &mut self.last_logged_refusals,
                    recovery.as_ref(),
                ) {
                    Ok(()) => StockResponseAdmission::Applied,
                    Err(reason) => StockResponseAdmission::Closed(reason),
                }
            }
            Err(StockResponseError::Policy(reason)) => StockResponseAdmission::Closed(reason),
            Err(StockResponseError::Transport(reason)) => StockResponseAdmission::Closed(reason),
            Err(StockResponseError::Retirement(_)) => StockResponseAdmission::Closed("retired"),
        }
    }
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
                    error = %crate::startup::sanitize_startup_cause(&e, &[]),
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
            file_path = %crate::startup::sanitize_startup_cause(format!("{path:?}"), &[]),
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
