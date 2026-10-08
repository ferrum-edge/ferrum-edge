//! Aggregate CP gRPC stream admission control (issues #3741 and #4432).
//!
//! The historical ADS guard bounded concurrent streams **per client-supplied
//! `Node.id`** only. A namespace-authorized client picks that string itself, so
//! cycling unique node ids reset the allowance and the CP's aggregate task /
//! channel / snapshot / broadcast-subscriber footprint stayed unbounded.
//!
//! This module owns CP configuration-stream admission as one fail-closed unit.
//! `ConfigSync.GetFullConfig` also holds a native permit through response-body
//! delivery and adds a bounded per-principal request rate. `ConfigSync.Subscribe`,
//! `MeshSubscribe`, and both ADS methods draw from the same controller:
//!
//! | Scope | Checked | Limit |
//! |-------|---------|-------|
//! | total active streams (process) | before response state or a filtered snapshot exists | `max_total_streams` |
//! | active streams per namespace/tenant | same reservation | `max_streams_per_namespace` |
//! | active streams per authenticated principal | same reservation | `max_streams_per_principal` |
//! | active streams per node state key | once the authenticated stream's node id is known | `max_streams_per_node` |
//! | distinct active node state keys | same registration | `max_active_nodes` |
//!
//! Precedence is deterministic and outermost-first: total → namespace →
//! principal → node streams → node cardinality. The first saturated scope
//! returns `RESOURCE_EXHAUSTED` and **nothing** is left reserved (a failed
//! inner scope rolls the outer reservations back before returning, so there is
//! no partial admission state).
//!
//! Reservation is transferred into an [`CpGrpcStreamPermit`] that releases exactly
//! once on drop, which covers normal completion, first-message errors, request
//! stream errors, receiver drop, client cancellation, forced task abort, and
//! process shutdown — a spawned task's locals are dropped on abort, so no path
//! needs its own release call.
//!
//! Both `StreamAggregatedResources` and `DeltaAggregatedResources` reserve from
//! the SAME controller instance, so a client cannot split a flood across the
//! two methods (or across connections) to double its budget.
//!
//! ## Identity aliasing
//!
//! `Node.id` is descriptive metadata, never an authorization decision. Every
//! mutable per-stream state key (snapshot cache, nonce tracker, workload
//! identity, waypoint name, node scoping, and the per-node stream quota) is
//! keyed by `namespace + full-width principal digest + node id`, so two
//! unrelated authenticated principals inside one namespace can never alias one
//! mutable xDS state key or consume each other's quota, even when they choose
//! the same `Node.id`.
//!
//! ## Cardinality and redaction
//!
//! Nothing here labels a metric or a log field with a raw `Node.id`, JWT
//! subject, SPIFFE URI, or token. The two digest domains are separate and are
//! never interchangeable: the principal is reduced to a full-width,
//! domain-separated SHA-256 digest ([`principal_key`]) before it is ever
//! stored — never truncated, because that digest is a state-key and quota
//! boundary — while log sites use the short, log-only [`redacted_identifier`]
//! for node ids. Rejection metrics carry only a compile-time
//! [`CpGrpcAdmissionRejection::metric_reason`] label.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::fips::approved::Sha256;

/// Closed metric/log dimension for the native stream handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpGrpcStreamSurface {
    ConfigSync,
    MeshSubscribe,
}

impl CpGrpcStreamSurface {
    fn warning_index(self) -> usize {
        match self {
            Self::ConfigSync => 0,
            Self::MeshSubscribe => 1,
        }
    }

    pub fn metric_label(self) -> &'static str {
        match self {
            Self::ConfigSync => "config_sync",
            Self::MeshSubscribe => "mesh_subscribe",
        }
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::ConfigSync => "ConfigSync.Subscribe",
            Self::MeshSubscribe => "MeshConfigSync.MeshSubscribe",
        }
    }
}

/// Default ceiling on total concurrent long-lived configuration streams.
///
/// **The sizing unit is one stream per DP *or per mesh workload*** (issue
/// #4531): every injected sidecar and every ambient node proxy holds one
/// `MeshSubscribe` stream, so this budget counts workloads, not control-plane
/// clients. It is deliberately *not* tied to the default CP gRPC connection
/// ceiling (`FERRUM_CP_GRPC_MAX_CONNECTIONS`), which bounds *connections*, not
/// streams: one HTTP/2 connection multiplexes up to
/// `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` (default 1000) concurrent
/// streams, so the transport budget does not bound stream occupancy. This is
/// the only aggregate CP configuration-stream bound.
pub const DEFAULT_CP_GRPC_MAX_TOTAL_STREAMS: usize = 8192;
/// Default ceiling on concurrent configuration streams for one
/// namespace/tenant. The unit is one stream per DP **or per mesh workload**, so
/// this is a workload count for a mesh-enabled namespace, not a tenant count.
pub const DEFAULT_CP_GRPC_MAX_STREAMS_PER_NAMESPACE: usize = 4096;
/// Default ceiling on concurrent configuration streams for one authenticated
/// principal (JWT `sub`). One stream per DP **or per mesh workload**, and every
/// workload sharing a ServiceAccount token presents the SAME principal, so this
/// must be sized against the fleet rather than against the tenant count. It
/// still bounds one compromised credential's aggregate footprint.
pub const DEFAULT_CP_GRPC_MAX_STREAMS_PER_PRINCIPAL: usize = 2048;
/// Default per-node concurrent configuration stream ceiling. A healthy DP or
/// mesh workload keeps a single stream; the small headroom tolerates brief
/// overlap during a client reconnect (old stream draining while the new one
/// establishes). Deliberately unchanged by the issue #4531 resizing: this one
/// is per node state key, not per fleet.
pub const DEFAULT_CP_GRPC_MAX_STREAMS_PER_NODE: usize = 4;
/// Default ceiling on distinct active node state keys. Bounds the node-scoped
/// maps (snapshot cache, nonce tracker, workload identity, waypoint, scoping).
///
/// A node state key exists only while at least one admitted stream holds it
/// (registered on that stream's first request, removed when its last stream
/// releases), so distinct active nodes can never exceed active streams. This
/// budget therefore only *binds* when it is set below
/// [`DEFAULT_CP_GRPC_MAX_TOTAL_STREAMS`] / `FERRUM_XDS_MAX_TOTAL_STREAMS`, or when
/// the total-stream budget is unbounded (`0`). At the shipped defaults
/// (`16384` > `8192`) it is a defense-in-depth ceiling that the total-stream
/// budget reaches first — deliberately, so tightening the node map bound is an
/// explicit operator choice rather than a surprise refusal on a large fleet.
///
/// The unit here is also one node state key per DP **or per mesh workload**.
/// Because the total-stream budget saturates first, the node-scoped maps hold
/// at most `DEFAULT_CP_GRPC_MAX_TOTAL_STREAMS` entries in practice, so raising
/// this ceiling does not raise the resident node-map footprint on its own.
pub const DEFAULT_CP_GRPC_MAX_ACTIVE_NODES: usize = 16384;
/// Default maximum `Node.id` length in UTF-8 bytes. 253 is the DNS name
/// ceiling, which covers every hostname / pod-identity shape Ferrum's own DP
/// produces.
pub const DEFAULT_CP_GRPC_MAX_NODE_ID_BYTES: usize = 253;
/// Default deadline for an admitted ADS stream to send its first request (and
/// therefore identify a node). Bounds a stalled stream that would otherwise
/// park a task, a channel, and a permit indefinitely.
pub const DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Width (hex characters) of a per-principal map/state key: the FULL SHA-256
/// digest.
///
/// Deliberately not truncated. A principal key is a security boundary — it
/// keys the per-principal stream quota and, through [`node_state_key`], the
/// mutable snapshot / nonce / workload-identity / waypoint / scoping state —
/// so a client that could find two subjects sharing a key could alias another
/// principal's mutable state and drain its quota. A 64-bit truncation is a
/// tractable collision target (~2^32 work by the birthday bound) for an
/// attacker who freely chooses its own JWT `sub`; the full 256-bit digest is
/// not.
const PRINCIPAL_KEY_DIGEST_LEN: usize = 64;

/// Length (hex characters) of the SHORT digest used ONLY as a redacted log
/// identifier.
///
/// Log correlation is not a security boundary: the digest exists so a log line
/// can correlate repeated occurrences of one client-supplied value without
/// echoing attacker-controlled bytes, and a short fixed width keeps the field
/// readable. This value is never used as a map key, a state key, or a metric
/// label. Do not reuse it for [`principal_key`].
const LOG_DIGEST_PREFIX_LEN: usize = 16;

/// Why an ADS stream was refused. Every variant is a compile-time constant, so
/// using [`Self::metric_reason`] as a metric label cannot grow the series at
/// runtime and never carries client-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpGrpcAdmissionRejection {
    /// The CP process is at its total concurrent ADS stream ceiling.
    TotalStreams,
    /// The stream's namespace/tenant is at its concurrent ADS stream ceiling.
    NamespaceStreams,
    /// The authenticated principal is at its concurrent ADS stream ceiling.
    PrincipalStreams,
    /// The resolved node state key is at its concurrent ADS stream ceiling.
    NodeStreams,
    /// Admitting this node would exceed the distinct-active-node ceiling.
    NodeCardinality,
    /// `Node.id` was absent or empty.
    NodeIdEmpty,
    /// `Node.id` exceeded the configured UTF-8 byte ceiling.
    NodeIdTooLong,
    /// `Node.id` contained control, whitespace, or non-ASCII-graphic bytes.
    NodeIdUnsafeCharacters,
    /// The stream was admitted but never sent a first request in time.
    FirstRequestTimeout,
    /// A principal requested unary full-config snapshots too frequently.
    FullConfigRateLimit,
}

/// Preserve known CP budget guidance, but never trust arbitrary peer status
/// text merely because the status code is RESOURCE_EXHAUSTED.
pub(crate) fn admission_status_diagnostic(status: &tonic::Status) -> String {
    for rejection in [
        CpGrpcAdmissionRejection::TotalStreams,
        CpGrpcAdmissionRejection::NamespaceStreams,
        CpGrpcAdmissionRejection::PrincipalStreams,
        CpGrpcAdmissionRejection::NodeStreams,
        CpGrpcAdmissionRejection::NodeCardinality,
    ] {
        let known = rejection.into_native_status();
        if status.message() == known.message() {
            return known.message().to_string();
        }
    }
    "CP gRPC stream admission refused (unrecognized details withheld)".to_string()
}

impl CpGrpcAdmissionRejection {
    fn warning_index(self) -> usize {
        match self {
            Self::TotalStreams => 0,
            Self::NamespaceStreams => 1,
            Self::PrincipalStreams => 2,
            Self::NodeStreams => 3,
            Self::NodeCardinality => 4,
            Self::NodeIdEmpty => 5,
            Self::NodeIdTooLong => 6,
            Self::NodeIdUnsafeCharacters => 7,
            Self::FirstRequestTimeout => 8,
            Self::FullConfigRateLimit => 9,
        }
    }

    /// Fixed-cardinality metric label. Never client-supplied.
    pub fn metric_reason(self) -> &'static str {
        match self {
            Self::TotalStreams => "total_streams",
            Self::NamespaceStreams => "namespace_streams",
            Self::PrincipalStreams => "principal_streams",
            Self::NodeStreams => "node_streams",
            Self::NodeCardinality => "node_cardinality",
            Self::NodeIdEmpty => "node_id_empty",
            Self::NodeIdTooLong => "node_id_too_long",
            Self::NodeIdUnsafeCharacters => "node_id_unsafe_characters",
            Self::FirstRequestTimeout => "first_request_timeout",
            Self::FullConfigRateLimit => "full_config_rate_limit",
        }
    }

    /// Outward gRPC message. Deliberately free of the offending `Node.id`,
    /// principal, namespace, or any other caller-supplied text so a rejection
    /// can never echo hostile input back onto a wire or a log line.
    pub fn status_message(self) -> &'static str {
        match self {
            Self::TotalStreams => {
                "xDS total concurrent ADS stream limit exceeded (FERRUM_XDS_MAX_TOTAL_STREAMS)"
            }
            Self::NamespaceStreams => {
                "xDS per-namespace concurrent ADS stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE)"
            }
            Self::PrincipalStreams => {
                "xDS per-principal concurrent ADS stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL)"
            }
            Self::NodeStreams => {
                "xDS per-node concurrent stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_NODE)"
            }
            Self::NodeCardinality => {
                "xDS active distinct node limit exceeded (FERRUM_XDS_MAX_ACTIVE_NODES)"
            }
            Self::NodeIdEmpty => "xDS Node.id is required",
            Self::NodeIdTooLong => {
                "xDS Node.id exceeds the maximum length (FERRUM_XDS_MAX_NODE_ID_BYTES)"
            }
            Self::NodeIdUnsafeCharacters => {
                "xDS Node.id must contain only printable ASCII characters"
            }
            Self::FirstRequestTimeout => {
                "xDS stream sent no first request before the initial-request deadline \
                 (FERRUM_XDS_FIRST_REQUEST_TIMEOUT_SECONDS)"
            }
            Self::FullConfigRateLimit => {
                "ConfigSync.GetFullConfig per-principal rate limit exceeded"
            }
        }
    }

    /// True when the rejection is a capacity refusal rather than a malformed
    /// request. Capacity refusals map to `RESOURCE_EXHAUSTED` so clients back
    /// off instead of treating the stream as permanently invalid.
    pub fn is_capacity(self) -> bool {
        matches!(
            self,
            Self::TotalStreams
                | Self::NamespaceStreams
                | Self::PrincipalStreams
                | Self::NodeStreams
                | Self::NodeCardinality
                | Self::FullConfigRateLimit
        )
    }

    /// Legacy ADS gRPC status for this rejection. Native callers use the same
    /// code but a surface-neutral message from their handler.
    pub fn into_status(self) -> tonic::Status {
        if self.is_capacity() {
            tonic::Status::resource_exhausted(self.status_message())
        } else if matches!(self, Self::FirstRequestTimeout) {
            tonic::Status::deadline_exceeded(self.status_message())
        } else {
            tonic::Status::invalid_argument(self.status_message())
        }
    }

    /// Surface-neutral status for native ConfigSync and MeshSubscribe.
    pub fn into_native_status(self) -> tonic::Status {
        let message = match self {
            Self::TotalStreams => {
                "CP gRPC total concurrent configuration stream limit exceeded \
                 (FERRUM_XDS_MAX_TOTAL_STREAMS)"
            }
            Self::NamespaceStreams => {
                "CP gRPC per-namespace concurrent configuration stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE)"
            }
            Self::PrincipalStreams => {
                "CP gRPC per-principal concurrent configuration stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL)"
            }
            Self::NodeStreams => {
                "CP gRPC per-node concurrent configuration stream limit exceeded \
                 (FERRUM_XDS_MAX_STREAMS_PER_NODE)"
            }
            Self::NodeCardinality => {
                "CP gRPC active distinct node limit exceeded \
                 (FERRUM_XDS_MAX_ACTIVE_NODES)"
            }
            Self::NodeIdEmpty => "CP gRPC stream node_id is required",
            Self::NodeIdTooLong => {
                "CP gRPC stream node_id exceeds the maximum length \
                 (FERRUM_XDS_MAX_NODE_ID_BYTES)"
            }
            Self::NodeIdUnsafeCharacters => {
                "CP gRPC stream node_id must contain only printable ASCII characters"
            }
            Self::FirstRequestTimeout => {
                "CP gRPC stream sent no first request before the initial-request deadline"
            }
            Self::FullConfigRateLimit => {
                "CP gRPC per-principal GetFullConfig request rate exceeded"
            }
        };
        if self.is_capacity() {
            tonic::Status::resource_exhausted(message)
        } else if matches!(self, Self::FirstRequestTimeout) {
            tonic::Status::deadline_exceeded(message)
        } else {
            tonic::Status::invalid_argument(message)
        }
    }
}

// The native refusal warning has fixed surface/reason buckets; metrics still
// count every rejection below.
static LAST_NATIVE_REJECTION_WARNED: [AtomicU64; 20] = [const { AtomicU64::new(0) }; 20];

/// Record a native admission refusal without accepting any caller-controlled
/// metric label or log field.
pub fn record_native_rejection(surface: CpGrpcStreamSurface, rejection: CpGrpcAdmissionRejection) {
    if let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let now = elapsed.as_secs();
        let bucket = surface.warning_index() * 10 + rejection.warning_index();
        let last = LAST_NATIVE_REJECTION_WARNED[bucket].load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 60
            && LAST_NATIVE_REJECTION_WARNED[bucket]
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                method = surface.method(),
                reason = rejection.metric_reason(),
                "Rejecting native CP gRPC configuration stream at admission"
            );
        }
    }
    crate::plugins::mesh::prometheus_helpers::increment_cp_grpc_stream_admission_rejection(
        surface.metric_label(),
        rejection.metric_reason(),
    );
}

/// Occupancy (percent of the configured ceiling) at which a budget layer starts
/// emitting the near-ceiling warning (issue #4531). Chosen so an operator sees
/// the signal with meaningful headroom left rather than at the first refusal.
pub const CP_GRPC_NEAR_CEILING_PERCENT: usize = 80;

/// Minimum interval between near-ceiling warnings for ONE budget layer. The
/// warning is a capacity-planning signal, not a per-stream event, so a fleet
/// reconnect storm must not turn it into a log flood.
const CP_GRPC_NEAR_CEILING_WARN_INTERVAL_MS: u64 = 60_000;

/// True when `current` occupancy has reached [`CP_GRPC_NEAR_CEILING_PERCENT`]
/// of `limit`. A `limit` of `0` is the documented "unbounded" posture and has
/// no ceiling to approach, so it never warns.
///
/// Uses saturating integer arithmetic rather than floating point so the
/// boundary is exact and cannot overflow on an operator-supplied ceiling.
pub fn cp_grpc_budget_is_near_ceiling(current: usize, limit: usize) -> bool {
    if limit == 0 {
        return false;
    }
    current.saturating_mul(100) >= limit.saturating_mul(CP_GRPC_NEAR_CEILING_PERCENT)
}

/// One admission budget layer, for the rate-limited near-ceiling warning.
///
/// Every field of the emitted warning is a compile-time constant or an integer
/// count: no namespace, principal, or node id ever reaches the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpGrpcBudgetLayer {
    TotalStreams,
    NamespaceStreams,
    PrincipalStreams,
    NodeStreams,
    NodeCardinality,
}

impl CpGrpcBudgetLayer {
    /// Dense index into the per-layer last-warned timestamps.
    const COUNT: usize = 5;

    fn index(self) -> usize {
        match self {
            Self::TotalStreams => 0,
            Self::NamespaceStreams => 1,
            Self::PrincipalStreams => 2,
            Self::NodeStreams => 3,
            Self::NodeCardinality => 4,
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::TotalStreams => "total_streams",
            Self::NamespaceStreams => "namespace_streams",
            Self::PrincipalStreams => "principal_streams",
            Self::NodeStreams => "node_streams",
            Self::NodeCardinality => "node_cardinality",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            Self::TotalStreams => "FERRUM_XDS_MAX_TOTAL_STREAMS",
            Self::NamespaceStreams => "FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE",
            Self::PrincipalStreams => "FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL",
            Self::NodeStreams => "FERRUM_XDS_MAX_STREAMS_PER_NODE",
            Self::NodeCardinality => "FERRUM_XDS_MAX_ACTIVE_NODES",
        }
    }
}

/// Operator-configured ADS admission budgets.
///
/// `0` means "unbounded" for every count and for
/// [`Self::first_request_timeout`]. `EnvConfig::validate()` refuses unbounded
/// values under `FERRUM_MESH_PRODUCTION_MODE=true` unless the operator sets the
/// visibly unsafe `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true` override, and
/// startup warns whenever any scope is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpGrpcAdmissionLimits {
    pub max_total_streams: usize,
    pub max_streams_per_namespace: usize,
    pub max_streams_per_principal: usize,
    pub max_streams_per_node: usize,
    pub max_active_nodes: usize,
    pub max_node_id_bytes: usize,
    pub first_request_timeout: Duration,
}

impl Default for CpGrpcAdmissionLimits {
    fn default() -> Self {
        Self {
            max_total_streams: DEFAULT_CP_GRPC_MAX_TOTAL_STREAMS,
            max_streams_per_namespace: DEFAULT_CP_GRPC_MAX_STREAMS_PER_NAMESPACE,
            max_streams_per_principal: DEFAULT_CP_GRPC_MAX_STREAMS_PER_PRINCIPAL,
            max_streams_per_node: DEFAULT_CP_GRPC_MAX_STREAMS_PER_NODE,
            max_active_nodes: DEFAULT_CP_GRPC_MAX_ACTIVE_NODES,
            max_node_id_bytes: DEFAULT_CP_GRPC_MAX_NODE_ID_BYTES,
            first_request_timeout: Duration::from_secs(DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS),
        }
    }
}

impl CpGrpcAdmissionLimits {
    /// True when any stream/node budget is configured as unbounded (`0`).
    // Exercised only from the external `tests/` crate (permit-release and
    // unbounded-posture assertions), so the `ferrum-edge` binary target
    // reports it as dead code.
    #[allow(dead_code)]
    pub fn has_unbounded_scope(&self) -> bool {
        self.max_total_streams == 0
            || self.max_streams_per_namespace == 0
            || self.max_streams_per_principal == 0
            || self.max_streams_per_node == 0
            || self.max_active_nodes == 0
            || self.max_node_id_bytes == 0
            || self.first_request_timeout.is_zero()
    }

    /// Names of the unbounded scopes, for a startup warning / validation error.
    /// Compile-time constants only.
    pub fn unbounded_scope_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.max_total_streams == 0 {
            names.push("FERRUM_XDS_MAX_TOTAL_STREAMS");
        }
        if self.max_streams_per_namespace == 0 {
            names.push("FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE");
        }
        if self.max_streams_per_principal == 0 {
            names.push("FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL");
        }
        if self.max_streams_per_node == 0 {
            names.push("FERRUM_XDS_MAX_STREAMS_PER_NODE");
        }
        if self.max_active_nodes == 0 {
            names.push("FERRUM_XDS_MAX_ACTIVE_NODES");
        }
        if self.max_node_id_bytes == 0 {
            names.push("FERRUM_XDS_MAX_NODE_ID_BYTES");
        }
        if self.first_request_timeout.is_zero() {
            names.push("FERRUM_XDS_FIRST_REQUEST_TIMEOUT_SECONDS");
        }
        names
    }
}

/// Shared CP configuration-stream admission accounting. One instance per CP
/// process, shared by ConfigSync, MeshSubscribe, SotW ADS, and Delta ADS.
///
/// Cloning shares the same accounting (an internal `Arc`), so every clone —
/// including the per-stream `XdsAdsServer` clone and both native servers —
/// draws from ONE budget.
#[derive(Debug, Clone)]
pub struct CpGrpcAdmissionController {
    inner: Arc<CpGrpcAdmissionState>,
}

#[derive(Debug)]
struct CpGrpcAdmissionState {
    limits: CpGrpcAdmissionLimits,
    total_streams: AtomicUsize,
    // Admission is outside the proxy hot path, so default DashMap sharding is
    // intentional. Every map is bounded: each entry needs at least one live
    // stream, and live streams are bounded by `max_total_streams`.
    per_namespace: DashMap<String, usize>,
    per_principal: DashMap<String, usize>,
    per_node: DashMap<String, usize>,
    active_nodes: AtomicUsize,
    /// Monotonic base for the near-ceiling warn rate limiter. No wall clock
    /// participates, so an NTP step cannot suppress or duplicate a warning.
    warn_epoch: Instant,
    /// Per-layer last-warned stamp, stored as `offset_ms + 1` so `0` means
    /// "never warned". Plain atomics: the reservation path takes no lock and
    /// allocates nothing for the common (not-near-ceiling) case.
    near_ceiling_warned_ms: [AtomicU64; CpGrpcBudgetLayer::COUNT],
    full_config_requests: Mutex<HashMap<String, HashMap<String, Instant>>>,
}

impl CpGrpcAdmissionController {
    pub fn new(limits: CpGrpcAdmissionLimits) -> Self {
        Self {
            inner: Arc::new(CpGrpcAdmissionState {
                limits,
                total_streams: AtomicUsize::new(0),
                per_namespace: DashMap::new(),
                per_principal: DashMap::new(),
                per_node: DashMap::new(),
                active_nodes: AtomicUsize::new(0),
                warn_epoch: Instant::now(),
                near_ceiling_warned_ms: std::array::from_fn(|_| AtomicU64::new(0)),
                full_config_requests: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn limits(&self) -> &CpGrpcAdmissionLimits {
        &self.inner.limits
    }

    /// Admit at most one unary full-config request per authenticated principal
    /// per second. Retained keys are bounded per namespace; lock poisoning fails closed.
    pub fn reserve_full_config_rate(
        &self,
        namespace: &str,
        subject: &str,
    ) -> Result<(), CpGrpcAdmissionRejection> {
        const WINDOW: Duration = Duration::from_secs(1);
        const RETENTION: Duration = Duration::from_secs(60);
        const MAX_KEYS_PER_NAMESPACE: usize = 4096;

        let key = authenticated_principal_key(namespace, subject);
        let now = Instant::now();
        let Ok(mut requests) = self.inner.full_config_requests.lock() else {
            return Err(CpGrpcAdmissionRejection::FullConfigRateLimit);
        };
        let namespace_requests = requests.entry(namespace.to_string()).or_default();
        if let Some(last) = namespace_requests.get_mut(&key) {
            if now.duration_since(*last) < WINDOW {
                return Err(CpGrpcAdmissionRejection::FullConfigRateLimit);
            }
            *last = now;
            return Ok(());
        }
        if namespace_requests.len() >= MAX_KEYS_PER_NAMESPACE {
            namespace_requests.retain(|_, last| now.duration_since(*last) < RETENTION);
            if namespace_requests.len() >= MAX_KEYS_PER_NAMESPACE {
                return Err(CpGrpcAdmissionRejection::FullConfigRateLimit);
            }
        }
        namespace_requests.insert(key, now);
        Ok(())
    }

    /// Current total active ADS streams (both methods).
    // Exercised only from the external `tests/` crate (permit-release and
    // unbounded-posture assertions), so the `ferrum-edge` binary target
    // reports it as dead code.
    #[allow(dead_code)]
    pub fn active_streams(&self) -> usize {
        self.inner.total_streams.load(Ordering::Acquire)
    }

    /// Current distinct active node state keys.
    // Exercised only from the external `tests/` crate (permit-release and
    // unbounded-posture assertions), so the `ferrum-edge` binary target
    // reports it as dead code.
    #[allow(dead_code)]
    pub fn active_nodes(&self) -> usize {
        self.inner.active_nodes.load(Ordering::Acquire)
    }

    /// Number of namespaces with at least one active stream.
    pub fn tracked_namespaces(&self) -> usize {
        self.inner.per_namespace.len()
    }

    /// Number of principals with at least one active stream.
    pub fn tracked_principals(&self) -> usize {
        self.inner.per_principal.len()
    }

    /// Active streams for one namespace.
    pub fn namespace_streams(&self, namespace: &str) -> usize {
        self.inner
            .per_namespace
            .get(namespace)
            .map(|entry| *entry.value())
            .unwrap_or(0)
    }

    /// Active streams for one principal key (see [`principal_key`]).
    pub fn principal_streams(&self, principal_key: &str) -> usize {
        self.inner
            .per_principal
            .get(principal_key)
            .map(|entry| *entry.value())
            .unwrap_or(0)
    }

    /// Active streams for one node state key.
    pub fn node_streams(&self, node_key: &str) -> usize {
        self.inner
            .per_node
            .get(node_key)
            .map(|entry| *entry.value())
            .unwrap_or(0)
    }

    /// Validate a client-supplied `Node.id` **before** it is cloned, stored in
    /// any map, used to build a state key, or reaches a log line.
    ///
    /// The length check runs before the character scan so a multi-megabyte id
    /// is refused without being walked. Length is measured in UTF-8 bytes, so
    /// the ceiling is an exact wire-size bound rather than a char count.
    pub fn validate_node_id(&self, node_id: &str) -> Result<(), CpGrpcAdmissionRejection> {
        validate_node_id(node_id, self.inner.limits.max_node_id_bytes)
    }

    /// Reserve total + namespace + principal capacity for one ADS stream.
    ///
    /// Callers MUST hold the returned permit for the whole stream lifetime and
    /// MUST call this before spawning the relay task, allocating the response
    /// channel, or building the per-stream filtered config snapshot.
    pub fn reserve_stream(
        &self,
        namespace: &str,
        principal_key: &str,
    ) -> Result<CpGrpcStreamPermit, CpGrpcAdmissionRejection> {
        let Some(total_after) = self.try_acquire_total() else {
            return Err(CpGrpcAdmissionRejection::TotalStreams);
        };
        let Some(namespace_after) = try_acquire_scope(
            &self.inner.per_namespace,
            namespace,
            self.inner.limits.max_streams_per_namespace,
        ) else {
            // Roll the outer reservation back so a refused stream leaves no
            // partial admission state behind.
            self.release_total();
            return Err(CpGrpcAdmissionRejection::NamespaceStreams);
        };
        let Some(principal_after) = try_acquire_scope(
            &self.inner.per_principal,
            principal_key,
            self.inner.limits.max_streams_per_principal,
        ) else {
            release_scope(&self.inner.per_namespace, namespace);
            self.release_total();
            return Err(CpGrpcAdmissionRejection::PrincipalStreams);
        };
        // Capacity planning signal: warn once per minute per layer while there
        // is still headroom, so a fleet that is growing into a budget is
        // visible before the first `RESOURCE_EXHAUSTED` refusal (issue #4531).
        self.warn_if_near_ceiling(
            CpGrpcBudgetLayer::TotalStreams,
            total_after,
            self.inner.limits.max_total_streams,
        );
        self.warn_if_near_ceiling(
            CpGrpcBudgetLayer::NamespaceStreams,
            namespace_after,
            self.inner.limits.max_streams_per_namespace,
        );
        self.warn_if_near_ceiling(
            CpGrpcBudgetLayer::PrincipalStreams,
            principal_after,
            self.inner.limits.max_streams_per_principal,
        );
        // Exact +1 tied to successful aggregate admission only — never a
        // load-then-store of live counters (that races under concurrent
        // reserve/release and can leave a stale exported gauge).
        crate::plugins::mesh::prometheus_helpers::adjust_cp_grpc_active_streams(1);
        Ok(CpGrpcStreamPermit {
            controller: self.clone(),
            namespace: namespace.to_string(),
            principal_key: principal_key.to_string(),
            node_key: None,
        })
    }

    /// Reserve every layer for a native ConfigSync or mesh RPC whose request
    /// already carries its node id. Streaming callers hold the permit for the
    /// stream; GetFullConfig transfers it to the encoded response body.
    ///
    /// Node validation precedes every clone or map insertion. Aggregate
    /// reservation and node registration both complete before the caller can
    /// subscribe to a broadcast channel, filter configuration, allocate its
    /// response stream, or insert a registry row. A node-scope refusal drops
    /// the provisional outer permit and rolls every outer counter back.
    pub fn reserve_native_stream(
        &self,
        namespace: &str,
        subject: &str,
        node_id: &str,
    ) -> Result<CpGrpcStreamPermit, CpGrpcAdmissionRejection> {
        self.validate_node_id(node_id)?;
        let principal = authenticated_principal_key(namespace, subject);
        let node_key = node_state_key(namespace, &principal, node_id);
        let mut permit = self.reserve_stream(namespace, &principal)?;
        permit.register_node(&node_key)?;
        Ok(permit)
    }

    /// Acquire one process-wide stream slot, returning total occupancy AFTER
    /// the acquisition, or `None` when the process budget is saturated.
    fn try_acquire_total(&self) -> Option<usize> {
        let max = self.inner.limits.max_total_streams;
        if max == 0 {
            return Some(self.inner.total_streams.fetch_add(1, Ordering::AcqRel) + 1);
        }
        self.inner
            .total_streams
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= max {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .ok()
            .map(|previous| previous + 1)
    }

    fn release_total(&self) {
        // `saturating_sub` semantics: never wrap below zero even if a future
        // caller double-releases.
        let _ =
            self.inner
                .total_streams
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(1))
                });
    }

    /// Register one stream against a node state key. Returns the per-node and
    /// distinct-node rejections; on `Err` nothing was registered, so no release
    /// is owed.
    fn register_node(&self, node_key: &str) -> Result<(), CpGrpcAdmissionRejection> {
        let max = self.inner.limits.max_streams_per_node;
        let node_streams_after;
        let cardinality_after;
        match self.inner.per_node.entry(node_key.to_string()) {
            Entry::Occupied(mut entry) => {
                if max != 0 && *entry.get() >= max {
                    return Err(CpGrpcAdmissionRejection::NodeStreams);
                }
                *entry.get_mut() += 1;
                node_streams_after = *entry.get();
                cardinality_after = None;
            }
            Entry::Vacant(entry) => {
                // A brand-new node consumes a distinct-node slot. The slot is
                // reserved while this shard's entry lock is held, so no other
                // thread can insert the same key concurrently and the counter
                // stays exact. Only an atomic is touched under the lock —
                // never `DashMap::len()`, which would take every shard lock.
                let Some(nodes_after) = self.try_acquire_node_slot() else {
                    return Err(CpGrpcAdmissionRejection::NodeCardinality);
                };
                entry.insert(1);
                node_streams_after = 1;
                cardinality_after = Some(nodes_after);
                // Exact +1 for a newly admitted distinct node key only.
                crate::plugins::mesh::prometheus_helpers::adjust_cp_grpc_active_node_ids(1);
            }
        }
        // Emitted after the entry lock is released: the warn path takes no
        // shard lock and must not extend the critical section.
        self.warn_if_near_ceiling(CpGrpcBudgetLayer::NodeStreams, node_streams_after, max);
        if let Some(nodes_after) = cardinality_after {
            self.warn_if_near_ceiling(
                CpGrpcBudgetLayer::NodeCardinality,
                nodes_after,
                self.inner.limits.max_active_nodes,
            );
        }
        Ok(())
    }

    /// Emit at most one near-ceiling warning per layer per
    /// [`CP_GRPC_NEAR_CEILING_WARN_INTERVAL_MS`] milliseconds.
    ///
    /// The common path is two relaxed atomic loads and no allocation: a layer
    /// below [`CP_GRPC_NEAR_CEILING_PERCENT`] returns before it reads the
    /// clock, and a layer that already warned recently returns before it
    /// formats anything.
    fn warn_if_near_ceiling(&self, layer: CpGrpcBudgetLayer, current: usize, limit: usize) {
        if !cp_grpc_budget_is_near_ceiling(current, limit) {
            return;
        }
        if !self.claim_near_ceiling_warn(layer) {
            return;
        }
        tracing::warn!(
            scope = layer.scope(),
            env_var = layer.env_var(),
            current,
            limit,
            "CP gRPC configuration-stream budget is near its ceiling; raise the named budget or \
             add CP replicas before subscriptions are refused with RESOURCE_EXHAUSTED. The sizing \
             unit is one stream per DP or per mesh workload"
        );
    }

    /// Rate-limit gate for one layer. Returns `true` for exactly one caller per
    /// interval: the CAS makes concurrent reservations agree on a single winner
    /// without a lock.
    fn claim_near_ceiling_warn(&self, layer: CpGrpcBudgetLayer) -> bool {
        let slot = &self.inner.near_ceiling_warned_ms[layer.index()];
        let last = slot.load(Ordering::Relaxed);
        // `offset_ms + 1`, so `0` is unambiguously "never warned".
        // Saturating rather than wrapping: a u64 of milliseconds is ~584
        // million years, so the clamp is unreachable and only keeps the stamp
        // monotonic in the impossible case.
        let now = u64::try_from(self.inner.warn_epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        if last != 0 && now.saturating_sub(last) < CP_GRPC_NEAR_CEILING_WARN_INTERVAL_MS {
            return false;
        }
        slot.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Acquire one distinct-node slot, returning node cardinality AFTER the
    /// acquisition, or `None` when the node-cardinality budget is saturated.
    fn try_acquire_node_slot(&self) -> Option<usize> {
        let max = self.inner.limits.max_active_nodes;
        if max == 0 {
            return Some(self.inner.active_nodes.fetch_add(1, Ordering::AcqRel) + 1);
        }
        self.inner
            .active_nodes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= max {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .ok()
            .map(|previous| previous + 1)
    }

    /// Release one stream from a node state key. When it is the last stream,
    /// run `cleanup` while the node entry is still exclusively occupied, then
    /// remove the entry and free its cardinality slot.
    ///
    /// Keeping cleanup inside the entry lock closes the last-stream/new-stream
    /// ABA window: a replacement stream for the same state key cannot register
    /// and publish fresh snapshot/identity/scoping state between removal of the
    /// old admission entry and cleanup of the old node-scoped maps.
    fn unregister_node_with_cleanup<F>(&self, node_key: &str, cleanup: F) -> bool
    where
        F: FnOnce(),
    {
        match self.inner.per_node.entry(node_key.to_string()) {
            Entry::Occupied(mut entry) => {
                if *entry.get() > 1 {
                    *entry.get_mut() -= 1;
                    false
                } else {
                    // Registration takes this same entry lock before it can
                    // publish any successor state. Clean the old state first,
                    // then make the key vacant for a new generation.
                    cleanup();
                    entry.remove();
                    let _ = self.inner.active_nodes.try_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |current| Some(current.saturating_sub(1)),
                    );
                    // Exact -1 tied to last-stream removal of this node key.
                    crate::plugins::mesh::prometheus_helpers::adjust_cp_grpc_active_node_ids(-1);
                    true
                }
            }
            // A missing entry is an invariant violation, not authorization to
            // delete state that may belong to a successor generation.
            Entry::Vacant(_) => false,
        }
    }

    fn release_stream(&self, namespace: &str, principal_key: &str) {
        release_scope(&self.inner.per_principal, principal_key);
        release_scope(&self.inner.per_namespace, namespace);
        self.release_total();
        // Exact -1 tied to the permit's exactly-once aggregate release.
        crate::plugins::mesh::prometheus_helpers::adjust_cp_grpc_active_streams(-1);
    }
}

/// Acquire one slot in a keyed scope, returning the scope's occupancy AFTER the
/// acquisition (so the caller can evaluate the near-ceiling boundary without a
/// second map lookup), or `None` when the scope is saturated.
fn try_acquire_scope(map: &DashMap<String, usize>, key: &str, max: usize) -> Option<usize> {
    match map.entry(key.to_string()) {
        Entry::Occupied(mut entry) => {
            if max != 0 && *entry.get() >= max {
                return None;
            }
            *entry.get_mut() += 1;
            Some(*entry.get())
        }
        // A first stream is always admitted, so a ceiling of 1 admits exactly
        // one concurrent stream.
        Entry::Vacant(entry) => {
            entry.insert(1);
            Some(1)
        }
    }
}

fn release_scope(map: &DashMap<String, usize>, key: &str) {
    if let Entry::Occupied(mut entry) = map.entry(key.to_string()) {
        if *entry.get() > 1 {
            *entry.get_mut() -= 1;
        } else {
            entry.remove();
        }
    }
}

/// Validate a client-supplied `Node.id`.
///
/// Accepts printable ASCII (`0x21..=0x7E`) only. That rejects the empty id,
/// every control character (including NUL, CR/LF log-injection bytes, and DEL),
/// all whitespace, and every non-ASCII form (bidi overrides, zero-width joiners,
/// homoglyphs) in one rule, while still admitting every hostname / pod identity
/// / Istio `~`-delimited node id shape.
///
/// `max_bytes == 0` disables the length ceiling (refused under production
/// posture by `EnvConfig::validate()`).
pub fn validate_node_id(node_id: &str, max_bytes: usize) -> Result<(), CpGrpcAdmissionRejection> {
    if node_id.is_empty() {
        return Err(CpGrpcAdmissionRejection::NodeIdEmpty);
    }
    if max_bytes != 0 && node_id.len() > max_bytes {
        return Err(CpGrpcAdmissionRejection::NodeIdTooLong);
    }
    if !node_id.as_bytes().iter().all(u8::is_ascii_graphic) {
        return Err(CpGrpcAdmissionRejection::NodeIdUnsafeCharacters);
    }
    Ok(())
}

/// Stable, non-reversible, FULL-WIDTH key for an authenticated principal
/// (JWT `sub`).
///
/// The raw subject is never stored in a map key, a state key, a log field, or a
/// metric label — only this digest is. The digest is domain-separated from
/// [`redacted_identifier`] and is NOT truncated (see
/// [`PRINCIPAL_KEY_DIGEST_LEN`]), so two authenticated principals cannot alias
/// one quota or one mutable state key even when one of them chooses its own
/// subject adversarially.
pub fn principal_key(subject: &str) -> String {
    domain_digest(b"xds-principal", subject, PRINCIPAL_KEY_DIGEST_LEN)
}

/// Stable key for a principal within its authenticated tenant namespace.
/// The same subject may be chosen independently by credentials in different
/// namespaces, so namespace is part of both the quota and mutable-state key.
pub fn authenticated_principal_key(namespace: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cp-principal");
    hasher.update([0xff]);
    hasher.update(namespace.len().to_be_bytes());
    hasher.update(namespace.as_bytes());
    hasher.update(subject.as_bytes());
    hex::encode(hasher.finalize())
}

/// Redacted, non-reversible stand-in for a client-supplied identifier
/// (`Node.id`) in log fields. Correlates repeated occurrences without echoing
/// attacker-controlled bytes into logs.
///
/// Log-only: this is a SHORT digest ([`LOG_DIGEST_PREFIX_LEN`]) in a different
/// hash domain from [`principal_key`], so a log identifier can never be
/// mistaken for — or reused as — a per-principal state key.
pub fn redacted_identifier(value: &str) -> String {
    domain_digest(b"xds-identifier", value, LOG_DIGEST_PREFIX_LEN)
}

/// Domain-separated SHA-256 of `value`, hex encoded and truncated to `len`
/// characters. The `0xff` separator cannot appear inside a UTF-8 `value`, so no
/// value can impersonate another domain's input.
fn domain_digest(domain: &[u8], value: &str, len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0xff]);
    hasher.update(value.as_bytes());
    let mut digest = hex::encode(hasher.finalize());
    // Hex is ASCII, so truncating is char-boundary safe; a `len` at or above
    // the full 64-character width is a no-op rather than a panic.
    digest.truncate(len);
    digest
}

/// Build the mutable per-stream state key.
///
/// Binds the namespace, the authenticated principal digest, and the
/// client-supplied `Node.id`. The namespace and principal segments are
/// length-prefixed so no combination of values can be forged into another
/// tenant's or principal's key by embedding a delimiter.
pub fn node_state_key(namespace: &str, principal_key: &str, node_id: &str) -> String {
    format!(
        "{}:{}{}:{}{}",
        namespace.len(),
        namespace,
        principal_key.len(),
        principal_key,
        node_id
    )
}

/// Capacity reservation for one ADS stream.
///
/// Releases total/namespace/principal capacity — and the node registration when
/// one was taken — exactly once on drop. Because the permit lives inside the
/// spawned relay task, an abort, panic, cancellation, client disconnect, or
/// process shutdown all drop it on the normal unwind path.
#[derive(Debug)]
pub struct CpGrpcStreamPermit {
    controller: CpGrpcAdmissionController,
    namespace: String,
    principal_key: String,
    node_key: Option<String>,
}

impl CpGrpcStreamPermit {
    /// Register this stream against a node state key (the innermost guard).
    ///
    /// On `Err` nothing was registered and the permit still holds only its
    /// aggregate reservation, so the caller owes no node release.
    pub fn register_node(&mut self, node_key: &str) -> Result<(), CpGrpcAdmissionRejection> {
        if self.node_key.as_deref() == Some(node_key) {
            return Ok(());
        }
        // A permit registers at most one node at a time; releasing first keeps
        // the accounting exact if a caller ever re-registers.
        let _ = self.release_node();
        self.controller.register_node(node_key)?;
        self.node_key = Some(node_key.to_string());
        Ok(())
    }

    /// Release the node registration, if any. Returns `true` when this was the
    /// node's last stream, i.e. the caller must clean node-scoped state.
    /// Idempotent: the key is taken, so a second call is a no-op returning
    /// `false`.
    pub fn release_node(&mut self) -> bool {
        self.release_node_with_cleanup(|| {})
    }

    /// Release this permit's node registration and, only when it owns the last
    /// stream for that state key, run `cleanup` before a successor generation
    /// can register the same key.
    pub(crate) fn release_node_with_cleanup<F>(&mut self, cleanup: F) -> bool
    where
        F: FnOnce(),
    {
        let Some(node_key) = self.node_key.as_deref() else {
            return false;
        };
        let last = self
            .controller
            .unregister_node_with_cleanup(node_key, cleanup);
        self.node_key = None;
        last
    }

    /// The permit's admission limits.
    pub fn limits(&self) -> &CpGrpcAdmissionLimits {
        self.controller.limits()
    }
}

impl Drop for CpGrpcStreamPermit {
    fn drop(&mut self) {
        // `release_node` takes the key, so an earlier explicit release is not
        // double-counted here.
        let _ = self.release_node();
        self.controller
            .release_stream(&self.namespace, &self.principal_key);
    }
}
