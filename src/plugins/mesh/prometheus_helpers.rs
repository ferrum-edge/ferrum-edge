//! Prometheus helpers for Istio/GAMMA-style mesh metrics.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::identity::ca::PublishedTrustBundle;
use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::metric_tag_cel::{
    MAX_METRIC_TAG_CEL_AST_NODES, MAX_METRIC_TAG_CEL_NESTING, MetricTagCelAttr,
    MetricTagCelContext, metadata_destination_port, metadata_request_host, metadata_request_method,
    sanitize_metric_tag_value, split_metric_tag_cel_plan,
};
use crate::plugins::StreamConnectionContext;
use crate::plugins::TransactionSummary;
use crate::plugins::prometheus_metrics::{HistogramBuckets, escape_label_value};

const MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS: u64 = 6 * 60 * 60;
const MESH_CERT_EXPIRY_EVICTION_INTERVAL_SECONDS: u64 = 60;

static MESH_CERT_EXPIRY_UNIX_SECONDS: LazyLock<DashMap<MeshCertExpiryKey, MeshCertExpiryGauge>> =
    LazyLock::new(DashMap::new);
static MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);
static MESH_CERT_ROTATION_FAILURES: LazyLock<DashMap<MeshCertRotationFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_CA_HEALTH: LazyLock<DashMap<MeshCaHealthKey, AtomicU64>> = LazyLock::new(DashMap::new);
static MESH_TRUST_BUNDLE_VERSIONS: LazyLock<
    DashMap<MeshTrustBundleVersionKey, TrustBundleVersionGauge>,
> = LazyLock::new(DashMap::new);
static MESH_CONFIG_LAST_RECEIVED: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_MTLS_HANDSHAKE_FAILURES: LazyLock<DashMap<MeshMtlsHandshakeFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_FEDERATION_POLL_FAILURES: LazyLock<DashMap<MeshFederationPollFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_FEDERATION_LAST_SUCCESS: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_REMOTE_DISCOVERY_POLL_FAILURES: LazyLock<
    DashMap<MeshRemoteDiscoveryPollFailureKey, AtomicU64>,
> = LazyLock::new(DashMap::new);
static MESH_REMOTE_DISCOVERY_POLL_SUCCESSES: LazyLock<
    DashMap<MeshRemoteDiscoveryPollSuccessKey, AtomicU64>,
> = LazyLock::new(DashMap::new);
static MESH_REMOTE_DISCOVERY_LAST_SUCCESS: LazyLock<
    DashMap<MeshRemoteDiscoveryPollSuccessKey, AtomicU64>,
> = LazyLock::new(DashMap::new);
static MESH_CONFIG_UPDATE_REJECTIONS: LazyLock<DashMap<MeshConfigUpdateRejectKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_CONFIG_REVISION_REJECTIONS: LazyLock<DashMap<&'static str, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_CONFIG_REVISION_ADOPTIONS: AtomicU64 = AtomicU64::new(0);
static MESH_SUBSCRIBE_AUDIENCE_REJECTIONS: LazyLock<
    DashMap<MeshSubscribeAudienceRejectKey, AtomicU64>,
> = LazyLock::new(DashMap::new);
static XDS_STREAMS_REJECTED: AtomicU64 = AtomicU64::new(0);
static MESH_INBOUND_PLAINTEXT_ALLOWED: AtomicU64 = AtomicU64::new(0);
static XDS_WARMING_PARTIAL_APPLIES: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static XDS_FIRST_SLICE_NACKS: LazyLock<DashMap<XdsFirstSliceNackKey, AtomicU64>> =
    LazyLock::new(DashMap::new);

/// Istio/GAMMA-style RED metric key for mesh HTTP-family requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshRequestKey {
    pub source_workload: Arc<str>,
    pub source_namespace: Arc<str>,
    pub source_principal: Arc<str>,
    pub source_app: Arc<str>,
    pub source_service: Arc<str>,
    pub destination_workload: Arc<str>,
    pub destination_namespace: Arc<str>,
    pub destination_principal: Arc<str>,
    pub destination_app: Arc<str>,
    pub destination_service: Arc<str>,
    pub request_protocol: Arc<str>,
    pub response_code: u16,
    response_code_override: Option<Arc<str>>,
    pub response_flags: Arc<str>,
    pub connection_security_policy: Arc<str>,
    /// Bitset of labels removed by a Telemetry metric tag override. The
    /// underlying values stay populated so ordered rename operations can copy a
    /// value before removing its source label.
    removed_labels: u16,
}

pub(crate) const MESH_METRICS_DISABLED_METADATA: &str = "mesh.metrics.disabled";
/// Stamped by the single enabled process-global `prometheus_metrics` plugin
/// when its request/stream hook actually observed this transaction.
///
/// Workload-metrics producers and body scanners require this marker before
/// updating the global registry. Mesh mode auto-injects `workload_metrics`, but
/// it deliberately does not auto-inject a Prometheus exporter; without this
/// gate, the opened half of a TCP lifecycle and gRPC body scanners would still
/// run in deployments where `/metrics` was otherwise plugin-gated silent.
pub const MESH_PROMETHEUS_METRICS_OBSERVED_METADATA: &str =
    "mesh.metrics.prometheus_metrics_observed";
/// Stamped by `workload_metrics::on_stream_connect` when that plugin actually
/// observed the stream. Stream-path lifecycle finalizers require this marker:
/// mesh routing/security setup may pre-populate other `mesh.*` metadata before
/// the plugin chain runs, and an earlier rejecting plugin must not create
/// workload-metric series that no workload-metrics instance observed.
///
/// The `mesh.metrics.` prefix also keeps this internal lifecycle signal out of
/// trace attributes.
pub const MESH_WORKLOAD_METRICS_OBSERVED_METADATA: &str = "mesh.metrics.workload_metrics_observed";
/// Stamped once per mesh TCP stream when `TCP_OPENED_CONNECTIONS` is finalized
/// under the metadata that path will also use for closed/byte series.
///
/// This is a connection-lifecycle marker, not an authorization-success flag:
/// every TCP stream path that reaches workload-metrics observation finalizes
/// exactly once after the last hook that actually ran (accepted chain, plugin
/// rejection, or client-disconnect-during-admission), before the disconnect
/// summary is emitted. Captured mesh egress TCP finalizes after selected
/// target metadata is stamped (or at teardown when no target was selected).
///
/// Ferrum allows several effective `workload_metrics` instances on one proxy,
/// so the plugin hook itself runs once per instance over intermediate metadata.
/// The opened counter therefore cannot be emitted from the hook: the marker is
/// what makes the TCP lifecycle counters exactly-once per connection under the
/// FINAL policy for that path. It also gates the closed/byte half so opened and
/// closed stay balanced.
///
/// The `mesh.metrics.` prefix keeps it out of `mesh_trace_attributes`, exactly
/// like the disable/tag-override plans.
pub const MESH_TCP_OPENED_FINALIZED_METADATA: &str = "mesh.metrics.tcp_opened_finalized";
pub(crate) const MESH_REQUEST_COUNT_OVERRIDES_METADATA: &str =
    "mesh.metrics.request_count.tag_overrides";
pub(crate) const MESH_REQUEST_DURATION_OVERRIDES_METADATA: &str =
    "mesh.metrics.request_duration.tag_overrides";
pub(crate) const MESH_REQUEST_SIZE_OVERRIDES_METADATA: &str =
    "mesh.metrics.request_size.tag_overrides";
pub(crate) const MESH_RESPONSE_SIZE_OVERRIDES_METADATA: &str =
    "mesh.metrics.response_size.tag_overrides";
pub(crate) const MESH_TCP_OPENED_OVERRIDES_METADATA: &str =
    "mesh.metrics.tcp_opened_connections.tag_overrides";
pub(crate) const MESH_TCP_CLOSED_OVERRIDES_METADATA: &str =
    "mesh.metrics.tcp_closed_connections.tag_overrides";
pub(crate) const MESH_TCP_SENT_OVERRIDES_METADATA: &str =
    "mesh.metrics.tcp_sent_bytes.tag_overrides";
pub(crate) const MESH_TCP_RECEIVED_OVERRIDES_METADATA: &str =
    "mesh.metrics.tcp_received_bytes.tag_overrides";
pub(crate) const MESH_GRPC_REQUEST_MESSAGES_OVERRIDES_METADATA: &str =
    "mesh.metrics.grpc_request_messages.tag_overrides";
pub(crate) const MESH_GRPC_RESPONSE_MESSAGES_OVERRIDES_METADATA: &str =
    "mesh.metrics.grpc_response_messages.tag_overrides";

/// Istio Telemetry metric families Ferrum emits with mesh identity labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum MeshMetricFamily {
    RequestCount,
    RequestDuration,
    RequestSize,
    ResponseSize,
    TcpOpenedConnections,
    TcpClosedConnections,
    TcpSentBytes,
    TcpReceivedBytes,
    GrpcRequestMessages,
    GrpcResponseMessages,
}

impl MeshMetricFamily {
    pub(crate) const ALL: [Self; 10] = [
        Self::RequestCount,
        Self::RequestDuration,
        Self::RequestSize,
        Self::ResponseSize,
        Self::TcpOpenedConnections,
        Self::TcpClosedConnections,
        Self::TcpSentBytes,
        Self::TcpReceivedBytes,
        Self::GrpcRequestMessages,
        Self::GrpcResponseMessages,
    ];

    pub(crate) fn from_config_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "REQUEST_COUNT" | "FERRUM_MESH_REQUESTS_TOTAL" => Some(Self::RequestCount),
            "REQUEST_DURATION" | "FERRUM_MESH_REQUEST_DURATION_MS" => Some(Self::RequestDuration),
            "REQUEST_SIZE" | "FERRUM_MESH_REQUEST_BYTES" => Some(Self::RequestSize),
            "RESPONSE_SIZE" | "FERRUM_MESH_RESPONSE_BYTES" => Some(Self::ResponseSize),
            "TCP_OPENED_CONNECTIONS" | "FERRUM_MESH_TCP_CONNECTIONS_OPENED_TOTAL" => {
                Some(Self::TcpOpenedConnections)
            }
            "TCP_CLOSED_CONNECTIONS" | "FERRUM_MESH_TCP_CONNECTIONS_CLOSED_TOTAL" => {
                Some(Self::TcpClosedConnections)
            }
            "TCP_SENT_BYTES" | "FERRUM_MESH_TCP_SENT_BYTES_TOTAL" => Some(Self::TcpSentBytes),
            "TCP_RECEIVED_BYTES" | "FERRUM_MESH_TCP_RECEIVED_BYTES_TOTAL" => {
                Some(Self::TcpReceivedBytes)
            }
            "GRPC_REQUEST_MESSAGES" | "FERRUM_MESH_REQUEST_MESSAGES_TOTAL" => {
                Some(Self::GrpcRequestMessages)
            }
            "GRPC_RESPONSE_MESSAGES" | "FERRUM_MESH_RESPONSE_MESSAGES_TOTAL" => {
                Some(Self::GrpcResponseMessages)
            }
            _ => None,
        }
    }

    pub(crate) fn override_metadata_key(self) -> &'static str {
        match self {
            Self::RequestCount => MESH_REQUEST_COUNT_OVERRIDES_METADATA,
            Self::RequestDuration => MESH_REQUEST_DURATION_OVERRIDES_METADATA,
            Self::RequestSize => MESH_REQUEST_SIZE_OVERRIDES_METADATA,
            Self::ResponseSize => MESH_RESPONSE_SIZE_OVERRIDES_METADATA,
            Self::TcpOpenedConnections => MESH_TCP_OPENED_OVERRIDES_METADATA,
            Self::TcpClosedConnections => MESH_TCP_CLOSED_OVERRIDES_METADATA,
            Self::TcpSentBytes => MESH_TCP_SENT_OVERRIDES_METADATA,
            Self::TcpReceivedBytes => MESH_TCP_RECEIVED_OVERRIDES_METADATA,
            Self::GrpcRequestMessages => MESH_GRPC_REQUEST_MESSAGES_OVERRIDES_METADATA,
            Self::GrpcResponseMessages => MESH_GRPC_RESPONSE_MESSAGES_OVERRIDES_METADATA,
        }
    }

    pub(crate) const fn disabled_name(self) -> &'static str {
        match self {
            Self::RequestCount => "request_count",
            Self::RequestDuration => "request_duration",
            Self::RequestSize => "request_size",
            Self::ResponseSize => "response_size",
            Self::TcpOpenedConnections => "tcp_opened_connections",
            Self::TcpClosedConnections => "tcp_closed_connections",
            Self::TcpSentBytes => "tcp_sent_bytes",
            Self::TcpReceivedBytes => "tcp_received_bytes",
            Self::GrpcRequestMessages => "grpc_request_messages",
            Self::GrpcResponseMessages => "grpc_response_messages",
        }
    }

    pub(crate) fn is_tcp(self) -> bool {
        matches!(
            self,
            Self::TcpOpenedConnections
                | Self::TcpClosedConnections
                | Self::TcpSentBytes
                | Self::TcpReceivedBytes
        )
    }

    /// Stable index into per-family live-series budget arrays. Must match
    /// [`Self::ALL`] order.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::RequestCount => 0,
            Self::RequestDuration => 1,
            Self::RequestSize => 2,
            Self::ResponseSize => 3,
            Self::TcpOpenedConnections => 4,
            Self::TcpClosedConnections => 5,
            Self::TcpSentBytes => 6,
            Self::TcpReceivedBytes => 7,
            Self::GrpcRequestMessages => 8,
            Self::GrpcResponseMessages => 9,
        }
    }

    /// Fixed Prometheus `family` label for dynamic-series overflow counters.
    pub(crate) const fn overflow_family_label(self) -> &'static str {
        self.disabled_name()
    }
}

/// Count complete gRPC length-prefixed messages in a contiguous byte buffer.
///
/// Incomplete trailing frames are ignored (authoritative completed-message
/// accounting). Does not allocate message payloads.
pub fn count_grpc_length_prefixed_messages(data: &[u8]) -> u64 {
    let mut pos = 0;
    let mut count = 0u64;
    while pos + 5 <= data.len() {
        let len = u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
            as usize;
        pos += 5;
        if pos.checked_add(len).is_none_or(|end| end > data.len()) {
            break;
        }
        pos += len;
        count = count.saturating_add(1);
    }
    count
}

/// Incremental scanner for gRPC length-prefixed messages spanning DATA frames.
#[derive(Debug, Default)]
pub struct GrpcLengthPrefixedScanner {
    header: [u8; 5],
    header_filled: u8,
    remaining: Option<u32>,
}

impl GrpcLengthPrefixedScanner {
    pub fn push(&mut self, mut data: &[u8], messages: &AtomicU64) {
        while !data.is_empty() {
            if let Some(left) = self.remaining {
                let take = (left as usize).min(data.len());
                data = &data[take..];
                let next = left.saturating_sub(take as u32);
                if next == 0 {
                    self.remaining = None;
                    messages.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.remaining = Some(next);
                }
                continue;
            }
            let need = 5usize.saturating_sub(self.header_filled as usize);
            let take = need.min(data.len());
            self.header[self.header_filled as usize..self.header_filled as usize + take]
                .copy_from_slice(&data[..take]);
            self.header_filled = self.header_filled.saturating_add(take as u8);
            data = &data[take..];
            if self.header_filled < 5 {
                return;
            }
            let len = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]);
            self.header_filled = 0;
            if len == 0 {
                messages.fetch_add(1, Ordering::Relaxed);
            } else {
                self.remaining = Some(len);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MeshMetricLabel {
    SourceWorkload = 0,
    SourceNamespace = 1,
    SourcePrincipal = 2,
    SourceApp = 3,
    SourceService = 4,
    DestinationWorkload = 5,
    DestinationNamespace = 6,
    DestinationPrincipal = 7,
    DestinationApp = 8,
    DestinationService = 9,
    RequestProtocol = 10,
    ResponseFlags = 11,
    ConnectionSecurityPolicy = 12,
    ResponseCode = 13,
}

impl MeshMetricLabel {
    pub(crate) fn from_config_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "mesh.source.workload" | "source_workload" => Some(Self::SourceWorkload),
            "mesh.source.namespace" | "source_namespace" | "source_workload_namespace" => {
                Some(Self::SourceNamespace)
            }
            "mesh.source.principal" | "source_principal" => Some(Self::SourcePrincipal),
            "mesh.source.app" | "source_app" => Some(Self::SourceApp),
            "mesh.source.service" | "source_service" | "source_canonical_service" => {
                Some(Self::SourceService)
            }
            "mesh.destination.workload" | "destination_workload" => Some(Self::DestinationWorkload),
            "mesh.destination.namespace"
            | "destination_namespace"
            | "destination_workload_namespace" => Some(Self::DestinationNamespace),
            "mesh.destination.principal" | "destination_principal" => {
                Some(Self::DestinationPrincipal)
            }
            "mesh.destination.app" | "destination_app" => Some(Self::DestinationApp),
            "mesh.destination.service"
            | "destination_service"
            | "destination_canonical_service" => Some(Self::DestinationService),
            "mesh.request_protocol" | "request_protocol" => Some(Self::RequestProtocol),
            "mesh.response_flags" | "response_flags" => Some(Self::ResponseFlags),
            "mesh.connection_security_policy" | "connection_security_policy" => {
                Some(Self::ConnectionSecurityPolicy)
            }
            "mesh.response_code" | "response_code" => Some(Self::ResponseCode),
            _ => None,
        }
    }

    pub(crate) const fn index(self) -> u8 {
        self as u8
    }

    fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::SourceWorkload),
            1 => Some(Self::SourceNamespace),
            2 => Some(Self::SourcePrincipal),
            3 => Some(Self::SourceApp),
            4 => Some(Self::SourceService),
            5 => Some(Self::DestinationWorkload),
            6 => Some(Self::DestinationNamespace),
            7 => Some(Self::DestinationPrincipal),
            8 => Some(Self::DestinationApp),
            9 => Some(Self::DestinationService),
            10 => Some(Self::RequestProtocol),
            11 => Some(Self::ResponseFlags),
            12 => Some(Self::ConnectionSecurityPolicy),
            13 => Some(Self::ResponseCode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCertExpiryKey {
    spiffe_id: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCertRotationFailureKey {
    spiffe_id: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCaHealthKey {
    ca_type: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshTrustBundleVersionKey {
    trust_domain: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshMtlsHandshakeFailureKey {
    reason: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshFederationPollFailureKey {
    trust_domain: Arc<str>,
    endpoint: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshRemoteDiscoveryPollFailureKey {
    cluster: Arc<str>,
    trust_domain: Arc<str>,
    control_plane: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshRemoteDiscoveryPollSuccessKey {
    cluster: Arc<str>,
    trust_domain: Arc<str>,
}

/// Key for the MeshSubscribe response-validation counter. Both fields are
/// `&'static str` values from closed enums in
/// `modes::mesh::config_consumer::update_validation`, so this series' label
/// space is fixed at compile time — no control-plane-supplied value ever
/// becomes a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MeshConfigUpdateRejectKey {
    consumer: &'static str,
    reason: &'static str,
}

/// Control-plane-side `MeshSubscribe` JWT audience rejections (issue #2475).
/// Both labels are `&'static str` from closed enums — the subscription class
/// (`remote_discovery` / `local`) and an `AudienceRejectReason` label — so the
/// series cardinality is fixed at compile time. No token, claim value, cluster
/// audience, or peer-supplied string ever becomes a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MeshSubscribeAudienceRejectKey {
    subscription: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct XdsFirstSliceNackKey {
    namespace: Arc<str>,
    type_url: Arc<str>,
}

struct MeshCertExpiryGauge {
    expires_at: AtomicU64,
    last_observed_at: AtomicU64,
}

impl MeshCertExpiryGauge {
    fn new(expires_at: u64, observed_at: u64) -> Self {
        Self {
            expires_at: AtomicU64::new(expires_at),
            last_observed_at: AtomicU64::new(observed_at),
        }
    }

    fn observe(&self, expires_at: u64, observed_at: u64) {
        self.expires_at.store(expires_at, Ordering::Relaxed);
        self.last_observed_at.store(observed_at, Ordering::Relaxed);
    }
}

struct TrustBundleVersionGauge {
    fingerprint: AtomicU64,
    version: AtomicU64,
}

impl TrustBundleVersionGauge {
    fn new(fingerprint: u64) -> Self {
        Self {
            fingerprint: AtomicU64::new(fingerprint),
            version: AtomicU64::new(1),
        }
    }

    fn observe(&self, fingerprint: u64) {
        let mut current = self.fingerprint.load(Ordering::Relaxed);
        while current != fingerprint {
            match self.fingerprint.compare_exchange_weak(
                current,
                fingerprint,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.version.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

pub fn record_mesh_cert_expiry_seconds(
    spiffe_id: impl AsRef<str>,
    source: impl AsRef<str>,
    seconds_until_expiry: u64,
) {
    let now = unix_now_seconds();
    record_mesh_cert_expiry_unix_seconds(
        spiffe_id,
        source,
        now.saturating_add(seconds_until_expiry),
        now,
    );
}

pub fn record_mesh_cert_expiry_at(
    spiffe_id: &SpiffeId,
    source: impl AsRef<str>,
    not_after: &DateTime<Utc>,
) {
    record_mesh_cert_expiry_unix_seconds(
        spiffe_id.as_str(),
        source,
        not_after.timestamp().max(0) as u64,
        unix_now_seconds(),
    );
}

fn record_mesh_cert_expiry_unix_seconds(
    spiffe_id: impl AsRef<str>,
    source: impl AsRef<str>,
    expires_at: u64,
    observed_at: u64,
) {
    let key = MeshCertExpiryKey {
        spiffe_id: Arc::from(spiffe_id.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_CERT_EXPIRY_UNIX_SECONDS
        .entry(key)
        .or_insert_with(|| MeshCertExpiryGauge::new(expires_at, observed_at))
        .observe(expires_at, observed_at);
}

pub fn increment_mesh_cert_rotation_failure(spiffe_id: impl AsRef<str>, source: impl AsRef<str>) {
    let key = MeshCertRotationFailureKey {
        spiffe_id: Arc::from(spiffe_id.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_CERT_ROTATION_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn set_mesh_ca_health(ca_type: impl AsRef<str>, healthy: bool) {
    let key = MeshCaHealthKey {
        ca_type: Arc::from(ca_type.as_ref()),
    };
    MESH_CA_HEALTH
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .store(u64::from(healthy), Ordering::Relaxed);
}

pub fn record_mesh_trust_bundle(bundle: &PublishedTrustBundle, source: impl AsRef<str>) {
    record_mesh_trust_bundle_roots(
        bundle.trust_domain.as_str(),
        source,
        bundle.roots_der.as_slice(),
    );
}

pub fn record_mesh_trust_bundle_roots(
    trust_domain: impl AsRef<str>,
    source: impl AsRef<str>,
    roots_der: &[Vec<u8>],
) {
    let fingerprint = trust_bundle_fingerprint(roots_der);
    let key = MeshTrustBundleVersionKey {
        trust_domain: Arc::from(trust_domain.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_TRUST_BUNDLE_VERSIONS
        .entry(key)
        .or_insert_with(|| TrustBundleVersionGauge::new(fingerprint))
        .observe(fingerprint);
}

/// Record the timestamp of the most recently installed mesh slice for `namespace`.
///
/// A mesh data-plane instance only ever installs slices for its own mesh
/// namespace, so the underlying map is effectively a single-element gauge —
/// the `retain` call deliberately evicts any stale namespace label that would
/// otherwise stick around forever in the `/metrics` output (for example after
/// `FERRUM_MESH_NAMESPACE` is reconfigured mid-process for testing). The map
/// shape is kept so the namespace label remains on the wire for alerting rules
/// that group by namespace; alerts must not rely on multiple namespace series
/// per gateway.
pub fn record_mesh_config_received(namespace: impl AsRef<str>) {
    let namespace = namespace.as_ref();
    MESH_CONFIG_LAST_RECEIVED.retain(|key, _| key.as_ref() == namespace);
    MESH_CONFIG_LAST_RECEIVED
        .entry(Arc::from(namespace))
        .or_insert_with(|| AtomicU64::new(0))
        .store(Utc::now().timestamp().max(0) as u64, Ordering::Relaxed);
}

pub fn increment_mesh_federation_poll_failure(
    trust_domain: impl AsRef<str>,
    _endpoint: impl AsRef<str>,
) {
    let key = MeshFederationPollFailureKey {
        trust_domain: Arc::from(trust_domain.as_ref()),
        // Federation URLs may carry credentials in userinfo, path, query, or
        // fragment components. Keep even authenticated observability output
        // free of those values by retaining only a fixed compatibility label.
        endpoint: Arc::from("redacted"),
    };
    MESH_FEDERATION_POLL_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_mesh_federation_poll_success(
    trust_domain: impl AsRef<str>,
    fetched_at_unix_seconds: u64,
) {
    MESH_FEDERATION_LAST_SUCCESS
        .entry(Arc::from(trust_domain.as_ref()))
        .or_insert_with(|| AtomicU64::new(0))
        .store(fetched_at_unix_seconds, Ordering::Relaxed);
}

/// Drop the federation last-success / bundle-age series once a polled bundle
/// is withdrawn. Failure counters are preserved, but the gauges must not keep
/// advertising a cached bundle after bounded staleness expires.
pub fn clear_mesh_federation_poll_success(trust_domain: impl AsRef<str>) {
    MESH_FEDERATION_LAST_SUCCESS.remove(trust_domain.as_ref());
}

pub fn increment_mesh_remote_discovery_poll_failure(
    cluster: impl AsRef<str>,
    trust_domain: impl AsRef<str>,
    control_plane: impl AsRef<str>,
) {
    let key = MeshRemoteDiscoveryPollFailureKey {
        cluster: Arc::from(cluster.as_ref()),
        trust_domain: Arc::from(trust_domain.as_ref()),
        control_plane: Arc::from(redact_control_plane_label(control_plane.as_ref())),
    };
    MESH_REMOTE_DISCOVERY_POLL_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Redact a control-plane URL before it becomes the `control_plane` metric
/// label.
///
/// `/metrics` is unauthenticated. Even a URL with userinfo/query/fragment
/// stripped can reveal remote control-plane topology through its host/port, and
/// deployments sometimes place bearer material in path segments. Keep the
/// legacy label key for metric compatibility, but store a fixed, non-sensitive
/// value so no URL component is rendered.
fn redact_control_plane_label(_control_plane: &str) -> &'static str {
    "redacted"
}

pub fn record_mesh_remote_discovery_poll_success(
    cluster: impl AsRef<str>,
    trust_domain: impl AsRef<str>,
    fetched_at_unix_seconds: u64,
) {
    let key = MeshRemoteDiscoveryPollSuccessKey {
        cluster: Arc::from(cluster.as_ref()),
        trust_domain: Arc::from(trust_domain.as_ref()),
    };
    MESH_REMOTE_DISCOVERY_POLL_SUCCESSES
        .entry(key.clone())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
    MESH_REMOTE_DISCOVERY_LAST_SUCCESS
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .store(fetched_at_unix_seconds, Ordering::Relaxed);
}

/// Drop the remote-discovery success / last-success / endpoint-age series for a
/// cluster once it is removed or becomes ineligible.
///
/// Removing a cluster from `RemoteEndpointStore` clears its cached endpoints but
/// leaves the success counter and the last-success gauge (plus the derived
/// `endpoint_age_seconds`) on the unauthenticated `/metrics` output, where they
/// would keep advertising a freshly-polled, endpoint-less cluster and could fire
/// stale alerts after a normal config/trust change. The success-counter and
/// last-success maps are keyed identically, so a single key prunes both.
pub fn clear_mesh_remote_discovery_metrics(
    cluster: impl AsRef<str>,
    trust_domain: impl AsRef<str>,
) {
    let key = MeshRemoteDiscoveryPollSuccessKey {
        cluster: Arc::from(cluster.as_ref()),
        trust_domain: Arc::from(trust_domain.as_ref()),
    };
    MESH_REMOTE_DISCOVERY_POLL_SUCCESSES.remove(&key);
    MESH_REMOTE_DISCOVERY_LAST_SUCCESS.remove(&key);
}

/// Withdraw only the remote-discovery **freshness gauges** (the last-success
/// timestamp, plus the derived `endpoint_age_seconds`) for a cluster whose
/// endpoints aged out of the bounded staleness window — while preserving the
/// monotonic poll-success counter.
///
/// Unlike [`clear_mesh_remote_discovery_metrics`] (used when a cluster is
/// removed/ineligible), staleness expiry is transient: the same poller stays
/// live and can reinstall endpoints later. Resetting
/// `ferrum_mesh_remote_discovery_poll_successes_total` to zero would corrupt
/// `rate()`/`increase()` with a counter reset and undercount successful polls.
/// Only the freshness gauges must stop advertising a cached, now-expired bundle.
pub fn withdraw_mesh_remote_discovery_freshness(
    cluster: impl AsRef<str>,
    trust_domain: impl AsRef<str>,
) {
    let key = MeshRemoteDiscoveryPollSuccessKey {
        cluster: Arc::from(cluster.as_ref()),
        trust_domain: Arc::from(trust_domain.as_ref()),
    };
    MESH_REMOTE_DISCOVERY_LAST_SUCCESS.remove(&key);
}

/// Count a `MeshConfigUpdate` a mesh config consumer refused before applying
/// it (issue #2457): a response that is not bound to the subscription that
/// opened the stream, carries an inconsistent version envelope, or fails the
/// CP compatibility contract.
///
/// `consumer` and `reason` are compile-time constants
/// (`MeshUpdateConsumer::as_metric_label` / `MeshUpdateRejectReason::as_metric_label`),
/// so the series' cardinality is fixed and no control-plane-supplied value can
/// reach `/metrics`. The mismatching values themselves stay in the structured
/// `warn!` diagnostic at the rejection site — security detail goes to logs, not
/// metrics.
pub fn increment_mesh_config_update_rejection(consumer: &'static str, reason: &'static str) {
    MESH_CONFIG_UPDATE_REJECTIONS
        .entry(MeshConfigUpdateRejectKey { consumer, reason })
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a mesh slice the DP freshness gate quarantined before replacing live
/// state (issue #2473): an older revision from the accepted authority, a
/// revision from a foreign ordering domain, or a slice carrying no usable
/// revision at all while a revisioned one is accepted.
///
/// `reason` is a compile-time constant
/// (`MeshRevisionRejectReason::as_metric_label`), so the series' cardinality is
/// fixed and no control-plane-supplied authority string or sequence number can
/// reach `/metrics`. Local-slice detail rides the JWT-authenticated
/// `GET /mesh/config-drift` `revision` block; local and remote-discovery gates
/// both emit sanitized, bounded structured warnings instead of dynamic labels.
pub fn increment_mesh_config_revision_rejection(reason: &'static str) {
    MESH_CONFIG_REVISION_REJECTIONS
        .entry(reason)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a control-plane-side `MeshSubscribe` JWT audience rejection
/// (issue #2475). `subscription` is `"remote_discovery"` or `"local"`;
/// `reason` is an `AudienceRejectReason` metric label. Both are compile-time
/// constants, so the series cannot grow at runtime and no credential metadata
/// reaches `/metrics` — the detail stays in the structured audit `warn!`.
pub fn increment_mesh_subscribe_audience_rejection(
    subscription: &'static str,
    reason: &'static str,
) {
    MESH_SUBSCRIBE_AUDIENCE_REJECTIONS
        .entry(MeshSubscribeAudienceRejectKey {
            subscription,
            reason,
        })
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a foreign config authority the DP adopted after the configured grace
/// period (`FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS`). Label-free on purpose:
/// the adopted authority is a CP-supplied string.
pub fn increment_mesh_config_revision_adoption() {
    MESH_CONFIG_REVISION_ADOPTIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_mesh_mtls_handshake_failure(reason: impl AsRef<str>) {
    let key = MeshMtlsHandshakeFailureKey {
        reason: Arc::from(reason.as_ref()),
    };
    MESH_MTLS_HANDSHAKE_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count an ADS stream the CP rejected because a node is already at its
/// per-node concurrent-stream ceiling (`FERRUM_XDS_MAX_STREAMS_PER_NODE`).
/// Aggregated (no per-node label) to avoid an unbounded, client-controlled
/// `node_id` metric dimension; the offending node id is still logged at `warn!`
/// at the reject site. Surfaces a DoS / misconfigured-client signal the plain
/// gRPC `RESOURCE_EXHAUSTED` status alone does not expose to scraping.
pub fn increment_xds_stream_rejected() {
    XDS_STREAMS_REJECTED.fetch_add(1, Ordering::Relaxed);
}

/// Set the coarse posture gauge for the mesh inbound listener's mTLS
/// enforcement: `true` when the listener was allowed to come up without
/// enforced mTLS (the dev opt-out posture of `decide_mesh_inbound_fail_closed`
/// — production mode refuses it instead), `false` when the resolved inbound
/// listener enforces mTLS. Deliberately label-free: the downgrade reason
/// (PeerAuthentication DISABLE vs no usable server identity) stays in the
/// `warn!` logs at the enforcement sites — security detail goes to logs, not
/// `/metrics`. Updated at startup enforcement and on *accepted*
/// PeerAuthentication live reloads (`apply_mesh_inbound_tls_reload`), never at
/// plan time, so a candidate slice the proxy rejects leaves the gauge at its
/// pre-reload value.
pub fn set_mesh_inbound_plaintext_allowed(allowed: bool) {
    MESH_INBOUND_PLAINTEXT_ALLOWED.store(u64::from(allowed), Ordering::Relaxed);
}

/// Count a NACK of a required mesh-slice type that occurred while the DP is
/// still waiting for its first slice. A persistently NACKing required type
/// wedges `wait_for_first_slice()` until the NACK circuit breaker trips, so a
/// non-zero, growing value here is the operator signal that startup
/// convergence is blocked by a malformed required resource.
pub fn increment_xds_first_slice_nack(namespace: impl AsRef<str>, type_url: impl AsRef<str>) {
    let key = XdsFirstSliceNackKey {
        namespace: Arc::from(namespace.as_ref()),
        type_url: Arc::from(type_url.as_ref()),
    };
    XDS_FIRST_SLICE_NACKS
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count any defensive mesh-slice apply that is explicitly marked as version
/// skewed. Normal xDS apply now requires coherent required-type versions before
/// installing a slice, so this counter should remain zero unless a future caller
/// deliberately opts into applying a skewed warmed slice. Keyed by `namespace` only
/// (matching `ferrum_xds_first_slice_nacks_total`) — low, operator-bounded
/// cardinality; the per-type version strings live behind JWT on
/// `/mesh/config-drift` because they embed config timestamps + content digests.
pub fn increment_xds_warming_partial_apply(namespace: impl AsRef<str>) {
    XDS_WARMING_PARTIAL_APPLIES
        .entry(Arc::from(namespace.as_ref()))
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Render process-static mesh families without a gateway namespace label.
/// Retained for diagnostics/tests that consume these helpers outside the
/// configured Prometheus plugin.
#[allow(dead_code)]
pub fn render_mesh_observability_metrics(output: &mut String) {
    render_mesh_observability_metrics_with_gateway_namespace(output, "");
}

/// Render process-static mesh families with the configured gateway namespace.
///
/// `gateway_ns_label` is either empty or a pre-escaped fragment beginning with
/// `,gateway_namespace=`. Mesh/resource families already use `namespace` for
/// their own identity, so the distinct key avoids duplicate Prometheus labels.
pub fn render_mesh_observability_metrics_with_gateway_namespace(
    output: &mut String,
    gateway_ns_label: &str,
) {
    let now = unix_now_seconds();
    maybe_evict_stale_mesh_cert_expiry_series(now);

    if !MESH_CERT_EXPIRY_UNIX_SECONDS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_cert_expiry_seconds Seconds until mesh X.509-SVID expiry.\n",
        );
        output.push_str("# TYPE ferrum_mesh_cert_expiry_seconds gauge\n");
        for entry in MESH_CERT_EXPIRY_UNIX_SECONDS.iter() {
            let seconds_until_expiry = entry
                .value()
                .expires_at
                .load(Ordering::Relaxed)
                .saturating_sub(now);
            output.push_str(&format!(
                "ferrum_mesh_cert_expiry_seconds{{spiffe_id=\"{}\",source=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().spiffe_id),
                escape_label_value(&entry.key().source),
                gateway_ns_label,
                seconds_until_expiry
            ));
        }
    }

    if !MESH_CERT_ROTATION_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_cert_rotation_failures_total Mesh certificate rotation failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_cert_rotation_failures_total counter\n");
        for entry in MESH_CERT_ROTATION_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_cert_rotation_failures_total{{spiffe_id=\"{}\",source=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().spiffe_id),
                escape_label_value(&entry.key().source),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_CA_HEALTH.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_ca_health Mesh CA backend health, 1 healthy and 0 unhealthy.\n",
        );
        output.push_str("# TYPE ferrum_mesh_ca_health gauge\n");
        for entry in MESH_CA_HEALTH.iter() {
            output.push_str(&format!(
                "ferrum_mesh_ca_health{{ca_type=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().ca_type),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_TRUST_BUNDLE_VERSIONS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_trust_bundle_version Monotonic version of observed mesh trust bundles.\n",
        );
        output.push_str("# TYPE ferrum_mesh_trust_bundle_version gauge\n");
        for entry in MESH_TRUST_BUNDLE_VERSIONS.iter() {
            output.push_str(&format!(
                "ferrum_mesh_trust_bundle_version{{trust_domain=\"{}\",source=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().trust_domain),
                escape_label_value(&entry.key().source),
                gateway_ns_label,
                entry.value().version.load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_CONFIG_LAST_RECEIVED.is_empty() {
        output.push_str("# HELP ferrum_mesh_config_last_received_timestamp_seconds Unix timestamp of the last installed mesh config slice.\n");
        output.push_str("# TYPE ferrum_mesh_config_last_received_timestamp_seconds gauge\n");
        for entry in MESH_CONFIG_LAST_RECEIVED.iter() {
            output.push_str(&format!(
                "ferrum_mesh_config_last_received_timestamp_seconds{{namespace=\"{}\"{}}} {}\n",
                escape_label_value(entry.key()),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_MTLS_HANDSHAKE_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_mtls_handshake_failures_total Frontend mesh TLS/mTLS handshake failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_mtls_handshake_failures_total counter\n");
        for entry in MESH_MTLS_HANDSHAKE_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_mtls_handshake_failures_total{{reason=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().reason),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_mesh_inbound_plaintext_allowed 1 when the mesh inbound listener was allowed to come up without enforced mTLS (dev opt-out posture; production mode refuses this). 0 otherwise.\n",
    );
    output.push_str("# TYPE ferrum_mesh_inbound_plaintext_allowed gauge\n");
    render_mesh_process_metric(
        output,
        "ferrum_mesh_inbound_plaintext_allowed",
        MESH_INBOUND_PLAINTEXT_ALLOWED.load(Ordering::Relaxed),
        gateway_ns_label,
    );

    if !MESH_CONFIG_UPDATE_REJECTIONS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_config_update_rejections_total MeshSubscribe responses refused before apply, by consumer and reason.\n",
        );
        output.push_str("# TYPE ferrum_mesh_config_update_rejections_total counter\n");
        for entry in MESH_CONFIG_UPDATE_REJECTIONS.iter() {
            output.push_str(&format!(
                "ferrum_mesh_config_update_rejections_total{{consumer=\"{}\",reason=\"{}\"{}}} {}\n",
                escape_label_value(entry.key().consumer),
                escape_label_value(entry.key().reason),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_CONFIG_REVISION_REJECTIONS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_config_revision_rejections_total Mesh slices quarantined by the config-revision freshness gate before replacing live state, by reason.\n",
        );
        output.push_str("# TYPE ferrum_mesh_config_revision_rejections_total counter\n");
        for entry in MESH_CONFIG_REVISION_REJECTIONS.iter() {
            output.push_str(&format!(
                "ferrum_mesh_config_revision_rejections_total{{reason=\"{}\"{}}} {}\n",
                escape_label_value(entry.key()),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_SUBSCRIBE_AUDIENCE_REJECTIONS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_subscribe_audience_rejections_total MeshSubscribe subscriptions refused by the control plane because the bearer JWT audience does not match the required subscription purpose, by subscription class and reason.\n",
        );
        output.push_str("# TYPE ferrum_mesh_subscribe_audience_rejections_total counter\n");
        for entry in MESH_SUBSCRIBE_AUDIENCE_REJECTIONS.iter() {
            output.push_str(&format!(
                "ferrum_mesh_subscribe_audience_rejections_total{{subscription=\"{}\",reason=\"{}\"{}}} {}\n",
                escape_label_value(entry.key().subscription),
                escape_label_value(entry.key().reason),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_mesh_config_revision_adoptions_total Foreign mesh config authorities adopted after the configured grace period.\n",
    );
    output.push_str("# TYPE ferrum_mesh_config_revision_adoptions_total counter\n");
    render_mesh_process_metric(
        output,
        "ferrum_mesh_config_revision_adoptions_total",
        MESH_CONFIG_REVISION_ADOPTIONS.load(Ordering::Relaxed),
        gateway_ns_label,
    );

    if !MESH_FEDERATION_POLL_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_federation_poll_failures_total SPIFFE federation trust-bundle poll failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_poll_failures_total counter\n");
        for entry in MESH_FEDERATION_POLL_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_federation_poll_failures_total{{trust_domain=\"{}\",endpoint=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().trust_domain),
                escape_label_value(&entry.key().endpoint),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_FEDERATION_LAST_SUCCESS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_federation_last_success_timestamp_seconds Unix timestamp of last successful SPIFFE federation poll.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_last_success_timestamp_seconds gauge\n");
        output.push_str(
            "# HELP ferrum_mesh_federation_bundle_age_seconds Age of the cached federated trust bundle, in seconds.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_bundle_age_seconds gauge\n");
        for entry in MESH_FEDERATION_LAST_SUCCESS.iter() {
            let last = entry.value().load(Ordering::Relaxed);
            let trust_domain = escape_label_value(entry.key());
            output.push_str(&format!(
                "ferrum_mesh_federation_last_success_timestamp_seconds{{trust_domain=\"{}\"{}}} {}\n",
                trust_domain, gateway_ns_label, last
            ));
            // Age clamps to 0 when the cached "last" timestamp is somehow in the
            // future (clock skew on a restart). Saturating subtraction keeps the
            // gauge non-negative for a Prometheus `gauge` type.
            let age = now.saturating_sub(last);
            output.push_str(&format!(
                "ferrum_mesh_federation_bundle_age_seconds{{trust_domain=\"{}\"{}}} {}\n",
                trust_domain, gateway_ns_label, age
            ));
        }
    }

    if !MESH_REMOTE_DISCOVERY_POLL_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_remote_discovery_poll_failures_total Remote-cluster endpoint discovery poll failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_remote_discovery_poll_failures_total counter\n");
        for entry in MESH_REMOTE_DISCOVERY_POLL_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_remote_discovery_poll_failures_total{{cluster=\"{}\",trust_domain=\"{}\",control_plane=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().cluster),
                escape_label_value(&entry.key().trust_domain),
                escape_label_value(&entry.key().control_plane),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_REMOTE_DISCOVERY_POLL_SUCCESSES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_remote_discovery_poll_successes_total Successful remote-cluster endpoint discovery polls.\n",
        );
        output.push_str("# TYPE ferrum_mesh_remote_discovery_poll_successes_total counter\n");
        for entry in MESH_REMOTE_DISCOVERY_POLL_SUCCESSES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_remote_discovery_poll_successes_total{{cluster=\"{}\",trust_domain=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().cluster),
                escape_label_value(&entry.key().trust_domain),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_REMOTE_DISCOVERY_LAST_SUCCESS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_remote_discovery_last_success_timestamp_seconds Unix timestamp of last successful remote-cluster endpoint discovery poll.\n",
        );
        output
            .push_str("# TYPE ferrum_mesh_remote_discovery_last_success_timestamp_seconds gauge\n");
        output.push_str(
            "# HELP ferrum_mesh_remote_discovery_endpoint_age_seconds Age of the cached remote-cluster endpoints, in seconds.\n",
        );
        output.push_str("# TYPE ferrum_mesh_remote_discovery_endpoint_age_seconds gauge\n");
        for entry in MESH_REMOTE_DISCOVERY_LAST_SUCCESS.iter() {
            let last = entry.value().load(Ordering::Relaxed);
            let cluster = escape_label_value(&entry.key().cluster);
            let trust_domain = escape_label_value(&entry.key().trust_domain);
            output.push_str(&format!(
                "ferrum_mesh_remote_discovery_last_success_timestamp_seconds{{cluster=\"{}\",trust_domain=\"{}\"{}}} {}\n",
                cluster, trust_domain, gateway_ns_label, last
            ));
            let age = now.saturating_sub(last);
            output.push_str(&format!(
                "ferrum_mesh_remote_discovery_endpoint_age_seconds{{cluster=\"{}\",trust_domain=\"{}\"{}}} {}\n",
                cluster, trust_domain, gateway_ns_label, age
            ));
        }
    }

    let xds_streams_rejected = XDS_STREAMS_REJECTED.load(Ordering::Relaxed);
    if xds_streams_rejected > 0 {
        output.push_str(
            "# HELP ferrum_xds_streams_rejected_total ADS streams rejected for exceeding the per-node concurrent-stream ceiling.\n",
        );
        output.push_str("# TYPE ferrum_xds_streams_rejected_total counter\n");
        render_mesh_process_metric(
            output,
            "ferrum_xds_streams_rejected_total",
            xds_streams_rejected,
            gateway_ns_label,
        );
    }

    if !XDS_WARMING_PARTIAL_APPLIES.is_empty() {
        output.push_str(
            "# HELP ferrum_xds_warming_partial_applies_total Mesh slices applied while marked as xDS required-version skewed. Normal coherent xDS apply should not increment this.\n",
        );
        output.push_str("# TYPE ferrum_xds_warming_partial_applies_total counter\n");
        for entry in XDS_WARMING_PARTIAL_APPLIES.iter() {
            output.push_str(&format!(
                "ferrum_xds_warming_partial_applies_total{{namespace=\"{}\"{}}} {}\n",
                escape_label_value(entry.key()),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !XDS_FIRST_SLICE_NACKS.is_empty() {
        output.push_str(
            "# HELP ferrum_xds_first_slice_nacks_total NACKs of a required mesh-slice type while the data plane is still waiting for its first slice.\n",
        );
        output.push_str("# TYPE ferrum_xds_first_slice_nacks_total counter\n");
        for entry in XDS_FIRST_SLICE_NACKS.iter() {
            output.push_str(&format!(
                "ferrum_xds_first_slice_nacks_total{{namespace=\"{}\",type_url=\"{}\"{}}} {}\n",
                escape_label_value(&entry.key().namespace),
                escape_label_value(&entry.key().type_url),
                gateway_ns_label,
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    crate::grpc::mesh_slice_drift::render_mesh_slice_drift_metrics(output, gateway_ns_label);
}

fn render_mesh_process_metric(
    output: &mut String,
    metric_name: &str,
    value: u64,
    gateway_ns_label: &str,
) {
    if gateway_ns_label.is_empty() {
        let _ = writeln!(output, "{metric_name} {value}");
    } else {
        let label_body = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        let _ = writeln!(output, "{metric_name}{{{label_body}}} {value}");
    }
}

fn unix_now_seconds() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn maybe_evict_stale_mesh_cert_expiry_series(now: u64) {
    let mut last = MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS.load(Ordering::Relaxed);
    loop {
        if last != 0 && now.saturating_sub(last) < MESH_CERT_EXPIRY_EVICTION_INTERVAL_SECONDS {
            return;
        }
        match MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS.compare_exchange_weak(
            last,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                evict_stale_mesh_cert_expiry_series(now);
                return;
            }
            Err(actual) => last = actual,
        }
    }
}

fn evict_stale_mesh_cert_expiry_series(now: u64) {
    let stale_keys: Vec<_> = MESH_CERT_EXPIRY_UNIX_SECONDS
        .iter()
        .filter_map(|entry| {
            let expires_at = entry.value().expires_at.load(Ordering::Relaxed);
            let last_observed_at = entry.value().last_observed_at.load(Ordering::Relaxed);
            mesh_cert_expiry_series_is_stale(expires_at, last_observed_at, now)
                .then(|| entry.key().clone())
        })
        .collect();
    for key in stale_keys {
        MESH_CERT_EXPIRY_UNIX_SECONDS.remove(&key);
    }
}

fn mesh_cert_expiry_series_is_stale(expires_at: u64, last_observed_at: u64, now: u64) -> bool {
    let stale_after = expires_at
        .max(last_observed_at)
        .saturating_add(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS);
    now >= stale_after
}

/// Build a `MeshRequestKey` from a transaction summary.
///
/// Hard cap on the number of distinct interned mesh-label values.
///
/// The legitimate mesh label space (workload / namespace / principal / app /
/// service / protocol / response-flags / security-policy) is small and
/// bounded, so this comfortably covers steady-state cardinality. Some label
/// values (e.g. workload / namespace) are attacker-influenceable in certain
/// topologies, so the pool is capped to stay a bounded memory cost rather than
/// an unbounded growth vector: once full it simply stops interning new values
/// and falls back to a per-call allocation (no worse than the prior behavior).
const MESH_LABEL_INTERN_CAP: usize = 4096;

/// Process-wide intern pool that turns repeated mesh-label `&str` values into a
/// shared `Arc<str>` so [`mesh_request_key`] can clone (atomic increment)
/// instead of heap-allocating a fresh `Arc` per field on every call.
static MESH_LABEL_INTERN: LazyLock<DashMap<Box<str>, Arc<str>>> =
    LazyLock::new(|| DashMap::with_shard_amount(super::observability_shard_amount()));
static MESH_LABEL_INTERN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Intern a mesh label value into a shared `Arc<str>`.
///
/// On the steady-state hot path (a previously-seen value) this is a single
/// hash lookup plus a cheap `Arc::clone`. A first-seen value allocates once and
/// is cached. Once the pool reaches [`MESH_LABEL_INTERN_CAP`] distinct values
/// it stops growing and falls back to a plain `Arc::from`, keeping memory
/// bounded under adversarial cardinality.
fn intern_label(value: &str) -> Arc<str> {
    if let Some(existing) = MESH_LABEL_INTERN.get(value) {
        return Arc::clone(existing.value());
    }
    if MESH_LABEL_INTERN_COUNT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MESH_LABEL_INTERN_CAP).then_some(count + 1)
        })
        .is_err()
    {
        return Arc::from(value);
    }

    match MESH_LABEL_INTERN.entry(Box::from(value)) {
        Entry::Occupied(entry) => {
            MESH_LABEL_INTERN_COUNT.fetch_sub(1, Ordering::Relaxed);
            Arc::clone(entry.get())
        }
        Entry::Vacant(entry) => {
            let interned = Arc::from(value);
            entry.insert(Arc::clone(&interned));
            interned
        }
    }
}

/// True when metadata carries mesh identity/routing keys rather than only the
/// reserved internal `mesh.metrics.*` coordination namespace.
fn metadata_has_mesh_identity_keys(metadata: &HashMap<String, String>) -> bool {
    metadata.keys().any(|key| {
        key.starts_with("mesh.")
            && !crate::plugins::utils::metadata_redaction::is_mesh_metrics_internal_metadata_key(
                key,
            )
    })
}

/// Build the RED/service-graph metric key for a mesh request.
///
/// Per-field label values are interned via [`intern_label`] so repeated label
/// values (the common case — a bounded set of workloads / namespaces /
/// protocols) become a hash lookup plus an `Arc` clone rather than ~11 fresh
/// heap allocations per call. This runs on the `log` phase (RED metrics,
/// service-graph aggregation, log shaping) and is gated off unless mesh
/// metrics / the service graph are enabled.
pub fn mesh_request_key(summary: &TransactionSummary) -> Option<MeshRequestKey> {
    if !metadata_has_mesh_identity_keys(&summary.metadata) {
        return None;
    }

    let source_workload = metadata_arc(&summary.metadata, "mesh.source.workload", "unknown");
    let source_namespace = metadata_arc(&summary.metadata, "mesh.source.namespace", "unknown");
    let source_principal = metadata_arc(&summary.metadata, "mesh.source.principal", "unknown");
    let source_app = metadata_arc_or_clone(&summary.metadata, "mesh.source.app", &source_workload);
    let source_service =
        metadata_arc_or_clone(&summary.metadata, "mesh.source.service", &source_workload);
    let destination_default = summary
        .proxy_name
        .as_deref()
        .or(summary.proxy_id.as_deref())
        .unwrap_or("unknown");
    let destination_workload = metadata_arc(
        &summary.metadata,
        "mesh.destination.workload",
        destination_default,
    );
    let destination_namespace =
        metadata_arc(&summary.metadata, "mesh.destination.namespace", "unknown");
    let destination_principal =
        metadata_arc(&summary.metadata, "mesh.destination.principal", "unknown");
    let destination_app = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.app",
        &destination_workload,
    );
    let destination_service = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.service",
        &destination_workload,
    );
    let request_protocol = metadata_arc_any(
        &summary.metadata,
        &["mesh.request_protocol", "request_protocol"],
        "http",
    );
    let response_flags = metadata_arc(
        &summary.metadata,
        "mesh.response_flags",
        inferred_response_flags(summary),
    );
    let connection_security_policy =
        metadata_arc(&summary.metadata, "mesh.connection_security_policy", "none");

    Some(MeshRequestKey {
        source_workload,
        source_namespace,
        source_principal,
        source_app,
        source_service,
        destination_workload,
        destination_namespace,
        destination_principal,
        destination_app,
        destination_service,
        request_protocol,
        response_code: summary.response_status_code,
        response_code_override: None,
        response_flags,
        connection_security_policy,
        removed_labels: 0,
    })
}

pub(crate) fn mesh_metric_disabled(summary: &TransactionSummary, family: MeshMetricFamily) -> bool {
    mesh_metric_disabled_metadata(&summary.metadata, family)
}

/// Apply the prevalidated, length-prefixed metric override plan emitted by
/// `workload_metrics` to a finalized mesh key. The compact plan is parsed in
/// place without JSON parsing, CEL text reparsing, or a lock on the request-log
/// path. Expression opcodes evaluate against the metric-phase attribute context.
pub(crate) fn mesh_request_key_for_family(
    summary: &TransactionSummary,
    base: &MeshRequestKey,
    family: MeshMetricFamily,
) -> MeshRequestKey {
    let Some(plan) = summary.metadata.get(family.override_metadata_key()) else {
        return base.clone();
    };
    let mut key = base.clone();
    let extras = MetricTagCelExtras {
        request_method: metadata_request_method(&summary.metadata)
            .or(Some(summary.http_method.as_str()).filter(|value| !value.is_empty())),
        request_host: metadata_request_host(&summary.metadata),
        response_code: Some(summary.response_status_code),
        destination_port: metadata_destination_port(&summary.metadata),
    };
    apply_metric_override_plan(&mut key, base, plan, extras);
    normalize_removed_labels(&mut key);
    key
}

/// Collapse every removed label onto one shared sentinel value so the derived
/// `Hash`/`Eq` no longer distinguishes keys by values that rendering omits.
/// Without this, traffic differing only on a removed label registers multiple
/// entries that render with an identical Prometheus label set, splitting one
/// logical series into duplicates. Runs after the full ordered plan so rename
/// operations can still copy a value before its source label is cleared.
fn normalize_removed_labels(key: &mut MeshRequestKey) {
    if key.removed_labels == 0 {
        return;
    }
    static REMOVED_LABEL_SENTINEL: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(""));
    for index in 0u8..=MeshMetricLabel::ResponseCode.index() {
        if key.removed_labels & (1u16 << index) == 0 {
            continue;
        }
        let Some(label) = MeshMetricLabel::from_index(index) else {
            continue;
        };
        set_metric_label_value(key, label, Arc::clone(&REMOVED_LABEL_SENTINEL));
    }
}

#[derive(Debug, Clone, Copy)]
struct MetricTagCelExtras<'a> {
    request_method: Option<&'a str>,
    request_host: Option<&'a str>,
    response_code: Option<u16>,
    destination_port: Option<u16>,
}

fn apply_metric_override_plan(
    key: &mut MeshRequestKey,
    attribution: &MeshRequestKey,
    plan: &str,
    extras: MetricTagCelExtras<'_>,
) {
    let Some((_, mut plan)) = split_metric_tag_cel_plan(plan) else {
        return;
    };
    while !plan.is_empty() {
        let Some(op) = plan.as_bytes().first().copied() else {
            return;
        };
        // Defensive: a hostile/corrupt plan may place a multibyte UTF-8 lead
        // byte where an ASCII opcode is expected. `str::get` fails closed
        // instead of panicking on a non-char-boundary index.
        let Some(rest) = plan.get(1..) else {
            return;
        };
        plan = rest;
        match op {
            b'r' => {
                let Some((index, rest)) = take_number_until(plan, b';') else {
                    return;
                };
                let Some(label) = u8::try_from(index)
                    .ok()
                    .and_then(MeshMetricLabel::from_index)
                else {
                    return;
                };
                key.removed_labels |= 1u16 << label.index();
                plan = rest;
            }
            b'n' => {
                let Some((from, after_from)) = take_number_until(plan, b',') else {
                    return;
                };
                let Some((to, rest)) = take_number_until(after_from, b';') else {
                    return;
                };
                let Some(from) = u8::try_from(from)
                    .ok()
                    .and_then(MeshMetricLabel::from_index)
                else {
                    return;
                };
                let Some(to) = u8::try_from(to).ok().and_then(MeshMetricLabel::from_index) else {
                    return;
                };
                if key.removed_labels & (1u16 << from.index()) == 0 {
                    let value = metric_label_value(key, from);
                    set_metric_label_value(key, to, value);
                    key.removed_labels &= !(1u16 << to.index());
                }
                key.removed_labels |= 1u16 << from.index();
                plan = rest;
            }
            b's' => {
                let Some((index, after_index)) = take_number_until(plan, b',') else {
                    return;
                };
                let Some((length, value_and_rest)) = take_number_until(after_index, b':') else {
                    return;
                };
                let Some(label) = u8::try_from(index)
                    .ok()
                    .and_then(MeshMetricLabel::from_index)
                else {
                    return;
                };
                let Some(value) = value_and_rest.get(..length) else {
                    return;
                };
                let Some(rest) = value_and_rest.get(length..) else {
                    return;
                };
                let Some(rest) = rest.strip_prefix(';') else {
                    return;
                };
                set_metric_label_value(key, label, intern_label(value));
                key.removed_labels &= !(1u16 << label.index());
                plan = rest;
            }
            b'x' => {
                let Some((index, after_index)) = take_number_until(plan, b',') else {
                    return;
                };
                let Some((length, body_and_rest)) = take_number_until(after_index, b':') else {
                    return;
                };
                let Some(label) = u8::try_from(index)
                    .ok()
                    .and_then(MeshMetricLabel::from_index)
                else {
                    return;
                };
                let Some(body) = body_and_rest.get(..length) else {
                    return;
                };
                let Some(rest) = body_and_rest.get(length..) else {
                    return;
                };
                let Some(rest) = rest.strip_prefix(';') else {
                    return;
                };
                let value = {
                    let visible = |label: MeshMetricLabel, value| {
                        (key.removed_labels & (1u16 << label.index()) == 0).then_some(value)
                    };
                    let live_ctx = MetricTagCelContext {
                        source_workload: visible(
                            MeshMetricLabel::SourceWorkload,
                            attribution.source_workload.as_ref(),
                        )
                        .unwrap_or(""),
                        source_namespace: visible(
                            MeshMetricLabel::SourceNamespace,
                            attribution.source_namespace.as_ref(),
                        )
                        .unwrap_or(""),
                        source_principal: visible(
                            MeshMetricLabel::SourcePrincipal,
                            attribution.source_principal.as_ref(),
                        )
                        .unwrap_or(""),
                        source_app: visible(
                            MeshMetricLabel::SourceApp,
                            attribution.source_app.as_ref(),
                        )
                        .unwrap_or(""),
                        source_service: visible(
                            MeshMetricLabel::SourceService,
                            attribution.source_service.as_ref(),
                        )
                        .unwrap_or(""),
                        destination_workload: visible(
                            MeshMetricLabel::DestinationWorkload,
                            attribution.destination_workload.as_ref(),
                        )
                        .unwrap_or(""),
                        destination_namespace: visible(
                            MeshMetricLabel::DestinationNamespace,
                            attribution.destination_namespace.as_ref(),
                        )
                        .unwrap_or(""),
                        destination_principal: visible(
                            MeshMetricLabel::DestinationPrincipal,
                            attribution.destination_principal.as_ref(),
                        )
                        .unwrap_or(""),
                        destination_app: visible(
                            MeshMetricLabel::DestinationApp,
                            attribution.destination_app.as_ref(),
                        )
                        .unwrap_or(""),
                        destination_service: visible(
                            MeshMetricLabel::DestinationService,
                            attribution.destination_service.as_ref(),
                        )
                        .unwrap_or(""),
                        request_protocol: visible(
                            MeshMetricLabel::RequestProtocol,
                            attribution.request_protocol.as_ref(),
                        )
                        .unwrap_or(""),
                        response_flags: visible(
                            MeshMetricLabel::ResponseFlags,
                            attribution.response_flags.as_ref(),
                        )
                        .unwrap_or(""),
                        connection_security_policy: visible(
                            MeshMetricLabel::ConnectionSecurityPolicy,
                            attribution.connection_security_policy.as_ref(),
                        )
                        .unwrap_or(""),
                        request_method: extras.request_method,
                        request_host: extras.request_host,
                        // HTTP/gRPC summaries stamp extras.response_code.
                        // Stream/TCP paths leave it None: TCP families reject
                        // HTTP-only `response.code` at admission, so there is
                        // no stream-side response-code evaluation path.
                        response_code: extras.response_code.filter(|_| {
                            key.removed_labels & (1u16 << MeshMetricLabel::ResponseCode.index())
                                == 0
                        }),
                        destination_port: extras.destination_port,
                    };
                    let Some(value) = evaluate_compact_metric_tag_cel(body, live_ctx) else {
                        return;
                    };
                    value
                };
                set_metric_label_value(key, label, intern_label(&value));
                key.removed_labels &= !(1u16 << label.index());
                plan = rest;
            }
            _ => return,
        }
    }
}

/// Validate and evaluate the reload-time compact CEL plan without rebuilding
/// its owned AST on every metric emission. The first bounded walk validates
/// the complete plan (including the unselected ternary branch); the second
/// evaluates only the selected branch and allocates only the final sanitized
/// label value.
fn evaluate_compact_metric_tag_cel(body: &str, ctx: MetricTagCelContext<'_>) -> Option<String> {
    if !compact_metric_tag_cel_is_valid(body) {
        return None;
    }
    let mut remaining = body;
    let value = evaluate_compact_metric_tag_cel_prefix(&mut remaining, ctx)?;
    remaining.is_empty().then_some(value)
}

fn compact_metric_tag_cel_is_valid(body: &str) -> bool {
    let mut nodes = 0usize;
    compact_metric_tag_cel_is_valid_at_depth(body, 0, &mut nodes)
}

fn compact_metric_tag_cel_is_valid_at_depth(body: &str, depth: usize, nodes: &mut usize) -> bool {
    let mut remaining = body;
    skip_compact_metric_tag_cel_prefix(&mut remaining, depth, nodes).is_some()
        && remaining.is_empty()
}

fn skip_compact_metric_tag_cel_prefix(
    body: &mut &str,
    depth: usize,
    nodes: &mut usize,
) -> Option<()> {
    if depth > MAX_METRIC_TAG_CEL_NESTING || *nodes >= MAX_METRIC_TAG_CEL_AST_NODES {
        return None;
    }
    *nodes += 1;
    let op = body.as_bytes().first().copied()?;
    // Fail closed on non-char-boundary indexes (malformed multibyte lead byte).
    *body = body.get(1..)?;
    match op {
        b'L' => {
            let (length, rest) = take_number_until(body, b':')?;
            rest.get(..length)?;
            *body = rest.get(length..)?;
            Some(())
        }
        b'A' | b'I' => {
            let (id, rest) = take_number_end(body)?;
            MetricTagCelAttr::from_plan_id(u8::try_from(id).ok()?)?;
            *body = rest;
            Some(())
        }
        b'H' => {
            let (id, after_id) = take_number_until(body, b',')?;
            MetricTagCelAttr::from_plan_id(u8::try_from(id).ok()?)?;
            let (then_len, after_then_len) = take_number_until(after_id, b':')?;
            let then_body = after_then_len.get(..then_len)?;
            let after_then = after_then_len.get(then_len..)?;
            let (else_len, after_else_len) = take_number_until(after_then, b':')?;
            let else_body = after_else_len.get(..else_len)?;
            let after_else = after_else_len.get(else_len..)?;
            *body = after_else;
            compact_metric_tag_cel_is_valid_at_depth(then_body, depth + 1, nodes)
                .then_some(())
                .filter(|()| compact_metric_tag_cel_is_valid_at_depth(else_body, depth + 1, nodes))
        }
        _ => None,
    }
}

fn evaluate_compact_metric_tag_cel_prefix(
    body: &mut &str,
    ctx: MetricTagCelContext<'_>,
) -> Option<String> {
    let op = body.as_bytes().first().copied()?;
    // Fail closed on non-char-boundary indexes (malformed multibyte lead byte).
    *body = body.get(1..)?;
    match op {
        b'L' => {
            let (length, rest) = take_number_until(body, b':')?;
            let value = sanitize_metric_tag_value(rest.get(..length)?);
            *body = rest.get(length..)?;
            Some(value)
        }
        b'A' => {
            let (id, rest) = take_number_end(body)?;
            let attribute = MetricTagCelAttr::from_plan_id(u8::try_from(id).ok()?)?;
            *body = rest;
            Some(sanitize_metric_tag_value(
                ctx.string_attr(attribute).unwrap_or(""),
            ))
        }
        b'I' => {
            let (id, rest) = take_number_end(body)?;
            let attribute = MetricTagCelAttr::from_plan_id(u8::try_from(id).ok()?)?;
            *body = rest;
            Some(
                ctx.int_attr(attribute)
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            )
        }
        b'H' => {
            let (id, after_id) = take_number_until(body, b',')?;
            let attribute = MetricTagCelAttr::from_plan_id(u8::try_from(id).ok()?)?;
            let (then_len, after_then_len) = take_number_until(after_id, b':')?;
            let then_body = after_then_len.get(..then_len)?;
            let after_then = after_then_len.get(then_len..)?;
            let (else_len, after_else_len) = take_number_until(after_then, b':')?;
            let else_body = after_else_len.get(..else_len)?;
            *body = after_else_len.get(else_len..)?;
            let mut selected = if ctx.string_attr(attribute).is_some() {
                then_body
            } else {
                else_body
            };
            let value = evaluate_compact_metric_tag_cel_prefix(&mut selected, ctx)?;
            selected.is_empty().then_some(value)
        }
        _ => None,
    }
}

fn take_number_end(value: &str) -> Option<(usize, &str)> {
    let mut end = 0usize;
    for (idx, byte) in value.as_bytes().iter().enumerate() {
        if byte.is_ascii_digit() {
            end = idx + 1;
            continue;
        }
        break;
    }
    if end == 0 {
        return None;
    }
    let number = value.get(..end)?.parse::<usize>().ok()?;
    Some((number, value.get(end..)?))
}

fn take_number_until(value: &str, delimiter: u8) -> Option<(usize, &str)> {
    let delimiter_index = value
        .as_bytes()
        .iter()
        .position(|byte| *byte == delimiter)?;
    let number = value.get(..delimiter_index)?.parse::<usize>().ok()?;
    Some((number, value.get(delimiter_index + 1..)?))
}

fn metric_label_value(key: &MeshRequestKey, label: MeshMetricLabel) -> Arc<str> {
    match label {
        MeshMetricLabel::SourceWorkload => Arc::clone(&key.source_workload),
        MeshMetricLabel::SourceNamespace => Arc::clone(&key.source_namespace),
        MeshMetricLabel::SourcePrincipal => Arc::clone(&key.source_principal),
        MeshMetricLabel::SourceApp => Arc::clone(&key.source_app),
        MeshMetricLabel::SourceService => Arc::clone(&key.source_service),
        MeshMetricLabel::DestinationWorkload => Arc::clone(&key.destination_workload),
        MeshMetricLabel::DestinationNamespace => Arc::clone(&key.destination_namespace),
        MeshMetricLabel::DestinationPrincipal => Arc::clone(&key.destination_principal),
        MeshMetricLabel::DestinationApp => Arc::clone(&key.destination_app),
        MeshMetricLabel::DestinationService => Arc::clone(&key.destination_service),
        MeshMetricLabel::RequestProtocol => Arc::clone(&key.request_protocol),
        MeshMetricLabel::ResponseFlags => Arc::clone(&key.response_flags),
        MeshMetricLabel::ConnectionSecurityPolicy => Arc::clone(&key.connection_security_policy),
        MeshMetricLabel::ResponseCode => key
            .response_code_override
            .as_ref()
            .map_or_else(|| intern_label(&key.response_code.to_string()), Arc::clone),
    }
}

fn set_metric_label_value(key: &mut MeshRequestKey, label: MeshMetricLabel, value: Arc<str>) {
    match label {
        MeshMetricLabel::SourceWorkload => key.source_workload = value,
        MeshMetricLabel::SourceNamespace => key.source_namespace = value,
        MeshMetricLabel::SourcePrincipal => key.source_principal = value,
        MeshMetricLabel::SourceApp => key.source_app = value,
        MeshMetricLabel::SourceService => key.source_service = value,
        MeshMetricLabel::DestinationWorkload => key.destination_workload = value,
        MeshMetricLabel::DestinationNamespace => key.destination_namespace = value,
        MeshMetricLabel::DestinationPrincipal => key.destination_principal = value,
        MeshMetricLabel::DestinationApp => key.destination_app = value,
        MeshMetricLabel::DestinationService => key.destination_service = value,
        MeshMetricLabel::RequestProtocol => key.request_protocol = value,
        MeshMetricLabel::ResponseFlags => key.response_flags = value,
        MeshMetricLabel::ConnectionSecurityPolicy => key.connection_security_policy = value,
        MeshMetricLabel::ResponseCode => {
            key.response_code = 0;
            key.response_code_override = Some(value);
        }
    }
}

fn metadata_arc(metadata: &HashMap<String, String>, key: &str, default: &str) -> Arc<str> {
    intern_label(metadata.get(key).map(String::as_str).unwrap_or(default))
}

fn trust_bundle_fingerprint(roots_der: &[Vec<u8>]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for root in roots_der {
        hash ^= root.len() as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        for byte in root {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

fn metadata_arc_any(metadata: &HashMap<String, String>, keys: &[&str], default: &str) -> Arc<str> {
    intern_label(
        keys.iter()
            .find_map(|key| metadata.get(*key).map(String::as_str))
            .unwrap_or(default),
    )
}

fn metadata_arc_or_clone(
    metadata: &HashMap<String, String>,
    key: &str,
    default: &Arc<str>,
) -> Arc<str> {
    metadata
        .get(key)
        .map(|value| intern_label(value.as_str()))
        .unwrap_or_else(|| Arc::clone(default))
}

fn inferred_response_flags(summary: &TransactionSummary) -> &'static str {
    if summary.client_disconnected {
        "DC"
    } else if summary.error_class.is_some() || summary.body_error_class.is_some() {
        "UF"
    } else {
        "-"
    }
}

pub fn render_mesh_histogram(
    output: &mut String,
    key: &MeshRequestKey,
    histogram: &HistogramBuckets,
    gateway_ns_label: &str,
) {
    render_mesh_histogram_named(
        output,
        "ferrum_mesh_request_duration_ms",
        key,
        histogram,
        gateway_ns_label,
    );
}

pub fn render_mesh_histogram_named(
    output: &mut String,
    metric_name: &str,
    key: &MeshRequestKey,
    histogram: &HistogramBuckets,
    gateway_ns_label: &str,
) {
    let base_labels = mesh_label_base_fragment(key);
    let le_separator = if base_labels.is_empty() { "" } else { "," };
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        let _ = writeln!(
            output,
            "{metric_name}_bucket{{{}{le_separator}le=\"{}\"{}}} {}",
            base_labels, boundary, gateway_ns_label, count
        );
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let _ = writeln!(
        output,
        "{metric_name}_bucket{{{}{le_separator}le=\"+Inf\"{}}} {}",
        base_labels, gateway_ns_label, total_count
    );
    let aggregate_gateway_ns_label = if base_labels.is_empty() {
        gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label)
    } else {
        gateway_ns_label
    };
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    let _ = writeln!(
        output,
        "{metric_name}_sum{{{}{}}} {:.2}",
        base_labels, aggregate_gateway_ns_label, sum
    );
    let _ = writeln!(
        output,
        "{metric_name}_count{{{}{}}} {}",
        base_labels, aggregate_gateway_ns_label, total_count
    );
}

/// Build a mesh identity key from stream metadata (TCP/UDP connect or disconnect).
///
/// TCP families omit `response_code` from the rendered label set (Istio parity).
pub fn mesh_stream_key_from_metadata(
    metadata: &HashMap<String, String>,
    proxy_id: &str,
    proxy_name: Option<&str>,
) -> Option<MeshRequestKey> {
    if !metadata_has_mesh_identity_keys(metadata) {
        return None;
    }
    let destination_default = proxy_name.unwrap_or(proxy_id);
    let source_workload = metadata_arc(metadata, "mesh.source.workload", "unknown");
    let source_namespace = metadata_arc(metadata, "mesh.source.namespace", "unknown");
    let source_principal = metadata_arc(metadata, "mesh.source.principal", "unknown");
    let source_app = metadata_arc_or_clone(metadata, "mesh.source.app", &source_workload);
    let source_service = metadata_arc_or_clone(metadata, "mesh.source.service", &source_workload);
    let destination_workload =
        metadata_arc(metadata, "mesh.destination.workload", destination_default);
    let destination_namespace = metadata_arc(metadata, "mesh.destination.namespace", "unknown");
    let destination_principal = metadata_arc(metadata, "mesh.destination.principal", "unknown");
    let destination_app =
        metadata_arc_or_clone(metadata, "mesh.destination.app", &destination_workload);
    let destination_service =
        metadata_arc_or_clone(metadata, "mesh.destination.service", &destination_workload);
    let request_protocol = metadata_arc_any(
        metadata,
        &["mesh.request_protocol", "request_protocol"],
        "tcp",
    );
    let response_flags = metadata_arc(metadata, "mesh.response_flags", "-");
    let connection_security_policy =
        metadata_arc(metadata, "mesh.connection_security_policy", "none");
    let mut key = MeshRequestKey {
        source_workload,
        source_namespace,
        source_principal,
        source_app,
        source_service,
        destination_workload,
        destination_namespace,
        destination_principal,
        destination_app,
        destination_service,
        request_protocol,
        response_code: 0,
        response_code_override: None,
        response_flags,
        connection_security_policy,
        removed_labels: 1u16 << MeshMetricLabel::ResponseCode.index(),
    };
    normalize_removed_labels(&mut key);
    Some(key)
}

pub(crate) fn mesh_metric_disabled_metadata(
    metadata: &HashMap<String, String>,
    family: MeshMetricFamily,
) -> bool {
    metadata
        .get(MESH_METRICS_DISABLED_METADATA)
        .is_some_and(|disabled| {
            disabled
                .split(',')
                .any(|name| name == family.disabled_name())
        })
}

pub(crate) fn mesh_request_key_for_family_from_metadata(
    metadata: &HashMap<String, String>,
    base: &MeshRequestKey,
    family: MeshMetricFamily,
) -> MeshRequestKey {
    let Some(plan) = metadata.get(family.override_metadata_key()) else {
        return base.clone();
    };
    let mut key = base.clone();
    let extras = MetricTagCelExtras {
        request_method: metadata_request_method(metadata),
        request_host: metadata_request_host(metadata),
        response_code: None,
        destination_port: metadata_destination_port(metadata),
    };
    apply_metric_override_plan(&mut key, base, plan, extras);
    // TCP families never carry an HTTP response-code dimension. Preserve that
    // fixed schema even when an ALL_METRICS plan contains a response-code
    // UPSERT/rename intended for the HTTP/gRPC families.
    if family.is_tcp() {
        key.removed_labels |= 1u16 << MeshMetricLabel::ResponseCode.index();
    }
    normalize_removed_labels(&mut key);
    key
}

/// True when both metric plugins actually observed a mesh TCP connection.
///
/// Other mesh paths stamp routing/security `mesh.*` metadata before the plugin
/// chain. Requiring both observation markers prevents an earlier plugin
/// rejection from synthesizing workload-metric lifecycle series under
/// incomplete/default labels and keeps mesh mode silent when its auto-injected
/// `workload_metrics` plugin has no configured Prometheus exporter. The request
/// protocol still defaults to `tcp` exactly as the key builder does.
pub fn metadata_is_mesh_tcp_stream(metadata: &HashMap<String, String>) -> bool {
    metadata.contains_key(MESH_PROMETHEUS_METRICS_OBSERVED_METADATA)
        && metadata.contains_key(MESH_WORKLOAD_METRICS_OBSERVED_METADATA)
        && metadata
            .get("mesh.request_protocol")
            .or_else(|| metadata.get("request_protocol"))
            .is_none_or(|protocol| is_mesh_tcp_protocol(protocol))
}

/// True when `TCP_OPENED_CONNECTIONS` was already finalized for this stream.
pub fn mesh_tcp_opened_finalized(metadata: &HashMap<String, String>) -> bool {
    metadata.contains_key(MESH_TCP_OPENED_FINALIZED_METADATA)
}

/// Finalize mesh `TCP_OPENED_CONNECTIONS` once for a stream that reached
/// Prometheus and workload-metrics observation (proved by
/// [`MESH_PROMETHEUS_METRICS_OBSERVED_METADATA`] and
/// [`MESH_WORKLOAD_METRICS_OBSERVED_METADATA`]).
///
/// Call from the stream path after the last `on_stream_connect` hook that
/// actually ran — and, for captured mesh egress TCP, after selected target
/// metadata is stamped — never from a plugin hook. Idempotent: a second call
/// is a no-op. UDP/DTLS remain excluded by request protocol.
pub(crate) fn finalize_mesh_tcp_opened_stream(ctx: &mut StreamConnectionContext) {
    let proxy_id = ctx.proxy_id.as_str();
    let proxy_name = ctx.proxy_name.as_deref();
    let Some(metadata) = ctx.metadata.as_mut() else {
        return;
    };
    let registry = crate::plugins::prometheus_metrics::global_registry();
    registry.finalize_mesh_tcp_opened(metadata, proxy_id, proxy_name);
}

pub fn is_mesh_tcp_protocol(protocol: &str) -> bool {
    matches!(
        protocol.trim().to_ascii_lowercase().as_str(),
        "tcp" | "tcp_tls" | "tls"
    )
}

pub fn is_mesh_grpc_protocol(protocol: &str) -> bool {
    let normalized = protocol.trim().to_ascii_lowercase();
    normalized == "grpc" || normalized.starts_with("grpc-")
}

/// True when the Prometheus hook observed a gRPC (or gRPC-Web) transaction that
/// should populate authoritative length-prefixed message counters.
pub fn metadata_observes_grpc_messages(metadata: &HashMap<String, String>) -> bool {
    metadata.contains_key(MESH_PROMETHEUS_METRICS_OBSERVED_METADATA)
        && metadata
            .get("request_protocol")
            .or_else(|| metadata.get("mesh.request_protocol"))
            .is_some_and(|protocol| is_mesh_grpc_protocol(protocol))
}

/// Record a complete buffered gRPC body with store/fetch_max semantics so
/// retry/replay of the same bytes cannot inflate the counter.
///
/// `body` must already be the NATIVE length-prefixed gRPC representation. The
/// client-visible gRPC-Web representation is not: text mode base64-armours the
/// whole body, and both modes may carry a `0x80`-flagged terminal trailer frame
/// that is metadata rather than a message. See
/// [`record_native_grpc_message_count`] for the guarded entry point every
/// dispatch ladder uses.
pub fn record_complete_grpc_message_count(counter: &AtomicU64, body: &[u8]) {
    let count = count_grpc_length_prefixed_messages(body);
    counter.fetch_max(count, Ordering::Release);
}

/// Guarded recorder for a complete, protocol-native gRPC body.
///
/// Ordering contract, enforced by the call sites rather than by this function:
///
/// * REQUEST bodies are counted from the BACKEND-VISIBLE bytes, i.e. after
///   `apply_request_body_plugins_with_context` has run, because that is where
///   the `grpc_web` plugin base64-decodes text mode and splits off the terminal
///   gRPC-Web trailer frame.
/// * RESPONSE bodies are counted from the BACKEND-PRODUCED bytes, i.e. before
///   any gRPC-Web re-encoding appends a trailer frame or base64-armours the
///   stream.
///
/// Both directions therefore describe the native gRPC representation exchanged
/// with the backend, and `fetch_max` keeps retried/replayed buffers idempotent.
pub fn record_native_grpc_message_count(
    metadata: &HashMap<String, String>,
    counter: &AtomicU64,
    body: &[u8],
) {
    if metadata_observes_grpc_messages(metadata) {
        record_complete_grpc_message_count(counter, body);
    }
}

pub fn mesh_label_fragment(key: &MeshRequestKey, le: Option<&str>) -> String {
    let mut labels = mesh_label_base_fragment(key);
    if let Some(le) = le {
        if !labels.is_empty() {
            labels.push(',');
        }
        let _ = write!(labels, "le=\"{le}\"");
    }
    labels
}

fn mesh_label_base_fragment(key: &MeshRequestKey) -> String {
    let mut labels = String::with_capacity(512);
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::SourceWorkload,
        "source_workload",
        &key.source_workload,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::SourceNamespace,
        "source_namespace",
        &key.source_namespace,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::SourcePrincipal,
        "source_principal",
        &key.source_principal,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::SourceApp,
        "source_app",
        &key.source_app,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::SourceService,
        "source_service",
        &key.source_service,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::DestinationWorkload,
        "destination_workload",
        &key.destination_workload,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::DestinationNamespace,
        "destination_namespace",
        &key.destination_namespace,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::DestinationPrincipal,
        "destination_principal",
        &key.destination_principal,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::DestinationApp,
        "destination_app",
        &key.destination_app,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::DestinationService,
        "destination_service",
        &key.destination_service,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::RequestProtocol,
        "request_protocol",
        &key.request_protocol,
    );
    if key.removed_labels & (1u16 << MeshMetricLabel::ResponseCode.index()) == 0 {
        if !labels.is_empty() {
            labels.push(',');
        }
        match key.response_code_override.as_deref() {
            Some(value) => {
                let _ = write!(labels, "response_code=\"{}\"", escape_label_value(value));
            }
            None => {
                let _ = write!(labels, "response_code=\"{}\"", key.response_code);
            }
        }
    }
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::ResponseFlags,
        "response_flags",
        &key.response_flags,
    );
    write_optional_mesh_label(
        &mut labels,
        key,
        MeshMetricLabel::ConnectionSecurityPolicy,
        "connection_security_policy",
        &key.connection_security_policy,
    );
    labels
}

fn write_optional_mesh_label(
    labels: &mut String,
    key: &MeshRequestKey,
    label: MeshMetricLabel,
    name: &str,
    value: &str,
) {
    if key.removed_labels & (1u16 << label.index()) != 0 {
        return;
    }
    if !labels.is_empty() {
        labels.push(',');
    }
    let _ = write!(labels, "{}=\"{}\"", name, escape_label_value(value));
}

/// Current value of the aggregate ADS stream rejection counter. Test-only
/// accessor so the cap can be asserted without scraping the full metrics text.
#[cfg(test)]
pub fn xds_streams_rejected_count() -> u64 {
    XDS_STREAMS_REJECTED.load(Ordering::Relaxed)
}

/// Current value of the warming partial-apply counter for a `namespace`.
/// Test-only accessor.
#[cfg(test)]
pub fn xds_warming_partial_apply_count(namespace: &str) -> u64 {
    XDS_WARMING_PARTIAL_APPLIES
        .get(namespace)
        .map(|entry| entry.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Current value of the first-slice NACK counter for a `(namespace, type_url)`
/// pair. Test-only accessor.
#[cfg(test)]
pub fn xds_first_slice_nack_count(namespace: &str, type_url: &str) -> u64 {
    let key = XdsFirstSliceNackKey {
        namespace: Arc::from(namespace),
        type_url: Arc::from(type_url),
    };
    XDS_FIRST_SLICE_NACKS
        .get(&key)
        .map(|entry| entry.load(Ordering::Relaxed))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh_key() -> MeshRequestKey {
        MeshRequestKey {
            source_workload: Arc::from("frontend"),
            source_namespace: Arc::from("default"),
            source_principal: Arc::from("source-principal"),
            source_app: Arc::from("frontend"),
            source_service: Arc::from("frontend"),
            destination_workload: Arc::from("backend"),
            destination_namespace: Arc::from("default"),
            destination_principal: Arc::from("destination-principal"),
            destination_app: Arc::from("backend"),
            destination_service: Arc::from("backend"),
            request_protocol: Arc::from("http"),
            response_code: 200,
            response_code_override: None,
            response_flags: Arc::from("-"),
            connection_security_policy: Arc::from("mutual_tls"),
            removed_labels: 0,
        }
    }

    #[test]
    fn metric_override_plan_applies_after_base_attribution_in_order() {
        let summary = TransactionSummary {
            metadata: HashMap::from([(
                MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
                // Copy the source workload into destination workload, then set
                // the source to a new value. The order is observable.
                "m0;n0,5;s0,4:edge;".to_string(),
            )]),
            ..TransactionSummary::default()
        };

        let transformed =
            mesh_request_key_for_family(&summary, &mesh_key(), MeshMetricFamily::RequestCount);
        let labels = mesh_label_fragment(&transformed, None);

        assert!(labels.contains("source_workload=\"edge\""), "{labels}");
        assert!(
            labels.contains("destination_workload=\"frontend\""),
            "{labels}"
        );
    }

    #[test]
    fn removed_and_renamed_labels_do_not_split_series_identity() {
        let summary = TransactionSummary {
            metadata: HashMap::from([(
                MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
                // Remove source_principal, rename source_workload into
                // source_app (removing source_workload).
                "m0;r2;n0,3;".to_string(),
            )]),
            ..TransactionSummary::default()
        };

        let base_a = mesh_key();
        let mut base_b = mesh_key();
        base_b.source_principal = Arc::from("other-principal");
        base_b.source_workload = Arc::from("frontend"); // same rename source value

        let key_a = mesh_request_key_for_family(&summary, &base_a, MeshMetricFamily::RequestCount);
        let key_b = mesh_request_key_for_family(&summary, &base_b, MeshMetricFamily::RequestCount);

        // Rendering omits removed labels, so keys differing only on removed
        // label values must compare and hash equal or one scrape emits
        // duplicate series with identical label sets.
        assert_eq!(key_a, key_b);
        assert_eq!(
            mesh_label_fragment(&key_a, None),
            mesh_label_fragment(&key_b, None)
        );
        // The rename still carried the original value before clearing it.
        assert!(
            mesh_label_fragment(&key_a, None).contains("source_app=\"frontend\""),
            "{}",
            mesh_label_fragment(&key_a, None)
        );

        // A base whose renamed *source value* differs must stay distinct.
        let mut base_c = mesh_key();
        base_c.source_workload = Arc::from("checkout");
        let key_c = mesh_request_key_for_family(&summary, &base_c, MeshMetricFamily::RequestCount);
        assert_ne!(key_a, key_c);
    }

    #[test]
    fn malformed_multibyte_override_opcode_fails_closed_without_panic() {
        // `é` is UTF-8 C3 A9. Reading the lead byte then slicing at index 1
        // would panic on a char-boundary check; defensive parsing must return.
        let summary = TransactionSummary {
            metadata: HashMap::from([(
                MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
                "m0;é".to_string(),
            )]),
            ..TransactionSummary::default()
        };
        let base = mesh_key();
        let key = mesh_request_key_for_family(&summary, &base, MeshMetricFamily::RequestCount);
        assert_eq!(key, base);
    }

    #[test]
    fn malformed_multibyte_compact_cel_body_fails_closed_without_panic() {
        // UPSERT CEL body whose first byte is a multibyte lead (`é` = C3 A9).
        // Length is UTF-8 bytes so the body slice is well-formed as a str, but
        // opcode consumption must not panic mid-character.
        let summary = TransactionSummary {
            metadata: HashMap::from([(
                MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
                "m0;x0,2:é;".to_string(),
            )]),
            ..TransactionSummary::default()
        };
        let base = mesh_key();
        let key = mesh_request_key_for_family(&summary, &base, MeshMetricFamily::RequestCount);
        assert_eq!(key, base);
        assert!(!compact_metric_tag_cel_is_valid("é"));
        assert!(
            evaluate_compact_metric_tag_cel(
                "é",
                MetricTagCelContext {
                    source_workload: "frontend",
                    source_namespace: "default",
                    source_principal: "source-principal",
                    source_app: "frontend",
                    source_service: "frontend",
                    destination_workload: "backend",
                    destination_namespace: "default",
                    destination_principal: "destination-principal",
                    destination_app: "backend",
                    destination_service: "backend",
                    request_protocol: "http",
                    response_flags: "-",
                    connection_security_policy: "mutual_tls",
                    request_method: Some("GET"),
                    request_host: Some("example"),
                    response_code: Some(200),
                    destination_port: Some(8080),
                }
            )
            .is_none()
        );
    }

    #[test]
    fn metric_disable_marker_is_family_specific() {
        let summary = TransactionSummary {
            metadata: HashMap::from([(
                MESH_METRICS_DISABLED_METADATA.to_string(),
                "request_duration".to_string(),
            )]),
            ..TransactionSummary::default()
        };

        assert!(!mesh_metric_disabled(
            &summary,
            MeshMetricFamily::RequestCount
        ));
        assert!(mesh_metric_disabled(
            &summary,
            MeshMetricFamily::RequestDuration
        ));
    }

    #[test]
    fn federation_failure_metric_never_renders_endpoint_secrets() {
        let trust_domain = format!("security-{}-{}.example", std::process::id(), line!());
        increment_mesh_federation_poll_failure(
            &trust_domain,
            "https://user:password@federation.example/secret/path?token=query-secret#fragment",
        );
        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);
        let line = output
            .lines()
            .find(|line| {
                line.starts_with("ferrum_mesh_federation_poll_failures_total")
                    && line.contains(&trust_domain)
            })
            .expect("federation failure metric");

        assert!(line.contains("endpoint=\"redacted\""), "{line}");
        for secret in ["user", "password", "secret", "token", "fragment"] {
            assert!(!line.contains(secret), "{secret} leaked in {line}");
        }
    }

    #[test]
    fn render_mesh_observability_metrics_evicts_stale_expired_series() {
        let now = unix_now_seconds();
        let suffix = format!("{}-{}", std::process::id(), now);
        let stale_id = format!("spiffe://cluster.local/ns/default/sa/stale-{suffix}");
        let active_expired_id = format!("spiffe://cluster.local/ns/default/sa/active-{suffix}");

        record_mesh_cert_expiry_unix_seconds(
            &stale_id,
            "unit-test",
            now.saturating_sub(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS + 1),
            now.saturating_sub(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS + 1),
        );
        record_mesh_cert_expiry_unix_seconds(
            &active_expired_id,
            "unit-test",
            now.saturating_sub(1),
            now,
        );
        // Evict deterministically rather than via `render`'s throttle-gated
        // path: the throttle (`MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS`) is a
        // shared global, so a concurrent test's `render` could consume the
        // interval and make this render skip eviction. Calling the eviction
        // directly isolates this test from that cross-test race while still
        // exercising the real staleness predicate.
        evict_stale_mesh_cert_expiry_series(now);

        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        assert!(
            !output.contains(&stale_id),
            "stale expired certificate series should be evicted: {output}"
        );
        assert!(
            output.contains(&active_expired_id),
            "recently observed expired certificate should still be exported: {output}"
        );
    }

    #[test]
    fn render_emits_xds_stream_rejection_and_first_slice_nack_metrics() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let namespace = format!("ns-{suffix}");
        let type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

        let before = xds_streams_rejected_count();
        increment_xds_stream_rejected();
        increment_xds_stream_rejected();
        increment_xds_first_slice_nack(&namespace, type_url);
        increment_xds_warming_partial_apply(&namespace);

        assert_eq!(xds_streams_rejected_count() - before, 2);
        assert_eq!(xds_first_slice_nack_count(&namespace, type_url), 1);
        // Unique namespace → this test is the only writer for that series.
        assert_eq!(xds_warming_partial_apply_count(&namespace), 1);

        let total = xds_streams_rejected_count();
        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        assert!(
            output.contains("# TYPE ferrum_xds_streams_rejected_total counter"),
            "rejection counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!("ferrum_xds_streams_rejected_total {total}\n")),
            "aggregate rejection counter value line missing: {output}"
        );
        assert!(
            output.contains("# TYPE ferrum_xds_first_slice_nacks_total counter"),
            "first-slice NACK counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_xds_first_slice_nacks_total{{namespace=\"{namespace}\",type_url=\"{type_url}\"}} 1"
            )),
            "first-slice NACK counter series missing: {output}"
        );
        assert!(
            output.contains("# TYPE ferrum_xds_warming_partial_applies_total counter"),
            "warming partial-apply counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_xds_warming_partial_applies_total{{namespace=\"{namespace}\"}} 1"
            )),
            "warming partial-apply counter series missing: {output}"
        );
    }

    #[test]
    fn render_emits_remote_discovery_poll_metrics() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("remote-{suffix}");
        let trust_domain = format!("td-{suffix}.example");
        let control_plane = format!("https://remote-{suffix}.example:9443");
        let fetched_at = unix_now_seconds().saturating_sub(5);

        increment_mesh_remote_discovery_poll_failure(&cluster, &trust_domain, &control_plane);
        increment_mesh_remote_discovery_poll_failure(&cluster, &trust_domain, &control_plane);
        record_mesh_remote_discovery_poll_success(&cluster, &trust_domain, fetched_at);

        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        assert!(
            output.contains("# TYPE ferrum_mesh_remote_discovery_poll_failures_total counter"),
            "remote discovery failure counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_mesh_remote_discovery_poll_failures_total{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\",control_plane=\"redacted\"}} 2"
            )),
            "remote discovery failure counter series missing: {output}"
        );
        assert!(
            output.contains("# TYPE ferrum_mesh_remote_discovery_poll_successes_total counter"),
            "remote discovery success counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_mesh_remote_discovery_poll_successes_total{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\"}} 1"
            )),
            "remote discovery success counter series missing: {output}"
        );
        assert!(
            output.contains(
                "# TYPE ferrum_mesh_remote_discovery_last_success_timestamp_seconds gauge"
            ),
            "remote discovery last-success gauge TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_mesh_remote_discovery_last_success_timestamp_seconds{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\"}} {fetched_at}"
            )),
            "remote discovery last-success series missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_mesh_remote_discovery_endpoint_age_seconds{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\"}} "
            )),
            "remote discovery endpoint age series missing: {output}"
        );
    }

    /// SECURITY: a `control_plane_url` must not surface on the unauthenticated
    /// `/metrics` failure-counter label. URLs can expose topology through the
    /// host/port and credential-like material through path/query/fragment data.
    #[test]
    fn remote_discovery_failure_label_redacts_control_plane_url() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("remote-{suffix}");
        let trust_domain = format!("td-{suffix}.example");
        let host = format!("cp-{suffix}.example");
        let leaky_url = format!(
            "https://user:pw@{host}:9443/tenant/path-token-secret/subscribe?token=secret&api_key=abc#frag"
        );

        increment_mesh_remote_discovery_poll_failure(&cluster, &trust_domain, &leaky_url);

        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        let line = output
            .lines()
            .find(|l| {
                l.starts_with("ferrum_mesh_remote_discovery_poll_failures_total")
                    && l.contains(&format!("cluster=\"{cluster}\""))
            })
            .unwrap_or_else(|| panic!("failure series for {cluster} missing: {output}"));

        for sensitive in [
            host.as_str(),
            "user",
            "pw",
            "9443",
            "tenant",
            "path-token-secret",
            "token",
            "secret",
            "api_key",
            "abc",
            "frag",
        ] {
            assert!(
                !line.contains(sensitive),
                "sensitive control-plane URL component leaked into metric label: {line}"
            );
        }
        assert!(
            line.contains("control_plane=\"redacted\""),
            "control-plane label should retain only a fixed redacted value: {line}"
        );
    }

    #[test]
    fn redact_control_plane_label_uses_fixed_non_sensitive_value() {
        assert_eq!(
            redact_control_plane_label("https://user:pw@cp.example:9443/p?token=x"),
            "redacted"
        );
        assert_eq!(
            redact_control_plane_label("not a url?token=secret"),
            "redacted"
        );
    }

    /// codex finding: when a remote cluster is removed, its success / last-success
    /// / endpoint-age series must be pruned so a stale, endpoint-less cluster does
    /// not keep advertising a fresh poll on unauthenticated `/metrics`.
    #[test]
    fn clear_mesh_remote_discovery_metrics_prunes_success_and_age() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("remote-{suffix}");
        let trust_domain = format!("td-{suffix}.example");
        let fetched_at = unix_now_seconds().saturating_sub(5);

        record_mesh_remote_discovery_poll_success(&cluster, &trust_domain, fetched_at);

        // Present before the clear.
        let mut before = String::new();
        render_mesh_observability_metrics(&mut before);
        assert!(
            before.contains(&format!(
                "ferrum_mesh_remote_discovery_poll_successes_total{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\"}} 1"
            )),
            "precondition: success series should exist before clear: {before}"
        );

        clear_mesh_remote_discovery_metrics(&cluster, &trust_domain);

        // Gone after the clear — neither the success counter nor the gauges.
        let mut after = String::new();
        render_mesh_observability_metrics(&mut after);
        assert!(
            !after.contains(&format!("cluster=\"{cluster}\"")),
            "success / last-success / age series must be pruned after clear: {after}"
        );
    }
}
