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
pub(crate) const MESH_REQUEST_COUNT_OVERRIDES_METADATA: &str =
    "mesh.metrics.request_count.tag_overrides";
pub(crate) const MESH_REQUEST_DURATION_OVERRIDES_METADATA: &str =
    "mesh.metrics.request_duration.tag_overrides";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeshMetricFamily {
    RequestCount,
    RequestDuration,
}

impl MeshMetricFamily {
    pub(crate) fn from_config_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "REQUEST_COUNT" | "FERRUM_MESH_REQUESTS_TOTAL" => Some(Self::RequestCount),
            "REQUEST_DURATION" | "FERRUM_MESH_REQUEST_DURATION_MS" => Some(Self::RequestDuration),
            _ => None,
        }
    }

    pub(crate) fn override_metadata_key(self) -> &'static str {
        match self {
            Self::RequestCount => MESH_REQUEST_COUNT_OVERRIDES_METADATA,
            Self::RequestDuration => MESH_REQUEST_DURATION_OVERRIDES_METADATA,
        }
    }

    fn disabled_name(self) -> &'static str {
        match self {
            Self::RequestCount => "request_count",
            Self::RequestDuration => "request_duration",
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

/// Build the RED/service-graph metric key for a mesh request.
///
/// Per-field label values are interned via [`intern_label`] so repeated label
/// values (the common case — a bounded set of workloads / namespaces /
/// protocols) become a hash lookup plus an `Arc` clone rather than ~11 fresh
/// heap allocations per call. This runs on the `log` phase (RED metrics,
/// service-graph aggregation, log shaping) and is gated off unless mesh
/// metrics / the service graph are enabled.
pub fn mesh_request_key(summary: &TransactionSummary) -> Option<MeshRequestKey> {
    if !summary.metadata.keys().any(|key| key.starts_with("mesh.")) {
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
    summary
        .metadata
        .get(MESH_METRICS_DISABLED_METADATA)
        .is_some_and(|disabled| {
            disabled
                .split(',')
                .any(|name| name == family.disabled_name())
        })
}

/// Apply the prevalidated, length-prefixed metric override plan emitted by
/// `workload_metrics` to a finalized mesh key. The compact plan is parsed in
/// place without JSON parsing, allocation, or a lock on the request-log path.
pub(crate) fn mesh_request_key_for_family(
    summary: &TransactionSummary,
    base: &MeshRequestKey,
    family: MeshMetricFamily,
) -> MeshRequestKey {
    let Some(plan) = summary.metadata.get(family.override_metadata_key()) else {
        return base.clone();
    };
    let mut key = base.clone();
    apply_metric_override_plan(&mut key, plan);
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

fn apply_metric_override_plan(key: &mut MeshRequestKey, mut plan: &str) {
    while !plan.is_empty() {
        let Some(op) = plan.as_bytes().first().copied() else {
            return;
        };
        plan = &plan[1..];
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
            _ => return,
        }
    }
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
    let base_labels = mesh_label_base_fragment(key);
    let le_separator = if base_labels.is_empty() { "" } else { "," };
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        let _ = writeln!(
            output,
            "ferrum_mesh_request_duration_ms_bucket{{{}{le_separator}le=\"{}\"{}}} {}",
            base_labels, boundary, gateway_ns_label, count
        );
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let _ = writeln!(
        output,
        "ferrum_mesh_request_duration_ms_bucket{{{}{le_separator}le=\"+Inf\"{}}} {}",
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
        "ferrum_mesh_request_duration_ms_sum{{{}{}}} {:.2}",
        base_labels, aggregate_gateway_ns_label, sum
    );
    let _ = writeln!(
        output,
        "ferrum_mesh_request_duration_ms_count{{{}{}}} {}",
        base_labels, aggregate_gateway_ns_label, total_count
    );
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
                "n0,5;s0,4:edge;".to_string(),
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
                "r2;n0,3;".to_string(),
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
