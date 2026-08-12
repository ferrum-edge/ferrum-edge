//! Aggregate xDS ADS admission control (issue #3741).
//!
//! The historical ADS guard bounded concurrent streams **per client-supplied
//! `Node.id`** only. A namespace-authorized client picks that string itself, so
//! cycling unique node ids reset the allowance and the CP's aggregate task /
//! channel / snapshot / broadcast-subscriber footprint stayed unbounded.
//!
//! This module owns every ADS admission budget as one fail-closed unit:
//!
//! | Scope | Checked | Limit |
//! |-------|---------|-------|
//! | total active ADS streams (process) | before the relay task, response channel, and filtered config snapshot exist | `max_total_streams` |
//! | active ADS streams per namespace/tenant | same reservation | `max_streams_per_namespace` |
//! | active ADS streams per authenticated principal | same reservation | `max_streams_per_principal` |
//! | active ADS streams per node state key | on the stream's first request, once `Node.id` is known | `max_streams_per_node` |
//! | distinct active node state keys | same registration | `max_active_nodes` |
//!
//! Precedence is deterministic and outermost-first: total → namespace →
//! principal → node streams → node cardinality. The first saturated scope
//! returns `RESOURCE_EXHAUSTED` and **nothing** is left reserved (a failed
//! inner scope rolls the outer reservations back before returning, so there is
//! no partial admission state).
//!
//! Reservation is transferred into an [`XdsStreamPermit`] that releases exactly
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
//! [`XdsAdmissionRejection::metric_reason`] label.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tonic::Status;

use crate::fips::approved::Sha256;

/// Default ceiling on total concurrent ADS streams for one CP process.
///
/// Numerically matches the default CP gRPC connection ceiling
/// (`FERRUM_CP_GRPC_MAX_CONNECTIONS`), but that ceiling bounds *connections*,
/// not streams: one HTTP/2 connection multiplexes up to
/// `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` (default 1000) concurrent ADS
/// streams, so the transport budget does not bound ADS occupancy. This is the
/// only aggregate ADS stream bound.
pub const DEFAULT_XDS_MAX_TOTAL_STREAMS: usize = 1024;
/// Default ceiling on concurrent ADS streams for one namespace/tenant.
pub const DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE: usize = 512;
/// Default ceiling on concurrent ADS streams for one authenticated principal
/// (JWT `sub`). Deliberately generous: fleets that share one credential across
/// every DP present a single principal, and this must not become a surprise
/// outage for them while still bounding one credential's aggregate footprint.
pub const DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL: usize = 256;
/// Default per-node concurrent ADS stream ceiling. A healthy DP keeps a single
/// ADS stream; the small headroom tolerates brief overlap during a client
/// reconnect (old stream draining while the new one establishes).
pub const DEFAULT_XDS_MAX_STREAMS_PER_NODE: usize = 4;
/// Default ceiling on distinct active node state keys. Bounds the node-scoped
/// maps (snapshot cache, nonce tracker, workload identity, waypoint, scoping).
///
/// A node state key exists only while at least one admitted stream holds it
/// (registered on that stream's first request, removed when its last stream
/// releases), so distinct active nodes can never exceed active streams. This
/// budget therefore only *binds* when it is set below
/// [`DEFAULT_XDS_MAX_TOTAL_STREAMS`] / `FERRUM_XDS_MAX_TOTAL_STREAMS`, or when
/// the total-stream budget is unbounded (`0`). At the shipped defaults
/// (`2048` > `1024`) it is a defense-in-depth ceiling that the total-stream
/// budget reaches first — deliberately, so tightening the node map bound is an
/// explicit operator choice rather than a surprise refusal on a large fleet.
pub const DEFAULT_XDS_MAX_ACTIVE_NODES: usize = 2048;
/// Default maximum `Node.id` length in UTF-8 bytes. 253 is the DNS name
/// ceiling, which covers every hostname / pod-identity shape Ferrum's own DP
/// produces.
pub const DEFAULT_XDS_MAX_NODE_ID_BYTES: usize = 253;
/// Default deadline for an admitted ADS stream to send its first request (and
/// therefore identify a node). Bounds a stalled stream that would otherwise
/// park a task, a channel, and a permit indefinitely.
pub const DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Width (hex characters) of a per-principal map/state key: the FULL SHA-256
/// digest.
///
/// Deliberately not truncated. A principal key is a security boundary — it
/// keys the per-principal stream quota and, through [`xds_state_key`], the
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
pub enum XdsAdmissionRejection {
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
}

impl XdsAdmissionRejection {
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
        )
    }

    /// gRPC status for this rejection.
    pub fn into_status(self) -> Status {
        if self.is_capacity() {
            Status::resource_exhausted(self.status_message())
        } else if matches!(self, Self::FirstRequestTimeout) {
            Status::deadline_exceeded(self.status_message())
        } else {
            Status::invalid_argument(self.status_message())
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
pub struct XdsAdmissionLimits {
    pub max_total_streams: usize,
    pub max_streams_per_namespace: usize,
    pub max_streams_per_principal: usize,
    pub max_streams_per_node: usize,
    pub max_active_nodes: usize,
    pub max_node_id_bytes: usize,
    pub first_request_timeout: Duration,
}

impl Default for XdsAdmissionLimits {
    fn default() -> Self {
        Self {
            max_total_streams: DEFAULT_XDS_MAX_TOTAL_STREAMS,
            max_streams_per_namespace: DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE,
            max_streams_per_principal: DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL,
            max_streams_per_node: DEFAULT_XDS_MAX_STREAMS_PER_NODE,
            max_active_nodes: DEFAULT_XDS_MAX_ACTIVE_NODES,
            max_node_id_bytes: DEFAULT_XDS_MAX_NODE_ID_BYTES,
            first_request_timeout: Duration::from_secs(DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS),
        }
    }
}

impl XdsAdmissionLimits {
    /// True when any stream/node budget is configured as unbounded (`0`).
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

/// Shared ADS admission accounting. One instance per CP process, shared by SotW
/// and Delta ADS.
///
/// Cloning shares the same accounting (an internal `Arc`), so every clone —
/// including the per-stream `XdsAdsServer` clone — draws from ONE budget.
#[derive(Debug, Clone)]
pub struct XdsAdmissionController {
    inner: Arc<XdsAdmissionState>,
}

#[derive(Debug)]
struct XdsAdmissionState {
    limits: XdsAdmissionLimits,
    total_streams: AtomicUsize,
    // ADS admission is outside the proxy hot path and only exists when
    // FERRUM_XDS_ENABLED=true, so default DashMap sharding is intentional.
    // Every map is bounded: each entry needs at least one live stream, and live
    // streams are bounded by `max_total_streams`.
    per_namespace: DashMap<String, usize>,
    per_principal: DashMap<String, usize>,
    per_node: DashMap<String, usize>,
    active_nodes: AtomicUsize,
}

impl XdsAdmissionController {
    pub fn new(limits: XdsAdmissionLimits) -> Self {
        Self {
            inner: Arc::new(XdsAdmissionState {
                limits,
                total_streams: AtomicUsize::new(0),
                per_namespace: DashMap::new(),
                per_principal: DashMap::new(),
                per_node: DashMap::new(),
                active_nodes: AtomicUsize::new(0),
            }),
        }
    }

    pub fn limits(&self) -> &XdsAdmissionLimits {
        &self.inner.limits
    }

    /// Current total active ADS streams (both methods).
    pub fn active_streams(&self) -> usize {
        self.inner.total_streams.load(Ordering::Acquire)
    }

    /// Current distinct active node state keys.
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
    pub fn validate_node_id(&self, node_id: &str) -> Result<(), XdsAdmissionRejection> {
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
    ) -> Result<XdsStreamPermit, XdsAdmissionRejection> {
        if !self.try_acquire_total() {
            return Err(XdsAdmissionRejection::TotalStreams);
        }
        if !try_acquire_scope(
            &self.inner.per_namespace,
            namespace,
            self.inner.limits.max_streams_per_namespace,
        ) {
            // Roll the outer reservation back so a refused stream leaves no
            // partial admission state behind.
            self.release_total();
            return Err(XdsAdmissionRejection::NamespaceStreams);
        }
        if !try_acquire_scope(
            &self.inner.per_principal,
            principal_key,
            self.inner.limits.max_streams_per_principal,
        ) {
            release_scope(&self.inner.per_namespace, namespace);
            self.release_total();
            return Err(XdsAdmissionRejection::PrincipalStreams);
        }
        // Exact +1 tied to successful aggregate admission only — never a
        // load-then-store of live counters (that races under concurrent
        // reserve/release and can leave a stale exported gauge).
        crate::plugins::mesh::prometheus_helpers::adjust_xds_active_streams(1);
        Ok(XdsStreamPermit {
            controller: self.clone(),
            namespace: namespace.to_string(),
            principal_key: principal_key.to_string(),
            node_key: None,
        })
    }

    fn try_acquire_total(&self) -> bool {
        let max = self.inner.limits.max_total_streams;
        if max == 0 {
            self.inner.total_streams.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        self.inner
            .total_streams
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= max {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .is_ok()
    }

    fn release_total(&self) {
        // `saturating_sub` semantics: never wrap below zero even if a future
        // caller double-releases.
        let _ =
            self.inner
                .total_streams
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(1))
                });
    }

    /// Register one stream against a node state key. Returns the per-node and
    /// distinct-node rejections; on `Err` nothing was registered, so no release
    /// is owed.
    fn register_node(&self, node_key: &str) -> Result<(), XdsAdmissionRejection> {
        let max = self.inner.limits.max_streams_per_node;
        match self.inner.per_node.entry(node_key.to_string()) {
            Entry::Occupied(mut entry) => {
                if max != 0 && *entry.get() >= max {
                    return Err(XdsAdmissionRejection::NodeStreams);
                }
                *entry.get_mut() += 1;
            }
            Entry::Vacant(entry) => {
                // A brand-new node consumes a distinct-node slot. The slot is
                // reserved while this shard's entry lock is held, so no other
                // thread can insert the same key concurrently and the counter
                // stays exact. Only an atomic is touched under the lock —
                // never `DashMap::len()`, which would take every shard lock.
                if !self.try_acquire_node_slot() {
                    return Err(XdsAdmissionRejection::NodeCardinality);
                }
                entry.insert(1);
                // Exact +1 for a newly admitted distinct node key only.
                crate::plugins::mesh::prometheus_helpers::adjust_xds_active_node_ids(1);
            }
        }
        Ok(())
    }

    fn try_acquire_node_slot(&self) -> bool {
        let max = self.inner.limits.max_active_nodes;
        if max == 0 {
            self.inner.active_nodes.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        self.inner
            .active_nodes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= max {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .is_ok()
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
                    let _ = self.inner.active_nodes.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |current| Some(current.saturating_sub(1)),
                    );
                    // Exact -1 tied to last-stream removal of this node key.
                    crate::plugins::mesh::prometheus_helpers::adjust_xds_active_node_ids(-1);
                    true
                }
            }
            // A missing entry is an invariant violation, not authorization to
            // delete state that may belong to a successor generation.
            Entry::Vacant(_) => false,
        }
    }

    fn unregister_node(&self, node_key: &str) -> bool {
        self.unregister_node_with_cleanup(node_key, || {})
    }

    fn release_stream(&self, namespace: &str, principal_key: &str) {
        release_scope(&self.inner.per_principal, principal_key);
        release_scope(&self.inner.per_namespace, namespace);
        self.release_total();
        // Exact -1 tied to the permit's exactly-once aggregate release.
        crate::plugins::mesh::prometheus_helpers::adjust_xds_active_streams(-1);
    }
}

fn try_acquire_scope(map: &DashMap<String, usize>, key: &str, max: usize) -> bool {
    match map.entry(key.to_string()) {
        Entry::Occupied(mut entry) => {
            if max != 0 && *entry.get() >= max {
                return false;
            }
            *entry.get_mut() += 1;
            true
        }
        // A first stream is always admitted, so a ceiling of 1 admits exactly
        // one concurrent stream.
        Entry::Vacant(entry) => {
            entry.insert(1);
            true
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
pub fn validate_node_id(node_id: &str, max_bytes: usize) -> Result<(), XdsAdmissionRejection> {
    if node_id.is_empty() {
        return Err(XdsAdmissionRejection::NodeIdEmpty);
    }
    if max_bytes != 0 && node_id.len() > max_bytes {
        return Err(XdsAdmissionRejection::NodeIdTooLong);
    }
    if !node_id.as_bytes().iter().all(u8::is_ascii_graphic) {
        return Err(XdsAdmissionRejection::NodeIdUnsafeCharacters);
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
pub fn xds_state_key(namespace: &str, principal_key: &str, node_id: &str) -> String {
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
pub struct XdsStreamPermit {
    controller: XdsAdmissionController,
    namespace: String,
    principal_key: String,
    node_key: Option<String>,
}

impl XdsStreamPermit {
    /// Register this stream against a node state key (the innermost guard).
    ///
    /// On `Err` nothing was registered and the permit still holds only its
    /// aggregate reservation, so the caller owes no node release.
    pub fn register_node(&mut self, node_key: &str) -> Result<(), XdsAdmissionRejection> {
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
    pub fn limits(&self) -> &XdsAdmissionLimits {
        self.controller.limits()
    }
}

impl Drop for XdsStreamPermit {
    fn drop(&mut self) {
        // `release_node` takes the key, so an earlier explicit release is not
        // double-counted here.
        let _ = self.release_node();
        self.controller
            .release_stream(&self.namespace, &self.principal_key);
    }
}
