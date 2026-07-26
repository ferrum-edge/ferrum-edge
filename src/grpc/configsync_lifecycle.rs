//! Pure helpers for DP ConfigSync stream lifecycle policy.
//!
//! Kept free of gRPC/runtime I/O so unit tests can exercise silent-partition
//! thresholds, multi-CP backoff continuity, FULL_SNAPSHOT fencing, freshness
//! watermark monotonicity, subscription base gating, version negotiation,
//! delta-rejection divergence, and connection-state staleness preservation
//! without standing up a CP.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use semver::Version;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::types::GatewayConfig;
use crate::identity::{TrustBundle, TrustBundleSet as RuntimeTrustBundleSet};
use crate::util::backoff::{BACKOFF_INITIAL_SECS, BACKOFF_MAX_SECS, next_backoff_secs};

/// HTTP/2 PING interval on the DP→CP ConfigSync channel.
pub const CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// HTTP/2 PING ack timeout on the DP→CP ConfigSync channel.
pub const CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
/// TCP keepalive idle probe interval for ConfigSync sockets.
pub const CONFIGSYNC_TCP_KEEPALIVE_SECS: u64 = 30;
/// CP application-level ConfigSync heartbeat interval.
pub const CONFIGSYNC_HEARTBEAT_INTERVAL_SECS: u64 = 60;
/// Reconnect when no ConfigSync message (including heartbeat) arrives within
/// this bound. Sized above the application heartbeat so healthy idle streams
/// are not treated as dead.
pub const CONFIGSYNC_MAX_SILENCE_SECS: u64 = 150;

/// Per-connection ConfigSync stream timing policy.
///
/// Production always uses [`ConfigSyncStreamTimings::production`], i.e. the
/// module constants above; the DP entry points that omit it default to exactly
/// that. Tests may pass a compressed bound so silent-partition failover is
/// provable inside bounded hosted CI without sleeping for production minutes.
///
/// The value is ordinary per-invocation state carried on the call stack — there
/// is no global, environment, or `cfg` override — so a test value has no path
/// into a production DP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSyncStreamTimings {
    /// Reconnect when a stream with *negotiated* heartbeats delivers no message
    /// for this long. Unnegotiated streams never arm the watchdog at all.
    pub max_silence: std::time::Duration,
}

impl ConfigSyncStreamTimings {
    /// The shipped production policy.
    pub const fn production() -> Self {
        Self {
            max_silence: std::time::Duration::from_secs(CONFIGSYNC_MAX_SILENCE_SECS),
        }
    }
}

impl Default for ConfigSyncStreamTimings {
    fn default() -> Self {
        Self::production()
    }
}

/// Maximum tolerated future clock skew (seconds) for admitting a CP-stamped
/// committed snapshot timestamp into freshness authority.
///
/// The freshness watermark ([`AppliedSnapshotAuthority::version`]) is entirely
/// CP-clock stamped (it tracks committed `GatewayConfig.loaded_at`). A CP whose
/// wall clock runs ahead would otherwise poison the monotonic watermark: once a
/// far-future stamp is admitted, every correct-clock failover CP carrying
/// genuinely newer config is fenced as "older than applied" until real wall
/// time catches up. To bound that, a committed stamp more than this far ahead of
/// the DP's own wall clock is treated as an implausibly-future (skewed or
/// hostile) stamp and refused — the DP fails closed, keeps last-known-good
/// config, and fails over, rather than silently clamping the untrusted timestamp
/// into authority.
///
/// 300s (5 minutes) matches the long-established Kerberos / JWT `iat`/`nbf`
/// leeway for tolerable NTP drift: generous enough that realistic DP↔CP clock
/// differences never false-reject a legitimate snapshot, tight enough that
/// watermark poisoning is bounded to at most one skew window.
pub const CONFIGSYNC_MAX_FUTURE_SKEW_SECS: i64 = 300;

/// Bounded, material-free view of the last accepted CP-authoritative gateway
/// trust-bundle state used by older-cross-source snapshot equivalence.
///
/// Present fingerprints are SHA-256 digests of a canonical encoding; raw trust
/// material is never retained here and must never be logged.
///
/// Comparability rules for the identical-fallback exception:
/// - [`Self::Unknown`] is never comparable (including Unknown vs Unknown).
/// - [`Self::Absent`] is established only by an accepted explicit Clear.
/// - [`Self::Present`] is established only by an accepted explicit Replace.
/// - Empty/Unchanged side channels leave trust Unknown (or preserve prior
///   Unknown) and cannot establish complete-payload equivalence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayTrustEquivalenceState {
    /// Trust state has not been established by an accepted explicit Clear or
    /// Replace. Empty/Unchanged side channels and resource-delta-only authority
    /// construction leave trust here. Never treat as equivalent to Absent.
    Unknown,
    /// Explicit clear / absent CP-delivered gateway trust.
    Absent,
    /// Present CP-delivered gateway trust, compared by canonical fingerprint.
    Present { fingerprint: String },
}

impl GatewayTrustEquivalenceState {
    /// True when this state can participate in complete-payload equivalence.
    pub fn is_comparable(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Authoritative freshness watermark already established by this DP.
///
/// `version` is the monotonic high-water mark used to fence cross-source
/// FULL_SNAPSHOTs. It tracks committed GatewayConfig / accepted resource-delta
/// timestamps and never decreases on same-source recovery. It is `None` only
/// when an older authority was recorded without a comparable timestamp (should
/// not arise for newly committed applies that always carry `loaded_at`).
///
/// `gateway_trust` is the last accepted CP-authoritative trust equivalence view.
/// It starts as [`GatewayTrustEquivalenceState::Unknown`] until an accepted
/// explicit Clear or Replace establishes Absent/Present. It is refreshed on
/// FULL_SNAPSHOT applies and on accepted trust Replace/Clear updates (including
/// trust-only deltas) so the identical-fallback exception cannot compare against
/// a stale trust view after a later trust change. Empty/Unchanged side channels
/// never convert Unknown into Absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSnapshotAuthority {
    pub version: Option<DateTime<Utc>>,
    pub source_cp_url: String,
    pub gateway_trust: GatewayTrustEquivalenceState,
}

/// Why an envelope version failed to reconcile with committed config freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionReconcileError {
    /// `ConfigUpdate.version` was not a parseable RFC3339 timestamp.
    UnparseableEnvelope,
    /// Envelope timestamp disagrees with the parsed snapshot's `loaded_at`.
    Inconsistent {
        envelope: DateTime<Utc>,
        loaded_at: DateTime<Utc>,
    },
}

/// Why a FULL_SNAPSHOT was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleSnapshotReject {
    /// Envelope/`loaded_at` could not be ordered safely; fail closed.
    UnparseableVersion,
    /// Envelope version disagreed with the snapshot body's `loaded_at`.
    InconsistentVersion {
        envelope: DateTime<Utc>,
        loaded_at: DateTime<Utc>,
    },
    /// A failover snapshot is older than the applied authority.
    OlderThanApplied {
        applied: DateTime<Utc>,
        incoming: DateTime<Utc>,
    },
    /// The committed stamp is implausibly far in the DP's future — a skewed or
    /// hostile CP clock. Admitting it would poison the monotonic freshness
    /// watermark, so it fails closed instead of being clamped into authority.
    ImplausiblyFutureStamp {
        committed: DateTime<Utc>,
        now: DateTime<Utc>,
        tolerance_secs: i64,
    },
}

/// Reconcile `ConfigUpdate.version` against the parsed snapshot's `loaded_at`.
///
/// Freshness must describe the committed GatewayConfig body, not an arbitrary
/// envelope string. On success returns the committed `loaded_at` (never a
/// fabricated timestamp). Inconsistent or unparseable inputs fail closed.
pub fn reconcile_snapshot_version(
    envelope_version: &str,
    loaded_at: DateTime<Utc>,
) -> Result<DateTime<Utc>, VersionReconcileError> {
    // Prefer exact CP stamp parity (`loaded_at.to_rfc3339()`), then accept
    // equivalent RFC3339 encodings of the same instant.
    if envelope_version == loaded_at.to_rfc3339() {
        return Ok(loaded_at);
    }
    let Some(envelope) = DateTime::parse_from_rfc3339(envelope_version)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
    else {
        return Err(VersionReconcileError::UnparseableEnvelope);
    };
    if envelope != loaded_at {
        return Err(VersionReconcileError::Inconsistent {
            envelope,
            loaded_at,
        });
    }
    Ok(loaded_at)
}

/// Monotonic max of an optional prior watermark and a newly committed stamp.
pub fn monotonic_watermark(
    prior: Option<DateTime<Utc>>,
    committed: DateTime<Utc>,
) -> DateTime<Utc> {
    match prior {
        Some(prev) if prev > committed => prev,
        _ => committed,
    }
}

/// Compare two gateway snapshots by their effective serialized content.
///
/// CP-local `loaded_at` stamps are deliberately excluded: independently
/// polling CPs can produce identical snapshots with different timestamps.
/// Object keys are canonicalized recursively so map insertion order cannot
/// create a false mismatch; array order remains significant.
///
/// This compares only `GatewayConfig` JSON. CP full snapshots deliver gateway
/// trust bundles exclusively through `ConfigUpdate.trust_bundles_json`, so
/// older-cross-source identical-fallback decisions must use
/// [`authoritative_snapshot_payload_matches`] instead.
pub fn gateway_config_content_matches(current: &GatewayConfig, incoming: &GatewayConfig) -> bool {
    let (Ok(mut current), Ok(mut incoming)) = (
        serde_json::to_value(current),
        serde_json::to_value(incoming),
    ) else {
        return false;
    };
    let Value::Object(current_object) = &mut current else {
        return false;
    };
    let Value::Object(incoming_object) = &mut incoming else {
        return false;
    };
    current_object.remove("loaded_at");
    incoming_object.remove("loaded_at");
    canonical_json_value(current) == canonical_json_value(incoming)
}

/// Build the bounded trust-equivalence view for an accepted explicit CP trust
/// material state.
///
/// `None` means explicitly cleared/absent CP trust (Clear), not an unestablished
/// Unknown side channel. Fingerprints are order-insensitive for federated
/// domains and certificate/JWT authority membership.
pub fn gateway_trust_equivalence_state(
    trust: Option<&RuntimeTrustBundleSet>,
) -> GatewayTrustEquivalenceState {
    match trust {
        None => GatewayTrustEquivalenceState::Absent,
        Some(trust) => GatewayTrustEquivalenceState::Present {
            fingerprint: fingerprint_runtime_trust_bundles(trust),
        },
    }
}

/// Resolve the trust equivalence state to record after an accepted FULL_SNAPSHOT.
///
/// `side_channel_trust` is `Some` for an accepted explicit Clear/Replace and
/// `None` for an empty/Unchanged side channel. Unchanged preserves any prior
/// remembered state; with no prior authority it remains
/// [`GatewayTrustEquivalenceState::Unknown`] and must never default to Absent.
pub fn resolve_authority_trust_after_snapshot(
    prior: Option<&AppliedSnapshotAuthority>,
    side_channel_trust: Option<GatewayTrustEquivalenceState>,
) -> GatewayTrustEquivalenceState {
    match side_channel_trust {
        Some(trust) => trust,
        None => prior
            .map(|authority| authority.gateway_trust.clone())
            .unwrap_or(GatewayTrustEquivalenceState::Unknown),
    }
}

/// Compare the complete authoritative ConfigSync snapshot payload.
///
/// Includes GatewayConfig content (excluding `loaded_at`) and the effective
/// CP gateway-trust state from the side channel. Fails closed when either side
/// is [`GatewayTrustEquivalenceState::Unknown`], when `incoming_trust` is
/// `None` (empty/unchanged mixed-version channel), or when comparison inputs
/// are otherwise unavailable. Unknown vs Unknown is not equivalence.
pub fn authoritative_snapshot_payload_matches(
    current_config: &GatewayConfig,
    current_trust: &GatewayTrustEquivalenceState,
    incoming_config: &GatewayConfig,
    incoming_trust: Option<&GatewayTrustEquivalenceState>,
) -> bool {
    let Some(incoming_trust) = incoming_trust else {
        return false;
    };
    if !current_trust.is_comparable() || !incoming_trust.is_comparable() {
        return false;
    }
    gateway_config_content_matches(current_config, incoming_config)
        && current_trust == incoming_trust
}

/// Record the last accepted CP gateway-trust equivalence view on authority.
///
/// No-op when authority has not been established yet. Callers must invoke this
/// after every accepted trust Replace/Clear (FULL_SNAPSHOT or trust-only DELTA)
/// so later identical-fallback comparisons stay synchronized. Pass only
/// comparable states from explicit Clear/Replace — never invent Absent from an
/// Unchanged side channel.
pub fn record_applied_gateway_trust(
    authority: &mut Option<AppliedSnapshotAuthority>,
    trust: GatewayTrustEquivalenceState,
) {
    if let Some(existing) = authority.as_mut() {
        existing.gateway_trust = trust;
    }
}

fn fingerprint_runtime_trust_bundles(trust: &RuntimeTrustBundleSet) -> String {
    let mut hasher = Sha256::new();
    hash_trust_bundle(&mut hasher, &trust.local);
    let mut federated_domains: Vec<_> = trust.federated.keys().collect();
    federated_domains.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    for domain in federated_domains {
        hasher.update(domain.as_str().as_bytes());
        hasher.update([0xff]);
        if let Some(bundle) = trust.federated.get(domain) {
            hash_trust_bundle(&mut hasher, bundle);
        }
    }
    hex::encode(hasher.finalize())
}

fn hash_trust_bundle(hasher: &mut Sha256, bundle: &TrustBundle) {
    hasher.update(bundle.trust_domain.as_str().as_bytes());
    hasher.update([0x00]);

    let mut authorities = bundle.x509_authorities.clone();
    authorities.sort_unstable();
    hasher.update((authorities.len() as u64).to_le_bytes());
    for der in authorities {
        hasher.update((der.len() as u64).to_le_bytes());
        hasher.update(&der);
    }

    let mut jwt_authorities = bundle.jwt_authorities.clone();
    jwt_authorities.sort_by(|left, right| {
        (&left.key_id, &left.public_key_pem).cmp(&(&right.key_id, &right.public_key_pem))
    });
    hasher.update((jwt_authorities.len() as u64).to_le_bytes());
    for jwt in jwt_authorities {
        hasher.update((jwt.key_id.len() as u64).to_le_bytes());
        hasher.update(jwt.key_id.as_bytes());
        hasher.update((jwt.public_key_pem.len() as u64).to_le_bytes());
        hasher.update(jwt.public_key_pem.as_bytes());
    }

    match bundle.refresh_hint_seconds {
        Some(hint) => {
            hasher.update([0x01]);
            hasher.update(hint.to_le_bytes());
        }
        None => hasher.update([0x00]),
    }
}

fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, canonical_json_value(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_json_value).collect())
        }
        other => other,
    }
}

/// Advance (or establish) freshness authority from a timestamp actually
/// committed into active config (full snapshot `loaded_at` or accepted
/// resource-delta `poll_timestamp` / resulting `loaded_at`).
///
/// The watermark is monotonic: same-source recovery that intentionally applies
/// an older body still keeps the highest known ordering for later cross-source
/// fencing. Source URL is always updated to the committing CP. Gateway-trust
/// equivalence state is preserved on existing authority (resource deltas do not
/// invent Clear/Absent); new authority starts with
/// [`GatewayTrustEquivalenceState::Unknown`] until an accepted explicit trust
/// Clear/Replace establishes a comparable state.
pub fn advance_authority_from_committed(
    authority: &mut Option<AppliedSnapshotAuthority>,
    source_cp_url: &str,
    committed: DateTime<Utc>,
) {
    match authority {
        Some(existing) => {
            existing.version = Some(monotonic_watermark(existing.version, committed));
            existing.source_cp_url = source_cp_url.to_string();
        }
        None => {
            *authority = Some(AppliedSnapshotAuthority {
                version: Some(committed),
                source_cp_url: source_cp_url.to_string(),
                gateway_trust: GatewayTrustEquivalenceState::Unknown,
            });
        }
    }
}

/// True when an accepted non-empty resource delta should advance freshness.
///
/// Rejected deltas and empty / trust-only side-channel updates must not.
pub fn resource_delta_advances_authority(accepted: bool, was_empty: bool) -> bool {
    accepted && !was_empty
}

/// Canonical `(scheme, host, port)` identity of a configured CP endpoint URL.
///
/// Scheme and host are ASCII-lowercased; the port defaults per scheme when the
/// URL omits it. Path, query, and fragment are ignored so harmless equivalent
/// spellings (e.g. a trailing slash) do not read as distinct endpoints. Returns
/// `None` for a URL that cannot be canonicalized (unparseable, missing
/// scheme/host, or an unknown scheme without an explicit port) so the caller can
/// fail closed.
fn canonical_cp_endpoint(url: &str) -> Option<(String, String, u16)> {
    let uri = url.parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let host = uri.host()?.to_ascii_lowercase();
    let port = match uri.port_u16() {
        Some(port) => port,
        None => match scheme.as_str() {
            "https" | "grpcs" => 443,
            "http" | "grpc" => 80,
            // Unknown scheme with no explicit port: cannot canonicalize safely.
            _ => return None,
        },
    };
    Some((scheme, host, port))
}

/// True when two configured CP endpoint URLs address the same source.
///
/// Same-source detection gates whether a FULL_SNAPSHOT is a reconnect/recovery
/// (always accepted, monotonic watermark) or a cross-source failover candidate
/// (subject to stale-fencing). Comparing raw URL strings would treat harmless
/// equivalent spellings such as a trailing slash as cross-source and needlessly
/// fence them; canonicalizing to `(scheme, host, port)` avoids that while
/// keeping distinct schemes/hosts/ports distinct.
///
/// Fails closed for malformed input: if either URL cannot be canonicalized,
/// only a byte-identical spelling is treated as same-source, so a parse failure
/// can never merge two genuinely different endpoints into one.
pub fn cp_endpoints_same_source(a: &str, b: &str) -> bool {
    match (canonical_cp_endpoint(a), canonical_cp_endpoint(b)) {
        (Some(canonical_a), Some(canonical_b)) => canonical_a == canonical_b,
        _ => a == b,
    }
}

/// Refuse a committed snapshot stamp that is implausibly far in the DP's future.
///
/// A committed `loaded_at` more than [`CONFIGSYNC_MAX_FUTURE_SKEW_SECS`] ahead of
/// `now` indicates a skewed or hostile CP clock. Admitting it into the monotonic
/// freshness watermark would fence every correct-clock failover CP carrying
/// genuinely newer config until wall time caught up, so it fails closed. The
/// stamp is never clamped into authority — the caller terminates the stream and
/// fails over while last-known-good config keeps serving. Stamps at or behind
/// `now`, and stamps within tolerance, are admitted unchanged.
pub fn evaluate_snapshot_clock_skew(
    incoming_committed: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), StaleSnapshotReject> {
    if incoming_committed.signed_duration_since(now)
        > chrono::Duration::seconds(CONFIGSYNC_MAX_FUTURE_SKEW_SECS)
    {
        return Err(StaleSnapshotReject::ImplausiblyFutureStamp {
            committed: incoming_committed,
            now,
            tolerance_secs: CONFIGSYNC_MAX_FUTURE_SKEW_SECS,
        });
    }
    Ok(())
}

/// True only when the FULL_SNAPSHOT disposition actually depends on the
/// expensive complete-payload equivalence check.
///
/// The identical-payload exception is consulted by
/// [`evaluate_full_snapshot_authority`] in exactly one case: a cross-source
/// candidate (different CP than the applied authority) that is strictly older
/// than a parseable applied watermark. Every other case — no authority yet,
/// same-source reconnect, an authority with no comparable version, or an
/// incoming stamp at/after the applied watermark — is decided without the
/// exception, so the two canonical JSON conversions can be skipped (nit N1).
///
/// Fails closed: returns `false` (compute nothing / assume no match) whenever the
/// exception is not strictly required.
pub fn snapshot_requires_older_payload_exception(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_committed: DateTime<Utc>,
    source_cp_url: &str,
) -> bool {
    let Some(authority) = authority else {
        return false;
    };
    if cp_endpoints_same_source(&authority.source_cp_url, source_cp_url) {
        return false;
    }
    let Some(applied) = authority.version else {
        return false;
    };
    incoming_committed < applied
}

/// Decide whether an incoming FULL_SNAPSHOT may replace the active config.
///
/// `incoming_committed` must already be the reconciled snapshot `loaded_at`
/// (see [`reconcile_snapshot_version`]). Returns the watermark to record after
/// a successful apply (monotonic vs any prior authority).
///
/// Rules:
/// - Same-source snapshots are always accepted (reconnect / recovery). The
///   recorded watermark stays monotonic even when the recovery body is older.
/// - Cross-source failover snapshots are fenced when a parseable applied
///   authority exists and the incoming committed stamp is strictly older,
///   unless the incoming snapshot's complete authoritative payload matches
///   the applied payload exactly (GatewayConfig content excluding `loaded_at`
///   plus effective CP gateway-trust state). Equivalent complete payloads
///   establish a safe delta base while the recorded watermark stays monotonic.
/// - With no applied authority (first snapshot) or an authority whose own
///   version is unknown, there is nothing to fence against, so the snapshot is
///   accepted and its committed stamp adopted.
pub fn evaluate_full_snapshot_authority(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_committed: DateTime<Utc>,
    source_cp_url: &str,
    incoming_matches_applied_config: bool,
) -> Result<DateTime<Utc>, StaleSnapshotReject> {
    let Some(authority) = authority else {
        return Ok(incoming_committed);
    };

    if cp_endpoints_same_source(&authority.source_cp_url, source_cp_url) {
        return Ok(monotonic_watermark(authority.version, incoming_committed));
    }

    let Some(applied) = authority.version else {
        return Ok(incoming_committed);
    };

    if incoming_committed < applied && !incoming_matches_applied_config {
        return Err(StaleSnapshotReject::OlderThanApplied {
            applied,
            incoming: incoming_committed,
        });
    }

    Ok(monotonic_watermark(Some(applied), incoming_committed))
}

/// How the ConfigSync stream must react to an incoming FULL_SNAPSHOT.
///
/// A fenced (older or unorderable cross-source) snapshot must **terminate** the
/// stream, not merely be skipped on a stream that keeps reading. Continuing
/// would let the same stale fallback CP's next DELTA apply against newer
/// config (issue #2970).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullSnapshotStreamDisposition {
    /// Apply the snapshot; adopt `version` as the new applied watermark once
    /// the apply succeeds.
    Apply { version: DateTime<Utc> },
    /// Refuse the snapshot and terminate the stream so no later message from
    /// the same source can apply; the outer loop fails over with backoff.
    RefuseAndTerminate(StaleSnapshotReject),
}

/// Decide how the ConfigSync stream must react after version reconciliation.
pub fn full_snapshot_stream_disposition(
    authority: Option<&AppliedSnapshotAuthority>,
    incoming_committed: DateTime<Utc>,
    source_cp_url: &str,
    incoming_matches_applied_config: bool,
) -> FullSnapshotStreamDisposition {
    match evaluate_full_snapshot_authority(
        authority,
        incoming_committed,
        source_cp_url,
        incoming_matches_applied_config,
    ) {
        Ok(version) => FullSnapshotStreamDisposition::Apply { version },
        Err(reject) => FullSnapshotStreamDisposition::RefuseAndTerminate(reject),
    }
}

/// Map a reconcile failure onto the stream-terminating refusal enum.
pub fn stale_reject_from_reconcile(err: VersionReconcileError) -> StaleSnapshotReject {
    match err {
        VersionReconcileError::UnparseableEnvelope => StaleSnapshotReject::UnparseableVersion,
        VersionReconcileError::Inconsistent {
            envelope,
            loaded_at,
        } => StaleSnapshotReject::InconsistentVersion {
            envelope,
            loaded_at,
        },
    }
}

/// How the stream must react when a FULL_SNAPSHOT fails parse/validate/apply.
///
/// An unusable FULL_SNAPSHOT is treated as an authoritative reload that did not
/// land. Keeping the stream open would let later deltas apply against a base
/// that missed those changes, so the subscription always terminates while the
/// last-known-good config keeps serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFailureStreamDisposition {
    /// Terminate and reconnect so the next subscription must establish a fresh
    /// authoritative FULL_SNAPSHOT base before any DELTA can apply.
    TerminateAndReconnect,
}

/// Decide stream reaction for a refused/invalid/unusable FULL_SNAPSHOT.
///
/// Independent of whether an earlier base was accepted on this subscription —
/// mid-stream full-snapshot failures must not continue reading deltas.
pub fn snapshot_failure_stream_disposition(
    _subscription_base_applied: bool,
) -> SnapshotFailureStreamDisposition {
    SnapshotFailureStreamDisposition::TerminateAndReconnect
}

/// Per-subscription apply gating for FULL_SNAPSHOT vs DELTA.
///
/// Startup readiness (`startup_ready`) is intentionally separate: library/test
/// callers may omit that flag and skip startup-only wait/capability work, but
/// every new subscription still starts without a committed base and must accept
/// a FULL_SNAPSHOT before any DELTA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriptionApplyState {
    /// True only after this subscription successfully accepted a FULL_SNAPSHOT.
    pub base_applied: bool,
}

impl SubscriptionApplyState {
    /// Every new ConfigSync subscription starts without a committed base.
    pub fn new() -> Self {
        Self {
            base_applied: false,
        }
    }

    /// Record that a FULL_SNAPSHOT was successfully accepted on this stream.
    pub fn note_full_snapshot_accepted(&mut self) {
        self.base_applied = true;
    }
}

/// Why a DELTA was refused before any apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaRefuse {
    /// No valid FULL_SNAPSHOT base has been committed on this subscription yet.
    BeforeSnapshotBase,
}

/// Each new subscription must accept exactly a valid FULL_SNAPSHOT base before
/// any DELTA can apply. A pre-snapshot DELTA must terminate without applying.
pub fn evaluate_delta_against_subscription_base(
    subscription_base_applied: bool,
) -> Result<(), DeltaRefuse> {
    if subscription_base_applied {
        Ok(())
    } else {
        Err(DeltaRefuse::BeforeSnapshotBase)
    }
}

/// Why a non-empty DELTA must terminate the stream (issue #2394).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaRejectionKind {
    /// JSON body could not be classified — fail closed.
    ParseFailure,
    /// Trust side-channel was invalid — resource deltas must not continue.
    InvalidTrustSideChannel,
    /// Resource validation/apply rejected a non-empty delta.
    NonEmptyApplyRejected,
}

/// Stream reaction after a DELTA rejection. Always terminates so a later
/// partial delta cannot apply against the wrong base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaRejectionStreamDisposition {
    TerminateAndResync,
}

pub fn delta_rejection_stream_disposition(
    _kind: DeltaRejectionKind,
) -> DeltaRejectionStreamDisposition {
    DeltaRejectionStreamDisposition::TerminateAndResync
}

/// Bounded observability for ConfigSync delta-rejection divergence.
///
/// Dimensions are fixed (no resource IDs) so `/metrics` cardinality stays
/// bounded under hostile or malformed CP pushes.
#[derive(Debug, Default)]
pub struct ConfigSyncDivergenceMetrics {
    rejected_nonempty_deltas_total: AtomicU64,
    recoveries_total: AtomicU64,
    fenced_full_snapshots_total: AtomicU64,
    diverged: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSyncDivergenceMetricsSnapshot {
    pub rejected_nonempty_deltas_total: u64,
    pub recoveries_total: u64,
    pub fenced_full_snapshots_total: u64,
    pub diverged: bool,
}

impl ConfigSyncDivergenceMetrics {
    pub fn record_rejection(&self) {
        self.rejected_nonempty_deltas_total
            .fetch_add(1, Ordering::Relaxed);
        self.diverged.store(true, Ordering::Release);
    }

    /// Record a FULL_SNAPSHOT the DP fenced without applying
    /// (stale/older, unorderable/inconsistent, or an implausibly-future clock
    /// stamp). Fixed-cardinality operator signal for skew/hostile-CP fencing.
    /// Does not touch sticky `diverged`: fencing keeps last-known-good config
    /// and is a failover event, not a delta-rejection divergence.
    pub fn record_fenced_snapshot(&self) {
        self.fenced_full_snapshots_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Clear sticky divergence only after an authoritative FULL_SNAPSHOT is
    /// accepted. Increments the recovery counter when clearing an active
    /// diverged state.
    pub fn record_recovery_after_full_snapshot(&self) -> bool {
        let was_diverged = self.diverged.swap(false, Ordering::AcqRel);
        if was_diverged {
            self.recoveries_total.fetch_add(1, Ordering::Relaxed);
        }
        was_diverged
    }

    pub fn is_diverged(&self) -> bool {
        self.diverged.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> ConfigSyncDivergenceMetricsSnapshot {
        ConfigSyncDivergenceMetricsSnapshot {
            rejected_nonempty_deltas_total: self
                .rejected_nonempty_deltas_total
                .load(Ordering::Relaxed),
            recoveries_total: self.recoveries_total.load(Ordering::Relaxed),
            fenced_full_snapshots_total: self.fenced_full_snapshots_total.load(Ordering::Relaxed),
            diverged: self.is_diverged(),
        }
    }
}

/// Why peer Ferrum version negotiation failed (issue #2395).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatError {
    /// Peer omitted its version entirely.
    Missing,
    /// Peer (or local) version is not valid SemVer.
    Malformed { peer: String },
    /// Parsed SemVer major/minor do not match.
    Incompatible { local: String, peer: String },
}

impl VersionCompatError {
    pub fn message(&self, local_role: &str, peer_role: &str, local_version: &str) -> String {
        match self {
            VersionCompatError::Missing => format!(
                "{peer_role} did not report its version. {local_role} is running Ferrum Edge v{local_version}. \
                 Upgrade the {peer_role} to a version that supports version negotiation."
            ),
            VersionCompatError::Malformed { peer } => format!(
                "Unable to parse {peer_role} version for compatibility check \
                 ({local_role}={local_version}, {peer_role}={peer}). \
                 Versions must be valid SemVer (major.minor.patch with optional prerelease/build)."
            ),
            VersionCompatError::Incompatible { local, peer } => format!(
                "Version mismatch: {local_role} is v{local} but {peer_role} is v{peer}. \
                 Major and minor versions must match. \
                 Upgrade the CP first, then upgrade DPs to the same major.minor version."
            ),
        }
    }
}

/// CP/DP version compatibility using SemVer.
///
/// # Prerelease policy
///
/// Compatibility compares **major and minor only**. Patch, prerelease
/// (`-rc.1`), and build metadata (`+gitsha`) differences are allowed when
/// major.minor match. Empty and unparseable versions are rejected on both
/// CP admission and every DP ConfigUpdate envelope, including heartbeats, so
/// an incompatible peer cannot keep an otherwise-refused stream alive.
pub fn check_peer_version_compatibility(
    local_version: &str,
    peer_version: &str,
) -> Result<(), VersionCompatError> {
    if peer_version.is_empty() {
        return Err(VersionCompatError::Missing);
    }

    let Ok(local) = Version::parse(local_version) else {
        return Err(VersionCompatError::Malformed {
            peer: peer_version.to_string(),
        });
    };
    let Ok(peer) = Version::parse(peer_version) else {
        return Err(VersionCompatError::Malformed {
            peer: peer_version.to_string(),
        });
    };

    if local.major != peer.major || local.minor != peer.minor {
        return Err(VersionCompatError::Incompatible {
            local: local_version.to_string(),
            peer: peer_version.to_string(),
        });
    }

    Ok(())
}

/// Multi-CP reconnect backoff state. Backoff follows the failure sequence and
/// is not reset merely because the selected CP index changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCpBackoffState {
    pub backoff_secs: u64,
    pub current_cp_index: usize,
    pub full_cycle_count: u32,
}

impl MultiCpBackoffState {
    pub fn new() -> Self {
        Self {
            backoff_secs: BACKOFF_INITIAL_SECS,
            current_cp_index: 0,
            full_cycle_count: 0,
        }
    }
}

impl Default for MultiCpBackoffState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of one ConfigSync stream attempt for backoff accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSyncAttemptOutcome {
    /// Transport/RPC failure before this attempt accepted any config.
    ConnectionError,
    /// Transport/RPC failure after this attempt already accepted config.
    /// Counts as healthy progress for backoff reset while still reconnecting.
    ConnectionErrorAfterConfig,
    /// Stream ended cleanly after delivering at least one config message.
    CleanCloseAfterConfig,
    /// Stream accepted Subscribe then ended without a config message.
    CleanCloseWithoutConfig,
    /// Operator-driven disconnect (primary retry / TLS reload). Not a failure.
    IntentionalDisconnect,
    /// A cross-source FULL_SNAPSHOT was fenced as stale/unorderable, so the DP
    /// refused the stream before any delta from it could apply. Treated exactly
    /// like a connection failure for failover/backoff accounting: advance to the
    /// next CP and keep accumulating backoff. It must never reset backoff — a
    /// stale fallback CP is not healthy progress (issue #2970).
    StaleSnapshotFenced,
    /// The subscription never established a valid FULL_SNAPSHOT base (malformed,
    /// inconsistent, rejected, or a pre-snapshot DELTA). Fail over with
    /// accumulating backoff; never treat as delivered config.
    InvalidSubscriptionBase,
    /// A DELTA carried an envelope/body timestamp mismatch or an
    /// implausibly-future committed timestamp. Fail over with accumulating
    /// backoff so a skewed or hostile CP cannot poison the freshness watermark.
    InvalidDeltaFreshness,
    /// An unusable FULL_SNAPSHOT arrived after a base was already accepted, or a
    /// non-empty DELTA was rejected. Keep serving last-known-good config, reset
    /// backoff, and reconnect to the same CP for a fresh authoritative snapshot
    /// (issues #2394 / mid-stream snapshot failure).
    ResyncAfterAcceptedConfig,
}

/// Advance multi-CP index/backoff after one attempt.
///
/// Returns whether the caller should sleep before the next attempt.
pub fn advance_multi_cp_backoff(
    state: &mut MultiCpBackoffState,
    cp_count: usize,
    outcome: ConfigSyncAttemptOutcome,
) -> bool {
    match outcome {
        ConfigSyncAttemptOutcome::IntentionalDisconnect => {
            state.backoff_secs = BACKOFF_INITIAL_SECS;
            false
        }
        ConfigSyncAttemptOutcome::CleanCloseAfterConfig
        | ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
        | ConfigSyncAttemptOutcome::ResyncAfterAcceptedConfig => {
            // Healthy progress (or a resync after previously accepted config)
            // resets delay to the initial value before the next attempt.
            state.backoff_secs = BACKOFF_INITIAL_SECS;
            true
        }
        ConfigSyncAttemptOutcome::ConnectionError
        | ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
        | ConfigSyncAttemptOutcome::StaleSnapshotFenced
        | ConfigSyncAttemptOutcome::InvalidSubscriptionBase
        | ConfigSyncAttemptOutcome::InvalidDeltaFreshness => {
            if cp_count > 1 {
                let next_index = (state.current_cp_index + 1) % cp_count;
                if next_index == 0 {
                    state.full_cycle_count = state.full_cycle_count.saturating_add(1);
                }
                state.current_cp_index = next_index;
            }
            // Sleep with the current backoff, then grow for the next failure.
            // Callers sleep first, then invoke `grow_backoff_after_sleep`.
            true
        }
    }
}

/// Grow backoff after a failure sleep. No-op after successful/intentional paths
/// that already reset `backoff_secs`.
pub fn grow_backoff_after_failure_sleep(state: &mut MultiCpBackoffState) {
    state.backoff_secs = next_backoff_secs(state.backoff_secs, true);
}

/// Deterministic failure-sleep sequence for continuously failing CPs.
///
/// Used by tests to prove N≥2 dead CPs still reach [`BACKOFF_MAX_SECS`].
#[allow(dead_code)] // external unit-test contract; production grows the live state directly
pub fn failure_backoff_sequence(cp_count: usize, attempts: usize) -> Vec<u64> {
    let mut state = MultiCpBackoffState::new();
    let mut sleeps = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let should_sleep = advance_multi_cp_backoff(
            &mut state,
            cp_count,
            ConfigSyncAttemptOutcome::ConnectionError,
        );
        if should_sleep {
            sleeps.push(state.backoff_secs);
            grow_backoff_after_failure_sleep(&mut state);
        }
    }
    sleeps
}

/// Whether the application-silence watchdog may fire on this subscription.
///
/// Two independent reasons to arm it:
/// - The CP confirmed heartbeat support (`ConfigUpdate.heartbeat_negotiated`),
///   so continued silence means the keepalive it promised stopped arriving.
/// - No message has arrived at all yet. Every CP — including one that predates
///   heartbeats — sends its initial FULL_SNAPSHOT immediately on Subscribe, so a
///   stream that is silent before its first message is anomalous at any version.
///   Without this, a blackholed reconnect against an unnegotiated stream would
///   hang forever on `message().await` (issue #2967).
///
/// It stays disarmed only in the case it must: a mixed-version stream from a CP
/// that never negotiated heartbeats, after that CP has proven liveness with at
/// least one message. Such a stream is legitimately silent while idle, and
/// HTTP/2 PING + TCP keepalive still cover it.
pub fn silence_watchdog_armed(heartbeats_negotiated: bool, received_any_message: bool) -> bool {
    heartbeats_negotiated || !received_any_message
}

/// A heartbeat frame is admissible only after this subscription has accepted
/// its authoritative FULL_SNAPSHOT base and that snapshot negotiated heartbeat
/// support. Heartbeats are liveness-only and must never establish either state.
pub fn heartbeat_frame_admissible(
    subscription_base_applied: bool,
    heartbeats_negotiated: bool,
) -> bool {
    subscription_base_applied && heartbeats_negotiated
}

/// True when a silence interval exceeds the ConfigSync liveness bound.
#[allow(dead_code)] // external unit-test contract for the liveness boundary
pub fn silence_exceeds_liveness(silence_secs: u64) -> bool {
    silence_secs >= CONFIGSYNC_MAX_SILENCE_SECS
}

/// Cap used by tests/docs — exported so callers can assert the documented max.
#[allow(dead_code)] // external unit-test contract for the documented ceiling
pub fn backoff_max_secs() -> u64 {
    BACKOFF_MAX_SECS
}

/// Map a transport/RPC failure onto the backoff outcome using whether this
/// attempt already accepted config (issue #2968).
pub fn connection_error_outcome(delivered_config: bool) -> ConfigSyncAttemptOutcome {
    if delivered_config {
        ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
    } else {
        ConfigSyncAttemptOutcome::ConnectionError
    }
}
