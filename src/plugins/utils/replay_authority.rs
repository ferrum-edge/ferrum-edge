//! One shared, fail-closed **single-use replay authority** for every gateway
//! admission control whose security property is "this exact proof may be
//! accepted at most once".
//!
//! Two plugins own such a property today — `jwks_auth`'s RFC 9449 DPoP proofs
//! (`jti` + JWK thumbprint) and `hmac_auth`'s `ferrum-hmac-v2` signed nonces —
//! and they must not grow two incompatible replay infrastructures with
//! different ownership, capacity, reload, and HA semantics. Everything that
//! decides whether a marker is fresh lives here.
//!
//! # What is stored
//!
//! Nothing that came off the wire. A marker is a fixed-size SHA-256 digest of a
//! **protection domain** and a **proof identity**, produced by
//! [`ReplayDomain::marker`]. No raw token, proof JWT, `jti`, nonce, signature,
//! username, subject, issuer, request path, query string, body digest, or
//! secret is retained, keyed, logged, or sent to a shared backend. Redis keys
//! reach `MONITOR`, `SLOWLOG`, and the Redis client's own error logging, so the
//! only thing that may become a key is a digest.
//!
//! Every field of a domain and of a marker is written through
//! [`replay_partition::PartitionHasher`], which frames each field as
//! `len(label) || label || len(value) || value`. Raw delimiter concatenation
//! (`a|b`) is structurally unsafe: an attacker-chosen `jti` containing the
//! delimiter could otherwise reproduce another domain's preimage.
//!
//! # Ownership: the lane, not the plugin instance
//!
//! Replay state is owned by a **stable policy identity** — `namespace` +
//! plugin name + plugin-config id (+ an optional plugin-chosen sub-domain such
//! as a digest of one provider's trust anchor) — and never by the plugin object
//! a `PluginCache` rebuild happened to construct. A `jwks_auth` provider that
//! reloads with an equivalent configuration rejoins the same
//! [`ProcessReplayLane`] and inherits its live markers; an empty replacement
//! cache is exactly the reload replay opening this module exists to close.
//!
//! A sub-domain must be *semantic* for the same reason. `jwks_auth` derives one
//! from each provider's exact issuer realm rather than from its JWKS contents,
//! source URL, or position in the `providers` array: an ordinal is not an
//! identity, and hashing a key set or endpoint would otherwise reopen live
//! proofs on an ordinary rotation. Reordering an unchanged list would strand a
//! provider's live markers in a lane nothing consults and readmit a proof it
//! had already claimed.
//!
//! Lanes live in a process-global registry ([`PROCESS_REPLAY_LANES`]) held by
//! **strong** reference, so a deleted or renamed policy leaves its lane behind
//! as a tombstone until every marker it retains has expired. Reclamation is
//! cold-path only (lane creation), bounded, and never touches a live marker:
//! [`ProcessReplayLane::all_markers_expired`] reads one atomic high-water mark
//! rather than scanning the map.
//!
//! # Capacity never forgets a live marker
//!
//! At capacity the lane prunes **expired** entries and nothing else. If no
//! expired slot can be reclaimed the new protected request is refused with the
//! fixed [`ReplayAdmission::CapacityRefused`] classification. Evicting an
//! unexpired marker to admit a new request — the previous `DpopJtiCache`
//! behavior — treats capacity pressure as permission to forget a replay marker,
//! which lets a client with one valid credential burn other clients' protection
//! by generating unique proofs. Capacity degrades into refusal, never into
//! silent unprotection. Repeated refusals while every retained marker is still
//! live are O(1): a conservative earliest-expiry lower bound skips the map walk
//! until an expiry is actually due. Ordinary admission publishes that bound
//! only earlier (`fetch_min`) under a lock-free active-writer count plus a
//! completed-revision counter; prune may store a later bound only after a scan
//! that observed no active writer and no missed completed revision. An even/odd
//! seqlock is not used: two writers on different DashMap shards can both be in
//! flight while a single parity bit looks stable.
//!
//! The shared lane retains markers; each live authority enforces the
//! `max_entries` *it was admitted with* against that shared count. An equivalent
//! reload that raises or lowers the configured capacity therefore takes effect
//! without rebuilding the lane, evicting a live marker, or changing the replay
//! domain. Lowering the limit refuses new admissions once the shared count meets
//! the new cap; raising it restores headroom. An expired occupied marker is a
//! new use of that proof: it may refresh in place only when the retained count
//! is already within this generation's cap, and otherwise goes through the same
//! expired-only prune-and-reserve path as a vacant insert. The first constructor
//! does **not** freeze a cap onto the lane — that would make a later equivalent
//! generation's configured capacity silently inert, and would make duplicate
//! equivalent constructors order-dependent.
//!
//! # Retention is fixed, not configured
//!
//! Each caller declares one compile-time retention horizon that dominates the
//! widest span over which *any admissible configuration* can accept one
//! unchanged proof (for DPoP: `2 * max clock skew`). This is not a knob:
//!
//! * a later generation that **widens** its clock skew would otherwise make a
//!   captured proof acceptable again after its shorter marker had already been
//!   reclaimed, and nothing can resurrect a dropped marker;
//! * `SET … NX EX` cannot rewrite the TTL of a key it did not create, so a
//!   shared marker written under an old, shorter TTL expires early no matter
//!   what a new generation declares.
//!
//! Because every generation and every replica writes the same horizon, an
//! existing marker always keeps at least the protection interval it was
//! admitted with, across reloads and rolling deployments alike.
//!
//! # Scope is an explicit operator declaration
//!
//! [`ReplayScope`] has **no default**. A gateway cannot observe its own replica
//! count, so "is this deployment single-process?" is an auditable declaration
//! rather than an inference. `process` asserts a single-process/development
//! deployment; `shared` points every replica at one authority (an atomic Redis
//! `SET … NX EX`). There is deliberately no fallback between them: falling back
//! to process-local acceptance when the shared authority is unreachable
//! reinstates exactly the cross-replica bypass the shared authority exists to
//! close. A shared-backend timeout, partition, authentication failure,
//! corruption, capacity failure, or proven-unsafe Redis eviction policy
//! rejects the protected request. Replay Redis clients additionally refuse a
//! server that cannot prove `maxmemory == 0` or `maxmemory_policy == noeviction`,
//! so `SET … NX EX` cannot silently recreate a still-live marker after Redis
//! evicted it. Durability and failover remain operator-owned.
//!
//! Process lanes enforce a one-quarter per-principal share of the configured
//! marker ceiling. Shared Redis scopes do not have per-principal quotas: one
//! principal can still fill a shared store and make claims fail closed for
//! everyone under `maxmemory`/`noeviction`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::redis_rate_limiter::RedisRateLimitClient;
use super::replay_partition::PartitionHasher;

/// Upper bound on distinct process replay lanes retained for the life of the
/// process.
///
/// Lanes are keyed by operator-controlled configuration identity, so the key
/// space must be bounded. Admission fails closed at the cap rather than
/// silently dropping replay history.
pub const MAX_PROCESS_REPLAY_LANES: usize = 1_024;

/// Fixed non-secret marker value written for a shared claim. The claim is
/// proven by the key existing, so nothing derived from a credential is stored.
const SHARED_MARKER_RECORD: &[u8] = b"ferrum-replay-marker-v1";

/// Redis key component that separates replay markers from any other keyspace
/// sharing a configured prefix.
const SHARED_KEY_COMPONENT: &str = "replay";

/// Process-relative monotonic base. Markers store an expiry in milliseconds
/// since this instant so an entry is 8 bytes and no `Instant` is retained.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Monotonic milliseconds since [`PROCESS_START`].
///
/// Saturating: a process running longer than ~584 million years would clamp
/// rather than wrap, which is the fail-closed direction (markers stop expiring
/// rather than expiring early).
pub fn monotonic_millis() -> u64 {
    u64::try_from(PROCESS_START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ── Observability ───────────────────────────────────────────────────────────

/// Process-global replay counters. Deliberately **unlabeled**: no namespace,
/// plugin id, provider, consumer, issuer, thumbprint, nonce, marker, route, or
/// backend error text can reach them.
static REPLAY_REJECTED: AtomicU64 = AtomicU64::new(0);
static CAPACITY_REFUSED: AtomicU64 = AtomicU64::new(0);
static AUTHORITY_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static ADMITTED_PROCESS: AtomicU64 = AtomicU64::new(0);
static ADMITTED_SHARED: AtomicU64 = AtomicU64::new(0);
static LEGACY_UNSAFE_PROFILE_ACCEPTED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the replay-authority counters for the runtime metrics endpoint.
///
/// Monotonic for the process lifetime, except `shared_authorities_unavailable`
/// and `process_lanes`, which are current cardinalities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReplayAuthorityCounters {
    /// Protected requests refused because the exact proof was already admitted.
    pub replay_rejected: u64,
    /// Protected requests refused because no expired marker slot could be
    /// reclaimed. Never an eviction of a live marker.
    pub capacity_refused: u64,
    /// Protected requests refused because the authority was unreachable,
    /// timed out, partitioned, rejected authentication, or returned an
    /// uncertain result. Never a fallback to local acceptance.
    pub authority_unavailable: u64,
    /// Markers admitted against a process-local (single-process) lane.
    pub admitted_process: u64,
    /// Markers admitted against the shared (cross-replica) authority.
    pub admitted_shared: u64,
    /// Requests accepted under an explicitly unsafe legacy freshness-only
    /// signing profile that provides no single-use guarantee.
    pub legacy_unsafe_profile_accepted: u64,
    /// Registered shared authorities whose backend is currently unavailable.
    /// Non-zero means protected requests on those policies are failing closed.
    pub shared_authorities_unavailable: u64,
    /// Registered shared authorities.
    pub shared_authorities: u64,
    /// Live process replay lanes (bounded by [`MAX_PROCESS_REPLAY_LANES`]).
    pub process_lanes: u64,
}

/// Read the replay-authority counters.
pub fn counters() -> ReplayAuthorityCounters {
    let (shared_authorities, shared_authorities_unavailable) = shared_authority_health();
    ReplayAuthorityCounters {
        replay_rejected: REPLAY_REJECTED.load(Ordering::Relaxed),
        capacity_refused: CAPACITY_REFUSED.load(Ordering::Relaxed),
        authority_unavailable: AUTHORITY_UNAVAILABLE.load(Ordering::Relaxed),
        admitted_process: ADMITTED_PROCESS.load(Ordering::Relaxed),
        admitted_shared: ADMITTED_SHARED.load(Ordering::Relaxed),
        legacy_unsafe_profile_accepted: LEGACY_UNSAFE_PROFILE_ACCEPTED.load(Ordering::Relaxed),
        shared_authorities_unavailable,
        shared_authorities,
        process_lanes: process_lane_count() as u64,
    }
}

/// Record one acceptance under an explicitly unsafe legacy freshness-only
/// profile, so operators can see that a deployment still depends on it.
pub fn record_legacy_unsafe_profile_accepted() {
    LEGACY_UNSAFE_PROFILE_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}

// ── Scope ───────────────────────────────────────────────────────────────────

/// Operator-declared deployment scope for replay state.
///
/// There is no `Default` impl on purpose. Silently defaulting to process-local
/// state is the posture that lets a captured proof be accepted once per
/// replica; the caller must require an explicit declaration whenever its
/// single-use protection is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayScope {
    /// Single-process / development contract. Replay state is stable across
    /// equivalent in-process reloads but is explicitly **not** cross-replica.
    Process,
    /// Production HA contract. Every replica serving one protection domain
    /// claims through one atomic shared authority.
    Shared,
}

impl ReplayScope {
    /// Parse the shared `replay_scope` configuration value.
    pub fn parse(plugin: &str, field: &str, value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "process" => Ok(Self::Process),
            "shared" => Ok(Self::Shared),
            _ => Err(format!(
                "{plugin}: `{field}` must be exactly `process` or `shared` — use `shared` \
                 together with `sync_mode: redis` for any deployment running more than one \
                 gateway replica, or `process` to declare a single-process deployment whose \
                 replay protection is not cross-replica"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Shared => "shared",
        }
    }
}

// ── Domain and marker identity ──────────────────────────────────────────────

/// Precomputed, fixed-size identity of one protection domain.
///
/// Built once at plugin construction (never per request) from a bounded set of
/// configuration-derived components. Two policies never share a domain, and two
/// replicas of the same policy always derive the same one — which is what makes
/// a shared claim meaningful and a rolling deployment safe.
#[derive(Clone)]
pub struct ReplayDomain {
    digest: [u8; 32],
}

impl std::fmt::Debug for ReplayDomain {
    /// The digest is not secret, but it is also not actionable, and printing it
    /// in a log line invites treating it as an identifier for correlation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayDomain(<digest>)")
    }
}

impl ReplayDomain {
    /// Derive a protection domain.
    ///
    /// * `profile` — the versioned proof profile (`ferrum-dpop-proof-v1`,
    ///   `ferrum-hmac-v2`). Two profiles never share markers, so a future
    ///   profile revision cannot be answered from an old profile's history.
    /// * `namespace` / `plugin` / `config_id` — the stable policy identity.
    /// * `sub_domain` — a bounded, configuration-derived discriminator such as
    ///   a digest of one provider's exact issuer realm. It must be *semantic*:
    ///   an ordinal position, JWKS document, key id, or source URL is not an
    ///   identity, because reordering or rotating keys would move a policy into
    ///   a fresh lane and reopen every proof it had already claimed. Never
    ///   request-controlled data.
    pub fn new(
        profile: &str,
        namespace: &str,
        plugin: &str,
        config_id: &str,
        sub_domain: &str,
    ) -> Self {
        let mut hasher = PartitionHasher::new("ferrum-edge/replay-authority/domain/v1");
        hasher.text("domain.profile", profile);
        hasher.text("domain.namespace", namespace);
        hasher.text("domain.plugin", plugin);
        hasher.text("domain.config_id", config_id);
        hasher.text("domain.sub_domain", sub_domain);
        Self {
            digest: hasher.digest(),
        }
    }

    /// Derive the marker for one proof identity inside this domain.
    ///
    /// `parts` are the components that identify the proof (for DPoP the JWK
    /// thumbprint and the `jti`; for HMAC v2 the consumer identity and client
    /// nonce). They are consumed here and never retained: only the resulting
    /// digest leaves this function.
    pub fn marker(&self, parts: &[&[u8]]) -> ReplayMarker {
        let principal = parts.first().copied().unwrap_or_default();
        self.marker_with_principal(parts, &[principal])
    }

    /// Derive a proof marker while assigning its capacity quota to an explicit
    /// verified principal. DPoP uses this so changing proof keys cannot mint
    /// fresh per-principal replay capacity for the same token holder.
    pub fn marker_with_principal(
        &self,
        parts: &[&[u8]],
        principal_parts: &[&[u8]],
    ) -> ReplayMarker {
        let mut hasher = PartitionHasher::new("ferrum-edge/replay-authority/marker/v1");
        hasher.nested("marker.domain", &self.digest);
        hasher.count("marker.parts", parts.len());
        for part in parts {
            hasher.field("marker.part", part);
        }
        let mut principal_hasher =
            PartitionHasher::new("ferrum-edge/replay-authority/principal/v1");
        principal_hasher.count("principal.parts", principal_parts.len());
        for part in principal_parts {
            principal_hasher.field("principal.part", part);
        }
        ReplayMarker {
            digest: hasher.digest(),
            principal_digest: principal_hasher.digest(),
        }
    }

    /// Raw domain digest.
    ///
    /// Opaque and non-secret: it is a hash of configuration identity only, and
    /// carries no credential, issuer, or request material. Callers use it to
    /// bind other request-scoped state to *this exact protection domain* (see
    /// `hmac_auth`'s prebuffer owner identity) and to assert domain isolation
    /// in external tests. It is deliberately not rendered by `Debug`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Stable process-lane registry key for this domain.
    ///
    /// The registry key is the domain digest in hex, so an operator-controlled
    /// namespace / config id can neither collide with another lane through a
    /// delimiter nor be read back out of the registry.
    fn lane_key(&self) -> String {
        hex::encode(self.digest)
    }
}

/// Fixed-size replay marker. Opaque; carries no recoverable proof material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReplayMarker {
    digest: [u8; 32],
    principal_digest: [u8; 32],
}

impl std::fmt::Debug for ReplayMarker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayMarker(<digest>)")
    }
}

impl ReplayMarker {
    /// Lowercase hex rendering, used only as a shared-backend key component.
    fn hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Raw digest, for process-lane keying and external test assertions on
    /// domain isolation / cross-replica equality.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

// ── Admission outcome ───────────────────────────────────────────────────────

/// Result of one atomic check-and-insert.
///
/// Every non-`Admitted` variant is terminal for the protected request. The
/// reasons are fixed-cardinality classifications, never backend error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayAdmission {
    /// This exact proof was previously unseen and is now claimed.
    Admitted,
    /// This exact proof was already admitted inside its protection interval.
    Replay,
    /// Replay state is full and no expired marker could be reclaimed. A live
    /// marker is never evicted to admit a new request.
    CapacityRefused,
    /// The authority timed out, was partitioned, refused authentication,
    /// returned corrupt data, or was otherwise uncertain. Never a fallback to
    /// local acceptance.
    AuthorityUnavailable,
}

impl ReplayAdmission {
    #[allow(dead_code)] // exercised by external unit tests
    pub fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Fixed, content-free classification suitable for a log field.
    pub fn classification(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Replay => "replay",
            Self::CapacityRefused => "capacity_refused",
            Self::AuthorityUnavailable => "authority_unavailable",
        }
    }
}

// ── Process lane ────────────────────────────────────────────────────────────

/// Process-local replay state for one protection domain.
///
/// Shared by every plugin generation that resolves the same domain, so an
/// equivalent reload inherits live markers instead of starting empty.
pub struct ProcessReplayLane {
    /// Marker digest → expiry and opaque principal digest.
    entries: DashMap<[u8; 32], ProcessReplayEntry>,
    /// Retained marker count by opaque principal digest.
    principal_counts: DashMap<[u8; 32], AtomicUsize>,
    entry_count: AtomicUsize,
    /// Highest expiry ever written. Reading it is how lane reclamation proves
    /// "no live marker remains" without scanning the map.
    newest_expiry_millis: AtomicU64,
    /// Conservative lower bound on the earliest live expiry. Starts at
    /// [`u64::MAX`] (empty). Inserts and refreshes may only move it earlier
    /// (`fetch_min`). A later bound is published only after a full scan whose
    /// writer epoch proves no writer was active during or racing the
    /// publication and no completed writer revision was missed. Capacity
    /// refusals compare this bound inside the prune lock and skip the map walk
    /// while it is still in the future.
    earliest_expiry_millis: AtomicU64,
    /// Writers currently between [`Self::begin_expiry_write`] and
    /// [`Self::end_expiry_write`]. Loaded before [`Self::completed_revisions`]
    /// so a zero count cannot be paired with a stale revision.
    active_writers: AtomicUsize,
    /// Incremented at writer release after the corresponding `fetch_min`.
    /// Prune snapshots this before the scan and refuses a later store if it
    /// changed.
    completed_revisions: AtomicU64,
    /// How many times the capacity path actually walked the map (test support).
    prune_scans: AtomicU64,
    /// Serializes the capacity-pressure prune so concurrent saturated requests
    /// do not each walk the map. Never taken on the ordinary admission path.
    prune_lock: Mutex<()>,
}

#[derive(Clone, Copy)]
struct ProcessReplayEntry {
    expires_at_millis: u64,
    principal_digest: [u8; 32],
}

impl ProcessReplayLane {
    fn new(shard_amount: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::with_shard_amount(shard_amount),
            principal_counts: DashMap::with_shard_amount(shard_amount),
            entry_count: AtomicUsize::new(0),
            newest_expiry_millis: AtomicU64::new(0),
            earliest_expiry_millis: AtomicU64::new(u64::MAX),
            active_writers: AtomicUsize::new(0),
            completed_revisions: AtomicU64::new(0),
            prune_scans: AtomicU64::new(0),
            prune_lock: Mutex::new(()),
        })
    }

    /// Atomic check-and-insert. Exactly one of any number of concurrent
    /// admissions of a previously unseen marker observes
    /// [`ReplayAdmission::Admitted`].
    ///
    /// The decision and the insertion happen under one DashMap entry guard, so
    /// there is no read-then-write window. The capacity path releases that
    /// guard before pruning and then re-acquires it, because a concurrent
    /// request may have claimed the same marker while this one waited — a live
    /// duplicate must be rejected rather than displace the marker that beat it.
    pub fn admit_at(
        &self,
        marker: &ReplayMarker,
        retention: Duration,
        max_entries: usize,
        now_millis: u64,
    ) -> ReplayAdmission {
        self.admit_for_principal_at(
            marker,
            &marker.principal_digest,
            retention,
            max_entries,
            now_millis,
        )
    }

    pub fn admit_for_principal_at(
        &self,
        marker: &ReplayMarker,
        principal_digest: &[u8; 32],
        retention: Duration,
        max_entries: usize,
        now_millis: u64,
    ) -> ReplayAdmission {
        let retention_millis = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
        let expires_at = now_millis.saturating_add(retention_millis);
        let principal_limit = max_entries.div_ceil(4).max(1);
        let mut key = marker.digest;
        let mut pruned = false;

        loop {
            match self.entries.entry(key) {
                Entry::Occupied(mut existing) => {
                    if existing.get().expires_at_millis > now_millis {
                        return ReplayAdmission::Replay;
                    }
                    if existing.get().principal_digest != *principal_digest {
                        return ReplayAdmission::Replay;
                    }
                    // Expired: in-place refresh is a *new* use of this proof.
                    // It is only safe when the retained count is already within
                    // this authority's cap. A lowered reload cap that left the
                    // lane over-full would otherwise admit above the new limit
                    // by recycling the occupied slot without consulting
                    // `max_entries`. The stored expiry only ever moves forward.
                    let principal_count = self
                        .principal_counts
                        .get(principal_digest)
                        .map(|count| count.load(Ordering::Acquire))
                        .unwrap_or(0);
                    if self.entry_count.load(Ordering::Acquire) <= max_entries
                        && principal_count <= principal_limit
                    {
                        let refreshed = existing.get().expires_at_millis.max(expires_at);
                        self.begin_expiry_write();
                        existing.insert(ProcessReplayEntry {
                            expires_at_millis: refreshed,
                            principal_digest: *principal_digest,
                        });
                        self.finish_expiry_write(refreshed);
                        return ReplayAdmission::Admitted;
                    }
                    // Over cap: drop the shard guard and reclaim expired
                    // entries (including this one) so a slot can be reserved
                    // under the new cap. Never refresh in place here, and
                    // never evict a live marker.
                }
                Entry::Vacant(vacant) => {
                    if !self.try_reserve_principal(principal_digest, principal_limit) {
                        key = vacant.into_key();
                    } else if self.try_reserve_slot(max_entries) {
                        self.begin_expiry_write();
                        vacant.insert(ProcessReplayEntry {
                            expires_at_millis: expires_at,
                            principal_digest: *principal_digest,
                        });
                        self.finish_expiry_write(expires_at);
                        return ReplayAdmission::Admitted;
                    } else {
                        self.release_principal(principal_digest);
                        // Do not walk other shards while holding a vacant-entry
                        // guard: the prune below touches every shard.
                        key = vacant.into_key();
                    }
                }
            }

            if pruned {
                // One bounded prune round has already run and the lane is still
                // full — either nothing was reclaimable or a concurrent request
                // took the reclaimed slot. Fail closed rather than retry
                // unboundedly, and never take a live marker to make room.
                return ReplayAdmission::CapacityRefused;
            }
            pruned = true;
            self.prune_expired(now_millis);
            // Re-observe after the bounded prune: a concurrent request may have
            // refreshed this same expired marker (Replay), pruning may have
            // restored headroom (Vacant + reserve), or live markers may still
            // fill the cap (CapacityRefused on the next iteration). Returning
            // CapacityRefused when prune reclaimed nothing would misclassify a
            // concurrent winner of this same marker as a capacity failure.
        }
    }

    fn note_expiry(&self, expires_at: u64) {
        self.newest_expiry_millis
            .fetch_max(expires_at, Ordering::AcqRel);
    }

    /// Record an insert or in-place refresh on the hot path: mark a writer
    /// active before the map write, move the earliest bound only earlier, then
    /// publish a completed revision and release the writer. AcqRel on the
    /// active count keeps the subsequent DashMap insert from becoming visible
    /// before prune can observe a writer. Never takes `prune_lock` and never
    /// allocates. Two concurrent writers both stay visible as `active_writers
    /// >= 2`; a single even/odd sequence cannot hide that.
    fn begin_expiry_write(&self) {
        self.active_writers.fetch_add(1, Ordering::AcqRel);
    }

    fn publish_written_expiry(&self, expires_at: u64) {
        self.note_expiry(expires_at);
        self.earliest_expiry_millis
            .fetch_min(expires_at, Ordering::AcqRel);
    }

    fn end_expiry_write(&self) {
        // Revision first, then the active count: a prune that observes
        // `active_writers == 0` must also observe every `fetch_min` that
        // writer published. Incrementing the revision after decrementing
        // the count would reopen a window where prune sees a stable empty
        // epoch and overwrites the earlier bound.
        self.completed_revisions.fetch_add(1, Ordering::AcqRel);
        self.active_writers.fetch_sub(1, Ordering::Release);
    }

    fn finish_expiry_write(&self, expires_at: u64) {
        self.publish_written_expiry(expires_at);
        self.end_expiry_write();
    }

    /// Active-writer count loaded first, then completed revisions. A zero
    /// active count therefore cannot be paired with a revision that still
    /// omits a writer that has already `fetch_min`'d and retired.
    fn writer_epoch(&self) -> (usize, u64) {
        let active = self.active_writers.load(Ordering::Acquire);
        let completed = self.completed_revisions.load(Ordering::Acquire);
        (active, completed)
    }

    fn can_publish_later_bound(&self, epoch: (usize, u64)) -> bool {
        epoch.0 == 0 && self.writer_epoch() == epoch
    }

    fn try_publish_later_bound(&self, live_min: u64, epoch: (usize, u64)) {
        if !self.can_publish_later_bound(epoch) {
            return;
        }
        // Publish a (possibly later) bound only after a clean exclusive scan.
        // Re-check the epoch after the store: a writer can insert, fetch_min an
        // earlier expiry, and finish between the last epoch load and this
        // store, and overwriting that earlier bound would forget a live marker.
        self.earliest_expiry_millis
            .store(live_min, Ordering::Release);
        if !self.can_publish_later_bound(epoch) {
            self.earliest_expiry_millis.store(0, Ordering::Release);
        }
    }

    fn try_reserve_slot(&self, max_entries: usize) -> bool {
        self.entry_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    fn try_reserve_principal(&self, principal: &[u8; 32], limit: usize) -> bool {
        match self.principal_counts.entry(*principal) {
            Entry::Occupied(count) => count
                .get()
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < limit).then_some(current + 1)
                })
                .is_ok(),
            Entry::Vacant(slot) => {
                slot.insert(AtomicUsize::new(1));
                true
            }
        }
    }

    fn release_principal(&self, principal: &[u8; 32]) {
        self.principal_counts.remove_if(principal, |_, count| {
            count.fetch_sub(1, Ordering::AcqRel) == 1
        });
    }

    /// Reclaim **expired** entries only. Returns how many were reclaimed.
    ///
    /// Serialized by [`Self::prune_lock`] so a burst of saturated requests pays
    /// for at most one concurrent walk. Bounded by the lane's retained entries,
    /// and reached only when the calling authority is already at its cap.
    /// Repeated refusals while the conservative earliest-expiry bound is still
    /// in the future return immediately without walking the map.
    fn prune_expired(&self, now_millis: u64) -> usize {
        self.prune_expired_at(now_millis, || {})
    }

    fn prune_expired_at(&self, now_millis: u64, after_scan: impl FnOnce()) -> usize {
        if self.earliest_expiry_millis.load(Ordering::Acquire) > now_millis {
            return 0;
        }
        let _guard = self
            .prune_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.earliest_expiry_millis.load(Ordering::Acquire) > now_millis {
            return 0;
        }

        self.prune_scans.fetch_add(1, Ordering::Relaxed);
        // Snapshot before the scan so a writer that inserts on an already
        // visited shard and completes before publication is visible as a
        // revision change. Load order is owned by [`Self::writer_epoch`].
        let epoch = self.writer_epoch();

        let mut expired: Vec<[u8; 32]> = Vec::new();
        let mut live_min = u64::MAX;
        for entry in self.entries.iter() {
            let expires_at = entry.value().expires_at_millis;
            if expires_at <= now_millis {
                expired.push(*entry.key());
            } else {
                live_min = live_min.min(expires_at);
            }
        }
        let mut reclaimed = 0usize;
        for key in expired {
            // Re-check the expiry under the shard guard: a concurrent request
            // may have refreshed this marker between the scan and the removal,
            // and removing it then would drop a live claim.
            match self
                .entries
                .remove_if(&key, |_, entry| entry.expires_at_millis <= now_millis)
            {
                Some((_, entry)) => {
                    self.entry_count.fetch_sub(1, Ordering::AcqRel);
                    self.release_principal(&entry.principal_digest);
                    reclaimed += 1;
                }
                None => {
                    if let Some(current) = self.entries.get(&key) {
                        live_min = live_min.min(current.expires_at_millis);
                    }
                }
            }
        }

        after_scan();
        self.try_publish_later_bound(live_min, epoch);
        reclaimed
    }

    /// Whether every marker this lane retains has expired.
    ///
    /// One atomic load, not a map scan: the high-water mark is the newest
    /// expiry ever written, so if it is in the past no live marker remains.
    fn all_markers_expired(&self, now_millis: u64) -> bool {
        self.newest_expiry_millis.load(Ordering::Acquire) <= now_millis
    }

    /// Retained entry count, including entries whose expiry has passed but
    /// which lazy reclamation has not yet removed (test support).
    #[allow(dead_code)] // exercised by external unit tests
    pub fn retained_entries(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    /// How many times the capacity path walked the map (test support).
    #[allow(dead_code)] // exercised by external unit tests
    pub fn prune_scans(&self) -> u64 {
        self.prune_scans.load(Ordering::Acquire)
    }

    /// Conservative earliest-expiry bound currently published (test support).
    #[allow(dead_code)] // exercised by external unit tests
    pub fn earliest_expiry_millis_for_tests(&self) -> u64 {
        self.earliest_expiry_millis.load(Ordering::Acquire)
    }

    /// Admit one marker but leave the writer active after `fetch_min`.
    ///
    /// Test support for the exact prune-vs-writer interleaving: the caller
    /// holds the returned guard across prune publication, then releases it.
    /// Does not take `prune_lock` and does not scan. A full lane returns
    /// [`ReplayAdmission::CapacityRefused`] rather than pruning.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn admit_at_holding_expiry_write_for_tests(
        &self,
        marker: &ReplayMarker,
        retention: Duration,
        max_entries: usize,
        now_millis: u64,
    ) -> Result<HeldExpiryWrite<'_>, ReplayAdmission> {
        let retention_millis = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
        let expires_at = now_millis.saturating_add(retention_millis);
        match self.entries.entry(marker.digest) {
            Entry::Occupied(mut existing) => {
                if existing.get().expires_at_millis > now_millis {
                    return Err(ReplayAdmission::Replay);
                }
                if self.entry_count.load(Ordering::Acquire) <= max_entries {
                    let refreshed = existing.get().expires_at_millis.max(expires_at);
                    let principal_digest = existing.get().principal_digest;
                    self.begin_expiry_write();
                    existing.insert(ProcessReplayEntry {
                        expires_at_millis: refreshed,
                        principal_digest,
                    });
                    self.publish_written_expiry(refreshed);
                    return Ok(HeldExpiryWrite {
                        lane: self,
                        finished: false,
                    });
                }
                Err(ReplayAdmission::CapacityRefused)
            }
            Entry::Vacant(vacant) => {
                if !self
                    .try_reserve_principal(&marker.principal_digest, max_entries.div_ceil(4).max(1))
                {
                    return Err(ReplayAdmission::CapacityRefused);
                }
                if self.try_reserve_slot(max_entries) {
                    self.begin_expiry_write();
                    vacant.insert(ProcessReplayEntry {
                        expires_at_millis: expires_at,
                        principal_digest: marker.principal_digest,
                    });
                    self.publish_written_expiry(expires_at);
                    return Ok(HeldExpiryWrite {
                        lane: self,
                        finished: false,
                    });
                }
                self.release_principal(&marker.principal_digest);
                Err(ReplayAdmission::CapacityRefused)
            }
        }
    }

    /// Run a due prune, invoke `after_scan` after reclaim and before the later
    /// bound is published, then apply the writer-epoch publication check.
    ///
    /// `after_scan` runs under [`Self::prune_lock`] and must not re-enter prune.
    /// Ordinary admission from the callback is safe: it never takes that lock.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn prune_expired_with_after_scan_for_tests(
        &self,
        now_millis: u64,
        after_scan: impl FnOnce(),
    ) -> usize {
        self.prune_expired_at(now_millis, after_scan)
    }
}

/// Guard that keeps one expiry writer active until [`Self::finish`] or drop.
///
/// Drop releases the writer without panicking so a test that abandons the
/// guard cannot wedge prune publication. Production admission never constructs
/// this type.
#[allow(dead_code)] // exercised by external unit tests
pub struct HeldExpiryWrite<'a> {
    lane: &'a ProcessReplayLane,
    finished: bool,
}

impl HeldExpiryWrite<'_> {
    /// Publish the completed revision and release the writer.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn finish(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if !self.finished {
            self.finished = true;
            self.lane.end_expiry_write();
        }
    }
}

impl Drop for HeldExpiryWrite<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Process-global lane registry, keyed by protection-domain digest.
///
/// Held by strong reference: a deleted or reconfigured policy leaves its lane
/// as a tombstone so its live markers keep protecting, and the lane is
/// reclaimed only once every marker has expired.
static PROCESS_REPLAY_LANES: LazyLock<Mutex<HashMap<String, Arc<ProcessReplayLane>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn process_lane_count() -> usize {
    PROCESS_REPLAY_LANES
        .lock()
        .map(|registry| registry.len())
        .unwrap_or(0)
}

/// Resolve (or create) the process lane for `domain`.
///
/// Cold path only — plugin construction, never a request. Creating a new lane
/// first reclaims retired lanes whose markers have all expired, so deleted
/// configurations cannot permanently exhaust [`MAX_PROCESS_REPLAY_LANES`].
///
/// An existing lane is returned as-is: capacity is enforced by the calling
/// authority, not frozen onto the lane by the first constructor. Rejoining must
/// never rebuild, forget, or re-key the lane.
fn resolve_process_lane(
    plugin: &str,
    domain: &ReplayDomain,
    shard_amount: usize,
) -> Result<Arc<ProcessReplayLane>, String> {
    let key = domain.lane_key();
    let mut registry = PROCESS_REPLAY_LANES
        .lock()
        .map_err(|_| format!("{plugin}: replay lane registry is unavailable"))?;
    if let Some(existing) = registry.get(&key) {
        return Ok(Arc::clone(existing));
    }
    let now = monotonic_millis();
    registry.retain(|_, lane| Arc::strong_count(lane) > 1 || !lane.all_markers_expired(now));
    if registry.len() >= MAX_PROCESS_REPLAY_LANES {
        // Fixed diagnostic: the lane key is a digest and would not help an
        // operator act on this.
        return Err(format!(
            "{plugin}: refusing to create more than {MAX_PROCESS_REPLAY_LANES} distinct replay \
             lanes in one process"
        ));
    }
    let lane = ProcessReplayLane::new(shard_amount);
    registry.insert(key, Arc::clone(&lane));
    Ok(lane)
}

/// Number of live process replay lanes (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane_count_for_tests() -> usize {
    process_lane_count()
}

/// Whether a domain currently owns a registered process lane (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane_registered_for_tests(domain: &ReplayDomain) -> bool {
    PROCESS_REPLAY_LANES
        .lock()
        .map(|registry| registry.contains_key(&domain.lane_key()))
        .unwrap_or(false)
}

// ── Shared authority health ─────────────────────────────────────────────────

/// Bounded, fixed-cardinality aggregate of shared replay-authority health.
///
/// Two counters and nothing else. There is deliberately no endpoint, host,
/// namespace, plugin id, provider, key prefix, credential, or backend error
/// text here: this snapshot is published on the authenticated `/health` and
/// `/status` tier, so its cardinality must not grow with configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct SharedReplayAuthorityHealth {
    /// Distinct shared authorities held by a live plugin generation. A retired
    /// generation drops its client, so it stops being counted immediately.
    pub shared_authorities: u64,
    /// How many of those are currently unavailable (unproven, outage, or
    /// terminal topology). Non-zero means protected requests on those policies
    /// are failing closed.
    pub shared_authorities_unavailable: u64,
}

impl SharedReplayAuthorityHealth {
    /// Whether any live policy depends on a shared authority at all.
    pub fn required(self) -> bool {
        self.shared_authorities > 0
    }

    /// Whether a required shared authority is unproven or known unavailable.
    pub fn unavailable(self) -> bool {
        self.shared_authorities_unavailable > 0
    }
}

/// Bounded aggregate over every live shared replay authority.
///
/// One acquire-load of a packed atomic published on lifecycle transitions
/// (first registration of a distinct replay Redis client, reachable to
/// unavailable, unavailable to reachable, terminal topology, and retirement).
/// No mutex on the read path, no registry scan, no allocation, no I/O, and no
/// work proportional to configured or historical authorities (writers serialize
/// their packed deltas behind a cold transition lock). `/health`, `/status`,
/// and `/metrics/runtime` all read this same word.
pub fn shared_health_snapshot() -> SharedReplayAuthorityHealth {
    let (shared_authorities, shared_authorities_unavailable) =
        super::redis_rate_limiter::shared_replay_health_counts();
    SharedReplayAuthorityHealth {
        shared_authorities,
        shared_authorities_unavailable,
    }
}

/// `(registered, unavailable)` shared authorities.
fn shared_authority_health() -> (u64, u64) {
    let health = shared_health_snapshot();
    (
        health.shared_authorities,
        health.shared_authorities_unavailable,
    )
}

/// Whether any registered shared replay authority is currently unavailable.
///
/// Protected requests on those policies are failing closed, which is a
/// readiness-relevant condition rather than a per-request error. Consumed by
/// the admin `/health` + `/status` readiness decision.
#[allow(dead_code)] // exercised by external unit tests
pub fn shared_authority_degraded() -> bool {
    shared_health_snapshot().unavailable()
}

// ── The authority ───────────────────────────────────────────────────────────

/// The replay authority one policy claims against.
pub enum ReplayAuthority {
    /// Single-process/development contract, stable across equivalent reloads.
    Process {
        lane: Arc<ProcessReplayLane>,
        retention: Duration,
        /// Cap this generation enforces against the shared lane. Live markers
        /// already in the lane are never evicted to meet it.
        max_entries: usize,
    },
    /// Production HA contract: one atomic `SET … NX EX` per marker.
    Shared {
        client: Arc<RedisRateLimitClient>,
        retention: Duration,
    },
}

impl std::fmt::Debug for ReplayAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayAuthority")
            .field("mode", &self.mode())
            .finish()
    }
}

impl ReplayAuthority {
    /// Build a process-scoped authority bound to `domain`'s stable lane.
    ///
    /// `retention` must be the caller's fixed compile-time horizon, not a
    /// configured value — see the module documentation.
    ///
    /// `max_entries` is enforced by *this* authority against the shared lane.
    /// An equivalent reload that changes the cap joins the same lane and
    /// applies the new cap without forgetting live markers.
    pub fn process(
        plugin: &str,
        domain: &ReplayDomain,
        max_entries: usize,
        retention: Duration,
        shard_amount: usize,
    ) -> Result<Self, String> {
        Ok(Self::Process {
            lane: resolve_process_lane(plugin, domain, shard_amount)?,
            retention,
            max_entries: max_entries.max(1),
        })
    }

    /// Build a shared authority over an existing Redis client.
    ///
    /// Construction is detached: it does not register packed readiness, start
    /// the recovery checker, dial Redis, or mutate live process health. Call
    /// [`Self::activate`] from [`crate::plugins::Plugin::commit_background_tasks`]
    /// after the containing plugin generation has been atomically installed.
    /// An unactivated authority stays fail-closed if [`Self::admit`] is reached
    /// before that commit — there is no local fallback.
    ///
    /// Callers must pass a client from
    /// [`RedisRateLimitClient::for_replay_authority`] so connection,
    /// authentication, command, topology, and recovery diagnostics stay
    /// classification-only and the client starts unproven. Generic rate-limiter
    /// clients retain [`RedisRateLimitClient::new`].
    pub fn shared(client: Arc<RedisRateLimitClient>, retention: Duration) -> Self {
        Self::Shared { client, retention }
    }

    /// Publish this shared authority as a live readiness dependency.
    ///
    /// Idempotent: several providers sharing one Redis client register that
    /// client exactly once, arm recovery at most once, and count the packed
    /// health aggregate exactly once. Process-scoped authorities are a no-op.
    /// Must run only after the containing plugin generation is committed.
    pub fn activate(&self) {
        if let Self::Shared { client, .. } = self {
            client.register_as_shared_replay_authority();
        }
    }

    /// Whether this shared authority's Redis recovery checker has been armed
    /// (test support). Process-scoped authorities never start one.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn recovery_checker_started_for_test(&self) -> bool {
        match self {
            Self::Shared { client, .. } => client.health_checker_started_for_test(),
            Self::Process { .. } => false,
        }
    }

    /// Fixed-cardinality mode label.
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Process { .. } => ReplayScope::Process.as_str(),
            Self::Shared { .. } => ReplayScope::Shared.as_str(),
        }
    }

    /// Retention horizon written with every marker in this authority.
    #[allow(dead_code)] // exercised by external unit tests
    pub fn retention(&self) -> Duration {
        match self {
            Self::Process { retention, .. } | Self::Shared { retention, .. } => *retention,
        }
    }

    /// Hostnames this authority dials, for gateway DNS warmup.
    pub fn warmup_hostnames(&self) -> Vec<String> {
        match self {
            Self::Process { .. } => Vec::new(),
            Self::Shared { client, .. } => client.warmup_hostname().into_iter().collect(),
        }
    }

    /// Atomically claim `marker` for exactly one request inside the retention
    /// horizon.
    ///
    /// Callers must reach this **only after** every cryptographic and claim
    /// check has passed, so unauthenticated garbage can never consume replay
    /// capacity or a shared-backend round trip.
    pub async fn admit(&self, marker: &ReplayMarker) -> ReplayAdmission {
        let outcome = match self {
            Self::Process {
                lane,
                retention,
                max_entries,
            } => lane.admit_at(marker, *retention, *max_entries, monotonic_millis()),
            Self::Shared { client, retention } => admit_shared(client, *retention, marker).await,
        };
        record_admission(self.mode(), outcome);
        outcome
    }
}

/// Saturating ceil of `retention` to a Redis-valid positive whole-second TTL.
/// Integral durations stay exact; a fractional remainder rounds up; zero becomes
/// 1 so `EX` cannot delete the marker it just wrote.
fn redis_claim_ttl_seconds(retention: Duration) -> u64 {
    let ceil = if retention.subsec_nanos() == 0 {
        retention.as_secs()
    } else {
        retention.as_secs().saturating_add(1)
    };
    ceil.max(1)
}

/// Cross-replica claim: one atomic Redis `SET key value NX EX ttl`.
///
/// A single server-side operation, so among any number of concurrent requests
/// on any number of replicas exactly one observes `Ok(true)`. There is no
/// read-then-write window and no process-local pre-check that could answer
/// differently from the shared truth.
///
/// Every failure mode — unavailable client, command error, response timeout,
/// partition, authentication rejection, malformed protocol reply, or a
/// proven-unsupported topology — arrives as `Err(())` or a false availability
/// flag and rejects the protected request. There is no local fallback.
///
/// The claim runs through the **bounded** primitive
/// ([`RedisRateLimitClient::set_bytes_nx_with_expire_bounded`]) on a Redis
/// client constructed with [`RedisRateLimitClient::for_replay_authority`]: a
/// connected blackhole that accepts the command and never answers must return a
/// fixed fail-closed result rather than hold a protected request open for as
/// long as the peer keeps the socket. Connection, authentication, command,
/// topology, and recovery diagnostics on that client publish only a fixed
/// classification plus the redacted endpoint, so no key, marker, nonce, proof,
/// signature, identity, credential, operator key prefix, or backend error text
/// can reach a log line from here.
///
/// A command that Redis executed but whose reply was lost still fails closed:
/// the marker exists, so the retry observes `Ok(false)` (`Replay`). Losing the
/// reply can therefore cost the client one request, never a second acceptance.
async fn admit_shared(
    client: &RedisRateLimitClient,
    retention: Duration,
    marker: &ReplayMarker,
) -> ReplayAdmission {
    if !client.is_live_shared_replay_registration() {
        // Detached construction must not dial Redis or admit locally if a
        // request arrives before the containing plugin generation commits.
        return ReplayAdmission::AuthorityUnavailable;
    }
    if !client.is_available() {
        // Fail closed without waiting on the backend. Arm (or retry-arm) the
        // bounded readiness probe so an unproven client activated without a
        // runtime can recover once one is present — without turning this
        // request into an unbounded connect.
        client.start_health_checker_if_needed();
        return ReplayAdmission::AuthorityUnavailable;
    }
    let key = client.make_key(&[SHARED_KEY_COMPONENT, marker.hex().as_str()]);
    // Exact whole seconds stay exact; a fractional remainder rounds up so Redis
    // `EX` (integral seconds) can never shorten the declared horizon. Zero still
    // becomes 1: Redis treats `EX 0` as an immediate delete, which would admit
    // an unprotected marker.
    let ttl_seconds = redis_claim_ttl_seconds(retention);
    match client
        .set_bytes_nx_with_expire_bounded(&key, SHARED_MARKER_RECORD, ttl_seconds)
        .await
    {
        Ok(true) => ReplayAdmission::Admitted,
        Ok(false) => ReplayAdmission::Replay,
        Err(()) => ReplayAdmission::AuthorityUnavailable,
    }
}

fn record_admission(mode: &'static str, outcome: ReplayAdmission) {
    match outcome {
        ReplayAdmission::Admitted => {
            if mode == ReplayScope::Shared.as_str() {
                ADMITTED_SHARED.fetch_add(1, Ordering::Relaxed);
            } else {
                ADMITTED_PROCESS.fetch_add(1, Ordering::Relaxed);
            }
        }
        ReplayAdmission::Replay => {
            REPLAY_REJECTED.fetch_add(1, Ordering::Relaxed);
        }
        ReplayAdmission::CapacityRefused => {
            CAPACITY_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        ReplayAdmission::AuthorityUnavailable => {
            AUTHORITY_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── Shared configuration admission ──────────────────────────────────────────

/// Reject a scope/backend combination that cannot deliver what it declares.
///
/// `shared` without a Redis backend would silently be process-local — the exact
/// "multi-replica production configuration falls back to local acceptance"
/// failure. A configured Redis backend without `shared` is equally a
/// misconfiguration: the operator provisioned a shared store the policy would
/// never consult.
pub fn validate_scope_backend(
    plugin: &str,
    field: &str,
    scope: ReplayScope,
    redis_configured: bool,
) -> Result<(), String> {
    match (scope, redis_configured) {
        (ReplayScope::Shared, false) => Err(format!(
            "{plugin}: `{field}` = `shared` requires `sync_mode: redis` and a `redis_url`"
        )),
        (ReplayScope::Process, true) => Err(format!(
            "{plugin}: `sync_mode: redis` is only meaningful with `{field}` = `shared`"
        )),
        _ => Ok(()),
    }
}

/// Test-support admission against an explicit monotonic instant, so external
/// tests can pin exact TTL boundaries without sleeping.
#[allow(dead_code)] // exercised by external unit tests
pub fn admit_process_at(
    authority: &ReplayAuthority,
    marker: &ReplayMarker,
    now_millis: u64,
) -> Option<ReplayAdmission> {
    let ReplayAuthority::Process {
        lane,
        retention,
        max_entries,
    } = authority
    else {
        return None;
    };
    let outcome = lane.admit_at(marker, *retention, *max_entries, now_millis);
    record_admission(authority.mode(), outcome);
    Some(outcome)
}

/// Process-lane capacity this authority enforces (test support). `None` for a
/// shared authority, which does not admit against a process lane.
pub fn process_max_entries(authority: &ReplayAuthority) -> Option<usize> {
    match authority {
        ReplayAuthority::Process { max_entries, .. } => Some(*max_entries),
        ReplayAuthority::Shared { .. } => None,
    }
}

/// The process lane behind a process-scoped authority (test support).
#[allow(dead_code)] // exercised by external unit tests
pub fn process_lane(authority: &ReplayAuthority) -> Option<&Arc<ProcessReplayLane>> {
    match authority {
        ReplayAuthority::Process { lane, .. } => Some(lane),
        ReplayAuthority::Shared { .. } => None,
    }
}
