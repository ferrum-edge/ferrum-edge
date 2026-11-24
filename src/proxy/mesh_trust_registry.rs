//! Gateway-to-mesh transport ownership registry for live trust withdrawal
//! (issue #3859).
//!
//! Draining the HBONE / mesh-mTLS pool maps proves only that a *future* lookup
//! cannot discover a connection. It does not reach a connection whose handles
//! have already left the map: an issued [`super::hbone_pool::H2ConnectTunnel`]
//! owns its `RecvStream`/`SendStream` directly, a cloned HTTP/2 sender can open
//! fresh streams on the established TLS session, and the one-connection-per-
//! session WebSocket / datagram bridges were never in the map at all. After an
//! operator withdraws an X.509 / JWT authority, every one of those keeps
//! carrying traffic authenticated under the withdrawn root until its own EOF.
//!
//! This module owns the missing half: **connection ownership**. Every
//! gateway-to-mesh TLS transport — pooled or 1:1 — registers here when its
//! connection driver is spawned, under the accepted gateway trust generation,
//! and hands its driver task a [`MeshTransportGate`]. The gate stays reachable
//! after callers clone the sender or take the tunnel out of the pool, because
//! the handles carry a clone of it rather than a pool reference.
//!
//! # Withdrawal sequence
//!
//! [`MeshTrustRegistry::retire_for_trust_withdrawal`] runs, in order:
//!
//! 1. take the admission fence for write, so no dial in flight can register;
//! 2. publish the next accepted generation;
//! 3. mark the outgoing generation retired;
//! 4. synchronously signal every registered transport at or below it;
//! 5. release the registry fence, allowing registrations for the new ownership
//!    generation.
//!
//! The outer gateway-trust publication fence is separate and remains closed
//! across this sequence. The publication path installs the accepted verifier
//! **before** calling this method, so a dial that takes a ticket for the newly
//! published generation can only load that already-stored material. Releasing
//! this registry fence therefore does not reopen request admission early, and
//! it does not create a window of new-generation tickets authenticated by the
//! withdrawn verifier.
//!
//! Signalling is synchronous — the gate flag is set and the driver is notified
//! before the fence is released — so no transport can be admitted, returned to
//! a pool, or handed to a caller in the window between publication and
//! teardown. Completing the teardown (dropping the HTTP/2 connection, which
//! closes the socket and errors every stream on it) is a bounded task wake, not
//! an unbounded wait: it does not depend on peer behaviour, backend liveness,
//! or a drain timer.
//!
//! # Creation race
//!
//! A dial that started before the fence takes an [`MeshAdmissionTicket`] stamped
//! with the generation it dialled under. [`MeshTrustRegistry::register`] refuses
//! a ticket whose generation is no longer the accepted one, so a connection
//! established under withdrawn trust can neither be inserted into a pool nor be
//! returned to the caller — it fails closed instead of escaping retirement.
//!
//! # No churn
//!
//! Nothing here fires unless an accepted publication actually *removes* an
//! authority ([`trust_withdrawal_reason`]). An identical `Replace`, an additive
//! overlap, an `Unchanged` side channel, a redundant `Clear` with no installed
//! override, and every rejected candidate leave the generation, the registry,
//! and every live session untouched.
//!
//! # Disclosure
//!
//! Metrics are fixed-cardinality counters over a closed reason/transport set.
//! No trust material, certificate subject, key id, fingerprint, source path, or
//! peer identity is ever a label value, a sample value, a log field, or part of
//! the client-visible error string.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};

use dashmap::DashMap;
use tokio::sync::Notify;

use crate::identity::TrustBundleSet;

/// Client-visible reason a retired gateway-to-mesh transport reports.
///
/// Deliberately fixed and material-free: it names the policy event, never the
/// authority, trust domain, subject, key id, or fingerprint that was withdrawn.
pub const MESH_TRUST_WITHDRAWN_MESSAGE: &str =
    "gateway-to-mesh transport retired: gateway trust authority withdrawn";

/// Client-visible reason a pooled HBONE HTTP/2 transport reports when keepalive
/// PING failure tears it down (issue #4162). Distinct from
/// [`MESH_TRUST_WITHDRAWN_MESSAGE`] so a dead peer is never labeled as a trust
/// withdrawal.
pub const MESH_KEEPALIVE_FAILED_MESSAGE: &str =
    "gateway-to-mesh transport closed: HTTP/2 keepalive ping failed";

/// Transport classes registered here. Closed set — it is a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshTransportKind {
    /// Ambient/Waypoint HBONE HTTP/2 CONNECT transport (`:15008`), pooled or
    /// 1:1 (WebSocket / datagram bridges).
    Hbone,
    /// Sidecar mesh-mTLS HTTP/2 transport (`:15006`), pooled or 1:1.
    MeshMtls,
}

impl MeshTransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hbone => "hbone",
            Self::MeshMtls => "mesh_mtls",
        }
    }
}

/// Every transport class, in render order. Closed set for metric emission.
pub const MESH_TRANSPORT_KINDS: [MeshTransportKind; 2] =
    [MeshTransportKind::Hbone, MeshTransportKind::MeshMtls];

/// Why an accepted gateway trust publication retired the outgoing generation.
/// Closed set — it is a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustWithdrawalReason {
    /// A publication that REPLACED the effective trust material no longer
    /// carries an authority the effective gateway trust previously accepted.
    ///
    /// Covers both replacement shapes, because they are indistinguishable to
    /// the live verifier: an accepted `GatewayTrustCommit::Replace`, and a
    /// source SVID rotation (SPIRE / file / CA backend) whose bundle drops a
    /// trust anchor while no CP/database override is masking it. Kept as ONE
    /// closed label rather than split, so the metric's cardinality does not
    /// grow with the number of trust SOURCES.
    ReplaceRemovedAuthority,
    /// An accepted `Clear` withdrew an installed override whose authorities the
    /// restored startup material does not fully carry.
    ClearedOverride,
}

impl TrustWithdrawalReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplaceRemovedAuthority => "replace_removed_authority",
            Self::ClearedOverride => "cleared_override",
        }
    }
}

/// Every withdrawal reason, in render order. Closed set for metric emission.
pub const TRUST_WITHDRAWAL_REASONS: [TrustWithdrawalReason; 2] = [
    TrustWithdrawalReason::ReplaceRemovedAuthority,
    TrustWithdrawalReason::ClearedOverride,
];

/// One authority identity inside an effective gateway trust view.
///
/// Compared only against other identities from the same process; it never
/// leaves this module, is never rendered, logged, or exported, and is dropped
/// as soon as the comparison finishes. X.509 entries carry the DER bytes and
/// JWT entries the key id plus the public key so a same-`kid` key swap counts
/// as a removal rather than an in-place edit.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum TrustAuthority {
    X509 {
        trust_domain: String,
        der: Vec<u8>,
    },
    Jwt {
        trust_domain: String,
        key_id: String,
        public_key_pem: String,
    },
}

fn collect_authorities(bundles: Option<&TrustBundleSet>) -> BTreeSet<TrustAuthority> {
    let mut set = BTreeSet::new();
    let Some(bundles) = bundles else {
        return set;
    };
    for bundle in std::iter::once(&bundles.local).chain(bundles.federated.values()) {
        let trust_domain = bundle.trust_domain.as_str().to_string();
        for der in &bundle.x509_authorities {
            set.insert(TrustAuthority::X509 {
                trust_domain: trust_domain.clone(),
                der: der.clone(),
            });
        }
        for jwt in &bundle.jwt_authorities {
            set.insert(TrustAuthority::Jwt {
                trust_domain: trust_domain.clone(),
                key_id: jwt.key_id.clone(),
                public_key_pem: jwt.public_key_pem.clone(),
            });
        }
    }
    set
}

/// Decide whether an accepted gateway trust publication removes any authority
/// the gateway-to-mesh TLS stack previously accepted.
///
/// `before` / `after` are the **effective** trust views — what
/// `build_spiffe_outbound_config` verifies peers against — not the raw CP
/// override, so a `Clear` is judged against the startup material it restores.
///
/// Returns `None` for every no-churn shape: an identical `Replace`, an additive
/// overlap (`before ⊆ after`), an `Unchanged` side channel that never reaches
/// this path, and a redundant `Clear` whose restored material still carries
/// every authority. A rejected candidate never reaches here at all, because the
/// publication path is only entered on acceptance.
///
/// `cleared` distinguishes the two closed metric reasons; it does not change
/// the verdict.
pub fn trust_withdrawal_reason(
    before: Option<&TrustBundleSet>,
    after: Option<&TrustBundleSet>,
    cleared: bool,
) -> Option<TrustWithdrawalReason> {
    let before = collect_authorities(before);
    if before.is_empty() {
        // Nothing was accepted before, so nothing can be withdrawn. This is the
        // redundant-`Clear`-with-no-override case and the first publication.
        return None;
    }
    let after = collect_authorities(after);
    if before.iter().all(|authority| after.contains(authority)) {
        return None;
    }
    Some(if cleared {
        TrustWithdrawalReason::ClearedOverride
    } else {
        TrustWithdrawalReason::ReplaceRemovedAuthority
    })
}

/// The retirement signal shared by one gateway-to-mesh transport, its connection
/// driver, and every handle issued from it.
///
/// Cloning is an `Arc` bump, and the hot-path read
/// ([`MeshTransportGate::is_retired`]) is a single relaxed atomic load with no
/// lock and no allocation, so a byte relay can check it on every poll.
pub struct MeshTransportGateInner {
    retired: AtomicBool,
    /// Set when HTTP/2 keepalive PING fails or times out (issue #4162). Kept
    /// separate from `retired` so a dead peer is never labeled as a trust
    /// withdrawal.
    keepalive_failed: AtomicBool,
    /// Wakes the connection driver exactly once. `notify_one` stores a permit
    /// when no waiter is parked, so a retirement that lands before the driver
    /// first polls is not lost.
    driver_cancel: Notify,
    /// Wakes the connection driver on keepalive failure. Separate from
    /// `driver_cancel` so a keepalive abort cannot be consumed by a waiter
    /// parked on trust withdrawal, and vice versa.
    keepalive_cancel: Notify,
}

#[derive(Clone)]
pub struct MeshTransportGate(Arc<MeshTransportGateInner>);

impl MeshTransportGate {
    pub fn new() -> Self {
        Self(Arc::new(MeshTransportGateInner {
            retired: AtomicBool::new(false),
            keepalive_failed: AtomicBool::new(false),
            driver_cancel: Notify::new(),
            keepalive_cancel: Notify::new(),
        }))
    }

    /// Hot-path check. One relaxed load: the store side publishes with
    /// `Release` and the only thing a reader needs is the flag itself, since
    /// every consequence (an `io::Error`, a refused lookup) is produced by the
    /// reader from the flag alone.
    #[inline]
    pub fn is_retired(&self) -> bool {
        self.0.retired.load(Ordering::Relaxed)
    }

    /// Retire this transport. Returns `true` exactly once, for the caller that
    /// performed the transition, so teardown accounting (metrics, relay
    /// release) can never double-count. Later calls — a second withdrawal, a
    /// registration drop racing a sweep — return `false` and do nothing.
    pub fn retire(&self) -> bool {
        if self.0.retired.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.0.driver_cancel.notify_one();
        true
    }

    /// Awaited by the connection driver. Resolves immediately when the gate is
    /// already retired.
    pub async fn cancelled(&self) {
        loop {
            if self.is_retired() {
                return;
            }
            let notified = self.0.driver_cancel.notified();
            if self.is_retired() {
                return;
            }
            notified.await;
        }
    }

    /// The uniform, material-free I/O error a retired transport reports to its
    /// relay. `ConnectionAborted` is what the byte relays already classify as
    /// an attributed transport failure, so no relay teardown path changes.
    pub fn retired_io_error(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            MESH_TRUST_WITHDRAWN_MESSAGE,
        )
    }

    /// True after [`Self::abort_keepalive`]. One relaxed load, same cost as
    /// [`Self::is_retired`].
    #[inline]
    pub fn keepalive_failed(&self) -> bool {
        self.0.keepalive_failed.load(Ordering::Relaxed)
    }

    /// Mark this transport dead because HTTP/2 keepalive PING failed or timed
    /// out (issue #4162). Returns `true` exactly once. Does not set
    /// [`Self::is_retired`], so trust-withdrawal accounting and error strings
    /// stay distinct.
    pub fn abort_keepalive(&self) -> bool {
        if self.0.keepalive_failed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.0.keepalive_cancel.notify_one();
        true
    }

    /// Awaited by the connection driver. Resolves immediately when keepalive
    /// has already failed.
    pub async fn keepalive_cancelled(&self) {
        loop {
            if self.keepalive_failed() {
                return;
            }
            let notified = self.0.keepalive_cancel.notified();
            if self.keepalive_failed() {
                return;
            }
            notified.await;
        }
    }

    /// Material-free I/O error for a keepalive-aborted transport. Same
    /// `ConnectionAborted` kind as trust withdrawal, different message.
    pub fn keepalive_io_error(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            MESH_KEEPALIVE_FAILED_MESSAGE,
        )
    }

    /// Identity of this gate, used so pool eviction removes *this* transport
    /// and not a newer replacement stored under the same pool key.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Default for MeshTransportGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Refusal returned when a transport cannot be admitted under the generation it
/// was dialled with. The caller maps it to a fixed pre-wire error and drops the
/// connection; the class is carried for diagnostics only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshTrustAdmissionRefused {
    pub kind: MeshTransportKind,
}

/// A generation stamp taken before dialling and presented at registration.
#[derive(Debug, Clone, Copy)]
pub struct MeshAdmissionTicket {
    generation: u64,
}

impl MeshAdmissionTicket {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// RAII registration. Held by the connection driver for the connection's whole
/// life, so the registry's live set is exactly the set of open gateway-to-mesh
/// transports. Dropping it deregisters; it does **not** retire the gate,
/// because an ordinary connection close is not a trust event.
pub struct MeshTransportRegistration {
    registry: Weak<MeshTrustRegistry>,
    id: u64,
    generation: u64,
    kind: MeshTransportKind,
    gate: MeshTransportGate,
}

impl MeshTransportRegistration {
    pub fn gate(&self) -> &MeshTransportGate {
        &self.gate
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn kind(&self) -> MeshTransportKind {
        self.kind
    }
}

impl Drop for MeshTransportRegistration {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.deregister(self.id);
        }
    }
}

struct RegisteredTransport {
    generation: u64,
    kind: MeshTransportKind,
    gate: MeshTransportGate,
}

/// What one accepted withdrawal actually retired. Returned so the publication
/// site can log fixed-cardinality counts (never identities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeshTrustRetirementOutcome {
    pub published_generation: u64,
    pub retired_generation: u64,
    pub retired_hbone: u64,
    pub retired_mesh_mtls: u64,
}

impl MeshTrustRetirementOutcome {
    pub fn retired_total(&self) -> u64 {
        self.retired_hbone.saturating_add(self.retired_mesh_mtls)
    }
}

/// Per-`ProxyState` ownership registry for gateway-to-mesh TLS transports.
pub struct MeshTrustRegistry {
    /// Accepted gateway trust generation. Starts at 1 so `retired_through = 0`
    /// is unambiguously "nothing retired yet".
    accepted_generation: AtomicU64,
    /// Every generation at or below this is retired; a transport dialled under
    /// one may not be admitted.
    retired_through: AtomicU64,
    /// Admission fence. Held for write across a withdrawal (publish + sweep) so
    /// registration cannot interleave; taken for read, without any `await`
    /// inside, by each registration. Cold path on both sides: one acquisition
    /// per new physical connection, never per request or per byte.
    fence: RwLock<()>,
    transports: DashMap<u64, RegisteredTransport>,
    next_id: AtomicU64,
}

impl MeshTrustRegistry {
    pub fn new() -> Arc<Self> {
        let registry = Arc::new(Self {
            accepted_generation: AtomicU64::new(1),
            retired_through: AtomicU64::new(0),
            fence: RwLock::new(()),
            // Low-cardinality (one entry per open physical mesh connection) and
            // written only on connect/close, so default sharding is right.
            transports: DashMap::new(),
            next_id: AtomicU64::new(1),
        });
        publish_generation_metric(1);
        registry
    }

    pub fn accepted_generation(&self) -> u64 {
        self.accepted_generation.load(Ordering::Acquire)
    }

    pub fn retired_through(&self) -> u64 {
        self.retired_through.load(Ordering::Acquire)
    }

    /// Number of live registered transports. Test/observability helper.
    pub fn registered_len(&self) -> usize {
        self.transports.len()
    }

    /// Stamp the generation a dial is about to be performed under.
    pub fn admission_ticket(&self) -> MeshAdmissionTicket {
        MeshAdmissionTicket {
            generation: self.accepted_generation(),
        }
    }

    /// Admit an established transport under the generation it was dialled with.
    ///
    /// Refuses — fail closed — when the accepted generation moved while the
    /// dial was in flight, which is exactly the creation race: the connection
    /// completed under trust material that has since been withdrawn, so it may
    /// neither be pooled nor returned. The caller drops the connection, which
    /// closes the socket.
    pub fn register(
        self: &Arc<Self>,
        ticket: MeshAdmissionTicket,
        kind: MeshTransportKind,
        gate: MeshTransportGate,
    ) -> Result<Arc<MeshTransportRegistration>, MeshTrustAdmissionRefused> {
        let _fence = self
            .fence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if ticket.generation != self.accepted_generation.load(Ordering::Acquire)
            || ticket.generation <= self.retired_through.load(Ordering::Acquire)
        {
            record_admission_refusal(kind);
            return Err(MeshTrustAdmissionRefused { kind });
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.transports.insert(
            id,
            RegisteredTransport {
                generation: ticket.generation,
                kind,
                gate: gate.clone(),
            },
        );
        Ok(Arc::new(MeshTransportRegistration {
            registry: Arc::downgrade(self),
            id,
            generation: ticket.generation,
            kind,
            gate,
        }))
    }

    fn deregister(&self, id: u64) {
        self.transports.remove(&id);
    }

    /// Retire every transport authenticated under the outgoing generation.
    ///
    /// Fence, publish, mark retired, signal, release — in that order. See the
    /// module docs for why the order is the security property rather than an
    /// implementation detail, and how this composes with the outer request
    /// admission fence.
    pub fn retire_for_trust_withdrawal(
        self: &Arc<Self>,
        reason: TrustWithdrawalReason,
    ) -> MeshTrustRetirementOutcome {
        let _fence = self
            .fence
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let retired_generation = self.accepted_generation.load(Ordering::Acquire);
        let published_generation = retired_generation.saturating_add(1);
        self.accepted_generation
            .store(published_generation, Ordering::Release);
        self.retired_through
            .store(retired_generation, Ordering::Release);

        let mut retired_hbone = 0u64;
        let mut retired_mesh_mtls = 0u64;
        self.transports.retain(|_, transport| {
            if transport.generation > retired_generation {
                return true;
            }
            // `retire` transitions exactly once, so a transport already retired
            // by a racing sweep is removed without being counted twice.
            if transport.gate.retire() {
                match transport.kind {
                    MeshTransportKind::Hbone => retired_hbone += 1,
                    MeshTransportKind::MeshMtls => retired_mesh_mtls += 1,
                }
            }
            false
        });

        record_withdrawal(reason, retired_hbone, retired_mesh_mtls);
        publish_generation_metric(published_generation);

        MeshTrustRetirementOutcome {
            published_generation,
            retired_generation,
            retired_hbone,
            retired_mesh_mtls,
        }
    }
}

// ===== Fixed-cardinality process metrics =====

static ACCEPTED_GENERATION: AtomicU64 = AtomicU64::new(0);
static WITHDRAWALS_REPLACE: AtomicU64 = AtomicU64::new(0);
static WITHDRAWALS_CLEAR: AtomicU64 = AtomicU64::new(0);
static RETIRED_HBONE: AtomicU64 = AtomicU64::new(0);
static RETIRED_MESH_MTLS: AtomicU64 = AtomicU64::new(0);
static REFUSED_HBONE: AtomicU64 = AtomicU64::new(0);
static REFUSED_MESH_MTLS: AtomicU64 = AtomicU64::new(0);

fn publish_generation_metric(generation: u64) {
    ACCEPTED_GENERATION.fetch_max(generation, Ordering::Relaxed);
}

fn record_withdrawal(reason: TrustWithdrawalReason, hbone: u64, mesh_mtls: u64) {
    match reason {
        TrustWithdrawalReason::ReplaceRemovedAuthority => {
            WITHDRAWALS_REPLACE.fetch_add(1, Ordering::Relaxed);
        }
        TrustWithdrawalReason::ClearedOverride => {
            WITHDRAWALS_CLEAR.fetch_add(1, Ordering::Relaxed);
        }
    }
    if hbone > 0 {
        RETIRED_HBONE.fetch_add(hbone, Ordering::Relaxed);
    }
    if mesh_mtls > 0 {
        RETIRED_MESH_MTLS.fetch_add(mesh_mtls, Ordering::Relaxed);
    }
}

fn record_admission_refusal(kind: MeshTransportKind) {
    match kind {
        MeshTransportKind::Hbone => REFUSED_HBONE.fetch_add(1, Ordering::Relaxed),
        MeshTransportKind::MeshMtls => REFUSED_MESH_MTLS.fetch_add(1, Ordering::Relaxed),
    };
}

/// Fixed-cardinality projection of the process-wide gateway trust retirement
/// state. Every field is a count or a generation counter; nothing here is
/// derived from trust material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeshTrustRetirementMetrics {
    pub accepted_generation: u64,
    pub withdrawals_replace_removed_authority: u64,
    pub withdrawals_cleared_override: u64,
    pub retired_hbone: u64,
    pub retired_mesh_mtls: u64,
    pub refused_hbone: u64,
    pub refused_mesh_mtls: u64,
}

impl MeshTrustRetirementMetrics {
    pub fn withdrawals_for(&self, reason: TrustWithdrawalReason) -> u64 {
        match reason {
            TrustWithdrawalReason::ReplaceRemovedAuthority => {
                self.withdrawals_replace_removed_authority
            }
            TrustWithdrawalReason::ClearedOverride => self.withdrawals_cleared_override,
        }
    }

    pub fn retired_for(&self, kind: MeshTransportKind) -> u64 {
        match kind {
            MeshTransportKind::Hbone => self.retired_hbone,
            MeshTransportKind::MeshMtls => self.retired_mesh_mtls,
        }
    }

    pub fn refused_for(&self, kind: MeshTransportKind) -> u64 {
        match kind {
            MeshTransportKind::Hbone => self.refused_hbone,
            MeshTransportKind::MeshMtls => self.refused_mesh_mtls,
        }
    }
}

/// Snapshot the process-wide retirement counters.
pub fn metrics_snapshot() -> MeshTrustRetirementMetrics {
    MeshTrustRetirementMetrics {
        accepted_generation: ACCEPTED_GENERATION.load(Ordering::Relaxed),
        withdrawals_replace_removed_authority: WITHDRAWALS_REPLACE.load(Ordering::Relaxed),
        withdrawals_cleared_override: WITHDRAWALS_CLEAR.load(Ordering::Relaxed),
        retired_hbone: RETIRED_HBONE.load(Ordering::Relaxed),
        retired_mesh_mtls: RETIRED_MESH_MTLS.load(Ordering::Relaxed),
        refused_hbone: REFUSED_HBONE.load(Ordering::Relaxed),
        refused_mesh_mtls: REFUSED_MESH_MTLS.load(Ordering::Relaxed),
    }
}
