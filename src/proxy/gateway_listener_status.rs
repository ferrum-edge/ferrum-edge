//! Shared, bounded realization status for dynamic Gateway API listener ports
//! (issue #3810).
//!
//! [`crate::proxy::gateway_listener::GatewayListenerManager`] binds one socket
//! per Gateway API listener port and deliberately never dies over a port it
//! cannot bind: routing for that port fails closed, every healthy listener
//! keeps serving, and the bind is retried on a slow tick. That availability
//! policy is correct, but on its own it makes a partial outage invisible — the
//! process stays green while a configured listener has never bound or has died
//! after startup.
//!
//! This module is the observability consumer of that state. It owns one
//! atomically replaced snapshot that both the authenticated `/health` detail
//! and the Prometheus renderer read lock-free:
//!
//! * **Structured, not free-form.** Every entry carries the affected port, the
//!   protocol half ([`GatewayListenerProtocolHalf`] — TCP and QUIC fail
//!   independently), a bounded [`GatewayListenerFailureCategory`], whether the
//!   listener was refused at admission or failed at runtime
//!   ([`GatewayListenerFailureOrigin`]), the config generation that decided it,
//!   first/last observation timestamps, and how many consecutive reconcile
//!   passes have observed it.
//! * **Bounded, on two separate axes.** The *public* detail vector retains at
//!   most [`MAX_TRACKED_FAILURES`] entries, each `detail` sanitized to
//!   printable ASCII and truncated to [`MAX_DETAIL_CHARS`]. Behind it, a
//!   *private* lightweight ledger keeps first-seen time and observation count
//!   for every currently-active `(port, protocol half, reason)` identity up to
//!   [`MAX_ACTIVE_TRACKED_FAILURES`], carrying no free-form text at all. That
//!   separation is what makes the counters honest: an identity outside the
//!   public 64 is still a known, aged identity, so it is not re-counted as a
//!   fresh onset on every retry and its later recovery is still counted. Beyond
//!   the ledger bound the snapshot reports `overflowed` rather than silently
//!   mis-counting.
//! * **Generation-fenced under one lock.** [`GatewayListenerStatus::publish`]
//!   refuses a publication whose config generation is older than the one
//!   already published, mirroring
//!   `ProxyState::publish_gateway_listener_admission`. A reconcile pass that
//!   awaited socket retirement while a newer config was published can therefore
//!   never overwrite the newer generation's status. Acceptance and the
//!   snapshot/ledger/counter read-modify-write are **one** serialized decision:
//!   deciding acceptance outside the critical section would let an older
//!   publisher that passed the fence first be overtaken by a newer one and then
//!   overwrite it.
//! * **Recoverable.** A failure that is absent from the next publication is
//!   cleared from the snapshot and counted in
//!   `ferrum_gateway_listener_recoveries_total`. This is deliberately *not*
//!   [`crate::startup::ServingListenerFailures`], whose entries are sticky:
//!   that surface exists for fatal post-start serve-task exits, while a Gateway
//!   listener bind failure is retried every 30 s and must clear on its own.
//!
//! # What is never published here
//!
//! Prometheus labels come only from the two closed enums below. Port, listener
//! name, hostname, config generation, and error text are per-entry status
//! detail on the **authenticated** `/health` tier — never a metric label and
//! never part of an unauthenticated response body.
//!
//! # One classification model
//!
//! [`GatewayListenerProtocolHalf`] and [`GatewayListenerFailureCategory`] are
//! the *only* classification of a Gateway listener failure in the tree.
//! `gateway_listener::GatewayListenerRefusal`,
//! `gateway_listener::GatewayListenerProtocolFailure`, and
//! `gateway_listener::GatewayListenerBindFailure` all carry these two types
//! directly rather than a parallel enum that would have to be mapped — a
//! mapping layer is exactly how an operator-facing reason and a metric label
//! drift apart. The two axes are orthogonal: a QUIC socket that fails to bind
//! beside a healthy TCP listener is `(Quic, BindFailed)`, not a distinct
//! "quic_bind_failed" reason, so the label space stays the product of two
//! closed sets and an alert on `reason="bind_failed"` covers both halves.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;

/// Hard cap on retained per-listener failure entries in the **public**
/// snapshot, each of which carries a free-form (sanitized) `detail`.
///
/// The desired listener set already bounds this in practice; the cap is the
/// unconditional guarantee that a hostile or pathological configuration cannot
/// grow the snapshot without limit.
pub const MAX_TRACKED_FAILURES: usize = 64;

/// Hard cap on the **private** active-identity ledger.
///
/// The ledger holds no free-form text: one entry is a `(port, protocol half,
/// reason)` key plus a first-seen timestamp and an observation count, so an
/// entry costs a few tens of bytes and the whole ledger is bounded at a few
/// hundred kilobytes in the worst case.
///
/// The bound is deliberately far above any realistic Gateway listener set — a
/// deployment would have to have 4096 distinct *simultaneously failing*
/// `(port, half, reason)` triples to reach it — because everything the ledger
/// holds is what keeps the cumulative counters correct. Once the bound is
/// reached, further distinct identities in the same pass are dropped and
/// [`GatewayListenerStatusSnapshot::overflowed`] is set: previously tracked
/// identities that still appear anywhere in the stream keep their ledger slots,
/// and only brand-new identities compete for remaining slots in deterministic
/// key order. The publication scan itself is bounded the same way: it never
/// materializes the full distinct stream, so hostile configuration cardinality
/// cannot drive unbounded temporary allocation.
pub const MAX_ACTIVE_TRACKED_FAILURES: usize = 4096;

/// Hard cap on the sanitized `detail` retained for one entry.
pub const MAX_DETAIL_CHARS: usize = 200;

/// Which protocol half of a Gateway listener port a failure applies to.
///
/// A TLS-class listener owns a TCP socket and, when HTTP/3 is enabled, a QUIC
/// socket on the same numeric port. They fail independently: a QUIC bind
/// failure leaves HTTP/1.1 and HTTP/2 serving on the TCP half, and reporting it
/// as a listener-wide outage would be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerProtocolHalf {
    Tcp,
    Quic,
}

impl GatewayListenerProtocolHalf {
    /// Every protocol half, in metric-label order.
    pub const ALL: [Self; 2] = [Self::Tcp, Self::Quic];

    /// Fixed-cardinality metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}
/// Bounded reason a Gateway listener port (or one protocol half of it) is not
/// serving.
///
/// Closed set: these are the only values that ever reach a Prometheus label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerFailureCategory {
    /// The port is reserved by another Ferrum listener (proxy / admin /
    /// control-plane gRPC / capture).
    PortReserved,
    /// A process-global proxy frontend already owns the port with the other
    /// TLS class, so the Gateway listener cannot be served from it.
    ProcessGlobalClassMismatch,
    /// A TCP/TLS stream proxy in the same config claims the port.
    StreamPortCollision,
    /// A UDP/DTLS stream proxy in the same config claims the port, so the
    /// TLS-class listener's QUIC socket is refused.
    UdpStreamCollision,
    /// Two HTTP-family proxies claim the port with different TLS classes.
    ClassConflict,
    /// A dedicated Sidecar ingress bind cannot be absorbed by the process-global
    /// socket that already owns the port; widening a loopback-only claim onto a
    /// shared frontend would violate bind isolation (#3266).
    DedicatedBindConflict,
    /// A dedicated Sidecar ingress bind was declared on a frontend-TLS listener;
    /// Sidecar bind materialization supports plaintext HTTP-family listeners
    /// only.
    DedicatedBindTlsUnsupported,
    /// A TLS-terminating listener (or its QUIC half) was declared without
    /// frontend TLS material.
    FrontendTlsMissing,
    /// The OS refused the bind (address in use, missing `CAP_NET_BIND_SERVICE`,
    /// unavailable address), or the listener task failed to start.
    BindFailed,
    /// A listener task that had bound successfully later exited — cleanly, with
    /// an error, or by panic — and the port is being rebound.
    ListenerTaskEnded,
    /// A frontend class flip did not finish retiring the previous socket within
    /// the retire budget, so the replacement bind is deferred fail-closed.
    ClassFlipDeferred,
    /// A previous generation of this port has not finished closing its accept
    /// sockets, so the replacement bind is deferred fail-closed.
    RetirementPending,
}

impl GatewayListenerFailureCategory {
    /// Every category, in metric-label order.
    pub const ALL: [Self; 12] = [
        Self::PortReserved,
        Self::ProcessGlobalClassMismatch,
        Self::StreamPortCollision,
        Self::UdpStreamCollision,
        Self::ClassConflict,
        Self::DedicatedBindConflict,
        Self::DedicatedBindTlsUnsupported,
        Self::FrontendTlsMissing,
        Self::BindFailed,
        Self::ListenerTaskEnded,
        Self::ClassFlipDeferred,
        Self::RetirementPending,
    ];

    /// Fixed-cardinality metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortReserved => "port_reserved",
            Self::ProcessGlobalClassMismatch => "process_global_class_mismatch",
            Self::StreamPortCollision => "stream_port_collision",
            Self::UdpStreamCollision => "udp_stream_collision",
            Self::ClassConflict => "class_conflict",
            Self::DedicatedBindConflict => "dedicated_bind_conflict",
            Self::DedicatedBindTlsUnsupported => "dedicated_bind_tls_unsupported",
            Self::FrontendTlsMissing => "frontend_tls_missing",
            Self::BindFailed => "bind_failed",
            Self::ListenerTaskEnded => "listener_task_ended",
            Self::ClassFlipDeferred => "class_flip_deferred",
            Self::RetirementPending => "retirement_pending",
        }
    }

    /// Whether the listener was refused before any socket was attempted
    /// (configuration/admission) or failed while realizing it (runtime).
    ///
    /// Operators act on these differently: an admission refusal is repaired in
    /// the configuration, a runtime failure is repaired in the environment.
    pub fn origin(self) -> GatewayListenerFailureOrigin {
        match self {
            Self::PortReserved
            | Self::ProcessGlobalClassMismatch
            | Self::StreamPortCollision
            | Self::UdpStreamCollision
            | Self::ClassConflict
            | Self::DedicatedBindConflict
            | Self::DedicatedBindTlsUnsupported
            | Self::FrontendTlsMissing => GatewayListenerFailureOrigin::Admission,
            Self::BindFailed
            | Self::ListenerTaskEnded
            | Self::ClassFlipDeferred
            | Self::RetirementPending => GatewayListenerFailureOrigin::Runtime,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::PortReserved => 0,
            Self::ProcessGlobalClassMismatch => 1,
            Self::StreamPortCollision => 2,
            Self::UdpStreamCollision => 3,
            Self::ClassConflict => 4,
            Self::DedicatedBindConflict => 5,
            Self::DedicatedBindTlsUnsupported => 6,
            Self::FrontendTlsMissing => 7,
            Self::BindFailed => 8,
            Self::ListenerTaskEnded => 9,
            Self::ClassFlipDeferred => 10,
            Self::RetirementPending => 11,
        }
    }
}

/// Whether a listener is administratively refused or failed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerFailureOrigin {
    Admission,
    Runtime,
}

/// A listener death observed during a reconcile pass that recovered before the
/// pass ended.
///
/// These never enter the active ledger or authenticated health snapshot: the
/// death is counted in the cumulative failure and recovery counters exactly
/// once for the pass, while the rebound half stays healthy in `active_*` gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GatewayListenerTransientEvent {
    pub port: u16,
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
}

/// One failure observed during a reconcile pass, before it is merged with the
/// previous snapshot's first-seen / occurrence history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayListenerFailureObservation {
    pub port: u16,
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub detail: String,
}

impl GatewayListenerFailureObservation {
    pub fn new(
        port: u16,
        protocol: GatewayListenerProtocolHalf,
        category: GatewayListenerFailureCategory,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            port,
            protocol,
            category,
            detail: detail.into(),
        }
    }

    fn key(&self) -> FailureKey {
        (self.port, self.protocol, self.category)
    }
}

/// A currently-active Gateway listener failure, as published to authenticated
/// observability surfaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerFailureEntry {
    pub port: u16,
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub origin: GatewayListenerFailureOrigin,
    /// Config generation whose reconcile last observed this failure.
    pub config_generation: u64,
    /// Sanitized, bounded diagnostic. Never a secret; never a metric label.
    pub detail: String,
    pub first_observed_unix_ms: u64,
    pub last_observed_unix_ms: u64,
    /// Consecutive reconcile/retry passes that have observed this failure.
    pub observations: u64,
}

/// Active count for one (protocol, category) pair. Fixed cardinality.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerActiveCategory {
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub count: u64,
}

/// Bounded realization status for the dynamic Gateway listener set.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerStatusSnapshot {
    /// Config generation this status was decided for.
    pub config_generation: u64,
    /// Gateway listener ports the published config asked this process to bind.
    pub desired_listeners: usize,
    /// Gateway listener ports with a live TCP accept loop right now.
    pub active_listeners: usize,
    /// Distinct ports carrying at least one active failure.
    pub failed_ports: usize,
    /// Active failure identities tracked for this generation, including those
    /// dropped from `failures` by the [`MAX_TRACKED_FAILURES`] detail cap.
    ///
    /// Capped by [`MAX_ACTIVE_TRACKED_FAILURES`]; see `overflowed`.
    pub active_failures: usize,
    /// Entries actually retained in `failures`.
    pub retained_failures: usize,
    /// Whether `failures` was truncated by [`MAX_TRACKED_FAILURES`].
    pub truncated: bool,
    /// Whether this pass observed more distinct failure identities than
    /// [`MAX_ACTIVE_TRACKED_FAILURES`].
    ///
    /// When set, `active_failures`, `failed_ports`, `active_by_category`, and
    /// the cumulative counters account only for the tracked identities: the
    /// input exceeded the representable domain and the snapshot says so rather
    /// than reporting totals it cannot stand behind.
    pub overflowed: bool,
    /// Active counts by bounded (protocol, category). Exact for every tracked
    /// identity — never truncated by the [`MAX_TRACKED_FAILURES`] detail cap.
    pub active_by_category: Vec<GatewayListenerActiveCategory>,
    pub failures: Vec<GatewayListenerFailureEntry>,
}

impl GatewayListenerStatusSnapshot {
    /// Whether any dynamic Gateway listener is currently not serving.
    pub fn degraded(&self) -> bool {
        self.active_failures > 0 || self.overflowed
    }
}

/// One cumulative counter series, keyed by the two closed label sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayListenerCounter {
    pub protocol: GatewayListenerProtocolHalf,
    pub category: GatewayListenerFailureCategory,
    pub value: u64,
}

/// Cumulative counter view for the Prometheus renderer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayListenerCumulativeMetrics {
    /// Every non-zero cumulative failure series.
    pub failures_total: Vec<GatewayListenerCounter>,
    /// Every non-zero cumulative recovery series.
    pub recoveries_total: Vec<GatewayListenerCounter>,
}

/// Snapshot key: one failure is identified by port, protocol half, and reason.
type FailureKey = (
    u16,
    GatewayListenerProtocolHalf,
    GatewayListenerFailureCategory,
);

const PROTOCOL_COUNT: usize = GatewayListenerProtocolHalf::ALL.len();
const CATEGORY_COUNT: usize = GatewayListenerFailureCategory::ALL.len();

type CounterGrid = [[AtomicU64; CATEGORY_COUNT]; PROTOCOL_COUNT];

fn protocol_index(protocol: GatewayListenerProtocolHalf) -> usize {
    match protocol {
        GatewayListenerProtocolHalf::Tcp => 0,
        GatewayListenerProtocolHalf::Quic => 1,
    }
}

fn bump(
    grid: &CounterGrid,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) {
    grid[protocol_index(protocol)][category.index()].fetch_add(1, Ordering::Relaxed);
}

fn read(
    grid: &CounterGrid,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    grid[protocol_index(protocol)][category.index()].load(Ordering::Relaxed)
}

/// Lightweight per-identity history, kept for every tracked active failure —
/// including identities the public snapshot had to drop.
///
/// Deliberately free of any free-form text: this is the state that keeps
/// onset/recovery accounting correct, not an operator-facing detail record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveFailureHistory {
    first_observed_unix_ms: u64,
    /// Consecutive reconcile/retry passes that have observed this identity.
    observations: u64,
}

/// Everything a publication reads and writes, under one lock.
#[derive(Debug, Default)]
struct PublishLedger {
    /// The last config generation whose status was accepted, or `None` before
    /// the first publication.
    published_generation: Option<u64>,
    /// Every currently-active failure identity, bounded by
    /// [`MAX_ACTIVE_TRACKED_FAILURES`].
    active: BTreeMap<FailureKey, ActiveFailureHistory>,
}

/// Shared, atomically replaced Gateway listener realization status.
///
/// One instance is owned by the mode, handed to the listener manager as its
/// publisher and to `AdminState` as a reader. Reads are lock-free `ArcSwap` and
/// atomic loads so an unauthenticated `/health` probe flood cannot drive work,
/// block, or contend with a reconcile. The mutex below is only ever taken by a
/// publisher.
#[derive(Debug)]
pub struct GatewayListenerStatus {
    snapshot: ArcSwap<GatewayListenerStatusSnapshot>,
    /// Lock-free mirror of [`PublishLedger::published_generation`], stored
    /// **after** the snapshot it belongs to is visible. Each store is Release
    /// so an Acquire load of this generation synchronizes-with that publication
    /// and therefore cannot advertise a generation whose snapshot is not yet
    /// visible — including after `published_generation_initialized` is already
    /// true.
    published_generation: AtomicU64,
    /// Whether [`Self::published_generation`] has been initialized by an
    /// accepted publication. Separated so generation `0` and `u64::MAX` are
    /// exact values with no sentinel encoding. This flag is not itself the
    /// generation fence after the first publication: every later advertised
    /// generation is a Release store on [`Self::published_generation`].
    published_generation_initialized: AtomicBool,
    /// Serializes generation acceptance together with the read-modify-write of
    /// the snapshot, the active ledger, and the cumulative counters. Never held
    /// by a reader.
    ledger: Mutex<PublishLedger>,
    failures_total: CounterGrid,
    recoveries_total: CounterGrid,
}

impl Default for GatewayListenerStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayListenerStatus {
    pub fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(GatewayListenerStatusSnapshot::default()),
            published_generation: AtomicU64::new(0),
            published_generation_initialized: AtomicBool::new(false),
            ledger: Mutex::new(PublishLedger::default()),
            failures_total: Default::default(),
            recoveries_total: Default::default(),
        }
    }

    /// Lock-free current status.
    pub fn snapshot(&self) -> Arc<GatewayListenerStatusSnapshot> {
        self.snapshot.load_full()
    }

    /// The last config generation whose status was accepted, lock-free.
    ///
    /// `None` before the first accepted publication. This never runs ahead of
    /// [`Self::snapshot`]: each advertised generation is an Acquire load of a
    /// Release store that happens after the snapshot it describes is visible.
    /// Generation `0` and `u64::MAX` are exact values; the initialized flag
    /// exists only so those are not sentinels.
    // The binary target re-declares these modules, so a `pub` item consumed
    // only by `tests/` reads as dead code there.
    #[allow(dead_code)]
    pub fn published_generation(&self) -> Option<u64> {
        if self
            .published_generation_initialized
            .load(Ordering::Acquire)
        {
            // Acquire on the generation itself: after the first publication
            // `initialized` stays `true`, so a later Release of that same
            // boolean would not synchronize a reader that already observed it.
            Some(self.published_generation.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Cumulative failure/recovery counters, non-zero entries only.
    pub fn cumulative(&self) -> GatewayListenerCumulativeMetrics {
        let mut failures_total = Vec::new();
        let mut recoveries_total = Vec::new();
        for protocol in GatewayListenerProtocolHalf::ALL {
            for category in GatewayListenerFailureCategory::ALL {
                let failures = read(&self.failures_total, protocol, category);
                if failures > 0 {
                    failures_total.push(GatewayListenerCounter {
                        protocol,
                        category,
                        value: failures,
                    });
                }
                let recoveries = read(&self.recoveries_total, protocol, category);
                if recoveries > 0 {
                    recoveries_total.push(GatewayListenerCounter {
                        protocol,
                        category,
                        value: recoveries,
                    });
                }
            }
        }
        GatewayListenerCumulativeMetrics {
            failures_total,
            recoveries_total,
        }
    }

    /// Publish the realization status decided for `config_generation`.
    ///
    /// Returns `false` — changing nothing at all — when `config_generation` is
    /// older than the generation already published. A reconcile pass that
    /// awaited socket retirement can finish after a newer config was published;
    /// its decision must never govern the newer generation's status, exactly as
    /// its route admission decision must not.
    ///
    /// An equal generation is accepted: the supervisor re-reconciles the same
    /// generation on every retry tick, and that is how a recovery clears.
    ///
    /// Acceptance is decided *inside* the same critical section that performs
    /// the merge, so the whole decision — accept/reject, ledger ageing,
    /// counters, snapshot — is one serialized read-modify-write. Deciding
    /// acceptance first and merging afterwards would be unsound: an older
    /// publisher that cleared the fence could be overtaken by a newer one and
    /// then overwrite the newer status with its own.
    ///
    /// `observations` is consumed inside that critical section, so a rejected
    /// publication leaves the snapshot, the active ledger, the cumulative
    /// counters, and every timestamp exactly as they were.
    // The binary target re-declares these modules, so a `pub` item consumed
    // only by `tests/` reads as dead code there.
    #[allow(dead_code)]
    pub fn publish(
        &self,
        config_generation: u64,
        desired_listeners: usize,
        active_listeners: usize,
        observations: impl IntoIterator<Item = GatewayListenerFailureObservation>,
        now_unix_ms: u64,
    ) -> bool {
        self.publish_transients(
            config_generation,
            desired_listeners,
            active_listeners,
            observations,
            std::iter::empty(),
            now_unix_ms,
        )
    }

    /// Like [`Self::publish`], but also records transient same-pass events such
    /// as a listener-task death that rebinded before the pass ended.
    pub fn publish_transients(
        &self,
        config_generation: u64,
        desired_listeners: usize,
        active_listeners: usize,
        observations: impl IntoIterator<Item = GatewayListenerFailureObservation>,
        transient_events: impl IntoIterator<Item = GatewayListenerTransientEvent>,
        now_unix_ms: u64,
    ) -> bool {
        let mut ledger = match self.ledger.lock() {
            Ok(guard) => guard,
            // A panicking publisher cannot corrupt the ledger (it is replaced
            // wholesale below), so recover rather than propagating the poison
            // into an observability path.
            Err(poisoned) => poisoned.into_inner(),
        };

        if ledger
            .published_generation
            .is_some_and(|published| config_generation < published)
        {
            return false;
        }

        let mut scan = BoundedStreamScan::new();
        for observation in observations {
            scan.observe(&ledger.active, observation);
        }
        let overflowed = scan.overflowed;
        let details = scan.public_details();

        // Age every selected identity that was already active, count an onset
        // for every selected identity that was not. The previous state comes
        // from the private ledger, never from the truncated public vector: an
        // identity the detail cap dropped is still a known, aged identity when
        // it remains selected.
        let mut next_active: BTreeMap<FailureKey, ActiveFailureHistory> = BTreeMap::new();
        for key in scan
            .prior_seen
            .iter()
            .copied()
            .chain(scan.new_candidates.iter().copied())
        {
            let (_, protocol, category) = key;
            let history = match ledger.active.get(&key) {
                Some(previous) => ActiveFailureHistory {
                    first_observed_unix_ms: previous.first_observed_unix_ms,
                    observations: previous.observations.saturating_add(1),
                },
                None => {
                    bump(&self.failures_total, protocol, category);
                    ActiveFailureHistory {
                        first_observed_unix_ms: now_unix_ms,
                        observations: 1,
                    }
                }
            };
            next_active.insert(key, history);
        }

        // Recovery is decided only from the bounded prior ledger's seen flags.
        // A previously tracked identity encountered anywhere in the stream was
        // marked seen and kept; only genuinely absent prior identities recover.
        for key in ledger.active.keys() {
            if scan.prior_seen.contains(key) {
                continue;
            }
            let (_, protocol, category) = *key;
            bump(&self.recoveries_total, protocol, category);
        }

        // Transient same-pass events advance both cumulative counters without
        // entering the active ledger. Deduped within the pass so a death that
        // both logs and rebinds in one reconcile is counted exactly once.
        let mut seen_transient: BTreeSet<FailureKey> = BTreeSet::new();
        for event in transient_events {
            let key = (event.port, event.protocol, event.category);
            if !seen_transient.insert(key) {
                continue;
            }
            bump(&self.failures_total, event.protocol, event.category);
            bump(&self.recoveries_total, event.protocol, event.category);
        }

        let active_failures = next_active.len();
        let mut failed_ports = 0usize;
        let mut last_port: Option<u16> = None;
        let mut active_counts = [[0u64; CATEGORY_COUNT]; PROTOCOL_COUNT];
        for (port, protocol, category) in next_active.keys().copied() {
            // Keys are ordered by port first, so a change of port is a new
            // distinct port.
            if last_port != Some(port) {
                failed_ports += 1;
                last_port = Some(port);
            }
            active_counts[protocol_index(protocol)][category.index()] += 1;
        }
        let mut active_by_category: Vec<GatewayListenerActiveCategory> = Vec::new();
        for protocol in GatewayListenerProtocolHalf::ALL {
            for category in GatewayListenerFailureCategory::ALL {
                let count = active_counts[protocol_index(protocol)][category.index()];
                if count > 0 {
                    active_by_category.push(GatewayListenerActiveCategory {
                        protocol,
                        category,
                        count,
                    });
                }
            }
        }

        let failures: Vec<GatewayListenerFailureEntry> = details
            .into_iter()
            .filter_map(|(key, detail)| {
                let (port, protocol, category) = key;
                // Every retained-detail key was inserted into `next_active` in
                // the same pass; skipping rather than indexing keeps this
                // panic-free regardless.
                let history = next_active.get(&key)?;
                Some(GatewayListenerFailureEntry {
                    port,
                    protocol,
                    category,
                    origin: category.origin(),
                    config_generation,
                    detail,
                    first_observed_unix_ms: history.first_observed_unix_ms,
                    last_observed_unix_ms: now_unix_ms,
                    observations: history.observations,
                })
            })
            .collect();
        let truncated = active_failures > failures.len();

        ledger.active = next_active;
        ledger.published_generation = Some(config_generation);
        self.snapshot.store(Arc::new(GatewayListenerStatusSnapshot {
            config_generation,
            desired_listeners,
            active_listeners,
            failed_ports,
            active_failures,
            retained_failures: failures.len(),
            truncated,
            overflowed,
            active_by_category,
            failures,
        }));
        // Snapshot first, then advertise this generation with Release so a
        // lock-free Acquire load cannot observe the generation before the
        // snapshot it names. Every publication uses Release on the generation
        // itself: a Release store of `initialized = true` only synchronizes
        // readers that observe *that* store, and after the first publication
        // the flag is already true.
        self.published_generation
            .store(config_generation, Ordering::Release);
        self.published_generation_initialized
            .store(true, Ordering::Release);
        true
    }
}

/// One-pass bounded selection over a failure-observation stream.
///
/// Temporary identity storage is rigorously O(MAX_ACTIVE_TRACKED_FAILURES):
/// `prior_seen` has one slot per already-tracked identity (≤ 4096) and
/// `new_candidates` holds at most the remaining ledger slots (≤ 4096). Distinct
/// unretained new identities set `overflowed` without being stored, so hostile
/// configuration cardinality cannot grow this pass's working set. Duplicate
/// unretained new keys are not distinguished: they never enter the ledger, so
/// they cannot double-count onsets, but any such sighting still leaves
/// `overflowed` true.
///
/// Recovery is decided only from `prior_seen`. A prior identity that appears
/// anywhere in the stream is marked seen and kept — even if it arrives after a
/// burst of brand-new keys that would have filled an encounter-order cap.
/// Brand-new identities then compete for whatever slots remain, in
/// deterministic key order, independent of encounter order.
///
/// Detail strings never track the full stream. Each population (seen prior, new
/// candidates) keeps at most [`MAX_TRACKED_FAILURES`] sanitized strings so a
/// late prior identity can still claim a public-detail slot after small new
/// keys are evicted. The published vector is the 64 lowest selected keys.
struct BoundedStreamScan {
    prior_seen: BTreeSet<FailureKey>,
    new_candidates: BTreeSet<FailureKey>,
    overflowed: bool,
    prior_details: BTreeMap<FailureKey, String>,
    new_details: BTreeMap<FailureKey, String>,
}

impl BoundedStreamScan {
    fn new() -> Self {
        Self {
            prior_seen: BTreeSet::new(),
            new_candidates: BTreeSet::new(),
            overflowed: false,
            prior_details: BTreeMap::new(),
            new_details: BTreeMap::new(),
        }
    }

    fn remaining(&self) -> usize {
        MAX_ACTIVE_TRACKED_FAILURES.saturating_sub(self.prior_seen.len())
    }

    fn evict_excess_new(&mut self) {
        let remaining = self.remaining();
        while self.new_candidates.len() > remaining {
            if let Some(largest) = self.new_candidates.pop_last() {
                self.new_details.remove(&largest);
            }
            self.overflowed = true;
        }
    }

    fn observe(
        &mut self,
        prior: &BTreeMap<FailureKey, ActiveFailureHistory>,
        observation: GatewayListenerFailureObservation,
    ) {
        let key = observation.key();
        if prior.contains_key(&key) {
            if !self.prior_seen.insert(key) {
                // Duplicate prior identity in this pass: keep the first detail
                // and do not double-count the occurrence.
                return;
            }
            self.evict_excess_new();
            retain_detail(&mut self.prior_details, key, &observation.detail);
            return;
        }
        if self.new_candidates.contains(&key) {
            return;
        }
        let remaining = self.remaining();
        if remaining == 0 {
            // Unretained new identity: remember overflow, store nothing.
            self.overflowed = true;
            return;
        }
        if self.new_candidates.len() < remaining {
            self.new_candidates.insert(key);
            retain_detail(&mut self.new_details, key, &observation.detail);
            return;
        }
        if let Some(largest) = self.new_candidates.last().copied() {
            if key < largest {
                self.new_candidates.remove(&largest);
                self.new_details.remove(&largest);
                self.new_candidates.insert(key);
                retain_detail(&mut self.new_details, key, &observation.detail);
            }
            self.overflowed = true;
        }
    }

    fn public_details(&mut self) -> BTreeMap<FailureKey, String> {
        let mut details = BTreeMap::new();
        let mut prior = self.prior_seen.iter().peekable();
        let mut new = self.new_candidates.iter().peekable();
        while details.len() < MAX_TRACKED_FAILURES {
            let next = match (prior.peek(), new.peek()) {
                (Some(prior_key), Some(new_key)) if **prior_key <= **new_key => prior.next(),
                (Some(_), Some(_)) => new.next(),
                (Some(_), None) => prior.next(),
                (None, Some(_)) => new.next(),
                (None, None) => break,
            };
            let Some(&key) = next else {
                break;
            };
            if let Some(detail) = self
                .prior_details
                .remove(&key)
                .or_else(|| self.new_details.remove(&key))
            {
                details.insert(key, detail);
            }
        }
        details
    }
}

/// Keep the sanitized `detail` for `key` only while it belongs to the
/// lowest-keyed [`MAX_TRACKED_FAILURES`] identities seen so far.
///
/// The public vector is the first `MAX_TRACKED_FAILURES` entries in key order,
/// so evicting the current largest key keeps exactly that set while never
/// holding more than the cap in strings — and never sanitizing a string that
/// cannot be retained.
fn retain_detail(details: &mut BTreeMap<FailureKey, String>, key: FailureKey, detail: &str) {
    if details.len() >= MAX_TRACKED_FAILURES {
        match details.keys().next_back().copied() {
            Some(largest) if key < largest => {
                details.remove(&largest);
            }
            _ => return,
        }
    }
    details.insert(key, sanitize_detail(detail));
}

/// The installed process-wide Gateway listener status, if this mode binds
/// dynamic Gateway listeners.
static GLOBAL: OnceLock<Arc<GatewayListenerStatus>> = OnceLock::new();

/// Publish this mode's status on the process-wide `/metrics` slot.
///
/// The authoritative handle is the `Arc` the mode owns: it is what the manager
/// publishes to and what `AdminState` reads for `/health`, so a process running
/// more than one serving runtime (a test binary) still gets per-instance health
/// detail. `/metrics` is inherently process-wide, so this slot is
/// first-writer-wins and is never re-pointed — exactly like
/// [`crate::dp_config_freshness::install`], which likewise must not be
/// swapped out from under an already-scraping process.
pub fn install_for_metrics(status: &Arc<GatewayListenerStatus>) {
    let _ = GLOBAL.set(status.clone());
}

/// The installed process-wide status, if any.
pub fn global() -> Option<&'static Arc<GatewayListenerStatus>> {
    GLOBAL.get()
}

/// Wall-clock milliseconds for a status observation.
///
/// Production timestamps only; the merge itself takes the clock as an argument
/// so tests are deterministic.
pub fn now_unix_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Bound and sanitize a diagnostic before it is retained.
///
/// Gateway listener errors are gateway-authored text plus OS error strings, but
/// this is a durable operator-visible surface: strip anything that is not
/// printable ASCII (control characters would corrupt a log or terminal render)
/// and cap the length so a pathological error cannot grow the snapshot.
fn sanitize_detail(detail: &str) -> String {
    let mut out = String::with_capacity(detail.len().min(MAX_DETAIL_CHARS + 3));
    let mut kept = 0usize;
    for ch in detail.chars() {
        if kept >= MAX_DETAIL_CHARS {
            out.push_str("...");
            break;
        }
        if ch == ' ' || ch.is_ascii_graphic() {
            out.push(ch);
            kept += 1;
        } else {
            // Newlines, tabs, and any non-ASCII byte sequence collapse to a
            // single space rather than being dropped, so token boundaries in
            // the original message survive.
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
                kept += 1;
            }
        }
    }
    out.trim_end().to_string()
}

/// Render one unlabeled process gauge, honoring the shared `ns_label`
/// convention (`,namespace="…"`, or empty when no namespace is configured).
fn render_process_gauge(output: &mut String, metric_name: &str, value: u64, ns_label: &str) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value}\n"));
    } else {
        let body = ns_label.strip_prefix(',').unwrap_or(ns_label);
        output.push_str(&format!("{metric_name}{{{body}}} {value}\n"));
    }
}

/// Render one `(protocol, reason)` series.
fn render_classified(
    output: &mut String,
    metric_name: &str,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
    value: u64,
    ns_label: &str,
) {
    output.push_str(&format!(
        "{metric_name}{{protocol=\"{}\",reason=\"{}\"{ns_label}}} {value}\n",
        protocol.as_str(),
        category.as_str()
    ));
}

/// Render the fixed-cardinality Gateway listener families.
///
/// Every label value comes from [`GatewayListenerProtocolHalf::as_str`] or
/// [`GatewayListenerFailureCategory::as_str`] — both closed sets — plus the
/// process namespace. Port, listener name, host, config generation, and error
/// text are deliberately absent: they are authenticated `/health` detail. The
/// complete series count is therefore `3 + 3 * 2 * 12` regardless of how many
/// Gateway listeners a configuration declares.
///
/// Emits nothing when the process has no dynamic Gateway listener status, so a
/// mode that never binds these listeners does not advertise empty families.
pub fn render_prometheus(
    output: &mut String,
    ns_label: &str,
    status: Option<&GatewayListenerStatus>,
) {
    let Some(status) = status else {
        return;
    };
    let snapshot = status.snapshot();
    let cumulative = status.cumulative();

    output.push_str(
        "# HELP ferrum_gateway_listeners_desired Dynamic Gateway API listener ports the published configuration asks this process to bind.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listeners_desired gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listeners_desired",
        snapshot.desired_listeners as u64,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listeners_active Dynamic Gateway API listener ports currently bound and accepting.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listeners_active gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listeners_active",
        snapshot.active_listeners as u64,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listener_failed_ports Distinct dynamic Gateway API listener ports with at least one active failure.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failed_ports gauge\n");
    render_process_gauge(
        output,
        "ferrum_gateway_listener_failed_ports",
        snapshot.failed_ports as u64,
        ns_label,
    );

    // The active gauge and both counters zero-fill the complete closed label
    // space, so an alert on a recovered listener reads `0` rather than losing
    // the series entirely.
    output.push_str(
        "# HELP ferrum_gateway_listener_failures_active Dynamic Gateway API listener halves currently failing, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failures_active gauge\n");
    for protocol in GatewayListenerProtocolHalf::ALL {
        for category in GatewayListenerFailureCategory::ALL {
            let count = snapshot
                .active_by_category
                .iter()
                .find(|active| active.protocol == protocol && active.category == category)
                .map_or(0, |active| active.count);
            render_classified(
                output,
                "ferrum_gateway_listener_failures_active",
                protocol,
                category,
                count,
                ns_label,
            );
        }
    }

    output.push_str(
        "# HELP ferrum_gateway_listener_failures_total Dynamic Gateway API listener failures observed since process start, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_failures_total counter\n");
    render_cumulative(
        output,
        "ferrum_gateway_listener_failures_total",
        &cumulative.failures_total,
        ns_label,
    );

    output.push_str(
        "# HELP ferrum_gateway_listener_recoveries_total Dynamic Gateway API listener failures cleared by a later reconcile since process start, by protocol half and bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_gateway_listener_recoveries_total counter\n");
    render_cumulative(
        output,
        "ferrum_gateway_listener_recoveries_total",
        &cumulative.recoveries_total,
        ns_label,
    );
}

fn render_cumulative(
    output: &mut String,
    metric_name: &str,
    values: &[GatewayListenerCounter],
    ns_label: &str,
) {
    for protocol in GatewayListenerProtocolHalf::ALL {
        for category in GatewayListenerFailureCategory::ALL {
            let value = values
                .iter()
                .find(|series| series.protocol == protocol && series.category == category)
                .map_or(0, |series| series.value);
            render_classified(output, metric_name, protocol, category, value, ns_label);
        }
    }
}
