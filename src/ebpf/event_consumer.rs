//! Userspace consumer for the SOCK_OPS ringbuf.
//!
//! The kernel-side `BPF_PROG_TYPE_SOCK_OPS` program emits TCP lifecycle and
//! handshake records, the SK_SKB parser emits captured accept-to-first-byte,
//! and connect4/connect6 emit BPF drop-reason records. Userspace polls the
//! shared ringbuf, decodes records, and updates [`BpfMetricsState`].
//!
//! ## Production wiring (GAP-3D)
//!
//! The kernel-side `BPF_PROG_TYPE_SOCK_OPS` program is loaded and pinned
//! by the node-agent (`src/ebpf/loader.rs::attach_sock_ops`). The mesh
//! proxy opens the pinned ringbuf at
//! [`BPF_SOCK_OPS_EVENTS_PIN_PATH`](crate::ebpf::BPF_SOCK_OPS_EVENTS_PIN_PATH)
//! and runs [`run_pinned_consumer`] as a background task that:
//!   1. Drives the kernel ringbuf with `tokio::io::unix::AsyncFd`, draining
//!      the records the kernel has published on each wakeup — and nothing
//!      past the producer position, which is what keeps a record from being
//!      counted twice (see [`RingBufCursor`] and issue #5563). Each wakeup
//!      is bounded by [`RINGBUF_DRAIN_RECORD_BUDGET`]; a pass that hits the
//!      budget retains ringbuf readiness instead of clearing it, so the
//!      drain resumes immediately while the other `select!` arms still get
//!      a turn.
//!   2. Decodes each record via [`SockOpsEvent::from_record_bytes`] and
//!      hands it to [`SockOpsConsumer::handle_event`].
//!   3. Queues first-data SockHash removal behind a bounded grace period, so
//!      ringbuf visibility cannot race the still-running parser/verdict callback.
//!   4. Polls the per-CPU dropped-events counter
//!      ([`BPF_SOCK_OPS_STATS_PIN_PATH`](crate::ebpf::BPF_SOCK_OPS_STATS_PIN_PATH))
//!      after each drain. When the sum advances, the consumer is in an
//!      overrun regime; [`SockOpsConsumer::record_overrun`] handles the
//!      warn/recover state machine so the log line never spams.
//!   5. Polls the per-CPU capture-bypass counters in the same stats map on a
//!      wall-clock timer and publishes their deltas. Those slots — not the
//!      `SOCK_OPS_EVENT_DROP_REASON` ringbuf records — are the accounting
//!      authority for `ferrum_mesh_bpf_drops_total`: a full ring discards the
//!      record while the kernel slot still moves, so counting records lost
//!      bypass classifications exactly when the node was busiest.
//!
//! On Linux `ebpf` builds, [`run_pinned_consumer`] waits for the
//! node-agent pins with capped exponential backoff (1s → 30s) and
//! attaches when they appear; it returns only on shutdown or an
//! unrecoverable attach error. The first miss logs one `info!` line.
//! Non-Linux / non-`ebpf` builds never start this task. The
//! [`BpfMetricsState`] stays at zero until maps appear — the
//! `__mesh_bpf_metrics` plugin still emits a stable Prometheus surface so
//! dashboards do not break.

#![allow(dead_code)]

use std::sync::Arc;

use ferrum_ebpf_common::{
    SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT, SOCK_OPS_DROP_BYPASS_UID_HIT,
    SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
    SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, SOCK_OPS_EVENT_ACCEPT_ESTABLISHED,
    SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, SOCK_OPS_EVENT_CONNECT,
    SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_FIN, SOCK_OPS_EVENT_RST, SOCK_OPS_EVENT_RTT_SAMPLE,
    SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY, SOCK_OPS_STATS_DROP_BYPASS_UID_HIT,
    SOCK_OPS_STATS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_STATS_DROP_EXCLUDE_PORT_HIT,
    SOCK_OPS_STATS_DROP_NOT_IN_INCLUDE_CIDR, SockOpsRecord,
};
use tracing::{info, warn};

use crate::ebpf::bpf_metrics::{BpfDropReason, BpfMetricsState, TcpDirection};

/// Number of advertised capture-bypass reasons.
pub const BPF_DROP_REASON_COUNT: usize = 4;

/// Fixed `(reason, FERRUM_SOCK_OPS_STATS index)` pairs shared by the kernel
/// emitter (`emit_drop_reason`) and the userspace poller.
///
/// The order is the Prometheus exposition order; the indices are the
/// accounting authority for `ferrum_mesh_bpf_drops_total`. Slot `0` is
/// deliberately absent — it is the ringbuf dropped-events counter that drives
/// the overrun regime, and a drop reason landing there would manufacture a
/// phantom overrun.
pub const BPF_DROP_REASON_STATS_SLOTS: [(BpfDropReason, u32); BPF_DROP_REASON_COUNT] = [
    (
        BpfDropReason::BypassUidHit,
        SOCK_OPS_STATS_DROP_BYPASS_UID_HIT,
    ),
    (
        BpfDropReason::ExcludeCidrHit,
        SOCK_OPS_STATS_DROP_EXCLUDE_CIDR_HIT,
    ),
    (
        BpfDropReason::NotInIncludeCidr,
        SOCK_OPS_STATS_DROP_NOT_IN_INCLUDE_CIDR,
    ),
    (
        BpfDropReason::ExcludePortHit,
        SOCK_OPS_STATS_DROP_EXCLUDE_PORT_HIT,
    ),
];

/// Number of consecutive `Drained` poll outcomes after an overrun before
/// the consumer considers the regime recovered. Three is consistent with
/// the overload manager's hysteresis pattern (warn enter, info recover,
/// no flap).
pub const SOCK_OPS_RECOVERY_THRESHOLD: u32 = 3;

/// One decoded SOCK_OPS event.
///
/// This enum is intentionally minimal — the kernel program emits records
/// keyed by `event_type` plus a small payload. The userspace decoder maps
/// those records into this shape so the counter logic stays decoupled
/// from the BPF wire format. When the wire format evolves, only
/// [`SockOpsEvent::from_record`] has to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsEvent {
    Connect,
    AcceptEstablished,
    /// Abnormal ESTABLISHED→CLOSE. Direction is not attributed (kernel
    /// SOCK_OPS state callbacks cannot distinguish sent vs received RST).
    Rst,
    Fin {
        direction: TcpDirection,
    },
    RttSample {
        srtt_us: u64,
    },
    SynToAckLatency {
        us: u64,
    },
    AcceptToFirstByteLatency {
        us: u64,
        socket_cookie: u64,
    },
    DropReason(BpfDropReason),
}

impl SockOpsEvent {
    /// Decode a single [`SockOpsRecord`] into the userspace enum. Returns
    /// `None` for unknown discriminants so the consumer can log + drop
    /// instead of panicking.
    pub fn from_record(record: SockOpsRecord) -> Option<Self> {
        let direction = match record.direction {
            SOCK_OPS_DIRECTION_SENT => Some(TcpDirection::Sent),
            SOCK_OPS_DIRECTION_RECEIVED => Some(TcpDirection::Received),
            _ => None,
        };
        let drop_reason = match record.drop_reason {
            SOCK_OPS_DROP_BYPASS_UID_HIT => Some(BpfDropReason::BypassUidHit),
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT => Some(BpfDropReason::ExcludeCidrHit),
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR => Some(BpfDropReason::NotInIncludeCidr),
            SOCK_OPS_DROP_EXCLUDE_PORT_HIT => Some(BpfDropReason::ExcludePortHit),
            _ => None,
        };
        match record.event_type {
            SOCK_OPS_EVENT_CONNECT => Some(Self::Connect),
            SOCK_OPS_EVENT_ACCEPT_ESTABLISHED => Some(Self::AcceptEstablished),
            // Direction field is ignored for RST: the producer emits unknown
            // (0). Older synthetic records with sent/received still decode
            // to the same non-directional event.
            SOCK_OPS_EVENT_RST => Some(Self::Rst),
            SOCK_OPS_EVENT_FIN => Some(Self::Fin {
                direction: direction.unwrap_or(TcpDirection::Received),
            }),
            SOCK_OPS_EVENT_RTT_SAMPLE => Some(Self::RttSample {
                srtt_us: record.value,
            }),
            SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY => Some(Self::SynToAckLatency { us: record.value }),
            SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY => Some(Self::AcceptToFirstByteLatency {
                us: record.value,
                socket_cookie: record.accepted_socket_cookie(),
            }),
            SOCK_OPS_EVENT_DROP_REASON => Some(Self::DropReason(drop_reason?)),
            _ => None,
        }
    }

    /// Decode a [`SockOpsRecord`] from a raw ringbuf byte slice. Returns
    /// `None` if the slice is too short or the discriminants are unknown.
    pub fn from_record_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<SockOpsRecord>() {
            return None;
        }
        // Safety: SockOpsRecord is `#[repr(C)]` with fixed-width fields
        // (no padding inserted by Rust besides what we explicitly add as
        // `_pad`). `read_unaligned` tolerates a non-8-aligned `bytes`
        // pointer; the ringbuf hands out 8-byte-aligned slices in
        // practice but we don't rely on that.
        let record = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const SockOpsRecord) };
        Self::from_record(record)
    }
}

/// Decoded ringbuf consumption outcome reported by a single poll cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// Polled events that fit in the ringbuf and got handed to the
    /// dispatch table.
    Drained { events: u32 },
    /// Kernel side reported overrun (ringbuf full before userspace could
    /// drain) — operator-visible regression.
    Overrun,
}

/// Userspace SOCK_OPS event consumer.
///
/// Wraps the shared [`BpfMetricsState`] with the dispatch logic that
/// routes decoded events into counter increments and manages the
/// ringbuf-overrun state machine. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct SockOpsConsumer {
    metrics: Arc<BpfMetricsState>,
}

impl SockOpsConsumer {
    pub fn new(metrics: Arc<BpfMetricsState>) -> Self {
        Self { metrics }
    }

    pub fn metrics(&self) -> Arc<BpfMetricsState> {
        self.metrics.clone()
    }

    /// Apply a decoded event to the metrics state. Called once per
    /// successfully-decoded ringbuf record.
    pub fn handle_event(&self, event: SockOpsEvent) {
        self.metrics.record_ringbuf_event();
        match event {
            SockOpsEvent::Connect => self.metrics.record_connect(),
            SockOpsEvent::AcceptEstablished => self.metrics.record_accept_established(),
            SockOpsEvent::Rst => self.metrics.record_rst(),
            SockOpsEvent::Fin { direction } => self.metrics.record_fin(direction),
            SockOpsEvent::RttSample { srtt_us } => self.metrics.record_srtt_sample(srtt_us),
            SockOpsEvent::SynToAckLatency { us } => self.metrics.record_syn_to_ack(us),
            SockOpsEvent::AcceptToFirstByteLatency { us, .. } => {
                self.metrics.record_accept_to_first_byte(us)
            }
            // Drop reasons are NOT counted here. The record still belongs to
            // the event stream (and is counted as a ringbuf event above), but
            // the accounting authority is the kernel's per-CPU
            // `FERRUM_SOCK_OPS_STATS` drop-reason slot, drained by
            // `publish_drop_reason_deltas`. A full ringbuf discards this
            // record, so counting it would under-report bypass decisions
            // exactly when the node is busiest — and counting BOTH would
            // double-count every decision that survived the ring.
            SockOpsEvent::DropReason(_) => {}
        }
    }

    /// Add `count` bypass decisions observed for `reason` on the kernel-side
    /// per-CPU counters. Sole writer for the drop-reason counters; see
    /// [`BpfMetricsState::record_drops`].
    pub fn record_drops(&self, reason: BpfDropReason, count: u64) {
        self.metrics.record_drops(reason, count);
    }

    /// Drive the warn-on-enter / info-on-recover state machine after
    /// observing a ringbuf overrun. Suppresses per-event log spam.
    pub fn record_overrun(&self) {
        if self.metrics.record_ringbuf_overrun() {
            warn!(
                target: "ferrum::ebpf::sock_ops",
                "BPF sock_ops ringbuf overrun: userspace consumer fell behind. \
                 Some TCP-layer events were dropped on the kernel side. \
                 Increase FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES or reduce event rate."
            );
        }
    }

    /// Indicate that the consumer caught up and successive `record_overrun`
    /// calls would fire a fresh warn. The caller decides when "caught up"
    /// means — typically: N consecutive poll cycles with `Drained { .. }`
    /// outcomes after the last overrun. Once the recovery threshold is
    /// met, call this once to flip the state and emit a single info line.
    pub fn record_recovery(&self) {
        if self.metrics.mark_ringbuf_recovered() {
            info!(
                target: "ferrum::ebpf::sock_ops",
                "BPF sock_ops ringbuf recovered from overrun regime"
            );
        }
    }

    /// Apply a polled outcome to the state machine. Convenience wrapper
    /// around `record_overrun` / `record_recovery` with a configurable
    /// recovery threshold: once `recovery_threshold` consecutive
    /// `Drained` outcomes are observed after an overrun, the regime is
    /// considered recovered. Returns the regime state *after* this call.
    pub fn observe_poll(
        &self,
        outcome: PollOutcome,
        consecutive_drained: &mut u32,
        recovery_threshold: u32,
    ) -> bool {
        match outcome {
            PollOutcome::Drained { events } => {
                // Only advance the recovery counter on real drain progress.
                // A spurious wakeup (epoll-edge artifact, drained=0) must
                // NOT count toward recovery while the kernel is still
                // dropping events on another CPU. Without this guard, three
                // spurious wakeups in a row would clear the overrun regime
                // and emit a false "recovered" info line.
                if events > 0 && self.metrics.is_in_overrun_regime() {
                    *consecutive_drained = consecutive_drained.saturating_add(1);
                    if *consecutive_drained >= recovery_threshold {
                        self.record_recovery();
                        *consecutive_drained = 0;
                    }
                }
            }
            PollOutcome::Overrun => {
                *consecutive_drained = 0;
                self.record_overrun();
            }
        }
        self.metrics.is_in_overrun_regime()
    }
}

/// Adopt a kernel dropped-events total as the comparison baseline.
///
/// Used on initial attach and after pin rotation reattachment. When the
/// new map generation already reports a nonzero dropped total, seed one
/// overrun episode ([`SockOpsConsumer::record_overrun`]) so the loss is
/// operator-visible instead of being silently adopted as the baseline.
/// Cumulative userspace counters on the shared [`BpfMetricsState`] are
/// preserved — this only updates the kernel-map comparison baseline and,
/// when needed, the overrun regime.
///
/// A pre-existing nonzero generation counts as **one** overrun episode
/// (same contract as initial attach), regardless of the absolute dropped
/// count on that generation.
pub fn seed_dropped_baseline(consumer: &SockOpsConsumer, dropped_total: u64) -> u64 {
    if dropped_total > 0 {
        consumer.record_overrun();
    }
    dropped_total
}

/// New bypass decisions to publish for one reason, given the previously
/// adopted kernel total and the freshly-read one.
///
/// The kernel counter is cumulative per map generation. A generation reset —
/// the node-agent restarted and re-created the map, so the counters are back
/// near zero — shows up as `current < last`; everything the new generation
/// reports happened after the rotation, so all of it is new. Without this the
/// metric would stall until the new generation climbed past the old total,
/// which is exactly the window an operator is watching after a restart.
pub fn drop_reason_delta(last: u64, current: u64) -> u64 {
    if current >= last {
        current - last
    } else {
        current
    }
}

/// Bytes of committed, unconsumed ringbuf data implied by a kernel
/// `(producer_pos, consumer_pos)` pair, or `None` when the pair cannot
/// describe a ring of `ring_bytes`.
///
/// The kernel never overwrites unconsumed data — a full ring fails the
/// producer's `bpf_ringbuf_reserve` instead — so a healthy ring always
/// satisfies `0 <= producer_pos - consumer_pos <= ring_bytes` in wrapping
/// arithmetic. Anything else means the retained consumer position is not a
/// point this consumer may resume from: either it ran past the producer, or
/// it is stale by more than a whole ring.
///
/// A consumer position ahead of the producer is not merely a userspace
/// bookkeeping error — the kernel's own reserve test (`new_prod_pos -
/// cons_pos > ring_bytes`) then underflows, so *every* subsequent record is
/// dropped and the ring never delivers anything again (issue #5563).
pub fn ringbuf_outstanding_bytes(
    producer_pos: u64,
    consumer_pos: u64,
    ring_bytes: u64,
) -> Option<u64> {
    let outstanding = producer_pos.wrapping_sub(consumer_pos);
    (outstanding <= ring_bytes).then_some(outstanding)
}

/// What a consumer must do with the consumer position a pinned ringbuf
/// retained from whoever drained it last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufAttach {
    /// The retained position is a valid resume point; `outstanding_bytes`
    /// of committed records are still waiting behind the producer.
    Resume { outstanding_bytes: u64 },
    /// The retained position cannot be resumed from. Republish the producer
    /// position as the consumer position before draining: that is the only
    /// value known to be consistent with the kernel, and it un-wedges a
    /// producer that has been failing every reserve.
    Resynchronize,
}

/// Classify a pinned ringbuf's retained consumer position at attach time.
///
/// Must be consulted *before* the ring is handed to aya, because
/// `RingBuf::new` adopts whatever the consumer page holds.
pub fn ringbuf_attach(producer_pos: u64, consumer_pos: u64, ring_bytes: u64) -> RingBufAttach {
    match ringbuf_outstanding_bytes(producer_pos, consumer_pos, ring_bytes) {
        Some(outstanding_bytes) => RingBufAttach::Resume { outstanding_bytes },
        None => RingBufAttach::Resynchronize,
    }
}

/// A ringbuf a drain can walk, plus the two kernel positions that bound it.
///
/// The bound is not optional bookkeeping. aya 0.13's `RingBuf` caches the
/// producer position, initialises that cache to `0`, and only refreshes it
/// once its own consumer position catches up to the cache. A pinned ring
/// opened with a non-zero consumer position — every ambient proxy that
/// replaces a predecessor on a node whose node-agent still owns the pin —
/// can never satisfy that condition, so `next()` keeps handing back bytes
/// the producer never published and the same resident records are replayed
/// on every wakeup. Reading the producer position ourselves is what makes
/// the drain stop in the right place (issue #5563).
pub trait RingBufCursor {
    /// Position the kernel has published records up to.
    fn producer_position(&self) -> u64;

    /// Position this consumer has committed back to the kernel. Must reflect
    /// every record already taken through [`Self::with_next_record`].
    fn consumer_position(&self) -> u64;

    /// Take the next record and hand its bytes to `f`, committing the
    /// consumer position afterwards. `None` when no record is available
    /// right now (the next one is still being written by the producer).
    fn with_next_record<R, F: FnOnce(&[u8]) -> R>(&mut self, f: F) -> Option<R>;
}

/// Records one [`drain_outstanding_records`] call delivers before handing
/// control back to its caller.
///
/// The drain shares a `tokio::select!` with the drop-reason poll, the
/// first-byte cleanup sweep and the pin-inode check. Without a bound, a node
/// producing events at or above the drain rate keeps the readable arm
/// resident and those timers never get a turn — the same starvation that let
/// the kernel per-CPU bypass counters go unread for a whole live-datapath
/// window. 4096 records is ~128 KiB of a 4 MiB ring, so a completely full
/// ring still drains in a bounded number of wakeups while every other arm
/// runs between them.
pub const RINGBUF_DRAIN_RECORD_BUDGET: u32 = 4096;

/// What one bounded drain pass observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainOutcome {
    /// Records handed to `on_record` during this call.
    pub records: u32,
    /// The per-wakeup budget stopped the pass while committed records were
    /// still outstanding behind the producer. The caller must retain ringbuf
    /// readiness (skip `clear_ready()`) so the drain resumes on the next
    /// poll instead of waiting for a fresh producer commit.
    pub budget_exhausted: bool,
    /// The kernel position pair could not describe this ring: the consumer
    /// position ran past the producer, or is stale by more than a whole
    /// ring. Nothing can be drained from it and the kernel drops every
    /// record it tries to reserve, so the ring has to be re-attached.
    pub needs_resynchronize: bool,
}

/// Drain the records the kernel has published, and not one byte more, up to
/// `record_budget` records.
///
/// Each pass takes a producer snapshot and consumes records while the
/// cursor's committed consumer position is still behind it; a pass that
/// made progress re-snapshots, because the producer may have published more
/// while the pass ran and a ringbuf wakeup only fires on commit.
///
/// The bound is what gives the exactly-once contract: a record can only be
/// delivered while the consumer position is behind the producer, and taking
/// it advances that position past the record.
///
/// `record_budget` bounds one call rather than the ring: hitting it reports
/// [`DrainOutcome::budget_exhausted`] with the consumer position committed
/// exactly where the pass stopped, so the next call resumes from there. A
/// budget of `0` is raised to `1` — a drain that can never take a record
/// would spin the caller's readiness loop forever.
pub fn drain_outstanding_records<C, F>(
    cursor: &mut C,
    ring_bytes: u64,
    record_budget: u32,
    mut on_record: F,
) -> DrainOutcome
where
    C: RingBufCursor,
    F: FnMut(&[u8]),
{
    let budget = record_budget.max(1);
    let mut records: u32 = 0;
    loop {
        let producer_pos = cursor.producer_position();
        let mut made_progress = false;
        loop {
            let consumer_pos = cursor.consumer_position();
            match ringbuf_outstanding_bytes(producer_pos, consumer_pos, ring_bytes) {
                // Caught up with this snapshot — stop walking the ring.
                Some(0) => break,
                // Not a position pair this consumer may resume from. Report
                // it so the caller can re-attach; walking on would hand out
                // bytes the producer never published.
                None => {
                    return DrainOutcome {
                        records,
                        budget_exhausted: false,
                        needs_resynchronize: true,
                    };
                }
                Some(_) => {}
            }
            if records >= budget {
                return DrainOutcome {
                    records,
                    budget_exhausted: true,
                    needs_resynchronize: false,
                };
            }
            if cursor.with_next_record(&mut on_record).is_none() {
                // The next record is still uncommitted. The producer's commit
                // delivers the wakeup that resumes this drain.
                return DrainOutcome {
                    records,
                    budget_exhausted: false,
                    needs_resynchronize: false,
                };
            }
            records = records.saturating_add(1);
            made_progress = true;
        }
        if !made_progress {
            return DrainOutcome {
                records,
                budget_exhausted: false,
                needs_resynchronize: false,
            };
        }
    }
}

/// Production async consumer that opens the pinned SOCK_OPS ringbuf and
/// drives the [`SockOpsConsumer`] dispatch from kernel events.
///
/// Spawned once per gateway from `ProxyState` init when mesh topology is
/// `NodeWaypoint` on Linux `ebpf` builds. Missing pins (no node-agent
/// yet, kernel too old, etc.) log one `info!` line and retry with capped
/// exponential backoff until the maps appear or shutdown fires — the
/// `__mesh_bpf_metrics` plugin continues to emit a stable Prometheus
/// surface populated by the empty [`BpfMetricsState`] until attach.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod production {
    use std::collections::VecDeque;
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use aya::maps::{Map, MapData, MapError, PerCpuArray, RingBuf, SockHash};
    use ferrum_ebpf_common::{
        ACCEPT_FIRST_BYTE_MAP_MAX_ENTRIES, SOCK_OPS_STATS_EVENTS_DROPPED, SockOpsRecord,
    };
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, info, warn};

    use super::{
        BPF_DROP_REASON_COUNT, BPF_DROP_REASON_STATS_SLOTS, PollOutcome,
        RINGBUF_DRAIN_RECORD_BUDGET, RingBufAttach, RingBufCursor, SOCK_OPS_RECOVERY_THRESHOLD,
        SockOpsConsumer, SockOpsEvent, drain_outstanding_records, drop_reason_delta,
        ringbuf_attach, seed_dropped_baseline,
    };
    use crate::ebpf::{
        BPF_ACCEPT_FIRST_BYTE_SOCKETS_PIN_PATH, BPF_SOCK_OPS_EVENTS_PIN_PATH,
        BPF_SOCK_OPS_STATS_PIN_PATH,
    };

    static MALFORMED_SOCK_OPS_RECORD_WARNED: AtomicBool = AtomicBool::new(false);
    static DROP_REASON_STATS_READ_WARNED: AtomicBool = AtomicBool::new(false);
    // `read_dropped_total` runs on every ringbuf wakeup; a stats map that
    // cannot serve the slot fails the same way every time.
    static DROPPED_TOTAL_READ_WARNED: AtomicBool = AtomicBool::new(false);
    // `wait_for_pinned_maps` retries forever at a 30s cap, and every refusal
    // `attach_events_ring` can raise is a static property of the pinned map:
    // the map info cannot be read, its size is not a non-zero power of two,
    // or its metadata pages cannot be mapped. Without a once-guard each of
    // those emits a warn every 30s for the life of the pod.
    static RINGBUF_INFO_READ_WARNED: AtomicBool = AtomicBool::new(false);
    static RINGBUF_SIZE_WARNED: AtomicBool = AtomicBool::new(false);
    static RINGBUF_POSITION_PAGES_WARNED: AtomicBool = AtomicBool::new(false);
    static RINGBUF_RUNTIME_RESYNC_WARNED: AtomicBool = AtomicBool::new(false);
    const FIRST_BYTE_HOOK_REMOVAL_GRACE: Duration = Duration::from_millis(250);
    const FIRST_BYTE_HOOK_CLEANUP_INTERVAL: Duration = Duration::from_millis(50);
    const FIRST_BYTE_HOOK_REMOVAL_QUEUE_CAP: usize = ACCEPT_FIRST_BYTE_MAP_MAX_ENTRIES as usize;
    /// How often the kernel per-CPU drop-reason counters are polled.
    ///
    /// Deliberately a timer rather than a per-drain read: the drop-reason
    /// counters must keep advancing even while the ringbuf produces nothing
    /// (a quiet node still makes bypass decisions), and four extra
    /// `bpf_map_lookup_elem` syscalls per ringbuf drain would scale with the
    /// event rate instead of with wall-clock time.
    const DROP_REASON_STATS_INTERVAL: Duration = Duration::from_secs(1);

    /// Run the consumer until the shutdown signal fires or an unrecoverable
    /// error is observed. Spawn via `tokio::spawn(run_pinned_consumer(...))`.
    ///
    /// `shutdown_rx` is a `watch` receiver: any change to `true` causes the
    /// consumer to drain remaining buffered events and return.
    pub async fn run_pinned_consumer(
        consumer: SockOpsConsumer,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        // Startup race: mesh-proxy may boot before node-agent has finished
        // attaching and pinning. Retry with backoff (1s → 30s, capped) so
        // the consumer recovers when node-agent eventually pins the maps.
        // Without this, an early miss permanently disables the consumer
        // and the plugin emits zeros forever until mesh-proxy itself
        // restarts. Backoff races against `shutdown_rx` so SIGTERM during
        // the wait still drains promptly.
        let (mut ring_buf, mut stats, mut first_byte_sockets) =
            match wait_for_pinned_maps(&mut shutdown_rx).await {
                WaitOutcome::Found(maps) => maps,
                WaitOutcome::Shutdown => {
                    info!("SOCK_OPS ringbuf consumer shutting down before maps were pinned");
                    return Ok(());
                }
            };

        let raw_fd = ring_buf.as_raw_fd();
        let mut async_fd = AsyncFd::with_interest(RingBufFd(raw_fd), Interest::READABLE)
            .map_err(|e| anyhow::anyhow!("Failed to wrap SOCK_OPS ringbuf fd in AsyncFd: {e}"))?;

        let mut last_dropped_total: u64 =
            seed_dropped_baseline(&consumer, read_dropped_total(&stats));
        // Adopt the generation's existing per-reason totals as the baseline
        // rather than replaying them: those bypass decisions predate this
        // consumer, exactly like `seed_dropped_baseline` treats the kernel
        // dropped total.
        let mut last_drop_totals: [u64; BPF_DROP_REASON_COUNT] = read_drop_reason_totals(&stats);
        let mut consecutive_drained: u32 = 0;
        let mut pending_first_byte_removals = VecDeque::new();

        // Track the inode of the events pin so we can detect node-agent
        // restarts. When the node-agent re-attaches it pins a new ringbuf
        // map at the same path — the inode changes, and our existing fd
        // is now reading from an orphan kernel map that no producer writes
        // to. Without periodic re-stat, counters silently freeze at their
        // pre-restart values until mesh-proxy itself restarts.
        let mut events_inode = pin_inode(BPF_SOCK_OPS_EVENTS_PIN_PATH);

        info!(
            pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
            initial_dropped_total = last_dropped_total,
            inode = events_inode,
            ring_bytes = ring_buf.ring_bytes(),
            producer_pos = ring_buf.producer_position(),
            consumer_pos = ring_buf.consumer_position(),
            "SOCK_OPS ringbuf consumer attached; draining events"
        );

        // Periodic sanity check for pin-path inode change (node-agent
        // restart). 30s is well within "operator can tolerate a brief
        // counter gap after a node-agent restart" but rare enough that
        // the stat syscall is negligible.
        let mut inode_check = tokio::time::interval(std::time::Duration::from_secs(30));
        inode_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        inode_check.tick().await; // consume the immediate first tick
        let mut first_byte_cleanup = tokio::time::interval(FIRST_BYTE_HOOK_CLEANUP_INTERVAL);
        first_byte_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        first_byte_cleanup.tick().await; // consume the immediate first tick
        let mut drop_reason_refresh = tokio::time::interval(DROP_REASON_STATS_INTERVAL);
        drop_reason_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        drop_reason_refresh.tick().await; // consume the immediate first tick

        loop {
            // Why the ringbuf has to be re-opened, if it does. Both reasons
            // need the identical repair `attach_events_ring` performs — the
            // consumer page is republished BEFORE aya adopts it, because
            // `RingBuf::new` caches that word and a later write to the page
            // alone would leave aya's own cursor stale-ahead.
            let mut reopen_reason: Option<&'static str> = None;
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        info!("SOCK_OPS ringbuf consumer shutting down");
                        return Ok(());
                    }
                }
                _ = inode_check.tick() => {
                    let current_inode = pin_inode(BPF_SOCK_OPS_EVENTS_PIN_PATH);
                    if current_inode != events_inode {
                        warn!(
                            previous_inode = events_inode,
                            current_inode,
                            pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                            "SOCK_OPS pin inode changed (likely node-agent restart); re-opening ringbuf"
                        );
                        reopen_reason = Some("pin rotation");
                    }
                }
                _ = first_byte_cleanup.tick() => {
                    drain_due_first_byte_removals(
                        &mut first_byte_sockets,
                        &mut pending_first_byte_removals,
                        Instant::now(),
                    );
                }
                _ = drop_reason_refresh.tick() => {
                    publish_drop_reason_deltas(&stats, &consumer, &mut last_drop_totals);
                }
                guard = async_fd.readable() => {
                    let mut guard = guard.map_err(|e| anyhow::anyhow!("SOCK_OPS AsyncFd readable failed: {e}"))?;
                    let drain = drain_ringbuf(
                        &mut ring_buf,
                        &mut pending_first_byte_removals,
                        &consumer,
                    );

                    let now_dropped_total = read_dropped_total(&stats);
                    let outcome = if now_dropped_total > last_dropped_total {
                        last_dropped_total = now_dropped_total;
                        PollOutcome::Overrun
                    } else {
                        // Propagate the actual count so the recovery state
                        // machine ignores spurious wakeups (events=0) and
                        // requires real drain progress before flipping back
                        // to "recovered". Without this, three epoll-edge
                        // artifacts in a row would clear the overrun regime
                        // even while the kernel is still dropping events on
                        // another CPU.
                        PollOutcome::Drained { events: drain.events }
                    };
                    consumer.observe_poll(
                        outcome,
                        &mut consecutive_drained,
                        SOCK_OPS_RECOVERY_THRESHOLD,
                    );

                    // A pass stopped by the per-wakeup budget deliberately
                    // KEEPS readiness: clearing it would park this arm until
                    // the producer commits again even though committed
                    // records are still outstanding. Retaining it re-polls
                    // the select immediately, so the drain resumes while the
                    // drop-reason poll, the first-byte cleanup and the inode
                    // check each get their turn (issue #5563).
                    if !drain.budget_exhausted {
                        guard.clear_ready();
                    }

                    if drain.needs_resynchronize {
                        reopen_reason = Some("ringbuf resynchronization");
                    }
                }
            }

            let Some(reason) = reopen_reason else {
                continue;
            };

            // Drop the old handles before re-opening so the pin is re-read
            // with the same retry/backoff contract used at startup. The
            // AsyncFd goes first: it must deregister the fd while the
            // RingBuf that owns it is still alive.
            drop(async_fd);
            drop(ring_buf);
            drop(stats);
            drop(first_byte_sockets);
            pending_first_byte_removals.clear();
            match wait_for_pinned_maps(&mut shutdown_rx).await {
                WaitOutcome::Found((new_rb, new_stats, new_first_byte_sockets)) => {
                    ring_buf = new_rb;
                    stats = new_stats;
                    first_byte_sockets = new_first_byte_sockets;
                    let new_fd = ring_buf.as_raw_fd();
                    async_fd = AsyncFd::with_interest(RingBufFd(new_fd), Interest::READABLE)
                        .map_err(|e| {
                            anyhow::anyhow!("Failed to re-wrap SOCK_OPS ringbuf fd in AsyncFd: {e}")
                        })?;
                    last_dropped_total =
                        seed_dropped_baseline(&consumer, read_dropped_total(&stats));
                    last_drop_totals = read_drop_reason_totals(&stats);
                    consecutive_drained = 0;
                    events_inode = pin_inode(BPF_SOCK_OPS_EVENTS_PIN_PATH);
                    info!(
                        pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                        inode = events_inode,
                        initial_dropped_total = last_dropped_total,
                        reason,
                        producer_pos = ring_buf.producer_position(),
                        consumer_pos = ring_buf.consumer_position(),
                        "SOCK_OPS ringbuf consumer re-attached"
                    );
                }
                WaitOutcome::Shutdown => {
                    info!("SOCK_OPS ringbuf consumer shutting down during pin re-open");
                    return Ok(());
                }
            }
        }
    }

    /// Returns the pin path's inode, or 0 if `stat` fails (treated as
    /// "absent / never seen"). 0 vs. a real inode of 0 doesn't matter for
    /// our comparison: we only care whether the value CHANGES, not its
    /// absolute value.
    fn pin_inode(path: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
    }

    /// Lightweight wrapper that owns a raw fd for `AsyncFd`. `RingBuf`
    /// itself implements `AsRawFd` but ownership is awkward to wire
    /// through `AsyncFd::with_interest`, which wants `T: AsRawFd + Send`.
    struct RingBufFd(std::os::fd::RawFd);

    impl AsRawFd for RingBufFd {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.0
        }
    }

    /// One mapped metadata page of a pinned ringbuf.
    ///
    /// The kernel lays a BPF ringbuf out as `[consumer page][producer page]
    /// [data pages][data pages again]`; the first machine word of each
    /// metadata page is that side's position. aya maps both pages for its
    /// own use but never exposes them, so the drain bound maps them again.
    struct MappedPage {
        ptr: NonNull<c_void>,
        len: usize,
    }

    // SAFETY: the mapping is owned by this value, is never handed out as a
    // reference that outlives it, and the only word ever touched through it
    // is read and written atomically.
    unsafe impl Send for MappedPage {}
    // SAFETY: as above — shared access is atomic-only.
    unsafe impl Sync for MappedPage {}

    impl MappedPage {
        fn map(
            fd: BorrowedFd<'_>,
            offset: usize,
            len: usize,
            prot: libc::c_int,
        ) -> io::Result<Self> {
            let Ok(offset) = libc::off_t::try_from(offset) else {
                return Err(io::Error::other("ringbuf page offset does not fit off_t"));
            };
            // `position()` reads the first machine word of the mapping, so a
            // shorter mapping would make that read out of bounds. Both call
            // sites pass `page_size()`, but enforce the precondition here
            // rather than leaving it to construction.
            if len < std::mem::size_of::<AtomicUsize>() {
                return Err(io::Error::other(
                    "ringbuf metadata page is shorter than one position word",
                ));
            }
            // SAFETY: `fd` is a live BPF ringbuf map fd, and `offset`/`len`
            // are the page-aligned metadata extents the kernel defines for
            // that map type. A failed mapping is reported as MAP_FAILED.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    prot,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    offset,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            match NonNull::new(ptr) {
                Some(ptr) => Ok(Self { ptr, len }),
                None => Err(io::Error::other("mmap returned a null pointer")),
            }
        }

        /// The position word the kernel publishes at the head of the page.
        fn position(&self) -> &AtomicUsize {
            // SAFETY: both ringbuf metadata pages begin with one
            // naturally-aligned `unsigned long` position word; `map`
            // refuses any length shorter than that word, and the mapping
            // outlives the borrow.
            unsafe { self.ptr.cast::<AtomicUsize>().as_ref() }
        }
    }

    impl Drop for MappedPage {
        fn drop(&mut self) {
            // SAFETY: `ptr` and `len` are exactly what `mmap` returned.
            unsafe { libc::munmap(self.ptr.as_ptr(), self.len) };
        }
    }

    fn page_size() -> io::Result<usize> {
        // SAFETY: `sysconf` takes an integer name and has no preconditions.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        match usize::try_from(size) {
            Ok(size) if size > 0 => Ok(size),
            _ => Err(io::Error::other("sysconf(_SC_PAGESIZE) gave no page size")),
        }
    }

    /// The kernel-published producer/consumer positions of a pinned ringbuf.
    struct RingBufPositions {
        consumer: MappedPage,
        producer: MappedPage,
    }

    impl RingBufPositions {
        fn open(fd: BorrowedFd<'_>) -> io::Result<Self> {
            let page = page_size()?;
            let consumer = MappedPage::map(fd, 0, page, libc::PROT_READ | libc::PROT_WRITE)?;
            let producer = MappedPage::map(fd, page, page, libc::PROT_READ)?;
            Ok(Self { consumer, producer })
        }

        fn producer_position(&self) -> u64 {
            // Acquire pairs with the kernel's release store of the producer
            // position, so the record header behind it is visible.
            self.producer.position().load(Ordering::Acquire) as u64
        }

        fn consumer_position(&self) -> u64 {
            self.consumer.position().load(Ordering::Acquire) as u64
        }

        /// Republish the consumer position. `SeqCst` matches the ordering
        /// aya commits with, so the kernel producer observes the repaired
        /// value before deciding whether its next reserve fits.
        fn publish_consumer_position(&self, pos: u64) {
            self.consumer
                .position()
                .store(pos as usize, Ordering::SeqCst);
        }
    }

    /// A pinned SOCK_OPS ringbuf together with the positions that bound each
    /// drain. See [`RingBufCursor`] for why the bound exists.
    struct PinnedRingBuf {
        ring_buf: RingBuf<MapData>,
        positions: RingBufPositions,
        ring_bytes: u64,
    }

    impl PinnedRingBuf {
        fn ring_bytes(&self) -> u64 {
            self.ring_bytes
        }
    }

    impl AsRawFd for PinnedRingBuf {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.ring_buf.as_raw_fd()
        }
    }

    impl RingBufCursor for PinnedRingBuf {
        fn producer_position(&self) -> u64 {
            self.positions.producer_position()
        }

        fn consumer_position(&self) -> u64 {
            self.positions.consumer_position()
        }

        fn with_next_record<R, F: FnOnce(&[u8]) -> R>(&mut self, f: F) -> Option<R> {
            // Dropping the item is what commits the consumer position, so
            // `consumer_position()` is accurate again by the time this
            // returns.
            let item = self.ring_buf.next()?;
            let bytes: &[u8] = &item;
            Some(f(bytes))
        }
    }

    /// Wrap a freshly-opened events map in a drain cursor, repairing a
    /// retained consumer position that cannot be resumed from.
    ///
    /// The repair has to happen before the map reaches aya: `RingBuf::new`
    /// adopts whatever the consumer page holds at construction.
    fn attach_events_ring(events_map: MapData) -> Option<PinnedRingBuf> {
        let ring_bytes = match events_map.info() {
            Ok(info) => u64::from(info.max_entries()),
            Err(e) => {
                if !RINGBUF_INFO_READ_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(
                        pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                        error = %e,
                        "Failed to read pinned SOCK_OPS ringbuf size; refusing to attach \
                         consumer. Suppressing repeated warnings: the attach loop retries \
                         forever and this condition is static."
                    );
                } else {
                    debug!(
                        pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                        error = %e,
                        "Failed to read pinned SOCK_OPS ringbuf size"
                    );
                }
                return None;
            }
        };
        if ring_bytes == 0 || !ring_bytes.is_power_of_two() {
            if !RINGBUF_SIZE_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    ring_bytes,
                    "Pinned SOCK_OPS ringbuf size is not a non-zero power of two; refusing to \
                     attach consumer because the drain bound cannot be trusted. Suppressing \
                     repeated warnings: the attach loop retries forever and this condition is \
                     static."
                );
            } else {
                debug!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    ring_bytes, "Pinned SOCK_OPS ringbuf size is not a non-zero power of two"
                );
            }
            return None;
        }

        let positions = match RingBufPositions::open(events_map.fd().as_fd()) {
            Ok(positions) => positions,
            Err(e) => {
                if !RINGBUF_POSITION_PAGES_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(
                        pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                        error = %e,
                        "Failed to map SOCK_OPS ringbuf position pages; refusing to attach \
                         consumer. Suppressing repeated warnings: the attach loop retries \
                         forever and this condition is static."
                    );
                } else {
                    debug!(
                        pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                        error = %e,
                        "Failed to map SOCK_OPS ringbuf position pages"
                    );
                }
                return None;
            }
        };

        let producer_pos = positions.producer_position();
        let consumer_pos = positions.consumer_position();
        if ringbuf_attach(producer_pos, consumer_pos, ring_bytes) == RingBufAttach::Resynchronize {
            warn!(
                pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                producer_pos,
                consumer_pos,
                ring_bytes,
                "Pinned SOCK_OPS ringbuf retained a consumer position that cannot be resumed \
                 from; resynchronizing to the producer position. While the consumer position is \
                 ahead of the producer the kernel drops every record it tries to reserve, so the \
                 ring delivers nothing until this is repaired."
            );
            positions.publish_consumer_position(producer_pos);
        }

        let ring_buf = match RingBuf::try_from(Map::RingBuf(events_map)) {
            Ok(ring_buf) => ring_buf,
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    error = %e,
                    "Pinned SOCK_OPS map is not a RingBuf; refusing to attach consumer"
                );
                return None;
            }
        };

        Some(PinnedRingBuf {
            ring_buf,
            positions,
            ring_bytes,
        })
    }

    /// Outcome of waiting for the SOCK_OPS pinned maps to appear.
    type PinnedSockOpsMaps = (
        PinnedRingBuf,
        PerCpuArray<MapData, u64>,
        SockHash<MapData, u64>,
    );

    enum WaitOutcome {
        Found(PinnedSockOpsMaps),
        Shutdown,
    }

    /// Poll for the pinned SOCK_OPS maps with exponential backoff until they
    /// appear or `shutdown_rx` signals. Backoff caps at 30s so the consumer
    /// recovers within ~1 minute even after long node-agent outages without
    /// burning a tight loop. The first miss is logged once at `info!`
    /// (matching the stable Prometheus-surface contract); each backoff is
    /// quiet.
    async fn wait_for_pinned_maps(
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> WaitOutcome {
        const BACKOFF_INITIAL_SECS: u64 = 1;
        const BACKOFF_MAX_SECS: u64 = 30;
        let mut backoff_secs = BACKOFF_INITIAL_SECS;
        let mut logged_first_miss = false;
        loop {
            if let Some(pair) = open_pinned_maps_quiet() {
                return WaitOutcome::Found(pair);
            }
            if !logged_first_miss {
                info!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    "SOCK_OPS event ringbuf pin not yet present; retrying with backoff. \
                     Expected when mesh-proxy boots before node-agent, or when no node-agent \
                     runs on this host. TCP-layer counters stay at zero until the pin appears."
                );
                logged_first_miss = true;
            }
            let sleep = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs));
            tokio::select! {
                _ = sleep => {
                    backoff_secs = (backoff_secs * 2).min(BACKOFF_MAX_SECS);
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return WaitOutcome::Shutdown;
                    }
                }
            }
        }
    }

    /// Open the pinned SOCK_OPS maps. Returns silently on "pin not present"
    /// (the retry loop calls this until the node-agent pins them), but still
    /// emits a warn for hard errors (type mismatch on pinned map).
    fn open_pinned_maps_quiet() -> Option<PinnedSockOpsMaps> {
        let events_map = MapData::from_pin(BPF_SOCK_OPS_EVENTS_PIN_PATH).ok()?;
        let ring_buf = attach_events_ring(events_map)?;

        let stats_map = MapData::from_pin(BPF_SOCK_OPS_STATS_PIN_PATH).ok()?;
        let stats: PerCpuArray<MapData, u64> = match PerCpuArray::try_from(Map::PerCpuArray(
            stats_map,
        )) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_STATS_PIN_PATH,
                    error = %e,
                    "Pinned SOCK_OPS stats map is not a PerCpuArray; refusing to attach consumer"
                );
                return None;
            }
        };

        let sockets_map = MapData::from_pin(BPF_ACCEPT_FIRST_BYTE_SOCKETS_PIN_PATH).ok()?;
        let first_byte_sockets = match SockHash::try_from(Map::SockHash(sockets_map)) {
            Ok(map) => map,
            Err(e) => {
                warn!(
                    pin_path = BPF_ACCEPT_FIRST_BYTE_SOCKETS_PIN_PATH,
                    error = %e,
                    "Pinned accept-first-byte map is not a SockHash; refusing to attach consumer"
                );
                return None;
            }
        };

        Some((ring_buf, stats, first_byte_sockets))
    }

    /// What one bounded `drain_ringbuf` wakeup produced.
    struct RingBufDrain {
        /// Valid decoded events dispatched to the consumer. Critical for the
        /// recovery state machine — a spurious wakeup with zero events must
        /// NOT advance `consecutive_drained` (which would falsely trigger
        /// recovery while the kernel is still dropping events on another
        /// CPU).
        events: u32,
        /// The per-wakeup budget stopped the pass with records still
        /// outstanding, so the caller must retain ringbuf readiness.
        budget_exhausted: bool,
        /// The kernel position pair is not one this consumer can resume
        /// from, so the ring has to be re-attached.
        needs_resynchronize: bool,
    }

    /// Drain pending ringbuf items, bounded by
    /// [`RINGBUF_DRAIN_RECORD_BUDGET`] records per wakeup.
    ///
    /// The walk is bounded by the kernel producer position rather than by
    /// aya deciding the ring looks empty; see [`drain_outstanding_records`].
    fn drain_ringbuf(
        ring_buf: &mut PinnedRingBuf,
        pending_first_byte_removals: &mut VecDeque<(Instant, u64)>,
        consumer: &SockOpsConsumer,
    ) -> RingBufDrain {
        let ring_bytes = ring_buf.ring_bytes();
        let mut events_handled: u32 = 0;
        let outcome = drain_outstanding_records(
            ring_buf,
            ring_bytes,
            RINGBUF_DRAIN_RECORD_BUDGET,
            |bytes: &[u8]| {
                if handle_ringbuf_record(bytes, pending_first_byte_removals, consumer) {
                    events_handled = events_handled.saturating_add(1);
                }
            },
        );
        if outcome.needs_resynchronize {
            log_ringbuf_runtime_resynchronization(
                ring_buf.producer_position(),
                ring_buf.consumer_position(),
                ring_bytes,
            );
        }
        RingBufDrain {
            events: events_handled,
            budget_exhausted: outcome.budget_exhausted,
            needs_resynchronize: outcome.needs_resynchronize,
        }
    }

    /// Decode one ringbuf record and dispatch it. Returns `true` when a
    /// valid event reached the consumer; a malformed record is logged and
    /// still counts as a consumed ringbuf slot, never as an event.
    fn handle_ringbuf_record(
        bytes: &[u8],
        pending_first_byte_removals: &mut VecDeque<(Instant, u64)>,
        consumer: &SockOpsConsumer,
    ) -> bool {
        if bytes.len() < std::mem::size_of::<SockOpsRecord>() {
            log_malformed_sock_ops_record(
                "short_read",
                std::mem::size_of::<SockOpsRecord>(),
                bytes.len(),
            );
            return false;
        }
        match SockOpsEvent::from_record_bytes(bytes) {
            Some(event) => {
                if let SockOpsEvent::AcceptToFirstByteLatency { socket_cookie, .. } = event {
                    // Ringbuf submission happens inside the stream parser,
                    // so readiness does not prove that the parser and its
                    // paired verdict have returned. Deleting immediately
                    // can race the socket callback's read-side lock. Queue
                    // removal behind a bounded grace period; correlation
                    // state was already consumed in-kernel, so no duplicate
                    // sample can be emitted while the hook remains attached.
                    queue_first_byte_removal(
                        pending_first_byte_removals,
                        socket_cookie,
                        Instant::now(),
                    );
                }
                consumer.handle_event(event);
                true
            }
            None => {
                // Unknown discriminant. Log once at warn level and suppress
                // repeats; high-volume malformed records are otherwise able
                // to starve the admin health path.
                log_malformed_sock_ops_record("unknown_discriminant", bytes.len(), bytes.len());
                false
            }
        }
    }

    /// Warn once that a live ring presented a consumer position this
    /// consumer cannot resume from.
    ///
    /// `attach_events_ring` repairs this at attach and at pin rotation, but
    /// nothing repaired it mid-run: the drain simply stopped, reported
    /// `Drained { events: 0 }`, and the pod silently stopped receiving every
    /// ringbuf-sourced metric because the 30s inode check never fires on a
    /// pin that did not rotate. aya's `next()` loops internally over
    /// discarded records without consulting the producer snapshot, so a
    /// discard adjacent to the producer position is enough to advance its
    /// cursor past it.
    ///
    /// Republishing the producer position onto the consumer page is NOT
    /// sufficient on its own: aya caches that word in `ConsumerPos` when the
    /// `RingBuf` is constructed and writes `cached + len` back on every
    /// commit, so a page-only write would be undone by the next record and
    /// meanwhile hand out bytes the producer never published. The repair
    /// therefore runs through a full re-attach, where `attach_events_ring`
    /// republishes the position BEFORE `RingBuf::new` adopts it.
    fn log_ringbuf_runtime_resynchronization(
        producer_pos: u64,
        consumer_pos: u64,
        ring_bytes: u64,
    ) {
        if !RINGBUF_RUNTIME_RESYNC_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                producer_pos,
                consumer_pos,
                ring_bytes,
                "Live SOCK_OPS ringbuf presented a consumer position that cannot be resumed \
                 from; re-attaching to resynchronize it to the producer position. While the \
                 consumer position is ahead of the producer the kernel drops every record it \
                 tries to reserve, so the ring delivers nothing until this is repaired. \
                 Suppressing repeated warnings."
            );
        } else {
            debug!(
                pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                producer_pos,
                consumer_pos,
                ring_bytes,
                "Live SOCK_OPS ringbuf consumer position is not resumable; re-attaching"
            );
        }
    }

    fn queue_first_byte_removal(
        pending: &mut VecDeque<(Instant, u64)>,
        socket_cookie: u64,
        now: Instant,
    ) {
        // Socket close remains the kernel cleanup backstop. Refuse excess
        // userspace retention rather than letting a continuously-drained
        // ringbuf grow this grace queue without bound under rapid close/churn.
        if socket_cookie == 0 || pending.len() >= FIRST_BYTE_HOOK_REMOVAL_QUEUE_CAP {
            return;
        }
        pending.push_back((now + FIRST_BYTE_HOOK_REMOVAL_GRACE, socket_cookie));
    }

    fn drain_due_first_byte_removals(
        first_byte_sockets: &mut SockHash<MapData, u64>,
        pending: &mut VecDeque<(Instant, u64)>,
        now: Instant,
    ) {
        while pending
            .front()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((_, socket_cookie)) = pending.pop_front() else {
                break;
            };
            let _ = first_byte_sockets.remove(&socket_cookie);
        }
    }

    fn log_malformed_sock_ops_record(reason: &'static str, expected: usize, actual: usize) {
        if !MALFORMED_SOCK_OPS_RECORD_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                reason,
                expected,
                actual,
                "SOCK_OPS malformed record observed; suppressing repeated warnings"
            );
        } else {
            debug!(
                reason,
                expected, actual, "SOCK_OPS malformed record observed"
            );
        }
    }

    fn read_stats_slot(stats: &PerCpuArray<MapData, u64>, index: u32) -> Result<u64, MapError> {
        stats
            .get(&index, 0)
            .map(|values| values.iter().copied().sum())
    }

    fn read_dropped_total(stats: &PerCpuArray<MapData, u64>) -> u64 {
        match read_stats_slot(stats, SOCK_OPS_STATS_EVENTS_DROPPED) {
            Ok(total) => total,
            Err(e) => {
                // Warn once, like the sibling drop-reason read: this runs on
                // every ringbuf wakeup, so repeating it would flood the log
                // with a static failure.
                if !DROPPED_TOTAL_READ_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(
                        pin_path = BPF_SOCK_OPS_STATS_PIN_PATH,
                        error = %e,
                        "Failed to read SOCK_OPS dropped-events counter; further read \
                         failures are not logged"
                    );
                }
                0
            }
        }
    }

    /// Read every kernel per-CPU drop-reason total for the current map
    /// generation. Used to adopt a baseline on attach and on pin rotation.
    ///
    /// A slot that cannot be read yields `0`, which as a BASELINE is the
    /// conservative choice: the next successful poll then publishes the whole
    /// generation rather than silently discarding it. The read failure itself
    /// is surfaced by [`publish_drop_reason_deltas`].
    fn read_drop_reason_totals(stats: &PerCpuArray<MapData, u64>) -> [u64; BPF_DROP_REASON_COUNT] {
        let mut totals = [0u64; BPF_DROP_REASON_COUNT];
        for (slot, (_, index)) in BPF_DROP_REASON_STATS_SLOTS.iter().enumerate() {
            totals[slot] = read_stats_slot(stats, *index).unwrap_or(0);
        }
        totals
    }

    /// Publish newly-observed bypass decisions from the kernel per-CPU
    /// counters.
    ///
    /// These counters — not the `SOCK_OPS_EVENT_DROP_REASON` ringbuf records
    /// — are the accounting authority for `ferrum_mesh_bpf_drops_total`: a
    /// full ring discards the record while the kernel slot still moves, so
    /// counting records lost bypass classifications exactly when the node was
    /// busiest.
    fn publish_drop_reason_deltas(
        stats: &PerCpuArray<MapData, u64>,
        consumer: &SockOpsConsumer,
        last_totals: &mut [u64; BPF_DROP_REASON_COUNT],
    ) {
        for (slot, (reason, index)) in BPF_DROP_REASON_STATS_SLOTS.iter().enumerate() {
            let current = match read_stats_slot(stats, *index) {
                Ok(current) => current,
                Err(e) => {
                    log_drop_reason_stats_read_failure(*index, &e);
                    continue;
                }
            };
            consumer.record_drops(*reason, drop_reason_delta(last_totals[slot], current));
            last_totals[slot] = current;
        }
    }

    /// Warn once that the pinned stats map cannot serve the drop-reason
    /// slots. Repeating this every second would starve the admin log path,
    /// and the condition is static: a node-agent whose map predates the
    /// per-reason slots never grows them.
    fn log_drop_reason_stats_read_failure(index: u32, error: &MapError) {
        if !DROP_REASON_STATS_READ_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                pin_path = BPF_SOCK_OPS_STATS_PIN_PATH,
                index,
                error = %error,
                "Failed to read SOCK_OPS per-reason bypass counter; \
                 ferrum_mesh_bpf_drops_total will not advance until the \
                 pinned stats map exposes the drop-reason slots"
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn first_byte_removal_queue_is_hard_bounded() {
            let mut pending = VecDeque::new();
            let now = Instant::now();
            for cookie in 1..=(FIRST_BYTE_HOOK_REMOVAL_QUEUE_CAP as u64 + 1) {
                queue_first_byte_removal(&mut pending, cookie, now);
            }
            queue_first_byte_removal(&mut pending, 0, now);

            assert_eq!(pending.len(), FIRST_BYTE_HOOK_REMOVAL_QUEUE_CAP);
            assert_eq!(pending.front().map(|(_, cookie)| *cookie), Some(1));
            assert_eq!(
                pending.back().map(|(_, cookie)| *cookie),
                Some(FIRST_BYTE_HOOK_REMOVAL_QUEUE_CAP as u64)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(consumer: &SockOpsConsumer) -> crate::ebpf::bpf_metrics::BpfMetricsSnapshot {
        consumer.metrics().snapshot()
    }

    #[test]
    fn handle_event_routes_each_variant_to_its_counter() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        consumer.handle_event(SockOpsEvent::Connect);
        consumer.handle_event(SockOpsEvent::AcceptEstablished);
        consumer.handle_event(SockOpsEvent::AcceptEstablished);
        consumer.handle_event(SockOpsEvent::Rst);
        consumer.handle_event(SockOpsEvent::Rst);
        consumer.handle_event(SockOpsEvent::Fin {
            direction: TcpDirection::Received,
        });
        consumer.handle_event(SockOpsEvent::RttSample { srtt_us: 250 });
        consumer.handle_event(SockOpsEvent::SynToAckLatency { us: 60 });
        consumer.handle_event(SockOpsEvent::AcceptToFirstByteLatency {
            us: 800,
            socket_cookie: 1,
        });
        consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::BypassUidHit));

        let s = snap(&consumer);
        assert_eq!(s.connect, 1);
        assert_eq!(s.accept_established, 2);
        assert_eq!(s.rst, 2);
        assert_eq!(s.fin_sent, 0);
        assert_eq!(s.fin_received, 1);
        assert_eq!(s.srtt_sample_us_sum, 250);
        assert_eq!(s.srtt_count, 1);
        assert_eq!(s.syn_to_ack_us_sum, 60);
        assert_eq!(s.accept_to_first_byte_us_sum, 800);
        assert_eq!(s.accept_to_first_byte_count, 1);
        // The drop-reason RECORD is part of the event stream but is not the
        // accounting authority: `ferrum_mesh_bpf_drops_total` is fed from the
        // kernel per-CPU counters, which a full ringbuf cannot discard.
        assert_eq!(s.drop_bypass_uid_hit, 0);
        // Every handled event also bumps the consumed-events counter.
        assert_eq!(s.ringbuf_events_consumed, 10);
    }

    #[test]
    fn from_record_decodes_every_known_discriminant() {
        use ferrum_ebpf_common::{
            SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT, SOCK_OPS_DROP_BYPASS_UID_HIT,
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, SOCK_OPS_EVENT_ACCEPT_ESTABLISHED,
            SOCK_OPS_EVENT_CONNECT, SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_FIN,
            SOCK_OPS_EVENT_RST, SOCK_OPS_EVENT_RTT_SAMPLE, SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY,
            SockOpsRecord,
        };

        fn rec(event: u32, direction: u32, drop_reason: u32, value: u64) -> SockOpsRecord {
            SockOpsRecord {
                event_type: event,
                direction,
                drop_reason,
                _pad: 0,
                value,
            }
        }

        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_CONNECT, 0, 0, 0)),
            Some(SockOpsEvent::Connect)
        );
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_ACCEPT_ESTABLISHED, 0, 0, 0)),
            Some(SockOpsEvent::AcceptEstablished)
        );
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, 0, 0, 0)),
            Some(SockOpsEvent::Rst)
        );
        // Legacy directional RST records still collapse to non-directional Rst.
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_SENT, 0, 0)),
            Some(SockOpsEvent::Rst)
        );
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_FIN, SOCK_OPS_DIRECTION_RECEIVED, 0, 0)),
            Some(SockOpsEvent::Fin {
                direction: TcpDirection::Received
            })
        );
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RTT_SAMPLE, 0, 0, 250)),
            Some(SockOpsEvent::RttSample { srtt_us: 250 })
        );
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY, 0, 0, 60)),
            Some(SockOpsEvent::SynToAckLatency { us: 60 })
        );
        let first_byte = SockOpsRecord::accept_to_first_byte_latency(800, 0x0123_4567_89ab_cdef);
        assert_eq!(
            SockOpsEvent::from_record(first_byte),
            Some(SockOpsEvent::AcceptToFirstByteLatency {
                us: 800,
                socket_cookie: 0x0123_4567_89ab_cdef,
            })
        );

        for (raw, expected) in [
            (SOCK_OPS_DROP_BYPASS_UID_HIT, BpfDropReason::BypassUidHit),
            (
                SOCK_OPS_DROP_EXCLUDE_CIDR_HIT,
                BpfDropReason::ExcludeCidrHit,
            ),
            (
                SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR,
                BpfDropReason::NotInIncludeCidr,
            ),
            (
                SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
                BpfDropReason::ExcludePortHit,
            ),
        ] {
            assert_eq!(
                SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_DROP_REASON, 0, raw, 0)),
                Some(SockOpsEvent::DropReason(expected))
            );
        }

        // Unknown event type → None (no panic).
        assert!(SockOpsEvent::from_record(rec(999, 0, 0, 0)).is_none());
        // Drop reason discriminant with unknown reason → None.
        assert!(SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_DROP_REASON, 0, 999, 0)).is_none());
    }

    #[test]
    fn from_record_bytes_rejects_short_slices() {
        assert!(SockOpsEvent::from_record_bytes(&[0u8; 4]).is_none());
        assert!(SockOpsEvent::from_record_bytes(&[]).is_none());
    }

    #[test]
    fn from_record_bytes_decodes_full_record() {
        use ferrum_ebpf_common::{SOCK_OPS_EVENT_RTT_SAMPLE, SockOpsRecord};

        let record = SockOpsRecord {
            event_type: SOCK_OPS_EVENT_RTT_SAMPLE,
            direction: 0,
            drop_reason: 0,
            _pad: 0,
            value: 9_999,
        };
        // SAFETY: SockOpsRecord is #[repr(C)] with no padding (we
        // explicitly added the _pad field). The byte layout is stable.
        let bytes: [u8; std::mem::size_of::<SockOpsRecord>()] =
            unsafe { std::mem::transmute(record) };

        assert_eq!(
            SockOpsEvent::from_record_bytes(&bytes),
            Some(SockOpsEvent::RttSample { srtt_us: 9_999 })
        );
    }

    #[test]
    fn observe_poll_state_machine_warns_once_per_regime() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        let mut consecutive = 0u32;
        // Initial drained: nothing happens (we weren't in overrun yet).
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 5 }, &mut consecutive, 3);
        assert!(!in_regime);

        // Overrun: flips into overrun regime.
        let in_regime = consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(consecutive, 0);
        assert_eq!(snap(&consumer).ringbuf_overruns, 1);

        // 2 drained polls — not yet at the recovery threshold of 3.
        consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 2 }, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(consecutive, 2);

        // 3rd consecutive drained — recovery threshold met, regime clears.
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        assert!(!in_regime);
        assert_eq!(consecutive, 0);

        // Subsequent overrun re-enters the regime (fresh warn would fire).
        let in_regime = consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(snap(&consumer).ringbuf_overruns, 2);
    }

    /// Regression guard: spurious wakeups (drained with events=0) must not
    /// advance the recovery counter. Three zero-event drains in a row used
    /// to falsely clear the overrun regime even when the kernel was still
    /// dropping events on another CPU.
    #[test]
    fn observe_poll_zero_event_drain_does_not_advance_recovery() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        let mut consecutive = 0u32;

        // Enter the overrun regime.
        let in_regime = consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(consecutive, 0);

        // 3 spurious wakeups (events: 0) — must NOT advance recovery
        // counter and must NOT clear the regime.
        for _ in 0..3 {
            let in_regime =
                consumer.observe_poll(PollOutcome::Drained { events: 0 }, &mut consecutive, 3);
            assert!(in_regime, "regime must persist across zero-event drains");
            assert_eq!(consecutive, 0, "zero-event drain must not advance counter");
        }

        // Real drain progress still recovers normally.
        consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        assert!(
            !in_regime,
            "three real drains in a row should clear the regime"
        );
    }

    #[test]
    fn seed_dropped_baseline_zero_does_not_enter_overrun() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        // Preserve unrelated cumulative state across a synthetic reattach.
        consumer.handle_event(SockOpsEvent::Connect);
        assert_eq!(seed_dropped_baseline(&consumer, 0), 0);
        let s = snap(&consumer);
        assert_eq!(s.connect, 1);
        assert_eq!(s.ringbuf_overruns, 0);
        assert!(!s.in_overrun_regime);
    }

    #[test]
    fn seed_dropped_baseline_nonzero_enters_overrun_once() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        consumer.handle_event(SockOpsEvent::Connect);
        consumer.record_drops(BpfDropReason::ExcludePortHit, 1);
        assert_eq!(seed_dropped_baseline(&consumer, 42), 42);
        let s = snap(&consumer);
        assert_eq!(
            s.connect, 1,
            "cumulative userspace state must survive reattach"
        );
        assert_eq!(s.drop_exclude_port_hit, 1);
        assert_eq!(s.ringbuf_overruns, 1);
        assert!(s.in_overrun_regime);
        // A second seed while already in-regime still increments the counter
        // but does not re-enter (warn fires only once per regime).
        assert_eq!(seed_dropped_baseline(&consumer, 99), 99);
        assert_eq!(snap(&consumer).ringbuf_overruns, 2);
        assert!(snap(&consumer).in_overrun_regime);
    }
}
