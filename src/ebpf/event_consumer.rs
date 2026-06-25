//! Userspace consumer for the SOCK_OPS ringbuf.
//!
//! The kernel-side `BPF_PROG_TYPE_SOCK_OPS` program emits one record per
//! TCP-layer event (Connect, AcceptEstablished, RstSent/Received,
//! FinSent/Received, RttSample) plus a record per BPF drop-reason hit.
//! Userspace polls the ringbuf, decodes the records, and updates the
//! shared [`BpfMetricsState`].
//!
//! ## Production wiring (GAP-3D)
//!
//! The kernel-side `BPF_PROG_TYPE_SOCK_OPS` program is loaded and pinned
//! by the node-agent (`src/ebpf/loader.rs::attach_sock_ops`). The mesh
//! proxy opens the pinned ringbuf at
//! [`BPF_SOCK_OPS_EVENTS_PIN_PATH`](crate::ebpf::BPF_SOCK_OPS_EVENTS_PIN_PATH)
//! and runs [`run_pinned_consumer`] as a background task that:
//!   1. Drives the kernel ringbuf with `tokio::io::unix::AsyncFd`,
//!      draining all available records on each wakeup.
//!   2. Decodes each record via [`SockOpsEvent::from_record_bytes`] and
//!      hands it to [`SockOpsConsumer::handle_event`].
//!   3. Polls the per-CPU dropped-events counter
//!      ([`BPF_SOCK_OPS_STATS_PIN_PATH`](crate::ebpf::BPF_SOCK_OPS_STATS_PIN_PATH))
//!      after each drain. When the sum advances, the consumer is in an
//!      overrun regime; [`SockOpsConsumer::record_overrun`] handles the
//!      warn/recover state machine so the log line never spams.
//!
//! When the SOCK_OPS program is not pinned (no node-agent on the host,
//! kernel < 5.7, BPF feature not built), [`run_pinned_consumer`] logs
//! once and exits. The [`BpfMetricsState`] stays at zero — the
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
    SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY, SockOpsRecord,
};
use tracing::{info, warn};

use crate::ebpf::bpf_metrics::{BpfDropReason, BpfMetricsState, TcpDirection};

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
/// `SockOpsEvent::decode` (separate module, lands with the BPF program)
/// has to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsEvent {
    Connect,
    AcceptEstablished,
    Rst { direction: TcpDirection },
    Fin { direction: TcpDirection },
    RttSample { srtt_us: u64 },
    SynToAckLatency { us: u64 },
    AcceptToFirstByteLatency { us: u64 },
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
            SOCK_OPS_EVENT_RST => Some(Self::Rst {
                direction: direction.unwrap_or(TcpDirection::Received),
            }),
            SOCK_OPS_EVENT_FIN => Some(Self::Fin {
                direction: direction.unwrap_or(TcpDirection::Received),
            }),
            SOCK_OPS_EVENT_RTT_SAMPLE => Some(Self::RttSample {
                srtt_us: record.value,
            }),
            SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY => Some(Self::SynToAckLatency { us: record.value }),
            SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY => {
                Some(Self::AcceptToFirstByteLatency { us: record.value })
            }
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
            SockOpsEvent::Rst { direction } => self.metrics.record_rst(direction),
            SockOpsEvent::Fin { direction } => self.metrics.record_fin(direction),
            SockOpsEvent::RttSample { srtt_us } => self.metrics.record_srtt_sample(srtt_us),
            SockOpsEvent::SynToAckLatency { us } => self.metrics.record_syn_to_ack(us),
            SockOpsEvent::AcceptToFirstByteLatency { us } => {
                self.metrics.record_accept_to_first_byte(us)
            }
            SockOpsEvent::DropReason(reason) => self.metrics.record_drop(reason),
        }
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

/// Production async consumer that opens the pinned SOCK_OPS ringbuf and
/// drives the [`SockOpsConsumer`] dispatch from kernel events.
///
/// Spawned once per gateway from `ProxyState` init when mesh topology is
/// `NodeWaypoint`. When the BPF program is not pinned (no node-agent on
/// the host, kernel too old, etc.), the function logs a single info line
/// and returns — the `__mesh_bpf_metrics` plugin continues to emit a
/// stable Prometheus surface populated by the empty [`BpfMetricsState`].
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod production {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};

    use aya::maps::{Map, MapData, PerCpuArray, RingBuf};
    use ferrum_ebpf_common::{SOCK_OPS_STATS_EVENTS_DROPPED, SockOpsRecord};
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, info, warn};

    use super::{PollOutcome, SOCK_OPS_RECOVERY_THRESHOLD, SockOpsConsumer, SockOpsEvent};
    use crate::ebpf::{BPF_SOCK_OPS_EVENTS_PIN_PATH, BPF_SOCK_OPS_STATS_PIN_PATH};

    static MALFORMED_SOCK_OPS_RECORD_WARNED: AtomicBool = AtomicBool::new(false);

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
        let (mut ring_buf, mut stats) = match wait_for_pinned_maps(&mut shutdown_rx).await {
            WaitOutcome::Found(pair) => pair,
            WaitOutcome::Shutdown => {
                info!("SOCK_OPS ringbuf consumer shutting down before maps were pinned");
                return Ok(());
            }
        };

        let raw_fd = ring_buf.as_raw_fd();
        let mut async_fd = AsyncFd::with_interest(RingBufFd(raw_fd), Interest::READABLE)
            .map_err(|e| anyhow::anyhow!("Failed to wrap SOCK_OPS ringbuf fd in AsyncFd: {e}"))?;

        let mut last_dropped_total: u64 = read_dropped_total(&stats);
        let mut consecutive_drained: u32 = 0;
        // Seed the regime as engaged when we observe pre-existing drops, so
        // the operator dashboard immediately reflects the kernel state
        // instead of waiting for the next drop to flip the regime.
        if last_dropped_total > 0 {
            consumer.record_overrun();
        }

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
            "SOCK_OPS ringbuf consumer attached; draining events"
        );

        // Periodic sanity check for pin-path inode change (node-agent
        // restart). 30s is well within "operator can tolerate a brief
        // counter gap after a node-agent restart" but rare enough that
        // the stat syscall is negligible.
        let mut inode_check = tokio::time::interval(std::time::Duration::from_secs(30));
        inode_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        inode_check.tick().await; // consume the immediate first tick

        loop {
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
                        // Drop the old async_fd / ring_buf / stats by
                        // returning from the inner loop body and letting
                        // the outer logic re-open. Easiest path: just
                        // recurse via tail-call into a fresh consumer run.
                        // We instead loop locally: drop old handles and
                        // attempt re-open with the same retry/backoff
                        // contract used at startup.
                        drop(async_fd);
                        drop(ring_buf);
                        drop(stats);
                        match wait_for_pinned_maps(&mut shutdown_rx).await {
                            WaitOutcome::Found((new_rb, new_stats)) => {
                                ring_buf = new_rb;
                                stats = new_stats;
                                let new_fd = ring_buf.as_raw_fd();
                                async_fd = AsyncFd::with_interest(
                                    RingBufFd(new_fd),
                                    Interest::READABLE,
                                )
                                .map_err(|e| anyhow::anyhow!(
                                    "Failed to re-wrap SOCK_OPS ringbuf fd in AsyncFd: {e}"
                                ))?;
                                last_dropped_total = read_dropped_total(&stats);
                                consecutive_drained = 0;
                                events_inode = pin_inode(BPF_SOCK_OPS_EVENTS_PIN_PATH);
                                info!(
                                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                                    inode = events_inode,
                                    initial_dropped_total = last_dropped_total,
                                    "SOCK_OPS ringbuf consumer re-attached after pin rotation"
                                );
                            }
                            WaitOutcome::Shutdown => {
                                info!("SOCK_OPS ringbuf consumer shutting down during pin re-open");
                                return Ok(());
                            }
                        }
                        continue;
                    }
                }
                guard = async_fd.readable() => {
                    let mut guard = guard.map_err(|e| anyhow::anyhow!("SOCK_OPS AsyncFd readable failed: {e}"))?;
                    let events_handled = drain_ringbuf(&mut ring_buf, &consumer);

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
                        PollOutcome::Drained { events: events_handled }
                    };
                    consumer.observe_poll(
                        outcome,
                        &mut consecutive_drained,
                        SOCK_OPS_RECOVERY_THRESHOLD,
                    );

                    guard.clear_ready();
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

    /// Outcome of waiting for the SOCK_OPS pinned maps to appear.
    enum WaitOutcome {
        Found((RingBuf<MapData>, PerCpuArray<MapData, u64>)),
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

    /// Variant of `open_pinned_maps` that returns silently on "pin not
    /// present" (used by the retry loop), but still emits a warn for hard
    /// errors (type mismatch on pinned map).
    fn open_pinned_maps_quiet() -> Option<(RingBuf<MapData>, PerCpuArray<MapData, u64>)> {
        let events_map = MapData::from_pin(BPF_SOCK_OPS_EVENTS_PIN_PATH).ok()?;
        let ring_buf = match RingBuf::try_from(Map::RingBuf(events_map)) {
            Ok(rb) => rb,
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    error = %e,
                    "Pinned SOCK_OPS map is not a RingBuf; refusing to attach consumer"
                );
                return None;
            }
        };

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

        Some((ring_buf, stats))
    }

    fn open_pinned_maps() -> Option<(RingBuf<MapData>, PerCpuArray<MapData, u64>)> {
        let events_map = match MapData::from_pin(BPF_SOCK_OPS_EVENTS_PIN_PATH) {
            Ok(m) => m,
            Err(e) => {
                info!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    error = %e,
                    "SOCK_OPS event ringbuf pin not present; TCP-layer counters will stay at zero. \
                     This is expected when no node-agent is running on the host."
                );
                return None;
            }
        };
        let ring_buf = match RingBuf::try_from(Map::RingBuf(events_map)) {
            Ok(rb) => rb,
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
                    error = %e,
                    "Pinned SOCK_OPS map is not a RingBuf; refusing to attach consumer"
                );
                return None;
            }
        };

        let stats_map = match MapData::from_pin(BPF_SOCK_OPS_STATS_PIN_PATH) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_STATS_PIN_PATH,
                    error = %e,
                    "SOCK_OPS stats pin missing; ringbuf overrun detection disabled but event drain continues"
                );
                // Without stats we can't detect overrun, but draining events
                // is still valuable. Returning None disables the whole
                // consumer though — to avoid that, build a synthetic empty
                // stats array isn't possible; surface the disable explicitly.
                return None;
            }
        };
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

        Some((ring_buf, stats))
    }

    /// Drain pending ringbuf items and return the count of valid events
    /// dispatched. Counter is critical for the recovery state machine —
    /// a spurious wakeup with zero events must NOT advance
    /// `consecutive_drained` (which would falsely trigger recovery while
    /// the kernel is still dropping events on another CPU).
    fn drain_ringbuf(ring_buf: &mut RingBuf<MapData>, consumer: &SockOpsConsumer) -> u32 {
        let mut events_handled: u32 = 0;
        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<SockOpsRecord>() {
                log_malformed_sock_ops_record(
                    "short_read",
                    std::mem::size_of::<SockOpsRecord>(),
                    bytes.len(),
                );
                continue;
            }
            match SockOpsEvent::from_record_bytes(bytes) {
                Some(event) => {
                    consumer.handle_event(event);
                    events_handled = events_handled.saturating_add(1);
                }
                None => {
                    // Unknown discriminant. Log once at warn level and
                    // suppress repeats; high-volume malformed records are
                    // otherwise able to starve the admin health path.
                    log_malformed_sock_ops_record("unknown_discriminant", bytes.len(), bytes.len());
                }
            }
        }
        events_handled
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

    fn read_dropped_total(stats: &PerCpuArray<MapData, u64>) -> u64 {
        match stats.get(&SOCK_OPS_STATS_EVENTS_DROPPED, 0) {
            Ok(values) => values.iter().copied().sum(),
            Err(e) => {
                warn!(
                    pin_path = BPF_SOCK_OPS_STATS_PIN_PATH,
                    error = %e,
                    "Failed to read SOCK_OPS dropped-events counter"
                );
                0
            }
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
        consumer.handle_event(SockOpsEvent::Rst {
            direction: TcpDirection::Sent,
        });
        consumer.handle_event(SockOpsEvent::Rst {
            direction: TcpDirection::Received,
        });
        consumer.handle_event(SockOpsEvent::Fin {
            direction: TcpDirection::Received,
        });
        consumer.handle_event(SockOpsEvent::RttSample { srtt_us: 250 });
        consumer.handle_event(SockOpsEvent::SynToAckLatency { us: 60 });
        consumer.handle_event(SockOpsEvent::AcceptToFirstByteLatency { us: 800 });
        consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::BypassUidHit));

        let s = snap(&consumer);
        assert_eq!(s.connect, 1);
        assert_eq!(s.accept_established, 2);
        assert_eq!(s.rst_sent, 1);
        assert_eq!(s.rst_received, 1);
        assert_eq!(s.fin_sent, 0);
        assert_eq!(s.fin_received, 1);
        assert_eq!(s.srtt_sample_us_sum, 250);
        assert_eq!(s.srtt_count, 1);
        assert_eq!(s.syn_to_ack_us_sum, 60);
        assert_eq!(s.accept_to_first_byte_us_sum, 800);
        assert_eq!(s.drop_bypass_uid_hit, 1);
        // Every handled event also bumps the consumed-events counter.
        assert_eq!(s.ringbuf_events_consumed, 10);
    }

    #[test]
    fn from_record_decodes_every_known_discriminant() {
        use ferrum_ebpf_common::{
            SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT, SOCK_OPS_DROP_BYPASS_UID_HIT,
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, SOCK_OPS_EVENT_ACCEPT_ESTABLISHED,
            SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, SOCK_OPS_EVENT_CONNECT,
            SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_FIN, SOCK_OPS_EVENT_RST,
            SOCK_OPS_EVENT_RTT_SAMPLE, SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY, SockOpsRecord,
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
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_SENT, 0, 0)),
            Some(SockOpsEvent::Rst {
                direction: TcpDirection::Sent
            })
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
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, 0, 0, 800)),
            Some(SockOpsEvent::AcceptToFirstByteLatency { us: 800 })
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
}
