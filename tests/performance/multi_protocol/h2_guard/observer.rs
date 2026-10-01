//! Temporary #5588 hosted observer. No payloads, peer names, or Debug errors.
//! Compiled only by the separately prepared dependency, never the shipping graph.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub(super) const TARGET: &str = "ferrum_h2_guard";

// 512 * 136 bytes plus Observation/Arc/registry metadata fits one 128 KiB slot.
// 64 live slots = 8 MiB. One serialized snapshot clone reserves another slot;
// its caller holds SNAPSHOT_LOCK, so total observation allocation is < 8.125 MiB.
pub(super) const TAIL: usize = 512;
pub(super) const SLOTS: usize = 64;
static LIVE: AtomicU64 = AtomicU64::new(0);
pub(super) static MEMORY_OVERFLOW: AtomicU64 = AtomicU64::new(0);

// Relaxed `fetch_update` as its own compare-exchange loop: Rust 1.99
// deprecates `fetch_update`, and `try_update` is newer than h2's MSRV.
pub(super) fn update(atomic: &AtomicU64, mut f: impl FnMut(u64) -> Option<u64>) -> Result<u64, u64> {
    let mut prev = atomic.load(Ordering::Relaxed);
    while let Some(next) = f(prev) {
        match atomic.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(previous) => return Ok(previous),
            Err(current) => prev = current,
        }
    }
    Err(prev)
}

#[derive(Debug)]
struct Permit;

impl Permit {
    fn take() -> Option<Self> {
        if update(&LIVE, |n| (n < SLOTS as u64).then_some(n + 1)).is_err() {
            MEMORY_OVERFLOW.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(Self)
    }
}

impl Drop for Permit {
    fn drop(&mut self) { LIVE.fetch_sub(1, Ordering::Relaxed); }
}

#[derive(Clone, Debug, Default)]
struct Transition {
    fields: [u64; 16],
    byte_available: isize,
    #[cfg(test)]
    drop_barrier: Option<Arc<std::sync::Barrier>>,
}

// Pause an actual ring element's destruction while its allocation is still
// owned. This probe and its storage do not exist in the diagnostic build.
#[cfg(test)]
impl Drop for Transition {
    fn drop(&mut self) {
        if let Some(barrier) = &self.drop_barrier {
            barrier.wait();
            barrier.wait();
        }
    }
}

#[derive(Debug)]
pub(super) struct Limit {
    used: AtomicU64,
    pub(super) suppressed: AtomicU64,
    cap: u64,
}

impl Limit {
    pub(super) const fn new(cap: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            cap,
        }
    }

    pub(super) fn take(&self, records: u64) -> Result<u64, u64> {
        match update(&self.used, |n| n.checked_add(records).filter(|&next| next <= self.cap)) {
            Ok(n) => Ok(n + records),
            Err(_) => {
                let old = update(&self.suppressed, |n| Some(n.saturating_add(1)));
                // The closure always returns Some: both arms avoid a panic.
                Err(old.unwrap_or_else(|n| n).saturating_add(1))
            }
        }
    }
}

static CONNECTIONS: Limit = Limit::new(4096);
// Each record reserves 4096 serialized bytes, including the log envelope.
// 128 MiB ordinary emission, 8 MiB exclusively for actual failures.
static LIFECYCLE: Limit = Limit::new(128 * 1024 * 1024 / 4096);
static FAILURES: Limit = Limit::new(8 * 1024 * 1024 / 4096);
pub(super) static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn suppressed() -> u64 {
    CONNECTIONS.suppressed.load(Ordering::Relaxed)
        .saturating_add(LIFECYCLE.suppressed.load(Ordering::Relaxed))
        .saturating_add(FAILURES.suppressed.load(Ordering::Relaxed))
}

pub(super) fn admit(limit: &Limit, scope: u8) -> Option<u64> {
    admit_records(limit, scope, 1)
}

fn admit_records(limit: &Limit, scope: u8, records: u64) -> Option<u64> {
    match limit.take(records) {
        Ok(id) => Some(id),
        Err(n) => {
            // At most 64 notices per scope, saturation cannot repeat a notice
            // because u64::MAX is not a power of two. These are lower bounds after the last notice.
            if n.is_power_of_two() {
                let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(target: TARGET, parent: None,
                    "H2_GUARD_LIMIT_V1 seq={} scope={} suppressed={}", seq, scope, n);
            }
            None
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Observation {
    pub(super) cid: u64,
    tail: Box<[Transition]>,
    pub(super) transitions: u64,
    pub(super) epoch: u64,
    pub(super) pending: u64,
    pub(super) high_pending: u64,
    min_credit: usize,
    overflow: u64,
    role: u8,
    initial_max: usize,
    pub(super) initial_target: u32,
    pub(super) target: u32,
    peak_target: u32,
    pub(super) target_updates: u64,
    pub(super) initial_stream: u32,
    pub(super) stream_window: u32,
    stream_updates: u64,
    pub(super) wire_window: u32,
    pub(super) byte_available: isize,
    pub(super) in_flight: u32,
    // zero, small(1..255), medium(256..16383), large(>=16384), final,
    // queued, ignored local reset, ignored released, empty unqueued,
    // receive rejected, untracked stream, polled, cleared, released credit.
    pub(super) counters: [u64; 14],
    frames: u64,
    bytes: u64,
    pub(super) last_stream: u32,
    pub(super) trigger_stream: u32,
    last_len: usize,
    last_flow: usize,
    last_end: bool,
    pub(super) disposition: u8,
    pub(super) branch: u8,
    reason: u32,
    // Fields drop in declaration order. Every owning clone must free its ring
    // before the last Arc can return the live slot to another connection.
    _permit: Arc<Permit>,
}

impl Observation {
    #[cfg(test)]
    pub(super) fn allocation_with_metadata_allowance(&self) -> usize {
        std::mem::size_of::<Self>() + std::mem::size_of_val(self.tail.as_ref()) + 1024
    }

    #[cfg(test)]
    pub(super) fn pause_tail_drop(&mut self, barrier: Arc<std::sync::Barrier>) {
        self.tail[TAIL - 1].drop_barrier = Some(barrier);
    }

    pub(super) fn transition(&mut self, kind: u8, frame: [u64; 5], credit: [usize; 2], consume: u8) {
        if self.transitions == u64::MAX {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        if kind == 1 && frame[4] == 1 && frame[3] == 0 {
            if let Some(pending) = self.pending.checked_add(1) {
                self.pending = pending;
            } else { self.overflow = self.overflow.saturating_add(1); }
        } else if matches!(kind, 2 | 3) && consume == 1 {
            if let Some(pending) = self.pending.checked_sub(1) {
                self.pending = pending;
            } else { self.overflow = self.overflow.saturating_add(1); }
        }
        self.high_pending = self.high_pending.max(self.pending);
        self.min_credit = self.min_credit.min(credit[1]);
        self.tail[self.transitions as usize % TAIL] = Transition {
            fields: [self.epoch, u64::from(kind), frame[0], frame[1], frame[2], frame[3], frame[4],
                     u64::from(consume), credit[0] as u64, credit[1] as u64,
                     credit[1].abs_diff(credit[0]) as u64, self.pending, u64::from(self.target),
                     u64::from(self.wire_window), u64::from(self.in_flight), u64::from(self.stream_window)],
            byte_available: self.byte_available,
            #[cfg(test)]
            drop_barrier: None,
        };
        self.transitions += 1;
    }

    pub(super) fn data_transition(&mut self, before: usize, after: usize, consume: u8) {
        self.transition(1, [u64::from(self.last_stream), self.last_len as u64, self.last_flow as u64,
            u64::from(self.last_end), u64::from(self.disposition)], [before, after], consume);
    }

    pub(super) fn window_transition(&mut self, kind: u8, credit: usize) {
        self.transition(kind, [0; 5], [credit; 2], 0);
    }

    pub(super) fn poll_epoch(&mut self, credit: usize) {
        if let Some(epoch) = self.epoch.checked_add(1) { self.epoch = epoch; }
        else { self.overflow = self.overflow.saturating_add(1); }
        self.window_transition(6, credit);
    }

    pub(super) fn new(server: bool, budget: usize) -> Option<Self> {
        if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            return None;
        }
        let cid = admit(&CONNECTIONS, 1)?;
        let permit = Permit::take()?;
        Some(Self {
            cid,
            tail: vec![Transition::default(); TAIL].into_boxed_slice(),
            transitions: 0, epoch: 0, pending: 0, high_pending: 0,
            min_credit: budget, overflow: 0,
            role: u8::from(!server),
            initial_max: budget,
            initial_target: 65535,
            target: 65535,
            peak_target: 65535,
            target_updates: 0,
            initial_stream: 65535,
            stream_window: 65535,
            stream_updates: 0,
            wire_window: 65535,
            byte_available: 65535,
            in_flight: 0,
            counters: [0; 14],
            frames: 0,
            bytes: 0,
            last_stream: 0,
            trigger_stream: 0,
            last_len: 0,
            last_flow: 0,
            last_end: false,
            disposition: 0,
            branch: 0,
            reason: 0,
            _permit: Arc::new(permit),
        })
    }

    pub(super) fn frame(&mut self, id: u32, len: usize, flow: usize, end: bool) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
        self.last_stream = id;
        self.last_len = len;
        self.last_flow = flow;
        self.last_end = end;
        self.disposition = 0;
        self.inc(match len {
            0 => 0,
            1..=255 => 1,
            256..=16383 => 2,
            _ => 3,
        }, 1);
        if end {
            self.inc(4, 1);
        }
    }

    pub(super) fn inc(&mut self, index: usize, value: u64) {
        self.counters[index] = self.counters[index].saturating_add(value);
    }

    pub(super) fn disposition(&mut self, code: u8) {
        // 1 queued, 2 local reset, 3 released, 4 empty nonfinal,
        // 5 recv rejected, 6 no tracked stream (guard bypass).
        self.disposition = code;
        self.inc(usize::from(code) + 4, 1);
    }

    pub(super) fn target(&mut self, size: u32) {
        if self.target_updates == 0 {
            self.initial_target = size;
        }
        self.target_updates = self.target_updates.saturating_add(1);
        self.target = size;
        self.peak_target = self.peak_target.max(size);
    }

    pub(super) fn stream_window(&mut self, size: u32) {
        if self.stream_updates == 0 {
            self.initial_stream = size;
        }
        self.stream_updates = self.stream_updates.saturating_add(1);
        self.stream_window = size;
    }

    pub(super) fn emit(&mut self, event: u8, branch: u8, reason: u32, state: [usize; 7]) {
        self.emit_generation(event, branch, reason, state, 0);
    }

    pub(super) fn emit_generation(&mut self, event: u8, branch: u8, reason: u32, state: [usize; 7], generation: u64) {
        if event == 1 {
            self.branch = branch;
            self.reason = reason;
        }
        let (limit, scope) = if event == 1 { (&FAILURES, 3) } else { (&LIFECYCLE, 2) };
        let tail_len = if matches!(event, 1 | 3) { self.transitions.min(TAIL as u64) } else { 0 };
        // Reserve the entire failure dump before emitting its summary. Other
        // connections cannot spend its promised tail units, even while tracing
        // interleaves. Refusal counts one suppressed dump and emits no fragment.
        let records = if event == 1 { 1 + tail_len } else { 1 };
        if admit_records(limit, scope, records).is_none() {
            return;
        }
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
        let c = &self.counters;
        // Fixed numeric schema, no inherited tracing span fields. Counters
        // saturate; quotas are process-wide and failure capacity is reserved.
        tracing::debug!(target: TARGET, parent: None,
            "H2_GUARD_V2 seq={} cid={} role={} event={} branch={} reason={} initial_max={} initial_available={} max={} available={} empty={} send={} recv={} error_resets={} remote_resets={} initial_target={} target={} peak_target={} target_updates={} initial_stream={} stream_window={} stream_updates={} wire_window={} byte_available={} in_flight={} frames={} bytes={} zero={} small={} medium={} large={} final={} queued={} ignored_reset={} ignored_release={} empty_unqueued={} rejected={} untracked={} polled={} cleared={} returned_credit={} last_stream={} trigger_stream={} last_len={} last_flow={} last_end={} disposition={} suppressed_connections={} suppressed_lifecycle={} suppressed_failures={} generation={} transitions={} tail_len={} wraps={} overwritten={} overflow={} pending={} high_pending={} min_credit={} epoch={} memory_overflow={}",
            seq, self.cid, self.role, event, self.branch, self.reason,
            self.initial_max, self.initial_max, state[0], state[1], state[2],
            state[3], state[4], state[5], state[6], self.initial_target,
            self.target, self.peak_target, self.target_updates, self.initial_stream,
            self.stream_window, self.stream_updates, self.wire_window,
            self.byte_available, self.in_flight, self.frames, self.bytes,
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
            c[10], c[11], c[12], c[13], self.last_stream, self.trigger_stream, self.last_len,
            self.last_flow, u8::from(self.last_end), self.disposition,
            CONNECTIONS.suppressed.load(Ordering::Relaxed),
            LIFECYCLE.suppressed.load(Ordering::Relaxed),
            FAILURES.suppressed.load(Ordering::Relaxed), generation, self.transitions,
            tail_len, self.transitions.saturating_sub(1) / TAIL as u64,
            self.transitions.saturating_sub(TAIL as u64), self.overflow, self.pending,
            self.high_pending, self.min_credit, self.epoch, MEMORY_OVERFLOW.load(Ordering::Relaxed));
        // Constructor has no transitions. Each dump is linked to its summary seq.
        // Terminal summaries retain exact totals; failure/live dumps carry tails.
        if !matches!(event, 1 | 3) { return; }
        for n in self.transitions.saturating_sub(TAIL as u64)..self.transitions {
            if event != 1 && admit(limit, scope).is_none() { break; }
            let t = &self.tail[n as usize % TAIL];
            let f = &t.fields;
            let issued = SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(target: TARGET, parent: None,
                "H2_GUARD_TAIL_V2 seq={} cid={} snapshot={} generation={} n={} epoch={} kind={} stream={} len={} flow={} end={} disposition={} consume={} before={} after={} delta={} pending={} target={} wire={} byte_available={} in_flight={} stream_window={}",
                issued, self.cid, seq, generation, n + 1, f[0], f[1], f[2], f[3], f[4],
                f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], t.byte_available, f[14], f[15]);
        }
    }
}
