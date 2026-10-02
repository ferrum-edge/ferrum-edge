//! Bounded, single-writer thread slots. No thread IDs or request labels escape.
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::schema::{COUNTERS, OVERFLOW};

pub const THREAD_SLOTS: usize = 128;
const PUBLICATION_INTERVAL: u64 = 1024;

#[repr(align(64))]
struct Slot {
    claimed: AtomicBool,
    sequence: AtomicU64,
    events: AtomicU64,
    published_events: AtomicU64,
    values: [AtomicU64; COUNTERS],
}

impl Slot {
    const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            events: AtomicU64::new(0),
            published_events: AtomicU64::new(0),
            values: [const { AtomicU64::new(0) }; COUNTERS],
        }
    }

    fn publish(&self, values: &[u64; COUNTERS], events: u64) {
        // All publication operations are SeqCst. A reader accepting an
        // unchanged even version sees ONE publication, not torn fields.
        // Atomic payloads avoid the data race of a plain-memory seqlock.
        // Sequence wrap freezes publication with explicit loss.
        if self.sequence.load(Ordering::SeqCst) > u64::MAX - 2 {
            lost();
            return;
        }
        self.sequence.fetch_add(1, Ordering::SeqCst);
        for (destination, value) in self.values.iter().zip(values) {
            destination.store(*value, Ordering::SeqCst);
        }
        self.published_events.store(events, Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);
    }

    fn capture(&self) -> Option<([u64; COUNTERS], u64)> {
        for _ in 0..3 {
            let before = self.sequence.load(Ordering::SeqCst);
            if !before.is_multiple_of(2) {
                continue;
            }
            let values = std::array::from_fn(|i| self.values[i].load(Ordering::SeqCst));
            let published = self.published_events.load(Ordering::SeqCst);
            if before == self.sequence.load(Ordering::SeqCst) {
                return Some((values, published));
            }
        }
        None
    }
}

// Slots are never recycled: exited threads retain their cumulative totals.
static SLOTS: [Slot; THREAD_SLOTS] = [const { Slot::new() }; THREAD_SLOTS];
static LOST: AtomicU64 = AtomicU64::new(0);

fn lost() {
    // Exceptional path only. Saturation is sticky and rejects completeness.
    let _ = LOST.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

pub(super) struct Local {
    slot: Option<usize>,
    registered: bool,
    events: u64,
    pub values: [u64; COUNTERS],
    pub active: u8,
    pub top: Option<usize>,
}

impl Local {
    const fn new() -> Self {
        Self {
            slot: None,
            registered: false,
            events: 0,
            values: [0; COUNTERS],
            active: 0,
            top: None,
        }
    }

    pub fn add(&mut self, index: usize, amount: u64) {
        // Checked indexing also makes malformed internal instrumentation inert.
        if let Some(value) = self.values.get_mut(index) {
            if let Some(sum) = value.checked_add(amount) {
                *value = sum;
                return;
            }
            *value = u64::MAX;
        }
        self.values[OVERFLOW] = self.values[OVERFLOW].saturating_add(1);
    }

    fn publish(&self) {
        if let Some(index) = self.slot {
            let slot = &SLOTS[index];
            slot.publish(&self.values, self.events);
        }
    }
}

thread_local! {
    // Const, non-destructible TLS: no TLS destructor registration from an
    // allocator callback. Unpublished tails on exit remain visible in slots
    // as unpublished_events; they are never silently treated as zero.
    static LOCAL: RefCell<Local> = const { RefCell::new(Local::new()) };
}

fn register(slots: &[Slot]) -> Option<usize> {
    slots.iter().position(|slot| {
        slot.claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    })
}

pub(super) fn with_local(f: impl FnOnce(&mut Local)) {
    let result = LOCAL.try_with(|cell| {
        let Ok(mut local) = cell.try_borrow_mut() else {
            lost();
            return;
        };
        if !local.registered {
            local.registered = true;
            local.slot = register(&SLOTS);
        }
        if local.slot.is_none() {
            lost();
            return;
        }
        f(&mut local);
        if let Some(events) = local.events.checked_add(1) {
            local.events = events;
        } else {
            local.add(OVERFLOW, 1);
        }
        if let Some(index) = local.slot {
            SLOTS[index].events.store(local.events, Ordering::SeqCst);
        }
        if local.events.is_multiple_of(PUBLICATION_INTERVAL) {
            local.publish();
        }
    });
    if result.is_err() {
        lost(); // TLS teardown: never initialize/access a destroyed value.
    }
}

/// Publish only this thread. Never blocks or asks another worker to run.
pub fn publish_current_thread() {
    let result = LOCAL.try_with(|cell| {
        if let Ok(local) = cell.try_borrow() {
            local.publish();
        } else {
            lost();
        }
    });
    if result.is_err() {
        lost();
    }
}

/// Diagnostic view of this thread, useful for checking source-site accounting.
pub fn current_thread_counters() -> [u64; COUNTERS] {
    let mut result = [0; COUNTERS];
    with_local(|local| result = local.values);
    result
}

#[derive(Debug)]
pub struct Snapshot {
    pub values: [u64; COUNTERS],
    pub registered_slots: u64,
    pub missing_slots: u64,
    pub unpublished_events: u64,
    pub lost_events: u64,
}

/// Bounded best-effort snapshot, not a stop-the-world measurement boundary.
pub fn snapshot() -> Snapshot {
    publish_current_thread();
    let mut result = Snapshot {
        values: [0; COUNTERS],
        registered_slots: 0,
        missing_slots: 0,
        unpublished_events: 0,
        lost_events: LOST.load(Ordering::Relaxed),
    };
    for slot in &SLOTS {
        if !slot.claimed.load(Ordering::SeqCst) {
            continue;
        }
        result.registered_slots += 1;
        let Some((values, published)) = slot.capture() else {
            result.missing_slots += 1;
            continue;
        };
        let pending = slot.events.load(Ordering::SeqCst).saturating_sub(published);
        if let Some(total) = result.unpublished_events.checked_add(pending) {
            result.unpublished_events = total;
        } else {
            result.unpublished_events = u64::MAX;
            result.lost_events = result.lost_events.saturating_add(1);
        }
        for (destination, value) in result.values.iter_mut().zip(values) {
            match destination.checked_add(value) {
                Some(sum) => *destination = sum,
                None => {
                    *destination = u64::MAX;
                    result.lost_events = result.lost_events.saturating_add(1);
                }
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "../../tests/unit/gateway_core/h1_profile_store_tests.rs"]
mod tests;
