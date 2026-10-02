//! TLS updates, bounded periodic publication. No shared per-event update.
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::schema::{COUNTERS, Counter, OPS};

pub const THREAD_SLOTS: usize = 128;
pub const PUBLICATION_INTERVAL: u64 = 2048;

#[repr(align(64))]
struct Slot {
    claimed: AtomicBool,
    dirty: AtomicBool,
    sequence: AtomicU64,
    values: [AtomicU64; COUNTERS],
}

impl Slot {
    const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            values: [const { AtomicU64::new(0) }; COUNTERS],
        }
    }

    fn publish(&self, values: &[u64; COUNTERS]) {
        if self.sequence.load(Ordering::SeqCst) > u64::MAX - 2 {
            lost();
            return;
        }
        self.sequence.fetch_add(1, Ordering::SeqCst);
        for (target, value) in self.values.iter().zip(values) {
            target.store(*value, Ordering::SeqCst);
        }
        self.dirty.store(false, Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);
    }

    fn capture(&self) -> Option<([u64; COUNTERS], bool)> {
        for _ in 0..3 {
            let before = self.sequence.load(Ordering::SeqCst);
            if !before.is_multiple_of(2) {
                continue;
            }
            let values = std::array::from_fn(|i| self.values[i].load(Ordering::SeqCst));
            let dirty = self.dirty.load(Ordering::SeqCst);
            if before == self.sequence.load(Ordering::SeqCst) {
                return Some((values, dirty));
            }
        }
        None
    }
}

// Never recycled: thread exits retain cumulative counts, preventing resets.
static SLOTS: [Slot; THREAD_SLOTS] = [const { Slot::new() }; THREAD_SLOTS];
static LOST: AtomicU64 = AtomicU64::new(0);

fn lost() {
    // Exceptional loss only; no shared profiling atomic on ordinary events.
    let _ = LOST.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

pub(super) struct Local {
    slot: Option<usize>,
    registered: bool,
    pending: u64,
    pub values: [u64; COUNTERS],
    pub samples: [u64; OPS],
}

impl Local {
    const fn new() -> Self {
        Self {
            slot: None,
            registered: false,
            pending: 0,
            values: [0; COUNTERS],
            samples: [0; OPS],
        }
    }

    pub fn add(&mut self, index: usize, amount: u64) {
        if let Some(value) = self.values.get_mut(index) {
            if let Some(sum) = value.checked_add(amount) {
                *value = sum;
                return;
            }
            *value = u64::MAX;
        }
        let overflow = &mut self.values[Counter::CounterOverflow as usize];
        *overflow = overflow.saturating_add(1);
    }

    fn publish(&mut self) {
        if let Some(index) = self.slot {
            SLOTS[index].publish(&self.values);
            self.pending = 0;
        }
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        self.publish();
    }
}

thread_local! {
    static LOCAL: RefCell<Local> = const { RefCell::new(Local::new()) };
}

pub(super) fn with_local(f: impl FnOnce(&mut Local)) {
    if LOCAL
        .try_with(|cell| {
            let Ok(mut local) = cell.try_borrow_mut() else {
                lost();
                return;
            };
            if !local.registered {
                local.registered = true;
                local.slot = SLOTS.iter().position(|slot| {
                    slot.claimed
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                });
            }
            let Some(index) = local.slot else {
                lost();
                return;
            };
            if local.pending == 0 {
                // Once per publication interval, before the first local write.
                SLOTS[index].dirty.store(true, Ordering::SeqCst);
            }
            f(&mut local);
            local.pending += 1;
            if local.pending == PUBLICATION_INTERVAL {
                local.publish();
            }
        })
        .is_err()
    {
        lost();
    }
}

pub fn publish_current_thread() {
    if LOCAL
        .try_with(|cell| match cell.try_borrow_mut() {
            Ok(mut local) => local.publish(),
            Err(_) => lost(),
        })
        .is_err()
    {
        lost();
    }
}

/// Source-site assertions can read their own TLS without mixing other tests.
pub fn current_thread_counters() -> [u64; COUNTERS] {
    let mut values = [0; COUNTERS];
    with_local(|local| values = local.values);
    values
}

pub struct Snapshot {
    pub values: [u64; COUNTERS],
    pub registered_slots: u64,
    pub missing_slots: u64,
    pub unpublished_event_bound: u64,
    pub lost_events: u64,
}

pub fn snapshot() -> Snapshot {
    publish_current_thread();
    let mut snapshot = Snapshot {
        values: [0; COUNTERS],
        registered_slots: 0,
        missing_slots: 0,
        unpublished_event_bound: 0,
        lost_events: LOST.load(Ordering::Relaxed),
    };
    for slot in &SLOTS {
        if !slot.claimed.load(Ordering::SeqCst) {
            continue;
        }
        snapshot.registered_slots += 1;
        let Some((values, dirty)) = slot.capture() else {
            snapshot.missing_slots += 1;
            continue;
        };
        if dirty {
            // This bounds update groups, NOT packets, bytes, or nanoseconds.
            snapshot.unpublished_event_bound += PUBLICATION_INTERVAL;
        }
        for (target, value) in snapshot.values.iter_mut().zip(values) {
            match target.checked_add(value) {
                Some(sum) => *target = sum,
                None => {
                    *target = u64::MAX;
                    snapshot.lost_events = snapshot.lost_events.saturating_add(1);
                }
            }
        }
    }
    snapshot
}

#[cfg(test)]
#[path = "../../tests/unit/gateway_core/udp_profile_store_tests.rs"]
mod tests;
