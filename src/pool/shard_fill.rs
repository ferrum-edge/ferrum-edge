//! Background shard fills for the sharded HTTP/2 pools (gRPC and direct H2).
//!
//! Both pools keep `http2_connections_per_host` backend connections (shards)
//! per host. An open hyper HTTP/2 sender always reports ready, so a probe that
//! takes "the first ready shard" never leaves the first shard it finds: one
//! connection then carries every stream, and the pool never reaches its
//! configured width. A pool that prefers a specific shard therefore serves the
//! call from a ready sibling when that shard is missing or closed and creates
//! the shard on a detached task. The bookkeeping for those creates lives here
//! so the two pools cannot drift:
//!
//! - [`ShardFill`]: single-flight marker for one detached create.
//! - [`ShardCreateBackoff`] / [`ShardCreateGuard`]: a short cooldown after a
//!   failed or cancelled physical create, so a backend refusing new
//!   connections (or a DestinationRule `maxConnections` below the shard count)
//!   is borrowed around instead of redialled on every request.
//! - [`ShardRing`]: a shard key's place in its ring.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long a failed preferred-shard create keeps that shard on the borrow
/// path before it is dialled again.
const SHARD_CREATE_BACKOFF: Duration = Duration::from_secs(2);

/// Hard bound on retained failure keys and FIFO records. Recording one
/// physical failure evicts at most one record; there are no full-map scans.
const SHARD_CREATE_BACKOFF_CAPACITY: usize = 4096;

/// A shard key's place in its ring: the base key length, the preferred
/// shard, and the ring size.
#[derive(Clone, Copy)]
pub(crate) struct ShardRing {
    pub(crate) base_len: usize,
    pub(crate) start: usize,
    pub(crate) shards: usize,
}

/// Removes a background shard fill from the in-flight set when its task ends,
/// however it ends.
pub(crate) struct ShardFill {
    pub(crate) fills: Arc<DashMap<String, ()>>,
    pub(crate) key: String,
}

impl Drop for ShardFill {
    fn drop(&mut self) {
        self.fills.remove(&self.key);
    }
}

pub(crate) struct ShardCreateBackoff {
    failures: DashMap<Arc<str>, ShardCreateFailure>,
    // Only physical failed/cancelled creates take this lock. Warm requests
    // never consult the backoff cache, and coalesced waiters never record.
    order: Mutex<VecDeque<(Arc<str>, usize)>>,
    recorded: AtomicUsize,
    evicted: AtomicUsize,
}

struct ShardCreateFailure {
    at: tokio::time::Instant,
    generation: usize,
}

impl ShardCreateBackoff {
    pub(crate) fn new(shards: usize) -> Self {
        Self {
            failures: DashMap::with_shard_amount(shards),
            order: Mutex::new(VecDeque::with_capacity(SHARD_CREATE_BACKOFF_CAPACITY)),
            recorded: AtomicUsize::new(0),
            evicted: AtomicUsize::new(0),
        }
    }

    pub(crate) fn backed_off(&self, key: &str) -> bool {
        let failed_at = match self.failures.get(key) {
            Some(entry) => entry.at,
            None => return false,
        };
        if failed_at.elapsed() < SHARD_CREATE_BACKOFF {
            return true;
        }
        self.failures.remove_if(key, |_, failure| {
            failure.at.elapsed() >= SHARD_CREATE_BACKOFF
        });
        false
    }

    fn record(&self, key: String) {
        // Recover the bounded bookkeeping after a panic without dropping the
        // cancellation cooldown. No user work runs while this lock is held.
        let mut order = self.order.lock().unwrap_or_else(|err| err.into_inner());
        if order.len() == SHARD_CREATE_BACKOFF_CAPACITY
            && let Some((old_key, old_generation)) = order.pop_front()
        {
            self.failures.remove_if(old_key.as_ref(), |_, failure| {
                failure.generation == old_generation
            });
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
        let key: Arc<str> = key.into();
        let generation = self.recorded.fetch_add(1, Ordering::Relaxed);
        self.failures.insert(
            Arc::clone(&key),
            ShardCreateFailure {
                at: tokio::time::Instant::now(),
                generation,
            },
        );
        order.push_back((key, generation));
    }

    /// Shard keys currently backed off.
    pub(crate) fn backed_off_keys(&self) -> usize {
        self.failures.len()
    }

    /// Physical failure records and bounded FIFO eviction operations.
    pub(crate) fn work(&self) -> (usize, usize) {
        (
            self.recorded.load(Ordering::Relaxed),
            self.evicted.load(Ordering::Relaxed),
        )
    }
}

/// Lives inside the elected physical creator, so cancellation records the
/// cooldown before GenericPool wakes waiters to elect the next creator.
pub(crate) struct ShardCreateGuard<'a> {
    pub(crate) backoff: &'a ShardCreateBackoff,
    pub(crate) key: Option<String>,
}

impl Drop for ShardCreateGuard<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.backoff.record(key);
        }
    }
}
