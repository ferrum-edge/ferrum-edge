//! Backend-shard affinity for a frontend connection (issue #5588).
//!
//! The gRPC pool keeps `http2_connections_per_host` backend connections
//! (shards) per host. Each request used to pick its starting
//! shard round-robin, so the streams of one multiplexed frontend connection
//! were spread across every backend connection. Their responses then arrived
//! on different backend connections at different times, and the frontend
//! connection wrote them to the client one at a time. The client and the
//! backend did more reads, wakeups and decryptions per request than behind a
//! gateway that keeps a downstream connection's streams on one upstream
//! connection (as Envoy does per worker).
//!
//! Each accepted HTTP/1.1 or HTTP/2 frontend connection now holds a slot for
//! its lifetime, and its requests run with that slot in a task-local. The gRPC
//! pool starts its shard probe at `slot % shards`, so the streams of one frontend
//! connection share a backend connection and their responses arrive, and
//! leave, together. A new connection takes the lowest slot with the fewest
//! live connections, so long-lived connections stay spread evenly over the
//! shards however many short-lived ones (health checks, probes) come and go.
//! The probe still moves on to the next shard when the preferred one is not
//! immediately ready, and a request with no frontend connection in scope
//! (HTTP/3, spawned work) keeps the round-robin start.
//!
//! The direct HTTP/2 pool keeps the round-robin start for every request: on the
//! protocol benchmark the same affinity made HTTP/2 slower (up to about 20% at
//! 1–5 MiB on one runner type), while gRPC gained at 10 KiB on every runner.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

/// More slots than any default shard count (`available_parallelism`), so
/// contiguous low slots spread over every shard.
const SLOTS: usize = 256;

/// Live frontend connections per slot.
pub struct SlotTable {
    live: [AtomicUsize; SLOTS],
}

impl SlotTable {
    pub const fn new() -> Self {
        Self {
            live: [const { AtomicUsize::new(0) }; SLOTS],
        }
    }

    /// Take the lowest slot with the fewest live connections. Two concurrent
    /// accepts may take the same slot; that only costs balance.
    pub fn acquire(&'static self) -> FrontendConnectionSlot {
        let mut slot = 0;
        let mut fewest = usize::MAX;
        for (index, live) in self.live.iter().enumerate() {
            let count = live.load(Ordering::Relaxed);
            if count < fewest {
                slot = index;
                fewest = count;
                if count == 0 {
                    break;
                }
            }
        }
        self.live[slot].fetch_add(1, Ordering::Relaxed);
        FrontendConnectionSlot { table: self, slot }
    }

    /// Live connections holding `slot`.
    pub fn live(&self, slot: usize) -> usize {
        self.live[slot].load(Ordering::Relaxed)
    }
}

impl Default for SlotTable {
    fn default() -> Self {
        Self::new()
    }
}

static FRONTEND_SLOTS: SlotTable = SlotTable::new();

/// A frontend connection's slot, released when the connection ends.
pub struct FrontendConnectionSlot {
    table: &'static SlotTable,
    slot: usize,
}

impl FrontendConnectionSlot {
    /// Acquire a slot for a newly accepted frontend connection.
    pub fn acquire() -> Self {
        FRONTEND_SLOTS.acquire()
    }

    pub fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for FrontendConnectionSlot {
    fn drop(&mut self) {
        self.table.live[self.slot].fetch_sub(1, Ordering::Relaxed);
    }
}

tokio::task_local! {
    static FRONTEND_CONNECTION: usize;
}

/// Run one request of the frontend connection holding `slot` with that slot in
/// scope for the gRPC pool.
pub async fn with_frontend_connection<F: Future>(slot: usize, request: F) -> F::Output {
    FRONTEND_CONNECTION.scope(slot, request).await
}

/// The shard the gRPC pool's probe starts at: the current frontend connection's
/// shard when one is in scope, otherwise the next round-robin position.
pub fn start_shard(round_robin: &AtomicUsize, shard_count: usize) -> usize {
    let shard_count = shard_count.max(1);
    FRONTEND_CONNECTION
        .try_with(|slot| *slot % shard_count)
        .unwrap_or_else(|_| round_robin.fetch_add(1, Ordering::Relaxed) % shard_count)
}
