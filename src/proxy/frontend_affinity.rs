//! Backend-shard affinity for an HTTP/2 frontend connection (issue #5588).
//!
//! The gRPC pool keeps `http2_connections_per_host` backend connections
//! (shards) per host, and every call used to pick its starting shard
//! round-robin. The streams of one multiplexed client connection were then
//! spread over every backend connection, their responses came back at
//! different times, and the frontend wrote them to the client one at a time:
//! the client and the backend did more reads, wakeups and decryptions per call
//! than behind a gateway that keeps a downstream connection's streams on one
//! upstream connection (as Envoy does per worker).
//!
//! An HTTP/2 frontend connection now takes a slot on its first request and
//! holds it for its lifetime. Slots are taken least-loaded, so long-lived
//! connections stay spread evenly however many short-lived ones come and go.
//! Each of its streams counts as open from the request until its response body
//! ends or is dropped ([`FrontendStream`] rides in the response body), and runs
//! with the connection in a task-local. The gRPC pool reads it through
//! [`shard_start`]:
//!
//! - While the connection has at most [`AFFINITY_MAX_OPEN_STREAMS`] open
//!   streams, a call goes to the connection's own shard (`slot % shards`). If
//!   that shard does not exist yet, or has closed, the pool creates it rather
//!   than borrowing a neighbour, so the pool still widens to its configured
//!   width as connections arrive.
//! - Beyond that, the connection is heavy enough that one backend connection
//!   (and its peer's `SETTINGS_MAX_CONCURRENT_STREAMS`) should not carry it
//!   alone: the call spills to the round-robin shard, which is likewise created
//!   if missing. A heavy connection therefore pins at most
//!   [`AFFINITY_MAX_OPEN_STREAMS`] calls on any one shard and still widens the
//!   pool.
//! - Calls with no frontend connection in scope (HTTP/1.1 and HTTP/3
//!   frontends, spawned work) keep the original round-robin probe.
//!
//! An open hyper HTTP/2 sender always reports ready, so the pool cannot see a
//! busy backend connection; the open-stream bound above is what keeps one
//! client from monopolising one.
//!
//! The direct HTTP/2 pool keeps the round-robin start for every request: on the
//! protocol benchmark the same affinity made HTTP/2 slower (up to about 20% at
//! 1–5 MiB on one runner type), while gRPC gained at 10 KiB on every runner.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use crossbeam_utils::CachePadded;

/// Slots in the table. Above the default shard counts (CPU cores clamped to
/// 2–8) so connections spread over every shard; a pool configured with more
/// shards than this does not use affinity (its calls take the spill path).
pub const SLOTS: usize = 64;

/// Open streams a frontend connection may keep on its own shard. Further
/// concurrent calls spill round-robin.
pub const AFFINITY_MAX_OPEN_STREAMS: usize = 32;

/// Live frontend connections per slot.
pub struct SlotTable {
    live: [CachePadded<AtomicUsize>; SLOTS],
}

impl SlotTable {
    pub const fn new() -> Self {
        Self {
            live: [const { CachePadded::new(AtomicUsize::new(0)) }; SLOTS],
        }
    }

    /// Take the lowest slot with the fewest live connections. Two concurrent
    /// acquires may take the same slot; that only costs balance.
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
    pub fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for FrontendConnectionSlot {
    fn drop(&mut self) {
        self.table.live[self.slot].fetch_sub(1, Ordering::Relaxed);
    }
}

/// One frontend connection's affinity state, shared by its streams.
pub struct FrontendConnectionAffinity {
    table: &'static SlotTable,
    /// Taken on the connection's first HTTP/2 request.
    slot: OnceLock<FrontendConnectionSlot>,
    open_streams: CachePadded<AtomicUsize>,
}

impl FrontendConnectionAffinity {
    /// State for a newly accepted frontend connection. Takes no slot until the
    /// connection's first HTTP/2 request.
    pub fn new() -> Arc<Self> {
        Self::with_table(&FRONTEND_SLOTS)
    }

    /// As [`Self::new`], drawing slots from `table`.
    pub fn with_table(table: &'static SlotTable) -> Arc<Self> {
        Arc::new(Self {
            table,
            slot: OnceLock::new(),
            open_streams: CachePadded::new(AtomicUsize::new(0)),
        })
    }

    /// Open one stream of this connection. The stream counts as open until the
    /// returned guard drops, exactly once, whether the response body ends,
    /// errors or the request is cancelled.
    pub fn open_stream(self: &Arc<Self>) -> FrontendStream {
        self.slot.get_or_init(|| self.table.acquire());
        self.open_streams.fetch_add(1, Ordering::Relaxed);
        FrontendStream {
            connection: Arc::clone(self),
        }
    }

    /// Streams currently open.
    pub fn open_streams(&self) -> usize {
        self.open_streams.load(Ordering::Relaxed)
    }

    /// The connection's slot, once its first stream opened.
    pub fn slot(&self) -> Option<usize> {
        self.slot.get().map(FrontendConnectionSlot::slot)
    }
}

/// One open stream of a frontend connection.
pub struct FrontendStream {
    connection: Arc<FrontendConnectionAffinity>,
}

impl FrontendStream {
    /// Run this stream's request with its connection in scope for the gRPC
    /// pool.
    pub async fn run<F: Future>(&self, request: F) -> F::Output {
        FRONTEND_STREAM
            .scope(Arc::clone(&self.connection), request)
            .await
    }
}

impl Drop for FrontendStream {
    fn drop(&mut self) {
        self.connection.open_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

tokio::task_local! {
    static FRONTEND_STREAM: Arc<FrontendConnectionAffinity>;
}

/// Where the gRPC pool's shard probe starts for the current call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardStart {
    /// The frontend connection's own shard; create it if missing.
    Affinity(usize),
    /// A frontend connection over its affinity bound (or a pool wider than
    /// [`SLOTS`]): the round-robin shard, created if missing.
    Spill,
    /// No frontend connection in scope: the round-robin probe, unchanged.
    Unscoped,
}

/// The shard start for the current call on a pool of `shard_count` shards.
pub fn shard_start(shard_count: usize) -> ShardStart {
    let shard_count = shard_count.max(1);
    FRONTEND_STREAM
        .try_with(|connection| match connection.slot() {
            Some(slot)
                if shard_count <= SLOTS
                    && connection.open_streams() <= AFFINITY_MAX_OPEN_STREAMS =>
            {
                ShardStart::Affinity(slot % shard_count)
            }
            _ => ShardStart::Spill,
        })
        .unwrap_or(ShardStart::Unscoped)
}
