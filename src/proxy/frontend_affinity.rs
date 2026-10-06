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
//! An HTTP/2 frontend connection (ALPN `h2`, prior-knowledge h2 over TLS, or
//! h2c) now takes a slot on its first HTTP/2 request and holds it for its
//! lifetime; HTTP/1.x connections allocate nothing. Slots come from the gRPC
//! pool's own [`SlotTable`], so separate gateways (and in-process tests) never
//! share balance state. Slots are taken least-loaded, so long-lived
//! connections stay spread evenly however many short-lived ones come and go.
//! Each stream counts until its response terminates: [`FrontendStream`] rides
//! in the response body and runs with the connection in a task-local. The
//! count is gateway-side only; an upload h2 still holds after an early
//! terminal response is no longer counted, which can only make the soft bound
//! below admit a few more affinity calls. The gRPC pool reads it through
//! [`shard_start`]:
//!
//! - While the connection has at most [`AFFINITY_MAX_OPEN_STREAMS`] open
//!   streams, and no more than its shard's backend allows
//!   ([`affinity_stream_limit`]), a call goes to the connection's own shard
//!   (`slot % shards`).
//! - Beyond that, the connection is heavy enough that one backend connection
//!   should not carry it alone: further calls spill to the round-robin shard.
//!   A heavy connection therefore pins at most that many of its calls to its
//!   own shard; the rest are spread round-robin over all shards (its own
//!   included).
//! - When the affinity or spill shard does not exist yet, or has closed, and a
//!   ready sibling exists, the call is served by the sibling at once and the
//!   preferred shard is created in the background (one detached create per
//!   shard), so the pool still widens to its configured width as connections
//!   arrive without a new connection waiting on a dial. Only a pool with no
//!   ready shard dials on the request path.
//! - A failed or cancelled affinity/spill create puts the shard on a short
//!   borrow cooldown. A cold pool can retry immediately. The bounded cache
//!   records only physical attempts, never coalesced waiters, and does at most
//!   one FIFO eviction per failure.
//! - Calls with no frontend connection in scope (HTTP/1.1 and HTTP/3
//!   frontends, spawned work) keep the original round-robin probe.
//!
//! An open hyper HTTP/2 sender always reports ready, however many streams it
//! carries, so the pool cannot see a busy backend connection from the sender.
//! The connection driver samples the backend's
//! `SETTINGS_MAX_CONCURRENT_STREAMS` from hyper's
//! `Connection::current_max_send_streams()` after every poll, and the pool
//! caps a connection's pinned streams at the smaller of that and
//! [`AFFINITY_MAX_OPEN_STREAMS`]. The bound is per frontend connection, not
//! per shard: several busy connections whose slots share a shard still share
//! its backend connection, each within its own bound, so a backend that allows
//! very few concurrent streams can still queue calls that round-robin would
//! have spread; counting per shard would put a shared atomic on every call.
//! Slots are spread evenly over shard counts that divide [`SLOTS`] (the
//! default 2, 4 and 8); other counts are slightly uneven once more than
//! [`SLOTS`] HTTP/2 connections are live.
//!
//! Affinity makes the pool open its shards on demand: a client that opens many
//! short-lived HTTP/2 connections spreads them over every slot, so each
//! backend host can see up to `http2_connections_per_host` backend
//! connections where round-robin borrowing would have reused fewer.
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
/// concurrent calls spill round-robin. A backend that advertises a lower
/// `SETTINGS_MAX_CONCURRENT_STREAMS` lowers this bound for its shard.
pub const AFFINITY_MAX_OPEN_STREAMS: usize = 32;

/// Open streams a frontend connection may pin to a shard whose backend
/// currently allows `peer_max_streams` concurrent streams.
pub fn affinity_stream_limit(peer_max_streams: usize) -> usize {
    AFFINITY_MAX_OPEN_STREAMS.min(peer_max_streams.max(1))
}

/// Live frontend connections per slot. One table per gRPC pool, shared by
/// every frontend listener of that gateway.
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
    pub fn acquire(self: &Arc<Self>) -> FrontendConnectionSlot {
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
        FrontendConnectionSlot {
            table: Arc::clone(self),
            slot,
        }
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

/// A frontend connection's slot, released when the connection ends.
pub struct FrontendConnectionSlot {
    table: Arc<SlotTable>,
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
    table: Arc<SlotTable>,
    /// Taken on the connection's first HTTP/2 request.
    slot: OnceLock<FrontendConnectionSlot>,
    open_streams: CachePadded<AtomicUsize>,
}

impl FrontendConnectionAffinity {
    /// State for a newly accepted frontend connection, drawing its slot from
    /// `table`. Takes no slot until the connection's first HTTP/2 request.
    pub fn with_table(table: &Arc<SlotTable>) -> Arc<Self> {
        Arc::new(Self {
            table: Arc::clone(table),
            slot: OnceLock::new(),
            open_streams: CachePadded::new(AtomicUsize::new(0)),
        })
    }

    /// Open one stream of this connection. The stream counts as open until the
    /// returned guard drops, exactly once.
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

/// A frontend connection's affinity state, allocated on its first HTTP/2
/// request: HTTP/1.x connections never allocate it or take a slot.
pub struct LazyConnectionAffinity {
    table: Arc<SlotTable>,
    connection: OnceLock<Arc<FrontendConnectionAffinity>>,
}

impl LazyConnectionAffinity {
    /// Affinity for one accepted frontend connection, drawing its slot from
    /// the gateway's gRPC pool table.
    pub fn new(table: Arc<SlotTable>) -> Self {
        Self {
            table,
            connection: OnceLock::new(),
        }
    }

    /// Open a stream for a request of `version`; HTTP/1.x requests get none.
    pub fn open_stream(&self, version: hyper::Version) -> Option<FrontendStream> {
        (version == hyper::Version::HTTP_2).then(|| {
            self.connection
                .get_or_init(|| FrontendConnectionAffinity::with_table(&self.table))
                .open_stream()
        })
    }
}

/// One open stream of a frontend connection. Dropping it closes the stream;
/// the frontend keeps it in the response body, so it closes when the response
/// terminates.
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

    /// Run a frontend handler in scope and hand the stream back for its
    /// response body. Cancelling the handler drops the stream, closing it.
    pub async fn run_request<F: Future>(self, request: F) -> (F::Output, Self) {
        let output = self.run(request).await;
        (output, self)
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
    /// The frontend connection's own shard, created if missing. The pool
    /// spills instead when `open_streams` exceeds that shard's
    /// [`affinity_stream_limit`].
    Affinity { shard: usize, open_streams: usize },
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
        .try_with(|connection| {
            let open_streams = connection.open_streams();
            match connection.slot() {
                Some(slot)
                    if shard_count <= SLOTS && open_streams <= AFFINITY_MAX_OPEN_STREAMS =>
                {
                    ShardStart::Affinity {
                        shard: slot % shard_count,
                        open_streams,
                    }
                }
                _ => ShardStart::Spill,
            }
        })
        .unwrap_or(ShardStart::Unscoped)
}
