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
//! lifetime; HTTP/1.x connections allocate nothing. Slots are taken least-loaded, so long-lived
//! connections stay spread evenly however many short-lived ones come and go.
//! Each stream counts until its response terminates; a streamed gRPC request
//! also retains the count until its upload terminates, even after an early
//! terminal response. [`FrontendStream`] rides in the response body and runs
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
//!   alone: further calls spill to the round-robin shard, which is likewise
//!   created if missing. A heavy connection therefore pins at most
//!   [`AFFINITY_MAX_OPEN_STREAMS`] of its calls to its own shard; the rest are
//!   spread round-robin over all shards (its own included), and it still
//!   widens the pool.
//! - A failed or cancelled affinity/spill create puts the shard on a short
//!   borrow cooldown when a ready sibling exists. A cold pool can retry
//!   immediately. The bounded cache records only physical attempts, never
//!   coalesced waiters, and does at most one FIFO eviction per failure.
//! - Calls with no frontend connection in scope (HTTP/1.1 and HTTP/3
//!   frontends, spawned work) keep the original round-robin probe.
//!
//! An open hyper HTTP/2 sender always reports ready, and hyper does not expose
//! the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`, so the pool cannot see a busy
//! backend connection; the open-stream bound above is what keeps one client
//! from monopolising one. The bound is per frontend connection, not per shard:
//! several busy connections whose slots share a shard still share its backend
//! connection (each with at most [`AFFINITY_MAX_OPEN_STREAMS`] affinity calls),
//! and a backend that allows fewer concurrent streams than that can queue
//! calls that round-robin would have spread. Slots are spread evenly over
//! shard counts that divide [`SLOTS`] (the default 2, 4 and 8); other counts
//! are slightly uneven once more than [`SLOTS`] HTTP/2 connections are live.
//!
//! The direct HTTP/2 pool keeps the round-robin start for every request: on the
//! protocol benchmark the same affinity made HTTP/2 slower (up to about 20% at
//! 1–5 MiB on one runner type), while gRPC gained at 10 KiB on every runner.

use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    /// returned guard drops, exactly once. A streaming gRPC upload joins its
    /// own termination with that response-side guard.
    pub fn open_stream(self: &Arc<Self>) -> FrontendStream {
        self.slot.get_or_init(|| self.table.acquire());
        self.open_streams.fetch_add(1, Ordering::Relaxed);
        FrontendStream {
            connection: Arc::clone(self),
            upload_join: None,
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
#[derive(Default)]
pub struct LazyConnectionAffinity {
    connection: OnceLock<Arc<FrontendConnectionAffinity>>,
}

impl LazyConnectionAffinity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a stream for a request of `version`; HTTP/1.x requests get none.
    pub fn open_stream(&self, version: hyper::Version) -> Option<FrontendStream> {
        (version == hyper::Version::HTTP_2).then(|| {
            self.connection
                .get_or_init(FrontendConnectionAffinity::new)
                .open_stream()
        })
    }
}

/// One open stream of a frontend connection.
pub struct FrontendStream {
    connection: Arc<FrontendConnectionAffinity>,
    // Streaming gRPC reuses its request-byte latch for two independent
    // transport owners. Other H2 requests keep one guard.
    upload_join: Option<Arc<super::body::DirectH2BytesLatch>>,
}

impl FrontendStream {
    /// Run this stream's request with its connection in scope for the gRPC
    /// pool.
    pub async fn run<F: Future>(&self, request: F) -> F::Output {
        FRONTEND_STREAM
            .scope(Arc::clone(&self.connection), request)
            .await
    }

    /// Scope a frontend handler and return its response-side guard. The
    /// request-body constructor may register an upload observer while the
    /// handler runs. Keeping the guard inside the scope makes cancellation
    /// release the response half even before a response body exists.
    pub async fn run_request<F: Future>(self, request: F) -> (F::Output, Self) {
        let connection = Arc::clone(&self.connection);
        FRONTEND_STREAM
            .scope(
                connection,
                FRONTEND_REQUEST.scope(RefCell::new(Some(self)), async move {
                    let output = request.await;
                    let stream = FRONTEND_REQUEST.with(|stream| stream.borrow_mut().take());
                    // This scope owns exactly one guard; only this terminal
                    // handoff takes it out. Upload registration borrows it.
                    let stream = stream.expect("frontend request scope owns its stream guard");
                    (output, stream)
                }),
            )
            .await
    }
}

impl Drop for FrontendStream {
    fn drop(&mut self) {
        if let Some(join) = self.upload_join.as_ref() {
            if let Some(join) = join.frontend_upload_join.get() {
                join.terminate(RESPONSE_TERMINATED);
            }
        } else {
            self.connection.open_streams.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

tokio::task_local! {
    static FRONTEND_STREAM: Arc<FrontendConnectionAffinity>;
    static FRONTEND_REQUEST: RefCell<Option<FrontendStream>>;
}

const UPLOAD_TERMINATED: u8 = 1;
const RESPONSE_TERMINATED: u8 = 2;
const BOTH_TERMINATED: u8 = UPLOAD_TERMINATED | RESPONSE_TERMINATED;

pub(crate) struct StreamUploadJoin {
    connection: Arc<FrontendConnectionAffinity>,
    terminated: AtomicU8,
    observer: Option<Arc<dyn super::grpc_proxy::GrpcUploadTerminationObserver>>,
}

impl StreamUploadJoin {
    fn terminate(&self, half: u8) -> bool {
        let previous = self.terminated.fetch_or(half, Ordering::AcqRel);
        if previous != BOTH_TERMINATED && previous | half == BOTH_TERMINATED {
            self.connection.open_streams.fetch_sub(1, Ordering::Relaxed);
        }
        previous & half == 0
    }
}

impl super::grpc_proxy::GrpcUploadTerminationObserver for super::body::DirectH2BytesLatch {
    fn on_upload_terminated(&self) {
        if let Some(join) = self.frontend_upload_join.get()
            && join.terminate(UPLOAD_TERMINATED)
            && let Some(observer) = join.observer.as_ref()
        {
            observer.on_upload_terminated();
        }
    }
}

/// Join the streamed gRPC upload's existing terminal observer with the
/// frontend response lifetime. Unscoped dispatches retain their observer.
/// Called immediately before constructing the body that owns the observer.
/// Reuses the request-byte latch when supplied; standalone callers without
/// byte accounting allocate a latch only if a frontend request is in scope.
pub fn retain_upload(
    observer: Option<Arc<dyn super::grpc_proxy::GrpcUploadTerminationObserver>>,
    request_latch: Option<&Arc<super::body::DirectH2BytesLatch>>,
) -> Option<Arc<dyn super::grpc_proxy::GrpcUploadTerminationObserver>> {
    let mut observer = observer;
    let joined = FRONTEND_REQUEST.try_with(|stream| {
        let mut stream = stream.borrow_mut();
        let stream = stream.as_mut()?;
        let latch = match request_latch {
            Some(latch) => Arc::clone(latch),
            None => Arc::new(super::body::DirectH2BytesLatch::new()),
        };
        let join = StreamUploadJoin {
            connection: Arc::clone(&stream.connection),
            terminated: AtomicU8::new(0),
            observer: observer.take(),
        };
        if let Err(join) = latch.frontend_upload_join.set(join) {
            // A latch belongs to one upload. Leave an already registered
            // owner intact if a caller attempts to register it again.
            observer = join.observer;
            return None;
        }
        stream.upload_join = Some(Arc::clone(&latch));
        let latch: Arc<dyn super::grpc_proxy::GrpcUploadTerminationObserver> = latch;
        Some(latch)
    });
    joined.ok().flatten().or(observer)
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
