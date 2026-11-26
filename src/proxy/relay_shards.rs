//! Per-core `current_thread` Tokio relay shards for long-lived byte relays.
//!
//! # Why relay shards exist
//!
//! High-throughput TCP/TLS stream relays (`tcp_proxy`) and raw WebSocket tunnel
//! sessions (`ws_tunnel`) execute short, tight bidirectional read→TLS→write
//! bursts across many persistent connections. On Tokio's shared `multi_thread`
//! runtime, those connections share one central I/O driver (`epoll`/`kqueue`),
//! contend on work-stealing queues, park/unpark workers via `futex` between
//! bursts, and migrate per-connection TLS state + copy buffers across CPU cores.
//!
//! Moving steady-state stream relays onto N independent `current_thread` Tokio
//! runtimes (one OS thread and one private reactor per core, assigned
//! round-robin at connection/upgrade handoff) eliminates cross-worker locking,
//! work-stealing wakeup latency, and TLS cache migration — matching a
//! thread-per-core event-loop architecture without `SO_REUSEPORT` (preserving
//! Ferrum Edge's exclusive listen-socket invariant).
//!
//! When the process-wide pool is not initialized (unit tests, non-serving modes,
//! or if shard initialization failed), [`next_handle`] returns `None` and
//! callers fall back transparently to the main runtime.

use std::io::{self, BufRead, IoSlice, Read, Write};
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, ready};
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::{Buf, Bytes};
use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::watch;

const MIN_SHARDS: usize = 1;
const MAX_SHARDS: usize = 64;
const SHARD_THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;
const SHARD_MAX_BLOCKING_THREADS: usize = 4;
const SHARD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

static RELAY_SHARD_POOL: ArcSwapOption<RelayShardPool> = ArcSwapOption::const_empty();

/// Resolves the number of per-core relay shards from `FERRUM_WORKER_THREADS`
/// (when explicitly set) or host CPU parallelism, clamped to `[1, 64]`.
pub fn resolve_shard_count(worker_threads: Option<usize>) -> usize {
    worker_threads
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(NonZeroUsize::get)
                .unwrap_or(1)
        })
        .clamp(MIN_SHARDS, MAX_SHARDS)
}

/// Pool of independent `current_thread` Tokio runtime handles, each backed by
/// its own OS thread and OS reactor (`epoll`/`kqueue`).
pub struct RelayShardPool {
    handles: Vec<Handle>,
    main_runtime_handle: Option<Handle>,
    next: AtomicUsize,
}

impl RelayShardPool {
    /// Spawns `shard_count` (clamped to `[1, 64]`) independent `current_thread`
    /// Tokio shard threads and waits until every shard runtime is ready to
    /// accept spawned tasks.
    pub fn new(shard_count: usize) -> io::Result<(Arc<Self>, RelayShardPoolGuard)> {
        Self::new_inner(shard_count, None)
    }

    fn new_inner(
        shard_count: usize,
        main_runtime_handle: Option<Handle>,
    ) -> io::Result<(Arc<Self>, RelayShardPoolGuard)> {
        let count = shard_count.clamp(MIN_SHARDS, MAX_SHARDS);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut handles = Vec::with_capacity(count);
        let mut threads: Vec<thread::JoinHandle<()>> = Vec::with_capacity(count);

        for idx in 0..count {
            let (ready_tx, ready_rx) = mpsc::sync_channel::<io::Result<Handle>>(1);
            let mut shard_shutdown_rx = shutdown_rx.clone();
            let spawn_result = thread::Builder::new()
                .name(format!("ferrum-relay-{idx}"))
                .stack_size(SHARD_THREAD_STACK_SIZE)
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .max_blocking_threads(SHARD_MAX_BLOCKING_THREADS)
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(rt.handle().clone())).is_err() {
                        rt.shutdown_timeout(SHARD_SHUTDOWN_TIMEOUT);
                        return;
                    }
                    rt.block_on(async move {
                        while !*shard_shutdown_rx.borrow_and_update() {
                            if shard_shutdown_rx.changed().await.is_err() {
                                break;
                            }
                        }
                    });
                    rt.shutdown_timeout(SHARD_SHUTDOWN_TIMEOUT);
                });

            let thread_handle = match spawn_result {
                Ok(h) => h,
                Err(err) => {
                    let _ = shutdown_tx.send(true);
                    for handle in threads {
                        let _ = handle.join();
                    }
                    return Err(err);
                }
            };
            threads.push(thread_handle);

            let shard_handle = match ready_rx.recv() {
                Ok(Ok(handle)) => handle,
                Ok(Err(err)) => {
                    let _ = shutdown_tx.send(true);
                    for handle in threads {
                        let _ = handle.join();
                    }
                    return Err(err);
                }
                Err(_) => {
                    let _ = shutdown_tx.send(true);
                    for handle in threads {
                        let _ = handle.join();
                    }
                    return Err(io::Error::other(format!(
                        "relay shard {idx} exited before publishing runtime handle"
                    )));
                }
            };
            handles.push(shard_handle);
        }

        let pool = Arc::new(Self {
            handles,
            main_runtime_handle,
            next: AtomicUsize::new(0),
        });
        let guard = RelayShardPoolGuard {
            pool: Some(Arc::clone(&pool)),
            registered_global: false,
            shutdown_tx,
            threads,
        };
        Ok((pool, guard))
    }

    /// Number of active shard runtimes in this pool.
    pub fn shard_count(&self) -> usize {
        self.handles.len()
    }

    /// Clones every shard runtime handle (used for bounded event-loop probes).
    pub fn handles(&self) -> Vec<Handle> {
        self.handles.clone()
    }

    /// Selects the next shard handle in round-robin order.
    #[inline]
    pub fn next_handle(&self) -> Handle {
        // Invariant: `RelayShardPool::new` clamps `count >= MIN_SHARDS (1)`, so
        // `self.handles` is non-empty and `idx < self.handles.len()`.
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.handles.len();
        self.handles[idx].clone()
    }
}

/// Lifecycle guard for a [`RelayShardPool`].
///
/// Dropping this guard unregisters the pool (if installed globally), signals
/// every shard thread to exit its event loop, and joins all shard threads after
/// draining with [`SHARD_SHUTDOWN_TIMEOUT`].
pub struct RelayShardPoolGuard {
    pool: Option<Arc<RelayShardPool>>,
    registered_global: bool,
    shutdown_tx: watch::Sender<bool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Drop for RelayShardPoolGuard {
    fn drop(&mut self) {
        if self.registered_global
            && let Some(pool) = self.pool.take()
        {
            // Identity-checked atomic CAS so an older guard cannot clear a
            // newer pool installed concurrently.
            RELAY_SHARD_POOL.rcu(|current| {
                if current
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &pool))
                {
                    None
                } else {
                    current.as_ref().map(Arc::clone)
                }
            });
        }
        let _ = self.shutdown_tx.send(true);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Initializes and publishes the process-wide per-core relay shard pool.
///
/// `main_runtime_handle` records the main multi-threaded Tokio runtime so
/// shard-hosted connections that need blocking workers (e.g., `io_uring`
/// splice) still submit against the operator's `FERRUM_BLOCKING_THREADS` pool.
///
/// Callers must hold the returned [`RelayShardPoolGuard`] for the lifetime of
/// the gateway and drop it after the main Tokio runtime finishes draining.
pub fn initialize(
    worker_threads: Option<usize>,
    main_runtime_handle: Handle,
) -> io::Result<RelayShardPoolGuard> {
    let count = resolve_shard_count(worker_threads);
    let (pool, mut guard) = RelayShardPool::new_inner(count, Some(main_runtime_handle))?;
    guard.registered_global = true;
    RELAY_SHARD_POOL.store(Some(pool));
    Ok(guard)
}

/// Returns the next round-robin relay shard handle if the process-wide pool is
/// active, or `None` when running without relay shards.
#[inline]
pub fn next_handle() -> Option<Handle> {
    RELAY_SHARD_POOL
        .load()
        .as_ref()
        .map(|pool| pool.next_handle())
}

/// Returns handles for all active process-wide relay shards, or an empty `Vec`
/// when relay shards are not initialized.
pub fn all_handles() -> Vec<Handle> {
    RELAY_SHARD_POOL
        .load()
        .as_ref()
        .map(|pool| pool.handles())
        .unwrap_or_default()
}

/// Returns the main Tokio runtime handle registered alongside the relay shard
/// pool, so shard-hosted tasks can route blocking work to the configured main
/// blocking pool (`FERRUM_BLOCKING_THREADS`).
#[inline]
pub fn main_runtime_handle() -> Option<Handle> {
    RELAY_SHARD_POOL
        .load()
        .as_ref()
        .and_then(|pool| pool.main_runtime_handle.clone())
}

/// RAII wrapper that defers dropping `T` onto the serving `MultiThread` main
/// runtime whenever dropped on a `current_thread` relay shard.
///
/// Long-lived shard tasks hold references to retired config epochs and plugin
/// instances across live reloads. Deferring their final drop to the main
/// runtime ensures plugin destructors that require `RuntimeFlavor::MultiThread`
/// (e.g., ordered flush/retirement) run in the expected runtime without
/// blocking the relay shard's event loop.
pub struct DropOnMainRuntime<T: Send + 'static>(Option<T>);

impl<T: Send + 'static> DropOnMainRuntime<T> {
    pub fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T: Send + 'static> Drop for DropOnMainRuntime<T> {
    fn drop(&mut self) {
        let Some(value) = self.0.take() else {
            return;
        };
        let on_current_thread = Handle::try_current()
            .ok()
            .is_some_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread);
        if on_current_thread && let Some(main_handle) = main_runtime_handle() {
            main_handle.spawn(async move {
                drop(value);
            });
        }
    }
}

/// Transparent I/O wrapper that yields already-buffered `prefix` bytes from
/// `poll_read` before delegating reads to the underlying `io`.
pub struct PrefixedIo<IO> {
    io: IO,
    prefix: Bytes,
}

impl<IO> PrefixedIo<IO> {
    pub fn new(io: IO, prefix: Bytes) -> Self {
        Self { io, prefix }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for PrefixedIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.prefix.is_empty() {
            let len = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..len]);
            this.prefix.advance(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Post-handshake TLS stream reconstructed around a re-registered underlying
/// transport (`IO`) and an established `rustls` session (`ServerConnection` or
/// `ClientConnection`), optionally preceded by already-decrypted `prefix` bytes
/// (e.g., Hyper's `upgrade::Parts::read_buf`).
///
/// Mirrors `tokio-rustls` 0.26 streaming semantics:
/// - Coalesces multiple already-ready TLS records per `poll_read`, deferring
///   trailing errors so valid decrypted bytes are never dropped.
/// - Preserves `rustls`'s `UnexpectedEof("peer closed connection without
///   sending TLS close_notify")` classification on unclean TCP EOF.
/// - Uses `write_vectored` when flushing ciphertext to `io`.
/// - Sends TLS `close_notify` on `poll_shutdown`, flushes it, and shuts down
///   `io` (ignoring `ErrorKind::NotConnected`).
pub struct RehomedTlsStream<IO, C> {
    io: IO,
    session: C,
    prefix: Bytes,
    read_eof: bool,
    write_shutdown: bool,
    deferred_read_err: Option<io::Error>,
}

impl<IO, C> RehomedTlsStream<IO, C> {
    pub fn new(io: IO, session: C, prefix: Bytes) -> Self {
        Self::with_deferred_read_error(io, session, prefix, None)
    }

    /// Reconstructs a post-handshake TLS stream while preserving any deferred
    /// read error observed on the previous `tokio_rustls::TlsStream` wrapper
    /// prior to `into_inner()`.
    pub fn with_deferred_read_error(
        io: IO,
        session: C,
        prefix: Bytes,
        deferred_read_err: Option<io::Error>,
    ) -> Self {
        let read_eof = deferred_read_err
            .as_ref()
            .is_some_and(|err| err.kind() == io::ErrorKind::ConnectionAborted);
        Self {
            io,
            session,
            prefix,
            read_eof,
            write_shutdown: false,
            deferred_read_err,
        }
    }
}

impl<IO, C, SD> RehomedTlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter {
            io: &mut self.io,
            cx,
        };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };

        self.session.process_new_packets().map_err(|err| {
            // Best-effort alert flush before surfacing the TLS error,
            // matching `tokio-rustls`.
            let _ = self.write_io(cx);
            io::Error::new(io::ErrorKind::InvalidData, err)
        })?;

        Poll::Ready(Ok(n))
    }

    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut io_pending = false;

        while !self.read_eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => {
                    if err.kind() == io::ErrorKind::ConnectionAborted {
                        self.read_eof = true;
                    }
                    return Poll::Ready(Err(err));
                }
            }
        }

        match self.session.reader().into_first_chunk() {
            Ok(data) => {
                if data.is_empty() {
                    self.read_eof = true;
                    return Poll::Ready(Ok(0));
                }
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                self.session.reader().consume(len);
                Poll::Ready(Ok(len))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::ConnectionAborted {
                    self.read_eof = true;
                }
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<IO, C, SD> AsyncRead for RehomedTlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.prefix.is_empty() {
            let len = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..len]);
            this.prefix.advance(len);
            return Poll::Ready(Ok(()));
        }
        if this.deferred_read_err.is_some() {
            // Drain any already-decrypted plaintext buffered in `session`
            // before surfacing a deferred transport/TLS read error so valid
            // bytes preceding a reset are never discarded.
            if let Ok(data) = this.session.reader().into_first_chunk()
                && !data.is_empty()
            {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                this.session.reader().consume(len);
                return Poll::Ready(Ok(()));
            }
            if let Some(err) = this.deferred_read_err.take() {
                return Poll::Ready(Err(err));
            }
        }
        if this.read_eof {
            return Poll::Ready(Ok(()));
        }

        let first = ready!(this.poll_read_chunk(cx, buf))?;
        if first == 0 {
            return Poll::Ready(Ok(()));
        }

        while buf.remaining() > 0 && !this.read_eof {
            match this.poll_read_chunk(cx, buf) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(err)) => {
                    this.deferred_read_err = Some(err);
                    break;
                }
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO, C, SD> AsyncWrite for RehomedTlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream write half is shut down",
            )));
        }

        let mut pos = 0;
        while pos != buf.len() {
            let mut would_block = false;
            let mut write_zero = false;
            let mut drained = false;

            let accepted = match this.session.writer().write(&buf[pos..]) {
                Ok(n) => {
                    pos += n;
                    n
                }
                Err(err) => return Poll::Ready(Err(err)),
            };

            while this.session.wants_write() {
                match this.write_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        write_zero = true;
                        break;
                    }
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        drained = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if write_zero {
                return if pos > 0 {
                    Poll::Ready(Ok(pos))
                } else {
                    Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                };
            }
            if would_block {
                return if pos > 0 {
                    Poll::Ready(Ok(pos))
                } else {
                    Poll::Pending
                };
            }
            if accepted == 0 && !drained {
                return if pos > 0 {
                    Poll::Ready(Ok(pos))
                } else {
                    Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                };
            }
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream write half is shut down",
            )));
        }
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        loop {
            let mut would_block = false;
            let mut write_zero = false;
            let mut drained = false;
            let written = this.session.writer().write_vectored(bufs)?;

            while this.session.wants_write() {
                match this.write_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        write_zero = true;
                        break;
                    }
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        drained = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if written > 0 {
                return Poll::Ready(Ok(written));
            }
            if write_zero {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            if would_block {
                return Poll::Pending;
            }
            if !drained {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.session.writer().flush()?;
        while this.session.wants_write() {
            if ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_shutdown {
            this.session.send_close_notify();
            this.write_shutdown = true;
        }
        while this.session.wants_write() {
            if ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Poll::Ready(match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(err) => Err(err),
        })
    }
}

struct SyncReadAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

struct SyncWriteAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
