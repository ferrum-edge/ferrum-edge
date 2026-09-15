//! Post-EOS backend send-queue drain bound for `backend_write_timeout_ms`
//! (issue #4411).
//!
//! # The gap this closes
//!
//! [`crate::proxy::upload_pump`] bounds the *pre*-EOS half of a backend write:
//! its idle arm fires while the transport has stopped taking frames from the
//! bridge. Once the last frame has crossed that bridge the pump completes, and
//! from that instant the gateway has no application-level receipt that the
//! backend ever read a byte — HTTP has no request-side acknowledgement. A
//! backend that `accept()`s and never calls `recv()` therefore left the request
//! sitting in the response-header wait until `backend_read_timeout_ms` (30 s by
//! default) or the client gave up, even with an 800 ms write watermark
//! configured.
//!
//! # What the kernel does know
//!
//! The local send queue. A peer that never reads fills its socket receive
//! buffer; Linux receive-buffer autotuning grows only on application reads, so
//! for a peer that never calls `recv()` the advertised window stays near the
//! initial ~128 KiB. Every byte of the upload beyond that window is parked in
//! the gateway's OWN send queue — unsent, or sent and unacked — for the life of
//! the connection. [`crate::socket_opts::socket_send_queue_bytes`] reads that
//! depth directly (`SIOCOUTQ` on Linux, `SO_NWRITE` on macOS).
//!
//! Sampling it after EOS turns "the backend is not consuming the upload" into a
//! monotonic transport observation rather than a timing heuristic: the depth of
//! a draining connection strictly decreases, and the depth of a stalled one
//! does not.
//!
//! # Residual, deliberately not approximated
//!
//! A body the peer's kernel fully accepted (depth reaches 0) is invisible to
//! this bound and stays governed by `backend_read_timeout_ms`, exactly as
//! before — which is the right answer, because the gateway's write genuinely
//! completed. In practice that is any upload smaller than the peer's receive
//! buffer. Platforms with no send-queue query (Windows) keep the read bound
//! too. Both are documented next to `backend_write_timeout_ms` in
//! `docs/configuration.md`.
//!
//! # Multiplexed transports
//!
//! On a pooled HTTP/2 connection the send queue is shared by every stream on
//! it. Even a flat or growing aggregate depth can represent healthy progress
//! when acknowledged bytes from one stream are replaced by bytes from another.
//! Such sockets must not be published to a per-request drain watcher; without
//! stream-attributable evidence, the response-header read timeout remains the
//! safe post-EOS bound.

use std::sync::Arc;
use std::time::Duration;

use crate::socket_opts::monotonic_now_ms;

/// Longest gap between two send-queue samples.
///
/// The cadence is `min(100 ms, write_timeout / 4)`: at least four observations
/// inside one watermark, so a stall verdict is never reached on a single
/// reading, and never coarser than 100 ms for a long watermark.
const MAX_SAMPLE_INTERVAL_MS: u64 = 100;

/// Sampling cadence for one configured `backend_write_timeout_ms`.
pub(crate) fn sample_interval(write_timeout_ms: u64) -> Duration {
    let quarter = write_timeout_ms / 4;
    let interval = if quarter < MAX_SAMPLE_INTERVAL_MS {
        quarter
    } else {
        MAX_SAMPLE_INTERVAL_MS
    };
    // Never zero: a sub-4ms watermark would otherwise spin the sampler.
    Duration::from_millis(if interval == 0 { 1 } else { interval })
}

/// A duplicated handle on one backend socket, usable for send-queue sampling
/// after the transport that owns the socket has stopped handing it to us.
///
/// The fd is `dup`ed rather than borrowed on purpose. A raw fd number that the
/// owning transport has closed can be recycled by any later socket in the
/// process, and sampling a recycled number would read an unrelated
/// connection's send queue. Duplicating keeps the file description alive for
/// exactly as long as a handle exists, so a sample is always about the socket
/// it was taken from or fails outright.
///
/// Lifetime: one handle is created per pooled backend connection and dropped
/// with the pool entry, and the request path only ever clones the `Arc` for the
/// duration of one response-header wait, so the duplicate never outlives the
/// connection it describes.
pub struct BackendSocketHandle {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

impl std::fmt::Debug for BackendSocketHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendSocketHandle")
            .finish_non_exhaustive()
    }
}

impl BackendSocketHandle {
    /// Duplicate `stream`'s descriptor for later sampling.
    ///
    /// `None` when the platform has no send-queue query, or when the duplicate
    /// cannot be made (fd exhaustion) — in both cases the drain bound stays
    /// disarmed and the read timeout governs, which is the pre-#4411 behaviour.
    // The direct HTTP/2 and native gRPC pools no longer publish their sockets
    // (multiplexed connections have no per-request send queue), so this
    // constructor has no binary caller until a per-request transport uses it;
    // it stays as the owned-stream counterpart of `duplicate_from_raw_fd` and
    // is exercised by the integration tests.
    #[allow(dead_code)]
    #[cfg(unix)]
    pub fn duplicate_from(stream: &tokio::net::TcpStream) -> Option<Arc<Self>> {
        if !crate::socket_opts::send_queue_probe_supported() {
            return None;
        }
        use std::os::fd::AsFd;
        let fd = stream.as_fd().try_clone_to_owned().ok()?;
        Some(Arc::new(Self { fd }))
    }

    #[cfg(not(unix))]
    pub fn duplicate_from(_stream: &tokio::net::TcpStream) -> Option<Arc<Self>> {
        None
    }

    /// [`duplicate_from`](Self::duplicate_from) for a socket the gateway only
    /// ever sees as a raw descriptor (issue #4411): the bundled HTTP client
    /// reports its newly dialed backend socket to
    /// [`crate::backend_conn_limit::ReqwestConnectionAdmission`] as an
    /// `AsRawFd` value, never as a `TcpStream` it hands over.
    ///
    /// The descriptor is duplicated here, inside the reporting call, exactly as
    /// [`duplicate_from`](Self::duplicate_from) duplicates an owned stream — so
    /// nothing outside this call ever holds a bare fd number that the owning
    /// transport could close and the kernel could recycle.
    ///
    /// # Safety contract
    ///
    /// `fd` must be open for the duration of this call. The vendored reqwest
    /// hook guarantees that: it reports the descriptor after the dial resolved
    /// and before the connection object is handed to hyper, with the connection
    /// (and therefore the socket) alive and owned by the connector.
    #[cfg(unix)]
    pub fn duplicate_from_raw_fd(fd: std::os::fd::RawFd) -> Option<Arc<Self>> {
        if !crate::socket_opts::send_queue_probe_supported() {
            return None;
        }
        // SAFETY: see the safety contract above — the caller reports a
        // descriptor its own live connection owns, and the borrow does not
        // escape this expression.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let fd = borrowed.try_clone_to_owned().ok()?;
        Some(Arc::new(Self { fd }))
    }

    /// Current send-queue depth in bytes, or `None` when the kernel refuses to
    /// answer (closed socket, unsupported platform).
    #[cfg(unix)]
    pub fn send_queue_bytes(&self) -> Option<u64> {
        use std::os::fd::AsRawFd;
        crate::socket_opts::socket_send_queue_bytes(self.fd.as_raw_fd()).ok()
    }

    #[cfg(not(unix))]
    pub fn send_queue_bytes(&self) -> Option<u64> {
        None
    }
}

/// Where a dispatcher publishes the backend socket for the request it is about
/// to send, so the upload pump can sample it after EOS.
///
/// Write-once and lock-free: the dispatcher fills it immediately before
/// `send_request`, which is strictly before any body frame can cross the
/// bridge, so the pump either sees the socket for the whole drain or sees
/// nothing at all and stays disarmed.
pub(crate) type BackendSocketSlot = Arc<std::sync::OnceLock<Arc<BackendSocketHandle>>>;

/// What one send-queue observation says about the backend's consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendQueueVerdict {
    /// The peer's kernel has accepted every byte. Nothing is left to bound; the
    /// response-header wait belongs to `backend_read_timeout_ms` from here.
    Drained,
    /// The queue is shrinking, or the watermark has not elapsed yet.
    Progressing,
    /// Non-zero and not strictly smaller than the best depth seen, for at least
    /// `backend_write_timeout_ms`.
    Stalled,
}

/// The progress rule for the post-EOS drain, kept separate from the syscall and
/// the timer so it can be proven directly (issue #4411).
///
/// Progress means **strictly decreasing** depth. The floor is a low-water mark
/// and is never raised, so a depth that oscillates upward and returns to the
/// same value has made no progress: an upload that keeps being re-queued
/// without the peer ever accepting more of it is exactly the stall this bounds.
#[derive(Debug)]
pub(crate) struct SendQueueProgress {
    /// Lowest non-zero depth observed so far; `u64::MAX` until the first
    /// observation establishes it.
    floor: u64,
    /// Monotonic milliseconds at the last strict decrease, or at the start of
    /// the watch when there has not been one.
    last_progress_ms: u64,
    timeout_ms: u64,
}

impl SendQueueProgress {
    pub(crate) fn new(now_ms: u64, timeout_ms: u64) -> Self {
        Self {
            floor: u64::MAX,
            last_progress_ms: now_ms,
            timeout_ms,
        }
    }

    /// Fold one observation into the rule.
    pub(crate) fn observe(&mut self, depth: u64, now_ms: u64) -> SendQueueVerdict {
        if depth == 0 {
            return SendQueueVerdict::Drained;
        }
        if depth < self.floor {
            // The FIRST observation only establishes the floor; it must not
            // also restart the clock, or the watermark would always be charged
            // one sampling interval late.
            if self.floor != u64::MAX {
                self.last_progress_ms = now_ms;
            }
            self.floor = depth;
            return SendQueueVerdict::Progressing;
        }
        if self.timeout_ms > 0 && now_ms.saturating_sub(self.last_progress_ms) >= self.timeout_ms {
            SendQueueVerdict::Stalled
        } else {
            SendQueueVerdict::Progressing
        }
    }
}

/// Watch one backend socket's send queue drain, resolving `true` only on a
/// stall.
///
/// Resolves `false` — and stops sampling — as soon as the queue drains or the
/// kernel stops answering for this socket, so a healthy request pays at most a
/// handful of `ioctl`s and no allocation per sample.
pub(crate) async fn await_send_queue_stall(
    socket: &BackendSocketHandle,
    write_timeout_ms: u64,
) -> bool {
    if write_timeout_ms == 0 {
        return false;
    }
    let interval = sample_interval(write_timeout_ms);
    let mut progress = SendQueueProgress::new(monotonic_now_ms(), write_timeout_ms);
    loop {
        tokio::time::sleep(interval).await;
        let Some(depth) = socket.send_queue_bytes() else {
            // The socket is gone or the kernel refuses to answer. Fail open:
            // the remaining bounds (`backend_read_timeout_ms`, the client
            // deadline) still apply, and inventing a stall from a failed probe
            // would 504 healthy traffic.
            return false;
        };
        match progress.observe(depth, monotonic_now_ms()) {
            SendQueueVerdict::Drained => return false,
            SendQueueVerdict::Progressing => {}
            SendQueueVerdict::Stalled => return true,
        }
    }
}

// ── The bundled HTTP client's backend socket (issue #4411) ──────────────────
//
// Every other backend transport constructs its own `TcpStream`, so its
// dispatcher can publish a [`BackendSocketHandle`] directly into the pump's
// slot. The bundled HTTP client owns and hides its socket pool: the gateway
// learns about a socket only through the vendored connection-admission hook
// (`docs/upstream-reqwest-patches/004-connection-established-fd/`), which fires
// deep inside the connector — with no reference to the request that caused the
// dial.
//
// A task-local closes that gap without a registry. The connector is polled by
// the very task that is awaiting this request's dispatch future, so scoping the
// pump's slot around that future makes "the connection this request dialed" the
// only thing the hook can publish into. It cannot mis-attribute: a task that
// dialed nothing publishes nothing, and the slot is write-once.
//
// A request served on an ALREADY-POOLED connection dials nothing and therefore
// arms no drain bound — `backend_read_timeout_ms` governs it, exactly as before
// #4411. That is a residual, not a hole in the reported failure mode: a
// connection whose send queue is stalled never completes its request, so it is
// never returned to the idle pool, so every request against a backend that
// accepts and never reads dials a fresh socket. It is documented next to
// `backend_write_timeout_ms` in `docs/configuration.md`.
tokio::task_local! {
    static REQWEST_BACKEND_SOCKET: BackendSocketSlot;
}

/// Poll an already-pinned dispatch future with `slot` armed as the task-local
/// destination for any backend socket the bundled HTTP client dials during
/// that poll.
///
/// Borrows the future instead of owning it. The dispatch futures this wraps
/// are the largest state machines in the gateway, and an HTTP/3 → plain
/// dispatch overflowed a 2 MiB worker stack on hosted runners once it was
/// routed through an `async fn` and a by-value `TaskLocalFuture` (two more
/// whole-future copies in a debug build). The caller pins the future exactly
/// once, as it did before issue #4411, and this adapter adds one pointer and
/// one `Arc` clone per poll.
pub(crate) struct ReqwestBackendSocketScope<'a, F> {
    future: std::pin::Pin<&'a mut F>,
    slot: BackendSocketSlot,
}

impl<'a, F> ReqwestBackendSocketScope<'a, F> {
    pub(crate) fn new(future: std::pin::Pin<&'a mut F>, slot: BackendSocketSlot) -> Self {
        Self { future, slot }
    }
}

impl<F> std::future::Future for ReqwestBackendSocketScope<'_, F>
where
    F: std::future::Future,
{
    type Output = F::Output;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        // `Pin<&mut F>` and `Arc` are both `Unpin`, so this projection is a
        // plain reborrow.
        let this = &mut *self;
        let slot = Arc::clone(&this.slot);
        REQWEST_BACKEND_SOCKET.sync_scope(slot, || this.future.as_mut().poll(cx))
    }
}

/// Publish a newly dialed backend socket into the slot the current dispatch
/// armed, duplicating the descriptor first.
///
/// A no-op outside an armed dispatch (warmup dials, admin-side clients, a
/// request with no upload pump) and for a slot that is already filled.
#[cfg(unix)]
pub(crate) fn publish_reqwest_backend_socket(fd: std::os::fd::RawFd) {
    diagnostics::bump(&diagnostics::ESTABLISHED_REPORTS);
    let published = REQWEST_BACKEND_SOCKET.try_with(|slot| {
        if slot.get().is_some() {
            diagnostics::bump(&diagnostics::SLOT_ALREADY_FILLED);
            return;
        }
        match BackendSocketHandle::duplicate_from_raw_fd(fd) {
            Some(handle) => {
                let _ = slot.set(handle);
                diagnostics::bump(&diagnostics::SOCKET_PUBLISHED);
            }
            None => diagnostics::bump(&diagnostics::SOCKET_DUP_FAILED),
        }
    });
    if published.is_err() {
        diagnostics::bump(&diagnostics::ESTABLISHED_OUT_OF_SCOPE);
    }
}

/// Debug-build counters for every link of the bundled-client socket handoff
/// and the post-EOS drain judgment (issue #4411), and for which task ended up
/// driving each upload pump (issue #5505).
///
/// Compiled to no-ops in release builds. Read through
/// `_test_support::post_eos_drain_diagnostics`, so an in-process acceptance
/// test that misses the drain bound can say WHICH link never happened instead
/// of only reporting the elapsed time — and a pump test can prove that an
/// ordinary upload was never handed to a task of its own.
///
/// Pump-driver counters: `PUMP_DETACHED_AT_INSTALL` is a pump spawned at
/// install because it carries an authorization lifetime;
/// `PUMP_DETACHED_LIVE` is an inline pump handed to a task because its
/// dispatcher stopped polling it before it resolved. An inline pump that
/// reached its terminal under the race bumps nothing.
///
/// `#[allow(dead_code)]`: the snapshot side is reached only through
/// `_test_support`, and the binary target recompiles this module without the
/// test crates that call it.
#[allow(dead_code)]
pub(crate) mod diagnostics {
    #[cfg(debug_assertions)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(debug_assertions)]
    pub(crate) struct Counter {
        pub(crate) name: &'static str,
        value: AtomicU64,
    }

    #[cfg(not(debug_assertions))]
    pub(crate) struct Counter;

    #[cfg(debug_assertions)]
    macro_rules! counters {
        ($($name:ident),* $(,)?) => {
            $(pub(crate) static $name: Counter = Counter {
                name: stringify!($name),
                value: AtomicU64::new(0),
            };)*
            static ALL: &[&Counter] = &[$(&$name),*];
        };
    }

    #[cfg(not(debug_assertions))]
    macro_rules! counters {
        ($($name:ident),* $(,)?) => {
            $(pub(crate) static $name: Counter = Counter;)*
        };
    }

    counters!(
        ESTABLISHED_REPORTS,
        ESTABLISHED_OUT_OF_SCOPE,
        SLOT_ALREADY_FILLED,
        SOCKET_PUBLISHED,
        SOCKET_DUP_FAILED,
        POST_EOS_NOT_COMPLETED,
        POST_EOS_UNARMED,
        POST_EOS_NO_SOCKET,
        POST_EOS_WATCHED,
        POST_EOS_CANCELLED,
        POST_EOS_NOT_STALLED,
        POST_EOS_STALLED,
        PUMP_DETACHED_AT_INSTALL,
        PUMP_DETACHED_LIVE,
    );

    #[inline]
    pub(crate) fn bump(counter: &Counter) {
        #[cfg(debug_assertions)]
        counter.value.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(debug_assertions))]
        let _ = counter;
    }

    /// Every counter's current value, in declaration order. Empty in release
    /// builds.
    pub(crate) fn snapshot() -> Vec<(&'static str, u64)> {
        #[cfg(debug_assertions)]
        {
            ALL.iter()
                .map(|counter| (counter.name, counter.value.load(Ordering::Relaxed)))
                .collect()
        }
        #[cfg(not(debug_assertions))]
        {
            Vec::new()
        }
    }
}
