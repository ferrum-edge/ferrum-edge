//! Cancellation and admission control for injected fault delays.
//!
//! Fault delays are the only place in the gateway where a *configured* policy
//! deliberately parks a live request or connection on a timer. Every other
//! long wait on the request path is bounded by a peer-driven transport event.
//! A bare `tokio::time::sleep` therefore turns an abandoned client into
//! server-side retention: the sleeping task keeps its overload guard, its
//! accepted socket or QUIC stream, its plugin snapshot, and its context alive
//! for the full configured duration even though nobody is waiting for the
//! answer. Repeating that cheaply from the client side is the amplification
//! this module exists to remove.
//!
//! Three independent bounds apply, in order:
//!
//! 1. **Ceiling** — the configuration boundary already rejects durations above
//!    [`MAX_FAULT_DELAY_MS`]. [`run_fault_delay_in`] re-clamps defensively so a
//!    future caller that skips validation still cannot park work for an hour.
//! 2. **Admission** — a process-wide budget of concurrently delayed units of
//!    work ([`FaultDelayAdmission`]). The budget is shared by every plugin
//!    instance in the process, so aggregate exposure is bounded even when many
//!    proxies each attach their own `fault_injection` instance. Exhaustion is
//!    fail-closed: the delay is *skipped*, never queued and never retained.
//!    A delayed unit may be an HTTP request, a TCP session admission, or a
//!    UDP/DTLS client→backend datagram parked on the isolated session worker
//!    (never the shared listener recv loop).
//! 3. **Cancellation** — the timer races a peer-gone signal and a gateway
//!    shutdown token. Whichever fires first ends the wait, so the caller can
//!    release its guards immediately through its own protocol-correct cleanup
//!    path.
//!
//! ## Peer-gone signals
//!
//! This module never owns a socket or a stream and never reads application
//! bytes. Callers pass a future that resolves when *their* transport says the
//! peer is gone, so ownership of request bytes stays where it already is:
//!
//! - TCP `on_stream_connect` — the stream proxy selects the hook against a
//!   read-half-preserving socket-error watch (`wait_for_tcp_peer_reset`). A
//!   half-close (FIN) is deliberately *not* cancellation: a request/response
//!   client may legitimately finish its request and wait for the answer, and
//!   queued application bytes must survive.
//! - UDP/DTLS `on_udp_datagram` — the per-session hook-ingress worker (and the
//!   isolated first-datagram / DTLS accept setup task) select the hook against
//!   session stop. Teardown drops the delay future, releasing the admission
//!   permit without forwarding. No application bytes are read here.
//! - HTTP/3 `before_proxy` — [`crate::plugins::PeerConnectionSignal`] carries a
//!   QUIC connection-close watch. Connection close is observable without
//!   polling the request stream, so no detached watcher competes for the
//!   request body. Per-stream RESET without connection close is not observable
//!   on the public `h3` API; that residual is covered by the ceiling and the
//!   admission budget rather than by a vendored patch.
//! - HTTP/1.1 and HTTP/2 — no signal is supplied, so behavior is unchanged
//!   apart from shutdown cancellation and the admission budget.
//!
//! ## Hot-path properties
//!
//! Nothing here runs unless a fault delay actually triggered. Admission is one
//! relaxed load plus one CAS; release is one relaxed decrement. There are no
//! locks, no allocations on the admitted path beyond the caller's optional
//! boxed peer future, and no formatting.

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::fault_roll::MAX_FAULT_DELAY_MS;

/// Default process-wide ceiling on concurrently delayed requests/connections.
///
/// Deliberately small. Fault injection is a chaos-engineering tool, not a
/// throughput feature: a few hundred simultaneously parked units of work is
/// far more than any real experiment needs and far less than what a remote
/// client would need to exhaust descriptors or memory.
pub const DEFAULT_MAX_CONCURRENT_FAULT_DELAYS: usize = 256;

/// Boxed peer-gone future accepted by [`run_fault_delay_in`].
pub type PeerGoneFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Why an injected fault delay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDelayOutcome {
    /// The configured duration elapsed.
    Completed,
    /// The client transport reported that the peer is gone.
    CancelledByPeer,
    /// The gateway entered shutdown drain.
    CancelledByShutdown,
    /// The process-wide delayed-work budget was exhausted; no wait happened.
    AdmissionExhausted,
}

impl FaultDelayOutcome {
    /// Whether the full configured delay actually elapsed.
    pub fn completed(self) -> bool {
        matches!(self, FaultDelayOutcome::Completed)
    }

    /// Stable, non-secret metadata label for transaction logs.
    pub fn metadata_label(self) -> &'static str {
        match self {
            FaultDelayOutcome::Completed => "completed",
            FaultDelayOutcome::CancelledByPeer => "peer_gone",
            FaultDelayOutcome::CancelledByShutdown => "shutdown",
            FaultDelayOutcome::AdmissionExhausted => "admission_exhausted",
        }
    }
}

/// Bounded budget of concurrently delayed units of work.
///
/// One process-wide instance ([`FAULT_DELAY_ADMISSION`]) backs production so
/// the bound covers aggregate exposure across every `fault_injection` instance
/// and every `mesh_route_dispatch` route-local fault in the process. Tests
/// construct their own instance rather than mutating global state.
#[derive(Debug)]
pub struct FaultDelayAdmission {
    capacity: AtomicUsize,
    in_flight: AtomicUsize,
}

impl FaultDelayAdmission {
    /// Construct a budget with a fixed initial capacity.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity: AtomicUsize::new(capacity),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Replace the capacity. Called once at startup from `EnvConfig`.
    ///
    /// A capacity of `0` disables injected delays entirely — deliberately
    /// *not* the "0 means unlimited" convention used by optional caps such as
    /// `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP`. This bound exists to remove a
    /// retention amplifier, so its degenerate value must be the safe one.
    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Release);
    }

    /// Current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    /// Units of work currently parked on an injected delay.
    #[allow(dead_code)] // Used by external tests; dead in the binary target.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Reserve one slot, or return `None` when the budget is exhausted.
    ///
    /// Reservation happens *before* the timer starts, so an admitted delay can
    /// never exceed the budget, and the slot is released the moment the permit
    /// drops — including on cancellation, panic unwind, and task abort.
    pub fn try_admit(&self) -> Option<FaultDelayPermit<'_>> {
        let capacity = self.capacity();
        let mut observed = self.in_flight.load(Ordering::Acquire);
        loop {
            if observed >= capacity {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(FaultDelayPermit { admission: self }),
                Err(current) => observed = current,
            }
        }
    }
}

/// RAII reservation released on drop.
#[derive(Debug)]
pub struct FaultDelayPermit<'a> {
    admission: &'a FaultDelayAdmission,
}

impl Drop for FaultDelayPermit<'_> {
    fn drop(&mut self) {
        self.admission.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Process-wide delayed-work budget used by production fault hooks.
pub static FAULT_DELAY_ADMISSION: FaultDelayAdmission =
    FaultDelayAdmission::new(DEFAULT_MAX_CONCURRENT_FAULT_DELAYS);

static FAULT_DELAY_SHUTDOWN: LazyLock<CancellationToken> = LazyLock::new(CancellationToken::new);
static FAULT_DELAY_RUNTIME_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Process-wide token cancelled when the gateway begins its shutdown drain.
///
/// Cancelled by [`crate::overload::begin_shutdown_drain`], which every serving
/// mode calls once its accept loops have exited. Plain
/// [`crate::overload::begin_drain`] deliberately does *not* cancel it: that
/// function is exercised by ordinary drain-flag tests, and cancelling a
/// process-global token from a test would silently disarm every later fault
/// delay in the same test binary.
pub fn fault_delay_shutdown() -> &'static CancellationToken {
    &FAULT_DELAY_SHUTDOWN
}

/// Apply the operator-configured delayed-work budget. Called once at startup.
pub fn init_fault_delay_admission(max_concurrent_fault_delays: usize) {
    FAULT_DELAY_ADMISSION.set_capacity(max_concurrent_fault_delays);
    // Published only after the configured capacity is visible. Serving-mode
    // shutdown may then cancel the one-shot process token. Unit tests that
    // exercise mode drain helpers without starting a gateway must not poison
    // unrelated plugin tests in the same process.
    FAULT_DELAY_RUNTIME_INITIALIZED.store(true, Ordering::Release);
}

/// Cancel production fault delays when a fully initialized gateway drains.
///
/// `begin_shutdown_drain` is also exercised by unit tests that never run
/// [`init_fault_delay_admission`]. Gating cancellation on runtime
/// initialization keeps those tests from permanently cancelling the
/// process-wide one-shot token while preserving the production startup/shutdown
/// contract: initialization occurs before any listener accepts traffic.
pub fn cancel_fault_delays_for_shutdown() {
    if FAULT_DELAY_RUNTIME_INITIALIZED.load(Ordering::Acquire) {
        fault_delay_shutdown().cancel();
    }
}

/// Run an injected fault delay against the process-wide budget and shutdown
/// token. See [`run_fault_delay_in`] for the semantics.
pub async fn run_fault_delay(
    duration_ms: u64,
    peer_gone: Option<PeerGoneFuture<'_>>,
) -> FaultDelayOutcome {
    run_fault_delay_in(
        &FAULT_DELAY_ADMISSION,
        fault_delay_shutdown(),
        duration_ms,
        peer_gone,
    )
    .await
}

/// Run an injected fault delay against an explicit budget and shutdown token.
///
/// Returns as soon as any of the following happens, in priority order when
/// several are ready in the same poll:
///
/// 1. shutdown was requested,
/// 2. the peer-gone future resolved,
/// 3. the (clamped) configured duration elapsed.
///
/// Admission is checked first; an exhausted budget returns
/// [`FaultDelayOutcome::AdmissionExhausted`] without waiting at all.
pub async fn run_fault_delay_in(
    admission: &FaultDelayAdmission,
    shutdown: &CancellationToken,
    duration_ms: u64,
    peer_gone: Option<PeerGoneFuture<'_>>,
) -> FaultDelayOutcome {
    let Some(_permit) = admission.try_admit() else {
        // Do not log here: once the budget is saturated this is an
        // attacker-controlled path. The caller records the closed-enum outcome
        // in request metadata without creating an additional flood surface.
        return FaultDelayOutcome::AdmissionExhausted;
    };

    // Defense in depth: every configuration path already rejects durations
    // above the ceiling, but a delay is retained work and must never depend on
    // a validator that a future call site might bypass.
    let bounded_ms = duration_ms.min(MAX_FAULT_DELAY_MS);
    let sleep = tokio::time::sleep(Duration::from_millis(bounded_ms));

    match peer_gone {
        Some(peer_gone) => {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => FaultDelayOutcome::CancelledByShutdown,
                () = peer_gone => FaultDelayOutcome::CancelledByPeer,
                () = sleep => FaultDelayOutcome::Completed,
            }
        }
        None => {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => FaultDelayOutcome::CancelledByShutdown,
                () = sleep => FaultDelayOutcome::Completed,
            }
        }
    }
}
