//! In-process ledger of UDP ports held by Ferrum's own datagram listeners
//! (issue #5843).
//!
//! Two independent managers bind UDP sockets on operator-chosen ports: the
//! Gateway listener manager's HTTP/3 (QUIC) half of a TLS-class listener, and
//! the stream listener manager's UDP/DTLS stream proxies. A config change can
//! move one numeric UDP port from one to the other in either direction — a
//! UDP/DTLS stream claim added on a Gateway HTTPS port drains QUIC there, and
//! removing that claim brings QUIC back. Both managers reconcile the same
//! publication concurrently and neither waits for the other, so the acquiring
//! side's bind can run while the releasing side's socket is still open:
//!
//! - it has not been signalled yet (the other manager's pass has not reached
//!   that port), or
//! - its task has been joined but the socket itself outlives the join — Quinn
//!   keeps it in endpoint state its separately spawned driver drops later, and
//!   UDP stream reply tasks hold clones of the listener socket until they
//!   observe the shutdown signal.
//!
//! Either way the bind fails with `EADDRINUSE` for a port that is about to be
//! free, and without help would stay unbound until that manager's slow retry
//! tick.
//!
//! This ledger lets the acquiring side tell that transient in-process collision
//! apart from a port genuinely owned by something else. Each managed datagram
//! listener task owns a [`UdpPortHold`] for as long as it runs; a bind that
//! fails with `EADDRINUSE` on a port [`UdpPortHandoff::handoff_pending`]
//! reports is retried within a short, bounded, pass-wide budget
//! ([`UDP_PORT_HANDOFF_BUDGET`]). A port the ledger knows nothing about fails
//! immediately, exactly as before, and a socket still held when the budget
//! runs out is reported as the ordinary bind failure. Two sockets never share a
//! port: nothing here sets `SO_REUSEADDR` / `SO_REUSEPORT`, it only decides
//! whether one more exclusive bind attempt is worth making.
//!
//! As a fallback for a release slower than the budget, every release by one
//! owner bumps a per-owner watch channel ([`UdpPortHandoff::subscribe_releases`])
//! that the *other* manager's supervisor listens on, so an outstanding bind
//! failure is retried when the port is actually released rather than on the
//! next 30-second tick. Each manager subscribes only to the other owner's
//! releases, so a listener that keeps failing can never wake its own manager
//! into a reconcile loop.
//!
//! Not on any hot path: the ledger is touched only when a datagram listener
//! starts or stops and when a bind has already failed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// How long one reconcile pass may spend, in total, retrying `EADDRINUSE` on
/// ports another in-process datagram listener is handing over. Shared by every
/// such port in the pass so unrelated listeners queued behind it are delayed by
/// at most this much; a release slower than this falls back to the ordinary
/// bind failure plus the release wakeup described in the module docs.
pub const UDP_PORT_HANDOFF_BUDGET: Duration = Duration::from_secs(2);

/// First pause between bind attempts while a handoff is pending. Doubles up to
/// [`UDP_PORT_HANDOFF_MAX_BACKOFF`].
pub const UDP_PORT_HANDOFF_INITIAL_BACKOFF: Duration = Duration::from_millis(5);

/// Longest pause between bind attempts while a handoff is pending.
pub const UDP_PORT_HANDOFF_MAX_BACKOFF: Duration = Duration::from_millis(100);

/// How long after its last in-process holder released a port a bind collision
/// on it is still treated as a pending handoff. Covers the socket outliving
/// the joined listener task (Quinn's endpoint driver, UDP reply tasks, or a
/// QUIC drain that was cut short by an abort). A genuinely foreign owner that
/// grabs the port inside this window only costs one bounded budget of retries
/// before it is reported.
pub const UDP_PORT_RECENT_RELEASE_WINDOW: Duration = Duration::from_secs(10);

/// Which Ferrum listener family holds a UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPortOwner {
    /// The HTTP/3 (QUIC) half of a TLS-class Gateway API listener port.
    GatewayQuic,
    /// A UDP or DTLS stream proxy listener.
    StreamDatagram,
}

#[derive(Default)]
struct PortEntry {
    /// Armed holds currently alive for this port, across both owners.
    holds: usize,
    /// When the last armed hold was released, if none is alive now.
    released_at: Option<Instant>,
}

/// The shared ledger. One instance per process, owned by the stream listener
/// manager and reached by the Gateway listener manager through `ProxyState`.
pub struct UdpPortHandoff {
    ports: Mutex<HashMap<u16, PortEntry>>,
    gateway_quic_released: watch::Sender<u64>,
    stream_datagram_released: watch::Sender<u64>,
}

impl Default for UdpPortHandoff {
    fn default() -> Self {
        Self {
            ports: Mutex::new(HashMap::new()),
            gateway_quic_released: watch::channel(0).0,
            stream_datagram_released: watch::channel(0).0,
        }
    }
}

impl UdpPortHandoff {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A hold on `port` for one listener task. It counts toward
    /// [`Self::handoff_pending`] only once [`UdpPortHold::arm`] is called, so a
    /// task whose bind fails never marks the port as recently released.
    pub fn hold(self: &Arc<Self>, port: u16, owner: UdpPortOwner) -> UdpPortHold {
        UdpPortHold {
            inner: Arc::new(HoldInner {
                ledger: Arc::clone(self),
                port,
                owner,
                armed: AtomicBool::new(false),
            }),
        }
    }

    /// Whether a bind collision on `port` is plausibly an in-process handoff:
    /// some managed datagram listener holds the port now, or released it
    /// within [`UDP_PORT_RECENT_RELEASE_WINDOW`].
    pub fn handoff_pending(&self, port: u16) -> bool {
        let ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
        ports.get(&port).is_some_and(|entry| {
            entry.holds > 0
                || entry
                    .released_at
                    .is_some_and(|at| at.elapsed() < UDP_PORT_RECENT_RELEASE_WINDOW)
        })
    }

    /// A receiver that changes every time a hold owned by `owner` is released.
    /// Subscribe to the *other* owner's releases only (see the module docs).
    pub fn subscribe_releases(&self, owner: UdpPortOwner) -> watch::Receiver<u64> {
        self.release_channel(owner).subscribe()
    }

    fn release_channel(&self, owner: UdpPortOwner) -> &watch::Sender<u64> {
        match owner {
            UdpPortOwner::GatewayQuic => &self.gateway_quic_released,
            UdpPortOwner::StreamDatagram => &self.stream_datagram_released,
        }
    }

    fn arm(&self, port: u16) {
        let mut ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = ports.entry(port).or_default();
        entry.holds += 1;
        entry.released_at = None;
    }

    fn release(&self, port: u16, owner: UdpPortOwner) {
        {
            let mut ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if let Some(entry) = ports.get_mut(&port) {
                entry.holds = entry.holds.saturating_sub(1);
                if entry.holds == 0 {
                    entry.released_at = Some(now);
                }
            }
            // Keep the map bounded by the ports that can still matter.
            ports.retain(|_, entry| {
                entry.holds > 0
                    || entry
                        .released_at
                        .is_some_and(|at| now.duration_since(at) < UDP_PORT_RECENT_RELEASE_WINDOW)
            });
        }
        // Wake the other manager only after the ledger records the release, so
        // a reconcile it runs in response already sees the port as recently
        // released and gives a lingering socket its bounded retry budget.
        self.release_channel(owner)
            .send_modify(|releases| *releases = releases.wrapping_add(1));
    }
}

/// One listener task's claim on a UDP port in [`UdpPortHandoff`].
///
/// Cloneable so the manager can arm it after the task reports a successful
/// bind while the task itself owns the other clone. The claim is released when
/// the last clone drops — normally when the listener task finishes or is
/// aborted, since the task future owns a clone.
#[derive(Clone)]
pub struct UdpPortHold {
    inner: Arc<HoldInner>,
}

impl UdpPortHold {
    /// Count this hold from now on. Idempotent.
    pub fn arm(&self) {
        if !self.inner.armed.swap(true, Ordering::AcqRel) {
            self.inner.ledger.arm(self.inner.port);
        }
    }
}

struct HoldInner {
    ledger: Arc<UdpPortHandoff>,
    port: u16,
    owner: UdpPortOwner,
    armed: AtomicBool,
}

impl Drop for HoldInner {
    fn drop(&mut self) {
        // `arm` needs a live clone, so it cannot race this final drop.
        if self.armed.load(Ordering::Acquire) {
            self.ledger.release(self.port, self.owner);
        }
    }
}

/// Retry pacing for one acquiring bind while a handoff is pending, bounded by
/// a deadline shared across the whole reconcile pass.
pub struct UdpPortHandoffBackoff {
    deadline: tokio::time::Instant,
    backoff: Duration,
}

impl UdpPortHandoffBackoff {
    pub fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            backoff: UDP_PORT_HANDOFF_INITIAL_BACKOFF,
        }
    }

    /// Sleep before the next attempt and return `true`, or return `false`
    /// without sleeping when the next attempt would not start before the
    /// deadline.
    pub async fn wait(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        if now >= self.deadline || now + self.backoff >= self.deadline {
            return false;
        }
        tokio::time::sleep(self.backoff).await;
        self.backoff = (self.backoff * 2).min(UDP_PORT_HANDOFF_MAX_BACKOFF);
        true
    }
}
