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
//! - its listener task has been joined but the socket itself outlives the
//!   join — Quinn shares it between endpoint state that its separately spawned
//!   driver drops later and every live connection, and UDP/DTLS session tasks
//!   hold clones of the listener socket until they observe the shutdown.
//!
//! Either way the bind fails with `EADDRINUSE` for a port that is about to be
//! free, and without help would stay unbound until that manager's slow retry
//! tick.
//!
//! This ledger lets the acquiring side tell that transient in-process collision
//! apart from a port genuinely owned by something else. Each managed datagram
//! listener's claim ([`UdpPortHold`]) is armed as soon as its socket is bound
//! and travels *with the socket*: it is owned by the socket object that every
//! user of the socket shares (Quinn's abstract socket, the plain-UDP frontend
//! socket, the DTLS server and its session drivers), so it is released when
//! the last reference drops and the socket closes, not when the listener task
//! returns. A bind that fails with `EADDRINUSE` on a port
//! [`UdpPortHandoff::note_bind_collision`] classifies as a handoff is retried
//! within a short, bounded, pass-wide budget ([`UDP_PORT_HANDOFF_BUDGET`]). A
//! port the ledger knows nothing about fails immediately, exactly as before,
//! and a socket still held when the budget runs out is reported as the
//! ordinary bind failure. Two sockets never share a port: nothing here sets
//! `SO_REUSEADDR` / `SO_REUSEPORT`, it only decides whether one more exclusive
//! bind attempt is worth making.
//!
//! As a fallback for a release slower than the budget, every release by one
//! owner is appended to that owner's release log
//! ([`UdpPortHandoff::subscribe_releases`]), which the *other* manager's
//! supervisor follows. It reconciles only when a released port is one of its
//! own outstanding bind failures, so an outstanding failure is retried when
//! its port is actually released rather than on the next 30-second tick,
//! while releases of unrelated ports cost nothing. Each manager subscribes
//! only to the other owner's releases, so a listener that keeps failing can
//! never wake its own manager into a reconcile loop. A reconcile the
//! supervisor did not run publishes its failures only when it ends, after the
//! supervisor may already have judged a release against the older failures,
//! so such a pass marks the log when it starts
//! ([`UdpPortHandoff::release_mark`]) and, when it publishes, wakes the
//! supervisor itself if a port it failed was released since
//! ([`UdpPortHandoff::released_since`]).
//!
//! The stream listener manager's pass only probes a UDP/DTLS port: the
//! listener task it spawns binds the real socket afterwards, and a config
//! change can hand the port to a Gateway QUIC half in that gap. That bind
//! fails after the pass has published its failures and checked the release
//! log, so the task rides out a handoff collision itself
//! ([`UdpPortHold::bind`]) with its own budget, started by its own first
//! collision, instead of reporting a failure nothing would retry before the
//! 30-second tick (issue #5851). The wait runs in the listener task, never in
//! a reconcile pass.
//!
//! Not on any hot path: the ledger is touched only when a datagram listener
//! binds or closes its socket and when a bind has already failed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::debug;

/// How long one reconcile pass may spend, in total, retrying `EADDRINUSE` on
/// ports another in-process datagram listener is handing over. Shared by every
/// such port in the pass and started by the first such collision, so unrelated
/// listeners queued behind it are delayed by at most this much on its account;
/// a release slower than this falls back to the ordinary bind failure plus the
/// release wakeup described in the module docs. The Gateway listener manager
/// also gives QUIC halves it retired in the same pass a separate budget of the
/// same length, counted from the start of the pass, so one Gateway pass can
/// wait up to about twice this in total.
pub const UDP_PORT_HANDOFF_BUDGET: Duration = Duration::from_secs(2);

/// First pause between bind attempts while a handoff is pending. Doubles up to
/// [`UDP_PORT_HANDOFF_MAX_BACKOFF`].
pub const UDP_PORT_HANDOFF_INITIAL_BACKOFF: Duration = Duration::from_millis(5);

/// Longest pause between bind attempts while a handoff is pending.
pub const UDP_PORT_HANDOFF_MAX_BACKOFF: Duration = Duration::from_millis(100);

/// How long after its last in-process holder released a port a bind collision
/// on it is still treated as a pending handoff.
///
/// A claim is released only when its socket closes, so this no longer has to
/// cover sockets outliving their listener task. It is a small cushion for the
/// two orderings that remain: the acquiring side's bind can fail an instant
/// before the release and consult the ledger an instant after it (a scheduler
/// turn, or a stalled worker thread, apart), and a socket shared with session
/// tasks can record its release while another clone of the socket is being
/// dropped on another thread. A genuinely foreign owner that grabs the port
/// inside this window only costs one bounded budget of retries before it is
/// reported.
pub const UDP_PORT_RECENT_RELEASE_WINDOW: Duration = Duration::from_secs(1);

/// Releases each owner's log keeps for its subscribers. A subscriber that
/// falls further behind than this treats the gap as matching every port.
const RELEASE_LOG_CAPACITY: usize = 64;

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

/// One owner's recent releases, published to the other manager's supervisor.
#[derive(Default)]
struct ReleaseLog {
    /// Sequence number of the latest release; `0` before the first.
    seq: u64,
    /// `(seq, port)` of the latest releases, oldest first, at most
    /// [`RELEASE_LOG_CAPACITY`] of them.
    recent: VecDeque<(u64, u16)>,
}

/// The shared ledger. One instance per process, owned by the stream listener
/// manager and reached by the Gateway listener manager through `ProxyState`.
pub struct UdpPortHandoff {
    ports: Mutex<HashMap<u16, PortEntry>>,
    gateway_quic_released: watch::Sender<ReleaseLog>,
    stream_datagram_released: watch::Sender<ReleaseLog>,
    handoff_retries: AtomicU64,
}

impl Default for UdpPortHandoff {
    fn default() -> Self {
        Self {
            ports: Mutex::new(HashMap::new()),
            gateway_quic_released: watch::channel(ReleaseLog::default()).0,
            stream_datagram_released: watch::channel(ReleaseLog::default()).0,
            handoff_retries: AtomicU64::new(0),
        }
    }
}

impl UdpPortHandoff {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A claim on `port` for one listener's socket. It counts toward
    /// [`Self::note_bind_collision`] only once [`UdpPortHold::arm`] is called
    /// right after the bind succeeds, so a listener whose bind fails never
    /// marks the port as recently released.
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

    /// Record that a bind on `port` just failed with `EADDRINUSE`, and return
    /// whether that collision is plausibly an in-process handoff: some managed
    /// datagram listener's socket holds the port now, or closed within
    /// [`UDP_PORT_RECENT_RELEASE_WINDOW`].
    ///
    /// Not a pure query: a `true` answer is a collision about to be retried
    /// and increments [`Self::handoff_retries`], so call it once per failed
    /// attempt and only after one.
    pub fn note_bind_collision(&self, port: u16) -> bool {
        let pending = {
            let ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
            ports.get(&port).is_some_and(|entry| {
                entry.holds > 0
                    || entry
                        .released_at
                        .is_some_and(|at| at.elapsed() < UDP_PORT_RECENT_RELEASE_WINDOW)
            })
        };
        if pending {
            self.handoff_retries.fetch_add(1, Ordering::Relaxed);
        }
        pending
    }

    /// Bind a UDP socket on `addr` for a managed datagram listener, retrying
    /// `EADDRINUSE` while [`Self::note_bind_collision`] classifies it as an
    /// in-process handoff. Attempts back off from
    /// [`UDP_PORT_HANDOFF_INITIAL_BACKOFF`] to [`UDP_PORT_HANDOFF_MAX_BACKOFF`]
    /// until `deadline`, which the first collision sets to
    /// [`UDP_PORT_HANDOFF_BUDGET`] from then when it is still unset, so callers
    /// that share one `deadline` share one budget. Any other error, a port
    /// nothing in-process holds, and a socket still held at the deadline are
    /// returned unchanged. Eligibility is re-checked after each failed attempt,
    /// because the other manager may arm or release its hold meanwhile.
    pub async fn bind(
        &self,
        addr: std::net::SocketAddr,
        deadline: &mut Option<tokio::time::Instant>,
    ) -> std::io::Result<tokio::net::UdpSocket> {
        let mut backoff: Option<UdpPortHandoffBackoff> = None;
        loop {
            let error = match tokio::net::UdpSocket::bind(addr).await {
                Ok(socket) => return Ok(socket),
                Err(error) => error,
            };
            if error.kind() != std::io::ErrorKind::AddrInUse
                || !self.note_bind_collision(addr.port())
            {
                return Err(error);
            }
            let now = tokio::time::Instant::now();
            let deadline = *deadline.get_or_insert(now + UDP_PORT_HANDOFF_BUDGET);
            debug!(
                port = addr.port(),
                "UDP listener bind is waiting for another in-process listener to release the \
                 port: {error}"
            );
            let backoff = backoff.get_or_insert_with(|| UdpPortHandoffBackoff::new(deadline));
            if !backoff.wait().await {
                return Err(error);
            }
        }
    }

    /// How many bind collisions [`Self::note_bind_collision`] has classified as
    /// in-process handoffs since the ledger was created. Diagnostic only.
    pub fn handoff_retries(&self) -> u64 {
        self.handoff_retries.load(Ordering::Relaxed)
    }

    /// Follow the releases of holds owned by `owner`, starting after the
    /// latest one. Subscribe to the *other* owner's releases only (see the
    /// module docs).
    pub fn subscribe_releases(&self, owner: UdpPortOwner) -> UdpPortReleases {
        let rx = self.release_channel(owner).subscribe();
        let seen = rx.borrow().seq;
        UdpPortReleases { rx, seen }
    }

    /// Where `owner`'s release log stands now. A reconcile pass takes one when
    /// it starts and passes it to [`Self::released_since`] when it publishes
    /// its bind failures (see the module docs).
    pub fn release_mark(&self, owner: UdpPortOwner) -> UdpPortReleaseMark {
        let seq = self.release_channel(owner).borrow().seq;
        UdpPortReleaseMark { owner, seq }
    }

    /// The ports the mark's owner released after `mark` was taken.
    pub fn released_since(&self, mark: UdpPortReleaseMark) -> ReleasedUdpPorts {
        released_after(&self.release_channel(mark.owner).borrow(), mark.seq)
    }

    fn release_channel(&self, owner: UdpPortOwner) -> &watch::Sender<ReleaseLog> {
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
        // Publish only after the ledger records the release, so a reconcile the
        // other manager runs in response already sees the port as recently
        // released and gives a lingering socket its bounded retry budget.
        self.release_channel(owner).send_modify(|log| {
            log.seq = log.seq.wrapping_add(1);
            if log.recent.len() == RELEASE_LOG_CAPACITY {
                log.recent.pop_front();
            }
            log.recent.push_back((log.seq, port));
        });
    }
}

/// One subscriber's view of one owner's releases.
pub struct UdpPortReleases {
    rx: watch::Receiver<ReleaseLog>,
    /// Sequence number of the latest release already returned.
    seen: u64,
}

impl UdpPortReleases {
    /// Wait for the next release(s) and return the ports released since the
    /// previous call, or `None` once the ledger is gone. Cancel-safe: nothing
    /// is consumed until the wait completes.
    pub async fn recv(&mut self) -> Option<ReleasedUdpPorts> {
        self.rx.changed().await.ok()?;
        Some(self.take())
    }

    /// [`Self::recv`] without waiting: `None` when nothing was released since
    /// the previous call.
    pub fn try_recv(&mut self) -> Option<ReleasedUdpPorts> {
        self.rx.has_changed().ok()?.then(|| self.take())
    }

    fn take(&mut self) -> ReleasedUdpPorts {
        let log = self.rx.borrow_and_update();
        let released = released_after(&log, self.seen);
        self.seen = log.seq;
        released
    }
}

/// A point in one owner's release log; see [`UdpPortHandoff::release_mark`].
#[derive(Debug, Clone, Copy)]
pub struct UdpPortReleaseMark {
    owner: UdpPortOwner,
    seq: u64,
}

/// The releases in `log` after sequence number `seen`.
fn released_after(log: &ReleaseLog, seen: u64) -> ReleasedUdpPorts {
    // Sequence numbers only wrap after 2^64 releases, so plain comparison is
    // enough for a process lifetime.
    let gap = log
        .recent
        .front()
        .is_some_and(|&(seq, _)| seq > seen.wrapping_add(1));
    let ports = log
        .recent
        .iter()
        .filter(|&&(seq, _)| seq > seen)
        .map(|&(_, port)| port)
        .collect();
    ReleasedUdpPorts { ports, gap }
}

/// Ports one owner released since a subscriber last looked.
#[derive(Debug)]
pub struct ReleasedUdpPorts {
    ports: Vec<u16>,
    /// The subscriber fell behind the bounded log, so some released ports are
    /// unknown.
    gap: bool,
}

impl ReleasedUdpPorts {
    /// Whether any of `ports` (a subscriber's outstanding bind failures) may
    /// have been released. Always `true` for a non-empty `ports` when the
    /// subscriber missed releases, so a failure is never left waiting on a
    /// release it did not see.
    pub fn includes_any(&self, ports: impl IntoIterator<Item = u16>) -> bool {
        let mut ports = ports.into_iter();
        if self.gap {
            return ports.next().is_some();
        }
        ports.any(|port| self.ports.contains(&port))
    }

    /// The released ports the subscriber saw, oldest first.
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

/// One listener socket's claim on a UDP port in [`UdpPortHandoff`].
///
/// Owned by the socket object the listener shares with everything that can
/// keep the socket open, so the claim is released exactly when that socket
/// closes. Cloneable for owners whose socket users each hold their own clone
/// (the DTLS server and its session drivers); the claim is released when the
/// last clone drops.
#[derive(Clone)]
pub struct UdpPortHold {
    inner: Arc<HoldInner>,
}

impl UdpPortHold {
    /// Count this hold from now on. Call right after the bind succeeds.
    /// Idempotent.
    pub fn arm(&self) {
        if !self.inner.armed.swap(true, Ordering::AcqRel) {
            self.inner.ledger.arm(self.inner.port);
        }
    }

    /// Bind this hold's listener socket on `addr`, riding out an in-process
    /// handoff of the port with a budget of its own (issue #5851); see
    /// [`UdpPortHandoff::bind`]. For the listener task's own bind, which runs
    /// after its manager's reconcile pass probed the port and published its
    /// failures: a collision there would otherwise go unretried until the slow
    /// tick. Does not arm the hold.
    pub async fn bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        self.inner.ledger.bind(addr, &mut None).await
    }
}

impl std::fmt::Debug for UdpPortHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPortHold")
            .field("port", &self.inner.port)
            .field("owner", &self.inner.owner)
            .field("armed", &self.inner.armed.load(Ordering::Relaxed))
            .finish()
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
