//! Shared pre-authentication connection admission for listener accept loops.
//!
//! Several Ferrum listeners hand every accepted TCP socket to an unbounded
//! `tokio::spawn` that then performs a TLS handshake and/or reads request
//! headers. Until that work completes the peer is unauthenticated, so the only
//! ceiling on concurrent sockets, TLS state machines, and tasks is the process
//! file-descriptor limit. A handshake *timeout* does not bound concurrency: a
//! client that opens connections faster than the timeout retires them grows
//! descriptor, memory, and scheduler usage linearly.
//!
//! [`ConnLimiter`] is the one admission primitive those loops share. It is
//! acquired **before** the per-connection task is spawned and enforces two
//! independent caps:
//!
//! * a **global** slot pool (`max_connections`), and
//! * a **per-source-IP** share (`max_connections_per_ip`) so a single host
//!   cannot consume the global budget.
//!
//! Acquisition is non-blocking ([`ConnLimiter::try_acquire`] never waits), so a
//! saturated limiter never stalls the accept loop; the caller drops the socket
//! immediately (TCP FIN/RST). At the pre-TLS/pre-HTTP point there is no
//! negotiated protocol on which to return a clean 503, so dropping is the
//! correct fail-closed behaviour.
//!
//! # Permit lifetime
//!
//! The returned [`ConnPermit`] is an RAII guard: it releases the global slot and
//! the per-IP slot exactly once, on drop, from every exit path (handshake
//! success, handshake failure, timeout, task cancellation, listener shutdown).
//! Callers decide how long to hold it:
//!
//! * the admin listeners move it into the spawned connection task, so it covers
//!   the handshake **and** the served HTTP connection;
//! * the CP gRPC listener stores it *inside the connection IO object* handed to
//!   tonic, so one permit likewise covers the handshake and the completed
//!   HTTP/2 session — see `modes::control_plane`.
//!
//! Holding a single permit for the whole connection lifetime is deliberate: a
//! permit released at the end of the handshake would leave completed-but-idle
//! sessions unbounded, which is the same exhaustion primitive one layer later.
//!
//! # Cardinality and cleanup
//!
//! `per_ip_active` only holds entries for IPs with at least one *live* permit;
//! the count is decremented and the entry evicted under the same shard lock on
//! release. Its size is therefore bounded by the number of admitted
//! connections — i.e. by `max_connections` when the global cap is enabled — so
//! a hostile client cycling source addresses cannot grow the map. The
//! check-and-increment runs under the DashMap shard lock so two concurrent
//! accepts for one IP cannot both slip past the cap.
//!
//! [`ConnLimiter::new`] is intentionally **not** wired through
//! `pool_shard_amount`: the admin and CP gRPC listeners are low-rate
//! management/control-plane surfaces, not a proxy hot path, so their per-IP map
//! uses DashMap's default sharding (matching `health_check` /
//! `circuit_breaker`). Data-plane accept loops build the same limiter through
//! [`ConnLimiter::with_per_ip_shard_amount`] instead, which sizes the per-IP
//! map with [`crate::util::sharding::pool_shard_amount`] as every other
//! hot-path `DashMap` in the gateway does.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Largest accepted global cap. Beyond this `Semaphore::new` would panic, so
/// configuration validators reject an out-of-range value instead of letting
/// [`ConnLimiter::new`] silently clamp it.
pub const MAX_CONN_LIMIT: usize = Semaphore::MAX_PERMITS;

/// Why the limiter refused a connection. The string form is a bounded,
/// non-attacker-controllable metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnRejectReason {
    /// The global concurrent-connection cap was reached.
    MaxConnections,
    /// The per-source-IP cap was reached.
    MaxConnectionsPerIp,
}

impl ConnRejectReason {
    /// Stable Prometheus / log label for this rejection reason.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::MaxConnections => "max_connections",
            Self::MaxConnectionsPerIp => "max_connections_per_ip",
        }
    }
}

/// Point-in-time view of the limiter, used for metrics and diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct ConnLimiterSnapshot {
    /// Configured global cap (0 = unlimited).
    pub max_connections: usize,
    /// Configured per-IP cap (0 = unlimited).
    pub max_connections_per_ip: usize,
    /// Currently held permits (connections in flight).
    pub active_connections: u64,
    /// Rejections attributed to the global cap.
    pub rejected_max_connections: u64,
    /// Rejections attributed to the per-IP cap.
    pub rejected_max_connections_per_ip: u64,
}

impl ConnLimiterSnapshot {
    /// Total rejections across both caps ("limit hits"). `#[allow(dead_code)]`
    /// because the binary target compiles this module tree separately from the
    /// library and only the external test crates call it.
    #[allow(dead_code)]
    pub fn rejected_total(&self) -> u64 {
        self.rejected_max_connections
            .saturating_add(self.rejected_max_connections_per_ip)
    }
}

/// Bounds the number of concurrent connections on one listener surface.
///
/// One instance is created per gateway surface and shared (via `Arc`) across
/// every listener that surface starts — e.g. admin plaintext **and** admin
/// HTTPS, or the CP gRPC listener across every TLS certificate reload
/// generation — so the cap applies to the surface as a whole rather than per
/// listener or per certificate generation.
#[derive(Debug)]
pub struct ConnLimiter {
    /// Global slot pool. `None` when `max_connections == 0` (cap disabled).
    semaphore: Option<Arc<Semaphore>>,
    max_connections: usize,
    /// Per-IP cap; `0` disables per-IP tracking entirely.
    max_connections_per_ip: usize,
    /// Live per-IP connection counts. Only populated when the per-IP cap is on.
    per_ip_active: DashMap<IpAddr, u32>,
    /// In-flight connections (gauge).
    active: AtomicU64,
    rejected_max_connections: AtomicU64,
    rejected_max_connections_per_ip: AtomicU64,
}

impl ConnLimiter {
    /// Build a limiter from the resolved env config values.
    ///
    /// `max_connections == 0` disables the global cap; `max_connections_per_ip
    /// == 0` disables the per-IP cap. With both zero the limiter only tracks the
    /// `active` gauge and never rejects.
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self::with_per_ip_map(max_connections, max_connections_per_ip, DashMap::new())
    }

    /// Shared body of both constructors: everything except the per-IP map,
    /// whose sharding is the one thing the two differ on.
    fn with_per_ip_map(
        max_connections: usize,
        max_connections_per_ip: usize,
        per_ip_active: DashMap<IpAddr, u32>,
    ) -> Self {
        let semaphore = if max_connections > 0 {
            // Clamp to the tokio semaphore ceiling so an absurd operator value
            // can't panic `Semaphore::new`.
            let permits = max_connections.min(Semaphore::MAX_PERMITS);
            Some(Arc::new(Semaphore::new(permits)))
        } else {
            None
        };
        Self {
            semaphore,
            max_connections,
            max_connections_per_ip,
            per_ip_active,
            active: AtomicU64::new(0),
            rejected_max_connections: AtomicU64::new(0),
            rejected_max_connections_per_ip: AtomicU64::new(0),
        }
    }

    /// Build a limiter whose per-IP map is sharded for a **data-plane** accept
    /// loop (issue #4626).
    ///
    /// Identical to [`ConnLimiter::new`] except that the per-IP `DashMap` is
    /// sized through [`crate::util::sharding::pool_shard_amount`], which every
    /// hot-path map in the gateway goes through: the NodeWaypoint transparent
    /// inbound capture listener fronts ordinary application traffic for every
    /// enrolled pod on the node, so its accept path sees real data-plane
    /// concurrency rather than the handful of management connections the admin
    /// and CP gRPC surfaces see.
    ///
    /// `shard_amount_override` is the operator's `FERRUM_POOL_SHARD_AMOUNT`
    /// (`0` = auto-derive from the host topology).
    pub fn with_per_ip_shard_amount(
        max_connections: usize,
        max_connections_per_ip: usize,
        shard_amount_override: usize,
    ) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(shard_amount_override);
        Self::with_per_ip_map(
            max_connections,
            max_connections_per_ip,
            DashMap::with_capacity_and_shard_amount(0, shards),
        )
    }

    /// Convenience constructor for an uncapped limiter. Used by the external
    /// test crates; `#[allow(dead_code)]` because the binary target compiles
    /// the module tree separately (alongside the library) and never calls it.
    #[allow(dead_code)]
    pub fn unlimited() -> Arc<Self> {
        Arc::new(Self::new(0, 0))
    }

    /// Try to admit one connection from `remote_ip`.
    ///
    /// Never blocks. On success returns a permit that must be held for as long
    /// as the connection consumes resources; dropping it releases the global +
    /// per-IP slots. On failure returns the reason and records the rejection
    /// counter — the caller should drop the socket without allocating a task.
    pub fn try_acquire(
        self: &Arc<Self>,
        remote_ip: IpAddr,
    ) -> Result<ConnPermit, ConnRejectReason> {
        // 1. Global cap first. Acquire the slot up front so a per-IP rejection
        //    releases it (the permit drops on the early return).
        let global = match self.semaphore {
            Some(ref sem) => match sem.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    self.rejected_max_connections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(ConnRejectReason::MaxConnections);
                }
            },
            None => None,
        };

        // 2. Per-IP cap. Check-and-increment under the DashMap shard lock so
        //    concurrent accepts for the same IP cannot both slip past the cap.
        let per_ip_tracked = if self.max_connections_per_ip > 0 {
            match self.per_ip_active.entry(remote_ip) {
                Entry::Occupied(mut occ) => {
                    if (*occ.get() as usize) >= self.max_connections_per_ip {
                        // `global` drops here, releasing the global slot.
                        self.rejected_max_connections_per_ip
                            .fetch_add(1, Ordering::Relaxed);
                        return Err(ConnRejectReason::MaxConnectionsPerIp);
                    }
                    *occ.get_mut() += 1;
                }
                Entry::Vacant(vac) => {
                    // First connection for this IP; the per-IP cap is >= 1 when
                    // enabled, so the first one always fits.
                    vac.insert(1);
                }
            }
            true
        } else {
            false
        };

        self.active.fetch_add(1, Ordering::Relaxed);
        Ok(ConnPermit {
            limiter: Arc::clone(self),
            remote_ip,
            per_ip_tracked,
            _global: global,
        })
    }

    /// Number of distinct source IPs currently tracked. Bounded by the number
    /// of live permits (see the module docs); exposed for diagnostics and
    /// regression coverage, never as a metric label. `#[allow(dead_code)]` for
    /// the same binary-target reason as [`ConnLimiter::unlimited`].
    #[allow(dead_code)]
    pub fn tracked_source_ips(&self) -> usize {
        self.per_ip_active.len()
    }

    /// Snapshot the limiter for metrics rendering.
    pub fn snapshot(&self) -> ConnLimiterSnapshot {
        let rejected_max_connections = self.rejected_max_connections.load(Ordering::Relaxed);
        let rejected_max_connections_per_ip =
            self.rejected_max_connections_per_ip.load(Ordering::Relaxed);
        ConnLimiterSnapshot {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            active_connections: self.active.load(Ordering::Relaxed),
            rejected_max_connections,
            rejected_max_connections_per_ip,
        }
    }

    /// Release accounting for a dropped permit. Internal to [`ConnPermit`].
    fn release(&self, remote_ip: IpAddr, per_ip_tracked: bool) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if per_ip_tracked {
            // Decrement under the shard lock and evict at zero so the map does
            // not grow unbounded with one entry per IP ever seen.
            if let Entry::Occupied(mut occ) = self.per_ip_active.entry(remote_ip) {
                let count = occ.get_mut();
                *count = count.saturating_sub(1);
                if *count == 0 {
                    occ.remove();
                }
            }
        }
    }
}

/// RAII guard representing one admitted connection. Releases the global +
/// per-IP slots exactly once on drop.
#[derive(Debug)]
pub struct ConnPermit {
    limiter: Arc<ConnLimiter>,
    remote_ip: IpAddr,
    per_ip_tracked: bool,
    /// Global semaphore slot; released when this field drops. `None` when the
    /// global cap is disabled.
    _global: Option<OwnedSemaphorePermit>,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.limiter.release(self.remote_ip, self.per_ip_tracked);
    }
}
