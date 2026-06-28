//! Admin listener connection limiting.
//!
//! The proxy data-plane accept loop is bounded by `FERRUM_MAX_CONNECTIONS`
//! (a semaphore sized at config load) plus the overload manager's
//! `reject_new_connections` flag. The admin/management-plane accept loops
//! (`serve_admin_on_listener` / `serve_admin_on_listener_with_dynamic_tls`)
//! historically had **no** equivalent: every accepted TCP connection was
//! handed to an unbounded `tokio::spawn`, so the only ceiling on concurrent
//! admin connections (each costing a file descriptor + a task + a pending TLS
//! handshake / header-read buffer) was the OS file-descriptor limit.
//!
//! [`AdminConnLimiter`] closes that gap with a dedicated, management-plane
//! connection cap that is independent of the data-plane `FERRUM_MAX_CONNECTIONS`
//! knob, so operators can size proxy traffic and admin traffic separately.
//!
//! Enforcement happens in the accept loop **after** the CIDR allowlist check
//! and **before** the per-connection task is spawned (i.e. before the TLS
//! handshake or any HTTP header parsing). Over-limit connections are dropped
//! immediately (TCP RST) with zero task overhead, mirroring the data-plane
//! accept loop's behaviour — at the pre-TLS/pre-HTTP point there is no
//! negotiated protocol state on which to return a clean 503.
//!
//! The acquired [`AdminConnPermit`] is held for the connection's entire
//! lifetime (it is moved into the spawned task) and releases the global slot +
//! per-IP slot on drop, so the cap tracks the real concurrency driver.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Why the limiter refused an admin connection. The string form is a bounded,
/// non-attacker-controllable metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminConnRejectReason {
    /// The global `FERRUM_ADMIN_MAX_CONNECTIONS` cap was reached.
    MaxConnections,
    /// The per-source-IP `FERRUM_ADMIN_MAX_CONNECTIONS_PER_IP` cap was reached.
    MaxConnectionsPerIp,
}

impl AdminConnRejectReason {
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
pub struct AdminConnLimiterSnapshot {
    /// Configured global cap (0 = unlimited).
    pub max_connections: usize,
    /// Configured per-IP cap (0 = unlimited).
    pub max_connections_per_ip: usize,
    /// Currently held permits (admin connections in flight).
    pub active_connections: u64,
    /// Rejections attributed to the global cap.
    pub rejected_max_connections: u64,
    /// Rejections attributed to the per-IP cap.
    pub rejected_max_connections_per_ip: u64,
}

/// Bounds the number of concurrent admin-listener connections.
///
/// One instance is created per gateway and shared (via `Arc`) across every
/// admin listener a mode starts (e.g. plaintext HTTP **and** HTTPS), so the cap
/// applies to the management plane as a whole rather than per listener.
///
/// This is intentionally **not** wired through `pool_shard_amount`: the admin
/// listener is a low-rate management surface, not a proxy hot path, so the
/// per-IP map uses DashMap's default sharding (matching `health_check` /
/// `circuit_breaker`).
pub struct AdminConnLimiter {
    /// Global slot pool. `None` when `max_connections == 0` (cap disabled).
    semaphore: Option<Arc<Semaphore>>,
    max_connections: usize,
    /// Per-IP cap; `0` disables per-IP tracking entirely.
    max_connections_per_ip: usize,
    /// Live per-IP connection counts. Only populated when the per-IP cap is on.
    per_ip_active: DashMap<IpAddr, u32>,
    /// In-flight admin connections (gauge).
    active: AtomicU64,
    rejected_max_connections: AtomicU64,
    rejected_max_connections_per_ip: AtomicU64,
}

impl AdminConnLimiter {
    /// Build a limiter from the resolved env config values.
    ///
    /// `max_connections == 0` disables the global cap; `max_connections_per_ip
    /// == 0` disables the per-IP cap. With both zero the limiter only tracks the
    /// `active` gauge and never rejects.
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
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
            per_ip_active: DashMap::new(),
            active: AtomicU64::new(0),
            rejected_max_connections: AtomicU64::new(0),
            rejected_max_connections_per_ip: AtomicU64::new(0),
        }
    }

    /// Convenience constructor for an uncapped limiter. Used by the external
    /// test crates; `#[allow(dead_code)]` because the binary target compiles
    /// the module tree separately (alongside the library) and never calls it.
    #[allow(dead_code)]
    pub fn unlimited() -> Arc<Self> {
        Arc::new(Self::new(0, 0))
    }

    /// Try to admit one admin connection from `remote_ip`.
    ///
    /// On success returns a permit that must be held for the connection's
    /// lifetime; dropping it releases the global + per-IP slots. On failure
    /// returns the reason and records the rejection counter — the caller should
    /// drop the socket.
    pub fn try_acquire(
        self: &Arc<Self>,
        remote_ip: IpAddr,
    ) -> Result<AdminConnPermit, AdminConnRejectReason> {
        // 1. Global cap first. Acquire the slot up front so a per-IP rejection
        //    releases it (the permit drops on the early return).
        let global = match self.semaphore {
            Some(ref sem) => match sem.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    self.rejected_max_connections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(AdminConnRejectReason::MaxConnections);
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
                        return Err(AdminConnRejectReason::MaxConnectionsPerIp);
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
        Ok(AdminConnPermit {
            limiter: Arc::clone(self),
            remote_ip,
            per_ip_tracked,
            _global: global,
        })
    }

    /// Snapshot the limiter for metrics rendering.
    pub fn snapshot(&self) -> AdminConnLimiterSnapshot {
        let rejected_max_connections = self.rejected_max_connections.load(Ordering::Relaxed);
        let rejected_max_connections_per_ip =
            self.rejected_max_connections_per_ip.load(Ordering::Relaxed);
        AdminConnLimiterSnapshot {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            active_connections: self.active.load(Ordering::Relaxed),
            rejected_max_connections,
            rejected_max_connections_per_ip,
        }
    }

    /// Release accounting for a dropped permit. Internal to `AdminConnPermit`.
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

/// RAII guard representing one admitted admin connection. Held for the
/// connection's lifetime; releases the global + per-IP slots on drop.
pub struct AdminConnPermit {
    limiter: Arc<AdminConnLimiter>,
    remote_ip: IpAddr,
    per_ip_tracked: bool,
    /// Global semaphore slot; released when this field drops. `None` when the
    /// global cap is disabled.
    _global: Option<OwnedSemaphorePermit>,
}

impl Drop for AdminConnPermit {
    fn drop(&mut self) {
        self.limiter.release(self.remote_ip, self.per_ip_tracked);
    }
}
