//! UDP Datagram Rate Limiting Plugin
//!
//! Rate limits UDP datagrams per client IP using a fixed-window algorithm
//! with atomic counters. Protects backend services from UDP flood attacks
//! by silently dropping excess datagrams — standard UDP behavior.
//!
//! Unlike the HTTP `rate_limiting` plugin which operates on HTTP requests,
//! this plugin operates on individual UDP datagrams before they are forwarded
//! to the backend. Each client IP gets its own independent rate window.
//!
//! Two independent limits can be configured (either or both):
//! - `datagrams_per_second`: maximum datagrams per window
//! - `bytes_per_second`: maximum bytes per window
//!
//! Config:
//! ```json
//! {
//!   "datagrams_per_second": 1000,
//!   "bytes_per_second": 1048576,
//!   "window_seconds": 1
//! }
//! ```
//!
//! At least one of `datagrams_per_second` or `bytes_per_second` must be set.
//! If `window_seconds` is not set, it defaults to 1.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use super::{Plugin, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext, UdpDatagramVerdict};

/// Hard cap on tracked client IPs. When exceeded after eviction, new IPs
/// are rejected without inserting state — preventing spoofed-IP floods
/// from causing unbounded memory growth.
const MAX_STATE_ENTRIES: usize = 100_000;

/// Minimum interval between eviction sweeps in seconds. Prevents O(n) retain
/// scans from running on every datagram during high-cardinality floods.
const EVICTION_COOLDOWN_SECS: u64 = 1;

/// Interval between periodic eviction sweeps (every N datagram checks).
/// At 10k datagrams/sec, this triggers roughly every 10 seconds.
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

/// Per-client-IP rate window state.
///
/// Uses a fixed-window approach with atomic operations for lock-free
/// per-datagram checking. Window transitions are handled via CAS on
/// the `window_epoch` field.
///
/// `last_check_secs` is stored as an `AtomicU64` of seconds since `epoch_base`
/// (the plugin instance's startup `Instant`) so the per-datagram update is
/// lock-free. CLAUDE.md forbids `Mutex`/`RwLock` on the proxy data path.
struct WindowState {
    /// Datagram count in the current window.
    count: AtomicU64,
    /// Byte count in the current window.
    bytes: AtomicU64,
    /// Window epoch (monotonic instant divided by window duration).
    /// When the current epoch exceeds this, the counters are reset.
    window_epoch: AtomicU64,
    /// Seconds since `UdpRateLimiting::epoch_base` at the most recent datagram.
    /// Used by eviction to detect idle client IPs without holding any lock.
    last_check_secs: AtomicU64,
}

impl WindowState {
    fn new(epoch: u64, now_secs: u64) -> Self {
        Self {
            count: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            window_epoch: AtomicU64::new(epoch),
            last_check_secs: AtomicU64::new(now_secs),
        }
    }

    /// Check if this entry has been inactive for longer than the eviction threshold.
    /// `now_secs` and `last_check_secs` are both seconds since `epoch_base`, so
    /// the comparison stays within the monotonic timeline used for window math.
    fn is_stale(&self, now_secs: u64, max_idle_secs: u64) -> bool {
        let last = self.last_check_secs.load(Ordering::Relaxed);
        now_secs.saturating_sub(last) > max_idle_secs
    }
}

pub struct UdpRateLimiting {
    datagrams_per_window: Option<u64>,
    bytes_per_window: Option<u64>,
    window_seconds: u64,
    /// Per-client-IP window state.
    state: DashMap<Arc<str>, WindowState>,
    /// Monotonic datagram counter for periodic eviction.
    check_counter: AtomicU64,
    /// Startup instant used to compute window epochs from Instant::now().
    epoch_base: Instant,
    /// Seconds-since-`epoch_base` of the last eviction sweep. Lock-free —
    /// CLAUDE.md forbids `Mutex` on the data path. Initialised to 0; the
    /// first sweep runs once one `EVICTION_COOLDOWN_SECS` window has elapsed
    /// since startup (nothing is stale before then anyway).
    last_eviction_secs: AtomicU64,
}

impl UdpRateLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        let datagrams_per_second = config["datagrams_per_second"].as_u64();
        let bytes_per_second = config["bytes_per_second"].as_u64();

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of 'datagrams_per_second' or 'bytes_per_second' must be set"
                    .to_string(),
            );
        }

        let window_seconds = config["window_seconds"].as_u64().unwrap_or(1).max(1);

        let datagrams_per_window = datagrams_per_second.map(|d| d * window_seconds);
        let bytes_per_window = bytes_per_second.map(|b| b * window_seconds);

        Ok(Self {
            datagrams_per_window,
            bytes_per_window,
            window_seconds,
            state: DashMap::new(),
            check_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
            last_eviction_secs: AtomicU64::new(0),
        })
    }

    /// Seconds elapsed since `epoch_base`. Used as the monotonic clock for
    /// both window-epoch math and last-activity tracking.
    fn secs_since_base(&self) -> u64 {
        Instant::now().duration_since(self.epoch_base).as_secs()
    }

    /// Evict stale entries to prevent unbounded memory growth.
    ///
    /// Returns `true` if the state map is over the hard cap after eviction,
    /// meaning new IPs should be rejected without inserting state.
    fn maybe_evict(&self) -> bool {
        let count = self.check_counter.fetch_add(1, Ordering::Relaxed);
        let len = self.state.len();

        let over_capacity = len > MAX_STATE_ENTRIES;
        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && !self.state.is_empty();

        if over_capacity || periodic {
            // Time-gate eviction sweeps to prevent O(n) retain on every datagram
            // during high-cardinality floods. Lock-free: the cooldown gate is
            // an `AtomicU64` of seconds-since-`epoch_base`, mirroring the
            // monotonic clock used by per-IP `last_check_secs`.
            let now_secs = self.secs_since_base();
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            // CAS guards against multiple concurrent sweeps — the loser of the
            // race exits without scanning. Equivalent to the previous
            // `last_eviction.lock()` mutex but without taking a lock on the
            // hot path. Note: the winner stamps `last_eviction_secs` *before*
            // running `retain`, so the cooldown measures from sweep start, not
            // end. Under sustained high-cardinality pressure this is
            // at-least-one-sweep-per-cooldown rather than at-most — intentional,
            // since the goal is memory containment, not strict rate-limiting
            // of the sweep itself.
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                let max_idle = (self.window_seconds * 2).max(10);
                self.state.retain(|_, v| !v.is_stale(now_secs, max_idle));
            }
        }

        // Hard cap: after eviction, if still over capacity, signal callers to
        // reject unknown IPs without inserting state.
        self.state.len() > MAX_STATE_ENTRIES
    }
}

#[async_trait]
impl Plugin for UdpRateLimiting {
    fn name(&self) -> &str {
        "udp_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.state.len())
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext) -> UdpDatagramVerdict {
        let over_capacity = self.maybe_evict();

        // Sample the monotonic clock once per datagram and reuse it for window
        // math + last-activity tracking — keeps the call to `Instant::now()`
        // (a vDSO-backed clock_gettime) to a single hot-path syscall.
        let now_secs = self.secs_since_base();
        let current_epoch = now_secs / self.window_seconds;
        let key = Arc::clone(&ctx.client_ip);

        // Hard cap: when over capacity, only allow datagrams from already-tracked
        // IPs. New IPs are dropped without inserting state to prevent spoofed-IP
        // floods from causing unbounded memory growth.
        if over_capacity && !self.state.contains_key(&key) {
            return UdpDatagramVerdict::Drop;
        }

        let entry = self
            .state
            .entry(key)
            .or_insert_with(|| WindowState::new(current_epoch, now_secs));
        let state = entry.value();

        // Check if we've moved to a new window — reset counters via CAS.
        // Uses Acquire on load and Release on CAS success + stores so that
        // the zeroed counters are visible to all threads before they increment.
        let stored_epoch = state.window_epoch.load(Ordering::Acquire);
        if current_epoch > stored_epoch
            && state
                .window_epoch
                .compare_exchange(
                    stored_epoch,
                    current_epoch,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            state.count.store(0, Ordering::Release);
            state.bytes.store(0, Ordering::Release);
        }

        // Lock-free last-activity update: store the seconds-since-`epoch_base`
        // sampled at the top of this datagram. Eviction reads this with
        // `Relaxed` ordering — staleness only needs eventual consistency.
        state.last_check_secs.store(now_secs, Ordering::Relaxed);

        // Increment counters. Acquire ordering ensures we see the most
        // recent counter reset before adding.
        let new_count = state.count.fetch_add(1, Ordering::AcqRel) + 1;
        let new_bytes = state
            .bytes
            .fetch_add(ctx.datagram_size as u64, Ordering::AcqRel)
            + ctx.datagram_size as u64;

        // Check limits.
        if let Some(max_datagrams) = self.datagrams_per_window
            && new_count > max_datagrams
        {
            warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                count = new_count,
                limit = max_datagrams,
                "UDP datagram rate exceeded, dropping"
            );
            return UdpDatagramVerdict::Drop;
        }

        if let Some(max_bytes) = self.bytes_per_window
            && new_bytes > max_bytes
        {
            warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                bytes = new_bytes,
                limit = max_bytes,
                "UDP byte rate exceeded, dropping"
            );
            return UdpDatagramVerdict::Drop;
        }

        UdpDatagramVerdict::Forward
    }
}
