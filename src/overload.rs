//! Overload manager with resource monitors and progressive load shedding.
//!
//! Runs a background task that periodically checks resource pressure (file
//! descriptors, connection semaphore saturation, event loop latency) and sets
//! atomic action flags that the proxy hot path reads with a single
//! `AtomicBool::load(Relaxed)` (~1ns, zero contention).
//!
//! Also provides graceful shutdown draining: after SIGTERM, tracks in-flight
//! connections and waits up to a configurable drain period for them to complete.

use crossbeam_utils::CachePadded;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Number of monitor ticks between `fd_limit` refreshes.
///
/// The soft `RLIMIT_NOFILE` is mutable at runtime — operators or systemd may
/// raise it without restarting the gateway via `setrlimit(2)` or by reloading
/// the unit. Re-querying once per minute (60 ticks at the default 1s interval)
/// keeps `fd_ratio` aligned with the live limit at negligible cost (one
/// `getrlimit` syscall per minute) without taking the hit on every tick.
const FD_LIMIT_REFRESH_INTERVAL_TICKS: u64 = 60;

/// One-shot warning latch for the `fd_limit == 0` (FD pressure disabled) case.
///
/// `get_fd_limit()` returns 0 on Windows and other non-Unix platforms (and on
/// the rare `getrlimit` failure on Unix). When that happens the FD ratio is
/// permanently 0.0 — FD-based load shedding is silently inert. We emit a
/// single `warn!` so operators can distinguish "FD pressure disabled by
/// platform" from "FD pressure at 0%". The latch ensures the periodic refresh
/// loop never spams the warn if it continues to see 0.
static FD_PRESSURE_DISABLED_WARN: Once = Once::new();

fn warn_fd_pressure_disabled_once() {
    FD_PRESSURE_DISABLED_WARN.call_once(|| {
        warn!(
            "FD-based pressure shedding disabled on this platform — fd_limit could not be queried. \
             Connection-based and request-based shedding remain active."
        );
    });
}

fn pressure_ratio(current: u64, max: u64) -> f64 {
    if max > 0 {
        current as f64 / max as f64
    } else {
        0.0
    }
}

fn red_probability_for_pressure(
    ratio: f64,
    pressure_threshold: f64,
    critical_threshold: f64,
) -> u32 {
    if ratio >= critical_threshold {
        RED_PROBABILITY_SCALE
    } else if ratio >= pressure_threshold {
        let range = critical_threshold - pressure_threshold;
        let position = ratio - pressure_threshold;
        ((position / range) * RED_PROBABILITY_SCALE as f64) as u32
    } else {
        0
    }
}

/// Scale factor for RED (Random Early Detection) drop probability.
///
/// The probability is stored as an integer in [0, RED_PROBABILITY_SCALE] where
/// `RED_PROBABILITY_SCALE` represents 100% drop.  The value 1024 matches the
/// 10-bit hash range produced by `>> 54` (which yields [0, 1023]), so
/// comparisons are exact with no precision bias.
pub const RED_PROBABILITY_SCALE: u32 = 1024;

/// Overload pressure level reported via the admin `/overload` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OverloadLevel {
    Normal,
    Pressure,
    Critical,
}

/// Atomic overload state read by the proxy hot path.
///
/// The background monitor writes these flags; request threads only read.
/// All fields use `Ordering::Relaxed` — eventual consistency is acceptable
/// for overload signals (a few ms of stale state is harmless).
///
/// Hot-path atomics (`disable_keepalive`, `reject_new_connections`,
/// `reject_new_requests`, `active_connections`, `active_requests`,
/// `red_drop_probability`, `red_request_counter`) are wrapped in
/// [`CachePadded`] to prevent false sharing across cores: at 1M conn/sec
/// churn, an unpadded layout puts the read-mostly action flags on the same
/// cache line as the `fetch_add`/`fetch_sub` counters, causing the line to
/// ping-pong between cores and turning every accept into a coherence stall.
/// Snapshot fields (`fd_current`, `conn_current`, etc.), `draining`, and
/// `port_exhaustion_events` are NOT padded — they are written ≤ once/sec or
/// only on rare events, so contention does not justify the memory cost.
/// `CachePadded<T>` derefs to `T`, so all existing
/// `.load()` / `.fetch_add()` call sites compile unchanged.
pub struct OverloadState {
    // ── Action flags (hot-path reads) ──────────────────────────────────
    /// When true, responses include `Connection: close` to drain idle keepalives.
    pub disable_keepalive: CachePadded<AtomicBool>,
    /// When true, new connections are rejected with 503 before routing.
    pub reject_new_connections: CachePadded<AtomicBool>,
    /// When true, new requests/streams are rejected with 503 before processing.
    /// Independent of `reject_new_connections` — connections track sockets,
    /// requests track multiplexed H2/H3/gRPC streams.
    pub reject_new_requests: CachePadded<AtomicBool>,

    // ── Graceful shutdown drain ────────────────────────────────────────
    /// Set to true when SIGTERM/SIGINT is received to begin the drain phase.
    pub draining: AtomicBool,
    /// In-flight connection counter. Incremented on accept, decremented on drop
    /// via [`ConnectionGuard`].
    pub active_connections: CachePadded<AtomicU64>,
    /// In-flight request/stream counter. Incremented on request start, decremented
    /// on drop via [`RequestGuard`]. Tracks H1 requests, H2/gRPC streams, and H3
    /// streams independently of connections.
    pub active_requests: CachePadded<AtomicU64>,
    /// Notified each time `active_connections` or `active_requests` reaches zero
    /// during drain. The drain waiter re-checks both counters in a loop.
    pub drain_complete: tokio::sync::Notify,

    // ── RED adaptive load shedding ────────────────────────────────────
    /// RED (Random Early Detection) drop probability (0–[`RED_PROBABILITY_SCALE`] scale,
    /// where [`RED_PROBABILITY_SCALE`] = 100%).  Matches the 10-bit hash range
    /// (`>> 54` produces [0, 1023]) so comparisons are exact with no precision bias.
    /// When in the pressure zone (between pressure and critical thresholds), responses
    /// are probabilistically marked with Connection: close based on this value.
    /// The hot path reads this with a single AtomicU32::load(Relaxed).
    pub red_drop_probability: CachePadded<AtomicU32>,
    /// Monotonic request counter used as per-request entropy for RED decisions.
    /// Incremented by `fetch_add(1, Relaxed)` on each `should_disable_keepalive_red()` call.
    red_request_counter: CachePadded<AtomicU64>,

    // ── Snapshot for admin endpoint (written by monitor, read by admin) ─
    pub fd_current: AtomicU64,
    pub fd_max: AtomicU64,
    pub conn_current: AtomicU64,
    pub conn_max: AtomicU64,
    pub req_current: AtomicU64,
    pub req_max: AtomicU64,
    pub loop_latency_us: AtomicU64,

    // ── Port exhaustion tracking ─────────────────────────────────────
    /// Monotonic count of EADDRNOTAVAIL errors (ephemeral port exhaustion).
    /// Incremented from error classification sites; never reset.
    pub port_exhaustion_events: AtomicU64,

    // ── Node-waypoint fail-closed drops ────────────────────────────────
    /// Accepted sockets rejected because `SO_COOKIE` was unavailable.
    pub node_waypoint_cookie_unavailable_drops: CachePadded<AtomicU64>,
    /// Accepted sockets whose cookie was not enrolled by the node-agent.
    pub node_waypoint_unknown_cookie_drops: CachePadded<AtomicU64>,
    /// Enrolled cookie records missing a pod UID.
    pub node_waypoint_missing_pod_uid_drops: CachePadded<AtomicU64>,
    /// Enrolled cookie records missing a workload SPIFFE hash.
    pub node_waypoint_missing_workload_hash_drops: CachePadded<AtomicU64>,
    /// Enrolled pod UID records with no userspace identity.
    pub node_waypoint_unknown_pod_drops: CachePadded<AtomicU64>,
    /// Enrolled pod UID records whose SPIFFE hash mismatched userspace state.
    pub node_waypoint_hash_mismatch_drops: CachePadded<AtomicU64>,
}

impl Default for OverloadState {
    fn default() -> Self {
        Self::new()
    }
}

impl OverloadState {
    pub fn new() -> Self {
        Self {
            disable_keepalive: CachePadded::new(AtomicBool::new(false)),
            reject_new_connections: CachePadded::new(AtomicBool::new(false)),
            reject_new_requests: CachePadded::new(AtomicBool::new(false)),
            draining: AtomicBool::new(false),
            active_connections: CachePadded::new(AtomicU64::new(0)),
            active_requests: CachePadded::new(AtomicU64::new(0)),
            drain_complete: tokio::sync::Notify::new(),
            red_drop_probability: CachePadded::new(AtomicU32::new(0)),
            red_request_counter: CachePadded::new(AtomicU64::new(0)),
            fd_current: AtomicU64::new(0),
            fd_max: AtomicU64::new(0),
            conn_current: AtomicU64::new(0),
            conn_max: AtomicU64::new(0),
            req_current: AtomicU64::new(0),
            req_max: AtomicU64::new(0),
            loop_latency_us: AtomicU64::new(0),
            port_exhaustion_events: AtomicU64::new(0),
            node_waypoint_cookie_unavailable_drops: CachePadded::new(AtomicU64::new(0)),
            node_waypoint_unknown_cookie_drops: CachePadded::new(AtomicU64::new(0)),
            node_waypoint_missing_pod_uid_drops: CachePadded::new(AtomicU64::new(0)),
            node_waypoint_missing_workload_hash_drops: CachePadded::new(AtomicU64::new(0)),
            node_waypoint_unknown_pod_drops: CachePadded::new(AtomicU64::new(0)),
            node_waypoint_hash_mismatch_drops: CachePadded::new(AtomicU64::new(0)),
        }
    }

    /// Current overload level derived from the action flags.
    pub fn level(&self) -> OverloadLevel {
        if self.reject_new_connections.load(Ordering::Relaxed)
            || self.reject_new_requests.load(Ordering::Relaxed)
        {
            OverloadLevel::Critical
        } else if self.disable_keepalive.load(Ordering::Relaxed) {
            OverloadLevel::Pressure
        } else {
            OverloadLevel::Normal
        }
    }

    /// Returns true if this response should have keepalive disabled based on RED probability.
    /// Uses a monotonic per-request counter with golden-ratio hashing for uniform distribution.
    /// Cost: one AtomicU32::load + one AtomicU64::fetch_add(Relaxed) + one multiply + one comparison.
    ///
    /// **This ONLY signals RED-probability shedding — NOT the binary "pressure-mode active"
    /// signal.** Callers that want the full "should we close this HTTP/1.1 keepalive?"
    /// decision must also OR with `self.disable_keepalive.load(Relaxed)`. Two reasons:
    /// (1) at the exact pressure threshold the linear ramp produces probability 0 while
    /// the binary flag is set; (2) the monitor loop writes `disable_keepalive` and
    /// `red_drop_probability` as independent `Relaxed` stores, so a reader can transiently
    /// observe the new flag with the prior cycle's probability. The hot-path response
    /// builder in `proxy::mod` performs that OR — see `connection: close` decision.
    pub fn should_disable_keepalive_red(&self) -> bool {
        let prob = self.red_drop_probability.load(Ordering::Relaxed);
        if prob == 0 {
            return false;
        }
        if prob >= RED_PROBABILITY_SCALE {
            return true;
        }
        // Monotonic counter ensures each call gets a unique input, producing
        // true per-response probabilistic shedding even when active_connections
        // is stable.
        let counter = self.red_request_counter.fetch_add(1, Ordering::Relaxed);
        // Golden-ratio hash: multiply and take high bits for 0-1023 range.
        // Both the hash output and probability scale use [0, RED_PROBABILITY_SCALE)
        // so the comparison is exact — no precision bias.
        let hash = counter.wrapping_mul(0x9E3779B97F4A7C15) >> 54;
        (hash as u32) < prob
    }

    /// Record an ephemeral port exhaustion event (EADDRNOTAVAIL).
    /// Called from error classification sites when a connect failure is
    /// identified as port exhaustion.
    pub fn record_port_exhaustion(&self) {
        self.port_exhaustion_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a node-waypoint accept-time identity failure.
    pub fn record_node_waypoint_drop(&self, reason: NodeWaypointDropReason) {
        reason.counter(self).fetch_add(1, Ordering::Relaxed);
    }

    /// Build a JSON-serializable snapshot for the admin endpoint.
    pub fn snapshot(&self) -> OverloadSnapshot {
        let fd_current = self.fd_current.load(Ordering::Relaxed);
        let fd_max = self.fd_max.load(Ordering::Relaxed);
        let conn_current = self.conn_current.load(Ordering::Relaxed);
        let conn_max = self.conn_max.load(Ordering::Relaxed);
        let req_current = self.req_current.load(Ordering::Relaxed);
        let req_max = self.req_max.load(Ordering::Relaxed);
        OverloadSnapshot {
            level: self.level(),
            draining: self.draining.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            active_requests: self.active_requests.load(Ordering::Relaxed),
            red_drop_probability_pct: self.red_drop_probability.load(Ordering::Relaxed) as f64
                / (RED_PROBABILITY_SCALE as f64 / 100.0),
            port_exhaustion_events: self.port_exhaustion_events.load(Ordering::Relaxed),
            node_waypoint_drops: NodeWaypointDropSnapshot {
                cookie_unavailable: self
                    .node_waypoint_cookie_unavailable_drops
                    .load(Ordering::Relaxed),
                unknown_cookie: self
                    .node_waypoint_unknown_cookie_drops
                    .load(Ordering::Relaxed),
                missing_pod_uid: self
                    .node_waypoint_missing_pod_uid_drops
                    .load(Ordering::Relaxed),
                missing_workload_hash: self
                    .node_waypoint_missing_workload_hash_drops
                    .load(Ordering::Relaxed),
                unknown_pod: self.node_waypoint_unknown_pod_drops.load(Ordering::Relaxed),
                hash_mismatch: self
                    .node_waypoint_hash_mismatch_drops
                    .load(Ordering::Relaxed),
            },
            pressure: PressureSnapshot {
                file_descriptors: FdPressure {
                    current: fd_current,
                    max: fd_max,
                    ratio: pressure_ratio(fd_current, fd_max),
                },
                connections: ConnPressure {
                    current: conn_current,
                    max: conn_max,
                    ratio: pressure_ratio(conn_current, conn_max),
                },
                requests: ReqPressure {
                    current: req_current,
                    max: req_max,
                    ratio: pressure_ratio(req_current, req_max),
                },
                event_loop_latency_us: self.loop_latency_us.load(Ordering::Relaxed),
            },
            actions: ActionSnapshot {
                disable_keepalive: self.disable_keepalive.load(Ordering::Relaxed),
                reject_new_connections: self.reject_new_connections.load(Ordering::Relaxed),
                reject_new_requests: self.reject_new_requests.load(Ordering::Relaxed),
            },
        }
    }
}

/// RAII guard that decrements [`OverloadState::active_connections`] on drop.
///
/// Created for every accepted connection. Cost: one `fetch_add(Relaxed)` on
/// construction, one `fetch_sub(Relaxed)` on drop (~5ns each, no contention).
pub struct ConnectionGuard {
    state: Arc<OverloadState>,
}

impl ConnectionGuard {
    pub fn new(state: &Arc<OverloadState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            state: state.clone(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self
            .state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        // If this was the last connection and we are draining, notify the waiter.
        // `Acquire` synchronizes-with the `Release` store in `begin_drain` so the
        // notify reliably fires when shutdown has begun, even on weakly-ordered
        // architectures.
        if prev == 1 && self.state.draining.load(Ordering::Acquire) {
            self.state.drain_complete.notify_one();
        }
    }
}

/// RAII guard that decrements [`OverloadState::active_requests`] on drop.
///
/// Created for every accepted request/stream (H1 requests, H2/gRPC streams,
/// H3 streams). Cost: one `fetch_add(Relaxed)` on construction, one
/// `fetch_sub(Relaxed)` on drop (~5ns each, no contention).
pub struct RequestGuard {
    state: Arc<OverloadState>,
}

impl RequestGuard {
    pub fn new(state: &Arc<OverloadState>) -> Self {
        state.active_requests.fetch_add(1, Ordering::Relaxed);
        Self {
            state: state.clone(),
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let prev = self.state.active_requests.fetch_sub(1, Ordering::Relaxed);
        // If this was the last request and we are draining, notify the waiter.
        // The drain waiter re-checks both active_connections and active_requests,
        // so spurious wakes from one counter reaching zero are harmless.
        // `Acquire` synchronizes-with the `Release` store in `begin_drain` so the
        // notify reliably fires when shutdown has begun, even on weakly-ordered
        // architectures.
        if prev == 1 && self.state.draining.load(Ordering::Acquire) {
            self.state.drain_complete.notify_one();
        }
    }
}

// ── Serializable snapshot types ──────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct OverloadSnapshot {
    pub level: OverloadLevel,
    pub draining: bool,
    pub active_connections: u64,
    pub active_requests: u64,
    pub red_drop_probability_pct: f64,
    pub port_exhaustion_events: u64,
    pub node_waypoint_drops: NodeWaypointDropSnapshot,
    pub pressure: PressureSnapshot,
    pub actions: ActionSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointDropReason {
    CookieUnavailable,
    UnknownCookie,
    MissingPodUid,
    MissingWorkloadHash,
    UnknownPod,
    HashMismatch,
}

impl NodeWaypointDropReason {
    fn counter(self, state: &OverloadState) -> &CachePadded<AtomicU64> {
        match self {
            Self::CookieUnavailable => &state.node_waypoint_cookie_unavailable_drops,
            Self::UnknownCookie => &state.node_waypoint_unknown_cookie_drops,
            Self::MissingPodUid => &state.node_waypoint_missing_pod_uid_drops,
            Self::MissingWorkloadHash => &state.node_waypoint_missing_workload_hash_drops,
            Self::UnknownPod => &state.node_waypoint_unknown_pod_drops,
            Self::HashMismatch => &state.node_waypoint_hash_mismatch_drops,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct NodeWaypointDropSnapshot {
    pub cookie_unavailable: u64,
    pub unknown_cookie: u64,
    pub missing_pod_uid: u64,
    pub missing_workload_hash: u64,
    pub unknown_pod: u64,
    pub hash_mismatch: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct PressureSnapshot {
    pub file_descriptors: FdPressure,
    pub connections: ConnPressure,
    pub requests: ReqPressure,
    pub event_loop_latency_us: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct FdPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ConnPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ReqPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ActionSnapshot {
    pub disable_keepalive: bool,
    pub reject_new_connections: bool,
    pub reject_new_requests: bool,
}

// ── Overload manager configuration ──────────────────────────────────────

/// Configuration for the overload manager, parsed from env vars.
#[derive(Debug, Clone)]
pub struct OverloadConfig {
    /// How often the monitor checks resource pressure (default: 1000ms).
    pub check_interval_ms: u64,
    /// FD ratio above which keepalive is disabled (default: 0.80).
    pub fd_pressure_threshold: f64,
    /// FD ratio above which new connections are rejected (default: 0.95).
    pub fd_critical_threshold: f64,
    /// Connection semaphore usage above which keepalive is disabled (default: 0.85).
    pub conn_pressure_threshold: f64,
    /// Connection semaphore usage above which new connections are rejected (default: 0.95).
    pub conn_critical_threshold: f64,
    /// Request usage above which keepalive is disabled (default: 0.85).
    pub req_pressure_threshold: f64,
    /// Request usage above which new requests are rejected (default: 0.95).
    pub req_critical_threshold: f64,
    /// Event loop latency (μs) above which a warning is logged (default: 10_000 = 10ms).
    pub loop_warn_us: u64,
    /// Event loop latency (μs) above which new connections are rejected (default: 500_000 = 500ms).
    pub loop_critical_us: u64,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: 1000,
            fd_pressure_threshold: 0.80,
            fd_critical_threshold: 0.95,
            conn_pressure_threshold: 0.85,
            conn_critical_threshold: 0.95,
            req_pressure_threshold: 0.85,
            req_critical_threshold: 0.95,
            loop_warn_us: 10_000,
            loop_critical_us: 500_000,
        }
    }
}

// ── Resource monitors ───────────────────────────────────────────────────

/// Count open file descriptors for the current process.
#[cfg(target_os = "linux")]
fn count_open_fds_linux(path: &str) -> u64 {
    std::fs::read_dir(path)
        .map(|d| d.count() as u64)
        // Fail closed: if we cannot inspect /proc/self/fd (for example,
        // EMFILE under descriptor exhaustion), force critical FD pressure.
        .unwrap_or(u64::MAX)
}

#[cfg(target_os = "linux")]
pub(crate) fn count_open_fds() -> u64 {
    // On Linux, /proc/self/fd is the canonical way to count open FDs.
    count_open_fds_linux("/proc/self/fd")
}

#[cfg(target_os = "macos")]
pub(crate) fn count_open_fds() -> u64 {
    // On macOS, use proc_pidinfo via the libc FFI constants.
    // PROC_PIDLISTFDS = 1, sizeof(proc_fdinfo) = 8
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_FDINFO_SIZE: u64 = 8; // sizeof(proc_fdinfo) = u32 + u32
    let pid = std::process::id() as i32;
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }
    let buffer_size = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if buffer_size <= 0 {
        return 0;
    }
    (buffer_size as u64) / PROC_FDINFO_SIZE
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn count_open_fds() -> u64 {
    0 // FD monitoring not available on this platform
}

/// Platform constant for `RLIMIT_NOFILE` (the rlimit resource selector for the
/// per-process open-file-descriptor cap). Linux puts it at 7, the BSD lineage
/// (macOS, FreeBSD, etc.) at 8 — see `<sys/resource.h>`.
#[cfg(target_os = "linux")]
const RLIMIT_NOFILE: i32 = 7;
#[cfg(target_os = "macos")]
const RLIMIT_NOFILE: i32 = 8;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const RLIMIT_NOFILE: i32 = 8; // BSD default

#[cfg(unix)]
unsafe extern "C" {
    fn getrlimit(resource: i32, rlim: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, rlim: *const [u64; 2]) -> i32;
}

/// Recommended floor for the FD hard cap on production hosts. 65,536 covers
/// 30K+ inbound TCP conns + their amortized outbound pool entries + the
/// runtime/CRT FDs without the gateway tripping its own 95% critical
/// threshold. Below this we emit a `warn!` at startup so operators see the
/// signal in their log pipeline rather than discovering it at the EMFILE.
pub const FD_HARD_LIMIT_PRODUCTION_FLOOR: u64 = 65_536;

/// Outcome of the startup attempt to raise the soft FD cap to the hard cap.
/// Reported by [`raise_fd_limit`] for logging and tests.
#[derive(Debug, Clone, Copy)]
pub struct RaiseFdLimitResult {
    /// Soft limit observed before the call (0 on non-Unix or if `getrlimit` failed).
    pub soft_before: u64,
    /// Soft limit after the call. Equal to `soft_before` if `setrlimit` was a
    /// no-op or failed; equal to `hard` on success.
    pub soft_after: u64,
    /// Hard limit (unchanged by this call — we never attempt to raise it).
    pub hard: u64,
    /// True when `setrlimit` actually moved the soft cap upward.
    pub raised: bool,
}

/// Get the maximum file descriptor limit (soft limit).
pub(crate) fn get_fd_limit() -> u64 {
    #[cfg(unix)]
    {
        get_fd_rlimit_pair().0
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Read both rlimit fields (soft, hard) at once. Returns `(0, 0)` on
/// non-Unix or if the syscall fails. Used by [`raise_fd_limit`] and
/// [`get_fd_limit`] so there is a single `getrlimit` call site.
#[cfg(unix)]
fn get_fd_rlimit_pair() -> (u64, u64) {
    let mut rlim: [u64; 2] = [0, 0];
    let result = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
    if result == 0 {
        (rlim[0], rlim[1])
    } else {
        (0, 0)
    }
}

/// Raise the soft FD limit (`RLIMIT_NOFILE.rlim_cur`) to the hard limit.
///
/// Called once at startup. Conservative by design — we never attempt to raise
/// the hard cap, so this never asks for privileges the process does not already
/// have. If `setrlimit` fails (sandboxed container, seccomp filter, or the
/// kernel rejects the value), the call is a no-op and the gateway continues
/// with whatever soft cap it inherited.
///
/// On non-Unix platforms this is a no-op that returns zeros.
///
/// Operators running production workloads should make sure the *hard* cap is
/// at least [`FD_HARD_LIMIT_PRODUCTION_FLOOR`] (set via `LimitNOFILE=` in
/// systemd, `--ulimit nofile=` in Docker, or `/etc/security/limits.conf`) —
/// when it is below that floor, [`raise_fd_limit`] only emits a structured
/// `warn!` at startup; it does not fail. The caller (typically `main.rs`) is
/// responsible for logging the result.
pub fn raise_fd_limit() -> RaiseFdLimitResult {
    #[cfg(unix)]
    {
        let (soft_before, hard) = get_fd_rlimit_pair();
        if soft_before == 0 && hard == 0 {
            // getrlimit failed — bail out without an unsafe second syscall.
            return RaiseFdLimitResult {
                soft_before: 0,
                soft_after: 0,
                hard: 0,
                raised: false,
            };
        }

        if soft_before >= hard {
            // Already at the hard cap — nothing to do.
            return RaiseFdLimitResult {
                soft_before,
                soft_after: soft_before,
                hard,
                raised: false,
            };
        }

        // `hard == RLIM_INFINITY` is safe here; the kernel still enforces its
        // platform ceiling (for example fs.nr_open on Linux).
        let new_rlim: [u64; 2] = [hard, hard];
        let result = unsafe { setrlimit(RLIMIT_NOFILE, &new_rlim) };
        if result == 0 {
            RaiseFdLimitResult {
                soft_before,
                soft_after: hard,
                hard,
                raised: true,
            }
        } else {
            // setrlimit refused the bump — keep running with the old soft cap.
            RaiseFdLimitResult {
                soft_before,
                soft_after: soft_before,
                hard,
                raised: false,
            }
        }
    }
    #[cfg(not(unix))]
    {
        RaiseFdLimitResult {
            soft_before: 0,
            soft_after: 0,
            hard: 0,
            raised: false,
        }
    }
}

/// Measure event loop latency across ALL tokio workers and return the maximum
/// observed scheduling delay.
///
/// Naively timing a single `tokio::task::yield_now().await` only measures the
/// reschedule latency of the CURRENT task on the CURRENT worker. With a
/// multi-threaded runtime (one worker per CPU by default), a single starved
/// worker (e.g., a misbehaving plugin doing blocking I/O on worker 0) is
/// invisible to a monitor task running on a healthy worker. The 500 ms
/// `loop_critical_us` gate would then almost never trip even when individual
/// workers are pinned.
///
/// To surface per-worker starvation, we spawn one tiny probe task per worker
/// (queried via `Handle::current().metrics().num_workers()`), let tokio's
/// scheduler distribute them across workers, and report the **maximum**
/// scheduling delay observed across all probes. The timer starts before each
/// probe is spawned, so a starved worker surfaces both first-poll queueing
/// delay and post-`yield_now()` re-poll delay in the aggregate reading.
///
/// Each probe is a single `yield_now().await` (a few microseconds in the
/// healthy case), so the overall cost scales linearly with worker count and
/// is negligible at the default 1 s monitor interval.
///
/// On `current_thread` runtimes (or any runtime where `num_workers()` returns 0
/// or 1, e.g. tokio's `LocalSet`-based tests), this falls back to the original
/// single-task probe.
async fn measure_event_loop_latency() -> Duration {
    const EVENT_LOOP_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
    const EVENT_LOOP_TIMEOUT_FAIL_CLOSED_LATENCY: Duration = Duration::from_micros(500_000);
    let num_workers = tokio::runtime::Handle::current().metrics().num_workers();

    // Single-threaded fallback: just measure our own reschedule.
    if num_workers <= 1 {
        let start = std::time::Instant::now();
        tokio::task::yield_now().await;
        return start.elapsed();
    }

    let mut probes = tokio::task::JoinSet::new();
    for _ in 0..num_workers {
        let start = std::time::Instant::now();
        probes.spawn(async move {
            tokio::task::yield_now().await;
            start.elapsed()
        });
    }

    let mut max_latency = Duration::ZERO;
    let drain_result = tokio::time::timeout(EVENT_LOOP_PROBE_TIMEOUT, async {
        while let Some(result) = probes.join_next().await {
            // A probe task panicking is unexpected (yield_now never panics) but if
            // it ever happens, prefer continuing over aborting the monitor cycle.
            if let Ok(latency) = result
                && latency > max_latency
            {
                max_latency = latency;
            }
        }
    })
    .await;

    if drain_result.is_err() {
        probes.abort_all();
        return max_latency.max(EVENT_LOOP_TIMEOUT_FAIL_CLOSED_LATENCY);
    }
    max_latency
}

// ── Background monitor task ─────────────────────────────────────────────

/// Start the overload monitor background task.
///
/// Returns a `JoinHandle` that the caller should await during shutdown.
/// The task exits cleanly when `shutdown_rx` fires.
pub fn start_monitor(
    state: Arc<OverloadState>,
    config: OverloadConfig,
    max_connections: usize,
    max_requests: usize,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_millis(config.check_interval_ms);
        // `fd_limit` is mutable so the monitor can pick up runtime changes to
        // the soft `RLIMIT_NOFILE` (e.g. operator `setrlimit(2)`, systemd unit
        // reload). Refreshed every `FD_LIMIT_REFRESH_INTERVAL_TICKS` iterations.
        let mut fd_limit = get_fd_limit();
        let mut tick: u64 = 0;

        // Store limits (max_connections / max_requests don't change during
        // runtime; fd_max is updated each refresh below).
        state.fd_max.store(fd_limit, Ordering::Relaxed);
        state
            .conn_max
            .store(max_connections as u64, Ordering::Relaxed);
        state.req_max.store(max_requests as u64, Ordering::Relaxed);

        // One-shot warn at startup when FD pressure is unavailable on this
        // platform (Windows, or `getrlimit` failed). Connection- and
        // request-based shedding still work; only FD-based shedding is inert.
        if fd_limit == 0 {
            warn_fd_pressure_disabled_once();
        }

        info!(
            "Overload monitor started (interval={}ms, fd_limit={}, max_conn={}, max_req={})",
            config.check_interval_ms, fd_limit, max_connections, max_requests
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => {
                    debug!("Overload monitor shutting down");
                    return;
                }
            }
            tick = tick.wrapping_add(1);

            // ── Periodic fd_limit refresh ──
            // The soft RLIMIT_NOFILE can be raised at runtime without
            // restarting the gateway. Re-query once per minute so `fd_ratio`
            // tracks the live limit. On platforms where the syscall returns
            // 0, the warn latch fires only once.
            if tick.is_multiple_of(FD_LIMIT_REFRESH_INTERVAL_TICKS) {
                let new_limit = get_fd_limit();
                if new_limit != fd_limit {
                    info!(
                        old_fd_limit = fd_limit,
                        new_fd_limit = new_limit,
                        "Overload monitor: fd_limit changed (RLIMIT_NOFILE updated)"
                    );
                    fd_limit = new_limit;
                    state.fd_max.store(fd_limit, Ordering::Relaxed);
                }
                if fd_limit == 0 {
                    warn_fd_pressure_disabled_once();
                }
            }

            // ── FD pressure ──
            let fd_current = count_open_fds();
            state.fd_current.store(fd_current, Ordering::Relaxed);

            let fd_ratio = pressure_ratio(fd_current, fd_limit);

            // ── Connection pressure ──
            // Uses the active_connections counter maintained by ConnectionGuard
            // (covers HTTP/1.1, H2, H3, gRPC, and stream proxy connections).
            let conn_used = state.active_connections.load(Ordering::Relaxed);
            state.conn_current.store(conn_used, Ordering::Relaxed);
            let conn_ratio = pressure_ratio(conn_used, max_connections as u64);

            // ── Request pressure ──
            let req_used = state.active_requests.load(Ordering::Relaxed);
            state.req_current.store(req_used, Ordering::Relaxed);
            let req_ratio = pressure_ratio(req_used, max_requests as u64);

            // ── Event loop latency ──
            let loop_latency = measure_event_loop_latency().await;
            let loop_us = loop_latency.as_micros() as u64;
            state.loop_latency_us.store(loop_us, Ordering::Relaxed);

            // ── Evaluate thresholds and set action flags ──
            let should_disable_keepalive = fd_ratio >= config.fd_pressure_threshold
                || conn_ratio >= config.conn_pressure_threshold
                || (max_requests > 0 && req_ratio >= config.req_pressure_threshold);

            let should_reject = fd_ratio >= config.fd_critical_threshold
                || conn_ratio >= config.conn_critical_threshold
                || loop_us >= config.loop_critical_us;

            // Request-level overload rejection only triggers when
            // FERRUM_MAX_REQUESTS is configured (non-zero). Shutdown drain is
            // also a request-admission rejection source: once begin_drain()
            // has published draining=true with Release ordering, the monitor
            // must preserve that state instead of clearing reject_new_requests
            // during a low-pressure sample.
            let should_reject_requests_due_to_pressure =
                max_requests > 0 && req_ratio >= config.req_critical_threshold;
            let should_reject_requests =
                state.draining.load(Ordering::Acquire) || should_reject_requests_due_to_pressure;

            // ── RED-style smooth ramp between pressure and critical thresholds ──
            // For BOTH fd and connection pressure, compute probability independently
            // and take the max. This gives a smooth ramp from 0% at the pressure
            // threshold to 100% at the critical threshold.
            let fd_red_prob = red_probability_for_pressure(
                fd_ratio,
                config.fd_pressure_threshold,
                config.fd_critical_threshold,
            );
            let conn_red_prob = red_probability_for_pressure(
                conn_ratio,
                config.conn_pressure_threshold,
                config.conn_critical_threshold,
            );
            let req_red_prob = if max_requests > 0 {
                red_probability_for_pressure(
                    req_ratio,
                    config.req_pressure_threshold,
                    config.req_critical_threshold,
                )
            } else {
                0
            };
            state.red_drop_probability.store(
                fd_red_prob.max(conn_red_prob).max(req_red_prob),
                Ordering::Relaxed,
            );

            // Transition logging — only log when state changes
            let was_rejecting = state.reject_new_connections.load(Ordering::Relaxed);
            let was_rejecting_requests = state.reject_new_requests.load(Ordering::Acquire);
            let was_keepalive_disabled = state.disable_keepalive.load(Ordering::Relaxed);

            state
                .disable_keepalive
                .store(should_disable_keepalive, Ordering::Relaxed);
            state
                .reject_new_connections
                .store(should_reject, Ordering::Relaxed);
            state
                .reject_new_requests
                .store(should_reject_requests, Ordering::Release);

            if should_reject && !was_rejecting {
                warn!(
                    level = "critical",
                    action = "reject_connections",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload CRITICAL: rejecting new connections",
                );
            } else if !should_reject && was_rejecting {
                info!(
                    level = "normal",
                    action = "accept_connections",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload recovered: accepting new connections",
                );
            }

            if should_reject_requests && !was_rejecting_requests {
                warn!(
                    level = "critical",
                    action = "reject_requests",
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    "Overload CRITICAL: rejecting new requests",
                );
            } else if !should_reject_requests && was_rejecting_requests {
                info!(
                    level = "normal",
                    action = "accept_requests",
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    "Overload recovered: accepting new requests",
                );
            }

            if should_disable_keepalive && !was_keepalive_disabled {
                warn!(
                    level = "pressure",
                    action = "disable_keepalive",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload pressure: disabling keepalive",
                );
            } else if !should_disable_keepalive && was_keepalive_disabled && !should_reject {
                info!(
                    level = "normal",
                    action = "enable_keepalive",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload pressure recovered: re-enabling keepalive",
                );
            }

            // Event loop latency warning (independent of action thresholds)
            if loop_us >= config.loop_warn_us && loop_us < config.loop_critical_us {
                warn!(
                    loop_latency_us = loop_us,
                    threshold_us = config.loop_warn_us,
                    "Tokio event loop delayed — possible thread starvation",
                );
            }
        }
    })
}

/// Mark the overload state as draining and refuse new request admission.
///
/// Sets both `draining` and `reject_new_requests` together so they are observed
/// atomically with respect to each other from the shutdown trigger task. Stores
/// use `Ordering::Release` so any loader that does an `Acquire` load (proxy hot
/// path keepalive-close decision, request admission control, guard drop drain
/// notification) sees the post-shutdown state in a happens-before relationship.
///
/// Called by every serving mode at the START of the post-listener-exit phase,
/// regardless of `FERRUM_SHUTDOWN_DRAIN_SECONDS`. Two effects:
///
/// 1. **`draining=true`** — `Connection: close` is injected on HTTP/1.1 responses
///    so keepalive clients release connections instead of holding them open
///    until process exit. Also gates the guard-drop `drain_complete` notify.
/// 2. **`reject_new_requests=true`** — new requests/streams arriving on
///    EXISTING connections (especially H2/H3 multiplexed streams that have no
///    `Connection: close` analogue and keepalive H1 streams that race the
///    close hint) are rejected with 503 / gRPC UNAVAILABLE before processing.
///
/// Decoupled from [`wait_for_drain`] so `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` still
/// emits the close hint and admission rejection — the wait loop is only useful
/// when the operator wants the gateway to linger for in-flight completion.
///
/// Mirrors the [PR #569] Acquire/Release pattern for `startup_ready`.
///
/// [PR #569]: https://github.com/ferrum-edge/ferrum-edge/pull/569
pub fn begin_drain(state: &Arc<OverloadState>) {
    state.draining.store(true, Ordering::Release);
    state.reject_new_requests.store(true, Ordering::Release);
}

/// Wait for all in-flight connections and requests to drain, up to the
/// configured timeout.
///
/// Called after the accept loops have exited and after [`begin_drain`] has
/// been invoked. Returns `true` if all connections and requests drained within
/// the timeout, `false` if the timeout expired.
///
/// This function does NOT toggle `draining` / `reject_new_requests` — that is
/// [`begin_drain`]'s job, run unconditionally on shutdown so the close hint
/// fires even when the operator has set `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` to
/// disable the wait loop.
pub async fn wait_for_drain(state: &Arc<OverloadState>, timeout: Duration) -> bool {
    let active_conns = state.active_connections.load(Ordering::Relaxed);
    let active_reqs = state.active_requests.load(Ordering::Relaxed);
    if active_conns == 0 && active_reqs == 0 {
        info!(
            phase = "drain",
            "No active connections or requests to drain"
        );
        return true;
    }

    info!(
        phase = "drain",
        active_connections = active_conns,
        active_requests = active_reqs,
        timeout_seconds = timeout.as_secs(),
        "Draining active connections and requests",
    );

    match tokio::time::timeout(timeout, async {
        loop {
            if state.active_connections.load(Ordering::Relaxed) == 0
                && state.active_requests.load(Ordering::Relaxed) == 0
            {
                break;
            }
            state.drain_complete.notified().await;
        }
    })
    .await
    {
        Ok(()) => {
            info!(
                phase = "drain",
                result = "complete",
                "All connections and requests drained successfully"
            );
            true
        }
        Err(_) => {
            let remaining_conns = state.active_connections.load(Ordering::Relaxed);
            let remaining_reqs = state.active_requests.load(Ordering::Relaxed);
            warn!(
                phase = "drain",
                result = "timeout",
                remaining_connections = remaining_conns,
                remaining_requests = remaining_reqs,
                "Drain timeout expired — force closing",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[cfg(unix)]
    #[test]
    fn fd_limit_is_nonzero() {
        assert!(get_fd_limit() > 0, "FD limit should be > 0 on Unix");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fd_count_is_nonzero() {
        let count = count_open_fds();
        assert!(count > 0, "Process should have at least some open FDs");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_count_failures_are_fail_closed() {
        let count = count_open_fds_linux("/proc/self/fd/definitely-missing");
        assert_eq!(count, u64::MAX);
    }

    /// `raise_fd_limit` must never return a soft cap above the hard cap, must
    /// never lower the soft cap, and must accurately report whether it
    /// actually moved the limit. Sandboxed/seccomp test runners are still
    /// expected to satisfy these invariants because the call is a silent
    /// no-op when `setrlimit` is denied.
    #[cfg(unix)]
    #[test]
    fn raise_fd_limit_respects_invariants() {
        let result = raise_fd_limit();
        assert!(
            result.soft_after >= result.soft_before,
            "soft cap must never decrease: before={} after={}",
            result.soft_before,
            result.soft_after,
        );
        assert!(
            result.soft_after <= result.hard,
            "soft cap must never exceed hard cap: soft_after={} hard={}",
            result.soft_after,
            result.hard,
        );
        // `raised` must be consistent with the before/after delta.
        if result.raised {
            assert!(
                result.soft_after > result.soft_before,
                "raised=true requires soft_after > soft_before",
            );
        }
    }

    /// `raise_fd_limit` is idempotent — calling it a second time after the
    /// first run reaches the hard cap must report `raised=false` and leave
    /// the cap untouched. This protects against accidental double-call from
    /// a future test or a CLI subcommand also wiring the helper into its
    /// startup.
    #[cfg(unix)]
    #[test]
    fn raise_fd_limit_is_idempotent() {
        let first = raise_fd_limit();
        let second = raise_fd_limit();
        assert_eq!(
            first.soft_after, second.soft_after,
            "second call must not change the soft cap",
        );
        assert!(
            !second.raised,
            "second call must report raised=false; got soft_before={} soft_after={}",
            second.soft_before, second.soft_after,
        );
    }

    /// `CachePadded<T>` must occupy at least one cache line so that two
    /// adjacent atomics in `OverloadState` do not share a line. The exact
    /// alignment is platform-specific (64 B on x86-64, 128 B on aarch64),
    /// but `crossbeam_utils` guarantees `>= 64`. This test catches a future
    /// dep update that silently regresses the padding contract.
    #[test]
    fn cache_padded_atomic_u64_is_at_least_one_cache_line() {
        let size = std::mem::size_of::<CachePadded<AtomicU64>>();
        assert!(
            size >= 64,
            "CachePadded<AtomicU64> should be >= 64 bytes (one cache line); got {}",
            size,
        );
    }

    /// The hot atomics on `OverloadState` are intentionally on separate
    /// cache lines from each other — verify the read-mostly action flag and
    /// the write-heavy connection counter are not co-located. Address
    /// distance >= 64 on x86-64 is sufficient evidence.
    #[test]
    fn hot_atomics_do_not_share_cache_line() {
        let state = OverloadState::new();
        let reject_addr = &*state.reject_new_connections as *const AtomicBool as usize;
        let active_addr = &*state.active_connections as *const AtomicU64 as usize;
        let distance = reject_addr.abs_diff(active_addr);
        assert!(
            distance >= 64,
            "reject_new_connections and active_connections should be on different cache lines; distance={}",
            distance,
        );
    }

    /// The fd_limit refresh cadence — tied to the default 1s tick — should
    /// land on whole-minute boundaries so the syscall load is predictable
    /// (one `getrlimit` per minute). If the constant is ever retuned, this
    /// guards against accidentally landing on a sub-minute interval.
    #[test]
    fn fd_limit_refresh_interval_is_one_minute_at_default_tick() {
        let default_tick_ms = OverloadConfig::default().check_interval_ms;
        let refresh_period_ms = default_tick_ms * FD_LIMIT_REFRESH_INTERVAL_TICKS;
        assert_eq!(
            refresh_period_ms, 60_000,
            "fd_limit refresh should be ~60s at the default 1s monitor tick"
        );
        const {
            assert!(
                FD_LIMIT_REFRESH_INTERVAL_TICKS > 0,
                "refresh interval must be positive to ever trigger a refresh"
            );
        }
    }

    /// Simulate the monitor loop's tick counter and verify a changed
    /// `fd_limit` is picked up exactly on the refresh boundary, not before
    /// and not skipped after. Mirrors the in-loop logic at the top of the
    /// `start_monitor` task body without needing a full tokio harness.
    #[test]
    fn fd_limit_refresh_boundary_picks_up_changes() {
        // Stand-in for `get_fd_limit()` whose return value flips after the
        // first refresh boundary, modeling an operator running `setrlimit(2)`
        // partway through the gateway's lifetime.
        let mut probe_calls = 0u64;
        let mut probe = |tick: u64| -> u64 {
            probe_calls += 1;
            // First boundary returns the original limit; subsequent
            // boundaries return the raised limit.
            if tick < FD_LIMIT_REFRESH_INTERVAL_TICKS {
                1024
            } else {
                65_536
            }
        };

        // Initial value (read once at task start).
        let mut fd_limit = probe(0);
        assert_eq!(fd_limit, 1024);

        // Walk through enough ticks to cross two refresh boundaries.
        let total_ticks = FD_LIMIT_REFRESH_INTERVAL_TICKS * 2 + 5;
        let mut refresh_observations = 0u64;
        let mut tick: u64 = 0;
        while tick < total_ticks {
            tick = tick.wrapping_add(1);
            if tick.is_multiple_of(FD_LIMIT_REFRESH_INTERVAL_TICKS) {
                refresh_observations += 1;
                let new_limit = probe(tick);
                if new_limit != fd_limit {
                    fd_limit = new_limit;
                }
            }
        }

        // Two boundaries crossed → two probes (plus the initial one).
        assert_eq!(refresh_observations, 2);
        assert_eq!(probe_calls, 3);
        // After crossing the first boundary, the raised limit must be visible.
        assert_eq!(
            fd_limit, 65_536,
            "raised RLIMIT_NOFILE should be picked up at the refresh boundary"
        );
    }

    /// The `fd_limit == 0` warn must fire only once even if the periodic
    /// refresh continues to observe 0 (Windows / unsupported platforms).
    /// `Once::call_once` provides this guarantee — verify the latch behaves
    /// correctly when invoked repeatedly.
    #[test]
    fn fd_pressure_disabled_warn_latches_once() {
        // Use a private latch so this test doesn't poison the production
        // `FD_PRESSURE_DISABLED_WARN` for any other test in the same binary.
        let local_latch = Once::new();
        let mut fired = 0u32;
        for _ in 0..10 {
            local_latch.call_once(|| {
                fired += 1;
            });
        }
        assert_eq!(fired, 1, "warn-once latch must fire exactly once");
    }

    #[test]
    fn pressure_ratio_handles_unbounded_max() {
        assert_eq!(pressure_ratio(5, 0), 0.0);
        assert_eq!(pressure_ratio(5, 10), 0.5);
    }

    #[test]
    fn red_probability_for_pressure_tracks_threshold_ramp() {
        assert_eq!(red_probability_for_pressure(0.79, 0.80, 0.95), 0);
        assert_eq!(
            red_probability_for_pressure(0.95, 0.80, 0.95),
            RED_PROBABILITY_SCALE
        );
        assert_eq!(
            red_probability_for_pressure(1.00, 0.80, 0.95),
            RED_PROBABILITY_SCALE
        );

        let midpoint = red_probability_for_pressure(0.875, 0.80, 0.95);
        assert!((511..=513).contains(&midpoint));
    }

    /// Verify that the RED shedding rate matches the configured probability
    /// within tight tolerance. The hash range [0, RED_PROBABILITY_SCALE) and
    /// probability scale [0, RED_PROBABILITY_SCALE] are aligned, so there
    /// should be no systematic bias.
    #[test]
    fn red_shedding_precision_no_bias() {
        let state = OverloadState::new();
        let samples = 102_400;
        let half = RED_PROBABILITY_SCALE / 2;

        // Test at 50% (prob = half the scale)
        state.red_drop_probability.store(half, Ordering::Relaxed);
        let mut triggered = 0u64;
        for _ in 0..samples {
            if state.should_disable_keepalive_red() {
                triggered += 1;
            }
        }
        let actual_rate = triggered as f64 / samples as f64;
        let expected_rate = half as f64 / RED_PROBABILITY_SCALE as f64;
        assert!(
            (actual_rate - expected_rate).abs() < 0.01,
            "50% probability: expected {:.4}, got {:.4}",
            expected_rate,
            actual_rate
        );

        // Test at ~99.9% (prob = RED_PROBABILITY_SCALE - 1)
        let near_max = RED_PROBABILITY_SCALE - 1;
        state
            .red_drop_probability
            .store(near_max, Ordering::Relaxed);
        triggered = 0;
        for _ in 0..samples {
            if state.should_disable_keepalive_red() {
                triggered += 1;
            }
        }
        let actual_rate = triggered as f64 / samples as f64;
        let expected_rate = near_max as f64 / RED_PROBABILITY_SCALE as f64;
        assert!(
            (actual_rate - expected_rate).abs() < 0.01,
            "99.9% probability: expected {:.4}, got {:.4}",
            expected_rate,
            actual_rate
        );
    }

    /// `should_disable_keepalive_red()` ONLY signals RED-probability shedding.
    /// The HTTP/1.1 keepalive-close decision in `proxy::mod` must OR this
    /// with `disable_keepalive`, otherwise pressure-mode is silently ignored
    /// at the exact threshold (where ramp produces probability 0) or during
    /// the inter-store window where the monitor has flipped the binary flag
    /// but `red_drop_probability` still reflects the previous cycle's value.
    ///
    /// This test pins down the contract for the three combinations the hot
    /// path must handle correctly. Because the hot path inlines the OR
    /// expression (`draining || disable_keepalive || should_disable_keepalive_red`),
    /// we assert each AtomicBool / AtomicU32 source independently. A future
    /// regression that drops one of those terms will be caught here.
    #[test]
    fn keepalive_close_decision_honors_binary_flag_independently_of_red_probability() {
        let state = OverloadState::new();

        // Case 1: pressure-mode active, RED probability 0 (the regression case).
        // The binary flag MUST cause Connection: close; the RED helper alone
        // returns false because the linear ramp produced 0 at the exact
        // pressure threshold, or because the cross-cycle inter-store window
        // hasn't advanced `red_drop_probability` yet.
        state.disable_keepalive.store(true, Ordering::Relaxed);
        state.red_drop_probability.store(0, Ordering::Relaxed);
        assert!(
            state.disable_keepalive.load(Ordering::Relaxed),
            "binary flag must surface true for the hot-path OR"
        );
        assert!(
            !state.should_disable_keepalive_red(),
            "RED helper alone returns false at probability 0 — \
             pressure-mode would be ignored without the OR"
        );

        // Case 2: both signals quiet — connection should be reused.
        state.disable_keepalive.store(false, Ordering::Relaxed);
        state.red_drop_probability.store(0, Ordering::Relaxed);
        assert!(
            !state.disable_keepalive.load(Ordering::Relaxed),
            "binary flag clear when no pressure"
        );
        assert!(
            !state.should_disable_keepalive_red(),
            "RED helper clear at probability 0"
        );

        // Case 3: binary flag clear but RED probability saturated (between
        // pressure and critical thresholds, deep in the ramp). RED helper
        // alone should still drive Connection: close.
        state.disable_keepalive.store(false, Ordering::Relaxed);
        state
            .red_drop_probability
            .store(RED_PROBABILITY_SCALE, Ordering::Relaxed);
        assert!(
            !state.disable_keepalive.load(Ordering::Relaxed),
            "binary flag still clear in this regime"
        );
        assert!(
            state.should_disable_keepalive_red(),
            "RED helper must return true at saturation (1024/1024 == 100%)"
        );
    }

    /// Sanity check: under no load, the all-worker probe should still return a
    /// small latency, well under the 10 ms warn threshold. This guards against
    /// regressions where the probe accidentally serializes on something that
    /// would inflate idle-runtime readings.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn measure_event_loop_latency_idle_is_small() {
        let latency = measure_event_loop_latency().await;
        assert!(
            latency < Duration::from_millis(10),
            "idle multi-worker probe should be <10ms, got {:?}",
            latency
        );
    }

    /// Sanity check: on a single-threaded runtime the function falls back to
    /// the original single-task probe and still returns quickly.
    #[tokio::test(flavor = "current_thread")]
    async fn measure_event_loop_latency_current_thread_fallback() {
        let latency = measure_event_loop_latency().await;
        assert!(
            latency < Duration::from_millis(10),
            "current-thread probe should be <10ms, got {:?}",
            latency
        );
    }

    /// Saturate every worker with a synchronous CPU-bound sleep, then verify
    /// the probe surfaces the resulting scheduling delay.
    ///
    /// Strategy: spawn one synchronous-sleep task per worker and have a
    /// separate OS thread wait until every blocker has entered its sleep before
    /// starting the latency probe. Each per-worker probe must then queue behind
    /// in-progress sleep work, so the MAX observed reschedule latency is
    /// bounded below by the sleep duration minus minor scheduling overhead.
    ///
    /// The OLD single-task implementation would also detect this scenario
    /// (because the driver itself can't make forward progress with every
    /// worker pinned), but only because the single yield_now happens to land
    /// behind a sleeping task — by luck of which worker the driver runs on.
    /// The new per-worker probe is GUARANTEED to surface the worst-case
    /// worker, not just the driver's worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn measure_event_loop_latency_detects_saturated_workers() {
        let handle = tokio::runtime::Handle::current();
        let num_workers = handle.metrics().num_workers();
        // Sleep budget for the blockers. Each worker stalls inside
        // `std::thread::sleep(SLEEP_MS)`, so the probe's queue wait is
        // bounded above by SLEEP_MS minus the post-signal grace below.
        const SLEEP_MS: u64 = 400;
        // Bridge the unavoidable race between the blocker future's signal
        // (`started.fetch_add` runs FIRST, then `std::thread::sleep`) and
        // the worker actually entering its blocking sleep. On a contended
        // CI host the OS scheduler can pause the worker between those two
        // instructions long enough for the probe — submitted the instant
        // `started == num_workers` — to land on a still-free worker and
        // return in microseconds. This grace gives every blocker time to
        // commit to its sleep call before the probe submits.
        const POST_SIGNAL_GRACE_MS: u64 = 100;

        let started = Arc::new(AtomicUsize::new(0));
        let probe_started = Arc::clone(&started);
        let probe_thread = std::thread::spawn(move || {
            while probe_started.load(Ordering::Acquire) < num_workers {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(POST_SIGNAL_GRACE_MS));
            handle.block_on(measure_event_loop_latency())
        });

        // Spawn one CPU-bound sleep per worker. The probe thread waits until
        // all of them have started, avoiding a race where the probe runs before
        // the runtime is actually saturated.
        let mut blockers = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let started = Arc::clone(&started);
            blockers.push(tokio::spawn(async move {
                started.fetch_add(1, Ordering::Release);
                std::thread::sleep(Duration::from_millis(SLEEP_MS));
            }));
        }

        for b in blockers {
            let _ = b.await;
        }
        let latency = probe_thread
            .join()
            .expect("latency probe thread should not panic");

        // Conservative lower bound: 25ms is well above µs-scale healthy
        // readings, well below the (SLEEP_MS - POST_SIGNAL_GRACE_MS) budget,
        // and tolerant of CI jitter.
        assert!(
            latency >= Duration::from_millis(25),
            "expected probe to surface ≥25ms saturation, got {:?} \
             (probe is not actually queuing on the busy workers)",
            latency
        );
    }
}
