//! Overload manager with resource monitors and progressive load shedding.
//!
//! Runs a background task that periodically checks resource pressure (file
//! descriptors, connection semaphore saturation, event loop latency) and sets
//! atomic action flags that the proxy hot path reads with a single
//! `AtomicBool::load(Relaxed)` (~1ns, zero contention).
//!
//! Also provides graceful shutdown draining: after SIGTERM, tracks in-flight
//! connections and waits up to a configurable drain period for them to complete.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

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
pub struct OverloadState {
    // ── Action flags (hot-path reads) ──────────────────────────────────
    /// When true, responses include `Connection: close` to drain idle keepalives.
    pub disable_keepalive: AtomicBool,
    /// When true, new connections are rejected with 503 before routing.
    pub reject_new_connections: AtomicBool,
    /// When true, new requests/streams are rejected with 503 before processing.
    /// Independent of `reject_new_connections` — connections track sockets,
    /// requests track multiplexed H2/H3/gRPC streams.
    pub reject_new_requests: AtomicBool,

    // ── Graceful shutdown drain ────────────────────────────────────────
    /// Set to true when SIGTERM/SIGINT is received to begin the drain phase.
    pub draining: AtomicBool,
    /// In-flight connection counter. Incremented on accept, decremented on drop
    /// via [`ConnectionGuard`].
    pub active_connections: AtomicU64,
    /// In-flight request/stream counter. Incremented on request start, decremented
    /// on drop via [`RequestGuard`]. Tracks H1 requests, H2/gRPC streams, and H3
    /// streams independently of connections.
    pub active_requests: AtomicU64,
    /// Notified each time `active_connections` or `active_requests` reaches zero
    /// during drain. The drain waiter re-checks both counters in a loop.
    pub drain_complete: tokio::sync::Notify,

    // ── RED adaptive load shedding ────────────────────────────────────
    /// RED (Random Early Detection) drop probability (0-1000 scale, where 1000 = 100%).
    /// When in the pressure zone (between pressure and critical thresholds), responses
    /// are probabilistically marked with Connection: close based on this value.
    /// The hot path reads this with a single AtomicU32::load(Relaxed).
    pub red_drop_probability: AtomicU32,
    /// Monotonic request counter used as per-request entropy for RED decisions.
    /// Incremented by `fetch_add(1, Relaxed)` on each `should_disable_keepalive_red()` call.
    red_request_counter: AtomicU64,

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
}

impl Default for OverloadState {
    fn default() -> Self {
        Self::new()
    }
}

impl OverloadState {
    pub fn new() -> Self {
        Self {
            disable_keepalive: AtomicBool::new(false),
            reject_new_connections: AtomicBool::new(false),
            reject_new_requests: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            active_connections: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            drain_complete: tokio::sync::Notify::new(),
            red_drop_probability: AtomicU32::new(0),
            red_request_counter: AtomicU64::new(0),
            fd_current: AtomicU64::new(0),
            fd_max: AtomicU64::new(0),
            conn_current: AtomicU64::new(0),
            conn_max: AtomicU64::new(0),
            req_current: AtomicU64::new(0),
            req_max: AtomicU64::new(0),
            loop_latency_us: AtomicU64::new(0),
            port_exhaustion_events: AtomicU64::new(0),
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
    pub fn should_disable_keepalive_red(&self) -> bool {
        let prob = self.red_drop_probability.load(Ordering::Relaxed);
        if prob == 0 {
            return false;
        }
        if prob >= 1000 {
            return true;
        }
        // Monotonic counter ensures each call gets a unique input, producing
        // true per-response probabilistic shedding even when active_connections
        // is stable.
        let counter = self.red_request_counter.fetch_add(1, Ordering::Relaxed);
        // Golden-ratio hash: multiply and take high bits for 0-1023 range
        let hash = counter.wrapping_mul(0x9E3779B97F4A7C15) >> 54;
        (hash as u32) < prob
    }

    /// Record an ephemeral port exhaustion event (EADDRNOTAVAIL).
    /// Called from error classification sites when a connect failure is
    /// identified as port exhaustion.
    pub fn record_port_exhaustion(&self) {
        self.port_exhaustion_events.fetch_add(1, Ordering::Relaxed);
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
                / 10.0,
            port_exhaustion_events: self.port_exhaustion_events.load(Ordering::Relaxed),
            pressure: PressureSnapshot {
                file_descriptors: FdPressure {
                    current: fd_current,
                    max: fd_max,
                    ratio: if fd_max > 0 {
                        fd_current as f64 / fd_max as f64
                    } else {
                        0.0
                    },
                },
                connections: ConnPressure {
                    current: conn_current,
                    max: conn_max,
                    ratio: if conn_max > 0 {
                        conn_current as f64 / conn_max as f64
                    } else {
                        0.0
                    },
                },
                requests: ReqPressure {
                    current: req_current,
                    max: req_max,
                    ratio: if req_max > 0 {
                        req_current as f64 / req_max as f64
                    } else {
                        0.0
                    },
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
        if prev == 1 && self.state.draining.load(Ordering::Relaxed) {
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
        if prev == 1 && self.state.draining.load(Ordering::Relaxed) {
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
    pub pressure: PressureSnapshot,
    pub actions: ActionSnapshot,
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
fn count_open_fds() -> u64 {
    // On Linux, /proc/self/fd is the canonical way to count open FDs.
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn count_open_fds() -> u64 {
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
fn count_open_fds() -> u64 {
    0 // FD monitoring not available on this platform
}

/// Get the maximum file descriptor limit (soft limit) via getrlimit.
fn get_fd_limit() -> u64 {
    #[cfg(unix)]
    {
        // rlimit struct: two u64 fields (rlim_cur, rlim_max) on 64-bit platforms
        let mut rlim: [u64; 2] = [0, 0];
        // RLIMIT_NOFILE is typically 7 on Linux, 8 on macOS — use platform constant
        #[cfg(target_os = "linux")]
        const RLIMIT_NOFILE: i32 = 7;
        #[cfg(target_os = "macos")]
        const RLIMIT_NOFILE: i32 = 8;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        const RLIMIT_NOFILE: i32 = 8; // BSD default

        unsafe extern "C" {
            fn getrlimit(resource: i32, rlim: *mut [u64; 2]) -> i32;
        }
        let result = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
        if result == 0 { rlim[0] } else { 0 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Measure event loop latency by yielding and measuring the scheduling delay.
async fn measure_event_loop_latency() -> Duration {
    let start = std::time::Instant::now();
    tokio::task::yield_now().await;
    start.elapsed()
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
        let fd_limit = get_fd_limit();

        // Store limits once (don't change during runtime)
        state.fd_max.store(fd_limit, Ordering::Relaxed);
        state
            .conn_max
            .store(max_connections as u64, Ordering::Relaxed);
        state.req_max.store(max_requests as u64, Ordering::Relaxed);

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

            // ── FD pressure ──
            let fd_current = count_open_fds();
            state.fd_current.store(fd_current, Ordering::Relaxed);

            let fd_ratio = if fd_limit > 0 {
                fd_current as f64 / fd_limit as f64
            } else {
                0.0
            };

            // ── Connection pressure ──
            // Uses the active_connections counter maintained by ConnectionGuard
            // (covers HTTP/1.1, H2, H3, gRPC, and stream proxy connections).
            let conn_used = state.active_connections.load(Ordering::Relaxed);
            state.conn_current.store(conn_used, Ordering::Relaxed);
            let conn_ratio = if max_connections > 0 {
                conn_used as f64 / max_connections as f64
            } else {
                0.0
            };

            // ── Request pressure ──
            let req_used = state.active_requests.load(Ordering::Relaxed);
            state.req_current.store(req_used, Ordering::Relaxed);
            let req_ratio = if max_requests > 0 {
                req_used as f64 / max_requests as f64
            } else {
                0.0 // unlimited — never triggers pressure
            };

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

            // Request-level rejection is independent — only triggers when
            // FERRUM_MAX_REQUESTS is configured (non-zero).
            let should_reject_requests =
                max_requests > 0 && req_ratio >= config.req_critical_threshold;

            // ── RED-style smooth ramp between pressure and critical thresholds ──
            // For BOTH fd and connection pressure, compute probability independently
            // and take the max. This gives a smooth ramp from 0% at the pressure
            // threshold to 100% at the critical threshold.
            let fd_red_prob = if fd_ratio >= config.fd_critical_threshold {
                1000 // 100% drop
            } else if fd_ratio >= config.fd_pressure_threshold {
                let range = config.fd_critical_threshold - config.fd_pressure_threshold;
                let position = fd_ratio - config.fd_pressure_threshold;
                ((position / range) * 1000.0) as u32
            } else {
                0
            };
            let conn_red_prob = if conn_ratio >= config.conn_critical_threshold {
                1000 // 100% drop
            } else if conn_ratio >= config.conn_pressure_threshold {
                let range = config.conn_critical_threshold - config.conn_pressure_threshold;
                let position = conn_ratio - config.conn_pressure_threshold;
                ((position / range) * 1000.0) as u32
            } else {
                0
            };
            let req_red_prob = if max_requests > 0 {
                if req_ratio >= config.req_critical_threshold {
                    1000
                } else if req_ratio >= config.req_pressure_threshold {
                    let range = config.req_critical_threshold - config.req_pressure_threshold;
                    let position = req_ratio - config.req_pressure_threshold;
                    ((position / range) * 1000.0) as u32
                } else {
                    0
                }
            } else {
                0
            };
            state.red_drop_probability.store(
                fd_red_prob.max(conn_red_prob).max(req_red_prob),
                Ordering::Relaxed,
            );

            // Transition logging — only log when state changes
            let was_rejecting = state.reject_new_connections.load(Ordering::Relaxed);
            let was_rejecting_requests = state.reject_new_requests.load(Ordering::Relaxed);
            let was_keepalive_disabled = state.disable_keepalive.load(Ordering::Relaxed);

            state
                .disable_keepalive
                .store(should_disable_keepalive, Ordering::Relaxed);
            state
                .reject_new_connections
                .store(should_reject, Ordering::Relaxed);
            state
                .reject_new_requests
                .store(should_reject_requests, Ordering::Relaxed);

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

/// Wait for all in-flight connections and requests to drain, up to the
/// configured timeout.
///
/// Called after the accept loops have exited. Returns `true` if all connections
/// and requests drained within the timeout, `false` if the timeout expired.
pub async fn wait_for_drain(state: &Arc<OverloadState>, timeout: Duration) -> bool {
    state.draining.store(true, Ordering::Relaxed);

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

    #[test]
    fn overload_state_defaults_to_normal() {
        let state = OverloadState::new();
        assert_eq!(state.level(), OverloadLevel::Normal);
        assert!(!state.disable_keepalive.load(Ordering::Relaxed));
        assert!(!state.reject_new_connections.load(Ordering::Relaxed));
        assert!(!state.reject_new_requests.load(Ordering::Relaxed));
        assert!(!state.draining.load(Ordering::Relaxed));
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.red_drop_probability.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn overload_level_pressure() {
        let state = OverloadState::new();
        state.disable_keepalive.store(true, Ordering::Relaxed);
        assert_eq!(state.level(), OverloadLevel::Pressure);
    }

    #[test]
    fn overload_level_critical() {
        let state = OverloadState::new();
        state.reject_new_connections.store(true, Ordering::Relaxed);
        assert_eq!(state.level(), OverloadLevel::Critical);
    }

    #[test]
    fn overload_level_critical_from_request_rejection() {
        let state = OverloadState::new();
        state.reject_new_requests.store(true, Ordering::Relaxed);
        assert_eq!(state.level(), OverloadLevel::Critical);
    }

    #[test]
    fn connection_guard_increments_and_decrements() {
        let state = Arc::new(OverloadState::new());
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
        {
            let _g1 = ConnectionGuard::new(&state);
            assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
            {
                let _g2 = ConnectionGuard::new(&state);
                assert_eq!(state.active_connections.load(Ordering::Relaxed), 2);
            }
            assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        }
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn drain_notifies_on_last_connection() {
        let state = Arc::new(OverloadState::new());
        state.draining.store(true, Ordering::Relaxed);

        let guard = ConnectionGuard::new(&state);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        let state2 = state.clone();
        let handle = tokio::spawn(async move {
            // Wait for drain notification
            state2.drain_complete.notified().await;
            assert_eq!(state2.active_connections.load(Ordering::Relaxed), 0);
        });

        // Drop the guard, which should notify
        drop(guard);

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout")
            .expect("task panicked");
    }

    #[test]
    fn request_guard_increments_and_decrements() {
        let state = Arc::new(OverloadState::new());
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
        {
            let _g1 = RequestGuard::new(&state);
            assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);
            {
                let _g2 = RequestGuard::new(&state);
                assert_eq!(state.active_requests.load(Ordering::Relaxed), 2);
            }
            assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);
        }
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn drain_notifies_on_last_request() {
        let state = Arc::new(OverloadState::new());
        state.draining.store(true, Ordering::Relaxed);

        let guard = RequestGuard::new(&state);
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);

        let state2 = state.clone();
        let handle = tokio::spawn(async move {
            state2.drain_complete.notified().await;
            assert_eq!(state2.active_requests.load(Ordering::Relaxed), 0);
        });

        drop(guard);

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn wait_for_drain_returns_immediately_when_empty() {
        let state = Arc::new(OverloadState::new());
        let drained = wait_for_drain(&state, Duration::from_secs(1)).await;
        assert!(drained);
    }

    #[tokio::test]
    async fn wait_for_drain_times_out_with_active_requests() {
        let state = Arc::new(OverloadState::new());
        let _guard = RequestGuard::new(&state);
        // Hold the request guard so drain can't complete
        let drained = wait_for_drain(&state, Duration::from_millis(50)).await;
        assert!(!drained);
    }

    #[tokio::test]
    async fn wait_for_drain_times_out() {
        let state = Arc::new(OverloadState::new());
        let _guard = ConnectionGuard::new(&state);
        // Hold the guard so drain can't complete
        let drained = wait_for_drain(&state, Duration::from_millis(50)).await;
        assert!(!drained);
    }

    #[tokio::test]
    async fn drain_waits_for_both_connections_and_requests() {
        let state = Arc::new(OverloadState::new());
        let conn_guard = ConnectionGuard::new(&state);
        let req_guard = RequestGuard::new(&state);

        let state2 = state.clone();
        let drain_handle =
            tokio::spawn(async move { wait_for_drain(&state2, Duration::from_secs(5)).await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drop requests first — drain should NOT complete (connections still active)
        drop(req_guard);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!drain_handle.is_finished());

        // Drop connections — now drain should complete
        drop(conn_guard);
        let result = tokio::time::timeout(Duration::from_secs(2), drain_handle)
            .await
            .expect("timeout")
            .expect("panic");
        assert!(result);
    }

    #[test]
    fn snapshot_reflects_state() {
        let state = OverloadState::new();
        state.fd_current.store(800, Ordering::Relaxed);
        state.fd_max.store(1000, Ordering::Relaxed);
        state.conn_current.store(850, Ordering::Relaxed);
        state.conn_max.store(1000, Ordering::Relaxed);
        state.req_current.store(5000, Ordering::Relaxed);
        state.req_max.store(10000, Ordering::Relaxed);
        state.loop_latency_us.store(500, Ordering::Relaxed);
        state.draining.store(true, Ordering::Relaxed);

        let snap = state.snapshot();
        assert_eq!(snap.level, OverloadLevel::Normal);
        assert!(snap.draining);
        assert_eq!(snap.pressure.file_descriptors.current, 800);
        assert_eq!(snap.pressure.file_descriptors.max, 1000);
        assert!((snap.pressure.file_descriptors.ratio - 0.8).abs() < 0.001);
        assert_eq!(snap.pressure.connections.current, 850);
        assert_eq!(snap.pressure.requests.current, 5000);
        assert_eq!(snap.pressure.requests.max, 10000);
        assert!((snap.pressure.requests.ratio - 0.5).abs() < 0.001);
        assert_eq!(snap.pressure.event_loop_latency_us, 500);
        assert!(!snap.actions.disable_keepalive);
        assert!(!snap.actions.reject_new_connections);
        assert!(!snap.actions.reject_new_requests);
    }

    #[test]
    fn overload_config_defaults() {
        let config = OverloadConfig::default();
        assert_eq!(config.check_interval_ms, 1000);
        assert!((config.fd_pressure_threshold - 0.80).abs() < 0.001);
        assert!((config.fd_critical_threshold - 0.95).abs() < 0.001);
        assert!((config.conn_pressure_threshold - 0.85).abs() < 0.001);
        assert!((config.conn_critical_threshold - 0.95).abs() < 0.001);
        assert!((config.req_pressure_threshold - 0.85).abs() < 0.001);
        assert!((config.req_critical_threshold - 0.95).abs() < 0.001);
        assert_eq!(config.loop_warn_us, 10_000);
        assert_eq!(config.loop_critical_us, 500_000);
    }

    #[cfg(unix)]
    #[test]
    fn fd_limit_is_nonzero() {
        assert!(get_fd_limit() > 0, "FD limit should be > 0 on Unix");
    }

    #[test]
    fn red_probability_zero_never_triggers() {
        let state = OverloadState::new();
        // prob = 0, should never trigger
        for _ in 0..100 {
            assert!(!state.should_disable_keepalive_red());
        }
    }

    #[test]
    fn red_probability_max_always_triggers() {
        let state = OverloadState::new();
        state.red_drop_probability.store(1000, Ordering::Relaxed);
        for _ in 0..100 {
            assert!(state.should_disable_keepalive_red());
        }
    }

    #[test]
    fn red_probability_partial_distributes_across_requests() {
        let state = OverloadState::new();
        state.red_drop_probability.store(500, Ordering::Relaxed);
        // At 50% probability, a run of 1000 calls should produce a mix of
        // true and false — not all-or-nothing.
        let mut true_count = 0u32;
        let total = 1000u32;
        for _ in 0..total {
            if state.should_disable_keepalive_red() {
                true_count += 1;
            }
        }
        // Expect roughly 50% ± generous margin (golden-ratio hash is uniform
        // but not perfectly so over small windows).
        assert!(
            true_count > 200 && true_count < 800,
            "expected ~50% true, got {true_count}/{total}"
        );
    }

    #[test]
    fn snapshot_includes_red_probability() {
        let state = OverloadState::new();
        state.red_drop_probability.store(500, Ordering::Relaxed);
        let snap = state.snapshot();
        assert!((snap.red_drop_probability_pct - 50.0).abs() < 0.1);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fd_count_is_nonzero() {
        let count = count_open_fds();
        assert!(count > 0, "Process should have at least some open FDs");
    }
}
