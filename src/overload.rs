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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

    // ── Graceful shutdown drain ────────────────────────────────────────
    /// Set to true when SIGTERM/SIGINT is received to begin the drain phase.
    pub draining: AtomicBool,
    /// In-flight connection counter. Incremented on accept, decremented on drop
    /// via [`ConnectionGuard`].
    pub active_connections: AtomicU64,
    /// Notified each time `active_connections` reaches zero during drain.
    pub drain_complete: tokio::sync::Notify,

    // ── Snapshot for admin endpoint (written by monitor, read by admin) ─
    pub fd_current: AtomicU64,
    pub fd_max: AtomicU64,
    pub conn_current: AtomicU64,
    pub conn_max: AtomicU64,
    pub loop_latency_us: AtomicU64,
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
            draining: AtomicBool::new(false),
            active_connections: AtomicU64::new(0),
            drain_complete: tokio::sync::Notify::new(),
            fd_current: AtomicU64::new(0),
            fd_max: AtomicU64::new(0),
            conn_current: AtomicU64::new(0),
            conn_max: AtomicU64::new(0),
            loop_latency_us: AtomicU64::new(0),
        }
    }

    /// Current overload level derived from the action flags.
    pub fn level(&self) -> OverloadLevel {
        if self.reject_new_connections.load(Ordering::Relaxed) {
            OverloadLevel::Critical
        } else if self.disable_keepalive.load(Ordering::Relaxed) {
            OverloadLevel::Pressure
        } else {
            OverloadLevel::Normal
        }
    }

    /// Build a JSON-serializable snapshot for the admin endpoint.
    pub fn snapshot(&self) -> OverloadSnapshot {
        let fd_current = self.fd_current.load(Ordering::Relaxed);
        let fd_max = self.fd_max.load(Ordering::Relaxed);
        let conn_current = self.conn_current.load(Ordering::Relaxed);
        let conn_max = self.conn_max.load(Ordering::Relaxed);
        OverloadSnapshot {
            level: self.level(),
            draining: self.draining.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
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
                event_loop_latency_us: self.loop_latency_us.load(Ordering::Relaxed),
            },
            actions: ActionSnapshot {
                disable_keepalive: self.disable_keepalive.load(Ordering::Relaxed),
                reject_new_connections: self.reject_new_connections.load(Ordering::Relaxed),
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

// ── Serializable snapshot types ──────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct OverloadSnapshot {
    pub level: OverloadLevel,
    pub draining: bool,
    pub active_connections: u64,
    pub pressure: PressureSnapshot,
    pub actions: ActionSnapshot,
}

#[derive(Debug, serde::Serialize)]
pub struct PressureSnapshot {
    pub file_descriptors: FdPressure,
    pub connections: ConnPressure,
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
pub struct ActionSnapshot {
    pub disable_keepalive: bool,
    pub reject_new_connections: bool,
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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_millis(config.check_interval_ms);
        let fd_limit = get_fd_limit();

        // Store the FD limit once (doesn't change during runtime)
        state.fd_max.store(fd_limit, Ordering::Relaxed);
        state
            .conn_max
            .store(max_connections as u64, Ordering::Relaxed);

        info!(
            "Overload monitor started (interval={}ms, fd_limit={}, max_conn={})",
            config.check_interval_ms, fd_limit, max_connections
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

            // ── Event loop latency ──
            let loop_latency = measure_event_loop_latency().await;
            let loop_us = loop_latency.as_micros() as u64;
            state.loop_latency_us.store(loop_us, Ordering::Relaxed);

            // ── Evaluate thresholds and set action flags ──
            let should_disable_keepalive = fd_ratio >= config.fd_pressure_threshold
                || conn_ratio >= config.conn_pressure_threshold;

            let should_reject = fd_ratio >= config.fd_critical_threshold
                || conn_ratio >= config.conn_critical_threshold
                || loop_us >= config.loop_critical_us;

            // Transition logging — only log when state changes
            let was_rejecting = state.reject_new_connections.load(Ordering::Relaxed);
            let was_keepalive_disabled = state.disable_keepalive.load(Ordering::Relaxed);

            state
                .disable_keepalive
                .store(should_disable_keepalive, Ordering::Relaxed);
            state
                .reject_new_connections
                .store(should_reject, Ordering::Relaxed);

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
                    loop_latency_us = loop_us,
                    "Overload recovered: accepting new connections",
                );
            } else if should_disable_keepalive && !was_keepalive_disabled {
                warn!(
                    level = "pressure",
                    action = "disable_keepalive",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
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

/// Wait for all in-flight connections to drain, up to the configured timeout.
///
/// Called after the accept loops have exited. Returns `true` if all connections
/// drained within the timeout, `false` if the timeout expired.
pub async fn wait_for_drain(state: &Arc<OverloadState>, timeout: Duration) -> bool {
    state.draining.store(true, Ordering::Relaxed);

    let active = state.active_connections.load(Ordering::Relaxed);
    if active == 0 {
        info!(phase = "drain", "No active connections to drain");
        return true;
    }

    info!(
        phase = "drain",
        active_connections = active,
        timeout_seconds = timeout.as_secs(),
        "Draining active connections",
    );

    match tokio::time::timeout(timeout, async {
        loop {
            if state.active_connections.load(Ordering::Relaxed) == 0 {
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
                "All connections drained successfully"
            );
            true
        }
        Err(_) => {
            let remaining = state.active_connections.load(Ordering::Relaxed);
            warn!(
                phase = "drain",
                result = "timeout",
                remaining_connections = remaining,
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
        assert!(!state.draining.load(Ordering::Relaxed));
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
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

    #[tokio::test]
    async fn wait_for_drain_returns_immediately_when_empty() {
        let state = Arc::new(OverloadState::new());
        let drained = wait_for_drain(&state, Duration::from_secs(1)).await;
        assert!(drained);
    }

    #[tokio::test]
    async fn wait_for_drain_times_out() {
        let state = Arc::new(OverloadState::new());
        let _guard = ConnectionGuard::new(&state);
        // Hold the guard so drain can't complete
        let drained = wait_for_drain(&state, Duration::from_millis(50)).await;
        assert!(!drained);
    }

    #[test]
    fn snapshot_reflects_state() {
        let state = OverloadState::new();
        state.fd_current.store(800, Ordering::Relaxed);
        state.fd_max.store(1000, Ordering::Relaxed);
        state.conn_current.store(850, Ordering::Relaxed);
        state.conn_max.store(1000, Ordering::Relaxed);
        state.loop_latency_us.store(500, Ordering::Relaxed);
        state.draining.store(true, Ordering::Relaxed);

        let snap = state.snapshot();
        assert_eq!(snap.level, OverloadLevel::Normal);
        assert!(snap.draining);
        assert_eq!(snap.pressure.file_descriptors.current, 800);
        assert_eq!(snap.pressure.file_descriptors.max, 1000);
        assert!((snap.pressure.file_descriptors.ratio - 0.8).abs() < 0.001);
        assert_eq!(snap.pressure.connections.current, 850);
        assert_eq!(snap.pressure.event_loop_latency_us, 500);
        assert!(!snap.actions.disable_keepalive);
        assert!(!snap.actions.reject_new_connections);
    }

    #[test]
    fn overload_config_defaults() {
        let config = OverloadConfig::default();
        assert_eq!(config.check_interval_ms, 1000);
        assert!((config.fd_pressure_threshold - 0.80).abs() < 0.001);
        assert!((config.fd_critical_threshold - 0.95).abs() < 0.001);
        assert!((config.conn_pressure_threshold - 0.85).abs() < 0.001);
        assert!((config.conn_critical_threshold - 0.95).abs() < 0.001);
        assert_eq!(config.loop_warn_us, 10_000);
        assert_eq!(config.loop_critical_us, 500_000);
    }

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
}
