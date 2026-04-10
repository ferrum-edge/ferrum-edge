//! Windowed rate metrics computed from cumulative counters.
//!
//! A background task snapshots `ProxyState.request_count` and
//! `ProxyState.status_counts` every `window_seconds` and stores the
//! per-second averages in [`WindowedMetrics`].  The admin `/status`
//! endpoint reads these with a single `AtomicU64::load(Relaxed)` per
//! field — zero contention with the proxy hot path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;

/// Per-second rate averages over a configurable window.
///
/// Written exclusively by [`start_metrics_monitor`]; read by
/// `admin::build_metrics()`.  All fields use `Ordering::Relaxed` —
/// eventual consistency is fine for admin/observability data.
pub struct WindowedMetrics {
    /// Average requests per second over the last completed window.
    pub requests_per_second: AtomicU64,
    /// Average per-second rate of each HTTP status code over the last window.
    pub status_codes_per_second: DashMap<u16, AtomicU64>,
    /// Window size in seconds (exposed in the JSON response for transparency).
    pub window_seconds: u64,
}

impl WindowedMetrics {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            requests_per_second: AtomicU64::new(0),
            status_codes_per_second: DashMap::new(),
            window_seconds,
        }
    }
}

/// Spawn a background task that computes windowed per-second rates.
///
/// The task snapshots the cumulative counters every `window_seconds`,
/// computes `(current - previous) / window_seconds`, and stores the
/// result in `windowed`.  Exits cleanly when `shutdown_rx` fires.
pub fn start_metrics_monitor(
    request_count: Arc<AtomicU64>,
    status_counts: Arc<DashMap<u16, AtomicU64>>,
    windowed: Arc<WindowedMetrics>,
    window_seconds: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(window_seconds);

        // Take the initial snapshot.
        let mut prev_requests = request_count.load(Ordering::Relaxed);
        let mut prev_status: std::collections::HashMap<u16, u64> = status_counts
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => break,
            }

            // Snapshot current values.
            let curr_requests = request_count.load(Ordering::Relaxed);
            let delta_requests = curr_requests.saturating_sub(prev_requests);
            windowed
                .requests_per_second
                .store(delta_requests / window_seconds, Ordering::Relaxed);
            prev_requests = curr_requests;

            // Status codes — iterate current counters, compute deltas.
            for entry in status_counts.iter() {
                let code = *entry.key();
                let curr = entry.value().load(Ordering::Relaxed);
                let prev = prev_status.get(&code).copied().unwrap_or(0);
                let rate = curr.saturating_sub(prev) / window_seconds;

                // Update or insert the per-second rate.
                if let Some(existing) = windowed.status_codes_per_second.get(&code) {
                    existing.value().store(rate, Ordering::Relaxed);
                } else {
                    windowed
                        .status_codes_per_second
                        .insert(code, AtomicU64::new(rate));
                }

                prev_status.insert(code, curr);
            }
        }
    })
}
