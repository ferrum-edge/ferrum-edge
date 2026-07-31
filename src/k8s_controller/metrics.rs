use std::sync::atomic::AtomicU64;

pub struct ControllerMetrics {
    pub reconciliations: AtomicU64,
    pub full_syncs: AtomicU64,
    pub errors: AtomicU64,
    pub last_reconcile_duration_ms: AtomicU64,
    /// Reflector generations restarted because a watch scope produced no event
    /// for the configured idle window (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS`), or
    /// because a replacement generation never finished its initial list. A
    /// steadily climbing value on a busy cluster means watch deliveries are
    /// being lost somewhere between the API server and the reflector.
    pub watch_idle_relists: AtomicU64,
}

impl Default for ControllerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerMetrics {
    pub fn new() -> Self {
        Self {
            reconciliations: AtomicU64::new(0),
            full_syncs: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_reconcile_duration_ms: AtomicU64::new(0),
            watch_idle_relists: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            reconciliations: self
                .reconciliations
                .load(std::sync::atomic::Ordering::Relaxed),
            full_syncs: self.full_syncs.load(std::sync::atomic::Ordering::Relaxed),
            errors: self.errors.load(std::sync::atomic::Ordering::Relaxed),
            last_reconcile_duration_ms: self
                .last_reconcile_duration_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            watch_idle_relists: self
                .watch_idle_relists
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub reconciliations: u64,
    pub full_syncs: u64,
    pub errors: u64,
    pub last_reconcile_duration_ms: u64,
    pub watch_idle_relists: u64,
}
