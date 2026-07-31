use std::sync::atomic::AtomicU64;

pub struct ControllerMetrics {
    pub reconciliations: AtomicU64,
    pub full_syncs: AtomicU64,
    pub errors: AtomicU64,
    pub last_reconcile_duration_ms: AtomicU64,
    /// Rotating Gateway API status-plan cursor (#2397). Advanced after each
    /// budgeted planning pass so every eligible resource eventually enters the
    /// fair work window.
    pub gateway_api_status_plan_cursor: AtomicU64,
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
            gateway_api_status_plan_cursor: AtomicU64::new(0),
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
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub reconciliations: u64,
    pub full_syncs: u64,
    pub errors: u64,
    pub last_reconcile_duration_ms: u64,
}
