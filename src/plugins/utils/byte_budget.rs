//! Shared retained-byte budgets for plugin-owned queues, caches, and snapshots.
//!
//! Count caps alone cannot bound attacker-shaped retained values. Callers
//! reserve a provisional lease before cloning, serializing, or constructing
//! retained data; shrink it to the exact retained size after measurement; and
//! release it on drop (or when ownership moves downstream).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::Value;
use tracing::warn;

/// Default per-entry retained-byte ceiling for summary log sinks.
pub const DEFAULT_MAX_ENTRY_BYTES: usize = 65_536;
/// Hard maximum for a single admitted observability record.
pub const HARD_MAX_ENTRY_BYTES: usize = 1_048_576;
/// Default aggregate retained-content budget across one sink instance.
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 16_777_216;
/// Hard maximum aggregate retained-content budget for one sink instance.
pub const HARD_MAX_BUFFER_MAX_BYTES: usize = 268_435_456;
/// Minimum admitted `max_entry_bytes` (keeps truncating serializers useful).
pub const MIN_MAX_ENTRY_BYTES: usize = 1_024;
/// Retained copies charged for a queued summary and its contiguous delivery
/// payload. Retries share the queued `Arc<str>` and run sequentially.
pub const SUMMARY_ENTRY_RETAINED_COPIES: usize = 2;
/// Per-record JSON array / NDJSON framing allowance.
pub const SUMMARY_ENTRY_FRAMING_BYTES: usize = 1;

const DROP_WARN_EVERY: u64 = 100;

/// Atomic aggregate byte budget with lease-based release.
#[derive(Debug)]
pub struct ByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    drops: AtomicU64,
    plugin_name: &'static str,
}

impl ByteBudget {
    pub fn new(plugin_name: &'static str, max_bytes: usize) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes: max_bytes.max(1),
            drops: AtomicU64::new(0),
            plugin_name,
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    // Read by external unit tests; the binary target compiles this shared
    // module separately and cannot observe those callers.
    #[allow(dead_code)]
    pub fn drops_total(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Reserve `bytes` against the aggregate budget. Returns `None` on
    /// saturation; callers must not retain the payload.
    pub fn try_acquire(&self, bytes: usize) -> Option<Arc<ByteLease>> {
        if bytes == 0 {
            return Some(Arc::new(ByteLease {
                used_bytes: Arc::clone(&self.used_bytes),
                bytes: AtomicUsize::new(0),
            }));
        }
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            self.record_drop("retained-byte budget exhausted");
            return None;
        }
        Some(Arc::new(ByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
        }))
    }

    pub fn record_drop(&self, reason: &'static str) {
        let dropped = self.drops.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(DROP_WARN_EVERY) {
            warn!(
                plugin = self.plugin_name,
                "{}: dropping retained admission because {} ({} dropped total; logging every {} drops)",
                self.plugin_name,
                reason,
                dropped,
                DROP_WARN_EVERY,
            );
        }
    }
}

/// One retained-byte lease. Cloning the `Arc` shares ownership; the budget is
/// released only when the last handle drops (or [`ByteLease::release`] runs).
#[derive(Debug)]
pub struct ByteLease {
    used_bytes: Arc<AtomicUsize>,
    bytes: AtomicUsize,
}

impl ByteLease {
    /// Shrink a provisional reservation down to the exact retained size.
    pub fn shrink_to(&self, exact: usize) {
        let current = self.bytes.load(Ordering::Acquire);
        if exact >= current {
            return;
        }
        let release = current - exact;
        match self
            .bytes
            .compare_exchange(current, exact, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                self.used_bytes.fetch_sub(release, Ordering::AcqRel);
            }
            Err(_) => {
                // Concurrent shrink/release already moved the lease; ignore.
            }
        }
    }

    /// Explicitly release remaining bytes (idempotent).
    pub fn release(&self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        self.release();
    }
}

/// JSON writer that fails closed once `max_bytes` would be exceeded.
#[derive(Debug)]
pub struct BoundedJsonWriter {
    pub bytes: Vec<u8>,
    max_bytes: usize,
    pub limit_exceeded: bool,
}

impl BoundedJsonWriter {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized observability entry exceeded its byte limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Admitted `max_entry_bytes` / `buffer_max_bytes` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedByteLimits {
    pub max_entry_bytes: usize,
    pub buffer_max_bytes: usize,
}

/// Conservative bytes charged for one serialized summary while it is queued
/// and copied into a contiguous HTTP/TCP/UDP delivery payload.
pub const fn accounted_summary_bytes(serialized_bytes: usize) -> usize {
    serialized_bytes
        .saturating_add(SUMMARY_ENTRY_FRAMING_BYTES)
        .saturating_mul(SUMMARY_ENTRY_RETAINED_COPIES)
}

/// Parse shared per-entry and aggregate byte budgets from plugin config.
pub fn admit_byte_limits(
    config: &Value,
    plugin_name: &'static str,
) -> Result<AdmittedByteLimits, String> {
    let max_entry_bytes = match config.get("max_entry_bytes") {
        None => DEFAULT_MAX_ENTRY_BYTES as u64,
        Some(value) => {
            let Some(parsed) = value.as_u64() else {
                return Err(format!(
                    "{plugin_name}: 'max_entry_bytes' must be an unsigned integer"
                ));
            };
            parsed
        }
    };
    if max_entry_bytes < MIN_MAX_ENTRY_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'max_entry_bytes' must be >= {MIN_MAX_ENTRY_BYTES}"
        ));
    }
    if max_entry_bytes > HARD_MAX_ENTRY_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'max_entry_bytes' must be <= {HARD_MAX_ENTRY_BYTES}"
        ));
    }

    let buffer_max_bytes = match config.get("buffer_max_bytes") {
        None => DEFAULT_BUFFER_MAX_BYTES as u64,
        Some(value) => {
            let Some(parsed) = value.as_u64() else {
                return Err(format!(
                    "{plugin_name}: 'buffer_max_bytes' must be an unsigned integer"
                ));
            };
            parsed
        }
    };
    let minimum_buffer_bytes = accounted_summary_bytes(max_entry_bytes as usize) as u64;
    if buffer_max_bytes < minimum_buffer_bytes {
        return Err(format!(
            "{plugin_name}: 'buffer_max_bytes' must be greater than or equal to \
             {SUMMARY_ENTRY_RETAINED_COPIES} * ('max_entry_bytes' + \
             {SUMMARY_ENTRY_FRAMING_BYTES})"
        ));
    }
    if buffer_max_bytes > HARD_MAX_BUFFER_MAX_BYTES as u64 {
        return Err(format!(
            "{plugin_name}: 'buffer_max_bytes' must be <= {HARD_MAX_BUFFER_MAX_BYTES}"
        ));
    }

    Ok(AdmittedByteLimits {
        max_entry_bytes: max_entry_bytes as usize,
        buffer_max_bytes: buffer_max_bytes as usize,
    })
}
