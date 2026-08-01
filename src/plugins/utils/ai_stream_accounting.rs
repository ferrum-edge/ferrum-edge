//! Aggregate admission for incremental AI stream-accounting state.
//!
//! [`super::ai_stream_usage::StreamUsageScanner`] is O(1) in the length of one
//! response, but "request-scoped" is *not* the same as "bounded in aggregate".
//! Each live SSE scanner may retain up to
//! [`super::ai_stream_usage::MAX_SSE_LINE_BYTES`] (64 KiB) and each live AWS
//! event-stream scanner up to
//! [`super::ai_stream_usage::MAX_EVENT_STREAM_MESSAGE_BYTES`] (256 KiB). A
//! client that opens many concurrent model streams therefore multiplies those
//! windows without ever exceeding any per-stream cap — which is exactly the
//! resource-exhaustion shape GHSA-q2r2-6r7h-f69x asks to be bounded, only moved
//! from "retain the whole body once" to "retain a bounded window many times".
//!
//! This module supplies the missing aggregate bound: one process-wide budget of
//! *retained accounting bytes*, reserved before a scanner is constructed and
//! released when the reservation's RAII permit drops. It deliberately mirrors
//! [`super::fault_delay::FaultDelayAdmission`], the gateway's existing
//! process-wide retention budget, so the two behave and read the same way.
//!
//! ## Why a byte budget rather than a stream count
//!
//! The two supported wire formats have a 4× difference in worst-case retention.
//! A count-based cap would either under-bound memory (sized for SSE) or
//! needlessly refuse SSE streams (sized for the AWS framing). Charging each
//! admission its format's worst-case window makes the configured number mean
//! exactly what an operator wants it to mean: the ceiling on memory this
//! subsystem may hold.
//!
//! ## Hot-path properties
//!
//! Admission is one relaxed load plus one CAS, performed **once per stream** —
//! never per chunk. Release is one relaxed subtract. There are no locks, no
//! allocations, and nothing here runs for traffic the limiter does not meter.

use std::sync::atomic::{AtomicU64, Ordering};

/// Default process-wide ceiling on retained stream-accounting bytes.
///
/// 64 MiB admits ~1024 concurrent SSE scanners or ~256 concurrent AWS
/// event-stream scanners — far above any realistic AI streaming fan-out on one
/// gateway process, and small enough that the subsystem can never be the thing
/// that exhausts a node.
pub const DEFAULT_MAX_STREAM_ACCOUNTING_BYTES: u64 = 64 * 1024 * 1024;

/// Smallest budget that will ever be installed.
///
/// A misconfigured (or `0`) budget must not silently become "no AI streaming
/// accounting at all". Below this floor a single AWS event-stream scanner could
/// not be admitted, so every Bedrock stream would fall to the unmetered posture
/// — a configuration cliff, not a bound. `0` selects the compiled-in default
/// (the `FERRUM_POOL_SHARD_AMOUNT` convention), and anything positive is raised
/// to at least one worst-case scanner.
pub const MIN_STREAM_ACCOUNTING_BYTES: u64 =
    super::ai_stream_usage::MAX_EVENT_STREAM_MESSAGE_BYTES as u64;

/// Bounded, process-wide budget of retained stream-accounting bytes.
///
/// One production instance ([`STREAM_ACCOUNTING_ADMISSION`]) backs every
/// `ai_rate_limiter` instance in the process, so the bound covers aggregate
/// exposure across proxies and across co-located limiter instances rather than
/// per policy. Tests construct their own instance instead of mutating global
/// state.
#[derive(Debug)]
pub struct StreamAccountingAdmission {
    capacity_bytes: AtomicU64,
    in_flight_bytes: AtomicU64,
    /// Monotonic count of refused admissions, for tests and future telemetry.
    refusals: AtomicU64,
}

impl StreamAccountingAdmission {
    /// Construct a budget with a fixed initial capacity in bytes.
    pub const fn new(capacity_bytes: u64) -> Self {
        Self {
            capacity_bytes: AtomicU64::new(capacity_bytes),
            in_flight_bytes: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        }
    }

    /// Replace the capacity. Called once at startup from `EnvConfig`.
    ///
    /// `0` restores [`DEFAULT_MAX_STREAM_ACCOUNTING_BYTES`]; any positive value
    /// is raised to [`MIN_STREAM_ACCOUNTING_BYTES`] so at least one worst-case
    /// scanner always fits. See [`MIN_STREAM_ACCOUNTING_BYTES`] for why this
    /// bound has no "disable everything" degenerate value.
    pub fn set_capacity_bytes(&self, capacity_bytes: u64) {
        let effective = if capacity_bytes == 0 {
            DEFAULT_MAX_STREAM_ACCOUNTING_BYTES
        } else {
            capacity_bytes.max(MIN_STREAM_ACCOUNTING_BYTES)
        };
        self.capacity_bytes.store(effective, Ordering::Release);
    }

    /// Current capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes.load(Ordering::Acquire)
    }

    /// Bytes currently reserved by live scanners.
    #[allow(dead_code)] // used by external tests; dead in the binary target
    pub fn in_flight_bytes(&self) -> u64 {
        self.in_flight_bytes.load(Ordering::Acquire)
    }

    /// Admissions refused because the budget was exhausted.
    #[allow(dead_code)] // used by external tests; dead in the binary target
    pub fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Acquire)
    }

    /// Reserve `bytes` of retained accounting state, or return `None` when the
    /// budget is exhausted.
    ///
    /// The reservation is taken *before* the scanner is constructed, so an
    /// admitted scanner can never push the process past the configured bound,
    /// and the slot is released the moment the permit drops — including on
    /// clean EOF, streaming error, client disconnect, deadline, plugin
    /// rejection, task cancellation, and panic unwind.
    pub fn try_admit(&self, bytes: u64) -> Option<StreamAccountingPermit<'_>> {
        let capacity = self.capacity_bytes();
        let mut observed = self.in_flight_bytes.load(Ordering::Acquire);
        loop {
            // `bytes` is a compiled-in per-format constant, so the sum cannot
            // realistically overflow; a checked add keeps that an invariant
            // rather than an assumption.
            let Some(next) = observed.checked_add(bytes) else {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if next > capacity {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match self.in_flight_bytes.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(StreamAccountingPermit {
                        admission: self,
                        bytes,
                    });
                }
                Err(current) => observed = current,
            }
        }
    }
}

/// RAII reservation of retained stream-accounting bytes, released on drop.
///
/// Held for the complete lifetime of the accounting state it authorizes: the
/// request context that pre-admitted it keeps one reference for the whole
/// request, and the streaming inspector that owns the scanner keeps another for
/// the whole body task. The budget is returned only once both are gone, so a
/// stream that dies mid-flight cannot leak its reservation and a permit can
/// never be released while its scanner is still allocated.
#[derive(Debug)]
pub struct StreamAccountingPermit<'a> {
    admission: &'a StreamAccountingAdmission,
    bytes: u64,
}

impl StreamAccountingPermit<'_> {
    /// Bytes this permit reserved.
    pub fn reserved_bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for StreamAccountingPermit<'_> {
    fn drop(&mut self) {
        self.admission
            .in_flight_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Process-wide retained-accounting-byte budget used by production streaming
/// token accounting.
pub static STREAM_ACCOUNTING_ADMISSION: StreamAccountingAdmission =
    StreamAccountingAdmission::new(DEFAULT_MAX_STREAM_ACCOUNTING_BYTES);

/// Apply the operator-configured stream-accounting budget. Called once at
/// startup, before any listener accepts traffic.
pub fn init_stream_accounting_admission(max_bytes: u64) {
    STREAM_ACCOUNTING_ADMISSION.set_capacity_bytes(max_bytes);
}

/// Reserve one scanner's worth of aggregate accounting state on the production
/// budget.
///
/// Returns `None` when the process-wide bound is already fully committed. The
/// caller must fail closed: refuse the stream up front where the response is
/// not yet committed, or decline to attach a scanner and settle the stream
/// through the configured unmetered posture where it is.
pub fn try_admit_stream_accounting(
    format: super::ai_stream_usage::StreamUsageFormat,
) -> Option<StreamAccountingPermit<'static>> {
    STREAM_ACCOUNTING_ADMISSION.try_admit(format.retained_state_bytes())
}
