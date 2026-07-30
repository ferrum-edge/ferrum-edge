//! Shared retained-byte budgets for plugin-owned queues, caches, and snapshots.
//!
//! Count caps alone cannot bound attacker-shaped retained values. Callers
//! reserve a provisional lease before cloning, serializing, or constructing
//! retained data; shrink it to the exact retained size after measurement; and
//! release it on drop (or when ownership moves downstream).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use serde_json::Value;
use tracing::warn;

/// Default process-wide retained-byte ceiling shared by every observability
/// sink instance (256 MiB — one instance's `HARD_MAX_BUFFER_MAX_BYTES`).
pub const PROCESS_MAX_RETAINED_BYTES_DEFAULT: usize = 268_435_456;
/// Smallest admitted process ceiling. Below this a single default-configured
/// sink could not retain one maximum record.
pub const PROCESS_MAX_RETAINED_BYTES_MIN: usize = 1_048_576;
/// Largest admitted process ceiling (2 GiB).
pub const PROCESS_MAX_RETAINED_BYTES_MAX: usize = 2_147_483_648;

/// A retained-byte ceiling: a shared `used`/`max` pair with rejection and
/// high-water accounting.
///
/// One `'static` instance ([`process_ceiling`]) is the process-wide ceiling
/// every observability sink reserves against. The type is public so external
/// tests can exercise saturation against their *own* leaked instance without
/// perturbing the process-global counter that concurrently running tests in
/// the same binary depend on.
#[derive(Debug)]
pub struct RetainedByteCeiling {
    used: AtomicUsize,
    max: AtomicUsize,
    rejections: AtomicU64,
    high_water: AtomicUsize,
}

impl RetainedByteCeiling {
    pub const fn new(max_bytes: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max: AtomicUsize::new(max_bytes),
            rejections: AtomicU64::new(0),
            high_water: AtomicUsize::new(0),
        }
    }

    /// Install a new ceiling. Values outside the documented clamp are brought
    /// into range rather than rejected.
    pub fn set_max(&self, max_bytes: usize) {
        self.max.store(
            max_bytes.clamp(
                PROCESS_MAX_RETAINED_BYTES_MIN,
                PROCESS_MAX_RETAINED_BYTES_MAX,
            ),
            Ordering::Release,
        );
    }

    /// Install an exact ceiling with no clamping. Test-only: saturation
    /// coverage needs ceilings far below the production minimum.
    // The binary target never calls this; external unit tests do.
    #[allow(dead_code)]
    pub fn set_max_unclamped_for_test(&self, max_bytes: usize) {
        self.max.store(max_bytes, Ordering::Release);
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::Acquire)
    }

    pub fn rejections(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    pub fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Acquire)
    }

    /// Reserve `bytes` against this ceiling. Returns `None` once the ceiling is
    /// reached; the caller must not retain the payload.
    pub fn try_acquire(&'static self, bytes: usize) -> Option<ProcessByteReservation> {
        if bytes == 0 {
            return Some(ProcessByteReservation {
                ceiling: self,
                bytes: AtomicUsize::new(0),
            });
        }
        let max = self.max.load(Ordering::Acquire);
        match self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= max)
            }) {
            Ok(previous) => {
                self.high_water
                    .fetch_max(previous.saturating_add(bytes), Ordering::AcqRel);
                Some(ProcessByteReservation {
                    ceiling: self,
                    bytes: AtomicUsize::new(bytes),
                })
            }
            Err(_) => {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

/// The process-wide retained-byte ceiling shared by every observability sink.
static PROCESS_CEILING: RetainedByteCeiling =
    RetainedByteCeiling::new(PROCESS_MAX_RETAINED_BYTES_DEFAULT);

/// Handle on the process-wide ceiling.
// The binary target reaches the ceiling through the wrappers below; external
// tests use this handle directly.
#[allow(dead_code)]
pub fn process_ceiling() -> &'static RetainedByteCeiling {
    &PROCESS_CEILING
}

/// Install the process-wide retained-byte ceiling.
///
/// Called once from `main` before mode dispatch, alongside
/// [`crate::observability_delivery::initialize`]. Values outside the
/// documented clamp are brought into range rather than rejected, matching the
/// pre-existing task-budget behavior; the admin/plugin configuration surfaces
/// that operators actually author still fail closed on unsafe values.
pub fn initialize_process_retained_byte_ceiling(max_bytes: usize) {
    PROCESS_CEILING.set_max(max_bytes);
}

/// Bytes retained across all observability sinks right now.
pub fn process_retained_bytes() -> usize {
    PROCESS_CEILING.used()
}

/// Configured process-wide retained-byte ceiling.
pub fn process_max_retained_bytes() -> usize {
    PROCESS_CEILING.max()
}

/// Admissions refused because the process ceiling — not the per-instance
/// budget — was exhausted.
pub fn process_ceiling_rejections() -> u64 {
    PROCESS_CEILING.rejections()
}

/// Peak process-wide retention observed since startup.
pub fn process_retained_bytes_high_water() -> usize {
    PROCESS_CEILING.high_water()
}

// ---------------------------------------------------------------------------
// Batch-materialization loss accounting.
//
// `process_ceiling_rejections` counts refused *reservations*. One refusal can
// discard anywhere from one record to a whole batch, so it must never be read
// as a record-loss count. These counters are the record-scale companion, and
// the diagnostics they emit are sampled so a saturated ceiling — which is
// exactly when the process is already under memory pressure — cannot produce an
// unbounded warning stream.
// ---------------------------------------------------------------------------

/// Sampling period for batch-materialization loss and fallback warnings.
const BATCH_DIAGNOSTIC_WARN_EVERY: u64 = 100;

/// Records (log entries / spans / rows) discarded because their batch
/// representation could not be materialized.
static BATCH_LOST_RECORDS: AtomicU64 = AtomicU64::new(0);
/// Discard events, each of which lost one or more records.
static BATCH_LOSS_EVENTS: AtomicU64 = AtomicU64::new(0);
/// Batches delivered in a degraded-but-complete form (for example uncompressed
/// because the compressed representation could not be reserved). No record loss.
static BATCH_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Account `records` lost by `sink` and emit a sampled, fixed-label warning.
///
/// `reason` must be a compiled-in label such as
/// [`PayloadMaterializationError::reason`] — never a serializer message, and
/// never anything derived from payload content.
pub fn record_batch_materialization_loss(sink: &'static str, records: u64, reason: &'static str) {
    BATCH_LOST_RECORDS.fetch_add(records, Ordering::Relaxed);
    let events = BATCH_LOSS_EVENTS
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if events == 1 || events.is_multiple_of(BATCH_DIAGNOSTIC_WARN_EVERY) {
        warn!(
            plugin = sink,
            "{}: discarded a batch before delivery because {} ({} records lost in this batch; \
             {} loss events total; logging every {} events)",
            sink,
            reason,
            records,
            events,
            BATCH_DIAGNOSTIC_WARN_EVERY,
        );
    }
}

/// Account a degraded-but-complete delivery by `sink` and emit a sampled,
/// fixed-label warning. No records are lost on this path.
pub fn record_batch_materialization_fallback(sink: &'static str, reason: &'static str) {
    let events = BATCH_FALLBACKS
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if events == 1 || events.is_multiple_of(BATCH_DIAGNOSTIC_WARN_EVERY) {
        warn!(
            plugin = sink,
            "{}: delivering a batch in a degraded representation because {} ({} fallbacks total; \
             logging every {} events)",
            sink,
            reason,
            events,
            BATCH_DIAGNOSTIC_WARN_EVERY,
        );
    }
}

/// Records lost to refused batch materialization since startup.
pub fn batch_materialization_lost_records() -> u64 {
    BATCH_LOST_RECORDS.load(Ordering::Relaxed)
}

/// Discard events (not records) since startup.
pub fn batch_materialization_loss_events() -> u64 {
    BATCH_LOSS_EVENTS.load(Ordering::Relaxed)
}

/// Degraded-but-complete deliveries since startup.
pub fn batch_materialization_fallbacks() -> u64 {
    BATCH_FALLBACKS.load(Ordering::Relaxed)
}

/// One reservation against a [`RetainedByteCeiling`].
///
/// Every observability sink budget — [`ByteBudget::new_observability`] and the
/// sink-private budgets in `loki_logging`, `ws_logging`, `kafka_logging`, and
/// `otel_tracing` — reserves against the process ceiling in addition to its own
/// per-instance budget, so N configured instances cannot multiply past the
/// process total. Release is on drop, so cancellation and rejected-handoff
/// paths cannot leak the reservation.
#[derive(Debug)]
pub struct ProcessByteReservation {
    ceiling: &'static RetainedByteCeiling,
    bytes: AtomicUsize,
}

impl ProcessByteReservation {
    /// Reserve `bytes` against the process-wide ceiling.
    pub fn try_acquire(bytes: usize) -> Option<Self> {
        PROCESS_CEILING.try_acquire(bytes)
    }

    /// Shrink a provisional reservation down to the exact retained size.
    pub fn shrink_to(&self, exact: usize) {
        let current = self.bytes.load(Ordering::Acquire);
        if exact >= current {
            return;
        }
        if self
            .bytes
            .compare_exchange(current, exact, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.ceiling
                .used
                .fetch_sub(current - exact, Ordering::AcqRel);
        }
    }

    /// Explicitly release the remaining reservation (idempotent).
    pub fn release(&self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.ceiling.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    /// Bytes still held by this reservation.
    // Read by external unit tests only.
    #[allow(dead_code)]
    pub fn reserved(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

impl Drop for ProcessByteReservation {
    fn drop(&mut self) {
        self.release();
    }
}

/// A reservation against a [`RetainedByteCeiling`] whose size changes over the
/// life of the state it charges.
///
/// [`ProcessByteReservation`] fits a payload that is sized once and then held.
/// Long-lived, incrementally mutated retained state — a snapshot accumulator
/// that admits and evicts identities, a recovery payload whose exact size is
/// only known after it is built — needs to grow and shrink instead. Growth
/// fails closed when the ceiling is exhausted; shrinking is saturating, so a
/// double release can never underflow the shared counter. Drop releases
/// whatever is still held, which covers cancellation, panic unwinding, and
/// ordinary teardown alike.
#[derive(Debug)]
pub struct GrowableProcessReservation {
    ceiling: &'static RetainedByteCeiling,
    held: AtomicUsize,
}

impl GrowableProcessReservation {
    pub fn new(ceiling: &'static RetainedByteCeiling) -> Self {
        Self {
            ceiling,
            held: AtomicUsize::new(0),
        }
    }

    /// Charge `bytes` in addition to what is already held. Returns `false` when
    /// the ceiling refused, in which case nothing was charged and the caller
    /// must not allocate.
    pub fn try_grow(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        let Some(reservation) = self.ceiling.try_acquire(bytes) else {
            return false;
        };
        // Take ownership of the accepted bytes: zeroing the handle disarms its
        // `Drop`, so the charge moves to `held` rather than being released.
        let accepted = reservation.bytes.swap(0, Ordering::AcqRel);
        self.held.fetch_add(accepted, Ordering::AcqRel);
        true
    }

    /// Release up to `bytes` of the held charge. Saturating: releasing more
    /// than is held releases exactly what is held.
    pub fn shrink_by(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut released = 0usize;
        let _ = self
            .held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                released = held.min(bytes);
                Some(held - released)
            });
        if released != 0 {
            self.ceiling.used.fetch_sub(released, Ordering::AcqRel);
        }
    }

    /// Release the entire held charge (idempotent).
    pub fn release_all(&self) {
        let released = self.held.swap(0, Ordering::AcqRel);
        if released != 0 {
            self.ceiling.used.fetch_sub(released, Ordering::AcqRel);
        }
    }

    /// Bytes currently charged by this reservation.
    // Read by external unit tests only; the binary target cannot observe them.
    #[allow(dead_code)]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

impl Drop for GrowableProcessReservation {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// Reserve `bound` bytes against `ceiling` **before** the buffer exists, hand
/// the zeroed buffer to `fill`, and wrap however many bytes `fill` reports into
/// an owned payload that keeps holding the reservation.
///
/// This is the companion of [`materialize_reserved_payload`] for producers that
/// need a contiguous `&mut [u8]` rather than a [`Write`] sink — notably
/// one-shot compressors. `fill` must return the number of leading bytes it
/// wrote; a larger value is rejected as [`PayloadMaterializationError::BoundExceeded`]
/// rather than trusted.
pub fn materialize_reserved_buffer<F>(
    ceiling: &'static RetainedByteCeiling,
    bound: usize,
    fill: F,
) -> Result<ReservedPayload, PayloadMaterializationError>
where
    F: FnOnce(&mut [u8]) -> Result<usize, String>,
{
    let reservation = ceiling
        .try_acquire(bound)
        .ok_or(PayloadMaterializationError::CeilingExhausted)?;
    let mut buffer = vec![0u8; bound];
    let written = fill(&mut buffer).map_err(|_| PayloadMaterializationError::WriteFailed)?;
    if written > bound {
        return Err(PayloadMaterializationError::BoundExceeded);
    }
    buffer.truncate(written);
    // The provisional `bound`-sized allocation is returned; charge only what
    // the truncated buffer still retains for the payload's lifetime.
    buffer.shrink_to_fit();
    reservation.shrink_to(buffer.capacity());
    Ok(ReservedPayload {
        bytes: Bytes::from(buffer),
        _reservation: reservation,
    })
}

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
    ceiling: Option<&'static RetainedByteCeiling>,
}

impl ByteBudget {
    pub fn new(plugin_name: &'static str, max_bytes: usize) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes: max_bytes.max(1),
            drops: AtomicU64::new(0),
            plugin_name,
            ceiling: None,
        }
    }

    /// Construct an observability budget charged against the process ceiling.
    pub fn new_observability(plugin_name: &'static str, max_bytes: usize) -> Self {
        Self::with_ceiling(plugin_name, max_bytes, process_ceiling())
    }

    /// Construct a budget bound to an explicit ceiling.
    ///
    /// Observability production callers use [`new_observability`](Self::new_observability).
    /// External tests pass their own leaked ceiling so saturation and
    /// byte-accounting assertions stay exact while other tests in the same
    /// binary run concurrently.
    // The binary target uses the named constructors; external unit tests use this.
    #[allow(dead_code)]
    pub fn with_ceiling(
        plugin_name: &'static str,
        max_bytes: usize,
        ceiling: &'static RetainedByteCeiling,
    ) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes: max_bytes.max(1),
            drops: AtomicU64::new(0),
            plugin_name,
            ceiling: Some(ceiling),
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
                process: self.ceiling.and_then(|ceiling| ceiling.try_acquire(0)),
            }));
        }
        // The shared ceiling is taken first so a per-instance reservation is
        // never left held while the aggregate reservation fails.
        let process = if let Some(ceiling) = self.ceiling {
            let Some(process) = ceiling.try_acquire(bytes) else {
                self.record_drop("process-wide retained-byte ceiling exhausted");
                return None;
            };
            Some(process)
        } else {
            None
        };
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            drop(process);
            self.record_drop("retained-byte budget exhausted");
            return None;
        }
        Some(Arc::new(ByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
            process,
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
    /// Optional matching reservation against the process-wide ceiling. When
    /// present, it is shrunk and released with the per-instance reservation.
    process: Option<ProcessByteReservation>,
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
                if let Some(process) = &self.process {
                    process.shrink_to(exact);
                }
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
        if let Some(process) = &self.process {
            process.release();
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

// ---------------------------------------------------------------------------
// Bounded batch materialization.
//
// A queued entry's lease covers the entry itself. Delivery workers additionally
// materialize a batch into a contiguous wire payload — and, for some sinks, an
// intermediate `serde_json::Value` tree and/or a compressed buffer — all of
// which coexist with the still-charged queue. Those copies are attacker-shaped,
// so they are reserved against the process ceiling *before* anything is cloned,
// serialized, or compressed, and held until the payload and every retry that
// reuses it are gone.
//
// The materialization charge goes to the process ceiling only, never to the
// per-instance budget: that budget is already committed to the queued entries,
// so charging it a second time would refuse every batch a full queue produces.
// ---------------------------------------------------------------------------

/// Worst-case bytes one raw string byte occupies once serialized as a JSON
/// string value: `serde_json` escapes a control byte as `\u00XX`.
pub const JSON_STRING_WORST_CASE_EXPANSION: usize = 6;

/// Worst-case expansion for text that is *already* valid JSON being re-embedded
/// as a JSON string value. Such text carries no raw control bytes (the inner
/// serializer already escaped them), so only `"` and `\` can still expand, and
/// each expands to exactly two bytes.
pub const JSON_REEMBEDDED_WORST_CASE_EXPANSION: usize = 2;

/// Initial capacity for a bounded payload buffer. Growth stays geometric but is
/// capped at the reserved bound so the reservation covers the real allocation.
const BOUNDED_PAYLOAD_INITIAL_CAPACITY: usize = 8_192;

/// Why a bounded batch payload could not be materialized.
///
/// Every variant maps to a fixed label, so drop diagnostics and metrics never
/// carry payload content or a serializer message built from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadMaterializationError {
    /// Computing the reserved upper bound overflowed `usize`.
    BoundOverflowed,
    /// The retained-byte ceiling refused the reserved upper bound.
    CeilingExhausted,
    /// Writing produced more bytes than the reserved upper bound allowed.
    BoundExceeded,
    /// The serializer or compressor itself failed.
    WriteFailed,
}

impl PayloadMaterializationError {
    /// Fixed label for metrics and redacted diagnostics.
    pub fn reason(self) -> &'static str {
        match self {
            Self::BoundOverflowed => "batch payload byte bound overflowed",
            Self::CeilingExhausted => "process-wide observability retained-byte ceiling exhausted",
            Self::BoundExceeded => "batch payload exceeded its reserved byte bound",
            Self::WriteFailed => "batch payload serialization failed",
        }
    }
}

impl std::fmt::Display for PayloadMaterializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason())
    }
}

/// Byte sink for a bounded batch payload.
///
/// Fails closed once `max_bytes` would be exceeded and never grows its
/// allocation past `max_bytes`, so the reservation taken for `max_bytes` covers
/// the buffer's real allocation for the writer's whole life.
#[derive(Debug)]
pub struct BoundedPayloadWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedPayloadWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(BOUNDED_PAYLOAD_INITIAL_CAPACITY)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedPayloadWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "bounded observability batch payload exceeded its reserved byte bound",
            ));
        }
        if self.bytes.capacity() - self.bytes.len() < buf.len() {
            // `buf` fits inside `max_bytes` (checked above), so the target is
            // always at least `len + buf.len()` and the subtraction cannot wrap.
            let target = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(self.bytes.len().saturating_add(buf.len()))
                .min(self.max_bytes);
            self.bytes.reserve_exact(target - self.bytes.len());
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An owned, immutable delivery payload whose bytes stay charged to a
/// [`RetainedByteCeiling`] for the payload's entire lifetime.
///
/// Retries clone [`ReservedPayload::bytes`], which is a refcount bump, so N
/// attempts never re-serialize or deep-copy an attacker-shaped batch.
#[derive(Debug)]
pub struct ReservedPayload {
    bytes: Bytes,
    /// Released on drop — that is, once the payload and every retry handle
    /// derived from it are gone, on success, error, and cancellation alike.
    _reservation: ProcessByteReservation,
}

impl ReservedPayload {
    /// Refcounted handle for one delivery attempt. No payload bytes are copied.
    pub fn bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Companion to [`ReservedPayload::len`], required by
    /// `clippy::len_without_is_empty`. No sink needs it — every caller either
    /// measures the payload or hands it to delivery — so it is dead in the
    /// binary target, which does not compile the `_test_support` wrappers.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Reserve `bound` bytes against `ceiling` **before** anything is written, run
/// `write` into a writer that fails closed at `bound`, and hand back an owned
/// payload that keeps holding the reservation.
///
/// `bound` is a fail-closed provisional ceiling (typically a worst-case JSON
/// framing/escaping estimate). After a successful write the buffer is
/// `shrink_to_fit`'d and the reservation shrinks to the buffer's exact retained
/// `capacity`, so escape-expanded bodies stay fully charged while ordinary
/// payloads do not pin the provisional over-estimate for the delivery lifetime.
/// Every failure path drops the reservation exactly once.
pub fn materialize_reserved_payload<F>(
    ceiling: &'static RetainedByteCeiling,
    bound: usize,
    write: F,
) -> Result<ReservedPayload, PayloadMaterializationError>
where
    F: FnOnce(&mut BoundedPayloadWriter) -> Result<(), String>,
{
    let reservation = ceiling
        .try_acquire(bound)
        .ok_or(PayloadMaterializationError::CeilingExhausted)?;
    let mut writer = BoundedPayloadWriter::new(bound);
    let outcome = write(&mut writer);
    if writer.limit_exceeded {
        return Err(PayloadMaterializationError::BoundExceeded);
    }
    if outcome.is_err() {
        return Err(PayloadMaterializationError::WriteFailed);
    }
    // `Bytes` retains the `Vec`'s allocation, so charge capacity — not `len` —
    // after discarding unused spare capacity from geometric growth.
    writer.bytes.shrink_to_fit();
    reservation.shrink_to(writer.bytes.capacity());
    Ok(ReservedPayload {
        bytes: Bytes::from(writer.bytes),
        _reservation: reservation,
    })
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
