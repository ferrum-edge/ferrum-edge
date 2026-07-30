//! Durable ClickHouse chargeback sink.
//!
//! This plugin is intentionally independent from `api_chargeback`: it uses the
//! same pricing parser/math but owns its queue, spool, replay, metrics, and
//! optional snapshot accumulator.
//!
//! Delivery is persistence-aware by default: HTTP 200/204 alone is not success.
//! The sink requires a complete empty acknowledgement without ClickHouse
//! exception markers/headers before counting an export or deleting spool data.
//! `wait_for_async_insert=0` is rejected unless
//! `clickhouse.allow_lossy_async_insert` is explicitly enabled.
//!
//! Construction (`new`) is runtime-free shape validation: it does not create
//! spool directories, materialize secrets, build a dedicated TLS client, spawn
//! the batching worker / background tasks, or publish accepted-generation
//! observability. Live staging happens from [`Plugin::start_background_tasks`];
//! workers stay dormant until [`Plugin::commit_background_tasks`] after
//! PluginCache publication. Observability tracks the current accepted
//! generation for every stable plugin-config ID — never a process-wide
//! last-constructor-wins singleton.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{SecondsFormat, TimeZone, Utc};
use dashmap::DashMap;
use http::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tracing::warn;
use url::Url;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use super::chargeback::pricing::{ChargeComputation, PricingConfig, require_finite_charge};
use super::chargeback::{HttpBillingOutcome, http_billing_outcome};
use super::utils::byte_budget::{
    GrowableProcessReservation, JSON_STRING_WORST_CASE_EXPANSION, PayloadMaterializationError,
    ProcessByteReservation, ReservedPayload, RetainedByteCeiling, materialize_reserved_buffer,
    materialize_reserved_payload, process_ceiling,
};
use super::utils::response_body::{BoundedReadError, read_response_body_bounded};
use super::utils::{
    BatchConfig, BatchingLogger, ByteBudget, ByteLease, DEFAULT_BUFFER_MAX_BYTES,
    HARD_MAX_BUFFER_MAX_BYTES, HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT, LoggerHooks,
    MAX_BATCH_FLUSH_INTERVAL_MS, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, PluginHttpClient,
    RetryPolicy, TrySendOutcome, redacted_endpoint_url, redacted_endpoint_url_str,
    wait_until_committed, wait_until_committed_or_closed,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::dns::DnsCacheResolver;
use crate::observability_delivery::DeliveryWorkerControl;
use crate::plugins::utils::log_schema::view::status_class;
use crate::plugins::utils::log_schema::{
    DerivedKind, FieldSpec, MetadataPolicy, SchemaCapabilities, SchemaSerializable, SchemaView,
    SummarySchema, TimestampFormat, resolve_schema,
};
use tokio::sync::mpsc;

const PLUGIN_NAME: &str = "api_chargeback_sink";
const STREAM_STATUS_SENTINEL: u16 = 0;
const DEFAULT_PRICING_VERSION: &str = "default";
const DEFAULT_CURRENCY: &str = "USD";
const DEFAULT_SPOOL_DIR: &str = "/var/lib/ferrum/chargeback-spool";
const STATUS_CACHE_TTL: Duration = Duration::from_secs(1);
const SNAPSHOT_FINALIZE_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_FINALIZE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FIELD_LEN: usize = 512;
const MAX_METADATA_FIELD_LEN: usize = 256;
/// Conservative ceiling for one owned [`ChargeEvent`] after field bounding.
const MAX_CHARGE_EVENT_BYTES: usize = 96 + (MAX_FIELD_LEN * 16) + (MAX_METADATA_FIELD_LEN * 4);
const SPOOL_WARN_INTERVAL_SECS: i64 = 60;
const SPOOL_JOB_WARN_EVERY: u64 = 100;
/// Bound refreshes when another process mutates the shared spool during quota eviction.
const SPOOL_QUOTA_MAX_INVENTORY_PASSES: u64 = 8;
const GRPC_STATUS_OTHER_SENTINEL: u32 = u32::MAX;
/// Versioned on-disk ownership format for managed chargeback spool trees.
const SPOOL_FORMAT_VERSION: u32 = 1;
const SPOOL_META_FILENAME: &str = "spool.meta.json";
const SPOOL_OWNER_DIGEST_DOMAIN: &[u8] = b"ferrum-edge/api_chargeback_sink/spool-owner\0";
/// Hex characters of the ownership digest kept in the namespace path component.
const SPOOL_OWNER_DIGEST_LEN: usize = 32;
/// Hex characters of the ownership digest embedded in every managed filename.
const SPOOL_OWNER_TAG_LEN: usize = 32;
/// Owner-tag length written by the original version-1 spool format.
const SPOOL_LEGACY_OWNER_TAG_LEN: usize = 16;
const SPOOL_INFLIGHT_SUFFIX: &str = ".inflight";
const SPOOL_CLAIM_MARKER: &str = ".claim-";
const SPOOL_WRITE_MARKER: &str = ".write-";
const SPOOL_TMP_SUFFIX: &str = ".tmp";
/// Bound recursive spool walks (day dirs + namespace depth headroom).
const MAX_SPOOL_TRAVERSAL_DEPTH: u32 = 8;
/// Hard cap on directory entries visited by one bounded tree walk, and on the
/// aggregate legacy/sibling-namespace portion of the unbound-record scan.
/// Counting directories and symlinks as well as regular files prevents an
/// attacker-controlled tree of empty directories from escaping the bound.
const MAX_SPOOL_TRAVERSAL_ENTRIES: usize = 100_000;
/// Production age before a foreign or unattributable temp may be reconciled.
const STALE_TEMP_AGE_SECS: u64 = 300;
/// Floor for the in-flight replay claim lease derived from the configured
/// ClickHouse delivery budget.
const SPOOL_CLAIM_LEASE_MIN_SECS: u64 = 300;
/// Safety multiplier applied to the worst-case delivery budget so an expiring
/// lease cannot overtake a delivery that is still legitimately in progress.
const SPOOL_CLAIM_LEASE_BUDGET_FACTOR: u64 = 4;

fn default_buffer_max_bytes() -> usize {
    DEFAULT_BUFFER_MAX_BYTES
}

fn default_spool_delivery_queue_capacity() -> usize {
    4_096
}

/// Deployment-safe ceiling for ClickHouse export attempt count (total attempts,
/// including the initial try). Rejects the historical silent `.max(1)` rewrite
/// of `0` and unbounded `u32::MAX` budgets that can pin the sole flush worker.
const MAX_RETRY_MAX_ATTEMPTS: u32 = 32;
/// Deployment-safe ceiling for each configured inter-attempt delay field
/// (`retry.initial_delay_ms` and `retry.max_delay_ms`).
const MAX_RETRY_DELAY_MS: u64 = 60_000;
/// Bound on how far one compressed spool record may expand during replay.
///
/// JSONEachRow charge batches normally compress at roughly 5-20x, so a 200x
/// allowance accepts ordinary zstd artifacts while a planted high-ratio archive
/// inside the managed tree cannot expand without limit inside the billing
/// process. The writer pads an unusually compressible legitimate frame with a
/// zstd skippable frame when needed, so every compressed artifact it publishes
/// remains within this ratio and replayable. An over-limit planted record is
/// quarantined, never silently dropped.
const SPOOL_MAX_DECOMPRESSION_RATIO: u64 = 200;
/// Floor for the expansion allowance so a very small legitimate record is never
/// bounded below its own framing overhead.
const SPOOL_MIN_DECOMPRESSED_BYTES: u64 = 1024 * 1024;
/// Hard ceiling for both encoded and decoded bytes in one spool artifact.
///
/// This matches the process-wide retained-byte ceiling accepted for sink
/// buffers. The writer refuses a larger artifact, so replay never rejects a
/// record this build successfully published. The absolute bound complements
/// the ratio check: a ratio alone still permits a multi-gigabyte allocation
/// when a same-UID attacker plants a large archive in the managed tree.
const SPOOL_MAX_ARTIFACT_BYTES: u64 = HARD_MAX_BUFFER_MAX_BYTES as u64;
// `spool_decompression_limit` clamps into this range, and `clamp` panics when
// the upper bound is below the lower one. Prove the ordering at compile time so
// the replay path can never panic inside the billing process.
const _: () = assert!(SPOOL_MIN_DECOMPRESSED_BYTES <= SPOOL_MAX_ARTIFACT_BYTES);
/// Headroom added to `ZSTD_compressBound` for the reserved compression buffer.
///
/// `compress_bound` already covers the worst-case incompressible expansion plus
/// the frame header this build asks for (the one-shot API records the
/// decompressed size). The slack only guards against a future zstd frame-format
/// addition; an under-sized buffer would fail closed, never truncate.
const SPOOL_ZSTD_FRAME_SLACK_BYTES: usize = 4 * 1024;
/// Decoded representations of one artifact that coexist during replay: the
/// single decoded text buffer, and the JSONEachRow request body materialized
/// for the chunk currently in flight. The largest chunk is the whole artifact,
/// so one extra decoded copy is the exact worst case.
const SPOOL_REPLAY_DECODED_COPIES: u64 = 2;
/// Reserved capacity of the 413 split worklist.
///
/// The worklist is a depth-first stack of `(start, end)` *line index* ranges. It
/// used to be allocated (and charged) at one entry per line, even though its
/// live occupancy is logarithmic — enough to deterministically exhaust the
/// ceiling for a legitimate high-row-count artifact. The real bound is:
///
/// * A pop that 413s pushes exactly two ranges partitioning the popped one, and
///   `replay_split_len` gives the **left** child `min(batch_size, len / 2)`
///   rows — never more than `len / 2`.
/// * The left child is pushed last, so it is popped first. Popping a right
///   sibling replaces the entry it occupied rather than adding one, so stack
///   occupancy grows only along a chain of successive *left* descents.
/// * Each left descent at least halves the row count, so a chain over `N` lines
///   is at most `ceil(log2(N))` long, plus the root and one pending sibling.
///
/// For any `N <= usize::MAX` that is at most `usize::BITS + 2`; the constant
/// carries extra slack. The stack is allocated at exactly this capacity,
/// reserved before it exists, and fails closed rather than growing past it — so
/// the reservation always covers the real allocation.
const SPOOL_SPLIT_WORKLIST_MAX_ENTRIES: usize = usize::BITS as usize + 4;

/// Peak retained bytes replaying one artifact requires, given the decoded byte
/// bound replay will reserve and the artifact's line count.
///
/// Replay holds, at its peak:
/// * the single decoded text buffer (`decoded_bound`);
/// * the line index, one `(start, end)` pair per line;
/// * the bounded 413 split worklist ([`SPOOL_SPLIT_WORKLIST_MAX_ENTRIES`]);
/// * one JSONEachRow request body for the chunk in flight, bounded by the
///   decoded bytes it copies plus one row separator each.
///
/// The writer refuses any artifact whose peak exceeds the configured process
/// ceiling, so an artifact this build publishes is always structurally
/// replayable under that same ceiling. Ceiling *pressure* stays retryable: the
/// claim is released and the file replays on a later tick.
fn spool_replay_peak_bytes(decoded_bound: u64, line_count: usize) -> Option<u64> {
    let line_count = u64::try_from(line_count).ok()?;
    let entry_bytes = SPOOL_INDEX_ENTRY_BYTES as u64;
    decoded_bound
        .checked_mul(SPOOL_REPLAY_DECODED_COPIES)?
        // Row separators in the materialized body.
        .checked_add(line_count)?
        // The line index.
        .checked_add(line_count.checked_mul(entry_bytes)?)?
        // The split worklist.
        .checked_add((SPOOL_SPLIT_WORKLIST_MAX_ENTRIES as u64).checked_mul(entry_bytes)?)
}
/// Bound for the ownership manifest (`spool.meta.json`).
///
/// The manifest is a small fixed-shape record, but it is read *before* this
/// owner's identity is established and on every prepare and replay listing, so
/// it is the one managed file a same-UID actor can inflate without first
/// deriving the owner tag. 64 KiB is orders of magnitude above the real record
/// and keeps a planted manifest from allocating inside the billing process.
const SPOOL_MAX_META_BYTES: usize = 64 * 1024;
/// Bound one ClickHouse attempt so the derived cross-process claim lease remains
/// finite and representable. Ten minutes is already substantially above the
/// default five-second export timeout.
const MAX_CLICKHOUSE_TIMEOUT_MS: u64 = 600_000;
/// Worst-case cumulative inter-attempt delay budget across retries after the
/// initial try (exponential/capped schedule, ignoring jitter reduction).
const MAX_RETRY_TOTAL_DELAY_MS: u64 = 600_000;
/// Hard cap on ClickHouse acknowledgement bodies retained for exception sniffing.
///
/// Successful inserts are empty; exception text is small. Bytes are classified
/// and dropped — never logged or retained beyond the drain.
const CLICKHOUSE_ACK_BODY_LIMIT_BYTES: usize = 64 * 1024;
/// ClickHouse HTTP setting that disables persistence-aware async-insert waits.
const WAIT_FOR_ASYNC_INSERT_PARAM: &str = "wait_for_async_insert";
/// Standalone / validation constructors that omit a plugin-config resource id.
/// Production `PluginCache` always supplies the configured resource id.
const DEFAULT_PLUGIN_CONFIG_ID: &str = "__standalone__";
/// Ledger identity used when a caller supplies no Ferrum namespace.
const DEFAULT_FERRUM_NAMESPACE: &str = "ferrum";

/// Accepted active sinks published after PluginCache commit. Keyed by stable
/// plugin-config ID so sibling configurations coexist while a newly accepted
/// generation atomically replaces the prior generation for the same ID. Drop
/// removes an entry only when it still points at that exact runtime.
static ACTIVE_SINKS: OnceLock<ArcSwap<BTreeMap<String, Arc<SinkRuntime>>>> = OnceLock::new();
static ACTIVE_SNAPSHOT_FINALIZATIONS: OnceLock<Mutex<BTreeMap<u64, PendingSnapshotFinalization>>> =
    OnceLock::new();
static STATUS_CACHE: OnceLock<ArcSwap<Option<(Instant, String)>>> = OnceLock::new();
static NEXT_SINK_GENERATION: AtomicU64 = AtomicU64::new(1);
static ULID_COUNTER: AtomicU64 = AtomicU64::new(0);
static ULID_RANDOM_PREFIX: OnceLock<u128> = OnceLock::new();

fn active_sinks() -> &'static ArcSwap<BTreeMap<String, Arc<SinkRuntime>>> {
    ACTIVE_SINKS.get_or_init(|| ArcSwap::from_pointee(BTreeMap::new()))
}

fn status_cache() -> &'static ArcSwap<Option<(Instant, String)>> {
    STATUS_CACHE.get_or_init(|| ArcSwap::from_pointee(None))
}

fn invalidate_status_cache() {
    status_cache().store(Arc::new(None));
}

fn active_snapshot_finalizations() -> &'static Mutex<BTreeMap<u64, PendingSnapshotFinalization>> {
    ACTIVE_SNAPSHOT_FINALIZATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Failed or in-progress snapshot finalization retained for bounded retry.
#[derive(Clone)]
enum PendingSnapshotFinalization {
    /// Full sink generation still owning accumulator/runtime state.
    Full(Arc<SnapshotLifecycle>),
    /// Compact durable-recovery payload after the heavy generation was released.
    Compact(Arc<CompactSnapshotRecovery>),
}

impl PendingSnapshotFinalization {
    fn generation(&self) -> u64 {
        match self {
            Self::Full(lifecycle) => lifecycle.generation,
            Self::Compact(recovery) => recovery.generation,
        }
    }

    fn retained_bytes(&self) -> u64 {
        match self {
            Self::Full(lifecycle) => lifecycle.retained_finalization_bytes(),
            Self::Compact(recovery) => recovery.retained_bytes as u64,
        }
    }

    fn age_secs(&self, now: Instant) -> u64 {
        match self {
            Self::Full(lifecycle) => lifecycle.closed_age_secs(now),
            Self::Compact(recovery) => now.saturating_duration_since(recovery.closed_at).as_secs(),
        }
    }

    fn is_pending(&self) -> bool {
        match self {
            Self::Full(lifecycle) => {
                lifecycle.committed.load(Ordering::Acquire)
                    && !lifecycle.accepting.load(Ordering::Acquire)
                    && !lifecycle.finalized.load(Ordering::Acquire)
            }
            Self::Compact(_) => true,
        }
    }
}

/// Compact recovery state for a failed snapshot finalization.
///
/// Retains only the pending terminal deltas and the spool handle needed to
/// retry durable handoff, instead of the full accumulator/runtime generation.
struct CompactSnapshotRecovery {
    generation: u64,
    plugin_config_id: Arc<str>,
    /// Serializes the take/write/restore transaction. An empty `events` vector
    /// is only a durable-success signal while no other retry owns the pending
    /// set outside the mutex.
    attempt_lock: Mutex<()>,
    events: Mutex<Vec<ChargeEvent>>,
    retained_bytes: usize,
    /// Process-wide charge on [`Self::events`], transferred from the Full
    /// generation's accumulator at compaction and released on drop — that is,
    /// on durable success, on abandonment, and on process teardown alike.
    _reservation: GrowableProcessReservation,
    closed_at: Instant,
    spool: Option<Arc<SpoolManager>>,
    metrics: Arc<SinkMetrics>,
}

/// Restores borrowed pending deltas to their [`CompactSnapshotRecovery`] unless
/// the handoff committed.
///
/// Retry must not clone the pending set (an uncharged full-batch copy on every
/// attempt), and it must not hold the recovery's mutex across the blocking spool
/// write. Taking ownership for the duration of the attempt satisfies both; this
/// guard makes the return path unconditional, so a panic or an early return in
/// between cannot lose a billing delta.
struct BorrowedPendingDeltas<'a> {
    recovery: &'a CompactSnapshotRecovery,
    events: Vec<ChargeEvent>,
}

impl BorrowedPendingDeltas<'_> {
    fn events(&self) -> &[ChargeEvent] {
        &self.events
    }

    /// Give up ownership after a durable write: nothing is restored.
    fn commit(mut self) -> usize {
        let count = self.events.len();
        self.events = Vec::new();
        count
    }
}

impl Drop for BorrowedPendingDeltas<'_> {
    fn drop(&mut self) {
        if self.events.is_empty() {
            return;
        }
        let mut guard = match self.recovery.events.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // A concurrent attempt may have re-published its own set; prepend ours
        // so ordering across retries stays stable and nothing is discarded.
        let mut restored = std::mem::take(&mut self.events);
        restored.append(&mut guard);
        *guard = restored;
    }
}

impl CompactSnapshotRecovery {
    fn borrow_pending(&self) -> BorrowedPendingDeltas<'_> {
        let mut guard = match self.events.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        BorrowedPendingDeltas {
            recovery: self,
            events: std::mem::take(&mut *guard),
        }
    }

    fn try_spool(&self) -> bool {
        let _attempt_guard = match self.attempt_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Ownership is taken out of the mutex, which is released before any
        // filesystem work begins. `attempt_lock` remains held until the
        // borrowed set commits or is restored, so another retry cannot mistake
        // the temporary empty vector for durable success.
        let borrowed = self.borrow_pending();
        if borrowed.events().is_empty() {
            return true;
        }
        let Some(spool) = self.spool.as_ref() else {
            self.metrics.record_failure(
                FailureReason::Serialize,
                "compact snapshot recovery requires an available spool",
            );
            return false;
        };
        if let Err(error) = spool.write_events(borrowed.events()) {
            self.metrics.spool_available.store(false, Ordering::Release);
            self.metrics.record_failure(
                FailureReason::Serialize,
                format!("compact snapshot recovery spool handoff failed: {error}"),
            );
            warn!(
                plugin = PLUGIN_NAME,
                generation = self.generation,
                plugin_config_id = %self.plugin_config_id,
                error = %error,
                "Chargeback sink compact snapshot recovery could not spool pending deltas"
            );
            // `borrowed` drops here and restores the pending set.
            return false;
        }
        let delivered = borrowed.commit();
        self.metrics
            .snapshot_emits_total
            .fetch_add(delivered as u64, Ordering::Relaxed);
        true
    }
}

fn register_snapshot_generation(lifecycle: Arc<SnapshotLifecycle>) {
    let mut generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    generations
        .entry(lifecycle.generation)
        .or_insert(PendingSnapshotFinalization::Full(lifecycle));
}

fn unregister_full_snapshot_generation(generation: u64) {
    let mut generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Full finalizers must never remove a Compact recovery that now owns the
    // generation's pending deltas after compaction.
    if matches!(
        generations.get(&generation),
        Some(PendingSnapshotFinalization::Full(_))
    ) {
        generations.remove(&generation);
    }
}

fn unregister_compact_snapshot_generation(generation: u64) {
    let mut generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    if matches!(
        generations.get(&generation),
        Some(PendingSnapshotFinalization::Compact(_))
    ) {
        generations.remove(&generation);
    }
}

fn compact_recovery_for_generation(generation: u64) -> Option<Arc<CompactSnapshotRecovery>> {
    let generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    match generations.get(&generation) {
        Some(PendingSnapshotFinalization::Compact(recovery)) => Some(Arc::clone(recovery)),
        _ => None,
    }
}

/// Retry compact recovery synchronously from non-async disposal paths.
fn try_finalize_compact_recovery_without_await(generation: u64) -> bool {
    let Some(recovery) = compact_recovery_for_generation(generation) else {
        // Compact already drained or never published.
        return true;
    };
    if recovery.try_spool() {
        unregister_compact_snapshot_generation(generation);
        invalidate_status_cache();
        true
    } else {
        false
    }
}

/// Retry compact recovery without blocking an async runtime worker on spool I/O.
async fn try_finalize_compact_recovery(generation: u64) -> bool {
    let Some(recovery) = compact_recovery_for_generation(generation) else {
        // Compact already drained or never published.
        return true;
    };
    let durable = tokio::task::spawn_blocking({
        let recovery = Arc::clone(&recovery);
        move || recovery.try_spool()
    })
    .await
    .unwrap_or(false);
    if durable {
        unregister_compact_snapshot_generation(generation);
        invalidate_status_cache();
    }
    durable
}

fn pending_snapshot_finalization_stats() -> (usize, u64, u64, usize, u64) {
    let generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    let mut pending = 0usize;
    let mut bytes = 0u64;
    let mut oldest_age = 0u64;
    let mut full = 0usize;
    let mut compact_bytes = 0u64;
    for entry in generations.values() {
        if !entry.is_pending() {
            continue;
        }
        pending = pending.saturating_add(1);
        let retained = entry.retained_bytes();
        bytes = bytes.saturating_add(retained);
        oldest_age = oldest_age.max(entry.age_secs(now));
        match entry {
            PendingSnapshotFinalization::Full(_) => full = full.saturating_add(1),
            PendingSnapshotFinalization::Compact(_) => {
                compact_bytes = compact_bytes.saturating_add(retained);
            }
        }
    }
    (pending, bytes, oldest_age, full, compact_bytes)
}

fn pending_finalization_budget_exceeded() -> bool {
    let (pending, _bytes, _age, _full, compact_bytes) = pending_snapshot_finalization_stats();
    pending >= MAX_PENDING_SNAPSHOT_FINALIZATIONS
        || compact_bytes >= MAX_COMPACT_SNAPSHOT_RECOVERY_BYTES as u64
}

/// Stop snapshot admission and durably spool every generation's final delta.
///
/// Serving modes call this after request/connection drain. Reload disposal
/// follows the same exact-once lifecycle from [`Drop for ApiChargebackSink`].
pub async fn finalize_all_snapshot_generations() {
    let generations: Vec<PendingSnapshotFinalization> = {
        let generations = match active_snapshot_finalizations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        generations.values().cloned().collect()
    };
    futures_util::future::join_all(generations.iter().map(finalize_pending_snapshot)).await;
}

/// Finalize the generation being retired and retry every older generation
/// whose bounded handoff previously failed. Retrying the retained set on each
/// later reload prevents a persistent spool outage from accumulating
/// never-revisited generations until process shutdown.
async fn finalize_snapshot_generation_and_pending(current: Arc<SnapshotLifecycle>) {
    let mut pending = Vec::new();
    {
        let registered = match active_snapshot_finalizations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Prefer the registry mapping: a prior failed finalization may already
        // have compacted this generation to Compact recovery state. Always
        // wrapping as Full would skip Compact and can later clear it.
        match registered.get(&current.generation) {
            Some(entry) => pending.push(entry.clone()),
            None if !current.compacted.load(Ordering::Acquire)
                && !current.finalized.load(Ordering::Acquire) =>
            {
                pending.push(PendingSnapshotFinalization::Full(Arc::clone(&current)));
            }
            None => {}
        }
        pending.extend(
            registered
                .values()
                .filter(|entry| entry.generation() != current.generation && entry.is_pending())
                .cloned(),
        );
    }
    futures_util::future::join_all(pending.iter().map(finalize_pending_snapshot)).await;

    // Full→Compact can occur while we still hold a Full handle from the local
    // pending snapshot taken above. Retry Compact ownership for this generation.
    if current.compacted.load(Ordering::Acquire)
        || compact_recovery_for_generation(current.generation).is_some()
    {
        let _ = try_finalize_compact_recovery(current.generation).await;
    }
}

async fn finalize_pending_snapshot(pending: &PendingSnapshotFinalization) -> bool {
    match pending {
        PendingSnapshotFinalization::Full(lifecycle) => {
            lifecycle.finalize_within(SNAPSHOT_FINALIZE_TIMEOUT).await
        }
        PendingSnapshotFinalization::Compact(recovery) => {
            try_finalize_compact_recovery(recovery.generation).await
        }
    }
}

/// Reduce a Full snapshot generation to compact durable recovery, but never
/// while an admitted terminal hook or queued overflow delivery can still
/// mutate the accumulator.
///
/// Losslessness takes precedence over meeting a smaller full-generation count:
/// admission is closed first and, until both terminal-hook admission and async
/// overflow-delivery ownership are observably zero, the Full generation is
/// retained untouched (returns `false`) so a later compaction pass — the next
/// reload or shutdown — can retry after drain. The budget gate is checked
/// against the current retained estimate *before* any staged overflow is
/// drained, so a refused compaction never loses events.
///
/// Every refusal after preparation restores the staged overflow it borrowed and
/// leaves the generation's periodic emitter running, so the Full generation is
/// genuinely retained: it still owns every pending delta exactly once and still
/// has a live path to durability.
///
/// Preparation through publication runs under the generation's `emission_lock`,
/// the same lock the periodic and final emitters hold across their own
/// prepare→durable-commit sequence. That makes emission and compaction mutually
/// exclusive owners of the pending deltas: no emitter can advance the
/// accumulator baseline in the interval between the deltas compaction prepared
/// and the moment it publishes them, so the same charge cannot be emitted twice.
fn compact_snapshot_lifecycle(lifecycle: &SnapshotLifecycle) -> bool {
    compact_snapshot_lifecycle_measured(lifecycle, None)
}

/// [`compact_snapshot_lifecycle`] with a test-only override of the *measured*
/// compact payload size.
///
/// Production always passes `None` and measures the real events, so no
/// production admission decision is relaxed by this parameter. It exists only
/// so external unit tests can reach the measured-payload-exceeds-projection
/// branch — which the deliberately conservative projection bound makes
/// unreachable with honest inputs — and prove that branch keeps the staged
/// overflow and the generation's retry mechanism.
fn compact_snapshot_lifecycle_measured(
    lifecycle: &SnapshotLifecycle,
    measured_bytes_override: Option<usize>,
) -> bool {
    // Stop new admissions and require the admitted set to drain before touching
    // full-generation state. `admit()`'s double-checked `accepting` flag means
    // that once we observe `accepting == false`, `in_flight == 0`, and no
    // overflow delivery ownership, no guard or stage-back job can mutate the
    // accumulator.
    lifecycle.mark_admission_closed();
    if lifecycle.in_flight.load(Ordering::Acquire) > 0
        || lifecycle.accumulator.overflow_deliveries_in_flight() > 0
    {
        return false;
    }

    let estimated_bytes = lifecycle.accumulator.retained_bytes();
    let (pending, _bytes, _age, full, compact_bytes) = pending_snapshot_finalization_stats();
    if (compact_bytes.saturating_add(estimated_bytes as u64)
        > MAX_COMPACT_SNAPSHOT_RECOVERY_BYTES as u64
        || pending >= MAX_PENDING_SNAPSHOT_FINALIZATIONS)
        && full <= 1
    {
        warn!(
            plugin = PLUGIN_NAME,
            generation = lifecycle.generation,
            retained_bytes = estimated_bytes,
            "Chargeback sink cannot compact failed finalization; pending recovery budget exhausted"
        );
        return false;
    }

    // Admission is closed and drained; preparing the pending deltas is now
    // race-free against the request path.
    //
    // The remaining race is the generation's own periodic/final emitter, which
    // is still running: it holds `emission_lock` across its whole
    // prepare-deltas → durable-spool → advance-baseline sequence. Compaction
    // therefore takes the same lock *before* it prepares anything and keeps it
    // until Compact ownership is published and the Full accumulator is cleared.
    // Aborting the periodic task is not synchronous, so the abort alone cannot
    // close this window: without the lock an emitter could durably advance the
    // baseline after compaction snapshotted its deltas, and compaction would
    // then publish the same deltas a second time.
    //
    // Only in-memory work runs under this guard: Full→Compact preparation and
    // publication perform no filesystem or network I/O.
    let emission_guard = match lifecycle.emission_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    // The projection is a second attacker-shaped representation that coexists
    // with the still-charged accumulator, so it owns its own process-wide
    // reservation *before* it is built. On refusal the Full generation is
    // retained untouched, the emission lock is released, and compaction retries
    // later; nothing is lost.
    let projection = GrowableProcessReservation::new(process_ceiling());
    let Some(projection_bound) = lifecycle.delta_projection_bound() else {
        warn!(
            plugin = PLUGIN_NAME,
            generation = lifecycle.generation,
            "Chargeback sink compaction projection byte bound overflowed; generation retained"
        );
        return false;
    };
    if !projection.try_grow(projection_bound) {
        warn!(
            plugin = PLUGIN_NAME,
            generation = lifecycle.generation,
            projection_bound,
            "Chargeback sink cannot compact failed finalization; {}",
            PayloadMaterializationError::CeilingExhausted.reason()
        );
        return false;
    }
    let Some((events, overflow_count, overflow_retained_bytes)) =
        lifecycle.prepare_compaction_events(&emission_guard)
    else {
        // Serialize failure: keep the Full generation intact and retry later.
        // `prepare_compaction_events` already restaged its borrowed overflow.
        return false;
    };

    let retained_bytes = measured_bytes_override.unwrap_or_else(|| {
        events
            .iter()
            .map(charge_event_retained_bytes)
            .fold(0usize, usize::saturating_add)
    });
    // Transfer the projection's reservation to the Compact owner and true it up
    // to the measured retained size. A shortfall is not expected because the
    // projection bound is conservative, but it must still fail closed: retain
    // the Full generation and retry later instead of publishing an undercharged
    // compact recovery.
    //
    // This is the last refusal point, so it runs *before* the generation's
    // periodic emitter is stopped: a refusal must leave both the staged
    // overflow and the retry mechanism exactly as compaction found them.
    if retained_bytes <= projection.held() {
        projection.shrink_by(projection.held().saturating_sub(retained_bytes));
    } else if !projection.try_grow(retained_bytes.saturating_sub(projection.held())) {
        warn!(
            plugin = PLUGIN_NAME,
            generation = lifecycle.generation,
            retained_bytes,
            "Chargeback sink cannot compact failed finalization because its measured recovery payload exceeds the reserved projection; Full generation retained"
        );
        // The staged overflow was taken out of the accumulator by preparation
        // and exists nowhere else; hand it back before dropping `events`.
        lifecycle.restage_compaction_overflow(events, overflow_count, overflow_retained_bytes);
        return false;
    }

    // Past the last refusal point: compaction now commits. Stop the periodic
    // emitter for this generation. This still runs under `emission_guard`, so
    // an emitter that was already blocked on the lock (or a blocking worker the
    // abort cannot cancel) cannot slip between the prepared deltas above and
    // the publication below; it can only observe the cleared accumulator
    // afterwards, which yields no events.
    let _ = lifecycle.shutdown_tx.send(true);
    {
        let mut task = match lifecycle.task.lock() {
            Ok(task) => task,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(task) = task.take() {
            task.abort();
        }
    }

    if events.is_empty() {
        // Nothing pending to hand off; the generation is already durable. Retire
        // it as a successful finalization rather than leaking a Full entry.
        lifecycle.accumulator.clear_for_compaction();
        lifecycle.finalized.store(true, Ordering::Release);
        unregister_full_snapshot_generation(lifecycle.generation);
        // Release this generation's emission lock before compacting *other*
        // generations, so no two emission locks are ever held at once.
        drop(emission_guard);
        enforce_full_pending_finalization_bound(lifecycle.generation);
        invalidate_status_cache();
        return true;
    }

    let recovery = Arc::new(CompactSnapshotRecovery {
        generation: lifecycle.generation,
        plugin_config_id: Arc::clone(&lifecycle.runtime.plugin_config_id),
        attempt_lock: Mutex::new(()),
        events: Mutex::new(events),
        retained_bytes,
        _reservation: projection,
        closed_at: Instant::now(),
        spool: lifecycle.runtime.spool.clone(),
        metrics: Arc::clone(&lifecycle.runtime.metrics),
    });
    // Publish Compact ownership before clearing Full state so a concurrent Full
    // finalizer cannot observe an empty accumulator and unregister the generation
    // while pending deltas exist only in this stack frame.
    {
        let mut generations = match active_snapshot_finalizations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        generations.insert(
            lifecycle.generation,
            PendingSnapshotFinalization::Compact(Arc::clone(&recovery)),
        );
    }
    lifecycle.compacted.store(true, Ordering::Release);
    lifecycle.accumulator.clear_for_compaction();
    // Compact ownership is published and Full state is cleared; from here an
    // emission can safely run again — it observes an empty accumulator and
    // emits nothing. Release before compacting other generations so no two
    // emission locks are ever held at once.
    drop(emission_guard);
    enforce_full_pending_finalization_bound(lifecycle.generation);
    invalidate_status_cache();
    true
}

fn enforce_full_pending_finalization_bound(keep_generation: u64) {
    let overflow: Vec<Arc<SnapshotLifecycle>> = {
        let generations = match active_snapshot_finalizations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut full: Vec<Arc<SnapshotLifecycle>> = generations
            .values()
            .filter_map(|entry| match entry {
                PendingSnapshotFinalization::Full(lifecycle)
                    if entry.is_pending() && lifecycle.generation != keep_generation =>
                {
                    Some(Arc::clone(lifecycle))
                }
                _ => None,
            })
            .collect();
        if full.len() < MAX_FULL_PENDING_SNAPSHOT_FINALIZATIONS {
            return;
        }
        full.sort_by_key(|lifecycle| lifecycle.generation);
        let remove_count = full
            .len()
            .saturating_add(1)
            .saturating_sub(MAX_FULL_PENDING_SNAPSHOT_FINALIZATIONS);
        full.into_iter().take(remove_count).collect()
    };
    for lifecycle in overflow {
        // compact_snapshot_lifecycle closes admission and refuses (retaining the
        // Full generation) until its own in_flight drains, so an admitted hook
        // can never race the accumulator clear here.
        let _ = compact_snapshot_lifecycle(&lifecycle);
    }
}

fn register_active_sink(runtime: Arc<SinkRuntime>) {
    let key = runtime.plugin_config_id.to_string();
    active_sinks().rcu(|map| {
        if map
            .get(&key)
            .is_some_and(|existing| Arc::ptr_eq(existing, &runtime))
        {
            return Arc::clone(map);
        }
        let mut next = (**map).clone();
        next.insert(key.clone(), Arc::clone(&runtime));
        Arc::new(next)
    });
    invalidate_status_cache();
}

fn unregister_active_sink(runtime: &Arc<SinkRuntime>) {
    let key = runtime.plugin_config_id.as_ref();
    let previous = active_sinks().load_full();
    if !previous
        .get(key)
        .is_some_and(|existing| Arc::ptr_eq(existing, runtime))
    {
        return;
    }
    active_sinks().rcu(|map| {
        if !map
            .get(key)
            .is_some_and(|existing| Arc::ptr_eq(existing, runtime))
        {
            return Arc::clone(map);
        }
        let mut next = (**map).clone();
        next.remove(key);
        Arc::new(next)
    });
    invalidate_status_cache();
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SinkMode {
    #[default]
    PerEvent,
    Snapshot,
}

impl SinkMode {
    fn as_str(self) -> &'static str {
        match self {
            SinkMode::PerEvent => "per_event",
            SinkMode::Snapshot => "snapshot",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpoolCompression {
    #[default]
    Zstd,
    None,
}

impl SpoolCompression {
    fn extension(self) -> &'static str {
        match self {
            SpoolCompression::Zstd => "ndjson.zst",
            SpoolCompression::None => "ndjson",
        }
    }
}

fn default_batch_size() -> usize {
    500
}

fn default_flush_interval_ms() -> u64 {
    2_000
}

fn default_buffer_capacity() -> usize {
    50_000
}

fn default_retry_max_attempts() -> u32 {
    5
}

fn default_retry_initial_delay_ms() -> u64 {
    250
}

fn default_retry_max_delay_ms() -> u64 {
    10_000
}

fn default_retry_jitter() -> bool {
    true
}

fn default_spool_enabled() -> bool {
    true
}

fn default_spool_dir() -> PathBuf {
    PathBuf::from(DEFAULT_SPOOL_DIR)
}

fn default_spool_max_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_spool_replay_interval_secs() -> u64 {
    60
}

fn default_snapshot_interval_secs() -> u64 {
    30
}

fn default_snapshot_cleanup_interval_secs() -> u64 {
    300
}

fn default_snapshot_stale_entry_ttl_secs() -> u64 {
    3_600
}

fn default_snapshot_max_entries() -> usize {
    100_000
}

fn default_snapshot_max_retained_bytes() -> usize {
    64 * 1024 * 1024
}

/// Ceiling on full failed-finalization generations retained in memory.
/// Additional failures compact to [`CompactSnapshotRecovery`] instead.
const MAX_FULL_PENDING_SNAPSHOT_FINALIZATIONS: usize = 2;
/// Ceiling on compact + full pending finalizations retained for retry.
const MAX_PENDING_SNAPSHOT_FINALIZATIONS: usize = 64;
/// Aggregate retained-byte budget for compact recovery payloads.
const MAX_COMPACT_SNAPSHOT_RECOVERY_BYTES: usize = 64 * 1024 * 1024;
/// Operator-facing recovery policy for pending snapshot finalizations.
const SNAPSHOT_FINALIZATION_RECOVERY_POLICY: &str = "restore_spool_writability; compact recoveries retry on reload and shutdown; new snapshot generations fail closed while pending recovery count or bytes exceed budget";

fn default_clickhouse_database() -> String {
    "ferrum".to_string()
}

fn default_clickhouse_table() -> String {
    "charges_raw".to_string()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_verify_hostname() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClickHouseTlsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_file: Option<PathBuf>,
    #[serde(default = "default_verify_hostname")]
    pub verify_hostname: bool,
    pub insecure_skip_verify: bool,
}

impl Default for ClickHouseTlsConfig {
    fn default() -> Self {
        Self {
            ca_file: None,
            client_cert_file: None,
            client_key_file: None,
            verify_hostname: true,
            insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClickHouseConfig {
    pub url: String,
    #[serde(default = "default_clickhouse_database")]
    pub database: String,
    #[serde(default = "default_clickhouse_table")]
    pub table: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<String>,
    pub tls: ClickHouseTlsConfig,
    pub insert_query_params: HashMap<String, String>,
    /// Explicit opt-in to fire-and-forget ClickHouse async inserts
    /// (`wait_for_async_insert=0`). Default durable mode rejects that setting
    /// because ClickHouse acknowledges buffered inserts before persistence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_lossy_async_insert: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            database: default_clickhouse_database(),
            table: default_clickhouse_table(),
            username: None,
            password_ref: None,
            tls: ClickHouseTlsConfig::default(),
            insert_query_params: HashMap::new(),
            allow_lossy_async_insert: false,
            timeout_ms: default_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BatchSettings {
    #[serde(default = "default_batch_size")]
    pub size: usize,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_buffer_capacity")]
    pub buffer_capacity: usize,
    /// Aggregate retained-byte budget for queued charge events awaiting export.
    #[serde(default = "default_buffer_max_bytes")]
    pub buffer_max_bytes: usize,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            size: default_batch_size(),
            flush_interval_ms: default_flush_interval_ms(),
            buffer_capacity: default_buffer_capacity(),
            buffer_max_bytes: default_buffer_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetrySettings {
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_retry_initial_delay_ms")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_retry_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default = "default_retry_jitter")]
    pub jitter: bool,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_max_attempts(),
            initial_delay_ms: default_retry_initial_delay_ms(),
            max_delay_ms: default_retry_max_delay_ms(),
            jitter: default_retry_jitter(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpoolSettings {
    #[serde(default = "default_spool_enabled")]
    pub enabled: bool,
    #[serde(default = "default_spool_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_spool_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_spool_replay_interval_secs")]
    pub replay_interval_secs: u64,
    /// Bounded async handoff queue for overflow/failed-batch spool writes.
    /// Request-path hooks only enqueue here; compression/write/fsync run on the
    /// dedicated delivery worker.
    #[serde(default = "default_spool_delivery_queue_capacity")]
    pub delivery_queue_capacity: usize,
    pub compression: SpoolCompression,
}

impl Default for SpoolSettings {
    fn default() -> Self {
        Self {
            enabled: default_spool_enabled(),
            dir: default_spool_dir(),
            max_bytes: default_spool_max_bytes(),
            replay_interval_secs: default_spool_replay_interval_secs(),
            delivery_queue_capacity: default_spool_delivery_queue_capacity(),
            compression: SpoolCompression::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnapshotSettings {
    #[serde(default = "default_snapshot_interval_secs")]
    pub interval_secs: u64,
    pub emit_zero_deltas: bool,
    #[serde(default = "default_snapshot_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_snapshot_stale_entry_ttl_secs")]
    pub stale_entry_ttl_secs: u64,
    /// Hard ceiling on distinct accumulator identities retained in memory.
    #[serde(default = "default_snapshot_max_entries")]
    pub max_entries: usize,
    /// Hard ceiling on estimated retained bytes for accumulator identities.
    #[serde(default = "default_snapshot_max_retained_bytes")]
    pub max_retained_bytes: usize,
}

impl Default for SnapshotSettings {
    fn default() -> Self {
        Self {
            interval_secs: default_snapshot_interval_secs(),
            emit_zero_deltas: false,
            cleanup_interval_secs: default_snapshot_cleanup_interval_secs(),
            stale_entry_ttl_secs: default_snapshot_stale_entry_ttl_secs(),
            max_entries: default_snapshot_max_entries(),
            max_retained_bytes: default_snapshot_max_retained_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiChargebackSinkConfig {
    pub mode: SinkMode,
    pub clickhouse: ClickHouseConfig,
    pub batch: BatchSettings,
    pub retry: RetrySettings,
    pub spool: SpoolSettings,
    pub snapshot: SnapshotSettings,
    pub pricing_version: String,
    pub currency: String,
    pub include_request_id: bool,
    pub include_trace_id: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_tiers: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_pricing: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_connection_pricing: Option<Value>,
    /// Inline transaction-log schema projecting the exported charge event.
    /// Validated and compiled by [`resolve_schema`]; retained here only so the
    /// `deny_unknown_fields` config struct admits the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    /// Named schema reference resolved against the global
    /// `transaction_log_schema` registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
}

impl Default for ApiChargebackSinkConfig {
    fn default() -> Self {
        Self {
            mode: SinkMode::PerEvent,
            clickhouse: ClickHouseConfig::default(),
            batch: BatchSettings::default(),
            retry: RetrySettings::default(),
            spool: SpoolSettings::default(),
            snapshot: SnapshotSettings::default(),
            pricing_version: DEFAULT_PRICING_VERSION.to_string(),
            currency: DEFAULT_CURRENCY.to_string(),
            include_request_id: true,
            include_trace_id: true,
            pricing_tiers: None,
            bandwidth_pricing: None,
            stream_connection_pricing: None,
            schema: None,
            schema_ref: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeEvent {
    pub event_id: String,
    pub received_at: i64,
    pub node_id: String,
    pub namespace: String,
    pub consumer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_name: Option<String>,
    pub proxy_id: String,
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Billable status: wire HTTP for ordinary requests, canonical effective
    /// HTTP status for native gRPC and translated gRPC-Web.
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_status: Option<u32>,
    pub protocol: String,
    /// Lossless call/session count. Snapshot deltas and ClickHouse DDL use u64
    /// so intervals that exceed `u32::MAX` never clamp while the baseline advances.
    pub call_count: u64,
    pub charge_call: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub charge_bytes_sent: f64,
    pub charge_bytes_received: f64,
    pub charge_total: f64,
    pub currency: String,
    pub pricing_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Charge-event schema projection
// ---------------------------------------------------------------------------

/// Worst-case rendered bytes of a derived value for this family.
///
/// `backend_host` (the only unbounded derived kind) is rejected at compile time
/// for the charge-event family, so every derived value is one of the fixed
/// tokens `"1xx"`…`"other"`, `"ok"` / `"error"`, or `"charge_event"`.
const MAX_DERIVED_VALUE_BYTES: usize = 24;

/// `"key":value,` framing charged on top of an added member's key and value.
const JSON_MEMBER_FRAMING_BYTES: usize = 4;

/// A compiled charge-event projection plus the extra worst-case bytes one
/// projected row costs beyond its native rendering.
///
/// The retained-byte reservation for a JSONEachRow body is taken **before** a
/// single byte is serialized, so the bound has to account for renamed keys and
/// injected static / derived members up front. The overhead is computed once at
/// construction — never on a flush path — and a schema whose overhead cannot be
/// bounded fails closed at construction rather than blowing the reservation
/// later.
#[derive(Debug)]
pub struct ChargeEventProjection {
    schema: Arc<SummarySchema>,
    row_overhead_bytes: usize,
}

impl ChargeEventProjection {
    fn new(schema: Arc<SummarySchema>) -> Result<Self, String> {
        let row_overhead_bytes = projection_row_overhead_bytes(&schema).ok_or_else(|| {
            format!("{PLUGIN_NAME}: schema adds an unboundable number of bytes per exported row")
        })?;
        Ok(Self {
            schema,
            row_overhead_bytes,
        })
    }

    /// The compiled schema. Test-visible so parity assertions can inspect it.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn schema(&self) -> &SummarySchema {
        &self.schema
    }

    /// Worst-case extra bytes one projected row costs.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn row_overhead_bytes(&self) -> usize {
        self.row_overhead_bytes
    }
}

/// Resolve and compile a charge-event projection straight from a raw plugin
/// config. Test-facing mirror of what the constructor does.
#[doc(hidden)]
#[allow(dead_code)]
pub fn compile_charge_event_projection(
    config: &Value,
) -> Result<Option<ChargeEventProjection>, String> {
    match resolve_schema(config, PLUGIN_NAME, SchemaCapabilities::API_CHARGEBACK_SINK)? {
        Some(schema) => ChargeEventProjection::new(schema).map(Some),
        None => Ok(None),
    }
}

/// Worst-case JSON cost of an output key, assuming maximal escaping.
fn json_key_bound(key: &str) -> Option<usize> {
    key.len()
        .checked_mul(JSON_STRING_WORST_CASE_EXPANSION)?
        .checked_add(2)
}

/// Worst-case extra bytes a compiled schema adds to one serialized row.
///
/// Omissions and shortened rename targets only shrink the row, so they are
/// deliberately not credited back — the result is an upper bound.
fn projection_row_overhead_bytes(schema: &SummarySchema) -> Option<usize> {
    let mut extra: usize = 0;
    for spec in &schema.fields {
        match spec {
            FieldSpec::Native { out_key, .. } => {
                extra = extra.checked_add(json_key_bound(out_key)?)?;
            }
            FieldSpec::Static { out_key, value } => {
                let rendered = serde_json::to_string(value).ok()?;
                extra = extra
                    .checked_add(json_key_bound(out_key)?)?
                    .checked_add(rendered.len())?
                    .checked_add(JSON_MEMBER_FRAMING_BYTES)?;
            }
            FieldSpec::Derived { out_key, .. } => {
                extra = extra
                    .checked_add(json_key_bound(out_key)?)?
                    .checked_add(MAX_DERIVED_VALUE_BYTES)?
                    .checked_add(JSON_MEMBER_FRAMING_BYTES)?;
            }
        }
    }
    Some(extra)
}

impl SchemaSerializable for ChargeEvent {
    fn owns_native(&self, source: &str) -> bool {
        crate::plugins::utils::log_schema::CHARGE_EVENT_FIELDS
            .iter()
            .any(|field| field.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        _ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        // Optional members preserve their native `skip_serializing_if` shape so
        // a projected row and a native row agree on presence, not just naming.
        match source {
            "event_id" => map.serialize_entry(out_key, &self.event_id),
            "received_at" => map.serialize_entry(out_key, &self.received_at),
            "node_id" => map.serialize_entry(out_key, &self.node_id),
            "namespace" => map.serialize_entry(out_key, &self.namespace),
            "consumer_id" => map.serialize_entry(out_key, &self.consumer_id),
            "consumer_name" => match &self.consumer_name {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "proxy_id" => map.serialize_entry(out_key, &self.proxy_id),
            "proxy_name" => map.serialize_entry(out_key, &self.proxy_name),
            "route_id" => match &self.route_id {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "status_code" => map.serialize_entry(out_key, &self.status_code),
            "http_status_code" => match &self.http_status_code {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "grpc_status" => match &self.grpc_status {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "protocol" => map.serialize_entry(out_key, &self.protocol),
            "call_count" => map.serialize_entry(out_key, &self.call_count),
            "charge_call" => map.serialize_entry(out_key, &self.charge_call),
            "bytes_sent" => map.serialize_entry(out_key, &self.bytes_sent),
            "bytes_received" => map.serialize_entry(out_key, &self.bytes_received),
            "charge_bytes_sent" => map.serialize_entry(out_key, &self.charge_bytes_sent),
            "charge_bytes_received" => map.serialize_entry(out_key, &self.charge_bytes_received),
            "charge_total" => map.serialize_entry(out_key, &self.charge_total),
            "currency" => map.serialize_entry(out_key, &self.currency),
            "pricing_version" => map.serialize_entry(out_key, &self.pricing_version),
            "request_id" => match &self.request_id {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "trace_id" => match &self.trace_id {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "snapshot_id" => match &self.snapshot_id {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => {
                map.serialize_entry(out_key, status_class(self.status_code))?;
                Ok(true)
            }
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "charge_event")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error =
                    self.status_code >= 500 || self.grpc_status.is_some_and(|status| status != 0);
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
            // Rejected at compile time for this family — a charge event has no
            // backend target to extract a host from.
            DerivedKind::BackendHost => Ok(false),
        }
    }

    fn serialize_metadata<S>(
        &self,
        _policy: &MetadataPolicy,
        _emitted: &mut std::collections::HashSet<String>,
        _map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        // Charge events carry no metadata map; the compiler rejects a
        // `metadata` policy for this family, so the default `Nested` policy is
        // the only value that reaches here and it has nothing to emit.
        Ok(())
    }
}

#[derive(Clone)]
struct SinkSummary {
    mode: SinkMode,
    pricing_version: String,
    endpoint: String,
    database: String,
    table: String,
    batch_size: usize,
    flush_interval_ms: u64,
    retry_max_attempts: u32,
    retry_initial_delay_ms: u64,
    retry_max_delay_ms: u64,
    retry_jitter: bool,
}

/// Worst-case cumulative inter-attempt delay for `max_attempts` total tries
/// (including the initial). Matches [`RetryPolicy::backoff_delay`]'s
/// exponential/capped schedule, excludes the initial attempt, ignores jitter
/// reduction, and uses overflow-safe saturating arithmetic.
fn worst_case_inter_attempt_delay_ms(
    max_attempts: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
) -> u64 {
    if max_attempts <= 1 {
        return 0;
    }
    let cap_ms = max_delay_ms.max(initial_delay_ms);
    let mut total: u64 = 0;
    for attempt in 1..max_attempts {
        let shift = (attempt - 1).min(63);
        let grown = initial_delay_ms.saturating_mul(1u64 << shift);
        let capped = grown.min(cap_ms);
        total = total.saturating_add(capped);
    }
    total
}

pub struct ApiChargebackSink {
    pricing: PricingConfig,
    config: Arc<ApiChargebackSinkConfig>,
    /// Compiled charge-event projection resolved at construction. `None` keeps
    /// the exported JSONEachRow representation byte-for-byte native with no
    /// added allocation.
    projection: Option<Arc<ChargeEventProjection>>,
    node_id: Arc<str>,
    /// Stable plugin-config resource id used for accepted-generation
    /// observability. Production cache supplies `PluginConfig.id`; standalone
    /// constructors fall back to [`DEFAULT_PLUGIN_CONFIG_ID`].
    plugin_config_id: Arc<str>,
    /// Ferrum namespace (billing ledger) this instance was built for. Part of
    /// the durable spool ownership identity so two ledgers can never share a
    /// managed spool namespace.
    ferrum_namespace: Arc<str>,
    /// Shared gateway client retained for dedicated ClickHouse client build at start.
    http_client: PluginHttpClient,
    /// Live sink runtime after [`Plugin::start_background_tasks`].
    runtime: OnceLock<Arc<SinkRuntime>>,
    snapshot_accumulator: OnceLock<Arc<SnapshotAccumulator>>,
    /// Awaitable ownership of snapshot admission and the periodic emitter.
    /// Present only in snapshot mode.
    snapshot_lifecycle: OnceLock<Arc<SnapshotLifecycle>>,
    /// Handles for the per-instance background loops (spool replayer and, in
    /// per-event mode, all runtime work). Snapshot emitter ownership lives in
    /// [`SnapshotLifecycle`] so reload/shutdown can await its final handoff.
    background_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    start_lock: Mutex<()>,
}

struct SinkRuntime {
    plugin_config_id: Arc<str>,
    generation: u64,
    summary: SinkSummary,
    logger: BatchingLogger<QueuedChargeEvent>,
    byte_budget: Arc<ByteBudget>,
    metrics: Arc<SinkMetrics>,
    spool: Option<Arc<SpoolManager>>,
    spool_delivery: Option<Arc<SpoolDelivery>>,
}

/// Charge event retained in the export queue under a byte lease.
#[derive(Clone)]
struct QueuedChargeEvent {
    event: ChargeEvent,
    lease: Arc<ByteLease>,
}

enum SpoolJob {
    Events(Vec<QueuedChargeEvent>),
    /// Snapshot cardinality/byte overflow charges. On durable write success the
    /// worker advances the overflow-spooled counters; on write/cancellation
    /// failure it re-stages the exact events into the accumulator's bounded
    /// overflow so a Tokio worker never blocks on compression/write/fsync.
    SnapshotOverflow(SnapshotOverflowJob),
}

/// Owned snapshot-overflow delivery.
///
/// The queued form preserves byte leases without copying events. Once a worker
/// starts a blocking write, `recovery_events` keeps an `Arc` to the exact
/// payload. Dropping this owner before durable success (queue teardown, worker
/// abort, or a failed blocking task) re-stages the payload and always releases
/// the lifecycle's delivery count.
struct SnapshotOverflowJob {
    queued_events: Vec<QueuedChargeEvent>,
    recovery_events: Option<Arc<Vec<ChargeEvent>>>,
    accumulator: Arc<SnapshotAccumulator>,
    generation: u64,
    metrics: Arc<SinkMetrics>,
    pending_jobs: Arc<AtomicUsize>,
    pending_events: Arc<AtomicUsize>,
    event_count: usize,
    durable: bool,
}

impl SnapshotOverflowJob {
    fn new(
        events: Vec<QueuedChargeEvent>,
        accumulator: Arc<SnapshotAccumulator>,
        generation: u64,
        metrics: Arc<SinkMetrics>,
        pending_jobs: Arc<AtomicUsize>,
        pending_events: Arc<AtomicUsize>,
    ) -> Self {
        let event_count = events.len();
        Self {
            queued_events: events,
            recovery_events: None,
            accumulator,
            generation,
            metrics,
            pending_jobs,
            pending_events,
            event_count,
            durable: false,
        }
    }

    fn event_count(&self) -> usize {
        self.event_count
    }

    fn prepare_write(&mut self) -> (Arc<Vec<ChargeEvent>>, Vec<Arc<ByteLease>>) {
        let queued_events = std::mem::take(&mut self.queued_events);
        let (events, leases): (Vec<_>, Vec<_>) = queued_events
            .into_iter()
            .map(|queued| (queued.event, queued.lease))
            .unzip();
        let events = Arc::new(events);
        self.recovery_events = Some(Arc::clone(&events));
        (events, leases)
    }

    fn mark_durable(&mut self) {
        self.durable = true;
        self.recovery_events = None;
    }

    fn restage(&mut self) {
        if self.durable {
            return;
        }
        // Held for the whole restage when the payload had to be copied out of a
        // shared handle, so the transient copy is never uncharged.
        let mut clone_reservation: Option<ProcessByteReservation> = None;
        let events = if !self.queued_events.is_empty() {
            std::mem::take(&mut self.queued_events)
                .into_iter()
                .map(|queued| queued.event)
                .collect()
        } else if let Some(events) = self.recovery_events.take() {
            match Arc::try_unwrap(events) {
                Ok(events) => events,
                Err(events) => {
                    // A blocking write task that panicked or was cancelled can
                    // still hold the other handle. Cloning is the only way to
                    // recover the payload, and the clone coexists with it, so
                    // it is reserved before it is allocated.
                    let bytes = events
                        .iter()
                        .map(charge_event_retained_bytes)
                        .fold(0usize, usize::saturating_add);
                    let Some(reservation) = ProcessByteReservation::try_acquire(bytes) else {
                        self.metrics.record_spool_job_loss(
                            self.event_count as u64,
                            "snapshot overflow restage refused by the retained-byte ceiling",
                        );
                        self.durable = true;
                        return;
                    };
                    clone_reservation = Some(reservation);
                    events.as_ref().clone()
                }
            }
        } else {
            self.metrics.record_failure(
                FailureReason::Serialize,
                "snapshot overflow delivery lost internal payload ownership",
            );
            self.durable = true;
            return;
        };
        stage_overflow_events_or_reject(&self.accumulator, &self.metrics, self.generation, events);
        drop(clone_reservation);
        self.durable = true;
    }
}

impl Drop for SnapshotOverflowJob {
    fn drop(&mut self) {
        self.restage();
        self.pending_jobs.fetch_sub(1, Ordering::Relaxed);
        self.pending_events
            .fetch_sub(self.event_count, Ordering::Relaxed);
        self.accumulator.finish_overflow_delivery();
    }
}

/// Bounded async handoff for spool compression/write/fsync work.
struct SpoolDelivery {
    sender: mpsc::Sender<SpoolJob>,
    worker: Arc<DeliveryWorkerControl>,
    pending_jobs: Arc<AtomicUsize>,
    pending_events: Arc<AtomicUsize>,
    metrics: Arc<SinkMetrics>,
}

impl SpoolDelivery {
    fn try_enqueue(&self, events: Vec<QueuedChargeEvent>, _reason: &'static str) -> bool {
        if events.is_empty() {
            return true;
        }
        let event_count = events.len();
        let Some(_admission) = self.worker.try_admit() else {
            self.metrics
                .record_spool_job_loss(event_count as u64, "worker unavailable during shutdown");
            return false;
        };
        self.pending_jobs.fetch_add(1, Ordering::Relaxed);
        self.pending_events
            .fetch_add(event_count, Ordering::Relaxed);
        match self.sender.try_send(SpoolJob::Events(events)) {
            Ok(()) => {
                self.metrics
                    .spool_jobs_enqueued_total
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.pending_jobs.fetch_sub(1, Ordering::Relaxed);
                self.pending_events
                    .fetch_sub(event_count, Ordering::Relaxed);
                self.metrics
                    .record_spool_job_loss(event_count as u64, "delivery queue full");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.pending_jobs.fetch_sub(1, Ordering::Relaxed);
                self.pending_events
                    .fetch_sub(event_count, Ordering::Relaxed);
                self.metrics
                    .record_spool_job_loss(event_count as u64, "delivery queue closed");
                false
            }
        }
    }

    /// Enqueue snapshot overflow events for durable async spooling. The bounded
    /// queue owns compression/write/fsync and preserves the byte leases until
    /// the blocking write finishes. Admission refusal returns the exact events
    /// to the caller; after delivery ownership begins, a full/closed queue or
    /// worker teardown re-stages them before releasing that ownership.
    fn try_enqueue_snapshot_overflow(
        &self,
        events: Vec<QueuedChargeEvent>,
        accumulator: Arc<SnapshotAccumulator>,
        generation: u64,
    ) -> Result<(), Vec<QueuedChargeEvent>> {
        if events.is_empty() {
            return Ok(());
        }
        let event_count = events.len();
        let Some(_admission) = self.worker.try_admit() else {
            return Err(events);
        };
        accumulator.begin_overflow_delivery();
        self.pending_jobs.fetch_add(1, Ordering::Relaxed);
        self.pending_events
            .fetch_add(event_count, Ordering::Relaxed);
        let job = SnapshotOverflowJob::new(
            events,
            accumulator,
            generation,
            Arc::clone(&self.metrics),
            Arc::clone(&self.pending_jobs),
            Arc::clone(&self.pending_events),
        );
        match self.sender.try_send(SpoolJob::SnapshotOverflow(job)) {
            Ok(()) => {
                self.metrics
                    .spool_jobs_enqueued_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                match error.into_inner() {
                    SpoolJob::SnapshotOverflow(mut job) => {
                        // Stage back while this job still owns the lifecycle's
                        // delivery count. Drop releases ownership only after the
                        // accumulator mutation is complete.
                        job.restage();
                        Ok(())
                    }
                    SpoolJob::Events(events) => Err(events),
                }
            }
        }
    }

    fn pending_jobs(&self) -> usize {
        self.pending_jobs.load(Ordering::Relaxed)
    }
}

fn start_spool_delivery(
    spool: Arc<SpoolManager>,
    metrics: Arc<SinkMetrics>,
    capacity: usize,
    commit_rx: watch::Receiver<bool>,
) -> Arc<SpoolDelivery> {
    let capacity = capacity.clamp(1, MAX_BUFFER_CAPACITY);
    let (sender, mut receiver) = mpsc::channel(capacity);
    let pending_jobs = Arc::new(AtomicUsize::new(0));
    let pending_events = Arc::new(AtomicUsize::new(0));
    let pending_events_for_control = Arc::clone(&pending_events);
    let pending_jobs_for_loop = Arc::clone(&pending_jobs);
    let pending_events_for_loop = Arc::clone(&pending_events);
    let (worker_control, close_rx) = DeliveryWorkerControl::new(PLUGIN_NAME, move || {
        pending_events_for_control.load(Ordering::Relaxed) as u64
    });
    let completion = worker_control.completion();
    let worker_drain = Arc::clone(&worker_control);
    let metrics_for_worker = Arc::clone(&metrics);
    let task = tokio::spawn(async move {
        let mut completion = completion;
        if !wait_until_committed_or_closed(commit_rx, close_rx.clone()).await {
            drop(receiver);
            completion.complete();
            return;
        }
        let mut closing = *close_rx.borrow();
        if closing {
            worker_drain.wait_for_admissions().await;
            receiver.close();
        }
        let mut close_rx = close_rx;
        loop {
            tokio::select! {
                biased;
                _ = close_rx.changed(), if !closing => {
                    closing = true;
                    worker_drain.wait_for_admissions().await;
                    receiver.close();
                }
                job = receiver.recv() => {
                    match job {
                        Some(SpoolJob::Events(queued_events)) => {
                            let event_count = queued_events.len();
                            let (events, leases): (Vec<_>, Vec<_>) = queued_events
                                .into_iter()
                                .map(|queued| (queued.event, queued.lease))
                                .unzip();
                            let spool = Arc::clone(&spool);
                            let metrics = Arc::clone(&metrics_for_worker);
                            let write_result = tokio::task::spawn_blocking(move || {
                                let result = spool.write_events(&events);
                                // Keep retained bytes charged until the actual
                                // blocking write finishes, even if its async
                                // waiter is cancelled during a timed-out drain.
                                drop(leases);
                                result
                            })
                            .await;
                            match write_result {
                                Ok(Ok(_)) => {
                                    metrics
                                        .spool_jobs_written_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    invalidate_status_cache();
                                }
                                Ok(Err(error)) => {
                                    warn!(
                                        plugin = PLUGIN_NAME,
                                        error = %error,
                                        "Chargeback sink async spool write failed"
                                    );
                                    metrics.record_spool_job_loss(
                                        event_count as u64,
                                        "spool write failed",
                                    );
                                }
                                Err(error) => {
                                    warn!(
                                        plugin = PLUGIN_NAME,
                                        error = %error,
                                        "Chargeback sink async spool write task failed"
                                    );
                                    metrics.record_spool_job_loss(
                                        event_count as u64,
                                        "spool write task failed",
                                    );
                                }
                            }
                            pending_jobs_for_loop.fetch_sub(1, Ordering::Relaxed);
                            pending_events_for_loop
                                .fetch_sub(event_count, Ordering::Relaxed);
                        }
                        Some(SpoolJob::SnapshotOverflow(mut job)) => {
                            let event_count = job.event_count();
                            let generation = job.generation;
                            let (events, leases) = job.prepare_write();
                            let spool = Arc::clone(&spool);
                            let metrics = Arc::clone(&metrics_for_worker);
                            let events_for_write = Arc::clone(&events);
                            drop(events);
                            let write_result = tokio::task::spawn_blocking(move || {
                                let result = spool.write_events(events_for_write.as_slice());
                                // Leases stay charged across the blocking write
                                // even if its async waiter is cancelled mid-drain.
                                drop(leases);
                                result
                            })
                            .await;
                            match write_result {
                                Ok(Ok(_)) => {
                                    job.mark_durable();
                                    metrics
                                        .spool_jobs_written_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    metrics
                                        .snapshot_overflow_spooled_total
                                        .fetch_add(event_count as u64, Ordering::Relaxed);
                                    metrics
                                        .snapshot_emits_total
                                        .fetch_add(event_count as u64, Ordering::Relaxed);
                                    invalidate_status_cache();
                                }
                                Ok(Err(error)) => {
                                    metrics.spool_available.store(false, Ordering::Release);
                                    warn!(
                                        plugin = PLUGIN_NAME,
                                        generation,
                                        error = %error,
                                        "Chargeback sink async snapshot overflow spool write failed; staging in bounded overflow"
                                    );
                                    job.restage();
                                }
                                Err(error) => {
                                    warn!(
                                        plugin = PLUGIN_NAME,
                                        generation,
                                        error = %error,
                                        "Chargeback sink async snapshot overflow spool task failed"
                                    );
                                    metrics.record_spool_job_loss(
                                        event_count as u64,
                                        "snapshot overflow spool task failed",
                                    );
                                    job.restage();
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        completion.complete();
    });
    if let Err(error) = worker_control.install_abort_handle(task.abort_handle()) {
        warn!(plugin = PLUGIN_NAME, "{PLUGIN_NAME}: {error}");
        task.abort();
    }
    drop(task);
    crate::observability_delivery::register_worker(Arc::clone(&worker_control));
    Arc::new(SpoolDelivery {
        sender,
        worker: worker_control,
        pending_jobs,
        pending_events,
        metrics,
    })
}

struct SnapshotLifecycle {
    generation: u64,
    runtime: Arc<SinkRuntime>,
    accumulator: Arc<SnapshotAccumulator>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    committed: AtomicBool,
    finalized: AtomicBool,
    /// Set when this generation's pending deltas were transferred to
    /// [`PendingSnapshotFinalization::Compact`]. Full finalize paths must not
    /// treat the cleared accumulator as an empty successful finalization.
    compacted: AtomicBool,
    closed_at_secs: AtomicI64,
    shutdown_tx: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<bool>>>,
    emission_lock: Arc<Mutex<()>>,
    finalize_lock: AsyncMutex<()>,
}

struct SnapshotAdmissionGuard<'a> {
    in_flight: &'a AtomicUsize,
}

impl Drop for SnapshotAdmissionGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SnapshotLifecycle {
    fn admit(&self) -> Option<SnapshotAdmissionGuard<'_>> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        if !self.accepting.load(Ordering::Acquire) {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(SnapshotAdmissionGuard {
            in_flight: &self.in_flight,
        })
    }

    fn commit(&self) {
        self.committed.store(true, Ordering::Release);
    }

    fn mark_admission_closed(&self) {
        if self.accepting.swap(false, Ordering::AcqRel) {
            self.closed_at_secs
                .store(unix_timestamp_seconds(), Ordering::Release);
            invalidate_status_cache();
        }
    }

    fn closed_age_secs(&self, _now: Instant) -> u64 {
        let closed = self.closed_at_secs.load(Ordering::Acquire);
        if closed <= 0 {
            return 0;
        }
        unix_timestamp_seconds().saturating_sub(closed) as u64
    }

    fn retained_finalization_bytes(&self) -> u64 {
        self.accumulator.retained_bytes() as u64
    }

    /// Conservative process-ceiling bound for the delta projection this
    /// generation would produce, computed before anything is allocated.
    fn delta_projection_bound(&self) -> Option<usize> {
        self.accumulator
            .delta_projection_bound(snapshot_event_extra_bytes(&self.config, &self.node_id))
    }

    /// Build the compact payload, returning it with the number of leading
    /// events that came from staged overflow.
    ///
    /// The staged overflow is *taken*, not cloned, so it has no other
    /// authoritative copy while the returned vector is alive. Every caller path
    /// that does not reach the compact publication point must hand it back
    /// through [`Self::restage_compaction_overflow`].
    ///
    /// The caller must already hold this generation's `emission_lock` and must
    /// keep holding it until compaction either publishes these deltas or
    /// restages them: the prepared set is only race-free against the periodic
    /// and final emitters for as long as that guard is alive. The guard is
    /// taken by reference purely as a compile-time witness of that requirement.
    fn prepare_compaction_events(
        &self,
        _emission_guard: &MutexGuard<'_, ()>,
    ) -> Option<(Vec<ChargeEvent>, usize, usize)> {
        let snapshot_id = new_ulid();
        let received_at = unix_timestamp_nanos();
        // Compaction owns the staged overflow going forward, so take it rather
        // than cloning it: a clone would be a second uncharged full-batch copy
        // that coexists with the still-staged originals.
        let taken = self.accumulator.take_overflow_pending();
        let overflow_count = taken.events.len();
        let overflow_retained_bytes = taken.retained_bytes;
        let mut events = taken.events;
        match self.accumulator.prepare_deltas(
            &self.config,
            &self.node_id,
            received_at,
            &snapshot_id,
        ) {
            Ok(prepared) => {
                events.extend(prepared.events);
                Some((events, overflow_count, overflow_retained_bytes))
            }
            Err(error) => {
                self.runtime
                    .metrics
                    .record_failure(FailureReason::Serialize, error);
                // Keep the full generation intact: compacting only the staged
                // overflow would clear accumulator totals that failed to
                // serialize. Return the borrowed overflow to bounded staging so
                // no pending billing delta is lost on this path.
                self.restage_compaction_overflow(events, overflow_count, overflow_retained_bytes);
                None
            }
        }
    }

    /// Give the borrowed staged overflow back to bounded staging.
    ///
    /// `SnapshotLifecycle::generation` is `runtime.generation`, so this is the
    /// same restore the periodic and final emitters use. The byte reservation
    /// remains continuously charged while the events are borrowed, so restore
    /// cannot be refused by unrelated process-wide ceiling pressure.
    fn restage_compaction_overflow(
        &self,
        events: Vec<ChargeEvent>,
        overflow_count: usize,
        overflow_retained_bytes: usize,
    ) {
        restage_borrowed_overflow(
            &self.accumulator,
            events,
            overflow_count,
            overflow_retained_bytes,
        );
    }

    async fn finalize_attempt(&self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let _guard = match tokio::time::timeout(remaining, self.finalize_lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if self.compacted.load(Ordering::Acquire)
            || compact_recovery_for_generation(self.generation).is_some()
        {
            self.compacted.store(true, Ordering::Release);
            return try_finalize_compact_recovery(self.generation).await;
        }
        if self.finalized.load(Ordering::Acquire) {
            unregister_full_snapshot_generation(self.generation);
            return true;
        }

        self.mark_admission_closed();
        while self.in_flight.load(Ordering::Acquire) > 0
            || self.accumulator.overflow_deliveries_in_flight() > 0
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                invalidate_status_cache();
                return false;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(1))).await;
        }

        let _ = self.shutdown_tx.send(true);
        let mut task = {
            let mut task = match self.task.lock() {
                Ok(task) => task,
                Err(poisoned) => poisoned.into_inner(),
            };
            task.take()
        };
        if task.is_none() && self.committed.load(Ordering::Acquire) {
            let accumulator = Arc::clone(&self.accumulator);
            let runtime = Arc::clone(&self.runtime);
            let config = Arc::clone(&self.config);
            let node_id = Arc::clone(&self.node_id);
            let emission_lock = Arc::clone(&self.emission_lock);
            task = Some(tokio::task::spawn_blocking(move || {
                emit_final_snapshot_to_spool(
                    &accumulator,
                    &runtime,
                    &config,
                    &node_id,
                    &emission_lock,
                )
            }));
        }
        let durable = match task {
            Some(mut task) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    let mut slot = match self.task.lock() {
                        Ok(slot) => slot,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    *slot = Some(task);
                    invalidate_status_cache();
                    return false;
                }
                match tokio::time::timeout(remaining, &mut task).await {
                    Ok(Ok(durable)) => durable,
                    Ok(Err(_)) if self.committed.load(Ordering::Acquire) => {
                        self.runtime.metrics.record_failure(
                            FailureReason::Serialize,
                            "snapshot finalizer task did not complete",
                        );
                        false
                    }
                    Ok(Err(_)) => true,
                    Err(_) => {
                        let mut slot = match self.task.lock() {
                            Ok(slot) => slot,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        *slot = Some(task);
                        invalidate_status_cache();
                        return false;
                    }
                }
            }
            None => true,
        };
        if durable {
            // A concurrent compaction may have published Compact while this Full
            // path observed an emptied accumulator. Never finalize away Compact.
            if compact_recovery_for_generation(self.generation).is_some() {
                self.compacted.store(true, Ordering::Release);
                invalidate_status_cache();
                return try_finalize_compact_recovery(self.generation).await;
            }
            self.finalized.store(true, Ordering::Release);
            unregister_full_snapshot_generation(self.generation);
        }
        invalidate_status_cache();
        durable
    }

    async fn finalize_within(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.finalize_attempt(deadline).await {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(
                    plugin = PLUGIN_NAME,
                    generation = self.generation,
                    timeout_ms = timeout.as_millis(),
                    "Chargeback sink final snapshot handoff timed out; compacting generation state"
                );
                self.compact_failed_finalization();
                // Ownership may now be Compact; retry that recovery once here so
                // a single finalize_within call does not leave Compact untouched.
                return try_finalize_compact_recovery(self.generation).await;
            }
            tokio::time::sleep(remaining.min(SNAPSHOT_FINALIZE_RETRY_INTERVAL)).await;
        }
    }

    fn compact_failed_finalization(&self) {
        if self.finalized.load(Ordering::Acquire)
            || self.compacted.load(Ordering::Acquire)
            || !self.committed.load(Ordering::Acquire)
        {
            return;
        }
        // Already compacted by a concurrent finalizer.
        {
            let generations = match active_snapshot_finalizations().lock() {
                Ok(generations) => generations,
                Err(poisoned) => poisoned.into_inner(),
            };
            if matches!(
                generations.get(&self.generation),
                Some(PendingSnapshotFinalization::Compact(_))
            ) {
                self.compacted.store(true, Ordering::Release);
                return;
            }
        }
        // compact_snapshot_lifecycle owns the whole gated sequence: it closes
        // admission, refuses (leaving the Full generation for a later retry)
        // until in_flight drains, then prepares and compacts the pending deltas.
        let _ = compact_snapshot_lifecycle(self);
    }

    fn finalize_without_await(&self) {
        if self.compacted.load(Ordering::Acquire)
            || compact_recovery_for_generation(self.generation).is_some()
        {
            self.compacted.store(true, Ordering::Release);
            let _ = try_finalize_compact_recovery_without_await(self.generation);
            return;
        }
        if self.finalized.load(Ordering::Acquire) {
            unregister_full_snapshot_generation(self.generation);
            return;
        }
        self.mark_admission_closed();
        let _ = self.shutdown_tx.send(true);
        let task = {
            let mut task = match self.task.lock() {
                Ok(task) => task,
                Err(poisoned) => poisoned.into_inner(),
            };
            task.take()
        };
        if let Some(task) = task {
            task.abort();
        }
        let durable = if self.committed.load(Ordering::Acquire) {
            emit_final_snapshot_to_spool(
                &self.accumulator,
                &self.runtime,
                &self.config,
                &self.node_id,
                &self.emission_lock,
            )
        } else {
            true
        };
        if durable {
            if compact_recovery_for_generation(self.generation).is_some() {
                self.compacted.store(true, Ordering::Release);
                let _ = try_finalize_compact_recovery_without_await(self.generation);
            } else {
                self.finalized.store(true, Ordering::Release);
                unregister_full_snapshot_generation(self.generation);
            }
        } else if self.committed.load(Ordering::Acquire) {
            self.compact_failed_finalization();
            let _ = try_finalize_compact_recovery_without_await(self.generation);
        }
        invalidate_status_cache();
    }
}

impl Drop for SnapshotLifecycle {
    fn drop(&mut self) {
        let task = match self.task.get_mut() {
            Ok(task) => task,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(task) = task.take() {
            task.abort();
        }
    }
}

struct SinkMetrics {
    events_enqueued_total: AtomicU64,
    events_exported_total: AtomicU64,
    failures_total: AtomicU64,
    failure_reasons: FailureReasonCounters,
    /// Observed queue depth at/above the high-water mark (telemetry only).
    queue_high_water_hits_total: AtomicU64,
    /// High-water events whose durable spool-delivery handoff actually accepted
    /// the job. Saturation/closure of the delivery queue is counted by spool
    /// loss metrics instead.
    queue_high_water_diversions_total: AtomicU64,
    /// Events lost because the bounded in-memory channel was actually full and
    /// no durable overflow path accepted ownership. Never incremented for
    /// shutdown/unavailable admission.
    queue_full_drops_total: AtomicU64,
    queue_byte_budget_exhausted_total: AtomicU64,
    spool_drops_total: AtomicU64,
    spool_available: AtomicBool,
    spool_prepare_failures_total: AtomicU64,
    spool_jobs_enqueued_total: AtomicU64,
    spool_jobs_written_total: AtomicU64,
    spool_jobs_lost_total: AtomicU64,
    spool_events_lost_total: AtomicU64,
    /// Retained spool records this identity does not own: pre-namespace layouts
    /// and namespaces orphaned by a destination/configuration change. Never
    /// replayed, never deleted; reported so operators can reconcile them.
    spool_unbound_files: AtomicU64,
    spool_unbound_namespaces: AtomicU64,
    snapshot_emits_total: AtomicU64,
    snapshot_overflow_spooled_total: AtomicU64,
    snapshot_overflow_pending_total: AtomicU64,
    snapshot_cardinality_rejections_total: AtomicU64,
    last_success_at: AtomicI64,
    last_failure_at: AtomicI64,
    last_replay_at: AtomicI64,
    last_failure_reason: RwLock<Option<String>>,
    last_spool_job_warn_at: AtomicI64,
    latency: LatencyHistogram,
}

impl Default for SinkMetrics {
    fn default() -> Self {
        Self {
            events_enqueued_total: AtomicU64::new(0),
            events_exported_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
            failure_reasons: FailureReasonCounters::default(),
            queue_high_water_hits_total: AtomicU64::new(0),
            queue_high_water_diversions_total: AtomicU64::new(0),
            queue_full_drops_total: AtomicU64::new(0),
            queue_byte_budget_exhausted_total: AtomicU64::new(0),
            spool_drops_total: AtomicU64::new(0),
            spool_available: AtomicBool::new(false),
            spool_prepare_failures_total: AtomicU64::new(0),
            spool_jobs_enqueued_total: AtomicU64::new(0),
            spool_jobs_written_total: AtomicU64::new(0),
            spool_jobs_lost_total: AtomicU64::new(0),
            spool_events_lost_total: AtomicU64::new(0),
            spool_unbound_files: AtomicU64::new(0),
            spool_unbound_namespaces: AtomicU64::new(0),
            snapshot_emits_total: AtomicU64::new(0),
            snapshot_overflow_spooled_total: AtomicU64::new(0),
            snapshot_overflow_pending_total: AtomicU64::new(0),
            snapshot_cardinality_rejections_total: AtomicU64::new(0),
            last_success_at: AtomicI64::new(0),
            last_failure_at: AtomicI64::new(0),
            last_replay_at: AtomicI64::new(0),
            last_failure_reason: RwLock::new(None),
            last_spool_job_warn_at: AtomicI64::new(0),
            latency: LatencyHistogram::default(),
        }
    }
}

impl SinkMetrics {
    fn record_spool_job_loss(&self, events: u64, reason: &'static str) {
        self.spool_jobs_lost_total.fetch_add(1, Ordering::Relaxed);
        self.spool_events_lost_total
            .fetch_add(events, Ordering::Relaxed);
        let lost = self.spool_jobs_lost_total.load(Ordering::Relaxed);
        let now = unix_timestamp_seconds();
        let last = self.last_spool_job_warn_at.load(Ordering::Relaxed);
        let should_warn = (lost == 1 || lost.is_multiple_of(SPOOL_JOB_WARN_EVERY))
            && now.saturating_sub(last) >= SPOOL_WARN_INTERVAL_SECS
            && self
                .last_spool_job_warn_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        if should_warn {
            warn!(
                plugin = PLUGIN_NAME,
                reason,
                jobs_lost_total = lost,
                events_lost_total = self.spool_events_lost_total.load(Ordering::Relaxed),
                "Chargeback sink spool delivery job was dropped (rate-limited)"
            );
        }
        invalidate_status_cache();
    }
}

#[derive(Default)]
struct FailureReasonCounters {
    network: AtomicU64,
    http_4xx: AtomicU64,
    http_5xx: AtomicU64,
    serialize: AtomicU64,
    tls: AtomicU64,
    timeout: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
enum FailureReason {
    Network,
    Http4xx,
    Http5xx,
    Serialize,
    Tls,
    Timeout,
}

impl FailureReason {
    fn as_str(self) -> &'static str {
        match self {
            FailureReason::Network => "network",
            FailureReason::Http4xx => "http_4xx",
            FailureReason::Http5xx => "http_5xx",
            FailureReason::Serialize => "serialize",
            FailureReason::Tls => "tls",
            FailureReason::Timeout => "timeout",
        }
    }
}

impl SinkMetrics {
    fn record_failure(&self, reason: FailureReason, detail: impl Into<String>) {
        self.failures_total.fetch_add(1, Ordering::Relaxed);
        match reason {
            FailureReason::Network => self.failure_reasons.network.fetch_add(1, Ordering::Relaxed),
            FailureReason::Http4xx => self
                .failure_reasons
                .http_4xx
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Http5xx => self
                .failure_reasons
                .http_5xx
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Serialize => self
                .failure_reasons
                .serialize
                .fetch_add(1, Ordering::Relaxed),
            FailureReason::Tls => self.failure_reasons.tls.fetch_add(1, Ordering::Relaxed),
            FailureReason::Timeout => self.failure_reasons.timeout.fetch_add(1, Ordering::Relaxed),
        };
        self.last_failure_at
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        if let Ok(mut slot) = self.last_failure_reason.write() {
            *slot = Some(bound_string(&detail.into(), MAX_METADATA_FIELD_LEN));
        }
        invalidate_status_cache();
    }

    fn record_success(&self, event_count: usize, elapsed: Duration) {
        self.events_exported_total
            .fetch_add(event_count as u64, Ordering::Relaxed);
        self.last_success_at
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.latency.observe(elapsed.as_secs_f64());
        invalidate_status_cache();
    }
}

struct LatencyHistogram {
    buckets: &'static [f64],
    counts: Vec<AtomicU64>,
    sum_bits: AtomicU64,
    count: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        const BUCKETS: &[f64] = &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];
        Self {
            buckets: BUCKETS,
            counts: BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_bits: AtomicU64::new(0f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    fn observe(&self, seconds: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        add_f64_atomic(&self.sum_bits, seconds);
        for (idx, bucket) in self.buckets.iter().enumerate() {
            if seconds <= *bucket {
                self.counts[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Clone)]
struct ClickHouseFlushConfig {
    http: ClickHouseHttpClient,
    /// Complete INSERT URL, including the `database`/`query` parameters and
    /// every operator `insert_query_params` pair. Used **only** to build the
    /// outbound request.
    insert_url: String,
    /// Structurally redacted rendering of [`Self::insert_url`] for every
    /// diagnostic surface. Credential-bearing `insert_query_params` names are
    /// already rejected at validation, but arbitrary values remain admitted, so
    /// no diagnostic ever renders the query string.
    redacted_insert_url: String,
    username: Option<String>,
    password: Option<String>,
    timeout: Duration,
    metrics: Arc<SinkMetrics>,
    /// Retained-byte ceiling the JSONEachRow request body is charged to. The
    /// queued `ChargeEvent`s already hold a per-instance lease; the serialized
    /// body is a second attacker-shaped copy that coexists with them. Admission
    /// takes a provisional escaping/framing bound, then shrinks to the exact
    /// retained allocation for the body's lifetime.
    ceiling: &'static RetainedByteCeiling,
    /// Compiled charge-event projection for the emitted representation.
    /// `None` keeps the native JSONEachRow rows byte-for-byte.
    projection: Option<Arc<ChargeEventProjection>>,
}

#[derive(Clone)]
enum ClickHouseHttpClient {
    Shared(Box<PluginHttpClient>),
    Dedicated(reqwest::Client),
}

impl ClickHouseHttpClient {
    /// Send the INSERT while keeping the complete URL out of diagnostics.
    ///
    /// The shared-client arm routes through `execute_with_redacted_url` so the
    /// literal-IP egress denial, retry, and slow-call warnings emitted inside
    /// `PluginHttpClient` record `redacted_url` instead of the INSERT URL. The
    /// dedicated custom-TLS arm emits no diagnostics of its own; its
    /// `reqwest::Error` is reduced to a fixed [`FailureReason`] by the caller
    /// and never rendered, so the URL cannot reach a log line there either.
    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
        redacted_url: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        match self {
            ClickHouseHttpClient::Shared(client) => {
                client
                    .execute_with_redacted_url(request, PLUGIN_NAME, redacted_url)
                    .await
            }
            ClickHouseHttpClient::Dedicated(_) => request.send().await,
        }
    }
}

impl ApiChargebackSink {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(
        raw_config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
    ) -> Result<Self, String> {
        Self::new_with_config_id(raw_config, http_client, namespace, None)
    }

    /// Construct with an optional stable plugin-config resource id.
    ///
    /// `plugin_config_id` partitions accepted-generation status/metrics across
    /// sibling sink instances. Blank supplied ids fail closed. `None` uses
    /// [`DEFAULT_PLUGIN_CONFIG_ID`] for standalone validation/tests.
    pub fn new_with_config_id(
        raw_config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        if !raw_config.is_object() {
            return Err(format!("{PLUGIN_NAME}: config must be an object"));
        }
        // Compile / resolve once here — never on a flush path. `schema_ref`
        // keeps the global-first lifecycle and fails closed when the named
        // definition is missing or is not representable for charge events.
        let projection = match resolve_schema(
            raw_config,
            PLUGIN_NAME,
            SchemaCapabilities::API_CHARGEBACK_SINK,
        )? {
            Some(schema) => Some(Arc::new(ChargeEventProjection::new(schema)?)),
            None => None,
        };

        let plugin_config_id = match plugin_config_id {
            Some(id) if id.trim().is_empty() => {
                return Err(format!(
                    "{PLUGIN_NAME}: plugin config id must be a non-empty stable identity"
                ));
            }
            Some(id) => Arc::<str>::from(id),
            None => Arc::<str>::from(DEFAULT_PLUGIN_CONFIG_ID),
        };

        let config: ApiChargebackSinkConfig = serde_json::from_value(raw_config.clone())
            .map_err(|error| format!("{PLUGIN_NAME}: invalid config: {error}"))?;
        validate_config(&config)?;
        let pricing = PricingConfig::from_config(raw_config, PLUGIN_NAME)?;
        if !pricing.has_any_pricing() {
            return Err(format!(
                "{PLUGIN_NAME}: at least one of 'pricing_tiers', 'bandwidth_pricing', or \
                 'stream_connection_pricing' must be configured"
            ));
        }

        let parsed_url = parse_clickhouse_url(&config.clickhouse.url)?;
        // The ClickHouse sink builds a dedicated client, so screen a literal-IP
        // clickhouse.url against the egress policy at config-load (the shared
        // DNS-cache screen still applies at send time).
        crate::plugins::utils::log_helpers::screen_url_host_egress(
            PLUGIN_NAME,
            "clickhouse.url",
            &parsed_url,
            http_client.backend_allow_ips(),
        )?;

        let ferrum_namespace = if namespace.trim().is_empty() {
            Arc::<str>::from(DEFAULT_FERRUM_NAMESPACE)
        } else {
            Arc::<str>::from(namespace.trim())
        };

        Ok(Self {
            pricing,
            config: Arc::new(config),
            projection,
            node_id: Arc::<str>::from(resolve_node_id()),
            plugin_config_id,
            ferrum_namespace,
            http_client,
            runtime: OnceLock::new(),
            snapshot_accumulator: OnceLock::new(),
            snapshot_lifecycle: OnceLock::new(),
            background_tasks: Mutex::new(Vec::new()),
            start_lock: Mutex::new(()),
        })
    }

    fn activate(&self) -> Result<(), String> {
        // Fallible setup first. Staged workers share one commit gate and stay
        // dormant until commit_background_tasks; ACTIVE_SINKS stays unpublished.
        let parsed_url = parse_clickhouse_url(&self.config.clickhouse.url)?;
        let endpoint = sanitized_endpoint(&parsed_url);
        let insert_url = build_insert_url(&parsed_url, &self.config.clickhouse);
        // Structural, not substring: nothing from the INSERT query string is
        // copied into the diagnostic rendering.
        let redacted_insert_url = redacted_endpoint_url(&parsed_url);
        let password = resolve_password_ref(self.config.clickhouse.password_ref.as_deref())?;
        let http = build_clickhouse_http_client(&self.config.clickhouse, &self.http_client)?;
        // Build the spool-replay client before staging so a TLS/file failure
        // cannot orphan an already-staged BatchingLogger or replayer task.
        let replay_http = if self.config.spool.enabled {
            Some(build_clickhouse_http_client(
                &self.config.clickhouse,
                &self.http_client,
            )?)
        } else {
            None
        };
        let metrics = Arc::new(SinkMetrics::default());
        let generation = NEXT_SINK_GENERATION.fetch_add(1, Ordering::Relaxed);
        let spool = if self.config.spool.enabled {
            // Ownership binds the stable plugin-config id, the Ferrum namespace
            // (ledger), the sanitized ClickHouse endpoint, and the destination
            // schema. `endpoint` is credential-free by construction, so nothing
            // secret reaches a path, a manifest, or a log line.
            let owner = SpoolOwner::new(
                Arc::clone(&self.plugin_config_id),
                Arc::clone(&self.ferrum_namespace),
                endpoint.clone(),
                self.config.clickhouse.database.clone(),
                self.config.clickhouse.table.clone(),
                Arc::clone(&self.node_id),
            );
            Some(Arc::new(SpoolManager::new(
                self.config.spool.clone(),
                owner,
                generation,
                SpoolManagerOptions {
                    metrics: Arc::clone(&metrics),
                    stale_temp_age_secs: STALE_TEMP_AGE_SECS,
                    claim_lease_secs: spool_claim_lease_secs(&self.config),
                    fs_ops: SpoolFsOps::REAL,
                    ceiling: process_ceiling(),
                    projection: self.projection.clone(),
                },
            )?))
        } else {
            None
        };

        let flush_config = ClickHouseFlushConfig {
            http,
            insert_url: insert_url.clone(),
            redacted_insert_url: redacted_insert_url.clone(),
            username: self.config.clickhouse.username.clone(),
            password,
            timeout: Duration::from_millis(self.config.clickhouse.timeout_ms),
            metrics: Arc::clone(&metrics),
            ceiling: process_ceiling(),
            projection: self.projection.clone(),
        };

        let snapshot_events_are_pre_spooled = self.config.mode == SinkMode::Snapshot;
        let high_water_metrics = Arc::clone(&metrics);
        let (commit_tx, commit_rx) = watch::channel(false);
        let spool_enqueue = spool.as_ref().map(|spool_manager| {
            start_spool_delivery(
                Arc::clone(spool_manager),
                Arc::clone(&metrics),
                self.config.spool.delivery_queue_capacity,
                commit_tx.subscribe(),
            )
        });
        let failed_enqueue = spool_enqueue.clone();
        // Install diversion only when a durable owner exists. Without spool,
        // high water is telemetry-only and the bounded channel remains usable
        // until it is actually full (issue #3038).
        let on_overflow: Option<
            Arc<dyn Fn(QueuedChargeEvent, &'static str) -> bool + Send + Sync>,
        > = spool_enqueue.as_ref().map(|overflow_enqueue| {
            let overflow_metrics = Arc::clone(&metrics);
            let overflow_enqueue = Arc::clone(overflow_enqueue);
            Arc::new(move |queued: QueuedChargeEvent, reason: &'static str| {
                if snapshot_events_are_pre_spooled {
                    // Snapshot charges are already durably owned; acknowledge
                    // ownership without counting a fresh high-water diversion.
                    invalidate_status_cache();
                    return true;
                }
                let accepted = overflow_enqueue.try_enqueue(vec![queued], reason);
                if accepted && reason == "queue high water" {
                    overflow_metrics
                        .queue_high_water_diversions_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                invalidate_status_cache();
                accepted
            }) as Arc<dyn Fn(QueuedChargeEvent, &'static str) -> bool + Send + Sync>
        });
        let hooks = LoggerHooks {
            on_failed_batch: Some(Arc::new(move |batch: Vec<QueuedChargeEvent>, error| {
                if snapshot_events_are_pre_spooled {
                    return;
                }
                if let Some(enqueue) = failed_enqueue.as_ref() {
                    let _ = enqueue.try_enqueue(batch, "export failure");
                } else {
                    warn!(
                        plugin = PLUGIN_NAME,
                        error = %error,
                        "Chargeback sink export failed and spool is disabled; batch was lost"
                    );
                }
            })),
            on_overflow,
            on_high_water: Some(Arc::new(move |_, _| {
                high_water_metrics
                    .queue_high_water_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                invalidate_status_cache();
            })),
            high_watermark_percent: 80,
        };

        let logger = BatchingLogger::spawn_with_hooks_on_commit_gate(
            BatchConfig {
                batch_size: self.config.batch.size,
                flush_interval: Duration::from_millis(self.config.batch.flush_interval_ms),
                buffer_capacity: self.config.batch.buffer_capacity,
                // Honor the advertised retry schema: bounded exponential
                // backoff from initial_delay_ms up to max_delay_ms, with
                // optional full jitter (finding #77).
                retry: RetryPolicy {
                    max_attempts: self.config.retry.max_attempts,
                    delay: Duration::from_millis(self.config.retry.initial_delay_ms),
                    max_delay: Duration::from_millis(self.config.retry.max_delay_ms),
                    jitter: self.config.retry.jitter,
                },
                plugin_name: PLUGIN_NAME,
            },
            hooks,
            commit_tx,
            commit_rx,
            {
                let flush_config = flush_config.clone();
                move |batch: Vec<QueuedChargeEvent>| {
                    let flush_config = flush_config.clone();
                    async move {
                        let (events, _leases): (Vec<_>, Vec<_>) = batch
                            .into_iter()
                            .map(|queued| (queued.event, queued.lease))
                            .unzip();
                        send_batch(&flush_config, events).await
                    }
                }
            },
        );

        let byte_budget = Arc::new(ByteBudget::new_observability(
            PLUGIN_NAME,
            self.config
                .batch
                .buffer_max_bytes
                .max(MAX_CHARGE_EVENT_BYTES),
        ));
        let runtime = Arc::new(SinkRuntime {
            plugin_config_id: Arc::clone(&self.plugin_config_id),
            generation,
            summary: SinkSummary {
                mode: self.config.mode,
                pricing_version: self.config.pricing_version.clone(),
                endpoint,
                database: self.config.clickhouse.database.clone(),
                table: self.config.clickhouse.table.clone(),
                batch_size: self.config.batch.size,
                flush_interval_ms: self.config.batch.flush_interval_ms,
                retry_max_attempts: self.config.retry.max_attempts,
                retry_initial_delay_ms: self.config.retry.initial_delay_ms,
                retry_max_delay_ms: self.config.retry.max_delay_ms,
                retry_jitter: self.config.retry.jitter,
            },
            logger,
            byte_budget,
            metrics,
            spool,
            spool_delivery: spool_enqueue,
        });

        let mut background_tasks = Vec::new();
        if let (Some(spool), Some(replay_http)) = (runtime.spool.clone(), replay_http) {
            background_tasks.push(start_spool_replayer(
                Arc::clone(&spool),
                runtime.summary.clone(),
                ClickHouseFlushConfig {
                    http: replay_http,
                    insert_url,
                    redacted_insert_url,
                    username: self.config.clickhouse.username.clone(),
                    password: flush_config.password.clone(),
                    timeout: Duration::from_millis(self.config.clickhouse.timeout_ms),
                    metrics: Arc::clone(&runtime.metrics),
                    ceiling: process_ceiling(),
                    projection: self.projection.clone(),
                },
                self.config.batch.size,
                self.config.spool.replay_interval_secs,
                runtime.logger.commit_sender().subscribe(),
            ));
        }

        let snapshot_lifecycle = if self.config.mode == SinkMode::Snapshot {
            if pending_finalization_budget_exceeded() {
                return Err(format!(
                    "{PLUGIN_NAME}: refusing new snapshot generation while pending finalization recovery budget is exhausted ({SNAPSHOT_FINALIZATION_RECOVERY_POLICY})"
                ));
            }
            let accumulator = Arc::new(SnapshotAccumulator::with_limits_and_shards(
                self.config.snapshot.max_entries,
                self.config.snapshot.max_retained_bytes,
                self.http_client.pool_shard_amount(),
            ));
            let emission_lock = Arc::new(Mutex::new(()));
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let task = start_snapshot_task(
                Arc::clone(&accumulator),
                Arc::clone(&runtime),
                Arc::clone(&self.config),
                Arc::clone(&self.node_id),
                runtime.logger.commit_sender().subscribe(),
                shutdown_rx,
                Arc::clone(&emission_lock),
            );
            Some(Arc::new(SnapshotLifecycle {
                generation: runtime.generation,
                runtime: Arc::clone(&runtime),
                accumulator,
                config: Arc::clone(&self.config),
                node_id: Arc::clone(&self.node_id),
                // The cache atomically publishes this staged instance just
                // before commit_background_tasks runs. Admission must already
                // be ready for readers that observe that new cache snapshot;
                // external workers and spool activity remain commit-gated.
                accepting: AtomicBool::new(true),
                in_flight: AtomicUsize::new(0),
                committed: AtomicBool::new(false),
                finalized: AtomicBool::new(false),
                compacted: AtomicBool::new(false),
                closed_at_secs: AtomicI64::new(0),
                shutdown_tx,
                task: Mutex::new(Some(task)),
                emission_lock,
                finalize_lock: AsyncMutex::new(()),
            }))
        } else {
            None
        };

        // Stage ownership. Abort every staged task on any failure so infinite
        // replayer/snapshot loops cannot outlive a rejected activation. The
        // BatchingLogger is owned by `runtime` and is not published to
        // ACTIVE_SINKS until commit succeeds; dropping `runtime` cancels its
        // commit gate. ACTIVE_SINKS is published only after `self.runtime` is set.
        let abort_tasks = |tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
            for task in tasks.drain(..) {
                task.abort();
            }
        };

        let mut owned_tasks = match self.background_tasks.lock() {
            Ok(guard) => guard,
            Err(_) => {
                abort_tasks(&mut background_tasks);
                if let Some(lifecycle) = snapshot_lifecycle.as_ref() {
                    lifecycle.finalize_without_await();
                }
                return Err(format!(
                    "{PLUGIN_NAME}: background task lock poisoned; refusing to start"
                ));
            }
        };

        *owned_tasks = std::mem::take(&mut background_tasks);

        if let Some(lifecycle) = snapshot_lifecycle.as_ref()
            && self
                .snapshot_accumulator
                .set(Arc::clone(&lifecycle.accumulator))
                .is_err()
        {
            abort_tasks(&mut owned_tasks);
            lifecycle.finalize_without_await();
            return Err(format!(
                "{PLUGIN_NAME}: snapshot accumulator already activated; refusing duplicate start"
            ));
        }

        if self.runtime.set(Arc::clone(&runtime)).is_err() {
            abort_tasks(&mut owned_tasks);
            if let Some(lifecycle) = snapshot_lifecycle.as_ref() {
                lifecycle.finalize_without_await();
            }
            return Err(format!(
                "{PLUGIN_NAME}: runtime already activated; refusing duplicate start"
            ));
        }

        if let Some(lifecycle) = snapshot_lifecycle
            && let Err(lifecycle) = self.snapshot_lifecycle.set(lifecycle)
        {
            abort_tasks(&mut owned_tasks);
            lifecycle.finalize_without_await();
            return Err(format!(
                "{PLUGIN_NAME}: snapshot lifecycle already activated; refusing duplicate start"
            ));
        }

        Ok(())
    }

    fn enqueue(&self, event: ChargeEvent) {
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        enqueue_charge_event(runtime, event);
    }

    /// Whether this instance currently owns a published slot in the
    /// process-global accepted-generation registry. Staging
    /// (`start_background_tasks`) must leave this false; only
    /// [`Plugin::commit_background_tasks`] publishes ownership.
    #[allow(dead_code)] // lifecycle tests observe pre/post-commit publication
    pub fn owns_active_sink(&self) -> bool {
        let Some(runtime) = self.runtime.get() else {
            return false;
        };
        active_sinks()
            .load_full()
            .get(runtime.plugin_config_id.as_ref())
            .is_some_and(|published| Arc::ptr_eq(published, runtime))
    }

    /// Accepted observability generation for this instance, if activated.
    #[allow(dead_code)] // multi-instance lifecycle tests assert exact-generation removal
    pub fn active_generation(&self) -> Option<u64> {
        self.runtime.get().map(|runtime| runtime.generation)
    }

    /// Stable plugin-config id used for observability identity.
    #[allow(dead_code)] // multi-instance lifecycle tests assert exact-id removal
    pub fn plugin_config_id(&self) -> &str {
        &self.plugin_config_id
    }

    // The library's hidden test-support module calls this accessor; the binary
    // compiles this module separately and cannot observe that use.
    #[allow(dead_code)]
    pub(crate) fn snapshot_accumulator_for_tests(&self) -> Option<Arc<SnapshotAccumulator>> {
        self.snapshot_accumulator.get().cloned()
    }

    #[allow(dead_code)]
    pub(crate) async fn finalize_snapshot_for_tests(&self) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        Some(
            lifecycle
                .finalize_attempt(Instant::now() + SNAPSHOT_FINALIZE_TIMEOUT)
                .await,
        )
    }

    #[allow(dead_code)]
    pub(crate) async fn finalize_snapshot_with_held_admission_for_tests(
        &self,
        timeout: Duration,
    ) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        let _admission = lifecycle.admit()?;
        Some(lifecycle.finalize_attempt(Instant::now() + timeout).await)
    }

    #[allow(dead_code)]
    pub(crate) fn snapshot_finalized_for_tests(&self) -> Option<bool> {
        self.snapshot_lifecycle
            .get()
            .map(|lifecycle| lifecycle.finalized.load(Ordering::Acquire))
    }

    #[allow(dead_code)]
    pub(crate) fn snapshot_generation_registered_for_tests(&self) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        let generations = match active_snapshot_finalizations().lock() {
            Ok(generations) => generations,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(match generations.get(&lifecycle.generation) {
            Some(PendingSnapshotFinalization::Full(registered)) => {
                Arc::ptr_eq(registered, lifecycle)
            }
            Some(PendingSnapshotFinalization::Compact(_)) => false,
            None => false,
        })
    }

    /// Force Full→Compact transfer for adversarial recovery tests.
    #[allow(dead_code)]
    pub(crate) fn force_compact_snapshot_finalization_for_tests(&self) -> bool {
        let Some(lifecycle) = self.snapshot_lifecycle.get() else {
            return false;
        };
        lifecycle.compact_failed_finalization();
        lifecycle.compacted.load(Ordering::Acquire)
            || compact_recovery_for_generation(lifecycle.generation).is_some()
    }

    /// True when this generation is retained as compact durable recovery.
    #[allow(dead_code)]
    pub(crate) fn snapshot_compact_recovery_registered_for_tests(&self) -> Option<bool> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        Some(compact_recovery_for_generation(lifecycle.generation).is_some())
    }

    #[allow(dead_code)]
    pub(crate) fn emit_snapshot_tick_for_tests(&self) -> Option<Result<usize, String>> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        Some(emit_periodic_snapshot(
            &lifecycle.accumulator,
            &lifecycle.runtime,
            &lifecycle.config,
            &lifecycle.node_id,
            &lifecycle.emission_lock,
        ))
    }

    /// Drive one snapshot cardinality overflow charge through the non-blocking
    /// delivery path for tests. Returns false when no snapshot lifecycle exists.
    #[allow(dead_code)]
    pub(crate) fn spool_snapshot_overflow_for_tests(&self, event: ChargeEvent) -> bool {
        let Some(lifecycle) = self.snapshot_lifecycle.get() else {
            return false;
        };
        spool_snapshot_overflow_event(lifecycle, event);
        true
    }

    /// Abort the owned spool-delivery worker so tests can prove queued snapshot
    /// overflow ownership re-stages on teardown before durable processing.
    #[allow(dead_code)]
    pub(crate) fn abort_spool_delivery_for_tests(&self) -> bool {
        let Some(runtime) = self.runtime.get() else {
            return false;
        };
        let Some(delivery) = runtime.spool_delivery.as_ref() else {
            return false;
        };
        delivery.worker.abort();
        true
    }

    /// Snapshot overflow counters `(spooled, pending, cardinality_rejections)`
    /// for the live generation; lets tests poll async durable-handoff outcomes.
    #[allow(dead_code)]
    pub(crate) fn snapshot_overflow_counters_for_tests(&self) -> Option<(u64, u64, u64)> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        let metrics = &lifecycle.runtime.metrics;
        Some((
            metrics
                .snapshot_overflow_spooled_total
                .load(Ordering::Relaxed),
            metrics
                .snapshot_overflow_pending_total
                .load(Ordering::Relaxed),
            metrics
                .snapshot_cardinality_rejections_total
                .load(Ordering::Relaxed),
        ))
    }

    /// Prove compaction refuses while an admission guard is held and succeeds
    /// after the admitted hook drains. Returns
    /// `(refused_while_admitted, compacted_after_drain)`.
    #[allow(dead_code)]
    pub(crate) fn compact_refuses_while_admitted_then_succeeds_for_tests(
        &self,
    ) -> Option<(bool, bool)> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        lifecycle.commit();
        let refused_while_held = {
            let _admission = lifecycle.admit()?;
            lifecycle.compact_failed_finalization();
            !lifecycle.compacted.load(Ordering::Acquire)
                && compact_recovery_for_generation(lifecycle.generation).is_none()
        };
        // Admission guard dropped; in_flight is now zero. Retry compaction.
        lifecycle.compact_failed_finalization();
        let compacted_after_drain = lifecycle.compacted.load(Ordering::Acquire)
            || compact_recovery_for_generation(lifecycle.generation).is_some();
        Some((refused_while_held, compacted_after_drain))
    }

    /// Prove Full→Compact refuses while an async overflow delivery can still
    /// stage back into the accumulator, then succeeds after delivery ownership
    /// drains.
    #[allow(dead_code)]
    pub(crate) fn compact_refuses_while_overflow_delivery_then_succeeds_for_tests(
        &self,
    ) -> Option<(bool, bool)> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        lifecycle.commit();
        lifecycle.accumulator.begin_overflow_delivery();
        lifecycle.compact_failed_finalization();
        let refused_while_held = !lifecycle.compacted.load(Ordering::Acquire)
            && compact_recovery_for_generation(lifecycle.generation).is_none();
        lifecycle.accumulator.finish_overflow_delivery();
        lifecycle.compact_failed_finalization();
        let compacted_after_drain = lifecycle.compacted.load(Ordering::Acquire)
            || compact_recovery_for_generation(lifecycle.generation).is_some();
        Some((refused_while_held, compacted_after_drain))
    }

    /// Drive Full→Compact with a forced measured-payload overshoot so the
    /// fail-closed projection-shortfall branch is exercised.
    ///
    /// Returns `(compacted, overflow_pending_len, periodic_task_alive)` observed
    /// after the attempt. A correct refusal reports
    /// `(false, <what was staged>, true)`: the generation kept the staged
    /// overflow it borrowed and kept its retry mechanism.
    #[allow(dead_code)]
    pub(crate) fn compact_projection_shortfall_for_tests(&self) -> Option<(bool, usize, bool)> {
        let lifecycle = self.snapshot_lifecycle.get()?;
        lifecycle.commit();
        let compacted = compact_snapshot_lifecycle_measured(lifecycle, Some(usize::MAX));
        let task_alive = {
            let task = match lifecycle.task.lock() {
                Ok(task) => task,
                Err(poisoned) => poisoned.into_inner(),
            };
            task.is_some()
        };
        Some((
            compacted || compact_recovery_for_generation(lifecycle.generation).is_some(),
            lifecycle.accumulator.overflow_pending_len(),
            task_alive,
        ))
    }

    /// Prove emission and Full→Compact compaction are mutually exclusive owners
    /// of a generation's pending deltas.
    ///
    /// This holds the generation's emission lock — exactly what
    /// `emit_periodic_snapshot` / `emit_final_snapshot_to_spool` hold across
    /// their whole prepare→durable-commit sequence — while a worker thread runs
    /// the entire compaction sequence. Compaction must not be able to reach its
    /// commit while that lock is held, and must complete once it is released.
    ///
    /// Returns `(blocked_while_emission_held, compacted_after_release)`; the
    /// correct observation is `(true, true)`. One mutex guards both directions,
    /// so this equally proves an emission cannot enter compaction's
    /// prepare→publish interval.
    #[allow(dead_code)]
    pub(crate) fn compact_excluded_by_emission_lock_for_tests(
        &self,
        hold: Duration,
    ) -> Option<(bool, bool)> {
        let lifecycle = Arc::clone(self.snapshot_lifecycle.get()?);
        lifecycle.commit();
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let emission_guard = match lifecycle.emission_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let worker = std::thread::spawn({
            let lifecycle = Arc::clone(&lifecycle);
            let started = Arc::clone(&started);
            let finished = Arc::clone(&finished);
            move || {
                started.store(true, Ordering::Release);
                let compacted = compact_snapshot_lifecycle(&lifecycle);
                finished.store(true, Ordering::Release);
                compacted
            }
        });
        // Only assert on blocking once the worker is actually running, so the
        // observation is about the lock rather than thread start-up latency.
        let spin_deadline = Instant::now() + hold;
        while !started.load(Ordering::Acquire) && Instant::now() < spin_deadline {
            std::thread::yield_now();
        }
        let running = started.load(Ordering::Acquire);
        std::thread::sleep(hold);
        let blocked_while_held = running && !finished.load(Ordering::Acquire);
        drop(emission_guard);
        let compacted = worker.join().unwrap_or(false);
        Some((
            blocked_while_held,
            compacted || compact_recovery_for_generation(lifecycle.generation).is_some(),
        ))
    }
}

impl Drop for ApiChargebackSink {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.snapshot_lifecycle.get()
            && !lifecycle.finalized.load(Ordering::Acquire)
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current()
                && handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            {
                let lifecycle = Arc::clone(lifecycle);
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        finalize_snapshot_generation_and_pending(lifecycle).await;
                    });
                });
            } else {
                // Current-thread tests and teardown after runtime exit cannot
                // synchronously await a Tokio task. No task can run
                // concurrently on the current-thread path while Drop is
                // executing, so abort it and perform the same final spool
                // handoff inline.
                lifecycle.finalize_without_await();
            }
        }

        // Stop the per-instance spool replay loop so a config reload or an
        // admin-validation throwaway does not leak an immortal task. The
        // BatchingLogger flush loop remains covered by the shared queued-work
        // lifecycle tracked in issue #2533.
        if let Ok(mut tasks) = self.background_tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        let Some(runtime) = self.runtime.get() else {
            // Never started: ACTIVE_SINKS was never published for this instance.
            return;
        };
        // Remove only when this exact runtime is still the accepted generation
        // for its plugin-config ID. Siblings and a newer replacement stay
        // published; a validation throwaway that never committed is a no-op.
        unregister_active_sink(runtime);
    }
}

#[async_trait]
impl Plugin for ApiChargebackSink {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        super::priority::API_CHARGEBACK_SINK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        if self.runtime.get().is_some() {
            return Ok(());
        }
        let _guard = self.start_lock.lock().map_err(|_| {
            format!("{PLUGIN_NAME}: start lock poisoned; refusing to start chargeback sink")
        })?;
        if self.runtime.get().is_some() {
            return Ok(());
        }
        let _runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            format!("{PLUGIN_NAME}: start_background_tasks requires a Tokio runtime")
        })?;
        self.activate()
    }

    fn commit_background_tasks(&self) {
        let Some(runtime) = self.runtime.get() else {
            return;
        };
        // Release flush/replay/snapshot dormancy before publishing diagnostics
        // so the live instance cannot appear active while workers are gated.
        runtime.logger.commit();
        if let Some(lifecycle) = self.snapshot_lifecycle.get() {
            lifecycle.commit();
            register_snapshot_generation(Arc::clone(lifecycle));
        }
        register_active_sink(Arc::clone(runtime));
    }

    async fn log(&self, summary: &TransactionSummary) {
        // Shadow/mirror summaries retain the primary consumer identity for
        // logging correlation, but they are internal backend probes — never
        // consumer-billable per-call or bandwidth charges (issue #2437).
        if summary.mirror {
            return;
        }

        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let outcome = http_billing_outcome(summary);
        let Some(charge) = self.pricing.compute_http(
            outcome.status_code,
            summary.bytes_sent,
            summary.bytes_received,
        ) else {
            return;
        };
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                match lifecycle
                    .accumulator
                    .record_http(summary, consumer, outcome, charge)
                {
                    SnapshotRecordOutcome::Accumulated => {}
                    SnapshotRecordOutcome::OverflowImmediate => {
                        spool_snapshot_overflow_event(
                            lifecycle,
                            event_from_http_summary(
                                summary,
                                consumer,
                                outcome,
                                charge,
                                &self.config,
                                &self.node_id,
                                None,
                            ),
                        );
                    }
                }
            }
            return;
        }
        self.enqueue(event_from_http_summary(
            summary,
            consumer,
            outcome,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let Some(charge) = self
            .pricing
            .compute_stream(summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                match lifecycle
                    .accumulator
                    .record_stream(summary, consumer, charge)
                {
                    SnapshotRecordOutcome::Accumulated => {}
                    SnapshotRecordOutcome::OverflowImmediate => {
                        spool_snapshot_overflow_event(
                            lifecycle,
                            event_from_stream_summary(
                                summary,
                                consumer,
                                charge,
                                &self.config,
                                &self.node_id,
                                None,
                            ),
                        );
                    }
                }
            }
            return;
        }
        self.enqueue(event_from_stream_summary(
            summary,
            consumer,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let Some(charge) = self.pricing.compute_websocket_bandwidth(
            summary.bytes_client_to_backend,
            summary.bytes_backend_to_client,
        ) else {
            return;
        };
        if self.config.mode == SinkMode::Snapshot {
            if let Some(lifecycle) = self.snapshot_lifecycle.get()
                && let Some(_admission) = lifecycle.admit()
            {
                match lifecycle
                    .accumulator
                    .record_websocket(summary, consumer, charge)
                {
                    SnapshotRecordOutcome::Accumulated => {}
                    SnapshotRecordOutcome::OverflowImmediate => {
                        spool_snapshot_overflow_event(
                            lifecycle,
                            event_from_ws_summary(
                                summary,
                                consumer,
                                charge,
                                &self.config,
                                &self.node_id,
                                None,
                            ),
                        );
                    }
                }
            }
            return;
        }
        self.enqueue(event_from_ws_summary(
            summary,
            consumer,
            charge,
            &self.config,
            &self.node_id,
            None,
        ));
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        parse_clickhouse_url(&self.config.clickhouse.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .into_iter()
            .collect()
    }
}

pub fn render_status_json() -> String {
    let cache = status_cache();
    let cached = cache.load();
    if let Some((cached_at, ref output)) = **cached
        && cached_at.elapsed() < STATUS_CACHE_TTL
    {
        return output.clone();
    }

    let body = serde_json::to_string(&aggregate_status_snapshot(&active_sinks().load_full()))
        .unwrap_or_else(|_| {
            "{\"enabled\":false,\"instance_count\":0,\"snapshot_finalizations_pending\":0,\"snapshot_finalizations_pending_bytes\":0,\"snapshot_finalizations_oldest_age_secs\":0,\"snapshot_finalization_recovery_policy\":\"restore_spool_writability\",\"totals\":{},\"instances\":[]}".to_string()
        });

    cache.store(Arc::new(Some((Instant::now(), body.clone()))));
    body
}

pub fn render_prometheus() -> String {
    let sinks = active_sinks().load_full();
    let (pending_finalizations, pending_bytes, oldest_age, _full, _compact) =
        pending_snapshot_finalization_stats();
    if sinks.is_empty() && pending_finalizations == 0 {
        return String::new();
    }
    render_prometheus_for_sinks(
        sinks.as_ref(),
        pending_finalizations,
        pending_bytes,
        oldest_age,
    )
}

fn disabled_status_snapshot() -> Value {
    let (pending, pending_bytes, oldest_age, _full, _compact) =
        pending_snapshot_finalization_stats();
    serde_json::json!({
        "enabled": false,
        "instance_count": 0,
        "snapshot_finalizations_pending": pending,
        "snapshot_finalizations_pending_bytes": pending_bytes,
        "snapshot_finalizations_oldest_age_secs": oldest_age,
        "snapshot_finalization_recovery_policy": SNAPSHOT_FINALIZATION_RECOVERY_POLICY,
        "totals": {
            "queue": {"depth": 0, "capacity": 0, "high_water_hits_total": 0, "high_water_diversions_total": 0, "full_drops_total": 0},
            "spool": {
                "files": 0,
                "bytes": 0,
                "drops_total": 0,
                "prepare_failures_total": 0,
                "available": false
            },
            "export": {
                "events_enqueued_total": 0,
                "events_exported_total": 0,
                "failures_total": 0
            }
        },
        "instances": []
    })
}

fn aggregate_status_snapshot(sinks: &BTreeMap<String, Arc<SinkRuntime>>) -> Value {
    if sinks.is_empty() {
        return disabled_status_snapshot();
    }

    let instances: Vec<Value> = sinks
        .values()
        .map(|runtime| runtime.status_snapshot())
        .collect();

    let mut queue_depth = 0u64;
    let mut queue_capacity = 0u64;
    let mut high_water = 0u64;
    let mut high_water_diversions = 0u64;
    let mut full_drops = 0u64;
    let mut spool_files = 0u64;
    let mut spool_bytes = 0u64;
    let mut spool_drops = 0u64;
    let mut spool_prepare_failures = 0u64;
    let mut spool_unbound_files = 0u64;
    let mut spool_unbound_namespaces = 0u64;
    let mut spool_enabled_any = false;
    let mut spool_all_available = true;
    let mut events_enqueued = 0u64;
    let mut events_exported = 0u64;
    let mut failures = 0u64;

    for runtime in sinks.values() {
        queue_depth = queue_depth.saturating_add(runtime.logger.queue_depth() as u64);
        queue_capacity = queue_capacity.saturating_add(runtime.logger.buffer_capacity() as u64);
        high_water = high_water.saturating_add(
            runtime
                .metrics
                .queue_high_water_hits_total
                .load(Ordering::Relaxed),
        );
        high_water_diversions = high_water_diversions.saturating_add(
            runtime
                .metrics
                .queue_high_water_diversions_total
                .load(Ordering::Relaxed),
        );
        full_drops = full_drops.saturating_add(
            runtime
                .metrics
                .queue_full_drops_total
                .load(Ordering::Relaxed),
        );
        events_enqueued = events_enqueued.saturating_add(
            runtime
                .metrics
                .events_enqueued_total
                .load(Ordering::Relaxed),
        );
        events_exported = events_exported.saturating_add(
            runtime
                .metrics
                .events_exported_total
                .load(Ordering::Relaxed),
        );
        failures = failures.saturating_add(runtime.metrics.failures_total.load(Ordering::Relaxed));
        spool_prepare_failures = spool_prepare_failures.saturating_add(
            runtime
                .metrics
                .spool_prepare_failures_total
                .load(Ordering::Relaxed),
        );
        spool_drops =
            spool_drops.saturating_add(runtime.metrics.spool_drops_total.load(Ordering::Relaxed));
        let unbound_files = runtime.metrics.spool_unbound_files.load(Ordering::Relaxed);
        spool_unbound_files = spool_unbound_files.saturating_add(unbound_files);
        let unbound_ns = runtime
            .metrics
            .spool_unbound_namespaces
            .load(Ordering::Relaxed);
        spool_unbound_namespaces = spool_unbound_namespaces.saturating_add(unbound_ns);
        if let Some(spool) = runtime.spool.as_ref() {
            spool_enabled_any = true;
            let stats = spool.scan_stats().unwrap_or_default();
            spool_files = spool_files.saturating_add(stats.files);
            spool_bytes = spool_bytes.saturating_add(stats.bytes);
            if !runtime.metrics.spool_available.load(Ordering::Acquire) {
                spool_all_available = false;
            }
        }
    }

    let (pending, pending_bytes, oldest_age, _full, _compact) =
        pending_snapshot_finalization_stats();
    serde_json::json!({
        "enabled": true,
        "instance_count": sinks.len(),
        "snapshot_finalizations_pending": pending,
        "snapshot_finalizations_pending_bytes": pending_bytes,
        "snapshot_finalizations_oldest_age_secs": oldest_age,
        "snapshot_finalization_recovery_policy": SNAPSHOT_FINALIZATION_RECOVERY_POLICY,
        "totals": {
            "queue": {
                "depth": queue_depth,
                "capacity": queue_capacity,
                "high_water_hits_total": high_water,
                "high_water_diversions_total": high_water_diversions,
                "full_drops_total": full_drops
            },
            "spool": {
                "files": spool_files,
                "bytes": spool_bytes,
                "drops_total": spool_drops,
                "prepare_failures_total": spool_prepare_failures,
                "unbound_files": spool_unbound_files,
                "unbound_namespaces": spool_unbound_namespaces,
                "available": spool_enabled_any && spool_all_available
            },
            "export": {
                "events_enqueued_total": events_enqueued,
                "events_exported_total": events_exported,
                "failures_total": failures
            }
        },
        "instances": instances
    })
}

impl SinkRuntime {
    fn status_snapshot(&self) -> Value {
        let (spool_enabled, spool_files, spool_bytes) = match self.spool.as_ref() {
            Some(spool) => {
                let stats = spool.scan_stats().unwrap_or_default();
                (true, stats.files, stats.bytes)
            }
            None => (false, 0, 0),
        };
        let last_failure_reason = self
            .metrics
            .last_failure_reason
            .read()
            .ok()
            .and_then(|guard| guard.clone());
        let snapshot = snapshot_accumulator_status(self.generation);
        serde_json::json!({
            "plugin_config_id": self.plugin_config_id.as_ref(),
            "generation": self.generation,
            "mode": self.summary.mode.as_str(),
            "pricing_version": self.summary.pricing_version,
            "clickhouse": {
                "endpoint": self.summary.endpoint,
                "database": self.summary.database,
                "table": self.summary.table,
            },
            "batch": {
                "size": self.summary.batch_size,
                "flush_interval_ms": self.summary.flush_interval_ms,
            },
            "retry": {
                "max_attempts": self.summary.retry_max_attempts,
                "initial_delay_ms": self.summary.retry_initial_delay_ms,
                "max_delay_ms": self.summary.retry_max_delay_ms,
                "jitter": self.summary.retry_jitter,
            },
            "queue": {
                "depth": self.logger.queue_depth(),
                "capacity": self.logger.buffer_capacity(),
                "high_water_hits_total": self.metrics.queue_high_water_hits_total.load(Ordering::Relaxed),
                "high_water_diversions_total": self
                    .metrics
                    .queue_high_water_diversions_total
                    .load(Ordering::Relaxed),
                "full_drops_total": self.metrics.queue_full_drops_total.load(Ordering::Relaxed),
                "retained_bytes": self.byte_budget.used(),
                "buffer_max_bytes": self.byte_budget.max_bytes(),
                "byte_budget_exhausted_total": self
                    .metrics
                    .queue_byte_budget_exhausted_total
                    .load(Ordering::Relaxed),
            },
            "snapshot": snapshot,
            "spool": {
                "enabled": spool_enabled,
                "available": spool_enabled && self.metrics.spool_available.load(Ordering::Acquire),
                "prepare_failures_total": self.metrics.spool_prepare_failures_total.load(Ordering::Relaxed),
                "files": spool_files,
                "bytes": spool_bytes,
                "drops_total": self.metrics.spool_drops_total.load(Ordering::Relaxed),
                "unbound_files": self.metrics.spool_unbound_files.load(Ordering::Relaxed),
                "unbound_namespaces": self.metrics.spool_unbound_namespaces.load(Ordering::Relaxed),
                "delivery_queue_depth": self
                    .spool_delivery
                    .as_ref()
                    .map(|delivery| delivery.pending_jobs())
                    .unwrap_or(0),
                "jobs_enqueued_total": self.metrics.spool_jobs_enqueued_total.load(Ordering::Relaxed),
                "jobs_written_total": self.metrics.spool_jobs_written_total.load(Ordering::Relaxed),
                "jobs_lost_total": self.metrics.spool_jobs_lost_total.load(Ordering::Relaxed),
                "events_lost_total": self.metrics.spool_events_lost_total.load(Ordering::Relaxed),
                "last_replay_at": timestamp_json(self.metrics.last_replay_at.load(Ordering::Relaxed)),
            },
            "export": {
                "events_enqueued_total": self.metrics.events_enqueued_total.load(Ordering::Relaxed),
                "events_exported_total": self.metrics.events_exported_total.load(Ordering::Relaxed),
                "failures_total": self.metrics.failures_total.load(Ordering::Relaxed),
                "last_success_at": timestamp_json(self.metrics.last_success_at.load(Ordering::Relaxed)),
                "last_failure_at": timestamp_json(self.metrics.last_failure_at.load(Ordering::Relaxed)),
                "last_failure_reason": last_failure_reason,
            }
        })
    }
}

fn snapshot_accumulator_gauges(generation: u64) -> Option<(u64, u64)> {
    let generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    match generations.get(&generation) {
        Some(PendingSnapshotFinalization::Full(lifecycle)) => Some((
            lifecycle.accumulator.entry_count() as u64,
            lifecycle.accumulator.retained_bytes() as u64,
        )),
        Some(PendingSnapshotFinalization::Compact(recovery)) => {
            Some((0, recovery.retained_bytes as u64))
        }
        None => None,
    }
}

fn snapshot_accumulator_status(generation: u64) -> Value {
    let generations = match active_snapshot_finalizations().lock() {
        Ok(generations) => generations,
        Err(poisoned) => poisoned.into_inner(),
    };
    match generations.get(&generation) {
        Some(PendingSnapshotFinalization::Full(lifecycle)) => serde_json::json!({
            "entries": lifecycle.accumulator.entry_count(),
            "retained_bytes": lifecycle.accumulator.retained_bytes(),
            "max_entries": lifecycle.accumulator.max_entries,
            "max_retained_bytes": lifecycle.accumulator.max_retained_bytes,
            "overflow_spooled_total": lifecycle.runtime.metrics.snapshot_overflow_spooled_total.load(Ordering::Relaxed),
            "overflow_pending_total": lifecycle.runtime.metrics.snapshot_overflow_pending_total.load(Ordering::Relaxed),
            "cardinality_rejections_total": lifecycle.runtime.metrics.snapshot_cardinality_rejections_total.load(Ordering::Relaxed),
        }),
        Some(PendingSnapshotFinalization::Compact(recovery)) => serde_json::json!({
            "entries": 0,
            "retained_bytes": recovery.retained_bytes,
            "max_entries": 0,
            "max_retained_bytes": 0,
            "overflow_spooled_total": recovery.metrics.snapshot_overflow_spooled_total.load(Ordering::Relaxed),
            "overflow_pending_total": recovery.metrics.snapshot_overflow_pending_total.load(Ordering::Relaxed),
            "cardinality_rejections_total": recovery.metrics.snapshot_cardinality_rejections_total.load(Ordering::Relaxed),
            "recovery": "compact",
        }),
        None => serde_json::json!({
            "entries": 0,
            "retained_bytes": 0,
            "max_entries": 0,
            "max_retained_bytes": 0,
            "overflow_spooled_total": 0,
            "overflow_pending_total": 0,
            "cardinality_rejections_total": 0,
        }),
    }
}

fn render_prometheus_for_sinks(
    sinks: &BTreeMap<String, Arc<SinkRuntime>>,
    pending_finalizations: usize,
    pending_finalization_bytes: u64,
    pending_finalization_oldest_age_secs: u64,
) -> String {
    let mut output = String::with_capacity(4096 * sinks.len().max(1));

    // Preserve the existing metric names as process-wide aggregates across
    // every current accepted instance. Per-instance identity and counters live in
    // the authenticated status endpoint; avoiding generation labels keeps
    // scrape cardinality stable across reloads and prevents aggregate +
    // component double-counting in ordinary PromQL sums.
    let mut events_enqueued = 0u64;
    let mut events_exported = 0u64;
    let mut failure_network = 0u64;
    let mut failure_http_4xx = 0u64;
    let mut failure_http_5xx = 0u64;
    let mut failure_serialize = 0u64;
    let mut failure_tls = 0u64;
    let mut failure_timeout = 0u64;
    let mut queue_depth = 0u64;
    let mut spool_bytes = 0u64;
    let mut spool_files = 0u64;
    let mut spool_drops = 0u64;
    let mut spool_prepare_failures = 0u64;
    let mut spool_jobs_enqueued = 0u64;
    let mut spool_jobs_written = 0u64;
    let mut spool_jobs_lost = 0u64;
    let mut spool_events_lost = 0u64;
    let mut spool_unbound_files = 0u64;
    let mut spool_unbound_namespaces = 0u64;
    let mut spool_enabled_any = false;
    let mut spool_all_available = true;
    let mut queue_retained_bytes = 0u64;
    let mut queue_byte_budget_exhausted = 0u64;
    let mut queue_high_water_hits = 0u64;
    let mut queue_high_water_diversions = 0u64;
    let mut queue_full_drops = 0u64;
    let mut snapshot_emits = 0u64;
    let mut snapshot_entries = 0u64;
    let mut snapshot_retained_bytes = 0u64;
    let mut snapshot_overflow_spooled = 0u64;
    let mut snapshot_overflow_pending = 0u64;
    let mut snapshot_cardinality_rejections = 0u64;
    let mut any_snapshot = false;
    let mut latency_counts: Vec<u64> = Vec::new();
    let mut latency_sum = 0.0f64;
    let mut latency_total = 0u64;
    let mut latency_buckets: &'static [f64] = &[];

    for runtime in sinks.values() {
        let metrics = &runtime.metrics;
        events_enqueued =
            events_enqueued.saturating_add(metrics.events_enqueued_total.load(Ordering::Relaxed));
        events_exported =
            events_exported.saturating_add(metrics.events_exported_total.load(Ordering::Relaxed));
        failure_network =
            failure_network.saturating_add(metrics.failure_reasons.network.load(Ordering::Relaxed));
        failure_http_4xx = failure_http_4xx
            .saturating_add(metrics.failure_reasons.http_4xx.load(Ordering::Relaxed));
        failure_http_5xx = failure_http_5xx
            .saturating_add(metrics.failure_reasons.http_5xx.load(Ordering::Relaxed));
        failure_serialize = failure_serialize
            .saturating_add(metrics.failure_reasons.serialize.load(Ordering::Relaxed));
        failure_tls =
            failure_tls.saturating_add(metrics.failure_reasons.tls.load(Ordering::Relaxed));
        failure_timeout =
            failure_timeout.saturating_add(metrics.failure_reasons.timeout.load(Ordering::Relaxed));
        queue_depth = queue_depth.saturating_add(runtime.logger.queue_depth() as u64);
        spool_drops = spool_drops.saturating_add(metrics.spool_drops_total.load(Ordering::Relaxed));
        spool_prepare_failures = spool_prepare_failures
            .saturating_add(metrics.spool_prepare_failures_total.load(Ordering::Relaxed));
        spool_jobs_enqueued = spool_jobs_enqueued
            .saturating_add(metrics.spool_jobs_enqueued_total.load(Ordering::Relaxed));
        spool_jobs_written = spool_jobs_written
            .saturating_add(metrics.spool_jobs_written_total.load(Ordering::Relaxed));
        spool_jobs_lost =
            spool_jobs_lost.saturating_add(metrics.spool_jobs_lost_total.load(Ordering::Relaxed));
        spool_events_lost = spool_events_lost
            .saturating_add(metrics.spool_events_lost_total.load(Ordering::Relaxed));
        let unbound_files = metrics.spool_unbound_files.load(Ordering::Relaxed);
        spool_unbound_files = spool_unbound_files.saturating_add(unbound_files);
        let unbound_ns = metrics.spool_unbound_namespaces.load(Ordering::Relaxed);
        spool_unbound_namespaces = spool_unbound_namespaces.saturating_add(unbound_ns);
        queue_retained_bytes =
            queue_retained_bytes.saturating_add(runtime.byte_budget.used() as u64);
        queue_byte_budget_exhausted = queue_byte_budget_exhausted.saturating_add(
            metrics
                .queue_byte_budget_exhausted_total
                .load(Ordering::Relaxed),
        );
        queue_high_water_hits = queue_high_water_hits
            .saturating_add(metrics.queue_high_water_hits_total.load(Ordering::Relaxed));
        queue_high_water_diversions = queue_high_water_diversions.saturating_add(
            metrics
                .queue_high_water_diversions_total
                .load(Ordering::Relaxed),
        );
        queue_full_drops =
            queue_full_drops.saturating_add(metrics.queue_full_drops_total.load(Ordering::Relaxed));
        let spool_stats = runtime
            .spool
            .as_ref()
            .and_then(|spool| spool.scan_stats().ok())
            .unwrap_or_default();
        spool_bytes = spool_bytes.saturating_add(spool_stats.bytes);
        spool_files = spool_files.saturating_add(spool_stats.files);
        if runtime.spool.is_some() {
            spool_enabled_any = true;
            if !metrics.spool_available.load(Ordering::Acquire) {
                spool_all_available = false;
            }
        }
        if runtime.summary.mode == SinkMode::Snapshot {
            any_snapshot = true;
            snapshot_emits =
                snapshot_emits.saturating_add(metrics.snapshot_emits_total.load(Ordering::Relaxed));
            snapshot_overflow_spooled = snapshot_overflow_spooled.saturating_add(
                metrics
                    .snapshot_overflow_spooled_total
                    .load(Ordering::Relaxed),
            );
            snapshot_overflow_pending = snapshot_overflow_pending.saturating_add(
                metrics
                    .snapshot_overflow_pending_total
                    .load(Ordering::Relaxed),
            );
            snapshot_cardinality_rejections = snapshot_cardinality_rejections.saturating_add(
                metrics
                    .snapshot_cardinality_rejections_total
                    .load(Ordering::Relaxed),
            );
            if let Some(status) = snapshot_accumulator_gauges(runtime.generation) {
                snapshot_entries = snapshot_entries.saturating_add(status.0);
                snapshot_retained_bytes = snapshot_retained_bytes.saturating_add(status.1);
            }
        }
        if latency_buckets.is_empty() {
            latency_buckets = metrics.latency.buckets;
            latency_counts = vec![0u64; latency_buckets.len()];
        }
        for (idx, count) in latency_counts.iter_mut().enumerate() {
            *count = count.saturating_add(metrics.latency.counts[idx].load(Ordering::Relaxed));
        }
        latency_sum += f64::from_bits(metrics.latency.sum_bits.load(Ordering::Relaxed));
        latency_total = latency_total.saturating_add(metrics.latency.count.load(Ordering::Relaxed));
    }

    output.push_str("# HELP chargeback_sink_events_enqueued_total Chargeback sink events admitted to the in-memory channel or accepted by a durable overflow handoff.\n");
    output.push_str("# TYPE chargeback_sink_events_enqueued_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_events_enqueued_total {}\n",
        events_enqueued
    ));
    output.push_str("# HELP chargeback_sink_events_exported_total Chargeback sink events successfully exported to ClickHouse.\n");
    output.push_str("# TYPE chargeback_sink_events_exported_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_events_exported_total {}\n",
        events_exported
    ));
    output.push_str("# HELP chargeback_sink_export_failures_total Chargeback sink export failures by bounded reason.\n");
    output.push_str("# TYPE chargeback_sink_export_failures_total counter\n");
    for (reason, value) in [
        ("network", failure_network),
        ("http_4xx", failure_http_4xx),
        ("http_5xx", failure_http_5xx),
        ("serialize", failure_serialize),
        ("tls", failure_tls),
        ("timeout", failure_timeout),
    ] {
        output.push_str(&format!(
            "chargeback_sink_export_failures_total{{reason=\"{}\"}} {}\n",
            reason, value
        ));
    }
    output.push_str("# HELP chargeback_sink_queue_depth Chargeback sink in-memory queue depth.\n");
    output.push_str("# TYPE chargeback_sink_queue_depth gauge\n");
    output.push_str(&format!("chargeback_sink_queue_depth {}\n", queue_depth));
    output.push_str(
        "# HELP chargeback_sink_queue_high_water_hits_total Chargeback sink enqueue attempts observed at or above the queue high-water mark (telemetry only).\n",
    );
    output.push_str("# TYPE chargeback_sink_queue_high_water_hits_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_queue_high_water_hits_total {}\n",
        queue_high_water_hits
    ));
    output.push_str(
        "# HELP chargeback_sink_queue_high_water_diversions_total Chargeback sink events whose high-water durable spool-delivery handoff was accepted. Spool delivery saturation/closure is counted by spool loss metrics, not this counter.\n",
    );
    output.push_str("# TYPE chargeback_sink_queue_high_water_diversions_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_queue_high_water_diversions_total {}\n",
        queue_high_water_diversions
    ));
    output.push_str(
        "# HELP chargeback_sink_queue_full_drops_total Chargeback sink events dropped because the bounded in-memory queue was full and no durable overflow path accepted ownership. Shutdown/unavailable admission is not counted here.\n",
    );
    output.push_str("# TYPE chargeback_sink_queue_full_drops_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_queue_full_drops_total {}\n",
        queue_full_drops
    ));
    output.push_str("# HELP chargeback_sink_snapshot_finalizations_pending Snapshot generations retaining unspooled terminal deltas after admission closed.\n");
    output.push_str("# TYPE chargeback_sink_snapshot_finalizations_pending gauge\n");
    output.push_str(&format!(
        "chargeback_sink_snapshot_finalizations_pending {}\n",
        pending_finalizations
    ));
    output.push_str("# HELP chargeback_sink_snapshot_finalizations_pending_bytes Estimated retained bytes for pending snapshot finalization recovery state.\n");
    output.push_str("# TYPE chargeback_sink_snapshot_finalizations_pending_bytes gauge\n");
    output.push_str(&format!(
        "chargeback_sink_snapshot_finalizations_pending_bytes {}\n",
        pending_finalization_bytes
    ));
    output.push_str("# HELP chargeback_sink_snapshot_finalizations_oldest_age_seconds Age in seconds of the oldest pending snapshot finalization recovery.\n");
    output.push_str("# TYPE chargeback_sink_snapshot_finalizations_oldest_age_seconds gauge\n");
    output.push_str(&format!(
        "chargeback_sink_snapshot_finalizations_oldest_age_seconds {}\n",
        pending_finalization_oldest_age_secs
    ));
    if any_snapshot || pending_finalizations > 0 {
        output.push_str("# HELP chargeback_sink_snapshot_entries Snapshot accumulator identities retained in memory.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_entries gauge\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_entries {}\n",
            snapshot_entries
        ));
        output.push_str("# HELP chargeback_sink_snapshot_retained_bytes Estimated snapshot accumulator retained bytes under configured max_retained_bytes.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_retained_bytes gauge\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_retained_bytes {}\n",
            snapshot_retained_bytes
        ));
        output.push_str("# HELP chargeback_sink_snapshot_overflow_spooled_total Snapshot charges durably spooled through the bounded async delivery worker after accumulator cardinality or byte budget overflow.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_overflow_spooled_total counter\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_overflow_spooled_total {}\n",
            snapshot_overflow_spooled
        ));
        output.push_str("# HELP chargeback_sink_snapshot_overflow_pending_total Snapshot overflow charges staged for the next durable emission when async spool handoff was unavailable or its write failed.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_overflow_pending_total counter\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_overflow_pending_total {}\n",
            snapshot_overflow_pending
        ));
        output.push_str("# HELP chargeback_sink_snapshot_cardinality_rejections_total Snapshot charges that could not be accumulated or overflow-spooled under hard budgets.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_cardinality_rejections_total counter\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_cardinality_rejections_total {}\n",
            snapshot_cardinality_rejections
        ));
    }
    output.push_str(
        "# HELP chargeback_sink_spool_bytes Chargeback sink on-disk owned spool bytes (active, temp, corrupt, and dead-lettered files).\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_bytes gauge\n");
    output.push_str(&format!("chargeback_sink_spool_bytes {}\n", spool_bytes));
    output.push_str(
        "# HELP chargeback_sink_spool_files Chargeback sink on-disk owned spool file count (active, temp, corrupt, and dead-lettered files).\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_files gauge\n");
    output.push_str(&format!("chargeback_sink_spool_files {}\n", spool_files));
    output.push_str("# HELP chargeback_sink_spool_drops_total Chargeback sink spool files dropped to enforce max_bytes.\n");
    output.push_str("# TYPE chargeback_sink_spool_drops_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_drops_total {}\n",
        spool_drops
    ));
    output.push_str("# HELP chargeback_sink_spool_available Whether committed spool storage is currently writable (1) or unavailable (0). Aggregate is 1 only when every spool-enabled live instance is available.\n");
    output.push_str("# TYPE chargeback_sink_spool_available gauge\n");
    output.push_str(&format!(
        "chargeback_sink_spool_available {}\n",
        if spool_enabled_any && spool_all_available {
            1
        } else {
            0
        }
    ));
    output.push_str("# HELP chargeback_sink_spool_prepare_failures_total Chargeback sink committed spool storage preparation failures.\n");
    output.push_str("# TYPE chargeback_sink_spool_prepare_failures_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_prepare_failures_total {}\n",
        spool_prepare_failures
    ));
    output.push_str("# HELP chargeback_sink_spool_unbound_files Retained spool records not bound to a live destination identity. Never replayed or deleted; an observed lower bound when the bounded aggregate scan is truncated.\n");
    output.push_str("# TYPE chargeback_sink_spool_unbound_files gauge\n");
    output.push_str(&format!(
        "chargeback_sink_spool_unbound_files {}\n",
        spool_unbound_files
    ));
    output.push_str("# HELP chargeback_sink_spool_unbound_namespaces Managed spool namespaces still holding records for a destination identity no live instance owns; an observed lower bound when the bounded aggregate scan is truncated.\n");
    output.push_str("# TYPE chargeback_sink_spool_unbound_namespaces gauge\n");
    output.push_str(&format!(
        "chargeback_sink_spool_unbound_namespaces {}\n",
        spool_unbound_namespaces
    ));
    output.push_str(
        "# HELP chargeback_sink_spool_jobs_enqueued_total Chargeback sink jobs accepted by the async spool delivery worker.\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_jobs_enqueued_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_jobs_enqueued_total {}\n",
        spool_jobs_enqueued
    ));
    output.push_str(
        "# HELP chargeback_sink_spool_jobs_written_total Chargeback sink jobs successfully written by the async spool delivery worker.\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_jobs_written_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_jobs_written_total {}\n",
        spool_jobs_written
    ));
    output.push_str(
        "# HELP chargeback_sink_spool_jobs_lost_total Chargeback sink spool delivery jobs dropped under saturation or write failure.\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_jobs_lost_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_jobs_lost_total {}\n",
        spool_jobs_lost
    ));
    output.push_str(
        "# HELP chargeback_sink_spool_events_lost_total Chargeback sink events lost with dropped spool delivery jobs.\n",
    );
    output.push_str("# TYPE chargeback_sink_spool_events_lost_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_spool_events_lost_total {}\n",
        spool_events_lost
    ));
    output.push_str(
        "# HELP chargeback_sink_queue_retained_bytes Chargeback sink retained export and spool-delivery bytes under the configured buffer_max_bytes budget.\n",
    );
    output.push_str("# TYPE chargeback_sink_queue_retained_bytes gauge\n");
    output.push_str(&format!(
        "chargeback_sink_queue_retained_bytes {}\n",
        queue_retained_bytes
    ));
    output.push_str(
        "# HELP chargeback_sink_queue_byte_budget_exhausted_total Chargeback sink export admissions rejected by the retained-byte budget.\n",
    );
    output.push_str("# TYPE chargeback_sink_queue_byte_budget_exhausted_total counter\n");
    output.push_str(&format!(
        "chargeback_sink_queue_byte_budget_exhausted_total {}\n",
        queue_byte_budget_exhausted
    ));
    output.push_str("# HELP chargeback_sink_export_latency_seconds Chargeback sink ClickHouse export latency in seconds.\n");
    output.push_str("# TYPE chargeback_sink_export_latency_seconds histogram\n");
    for (idx, bucket) in latency_buckets.iter().enumerate() {
        let cumulative = latency_counts.get(idx).copied().unwrap_or(0);
        output.push_str(&format!(
            "chargeback_sink_export_latency_seconds_bucket{{le=\"{}\"}} {}\n",
            bucket, cumulative
        ));
    }
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
        latency_total
    ));
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_sum {:.6}\n",
        latency_sum
    ));
    output.push_str(&format!(
        "chargeback_sink_export_latency_seconds_count {}\n",
        latency_total
    ));
    if any_snapshot {
        output.push_str("# HELP chargeback_sink_snapshot_emits_total Chargeback sink snapshot delta events emitted.\n");
        output.push_str("# TYPE chargeback_sink_snapshot_emits_total counter\n");
        output.push_str(&format!(
            "chargeback_sink_snapshot_emits_total {}\n",
            snapshot_emits
        ));
    }

    output
}

/// Structured ClickHouse delivery result.
///
/// Distinguishes retryable transport/backpressure failures from permanent HTTP
/// rejection and payload-too-large (413) so spool replay can dead-letter or
/// split without head-of-line blocking newer files. Safe messages never include
/// response bodies, credentials, or charge-record fields.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeliveryOutcome {
    Delivered,
    Retryable { message: String },
    Permanent { status: u16, message: String },
    PayloadTooLarge { message: String },
}

impl DeliveryOutcome {
    fn safe_message(&self) -> &str {
        match self {
            DeliveryOutcome::Delivered => "delivered",
            DeliveryOutcome::Retryable { message }
            | DeliveryOutcome::Permanent { message, .. }
            | DeliveryOutcome::PayloadTooLarge { message } => message.as_str(),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            DeliveryOutcome::Delivered => "delivered",
            DeliveryOutcome::Retryable { .. } => "retryable",
            DeliveryOutcome::Permanent { .. } => "permanent",
            DeliveryOutcome::PayloadTooLarge { .. } => "payload_too_large",
        }
    }
}

/// Bounded ClickHouse HTTP acknowledgement after headers arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClickHouseAckRead {
    /// Full body drained within the byte/time caps.
    Complete { byte_len: u64, has_exception: bool },
    /// Drain did not finish cleanly; treat as ambiguous for durability.
    Incomplete { kind: ClickHouseAckIncomplete },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClickHouseAckIncomplete {
    LimitExceeded,
    Timeout,
    TransportFailure,
}

impl ClickHouseAckIncomplete {
    fn as_str(self) -> &'static str {
        match self {
            Self::LimitExceeded => "acknowledgement body exceeded the drain limit",
            Self::Timeout => "acknowledgement body drain timed out",
            Self::TransportFailure => "acknowledgement body drain had a transport failure",
        }
    }
}

/// Fixed JSONEachRow row framing plus the compile-time field-name set one
/// serialized charge event costs beyond its own retained strings.
const CHARGE_ROW_JSON_OVERHEAD_BYTES: usize = 1_024;

/// Provisional upper bound on the JSONEachRow request body for `batch`.
///
/// Charge-event strings are raw, so JSON escaping can expand each byte six-fold.
/// This bound is reserved **before** serialization; after the body exists the
/// reservation shrinks to the buffer's exact retained capacity (framing and
/// escaping included), so the delivery lifetime never pins the provisional
/// over-estimate.
fn charge_body_byte_bound(
    batch: &[ChargeEvent],
    projection: Option<&ChargeEventProjection>,
) -> Option<usize> {
    // A projection can only ADD bytes per row (renamed keys, injected static /
    // derived members). The per-row surcharge is precomputed at construction so
    // the reservation still precedes serialization.
    let projection_row_bytes = projection.map_or(0, |p| p.row_overhead_bytes);
    let mut total = CHARGE_ROW_JSON_OVERHEAD_BYTES;
    for event in batch {
        total = total
            .checked_add(
                charge_event_retained_bytes(event).checked_mul(JSON_STRING_WORST_CASE_EXPANSION)?,
            )?
            .checked_add(CHARGE_ROW_JSON_OVERHEAD_BYTES)?
            .checked_add(projection_row_bytes)?;
    }
    Some(total)
}

/// Serialize `batch` into the reserved-and-charged JSONEachRow request body.
///
/// The queued events still hold their per-instance leases here, so the body is a
/// second attacker-shaped copy: a provisional escaping/framing bound is reserved
/// against the retained-byte ceiling before serialization, then shrunk to the
/// exact retained allocation, and stays charged until the request (and every
/// retry handle taken from it) is gone.
fn materialize_charge_body(
    cfg: &ClickHouseFlushConfig,
    batch: &[ChargeEvent],
) -> Result<ReservedPayload, String> {
    materialize_json_each_row(cfg.ceiling, batch, cfg.projection.as_deref())
}

/// Reject a batch whose charges cannot be represented in JSON before any
/// attacker-shaped representation of it is allocated.
fn validate_charge_batch(batch: &[ChargeEvent]) -> Result<(), String> {
    for event in batch {
        for (field, value) in [
            ("charge_call", event.charge_call),
            ("charge_bytes_sent", event.charge_bytes_sent),
            ("charge_bytes_received", event.charge_bytes_received),
            ("charge_total", event.charge_total),
        ] {
            require_finite_charge(value, field).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: event '{}' cannot be serialized: {error}",
                    event.event_id
                )
            })?;
        }
    }
    Ok(())
}

/// Write `batch` as JSONEachRow into `writer` without ever building an
/// intermediate owned row `String`.
/// This is the single funnel every externally emitted charge-event
/// representation goes through — the HTTP INSERT body and the durable spool
/// artifact alike — so the projection is applied here exactly once. The spool
/// artifact is a durable copy of the delivery body and is replayed verbatim, so
/// a file written before a schema change replays under the schema in force when
/// it was written. Internal identities (`SnapshotEntry` keys, spool ownership,
/// accumulator keys) never pass through here and are untouched by projection.
fn write_json_each_row<W: Write>(
    writer: &mut W,
    batch: &[ChargeEvent],
    projection: Option<&ChargeEventProjection>,
) -> Result<(), String> {
    for (index, event) in batch.iter().enumerate() {
        if index > 0 {
            writer
                .write_all(b"\n")
                .map_err(|error| format!("failed to write row separator: {error}"))?;
        }
        let result = match projection {
            None => serde_json::to_writer(&mut *writer, event),
            Some(projection) => serde_json::to_writer(
                &mut *writer,
                &SchemaView {
                    summary: event,
                    schema: &projection.schema,
                },
            ),
        };
        result.map_err(|error| format!("failed to serialize charge event: {error}"))?;
    }
    Ok(())
}

/// Serialize `batch` into a JSONEachRow payload whose allocation is reserved
/// against `ceiling` before a single byte is written and stays charged for the
/// payload's whole life.
///
/// Admission uses a provisional escaping/framing bound so serialization cannot
/// outgrow the ceiling; after the write succeeds the charge shrinks to the
/// exact retained buffer capacity (JSON framing and escaping included). Every
/// producer of an attacker-shaped JSONEachRow representation — the HTTP delivery
/// body and the durable spool artifact alike — goes through here, so no caller
/// can serialize first and measure afterwards.
fn materialize_json_each_row(
    ceiling: &'static RetainedByteCeiling,
    batch: &[ChargeEvent],
    projection: Option<&ChargeEventProjection>,
) -> Result<ReservedPayload, String> {
    validate_charge_batch(batch)?;
    let bound = charge_body_byte_bound(batch, projection).ok_or_else(|| {
        format!(
            "{PLUGIN_NAME}: {}",
            PayloadMaterializationError::BoundOverflowed.reason()
        )
    })?;
    materialize_reserved_payload(ceiling, bound, |writer| {
        write_json_each_row(writer, batch, projection)
    })
    .map_err(|error| format!("{PLUGIN_NAME}: {}", error.reason()))
}

async fn send_batch(cfg: &ClickHouseFlushConfig, batch: Vec<ChargeEvent>) -> Result<(), String> {
    let event_count = batch.len();
    let body = materialize_charge_body(cfg, &batch).inspect_err(|error| {
        cfg.metrics
            .record_failure(FailureReason::Serialize, error.clone());
    })?;
    // The reserved body is the only representation delivery needs; the events
    // themselves are released here so peak retention is the queue's leases plus
    // one exactly-charged body rather than the queue plus per-attempt copies.
    drop(batch);
    match post_json_each_row(cfg, body, event_count).await {
        DeliveryOutcome::Delivered => Ok(()),
        other => Err(other.safe_message().to_string()),
    }
}

async fn post_json_each_row(
    cfg: &ClickHouseFlushConfig,
    body: ReservedPayload,
    event_count: usize,
) -> DeliveryOutcome {
    let start = Instant::now();
    let mut request = match &cfg.http {
        ClickHouseHttpClient::Shared(client) => client.get().post(&cfg.insert_url),
        ClickHouseHttpClient::Dedicated(client) => client.post(&cfg.insert_url),
    }
    .timeout(cfg.timeout)
    .header(CONTENT_TYPE, "application/json")
    // Refcount handle on the reserved body: no second copy per attempt.
    .body(body.bytes());
    if let Some(username) = cfg.username.as_deref() {
        request = request.basic_auth(username, cfg.password.clone());
    }
    let result = cfg.http.execute(request, &cfg.redacted_insert_url).await;
    match result {
        Ok(response) => {
            let status = response.status();
            let has_exception_header = response
                .headers()
                .contains_key("x-clickhouse-exception-code");
            let ack = read_clickhouse_acknowledgement(response).await;
            classify_clickhouse_delivery(
                cfg,
                status,
                ack,
                has_exception_header,
                event_count,
                start.elapsed(),
            )
        }
        Err(error) => {
            let reason = classify_reqwest_failure(&error);
            let message = reason.as_str().to_string();
            cfg.metrics.record_failure(reason, message.clone());
            DeliveryOutcome::Retryable { message }
        }
    }
}

async fn read_clickhouse_acknowledgement(response: reqwest::Response) -> ClickHouseAckRead {
    if response
        .content_length()
        .is_some_and(|length| length > CLICKHOUSE_ACK_BODY_LIMIT_BYTES as u64)
    {
        return ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::LimitExceeded,
        };
    }
    match tokio::time::timeout(
        HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT,
        read_response_body_bounded(response, CLICKHOUSE_ACK_BODY_LIMIT_BYTES),
    )
    .await
    {
        Err(_) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::Timeout,
        },
        Ok(Ok(bytes)) => {
            // Response (and its pooled connection) were dropped when the read
            // future completed; yield so idle-pool reclaim can run before the
            // next POST on this client.
            tokio::task::yield_now().await;
            ClickHouseAckRead::Complete {
                byte_len: bytes.len() as u64,
                has_exception: body_has_clickhouse_exception(&bytes),
            }
        }
        Ok(Err(BoundedReadError::LimitExceeded { .. })) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::LimitExceeded,
        },
        Ok(Err(BoundedReadError::Stream(_))) => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::TransportFailure,
        },
    }
}

/// Detect ClickHouse exception markers in a bounded acknowledgement body.
///
/// Inspects bytes only for known markers; never logs or returns the payload.
fn body_has_clickhouse_exception(body: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[b"DB::Exception", b"Code: "];
    MARKERS
        .iter()
        .any(|marker| find_bytes_subslice(body, marker).is_some())
}

fn find_bytes_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn classify_clickhouse_delivery(
    cfg: &ClickHouseFlushConfig,
    status: StatusCode,
    ack: ClickHouseAckRead,
    has_exception_header: bool,
    event_count: usize,
    elapsed: Duration,
) -> DeliveryOutcome {
    if matches!(status, StatusCode::OK | StatusCode::NO_CONTENT) {
        return classify_success_status_acknowledgement(
            cfg,
            status,
            ack,
            has_exception_header,
            event_count,
            elapsed,
        );
    }

    let code = status.as_u16();
    let message = format!("clickhouse returned HTTP {code}");
    if code == 413 {
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::PayloadTooLarge { message };
    }
    if code == 401 || code == 403 || code == 408 || code == 429 || status.is_server_error() {
        let reason = if status.is_server_error() {
            FailureReason::Http5xx
        } else {
            FailureReason::Http4xx
        };
        cfg.metrics.record_failure(reason, message.clone());
        return DeliveryOutcome::Retryable { message };
    }
    if status.is_client_error() {
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::Permanent {
            status: code,
            message,
        };
    }
    cfg.metrics
        .record_failure(FailureReason::Network, message.clone());
    DeliveryOutcome::Retryable { message }
}

fn classify_success_status_acknowledgement(
    cfg: &ClickHouseFlushConfig,
    status: StatusCode,
    ack: ClickHouseAckRead,
    has_exception_header: bool,
    event_count: usize,
    elapsed: Duration,
) -> DeliveryOutcome {
    let code = status.as_u16();
    if has_exception_header {
        let message = format!("clickhouse returned HTTP {code} with X-ClickHouse-Exception-Code");
        cfg.metrics
            .record_failure(FailureReason::Http4xx, message.clone());
        return DeliveryOutcome::Permanent {
            status: code,
            message,
        };
    }
    match ack {
        ClickHouseAckRead::Complete {
            byte_len: 0,
            has_exception: false,
        } => {
            cfg.metrics.record_success(event_count, elapsed);
            DeliveryOutcome::Delivered
        }
        ClickHouseAckRead::Complete {
            has_exception: true,
            ..
        } => {
            let message = format!(
                "clickhouse returned HTTP {code} with an exception in the acknowledgement body"
            );
            cfg.metrics
                .record_failure(FailureReason::Http4xx, message.clone());
            DeliveryOutcome::Permanent {
                status: code,
                message,
            }
        }
        ClickHouseAckRead::Complete {
            byte_len,
            has_exception: false,
        } => {
            // Non-empty success bodies are not a persistence-proof ACK for
            // INSERT JSONEachRow; keep the spool and retry idempotently.
            let message = format!(
                "clickhouse returned HTTP {code} with an ambiguous non-empty acknowledgement ({byte_len} bytes)"
            );
            cfg.metrics
                .record_failure(FailureReason::Network, message.clone());
            DeliveryOutcome::Retryable { message }
        }
        ClickHouseAckRead::Incomplete { kind } => {
            let message = format!(
                "clickhouse returned HTTP {code} but acknowledgement was incomplete: {}",
                kind.as_str()
            );
            let reason = match kind {
                ClickHouseAckIncomplete::Timeout => FailureReason::Timeout,
                ClickHouseAckIncomplete::LimitExceeded
                | ClickHouseAckIncomplete::TransportFailure => FailureReason::Network,
            };
            cfg.metrics.record_failure(reason, message.clone());
            DeliveryOutcome::Retryable { message }
        }
    }
}

/// Deterministic split point for a 413 replay chunk.
///
/// Prefers `batch_size` when that still shrinks the chunk; otherwise halves.
/// Always returns a value in `1..len` when `len >= 2` so splitting makes progress.
fn replay_split_len(len: usize, batch_size: usize) -> usize {
    debug_assert!(len >= 2);
    let half = len / 2;
    let preferred = batch_size.min(half).max(1);
    preferred.min(len - 1)
}

/// Serialize `batch` into an owned JSONEachRow `String`.
///
/// Production never uses this shape: the resulting `String` outlives any
/// retained-byte reservation, which is exactly the uncharged materialization
/// [`materialize_json_each_row`] exists to prevent. External unit tests use it
/// to build expected wire bytes.
#[allow(dead_code)]
pub fn serialize_json_each_row(batch: &[ChargeEvent]) -> Result<String, String> {
    serialize_json_each_row_projected(batch, None)
}

/// [`serialize_json_each_row`] under an optional compiled projection.
///
/// External unit tests use this to assert that a projected wire representation
/// matches the operator's schema while the native shape is unchanged.
#[doc(hidden)]
#[allow(dead_code)]
pub fn serialize_json_each_row_projected(
    batch: &[ChargeEvent],
    projection: Option<&ChargeEventProjection>,
) -> Result<String, String> {
    validate_charge_batch(batch)?;
    let mut output: Vec<u8> = Vec::new();
    write_json_each_row(&mut output, batch, projection)
        .map_err(|error| format!("{PLUGIN_NAME}: {error}"))?;
    String::from_utf8(output)
        .map_err(|error| format!("{PLUGIN_NAME}: failed to serialize charge event: {error}"))
}

fn classify_reqwest_failure(error: &reqwest::Error) -> FailureReason {
    if error.is_timeout() {
        return FailureReason::Timeout;
    }
    let lower = error.to_string().to_ascii_lowercase();
    if lower.contains("tls")
        || lower.contains("certificate")
        || lower.contains("handshake")
        || lower.contains("rustls")
    {
        FailureReason::Tls
    } else {
        FailureReason::Network
    }
}

fn validate_config(config: &ApiChargebackSinkConfig) -> Result<(), String> {
    let url = parse_clickhouse_url(&config.clickhouse.url)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.url must not contain user-info; use username/password_ref"
        ));
    }
    validate_clickhouse_identifier(&config.clickhouse.database, "database")?;
    validate_clickhouse_identifier(&config.clickhouse.table, "table")?;
    if config.clickhouse.timeout_ms == 0 || config.clickhouse.timeout_ms > MAX_CLICKHOUSE_TIMEOUT_MS
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.timeout_ms must be between 1 and {MAX_CLICKHOUSE_TIMEOUT_MS}"
        ));
    }
    validate_query_params(&config.clickhouse.insert_query_params)?;
    validate_insert_durability_settings(&config.clickhouse)?;

    if config.batch.size == 0 || config.batch.size > MAX_BATCH_SIZE {
        return Err(format!(
            "{PLUGIN_NAME}: batch.size must be between 1 and {MAX_BATCH_SIZE}"
        ));
    }
    if config.batch.buffer_capacity == 0 || config.batch.buffer_capacity > MAX_BUFFER_CAPACITY {
        return Err(format!(
            "{PLUGIN_NAME}: batch.buffer_capacity must be between 1 and {MAX_BUFFER_CAPACITY}"
        ));
    }
    if config.batch.buffer_max_bytes < MAX_CHARGE_EVENT_BYTES
        || config.batch.buffer_max_bytes > HARD_MAX_BUFFER_MAX_BYTES
    {
        return Err(format!(
            "{PLUGIN_NAME}: batch.buffer_max_bytes must be between {MAX_CHARGE_EVENT_BYTES} and {HARD_MAX_BUFFER_MAX_BYTES}"
        ));
    }
    if config.batch.flush_interval_ms == 0
        || config.batch.flush_interval_ms > MAX_BATCH_FLUSH_INTERVAL_MS
    {
        return Err(format!(
            "{PLUGIN_NAME}: batch.flush_interval_ms must be between 1 and {MAX_BATCH_FLUSH_INTERVAL_MS}"
        ));
    }
    if config.retry.max_attempts == 0 || config.retry.max_attempts > MAX_RETRY_MAX_ATTEMPTS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_attempts must be between 1 and {MAX_RETRY_MAX_ATTEMPTS}"
        ));
    }
    if config.retry.initial_delay_ms > MAX_RETRY_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.initial_delay_ms must be between 0 and {MAX_RETRY_DELAY_MS}"
        ));
    }
    if config.retry.max_delay_ms > MAX_RETRY_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_delay_ms must be between 0 and {MAX_RETRY_DELAY_MS}"
        ));
    }
    if config.retry.max_delay_ms < config.retry.initial_delay_ms {
        return Err(format!(
            "{PLUGIN_NAME}: retry.max_delay_ms must be >= retry.initial_delay_ms"
        ));
    }
    let worst_case_delay_ms = worst_case_inter_attempt_delay_ms(
        config.retry.max_attempts,
        config.retry.initial_delay_ms,
        config.retry.max_delay_ms,
    );
    if worst_case_delay_ms > MAX_RETRY_TOTAL_DELAY_MS {
        return Err(format!(
            "{PLUGIN_NAME}: retry worst-case cumulative inter-attempt delay ({worst_case_delay_ms} ms) exceeds the {MAX_RETRY_TOTAL_DELAY_MS} ms budget; reduce retry.max_attempts, retry.initial_delay_ms, and/or retry.max_delay_ms"
        ));
    }
    if config.spool.enabled {
        if config.spool.max_bytes == 0 {
            return Err(format!("{PLUGIN_NAME}: spool.max_bytes must be at least 1"));
        }
        if config.spool.replay_interval_secs == 0 {
            return Err(format!(
                "{PLUGIN_NAME}: spool.replay_interval_secs must be at least 1"
            ));
        }
        if config.spool.delivery_queue_capacity == 0
            || config.spool.delivery_queue_capacity > MAX_BUFFER_CAPACITY
        {
            return Err(format!(
                "{PLUGIN_NAME}: spool.delivery_queue_capacity must be between 1 and {MAX_BUFFER_CAPACITY}"
            ));
        }
        // Shape-only: do not mkdir/chmod/probe here. Live storage preparation
        // starts only after the candidate generation is committed.
        validate_spool_dir_shape(&config.spool.dir)?;
    } else if config.mode == SinkMode::Snapshot {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot mode requires spool.enabled=true so emitted deltas remain durable during ClickHouse outages"
        ));
    }
    if config.snapshot.interval_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.interval_secs must be at least 1"
        ));
    }
    if config.snapshot.cleanup_interval_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.cleanup_interval_secs must be at least 1"
        ));
    }
    if config.snapshot.stale_entry_ttl_secs == 0 {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.stale_entry_ttl_secs must be at least 1"
        ));
    }
    if config.snapshot.stale_entry_ttl_secs < config.snapshot.interval_secs {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.stale_entry_ttl_secs must be >= snapshot.interval_secs so idle keys cannot expire before their first durable emission window"
        ));
    }
    if config.snapshot.max_entries == 0 || config.snapshot.max_entries > MAX_BUFFER_CAPACITY {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.max_entries must be between 1 and {MAX_BUFFER_CAPACITY}"
        ));
    }
    if config.snapshot.max_retained_bytes < MAX_CHARGE_EVENT_BYTES
        || config.snapshot.max_retained_bytes > HARD_MAX_BUFFER_MAX_BYTES
    {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot.max_retained_bytes must be between {MAX_CHARGE_EVENT_BYTES} and {HARD_MAX_BUFFER_MAX_BYTES}"
        ));
    }
    if config
        .clickhouse
        .password_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty() && url.scheme() != "https")
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref requires clickhouse.url to use https://"
        ));
    }
    if config
        .clickhouse
        .password_ref
        .as_deref()
        .is_some_and(|value| {
            !value.trim().is_empty()
                && (config.clickhouse.tls.insecure_skip_verify
                    || !config.clickhouse.tls.verify_hostname)
        })
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref cannot be used when ClickHouse TLS certificate or hostname verification is disabled"
        ));
    }
    // Shape-only secret-ref check (do not materialize the env value here).
    if let Some(reference) = config
        .clickhouse
        .password_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && !reference.starts_with("FERRUM_")
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref must reference a FERRUM_* environment variable"
        ));
    }
    if config.pricing_version.trim().is_empty() {
        return Err(format!("{PLUGIN_NAME}: pricing_version must not be empty"));
    }
    if config.currency.trim().is_empty() {
        return Err(format!("{PLUGIN_NAME}: currency must not be empty"));
    }
    Ok(())
}

fn validate_spool_dir_shape(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(format!("{PLUGIN_NAME}: spool.dir must not be empty"));
    }
    // Reject NUL-containing paths without touching the filesystem.
    let display = path.to_string_lossy();
    if display.contains('\0') {
        return Err(format!(
            "{PLUGIN_NAME}: spool.dir must not contain NUL bytes"
        ));
    }
    Ok(())
}

fn parse_clickhouse_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw)
        .map_err(|error| format!("{PLUGIN_NAME}: invalid clickhouse.url: {error}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.url must use http:// or https:// (got {scheme})"
            ));
        }
    }
    if url.host_str().is_none() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.url must include a hostname or IP address"
        ));
    }
    Ok(url)
}

/// ClickHouse database/table names are interpolated directly into the
/// `INSERT INTO <table> FORMAT JSONEachRow` query string in [`build_insert_url`],
/// so restrict them to a safe identifier charset (ASCII letters, digits,
/// underscore, and a `.` db-qualifier) to keep operator config from injecting
/// SQL into the export query.
fn validate_clickhouse_identifier(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.{field} must not be empty"
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.{field} may only contain ASCII letters, digits, underscores, and dots"
        ));
    }
    Ok(())
}

/// ClickHouse parameter names that carry a reusable credential.
///
/// ClickHouse accepts `user`/`password`/`access_token` as HTTP query
/// parameters, so an operator could authenticate that way. Ferrum does not
/// support it: `clickhouse.username` and `clickhouse.password_ref` are the
/// dedicated channel and send the credential as an HTTP Basic header, which is
/// never rendered in diagnostics and never appended to a URL. Admitting the
/// query form would put a reusable database credential into the configured
/// `insert_query_params` map — a value that admin projections and config
/// exports treat as ordinary tuning.
///
/// This list is exact-match and lowercase; it is deliberately bounded rather
/// than a substring screen so that legitimate ClickHouse settings are never
/// refused by accident.
const CREDENTIAL_QUERY_PARAM_NAMES: &[&str] = &["access_token", "password", "session_id", "user"];

/// Substrings that mark an operator-invented credential-bearing parameter name.
///
/// ClickHouse has no settings containing these tokens, so a name that does is
/// far more likely to be a hand-rolled secret than a tuning knob. Kept short
/// and explicit for the same reason as [`CREDENTIAL_QUERY_PARAM_NAMES`].
const CREDENTIAL_QUERY_PARAM_MARKERS: &[&str] = &[
    "apikey",
    "api_key",
    "credential",
    "passwd",
    "secret",
    "token",
];

fn validate_query_params(params: &HashMap<String, String>) -> Result<(), String> {
    for (key, value) in params {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.insert_query_params contains invalid key"
            ));
        }
        // Reject credential-bearing *names* outright. Values stay arbitrary
        // (bounded length, no control characters) and are protected instead by
        // never rendering the INSERT query string in any diagnostic — see
        // `ClickHouseFlushConfig::redacted_insert_url`.
        let lowered = key.to_ascii_lowercase();
        if CREDENTIAL_QUERY_PARAM_NAMES.contains(&lowered.as_str())
            || CREDENTIAL_QUERY_PARAM_MARKERS
                .iter()
                .any(|marker| lowered.contains(marker))
        {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.insert_query_params['{key}'] names a credential; \
                 ClickHouse credentials belong in clickhouse.username and \
                 clickhouse.password_ref, which are sent as an HTTP Basic header rather than \
                 appended to the INSERT URL"
            ));
        }
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.insert_query_params['{key}'] contains invalid value"
            ));
        }
    }
    Ok(())
}

/// Durable mode rejects fire-and-forget async inserts unless the operator sets
/// an explicitly named lossy opt-in that cannot be confused with durable mode.
fn validate_insert_durability_settings(cfg: &ClickHouseConfig) -> Result<(), String> {
    let Some(wait_value) = cfg.insert_query_params.get(WAIT_FOR_ASYNC_INSERT_PARAM) else {
        return Ok(());
    };
    if !is_falsy_clickhouse_setting(wait_value) {
        return Ok(());
    }
    if !cfg.allow_lossy_async_insert {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.insert_query_params['{WAIT_FOR_ASYNC_INSERT_PARAM}']=\
             {wait_value:?} disables persistence-aware acknowledgement; set \
             wait_for_async_insert to \"1\" for durable export, or set \
             clickhouse.allow_lossy_async_insert=true to explicitly opt into \
             fire-and-forget loss"
        ));
    }
    Ok(())
}

fn is_falsy_clickhouse_setting(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn build_insert_url(base: &Url, cfg: &ClickHouseConfig) -> String {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let pins_durable_async_ack = cfg
        .insert_query_params
        .get("async_insert")
        .is_some_and(|value| !is_falsy_clickhouse_setting(value))
        && !cfg
            .insert_query_params
            .contains_key(WAIT_FOR_ASYNC_INSERT_PARAM);
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("database", &cfg.database);
        pairs.append_pair(
            "query",
            &format!("INSERT INTO {} FORMAT JSONEachRow", cfg.table),
        );
        for (key, value) in &cfg.insert_query_params {
            pairs.append_pair(key, value);
        }
        if pins_durable_async_ack {
            // Do not inherit a ClickHouse user/profile default that may be
            // fire-and-forget. An explicit falsy value remains available only
            // through the separately validated lossy opt-in.
            pairs.append_pair(WAIT_FOR_ASYNC_INSERT_PARAM, "1");
        }
    }
    url.to_string()
}

fn sanitized_endpoint(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string().trim_end_matches('/').to_string()
}

fn resolve_password_ref(password_ref: Option<&str>) -> Result<Option<String>, String> {
    let Some(reference) = password_ref
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if !reference.starts_with("FERRUM_") {
        return Err(format!(
            "{PLUGIN_NAME}: clickhouse.password_ref must reference a FERRUM_* environment variable"
        ));
    }
    if let Ok(value) = std::env::var(reference) {
        return Ok(Some(value));
    }
    Err(format!(
        "{PLUGIN_NAME}: clickhouse.password_ref references unset environment variable"
    ))
}

fn build_clickhouse_http_client(
    cfg: &ClickHouseConfig,
    shared: &PluginHttpClient,
) -> Result<ClickHouseHttpClient, String> {
    let custom_tls = cfg.tls.ca_file.is_some()
        || cfg.tls.client_cert_file.is_some()
        || cfg.tls.client_key_file.is_some()
        || !cfg.tls.verify_hostname
        || cfg.tls.insecure_skip_verify;
    if !custom_tls {
        return Ok(ClickHouseHttpClient::Shared(Box::new(shared.clone())));
    }

    // Ignore ambient `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`
    // process state (matches the shared PluginHttpClient builders). reqwest
    // enables system-proxy discovery by default. With a proxy selected, the
    // connector dials and screens the *proxy* while the proxy resolves and
    // connects to the configured ClickHouse host, so the ultimate destination
    // address never passes the `DnsCacheResolver` egress screen installed
    // below. Inherited proxy environment must not be able to override the
    // gateway's documented outbound address boundary.
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_millis(cfg.timeout_ms))
        .timeout(Duration::from_millis(cfg.timeout_ms))
        // Do not follow redirects: a 3xx from an allowed ClickHouse host could
        // otherwise bounce an export to an egress-policy-denied IP (matches the
        // shared PluginHttpClient redirect policy).
        .redirect(reqwest::redirect::Policy::none());
    if let Some(dns_cache) = shared.dns_cache().cloned() {
        builder = builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache)));
    }
    if cfg.tls.insecure_skip_verify {
        warn!(
            plugin = PLUGIN_NAME,
            "ClickHouse TLS certificate verification is disabled; use only for testing"
        );
        builder = builder.danger_accept_invalid_certs(true);
    }
    if !cfg.tls.verify_hostname {
        warn!(
            plugin = PLUGIN_NAME,
            "ClickHouse TLS hostname verification is disabled; use only for testing"
        );
        builder = builder.tls_danger_accept_invalid_hostnames(true);
    }
    if let Some(ca_file) = cfg.tls.ca_file.as_ref() {
        let pem = fs::read(ca_file).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to read clickhouse.tls.ca_file '{}': {error}",
                ca_file.display()
            )
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to parse clickhouse.tls.ca_file '{}': {error}",
                ca_file.display()
            )
        })?;
        builder = builder.tls_certs_only(certs);
    }
    match (&cfg.tls.client_cert_file, &cfg.tls.client_key_file) {
        (Some(cert), Some(key)) => {
            let mut pem = fs::read(cert).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to read clickhouse.tls.client_cert_file '{}': {error}",
                    cert.display()
                )
            })?;
            let mut key_pem = fs::read(key).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to read clickhouse.tls.client_key_file '{}': {error}",
                    key.display()
                )
            })?;
            pem.push(b'\n');
            pem.append(&mut key_pem);
            let identity = reqwest::Identity::from_pem(&pem).map_err(|error| {
                format!("{PLUGIN_NAME}: failed to parse ClickHouse client identity: {error}")
            })?;
            builder = builder.identity(identity);
        }
        (None, None) => {}
        _ => {
            return Err(format!(
                "{PLUGIN_NAME}: clickhouse.tls.client_cert_file and client_key_file must be set together"
            ));
        }
    }
    builder
        .build()
        .map(ClickHouseHttpClient::Dedicated)
        .map_err(|error| format!("{PLUGIN_NAME}: failed to build ClickHouse HTTP client: {error}"))
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolStats {
    pub files: u64,
    pub bytes: u64,
}

/// One owned spool artifact with the size used for quota accounting.
#[derive(Debug, Clone)]
struct OwnedSpoolEntry {
    path: PathBuf,
    len: u64,
}

/// Single walk/sort/stat snapshot of owned spool usage.
#[derive(Debug, Clone, Default)]
struct OwnedSpoolInventory {
    entries: Vec<OwnedSpoolEntry>,
    stats: SpoolStats,
}

/// Deterministic report from one quota-eviction admission attempt.
///
/// External tests use this to prove multi-file reclaim is planned from a single
/// inventory/sort rather than rescanning after every deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaEvictionReport {
    /// How many times owned spool metadata was inventoried/sorted. Greater than
    /// one only when a selected candidate disappeared and the snapshot had to be
    /// refreshed before an admission decision could be made.
    pub inventory_passes: u64,
    /// Owned files observed, summed across every inventory pass.
    pub files_inventoried: u64,
    /// Owned bytes observed by the first inventory pass, before any deletion.
    pub bytes_before: u64,
    /// Files successfully unlinked during the pass.
    pub files_deleted: u64,
    /// Bytes freed according to the inventory snapshot sizes.
    pub bytes_freed: u64,
}

/// Versioned durable ownership record for one managed chargeback spool namespace.
///
/// Binds the whole namespace to the accepted plugin-config identity, the Ferrum
/// namespace/ledger, the node identity, and the ClickHouse destination/schema it
/// was produced for. It holds no credentials: `destination_endpoint` is the
/// credential-free configured base URL (including its path, when present) and
/// the ClickHouse password is deliberately excluded so neither the record nor
/// the derived digest is credential-derived. Replay validates this record before
/// touching any billing file, and every individual file additionally carries
/// [`SpoolOwner::tag`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SpoolNamespaceMeta {
    version: u32,
    owner_digest: String,
    owner_tag: String,
    plugin_config_id: String,
    ferrum_namespace: String,
    destination_endpoint: String,
    database: String,
    table: String,
    node_id: String,
    created_at_unix: i64,
}

/// Stable, validated, non-secret spool ownership identity.
#[derive(Debug, Clone)]
struct SpoolOwner {
    plugin_config_id: Arc<str>,
    ferrum_namespace: Arc<str>,
    destination_endpoint: Arc<str>,
    database: Arc<str>,
    table: Arc<str>,
    node_id: Arc<str>,
    /// Full hex digest over the complete ownership tuple.
    digest: Arc<str>,
    /// Digest prefix embedded in every managed filename.
    tag: Arc<str>,
}

impl SpoolOwner {
    fn new(
        plugin_config_id: impl Into<Arc<str>>,
        ferrum_namespace: impl Into<Arc<str>>,
        destination_endpoint: impl Into<Arc<str>>,
        database: impl Into<Arc<str>>,
        table: impl Into<Arc<str>>,
        node_id: impl Into<Arc<str>>,
    ) -> Self {
        let plugin_config_id = plugin_config_id.into();
        let ferrum_namespace = ferrum_namespace.into();
        let destination_endpoint = destination_endpoint.into();
        let database = database.into();
        let table = table.into();
        let node_id = node_id.into();
        let digest = spool_owner_digest(&[
            plugin_config_id.as_ref(),
            ferrum_namespace.as_ref(),
            destination_endpoint.as_ref(),
            database.as_ref(),
            table.as_ref(),
            node_id.as_ref(),
        ]);
        let tag = digest[..SPOOL_OWNER_TAG_LEN].to_string();
        Self {
            plugin_config_id,
            ferrum_namespace,
            destination_endpoint,
            database,
            table,
            node_id,
            digest: Arc::<str>::from(digest),
            tag: Arc::<str>::from(tag),
        }
    }

    fn to_meta(&self, created_at_unix: i64) -> SpoolNamespaceMeta {
        SpoolNamespaceMeta {
            version: SPOOL_FORMAT_VERSION,
            owner_digest: self.digest.to_string(),
            owner_tag: self.tag.to_string(),
            plugin_config_id: self.plugin_config_id.to_string(),
            ferrum_namespace: self.ferrum_namespace.to_string(),
            destination_endpoint: self.destination_endpoint.to_string(),
            database: self.database.to_string(),
            table: self.table.to_string(),
            node_id: self.node_id.to_string(),
            created_at_unix,
        }
    }

    fn matches_meta(&self, meta: &SpoolNamespaceMeta) -> bool {
        meta.version == SPOOL_FORMAT_VERSION
            && meta.owner_digest == self.digest.as_ref()
            && self.matches_tag(&meta.owner_tag)
            && meta.plugin_config_id == self.plugin_config_id.as_ref()
            && meta.ferrum_namespace == self.ferrum_namespace.as_ref()
            && meta.destination_endpoint == self.destination_endpoint.as_ref()
            && meta.database == self.database.as_ref()
            && meta.table == self.table.as_ref()
            && meta.node_id == self.node_id.as_ref()
    }

    fn matches_tag(&self, tag: &str) -> bool {
        tag == self.tag.as_ref()
            || (tag.len() == SPOOL_LEGACY_OWNER_TAG_LEN && self.tag.starts_with(tag))
    }
}

/// Domain-separated, length-prefixed ownership digest.
///
/// Length prefixes keep two different tuples from colliding by shifting text
/// across a field boundary (`db="a", table="bc"` versus `db="ab", table="c"`).
fn spool_owner_digest(fields: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(SPOOL_OWNER_DIGEST_DOMAIN);
    hasher.update(u64::from(SPOOL_FORMAT_VERSION).to_be_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    hex::encode(&digest[..])
}

/// Durable-write step a test asks one spool manager to fail at.
///
/// Fault selection is per-[`SpoolManager`] state supplied at construction, not a
/// process-global switch, so no production sink can be steered away from the
/// real filesystem calls.
///
/// Non-`None` variants are constructed only by the external unit-test suite via
/// [`SpoolManager::for_tests_with_owner_and_faults`]; the binary crate never
/// builds them, so clippy's dead-code lint is expected there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SpoolFsFault {
    None,
    FileSync,
    Rename,
    DirOpen,
    DirSync,
    /// A peer republishes the final path between this attempt's rename and its
    /// parent-directory fsync, and that fsync then fails. Models the
    /// interleaving in which a path-based rollback would unlink an entry this
    /// attempt no longer owns.
    PeerRepublishThenDirSync,
}

/// Whether this write attempt exclusively owns the name it publishes to.
///
/// Rollback after a failed publish may only unlink a final path when no other
/// writer can be publishing to that same name, because a path unlink cannot be
/// made atomic with any proof about which file the name currently resolves to.
/// Stat-then-unlink, content comparison, and timestamp comparison all lose the
/// race against an atomic `rename` by a peer between the check and the unlink,
/// and an in-process lock says nothing about a peer process sharing the volume.
/// So the distinction is drawn statically, at each call site, instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolFinalOwnership {
    /// A name no other writer can publish to: the ULID-derived data batch
    /// `<ulid>.<owner_tag>.<ext>`, and the `<that name>.rejected.meta`
    /// dead-letter record derived from one. Rollback unlinks such a final,
    /// because the only entry it can ever destroy is this attempt's own
    /// unsynced publication.
    Unique,
    /// A well-known name every writer of the namespace publishes to — currently
    /// only `spool.meta.json`. Rollback never unlinks such a final.
    Shared,
}

/// Injectable durable-write steps for the atomic spool publish sequence.
///
/// Parent-directory fsync is a Unix-only step, so the two directory hooks are
/// unread on other targets.
#[derive(Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
struct SpoolFsOps {
    sync_file: fn(&File, &Path) -> Result<(), String>,
    rename: fn(&Path, &Path) -> Result<(), String>,
    /// Runs immediately after a successful rename. Production wires it to a
    /// no-op; tests use it to interleave a peer republication of the final path
    /// between this attempt's rename and its parent-directory fsync.
    after_rename: fn(&Path),
    open_dir: fn(&Path) -> Result<File, String>,
    sync_dir: fn(&File, &Path) -> Result<(), String>,
}

impl SpoolFsOps {
    const REAL: Self = Self {
        sync_file: real_sync_spool_file,
        rename: real_rename_spool_file,
        after_rename: noop_after_rename,
        open_dir: real_open_spool_dir,
        sync_dir: real_sync_spool_dir,
    };

    fn with_fault(fault: SpoolFsFault) -> Self {
        let mut ops = Self::REAL;
        match fault {
            SpoolFsFault::None => {}
            SpoolFsFault::FileSync => ops.sync_file = fail_sync_spool_file,
            SpoolFsFault::Rename => ops.rename = fail_rename_spool_file,
            SpoolFsFault::DirOpen => ops.open_dir = fail_open_spool_dir,
            SpoolFsFault::DirSync => ops.sync_dir = fail_sync_spool_dir,
            SpoolFsFault::PeerRepublishThenDirSync => {
                ops.after_rename = republish_final_path_as_peer;
                ops.sync_dir = fail_sync_spool_dir;
            }
        }
        ops
    }
}

fn noop_after_rename(_final_path: &Path) {}

fn real_sync_spool_file(file: &File, path: &Path) -> Result<(), String> {
    file.sync_all().map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to fsync spool temp file '{}': {error}",
            path.display()
        )
    })
}

fn real_rename_spool_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to rename spool temp file '{}' to '{}': {error}",
            from.display(),
            to.display()
        )
    })
}

fn real_open_spool_dir(path: &Path) -> Result<File, String> {
    File::open(path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to open spool parent directory '{}' after rename: {error}",
            path.display()
        )
    })
}

fn real_sync_spool_dir(dir: &File, path: &Path) -> Result<(), String> {
    dir.sync_all().map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to fsync spool parent directory '{}' after rename: {error}",
            path.display()
        )
    })
}

#[allow(dead_code)] // reachable only through the test-only faulted constructors
fn fail_sync_spool_file(_file: &File, path: &Path) -> Result<(), String> {
    Err(format!(
        "{PLUGIN_NAME}: injected fault: failed to fsync spool temp file '{}'",
        path.display()
    ))
}

#[allow(dead_code)] // reachable only through the test-only faulted constructors
fn fail_rename_spool_file(from: &Path, to: &Path) -> Result<(), String> {
    Err(format!(
        "{PLUGIN_NAME}: injected fault: failed to rename spool temp file '{}' to '{}'",
        from.display(),
        to.display()
    ))
}

#[allow(dead_code)] // reachable only through the test-only faulted constructors
fn fail_open_spool_dir(path: &Path) -> Result<File, String> {
    Err(format!(
        "{PLUGIN_NAME}: injected fault: failed to open spool parent directory '{}' after rename",
        path.display()
    ))
}

/// Atomically replace the just-published final path with a distinct file, as a
/// peer writer racing this attempt would. The replacement is renamed into place
/// so the entry always names a complete file with a different inode.
#[allow(dead_code)] // reachable only through the test-only faulted constructors
fn republish_final_path_as_peer(final_path: &Path) {
    let mut peer_tmp = final_path.as_os_str().to_os_string();
    peer_tmp.push(".peer-republish");
    let peer_tmp = PathBuf::from(peer_tmp);
    if fs::write(&peer_tmp, PEER_REPUBLISH_MARKER).is_ok() {
        let _ = fs::rename(&peer_tmp, final_path);
    }
}

/// Contents written by [`republish_final_path_as_peer`]; asserted by tests that
/// check a peer publication survived another writer's rollback.
#[doc(hidden)]
#[allow(dead_code)]
pub const PEER_REPUBLISH_MARKER: &[u8] = b"{\"peer_republished\":true}\n";

#[allow(dead_code)] // reachable only through the test-only faulted constructors
fn fail_sync_spool_dir(_dir: &File, path: &Path) -> Result<(), String> {
    Err(format!(
        "{PLUGIN_NAME}: injected fault: failed to fsync spool parent directory '{}' after rename",
        path.display()
    ))
}

static SPOOL_PROCESS_TAG: OnceLock<String> = OnceLock::new();
static LIVE_SPOOL_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Per-process instance tag embedded in every temp and in-flight claim name.
///
/// Distinguishes this process's live files from those left behind by a crashed
/// or restarted process sharing the same persistent volume: a restart always
/// draws a fresh tag, so leftovers are recovered through the lease path instead
/// of being mistaken for live work.
fn spool_process_tag() -> &'static str {
    SPOOL_PROCESS_TAG
        .get_or_init(|| {
            let nonce = uuid::Uuid::new_v4();
            hex::encode(nonce.as_bytes())
        })
        .as_str()
}

/// Managed paths this process is actively writing or delivering.
///
/// Shared by every [`SpoolManager`] in the process so an overlapping accepted
/// generation, or a replacement generation created by a reload, can never
/// reconcile or reclaim a live peer's temp or in-flight claim.
fn live_spool_paths() -> &'static Mutex<HashSet<PathBuf>> {
    LIVE_SPOOL_PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_live_spool_path(path: &Path) -> bool {
    let live = match live_spool_paths().lock() {
        Ok(live) => live,
        Err(poisoned) => poisoned.into_inner(),
    };
    live.contains(path)
}

/// RAII lease keeping one managed path registered as live for this process.
pub struct LiveSpoolPathGuard {
    path: PathBuf,
}

impl LiveSpoolPathGuard {
    fn new(path: PathBuf) -> Self {
        let mut live = match live_spool_paths().lock() {
            Ok(live) => live,
            Err(poisoned) => poisoned.into_inner(),
        };
        live.insert(path.clone());
        drop(live);
        Self { path }
    }
}

impl Drop for LiveSpoolPathGuard {
    fn drop(&mut self) {
        let mut live = match live_spool_paths().lock() {
            Ok(live) => live,
            Err(poisoned) => poisoned.into_inner(),
        };
        live.remove(&self.path);
    }
}

fn short_spool_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..16])
}

/// Reject absolute, parent, separator, NUL, drive/UNC, and platform-prefix forms.
fn is_hostile_path_component(value: &str) -> bool {
    if value.is_empty() || value == "." || value == ".." {
        return true;
    }
    if value.contains('\0') {
        return true;
    }
    if value.contains('/') || value.contains('\\') {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.starts_with(b"/") {
        return true;
    }
    // Windows drive / path prefix forms (`C:`, `\\?\`, `\\.`, UNC).
    if bytes.len() >= 2 && bytes[1] == b':' {
        return true;
    }
    if value.starts_with(r"\\") || value.starts_with("//") {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with(r"\\?\")
        || lower.starts_with(r"\\.\")
        || lower.starts_with("//?/")
        || lower.starts_with("//./")
    {
        return true;
    }
    false
}

fn is_safe_literal_path_component(value: &str) -> bool {
    !is_hostile_path_component(value)
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Encode operator/config text as one managed path component that cannot escape
/// the configured spool root. Hostile or overlong values are hashed.
fn encode_spool_path_component(raw: &str, prefix: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{PLUGIN_NAME}: spool path component must not be empty"
        ));
    }
    if trimmed.contains('\0') {
        return Err(format!(
            "{PLUGIN_NAME}: spool path component must not contain NUL bytes"
        ));
    }
    if is_safe_literal_path_component(trimmed) {
        return Ok(trimmed.to_string());
    }
    Ok(format!("{prefix}_{}", short_spool_hash(trimmed)))
}

/// Managed path components for one owner: `<safe_node>/<safe_plugin>/o<digest>`.
///
/// The readable node/plugin components keep operator navigation possible; the
/// `o<digest>` component is what actually partitions ownership, because it also
/// covers the Ferrum namespace/ledger and the ClickHouse destination/schema.
struct SpoolNamespaceComponents {
    node: String,
    plugin: String,
    owner: String,
}

fn spool_namespace_components(owner: &SpoolOwner) -> Result<SpoolNamespaceComponents, String> {
    Ok(SpoolNamespaceComponents {
        node: encode_spool_path_component(owner.node_id.as_ref(), "n")?,
        plugin: encode_spool_path_component(owner.plugin_config_id.as_ref(), "p")?,
        owner: format!("o{}", &owner.digest[..SPOOL_OWNER_DIGEST_LEN]),
    })
}

fn build_namespace_root(spool_dir: &Path, owner: &SpoolOwner) -> Result<PathBuf, String> {
    let components = spool_namespace_components(owner)?;
    let root = spool_dir
        .join(&components.node)
        .join(&components.plugin)
        .join(&components.owner);
    ensure_path_within_root(spool_dir, &root)?;
    Ok(root)
}

/// Derive the in-flight claim lease from the configured worst-case delivery
/// budget so a lease cannot expire while a legitimate delivery is still running.
fn spool_claim_lease_secs(config: &ApiChargebackSinkConfig) -> u64 {
    let attempts = u64::from(config.retry.max_attempts.max(1));
    let attempt_budget_ms = config.clickhouse.timeout_ms.saturating_mul(attempts);
    let delay_budget_ms = worst_case_inter_attempt_delay_ms(
        config.retry.max_attempts,
        config.retry.initial_delay_ms,
        config.retry.max_delay_ms,
    );
    attempt_budget_ms
        .saturating_add(delay_budget_ms)
        .div_ceil(1_000)
        .saturating_mul(SPOOL_CLAIM_LEASE_BUDGET_FACTOR)
        .max(SPOOL_CLAIM_LEASE_MIN_SECS)
}

#[doc(hidden)]
#[allow(dead_code)] // external unit tests only
pub fn spool_claim_lease_secs_for_tests(config: &ApiChargebackSinkConfig) -> u64 {
    spool_claim_lease_secs(config)
}

fn ensure_path_within_root(root: &Path, candidate: &Path) -> Result<(), String> {
    // Lexical containment first (no filesystem touch): reject `..` escape and
    // absolute replacement joins before any create/scan/delete.
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(format!(
                        "{PLUGIN_NAME}: managed spool path '{}' escapes root '{}'",
                        candidate.display(),
                        root.display()
                    ));
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized = PathBuf::from(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.starts_with(root) {
        return Err(format!(
            "{PLUGIN_NAME}: managed spool path '{}' is outside root '{}'",
            candidate.display(),
            root.display()
        ));
    }
    Ok(())
}

/// Prove one existing directory resolves beneath the canonical managed root.
///
/// Used once per prepare for the namespace root itself and once per directory
/// descended during a walk. Individual files do not need this: every managed
/// file path is built by joining validated components onto the namespace root,
/// and every walk rejects symlinks with `symlink_metadata` at every level, so no
/// reachable file can resolve outside the canonical root.
fn directory_is_within_canonical_root(canonical_root: &Path, dir: &Path) -> Result<(), String> {
    let canonical_dir = fs::canonicalize(dir).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to canonicalize spool directory '{}': {error}",
            dir.display()
        )
    })?;
    if !canonical_dir.starts_with(canonical_root) {
        return Err(format!(
            "{PLUGIN_NAME}: canonical spool directory '{}' escapes root '{}'",
            canonical_dir.display(),
            canonical_root.display()
        ));
    }
    Ok(())
}

/// Reject a managed path that is itself a symlink.
///
/// Spool maintenance must operate on the real file it enumerated, never on a
/// link planted by a same-UID process pointing outside the managed tree.
fn reject_symlinked_spool_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "{PLUGIN_NAME}: refusing to operate on symlinked spool path '{}'",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "{PLUGIN_NAME}: failed to lstat spool path '{}': {error}",
            path.display()
        )),
    }
}

/// Reject an existing symlink at any managed component below `root`.
///
/// `create_dir_all` follows existing directory symlinks. Preflighting the
/// validated node/plugin/owner chain prevents initial preparation from chmoding
/// or write-probing a replacement tree before canonical containment is
/// established.
fn reject_symlinked_managed_chain(root: &Path, candidate: &Path) -> Result<(), String> {
    ensure_path_within_root(root, candidate)?;
    let relative = candidate.strip_prefix(root).map_err(|_| {
        format!(
            "{PLUGIN_NAME}: managed spool path '{}' is outside root '{}'",
            candidate.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(format!(
                "{PLUGIN_NAME}: invalid managed spool component in '{}'",
                candidate.display()
            ));
        };
        current.push(part);
        reject_symlinked_spool_path(&current)?;
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DirIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn dir_identity(meta: &fs::Metadata) -> Option<DirIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(DirIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DirIdentity;

#[cfg(not(unix))]
fn dir_identity(_meta: &fs::Metadata) -> Option<DirIdentity> {
    None
}

/// Test-facing description of one spool owner identity.
///
/// Mirrors the fields production derives from the accepted plugin config so
/// external tests can build sibling instances without a live ClickHouse.
#[derive(Debug, Clone)]
#[allow(dead_code)] // constructed only by the test-only entry points below
pub struct SpoolOwnerSpec<'a> {
    pub node_id: &'a str,
    pub plugin_config_id: &'a str,
    pub ferrum_namespace: &'a str,
    pub destination_endpoint: &'a str,
    pub database: &'a str,
    pub table: &'a str,
}

impl SpoolOwnerSpec<'_> {
    fn to_owner(&self) -> SpoolOwner {
        SpoolOwner::new(
            self.plugin_config_id.to_string(),
            self.ferrum_namespace.to_string(),
            self.destination_endpoint.to_string(),
            self.database.to_string(),
            self.table.to_string(),
            self.node_id.to_string(),
        )
    }
}

pub struct SpoolManager {
    cfg: SpoolSettings,
    owner: SpoolOwner,
    generation: u64,
    namespace_root: PathBuf,
    /// Canonicalized namespace root, resolved once the tree exists.
    canonical_root: OnceLock<PathBuf>,
    metrics: Arc<SinkMetrics>,
    last_drop_warn_at: AtomicI64,
    last_unbound_warn_at: AtomicI64,
    live_storage_prepared: AtomicBool,
    write_lock: Mutex<()>,
    /// Foreign or unattributable temps are reconciled only once this old.
    stale_temp_age_secs: u64,
    /// Lifetime of an in-flight replay claim before another owner may recover it.
    claim_lease_secs: u64,
    /// Durable-write steps; production always uses [`SpoolFsOps::REAL`].
    fs_ops: SpoolFsOps,
    /// Retained-byte ceiling every spool-write materialization is charged to.
    /// Queued events still hold their per-instance export leases while the
    /// serialized (and optionally compressed) artifact exists, so both are
    /// attacker-shaped copies that must be reserved before they are built.
    ceiling: &'static RetainedByteCeiling,
    /// Charge-event projection applied to the durable artifact.
    projection: Option<Arc<ChargeEventProjection>>,
}

struct SpoolManagerOptions {
    metrics: Arc<SinkMetrics>,
    stale_temp_age_secs: u64,
    claim_lease_secs: u64,
    fs_ops: SpoolFsOps,
    ceiling: &'static RetainedByteCeiling,
    /// Projection applied to the durable spool artifact. The spool is a durable
    /// copy of the delivery body and is replayed verbatim, so it must carry the
    /// same representation the live INSERT path emits.
    projection: Option<Arc<ChargeEventProjection>>,
}

impl SpoolManager {
    fn new(
        cfg: SpoolSettings,
        owner: SpoolOwner,
        generation: u64,
        options: SpoolManagerOptions,
    ) -> Result<Self, String> {
        let namespace_root = build_namespace_root(&cfg.dir, &owner)?;
        Ok(Self {
            cfg,
            owner,
            generation,
            namespace_root,
            canonical_root: OnceLock::new(),
            metrics: options.metrics,
            last_drop_warn_at: AtomicI64::new(0),
            last_unbound_warn_at: AtomicI64::new(0),
            live_storage_prepared: AtomicBool::new(false),
            write_lock: Mutex::new(()),
            stale_temp_age_secs: options.stale_temp_age_secs,
            claim_lease_secs: options.claim_lease_secs,
            fs_ops: options.fs_ops,
            ceiling: options.ceiling,
            projection: options.projection,
        })
    }

    #[allow(dead_code)] // external unit tests only
    pub fn for_tests(cfg: SpoolSettings, node_id: &str) -> Result<Self, String> {
        Self::for_tests_with_owner(cfg, &default_test_spool_owner_spec(node_id), 1)
    }

    /// [`Self::for_tests`] bound to a test-owned retained-byte ceiling.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn for_tests_with_ceiling(
        cfg: SpoolSettings,
        node_id: &str,
        ceiling: &'static RetainedByteCeiling,
    ) -> Result<Self, String> {
        Self::for_tests_with_owner_faults_ages_and_ceiling(
            cfg,
            &default_test_spool_owner_spec(node_id),
            1,
            SpoolFsFault::None,
            0,
            SPOOL_CLAIM_LEASE_MIN_SECS,
            ceiling,
        )
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn for_tests_with_owner(
        cfg: SpoolSettings,
        spec: &SpoolOwnerSpec<'_>,
        generation: u64,
    ) -> Result<Self, String> {
        Self::for_tests_with_owner_and_faults(cfg, spec, generation, SpoolFsFault::None)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn for_tests_with_owner_and_faults(
        cfg: SpoolSettings,
        spec: &SpoolOwnerSpec<'_>,
        generation: u64,
        fault: SpoolFsFault,
    ) -> Result<Self, String> {
        Self::for_tests_with_owner_faults_and_ages(
            cfg,
            spec,
            generation,
            fault,
            // Tests treat a foreign temp as immediately reconcilable unless a
            // live in-process writer lease protects it.
            0,
            SPOOL_CLAIM_LEASE_MIN_SECS,
        )
    }

    /// Same as [`Self::for_tests_with_owner_and_faults`] with explicit
    /// stale-temp and claim-lease horizons, so age-gated recovery is exercised
    /// without wall-clock sleeps.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn for_tests_with_owner_faults_and_ages(
        cfg: SpoolSettings,
        spec: &SpoolOwnerSpec<'_>,
        generation: u64,
        fault: SpoolFsFault,
        stale_temp_age_secs: u64,
        claim_lease_secs: u64,
    ) -> Result<Self, String> {
        Self::for_tests_with_owner_faults_ages_and_ceiling(
            cfg,
            spec,
            generation,
            fault,
            stale_temp_age_secs,
            claim_lease_secs,
            process_ceiling(),
        )
    }

    /// Same as [`Self::for_tests_with_owner_faults_and_ages`] against a
    /// test-owned retained-byte ceiling, so write-side reservation and refusal
    /// assertions stay exact while other tests in the same binary reserve
    /// against the process-global counter.
    #[doc(hidden)]
    #[allow(dead_code, clippy::too_many_arguments)] // external unit tests only
    pub fn for_tests_with_owner_faults_ages_and_ceiling(
        cfg: SpoolSettings,
        spec: &SpoolOwnerSpec<'_>,
        generation: u64,
        fault: SpoolFsFault,
        stale_temp_age_secs: u64,
        claim_lease_secs: u64,
        ceiling: &'static RetainedByteCeiling,
    ) -> Result<Self, String> {
        let manager = Self::new(
            cfg,
            spec.to_owner(),
            generation,
            SpoolManagerOptions {
                metrics: Arc::new(SinkMetrics::default()),
                stale_temp_age_secs,
                claim_lease_secs,
                fs_ops: SpoolFsOps::REAL,
                ceiling,
                projection: None,
            },
        )?;
        // Test callers model a committed/live sink and retain the historical
        // eager startup validation contract. The managed tree is prepared with
        // the real filesystem so an injected fault applies only to the durable
        // writes actually under test.
        manager.prepare_live_storage()?;
        Ok(Self {
            fs_ops: SpoolFsOps::with_fault(fault),
            ..manager
        })
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn namespace_root_for_tests(&self) -> &Path {
        &self.namespace_root
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn owner_tag_for_tests(&self) -> &str {
        self.owner.tag.as_ref()
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn generation_for_tests(&self) -> u64 {
        self.generation
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn prepare_live_storage_for_tests(&self) -> Result<(), String> {
        self.prepare_live_storage()
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn namespace_root_path_for_tests(
        spool_dir: &Path,
        spec: &SpoolOwnerSpec<'_>,
    ) -> Result<PathBuf, String> {
        build_namespace_root(spool_dir, &spec.to_owner())
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn owner_tag_of_spec_for_tests(spec: &SpoolOwnerSpec<'_>) -> String {
        spec.to_owner().tag.to_string()
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn encode_spool_path_component_for_tests(raw: &str) -> Result<String, String> {
        encode_spool_path_component(raw, "n")
    }

    /// Exercise the lexical containment guard that every managed create,
    /// rename, and unlink runs before touching the filesystem.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn ensure_path_within_root_for_tests(root: &Path, candidate: &Path) -> Result<(), String> {
        ensure_path_within_root(root, candidate)
    }

    /// Renew a held claim onto an explicit lease deadline so the rename half of
    /// the claim protocol is covered deterministically.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn renew_claim_at_for_tests(
        &self,
        claim: &mut SpoolClaimHandle,
        lease_deadline_unix: i64,
    ) -> Result<(), String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.renew_claim_locked_at(claim, lease_deadline_unix)
    }

    /// Claim one replay candidate, returning `None` when another owner,
    /// generation, or process won the atomic rename first.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn claim_replay_file_for_tests(&self, path: &Path) -> Result<Option<PathBuf>, String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        Ok(self
            .claim_replay_file_locked(path)?
            .map(|claim| claim.path().to_path_buf()))
    }

    /// Claim one replay candidate and keep the live-path lease held for the
    /// caller so tests can model an in-flight delivery across other operations.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn hold_replay_claim_for_tests(
        &self,
        path: &Path,
    ) -> Result<Option<SpoolClaimHandle>, String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.claim_replay_file_locked(path)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn release_inflight_file_for_tests(
        &self,
        inflight: &Path,
    ) -> Result<Option<PathBuf>, String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.release_claim_locked(inflight)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn list_owned_spool_files_for_tests(&self) -> Result<Vec<PathBuf>, String> {
        self.list_owned_spool_files()
    }

    /// Run quota eviction under the writer lock and return the planning report.
    ///
    /// External tests use this to assert multi-file reclaim is driven by one
    /// inventory/sort pass rather than a per-deletion rescan.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn evict_until_can_admit_for_tests(
        &self,
        incoming_len: u64,
    ) -> Result<QuotaEvictionReport, String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.evict_until_can_admit_with_report(incoming_len)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn list_owned_spool_files_with_entry_limit_for_tests(
        &self,
        max_entries: usize,
    ) -> Result<Vec<PathBuf>, String> {
        self.validate_namespace_meta_if_present()?;
        let mut files = Vec::new();
        self.collect_with_entry_limit(&mut files, SpoolFileClass::Owned, max_entries)?;
        files.sort();
        Ok(files)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn list_replayable_spool_files_for_tests(&self) -> Result<Vec<PathBuf>, String> {
        self.list_replayable_spool_files()
    }

    /// Register one managed path as live for this process, as an in-progress
    /// write or delivery would.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn hold_live_spool_path_for_tests(path: &Path) -> LiveSpoolPathGuard {
        LiveSpoolPathGuard::new(path.to_path_buf())
    }

    /// Build the generation-owned temp name `write_events` would use.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn write_temp_path_for_tests(&self, final_path: &Path) -> Result<PathBuf, String> {
        spool_write_temp_path(final_path, self.generation)
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn unbound_record_counts_for_tests(&self) -> (u64, u64) {
        (
            self.metrics.spool_unbound_files.load(Ordering::Relaxed),
            self.metrics
                .spool_unbound_namespaces
                .load(Ordering::Relaxed),
        )
    }

    /// Re-run the aggregate unbound-record scan with a deterministic global
    /// entry budget. External tests use this to prove sibling namespaces share
    /// one bound rather than each receiving a fresh traversal allowance.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn scan_unbound_records_with_entry_limit_for_tests(
        &self,
        max_entries: usize,
    ) -> (u64, u64, bool) {
        self.scan_unbound_records_with_entry_limit(max_entries)
    }

    pub fn write_events(&self, events: &[ChargeEvent]) -> Result<PathBuf, String> {
        if events.is_empty() {
            return Err(format!("{PLUGIN_NAME}: refusing to spool empty batch"));
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        // Optional test seam: runs under the writer lock so injected stalls
        // model real compression/write/fsync latency without changing the
        // request-path enqueue contract. Snapshot the hook once so AfterWrite
        // cannot observe a different (later-installed) hook than BeforeWrite.
        let _after_hook = SpoolWriteHookAfterGuard::enter(&self.namespace_root);
        self.prepare_live_storage_locked()?;
        let bytes = self.materialize_spool_artifact(events)?;
        let incoming_len = bytes.len() as u64;
        if incoming_len > SPOOL_MAX_ARTIFACT_BYTES {
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) exceeds the hard per-artifact limit ({SPOOL_MAX_ARTIFACT_BYTES} bytes)"
            ));
        }
        if incoming_len > self.cfg.max_bytes {
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) exceeds spool.max_bytes ({})",
                self.cfg.max_bytes
            ));
        }
        self.evict_until_can_admit(incoming_len)?;
        let day = Utc::now().format("%Y%m%d").to_string();
        let dir = self.namespace_root.join(day);
        self.assert_managed_path(&dir)?;
        ensure_private_dir(&dir)?;
        // Every file carries the owner tag, so a record can be attributed to its
        // intended plugin config / namespace / destination / schema even if it is
        // later moved between directories.
        let final_path = dir.join(format!(
            "{}.{}.{}",
            new_ulid(),
            self.owner.tag,
            self.cfg.compression.extension()
        ));
        let tmp_path = spool_write_temp_path(&final_path, self.generation)?;
        self.assert_managed_path(&final_path)?;
        self.assert_managed_path(&tmp_path)?;
        // Hold the live-path lease across the whole atomic write so no peer
        // generation in this process can reconcile the temp mid-write.
        let write_result = {
            let _live = LiveSpoolPathGuard::new(tmp_path.clone());
            // The final name carries a freshly minted ULID, so no peer can be
            // publishing to it and a failed publish rolls its own file back.
            write_private_file_atomically_with_ops(
                &tmp_path,
                &final_path,
                bytes.as_slice(),
                self.fs_ops,
                SpoolFinalOwnership::Unique,
            )
        };
        write_result?;
        // The reservation on the encoded artifact is released only here, after
        // the blocking write, fsync, and rename have all completed.
        drop(bytes);
        invalidate_status_cache();
        Ok(final_path)
    }

    /// Build the durable spool artifact for `events` with every coexisting
    /// representation reserved against the retained-byte ceiling **before** it
    /// is allocated.
    ///
    /// Two attacker-shaped representations can exist here at once — the
    /// JSONEachRow text and, under `zstd`, its compressed form — while the
    /// caller's queued events still hold their per-instance export leases.
    /// Both are charged; the JSON reservation is released as soon as the
    /// compressed form owns the bytes, so only one artifact-sized charge
    /// survives into the blocking durable write.
    ///
    /// The artifact is additionally refused unless replaying it would fit under
    /// the same configured ceiling (see [`spool_replay_peak_bytes`]). When a
    /// legitimate zstd payload exceeds the untrusted-archive expansion ratio,
    /// materialization pads it with an ignored zstd skippable frame until the
    /// encoded size satisfies that ratio. Writing a file this process could
    /// never read back is a permanent loss; every artifact returned here is
    /// structurally replayable.
    fn materialize_spool_artifact(
        &self,
        events: &[ChargeEvent],
    ) -> Result<ReservedPayload, String> {
        let json = materialize_json_each_row(self.ceiling, events, self.projection.as_deref())?;
        let decoded_len = json.len() as u64;
        if decoded_len > SPOOL_MAX_ARTIFACT_BYTES {
            return Err(format!(
                "{PLUGIN_NAME}: serialized spool batch ({decoded_len} bytes) exceeds the hard per-artifact limit ({SPOOL_MAX_ARTIFACT_BYTES} bytes)"
            ));
        }
        let replay_peak = spool_replay_peak_bytes(decoded_len, events.len())
            .ok_or_else(|| format!("{PLUGIN_NAME}: spool artifact replay byte bound overflowed"))?;
        let ceiling_max = self.ceiling.max() as u64;
        if replay_peak > ceiling_max {
            return Err(format!(
                "{PLUGIN_NAME}: refusing to spool a {decoded_len}-byte / {}-row artifact whose replay would need {replay_peak} retained bytes under the configured {ceiling_max}-byte process ceiling",
                events.len()
            ));
        }
        match self.cfg.compression {
            // The JSON payload is already the artifact: no second copy exists.
            SpoolCompression::None => Ok(json),
            SpoolCompression::Zstd => {
                let bound = zstd::zstd_safe::compress_bound(json.len())
                    .checked_add(SPOOL_ZSTD_FRAME_SLACK_BYTES)
                    .ok_or_else(|| {
                        format!("{PLUGIN_NAME}: spool compression byte bound overflowed")
                    })?;

                let encoded = materialize_reserved_buffer(self.ceiling, bound, |buffer| {
                    // One-shot compression records the decompressed size in the
                    // zstd frame header. Replay uses it only when the whole file
                    // also satisfies the untrusted-archive ratio limit.
                    let written = zstd::bulk::compress_to_buffer(json.as_slice(), buffer, 0)
                        .map_err(|error| format!("zstd compression failed: {error}"))?;
                    pad_zstd_to_replay_ratio(buffer, written, decoded_len)
                })
                .map_err(|error| {
                    format!(
                        "{PLUGIN_NAME}: spool artifact compression failed: {}",
                        error.reason()
                    )
                })?;
                // Release the JSON charge now that the compressed artifact owns
                // the only representation the durable write needs.
                drop(json);
                Ok(encoded)
            }
        }
    }

    /// Deterministic spool-artifact materialization probe for external tests.
    ///
    /// Returns `(encoded_len, ceiling_used_while_artifact_held,
    /// ceiling_used_after_drop)`. Read `RetainedByteCeiling::high_water` around
    /// the call to observe the coexisting JSON + compressed peak.
    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn probe_spool_artifact_materialization_for_tests(
        &self,
        events: &[ChargeEvent],
    ) -> Result<(usize, usize, usize), String> {
        let artifact = self.materialize_spool_artifact(events)?;
        let encoded_len = artifact.len();
        let held = self.ceiling.used();
        drop(artifact);
        Ok((encoded_len, held, self.ceiling.used()))
    }

    /// Prepare mutable spool state only for a committed generation. Candidate
    /// staging must not create directories, write probes, or reconcile files.
    fn prepare_live_storage(&self) -> Result<(), String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
        self.prepare_live_storage_locked()
    }

    fn prepare_live_storage_locked(&self) -> Result<(), String> {
        let result = self.prepare_live_storage_locked_inner();
        let available = result.is_ok();
        let changed = self
            .metrics
            .spool_available
            .swap(available, Ordering::AcqRel)
            != available;
        if !available {
            self.metrics
                .spool_prepare_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if changed || !available {
            invalidate_status_cache();
        }
        result
    }

    fn prepare_live_storage_locked_inner(&self) -> Result<(), String> {
        ensure_path_within_root(&self.cfg.dir, &self.namespace_root)?;
        if self.live_storage_prepared.load(Ordering::Acquire)
            && self.cfg.dir.is_dir()
            && self.namespace_root.is_dir()
        {
            self.verify_stable_namespace_root()?;
            self.validate_namespace_meta()?;
            // Recover only claims whose owning process/generation is demonstrably
            // gone or whose lease expired; a live delivery keeps its claim.
            self.recover_expired_claims()?;
            return Ok(());
        }
        ensure_private_dir(&self.cfg.dir)?;
        reject_symlinked_managed_chain(&self.cfg.dir, &self.namespace_root)?;
        ensure_private_dir(&self.namespace_root)?;
        self.resolve_canonical_root()?;
        self.persist_or_validate_namespace_meta()?;
        self.scan_unbound_records();
        self.recover_expired_claims()?;
        self.reconcile_stale_temp_files()?;
        self.live_storage_prepared.store(true, Ordering::Release);
        Ok(())
    }

    /// Canonicalize the managed root once and prove it resolves under the
    /// configured `spool.dir`, so later walks only need lexical containment plus
    /// symlink rejection.
    fn resolve_canonical_root(&self) -> Result<(), String> {
        if self.canonical_root.get().is_some() {
            return self.verify_stable_namespace_root();
        }
        reject_symlinked_managed_chain(&self.cfg.dir, &self.namespace_root)?;
        reject_symlinked_spool_path(&self.namespace_root)?;
        let canonical_dir = fs::canonicalize(&self.cfg.dir).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to canonicalize spool.dir '{}': {error}",
                self.cfg.dir.display()
            )
        })?;
        directory_is_within_canonical_root(&canonical_dir, &self.namespace_root)?;
        let canonical_root = fs::canonicalize(&self.namespace_root).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to canonicalize managed spool namespace '{}': {error}",
                self.namespace_root.display()
            )
        })?;
        let _ = self.canonical_root.set(canonical_root);
        Ok(())
    }

    /// Verify that the namespace path still names the exact directory prepared
    /// for this manager.
    ///
    /// A same-UID process can replace a directory entry after initial prepare.
    /// Reject both a symlink replacement and any canonical-target change before
    /// validating metadata, walking, replaying, renaming, or unlinking.
    fn verify_stable_namespace_root(&self) -> Result<(), String> {
        let expected = self.canonical_root.get().ok_or_else(|| {
            format!(
                "{PLUGIN_NAME}: managed spool namespace '{}' has no canonical root",
                self.namespace_root.display()
            )
        })?;
        reject_symlinked_spool_path(&self.namespace_root)?;
        let current = fs::canonicalize(&self.namespace_root).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to canonicalize managed spool namespace '{}': {error}",
                self.namespace_root.display()
            )
        })?;
        if &current != expected {
            return Err(format!(
                "{PLUGIN_NAME}: managed spool namespace '{}' changed canonical target from '{}' to '{}'",
                self.namespace_root.display(),
                expected.display(),
                current.display()
            ));
        }
        Ok(())
    }

    /// Prove one path is a managed, non-symlinked node of this namespace before
    /// any create, rename, or unlink.
    fn assert_managed_path(&self, path: &Path) -> Result<(), String> {
        ensure_path_within_root(&self.namespace_root, path)?;
        reject_symlinked_spool_path(path)?;
        if let Some(canonical_root) = self.canonical_root.get() {
            self.verify_stable_namespace_root()?;
            if let Some(parent) = path.parent()
                && parent.is_dir()
            {
                directory_is_within_canonical_root(canonical_root, parent)?;
            }
        }
        Ok(())
    }

    fn meta_path(&self) -> PathBuf {
        self.namespace_root.join(SPOOL_META_FILENAME)
    }

    fn persist_or_validate_namespace_meta(&self) -> Result<(), String> {
        let path = self.meta_path();
        self.assert_managed_path(&path)?;
        if path.exists() {
            return self.validate_namespace_meta();
        }
        let meta = self.owner.to_meta(unix_timestamp_seconds());
        let bytes = serde_json::to_vec_pretty(&meta).map_err(|error| {
            format!("{PLUGIN_NAME}: failed to serialize spool namespace metadata: {error}")
        })?;
        // Attribute the manifest temp to this process and generation like every
        // other managed temp. A fixed `spool.meta.json.tmp` is the same name for
        // every peer, so a concurrent first prepare by another generation or
        // another process sharing the volume would collide on `create_new` and
        // then unlink the live writer's temp during rollback — exactly the
        // cross-writer clobber the rest of this protocol forbids. The attributed
        // name is also recognized by `reconcile_stale_temp_files`, so a crash
        // leftover is reclaimed and quota-accounted instead of leaking.
        let tmp = spool_write_temp_path(&path, self.generation)?;
        self.assert_managed_path(&tmp)?;
        let _live = LiveSpoolPathGuard::new(tmp.clone());
        // `spool.meta.json` is the one shared final name in this protocol: every
        // writer of the namespace publishes to it. A failed publish therefore
        // cleans only the attributed temp above and leaves the manifest entry
        // alone — see the rollback in `write_private_file_atomically_with_ops`.
        // The error still propagates, so `live_storage_prepared` stays unset and
        // the next prepare revalidates or regenerates the manifest.
        write_private_file_atomically_with_ops(
            &tmp,
            &path,
            &bytes,
            self.fs_ops,
            SpoolFinalOwnership::Shared,
        )
    }

    /// Fail closed when the on-disk ownership record does not name this exact
    /// sink identity. Nothing is deleted, replayed, or rerouted on mismatch.
    fn validate_namespace_meta(&self) -> Result<(), String> {
        self.verify_stable_namespace_root()?;
        let path = self.meta_path();
        if !path.exists() {
            return Err(format!(
                "{PLUGIN_NAME}: missing spool namespace metadata at '{}'",
                path.display()
            ));
        }
        reject_symlinked_spool_path(&path)?;
        // The manifest is read before ownership is established, on every prepare
        // and every replay listing, so it is the one managed file a same-UID
        // actor can grow without first knowing this owner's tag. Bound it like
        // any other spool artifact instead of reading it whole.
        let file = File::open(&path).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to read spool namespace metadata '{}': {error}",
                path.display()
            )
        })?;
        let bytes = read_spool_bytes_bounded(file, SPOOL_MAX_META_BYTES, &path)?;
        let meta: SpoolNamespaceMeta = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: invalid spool namespace metadata '{}': {error}",
                path.display()
            )
        })?;
        if !self.owner.matches_meta(&meta) {
            return Err(format!(
                "{PLUGIN_NAME}: spool namespace metadata at '{}' does not match this sink identity (format version/plugin_config_id/ferrum namespace/destination/schema/node)",
                path.display()
            ));
        }
        Ok(())
    }

    pub fn scan_stats(&self) -> Result<SpoolStats, String> {
        Ok(self.inventory_owned_spool_files()?.stats)
    }

    /// Collect owned `(path, size)` metadata once, sorted oldest-first.
    ///
    /// Quota eviction plans from this snapshot so reclaiming K files never
    /// repeats a full directory walk/sort per deletion.
    fn inventory_owned_spool_files(&self) -> Result<OwnedSpoolInventory, String> {
        let files = self.list_owned_spool_files()?;
        let mut inventory = OwnedSpoolInventory {
            entries: Vec::with_capacity(files.len()),
            stats: SpoolStats::default(),
        };
        for file in files {
            match fs::symlink_metadata(&file) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    let len = meta.len();
                    inventory.stats.files = inventory.stats.files.saturating_add(1);
                    inventory.stats.bytes = inventory.stats.bytes.saturating_add(len);
                    inventory.entries.push(OwnedSpoolEntry { path: file, len });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A peer sharing the volume can unlink a listed file between
                    // the walk and this stat. A path with no directory entry
                    // occupies no quota bytes, so drop it from the snapshot
                    // instead of failing the caller. The quota refresh loop
                    // exists to survive exactly this race and cannot do so if
                    // re-inventorying hard-errors on it.
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "{PLUGIN_NAME}: failed to stat spool file '{}': {error}",
                        file.display()
                    ));
                }
            }
        }
        Ok(inventory)
    }

    /// Drop oldest evictable owned spool files until
    /// `owned_bytes + incoming_len <= max_bytes`.
    ///
    /// Owned bytes include active data files, crash-left temps, corrupt
    /// quarantine, metadata-only dead-letter (`.rejected.meta`) files, in-flight
    /// replay claims, and any unattributable record still occupying the tree.
    /// Eviction never selects an in-flight claim, a temp under an active write,
    /// or a record whose owner tag is not ours: deleting any of them would
    /// destroy another owner's or another delivery's billing data. When only
    /// such files remain the write fails closed instead of over-admitting or
    /// stealing them.
    ///
    /// Planning inventories and sorts the owned set once, then deletes enough
    /// eligible files from that snapshot in a single bounded pass. If a peer
    /// removes a selected file, refresh the inventory before admitting so a
    /// peer replacement absent from the stale snapshot is quota-accounted.
    fn evict_until_can_admit(&self, incoming_len: u64) -> Result<(), String> {
        self.evict_until_can_admit_with_report(incoming_len)
            .map(|_| ())
    }

    fn evict_until_can_admit_with_report(
        &self,
        incoming_len: u64,
    ) -> Result<QuotaEvictionReport, String> {
        if incoming_len > self.cfg.max_bytes {
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) exceeds spool.max_bytes ({})",
                self.cfg.max_bytes
            ));
        }
        let mut report = QuotaEvictionReport {
            inventory_passes: 0,
            files_inventoried: 0,
            bytes_before: 0,
            files_deleted: 0,
            bytes_freed: 0,
        };
        let mut warned = false;
        loop {
            let inventory = self.inventory_owned_spool_files()?;
            report.inventory_passes = report.inventory_passes.saturating_add(1);
            report.files_inventoried = report
                .files_inventoried
                .saturating_add(inventory.stats.files);
            if report.inventory_passes == 1 {
                report.bytes_before = inventory.stats.bytes;
            }
            let mut remaining_bytes = inventory.stats.bytes;
            if remaining_bytes.saturating_add(incoming_len) <= self.cfg.max_bytes {
                return Ok(report);
            }

            // Test seam only: one uncontended slot read, taken after the early
            // "already fits" return so the common admission path is untouched,
            // and on a pass that has already paid for a full directory walk.
            if let Some(hook) = snapshot_spool_write_hook_for_tests() {
                hook(
                    SpoolWriteHookPoint::QuotaInventoryTaken,
                    &self.namespace_root,
                );
            }

            let wall_clock = SystemTime::now();
            let mut protected = 0u64;
            let mut inventory_stale = false;
            for entry in &inventory.entries {
                if remaining_bytes.saturating_add(incoming_len) <= self.cfg.max_bytes {
                    return Ok(report);
                }
                if !self.is_evictable_owned_file(entry.path.as_path(), wall_clock) {
                    protected = protected.saturating_add(1);
                    continue;
                }
                self.assert_managed_path(&entry.path)?;
                match fs::remove_file(&entry.path) {
                    Ok(()) => {
                        remaining_bytes = remaining_bytes.saturating_sub(entry.len);
                        report.files_deleted = report.files_deleted.saturating_add(1);
                        report.bytes_freed = report.bytes_freed.saturating_add(entry.len);
                        self.metrics
                            .spool_drops_total
                            .fetch_add(1, Ordering::Relaxed);
                        if !warned {
                            let now = unix_timestamp_seconds();
                            let last = self.last_drop_warn_at.load(Ordering::Relaxed);
                            if now.saturating_sub(last) >= SPOOL_WARN_INTERVAL_SECS
                                && self
                                    .last_drop_warn_at
                                    .compare_exchange(
                                        last,
                                        now,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                            {
                                warn!(
                                    plugin = PLUGIN_NAME,
                                    max_bytes = self.cfg.max_bytes,
                                    incoming_bytes = incoming_len,
                                    "Chargeback sink spool exceeded max_bytes; oldest owned spool file was dropped"
                                );
                                warned = true;
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // A peer may have replaced the missing file with a new
                        // path after this snapshot. Never credit stale bytes;
                        // refresh before making an admission decision.
                        inventory_stale = true;
                        break;
                    }
                    Err(error) => {
                        return Err(format!(
                            "{PLUGIN_NAME}: failed to remove oldest spool file '{}': {error}",
                            entry.path.display()
                        ));
                    }
                }
            }

            if inventory_stale {
                if report.inventory_passes < SPOOL_QUOTA_MAX_INVENTORY_PASSES {
                    continue;
                }
                return Err(format!(
                    "{PLUGIN_NAME}: spool changed concurrently during {} quota inventory passes; refusing to admit encoded batch ({incoming_len} bytes)",
                    report.inventory_passes
                ));
            }

            if remaining_bytes.saturating_add(incoming_len) <= self.cfg.max_bytes {
                return Ok(report);
            }
            return Err(format!(
                "{PLUGIN_NAME}: encoded spool batch ({incoming_len} bytes) cannot fit within spool.max_bytes ({}); {protected} retained spool file(s) are in-flight, under an active write, or owned by another identity and are never evicted",
                self.cfg.max_bytes
            ));
        }
    }

    /// Whether one owned file may be dropped to make room for a new batch.
    ///
    /// Eviction runs per [`SpoolManager`], so two accepted generations in one
    /// process (or two processes sharing the volume) hold different writer
    /// locks. A temp that a peer is actively publishing is therefore protected
    /// by exactly the reconciliation predicate: unlinking it would leave the
    /// peer's already-fsynced payload with no directory entry to rename onto,
    /// failing that publish and silently losing a billing batch. Crash-left
    /// temps stay reclaimable, so quota pressure still makes progress.
    fn is_evictable_owned_file(&self, path: &Path, now: SystemTime) -> bool {
        if is_spool_inflight_file(path) || is_live_spool_path(path) {
            return false;
        }
        if is_spool_temp_file(path) && !self.temp_is_reclaimable(path, now) {
            return false;
        }
        match spool_file_owner_tag(path) {
            // Untagged retained artifacts (legacy temps, dead-letter metadata for
            // pre-tag files) belong to this namespace and stay evictable.
            None => true,
            Some(tag) => self.owner.matches_tag(tag),
        }
    }

    /// Same ownership/age test [`Self::reconcile_stale_temp_files`] applies,
    /// minus the live-path check the caller has already made. An unreadable
    /// temp is treated as protected so a transient stat failure can never
    /// escalate into deleting a peer's in-progress write.
    fn temp_is_reclaimable(&self, path: &Path, now: SystemTime) -> bool {
        let owned_by_this_process = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(parse_spool_write_temp)
            .is_some_and(|temp| temp.process_tag == spool_process_tag());
        if owned_by_this_process {
            return true;
        }
        spool_temp_is_stale(path, now, self.stale_temp_age_secs).unwrap_or(false)
    }

    fn collect(&self, files: &mut Vec<PathBuf>, class: SpoolFileClass) -> Result<(), String> {
        self.collect_with_entry_limit(files, class, MAX_SPOOL_TRAVERSAL_ENTRIES)
    }

    fn collect_with_entry_limit(
        &self,
        files: &mut Vec<PathBuf>,
        class: SpoolFileClass,
        max_entries: usize,
    ) -> Result<(), String> {
        self.verify_stable_namespace_root()?;
        let canonical_root = self.canonical_root.get().ok_or_else(|| {
            format!(
                "{PLUGIN_NAME}: managed spool namespace '{}' has no canonical root",
                self.namespace_root.display()
            )
        })?;
        let mut walk = SpoolWalk::new_with_expected_root(
            self.namespace_root.as_path(),
            class,
            canonical_root,
            max_entries,
        )?;
        walk.run(&self.namespace_root, files)
    }

    /// Reconcile abandoned atomic-write temps.
    ///
    /// A temp is removed only when this process demonstrably owns it and is no
    /// longer writing it, or when it is foreign/unattributable and older than
    /// `stale_temp_age_secs`. A reloaded generation therefore cannot unlink the
    /// active temp of an older accepted generation or of a peer process sharing
    /// the volume.
    fn reconcile_stale_temp_files(&self) -> Result<(), String> {
        let mut temps = Vec::new();
        self.collect(&mut temps, SpoolFileClass::Temp)?;
        let now = SystemTime::now();
        for path in temps {
            self.assert_managed_path(&path)?;
            if is_live_spool_path(&path) {
                // A live writer in this process owns it, whichever generation.
                continue;
            }
            let owned_by_this_process = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(parse_spool_write_temp)
                .is_some_and(|temp| temp.process_tag == spool_process_tag());
            if owned_by_this_process {
                self.remove_stale_temp(&path, "interrupted write in this process")?;
                continue;
            }
            if spool_temp_is_stale(&path, now, self.stale_temp_age_secs)? {
                self.remove_stale_temp(&path, "stale unattributed temp")?;
            }
        }
        Ok(())
    }

    fn remove_stale_temp(&self, path: &Path, reason: &'static str) -> Result<(), String> {
        match fs::remove_file(path) {
            Ok(()) => {
                warn!(
                    plugin = PLUGIN_NAME,
                    path = %path.display(),
                    generation = self.generation,
                    reason,
                    "Chargeback sink removed a stale spool temp file left by an interrupted write"
                );
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "{PLUGIN_NAME}: failed to remove stale spool temp file '{}': {error}",
                path.display()
            )),
        }
    }

    /// Return crash-left in-flight claims to their durable replayable names.
    ///
    /// Live claims held by this process are skipped outright, so in-process
    /// exclusion is absolute. A claim written by another process (or by an
    /// earlier run of this one) is recovered only after its lease deadline
    /// passes. That cross-process bound is temporal, not a proof the peer
    /// stopped: a peer stalled past its lease can still be delivering. The lease
    /// is four times the accepted worst-case delivery budget and is renewed per
    /// chunk so ordinary slow delivery cannot reach that window, and the
    /// residual outcome is a duplicate insert the stable `event_id` /
    /// `ReplacingMergeTree` contract deduplicates — never a misrouted or lost
    /// record, because the owner tag still gates the destination.
    fn recover_expired_claims(&self) -> Result<(), String> {
        let mut claims = Vec::new();
        self.collect(&mut claims, SpoolFileClass::Inflight)?;
        let now = unix_timestamp_seconds();
        let wall_clock = SystemTime::now();
        for path in claims {
            self.assert_managed_path(&path)?;
            if is_live_spool_path(&path) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let reason = match parse_spool_claim(name) {
                Some(claim) if claim.process_tag == spool_process_tag() => {
                    // Our process, no live lease: the owning replay task was
                    // aborted or its generation was dropped mid-delivery.
                    "aborted delivery in this process"
                }
                Some(claim) if now >= claim.lease_deadline_unix => "expired peer claim lease",
                Some(_) => continue,
                None => {
                    // Unparseable claim marker: treat conservatively as a peer's
                    // and wait out a full lease horizon by mtime.
                    if !spool_temp_is_stale(&path, wall_clock, self.claim_lease_secs)? {
                        continue;
                    }
                    "expired unattributed claim"
                }
            };
            let Some(restored) = self.restore_claim_path(&path)? else {
                continue;
            };
            warn!(
                plugin = PLUGIN_NAME,
                path = %path.display(),
                restored = %restored.display(),
                generation = self.generation,
                reason,
                "Chargeback sink recovered an in-flight spool claim"
            );
        }
        Ok(())
    }

    /// Rename one claim back to its durable replayable name.
    ///
    /// `Ok(None)` means the claim disappeared (already recovered or finalized by
    /// its owner) and is not an error.
    fn restore_claim_path(&self, claim: &Path) -> Result<Option<PathBuf>, String> {
        let restored = spool_claim_restore_path(claim)?;
        self.assert_managed_path(&restored)?;
        match fs::rename(claim, &restored) {
            Ok(()) => Ok(Some(restored)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "{PLUGIN_NAME}: failed to restore in-flight spool claim '{}' to '{}': {error}",
                claim.display(),
                restored.display()
            )),
        }
    }

    fn list_owned_spool_files(&self) -> Result<Vec<PathBuf>, String> {
        self.validate_namespace_meta_if_present()?;
        let mut files = Vec::new();
        self.collect(&mut files, SpoolFileClass::Owned)?;
        files.sort();
        Ok(files)
    }

    /// Replay candidates owned by this exact identity.
    ///
    /// Ownership metadata is validated first, then every candidate must carry
    /// this owner's tag. A data file whose tag names a different owner is never
    /// read, delivered, deleted, or dead-lettered here; it is only counted and
    /// surfaced so operators can reconcile it.
    fn list_replayable_spool_files(&self) -> Result<Vec<PathBuf>, String> {
        self.validate_namespace_meta()?;
        let mut candidates = Vec::new();
        self.collect(&mut candidates, SpoolFileClass::Replayable)?;
        let mut files = Vec::new();
        for path in candidates {
            if spool_file_owner_tag(&path).is_some_and(|tag| self.owner.matches_tag(tag)) {
                files.push(path);
            }
        }
        // Refresh the exported gauge as well as the warning. A foreign file may
        // be planted after initial prepare, and warning without updating status
        // would hide live operational evidence until the next full prepare.
        self.scan_unbound_records();
        files.sort();
        Ok(files)
    }

    /// Records inside this managed namespace whose owner tag names a different
    /// identity. Reachable only by tampering or a hand-moved file; counted so
    /// quota reporting stays honest, and never replayed, evicted, or deleted.
    fn count_foreign_tagged_records(&self) -> u64 {
        let mut candidates = Vec::new();
        let class = SpoolFileClass::Replayable;
        if self.collect(&mut candidates, class).is_err() {
            return 0;
        }
        let mut foreign = 0u64;
        for path in &candidates {
            if !spool_file_owner_tag(path).is_some_and(|tag| self.owner.matches_tag(tag)) {
                foreign = foreign.saturating_add(1);
            }
        }
        foreign
    }

    fn validate_namespace_meta_if_present(&self) -> Result<(), String> {
        if self.meta_path().exists() {
            self.validate_namespace_meta()?;
        }
        Ok(())
    }

    /// Atomically claim one replay candidate.
    ///
    /// The rename is the mutual-exclusion primitive: on a shared volume exactly
    /// one accepted generation or process can win it. `Ok(None)` means somebody
    /// else won, and the caller must simply move on.
    fn claim_replay_file_locked(&self, path: &Path) -> Result<Option<SpoolClaimHandle>, String> {
        self.assert_managed_path(path)?;
        if !is_spool_data_file(path) {
            return Err(format!(
                "{PLUGIN_NAME}: refusing to claim non-replayable spool file '{}'",
                path.display()
            ));
        }
        match spool_file_owner_tag(path) {
            Some(tag) if self.owner.matches_tag(tag) => {}
            _ => {
                return Err(format!(
                    "{PLUGIN_NAME}: refusing to claim spool file '{}' owned by another identity",
                    path.display()
                ));
            }
        }
        let lease_delta = self.claim_lease_secs.min(i64::MAX as u64) as i64;
        let lease_deadline = unix_timestamp_seconds().saturating_add(lease_delta);
        let claim_path = spool_claim_path(path, self.generation, lease_deadline)?;
        self.assert_managed_path(&claim_path)?;
        // Register the live lease before the rename so a concurrent prepare in
        // this process can never see the claim as orphaned.
        let guard = LiveSpoolPathGuard::new(claim_path.clone());
        match fs::rename(path, &claim_path) {
            Ok(()) => Ok(Some(SpoolClaimHandle {
                path: claim_path,
                _live: guard,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "{PLUGIN_NAME}: failed to claim spool file '{}' as in-flight '{}': {error}",
                path.display(),
                claim_path.display()
            )),
        }
    }

    /// Extend one live claim before starting the next bounded ClickHouse
    /// delivery attempt.
    ///
    /// A single spool file can contain multiple replay chunks. Renewing between
    /// chunks prevents the aggregate file-delivery time from outliving a lease
    /// that is intentionally derived from one bounded request/retry budget.
    fn renew_claim_locked(&self, claim: &mut SpoolClaimHandle) -> Result<(), String> {
        let lease_delta = self.claim_lease_secs.min(i64::MAX as u64) as i64;
        let lease_deadline = unix_timestamp_seconds().saturating_add(lease_delta);
        self.renew_claim_locked_at(claim, lease_deadline)
    }

    /// Renew one live claim onto an explicit lease deadline.
    ///
    /// Split out from [`Self::renew_claim_locked`] so the rename half of the
    /// protocol is exercised deterministically instead of only when a chunk
    /// boundary happens to cross a wall-clock second.
    fn renew_claim_locked_at(
        &self,
        claim: &mut SpoolClaimHandle,
        lease_deadline: i64,
    ) -> Result<(), String> {
        let durable = spool_claim_restore_path(claim.path())?;
        let renewed = spool_claim_path(&durable, self.generation, lease_deadline)?;
        if renewed == claim.path {
            return Ok(());
        }
        self.assert_managed_path(claim.path())?;
        self.assert_managed_path(&renewed)?;
        // Register the renewed name before the atomic rename so another
        // generation in this process cannot observe an unleased path.
        let renewed_live = LiveSpoolPathGuard::new(renewed.clone());
        fs::rename(claim.path(), &renewed).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to renew in-flight spool claim '{}' as '{}': {error}",
                claim.path().display(),
                renewed.display()
            )
        })?;
        claim.path = renewed;
        let old_live = std::mem::replace(&mut claim._live, renewed_live);
        drop(old_live);
        Ok(())
    }

    /// Release a claim back to its durable replayable name after a retryable
    /// delivery failure. `Ok(None)` means the claim was already recovered.
    fn release_claim_locked(&self, claim: &Path) -> Result<Option<PathBuf>, String> {
        self.assert_managed_path(claim)?;
        self.restore_claim_path(claim)
    }

    /// Remove a claim whose rows were fully delivered.
    fn remove_delivered_claim(&self, claim: &Path) -> Result<(), String> {
        self.assert_managed_path(claim)?;
        match fs::remove_file(claim) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    plugin = PLUGIN_NAME,
                    path = %claim.display(),
                    generation = self.generation,
                    "Chargeback sink delivered a spool claim that another owner had already recovered"
                );
                Ok(())
            }
            Err(error) => Err(format!(
                "{PLUGIN_NAME}: failed to remove replayed spool file '{}': {error}",
                claim.display()
            )),
        }
    }

    /// Count records under this node/plugin subtree that no accepted generation
    /// owns: pre-namespace layouts and sibling namespaces left behind by a
    /// destination/schema/Ferrum-namespace change. A node-id or plugin-config-id
    /// change moves to a different parent subtree and requires explicit operator
    /// discovery. Unbound records are never replayed, deleted, or rerouted.
    fn scan_unbound_records(&self) {
        let _ = self.scan_unbound_records_with_entry_limit(MAX_SPOOL_TRAVERSAL_ENTRIES);
    }

    /// Scan legacy and sibling namespaces under one aggregate entry budget.
    ///
    /// Giving every sibling subtree a fresh [`MAX_SPOOL_TRAVERSAL_ENTRIES`]
    /// allowance would make a shared-volume maintenance tick unbounded in the
    /// number of owner namespaces. A truncated scan reports the observed lower
    /// bound and an explicit warning; it never replays or mutates an unvisited
    /// record.
    fn scan_unbound_records_with_entry_limit(&self, max_entries: usize) -> (u64, u64, bool) {
        let components = match spool_namespace_components(&self.owner) {
            Ok(components) => components,
            Err(_) => return (0, 0, false),
        };
        let root = self.namespace_root.as_path();
        let dir = self.cfg.dir.as_path();
        let (orphaned, namespaces, truncated) =
            count_unbound_spool_records(dir, &components, root, max_entries);
        let files = orphaned.saturating_add(self.count_foreign_tagged_records());
        self.metrics
            .spool_unbound_files
            .store(files, Ordering::Relaxed);
        self.metrics
            .spool_unbound_namespaces
            .store(namespaces, Ordering::Relaxed);
        if files > 0 || namespaces > 0 || truncated {
            self.warn_unbound_records(files, namespaces, truncated);
        }
        (files, namespaces, truncated)
    }

    fn warn_unbound_records(&self, files: u64, namespaces: u64, truncated: bool) {
        let now = unix_timestamp_seconds();
        let last = self.last_unbound_warn_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SPOOL_WARN_INTERVAL_SECS
            || self
                .last_unbound_warn_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        warn!(
            plugin = PLUGIN_NAME,
            generation = self.generation,
            unbound_files = files,
            unbound_namespaces = namespaces,
            scan_truncated = truncated,
            spool_dir = %self.cfg.dir.display(),
            managed_namespace = %self.namespace_root.display(),
            "Chargeback sink found spool records that are not bound to this destination identity, or reached the bounded scan limit; reported counts are lower bounds when scan_truncated=true, records are never replayed or deleted, and an operator must reconcile them (rate-limited)"
        );
    }
}

/// One in-flight replay claim plus the live-path lease that protects it.
pub struct SpoolClaimHandle {
    path: PathBuf,
    _live: LiveSpoolPathGuard,
}

impl SpoolClaimHandle {
    fn path(&self) -> &Path {
        &self.path
    }

    #[doc(hidden)]
    #[allow(dead_code)] // external unit tests only
    pub fn claim_path_for_tests(&self) -> &Path {
        &self.path
    }
}

/// Default owner identity used by the simple test constructor.
#[allow(dead_code)] // external unit tests only
fn default_test_spool_owner_spec(node_id: &str) -> SpoolOwnerSpec<'_> {
    SpoolOwnerSpec {
        node_id,
        plugin_config_id: "test-plugin",
        ferrum_namespace: "ferrum",
        destination_endpoint: "http://127.0.0.1:8123",
        database: "ferrum",
        table: "charges_raw",
    }
}

fn spool_temp_is_stale(path: &Path, now: SystemTime, age_secs: u64) -> Result<bool, String> {
    let meta = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to stat spool temp '{}': {error}",
            path.display()
        )
    })?;
    if meta.file_type().is_symlink() {
        return Ok(false);
    }
    if age_secs == 0 {
        return Ok(true);
    }
    let modified = meta.modified().map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to read mtime for spool temp '{}': {error}",
            path.display()
        )
    })?;
    let elapsed = now.duration_since(modified).unwrap_or_default();
    Ok(elapsed >= Duration::from_secs(age_secs))
}

/// Parsed generation-owned atomic-write temp marker.
struct SpoolWriteTemp<'a> {
    process_tag: &'a str,
    #[allow(dead_code)] // retained for diagnostics and future lease policy
    generation: u64,
}

/// `<data-name>.write-<process_tag>-<generation>.tmp`
fn spool_write_temp_path(final_path: &Path, generation: u64) -> Result<PathBuf, String> {
    let name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    Ok(final_path.with_file_name(format!(
        "{name}{SPOOL_WRITE_MARKER}{}-{generation}{SPOOL_TMP_SUFFIX}",
        spool_process_tag()
    )))
}

fn parse_spool_write_temp(name: &str) -> Option<SpoolWriteTemp<'_>> {
    let marker = name.strip_suffix(SPOOL_TMP_SUFFIX)?;
    let (_, attribution) = marker.rsplit_once(SPOOL_WRITE_MARKER)?;
    let (process_tag, generation) = attribution.rsplit_once('-')?;
    if process_tag.is_empty() {
        return None;
    }
    Some(SpoolWriteTemp {
        process_tag,
        generation: generation.parse().ok()?,
    })
}

/// Parsed in-flight replay claim marker.
struct SpoolClaim<'a> {
    process_tag: &'a str,
    #[allow(dead_code)] // retained for diagnostics and future lease policy
    generation: u64,
    lease_deadline_unix: i64,
}

/// `<data-name>.claim-<process_tag>-<generation>-<lease_deadline_unix>.inflight`
fn spool_claim_path(
    path: &Path,
    generation: u64,
    lease_deadline_unix: i64,
) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    Ok(path.with_file_name(format!(
        "{name}{SPOOL_CLAIM_MARKER}{}-{generation}-{lease_deadline_unix}{SPOOL_INFLIGHT_SUFFIX}",
        spool_process_tag()
    )))
}

fn parse_spool_claim(name: &str) -> Option<SpoolClaim<'_>> {
    let marker = name.strip_suffix(SPOOL_INFLIGHT_SUFFIX)?;
    let (_, attribution) = marker.rsplit_once(SPOOL_CLAIM_MARKER)?;
    let mut parts = attribution.split('-');
    let process_tag = parts.next()?;
    let generation = parts.next()?.parse().ok()?;
    let lease_deadline_unix = parts.next()?.parse().ok()?;
    if process_tag.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(SpoolClaim {
        process_tag,
        generation,
        lease_deadline_unix,
    })
}

/// Strip a claim marker back to the durable replayable name.
fn spool_claim_restore_path(claim: &Path) -> Result<PathBuf, String> {
    let name = claim
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    let base = spool_claim_base_name(name).ok_or_else(|| {
        format!(
            "{PLUGIN_NAME}: in-flight spool path '{}' is missing a claim marker",
            claim.display()
        )
    })?;
    Ok(claim.with_file_name(base))
}

fn spool_claim_base_name(name: &str) -> Option<&str> {
    let marker = name.strip_suffix(SPOOL_INFLIGHT_SUFFIX)?;
    let (base, _) = marker.rsplit_once(SPOOL_CLAIM_MARKER)?;
    Some(base)
}

/// Managed base name of any derived artifact (claim or temp).
fn spool_artifact_base_name(name: &str) -> &str {
    if let Some(base) = spool_claim_base_name(name) {
        return base;
    }
    if let Some(marker) = name.strip_suffix(SPOOL_TMP_SUFFIX)
        && let Some((base, _)) = marker.rsplit_once(SPOOL_WRITE_MARKER)
    {
        return base;
    }
    name
}

/// Owner tag embedded in `<ULID>.<owner_tag>.ndjson[.zst]`, including derived
/// claim, temp, corrupt, and dead-letter artifacts of that name.
fn spool_file_owner_tag(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    spool_owner_tag_of_name(spool_artifact_base_name(name))
}

fn spool_owner_tag_of_name(name: &str) -> Option<&str> {
    // Peel retained-artifact suffixes outermost-first so a dead-letter temp
    // (`....ndjson.rejected.meta.tmp`) still resolves back to its data name.
    let mut rest = name;
    for suffix in [".tmp", ".rejected.meta", ".corrupt"] {
        rest = rest.strip_suffix(suffix).unwrap_or(rest);
    }
    let stem = rest
        .strip_suffix(".ndjson.zst")
        .or_else(|| rest.strip_suffix(".ndjson"))?;
    let (_, tag) = stem.rsplit_once('.')?;
    if matches!(tag.len(), SPOOL_LEGACY_OWNER_TAG_LEN | SPOOL_OWNER_TAG_LEN)
        && tag.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(tag)
    } else {
        None
    }
}

/// Count spool records under this node/plugin subtree that no accepted
/// generation owns.
///
/// Two shapes matter: the pre-namespace layout that wrote directly under
/// `<spool.dir>/<node>/<day>/`, and sibling owner namespaces left behind when
/// the ClickHouse destination, database, table, or Ferrum namespace changed.
/// A plugin-config-id or node-id change moves to another parent subtree and is
/// intentionally not attributed to this live instance. Discoverable records are
/// reported, never replayed and never deleted, so an operator decides whether
/// they still belong to the new destination.
fn count_unbound_spool_records(
    spool_dir: &Path,
    components: &SpoolNamespaceComponents,
    namespace_root: &Path,
    max_entries: usize,
) -> (u64, u64, bool) {
    let node_dir = spool_dir.join(&components.node);
    let plugin_dir = node_dir.join(&components.plugin);
    let mut files = 0u64;
    let mut namespaces = 0u64;
    let mut remaining = max_entries;
    let mut truncated = false;

    // Pre-namespace layout: `<spool.dir>/<node>/<YYYYMMDD>/*.ndjson[.zst]`.
    // Only day-shaped directories are inspected so a sibling plugin config's own
    // managed subtree is never counted against this instance.
    for day_dir in child_dirs_bounded(
        &node_dir,
        is_spool_day_component,
        &mut remaining,
        &mut truncated,
    ) {
        let (records, complete) = count_records_in_bounded(&day_dir, &mut remaining);
        files = files.saturating_add(records);
        if !complete {
            truncated = true;
            break;
        }
    }

    // Sibling owner namespaces under this node/plugin: what a destination,
    // database, table, ledger, or plugin-id change leaves behind.
    if !truncated {
        for owner_dir in child_dirs_bounded(
            &plugin_dir,
            |name| name.starts_with('o'),
            &mut remaining,
            &mut truncated,
        ) {
            if owner_dir == namespace_root {
                continue;
            }
            let (records, complete) = count_records_in_bounded(&owner_dir, &mut remaining);
            if records > 0 {
                namespaces = namespaces.saturating_add(1);
                files = files.saturating_add(records);
            }
            if !complete {
                truncated = true;
                break;
            }
        }
    }
    (files, namespaces, truncated)
}

fn is_spool_day_component(name: &str) -> bool {
    name.len() == 8 && name.bytes().all(|byte| byte.is_ascii_digit())
}

/// Non-symlink child directories of `dir` whose name passes `accept`, charged
/// against the caller's aggregate traversal budget.
fn child_dirs_bounded(
    dir: &Path,
    accept: impl Fn(&str) -> bool,
    remaining: &mut usize,
    truncated: &mut bool,
) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        if *remaining == 0 {
            *truncated = true;
            break;
        }
        *remaining = (*remaining).saturating_sub(1);
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if accept(name) {
            dirs.push(path);
        }
    }
    dirs
}

/// Count records while consuming the same global budget used to discover
/// sibling roots. `complete=false` stops the aggregate scan immediately.
fn count_records_in_bounded(dir: &Path, remaining: &mut usize) -> (u64, bool) {
    if *remaining == 0 {
        return (0, false);
    }
    let mut records = Vec::new();
    let mut walk = match SpoolWalk::new_inner(dir, SpoolFileClass::AnyRecord, None, *remaining) {
        Ok(walk) => walk,
        Err(_) => return (0, false),
    };
    let complete = walk.run(dir, &mut records).is_ok();
    *remaining = (*remaining).saturating_sub(walk.entry_count);
    (records.len() as u64, complete)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpoolFileClass {
    /// Active data, crash-left temps, corrupt quarantine, metadata-only
    /// dead-letter files, and in-flight replay claims — quota/status.
    Owned,
    /// Durable replay candidates (`*.ndjson` / `*.ndjson.zst`).
    Replayable,
    /// Interrupted atomic-write temps.
    Temp,
    /// Atomically claimed replay files.
    Inflight,
    /// Any durable record shape, whether or not it carries an owner tag; used
    /// only by the unbound/legacy reconciliation scan.
    AnyRecord,
}

/// Bounded, symlink-free, cycle-free walk of one managed subtree.
struct SpoolWalk<'a> {
    root: &'a Path,
    class: SpoolFileClass,
    entry_count: usize,
    max_entries: usize,
    visited: HashSet<DirIdentity>,
    canonical_root: Option<PathBuf>,
}

impl<'a> SpoolWalk<'a> {
    fn new_with_expected_root(
        root: &'a Path,
        class: SpoolFileClass,
        expected_root: &Path,
        max_entries: usize,
    ) -> Result<Self, String> {
        Self::new_inner(root, class, Some(expected_root), max_entries)
    }

    fn new_inner(
        root: &'a Path,
        class: SpoolFileClass,
        expected_root: Option<&Path>,
        max_entries: usize,
    ) -> Result<Self, String> {
        let canonical_root = match fs::symlink_metadata(root) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "{PLUGIN_NAME}: refusing to walk symlinked spool root '{}'",
                    root.display()
                ));
            }
            Ok(_) => Some(fs::canonicalize(root).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to canonicalize spool walk root '{}': {error}",
                    root.display()
                )
            })?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "{PLUGIN_NAME}: failed to lstat spool walk root '{}': {error}",
                    root.display()
                ));
            }
        };
        if let (Some(expected), Some(actual)) = (expected_root, canonical_root.as_deref())
            && actual != expected
        {
            return Err(format!(
                "{PLUGIN_NAME}: spool walk root '{}' changed canonical target from '{}' to '{}'",
                root.display(),
                expected.display(),
                actual.display()
            ));
        }
        Ok(Self {
            root,
            class,
            entry_count: 0,
            max_entries,
            visited: HashSet::new(),
            canonical_root,
        })
    }

    fn run(&mut self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
        self.walk(dir, files, 0)
    }

    fn walk(&mut self, dir: &Path, files: &mut Vec<PathBuf>, depth: u32) -> Result<(), String> {
        if depth > MAX_SPOOL_TRAVERSAL_DEPTH {
            return Err(format!(
                "{PLUGIN_NAME}: spool traversal exceeded max depth ({MAX_SPOOL_TRAVERSAL_DEPTH}) under '{}'",
                self.root.display()
            ));
        }
        ensure_path_within_root(self.root, dir)?;
        reject_symlinked_spool_path(dir)?;
        if let Some(canonical_root) = self.canonical_root.as_deref() {
            directory_is_within_canonical_root(canonical_root, dir)?;
        }
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "{PLUGIN_NAME}: failed to read spool directory '{}': {error}",
                    dir.display()
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to read spool directory entry '{}': {error}",
                    dir.display()
                )
            })?;
            if self.entry_count >= self.max_entries {
                return Err(format!(
                    "{PLUGIN_NAME}: spool traversal exceeded max entry count ({}) under '{}'",
                    self.max_entries,
                    self.root.display()
                ));
            }
            self.entry_count = self.entry_count.saturating_add(1);
            let path = entry.path();
            ensure_path_within_root(self.root, &path)?;
            // Never follow symlinks for scan, replay, eviction, quarantine, or
            // temp cleanup: the entry must be the real node we enumerated.
            let meta = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "{PLUGIN_NAME}: failed to lstat spool path '{}': {error}",
                    path.display()
                )
            })?;
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                warn!(
                    plugin = PLUGIN_NAME,
                    path = %path.display(),
                    "Chargeback sink ignored a symlink under the managed spool namespace"
                );
                continue;
            }
            if file_type.is_dir() {
                if let Some(identity) = dir_identity(&meta)
                    && !self.visited.insert(identity)
                {
                    warn!(
                        plugin = PLUGIN_NAME,
                        path = %path.display(),
                        "Chargeback sink skipped a spool directory cycle"
                    );
                    continue;
                }
                self.walk(&path, files, depth + 1)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some(SPOOL_META_FILENAME) {
                continue;
            }
            if spool_file_matches(&path, self.class) {
                files.push(path);
            }
        }
        Ok(())
    }
}

fn quarantine_spool_file(spool: &SpoolManager, path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    // Quarantine under the durable data name so the owner tag survives.
    let base = spool_artifact_base_name(name);
    let quarantine_path = path.with_file_name(format!("{base}.corrupt"));
    // Quarantine is a rename inside the managed tree, so it takes the same
    // writer lock and containment/symlink proof as every other spool mutation.
    let _guard = spool
        .write_lock
        .lock()
        .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
    spool.assert_managed_path(path)?;
    spool.assert_managed_path(&quarantine_path)?;
    fs::rename(path, &quarantine_path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to quarantine corrupt spool file '{}' to '{}': {error}",
            path.display(),
            quarantine_path.display()
        )
    })?;
    Ok(quarantine_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadLetterReason {
    PermanentHttp,
    PayloadTooLarge,
}

impl DeadLetterReason {
    fn as_str(self) -> &'static str {
        match self {
            DeadLetterReason::PermanentHttp => "permanent_http",
            DeadLetterReason::PayloadTooLarge => "payload_too_large",
        }
    }
}

/// One aggregated safe outcome within a metadata-only dead-letter record.
#[derive(Debug, Clone, Serialize)]
struct DeadLetterOutcomeMeta {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    row_count: usize,
}

/// Safe dead-letter metadata only: no response bodies, credentials, or charge PII.
#[derive(Debug, Clone, Serialize)]
struct DeadLetterMeta {
    rejected_rows: usize,
    outcomes: Vec<DeadLetterOutcomeMeta>,
    quarantined_at_unix: i64,
}

fn dead_letter_meta_paths(path: &Path) -> Result<(PathBuf, PathBuf), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{PLUGIN_NAME}: invalid spool file path"))?;
    // Name the record after the durable data file, not after the claim marker,
    // so the dead letter keeps the owner tag and stays attributable.
    let base = spool_artifact_base_name(name);
    let meta_path = path.with_file_name(format!("{base}.rejected.meta"));
    let tmp_path = path.with_file_name(format!("{base}.rejected.meta.tmp"));
    Ok((tmp_path, meta_path))
}

fn write_dead_letter_meta(
    spool: &SpoolManager,
    source_path: &Path,
    meta: &DeadLetterMeta,
) -> Result<PathBuf, String> {
    let (tmp_path, meta_path) = dead_letter_meta_paths(source_path)?;
    let bytes = serde_json::to_vec(&meta).map_err(|error| {
        format!("{PLUGIN_NAME}: failed to serialize dead-letter metadata: {error}")
    })?;
    let _guard = spool
        .write_lock
        .lock()
        .map_err(|_| format!("{PLUGIN_NAME}: spool write lock poisoned"))?;
    spool.assert_managed_path(&meta_path)?;
    spool.assert_managed_path(&tmp_path)?;
    spool.assert_managed_path(source_path)?;
    match fs::remove_file(&meta_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "{PLUGIN_NAME}: failed to replace dead-letter metadata '{}': {error}",
                meta_path.display()
            ));
        }
    }
    let _live = LiveSpoolPathGuard::new(tmp_path.clone());
    // `<ulid>.<owner_tag>.<ext>.rejected.meta` inherits the uniqueness of the
    // ULID-named source artifact it describes, so this final is exclusively this
    // attempt's and a failed publish rolls it back.
    write_private_file_atomically_with_ops(
        &tmp_path,
        &meta_path,
        &bytes,
        spool.fs_ops,
        SpoolFinalOwnership::Unique,
    )?;
    if let Err(error) = fs::remove_file(source_path) {
        let cleanup_error = fs::remove_file(&meta_path).err();
        return Err(format!(
            "{PLUGIN_NAME}: failed to remove permanently rejected spool file '{}': {error}; dead-letter metadata cleanup: {}",
            source_path.display(),
            cleanup_error
                .map(|cleanup| cleanup.to_string())
                .unwrap_or_else(|| "ok".to_string())
        ));
    }
    // Reuse the spool's owned-byte eviction policy after replacing the source
    // payload with its much smaller safe metadata record. This also handles an
    // operator-configured max_bytes too small to retain even the metadata.
    spool.evict_until_can_admit(0)?;
    Ok(meta_path)
}

fn spool_file_matches(path: &Path, class: SpoolFileClass) -> bool {
    match class {
        SpoolFileClass::Owned => is_spool_owned_file(path),
        SpoolFileClass::Replayable => is_spool_data_file(path),
        SpoolFileClass::Temp => is_spool_temp_file(path),
        SpoolFileClass::Inflight => is_spool_inflight_file(path),
        SpoolFileClass::AnyRecord => is_spool_data_file(path),
    }
}

fn is_spool_data_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.ends_with(SPOOL_INFLIGHT_SUFFIX)
        || name.ends_with(SPOOL_TMP_SUFFIX)
        || name.ends_with(".corrupt")
        || name.ends_with(".rejected")
        || name.ends_with(".meta")
    {
        return false;
    }
    name.ends_with(".ndjson.zst") || name.ends_with(".ndjson")
}

fn is_spool_temp_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !name.ends_with(SPOOL_TMP_SUFFIX) {
        return false;
    }
    // Generation/process-attributed temps written by this format, plus the
    // pre-attribution shapes and dead-letter metadata temps that a prior
    // release could have left behind.
    parse_spool_write_temp(name).is_some()
        || name.ends_with(".ndjson.tmp")
        || name.ends_with(".ndjson.zst.tmp")
        || name.ends_with(".rejected.meta.tmp")
}

fn is_spool_inflight_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(SPOOL_INFLIGHT_SUFFIX)
}

fn is_spool_corrupt_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson.corrupt") || name.ends_with(".ndjson.zst.corrupt")
}

fn is_spool_rejected_meta_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson.rejected.meta") || name.ends_with(".ndjson.zst.rejected.meta")
}

fn is_spool_owned_file(path: &Path) -> bool {
    is_spool_data_file(path)
        || is_spool_temp_file(path)
        || is_spool_corrupt_file(path)
        || is_spool_rejected_meta_file(path)
        || is_spool_inflight_file(path)
}

/// Unreserved reference encoder for external tests.
///
/// Byte-for-byte equivalent to the artifact
/// [`SpoolManager::materialize_spool_artifact`] publishes — same one-shot zstd
/// path, so the frame carries the decompressed size — but without the ceiling
/// reservation that makes the production path safe. Tests use it to predict
/// on-disk sizes; production must never call it.
#[allow(dead_code)] // external unit tests only
fn encode_spool_bytes(bytes: &[u8], compression: SpoolCompression) -> Result<Vec<u8>, String> {
    match compression {
        SpoolCompression::Zstd => {
            let bound = zstd::zstd_safe::compress_bound(bytes.len())
                .checked_add(SPOOL_ZSTD_FRAME_SLACK_BYTES)
                .ok_or_else(|| format!("{PLUGIN_NAME}: spool compression byte bound overflowed"))?;
            let mut encoded = vec![0u8; bound];
            let written = zstd::bulk::compress_to_buffer(bytes, &mut encoded, 0)
                .map_err(|error| format!("{PLUGIN_NAME}: zstd compression failed: {error}"))?;
            let written = pad_zstd_to_replay_ratio(&mut encoded, written, bytes.len() as u64)?;
            encoded.truncate(written);
            Ok(encoded)
        }
        SpoolCompression::None => Ok(bytes.to_vec()),
    }
}

/// Encode a raw one-shot zstd frame without the writer's ratio padding.
///
/// External tests use this to model a planted frame whose truthful declared
/// size would exceed the replay ratio. Production must never call it.
#[doc(hidden)]
#[allow(dead_code)] // external unit tests only
pub fn encode_spool_bytes_without_ratio_padding_for_tests(bytes: &[u8]) -> Result<Vec<u8>, String> {
    zstd::bulk::compress(bytes, 0)
        .map_err(|error| format!("{PLUGIN_NAME}: zstd compression failed: {error}"))
}

/// Encode a spool artifact with the *streaming* zstd encoder, which omits the
/// decompressed size from the frame header.
///
/// This is the legacy / foreign-archive shape replay must still accept by
/// falling back to the ratio clamp; no production path produces it.
#[doc(hidden)]
#[allow(dead_code)] // external unit tests only
pub fn encode_spool_bytes_without_content_size_for_tests(
    bytes: &[u8],
    compression: SpoolCompression,
) -> Result<Vec<u8>, String> {
    match compression {
        SpoolCompression::Zstd => zstd::stream::encode_all(bytes, 0)
            .map_err(|error| format!("{PLUGIN_NAME}: zstd compression failed: {error}")),
        SpoolCompression::None => Ok(bytes.to_vec()),
    }
}

/// Observation points for the optional spool-write test seam.
///
/// Used by external unit tests to inject deliberate stalls around
/// [`SpoolManager::write_events`] without relying on wall-clock sleeps, and to
/// mutate the spool tree at the exact instant a quota-eviction snapshot has been
/// taken so the disappearing-candidate race is deterministic rather than timed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolWriteHookPoint {
    BeforeWrite,
    AfterWrite,
    /// One quota-eviction inventory snapshot has been taken and the tree is over
    /// the ceiling; deletions from that snapshot have not started yet.
    QuotaInventoryTaken,
}

/// The hook carries the namespace root of the [`SpoolManager`] that reached the
/// point, so a hook installed by one test is inert for every other manager.
///
/// The slot is process-global and the test binary runs tests in parallel, so
/// without that discriminator an unrelated test's eviction or write fires the
/// installed closure — which is an extra, unaccounted invocation for the test
/// that owns it, not a bug in the code under test.
type SpoolWriteHookForTests = Arc<dyn Fn(SpoolWriteHookPoint, &Path) + Send + Sync + 'static>;

fn spool_write_hook_slot() -> &'static Mutex<Option<SpoolWriteHookForTests>> {
    static HOOK: OnceLock<Mutex<Option<SpoolWriteHookForTests>>> = OnceLock::new();
    HOOK.get_or_init(|| Mutex::new(None))
}

/// Install or clear a process-global hook around spool filesystem writes.
///
/// Tests must clear the hook before finishing (including panic paths), serialize
/// against other chargeback-sink tests that publish ACTIVE_SINKS, and ignore
/// every point whose namespace root is not their own spool.
#[doc(hidden)]
#[allow(dead_code)]
pub fn set_spool_write_hook_for_tests(hook: Option<SpoolWriteHookForTests>) {
    if let Ok(mut slot) = spool_write_hook_slot().lock() {
        *slot = hook;
    }
}

fn snapshot_spool_write_hook_for_tests() -> Option<SpoolWriteHookForTests> {
    spool_write_hook_slot()
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
}

/// Ensures [`SpoolWriteHookPoint::AfterWrite`] runs on every `write_events`
/// exit path with the same hook instance that observed `BeforeWrite`.
///
/// Re-reading the process-global slot on drop would let a write that entered
/// under hook A publish `AfterWrite` to a later-installed hook B — breaking
/// tests that deliberately stall one generation's write while asserting that
/// generation has not finished.
struct SpoolWriteHookAfterGuard {
    hook: Option<SpoolWriteHookForTests>,
    namespace_root: PathBuf,
}

impl SpoolWriteHookAfterGuard {
    fn enter(namespace_root: &Path) -> Self {
        let hook = snapshot_spool_write_hook_for_tests();
        if let Some(ref hook) = hook {
            hook(SpoolWriteHookPoint::BeforeWrite, namespace_root);
        }
        Self {
            hook,
            namespace_root: namespace_root.to_path_buf(),
        }
    }
}

impl Drop for SpoolWriteHookAfterGuard {
    fn drop(&mut self) {
        if let Some(hook) = self.hook.take() {
            hook(SpoolWriteHookPoint::AfterWrite, &self.namespace_root);
        }
    }
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn encode_spool_bytes_for_tests(
    bytes: &[u8],
    compression: SpoolCompression,
) -> Result<Vec<u8>, String> {
    encode_spool_bytes(bytes, compression)
}

/// Bytes one `(start, end)` entry of the spool line index or replay worklist
/// occupies.
const SPOOL_INDEX_ENTRY_BYTES: usize = 2 * std::mem::size_of::<usize>();

/// Growth step for the bounded spool decode buffer.
const SPOOL_DECODE_CHUNK_BYTES: usize = 64 * 1024;

/// Why a spool artifact could not be decoded into a charged representation.
enum SpoolDecodeError {
    /// The artifact itself is unreadable, oversized, or corrupt. The caller
    /// quarantines it so an operator can review it.
    Unreadable(String),
    /// The retained-byte ceiling refused the artifact *before* it was decoded.
    /// Nothing is wrong with the file: the caller releases the claim so a later
    /// tick replays it in order.
    CeilingExhausted(String),
}

impl SpoolDecodeError {
    // Only the external decode test helper flattens the variants; the binary
    // target does not compile that caller.
    #[allow(dead_code)]
    fn into_message(self) -> String {
        match self {
            Self::Unreadable(message) | Self::CeilingExhausted(message) => message,
        }
    }
}

/// One decoded spool artifact plus its line index, both charged to the
/// retained-byte ceiling for exactly as long as they are held.
///
/// Rows are never copied out of `text`: chunking, 413 splits, and retries all
/// address lines by `(start, end)` byte range into the single decoded buffer.
/// A 256 MiB artifact therefore produces one decoded representation, not one
/// per worklist level.
struct ReservedSpoolArtifact {
    text: String,
    lines: Vec<(usize, usize)>,
    /// Charge on the decoded buffer. Reserved before the file is read, shrunk
    /// to the buffer's real allocation, released on drop.
    _text_reservation: ProcessByteReservation,
    /// Charge on the line index. Reserved before the index is allocated.
    _index_reservation: ProcessByteReservation,
}

impl ReservedSpoolArtifact {
    fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Borrow one indexed line. Never panics: an out-of-range or non-boundary
    /// index is a fixed-label error rather than a slice panic.
    fn line(&self, index: usize) -> Result<&str, String> {
        let (start, end) = *self.lines.get(index).ok_or_else(|| {
            format!("{PLUGIN_NAME}: spool replay line index {index} is out of range")
        })?;
        self.text.get(start..end).ok_or_else(|| {
            format!("{PLUGIN_NAME}: spool replay line index {index} is not a character boundary")
        })
    }

    #[allow(dead_code)] // used by the external decode test helper
    fn into_text(self) -> String {
        self.text
    }
}

/// Visit every non-empty JSONEachRow line of `text` as a `(start, end)` byte
/// range, matching `str::lines` framing (`\n` separated, trailing `\r`
/// stripped) without allocating a single row copy.
fn for_each_spool_line(text: &str, mut visit: impl FnMut(usize, usize)) {
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while let Some(rest) = bytes.get(start..) {
        let separator = match rest.iter().position(|byte| *byte == b'\n') {
            Some(offset) => start.saturating_add(offset),
            None => bytes.len(),
        };
        let mut end = separator;
        if end > start && bytes.get(end.saturating_sub(1)) == Some(&b'\r') {
            end -= 1;
        }
        if let Some(line) = text.get(start..end)
            && !line.trim().is_empty()
        {
            visit(start, end);
        }
        if separator >= bytes.len() {
            break;
        }
        start = separator.saturating_add(1);
    }
}

/// Decode one spool artifact into a representation that is charged to `ceiling`
/// for its whole life.
///
/// The decoded upper bound is reserved *before* the file is read, so a process
/// already at its retained-byte ceiling refuses the artifact instead of
/// materializing an unbounded owned copy of it.
fn decode_spool_artifact(
    path: &Path,
    ceiling: &'static RetainedByteCeiling,
) -> Result<ReservedSpoolArtifact, SpoolDecodeError> {
    let file = File::open(path).map_err(|error| {
        SpoolDecodeError::Unreadable(format!(
            "{PLUGIN_NAME}: failed to open spool file '{}': {error}",
            path.display()
        ))
    })?;
    let encoded_len = file
        .metadata()
        .map_err(|error| {
            SpoolDecodeError::Unreadable(format!(
                "{PLUGIN_NAME}: failed to stat spool file '{}': {error}",
                path.display()
            ))
        })?
        .len();
    if encoded_len > SPOOL_MAX_ARTIFACT_BYTES {
        return Err(SpoolDecodeError::Unreadable(format!(
            "{PLUGIN_NAME}: spool file '{}' exceeds the hard {SPOOL_MAX_ARTIFACT_BYTES}-byte artifact bound",
            path.display()
        )));
    }
    let compressed = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".ndjson.zst"));
    // An uncompressed artifact decodes to exactly its on-disk size. Treat a
    // zstd frame's declared content size only as a tighter bound: the header is
    // unauthenticated, so it must never bypass the decompression-ratio limit.
    let mut file = file;
    let decoded_bound = if compressed {
        let ratio_limit = spool_decompression_limit(encoded_len);
        match read_zstd_frame_content_size(&mut file, path)? {
            Some(declared) if declared <= SPOOL_MAX_ARTIFACT_BYTES => declared.min(ratio_limit),
            Some(declared) => {
                return Err(SpoolDecodeError::Unreadable(format!(
                    "{PLUGIN_NAME}: spool file '{}' declares a {declared}-byte decoded size above the hard {SPOOL_MAX_ARTIFACT_BYTES}-byte artifact bound",
                    path.display()
                )));
            }
            None => ratio_limit,
        }
    } else {
        encoded_len
    };
    let decoded_bound = usize::try_from(decoded_bound).map_err(|_| {
        SpoolDecodeError::Unreadable(format!(
            "{PLUGIN_NAME}: spool file '{}' decoded bound exceeds this platform's addressable size",
            path.display()
        ))
    })?;
    let text_reservation = ceiling.try_acquire(decoded_bound).ok_or_else(|| {
        SpoolDecodeError::CeilingExhausted(format!(
            "{PLUGIN_NAME}: spool replay deferred for '{}': {}",
            path.display(),
            PayloadMaterializationError::CeilingExhausted.reason()
        ))
    })?;

    let decoded = if compressed {
        decode_zstd_bounded(file, decoded_bound, path).map_err(SpoolDecodeError::Unreadable)?
    } else {
        read_spool_bytes_bounded(file, decoded_bound, path).map_err(SpoolDecodeError::Unreadable)?
    };
    let text = String::from_utf8(decoded).map_err(|error| {
        SpoolDecodeError::Unreadable(format!(
            "{PLUGIN_NAME}: spool file '{}' is not valid UTF-8 JSONEachRow: {error}",
            path.display()
        ))
    })?;
    // Charge only what the buffer really holds; `from_utf8` reuses the `Vec`
    // allocation, so `capacity` is the true retained size.
    text_reservation.shrink_to(text.capacity());

    let mut line_count = 0usize;
    for_each_spool_line(&text, |_, _| line_count = line_count.saturating_add(1));
    let index_bytes = line_count
        .checked_mul(SPOOL_INDEX_ENTRY_BYTES)
        .ok_or_else(|| {
            SpoolDecodeError::Unreadable(format!(
                "{PLUGIN_NAME}: spool file '{}' line index byte bound overflowed",
                path.display()
            ))
        })?;
    let index_reservation = ceiling.try_acquire(index_bytes).ok_or_else(|| {
        SpoolDecodeError::CeilingExhausted(format!(
            "{PLUGIN_NAME}: spool replay deferred for '{}': {}",
            path.display(),
            PayloadMaterializationError::CeilingExhausted.reason()
        ))
    })?;
    // `with_capacity` plus exactly `line_count` pushes never grows past the
    // reserved allocation.
    let mut lines: Vec<(usize, usize)> = Vec::with_capacity(line_count);
    for_each_spool_line(&text, |start, end| lines.push((start, end)));

    Ok(ReservedSpoolArtifact {
        text,
        lines,
        _text_reservation: text_reservation,
        _index_reservation: index_reservation,
    })
}

/// Bytes of a zstd frame prefix that always contain the complete frame header.
///
/// A zstd frame header is at most 18 bytes (4-byte magic + 14-byte header).
const ZSTD_FRAME_HEADER_PROBE_BYTES: usize = 18;

/// Read the declared decompressed size from a zstd frame header, leaving the
/// file positioned back at byte zero for the streaming decoder.
///
/// Returns `Ok(None)` when the frame carries no content size (a foreign archive,
/// or one produced by a streaming encoder), in which case the caller falls back
/// to the ratio clamp. A corrupt header is not diagnosed here: the streaming
/// decoder reports it with its existing quarantine path.
fn read_zstd_frame_content_size(
    file: &mut File,
    path: &Path,
) -> Result<Option<u64>, SpoolDecodeError> {
    let seek_error = |error: std::io::Error| {
        SpoolDecodeError::Unreadable(format!(
            "{PLUGIN_NAME}: failed to read spool file '{}' frame header: {error}",
            path.display()
        ))
    };
    let mut header = [0u8; ZSTD_FRAME_HEADER_PROBE_BYTES];
    let mut filled = 0usize;
    while filled < header.len() {
        let Some(spare) = header.get_mut(filled..) else {
            break;
        };
        match file.read(spare) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(seek_error(error)),
        }
    }
    file.seek(SeekFrom::Start(0)).map_err(seek_error)?;
    let Some(prefix) = header.get(..filled) else {
        return Ok(None);
    };
    Ok(zstd::zstd_safe::get_frame_content_size(prefix)
        .ok()
        .flatten())
}

/// Decompress one spool record, failing closed past `limit` decoded bytes.
///
/// The caller quarantines an undecodable record to `<data-name>.corrupt` rather
/// than deleting it, so a rejected archive stays on disk for operator review.
fn spool_decompression_limit(encoded_len: u64) -> u64 {
    // `clamp` cannot panic here: both bounds are constants and
    // `SPOOL_MIN_DECOMPRESSED_BYTES` (1 MiB) is far below
    // `SPOOL_MAX_ARTIFACT_BYTES` (the retained-byte ceiling).
    encoded_len
        .saturating_mul(SPOOL_MAX_DECOMPRESSION_RATIO)
        .clamp(SPOOL_MIN_DECOMPRESSED_BYTES, SPOOL_MAX_ARTIFACT_BYTES)
}

/// Make one writer-owned zstd artifact satisfy the same expansion-ratio bound
/// replay applies to untrusted files.
///
/// Zstd skippable frames are explicitly ignored by decoders but count toward
/// the on-disk encoded length. Appending a zero-filled skippable frame therefore
/// preserves the decoded JSON exactly while preventing an unusually
/// compressible legitimate batch from becoming an artifact replay would
/// quarantine. A local actor who removes the padding only makes the file fail
/// closed at replay.
fn pad_zstd_to_replay_ratio(
    buffer: &mut [u8],
    encoded_len: usize,
    decoded_len: u64,
) -> Result<usize, String> {
    let encoded_len_u64 = u64::try_from(encoded_len)
        .map_err(|_| format!("{PLUGIN_NAME}: zstd encoded length exceeds u64"))?;
    if decoded_len <= spool_decompression_limit(encoded_len_u64) {
        return Ok(encoded_len);
    }

    const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
    const SKIPPABLE_HEADER_BYTES: usize = 8;

    let required_encoded_len = decoded_len.div_ceil(SPOOL_MAX_DECOMPRESSION_RATIO);
    let required_encoded_len = usize::try_from(required_encoded_len)
        .map_err(|_| format!("{PLUGIN_NAME}: zstd ratio padding length exceeds this platform"))?;
    let final_len = required_encoded_len.max(
        encoded_len
            .checked_add(SKIPPABLE_HEADER_BYTES)
            .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding length overflowed"))?,
    );
    let padding = buffer.get_mut(encoded_len..final_len).ok_or_else(|| {
        format!("{PLUGIN_NAME}: reserved zstd buffer is too small for ratio padding")
    })?;
    let payload_len = padding
        .len()
        .checked_sub(SKIPPABLE_HEADER_BYTES)
        .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding header is incomplete"))?;
    let payload_len = u32::try_from(payload_len)
        .map_err(|_| format!("{PLUGIN_NAME}: zstd ratio padding payload is too large"))?;
    {
        let header = padding
            .get_mut(..SKIPPABLE_HEADER_BYTES)
            .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding header is incomplete"))?;
        let magic = header
            .get_mut(..4)
            .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding magic is incomplete"))?;
        magic.copy_from_slice(&SKIPPABLE_MAGIC.to_le_bytes());
        let size = header
            .get_mut(4..SKIPPABLE_HEADER_BYTES)
            .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding size is incomplete"))?;
        size.copy_from_slice(&payload_len.to_le_bytes());
    }
    let payload = padding
        .get_mut(SKIPPABLE_HEADER_BYTES..)
        .ok_or_else(|| format!("{PLUGIN_NAME}: zstd ratio padding payload is missing"))?;
    payload.fill(0);
    let final_len_u64 = u64::try_from(final_len)
        .map_err(|_| format!("{PLUGIN_NAME}: padded zstd length exceeds u64"))?;
    if decoded_len > spool_decompression_limit(final_len_u64) {
        return Err(format!(
            "{PLUGIN_NAME}: zstd ratio padding did not satisfy the replay bound"
        ));
    }
    Ok(final_len)
}

/// Read at most `limit` bytes, growing geometrically but never allocating past
/// `limit`.
///
/// The caller has already reserved `limit` against the retained-byte ceiling, so
/// the buffer must not overshoot it — which rules out `read_to_end`, whose
/// amortized growth can allocate roughly twice the bytes actually read.
fn read_spool_bytes_bounded(
    mut reader: impl Read,
    limit: usize,
    path: &Path,
) -> Result<Vec<u8>, String> {
    let read_error = |error: std::io::Error| {
        format!(
            "{PLUGIN_NAME}: failed to read spool file '{}': {error}",
            path.display()
        )
    };
    let mut decoded: Vec<u8> = Vec::new();
    let mut filled = 0usize;
    loop {
        if filled == decoded.len() {
            if filled >= limit {
                // One probe byte past the bound: anything still readable means
                // the artifact exceeds the reservation, so fail closed.
                let mut probe = [0u8; 1];
                return match reader.read(&mut probe) {
                    Ok(0) => {
                        decoded.truncate(filled);
                        Ok(decoded)
                    }
                    Ok(_) => Err(format!(
                        "{PLUGIN_NAME}: spool file '{}' exceeds its {limit}-byte artifact bound",
                        path.display()
                    )),
                    Err(error) => Err(read_error(error)),
                };
            }
            let target = filled
                .max(SPOOL_DECODE_CHUNK_BYTES)
                .saturating_mul(2)
                .min(limit);
            // `reserve_exact` (not `resize`'s amortized `reserve`) keeps the
            // real capacity from overshooting `limit`, which is what the caller
            // reserved: an amortized doubling past the bound would leave the
            // buffer's true allocation undercharged.
            decoded.reserve_exact(target.saturating_sub(decoded.len()));
            decoded.resize(target, 0);
        }
        let Some(spare) = decoded.get_mut(filled..) else {
            break;
        };
        match reader.read(spare) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(read_error(error)),
        }
    }
    decoded.truncate(filled);
    Ok(decoded)
}

fn decode_zstd_bounded(reader: impl Read, limit: usize, path: &Path) -> Result<Vec<u8>, String> {
    let decoder = zstd::stream::read::Decoder::new(reader).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to open spool file '{}' for decompression: {error}",
            path.display()
        )
    })?;
    read_spool_bytes_bounded(decoder, limit, path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: spool file '{}' exceeded its decompression bound: {error}",
            path.display()
        )
    })
}

/// Decode-only helper for external unit tests. The returned `String` outlives
/// its ceiling reservation, which is exactly why production never uses this
/// shape: [`decode_spool_artifact`] keeps the charge for the buffer's life.
#[allow(dead_code)]
pub fn decode_spool_file_for_tests(path: &Path) -> Result<String, String> {
    decode_spool_artifact(path, process_ceiling())
        .map(ReservedSpoolArtifact::into_text)
        .map_err(SpoolDecodeError::into_message)
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn spool_artifact_byte_limit_for_tests() -> u64 {
    SPOOL_MAX_ARTIFACT_BYTES
}

/// Proven peak replay retention for an artifact, exposed so external tests can
/// assert the writer-side liveness admission bound is the same arithmetic.
#[doc(hidden)]
#[allow(dead_code)]
pub fn spool_replay_peak_bytes_for_tests(decoded_bound: u64, line_count: usize) -> Option<u64> {
    spool_replay_peak_bytes(decoded_bound, line_count)
}

/// Reserved capacity of the 413 split worklist.
#[doc(hidden)]
#[allow(dead_code)]
pub fn spool_split_worklist_max_entries_for_tests() -> usize {
    SPOOL_SPLIT_WORKLIST_MAX_ENTRIES
}

/// Bytes one spool line-index / worklist entry occupies.
#[doc(hidden)]
#[allow(dead_code)]
pub fn spool_index_entry_bytes_for_tests() -> usize {
    SPOOL_INDEX_ENTRY_BYTES
}

/// Deterministic compact-recovery probe for external unit tests.
///
/// Builds a [`CompactSnapshotRecovery`] that owns `events` under a reservation
/// against `ceiling`, runs one retry that cannot reach a spool, and reports
/// `(reserved_bound, held_after_failed_retry, pending_events_after_failed_retry,
/// ceiling_used_after_drop)`.
///
/// This is the ownership contract compaction relies on: the retry never clones
/// the pending set, a failed retry restores every pending delta, and the
/// reservation is released exactly once when the recovery is dropped.
#[doc(hidden)]
#[allow(dead_code)]
pub fn probe_compact_recovery_retry_for_tests(
    ceiling: &'static RetainedByteCeiling,
    events: Vec<ChargeEvent>,
) -> Result<(usize, usize, usize, usize), String> {
    let retained_bytes = events
        .iter()
        .map(charge_event_retained_bytes)
        .fold(0usize, usize::saturating_add);
    let reservation = GrowableProcessReservation::new(ceiling);
    if !reservation.try_grow(retained_bytes) {
        return Err(format!(
            "{PLUGIN_NAME}: {}",
            PayloadMaterializationError::CeilingExhausted.reason()
        ));
    }
    let recovery = CompactSnapshotRecovery {
        generation: 1,
        plugin_config_id: Arc::from("probe"),
        attempt_lock: Mutex::new(()),
        events: Mutex::new(events),
        retained_bytes,
        _reservation: reservation,
        closed_at: Instant::now(),
        // No spool: `try_spool` must fail and restore every pending delta.
        spool: None,
        metrics: Arc::new(SinkMetrics::default()),
    };
    let durable = recovery.try_spool();
    if durable {
        return Err(format!(
            "{PLUGIN_NAME}: probe expected a failed compact recovery handoff"
        ));
    }
    let held = ceiling.used();
    let pending = match recovery.events.lock() {
        Ok(guard) => guard.len(),
        Err(poisoned) => poisoned.into_inner().len(),
    };
    drop(recovery);
    Ok((retained_bytes, held, pending, ceiling.used()))
}

/// Opaque compact-recovery handle for deterministic external concurrency tests.
#[doc(hidden)]
#[allow(dead_code)]
pub struct CompactRecoveryProbe {
    recovery: CompactSnapshotRecovery,
}

#[allow(dead_code)]
impl CompactRecoveryProbe {
    /// Run one synchronous retry through the production take/write/restore path.
    #[doc(hidden)]
    pub fn try_spool_for_tests(&self) -> bool {
        self.recovery.try_spool()
    }

    /// Pending deltas currently owned by the recovery.
    #[doc(hidden)]
    pub fn pending_len_for_tests(&self) -> usize {
        match self.recovery.events.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

/// Build a compact recovery backed by a real spool for deterministic external
/// concurrency tests.
#[doc(hidden)]
#[allow(dead_code)]
pub fn compact_recovery_probe_for_tests(
    ceiling: &'static RetainedByteCeiling,
    events: Vec<ChargeEvent>,
    spool: SpoolManager,
) -> Result<CompactRecoveryProbe, String> {
    let retained_bytes = events
        .iter()
        .map(charge_event_retained_bytes)
        .fold(0usize, usize::saturating_add);
    let reservation = GrowableProcessReservation::new(ceiling);
    if !reservation.try_grow(retained_bytes) {
        return Err(format!(
            "{PLUGIN_NAME}: {}",
            PayloadMaterializationError::CeilingExhausted.reason()
        ));
    }
    Ok(CompactRecoveryProbe {
        recovery: CompactSnapshotRecovery {
            generation: 1,
            plugin_config_id: Arc::from("concurrency-probe"),
            attempt_lock: Mutex::new(()),
            events: Mutex::new(events),
            retained_bytes,
            _reservation: reservation,
            closed_at: Instant::now(),
            spool: Some(Arc::new(spool)),
            metrics: Arc::new(SinkMetrics::default()),
        },
    })
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn spool_decompression_limit_for_tests(encoded_len: u64) -> u64 {
    spool_decompression_limit(encoded_len)
}

#[doc(hidden)]
#[allow(dead_code)]
pub async fn replay_spool_once_for_tests(
    spool: &SpoolManager,
    insert_url: &str,
) -> Result<(), String> {
    replay_spool_once_with_batch_size_for_tests(spool, insert_url, default_batch_size()).await
}

#[doc(hidden)]
#[allow(dead_code)]
pub async fn replay_spool_once_with_batch_size_for_tests(
    spool: &SpoolManager,
    insert_url: &str,
    batch_size: usize,
) -> Result<(), String> {
    replay_spool_once_with_ceiling_for_tests(spool, insert_url, batch_size, process_ceiling()).await
}

/// Replay one tick against a test-owned retained-byte ceiling, so ownership and
/// refusal assertions stay exact while other tests in the same binary reserve
/// against the process-global counter.
#[doc(hidden)]
#[allow(dead_code)]
pub async fn replay_spool_once_with_ceiling_for_tests(
    spool: &SpoolManager,
    insert_url: &str,
    batch_size: usize,
    ceiling: &'static RetainedByteCeiling,
) -> Result<(), String> {
    let flush_config = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: insert_url.to_string(),
        redacted_insert_url: redacted_endpoint_url_str(insert_url),
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        metrics: Arc::clone(&spool.metrics),
        ceiling,
        projection: spool.projection.clone(),
    };
    replay_spool_once(spool, &flush_config, batch_size.max(1)).await
}

/// Deterministic body-materialization probe for external unit tests.
///
/// Returns `(provisional_bound, ceiling_used_while_body_held, ceiling_used_after_drop)`,
/// or `Err` when the ceiling refused the body before it was serialized.
///
/// `ceiling_used_while_body_held` is the **exact** retained charge after the
/// provisional escaping/framing reservation has been shrunk to the buffer's
/// capacity — not the provisional bound.
#[doc(hidden)]
#[allow(dead_code)]
pub fn probe_charge_body_materialization_for_tests(
    ceiling: &'static RetainedByteCeiling,
    batch: &[ChargeEvent],
) -> Result<(usize, usize, usize), String> {
    probe_charge_body_materialization_with_projection_for_tests(ceiling, batch, None)
}

/// [`probe_charge_body_materialization_for_tests`] under a compiled projection,
/// so a schema's provisional reservation bound can be asserted to still precede
/// — and cover — the projected serialization, while the held charge reflects
/// the exact retained body allocation.
#[doc(hidden)]
#[allow(dead_code)]
pub fn probe_charge_body_materialization_with_projection_for_tests(
    ceiling: &'static RetainedByteCeiling,
    batch: &[ChargeEvent],
    projection: Option<Arc<ChargeEventProjection>>,
) -> Result<(usize, usize, usize), String> {
    let metrics = Arc::new(SinkMetrics::default());
    let cfg = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: "http://127.0.0.1/".to_string(),
        redacted_insert_url: "http://127.0.0.1/redacted".to_string(),
        username: None,
        password: None,
        timeout: Duration::from_secs(1),
        metrics,
        ceiling,
        projection: projection.clone(),
    };
    let bound = charge_body_byte_bound(batch, projection.as_deref())
        .ok_or_else(|| format!("{PLUGIN_NAME}: bound overflowed"))?;
    let body = materialize_charge_body(&cfg, batch)?;
    let held = ceiling.used();
    drop(body);
    Ok((bound, held, ceiling.used()))
}

/// Deliver `batch` against `insert_url` while reporting the exact body charge
/// observed before the request returns and after the payload is released.
///
/// Returns `(held_while_in_flight, ceiling_used_after_delivery)`. The in-flight
/// observation is taken after materialization and before `post_json_each_row`
/// returns, so a slow ClickHouse acknowledgement keeps the exact body charge
/// visible for the whole request lifetime. Cancellation, success, and error
/// paths all release through `ReservedPayload`'s drop.
#[doc(hidden)]
#[allow(dead_code)]
pub async fn probe_charge_body_delivery_retention_for_tests(
    ceiling: &'static RetainedByteCeiling,
    batch: Vec<ChargeEvent>,
    insert_url: &str,
) -> Result<(usize, usize), String> {
    let metrics = Arc::new(SinkMetrics::default());
    let cfg = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: insert_url.to_string(),
        redacted_insert_url: redacted_endpoint_url_str(insert_url),
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        metrics,
        ceiling,
        projection: None,
    };
    let event_count = batch.len();
    let body = materialize_charge_body(&cfg, &batch)?;
    drop(batch);
    let held_while_in_flight = ceiling.used();
    let _ = post_json_each_row(&cfg, body, event_count).await;
    Ok((held_while_in_flight, ceiling.used()))
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn classify_clickhouse_http_status_for_tests(status: u16) -> &'static str {
    // Status-only helper for non-success paths. HTTP 200/204 durable success
    // additionally requires a complete empty acknowledgement body with no
    // exception header; see classify_clickhouse_acknowledgement_for_tests.
    match status {
        200 | 204 => "delivered",
        413 => "payload_too_large",
        401 | 403 | 408 | 429 => "retryable",
        code if (500..600).contains(&code) => "retryable",
        code if (400..500).contains(&code) => "permanent",
        _ => "retryable",
    }
}

/// Classify a ClickHouse acknowledgement the same way production delivery does.
///
/// `body = None` models an incomplete/ambiguous drain. `body = Some(b"")` is the
/// durable success shape for HTTP 200/204. Exception markers and
/// `X-ClickHouse-Exception-Code` never appear in returned labels or messages
/// beyond bounded reason classes.
#[doc(hidden)]
#[allow(dead_code)]
pub fn classify_clickhouse_acknowledgement_for_tests(
    status: u16,
    body: Option<&[u8]>,
    has_exception_code_header: bool,
) -> &'static str {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let ack = match body {
        Some(bytes) => ClickHouseAckRead::Complete {
            byte_len: bytes.len() as u64,
            has_exception: body_has_clickhouse_exception(bytes),
        },
        None => ClickHouseAckRead::Incomplete {
            kind: ClickHouseAckIncomplete::TransportFailure,
        },
    };
    let metrics = Arc::new(SinkMetrics::default());
    let cfg = ClickHouseFlushConfig {
        http: ClickHouseHttpClient::Dedicated(reqwest::Client::new()),
        insert_url: "http://127.0.0.1/".to_string(),
        redacted_insert_url: "http://127.0.0.1/redacted".to_string(),
        username: None,
        password: None,
        timeout: Duration::from_secs(1),
        metrics,
        ceiling: process_ceiling(),
        projection: None,
    };
    classify_clickhouse_delivery(
        &cfg,
        status,
        ack,
        has_exception_code_header,
        1,
        Duration::from_millis(1),
    )
    .label()
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn clickhouse_insert_url_for_tests(config: &ApiChargebackSinkConfig) -> Result<String, String> {
    let base = Url::parse(&config.clickhouse.url)
        .map_err(|err| format!("invalid ClickHouse URL: {err}"))?;
    Ok(build_insert_url(&base, &config.clickhouse))
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn write_private_file_atomically_for_tests(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
    ownership: SpoolFinalOwnership,
) -> Result<(), String> {
    let ops = SpoolFsOps::REAL;
    write_private_file_atomically_with_ops(tmp_path, final_path, bytes, ops, ownership)
}

/// Exercise the durable-write contract with one step forced to fail.
#[doc(hidden)]
#[allow(dead_code)] // external unit tests only
pub fn write_private_file_atomically_with_fault_for_tests(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
    fault: SpoolFsFault,
    ownership: SpoolFinalOwnership,
) -> Result<(), String> {
    let ops = SpoolFsOps::with_fault(fault);
    write_private_file_atomically_with_ops(tmp_path, final_path, bytes, ops, ownership)
}

fn write_private_file_atomically_with_ops(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
    ops: SpoolFsOps,
    ownership: SpoolFinalOwnership,
) -> Result<(), String> {
    let result = write_private_file_atomically_inner(tmp_path, final_path, bytes, ops);
    let Err(primary_error) = result else {
        return Ok(());
    };

    // Keep quota accounting honest and make rollback as durable as the
    // filesystem permits after a failed write, rename, or directory sync. A
    // second real parent-directory fsync persists successful cleanup even when
    // the injected or first production sync failed. If cleanup itself cannot be
    // completed, preserve that evidence in the returned error rather than
    // claiming a guaranteed rollback.
    let mut cleanup_errors = Vec::new();
    // Every temp this helper is given is derived from a name only this attempt
    // can be writing: a fresh ULID for data batches, the
    // `*.write-<process_tag>-<generation>.tmp` attribution for the shared
    // manifest, and the claimed source artifact's ULID for dead-letter metadata.
    // Unlinking it can therefore only discard this attempt's own bytes.
    match fs::remove_file(tmp_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => cleanup_errors.push(format!(
            "failed to remove rollback path '{}': {error}",
            tmp_path.display()
        )),
    }
    // `final_path`, unlike the temp, is not always this attempt's to delete.
    //
    // For a [`SpoolFinalOwnership::Unique`] name — a ULID-derived data batch or
    // its dead-letter metadata — no other writer can publish to that path, so
    // the only entry an unlink can destroy is this attempt's own unsynced
    // publication. Roll it back, and report a cleanup failure rather than
    // claiming a guaranteed rollback.
    //
    // For a [`SpoolFinalOwnership::Shared`] name — `spool.meta.json`, one
    // well-known path for every writer of the namespace — the unlink is skipped
    // entirely. There is no way to make "this entry is still the file I renamed"
    // atomic with the unlink that acts on it: a peer's `rename` can replace the
    // name between any check and the removal, so stat-then-unlink (by inode or
    // otherwise), content comparison, and timestamp comparison would all still
    // permit deleting a peer's newer publication. An in-process lock does not
    // help either, since peers are separate processes on a shared volume.
    //
    // Skipping it can leave a manifest whose directory entry was never fsynced,
    // or whose bytes replaced a peer's. That is recoverable: the durability
    // error is still returned, live storage is never marked prepared, and the
    // next prepare validates the manifest against this sink's identity and
    // regenerates or fails closed on it. Deleting a peer's publication is not
    // recoverable, so the residual is deliberately pushed to the safe side.
    if ownership == SpoolFinalOwnership::Unique {
        match fs::remove_file(final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => cleanup_errors.push(format!(
                "failed to remove rollback path '{}': {error}",
                final_path.display()
            )),
        }
    }
    #[cfg(unix)]
    if let Some(parent) = final_path.parent() {
        match File::open(parent) {
            Ok(dir) => {
                if let Err(error) = dir.sync_all() {
                    cleanup_errors.push(format!(
                        "failed to fsync rollback directory '{}': {error}",
                        parent.display()
                    ));
                }
            }
            Err(error) => cleanup_errors.push(format!(
                "failed to open rollback directory '{}': {error}",
                parent.display()
            )),
        }
    }
    if cleanup_errors.is_empty() {
        Err(primary_error)
    } else {
        Err(format!(
            "{primary_error}; rollback cleanup also failed: {}",
            cleanup_errors.join("; ")
        ))
    }
}

/// Publish `bytes` at `final_path` durably: private temp, write, fsync, rename,
/// parent-directory fsync. Rollback of a partial sequence is the caller's job.
fn write_private_file_atomically_inner(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
    ops: SpoolFsOps,
) -> Result<(), String> {
    if let Some(parent) = tmp_path.parent() {
        ensure_private_dir(parent)?;
    }
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp_path)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to create spool temp file '{}': {error}",
                tmp_path.display()
            )
        })?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to create spool temp file '{}': {error}",
                tmp_path.display()
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to write spool temp file '{}': {error}",
            tmp_path.display()
        )
    })?;
    (ops.sync_file)(&file, tmp_path)?;
    drop(file);
    (ops.rename)(tmp_path, final_path)?;
    // Test-only interleaving point: production wires this to a no-op, and the
    // fault-injection suite uses it to republish `final_path` as a peer would
    // before the directory fsync below fails.
    (ops.after_rename)(final_path);
    // Durably persist the rename itself. The file contents were fsynced above,
    // but the directory entry pointing at them is only guaranteed after an fsync
    // of the containing directory. On Unix a parent-directory open or fsync
    // failure is therefore a write failure: it is reported to the caller and the
    // publish is rolled back, before any snapshot baseline can advance.
    //
    // Directory fsync is a Unix concept. On platforms without it (notably
    // Windows) a successful file sync plus rename is the durability boundary
    // this plugin can offer, and the documentation states that limit rather than
    // claiming a guarantee the platform does not provide. Both platforms run the
    // same fault-injection contract tests.
    #[cfg(unix)]
    {
        let Some(parent) = final_path.parent() else {
            return Ok(());
        };
        let dir = (ops.open_dir)(parent)?;
        (ops.sync_dir)(&dir, parent)?;
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    // Refuse a pre-existing symlink before `create_dir_all` or chmod can follow
    // it, then lstat again after creation to close the ordinary check/create
    // race as far as path-based filesystem APIs permit.
    reject_symlinked_spool_path(path)?;
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to create spool directory '{}': {error}",
            path.display()
        )
    })?;
    reject_symlinked_spool_path(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "{PLUGIN_NAME}: failed to set permissions on spool directory '{}': {error}",
                path.display()
            )
        })?;
    }
    // A fixed `create + truncate` probe lets a same-UID actor pre-plant a
    // symlink and redirect truncation outside the managed tree. Use an
    // unpredictable name and `create_new` so an existing path of any type is
    // never followed.
    let probe = path.join(format!(".ferrum-write-test-{}.tmp", new_ulid()));
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: spool directory '{}' is not writable: {error}",
                path.display()
            )
        })?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|error| {
            format!(
                "{PLUGIN_NAME}: spool directory '{}' is not writable: {error}",
                path.display()
            )
        })?;
    if let Err(error) = file.write_all(b"ok") {
        drop(file);
        let _ = fs::remove_file(&probe);
        return Err(format!(
            "{PLUGIN_NAME}: spool directory '{}' write probe failed: {error}",
            path.display()
        ));
    }
    drop(file);
    fs::remove_file(&probe).map_err(|error| {
        format!(
            "{PLUGIN_NAME}: failed to remove spool directory write probe '{}': {error}",
            probe.display()
        )
    })?;
    Ok(())
}

fn start_spool_replayer(
    spool: Arc<SpoolManager>,
    _summary: SinkSummary,
    flush_config: ClickHouseFlushConfig,
    batch_size: usize,
    replay_interval_secs: u64,
    commit_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let batch_size = batch_size.max(1);
    tokio::spawn(async move {
        if !wait_until_committed(commit_rx).await {
            return;
        }
        let mut timer = tokio::time::interval(Duration::from_secs(replay_interval_secs));
        loop {
            timer.tick().await;
            if let Err(error) = spool.prepare_live_storage() {
                warn!(
                    plugin = PLUGIN_NAME,
                    error = %error,
                    "Chargeback sink live spool preparation failed"
                );
                continue;
            }
            if let Err(error) = replay_spool_once(&spool, &flush_config, batch_size).await {
                warn!(plugin = PLUGIN_NAME, error = %error, "Chargeback sink spool replay failed");
            }
        }
    })
}

/// Replay one tick of this owner's durable spool files.
///
/// Each candidate is atomically claimed before it is read or delivered, so an
/// overlapping accepted generation, a reloaded replacement generation, or a peer
/// process sharing the volume can never deliver or destroy the same file. Losing
/// the claim race is normal and simply skips that file. Quota eviction never
/// selects a claimed file, so a retryable failure can always release the claim
/// back to a durable name.
async fn replay_spool_once(
    spool: &SpoolManager,
    flush_config: &ClickHouseFlushConfig,
    batch_size: usize,
) -> Result<(), String> {
    let files = spool.list_replayable_spool_files()?;
    for file in files {
        let mut claim = {
            let _guard = spool
                .write_lock
                .lock()
                .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
            match spool.claim_replay_file_locked(&file)? {
                Some(claim) => claim,
                // Another accepted generation or process won the atomic claim.
                None => continue,
            }
        };
        let inflight = claim.path().to_path_buf();
        let artifact = match decode_spool_artifact(&inflight, flush_config.ceiling) {
            Ok(artifact) => artifact,
            Err(SpoolDecodeError::CeilingExhausted(error)) => {
                // The artifact is fine; the process is at its retained-byte
                // ceiling. Quarantining here would destroy a healthy record, so
                // release the claim and stop the tick, exactly as for a
                // retryable delivery failure.
                spool
                    .metrics
                    .record_failure(FailureReason::Serialize, error.clone());
                let _guard = spool
                    .write_lock
                    .lock()
                    .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
                spool.release_claim_locked(claim.path())?;
                return Err(error);
            }
            Err(SpoolDecodeError::Unreadable(error)) => {
                spool
                    .metrics
                    .record_failure(FailureReason::Serialize, error.clone());
                match quarantine_spool_file(spool, &inflight) {
                    Ok(quarantine_path) => {
                        warn!(
                            plugin = PLUGIN_NAME,
                            error = %error,
                            path = %inflight.display(),
                            quarantine_path = %quarantine_path.display(),
                            "Chargeback sink quarantined an unreadable spool file and will continue replay"
                        );
                    }
                    Err(quarantine_error) => {
                        warn!(
                            plugin = PLUGIN_NAME,
                            error = %error,
                            quarantine_error = %quarantine_error,
                            path = %inflight.display(),
                            "Chargeback sink could not quarantine an unreadable spool file; replay will continue"
                        );
                    }
                }
                continue;
            }
        };
        let line_count = artifact.line_count();
        if line_count == 0 {
            spool.remove_delivered_claim(claim.path())?;
            continue;
        }

        match replay_spool_lines(spool, &mut claim, flush_config, &artifact, batch_size).await {
            Ok(dead_letters) => {
                if let Err(error) =
                    finalize_replayed_spool_file(spool, claim.path(), line_count, dead_letters)
                {
                    // Permanent rejection could not publish dead-letter metadata.
                    // Release the claim so the original record remains
                    // replayable: durability of the payload outranks quarantine
                    // progress when the sidecar write fails.
                    let _guard = spool
                        .write_lock
                        .lock()
                        .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
                    spool.release_claim_locked(claim.path())?;
                    return Err(error);
                }
                spool
                    .metrics
                    .last_replay_at
                    .store(unix_timestamp_seconds(), Ordering::Relaxed);
                invalidate_status_cache();
            }
            Err(error) => {
                // Retryable delivery failure: release the claim back to a durable
                // replayable name and stop the tick so ordering is preserved
                // across transient outages.
                let _guard = spool
                    .write_lock
                    .lock()
                    .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
                spool.release_claim_locked(claim.path())?;
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Lowest HTTP status code the dead-letter tally addresses directly.
const DEAD_LETTER_STATUS_BASE: u16 = 100;
/// Number of directly addressed HTTP status codes (100..=999). `http`'s
/// `StatusCode` admits exactly this range, so the tally is lossless for every
/// status a real response can carry.
const DEAD_LETTER_STATUS_SPAN: usize = 900;

/// Fixed-size dead-letter accounting for one replayed artifact.
///
/// Replay previously pushed one record per permanently rejected row, so an
/// artifact with an attacker-controlled row count grew an uncharged `O(rows)`
/// vector while the decoded artifact, its line index, and a request body were
/// all still retained. This aggregate is the same size — one counter per
/// addressable status plus two scalars — no matter how many rows are rejected,
/// and it preserves the exact per-status row counts the sidecar metadata
/// records.
struct DeadLetterTally {
    payload_too_large_rows: usize,
    permanent_rows_by_status: Box<[usize; DEAD_LETTER_STATUS_SPAN]>,
    /// Rows rejected with a status outside the addressable range. Recorded
    /// without a status rather than dropped.
    permanent_rows_unclassified: usize,
}

impl DeadLetterTally {
    fn new() -> Self {
        Self {
            payload_too_large_rows: 0,
            permanent_rows_by_status: Box::new([0usize; DEAD_LETTER_STATUS_SPAN]),
            permanent_rows_unclassified: 0,
        }
    }

    fn record_payload_too_large(&mut self, rows: usize) {
        self.payload_too_large_rows = self.payload_too_large_rows.saturating_add(rows);
    }

    fn record_permanent(&mut self, status: u16, rows: usize) {
        let slot = status
            .checked_sub(DEAD_LETTER_STATUS_BASE)
            .map(usize::from)
            .and_then(|index| self.permanent_rows_by_status.get_mut(index));
        match slot {
            Some(counter) => *counter = counter.saturating_add(rows),
            None => {
                self.permanent_rows_unclassified =
                    self.permanent_rows_unclassified.saturating_add(rows);
            }
        }
    }

    fn rejected_rows(&self) -> usize {
        self.permanent_rows_by_status
            .iter()
            .copied()
            .fold(self.payload_too_large_rows, usize::saturating_add)
            .saturating_add(self.permanent_rows_unclassified)
    }

    fn is_empty(&self) -> bool {
        self.rejected_rows() == 0
    }

    /// Expand into sidecar metadata rows. Bounded by the addressable status
    /// span, never by the artifact's row count.
    fn into_outcomes(self) -> Vec<DeadLetterOutcomeMeta> {
        let mut outcomes = Vec::new();
        if self.payload_too_large_rows > 0 {
            outcomes.push(DeadLetterOutcomeMeta {
                reason: DeadLetterReason::PayloadTooLarge.as_str(),
                http_status: Some(413),
                row_count: self.payload_too_large_rows,
            });
        }
        for (index, row_count) in self.permanent_rows_by_status.iter().copied().enumerate() {
            if row_count == 0 {
                continue;
            }
            let status = u16::try_from(index)
                .ok()
                .and_then(|offset| offset.checked_add(DEAD_LETTER_STATUS_BASE));
            outcomes.push(DeadLetterOutcomeMeta {
                reason: DeadLetterReason::PermanentHttp.as_str(),
                http_status: status,
                row_count,
            });
        }
        if self.permanent_rows_unclassified > 0 {
            outcomes.push(DeadLetterOutcomeMeta {
                reason: DeadLetterReason::PermanentHttp.as_str(),
                http_status: None,
                row_count: self.permanent_rows_unclassified,
            });
        }
        outcomes
    }
}

/// Deliver spool JSONEachRow lines with status-aware split / dead-letter policy.
///
/// On retryable failure returns `Err` and leaves caller-owned durable state
/// unchanged. Permanent rejection and single-row 413 become dead-letter chunks.
/// Multi-row 413 splits deterministically using `batch_size` without rewriting
/// row payloads (event_id and other fields stay byte-identical).
async fn replay_spool_lines(
    spool: &SpoolManager,
    claim: &mut SpoolClaimHandle,
    flush_config: &ClickHouseFlushConfig,
    artifact: &ReservedSpoolArtifact,
    batch_size: usize,
) -> Result<DeadLetterTally, String> {
    let mut tally = DeadLetterTally::new();
    // The worklist addresses chunks by *line index range*, so neither a chunk
    // nor a 413 split ever copies a row: every attempt borrows straight out of
    // the artifact's single decoded buffer.
    //
    // Its whole allocation is reserved before it exists, and is now proportional
    // to real live stack occupancy instead of to the artifact's
    // attacker-controlled row count — see [`SPOOL_SPLIT_WORKLIST_MAX_ENTRIES`]
    // for the bound and its proof. Exceeding the bound is a fail-closed
    // retryable error rather than an unreserved reallocation, so the reservation
    // can never under-cover the allocation.
    let line_count = artifact.line_count();
    let worklist_bytes = SPOOL_SPLIT_WORKLIST_MAX_ENTRIES
        .checked_mul(SPOOL_INDEX_ENTRY_BYTES)
        .ok_or_else(|| format!("{PLUGIN_NAME}: spool replay worklist byte bound overflowed"))?;
    let _worklist_reservation = flush_config
        .ceiling
        .try_acquire(worklist_bytes)
        .ok_or_else(|| {
            format!(
                "{PLUGIN_NAME}: spool replay deferred: {}",
                PayloadMaterializationError::CeilingExhausted.reason()
            )
        })?;
    let mut stack: Vec<(usize, usize)> = Vec::with_capacity(SPOOL_SPLIT_WORKLIST_MAX_ENTRIES);
    stack.push((0, line_count));
    while let Some((start, end)) = stack.pop() {
        let Some(rows) = end.checked_sub(start).filter(|rows| *rows > 0) else {
            continue;
        };
        {
            let _guard = spool
                .write_lock
                .lock()
                .map_err(|_| format!("{PLUGIN_NAME}: spool writer lock is poisoned"))?;
            spool.renew_claim_locked(claim)?;
        }
        let body = materialize_spool_chunk_body(flush_config.ceiling, artifact, start, end)?;
        match post_json_each_row(flush_config, body, rows).await {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::Retryable { message } => return Err(message),
            DeliveryOutcome::PayloadTooLarge { .. } => {
                if rows == 1 {
                    tally.record_payload_too_large(1);
                } else {
                    if stack.len().saturating_add(2) > SPOOL_SPLIT_WORKLIST_MAX_ENTRIES {
                        return Err(format!(
                            "{PLUGIN_NAME}: spool replay split worklist exceeded its reserved {SPOOL_SPLIT_WORKLIST_MAX_ENTRIES}-entry bound"
                        ));
                    }
                    let split_at = start.saturating_add(replay_split_len(rows, batch_size));
                    // Stack: push right first so left is delivered first.
                    stack.push((split_at, end));
                    stack.push((start, split_at));
                }
            }
            DeliveryOutcome::Permanent { status, .. } => {
                tally.record_permanent(status, rows);
            }
        }
    }
    Ok(tally)
}

/// Serialize the `[start, end)` line range into a reserved-and-charged
/// JSONEachRow body.
///
/// Rows are written verbatim out of the artifact's decoded buffer, so the bound
/// (row bytes plus one separator each) is exact and no row is ever copied
/// outside the reserved payload. A ceiling refusal is reported as a retryable
/// error, which leaves the durable claim untouched for a later tick.
fn materialize_spool_chunk_body(
    ceiling: &'static RetainedByteCeiling,
    artifact: &ReservedSpoolArtifact,
    start: usize,
    end: usize,
) -> Result<ReservedPayload, String> {
    let mut bound = end.saturating_sub(start);
    for index in start..end {
        bound = bound
            .checked_add(artifact.line(index)?.len())
            .ok_or_else(|| format!("{PLUGIN_NAME}: spool replay body byte bound overflowed"))?;
    }
    materialize_reserved_payload(ceiling, bound, |writer| {
        for index in start..end {
            if index > start {
                writer
                    .write_all(b"\n")
                    .map_err(|error| format!("row separator: {error}"))?;
            }
            writer
                .write_all(artifact.line(index)?.as_bytes())
                .map_err(|error| format!("row: {error}"))?;
        }
        Ok(())
    })
    .map_err(|error| {
        format!(
            "{PLUGIN_NAME}: spool replay body was not materialized: {}",
            error.reason()
        )
    })
}

fn finalize_replayed_spool_file(
    spool: &SpoolManager,
    file: &Path,
    original_row_count: usize,
    dead_letters: DeadLetterTally,
) -> Result<(), String> {
    if dead_letters.is_empty() {
        spool.remove_delivered_claim(file)?;
        return Ok(());
    }

    let rejected_rows = dead_letters.rejected_rows();
    if rejected_rows > original_row_count {
        return Err(format!(
            "{PLUGIN_NAME}: dead-letter row count ({rejected_rows}) exceeds source row count ({original_row_count})"
        ));
    }
    let outcomes = dead_letters.into_outcomes();
    let meta = DeadLetterMeta {
        rejected_rows,
        outcomes,
        quarantined_at_unix: unix_timestamp_seconds(),
    };
    let meta_path = write_dead_letter_meta(spool, file, &meta)?;
    warn!(
        plugin = PLUGIN_NAME,
        rejected_rows,
        source_rows = original_row_count,
        outcome_count = meta.outcomes.len(),
        path = %file.display(),
        meta_path = %meta_path.display(),
        "Chargeback sink recorded safe dead-letter metadata for permanently rejected spool rows and will continue replay"
    );
    Ok(())
}

/// Immutable categorical dimensions for one snapshot accumulator identity.
///
/// The complete value is the typed accumulator key and is also copied into
/// emitted `ChargeEvent`s. It must not be treated as first-writer-wins
/// decoration on a coarser or delimiter-encoded identity.
#[derive(Clone, Eq, Hash, PartialEq)]
struct SnapshotMetadata {
    namespace: String,
    consumer_id: String,
    consumer_name: Option<String>,
    proxy_id: String,
    proxy_name: String,
    route_id: Option<String>,
    status_code: u16,
    http_status_code: Option<u16>,
    grpc_status: Option<u32>,
    protocol: String,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct SnapshotTotals {
    pub call_count: u64,
    pub charge_call: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub charge_bytes_sent: f64,
    pub charge_bytes_received: f64,
    pub charge_total: f64,
}

impl SnapshotTotals {
    fn delta_since(self, last: SnapshotTotals) -> Result<SnapshotTotals, String> {
        Ok(SnapshotTotals {
            call_count: self.call_count.saturating_sub(last.call_count),
            charge_call: non_negative_delta(self.charge_call, last.charge_call, "charge_call")?,
            bytes_sent: self.bytes_sent.saturating_sub(last.bytes_sent),
            bytes_received: self.bytes_received.saturating_sub(last.bytes_received),
            charge_bytes_sent: non_negative_delta(
                self.charge_bytes_sent,
                last.charge_bytes_sent,
                "charge_bytes_sent",
            )?,
            charge_bytes_received: non_negative_delta(
                self.charge_bytes_received,
                last.charge_bytes_received,
                "charge_bytes_received",
            )?,
            charge_total: non_negative_delta(self.charge_total, last.charge_total, "charge_total")?,
        })
    }

    fn is_zero(self) -> bool {
        self.call_count == 0
            && self.bytes_sent == 0
            && self.bytes_received == 0
            && self.charge_call == 0.0
            && self.charge_bytes_sent == 0.0
            && self.charge_bytes_received == 0.0
            && self.charge_total == 0.0
    }
}

struct SnapshotAtomicTotals {
    call_count: AtomicU64,
    charge_call_bits: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    charge_bytes_sent_bits: AtomicU64,
    charge_bytes_received_bits: AtomicU64,
    charge_total_bits: AtomicU64,
}

impl Default for SnapshotAtomicTotals {
    fn default() -> Self {
        Self {
            call_count: AtomicU64::new(0),
            charge_call_bits: AtomicU64::new(0f64.to_bits()),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            charge_bytes_sent_bits: AtomicU64::new(0f64.to_bits()),
            charge_bytes_received_bits: AtomicU64::new(0f64.to_bits()),
            charge_total_bits: AtomicU64::new(0f64.to_bits()),
        }
    }
}

impl SnapshotAtomicTotals {
    fn try_add(&self, charge: ChargeComputation) -> Result<(), String> {
        let added_calls = charge.call_count as u64;
        let previous =
            self.call_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(added_calls)
                });
        if previous.is_err() {
            return Err(format!(
                "{PLUGIN_NAME}: snapshot call_count overflowed u64 while accumulating"
            ));
        }
        add_f64_atomic(&self.charge_call_bits, charge.charge_call);
        self.bytes_sent
            .fetch_add(charge.bytes_sent, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(charge.bytes_received, Ordering::Relaxed);
        add_f64_atomic(&self.charge_bytes_sent_bits, charge.charge_bytes_sent);
        add_f64_atomic(
            &self.charge_bytes_received_bits,
            charge.charge_bytes_received,
        );
        add_f64_atomic(&self.charge_total_bits, charge.charge_total);
        Ok(())
    }

    fn snapshot(&self) -> SnapshotTotals {
        SnapshotTotals {
            call_count: self.call_count.load(Ordering::Relaxed),
            charge_call: f64::from_bits(self.charge_call_bits.load(Ordering::Relaxed)),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            charge_bytes_sent: f64::from_bits(self.charge_bytes_sent_bits.load(Ordering::Relaxed)),
            charge_bytes_received: f64::from_bits(
                self.charge_bytes_received_bits.load(Ordering::Relaxed),
            ),
            charge_total: f64::from_bits(self.charge_total_bits.load(Ordering::Relaxed)),
        }
    }
}

struct SnapshotEntry {
    meta: SnapshotMetadata,
    totals: SnapshotAtomicTotals,
    last_seen_at: AtomicI64,
    /// Stable identity for this map slot. Assigned once at insert and never
    /// changed by in-place refreshes. Couples `last_emitted` cleanup to the
    /// exact entry generation that eviction removed.
    generation: u64,
    /// Bumped on every `record` (insert or refresh). Stale cleanup observes a
    /// revision and only evicts when that exact revision is still present, so a
    /// same-key refresh that races after the stale check cannot be deleted.
    revision: AtomicU64,
    /// Estimated retained bytes charged against `max_retained_bytes` at insert.
    retained_bytes: usize,
}

/// Baseline emitted for one accumulator generation of a snapshot identity.
struct LastEmitted {
    generation: u64,
    totals: SnapshotTotals,
}

struct PreparedSnapshot {
    events: Vec<ChargeEvent>,
    emitted_totals: Vec<(SnapshotMetadata, u64, SnapshotTotals)>,
}

/// Staged overflow moved out of the accumulator while its existing byte charge
/// remains owned by the accumulator.
///
/// Keeping the reservation in place closes a loss window: if a spool write
/// fails, another sink cannot consume this process-ceiling capacity while the
/// events are borrowed and make restoration of the already-admitted billing
/// deltas fail.
struct TakenOverflow {
    events: Vec<ChargeEvent>,
    retained_bytes: usize,
}

#[cfg(test)]
type CleanupAfterStaleCheckHook = Arc<dyn Fn() + Send + Sync + 'static>;

/// Outcome of attempting to accumulate one charge under cardinality/byte budgets.
#[derive(Debug)]
enum SnapshotRecordOutcome {
    Accumulated,
    /// New identity exceeded the hard budget; caller must durably spool this event.
    OverflowImmediate,
}

pub struct SnapshotAccumulator {
    entries: DashMap<SnapshotMetadata, SnapshotEntry>,
    last_emitted: DashMap<SnapshotMetadata, LastEmitted>,
    next_generation: AtomicU64,
    max_entries: usize,
    max_retained_bytes: usize,
    /// Authoritative identity-slot reservation gate. Reserved before a new key
    /// is published and released on eviction or a lost publish race, so the
    /// hard `max_entries` ceiling holds under concurrent inserts without a
    /// global request-path lock. Tracks `entries.len()` up to transient
    /// same-key reservation windows that only ever reject conservatively.
    reserved_entries: AtomicUsize,
    /// Combined retained-byte reservation (accumulator entries plus staged
    /// overflow). Both entry insertion and overflow staging CAS against this
    /// single counter so the combined hard ceiling cannot be exceeded even when
    /// they race.
    retained_bytes: AtomicUsize,
    /// Matching process-wide charge for [`Self::retained_bytes`].
    ///
    /// `max_retained_bytes` bounds **one** accumulator; without this the same
    /// attacker-shaped identity keys and staged overflow could be multiplied by
    /// the number of configured plugin instances and pending generations before
    /// anything refused. Every admission grows it before the key or the staged
    /// event exists, every eviction/drain/clear shrinks it by exactly the same
    /// amount, and `Drop` releases whatever is still held — so a generation that
    /// is dropped without an explicit clear cannot leak the charge.
    process_retained: GrowableProcessReservation,
    overflow_pending: Mutex<Vec<ChargeEvent>>,
    /// Overflow subset of `retained_bytes`, tracked separately so a take can
    /// transfer logical ownership without releasing the charge, while
    /// durable commit or clear releases exactly the staged portion.
    overflow_pending_bytes: AtomicUsize,
    /// Async snapshot-overflow jobs that can still re-stage an event after a
    /// durable spool failure. Full→Compact and finalization must wait for these
    /// jobs as well as terminal-hook admission guards before transferring or
    /// clearing accumulator state.
    overflow_deliveries_in_flight: AtomicUsize,
    /// Test-only callback invoked after a key is selected as a stale candidate
    /// and before conditional eviction. Production leaves this unset.
    #[cfg(test)]
    cleanup_after_stale_check_hook: Mutex<Option<CleanupAfterStaleCheckHook>>,
}

impl SnapshotAccumulator {
    pub fn new() -> Self {
        Self::with_limits(
            default_snapshot_max_entries(),
            default_snapshot_max_retained_bytes(),
        )
    }

    pub fn with_limits(max_entries: usize, max_retained_bytes: usize) -> Self {
        Self::with_limits_and_shards(
            max_entries,
            max_retained_bytes,
            crate::util::sharding::pool_shard_amount(0),
        )
    }

    /// Build an accumulator whose hot-path maps use `shard_amount` shards.
    ///
    /// `shard_amount` must already be normalized (production passes
    /// `PluginHttpClient::pool_shard_amount()`, which applies
    /// `FERRUM_POOL_SHARD_AMOUNT` exactly once). Both maps are written from the
    /// request path under attacker-shaped key cardinality, so they must not
    /// keep DashMap's default shard count.
    pub fn with_limits_and_shards(
        max_entries: usize,
        max_retained_bytes: usize,
        shard_amount: usize,
    ) -> Self {
        Self::with_limits_shards_and_ceiling(
            max_entries,
            max_retained_bytes,
            shard_amount,
            process_ceiling(),
        )
    }

    /// Build an accumulator whose retained state is charged to an explicit
    /// ceiling. Production always passes [`process_ceiling`]; external tests
    /// pass their own leaked ceiling so multi-instance saturation assertions
    /// stay exact alongside concurrently running tests.
    pub fn with_limits_shards_and_ceiling(
        max_entries: usize,
        max_retained_bytes: usize,
        shard_amount: usize,
        ceiling: &'static RetainedByteCeiling,
    ) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            last_emitted: DashMap::with_shard_amount(shard_amount),
            next_generation: AtomicU64::new(1),
            max_entries: max_entries.max(1),
            max_retained_bytes: max_retained_bytes.max(1),
            reserved_entries: AtomicUsize::new(0),
            retained_bytes: AtomicUsize::new(0),
            process_retained: GrowableProcessReservation::new(ceiling),
            overflow_pending: Mutex::new(Vec::new()),
            overflow_pending_bytes: AtomicUsize::new(0),
            overflow_deliveries_in_flight: AtomicUsize::new(0),
            #[cfg(test)]
            cleanup_after_stale_check_hook: Mutex::new(None),
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Combined retained bytes (accumulator entries plus staged overflow).
    /// `retained_bytes` already tracks both, so the accessor is a single load.
    fn retained_bytes(&self) -> usize {
        self.retained_bytes.load(Ordering::Acquire)
    }

    fn begin_overflow_delivery(&self) {
        self.overflow_deliveries_in_flight
            .fetch_add(1, Ordering::AcqRel);
    }

    fn finish_overflow_delivery(&self) {
        self.overflow_deliveries_in_flight
            .fetch_sub(1, Ordering::AcqRel);
    }

    fn overflow_deliveries_in_flight(&self) -> usize {
        self.overflow_deliveries_in_flight.load(Ordering::Acquire)
    }

    // External adversarial tests assert the hard byte ceiling is never crossed;
    // the binary target compiles this module separately and cannot observe them.
    #[allow(dead_code)]
    pub fn retained_bytes_for_tests(&self) -> usize {
        self.retained_bytes()
    }

    /// Bytes this accumulator currently charges to the process-wide ceiling.
    /// External tests assert it tracks the per-instance counter exactly, so N
    /// instances cannot multiply past the shared ceiling.
    #[allow(dead_code)]
    pub fn process_retained_bytes_for_tests(&self) -> usize {
        self.process_retained.held()
    }

    /// Release every process-wide charge as `Drop` would, without consuming the
    /// accumulator. External tests use it to assert exact release.
    #[allow(dead_code)]
    pub fn clear_for_compaction_for_tests(&self) {
        self.clear_for_compaction();
    }

    /// Reserve one identity slot and its retained bytes against the hard
    /// ceilings before a new key is published. Returns `false` when either
    /// ceiling would be exceeded so the caller durably spools the charge. On a
    /// byte-ceiling refusal the already-taken slot reservation is released.
    fn try_reserve_identity(&self, entry_bytes: usize) -> bool {
        if self
            .reserved_entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max_entries).then_some(count + 1)
            })
            .is_err()
        {
            return false;
        }
        if self.try_reserve_bytes(entry_bytes) {
            true
        } else {
            self.reserved_entries.fetch_sub(1, Ordering::AcqRel);
            false
        }
    }

    /// Reserve `bytes` against the combined retained-byte ceiling. Shared by
    /// entry insertion and overflow staging so their combined footprint can
    /// never exceed `max_retained_bytes` under concurrency.
    fn try_reserve_bytes(&self, bytes: usize) -> bool {
        // The process ceiling is taken first so a per-instance reservation is
        // never left held while the shared reservation fails.
        if !self.process_retained.try_grow(bytes) {
            return false;
        }
        if self
            .retained_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_retained_bytes)
            })
            .is_ok()
        {
            true
        } else {
            self.process_retained.shrink_by(bytes);
            false
        }
    }

    /// Release a previously reserved identity slot and its retained bytes.
    fn release_identity(&self, entry_bytes: usize) {
        self.reserved_entries.fetch_sub(1, Ordering::AcqRel);
        self.retained_bytes.fetch_sub(entry_bytes, Ordering::AcqRel);
        self.process_retained.shrink_by(entry_bytes);
    }

    fn clear_for_compaction(&self) {
        self.entries.clear();
        self.last_emitted.clear();
        self.reserved_entries.store(0, Ordering::Release);
        self.retained_bytes.store(0, Ordering::Release);
        if let Ok(mut pending) = self.overflow_pending.lock() {
            pending.clear();
        }
        self.overflow_pending_bytes.store(0, Ordering::Release);
        // Both per-instance counters are now zero, so the whole process-wide
        // charge belongs to state that no longer exists. `release_all` is
        // idempotent and saturating, so a later drop cannot double-release.
        self.process_retained.release_all();
    }

    fn record_http(
        &self,
        summary: &TransactionSummary,
        consumer: &str,
        outcome: HttpBillingOutcome,
        charge: ChargeComputation,
    ) -> SnapshotRecordOutcome {
        let proxy_id = summary.proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        let meta = SnapshotMetadata {
            namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_key_field(proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_key_field(proxy_name, MAX_FIELD_LEN),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: outcome.status_code,
            http_status_code: Some(outcome.http_status_code),
            grpc_status: outcome.grpc_status.map(normalize_snapshot_grpc_status),
            protocol: infer_http_protocol(summary),
        };
        self.record(meta, charge)
    }

    fn record_stream(
        &self,
        summary: &StreamTransactionSummary,
        consumer: &str,
        charge: ChargeComputation,
    ) -> SnapshotRecordOutcome {
        let meta = SnapshotMetadata {
            namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_key_field(&summary.proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_key_field(
                summary.proxy_name.as_deref().unwrap_or("unknown"),
                MAX_FIELD_LEN,
            ),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: STREAM_STATUS_SENTINEL,
            http_status_code: None,
            grpc_status: None,
            protocol: bound_key_field(&summary.protocol, MAX_FIELD_LEN),
        };
        self.record(meta, charge)
    }

    fn record_websocket(
        &self,
        summary: &WsDisconnectContext,
        consumer: &str,
        charge: ChargeComputation,
    ) -> SnapshotRecordOutcome {
        let meta = SnapshotMetadata {
            namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
            consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
            consumer_name: metadata_value(&summary.metadata, &["consumer_name"]),
            proxy_id: bound_key_field(&summary.proxy_id, MAX_FIELD_LEN),
            proxy_name: bound_key_field(
                summary.proxy_name.as_deref().unwrap_or("unknown"),
                MAX_FIELD_LEN,
            ),
            route_id: metadata_value(&summary.metadata, &["route_id"]),
            status_code: STREAM_STATUS_SENTINEL,
            http_status_code: None,
            grpc_status: None,
            protocol: "ws".to_string(),
        };
        self.record(meta, charge)
    }

    fn record(&self, meta: SnapshotMetadata, charge: ChargeComputation) -> SnapshotRecordOutcome {
        self.record_at(meta, charge, unix_timestamp_seconds())
    }

    fn record_at(
        &self,
        meta: SnapshotMetadata,
        charge: ChargeComputation,
        now: i64,
    ) -> SnapshotRecordOutcome {
        let key = meta.clone();
        // Fast path: refresh an already-published identity in place. No new
        // admission is charged for a same-key refresh.
        if let Some(entry) = self.entries.get(&key) {
            entry.last_seen_at.store(now, Ordering::Relaxed);
            entry.revision.fetch_add(1, Ordering::Relaxed);
            if let Err(error) = entry.totals.try_add(charge) {
                warn!(plugin = PLUGIN_NAME, error = %error, "Chargeback sink rejected impossible snapshot call_count overflow");
                return SnapshotRecordOutcome::OverflowImmediate;
            }
            return SnapshotRecordOutcome::Accumulated;
        }

        let entry_bytes = snapshot_metadata_retained_bytes(&meta);
        // Reserve the identity slot and its retained bytes against the hard
        // ceilings *before* publishing the key. Because the reservation is
        // atomic, concurrent new-key inserts can never publish state above
        // `max_entries`/`max_retained_bytes`, and the old publish-then-recheck
        // overshoot window (which could pin an over-budget entry when a same-key
        // refresh raced the recheck) no longer exists.
        if !self.try_reserve_identity(entry_bytes) {
            return SnapshotRecordOutcome::OverflowImmediate;
        }

        let mut created = false;
        let refresh_result = {
            let entry = self.entries.entry(key.clone()).or_insert_with(|| {
                created = true;
                SnapshotEntry {
                    meta,
                    totals: SnapshotAtomicTotals::default(),
                    last_seen_at: AtomicI64::new(now),
                    generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
                    revision: AtomicU64::new(0),
                    retained_bytes: entry_bytes,
                }
            });
            entry.last_seen_at.store(now, Ordering::Relaxed);
            entry.revision.fetch_add(1, Ordering::Relaxed);
            entry.totals.try_add(charge)
        };

        if !created {
            // Lost the publish race: another inserter already owns the single
            // reservation for this identity. Release ours exactly once so the
            // budget stays exact, and keep the winner's refresh above.
            self.release_identity(entry_bytes);
        }

        match refresh_result {
            Ok(()) => SnapshotRecordOutcome::Accumulated,
            Err(error) => {
                warn!(plugin = PLUGIN_NAME, error = %error, "Chargeback sink rejected impossible snapshot call_count overflow");
                if created {
                    // The freshly created identity could not accept the charge
                    // and still holds zero totals. Roll it back (releasing its
                    // reservation) unless a concurrent refresh already attached
                    // real totals, in which case its reservation is legitimate.
                    self.remove_pristine_entry(&key);
                }
                SnapshotRecordOutcome::OverflowImmediate
            }
        }
    }

    /// Remove a just-created identity that never accepted a charge, releasing
    /// its reservation. A concurrent same-key refresh that attached real totals
    /// keeps the entry (and the single reservation that backs it).
    fn remove_pristine_entry(&self, key: &SnapshotMetadata) {
        if let Some((_, evicted)) = self.entries.remove_if(key, |_, live| {
            live.totals.snapshot().is_zero() && live.revision.load(Ordering::Relaxed) <= 1
        }) {
            self.release_identity(evicted.retained_bytes);
        }
    }

    fn stage_overflow_event(&self, event: ChargeEvent) -> bool {
        let bytes = charge_event_retained_bytes(&event);
        // Reserve against the combined retained-byte ceiling shared with entry
        // insertion, so concurrent staging and new-key admission can never push
        // the accumulator over `max_retained_bytes`.
        if !self.try_reserve_bytes(bytes) {
            return false;
        }
        let mut pending = match self.overflow_pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        pending.push(event);
        // Track the staged portion of the combined reservation so take can
        // transfer ownership and durable commit or clear can release exactly
        // these bytes.
        self.overflow_pending_bytes
            .fetch_add(bytes, Ordering::AcqRel);
        true
    }

    #[allow(dead_code)]
    pub fn stage_overflow_event_for_tests(&self, event: ChargeEvent) -> bool {
        self.stage_overflow_event(event)
    }

    /// Deterministic external-test probe for borrowed overflow ownership.
    ///
    /// Returns `(taken_events, taken_bytes, held_while_taken,
    /// competing_byte_admitted, pending_after_restore, held_after_restore)`.
    /// Tests set `ceiling.max()` to the staged charge before calling this. A
    /// correct take keeps the ceiling saturated, so the competing byte is
    /// refused and restoration cannot need a second admission.
    #[allow(dead_code)]
    pub fn probe_taken_overflow_ownership_for_tests(
        &self,
        ceiling: &'static RetainedByteCeiling,
    ) -> (usize, usize, usize, bool, usize, usize) {
        let taken = self.take_overflow_pending();
        let taken_events = taken.events.len();
        let taken_bytes = taken.retained_bytes;
        let held_while_taken = self.process_retained.held();
        let competing = ceiling.try_acquire(1);
        let competing_byte_admitted = competing.is_some();
        drop(competing);
        self.restore_taken_overflow(taken);
        (
            taken_events,
            taken_bytes,
            held_while_taken,
            competing_byte_admitted,
            self.overflow_pending_len(),
            self.process_retained.held(),
        )
    }

    fn take_overflow_pending(&self) -> TakenOverflow {
        let mut pending = match self.overflow_pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        TakenOverflow {
            events: std::mem::take(&mut *pending),
            // Move the logical ownership out of `overflow_pending`, but keep
            // both byte reservations charged until durable success commits the
            // take or failure restores it. A concurrent stage starts a fresh
            // `overflow_pending_bytes` subtotal without being released by this
            // take.
            retained_bytes: self.overflow_pending_bytes.swap(0, Ordering::AcqRel),
        }
    }

    /// Commit a successfully persisted overflow take, releasing the reservation
    /// that stayed charged while the events were outside the accumulator.
    fn commit_taken_overflow(&self, retained_bytes: usize) {
        if retained_bytes == 0 {
            return;
        }
        self.retained_bytes
            .fetch_sub(retained_bytes, Ordering::AcqRel);
        self.process_retained.shrink_by(retained_bytes);
    }

    /// Restore a failed overflow take without any new byte admission.
    ///
    /// The old events precede concurrently staged ones, preserving retry order.
    /// Their retained-byte charge never left the accumulator, so restoration
    /// cannot fail under process-wide ceiling pressure.
    fn restore_taken_overflow(&self, mut taken: TakenOverflow) {
        if taken.events.is_empty() {
            debug_assert_eq!(taken.retained_bytes, 0);
            return;
        }
        let mut pending = match self.overflow_pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        taken.events.append(&mut pending);
        *pending = taken.events;
        self.overflow_pending_bytes
            .fetch_add(taken.retained_bytes, Ordering::AcqRel);
    }

    /// Staged overflow events still awaiting durable handoff.
    fn overflow_pending_len(&self) -> usize {
        match self.overflow_pending.lock() {
            Ok(pending) => pending.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Conservative process-ceiling bound for the delta projection this
    /// accumulator would produce right now.
    ///
    /// `prepare_deltas` allocates two attacker-shaped copies per live identity —
    /// the emitted `ChargeEvent` and the `emitted_totals` key clone — on top of
    /// the entries and staged overflow that are already charged. `per_event_extra`
    /// covers the per-event fields that come from configuration rather than from
    /// the accumulator key.
    fn delta_projection_bound(&self, per_event_extra: usize) -> Option<usize> {
        let identities = self
            .entries
            .len()
            .checked_add(self.overflow_pending_len())?;
        self.retained_bytes()
            .checked_mul(SNAPSHOT_PROJECTION_COPIES)?
            .checked_add(identities.checked_mul(per_event_extra)?)
    }

    // External integration tests exercise the public accumulator contract;
    // the separately compiled binary cannot observe those call sites.
    #[allow(dead_code)]
    pub fn compute_deltas(
        &self,
        config: &ApiChargebackSinkConfig,
        node_id: &str,
        received_at: i64,
        snapshot_id: &str,
    ) -> Result<Vec<ChargeEvent>, String> {
        let prepared = self.prepare_deltas(config, node_id, received_at, snapshot_id)?;
        self.commit_prepared(&prepared);
        Ok(prepared.events)
    }

    fn prepare_deltas(
        &self,
        config: &ApiChargebackSinkConfig,
        node_id: &str,
        received_at: i64,
        snapshot_id: &str,
    ) -> Result<PreparedSnapshot, String> {
        let mut events = Vec::new();
        let mut emitted_totals = Vec::new();
        for entry in self.entries.iter() {
            let key = entry.key().clone();
            let generation = entry.value().generation;
            let current = entry.value().totals.snapshot();
            // Ignore a baseline tagged for a different generation (for example
            // an orphan left after eviction+reinsert). That treats the live
            // entry as starting from zero rather than subtracting a stale
            // prior total.
            let last = self
                .last_emitted
                .get(&key)
                .filter(|value| value.generation == generation)
                .map(|value| value.totals)
                .unwrap_or_default();
            let delta = current.delta_since(last)?;
            if !delta.is_zero() || config.snapshot.emit_zero_deltas {
                events.push(event_from_snapshot(
                    &entry.value().meta,
                    delta,
                    config,
                    node_id,
                    received_at,
                    snapshot_id,
                ));
                emitted_totals.push((key, generation, current));
            }
        }
        Ok(PreparedSnapshot {
            events,
            emitted_totals,
        })
    }

    // Only the external `compute_deltas` test contract still commits a whole
    // `PreparedSnapshot`; production moves the projection apart and commits the
    // emitted totals directly.
    #[allow(dead_code)]
    fn commit_prepared(&self, prepared: &PreparedSnapshot) {
        self.commit_emitted_totals(&prepared.emitted_totals);
    }

    fn commit_emitted_totals(&self, emitted_totals: &[(SnapshotMetadata, u64, SnapshotTotals)]) {
        for (key, generation, current) in emitted_totals {
            // Publish the baseline only while this generation is still live so
            // a concurrent eviction cannot leave an orphaned baseline that a
            // later reinsert would mis-subtract, and so we cannot overwrite a
            // newer generation's baseline with an older snapshot read.
            if let Some(entry) = self.entries.get(key)
                && entry.generation == *generation
            {
                // Keep the entry guard through publication. Cleanup cannot
                // evict this generation and remove its baseline between
                // the generation check and the insert.
                self.last_emitted.insert(
                    key.clone(),
                    LastEmitted {
                        generation: *generation,
                        totals: *current,
                    },
                );
            }
        }
    }

    fn entry_has_uncommitted_delta(&self, entry: &SnapshotEntry) -> bool {
        let current = entry.totals.snapshot();
        let last = self
            .last_emitted
            .get(&entry.meta)
            .filter(|value| value.generation == entry.generation)
            .map(|value| value.totals)
            .unwrap_or_default();
        match current.delta_since(last) {
            Ok(delta) => !delta.is_zero(),
            // Fail closed: non-finite/regressed state must not be deleted.
            Err(_) => true,
        }
    }

    #[allow(dead_code)]
    pub fn cleanup_stale_for_tests(&self, stale_entry_ttl_secs: u64) -> usize {
        self.cleanup_stale(unix_timestamp_seconds(), stale_entry_ttl_secs)
    }

    #[cfg(test)]
    fn set_cleanup_after_stale_check_hook(&self, hook: Option<CleanupAfterStaleCheckHook>) {
        if let Ok(mut slot) = self.cleanup_after_stale_check_hook.lock() {
            *slot = hook;
        }
    }

    #[cfg(test)]
    fn run_cleanup_after_stale_check_hook(&self) {
        let hook = self
            .cleanup_after_stale_check_hook
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn cleanup_stale(&self, now: i64, stale_entry_ttl_secs: u64) -> usize {
        let cutoff = now.saturating_sub(stale_entry_ttl_secs.min(i64::MAX as u64) as i64);
        // Candidate scan is best-effort. Eviction re-validates generation,
        // revision, staleness, and pending-delta state atomically under the
        // DashMap shard lock so a same-key refresh cannot be deleted, unemitted
        // totals survive TTL, and unrelated keys stay non-blocking.
        let candidates: Vec<(SnapshotMetadata, u64, u64)> = self
            .entries
            .iter()
            .filter(|entry| {
                entry.value().last_seen_at.load(Ordering::Relaxed) <= cutoff
                    && !self.entry_has_uncommitted_delta(entry.value())
            })
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().generation,
                    entry.value().revision.load(Ordering::Relaxed),
                )
            })
            .collect();
        let mut removed = 0;
        for (key, observed_generation, observed_revision) in candidates {
            #[cfg(test)]
            self.run_cleanup_after_stale_check_hook();
            if let Some((_, evicted)) = self.entries.remove_if(&key, |_, entry| {
                entry.generation == observed_generation
                    && entry.revision.load(Ordering::Relaxed) == observed_revision
                    && entry.last_seen_at.load(Ordering::Relaxed) <= cutoff
                    && !self.entry_has_uncommitted_delta(entry)
            }) {
                // Drop the baseline only for the generation that was actually
                // evicted. A concurrent reinsert+emit for a newer generation
                // must keep its last_emitted row.
                self.last_emitted.remove_if(&key, |_, baseline| {
                    baseline.generation == evicted.generation
                });
                self.release_identity(evicted.retained_bytes);
                removed += 1;
            }
        }
        removed
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn record_for_test(
        &self,
        namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol: &str,
        charge: ChargeComputation,
    ) {
        let _ = self.record_at(
            SnapshotMetadata {
                namespace: namespace.to_string(),
                consumer_id: consumer.to_string(),
                consumer_name: None,
                proxy_id: proxy_id.to_string(),
                proxy_name: proxy_name.to_string(),
                route_id: None,
                status_code,
                http_status_code: (protocol == "http").then_some(status_code),
                grpc_status: None,
                protocol: protocol.to_string(),
            },
            charge,
            unix_timestamp_seconds(),
        );
    }

    /// Record a charge and report whether it was accumulated (`true`) or spilled
    /// to durable overflow (`false`). Adversarial concurrency tests tally the
    /// two outcomes to prove no charge is double-counted or silently dropped.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn record_accumulated_for_test(
        &self,
        namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol: &str,
        charge: ChargeComputation,
    ) -> bool {
        matches!(
            self.record_at(
                SnapshotMetadata {
                    namespace: namespace.to_string(),
                    consumer_id: consumer.to_string(),
                    consumer_name: None,
                    proxy_id: proxy_id.to_string(),
                    proxy_name: proxy_name.to_string(),
                    route_id: None,
                    status_code,
                    http_status_code: (protocol == "http").then_some(status_code),
                    grpc_status: None,
                    protocol: protocol.to_string(),
                },
                charge,
                unix_timestamp_seconds(),
            ),
            SnapshotRecordOutcome::Accumulated
        )
    }

    /// Sum of accumulated `call_count` across every live identity. Equals the
    /// number of accumulated records in a test that seeds one call per record.
    #[allow(dead_code)]
    pub fn total_call_count_for_tests(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.value().totals.call_count.load(Ordering::Relaxed))
            .fold(0u64, u64::saturating_add)
    }

    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn record_http_for_test(
        &self,
        summary: &TransactionSummary,
        consumer: &str,
        charge: ChargeComputation,
    ) {
        let _ = self.record_http(summary, consumer, http_billing_outcome(summary), charge);
    }

    /// Seed a single identity with an arbitrary `call_count` for boundary tests.
    #[doc(hidden)]
    // External boundary tests need every identity dimension explicit.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn seed_call_count_for_test(
        &self,
        namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol: &str,
        call_count: u64,
    ) {
        let meta = SnapshotMetadata {
            namespace: namespace.to_string(),
            consumer_id: consumer.to_string(),
            consumer_name: None,
            proxy_id: proxy_id.to_string(),
            proxy_name: proxy_name.to_string(),
            route_id: None,
            status_code,
            http_status_code: (protocol == "http").then_some(status_code),
            grpc_status: None,
            protocol: protocol.to_string(),
        };
        let entry_bytes = snapshot_metadata_retained_bytes(&meta);
        let key = meta.clone();
        let entry = self.entries.entry(key).or_insert_with(|| SnapshotEntry {
            meta,
            totals: SnapshotAtomicTotals::default(),
            last_seen_at: AtomicI64::new(unix_timestamp_seconds()),
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
            revision: AtomicU64::new(0),
            retained_bytes: entry_bytes,
        });
        if entry.totals.call_count.load(Ordering::Relaxed) == 0
            && entry.revision.load(Ordering::Relaxed) == 0
        {
            self.reserved_entries.fetch_add(1, Ordering::AcqRel);
            self.retained_bytes.fetch_add(entry_bytes, Ordering::AcqRel);
            // Keep the process-wide charge in lockstep with the per-instance
            // counter so a seeded identity releases exactly what it took.
            let _ = self.process_retained.try_grow(entry_bytes);
        }
        entry.totals.call_count.store(call_count, Ordering::Relaxed);
        entry.revision.fetch_add(1, Ordering::Relaxed);
        entry
            .last_seen_at
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
    }
}

impl Default for SnapshotAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

fn start_snapshot_task(
    accumulator: Arc<SnapshotAccumulator>,
    runtime: Arc<SinkRuntime>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    commit_rx: watch::Receiver<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
    emission_lock: Arc<Mutex<()>>,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        if *shutdown_rx.borrow() {
            return if *commit_rx.borrow() {
                emit_final_snapshot_to_spool_off_thread(
                    Arc::clone(&accumulator),
                    Arc::clone(&runtime),
                    Arc::clone(&config),
                    Arc::clone(&node_id),
                    Arc::clone(&emission_lock),
                )
                .await
            } else {
                true
            };
        }
        let commit_observer = commit_rx.clone();
        let committed = tokio::select! {
            committed = wait_until_committed(commit_rx) => committed,
            _ = wait_for_snapshot_shutdown(&mut shutdown_rx) => {
                if *commit_observer.borrow() {
                    return emit_final_snapshot_to_spool_off_thread(
                        Arc::clone(&accumulator),
                        Arc::clone(&runtime),
                        Arc::clone(&config),
                        Arc::clone(&node_id),
                        Arc::clone(&emission_lock),
                    )
                    .await;
                }
                false
            },
        };
        if !committed {
            return true;
        }
        let mut snapshot_timer =
            tokio::time::interval(Duration::from_secs(config.snapshot.interval_secs));
        let mut cleanup_timer =
            tokio::time::interval(Duration::from_secs(config.snapshot.cleanup_interval_secs));
        // Tokio intervals are immediately ready on their first tick. Consume
        // those scheduling ticks so the documented interval starts at
        // generation commit instead of racing the first request.
        snapshot_timer.tick().await;
        cleanup_timer.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = wait_for_snapshot_shutdown(&mut shutdown_rx) => {
                    return emit_final_snapshot_to_spool_off_thread(
                        Arc::clone(&accumulator),
                        Arc::clone(&runtime),
                        Arc::clone(&config),
                        Arc::clone(&node_id),
                        Arc::clone(&emission_lock),
                    )
                    .await;
                }
                _ = snapshot_timer.tick() => {
                    let _ = emit_periodic_snapshot_off_thread(
                        Arc::clone(&accumulator),
                        Arc::clone(&runtime),
                        Arc::clone(&config),
                        Arc::clone(&node_id),
                        Arc::clone(&emission_lock),
                    )
                    .await;
                }
                _ = cleanup_timer.tick() => {
                    let removed = accumulator.cleanup_stale(
                        unix_timestamp_seconds(),
                        config.snapshot.stale_entry_ttl_secs,
                    );
                    if removed > 0 {
                        invalidate_status_cache();
                    }
                }
            }
        }
    })
}

async fn emit_periodic_snapshot_off_thread(
    accumulator: Arc<SnapshotAccumulator>,
    runtime: Arc<SinkRuntime>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    emission_lock: Arc<Mutex<()>>,
) -> Result<usize, String> {
    let metrics = Arc::clone(&runtime.metrics);
    let generation = runtime.generation;
    match tokio::task::spawn_blocking(move || {
        emit_periodic_snapshot(&accumulator, &runtime, &config, &node_id, &emission_lock)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let error = format!("periodic snapshot worker did not complete: {error}");
            metrics.record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                generation,
                error = %error,
                "Chargeback sink periodic snapshot worker failed"
            );
            Err(error)
        }
    }
}

async fn emit_final_snapshot_to_spool_off_thread(
    accumulator: Arc<SnapshotAccumulator>,
    runtime: Arc<SinkRuntime>,
    config: Arc<ApiChargebackSinkConfig>,
    node_id: Arc<str>,
    emission_lock: Arc<Mutex<()>>,
) -> bool {
    let metrics = Arc::clone(&runtime.metrics);
    let generation = runtime.generation;
    match tokio::task::spawn_blocking(move || {
        emit_final_snapshot_to_spool(&accumulator, &runtime, &config, &node_id, &emission_lock)
    })
    .await
    {
        Ok(durable) => durable,
        Err(error) => {
            metrics.record_failure(
                FailureReason::Serialize,
                format!("final snapshot worker did not complete: {error}"),
            );
            warn!(
                plugin = PLUGIN_NAME,
                generation,
                error = %error,
                "Chargeback sink final snapshot worker failed; generation state retained"
            );
            false
        }
    }
}

fn emit_periodic_snapshot(
    accumulator: &SnapshotAccumulator,
    runtime: &SinkRuntime,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    emission_lock: &Mutex<()>,
) -> Result<usize, String> {
    let _emission_guard = match emission_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let snapshot_id = new_ulid();
    let received_at = unix_timestamp_nanos();
    // The projection coexists with the still-charged accumulator, so reserve it
    // before it is built. Refusal is a retryable emission failure: no baseline
    // is advanced and the next tick retries.
    let _projection =
        reserve_delta_projection(accumulator, config, node_id).inspect_err(|error| {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
        })?;
    let prepared = match accumulator.prepare_deltas(config, node_id, received_at, &snapshot_id) {
        Ok(prepared) => prepared,
        Err(error) => {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                error = %error,
                "Chargeback sink snapshot arithmetic failed; no delta was advanced"
            );
            return Err(error);
        }
    };
    let PreparedSnapshot {
        events: delta_events,
        emitted_totals,
    } = prepared;
    // Take the staged overflow instead of cloning it, and move the prepared
    // deltas rather than copying them: both were previously duplicated into a
    // third uncharged full-batch vector.
    let taken = accumulator.take_overflow_pending();
    let overflow_count = taken.events.len();
    let overflow_retained_bytes = taken.retained_bytes;
    let mut events = taken.events;
    events.extend(delta_events);
    let event_count = events.len();
    if event_count == 0 {
        accumulator.commit_taken_overflow(overflow_retained_bytes);
        return Ok(0);
    }
    let Some(spool) = runtime.spool.as_ref() else {
        let error = "snapshot emission requires an available spool".to_string();
        runtime
            .metrics
            .record_failure(FailureReason::Serialize, error.clone());
        restage_borrowed_overflow(accumulator, events, overflow_count, overflow_retained_bytes);
        return Err(error);
    };
    // Bind the result first so the borrow of `events` ends before the failure
    // arm needs to move them back into bounded staging.
    let write_result = spool.write_events(&events);
    if let Err(error) = write_result {
        runtime
            .metrics
            .spool_available
            .store(false, Ordering::Release);
        let error = format!("periodic snapshot spool handoff failed: {error}");
        runtime
            .metrics
            .record_failure(FailureReason::Serialize, error.clone());
        warn!(
            plugin = PLUGIN_NAME,
            generation = runtime.generation,
            error = %error,
            "Chargeback sink could not durably spool its periodic snapshot; no baseline was advanced"
        );
        restage_borrowed_overflow(accumulator, events, overflow_count, overflow_retained_bytes);
        return Err(error);
    }
    // Snapshot mode requires the spool. It is the durable commit point before
    // the accumulator baseline advances; the same event IDs are then enqueued as
    // a low-latency delivery attempt. A reload racing this point can abort the
    // queue worker without losing or double-charging the snapshot: replay is
    // idempotent on event_id. The staged overflow was already taken above, so
    // durable success simply keeps it taken.
    accumulator.commit_taken_overflow(overflow_retained_bytes);
    accumulator.commit_emitted_totals(&emitted_totals);
    runtime
        .metrics
        .snapshot_emits_total
        .fetch_add(event_count as u64, Ordering::Relaxed);
    for event in events {
        enqueue_charge_event(runtime, event);
    }
    invalidate_status_cache();
    Ok(event_count)
}

async fn wait_for_snapshot_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
}

fn emit_final_snapshot_to_spool(
    accumulator: &SnapshotAccumulator,
    runtime: &SinkRuntime,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    emission_lock: &Mutex<()>,
) -> bool {
    let _emission_guard = match emission_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let snapshot_id = new_ulid();
    let received_at = unix_timestamp_nanos();
    let _projection = match reserve_delta_projection(accumulator, config, node_id) {
        Ok(reservation) => reservation,
        Err(error) => {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                generation = runtime.generation,
                error = %error,
                "Chargeback sink final snapshot could not reserve its projection; generation state retained"
            );
            return false;
        }
    };
    let prepared = match accumulator.prepare_deltas(config, node_id, received_at, &snapshot_id) {
        Ok(prepared) => prepared,
        Err(error) => {
            runtime
                .metrics
                .record_failure(FailureReason::Serialize, error.clone());
            warn!(
                plugin = PLUGIN_NAME,
                generation = runtime.generation,
                error = %error,
                "Chargeback sink final snapshot arithmetic failed; generation state retained"
            );
            return false;
        }
    };
    let PreparedSnapshot {
        events: delta_events,
        emitted_totals,
    } = prepared;
    let taken = accumulator.take_overflow_pending();
    let overflow_count = taken.events.len();
    let overflow_retained_bytes = taken.retained_bytes;
    let mut events = taken.events;
    events.extend(delta_events);
    if events.is_empty() {
        accumulator.commit_taken_overflow(overflow_retained_bytes);
        return true;
    }
    let Some(spool) = runtime.spool.as_ref() else {
        runtime.metrics.record_failure(
            FailureReason::Serialize,
            "snapshot finalization requires an available spool",
        );
        restage_borrowed_overflow(accumulator, events, overflow_count, overflow_retained_bytes);
        return false;
    };
    // Bind the result first so the borrow of `events` ends before the failure
    // arm needs to move them back into bounded staging.
    let write_result = spool.write_events(&events);
    if let Err(error) = write_result {
        runtime
            .metrics
            .spool_available
            .store(false, Ordering::Release);
        runtime.metrics.record_failure(
            FailureReason::Serialize,
            format!("final snapshot spool handoff failed: {error}"),
        );
        warn!(
            plugin = PLUGIN_NAME,
            generation = runtime.generation,
            error = %error,
            "Chargeback sink could not durably spool its final snapshot; generation state retained"
        );
        restage_borrowed_overflow(accumulator, events, overflow_count, overflow_retained_bytes);
        return false;
    }
    accumulator.commit_taken_overflow(overflow_retained_bytes);
    accumulator.commit_emitted_totals(&emitted_totals);
    runtime
        .metrics
        .snapshot_emits_total
        .fetch_add(events.len() as u64, Ordering::Relaxed);
    invalidate_status_cache();
    true
}

fn event_from_http_summary(
    summary: &TransactionSummary,
    consumer: &str,
    outcome: HttpBillingOutcome,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_key_field(
            summary.proxy_id.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        proxy_name: bound_key_field(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: outcome.status_code,
        http_status_code: Some(outcome.http_status_code),
        grpc_status: outcome.grpc_status,
        protocol: infer_http_protocol(summary),
        call_count: u64::from(charge.call_count),
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_stream_summary(
    summary: &StreamTransactionSummary,
    consumer: &str,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_key_field(&summary.proxy_id, MAX_FIELD_LEN),
        proxy_name: bound_key_field(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: STREAM_STATUS_SENTINEL,
        http_status_code: None,
        grpc_status: None,
        protocol: bound_key_field(&summary.protocol, MAX_FIELD_LEN),
        call_count: u64::from(charge.call_count),
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_ws_summary(
    summary: &WsDisconnectContext,
    consumer: &str,
    charge: ChargeComputation,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    snapshot_id: Option<String>,
) -> ChargeEvent {
    let metadata = &summary.metadata;
    ChargeEvent {
        event_id: new_ulid(),
        received_at: unix_timestamp_nanos(),
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: bound_key_field(&summary.namespace, MAX_FIELD_LEN),
        consumer_id: bound_key_field(consumer, MAX_FIELD_LEN),
        consumer_name: metadata_value(metadata, &["consumer_name"]),
        proxy_id: bound_key_field(&summary.proxy_id, MAX_FIELD_LEN),
        proxy_name: bound_key_field(
            summary.proxy_name.as_deref().unwrap_or("unknown"),
            MAX_FIELD_LEN,
        ),
        route_id: metadata_value(metadata, &["route_id"]),
        status_code: STREAM_STATUS_SENTINEL,
        http_status_code: None,
        grpc_status: None,
        protocol: "ws".to_string(),
        call_count: u64::from(charge.call_count),
        charge_call: charge.charge_call,
        bytes_sent: charge.bytes_sent,
        bytes_received: charge.bytes_received,
        charge_bytes_sent: charge.charge_bytes_sent,
        charge_bytes_received: charge.charge_bytes_received,
        charge_total: charge.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: if config.include_request_id {
            metadata_value(
                metadata,
                &[
                    super::REQUEST_ID_METADATA_KEY,
                    "x-request-id",
                    "correlation_id",
                ],
            )
        } else {
            None
        },
        trace_id: if config.include_trace_id {
            metadata_value(metadata, &["trace_id", "traceparent"])
        } else {
            None
        },
        snapshot_id,
    }
}

fn event_from_snapshot(
    meta: &SnapshotMetadata,
    totals: SnapshotTotals,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
    received_at: i64,
    snapshot_id: &str,
) -> ChargeEvent {
    ChargeEvent {
        event_id: new_ulid(),
        received_at,
        node_id: bound_string(node_id, MAX_FIELD_LEN),
        namespace: meta.namespace.clone(),
        consumer_id: meta.consumer_id.clone(),
        consumer_name: meta.consumer_name.clone(),
        proxy_id: meta.proxy_id.clone(),
        proxy_name: meta.proxy_name.clone(),
        route_id: meta.route_id.clone(),
        status_code: meta.status_code,
        http_status_code: meta.http_status_code,
        grpc_status: meta.grpc_status,
        protocol: meta.protocol.clone(),
        call_count: totals.call_count,
        charge_call: totals.charge_call,
        bytes_sent: totals.bytes_sent,
        bytes_received: totals.bytes_received,
        charge_bytes_sent: totals.charge_bytes_sent,
        charge_bytes_received: totals.charge_bytes_received,
        charge_total: totals.charge_total,
        currency: config.currency.clone(),
        pricing_version: config.pricing_version.clone(),
        request_id: None,
        trace_id: None,
        snapshot_id: Some(snapshot_id.to_string()),
    }
}

fn infer_http_protocol(summary: &TransactionSummary) -> String {
    if let Some(protocol) = summary
        .metadata
        .get("request_protocol")
        .or_else(|| summary.metadata.get("mesh.request_protocol"))
    {
        return bound_key_field(protocol, MAX_FIELD_LEN);
    }
    if summary.response_status_code == 101 {
        "ws".to_string()
    } else {
        "http".to_string()
    }
}

fn metadata_value(metadata: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| metadata.get(*key))
        .map(|value| bound_key_field(value, MAX_METADATA_FIELD_LEN))
        .filter(|value| !value.is_empty())
}

/// Durably record a snapshot cardinality/byte overflow charge without ever
/// blocking the calling Tokio worker on compression/write/fsync.
///
/// The event is handed to the owned, bounded [`SpoolDelivery`] worker (charged
/// against the export byte budget until the worker's blocking write finishes),
/// which advances the durable-success counters only after the write genuinely
/// lands. If the bounded queue is full or closed, or the byte budget is
/// exhausted, the exact event is staged in the accumulator's bounded overflow
/// instead; only when durable handoff *and* bounded staging both fail is a
/// genuine cardinality loss recorded.
fn spool_snapshot_overflow_event(lifecycle: &SnapshotLifecycle, event: ChargeEvent) {
    let runtime = &lifecycle.runtime;
    let metrics = &runtime.metrics;
    // Prefer the bounded async delivery worker so terminal hooks never run spool
    // I/O inline. Recover the exact event when it cannot be handed off.
    let event = match runtime.spool_delivery.as_ref() {
        Some(delivery) => {
            let retained = charge_event_retained_bytes(&event);
            match runtime.byte_budget.try_acquire(retained) {
                Some(lease) => {
                    let queued = QueuedChargeEvent { event, lease };
                    match delivery.try_enqueue_snapshot_overflow(
                        vec![queued],
                        Arc::clone(&lifecycle.accumulator),
                        lifecycle.generation,
                    ) {
                        Ok(()) => {
                            // Either the delivery worker owns the job (durable
                            // counters advance after write) or a full/closed
                            // queue already restaged under delivery ownership.
                            invalidate_status_cache();
                            return;
                        }
                        // Admission refused (worker closing): recover the event
                        // (the lease drops here, releasing its export-queue byte
                        // reservation) and fall through to bounded staging.
                        Err(mut returned) => match returned.pop() {
                            Some(queued) => queued.event,
                            None => return,
                        },
                    }
                }
                // Export byte budget exhausted: stage the original event below.
                None => event,
            }
        }
        None => event,
    };
    stage_overflow_events_or_reject(
        &lifecycle.accumulator,
        metrics,
        lifecycle.generation,
        vec![event],
    );
}

/// Stage overflow charges into bounded pending state, or record a genuine
/// cardinality loss for any that the retained-byte budget cannot hold.
fn stage_overflow_events_or_reject(
    accumulator: &SnapshotAccumulator,
    metrics: &SinkMetrics,
    generation: u64,
    events: Vec<ChargeEvent>,
) {
    let mut rejected = 0u64;
    for event in events {
        if accumulator.stage_overflow_event(event) {
            metrics
                .snapshot_overflow_pending_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            rejected = rejected.saturating_add(1);
        }
    }
    if rejected > 0 {
        metrics
            .snapshot_cardinality_rejections_total
            .fetch_add(rejected, Ordering::Relaxed);
        warn!(
            plugin = PLUGIN_NAME,
            generation,
            rejected,
            "Chargeback sink snapshot cardinality budget exhausted and overflow could not be staged; restore spool capacity"
        );
    }
    invalidate_status_cache();
}

/// Reserve the process-ceiling charge for a delta projection **before** it is
/// built.
///
/// The projection (`ChargeEvent`s plus their `emitted_totals` key clones) is an
/// attacker-shaped copy that coexists with the still-charged accumulator, so it
/// must own a reservation for its whole life. Refusal is retryable: no baseline
/// is advanced and nothing is discarded.
fn reserve_delta_projection(
    accumulator: &SnapshotAccumulator,
    config: &ApiChargebackSinkConfig,
    node_id: &str,
) -> Result<GrowableProcessReservation, String> {
    let bound = accumulator
        .delta_projection_bound(snapshot_event_extra_bytes(config, node_id))
        .ok_or_else(|| {
            format!(
                "{PLUGIN_NAME}: {}",
                PayloadMaterializationError::BoundOverflowed.reason()
            )
        })?;
    let reservation = GrowableProcessReservation::new(process_ceiling());
    if !reservation.try_grow(bound) {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot delta projection deferred: {}",
            PayloadMaterializationError::CeilingExhausted.reason()
        ));
    }
    Ok(reservation)
}

/// Return the leading `overflow_count` events of a borrowed emission set to
/// bounded overflow staging.
///
/// The emission paths take staged overflow rather than cloning it. Every path
/// that does not reach the durable commit point must give it back, or a pending
/// billing delta would be silently lost. Prepared deltas beyond `overflow_count`
/// are intentionally dropped: no baseline was advanced, so they are still held
/// by the accumulator.
fn restage_borrowed_overflow(
    accumulator: &SnapshotAccumulator,
    mut events: Vec<ChargeEvent>,
    overflow_count: usize,
    overflow_retained_bytes: usize,
) {
    if overflow_count == 0 {
        debug_assert_eq!(overflow_retained_bytes, 0);
        return;
    }
    events.truncate(overflow_count);
    accumulator.restore_taken_overflow(TakenOverflow {
        events,
        retained_bytes: overflow_retained_bytes,
    });
    invalidate_status_cache();
}

/// Attacker-shaped copies of one accumulator identity that a delta projection
/// holds at once: the emitted `ChargeEvent` and the `emitted_totals` key clone.
const SNAPSHOT_PROJECTION_COPIES: usize = 2;
/// ULID text length (`event_id`, `snapshot_id`).
const SNAPSHOT_ULID_TEXT_BYTES: usize = 26;

/// Per-event bytes a projected `ChargeEvent` carries beyond the accumulator key
/// it is derived from: its own identifiers and the configured currency and
/// pricing version.
fn snapshot_event_extra_bytes(config: &ApiChargebackSinkConfig, node_id: &str) -> usize {
    SNAPSHOT_ULID_TEXT_BYTES
        .saturating_mul(2)
        .saturating_add(node_id.len().min(MAX_FIELD_LEN))
        .saturating_add(config.currency.len())
        .saturating_add(config.pricing_version.len())
}

fn snapshot_metadata_retained_bytes(meta: &SnapshotMetadata) -> usize {
    let mut total = 128usize;
    total = total.saturating_add(meta.namespace.len());
    total = total.saturating_add(meta.consumer_id.len());
    total = total.saturating_add(meta.consumer_name.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(meta.proxy_id.len());
    total = total.saturating_add(meta.proxy_name.len());
    total = total.saturating_add(meta.route_id.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(meta.protocol.len());
    total
}

fn charge_event_retained_bytes(event: &ChargeEvent) -> usize {
    let mut total = 96usize;
    total = total.saturating_add(event.event_id.len());
    total = total.saturating_add(event.node_id.len());
    total = total.saturating_add(event.namespace.len());
    total = total.saturating_add(event.consumer_id.len());
    total = total.saturating_add(event.consumer_name.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(event.proxy_id.len());
    total = total.saturating_add(event.proxy_name.len());
    total = total.saturating_add(event.route_id.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(event.protocol.len());
    total = total.saturating_add(event.currency.len());
    total = total.saturating_add(event.pricing_version.len());
    total = total.saturating_add(event.request_id.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(event.trace_id.as_ref().map(String::len).unwrap_or(0));
    total = total.saturating_add(event.snapshot_id.as_ref().map(String::len).unwrap_or(0));
    total
}

fn enqueue_charge_event(runtime: &SinkRuntime, event: ChargeEvent) {
    let retained = charge_event_retained_bytes(&event);
    if retained > MAX_CHARGE_EVENT_BYTES {
        runtime
            .byte_budget
            .record_drop("charge event exceeded max retained bytes");
        invalidate_status_cache();
        return;
    }
    let Some(lease) = runtime.byte_budget.try_acquire(retained) else {
        runtime
            .metrics
            .queue_byte_budget_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
        invalidate_status_cache();
        return;
    };
    match runtime
        .logger
        .try_send_outcome(QueuedChargeEvent { event, lease })
    {
        TrySendOutcome::ChannelAccepted | TrySendOutcome::DiversionAccepted => {
            runtime
                .metrics
                .events_enqueued_total
                .fetch_add(1, Ordering::Relaxed);
        }
        TrySendOutcome::BufferFull => {
            // Genuine full in-memory channel with no accepted durable ownership.
            runtime
                .metrics
                .queue_full_drops_total
                .fetch_add(1, Ordering::Relaxed);
        }
        TrySendOutcome::DiversionRejected | TrySendOutcome::WorkerUnavailable => {
            // DiversionRejected: spool delivery saturation/closure already
            // recorded spool job/event loss. WorkerUnavailable: shutdown must
            // not masquerade as a full-buffer drop.
        }
    }
    invalidate_status_cache();
}

/// Bound a **display-only** field. Never use this for a value that
/// participates in a snapshot key or an exported billing identity — see
/// [`bound_key_field`].
fn bound_string(value: &str, max_len: usize) -> String {
    crate::plugins::chargeback::bounded_display(value, max_len).to_string()
}

/// Bound a field that is part of the snapshot accumulator key or the exported
/// billing identity.
///
/// Prefix truncation here would merge two distinct authenticated principals
/// (or two distinct routes/proxies) that share a prefix into one exported row
/// and, in snapshot mode, into one accumulator entry that combines both
/// parties' calls, bytes, and charges (GHSA-m28c-f3v5-26qg). Oversized values
/// therefore keep a readable prefix plus a domain-separated digest of the
/// complete value, which is stable, collision-resistant, and still bounded.
///
/// Authenticated external identities are additionally capped at the
/// authentication boundary
/// ([`crate::plugins::utils::auth_flow::MAX_AUTHENTICATED_IDENTITY_BYTES`]), so
/// in practice this path is reached only by long operator-configured Consumer
/// usernames, display names, or route identifiers.
fn bound_key_field(value: &str, max_len: usize) -> String {
    crate::plugins::chargeback::bounded_billing_identity(value, max_len).into_owned()
}

fn normalize_snapshot_grpc_status(status: u32) -> u32 {
    if status <= 16 {
        status
    } else {
        GRPC_STATUS_OTHER_SENTINEL
    }
}

fn non_negative_delta(current: f64, last: f64, field: &str) -> Result<f64, String> {
    if !current.is_finite() || !last.is_finite() {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot {field} is non-finite (current={current}, last={last})"
        ));
    }
    if current < last {
        return Err(format!(
            "{PLUGIN_NAME}: snapshot {field} regressed (current={current}, last={last})"
        ));
    }
    Ok(current - last)
}

fn add_f64_atomic(slot: &AtomicU64, delta: f64) {
    loop {
        let old = slot.load(Ordering::Relaxed);
        let new_val = f64::from_bits(old) + delta;
        match slot.compare_exchange_weak(
            old,
            new_val.to_bits(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
}

pub fn new_ulid() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const RANDOM_MASK: u128 = (1u128 << 80) - 1;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
        & 0x0000_FFFF_FFFF_FFFF;
    let seq = ULID_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let random_prefix =
        *ULID_RANDOM_PREFIX.get_or_init(|| uuid::Uuid::new_v4().as_u128() & RANDOM_MASK);
    let value = ((millis as u128) << 80) | (random_prefix.wrapping_add(seq) & RANDOM_MASK);
    let mut encoded = [b'0'; 26];
    let mut n = value;
    for idx in (0..26).rev() {
        encoded[idx] = ALPHABET[(n & 0x1f) as usize];
        n >>= 5;
    }
    String::from_utf8_lossy(&encoded).into_owned()
}

fn resolve_node_id() -> String {
    std::env::var("FERRUM_NODE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
        })
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| bound_string(value.trim(), MAX_FIELD_LEN))
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn unix_timestamp_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn timestamp_json(timestamp: i64) -> Value {
    if timestamp <= 0 {
        Value::Null
    } else {
        match Utc.timestamp_opt(timestamp, 0).single() {
            Some(dt) => Value::String(dt.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => Value::Null,
        }
    }
}

#[cfg(test)]
mod snapshot_cleanup_race_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn test_metadata() -> SnapshotMetadata {
        SnapshotMetadata {
            namespace: "ferrum".to_string(),
            consumer_id: "alice".to_string(),
            consumer_name: None,
            proxy_id: "proxy-a".to_string(),
            proxy_name: "Payments".to_string(),
            route_id: None,
            status_code: 200,
            http_status_code: Some(200),
            grpc_status: None,
            protocol: "http".to_string(),
        }
    }

    fn call_charge(call_count: u32, price: f64) -> ChargeComputation {
        ChargeComputation {
            call_count,
            charge_call: price,
            charge_total: price,
            ..ChargeComputation::default()
        }
    }

    #[test]
    fn cleanup_loses_race_to_same_key_refresh_after_stale_check() {
        // Deterministic issue #2576 interleaving: park cleanup after candidate
        // selection, refresh the same key, then prove conditional eviction
        // preserves and emits the refresh exactly once.
        let config = ApiChargebackSinkConfig {
            mode: SinkMode::Snapshot,
            currency: "USD".to_string(),
            pricing_version: "test-v1".to_string(),
            ..Default::default()
        };

        let accumulator = Arc::new(SnapshotAccumulator::new());
        let metadata = test_metadata();
        accumulator.record_at(metadata.clone(), call_charge(1, 0.01), 100);
        assert_eq!(
            accumulator
                .compute_deltas(&config, "node-a", 100, "snap-1")
                .expect("initial delta")
                .len(),
            1
        );

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        accumulator.set_cleanup_after_stale_check_hook(Some(Arc::new({
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.wait();
                release.wait();
            }
        })));

        let cleanup_accumulator = Arc::clone(&accumulator);
        let cleanup =
            thread::spawn(move || cleanup_accumulator.cleanup_stale(200, /* ttl */ 0));

        entered.wait();
        accumulator.record_at(metadata, call_charge(2, 0.02), 201);
        release.wait();

        assert_eq!(
            cleanup.join().expect("cleanup thread"),
            0,
            "conditional eviction must preserve a same-key refresh"
        );
        accumulator.set_cleanup_after_stale_check_hook(None);
        assert_eq!(accumulator.entries.len(), 1);
        assert_eq!(accumulator.last_emitted.len(), 1);

        let delta = accumulator
            .compute_deltas(&config, "node-a", 200, "snap-2")
            .expect("refresh delta");
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].call_count, 2);
        assert!((delta[0].charge_total - 0.02).abs() < f64::EPSILON);
        assert!(
            accumulator
                .compute_deltas(&config, "node-a", 300, "snap-3")
                .expect("post-refresh delta")
                .is_empty(),
            "refreshed charge must emit exactly once"
        );
    }
}
