//! Bounded, non-blocking process log sinks with explicit loss accounting.
//!
//! Producers reserve both a record slot and the configured maximum record
//! budget before formatting, then shrink the byte reservation to the actual
//! serialized length before enqueue. Queued records use exact-sized boxed
//! slices so spare `Vec` capacity cannot escape the byte budget. A dedicated
//! OS thread owns the blocking writer; request/runtime threads only perform
//! atomic admission plus a fixed-queue push.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use serde::Serialize;
use tracing_subscriber::fmt::MakeWriter;

use crate::secrets::LogRecordSource;

const FAILURE_NOTICE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkName {
    Stdout,
    Stderr,
}

impl SinkName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl fmt::Display for SinkName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NonBlockingOptions {
    pub record_capacity: usize,
    pub byte_capacity: usize,
    pub max_record_bytes: usize,
    pub shutdown_timeout: Duration,
}

impl NonBlockingOptions {
    fn normalized(self) -> Self {
        let max_record_bytes = self.max_record_bytes.max(1);
        Self {
            record_capacity: self.record_capacity.max(1),
            byte_capacity: self.byte_capacity.max(max_record_bytes),
            max_record_bytes,
            shutdown_timeout: self.shutdown_timeout,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SinkFailure {
    pub operation: &'static str,
    pub error_kind: &'static str,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SinkSnapshot {
    pub sink: SinkName,
    pub healthy: bool,
    pub accepting: bool,
    pub queue_capacity_records: usize,
    pub queue_capacity_bytes: usize,
    pub max_record_bytes: usize,
    pub queued_records: usize,
    pub reserved_bytes: usize,
    pub queued_bytes: usize,
    pub accepted_records_total: u64,
    pub saturation_dropped_records_total: u64,
    pub oversized_dropped_records_total: u64,
    pub closed_dropped_records_total: u64,
    pub writer_failures_total: u64,
    pub flush_failures_total: u64,
    pub shutdown_timeouts_total: u64,
    pub shutdown_incomplete_records_total: u64,
    pub last_failure: Option<SinkFailure>,
}

/// Retained producer-side loss counter handle.
///
/// Stdout runtime events and `stdout_logging` access records intentionally
/// share one handle because they share one queue. Stderr owns a separate
/// handle, so operators can distinguish access/stdout loss from diagnostic
/// loss without adding attacker-controlled labels.
#[derive(Clone)]
pub struct ErrorCounter {
    state: Arc<SinkState>,
}

impl ErrorCounter {
    pub fn saturation_dropped_records(&self) -> u64 {
        self.state.saturation_dropped.load(Ordering::Relaxed)
    }

    pub fn oversized_dropped_records(&self) -> u64 {
        self.state.oversized_dropped.load(Ordering::Relaxed)
    }

    pub fn closed_dropped_records(&self) -> u64 {
        self.state.closed_dropped.load(Ordering::Relaxed)
    }
}

struct WorkerCompletion {
    finished: Mutex<bool>,
    wake: Condvar,
}

impl WorkerCompletion {
    fn new() -> Self {
        Self {
            finished: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn finish(&self) {
        let mut finished = match self.finished.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *finished = true;
        self.wake.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let finished = match self.finished.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *finished {
            return true;
        }
        let waited = self
            .wake
            .wait_timeout_while(finished, timeout, |done| !*done);
        match waited {
            Ok((guard, _)) => *guard,
            Err(poisoned) => *poisoned.into_inner().0,
        }
    }
}

struct SinkState {
    name: SinkName,
    options: NonBlockingOptions,
    accepting: AtomicBool,
    healthy: AtomicBool,
    outstanding_records: AtomicUsize,
    reserved_bytes: AtomicUsize,
    queued_bytes: AtomicUsize,
    accepted_records: AtomicU64,
    saturation_dropped: AtomicU64,
    oversized_dropped: AtomicU64,
    closed_dropped: AtomicU64,
    writer_failures: AtomicU64,
    flush_failures: AtomicU64,
    shutdown_timeouts: AtomicU64,
    shutdown_incomplete_records: AtomicU64,
    last_failure: Mutex<Option<SinkFailure>>,
    fallback: OnceLock<NonBlockingSink>,
    last_failure_notice: Mutex<Option<Instant>>,
    worker_thread: OnceLock<std::thread::Thread>,
    completion: WorkerCompletion,
}

impl SinkState {
    fn try_reserve(&self) -> Result<(), EnqueueResult> {
        if !self.accepting.load(Ordering::Acquire) {
            self.closed_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueResult::Closed);
        }

        if self
            .outstanding_records
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.options.record_capacity).then_some(current + 1)
            })
            .is_err()
        {
            self.saturation_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueResult::Saturated);
        }

        let max_record_bytes = self.options.max_record_bytes;
        let byte_reserved = self
            .reserved_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(max_record_bytes)
                    .filter(|next| *next <= self.options.byte_capacity)
            })
            .is_ok();
        if !byte_reserved {
            self.release_record_slot();
            self.saturation_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueResult::Saturated);
        }

        if !self.accepting.load(Ordering::Acquire) {
            self.release_reservation(self.options.max_record_bytes);
            self.closed_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueResult::Closed);
        }
        Ok(())
    }

    fn release_reserved_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        // Every caller owns this many bytes from a successful reservation.
        // checked_sub prevents a bookkeeping bug from wrapping the public
        // gauge even in optimized builds.
        let _ = self
            .reserved_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(bytes)
            });
    }

    fn shrink_reservation(&self, reserved: usize, actual: usize) {
        if let Some(excess) = reserved.checked_sub(actual) {
            self.release_reserved_bytes(excess);
        }
    }

    fn release_reservation(&self, reserved_bytes: usize) {
        self.release_reserved_bytes(reserved_bytes);
        self.release_record_slot();
    }

    fn release_record_slot(&self) {
        let became_idle = self
            .outstanding_records
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_ok_and(|previous| previous == 1);
        // A producer can reserve and then abandon a record while shutdown is
        // waiting. Wake the worker when that final reservation disappears so
        // plain park() cannot strand the drain.
        if became_idle && !self.accepting.load(Ordering::Acquire) {
            self.wake_worker();
        }
    }

    fn wake_worker(&self) {
        if let Some(worker) = self.worker_thread.get() {
            worker.unpark();
        }
    }

    fn record_failure(&self, operation: &'static str, error_kind: &'static str) {
        self.healthy.store(false, Ordering::Release);
        let failure = SinkFailure {
            operation,
            error_kind,
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        };
        let mut last = match self.last_failure.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *last = Some(failure);
        drop(last);
        self.maybe_emit_failure_notice(operation, error_kind);
    }

    fn maybe_emit_failure_notice(&self, operation: &'static str, error_kind: &'static str) {
        if self.name != SinkName::Stdout {
            return;
        }
        let Some(fallback) = self.fallback.get() else {
            return;
        };
        let now = Instant::now();
        let mut last = match self.last_failure_notice.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.is_some_and(|previous| now.duration_since(previous) < FAILURE_NOTICE_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);

        let notice = format!(
            "{{\"level\":\"ERROR\",\"target\":\"ferrum_edge::logging\",\"message\":\"stdout log sink failure\",\"operation\":\"{operation}\",\"error_kind\":\"{error_kind}\"}}\n"
        );
        // A fixed literal carrying the fmt layer's own root envelope, so it is
        // submitted as one: its `level`/`target`/`message` keys are structural
        // here, unlike the same spellings in an access record.
        let _ = fallback.write_bytes_from(notice.as_bytes(), LogRecordSource::TracingEnvelope);
    }

    fn snapshot(&self) -> SinkSnapshot {
        // Failure counters are the publication barrier for their associated
        // health and last-failure details. Load them first so a snapshot that
        // observes a new counter value also observes the diagnostic state the
        // worker stored before incrementing that counter.
        let writer_failures_total = self.writer_failures.load(Ordering::Acquire);
        let flush_failures_total = self.flush_failures.load(Ordering::Acquire);
        let shutdown_timeouts_total = self.shutdown_timeouts.load(Ordering::Acquire);
        let last_failure = match self.last_failure.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        SinkSnapshot {
            sink: self.name,
            healthy: self.healthy.load(Ordering::Acquire),
            accepting: self.accepting.load(Ordering::Acquire),
            queue_capacity_records: self.options.record_capacity,
            queue_capacity_bytes: self.options.byte_capacity,
            max_record_bytes: self.options.max_record_bytes,
            queued_records: self.outstanding_records.load(Ordering::Acquire),
            reserved_bytes: self.reserved_bytes.load(Ordering::Acquire),
            queued_bytes: self.queued_bytes.load(Ordering::Acquire),
            accepted_records_total: self.accepted_records.load(Ordering::Relaxed),
            saturation_dropped_records_total: self.saturation_dropped.load(Ordering::Relaxed),
            oversized_dropped_records_total: self.oversized_dropped.load(Ordering::Relaxed),
            closed_dropped_records_total: self.closed_dropped.load(Ordering::Relaxed),
            writer_failures_total,
            flush_failures_total,
            shutdown_timeouts_total,
            shutdown_incomplete_records_total: self
                .shutdown_incomplete_records
                .load(Ordering::Relaxed),
            last_failure,
        }
    }
}

#[derive(Clone)]
pub struct NonBlockingSink {
    queue: Arc<ArrayQueue<Box<[u8]>>>,
    state: Arc<SinkState>,
}

impl NonBlockingSink {
    pub fn spawn<W>(
        name: SinkName,
        writer: W,
        options: NonBlockingOptions,
    ) -> io::Result<(Self, WorkerGuard)>
    where
        W: Write + Send + 'static,
    {
        let options = options.normalized();
        let queue = Arc::new(ArrayQueue::new(options.record_capacity));
        let state = Arc::new(SinkState {
            name,
            options,
            accepting: AtomicBool::new(true),
            healthy: AtomicBool::new(true),
            outstanding_records: AtomicUsize::new(0),
            reserved_bytes: AtomicUsize::new(0),
            queued_bytes: AtomicUsize::new(0),
            accepted_records: AtomicU64::new(0),
            saturation_dropped: AtomicU64::new(0),
            oversized_dropped: AtomicU64::new(0),
            closed_dropped: AtomicU64::new(0),
            writer_failures: AtomicU64::new(0),
            flush_failures: AtomicU64::new(0),
            shutdown_timeouts: AtomicU64::new(0),
            shutdown_incomplete_records: AtomicU64::new(0),
            last_failure: Mutex::new(None),
            fallback: OnceLock::new(),
            last_failure_notice: Mutex::new(None),
            worker_thread: OnceLock::new(),
            completion: WorkerCompletion::new(),
        });
        let worker_state = Arc::clone(&state);
        let worker_queue = Arc::clone(&queue);
        let thread_name = format!("ferrum-log-{name}");
        let join = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || run_worker(writer, worker_queue, worker_state))?;
        let _ = state.worker_thread.set(join.thread().clone());
        let sink = Self { queue, state };
        let guard = WorkerGuard {
            state: Arc::clone(&sink.state),
            join: Some(join),
            shutdown_started: false,
        };
        Ok((sink, guard))
    }

    pub fn error_counter(&self) -> ErrorCounter {
        ErrorCounter {
            state: Arc::clone(&self.state),
        }
    }

    pub fn snapshot(&self) -> SinkSnapshot {
        self.state.snapshot()
    }

    /// Install a separate non-blocking sink for bounded failure notices.
    /// Only stdout uses this; stderr failures never recurse into stderr.
    pub fn set_failure_fallback(&self, fallback: Self) -> Result<(), &'static str> {
        if self.state.name != SinkName::Stdout || fallback.state.name != SinkName::Stderr {
            return Err("failure fallback must connect stdout to a separate stderr sink");
        }
        self.state
            .fallback
            .set(fallback)
            .map_err(|_| "stdout failure fallback is already installed")
    }

    pub fn try_write_json<T: Serialize + ?Sized>(
        &self,
        value: &T,
    ) -> Result<EnqueueResult, serde_json::Error> {
        // Access records: no tracing envelope, so no key in them is structural.
        // `log_schema` puts operator strings at the root (`rename:`,
        // `static_fields:`, flattened `metadata`), which is precisely where the
        // envelope names would otherwise be waved through.
        let mut record = match RecordWriter::reserved(self, false, LogRecordSource::Dynamic) {
            Ok(record) => record,
            Err(outcome) => return Ok(outcome),
        };
        if let Err(error) = serde_json::to_writer(&mut record, value) {
            if record.oversized {
                record.discard_oversized();
                return Ok(EnqueueResult::RecordTooLarge);
            }
            return Err(error);
        }
        let _ = record.write_all(b"\n");
        if record.oversized {
            record.discard_oversized();
            return Ok(EnqueueResult::RecordTooLarge);
        }
        Ok(record.submit())
    }

    /// Enqueue pre-serialized bytes from an unidentified producer.
    ///
    /// Treated as [`LogRecordSource::Dynamic`]: a caller handing over opaque
    /// bytes cannot vouch that any key in them is tracing-envelope structure.
    /// This stays the only public byte entrypoint so that provenance cannot be
    /// asserted from outside; `write_bytes_from` is deliberately not exposed.
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn try_write_bytes(&self, bytes: &[u8]) -> EnqueueResult {
        self.write_bytes_from(bytes, LogRecordSource::Dynamic)
    }

    fn write_bytes_from(&self, bytes: &[u8], source: LogRecordSource) -> EnqueueResult {
        let mut record = match RecordWriter::reserved(self, false, source) {
            Ok(record) => record,
            Err(outcome) => return outcome,
        };
        let _ = record.write_all(bytes);
        if record.oversized {
            record.discard_oversized();
            return EnqueueResult::RecordTooLarge;
        }
        record.submit()
    }

    fn tracing_writer(&self) -> RecordWriter {
        // The only producer that genuinely carries the fmt layer's envelope.
        match RecordWriter::reserved(self, true, LogRecordSource::TracingEnvelope) {
            Ok(writer) => writer,
            Err(_) => RecordWriter::discarding(self.clone()),
        }
    }
}

impl<'a> MakeWriter<'a> for NonBlockingSink {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.tracing_writer()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    Queued,
    Saturated,
    RecordTooLarge,
    Closed,
}

pub struct RecordWriter {
    sink: NonBlockingSink,
    bytes: Vec<u8>,
    reserved: bool,
    reserved_bytes: usize,
    oversized: bool,
    auto_submit: bool,
    /// Which producer opened this record. Carried to `submit()` so the
    /// structural redactor knows whether the tracing envelope applies; see
    /// `secrets::LogRecordSource`.
    source: LogRecordSource,
}

impl RecordWriter {
    fn reserved(
        sink: &NonBlockingSink,
        auto_submit: bool,
        source: LogRecordSource,
    ) -> Result<Self, EnqueueResult> {
        sink.state.try_reserve()?;
        let initial_capacity = sink.state.options.max_record_bytes.min(1_024);
        Ok(Self {
            sink: sink.clone(),
            bytes: Vec::with_capacity(initial_capacity),
            reserved: true,
            reserved_bytes: sink.state.options.max_record_bytes,
            oversized: false,
            auto_submit,
            source,
        })
    }

    fn discarding(sink: NonBlockingSink) -> Self {
        Self {
            sink,
            bytes: Vec::new(),
            reserved: false,
            reserved_bytes: 0,
            oversized: false,
            auto_submit: false,
            // Never submitted, so the value is inert; the conservative one.
            source: LogRecordSource::Dynamic,
        }
    }

    fn discard_oversized(&mut self) {
        if self.reserved {
            self.sink
                .state
                .oversized_dropped
                .fetch_add(1, Ordering::Relaxed);
            self.sink.state.release_reservation(self.reserved_bytes);
            self.reserved = false;
            self.reserved_bytes = 0;
        }
        self.bytes.clear();
    }

    fn oversized_write_result(&self, input_len: usize) -> io::Result<usize> {
        if self.auto_submit {
            Ok(input_len)
        } else {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        }
    }

    fn submit(&mut self) -> EnqueueResult {
        if !self.reserved {
            return EnqueueResult::Saturated;
        }
        if self.oversized {
            self.discard_oversized();
            return EnqueueResult::RecordTooLarge;
        }

        // Emission boundary for externally resolved secret values. This is the
        // one place a tracing record exists as complete bytes before it leaves
        // the process, so it is where a `warn!`/`info!` emitted *during*
        // config parsing — which never passes through a returned `Result` and
        // so is untouched by the sanitizers on the `validate`/`run` error
        // paths — stops echoing a value fetched from `_FILE`/`_VAULT`/`_AWS`/
        // `_AZURE`/`_GCP`. Costs one relaxed atomic load when no external
        // secret was resolved, which is every process that does not use them.
        //
        // Every producer that reaches here emits a JSON document (the fmt
        // layer is `.json()`, access records go through `try_write_json`, and
        // the failure notice above is a JSON literal), and the redactor treats
        // it as one: it rewrites values and dynamic keys, never JSON syntax,
        // and withholds a record it cannot parse. A resolved value has no
        // minimum length, so a flat text substitution here would let a
        // one-character secret rewrite the record's own delimiters.
        //
        // `self.source` is why a key is judged by provenance rather than
        // spelling: `filename` is the fmt layer's structural field *and* a name
        // `log_schema` can hand an access record, and the bytes alone cannot
        // tell those apart.
        crate::secrets::redact_log_record(&mut self.bytes, self.source);
        if self.bytes.len() > self.sink.state.options.max_record_bytes {
            // Substitution can grow a record past the admission bound. Drop it
            // through the existing oversized path (counted in
            // `oversized_dropped`) rather than enqueueing a payload the byte
            // reservation did not cover: losing one diagnostic is acceptable,
            // breaking the reservation invariant or printing the secret is not.
            self.discard_oversized();
            return EnqueueResult::RecordTooLarge;
        }

        // Vec growth can retain substantially more capacity than its length.
        // Convert to an exact-sized allocation before enqueueing so the byte
        // reservation remains a hard bound on retained queue payloads.
        let bytes = std::mem::take(&mut self.bytes).into_boxed_slice();
        let len = bytes.len();
        // Admission reserves max_record_bytes before attacker-shaped data is
        // serialized. Once serialization succeeds, retain only the actual
        // record length so the aggregate byte budget reflects queued payload
        // memory instead of pessimistically reducing capacity until I/O ends.
        self.sink.state.shrink_reservation(self.reserved_bytes, len);
        self.reserved_bytes = len;
        self.sink
            .state
            .queued_bytes
            .fetch_add(len, Ordering::Release);
        let result = match self.sink.queue.push(bytes) {
            Ok(()) => {
                self.sink
                    .state
                    .accepted_records
                    .fetch_add(1, Ordering::Relaxed);
                self.sink.state.wake_worker();
                EnqueueResult::Queued
            }
            Err(bytes) => {
                self.sink
                    .state
                    .queued_bytes
                    .fetch_sub(bytes.len(), Ordering::Release);
                self.sink
                    .state
                    .saturation_dropped
                    .fetch_add(1, Ordering::Relaxed);
                self.sink.state.release_reservation(self.reserved_bytes);
                EnqueueResult::Saturated
            }
        };
        self.reserved = false;
        self.reserved_bytes = 0;
        result
    }
}

impl Write for RecordWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.reserved {
            return Ok(bytes.len());
        }
        if self.oversized {
            return self.oversized_write_result(bytes.len());
        }
        let Some(next_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.oversized = true;
            self.bytes.clear();
            return self.oversized_write_result(bytes.len());
        };
        if next_len > self.sink.state.options.max_record_bytes {
            self.oversized = true;
            self.bytes.clear();
            return self.oversized_write_result(bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        if self.auto_submit {
            let _ = self.submit();
        } else {
            self.sink.state.release_reservation(self.reserved_bytes);
            self.reserved = false;
            self.reserved_bytes = 0;
        }
    }
}

pub struct WorkerGuard {
    state: Arc<SinkState>,
    join: Option<JoinHandle<()>>,
    shutdown_started: bool,
}

impl WorkerGuard {
    pub fn shutdown(&mut self) -> bool {
        if self.shutdown_started {
            let completed = self.state.completion.wait(Duration::ZERO);
            if completed && let Some(join) = self.join.take() {
                let _ = join.join();
            }
            return completed;
        }
        self.shutdown_started = true;
        self.state.accepting.store(false, Ordering::Release);
        if let Some(join) = &self.join {
            join.thread().unpark();
        }

        let completed = self
            .state
            .completion
            .wait(self.state.options.shutdown_timeout);
        if completed {
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            return true;
        }

        let incomplete = self.state.outstanding_records.load(Ordering::Acquire) as u64;
        self.state.record_failure("shutdown", "drain_timeout");
        self.state
            .shutdown_incomplete_records
            .fetch_add(incomplete, Ordering::Relaxed);
        self.state.shutdown_timeouts.fetch_add(1, Ordering::Release);
        false
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_worker<W>(mut writer: W, queue: Arc<ArrayQueue<Box<[u8]>>>, state: Arc<SinkState>)
where
    W: Write,
{
    loop {
        if let Some(bytes) = queue.pop() {
            write_record(&mut writer, bytes, &state);
            continue;
        }
        if !state.accepting.load(Ordering::Acquire)
            && state.outstanding_records.load(Ordering::Acquire) == 0
        {
            break;
        }
        // submit(), shutdown(), and the final abandoned reservation all unpark
        // this worker. Thread park tokens make the queue-empty/check/park
        // sequence safe when a wake arrives immediately before park().
        std::thread::park();
    }

    if let Err(error) = writer.flush() {
        state.record_failure("flush", io_error_kind(&error));
        state.flush_failures.fetch_add(1, Ordering::Release);
    }
    state.completion.finish();
}

fn write_record<W: Write>(writer: &mut W, bytes: Box<[u8]>, state: &SinkState) {
    let len = bytes.len();
    match writer.write_all(bytes.as_ref()) {
        Ok(()) => state.healthy.store(true, Ordering::Release),
        Err(error) => {
            state.record_failure("write", io_error_kind(&error));
            state.writer_failures.fetch_add(1, Ordering::Release);
        }
    }
    state.queued_bytes.fetch_sub(len, Ordering::Release);
    state.release_reservation(len);
}

fn io_error_kind(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::BrokenPipe => "broken_pipe",
        io::ErrorKind::WriteZero => "write_zero",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::Interrupted => "interrupted",
        io::ErrorKind::WouldBlock => "would_block",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::NotConnected => "not_connected",
        _ => "other",
    }
}
