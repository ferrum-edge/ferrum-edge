//! Process-global logging plumbing shared across the library and binary.
//!
//! The binary owns `tracing_subscriber` setup (`src/main.rs::init_logging`),
//! but the RTDS log-level overlay consumer needs to reach the same reload
//! handle from the library. Storing the reloader behind a tiny dyn trait
//! lets the binary register a concrete `tracing_subscriber::reload::Handle`
//! at startup while keeping the library free of the generic subscriber
//! type.

use std::sync::OnceLock;

use serde::Serialize;

pub mod non_blocking;
pub mod runtime_overlay;

pub use non_blocking::{
    ErrorCounter, NonBlockingOptions, NonBlockingSink, SinkName, SinkSnapshot, WorkerGuard,
};

// Process-log defaults and clamp ranges are consumed before EnvConfig exists,
// then retained on EnvConfig for diagnostics/documentation parity. Keep the
// numeric policy here so both startup paths use one source of truth.
pub const LOG_BUFFER_CAPACITY_DEFAULT: usize = 4_096;
pub const LOG_BUFFER_CAPACITY_MIN: usize = 1;
pub const LOG_BUFFER_CAPACITY_MAX: usize = 65_536;
pub const LOG_BUFFER_BYTES_DEFAULT: usize = 32 * 1_048_576;
pub const LOG_BUFFER_BYTES_MIN: usize = 1_024;
pub const LOG_BUFFER_BYTES_MAX: usize = 1_073_741_824;
pub const LOG_MAX_RECORD_BYTES_DEFAULT: usize = 65_536;
pub const LOG_MAX_RECORD_BYTES_MIN: usize = 1_024;
pub const LOG_MAX_RECORD_BYTES_MAX: usize = 1_048_576;
pub const LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_DEFAULT: usize = 2_000;
pub const LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MIN: usize = 100;
pub const LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MAX: usize = 30_000;
/// Aggregate admitted terminal/mirror/deadline-cleanup task budget.
///
/// Distinct from queue byte/count limits: this caps the pre-queue Tokio task
/// and registry layer. Overflow rejects immediately (non-blocking).
pub const LOG_DELIVERY_MAX_TASKS_DEFAULT: usize = 4_096;
pub const LOG_DELIVERY_MAX_TASKS_MIN: usize = 1;
pub const LOG_DELIVERY_MAX_TASKS_MAX: usize = 1_048_576;

/// Stable callback that knows how to rebuild the gateway-wide tracing
/// filter. `directive` is a `RUST_LOG`-style filter expression
/// (`"info"`, `"ferrum_edge=trace,hyper=warn"`, etc.). Implementations must
/// be cheap to call — slice install runs on the mesh runtime hot-swap path
/// and a slow handler would stall every config update.
pub trait LogLevelReloader: Send + Sync + 'static {
    fn reload(&self, directive: &str) -> Result<(), String>;
}

/// Errors returned by [`set_log_level_reloader`]. Single variant for now;
/// reserved for future expansion without bumping the function signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetReloaderError {
    /// A reloader has already been installed for the process; the new
    /// reloader was discarded and the existing one remains in effect.
    AlreadyInstalled,
}

static RELOADER: OnceLock<Box<dyn LogLevelReloader>> = OnceLock::new();

/// Register the process-global reloader. Returns
/// [`SetReloaderError::AlreadyInstalled`] when a reloader has already been
/// installed (the second caller's value is discarded — the existing
/// reloader stays in place).
///
/// Called once from the binary's `init_logging`. The library never calls
/// this; the RTDS consumer only reads. Tests can register a capturing
/// reloader through the same entry point.
pub fn set_log_level_reloader(reloader: Box<dyn LogLevelReloader>) -> Result<(), SetReloaderError> {
    RELOADER
        .set(reloader)
        .map_err(|_| SetReloaderError::AlreadyInstalled)
}

/// Read access for consumers. `None` when no reloader has been registered
/// yet (e.g. early startup before `init_logging`, validate-only mode, unit
/// tests). Consumers must tolerate that — RTDS log overrides become a
/// no-op rather than a hard error.
pub fn log_level_reloader() -> Option<&'static dyn LogLevelReloader> {
    RELOADER.get().map(|reloader| reloader.as_ref())
}

/// Dependency log targets whose records render credential-bearing protocol
/// bytes verbatim, each with the level from which its records are dropped.
/// The gateway never emits those records, whatever `RUST_LOG`,
/// `FERRUM_LOG_LEVEL`, or an RTDS `ferrum.log.level` reload requests.
///
/// - `tungstenite::handshake::client`, from DEBUG: logs the complete
///   serialized WebSocket upgrade request at TRACE, meaning the request target
///   (path and query) and every header, including a proxied client's
///   `Authorization` / `Cookie` and the `ws_logging` `custom_headers` collector
///   credentials. Its only other record is a DEBUG "handshake done" line.
/// - `tungstenite::protocol` (including `::frame`), at TRACE: renders every
///   received message and every sent/received frame with its full payload,
///   which carries in-band WebSocket credentials and every `ws_logging` batch.
///   The module's DEBUG close-frame lines stay available.
///
/// Neither module logs at INFO or above, so no warning or error is lost.
pub const CREDENTIAL_DUMPING_LOG_TARGETS: &[(&str, tracing::Level)] = &[
    ("tungstenite::handshake::client", tracing::Level::DEBUG),
    ("tungstenite::protocol", tracing::Level::TRACE),
];

/// Whether `target` is `module` or one of its submodules.
fn log_target_within(target: &str, module: &str) -> bool {
    target
        .strip_prefix(module)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

/// Whether a record with this metadata belongs to a
/// [`CREDENTIAL_DUMPING_LOG_TARGETS`] target at or below its drop level.
/// `log`-crate records bridged into `tracing` carry the emitting module path
/// as their target, so they match the same way as native events.
pub fn is_credential_dumping_log_record(metadata: &tracing::Metadata<'_>) -> bool {
    CREDENTIAL_DUMPING_LOG_TARGETS
        .iter()
        .any(|(module, from_level)| {
            log_target_within(metadata.target(), module) && *metadata.level() >= *from_level
        })
}

fn allows_non_credential_dumping_record(metadata: &tracing::Metadata<'_>) -> bool {
    !is_credential_dumping_log_record(metadata)
}

/// Per-layer filter that drops [`is_credential_dumping_log_record`] records.
///
/// Compose it through [`filter_output_layer`], never on its own: the two
/// per-layer filters there are AND-ed, so no directive can re-enable these
/// records: not a target, span-scoped, or field-scoped one
/// (`tungstenite::handshake::client[{message}]=trace`), and not an RTDS
/// reload, which replaces only the level filter.
pub fn credential_dumping_log_filter() -> tracing_subscriber::filter::FilterFn {
    tracing_subscriber::filter::filter_fn(
        allows_non_credential_dumping_record as fn(&tracing::Metadata<'_>) -> bool,
    )
}

/// Filters a gateway output layer by `level_filter` (the reloadable
/// `EnvFilter`) AND [`credential_dumping_log_filter`].
///
/// The level filter must stay the outermost per-layer filter. The outermost
/// filter alone supplies the layer's max-level hint, which feeds the
/// process-wide `LevelFilter::current()` (the maximum over every output and
/// counting layer) that each `tracing` macro checks before anything else.
/// Nesting also merges callsite interests: an outer `always` over an inner
/// `never` becomes `sometimes`. With the hint-less credential filter outside
/// (#6852), every TRACE/DEBUG callsite in hyper, h2, and tokio was evaluated
/// dynamically on every hit even at `FERRUM_LOG_LEVEL=error`. With the level
/// filter outside, a callsite that a static (target/level) directive disables
/// registers `never` and is skipped by the max-level check. Span- and
/// field-scoped directives still evaluate dynamically, by `EnvFilter`'s
/// design, as they did before #6852. The credential filter still vetoes
/// every record the level filter enables.
pub fn filter_output_layer<L, F, S>(
    layer: L,
    level_filter: F,
) -> tracing_subscriber::filter::Filtered<
    tracing_subscriber::filter::Filtered<L, tracing_subscriber::filter::FilterFn, S>,
    F,
    S,
>
where
    L: tracing_subscriber::Layer<S>,
    F: tracing_subscriber::layer::Filter<S> + 'static,
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span> + 'static,
{
    use tracing_subscriber::Layer as _;

    layer
        .with_filter(credential_dumping_log_filter())
        .with_filter(level_filter)
}

/// Process-global, non-blocking sink for transaction access logs.
///
/// The `stdout_logging` plugin writes one JSON line per proxied transaction
/// or stream disconnect. It must not perform a synchronous
/// `std::io::stdout().lock()` write on the proxy hot path — under stdout
/// backpressure that blocks a Tokio worker thread and stalls the runtime. It
/// must also stay independent of `FERRUM_LOG_LEVEL`: access logging is a
/// plugin-enablement decision, not a diagnostic verbosity knob, so lowering
/// the runtime log level must never silence it.
///
/// `init_logging` installs the same bounded stdout sink used by the fmt layer.
/// The sink enforces both record and byte budgets and exposes independent
/// saturation, I/O, flush, and shutdown-drain counters.
struct ProcessLogSinks {
    stdout: NonBlockingSink,
    stderr: NonBlockingSink,
    stdout_errors: ErrorCounter,
    stderr_errors: ErrorCounter,
}

static PROCESS_LOG_SINKS: OnceLock<ProcessLogSinks> = OnceLock::new();

/// Install the process-global stdout/stderr sinks. Called once from the
/// binary's `init_logging`; a second call returns an error and leaves the
/// original sinks in place.
pub fn set_process_log_sinks(
    stdout: NonBlockingSink,
    stderr: NonBlockingSink,
) -> Result<(), &'static str> {
    let stdout_errors = stdout.error_counter();
    let stderr_errors = stderr.error_counter();
    PROCESS_LOG_SINKS
        .set(ProcessLogSinks {
            stdout,
            stderr,
            stdout_errors,
            stderr_errors,
        })
        .map_err(|_| "process log sinks are already installed")
}

/// Read access for the access-log sink. `None` before `init_logging` runs
/// (unit/library contexts). Callers must remain non-blocking and may skip
/// output; the gateway binary treats sink initialization failure as fatal.
pub fn access_log_writer() -> Option<&'static NonBlockingSink> {
    PROCESS_LOG_SINKS.get().map(|sinks| &sinks.stdout)
}

#[derive(Debug, Clone, Serialize)]
pub struct LoggingSnapshot {
    pub stdout: Option<SinkSnapshot>,
    pub stderr: Option<SinkSnapshot>,
}

pub fn snapshot() -> LoggingSnapshot {
    match PROCESS_LOG_SINKS.get() {
        Some(sinks) => LoggingSnapshot {
            stdout: Some(sinks.stdout.snapshot()),
            stderr: Some(sinks.stderr.snapshot()),
        },
        None => LoggingSnapshot {
            stdout: None,
            stderr: None,
        },
    }
}

/// Render process log sink telemetry with fixed labels only. This is appended
/// to the authenticated `/metrics` response and never written through either
/// log sink, avoiding recursive failure reporting.
pub fn render_prometheus() -> String {
    let Some(sinks) = PROCESS_LOG_SINKS.get() else {
        return String::new();
    };
    let mut output = String::with_capacity(2_048);
    output.push_str(
        "# HELP ferrum_log_sink_healthy Whether the process log sink has recovered from its latest I/O or drain failure.\n\
# TYPE ferrum_log_sink_healthy gauge\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_queued_records Records admitted but not yet completed.\n\
# TYPE ferrum_log_sink_queued_records gauge\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_reserved_bytes Byte budget reserved by admitted records.\n\
# TYPE ferrum_log_sink_reserved_bytes gauge\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_queued_bytes Serialized bytes admitted but not yet completed.\n\
# TYPE ferrum_log_sink_queued_bytes gauge\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_accepted_records_total Records accepted by the bounded process log sink.\n\
# TYPE ferrum_log_sink_accepted_records_total counter\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_dropped_records_total Log records dropped by bounded admission.\n\
# TYPE ferrum_log_sink_dropped_records_total counter\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_shutdown_timeouts_total Bounded process log drain deadlines reached.\n\
# TYPE ferrum_log_sink_shutdown_timeouts_total counter\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_shutdown_incomplete_records_total Records still outstanding when a bounded drain deadline was reached.\n\
# TYPE ferrum_log_sink_shutdown_incomplete_records_total counter\n",
    );
    output.push_str(
        "# HELP ferrum_log_sink_io_failures_total Underlying writer and flush failures.\n\
# TYPE ferrum_log_sink_io_failures_total counter\n",
    );
    for (sink, error_counter) in [
        (&sinks.stdout, &sinks.stdout_errors),
        (&sinks.stderr, &sinks.stderr_errors),
    ] {
        let snapshot = sink.snapshot();
        let name = snapshot.sink.as_str();
        output.push_str(&format!(
            "ferrum_log_sink_healthy{{sink=\"{name}\"}} {}\n",
            u8::from(snapshot.healthy)
        ));
        output.push_str(&format!(
            "ferrum_log_sink_queued_records{{sink=\"{name}\"}} {}\n",
            snapshot.queued_records
        ));
        output.push_str(&format!(
            "ferrum_log_sink_reserved_bytes{{sink=\"{name}\"}} {}\n",
            snapshot.reserved_bytes
        ));
        output.push_str(&format!(
            "ferrum_log_sink_queued_bytes{{sink=\"{name}\"}} {}\n",
            snapshot.queued_bytes
        ));
        output.push_str(&format!(
            "ferrum_log_sink_accepted_records_total{{sink=\"{name}\"}} {}\n",
            snapshot.accepted_records_total
        ));
        for (reason, value) in [
            ("saturation", error_counter.saturation_dropped_records()),
            (
                "record_too_large",
                error_counter.oversized_dropped_records(),
            ),
            ("closed", error_counter.closed_dropped_records()),
        ] {
            output.push_str(&format!(
                "ferrum_log_sink_dropped_records_total{{sink=\"{name}\",reason=\"{reason}\"}} {value}\n"
            ));
        }
        output.push_str(&format!(
            "ferrum_log_sink_shutdown_timeouts_total{{sink=\"{name}\"}} {}\n",
            snapshot.shutdown_timeouts_total
        ));
        output.push_str(&format!(
            "ferrum_log_sink_shutdown_incomplete_records_total{{sink=\"{name}\"}} {}\n",
            snapshot.shutdown_incomplete_records_total
        ));
        for (operation, value) in [
            ("write", snapshot.writer_failures_total),
            ("flush", snapshot.flush_failures_total),
        ] {
            output.push_str(&format!(
                "ferrum_log_sink_io_failures_total{{sink=\"{name}\",operation=\"{operation}\"}} {value}\n"
            ));
        }
    }
    output
}
