//! Process-global logging plumbing shared across the library and binary.
//!
//! The binary owns `tracing_subscriber` setup (`src/main.rs::init_logging`),
//! but the RTDS log-level overlay consumer needs to reach the same reload
//! handle from the library. Storing the reloader behind a tiny dyn trait
//! lets the binary register a concrete `tracing_subscriber::reload::Handle`
//! at startup while keeping the library free of the generic subscriber
//! type.

use std::sync::OnceLock;

use tracing_appender::non_blocking::NonBlocking;

pub mod runtime_overlay;

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
/// `init_logging` (in the binary) installs a clone of the same
/// `tracing_appender` non-blocking stdout writer the fmt layers use. Writing
/// here is a bounded-channel send handled off-thread, and the writer bypasses
/// the `EnvFilter`/`SeverityWriter` tracing stack entirely. The plugin holds
/// only a sender clone; the flush-on-exit `WorkerGuard` stays owned by
/// `run_gateway()`.
static ACCESS_LOG_WRITER: OnceLock<NonBlocking> = OnceLock::new();

/// Install the process-global access-log writer. Called once from the
/// binary's `init_logging`. A second call is a no-op (the first writer
/// stays in effect), matching the single-install contract of the rest of
/// this module.
pub fn set_access_log_writer(writer: NonBlocking) {
    let _ = ACCESS_LOG_WRITER.set(writer);
}

/// Read access for the access-log sink. `None` before `init_logging` runs
/// (validate-only mode, unit tests). Callers must fall back to a direct
/// write so output is still produced in those contexts.
pub fn access_log_writer() -> Option<&'static NonBlocking> {
    ACCESS_LOG_WRITER.get()
}
