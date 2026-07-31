// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod adaptive_buffer;
mod adaptive_concurrency;
mod admin;
mod backend_conn_limit;
mod backend_pending_limit;
mod capture;
mod circuit_breaker;
mod cli;
// CNI surface types: shared library for the `ferrum-cni` binary
// (`src/bin/ferrum-cni.rs`). The `ferrum-edge` binary itself only consumes
// the `rpc` submodule via `crate::modes::node_agent_cni_server`, so most
// of the `spec` types appear unused from the gateway's perspective.
#[allow(dead_code)]
mod cni;
mod config;
mod config_delta;
#[allow(dead_code)]
mod config_sources;
mod connection_pool;
mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
mod custom_plugins;
mod date_cache;
mod dns;
mod dtls;
mod ebpf;
mod grpc;
mod health_check;
mod http3;
#[allow(dead_code)]
mod identity;
#[allow(dead_code)]
mod k8s_controller;
#[allow(dead_code)]
mod lazy_timeout;
mod load_balancer;
mod logging;
mod metrics;
mod modes;
// The reusable notification surface intentionally exposes helpers used by the
// library's external tests and future producers that the binary does not yet
// call directly.
#[allow(dead_code)]
mod notifications;
mod observability_delivery;
mod overload;
mod plugin_cache;
mod plugins;
mod policy_path;
mod pool;
mod proxy;
pub mod request_epoch;
mod retry;
mod router_cache;
mod runtime_metrics;
mod runtime_metrics_tracing_layer;
mod secrets;
mod service_discovery;
mod socket_opts;
mod startup;
mod system_metrics;
mod tls;
#[allow(dead_code)]
mod tls_offload;
mod util;
mod xds;

use clap::Parser;
use config::{AdminHttpExposure, EnvConfig, OperatingMode};
use tracing::{Level, Metadata, debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

/// The Ferrum Edge binary version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Severity-routing `MakeWriter` that splits log events across stdout and
/// stderr non-blocking appenders:
///
/// | Level         | Sink   | Reasoning                                         |
/// |---------------|--------|---------------------------------------------------|
/// | `ERROR`       | stderr | Fatal/failure signals — Unix convention, what process supervisors (systemd, Kubernetes liveness), alerting pipelines, and `2>&1`-style scripts key off. |
/// | `WARN`        | stderr | Non-fatal but operator-noteworthy: matches `cargo`, `gcc`, `make`, and most CLI ecosystems that treat warnings as diagnostic output rather than "primary output". |
/// | `INFO`        | stdout | Normal operational telemetry — this is what log aggregators (Fluentd/Promtail/Vector) ship; belongs with the bulk of structured-JSON output. |
/// | `DEBUG`/`TRACE` | stdout | Developer-facing verbose output, gated behind `FERRUM_LOG_LEVEL=debug`/`trace`. Staying on stdout keeps them in the same stream as INFO so developers tailing a container see a contiguous timeline. |
///
/// Both sinks use Ferrum's bounded non-blocking worker, so the hot path remains
/// an atomic admission plus fixed-queue push rather than blocking I/O. The worker
/// guards are owned by `run_gateway()` and perform a bounded drain on exit.
struct SeverityWriter {
    stdout: logging::NonBlockingSink,
    stderr: logging::NonBlockingSink,
}

impl<'a> MakeWriter<'a> for SeverityWriter {
    type Writer = logging::non_blocking::RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        // Called when no metadata is available (e.g., some tracing internals).
        // Default to stdout to match the pre-split behavior.
        self.stdout.make_writer()
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        // ERROR and WARN → stderr; INFO/DEBUG/TRACE → stdout.
        // See the type-level docstring above for the level → sink table
        // and the rationale for each row.
        match *meta.level() {
            Level::ERROR | Level::WARN => self.stderr.make_writer(),
            Level::INFO | Level::DEBUG | Level::TRACE => self.stdout.make_writer(),
        }
    }
}

/// Emit a structured bootstrap diagnostic before the tracing subscriber can
/// safely start. This path is intentionally synchronous: secret resolution
/// mutates environment variables immediately after it runs, so starting
/// logging worker threads before that point would weaken the startup safety
/// invariant around process env mutation.
fn emit_bootstrap_error(message: &str, fields: &[(&str, String)]) {
    let mut event = serde_json::Map::new();
    event.insert(
        "timestamp".to_string(),
        serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
    );
    event.insert(
        "level".to_string(),
        serde_json::Value::String("ERROR".to_string()),
    );
    event.insert(
        "target".to_string(),
        serde_json::Value::String("ferrum_edge::bootstrap".to_string()),
    );
    event.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    for (key, value) in fields {
        // This writer bypasses the tracing sink, so it also bypasses the
        // emission-boundary redaction in `RecordWriter::submit`. Bootstrap
        // errors raised *after* secret resolution succeeded (a logging-init
        // failure on an externally resolved `FERRUM_LOG_*` value, say) would
        // otherwise echo the fetched value; before it, this is a no-op.
        event.insert(
            (*key).to_string(),
            serde_json::Value::String(secrets::redact_external_secret_values(value)),
        );
    }

    let mut stderr = std::io::stderr().lock();
    if serde_json::to_writer(&mut stderr, &serde_json::Value::Object(event)).is_err() {
        let _ = std::io::Write::write_all(&mut stderr, message.as_bytes());
    }
    let _ = std::io::Write::write_all(&mut stderr, b"\n");
}

/// Entry point for the Ferrum Edge gateway binary.
///
/// Startup sequence:
/// 1. Parse CLI arguments
/// 2. Install rustls crypto provider (ring backend)
/// 3. Resolve external secrets (Vault, AWS, Azure, GCP, env, file) using a
///    temporary runtime that is dropped before env mutation
/// 4. Initialize structured JSON logging
/// 5. Parse environment configuration (`EnvConfig::from_env()`)
/// 6. Build the multi-threaded tokio runtime with configured worker/blocking threads
/// 7. Dispatch to the appropriate operating mode (database, file, cp, dp, mesh, injector, migrate)
///    — each mode then loads TLS certs (frontend, admin, DTLS, gRPC) and validates
///    per-proxy backend TLS paths before starting listeners
/// 8. Wait for SIGINT/SIGTERM for graceful shutdown
fn main() {
    // ── CLI parsing ─────────────────────────────────────────────────────
    // Parse before anything else so `--settings`/`--spec`/`--mode` env var
    // overrides are in place before `CONF_FILE_CACHE` OnceLock is triggered
    // by `resolve_ferrum_var()` during logging init (line ~95 below).
    let cli = cli::Cli::parse();

    // Handle early-exit subcommands that don't need the startup pipeline.
    match &cli.command {
        Some(cli::Command::Version(args)) => {
            cli::execute_version(args);
            return;
        }
        Some(cli::Command::Reload(args)) => {
            match cli::execute_reload(args) {
                Ok(()) => {}
                Err(e) => {
                    emit_bootstrap_error(
                        "admin CLI reload failed",
                        &[("command", "reload".to_string()), ("error", e.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(cli::Command::Health(args)) => {
            match cli::execute_health(args) {
                Ok(()) => {}
                Err(e) => {
                    emit_bootstrap_error(
                        "admin CLI health check failed",
                        &[("command", "health".to_string()), ("error", e.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            return;
        }
        _ => {}
    }

    // Apply CLI overrides before anything reads config (OnceLock ordering).
    match &cli.command {
        Some(cli::Command::Run(args)) => cli::apply_run_overrides(args),
        Some(cli::Command::Validate(args)) => cli::apply_validate_overrides(args),
        _ => {}
    }

    // ── Crypto provider ─────────────────────────────────────────────────
    // Initialize rustls crypto provider (needed by validate for TLS cert checks)
    if rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .is_err()
    {
        emit_bootstrap_error("failed to install rustls crypto provider", &[]);
        std::process::exit(1);
    }

    // Initialize tracing/logging with non-blocking writers and run the
    // rest of startup + the gateway in `run_gateway`. Keeping the bounded
    // worker guards local to that helper ensures every exit path
    // attempts its configured drain, including errors. A
    // `std::process::exit()` inline inside main would bypass the guards'
    // destructors and silently drop buffered log events, which is exactly
    // what would make a test captor of stderr see nothing after a fatal
    // error.
    let exit_code = run_gateway(&cli);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

struct LoggingGuards {
    stdout: Option<logging::WorkerGuard>,
    stderr: Option<logging::WorkerGuard>,
}

impl Drop for LoggingGuards {
    fn drop(&mut self) {
        // Keep stderr accepting while stdout drains so the stdout worker can
        // emit at most one rate-limited constant failure notice to the separate
        // stderr queue. Neither path writes recursively into stdout.
        if let Some(mut stdout) = self.stdout.take() {
            let _ = stdout.shutdown();
        }
        if let Some(mut stderr) = self.stderr.take() {
            let _ = stderr.shutdown();
        }
    }
}

struct ResolvedLoggingUsize {
    name: &'static str,
    applied: usize,
    supplied: Option<usize>,
}

fn resolve_logging_usize(
    name: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<ResolvedLoggingUsize, String> {
    let Some(value) = config::conf_file::resolve_ferrum_var(name) else {
        return Ok(ResolvedLoggingUsize {
            name,
            applied: default,
            supplied: None,
        });
    };
    let supplied = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {name}: expected an unsigned integer"))?;
    Ok(ResolvedLoggingUsize {
        name,
        applied: supplied.clamp(min, max),
        supplied: Some(supplied),
    })
}

fn init_logging() -> Result<LoggingGuards, String> {
    let log_buffer_capacity = resolve_logging_usize(
        "FERRUM_LOG_BUFFER_CAPACITY",
        logging::LOG_BUFFER_CAPACITY_DEFAULT,
        logging::LOG_BUFFER_CAPACITY_MIN,
        logging::LOG_BUFFER_CAPACITY_MAX,
    )?;
    let max_record_bytes = resolve_logging_usize(
        "FERRUM_LOG_MAX_RECORD_BYTES",
        logging::LOG_MAX_RECORD_BYTES_DEFAULT,
        logging::LOG_MAX_RECORD_BYTES_MIN,
        logging::LOG_MAX_RECORD_BYTES_MAX,
    )?;
    let log_buffer_bytes = resolve_logging_usize(
        "FERRUM_LOG_BUFFER_BYTES",
        logging::LOG_BUFFER_BYTES_DEFAULT,
        logging::LOG_BUFFER_BYTES_MIN.max(max_record_bytes.applied),
        logging::LOG_BUFFER_BYTES_MAX,
    )?;
    let shutdown_timeout_ms = resolve_logging_usize(
        "FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS",
        logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_DEFAULT,
        logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MIN,
        logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MAX,
    )?;
    let options = logging::NonBlockingOptions {
        record_capacity: log_buffer_capacity.applied,
        byte_capacity: log_buffer_bytes.applied,
        max_record_bytes: max_record_bytes.applied,
        shutdown_timeout: std::time::Duration::from_millis(shutdown_timeout_ms.applied as u64),
    };
    let (stdout_writer, stdout_guard) =
        logging::NonBlockingSink::spawn(logging::SinkName::Stdout, std::io::stdout(), options)
            .map_err(|error| format!("failed to start stdout logging worker: {error}"))?;
    let (stderr_writer, stderr_guard) =
        logging::NonBlockingSink::spawn(logging::SinkName::Stderr, std::io::stderr(), options)
            .map_err(|error| format!("failed to start stderr logging worker: {error}"))?;
    stdout_writer.set_failure_fallback(stderr_writer.clone())?;
    // Hand the access-log sink (the `stdout_logging` plugin) a clone of the
    // non-blocking stdout writer so per-transaction JSON lines go through the
    // same backpressure-aware worker thread the tracing layers use, but
    // bypass the `EnvFilter`/`SeverityWriter` stack. That keeps access logs
    // (a) off the Tokio hot path — a fixed-queue push, never a blocking
    // `stdout().lock()` write — and (b) decoupled from `FERRUM_LOG_LEVEL`, so
    // lowering runtime verbosity never silences them and the plugin's
    // enablement is the only on/off switch. Set before the branches below
    // move `stdout_writer` into the fallback fmt layer.
    crate::logging::set_process_log_sinks(stdout_writer.clone(), stderr_writer.clone())?;
    let log_level =
        config::conf_file::resolve_ferrum_var("FERRUM_LOG_LEVEL").unwrap_or_else(|| "warn".into());
    let log_counter_enabled =
        config::conf_file::resolve_ferrum_var("FERRUM_METRICS_LOG_COUNTER_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(true);

    // GAP-3E: wrap the fmt-layer filter in a `reload::Layer` so the
    // mesh RTDS log-level consumer can rebuild it at runtime. The
    // log-counter layer keeps its own filter — its sole job is per-target
    // metric counting, and reloading two filters from one RTDS knob would
    // double-charge events that count once and surface twice. Only the
    // visible fmt filter responds to `ferrum.log.level`.
    let installed = if log_counter_enabled {
        let fmt_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
        let (fmt_reload_layer, fmt_handle) = reload::Layer::new(fmt_filter);
        let log_counter_level_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(SeverityWriter {
                stdout: stdout_writer.clone(),
                stderr: stderr_writer.clone(),
            })
            .with_filter(fmt_reload_layer);
        let log_counter_filter = filter_fn(|metadata| {
            crate::runtime_metrics_tracing_layer::should_count_target(metadata.target())
        });
        let init_ok = tracing_subscriber::registry()
            .with(fmt_layer)
            .with(
                crate::runtime_metrics_tracing_layer::CountingLayer::new(
                    crate::runtime_metrics::global(),
                )
                .with_filter(log_counter_filter)
                .with_filter(log_counter_level_filter),
            )
            .try_init()
            .is_ok();
        if init_ok {
            register_log_level_reloader(fmt_handle);
        }
        init_ok
    } else {
        false
    };

    if !installed {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
        let (reload_layer, fallback_handle) = reload::Layer::new(env_filter);
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(SeverityWriter {
                stdout: stdout_writer,
                stderr: stderr_writer,
            })
            .with_filter(reload_layer);
        if tracing_subscriber::registry()
            .with(fmt_layer)
            .try_init()
            .is_ok()
        {
            register_log_level_reloader(fallback_handle);
        }
    }

    for resolved in [
        &log_buffer_capacity,
        &log_buffer_bytes,
        &max_record_bytes,
        &shutdown_timeout_ms,
    ] {
        if let Some(supplied) = resolved.supplied
            && supplied != resolved.applied
        {
            // Key-tied: a short clamped scalar (`1`, `99`, …) is below the
            // derived-candidate minimum, so structured fields must not carry
            // the raw numbers when the variable was externally resolved.
            warn!(
                variable = resolved.name,
                supplied_value = %secrets::report_env_field(resolved.name, &supplied.to_string()),
                applied_value =
                    %secrets::report_env_field(resolved.name, &resolved.applied.to_string()),
                "logging configuration value was clamped"
            );
        }
    }

    Ok(LoggingGuards {
        stdout: Some(stdout_guard),
        stderr: Some(stderr_guard),
    })
}

/// Adapter that turns a `tracing_subscriber::reload::Handle` into the
/// process-global `crate::logging::LogLevelReloader` consumed by the mesh
/// RTDS overlay path. Kept in `main.rs` so the binary owns the concrete
/// subscriber type and the library stays subscriber-generic.
struct EnvFilterReloader<S>
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    handle: reload::Handle<EnvFilter, S>,
}

impl<S> crate::logging::LogLevelReloader for EnvFilterReloader<S>
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    fn reload(&self, directive: &str) -> Result<(), String> {
        let filter = EnvFilter::try_new(directive)
            .map_err(|e| format!("invalid filter directive '{directive}': {e}"))?;
        self.handle
            .reload(filter)
            .map_err(|e| format!("tracing reload failed: {e}"))
    }
}

fn register_log_level_reloader<S>(handle: reload::Handle<EnvFilter, S>)
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    // Best-effort: a second registration loses the new handle quietly so
    // an internal init bug never panics the binary at startup.
    let _ = crate::logging::set_log_level_reloader(Box::new(EnvFilterReloader { handle }));
}

/// Resolve external secret suffixes (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`,
/// `_GCP`) into their base `FERRUM_*` variables and apply the result to the
/// process environment.
///
/// Runs on a temporary single-threaded runtime that is dropped before the
/// environment is mutated, and must be called before non-blocking logging or
/// any multi-threaded runtime exists. Shared by `run` and `validate` so both
/// commands see identical configuration and identical resolution/conflict
/// failures; secret values are never logged. The returned metadata lets each
/// caller report which base variables and providers were loaded after tracing
/// is initialized (never source references or values).
fn resolve_startup_secrets() -> Result<secrets::ResolvedEnvSecrets, String> {
    let resolved = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to create secret resolution runtime: {}", e))?;

        rt.block_on(secrets::resolve_all_env_secrets())?
    };

    // `std::env::set_var` panics on a value containing a NUL byte, and a
    // resolved value is attacker-adjacent input (a `_FILE` source pointing at a
    // binary blob, a cloud backend handing back non-text material). Startup
    // resolution now runs before any settings are parsed, so a panic here would
    // abort `validate` before it could report anything at all. `registry`
    // already rejects these as ordinary fetch failures; re-checking at the one
    // site that actually calls `set_var` keeps that invariant local to the
    // unsafe block that depends on it. The value is never named.
    if let Some((base_key, _)) = resolved.vars.iter().find(|(_, v)| v.contains('\0')) {
        return Err(format!(
            "Secret resolved for {base_key} contains a NUL byte and cannot be placed in the process environment."
        ));
    }

    // SAFETY: Secret resolution completed before non-blocking logging or the
    // main multi-threaded runtime were created, and the temporary runtime
    // above has already been dropped. We mutate the environment before any
    // later startup stage can spawn additional worker threads. Every value is
    // NUL-free per the check above, so `set_var` cannot panic.
    unsafe {
        for (base_key, value) in &resolved.vars {
            std::env::set_var(base_key, value);
        }
        for suffixed_key in &resolved.source_keys_to_remove {
            std::env::remove_var(suffixed_key);
        }
    }

    // Record which base variables now hold externally resolved material, before
    // any configuration is parsed. Everything downstream that renders a config
    // failure — `EnvConfig`'s typed parse boundary and the sanitizers on the
    // `validate`/`run` error paths — keys off this set to withhold the value
    // while still naming the variable.
    secrets::record_external_secret_keys(
        resolved
            .vars
            .iter()
            .map(|(base_key, _value)| base_key.to_string()),
    );

    Ok(resolved)
}

/// Report non-secret startup resolution metadata for `run`, after tracing is
/// initialized.
///
/// Serving modes are long-lived log producers, so this stays on the structured
/// `info!` path and inherits `FERRUM_LOG_LEVEL`/`RUST_LOG` like every other
/// startup record. `validate` deliberately does not use this path — see
/// [`print_resolved_secret_sources`].
///
/// Only base variable names and backend display names are emitted. Secret
/// values and source references (file paths, Vault paths, cloud resource IDs)
/// are never included.
fn log_resolved_secret_sources(resolved: &secrets::ResolvedEnvSecrets) {
    for (base_key, backend_name) in &resolved.loaded_sources {
        info!("Loaded {} from {}", base_key, backend_name);
    }
    if !resolved.vars.is_empty() {
        info!(
            "Resolved {} env var(s) from external secret sources",
            resolved.vars.len()
        );
    }
}

/// Print the external-secret resolution report as part of `validate`'s
/// operator-facing stdout report.
///
/// `validate` is a one-shot reporting command: every other thing it tells the
/// operator (`Settings (ferrum.conf): OK`, `Mode:`, `Spec (...): OK`,
/// `Validation passed.`) is an unconditional `println!`, not a tracing record.
/// The secret-source report is the same kind of output and is emitted the same
/// way, for three reasons:
///
/// 1. **It is part of the report surface, not diagnostic logging.** Every other
///    line `validate` prints (`Settings (ferrum.conf): OK`, `Mode:`,
///    `Spec (...): OK`, `Validation passed.`) is an unconditional `println!`,
///    not a tracing record. The secret-source report is the same kind of output
///    and is emitted the same way, so it appears alongside the rest of the
///    report rather than being filtered by `FERRUM_LOG_LEVEL` (which defaults
///    to `warn`) or gated behind `-v/--verbose`.
/// 2. **It is deterministically flushed.** `println!` goes straight to the
///    process stdout `LineWriter` and is flushed at the newline, so the report
///    cannot be lost to the non-blocking tracing sink's guard-drop drain racing
///    `std::process::exit()`.
/// 3. **Ordering is stable.** It lands with the rest of the validate report on
///    the same writer, rather than interleaving across two writers on one fd.
///
/// Only base variable names and backend display names are printed. Secret
/// values and source references are never included, exactly as in
/// [`log_resolved_secret_sources`].
fn print_resolved_secret_sources(resolved: &secrets::ResolvedEnvSecrets) {
    if resolved.vars.is_empty() {
        return;
    }
    println!("External secrets: OK");
    for (base_key, backend_name) in &resolved.loaded_sources {
        println!("  Loaded {} from {}", base_key, backend_name);
    }
    println!(
        "  Resolved {} env var(s) from external secret sources",
        resolved.vars.len()
    );
}

/// Runs startup secret resolution, logging init, env-config parsing, and the
/// gateway runtime. Returns the process exit code.
///
/// The bounded logging guards are local here, so every return path attempts a
/// lifecycle-owned drain before `main()` can call `std::process::exit()`.
/// Drain timeout and incomplete-record accounting are explicit rather than
/// hidden inside a dependency guard. Normal startup resolves secrets before
/// these worker threads exist so the temporary runtime can fully shut down
/// before unsafe env mutation.
fn run_gateway(cli: &cli::Cli) -> i32 {
    // Handle validate subcommand: resolve secrets, load config, validate, exit.
    // Runs after crypto init so TLS cert checks work, but before the
    // multi-threaded runtime. External secret suffixes resolve with the same
    // semantics as `run` so validation sees the identical configuration
    // picture (and the same provider-conflict/fetch failures).
    if matches!(&cli.command, Some(cli::Command::Validate(_))) {
        let resolved = match resolve_startup_secrets() {
            Ok(resolved) => resolved,
            Err(error) => {
                emit_bootstrap_error("secret resolution failed", &[("error", error)]);
                return 1;
            }
        };
        // Lowest-precedence mode selection, deliberately after resolution: a
        // `FERRUM_MODE_*` source is now materialized and wins, a secret-backed
        // spec path is now visible as `FERRUM_FILE_CONFIG_PATH`, and the
        // settings file named by a resolved `FERRUM_CONF_PATH` is the one
        // consulted for a configured mode. See `cli::infer_file_mode`.
        cli::infer_file_mode();
        let _logging_guards = match init_logging() {
            Ok(guards) => guards,
            Err(error) => {
                emit_bootstrap_error("logging initialization failed", &[("error", error)]);
                return 1;
            }
        };
        // Printed after logging init so any warning emitted by a later stage
        // still has a live subscriber, and before `execute_validate()` so the
        // report reads in resolution order: secrets, then settings, then spec.
        print_resolved_secret_sources(&resolved);
        match cli::execute_validate() {
            Ok(()) => return 0,
            Err(e) => {
                // Settings and spec validation run against an environment that
                // now contains externally resolved secrets, and their messages
                // interpolate the offending value. Filter the rendered failure
                // against the keys resolved above so `validate` cannot echo
                // fetched secret material.
                error!(
                    "Validation error: {}",
                    secrets::redact_external_secret_values(&e)
                );
                return 1;
            }
        }
    }

    // Resolve secrets before initializing non-blocking logging so the
    // temporary runtime can shut down completely before env mutation.
    let resolved = match resolve_startup_secrets() {
        Ok(resolved) => resolved,
        Err(error) => {
            emit_bootstrap_error("secret resolution failed", &[("error", error)]);
            return 1;
        }
    };

    // Same lowest-precedence mode selection as the `validate` branch above, and
    // for the same reasons. Scoped to `run` because that is the only serving
    // entry point whose CLI overrides were applied in `main()`.
    if matches!(&cli.command, Some(cli::Command::Run(_))) {
        cli::infer_file_mode();
    }

    let _logging_guards = match init_logging() {
        Ok(guards) => guards,
        Err(error) => {
            emit_bootstrap_error("logging initialization failed", &[("error", error)]);
            return 1;
        }
    };

    // Raise the soft FD cap to the hard cap before any subsystem opens
    // sockets. The call never asks for privileges we don't have (it caps at
    // the existing hard limit), so a sandboxed/seccomp-restricted run is a
    // silent no-op rather than a failure. We log the result so operators see
    // the headroom they actually got, and emit a warn when the effective
    // soft cap remains below the production floor — the gateway will still
    // run, but its 95% FD-critical threshold will trigger early on busy hosts.
    let fd_raise = overload::raise_fd_limit();
    if fd_raise.raised {
        info!(
            soft_before = fd_raise.soft_before,
            soft_after = fd_raise.soft_after,
            hard = fd_raise.hard,
            "raised soft FD limit to hard cap"
        );
    }
    if fd_raise.soft_after > 0 && fd_raise.soft_after < overload::FD_HARD_LIMIT_PRODUCTION_FLOOR {
        warn!(
            soft_before = fd_raise.soft_before,
            soft_after = fd_raise.soft_after,
            hard = fd_raise.hard,
            recommended_floor = overload::FD_HARD_LIMIT_PRODUCTION_FLOOR,
            "effective soft FD limit is {} (hard cap {}); recommend raising to >= {} via /etc/security/limits.conf, systemd LimitNOFILE=, or docker --ulimit nofile= for production workloads",
            fd_raise.soft_after,
            fd_raise.hard,
            overload::FD_HARD_LIMIT_PRODUCTION_FLOOR,
        );
    } else if !fd_raise.raised && fd_raise.hard > 0 {
        debug!(
            soft = fd_raise.soft_after,
            hard = fd_raise.hard,
            "FD soft limit already at hard cap"
        );
    }

    info!(
        "Ferrum Edge v{} ({}) starting...",
        env!("CARGO_PKG_VERSION"),
        env!("TARGET")
    );
    log_resolved_secret_sources(&resolved);

    // Load environment config (now includes any resolved secrets)
    let env_config = match EnvConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            // Same redaction contract as `validate`: a settings failure on an
            // externally resolved variable names the variable, never its value.
            error!(
                "Configuration error: {}",
                secrets::redact_external_secret_values(&e)
            );
            return 1;
        }
    };

    // Apply the delayed-work admission budget before any listener can accept
    // traffic, so a fault-injection delay is never admitted against the
    // compiled-in default when the operator configured a smaller bound.
    crate::plugins::utils::fault_delay::init_fault_delay_admission(
        env_config.max_concurrent_fault_delays,
    );

    // Initialize DTLS buffer config from resolved EnvConfig before any DTLS sessions.
    crate::dtls::init_dtls_buf_config(
        env_config.dtls_max_plaintext_bytes,
        env_config.dtls_record_overhead_bytes,
    );

    // Key-tied, not left to the emission-boundary redactor: this line re-renders
    // the value rather than echoing it, so a `FERRUM_MODE_FILE` holding
    // `database` would reach the sink as `Database` — a form
    // `secrets::derive_candidates` deliberately does not produce. See
    // `secrets::report_env_field`. `{:?}` on the withheld path would re-quote
    // the placeholder, so the rendering is formatted first and printed as `{}`.
    info!(
        "Operating mode: {}",
        secrets::report_env_field("FERRUM_MODE", &format!("{:?}", env_config.mode))
    );
    info!(
        "Proxy bind address: {}, Admin bind address: {}",
        secrets::report_env_field("FERRUM_PROXY_BIND_ADDRESS", &env_config.proxy_bind_address),
        secrets::report_env_field("FERRUM_ADMIN_BIND_ADDRESS", &env_config.admin_bind_address)
    );
    // Surface the plaintext admin HTTP listener's network exposure. The
    // unsafe writable-mode case (database/cp, public, no allowlist, no opt-in)
    // already aborted in `EnvConfig::validate()`; the warnings below cover the
    // remaining live postures (allowlisted, read-only modes, or the explicit
    // dev escape hatch).
    match env_config.admin_http_exposure() {
        AdminHttpExposure::Disabled | AdminHttpExposure::Loopback => {}
        AdminHttpExposure::ReachableAllowlisted => {
            warn!(
                "Admin API plaintext HTTP listener (FERRUM_ADMIN_HTTP_PORT={}) is bound to {} \
                 (reachable beyond loopback). FERRUM_ADMIN_ALLOWED_CIDRS restricts which source \
                 IPs may connect, but operator bearer tokens still traverse cleartext on this \
                 port. Prefer admin over TLS (FERRUM_ADMIN_TLS_CERT_PATH / \
                 FERRUM_ADMIN_TLS_KEY_PATH) and disable plaintext with FERRUM_ADMIN_HTTP_PORT=0.",
                secrets::report_env_field(
                    "FERRUM_ADMIN_HTTP_PORT",
                    &env_config.admin_http_port.to_string()
                ),
                secrets::report_env_field(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    &env_config.admin_bind_address
                )
            );
        }
        AdminHttpExposure::ReachableUnrestricted => {
            // database/cp only reach here with FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true
            // (otherwise `validate()` already aborted startup). Read-only modes
            // (file/dp/mesh) are warned but allowed to start.
            if env_config.allow_insecure_admin_http {
                warn!(
                    "FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true: the plaintext admin HTTP listener is \
                     bound to {} with no FERRUM_ADMIN_ALLOWED_CIDRS allowlist — the admin API and \
                     operator bearer tokens are exposed in cleartext on every matching interface. \
                     Development only; never use this in production.",
                    secrets::report_env_field(
                        "FERRUM_ADMIN_BIND_ADDRESS",
                        &env_config.admin_bind_address
                    )
                );
            } else {
                warn!(
                    "Admin API plaintext HTTP listener is bound to {} with no \
                     FERRUM_ADMIN_ALLOWED_CIDRS allowlist; ensure it is not publicly reachable. \
                     Prefer FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1, an allowlist, or admin TLS with \
                     FERRUM_ADMIN_HTTP_PORT=0.",
                    secrets::report_env_field(
                        "FERRUM_ADMIN_BIND_ADDRESS",
                        &env_config.admin_bind_address
                    )
                );
            }
        }
    }

    // Detect IPv6 dual-stack support and log a hint if listeners are IPv4-only
    if (env_config.proxy_bind_address == "0.0.0.0" || env_config.admin_bind_address == "0.0.0.0")
        && std::net::TcpListener::bind("[::]:0").is_ok()
    {
        info!(
            "IPv6 dual-stack support detected. To accept both IPv4 and IPv6 connections, \
             set FERRUM_PROXY_BIND_ADDRESS=:: and/or FERRUM_ADMIN_BIND_ADDRESS=:: \
             (dual-stack binds to [::] and accepts IPv4 via mapped addresses on most OSes)"
        );
    }

    // Start the main multi-threaded runtime for the gateway
    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    rt_builder.enable_all();
    // Key-tied for the same reason as the logging-clamp fields above: both are
    // parsed to `usize` and clamped with `.max(1)` before being re-rendered, so
    // a secret-backed `004` surfaces as `4` and a `0` as `1`. Those are derived
    // one-byte forms, below `MIN_DERIVED_CANDIDATE_LEN`, which the structural
    // log-record redactor deliberately will not admit.
    if let Some(workers) = env_config.worker_threads {
        info!(
            "Tokio worker threads: {}",
            secrets::report_env_field("FERRUM_WORKER_THREADS", &workers.to_string())
        );
        rt_builder.worker_threads(workers);
    }
    if let Some(blocking) = env_config.blocking_threads {
        info!(
            "Tokio max blocking threads: {}",
            secrets::report_env_field("FERRUM_BLOCKING_THREADS", &blocking.to_string())
        );
        rt_builder.max_blocking_threads(blocking);
    }
    let rt = match rt_builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return 1;
        }
    };

    observability_delivery::initialize(
        env_config.pool_shard_amount,
        env_config.log_delivery_max_tasks,
    );
    // Process-wide retained-byte ceiling for observability sink instances.
    // Installed before mode dispatch so the first plugin activation already
    // reserves against the operator-configured total.
    plugins::utils::byte_budget::initialize_process_retained_byte_ceiling(
        env_config.log_delivery_max_retained_bytes,
    );
    let observability_delivery_timeout =
        std::time::Duration::from_millis(env_config.log_shutdown_drain_timeout_ms);
    let gateway_exit_code: i32 = rt.block_on(async {
        // Shutdown signal
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let shutdown_tx_signal = shutdown_tx.clone();

        // Graceful shutdown handler
        tokio::spawn(async move {
            let ctrl_c = tokio::signal::ctrl_c();

            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to register SIGTERM handler: {}", e);
                        return;
                    }
                };
                tokio::select! {
                    _ = ctrl_c => {
                        info!("SIGINT received, initiating graceful shutdown...");
                    }
                    _ = sigterm.recv() => {
                        info!("SIGTERM received, initiating graceful shutdown...");
                    }
                }
            }

            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
                info!("Ctrl+C received, initiating graceful shutdown...");
            }

            let _ = shutdown_tx_signal.send(true);
        });

        // Run the appropriate mode
        let result = match env_config.mode {
            OperatingMode::Database => modes::database::run(env_config, shutdown_tx).await,
            OperatingMode::File => modes::file::run(env_config, shutdown_tx).await,
            OperatingMode::ControlPlane => modes::control_plane::run(env_config, shutdown_tx).await,
            OperatingMode::DataPlane => modes::data_plane::run(env_config, shutdown_tx).await,
            OperatingMode::Mesh => modes::mesh::run(env_config, shutdown_tx).await,
            OperatingMode::Injector => modes::injector::run(env_config, shutdown_tx).await,
            OperatingMode::NodeAgent => modes::node_agent::run(env_config, shutdown_tx).await,
            OperatingMode::Migrate => modes::migrate::run(env_config, shutdown_tx).await,
        };

        // Serving modes perform the ordered delivery drain before their
        // producer-specific finalizers. This idempotent fallback covers early
        // mode errors and non-serving modes after mode-owned state has dropped,
        // before the Tokio runtime or process-log appenders can shut down.
        let _ = observability_delivery::shutdown(observability_delivery_timeout).await;

        match result {
            Ok(()) => {
                info!("Ferrum Edge shut down cleanly");
                0
            }
            Err(e) => {
                // `error!` events are routed to stderr by `SeverityWriter`.
                // The bounded worker guards are held in `run_gateway`;
                // returning drains them before `main` may exit. Inline
                // `std::process::exit` would bypass that accounting.
                error!("Fatal error: {}", e);
                1
            }
        }
    });

    gateway_exit_code
}
