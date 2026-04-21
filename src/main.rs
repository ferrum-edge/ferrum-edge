// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod adaptive_buffer;
mod admin;
mod circuit_breaker;
mod cli;
mod config;
mod config_delta;
mod connection_pool;
mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
mod custom_plugins;
mod date_cache;
mod dns;
mod dtls;
mod grpc;
mod health_check;
mod http3;
#[allow(dead_code)]
mod lazy_timeout;
mod load_balancer;
mod metrics;
mod modes;
mod overload;
mod plugin_cache;
mod plugins;
mod pool;
mod proxy;
mod retry;
mod router_cache;
mod secrets;
mod service_discovery;
mod socket_opts;
mod startup;
mod tls;
#[allow(dead_code)]
mod tls_offload;

use clap::Parser;
use config::{EnvConfig, OperatingMode};
use tracing::{Level, Metadata, error, info};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

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
/// Both sinks are `tracing_appender::non_blocking::NonBlocking`, so the hot
/// path remains a channel send rather than a blocking I/O write. The
/// corresponding `WorkerGuard`s are owned by `run_gateway()` so they drop
/// (and flush buffered events) when it returns — see the ownership
/// comment on those bindings for the full reasoning.
struct SeverityWriter {
    stdout: NonBlocking,
    stderr: NonBlocking,
}

impl<'a> MakeWriter<'a> for SeverityWriter {
    type Writer = NonBlocking;

    fn make_writer(&'a self) -> Self::Writer {
        // Called when no metadata is available (e.g., some tracing internals).
        // Default to stdout to match the pre-split behavior.
        self.stdout.clone()
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        // ERROR and WARN → stderr; INFO/DEBUG/TRACE → stdout.
        // See the type-level docstring above for the level → sink table
        // and the rationale for each row.
        match *meta.level() {
            Level::ERROR | Level::WARN => self.stderr.clone(),
            Level::INFO | Level::DEBUG | Level::TRACE => self.stdout.clone(),
        }
    }
}

/// Entry point for the Ferrum Edge gateway binary.
///
/// Startup sequence:
/// 1. Parse CLI arguments (if any — no args falls through to legacy env-var mode)
/// 2. Install rustls crypto provider (ring backend)
/// 3. Resolve external secrets (Vault, AWS, Azure, GCP, env, file) using a
///    temporary runtime that is dropped before env mutation
/// 4. Initialize structured JSON logging
/// 5. Parse environment configuration (`EnvConfig::from_env()`)
/// 6. Build the multi-threaded tokio runtime with configured worker/blocking threads
/// 7. Dispatch to the appropriate operating mode (database, file, cp, dp, migrate)
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
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(cli::Command::Health(args)) => {
            match cli::execute_health(args) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error: {}", e);
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
        _ => {} // No subcommand: legacy env-var-only mode.
    }

    // ── Crypto provider ─────────────────────────────────────────────────
    // Initialize rustls crypto provider (needed by validate for TLS cert checks)
    if rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .is_err()
    {
        eprintln!("Failed to install crypto provider");
        std::process::exit(1);
    }

    // Initialize tracing/logging with non-blocking writers and run the
    // rest of startup + the gateway in `run_gateway`. Keeping the tracing
    // `WorkerGuard`s local to that helper (via its return path) ensures they
    // drop — and thus flush — on EVERY exit path, including errors. A
    // `std::process::exit()` inline inside main would bypass the guards'
    // destructors and silently drop buffered log events, which is exactly
    // what would make a test captor of stderr see nothing after a fatal
    // error.
    let exit_code = run_gateway(&cli);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn init_logging() -> (WorkerGuard, WorkerGuard) {
    let log_buffer_capacity: usize =
        config::conf_file::resolve_ferrum_var("FERRUM_LOG_BUFFER_CAPACITY")
            .and_then(|v| v.parse().ok())
            .unwrap_or(128_000);
    let (stdout_writer, stdout_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(log_buffer_capacity)
            .finish(std::io::stdout());
    let (stderr_writer, stderr_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(log_buffer_capacity)
            .finish(std::io::stderr());
    let log_level =
        config::conf_file::resolve_ferrum_var("FERRUM_LOG_LEVEL").unwrap_or_else(|| "error".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level)),
        )
        .json()
        .with_writer(SeverityWriter {
            stdout: stdout_writer,
            stderr: stderr_writer,
        })
        .init();

    (stdout_guard, stderr_guard)
}

/// Runs startup secret resolution, logging init, env-config parsing, and the
/// gateway runtime. Returns the process exit code.
///
/// All `tracing_appender::non_blocking::WorkerGuard`s are local here, so
/// any path out of this function (early return on error or fall-through on
/// success) runs their `Drop` impls and flushes any buffered events before
/// `main()` calls `std::process::exit()`. This is the invariant that lets
/// error-level events actually reach stderr instead of being abandoned in
/// the non-blocking writer's channel at process termination. Normal startup
/// resolves secrets before those logging threads exist so the temporary
/// runtime can fully shut down before unsafe env mutation.
fn run_gateway(cli: &cli::Cli) -> i32 {
    // Handle validate subcommand: load config, validate, exit.
    // Runs after crypto + logging init so TLS cert checks and tracing work,
    // but before secret resolution and the multi-threaded runtime.
    if matches!(&cli.command, Some(cli::Command::Validate(_))) {
        let (_stdout_guard, _stderr_guard) = init_logging();
        match cli::execute_validate() {
            Ok(()) => return 0,
            Err(e) => {
                error!("Validation error: {}", e);
                return 1;
            }
        }
    }

    // Resolve secrets before initializing non-blocking logging so the
    // temporary runtime can shut down completely before env mutation.
    let resolved = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create secret resolution runtime");

        match rt.block_on(secrets::resolve_all_env_secrets()) {
            Ok(resolved) => resolved,
            Err(e) => {
                eprintln!("Secret resolution error: {}", e);
                return 1;
            }
        }
    };

    // SAFETY: Secret resolution completed before non-blocking logging or the
    // main multi-threaded runtime were created, and the temporary runtime
    // above has already been dropped. We mutate the environment before any
    // later startup stage can spawn additional worker threads.
    unsafe {
        for (base_key, value) in &resolved.vars {
            std::env::set_var(base_key, value);
        }
        for suffixed_key in &resolved.source_keys_to_remove {
            std::env::remove_var(suffixed_key);
        }
    }

    let (_stdout_guard, _stderr_guard) = init_logging();

    info!(
        "Ferrum Edge v{} ({}) starting...",
        env!("CARGO_PKG_VERSION"),
        env!("TARGET")
    );
    for (base_key, backend_name) in &resolved.loaded_sources {
        info!("Loaded {} from {}", base_key, backend_name);
    }
    if !resolved.vars.is_empty() {
        info!(
            "Resolved {} env var(s) from external secret sources",
            resolved.vars.len()
        );
    }

    // Load environment config (now includes any resolved secrets)
    let env_config = match EnvConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            return 1;
        }
    };

    // Initialize DTLS buffer config from resolved EnvConfig before any DTLS sessions.
    crate::dtls::init_dtls_buf_config(
        env_config.dtls_max_plaintext_bytes,
        env_config.dtls_record_overhead_bytes,
    );

    info!("Operating mode: {:?}", env_config.mode);
    info!(
        "Proxy bind address: {}, Admin bind address: {}",
        env_config.proxy_bind_address, env_config.admin_bind_address
    );

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
    if let Some(workers) = env_config.worker_threads {
        info!("Tokio worker threads: {}", workers);
        rt_builder.worker_threads(workers);
    }
    if let Some(blocking) = env_config.blocking_threads {
        info!("Tokio max blocking threads: {}", blocking);
        rt_builder.max_blocking_threads(blocking);
    }
    let rt = rt_builder.build().expect("Failed to create tokio runtime");

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
            OperatingMode::Migrate => modes::migrate::run(env_config, shutdown_tx).await,
        };

        match result {
            Ok(()) => {
                info!("Ferrum Edge shut down cleanly");
                0
            }
            Err(e) => {
                // `error!` events are routed to stderr by `SeverityWriter`.
                // The tracing appender's `WorkerGuard`s are held in the
                // caller (`run_gateway`); returning from this closure +
                // returning from `run_gateway` drops them in order, which
                // flushes any buffered events to their respective sinks
                // before `main` calls `std::process::exit`. Inline
                // `std::process::exit` would bypass those destructors and
                // lose the fatal event.
                error!("Fatal error: {}", e);
                1
            }
        }
    });

    gateway_exit_code
}
