// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod admin;
mod circuit_breaker;
mod cli;
mod config;
mod config_delta;
mod connection_pool;
mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
mod custom_plugins;
mod dns;
mod dtls;
mod grpc;
mod health_check;
mod http3;
mod load_balancer;
mod modes;
mod overload;
mod plugin_cache;
mod plugins;
mod proxy;
mod retry;
mod router_cache;
mod secrets;
mod service_discovery;
mod startup;
mod tls;

use clap::Parser;
use config::{EnvConfig, OperatingMode};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// The Ferrum Edge binary version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry point for the Ferrum Edge gateway binary.
///
/// Startup sequence:
/// 1. Parse CLI arguments (if any — no args falls through to legacy env-var mode)
/// 2. Install rustls crypto provider (ring backend)
/// 3. Initialize structured JSON logging
/// 4. Resolve external secrets (Vault, AWS, Azure, GCP, env, file) using a
///    single-threaded runtime — env var mutations are unsafe with multiple threads
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

    // Initialize tracing/logging with a non-blocking writer. The default
    // tracing-subscriber fmt layer writes synchronously to stdout, acquiring a
    // mutex lock on every log event. Under high concurrency this creates
    // contention across tokio worker threads. `tracing_appender::non_blocking`
    // sends events through a channel to a dedicated writer thread, making the
    // hot-path log call a fast channel send instead of a blocking I/O write.
    // The `_guard` must be held until shutdown to keep the writer thread alive
    // and flush remaining events on drop.
    let log_buffer_capacity: usize =
        config::conf_file::resolve_ferrum_var("FERRUM_LOG_BUFFER_CAPACITY")
            .and_then(|v| v.parse().ok())
            .unwrap_or(128_000);
    let (non_blocking, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(log_buffer_capacity)
        .finish(std::io::stdout());
    let log_level =
        config::conf_file::resolve_ferrum_var("FERRUM_LOG_LEVEL").unwrap_or_else(|| "error".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level)),
        )
        .json()
        .with_writer(non_blocking)
        .init();

    // Handle validate subcommand: load config, validate, exit.
    // Runs after crypto + logging init so TLS cert checks and tracing work,
    // but before secret resolution and the multi-threaded runtime.
    if matches!(&cli.command, Some(cli::Command::Validate(_))) {
        match cli::execute_validate() {
            Ok(()) => return,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    info!("Ferrum Edge v{} starting...", env!("CARGO_PKG_VERSION"));

    // Resolve secrets using a single-threaded runtime so that subsequent
    // env var mutations are safe — no concurrent threads exist yet.
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create secret resolution runtime");

        match rt.block_on(secrets::resolve_all_env_secrets()) {
            Ok(resolved) => {
                // SAFETY: The single-threaded tokio runtime above is the only
                // runtime. No worker threads or concurrent env var readers exist.
                // We set the resolved values and remove the suffixed source keys
                // before any multi-threaded runtime starts.
                unsafe {
                    for (base_key, value) in &resolved.vars {
                        std::env::set_var(base_key, value);
                    }
                    for suffixed_key in &resolved.source_keys_to_remove {
                        std::env::remove_var(suffixed_key);
                    }
                }
                if !resolved.vars.is_empty() {
                    info!(
                        "Resolved {} env var(s) from external secret sources",
                        resolved.vars.len()
                    );
                }
            }
            Err(e) => {
                error!("Secret resolution error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Load environment config (now includes any resolved secrets)
    let env_config = match EnvConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

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

    rt.block_on(async {
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

        if let Err(e) = result {
            error!("Fatal error: {}", e);
            std::process::exit(1);
        }

        info!("Ferrum Edge shut down cleanly");
    });
}
