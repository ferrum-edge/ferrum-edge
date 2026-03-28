mod admin;
mod circuit_breaker;
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
mod plugin_cache;
mod plugins;
mod proxy;
mod retry;
mod router_cache;
mod secrets;
mod service_discovery;
mod tls;

use config::{EnvConfig, OperatingMode};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize rustls crypto provider
    if rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .is_err()
    {
        eprintln!("Failed to install crypto provider");
        std::process::exit(1);
    }

    // Initialize tracing/logging
    let log_level = std::env::var("FERRUM_LOG_LEVEL").unwrap_or_else(|_| "error".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level)),
        )
        .json()
        .init();

    info!("Ferrum Gateway starting...");

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

    // Start the main multi-threaded runtime for the gateway
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

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

        info!("Ferrum Gateway shut down cleanly");
    });
}
