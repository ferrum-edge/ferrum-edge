mod admin;
mod config;
mod connection_pool;
mod consumer_index;
mod dns;
mod grpc;
mod http3;
mod modes;
mod plugin_cache;
mod plugins;
mod proxy;
mod router_cache;
mod tls;

use config::{EnvConfig, OperatingMode};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize rustls crypto provider
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("Failed to install crypto provider");

    // Initialize tracing/logging
    let log_level = std::env::var("FERRUM_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level)),
        )
        .json()
        .init();

    info!("Ferrum Gateway starting...");

    // Load environment config
    let env_config = match EnvConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    info!("Operating mode: {:?}", env_config.mode);

    // Shutdown signal
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown_tx_signal = shutdown_tx.clone();

    // Graceful shutdown handler
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
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
    };

    if let Err(e) = result {
        error!("Fatal error: {}", e);
        std::process::exit(1);
    }

    info!("Ferrum Gateway shut down cleanly");
}
