//! Data Plane gRPC client — subscribes to the CP's config stream.
//!
//! The outer reconnect loop (`start_dp_client_with_shutdown`) retries every
//! 5 seconds on disconnect. Inside the stream handler, two message types:
//! - `update_type=0` (FULL_SNAPSHOT): replaces the entire `GatewayConfig`
//! - `update_type=1` (DELTA): applies incremental changes via `apply_incremental()`
//!
//! SNI is extracted from the CP URL so TLS certificate validation works
//! correctly even when connecting via IP address with a hostname-based cert.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::transport::channel::ClientTlsConfig;
use tonic::transport::{Certificate, Channel, Identity};
use tracing::{error, info, warn};

use super::proto::SubscribeRequest;
use super::proto::config_sync_client::ConfigSyncClient;
use crate::FERRUM_VERSION;
use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;
use crate::proxy::ProxyState;

/// TLS configuration for the DP gRPC client.
#[derive(Clone, Default)]
pub struct DpGrpcTlsConfig {
    /// CA certificate PEM bytes for verifying CP server cert.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client certificate PEM bytes for mTLS.
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key PEM bytes for mTLS.
    pub client_key_pem: Option<Vec<u8>>,
    /// Skip server certificate verification (testing only).
    /// When true and no `ca_cert_pem` is set, the client accepts any server cert.
    #[allow(dead_code)]
    pub no_verify: bool,
}

/// Connect to the Control Plane with an optional shutdown signal.
#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn start_dp_client_with_shutdown(
    cp_url: String,
    auth_token: String,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
) {
    start_dp_client_with_shutdown_and_startup_ready(
        cp_url,
        auth_token,
        proxy_state,
        shutdown_rx,
        tls_config,
        None,
    )
    .await;
}

/// Connect to the Control Plane with an optional startup readiness flag.
pub async fn start_dp_client_with_shutdown_and_startup_ready(
    cp_url: String,
    auth_token: String,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
) {
    let node_id = uuid::Uuid::new_v4().to_string();
    info!("DP client starting, connecting to CP at {}", cp_url);

    loop {
        if let Some(ref rx) = shutdown_rx
            && *rx.borrow()
        {
            info!("DP client shutting down");
            return;
        }

        match connect_and_subscribe_with_startup_ready(
            &cp_url,
            &auth_token,
            &node_id,
            &proxy_state,
            tls_config.as_ref(),
            startup_ready.clone(),
        )
        .await
        {
            Ok(_) => {
                warn!("CP connection stream ended, will reconnect...");
            }
            Err(e) => {
                error!("CP connection error: {}, will retry in 5s", e);
            }
        }

        // Continue serving with cached config; retry connection
        if let Some(ref rx) = shutdown_rx {
            let mut rx_clone = rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = async {
                    while !*rx_clone.borrow() {
                        if rx_clone.changed().await.is_err() { return; }
                    }
                } => {
                    info!("DP client shutting down");
                    return;
                }
            }
        } else {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn connect_and_subscribe(
    cp_url: &str,
    auth_token: &str,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
) -> Result<(), anyhow::Error> {
    connect_and_subscribe_with_startup_ready(
        cp_url,
        auth_token,
        node_id,
        proxy_state,
        tls_config,
        None,
    )
    .await
}

/// Connect to CP and optionally flip startup readiness after the first applied snapshot.
pub async fn connect_and_subscribe_with_startup_ready(
    cp_url: &str,
    auth_token: &str,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
) -> Result<(), anyhow::Error> {
    let mut endpoint =
        Channel::from_shared(cp_url.to_string())?.connect_timeout(Duration::from_secs(10));

    // Apply TLS configuration if the URL uses https:// or TLS config is provided
    if let Some(tls) = tls_config {
        let mut client_tls = ClientTlsConfig::new();

        if let Some(ref ca_pem) = tls.ca_cert_pem {
            client_tls = client_tls.ca_certificate(Certificate::from_pem(ca_pem));
        }

        if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
            client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
        }

        // Extract domain from URL for TLS SNI
        if let Ok(uri) = cp_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }

        endpoint = endpoint.tls_config(client_tls)?;
    }

    let channel = endpoint.connect().await?;

    let token: MetadataValue<_> = format!("Bearer {}", auth_token).parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        ConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    info!(
        "Connected to CP, subscribing for config updates (DP v{})",
        FERRUM_VERSION
    );

    let request = tonic::Request::new(SubscribeRequest {
        node_id: node_id.to_string(),
        ferrum_version: FERRUM_VERSION.to_string(),
    });

    let mut stream = client.subscribe(request).await?.into_inner();
    let mut initial_snapshot_applied = startup_ready.is_none();

    while let Some(update) = stream.message().await? {
        info!(
            "Received config update (type={}, version={}, cp_version={})",
            update.update_type, update.version, update.ferrum_version
        );

        // Validate CP version compatibility before applying any config.
        if !update.ferrum_version.is_empty()
            && let Err(msg) = check_cp_version_compatibility(&update.ferrum_version)
        {
            error!("{}", msg);
            return Err(anyhow::anyhow!(msg));
        }

        match update.update_type {
            0 => {
                // FULL_SNAPSHOT — replace entire config
                match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                    Ok(mut config) => {
                        config.normalize_fields();
                        if let Err(errors) = config.validate_all_fields() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid field values");
                            continue;
                        }
                        if let Err(errors) = config.validate_hosts() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid hosts");
                            continue;
                        }
                        if let Err(errors) = config.validate_regex_listen_paths() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid regex listen_paths");
                            continue;
                        }
                        if let Err(errors) = config.validate_unique_listen_paths() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with conflicting listen paths");
                            continue;
                        }
                        if let Err(errors) = config.validate_stream_proxies() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid stream proxy config");
                            continue;
                        }
                        if let Err(errors) = config.validate_upstream_references() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid upstream references");
                            continue;
                        }
                        if let Err(errors) = config.validate_plugin_references() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid plugin references");
                            continue;
                        }
                        if let Err(errors) = config.validate_unique_plugins_per_proxy() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with duplicate proxy plugins");
                            continue;
                        }
                        proxy_state.update_config(config);
                        if !initial_snapshot_applied {
                            proxy_state
                                .stream_listener_manager
                                .wait_until_started(Duration::from_secs(10))
                                .await?;
                            if let Some(ref startup_ready) = startup_ready {
                                startup_ready.store(true, Ordering::Relaxed);
                            }
                            initial_snapshot_applied = true;
                            info!("DP startup complete; /health now reports ready");
                        }
                        info!("Full configuration snapshot applied from CP");
                    }
                    Err(e) => {
                        error!("Failed to parse full config update: {}", e);
                    }
                }
            }
            1 => {
                // DELTA — apply incremental changes only
                match serde_json::from_str::<IncrementalResult>(&update.config_json) {
                    Ok(result) => {
                        if proxy_state.apply_incremental(result) {
                            info!("Incremental config delta applied from CP");
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse delta update: {}", e);
                    }
                }
            }
            other => {
                warn!("Unknown config update type {}, ignoring", other);
            }
        }
    }

    Ok(())
}

/// Check whether the CP's reported version is compatible with this DP.
///
/// Major and minor versions must match. Patch-level differences are allowed.
fn check_cp_version_compatibility(cp_version: &str) -> Result<(), String> {
    let dp_parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
    let cp_parts: Vec<&str> = cp_version.split('.').collect();

    if dp_parts.len() < 2 || cp_parts.len() < 2 {
        warn!(
            "Unable to parse version for compatibility check (DP={}, CP={}), allowing connection",
            FERRUM_VERSION, cp_version
        );
        return Ok(());
    }

    if dp_parts[0] != cp_parts[0] || dp_parts[1] != cp_parts[1] {
        return Err(format!(
            "Version mismatch: DP is v{} but CP is v{}. \
             Major and minor versions must match. \
             Upgrade the CP first, then upgrade DPs to the same major.minor version.",
            FERRUM_VERSION, cp_version
        ));
    }

    Ok(())
}
