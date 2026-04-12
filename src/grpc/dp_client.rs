//! Data Plane gRPC client — subscribes to the CP's config stream.
//!
//! The outer reconnect loop (`start_dp_client_with_shutdown`) uses exponential
//! backoff with jitter (1s → 2s → 4s → … → 30s cap, ±25% jitter) to avoid
//! thundering-herd reconnection storms when many DPs restart simultaneously.
//! Inside the stream handler, two message types:
//! - `update_type=0` (FULL_SNAPSHOT): replaces the entire `GatewayConfig`
//! - `update_type=1` (DELTA): applies incremental changes via `apply_incremental()`
//!
//! SNI is extracted from the CP URL so TLS certificate validation works
//! correctly even when connecting via IP address with a hostname-based cert.
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
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

/// Newtype for the shared CP/DP gRPC JWT secret (`FERRUM_CP_DP_GRPC_JWT_SECRET`).
///
/// This wrapper exists so the compiler catches callers who accidentally pass a
/// pre-signed JWT token where a shared secret is now expected. Before this change
/// both were `String`, so the old code compiled silently with the wrong value.
#[derive(Clone, Debug)]
pub struct GrpcJwtSecret(pub String);

impl GrpcJwtSecret {
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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

/// JWT token lifetime for DP-generated tokens (59 minutes, under the 1-hour ceiling).
const DP_JWT_TTL_SECONDS: i64 = 3540;

/// Generate a short-lived HS256 JWT for authenticating the DP to the CP.
///
/// The token is signed with the shared `FERRUM_CP_DP_GRPC_JWT_SECRET` and
/// includes `sub`, `iat`, `exp`, and `role` claims. A fresh token is minted
/// on each gRPC connection attempt so that tokens captured from the wire
/// are only valid for ~59 minutes.
pub fn generate_dp_jwt(secret: &str, node_id: &str) -> Result<String, anyhow::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": now + DP_JWT_TTL_SECONDS,
        "role": "data_plane",
    });
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

/// Connect to the Control Plane with an optional shutdown signal.
///
/// Accepts a single CP URL for backward compatibility. For multi-CP failover,
/// use [`start_dp_client_with_shutdown_and_startup_ready`] with a `Vec`.
#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn start_dp_client_with_shutdown(
    cp_url: String,
    jwt_secret: GrpcJwtSecret,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
    namespace: String,
) {
    start_dp_client_with_shutdown_and_startup_ready(
        vec![cp_url],
        jwt_secret,
        proxy_state,
        shutdown_rx,
        tls_config,
        None,
        namespace,
        0,
    )
    .await;
}

/// Connect to Control Plane(s) with multi-CP failover and optional startup readiness.
///
/// `cp_urls` is a priority-ordered list of CP gRPC URLs. The DP connects to the
/// first (primary) URL and fails over to subsequent URLs when unreachable. When
/// connected to a fallback CP and `primary_retry_secs > 0`, the DP periodically
/// disconnects from the fallback and retries the primary CP.
#[allow(clippy::too_many_arguments)]
pub async fn start_dp_client_with_shutdown_and_startup_ready(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: String,
    primary_retry_secs: u64,
) {
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start DP client");
        return;
    }

    let node_id = uuid::Uuid::new_v4().to_string();
    let cp_count = cp_urls.len();

    if cp_count > 1 {
        info!(
            "DP client starting with {} CP URLs (failover enabled): {}",
            cp_count,
            cp_urls
                .iter()
                .enumerate()
                .map(|(i, u)| if i == 0 {
                    format!("{} (primary)", u)
                } else {
                    u.to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        info!(
            "DP client starting, connecting to CP at {}",
            cp_urls.first().map(|s| s.as_str()).unwrap_or("(none)")
        );
    }

    const BACKOFF_INITIAL_SECS: u64 = 1;
    const BACKOFF_MAX_SECS: u64 = 30;
    let mut current_cp_index: usize = 0;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut full_cycle_count: u32 = 0;

    loop {
        if let Some(ref rx) = shutdown_rx
            && *rx.borrow()
        {
            info!("DP client shutting down");
            return;
        }

        let cp_url = &cp_urls[current_cp_index];
        let is_primary = current_cp_index == 0;
        let is_fallback = !is_primary && cp_count > 1;

        if is_fallback {
            info!(
                "Connecting to fallback CP [{}/{}] at {}",
                current_cp_index + 1,
                cp_count,
                cp_url
            );
        } else if cp_count > 1 {
            info!("Connecting to primary CP at {}", cp_url);
        }

        // When connected to a fallback CP and primary_retry_secs > 0,
        // race the stream against a timer to periodically retry the primary.
        // The timer is only armed after startup readiness (initial snapshot applied)
        // to avoid disconnecting from the fallback before the DP has any config.
        let should_race_primary = is_fallback
            && primary_retry_secs > 0
            && startup_ready
                .as_ref()
                .is_none_or(|r| r.load(Ordering::Relaxed));
        let result = if should_race_primary {
            tokio::select! {
                res = connect_and_subscribe_with_startup_ready(
                    cp_url,
                    &jwt_secret,
                    &node_id,
                    &proxy_state,
                    tls_config.as_ref(),
                    startup_ready.clone(),
                    &namespace,
                ) => res,
                _ = tokio::time::sleep(Duration::from_secs(primary_retry_secs)) => {
                    info!(
                        "Primary CP retry interval ({}s) elapsed; disconnecting from \
                         fallback CP [{}/{}] to retry primary",
                        primary_retry_secs,
                        current_cp_index + 1,
                        cp_count,
                    );
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            connect_and_subscribe_with_startup_ready(
                cp_url,
                &jwt_secret,
                &node_id,
                &proxy_state,
                tls_config.as_ref(),
                startup_ready.clone(),
                &namespace,
            )
            .await
        };

        match result {
            Ok(_) => {
                warn!(
                    "CP [{}/{}] connection stream ended ({}), will reconnect...",
                    current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                // On clean disconnect, try primary first if we were on a fallback
                if is_fallback {
                    info!("Stream ended on fallback CP; will retry primary CP first");
                    current_cp_index = 0;
                }
                backoff_secs = BACKOFF_INITIAL_SECS;
            }
            Err(e) => {
                error!(
                    "CP [{}/{}] connection error ({}): {}",
                    current_cp_index + 1,
                    cp_count,
                    cp_url,
                    e
                );

                if cp_count > 1 {
                    let next_index = (current_cp_index + 1) % cp_count;
                    if next_index == 0 {
                        full_cycle_count += 1;
                        warn!(
                            "All {} CP URLs exhausted (cycle {}), restarting from primary",
                            cp_count, full_cycle_count
                        );
                        // Keep accumulated backoff when cycling back
                    } else {
                        // Fresh start on next CP
                        backoff_secs = BACKOFF_INITIAL_SECS;
                    }
                    current_cp_index = next_index;
                }
            }
        }

        // Apply ±25% jitter to the backoff to desynchronize reconnection attempts.
        let base_ms = backoff_secs * 1000;
        let jitter_range_ms = base_ms / 4;
        let jitter_ms = if jitter_range_ms > 0 {
            let full_range = jitter_range_ms * 2;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            (nanos % full_range) as i64 - jitter_range_ms as i64
        } else {
            0
        };
        let sleep_ms = base_ms as i64 + jitter_ms;
        let sleep_duration = Duration::from_millis(sleep_ms.max(100) as u64);

        if let Some(ref rx) = shutdown_rx {
            let mut rx_clone = rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {}
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
            tokio::time::sleep(sleep_duration).await;
        }

        backoff_secs = (backoff_secs * 2).min(BACKOFF_MAX_SECS);
    }
}

#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn connect_and_subscribe(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    namespace: &str,
) -> Result<(), anyhow::Error> {
    connect_and_subscribe_with_startup_ready(
        cp_url,
        jwt_secret,
        node_id,
        proxy_state,
        tls_config,
        None,
        namespace,
    )
    .await
}

/// Connect to CP and optionally flip startup readiness after the first applied snapshot.
pub async fn connect_and_subscribe_with_startup_ready(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: &str,
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

    // Mint a fresh short-lived JWT for this connection attempt.
    let auth_token = generate_dp_jwt(jwt_secret.as_str(), node_id)?;
    info!(
        "Generated fresh DP JWT (TTL={}s) for CP authentication",
        DP_JWT_TTL_SECONDS
    );
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
        namespace: namespace.to_string(),
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
                        if let Err(errors) = config.validate_all_fields_with_ip_policy(
                            proxy_state.env_config.tls_cert_expiry_warning_days,
                            &proxy_state.env_config.backend_allow_ips,
                        ) {
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
                        if proxy_state.apply_incremental(result).await {
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
