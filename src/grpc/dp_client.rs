//! Data Plane gRPC client — subscribes to the CP's config stream.
//!
//! The outer reconnect loop (`start_dp_client_with_shutdown`) uses exponential
//! backoff with jitter (1s → 2s → 4s → … → 30s cap, ±25% jitter) to avoid
//! thundering-herd reconnection storms when many DPs restart simultaneously.
//! Inside the stream handler, two message types:
//! - `update_type=0` (FULL_SNAPSHOT): replaces the entire `GatewayConfig`
//! - `update_type=1` (DELTA): applies incremental changes via `apply_incremental()`
//!
//! Multi-CP failover: `cp_urls` is a priority-ordered list. The DP connects to
//! the first (primary) URL and fails over to subsequent URLs when unreachable.
//! When connected to a fallback CP and `primary_retry_secs > 0`, the DP
//! periodically disconnects from the fallback to retry the primary.
//!
//! SNI is extracted from the CP URL so TLS certificate validation works
//! correctly even when connecting via IP address with a hostname-based cert.
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tonic::metadata::MetadataValue;
use tonic::transport::channel::ClientTlsConfig;
use tonic::transport::{Certificate, Channel, Identity};
use tracing::{debug, error, info, warn};

use super::proto::SubscribeRequest;
use super::proto::config_sync_client::ConfigSyncClient;
use crate::FERRUM_VERSION;
use crate::config::EnvConfig;
use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;
use crate::identity::TrustBundleSet as RuntimeTrustBundleSet;
use crate::modes::mesh::config::TrustBundleSet as ConfigTrustBundleSet;
use crate::proxy::{ConfigApplyOutcome, ProxyState};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::util::backoff::{BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs};

/// Tracks the DP's connection status to its Control Plane.
/// Shared between the DP gRPC client and the admin API (`GET /cluster`).
#[derive(Clone, Serialize)]
pub struct DpCpConnectionState {
    /// Whether the gRPC stream to a CP is currently active.
    pub connected: bool,
    /// URL of the CP this DP is currently connected to (or last attempted).
    pub cp_url: String,
    /// Whether the current CP is the primary (index 0) or a fallback.
    pub is_primary: bool,
    /// Timestamp of the last config update received from CP.
    pub last_config_received_at: Option<DateTime<Utc>>,
    /// When the current connection was established (None if disconnected).
    pub connected_since: Option<DateTime<Utc>>,
}

impl DpCpConnectionState {
    pub fn new_disconnected(cp_url: &str) -> Self {
        Self {
            connected: false,
            cp_url: cp_url.to_string(),
            is_primary: true,
            last_config_received_at: None,
            connected_since: None,
        }
    }
}

/// Newtype for the shared CP/DP gRPC JWT secret (`FERRUM_CP_DP_GRPC_JWT_SECRET`).
///
/// This wrapper exists so the compiler catches callers who accidentally pass a
/// pre-signed JWT token where a shared secret is now expected. Before this change
/// both were `String`, so the old code compiled silently with the wrong value.
///
/// The wrapper also carries the expected `iss` claim
/// (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) since the secret and issuer always travel
/// together: every token minted with this secret needs to bear the configured
/// issuer or the CP will reject it.
#[derive(Clone, Debug)]
pub struct GrpcJwtSecret {
    secret: String,
    issuer: String,
}

impl GrpcJwtSecret {
    /// Create a `GrpcJwtSecret` with the default issuer
    /// (`crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER`).
    ///
    /// Used by tests and library callers; production binary code path uses
    /// [`GrpcJwtSecret::with_issuer`] so the operator-configured
    /// `FERRUM_CP_DP_GRPC_JWT_ISSUER` is honored.
    #[allow(dead_code)]
    pub fn new(secret: String) -> Self {
        Self::with_issuer(
            secret,
            crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER.to_string(),
        )
    }

    /// Create a `GrpcJwtSecret` with an operator-configured issuer.
    pub fn with_issuer(secret: String, issuer: String) -> Self {
        Self { secret, issuer }
    }

    pub fn as_str(&self) -> &str {
        &self.secret
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
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
}

pub struct DpGrpcTlsReload {
    pub env_config: Arc<EnvConfig>,
    pub label: &'static str,
    pub revision_rx: watch::Receiver<u64>,
}

#[derive(Clone)]
pub struct DpFrontendTlsRuntime {
    pub listener_slot: crate::tls::SharedFrontendTls,
    pub restore_source_slot: Option<crate::tls::SharedFrontendTls>,
    pub h3_revision_tx: Option<watch::Sender<u64>>,
    pub cp_materialized: Arc<AtomicBool>,
}

impl DpFrontendTlsRuntime {
    pub fn new(listener_slot: crate::tls::SharedFrontendTls) -> Self {
        Self {
            listener_slot,
            restore_source_slot: None,
            h3_revision_tx: None,
            cp_materialized: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Build the DP/mesh gRPC TLS client config from shared env settings.
pub fn build_dp_grpc_tls_config(
    env_config: &EnvConfig,
    cp_urls: &[String],
    label: &str,
) -> Result<Option<DpGrpcTlsConfig>, anyhow::Error> {
    let has_tls = env_config.dp_grpc_tls_ca_cert_path.is_some()
        || env_config.dp_grpc_tls_client_cert_path.is_some()
        || cp_urls.iter().any(|u| u.starts_with("https://"));

    if !has_tls {
        return Ok(None);
    }

    if let Some(ref path) = env_config.dp_grpc_tls_ca_cert_path {
        crate::tls::check_cert_expiry(
            path,
            &format!("{label} gRPC TLS CA cert"),
            env_config.tls_cert_expiry_warning_days,
        )?;
    }
    if let Some(ref path) = env_config.dp_grpc_tls_client_cert_path {
        crate::tls::check_cert_expiry(
            path,
            &format!("{label} gRPC TLS client cert"),
            env_config.tls_cert_expiry_warning_days,
        )?;
    }

    let ca_cert_pem = if let Some(ref path) = env_config.dp_grpc_tls_ca_cert_path {
        Some(load_grpc_material(
            path,
            MaterialKind::CaBundle,
            &format!("{label} gRPC TLS CA cert"),
        )?)
    } else {
        None
    };

    let (client_cert_pem, client_key_pem) = if let (Some(cert_path), Some(key_path)) = (
        &env_config.dp_grpc_tls_client_cert_path,
        &env_config.dp_grpc_tls_client_key_path,
    ) {
        let cert = load_grpc_material(
            cert_path,
            MaterialKind::Cert,
            &format!("{label} gRPC TLS client cert"),
        )?;
        let key = load_grpc_material(
            key_path,
            MaterialKind::Key,
            &format!("{label} gRPC TLS client key"),
        )?;
        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    if ca_cert_pem.is_some() && client_cert_pem.is_some() {
        info!("{label} gRPC TLS configured with mTLS (CA cert + client cert)");
    } else if ca_cert_pem.is_some() {
        info!("{label} gRPC TLS configured with server verification (CA cert)");
    } else {
        info!("{label} gRPC TLS configured (https URL, system roots)");
    }

    Ok(Some(DpGrpcTlsConfig {
        ca_cert_pem,
        client_cert_pem,
        client_key_pem,
    }))
}

fn load_grpc_material(
    raw: &str,
    kind: MaterialKind,
    label: &str,
) -> Result<Vec<u8>, anyhow::Error> {
    let source = CertSource::parse(raw, kind);
    let material = load_material_blocking(&source, kind).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load {label} {}: {e}",
            source.redacted_source_id()
        )
    })?;
    Ok(material.bytes.expose_secret().to_vec())
}

/// JWT token lifetime for DP-generated tokens (59 minutes, under the 1-hour ceiling).
const DP_JWT_TTL_SECONDS: i64 = 3540;
/// Generate a short-lived HS256 JWT for authenticating the DP to the CP using
/// the default issuer (`DEFAULT_CP_DP_JWT_ISSUER`).
///
/// Most production callers should prefer [`generate_dp_jwt_with_issuer`] so
/// the operator-configured `FERRUM_CP_DP_GRPC_JWT_ISSUER` is honored. This
/// helper is kept for tests and library callers that want the default behavior
/// without threading the issuer through.
#[allow(dead_code)]
pub fn generate_dp_jwt(secret: &str, node_id: &str) -> Result<String, anyhow::Error> {
    generate_dp_jwt_with_issuer(
        secret,
        node_id,
        crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER,
    )
}

/// Generate a short-lived HS256 JWT for authenticating the DP to the CP.
///
/// The token is signed with the shared `FERRUM_CP_DP_GRPC_JWT_SECRET` and
/// includes `sub`, `iat`, `exp`, `iss`, and `role` claims. The `iss` claim
/// is set to `issuer` (operator-configured via `FERRUM_CP_DP_GRPC_JWT_ISSUER`,
/// default `"ferrum-edge-cp-dp"`) and MUST match the value the CP expects —
/// the CP rejects any token with a different `iss`. A fresh token is minted
/// on each gRPC connection attempt so that tokens captured from the wire
/// are only valid for ~59 minutes.
pub fn generate_dp_jwt_with_issuer(
    secret: &str,
    node_id: &str,
    issuer: &str,
) -> Result<String, anyhow::Error> {
    generate_dp_jwt_with_issuer_and_namespace(secret, node_id, issuer, None)
}

/// Generate a short-lived HS256 JWT with an optional `ns` claim pinning the
/// authorised namespace(s).
///
/// Self-minted DP tokens carry a single-namespace `ns` claim derived from
/// `FERRUM_NAMESPACE` so that CPs running with
/// `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` still accept DP self-mint flows
/// out of the box. Operator-minted tokens that should grant access to
/// multiple namespaces should bypass this helper and embed the claim as an
/// array — the CP accepts both shapes.
pub fn generate_dp_jwt_with_issuer_and_namespace(
    secret: &str,
    node_id: &str,
    issuer: &str,
    namespace: Option<&str>,
) -> Result<String, anyhow::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = match namespace {
        Some(ns) if !ns.is_empty() => json!({
            "sub": node_id,
            "iat": now,
            "exp": now + DP_JWT_TTL_SECONDS,
            "iss": issuer,
            "role": "data_plane",
            "ns": ns,
        }),
        _ => json!({
            "sub": node_id,
            "iat": now,
            "exp": now + DP_JWT_TTL_SECONDS,
            "iss": issuer,
            "role": "data_plane",
        }),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
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
    mut tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: String,
    primary_retry_secs: u64,
    connection_state: Option<Arc<ArcSwap<DpCpConnectionState>>>,
    frontend_tls_runtime: Option<DpFrontendTlsRuntime>,
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

    let mut current_cp_index: usize = 0;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut full_cycle_count: u32 = 0;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);
    let frontend_tls_slot = frontend_tls_runtime
        .as_ref()
        .map(|runtime| runtime.listener_slot.clone());
    let cp_frontend_tls_materialized = frontend_tls_runtime
        .as_ref()
        .map(|runtime| runtime.cp_materialized.clone())
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let frontend_tls_restore_slot: Arc<ArcSwap<Option<Arc<rustls::ServerConfig>>>> =
        Arc::new(ArcSwap::new(Arc::new(
            frontend_tls_slot
                .as_ref()
                .and_then(|slot| slot.load_full().as_ref().clone()),
        )));

    loop {
        if let Some(ref rx) = shutdown_rx
            && *rx.borrow()
        {
            info!("DP client shutting down");
            return;
        }

        if let Some(reload) = tls_reload.as_ref() {
            let revision = *reload.revision_rx.borrow();
            if revision != last_tls_revision {
                last_tls_revision = revision;
                match build_dp_grpc_tls_config(&reload.env_config, &cp_urls, reload.label) {
                    Ok(next_config) => {
                        tls_config = next_config;
                        info!(
                            revision,
                            "{} gRPC TLS material reloaded; reconnecting to CP with rotated material",
                            reload.label
                        );
                    }
                    Err(error) => {
                        warn!(
                            revision,
                            error = %error,
                            "{} gRPC TLS source revision changed but rebuild failed; keeping previous TLS material",
                            reload.label
                        );
                    }
                }
            }
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
        //
        // Acquire pairs with the Release store in connect_and_subscribe_with_startup_ready
        // (and the admin /health endpoint reads with Acquire too). On x86 all loads are
        // acquire-fenced by the hardware, but on ARM/AArch64 Relaxed could theoretically
        // delay visibility of the store, so we use Acquire/Release consistently.
        let should_race_primary = is_fallback
            && primary_retry_secs > 0
            && startup_ready
                .as_ref()
                .is_none_or(|r| r.load(Ordering::Acquire));
        let result = if should_race_primary {
            tokio::select! {
                res = connect_and_subscribe_with_startup_ready_inner(
                    cp_url,
                    &jwt_secret,
                    &node_id,
                    &proxy_state,
                    tls_config.as_ref(),
                    startup_ready.clone(),
                    &namespace,
                    connection_state.as_ref(),
                    is_primary,
                    frontend_tls_slot.as_ref(),
                    frontend_tls_runtime.as_ref(),
                    cp_frontend_tls_materialized.clone(),
                    frontend_tls_restore_slot.clone(),
                ) => res,
                _ = tokio::time::sleep(Duration::from_secs(primary_retry_secs)) => {
                    info!(
                        "Primary CP retry interval ({}s) elapsed; disconnecting from \
                         fallback CP [{}/{}] to retry primary",
                        primary_retry_secs,
                        current_cp_index + 1,
                        cp_count,
                    );
                    // Mark disconnected before switching — record fallback CP as last attempted
                    update_state_disconnected(&connection_state, cp_url, is_primary);
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    info!("{} gRPC TLS source changed; reconnecting CP stream", tls_reload.as_ref().map(|reload| reload.label).unwrap_or("DP"));
                    update_state_disconnected(&connection_state, cp_url, is_primary);
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            tokio::select! {
                res = connect_and_subscribe_with_startup_ready_inner(
                    cp_url,
                    &jwt_secret,
                    &node_id,
                    &proxy_state,
                    tls_config.as_ref(),
                    startup_ready.clone(),
                    &namespace,
                    connection_state.as_ref(),
                    is_primary,
                    frontend_tls_slot.as_ref(),
                    frontend_tls_runtime.as_ref(),
                    cp_frontend_tls_materialized.clone(),
                    frontend_tls_restore_slot.clone(),
                ) => res,
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    info!("{} gRPC TLS source changed; reconnecting CP stream", tls_reload.as_ref().map(|reload| reload.label).unwrap_or("DP"));
                    update_state_disconnected(&connection_state, cp_url, is_primary);
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
                _ = wait_for_readiness_then_primary_retry(
                    startup_ready.clone(),
                    primary_retry_secs,
                ), if is_fallback && primary_retry_secs > 0 => {
                    info!(
                        "Primary CP retry interval ({}s) elapsed after startup readiness; disconnecting from fallback CP [{}/{}] to retry primary",
                        primary_retry_secs,
                        current_cp_index + 1,
                        cp_count,
                    );
                    update_state_disconnected(&connection_state, cp_url, is_primary);
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        };

        let mut increase_backoff = true;
        match result {
            Ok(_) => {
                warn!(
                    "CP [{}/{}] connection stream ended ({}), will reconnect...",
                    current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                // On clean disconnect, try primary first if we were on a fallback
                if is_fallback {
                    info!("Stream ended on fallback CP; will retry primary CP first");
                    current_cp_index = 0;
                }
                backoff_secs = BACKOFF_INITIAL_SECS;
                increase_backoff = false;
            }
            Err(e) => {
                error!(
                    "CP [{}/{}] connection error ({}): {}",
                    current_cp_index + 1,
                    cp_count,
                    cp_url,
                    e
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);

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

        let sleep_duration = jittered_backoff(backoff_secs);

        if let Some(ref rx) = shutdown_rx {
            let mut rx_clone = rx.clone();
            if tls_reload.is_some() {
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
                    _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                        backoff_secs = BACKOFF_INITIAL_SECS;
                        continue;
                    }
                }
            } else {
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
            }
        } else {
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {}
                _ = wait_optional_tls_reload(tls_reload.as_ref().map(|reload| reload.revision_rx.clone())) => {
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        }

        backoff_secs = next_backoff_secs(backoff_secs, increase_backoff);
    }
}

async fn wait_for_readiness_then_primary_retry(
    startup_ready: Option<Arc<AtomicBool>>,
    primary_retry_secs: u64,
) {
    let Some(startup_ready) = startup_ready else {
        std::future::pending::<()>().await;
        return;
    };
    while !startup_ready.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(primary_retry_secs)).await;
}

async fn wait_optional_tls_reload(mut revision_rx: Option<watch::Receiver<u64>>) {
    let changed = if let Some(revision_rx) = revision_rx.as_mut() {
        revision_rx.changed().await.is_ok()
    } else {
        false
    };
    if !changed {
        std::future::pending::<()>().await;
    }
}

/// Helper: mark connection state as disconnected with the last attempted CP target.
fn update_state_disconnected(
    connection_state: &Option<Arc<ArcSwap<DpCpConnectionState>>>,
    cp_url: &str,
    is_primary: bool,
) {
    if let Some(cs) = connection_state {
        let prev = cs.load();
        cs.store(Arc::new(DpCpConnectionState {
            connected: false,
            cp_url: cp_url.to_string(),
            is_primary,
            last_config_received_at: prev.last_config_received_at,
            connected_since: None,
        }));
    }
}

/// Helper: update last_config_received_at timestamp on successful config application.
fn update_state_config_received(connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>) {
    if let Some(cs) = connection_state {
        let prev = cs.load();
        cs.store(Arc::new(DpCpConnectionState {
            connected: true,
            cp_url: prev.cp_url.clone(),
            is_primary: prev.is_primary,
            last_config_received_at: Some(Utc::now()),
            connected_since: prev.connected_since,
        }));
    }
}

#[derive(Debug)]
enum GatewayTrustBundleUpdate {
    Unchanged,
    Replace(RuntimeTrustBundleSet),
    Clear,
}

fn validate_gateway_trust_bundles(
    trust_bundles: &ConfigTrustBundleSet,
    source: &str,
) -> Result<(), String> {
    let errors = crate::modes::mesh::config::validate_mesh_config(
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        Some(trust_bundles),
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "gateway trust bundles {source} failed validation: {}",
            errors.join("; ")
        ))
    }
}

fn convert_gateway_trust_bundles(
    trust_bundles: ConfigTrustBundleSet,
    source: &str,
) -> Result<RuntimeTrustBundleSet, String> {
    validate_gateway_trust_bundles(&trust_bundles, source)?;
    trust_bundles
        .to_runtime()
        .map_err(|e| format!("gateway trust bundles {source} contains invalid trust material: {e}"))
}

fn parse_gateway_trust_bundle_update(
    trust_bundles_json: &str,
) -> Result<GatewayTrustBundleUpdate, String> {
    let trust_bundles_json = trust_bundles_json.trim();
    if !trust_bundles_json.is_empty() {
        let trust_bundles: Option<ConfigTrustBundleSet> = serde_json::from_str(trust_bundles_json)
            .map_err(|e| format!("gateway trust bundles side-channel is not valid JSON: {e}"))?;
        return match trust_bundles {
            Some(trust_bundles) => convert_gateway_trust_bundles(trust_bundles, "side-channel")
                .map(GatewayTrustBundleUpdate::Replace),
            None => Ok(GatewayTrustBundleUpdate::Clear),
        };
    }

    Ok(GatewayTrustBundleUpdate::Unchanged)
}

fn apply_gateway_trust_bundle_update(
    proxy_state: &ProxyState,
    update: GatewayTrustBundleUpdate,
) -> bool {
    match update {
        GatewayTrustBundleUpdate::Unchanged => false,
        GatewayTrustBundleUpdate::Replace(trust_bundles) => {
            let trust_domain = trust_bundles.local.trust_domain.clone();
            let federated_count = trust_bundles.federated.len();
            proxy_state.update_gateway_trust_bundles(trust_bundles);
            info!(
                %trust_domain,
                federated_count,
                "Updated gateway SPIFFE trust bundles from CP"
            );
            true
        }
        GatewayTrustBundleUpdate::Clear => {
            proxy_state.clear_gateway_trust_bundles();
            info!("Cleared CP-delivered gateway SPIFFE trust bundles");
            true
        }
    }
}

enum FrontendTlsSnapshotUpdate {
    Unchanged,
    Clear {
        restore_tls_config: Option<Arc<rustls::ServerConfig>>,
    },
    Replace {
        tls_config: Arc<rustls::ServerConfig>,
        cert_source: String,
    },
}

fn stage_frontend_tls_snapshot(
    config: &GatewayConfig,
    proxy_state: &ProxyState,
    frontend_tls_slot: Option<&crate::tls::SharedFrontendTls>,
    frontend_tls_runtime: Option<&DpFrontendTlsRuntime>,
    cp_frontend_tls_materialized: &AtomicBool,
    frontend_tls_restore_slot: &ArcSwap<Option<Arc<rustls::ServerConfig>>>,
) -> Result<FrontendTlsSnapshotUpdate, anyhow::Error> {
    if frontend_tls_slot.is_none() {
        return Ok(FrontendTlsSnapshotUpdate::Unchanged);
    }
    match (
        config.frontend_tls_cert_path.as_deref(),
        config.frontend_tls_key_path.as_deref(),
    ) {
        (None, None) => {
            if cp_frontend_tls_materialized.load(Ordering::Acquire) {
                Ok(FrontendTlsSnapshotUpdate::Clear {
                    restore_tls_config: frontend_tls_runtime
                        .and_then(|runtime| runtime.restore_source_slot.as_ref())
                        .and_then(|slot| slot.load_full().as_ref().clone())
                        .or_else(|| frontend_tls_restore_slot.load_full().as_ref().clone()),
                })
            } else {
                Ok(FrontendTlsSnapshotUpdate::Unchanged)
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "frontend TLS config must include both frontend_tls_cert_path and frontend_tls_key_path"
            );
        }
        (Some(cert_path), Some(key_path)) => {
            if !cp_frontend_tls_materialized.load(Ordering::Acquire)
                && let Some(slot) = frontend_tls_slot
            {
                frontend_tls_restore_slot.store(slot.load_full());
            }
            let Some(tls_policy) = proxy_state.tls_policy.as_deref() else {
                anyhow::bail!(
                    "frontend TLS material was provided by CP but this DP has no TLS policy"
                );
            };

            let mut tls_config = crate::tls::load_tls_config_with_client_auth_and_ocsp(
                cert_path,
                key_path,
                proxy_state
                    .env_config
                    .frontend_tls_client_ca_bundle_path
                    .as_deref(),
                proxy_state
                    .env_config
                    .frontend_tls_ocsp_response_source
                    .as_deref(),
                false,
                tls_policy,
                proxy_state.env_config.tls_cert_expiry_warning_days,
                proxy_state.crls.as_ref().as_slice(),
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to materialize frontend TLS certificate source {}: {}",
                    cert_path,
                    error
                )
            })?;
            crate::tls::enable_early_data(&mut tls_config, tls_policy);
            if proxy_state.env_config.ktls_enabled.could_be_enabled() {
                crate::tls::enable_secret_extraction_for_ktls(&mut tls_config);
            }

            Ok(FrontendTlsSnapshotUpdate::Replace {
                tls_config,
                cert_source: cert_path.to_string(),
            })
        }
    }
}

async fn commit_frontend_tls_snapshot(
    update: FrontendTlsSnapshotUpdate,
    proxy_state: &ProxyState,
    frontend_tls_slot: Option<&crate::tls::SharedFrontendTls>,
    frontend_tls_runtime: Option<&DpFrontendTlsRuntime>,
    cp_frontend_tls_materialized: &AtomicBool,
) {
    match update {
        FrontendTlsSnapshotUpdate::Unchanged => {}
        FrontendTlsSnapshotUpdate::Clear { restore_tls_config } => {
            if let Some(slot) = frontend_tls_slot {
                let had_tls = slot.load_full().as_ref().is_some();
                slot.store(Arc::new(restore_tls_config.clone()));
                proxy_state
                    .stream_listener_manager
                    .set_frontend_tls_config(restore_tls_config.clone())
                    .await;
                if restore_tls_config.is_some() {
                    info!(
                        "Restored operator frontend TLS material after clearing CP-delivered Gateway frontend TLS"
                    );
                } else if had_tls {
                    info!("Cleared CP-delivered Gateway frontend TLS material");
                }
                bump_frontend_tls_revision(frontend_tls_runtime);
            }
            cp_frontend_tls_materialized.store(false, Ordering::Release);
        }
        FrontendTlsSnapshotUpdate::Replace {
            tls_config,
            cert_source,
        } => {
            if let Some(slot) = frontend_tls_slot {
                slot.store(Arc::new(Some(tls_config.clone())));
                proxy_state
                    .stream_listener_manager
                    .set_frontend_tls_config(Some(tls_config))
                    .await;
                cp_frontend_tls_materialized.store(true, Ordering::Release);
                bump_frontend_tls_revision(frontend_tls_runtime);
                info!(
                    cert_source = %cert_source,
                    "Applied CP-delivered Gateway frontend TLS material"
                );
            }
        }
    }
}

fn bump_frontend_tls_revision(frontend_tls_runtime: Option<&DpFrontendTlsRuntime>) {
    if let Some(revision_tx) =
        frontend_tls_runtime.and_then(|runtime| runtime.h3_revision_tx.as_ref())
    {
        revision_tx.send_modify(|revision| *revision = revision.saturating_add(1));
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
        None,
        true,
        None,
    )
    .await
}

/// Connect to CP and optionally flip startup readiness after the first applied snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn connect_and_subscribe_with_startup_ready(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: &str,
    connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>,
    is_primary: bool,
    frontend_tls_slot: Option<&crate::tls::SharedFrontendTls>,
) -> Result<(), anyhow::Error> {
    let frontend_tls_runtime =
        frontend_tls_slot.map(|slot| DpFrontendTlsRuntime::new(slot.clone()));
    connect_and_subscribe_with_startup_ready_inner(
        cp_url,
        jwt_secret,
        node_id,
        proxy_state,
        tls_config,
        startup_ready,
        namespace,
        connection_state,
        is_primary,
        frontend_tls_slot,
        frontend_tls_runtime.as_ref(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(ArcSwap::new(Arc::new(
            frontend_tls_slot
                .map(|slot| slot.load_full().as_ref().clone())
                .unwrap_or(None),
        ))),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_and_subscribe_with_startup_ready_inner(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: &str,
    connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>,
    is_primary: bool,
    frontend_tls_slot: Option<&crate::tls::SharedFrontendTls>,
    frontend_tls_runtime: Option<&DpFrontendTlsRuntime>,
    cp_frontend_tls_materialized: Arc<AtomicBool>,
    frontend_tls_restore_slot: Arc<ArcSwap<Option<Arc<rustls::ServerConfig>>>>,
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

    // Mint a fresh short-lived JWT for this connection attempt. The `iss`
    // claim is set from the operator-configured issuer carried alongside
    // the shared secret; the CP rejects any token with a mismatched `iss`.
    // The `ns` claim is set from the DP's own FERRUM_NAMESPACE so
    // multi-namespace CPs configured with `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`
    // accept self-minted DP tokens. Single-namespace CPs ignore the extra
    // claim — it never restricts the back-compat path.
    let auth_token = generate_dp_jwt_with_issuer_and_namespace(
        jwt_secret.as_str(),
        node_id,
        jwt_secret.issuer(),
        Some(namespace),
    )?;
    info!(
        "Generated fresh DP JWT (TTL={}s, iss='{}', ns='{}') for CP authentication",
        DP_JWT_TTL_SECONDS,
        jwt_secret.issuer(),
        namespace,
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
        real_ip_header: Some(
            proxy_state
                .env_config
                .real_ip_header
                .clone()
                .unwrap_or_default(),
        ),
    });

    let mut stream = client.subscribe(request).await?.into_inner();
    let mut initial_snapshot_applied = startup_ready.is_none();

    // Mark connected
    if let Some(cs) = connection_state {
        let now = Utc::now();
        cs.store(Arc::new(DpCpConnectionState {
            connected: true,
            cp_url: cp_url.to_string(),
            is_primary,
            last_config_received_at: None,
            connected_since: Some(now),
        }));
    }

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
                        let gateway_trust_bundle_update =
                            match parse_gateway_trust_bundle_update(&update.trust_bundles_json) {
                                Ok(update) => update,
                                Err(msg) => {
                                    error!("CP config rejected — {}", msg);
                                    error!(
                                        "Ignoring config update with invalid gateway trust bundles"
                                    );
                                    continue;
                                }
                            };
                        // Gateway trust material is delivered via the ConfigUpdate
                        // side-channel. Do not retain any legacy/config-file copy in
                        // the DP's regular GatewayConfig snapshot.
                        config.trust_bundles = None;
                        // Defense in depth: even though the CP-side
                        // namespace check should prevent any
                        // cross-namespace resources from reaching this
                        // DP, filter again locally so a CP regression or
                        // buggy/malicious snapshot can't leak resources
                        // from another tenant into this DP's
                        // GatewayConfig. See `filter_config_to_namespace`.
                        let filtered = filter_config_to_namespace(&mut config, namespace);
                        if filtered > 0 {
                            warn!(
                                "DP namespace filter '{}' excluded {} cross-namespace resources from CP snapshot — \
                                 the CP should have filtered these (verify CP namespace matches DP)",
                                namespace, filtered
                            );
                        }
                        if frontend_tls_slot.is_none() && clear_frontend_tls_material(&mut config) {
                            warn!(
                                "Ignoring CP-delivered frontend TLS material because this DP has no HTTPS listener"
                            );
                        }
                        config.normalize_fields();
                        config.resolve_upstream_tls();
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
                        if let Err(errors) = config.validate_listen_path_encodings() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with encoded-slash listen_paths");
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
                        if let Err(errors) =
                            crate::proxy::validate_mesh_route_dispatch_upstream_references(&config)
                        {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!(
                                "Ignoring config update with invalid mesh_route_dispatch upstream references"
                            );
                            continue;
                        }
                        let frontend_tls_update = match stage_frontend_tls_snapshot(
                            &config,
                            proxy_state,
                            frontend_tls_slot,
                            frontend_tls_runtime,
                            cp_frontend_tls_materialized.as_ref(),
                            frontend_tls_restore_slot.as_ref(),
                        ) {
                            Ok(update) => update,
                            Err(error) => {
                                error!("CP config rejected — {}", error);
                                error!(
                                    "Ignoring config update with unusable frontend TLS material"
                                );
                                continue;
                            }
                        };
                        match proxy_state.update_config_off_thread(config).await {
                            ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged => {
                                commit_frontend_tls_snapshot(
                                    frontend_tls_update,
                                    proxy_state,
                                    frontend_tls_slot,
                                    frontend_tls_runtime,
                                    cp_frontend_tls_materialized.as_ref(),
                                )
                                .await;
                                apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                );
                                update_state_config_received(connection_state);
                                if !initial_snapshot_applied {
                                    proxy_state
                                        .stream_listener_manager
                                        .wait_until_started(Duration::from_secs(10))
                                        .await?;
                                    // Block DP readiness on the first capability
                                    // classification. Without this the `/health`
                                    // endpoint would flip to ready while the
                                    // registry is still empty, so an L4 LB could
                                    // route traffic to an H3-only HTTPS backend
                                    // and the cross-protocol bridge would 502
                                    // until the background refresh landed.
                                    // Subsequent CP snapshots don't take this
                                    // path — `update_config` already spawns a
                                    // coalesced background refresh for them.
                                    proxy_state.refresh_backend_capabilities().await;
                                    if let Some(ref startup_ready) = startup_ready {
                                        startup_ready.store(true, Ordering::Release);
                                    }
                                    initial_snapshot_applied = true;
                                    info!(
                                        "DP startup complete; backend capabilities classified; /health now reports ready"
                                    );
                                }
                                info!("Full configuration snapshot accepted from CP");
                            }
                            ConfigApplyOutcome::Rejected { .. } => {
                                error!(
                                    "Full configuration snapshot rejected during apply; keeping previous config"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse full config update: {}", e);
                    }
                }
            }
            1 => {
                // DELTA — apply incremental changes only
                match serde_json::from_str::<IncrementalResult>(&update.config_json) {
                    Ok(mut result) => {
                        let gateway_trust_bundle_update =
                            match parse_gateway_trust_bundle_update(&update.trust_bundles_json) {
                                Ok(update) => update,
                                Err(msg) => {
                                    error!("CP delta rejected — {}", msg);
                                    error!("Ignoring delta with invalid gateway trust bundles");
                                    continue;
                                }
                            };
                        // Defense in depth: filter cross-namespace
                        // additions/modifications before applying. See
                        // `filter_incremental_to_namespace`.
                        let filtered = filter_incremental_to_namespace(&mut result, namespace);
                        if filtered > 0 {
                            warn!(
                                "DP namespace filter '{}' excluded {} cross-namespace resources from CP delta",
                                namespace, filtered
                            );
                        }

                        // Empty deltas mean "nothing changed since last poll" — the
                        // CP poll loop suppresses these (see modes/control_plane.rs),
                        // but a custom CP or test could still emit one. Treat as
                        // benign so we don't trip the divergence log below.
                        let was_empty = result.is_empty();

                        // Capture summary BEFORE moving `result` into apply_incremental
                        // so the rejection log can identify the divergent CP push.
                        let added_proxy_ids: Vec<String> = result
                            .added_or_modified_proxies
                            .iter()
                            .map(|p| p.id.clone())
                            .collect();
                        let added_upstream_ids: Vec<String> = result
                            .added_or_modified_upstreams
                            .iter()
                            .map(|u| u.id.clone())
                            .collect();
                        let added_consumer_ids: Vec<String> = result
                            .added_or_modified_consumers
                            .iter()
                            .map(|c| c.id.clone())
                            .collect();
                        let added_plugin_config_ids: Vec<String> = result
                            .added_or_modified_plugin_configs
                            .iter()
                            .map(|pc| pc.id.clone())
                            .collect();
                        let removed_proxy_ids = result.removed_proxy_ids.clone();
                        let removed_upstream_ids = result.removed_upstream_ids.clone();
                        let removed_consumer_ids = result.removed_consumer_ids.clone();
                        let removed_plugin_config_ids = result.removed_plugin_config_ids.clone();
                        let cp_version = update.ferrum_version.clone();
                        let update_version = update.version;

                        match proxy_state.apply_incremental(result).await {
                            ConfigApplyOutcome::Applied => {
                                apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                );
                                update_state_config_received(connection_state);
                                info!("Incremental config delta applied from CP");
                            }
                            ConfigApplyOutcome::Unchanged => {
                                if apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                ) {
                                    update_state_config_received(connection_state);
                                    info!("Gateway trust bundle update applied from CP");
                                    continue;
                                }
                                if !was_empty {
                                    update_state_config_received(connection_state);
                                    debug!(
                                        "Incremental config delta from CP was valid but unchanged"
                                    );
                                    continue;
                                }
                                // Empty delta — preserve original behavior of not
                                // touching `last_config_received_at` so cluster
                                // observability still reflects only deltas that
                                // carried real changes.
                                if was_empty {
                                    tracing::debug!(
                                        "Ignoring empty delta from CP (no resource changes)"
                                    );
                                }
                            }
                            ConfigApplyOutcome::Rejected { errors } => {
                                if apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                ) {
                                    update_state_config_received(connection_state);
                                    info!(
                                        "Gateway trust bundle update applied from CP despite rejected resource delta"
                                    );
                                }
                                if was_empty {
                                    tracing::debug!(
                                        "Ignoring rejected empty delta from CP (no resource changes)"
                                    );
                                } else {
                                    // apply_incremental rejected a non-empty delta
                                    // — surface the divergence to operators so the
                                    // DP does not silently keep serving its cached
                                    // config until the next full snapshot.
                                    error!(
                                        cp_version = %cp_version,
                                        update_version = update_version,
                                        added_proxies = ?added_proxy_ids,
                                        removed_proxies = ?removed_proxy_ids,
                                        added_upstreams = ?added_upstream_ids,
                                        removed_upstreams = ?removed_upstream_ids,
                                        added_consumers = ?added_consumer_ids,
                                        removed_consumers = ?removed_consumer_ids,
                                        added_plugin_configs = ?added_plugin_config_ids,
                                        removed_plugin_configs = ?removed_plugin_config_ids,
                                        validation_errors = ?errors,
                                        "DP rejected CP-pushed delta — divergence possible until next full snapshot"
                                    );
                                }
                            }
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

/// Defense-in-depth: filter a full config snapshot to only the DP's
/// configured namespace before applying.
///
/// The CP-side `check_namespace` guard already rejects DP subscriptions that
/// advertise a mismatched namespace, so under normal operation this filter
/// is a no-op (the snapshot the CP sends is already single-namespace).
/// We still run it because:
///
/// 1. A future bug or regression on the CP side that re-enables
///    cross-namespace serving would silently leak resources to the DP.
///    The DP enforcing its own namespace bound prevents that.
/// 2. The serialization is JSON, so a malicious or buggy CP could craft
///    a snapshot whose `proxies[i].namespace != requested_namespace`.
///    Belt-and-braces is cheap.
///
/// Returns the number of resources filtered out so the caller can warn.
fn filter_config_to_namespace(config: &mut GatewayConfig, namespace: &str) -> usize {
    let pre = (
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len(),
        config.upstreams.len(),
    );
    config.proxies.retain(|p| p.namespace == namespace);
    config.consumers.retain(|c| c.namespace == namespace);
    config.plugin_configs.retain(|pc| pc.namespace == namespace);
    config.upstreams.retain(|u| u.namespace == namespace);
    let frontend_tls_filtered = filter_frontend_tls_sources_to_namespace(config, namespace);
    (pre.0 - config.proxies.len())
        + (pre.1 - config.consumers.len())
        + (pre.2 - config.plugin_configs.len())
        + (pre.3 - config.upstreams.len())
        + usize::from(frontend_tls_filtered)
}

fn filter_frontend_tls_sources_to_namespace(config: &mut GatewayConfig, namespace: &str) -> bool {
    let had_namespace_sources = !config.frontend_tls_namespace_sources.is_empty();
    if let Some(source) = config
        .frontend_tls_namespace_sources
        .iter()
        .find(|source| source.namespace == namespace)
        .cloned()
    {
        config.frontend_tls_cert_path = Some(source.cert_path);
        config.frontend_tls_key_path = Some(source.key_path);
        config.frontend_tls_source_namespace = Some(source.namespace);
        config.frontend_tls_namespace_sources.clear();
        return false;
    }
    config.frontend_tls_namespace_sources.clear();
    let foreign = config
        .frontend_tls_source_namespace
        .as_deref()
        .is_some_and(|source_namespace| source_namespace != namespace);
    if foreign {
        config.frontend_tls_cert_path = None;
        config.frontend_tls_key_path = None;
        config.frontend_tls_source_namespace = None;
    }
    foreign || had_namespace_sources
}

fn clear_frontend_tls_material(config: &mut GatewayConfig) -> bool {
    let had_material = config.frontend_tls_cert_path.is_some()
        || config.frontend_tls_key_path.is_some()
        || config.frontend_tls_source_namespace.is_some()
        || !config.frontend_tls_namespace_sources.is_empty();
    config.frontend_tls_cert_path = None;
    config.frontend_tls_key_path = None;
    config.frontend_tls_source_namespace = None;
    config.frontend_tls_namespace_sources.clear();
    had_material
}

/// Defense-in-depth filter for incremental deltas. Applied to
/// `added_or_modified_*` vectors only; removal IDs are namespace-agnostic
/// and harmless on the DP side because they only delete resources the DP
/// already has (which were themselves filtered through this same check).
///
/// Returns the number of resources filtered out so the caller can warn.
fn filter_incremental_to_namespace(result: &mut IncrementalResult, namespace: &str) -> usize {
    let pre = (
        result.added_or_modified_proxies.len(),
        result.added_or_modified_consumers.len(),
        result.added_or_modified_plugin_configs.len(),
        result.added_or_modified_upstreams.len(),
    );
    result
        .added_or_modified_proxies
        .retain(|p| p.namespace == namespace);
    result
        .added_or_modified_consumers
        .retain(|c| c.namespace == namespace);
    result
        .added_or_modified_plugin_configs
        .retain(|pc| pc.namespace == namespace);
    result
        .added_or_modified_upstreams
        .retain(|u| u.namespace == namespace);
    (pre.0 - result.added_or_modified_proxies.len())
        + (pre.1 - result.added_or_modified_consumers.len())
        + (pre.2 - result.added_or_modified_plugin_configs.len())
        + (pre.3 - result.added_or_modified_upstreams.len())
}

/// Check whether the CP's reported version is compatible with this DP.
///
/// Major and minor versions must match. Patch-level differences are allowed.
pub(crate) fn check_cp_version_compatibility(cp_version: &str) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    //! Inline tests for the DP-side namespace filter helpers. These are
    //! private functions, so they live alongside the implementation rather
    //! than in `tests/`. The end-to-end behavior is exercised by
    //! `tests/integration/cp_dp_grpc_tests.rs` via
    //! `test_dp_filters_cross_namespace_resources_from_snapshot`.
    use super::*;
    use crate::config::EnvConfig;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::proxy::ProxyState;
    use crate::util::backoff::jittered_backoff_with_entropy;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn next_backoff_does_not_increase_after_clean_stream_end() {
        assert_eq!(
            next_backoff_secs(BACKOFF_INITIAL_SECS, false),
            BACKOFF_INITIAL_SECS
        );
        assert_eq!(next_backoff_secs(16, false), BACKOFF_INITIAL_SECS);
    }

    #[test]
    fn next_backoff_increases_after_connection_error_until_cap() {
        assert_eq!(next_backoff_secs(1, true), 2);
        assert_eq!(next_backoff_secs(16, true), 30);
        assert_eq!(next_backoff_secs(30, true), 30);
    }

    #[test]
    fn jittered_backoff_with_entropy_stays_within_expected_range() {
        let samples = [0, 249, 250, 499, u64::MAX];

        for entropy in samples {
            let duration = jittered_backoff_with_entropy(1, entropy);
            assert!(duration >= Duration::from_millis(750));
            assert!(duration < Duration::from_millis(1250));
        }
    }

    #[test]
    fn jittered_backoff_never_sleeps_below_minimum() {
        assert_eq!(
            jittered_backoff_with_entropy(0, 0),
            Duration::from_millis(100)
        );
    }

    fn minimal_proxy_state() -> ProxyState {
        ProxyState::new(
            GatewayConfig::default(),
            DnsCache::new(DnsConfig::default()),
            EnvConfig::default(),
            None,
            None,
        )
        .expect("minimal ProxyState should construct")
        .0
    }

    #[tokio::test]
    async fn commit_frontend_tls_snapshot_notifies_h3_reload_revision() {
        let proxy_state = minimal_proxy_state();
        let listener_slot = crate::tls::empty_frontend_tls_slot();
        let (revision_tx, revision_rx) = watch::channel(0_u64);
        let runtime = DpFrontendTlsRuntime {
            listener_slot: listener_slot.clone(),
            restore_source_slot: None,
            h3_revision_tx: Some(revision_tx),
            cp_materialized: Arc::new(AtomicBool::new(false)),
        };
        let tls_config =
            crate::tls::temporary_disabled_listener_tls_config().expect("test TLS config");

        commit_frontend_tls_snapshot(
            FrontendTlsSnapshotUpdate::Replace {
                tls_config,
                cert_source: "test-cert".to_string(),
            },
            &proxy_state,
            Some(&listener_slot),
            Some(&runtime),
            runtime.cp_materialized.as_ref(),
        )
        .await;

        assert_eq!(*revision_rx.borrow(), 1);
        assert!(runtime.cp_materialized.load(Ordering::Acquire));
        assert!(listener_slot.load_full().as_ref().is_some());

        commit_frontend_tls_snapshot(
            FrontendTlsSnapshotUpdate::Clear {
                restore_tls_config: None,
            },
            &proxy_state,
            Some(&listener_slot),
            Some(&runtime),
            runtime.cp_materialized.as_ref(),
        )
        .await;

        assert_eq!(*revision_rx.borrow(), 2);
        assert!(!runtime.cp_materialized.load(Ordering::Acquire));
        assert!(listener_slot.load_full().as_ref().is_none());
    }

    #[tokio::test]
    async fn stage_frontend_tls_snapshot_ignores_tls_when_https_listener_is_absent() {
        let proxy_state = minimal_proxy_state();
        let config = GatewayConfig {
            frontend_tls_cert_path: Some("k8s://default/cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://default/cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("default".to_string()),
            ..Default::default()
        };
        let cp_materialized = AtomicBool::new(false);
        let restore_slot = ArcSwap::from_pointee(None);

        let update = stage_frontend_tls_snapshot(
            &config,
            &proxy_state,
            None,
            None,
            &cp_materialized,
            &restore_slot,
        )
        .expect("disabled HTTPS listener should not reject the whole snapshot");

        assert!(matches!(update, FrontendTlsSnapshotUpdate::Unchanged));
        assert!(!cp_materialized.load(Ordering::Acquire));
    }

    #[test]
    fn clear_frontend_tls_material_removes_all_cp_tls_fields() {
        let mut config = GatewayConfig {
            frontend_tls_cert_path: Some("k8s://default/cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://default/cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("default".to_string()),
            frontend_tls_namespace_sources: vec![
                crate::config::types::FrontendTlsNamespaceSource {
                    namespace: "default".to_string(),
                    cert_path: "k8s://default/cert#tls.crt".to_string(),
                    key_path: "k8s://default/cert#tls.key".to_string(),
                },
            ],
            ..Default::default()
        };

        assert!(clear_frontend_tls_material(&mut config));
        assert_eq!(config.frontend_tls_cert_path, None);
        assert_eq!(config.frontend_tls_key_path, None);
        assert_eq!(config.frontend_tls_source_namespace, None);
        assert!(config.frontend_tls_namespace_sources.is_empty());
        assert!(!clear_frontend_tls_material(&mut config));
    }

    fn test_config_trust_bundles(x509_authorities: Vec<String>) -> ConfigTrustBundleSet {
        ConfigTrustBundleSet {
            local: crate::modes::mesh::config::TrustBundle {
                trust_domain: crate::identity::TrustDomain::new("cluster.local")
                    .expect("test trust domain should be valid"),
                x509_authorities,
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    #[test]
    fn parse_gateway_trust_bundle_update_treats_empty_side_channel_as_unchanged() {
        let update = parse_gateway_trust_bundle_update("").expect("empty side-channel is valid");
        assert!(matches!(update, GatewayTrustBundleUpdate::Unchanged));
    }

    #[test]
    fn parse_gateway_trust_bundle_update_treats_null_side_channel_as_clear() {
        let update = parse_gateway_trust_bundle_update("null").expect("null side-channel is valid");
        assert!(matches!(update, GatewayTrustBundleUpdate::Clear));
    }

    #[test]
    fn parse_gateway_trust_bundle_update_rejects_semantically_invalid_bundle() {
        let trust_bundles = test_config_trust_bundles(Vec::new());
        let json = serde_json::to_string(&trust_bundles).expect("test bundle should serialize");
        let err = parse_gateway_trust_bundle_update(&json)
            .expect_err("empty authority bundle should be rejected");

        assert!(err.contains("failed validation"), "unexpected error: {err}");
        assert!(
            err.contains("has no authorities"),
            "unexpected error: {err}"
        );
    }

    fn proxy_in_namespace(id: &str, ns: &str) -> crate::config::types::Proxy {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "backend_host": "example.com",
            "backend_port": 443,
        }))
        .expect("proxy fixture should deserialize")
    }

    fn upstream_in_namespace(id: &str, ns: &str) -> crate::config::types::Upstream {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "targets": [{"host": "example.com", "port": 443, "weight": 100}],
            "algorithm": "round_robin",
        }))
        .expect("upstream fixture should deserialize")
    }

    fn consumer_in_namespace(id: &str, ns: &str) -> crate::config::types::Consumer {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "username": id,
            "credentials": {},
        }))
        .expect("consumer fixture should deserialize")
    }

    fn plugin_config_in_namespace(id: &str, ns: &str) -> crate::config::types::PluginConfig {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "plugin_name": "rate_limiting",
            "config": {},
            "scope": "global",
        }))
        .expect("plugin_config fixture should deserialize")
    }

    #[test]
    fn filter_config_keeps_matching_namespace_only() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![
                proxy_in_namespace("p-prod", "production"),
                proxy_in_namespace("p-staging", "staging"),
                proxy_in_namespace("p-prod-2", "production"),
            ],
            consumers: vec![
                consumer_in_namespace("c-prod", "production"),
                consumer_in_namespace("c-staging", "staging"),
            ],
            plugin_configs: vec![
                plugin_config_in_namespace("pc-prod", "production"),
                plugin_config_in_namespace("pc-staging", "staging"),
            ],
            upstreams: vec![
                upstream_in_namespace("u-prod", "production"),
                upstream_in_namespace("u-staging", "staging"),
            ],
            expected_resource_counts: None,
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
        };

        let filtered = filter_config_to_namespace(&mut cfg, "production");
        assert_eq!(filtered, 4, "1 proxy + 1 consumer + 1 plugin + 1 upstream");

        assert_eq!(cfg.proxies.len(), 2);
        assert!(cfg.proxies.iter().all(|p| p.namespace == "production"));
        assert_eq!(cfg.consumers.len(), 1);
        assert_eq!(cfg.consumers[0].namespace, "production");
        assert_eq!(cfg.plugin_configs.len(), 1);
        assert_eq!(cfg.plugin_configs[0].namespace, "production");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].namespace, "production");
    }

    #[test]
    fn filter_config_returns_zero_when_clean() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![proxy_in_namespace("p-prod", "production")],
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            expected_resource_counts: None,
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
        };
        assert_eq!(filter_config_to_namespace(&mut cfg, "production"), 0);
        assert_eq!(cfg.proxies.len(), 1);
    }

    #[test]
    fn filter_config_clears_foreign_gateway_frontend_tls_sources() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://staging/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://staging/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("staging".to_string()),
            ..Default::default()
        };

        assert_eq!(filter_config_to_namespace(&mut cfg, "production"), 1);
        assert_eq!(cfg.frontend_tls_cert_path, None);
        assert_eq!(cfg.frontend_tls_key_path, None);
        assert_eq!(cfg.frontend_tls_source_namespace, None);
    }

    #[test]
    fn filter_config_keeps_matching_gateway_frontend_tls_sources() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://secrets/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://secrets/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("production".to_string()),
            ..Default::default()
        };

        assert_eq!(filter_config_to_namespace(&mut cfg, "production"), 0);
        assert_eq!(
            cfg.frontend_tls_cert_path.as_deref(),
            Some("k8s://secrets/gateway-cert#tls.crt")
        );
        assert_eq!(
            cfg.frontend_tls_key_path.as_deref(),
            Some("k8s://secrets/gateway-cert#tls.key")
        );
    }

    #[test]
    fn filter_config_projects_namespace_scoped_gateway_frontend_tls_sources() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://staging/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://staging/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("staging".to_string()),
            frontend_tls_namespace_sources: vec![
                crate::config::types::FrontendTlsNamespaceSource {
                    namespace: "staging".to_string(),
                    cert_path: "k8s://staging/gateway-cert#tls.crt".to_string(),
                    key_path: "k8s://staging/gateway-cert#tls.key".to_string(),
                },
                crate::config::types::FrontendTlsNamespaceSource {
                    namespace: "production".to_string(),
                    cert_path: "k8s://production/gateway-cert#tls.crt".to_string(),
                    key_path: "k8s://production/gateway-cert#tls.key".to_string(),
                },
            ],
            ..Default::default()
        };

        assert_eq!(filter_config_to_namespace(&mut cfg, "production"), 0);
        assert_eq!(
            cfg.frontend_tls_cert_path.as_deref(),
            Some("k8s://production/gateway-cert#tls.crt")
        );
        assert_eq!(
            cfg.frontend_tls_key_path.as_deref(),
            Some("k8s://production/gateway-cert#tls.key")
        );
        assert_eq!(
            cfg.frontend_tls_source_namespace.as_deref(),
            Some("production")
        );
        assert!(cfg.frontend_tls_namespace_sources.is_empty());
    }

    #[test]
    fn filter_incremental_keeps_matching_namespace_only() {
        let mut delta = IncrementalResult {
            added_or_modified_proxies: vec![
                proxy_in_namespace("p-prod", "production"),
                proxy_in_namespace("p-staging", "staging"),
            ],
            removed_proxy_ids: vec!["doesnt-matter".to_string()],
            added_or_modified_consumers: vec![consumer_in_namespace("c-staging", "staging")],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![plugin_config_in_namespace(
                "pc-prod",
                "production",
            )],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![
                upstream_in_namespace("u-prod", "production"),
                upstream_in_namespace("u-staging", "staging"),
            ],
            removed_upstream_ids: vec![],
            sequence_cursor: 0,
            poll_timestamp: Utc::now(),
        };

        let filtered = filter_incremental_to_namespace(&mut delta, "production");
        assert_eq!(filtered, 3, "1 proxy + 1 consumer + 1 upstream filtered");

        assert_eq!(delta.added_or_modified_proxies.len(), 1);
        assert_eq!(delta.added_or_modified_proxies[0].namespace, "production");
        assert!(delta.added_or_modified_consumers.is_empty());
        assert_eq!(delta.added_or_modified_plugin_configs.len(), 1);
        assert_eq!(delta.added_or_modified_upstreams.len(), 1);

        // Removal IDs are intentionally NOT filtered — the DP only has
        // resources in its own namespace anyway, so deleting an unknown ID
        // is harmless.
        assert_eq!(delta.removed_proxy_ids.len(), 1);
    }

    #[test]
    fn filter_incremental_returns_zero_when_empty() {
        let mut delta = IncrementalResult {
            added_or_modified_proxies: vec![],
            removed_proxy_ids: vec![],
            added_or_modified_consumers: vec![],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![],
            removed_upstream_ids: vec![],
            sequence_cursor: 0,
            poll_timestamp: Utc::now(),
        };
        assert_eq!(filter_incremental_to_namespace(&mut delta, "production"), 0);
    }
}
