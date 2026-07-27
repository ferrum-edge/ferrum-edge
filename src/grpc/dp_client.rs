//! Data Plane gRPC client — subscribes to the CP's config stream.
//!
//! The outer reconnect loop (`start_dp_client_with_shutdown`) uses exponential
//! backoff with jitter (1s → 2s → 4s → … → 30s cap, ±25% jitter) to avoid
//! thundering-herd reconnection storms when many DPs restart simultaneously.
//! Backoff follows the failure sequence across multi-CP failover and is not
//! reset merely because the selected CP index changed; a clean close that
//! delivered no config message counts as a failure for backoff purposes.
//! A transport/RPC failure after this attempt already accepted config also
//! resets backoff (healthy progress). Intentional disconnect (primary retry /
//! TLS reload) resets without sleeping as a failure.
//!
//! Inside the stream handler, two message types:
//! - `update_type=0` (FULL_SNAPSHOT): replaces the entire `GatewayConfig`
//! - `update_type=1` (DELTA): applies incremental changes via `apply_incremental()`
//!
//! Heartbeat frames (`ConfigUpdate.heartbeat`) refresh liveness without apply.
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
use std::time::{Duration, Instant};
use tokio::sync::{Notify, watch};
use tonic::metadata::MetadataValue;
use tonic::transport::channel::ClientTlsConfig;
use tonic::transport::{Certificate, Channel, Endpoint, Identity};
use tracing::{debug, error, info, warn};

use super::configsync_lifecycle::{
    AppliedSnapshotAuthority, CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
    CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, CONFIGSYNC_TCP_KEEPALIVE_SECS,
    ConfigSyncAttemptOutcome, ConfigSyncDivergenceMetrics, ConfigSyncStreamTimings,
    DeltaRejectionKind, FullSnapshotStreamDisposition, GatewayTrustEquivalenceState,
    MultiCpBackoffState, SubscriptionApplyState, advance_authority_from_committed,
    advance_multi_cp_backoff, authoritative_snapshot_payload_matches,
    check_peer_version_compatibility, connection_error_outcome, delta_rejection_stream_disposition,
    evaluate_delta_against_subscription_base, evaluate_delta_authority,
    evaluate_snapshot_clock_skew, full_snapshot_stream_disposition,
    gateway_trust_equivalence_state, grow_backoff_after_failure_sleep, heartbeat_frame_admissible,
    reconcile_snapshot_version, record_applied_gateway_trust,
    resolve_authority_trust_after_snapshot, resource_delta_advances_authority,
    silence_watchdog_armed, snapshot_failure_stream_disposition,
    snapshot_requires_older_payload_exception, stale_reject_from_reconcile,
};
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
use crate::util::backoff::jittered_backoff;

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
    /// Timestamp of the last *accepted* config update received from CP.
    /// Rejected resource deltas must not advance this stamp.
    pub last_config_received_at: Option<DateTime<Utc>>,
    /// When the current connection was established (None if disconnected).
    pub connected_since: Option<DateTime<Utc>>,
    /// Sticky operator signal: a non-empty ConfigSync DELTA was rejected and
    /// the DP has not yet accepted an authoritative FULL_SNAPSHOT recovery
    /// (issue #2394). Last-known-good config continues to serve.
    pub config_diverged: bool,
    /// When sticky divergence was first raised (cleared on FULL_SNAPSHOT recovery).
    pub config_diverged_since: Option<DateTime<Utc>>,
    /// Count of divergence → FULL_SNAPSHOT recovery transitions.
    pub config_divergence_recoveries_total: u64,
}

impl DpCpConnectionState {
    pub fn new_disconnected(cp_url: &str) -> Self {
        Self {
            connected: false,
            cp_url: cp_url.to_string(),
            is_primary: true,
            last_config_received_at: None,
            connected_since: None,
            config_diverged: false,
            config_diverged_since: None,
            config_divergence_recoveries_total: 0,
        }
    }

    /// Build the connected-state view a reconnect must publish, preserving the
    /// applied-config age and sticky ConfigSync divergence carried across the
    /// disconnect while marking the new stream connected.
    ///
    /// A reconnect (including CP failover) must not reset `last_config_received_at`
    /// or clear `config_diverged` / `config_diverged_since` /
    /// `config_divergence_recoveries_total`: last-known-good config keeps serving
    /// and sticky divergence clears only after an accepted authoritative
    /// FULL_SNAPSHOT, not merely because the transport reconnected.
    pub fn reconnected(
        &self,
        cp_url: &str,
        is_primary: bool,
        connected_since: DateTime<Utc>,
    ) -> Self {
        Self {
            connected: true,
            cp_url: cp_url.to_string(),
            is_primary,
            last_config_received_at: self.last_config_received_at,
            connected_since: Some(connected_since),
            config_diverged: self.config_diverged,
            config_diverged_since: self.config_diverged_since,
            config_divergence_recoveries_total: self.config_divergence_recoveries_total,
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
    #[allow(dead_code)] // compatibility wrapper and external unit-test construction
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
    generate_dp_jwt_full(secret, node_id, issuer, namespace, None)
}

/// Generate a short-lived HS256 JWT with an optional `ns` claim and an optional
/// **single-valued** `aud` claim naming the token's intended target.
///
/// Audience binding (issue #2475) is what makes a credential non-transferable
/// between destinations that share a secret and issuer: the cross-cluster mesh
/// remote-discovery poller mints
/// `aud = "ferrum-mesh-discovery:<target RemoteCluster.name>"`, and the
/// receiving control plane refuses any token whose single `aud` is not its own.
/// The claim is always a plain string (never an array), because Ferrum's
/// verifier treats a multi-valued audience as ambiguous and fails closed.
///
/// `audience` of `None` reproduces the ordinary CP↔DP ConfigSync / xDS token
/// shape exactly. Native local mesh callers pass
/// [`crate::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE`], while remote discovery
/// passes its target-cluster audience, so the two MeshSubscribe purposes are
/// cryptographically distinct.
pub fn generate_dp_jwt_full(
    secret: &str,
    node_id: &str,
    issuer: &str,
    namespace: Option<&str>,
    audience: Option<&str>,
) -> Result<String, anyhow::Error> {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": now + DP_JWT_TTL_SECONDS,
        "iss": issuer,
        "role": "data_plane",
    });
    // `claims` is constructed as a JSON object literal directly above, so the
    // `as_object_mut` invariant cannot fail.
    let Some(object) = claims.as_object_mut() else {
        anyhow::bail!("internal error: DP JWT claims are not a JSON object");
    };
    if let Some(ns) = namespace.filter(|ns| !ns.is_empty()) {
        object.insert("ns".to_string(), json!(ns));
    }
    if let Some(aud) = audience.map(str::trim).filter(|aud| !aud.is_empty()) {
        object.insert("aud".to_string(), json!(aud));
    }
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
    tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: String,
    primary_retry_secs: u64,
    connection_state: Option<Arc<ArcSwap<DpCpConnectionState>>>,
    frontend_tls_runtime: Option<DpFrontendTlsRuntime>,
) {
    start_dp_client_with_stream_timings(
        cp_urls,
        jwt_secret,
        proxy_state,
        shutdown_rx,
        tls_config,
        tls_reload,
        startup_ready,
        namespace,
        primary_retry_secs,
        connection_state,
        frontend_tls_runtime,
        ConfigSyncStreamTimings::production(),
    )
    .await
}

/// Same as [`start_dp_client_with_shutdown_and_startup_ready`] with an explicit
/// per-invocation ConfigSync stream timing policy.
///
/// Production callers use the wrapper above, which always passes
/// [`ConfigSyncStreamTimings::production`]. Tests use this entry point to
/// compress the silent-partition bound so blackhole→failover is provable in
/// bounded hosted CI. The policy is a plain stack argument, so a test value has
/// no path into a production DP.
#[allow(clippy::too_many_arguments)]
pub async fn start_dp_client_with_stream_timings(
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
    timings: ConfigSyncStreamTimings,
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

    let mut backoff = MultiCpBackoffState::new();
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
    let mut snapshot_authority: Option<AppliedSnapshotAuthority> = None;
    let divergence_metrics = Arc::new(ConfigSyncDivergenceMetrics::default());
    crate::plugins::prometheus_metrics::global_registry()
        .set_configsync_divergence_metrics(divergence_metrics.clone());
    // Event-driven startup-readiness wakeup shared across subscription attempts.
    // Paired with `startup_ready` (the source-of-truth flag) so the fallback
    // primary-retry timer waits for readiness without a busy-poll (nit N2).
    let readiness_signal = Arc::new(Notify::new());

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

        let cp_url = &cp_urls[backoff.current_cp_index];
        let is_primary = backoff.current_cp_index == 0;
        let is_fallback = !is_primary && cp_count > 1;

        if is_fallback {
            info!(
                "Connecting to fallback CP [{}/{}] at {}",
                backoff.current_cp_index + 1,
                cp_count,
                cp_url
            );
        } else if cp_count > 1 {
            info!("Connecting to primary CP at {}", cp_url);
        }

        let result = connect_and_subscribe_with_startup_ready_inner(
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
            shutdown_rx.clone(),
            tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
            if is_fallback { primary_retry_secs } else { 0 },
            &mut snapshot_authority,
            divergence_metrics.as_ref(),
            readiness_signal.clone(),
            timings,
        )
        .await;

        let attempt_outcome = match result {
            Ok(DpStreamEnd::Shutdown) => {
                info!("DP client shutting down");
                return;
            }
            Ok(DpStreamEnd::PrimaryRetry) => {
                info!(
                    "Primary CP retry interval ({}s) elapsed; disconnecting from \
                     fallback CP [{}/{}] to retry primary",
                    primary_retry_secs,
                    backoff.current_cp_index + 1,
                    cp_count,
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                backoff.current_cp_index = 0;
                ConfigSyncAttemptOutcome::IntentionalDisconnect
            }
            Ok(DpStreamEnd::TlsReload) => {
                info!(
                    "{} gRPC TLS source changed; reconnecting CP stream",
                    tls_reload
                        .as_ref()
                        .map(|reload| reload.label)
                        .unwrap_or("DP")
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                ConfigSyncAttemptOutcome::IntentionalDisconnect
            }
            Ok(DpStreamEnd::Clean { received_config }) => {
                warn!(
                    "CP [{}/{}] connection stream ended ({}), will reconnect...",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                if received_config {
                    if is_fallback {
                        info!("Stream ended on fallback CP; will retry primary CP first");
                        backoff.current_cp_index = 0;
                    }
                    ConfigSyncAttemptOutcome::CleanCloseAfterConfig
                } else {
                    ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
                }
            }
            Ok(DpStreamEnd::StaleSnapshotFenced) => {
                // The stream delivered a stale cross-source FULL_SNAPSHOT that we
                // refused; the applied config is unchanged and still served. Fail
                // over to the next CP with accumulating backoff — never reset it,
                // and never mark config as received — so a stale fallback cache
                // can neither roll config back nor masquerade as healthy progress.
                warn!(
                    "Refused stale FULL_SNAPSHOT from CP [{}/{}] ({}); failing over without \
                     applying so a stale fallback cache cannot roll config back",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                ConfigSyncAttemptOutcome::StaleSnapshotFenced
            }
            Ok(DpStreamEnd::InvalidDeltaFreshness) => {
                // The CP supplied a DELTA whose envelope timestamp did not
                // describe its body, whose committed timestamp was implausibly
                // far in the future, or whose committed stamp predates the
                // monotonic authority watermark (ABA / lagging-CP replay). The
                // delta was refused before apply, so fail over with accumulating
                // backoff rather than letting that source poison or roll back
                // freshness authority.
                warn!(
                    "Refused invalid DELTA freshness from CP [{}/{}] ({}); failing over \
                     without applying while keeping last-known-good config",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                ConfigSyncAttemptOutcome::InvalidDeltaFreshness
            }
            Ok(DpStreamEnd::InvalidSubscriptionBase) => {
                // No valid FULL_SNAPSHOT base was established (or a pre-snapshot
                // DELTA arrived first). Fail over with accumulating backoff so a
                // later delta cannot apply against an unrelated old base.
                warn!(
                    "ConfigSync subscription from CP [{}/{}] ({}) failed to establish a valid \
                     FULL_SNAPSHOT base; failing over without applying",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                ConfigSyncAttemptOutcome::InvalidSubscriptionBase
            }
            Ok(DpStreamEnd::ResyncAfterAcceptedConfig) => {
                // Mid-stream unusable FULL_SNAPSHOT or rejected non-empty DELTA
                // after a base was accepted. Keep serving last-known-good config,
                // reset backoff, and reconnect to the same CP for a fresh
                // authoritative FULL_SNAPSHOT (issues #2394 / snapshot failure).
                warn!(
                    "ConfigSync subscription from CP [{}/{}] ({}) requires an authoritative \
                     FULL_SNAPSHOT resync; reconnecting while keeping last-known-good config",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                ConfigSyncAttemptOutcome::ResyncAfterAcceptedConfig
            }
            Ok(DpStreamEnd::TransportFailure { received_config }) => {
                update_state_disconnected(&connection_state, cp_url, is_primary);
                if received_config && is_fallback {
                    info!(
                        "Transport failure on fallback CP after accepted config; will retry primary CP first"
                    );
                    backoff.current_cp_index = 0;
                }
                connection_error_outcome(received_config)
            }
            Err(e) => {
                error!(
                    "CP [{}/{}] connection error ({}): {}",
                    backoff.current_cp_index + 1,
                    cp_count,
                    cp_url,
                    e
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                // Pre-stream connect/subscribe failures never delivered config.
                ConfigSyncAttemptOutcome::ConnectionError
            }
        };

        let should_sleep = advance_multi_cp_backoff(&mut backoff, cp_count, attempt_outcome);
        if !should_sleep {
            continue;
        }

        if matches!(
            attempt_outcome,
            ConfigSyncAttemptOutcome::ConnectionError
                | ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
                | ConfigSyncAttemptOutcome::StaleSnapshotFenced
                | ConfigSyncAttemptOutcome::InvalidSubscriptionBase
                | ConfigSyncAttemptOutcome::InvalidDeltaFreshness
        ) && backoff.current_cp_index == 0
            && backoff.full_cycle_count > 0
            && cp_count > 1
        {
            warn!(
                "All {} CP URLs exhausted (cycle {}), restarting from primary",
                cp_count, backoff.full_cycle_count
            );
        }

        let sleep_duration = jittered_backoff(backoff.backoff_secs);

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
                        // TLS material rotated mid-backoff: reconnect immediately
                        // with the new material (rebuilt at the top of the loop),
                        // but PRESERVE accumulated failure backoff. No connection
                        // has succeeded, so resetting to the initial delay would
                        // let a flapping TLS source defeat backoff against a
                        // still-failing CP (L2). Only real healthy progress or an
                        // intentional connected disconnect resets backoff.
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
                    // Same as the shutdown-aware arm above: reconnect immediately
                    // with rotated TLS material while preserving accumulated
                    // failure backoff. A TLS source flap is not healthy progress
                    // and must not reset the delay against a still-failing CP (L2).
                    continue;
                }
            }
        }

        if matches!(
            attempt_outcome,
            ConfigSyncAttemptOutcome::ConnectionError
                | ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
                | ConfigSyncAttemptOutcome::StaleSnapshotFenced
                | ConfigSyncAttemptOutcome::InvalidSubscriptionBase
                | ConfigSyncAttemptOutcome::InvalidDeltaFreshness
        ) {
            grow_backoff_after_failure_sleep(&mut backoff);
        }
    }
}

/// How a ConfigSync stream session ended when the connection itself succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DpStreamEnd {
    /// Stream closed cleanly (EOF).
    Clean { received_config: bool },
    /// Fallback primary-retry timer fired between messages.
    PrimaryRetry,
    /// CP/DP TLS material changed; reconnect with rotated material.
    TlsReload,
    /// Process shutdown observed while connected.
    Shutdown,
    /// A cross-source FULL_SNAPSHOT was fenced as stale/unorderable, so the DP
    /// refused this stream before any later delta from it could apply against
    /// the newer active config. The outer loop treats this as a
    /// failover-with-backoff failure — never as delivered config (issue #2970).
    StaleSnapshotFenced,
    /// A DELTA envelope/body timestamp was inconsistent, implausibly far in the
    /// future, or older than the applied authority watermark. The update is
    /// refused before apply and the outer loop fails over with accumulating
    /// backoff so freshness authority cannot be poisoned or rolled back.
    InvalidDeltaFreshness,
    /// This subscription never committed a valid FULL_SNAPSHOT base (invalid /
    /// unparseable / rejected initial snapshot, or a pre-snapshot DELTA). Fail
    /// over with accumulating backoff.
    InvalidSubscriptionBase,
    /// Mid-stream unusable FULL_SNAPSHOT or rejected non-empty DELTA after a
    /// base was accepted. Keep serving last-known-good and reconnect for a
    /// fresh authoritative snapshot (issue #2394).
    ResyncAfterAcceptedConfig,
    /// Transport/RPC failure after Subscribe succeeded. `received_config`
    /// distinguishes backoff reset (issue #2968) from accumulating failure.
    TransportFailure { received_config: bool },
}

async fn wait_for_readiness_then_primary_retry(
    startup_ready: Option<Arc<AtomicBool>>,
    readiness_signal: Arc<Notify>,
    primary_retry_secs: u64,
) {
    // A startup-readiness gate only DELAYS the first primary retry so the DP does
    // not flap back to the primary before it is serving; it must never disable the
    // retry entirely. When no gate is supplied (`None`) there is nothing to wait
    // for, so fire on the plain `primary_retry_secs` cadence — matching the
    // pre-refactor `startup_ready.is_none_or(..)` race semantics. Returning a
    // never-ready future here would strand the DP on a fallback CP forever.
    if let Some(startup_ready) = startup_ready {
        // Event-driven wait (no 100ms busy-poll, nit N2). `startup_ready` is the
        // source of truth; the paired `Notify` only delivers the wakeup. The
        // apply path stores `true` then calls `notify_one`, which stores a permit
        // even if no waiter is currently parked — so a store that races the flag
        // check below is never a lost wakeup: the subsequent `notified().await`
        // consumes the stored permit immediately and the loop re-observes the
        // flag. Cancellation-safe: dropping this future (when another select! arm
        // wins) leaves no state behind.
        while !startup_ready.load(Ordering::Acquire) {
            readiness_signal.notified().await;
        }
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
            config_diverged: prev.config_diverged,
            config_diverged_since: prev.config_diverged_since,
            config_divergence_recoveries_total: prev.config_divergence_recoveries_total,
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
            config_diverged: prev.config_diverged,
            config_diverged_since: prev.config_diverged_since,
            config_divergence_recoveries_total: prev.config_divergence_recoveries_total,
        }));
    }
}

/// Raise sticky config divergence without advancing last_config_received_at.
fn update_state_config_diverged(
    connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>,
    metrics: &ConfigSyncDivergenceMetrics,
) {
    metrics.record_rejection();
    crate::plugins::prometheus_metrics::global_registry()
        .invalidate_configsync_divergence_metrics_cache();
    if let Some(cs) = connection_state {
        let prev = cs.load();
        let since = prev.config_diverged_since.unwrap_or_else(Utc::now);
        cs.store(Arc::new(DpCpConnectionState {
            connected: prev.connected,
            cp_url: prev.cp_url.clone(),
            is_primary: prev.is_primary,
            last_config_received_at: prev.last_config_received_at,
            connected_since: prev.connected_since,
            config_diverged: true,
            config_diverged_since: Some(since),
            config_divergence_recoveries_total: prev.config_divergence_recoveries_total,
        }));
    }
}

/// Record a fenced (refused-without-applying) FULL_SNAPSHOT and
/// invalidate the cached `/metrics` render so the fixed-cardinality fenced
/// counter surfaces promptly. Fencing keeps last-known-good config and does not
/// raise sticky `config_diverged` — it is a failover/skew signal, not a
/// delta-rejection divergence.
fn record_fenced_full_snapshot(metrics: &ConfigSyncDivergenceMetrics) {
    metrics.record_fenced_snapshot();
    crate::plugins::prometheus_metrics::global_registry()
        .invalidate_configsync_divergence_metrics_cache();
}

/// Clear sticky divergence after an accepted authoritative FULL_SNAPSHOT.
fn update_state_clear_divergence_after_snapshot(
    connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>,
    metrics: &ConfigSyncDivergenceMetrics,
) {
    let recovered = metrics.record_recovery_after_full_snapshot();
    if recovered {
        crate::plugins::prometheus_metrics::global_registry()
            .invalidate_configsync_divergence_metrics_cache();
    }
    if let Some(cs) = connection_state {
        let prev = cs.load();
        if !prev.config_diverged && !recovered {
            return;
        }
        let recoveries = if prev.config_diverged {
            prev.config_divergence_recoveries_total.saturating_add(1)
        } else {
            prev.config_divergence_recoveries_total
        };
        cs.store(Arc::new(DpCpConnectionState {
            connected: prev.connected,
            cp_url: prev.cp_url.clone(),
            is_primary: prev.is_primary,
            last_config_received_at: prev.last_config_received_at,
            connected_since: prev.connected_since,
            config_diverged: false,
            config_diverged_since: None,
            config_divergence_recoveries_total: recoveries,
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

/// Map an accepted trust side-channel update onto the bounded equivalence view.
///
/// `Unchanged` returns `None` so callers leave remembered trust state alone
/// (and so older-cross-source complete-payload matching fails closed when a
/// FULL_SNAPSHOT cannot establish comparable trust state). `Clear` /
/// `Replace` always produce a comparable Absent/Present state. Callers must
/// never invent Absent from `None`.
fn gateway_trust_equivalence_after_update(
    update: &GatewayTrustBundleUpdate,
) -> Option<GatewayTrustEquivalenceState> {
    match update {
        GatewayTrustBundleUpdate::Unchanged => None,
        GatewayTrustBundleUpdate::Clear => Some(GatewayTrustEquivalenceState::Absent),
        GatewayTrustBundleUpdate::Replace(trust_bundles) => {
            Some(gateway_trust_equivalence_state(Some(trust_bundles)))
        }
    }
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
    let mut authority = None;
    match connect_and_subscribe_with_startup_ready_inner(
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
        None,
        Arc::new(AtomicBool::new(false)),
        Arc::new(ArcSwap::new(Arc::new(None))),
        None,
        None,
        0,
        &mut authority,
        &ConfigSyncDivergenceMetrics::default(),
        Arc::new(Notify::new()),
        ConfigSyncStreamTimings::production(),
    )
    .await?
    {
        DpStreamEnd::Shutdown | DpStreamEnd::Clean { .. } => Ok(()),
        DpStreamEnd::PrimaryRetry | DpStreamEnd::TlsReload => Ok(()),
        DpStreamEnd::StaleSnapshotFenced
        | DpStreamEnd::InvalidDeltaFreshness
        | DpStreamEnd::InvalidSubscriptionBase
        | DpStreamEnd::ResyncAfterAcceptedConfig
        | DpStreamEnd::TransportFailure { .. } => Ok(()),
    }
}

/// Connect to CP and optionally flip startup readiness after the first applied snapshot.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // compatibility wrapper; production uses the lifecycle-aware inner entry point
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
    let mut authority = None;
    match connect_and_subscribe_with_startup_ready_inner(
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
        None,
        None,
        0,
        &mut authority,
        &ConfigSyncDivergenceMetrics::default(),
        Arc::new(Notify::new()),
        ConfigSyncStreamTimings::production(),
    )
    .await?
    {
        DpStreamEnd::Shutdown | DpStreamEnd::Clean { .. } => Ok(()),
        DpStreamEnd::PrimaryRetry | DpStreamEnd::TlsReload => Ok(()),
        DpStreamEnd::StaleSnapshotFenced
        | DpStreamEnd::InvalidDeltaFreshness
        | DpStreamEnd::InvalidSubscriptionBase
        | DpStreamEnd::ResyncAfterAcceptedConfig
        | DpStreamEnd::TransportFailure { .. } => Ok(()),
    }
}

/// Build a ConfigSync client endpoint with bounded transport keepalive so
/// silent partitions fail the stream instead of hanging forever on idle reads.
pub fn configure_configsync_endpoint(endpoint: Endpoint) -> Endpoint {
    endpoint
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(
            CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
        ))
        .keep_alive_timeout(Duration::from_secs(CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(CONFIGSYNC_TCP_KEEPALIVE_SECS)))
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
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_revision_rx: Option<watch::Receiver<u64>>,
    primary_retry_secs: u64,
    snapshot_authority: &mut Option<AppliedSnapshotAuthority>,
    divergence_metrics: &ConfigSyncDivergenceMetrics,
    readiness_signal: Arc<Notify>,
    timings: ConfigSyncStreamTimings,
) -> Result<DpStreamEnd, anyhow::Error> {
    let mut endpoint = configure_configsync_endpoint(Channel::from_shared(cp_url.to_string())?);

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
        // Advertise the heartbeat capability. The CP only emits keepalive frames
        // to advertising subscribers, and only confirms the capability back on
        // the initial update — so this DP arms its silence watchdog against a CP
        // that actually committed to heartbeats, never against one that predates
        // them.
        supports_heartbeat: true,
    });

    let mut stream = client.subscribe(request).await?.into_inner();
    // Startup readiness is independent of subscription base gating: callers with
    // `startup_ready = None` may skip startup-only wait/capability work, but every
    // new subscription still requires an accepted FULL_SNAPSHOT before any DELTA.
    let mut subscription = SubscriptionApplyState::new();
    let skip_startup_readiness_work = startup_ready.is_none();
    let mut received_config = false;
    // Application silence is only a liveness signal once the CP has confirmed it
    // will send heartbeats. Against a CP that predates the capability the stream
    // is legitimately silent while idle, and arming the watchdog would force a
    // reconnect the CP was never asked to prevent. Transport keepalive (HTTP/2
    // PING + TCP) still covers those streams. Set true and never cleared: only
    // the initial update carries the confirmation.
    let mut heartbeats_negotiated = false;
    // Silence before the *first* message is anomalous at any peer version, so
    // the watchdog stays armed until one arrives (see `silence_watchdog_armed`).
    let mut received_any_message = false;
    let mut last_stream_activity = Instant::now();
    let primary_retry_fut = wait_for_readiness_then_primary_retry(
        startup_ready.clone(),
        readiness_signal.clone(),
        primary_retry_secs,
    );
    tokio::pin!(primary_retry_fut);
    let enable_primary_retry = primary_retry_secs > 0;
    let shutdown_fut = wait_optional_shutdown(shutdown_rx.clone());
    tokio::pin!(shutdown_fut);
    let tls_reload_fut = wait_optional_tls_reload(tls_revision_rx.clone());
    tokio::pin!(tls_reload_fut);

    // Mark connected while preserving last applied-config age and sticky
    // divergence across reconnects (see `DpCpConnectionState::reconnected`).
    if let Some(cs) = connection_state {
        let prev = cs.load();
        cs.store(Arc::new(prev.reconnected(cp_url, is_primary, Utc::now())));
    }

    loop {
        let silence_remaining = timings
            .max_silence
            .saturating_sub(last_stream_activity.elapsed());
        let silence_armed = silence_watchdog_armed(heartbeats_negotiated, received_any_message);

        // Poll lifecycle signals (shutdown / TLS reload / primary retry) before
        // the message arm so a sustained stream cannot starve them, but keep the
        // message arm ahead of the silence timer so real traffic always wins the
        // liveness tie-break. These lifecycle futures are pending in steady
        // state, so ordering them first never starves stream work. The config
        // apply happens after this select returns — never inside an arm — so no
        // arm can cancel an in-flight `spawn_blocking` apply.
        let update = tokio::select! {
            biased;
            _ = &mut shutdown_fut => {
                return Ok(DpStreamEnd::Shutdown);
            }
            _ = &mut tls_reload_fut => {
                return Ok(DpStreamEnd::TlsReload);
            }
            _ = &mut primary_retry_fut, if enable_primary_retry => {
                return Ok(DpStreamEnd::PrimaryRetry);
            }
            msg = stream.message() => {
                match msg {
                    Ok(Some(update)) => update,
                    Ok(None) => {
                        return Ok(DpStreamEnd::Clean { received_config });
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            received_config,
                            "ConfigSync stream RPC error; reconnecting"
                        );
                        return Ok(DpStreamEnd::TransportFailure { received_config });
                    }
                }
            }
            _ = tokio::time::sleep(silence_remaining), if silence_armed => {
                error!(
                    received_config,
                    "ConfigSync stream silent for {}s (no message/heartbeat); reconnecting",
                    timings.max_silence.as_secs()
                );
                return Ok(DpStreamEnd::TransportFailure { received_config });
            }
        };

        last_stream_activity = Instant::now();
        received_any_message = true;

        // Every envelope, including a heartbeat, must come from a compatible
        // peer. Otherwise an incompatible or malformed-version CP could keep a
        // stream alive indefinitely while bypassing the config-update gate.
        if let Err(err) = check_cp_version_compatibility(&update.ferrum_version) {
            error!("{}", err);
            return Ok(DpStreamEnd::TransportFailure { received_config });
        }

        if update.heartbeat {
            // Heartbeats are valid only after this subscription accepted its
            // authoritative base and the initial FULL_SNAPSHOT negotiated the
            // capability. A heartbeat cannot bootstrap either state: accepting
            // it would let a buggy/adversarial CP keep an unready DP connected
            // forever without ever supplying usable configuration.
            if !heartbeat_frame_admissible(subscription.base_applied, heartbeats_negotiated) {
                warn!(
                    base_applied = subscription.base_applied,
                    heartbeats_negotiated,
                    cp_url,
                    "Refusing ConfigSync heartbeat before an accepted, negotiated \
                     FULL_SNAPSHOT base; terminating stream"
                );
                return Ok(react_to_unusable_snapshot(subscription.base_applied));
            }
            debug!(
                version = %update.version,
                "Received ConfigSync heartbeat"
            );
            continue;
        }

        // The CP confirms heartbeat support only on a real FULL_SNAPSHOT.
        // Rejecting a confirmation on DELTA prevents a partial update from
        // changing lifecycle policy before establishing an authoritative base.
        if update.heartbeat_negotiated && update.update_type != 0 {
            warn!(
                update_type = update.update_type,
                cp_url, "Refusing heartbeat capability confirmation outside a FULL_SNAPSHOT"
            );
            return Ok(react_to_unusable_snapshot(subscription.base_applied));
        }
        if update.heartbeat_negotiated && !heartbeats_negotiated {
            heartbeats_negotiated = true;
            debug!(
                max_silence_secs = timings.max_silence.as_secs(),
                "CP confirmed ConfigSync heartbeat support; arming stream silence watchdog"
            );
        }

        info!(
            "Received config update (type={}, version={}, cp_version={})",
            update.update_type, update.version, update.ferrum_version
        );

        match update.update_type {
            0 => {
                // FULL_SNAPSHOT — parse and validate the body first so freshness
                // describes the committed GatewayConfig (`loaded_at`), not an
                // inconsistent envelope string. Cross-CP fencing then runs on
                // the reconciled committed stamp. A fenced or inconsistent
                // snapshot must TERMINATE this stream (issue #2970). An invalid
                // initial snapshot must also terminate so a later DELTA cannot
                // apply against an unrelated old base.
                let mut config = match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                    Ok(config) => config,
                    Err(e) => {
                        error!("Failed to parse full config update: {}", e);
                        return Ok(react_to_unusable_snapshot(subscription.base_applied));
                    }
                };
                let gateway_trust_bundle_update =
                    match parse_gateway_trust_bundle_update(&update.trust_bundles_json) {
                        Ok(update) => update,
                        Err(msg) => {
                            error!("CP config rejected — {}", msg);
                            error!("Ignoring config update with invalid gateway trust bundles");
                            return Ok(react_to_unusable_snapshot(subscription.base_applied));
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
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_hosts() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with invalid hosts");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_regex_listen_paths() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with invalid regex listen_paths");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_listen_path_encodings() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with encoded-slash listen_paths");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_unique_listen_paths() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with conflicting listen paths");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_stream_proxies() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with invalid stream proxy config");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_upstream_references() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with invalid upstream references");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                if let Err(errors) = config.validate_plugin_references() {
                    for msg in &errors {
                        error!("CP config rejected — {}", msg);
                    }
                    error!("Ignoring config update with invalid plugin references");
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
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
                    return Ok(react_to_unusable_snapshot(subscription.base_applied));
                }
                // Freshness describes the committed body: envelope version must
                // agree with GatewayConfig.loaded_at. Fail closed otherwise —
                // never fabricate a timestamp.
                let committed = match reconcile_snapshot_version(&update.version, config.loaded_at)
                {
                    Ok(committed) => committed,
                    Err(err) => {
                        let reason = stale_reject_from_reconcile(err);
                        record_fenced_full_snapshot(divergence_metrics);
                        warn!(
                            ?reason,
                            cp_url,
                            version = %update.version,
                            loaded_at = %config.loaded_at,
                            "Refusing FULL_SNAPSHOT with inconsistent or unorderable version \
                             and terminating this ConfigSync stream"
                        );
                        return Ok(DpStreamEnd::StaleSnapshotFenced);
                    }
                };
                // Bounded clock-skew guard: a committed stamp implausibly far in
                // this DP's future indicates a skewed or hostile CP clock. Admit
                // it and the monotonic watermark is poisoned — every correct-clock
                // failover CP with genuinely newer config is fenced until wall
                // time catches up. Fail closed: refuse, alarm, and fail over while
                // last-known-good config keeps serving. Never clamp the untrusted
                // stamp into authority (issue M1).
                if let Err(reason) = evaluate_snapshot_clock_skew(committed, Utc::now()) {
                    record_fenced_full_snapshot(divergence_metrics);
                    warn!(
                        ?reason,
                        cp_url,
                        version = %update.version,
                        loaded_at = %config.loaded_at,
                        "Refusing FULL_SNAPSHOT with an implausibly-future committed timestamp \
                         (CP clock skew beyond tolerance) and terminating this ConfigSync stream \
                         so a skewed clock cannot poison the freshness watermark"
                    );
                    return Ok(DpStreamEnd::StaleSnapshotFenced);
                }
                // Older-cross-source identical-fallback must compare the complete
                // authoritative payload: GatewayConfig content plus effective CP
                // gateway-trust side-channel state. Empty/unchanged trust side
                // channels fail closed (cannot establish equivalence). The two
                // canonical JSON conversions are expensive, so only run them when
                // the disposition actually depends on the exception — a cross-
                // source candidate strictly older than a parseable applied
                // watermark. Routine same-source/fresh snapshots skip it (nit N1).
                let incoming_matches_applied = if snapshot_requires_older_payload_exception(
                    snapshot_authority.as_ref(),
                    committed,
                    cp_url,
                ) {
                    let incoming_trust_equiv =
                        gateway_trust_equivalence_after_update(&gateway_trust_bundle_update);
                    // Compare like against like: the applied config has already
                    // been through `update_config`'s pre-swap canonicalization
                    // (HMAC quarantine, gateway workload-metrics identity
                    // injection), which this candidate has not. Without that the
                    // exception is silently inert on any node those steps touch —
                    // notably a DP with a gateway SVID — and every equivalent
                    // failover snapshot is fenced.
                    let comparable = proxy_state.canonicalize_snapshot_for_comparison(&config);
                    match snapshot_authority.as_ref() {
                        Some(authority) => authoritative_snapshot_payload_matches(
                            proxy_state.current_config().as_ref(),
                            &authority.gateway_trust,
                            &comparable,
                            incoming_trust_equiv.as_ref(),
                        ),
                        None => false,
                    }
                } else {
                    false
                };
                let watermark = match full_snapshot_stream_disposition(
                    snapshot_authority.as_ref(),
                    committed,
                    cp_url,
                    incoming_matches_applied,
                ) {
                    FullSnapshotStreamDisposition::Apply { version } => version,
                    FullSnapshotStreamDisposition::RefuseAndTerminate(reason) => {
                        record_fenced_full_snapshot(divergence_metrics);
                        warn!(
                            ?reason,
                            cp_url,
                            version = %update.version,
                            "Refusing stale cross-source FULL_SNAPSHOT and terminating this \
                             ConfigSync stream so no later delta from it can apply against newer \
                             config; keeping applied config and failing over"
                        );
                        return Ok(DpStreamEnd::StaleSnapshotFenced);
                    }
                };

                // Materialize external/file-backed TLS sources only after the
                // snapshot passes freshness authorization. A stale/fenced CP
                // must not trigger secret-provider access or mutate the local
                // operator-TLS restore slot before the snapshot is refused.
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
                        error!("Ignoring config update with unusable frontend TLS material");
                        return Ok(react_to_unusable_snapshot(subscription.base_applied));
                    }
                };

                // Await apply to completion before returning to the
                // select! above so primary-retry / TLS / shutdown arms
                // cannot cancel a detached spawn_blocking mid-apply.
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
                        let next_trust =
                            gateway_trust_equivalence_after_update(&gateway_trust_bundle_update);
                        apply_gateway_trust_bundle_update(proxy_state, gateway_trust_bundle_update);
                        update_state_config_received(connection_state);
                        received_config = true;
                        // Watermark is the monotonic value from fencing policy
                        // (max of prior authority and committed loaded_at).
                        // Explicit Clear/Replace establish comparable trust;
                        // empty/Unchanged preserves prior state or remains
                        // Unknown — never invent Absent from an unestablished
                        // side channel.
                        let gateway_trust = resolve_authority_trust_after_snapshot(
                            snapshot_authority.as_ref(),
                            next_trust,
                        );
                        *snapshot_authority = Some(AppliedSnapshotAuthority {
                            version: Some(watermark),
                            source_cp_url: cp_url.to_string(),
                            gateway_trust,
                        });
                        // Authoritative FULL_SNAPSHOT clears sticky divergence
                        // from a prior rejected delta (issue #2394).
                        update_state_clear_divergence_after_snapshot(
                            connection_state,
                            divergence_metrics,
                        );
                        let first_base_on_subscription = !subscription.base_applied;
                        subscription.note_full_snapshot_accepted();
                        if first_base_on_subscription && !skip_startup_readiness_work {
                            // Bind failures are non-fatal in DP mode —
                            // do not tear down a healthy ConfigSync
                            // stream or misclassify this as a CP error.
                            if let Err(error) = proxy_state
                                .stream_listener_manager
                                .wait_until_started(Duration::from_secs(10))
                                .await
                            {
                                warn!(
                                    error = %error,
                                    "Stream listener startup wait timed out after CP snapshot; continuing (bind failures are non-fatal in DP mode)"
                                );
                            }
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
                                // Wake a fallback subscription's primary-retry
                                // timer waiting on readiness (event-driven, nit
                                // N2). `notify_one` stores a permit so the wakeup
                                // is never lost even if the waiter is mid-check.
                                readiness_signal.notify_one();
                            }
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
                        return Ok(react_to_unusable_snapshot(subscription.base_applied));
                    }
                }
            }
            1 => {
                // DELTA — require a valid FULL_SNAPSHOT base on this subscription
                // first. A buggy/adversarial CP that sends DELTA first must not
                // apply against an unrelated old base.
                if let Err(reason) =
                    evaluate_delta_against_subscription_base(subscription.base_applied)
                {
                    warn!(
                        ?reason,
                        cp_url,
                        "Refusing DELTA before a valid FULL_SNAPSHOT base on this \
                         subscription; terminating stream without applying"
                    );
                    return Ok(DpStreamEnd::InvalidSubscriptionBase);
                }
                match serde_json::from_str::<IncrementalResult>(&update.config_json) {
                    Ok(mut result) => {
                        let gateway_trust_bundle_update =
                            match parse_gateway_trust_bundle_update(&update.trust_bundles_json) {
                                Ok(update) => update,
                                Err(msg) => {
                                    error!("CP delta rejected — {}", msg);
                                    error!(
                                        "Terminating ConfigSync stream after invalid gateway trust \
                                         side-channel so later resource deltas cannot apply"
                                    );
                                    let _ = delta_rejection_stream_disposition(
                                        DeltaRejectionKind::InvalidTrustSideChannel,
                                    );
                                    update_state_config_diverged(
                                        connection_state,
                                        divergence_metrics,
                                    );
                                    return Ok(DpStreamEnd::ResyncAfterAcceptedConfig);
                                }
                            };
                        // Rolling-upgrade compatibility: a same-major.minor CP
                        // that predates namespace-qualified removals sends bare
                        // resource IDs, which decode without a namespace. Adopt
                        // this subscription's already-authorized namespace — the
                        // only one this DP may act on — so the legacy semantics
                        // are reproduced without widening reach. Keys that stay
                        // unqualified (empty namespace) are dropped by the
                        // namespace filter immediately below.
                        let unqualified = result.qualify_unqualified_removals(namespace);
                        if unqualified > 0 {
                            debug!(
                                unqualified,
                                namespace,
                                "CP delta carried legacy unqualified removal keys; scoping them to \
                                 this subscription's authorized namespace"
                            );
                        }
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
                        let poll_timestamp = result.poll_timestamp;

                        // DELTA freshness is the body poll timestamp, not an
                        // arbitrary envelope string. Refuse an inconsistency or
                        // implausibly-future stamp before apply; otherwise a
                        // skewed/hostile CP could commit a far-future
                        // `loaded_at` and poison cross-CP freshness fencing.
                        let committed_delta =
                            match reconcile_snapshot_version(&update.version, poll_timestamp) {
                                Ok(committed) => committed,
                                Err(reason) => {
                                    warn!(
                                        ?reason,
                                        cp_url,
                                        version = %update.version,
                                        poll_timestamp = %poll_timestamp,
                                        "Refusing DELTA with inconsistent or unorderable freshness"
                                    );
                                    if !was_empty {
                                        update_state_config_diverged(
                                            connection_state,
                                            divergence_metrics,
                                        );
                                    }
                                    return Ok(DpStreamEnd::InvalidDeltaFreshness);
                                }
                            };
                        if let Err(reason) =
                            evaluate_snapshot_clock_skew(committed_delta, Utc::now())
                        {
                            warn!(
                                ?reason,
                                cp_url,
                                version = %update.version,
                                poll_timestamp = %poll_timestamp,
                                "Refusing DELTA with an implausibly-future committed timestamp \
                                 before it can poison the freshness watermark"
                            );
                            if !was_empty {
                                update_state_config_diverged(connection_state, divergence_metrics);
                            }
                            return Ok(DpStreamEnd::InvalidDeltaFreshness);
                        }
                        if let Err(reason) =
                            evaluate_delta_authority(snapshot_authority.as_ref(), committed_delta)
                        {
                            warn!(
                                ?reason,
                                cp_url,
                                version = %update.version,
                                poll_timestamp = %poll_timestamp,
                                "Refusing DELTA older than the applied authority watermark"
                            );
                            if !was_empty {
                                update_state_config_diverged(connection_state, divergence_metrics);
                            }
                            return Ok(DpStreamEnd::InvalidDeltaFreshness);
                        }

                        // Capture a bounded summary BEFORE moving `result` into
                        // apply_incremental. Logging every user-controlled ID
                        // would allocate and amplify one rejection into an
                        // unbounded log record; fixed counts retain useful
                        // diagnostics without exposing resource names.
                        let added_proxy_count = result.added_or_modified_proxies.len();
                        let added_upstream_count = result.added_or_modified_upstreams.len();
                        let added_consumer_count = result.added_or_modified_consumers.len();
                        let added_plugin_config_count =
                            result.added_or_modified_plugin_configs.len();
                        let removed_proxy_count = result.removed_proxy_ids.len();
                        let removed_upstream_count = result.removed_upstream_ids.len();
                        let removed_consumer_count = result.removed_consumer_ids.len();
                        let removed_plugin_config_count = result.removed_plugin_config_ids.len();
                        let cp_version = update.ferrum_version.clone();
                        let update_version = update.version;

                        match proxy_state.apply_incremental(result).await {
                            ConfigApplyOutcome::Applied => {
                                let next_trust = gateway_trust_equivalence_after_update(
                                    &gateway_trust_bundle_update,
                                );
                                apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                );
                                if let Some(trust) = next_trust {
                                    record_applied_gateway_trust(snapshot_authority, trust);
                                }
                                update_state_config_received(connection_state);
                                received_config = true;
                                // Advance freshness from the committed delta
                                // timestamp so a later cross-source snapshot
                                // cannot roll back past accepted deltas.
                                if resource_delta_advances_authority(true, was_empty) {
                                    let committed = proxy_state.config.load().loaded_at;
                                    advance_authority_from_committed(
                                        snapshot_authority,
                                        cp_url,
                                        committed,
                                    );
                                }
                                info!("Incremental config delta applied from CP");
                            }
                            ConfigApplyOutcome::Unchanged => {
                                let next_trust = gateway_trust_equivalence_after_update(
                                    &gateway_trust_bundle_update,
                                );
                                if apply_gateway_trust_bundle_update(
                                    proxy_state,
                                    gateway_trust_bundle_update,
                                ) {
                                    if let Some(trust) = next_trust {
                                        // Keep identical-fallback equivalence in
                                        // sync after accepted trust-only updates.
                                        record_applied_gateway_trust(snapshot_authority, trust);
                                    }
                                    update_state_config_received(connection_state);
                                    // An accepted trust-only update is authoritative
                                    // config delivery even though the gateway object
                                    // is unchanged — keep `received_config` in step
                                    // with the connection-state timestamp.
                                    // Do NOT advance snapshot authority watermark:
                                    // trust-only side-channels are not resource-config
                                    // freshness. Trust equivalence state is updated
                                    // above so later complete-payload comparisons
                                    // cannot see a stale trust view.
                                    received_config = true;
                                    info!("Gateway trust bundle update applied from CP");
                                    continue;
                                }
                                if !was_empty {
                                    update_state_config_received(connection_state);
                                    received_config = true;
                                    // Valid unchanged resource candidate still
                                    // advances freshness (poll_timestamp) so the
                                    // watermark tracks accepted resource deltas.
                                    if resource_delta_advances_authority(true, was_empty) {
                                        advance_authority_from_committed(
                                            snapshot_authority,
                                            cp_url,
                                            committed_delta,
                                        );
                                    }
                                    debug!(
                                        "Incremental config delta from CP was valid but unchanged"
                                    );
                                    continue;
                                }
                                // Empty delta — preserve original behavior of not
                                // touching `last_config_received_at` so cluster
                                // observability still reflects only deltas that
                                // carried real changes. Do not advance authority.
                                tracing::debug!(
                                    "Ignoring empty delta from CP (no resource changes)"
                                );
                            }
                            ConfigApplyOutcome::Rejected { errors } => {
                                // Rejected resource deltas must not advance
                                // freshness authority or last_config_received_at.
                                // Do not apply trust from a rejected resource batch.
                                let _ = gateway_trust_bundle_update;
                                if was_empty {
                                    tracing::debug!(
                                        "Ignoring rejected empty delta from CP (no resource changes)"
                                    );
                                } else {
                                    // Non-empty rejection: stop consuming this stream
                                    // so a later partial delta cannot apply against
                                    // the wrong base (issue #2394).
                                    let _ = delta_rejection_stream_disposition(
                                        DeltaRejectionKind::NonEmptyApplyRejected,
                                    );
                                    error!(
                                        cp_version = %cp_version,
                                        update_version = update_version,
                                        added_proxies = added_proxy_count,
                                        removed_proxies = removed_proxy_count,
                                        added_upstreams = added_upstream_count,
                                        removed_upstreams = removed_upstream_count,
                                        added_consumers = added_consumer_count,
                                        removed_consumers = removed_consumer_count,
                                        added_plugin_configs = added_plugin_config_count,
                                        removed_plugin_configs = removed_plugin_config_count,
                                        validation_errors = ?errors,
                                        "DP rejected CP-pushed delta — terminating stream for \
                                         authoritative FULL_SNAPSHOT resync; last-known-good \
                                         config kept serving"
                                    );
                                    update_state_config_diverged(
                                        connection_state,
                                        divergence_metrics,
                                    );
                                    return Ok(DpStreamEnd::ResyncAfterAcceptedConfig);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Parse failure is unclassifiable — fail closed (issue #2394).
                        error!("Failed to parse delta update: {}", e);
                        let _ =
                            delta_rejection_stream_disposition(DeltaRejectionKind::ParseFailure);
                        update_state_config_diverged(connection_state, divergence_metrics);
                        return Ok(DpStreamEnd::ResyncAfterAcceptedConfig);
                    }
                }
            }
            other => {
                warn!(
                    update_type = other,
                    cp_url,
                    base_applied = subscription.base_applied,
                    "Refusing unknown ConfigSync update type; terminating stream so an \
                     unrecognized authoritative message cannot be skipped before later deltas"
                );
                return Ok(react_to_unusable_snapshot(subscription.base_applied));
            }
        }
    }
}

/// An unusable FULL_SNAPSHOT always terminates the subscription so later
/// deltas cannot apply against a base that missed the authoritative reload.
/// When a prior base was already accepted, reconnect for a fresh snapshot
/// while keeping last-known-good config; otherwise fail over as an invalid base.
fn react_to_unusable_snapshot(subscription_base_applied: bool) -> DpStreamEnd {
    let _ = snapshot_failure_stream_disposition(subscription_base_applied);
    if subscription_base_applied {
        DpStreamEnd::ResyncAfterAcceptedConfig
    } else {
        DpStreamEnd::InvalidSubscriptionBase
    }
}

async fn wait_optional_shutdown(mut shutdown_rx: Option<watch::Receiver<bool>>) {
    let Some(rx) = shutdown_rx.as_mut() else {
        std::future::pending::<()>().await;
        return;
    };
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
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

/// Defense-in-depth filter for incremental deltas. Filters both
/// `added_or_modified_*` vectors and namespace-qualified removal keys so a
/// misrouted or adversarial delta cannot delete a same-id object in another
/// namespace.
///
/// Returns the number of resources filtered out so the caller can warn.
///
/// Exposed so the namespace-qualified removal fail-closed behavior can be
/// exercised directly by external unit tests instead of reimplementing the
/// retain logic.
pub fn filter_incremental_to_namespace(result: &mut IncrementalResult, namespace: &str) -> usize {
    let pre = (
        result.added_or_modified_proxies.len(),
        result.added_or_modified_consumers.len(),
        result.added_or_modified_plugin_configs.len(),
        result.added_or_modified_upstreams.len(),
        result.removed_proxy_ids.len(),
        result.removed_consumer_ids.len(),
        result.removed_plugin_config_ids.len(),
        result.removed_upstream_ids.len(),
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
    result
        .removed_proxy_ids
        .retain(|key| key.namespace == namespace);
    result
        .removed_consumer_ids
        .retain(|key| key.namespace == namespace);
    result
        .removed_plugin_config_ids
        .retain(|key| key.namespace == namespace);
    result
        .removed_upstream_ids
        .retain(|key| key.namespace == namespace);
    (pre.0 - result.added_or_modified_proxies.len())
        + (pre.1 - result.added_or_modified_consumers.len())
        + (pre.2 - result.added_or_modified_plugin_configs.len())
        + (pre.3 - result.added_or_modified_upstreams.len())
        + (pre.4 - result.removed_proxy_ids.len())
        + (pre.5 - result.removed_consumer_ids.len())
        + (pre.6 - result.removed_plugin_config_ids.len())
        + (pre.7 - result.removed_upstream_ids.len())
}

/// Check whether the CP's reported version is compatible with this DP.
///
/// Uses SemVer parsing. Major and minor must match; patch and prerelease/build
/// differences are allowed. Empty and malformed versions are rejected
/// (issue #2395). See [`check_peer_version_compatibility`] for the prerelease
/// policy.
pub fn check_cp_version_compatibility(cp_version: &str) -> Result<(), String> {
    check_peer_version_compatibility(FERRUM_VERSION, cp_version)
        .map_err(|err| err.message("DP", "CP", FERRUM_VERSION))
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
    use crate::config::db_loader::NamespacedResourceId;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::proxy::ProxyState;
    use crate::util::backoff::jittered_backoff_with_entropy;
    use chrono::Utc;
    use serde_json::json;

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

    #[test]
    fn parse_gateway_trust_bundle_update_rejects_unparseable_json_fail_closed() {
        let err = parse_gateway_trust_bundle_update("{not-json")
            .expect_err("malformed trust side-channel must fail closed");
        assert!(err.contains("not valid JSON"), "unexpected error: {err}");
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
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
            mesh_revision: None,
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
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
            mesh_revision: None,
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
            removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "doesnt-matter")],
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
        assert_eq!(
            filtered, 4,
            "1 proxy + 1 consumer + 1 upstream + 1 foreign removal filtered"
        );

        assert_eq!(delta.added_or_modified_proxies.len(), 1);
        assert_eq!(delta.added_or_modified_proxies[0].namespace, "production");
        assert!(delta.added_or_modified_consumers.is_empty());
        assert_eq!(delta.added_or_modified_plugin_configs.len(), 1);
        assert_eq!(delta.added_or_modified_upstreams.len(), 1);

        // Removal keys are namespace-qualified and filtered fail-closed.
        assert!(delta.removed_proxy_ids.is_empty());
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
