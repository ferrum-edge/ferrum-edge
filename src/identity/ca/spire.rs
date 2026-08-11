//! SPIRE Agent CA backend.
//!
//! Delegates SVID issuance and trust-bundle retrieval to a SPIRE Agent over
//! the SPIFFE Workload API (Unix domain socket). Unlike the internal CA that
//! holds a root key and signs locally, this backend delegates all crypto to
//! the agent — Ferrum never sees a CA private key.
//!
//! ## How it works
//!
//! The SPIRE Agent's Workload API streams X.509 SVIDs to registered
//! workloads. This CA backend opens the streaming `FetchX509SVID` RPC at
//! construction time, parks a background task that continuously feeds the
//! latest SVID + bundle into an `ArcSwap`, and serves `issue_svid` /
//! `trust_bundle` reads from that snapshot. The agent handles rotation —
//! when it pushes a fresh SVID, the snapshot is atomically replaced.
//!
//! ## Issuance semantics
//!
//! Because the SPIRE agent manages keys and certs, `issue_svid` does NOT
//! mint a new certificate on every call. Instead it returns the current
//! SVID from the agent-supplied snapshot. Callers that need per-workload
//! SVIDs (the in-process Workload API server) should use the internal CA
//! or Vault PKI backend instead.
//!
//! ## JWT trust material (issue #3617)
//!
//! When this adapter is constructed directly, a second background task consumes
//! the agent's own `FetchJWTBundles` stream and converts each JWKS document back
//! into the SPKI-PEM form the identity subsystem speaks. It is independent of
//! the X.509 readiness gate: a SPIRE deployment with no JWT-SVID registration
//! entries answers `UNIMPLEMENTED`, and that is retried on the ordinary
//! reconnect schedule rather than failing construction. A malformed bundle is
//! never installed — the last good snapshot is retained — so hostile or corrupt
//! material can neither widen nor blank the trusted set.
//!
//! The active mesh `FERRUM_MESH_CA_BACKEND=spire` path uses the dedicated X.509
//! fetch loop and does **not** construct this adapter or start its JWT stream.
//! Consequently this helper must not be described as live mesh SPIRE JWT-bundle
//! consumption until that runtime wiring exists.
//!
//! JWT-SVID **mint** stays fail-closed here; see [`SpireAgentCa::jwt_authorities`]
//! for why that is a terminal capability boundary rather than a deferral.
//!
//! ## Configuration
//!
//! - `FERRUM_MESH_SPIRE_AGENT_SOCKET` — path to the SPIRE Agent UDS.
//!   Defaults to [`DEFAULT_SPIRE_AGENT_SOCKET`].

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use super::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use crate::identity::SvidBundle;
use crate::identity::spiffe::TrustDomain;
use crate::identity::workload_api::client::{JwtBundleSet, WorkloadApiClient};

/// Default UDS path for the SPIRE Agent. Operators override via
/// `FERRUM_MESH_SPIRE_AGENT_SOCKET`.
pub const DEFAULT_SPIRE_AGENT_SOCKET: &str = "/run/spire/sockets/agent.sock";

/// Reconnect backoff floor.
const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Reconnect backoff ceiling.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long to wait for the first SVID from the agent before giving up.
const INITIAL_SVID_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for [`SpireAgentCa`].
#[derive(Debug, Clone)]
pub struct SpireAgentCaConfig {
    /// Path to the SPIRE Agent's Workload API UDS.
    pub socket_path: String,
    /// SVID lifetime hint (seconds). The SPIRE agent may ignore this — it
    /// controls the actual TTL. Stored so `issue_svid` can populate
    /// `SignedSvid.not_after` from the agent-issued leaf.
    pub cert_ttl_secs: u64,
}

impl Default for SpireAgentCaConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SPIRE_AGENT_SOCKET.to_string(),
            cert_ttl_secs: 3600,
        }
    }
}

/// Internal snapshot holding the latest agent-pushed SVID and bundles.
#[derive(Debug, Clone)]
struct AgentSnapshot {
    bundle: SvidBundle,
}

/// SPIRE-Agent-backed certificate authority.
///
/// Holds a shared snapshot of the latest SVID pushed by the agent over the
/// Workload API stream. A background task keeps the snapshot up to date;
/// all `CertificateAuthority` methods read from it lock-free.
pub struct SpireAgentCa {
    config: SpireAgentCaConfig,
    /// Latest snapshot. `None` until the first SVID arrives.
    current: Arc<ArcSwap<Option<AgentSnapshot>>>,
    /// Fires once the first SVID has been observed.
    first_ready: Arc<Notify>,
    first_received: Arc<std::sync::atomic::AtomicBool>,
    /// Cancels the detached Workload API stream task when this CA is dropped.
    stream_task_abort: AbortHandle,
    /// JWT authorities the agent publishes, keyed by trust domain. Fed by a
    /// second background stream over the agent's own `FetchJWTBundles` RPC and
    /// read lock-free. Empty until the agent pushes a bundle (or forever, when
    /// the deployment issues no JWT-SVIDs), in which case `FetchJWTBundles` /
    /// `ValidateJWTSVID` answer `UNIMPLEMENTED` rather than an empty map.
    jwt_bundles: Arc<ArcSwap<JwtBundleSet>>,
    /// Cancels the detached JWT bundle stream task when this CA is dropped.
    jwt_stream_task_abort: AbortHandle,
}

impl SpireAgentCa {
    /// Build and start the background fetch loop. Returns once the first SVID
    /// has arrived from the agent (or after `INITIAL_SVID_TIMEOUT`).
    pub async fn new(config: SpireAgentCaConfig) -> Result<Self, CaError> {
        let current: Arc<ArcSwap<Option<AgentSnapshot>>> = Arc::new(ArcSwap::new(Arc::new(None)));
        let first_ready = Arc::new(Notify::new());
        let first_received = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Spawn the background stream loop.
        let stream_task = tokio::spawn(stream_loop(
            config.socket_path.clone(),
            Arc::clone(&current),
            Arc::clone(&first_ready),
            Arc::clone(&first_received),
        ));
        // JWT trust material rides its own stream (issue #3617). It is
        // deliberately NOT joined to the X.509 stream's readiness: a deployment
        // that issues no JWT-SVIDs must still start, and JWT bundles are not
        // required to bind a listener the way an X.509 SVID is.
        let jwt_bundles: Arc<ArcSwap<JwtBundleSet>> =
            Arc::new(ArcSwap::new(Arc::new(JwtBundleSet::new())));
        let jwt_stream_task = tokio::spawn(jwt_bundle_stream_loop(
            config.socket_path.clone(),
            Arc::clone(&jwt_bundles),
        ));
        let ca = Self {
            config: config.clone(),
            current: Arc::clone(&current),
            first_ready: Arc::clone(&first_ready),
            first_received: Arc::clone(&first_received),
            stream_task_abort: stream_task.abort_handle(),
            jwt_bundles: Arc::clone(&jwt_bundles),
            jwt_stream_task_abort: jwt_stream_task.abort_handle(),
        };
        drop(stream_task);
        drop(jwt_stream_task);

        // Wait for the first SVID with a timeout so startup does not hang
        // indefinitely when the agent is unreachable.
        let notified = first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if !first_received.load(std::sync::atomic::Ordering::Acquire) {
            match tokio::time::timeout(INITIAL_SVID_TIMEOUT, notified).await {
                Ok(()) => {
                    crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health(
                        "spire_agent",
                        true,
                    );
                    info!(
                        socket = %config.socket_path,
                        "SPIRE agent CA: received initial SVID"
                    );
                }
                Err(_) => {
                    crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health(
                        "spire_agent",
                        false,
                    );
                    warn!(
                        socket = %config.socket_path,
                        timeout_secs = INITIAL_SVID_TIMEOUT.as_secs(),
                        "SPIRE agent CA: timed out waiting for initial SVID — \
                         CA will serve once the agent pushes one"
                    );
                }
            }
        }

        Ok(ca)
    }

    /// Configuration this CA was built with.
    pub fn config(&self) -> &SpireAgentCaConfig {
        &self.config
    }

    /// Snapshot the current SVID bundle. Returns `None` before the first
    /// agent push.
    fn snapshot(&self) -> Option<AgentSnapshot> {
        let guard = self.current.load();
        guard.as_ref().clone()
    }

    /// Block until the first SVID arrives.
    ///
    /// Race-free: registers a waiter before checking the flag — same
    /// pattern as [`crate::identity::workload_api::fetch_loop::SvidFetchHandle`].
    pub async fn wait_for_first_svid(&self) {
        let notified = self.first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self
            .first_received
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        notified.await;
    }
}

impl Drop for SpireAgentCa {
    fn drop(&mut self) {
        self.stream_task_abort.abort();
        self.jwt_stream_task_abort.abort();
    }
}

/// Background loop that keeps the snapshot up to date. Never returns
/// unless the task is cancelled.
async fn stream_loop(
    socket_path: String,
    current: Arc<ArcSwap<Option<AgentSnapshot>>>,
    first_ready: Arc<Notify>,
    first_received: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    // Track the last successfully-fetched SPIFFE ID so subsequent rotation
    // failures attribute to the actual workload identity instead of "unknown".
    // Per-workload alerting (e.g. `ferrum_mesh_cert_rotation_failures_total`
    // grouped by `spiffe_id`) needs this label to be stable across reconnects.
    let attributed_spiffe_id = |current: &Arc<ArcSwap<Option<AgentSnapshot>>>| -> String {
        current
            .load_full()
            .as_ref()
            .as_ref()
            .map(|snap| snap.bundle.spiffe_id.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };

    loop {
        match WorkloadApiClient::connect(&socket_path).await {
            Ok(mut client) => match client.fetch_x509_svid_stream(None).await {
                Ok((mut stream, _first_signal)) => {
                    info!(socket = %socket_path, "SPIRE agent CA: stream established");
                    backoff = RECONNECT_BACKOFF_INITIAL;

                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bundle) => {
                                debug!(
                                    spiffe_id = %bundle.spiffe_id,
                                    "SPIRE agent CA: received SVID"
                                );
                                record_spire_bundle_metrics(&bundle);
                                crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health(
                                    "spire_agent",
                                    true,
                                );
                                let snapshot = AgentSnapshot { bundle };
                                current.store(Arc::new(Some(snapshot)));

                                let was_first =
                                    first_received.swap(true, std::sync::atomic::Ordering::AcqRel);
                                if !was_first {
                                    first_ready.notify_waiters();
                                }
                            }
                            Err(e) => {
                                crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health(
                                    "spire_agent",
                                    false,
                                );
                                crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
                                    attributed_spiffe_id(&current),
                                    "spire_agent",
                                );
                                warn!(
                                    error = %e,
                                    "SPIRE agent CA: stream error — reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health(
                        "spire_agent",
                        false,
                    );
                    crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
                        attributed_spiffe_id(&current),
                        "spire_agent",
                    );
                    error!(
                        error = %e,
                        "SPIRE agent CA: stream RPC failed"
                    );
                }
            },
            Err(e) => {
                crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("spire_agent", false);
                crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
                    attributed_spiffe_id(&current),
                    "spire_agent",
                );
                error!(
                    error = %e,
                    socket = %socket_path,
                    "SPIRE agent CA: failed to connect"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// Extract `not_after` from the leaf certificate in a snapshot.
fn leaf_not_after(cert_chain_der: &[Vec<u8>]) -> Result<chrono::DateTime<chrono::Utc>, CaError> {
    use x509_parser::prelude::*;

    let leaf = cert_chain_der
        .first()
        .ok_or_else(|| CaError::Internal("SPIRE agent returned empty cert chain".to_string()))?;
    let (_, parsed) = X509Certificate::from_der(leaf)
        .map_err(|e| CaError::Internal(format!("failed to parse SPIRE leaf cert: {e}")))?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(parsed.validity().not_after.timestamp(), 0)
        .ok_or_else(|| {
            CaError::Internal(
                "SPIRE leaf cert notAfter is outside supported timestamp range".to_string(),
            )
        })
}

fn record_spire_bundle_metrics(bundle: &crate::identity::SvidBundle) {
    if let Ok(not_after) = leaf_not_after(&bundle.cert_chain_der) {
        crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_at(
            &bundle.spiffe_id,
            "spire_agent",
            &not_after,
        );
    }
    crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle_roots(
        bundle.trust_bundles.local.trust_domain.as_str(),
        "spire_agent",
        bundle.trust_bundles.local.x509_authorities.as_slice(),
    );
    for federated in bundle.trust_bundles.federated.values() {
        crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle_roots(
            federated.trust_domain.as_str(),
            "spire_agent",
            federated.x509_authorities.as_slice(),
        );
    }
}

#[async_trait]
impl CertificateAuthority for SpireAgentCa {
    /// Return the current SVID from the agent snapshot.
    ///
    /// Unlike the internal CA, this does NOT mint a fresh cert — the SPIRE
    /// agent controls issuance. The returned `SignedSvid` always reflects the
    /// latest agent-pushed SVID.
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream(
                "SPIRE agent has not yet pushed an SVID — is the agent running and \
                 is this workload registered?"
                    .to_string(),
            )
        })?;

        // Validate that the requested SPIFFE ID matches the agent-issued one.
        let requested_id = match &req {
            IssuanceRequest::Csr { .. } => {
                return Err(CaError::BadCsr(
                    "SPIRE agent CA cannot sign caller-supplied CSRs; it can only return \
                     the current agent-issued SVID for generate requests"
                        .to_string(),
                ));
            }
            IssuanceRequest::Generate { spiffe_id, .. } => spiffe_id,
        };

        if requested_id != &snap.bundle.spiffe_id {
            return Err(CaError::BadCsr(format!(
                "requested SPIFFE ID '{}' does not match agent-issued SVID '{}'; \
                 the SPIRE agent controls identity assignment",
                requested_id, snap.bundle.spiffe_id
            )));
        }

        let not_after = leaf_not_after(&snap.bundle.cert_chain_der)?;
        crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_at(
            &snap.bundle.spiffe_id,
            "spire_agent",
            &not_after,
        );
        crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("spire_agent", true);

        Ok(SignedSvid {
            spiffe_id: snap.bundle.spiffe_id.clone(),
            cert_chain_der: snap.bundle.cert_chain_der.clone(),
            private_key_pkcs8_der: snap.bundle.private_key_pkcs8_der.clone(),
            not_after,
        })
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream("SPIRE agent has not yet pushed trust bundles".to_string())
        })?;

        // Check local bundle first, then federated.
        let bundle = snap
            .bundle
            .trust_bundles
            .get(td)
            .ok_or_else(|| CaError::UnknownTrustDomain(td.to_string()))?;

        let published = PublishedTrustBundle {
            trust_domain: bundle.trust_domain.clone(),
            roots_der: bundle.x509_authorities.clone(),
            refresh_hint_secs: bundle.refresh_hint_seconds,
        };
        crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle(
            &published,
            "spire_agent",
        );
        crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("spire_agent", true);
        Ok(published)
    }

    /// Publish the JWT authorities the SPIRE agent's own `FetchJWTBundles`
    /// stream has delivered for `td` (issue #3617).
    ///
    /// For a caller that explicitly constructs this adapter, Ferrum consumes
    /// the agent's JWKS documents, converts them to the SPKI-PEM form the
    /// identity subsystem speaks, and holds them to exactly the bounds a locally
    /// published bundle is held to. Nothing here carries a private key. Mesh
    /// startup currently uses its dedicated X.509 fetch loop instead and does
    /// not construct `SpireAgentCa`, so this is helper capability rather than a
    /// claim about live `FERRUM_MESH_CA_BACKEND=spire` runtime wiring.
    ///
    /// A trust domain the agent has published no JWT authorities for returns an
    /// empty vector, which the Workload API reports as `UNIMPLEMENTED` — never
    /// as an empty (and therefore misleading) bundle map. An `UnknownTrustDomain`
    /// error is reserved for a domain the agent serves no trust material for at
    /// all, so a federated peer that simply has no JWT keys is distinguishable
    /// from one Ferrum does not federate with.
    ///
    /// ## Terminal capability boundary: mint stays fail-closed
    ///
    /// `jwt_signer()` deliberately keeps the trait default (`None`), and that is
    /// **not** a deferral that local work can close. A SPIRE agent authorizes
    /// `FetchJWTSVID` against the *calling process's* attested identity, so
    /// proxying the ordinary agent Workload API would return a token whose `sub`
    /// is Ferrum's own SPIFFE ID rather than the downstream workload's — a
    /// silent identity substitution, which is strictly worse than
    /// `UNIMPLEMENTED`. Minting for a delegated subject requires SPIRE's
    /// delegated-identity / admin API, an explicitly authorized integration
    /// Ferrum is not granted here. Until such an integration is configured, mint
    /// must fail closed; do not "fix" this by proxying the agent's own mint RPC.
    async fn jwt_authorities(
        &self,
        td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        // Lock-free read of the JWT bundle snapshot. Checked FIRST so a
        // deployment whose JWT bundles have arrived but whose X.509 stream is
        // momentarily reconnecting still serves JWT trust material.
        let jwt_bundles = self.jwt_bundles.load();
        if let Some(authorities) = jwt_bundles.get(td) {
            return Ok(authorities.clone());
        }
        // The agent has published no JWT authorities for this domain. Fall back
        // to whatever the X.509 bundle set carried (a native/file-sourced
        // deployment can populate `TrustBundle.jwt_authorities` directly), and
        // distinguish "no JWT keys" from "not a trust domain we hold at all".
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream("SPIRE agent has not yet pushed trust bundles".to_string())
        })?;
        let bundle = snap
            .bundle
            .trust_bundles
            .get(td)
            .ok_or_else(|| CaError::UnknownTrustDomain(td.to_string()))?;
        Ok(bundle
            .jwt_authorities
            .iter()
            .map(|ja| {
                // The X.509 trust-bundle carrier holds a bare SPKI PEM with no
                // `alg`, so nothing is declared here. Validation then applies the
                // conservative undeclared-key policy rather than the key type's
                // full family — see `jwt_svid::decoding_key_for_authority`.
                PublishedJwtAuthority::new(td.clone(), ja.key_id.clone(), ja.public_key_pem.clone())
            })
            .collect())
    }
}

/// Background loop consuming the SPIRE agent's `FetchJWTBundles` stream into
/// [`SpireAgentCa::jwt_bundles`].
///
/// Deliberately tolerant of an agent that does not serve the RPC at all: a
/// SPIRE deployment with no JWT-SVID entries answers `UNIMPLEMENTED`, and that
/// must not become a reconnect storm or a startup failure. It is logged once per
/// connection attempt at debug and retried on the same exponential backoff
/// schedule as the X.509 stream, so a later agent upgrade is picked up with no
/// restart.
///
/// A malformed bundle is *not* installed: the previous snapshot is retained, so
/// hostile or corrupt material can neither widen nor blank the trusted set.
async fn jwt_bundle_stream_loop(socket_path: String, jwt_bundles: Arc<ArcSwap<JwtBundleSet>>) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    loop {
        match WorkloadApiClient::connect(&socket_path).await {
            Ok(mut client) => match client.fetch_jwt_bundles_stream().await {
                Ok(mut stream) => {
                    info!(socket = %socket_path, "SPIRE agent CA: JWT bundle stream established");
                    backoff = RECONNECT_BACKOFF_INITIAL;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(set) => {
                                debug!(
                                    trust_domains = set.len(),
                                    "SPIRE agent CA: received JWT bundles"
                                );
                                jwt_bundles.store(Arc::new(set));
                            }
                            Err(e) => {
                                // Terminal for this stream. Keep the last good
                                // snapshot: dropping it would strand workloads
                                // that already validate against it.
                                warn!(
                                    socket = %socket_path,
                                    error = %e,
                                    "SPIRE agent CA: JWT bundle stream failed; retaining the last \
                                     published JWT authorities"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        socket = %socket_path,
                        error = %e,
                        "SPIRE agent CA: agent does not serve FetchJWTBundles (or refused it); \
                         JWT-SVID bundle/validate stay UNIMPLEMENTED until it does"
                    );
                }
            },
            Err(e) => {
                debug!(
                    socket = %socket_path,
                    error = %e,
                    "SPIRE agent CA: JWT bundle stream connect failed"
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use crate::identity::ca::CertificateAuthority;
    use crate::identity::spiffe::{SpiffeId, spiffe_id_to_san};
    use crate::identity::{TrustBundle, TrustBundleSet};

    use super::*;

    fn test_bundle(spiffe_id: &str) -> SvidBundle {
        let spiffe_id = SpiffeId::new(spiffe_id).expect("test SPIFFE ID is valid");
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("test key generated");
        let mut params = rcgen::CertificateParams::default();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&spiffe_id).expect("SPIFFE SAN encodes"));
        let cert = params.self_signed(&key_pair).expect("test cert signed");
        let cert_der = cert.der().to_vec();
        let trust_domain = spiffe_id.trust_domain().clone();

        SvidBundle {
            spiffe_id,
            cert_chain_der: vec![cert_der.clone()],
            private_key_pkcs8_der: key_pair.serialize_der().into(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain,
                x509_authorities: vec![cert_der],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }),
        }
    }

    fn test_ca_with_bundle(bundle: SvidBundle, stream_task_abort: AbortHandle) -> SpireAgentCa {
        // The JWT bundle stream is inert here: these tests cover the X.509
        // issuance boundary, and an empty set is exactly what an agent that
        // publishes no JWT authorities produces.
        let jwt_stream_task_abort = stream_task_abort.clone();
        SpireAgentCa {
            config: SpireAgentCaConfig::default(),
            current: Arc::new(ArcSwap::new(Arc::new(Some(AgentSnapshot { bundle })))),
            first_ready: Arc::new(Notify::new()),
            first_received: Arc::new(AtomicBool::new(true)),
            stream_task_abort,
            jwt_bundles: Arc::new(ArcSwap::new(Arc::new(JwtBundleSet::new()))),
            jwt_stream_task_abort,
        }
    }

    #[tokio::test]
    async fn rejects_csr_requests_instead_of_returning_agent_private_key() {
        let id = SpiffeId::new("spiffe://example.test/ns/default/sa/ferrum").unwrap();
        let stream_task = tokio::spawn(future::pending::<()>());
        let ca = test_ca_with_bundle(test_bundle(id.as_str()), stream_task.abort_handle());
        let csr_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("CSR key generated");
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&csr_key)
            .expect("CSR generated");

        let err = ca
            .issue_svid(IssuanceRequest::Csr {
                csr_der: csr.der().as_ref().to_vec(),
                spiffe_id: id,
                ttl_secs: 60,
            })
            .await
            .expect_err("SPIRE agent CA cannot sign caller CSRs");

        assert!(matches!(err, CaError::BadCsr(_)));
        drop(ca);
        let _ = stream_task.await;
    }

    #[tokio::test]
    async fn drop_aborts_background_stream_task() {
        let stream_task = tokio::spawn(future::pending::<()>());
        let ca = test_ca_with_bundle(
            test_bundle("spiffe://example.test/ns/default/sa/ferrum"),
            stream_task.abort_handle(),
        );

        drop(ca);

        let err = tokio::time::timeout(Duration::from_secs(1), stream_task)
            .await
            .expect("background task should be aborted promptly")
            .expect_err("aborted task returns JoinError");
        assert!(err.is_cancelled());
    }

    #[tokio::test]
    async fn wait_for_first_svid_returns_when_snapshot_already_ready() {
        let stream_task = tokio::spawn(future::pending::<()>());
        let ca = test_ca_with_bundle(
            test_bundle("spiffe://example.test/ns/default/sa/ferrum"),
            stream_task.abort_handle(),
        );

        tokio::time::timeout(Duration::from_secs(1), ca.wait_for_first_svid())
            .await
            .expect("ready snapshot should not block");
        assert!(ca.first_received.load(Ordering::Acquire));

        drop(ca);
        let _ = stream_task.await;
    }
}
