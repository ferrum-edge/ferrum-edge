//! In-process SPIFFE Workload API server.
//!
//! When Ferrum is acting as the SVID issuer, this server exposes the
//! Workload API over a Unix domain socket so local workloads (sidecars,
//! ambient ztunnels, plain processes on the host) can fetch SVIDs without
//! shipping a secret out-of-band.
//!
//! Architecture:
//!
//! 1. Listener: `tokio::net::UnixListener` bound to a configured path.
//! 2. Per-stream: gather peer creds + caller-supplied bearer token into
//!    [`PeerInfo`].
//! 3. Run the configured chain of [`Attestor`]s.
//! 4. Ask the [`CertificateAuthority`] to mint an SVID for the resulting
//!    SPIFFE ID and stream it back to the workload.
//!
//! Entitlement on long-lived streams (SPIFFE Workload API Appendix A §6):
//!
//! - `FetchX509SVID` retains the authenticated [`PeerInfo`] and re-runs the
//!   attestor chain before every rotated issuance. A revoked/changed
//!   entitlement yields a terminal `PermissionDenied` on the stream
//!   (fail-closed); a changed authorized identity is reflected in the next
//!   complete response.
//! - `FetchX509Bundles` returns only public CA trust material (no private
//!   keys). It requires the mandatory Workload API metadata header but does
//!   **not** run attestor/entitlement checks — bundle-only callers need trust
//!   roots to validate peers without holding an SVID. Private-key issuance
//!   remains gated exclusively on `FetchX509SVID`.
//! - JWT-SVID RPCs (issue #3617) are served whenever the selected CA backend
//!   supplies a JWT authority, and fail closed with `UNIMPLEMENTED` when it
//!   genuinely cannot:
//!   - `FetchJWTSVID` re-runs the attestor chain and mints **only** for the
//!     attested identity. A caller-supplied `spiffe_id` is honoured only when
//!     byte-equal to the attested one; anything else is `PermissionDenied`.
//!     Requires `CertificateAuthority::jwt_signer()`.
//!   - `FetchJWTBundles` streams the JWKS document for the local trust domain
//!     (plus any federated ones) and republishes on rotation, skipping
//!     unchanged generations. It never emits an empty `bundles` map as
//!     success — SPIFFE Workload API §6.2.2 requires at least the local
//!     trust-domain bundle, so "no authorities" is reported as
//!     `UNIMPLEMENTED`, not as an empty map.
//!   - `ValidateJWTSVID` verifies against the same published authorities.
//!     Like `FetchX509Bundles` it needs only the mandatory metadata header —
//!     it consumes public trust material and mints nothing.
//!
//! Rotation delivery is capacity-one / latest-wins ([`super::latest_wins`]):
//! slow consumers do not accumulate private-key-bearing responses, and
//! stream cancel drops any pending slot immediately so rotation tasks exit
//! without waiting on backpressure.
//!
//! The listener lifecycle — socket path/ownership/mode contract, bind, serve,
//! and owned-artifact cleanup — lives in [`super::listener`]; mesh mode stands
//! this service up through it when
//! `FERRUM_MESH_WORKLOAD_API_ENABLED=true`, and a bind failure is fatal to
//! startup rather than a silent downgrade to "not listening".

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, warn};

use super::latest_wins::{self, LatestWinsSender};
use super::proto::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use super::proto::{
    JwtBundlesRequest, JwtBundlesResponse, Jwtsvid, JwtsvidRequest, JwtsvidResponse,
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse,
    X509svid, X509svidRequest, X509svidResponse,
};
use crate::identity::attestation::{Attestor, PeerInfo, attest_chain};
use crate::identity::ca::{CertificateAuthority, IssuanceRequest, PublishedJwtAuthority};
use crate::identity::jwt_svid::{
    self, DEFAULT_JWT_SVID_TTL_SECS, JwtSvidError, MAX_JWT_BUNDLE_TRUST_DOMAINS,
};
use crate::identity::spiffe::TrustDomain;

const WORKLOAD_METADATA_KEY: &str = "workload.spiffe.io";
const WORKLOAD_METADATA_VAL: &str = "true";

/// Maximum number of **federated** trust domains one service may be configured
/// with.
///
/// The local trust domain always occupies one slot of
/// [`MAX_JWT_BUNDLE_TRUST_DOMAINS`], so the federated set gets the rest. The
/// bound is enforced once, in
/// [`WorkloadApiService::with_federated_trust_domains`], and every per-RPC loop
/// additionally iterates at most this many entries — a belt on the constructor's
/// braces, so no future field mutation can reopen an unbounded CA fan-out.
const MAX_FEDERATED_TRUST_DOMAINS: usize = MAX_JWT_BUNDLE_TRUST_DOMAINS - 1;

/// Workload API service implementation. Held as an `Arc` and cloned per RPC.
pub struct WorkloadApiService {
    pub attestors: Vec<Arc<dyn Attestor>>,
    pub ca: Arc<dyn CertificateAuthority>,
    pub trust_domain: TrustDomain,
    /// SVID lifetime (seconds) when an SVID is freshly minted in response to
    /// an attested workload. Falls back to the CA's clamp if higher.
    pub svid_ttl_secs: u64,
    /// Bumped by the rotation layer when SVIDs or trust bundles change.
    /// Long-lived Workload API streams subscribe to this channel and push
    /// fresh responses on each epoch change.
    rotation_signal: Arc<watch::Sender<u64>>,
    /// Federated trust domains to include in X.509 Workload API responses.
    federated_trust_domains: Vec<TrustDomain>,
    /// Lifetime requested for minted JWT-SVIDs. The signing authority clamps
    /// this down to its own ceiling; it can never raise it.
    jwt_svid_ttl_secs: u64,
    /// Listener-owned shutdown signal. Streaming RPC producers observe this so
    /// tonic's graceful server shutdown is not held open forever by the
    /// deliberately long-lived Workload API streams.
    service_shutdown: Option<watch::Receiver<bool>>,
}

impl WorkloadApiService {
    pub fn new(
        attestors: Vec<Arc<dyn Attestor>>,
        ca: Arc<dyn CertificateAuthority>,
        trust_domain: TrustDomain,
        svid_ttl_secs: u64,
    ) -> Self {
        let (tx, _) = watch::channel(0u64);
        Self {
            attestors,
            ca,
            trust_domain,
            svid_ttl_secs,
            rotation_signal: Arc::new(tx),
            federated_trust_domains: Vec::new(),
            jwt_svid_ttl_secs: DEFAULT_JWT_SVID_TTL_SECS,
            service_shutdown: None,
        }
    }

    pub fn with_rotation_signal(
        attestors: Vec<Arc<dyn Attestor>>,
        ca: Arc<dyn CertificateAuthority>,
        trust_domain: TrustDomain,
        svid_ttl_secs: u64,
        rotation_signal: Arc<watch::Sender<u64>>,
    ) -> Self {
        Self {
            attestors,
            ca,
            trust_domain,
            svid_ttl_secs,
            rotation_signal,
            federated_trust_domains: Vec::new(),
            jwt_svid_ttl_secs: DEFAULT_JWT_SVID_TTL_SECS,
            service_shutdown: None,
        }
    }

    /// Attach the federated trust domains this service publishes bundles for.
    ///
    /// The input is **normalized once, here**, and every later RPC iterates the
    /// result rather than the operator's raw list:
    ///
    /// - exact duplicates are collapsed (the map keys they produce are
    ///   identical, so a repeated alias is pure extra CA work);
    /// - the local trust domain is dropped — it is always published from its own
    ///   dedicated path, and a federated entry for it would be a second fetch of
    ///   the same bundle;
    /// - the remaining count is bounded by
    ///   [`MAX_JWT_BUNDLE_TRUST_DOMAINS`] minus the local domain's slot.
    ///
    /// Over-cap input is an **error**, not a truncation. Bounding inside the
    /// per-RPC loops instead let arbitrarily many empty or failing aliases drive
    /// unbounded CA calls (the JWT loop counted only *successfully inserted*
    /// bundles, so a domain that published nothing never advanced it), and
    /// silently dropping the tail would have reported a trust posture the
    /// operator did not configure. Refusing at construction is the only answer
    /// that is both bounded and honest.
    pub fn with_federated_trust_domains(
        mut self,
        trust_domains: Vec<TrustDomain>,
    ) -> Result<Self, JwtSvidError> {
        let mut normalized: Vec<TrustDomain> = Vec::with_capacity(trust_domains.len());
        for domain in trust_domains {
            if domain == self.trust_domain || normalized.contains(&domain) {
                continue;
            }
            normalized.push(domain);
        }
        if normalized.len() > MAX_FEDERATED_TRUST_DOMAINS {
            return Err(JwtSvidError::InvalidRequest(
                "more federated trust domains are configured than one Workload API bundle response \
                 may carry",
            ));
        }
        self.federated_trust_domains = normalized;
        Ok(self)
    }

    /// Requested lifetime for minted JWT-SVIDs.
    ///
    /// The signing authority clamps to its own ceiling
    /// ([`crate::identity::jwt_svid::MAX_JWT_SVID_TTL_SECS`]), so this can
    /// only shorten a JWT-SVID, never extend one past what the rotation
    /// overlap guarantees remains verifiable.
    pub fn with_jwt_svid_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.jwt_svid_ttl_secs = ttl_secs;
        self
    }

    /// Attach the listener lifecycle to every streaming RPC producer.
    ///
    /// `serve_with_incoming_shutdown` stops accepting new work but waits for
    /// existing response streams to finish. Workload API streams are designed
    /// to remain open across rotations, so without this second signal a normal
    /// process shutdown can wait forever for a connected workload. Ending each
    /// producer drops its response sender, lets tonic finish the RPC, and keeps
    /// shutdown graceful rather than aborting the transport task.
    pub fn with_service_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.service_shutdown = Some(shutdown);
        self
    }

    pub fn rotation_signal(&self) -> &Arc<watch::Sender<u64>> {
        &self.rotation_signal
    }

    /// Wrap into a `tonic` server. Exposed so callers can register additional
    /// services on the same listener if they wish.
    pub fn into_server(self) -> SpiffeWorkloadApiServer<Self> {
        SpiffeWorkloadApiServer::new(self)
    }

    /// Extract `PeerInfo` from a tonic request: the bearer token from the
    /// `authorization` metadata header (Bearer scheme) plus, on a Unix-socket
    /// transport, the kernel-supplied `SO_PEERCRED` pid/uid/gid.
    ///
    /// Peer credentials come from `UdsConnectInfo`, which tonic populates from
    /// the accepted socket itself — they are kernel-attested and cannot be
    /// spoofed by the caller, unlike anything in the metadata. Their absence is
    /// not fatal here: it simply means no `SO_PEERCRED`-based attestor applies,
    /// and the attestor chain decides.
    fn peer_info_from_request<T>(req: &Request<T>) -> PeerInfo {
        let mut info = PeerInfo::default();
        if let Some(auth) = req.metadata().get("authorization")
            && let Ok(s) = auth.to_str()
        {
            info.bearer_token = parse_authorization_header(s);
        }
        #[cfg(unix)]
        if let Some(connect_info) = req
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            && let Some(cred) = connect_info.peer_cred
        {
            info.pid = cred.pid();
            info.uid = Some(cred.uid());
            info.gid = Some(cred.gid());
        }
        info
    }

    fn validate_workload_metadata<T>(req: &Request<T>) -> Result<(), Status> {
        match req.metadata().get(WORKLOAD_METADATA_KEY) {
            Some(value) if value == WORKLOAD_METADATA_VAL => Ok(()),
            _ => Err(Status::invalid_argument(format!(
                "missing required {WORKLOAD_METADATA_KEY}: {WORKLOAD_METADATA_VAL} metadata"
            ))),
        }
    }

    /// Wait for the next rotation epoch or stream cancel.
    ///
    /// When several epochs fire while the prior issuance is still in flight,
    /// collapse them into a single wake so we mint/publish at most one newest
    /// response per producer cycle (no FIFO of intermediate private keys).
    async fn wait_for_rotation_or_stream_close<T>(
        rx: &mut watch::Receiver<u64>,
        tx: &LatestWinsSender<T>,
        service_shutdown: &mut Option<watch::Receiver<bool>>,
    ) -> bool {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    return false;
                }
                // Drain any epochs that arrived while we were waking so one
                // issuance observes the newest rotation state.
                while rx.has_changed().is_ok_and(|changed| changed) {
                    rx.borrow_and_update();
                }
                true
            }
            _ = tx.closed() => false,
            _ = Self::wait_for_service_shutdown(service_shutdown) => false,
        }
    }

    /// Wait for listener shutdown when this service is listener-owned, or stay
    /// pending for services constructed directly in tests and other callers.
    async fn wait_for_service_shutdown(shutdown: &mut Option<watch::Receiver<bool>>) {
        let Some(shutdown) = shutdown.as_mut() else {
            std::future::pending::<()>().await;
            return;
        };
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    }

    async fn attest(
        &self,
        peer: &PeerInfo,
    ) -> Result<crate::identity::attestation::WorkloadIdentity, Status> {
        Self::attest_with(&self.attestors, peer).await
    }

    /// Authoritative attestor-chain check used both at stream open and before
    /// every rotated `FetchX509SVID` issuance. Failures map to
    /// `PermissionDenied` (SPIFFE Workload API entitlement denial).
    async fn attest_with(
        attestors: &[Arc<dyn Attestor>],
        peer: &PeerInfo,
    ) -> Result<crate::identity::attestation::WorkloadIdentity, Status> {
        match attest_chain(attestors, peer).await {
            Ok(id) => {
                debug!(
                    spiffe_id = %id.spiffe_id,
                    attestor = %id.attestor_kind,
                    "workload attested"
                );
                Ok(id)
            }
            Err(e) => {
                warn!(error = %e, "workload attestation failed");
                // Attestors may carry local filesystem or provider diagnostics.
                // Keep those in the structured server log and expose only the
                // fixed entitlement result to the untrusted caller.
                Err(Status::permission_denied("workload attestation failed"))
            }
        }
    }

    async fn build_x509_svid_response(
        &self,
        identity: &crate::identity::attestation::WorkloadIdentity,
    ) -> Result<X509svidResponse, Status> {
        let svid = self
            .ca
            .issue_svid(IssuanceRequest::Generate {
                spiffe_id: identity.spiffe_id.clone(),
                ttl_secs: self.svid_ttl_secs,
            })
            .await
            .map_err(|e| {
                error!(error = %e, "CA failed to issue SVID");
                Status::internal(format!("CA failed: {e}"))
            })?;

        let bundle = self
            .ca
            .trust_bundle(&self.trust_domain)
            .await
            .map_err(|e| Status::internal(format!("CA bundle fetch failed: {e}")))?;

        let chain_concat: Vec<u8> = svid.cert_chain_der.iter().flatten().copied().collect();
        let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
        let federated_bundles =
            Self::build_federated_x509_bundle_map(&self.ca, &self.federated_trust_domains)
                .await
                .map_err(|e| Status::internal(format!("CA federated bundle fetch failed: {e}")))?;

        let proto_svid = X509svid {
            spiffe_id: svid.spiffe_id.to_string(),
            x509_svid: chain_concat,
            x509_svid_key: svid.private_key_pkcs8_der.to_vec(),
            bundle: bundle_concat,
            // The SPIFFE Workload API `hint` field is an operator-specified
            // workload-matching hint (string), not a timestamp. We have no
            // hint to propagate today; the cert's NotAfter is in the cert
            // itself and is what consumers parse for rotation.
            hint: String::new(),
        };

        Ok(X509svidResponse {
            svids: vec![proto_svid],
            crl: Vec::new(),
            federated_bundles,
        })
    }

    async fn build_x509_svid_response_static(
        ca: &Arc<dyn CertificateAuthority>,
        trust_domain: &TrustDomain,
        spiffe_id: &crate::identity::spiffe::SpiffeId,
        ttl_secs: u64,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<X509svidResponse, Status> {
        let svid = ca
            .issue_svid(IssuanceRequest::Generate {
                spiffe_id: spiffe_id.clone(),
                ttl_secs,
            })
            .await
            .map_err(|e| {
                error!(error = %e, "CA failed to issue SVID");
                Status::internal(format!("CA failed: {e}"))
            })?;

        let bundle = ca
            .trust_bundle(trust_domain)
            .await
            .map_err(|e| Status::internal(format!("CA bundle fetch failed: {e}")))?;

        let chain_concat: Vec<u8> = svid.cert_chain_der.iter().flatten().copied().collect();
        let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
        let federated_bundles = Self::build_federated_x509_bundle_map(ca, federated_trust_domains)
            .await
            .map_err(|e| Status::internal(format!("CA federated bundle fetch failed: {e}")))?;

        let proto_svid = X509svid {
            spiffe_id: svid.spiffe_id.to_string(),
            x509_svid: chain_concat,
            x509_svid_key: svid.private_key_pkcs8_der.to_vec(),
            bundle: bundle_concat,
            hint: String::new(),
        };

        Ok(X509svidResponse {
            svids: vec![proto_svid],
            crl: Vec::new(),
            federated_bundles,
        })
    }

    async fn build_x509_bundles_response_static(
        ca: &Arc<dyn CertificateAuthority>,
        trust_domain: &TrustDomain,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<X509BundlesResponse, crate::identity::ca::CaError> {
        let bundle = ca.trust_bundle(trust_domain).await?;
        let mut bundles = HashMap::new();
        let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
        bundles.insert(trust_domain.to_string(), bundle_concat);
        // Same bounded-iteration contract as the JWT path: the configured vector
        // is normalized and capped at construction, and `take` keeps the CA
        // fan-out bounded regardless.
        for td in federated_trust_domains
            .iter()
            .take(MAX_FEDERATED_TRUST_DOMAINS)
        {
            if td == trust_domain {
                continue;
            }
            let bundle = ca.trust_bundle(td).await?;
            let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
            bundles.insert(td.to_string(), bundle_concat);
        }
        Ok(X509BundlesResponse {
            crl: Vec::new(),
            bundles,
        })
    }

    /// Collect the JWT authorities this service is willing to trust, keyed by
    /// trust domain: the local trust domain plus every configured federated
    /// one that actually publishes authorities.
    ///
    /// **Every** domain's complete authority set is admitted through
    /// [`jwt_svid::validate_published_authorities`] here, before it is returned
    /// to either RPC. That is the single place the documented authority bounds
    /// (count cap, trust-domain binding, duplicate `kid`, key-id / PEM / DER /
    /// key-type / key-size constraints, total JWKS size) are enforced, so
    /// `ValidateJWTSVID` and `FetchJWTBundles` cannot disagree about what is
    /// acceptable material and a hostile externally supplied bundle can never
    /// reach a scan.
    ///
    /// The federated iteration is bounded by [`MAX_FEDERATED_TRUST_DOMAINS`]
    /// *inputs*, not by outputs. Configuration is already deduplicated,
    /// local-domain-free, and capped by
    /// [`WorkloadApiService::with_federated_trust_domains`], so the number of CA
    /// calls one RPC can make is fixed before any of them is issued.
    ///
    /// A federated domain the CA does not serve is skipped rather than failing
    /// the whole call — federation is best-effort and the local bundle is the
    /// load-bearing one. A local-domain failure is not skipped, and neither is
    /// *malformed* federated material: a bundle the CA did publish but that
    /// fails admission is a real fault, not an absent peer, so it fails the call
    /// closed rather than being silently dropped from the trusted set.
    async fn collect_jwt_authorities(
        ca: &Arc<dyn CertificateAuthority>,
        trust_domain: &TrustDomain,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>>, JwtSvidError> {
        let mut bundles: BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> = BTreeMap::new();

        let local = ca.jwt_authorities(trust_domain).await.map_err(|e| {
            warn!(error = %e, "CA failed to publish local JWT authorities");
            JwtSvidError::Internal("CA failed to publish JWT authorities".to_string())
        })?;
        if local.is_empty() {
            return Err(JwtSvidError::NoJwtAuthority(
                "the active identity backend publishes no JWT authority for this trust domain",
            ));
        }
        jwt_svid::validate_published_authorities(trust_domain, &local)?;
        bundles.insert(trust_domain.clone(), local);

        // Bounded by the ITERATION, not by how many bundles came back: counting
        // successful insertions let arbitrarily many empty or failing aliases
        // drive unbounded CA calls, because neither outcome advanced the count.
        // The configured vector is already deduplicated, local-domain-free, and
        // capped; `take` keeps that true independently of how it was populated.
        for federated in federated_trust_domains
            .iter()
            .take(MAX_FEDERATED_TRUST_DOMAINS)
        {
            if federated == trust_domain {
                continue;
            }
            match ca.jwt_authorities(federated).await {
                Ok(authorities) if !authorities.is_empty() => {
                    jwt_svid::validate_published_authorities(federated, &authorities)?;
                    bundles.insert(federated.clone(), authorities);
                }
                // No authorities published for this federation peer — publish
                // nothing for it rather than an empty (misleading) entry.
                Ok(_) => {}
                Err(e) => {
                    debug!(
                        trust_domain = %federated,
                        error = %e,
                        "federated JWT authorities unavailable; omitting from JWT bundles"
                    );
                }
            }
        }
        Ok(bundles)
    }

    /// Build the `FetchJWTBundles` payload: one JWKS document per trust
    /// domain. Never returns an empty map — [`Self::collect_jwt_authorities`]
    /// has already refused that case.
    async fn build_jwt_bundles_response_static(
        ca: &Arc<dyn CertificateAuthority>,
        trust_domain: &TrustDomain,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<JwtBundlesResponse, JwtSvidError> {
        let authorities =
            Self::collect_jwt_authorities(ca, trust_domain, federated_trust_domains).await?;
        let mut bundles = HashMap::with_capacity(authorities.len());
        for (domain, published) in &authorities {
            // A malformed authority is refused before publication rather than
            // shipped to workloads as trust material.
            let jwks = jwt_svid::jwks_document(published)?;
            bundles.insert(domain.to_string(), jwks);
        }
        if bundles.is_empty() {
            return Err(JwtSvidError::NoJwtAuthority(
                "no JWT bundle could be published for this trust domain",
            ));
        }
        Ok(JwtBundlesResponse { bundles })
    }

    /// Stable fingerprint of a bundle response, used to skip republishing an
    /// unchanged authority set on a rotation signal that did not touch JWT
    /// material.
    fn jwt_bundles_fingerprint(response: &JwtBundlesResponse) -> Vec<(String, Vec<u8>)> {
        let mut entries: Vec<(String, Vec<u8>)> = response
            .bundles
            .iter()
            .map(|(domain, jwks)| (domain.clone(), jwks.clone()))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    async fn build_federated_x509_bundle_map(
        ca: &Arc<dyn CertificateAuthority>,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<HashMap<String, Vec<u8>>, crate::identity::ca::CaError> {
        let mut bundles = HashMap::new();
        for td in federated_trust_domains
            .iter()
            .take(MAX_FEDERATED_TRUST_DOMAINS)
        {
            let bundle = ca.trust_bundle(td).await?;
            let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
            bundles.insert(td.to_string(), bundle_concat);
        }
        Ok(bundles)
    }
}

/// Parse an `authorization` header value into the bare bearer token.
///
/// RFC 6750 §2.1: the Bearer scheme name is case-insensitive. We accept
/// `Bearer`, `bearer`, `BEARER`, etc. If the value carries no scheme word
/// (no whitespace separator), the entire trimmed value is treated as the
/// raw token — preserving the existing behaviour for callers that hand in
/// a bare token string. If the scheme is present but not Bearer (e.g.
/// `Basic xyz`), the entire value is also passed through as-is so the
/// downstream attestor chain sees the original metadata; no attestor
/// today recognises non-Bearer schemes, so they reject the resulting
/// "token" with `NotApplicable` / `Failed`.
fn parse_authorization_header(raw: &str) -> Option<String> {
    // Strip leading whitespace only — preserve trailing whitespace so that
    // an input like `"Bearer "` (scheme word with no token) splits on the
    // delimiter and resolves to an empty token (returned as `None`)
    // instead of being collapsed to the bare string `"Bearer"`.
    let leading_trimmed = raw.trim_start();
    let token = match leading_trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => rest.trim(),
        _ => leading_trimmed.trim_end(),
    };
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Map a JWT-SVID failure onto a gRPC status.
///
/// Every message is a fixed string authored in `identity::jwt_svid` — token
/// bytes, claim values, and key material never reach a client. The
/// `UNIMPLEMENTED` arm is the honest "this backend cannot do JWT-SVID"
/// signal and is deliberately distinct from an `INVALID_ARGUMENT` "this token
/// is bad".
fn jwt_svid_status(error: JwtSvidError) -> Status {
    let message = error.to_string();
    match error {
        JwtSvidError::InvalidRequest(_) | JwtSvidError::InvalidToken(_) => {
            Status::invalid_argument(message)
        }
        JwtSvidError::Denied(_) => Status::permission_denied(message),
        JwtSvidError::NoJwtAuthority(_) => Status::unimplemented(message),
        JwtSvidError::InvalidAuthority(_) => {
            warn!(reason = %message, "JWT authority material rejected before publication");
            Status::internal(message)
        }
        // Neither is reachable from an RPC: rotation runs on the background
        // task and signing material is loaded at startup. Mapped explicitly so
        // adding a variant cannot silently acquire a wrong status.
        JwtSvidError::RotationRefused(_) | JwtSvidError::InvalidSigningMaterial(_) => {
            error!(reason = %message, "JWT-SVID signing/rotation failure surfaced on an RPC path");
            Status::internal(message)
        }
        JwtSvidError::Internal(_) => {
            error!(reason = %message, "JWT-SVID internal failure");
            Status::internal(message)
        }
    }
}

#[async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream =
        Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send + 'static>>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        Self::validate_workload_metadata(&request)?;
        // Retain PeerInfo for the lifetime of the stream so each rotation
        // re-runs the authoritative attestor/entitlement checks rather than
        // treating the initial SPIFFE ID as an indefinite renewal capability.
        let peer = Self::peer_info_from_request(&request);
        let identity = self.attest(&peer).await?;
        let initial = self.build_x509_svid_response(&identity).await?;

        let ca = Arc::clone(&self.ca);
        let td = self.trust_domain.clone();
        let ttl = self.svid_ttl_secs;
        let attestors = self.attestors.clone();
        let federated_trust_domains = self.federated_trust_domains.clone();
        let mut rx = self.rotation_signal.subscribe();
        let mut service_shutdown = self.service_shutdown.clone();

        let (tx, out_rx) = latest_wins::channel();
        if !tx.publish(Ok(initial)) {
            return Err(Status::cancelled(
                "FetchX509SVID stream closed before start",
            ));
        }

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx, &mut service_shutdown)
                    .await
                {
                    return;
                }
                // Appendix A §6: validate the pending response — ensure the
                // client is still entitled before minting a replacement SVID.
                let identity = match Self::attest_with(&attestors, &peer).await {
                    Ok(id) => id,
                    Err(status) => {
                        let _ = tx.publish(Err(status));
                        return;
                    }
                };
                match Self::build_x509_svid_response_static(
                    &ca,
                    &td,
                    &identity.spiffe_id,
                    ttl,
                    &federated_trust_domains,
                )
                .await
                {
                    Ok(resp) => {
                        // Latest-wins: replaces any unread prior response and
                        // drops superseded private-key material immediately.
                        if !tx.publish(Ok(resp)) {
                            return;
                        }
                    }
                    Err(e) => {
                        // Transient CA failures are not entitlement denials;
                        // keep the stream open and retry on the next epoch.
                        warn!(error = %e, "rotation push failed for FetchX509SVID stream");
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(out_rx.into_stream())))
    }

    type FetchX509BundlesStream =
        Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_x509_bundles(
        &self,
        request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        // Bundle-only entitlement policy (explicit): this RPC returns public
        // CA trust material only — never private keys — so it does not run
        // the attestor chain. Callers still must present the mandatory
        // `workload.spiffe.io` metadata. Private-key SVID issuance and
        // rotation revalidation live exclusively on `FetchX509SVID`.
        Self::validate_workload_metadata(&request)?;
        let initial = Self::build_x509_bundles_response_static(
            &self.ca,
            &self.trust_domain,
            &self.federated_trust_domains,
        )
        .await
        .map_err(|e| Status::internal(format!("CA bundle fetch failed: {e}")))?;

        let ca = Arc::clone(&self.ca);
        let td = self.trust_domain.clone();
        let federated_trust_domains = self.federated_trust_domains.clone();
        let mut rx = self.rotation_signal.subscribe();
        let mut service_shutdown = self.service_shutdown.clone();

        let (tx, out_rx) = latest_wins::channel();
        if !tx.publish(Ok(initial)) {
            return Err(Status::cancelled(
                "FetchX509Bundles stream closed before start",
            ));
        }

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx, &mut service_shutdown)
                    .await
                {
                    return;
                }
                match Self::build_x509_bundles_response_static(&ca, &td, &federated_trust_domains)
                    .await
                {
                    Ok(resp) => {
                        if !tx.publish(Ok(resp)) {
                            return;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "rotation push failed for FetchX509Bundles stream");
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(out_rx.into_stream())))
    }

    async fn fetch_jwtsvid(
        &self,
        request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Self::validate_workload_metadata(&request)?;
        // The subject is the *attested* identity, never a caller claim. Run
        // the attestor chain before looking at the payload so an unattested
        // caller cannot probe which backends can mint.
        let peer = Self::peer_info_from_request(&request);
        let identity = self.attest(&peer).await?;
        let req = request.into_inner();

        let audiences = jwt_svid::canonical_audiences(&req.audience).map_err(jwt_svid_status)?;

        // SPIFFE Workload API §5.3: `spiffe_id` selects among the identities
        // the caller already holds. Ferrum attests exactly one, so the only
        // authorized value is that one — an arbitrary caller-chosen subject is
        // an entitlement violation, not a lookup miss.
        if !req.spiffe_id.is_empty() && req.spiffe_id != identity.spiffe_id.as_str() {
            warn!(
                attested = %identity.spiffe_id,
                "FetchJWTSVID requested a SPIFFE ID this workload is not entitled to"
            );
            return Err(Status::permission_denied(
                "requested SPIFFE ID is not authorized for this workload",
            ));
        }

        let signer = self.ca.jwt_signer().ok_or_else(|| {
            Status::unimplemented(
                "the active identity backend cannot mint JWT-SVIDs; \
                 only X.509-SVIDs are available on this Workload API",
            )
        })?;
        if identity.spiffe_id.trust_domain() != signer.trust_domain() {
            return Err(Status::permission_denied(
                "attested SPIFFE ID is outside the JWT signing authority's trust domain",
            ));
        }

        let minted = signer
            .mint(&identity.spiffe_id, &audiences, self.jwt_svid_ttl_secs)
            .map_err(jwt_svid_status)?;

        Ok(Response::new(JwtsvidResponse {
            svids: vec![Jwtsvid {
                spiffe_id: minted.spiffe_id.to_string(),
                svid: minted.token,
                // No operator-specified matching hint to propagate; the
                // audiences the caller asked for are already in the token.
                hint: String::new(),
            }],
        }))
    }

    type FetchJWTBundlesStream =
        Pin<Box<dyn Stream<Item = Result<JwtBundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_jwt_bundles(
        &self,
        request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        // Same entitlement policy as `FetchX509Bundles`: public trust material
        // only, so the mandatory metadata header is required but the attestor
        // chain is not run. Private key material stays exclusive to
        // `FetchX509SVID` / `FetchJWTSVID`.
        Self::validate_workload_metadata(&request)?;

        // Fail closed at the RPC boundary rather than streaming an empty map:
        // SPIFFE Workload API §6.2.2 requires at least the local trust-domain
        // JWT bundle, so an empty `bundles` map would be read as "zero trusted
        // JWT authorities" rather than "unsupported".
        let initial = Self::build_jwt_bundles_response_static(
            &self.ca,
            &self.trust_domain,
            &self.federated_trust_domains,
        )
        .await
        .map_err(jwt_svid_status)?;
        let mut last_published = Self::jwt_bundles_fingerprint(&initial);

        let ca = Arc::clone(&self.ca);
        let td = self.trust_domain.clone();
        let federated_trust_domains = self.federated_trust_domains.clone();
        let mut rx = self.rotation_signal.subscribe();
        let mut service_shutdown = self.service_shutdown.clone();

        let (tx, out_rx) = latest_wins::channel();
        if !tx.publish(Ok(initial)) {
            return Err(Status::cancelled(
                "FetchJWTBundles stream closed before start",
            ));
        }

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx, &mut service_shutdown)
                    .await
                {
                    return;
                }
                match Self::build_jwt_bundles_response_static(&ca, &td, &federated_trust_domains)
                    .await
                {
                    Ok(resp) => {
                        let fingerprint = Self::jwt_bundles_fingerprint(&resp);
                        if fingerprint == last_published {
                            // Rotation signal that did not change JWT trust
                            // material (an X.509-only rotation, or a rotation
                            // collapsed with an earlier one).
                            continue;
                        }
                        last_published = fingerprint;
                        if !tx.publish(Ok(resp)) {
                            return;
                        }
                    }
                    Err(e) => {
                        // Keep the stream open and retry on the next epoch: a
                        // transient CA failure is not a trust-material change,
                        // and tearing the stream down would strand the
                        // workload without bundles it already validated
                        // against. Never publish a partial or empty map.
                        warn!(error = %e, "rotation push failed for FetchJWTBundles stream");
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(out_rx.into_stream())))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        // Validation consumes only public trust material and mints nothing,
        // so — like the bundle RPCs — it requires the mandatory metadata
        // header but not the attestor chain.
        Self::validate_workload_metadata(&request)?;
        let req = request.into_inner();

        let bundles = Self::collect_jwt_authorities(
            &self.ca,
            &self.trust_domain,
            &self.federated_trust_domains,
        )
        .await
        .map_err(jwt_svid_status)?;

        let validated =
            jwt_svid::validate_jwt_svid(&req.svid, &req.audience, &bundles).map_err(|e| {
                debug!(reason = %e, "ValidateJWTSVID rejected a token");
                jwt_svid_status(e)
            })?;

        Ok(Response::new(ValidateJwtsvidResponse {
            spiffe_id: validated.spiffe_id.to_string(),
            claims_json: validated.claims_json,
        }))
    }
}

#[cfg(test)]
mod authz_parse_tests {
    use super::parse_authorization_header;

    #[test]
    fn strips_canonical_bearer_prefix() {
        assert_eq!(
            parse_authorization_header("Bearer eyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn strips_lowercase_bearer_prefix() {
        // RFC 6750 §2.1: Bearer scheme is case-insensitive.
        assert_eq!(
            parse_authorization_header("bearer eyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn strips_uppercase_bearer_prefix() {
        assert_eq!(
            parse_authorization_header("BEARER eyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn strips_mixed_case_bearer_prefix() {
        assert_eq!(
            parse_authorization_header("BeArEr eyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn handles_extra_whitespace_after_scheme() {
        assert_eq!(
            parse_authorization_header("bearer    eyJhbGciOiJI   "),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn handles_tab_separator() {
        // Some clients use a tab between scheme and token. RFC 7230 allows
        // any HTAB or SP between scheme and credentials.
        assert_eq!(
            parse_authorization_header("bearer\teyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn passes_through_raw_token_with_no_scheme() {
        // Bare token (no whitespace) — keep as-is.
        assert_eq!(
            parse_authorization_header("eyJhbGciOiJI"),
            Some("eyJhbGciOiJI".to_string())
        );
    }

    #[test]
    fn passes_through_non_bearer_scheme_unchanged() {
        // Non-Bearer schemes (e.g. Basic) flow through unchanged so the
        // downstream attestor chain rejects them with NotApplicable rather
        // than the server stripping a scheme it does not recognise.
        assert_eq!(
            parse_authorization_header("Basic dXNlcjpwYXNz"),
            Some("Basic dXNlcjpwYXNz".to_string())
        );
    }

    #[test]
    fn returns_none_for_empty_value() {
        assert_eq!(parse_authorization_header(""), None);
        assert_eq!(parse_authorization_header("   "), None);
    }

    #[test]
    fn returns_none_for_bearer_with_no_token() {
        // Just "Bearer" with no token after — strip leaves empty.
        assert_eq!(parse_authorization_header("Bearer "), None);
        assert_eq!(parse_authorization_header("bearer   "), None);
    }
}
