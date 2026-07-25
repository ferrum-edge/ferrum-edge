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
//!
//! Phase A wires up the gRPC service handlers and a `serve` entry point.
//! Listener bind / shutdown integration with the rest of the binary lands
//! in Phase C — Phase A keeps everything additive.

use async_trait::async_trait;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, warn};

use super::proto::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use super::proto::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest,
    X509svidResponse,
};
use crate::identity::attestation::{Attestor, PeerInfo, attest_chain};
use crate::identity::ca::{CertificateAuthority, IssuanceRequest};
use crate::identity::spiffe::TrustDomain;

const WORKLOAD_METADATA_KEY: &str = "workload.spiffe.io";
const WORKLOAD_METADATA_VAL: &str = "true";

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
        }
    }

    pub fn with_federated_trust_domains(mut self, trust_domains: Vec<TrustDomain>) -> Self {
        self.federated_trust_domains = trust_domains;
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

    /// Extract `PeerInfo` from a tonic request. Phase A pulls the bearer
    /// token from the `authorization` metadata header (Bearer scheme); peer
    /// creds are surfaced by future Phase C wiring on the listener side.
    fn peer_info_from_request<T>(req: &Request<T>) -> PeerInfo {
        let mut info = PeerInfo::default();
        if let Some(auth) = req.metadata().get("authorization")
            && let Ok(s) = auth.to_str()
        {
            info.bearer_token = parse_authorization_header(s);
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

    async fn wait_for_rotation_or_stream_close<T>(
        rx: &mut watch::Receiver<u64>,
        tx: &tokio::sync::mpsc::UnboundedSender<Result<T, Status>>,
    ) -> bool {
        tokio::select! {
            changed = rx.changed() => changed.is_ok(),
            _ = tx.closed() => false,
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
                Err(Status::permission_denied(format!(
                    "workload attestation failed: {e}"
                )))
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
        for td in federated_trust_domains {
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

    async fn build_federated_x509_bundle_map(
        ca: &Arc<dyn CertificateAuthority>,
        federated_trust_domains: &[TrustDomain],
    ) -> Result<HashMap<String, Vec<u8>>, crate::identity::ca::CaError> {
        let mut bundles = HashMap::new();
        for td in federated_trust_domains {
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

        let (tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send(Ok(initial));

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx).await {
                    return;
                }
                // Appendix A §6: validate the pending response — ensure the
                // client is still entitled before minting a replacement SVID.
                let identity = match Self::attest_with(&attestors, &peer).await {
                    Ok(id) => id,
                    Err(status) => {
                        let _ = tx.send(Err(status));
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
                        if tx.send(Ok(resp)).is_err() {
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

        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(
            out_rx,
        ))))
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

        let (tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send(Ok(initial));

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx).await {
                    return;
                }
                match Self::build_x509_bundles_response_static(&ca, &td, &federated_trust_domains)
                    .await
                {
                    Ok(resp) => {
                        if tx.send(Ok(resp)).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "rotation push failed for FetchX509Bundles stream");
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(
            out_rx,
        ))))
    }

    async fn fetch_jwtsvid(
        &self,
        request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Self::validate_workload_metadata(&request)?;
        // Phase A: JWT-SVID minting is intentionally unimplemented; later
        // phases plug into the CA's `jwt_authorities()`.
        Err(Status::unimplemented(
            "JWT-SVID issuance is deferred to a later mesh phase",
        ))
    }

    type FetchJWTBundlesStream =
        Pin<Box<dyn Stream<Item = Result<JwtBundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_jwt_bundles(
        &self,
        request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Self::validate_workload_metadata(&request)?;
        let initial = JwtBundlesResponse {
            bundles: Default::default(),
        };

        let mut rx = self.rotation_signal.subscribe();
        let (tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send(Ok(initial));

        tokio::spawn(async move {
            loop {
                if !Self::wait_for_rotation_or_stream_close(&mut rx, &tx).await {
                    return;
                }
                let resp = JwtBundlesResponse {
                    bundles: Default::default(),
                };
                if tx.send(Ok(resp)).is_err() {
                    return;
                }
            }
        });

        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(
            out_rx,
        ))))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Self::validate_workload_metadata(&request)?;
        Err(Status::unimplemented(
            "JWT-SVID validation is deferred to a later mesh phase",
        ))
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
