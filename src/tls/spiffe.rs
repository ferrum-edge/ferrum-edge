//! SPIFFE-aware rustls server / client configurations.
//!
//! These builders back the mesh data-plane mode's dynamic SPIFFE identity:
//! [`crate::modes::mesh`] wires them into the inbound server cert resolver,
//! the SPIFFE peer-cert verifier, and the outbound client config for
//! `FERRUM_MESH_CA_BACKEND`-issued (and file-gateway) SVIDs. They consume the
//! `Arc<ArcSwap<Option<SvidBundle>>>` slot produced by
//! [`crate::identity::workload_api::fetch_loop`] /
//! [`crate::identity::rotation`] so cert rotation is lock-free and atomic
//! from the rustls resolver's perspective — no listener restart, no per-
//! request cloning of the bundle.
//!
//! ## Verifier semantics
//!
//! - **Inbound**: trust anchors come from the SVID bundle's local + federated
//!   trust bundles. We require client certs (mesh = mTLS-everywhere). The
//!   verifier walks each peer cert and:
//!   1. Validates the chain against the bundle.
//!   2. Extracts the URI SAN, parses it as a SPIFFE ID, and confirms the
//!      trust domain matches the local or a federated bundle.
//!
//! - **Outbound**: trust anchors come from the bundle. When the caller pins
//!   `expected_peer`, the verifier additionally requires the peer's URI SAN
//!   to match exactly — this is how an outbound mesh hop can pin "I expect
//!   service /ns/foo/sa/bar". When the caller instead supplies
//!   `expected_trust_domain` (and NO `expected_peer`), the verifier requires the
//!   peer's SPIFFE id to be in exactly that trust domain — IN ADDITION to the
//!   existing federated-bundle-exists check, never instead of it. This scopes a
//!   cross-cluster east-west dial (where the SNI-passthrough gateway LB-picks the
//!   workload, so a pod identity cannot be pinned) to the TARGET's remote trust
//!   domain, so a misrouted/malicious path cannot complete TLS with a cert from a
//!   DIFFERENT federated trust domain. With both `None` the verifier keeps the
//!   any-federated behavior (HBONE operator targets).

use arc_swap::ArcSwap;
use rustls::client::WantsClientCert;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    UnixTime,
};
use rustls::server::{WantsServerCert, WebPkiClientVerifier};
use rustls::{ClientConfig, ServerConfig};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::identity::spiffe::{SpiffeId, extract_spiffe_id_from_parsed};
use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet, TrustDomain};
use crate::tls::CrlList;

/// Errors raised by the SPIFFE TLS builders.
///
/// `Clone` is derived so a mesh pool can rebuild a coalesced create failure for
/// the waiters that joined the same in-flight attempt (issue #5046). Every
/// payload is already an owned `String`, so the clone is exact.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SpiffeTlsError {
    #[error("SVID bundle has no leaf certificate")]
    NoLeafCert,
    #[error("SVID bundle is empty (rotation has not yet produced an SVID)")]
    NoSvid,
    #[error("rustls error: {0}")]
    Rustls(String),
    #[error("malformed certificate / key in SVID bundle: {0}")]
    BadKeyMaterial(String),
}

impl From<rustls::Error> for SpiffeTlsError {
    fn from(e: rustls::Error) -> Self {
        SpiffeTlsError::Rustls(e.to_string())
    }
}

/// Shared bundle slot type alias used by the rustls resolvers.
pub type SharedBundleSlot = Arc<ArcSwap<Option<SvidBundle>>>;

// ── Inbound (server-side) ─────────────────────────────────────────────────

/// Build a [`ServerConfig`] that:
/// - Presents the SVID currently in `bundle_slot` (re-read on every TLS handshake).
/// - Requires + verifies the peer's SVID against the trust bundle in the slot.
///
/// `peer_required` controls whether the resulting config rejects clients
/// that do not present a certificate (mesh-strict ⇒ `true`; permissive
/// modes use the lower-level [`build_spiffe_inbound_resolver`] directly).
///
/// `crls` is threaded into the inbound peer-chain verifier for end-entity
/// revocation; an empty list disables revocation checking (unchanged behavior).
pub fn build_spiffe_inbound_config(
    bundle_slot: SharedBundleSlot,
    peer_required: bool,
    crls: CrlList,
) -> Result<Arc<ServerConfig>, SpiffeTlsError> {
    let snapshot = bundle_slot.load_full();
    if snapshot.is_none() {
        return Err(SpiffeTlsError::NoSvid);
    }
    let provider = Arc::new(crate::fips::base_crypto_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SpiffeTlsError::Rustls(e.to_string()))?;

    let verifier = SpiffeClientCertVerifier::new(bundle_slot.clone(), peer_required, crls);
    let server_resolver = SpiffeServerCertResolver::new(bundle_slot);

    let builder: rustls::ConfigBuilder<ServerConfig, WantsServerCert> =
        builder.with_client_cert_verifier(Arc::new(verifier));
    let mut cfg = builder.with_cert_resolver(Arc::new(server_resolver));
    // SPIFFE inbound is currently used by HBONE listeners, which require
    // HTTP/2 over mTLS.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Build a [`rustls::server::danger::ClientCertVerifier`] that validates an
/// inbound peer's SVID: chain-to-bundle plus the peer SAN's trust domain
/// matching the local or a federated bundle in `bundle_slot`.
///
/// Unlike [`build_spiffe_inbound_config`], this returns only the *verifier*,
/// so a caller can attach it to a `ServerConfig` that still presents the
/// operator-supplied mesh server certificate and keeps its own ALPN, CRL,
/// early-data, and session-resumption settings. The mesh inbound listener
/// uses this so peer SPIFFE SANs are trust-domain-validated without changing
/// server-cert presentation or forcing h2-only ALPN on the shared
/// HBONE + mTLS-termination listener.
///
/// `peer_required` controls `client_auth_mandatory()`: `true` for STRICT
/// (reject clients with no cert), `false` for PERMISSIVE (a presented cert is
/// still trust-domain-validated, but a missing cert is allowed through so the
/// PERMISSIVE listener can also serve plaintext-identity-less peers).
///
/// `crls` is threaded into the per-trust-domain peer-chain verifiers so inbound
/// mesh peers are subject to end-entity revocation checks, matching the
/// operator-CA path. An empty `crls` leaves revocation checking off, preserving the
/// pre-CRL behavior exactly.
pub fn build_spiffe_client_cert_verifier(
    bundle_slot: SharedBundleSlot,
    peer_required: bool,
    crls: CrlList,
) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    Arc::new(SpiffeClientCertVerifier::new(
        bundle_slot,
        peer_required,
        crls,
    ))
}

// ── Outbound (client-side) ────────────────────────────────────────────────

/// Build a [`ClientConfig`] that:
/// - Presents the SVID currently in `bundle_slot`.
/// - Validates the server's SVID against the trust bundle.
/// - Optionally pins the peer SPIFFE ID (`expected_peer`).
/// - Optionally scopes verification to a single trust domain
///   (`expected_trust_domain`) when no peer is pinned.
/// - Advertises the given `alpn_protocols`.
/// - Applies `crls` to outbound peer-chain verification; an empty list leaves
///   revocation checking disabled, matching the no-CRL deployment behavior.
///
/// `expected_peer` and `expected_trust_domain` are mutually exclusive in
/// practice (the pinned-peer path already constrains the domain): when BOTH are
/// set, the peer pin takes precedence (it is strictly stronger) and the
/// trust-domain scope is redundant. The cross-cluster east-west dispatch passes
/// `expected_peer = None` + `expected_trust_domain = Some(target_td)`; the
/// in-cluster pinned path passes `Some(peer)` + `None`; other callers pass both
/// `None` (any-federated HBONE operator targets).
///
/// HBONE callers pass `["h2"]` (HTTP/2 CONNECT over mTLS). Sidecar outbound
/// SVID-mTLS-HTTP origination (to a peer's `:15006`, which negotiates
/// `["h2","http/1.1"]`) passes the protocol(s) the backend client speaks. The
/// verifier and client-cert resolver are transport-agnostic — only the ALPN and
/// the post-TLS framing differ between HBONE and plain mesh HTTP.
pub fn build_spiffe_outbound_config(
    bundle_slot: SharedBundleSlot,
    expected_peer: Option<SpiffeId>,
    expected_trust_domain: Option<TrustDomain>,
    alpn_protocols: Vec<Vec<u8>>,
    crls: CrlList,
) -> Result<Arc<ClientConfig>, SpiffeTlsError> {
    if bundle_slot.load_full().is_none() {
        return Err(SpiffeTlsError::NoSvid);
    }
    let provider = Arc::new(crate::fips::base_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SpiffeTlsError::Rustls(e.to_string()))?;

    let verifier = SpiffeServerCertVerifier::new(
        bundle_slot.clone(),
        expected_peer,
        expected_trust_domain,
        crls,
    );
    let resolver = SpiffeClientCertResolver::new(bundle_slot);

    let mut cfg: ClientConfig = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = alpn_protocols;
    Ok(Arc::new(cfg))
}

// ── Server cert resolver (presents our SVID) ──────────────────────────────

/// rustls server-side resolver that presents the SVID currently in the slot.
pub struct SpiffeServerCertResolver {
    slot: SharedBundleSlot,
    certified_key_cache: ArcSwap<Option<SpiffeCertifiedKeyCache>>,
}

impl SpiffeServerCertResolver {
    pub fn new(slot: SharedBundleSlot) -> Self {
        Self {
            slot,
            certified_key_cache: ArcSwap::new(Arc::new(None)),
        }
    }

    fn build_cert_key(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let snapshot = self.slot.load_full();
        cached_certified_key(&self.certified_key_cache, snapshot, "server")
    }

    pub fn validate_current(&self) -> Result<(), SpiffeTlsError> {
        let snapshot = self.slot.load_full();
        let bundle = snapshot.as_ref().as_ref().ok_or(SpiffeTlsError::NoSvid)?;
        certified_key_from_bundle(bundle)
            .map(|_| ())
            .map_err(SpiffeTlsError::BadKeyMaterial)
    }
}

impl std::fmt::Debug for SpiffeServerCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerCertResolver").finish()
    }
}

impl rustls::server::ResolvesServerCert for SpiffeServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.build_cert_key()
    }
}

// ── Client cert resolver (presents our SVID outbound) ────────────────────

pub struct SpiffeClientCertResolver {
    slot: SharedBundleSlot,
    certified_key_cache: ArcSwap<Option<SpiffeCertifiedKeyCache>>,
}

impl SpiffeClientCertResolver {
    pub fn new(slot: SharedBundleSlot) -> Self {
        Self {
            slot,
            certified_key_cache: ArcSwap::new(Arc::new(None)),
        }
    }
}

impl std::fmt::Debug for SpiffeClientCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertResolver").finish()
    }
}

impl rustls::client::ResolvesClientCert for SpiffeClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let snapshot = self.slot.load_full();
        cached_certified_key(&self.certified_key_cache, snapshot, "client")
    }

    fn has_certs(&self) -> bool {
        self.slot.load_full().is_some()
    }
}

// ── Verifiers ─────────────────────────────────────────────────────────────

/// Server-side verifier of inbound peer certificates.
struct SpiffeClientCertVerifier {
    slot: SharedBundleSlot,
    peer_required: bool,
    /// End-entity CRLs applied to inbound mesh peers. Empty when no CRL file is
    /// configured, in which case revocation checking is skipped (matching the
    /// operator-CA path).
    crls: CrlList,
    schemes: Vec<rustls::SignatureScheme>,
    peer_verifier_cache: ArcSwap<Option<SpiffePeerVerifierCache>>,
}

impl SpiffeClientCertVerifier {
    fn new(slot: SharedBundleSlot, peer_required: bool, crls: CrlList) -> Self {
        Self {
            slot,
            peer_required,
            crls,
            schemes: crate::fips::base_crypto_provider()
                .signature_verification_algorithms
                .supported_schemes(),
            peer_verifier_cache: ArcSwap::new(Arc::new(None)),
        }
    }
}

impl std::fmt::Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier").finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let snapshot = self.slot.load_full();
        snapshot.as_ref().as_ref().ok_or_else(|| {
            rustls::Error::General("SPIFFE inbound verifier: no SVID bundle yet".into())
        })?;
        verify_peer_against_cached_snapshot(
            &self.peer_verifier_cache,
            snapshot.clone(),
            end_entity,
            intermediates,
            None,
            // Inbound mesh verification is any-federated (a peer from any trust
            // domain with a bundle is accepted; fine-grained source checks are
            // AuthorizationPolicy's job) — no single-trust-domain scope.
            None,
            &self.crls,
        )
        .map(|_| rustls::server::danger::ClientCertVerified::assertion())
        .map_err(|e| rustls::Error::General(format!("SPIFFE inbound verify: {e}")))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &crate::fips::base_crypto_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &crate::fips::base_crypto_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.peer_required
    }

    fn offer_client_auth(&self) -> bool {
        true
    }
}

/// Client-side verifier of outbound server certificates.
struct SpiffeServerCertVerifier {
    slot: SharedBundleSlot,
    expected_peer: Option<SpiffeId>,
    /// When set (and `expected_peer` is `None`), the peer's SPIFFE id must be in
    /// exactly this trust domain — an ADDITIONAL constraint on top of the
    /// federated-bundle-exists check, never a replacement. Scopes cross-cluster
    /// east-west dials to the target's remote trust domain so a federated cert
    /// from a DIFFERENT trust domain cannot complete the handshake.
    expected_trust_domain: Option<TrustDomain>,
    /// End-entity CRLs applied to outbound mesh peers. Empty when no CRL file
    /// is configured, in which case revocation checking is skipped.
    crls: CrlList,
    schemes: Vec<rustls::SignatureScheme>,
    peer_verifier_cache: ArcSwap<Option<SpiffePeerVerifierCache>>,
}

impl SpiffeServerCertVerifier {
    fn new(
        slot: SharedBundleSlot,
        expected_peer: Option<SpiffeId>,
        expected_trust_domain: Option<TrustDomain>,
        crls: CrlList,
    ) -> Self {
        Self {
            slot,
            expected_peer,
            expected_trust_domain,
            crls,
            schemes: crate::fips::base_crypto_provider()
                .signature_verification_algorithms
                .supported_schemes(),
            peer_verifier_cache: ArcSwap::new(Arc::new(None)),
        }
    }
}

impl std::fmt::Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerCertVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let snapshot = self.slot.load_full();
        snapshot.as_ref().as_ref().ok_or_else(|| {
            rustls::Error::General("SPIFFE outbound verifier: no SVID bundle yet".into())
        })?;
        verify_peer_against_cached_snapshot(
            &self.peer_verifier_cache,
            snapshot.clone(),
            end_entity,
            intermediates,
            self.expected_peer.as_ref(),
            self.expected_trust_domain.as_ref(),
            &self.crls,
        )
        .map(|_| rustls::client::danger::ServerCertVerified::assertion())
        .map_err(|e| rustls::Error::General(format!("SPIFFE outbound verify: {e}")))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &crate::fips::base_crypto_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &crate::fips::base_crypto_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Build a [`rustls::sign::CertifiedKey`] from a `SvidBundle`, using the
/// build-selected provider's signing-key abstraction.
fn certified_key_from_bundle(bundle: &SvidBundle) -> Result<rustls::sign::CertifiedKey, String> {
    if bundle.cert_chain_der.is_empty() {
        return Err("SVID bundle has empty cert chain".to_string());
    }
    let chain: Vec<CertificateDer<'static>> = bundle
        .cert_chain_der
        .iter()
        .map(|d| CertificateDer::from(d.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        bundle.private_key_pkcs8_der.to_vec(),
    ));
    let signing_key = crate::fips::any_supported_signing_key(&key)
        .map_err(|e| format!("crypto provider sign init failed: {e}"))?;
    Ok(rustls::sign::CertifiedKey::new(chain, signing_key))
}

struct SpiffeCertifiedKeyCache {
    source: Arc<Option<SvidBundle>>,
    key: Arc<rustls::sign::CertifiedKey>,
}

fn cached_certified_key(
    cache_slot: &ArcSwap<Option<SpiffeCertifiedKeyCache>>,
    source: Arc<Option<SvidBundle>>,
    resolver_kind: &'static str,
) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let cached = cache_slot.load_full();
    if let Some(cache) = cached.as_ref()
        && Arc::ptr_eq(&cache.source, &source)
    {
        return Some(cache.key.clone());
    }

    let bundle = source.as_ref().as_ref()?;
    match certified_key_from_bundle(bundle) {
        Ok(key) => {
            let key = Arc::new(key);
            cache_slot.store(Arc::new(Some(SpiffeCertifiedKeyCache {
                source,
                key: key.clone(),
            })));
            Some(key)
        }
        Err(error) => {
            warn!(
                resolver = resolver_kind,
                error = %error,
                "SPIFFE resolver: failed to materialise CertifiedKey"
            );
            None
        }
    }
}

struct SpiffePeerVerifierCache {
    source: Arc<Option<SvidBundle>>,
    verifiers: PeerVerifierMap,
}

type PeerChainVerifier = Arc<dyn rustls::server::danger::ClientCertVerifier>;
type PeerVerifierMap = HashMap<TrustDomain, PeerChainVerifier>;

#[allow(clippy::too_many_arguments)]
fn verify_peer_against_cached_snapshot(
    cache_slot: &ArcSwap<Option<SpiffePeerVerifierCache>>,
    source: Arc<Option<SvidBundle>>,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    expected_peer: Option<&SpiffeId>,
    expected_trust_domain: Option<&TrustDomain>,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<SpiffeId, String> {
    let peer_id = extract_and_check_peer_spiffe_id(end_entity, expected_peer)?;
    // Scope to the target's trust domain when requested (cross-cluster east-west:
    // no pod pin possible across the SNI-passthrough gateway). This is an
    // ADDITIONAL constraint, evaluated before selecting the cached verifier —
    // it never removes the requirement that the admitted all-or-nothing trust
    // set contain the peer's domain. `expected_peer` (when set) is strictly
    // stronger, so the scope is skipped under a pin.
    if expected_peer.is_none()
        && let Some(td) = expected_trust_domain
        && peer_id.trust_domain() != td
    {
        return Err(format!(
            "peer SPIFFE ID '{}' is in trust domain '{}', expected trust domain '{}'",
            peer_id,
            peer_id.trust_domain(),
            td
        ));
    }
    // Select the admitted verifier snapshot first (including last-known-good
    // when a partial/invalid candidate is rejected). Membership and chain
    // verification must consult that same snapshot — never the rejected
    // candidate's declared trust set.
    let cache_snapshot = peer_verifier_cache(cache_slot, source, crls)?;
    let cache = cache_snapshot
        .as_ref()
        .as_ref()
        .ok_or_else(|| "SPIFFE verifier cache unexpectedly empty".to_string())?;
    // With atomic admission, a declared domain that has no usable roots
    // rejects the complete candidate at cache build time; a missing domain in
    // the selected snapshot is therefore the trust-domain membership failure
    // (not an unusable-root admission failure).
    let trust_bundles = &cache
        .source
        .as_ref()
        .as_ref()
        .ok_or_else(|| "SPIFFE verifier: no SVID bundle yet".to_string())?
        .trust_bundles;
    if trust_bundles.get(peer_id.trust_domain()).is_none() {
        return Err(format!(
            "no trust bundle for peer's trust domain '{}'",
            peer_id.trust_domain()
        ));
    }
    let verifier = cache
        .verifiers
        .get(peer_id.trust_domain())
        .ok_or_else(|| "trust bundle for peer's domain has no usable roots".to_string())?;

    verify_peer_chain(verifier.as_ref(), end_entity, intermediates)?;
    debug!(
        peer_id = %peer_id,
        "SPIFFE peer verified against cached trust bundle"
    );
    Ok(peer_id)
}

fn peer_verifier_cache(
    cache_slot: &ArcSwap<Option<SpiffePeerVerifierCache>>,
    source: Arc<Option<SvidBundle>>,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<Option<SpiffePeerVerifierCache>>, String> {
    let cached = cache_slot.load_full();
    if let Some(cache) = cached.as_ref()
        && Arc::ptr_eq(&cache.source, &source)
    {
        // The CRL set is fixed for the lifetime of a given verifier instance
        // (it owns its `crls` and passes the same slice on every handshake),
        // so an SVID-source match is sufficient to reuse the cached per-domain
        // verifiers without re-checking CRL identity.
        return Ok(cached);
    }

    match SpiffePeerVerifierCache::build(source, crls) {
        Ok(next) => {
            let next = Arc::new(Some(next));
            cache_slot.store(next.clone());
            Ok(next)
        }
        Err(error) if cached.is_some() => {
            warn!(
                error = %error,
                "SPIFFE verifier cache: candidate trust update rejected; keeping last-known-good set"
            );
            Ok(cached)
        }
        Err(error) => Err(error),
    }
}

impl SpiffePeerVerifierCache {
    fn build(
        source: Arc<Option<SvidBundle>>,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Self, String> {
        let bundle = source
            .as_ref()
            .as_ref()
            .ok_or_else(|| "SPIFFE verifier cache: no SVID bundle yet".to_string())?;
        let mut verifiers = HashMap::new();

        insert_trust_bundle_verifier(&mut verifiers, &bundle.trust_bundles.local, crls)?;
        for trust_bundle in bundle.trust_bundles.federated.values() {
            insert_trust_bundle_verifier(&mut verifiers, trust_bundle, crls)?;
        }

        Ok(Self { source, verifiers })
    }
}

/// Validate every X.509 trust domain as one candidate set.
///
/// Call reload/admission paths before publishing a new `SvidBundle` or trust
/// overlay. A single empty or unusable domain rejects the complete candidate.
pub(crate) fn validate_trust_bundle_set(trust_bundles: &TrustBundleSet) -> Result<(), String> {
    let mut verifiers = HashMap::new();
    insert_trust_bundle_verifier(&mut verifiers, &trust_bundles.local, &[])?;
    for trust_bundle in trust_bundles.federated.values() {
        insert_trust_bundle_verifier(&mut verifiers, trust_bundle, &[])?;
    }
    Ok(())
}

fn insert_trust_bundle_verifier(
    verifiers: &mut PeerVerifierMap,
    trust_bundle: &TrustBundle,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<(), String> {
    if verifiers.contains_key(&trust_bundle.trust_domain) {
        return Err(format!(
            "SPIFFE trust bundle declares trust domain '{}' more than once",
            trust_bundle.trust_domain
        ));
    }

    let verifier = build_peer_chain_verifier(trust_bundle, crls)?;
    verifiers.insert(trust_bundle.trust_domain.clone(), verifier);
    Ok(())
}

fn build_peer_chain_verifier(
    trust_bundle: &TrustBundle,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<PeerChainVerifier, String> {
    let display_source = format!("SPIFFE trust domain {}", trust_bundle.trust_domain);
    let roots = crate::tls::root_cert_store_from_certificates(
        trust_bundle
            .x509_authorities
            .iter()
            .cloned()
            .map(CertificateDer::from),
        "SPIFFE trust bundle",
        &display_source,
    )
    .map_err(|error| error.to_string())?;

    // SPIFFE peer verification is chain-only: the peer's identity is its
    // SPIFFE URI SAN, not a DNS / IP name. `WebPkiClientVerifier` performs
    // the chain-up-to-trust-anchor check without server-name matching, which
    // is the desired behavior for both inbound and outbound mesh peers.
    let mut builder = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(crate::fips::base_crypto_provider()),
    );
    // Mirror every other Ferrum surface: when CRLs are configured, the shared
    // policy enforces full-chain revocation and CRL validity windows for
    // inbound and outbound mesh peers. Empty CRLs leave revocation checking off
    // so behavior is unchanged for deployments without a CRL file.
    builder = crate::tls::crl_policy::apply_client_crl_policy(builder, crls);
    builder
        .build()
        .map_err(|e| format!("webpki verifier build failed: {e}"))
}

fn extract_and_check_peer_spiffe_id(
    end_entity: &CertificateDer<'_>,
    expected_peer: Option<&SpiffeId>,
) -> Result<SpiffeId, String> {
    use x509_parser::prelude::*;

    let (_, parsed_leaf) = X509Certificate::from_der(end_entity)
        .map_err(|e| format!("leaf cert parse failed: {e}"))?;

    let peer_id = extract_spiffe_id_from_parsed(&parsed_leaf)
        .map_err(|e| format!("peer cert lacks valid SPIFFE URI SAN: {e}"))?;

    if let Some(expected) = expected_peer
        && expected != &peer_id
    {
        return Err(format!(
            "peer SPIFFE ID '{}' does not match expected '{}'",
            peer_id, expected
        ));
    }

    Ok(peer_id)
}

fn verify_peer_chain(
    verifier: &dyn rustls::server::danger::ClientCertVerifier,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), String> {
    rustls::server::danger::ClientCertVerifier::verify_client_cert(
        verifier,
        end_entity,
        intermediates,
        UnixTime::now(),
    )
    .map(|_| ())
    .map_err(|e| format!("chain verify failed: {e}"))
}

/// Validate `end_entity + intermediates` against `bundle.trust_bundles`,
/// extract the SPIFFE ID, and (optionally) match it against `expected_peer`.
///
/// This uncached helper is retained for direct validation tests. Runtime
/// verifiers use [`verify_peer_against_cached_snapshot`] so live handshakes
/// rebuild chain verifiers only when the bundle slot rotates.
fn verify_peer_against_bundle(
    trust_bundles: &TrustBundleSet,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    expected_peer: Option<&SpiffeId>,
) -> Result<SpiffeId, String> {
    let peer_id = extract_and_check_peer_spiffe_id(end_entity, expected_peer)?;
    let bundle = trust_bundles.get(peer_id.trust_domain()).ok_or_else(|| {
        format!(
            "no trust bundle for peer's trust domain '{}'",
            peer_id.trust_domain()
        )
    })?;

    // The uncached path is test-only direct validation; it intentionally does
    // not apply CRLs (an empty slice leaves revocation checking off), preserving
    // its existing behavior. Inbound CRL enforcement flows through the cached
    // verifier path above.
    let verifier = build_peer_chain_verifier(bundle, &[])?;
    verify_peer_chain(verifier.as_ref(), end_entity, intermediates)?;
    debug!(
        peer_id = %peer_id,
        "SPIFFE peer verified against trust bundle"
    );
    Ok(peer_id)
}

// re-export the ConfigBuilder marker types so the build steps above compile
// without doc warnings on unused import lints.
#[allow(dead_code)]
fn _marker_imports(_x: WantsServerCert, _y: WantsClientCert) {}

#[cfg(test)]
mod tests {
    //! Inline tests for `verify_peer_against_bundle`. The function is private
    //! so these live alongside the implementation rather than in
    //! `tests/unit/`. The synthetic SVIDs are issued via `rcgen` so the tests
    //! are hermetic.
    //!
    //! Specifically covered:
    //! - URI-SAN-only SVID passes (no DNS SAN, no name match attempted).
    //! - URI-SAN + extra DNS SAN SVID passes (chain-only validation tolerates
    //!   the DNS SAN that some CAs emit).
    //! - `expected_peer` pin matches and rejects mismatches.
    //! - Wrong trust domain rejects (no trust anchor in the bundle).
    use super::*;
    use crate::identity::TrustBundle;
    use crate::identity::spiffe::{TrustDomain, spiffe_id_to_san};
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };

    /// Generate a self-signed root + (DER, PEM, key-PEM) tuple.
    fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{}-test-root", td.as_str()));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen");
        let cert = params.self_signed(&kp).expect("self-signed root");
        let der = cert.der().to_vec();
        let pem = cert.pem();
        let key_pem = kp.serialize_pem();
        (der, pem, key_pem)
    }

    /// Issue a leaf SVID under the given root with only a SPIFFE URI SAN
    /// (and optionally an extra DNS SAN, to exercise the path some CAs use).
    fn issue_leaf(
        spiffe_id: &SpiffeId,
        root_pem: &str,
        root_key_pem: &str,
        extra_dns_san: Option<&str>,
    ) -> Vec<u8> {
        let issuer_kp = KeyPair::from_pem(root_key_pem).expect("re-parse root key");
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(root_pem, issuer_kp).expect("issuer build");

        let mut params = CertificateParams::default();
        // SPIFFE recommends an empty subject; we follow that.
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(spiffe_id).expect("spiffe SAN"));
        if let Some(dns) = extra_dns_san {
            params.subject_alt_names.push(SanType::DnsName(
                Ia5String::try_from(dns.to_string()).unwrap(),
            ));
        }
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(3600);

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");
        let cert = params.signed_by(&leaf_kp, &issuer).expect("sign leaf");
        cert.der().to_vec()
    }

    fn issue_leaf_with_key(
        spiffe_id: &SpiffeId,
        root_pem: &str,
        root_key_pem: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let issuer_kp = KeyPair::from_pem(root_key_pem).expect("re-parse root key");
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(root_pem, issuer_kp).expect("issuer build");

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(spiffe_id).expect("spiffe SAN"));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(3600);

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");
        let cert = params.signed_by(&leaf_kp, &issuer).expect("sign leaf");
        (cert.der().to_vec(), leaf_kp.serialize_der())
    }

    fn bundle_for(td: TrustDomain, root_der: Vec<u8>) -> TrustBundleSet {
        TrustBundleSet::local_only(TrustBundle {
            trust_domain: td,
            x509_authorities: vec![root_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
    }

    fn svid_bundle_for(id: SpiffeId, trust_bundles: TrustBundleSet, leaf: Vec<u8>) -> SvidBundle {
        SvidBundle {
            spiffe_id: id,
            cert_chain_der: vec![leaf],
            private_key_pkcs8_der: Vec::new().into(),
            trust_bundles,
        }
    }

    fn svid_bundle_with_key(
        id: SpiffeId,
        trust_bundles: TrustBundleSet,
        leaf: Vec<u8>,
        key: Vec<u8>,
    ) -> SvidBundle {
        SvidBundle {
            spiffe_id: id,
            cert_chain_der: vec![leaf],
            private_key_pkcs8_der: key.into(),
            trust_bundles,
        }
    }

    /// An empty CRL list (`Arc<Vec<_>>`) — the no-revocation-checking default.
    fn empty_crls() -> CrlList {
        Arc::new(Vec::new())
    }

    #[test]
    fn certified_key_cache_reuses_until_svid_snapshot_changes() {
        let td = TrustDomain::new("cluster.local").unwrap();
        let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
        let id = SpiffeId::from_parts(&td, "ns/default/sa/gateway").unwrap();
        let trust_bundles = bundle_for(td, root_der);
        let (leaf, key) = issue_leaf_with_key(&id, &root_pem, &root_key_pem);
        let source = Arc::new(Some(svid_bundle_with_key(
            id.clone(),
            trust_bundles.clone(),
            leaf.clone(),
            key.clone(),
        )));
        let cache = ArcSwap::new(Arc::new(None));

        let first = cached_certified_key(&cache, source.clone(), "test").unwrap();
        let second = cached_certified_key(&cache, source.clone(), "test").unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "same ArcSwap snapshot should reuse CertifiedKey material"
        );

        let rotated_snapshot = Arc::new(Some(svid_bundle_with_key(id, trust_bundles, leaf, key)));
        let third = cached_certified_key(&cache, rotated_snapshot, "test").unwrap();

        assert!(
            !Arc::ptr_eq(&first, &third),
            "a new SVID snapshot pointer must rebuild CertifiedKey material"
        );
    }

    #[test]
    fn peer_verifier_cache_rejects_partial_trust_update_and_keeps_last_good() {
        let local_td = TrustDomain::new("cache.local").unwrap();
        let federated_td = TrustDomain::new("cache.federated").unwrap();
        let id = SpiffeId::from_parts(&local_td, "ns/default/sa/gateway").unwrap();
        let (root_der, root_pem, root_key_pem) = synthetic_root(&local_td);
        let leaf = issue_leaf(&id, &root_pem, &root_key_pem, None);
        let valid_source = Arc::new(Some(svid_bundle_for(
            id.clone(),
            bundle_for(local_td.clone(), root_der.clone()),
            leaf.clone(),
        )));
        let cache = ArcSwap::new(Arc::new(None));

        peer_verifier_cache(&cache, valid_source.clone(), &[])
            .expect("initial trust bundle must build");
        let last_good = cache.load_full();

        let mut partial = bundle_for(local_td, root_der);
        partial.federated.insert(
            federated_td.clone(),
            TrustBundle {
                trust_domain: federated_td,
                x509_authorities: vec![vec![1, 2, 3, 4]],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        );
        let rejected_source = Arc::new(Some(svid_bundle_for(id, partial, leaf)));
        let rejected_bundles = &rejected_source
            .as_ref()
            .as_ref()
            .expect("candidate SVID")
            .trust_bundles;
        let error = validate_trust_bundle_set(rejected_bundles)
            .expect_err("one unusable federated root must reject the complete update");
        let retained = peer_verifier_cache(&cache, rejected_source, &[])
            .expect("a failed reload with an existing cache must retain last-known-good");

        assert!(error.contains("certificate record #1"), "got: {error}");
        assert!(Arc::ptr_eq(&retained, &last_good));
        assert!(
            Arc::ptr_eq(&cache.load_full(), &last_good),
            "failed candidate must not replace the last-good verifier cache"
        );
    }

    #[test]
    fn rejected_candidate_lkg_membership_uses_retained_snapshot() {
        // After a rejected trust update, membership and chain verification must
        // both use the retained last-known-good snapshot — not the candidate
        // that failed admission.
        let local_td = TrustDomain::new("lkg.local").unwrap();
        let federated_td = TrustDomain::new("lkg.federated").unwrap();
        let only_in_candidate_td = TrustDomain::new("lkg.candidate-only").unwrap();
        let gateway_id = SpiffeId::from_parts(&local_td, "ns/default/sa/gateway").unwrap();
        let federated_peer = SpiffeId::from_parts(&federated_td, "ns/remote/sa/peer").unwrap();
        let candidate_only_peer = SpiffeId::from_parts(&only_in_candidate_td, "ns/x/sa/y").unwrap();

        let (local_root_der, local_root_pem, local_key_pem) = synthetic_root(&local_td);
        let (federated_root_der, federated_root_pem, federated_key_pem) =
            synthetic_root(&federated_td);
        let (_candidate_root_der, candidate_root_pem, candidate_key_pem) =
            synthetic_root(&only_in_candidate_td);
        let gateway_leaf = issue_leaf(&gateway_id, &local_root_pem, &local_key_pem, None);
        let federated_leaf = issue_leaf(
            &federated_peer,
            &federated_root_pem,
            &federated_key_pem,
            None,
        );
        let candidate_only_leaf = issue_leaf(
            &candidate_only_peer,
            &candidate_root_pem,
            &candidate_key_pem,
            None,
        );

        let mut admitted = bundle_for(local_td.clone(), local_root_der.clone());
        admitted.federated.insert(
            federated_td.clone(),
            TrustBundle {
                trust_domain: federated_td,
                x509_authorities: vec![federated_root_der],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        );
        let valid_source = Arc::new(Some(svid_bundle_for(
            gateway_id.clone(),
            admitted,
            gateway_leaf.clone(),
        )));
        let cache = ArcSwap::new(Arc::new(None));
        peer_verifier_cache(&cache, valid_source, &[])
            .expect("admitted multi-domain trust set must build");
        let last_good = cache.load_full();

        // Candidate drops the federated domain and corrupts the local root so
        // the complete update is rejected and LKG is retained.
        let rejected_drop = Arc::new(Some(svid_bundle_for(
            gateway_id.clone(),
            bundle_for(local_td.clone(), vec![1, 2, 3, 4]),
            gateway_leaf.clone(),
        )));
        let retained_after_drop = peer_verifier_cache(&cache, rejected_drop.clone(), &[])
            .expect("rejected candidate must keep last-known-good");
        assert!(Arc::ptr_eq(&retained_after_drop, &last_good));

        // Domain present only in LKG (removed by rejected candidate) must still
        // pass membership + chain verification against the retained snapshot.
        let still_trusted = verify_peer_against_cached_snapshot(
            &cache,
            rejected_drop,
            &CertificateDer::from(federated_leaf),
            &[],
            None,
            None,
            &[],
        )
        .expect("LKG-federated peer must remain trusted after rejected drop");
        assert_eq!(still_trusted.as_str(), federated_peer.as_str());
        assert!(Arc::ptr_eq(&cache.load_full(), &last_good));

        // Candidate declares an extra domain that LKG never admitted, but the
        // extra domain's authority is unusable so the whole candidate fails.
        let mut adds_unusable = bundle_for(local_td, local_root_der);
        adds_unusable.federated.insert(
            only_in_candidate_td.clone(),
            TrustBundle {
                trust_domain: only_in_candidate_td.clone(),
                x509_authorities: vec![vec![9, 9, 9, 9]],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        );
        let rejected_add = Arc::new(Some(svid_bundle_for(
            gateway_id,
            adds_unusable,
            gateway_leaf,
        )));
        let retained_after_add = peer_verifier_cache(&cache, rejected_add.clone(), &[])
            .expect("rejected candidate must keep last-known-good");
        assert!(Arc::ptr_eq(&retained_after_add, &last_good));

        // Membership must deny against the retained snapshot with the unknown-
        // domain diagnostic — not pass candidate membership then fail with
        // "no usable roots" against LKG.
        let err = verify_peer_against_cached_snapshot(
            &cache,
            rejected_add,
            &CertificateDer::from(candidate_only_leaf),
            &[],
            None,
            None,
            &[],
        )
        .expect_err("candidate-only domain must not pass LKG membership");
        assert!(
            err.contains(&format!(
                "no trust bundle for peer's trust domain '{}'",
                only_in_candidate_td
            )),
            "expected unknown-domain membership error, got: {err}"
        );
        assert!(
            !err.contains("no usable roots"),
            "candidate-only domain must not surface the unusable-roots path: {err}"
        );
        assert!(Arc::ptr_eq(&cache.load_full(), &last_good));
    }

    /// Issue a leaf SVID under `root` with a known serial so a CRL can revoke
    /// it by serial. Mirrors [`issue_leaf`] otherwise.
    fn issue_leaf_with_serial(
        spiffe_id: &SpiffeId,
        root_pem: &str,
        root_key_pem: &str,
        serial: &rcgen::SerialNumber,
    ) -> Vec<u8> {
        let issuer_kp = KeyPair::from_pem(root_key_pem).expect("re-parse root key");
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(root_pem, issuer_kp).expect("issuer build");

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(spiffe_id).expect("spiffe SAN"));
        params.serial_number = Some(serial.clone());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(3600);

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");
        let cert = params.signed_by(&leaf_kp, &issuer).expect("sign leaf");
        cert.der().to_vec()
    }

    /// Build a DER CRL signed by `root` revoking `serial`.
    fn build_crl(root_pem: &str, root_key_pem: &str, serial: rcgen::SerialNumber) -> CrlList {
        use rcgen::{
            CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
        };
        let issuer_kp = KeyPair::from_pem(root_key_pem).expect("re-parse root key");
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(root_pem, issuer_kp).expect("issuer build");
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: serial,
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl_pem = params
            .signed_by(&issuer)
            .expect("sign CRL")
            .pem()
            .expect("CRL pem");
        let crls: Vec<CertificateRevocationListDer<'static>> =
            rustls_pemfile::crls(&mut crl_pem.as_bytes())
                .filter_map(|r| r.ok())
                .collect();
        assert!(!crls.is_empty(), "should parse CRL from PEM");
        Arc::new(crls)
    }

    #[test]
    fn verifies_uri_san_only_svid() {
        let td = TrustDomain::new("td.verify-test").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        let extracted = result.expect("URI-SAN-only SVID should pass verification");
        assert_eq!(extracted.as_str(), id.as_str());
    }

    #[test]
    fn verifies_svid_with_extra_dns_san() {
        // Some CAs emit SPIFFE SVIDs with both a URI SAN and a DNS SAN. The
        // chain-only verifier must tolerate this — the DNS SAN is irrelevant
        // to peer identity in mesh mode.
        let td = TrustDomain::new("td.dns-san").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, Some("foo.example.com"));
        let bundles = bundle_for(td, root_der);

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        let extracted = result.expect("URI+DNS SAN SVID should still verify");
        assert_eq!(extracted.as_str(), id.as_str());
    }

    #[test]
    fn pin_match_passes() {
        let td = TrustDomain::new("td.pin-match").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/svc/sa/a").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result =
            verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], Some(&id));
        assert!(result.is_ok());
    }

    #[test]
    fn pin_mismatch_rejects() {
        let td = TrustDomain::new("td.pin-mismatch").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/svc/sa/a").unwrap();
        let other = SpiffeId::from_parts(&td, "ns/svc/sa/b").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result =
            verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], Some(&other));
        let err = result.expect_err("pin mismatch must reject");
        assert!(err.contains("does not match expected"));
    }

    #[test]
    fn rejects_unknown_trust_domain() {
        // Bundle for `td.known` only. Leaf is in `td.foreign` with its own
        // root. No cross-trust — must reject.
        let known_td = TrustDomain::new("td.known").unwrap();
        let foreign_td = TrustDomain::new("td.foreign").unwrap();
        let foreign_id = SpiffeId::from_parts(&foreign_td, "ns/x/sa/y").unwrap();
        let (foreign_root_der, foreign_root_pem, foreign_key_pem) = synthetic_root(&foreign_td);
        let leaf = issue_leaf(&foreign_id, &foreign_root_pem, &foreign_key_pem, None);

        let (known_root_der, _, _) = synthetic_root(&known_td);
        let bundles = bundle_for(known_td, known_root_der);
        // Pretend we don't even have the foreign root.
        let _ = foreign_root_der;

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn peer_verifier_cache_reuses_snapshot_and_rebuilds_after_rotation() {
        let td = TrustDomain::new("td.cache-rotation").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der_a, root_pem_a, key_pem_a) = synthetic_root(&td);
        let leaf_a = issue_leaf(&id, &root_pem_a, &key_pem_a, None);
        let initial = Arc::new(Some(svid_bundle_for(
            id.clone(),
            bundle_for(td.clone(), root_der_a),
            leaf_a.clone(),
        )));
        let slot = Arc::new(ArcSwap::new(initial.clone()));
        let verifier = SpiffeClientCertVerifier::new(slot.clone(), true, empty_crls());

        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            &verifier,
            &CertificateDer::from(leaf_a.clone()),
            &[],
            UnixTime::now(),
        )
        .expect("initial leaf verifies");
        let cache_a = verifier.peer_verifier_cache.load_full();
        let cache_a_inner = cache_a
            .as_ref()
            .as_ref()
            .expect("initial verification should build cache");
        assert!(Arc::ptr_eq(&cache_a_inner.source, &initial));
        assert_eq!(cache_a_inner.verifiers.len(), 1);

        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            &verifier,
            &CertificateDer::from(leaf_a),
            &[],
            UnixTime::now(),
        )
        .expect("same snapshot still verifies");
        let cache_a_again = verifier.peer_verifier_cache.load_full();
        assert!(Arc::ptr_eq(&cache_a, &cache_a_again));

        let (root_der_b, root_pem_b, key_pem_b) = synthetic_root(&td);
        let leaf_b = issue_leaf(&id, &root_pem_b, &key_pem_b, None);
        let rotated = Arc::new(Some(svid_bundle_for(
            id,
            bundle_for(td, root_der_b),
            leaf_b.clone(),
        )));
        slot.store(rotated.clone());

        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            &verifier,
            &CertificateDer::from(leaf_b),
            &[],
            UnixTime::now(),
        )
        .expect("rotated bundle verifies");
        let cache_b = verifier.peer_verifier_cache.load_full();
        let cache_b_inner = cache_b
            .as_ref()
            .as_ref()
            .expect("rotated verification should rebuild cache");
        assert!(!Arc::ptr_eq(&cache_a, &cache_b));
        assert!(Arc::ptr_eq(&cache_b_inner.source, &rotated));
        assert_eq!(cache_b_inner.verifiers.len(), 1);
    }

    #[test]
    fn public_client_cert_verifier_validates_trust_domain() {
        // `build_spiffe_client_cert_verifier` is the entry point the mesh
        // inbound listener uses. It must reject a peer whose trust domain has
        // no bundle (the gap PR-2b closes) and accept one that does.
        let td = TrustDomain::new("td.inbound-verify").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let slot: SharedBundleSlot = Arc::new(ArcSwap::new(Arc::new(Some(svid_bundle_for(
            id,
            bundle_for(td, root_der),
            leaf.clone(),
        )))));

        let verifier = build_spiffe_client_cert_verifier(slot, true, empty_crls());
        // Known trust domain + valid chain → accepted.
        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            verifier.as_ref(),
            &CertificateDer::from(leaf),
            &[],
            UnixTime::now(),
        )
        .expect("peer in a known trust domain should verify");

        // A peer from a foreign trust domain (its own root, not in the slot)
        // must be rejected even though its chain is internally valid.
        let foreign_td = TrustDomain::new("td.foreign-inbound").unwrap();
        let foreign_id = SpiffeId::from_parts(&foreign_td, "ns/x/sa/y").unwrap();
        let (_foreign_root_der, foreign_root_pem, foreign_key_pem) = synthetic_root(&foreign_td);
        let foreign_leaf = issue_leaf(&foreign_id, &foreign_root_pem, &foreign_key_pem, None);
        let err = rustls::server::danger::ClientCertVerifier::verify_client_cert(
            verifier.as_ref(),
            &CertificateDer::from(foreign_leaf),
            &[],
            UnixTime::now(),
        )
        .expect_err("peer from an untrusted trust domain must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("trust domain") || msg.contains("trust bundle"),
            "rejection should cite the missing trust domain, got: {msg}"
        );
    }

    #[test]
    fn public_client_cert_verifier_permissive_does_not_require_cert() {
        // PERMISSIVE builds the verifier with `peer_required = false` so a peer
        // that offers no cert is still admitted (rustls won't invoke
        // verify_client_cert), while an offered cert is still validated.
        let td = TrustDomain::new("td.permissive").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let slot: SharedBundleSlot = Arc::new(ArcSwap::new(Arc::new(Some(svid_bundle_for(
            id,
            bundle_for(td, root_der),
            leaf,
        )))));

        let required = build_spiffe_client_cert_verifier(slot.clone(), true, empty_crls());
        assert!(
            rustls::server::danger::ClientCertVerifier::client_auth_mandatory(required.as_ref()),
            "STRICT verifier must mandate client auth"
        );
        let permissive = build_spiffe_client_cert_verifier(slot, false, empty_crls());
        assert!(
            !rustls::server::danger::ClientCertVerifier::client_auth_mandatory(permissive.as_ref()),
            "PERMISSIVE verifier must not mandate client auth"
        );
        assert!(
            rustls::server::danger::ClientCertVerifier::offer_client_auth(permissive.as_ref()),
            "PERMISSIVE verifier must still offer/request client auth so identity is recorded when present"
        );
    }

    #[test]
    fn inbound_verifier_rejects_revoked_peer_when_crls_configured() {
        // PR-2b CRL parity: with a CRL revoking the peer's serial, the inbound
        // SPIFFE verifier must reject the peer even though its chain and trust
        // domain are otherwise valid. Without the CRL the same peer verifies,
        // proving the rejection is the revocation check and not some other
        // failure (i.e. an empty CRL list preserves pre-CRL behavior).
        let td = TrustDomain::new("td.crl-revoke").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let serial = rcgen::SerialNumber::from_slice(&(1u8..=20).collect::<Vec<u8>>());
        let leaf = issue_leaf_with_serial(&id, &root_pem, &key_pem, &serial);

        let slot: SharedBundleSlot = Arc::new(ArcSwap::new(Arc::new(Some(svid_bundle_for(
            id,
            bundle_for(td, root_der),
            leaf.clone(),
        )))));

        // Sanity: without CRLs, the leaf verifies.
        let no_crl = build_spiffe_client_cert_verifier(slot.clone(), true, empty_crls());
        rustls::server::danger::ClientCertVerifier::verify_client_cert(
            no_crl.as_ref(),
            &CertificateDer::from(leaf.clone()),
            &[],
            UnixTime::now(),
        )
        .expect("non-revoked peer should verify without a CRL");

        // With a CRL revoking the leaf's serial, the verifier must reject it.
        let crls = build_crl(&root_pem, &key_pem, serial);
        let revoking = build_spiffe_client_cert_verifier(slot, true, crls);
        let err = rustls::server::danger::ClientCertVerifier::verify_client_cert(
            revoking.as_ref(),
            &CertificateDer::from(leaf),
            &[],
            UnixTime::now(),
        )
        .expect_err("revoked peer must be rejected when a CRL is configured");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("revok"),
            "rejection should cite revocation, got: {msg}"
        );
    }

    /// Build a `TrustBundleSet` whose LOCAL domain is `local` (root `local_der`)
    /// and which FEDERATES `federated` (root `federated_der`) — both trust
    /// domains have a usable bundle, so a cert in EITHER chains successfully
    /// under the any-federated rule.
    fn bundle_with_federated(
        local: TrustDomain,
        local_der: Vec<u8>,
        federated: TrustDomain,
        federated_der: Vec<u8>,
    ) -> TrustBundleSet {
        let mut set = TrustBundleSet::local_only(TrustBundle {
            trust_domain: local,
            x509_authorities: vec![local_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        });
        set.federated.insert(
            federated.clone(),
            TrustBundle {
                trust_domain: federated,
                x509_authorities: vec![federated_der],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        );
        set
    }

    #[test]
    fn outbound_trust_domain_scope_rejects_other_federated_domain() {
        // SECURITY (cross-cluster east-west, Codex round-1 finding #4): a server
        // SVID in trust domain C must be REJECTED when the dial scoped
        // verification to trust domain B (`expected_trust_domain = Some(B)`),
        // EVEN THOUGH C is a FEDERATED/trusted domain — so a misrouted/malicious
        // east-west path cannot complete TLS with a cert from a different trusted
        // domain. The same cert is ACCEPTED when the scope is C.
        let td_b = TrustDomain::new("cluster-b.local").unwrap();
        let td_c = TrustDomain::new("cluster-c.local").unwrap();
        let (root_b_der, _root_b_pem, _root_b_key) = synthetic_root(&td_b);
        let (root_c_der, root_c_pem, root_c_key) = synthetic_root(&td_c);

        // The server presents a VALID SVID in trust domain C, signed by C's root.
        let server_c = SpiffeId::from_parts(&td_c, "ns/default/sa/svc-c").unwrap();
        let (server_leaf, server_key) = issue_leaf_with_key(&server_c, &root_c_pem, &root_c_key);

        // The client's bundle is local B + federated C (both trusted).
        let trust_bundles =
            bundle_with_federated(td_b.clone(), root_b_der, td_c.clone(), root_c_der);
        // A client SVID in B so the slot is populated (the slot is the client's
        // own identity bundle; only `trust_bundles` matters for server verify).
        let client_b = SpiffeId::from_parts(&td_b, "ns/default/sa/client").unwrap();
        let slot: SharedBundleSlot = Arc::new(ArcSwap::new(Arc::new(Some(svid_bundle_with_key(
            client_b,
            trust_bundles,
            server_leaf.clone(),
            server_key,
        )))));
        let server_name = ServerName::try_from("svc-b.default.svc.cluster.local").unwrap();

        // Scoped to B: the C-domain server cert must be REJECTED even though C is
        // federated. expected_peer = None (trust-domain-only, like cross-cluster).
        let scoped_b = SpiffeServerCertVerifier::new(
            slot.clone(),
            None,
            Some(td_b.clone()),
            Arc::new(Vec::new()),
        );
        let err = rustls::client::danger::ServerCertVerifier::verify_server_cert(
            &scoped_b,
            &CertificateDer::from(server_leaf.clone()),
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .expect_err("a federated-but-wrong-trust-domain server cert must be rejected when scoped");
        let msg = format!("{err}");
        assert!(
            msg.contains("expected trust domain") && msg.contains("cluster-b.local"),
            "rejection should cite the expected trust domain, got: {msg}"
        );

        // Scoped to C (the cert's actual domain): ACCEPTED.
        let scoped_c =
            SpiffeServerCertVerifier::new(slot.clone(), None, Some(td_c), Arc::new(Vec::new()));
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            &scoped_c,
            &CertificateDer::from(server_leaf.clone()),
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .expect("a server cert in the scoped trust domain must verify");

        // No scope (any-federated, both None): the same C cert ACCEPTED — proves
        // the rejection above is the scope and not some other chain failure.
        let unscoped = SpiffeServerCertVerifier::new(slot, None, None, Arc::new(Vec::new()));
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            &unscoped,
            &CertificateDer::from(server_leaf),
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .expect("any-federated verification (no scope) must still accept a federated cert");
    }
}
