//! Mesh SPIFFE identity plumbing conformance (GA contract row
//! `mesh.identity.spire_svid_issuance`).
//!
//! Pins the *decision* semantics of the SPIRE-backed identity path — the
//! plumbing every mesh mTLS hop rides — hermetically (rcgen-minted certs, no
//! network, no SPIRE):
//!
//! 1. SPIFFE ID parsing + the Istio `ns/<ns>/sa/<sa>` convention that authz
//!    principal matching and workload identity attribution are built on.
//! 2. X.509 URI-SAN SVID identity extraction, including the SVID spec's
//!    single-URI-SAN rule.
//! 3. The inbound peer-SVID verification decision: chain-to-bundle plus
//!    trust-domain membership (unknown domains and forged issuers rejected).
//! 4. The SVID slot backing inbound server identity fails closed: no SVID in
//!    the slot ⇒ no inbound mTLS server config (never a plaintext fallback).
//! 5. `FERRUM_MESH_CA_BACKEND=spire_agent` backend selection — the env
//!    contract the live fixture (`tests/k8s/mesh_e2e_sidecar/manifests.yaml`)
//!    runs on.
//!
//! The *runtime* half of this row (real SPIRE-issued SVIDs carrying real
//! captured traffic) is live-gated by `sidecar.spire.workload_entries` and
//! `sidecar.peer_auth.strict_mtls_authenticated` in the `mesh-e2e-sidecar`
//! suite.

use std::sync::Arc;

use arc_swap::ArcSwap;
use ferrum_edge::identity::ca::CaBackend;
use ferrum_edge::identity::spiffe::{
    SpiffeId, TrustDomain, extract_spiffe_id_from_cert, spiffe_id_to_san, try_extract_spiffe_id,
};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::tls::CrlList;
use ferrum_edge::tls::spiffe::{
    SpiffeTlsError, build_spiffe_client_cert_verifier, build_spiffe_inbound_config,
};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "mesh_spiffe_identity";

fn td(value: &str) -> TrustDomain {
    TrustDomain::new(value).expect("test trust domain")
}

fn empty_crls() -> CrlList {
    Arc::new(Vec::new())
}

/// Self-signed CA root for a synthetic trust domain. Returns
/// `(root_der, root_pem, root_key_pem)` — the PEM pair feeds `issue_svid`.
fn synthetic_root(name: &str) -> (Vec<u8>, String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{name}-conformance-root"));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let cert = params.self_signed(&key).expect("root cert");
    (cert.der().to_vec(), cert.pem(), key.serialize_pem())
}

/// Issue a leaf SVID (URI-SAN = the SPIFFE ID) signed by the given root.
/// Returns `(leaf_der, leaf_key_pkcs8_der)`.
fn issue_svid(spiffe_id: &SpiffeId, root_pem: &str, root_key_pem: &str) -> (Vec<u8>, Vec<u8>) {
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(spiffe_id_to_san(spiffe_id).expect("spiffe san"));
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
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::hours(1);

    let cert = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (cert.der().to_vec(), leaf_key.serialize_der())
}

/// Wrap a gateway SVID + its trust-domain root into the slot shape the
/// inbound listener consumes (`Arc<ArcSwap<Option<SvidBundle>>>`).
fn svid_slot(
    id: SpiffeId,
    leaf_der: Vec<u8>,
    key_der: Vec<u8>,
    root_der: Vec<u8>,
) -> SharedSvidBundle {
    let bundle = SvidBundle {
        spiffe_id: id.clone(),
        cert_chain_der: vec![leaf_der],
        private_key_pkcs8_der: key_der.into(),
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain: id.trust_domain().clone(),
            x509_authorities: vec![root_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }),
    };
    Arc::new(ArcSwap::new(Arc::new(Some(bundle))))
}

/// SPIFFE ID parsing and the Istio `ns/<ns>/sa/<sa>` convention. This is the
/// vocabulary authz principal matching, workload attribution, and SPIRE entry
/// registration all share — a parse relaxation (accepting query strings,
/// traversal segments, or a non-lowercase scheme) would widen every identity
/// check built on top.
#[test]
fn spiffe_id_parse_and_istio_convention() {
    register_feature!(
        category = CATEGORY,
        feature = "SPIFFE ID parse + Istio ns/sa convention",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "spiffe://<td>/ns/<ns>/sa/<sa> parses with namespace()/service_account() views; \
                 query/fragment/trailing-slash/dot-segment/uppercase-scheme forms are rejected. \
                 Live-gated via sidecar.spire.workload_entries in mesh-e2e-sidecar.",
    );
    let id = SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/svc").expect("valid id");
    assert_eq!(id.trust_domain().as_str(), "cluster.local");
    assert_eq!(id.namespace(), Some("ferrum"));
    assert_eq!(id.service_account(), Some("svc"));

    let from_parts =
        SpiffeId::from_parts(&td("cluster.local"), "/ns/ferrum/sa/svc").expect("from_parts");
    assert_eq!(from_parts, id, "from_parts must normalize to the URI form");

    // Root SPIFFE ID (trust domain itself): no ns/sa attribution.
    let root = SpiffeId::new("spiffe://cluster.local").expect("root id");
    assert_eq!(root.namespace(), None);
    assert_eq!(root.service_account(), None);

    for malformed in [
        "",
        "SPIFFE://cluster.local/ns/a/sa/b", // scheme must be lowercase
        "spiffe://cluster.local/ns/a?x=1",  // no query strings
        "spiffe://cluster.local/ns/a#frag", // no fragments
        "spiffe://cluster.local/ns/a/",     // no trailing slash
        "spiffe://cluster.local/ns/../sa/b", // no traversal segments
        "spiffe://cluster.local//ns/a/sa/b", // no empty segments
        "https://cluster.local/ns/a/sa/b",  // wrong scheme
    ] {
        assert!(
            SpiffeId::new(malformed).is_err(),
            "malformed SPIFFE ID must be rejected: {malformed:?}"
        );
    }
}

/// X.509 URI-SAN SVID identity extraction: the exact SPIFFE ID minted into a
/// leaf's URI SAN comes back out, a non-mesh cert yields `None` (not an
/// error), and a leaf carrying more than one URI SAN is rejected per the
/// X.509-SVID spec's single-URI-SAN rule (so a trusted-but-misconfigured leaf
/// cannot be attributed differently here than by a peer mesh implementation).
#[test]
fn spiffe_uri_san_extraction() {
    register_feature!(
        category = CATEGORY,
        feature = "X.509 URI-SAN SVID identity extraction",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "URI-SAN round trip is byte-exact; non-mesh certs extract None; multiple URI \
                 SANs are rejected (SPIFFE X.509-SVID single-URI-SAN rule).",
    );
    let identity = SpiffeId::new("spiffe://mesh-conf.test/ns/ferrum/sa/gateway").expect("id");

    let self_signed = |sans: Vec<SanType>| -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        params.self_signed(&key).expect("cert").der().to_vec()
    };

    // Round trip: the SAN encodes the SPIFFE ID byte-identically.
    let svid_der = self_signed(vec![spiffe_id_to_san(&identity).expect("san")]);
    let extracted = extract_spiffe_id_from_cert(&svid_der).expect("extraction succeeds");
    assert_eq!(extracted, identity);

    // A non-mesh cert (DNS SAN only) is `None`, not an error: the common
    // non-mesh deployment case must not fail identity-optional paths.
    let dns_der = self_signed(vec![SanType::DnsName(
        Ia5String::try_from("app.example.com".to_string()).expect("ia5"),
    )]);
    assert_eq!(
        try_extract_spiffe_id(&dns_der).expect("no hard error"),
        None
    );

    // Two URI SANs (one SPIFFE + one other) violate X.509-SVID §4.1: reject
    // rather than silently picking the first SPIFFE URI.
    let double_uri_der = self_signed(vec![
        spiffe_id_to_san(&identity).expect("san"),
        SanType::URI(Ia5String::try_from("https://not-an-svid.example".to_string()).expect("ia5")),
    ]);
    assert!(
        extract_spiffe_id_from_cert(&double_uri_der).is_err(),
        "an SVID with more than one URI SAN must be rejected"
    );
}

/// The inbound peer-SVID verification decision, exactly as the mesh inbound
/// listener consumes it (`build_spiffe_client_cert_verifier`):
///   - a peer SVID chained to the local trust bundle verifies;
///   - a peer from a trust domain with NO bundle is rejected (membership
///     check) even though its cert is otherwise well-formed;
///   - a forged peer — correct local trust domain in the SAN but issued by an
///     untrusted root — is rejected (chain check);
///   - a peer cert with no SPIFFE SAN is rejected;
///   - STRICT posture (`peer_required = true`) makes client auth mandatory,
///     PERMISSIVE (`false`) does not.
#[test]
fn inbound_peer_svid_verification_decision() {
    register_feature!(
        category = CATEGORY,
        feature = "inbound peer SVID verification decision",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Chain-to-bundle + trust-domain membership: unknown-domain, forged-issuer, and \
                 SAN-less peers are rejected; STRICT makes client auth mandatory. Live-gated via \
                 sidecar.peer_auth.strict_mtls_authenticated in mesh-e2e-sidecar.",
    );
    let local_td = td("mesh-conf.test");
    let (root_der, root_pem, root_key_pem) = synthetic_root(local_td.as_str());
    let gateway_id = SpiffeId::from_parts(&local_td, "ns/ferrum/sa/gateway").expect("gateway id");
    let (gw_leaf, gw_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let slot = svid_slot(gateway_id, gw_leaf, gw_key, root_der);

    let strict = build_spiffe_client_cert_verifier(slot.clone(), true, empty_crls());
    assert!(
        strict.client_auth_mandatory(),
        "STRICT (peer_required) must make client auth mandatory"
    );
    let permissive = build_spiffe_client_cert_verifier(slot, false, empty_crls());
    assert!(
        !permissive.client_auth_mandatory(),
        "PERMISSIVE must not make client auth mandatory"
    );

    let verify = |leaf_der: Vec<u8>| {
        strict
            .verify_client_cert(&CertificateDer::from(leaf_der), &[], UnixTime::now())
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    // Positive: same-trust-domain peer issued by the trusted root.
    let peer_id = SpiffeId::from_parts(&local_td, "ns/ferrum/sa/client").expect("peer id");
    let (peer_leaf, _) = issue_svid(&peer_id, &root_pem, &root_key_pem);
    verify(peer_leaf).expect("trusted same-domain peer SVID must verify");

    // Unknown trust domain: no bundle for it — must fail on membership.
    let (_, other_root_pem, other_root_key_pem) = synthetic_root("other.test");
    let foreign_id = SpiffeId::new("spiffe://other.test/ns/x/sa/y").expect("foreign id");
    let (foreign_leaf, _) = issue_svid(&foreign_id, &other_root_pem, &other_root_key_pem);
    let err = verify(foreign_leaf).expect_err("unknown-trust-domain peer must be rejected");
    assert!(
        err.contains("no trust bundle"),
        "rejection must be the trust-domain membership check, got: {err}"
    );

    // Forged issuer: the SAN claims the LOCAL trust domain but the chain was
    // signed by an untrusted root — chain validation must reject it.
    let impostor_id = SpiffeId::from_parts(&local_td, "ns/ferrum/sa/impostor").expect("id");
    let (forged_leaf, _) = issue_svid(&impostor_id, &other_root_pem, &other_root_key_pem);
    verify(forged_leaf).expect_err("forged-issuer peer SVID must be rejected");

    // No SPIFFE SAN at all: identity extraction fails before any chain check.
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let san_less = params.self_signed(&key).expect("cert").der().to_vec();
    verify(san_less).expect_err("a peer cert without a SPIFFE SAN must be rejected");
}

/// The gateway SVID slot backs inbound server identity and fails CLOSED: with
/// no SVID in the slot there is no inbound mTLS server config to build — the
/// mesh can never fall back to an identity-less inbound listener. With a
/// populated slot the config builds (the resolver presents the slot's SVID on
/// every handshake, which is what makes rotation atomic).
#[test]
fn svid_slot_fail_closed_inbound_identity() {
    register_feature!(
        category = CATEGORY,
        feature = "gateway SVID slot fail-closed inbound identity",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "build_spiffe_inbound_config on an empty SVID slot is SpiffeTlsError::NoSvid \
                 (never a plaintext/identity-less fallback); a populated slot builds the \
                 mTLS-required server config.",
    );
    let empty_slot: SharedSvidBundle = Arc::new(ArcSwap::new(Arc::new(None)));
    assert!(
        matches!(
            build_spiffe_inbound_config(empty_slot, true, empty_crls()),
            Err(SpiffeTlsError::NoSvid)
        ),
        "an empty SVID slot must fail closed (NoSvid), not build a serverless/plaintext config"
    );

    let local_td = td("mesh-conf.test");
    let (root_der, root_pem, root_key_pem) = synthetic_root(local_td.as_str());
    let gateway_id = SpiffeId::from_parts(&local_td, "ns/ferrum/sa/gateway").expect("gateway id");
    let (leaf, key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let slot = svid_slot(gateway_id, leaf, key, root_der);
    assert!(
        build_spiffe_inbound_config(slot, true, empty_crls()).is_ok(),
        "a populated SVID slot must yield an inbound mTLS server config"
    );
}

/// `FERRUM_MESH_CA_BACKEND` selection: the `spire_agent` token (and its
/// aliases) selects the SPIRE Agent Workload API backend, unknown tokens are
/// startup errors (never silently `None`), and empty/`none` disables the CA.
/// This is the env contract the live fixture pods run on.
#[test]
fn ca_backend_spire_agent_selection() {
    register_feature!(
        category = CATEGORY,
        feature = "FERRUM_MESH_CA_BACKEND spire_agent selection",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "spire_agent/spire/spire-agent (case-insensitive) select CaBackend::SpireAgent; \
                 unknown tokens error at startup; empty/none disable the CA backend.",
    );
    for token in ["spire_agent", "spire", "spire-agent", "SPIRE_AGENT"] {
        assert_eq!(
            CaBackend::from_str_lossy(token),
            Ok(CaBackend::SpireAgent),
            "token {token:?} must select the SPIRE Agent backend"
        );
    }
    assert_eq!(
        CaBackend::from_str_lossy("internal"),
        Ok(CaBackend::Internal)
    );
    assert_eq!(CaBackend::from_str_lossy(""), Ok(CaBackend::None));
    assert_eq!(CaBackend::from_str_lossy("none"), Ok(CaBackend::None));
    assert!(
        CaBackend::from_str_lossy("vault").is_err(),
        "unknown CA backend tokens must be a startup error, not a silent None"
    );
}
