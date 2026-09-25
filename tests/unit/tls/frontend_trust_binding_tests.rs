//! The accepted frontend TLS candidate binds verifier and trust identity
//! (issue #3857).
//!
//! The HTTP/3 endpoint applies a reload asynchronously, so it is the one
//! listener that cannot reassemble "the accepted generation" from parts. It
//! used to install a verifier rebuilt from a re-read client-CA source plus the
//! **startup** CRL clone, and then publish `ProxyFrontend`'s latest material as
//! its own generation. An accepted CRL rotation therefore advanced the H3
//! generation — retiring established H3 connections — while the verifier QUIC
//! kept handshaking with still had the old CRLs, so the very certificate the
//! rotation revoked could simply reconnect.
//!
//! These tests pin the replacement contract on the exact objects the H3 reload
//! arm consumes:
//!
//! - one accepted candidate carries the verifier AND the identity of the same
//!   client-CA bytes and CRLs;
//! - a CRL rotation produces a candidate whose verifier actually refuses the
//!   newly revoked client certificate, which is what makes a reconnect meet the
//!   new verifier rather than only tearing down the old connection;
//! - publishing that candidate's identity is a `Withdrawn`, and publishing the
//!   identity of a candidate that did not narrow authority is not;
//! - a malformed later candidate never becomes a candidate at all, so the
//!   last-good verifier, identity and generation are retained.
//!
//! No sleeps and no source races: every assertion is driven by loading a
//! candidate from files this test wrote, and by calling the verifier directly.

use std::sync::OnceLock;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::grpc::dp_client::DpFrontendH3Pairing;
use ferrum_edge::tls::client_trust::{
    self, ClientTrustPublication, ClientTrustPublicationOutcome, ClientTrustScope,
};
use ferrum_edge::tls::{
    AcceptedClientTrust, AcceptedFrontendTls, ClientTrustMaterial, CrlList, TlsPolicy,
    load_frontend_tls_candidate_from_paths,
};
use rustls::ClientConfig;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// The trust registry is process-global and `reset_for_test` clears every scope,
// so this file shares the sibling suite's lock rather than taking its own.
use super::client_trust_tests::isolated_registry;

/// A serial that belongs to no certificate in these tests, so a CRL carrying
/// only it revokes nothing that is being verified.
const UNRELATED_SERIAL: u64 = 0xdead_beef;

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_policy() -> TlsPolicy {
    ensure_crypto_provider();
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy")
}

/// A client CA plus one client certificate issued under it.
struct TestPki {
    ca_pem: String,
    client_der: Vec<u8>,
    client_key_pem: String,
    client_serial: u64,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    server_cert_pem: String,
    server_key_pem: String,
}

fn build_pki() -> TestPki {
    ensure_crypto_provider();

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Frontend Client CA");
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let ca_pem = ca_cert.pem();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    // The client certificate must carry the clientAuth EKU or webpki refuses it
    // before revocation is ever consulted, which would make the CRL assertions
    // vacuous.
    let client_serial = 0x3857u64;
    let client_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "frontend-client");
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    client_params.serial_number = Some(rcgen::SerialNumber::from(client_serial));
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");
    let client_der = client_cert.der().to_vec();

    // An unrelated self-signed server identity; the frontend loader validates
    // it, but none of these assertions depend on it.
    let server_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .self_signed(&server_key)
        .expect("self-signed server cert");

    TestPki {
        ca_pem,
        client_der,
        client_key_pem: client_key.serialize_pem(),
        client_serial,
        issuer,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    }
}

impl TestPki {
    /// A CRL revoking `serials`, re-issued at `crl_number`.
    fn crl_pem(&self, serials: &[u64], crl_number: u64) -> String {
        let now = time::OffsetDateTime::now_utc();
        rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: rcgen::SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*serial),
                    revocation_time: now,
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&self.issuer)
        .expect("sign CRL")
        .pem()
        .expect("CRL PEM")
    }

    fn client_cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.client_der.clone())
    }
}

fn parse_crls(pem: &str) -> CrlList {
    std::sync::Arc::new(
        CertificateRevocationListDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRLs"),
    )
}

/// Load one accepted frontend candidate exactly as the reload pipeline does.
fn load_candidate(
    dir: &std::path::Path,
    pki: &TestPki,
    crls: &CrlList,
) -> Result<AcceptedClientTrust, anyhow::Error> {
    let cert_path = dir.join("server-cert.pem");
    let key_path = dir.join("server-key.pem");
    let ca_path = dir.join("client-ca.pem");
    std::fs::write(&cert_path, pki.server_cert_pem.as_bytes()).expect("write server cert");
    std::fs::write(&key_path, pki.server_key_pem.as_bytes()).expect("write server key");
    std::fs::write(&ca_path, pki.ca_pem.as_bytes()).expect("write client CA");

    load_frontend_tls_candidate_from_paths(
        cert_path.to_str().expect("utf8 cert path"),
        key_path.to_str().expect("utf8 key path"),
        Some(ca_path.to_str().expect("utf8 ca path")),
        None,
        false,
        &tls_policy(),
        30,
        30,
        crls,
        None,
    )
    .map(|candidate| candidate.client_trust)
}

fn load_accepted_frontend(
    dir: &std::path::Path,
    pki: &TestPki,
    crls: &CrlList,
    label: &str,
) -> Result<std::sync::Arc<AcceptedFrontendTls>, anyhow::Error> {
    load_accepted_frontend_parts(
        dir,
        label,
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &pki.ca_pem,
        crls,
        None,
    )
}

fn load_accepted_frontend_parts(
    dir: &std::path::Path,
    label: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
    ca_pem: &str,
    crls: &CrlList,
    handshake_scope: Option<ClientTrustScope>,
) -> Result<std::sync::Arc<AcceptedFrontendTls>, anyhow::Error> {
    let cert_path = dir.join(format!("{label}-server-cert.pem"));
    let key_path = dir.join(format!("{label}-server-key.pem"));
    let ca_path = dir.join(format!("{label}-client-ca.pem"));
    std::fs::write(&cert_path, server_cert_pem.as_bytes()).expect("write server cert");
    std::fs::write(&key_path, server_key_pem.as_bytes()).expect("write server key");
    std::fs::write(&ca_path, ca_pem.as_bytes()).expect("write client CA");

    load_frontend_tls_candidate_from_paths(
        cert_path.to_str().expect("utf8 cert path"),
        key_path.to_str().expect("utf8 key path"),
        Some(ca_path.to_str().expect("utf8 ca path")),
        None,
        false,
        &tls_policy(),
        30,
        30,
        crls,
        handshake_scope,
    )
    .map(|candidate| {
        std::sync::Arc::new(AcceptedFrontendTls {
            config: candidate.config,
            client_trust: candidate.client_trust,
        })
    })
}

/// Whether the candidate's verifier admits the client certificate.
fn admits_client(trust: &AcceptedClientTrust, pki: &TestPki) -> bool {
    trust
        .verifier
        .as_ref()
        .expect("a configured client CA must yield a verifier")
        .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
        .is_ok()
}

/// Rustls tests must go through the explicit transaction with a simulated
/// config-exposure callback. An empty `|| {}` would recreate the removed
/// production bypass. Material-only / DTLS tests use
/// [`client_trust::publish_accepted_material`] instead.
fn publish_rustls(scope: ClientTrustScope, trust: &AcceptedClientTrust) -> ClientTrustPublication {
    let verifier = trust
        .verifier
        .clone()
        .expect("rustls test publishes a live verifier");
    let exposed = std::sync::atomic::AtomicBool::new(false);
    let publication = client_trust::publish_accepted_rustls_candidate(
        scope,
        trust.material.clone(),
        verifier,
        || {
            exposed.store(true, std::sync::atomic::Ordering::SeqCst);
        },
    );
    assert!(
        exposed.load(std::sync::atomic::Ordering::SeqCst),
        "{scope:?}: rustls publication must run an explicit config-exposure callback"
    );
    publication
}

/// The heart of the finding: an accepted CRL rotation must reach the verifier a
/// reconnecting HTTP/3 client meets, not merely retire the old connection.
///
/// The H3 reload arm installs `AcceptedClientTrust::verifier` and publishes
/// `AcceptedClientTrust::material` from ONE value, so proving the rotated
/// candidate's verifier refuses the revoked certificate proves the reconnect is
/// refused too. Under the old code the H3 verifier was rebuilt with the startup
/// CRL clone, which is exactly the `before` candidate here — it still admits the
/// certificate the rotation revoked.
#[test]
fn an_accepted_crl_rotation_changes_the_verifier_a_reconnect_meets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    // Generation 1: a CRL that revokes an unrelated serial. Non-empty on
    // purpose — an empty revocation list is a needless encoding edge case, and
    // the point here is only that the client's own serial is not on it.
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    assert!(
        admits_client(&before, &pki),
        "the startup verifier must admit a client certificate no CRL revokes"
    );

    // Generation 2: the operator revokes the client's serial.
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(
        !admits_client(&after, &pki),
        "the accepted candidate's verifier must refuse the newly revoked client certificate; \
         reusing the startup CRL clone here is what let a revoked client reconnect over HTTP/3"
    );

    // ...and the identity published alongside it describes those same CRLs, so
    // the generation cannot advance ahead of what the verifier enforces.
    assert_eq!(
        after.material,
        ClientTrustMaterial::from_parts(Some(pki.ca_pem.as_bytes()), &rotated_crls)
            .expect("summarize rotated material"),
        "the candidate's identity must describe the CRLs compiled into its verifier"
    );
    assert_ne!(
        before.material, after.material,
        "a new revocation is a semantically different accepted generation"
    );
}

/// The published generation is derived from the adopted candidate, so a
/// withdrawal is reported exactly when the adopted verifier narrowed.
#[test]
fn publishing_the_adopted_candidates_identity_reports_the_withdrawal_it_enforces() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    // The H3 listener arms its own scope from the verifier it installed.
    let armed =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, before.material.clone());
    assert_eq!(armed.outcome, ClientTrustPublicationOutcome::Armed);

    // A connection admitted under that verifier.
    let session = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");

    // A routine CRL re-issue over the same revocation set is not a withdrawal:
    // the verifier still admits the same principals, so nothing is churned.
    let reissued_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 2));
    let reissued = load_candidate(dir.path(), &pki, &reissued_crls).expect("re-issued candidate");
    assert!(
        admits_client(&reissued, &pki),
        "a re-issued CRL over the same set must still admit the client"
    );
    let unchanged =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, reissued.material);
    assert_eq!(
        unchanged.outcome,
        ClientTrustPublicationOutcome::Unchanged,
        "an additive/no-op trust change must not churn sessions"
    );
    assert!(!session.session().is_retired());

    // The real revocation narrows authority: the adopted verifier refuses the
    // certificate, and the generation published for it retires the transport
    // that was admitted under the old one.
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 3));
    let rotated = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(!admits_client(&rotated, &pki));
    let withdrawn =
        client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, rotated.material);
    assert!(
        withdrawn.withdrew(),
        "adopting a verifier that revokes a live peer must publish a withdrawal"
    );
    assert_eq!(withdrawn.retired_sessions, 1);
    assert!(
        session.session().is_retired(),
        "the established transport admitted under the previous verifier is retired"
    );

    // A transport that reconnects now captures the new generation, and the
    // verifier it meets is the one that refuses it — the two halves cannot
    // disagree because they came from one candidate.
    let reconnected = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");
    assert!(
        !reconnected.session().is_retired(),
        "a reconnect is admitted by the fence and refused by the verifier, not the reverse"
    );
}

/// The live handshake verifier is stored before the generation advances, so a
/// reconnect that still holds a stale `ServerConfig` snapshot is refused by
/// the published verifier rather than served (issue #3857).
#[test]
fn live_verifier_refuses_a_withdrawn_cert_even_if_the_handshake_used_a_stale_snapshot() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    publish_rustls(ClientTrustScope::ProxyH3, &before);
    assert!(
        client_trust::live_peer_still_trusted(ClientTrustScope::ProxyH3, &[pki.client_cert()]),
        "the live verifier must admit a client no CRL revokes"
    );
    publish_rustls(ClientTrustScope::ProxyFrontend, &before);
    assert!(
        client_trust::live_peer_still_trusted(
            ClientTrustScope::ProxyFrontend,
            &[pki.client_cert()]
        ),
        "the same candidate must arm every rustls scope that publishes it"
    );

    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(!admits_client(&after, &pki));
    let withdrawn = publish_rustls(ClientTrustScope::ProxyH3, &after);
    assert!(withdrawn.withdrew());
    assert!(
        !client_trust::live_peer_still_trusted(ClientTrustScope::ProxyH3, &[pki.client_cert()]),
        "after the accepted withdrawal the live H3 verifier must refuse the revoked cert, \
         even if a stale QUIC Incoming still completed TLS against the previous snapshot"
    );
    publish_rustls(ClientTrustScope::ProxyFrontend, &after);
    assert!(
        !client_trust::live_peer_still_trusted(
            ClientTrustScope::ProxyFrontend,
            &[pki.client_cert()]
        ),
        "after the accepted withdrawal the live H1/H2 verifier must refuse the revoked cert, \
         even if a stale TlsAcceptor snapshot still completed the handshake"
    );
}

/// rustls bakes the client-cert verifier into each `ServerConfig`. A wrapper
/// around a *stale* inner verifier must still refuse after the accepted
/// candidate is published, which is what new H1/H3 handshakes actually run
/// (issue #3857).
#[test]
fn live_handshake_wrapper_refuses_after_accepted_withdrawal_even_with_a_stale_inner() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    publish_rustls(ClientTrustScope::ProxyH3, &before);
    publish_rustls(ClientTrustScope::ProxyFrontend, &before);
    let stale_h3_inner = before
        .verifier
        .clone()
        .expect("startup candidate installs a verifier");
    let stale_frontend_inner = before
        .verifier
        .clone()
        .expect("startup candidate installs a verifier");
    let stale_h3 = client_trust::bind_live_handshake_verifier(
        ClientTrustScope::ProxyH3,
        stale_h3_inner.clone(),
    );
    let stale_frontend = client_trust::bind_live_handshake_verifier(
        ClientTrustScope::ProxyFrontend,
        stale_frontend_inner.clone(),
    );
    assert!(
        !stale_h3_inner.root_hint_subjects().is_empty(),
        "the snapshot inner verifier still has CA names; the wrapper must not forward them"
    );
    assert!(
        stale_h3.root_hint_subjects().is_empty(),
        "live wrapper must expose no snapshot CertificateRequest CA-name constraint"
    );
    assert!(
        stale_frontend.root_hint_subjects().is_empty(),
        "H1/H2 wrapper must expose no snapshot CertificateRequest CA-name constraint"
    );
    assert!(
        stale_h3.client_auth_mandatory() && stale_h3.offer_client_auth(),
        "generation-neutral hints must still require and offer client authentication"
    );
    assert!(
        !stale_h3.requires_raw_public_keys(),
        "the wrapper must preserve the inner verifier's raw-key posture"
    );
    assert!(
        stale_h3
            .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
            .is_ok(),
        "before withdrawal the live wrapper must still admit through the published verifier"
    );
    assert!(
        stale_frontend
            .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
            .is_ok(),
        "before withdrawal the H1/H2 wrapper must still admit through the published verifier"
    );

    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(!admits_client(&after, &pki));
    assert!(publish_rustls(ClientTrustScope::ProxyH3, &after).withdrew());
    assert!(publish_rustls(ClientTrustScope::ProxyFrontend, &after).withdrew());
    assert!(
        stale_h3
            .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
            .is_err(),
        "a stale H3 ServerConfig snapshot must consult the live verifier and refuse the revoked cert"
    );
    assert!(
        stale_frontend
            .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
            .is_err(),
        "a stale H1/H2 ServerConfig snapshot must consult the live verifier and refuse the withdrawn cert"
    );
    assert!(
        !client_trust::armed_handshake_still_trusted(
            ClientTrustScope::ProxyH3,
            Some(&[pki.client_cert()])
        ),
        "armed admission must also refuse the revoked cert after the accepted withdrawal"
    );
    assert!(
        !client_trust::armed_handshake_still_trusted(ClientTrustScope::ProxyH3, None),
        "armed admission must fail closed when the handshake exposes no peer certificate"
    );
    assert!(
        stale_h3.root_hint_subjects().is_empty() && stale_frontend.root_hint_subjects().is_empty(),
        "live verification must not start advertising snapshot CA names after a withdrawal"
    );
}

/// CertificateRequest CA names must stay generation-neutral on the live
/// wrapper: rustls omits or does not constrain `certificate_authorities` for
/// an empty list, so an additive CA is not filtered by a stale snapshot
/// (issue #3857). Trust itself is unchanged — the inner verifier still has
/// names, client auth stays mandatory, and verification is still fail-closed.
#[test]
fn live_handshake_wrapper_exposes_no_stale_ca_name_constraint() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let extra = issue_client_under_new_ca("overlap-client", 0x3858);

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    publish_rustls(ClientTrustScope::ProxyFrontend, &before);
    let inner = before
        .verifier
        .clone()
        .expect("startup candidate installs a verifier");
    let wrapper =
        client_trust::bind_live_handshake_verifier(ClientTrustScope::ProxyFrontend, inner.clone());

    assert!(
        !inner.root_hint_subjects().is_empty(),
        "the snapshot inner verifier still has CA names; the wrapper must not forward them"
    );
    assert!(
        wrapper.root_hint_subjects().is_empty(),
        "live wrapper must expose no snapshot CertificateRequest CA-name constraint"
    );
    assert_eq!(
        wrapper.client_auth_mandatory(),
        inner.client_auth_mandatory(),
    );
    assert_eq!(wrapper.offer_client_auth(), inner.offer_client_auth());
    assert_eq!(
        wrapper.requires_raw_public_keys(),
        inner.requires_raw_public_keys(),
    );
    assert!(
        wrapper.client_auth_mandatory() && wrapper.offer_client_auth(),
        "generation-neutral hints must still require and offer client authentication"
    );
    assert!(
        wrapper
            .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
            .is_ok(),
        "live wrapper must still admit the original CA through the published verifier"
    );
    assert!(
        wrapper
            .verify_client_cert(
                &CertificateDer::from(extra.cert_der.clone()),
                &[],
                UnixTime::now(),
            )
            .is_err(),
        "empty hints must not broaden trust to a CA the live verifier does not admit"
    );

    let overlap_pem = format!("{}{}", pki.ca_pem, extra.ca_pem);
    let overlap = load_accepted_frontend_parts(
        dir.path(),
        "wrapper-overlap",
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &overlap_pem,
        &startup_crls,
        None,
    )
    .expect("additive overlap candidate");
    publish_rustls(ClientTrustScope::ProxyFrontend, &overlap.client_trust);
    assert!(
        wrapper.root_hint_subjects().is_empty(),
        "an additive live publish must not start advertising snapshot CA names"
    );
    assert!(
        wrapper
            .verify_client_cert(
                &CertificateDer::from(extra.cert_der.clone()),
                &[],
                UnixTime::now(),
            )
            .is_ok(),
        "after the additive publish the live wrapper must admit the new CA"
    );
}

/// Counterexample for the rustls publication-order race: a ServerConfig built
/// with candidate V2 must consult live V2 during the window after verifier
/// install and before generation advances — never the withdrawn V1. That
/// window exists only inside the transaction's expose callback.
#[test]
fn a_v2_handshake_config_cannot_consult_v1_during_the_pre_generation_window() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    assert!(admits_client(&before, &pki));
    assert!(!admits_client(&after, &pki));

    let v2_inner = after
        .verifier
        .clone()
        .expect("rotated candidate installs a verifier");
    let rustls_scopes = [
        ClientTrustScope::ProxyFrontend,
        ClientTrustScope::ProxyH3,
        ClientTrustScope::AdminHttps,
    ];
    for scope in rustls_scopes {
        publish_rustls(scope, &before);
        let generation_before = client_trust::capture(scope).expect("armed").generation();
        assert_eq!(generation_before, 1);

        let v2_wrapper = client_trust::bind_live_handshake_verifier(scope, v2_inner.clone());
        assert!(
            v2_wrapper
                .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
                .is_ok(),
            "{:?}: a V2 config that still sees live V1 would admit the withdrawn cert",
            scope,
        );

        let exposed = std::sync::atomic::AtomicBool::new(false);
        let withdrawn = client_trust::publish_accepted_rustls_candidate(
            scope,
            after.material.clone(),
            v2_inner.clone(),
            || {
                assert_eq!(
                    client_trust::capture(scope)
                        .expect("still armed")
                        .generation(),
                    generation_before,
                    "{:?}: config exposure must happen before generation advances",
                    scope,
                );
                assert!(
                    v2_wrapper
                        .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
                        .is_err(),
                    "{:?}: a config built with V2 must consult live V2 and refuse the withdrawn cert \
                     before generation advances",
                    scope,
                );
                assert!(
                    !client_trust::live_peer_still_trusted(scope, &[pki.client_cert()]),
                    "{:?}: the post-handshake live check must also see V2 in the pre-generation window",
                    scope,
                );
                assert!(
                    !client_trust::armed_handshake_still_trusted(scope, Some(&[pki.client_cert()])),
                    "{:?}: armed admission must fail closed on the withdrawn cert before the fence moves",
                    scope,
                );
                let v1_wrapper = client_trust::bind_live_handshake_verifier(
                    scope,
                    before
                        .verifier
                        .clone()
                        .expect("startup candidate installs a verifier"),
                );
                assert!(
                    v1_wrapper
                        .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
                        .is_err(),
                    "{:?}: a stale V1 config must refuse withdrawn credentials once V2 is live",
                    scope,
                );
                exposed.store(true, std::sync::atomic::Ordering::SeqCst);
            },
        );
        assert!(
            exposed.load(std::sync::atomic::Ordering::SeqCst),
            "{:?}: expose_config must run inside the transaction",
            scope,
        );
        assert!(
            withdrawn.withdrew(),
            "{:?}: publishing the same already-installed verifier must still record the withdrawal",
            scope,
        );
        assert!(
            withdrawn.generation > generation_before,
            "{:?}: generation advances only at publish, after the config would already be exposed",
            scope,
        );
    }
}

/// A fallible/refused candidate must never replace the live verifier. The
/// previous config keeps being served against last-good V1.
#[test]
fn a_refused_candidate_never_replaces_the_live_verifier() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let before = load_candidate(dir.path(), &pki, &startup_crls).expect("startup candidate");
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let after = load_candidate(dir.path(), &pki, &rotated_crls).expect("rotated candidate");
    let v2_inner = after
        .verifier
        .clone()
        .expect("rotated candidate installs a verifier");

    for scope in [
        ClientTrustScope::ProxyFrontend,
        ClientTrustScope::ProxyH3,
        ClientTrustScope::AdminHttps,
    ] {
        publish_rustls(scope, &before);
        let generation_before = client_trust::capture(scope).expect("armed").generation();

        // Simulate a fallible later rebuild: record the refusal and do not
        // enter a rustls publication transaction.
        client_trust::record_rejected_candidate(scope);

        let would_be_v2 = client_trust::bind_live_handshake_verifier(scope, v2_inner.clone());
        assert!(
            would_be_v2
                .verify_client_cert(&pki.client_cert(), &[], UnixTime::now())
                .is_ok(),
            "{:?}: a refused V2 candidate must leave live V1 in place",
            scope,
        );
        assert!(
            client_trust::live_peer_still_trusted(scope, &[pki.client_cert()]),
            "{:?}: last-good V1 must still admit the client after a refused candidate",
            scope,
        );
        assert_eq!(
            client_trust::current_material(scope),
            Some(before.material.clone()),
            "{:?}: a refused candidate retains last-good material",
            scope,
        );
        assert_eq!(
            client_trust::capture(scope)
                .expect("still armed")
                .generation(),
            generation_before,
            "{:?}: a refused candidate must not advance generation",
            scope,
        );
        let row = client_trust::snapshot()
            .into_iter()
            .find(|row| row.scope == scope)
            .expect("scope present");
        assert_eq!(row.rejected_candidates, 1);
        assert_eq!(row.withdrawal_generation, 0);
    }
}

/// Pin the fail-closed rustls order in the reload surfaces: the singular
/// scope's one transaction installs the live verifier, exposes config, then
/// publishes generation. A refused path records rejection without entering
/// that transaction. DTLS keeps config-before-generation and must not grow a
/// rustls live-verifier transaction. The production-capable empty-callback
/// bypass and a multi-scope `Vec` on one rustls family must stay absent.
#[test]
fn rustls_reload_surfaces_install_live_verifier_before_exposing_config() {
    let bypass = concat!("publish_accepted_", "candidate");
    let multi_scope_field = concat!("client_trust_", "scopes");
    let empty_rustls_callback = concat!(
        "publish_accepted_rustls_candidate(scope, material, verifier, ",
        "|| {})"
    );

    let trust_src = include_str!("../../../src/tls/client_trust.rs");
    assert!(
        !trust_src.contains(&format!("fn {bypass}")),
        "client_trust must not expose a rustls publication bypass that omits config exposure"
    );
    assert!(
        !trust_src.contains(empty_rustls_callback),
        "client_trust must not hide an empty-callback rustls convenience"
    );

    let reload = include_str!("../../../src/tls/frontend_reload.rs");
    assert!(
        !reload.contains("install_accepted_live_verifier"),
        "frontend rustls reload must not use the split install path"
    );
    assert!(
        !reload.contains(bypass),
        "frontend rustls reload must not call the removed rustls publication bypass"
    );
    assert!(
        !reload.contains(multi_scope_field),
        "frontend reload owns exactly one optional ClientTrustScope, not a Vec"
    );
    assert!(
        !reload.contains("for scope in"),
        "frontend reload must not loop over client-trust scopes; one family owns one scope"
    );
    assert!(
        reload.contains("client_trust_scope: Option<crate::tls::ClientTrustScope>"),
        "frontend reload config must type the owned scope as Option<ClientTrustScope>"
    );
    assert_source_order(
        reload,
        &[
            "publish_accepted_rustls_candidate",
            "slot.store(Arc::new(Some(new_config.clone())))",
        ],
        "frontend rustls reload: live-verifier transaction exposes the config inside the callback",
    );
    let first_reject = reload
        .find("record_rejected_candidate")
        .expect("frontend reload records refused candidates");
    let publish = reload
        .find("publish_accepted_rustls_candidate")
        .expect("frontend reload publishes through the rustls transaction");
    assert!(
        first_reject < publish,
        "a fallible frontend reload must record rejection before any rustls transaction"
    );

    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        !h3.contains("install_accepted_live_verifier"),
        "H3 must not use the split install path"
    );
    assert!(
        !h3.contains(bypass),
        "H3 must not call the removed rustls publication bypass"
    );
    assert!(
        !h3.contains(multi_scope_field),
        "H3 must not grow a multi-scope Vec; ProxyH3 is independently owned"
    );
    let reload_arm_start = h3
        .find("&reload_h3_config,")
        .expect("H3 reload arm rebuild");
    let reload_arm = &h3[reload_arm_start..];
    assert_source_order(
        reload_arm,
        &[
            "publish_accepted_rustls_candidate",
            "adopted_quic.store",
            "endpoint.set_server_config(Some(server_config.clone()))",
        ],
        "H3 rustls reload must expose the exact candidate inside the rustls transaction",
    );
    let publish = reload_arm
        .find("publish_accepted_rustls_candidate")
        .expect("H3 reload publishes generation after adopt");
    let err_arm = reload_arm
        .find("record_rejected_candidate")
        .expect("H3 reload records a refused quinn rebuild");
    assert!(
        err_arm > publish,
        "the H3 Ok arm must not install a verifier on the fallible Err path"
    );

    let startup_h3 = h3
        .find("pub async fn start_http3_listener_with_signal")
        .expect("H3 startup");
    let startup_h3_src = &h3[startup_h3..reload_arm_start];
    assert_source_order(
        startup_h3_src,
        &[
            "publish_accepted_rustls_candidate",
            "adopted_for_expose.store",
            "endpoint.set_server_config(Some(server_config.clone()))",
        ],
        "H3 startup must expose the serving config inside the rustls transaction",
    );
    assert!(
        h3.contains("adopted_quic.store(Arc::new(None));"),
        "H3 config withdrawal must clear the config consulted by queued Incoming handles"
    );
    let accept_incoming = h3
        .find("fn accept_h3_incoming")
        .expect("H3 queued-Incoming admission helper");
    let accept_incoming_src = &h3[accept_incoming..];
    assert!(
        accept_incoming_src.contains("incoming.refuse();"),
        "a queued H3 Incoming must be refused when no adopted config remains"
    );

    let modes = include_str!("../../../src/modes/tls_reload.rs");
    assert!(
        !modes.contains("install_accepted_live_verifier"),
        "proxy/admin startup must not use the split install path"
    );
    assert!(
        !modes.contains(bypass),
        "proxy/admin startup must not call the removed rustls publication bypass"
    );
    assert!(
        !modes.contains(multi_scope_field),
        "proxy/admin startup must not pass a multi-scope Vec into frontend reload"
    );
    assert!(
        !modes.contains("vec![ClientTrustScope"),
        "proxy/admin startup must not construct a ClientTrustScope Vec"
    );
    assert!(
        !modes.contains("for scope in"),
        "proxy/admin startup must not loop over client-trust scopes"
    );
    let proxy_fn = modes
        .find("pub fn prepare_proxy_frontend_tls")
        .expect("proxy startup");
    let admin_fn = modes
        .find("pub fn prepare_admin_frontend_tls")
        .expect("admin startup");
    assert!(proxy_fn < admin_fn);
    assert_source_order(
        &modes[proxy_fn..admin_fn],
        &[
            "publish_accepted_rustls_candidate",
            "slot.store(Arc::new(Some(tls_config.clone())))",
        ],
        "proxy startup must expose the slot inside the rustls transaction",
    );
    assert_source_order(
        &modes[admin_fn..],
        &[
            "publish_accepted_rustls_candidate",
            "slot.store(Arc::new(Some(tls_config.clone())))",
        ],
        "admin startup must expose the slot inside the rustls transaction",
    );

    let grpc = include_str!("../../../src/modes/grpc_tls_reload.rs");
    assert!(
        grpc.contains("client_trust_scope: None"),
        "CP gRPC TLS reload is outside the frontend client-trust domain"
    );
    assert!(
        !grpc.contains("publish_accepted_rustls_candidate"),
        "CP gRPC TLS reload must not publish a frontend rustls trust generation"
    );
    assert!(
        !grpc.contains(bypass) && !grpc.contains(multi_scope_field),
        "CP gRPC TLS reload must not reintroduce the rustls bypass or a multi-scope Vec"
    );

    let dtls = include_str!("../../../src/proxy/stream_listener.rs");
    assert!(
        !dtls.contains("install_accepted_live_verifier"),
        "DTLS has no rustls live verifier and must not grow one"
    );
    assert!(
        !dtls.contains("publish_accepted_rustls_candidate"),
        "DTLS has no rustls live verifier and must not use the rustls transaction"
    );
    assert!(
        !dtls.contains(bypass),
        "DTLS must not call the removed rustls publication bypass"
    );
    let dtls_fn = dtls
        .find("pub async fn publish_frontend_dtls_generation")
        .expect("DTLS publish entry");
    assert_source_order(
        &dtls[dtls_fn..],
        &[
            "swap_active_dtls_frontend_config",
            "publish_accepted_material",
        ],
        "DTLS keeps config-before-generation ordering",
    );

    let binding_tests = include_str!("frontend_trust_binding_tests.rs");
    let material_tests = include_str!("client_trust_tests.rs");
    assert!(
        !binding_tests.contains(bypass) && !material_tests.contains(bypass),
        "unit tests must not call the removed rustls publication bypass"
    );
    assert!(
        !binding_tests.contains(multi_scope_field) && !material_tests.contains(multi_scope_field),
        "unit tests must not reintroduce a multi-scope Vec"
    );
}

/// Two accepted rustls publishers racing on one scope cannot leave verifier,
/// exposed config, and published material describing different candidates.
#[test]
fn concurrent_rustls_publishers_cannot_cross_wire_verifier_config_and_material() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let v2 = load_candidate(dir.path(), &pki, &startup_crls).expect("V2 candidate");
    let rotated_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let v3 = load_candidate(dir.path(), &pki, &rotated_crls).expect("V3 candidate");
    assert!(admits_client(&v2, &pki));
    assert!(!admits_client(&v3, &pki));
    let v2_verifier = v2.verifier.clone().expect("V2 verifier");
    let v3_verifier = v3.verifier.clone().expect("V3 verifier");

    let scope = ClientTrustScope::ProxyFrontend;
    let exposed = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let spawn = |id: u8,
                 material: ClientTrustMaterial,
                 verifier: std::sync::Arc<dyn ClientCertVerifier>,
                 exposed: std::sync::Arc<std::sync::atomic::AtomicU8>,
                 barrier: std::sync::Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            client_trust::publish_accepted_rustls_candidate(scope, material, verifier, || {
                exposed.store(id, std::sync::atomic::Ordering::SeqCst);
            })
        })
    };

    let handle_v2 = spawn(
        2,
        v2.material.clone(),
        v2_verifier,
        std::sync::Arc::clone(&exposed),
        std::sync::Arc::clone(&barrier),
    );
    let handle_v3 = spawn(
        3,
        v3.material.clone(),
        v3_verifier,
        std::sync::Arc::clone(&exposed),
        barrier,
    );
    handle_v2.join().expect("V2 publisher");
    handle_v3.join().expect("V3 publisher");

    let config_id = exposed.load(std::sync::atomic::Ordering::SeqCst);
    let published = client_trust::current_material(scope).expect("armed");
    let live_admits = client_trust::live_peer_still_trusted(scope, &[pki.client_cert()]);
    let is_v2 = published == v2.material;
    let is_v3 = published == v3.material;
    assert!(
        is_v2 ^ is_v3,
        "the published material must be exactly one of the two accepted candidates"
    );
    assert_eq!(
        config_id == 2,
        is_v2,
        "exposed config id {config_id} must belong to the published material (v2={is_v2})"
    );
    assert_eq!(
        config_id == 3,
        is_v3,
        "exposed config id {config_id} must belong to the published material (v3={is_v3})"
    );
    assert_eq!(
        live_admits, is_v2,
        "live verifier must admit the client iff the published material is V2, not a mix of V2/V3"
    );
    assert_eq!(
        !live_admits, is_v3,
        "live verifier must refuse the client iff the published material is V3"
    );
}

fn assert_source_order(source: &str, needles: &[&str], message: &str) {
    let mut pos = 0usize;
    for needle in needles {
        match source[pos..].find(needle) {
            Some(found) => pos += found + needle.len(),
            None => panic!("{message}: missing `{needle}` after prior step"),
        }
    }
}

/// Suppressing TLS 1.3 resumption is required only where a withdrawal can
/// actually land: a session ticket does not re-run client-certificate
/// verification, so a listener bound to a client-trust scope must not issue
/// one. A listener that is never bound can never publish a generation, so it
/// has to keep the resumption it had before issue #3857 — otherwise every
/// static mTLS deployment silently pays a full handshake per connection for a
/// protection that cannot engage.
#[test]
fn resumption_is_suppressed_only_for_a_scope_bound_mtls_listener() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));

    let unbound = load_accepted_frontend_parts(
        dir.path(),
        "resumption-unbound",
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &pki.ca_pem,
        &crls,
        None,
    )
    .expect("unbound mTLS candidate");
    assert!(
        unbound.config.send_tls13_tickets > 0,
        "a static mTLS listener must keep TLS 1.3 session tickets: no generation can advance, \
         so no ticket can outlive a withdrawal"
    );

    let bound = load_accepted_frontend_parts(
        dir.path(),
        "resumption-bound",
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &pki.ca_pem,
        &crls,
        Some(ClientTrustScope::ProxyFrontend),
    )
    .expect("scope-bound mTLS candidate");
    assert_eq!(
        bound.config.send_tls13_tickets, 0,
        "a listener that can publish a withdrawal must not issue resumption tickets that skip \
         client-certificate verification"
    );
}

/// A listener with no client-CA source installs no verifier, so a globally
/// loaded CRL list is irrelevant: it must not reject the candidate, and the
/// captured identity must stay empty rather than summarizing CRLs no handshake
/// will enforce. The same CRL list remains fail-closed once a client CA is
/// configured.
#[test]
fn no_client_ca_listener_accepts_unrelated_crls_as_an_unarmed_candidate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    assert!(
        !crls.is_empty(),
        "the globally loaded CRL list under test must be non-empty"
    );

    let cert_path = dir.path().join("server-cert.pem");
    let key_path = dir.path().join("server-key.pem");
    std::fs::write(&cert_path, pki.server_cert_pem.as_bytes()).expect("write server cert");
    std::fs::write(&key_path, pki.server_key_pem.as_bytes()).expect("write server key");

    let unarmed = load_frontend_tls_candidate_from_paths(
        cert_path.to_str().expect("utf8 cert path"),
        key_path.to_str().expect("utf8 key path"),
        None,
        None,
        false,
        &tls_policy(),
        30,
        30,
        &crls,
        None,
    )
    .expect("no-client-CA listener must accept a global CRL list");
    assert!(
        unarmed.client_trust.verifier.is_none(),
        "a listener with no client CA must install no client-certificate verifier"
    );
    assert_eq!(
        unarmed.client_trust.material,
        ClientTrustMaterial::default(),
        "unarmed identity must stay empty rather than publishing CRLs no verifier enforces"
    );
    if let Ok(leaked) = ClientTrustMaterial::from_parts(None, &crls) {
        assert_ne!(
            unarmed.client_trust.material, leaked,
            "summarizing CRLs without a client-CA signer must not become the captured identity"
        );
    }

    // The same CRLs with a configured client CA still compile into the verifier
    // and the captured identity — the armed path is not weakened.
    let armed = load_candidate(dir.path(), &pki, &crls).expect("armed candidate");
    assert!(
        armed.verifier.is_some(),
        "a configured client CA must still construct a verifier"
    );
    assert_eq!(
        armed.material,
        ClientTrustMaterial::from_parts(Some(pki.ca_pem.as_bytes()), &crls)
            .expect("summarize armed material"),
        "an armed candidate must still summarize the exact client-CA bytes and CRLs"
    );
    assert!(
        admits_client(&armed, &pki),
        "an unrelated CRL must not revoke the client under the configured CA"
    );

    // Malformed CRLs still fail closed when client authentication is armed.
    let mut truncated = crls[0].as_ref().to_vec();
    truncated.truncate(truncated.len() / 2);
    let broken: CrlList = std::sync::Arc::new(vec![CertificateRevocationListDer::from(truncated)]);
    assert!(
        load_candidate(dir.path(), &pki, &broken).is_err(),
        "a configured client CA must still refuse unverifiable CRL material"
    );
}

/// A malformed later candidate never produces an `AcceptedClientTrust`, so the
/// H3 reload arm has nothing to install or publish and keeps the last-good
/// verifier, identity, generation and sessions. mTLS is never downgraded.
#[test]
fn a_malformed_later_candidate_retains_the_last_good_trust() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();

    let rotated_crls = parse_crls(&pki.crl_pem(&[pki.client_serial], 1));
    let good = load_candidate(dir.path(), &pki, &rotated_crls).expect("accepted candidate");
    client_trust::publish_accepted_material(ClientTrustScope::ProxyH3, good.material.clone());
    let session = client_trust::capture(ClientTrustScope::ProxyH3)
        .expect("armed")
        .register(true)
        .expect("client-certificate transport");

    // The client-CA source is truncated mid-rotation.
    let ca_path = dir.path().join("client-ca.pem");
    std::fs::write(&ca_path, b"-----BEGIN CERTIFICATE-----\nnot base64\n").expect("truncate CA");
    let refused = load_frontend_tls_candidate_from_paths(
        dir.path()
            .join("server-cert.pem")
            .to_str()
            .expect("utf8 cert path"),
        dir.path()
            .join("server-key.pem")
            .to_str()
            .expect("utf8 key path"),
        Some(ca_path.to_str().expect("utf8 ca path")),
        None,
        false,
        &tls_policy(),
        30,
        30,
        &rotated_crls,
        None,
    );
    assert!(
        refused.is_err(),
        "an unloadable client-CA candidate must fail closed rather than yield an empty trust set"
    );
    client_trust::record_rejected_candidate(ClientTrustScope::ProxyH3);

    // Last-good state is intact: the verifier still refuses the revoked client,
    // the generation did not advance, and no session was touched.
    assert!(!admits_client(&good, &pki));
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyH3),
        Some(good.material),
        "a refused candidate retains the last accepted identity"
    );
    assert!(!session.session().is_retired());
}

/// A ready H3 stream is resolved in a spawned task after the connection loop's
/// first retirement check. Pin the second, request-handler fence ahead of every
/// ordinary admission and routing surface so that asynchronous resolution can
/// never reopen the withdrawn credential.
#[test]
fn h3_request_handler_rechecks_withdrawal_before_admission() {
    let source = include_str!("../../../src/http3/server.rs");
    let handler_start = source
        .find("async fn handle_h3_request(")
        .expect("H3 request handler");
    let handler_tail = &source[handler_start..];
    let handler_end = handler_tail
        .find("\nfn build_h3_backend_url_for_flavor")
        .expect("end of H3 request handler");
    let handler = &handler_tail[..handler_end];

    let fence = handler
        .find("Frontend client-trust admission fence (HTTP/3")
        .expect("request-handler client-trust fence");
    assert!(
        handler[fence..].contains("client_trust_session.as_ref()")
            && handler[fence..].contains("session.is_retired()")
            && handler[fence..].contains("session.record_fenced()"),
        "the H3 request task must consult and account the connection trust fence"
    );
    let ordinary_admission = handler
        .find("Global request admission control (HTTP/3)")
        .expect("ordinary H3 request admission");
    assert!(
        fence < ordinary_admission,
        "withdrawn trust must be fenced before overload, routing, plugins, and backend dispatch"
    );
}

/// DP mode must pair CP-owned server config with the accepted operator trust
/// into one H3 candidate. Independently reading the listener slot and a startup
/// CRL clone is the fail-open the pairing slot exists to close.
#[tokio::test]
async fn dp_h3_pairing_wakes_on_operator_trust_while_cp_owns_the_server_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let withdrawn_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));

    let operator_startup =
        load_accepted_frontend(dir.path(), &pki, &startup_crls, "operator-startup")
            .expect("operator startup candidate");
    let cp_startup =
        load_accepted_frontend(dir.path(), &pki, &startup_crls, "cp-server").expect("CP candidate");
    let operator_withdrawn =
        load_accepted_frontend(dir.path(), &pki, &withdrawn_crls, "operator-withdrawn")
            .expect("operator CRL withdrawal");
    assert!(admits_client(&operator_startup.client_trust, &pki));
    assert!(!admits_client(&operator_withdrawn.client_trust, &pki));

    let pairing = DpFrontendH3Pairing::from_operator_candidate(operator_startup);
    let listener = ferrum_edge::tls::empty_frontend_tls_slot();
    pairing
        .publish_cp_server_config(Some(cp_startup.config.clone()), Some(&listener), None)
        .await;

    let update = pairing
        .publish_operator_candidate(operator_withdrawn.clone(), Some(&listener), None)
        .await;
    assert!(
        !update.replace_listener,
        "operator trust must not substitute the operator server certificate while CP material is active"
    );
    assert!(std::sync::Arc::ptr_eq(
        listener.load_full().as_ref().as_ref().expect("CP config"),
        &cp_startup.config
    ));

    let h3 = pairing.h3_accepted().expect("paired H3 candidate");
    assert!(
        std::sync::Arc::ptr_eq(&h3.config, &cp_startup.config),
        "H3 must keep the CP server certificate"
    );
    assert_eq!(
        h3.client_trust.material, operator_withdrawn.client_trust.material,
        "H3 must adopt the accepted operator trust, not the startup CRL clone"
    );
    assert!(
        !admits_client(&h3.client_trust, &pki),
        "the paired H3 verifier must refuse the newly revoked client certificate"
    );
}

#[test]
fn dp_mode_pairs_cp_server_config_with_operator_trust_for_h3() {
    let dp = include_str!("../../../src/modes/data_plane.rs");
    assert!(
        dp.contains("publish_operator_candidate"),
        "the DP operator revision bridge must publish into the H3 pairing slot"
    );
    assert!(
        dp.contains("h3_pairing"),
        "DP must own a pairing slot for the exact H3 serving candidate"
    );
    assert!(
        dp.contains("pairing.h3_accepted_slot.clone()"),
        "DP H3 and Gateway QUIC listeners must adopt the pairing slot, not accepted_slot: None"
    );
    let bridge = dp
        .find("changed = operator_revision_rx.changed()")
        .expect("DP operator TLS revision bridge");
    let pairing_publish = dp[bridge..]
        .find("publish_operator_candidate")
        .expect("pairing publish in the operator revision arm");
    let fallback_skip = dp[bridge..]
        .find("if cp_materialized.load(Ordering::Acquire)")
        .expect("legacy skip when pairing is absent");
    assert!(
        pairing_publish < fallback_skip,
        "CP-owned material must not skip the H3 pairing wakeup; the continue is only the no-pairing fallback"
    );
    let pairing_arm = &dp[bridge..][..fallback_skip];
    assert!(
        pairing_arm.contains("stream_listener_manager"),
        "operator pairing publication must include the stream-listener manager in the same transaction"
    );
    assert!(
        !pairing_arm.contains("set_frontend_tls_config"),
        "stream-listener TLS must be stored inside the pairing lock, not after the operator bridge returns"
    );

    let client = include_str!("../../../src/grpc/dp_client.rs");
    assert!(
        client.contains("commit_listener_publication"),
        "pairing publications must finish StreamListenerManager updates under the same lock"
    );
    assert!(
        client.contains("set_frontend_tls_config(update.listener_config.clone())"),
        "StreamListenerManager must be updated before the pairing lock is released"
    );
    let commit = client
        .find("async fn commit_frontend_tls_snapshot(")
        .expect("commit function");
    let commit_end = client[commit..]
        .find("\nfn bump_frontend_tls_revision(")
        .expect("commit function ends before the revision bump");
    let commit_fn = &client[commit..commit + commit_end];
    let clear_arm = commit_fn
        .find("FrontendTlsSnapshotUpdate::Clear")
        .expect("CP clear arm");
    let replace_arm = commit_fn
        .find("FrontendTlsSnapshotUpdate::Replace")
        .expect("CP replace arm");
    assert!(
        commit_fn[clear_arm..replace_arm].contains("publish_cp_server_config")
            && commit_fn[clear_arm..replace_arm].contains("None,")
            && commit_fn[clear_arm..replace_arm]
                .contains("Some(proxy_state.stream_listener_manager.as_ref())"),
        "clearing CP material must restore the latest accepted operator candidate through the pairing slot"
    );
    assert!(
        commit_fn[replace_arm..].contains("publish_cp_server_config")
            && commit_fn[replace_arm..].contains("Some(tls_config.clone())")
            && commit_fn[replace_arm..]
                .contains("Some(proxy_state.stream_listener_manager.as_ref())"),
        "applying CP material must pair it with the latest accepted operator trust and update stream listeners under that lock"
    );

    let stage = client
        .find("fn stage_frontend_tls_snapshot")
        .expect("CP frontend TLS staging");
    let stage_end = client[stage..]
        .find("async fn commit_frontend_tls_snapshot")
        .expect("commit follows stage");
    let staged = &client[stage..][..stage_end];
    assert!(
        staged.contains("ClientTrustScope::ProxyFrontend"),
        "CP-delivered frontend TLS must bind ProxyFrontend's live handshake wrapper"
    );
    assert!(
        staged.contains("frontend_tls_live_reload_enabled"),
        "the wrapper must be bound only under the opt-in that can arm the scope; binding it \
         unconditionally strips CertificateRequest CA-name hints and TLS 1.3 resumption on a \
         DP that can never publish an operator trust generation"
    );
    assert!(
        staged.contains("load_gateway_multi_cert_tls_config_with_handshake_scope")
            && staged.contains("load_frontend_tls_candidate_from_paths"),
        "both Gateway multi-cert and single-cert CP paths must bind the live wrapper"
    );
    assert!(
        !staged.contains("load_tls_config_with_client_auth_and_ocsp"),
        "the no-handshake-scope loader must not build CP frontend TLS"
    );

    let h3 = include_str!("../../../src/http3/server.rs");
    let reload_arm = h3
        .find("reload_change = reload_rx.changed()")
        .expect("H3 reload arm");
    let adoption_start = h3[reload_arm..]
        .find("let adopted = match reload_accepted.as_ref()")
        .expect("accepted-candidate adoption in H3 reload arm");
    let adoption_end = h3[reload_arm + adoption_start..]
        .find("let Some((new_tls, client_trust)) = adopted")
        .expect("accepted-candidate adoption completes before H3 rebuild");
    let adoption = &h3[reload_arm + adoption_start..reload_arm + adoption_start + adoption_end];
    let compact_adoption: String = adoption
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(
        compact_adoption.contains("Some(accepted_slot)=>accepted_slot.load_full()")
            && compact_adoption
                .contains("map(|accepted|(accepted.config.clone(),accepted.client_trust.clone()))")
            && compact_adoption.contains("None=>matchconfigured_h3_reload_candidate("),
        "H3 must adopt one accepted candidate rather than independently reading config and startup CRLs"
    );
}

/// Write the operator's client-CA bundle and CRL, and build the `EnvConfig` a
/// CP-only-server-certificate data plane runs with: HTTPS enabled, frontend
/// live reload on, client trust configured, and **no** operator cert/key.
fn cp_only_dp_env(
    dir: &std::path::Path,
    label: &str,
    ca_pem: &str,
    crl_pem: Option<&str>,
) -> (EnvConfig, String) {
    let ca_path = dir.join(format!("{label}-client-ca.pem"));
    std::fs::write(&ca_path, ca_pem.as_bytes()).expect("write client CA");
    let ca_path = ca_path.to_str().expect("utf8 ca path").to_string();
    let crl_path = crl_pem.map(|pem| {
        let path = dir.join(format!("{label}-revocations.pem"));
        std::fs::write(&path, pem.as_bytes()).expect("write CRL");
        path.to_str().expect("utf8 crl path").to_string()
    });
    (
        EnvConfig {
            proxy_https_port: 8443,
            frontend_tls_live_reload_enabled: true,
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_client_ca_bundle_path: Some(ca_path.clone()),
            tls_crl_file_path: crl_path,
            ..EnvConfig::default()
        },
        ca_path,
    )
}

/// A data plane whose only frontend server certificate is CP-delivered still
/// owns client trust, so `prepare_dp_operator_client_trust` must load it
/// coherently — with no operator cert/key anywhere in the picture.
#[test]
fn dp_cp_only_certificate_loads_operator_client_trust_without_a_server_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let crl_pem = pki.crl_pem(&[UNRELATED_SERIAL], 1);
    let crls = parse_crls(&crl_pem);
    let (env_config, _) = cp_only_dp_env(dir.path(), "cp-only-load", &pki.ca_pem, Some(&crl_pem));

    let prepared =
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .expect("client trust must load")
            .expect("the CP-only-certificate shape applies");

    assert!(
        prepared.client_trust.verifier.is_some(),
        "an operator client-CA bundle must yield a verifier even with no operator server certificate"
    );
    assert!(
        admits_client(&prepared.client_trust, &pki),
        "the loaded verifier must admit a client certificate no CRL revokes"
    );
    // The identity must describe the exact CRLs handed in, not an empty set:
    // a candidate summarized without them would read as a withdrawal later.
    let ca_path = env_config
        .frontend_tls_client_ca_bundle_path
        .clone()
        .expect("client CA configured");
    let withdrawn_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let rotated = trust_only_candidate(&ca_path, &withdrawn_crls);
    assert_ne!(
        prepared.client_trust.material, rotated.material,
        "the startup identity must carry the accepted CRLs, so a later revocation is a change"
    );
}

/// The scope must stay unarmed where there is nothing to protect, and the
/// startup load must fail closed where client authentication IS configured but
/// its material is unusable.
#[test]
fn dp_cp_only_certificate_client_trust_applicability_is_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));

    let (mut env_config, ca_path) = cp_only_dp_env(dir.path(), "cp-only-gates", &pki.ca_pem, None);

    env_config.frontend_tls_live_reload_enabled = false;
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .expect("no error without the opt-in")
            .is_none(),
        "without FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED no generation can ever advance"
    );

    env_config.frontend_tls_live_reload_enabled = true;
    env_config.frontend_tls_client_ca_bundle_path = None;
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .expect("no error without client authentication")
            .is_none(),
        "a listener that requests no client certificate must not arm a scope, and an unrelated \
         CRL must not make it fail"
    );

    // Inline PEM can never change, so there is nothing to watch and nothing to
    // arm — the same rule the operator cert/key pipeline applies.
    env_config.frontend_tls_client_ca_bundle_path = Some(pki.ca_pem.clone());
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .expect("no error for static inline material")
            .is_none(),
        "static inline client-CA material must not start a watcher"
    );
    env_config.frontend_tls_client_ca_bundle_path =
        Some("-----BEGIN CERTIFICATE-----\nnot pem\n-----END CERTIFICATE-----".to_string());
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .is_err(),
        "static inline trust still has to validate before the CP certificate arrives"
    );

    let broken = dir.path().join("broken-client-ca.pem");
    std::fs::write(&broken, b"-----BEGIN CERTIFICATE-----\nnot pem\n").expect("write broken CA");
    env_config.frontend_tls_client_ca_bundle_path =
        Some(broken.to_str().expect("utf8 path").to_string());
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .is_err(),
        "configured-but-unusable client trust must fail closed at startup, not serve CP material \
         under an unknown baseline"
    );

    // The usable configuration still loads, so the failure above is about the
    // material and not about the shape.
    env_config.frontend_tls_client_ca_bundle_path = Some(ca_path);
    assert!(
        ferrum_edge::modes::tls_reload::prepare_dp_operator_client_trust(&env_config, &crls)
            .expect("usable client trust loads")
            .is_some()
    );
}

/// End-to-end pairing contract for the CP-only-server-certificate shape:
/// arming with no server certificate, CP delivery, an accepted operator
/// withdrawal that never substitutes a server certificate, and a CP clear that
/// disables the listener instead of synthesizing one.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn dp_cp_only_certificate_arms_pairs_and_clears_without_synthesizing_a_certificate() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let withdrawn_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL, pki.client_serial], 2));
    let ca_path = dir.path().join("cp-only-pairing-ca.pem");
    std::fs::write(&ca_path, pki.ca_pem.as_bytes()).expect("write client CA");
    let ca_path = ca_path.to_str().expect("utf8 ca path").to_string();

    let startup_trust = trust_only_candidate(&ca_path, &startup_crls);
    let withdrawn_trust = trust_only_candidate(&ca_path, &withdrawn_crls);
    assert!(admits_client(&startup_trust, &pki));
    assert!(!admits_client(&withdrawn_trust, &pki));

    // The CP server certificate. Nothing operator-owned supplies one here.
    let cp = load_accepted_frontend(dir.path(), &pki, &startup_crls, "cp-only-server")
        .expect("CP candidate");

    let pairing = DpFrontendH3Pairing::from_operator_client_trust(startup_trust.clone());
    let listener_slot = ferrum_edge::tls::empty_frontend_tls_slot();
    assert!(
        pairing.h3_accepted().is_none(),
        "with no server certificate there is no coherent H3 candidate to adopt"
    );

    // Arming publishes the baseline and installs the live verifier the CP
    // snapshot's handshake wrapper consults, without exposing any config.
    let armed = pairing
        .publish_operator_client_trust(startup_trust.clone(), Some(&listener_slot), None)
        .await;
    assert!(armed.listener_config.is_none());
    assert!(
        listener_slot.load_full().as_ref().is_none(),
        "arming must not synthesize an operator server certificate"
    );
    assert!(pairing.h3_accepted().is_none());
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyFrontend).as_ref(),
        Some(&startup_trust.material),
        "the armed baseline must be the identity of the exact accepted load"
    );
    assert!(
        client_trust::armed_handshake_still_trusted(
            ClientTrustScope::ProxyFrontend,
            Some(&[pki.client_cert()])
        ),
        "the accepted verifier must be the live one new handshakes are checked against"
    );

    // CP delivers the server certificate; H3 gets one coherent pair.
    pairing
        .publish_cp_server_config(Some(cp.config.clone()), Some(&listener_slot), None)
        .await;
    assert!(std::sync::Arc::ptr_eq(
        listener_slot
            .load_full()
            .as_ref()
            .as_ref()
            .expect("CP config"),
        &cp.config
    ));
    let paired = pairing.h3_accepted().expect("paired H3 candidate");
    assert!(std::sync::Arc::ptr_eq(&paired.config, &cp.config));
    assert_eq!(paired.client_trust.material, startup_trust.material);

    // An accepted CRL withdrawal advances the scope and re-pairs, but never
    // replaces the CP-owned server certificate.
    let before = proxy_frontend_trust_snapshot().generation;
    let update = pairing
        .publish_operator_client_trust(withdrawn_trust.clone(), Some(&listener_slot), None)
        .await;
    assert!(
        !update.replace_listener,
        "an operator trust reload must not take the listener slot away from CP material"
    );
    assert!(std::sync::Arc::ptr_eq(
        listener_slot
            .load_full()
            .as_ref()
            .as_ref()
            .expect("CP config"),
        &cp.config
    ));
    let paired = pairing.h3_accepted().expect("re-paired H3 candidate");
    assert!(
        std::sync::Arc::ptr_eq(&paired.config, &cp.config),
        "H3 must keep the CP server certificate while adopting the new trust"
    );
    assert!(!admits_client(&paired.client_trust, &pki));
    let after = proxy_frontend_trust_snapshot();
    assert!(
        after.generation > before && after.withdrawal_generation == after.generation,
        "an accepted withdrawal must advance the generation and move the retirement fence"
    );
    assert!(
        !client_trust::armed_handshake_still_trusted(
            ClientTrustScope::ProxyFrontend,
            Some(&[pki.client_cert()])
        ),
        "new handshakes must meet the withdrawn verifier"
    );

    // Clearing CP material leaves nothing to serve: the listener is cleared and
    // HTTP/3 disabled, never backfilled with a synthesized certificate.
    let cleared = pairing
        .publish_cp_server_config(None, Some(&listener_slot), None)
        .await;
    assert!(cleared.replace_listener && cleared.listener_config.is_none());
    assert!(listener_slot.load_full().as_ref().is_none());
    assert!(
        pairing.h3_accepted().is_none(),
        "clearing CP material with no operator server certificate must disable HTTP/3"
    );
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyFrontend).as_ref(),
        Some(&withdrawn_trust.material),
        "a CP server-material change must not disturb the operator trust generation"
    );
}

/// A refused client-trust candidate never reaches the pairing, so the complete
/// last-good verifier, identity, generation and paired config are retained and
/// the refusal is accounted on the singular scope.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn dp_cp_only_certificate_refused_candidate_retains_last_good_state() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));
    let ca_path = dir.path().join("cp-only-refuse-ca.pem");
    std::fs::write(&ca_path, pki.ca_pem.as_bytes()).expect("write client CA");
    let ca_source = ca_path.to_str().expect("utf8 ca path").to_string();

    let startup_trust = trust_only_candidate(&ca_source, &startup_crls);
    let cp = load_accepted_frontend(dir.path(), &pki, &startup_crls, "cp-only-refuse-server")
        .expect("CP candidate");
    let pairing = DpFrontendH3Pairing::from_operator_client_trust(startup_trust.clone());
    let listener_slot = ferrum_edge::tls::empty_frontend_tls_slot();
    pairing
        .publish_operator_client_trust(startup_trust.clone(), Some(&listener_slot), None)
        .await;
    pairing
        .publish_cp_server_config(Some(cp.config.clone()), Some(&listener_slot), None)
        .await;
    let before_snapshot = proxy_frontend_trust_snapshot();
    let before_pair = pairing.h3_accepted().expect("paired candidate");

    // The watcher's load step now fails: the client-CA bundle is truncated to
    // material no verifier can be built from.
    std::fs::write(&ca_path, b"-----BEGIN CERTIFICATE-----\ntruncated\n").expect("break CA");
    let reload = ferrum_edge::tls::build_client_cert_verifier_candidate(&ca_source, &startup_crls);
    assert!(reload.is_err(), "the broken bundle must not load");
    client_trust::record_rejected_candidate(ClientTrustScope::ProxyFrontend);

    let after_snapshot = proxy_frontend_trust_snapshot();
    assert_eq!(after_snapshot.generation, before_snapshot.generation);
    assert_eq!(
        after_snapshot.withdrawal_generation,
        before_snapshot.withdrawal_generation
    );
    assert_eq!(
        after_snapshot.rejected_candidates,
        before_snapshot.rejected_candidates + 1,
        "a refused candidate must be accounted on the singular scope, not silently ignored"
    );
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyFrontend).as_ref(),
        Some(&startup_trust.material)
    );
    assert!(
        client_trust::armed_handshake_still_trusted(
            ClientTrustScope::ProxyFrontend,
            Some(&[pki.client_cert()])
        ),
        "the last-good live verifier must be retained"
    );
    let after_pair = pairing.h3_accepted().expect("retained pair");
    assert!(std::sync::Arc::ptr_eq(&before_pair, &after_pair));
    assert!(std::sync::Arc::ptr_eq(
        listener_slot
            .load_full()
            .as_ref()
            .as_ref()
            .expect("CP config"),
        &cp.config
    ));
}

/// Source-shape contract for the CP-only wiring: the data plane must arm and
/// watch operator client trust on the CP-only-certificate shape, and must not
/// do so when it owns an operator server certificate (that shape already has a
/// reload pipeline which owns the transaction).
#[test]
fn dp_cp_only_certificate_client_trust_is_wired_without_an_operator_certificate() {
    let dp = include_str!("../../../src/modes/data_plane.rs");
    let block = dp
        .find("let mut dp_client_trust_watcher")
        .expect("DP must arm operator client trust for the CP-only-certificate shape");
    assert_source_order(
        &dp[block..],
        &[
            "tls_config.is_none()",
            "prepare_dp_operator_client_trust",
            "from_operator_client_trust",
            "publish_operator_client_trust",
            "spawn_dp_operator_client_trust_watcher",
        ],
        "the CP-only path must be gated on owning no operator server certificate, then load, \
         seed the pairing, arm the baseline, and start the watcher",
    );

    let modes = include_str!("../../../src/modes/tls_reload.rs");
    let watcher = modes
        .find("pub fn spawn_dp_operator_client_trust_watcher")
        .expect("CP-only client-trust watcher");
    let watcher_end = modes[watcher..]
        .find("fn load_dp_operator_client_trust(")
        .expect("the coherent loader follows the watcher");
    let watcher_body = &modes[watcher..watcher + watcher_end];
    assert_source_order(
        watcher_body,
        &["record_rejected_candidate", "publish_operator_client_trust"],
        "a refused load must be recorded and must never reach the pairing publication",
    );
    assert!(
        !watcher_body.contains("frontend_tls_cert_path"),
        "the CP-only client-trust watcher must never read an operator server certificate"
    );

    let client = include_str!("../../../src/grpc/dp_client.rs");
    let paired = client
        .find("fn pair_h3_candidate(")
        .expect("pairing helper");
    assert!(
        client[paired..].contains("state.cp_config")
            && client[paired..].contains("or_else(|| state.operator_config.clone())?"),
        "CP material owns the server certificate, the operator's own certificate is the only \
         fallback, and neither present means no candidate at all"
    );
    let publish = client
        .find("pub async fn publish_operator_client_trust")
        .expect("CP-only client-trust publisher");
    assert_source_order(
        &client[publish..],
        &[
            "publish_accepted_rustls_candidate",
            "commit_listener_publication",
        ],
        "the rustls transaction must complete before the awaited stream-listener store",
    );
}

/// One coherent client-trust load with no operator server certificate — the
/// exact primitive the CP-only-certificate data plane arms and reloads from.
fn trust_only_candidate(ca_path: &str, crls: &CrlList) -> AcceptedClientTrust {
    let candidate = ferrum_edge::tls::build_client_cert_verifier_candidate(ca_path, crls)
        .expect("client trust candidate");
    AcceptedClientTrust {
        verifier: Some(candidate.verifier),
        material: candidate.material,
    }
}

/// `ClientTrustScope::index` is private, so select the row by scope.
fn proxy_frontend_trust_snapshot() -> client_trust::ClientTrustScopeSnapshot {
    client_trust::snapshot()
        .into_iter()
        .find(|row| row.scope == ClientTrustScope::ProxyFrontend)
        .expect("proxy_frontend trust scope row")
}

struct IssuedClient {
    ca_pem: String,
    cert_der: Vec<u8>,
    key_pem: String,
}

fn issue_client_under_new_ca(cn: &str, serial: u64) -> IssuedClient {
    ensure_crypto_provider();
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("{cn} CA"));
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    client_params.serial_number = Some(rcgen::SerialNumber::from(serial));
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");

    IssuedClient {
        ca_pem: ca_cert.pem(),
        cert_der: client_cert.der().to_vec(),
        key_pem: client_key.serialize_pem(),
    }
}

fn self_signed_server(cn: &str) -> (String, String, Vec<u8>) {
    ensure_crypto_provider();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let params = rcgen::CertificateParams::new(vec![cn.to_string()]).expect("server params");
    let cert = params.self_signed(&key).expect("self-signed server cert");
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

fn parse_client_key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("read client key")
}

fn mtls_client_config(cert_der: &[u8], key_pem: &str) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(ferrum_edge::tls::NoVerifier))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            parse_client_key(key_pem),
        )
        .expect("client auth cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// A client that withholds its certificate unless CertificateRequest CA names
/// are unconstrained (empty) or include this certificate's issuer. rustls
/// `with_client_auth_cert` ignores those hints, so it cannot prove the live
/// wrapper stopped advertising a stale snapshot CA list.
struct HintHonoringClientCert {
    key: std::sync::Arc<CertifiedKey>,
    issuer_subjects: Vec<Vec<u8>>,
}

impl std::fmt::Debug for HintHonoringClientCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HintHonoringClientCert").finish()
    }
}

impl ResolvesClientCert for HintHonoringClientCert {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<CertifiedKey>> {
        if root_hint_subjects.is_empty()
            || self
                .issuer_subjects
                .iter()
                .any(|subject| root_hint_subjects.contains(&subject.as_slice()))
        {
            Some(self.key.clone())
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn mtls_client_config_honoring_ca_hints(
    cert_der: &[u8],
    key_pem: &str,
    issuer_ca_pem: &str,
) -> ClientConfig {
    let certified = std::sync::Arc::new(
        CertifiedKey::from_der(
            vec![CertificateDer::from(cert_der.to_vec())],
            parse_client_key(key_pem),
            &rustls::crypto::ring::default_provider(),
        )
        .expect("client certified key"),
    );
    let certs = CertificateDer::pem_slice_iter(issuer_ca_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse issuer CA");
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).expect("issuer CA is a trust anchor");
    }
    let issuer_subjects: Vec<Vec<u8>> = roots
        .subjects()
        .into_iter()
        .map(|dn| dn.as_ref().to_vec())
        .collect();
    assert!(
        !issuer_subjects.is_empty(),
        "hint-honoring client must know its issuer subject"
    );
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(ferrum_edge::tls::NoVerifier))
        .with_client_cert_resolver(std::sync::Arc::new(HintHonoringClientCert {
            key: certified,
            issuer_subjects,
        }));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Drive one real rustls handshake through `server_config` and return the
/// leaf the server presented. The handshake is the only way to observe the
/// live wrapper baked into a CP `ServerConfig`.
///
/// TLS 1.3 verifies client certificates on the server after the client has
/// already sent Finished, so a rejected client certificate can complete
/// `connect()` successfully and fail `accept()`. Honor the server outcome;
/// otherwise fail-closed proofs look like a successful handshake.
async fn handshake_presented_leaf(
    server_config: std::sync::Arc<rustls::ServerConfig>,
    client_config: ClientConfig,
) -> Result<Vec<u8>, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TlsAcceptor::from(server_config);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        acceptor.accept(stream).await
    });

    let connector = TlsConnector::from(std::sync::Arc::new(client_config));
    let stream = TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from("localhost".to_string()).expect("server name");
    let client_result = connector.connect(name, stream).await;
    let server_result = server
        .await
        .unwrap_or_else(|join_err| Err(std::io::Error::other(join_err)));
    let tls_stream = match (client_result, server_result) {
        (Ok(tls_stream), Ok(_)) => tls_stream,
        (Err(err), _) | (_, Err(err)) => return Err(err),
    };
    Ok(tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|cert| cert.as_ref().to_vec())
        .expect("server presented a certificate"))
}

/// Under active CP server material, an accepted additive operator CA overlap
/// must be what a new H1/H2/TCP handshake verifies against, while the exact CP
/// server certificate/resolver stays in the listener slot (issue #3857). The
/// retained CP `ServerConfig` must not advertise a stale CertificateRequest
/// CA-name list: a client that honors those hints still presents a certificate
/// issued by the newly added CA.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn dp_h12_tcp_adopts_additive_operator_verifier_while_retaining_cp_server_cert() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let extra = issue_client_under_new_ca("overlap-client", 0x3858);
    let (cp_cert_pem, cp_key_pem, cp_cert_der) = self_signed_server("cp.example.test");
    let (operator_cert_pem, operator_key_pem, _) = self_signed_server("operator.example.test");
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));

    let cp_startup = load_accepted_frontend_parts(
        dir.path(),
        "cp-server",
        &cp_cert_pem,
        &cp_key_pem,
        &pki.ca_pem,
        &startup_crls,
        Some(ClientTrustScope::ProxyFrontend),
    )
    .expect("CP candidate with live wrapper");
    let operator_startup = load_accepted_frontend_parts(
        dir.path(),
        "operator-startup",
        &operator_cert_pem,
        &operator_key_pem,
        &pki.ca_pem,
        &startup_crls,
        None,
    )
    .expect("operator startup candidate");

    let pairing = DpFrontendH3Pairing::from_operator_candidate(operator_startup);
    let listener = ferrum_edge::tls::empty_frontend_tls_slot();
    pairing
        .publish_cp_server_config(Some(cp_startup.config.clone()), Some(&listener), None)
        .await;

    let listener_before = listener
        .load_full()
        .as_ref()
        .clone()
        .expect("CP config on the H1/H2/TCP slot");
    assert!(std::sync::Arc::ptr_eq(&listener_before, &cp_startup.config));
    assert!(std::sync::Arc::ptr_eq(
        &listener_before.cert_resolver,
        &cp_startup.config.cert_resolver
    ));

    let ca1_client = mtls_client_config(&pki.client_der, &pki.client_key_pem);
    let ca2_client =
        mtls_client_config_honoring_ca_hints(&extra.cert_der, &extra.key_pem, &extra.ca_pem);
    let wrapper = client_trust::bind_live_handshake_verifier(
        ClientTrustScope::ProxyFrontend,
        cp_startup
            .client_trust
            .verifier
            .clone()
            .expect("CP candidate installs a verifier"),
    );
    assert!(
        wrapper.root_hint_subjects().is_empty(),
        "live wrapper must expose no snapshot CertificateRequest CA-name constraint"
    );
    assert!(
        !cp_startup
            .client_trust
            .verifier
            .as_ref()
            .expect("CP inner verifier")
            .root_hint_subjects()
            .is_empty(),
        "the snapshot inner verifier still has CA names; the wrapper must not forward them"
    );
    assert!(
        cp_startup
            .client_trust
            .verifier
            .as_ref()
            .expect("CP inner verifier")
            .verify_client_cert(
                &CertificateDer::from(extra.cert_der.clone()),
                &[],
                UnixTime::now(),
            )
            .is_err(),
        "the extra CA is not in the snapshot inner verifier until the operator reload publishes"
    );
    assert!(
        wrapper
            .verify_client_cert(
                &CertificateDer::from(extra.cert_der.clone()),
                &[],
                UnixTime::now(),
            )
            .is_err(),
        "unpublished live wrapper falls back to the inner verifier and must not admit the extra CA"
    );
    assert_eq!(
        handshake_presented_leaf(listener_before.clone(), ca1_client.clone())
            .await
            .expect("CA1 client is admitted by the snapshot verifier"),
        cp_cert_der,
        "the CP server certificate must be the one presented"
    );
    assert!(
        handshake_presented_leaf(listener_before.clone(), ca2_client.clone())
            .await
            .is_err(),
        "a hint-honoring extra-CA handshake must fail closed on the retained CP config until the operator reload publishes"
    );

    let overlap_pem = format!("{}{}", pki.ca_pem, extra.ca_pem);
    let operator_overlap = load_accepted_frontend_parts(
        dir.path(),
        "operator-overlap",
        &operator_cert_pem,
        &operator_key_pem,
        &overlap_pem,
        &startup_crls,
        None,
    )
    .expect("additive operator candidate");
    assert!(
        operator_overlap
            .client_trust
            .verifier
            .as_ref()
            .expect("overlap verifier")
            .verify_client_cert(
                &CertificateDer::from(extra.cert_der.clone()),
                &[],
                UnixTime::now()
            )
            .is_ok(),
        "the accepted operator verifier must admit the extra CA"
    );

    // Production publishes the live ProxyFrontend verifier before pairing.
    let publication = publish_rustls(
        ClientTrustScope::ProxyFrontend,
        &operator_overlap.client_trust,
    );
    assert!(
        publication.outcome == ClientTrustPublicationOutcome::Armed
            || publication.outcome == ClientTrustPublicationOutcome::Advanced,
        "additive overlap must arm or advance, never withdraw: {:?}",
        publication.outcome
    );

    let update = pairing
        .publish_operator_candidate(operator_overlap.clone(), Some(&listener), None)
        .await;
    assert!(
        !update.replace_listener,
        "an additive operator trust reload must not substitute the operator server certificate"
    );

    let listener_after = listener
        .load_full()
        .as_ref()
        .clone()
        .expect("CP config retained");
    assert!(
        std::sync::Arc::ptr_eq(&listener_after, &cp_startup.config),
        "H1/H2/TCP must keep the exact CP ServerConfig Arc"
    );
    assert!(
        std::sync::Arc::ptr_eq(
            &listener_after.cert_resolver,
            &cp_startup.config.cert_resolver
        ),
        "H1/H2/TCP must keep the exact CP server certificate resolver"
    );
    assert!(!std::sync::Arc::ptr_eq(
        &listener_after,
        &operator_overlap.config
    ));

    let presented = handshake_presented_leaf(listener_after.clone(), ca2_client)
        .await
        .expect("hint-honoring additive CA client must complete the retained-CP handshake");
    assert_eq!(
        presented, cp_cert_der,
        "the additive handshake must still present the CP server certificate"
    );
    assert_eq!(
        handshake_presented_leaf(listener_after, ca1_client)
            .await
            .expect("original CA remains trusted under additive overlap"),
        cp_cert_der
    );

    let h3 = pairing.h3_accepted().expect("paired H3 candidate");
    assert!(
        std::sync::Arc::ptr_eq(&h3.config, &cp_startup.config),
        "H3 must keep the CP server certificate"
    );
    assert_eq!(
        h3.client_trust.material, operator_overlap.client_trust.material,
        "H3 must adopt the accepted additive operator trust"
    );
}

/// A refused later operator candidate never reaches pairing, so the H1/H2/TCP
/// slot keeps the last-good CP config and the live wrapper keeps admitting the
/// last accepted overlap verifier.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn dp_refused_operator_candidate_retains_cp_config_and_last_good_verifier() {
    let _guard = isolated_registry();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = build_pki();
    let extra = issue_client_under_new_ca("overlap-client", 0x3858);
    let (cp_cert_pem, cp_key_pem, cp_cert_der) = self_signed_server("cp.example.test");
    let startup_crls = parse_crls(&pki.crl_pem(&[UNRELATED_SERIAL], 1));

    let cp_startup = load_accepted_frontend_parts(
        dir.path(),
        "cp-server",
        &cp_cert_pem,
        &cp_key_pem,
        &pki.ca_pem,
        &startup_crls,
        Some(ClientTrustScope::ProxyFrontend),
    )
    .expect("CP candidate");
    let operator_startup = load_accepted_frontend_parts(
        dir.path(),
        "operator-startup",
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &pki.ca_pem,
        &startup_crls,
        None,
    )
    .expect("operator startup");

    let pairing = DpFrontendH3Pairing::from_operator_candidate(operator_startup);
    let listener = ferrum_edge::tls::empty_frontend_tls_slot();
    pairing
        .publish_cp_server_config(Some(cp_startup.config.clone()), Some(&listener), None)
        .await;

    let overlap_pem = format!("{}{}", pki.ca_pem, extra.ca_pem);
    let operator_overlap = load_accepted_frontend_parts(
        dir.path(),
        "operator-overlap",
        &pki.server_cert_pem,
        &pki.server_key_pem,
        &overlap_pem,
        &startup_crls,
        None,
    )
    .expect("additive operator candidate");
    publish_rustls(
        ClientTrustScope::ProxyFrontend,
        &operator_overlap.client_trust,
    );
    pairing
        .publish_operator_candidate(operator_overlap.clone(), Some(&listener), None)
        .await;

    let before = pairing.h3_accepted().expect("paired");
    let listener_before = listener.load_full().as_ref().clone().expect("CP config");

    // Production never calls publish_operator_candidate for a refused load.
    let refused = load_frontend_tls_candidate_from_paths(
        dir.path()
            .join("operator-overlap-server-cert.pem")
            .to_str()
            .expect("utf8"),
        dir.path()
            .join("operator-overlap-server-key.pem")
            .to_str()
            .expect("utf8"),
        Some("this-is-not-a-certificate"),
        None,
        false,
        &tls_policy(),
        30,
        30,
        &startup_crls,
        None,
    );
    assert!(
        refused.is_err(),
        "a malformed client-CA path must fail closed rather than publishing"
    );
    let after = pairing.h3_accepted().expect("retained");
    assert!(std::sync::Arc::ptr_eq(&before, &after));
    assert!(std::sync::Arc::ptr_eq(
        listener.load_full().as_ref().as_ref().expect("retained CP"),
        &listener_before
    ));
    assert_eq!(
        handshake_presented_leaf(
            listener_before,
            mtls_client_config_honoring_ca_hints(&extra.cert_der, &extra.key_pem, &extra.ca_pem),
        )
        .await
        .expect("last-good overlap verifier must still admit a hint-honoring extra-CA client"),
        cp_cert_der
    );
}
