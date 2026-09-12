//! Frontend client-trust generations and established-transport retirement
//! (issue #3857).
//!
//! Covers the semantic diff (what does and does not count as a withdrawal), the
//! publication state machine, the admission fence, the register-across-
//! publication race, exactly-once retirement accounting, the fenced stream
//! wrapper, and metric/label redaction.
//!
//! The trust registry is process-global by design — it is the thing every
//! listener consults — so these tests serialize on one lock and reset it
//! between cases.

use std::sync::{Mutex, MutexGuard, OnceLock};

#[path = "../../common/crl_fixtures.rs"]
mod crl_fixtures;

use ferrum_edge::tls::TrustFencedStream;
use ferrum_edge::tls::client_trust::{
    self, ClientTrustMaterial, ClientTrustPublicationOutcome, ClientTrustRetirementReason,
    ClientTrustScope,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::CertificateRevocationListDer;

/// The one lock every test in this binary that touches the process-global trust
/// registry must hold. `frontend_trust_binding_tests` shares it, because
/// `reset_for_test` clears every scope: two files with private locks would reset
/// each other mid-test.
pub(crate) fn registry_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Take the registry lock and reset every scope. Held for the test body.
pub(crate) fn isolated_registry() -> MutexGuard<'static, ()> {
    let guard = registry_lock();
    client_trust::reset_for_test();
    guard
}

// ---------------------------------------------------------------------------
// Material helpers
// ---------------------------------------------------------------------------

struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn generate_ca(cn: &str) -> TestCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-signed CA");
    let cert_pem = cert.pem();
    TestCa {
        cert_pem,
        issuer: Issuer::new(params, key_pair),
    }
}

fn crl_pem(ca: &TestCa, serials: &[u64], crl_number: u64) -> String {
    crl_pem_with_key_id(ca, serials, crl_number, rcgen::KeyIdMethod::Sha256)
}

fn crl_pem_with_key_id(
    ca: &TestCa,
    serials: &[u64],
    crl_number: u64,
    key_identifier_method: rcgen::KeyIdMethod,
) -> String {
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs = serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method,
    }
    .signed_by(&ca.issuer)
    .expect("sign CRL")
    .pem()
    .expect("CRL PEM")
}

fn parse_crls(pem: &str) -> Vec<CertificateRevocationListDer<'static>> {
    rustls_pemfile::crls(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse CRLs")
}

fn first_cert_der(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .expect("certificate block")
        .expect("PEM-decode")
        .as_ref()
        .to_vec()
}

fn certificate_pem(der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

fn material(ca_pems: &[&str], crl_pems: &[&str]) -> ClientTrustMaterial {
    let bundle = ca_pems.concat();
    let crl_bundle = crl_pems.concat();
    let crls = if crl_bundle.is_empty() {
        Vec::new()
    } else {
        parse_crls(&crl_bundle)
    };
    let ca_bytes = (!bundle.is_empty()).then(|| bundle.into_bytes());
    ClientTrustMaterial::from_parts(ca_bytes.as_deref(), &crls).expect("summarize material")
}

/// Deterministic named client-CA bundle material.
///
/// The same `cn` always yields the same trust anchor for the life of the test
/// binary, so subset relationships between two calls are meaningful: publishing
/// `["ca-a", "ca-b"]` and then `["ca-b"]` is a real CA withdrawal, not two
/// unrelated bundles that merely happen to differ.
pub(crate) fn test_material(cns: &[&str]) -> ClientTrustMaterial {
    static CAS: OnceLock<Mutex<std::collections::HashMap<String, String>>> = OnceLock::new();
    let mut cache = CAS
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let pems: Vec<String> = cns
        .iter()
        .map(|cn| {
            cache
                .entry((*cn).to_string())
                .or_insert_with(|| generate_ca(cn).cert_pem)
                .clone()
        })
        .collect();
    let refs: Vec<&str> = pems.iter().map(String::as_str).collect();
    material(&refs, &[])
}

fn scope_row(scope: ClientTrustScope) -> ferrum_edge::tls::client_trust::ClientTrustScopeSnapshot {
    client_trust::snapshot()
        .into_iter()
        .find(|row| row.scope == scope)
        .expect("every scope is present in a snapshot")
}

// ---------------------------------------------------------------------------
// Semantic diff
// ---------------------------------------------------------------------------

#[test]
fn a_reissued_crl_with_the_same_revocation_set_is_not_a_semantic_change() {
    let ca = generate_ca("trust-ca");
    // Same revoked serial, different CRL number and validity window — exactly
    // what a scheduled re-issue produces.
    let first = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 1)]);
    let second = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 2)]);

    assert_eq!(
        first, second,
        "a routine CRL re-issue over an unchanged revocation set must not read as a change"
    );
    assert_eq!(second.withdrawal_relative_to(&first), None);
}

#[test]
fn adding_a_revocation_is_a_crl_withdrawal() {
    let ca = generate_ca("trust-ca");
    let before = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 1)]);
    let after = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7, 9], 2)]);

    assert_ne!(before, after);
    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::CrlChanged)
    );
}

#[test]
fn removing_a_revocation_advances_without_withdrawing() {
    let ca = generate_ca("trust-ca");
    let before = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7, 9], 1)]);
    let after = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 2)]);

    assert_ne!(before, after, "the revocation set genuinely changed");
    assert_eq!(
        after.withdrawal_relative_to(&before),
        None,
        "un-revoking widens authority; it must not retire sessions"
    );
}

#[test]
fn an_additive_overlapping_ca_rotation_does_not_withdraw() {
    let old_ca = generate_ca("old-ca");
    let new_ca = generate_ca("new-ca");
    let before = material(&[&old_ca.cert_pem], &[]);
    let after = material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]);

    assert_ne!(before, after);
    assert_eq!(
        after.withdrawal_relative_to(&before),
        None,
        "an overlap rotation that only ADDS an anchor must not churn live sessions"
    );
}

#[test]
fn removing_a_ca_is_a_client_ca_withdrawal() {
    let old_ca = generate_ca("old-ca");
    let new_ca = generate_ca("new-ca");
    let before = material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]);
    let after = material(&[&new_ca.cert_pem], &[]);

    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::ClientCaWithdrawn)
    );
}

#[test]
fn a_ca_withdrawal_outranks_a_simultaneous_crl_addition() {
    let old_ca = generate_ca("old-ca");
    let new_ca = generate_ca("new-ca");
    let before = material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]);
    let after = material(&[&new_ca.cert_pem], &[&crl_pem(&new_ca, &[3], 1)]);

    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::ClientCaWithdrawn),
        "the broader withdrawal is the reported reason"
    );
}

#[test]
fn revocations_are_scoped_by_issuer_not_by_bare_serial() {
    let ca_a = generate_ca("ca-a");
    let ca_b = generate_ca("ca-b");
    // Serial 7 is revoked under CA A only. Moving that revocation to CA B is a
    // NEW revocation, not a no-op: serials are unique only within an issuer.
    let before = material(
        &[&ca_a.cert_pem, &ca_b.cert_pem],
        &[&crl_pem(&ca_a, &[7], 1)],
    );
    let after = material(
        &[&ca_a.cert_pem, &ca_b.cert_pem],
        &[&crl_pem(&ca_a, &[7], 2), &crl_pem(&ca_b, &[7], 1)],
    );

    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::CrlChanged),
        "the same serial under a different issuer is a distinct revocation"
    );
}

#[test]
fn revocations_are_scoped_by_signer_key_not_by_issuer_dn() {
    // Two distinct CA keys that share a subject DN and revoke the same leaf
    // serial. Hashing issuer DN || serial would collide and suppress the
    // second key's withdrawal.
    let ca_a = generate_ca("Shared CA Name");
    let ca_b = generate_ca("Shared CA Name");
    let before = material(
        &[&ca_a.cert_pem, &ca_b.cert_pem],
        &[&crl_pem(&ca_a, &[7], 1)],
    );
    let after = material(
        &[&ca_a.cert_pem, &ca_b.cert_pem],
        &[&crl_pem(&ca_a, &[7], 2), &crl_pem(&ca_b, &[7], 1)],
    );

    assert_ne!(
        before, after,
        "the same serial under a second key that shares the issuer DN is a distinct revocation"
    );
    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::CrlChanged),
        "adding the second issuer's revocation must be observed as a withdrawal"
    );
}

#[test]
fn a_same_signer_crl_reissue_stays_semantically_unchanged() {
    let ca = generate_ca("trust-ca");
    let first = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 1)]);
    let reissued = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 2)]);
    assert_eq!(first, reissued);
    assert_eq!(reissued.withdrawal_relative_to(&first), None);
}

#[test]
fn identical_signer_spkis_in_the_bundle_are_deduplicated() {
    let ca = generate_ca("trust-ca");
    let duplicated = format!("{}{}", ca.cert_pem, ca.cert_pem);
    let first = material(&[&duplicated], &[&crl_pem(&ca, &[7], 1)]);
    let reissued = material(&[&duplicated], &[&crl_pem(&ca, &[7], 2)]);
    assert_eq!(
        first, reissued,
        "repeating the same CA key in the bundle must not make a routine reissue look like a change"
    );
}

#[test]
fn an_outside_bundle_crl_reissue_conservatively_retires_sessions() {
    let trusted = generate_ca("trusted-ca");
    let unknown = generate_ca("unknown-ca");
    let first = material(&[&trusted.cert_pem], &[&crl_pem(&unknown, &[7], 1)]);
    let reissued = material(&[&trusted.cert_pem], &[&crl_pem(&unknown, &[7], 2)]);
    assert_eq!(
        reissued.withdrawal_relative_to(&first),
        Some(ClientTrustRetirementReason::CrlChanged),
        "without a verified signer SPKI, a reissue must conservatively retire rather than trust attacker-selectable issuer metadata"
    );

    let other_unknown = generate_ca("other-unknown-ca");
    let with_second = material(
        &[&trusted.cert_pem],
        &[
            &crl_pem(&unknown, &[7], 3),
            &crl_pem(&other_unknown, &[7], 1),
        ],
    );
    assert_eq!(
        with_second.withdrawal_relative_to(&first),
        Some(ClientTrustRetirementReason::CrlChanged),
        "a second unknown signer revoking the same serial is a distinct key-bound revocation"
    );
}

#[test]
fn outside_bundle_crl_signers_with_the_same_aki_remain_distinct() {
    let trusted = generate_ca("trusted-ca");
    // Distinct keys deliberately share both issuer DN and AKI. Neither field is
    // a cryptographic key identity, so the second revocation must not collide.
    let unknown_a = generate_ca("shared outside-bundle issuer");
    let unknown_b = generate_ca("shared outside-bundle issuer");
    let shared_aki = vec![0x42; 20];
    let first_crl = crl_pem_with_key_id(
        &unknown_a,
        &[7],
        1,
        rcgen::KeyIdMethod::PreSpecified(shared_aki.clone()),
    );
    let reissued_first = crl_pem_with_key_id(
        &unknown_a,
        &[7],
        2,
        rcgen::KeyIdMethod::PreSpecified(shared_aki.clone()),
    );
    let second_crl = crl_pem_with_key_id(
        &unknown_b,
        &[7],
        1,
        rcgen::KeyIdMethod::PreSpecified(shared_aki),
    );

    let before = material(&[&trusted.cert_pem], &[&first_crl]);
    let after = material(&[&trusted.cert_pem], &[&reissued_first, &second_crl]);
    assert_eq!(
        after.withdrawal_relative_to(&before),
        Some(ClientTrustRetirementReason::CrlChanged),
        "issuer-DN and AKI reuse by a distinct outside-bundle key must not suppress a new revocation"
    );
}

#[test]
fn a_crl_with_no_identifiable_issuer_key_is_refused() {
    let trusted = generate_ca("trusted-ca");
    let unknown = generate_ca("unknown-ca");
    let empty_aki = crl_pem_with_key_id(
        &unknown,
        &[7],
        1,
        rcgen::KeyIdMethod::PreSpecified(Vec::new()),
    );
    assert!(
        ClientTrustMaterial::from_parts(Some(trusted.cert_pem.as_bytes()), &parse_crls(&empty_aki))
            .is_err(),
        "a CRL whose signer is not in the bundle and whose AKI is empty must fail closed"
    );
}

#[test]
fn a_crl_with_trailing_der_is_refused() {
    let ca = generate_ca("trust-ca");
    let mut trailing = parse_crls(&crl_pem(&ca, &[7], 1));
    let mut der = trailing.remove(0).as_ref().to_vec();
    der.push(0x00);
    let broken = vec![CertificateRevocationListDer::from(der)];
    assert!(
        ClientTrustMaterial::from_parts(Some(ca.cert_pem.as_bytes()), &broken).is_err(),
        "trailing unconsumed CRL DER must fail closed"
    );
}

#[test]
fn a_malformed_crl_candidate_is_refused_rather_than_summarized() {
    let ca = generate_ca("trust-ca");
    let mut truncated = parse_crls(&crl_pem(&ca, &[7], 1));
    let der = truncated.remove(0).as_ref().to_vec();
    let half = der[..der.len() / 2].to_vec();
    let broken = vec![CertificateRevocationListDer::from(half)];

    assert!(
        ClientTrustMaterial::from_parts(Some(ca.cert_pem.as_bytes()), &broken).is_err(),
        "a truncated CRL must fail closed, never summarize to an empty revocation set"
    );
}

#[test]
fn a_malformed_ca_bundle_is_refused_rather_than_summarized() {
    let garbage = b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n";
    assert!(
        ClientTrustMaterial::from_parts(Some(garbage), &[]).is_err(),
        "an unparseable client-CA bundle must fail closed"
    );
}

#[test]
fn a_base64_decodable_non_x509_ca_block_is_refused() {
    let garbage = certificate_pem(b"not an X.509 certificate");
    assert!(
        ClientTrustMaterial::from_parts(Some(garbage.as_bytes()), &[]).is_err(),
        "PEM-decoded non-X.509 bytes must not become a trust-anchor identity"
    );
}

#[test]
fn a_ca_block_with_trailing_or_partial_der_is_refused() {
    let ca = generate_ca("trust-ca");
    let der = first_cert_der(&ca.cert_pem);

    let mut trailing = der.clone();
    trailing.push(0x00);
    assert!(
        ClientTrustMaterial::from_parts(Some(certificate_pem(&trailing).as_bytes()), &[]).is_err(),
        "trailing unconsumed DER must fail closed"
    );

    let partial = &der[..der.len() / 2];
    assert!(
        ClientTrustMaterial::from_parts(Some(certificate_pem(partial).as_bytes()), &[]).is_err(),
        "a truncated certificate DER must fail closed"
    );
}

#[test]
fn one_invalid_ca_block_refuses_the_entire_bundle() {
    let ca = generate_ca("trust-ca");
    let mixed = format!(
        "{}{}",
        ca.cert_pem,
        certificate_pem(b"not an X.509 certificate")
    );
    assert!(
        ClientTrustMaterial::from_parts(Some(mixed.as_bytes()), &[]).is_err(),
        "an invalid certificate block must fail the whole candidate, not skip it"
    );
}

// ---------------------------------------------------------------------------
// Publication state machine
// ---------------------------------------------------------------------------

#[test]
fn arming_publishes_generation_one_and_retires_nothing() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");

    assert!(
        client_trust::capture(ClientTrustScope::ProxyFrontend).is_none(),
        "an unarmed scope must cost listeners nothing"
    );

    let publication = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );

    assert_eq!(publication.outcome, ClientTrustPublicationOutcome::Armed);
    assert_eq!(publication.generation, 1);
    assert_eq!(publication.retired_sessions, 0);
    assert_eq!(publication.reason, None);
    assert_eq!(
        client_trust::capture(ClientTrustScope::ProxyFrontend)
            .expect("armed")
            .generation(),
        1
    );
}

#[test]
fn an_unchanged_candidate_does_not_advance_the_generation() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    let snapshot = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 1)]);
    client_trust::publish_accepted_material(ClientTrustScope::AdminHttps, snapshot);

    // A CRL re-issue with the same revocation set summarizes identically.
    let reissued = material(&[&ca.cert_pem], &[&crl_pem(&ca, &[7], 2)]);
    let publication =
        client_trust::publish_accepted_material(ClientTrustScope::AdminHttps, reissued);

    assert_eq!(
        publication.outcome,
        ClientTrustPublicationOutcome::Unchanged
    );
    assert_eq!(publication.generation, 1, "generation must not advance");
    let row = scope_row(ClientTrustScope::AdminHttps);
    assert_eq!(row.publications[1], 1, "one unchanged publication recorded");
    assert_eq!(row.withdrawal_generation, 0);
}

#[test]
fn an_additive_change_advances_without_moving_the_fence() {
    let _guard = isolated_registry();
    let old_ca = generate_ca("old-ca");
    let new_ca = generate_ca("new-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&old_ca.cert_pem], &[]),
    );

    let publication = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]),
    );

    assert_eq!(publication.outcome, ClientTrustPublicationOutcome::Advanced);
    assert_eq!(publication.generation, 2);
    assert_eq!(publication.retired_sessions, 0);
    assert_eq!(
        scope_row(ClientTrustScope::ProxyFrontend).withdrawal_generation,
        0
    );
}

#[test]
fn scopes_are_independent_trust_domains() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    let baseline = material(&[&ca.cert_pem], &[]);
    client_trust::publish_accepted_material(ClientTrustScope::ProxyFrontend, baseline.clone());
    client_trust::publish_accepted_material(ClientTrustScope::AdminHttps, baseline);

    let proxy_session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("client-cert transport is registered");
    let admin_session = client_trust::capture(ClientTrustScope::AdminHttps)
        .expect("armed")
        .register(true)
        .expect("client-cert transport is registered");

    // Withdraw on the proxy scope only.
    client_trust::publish_accepted_material(ClientTrustScope::ProxyFrontend, material(&[], &[]));

    assert!(proxy_session.session().is_retired());
    assert!(
        !admin_session.session().is_retired(),
        "a proxy-scope withdrawal must not tear down admin-scope sessions"
    );
}

// ---------------------------------------------------------------------------
// Registration, fencing, and races
// ---------------------------------------------------------------------------

#[test]
fn an_anonymous_tls_transport_is_never_registered() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );

    assert!(
        client_trust::capture(ClientTrustScope::ProxyFrontend)
            .expect("armed")
            .register(false)
            .is_none(),
        "a transport with no verified client certificate holds no withdrawable decision"
    );
    assert_eq!(
        scope_row(ClientTrustScope::ProxyFrontend).tracked_sessions,
        0
    );
}

#[test]
fn a_withdrawal_retires_only_transports_below_the_new_generation() {
    let _guard = isolated_registry();
    let old_ca = generate_ca("old-ca");
    let new_ca = generate_ca("new-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]),
    );

    let established = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    let publication = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&new_ca.cert_pem], &[]),
    );
    assert_eq!(
        publication.outcome,
        ClientTrustPublicationOutcome::Withdrawn
    );
    assert_eq!(
        publication.reason,
        Some(ClientTrustRetirementReason::ClientCaWithdrawn)
    );
    assert_eq!(publication.retired_sessions, 1);
    assert!(established.session().is_retired());

    // A connection handshaking against the NEW verifier captures the new
    // generation and must not be retired by the withdrawal that produced it.
    let post_reload = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");
    assert_eq!(post_reload.session().generation(), publication.generation);
    assert!(
        !post_reload.session().is_retired(),
        "a connection admitted under the new generation must survive"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn retirement_resolves_the_session_wait_future() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[&crl_pem(&ca, &[1], 1)]),
    );
    let session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    let waiting = session.session().clone();
    let waiter = tokio::spawn(async move { waiting.retired().await });

    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[&crl_pem(&ca, &[1, 42], 2)]),
    );

    tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("a retired session must wake its waiter")
        .expect("waiter task");
}

#[test]
fn a_session_registered_after_the_sweep_cannot_escape_the_fence() {
    let _guard = isolated_registry();
    // Model the exact race: a connection captures the pre-publication
    // generation, the publication moves the fence and sweeps an empty registry,
    // and only then does the connection register.
    client_trust::arm_at_generation_for_test(ClientTrustScope::ProxyH3, 4);
    let admission = client_trust::capture(ClientTrustScope::ProxyH3).expect("armed");
    assert_eq!(admission.generation(), 4);

    client_trust::force_withdrawal_fence_for_test(
        ClientTrustScope::ProxyH3,
        5,
        ClientTrustRetirementReason::CrlChanged,
    );

    let late = admission.register(true).expect("registered");
    assert!(
        late.session().is_retired(),
        "a registration that lands behind the sweep must self-retire, not repopulate the domain"
    );
    assert_eq!(
        scope_row(ClientTrustScope::ProxyH3).retirements[1],
        1,
        "the late retirement is accounted exactly once, under the recorded reason"
    );
}

#[test]
fn retirement_accounting_fires_exactly_once_across_repeated_withdrawals() {
    let _guard = isolated_registry();
    let ca_a = generate_ca("ca-a");
    let ca_b = generate_ca("ca-b");
    let ca_c = generate_ca("ca-c");
    client_trust::publish_accepted_material(
        ClientTrustScope::FrontendDtls,
        material(&[&ca_a.cert_pem, &ca_b.cert_pem, &ca_c.cert_pem], &[]),
    );
    let session = client_trust::capture(ClientTrustScope::FrontendDtls)
        .expect("armed")
        .register(true)
        .expect("registered");

    let first = client_trust::publish_accepted_material(
        ClientTrustScope::FrontendDtls,
        material(&[&ca_b.cert_pem, &ca_c.cert_pem], &[]),
    );
    let second = client_trust::publish_accepted_material(
        ClientTrustScope::FrontendDtls,
        material(&[&ca_c.cert_pem], &[]),
    );

    assert_eq!(first.retired_sessions, 1);
    assert_eq!(
        second.retired_sessions, 0,
        "an already-retired session must not be counted a second time"
    );
    assert!(session.session().is_retired());
    let row = scope_row(ClientTrustScope::FrontendDtls);
    assert_eq!(
        row.retirements[0], 1,
        "exactly one retirement is accounted for the transport"
    );
}

#[test]
fn dropping_the_guard_deregisters_the_transport() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );

    {
        let _session = client_trust::capture(ClientTrustScope::ProxyFrontend)
            .expect("armed")
            .register(true)
            .expect("registered");
        assert_eq!(
            scope_row(ClientTrustScope::ProxyFrontend).tracked_sessions,
            1
        );
    }

    assert_eq!(
        scope_row(ClientTrustScope::ProxyFrontend).tracked_sessions,
        0,
        "a closed transport must leave the retirement domain"
    );
}

#[test]
fn a_cloned_session_that_outlives_the_guard_is_still_retired() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );

    let clone = {
        let guard = client_trust::capture(ClientTrustScope::ProxyFrontend)
            .expect("armed")
            .register(true)
            .expect("registered");
        let clone = guard.session().clone();
        drop(guard);
        assert_eq!(
            scope_row(ClientTrustScope::ProxyFrontend).tracked_sessions,
            1,
            "a WebSocket-style clone that outlives the HTTP guard must stay in the retirement domain"
        );
        assert!(!clone.is_retired());
        clone
    };

    let withdrawn = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&generate_ca("replacement-ca").cert_pem], &[]),
    );
    assert_eq!(withdrawn.outcome, ClientTrustPublicationOutcome::Withdrawn);
    assert_eq!(withdrawn.retired_sessions, 1);
    assert!(
        clone.is_retired(),
        "a withdrawal must cancel the clone that outlived the HTTP connection guard"
    );
}

#[test]
fn a_refused_candidate_retains_generation_material_and_sessions() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );
    let session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    // A malformed reload candidate never reaches publication; the caller records
    // the refusal instead.
    client_trust::record_rejected_candidate(ClientTrustScope::ProxyFrontend);

    let row = scope_row(ClientTrustScope::ProxyFrontend);
    assert_eq!(row.generation, 1, "the last-good generation is retained");
    assert_eq!(row.withdrawal_generation, 0, "the fence did not move");
    assert_eq!(row.rejected_candidates, 1);
    assert!(
        !session.session().is_retired(),
        "a refused candidate must not tear down live sessions"
    );
    assert_eq!(
        client_trust::current_material(ClientTrustScope::ProxyFrontend),
        Some(material(&[&ca.cert_pem], &[])),
        "the last accepted material is retained for the next comparison"
    );
}

// ---------------------------------------------------------------------------
// Fenced stream wrapper
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // `isolated_registry()` must span awaits to serialize process-global registry state
async fn a_fenced_stream_relays_until_retirement_then_fails_bounded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[&crl_pem(&ca, &[1], 1)]),
    );
    let guard = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    let (client, mut peer) = tokio::io::duplex(1024);
    let mut fenced = TrustFencedStream::new(client, Some(guard.session()));
    assert!(fenced.is_fencing());

    fenced
        .write_all(b"before")
        .await
        .expect("write before fence");
    let mut received = [0u8; 6];
    peer.read_exact(&mut received).await.expect("peer read");
    assert_eq!(&received, b"before");

    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[&crl_pem(&ca, &[1, 11], 2)]),
    );

    let error = fenced
        .write_all(b"after")
        .await
        .expect_err("a retired transport must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    let rendered = error.to_string();
    assert!(
        !rendered.contains("11") && !rendered.contains("trust-ca"),
        "the fenced-stream error must not disclose a serial or a subject: {rendered}"
    );

    // Shutdown stays available so the relay can still half-close cleanly.
    fenced.shutdown().await.expect("shutdown after fence");
}

#[tokio::test]
async fn an_unfenced_stream_is_a_transparent_passthrough() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut peer) = tokio::io::duplex(1024);
    let mut plain = TrustFencedStream::new(client, None);
    assert!(!plain.is_fencing());

    plain.write_all(b"payload").await.expect("write");
    let mut received = [0u8; 7];
    peer.read_exact(&mut received).await.expect("read");
    assert_eq!(&received, b"payload");
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[test]
fn an_unarmed_process_renders_no_client_trust_series() {
    let _guard = isolated_registry();
    let mut output = String::new();
    client_trust::render_prometheus(&mut output, "");
    assert!(
        output.is_empty(),
        "a deployment without frontend client-trust material must pay no scrape bytes"
    );
}

#[test]
fn rendered_series_carry_only_closed_vocabularies_and_no_certificate_fields() {
    let _guard = isolated_registry();
    let old_ca = generate_ca("old-ca-subject-name");
    let new_ca = generate_ca("new-ca-subject-name");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&old_ca.cert_pem, &new_ca.cert_pem], &[]),
    );
    let _session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&new_ca.cert_pem], &[&crl_pem(&new_ca, &[4242], 1)]),
    );

    let mut output = String::new();
    client_trust::render_prometheus(&mut output, "");

    for expected in [
        "ferrum_frontend_client_trust_generation{scope=\"proxy_frontend\"} 2",
        "ferrum_frontend_client_trust_withdrawal_generation{scope=\"proxy_frontend\"} 2",
        "ferrum_frontend_client_trust_tracked_connections{scope=\"proxy_frontend\"} 1",
        concat!(
            "ferrum_frontend_client_trust_retired_connections_total",
            "{scope=\"proxy_frontend\",reason=\"client_ca_withdrawn\"} 1"
        ),
        concat!(
            "ferrum_frontend_client_trust_publications_total",
            "{scope=\"proxy_frontend\",outcome=\"withdrawn\"} 1"
        ),
    ] {
        assert!(
            output.contains(expected),
            "expected `{expected}` in rendered client-trust series:\n{output}"
        );
    }

    for forbidden in [
        "old-ca-subject-name",
        "new-ca-subject-name",
        "4242",
        "BEGIN CERTIFICATE",
    ] {
        assert!(
            !output.contains(forbidden),
            "rendered client-trust series must not disclose `{forbidden}`"
        );
    }

    // Only armed scopes are rendered; the vocabulary is closed.
    for scope in ["proxy_h3", "admin_https", "frontend_dtls"] {
        assert!(
            !output.contains(scope),
            "an unarmed scope must not be rendered: {scope}"
        );
    }
}

#[test]
fn the_fence_counter_records_refused_requests_per_scope() {
    let _guard = isolated_registry();
    let ca = generate_ca("trust-ca");
    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        material(&[&ca.cert_pem], &[]),
    );
    let session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    session.session().record_fenced();
    session.session().record_fenced();

    assert_eq!(scope_row(ClientTrustScope::ProxyFrontend).fenced, 2);
}

#[test]
fn scope_and_reason_labels_are_stable() {
    assert_eq!(ClientTrustScope::ProxyFrontend.label(), "proxy_frontend");
    assert_eq!(ClientTrustScope::ProxyH3.label(), "proxy_h3");
    assert_eq!(ClientTrustScope::AdminHttps.label(), "admin_https");
    assert_eq!(ClientTrustScope::FrontendDtls.label(), "frontend_dtls");
    assert_eq!(
        ClientTrustRetirementReason::ClientCaWithdrawn.label(),
        "client_ca_withdrawn"
    );
    assert_eq!(
        ClientTrustRetirementReason::CrlChanged.label(),
        "crl_changed"
    );
    assert_eq!(ClientTrustScope::ALL.len(), 4);
}

#[test]
fn outside_bundle_crls_without_aki_have_stable_distinct_identities() {
    let trusted = generate_ca("trusted");
    let first_signer = generate_ca("shared-outside-issuer");
    let second_signer = generate_ca("shared-outside-issuer");
    let no_aki = |ca: &TestCa, number| {
        crl_fixtures::without_authority_key_identifier(
            &crl_pem(ca, &[7], number),
            ca.issuer.key(),
            &ca.cert_pem,
        )
    };
    let first = no_aki(&first_signer, 1);
    let reissued = no_aki(&first_signer, 2);
    let second = no_aki(&second_signer, 1);
    let before = material(&[&trusted.cert_pem], &[&first]);
    assert_eq!(before, material(&[&trusted.cert_pem], &[&first]));
    for changed in [&reissued, &second] {
        let after = material(&[&trusted.cert_pem], &[changed]);
        assert_ne!(before, after);
        assert_eq!(
            after.withdrawal_relative_to(&before),
            Some(ClientTrustRetirementReason::CrlChanged)
        );
    }
    // A verified signer retains semantic reissue behavior without AKI.
    let verified = material(&[&first_signer.cert_pem], &[&first]);
    assert_eq!(verified, material(&[&first_signer.cert_pem], &[&reissued]));
}
