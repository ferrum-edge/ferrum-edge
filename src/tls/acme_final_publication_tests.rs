//! Final ACME renewal publication boundary (issue #2409 / PR #3506).
//!
//! Both final store writes are attempted under one lease fence even when the
//! first fails. Partial outcomes must not permanently wedge renewal: a
//! Valid-without-material order does not block retries, and material-without-
//! Valid uses the published certificate's exact `order_url` as durable
//! completion evidence for [`has_active_renewal_order`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeHttp01ChallengeRecord,
    AcmeHttp01OrderInput, AcmeIssuedCertificateInput, AcmeOrderFinalization, AcmeOrderRecord,
    AcmeOrderStatus, AcmeOrderStore, FinalRenewalPublication, commit_final_renewal_publication,
    has_active_renewal_order, inject_final_publication_certificate_write_fault_for_tests,
    inject_final_publication_order_write_fault_for_tests, map_final_renewal_publication_outcome,
};
use crate::tls::lease::{RenewalLeaseKeeper, TlsLeaseStore, acme_renewal_lease_name};
use crate::tls::private_file::PrivateFileFault;
use base64::Engine as _;
use tempfile::TempDir;

const DIRECTORY_URL: &str = "https://acme.example/directory";
const ORDER_URL: &str = "https://acme.example/order/1";
const OTHER_ORDER_URL: &str = "https://acme.example/order/2";
const TEST_RELOAD_SURFACE: &str = "final_publication_matrix_local_reload";

fn generated_cert_and_key() -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params =
        rcgen::CertificateParams::new(vec!["example.com".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

fn sample_certificate(
    id: &str,
    cert_pem: &str,
    key_pem: &str,
    order_url: Option<&str>,
) -> AcmeCertificateRecord {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: id.to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        order_url: order_url.map(str::to_string),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        chain_pem: None,
    })
    .expect("acme certificate record")
}

fn order_with(
    id: &str,
    certificate_id: &str,
    status: AcmeOrderStatus,
    order_url: Option<&str>,
) -> AcmeOrderRecord {
    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: id.to_string(),
        certificate_id: Some(certificate_id.to_string()),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
        order_url: order_url.map(str::to_string),
        status,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "example.com".to_string(),
            token: "tok_processing".to_string(),
            key_authorization: "tok_processing.thumbprint".to_string(),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        finalization: Some(test_finalization()),
        error: None,
    })
    .expect("acme order record")
}

/// Real generated material, so "was it cleared?" is a question about the write
/// path rather than about a placeholder that was never there.
fn test_finalization() -> AcmeOrderFinalization {
    AcmeOrderFinalization::generate(&["example.com".to_string()])
        .expect("generate finalization material")
}

fn processing_order(id: &str, certificate_id: &str) -> AcmeOrderRecord {
    order_with(
        id,
        certificate_id,
        AcmeOrderStatus::Processing,
        Some(ORDER_URL),
    )
}

fn takeover_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":99,"leases":{{"{name}":{{"#,
            r#""holder":"replica-b","#,
            r#""acquired_at":"2026-01-01T00:00:00Z","#,
            r#""expires_at":"2999-01-01T00:00:00Z","#,
            r#""fence":9999}}}}}}"#
        ),
        name = name
    )
}

fn assert_no_material_disclosure(message: &str, material: &[&str]) {
    assert!(
        !message.contains("BEGIN CERTIFICATE")
            && !message.contains("BEGIN PRIVATE KEY")
            && !message.contains("BEGIN EC PRIVATE KEY")
            && material.iter().all(|value| !message.contains(value)),
        "error must not disclose certificate or key material: {message}"
    );
}

/// Observe whether this outcome requested reload through the injected callback
/// instead of a process-global probe that parallel lib tests can populate.
fn track_reload_request(
    outcome: FinalRenewalPublication,
) -> (bool, Result<Vec<&'static str>, AcmeError>) {
    let requested = AtomicBool::new(false);
    let result = map_final_renewal_publication_outcome(outcome, || {
        requested.store(true, Ordering::SeqCst);
        vec![TEST_RELOAD_SURFACE]
    });
    (requested.load(Ordering::SeqCst), result)
}

/// Happy path: one fenced commit marks the order Valid then publishes
/// certificate material, and reload is requested.
#[tokio::test]
async fn final_publication_commits_order_then_certificate_under_one_lease_fence() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let keeper = RenewalLeaseKeeper::start(held, Duration::from_secs(60));

    let outcome = keeper
        .commit_fenced({
            let certificates = Arc::clone(&certificates);
            let orders = Arc::clone(&orders);
            move || commit_final_renewal_publication(&certificates, &orders, issued, order)
        })
        .await
        .expect("lease still held");
    assert!(matches!(outcome, FinalRenewalPublication::Complete));

    let (reload_requested, reloaded) = track_reload_request(outcome);
    let reloaded = reloaded.expect("complete publication");
    assert!(
        reload_requested,
        "successful publication must request material reload"
    );
    assert_eq!(
        reloaded,
        vec![TEST_RELOAD_SURFACE],
        "successful publication must return the reload callback's surfaces"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("cert published");
    assert_eq!(stored.cert_pem, cert_pem);
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Valid
    );
    let _ = keeper.finish().await;
}

/// If ownership is already gone, neither final write runs.
#[tokio::test]
async fn final_publication_runs_neither_write_when_lease_is_lost() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let keeper = RenewalLeaseKeeper::start(held, Duration::from_secs(60));

    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate takeover");

    let entered = Arc::new(AtomicBool::new(false));
    let saw_entry = Arc::clone(&entered);
    let outcome = keeper
        .commit_fenced({
            let certificates = Arc::clone(&certificates);
            let orders = Arc::clone(&orders);
            move || {
                saw_entry.store(true, Ordering::SeqCst);
                commit_final_renewal_publication(&certificates, &orders, issued, order)
            }
        })
        .await;
    assert!(
        outcome.is_err(),
        "a superseded owner must not enter the final publication closure"
    );
    assert!(
        !entered.load(Ordering::SeqCst),
        "fail-closed fencing must skip both final writes"
    );
    assert!(matches!(
        certificates.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing
    );
    let _ = keeper.finish().await;
}

/// Order-store failure still attempts certificate publication under the same
/// fence: new material lands, reload is requested, outcome is explicit failure
/// (not a renewed count), and the published order_url clears the stale active
/// order on a later scan.
#[tokio::test]
async fn order_failure_certificate_success_publishes_reloads_and_clears_active_order() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("edge-cert");
    let held = leases
        .try_acquire(&name, Duration::from_secs(60))
        .expect("claim")
        .expect("won");
    let keeper = RenewalLeaseKeeper::start(held, Duration::from_secs(60));

    let outcome = keeper
        .commit_fenced({
            let certificates = Arc::clone(&certificates);
            let orders = Arc::clone(&orders);
            move || {
                let _fault =
                    inject_final_publication_order_write_fault_for_tests(PrivateFileFault::Rename);
                commit_final_renewal_publication(&certificates, &orders, issued, order)
            }
        })
        .await
        .expect("lease still held for both attempted writes");
    assert!(matches!(
        outcome,
        FinalRenewalPublication::MaterialPublishedOrderNotCommitted(_)
    ));

    let (reload_requested, result) = track_reload_request(outcome);
    let error = result.expect_err("order write failed");
    let message = error.to_string();
    assert!(
        message.contains(
            "renewed certificate material published but marking the ACME order valid failed"
        ),
        "error must state material published without Valid: {message}"
    );
    assert_no_material_disclosure(&message, &[&cert_pem, &key_pem]);
    assert!(
        reload_requested,
        "published material must request reload even when Valid failed"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("new material must persist");
    assert_eq!(stored.cert_pem, cert_pem);
    assert_eq!(stored.order_url.as_deref(), Some(ORDER_URL));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing,
        "failed Valid write must leave Processing"
    );
    assert!(
        !has_active_renewal_order(&orders, &certificates, "edge-cert").expect("scan"),
        "exact published order_url must make the matching stale Processing order non-blocking"
    );
    let _ = keeper.finish().await;
}

/// Order succeeds, certificate fails: Valid sticks, prior material remains, no
/// reload, explicit failure.
#[test]
fn order_success_certificate_failure_retains_prior_material_without_reload() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (old_cert_pem, old_key_pem) = generated_cert_and_key();
    let prior = sample_certificate(
        "edge-cert",
        &old_cert_pem,
        &old_key_pem,
        Some(OTHER_ORDER_URL),
    );
    certificates
        .upsert_certificate(prior, false)
        .expect("seed prior certificate");
    let (new_cert_pem, new_key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &new_cert_pem, &new_key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let _fault =
        inject_final_publication_certificate_write_fault_for_tests(PrivateFileFault::Rename);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(
        outcome,
        FinalRenewalPublication::OrderCommittedMaterialNotPublished(_)
    ));

    let (reload_requested, result) = track_reload_request(outcome);
    let error = result.expect_err("cert write failed");
    let message = error.to_string();
    assert!(
        message.contains(
            "ACME order was marked valid but renewed certificate material failed to publish"
        ),
        "error must state order committed without material: {message}"
    );
    assert_no_material_disclosure(
        &message,
        &[&new_key_pem, &new_cert_pem, &old_key_pem, &old_cert_pem],
    );
    assert!(
        !reload_requested,
        "certificate failure after order Valid must not request reload"
    );

    let stored = certificates
        .get_certificate("edge-cert")
        .expect("prior certificate remains");
    assert_eq!(
        stored.cert_pem, old_cert_pem,
        "failed certificate write must leave the prior material"
    );
    assert_ne!(stored.cert_pem, new_cert_pem);
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Valid,
        "order Valid must stick so Processing cannot block a later retry"
    );
    assert!(
        !has_active_renewal_order(&orders, &certificates, "edge-cert").expect("scan"),
        "Valid status must not block a later renewal"
    );
}

/// Both final writes fail: neither lands, no reload, combined failure without
/// disclosing PEM or keys, and Processing remains active (fail-closed outage).
#[test]
fn both_final_writes_fail_without_reload_or_material_disclosure() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let _order_fault =
        inject_final_publication_order_write_fault_for_tests(PrivateFileFault::Rename);
    let _cert_fault =
        inject_final_publication_certificate_write_fault_for_tests(PrivateFileFault::Sync);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    match outcome {
        FinalRenewalPublication::NeitherCommitted {
            ref order,
            ref certificate,
        } => {
            let order_message = order.to_string();
            let certificate_message = certificate.to_string();
            assert!(
                !order_message.is_empty() && !certificate_message.is_empty(),
                "both diagnostics must be preserved"
            );
            assert_ne!(
                order_message, certificate_message,
                "order and certificate failure diagnostics must remain distinguishable"
            );
        }
        other => panic!("expected NeitherCommitted, got {other:?}"),
    }

    let (reload_requested, result) = track_reload_request(outcome);
    let error = result.expect_err("both writes failed");
    let message = error.to_string();
    assert!(
        message.contains("ACME final publication failed for both order and certificate stores")
            && message.contains("order:")
            && message.contains("certificate:"),
        "combined failure must preserve both diagnostics: {message}"
    );
    assert_no_material_disclosure(&message, &[&cert_pem, &key_pem]);
    assert!(!reload_requested, "both-failure must not request reload");
    assert!(matches!(
        certificates.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing
    );
    assert!(
        has_active_renewal_order(&orders, &certificates, "edge-cert").expect("scan"),
        "storage-outage both-failure may remain fail-closed on the Processing order"
    );
}

/// Exact matching published `certificate.order_url` clears only that stale
/// active order; different/missing URLs and unrelated certificates stay active.
#[test]
fn published_order_url_clears_only_exact_matching_active_order() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();

    // Matching Processing order + published URL → non-blocking.
    certificates
        .upsert_certificate(
            sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL)),
            false,
        )
        .expect("publish matching cert");
    orders
        .upsert_order(
            order_with(
                "edge-order",
                "edge-cert",
                AcmeOrderStatus::Processing,
                Some(ORDER_URL),
            ),
            false,
        )
        .expect("matching processing order");
    assert!(
        !has_active_renewal_order(&orders, &certificates, "edge-cert").expect("match"),
        "exact non-empty order_url match must clear the stale active order"
    );

    // Different URL on the same certificate keeps Ready active.
    let (other_pem, other_key) = generated_cert_and_key();
    certificates
        .upsert_certificate(
            sample_certificate("edge-cert", &other_pem, &other_key, Some(OTHER_ORDER_URL)),
            true,
        )
        .expect("overwrite with different URL");
    orders
        .upsert_order(
            order_with(
                "edge-order-ready",
                "edge-cert",
                AcmeOrderStatus::Ready,
                Some(ORDER_URL),
            ),
            false,
        )
        .expect("ready order with different published URL");
    assert!(
        has_active_renewal_order(&orders, &certificates, "edge-cert").expect("different url"),
        "a different published order_url must keep Ready active"
    );

    // Missing published URL keeps PendingChallenges active.
    let dir_missing = TempDir::new().expect("tempdir");
    let certificates_missing =
        AcmeCertificateStore::open(dir_missing.path()).expect("open cert store");
    let orders_missing = AcmeOrderStore::open(dir_missing.path()).expect("open order store");
    let (missing_pem, missing_key) = generated_cert_and_key();
    certificates_missing
        .upsert_certificate(
            sample_certificate("edge-cert", &missing_pem, &missing_key, None),
            false,
        )
        .expect("cert without order_url");
    orders_missing
        .upsert_order(
            order_with(
                "pending-order",
                "edge-cert",
                AcmeOrderStatus::PendingChallenges,
                Some(ORDER_URL),
            ),
            false,
        )
        .expect("pending order");
    assert!(
        has_active_renewal_order(&orders_missing, &certificates_missing, "edge-cert")
            .expect("missing published url"),
        "missing published order_url must keep PendingChallenges active"
    );

    // Empty order URLs are not completion evidence.
    let dir_empty = TempDir::new().expect("tempdir");
    let certificates_empty = AcmeCertificateStore::open(dir_empty.path()).expect("open cert store");
    let orders_empty = AcmeOrderStore::open(dir_empty.path()).expect("open order store");
    let (empty_pem, empty_key) = generated_cert_and_key();
    certificates_empty
        .upsert_certificate(
            sample_certificate("edge-cert", &empty_pem, &empty_key, Some("")),
            false,
        )
        .expect("cert with empty order_url");
    orders_empty
        .upsert_order(
            order_with(
                "empty-order",
                "edge-cert",
                AcmeOrderStatus::Processing,
                Some(""),
            ),
            false,
        )
        .expect("processing order with empty url");
    assert!(
        has_active_renewal_order(&orders_empty, &certificates_empty, "edge-cert")
            .expect("empty urls"),
        "empty order URLs must not clear an active order"
    );

    // Missing order URL on the order itself keeps Processing active even when
    // the certificate carries a URL.
    let dir_missing_order_url = TempDir::new().expect("tempdir");
    let certificates_missing_order_url =
        AcmeCertificateStore::open(dir_missing_order_url.path()).expect("open cert store");
    let orders_missing_order_url =
        AcmeOrderStore::open(dir_missing_order_url.path()).expect("open order store");
    let (order_none_pem, order_none_key) = generated_cert_and_key();
    certificates_missing_order_url
        .upsert_certificate(
            sample_certificate(
                "edge-cert",
                &order_none_pem,
                &order_none_key,
                Some(ORDER_URL),
            ),
            false,
        )
        .expect("cert with order_url");
    orders_missing_order_url
        .upsert_order(
            order_with(
                "no-url-order",
                "edge-cert",
                AcmeOrderStatus::Processing,
                None,
            ),
            false,
        )
        .expect("processing order without url");
    assert!(
        has_active_renewal_order(
            &orders_missing_order_url,
            &certificates_missing_order_url,
            "edge-cert"
        )
        .expect("missing order url"),
        "a missing order URL must keep Processing active"
    );

    // An unrelated certificate carrying the same URL must not clear another
    // certificate's active order.
    let dir_unrelated = TempDir::new().expect("tempdir");
    let certificates_unrelated =
        AcmeCertificateStore::open(dir_unrelated.path()).expect("open cert store");
    let orders_unrelated = AcmeOrderStore::open(dir_unrelated.path()).expect("open order store");
    let (a_pem, a_key) = generated_cert_and_key();
    let (b_pem, b_key) = generated_cert_and_key();
    certificates_unrelated
        .upsert_certificate(
            sample_certificate("other-cert", &a_pem, &a_key, Some(ORDER_URL)),
            false,
        )
        .expect("unrelated cert with matching URL");
    certificates_unrelated
        .upsert_certificate(
            sample_certificate("edge-cert", &b_pem, &b_key, Some(OTHER_ORDER_URL)),
            false,
        )
        .expect("target cert with different URL");
    orders_unrelated
        .upsert_order(
            order_with(
                "edge-order",
                "edge-cert",
                AcmeOrderStatus::Processing,
                Some(ORDER_URL),
            ),
            false,
        )
        .expect("processing order for edge-cert");
    assert!(
        has_active_renewal_order(&orders_unrelated, &certificates_unrelated, "edge-cert")
            .expect("unrelated"),
        "an unrelated certificate's order_url must not clear this certificate's active order"
    );
}

/// The production helper itself attempts both writes: Valid first, certificate
/// second even after an order-store failure.
#[test]
fn commit_final_renewal_publication_attempts_certificate_after_order_failure() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");

    let _fault = inject_final_publication_order_write_fault_for_tests(PrivateFileFault::Rename);
    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(
        outcome,
        FinalRenewalPublication::MaterialPublishedOrderNotCommitted(_)
    ));
    assert_eq!(
        certificates
            .get_certificate("edge-cert")
            .expect("published despite order failure")
            .cert_pem,
        cert_pem
    );
    assert_eq!(
        orders.get_order("edge-order").expect("order").status,
        AcmeOrderStatus::Processing
    );
    // The order write failed, so the order is still active and still resumable
    // — which means its finalization material must have survived untouched.
    let still_active = orders.get_order("edge-order").expect("order");
    assert!(
        still_active.finalization.is_some(),
        "a still-resumable order must keep the material a successor needs"
    );
}

/// Retention is tied to resumability: the material is dropped in exactly the
/// write that makes the order terminal, and only then.
#[test]
fn finalization_material_is_cleared_only_when_the_order_becomes_terminal() {
    let dir = TempDir::new().expect("tempdir");
    let certificates = AcmeCertificateStore::open(dir.path()).expect("open cert store");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let (cert_pem, key_pem) = generated_cert_and_key();
    let issued = sample_certificate("edge-cert", &cert_pem, &key_pem, Some(ORDER_URL));
    let order = processing_order("edge-order", "edge-cert");
    let seeded = order.finalization.clone().expect("seeded material");
    let persisted_key = seeded.key_pem().to_string();
    orders
        .upsert_order(order.clone(), false)
        .expect("seed processing order");
    let seeded_back = orders.get_order("edge-order").expect("order");
    assert!(
        seeded_back.finalization.is_some(),
        "the material must be durable before completion, not only in memory"
    );

    let outcome = commit_final_renewal_publication(&certificates, &orders, issued, order);
    assert!(matches!(outcome, FinalRenewalPublication::Complete));
    let published = orders.get_order("edge-order").expect("order");
    assert_eq!(published.status, AcmeOrderStatus::Valid);
    assert!(
        published.finalization.is_none(),
        "a terminal order can never be resumed, so it must not keep private-key material"
    );
    // Nothing about the cleared material may survive in an operator-facing
    // rendering of the record.
    let debug = format!("{published:?}");
    let summary = serde_json::to_string(&published.summary()).expect("serialize summary");
    for surface in [&debug, &summary] {
        assert!(
            !surface.contains(&persisted_key) && !surface.contains("PRIVATE KEY"),
            "finalization material must not surface: {surface}"
        );
    }
}

/// `Debug` and the Admin summary are the two places a whole order record is
/// rendered. Neither may disclose the key or the CSR while the order is still
/// carrying them.
#[test]
fn a_live_order_never_discloses_its_finalization_material() {
    let order = processing_order("edge-order", "edge-cert");
    let material = order.finalization.clone().expect("seeded material");
    let key_pem = material.key_pem().to_string();
    let csr_der = material
        .csr_der(&["example.com".to_string()])
        .expect("decodable csr");
    let csr_base64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);

    let debug = format!("{order:?}");
    assert!(
        debug.contains("<redacted>"),
        "the material's Debug must be a fixed placeholder: {debug}"
    );
    let summary = serde_json::to_string(&order.summary()).expect("serialize summary");
    let summary_value: serde_json::Value =
        serde_json::from_str(&summary).expect("summary is an object");
    assert!(
        summary_value.get("finalization").is_none(),
        "the Admin order shape must be unchanged by this field"
    );
    for surface in [&debug, &summary] {
        assert!(
            !surface.contains(&key_pem)
                && !surface.contains(&csr_base64)
                && !surface.contains("PRIVATE KEY"),
            "finalization material must not surface: {surface}"
        );
    }
}

/// Corrupt material cannot be written, and cannot be used. Both checks are
/// content-free, so neither reveals what was found.
#[test]
fn corrupt_finalization_material_fails_closed_without_disclosure() {
    let material = serde_json::json!({
        "key_pem": "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        "csr_der_base64": "!!!not-base64!!!",
    });
    let corrupt: AcmeOrderFinalization =
        serde_json::from_value(material).expect("deserialize corrupt material");
    let error = corrupt
        .csr_der(&["example.com".to_string()])
        .expect_err("corrupt CSR must fail closed");
    let rendered = error.to_string();
    assert!(
        !rendered.contains("PRIVATE KEY") && !rendered.contains("not-base64"),
        "the diagnostic must not describe the material: {rendered}"
    );

    let mut order = processing_order("edge-order", "edge-cert");
    order.finalization = Some(corrupt);
    let dir = TempDir::new().expect("tempdir");
    let orders = AcmeOrderStore::open(dir.path()).expect("open order store");
    let error = orders
        .upsert_order(order, true)
        .expect_err("corrupt material must not be storable");
    assert!(matches!(error, AcmeError::Parse(_)));
    assert!(
        !error.to_string().contains("not-base64"),
        "the store diagnostic must not describe the material"
    );
}

fn assert_unusable_without_disclosure(error: &AcmeError) {
    let rendered = error.to_string();
    assert!(
        rendered.contains("missing or unusable"),
        "unexpected diagnostic: {rendered}"
    );
    assert!(
        !rendered.contains("PRIVATE KEY")
            && !rendered.contains("BEGIN")
            && !rendered.contains("example.com")
            && !rendered.contains("*.example.com")
            && !rendered.contains("other.example"),
        "diagnostic must stay content-free: {rendered}"
    );
}

fn package_from_key_and_csr(key_pem: String, csr_der: Vec<u8>) -> AcmeOrderFinalization {
    serde_json::from_value(serde_json::json!({
        "key_pem": key_pem,
        "csr_der_base64": base64::engine::general_purpose::STANDARD.encode(csr_der),
    }))
    .expect("deserialize finalization package")
}

fn csr_der_for_sans(key_pair: &rcgen::KeyPair, sans: Vec<rcgen::SanType>) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = sans;
    params
        .serialize_request(key_pair)
        .expect("serialize csr")
        .der()
        .as_ref()
        .to_vec()
}

fn dns_san(name: &str) -> rcgen::SanType {
    rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from(name).expect("dns san"))
}

/// Strong preflight rejects every class of unusable package with the same
/// fixed diagnostic and never regenerates material.
#[test]
fn finalization_preflight_rejects_malformed_and_mismatched_packages() {
    let domains = vec!["example.com".to_string()];
    let good = AcmeOrderFinalization::generate(&domains).expect("generate");
    good.validate(&domains)
        .expect("generated package validates");
    good.csr_der(&domains).expect("generated csr decodes");

    // Malformed PEM that is non-empty but not a private key.
    let malformed_pem = package_from_key_and_csr(
        "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n".to_string(),
        good.csr_der(&domains).expect("csr"),
    );
    assert_unusable_without_disclosure(
        &malformed_pem.validate(&domains).expect_err("malformed PEM"),
    );

    // A parser that accepts only the first PEM block would silently ignore the
    // second private key. The package must contain exactly one key record.
    let trailing_key = rcgen::KeyPair::generate().expect("trailing key");
    let multiple_keys = package_from_key_and_csr(
        format!("{}\n{}", good.key_pem(), trailing_key.serialize_pem()),
        good.csr_der(&domains).expect("csr"),
    );
    assert_unusable_without_disclosure(
        &multiple_keys
            .validate(&domains)
            .expect_err("multiple private keys"),
    );

    // Well-base64-encoded trailing DER after a complete CSR.
    let mut trailing = good.csr_der(&domains).expect("csr");
    trailing.push(0x00);
    let trailing_der = package_from_key_and_csr(good.key_pem().to_string(), trailing);
    assert_unusable_without_disclosure(&trailing_der.validate(&domains).expect_err("trailing DER"));

    // Invalid CSR proof-of-possession signature (flip a byte in the DER).
    let mut tampered = good.csr_der(&domains).expect("csr");
    let last = tampered.last_mut().expect("csr bytes");
    *last ^= 0x01;
    let bad_sig = package_from_key_and_csr(good.key_pem().to_string(), tampered);
    assert_unusable_without_disclosure(&bad_sig.validate(&domains).expect_err("bad CSR signature"));

    // Private key / CSR public key mismatch.
    let other_key = rcgen::KeyPair::generate().expect("other key");
    let mismatched = package_from_key_and_csr(
        other_key.serialize_pem(),
        good.csr_der(&domains).expect("csr"),
    );
    assert_unusable_without_disclosure(
        &mismatched
            .validate(&domains)
            .expect_err("mismatched key/CSR"),
    );

    let key = rcgen::KeyPair::generate().expect("key");

    // Wrong SAN set.
    let wrong = package_from_key_and_csr(
        key.serialize_pem(),
        csr_der_for_sans(&key, vec![dns_san("other.example")]),
    );
    assert_unusable_without_disclosure(&wrong.validate(&domains).expect_err("wrong SAN"));

    // Extra SAN.
    let extra = package_from_key_and_csr(
        key.serialize_pem(),
        csr_der_for_sans(&key, vec![dns_san("example.com"), dns_san("extra.example")]),
    );
    assert_unusable_without_disclosure(&extra.validate(&domains).expect_err("extra SAN"));

    // Missing SAN (empty SAN extension).
    let missing = package_from_key_and_csr(key.serialize_pem(), csr_der_for_sans(&key, Vec::new()));
    assert_unusable_without_disclosure(&missing.validate(&domains).expect_err("missing SAN"));

    // Duplicate DNS SAN.
    let duplicate = package_from_key_and_csr(
        key.serialize_pem(),
        csr_der_for_sans(&key, vec![dns_san("example.com"), dns_san("example.com")]),
    );
    assert_unusable_without_disclosure(
        &duplicate.validate(&domains).expect_err("duplicate DNS SAN"),
    );

    // Non-DNS SAN.
    let non_dns = package_from_key_and_csr(
        key.serialize_pem(),
        csr_der_for_sans(
            &key,
            vec![
                dns_san("example.com"),
                rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
            ],
        ),
    );
    assert_unusable_without_disclosure(&non_dns.validate(&domains).expect_err("non-DNS SAN"));

    // Wildcard domains are exact-match values, not expanded.
    let wild_domains = vec!["*.example.com".to_string()];
    let wild = AcmeOrderFinalization::generate(&wild_domains).expect("wildcard package");
    wild.validate(&wild_domains)
        .expect("wildcard package validates against itself");
    assert_unusable_without_disclosure(
        &wild
            .validate(&["example.com".to_string()])
            .expect_err("wildcard is not equivalent to the apex"),
    );
}
