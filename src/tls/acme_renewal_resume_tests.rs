//! Crash recovery for automatic ACME renewal (issue #2409 / PR #3506).
//!
//! Issue #2409 requires a per-certificate claim with expiry *and* crash
//! recovery. A prior renewer can die after its fenced order upsert persisted
//! `PendingChallenges`/`Ready`/`Processing` but before final publication. Its
//! claim expires, and the successor that wins the claim must finish that same
//! persisted order rather than skip it forever or duplicate it with the CA.
//!
//! The ordering is the contract: the claim is attempted for every due
//! certificate, and only the winner reads the authoritative order. A live claim
//! held by another replica still denies the takeover outright, which is the
//! single mechanism that keeps two renewers apart.
//!
//! These exercise pure store and lease decisions. The stretches they gate —
//! authorization polling, finalization, certificate download — cannot run
//! without a real ACME server, so the seams are driven directly instead.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::tls::acme::{
    AcmeCertificateRecord, AcmeCertificateStore, AcmeDns01ChallengeRecord,
    AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeIssuedCertificateInput,
    AcmeOrderFinalization, AcmeOrderRecord, AcmeOrderStatus, AcmeOrderStore,
    AcmeRenewalChallengeType, AcmeTlsAlpn01ChallengeRecord, RenewalClaim, RenewalOrderPlan,
    claim_and_plan_renewal, infer_persisted_challenge_type,
};
#[cfg(feature = "acme")]
use crate::tls::acme::{AcmeRenewalSchedulerConfig, resume_persisted_renewal_order};
use crate::tls::lease::{RenewalLeaseKeeper, TlsLeaseStore, acme_renewal_lease_name};
use tempfile::TempDir;

const DIRECTORY_URL: &str = "https://acme.example/directory";
const ORDER_URL: &str = "https://acme.example/order/1";
const OTHER_ORDER_URL: &str = "https://acme.example/order/2";
const CERTIFICATE_ID: &str = "edge-cert";
const ORDER_ID: &str = "renew-order";
const CREDENTIALS: &str = r#"{"kid":"https://acme.example/acct/1"}"#;
const TOKEN: &str = "tok_resume";
const KEY_AUTHORIZATION: &str = "tok_resume.thumbprint";
const LEASE_TTL: Duration = Duration::from_secs(60);

fn generated_cert_and_key() -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params =
        rcgen::CertificateParams::new(vec!["example.com".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

fn issued_certificate(order_url: Option<&str>) -> AcmeCertificateRecord {
    let (cert_pem, key_pem) = generated_cert_and_key();
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: CERTIFICATE_ID.to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        order_url: order_url.map(str::to_string),
        cert_pem,
        key_pem,
        chain_pem: None,
    })
    .expect("acme certificate record")
}

/// Real key/CSR material, generated the way preparation generates it.
fn test_finalization() -> AcmeOrderFinalization {
    AcmeOrderFinalization::generate(&["example.com".to_string()])
        .expect("generate finalization material")
}

/// A prior renewer's persisted order, described by the state that matters here.
struct OrderSpec {
    status: AcmeOrderStatus,
    order_url: Option<&'static str>,
    http01: bool,
    tls_alpn01: bool,
    dns01: bool,
    /// `None` models a renewer that persisted an order without the material a
    /// successor needs — which must fail closed rather than improvise.
    finalization: Option<AcmeOrderFinalization>,
}

impl OrderSpec {
    fn http01() -> Self {
        Self {
            status: AcmeOrderStatus::Processing,
            order_url: Some(ORDER_URL),
            http01: true,
            tls_alpn01: false,
            dns01: false,
            finalization: Some(test_finalization()),
        }
    }

    fn tls_alpn01() -> Self {
        Self {
            http01: false,
            tls_alpn01: true,
            ..Self::http01()
        }
    }

    fn dns01() -> Self {
        Self {
            http01: false,
            dns01: true,
            ..Self::http01()
        }
    }

    fn with_status(status: AcmeOrderStatus) -> Self {
        Self {
            status,
            ..Self::http01()
        }
    }

    fn build(self) -> AcmeOrderRecord {
        let http01_challenges = if self.http01 {
            vec![AcmeHttp01ChallengeRecord {
                identifier: "example.com".to_string(),
                token: TOKEN.to_string(),
                key_authorization: KEY_AUTHORIZATION.to_string(),
            }]
        } else {
            Vec::new()
        };
        let tls_alpn01_challenges = if self.tls_alpn01 {
            vec![AcmeTlsAlpn01ChallengeRecord {
                identifier: "example.com".to_string(),
                token: TOKEN.to_string(),
                key_authorization: KEY_AUTHORIZATION.to_string(),
            }]
        } else {
            Vec::new()
        };
        let dns01_challenges = if self.dns01 {
            vec![AcmeDns01ChallengeRecord {
                identifier: "example.com".to_string(),
                token: TOKEN.to_string(),
                key_authorization: KEY_AUTHORIZATION.to_string(),
            }]
        } else {
            Vec::new()
        };
        AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: ORDER_ID.to_string(),
            certificate_id: Some(CERTIFICATE_ID.to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: DIRECTORY_URL.to_string(),
            account_id: Some("account-1".to_string()),
            account_credentials_json: Some(CREDENTIALS.to_string()),
            order_url: self.order_url.map(str::to_string),
            status: self.status,
            http01_challenges,
            tls_alpn01_challenges,
            dns01_challenges,
            finalization: self.finalization,
            error: None,
        })
        .expect("acme order record")
    }
}

/// A claim left behind by a renewer that crashed: same name, another holder,
/// already expired. This is exactly what a successor must be able to take.
fn expired_lease_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":12,"leases":{{"{name}":{{"#,
            r#""holder":"replica-a","#,
            r#""acquired_at":"2020-01-01T00:00:00Z","#,
            r#""expires_at":"2020-01-01T00:01:00Z","#,
            r#""fence":7}}}}}}"#
        ),
        name = name
    )
}

/// A live claim held by another replica, written straight into the table.
fn live_takeover_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":99,"leases":{{"{name}":{{"#,
            r#""holder":"replica-c","#,
            r#""acquired_at":"2026-01-01T00:00:00Z","#,
            r#""expires_at":"2999-01-01T00:00:00Z","#,
            r#""fence":9999}}}}}}"#
        ),
        name = name
    )
}

struct Fixture {
    dir: TempDir,
    certificates: Arc<AcmeCertificateStore>,
    orders: Arc<AcmeOrderStore>,
    leases: Arc<TlsLeaseStore>,
}

impl Fixture {
    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    fn lease_file(&self) -> std::path::PathBuf {
        self.dir.path().join("tls-leases.json")
    }

    fn lease_name(&self) -> String {
        acme_renewal_lease_name(CERTIFICATE_ID)
    }
}

/// Seed a due certificate plus a prior renewer's persisted order, and leave an
/// expired claim behind so `replica-b` is a successor rather than the original.
fn fixture_with(
    order: Option<AcmeOrderRecord>,
    certificate: Option<AcmeCertificateRecord>,
    expired_claim: bool,
) -> Fixture {
    let dir = TempDir::new().expect("tempdir");
    let certificates = Arc::new(AcmeCertificateStore::open(dir.path()).expect("open cert store"));
    let orders = Arc::new(AcmeOrderStore::open(dir.path()).expect("open order store"));
    if let Some(certificate) = certificate {
        certificates
            .upsert_certificate(certificate, true)
            .expect("seed certificate");
    }
    if let Some(order) = order {
        orders.upsert_order(order, true).expect("seed order");
    }
    if expired_claim {
        let name = acme_renewal_lease_name(CERTIFICATE_ID);
        let document = expired_lease_document(&name);
        std::fs::write(dir.path().join("tls-leases.json"), document)
            .expect("seed the crashed renewer's expired claim");
    }
    let leases = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "replica-b".to_string())
            .expect("open lease store"),
    );
    Fixture {
        dir,
        certificates,
        orders,
        leases,
    }
}

/// A resumable HTTP-01 fixture: a crashed renewer's order plus a due
/// certificate that carries no completion evidence.
fn resumable_http01_fixture() -> Fixture {
    let order = OrderSpec::http01().build();
    fixture_with(Some(order), Some(issued_certificate(None)), true)
}

async fn claim(fixture: &Fixture) -> RenewalClaim {
    claim_and_plan_renewal(
        &fixture.leases,
        &fixture.orders,
        &fixture.certificates,
        CERTIFICATE_ID,
        LEASE_TTL,
    )
    .await
}

async fn plan_after_claim(fixture: &Fixture) -> RenewalOrderPlan {
    match claim(fixture).await {
        RenewalClaim::Claimed(claimed) => {
            let plan = claimed.plan.expect("planning must succeed");
            claimed.keeper.finish().await.expect("release claim");
            plan
        }
        RenewalClaim::Denied => panic!("the expired claim must be takeable"),
        RenewalClaim::Failed(reason) => panic!("claim attempt failed: {reason}"),
    }
}

fn expect_resume(plan: RenewalOrderPlan) -> AcmeOrderRecord {
    match plan {
        RenewalOrderPlan::Resume(order) => *order,
        RenewalOrderPlan::NewOrder => {
            panic!("a crashed renewer's active order must be resumed, not duplicated")
        }
    }
}

fn expect_new_order(plan: RenewalOrderPlan, context: &str) {
    match plan {
        RenewalOrderPlan::NewOrder => {}
        RenewalOrderPlan::Resume(order) => {
            panic!("{context}: order {} must not be resumed", order.id)
        }
    }
}

/// Take the claim this test's successor needs, without planning.
fn successor_keeper(fixture: &Fixture) -> RenewalLeaseKeeper {
    let held = fixture
        .leases
        .try_acquire(&fixture.lease_name(), LEASE_TTL)
        .expect("claim")
        .expect("the successor wins the expired claim");
    RenewalLeaseKeeper::start(held, LEASE_TTL)
}

/// HTTP-01: the successor resumes the persisted order and would drive it with
/// the challenge type the order actually carries.
#[tokio::test]
async fn expired_claim_takeover_resumes_a_persisted_http01_order() {
    let fixture = resumable_http01_fixture();
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    assert_eq!(resumed.id, ORDER_ID);
    assert_eq!(resumed.order_url.as_deref(), Some(ORDER_URL));
    assert_eq!(
        resumed.account_credentials_json.as_deref(),
        Some(CREDENTIALS),
        "resumption must reuse the persisted account credentials"
    );
    let inferred = infer_persisted_challenge_type(&resumed).expect("infer");
    assert_eq!(inferred, AcmeRenewalChallengeType::Http01);
    // The record is left in place, so the shared HTTP-01 resolver keeps serving
    // the prior renewer's token while completion is polled.
    let served = fixture.orders.http01_key_authorization(TOKEN);
    assert_eq!(served.as_deref(), Some(KEY_AUTHORIZATION));
}

/// TLS-ALPN-01: same takeover, and the stored challenge stays servable.
#[tokio::test]
async fn expired_claim_takeover_resumes_a_persisted_tls_alpn01_order() {
    let order = OrderSpec::tls_alpn01().build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    assert_eq!(resumed.id, ORDER_ID);
    let inferred = infer_persisted_challenge_type(&resumed).expect("infer");
    assert_eq!(inferred, AcmeRenewalChallengeType::TlsAlpn01);
    let served = fixture.orders.tls_alpn01_key_authorization("example.com");
    assert_eq!(served.as_deref(), Some(KEY_AUTHORIZATION));
}

/// DNS-01: same takeover, with the stored challenge records the successor
/// re-presents through the configured hook.
#[tokio::test]
async fn expired_claim_takeover_resumes_a_persisted_dns01_order() {
    let order = OrderSpec::dns01().build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    assert_eq!(resumed.id, ORDER_ID);
    let inferred = infer_persisted_challenge_type(&resumed).expect("infer");
    assert_eq!(inferred, AcmeRenewalChallengeType::Dns01);
    assert_eq!(resumed.dns01_challenges.len(), 1);
}

/// Every active status a crashed renewer can leave behind is resumable.
#[tokio::test]
async fn every_active_order_status_is_resumed_after_takeover() {
    let statuses = [
        AcmeOrderStatus::PendingChallenges,
        AcmeOrderStatus::Ready,
        AcmeOrderStatus::Processing,
    ];
    for status in statuses {
        let order = OrderSpec::with_status(status).build();
        let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
        let resumed = expect_resume(plan_after_claim(&fixture).await);
        assert_eq!(resumed.status, status, "{status:?} must resume");
    }
}

/// A live claim still keeps a second renewer out, and it does so *before* any
/// plan exists: `Denied` carries no plan at all, so a replica that is not the
/// renewer never even selects a persisted order.
#[tokio::test]
async fn a_live_claim_denies_a_second_renewer_before_any_plan_is_made() {
    let order = OrderSpec::http01().build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), false);
    let incumbent = Arc::new(
        TlsLeaseStore::open_with_holder(fixture.path(), "replica-a".to_string())
            .expect("open the incumbent's lease store"),
    );
    let held = incumbent
        .try_acquire(&fixture.lease_name(), LEASE_TTL)
        .expect("claim")
        .expect("the incumbent wins");

    let denied = matches!(claim(&fixture).await, RenewalClaim::Denied);
    assert!(denied, "a live claim must deny a second renewer");
    held.release().expect("release the incumbent's claim");
}

/// The published certificate's exact non-empty `order_url` is durable
/// completion evidence: a matching stale active order is finished work, so the
/// successor plans a fresh order instead of resuming it.
#[tokio::test]
async fn a_matching_published_order_url_suppresses_resume() {
    let order = OrderSpec::http01().build();
    let published = issued_certificate(Some(ORDER_URL));
    let fixture = fixture_with(Some(order), Some(published), true);
    let plan = plan_after_claim(&fixture).await;
    expect_new_order(plan, "exact order_url evidence");
}

/// Anything short of exact matching evidence still resumes.
#[tokio::test]
async fn weak_or_missing_completion_evidence_still_resumes() {
    for published in [Some(OTHER_ORDER_URL), Some("   "), None] {
        let order = OrderSpec::http01().build();
        let certificate = issued_certificate(published);
        let fixture = fixture_with(Some(order), Some(certificate), true);
        let resumed = expect_resume(plan_after_claim(&fixture).await);
        assert_eq!(resumed.id, ORDER_ID, "{published:?} is not evidence");
    }
    // No certificate record at all is not evidence either.
    let fixture = fixture_with(Some(OrderSpec::http01().build()), None, true);
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    assert_eq!(resumed.id, ORDER_ID);
}

/// An order the prior renewer never got a URL for is still its work to finish,
/// whatever the published certificate happens to carry.
#[tokio::test]
async fn an_order_without_a_url_is_resumed_rather_than_skipped() {
    let order = OrderSpec {
        order_url: None,
        ..OrderSpec::http01()
    }
    .build();
    let published = issued_certificate(Some(ORDER_URL));
    let fixture = fixture_with(Some(order), Some(published), true);
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    assert_eq!(resumed.id, ORDER_ID);
}

/// Terminal and absent orders plan fresh work, unchanged by this repair.
#[tokio::test]
async fn terminal_and_absent_orders_plan_a_new_order() {
    let statuses = [
        AcmeOrderStatus::Valid,
        AcmeOrderStatus::Failed,
        AcmeOrderStatus::Cancelled,
    ];
    for status in statuses {
        let order = OrderSpec::with_status(status).build();
        let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
        let plan = plan_after_claim(&fixture).await;
        expect_new_order(plan, "a terminal order");
    }
    let fixture = fixture_with(None, Some(issued_certificate(None)), true);
    let plan = plan_after_claim(&fixture).await;
    expect_new_order(plan, "no persisted order");
}

/// Ambiguous or missing challenge state is an explicit failure, never a
/// fallback to whatever challenge type is configured now. The diagnostics name
/// the order and nothing else.
#[test]
fn ambiguous_or_missing_challenge_families_fail_closed() {
    let ambiguous = OrderSpec {
        dns01: true,
        ..OrderSpec::http01()
    }
    .build();
    let error = infer_persisted_challenge_type(&ambiguous)
        .expect_err("two challenge families must not infer a type");
    let rendered = error.to_string();
    assert!(
        rendered.contains("ambiguous"),
        "unexpected inference error: {rendered}"
    );
    assert_no_challenge_disclosure(&rendered);

    let empty = OrderSpec {
        http01: false,
        ..OrderSpec::http01()
    }
    .build();
    let error = infer_persisted_challenge_type(&empty)
        .expect_err("no challenge families must not infer a type");
    let rendered = error.to_string();
    assert!(
        rendered.contains("no persisted challenge records"),
        "unexpected inference error: {rendered}"
    );
    assert_no_challenge_disclosure(&rendered);
}

/// The whole point of persisting the material during preparation: it has to be
/// on disk before completion begins, and it has to survive the process that
/// wrote it. A fresh store handle over the same directory is exactly what a
/// successor opens after a takeover.
#[tokio::test]
async fn finalization_material_survives_store_reopen_and_takeover() {
    let order = OrderSpec::http01().build();
    let seeded = order.finalization.clone().expect("seeded material");
    let expected_key = seeded.key_pem().to_string();
    let expected_csr = seeded
        .csr_der(&["example.com".to_string()])
        .expect("decodable csr");
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);

    // Reopened from scratch, as a successor process would.
    let reopened = AcmeOrderStore::open(fixture.path()).expect("reopen order store");
    let reread = reopened.get_order(ORDER_ID).expect("order survives reopen");
    let persisted = reread.finalization.expect("material survives reopen");
    assert_eq!(persisted.key_pem(), expected_key);
    let persisted_csr = persisted
        .csr_der(&["example.com".to_string()])
        .expect("decodable csr");
    assert_eq!(persisted_csr, expected_csr);

    // And the successor that wins the expired claim is handed the same material
    // by the plan, so completion never has to regenerate anything.
    let resumed = expect_resume(plan_after_claim(&fixture).await);
    let material = resumed.finalization.expect("takeover carries the material");
    assert_eq!(material.key_pem(), expected_key);
    let resumed_csr = material
        .csr_der(&["example.com".to_string()])
        .expect("decodable csr");
    assert_eq!(resumed_csr, expected_csr);
}

/// A resumable order whose finalization material is gone cannot be finished and
/// must not improvise: no new order, no replacement key, no duplicate finalize.
/// The failure lands *before* the DNS-01 hook runs, so no external side effect
/// happens either, and the persisted order is left intact for inspection.
#[cfg(feature = "acme")]
#[tokio::test]
async fn a_resumed_order_without_finalization_material_fails_before_any_side_effect() {
    let order = OrderSpec {
        finalization: None,
        ..OrderSpec::dns01()
    }
    .build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let keeper = successor_keeper(&fixture);
    let certificate = fixture
        .certificates
        .get_certificate(CERTIFICATE_ID)
        .expect("seeded certificate");
    let persisted = fixture.orders.get_order(ORDER_ID).expect("seeded order");
    assert!(persisted.finalization.is_none());

    // A hook *is* configured, and it does not exist: if the resume reached it,
    // the failure would be the hook's, not the material check's.
    let config = scheduler_config(Some("/nonexistent/ferrum-dns01-hook"));
    let error = resume_persisted_renewal_order(
        &fixture.certificates,
        &fixture.orders,
        &keeper,
        certificate,
        persisted,
        &config,
    )
    .await
    .expect_err("missing finalization material must fail closed");
    let rendered = error.to_string();
    assert!(
        rendered.contains("missing or unusable"),
        "unexpected resume error: {rendered}"
    );
    assert!(
        !rendered.contains("hook"),
        "the material check must run before the DNS-01 hook: {rendered}"
    );
    assert_no_challenge_disclosure(&rendered);

    let untouched = fixture.orders.get_order(ORDER_ID).expect("order preserved");
    assert_eq!(untouched.status, AcmeOrderStatus::Processing);
    assert_eq!(untouched.dns01_challenges.len(), 1);
    let _ = keeper.finish().await;
}

/// Material that survived serialization but is no longer decodable is treated
/// exactly like missing material, and the diagnostic stays content-free.
#[cfg(feature = "acme")]
#[tokio::test]
async fn a_resumed_order_with_corrupt_finalization_material_fails_closed() {
    let material = serde_json::json!({
        "key_pem": "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        "csr_der_base64": "!!!not-base64!!!",
    });
    let corrupt: AcmeOrderFinalization =
        serde_json::from_value(material).expect("deserialize corrupt material");
    let mut order = OrderSpec::dns01().build();
    order.finalization = Some(corrupt);
    // Seeded past the store's own guard: this models a document that decayed on
    // disk, not a write Ferrum would have accepted.
    let fixture = fixture_with(None, Some(issued_certificate(None)), true);
    let keeper = successor_keeper(&fixture);
    let certificate = fixture
        .certificates
        .get_certificate(CERTIFICATE_ID)
        .expect("seeded certificate");

    let error = resume_persisted_renewal_order(
        &fixture.certificates,
        &fixture.orders,
        &keeper,
        certificate,
        order,
        &scheduler_config(Some("/nonexistent/ferrum-dns01-hook")),
    )
    .await
    .expect_err("corrupt finalization material must fail closed");
    let rendered = error.to_string();
    assert!(
        rendered.contains("missing or unusable"),
        "unexpected resume error: {rendered}"
    );
    assert!(
        !rendered.contains("not-base64") && !rendered.contains("PRIVATE KEY"),
        "the diagnostic must not describe the material: {rendered}"
    );
    let _ = keeper.finish().await;
}

fn assert_no_challenge_disclosure(message: &str) {
    for secret in [TOKEN, KEY_AUTHORIZATION, CREDENTIALS] {
        assert!(
            !message.contains(secret),
            "diagnostic must not disclose challenge or credential material: {message}"
        );
    }
}

/// Losing the claim mid-resume abandons the work at the same seams a newly
/// prepared renewal uses: `guarded` stops the completion poll, and
/// `guarded_cleanup` refuses to run the DNS-01 retraction the new owner needs.
/// Resumed and newly prepared renewals route through exactly these calls.
#[tokio::test]
async fn a_claim_lost_during_resumed_work_cancels_completion_and_cleanup() {
    let order = OrderSpec::dns01().build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let keeper = Arc::new(successor_keeper(&fixture));

    let work_started = Arc::new(tokio::sync::Notify::new());
    let work_hold = Arc::new(tokio::sync::Notify::new());
    let started_for_work = Arc::clone(&work_started);
    let hold_for_work = Arc::clone(&work_hold);

    let completion = {
        let keeper = Arc::clone(&keeper);
        async move {
            keeper
                .guarded(async move {
                    started_for_work.notify_one();
                    hold_for_work.notified().await;
                    "completed order"
                })
                .await
        }
    };

    let takeover = {
        let keeper = Arc::clone(&keeper);
        let lease_file = fixture.lease_file();
        let lease_name = fixture.lease_name();
        async move {
            work_started.notified().await;
            std::fs::write(lease_file, live_takeover_document(&lease_name))
                .expect("simulate a takeover");
            keeper.ensure_owned().await
        }
    };

    let (completion, ownership) = tokio::join!(completion, takeover);
    assert!(
        ownership.is_err(),
        "authoritative ownership must observe the takeover"
    );
    assert!(
        completion.is_err(),
        "a superseded owner must not keep completing a resumed order"
    );

    let ran_cleanup = Arc::new(AtomicBool::new(false));
    let saw_cleanup = Arc::clone(&ran_cleanup);
    let cleanup = keeper
        .guarded_cleanup(async move {
            saw_cleanup.store(true, Ordering::SeqCst);
            Ok::<(), std::io::Error>(())
        })
        .await;
    assert!(
        matches!(cleanup, crate::tls::lease::GuardedCleanup::Lost),
        "a superseded owner must not retract the new owner's DNS-01 records"
    );
    assert!(
        !ran_cleanup.load(Ordering::SeqCst),
        "the cleanup hook must never start after the claim is lost"
    );
    let _ = Arc::try_unwrap(keeper)
        .expect("keeper fully owned at test end")
        .finish()
        .await;
}

/// A resumed DNS-01 order whose hook is no longer configured is skipped
/// explicitly: not renewed, not deleted, and not marked complete. The
/// configured challenge type is HTTP-01, so this also proves the resume follows
/// the order's own persisted challenge type.
#[cfg(feature = "acme")]
#[tokio::test]
async fn a_resumed_dns01_order_without_a_hook_is_skipped_without_side_effects() {
    let order = OrderSpec::dns01().build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let keeper = successor_keeper(&fixture);
    let certificate = fixture
        .certificates
        .get_certificate(CERTIFICATE_ID)
        .expect("seeded certificate");
    let persisted = fixture.orders.get_order(ORDER_ID).expect("seeded order");

    let renewed = resume_persisted_renewal_order(
        &fixture.certificates,
        &fixture.orders,
        &keeper,
        certificate,
        persisted,
        &scheduler_config(None),
    )
    .await
    .expect("a missing hook is an explicit skip, not an error");
    assert!(!renewed, "a skipped resume must not count as a renewal");
    let untouched = fixture.orders.get_order(ORDER_ID).expect("order preserved");
    assert_eq!(untouched.status, AcmeOrderStatus::Processing);
    assert_eq!(untouched.dns01_challenges.len(), 1);
    let _ = keeper.finish().await;
}

/// A resumed order with ambiguous challenge state fails before any hook runs
/// and leaves the persisted order exactly as it found it.
#[cfg(feature = "acme")]
#[tokio::test]
async fn a_resumed_order_with_ambiguous_challenges_fails_before_any_side_effect() {
    let order = OrderSpec {
        dns01: true,
        ..OrderSpec::http01()
    }
    .build();
    let fixture = fixture_with(Some(order), Some(issued_certificate(None)), true);
    let keeper = successor_keeper(&fixture);
    let certificate = fixture
        .certificates
        .get_certificate(CERTIFICATE_ID)
        .expect("seeded certificate");
    let persisted = fixture.orders.get_order(ORDER_ID).expect("seeded order");

    // A hook *is* configured; the ambiguity must still stop the resume.
    let config = scheduler_config(Some("/nonexistent/ferrum-dns01-hook"));
    let error = resume_persisted_renewal_order(
        &fixture.certificates,
        &fixture.orders,
        &keeper,
        certificate,
        persisted,
        &config,
    )
    .await
    .expect_err("ambiguous challenge state must fail closed");
    assert_no_challenge_disclosure(&error.to_string());
    let untouched = fixture.orders.get_order(ORDER_ID).expect("order preserved");
    assert_eq!(untouched.status, AcmeOrderStatus::Processing);
    let _ = keeper.finish().await;
}

#[cfg(feature = "acme")]
fn scheduler_config(dns01_hook_command: Option<&str>) -> AcmeRenewalSchedulerConfig {
    AcmeRenewalSchedulerConfig {
        enabled: true,
        renew_when_remaining_days: 30,
        check_interval: Duration::from_secs(3600),
        poll_timeout: Duration::from_secs(1),
        // Deliberately *not* the persisted order's type: a resume must use the
        // order's own challenge type, never the current configuration's.
        challenge_type: AcmeRenewalChallengeType::Http01,
        dns01_hook_command: dns01_hook_command.map(str::to_string),
        dns01_propagation: Duration::ZERO,
        renewal_lease_ttl: LEASE_TTL,
        dns_cache: crate::dns::DnsCache::new(crate::dns::DnsConfig::default()),
    }
}
