//! Explicit ACME order lifecycle: the transition function and the
//! compare-and-set write admin finalize commits through.
//!
//! Admin finalize reads an order, spends up to its poll timeout on CA I/O
//! without the renewal lease, and then commits its outcome. The commit must act
//! on the snapshot it read, never blindly: a renewal may have completed the same
//! order meanwhile, an operator may have deleted it, and a terminal order must
//! never become `valid` again.
//!
//! The same table governs every other order write (issue #7028): an
//! `allow_overwrite` replacement through the Admin API, and the renewal's own
//! final `valid` write (pinned in the lib's `acme_final_publication_tests`).

use ferrum_edge::tls::acme::{
    AcmeAccountStore, AcmeCertificateRecord, AcmeCertificateStore, AcmeError,
    AcmeHttp01ChallengeRecord, AcmeIssuedCertificateInput, AcmeOrderFinalization, AcmeOrderInput,
    AcmeOrderRecord, AcmeOrderStatus, AcmeOrderStore, completed_finalize,
    order_produced_certificate, order_replacement_refusal, renewal_account_credentials,
};

const DIRECTORY_URL: &str = "https://acme.example/directory";
const ACCOUNT_ID: &str = "https://acme.example/acct/1";
const CERTIFICATE_ID: &str = "edge-cert";

const ALL_STATUSES: [AcmeOrderStatus; 6] = [
    AcmeOrderStatus::PendingChallenges,
    AcmeOrderStatus::Ready,
    AcmeOrderStatus::Processing,
    AcmeOrderStatus::Valid,
    AcmeOrderStatus::Failed,
    AcmeOrderStatus::Cancelled,
];

fn domains() -> Vec<String> {
    vec!["example.com".to_string()]
}

/// An order carrying real key/CSR material, the shape every finalizable order
/// has.
fn order(id: &str, certificate_id: Option<&str>, status: AcmeOrderStatus) -> AcmeOrderRecord {
    AcmeOrderRecord::new(AcmeOrderInput {
        id: id.to_string(),
        certificate_id: certificate_id.map(str::to_string),
        domains: domains(),
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some(ACCOUNT_ID.to_string()),
        account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
        order_url: Some(format!("https://acme.example/order/{id}")),
        status,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "example.com".to_string(),
            token: format!("{}_token", id.replace('-', "_")),
            key_authorization: format!("{id}.thumbprint"),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        finalization: Some(AcmeOrderFinalization::generate(&domains()).expect("finalization")),
        error: None,
    })
    .expect("acme order record")
}

fn open_store(dir: &tempfile::TempDir) -> AcmeOrderStore {
    AcmeOrderStore::open_with_limits(dir.path(), 16, None).expect("open order store")
}

/// Persist `record` and return the snapshot a reader would see.
fn seed(store: &AcmeOrderStore, record: AcmeOrderRecord) -> AcmeOrderRecord {
    let id = record.id.clone();
    store.upsert_order(record, false).expect("seed order");
    store.get_order(&id).expect("read seeded order")
}

#[test]
fn only_pending_ready_and_processing_orders_are_active() {
    for status in ALL_STATUSES {
        let expected = matches!(
            status,
            AcmeOrderStatus::PendingChallenges
                | AcmeOrderStatus::Ready
                | AcmeOrderStatus::Processing
        );
        assert_eq!(status.is_active(), expected, "{status:?}");
    }
}

#[test]
fn transition_function_admits_only_forward_or_terminal_moves() {
    use AcmeOrderStatus::{Cancelled, Failed, PendingChallenges, Processing, Ready, Valid};
    let legal = [
        (PendingChallenges, Ready),
        (PendingChallenges, Processing),
        (PendingChallenges, Valid),
        (PendingChallenges, Failed),
        (PendingChallenges, Cancelled),
        (Ready, Processing),
        (Ready, Valid),
        (Ready, Failed),
        (Ready, Cancelled),
        (Processing, Valid),
        (Processing, Failed),
        (Processing, Cancelled),
    ];
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let expected = legal.contains(&(from, to)).then_some(to);
            assert_eq!(from.transition_to(to), expected, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn terminal_order_states_cannot_be_left() {
    for from in ALL_STATUSES
        .into_iter()
        .filter(|status| !status.is_active())
    {
        for to in ALL_STATUSES {
            assert_eq!(from.transition_to(to), None, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn finalize_commit_does_not_overwrite_a_concurrent_renewal_valid_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let snapshot = seed(
        &store,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );

    // While admin finalize is in CA I/O, the renewer resumes and completes the
    // same order: `commit_final_renewal_publication` writes it `valid` with its
    // key/CSR cleared.
    let mut renewed = snapshot.clone();
    renewed.status = AcmeOrderStatus::Valid;
    renewed.error = None;
    renewed.finalization = None;
    store.upsert_order(renewed, true).unwrap();
    let committed = store.get_order("edge-order").unwrap();
    let version = store.store_version().unwrap();

    // Neither admin outcome may land on top of it from the stale snapshot.
    assert!(
        store
            .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert!(!store.fail_ca_invalid_order_if_current(&snapshot).unwrap());

    assert_eq!(store.store_version().unwrap(), version);
    let after = store.get_order("edge-order").unwrap();
    assert_eq!(after.status, AcmeOrderStatus::Valid);
    assert_eq!(after.updated_at, committed.updated_at);
    assert!(after.error.is_none());
    assert!(
        after.finalization.is_none(),
        "key/CSR must not be re-populated from the stale snapshot"
    );
}

#[test]
fn finalize_commit_does_not_recreate_a_deleted_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let snapshot = seed(
        &store,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::PendingChallenges,
        ),
    );

    // An operator deletes the order while admin finalize is in flight.
    store.delete_order("edge-order").unwrap();
    let version = store.store_version().unwrap();

    assert!(
        store
            .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert!(!store.fail_ca_invalid_order_if_current(&snapshot).unwrap());

    assert_eq!(store.store_version().unwrap(), version);
    assert!(matches!(
        store.get_order("edge-order"),
        Err(AcmeError::OrderNotFound(_))
    ));
    assert!(store.list_orders().unwrap().is_empty());
}

#[test]
fn a_failed_order_cannot_become_valid() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);

    // Failed through the CAS: terminal, and the key/CSR goes with it.
    let snapshot = seed(
        &store,
        order(
            "failed-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    assert!(store.fail_ca_invalid_order_if_current(&snapshot).unwrap());
    let failed = store.get_order("failed-order").unwrap();
    assert_eq!(failed.status, AcmeOrderStatus::Failed);
    assert!(failed.error.is_some());
    assert!(failed.finalization.is_none());

    // Even with an exactly current snapshot, `failed -> valid` is refused.
    let version = store.store_version().unwrap();
    assert!(
        store
            .complete_order_if_current(&failed, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert_eq!(store.store_version().unwrap(), version);
    assert_eq!(
        store.get_order("failed-order").unwrap().status,
        AcmeOrderStatus::Failed
    );

    // A failed record that still carries usable key/CSR material (the shape
    // earlier writers left behind) is refused the same way.
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let stale_failed = seed(
        &store,
        order(
            "legacy-failed",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Failed,
        ),
    );
    assert!(stale_failed.finalization.is_some());
    assert!(
        store
            .complete_order_if_current(&stale_failed, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .fail_ca_invalid_order_if_current(&stale_failed)
            .unwrap()
    );
    let untouched = store.get_order("legacy-failed").unwrap();
    assert_eq!(untouched.status, AcmeOrderStatus::Failed);
    assert_eq!(untouched.updated_at, stale_failed.updated_at);
}

#[test]
fn finalize_commit_on_the_current_active_snapshot_marks_it_valid_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    // Created without a certificate id; finalize assigns it.
    let snapshot = seed(&store, order("edge-order", None, AcmeOrderStatus::Ready));

    let committed = store
        .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
        .unwrap()
        .expect("current active snapshot commits");
    assert_eq!(committed.status, AcmeOrderStatus::Valid);
    assert_eq!(committed.certificate_id.as_deref(), Some(CERTIFICATE_ID));
    assert!(committed.error.is_none());
    assert!(committed.finalization.is_none());

    let stored = store.get_order("edge-order").unwrap();
    assert_eq!(stored.status, AcmeOrderStatus::Valid);
    assert_eq!(stored.updated_at, committed.updated_at);
    assert!(stored.finalization.is_none());

    // Replaying the same, now stale, snapshot writes nothing.
    let version = store.store_version().unwrap();
    assert!(
        store
            .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert_eq!(store.store_version().unwrap(), version);
}

#[test]
fn finalize_commit_refuses_an_order_superseded_for_its_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let older = seed(
        &store,
        order("older", Some(CERTIFICATE_ID), AcmeOrderStatus::Processing),
    );
    seed(
        &store,
        order(
            "newer",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::PendingChallenges,
        ),
    );

    // Committing the older order would stamp it newest and hide the newer
    // active order from the renewal planner.
    assert!(
        store
            .complete_order_if_current(&older, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .latest_order_for_certificate(CERTIFICATE_ID)
            .unwrap()
            .unwrap()
            .id,
        "newer"
    );
}

#[test]
fn orders_without_a_certificate_are_not_superseded_by_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let first = seed(&store, order("first", None, AcmeOrderStatus::Processing));
    seed(&store, order("second", None, AcmeOrderStatus::Processing));

    // The renewal planner never looks at certificate-less orders, so a newer
    // unrelated one must not block finalizing this one.
    assert!(
        store
            .complete_order_if_current(&first, "first-cert".to_string())
            .unwrap()
            .is_some()
    );
}

#[test]
fn finalize_commit_can_move_an_order_away_from_a_superseded_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let older = seed(
        &store,
        order("older", Some(CERTIFICATE_ID), AcmeOrderStatus::Processing),
    );
    seed(
        &store,
        order(
            "newer",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::PendingChallenges,
        ),
    );

    // Finalize with an explicit `certificate_id` override: the order is
    // persisted under the other certificate, which has no competing order, and
    // leaving the original certificate cannot hide its newer order.
    let committed = store
        .complete_order_if_current(&older, "other-cert".to_string())
        .unwrap()
        .expect("the destination certificate has no competing order");
    assert_eq!(committed.status, AcmeOrderStatus::Valid);
    assert_eq!(committed.certificate_id.as_deref(), Some("other-cert"));
    assert!(committed.finalization.is_none());
    assert_eq!(
        store
            .latest_order_for_certificate(CERTIFICATE_ID)
            .unwrap()
            .unwrap()
            .id,
        "newer"
    );
    assert_eq!(
        store
            .latest_order_for_certificate("other-cert")
            .unwrap()
            .unwrap()
            .id,
        "older"
    );
}

#[test]
fn finalize_commit_refuses_moving_an_order_onto_a_certificate_with_an_active_order() {
    // The destination's active order is refused whether it is older or newer
    // than the moving order: either way it is that certificate's latest order
    // until the commit would stamp the moving one newer.
    for destination_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        if destination_first {
            seed(
                &store,
                order("renewal", Some("other-cert"), AcmeOrderStatus::Processing),
            );
        }
        let moving = seed(&store, order("moving", None, AcmeOrderStatus::Ready));
        if !destination_first {
            seed(
                &store,
                order("renewal", Some("other-cert"), AcmeOrderStatus::Processing),
            );
        }
        let version = store.store_version().unwrap();

        assert!(
            store
                .complete_order_if_current(&moving, "other-cert".to_string())
                .unwrap()
                .is_none(),
            "destination_first={destination_first}"
        );
        assert_eq!(store.store_version().unwrap(), version);
        let untouched = store.get_order("moving").unwrap();
        assert_eq!(untouched.status, AcmeOrderStatus::Ready);
        assert!(untouched.certificate_id.is_none());
        assert!(untouched.finalization.is_some());
        assert_eq!(
            store
                .latest_order_for_certificate("other-cert")
                .unwrap()
                .unwrap()
                .id,
            "renewal"
        );
    }
}

#[test]
fn a_newer_terminal_order_does_not_block_completing_an_order() {
    // The planner already plans a fresh order behind a terminal latest order,
    // so committing this one hides nothing — in its own certificate or in one
    // it is moved onto.
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let own = seed(
        &store,
        order("own", Some(CERTIFICATE_ID), AcmeOrderStatus::Processing),
    );
    let moving = seed(&store, order("moving", None, AcmeOrderStatus::Processing));
    seed(
        &store,
        order("done", Some(CERTIFICATE_ID), AcmeOrderStatus::Failed),
    );
    seed(
        &store,
        order("other-done", Some("other-cert"), AcmeOrderStatus::Valid),
    );

    assert!(
        store
            .complete_order_if_current(&own, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .complete_order_if_current(&moving, "other-cert".to_string())
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_newer_terminal_order_does_not_block_recording_a_ca_invalid_order() {
    // The CA-invalid fail path shares the completion guard: a terminal latest
    // order hides nothing, so the older order is still recorded `failed` and
    // renewal does not keep resuming an order the CA has already rejected.
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let own = seed(
        &store,
        order("own", Some(CERTIFICATE_ID), AcmeOrderStatus::Processing),
    );
    seed(
        &store,
        order("done", Some(CERTIFICATE_ID), AcmeOrderStatus::Valid),
    );

    assert!(store.fail_ca_invalid_order_if_current(&own).unwrap());
}

#[test]
fn overwrite_admission_is_a_legal_transition_or_the_same_active_state() {
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let expected = from.transition_to(to).is_some() || (from == to && from.is_active());
            assert_eq!(
                from.admits_overwrite_with(to),
                expected,
                "{from:?} -> {to:?}"
            );
        }
    }
    // Spelled out: a terminal order is never replaced, not even by itself, and
    // an active order never moves back to `pending_challenges`.
    for terminal in [
        AcmeOrderStatus::Valid,
        AcmeOrderStatus::Failed,
        AcmeOrderStatus::Cancelled,
    ] {
        for to in ALL_STATUSES {
            assert!(
                !terminal.admits_overwrite_with(to),
                "{terminal:?} -> {to:?}"
            );
        }
    }
    assert!(
        AcmeOrderStatus::PendingChallenges
            .admits_overwrite_with(AcmeOrderStatus::PendingChallenges)
    );
    assert!(!AcmeOrderStatus::Ready.admits_overwrite_with(AcmeOrderStatus::PendingChallenges));
    assert!(!AcmeOrderStatus::Processing.admits_overwrite_with(AcmeOrderStatus::PendingChallenges));
}

#[test]
fn allow_overwrite_enforces_the_transition_table() {
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let dir = tempfile::tempdir().unwrap();
            let store = open_store(&dir);
            let stored = seed(&store, order("edge-order", Some(CERTIFICATE_ID), from));
            let version = store.store_version().unwrap();

            let result = store.upsert_order(order("edge-order", Some(CERTIFICATE_ID), to), true);
            if from.admits_overwrite_with(to) {
                let replaced = result.unwrap_or_else(|error| panic!("{from:?} -> {to:?}: {error}"));
                assert_eq!(replaced.status, to, "{from:?} -> {to:?}");
                assert_eq!(replaced.created_at, stored.created_at, "{from:?} -> {to:?}");
                continue;
            }
            match result {
                Err(AcmeError::IllegalOrderTransition {
                    id,
                    from: refused_from,
                    to: refused_to,
                }) => {
                    assert_eq!(id, "edge-order");
                    assert_eq!((refused_from, refused_to), (from, to));
                }
                other => panic!("{from:?} -> {to:?} must be refused, got {other:?}"),
            }
            assert_eq!(
                store.store_version().unwrap(),
                version,
                "a refused overwrite writes nothing ({from:?} -> {to:?})"
            );
            let untouched = store.get_order("edge-order").unwrap();
            assert_eq!(untouched.status, from);
            assert_eq!(untouched.updated_at, stored.updated_at);
        }
    }
}

#[test]
fn a_terminal_order_cannot_be_reopened_by_an_admin_style_replacement() {
    // Every order the Admin API writes is a freshly prepared
    // `pending_challenges` one, so `allow_overwrite` on a finished order is the
    // terminal -> active move the lifecycle forbids.
    for terminal in [
        AcmeOrderStatus::Valid,
        AcmeOrderStatus::Failed,
        AcmeOrderStatus::Cancelled,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        seed(&store, order("edge-order", Some(CERTIFICATE_ID), terminal));
        let error = store
            .upsert_order(
                order(
                    "edge-order",
                    Some(CERTIFICATE_ID),
                    AcmeOrderStatus::PendingChallenges,
                ),
                true,
            )
            .expect_err("a terminal order must not be reopened");
        let rendered = error.to_string();
        assert!(
            matches!(error, AcmeError::IllegalOrderTransition { .. }),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("`{}`", terminal.as_str()))
                && rendered.contains("`pending_challenges`")
                && !rendered.contains("PRIVATE KEY")
                && !rendered.contains("redacted"),
            "diagnostic names the id and both states only: {rendered}"
        );
        assert_eq!(store.get_order("edge-order").unwrap().status, terminal);
    }
}

#[test]
fn creating_a_brand_new_order_is_admitted_in_any_state() {
    for status in ALL_STATUSES {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        let created = store
            .upsert_order(order("fresh", Some(CERTIFICATE_ID), status), true)
            .unwrap_or_else(|error| panic!("{status:?}: {error}"));
        assert_eq!(created.status, status);
    }
}

#[test]
fn order_status_renders_its_wire_spelling() {
    for status in ALL_STATUSES {
        let wire = serde_json::to_value(status).unwrap();
        assert_eq!(wire.as_str(), Some(status.as_str()));
        assert_eq!(status.to_string(), status.as_str());
    }
}

fn issued_certificate(id: &str, order_url: Option<&str>) -> AcmeCertificateRecord {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: id.to_string(),
        domains: domains(),
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some(ACCOUNT_ID.to_string()),
        order_url: order_url.map(str::to_string),
        cert_pem: "pem".to_string(),
        key_pem: "key".to_string(),
        chain_pem: None,
    })
    .expect("acme certificate record")
}

#[test]
fn an_order_produced_the_certificate_only_when_valid_with_the_same_order_url() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let snapshot = seed(
        &store,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    let order_url = snapshot.order_url.clone().expect("order url");
    let completed = store
        .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
        .unwrap()
        .expect("commit");

    let produced = issued_certificate(CERTIFICATE_ID, Some(order_url.as_str()));
    assert!(order_produced_certificate(&completed, &produced));

    // Not yet valid: a finalize still has work to do.
    assert!(!order_produced_certificate(&snapshot, &produced));
    // A certificate issued for another CA order, or with no evidence at all.
    assert!(!order_produced_certificate(
        &completed,
        &issued_certificate(CERTIFICATE_ID, Some("https://acme.example/order/other"))
    ));
    assert!(!order_produced_certificate(
        &completed,
        &issued_certificate(CERTIFICATE_ID, None)
    ));
    // The order was finalized into a different certificate.
    assert!(!order_produced_certificate(
        &completed,
        &issued_certificate("other-cert", Some(order_url.as_str()))
    ));
    // Empty URLs are never evidence.
    let mut blank = completed.clone();
    blank.order_url = Some(" ".to_string());
    assert!(!order_produced_certificate(
        &blank,
        &issued_certificate(CERTIFICATE_ID, Some(" "))
    ));
}

#[test]
fn renewal_prefers_the_account_store_over_the_latest_order_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let accounts = AcmeAccountStore::open_with_limits(dir.path(), 16, None).unwrap();

    // An older order carrying an earlier account key becomes the latest order
    // through a terminal commit (here the CA-invalid `failed` write), even
    // though a newer, terminal order exists for the certificate.
    let mut older = order("older", Some(CERTIFICATE_ID), AcmeOrderStatus::Processing);
    older.account_credentials_json = Some(r#"{"key":"stale"}"#.to_string());
    let older = seed(&orders, older);
    let mut newer = order("newer", Some(CERTIFICATE_ID), AcmeOrderStatus::Valid);
    newer.account_credentials_json = Some(r#"{"key":"current"}"#.to_string());
    seed(&orders, newer);
    assert!(orders.fail_ca_invalid_order_if_current(&older).unwrap());
    let latest = orders
        .latest_order_for_certificate(CERTIFICATE_ID)
        .unwrap()
        .unwrap();
    assert_eq!(latest.id, "older");

    // Store has no account yet: the latest order is the only source.
    assert_eq!(
        renewal_account_credentials(
            &accounts,
            &orders,
            CERTIFICATE_ID,
            DIRECTORY_URL,
            ACCOUNT_ID
        )
        .unwrap()
        .as_deref(),
        Some(r#"{"key":"stale"}"#)
    );

    // Once the account store knows the certificate's account, it wins.
    accounts
        .upsert_account(
            ACCOUNT_ID.to_string(),
            DIRECTORY_URL.to_string(),
            r#"{"key":"current"}"#.to_string(),
        )
        .unwrap();
    assert_eq!(
        renewal_account_credentials(
            &accounts,
            &orders,
            CERTIFICATE_ID,
            DIRECTORY_URL,
            ACCOUNT_ID
        )
        .unwrap()
        .as_deref(),
        Some(r#"{"key":"current"}"#)
    );

    // No account and no order: nothing to renew with.
    assert_eq!(
        renewal_account_credentials(
            &accounts,
            &orders,
            "unknown-cert",
            DIRECTORY_URL,
            "https://acme.example/acct/unknown"
        )
        .unwrap(),
        None
    );
}

// Admin finalize's idempotent answers and the create/renew pre-check are
// decided by `completed_finalize` and `order_replacement_refusal` over the
// stores; the handlers only map the answer to `200`/`409`. The handlers
// themselves cannot be driven here: they need the `acme` feature, and the
// in-flight case needs a real CA round trip before the decision is made.

fn open_certificates(dir: &tempfile::TempDir) -> AcmeCertificateStore {
    AcmeCertificateStore::open(dir.path()).expect("open certificate store")
}

/// Seed an active order, then complete it the way a renewal does: the order
/// is committed `valid` and its certificate is published with the order's
/// `order_url`. Returns the snapshot an Admin finalize would have read before
/// that happened.
fn seed_and_complete_by_renewal(
    orders: &AcmeOrderStore,
    certificates: &AcmeCertificateStore,
) -> AcmeOrderRecord {
    let snapshot = seed(
        orders,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    orders
        .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
        .unwrap()
        .expect("renewal completes the order");
    certificates
        .upsert_certificate(
            issued_certificate(CERTIFICATE_ID, snapshot.order_url.as_deref()),
            false,
        )
        .expect("renewal publishes the certificate");
    snapshot
}

#[test]
fn repeat_finalize_of_a_completed_order_is_answered_as_completed() {
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    seed_and_complete_by_renewal(&orders, &certificates);

    // The handler's pre-check: the stored order is terminal, and it is asked
    // with the stored order's own URL before any CA I/O.
    let stored = orders.get_order("edge-order").unwrap();
    assert_eq!(stored.status, AcmeOrderStatus::Valid);
    let (order, certificate) = completed_finalize(
        &orders,
        &certificates,
        "edge-order",
        CERTIFICATE_ID,
        stored.order_url.as_deref(),
    )
    .unwrap()
    .expect("a repeat finalize of a completed order is a success");
    assert_eq!(order.id, "edge-order");
    assert_eq!(order.status, AcmeOrderStatus::Valid);
    assert_eq!(certificate.id, CERTIFICATE_ID);
    assert_eq!(certificate.order_url, stored.order_url);
}

#[test]
fn in_flight_completion_without_allow_overwrite_is_answered_as_completed() {
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    // Admin finalize read the active order, then spent its CA I/O while a
    // renewal completed the same CA order and published its certificate.
    let snapshot = seed_and_complete_by_renewal(&orders, &certificates);

    // The request's own certificate write (default `allow_overwrite: false`)
    // meets the renewal's record...
    let refused = certificates
        .upsert_certificate(
            issued_certificate(CERTIFICATE_ID, snapshot.order_url.as_deref()),
            false,
        )
        .expect_err("the renewal published first");
    assert!(matches!(refused, AcmeError::AlreadyExists(_)), "{refused}");

    // ...and the follow-up question, asked with the URL this request finalized,
    // recognises it as this very order's completion.
    let completed = completed_finalize(
        &orders,
        &certificates,
        &snapshot.id,
        CERTIFICATE_ID,
        snapshot.order_url.as_deref(),
    )
    .unwrap();
    let (order, certificate) = completed.expect("same CA order, same certificate: success");
    assert_eq!(order.status, AcmeOrderStatus::Valid);
    assert_eq!(certificate.order_url, snapshot.order_url);

    // The order compare-and-set path asks the same question after its own
    // stale-snapshot commit is refused.
    assert!(
        orders
            .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
            .unwrap()
            .is_none()
    );
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            &snapshot.id,
            CERTIFICATE_ID,
            snapshot.order_url.as_deref(),
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn unrelated_or_unfinished_state_is_not_a_completed_finalize() {
    // Certificate material from another CA order: still a conflict.
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    let snapshot = seed(
        &orders,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    orders
        .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
        .unwrap()
        .expect("commit");
    certificates
        .upsert_certificate(
            issued_certificate(CERTIFICATE_ID, Some("https://acme.example/order/other")),
            false,
        )
        .unwrap();
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            CERTIFICATE_ID,
            snapshot.order_url.as_deref(),
        )
        .unwrap()
        .is_none(),
        "a certificate from another CA order is unrelated material"
    );

    // The order still active (material published, order write not landed).
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    let active = seed(
        &orders,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    certificates
        .upsert_certificate(
            issued_certificate(CERTIFICATE_ID, active.order_url.as_deref()),
            false,
        )
        .unwrap();
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            CERTIFICATE_ID,
            active.order_url.as_deref(),
        )
        .unwrap()
        .is_none(),
        "an order that is not `valid` is not completed"
    );

    // Completed, but not as the CA order this request finalized, or not into
    // the certificate it names.
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    let snapshot = seed_and_complete_by_renewal(&orders, &certificates);
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            CERTIFICATE_ID,
            Some("https://acme.example/order/other"),
        )
        .unwrap()
        .is_none(),
        "the order now names a different CA order"
    );
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            "other-cert",
            snapshot.order_url.as_deref(),
        )
        .unwrap()
        .is_none(),
        "the order was finalized into another certificate"
    );

    // Deleted meanwhile, and the certificate missing.
    orders.delete_order("edge-order").unwrap();
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            CERTIFICATE_ID,
            snapshot.order_url.as_deref(),
        )
        .unwrap()
        .is_none(),
        "a deleted order is not completed"
    );
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let certificates = open_certificates(&dir);
    let snapshot = seed(
        &orders,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::Processing,
        ),
    );
    orders
        .complete_order_if_current(&snapshot, CERTIFICATE_ID.to_string())
        .unwrap()
        .expect("commit");
    assert!(
        completed_finalize(
            &orders,
            &certificates,
            "edge-order",
            CERTIFICATE_ID,
            snapshot.order_url.as_deref(),
        )
        .unwrap()
        .is_none(),
        "no stored certificate is not completion"
    );
}

#[test]
fn replacement_precheck_refuses_ready_and_terminal_orders_before_preparation() {
    let next = AcmeOrderStatus::PendingChallenges;
    for stored in [
        AcmeOrderStatus::Ready,
        AcmeOrderStatus::Processing,
        AcmeOrderStatus::Valid,
        AcmeOrderStatus::Failed,
        AcmeOrderStatus::Cancelled,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let orders = open_store(&dir);
        seed(&orders, order("edge-order", Some(CERTIFICATE_ID), stored));
        match order_replacement_refusal(&orders, "edge-order", true, next).unwrap() {
            Some(AcmeError::IllegalOrderTransition { id, from, to }) => {
                assert_eq!(id, "edge-order");
                assert_eq!((from, to), (stored, next));
            }
            other => panic!("{stored:?} must be refused, got {other:?}"),
        }
        // Without `allow_overwrite` an existing id is refused outright.
        assert!(matches!(
            order_replacement_refusal(&orders, "edge-order", false, next).unwrap(),
            Some(AcmeError::OrderAlreadyExists(_))
        ));
    }
}

#[test]
fn replacement_precheck_admits_new_ids_and_pending_replacements() {
    let dir = tempfile::tempdir().unwrap();
    let orders = open_store(&dir);
    let next = AcmeOrderStatus::PendingChallenges;
    assert!(
        order_replacement_refusal(&orders, "fresh", false, next)
            .unwrap()
            .is_none()
    );
    assert!(
        order_replacement_refusal(&orders, "fresh", true, next)
            .unwrap()
            .is_none()
    );
    seed(
        &orders,
        order(
            "edge-order",
            Some(CERTIFICATE_ID),
            AcmeOrderStatus::PendingChallenges,
        ),
    );
    assert!(
        order_replacement_refusal(&orders, "edge-order", true, next)
            .unwrap()
            .is_none()
    );
}

#[test]
fn replacement_precheck_agrees_with_the_store() {
    // The pre-check runs before CA preparation and the store decides again
    // under its lock; the two must never disagree.
    let next = AcmeOrderStatus::PendingChallenges;
    for stored in ALL_STATUSES {
        for allow_overwrite in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let orders = open_store(&dir);
            seed(&orders, order("edge-order", Some(CERTIFICATE_ID), stored));
            let refusal =
                order_replacement_refusal(&orders, "edge-order", allow_overwrite, next).unwrap();
            let write = orders.upsert_order(
                order("edge-order", Some(CERTIFICATE_ID), next),
                allow_overwrite,
            );
            assert_eq!(
                refusal.is_none(),
                write.is_ok(),
                "{stored:?} allow_overwrite={allow_overwrite}: {refusal:?} vs {write:?}"
            );
        }
    }
}
