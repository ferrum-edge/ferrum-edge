//! Explicit ACME order lifecycle: the transition function and the
//! compare-and-set write admin finalize commits through.
//!
//! Admin finalize reads an order, spends up to its poll timeout on CA I/O
//! without the renewal lease, and then commits its outcome. The commit must act
//! on the snapshot it read, never blindly: a renewal may have completed the same
//! order meanwhile, an operator may have deleted it, and a terminal order must
//! never become `valid` again.

use ferrum_edge::tls::acme::{
    AcmeError, AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeOrderFinalization,
    AcmeOrderRecord, AcmeOrderStatus, AcmeOrderStore,
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
    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
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
