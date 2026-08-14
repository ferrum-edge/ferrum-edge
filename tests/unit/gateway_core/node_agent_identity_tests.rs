//! Injected lookup/publication coverage for node-agent Ambient UDP identity
//! retry and revalidation (issue #3809).
//!
//! The production loop resolves `Node.metadata.uid` once at startup and then
//! again on the existing enrollment-retry cadence. These tests drive that
//! ordering with closures so recovery, same-name UID change, and
//! retraction/publication failure are deterministic and never log the UID.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum_edge::_test_support::{
    NodeIdentityRefreshForTest, refresh_node_identity_binding_for_test,
};

const NODE_A: &str = "11111111-1111-4111-8111-111111111111";
const NODE_B: &str = "22222222-2222-4222-8222-222222222222";

struct IdentityJournal {
    registry_sync_retracts: AtomicUsize,
    identity_retracts: AtomicUsize,
    publishes: std::sync::Mutex<Vec<String>>,
}

impl IdentityJournal {
    fn new() -> Self {
        Self {
            registry_sync_retracts: AtomicUsize::new(0),
            identity_retracts: AtomicUsize::new(0),
            publishes: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn retract_sync(&self) -> Result<(), String> {
        self.registry_sync_retracts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn retract_identity(&self) -> Result<(), String> {
        self.identity_retracts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn publish(&self, uid: &str) -> Result<(), String> {
        self.publishes
            .lock()
            .expect("journal")
            .push(uid.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn initial_lookup_failure_then_recovery_publishes_only_after_retract() {
    let journal = IdentityJournal::new();
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let first = refresh_node_identity_binding_for_test(
        None,
        &mut shutdown,
        || async { Err("api unavailable".to_string()) },
        || journal.retract_sync(),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(first, NodeIdentityRefreshForTest::Unresolved);
    assert_eq!(journal.registry_sync_retracts.load(Ordering::SeqCst), 1);
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 1);
    assert!(journal.publishes.lock().expect("journal").is_empty());

    let recovered = refresh_node_identity_binding_for_test(
        None,
        &mut shutdown,
        || async { Ok(NODE_A.to_string()) },
        || journal.retract_sync(),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(
        recovered,
        NodeIdentityRefreshForTest::Established {
            uid: NODE_A.to_string()
        }
    );
    assert_eq!(journal.registry_sync_retracts.load(Ordering::SeqCst), 2);
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 2);
    assert_eq!(
        journal.publishes.lock().expect("journal").as_slice(),
        &[NODE_A]
    );
}

#[tokio::test]
async fn same_name_uid_change_never_keeps_the_old_uid() {
    let journal = IdentityJournal::new();
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        Some(NODE_A),
        &mut shutdown,
        || async { Ok(NODE_B.to_string()) },
        || journal.retract_sync(),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(
        refresh,
        NodeIdentityRefreshForTest::Established {
            uid: NODE_B.to_string()
        }
    );
    assert_eq!(journal.registry_sync_retracts.load(Ordering::SeqCst), 1);
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 1);
    assert_eq!(
        journal.publishes.lock().expect("journal").as_slice(),
        &[NODE_B]
    );
}

#[tokio::test]
async fn stable_uid_revalidation_does_not_retract_registry_sync() {
    let journal = IdentityJournal::new();
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        Some(NODE_A),
        &mut shutdown,
        || async { Ok(NODE_A.to_string()) },
        || journal.retract_sync(),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(
        refresh,
        NodeIdentityRefreshForTest::Unchanged {
            uid: NODE_A.to_string()
        }
    );
    assert_eq!(journal.registry_sync_retracts.load(Ordering::SeqCst), 0);
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 0);
    assert!(journal.publishes.lock().expect("journal").is_empty());
}

#[tokio::test]
async fn registry_sync_retraction_failure_still_retracts_identity_before_fencing() {
    let journal = IdentityJournal::new();
    let lookups = AtomicUsize::new(0);
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        None,
        &mut shutdown,
        || {
            lookups.fetch_add(1, Ordering::SeqCst);
            async { Ok(NODE_B.to_string()) }
        },
        || Err("registry marker is immutable".to_string()),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(refresh, NodeIdentityRefreshForTest::Fenced { uid: None });
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 1);
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert!(journal.publishes.lock().expect("journal").is_empty());
}

#[tokio::test]
async fn registry_sync_retraction_failure_on_uid_change_still_retracts_identity_before_fencing() {
    let journal = IdentityJournal::new();
    let lookups = AtomicUsize::new(0);
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        Some(NODE_A),
        &mut shutdown,
        || {
            lookups.fetch_add(1, Ordering::SeqCst);
            async { Ok(NODE_B.to_string()) }
        },
        || Err("registry marker is immutable".to_string()),
        || journal.retract_identity(),
        |uid| journal.publish(uid),
    )
    .await;
    assert_eq!(refresh, NodeIdentityRefreshForTest::Fenced { uid: None });
    assert_eq!(journal.identity_retracts.load(Ordering::SeqCst), 1);
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert!(journal.publishes.lock().expect("journal").is_empty());
}

#[tokio::test]
async fn identity_retraction_failure_does_not_lookup_or_publish() {
    let lookups = AtomicUsize::new(0);
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        None,
        &mut shutdown,
        || {
            lookups.fetch_add(1, Ordering::SeqCst);
            async { Ok(NODE_A.to_string()) }
        },
        || Ok(()),
        || Err("identity file is immutable".to_string()),
        |_uid| panic!("must not publish over an identity that could not be retracted"),
    )
    .await;
    assert_eq!(refresh, NodeIdentityRefreshForTest::Fenced { uid: None });
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn publication_failure_retracts_and_leaves_no_uid() {
    let identity_retracts = AtomicUsize::new(0);
    let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);

    let refresh = refresh_node_identity_binding_for_test(
        None,
        &mut shutdown,
        || async { Ok(NODE_A.to_string()) },
        || Ok(()),
        || {
            identity_retracts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_uid| Err("directory sync failed".to_string()),
    )
    .await;
    assert_eq!(refresh, NodeIdentityRefreshForTest::Unresolved);
    assert_eq!(identity_retracts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn shutdown_during_lookup_keeps_the_loop_responsive() {
    let (shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let lookup_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&lookup_started);

    let refresh = tokio::spawn(async move {
        refresh_node_identity_binding_for_test(
            Some(NODE_A),
            &mut shutdown,
            move || {
                let started = Arc::clone(&started);
                async move {
                    started.notify_one();
                    let _ = release_rx.await;
                    std::future::pending::<Result<String, String>>().await
                }
            },
            || Ok(()),
            || Ok(()),
            |_uid| Ok(()),
        )
        .await
    });

    lookup_started.notified().await;
    shutdown_tx.send(true).expect("shutdown");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), refresh)
        .await
        .expect("shutdown must not wait out the pending GET")
        .expect("join");
    assert_eq!(
        outcome,
        NodeIdentityRefreshForTest::Interrupted {
            uid: Some(NODE_A.to_string())
        }
    );
    let _ = release_tx.send(());
}

#[test]
fn explicit_k8s_node_uid_is_first_precedence_and_fail_closed_without_echoing_the_value() {
    use ferrum_edge::proxy::udp_placement_migration::parse_explicit_k8s_node_uid;

    assert_eq!(parse_explicit_k8s_node_uid(None).expect("unset"), None);

    let empty = parse_explicit_k8s_node_uid(Some("")).expect_err("empty");
    assert!(
        empty.contains("FERRUM_K8S_NODE_UID") && empty.contains("empty"),
        "{empty}"
    );

    let whitespace = parse_explicit_k8s_node_uid(Some(" \t\n")).expect_err("whitespace");
    assert!(
        whitespace.contains("FERRUM_K8S_NODE_UID") && whitespace.contains("empty"),
        "{whitespace}"
    );
    assert!(
        !whitespace.contains('\t') && !whitespace.contains('\n'),
        "the error must not echo the supplied value: {whitespace}"
    );

    let malformed_value = "!!not-a-uid!!";
    let malformed = parse_explicit_k8s_node_uid(Some(malformed_value)).expect_err("malformed");
    assert!(
        malformed.contains("Kubernetes node UID") && !malformed.contains(malformed_value),
        "malformed UID errors must stay material-free, got {malformed}"
    );

    let too_long = "a".repeat(129);
    let oversized = parse_explicit_k8s_node_uid(Some(&too_long)).expect_err("oversized");
    assert!(
        !oversized.contains(&too_long),
        "oversized UID errors must not echo the value"
    );

    let parsed = parse_explicit_k8s_node_uid(Some(NODE_A)).expect("valid");
    assert_eq!(parsed.as_deref(), Some(NODE_A));
    let padded = format!("  {NODE_A}  ");
    let trimmed = parse_explicit_k8s_node_uid(Some(&padded)).expect("trimmed valid");
    assert_eq!(trimmed.as_deref(), Some(NODE_A));
}
