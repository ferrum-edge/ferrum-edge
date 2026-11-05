//! Deterministic coverage for the mesh pools' coalesced create-failure
//! broadcast (issue #5046).
//!
//! The HBONE and sidecar mesh-mTLS pools serialize connection creation with a
//! per-key mutex. Before #5046 a failed dial was returned only to the caller
//! that owned the mutex, so every caller queued behind it took the mutex in
//! turn and repeated the same failed dial against a hard-down peer.
//! `SharedCreationSlot` is the shared machinery both pools now use: the same
//! serialization mutex plus a generation-scoped broadcast of the creator's
//! typed failure.
//!
//! These tests inject a fake "dial" (a counter plus a gate the test opens) so
//! the attempt count is exact and no clock, socket, or benchmark is involved.
//! The cohort is synchronized on a `Barrier` plus the fact that
//! `SharedCreationSlot::join` is SYNCHRONOUS: once every caller has joined, a
//! failure published afterwards is observable by all of them whether or not
//! they have reached the lock yet.

use ferrum_edge::pool::{SharedCreationRole, SharedCreationSlot};
use ferrum_edge::proxy::hbone_pool::HbonePoolError;
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::tls::spiffe::SpiffeTlsError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Barrier, oneshot};

type FailureSlot = SharedCreationSlot<Arc<HbonePoolError>>;

fn tls_handshake_failure() -> HbonePoolError {
    HbonePoolError::TlsHandshake {
        host: "orders.default.svc.cluster.local".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed"),
    }
}

/// The exact shape both pools use: elect a creator, run one fake dial, publish
/// the typed failure to the cohort while the creation lock is still held.
async fn checkout(
    slot: &FailureSlot,
    dials: &AtomicUsize,
    release_dial: impl std::future::Future<Output = ()>,
) -> Result<(), HbonePoolError> {
    let cohort = slot.join();
    let mut lease = match cohort.wait().await {
        SharedCreationRole::Creator(lease) => lease,
        SharedCreationRole::Failed(shared) => return Err(shared.clone_for_broadcast()),
    };
    if let Some(shared) = lease.take_broadcast_failure() {
        return Err(shared.clone_for_broadcast());
    }
    dials.fetch_add(1, Ordering::SeqCst);
    release_dial.await;
    let failure = tls_handshake_failure();
    lease.publish_failure(Arc::new(failure.clone_for_broadcast()));
    Err(failure)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_waiters_share_one_failed_creation_attempt() {
    const COHORT: usize = 8;
    let slot = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));
    // Taken by whichever caller wins the lock, and opened only after every
    // caller has joined, so the failure is published to the whole cohort.
    let (open_dial_tx, open_dial_rx) = oneshot::channel::<()>();
    let open_dial_rx = Arc::new(tokio::sync::Mutex::new(Some(open_dial_rx)));
    let joined = Arc::new(Barrier::new(COHORT + 1));

    let mut tasks = Vec::with_capacity(COHORT);
    for _ in 0..COHORT {
        let slot = Arc::clone(&slot);
        let dials = Arc::clone(&dials);
        let joined = Arc::clone(&joined);
        let open_dial_rx = Arc::clone(&open_dial_rx);
        tasks.push(tokio::spawn(async move {
            // `join` is synchronous, so clearing the barrier proves cohort
            // membership even for callers not yet queued on the lock.
            let cohort = slot.join();
            joined.wait().await;
            let mut lease = match cohort.wait().await {
                SharedCreationRole::Creator(lease) => lease,
                SharedCreationRole::Failed(shared) => return shared.clone_for_broadcast(),
            };
            if let Some(shared) = lease.take_broadcast_failure() {
                return shared.clone_for_broadcast();
            }
            dials.fetch_add(1, Ordering::SeqCst);
            let gate = open_dial_rx.lock().await.take();
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            let failure = tls_handshake_failure();
            lease.publish_failure(Arc::new(failure.clone_for_broadcast()));
            failure
        }));
    }

    joined.wait().await;
    let _ = open_dial_tx.send(());

    let mut outcomes = Vec::with_capacity(COHORT);
    for task in tasks {
        outcomes.push(task.await.expect("checkout task should not panic"));
    }

    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "a cohort that joined one in-flight creation must run exactly one physical dial"
    );
    assert_eq!(outcomes.len(), COHORT);
    for outcome in &outcomes {
        assert!(matches!(outcome, HbonePoolError::TlsHandshake { .. }));
        assert_eq!(outcome.error_class(), ErrorClass::TlsError);
        assert_eq!(outcome.public_reason(), "TLS handshake failed");
        assert_eq!(outcome.to_string(), tls_handshake_failure().to_string());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_creator_releases_waiters_to_elect_a_fresh_creator() {
    let slot = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));
    let creator_started = Arc::new(Barrier::new(2));

    let cancelled = {
        let slot = Arc::clone(&slot);
        let dials = Arc::clone(&dials);
        let creator_started = Arc::clone(&creator_started);
        tokio::spawn(async move {
            let _ = checkout(&slot, &dials, async move {
                creator_started.wait().await;
                // Never completes: the task is aborted mid-dial, dropping the
                // lease WITHOUT publishing anything.
                std::future::pending::<()>().await;
            })
            .await;
        })
    };

    creator_started.wait().await;
    cancelled.abort();
    let _ = cancelled.await;

    // A cancelled creator broadcasts nothing, so the next caller must be
    // elected as a fresh creator instead of inheriting a phantom failure.
    let outcome = checkout(&slot, &dials, std::future::ready(())).await;
    assert!(matches!(outcome, Err(HbonePoolError::TlsHandshake { .. })));
    assert_eq!(
        dials.load(Ordering::SeqCst),
        2,
        "cancellation must re-elect a creator instead of publishing a failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_arriving_after_a_broadcast_dials_again() {
    let slot = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));

    let first = checkout(&slot, &dials, std::future::ready(())).await;
    assert!(matches!(first, Err(HbonePoolError::TlsHandshake { .. })));
    assert_eq!(dials.load(Ordering::SeqCst), 1);

    // The published failure stays in the watch channel, but `join` marks it
    // seen: a caller that never overlapped the attempt must not consume it.
    // There is no durable negative cache.
    let second = checkout(&slot, &dials, std::future::ready(())).await;
    assert!(matches!(second, Err(HbonePoolError::TlsHandshake { .. })));
    assert_eq!(
        dials.load(Ordering::SeqCst),
        2,
        "a later independent request must still be able to retry the peer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_creation_immediately_after_a_broadcast_can_still_succeed() {
    let slot = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));

    let failed = checkout(&slot, &dials, std::future::ready(())).await;
    assert!(failed.is_err());

    // Recovery: the very next caller elects itself and completes successfully.
    let cohort = slot.join();
    let mut lease = match cohort.wait().await {
        SharedCreationRole::Creator(lease) => lease,
        SharedCreationRole::Failed(_) => panic!("a caller after the broadcast must dial"),
    };
    assert!(
        lease.take_broadcast_failure().is_none(),
        "a stale failure must never be charged to a caller that did not join the attempt"
    );
    dials.fetch_add(1, Ordering::SeqCst);
    // A successful creator publishes nothing; the lock is simply released.
    drop(lease);

    assert_eq!(dials.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiter_keeps_its_own_deadline_when_the_creation_outlasts_it() {
    let slot = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));
    let creator_started = Arc::new(Barrier::new(2));

    let creator = {
        let slot = Arc::clone(&slot);
        let dials = Arc::clone(&dials);
        let creator_started = Arc::clone(&creator_started);
        tokio::spawn(async move {
            let _ = checkout(&slot, &dials, async move {
                creator_started.wait().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            })
            .await;
        })
    };
    creator_started.wait().await;

    // The waiter's own budget decides when it gives up — both pools wrap
    // `wait()` in their own `tokio::time::timeout`, never the creator's.
    let cohort = slot.join();
    let waiter = tokio::time::timeout(Duration::from_millis(150), cohort.wait()).await;
    assert!(
        waiter.is_err(),
        "a waiter whose deadline expires first must time out on its own budget"
    );
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "a timed-out waiter must not have started a second dial"
    );

    creator.abort();
    let _ = creator.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_keys_do_not_coalesce_with_each_other() {
    let slot_a = Arc::new(FailureSlot::new());
    let slot_b = Arc::new(FailureSlot::new());
    let dials = Arc::new(AtomicUsize::new(0));
    // Clears only if BOTH keys are dialing at once: a slot must never
    // serialize a different peer / trust domain / DNS override.
    let both_creating = Arc::new(Barrier::new(2));

    let task_a = {
        let slot_a = Arc::clone(&slot_a);
        let dials = Arc::clone(&dials);
        let both_creating = Arc::clone(&both_creating);
        tokio::spawn(async move {
            checkout(&slot_a, &dials, async move {
                both_creating.wait().await;
            })
            .await
        })
    };
    let task_b = {
        let slot_b = Arc::clone(&slot_b);
        let dials = Arc::clone(&dials);
        let both_creating = Arc::clone(&both_creating);
        tokio::spawn(async move {
            checkout(&slot_b, &dials, async move {
                both_creating.wait().await;
            })
            .await
        })
    };

    let outcome_a = tokio::time::timeout(Duration::from_secs(10), task_a)
        .await
        .expect("key a must not be serialized behind key b")
        .expect("key a task should not panic");
    let outcome_b = tokio::time::timeout(Duration::from_secs(10), task_b)
        .await
        .expect("key b must not be serialized behind key a")
        .expect("key b task should not panic");

    assert!(outcome_a.is_err());
    assert!(outcome_b.is_err());
    assert_eq!(dials.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_published_failure_is_a_pull_never_a_push() {
    // Both pools call `take_broadcast_failure` only AFTER re-checking their own
    // cache under the lock, so a usable connection always wins over a shared
    // failure. This pins the half of that contract the slot owns: a published
    // failure is offered to the creator, never forced on it.
    let slot = Arc::new(FailureSlot::new());
    let cohort = slot.join();
    let lease = match cohort.wait().await {
        SharedCreationRole::Creator(lease) => lease,
        SharedCreationRole::Failed(_) => panic!("a fresh slot must elect a creator"),
    };
    lease.publish_failure(Arc::new(tls_handshake_failure()));
    drop(lease);

    let cohort = slot.join();
    let mut lease = match cohort.wait().await {
        SharedCreationRole::Creator(lease) => lease,
        SharedCreationRole::Failed(_) => panic!("a later caller must be the creator"),
    };
    assert!(lease.take_broadcast_failure().is_none());
}

/// Every broadcastable variant must rebuild with an identical pre-wire
/// classification, capability verdict and client-visible reason: a coalesced
/// waiter is charged exactly what the creator was charged.
#[test]
fn clone_for_broadcast_preserves_the_creators_typed_classification() {
    let variants = [
        HbonePoolError::NoSvid,
        HbonePoolError::NoLeafCert,
        HbonePoolError::DnsLookup {
            host: "orders.default.svc.cluster.local".to_string(),
            message: "no records".to_string(),
        },
        HbonePoolError::ConnectTimeout {
            addr: "10.0.0.7:15008".to_string(),
            timeout_ms: 250,
        },
        HbonePoolError::Connect {
            addr: "10.0.0.7:15008".to_string(),
            source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        },
        HbonePoolError::InvalidServerName {
            host: "bad name".to_string(),
            message: "invalid dns name".to_string(),
        },
        HbonePoolError::InvalidDialHostTag {
            value: "??".to_string(),
            message: "not a host".to_string(),
        },
        HbonePoolError::InvalidAuthorityHostTag {
            value: "??".to_string(),
            message: "not a host".to_string(),
        },
        HbonePoolError::InvalidPeerSpiffeTag {
            value: "??".to_string(),
            message: "not a spiffe id".to_string(),
        },
        HbonePoolError::TlsConfig(SpiffeTlsError::Rustls("bad root".to_string())),
        HbonePoolError::TlsConfig(SpiffeTlsError::NoLeafCert),
        tls_handshake_failure(),
        HbonePoolError::TlsHandshake {
            host: "orders.default.svc.cluster.local".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad certificate"),
        },
        HbonePoolError::H2Handshake {
            host: "orders.default.svc.cluster.local".to_string(),
            message: "GOAWAY".to_string(),
        },
        HbonePoolError::InvalidConnectRequest {
            authority: "orders:8080".to_string(),
            message: "bad authority".to_string(),
        },
        HbonePoolError::ConnectStream {
            authority: "orders:8080".to_string(),
            message: "timed out".to_string(),
        },
        HbonePoolError::ConnectRejected {
            authority: "orders:8080".to_string(),
            status: 403,
        },
        HbonePoolError::TrustWithdrawn,
        HbonePoolError::MaxConnectionsExceeded {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            current: 32,
            cap: 32,
        },
        HbonePoolError::ExtendedConnectUnsupported {
            authority: "orders:8080".to_string(),
        },
        HbonePoolError::MissingCrossClusterSni,
        HbonePoolError::MissingCrossClusterTrustDomain,
        HbonePoolError::MissingCrossClusterAuthorityHost,
    ];

    for original in &variants {
        let broadcast = original.clone_for_broadcast();
        assert_eq!(
            broadcast.error_class(),
            original.error_class(),
            "error class must survive the broadcast for {original}"
        );
        assert_eq!(
            broadcast.is_capability_failure(),
            original.is_capability_failure(),
            "capability verdict must survive the broadcast for {original}"
        );
        assert_eq!(
            broadcast.public_reason(),
            original.public_reason(),
            "public reason must survive the broadcast for {original}"
        );
        assert_eq!(
            broadcast.public_status(),
            original.public_status(),
            "public status must survive the broadcast for {original}"
        );
        assert_eq!(
            broadcast.to_string(),
            original.to_string(),
            "rendered message must survive the broadcast for {original}"
        );
    }
}

/// Port exhaustion is classified from `raw_os_error()`, which
/// `std::io::Error::new` would discard. The broadcast must keep it or a
/// coalesced waiter would be charged `RequestError` where the creator was
/// charged `PortExhaustion`.
#[test]
fn clone_for_broadcast_preserves_port_exhaustion_evidence() {
    // EADDRNOTAVAIL: Linux 99, macOS/BSD 49, Windows 10049. The classifier
    // matches all three regardless of host platform.
    for code in [99, 49, 10049] {
        let original = HbonePoolError::Connect {
            addr: "10.0.0.7:15008".to_string(),
            source: std::io::Error::from_raw_os_error(code),
        };
        assert_eq!(
            original.error_class(),
            ErrorClass::PortExhaustion,
            "os error {code} is EADDRNOTAVAIL on some supported platform"
        );
        assert_eq!(
            original.clone_for_broadcast().error_class(),
            ErrorClass::PortExhaustion,
            "raw OS error {code} must survive the broadcast"
        );
    }
}

// ===== opportunistic growth: try_claim never queues (issue #5043) =====

#[tokio::test]
async fn try_claim_takes_a_free_slot_and_declines_a_held_one() {
    let slot = FailureSlot::new();

    let held = slot
        .try_claim()
        .expect("a free slot is claimed immediately");
    assert!(
        slot.try_claim().is_none(),
        "a second claimant must be told 'not now' instead of waiting"
    );
    // The cold path's blocking join must also see the lock as held: the
    // grower is a real creator for the key while it dials.
    let cold = slot.join();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), cold.wait())
            .await
            .is_err(),
        "a blocking joiner waits behind the claimed lock"
    );

    drop(held);
    assert!(
        slot.try_claim().is_some(),
        "dropping the lease frees the slot for the next opportunistic claim"
    );
}

#[tokio::test]
async fn try_claim_lease_does_not_broadcast_unless_asked() {
    let slot = Arc::new(FailureSlot::new());
    // A cold-path caller joins while a grower holds the lock.
    let grower = slot.try_claim().expect("claimed");
    let waiter = {
        let slot = Arc::clone(&slot);
        tokio::spawn(async move {
            match slot.join().wait().await {
                SharedCreationRole::Creator(_) => Ok(()),
                SharedCreationRole::Failed(shared) => Err(shared.clone_for_broadcast()),
            }
        })
    };
    // Let the waiter queue behind the held lock before it is released.
    tokio::time::sleep(Duration::from_millis(20)).await;
    // Dropping the lease without publishing (the growth path's failure
    // handling) elects the waiter as a fresh creator rather than failing it.
    drop(grower);
    let outcome = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("waiter resolves")
        .expect("waiter task");
    assert!(
        outcome.is_ok(),
        "a growth dial that gives up must not fail the cold cohort: {outcome:?}"
    );
}
