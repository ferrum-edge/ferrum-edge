//! Issue #2409: two-instance coherence for the file-backed managed TLS store.
//!
//! Each `ManagedTlsStore` opened over the same directory stands in for one
//! gateway replica sharing a writable volume. Before this coverage the store
//! cached one process-local map forever and rewrote the whole document from
//! that stale snapshot, so a record written through replica A was invisible to
//! replica B and B's next write erased it.

use std::sync::Arc;

use ferrum_edge::tls::managed::{
    ManagedTlsError, ManagedTlsMaterialKind, ManagedTlsRecord, ManagedTlsStore,
};
use ferrum_edge::tls::source::MaterialKind;

fn ca_record(id: &str, pem: &str) -> ManagedTlsRecord {
    ManagedTlsRecord::new_ca_bundle(id.to_string(), id.to_string(), None, pem.to_string())
}

fn ca_ids(store: &ManagedTlsStore) -> Vec<String> {
    let summaries = store
        .list(ManagedTlsMaterialKind::CaBundle)
        .expect("list ca bundles");
    let mut ids: Vec<String> = summaries.into_iter().map(|entry| entry.id).collect();
    ids.sort();
    ids
}

#[test]
fn a_write_on_one_instance_is_visible_to_the_other_without_reopening() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    // B primes its cache on the empty store, exactly as a long-lived replica
    // does before the first admin mutation reaches its peer.
    assert!(ca_ids(&instance_b).is_empty());

    instance_a
        .upsert(ca_record("edge-ca", "from-a"), false)
        .expect("A creates the record");

    let seen = instance_b.get("edge-ca").expect("B observes A's record");
    assert_eq!(seen.ca_bundle_pem.as_deref(), Some("from-a"));
    assert_eq!(ca_ids(&instance_b), vec!["edge-ca".to_string()]);
}

#[test]
fn interleaved_writes_from_two_instances_preserve_both_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    // Both replicas prime their caches on the empty document first: this is the
    // stale-snapshot condition that used to make the second write clobber the
    // first.
    assert!(ca_ids(&instance_a).is_empty());
    assert!(ca_ids(&instance_b).is_empty());

    instance_a
        .upsert(ca_record("ca-a", "from-a"), false)
        .expect("A writes");
    instance_b
        .upsert(ca_record("ca-b", "from-b"), false)
        .expect("B writes from its pre-A snapshot");

    let expected = vec!["ca-a".to_string(), "ca-b".to_string()];
    assert_eq!(ca_ids(&instance_a), expected, "A must not lose B's record");
    assert_eq!(ca_ids(&instance_b), expected, "B must not lose A's record");

    // A third reader stands in for a restarted replica reading the volume.
    let restarted = ManagedTlsStore::open(dir.path()).expect("reopen");
    assert_eq!(ca_ids(&restarted), expected, "durable state holds both");
}

#[test]
fn a_stale_instance_cannot_erase_a_committed_record_by_updating_another() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    instance_a
        .upsert(ca_record("shared-ca", "v1"), false)
        .expect("seed");
    // B loads the document at v1, then A rotates the same record.
    let before = instance_b.get("shared-ca").expect("B reads v1");
    assert_eq!(before.ca_bundle_pem.as_deref(), Some("v1"));
    instance_a
        .upsert(ca_record("shared-ca", "v2"), true)
        .expect("A rotates");

    // B now writes an unrelated record from what was a v1 view. The rotation
    // must survive: B's write is applied to authoritative state, not replayed
    // from its own snapshot.
    instance_b
        .upsert(ca_record("other-ca", "from-b"), false)
        .expect("B writes an unrelated record");

    let restarted = ManagedTlsStore::open(dir.path()).expect("reopen");
    let rotated = restarted.get("shared-ca").expect("rotation retained");
    assert_eq!(rotated.ca_bundle_pem.as_deref(), Some("v2"));
    assert!(restarted.get("other-ca").is_ok());
}

#[test]
fn create_without_overwrite_conflicts_with_another_instances_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    assert!(ca_ids(&instance_b).is_empty());
    instance_a
        .upsert(ca_record("edge-ca", "from-a"), false)
        .expect("A creates");

    let error = instance_b
        .upsert(ca_record("edge-ca", "from-b"), false)
        .expect_err("B must not silently replace A's record");
    assert!(matches!(error, ManagedTlsError::AlreadyExists(_)));

    let kept = instance_b.get("edge-ca").expect("A's record kept");
    assert_eq!(kept.ca_bundle_pem.as_deref(), Some("from-a"));
}

#[test]
fn a_cross_kind_collision_is_detected_against_another_instances_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    assert!(ca_ids(&instance_b).is_empty());
    instance_a
        .upsert(ca_record("shared-id", "from-a"), false)
        .expect("A creates a CA bundle");

    let crl = ManagedTlsRecord::new_crl(
        "shared-id".to_string(),
        "shared-id".to_string(),
        None,
        "crl-bytes".to_string(),
    );
    let error = instance_b
        .upsert(crl, true)
        .expect_err("cross-kind overwrite must be refused");
    assert!(matches!(error, ManagedTlsError::KindConflict { .. }));
}

#[test]
fn a_delete_on_one_instance_is_observed_by_the_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    instance_a
        .upsert(ca_record("edge-ca", "from-a"), false)
        .expect("seed");
    assert!(instance_b.get("edge-ca").is_ok());

    instance_a.delete("edge-ca").expect("A deletes");

    let error = instance_b.get("edge-ca").expect_err("B sees the delete");
    assert!(matches!(error, ManagedTlsError::NotFound(_)));
    let error = instance_b
        .delete("edge-ca")
        .expect_err("a second delete is not found, not a resurrection");
    assert!(matches!(error, ManagedTlsError::NotFound(_)));
}

#[test]
fn material_lookup_reflects_another_instances_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = ManagedTlsStore::open(dir.path()).expect("open A");
    let instance_b = ManagedTlsStore::open(dir.path()).expect("open B");

    instance_a
        .upsert(ca_record("edge-ca", "v1"), false)
        .expect("seed");
    let first = instance_b
        .material("ca-bundles/edge-ca", MaterialKind::CaBundle)
        .expect("B loads v1");
    assert_eq!(first.bytes, b"v1");

    instance_a
        .upsert(ca_record("edge-ca", "v2"), true)
        .expect("A rotates");

    let rotated = instance_b
        .material("ca-bundles/edge-ca", MaterialKind::CaBundle)
        .expect("B loads the rotation");
    assert_eq!(rotated.bytes, b"v2");
    assert_ne!(
        first.version, rotated.version,
        "the material version must change so source-set fingerprints rotate"
    );
}

#[test]
fn concurrent_writes_from_two_instances_all_commit() {
    const PER_INSTANCE: usize = 12;

    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = Arc::new(ManagedTlsStore::open(dir.path()).expect("open A"));
    let instance_b = Arc::new(ManagedTlsStore::open(dir.path()).expect("open B"));

    let writer_a = Arc::clone(&instance_a);
    let writer_b = Arc::clone(&instance_b);
    let thread_a = std::thread::spawn(move || {
        for index in 0..PER_INSTANCE {
            let id = format!("a-{index:02}");
            writer_a
                .upsert(ca_record(&id, "from-a"), false)
                .expect("A writes");
        }
    });
    let thread_b = std::thread::spawn(move || {
        for index in 0..PER_INSTANCE {
            let id = format!("b-{index:02}");
            writer_b
                .upsert(ca_record(&id, "from-b"), false)
                .expect("B writes");
        }
    });
    thread_a.join().expect("A joins");
    thread_b.join().expect("B joins");

    let restarted = ManagedTlsStore::open(dir.path()).expect("reopen");
    let ids = ca_ids(&restarted);
    assert_eq!(
        ids.len(),
        PER_INSTANCE * 2,
        "every interleaved write must survive: {ids:?}"
    );

    let version = restarted.store_version().expect("store version");
    let expected_version = (PER_INSTANCE * 2) as u64;
    assert!(
        version >= expected_version,
        "each committed write must advance the store version, got {version}"
    );
}

/// Reads must not be serialized behind a writer's cross-instance lock.
///
/// `managed://` material lookups feed frontend/admin TLS reload and the admin
/// API, both of which run on Tokio workers. Polling a contended advisory lock
/// for up to `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS` (10s by default) would let
/// one slow writer — on this host or another replica — stall runtime threads,
/// turning a shared volume into a denial-of-service amplifier.
#[test]
fn reads_do_not_wait_for_a_writer_holding_the_store_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    store
        .upsert(ca_record("edge-ca", "v1"), false)
        .expect("seed");

    // Hold the sidecar advisory lock exactly as a mid-flight writer in another
    // process does: a separate open file description on the same lock file.
    let lock = std::fs::File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.path().join(".managed-tls.json.lock"))
        .expect("open the lock sidecar");
    lock.lock().expect("hold the writer lock");

    let reader = ManagedTlsStore::open(dir.path()).expect("open a second instance");
    let started = std::time::Instant::now();
    let seen = reader
        .get("edge-ca")
        .expect("read under a held writer lock");
    let listed = ca_ids(&reader);
    let material = reader
        .material("ca-bundles/edge-ca", MaterialKind::CaBundle)
        .expect("material read under a held writer lock");
    let elapsed = started.elapsed();

    assert_eq!(seen.ca_bundle_pem.as_deref(), Some("v1"));
    assert_eq!(listed, vec!["edge-ca".to_string()]);
    assert_eq!(material.bytes, b"v1");
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "reads must not wait on the writer lock; took {elapsed:?}"
    );

    lock.unlock().expect("release the writer lock");
}

/// Conditional writes (the Admin API's `If-Match`): the precondition is
/// evaluated against the authoritative record inside the exclusive lock that
/// commits the write. Two replicas that read the same representation and then
/// both replace it conditionally must not both commit — exactly one wins and
/// the other is refused without writing.
#[test]
fn conditional_replacement_from_two_instances_commits_exactly_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = ManagedTlsStore::open(dir.path()).expect("open seed");
    seed.upsert(ca_record("rotating-ca", "v0"), false)
        .expect("seed");

    for round in 0..8 {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = ["from-a", "from-b"]
            .into_iter()
            .map(|pem| {
                let path = dir.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                let pem = format!("{pem}-{round}");
                std::thread::spawn(move || {
                    let instance = ManagedTlsStore::open(path).expect("open replica");
                    // Both replicas read the same representation before either
                    // writes, as two operators opening one record would.
                    let seen = instance.get("rotating-ca").expect("read");
                    barrier.wait();
                    let outcome =
                        instance.update_existing_if(ca_record("rotating-ca", &pem), |current| {
                            current.ca_bundle_pem == seen.ca_bundle_pem
                                && current.updated_at == seen.updated_at
                        });
                    (pem, outcome)
                })
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("replica thread"))
            .collect();
        let winners: Vec<&str> = outcomes
            .iter()
            .filter(|(_, outcome)| outcome.is_ok())
            .map(|(pem, _)| pem.as_str())
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "round {round}: exactly one conditional writer commits: {outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|(_, outcome)| matches!(
                outcome,
                Err(ManagedTlsError::PreconditionFailed(id)) if id == "rotating-ca"
            )),
            "round {round}: the loser is refused with PreconditionFailed: {outcomes:?}"
        );
        let stored = seed.get("rotating-ca").expect("read back");
        assert_eq!(
            stored.ca_bundle_pem.as_deref(),
            Some(winners[0]),
            "round {round}: the stored record is the winner's, never the loser's"
        );
    }
}

#[test]
fn a_refused_precondition_changes_nothing_on_any_write_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    store
        .upsert(ca_record("held-ca", "original"), false)
        .expect("seed");
    let version = store.store_version().expect("version");

    let error = store
        .update_existing_if(ca_record("held-ca", "stale-put"), |_| false)
        .expect_err("refused update");
    assert!(matches!(error, ManagedTlsError::PreconditionFailed(ref id) if id == "held-ca"));
    // The rendering names the id only, never the record's material.
    assert!(!error.to_string().contains("original"));
    assert!(!error.to_string().contains("stale-put"));

    let error = store
        .upsert_if(ca_record("held-ca", "stale-overwrite"), true, |_| false)
        .expect_err("refused overwrite");
    assert!(matches!(error, ManagedTlsError::PreconditionFailed(_)));

    let error = store
        .delete_kind_if_authorized_and(
            "held-ca",
            ManagedTlsMaterialKind::CaBundle,
            |_| false,
            || true,
        )
        .expect_err("refused delete");
    assert!(matches!(error, ManagedTlsError::PreconditionFailed(_)));

    assert_eq!(
        store
            .get("held-ca")
            .expect("still present")
            .ca_bundle_pem
            .as_deref(),
        Some("original")
    );
    assert_eq!(
        store.store_version().expect("version"),
        version,
        "a refused precondition must not republish the document"
    );

    // A conditional overwrite whose precondition requires a current record
    // never turns into a create.
    let error = store
        .upsert_if(ca_record("absent-ca", "created"), true, |current| {
            current.is_some()
        })
        .expect_err("conditional overwrite of a free id is refused");
    assert!(matches!(error, ManagedTlsError::PreconditionFailed(ref id) if id == "absent-ca"));
    assert!(matches!(
        store.get("absent-ca"),
        Err(ManagedTlsError::NotFound(_))
    ));

    // Existence and kind are still decided first.
    assert!(matches!(
        store.update_existing_if(ca_record("absent-ca", "x"), |_| false),
        Err(ManagedTlsError::NotFound(_))
    ));
    assert!(matches!(
        store.delete_kind_if_authorized_and(
            "held-ca",
            ManagedTlsMaterialKind::Crl,
            |_| false,
            || true,
        ),
        Err(ManagedTlsError::WrongKind { .. })
    ));

    // A holding precondition commits.
    store
        .update_existing_if(ca_record("held-ca", "rotated"), |current| {
            current.ca_bundle_pem.as_deref() == Some("original")
        })
        .expect("matching precondition commits");
    let removed = store
        .delete_kind_if_authorized_and(
            "held-ca",
            ManagedTlsMaterialKind::CaBundle,
            |current| current.ca_bundle_pem.as_deref() == Some("rotated"),
            || true,
        )
        .expect("matching delete")
        .expect("removed");
    assert_eq!(removed.ca_bundle_pem.as_deref(), Some("rotated"));
}
