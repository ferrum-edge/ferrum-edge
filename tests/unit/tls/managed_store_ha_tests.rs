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
