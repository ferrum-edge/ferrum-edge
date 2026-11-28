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
            false,
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
            false,
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
            false,
            |current| current.ca_bundle_pem.as_deref() == Some("rotated"),
            || true,
        )
        .expect("matching delete")
        .expect("removed");
    assert_eq!(removed.ca_bundle_pem.as_deref(), Some("rotated"));
}

/// Review F1/F3: the existing-record rules and a lapsed delete fence answer
/// before the caller's precondition, so a stale tag never hides them.
#[test]
fn existing_record_rules_and_a_lapsed_fence_take_precedence_over_the_precondition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    store
        .upsert(ca_record("shared-id", "ca"), false)
        .expect("seed CA bundle");

    // A cross-kind overwrite is the documented 409, whatever the tag says.
    let crl = ManagedTlsRecord::new_crl(
        "shared-id".to_string(),
        "shared-id".to_string(),
        None,
        "crl".to_string(),
    );
    assert!(matches!(
        store.upsert_if(crl, true, |_| false),
        Err(ManagedTlsError::KindConflict { .. })
    ));
    // So is an existing id without `allow_overwrite`.
    assert!(matches!(
        store.upsert_if(ca_record("shared-id", "other"), false, |_| false),
        Err(ManagedTlsError::AlreadyExists(_))
    ));
    // And a typed update of another kind.
    let crl = ManagedTlsRecord::new_crl(
        "shared-id".to_string(),
        "shared-id".to_string(),
        None,
        "crl".to_string(),
    );
    assert!(matches!(
        store.update_existing_if(crl, |_| false),
        Err(ManagedTlsError::KindConflict { .. })
    ));

    // A delete whose authorization fence lapsed reports that (`Ok(None)`,
    // answered as 503), never a stale-tag refusal.
    assert!(matches!(
        store.delete_kind_if_authorized_and(
            "shared-id",
            ManagedTlsMaterialKind::CaBundle,
            false,
            |_| false,
            || false,
        ),
        Ok(None)
    ));
    assert!(store.get("shared-id").is_ok(), "nothing was removed");
}

/// Review F4: every successful write stamps a revision the record never had,
/// so a same-material replacement whose clock repeats `updated_at` — and a
/// delete-then-recreate — still change the stored representation the Admin
/// API `ETag` is computed over.
#[test]
fn every_write_stamps_a_new_revision_independent_of_the_clock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    let created = store
        .upsert(ca_record("same-material", "pem"), false)
        .expect("create");
    assert!(created.revision > 0, "a create is stamped");
    let seen = store.get("same-material").expect("read");
    assert_eq!(seen.revision, created.revision, "the stamp is persisted");

    let replaced = store
        .update_existing_if(ca_record("same-material", "pem"), |_| true)
        .expect("same-material replacement");
    assert!(replaced.revision > seen.revision);

    // Pin the clock-derived fields to the earlier read: the representation
    // still differs, so an earlier tag can never match after a write.
    let mut pinned = store.get("same-material").expect("read back");
    pinned.updated_at = seen.updated_at;
    pinned.created_at = seen.created_at;
    assert_ne!(
        serde_json::to_value(&pinned).expect("serialize"),
        serde_json::to_value(&seen).expect("serialize"),
        "a same-material replacement must change the tagged representation \
         even when the clock repeats"
    );

    let overwritten = store
        .upsert(ca_record("same-material", "pem"), true)
        .expect("same-material overwrite");
    assert!(overwritten.revision > replaced.revision);

    store.delete("same-material").expect("delete");
    let recreated = store
        .upsert(ca_record("same-material", "pem"), false)
        .expect("recreate");
    assert!(
        recreated.revision > overwritten.revision,
        "a recreate never reuses a revision the deleted record had"
    );
}

/// Review round 2, F1: a document written before records carried a revision
/// must keep its exact shape for every record a write does not touch, so a
/// store sitting at its byte ceiling can still delete a record (and is not
/// refused 413 because every untouched record grew a `"revision": 0`).
#[test]
fn legacy_records_keep_their_shape_so_a_full_store_can_still_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("managed-tls.json");
    {
        let seeding = ManagedTlsStore::open(dir.path()).expect("open seeding store");
        for index in 0..40 {
            seeding
                .upsert(ca_record(&format!("legacy-{index:02}"), "x"), false)
                .expect("seed");
        }
    }

    // Rewrite the document as a pre-revision gateway left it: no record
    // carries the field. Same pretty-printed form the store itself writes.
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read store")).expect("parse");
    for record in document["records"]
        .as_object_mut()
        .expect("records map")
        .values_mut()
    {
        record
            .as_object_mut()
            .expect("record object")
            .remove("revision");
    }
    let legacy = serde_json::to_vec_pretty(&document).expect("serialize legacy");
    std::fs::write(&path, &legacy).expect("write legacy store");
    assert!(!String::from_utf8_lossy(&legacy).contains("\"revision\""));

    // The ceiling is exactly the legacy document's size: any growth of the
    // untouched records would refuse the delete.
    let full = ManagedTlsStore::open_with_limits(dir.path(), 64 * 1024, 1000, Some(legacy.len()))
        .expect("open at the ceiling");
    let removed = full
        .delete("legacy-00")
        .expect("delete at the byte ceiling");
    assert_eq!(removed.id, "legacy-00");

    let after = String::from_utf8(std::fs::read(&path).expect("read back")).expect("utf8");
    assert!(
        !after.contains("\"revision\""),
        "untouched legacy records keep their serialized shape"
    );
    assert!(after.len() < legacy.len());

    // A record a write does touch is stamped, and only that one.
    full.update_existing(ca_record("legacy-01", "x"))
        .expect("rewrite one record");
    let after = String::from_utf8(std::fs::read(&path).expect("read back")).expect("utf8");
    assert_eq!(after.matches("\"revision\"").count(), 1);
    assert!(full.get("legacy-01").expect("stamped").revision > 0);
    assert_eq!(full.get("legacy-02").expect("untouched").revision, 0);
}

/// Review round 2, F3: the caller's reference-scan verdict is decided under
/// the lock after the authoritative existence and kind checks. A scan that
/// matched the id of a replacement under another kind reports the kind
/// mismatch, never the replacement's references; on the right kind the
/// reference conflict answers before the fence and the tag.
#[test]
fn a_reference_verdict_never_masks_a_missing_record_or_a_kind_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    // The CA bundle the caller meant was replaced by a certificate.
    store
        .upsert(
            ManagedTlsRecord::new_certificate(
                "replaced".to_string(),
                "replaced".to_string(),
                None,
                "cert".to_string(),
                "key".to_string(),
                None,
            ),
            false,
        )
        .expect("seed replacement");

    assert!(matches!(
        store.delete_kind_if_authorized_and(
            "replaced",
            ManagedTlsMaterialKind::CaBundle,
            true,
            |_| false,
            || false,
        ),
        Err(ManagedTlsError::WrongKind { .. })
    ));
    assert!(matches!(
        store.delete_kind_if_authorized_and(
            "never-existed",
            ManagedTlsMaterialKind::CaBundle,
            true,
            |_| false,
            || false,
        ),
        Err(ManagedTlsError::NotFound(_))
    ));
    // Right kind: the reference conflict answers before a lapsed fence or a
    // stale tag.
    assert!(matches!(
        store.delete_kind_if_authorized_and(
            "replaced",
            ManagedTlsMaterialKind::Certificate,
            true,
            |_| false,
            || false,
        ),
        Err(ManagedTlsError::StillReferenced(ref id)) if id == "replaced"
    ));
    assert!(store.get("replaced").is_ok(), "no refusal removes anything");
}
