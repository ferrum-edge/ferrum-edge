//! Issue #2409 root repair: shared-store read availability and deterministic
//! change detection.
//!
//! These live inline (behind `#[cfg(test)]`, like `store_atomicity_tests`)
//! because both properties are about `SharedStoreFile`'s own internals — the
//! sidecar lock path and the replacement-identity mode — and neither is
//! reachable from an external test without widening a runtime API.

use std::fs::{File, FileTimes};
use std::io::Write;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::tls::private_file::replace_private_file;
use crate::tls::shared_store::{SharedStoreFile, StoreIdentityMode, VersionedStoreFile};

/// A minimal shared document. `value` is fixed-width in every fixture below so
/// two generations can be made byte-length identical on purpose.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    value: String,
}

impl VersionedStoreFile for ProbeDocument {
    fn store_version(&self) -> u64 {
        self.version
    }

    fn set_store_version(&mut self, version: u64) {
        self.version = version;
    }
}

fn document_bytes(value: &str) -> Vec<u8> {
    format!(r#"{{"version":1,"value":"{value}"}}"#).into_bytes()
}

fn store_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("probe-store.json")
}

fn lock_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join(".probe-store.json.lock")
}

fn open(dir: &tempfile::TempDir, mode: StoreIdentityMode) -> SharedStoreFile<ProbeDocument> {
    SharedStoreFile::open_with_identity_mode(store_path(dir), mode).expect("open shared store")
}

/// An ACME HTTP-01 / TLS-ALPN-01 challenge lookup is request-adjacent and admin
/// reads run on Tokio workers. A reader that polled the writer's advisory lock
/// would stall a runtime thread for up to
/// `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS` whenever any instance held it, which
/// turns a slow peer into a denial-of-service amplifier.
#[test]
fn a_reader_never_waits_for_a_held_writer_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    replace_private_file(&store_path(&dir), &document_bytes("aaaa")).expect("seed document");
    let store = open(&dir, StoreIdentityMode::platform_default());

    // Hold the exclusive sidecar lock the way a mid-flight writer in another
    // process does. A separate open file description conflicts with the one the
    // store would take.
    let holder = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path(&dir))
        .expect("open lock sidecar");
    holder.lock().expect("hold the writer lock");

    // Force a cache miss so the read genuinely goes to disk.
    replace_private_file(&store_path(&dir), &document_bytes("bbbb")).expect("republish");

    let started = Instant::now();
    let snapshot = store.snapshot().expect("read under a held writer lock");
    let elapsed = started.elapsed();

    assert_eq!(
        snapshot.value, "bbbb",
        "the reader sees the complete document"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "a reader must not wait on the writer lock; took {elapsed:?}"
    );

    holder.unlock().expect("release the writer lock");
}

/// A reader that loses the race with a `rename` may return the previous
/// complete generation once, but its cached stamp is taken from the handle it
/// actually read, so the next observation must detect the newer generation.
#[test]
fn a_reader_observes_every_committed_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    replace_private_file(&store_path(&dir), &document_bytes("aaaa")).expect("seed document");
    let store = open(&dir, StoreIdentityMode::platform_default());
    assert_eq!(store.snapshot().expect("first read").value, "aaaa");

    for value in ["bbbb", "cccc", "dddd"] {
        replace_private_file(&store_path(&dir), &document_bytes(value)).expect("republish");
        assert_eq!(
            store.snapshot().expect("read after replacement").value,
            value,
            "each committed generation must become visible"
        );
    }
}

/// Length plus modification time is not a change detector. Two atomic
/// replacements can share both — equal payload width, and an `mtime` that a
/// coarse-granularity filesystem records identically — so a cache that trusted
/// them could serve a superseded document forever. Without an exact replacement
/// identity the document is always re-read.
#[test]
fn an_identical_length_and_mtime_replacement_is_still_observed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = store_path(&dir);
    replace_private_file(&path, &document_bytes("aaaa")).expect("seed document");

    let store = open(&dir, StoreIdentityMode::Unavailable);
    assert_eq!(store.snapshot().expect("first read").value, "aaaa");

    let first_times = {
        let metadata = std::fs::metadata(&path).expect("stat seed");
        FileTimes::new()
            .set_accessed(metadata.accessed().expect("accessed"))
            .set_modified(metadata.modified().expect("modified"))
    };

    let replacement = document_bytes("bbbb");
    assert_eq!(
        replacement.len(),
        document_bytes("aaaa").len(),
        "the fixture must keep both generations byte-length identical"
    );
    replace_private_file(&path, &replacement).expect("republish");

    // Reproduce a filesystem that cannot tell the two writes apart in time.
    File::options()
        .write(true)
        .open(&path)
        .expect("reopen for timestamps")
        .set_times(first_times)
        .expect("force an identical mtime");

    let stamped = std::fs::metadata(&path).expect("stat replacement");
    assert_eq!(
        stamped.len() as usize,
        replacement.len(),
        "lengths must match for this regression to mean anything"
    );

    assert_eq!(
        store
            .snapshot()
            .expect("read after an indistinguishable stamp")
            .value,
        "bbbb",
        "a replacement with identical length and mtime must still be observed"
    );
}

/// The Unix fast path is exact rather than merely likely: publication renames a
/// new inode into place, and the cache pins the inode it read, so the identity
/// it compares against cannot be recycled.
#[cfg(unix)]
#[test]
fn the_native_identity_fast_path_also_observes_an_indistinguishable_stamp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = store_path(&dir);
    replace_private_file(&path, &document_bytes("aaaa")).expect("seed document");

    let store = open(&dir, StoreIdentityMode::Native);
    assert_eq!(store.snapshot().expect("first read").value, "aaaa");

    let first_times = {
        let metadata = std::fs::metadata(&path).expect("stat seed");
        FileTimes::new()
            .set_accessed(metadata.accessed().expect("accessed"))
            .set_modified(metadata.modified().expect("modified"))
    };
    replace_private_file(&path, &document_bytes("bbbb")).expect("republish");
    File::options()
        .write(true)
        .open(&path)
        .expect("reopen for timestamps")
        .set_times(first_times)
        .expect("force an identical mtime");

    assert_eq!(
        store
            .snapshot()
            .expect("read after an indistinguishable stamp")
            .value,
        "bbbb"
    );
}

/// Corruption stays an error on the lock-free read path. Silently returning an
/// empty document would let a mutation republish it and erase every record.
#[test]
fn a_corrupt_document_is_an_error_not_an_empty_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = store_path(&dir);
    replace_private_file(&path, &document_bytes("aaaa")).expect("seed document");
    let store = open(&dir, StoreIdentityMode::platform_default());
    assert_eq!(store.snapshot().expect("first read").value, "aaaa");

    let mut corrupt = tempfile::NamedTempFile::new_in(dir.path()).expect("temp");
    corrupt
        .write_all(b"{ not json")
        .expect("write corrupt bytes");
    corrupt.persist(&path).expect("replace with corruption");

    assert!(
        store.snapshot().is_err(),
        "an unparseable shared document must fail closed"
    );
}
