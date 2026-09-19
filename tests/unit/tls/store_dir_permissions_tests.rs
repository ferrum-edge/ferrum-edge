//! Regression coverage for TLS store directory permissions (GHSA-62hx-fwcg-mwgr).

#![cfg(unix)]

use ferrum_edge::tls::events::TlsEventLog;
use ferrum_edge::tls::managed::{ManagedTlsRecord, ManagedTlsStore};

#[test]
fn freshly_created_store_dir_is_owner_only() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let parent = tempfile::tempdir().expect("tempdir");
    let store_dir = parent.path().join("managed-tls");

    let store = ManagedTlsStore::open(&store_dir).expect("open managed store");

    use std::os::unix::fs::PermissionsExt;

    let dir_mode = std::fs::metadata(&store_dir)
        .expect("store dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "store directory must be owner-only");

    // The document is written on the first mutation, not on open.
    let record = ManagedTlsRecord::new_ca_bundle(
        "ca".to_string(),
        "ca".to_string(),
        None,
        "pem".to_string(),
    );
    store.upsert(record, false).expect("first write");

    let store_file = store_dir.join("managed-tls.json");
    assert!(store_file.is_file(), "managed store file must exist");
    let file_mode = std::fs::metadata(&store_file)
        .expect("store file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "store file must remain owner-only");
}

#[test]
fn event_log_store_dir_is_owner_only() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let parent = tempfile::tempdir().expect("tempdir");
    let store_dir = parent.path().join("tls-events");
    let event_path = store_dir.join("tls-events.json");

    TlsEventLog::open(16, Some(event_path.clone())).expect("open event log");

    use std::os::unix::fs::PermissionsExt;

    let dir_mode = std::fs::metadata(&store_dir)
        .expect("store dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "event log directory must be owner-only");

    let file_mode = std::fs::metadata(&event_path)
        .expect("event log file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "event log file must remain owner-only");
}

#[test]
fn preexisting_permissive_store_dir_is_not_tightened() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().expect("tempdir");
    let store_dir = parent.path().join("managed-tls");
    std::fs::create_dir(&store_dir).expect("mkdir");
    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    ManagedTlsStore::open(&store_dir).expect("open managed store");

    let dir_mode = std::fs::metadata(&store_dir)
        .expect("store dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o755,
        "pre-existing permissive directory must not be chmodded"
    );
}

// Exercise every persistent-store consumer through its public open path. The
// helper must reject unsafe directories before any store can write into them.
fn open_store(kind: &str, directory: &std::path::Path) -> bool {
    use ferrum_edge::tls::acme::{AcmeAccountStore, AcmeCertificateStore, AcmeOrderStore};
    use ferrum_edge::tls::lease::TlsLeaseStore;

    match kind {
        "managed" => ManagedTlsStore::open(directory).is_ok(),
        "certificates" => AcmeCertificateStore::open(directory).is_ok(),
        "orders" => AcmeOrderStore::open(directory).is_ok(),
        "accounts" => AcmeAccountStore::open(directory).is_ok(),
        "leases" => TlsLeaseStore::open_with_holder(directory, "test-holder".to_string()).is_ok(),
        "events" => TlsEventLog::open(16, Some(directory.join("tls-events.json"))).is_ok(),
        "limited-events" => TlsEventLog::open_with_document_limit(
            16,
            Some(directory.join("tls-events.json")),
            1024 * 1024,
        )
        .is_ok(),
        _ => panic!("unknown store"),
    }
}

const STORE_KINDS: &[&str] = &[
    "managed",
    "certificates",
    "orders",
    "accounts",
    "leases",
    "events",
    "limited-events",
];

fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn all_stores_create_private_missing_parents_without_chmodding_existing_ancestors() {
    use std::os::unix::fs::PermissionsExt;

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let foreign = root.path().join("unrelated");
    std::fs::write(&foreign, b"preserve me").unwrap();
    for kind in STORE_KINDS {
        let parent = root.path().join(kind);
        let directory = parent.join("nested").join("store");
        assert!(open_store(kind, &directory), "{kind}");
        assert_eq!(mode(&parent), 0o700, "{kind} parent");
        assert_eq!(mode(&parent.join("nested")), 0o700, "{kind} nested parent");
        assert_eq!(mode(&directory), 0o700, "{kind} leaf");
        assert_eq!(mode(root.path()), 0o755, "existing ancestor is unchanged");
    }
    assert_eq!(std::fs::read(foreign).unwrap(), b"preserve me");
}

#[test]
fn all_stores_reject_existing_and_dangling_leaf_symlinks_without_touching_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("foreign");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(target.join("keep"), b"foreign data").unwrap();
    let missing = root.path().join("missing");
    for kind in STORE_KINDS {
        let link = root.path().join(kind);
        symlink(&target, &link).unwrap();
        assert!(!open_store(kind, &link), "{kind} must reject a leaf link");
        // Trailing slash / dot must not turn a leaf link into an accepted dir.
        assert!(!open_store(kind, &link.join("")), "{kind} trailing slash");
        assert!(!open_store(kind, &link.join(".")), "{kind} trailing dot");
        let dangling = root.path().join(format!("{kind}-dangling"));
        symlink(&missing, &dangling).unwrap();
        assert!(!open_store(kind, &dangling), "{kind} dangling leaf");
    }
    assert!(!missing.exists());
    assert_eq!(mode(&target), 0o755);
    assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"foreign data");
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
}

#[test]
fn all_stores_preserve_existing_permissive_directories_and_foreign_files() {
    use std::os::unix::fs::PermissionsExt;

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let root = tempfile::tempdir().unwrap();
    for kind in STORE_KINDS {
        let directory = root.path().join(kind);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let foreign = directory.join("foreign");
        std::fs::write(&foreign, b"keep").unwrap();
        assert!(open_store(kind, &directory), "{kind} warning-only directory");
        assert_eq!(mode(&directory), 0o755);
        assert_eq!(std::fs::read(&foreign).unwrap(), b"keep");
    }
}

#[test]
fn all_stores_propagate_leaf_and_parent_creation_failures() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("foreign-file");
    std::fs::write(&file, b"keep").unwrap();
    for kind in STORE_KINDS {
        assert!(!open_store(kind, &file), "{kind} file leaf");
        assert!(!open_store(kind, &file.join("child")), "{kind} file parent");
        assert!(
            !open_store(kind, &root.path().join("nul\0suffix")),
            "{kind} invalid path"
        );
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
