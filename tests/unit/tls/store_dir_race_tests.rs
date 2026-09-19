//! Deterministic checks at the mkdir/open and open/path-validation boundaries.
//! Compiled inside store_dir so no production test API or timing hook is needed.

use super::unix::{open_created_dir, verify_path};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn a_leaf_symlink_substituted_after_creation_is_rejected_without_chmod() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("store");
    let moved = root.path().join("moved");
    let target = root.path().join("foreign");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(target.join("keep"), b"foreign data").unwrap();
    std::fs::rename(&leaf, &moved).unwrap();
    symlink(&target, &leaf).unwrap();

    assert!(
        open_created_dir(
            &File::open(root.path()).unwrap(),
            &CString::new("store").unwrap(),
            &leaf,
        )
        .is_err()
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"foreign data");
    assert_eq!(std::fs::read_dir(target).unwrap().count(), 1);
    assert!(moved.is_dir());
}

#[test]
fn a_permissive_directory_winning_the_creation_race_is_rejected_without_chmod() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("store");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        open_created_dir(
            &File::open(root.path()).unwrap(),
            &CString::new("store").unwrap(),
            &leaf,
        )
        .is_err()
    );
    assert_eq!(
        std::fs::metadata(leaf).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn replacement_of_an_opened_directory_is_detected_by_identity() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("store");
    let moved = root.path().join("moved");
    std::fs::create_dir(&leaf).unwrap();
    let original = File::open(&leaf).unwrap();
    std::fs::rename(&leaf, &moved).unwrap();
    std::fs::create_dir(&leaf).unwrap();
    assert!(verify_path(&leaf, &original.metadata().unwrap()).is_err());
    assert!(verify_path(&moved, &original.metadata().unwrap()).is_ok());
}

#[test]
fn a_disappearing_leaf_is_an_error_and_is_not_recreated_by_validation() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("store");
    std::fs::create_dir(&leaf).unwrap();
    let original = File::open(&leaf).unwrap();
    std::fs::rename(&leaf, root.path().join("moved")).unwrap();
    assert!(verify_path(&leaf, &original.metadata().unwrap()).is_err());
    assert!(!leaf.exists());
}

#[test]
fn current_directory_and_empty_relative_event_parent_remain_supported() {
    super::create_private_store_dir(std::path::Path::new(".")).unwrap();
    super::create_private_store_dir(std::path::Path::new("")).unwrap();
}

#[test]
fn restricted_owner_permissions_are_not_widened_after_creation() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("store");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        open_created_dir(
            &File::open(root.path()).unwrap(),
            &CString::new("store").unwrap(),
            &leaf,
        )
        .is_err()
    );
    assert_eq!(
        std::fs::metadata(leaf).unwrap().permissions().mode() & 0o777,
        0o500
    );
}

#[test]
fn concurrent_creators_accept_only_the_same_private_directory() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("parent/nested/store");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let leaf = leaf.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                super::create_private_store_dir(&leaf).unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        std::fs::metadata(&leaf).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(std::fs::read_dir(&leaf).unwrap().count(), 0);
}
