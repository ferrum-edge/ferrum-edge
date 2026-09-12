//! Regression coverage for TLS store directory permissions (GHSA-62hx-fwcg-mwgr).

use ferrum_edge::tls::events::TlsEventLog;
use ferrum_edge::tls::managed::{ManagedTlsRecord, ManagedTlsStore};

#[cfg(unix)]
struct UmaskGuard {
    previous: libc::mode_t,
}

#[cfg(unix)]
impl UmaskGuard {
    fn new(umask: libc::mode_t) -> Self {
        let previous = unsafe { libc::umask(umask) };
        Self { previous }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

#[cfg(unix)]
#[test]
fn freshly_created_store_dir_is_owner_only_under_permissive_umask() {
    let _umask = UmaskGuard::new(0o022);
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

#[cfg(unix)]
#[test]
fn event_log_store_dir_is_owner_only_under_permissive_umask() {
    let _umask = UmaskGuard::new(0o022);
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

#[cfg(unix)]
#[test]
fn preexisting_permissive_store_dir_is_not_tightened() {
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
