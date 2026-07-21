use ferrum_edge::secrets::file::{read_secret, read_secret_detached, resolve_ref};
use std::io::Write;

use crate::unit::env_lock::ENV_LOCK;

#[test]
fn file_secret_reads_use_detached_os_thread_not_spawn_blocking() {
    let file_src = include_str!("../../../src/secrets/file.rs");
    let registry_src = include_str!("../../../src/secrets/registry.rs");

    assert!(
        file_src.contains("pub async fn read_secret_detached"),
        "the canonical _FILE async read must live in secrets::file"
    );
    assert!(
        file_src.contains("ferrum-secret-file"),
        "detached reader threads must keep the ferrum-secret-file name"
    );
    assert!(
        file_src.contains("drop(join_handle)"),
        "JoinHandle must be dropped explicitly so the OS thread detaches"
    );
    let file_code_lines = file_src.lines().filter(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//")
    });
    assert!(
        file_code_lines.all(|line| !line.contains("spawn_blocking")),
        "_FILE reads must not use Tokio's blocking pool"
    );
    assert!(
        registry_src.contains("file::read_secret_detached"),
        "FileBackend must delegate to the shared detached reader"
    );
}

#[test]
fn read_secret_reads_file_content() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "super-secret").unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
    assert_eq!(result.unwrap(), "super-secret");
}

#[test]
fn read_secret_detached_reads_ordinary_file() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "detached-secret\n").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(read_secret_detached(&path, "TEST_KEY"));
    assert_eq!(result.unwrap(), "detached-secret");
}

#[test]
fn read_secret_trims_trailing_whitespace() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "my-secret\n\n").unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
    assert_eq!(result.unwrap(), "my-secret");
}

#[test]
fn read_secret_trims_trailing_spaces_and_tabs() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "password123  \t").unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
    assert_eq!(result.unwrap(), "password123");
}

#[test]
fn read_secret_preserves_leading_whitespace() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "  leading-space").unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
    assert_eq!(result.unwrap(), "  leading-space");
}

#[test]
fn read_secret_error_for_nonexistent_file() {
    let missing = "/nonexistent/path/secret.txt";
    let result = read_secret(missing, "MY_KEY");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Failed to read MY_KEY_FILE"));
    assert!(
        !err.contains(missing),
        "source path must not be disclosed, got: {err}"
    );
}

#[test]
fn read_secret_detached_error_for_nonexistent_file_redacts_path() {
    let missing = "/nonexistent/path/detached-secret.txt";
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(read_secret_detached(missing, "MY_KEY"))
        .expect_err("missing file must fail");
    assert!(err.contains("Failed to read MY_KEY_FILE"));
    assert!(
        !err.contains(missing),
        "source path must not be disclosed, got: {err}"
    );
}

#[test]
fn read_secret_error_for_empty_file() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "EMPTY_KEY");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("is empty after trimming"));
}

#[test]
fn read_secret_error_for_whitespace_only_file() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "   \n\n\t  ").unwrap();
    let result = read_secret(tmp.path().to_str().unwrap(), "WS_KEY");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("is empty after trimming"));
}

#[test]
fn resolve_ref_returns_none_when_not_set() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(resolve_ref("FERRUM_TEST_SECRET_NOT_SET_XYZ_99999").is_none());
}

#[test]
fn resolve_ref_returns_path_when_set() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let key = "FERRUM_TEST_SECRET_FILE_REF_12345";
    let file_key = format!("{}_FILE", key);
    // SAFETY: We hold a mutex preventing concurrent env access.
    unsafe { std::env::set_var(&file_key, "/run/secrets/db_password") };
    assert_eq!(
        resolve_ref(key),
        Some("/run/secrets/db_password".to_string())
    );
    unsafe { std::env::remove_var(&file_key) };
}
