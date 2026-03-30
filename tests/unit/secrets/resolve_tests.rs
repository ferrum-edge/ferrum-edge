//! Tests for the secret resolution system (env + file backends).
//!
//! These tests mutate process-global environment variables, so they MUST run
//! serially. We use the same ENV_LOCK pattern as env_config_tests.

use ferrum_edge::secrets::resolve_secret;
use std::io::Write;
use std::sync::Mutex;
use tempfile::NamedTempFile;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set env vars, run an async closure, then clean them up.
fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(f());
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::remove_var(k);
        }
    }
}

#[test]
fn test_resolve_secret_from_env_var() {
    with_env_vars_async(&[("FERRUM_TEST_SECRET_A", "my-secret-value")], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_A").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "my-secret-value");
        assert_eq!(resolved.source, "env");
    });
}

#[test]
fn test_resolve_secret_from_file() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-secret-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_B_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_B").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "file-secret-value");
        assert!(resolved.source.starts_with("file:"));
    });
}

#[test]
fn test_resolve_secret_file_trims_trailing_whitespace() {
    let mut tmp = NamedTempFile::new().unwrap();
    write!(tmp, "secret-with-trailing  \n\n").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_C_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_C").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "secret-with-trailing");
    });
}

#[test]
fn test_resolve_secret_both_env_and_file_errors() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_D", "env-value"),
            ("FERRUM_TEST_SECRET_D_FILE", &path),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_SECRET_D").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
            assert!(err.contains("FERRUM_TEST_SECRET_D"));
        },
    );
}

#[test]
fn test_resolve_secret_neither_set() {
    with_env_vars_async(&[], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_NONE").await;
        assert!(result.unwrap().is_none());
    });
}

#[test]
fn test_resolve_secret_file_not_found() {
    with_env_vars_async(
        &[("FERRUM_TEST_SECRET_E_FILE", "/nonexistent/path/to/secret")],
        || async {
            let result = resolve_secret("FERRUM_TEST_SECRET_E").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Failed to read"));
        },
    );
}

#[test]
fn test_resolve_secret_file_empty() {
    let tmp = NamedTempFile::new().unwrap();
    // File is empty (0 bytes)
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_F_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_F").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("empty"));
    });
}

#[test]
fn test_resolve_secret_empty_env_var_ignored() {
    with_env_vars_async(&[("FERRUM_TEST_SECRET_G", "")], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_G").await;
        assert!(result.unwrap().is_none());
    });
}

#[test]
fn test_resolve_secret_file_preserves_internal_whitespace() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "secret with spaces").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_H_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_H").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "secret with spaces");
    });
}
