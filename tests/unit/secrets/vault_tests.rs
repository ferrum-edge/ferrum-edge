//! Tests for Vault secret resolution.
//!
//! These test the reference parsing and env var detection logic.
//! Actual Vault connectivity tests require a running Vault server.

use ferrum_edge::secrets::resolve_secret;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
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
        unsafe {
            std::env::remove_var(k);
        }
    }
}

#[test]
fn test_vault_ref_detected() {
    // When _VAULT is set, resolve_secret should detect it as a vault source
    // (will fail at fetch time since no Vault server, but should not return None)
    with_env_vars_async(
        &[
            ("FERRUM_TEST_VAULT_A_VAULT", "secret/data/myapp#jwt_secret"),
            ("VAULT_ADDR", "http://127.0.0.1:8200"),
            ("VAULT_TOKEN", "test-token"),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_VAULT_A").await;
            // Should fail with a connection error, not return None
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("Vault") || err.contains("vault"),
                "Expected Vault-related error, got: {}",
                err
            );
        },
    );
}

#[test]
fn test_vault_ref_conflict_with_direct_value() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_VAULT_B", "direct-value"),
            ("FERRUM_TEST_VAULT_B_VAULT", "secret/data/app#key"),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_VAULT_B").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
        },
    );
}

#[test]
fn test_vault_missing_vault_addr() {
    with_env_vars_async(
        &[("FERRUM_TEST_VAULT_C_VAULT", "secret/data/app#key")],
        || async {
            let result = resolve_secret("FERRUM_TEST_VAULT_C").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("VAULT_ADDR"));
        },
    );
}

#[test]
fn test_vault_missing_vault_token() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_VAULT_D_VAULT", "secret/data/app#key"),
            ("VAULT_ADDR", "http://127.0.0.1:8200"),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_VAULT_D").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("VAULT_TOKEN"));
        },
    );
}

#[test]
fn test_vault_invalid_reference_format() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_VAULT_E_VAULT", "invalid-no-data-segment"),
            ("VAULT_ADDR", "http://127.0.0.1:8200"),
            ("VAULT_TOKEN", "test-token"),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_VAULT_E").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Invalid Vault KV v2 reference"));
        },
    );
}
