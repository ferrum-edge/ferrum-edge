//! Tests for Vault secret resolution.
//!
//! These test the reference parsing and env var detection logic.
//! Actual Vault connectivity tests require a running Vault server.

use ferrum_edge::secrets::resolve_secret;

use crate::unit::env_lock::with_env_vars_async;

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

/// Resolve a deliberately malformed reference so the call stops right after
/// client construction: "Invalid Vault KV v2 reference" proves `VAULT_ADDR`
/// was admitted, any other error is the construction refusal itself.
fn vault_addr_outcome(key: &str, addr: &str, allow_plaintext: &str) -> String {
    let reference_key = format!("{key}_VAULT");
    let mut outcome = String::new();
    let slot = &mut outcome;
    with_env_vars_async(
        &[
            (reference_key.as_str(), "invalid-no-data-segment"),
            ("VAULT_ADDR", addr),
            ("VAULT_TOKEN", "plaintext-token-sentinel"),
            ("FERRUM_VAULT_ALLOW_PLAINTEXT", allow_plaintext),
        ],
        || async move {
            *slot = resolve_secret(key)
                .await
                .expect_err("a malformed reference never resolves");
        },
    );
    outcome
}

#[test]
fn test_vault_plaintext_http_to_remote_host_is_refused() {
    // Issue #6582: VAULT_TOKEN rides every request, so plaintext to a remote
    // host hands it to any on-path observer.
    for addr in [
        "http://vault.example.com:8200",
        "http://10.0.0.5:8200",
        "http://[2001:db8::1]:8200",
        "http://localhost.example.com:8200",
    ] {
        let err = vault_addr_outcome("FERRUM_TEST_VAULT_F", addr, "");
        assert!(
            err.contains("VAULT_ADDR must use https")
                && err.contains("FERRUM_VAULT_ALLOW_PLAINTEXT"),
            "{addr}: {err}"
        );
        assert!(!err.contains("example.com") && !err.contains("10.0.0.5"));
        assert!(!err.contains("plaintext-token-sentinel"));
    }
}

#[test]
fn test_vault_plaintext_http_to_loopback_and_https_are_admitted() {
    for addr in [
        "http://127.0.0.1:8200",
        "http://127.8.9.10:8200",
        "http://localhost:8200",
        "http://LOCALHOST:8200",
        "http://[::1]:8200",
        "http://[::ffff:127.0.0.1]:8200",
        "https://vault.example.com:8200",
    ] {
        let err = vault_addr_outcome("FERRUM_TEST_VAULT_G", addr, "");
        assert!(
            err.contains("Invalid Vault KV v2 reference"),
            "{addr} must construct a client: {err}"
        );
    }
}

#[test]
fn test_vault_plaintext_opt_in_admits_remote_http() {
    for allow in ["true", "TRUE", "1", "yes"] {
        let err = vault_addr_outcome(
            "FERRUM_TEST_VAULT_H",
            "http://vault.example.com:8200",
            allow,
        );
        assert!(
            err.contains("Invalid Vault KV v2 reference"),
            "FERRUM_VAULT_ALLOW_PLAINTEXT={allow} must admit remote http: {err}"
        );
    }
    for deny in ["false", "0", "no"] {
        let err = vault_addr_outcome("FERRUM_TEST_VAULT_H", "http://vault.example.com:8200", deny);
        assert!(err.contains("VAULT_ADDR must use https"), "{deny}: {err}");
    }
}

#[test]
fn test_vault_plaintext_opt_in_rejects_an_unrecognized_value() {
    // A typo must not read as either answer, even for an https address.
    for addr in [
        "http://vault.example.com:8200",
        "https://vault.example.com:8200",
    ] {
        let err = vault_addr_outcome("FERRUM_TEST_VAULT_I", addr, "maybe");
        assert!(
            err.contains("FERRUM_VAULT_ALLOW_PLAINTEXT must be true or false"),
            "{addr}: {err}"
        );
    }
}
