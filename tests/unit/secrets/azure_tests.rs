//! Tests for Azure Key Vault secret resolution and reference grammar.

use ferrum_edge::secrets::{
    azure_apply_tls_version_option, azure_parse_keyvault_reference, resolve_secret,
};

use crate::unit::env_lock::ENV_LOCK;

fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
fn test_azure_ref_conflict_with_direct_value() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_AZURE_A", "direct-value"),
            (
                "FERRUM_TEST_AZURE_A_AZURE",
                "https://myvault.vault.azure.net/secrets/mysecret",
            ),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_AZURE_A").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
        },
    );
}

#[test]
fn parse_unversioned_keyvault_reference() {
    let (vault, name, version) = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets/admin-jwt",
        "FERRUM_TEST",
    )
    .expect("unversioned URL should parse");
    assert_eq!(vault, "https://myvault.vault.azure.net");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version, None);
}

#[test]
fn parse_versioned_keyvault_reference() {
    let (vault, name, version) = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets/admin-jwt/abc123version",
        "FERRUM_TEST",
    )
    .expect("versioned URL should parse");
    assert_eq!(vault, "https://myvault.vault.azure.net");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version.as_deref(), Some("abc123version"));
}

#[test]
fn parse_rejects_extra_path_segments() {
    let err = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets/admin-jwt/v1/extra",
        "FERRUM_TEST",
    )
    .expect_err("extra segments must fail closed");
    assert!(
        err.contains("unexpected path segments"),
        "expected extra-segment error, got: {err}"
    );
}

#[test]
fn parse_rejects_empty_secret_name_segment() {
    let err = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets//v1",
        "FERRUM_TEST",
    )
    .expect_err("empty secret name must fail");
    assert!(
        err.contains("secret name must not be empty"),
        "expected empty-name error, got: {err}"
    );
}

#[test]
fn parse_trailing_slash_on_unversioned_remains_latest() {
    let (vault, name, version) = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets/admin-jwt/",
        "FERRUM_TEST",
    )
    .expect("trailing slash on unversioned URL must stay latest");
    assert_eq!(vault, "https://myvault.vault.azure.net");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version, None);
}

#[test]
fn parse_rejects_empty_interior_version_segment() {
    let err = azure_parse_keyvault_reference(
        "https://myvault.vault.azure.net/secrets/admin-jwt//",
        "FERRUM_TEST",
    )
    .expect_err("empty interior version segment must fail");
    assert!(
        err.contains("version segment must not be empty"),
        "expected empty-version error, got: {err}"
    );
}

#[test]
fn parse_preserves_explicit_port() {
    let (vault, name, version) = azure_parse_keyvault_reference(
        "http://127.0.0.1:12345/secrets/admin-jwt/v9",
        "FERRUM_TEST",
    )
    .expect("ported URL should parse");
    assert_eq!(vault, "http://127.0.0.1:12345");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version.as_deref(), Some("v9"));
}

#[test]
fn tls_version_option_matches_path_version() {
    let merged = azure_apply_tls_version_option(
        "https://myvault.vault.azure.net/secrets/admin-jwt/v1",
        Some("v1"),
        "TLS cert material",
    )
    .expect("matching versions should accept");
    assert_eq!(
        merged,
        "https://myvault.vault.azure.net/secrets/admin-jwt/v1"
    );
}

#[test]
fn tls_version_option_alone_pins_fetch_reference() {
    let merged = azure_apply_tls_version_option(
        "https://myvault.vault.azure.net/secrets/admin-jwt",
        Some("v1"),
        "TLS cert material",
    )
    .expect("query-only version should pin");
    assert_eq!(
        merged,
        "https://myvault.vault.azure.net/secrets/admin-jwt/v1"
    );
}

#[test]
fn tls_version_option_conflicts_with_path_version() {
    let err = azure_apply_tls_version_option(
        "https://myvault.vault.azure.net/secrets/admin-jwt/v1",
        Some("v2"),
        "TLS cert material",
    )
    .expect_err("conflicting versions must fail closed");
    assert!(
        err.contains("Conflicting Azure Key Vault versions"),
        "expected conflict error, got: {err}"
    );
    assert!(
        !err.contains("myvault") && !err.contains("admin-jwt"),
        "conflict error must not leak the source reference: {err}"
    );
}

#[test]
fn tls_version_option_rejects_empty_query_version() {
    let err = azure_apply_tls_version_option(
        "https://myvault.vault.azure.net/secrets/admin-jwt",
        Some("  "),
        "TLS cert material",
    )
    .expect_err("empty ?version= must fail");
    assert!(
        err.contains("version must not be empty"),
        "expected empty-version error, got: {err}"
    );
}
