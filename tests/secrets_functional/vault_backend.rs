//! HashiCorp Vault (KV v2) functional tests.
//!
//! Connectivity tests run against a Vault dev server started in Docker via
//! testcontainers. When the container is unavailable they FAIL in CI (where
//! Docker is required) and skip with a printed notice locally. Reference-shape,
//! missing-credential, and timeout tests need no Vault server and always run.

use crate::common::containers::{VaultContainer, fail_in_ci_else_skip, start_vault_dev_container};
use crate::common::env::{EnvGuard, assert_resolved_var};
use ferrum_edge::secrets::{resolve_all_env_secrets, resolve_external_reference, resolve_secret};
use serial_test::serial;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const INVALID_ADDRESSES: &[(&str, &str)] = &[
    ("", "not a valid URL"),
    ("not a url", "not a valid URL"),
    ("https://vault.example.com:99999", "not a valid URL"),
    (
        "https://address-user:address-password@[invalid",
        "not a valid URL",
    ),
    ("ftp://vault.example.com", "must use http or https"),
];

#[tokio::test]
#[serial]
async fn vault_address_validation_precedes_reference_parsing_without_panicking() {
    let guard = EnvGuard::new();
    guard.set("VAULT_TOKEN", "address-token-sentinel");
    for &(address, reason) in INVALID_ADDRESSES {
        guard.set("VAULT_ADDR", address);
        let error = resolve_external_reference("vault", "invalid-reference", "FERRUM_TEST")
            .await
            .err()
            .expect("invalid address must return an ordinary error");
        assert!(error.contains("VAULT_ADDR") && error.contains(reason));
        assert!(!error.contains("address-user"));
        assert!(!error.contains("address-password"));
        assert!(!error.contains("address-token-sentinel"));
    }

    // VaultClientWrapper is private. The public provider path constructs it
    // before checking KV v2 reference shape, so this exact later error proves
    // both schemes constructed successfully without requiring a network call.
    for address in ["https://vault.example.com:8200", "http://127.0.0.1:8200"] {
        guard.set("VAULT_ADDR", address);
        let error = resolve_external_reference("vault", "invalid-reference", "FERRUM_TEST")
            .await
            .err()
            .expect("construction succeeds before the reference is rejected");
        assert!(error.contains("Invalid Vault KV v2 reference"), "{error}");
    }
}

#[tokio::test]
#[serial]
async fn vault_invalid_address_fails_single_and_batch_resolution() {
    let guard = EnvGuard::new();
    guard.set("VAULT_TOKEN", "address-token-sentinel");
    guard.set("FERRUM_ADMIN_JWT_SECRET_VAULT", "secret/data/app#field");
    for &(address, reason) in INVALID_ADDRESSES {
        guard.set("VAULT_ADDR", address);
        let single = resolve_secret("FERRUM_ADMIN_JWT_SECRET")
            .await
            .err()
            .expect("single-key resolution must reject the address");
        let batch = resolve_all_env_secrets()
            .await
            .err()
            .expect("startup resolution must reject the address");
        for error in [single, batch] {
            assert!(error.contains("VAULT_ADDR") && error.contains(reason));
            assert!(!error.contains("address-password"));
            assert!(!error.contains("address-token-sentinel"));
            assert!(!error.contains("secret/data/app"));
        }
    }
}

// Keep these CLI regressions in the required Secret Backends feature lane:
// the ordinary functional shard builds without secrets-vault. Cargo supplies
// the binary built with this test target's features; a missing binary fails.
fn vault_cli_command(temp: &tempfile::TempDir, subcommand: &str) -> tokio::process::Command {
    let settings = temp.path().join("ferrum.conf");
    std::fs::write(&settings, "").expect("write isolated settings");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_ferrum-edge"));
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SystemRoot",
        "USERPROFILE",
        "LLVM_PROFILE_FILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .arg(subcommand)
        .current_dir(temp.path())
        .env("FERRUM_CONF_PATH", settings)
        .env("FERRUM_MODE", "database")
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        .env("FERRUM_ADMIN_JWT_SECRET_VAULT", "secret/data/app#field")
        .env("VAULT_TOKEN", "address-token-sentinel")
        .kill_on_drop(true);
    command
}

#[tokio::test]
#[serial]
async fn vault_invalid_address_cli_exits_normally_with_redacted_diagnostic() {
    let temp = tempfile::TempDir::new().unwrap();
    for subcommand in ["validate", "run"] {
        for &(address, reason) in INVALID_ADDRESSES {
            let output = tokio::time::timeout(
                Duration::from_secs(15),
                vault_cli_command(&temp, subcommand)
                    .env("VAULT_ADDR", address)
                    .output(),
            )
            .await
            .expect("CLI must exit promptly")
            .expect("spawn the feature-enabled Ferrum binary");
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            // A signal/abort has no exit code on Unix; unwind usually exits 101.
            assert_eq!(output.status.code(), Some(1), "{diagnostic}");
            assert!(diagnostic.contains("secret resolution failed"));
            assert!(diagnostic.contains("VAULT_ADDR") && diagnostic.contains(reason));
            assert!(!diagnostic.contains("panicked"));
            for sensitive in [
                "address-user",
                "address-password",
                "address-token-sentinel",
                "secret/data/app",
            ] {
                assert!(!diagnostic.contains(sensitive));
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn vault_valid_address_cli_fetches_secret_and_validates() {
    let temp = tempfile::TempDir::new().unwrap();
    let vault = MockServer::start().await;
    const SECRET: &str = "valid-vault-admin-secret-0123456789abcdef";
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .and(header("X-Vault-Token", "address-token-sentinel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "vault-address-positive-control",
            "lease_id": "",
            "lease_duration": 0,
            "renewable": false,
            "data": {
                "data": { "field": SECRET },
                "metadata": {
                    "created_time": "2026-01-01T00:00:00Z",
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 1
                }
            }
        })))
        .expect(1)
        .mount(&vault)
        .await;
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        vault_cli_command(&temp, "validate")
            .env("VAULT_ADDR", vault.uri())
            .output(),
    )
    .await
    .expect("validate must exit promptly")
    .expect("spawn the feature-enabled Ferrum binary");
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{diagnostic}");
    assert!(diagnostic.contains("Validation passed."), "{diagnostic}");
    assert!(!diagnostic.contains(SECRET));
    assert!(!diagnostic.contains("address-token-sentinel"));
    vault.verify().await;
}

/// Start a seeded Vault dev server. Fails the test in CI and skips it locally
/// when the container is unavailable.
async fn try_vault(test: &str) -> Option<VaultContainer> {
    match start_vault_dev_container().await {
        Ok(v) => Some(v),
        Err(e) => {
            fail_in_ci_else_skip(test, "Vault dev container", &e);
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_kv2_field_success() {
    let guard = EnvGuard::new();
    let Some(vault) = try_vault("vault_kv2_field_success").await else {
        return;
    };
    guard.set("VAULT_ADDR", &vault.addr);
    guard.set("VAULT_TOKEN", &vault.token);
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_VAULT",
        "secret/data/ferrum#admin_jwt",
    );

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "vault-admin-jwt");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_single_key_without_suffix_success() {
    let guard = EnvGuard::new();
    let Some(vault) = try_vault("vault_single_key_without_suffix_success").await else {
        return;
    };
    guard.set("VAULT_ADDR", &vault.addr);
    guard.set("VAULT_TOKEN", &vault.token);
    // `secret/data/single` has exactly one key, so the `#field` suffix is
    // optional.
    guard.set("FERRUM_ONLY_SECRET_VAULT", "secret/data/single");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert_resolved_var(&result, "FERRUM_ONLY_SECRET", "only-one");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_multi_key_without_suffix_errors() {
    let guard = EnvGuard::new();
    let Some(vault) = try_vault("vault_multi_key_without_suffix_errors").await else {
        return;
    };
    guard.set("VAULT_ADDR", &vault.addr);
    guard.set("VAULT_TOKEN", &vault.token);
    // `secret/data/ferrum` has two keys; without `#field` the resolver cannot
    // pick one deterministically.
    guard.set("FERRUM_ADMIN_JWT_SECRET_VAULT", "secret/data/ferrum");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("ambiguous multi-key secret must fail");
    assert!(
        err.contains("#<json_key>"),
        "error should ask for a #<json_key> suffix, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_missing_field_errors() {
    let guard = EnvGuard::new();
    let Some(vault) = try_vault("vault_missing_field_errors").await else {
        return;
    };
    guard.set("VAULT_ADDR", &vault.addr);
    guard.set("VAULT_TOKEN", &vault.token);
    // A distinctive absent field name, so the absence assertion below cannot
    // pass by accident on a common English word.
    const ABSENT_FIELD: &str = "ferrum-absent-vault-field-sentinel";
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_VAULT",
        &format!("secret/data/ferrum#{ABSENT_FIELD}"),
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing field must fail");
    // The failure class and the base key are the actionable parts and are kept.
    assert!(
        err.contains("does not contain the requested key")
            && err.contains("FERRUM_ADMIN_JWT_SECRET"),
        "error must stay actionable at base-key + failure-class level, got: {err}"
    );
    // The requested field and the Vault path are both parts of the source
    // reference, which is as sensitive as the value it points at.
    assert!(
        !err.contains(ABSENT_FIELD) && !err.contains("secret/data/ferrum"),
        "error must not disclose the source reference or requested field, got: {err}"
    );
}

/// No Vault server required — the reference shape is validated before any read.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_invalid_reference_shape_errors() {
    let guard = EnvGuard::new();
    // A real-looking but unreachable address; the shape check fires first.
    guard.set("VAULT_ADDR", "http://127.0.0.1:1");
    guard.set("VAULT_TOKEN", "root");
    // Missing the required `/data/` segment for KV v2.
    guard.set("FERRUM_ADMIN_JWT_SECRET_VAULT", "secret/ferrum#admin_jwt");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("malformed KV v2 reference must fail");
    assert!(
        err.contains("Invalid Vault KV v2 reference"),
        "expected a KV v2 reference-shape error, got: {err}"
    );
}

/// No Vault server required — missing `VAULT_TOKEN` fails before any network
/// call.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_missing_token_errors() {
    let guard = EnvGuard::new();
    guard.set("VAULT_ADDR", "http://127.0.0.1:1");
    // VAULT_TOKEN intentionally unset.
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_VAULT",
        "secret/data/ferrum#admin_jwt",
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing VAULT_TOKEN must fail");
    assert!(
        err.contains("VAULT_TOKEN"),
        "expected a missing-token error, got: {err}"
    );
}

/// No Vault server required — missing `VAULT_ADDR` fails before any network
/// call.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_missing_addr_errors() {
    let guard = EnvGuard::new();
    guard.set("VAULT_TOKEN", "root");
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_VAULT",
        "secret/data/ferrum#admin_jwt",
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("missing VAULT_ADDR must fail");
    assert!(
        err.contains("VAULT_ADDR"),
        "expected a missing-address error, got: {err}"
    );
}

/// No Vault server required — a slow HTTP endpoint trips the fetch timeout
/// without hanging. Uses an in-process delaying server (not the dev container)
/// so the test is hermetic.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_timeout_errors() {
    let guard = EnvGuard::new();
    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&slow)
        .await;

    guard.set("VAULT_ADDR", slow.uri());
    guard.set("VAULT_TOKEN", "root");
    guard.set("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS", "1");
    guard.set("FERRUM_ADMIN_JWT_SECRET_VAULT", "secret/data/app#field");

    let started = std::time::Instant::now();
    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("slow Vault must time out");
    assert!(
        err.contains("Timeout"),
        "expected a timeout error, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "resolution should give up at ~1s, not hang"
    );
}
