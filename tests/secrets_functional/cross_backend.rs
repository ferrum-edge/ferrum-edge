//! Cross-backend registry tests: conflict detection, empty-source handling,
//! prefix scoping, source-key removal, and unsupported-suffix fail-closed
//! behavior. These exercise `resolve_all_env_secrets()` and never touch the
//! network (conflicts and suffix validation are resolved before any fetch).

use crate::common::env::{
    EnvGuard, assert_resolved_var, assert_secret_not_logged_or_exposed, assert_source_removed,
};
use ferrum_edge::secrets::resolve_all_env_secrets;
#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
use ferrum_edge::secrets::resolve_secret;
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

/// (1) A single external source resolves, the base var is injected, the
/// suffixed source key is marked for removal, and the value is not exposed in
/// metadata.
#[tokio::test]
#[serial]
async fn resolves_one_external_source_and_marks_source_for_removal() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secret");
    fs::write(&path, "file-secret-value").unwrap();

    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", path.to_string_lossy());

    let result = resolve_all_env_secrets().await.expect("resolution failed");

    assert_resolved_var(&result, "FERRUM_ADMIN_JWT_SECRET", "file-secret-value");
    assert_source_removed(&result, "FERRUM_ADMIN_JWT_SECRET_FILE");
    assert_secret_not_logged_or_exposed(&result, "file-secret-value");
}

/// (2) A direct env var AND a suffixed external source for the same base key is
/// ambiguous and must error.
#[tokio::test]
#[serial]
async fn direct_env_and_external_source_conflict_errors() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secret");
    fs::write(&path, "from-file").unwrap();

    guard.set("FERRUM_ADMIN_JWT_SECRET", "from-direct-env");
    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", path.to_string_lossy());

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("direct + suffixed source must conflict");
    assert!(
        err.contains("Multiple secret sources"),
        "expected a multiple-sources error, got: {err}"
    );
    assert!(err.contains("FERRUM_ADMIN_JWT_SECRET"));
}

/// (2b) Every compiled-in cloud suffix takes part in conflict detection: a
/// direct env var plus that provider's suffixed source must error before any
/// fetch, through both the single-key and the bulk resolver. No provider
/// address or credentials are configured, so reaching a fetch would surface a
/// different error.
#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
#[tokio::test]
#[serial]
async fn direct_env_conflicts_with_each_enabled_cloud_suffix() {
    let mut sources: Vec<(&str, &str)> = Vec::new();
    #[cfg(feature = "secrets-vault")]
    sources.push(("_VAULT", "secret/data/ferrum#admin_jwt"));
    #[cfg(feature = "secrets-aws")]
    sources.push(("_AWS", "ferrum/admin"));
    #[cfg(feature = "secrets-gcp")]
    sources.push(("_GCP", "projects/p/secrets/s/versions/latest"));
    #[cfg(feature = "secrets-azure")]
    sources.push(("_AZURE", "https://v.vault.azure.net/secrets/admin"));

    for (suffix, reference) in sources {
        let guard = EnvGuard::new();
        guard.set("FERRUM_ADMIN_JWT_SECRET", "from-direct-env");
        guard.set(&format!("FERRUM_ADMIN_JWT_SECRET{suffix}"), reference);

        let single = match resolve_secret("FERRUM_ADMIN_JWT_SECRET").await {
            Ok(_) => panic!("direct env plus {suffix} must conflict in resolve_secret"),
            Err(err) => err,
        };
        assert!(
            single.contains("Multiple secret sources"),
            "{suffix}: expected a multiple-sources error from resolve_secret, got: {single}"
        );

        let bulk = resolve_all_env_secrets()
            .await
            .err()
            .expect("direct env plus a cloud suffix must conflict in bulk resolution");
        assert!(
            bulk.contains("Multiple secret sources") && bulk.contains("FERRUM_ADMIN_JWT_SECRET"),
            "{suffix}: expected a multiple-sources error from bulk resolution, got: {bulk}"
        );
        drop(guard);
    }
}

/// (3) Two suffixed external sources for the same base key must error before
/// any network fetch is attempted. Requires a second recognized backend, so it
/// runs in builds with the AWS provider enabled (e.g. the `secrets-all` job).
#[cfg(feature = "secrets-aws")]
#[tokio::test]
#[serial]
async fn multiple_external_sources_for_same_key_conflict_errors() {
    let guard = EnvGuard::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secret");
    fs::write(&path, "from-file").unwrap();

    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", path.to_string_lossy());
    // No AWS endpoint/creds are configured; the conflict must be detected before
    // the resolver ever tries to reach AWS.
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/admin");

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("two external sources must conflict");
    assert!(
        err.contains("Multiple secret sources"),
        "expected a multiple-sources error, got: {err}"
    );
    assert!(err.contains("FERRUM_ADMIN_JWT_SECRET"));
}

/// (4a) An empty suffixed source is ignored (no resolution, no fetch). Uses the
/// always-available `_FILE` suffix.
#[tokio::test]
#[serial]
async fn empty_file_suffixed_source_is_ignored() {
    let guard = EnvGuard::new();
    guard.set("FERRUM_ADMIN_JWT_SECRET_FILE", "");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert!(result.vars.is_empty(), "empty source must not resolve");
    assert!(result.source_keys_to_remove.is_empty());
}

/// (4b) An empty cloud-suffixed source is ignored and never triggers a fetch.
#[cfg(feature = "secrets-aws")]
#[tokio::test]
#[serial]
async fn empty_aws_suffixed_source_is_ignored() {
    let guard = EnvGuard::new();
    // Empty value: recognized suffix, but no reference -> skipped, no AWS call.
    guard.set("FERRUM_ADMIN_JWT_SECRET_AWS", "");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert!(result.vars.is_empty(), "empty AWS source must not resolve");
}

/// (5) A key without the `FERRUM_` prefix is never treated as a secret source.
#[tokio::test]
#[serial]
async fn non_ferrum_prefix_is_ignored() {
    let guard = EnvGuard::new();
    // Tracked for cleanup even though it is outside the managed prefixes.
    guard.set_other("OTHER_ADMIN_JWT_SECRET_AWS", "ferrum/admin");

    let result = resolve_all_env_secrets().await.expect("resolution failed");
    assert!(
        result.vars.is_empty(),
        "non-FERRUM_ prefixed key must be ignored"
    );
    assert!(result.source_keys_to_remove.is_empty());
}

// ---------------------------------------------------------------------------
// (6) Unsupported-suffix fail-closed behavior when a provider feature is OFF.
// Each runs only in builds where its provider is disabled.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "secrets-aws"))]
#[tokio::test]
#[serial]
async fn unsupported_aws_suffix_errors_when_feature_disabled() {
    assert_unsupported_suffix("FERRUM_ADMIN_JWT_SECRET_AWS", "ferrum/admin", "_AWS").await;
}

#[cfg(not(feature = "secrets-vault"))]
#[tokio::test]
#[serial]
async fn unsupported_vault_suffix_errors_when_feature_disabled() {
    assert_unsupported_suffix(
        "FERRUM_ADMIN_JWT_SECRET_VAULT",
        "secret/data/ferrum#admin_jwt",
        "_VAULT",
    )
    .await;
}

#[cfg(not(feature = "secrets-gcp"))]
#[tokio::test]
#[serial]
async fn unsupported_gcp_suffix_errors_when_feature_disabled() {
    assert_unsupported_suffix(
        "FERRUM_ADMIN_JWT_SECRET_GCP",
        "projects/p/secrets/s/versions/latest",
        "_GCP",
    )
    .await;
}

#[cfg(not(feature = "secrets-azure"))]
#[tokio::test]
#[serial]
async fn unsupported_azure_suffix_errors_when_feature_disabled() {
    assert_unsupported_suffix(
        "FERRUM_ADMIN_JWT_SECRET_AZURE",
        "https://v.vault.azure.net/secrets/admin",
        "_AZURE",
    )
    .await;
}

#[allow(dead_code)]
async fn assert_unsupported_suffix(suffixed_key: &str, reference: &str, suffix: &str) {
    let guard = EnvGuard::new();
    guard.set(suffixed_key, reference);

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("unsupported suffix must fail closed");
    assert!(
        err.contains("Unsupported secret suffix") && err.contains(suffix),
        "expected unsupported-suffix error mentioning {suffix}, got: {err}"
    );
    assert!(
        err.contains("not enabled"),
        "error should explain the provider is not enabled, got: {err}"
    );
}
