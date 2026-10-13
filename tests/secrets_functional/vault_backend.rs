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

/// Provider material is resolved directly into pool-owned files. Rotations,
/// rejected partial generations, and the last pool clone all exercise the
/// same ownership path as file and inline sources in the ordinary unit lane.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn vault_database_tls_snapshots_follow_pool_lifetime() {
    use ferrum_edge::config::{DbTlsMode, EnvConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    let guard = EnvGuard::new();
    let Some(vault) = try_vault("vault_database_tls_snapshots_follow_pool_lifetime").await else {
        return;
    };
    guard.set("VAULT_ADDR", &vault.addr);
    guard.set("VAULT_TOKEN", &vault.token);
    let dir = tempfile::tempdir().unwrap();
    guard.set_other("TMPDIR", dir.path().to_str().unwrap());
    let foreign = dir.path().join("ferrum-db-client-key-foreign.pem");
    std::fs::write(&foreign, "foreign owner").unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    for db_type in ["postgres", "mysql"] {
        let env = EnvConfig {
            db_type: Some(db_type.into()),
            db_url: Some(format!("{db_type}://localhost/ferrum")),
            db_tls_mode: Some(DbTlsMode::VerifyFull),
            db_tls_ca_cert_path: Some("vault://secret/data/db-tls#ca".into()),
            db_tls_client_cert_path: Some("vault://secret/data/db-tls#cert".into()),
            db_tls_client_key_path: Some("vault://secret/data/db-tls#key".into()),
            ..EnvConfig::default()
        };
        let backend = env.effective_sql_backend().unwrap();
        let options = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .min_connections(0)
            .idle_timeout(None)
            .max_lifetime(None);
        let mut old = None;
        let mut old_paths = Vec::<PathBuf>::new();
        for generation in 0..3 {
            let material = format!("provider generation {generation}");
            client
                .post(format!("{}/v1/secret/data/db-tls", vault.addr))
                .header("X-Vault-Token", &vault.token)
                .json(&serde_json::json!({
                    "data": { "ca": material, "cert": material, "key": material }
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            let pool = backend.connect_lazy(options.clone(), 10).await.unwrap();
            let paths: Vec<PathBuf> = pool
                .connect_options()
                .database_url
                .query_pairs()
                .filter(|(key, _)| key != "sslmode" && key != "ssl-mode")
                .map(|(_, value)| PathBuf::from(value.as_ref()))
                .collect();
            assert_eq!(paths.len(), 3);
            for path in &paths {
                assert_eq!(std::fs::read_to_string(path).unwrap(), material);
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            for path in &old_paths {
                assert_eq!(
                    std::fs::read_to_string(path).unwrap(),
                    "provider generation 0"
                );
            }
            if generation == 0 {
                old = Some(pool.clone());
                old_paths = paths;
            }
            drop(pool);
            // Exactly the retained generation plus the foreign sentinel.
            // An EnvConfig keep()-persisted layer would grow this on each call.
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 4);
        }
        let mut rejected = env;
        rejected.db_tls_client_key_path = Some("vault://secret/data/db-tls#absent".into());
        assert!(
            rejected
                .effective_sql_backend()
                .unwrap()
                .connect_lazy(options, 10)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 4);
        let observer = dir.path().join("key-observer");
        std::fs::hard_link(&old_paths[2], &observer).unwrap();
        drop(old);
        for path in old_paths {
            assert!(!path.exists());
        }
        assert!(
            std::fs::read(&observer)
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        std::fs::remove_file(observer).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read_to_string(&foreign).unwrap(), "foreign owner");
    }
}

// --- Plaintext transport policy (issue #6582) -------------------------------
//
// `VAULT_ADDR` must use https unless the host is loopback or
// `FERRUM_VAULT_ALLOW_PLAINTEXT=true`, and the same rule follows redirects and
// keeps loopback traffic off any configured proxy.

/// Stop resolution right after client construction: "Invalid Vault KV v2
/// reference" proves `VAULT_ADDR` was admitted, any other error is the
/// construction refusal itself.
async fn vault_construction_outcome(guard: &EnvGuard, address: &str, allow: &str) -> String {
    guard.set("VAULT_ADDR", address);
    guard.set("VAULT_TOKEN", "plaintext-token-sentinel");
    guard.set("FERRUM_VAULT_ALLOW_PLAINTEXT", allow);
    resolve_external_reference("vault", "invalid-reference", "FERRUM_TEST")
        .await
        .err()
        .expect("a malformed reference never resolves")
}

fn kv2_body(field: &str) -> serde_json::Value {
    serde_json::json!({
        "request_id": "plaintext-policy",
        "lease_id": "",
        "lease_duration": 0,
        "renewable": false,
        "data": {
            "data": { "field": field },
            "metadata": {
                "created_time": "2026-01-01T00:00:00Z",
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        }
    })
}

/// A non-loopback address of this host, or `None` when it has no route. A
/// server bound on `0.0.0.0` is reachable there, which lets a test stand up a
/// "remote" plaintext destination and observe whether it was contacted.
fn non_loopback_local_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

async fn mock_server_on_all_interfaces() -> MockServer {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind 0.0.0.0");
    MockServer::builder().listener(listener).start().await
}

#[tokio::test]
#[serial]
async fn vault_plaintext_http_to_remote_host_is_refused() {
    let guard = EnvGuard::new();
    for address in [
        "http://vault.example.com:8200",
        "http://10.0.0.5:8200",
        "http://[2001:db8::1]:8200",
        "http://localhost.example.com:8200",
    ] {
        let error = vault_construction_outcome(&guard, address, "").await;
        assert!(
            error.contains("VAULT_ADDR must use https")
                && error.contains("FERRUM_VAULT_ALLOW_PLAINTEXT"),
            "{address}: {error}"
        );
        assert!(!error.contains("example.com") && !error.contains("10.0.0.5"));
        assert!(!error.contains("plaintext-token-sentinel"));
    }
}

#[tokio::test]
#[serial]
async fn vault_loopback_http_and_remote_https_are_admitted() {
    let guard = EnvGuard::new();
    for address in [
        "http://127.0.0.1:8200",
        "http://127.8.9.10:8200",
        "http://localhost:8200",
        "http://LOCALHOST:8200",
        "http://[::1]:8200",
        "http://[::ffff:127.0.0.1]:8200",
        "https://vault.example.com:8200",
    ] {
        let error = vault_construction_outcome(&guard, address, "").await;
        assert!(
            error.contains("Invalid Vault KV v2 reference"),
            "{address} must construct a client: {error}"
        );
    }
}

#[tokio::test]
#[serial]
async fn vault_plaintext_opt_in_is_explicit_and_strict() {
    let guard = EnvGuard::new();
    let remote = "http://vault.example.com:8200";
    for allow in ["true", "TRUE", "1", "yes"] {
        let error = vault_construction_outcome(&guard, remote, allow).await;
        assert!(
            error.contains("Invalid Vault KV v2 reference"),
            "FERRUM_VAULT_ALLOW_PLAINTEXT={allow} must admit remote http: {error}"
        );
    }
    for deny in ["false", "0", "no"] {
        let error = vault_construction_outcome(&guard, remote, deny).await;
        assert!(
            error.contains("VAULT_ADDR must use https"),
            "{deny}: {error}"
        );
    }
    // A typo must not read as either answer, even for an https address.
    for address in [remote, "https://vault.example.com:8200"] {
        let error = vault_construction_outcome(&guard, address, "maybe").await;
        assert!(
            error.contains("FERRUM_VAULT_ALLOW_PLAINTEXT must be true or false"),
            "{address}: {error}"
        );
    }
}

/// reqwest strips `Authorization` on a cross-origin redirect but not
/// `X-Vault-Token`, so an admitted loopback address must not be able to bounce
/// the token to a plaintext remote host.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_redirect_to_remote_plaintext_is_refused_before_any_request() {
    let guard = EnvGuard::new();
    let Some(lan_ip) = non_loopback_local_ip() else {
        eprintln!("skipping: this host has no non-loopback address to stand in for a remote host");
        return;
    };
    let remote = mock_server_on_all_interfaces().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_body("leaked")))
        .mount(&remote)
        .await;
    let remote_port = remote.address().port();

    let local = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "Location",
            format!("http://{lan_ip}:{remote_port}/v1/secret/data/app").as_str(),
        ))
        .mount(&local)
        .await;

    guard.set("VAULT_ADDR", local.uri());
    guard.set("VAULT_TOKEN", "redirect-token-sentinel");
    let outcome = resolve_external_reference("vault", "secret/data/app#field", "FERRUM_TEST").await;
    assert!(
        outcome.is_err(),
        "a redirect to remote plaintext must not resolve the secret"
    );
    assert!(
        remote
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the plaintext redirect target must never receive the token"
    );

    // The explicit opt-in follows the same redirect.
    guard.set("FERRUM_VAULT_ALLOW_PLAINTEXT", "true");
    let resolved = resolve_external_reference("vault", "secret/data/app#field", "FERRUM_TEST")
        .await
        .expect("the opt-in admits plaintext redirects");
    assert_eq!(resolved.value, "leaked");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_loopback_redirect_is_followed() {
    let guard = EnvGuard::new();
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .and(header("X-Vault-Token", "loopback-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_body("followed")))
        .expect(1)
        .mount(&target)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "Location",
            format!("{}/v1/secret/data/app", target.uri()).as_str(),
        ))
        .mount(&origin)
        .await;

    guard.set("VAULT_ADDR", origin.uri());
    guard.set("VAULT_TOKEN", "loopback-token");
    let resolved = resolve_external_reference("vault", "secret/data/app#field", "FERRUM_TEST")
        .await
        .expect("a loopback-to-loopback redirect is followed");
    assert_eq!(resolved.value, "followed");
    target.verify().await;
}

/// A loopback `http` Vault never goes through `HTTP_PROXY`: the proxy may be
/// remote, and the request would carry the token to it in plaintext.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_loopback_http_bypasses_http_proxy() {
    let guard = EnvGuard::new();
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&proxy)
        .await;
    let vault = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_body("direct")))
        .expect(1)
        .mount(&vault)
        .await;

    for key in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        guard.set_other(key, proxy.uri());
    }
    for key in ["NO_PROXY", "no_proxy"] {
        guard.set_other(key, "");
    }
    guard.set("VAULT_ADDR", vault.uri());
    guard.set("VAULT_TOKEN", "proxy-token-sentinel");
    let resolved = resolve_external_reference("vault", "secret/data/app#field", "FERRUM_TEST")
        .await
        .expect("loopback Vault resolves directly");
    assert_eq!(resolved.value, "direct");
    assert!(
        proxy
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the proxy must never see the loopback Vault request"
    );
    vault.verify().await;
}

/// Startup resolution runs before logging exists, so the opt-in warning is
/// deferred and must still appear exactly once.
#[tokio::test]
#[serial]
async fn vault_plaintext_opt_in_warning_survives_startup_resolution() {
    let Some(lan_ip) = non_loopback_local_ip() else {
        eprintln!("skipping: this host has no non-loopback address to stand in for a remote host");
        return;
    };
    let temp = tempfile::TempDir::new().unwrap();
    let vault = mock_server_on_all_interfaces().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(kv2_body("valid-vault-admin-secret-0123456789abcdef")),
        )
        .mount(&vault)
        .await;
    let address = format!("http://{lan_ip}:{}", vault.address().port());
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        vault_cli_command(&temp, "validate")
            .env("VAULT_ADDR", &address)
            .env("FERRUM_VAULT_ALLOW_PLAINTEXT", "true")
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
    assert_eq!(
        diagnostic
            .matches("Vault traffic uses plaintext http to a non-loopback host")
            .count(),
        1,
        "{diagnostic}"
    );
}

/// `localhost` is admitted as loopback by name, and the transport pins it to
/// the loopback addresses rather than the system resolver.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn vault_localhost_http_resolves_to_loopback() {
    let guard = EnvGuard::new();
    let vault = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_body("pinned")))
        .expect(1)
        .mount(&vault)
        .await;
    guard.set(
        "VAULT_ADDR",
        format!("http://localhost:{}", vault.address().port()),
    );
    guard.set("VAULT_TOKEN", "localhost-token-sentinel");
    let resolved = resolve_external_reference("vault", "secret/data/app#field", "FERRUM_TEST")
        .await
        .expect("localhost Vault resolves over loopback");
    assert_eq!(resolved.value, "pinned");
    vault.verify().await;
}

/// A redirect that only the opt-in admits carries the token off the host in
/// plaintext, so it warns exactly like a plaintext `VAULT_ADDR` does.
#[tokio::test]
#[serial]
async fn vault_opted_in_plaintext_redirect_warns_once() {
    let Some(lan_ip) = non_loopback_local_ip() else {
        eprintln!("skipping: this host has no non-loopback address to stand in for a remote host");
        return;
    };
    let temp = tempfile::TempDir::new().unwrap();
    let remote = mock_server_on_all_interfaces().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(kv2_body("valid-vault-admin-secret-0123456789abcdef")),
        )
        .mount(&remote)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .respond_with(
            ResponseTemplate::new(307).insert_header(
                "Location",
                format!(
                    "http://{lan_ip}:{}/v1/secret/data/app",
                    remote.address().port()
                )
                .as_str(),
            ),
        )
        .mount(&origin)
        .await;
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        vault_cli_command(&temp, "validate")
            .env("VAULT_ADDR", origin.uri())
            .env("FERRUM_VAULT_ALLOW_PLAINTEXT", "true")
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
    assert_eq!(
        diagnostic
            .matches("Vault traffic uses plaintext http to a non-loopback host")
            .count(),
        1,
        "{diagnostic}"
    );
}
