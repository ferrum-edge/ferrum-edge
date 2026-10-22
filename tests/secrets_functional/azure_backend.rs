//! Azure Key Vault functional tests against an in-process fake.
//!
//! The real `azure_security_keyvault_secrets::SecretClient` makes real HTTPS
//! calls to the fake, which terminates TLS with a per-fake test CA that the
//! client trusts through `FERRUM_TLS_CA_BUNDLE_PATH`
//! ([`AzureKeyVaultFake::trust_ca`]). The only thing faked out is Entra ID — a
//! dummy bearer token is injected via `AzureCredentials::from_static_token(..)`,
//! so no real Azure AD round trip ever happens.

// `.err().expect(..)` is used deliberately on the secret-returning fetch path:
// the `Ok` value is the resolved secret, and `.expect_err()` (clippy's
// suggestion) would format and print it on an unexpected success. `.err()`
// drops the `Ok` value so a secret can never reach panic output.
#![allow(clippy::err_expect)]

use crate::common::env::EnvGuard;
use crate::common::fakes::AzureKeyVaultFake;
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::secrets::{
    AzureCredentials, azure_apply_tls_version_option, azure_hold_ca_bundle_reader_permit_for_test,
    azure_parse_keyvault_reference, resolve_all_env_secrets, resolve_external_reference,
};
use ferrum_edge::tls::inventory::TlsInventory;
use ferrum_edge::tls::source::{CertSource, MaterialKind, SourceScheme};
use serial_test::serial;
use std::time::Duration;

const KEY: &str = "FERRUM_ADMIN_JWT_SECRET";

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_url_success() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let secret = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .expect("fetch should succeed against the fake");
    assert_eq!(secret.value, "azure-admin-jwt");
    assert_eq!(secret.version.as_deref(), Some("0123456789abcdef"));

    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        hits.iter().any(|req| {
            let path = req.url.path();
            path == "/secrets/admin-jwt" || path == "/secrets/admin-jwt/"
        }),
        "unversioned fetch must request latest (no version segment), got: {:?}",
        hits.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

/// Regression for the port-dropping bug: an explicit port in the secret URL
/// must be preserved when constructing the vault URL.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_port_is_preserved_regression() {
    // (a) Direct parser assertion — the explicit port survives.
    let (vault_url, name, version) =
        azure_parse_keyvault_reference("https://127.0.0.1:12345/secrets/admin-jwt", KEY)
            .expect("valid URL should parse");
    assert_eq!(vault_url, "https://127.0.0.1:12345");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version, None);

    // (b) End-to-end: a successful fetch via the fake (which listens on an
    // ephemeral non-standard port) can only happen if the port was preserved —
    // dropping it would target :443 and fail to connect.
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let secret = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .expect("fetch on an explicit ephemeral port should succeed");
    assert_eq!(secret.value, "azure-admin-jwt");

    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        !hits.is_empty(),
        "the fake on the explicit port must have received the request"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_invalid_url_errors() {
    let _guard = EnvGuard::new();
    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret("not-a-url", KEY)
        .await
        .err()
        .expect("a non-URL reference must fail");
    assert!(
        err.contains("Invalid Azure Key Vault URL"),
        "expected an invalid-URL error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_invalid_path_errors() {
    let _guard = EnvGuard::new();
    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    // `/keys/...` is the wrong resource path; only `/secrets/<name>` is valid.
    let err = creds
        .fetch_secret("https://127.0.0.1:12345/keys/admin-jwt", KEY)
        .await
        .err()
        .expect("a non-/secrets path must fail");
    assert!(
        err.contains("expected format"),
        "expected a path-format error, got: {err}"
    );
}

/// The production credential constructor must fail (before any network call)
/// when the Entra ID env vars are missing.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_missing_env_credentials_errors() {
    // EnvGuard clears all AZURE_* vars, so the constructor sees none.
    let _guard = EnvGuard::new();
    let err = AzureCredentials::new()
        .await
        .err()
        .expect("missing AZURE_* must fail");
    assert!(
        err.contains("AZURE_TENANT_ID")
            || err.contains("AZURE_CLIENT_ID")
            || err.contains("AZURE_CLIENT_SECRET"),
        "expected a missing-credential error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_not_found_errors() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret_status("admin-jwt", 404).await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("404 must fail");
    assert!(
        err.contains("Failed to get Azure secret"),
        "expected an Azure fetch failure, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_secret_has_no_value_errors() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret_no_value("admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("a secret with no value must fail");
    assert!(
        err.contains("has no value"),
        "expected a no-value error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_malformed_response_errors() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret_malformed("admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("a malformed body must fail");
    assert!(
        err.contains("Failed to get Azure secret") || err.contains("Failed to parse Azure secret"),
        "expected a fetch/parse error, got: {err}"
    );
}

/// Drives the registry timeout (`FERRUM_SECRET_FETCH_TIMEOUT_SECONDS`) through
/// the full resolver. The fake delays its first (unauthenticated) response, so
/// the resolver times out before any token is ever requested — no Entra ID call
/// occurs even though `AzureCredentials::new()` builds a real client-secret
/// credential from placeholder env values.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_timeout_errors() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret_delayed("slow", "value", Duration::from_secs(5))
        .await;

    // Placeholder credentials so `AzureCredentials::new()` succeeds; they are
    // never exchanged because the delayed first response times out first.
    guard.set("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    guard.set("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001");
    guard.set("AZURE_CLIENT_SECRET", "placeholder-not-used");
    guard.set("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS", "1");
    guard.set("FERRUM_ADMIN_JWT_SECRET_AZURE", fake.secret_url("slow"));

    let started = std::time::Instant::now();
    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("slow backend must time out");
    assert!(
        err.contains("Timeout"),
        "expected a timeout error, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "resolution should give up at ~1s, not hang"
    );
}

/// A `/secrets/<name>/<version>` URL must request exactly that version.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_versioned_url_fetches_exact_version() {
    let (vault_url, name, version) = azure_parse_keyvault_reference(
        "https://vault.example.net/secrets/admin-jwt/abc123version",
        KEY,
    )
    .expect("versioned URL should parse");
    assert_eq!(vault_url, "https://vault.example.net");
    assert_eq!(name, "admin-jwt");
    assert_eq!(version.as_deref(), Some("abc123version"));

    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    // Latest-only mock must not satisfy a versioned request.
    fake.mock_secret("admin-jwt", "latest-value").await;
    fake.mock_secret_version("admin-jwt", "abc123version", "pinned-value")
        .await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let secret = creds
        .fetch_secret(&fake.secret_version_url("admin-jwt", "abc123version"), KEY)
        .await
        .expect("versioned fetch should succeed");
    assert_eq!(secret.value, "pinned-value");
    assert_eq!(secret.version.as_deref(), Some("abc123version"));

    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        hits.iter().any(|req| {
            let path = req.url.path();
            path == "/secrets/admin-jwt/abc123version"
                || path == "/secrets/admin-jwt/abc123version/"
        }),
        "versioned fetch must include the version in the request path, got: {:?}",
        hits.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        !hits.iter().any(|req| {
            let path = req.url.path();
            path == "/secrets/admin-jwt" || path == "/secrets/admin-jwt/"
        }),
        "versioned fetch must not fall back to latest"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_versioned_url_does_not_use_latest_mock() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret("admin-jwt", "latest-only").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(
            &fake.secret_version_url("admin-jwt", "missing-version"),
            KEY,
        )
        .await
        .err()
        .expect("pinned version with only a latest mock must fail closed");
    assert!(
        err.contains("Failed to get Azure secret"),
        "expected fetch failure when the pinned version is absent, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_extra_path_segments_are_rejected() {
    let err =
        azure_parse_keyvault_reference("https://vault.example.net/secrets/admin-jwt/v1/extra", KEY)
            .expect_err("extra segments must fail");
    assert!(
        err.contains("unexpected path segments"),
        "expected extra-segment error, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_tls_version_option_conflict_is_rejected() {
    let err = azure_apply_tls_version_option(
        "https://vault.example.net/secrets/admin-jwt/v1",
        Some("v2"),
        "TLS cert material",
    )
    .expect_err("conflicting versions must fail");
    assert!(
        err.contains("Conflicting Azure Key Vault versions"),
        "expected conflict error, got: {err}"
    );
}

/// TLS inventory reports the version Key Vault actually returned, not a
/// configured label that was never fetched.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_tls_inventory_reports_fetched_version() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.mock_secret_version("edge-cert", "v1", "not-a-pem-body")
        .await;

    // The Key Vault client can be constructed from placeholders. The fake
    // returns the secret on the initial data-plane request, so these values are
    // never exchanged with Entra ID.
    guard.set("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    guard.set("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001");
    guard.set("AZURE_CLIENT_SECRET", "placeholder-not-used");

    let reference = fake.secret_version_url("edge-cert", "v1");
    let azure_uri = format!("azure://{reference}");

    // Direct provider fetch must surface the returned version.
    let resolved = resolve_external_reference("azure", &reference, "TLS certificate material")
        .await
        .expect("versioned azure:// fetch should succeed");
    assert_eq!(resolved.value, "not-a-pem-body");
    assert_eq!(resolved.version.as_deref(), Some("v1"));

    // Distinct source identities: path-pinned vs query-pinned must not collapse.
    let path_source = CertSource::parse(&azure_uri, MaterialKind::Cert);
    let query_source = CertSource::parse(
        format!("azure://{}?version=v1", fake.secret_url("edge-cert")),
        MaterialKind::Cert,
    );
    assert_ne!(
        path_source.source_id(),
        query_source.source_id(),
        "path-versioned and query-versioned azure:// sources must stay distinct identities"
    );
    assert_eq!(path_source.source_id(), format!("azure://{reference}"));
    match (&path_source, &query_source) {
        (CertSource::Uri(path_uri), CertSource::Uri(query_uri)) => {
            assert_eq!(path_uri.scheme, SourceScheme::Azure);
            assert_eq!(query_uri.scheme, SourceScheme::Azure);
            assert_eq!(
                query_uri.options.get("version").map(String::as_str),
                Some("v1")
            );
            assert!(!path_uri.options.contains_key("version"));
        }
        _ => panic!("expected azure:// URIs"),
    }

    let env = EnvConfig {
        frontend_tls_cert_path: Some(azure_uri),
        ..EnvConfig::default()
    };
    let inventory = TlsInventory::collect(Some(&env), None);
    assert_eq!(inventory.entries.len(), 1);
    let entry = &inventory.entries[0];
    assert_eq!(entry.source.kind, "azure");
    assert_eq!(entry.source.version.as_deref(), Some("v1"));
    assert_eq!(entry.source.identifier, format!("azure://{reference}"));
}

/// Plain-`http://` vault URLs are refused at parse time with an explicit
/// error, before any client or network call — the 1.x SDK would otherwise
/// fail obscurely inside its bearer-token policy.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_http_vault_url_is_refused() {
    let _guard = EnvGuard::new();
    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret("http://127.0.0.1:12345/secrets/admin-jwt", KEY)
        .await
        .err()
        .expect("an http:// vault URL must be refused");
    assert!(
        err.contains("must use https://"),
        "expected an https-required error, got: {err}"
    );
    assert!(
        !err.contains("127.0.0.1") && !err.contains("admin-jwt"),
        "the refusal must not echo the source reference: {err}"
    );

    let err = azure_parse_keyvault_reference("http://myvault.vault.azure.net/secrets/x", KEY)
        .expect_err("the parser itself must refuse http://");
    assert!(err.contains("must use https://"), "got: {err}");
}

/// The same refusal surfaces through the startup resolver (and therefore
/// `ferrum-edge validate`) as a config error, not an SDK transport failure.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_http_reference_fails_startup_resolution() {
    let guard = EnvGuard::new();
    guard.set("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    guard.set("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001");
    guard.set("AZURE_CLIENT_SECRET", "placeholder-not-used");
    guard.set(
        "FERRUM_ADMIN_JWT_SECRET_AZURE",
        "http://127.0.0.1:12345/secrets/admin-jwt",
    );

    let err = resolve_all_env_secrets()
        .await
        .err()
        .expect("an http:// _AZURE reference must fail startup resolution");
    assert!(
        err.contains("must use https://"),
        "expected an https-required error, got: {err}"
    );
    assert!(
        !err.contains("127.0.0.1:12345"),
        "the refusal must not echo the source reference: {err}"
    );
}

/// Without the fake's CA in `FERRUM_TLS_CA_BUNDLE_PATH`, the TLS handshake
/// fails: certificate verification stays on and the bundle is the only way to
/// add trust.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_untrusted_certificate_fails_closed() {
    let _guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("an untrusted certificate must fail the fetch");
    assert!(
        err.contains("Failed to get Azure secret"),
        "expected an Azure fetch failure, got: {err}"
    );
    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        hits.is_empty(),
        "no HTTP request may reach the vault over an unverified TLS session"
    );
}

/// An unusable `FERRUM_TLS_CA_BUNDLE_PATH` is an explicit error at credential
/// construction, never a silent fallback to platform roots only, and the error
/// names the variable but not the path.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_invalid_ca_bundle_is_refused() {
    let guard = EnvGuard::new();

    let dir = tempfile::tempdir().expect("temp dir");
    let missing = dir.path().join("missing-ca-sentinel.pem");
    guard.set("FERRUM_TLS_CA_BUNDLE_PATH", missing.to_string_lossy());
    let err = AzureCredentials::from_static_token("dummy-token")
        .await
        .err()
        .expect("a missing CA bundle must fail");
    assert!(
        err.contains("FERRUM_TLS_CA_BUNDLE_PATH") && !err.contains("missing-ca-sentinel"),
        "expected a variable-level read error, got: {err}"
    );

    let not_pem = dir.path().join("not-pem-sentinel.pem");
    std::fs::write(&not_pem, "this is not a certificate").expect("write bundle");
    guard.set("FERRUM_TLS_CA_BUNDLE_PATH", not_pem.to_string_lossy());
    let err = AzureCredentials::from_static_token("dummy-token")
        .await
        .err()
        .expect("a bundle with no certificates must fail");
    assert!(
        err.contains("FERRUM_TLS_CA_BUNDLE_PATH") && !err.contains("not-pem-sentinel"),
        "expected a variable-level bundle error, got: {err}"
    );

    // Oversized (sparse) bundle: refused from metadata, without reading it.
    let oversized = dir.path().join("oversized-ca-sentinel.pem");
    std::fs::File::create(&oversized)
        .expect("create oversized bundle")
        .set_len(5 * 1024 * 1024)
        .expect("size oversized bundle");
    guard.set("FERRUM_TLS_CA_BUNDLE_PATH", oversized.to_string_lossy());
    let err = AzureCredentials::from_static_token("dummy-token")
        .await
        .err()
        .expect("an oversized CA bundle must fail");
    assert!(
        err.contains("FERRUM_TLS_CA_BUNDLE_PATH")
            && err.contains("limit")
            && !err.contains("oversized-ca-sentinel"),
        "expected a size-limit error, got: {err}"
    );

    // A directory is not a regular file.
    guard.set("FERRUM_TLS_CA_BUNDLE_PATH", dir.path().to_string_lossy());
    let err = AzureCredentials::from_static_token("dummy-token")
        .await
        .err()
        .expect("a directory CA bundle must fail");
    assert!(err.contains("regular file"), "got: {err}");
}

/// A FIFO without a writer must be refused at once, not block credential
/// construction (and with it startup) on `open(2)`/`read(2)`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_fifo_ca_bundle_is_refused_without_blocking() {
    let guard = EnvGuard::new();
    let dir = tempfile::tempdir().expect("temp dir");
    let fifo = dir.path().join("ca-fifo-sentinel");
    let c_path = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).expect("fifo path");
    // SAFETY: `c_path` is a valid NUL-terminated path for the call's duration.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
    guard.set("FERRUM_TLS_CA_BUNDLE_PATH", fifo.to_string_lossy());

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        AzureCredentials::from_static_token("dummy-token"),
    )
    .await
    .expect("a FIFO CA bundle must not block credential construction")
    .err()
    .expect("a FIFO CA bundle must fail");
    assert!(
        err.contains("regular file") && !err.contains("ca-fifo-sentinel"),
        "expected a regular-file error, got: {err}"
    );
}

/// Full Key Vault challenge flow over TLS: the first request goes out without
/// a token, the fake answers `401` with a `resource="https://vault.azure.net"`
/// challenge, the SDK verifies that resource against the `*.vault.azure.net`
/// request host, and retries with the bearer token. The request host is a real
/// Key Vault-shaped name routed to the fake through a `CONNECT` proxy.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_challenge_auth_sends_bearer_token_after_verified_challenge() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.route_through_proxy(&guard);
    fake.mock_secret_challenge(
        "admin-jwt",
        "challenge-value",
        "https://vault.azure.net",
        "dummy-token",
    )
    .await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let secret = creds
        .fetch_secret(&fake.vault_host_secret_url("admin-jwt"), KEY)
        .await
        .expect("challenge flow should succeed");
    assert_eq!(secret.value, "challenge-value");

    let hits = fake.server.received_requests().await.unwrap_or_default();
    let auth: Vec<Option<String>> = hits
        .iter()
        .map(|req| {
            req.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .collect();
    assert_eq!(
        auth,
        vec![None, Some("Bearer dummy-token".to_string())],
        "expected an unauthenticated probe, then one bearer-authenticated retry"
    );
}

/// A challenge naming a resource outside the request host's domain is
/// rejected by the SDK's challenge-resource verification, which Ferrum keeps
/// on: the token is never sent.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_mismatched_challenge_resource_is_rejected() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);
    fake.route_through_proxy(&guard);
    fake.mock_secret_challenge(
        "admin-jwt",
        "must-not-be-returned",
        "https://attacker.example",
        "dummy-token",
    )
    .await;

    let creds = AzureCredentials::from_static_token("dummy-token")
        .await
        .expect("static-token credentials");
    let err = creds
        .fetch_secret(&fake.vault_host_secret_url("admin-jwt"), KEY)
        .await
        .err()
        .expect("a mismatched challenge resource must fail");
    assert!(
        err.contains("Failed to get Azure secret"),
        "expected an Azure fetch failure, got: {err}"
    );

    let hits = fake.server.received_requests().await.unwrap_or_default();
    assert!(
        !hits.is_empty(),
        "the unauthenticated probe must reach the fake"
    );
    assert!(
        hits.iter()
            .all(|req| req.headers.get("authorization").is_none()),
        "no request may carry the bearer token after a mismatched challenge"
    );
}

/// CA bundle reads are admission-gated: while a reader holds the permit (as a
/// reader stalled on a hung filesystem would, even after its caller timed
/// out), further credential construction waits for admission instead of
/// spawning another native reader, and proceeds once the permit is released.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn azure_ca_bundle_reads_are_admission_gated() {
    let guard = EnvGuard::new();
    let fake = AzureKeyVaultFake::start().await;
    fake.trust_ca(&guard);

    let held = azure_hold_ca_bundle_reader_permit_for_test().await;
    // With a readable bundle, an ungated reader would finish in milliseconds;
    // timing out proves construction is parked on admission.
    for _ in 0..3 {
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                AzureCredentials::from_static_token("dummy-token"),
            )
            .await
            .is_err(),
            "construction must wait for the held reader permit"
        );
    }
    drop(held);

    let creds = tokio::time::timeout(
        Duration::from_secs(10),
        AzureCredentials::from_static_token("dummy-token"),
    )
    .await
    .expect("construction proceeds once the permit is released")
    .expect("static-token credentials");
    fake.mock_secret("admin-jwt", "azure-admin-jwt").await;
    let secret = creds
        .fetch_secret(&fake.secret_url("admin-jwt"), KEY)
        .await
        .expect("fetch should succeed after admission");
    assert_eq!(secret.value, "azure-admin-jwt");
}
