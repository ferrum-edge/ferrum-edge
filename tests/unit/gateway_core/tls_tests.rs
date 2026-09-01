//! Unit tests for src/tls/mod.rs
//!
//! Tests: check_cert_expiry, load_crls, TlsPolicy, build_server_verifier_with_crls,
//! backend_client_config_builder, load_tls_config_with_client_auth

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::{
    self, TlsPolicy, backend_client_config_builder, build_server_verifier_with_crls,
    check_cert_expiry, check_cert_expiry_for_validation, load_crls,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::Once;
use std::time::Duration;
use tempfile::TempDir;

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn generate_self_signed_cert(sans: &[&str]) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let params = CertificateParams::new(san_strings).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn generate_ca() -> (Issuer<'static, KeyPair>, String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (Issuer::new(params, key_pair), cert_pem, key_pem)
}

fn generate_signed_cert(ca_issuer: &Issuer<'static, KeyPair>, sans: &[&str]) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Leaf");
    let cert = params.signed_by(&key_pair, ca_issuer).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn generate_expired_cert() -> (String, String) {
    use rcgen::KeyPair;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    // Set validity to a window in the past
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(30);
    params.not_after = now - time::Duration::days(1);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn generate_not_yet_valid_cert() -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::days(10);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn generate_near_expiry_cert(days_remaining: i64) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(30);
    params.not_after = now + time::Duration::days(days_remaining);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

fn malformed_certificate_record() -> &'static str {
    "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
}

fn default_env_config() -> EnvConfig {
    EnvConfig::default()
}

#[test]
fn tls_source_execution_policy_defaults_and_bounds_are_fail_closed() {
    use ferrum_edge::config::env_config::{
        DEFAULT_TLS_SOURCE_LOAD_TIMEOUT_SECONDS, DEFAULT_TLS_SOURCE_MAX_BLOCKING_CONCURRENCY,
        HARD_MAX_TLS_SOURCE_LOAD_TIMEOUT_SECONDS, HARD_MAX_TLS_SOURCE_MAX_BLOCKING_CONCURRENCY,
        parse_tls_source_execution_policy,
    };

    assert_eq!(
        parse_tls_source_execution_policy(None, None).expect("default policy"),
        (
            DEFAULT_TLS_SOURCE_MAX_BLOCKING_CONCURRENCY,
            DEFAULT_TLS_SOURCE_LOAD_TIMEOUT_SECONDS,
        )
    );
    let hard_max = parse_tls_source_execution_policy(Some("256"), Some("5")).expect("hard maxima");
    assert_eq!(
        hard_max,
        (
            HARD_MAX_TLS_SOURCE_MAX_BLOCKING_CONCURRENCY,
            HARD_MAX_TLS_SOURCE_LOAD_TIMEOUT_SECONDS,
        )
    );
    assert!(parse_tls_source_execution_policy(Some("0"), Some("1")).is_err());
    assert!(parse_tls_source_execution_policy(Some("1"), Some("0")).is_err());
    assert!(parse_tls_source_execution_policy(Some("not-a-number"), Some("1")).is_err());
    assert!(parse_tls_source_execution_policy(Some("1"), Some("6")).is_err());
}

// ── check_cert_expiry tests ────────────────────────────────────────────────

#[test]
fn test_check_cert_expiry_valid_cert_succeeds() {
    let dir = TempDir::new().unwrap();
    let (cert_pem, _key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);

    let result = check_cert_expiry(&cert_path, "test cert", 30);
    assert!(result.is_ok());
}

#[test]
fn test_check_cert_expiry_expired_cert_fails() {
    let dir = TempDir::new().unwrap();
    let (cert_pem, _key_pem) = generate_expired_cert();
    let cert_path = write_pem(&dir, "expired.pem", &cert_pem);

    let result = check_cert_expiry(&cert_path, "expired cert", 30);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("has expired"),
        "expected 'has expired' in: {}",
        err
    );
}

#[test]
fn test_check_cert_expiry_not_yet_valid_cert_fails() {
    let dir = TempDir::new().unwrap();
    let (cert_pem, _key_pem) = generate_not_yet_valid_cert();
    let cert_path = write_pem(&dir, "future.pem", &cert_pem);

    let result = check_cert_expiry(&cert_path, "future cert", 30);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not yet valid"),
        "expected 'not yet valid' in: {}",
        err
    );
}

#[test]
fn test_check_cert_expiry_near_expiry_warns_but_succeeds() {
    let dir = TempDir::new().unwrap();
    // Certificate expires in 5 days, warning threshold is 30 days
    let (cert_pem, _key_pem) = generate_near_expiry_cert(5);
    let cert_path = write_pem(&dir, "nearexpiry.pem", &cert_pem);

    // Should succeed (warning is just a log, not an error)
    let result = check_cert_expiry(&cert_path, "near-expiry cert", 30);
    assert!(result.is_ok());
}

#[test]
fn test_check_cert_expiry_warning_disabled_with_zero() {
    let dir = TempDir::new().unwrap();
    let (cert_pem, _key_pem) = generate_near_expiry_cert(5);
    let cert_path = write_pem(&dir, "nearexpiry2.pem", &cert_pem);

    // warning_days=0 disables warnings entirely
    let result = check_cert_expiry(&cert_path, "near-expiry cert", 0);
    assert!(result.is_ok());
}

#[test]
fn test_check_cert_expiry_nonexistent_file_fails() {
    let result = check_cert_expiry("/nonexistent/cert.pem", "missing cert", 30);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("failed to read"));
}

#[test]
fn test_check_cert_expiry_empty_file_fails() {
    let dir = TempDir::new().unwrap();
    let path = write_pem(&dir, "empty.pem", "");

    let result = check_cert_expiry(&path, "empty cert", 30);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("no valid PEM certificates")
    );
}

#[test]
fn test_check_cert_expiry_invalid_pem_fails() {
    let dir = TempDir::new().unwrap();
    let path = write_pem(&dir, "bad.pem", "not a certificate");

    let result = check_cert_expiry(&path, "bad cert", 30);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("no valid PEM certificates")
    );
}

#[test]
fn test_check_cert_expiry_rejects_malformed_later_record_with_original_index() {
    let dir = TempDir::new().unwrap();
    let (valid_pem, _key_pem) = generate_self_signed_cert(&["localhost"]);
    let bundle = format!("{valid_pem}{}", malformed_certificate_record());
    let path = write_pem(&dir, "mixed-later.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("a malformed later certificate record must reject the complete bundle")
        .to_string();
    assert!(error.contains("expiry bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
    assert!(error.contains("mixed-later.pem"), "got: {error}");
}

#[test]
fn test_check_cert_expiry_rejects_malformed_first_record_without_compressing_index() {
    let dir = TempDir::new().unwrap();
    let (valid_pem, _key_pem) = generate_self_signed_cert(&["localhost"]);
    let bundle = format!("{}{valid_pem}", malformed_certificate_record());
    let path = write_pem(&dir, "mixed-first.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("a malformed first certificate record must reject the complete bundle")
        .to_string();
    assert!(error.contains("record #1"), "got: {error}");
}

#[test]
fn test_check_cert_expiry_rejects_all_malformed_certificate_records() {
    let dir = TempDir::new().unwrap();
    let bundle = format!(
        "{}{}",
        malformed_certificate_record(),
        malformed_certificate_record()
    );
    let path = write_pem(&dir, "all-malformed.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("an all-malformed bundle must fail")
        .to_string();
    assert!(error.contains("record #1"), "got: {error}");
}

#[test]
fn test_check_cert_expiry_for_validation_returns_string_error() {
    let result = check_cert_expiry_for_validation("/nonexistent/cert.pem", "test_field", 30);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("failed to read"));
}

#[test]
fn test_check_cert_expiry_for_validation_valid_cert_succeeds() {
    let dir = TempDir::new().unwrap();
    let (cert_pem, _key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);

    let result = check_cert_expiry_for_validation(&cert_path, "test_field", 30);
    assert!(result.is_ok());
}

// ── load_crls tests ────────────────────────────────────────────────────────

#[test]
fn test_load_crls_none_returns_empty() {
    let result = load_crls(None).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_load_crls_nonexistent_file_fails() {
    let result = load_crls(Some("/nonexistent/crl.pem"));
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Failed to load CRL source")
            && message.contains("failed to read TLS material"),
        "unexpected CRL load error: {message}"
    );
}

#[test]
fn test_load_crls_empty_file_fails() {
    let dir = TempDir::new().unwrap();
    let path = write_pem(&dir, "empty.pem", "");

    let result = load_crls(Some(&path));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No valid CRL entries")
    );
}

#[test]
fn test_load_crls_invalid_content_fails() {
    let dir = TempDir::new().unwrap();
    let path = write_pem(&dir, "bad_crl.pem", "not a CRL");

    let result = load_crls(Some(&path));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No valid CRL entries")
    );
}

// ── TlsPolicy tests ──────────────────────────────────────────────────────

#[test]
fn test_tls_policy_default_env_config() {
    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    // Should have both TLS 1.2 and 1.3 by default
    assert_eq!(policy.protocol_versions.len(), 2);
    assert!(policy.prefer_server_cipher_order);
}

#[test]
fn test_tls_policy_tls13_only() {
    let mut env = default_env_config();
    env.tls_min_version = "1.3".to_string();
    env.tls_max_version = "1.3".to_string();

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.protocol_versions.len(), 1);
}

#[test]
fn test_tls_policy_tls12_only() {
    let mut env = default_env_config();
    env.tls_min_version = "1.2".to_string();
    env.tls_max_version = "1.2".to_string();

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.protocol_versions.len(), 1);
}

#[test]
fn test_tls_policy_invalid_version_range_fails() {
    let mut env = default_env_config();
    env.tls_min_version = "1.4".to_string();
    env.tls_max_version = "1.4".to_string();

    let result = TlsPolicy::from_env_config(&env);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No valid TLS versions")
    );
}

#[test]
fn test_tls_policy_custom_cipher_suites() {
    let mut env = default_env_config();
    env.tls_cipher_suites = Some("TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256".to_string());

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    // Should succeed with 2 TLS 1.3 cipher suites
    assert_eq!(policy.crypto_provider.cipher_suites.len(), 2);
}

#[test]
fn test_tls_policy_defaults_prefer_aes128_gcm() {
    let env = default_env_config();

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    let suites: Vec<_> = policy
        .crypto_provider
        .cipher_suites
        .iter()
        .map(|suite| suite.suite())
        .collect();

    assert_eq!(
        suites,
        vec![
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]
    );
}

#[test]
fn test_tls_policy_unknown_cipher_suite_fails() {
    let mut env = default_env_config();
    env.tls_cipher_suites = Some("INVALID_SUITE".to_string());

    let result = TlsPolicy::from_env_config(&env);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unknown cipher suite")
    );
}

#[test]
fn test_tls_policy_empty_cipher_suites_fails() {
    let mut env = default_env_config();
    env.tls_cipher_suites = Some("".to_string());

    let result = TlsPolicy::from_env_config(&env);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No cipher suites"));
}

#[test]
fn test_tls_policy_custom_curves() {
    let mut env = default_env_config();
    env.tls_curves = Some("X25519,P-256".to_string());

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.crypto_provider.kx_groups.len(), 2);
}

#[test]
fn test_tls_policy_unknown_curve_fails() {
    let mut env = default_env_config();
    env.tls_curves = Some("invalid_curve".to_string());

    let result = TlsPolicy::from_env_config(&env);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unknown curve/group")
    );
}

#[test]
fn test_tls_policy_curve_aliases() {
    // Test that aliases for the same curve work
    let mut env = default_env_config();
    env.tls_curves = Some("secp256r1".to_string());
    assert!(TlsPolicy::from_env_config(&env).is_ok());

    env.tls_curves = Some("P-256".to_string());
    assert!(TlsPolicy::from_env_config(&env).is_ok());

    env.tls_curves = Some("P256".to_string());
    assert!(TlsPolicy::from_env_config(&env).is_ok());

    env.tls_curves = Some("secp384r1".to_string());
    assert!(TlsPolicy::from_env_config(&env).is_ok());

    env.tls_curves = Some("P-384".to_string());
    assert!(TlsPolicy::from_env_config(&env).is_ok());
}

#[test]
fn test_tls_policy_tls12_cipher_suites() {
    let mut env = default_env_config();
    env.tls_cipher_suites = Some(
        "ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,\
         ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,\
         ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305"
            .to_string(),
    );

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.crypto_provider.cipher_suites.len(), 6);
}

#[test]
fn test_tls_policy_session_cache_size() {
    let mut env = default_env_config();
    env.tls_session_cache_size = 512;

    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.session_cache_size, 512);
}

// ── build_server_verifier_with_crls tests ─────────────────────────────────

#[test]
fn test_build_server_verifier_empty_crls_with_roots() {
    ensure_crypto_provider();
    // Need at least one root cert for WebPki verifier to succeed
    let (cert_pem, _) = generate_self_signed_cert(&["localhost"]);
    let der_certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(der_certs);
    let result = build_server_verifier_with_crls(root_store, &[]);
    assert!(result.is_ok());
}

#[test]
fn test_build_server_verifier_empty_root_store_fails() {
    ensure_crypto_provider();
    let root_store = rustls::RootCertStore::empty();
    let result = build_server_verifier_with_crls(root_store, &[]);
    // Empty root store should fail - WebPki requires at least one trust anchor
    assert!(result.is_err());
}

// ── backend_client_config_builder tests ───────────────────────────────────

#[test]
fn test_backend_client_config_builder_with_policy() {
    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = backend_client_config_builder(Some(&policy));
    assert!(result.is_ok());
}

#[test]
fn test_backend_client_config_builder_without_policy() {
    let result = backend_client_config_builder(None);
    assert!(result.is_ok());
}

// ── load_tls_config_with_client_auth tests ────────────────────────────────

#[test]
fn test_load_tls_config_basic_no_client_auth() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result =
        tls::load_tls_config_with_client_auth(&cert_path, &key_path, None, false, &policy, 30, &[]);
    assert!(result.is_ok());
}

#[test]
fn test_load_tls_config_accepts_inline_cert_source() {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result =
        tls::load_tls_config_with_client_auth(&cert_pem, &key_pem, None, false, &policy, 30, &[]);
    assert!(result.is_ok());
}

/// Issue #4300: this used to assert that four arbitrary bytes loaded
/// successfully. A stapled response is now bound to the certificate it will be
/// served with, so unparseable bytes fail the whole TLS load. Acceptance of a
/// genuine signed response is covered in
/// `tests/unit/tls/ocsp_validation_tests.rs`, which owns the fixture builder.
#[test]
fn test_load_tls_config_rejects_unparseable_ocsp_response_source() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);
    let ocsp_path = dir.path().join("ocsp.der");
    std::fs::write(&ocsp_path, [1_u8, 2, 3, 4]).unwrap();

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = tls::load_tls_config_with_client_auth_and_ocsp(
        &cert_path,
        &key_path,
        None,
        Some(ocsp_path.to_string_lossy().as_ref()),
        false,
        &policy,
        30,
        &[],
    );
    let error = result.expect_err("arbitrary bytes are not a stapled OCSP response");
    assert!(format!("{error:#}").contains("was rejected"));
}

#[test]
fn test_load_tls_config_rejects_empty_ocsp_response_source() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);
    let ocsp_path = dir.path().join("ocsp.der");
    std::fs::write(&ocsp_path, []).unwrap();

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = tls::load_tls_config_with_client_auth_and_ocsp(
        &cert_path,
        &key_path,
        None,
        Some(ocsp_path.to_string_lossy().as_ref()),
        false,
        &policy,
        30,
        &[],
    );
    assert!(result.is_err());
}

#[test]
fn test_load_tls_config_with_client_auth_ca() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (ca_issuer, ca_pem, _) = generate_ca();
    let (cert_pem, key_pem) = generate_signed_cert(&ca_issuer, &["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);
    let ca_path = write_pem(&dir, "ca.pem", &ca_pem);

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = tls::load_tls_config_with_client_auth(
        &cert_path,
        &key_path,
        Some(&ca_path),
        false,
        &policy,
        30,
        &[],
    );
    assert!(result.is_ok());
}

#[test]
fn test_load_tls_config_no_verify_mode() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result =
        tls::load_tls_config_with_client_auth(&cert_path, &key_path, None, true, &policy, 30, &[]);
    assert!(result.is_ok());
}

#[test]
fn test_load_tls_config_missing_cert_fails() {
    ensure_crypto_provider();
    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = tls::load_tls_config_with_client_auth(
        "/nonexistent/cert.pem",
        "/nonexistent/key.pem",
        None,
        false,
        &policy,
        30,
        &[],
    );
    assert!(result.is_err());
}

#[test]
fn test_load_tls_config_expired_cert_fails() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_expired_cert();
    let cert_path = write_pem(&dir, "expired.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result =
        tls::load_tls_config_with_client_auth(&cert_path, &key_path, None, false, &policy, 30, &[]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}

#[test]
fn test_load_tls_config_empty_ca_bundle_fails() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);
    let ca_path = write_pem(&dir, "empty_ca.pem", "not a cert");

    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();

    let result = tls::load_tls_config_with_client_auth(
        &cert_path,
        &key_path,
        Some(&ca_path),
        false,
        &policy,
        30,
        &[],
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    // The cert path check runs first (check_cert_expiry on the CA bundle),
    // so we may get a "no valid PEM certificates" error from that check
    assert!(
        err.contains("No valid client CA certificates")
            || err.contains("no valid PEM certificates"),
        "expected cert validation error, got: {err}"
    );
}

// ── 0-RTT early data TLS policy tests ─────────────────────────────────────

#[test]
fn test_tls_policy_early_data_disabled_by_default() {
    let env = default_env_config();
    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.early_data_max_size, 0);
}

#[test]
fn test_tls_policy_early_data_enabled_when_methods_set() {
    let mut env = default_env_config();
    env.tls_early_data_methods = ["GET".to_string()].into_iter().collect();
    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert!(
        policy.early_data_max_size > 0,
        "expected non-zero early_data_max_size"
    );
    assert_eq!(policy.early_data_max_size, 16_384);
}

#[test]
fn test_tls_policy_early_data_enabled_multiple_methods() {
    let mut env = default_env_config();
    env.tls_early_data_methods = ["GET", "HEAD", "OPTIONS"]
        .into_iter()
        .map(String::from)
        .collect();
    let policy = TlsPolicy::from_env_config(&env).unwrap();
    assert_eq!(policy.early_data_max_size, 16_384);
}

// ── enable_early_data tests ──────────────────────────────────────────

#[test]
fn test_enable_early_data_keeps_https_frontend_disabled() {
    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();

    let base_policy = TlsPolicy::from_env_config(&default_env_config()).unwrap();

    let mut config = tls::load_tls_config_with_client_auth(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None,
        false,
        &base_policy,
        30,
        &[],
    )
    .unwrap();

    let policy = TlsPolicy {
        early_data_max_size: 16_384,
        ..base_policy
    };

    tls::enable_early_data(&mut config, &policy);
    assert_eq!(
        config.max_early_data_size, 0,
        "HTTPS frontend should keep TLS 0-RTT disabled until per-request early-data state is available"
    );
}

#[test]
fn test_enable_early_data_zero_is_noop() {
    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]);
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();

    let base_policy = TlsPolicy::from_env_config(&default_env_config()).unwrap();

    let mut config = tls::load_tls_config_with_client_auth(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None,
        false,
        &base_policy,
        30,
        &[],
    )
    .unwrap();

    let policy = TlsPolicy {
        early_data_max_size: 0,
        ..base_policy
    };

    tls::enable_early_data(&mut config, &policy);
    assert_eq!(
        config.max_early_data_size, 0,
        "early_data_max_size=0 should leave config unchanged"
    );
}

// ── NoVerifier tests ─────────────────────────────────────────────────

#[test]
fn test_no_verifier_accepts_any_cert() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls_pemfile::certs;
    use std::io::BufReader;

    ensure_crypto_provider();

    let verifier = tls::NoVerifier;

    // Create a dummy certificate (self-signed, doesn't matter — verifier should accept anything)
    let (cert_pem, _) = generate_self_signed_cert(&["example.com"]);
    let mut reader = BufReader::new(cert_pem.as_bytes());
    let cert_der: Vec<CertificateDer<'static>> =
        certs(&mut reader).filter_map(|r| r.ok()).collect();
    assert!(!cert_der.is_empty(), "Should parse at least one cert");

    let server_name = ServerName::try_from("example.com").unwrap();
    let now = UnixTime::now();

    let result = verifier.verify_server_cert(&cert_der[0], &[], &server_name, &[], now);
    assert!(
        result.is_ok(),
        "NoVerifier should accept any certificate: {:?}",
        result.err()
    );
}

#[test]
fn test_no_verifier_supported_schemes_not_empty() {
    use rustls::client::danger::ServerCertVerifier;

    ensure_crypto_provider();

    let verifier = tls::NoVerifier;
    let schemes = verifier.supported_verify_schemes();
    assert!(
        !schemes.is_empty(),
        "NoVerifier should support at least one verify scheme"
    );
}

// ── build_client_cert_verifier tests ──────────────────────────────────

#[test]
fn test_build_client_cert_verifier_with_valid_ca() {
    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (_ca_issuer, ca_pem, _) = generate_ca();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();

    let result = tls::build_client_cert_verifier(ca_path.to_str().unwrap(), &[]);
    assert!(
        result.is_ok(),
        "Should build verifier with valid CA: {:?}",
        result.err()
    );
}

#[test]
fn test_build_client_cert_verifier_missing_file() {
    ensure_crypto_provider();

    let result = tls::build_client_cert_verifier("/nonexistent/path/ca.pem", &[]);
    assert!(result.is_err(), "Missing CA file should fail");
}

#[test]
fn test_build_client_cert_verifier_empty_file() {
    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let ca_path = dir.path().join("empty_ca.pem");
    std::fs::write(&ca_path, "").unwrap();

    let result = tls::build_client_cert_verifier(ca_path.to_str().unwrap(), &[]);
    assert!(result.is_err(), "Empty CA file should fail");
}

#[test]
fn test_build_client_cert_verifier_with_crls_succeeds() {
    use rcgen::{
        CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
    };

    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (ca_issuer, ca_pem, _) = generate_ca();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();

    // Build a valid CRL signed by the CA. The CRL revokes a placeholder serial;
    // the verifier construction itself only requires the CRL to be parseable
    // and validly signed by a CA in the trust store.
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs = vec![RevokedCertParams {
        serial_number: SerialNumber::from(99u64),
        revocation_time: now,
        reason_code: Some(RevocationReason::KeyCompromise),
        invalidity_date: None,
    }];
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl_pem = params.signed_by(&ca_issuer).unwrap().pem().unwrap();
    let crl_der: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
        rustls_pemfile::crls(&mut crl_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    assert!(
        !crl_der.is_empty(),
        "should parse at least one CRL from PEM"
    );

    // Verifier construction must succeed and (implicitly) honour CRL config.
    // The `with_crls` call path is gated on `!crls.is_empty()`, so this
    // exercises that branch — earlier the H3 verifier silently skipped CRLs.
    let result = tls::build_client_cert_verifier(ca_path.to_str().unwrap(), &crl_der);
    assert!(
        result.is_ok(),
        "Should build verifier with CRLs: {:?}",
        result.err()
    );
}

/// End-to-end CRL enforcement on the H3 client-cert verifier.
///
/// Issue a CA-signed leaf with an explicit serial, build a CRL revoking that
/// exact serial, then verify the leaf via the verifier returned by
/// `build_client_cert_verifier`. Before the H3 CRL fix, the verifier silently
/// dropped the CRL list and accepted the revoked cert. After the fix, with
/// `allow_unknown_revocation_status` + `only_check_end_entity_revocation`, a
/// matching revocation entry must produce a verification failure surfacing the
/// `Revoked` rustls error.
#[test]
fn test_h3_client_verifier_rejects_revoked_cert() {
    use rcgen::{
        CertificateParams, CertificateRevocationListParams, KeyPair, RevocationReason,
        RevokedCertParams, SerialNumber,
    };
    use rustls::pki_types::{CertificateDer, UnixTime};

    ensure_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (ca_issuer, ca_pem, _) = generate_ca();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();

    // Issue a leaf cert with a known serial so the CRL can revoke it by serial.
    let leaf_serial = SerialNumber::from_slice(&(1u8..=20).collect::<Vec<u8>>());
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["client.example".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Client");
    leaf_params.serial_number = Some(leaf_serial.clone());
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer).unwrap();
    let leaf_der: CertificateDer<'static> = {
        let pem = leaf_cert.pem();
        let parsed: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        parsed.into_iter().next().expect("leaf DER")
    };

    // Build a CRL that revokes the leaf's serial.
    let now = time::OffsetDateTime::now_utc();
    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: leaf_serial.clone(),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl_pem = crl_params.signed_by(&ca_issuer).unwrap().pem().unwrap();
    let crl_der: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
        rustls_pemfile::crls(&mut crl_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    assert!(!crl_der.is_empty(), "should parse CRL from PEM");

    // Sanity: without CRLs, the verifier accepts the leaf.
    let no_crl_verifier = tls::build_client_cert_verifier(ca_path.to_str().unwrap(), &[]).unwrap();
    let no_crl_result = no_crl_verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());
    assert!(
        no_crl_result.is_ok(),
        "Without CRLs, the leaf must verify: {:?}",
        no_crl_result.err()
    );

    // With CRLs, the same leaf must be rejected as revoked.
    let crl_verifier =
        tls::build_client_cert_verifier(ca_path.to_str().unwrap(), &crl_der).unwrap();
    let result = crl_verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());
    assert!(
        result.is_err(),
        "Revoked client cert must be rejected when CRL is configured"
    );
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.to_ascii_lowercase().contains("revoked"),
        "expected a revocation error, got: {}",
        err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_tls_source_work_does_not_stall_tokio_heartbeat() {
    use ferrum_edge::tls::source::TlsSourceExecutor;
    use std::sync::{Arc, Condvar, Mutex};

    let executor = TlsSourceExecutor::new(1, Duration::from_secs(1)).expect("executor");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let operation_release = Arc::clone(&release);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let operation = tokio::spawn(async move {
        executor
            .run_blocking(move || {
                started_tx
                    .send(())
                    .map_err(|_| ferrum_edge::tls::source::MaterialError::ExecutorUnavailable)?;
                let (lock, condition) = &*operation_release;
                let ready = lock
                    .lock()
                    .map_err(|_| ferrum_edge::tls::source::MaterialError::ExecutorUnavailable)?;
                let _ready = condition
                    .wait_while(ready, |ready| !*ready)
                    .map_err(|_| ferrum_edge::tls::source::MaterialError::ExecutorUnavailable)?;
                Ok(())
            })
            .await
    });

    started_rx.await.expect("blocking operation started");
    tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
        .await
        .expect("the single Tokio worker must remain responsive");

    let (lock, condition) = &*release;
    *lock.lock().expect("release lock") = true;
    condition.notify_one();
    operation
        .await
        .expect("operation task")
        .expect("operation result");
}

#[tokio::test(flavor = "current_thread")]
async fn tls_source_executor_bounds_admission_and_deadline() {
    use ferrum_edge::tls::source::{MaterialError, TlsSourceExecutor};
    use std::sync::{Arc, Condvar, Mutex};

    let executor = TlsSourceExecutor::new(1, Duration::from_millis(50)).expect("executor");
    assert_eq!(executor.max_blocking_concurrency(), 1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let operation_release = Arc::clone(&release);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let first_executor = executor.clone();
    let first = tokio::spawn(async move {
        first_executor
            .run_blocking(move || {
                let _ = started_tx.send(());
                let (lock, condition) = &*operation_release;
                let ready = lock
                    .lock()
                    .map_err(|_| MaterialError::ExecutorUnavailable)?;
                let _ready = condition
                    .wait_while(ready, |ready| !*ready)
                    .map_err(|_| MaterialError::ExecutorUnavailable)?;
                Ok(())
            })
            .await
    });

    started_rx.await.expect("first operation started");
    let second = executor.run_blocking(|| Ok(())).await;
    assert!(matches!(second, Err(MaterialError::DeadlineExceeded)));

    let (lock, condition) = &*release;
    *lock.lock().expect("release lock") = true;
    condition.notify_one();
    let first_result = first.await.expect("first task");
    assert!(matches!(
        first_result,
        Ok(()) | Err(MaterialError::DeadlineExceeded)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn tls_source_deadline_keeps_last_known_good_generation() {
    use ferrum_edge::tls::source::{MaterialError, TlsSourceExecutor};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let accepted_generation = Arc::new(AtomicU64::new(7));
    let executor = TlsSourceExecutor::new(1, Duration::from_millis(25)).expect("executor");
    let candidate = executor
        .run_blocking(|| {
            std::thread::sleep(Duration::from_millis(75));
            Ok(8_u64)
        })
        .await;

    if let Ok(generation) = &candidate {
        accepted_generation.store(*generation, Ordering::Release);
    }
    assert!(matches!(candidate, Err(MaterialError::DeadlineExceeded)));
    assert_eq!(accepted_generation.load(Ordering::Acquire), 7);
}
