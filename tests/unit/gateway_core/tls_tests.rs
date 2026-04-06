//! Unit tests for src/tls/mod.rs
//!
//! Tests: check_cert_expiry, load_crls, TlsPolicy, build_server_verifier_with_crls,
//! backend_client_config_builder, load_tls_config_with_client_auth

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::{
    self, TlsPolicy, backend_client_config_builder, build_server_verifier_with_crls,
    check_cert_expiry, check_cert_expiry_for_validation, load_crls,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::sync::Once;
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

fn generate_ca() -> (rcgen::Certificate, KeyPair, String, String) {
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
    (cert, key_pair, cert_pem, key_pem)
}

fn generate_signed_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    sans: &[&str],
) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Leaf");
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
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

fn default_env_config() -> EnvConfig {
    EnvConfig::default()
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
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to open CRL file")
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
fn test_load_tls_config_with_client_auth_ca() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (ca_cert, ca_key, ca_pem, _) = generate_ca();
    let (cert_pem, key_pem) = generate_signed_cert(&ca_cert, &ca_key, &["localhost"]);
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
