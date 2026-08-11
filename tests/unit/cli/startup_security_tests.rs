//! Unit tests for shared startup security loaders (issue #2976).
//!
//! These cover the env-level TLS/CIDR/metrics surfaces that `ferrum-edge
//! validate` and `run` must exercise identically, without binding sockets or
//! spawning servers.

use ferrum_edge::config::env_config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::startup_security::{
    StartupSecurityScope, load_startup_security, load_startup_security_with_scope,
    mesh_inbound_modes_need_client_ca, mesh_inbound_server_identity_configured,
    try_load_frontend_tls, validate_dtls_material, validate_mesh_inbound_client_ca_if_applicable,
};
use ferrum_edge::tls::{TlsPolicy, load_crls};
use rcgen::{CertificateParams, KeyPair};
use std::sync::Once;
use tempfile::TempDir;

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

fn generate_self_signed_cert() -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn generate_expired_cert() -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(30);
    params.not_after = now - time::Duration::days(1);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn file_mode_env() -> EnvConfig {
    // Disable admin HTTPS by default so tests that don't set admin TLS paths
    // are not gated on the default port 9443 listener.
    EnvConfig {
        mode: OperatingMode::File,
        admin_https_port: 0,
        ..EnvConfig::default()
    }
}

#[test]
fn scope_for_proxy_modes_includes_frontend_admin_and_dtls() {
    for mode in [
        OperatingMode::File,
        OperatingMode::Database,
        OperatingMode::DataPlane,
    ] {
        let scope = StartupSecurityScope::for_mode(&mode);
        assert!(scope.tls_policy_and_crls);
        assert!(scope.admin_cidrs_and_metrics);
        assert!(scope.frontend_tls);
        assert!(scope.admin_tls);
        assert!(scope.dtls);
    }
}

#[test]
fn scope_for_cp_skips_frontend_and_dtls() {
    let scope = StartupSecurityScope::for_mode(&OperatingMode::ControlPlane);
    assert!(scope.tls_policy_and_crls);
    assert!(scope.admin_cidrs_and_metrics);
    assert!(!scope.frontend_tls);
    assert!(scope.admin_tls);
    assert!(!scope.dtls);
}

#[test]
fn scope_for_mesh_uses_mesh_frontend_but_skips_dtls() {
    let scope = StartupSecurityScope::for_mode(&OperatingMode::Mesh);
    assert!(scope.tls_policy_and_crls);
    assert!(scope.admin_cidrs_and_metrics);
    assert!(scope.frontend_tls);
    assert!(scope.admin_tls);
    assert!(!scope.dtls);
}

#[test]
fn scope_for_node_agent_is_admin_only() {
    let scope = StartupSecurityScope::for_mode(&OperatingMode::NodeAgent);
    // TLS policy/CRL/admin TLS are in scope for validate/run parity, but
    // load_startup_security_with_scope gates them on an active/explicit HTTPS
    // admin surface so HTTP-only installs stay unaffected.
    assert!(scope.tls_policy_and_crls);
    assert!(scope.admin_cidrs_and_metrics);
    assert!(!scope.frontend_tls);
    assert!(scope.admin_tls);
    assert!(!scope.dtls);
}

#[test]
fn scope_for_migrate_and_injector_is_empty() {
    assert!(StartupSecurityScope::for_mode(&OperatingMode::Migrate).is_empty());
    assert!(StartupSecurityScope::for_mode(&OperatingMode::Injector).is_empty());
}

#[test]
fn load_startup_security_succeeds_for_default_file_mode() {
    ensure_crypto_provider();
    let env = file_mode_env();
    load_startup_security(&env).expect("default file-mode env should pass startup security");
}

#[test]
fn missing_frontend_cert_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let key_path = write_pem(&dir, "key.pem", &key_pem);
    let _cert_path = write_pem(&dir, "cert.pem", &cert_pem);

    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some(dir.path().join("missing-cert.pem").display().to_string());
    env.frontend_tls_key_path = Some(key_path);

    let err = load_startup_security(&env)
        .err()
        .expect("missing frontend cert must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid TLS configuration"),
        "expected Invalid TLS configuration context, got: {msg}"
    );
}

#[test]
fn mismatched_frontend_key_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, _) = generate_self_signed_cert();
    let (_, other_key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "other-key.pem", &other_key_pem);

    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some(cert_path);
    env.frontend_tls_key_path = Some(key_path);

    let err = load_startup_security(&env)
        .err()
        .expect("mismatched key must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid TLS configuration"),
        "expected Invalid TLS configuration context, got: {msg}"
    );
}

#[test]
fn malformed_crl_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let crl_path = write_pem(&dir, "bad.crl", "not-a-crl\n");

    let mut env = file_mode_env();
    env.tls_crl_file_path = Some(crl_path);

    let err = load_startup_security(&env)
        .err()
        .expect("malformed CRL must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("CRL") || msg.contains("PEM"),
        "expected CRL parse failure, got: {msg}"
    );
}

#[test]
fn malformed_admin_cidrs_fails_closed() {
    ensure_crypto_provider();
    let mut env = file_mode_env();
    env.admin_allowed_cidrs = "10.0.0.1, not-a-cidr".to_string();

    let err = load_startup_security(&env)
        .err()
        .expect("malformed admin CIDRs must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("FERRUM_ADMIN_ALLOWED_CIDRS"),
        "expected admin CIDR context, got: {msg}"
    );
}

#[test]
fn malformed_metrics_cidrs_fails_closed() {
    ensure_crypto_provider();
    let mut env = file_mode_env();
    env.metrics_allowed_cidrs = "not-a-cidr".to_string();

    let err = load_startup_security(&env)
        .err()
        .expect("malformed metrics CIDRs must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("FERRUM_METRICS_ALLOWED_CIDRS"),
        "expected metrics CIDR context, got: {msg}"
    );
}

#[test]
fn expired_frontend_cert_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_expired_cert();
    let cert_path = write_pem(&dir, "expired.pem", &cert_pem);
    let key_path = write_pem(&dir, "expired-key.pem", &key_pem);

    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some(cert_path);
    env.frontend_tls_key_path = Some(key_path);

    let err = load_startup_security(&env)
        .err()
        .expect("expired frontend cert must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid TLS configuration"),
        "expected Invalid TLS configuration context, got: {msg}"
    );
}

#[test]
fn valid_frontend_tls_pair_passes() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
    let key_path = write_pem(&dir, "key.pem", &key_pem);

    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some(cert_path);
    env.frontend_tls_key_path = Some(key_path);

    let materials = load_startup_security(&env).expect("valid frontend TLS must pass");
    assert!(materials.frontend_tls.is_some());
    assert!(materials.tls_policy.is_some());
}

#[test]
fn expired_dtls_cert_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_expired_cert();
    let cert_path = write_pem(&dir, "dtls.pem", &cert_pem);
    let key_path = write_pem(&dir, "dtls-key.pem", &key_pem);

    let mut env = file_mode_env();
    env.dtls_cert_path = Some(cert_path);
    env.dtls_key_path = Some(key_path);

    let err = validate_dtls_material(&env).expect_err("expired DTLS cert must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid DTLS frontend cert"),
        "expected DTLS expiry context, got: {msg}"
    );
}

#[test]
fn missing_admin_tls_cert_fails_when_https_enabled() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let _cert_path = write_pem(&dir, "admin.pem", &cert_pem);
    let key_path = write_pem(&dir, "admin-key.pem", &key_pem);

    let mut env = file_mode_env();
    env.admin_https_port = 9443;
    env.admin_tls_cert_path = Some(dir.path().join("missing-admin.pem").display().to_string());
    env.admin_tls_key_path = Some(key_path);

    let err = load_startup_security(&env)
        .err()
        .expect("missing admin cert must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid admin TLS configuration"),
        "expected admin TLS context, got: {msg}"
    );
}

#[test]
fn valid_admin_tls_pair_passes_when_https_enabled() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.pem", &cert_pem);
    let key_path = write_pem(&dir, "admin-key.pem", &key_pem);

    let mut env = file_mode_env();
    env.admin_https_port = 9443;
    env.admin_tls_cert_path = Some(cert_path);
    env.admin_tls_key_path = Some(key_path);

    let materials = load_startup_security(&env).expect("valid admin TLS must pass");
    assert!(materials.admin_tls.is_some());
}

#[test]
fn partial_admin_tls_pair_is_ignored_when_https_listener_is_disabled() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 9443,
        admin_tls_cert_path: Some("/nonexistent/admin.pem".to_string()),
        admin_tls_key_path: None,
        ..file_mode_env()
    };

    let materials =
        load_startup_security(&env).expect("disabled admin HTTPS must not load partial material");
    assert!(materials.admin_tls.is_none());
}

#[test]
fn cp_scope_ignores_frontend_tls_paths() {
    ensure_crypto_provider();
    // Point frontend at a missing path — CP must not load it.
    let env = EnvConfig {
        mode: OperatingMode::ControlPlane,
        admin_https_port: 0,
        frontend_tls_cert_path: Some("/nonexistent/frontend.pem".to_string()),
        frontend_tls_key_path: Some("/nonexistent/frontend-key.pem".to_string()),
        ..EnvConfig::default()
    };

    load_startup_security_with_scope(&env, StartupSecurityScope::for_mode(&env.mode))
        .expect("CP scope must skip frontend TLS paths");
}

#[test]
fn mesh_scope_ignores_dtls_material() {
    ensure_crypto_provider();
    let env_guard = crate::unit::env_lock::EnvGuard::new(&["FERRUM_MESH_TOPOLOGY"]);
    env_guard.unset("FERRUM_MESH_TOPOLOGY");

    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        dtls_cert_path: Some("/nonexistent/dtls.pem".to_string()),
        dtls_key_path: Some("/nonexistent/dtls-key.pem".to_string()),
        ..EnvConfig::default()
    };

    load_startup_security(&env).expect("mesh startup does not gate on DTLS material");
}

#[test]
fn mesh_terminating_missing_client_ca_fails_closed() {
    ensure_crypto_provider();
    let env_guard = crate::unit::env_lock::EnvGuard::new(&["FERRUM_MESH_TOPOLOGY"]);
    env_guard.unset("FERRUM_MESH_TOPOLOGY");

    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_client_ca_bundle_path: Some("/nonexistent/mesh-client-ca.pem".to_string()),
        ..EnvConfig::default()
    };

    // Default topology is sidecar (terminating). No-slice startup uses
    // PERMISSIVE, so run would load the configured client CA even with no
    // server identity (before the plaintext Ok(None) return).
    let err = load_startup_security(&env)
        .err()
        .expect("missing mesh client CA must fail on terminating topology");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("failed to load mesh frontend client CA bundle"),
        "expected shared mesh client-CA load failure, got: {msg}"
    );
}

#[test]
fn mesh_terminating_malformed_client_ca_without_identity_matches_run_plaintext() {
    ensure_crypto_provider();
    let env_guard = crate::unit::env_lock::EnvGuard::new(&["FERRUM_MESH_TOPOLOGY"]);
    env_guard.unset("FERRUM_MESH_TOPOLOGY");

    let dir = TempDir::new().unwrap();
    let ca_path = write_pem(&dir, "bad-client-ca.pem", "not-a-certificate\n");
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };

    assert!(
        !mesh_inbound_server_identity_configured(&env).unwrap(),
        "fixture must have no configured mesh server identity"
    );
    // Run loads CA bytes on the no-slice PERMISSIVE snapshot, then
    // `load_mesh_frontend_tls` returns Ok(None) before PEM-parsing the CA.
    load_startup_security(&env).expect(
        "readable malformed client CA with no identity must match run's permissive plaintext path",
    );
}

#[test]
fn mesh_malformed_client_ca_rejected_with_explicit_frontend_identity() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let ca_path = write_pem(&dir, "bad-client-ca.pem", "not-a-certificate\n");
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_cert_path: Some(write_pem(
            &dir,
            "frontend.crt",
            "unused-for-identity-gate\n",
        )),
        frontend_tls_key_path: Some(write_pem(
            &dir,
            "frontend.key",
            "unused-for-identity-gate\n",
        )),
        frontend_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };

    assert!(mesh_inbound_server_identity_configured(&env).unwrap());
    let err = validate_mesh_inbound_client_ca_if_applicable(&env, true, true)
        .expect_err("malformed CA must PEM-fail when explicit frontend identity is configured");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("mesh client CA bundle"),
        "expected mesh client CA PEM/expiry failure, got: {msg}"
    );
}

#[test]
fn mesh_malformed_client_ca_rejected_with_gateway_svid_identity() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let ca_path = write_pem(&dir, "bad-client-ca.pem", "not-a-certificate\n");
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        gateway_svid_cert_path: Some(write_pem(&dir, "svid.crt", "unused-for-identity-gate\n")),
        gateway_svid_key_path: Some(write_pem(&dir, "svid.key", "unused-for-identity-gate\n")),
        frontend_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };

    assert!(mesh_inbound_server_identity_configured(&env).unwrap());
    let err = validate_mesh_inbound_client_ca_if_applicable(&env, true, true)
        .expect_err("malformed CA must PEM-fail when gateway SVID identity is configured");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("mesh client CA bundle"),
        "expected mesh client CA PEM/expiry failure, got: {msg}"
    );
}

#[test]
fn mesh_malformed_client_ca_rejected_with_mesh_ca_backend_identity() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let ca_path = write_pem(&dir, "bad-client-ca.pem", "not-a-certificate\n");
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        mesh_ca_backend: "spire".to_string(),
        frontend_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };

    assert!(mesh_inbound_server_identity_configured(&env).unwrap());
    let err = validate_mesh_inbound_client_ca_if_applicable(&env, true, true)
        .expect_err("malformed CA must PEM-fail when mesh CA backend identity is configured");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("mesh client CA bundle"),
        "expected mesh client CA PEM/expiry failure, got: {msg}"
    );
}

#[test]
fn mesh_passthrough_topology_skips_unused_client_ca() {
    ensure_crypto_provider();
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_client_ca_bundle_path: Some("/nonexistent/unused-client-ca.pem".to_string()),
        ..EnvConfig::default()
    };

    // East-west is passthrough-only: run's listener-aware snapshot skips CA.
    validate_mesh_inbound_client_ca_if_applicable(&env, false, true)
        .expect("passthrough topology must not reject an unused configured client CA");
}

#[test]
fn mesh_mtls_disabled_skips_unused_client_ca() {
    ensure_crypto_provider();
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_client_ca_bundle_path: Some("/nonexistent/unused-client-ca.pem".to_string()),
        ..EnvConfig::default()
    };

    // Workload DISABLE with no enabling port overrides: run skips CA load.
    let needs_ca = mesh_inbound_modes_need_client_ca(false, false);
    assert!(!needs_ca);
    validate_mesh_inbound_client_ca_if_applicable(&env, true, needs_ca)
        .expect("DISABLE mTLS must not reject an unused configured client CA");
}

#[test]
fn mesh_valid_client_ca_with_identity_passes_on_terminating_topology() {
    ensure_crypto_provider();
    let env_guard = crate::unit::env_lock::EnvGuard::new(&["FERRUM_MESH_TOPOLOGY"]);
    env_guard.unset("FERRUM_MESH_TOPOLOGY");

    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let ca_path = write_pem(&dir, "client-ca.pem", &cert_pem);
    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_cert_path: Some(write_pem(&dir, "frontend.crt", &cert_pem)),
        frontend_tls_key_path: Some(write_pem(&dir, "frontend.key", &key_pem)),
        frontend_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };

    load_startup_security(&env)
        .expect("valid mesh client CA with explicit identity must pass on terminating topology");
}

#[test]
fn mesh_east_west_env_topology_skips_client_ca_via_load_startup_security() {
    ensure_crypto_provider();
    let env_guard = crate::unit::env_lock::EnvGuard::new(&["FERRUM_MESH_TOPOLOGY"]);
    env_guard.set("FERRUM_MESH_TOPOLOGY", "east_west_gateway");

    let env = EnvConfig {
        mode: OperatingMode::Mesh,
        admin_https_port: 0,
        frontend_tls_client_ca_bundle_path: Some("/nonexistent/unused-client-ca.pem".to_string()),
        ..EnvConfig::default()
    };

    load_startup_security(&env)
        .expect("east_west_gateway validate must skip unused configured client CA");
}

#[test]
fn node_agent_admin_gate_matches_serving_listener_boundary() {
    let disabled = EnvConfig {
        mode: OperatingMode::NodeAgent,
        node_agent_admin_enabled: false,
        admin_http_port: 9000,
        admin_allowed_cidrs: "not-a-cidr".to_string(),
        metrics_allowed_cidrs: "also-not-a-cidr".to_string(),
        // Unrelated TLS policy/CRL must not fail a disabled admin surface.
        tls_crl_file_path: Some("/nonexistent/unrelated.crl".to_string()),
        ..EnvConfig::default()
    };
    load_startup_security(&disabled)
        .expect("disabled node-agent admin must not parse admin security policy");

    let port_disabled = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: 0,
        ..disabled.clone()
    };
    load_startup_security(&port_disabled)
        .expect("port-zero node-agent admin must not parse admin security policy");

    let http_only_unrelated_crl = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 9000,
        admin_https_port: 0,
        admin_allowed_cidrs: String::new(),
        metrics_allowed_cidrs: String::new(),
        tls_crl_file_path: Some("/nonexistent/unrelated.crl".to_string()),
        ..EnvConfig {
            mode: OperatingMode::NodeAgent,
            ..EnvConfig::default()
        }
    };
    load_startup_security(&http_only_unrelated_crl)
        .expect("HTTP-only node-agent must not fail on unrelated CRL settings");

    let https_only_malformed = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/tmp/tls.crt".to_string()),
        admin_tls_key_path: Some("/tmp/tls.key".to_string()),
        tls_crl_file_path: None,
        ..disabled.clone()
    };
    let err = load_startup_security(&https_only_malformed)
        .err()
        .expect("HTTPS-only node-agent admin must still parse CIDRs or fail closed on TLS");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("FERRUM_ADMIN_ALLOWED_CIDRS")
            || msg.contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {msg}"
    );

    let explicit_https_missing_tls = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_allowed_cidrs: String::new(),
        metrics_allowed_cidrs: String::new(),
        ..EnvConfig {
            mode: OperatingMode::NodeAgent,
            ..EnvConfig::default()
        }
    };
    let err = load_startup_security(&explicit_https_missing_tls)
        .err()
        .expect("explicit HTTPS without TLS must fail closed at validate");
    assert!(
        format!("{err:#}").contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {err:#}"
    );

    let active = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 9000,
        admin_https_port: 0,
        ..disabled
    };
    let err = load_startup_security(&active)
        .err()
        .expect("active node-agent admin must reject malformed CIDRs");
    assert!(format!("{err:#}").contains("FERRUM_ADMIN_ALLOWED_CIDRS"));
}

#[test]
fn try_load_frontend_tls_returns_none_when_unset() {
    ensure_crypto_provider();
    let env = file_mode_env();
    let policy = TlsPolicy::from_env_config(&env).unwrap();
    let crls = load_crls(None).unwrap();
    let loaded = try_load_frontend_tls(&env, &policy, &crls).unwrap();
    assert!(loaded.is_none());
}
