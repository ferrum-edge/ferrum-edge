use ferrum_edge::config::EnvConfig;

#[test]
fn admin_tls_defaults_have_no_client_ca_and_verification_enabled() {
    let config = EnvConfig::default();

    assert!(config.admin_tls_cert_path.is_none());
    assert!(config.admin_tls_key_path.is_none());
    assert!(config.admin_tls_client_ca_bundle_path.is_none());
    assert!(!config.admin_tls_no_verify);
}

#[test]
fn admin_mtls_material_is_distinct_from_frontend_mtls_material() {
    let config = EnvConfig {
        frontend_tls_client_ca_bundle_path: Some("/etc/ferrum/frontend-ca.pem".to_string()),
        admin_tls_client_ca_bundle_path: Some("/etc/ferrum/admin-ca.pem".to_string()),
        ..Default::default()
    };

    assert_eq!(
        config.frontend_tls_client_ca_bundle_path.as_deref(),
        Some("/etc/ferrum/frontend-ca.pem")
    );
    assert_eq!(
        config.admin_tls_client_ca_bundle_path.as_deref(),
        Some("/etc/ferrum/admin-ca.pem")
    );
    assert_ne!(
        config.frontend_tls_client_ca_bundle_path,
        config.admin_tls_client_ca_bundle_path
    );
}

#[test]
fn admin_and_backend_no_verify_flags_are_independent() {
    let admin_only = EnvConfig {
        admin_tls_no_verify: true,
        tls_no_verify: false,
        ..Default::default()
    };
    assert!(admin_only.admin_tls_no_verify);
    assert!(!admin_only.tls_no_verify);

    let backend_only = EnvConfig {
        admin_tls_no_verify: false,
        tls_no_verify: true,
        ..Default::default()
    };
    assert!(!backend_only.admin_tls_no_verify);
    assert!(backend_only.tls_no_verify);
}

#[test]
fn admin_tls_server_material_does_not_enable_frontend_tls() {
    let config = EnvConfig {
        admin_tls_cert_path: Some("/etc/ferrum/admin.crt".to_string()),
        admin_tls_key_path: Some("/etc/ferrum/admin.key".to_string()),
        ..Default::default()
    };

    assert_eq!(
        config.admin_tls_cert_path.as_deref(),
        Some("/etc/ferrum/admin.crt")
    );
    assert_eq!(
        config.admin_tls_key_path.as_deref(),
        Some("/etc/ferrum/admin.key")
    );
    assert!(config.frontend_tls_cert_path.is_none());
    assert!(config.frontend_tls_key_path.is_none());
}
