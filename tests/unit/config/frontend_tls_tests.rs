use ferrum_edge::config::EnvConfig;

#[test]
fn frontend_tls_defaults_have_no_server_or_client_material() {
    let config = EnvConfig::default();

    assert!(config.frontend_tls_cert_path.is_none());
    assert!(config.frontend_tls_key_path.is_none());
    assert!(config.frontend_tls_client_ca_bundle_path.is_none());
    assert!(!config.tls_no_verify);
}

#[test]
fn frontend_tls_server_material_and_client_ca_are_preserved() {
    let config = EnvConfig {
        frontend_tls_cert_path: Some("/etc/ferrum/frontend.crt".to_string()),
        frontend_tls_key_path: Some("/etc/ferrum/frontend.key".to_string()),
        frontend_tls_client_ca_bundle_path: Some("/etc/ferrum/client-ca.pem".to_string()),
        ..Default::default()
    };

    assert_eq!(
        config.frontend_tls_cert_path.as_deref(),
        Some("/etc/ferrum/frontend.crt")
    );
    assert_eq!(
        config.frontend_tls_key_path.as_deref(),
        Some("/etc/ferrum/frontend.key")
    );
    assert_eq!(
        config.frontend_tls_client_ca_bundle_path.as_deref(),
        Some("/etc/ferrum/client-ca.pem")
    );
}

#[test]
fn frontend_client_ca_does_not_toggle_backend_or_admin_no_verify_flags() {
    let config = EnvConfig {
        frontend_tls_client_ca_bundle_path: Some("/etc/ferrum/client-ca.pem".to_string()),
        ..Default::default()
    };

    assert!(config.frontend_tls_client_ca_bundle_path.is_some());
    assert!(!config.tls_no_verify);
    assert!(!config.admin_tls_no_verify);
    assert!(config.admin_tls_client_ca_bundle_path.is_none());
}
