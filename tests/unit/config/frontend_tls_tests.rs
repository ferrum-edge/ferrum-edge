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

// ===========================================================================
// Issue #4506: ACME auto-renewal that can never reach the serving listener
// ===========================================================================
//
// Renewed ACME material is published into the certificate store and then
// offered to the TLS surfaces that registered a force-reload sender. Only the
// frontend live-reload watcher registers one, and it is not built when
// `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` is false (its default). The
// combination is refused at startup rather than served as a silent no-op.

const ACME_CERT_SOURCE: &str = "acme://certificates/edge-cert#cert";
const ACME_KEY_SOURCE: &str = "acme://certificates/edge-cert#key";

fn acme_frontend(auto_renew: bool, live_reload: bool) -> EnvConfig {
    EnvConfig {
        acme_auto_renew_enabled: auto_renew,
        frontend_tls_live_reload_enabled: live_reload,
        frontend_tls_cert_path: Some(ACME_CERT_SOURCE.to_string()),
        frontend_tls_key_path: Some(ACME_KEY_SOURCE.to_string()),
        ..Default::default()
    }
}

/// Issue #7251: only database, file and dp modes run the ACME renewal
/// scheduler, so every other mode refuses the flag instead of accepting it and
/// never renewing.
#[test]
fn acme_auto_renew_is_refused_in_modes_without_the_renewal_scheduler() {
    use ferrum_edge::config::env_config::OperatingMode;

    for (mode, runs_scheduler) in [
        (OperatingMode::Database, true),
        (OperatingMode::File, true),
        (OperatingMode::DataPlane, true),
        (OperatingMode::Mesh, false),
        (OperatingMode::ControlPlane, false),
        (OperatingMode::Injector, false),
        (OperatingMode::NodeAgent, false),
        (OperatingMode::Migrate, false),
    ] {
        let enabled = EnvConfig {
            mode: mode.clone(),
            acme_auto_renew_enabled: true,
            ..Default::default()
        };
        let result = enabled.validate_acme_renewal_mode();
        if runs_scheduler {
            result.unwrap_or_else(|error| panic!("{mode:?} runs the scheduler: {error}"));
        } else {
            let error = result.expect_err("a mode without the scheduler must refuse the flag");
            assert!(
                error.contains("FERRUM_ACME_AUTO_RENEW_ENABLED"),
                "the diagnostic must name the flag: {error}"
            );
        }

        let disabled = EnvConfig {
            mode,
            acme_auto_renew_enabled: false,
            ..Default::default()
        };
        disabled
            .validate_acme_renewal_mode()
            .expect("auto-renew off is valid in every mode");
    }
}

#[test]
fn acme_renewal_reachability_accepts_auto_renew_disabled() {
    acme_frontend(false, false)
        .validate_acme_renewal_reachability()
        .expect("auto-renew off never publishes material, so nothing can go unserved");
}

#[test]
fn acme_renewal_reachability_accepts_a_non_acme_source() {
    let config = EnvConfig {
        acme_auto_renew_enabled: true,
        frontend_tls_live_reload_enabled: false,
        frontend_tls_cert_path: Some("/etc/ferrum/frontend.crt".to_string()),
        frontend_tls_key_path: Some("/etc/ferrum/frontend.key".to_string()),
        admin_tls_cert_path: Some("/etc/ferrum/admin.crt".to_string()),
        admin_tls_key_path: Some("/etc/ferrum/admin.key".to_string()),
        ..Default::default()
    };

    config
        .validate_acme_renewal_reachability()
        .expect("a file-backed serving source is not renewed by the ACME scheduler");
}

#[test]
fn acme_renewal_reachability_accepts_live_reload_enabled() {
    acme_frontend(true, true)
        .validate_acme_renewal_reachability()
        .expect("the live-reload watcher registers the force-reload sender the renewal needs");
}

#[test]
fn acme_renewal_reachability_rejects_an_unserviceable_frontend_source() {
    let error = acme_frontend(true, false)
        .validate_acme_renewal_reachability()
        .expect_err("renewals would land in the store and never reach the listener");

    assert!(
        error.contains("FERRUM_ACME_AUTO_RENEW_ENABLED"),
        "the diagnostic must name the renewal flag: {error}"
    );
    assert!(
        error.contains("FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED"),
        "the diagnostic must name the reload flag the operator has to set: {error}"
    );
    assert!(
        error.contains("acme://certificates/edge-cert"),
        "the diagnostic must name the offending source: {error}"
    );
}

/// The admin HTTPS listener has no live-reload flag of its own — it shares
/// `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` — so an `acme://` admin source is
/// refused on exactly the same terms.
#[test]
fn acme_renewal_reachability_rejects_an_unserviceable_admin_source() {
    let config = EnvConfig {
        acme_auto_renew_enabled: true,
        frontend_tls_live_reload_enabled: false,
        admin_tls_cert_path: Some(ACME_CERT_SOURCE.to_string()),
        admin_tls_key_path: Some(ACME_KEY_SOURCE.to_string()),
        ..Default::default()
    };

    let error = config
        .validate_acme_renewal_reachability()
        .expect_err("the admin listener has the same unregistered-surface gap");
    assert!(
        error.contains("FERRUM_ADMIN_TLS_CERT_SOURCE"),
        "the diagnostic must name the admin variable that carries the source: {error}"
    );
    assert!(
        error.contains("FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED"),
        "the admin surface shares the frontend live-reload flag: {error}"
    );
}

// ===========================================================================
// Issue #7194: an unparseable ACME renewal challenge type is refused
// ===========================================================================

fn acme_challenge(auto_renew: bool, challenge_type: &str) -> EnvConfig {
    EnvConfig {
        acme_auto_renew_enabled: auto_renew,
        acme_renew_challenge_type: challenge_type.to_string(),
        ..Default::default()
    }
}

#[test]
fn acme_renewal_challenge_type_accepts_every_supported_spelling() {
    for value in [
        "http01",
        "http-01",
        "tls_alpn01",
        "tls-alpn-01",
        "tls-alpn01",
        "dns01",
        "DNS-01",
    ] {
        acme_challenge(true, value)
            .validate_acme_renewal_challenge_type()
            .unwrap_or_else(|error| panic!("{value:?} must be accepted: {error}"));
    }
}

#[test]
fn acme_renewal_challenge_type_rejects_a_typo_when_auto_renew_is_enabled() {
    for value in ["http", "tls-alpn", "dns", ""] {
        let error = acme_challenge(true, value)
            .validate_acme_renewal_challenge_type()
            .expect_err("the scheduler would refuse to start and renewal would stop silently");
        assert!(
            error.contains("FERRUM_ACME_RENEW_CHALLENGE_TYPE")
                && error.contains("FERRUM_ACME_AUTO_RENEW_ENABLED"),
            "the diagnostic must name both settings: {error}"
        );
    }
    let error = acme_challenge(true, "secret-looking-typo")
        .validate_acme_renewal_challenge_type()
        .expect_err("an unknown value is refused");
    assert!(
        !error.contains("secret-looking-typo"),
        "the configured value must be withheld: {error}"
    );
}

#[test]
fn acme_renewal_challenge_type_is_ignored_when_auto_renew_is_disabled() {
    acme_challenge(false, "http")
        .validate_acme_renewal_challenge_type()
        .expect("the scheduler does not start, so the value is never parsed");
}
