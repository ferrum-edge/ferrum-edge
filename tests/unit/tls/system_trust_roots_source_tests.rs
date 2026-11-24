//! `system://` — the first-class backend trust-anchor source (issue #3276).
//!
//! `system://` is Ferrum's representation of Gateway API `BackendTLSPolicy`
//! `wellKnownCACertificates: System`. It differs from an *unset* CA path in
//! three security-relevant ways, all pinned here:
//!
//! 1. it does not fall back to the cluster-global `FERRUM_TLS_CA_BUNDLE_PATH`;
//! 2. it never inherits the global `FERRUM_TLS_NO_VERIFY` opt-out;
//! 3. it is a distinct pool-key identity, so a system-trust backend never
//!    shares a pooled connection with a custom-CA one.

use ferrum_edge::config::types::{BackendTlsConfig, Proxy, Upstream};
use ferrum_edge::tls::backend::append_backend_tls_pool_key_fields;
use ferrum_edge::tls::source::{
    CertSource, MaterialKind, SYSTEM_TRUST_ROOTS_SOURCE, is_system_trust_roots_source,
};
use serde_json::json;

fn system_trust_config() -> BackendTlsConfig {
    BackendTlsConfig {
        server_ca_cert_path: Some(SYSTEM_TRUST_ROOTS_SOURCE.to_string()),
        verify_server_cert: true,
        ..BackendTlsConfig::default_verify()
    }
}

#[test]
fn system_source_parses_as_a_typed_uri_not_a_filesystem_path() {
    let source = CertSource::parse(SYSTEM_TRUST_ROOTS_SOURCE, MaterialKind::CaBundle);
    assert!(
        source.is_system_trust_roots(),
        "system:// must parse as the typed system-roots source"
    );
    assert!(
        source.as_file_path().is_none(),
        "system:// must never be interpreted as a file path"
    );
    assert_eq!(source.source_id(), SYSTEM_TRUST_ROOTS_SOURCE);
    assert_eq!(source.to_config_value(), SYSTEM_TRUST_ROOTS_SOURCE);
    assert!(is_system_trust_roots_source(SYSTEM_TRUST_ROOTS_SOURCE));
    assert!(!is_system_trust_roots_source("/etc/ssl/ca.pem"));
    assert!(!is_system_trust_roots_source("k8s://ns/secret#ca.crt"));
}

#[test]
fn system_source_does_not_fall_back_to_the_global_ca_bundle() {
    let tls = system_trust_config();
    assert!(tls.uses_system_trust_roots());
    assert_eq!(
        tls.effective_ca_source(Some("/etc/ferrum/cluster-ca.pem")),
        None,
        "an explicit system-roots selection must not be replaced by the global bundle"
    );

    // An unset CA path is the case that DOES fall back — that difference is the
    // whole reason `system://` exists.
    let unset = BackendTlsConfig::default_verify();
    assert!(!unset.uses_system_trust_roots());
    assert_eq!(
        unset.effective_ca_source(Some("/etc/ferrum/cluster-ca.pem")),
        Some("/etc/ferrum/cluster-ca.pem")
    );

    // A configured custom CA still wins over the global bundle.
    let custom = BackendTlsConfig {
        server_ca_cert_path: Some("/etc/ferrum/backend-ca.pem".to_string()),
        ..BackendTlsConfig::default_verify()
    };
    assert_eq!(
        custom.effective_ca_source(Some("/etc/ferrum/cluster-ca.pem")),
        Some("/etc/ferrum/backend-ca.pem")
    );
}

#[test]
fn system_source_does_not_inherit_the_global_no_verify_opt_out() {
    assert!(
        !system_trust_config().allows_global_no_verify(),
        "FERRUM_TLS_NO_VERIFY must not disable verification for a system-trust backend"
    );
    assert!(BackendTlsConfig::default_verify().allows_global_no_verify());
}

#[test]
fn system_source_is_a_distinct_pool_key_identity() {
    let mut system_key = String::new();
    append_backend_tls_pool_key_fields(
        &mut system_key,
        &system_trust_config(),
        None,
        None,
        true,
        None,
    );

    let mut unset_key = String::new();
    append_backend_tls_pool_key_fields(
        &mut unset_key,
        &BackendTlsConfig::default_verify(),
        None,
        None,
        true,
        None,
    );

    let mut custom_key = String::new();
    append_backend_tls_pool_key_fields(
        &mut custom_key,
        &BackendTlsConfig {
            server_ca_cert_path: Some("/etc/ferrum/backend-ca.pem".to_string()),
            ..BackendTlsConfig::default_verify()
        },
        None,
        None,
        true,
        None,
    );

    assert_ne!(
        system_key, unset_key,
        "system trust and no-CA-configured must not share a pooled connection"
    );
    assert_ne!(system_key, custom_key);
    assert!(system_key.contains(SYSTEM_TRUST_ROOTS_SOURCE));
}

// ---------------------------------------------------------------------------
// Config admission
// ---------------------------------------------------------------------------

fn upstream_errors(ca: &str, verify: bool) -> Vec<String> {
    let upstream: Upstream = serde_json::from_value(json!({
        "id": "u1",
        "targets": [{ "host": "backend.example.com", "port": 443 }],
        "backend_tls_server_ca_cert_path": ca,
        "backend_tls_verify_server_cert": verify,
    }))
    .expect("upstream fixture");
    upstream.validate_fields().err().unwrap_or_default()
}

#[test]
fn upstream_admits_the_canonical_system_source() {
    let errors = upstream_errors(SYSTEM_TRUST_ROOTS_SOURCE, true);
    assert!(
        !errors
            .iter()
            .any(|error| error.contains("backend_tls_server_ca_cert_path")
                || error.contains("system trust-roots")),
        "the canonical system:// spelling must be admitted: {errors:?}"
    );
}

#[test]
fn upstream_rejects_a_system_source_with_a_path_or_options() {
    for value in [
        "system://corp-ca.pem",
        "system://?kind=ca_bundle",
        "system://etc/ssl/certs",
    ] {
        let errors = upstream_errors(value, true);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("must be exactly `system://`")),
            "'{value}' must be rejected rather than silently selecting system roots: {errors:?}"
        );
    }
}

#[test]
fn upstream_rejects_system_source_with_verification_disabled() {
    let errors = upstream_errors(SYSTEM_TRUST_ROOTS_SOURCE, false);
    assert!(
        errors.iter().any(|error| {
            error.contains("backend_tls_verify_server_cert")
                && error
                    .contains("system trust-roots source requires server certificate verification")
        }),
        "system:// with verification disabled is a contradiction and must fail closed: {errors:?}"
    );
}

#[test]
fn client_cert_and_key_fields_reject_the_system_source() {
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "backend_tls_client_cert_path": SYSTEM_TRUST_ROOTS_SOURCE,
        "backend_tls_client_key_path": SYSTEM_TRUST_ROOTS_SOURCE,
    }))
    .expect("proxy fixture");

    let errors = proxy.validate_fields().err().unwrap_or_default();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("backend_tls_client_cert_path")
                && error.contains("only valid on a CA bundle field")),
        "system:// on a client cert field selects nothing and must be rejected: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("backend_tls_client_key_path")
                && error.contains("only valid on a CA bundle field")),
        "system:// on a client key field must be rejected: {errors:?}"
    );
}

// ---------------------------------------------------------------------------
// Provider isolation (`BackendTlsConfig::isolated_public_verify`)
// ---------------------------------------------------------------------------

/// `ai_stream_router` commits this configuration for a third-party HTTPS
/// provider. `default_verify()` leaves the CA and client identity unset, and the
/// backend TLS builder fills unset fields from gateway-global settings; the
/// isolated form must take none of them: no global CA bundle, no
/// `FERRUM_TLS_NO_VERIFY`, and no global backend client certificate.
#[test]
fn provider_isolated_tls_never_inherits_global_ca_no_verify_or_client_identity() {
    use ferrum_edge::tls::backend::BackendTlsConfigBuilder;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let isolated = BackendTlsConfig::isolated_public_verify();
    assert!(isolated.uses_system_trust_roots());
    assert!(!isolated.allows_global_no_verify());
    assert!(isolated.verify_server_cert);
    assert_eq!(
        isolated.effective_ca_source(Some("/etc/ferrum/cluster-ca.pem")),
        None
    );
    assert_eq!(
        isolated.effective_client_cert_path(Some("/etc/ferrum/global-client.pem")),
        None
    );
    assert_eq!(
        isolated.effective_client_key_path(Some("/etc/ferrum/global-client.key")),
        None
    );
    // An ordinary destination still inherits the global pair, and an explicit
    // per-destination identity still wins on an isolated one.
    let ordinary = BackendTlsConfig::default_verify();
    assert_eq!(
        ordinary.effective_client_cert_path(Some("/etc/ferrum/global-client.pem")),
        Some("/etc/ferrum/global-client.pem")
    );
    let explicit = BackendTlsConfig {
        client_cert_path: Some("/certs/own.pem".to_string()),
        client_key_path: Some("/certs/own.key".to_string()),
        ..BackendTlsConfig::isolated_public_verify()
    };
    assert_eq!(
        explicit.effective_client_cert_path(Some("/etc/ferrum/global-client.pem")),
        Some("/certs/own.pem")
    );

    // The real builder, driven exactly as a pool manager drives it with
    // `FERRUM_TLS_NO_VERIFY=true` and a global CA / client pair whose files do
    // not exist: any attempt to read the global material fails the build.
    let missing = std::path::Path::new("/nonexistent/ferrum-global-backend-tls.pem");
    let mut proxy: Proxy = serde_json::from_value(json!({
        "id": "provider",
        "name": "provider",
        "listen_path": "/provider",
        "backend_scheme": "https",
        "backend_host": "api.provider.test",
        "backend_port": 443,
    }))
    .expect("proxy fixture");
    let build = |proxy: &Proxy| {
        BackendTlsConfigBuilder {
            proxy,
            policy: None,
            global_ca: Some(missing),
            global_no_verify: true,
            global_client_cert: Some(missing),
            global_client_key: Some(missing),
            crls: &[],
        }
        .build_rustls()
        .is_ok()
    };
    proxy.resolved_tls = BackendTlsConfig::default_verify();
    assert!(
        !build(&proxy),
        "control: an ordinary destination reads the global client pair"
    );
    proxy.resolved_tls = BackendTlsConfig::isolated_public_verify();
    assert!(
        build(&proxy),
        "an isolated provider destination must not read any gateway-global TLS material"
    );

    // Its pool / TLS-config key never collides with a plain `system://` one.
    let mut isolated_key = String::new();
    append_backend_tls_pool_key_fields(
        &mut isolated_key,
        &BackendTlsConfig::isolated_public_verify(),
        None,
        None,
        true,
        None,
    );
    let mut system_key = String::new();
    append_backend_tls_pool_key_fields(
        &mut system_key,
        &system_trust_config(),
        None,
        None,
        true,
        None,
    );
    assert!(isolated_key.contains("|noglobalid"), "{isolated_key}");
    assert_ne!(isolated_key, system_key);
}
