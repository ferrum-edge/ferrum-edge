//! Explicit TLS source selectors must agree with the field's material kind
//! (issue #5959).
//!
//! A source reference can name the material it resolves to through a
//! `?kind=` hint, a scheme-specific fragment or data key, and — for
//! `managed://` / `acme://` — a collection path segment. Those used to be
//! honored or ignored without consulting the field, so a CA field configured
//! as `managed://certificates/<id>#cert` loaded a leaf certificate and its
//! chain into a trust store. These tests pin the rejection for every scheme
//! that carries such a selector, the positive spellings that must keep
//! working, and the admission surfaces that raise it before any load.

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::config::types::{GatewayConfig, Proxy, Upstream};
use ferrum_edge::tls::source::{
    CertSource, MaterialError, MaterialKind, load_material_blocking, validate_source_field_kind,
};
use serde_json::json;

use crate::unit::env_lock::with_env_vars;

const CA: MaterialKind = MaterialKind::CaBundle;
const CERT: MaterialKind = MaterialKind::Cert;
const KEY: MaterialKind = MaterialKind::Key;

fn check(value: &str, field_kind: MaterialKind) -> Result<(), MaterialError> {
    validate_source_field_kind(&CertSource::parse(value, field_kind), field_kind)
}

#[track_caller]
fn assert_rejected(value: &str, field_kind: MaterialKind, reason: &str) {
    match check(value, field_kind) {
        Err(error @ MaterialError::InvalidSource { .. }) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains(reason),
                "{value:?} in a {field_kind} field: expected {reason:?}, got: {rendered}"
            );
        }
        other => panic!("{value:?} must be rejected in a {field_kind} field, got: {other:?}"),
    }
}

#[track_caller]
fn assert_admitted(value: &str, field_kind: MaterialKind) {
    if let Err(error) = check(value, field_kind) {
        panic!("{value:?} must stay admitted in a {field_kind} field, got: {error}");
    }
}

// ---------------------------------------------------------------------------
// managed://
// ---------------------------------------------------------------------------

#[test]
fn managed_fragment_must_select_the_field_kind() {
    let cases = [
        (
            "managed://certificates/edge-cert#cert",
            CA,
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://edge-cert#cert",
            CA,
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://edge-cert#chain",
            CA,
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://crls/edge-crl#crl",
            CA,
            "fragment selects crl material, but this field expects ca_bundle material",
        ),
        (
            "managed://ca-bundles/edge-ca#ca",
            CERT,
            "fragment selects ca_bundle material, but this field expects cert material",
        ),
        (
            "managed://certificates/edge-cert#key",
            CERT,
            "fragment selects key material, but this field expects cert material",
        ),
        (
            "managed://certificates/edge-cert#cert",
            KEY,
            "fragment selects cert material, but this field expects key material",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn managed_collection_must_hold_the_field_kind() {
    let cases = [
        (
            "managed://certificates/edge-ca",
            CA,
            "collection `certificates` holds certificate records, which cannot supply \
             ca_bundle material",
        ),
        (
            "managed://certificates/edge-ca#ca",
            CA,
            "collection `certificates` holds certificate records, which cannot supply \
             ca_bundle material",
        ),
        (
            "managed://crls/edge-ca",
            CA,
            "collection `crls` holds crl records, which cannot supply ca_bundle material",
        ),
        (
            "managed://ca-bundles/edge-cert",
            CERT,
            "collection `ca-bundles` holds ca_bundle records, which cannot supply cert material",
        ),
        (
            "managed://ca-bundles/edge-cert",
            KEY,
            "collection `ca-bundles` holds ca_bundle records, which cannot supply key material",
        ),
        ("managed://trust/edge-ca", CA, "collection must be one of"),
        (
            "managed://tls/ca-bundles/edge-ca",
            CA,
            "collection must be one of",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn managed_kind_option_must_name_the_field_kind() {
    let cases = [
        (
            "managed://edge-cert?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://ca-bundles/edge-ca?kind=certificate",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://ca-bundles/edge-ca?kind=ca",
            CERT,
            "`kind` option selects ca_bundle material, but this field expects cert material",
        ),
        (
            "managed://ca-bundles/edge-ca?kind=trust-anchor",
            CA,
            "`kind` option is not a recognized material kind",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn managed_compatible_references_stay_admitted() {
    for value in [
        "managed://ca-bundles/edge-ca",
        "managed://edge-ca",
        "managed://ca-bundles/edge-ca#ca",
        "managed://ca-bundles/edge-ca#ca-bundle",
        "managed://ca-bundles/edge-ca#ca_bundle",
        "managed://ca-bundles/edge-ca?kind=ca-bundle",
    ] {
        assert_admitted(value, CA);
    }
    for value in [
        "managed://certificates/edge-cert",
        "managed://certificates/edge-cert#cert",
        "managed://certificates/edge-cert#certificate",
        "managed://certificates/edge-cert#chain",
        "managed://edge-cert#cert",
    ] {
        assert_admitted(value, CERT);
    }
    for value in [
        "managed://certificates/edge-cert",
        "managed://certificates/edge-cert#key",
        "managed://edge-cert#private-key",
    ] {
        assert_admitted(value, KEY);
    }
    assert_admitted("managed://crls/edge-crl#crl", MaterialKind::Crl);
}

// ---------------------------------------------------------------------------
// acme://
// ---------------------------------------------------------------------------

#[test]
fn acme_selectors_must_agree_with_the_field_kind() {
    let cases = [
        (
            "acme://certificates/edge-cert#cert",
            CA,
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
        (
            "acme://edge-cert#key",
            CERT,
            "fragment selects key material, but this field expects cert material",
        ),
        (
            "acme://certificates/edge-cert#cert",
            KEY,
            "fragment selects cert material, but this field expects key material",
        ),
        (
            "acme://ca-bundles/edge-cert",
            CERT,
            "collection must be `certificates`",
        ),
        (
            "acme://certificates/edge-cert?kind=key",
            CERT,
            "`kind` option selects key material, but this field expects cert material",
        ),
        (
            "acme://certificates/edge-cert?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn acme_compatible_references_stay_admitted() {
    for value in [
        "acme://certificates/edge-cert",
        "acme://certificates/edge-cert#cert",
        "acme://edge-cert#chain",
    ] {
        assert_admitted(value, CERT);
    }
    for value in [
        "acme://certificates/edge-cert",
        "acme://certificates/edge-cert#key",
        "acme://edge-cert#private-key",
    ] {
        assert_admitted(value, KEY);
    }
}

// ---------------------------------------------------------------------------
// k8s://
// ---------------------------------------------------------------------------

#[test]
fn k8s_data_key_must_name_the_field_kind() {
    let cases = [
        (
            "k8s://edge/backend#tls.crt",
            CA,
            "Kubernetes Secret data key selects cert material, but this field expects \
             ca_bundle material",
        ),
        (
            "k8s://edge/backend?key=tls.crt",
            CA,
            "Kubernetes Secret data key selects cert material, but this field expects \
             ca_bundle material",
        ),
        (
            "k8s://edge/backend#cert",
            CA,
            "Kubernetes Secret data key selects cert material, but this field expects \
             ca_bundle material",
        ),
        (
            "k8s://edge/frontend#tls.key",
            CERT,
            "Kubernetes Secret data key selects key material, but this field expects \
             cert material",
        ),
        (
            "k8s://edge/frontend#ca.crt",
            CERT,
            "Kubernetes Secret data key selects ca_bundle material, but this field expects \
             cert material",
        ),
        (
            "k8s://edge/frontend#ca.crt",
            KEY,
            "Kubernetes Secret data key selects ca_bundle material, but this field expects \
             key material",
        ),
        (
            "k8s://edge/backend?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
        (
            "k8s://edge/backend#ca.crt?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn k8s_compatible_and_opaque_data_keys_stay_admitted() {
    for value in [
        "k8s://edge/backend",
        "k8s://edge/backend#ca.crt",
        "k8s://edge/backend?key=ca.crt",
        "k8s://edge/backend#ca.crt?sha256=abc",
        "k8s://edge/backend#custom-ca.pem",
        "k8s://edge/backend?kind=ca-bundle&key=custom.pem",
    ] {
        assert_admitted(value, CA);
    }
    for value in ["k8s://edge/frontend", "k8s://edge/frontend#tls.crt"] {
        assert_admitted(value, CERT);
    }
    for value in ["k8s://edge/frontend", "k8s://edge/frontend#tls.key"] {
        assert_admitted(value, KEY);
    }
}

// ---------------------------------------------------------------------------
// Secret providers and file:// (no build feature needed: nothing is fetched)
// ---------------------------------------------------------------------------

#[test]
fn provider_and_file_selectors_must_agree_with_the_field_kind() {
    let cases = [
        (
            "vault://secret/data/edge#cert",
            CA,
            "secret field selects cert material, but this field expects ca_bundle material",
        ),
        (
            "aws://edge-tls#key",
            CERT,
            "secret field selects key material, but this field expects cert material",
        ),
        (
            "vault://secret/data/edge?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
        (
            "gcp://projects/p/secrets/edge-ca/versions/latest?kind=key",
            CA,
            "`kind` option selects key material, but this field expects ca_bundle material",
        ),
        (
            "file:///etc/ferrum/ca.pem?kind=cert",
            CA,
            "`kind` option selects cert material, but this field expects ca_bundle material",
        ),
    ];
    for (value, kind, reason) in cases {
        assert_rejected(value, kind, reason);
    }
}

#[test]
fn provider_file_path_and_inline_sources_stay_admitted() {
    for value in [
        "vault://secret/data/edge#ca",
        "vault://secret/data/edge#pem",
        "aws://edge-ca",
        "file:///etc/ferrum/ca.pem",
        "file:///etc/ferrum/ca.pem?kind=ca",
        "/etc/ferrum/ca.pem",
        "system://",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ] {
        assert_admitted(value, CA);
    }
    assert_admitted("vault://secret/data/edge#cert?kind=cert", CERT);
}

#[test]
fn a_caller_without_a_field_kind_lets_the_reference_decide() {
    for value in [
        "managed://certificates/edge-cert#cert",
        "acme://certificates/edge-cert#key",
        "k8s://edge/frontend#tls.crt",
        "vault://secret/data/edge#cert?kind=cert",
    ] {
        assert_admitted(value, MaterialKind::Unknown);
    }
}

// ---------------------------------------------------------------------------
// Enforcement points
// ---------------------------------------------------------------------------

/// Every load runs the check before resolving anything, so neither a store, a
/// Kubernetes API, nor a file is consulted for an incompatible reference.
#[test]
fn loads_reject_incompatible_selectors_before_resolving_the_source() {
    for value in [
        "managed://certificates/edge-cert#cert",
        "managed://certificates/edge-ca",
        "acme://certificates/edge-cert#cert",
        "k8s://edge/backend#tls.crt",
        "file:///nonexistent/ferrum-5959/ca.pem?kind=cert",
    ] {
        let error = load_material_blocking(&CertSource::parse(value, CA), CA)
            .expect_err("an incompatible CA reference must not load");
        assert!(
            matches!(error, MaterialError::InvalidSource { .. }),
            "{value:?} must fail as an invalid source, got: {error:?}"
        );
        assert!(
            error.to_string().contains("ca_bundle material"),
            "{value:?} must name the expected kind, got: {error}"
        );
    }
}

fn https_proxy(ca: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": "p5959",
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "backend_tls_server_ca_cert_path": ca,
    }))
    .expect("proxy fixture")
}

fn tls_upstream(ca: &str) -> Upstream {
    serde_json::from_value(json!({
        "id": "u5959",
        "targets": [{ "host": "backend.example.com", "port": 443 }],
        "backend_tls_server_ca_cert_path": ca,
    }))
    .expect("upstream fixture")
}

#[track_caller]
fn assert_one_field_error(errors: &[String], field: &str, reason: &str) {
    let matching: Vec<&String> = errors.iter().filter(|e| e.contains(field)).collect();
    assert_eq!(
        matching.len(),
        1,
        "one incompatible reference must be reported once for `{field}`: {errors:?}"
    );
    assert!(
        matching[0].contains(reason),
        "`{field}` error must explain the kind mismatch ({reason:?}), got: {}",
        matching[0]
    );
}

#[test]
fn proxy_and_upstream_admission_reject_a_certificate_selected_for_a_ca_field() {
    let cases = [
        (
            "k8s://edge/backend#tls.crt",
            "data key selects cert material, but this field expects ca_bundle material",
        ),
        (
            "managed://certificates/edge-cert#cert",
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
        (
            "acme://certificates/edge-cert#cert",
            "fragment selects cert material, but this field expects ca_bundle material",
        ),
    ];
    for (value, reason) in cases {
        let proxy_errors = https_proxy(value).validate_fields().unwrap_err();
        assert_one_field_error(&proxy_errors, "backend_tls_server_ca_cert_path", reason);
        let upstream_errors = tls_upstream(value).validate_fields().unwrap_err();
        assert_one_field_error(&upstream_errors, "backend_tls_server_ca_cert_path", reason);
    }
}

#[test]
fn gateway_frontend_cert_and_key_reject_swapped_selectors() {
    let gateway = GatewayConfig {
        frontend_tls_cert_path: Some("k8s://edge/gateway-cert#tls.key".to_string()),
        frontend_tls_key_path: Some("k8s://edge/gateway-cert#tls.crt".to_string()),
        ..GatewayConfig::default()
    };
    let errors = gateway.validate_all_fields(30).unwrap_err();
    assert_one_field_error(
        &errors,
        "`frontend_tls_cert_path`",
        "data key selects key material, but this field expects cert material",
    );
    assert_one_field_error(
        &errors,
        "`frontend_tls_key_path`",
        "data key selects cert material, but this field expects key material",
    );
}

#[test]
fn env_tls_settings_reject_incompatible_selectors_at_validation() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            (
                "FERRUM_DP_GRPC_TLS_CA_CERT_SOURCE",
                "managed://certificates/edge-cert#cert",
            ),
        ],
        || {
            let error = EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap_err();
            let reason =
                "fragment selects cert material, but this field expects ca_bundle material";
            assert!(
                error.contains("FERRUM_DP_GRPC_TLS_CA_CERT_PATH") && error.contains(reason),
                "DP gRPC CA setting must reject a certificate fragment, got: {error}"
            );
        },
    );

    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            (
                "FERRUM_DP_GRPC_TLS_CA_CERT_SOURCE",
                "managed://ca-bundles/edge-ca#ca",
            ),
        ],
        || {
            let env = EnvConfig::from_env_with_conf(&ConfFile::default())
                .expect("a matching CA fragment stays admitted");
            assert_eq!(
                env.dp_grpc_tls_ca_cert_path.as_deref(),
                Some("managed://ca-bundles/edge-ca#ca")
            );
        },
    );
}
