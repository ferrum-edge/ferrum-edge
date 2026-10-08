//! Explicit backend TLS refusal (issue #6105).
//!
//! A tenant DestinationRule whose local TLS file this node refuses marks the
//! destination's backend TLS refused (`BackendTlsConfig::tls_refused`). Every
//! builder must refuse before it reads anything else, so the gateway-wide
//! opt-outs and fallbacks — `FERRUM_TLS_NO_VERIFY`, the global
//! `FERRUM_TLS_CA_BUNDLE_PATH`, and the global
//! `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` / `_KEY_PATH` pair — can never stand in
//! for the refused material. The marker must also partition every key that
//! caches a built client, and backend TLS live-reload validation must skip a
//! failing destination instead of stopping at it.

use std::path::PathBuf;

use ferrum_edge::config::types::{BackendTlsConfig, GatewayConfig, Proxy, Upstream};
use ferrum_edge::health_check::build_probe_server_verifier_for_test;
use ferrum_edge::proxy::{BackendTlsValidationInputs, validate_backend_tls_material_for_config};
use ferrum_edge::tls::backend::{
    BackendTlsConfigBuilder, BackendTlsRefusalSurface, TlsError, backend_tls_config_cache_key,
    backend_tls_refusal_count,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use tempfile::TempDir;

/// A real global CA bundle and a real global client certificate/key pair, so a
/// build that is NOT refused succeeds with exactly the same inputs. That is what
/// proves the refused builds below fail because of the marker and nothing else.
struct GlobalTlsMaterial {
    _dir: TempDir,
    ca: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

fn global_tls_material() -> GlobalTlsMaterial {
    let dir = TempDir::new().expect("tempdir");

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let client_cert = CertificateParams::new(vec!["gateway.refusal.test".to_string()])
        .expect("client params")
        .self_signed(&client_key)
        .expect("client cert");

    let ca = dir.path().join("global-ca.pem");
    let client_cert_path = dir.path().join("global-client.pem");
    let client_key_path = dir.path().join("global-client.key");
    std::fs::write(&ca, ca_cert.pem()).expect("write ca");
    std::fs::write(&client_cert_path, client_cert.pem()).expect("write client cert");
    std::fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");

    GlobalTlsMaterial {
        _dir: dir,
        ca,
        client_cert: client_cert_path,
        client_key: client_key_path,
    }
}

fn https_proxy(id: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "name": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "https",
        "backend_host": "backend.refusal.test",
        "backend_port": 443,
    }))
    .expect("proxy fixture")
}

fn refused_proxy(id: &str) -> Proxy {
    let mut proxy = https_proxy(id);
    proxy.resolved_tls = BackendTlsConfig::refused();
    proxy
}

/// The builder as a pool manager drives it with `FERRUM_TLS_NO_VERIFY=true`
/// and the global CA / client pair configured.
fn builder_with_global_opt_outs<'a>(
    proxy: &'a Proxy,
    material: &'a GlobalTlsMaterial,
) -> BackendTlsConfigBuilder<'a> {
    BackendTlsConfigBuilder {
        proxy,
        policy: None,
        global_ca: Some(material.ca.as_path()),
        global_no_verify: true,
        global_client_cert: Some(material.client_cert.as_path()),
        global_client_key: Some(material.client_key.as_path()),
        crls: &[],
    }
}

#[test]
fn refused_destination_errors_under_no_verify_with_a_global_ca_and_client_pair() {
    let material = global_tls_material();

    // Control: the identical global inputs build a client for an ordinary
    // destination, so the global CA and client pair are usable fallbacks.
    let ordinary = https_proxy("ordinary");
    builder_with_global_opt_outs(&ordinary, &material)
        .build_rustls()
        .expect("the global no-verify + CA + client pair builds for an ordinary destination");

    let refused = refused_proxy("refused");
    let before = backend_tls_refusal_count(BackendTlsRefusalSurface::ClientBuild);
    let builder = builder_with_global_opt_outs(&refused, &material);
    assert!(
        matches!(builder.build_rustls(), Err(TlsError::Refused)),
        "a refused destination must not fall back to no-verify or the global CA / client pair"
    );
    assert!(
        matches!(builder.build_rustls_quic(), Err(TlsError::Refused)),
        "the HTTP/3 builder must refuse too"
    );
    assert!(
        matches!(builder.build_rustls_for_reqwest(true), Err(TlsError::Refused)),
        "the reqwest builder must refuse too"
    );
    assert!(builder.build_reqwest().is_err());
    assert!(
        backend_tls_refusal_count(BackendTlsRefusalSurface::ClientBuild) >= before + 3,
        "every refused build is counted"
    );
}

#[test]
fn refused_destination_errors_with_verification_on_and_a_global_ca() {
    let material = global_tls_material();
    let refused = refused_proxy("refused-verify");
    let result = BackendTlsConfigBuilder {
        proxy: &refused,
        policy: None,
        global_ca: Some(material.ca.as_path()),
        global_no_verify: false,
        global_client_cert: Some(material.client_cert.as_path()),
        global_client_key: Some(material.client_key.as_path()),
        crls: &[],
    }
    .build_rustls();
    assert!(matches!(result, Err(TlsError::Refused)));
}

#[test]
fn refusal_error_names_no_material() {
    let rendered = TlsError::Refused.to_string();
    assert!(rendered.contains("refused"), "got: {rendered}");
    assert!(!rendered.contains('/'), "the refusal must not echo a path: {rendered}");
}

#[test]
fn refused_destination_errors_on_the_backend_dtls_builder() {
    let material = global_tls_material();
    let refused = refused_proxy("refused-dtls");
    let crls: ferrum_edge::tls::CrlList = std::sync::Arc::new(Vec::new());
    let before = backend_tls_refusal_count(BackendTlsRefusalSurface::DtlsBuild);
    let result = ferrum_edge::dtls::build_backend_dtls_config(
        &refused,
        "backend.refusal.test",
        true,
        &crls,
        material.ca.to_str(),
        None,
    );
    let error = result
        .err()
        .expect("a refused destination must not get backend DTLS params");
    assert!(
        matches!(error.downcast_ref::<TlsError>(), Some(TlsError::Refused)),
        "DTLS must refuse before generating an ephemeral identity: {error}"
    );
    assert!(backend_tls_refusal_count(BackendTlsRefusalSurface::DtlsBuild) > before);
}

#[test]
fn refused_destination_errors_on_the_health_probe_verifier() {
    let material = global_tls_material();
    let before = backend_tls_refusal_count(BackendTlsRefusalSurface::HealthProbe);
    let refused = BackendTlsConfig::refused();
    let result = build_probe_server_verifier_for_test(&refused, material.ca.to_str(), &[]);
    let error = result
        .err()
        .expect("a refused destination must not get a probe verifier from the global CA");
    assert!(error.contains("refused"), "got: {error}");
    assert!(backend_tls_refusal_count(BackendTlsRefusalSurface::HealthProbe) > before);
}

#[test]
fn refusal_partitions_the_backend_tls_cache_key() {
    // A refused slot keeps no material, so without its own segment it would
    // share a key — and therefore a cached client — with an unconfigured one.
    let global_cert = Some("/etc/ferrum/global-client.pem");
    let global_key = Some("/etc/ferrum/global-client.key");
    let refused = backend_tls_config_cache_key(
        &BackendTlsConfig::refused(),
        global_cert,
        global_key,
        true,
        None,
    );
    let unconfigured = backend_tls_config_cache_key(
        &BackendTlsConfig::default_verify(),
        global_cert,
        global_key,
        true,
        None,
    );
    assert_ne!(refused, unconfigured);
    assert!(refused.contains("|tlsrefused|svidg="), "got: {refused}");
    assert!(
        !unconfigured.contains("tlsrefused"),
        "keys of destinations that are not refused are unchanged"
    );
}

#[test]
fn refusal_reaches_the_resolved_tls_of_every_proxy_on_the_upstream() {
    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "refused-upstream",
        "targets": [{ "host": "backend.refusal.test", "port": 443 }],
    }))
    .expect("upstream fixture");
    assert!(!BackendTlsConfig::from_upstream(&upstream).tls_refused);
    upstream.backend_tls_refused = true;
    assert!(BackendTlsConfig::from_upstream(&upstream).tls_refused);

    // Runtime-only: the marker is never emitted to, or accepted from, config.
    let serialized = serde_json::to_value(&upstream).expect("serialize upstream");
    assert!(serialized.get("backend_tls_refused").is_none());
    let mut with_field = serialized.clone();
    with_field["backend_tls_refused"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<Upstream>(with_field).is_err(),
        "operators cannot set the refusal marker"
    );
}

#[test]
fn live_reload_validation_skips_a_failing_destination_and_validates_the_rest() {
    let material = global_tls_material();
    let missing_ca = material.ca.with_file_name("rotated-away-ca.pem");

    // Order matters: the failing destination comes first, so a validator that
    // stopped at the first failure would never reach the other two.
    let mut broken = https_proxy("broken");
    broken.resolved_tls = BackendTlsConfig {
        server_ca_cert_path: Some(missing_ca.to_string_lossy().into_owned()),
        ..BackendTlsConfig::default_verify()
    };
    let refused = refused_proxy("refused");
    let healthy = https_proxy("healthy");
    let config = GatewayConfig {
        proxies: vec![broken, refused, healthy],
        ..GatewayConfig::default()
    };

    let report = validate_backend_tls_material_for_config(
        &config,
        BackendTlsValidationInputs {
            policy: None,
            global_ca: None,
            global_no_verify: false,
            global_client_cert: None,
            global_client_key: None,
            crls: &[],
        },
    );

    assert_eq!(report.failed, 1, "the broken destination is skipped: {report:?}");
    assert_eq!(report.refused, 1, "the refused destination is skipped: {report:?}");
    assert_eq!(
        report.validated, 1,
        "the destination after the failure is still validated: {report:?}"
    );
}
