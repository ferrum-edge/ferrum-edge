//! Hosted SoftHSM coverage for the PKCS#11 token-key ↔ leaf-certificate proof
//! (issue #2406).
//!
//! Every test here is `#[ignore]` because it needs real token state. CI runs
//! them in the `PKCS#11 SoftHSM Smoke Test` job, which initializes a token with
//! two distinct RSA keys and a certificate that pairs with only one of them.
//!
//! Required environment:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `FERRUM_PKCS11_TEST_CERT_PATH` | PEM leaf certificate for the *matching* token key |
//! | `FERRUM_PKCS11_TEST_KEY_SOURCE` | `pkcs11://` URI selecting the matching token key |
//! | `FERRUM_PKCS11_TEST_MISMATCHED_KEY_SOURCE` | `pkcs11://` URI selecting a different token key |

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::types::Proxy;
use ferrum_edge::tls::TlsPolicy;
use ferrum_edge::tls::backend::BackendTlsConfigBuilder;
use ferrum_edge::tls::source::subscription::WatchedMaterialSource;
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use ferrum_edge::tls::{
    FrontendTlsRebuildFn, FrontendTlsReloadConfig, frontend_tls_slot_with,
    spawn_frontend_tls_reload_task,
};

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run the hosted PKCS#11 tests"))
}

fn matching_key_source() -> String {
    env_var("FERRUM_PKCS11_TEST_KEY_SOURCE")
}

fn mismatched_key_source() -> String {
    env_var("FERRUM_PKCS11_TEST_MISMATCHED_KEY_SOURCE")
}

fn certificate_path() -> String {
    env_var("FERRUM_PKCS11_TEST_CERT_PATH")
}

fn test_tls_policy() -> TlsPolicy {
    TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS13, &rustls::version::TLS12],
        crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        prefer_server_cipher_order: true,
        session_cache_size: 64,
        early_data_max_size: 0,
    }
}

fn load_server_config(key_source: &str) -> Result<Arc<rustls::ServerConfig>, anyhow::Error> {
    let cert_source = CertSource::parse(certificate_path(), MaterialKind::Cert);
    let key_source = CertSource::parse(key_source.to_string(), MaterialKind::Key);
    ferrum_edge::tls::load_tls_config_with_client_auth_from_sources(
        &cert_source,
        &key_source,
        None,
        false,
        &test_tls_policy(),
        30,
        &[],
    )
}

fn backend_proxy(key_source: &str) -> Proxy {
    let json = serde_json::json!({
        "id": "pkcs11-backend",
        "listen_path": "/",
        "backend_scheme": "https",
        "backend_host": "localhost",
        "backend_port": 443,
    });
    let mut proxy: Proxy = serde_json::from_value(json).expect("proxy fixture");
    proxy.resolved_tls.client_cert_path = Some(certificate_path());
    proxy.resolved_tls.client_key_path = Some(key_source.to_string());
    proxy.resolved_tls.verify_server_cert = false;
    proxy
}

fn build_backend_client_config(key_source: &str) -> Result<rustls::ClientConfig, String> {
    let proxy = backend_proxy(key_source);
    BackendTlsConfigBuilder {
        proxy: &proxy,
        policy: None,
        global_ca: None,
        global_no_verify: false,
        global_client_cert: None,
        global_client_key: None,
        crls: &[],
    }
    .build_rustls()
    .map_err(|error| error.to_string())
}

/// A rejection must name the configured source and the selector, and nothing
/// else: no PIN, no token attribute bytes, no signature or challenge material.
fn assert_rejected_without_disclosure(message: &str) {
    assert!(
        message.contains("PKCS#11 TLS key source")
            && (message.contains("does not match the configured leaf certificate")
                || message.contains("not a pair")),
        "expected a certificate-pairing rejection, got: {message}"
    );
    for forbidden in ["challenge", "signature bytes", "modulus", "pin="] {
        assert!(
            !message.to_ascii_lowercase().contains(forbidden),
            "rejection must not disclose '{forbidden}': {message}"
        );
    }
    if let Ok(pin) = std::env::var("FERRUM_PKCS11_PIN") {
        assert!(
            !message.contains(&pin),
            "rejection must not disclose the PIN"
        );
    }
}

#[test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
fn server_tls_accepts_a_token_key_that_matches_the_certificate() {
    load_server_config(&matching_key_source()).expect("matching token key builds a server config");
}

#[test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
fn server_tls_rejects_a_token_key_that_does_not_match_the_certificate() {
    let error = load_server_config(&mismatched_key_source())
        .expect_err("a mismatched token key must not produce a server config");
    assert_rejected_without_disclosure(&format!("{error:#}"));
}

#[test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
fn backend_mtls_accepts_a_token_key_that_matches_the_certificate() {
    build_backend_client_config(&matching_key_source())
        .expect("matching token key builds a backend client config");
}

#[test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
fn backend_mtls_rejects_a_token_key_that_does_not_match_the_certificate() {
    let error = build_backend_client_config(&mismatched_key_source())
        .expect_err("a mismatched token key must not produce a backend client identity");
    assert_rejected_without_disclosure(&error);
}

/// A failed frontend live reload must keep the last-good PKCS#11 identity in
/// the published slot. This drives the real `spawn_frontend_tls_reload_task`
/// path: a watched cert-file change triggers rebuild, the rebuild closure
/// attempts a mismatched PKCS#11 pairing, and the slot must retain the
/// original matching `ServerConfig`.
#[tokio::test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
async fn a_rejected_reload_leaves_the_matching_identity_loadable() {
    use rustls::crypto::ring::default_provider;
    use tokio::sync::watch;

    let _ = default_provider().install_default();

    let published = load_server_config(&matching_key_source()).expect("initial good config");
    let slot = frontend_tls_slot_with(published.clone());
    let (revision_tx, revision_rx) = watch::channel(0u64);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let dir = tempfile::tempdir().expect("tempdir");
    let cert_trigger = dir.path().join("cert.pem");
    let cert_bytes = std::fs::read(certificate_path()).expect("read test certificate");
    std::fs::write(&cert_trigger, &cert_bytes).expect("write trigger cert");

    let completed_rebuilds = Arc::new(AtomicUsize::new(0));
    let completed_for_rebuild = completed_rebuilds.clone();
    let mismatched_key = mismatched_key_source();
    let rebuild: FrontendTlsRebuildFn = Box::new(move || {
        let error = load_server_config(&mismatched_key)
            .expect_err("rotating onto a mismatched key must fail the rebuild");
        assert_rejected_without_disclosure(&format!("{error:#}"));
        completed_for_rebuild.fetch_add(1, Ordering::SeqCst);
        Err(error)
    });

    let task = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            // Unique surface: the force-reload registry is process-global.
            surface: "test_pkcs11_rejected_frontend_reload",
            sources: vec![
                WatchedMaterialSource::new(
                    "cert",
                    CertSource::parse(
                        cert_trigger.to_string_lossy().into_owned(),
                        MaterialKind::Cert,
                    ),
                    MaterialKind::Cert,
                ),
                WatchedMaterialSource::new(
                    "key",
                    CertSource::parse(matching_key_source(), MaterialKind::Key),
                    MaterialKind::Key,
                ),
            ],
            slot: slot.clone(),
            interval: Duration::from_millis(50),
            revision_tx,
            rebuild,
            max_material_bytes:
                ferrum_edge::config::env_config::DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES,
        },
        Some(shutdown_rx),
    );

    tokio::time::sleep(Duration::from_millis(80)).await;
    std::thread::sleep(Duration::from_millis(10));
    let mut rotated = cert_bytes;
    rotated.push(b'\n');
    std::fs::write(&cert_trigger, &rotated).expect("mutate trigger cert");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while completed_rebuilds.load(Ordering::SeqCst) == 0 {
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for rejected frontend TLS rebuild to complete");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        *revision_rx.borrow(),
        0,
        "failed reload must not advance the revision counter"
    );
    let retained = slot.load_full().as_ref().clone().expect("slot intact");
    assert!(
        Arc::ptr_eq(&retained, &published),
        "failed reload must keep the original matching server config in the slot"
    );
    load_server_config(&matching_key_source()).expect("matching identity still loadable");

    task.abort();
}

/// The token key must expose an SPKI that rustls can compare, or prove the
/// pairing by challenge — either way `certified_key_from_uri` returns a
/// certified key only for the matching pair.
#[test]
#[ignore = "requires a configured SoftHSM token; see the PKCS#11 SoftHSM CI job"]
fn certified_key_is_only_produced_for_the_matching_pair() {
    use rustls::pki_types::pem::PemObject;

    let pem = std::fs::read(certificate_path()).expect("read test certificate");
    let cert_chain = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test certificate");

    let matching = CertSource::parse(matching_key_source(), MaterialKind::Key);
    let CertSource::Uri(matching) = matching else {
        panic!("FERRUM_PKCS11_TEST_KEY_SOURCE must be a pkcs11:// URI");
    };
    ferrum_edge::tls::pkcs11::certified_key_from_uri(cert_chain.clone(), &matching)
        .expect("matching token key certifies");

    let mismatched = CertSource::parse(mismatched_key_source(), MaterialKind::Key);
    let CertSource::Uri(mismatched) = mismatched else {
        panic!("FERRUM_PKCS11_TEST_MISMATCHED_KEY_SOURCE must be a pkcs11:// URI");
    };
    let error = ferrum_edge::tls::pkcs11::certified_key_from_uri(cert_chain, &mismatched)
        .expect_err("mismatched token key must not certify");
    assert_rejected_without_disclosure(&format!("{error:#}"));
}
