//! Metrics-safe TLS inventory scope (issue #2410).
//!
//! `TlsInventory::collect_public_metadata` is what the cached snapshot behind the
//! `/metrics` certificate gauges is built from. It must load public
//! certificate-family material only, and must never materialize a private key,
//! JWKS document, or OCSP response — those are loaded by the full operator
//! inventory alone.

use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::tls::inventory::{TlsInventory, TlsInventoryEntry, TlsInventoryState};

const MISSING_KEY_PATH: &str = "/nonexistent-ferrum-tls/private-key.pem";
const MISSING_CERT_PATH: &str = "/nonexistent-ferrum-tls/certificate.pem";
const MISSING_OCSP_PATH: &str = "/nonexistent-ferrum-tls/ocsp.der";

fn generated_cert_pem() -> String {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.self_signed(&key_pair).expect("self-sign cert").pem()
}

fn entry_of_kind<'a>(inventory: &'a TlsInventory, kind: &str) -> &'a TlsInventoryEntry {
    inventory
        .entries
        .iter()
        .find(|entry| entry.material_kind == kind)
        .unwrap_or_else(|| panic!("inventory has no {kind} entry"))
}

fn env_with_missing_sources() -> EnvConfig {
    EnvConfig {
        frontend_tls_cert_path: Some(MISSING_CERT_PATH.to_string()),
        frontend_tls_key_path: Some(MISSING_KEY_PATH.to_string()),
        frontend_tls_ocsp_response_source: Some(MISSING_OCSP_PATH.to_string()),
        ..EnvConfig::default()
    }
}

#[test]
fn public_metadata_scope_never_reads_private_key_jwks_or_ocsp_sources() {
    let env = env_with_missing_sources();

    let public = TlsInventory::collect_public_metadata(Some(&env), None);

    // Unreadable key/OCSP sources stay `loaded` because the scope never touched
    // them: an unreachable path cannot be observed without reading it. Their
    // health is owned by startup/reload validation instead.
    let key = entry_of_kind(&public, "private_key");
    assert_eq!(
        key.state,
        TlsInventoryState::Loaded,
        "private key source must not be read by the metrics scope: {:?}",
        key.error
    );
    assert!(key.error.is_none(), "unexpected key error: {:?}", key.error);
    assert!(key.fingerprint_sha256.is_none());

    let ocsp = entry_of_kind(&public, "ocsp");
    assert_eq!(
        ocsp.state,
        TlsInventoryState::Loaded,
        "OCSP source must not be read by the metrics scope: {:?}",
        ocsp.error
    );

    // Public certificate material is still loaded, so an unreadable certificate
    // is reported and a readable one yields expiry metadata.
    let cert = entry_of_kind(&public, "certificate");
    assert_eq!(
        cert.state,
        TlsInventoryState::Unavailable,
        "missing certificate source must be reported as unavailable"
    );
}

#[test]
fn full_scope_still_reads_key_and_ocsp_sources() {
    let env = env_with_missing_sources();

    let full = TlsInventory::collect(Some(&env), None);

    assert_eq!(
        entry_of_kind(&full, "private_key").state,
        TlsInventoryState::Unavailable,
        "the operator inventory endpoint still loads key sources"
    );
    assert_eq!(
        entry_of_kind(&full, "ocsp").state,
        TlsInventoryState::Unavailable,
        "the operator inventory endpoint still loads OCSP sources"
    );
    assert_eq!(
        entry_of_kind(&full, "certificate").state,
        TlsInventoryState::Unavailable
    );
}

#[test]
fn public_metadata_scope_populates_certificate_expiry_metadata() {
    let cert_pem = generated_cert_pem();
    let mut config = GatewayConfig::default();
    config.proxies.push(
        serde_json::from_value(serde_json::json!({
            "id": "api",
            "hosts": ["api.example.test"],
            "backend_host": "127.0.0.1",
            "backend_port": 443,
            "backend_tls_client_cert_path": cert_pem,
            "backend_tls_client_key_path": MISSING_KEY_PATH,
        }))
        .expect("proxy"),
    );

    let public = TlsInventory::collect_public_metadata(None, Some(&config));

    let cert = entry_of_kind(&public, "certificate");
    assert_eq!(cert.state, TlsInventoryState::Loaded);
    assert!(
        cert.not_after.is_some(),
        "certificate gauges need not_after from the metrics scope"
    );
    assert!(cert.not_before.is_some());
    assert_eq!(cert.certificate_count, Some(1));

    let key = entry_of_kind(&public, "private_key");
    assert_eq!(key.state, TlsInventoryState::Loaded);
    assert!(
        key.not_after.is_none() && key.fingerprint_sha256.is_none(),
        "key entries carry no certificate metadata and are never fingerprinted"
    );

    // No collected entry may leak material bytes.
    let json = serde_json::to_string(&public).expect("json");
    assert!(!json.contains("BEGIN CERTIFICATE"));
    assert!(!json.contains("PRIVATE KEY"));
}
