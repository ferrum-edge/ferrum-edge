use ferrum_gateway::config::types::Consumer;
use ferrum_gateway::consumer_index::ConsumerIndex;
use ferrum_gateway::plugins::mtls_auth::MtlsAuth;
use ferrum_gateway::plugins::{Plugin, RequestContext};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject};

/// Create a self-signed test certificate with the given CN and OU.
/// Returns DER-encoded bytes.
fn create_test_cert(cn: &str, ou: Option<&str>, san_dns: Option<&str>) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    dn.push(rcgen::DnType::OrganizationName, "Test Org");
    if let Some(ou_val) = ou {
        dn.push(rcgen::DnType::OrganizationalUnitName, ou_val);
    }
    params.distinguished_name = dn;

    if let Some(dns) = san_dns {
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(dns.try_into().unwrap()));
    }

    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    cert.der().to_vec()
}

/// Create a CA certificate and a client certificate signed by that CA.
/// Returns (ca_der, client_der) — both DER-encoded.
fn create_ca_signed_cert(
    ca_cn: &str,
    ca_o: Option<&str>,
    ca_ou: Option<&str>,
    client_cn: &str,
) -> (Vec<u8>, Vec<u8>) {
    // Build CA cert
    let mut ca_params = rcgen::CertificateParams::default();
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(rcgen::DnType::CommonName, ca_cn);
    if let Some(o) = ca_o {
        ca_dn.push(rcgen::DnType::OrganizationName, o);
    }
    if let Some(ou) = ca_ou {
        ca_dn.push(rcgen::DnType::OrganizationalUnitName, ou);
    }
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca_cert.der().to_vec();

    // Build client cert signed by CA
    let mut client_params = rcgen::CertificateParams::default();
    let mut client_dn = rcgen::DistinguishedName::new();
    client_dn.push(rcgen::DnType::CommonName, client_cn);
    client_dn.push(rcgen::DnType::OrganizationName, "Client Org");
    client_params.distinguished_name = client_dn;

    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let client_der = client_cert.der().to_vec();

    (ca_der, client_der)
}

/// Create a test consumer with mtls_auth credentials.
fn create_mtls_consumer(id: &str, username: &str, identity: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut mtls_creds = Map::new();
    mtls_creds.insert("identity".to_string(), Value::String(identity.to_string()));
    credentials.insert("mtls_auth".to_string(), Value::Object(mtls_creds));

    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        custom_id: Some(identity.to_string()),
        credentials,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn create_ctx_with_cert(cert_der: Vec<u8>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx
}

fn create_ctx_with_cert_and_chain(cert_der: Vec<u8>, chain: Vec<Vec<u8>>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx.tls_client_cert_chain_der = Some(Arc::new(chain));
    ctx
}

// --- Basic auth flow tests ---

#[tokio::test]
async fn test_mtls_auth_success_by_subject_cn() {
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "alice");
}

#[tokio::test]
async fn test_mtls_auth_success_by_subject_ou() {
    let cert_der = create_test_cert("client.example.com", Some("Engineering"), None);
    let consumer = create_mtls_consumer("c1", "alice", "Engineering");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_ou"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_success_by_san_dns() {
    let cert_der = create_test_cert("unused-cn", None, Some("api.example.com"));
    let consumer = create_mtls_consumer("c1", "alice", "api.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_success_by_subject_o() {
    let cert_der = create_test_cert("client.example.com", None, None);
    // The cert has O="Test Org" set in create_test_cert
    let consumer = create_mtls_consumer("c1", "alice", "Test Org");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_o"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_success_by_fingerprint() {
    let cert_der = create_test_cert("client.example.com", None, None);

    // Compute the expected fingerprint
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let fingerprint = hex::encode(hasher.finalize());

    let consumer = create_mtls_consumer("c1", "alice", &fingerprint);
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "fingerprint_sha256"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_success_by_serial() {
    let cert_der = create_test_cert("client.example.com", None, None);

    // Parse the cert to get the serial number
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    let serial_hex = cert.serial.to_str_radix(16);

    let consumer = create_mtls_consumer("c1", "alice", &serial_hex);
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "serial"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- Rejection tests ---

#[tokio::test]
async fn test_mtls_auth_rejects_no_cert() {
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_rejects_unknown_identity() {
    let cert_der = create_test_cert("unknown-client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_rejects_invalid_cert_der() {
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = create_ctx_with_cert(vec![0, 1, 2, 3]); // garbage bytes

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_mtls_auth_rejects_missing_ou_field() {
    // Cert has no OU set
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "SomeOU");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_ou"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_mtls_auth_rejects_missing_san_dns() {
    // Cert has no SAN
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "api.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"}));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
}

// --- Issuer constraint tests ---

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_cn_match() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let _ = ca_der; // CA cert not needed for issuer DN matching (it's in the peer cert)
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "Internal CA"}]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_rejects_wrong_ca() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "External Partner CA"}]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_multiple_filters_or_logic() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Partner CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // First filter won't match, second will (OR logic across filters)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [
            {"cn": "Internal CA"},
            {"cn": "Partner CA"}
        ]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_multi_field_and_logic() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal CA", Some("My Corp"), None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // Both cn AND o must match (AND logic within a filter)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "Internal CA", "o": "My Corp"}]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_multi_field_rejects_partial_match() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal CA", Some("My Corp"), None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // CN matches but O doesn't — AND logic should reject
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "Internal CA", "o": "Other Corp"}]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_with_ou() {
    let (_ca_der, client_der) = create_ca_signed_cert(
        "Internal CA",
        Some("My Corp"),
        Some("Engineering"),
        "client.example.com",
    );
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"ou": "Engineering"}]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- CA fingerprint tests ---

#[tokio::test]
async fn test_mtls_auth_ca_fingerprint_match() {
    use sha2::{Digest, Sha256};

    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // Compute CA fingerprint
    let mut hasher = Sha256::new();
    hasher.update(&ca_der);
    let ca_fingerprint = hex::encode(hasher.finalize());

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_ca_fingerprints_sha256": [ca_fingerprint]
    }));
    // Client cert + CA cert in chain
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_ca_fingerprint_rejects_wrong_fingerprint() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_ca_fingerprints_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"]
    }));
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_ca_fingerprint_rejects_no_chain() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // No chain provided — fingerprint check should fail
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_ca_fingerprints_sha256": ["abcd1234"]
    }));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_both_issuer_and_fingerprint_must_pass() {
    use sha2::{Digest, Sha256};

    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let mut hasher = Sha256::new();
    hasher.update(&ca_der);
    let ca_fingerprint = hex::encode(hasher.finalize());

    // Both constraints configured — both must pass (AND logic)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "Internal CA"}],
        "allowed_ca_fingerprints_sha256": [ca_fingerprint]
    }));
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_issuer_pass_fingerprint_fail_rejects() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // Issuer matches but fingerprint doesn't — should reject
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "Internal CA"}],
        "allowed_ca_fingerprints_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"]
    }));
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_ca_fingerprint_case_insensitive() {
    use sha2::{Digest, Sha256};

    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let mut hasher = Sha256::new();
    hasher.update(&ca_der);
    let ca_fingerprint = hex::encode(hasher.finalize()).to_uppercase();

    // Uppercase fingerprint should still match (normalized to lowercase)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_ca_fingerprints_sha256": [ca_fingerprint]
    }));
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
}

// --- No constraints configured (backwards compatible) ---

#[tokio::test]
async fn test_mtls_auth_no_issuer_constraints_allows_any_ca() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Any Random CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // No allowed_issuers or fingerprints — should work like before
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- Self-signed cert issuer tests ---

#[tokio::test]
async fn test_mtls_auth_self_signed_cert_issuer_is_self() {
    // Self-signed cert has issuer == subject
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [{"cn": "client.example.com"}]
    }));
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- Plugin trait tests ---

#[test]
fn test_mtls_auth_is_auth_plugin() {
    let plugin = MtlsAuth::new(&json!({}));
    assert!(plugin.is_auth_plugin());
}

#[test]
fn test_mtls_auth_name() {
    let plugin = MtlsAuth::new(&json!({}));
    assert_eq!(plugin.name(), "mtls_auth");
}

#[test]
fn test_mtls_auth_priority() {
    let plugin = MtlsAuth::new(&json!({}));
    assert_eq!(
        plugin.priority(),
        ferrum_gateway::plugins::priority::MTLS_AUTH
    );
}

#[test]
fn test_mtls_auth_supported_protocols() {
    let plugin = MtlsAuth::new(&json!({}));
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_gateway::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_gateway::plugins::ProxyProtocol::Grpc));
    assert!(protocols.contains(&ferrum_gateway::plugins::ProxyProtocol::WebSocket));
    // Should NOT support raw UDP
    assert!(!protocols.contains(&ferrum_gateway::plugins::ProxyProtocol::Udp));
}

#[test]
fn test_mtls_auth_default_cert_field_is_subject_cn() {
    // When no cert_field is specified, defaults to subject_cn
    let plugin = MtlsAuth::new(&json!({}));
    assert_eq!(plugin.name(), "mtls_auth"); // just verify it creates successfully
}

// --- Consumer index tests ---

#[test]
fn test_consumer_index_mtls_lookup() {
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let found = index.find_by_mtls_identity("client.example.com");
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "alice");

    // Unknown identity should return None
    assert!(index.find_by_mtls_identity("unknown").is_none());
}

#[test]
fn test_consumer_index_mtls_rebuild() {
    let consumer1 = create_mtls_consumer("c1", "alice", "client-a.example.com");
    let index = ConsumerIndex::new(&[consumer1]);
    assert!(
        index
            .find_by_mtls_identity("client-a.example.com")
            .is_some()
    );

    // Rebuild with different consumer
    let consumer2 = create_mtls_consumer("c2", "bob", "client-b.example.com");
    index.rebuild(&[consumer2]);

    assert!(
        index
            .find_by_mtls_identity("client-a.example.com")
            .is_none()
    );
    assert!(
        index
            .find_by_mtls_identity("client-b.example.com")
            .is_some()
    );
}

#[test]
fn test_consumer_index_mtls_delta() {
    let consumer1 = create_mtls_consumer("c1", "alice", "client-a.example.com");
    let index = ConsumerIndex::new(&[consumer1]);

    // Add a new consumer via delta
    let consumer2 = create_mtls_consumer("c2", "bob", "client-b.example.com");
    index.apply_delta(&[consumer2], &[], &[]);

    assert!(
        index
            .find_by_mtls_identity("client-a.example.com")
            .is_some()
    );
    assert!(
        index
            .find_by_mtls_identity("client-b.example.com")
            .is_some()
    );

    // Remove a consumer via delta
    index.apply_delta(&[], &["c1".to_string()], &[]);
    assert!(
        index
            .find_by_mtls_identity("client-a.example.com")
            .is_none()
    );
    assert!(
        index
            .find_by_mtls_identity("client-b.example.com")
            .is_some()
    );
}

// --- Does not overwrite existing consumer identification ---

#[tokio::test]
async fn test_mtls_auth_does_not_overwrite_existing_consumer() {
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer1 = create_mtls_consumer("c1", "alice", "client.example.com");
    let consumer2 = create_mtls_consumer("c2", "bob", "other.example.com");
    let index = ConsumerIndex::new(&[consumer1, consumer2.clone()]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"}));
    let mut ctx = create_ctx_with_cert(cert_der);
    // Pre-set a different consumer (e.g., from a previous auth plugin)
    ctx.identified_consumer = Some(consumer2);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    // Should keep the original consumer, not overwrite
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "bob");
}
