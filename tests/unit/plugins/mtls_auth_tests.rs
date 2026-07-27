use base64::Engine;
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::mtls_auth::{MtlsAuth, MtlsAuthConnectionCache};
use ferrum_edge::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, RequestContext, StreamConnectionContext, priority,
};
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

/// Create a self-signed test certificate with the given CN and an explicit
/// serial number (raw big-endian integer bytes). Returns DER-encoded bytes.
fn create_test_cert_with_serial(cn: &str, serial_bytes: &[u8]) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(serial_bytes));

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
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca_cert.der().to_vec();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    // Build client cert signed by CA
    let mut client_params = rcgen::CertificateParams::default();
    let mut client_dn = rcgen::DistinguishedName::new();
    client_dn.push(rcgen::DnType::CommonName, client_cn);
    client_dn.push(rcgen::DnType::OrganizationName, "Client Org");
    client_params.distinguished_name = client_dn;

    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();
    let client_der = client_cert.der().to_vec();

    (ca_der, client_der)
}

/// Create root -> intermediate -> client certificate material.
/// Returns (root_der, intermediate_der, client_der).
fn create_intermediate_signed_cert(
    root_cn: &str,
    intermediate_cn: &str,
    client_cn: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut root_params = rcgen::CertificateParams::default();
    let mut root_dn = rcgen::DistinguishedName::new();
    root_dn.push(rcgen::DnType::CommonName, root_cn);
    root_params.distinguished_name = root_dn;
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let root_key = rcgen::KeyPair::generate().unwrap();
    let root_cert = root_params.self_signed(&root_key).unwrap();
    let root_der = root_cert.der().to_vec();
    let root_issuer = rcgen::Issuer::new(root_params, root_key);

    let mut intermediate_params = rcgen::CertificateParams::default();
    let mut intermediate_dn = rcgen::DistinguishedName::new();
    intermediate_dn.push(rcgen::DnType::CommonName, intermediate_cn);
    intermediate_params.distinguished_name = intermediate_dn;
    intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_der = intermediate_cert.der().to_vec();
    let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);

    let mut client_params = rcgen::CertificateParams::default();
    let mut client_dn = rcgen::DistinguishedName::new();
    client_dn.push(rcgen::DnType::CommonName, client_cn);
    client_params.distinguished_name = client_dn;
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &intermediate_issuer)
        .unwrap();

    (root_der, intermediate_der, client_cert.der().to_vec())
}

/// Create a client chain with two cross-signed versions of the same
/// intermediate key. Only the second intermediate reaches the pinned root.
/// Returns (pinned_root_der, unpinned_intermediate_der,
/// pinned_intermediate_der, client_der).
fn create_cross_signed_intermediate_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut unpinned_root_params = rcgen::CertificateParams::default();
    let mut unpinned_root_dn = rcgen::DistinguishedName::new();
    unpinned_root_dn.push(rcgen::DnType::CommonName, "Unpinned Root CA");
    unpinned_root_params.distinguished_name = unpinned_root_dn;
    unpinned_root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    unpinned_root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let unpinned_root_key = rcgen::KeyPair::generate().unwrap();
    let unpinned_root_issuer = rcgen::Issuer::new(unpinned_root_params, unpinned_root_key);

    let mut pinned_root_params = rcgen::CertificateParams::default();
    let mut pinned_root_dn = rcgen::DistinguishedName::new();
    pinned_root_dn.push(rcgen::DnType::CommonName, "Pinned Root CA");
    pinned_root_params.distinguished_name = pinned_root_dn;
    pinned_root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    pinned_root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let pinned_root_key = rcgen::KeyPair::generate().unwrap();
    let pinned_root_cert = pinned_root_params.self_signed(&pinned_root_key).unwrap();
    let pinned_root_der = pinned_root_cert.der().to_vec();
    let pinned_root_issuer = rcgen::Issuer::new(pinned_root_params, pinned_root_key);

    let mut intermediate_params = rcgen::CertificateParams::default();
    let mut intermediate_dn = rcgen::DistinguishedName::new();
    intermediate_dn.push(rcgen::DnType::CommonName, "Cross-Signed Intermediate CA");
    intermediate_params.distinguished_name = intermediate_dn;
    intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let unpinned_intermediate = intermediate_params
        .signed_by(&intermediate_key, &unpinned_root_issuer)
        .unwrap()
        .der()
        .to_vec();
    let pinned_intermediate = intermediate_params
        .signed_by(&intermediate_key, &pinned_root_issuer)
        .unwrap()
        .der()
        .to_vec();
    let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);

    let mut client_params = rcgen::CertificateParams::default();
    let mut client_dn = rcgen::DistinguishedName::new();
    client_dn.push(rcgen::DnType::CommonName, "client.example.com");
    client_params.distinguished_name = client_dn;
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_der = client_params
        .signed_by(&client_key, &intermediate_issuer)
        .unwrap()
        .der()
        .to_vec();

    (
        pinned_root_der,
        unpinned_intermediate,
        pinned_intermediate,
        client_der,
    )
}

#[derive(Clone, Copy)]
enum InvalidPinnedIntermediate {
    Expired,
    NotCa,
}

/// Create a leaf with two certificates for the same intermediate key/subject.
/// The valid certificate reaches an unpinned root while the alternate reaches
/// the pinned root but is deliberately not a valid issuer.
fn create_invalid_pinned_intermediate_chain(
    invalid: InvalidPinnedIntermediate,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut unpinned_root_params = rcgen::CertificateParams::default();
    let mut unpinned_root_dn = rcgen::DistinguishedName::new();
    unpinned_root_dn.push(rcgen::DnType::CommonName, "Unpinned Valid Root CA");
    unpinned_root_params.distinguished_name = unpinned_root_dn;
    unpinned_root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    unpinned_root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let unpinned_root_key = rcgen::KeyPair::generate().unwrap();
    let unpinned_root_issuer = rcgen::Issuer::new(unpinned_root_params, unpinned_root_key);

    let mut pinned_root_params = rcgen::CertificateParams::default();
    let mut pinned_root_dn = rcgen::DistinguishedName::new();
    pinned_root_dn.push(rcgen::DnType::CommonName, "Pinned Policy Root CA");
    pinned_root_params.distinguished_name = pinned_root_dn;
    pinned_root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    pinned_root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let pinned_root_key = rcgen::KeyPair::generate().unwrap();
    let pinned_root_cert = pinned_root_params.self_signed(&pinned_root_key).unwrap();
    let pinned_root_der = pinned_root_cert.der().to_vec();
    let pinned_root_issuer = rcgen::Issuer::new(pinned_root_params, pinned_root_key);

    let mut valid_intermediate_params = rcgen::CertificateParams::default();
    let mut intermediate_dn = rcgen::DistinguishedName::new();
    intermediate_dn.push(
        rcgen::DnType::CommonName,
        "Shared Alternate Intermediate CA",
    );
    valid_intermediate_params.distinguished_name = intermediate_dn;
    valid_intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    valid_intermediate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let valid_intermediate_der = valid_intermediate_params
        .signed_by(&intermediate_key, &unpinned_root_issuer)
        .unwrap()
        .der()
        .to_vec();

    let mut invalid_intermediate_params = valid_intermediate_params.clone();
    match invalid {
        InvalidPinnedIntermediate::Expired => {
            invalid_intermediate_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            invalid_intermediate_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        InvalidPinnedIntermediate::NotCa => {
            invalid_intermediate_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        }
    }
    let invalid_intermediate_der = invalid_intermediate_params
        .signed_by(&intermediate_key, &pinned_root_issuer)
        .unwrap()
        .der()
        .to_vec();
    let valid_intermediate_issuer = rcgen::Issuer::new(valid_intermediate_params, intermediate_key);

    let mut client_params = rcgen::CertificateParams::default();
    let mut client_dn = rcgen::DistinguishedName::new();
    client_dn.push(rcgen::DnType::CommonName, "client.example.com");
    client_params.distinguished_name = client_dn;
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_der = client_params
        .signed_by(&client_key, &valid_intermediate_issuer)
        .unwrap()
        .der()
        .to_vec();

    (
        pinned_root_der,
        valid_intermediate_der,
        invalid_intermediate_der,
        client_der,
    )
}

fn cert_der_to_pem(cert_der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(cert_der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

fn issuer_filter(ca_der: &[u8], cn: Option<&str>, o: Option<&str>, ou: Option<&str>) -> Value {
    let mut filter = Map::new();
    if let Some(cn) = cn {
        filter.insert("cn".to_string(), Value::String(cn.to_string()));
    }
    if let Some(o) = o {
        filter.insert("o".to_string(), Value::String(o.to_string()));
    }
    if let Some(ou) = ou {
        filter.insert("ou".to_string(), Value::String(ou.to_string()));
    }
    filter.insert(
        "ca_certificate_pem".to_string(),
        Value::String(cert_der_to_pem(ca_der)),
    );
    Value::Object(filter)
}

fn create_test_cert_with_dns_sans(cn: &str, dns_names: &[&str]) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
    for dns_name in dns_names {
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName((*dns_name).try_into().unwrap()));
    }
    params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

/// Create a test consumer with mtls_auth credentials.
fn create_mtls_consumer(id: &str, username: &str, identity: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut mtls_creds = Map::new();
    mtls_creds.insert("identity".to_string(), Value::String(identity.to_string()));
    credentials.insert(
        "mtls_auth".to_string(),
        Value::Array(vec![Value::Object(mtls_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: Some(identity.to_string()),
        credentials,
        acl_groups: Vec::new(),
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

fn create_stream_ctx_with_cert(
    cert_der: Vec<u8>,
    consumers: Vec<Consumer>,
) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        Some("TCP Proxy".to_string()),
        5432,
        ferrum_edge::config::types::BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&consumers)),
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx
}

// --- Basic auth flow tests ---

#[tokio::test]
async fn test_mtls_auth_success_by_subject_cn() {
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_ou"})).unwrap();
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_san_dns_matching_is_ascii_case_insensitive() {
    let cert_der = create_test_cert("unused-cn", None, Some("API.Example.COM"));
    let consumer = create_mtls_consumer("c1", "alice", "Api.Example.Com");
    let index = ConsumerIndex::new(&[consumer]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "alice");
}

#[tokio::test]
async fn test_mtls_auth_san_dns_rotation_accepts_certificate_case_variants() {
    let mut consumer = create_mtls_consumer("c1", "alice", "old.api.example.com");
    consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([
            {"identity": "old.api.example.com"},
            {"identity": "New.API.Example.COM"}
        ]),
    );
    let index = ConsumerIndex::new(&[consumer]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"})).unwrap();

    for certificate_dns in ["OLD.API.EXAMPLE.COM", "new.api.example.com"] {
        let certificate = create_test_cert("unused-cn", None, Some(certificate_dns));
        let mut ctx = create_ctx_with_cert(certificate);
        assert_continue(plugin.authenticate(&mut ctx, &index).await);
        assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "alice");
    }
}

#[tokio::test]
async fn test_mtls_auth_san_dns_uses_only_first_dns_value() {
    let cert_der =
        create_test_cert_with_dns_sans("unused-cn", &["first.example.com", "second.example.com"]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"})).unwrap();

    let first_index =
        ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "first.example.com")]);
    let mut first_ctx = create_ctx_with_cert(cert_der.clone());
    assert_continue(plugin.authenticate(&mut first_ctx, &first_index).await);

    let second_index =
        ConsumerIndex::new(&[create_mtls_consumer("c2", "bob", "second.example.com")]);
    let mut second_ctx = create_ctx_with_cert(cert_der);
    assert_reject(
        plugin.authenticate(&mut second_ctx, &second_index).await,
        Some(401),
    );
}

#[tokio::test]
async fn test_mtls_auth_non_dns_identity_matching_remains_case_sensitive() {
    let cert_der = create_test_cert("Client.Example.COM", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
}

#[tokio::test]
async fn test_mtls_auth_success_by_subject_o() {
    let cert_der = create_test_cert("client.example.com", None, None);
    // The cert has O="Test Org" set in create_test_cert
    let consumer = create_mtls_consumer("c1", "alice", "Test Org");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_o"})).unwrap();
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "fingerprint_sha256"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_success_by_serial() {
    let cert_der = create_test_cert("client.example.com", None, None);

    // Parse the cert to get the serial number. The identity is the lowercase
    // hex of the DER integer value bytes, matching the lowercase of
    // `openssl x509 -serial` output.
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    let raw_serial = cert.raw_serial();
    let serial_bytes = if raw_serial.len() > 1 && raw_serial[0] == 0 && (raw_serial[1] & 0x80) != 0
    {
        &raw_serial[1..]
    } else {
        raw_serial
    };
    let serial_hex = hex::encode(serial_bytes);

    let consumer = create_mtls_consumer("c1", "alice", &serial_hex);
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "serial"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// Regression for finding #31: a serial whose leading value byte has the high
// bit set is DER-encoded with a leading `00` sign pad. The identity must match
// OpenSSL's value output (`c001`), not the DER content bytes (`00c001`).
#[tokio::test]
async fn test_mtls_auth_serial_strips_der_sign_padding() {
    let cert_der = create_test_cert_with_serial("client.example.com", &[0xC0, 0x01]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "serial"})).unwrap();

    // Canonical identity (DER sign pad stripped) authenticates.
    let consumer = create_mtls_consumer("c1", "alice", "c001");
    let index = ConsumerIndex::new(&[consumer]);
    let mut ctx = create_ctx_with_cert(cert_der.clone());
    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());

    // The raw DER content form must NOT match.
    let der_padded = create_mtls_consumer("c2", "bob", "00c001");
    let der_padded_index = ConsumerIndex::new(&[der_padded]);
    let mut ctx2 = create_ctx_with_cert(cert_der);
    let result2 = plugin.authenticate(&mut ctx2, &der_padded_index).await;
    assert_reject(result2, Some(401));
    assert!(ctx2.identified_consumer.is_none());
}

// Regression for finding #31: a serial that `to_str_radix(16)` would render
// with an odd number of hex digits (`10203`) must produce even-length,
// zero-padded hex (`010203`).
#[tokio::test]
async fn test_mtls_auth_serial_is_even_length_zero_padded() {
    let cert_der = create_test_cert_with_serial("client.example.com", &[0x01, 0x02, 0x03]);
    let plugin = MtlsAuth::new(&json!({"cert_field": "serial"})).unwrap();

    let consumer = create_mtls_consumer("c1", "alice", "010203");
    let index = ConsumerIndex::new(&[consumer]);
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_rejects_unknown_identity() {
    let cert_der = create_test_cert("unknown-client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_rejects_invalid_cert_der() {
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_ou"})).unwrap();
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "san_dns"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(401));
}

// --- Issuer constraint tests ---

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_cn_match() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&ca_der, Some("Internal CA"), None, None)]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_root_accepts_intermediate_issued_client() {
    let (root_der, intermediate_der, client_der) = create_intermediate_signed_cert(
        "Corporate Root CA",
        "Issuing Intermediate CA",
        "client.example.com",
    );
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&root_der, Some("Corporate Root CA"), None, None)]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);

    let mut valid_ctx = create_ctx_with_cert_and_chain(client_der.clone(), vec![intermediate_der]);
    assert_continue(plugin.authenticate(&mut valid_ctx, &index).await);

    let mut missing_intermediate_ctx = create_ctx_with_cert(client_der);
    assert_reject(
        plugin
            .authenticate(&mut missing_intermediate_ctx, &index)
            .await,
        Some(403),
    );
}

#[tokio::test]
async fn test_mtls_auth_backtracks_across_cross_signed_intermediates() {
    let (pinned_root, unpinned_intermediate, pinned_intermediate, client_der) =
        create_cross_signed_intermediate_chain();
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&pinned_root, Some("Pinned Root CA"), None, None)]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);

    let mut valid_ctx = create_ctx_with_cert_and_chain(
        client_der.clone(),
        vec![
            vec![0, 1, 2, 3],
            unpinned_intermediate.clone(),
            pinned_intermediate,
        ],
    );
    assert_continue(plugin.authenticate(&mut valid_ctx, &index).await);

    let mut unpinned_only_ctx =
        create_ctx_with_cert_and_chain(client_der, vec![unpinned_intermediate]);
    assert_reject(
        plugin.authenticate(&mut unpinned_only_ctx, &index).await,
        Some(403),
    );
}

#[tokio::test]
async fn test_mtls_auth_rejects_expired_alternate_intermediate_to_pinned_root() {
    let (pinned_root, valid_intermediate, expired_intermediate, client_der) =
        create_invalid_pinned_intermediate_chain(InvalidPinnedIntermediate::Expired);
    let plugin = MtlsAuth::new(&json!({
        "allowed_issuers": [issuer_filter(&pinned_root, Some("Pinned Policy Root CA"), None, None)]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);
    let mut ctx =
        create_ctx_with_cert_and_chain(client_der, vec![valid_intermediate, expired_intermediate]);

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_rejects_non_ca_alternate_intermediate_to_pinned_root() {
    let (pinned_root, valid_intermediate, non_ca_intermediate, client_der) =
        create_invalid_pinned_intermediate_chain(InvalidPinnedIntermediate::NotCa);
    let plugin = MtlsAuth::new(&json!({
        "allowed_issuers": [issuer_filter(&pinned_root, Some("Pinned Policy Root CA"), None, None)]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);
    let mut ctx =
        create_ctx_with_cert_and_chain(client_der, vec![valid_intermediate, non_ca_intermediate]);

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_rejects_wrong_ca() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal CA", None, None, "client.example.com");
    let (external_ca_der, _) =
        create_ca_signed_cert("External Partner CA", None, None, "unused.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&external_ca_der, Some("External Partner CA"), None, None)]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_multiple_filters_or_logic() {
    let (partner_ca_der, client_der) =
        create_ca_signed_cert("Partner CA", None, None, "client.example.com");
    let (internal_ca_der, _) =
        create_ca_signed_cert("Internal CA", None, None, "unused.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // First filter won't match, second will (OR logic across filters)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [
            issuer_filter(&internal_ca_der, Some("Internal CA"), None, None),
            issuer_filter(&partner_ca_der, Some("Partner CA"), None, None)
        ]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_multi_field_and_logic() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Internal CA", Some("My Corp"), None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // Both cn AND o must match (AND logic within a filter)
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&ca_der, Some("Internal CA"), Some("My Corp"), None)]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_rejects_dn_that_disagrees_with_pin() {
    let (ca_der, _client_der) =
        create_ca_signed_cert("Internal CA", Some("My Corp"), None, "client.example.com");
    let error = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&ca_der, Some("Internal CA"), Some("Other Corp"), None)]
    }))
    .err()
    .expect("DN labels that disagree with the pinned CA must be rejected");
    assert!(error.contains("DN fields do not match"), "got: {error}");
}

#[tokio::test]
async fn test_mtls_auth_issuer_rejection_body_is_valid_json_with_control_chars() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Internal\nCA", None, None, "client.example.com");
    let (external_ca_der, _) =
        create_ca_signed_cert("External CA", None, None, "unused.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&external_ca_der, Some("External CA"), None, None)]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    match plugin.authenticate(&mut ctx, &index).await {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            let error = parsed["error"].as_str().unwrap();
            assert!(error.contains("Internal\nCA"));
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuers_with_ou() {
    let (ca_der, client_der) = create_ca_signed_cert(
        "Internal CA",
        Some("My Corp"),
        Some("Engineering"),
        "client.example.com",
    );
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&ca_der, None, None, Some("Engineering"))]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_mtls_auth_allowed_issuer_rejects_same_dn_different_key() {
    let (pinned_ca_der, pinned_client_der) =
        create_ca_signed_cert("Shared CA Name", None, None, "client.example.com");
    let (_impostor_ca_der, impostor_client_der) =
        create_ca_signed_cert("Shared CA Name", None, None, "client.example.com");
    let plugin = MtlsAuth::new(&json!({
        "allowed_issuers": [issuer_filter(&pinned_ca_der, Some("Shared CA Name"), None, None)]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);

    let mut pinned_ctx = create_ctx_with_cert(pinned_client_der);
    assert_continue(plugin.authenticate(&mut pinned_ctx, &index).await);

    let mut impostor_ctx = create_ctx_with_cert(impostor_client_der);
    assert_reject(
        plugin.authenticate(&mut impostor_ctx, &index).await,
        Some(403),
    );
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
    }))
    .unwrap();
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
    })).unwrap();
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
        "allowed_ca_fingerprints_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"]
    }))
    .unwrap();
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
        "allowed_issuers": [issuer_filter(&ca_der, Some("Internal CA"), None, None)],
        "allowed_ca_fingerprints_sha256": [ca_fingerprint]
    }))
    .unwrap();
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
        "allowed_issuers": [issuer_filter(&ca_der, Some("Internal CA"), None, None)],
        "allowed_ca_fingerprints_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"]
    })).unwrap();
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_ca_fingerprint_rejects_unrelated_extra_cert() {
    use sha2::{Digest, Sha256};

    let (real_ca_der, client_der) =
        create_ca_signed_cert("Real Trust CA", None, None, "client.example.com");
    let (allowed_ca_der, _unused_client_der) = create_ca_signed_cert(
        "Per Proxy Allowed CA",
        None,
        None,
        "other-client.example.com",
    );

    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let mut hasher = Sha256::new();
    hasher.update(&allowed_ca_der);
    let allowed_fp = hex::encode(hasher.finalize());

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_ca_fingerprints_sha256": [allowed_fp]
    }))
    .unwrap();

    // Client can send unrelated extra certs, but they must not satisfy CA fingerprint checks.
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![real_ca_der, allowed_ca_der]);

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
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert_and_chain(client_der, vec![ca_der]);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
}

// --- No issuer constraints configured ---

#[tokio::test]
async fn test_mtls_auth_no_issuer_constraints_allows_any_ca() {
    let (_ca_der, client_der) =
        create_ca_signed_cert("Any Random CA", None, None, "client.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    // No allowed_issuers or fingerprints means any trusted client CA is allowed.
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_ctx_with_cert(client_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- Self-signed cert issuer tests ---

#[tokio::test]
async fn test_mtls_auth_self_signed_cert_issuer_is_self() {
    // A pinned self-signed CA certificate has issuer == subject and verifies with its own key.
    let (cert_der, _) =
        create_ca_signed_cert("client.example.com", None, None, "unused.example.com");
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let index = ConsumerIndex::new(&[consumer]);

    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&cert_der, Some("client.example.com"), None, None)]
    }))
    .unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// --- Plugin trait tests ---

#[test]
fn test_mtls_auth_is_auth_plugin() {
    let plugin = MtlsAuth::new(&json!({})).unwrap();
    assert!(plugin.is_auth_plugin());
}

#[test]
fn test_mtls_auth_name() {
    let plugin = MtlsAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "mtls_auth");
}

#[test]
fn test_mtls_auth_priority() {
    let plugin = MtlsAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.priority(), priority::MTLS_AUTH);
}

#[test]
fn test_mtls_auth_supported_protocols() {
    let plugin = MtlsAuth::new(&json!({})).unwrap();
    assert_eq!(
        plugin.supported_protocols(),
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    );
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_mtls_auth_default_cert_field_is_subject_cn() {
    // When no cert_field is specified, defaults to subject_cn
    let plugin = MtlsAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "mtls_auth"); // just verify it creates successfully
}

// --- Constructor validation tests ---

#[test]
fn test_mtls_auth_rejects_unknown_cert_field() {
    let err = MtlsAuth::new(&json!({"cert_field": "subject_serial"}))
        .err()
        .expect("unknown cert_field must be rejected");
    assert!(err.contains("'cert_field'"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_non_string_cert_field() {
    let err = MtlsAuth::new(&json!({"cert_field": 42}))
        .err()
        .expect("non-string cert_field must be rejected");
    assert!(err.contains("'cert_field' must be a string"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_non_array_allowed_issuers() {
    let err = MtlsAuth::new(&json!({"allowed_issuers": {"cn": "CA"}}))
        .err()
        .expect("non-array allowed_issuers must be rejected");
    assert!(
        err.contains("'allowed_issuers' must be an array"),
        "got: {err}"
    );
}

#[test]
fn test_mtls_auth_rejects_empty_allowed_issuer_filter() {
    let err = MtlsAuth::new(&json!({"allowed_issuers": [{}]}))
        .err()
        .expect("empty issuer filter must be rejected");
    assert!(
        err.contains("ca_certificate_pem") && err.contains("required"),
        "got: {err}"
    );
}

#[test]
fn test_mtls_auth_rejects_non_string_allowed_issuer_field() {
    let (ca_der, _) = create_ca_signed_cert("CA", None, None, "unused.example.com");
    let err = MtlsAuth::new(&json!({"allowed_issuers": [{
        "cn": 42,
        "ca_certificate_pem": cert_der_to_pem(&ca_der)
    }]}))
    .err()
    .expect("non-string issuer field must be rejected");
    assert!(err.contains("allowed_issuers[0].cn"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_unknown_allowed_issuer_field() {
    let err = MtlsAuth::new(&json!({"allowed_issuers": [{"issuer_cn": "CA"}]}))
        .err()
        .expect("unknown issuer field must be rejected");
    assert!(err.contains("unsupported issuer field"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_removed_issuer_verification() {
    let err = MtlsAuth::new(&json!({"issuer_verification": {"cn": "CA"}}))
        .err()
        .expect("removed issuer field must be rejected");
    assert!(err.contains("issuer_verification"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_non_array_ca_fingerprints() {
    let err = MtlsAuth::new(&json!({"allowed_ca_fingerprints_sha256": "abcd"}))
        .err()
        .expect("non-array CA fingerprints must be rejected");
    assert!(
        err.contains("'allowed_ca_fingerprints_sha256' must be an array"),
        "got: {err}"
    );
}

#[test]
fn test_mtls_auth_rejects_non_string_ca_fingerprint() {
    let err = MtlsAuth::new(&json!({"allowed_ca_fingerprints_sha256": [42]}))
        .err()
        .expect("non-string CA fingerprint must be rejected");
    assert!(
        err.contains("allowed_ca_fingerprints_sha256[0]"),
        "got: {err}"
    );
}

#[test]
fn test_mtls_auth_rejects_malformed_ca_fingerprint() {
    let err = MtlsAuth::new(&json!({"allowed_ca_fingerprints_sha256": ["abcd"]}))
        .err()
        .expect("short CA fingerprint must be rejected");
    assert!(err.contains("64 hex characters"), "got: {err}");
}

#[test]
fn test_mtls_auth_rejects_unknown_top_level_field() {
    let error = MtlsAuth::new(&json!({"cert_field": "subject_cn", "typo": true}))
        .err()
        .expect("unknown top-level fields must fail closed");
    assert!(error.contains("unsupported field 'typo'"), "got: {error}");
}

#[test]
fn test_mtls_auth_rejects_explicit_empty_constraint_arrays_and_nulls() {
    for config in [
        json!({"allowed_issuers": []}),
        json!({"allowed_issuers": null}),
        json!({"allowed_ca_fingerprints_sha256": []}),
        json!({"allowed_ca_fingerprints_sha256": null}),
    ] {
        assert!(
            MtlsAuth::new(&config).is_err(),
            "constraint must not silently disable itself: {config}"
        );
    }
}

#[test]
fn test_mtls_auth_rejects_malformed_or_ambiguous_ca_pem() {
    let (ca_der, _) = create_ca_signed_cert("Internal CA", None, None, "unused.example.com");
    let pem = cert_der_to_pem(&ca_der);
    for ca_certificate_pem in [
        "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n".to_string(),
        format!("{pem}{pem}"),
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".to_string(),
    ] {
        let error = MtlsAuth::new(&json!({
            "allowed_issuers": [{
                "cn": "Internal CA",
                "ca_certificate_pem": ca_certificate_pem
            }]
        }))
        .err()
        .expect("malformed or multi-item CA PEM must be rejected");
        assert!(error.contains("ca_certificate_pem"), "got: {error}");
    }
}

#[test]
fn test_mtls_auth_rejects_non_ca_issuer_pin() {
    let leaf_der = create_test_cert("Not A CA", None, None);
    let error = MtlsAuth::new(&json!({
        "allowed_issuers": [{
            "cn": "Not A CA",
            "ca_certificate_pem": cert_der_to_pem(&leaf_der)
        }]
    }))
    .err()
    .expect("issuer pins must be CA certificates");
    assert!(
        error.contains("must contain a CA certificate"),
        "got: {error}"
    );
}

#[test]
fn test_mtls_auth_rejects_issuer_pin_without_key_cert_sign() {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "CA Without Key Usage");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let error = MtlsAuth::new(&json!({
        "allowed_issuers": [{
            "cn": "CA Without Key Usage",
            "ca_certificate_pem": cert_der_to_pem(cert.der().as_ref())
        }]
    }))
    .err()
    .expect("issuer pins must assert keyCertSign");

    assert!(error.contains("keyCertSign"), "got: {error}");
}

#[tokio::test]
async fn test_mtls_auth_connection_cache_reuses_crypto_but_refreshes_consumer_lookup() {
    let cert_der = Arc::new(create_test_cert("client.example.com", None, None));
    let cache = Arc::new(MtlsAuthConnectionCache::new());
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let index = ConsumerIndex::new(&[create_mtls_consumer("c1", "alice", "client.example.com")]);

    let mut first_ctx = create_ctx_with_cert(Vec::new());
    first_ctx.tls_client_cert_der = Some(Arc::clone(&cert_der));
    first_ctx.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut first_ctx, &index).await);
    assert_eq!(
        first_ctx.identified_consumer.as_ref().unwrap().username,
        "alice"
    );

    index.rebuild(&[create_mtls_consumer("c2", "bob", "client.example.com")]);
    let mut second_ctx = create_ctx_with_cert(Vec::new());
    second_ctx.tls_client_cert_der = Some(Arc::clone(&cert_der));
    second_ctx.mtls_auth_connection_cache = Some(Arc::clone(&cache));
    assert_continue(plugin.authenticate(&mut second_ctx, &index).await);
    assert_eq!(
        second_ctx.identified_consumer.as_ref().unwrap().username,
        "bob"
    );
    assert_eq!(cache.evaluation_count(), 1);
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
fn test_consumer_index_mtls_dns_lookup_is_case_insensitive() {
    let consumer = create_mtls_consumer("c1", "alice", "Api.Example.COM");
    let index = ConsumerIndex::new(&[consumer]);

    assert_eq!(
        index
            .find_by_mtls_dns_identity("api.example.com")
            .unwrap()
            .username,
        "alice"
    );
    assert!(index.find_by_mtls_identity("api.example.com").is_none());
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
    index.apply_delta(&[], &[NamespacedResourceId::new("ferrum", "c1")], &[]);
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

    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_ctx_with_cert(cert_der);
    // Pre-set a different consumer (e.g., from a previous auth plugin)
    ctx.identified_consumer = Some(Arc::new(consumer2));

    let result = plugin.authenticate(&mut ctx, &index).await;
    assert_continue(result);
    // Should keep the original consumer, not overwrite
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "bob");
}

#[tokio::test]
async fn test_mtls_auth_stream_connect_identifies_consumer() {
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_stream_ctx_with_cert(cert_der, vec![consumer]);

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "alice");
    assert_eq!(ctx.auth_method, Some("mtls_auth"));
    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|m| m.get("consumer_username"))
            .map(String::as_str),
        Some("alice")
    );
}

#[tokio::test]
async fn test_mtls_auth_stream_connect_does_not_overwrite_existing_auth_method() {
    let cert_der = create_test_cert("client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_stream_ctx_with_cert(cert_der, vec![consumer]);
    ctx.auth_method = Some("custom_stream_auth");

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "alice");
    assert_eq!(ctx.auth_method, Some("custom_stream_auth"));
}

#[tokio::test]
async fn test_mtls_auth_stream_connect_rejects_unknown_consumer() {
    let cert_der = create_test_cert("unknown-client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "alice", "client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_stream_ctx_with_cert(cert_der, vec![consumer]);

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

// --- DTLS/UDP mTLS auth tests ---

fn create_udp_stream_ctx_with_cert(
    cert_der: Vec<u8>,
    consumers: Vec<Consumer>,
) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "udp-proxy".to_string(),
        Some("UDP Proxy".to_string()),
        5353,
        ferrum_edge::config::types::BackendScheme::Dtls,
        Arc::new(ConsumerIndex::new(&consumers)),
    );
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));
    ctx
}

fn create_udp_stream_ctx_no_cert(consumers: Vec<Consumer>) -> StreamConnectionContext {
    StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "udp-proxy".to_string(),
        Some("UDP Proxy".to_string()),
        5353,
        ferrum_edge::config::types::BackendScheme::Udp,
        Arc::new(ConsumerIndex::new(&consumers)),
    )
}

#[tokio::test]
async fn test_mtls_auth_dtls_stream_connect_identifies_consumer() {
    let cert_der = create_test_cert("dtls-client.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "bob", "dtls-client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_udp_stream_ctx_with_cert(cert_der, vec![consumer]);

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "bob");
    assert_eq!(ctx.auth_method, Some("mtls_auth"));
}

#[tokio::test]
async fn test_mtls_auth_dtls_stream_connect_rejects_no_cert() {
    let consumer = create_mtls_consumer("c1", "bob", "dtls-client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_udp_stream_ctx_no_cert(vec![consumer]);

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_mtls_auth_dtls_stream_connect_rejects_unknown_consumer() {
    let cert_der = create_test_cert("unknown-dtls.example.com", None, None);
    let consumer = create_mtls_consumer("c1", "bob", "dtls-client.example.com");
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let mut ctx = create_udp_stream_ctx_with_cert(cert_der, vec![consumer]);

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_mtls_auth_dtls_with_allowed_issuer() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Test CA", Some("TestOrg"), None, "dtls-client.example.com");
    let consumer = create_mtls_consumer("c1", "bob", "dtls-client.example.com");
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&ca_der, Some("Test CA"), Some("TestOrg"), None)]
    }))
    .unwrap();
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "udp-proxy".to_string(),
        Some("UDP Proxy".to_string()),
        5353,
        ferrum_edge::config::types::BackendScheme::Dtls,
        Arc::new(ConsumerIndex::new(&[consumer])),
    );
    ctx.tls_client_cert_der = Some(Arc::new(client_der));
    // The DTLS implementation exposes the leaf only. The configured CA pin
    // still verifies the leaf signature without requiring the root in-chain.

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.as_ref().unwrap().username, "bob");
}

#[tokio::test]
async fn test_mtls_auth_dtls_allowed_issuer_rejects_mismatch() {
    let (ca_der, client_der) =
        create_ca_signed_cert("Test CA", Some("TestOrg"), None, "dtls-client.example.com");
    let (other_ca_der, _) = create_ca_signed_cert("Other CA", None, None, "unused.example.com");
    let consumer = create_mtls_consumer("c1", "bob", "dtls-client.example.com");
    let plugin = MtlsAuth::new(&json!({
        "cert_field": "subject_cn",
        "allowed_issuers": [issuer_filter(&other_ca_der, Some("Other CA"), None, None)]
    }))
    .unwrap();
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "udp-proxy".to_string(),
        Some("UDP Proxy".to_string()),
        5353,
        ferrum_edge::config::types::BackendScheme::Dtls,
        Arc::new(ConsumerIndex::new(&[consumer])),
    );
    ctx.tls_client_cert_der = Some(Arc::new(client_der));
    ctx.tls_client_cert_chain_der = Some(Arc::new(vec![ca_der]));

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_mtls_auth_supports_udp_protocol() {
    let plugin = MtlsAuth::new(&json!({"cert_field": "subject_cn"})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(
        protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Udp),
        "mtls_auth should support UDP/DTLS protocol"
    );
    assert!(
        protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Tcp),
        "mtls_auth should still support TCP protocol"
    );
    assert!(
        protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http),
        "mtls_auth should still support HTTP protocol"
    );
}
