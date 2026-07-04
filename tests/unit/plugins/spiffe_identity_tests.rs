use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, spiffe_id_to_san};
use ferrum_edge::plugins::mesh::spiffe_identity::SpiffeIdentity;
use ferrum_edge::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, RequestContext,
    StreamConnectionContext, priority,
};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, KeyPair, SanType};
use serde_json::json;
use std::sync::Arc;

fn build_cert(spiffe_uri: Option<&str>, dns: Option<&str>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    if let Some(uri) = spiffe_uri {
        let id = SpiffeId::new(uri).unwrap();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).unwrap());
    }
    if let Some(dns_name) = dns {
        params.subject_alt_names.push(SanType::DnsName(
            rcgen::string::Ia5String::try_from(dns_name.to_string()).unwrap(),
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn build_cert_with_uri_sans(uris: &[&str]) -> Vec<u8> {
    let mut params = CertificateParams::default();
    for uri in uris {
        params.subject_alt_names.push(SanType::URI(
            Ia5String::try_from((*uri).to_string()).unwrap(),
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn empty_stream_ctx(cert_der: Option<Vec<u8>>) -> StreamConnectionContext {
    StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        direct_client_ip: "127.0.0.1".to_string(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("tcp".to_string()),
        listen_port: 5432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ConsumerIndex::new(&[] as &[Consumer])),
        identified_consumer: None,
        authenticated_identity: None,
        auth_method: None,
        metadata: None,
        tls_client_cert_der: cert_der.map(Arc::new),
        tls_client_cert_chain_der: None,
        sni_hostname: None,
        mesh_direction: None,
        node_waypoint_policy_scope: None,
        first_bytes: None,
        first_bytes_kind: None,
    }
}

#[test]
fn test_spiffe_identity_trait_contract() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "spiffe_identity");
    assert_eq!(plugin.priority(), priority::SPIFFE_IDENTITY);
    assert_eq!(
        plugin.supported_protocols(),
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_spiffe_identity_rejects_config_fields() {
    let err = SpiffeIdentity::new(&json!({"unexpected": true}))
        .err()
        .expect("unknown config must be rejected");
    assert!(err.contains("no configuration fields are supported"));
}

#[tokio::test]
async fn test_http_request_extracts_spiffe_id() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/api/sa/default"), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some("spiffe://prod.example.com/ns/api/sa/default")
    );
}

#[tokio::test]
async fn test_http_request_ignores_non_spiffe_cert() {
    let cert_der = build_cert(None, Some("client.example.com"));
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_ignores_invalid_der() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(vec![0, 1, 2, 3]));

    plugin.on_request_received(&mut ctx).await;

    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_rejects_duplicate_spiffe_uri_sans() {
    let cert_der = build_cert_with_uri_sans(&[
        "spiffe://prod.example.com/ns/api/sa/default",
        "spiffe://prod.example.com/ns/admin/sa/default",
    ]);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    let result = plugin.on_request_received(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("invalid SPIFFE identity"));
        }
        other => panic!("expected duplicate SPIFFE URI SANs to reject, got {other:?}"),
    }
    assert!(ctx.peer_spiffe_id.is_none());
}

#[tokio::test]
async fn test_http_request_preserves_existing_spiffe_id() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/new/sa/default"), None);
    let existing = SpiffeId::new("spiffe://prod.example.com/ns/existing/sa/default").unwrap();
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.peer_spiffe_id = Some(existing);
    ctx.tls_client_cert_der = Some(Arc::new(cert_der));

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str),
        Some("spiffe://prod.example.com/ns/existing/sa/default")
    );
}

#[tokio::test]
async fn test_stream_connect_extracts_spiffe_metadata() {
    let cert_der = build_cert(Some("spiffe://prod.example.com/ns/tcp/sa/default"), None);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    plugin.on_stream_connect(&mut ctx).await;

    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|metadata| metadata.get("peer_spiffe_id"))
            .map(String::as_str),
        Some("spiffe://prod.example.com/ns/tcp/sa/default")
    );
}

#[tokio::test]
async fn test_stream_connect_rejects_duplicate_spiffe_uri_sans() {
    let cert_der = build_cert_with_uri_sans(&[
        "spiffe://prod.example.com/ns/tcp/sa/default",
        "spiffe://prod.example.com/ns/admin/sa/default",
    ]);
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(Some(cert_der));

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(ctx.metadata.is_none());
}

#[tokio::test]
async fn test_stream_connect_without_cert_is_noop() {
    let plugin = SpiffeIdentity::new(&json!({})).unwrap();
    let mut ctx = empty_stream_ctx(None);

    plugin.on_stream_connect(&mut ctx).await;

    assert!(ctx.metadata.is_none());
}
