//! Tests for jwks_auth plugin

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, RequestContext, jwks_auth::JwksAuth};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn create_consumer(username: &str) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    ferrum_edge::config::types::Consumer {
        id: format!("{}-id", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_consumer_with_custom_id(
    username: &str,
    custom_id: &str,
) -> ferrum_edge::config::types::Consumer {
    use chrono::Utc;
    ferrum_edge::config::types::Consumer {
        id: format!("{}-id", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: Some(custom_id.to_string()),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_rs256_token(claims: &serde_json::Value, private_key_pem: &[u8]) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

#[allow(dead_code)]
fn create_rs256_token_with_kid(
    claims: &serde_json::Value,
    private_key_pem: &[u8],
    kid: &str,
) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

fn create_rs256_token_no_kid(claims: &serde_json::Value, private_key_pem: &[u8]) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let header = Header::new(jsonwebtoken::Algorithm::RS256);
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
    )
    .unwrap()
}

/// Build a JWKS JSON response from an RSA public key PEM.
fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
    build_rsa_jwks_from_pem_with_kid(public_key_pem, "test-key-1")
}

fn build_rsa_jwks_from_pem_with_kid(public_key_pem: &[u8], kid: &str) -> serde_json::Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pem_str = std::str::from_utf8(public_key_pem).unwrap();
    let der = extract_der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);

    json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e)
        }]
    })
}

fn extract_der_from_pem(pem: &str) -> Vec<u8> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(&b64).unwrap()
}

fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_outer_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_bs_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += 1;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_inner_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}

/// Helper: start a wiremock server serving a JWKS endpoint and return (server, jwks_uri).
async fn start_jwks_server(public_key_pem: &[u8]) -> (wiremock::MockServer, String) {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;
    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    (mock_server, jwks_uri)
}

/// Helper to make a single-provider config
fn single_provider_config(jwks_uri: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "jwks_uri": jwks_uri
        }]
    })
}

// ─── Basic Plugin Tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_plugin_creation() {
    let mock_server = wiremock::MockServer::start().await;
    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    assert_eq!(plugin.name(), "jwks_auth");
}

#[tokio::test]
async fn test_jwks_auth_requires_providers_array() {
    let result = JwksAuth::new(&json!({}), default_client());
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("providers"));
}

#[tokio::test]
async fn test_jwks_auth_requires_non_empty_providers() {
    let result = JwksAuth::new(&json!({"providers": []}), default_client());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwks_auth_provider_requires_jwks_or_discovery() {
    let result = JwksAuth::new(
        &json!({"providers": [{"issuer": "https://example.com"}]}),
        default_client(),
    );
    assert!(result.is_err());
    assert!(result.as_ref().err().unwrap().contains("jwks_uri"));
}

#[tokio::test]
async fn test_jwks_auth_missing_bearer_token() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_non_bearer_scheme() {
    let (_server, jwks_uri) = start_jwks_server(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ─── Single Provider JWKS Validation ───────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_validates_rs256_token() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer("idp-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "idp-user");
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("idp-user"));
}

#[tokio::test]
async fn test_jwks_auth_rejects_wrong_key() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let other_public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem");

    let (_server, jwks_uri) = start_jwks_server(other_public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("idp-user")]);
    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_validates_with_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "issuer": "https://auth.example.com"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(
        &json!({"sub": "user", "iss": "https://auth.example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_rejects_wrong_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "issuer": "https://auth.example.com"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(
        &json!({"sub": "user", "iss": "https://evil.example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwks_auth_validates_with_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "audience": "my-api"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token(&json!({"sub": "user", "aud": "my-api"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_token_without_kid_tries_all_keys() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);
    let token = create_rs256_token_no_kid(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Consumer-Optional Flow ────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_continues_without_consumer_in_index() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    // Empty consumer index — no consumers defined at all
    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(&json!({"sub": "external-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // No identified_consumer (not in index), but authenticated_identity is set
    assert!(ctx.identified_consumer.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_jwks_auth_consumer_header_claim_separate_from_identity() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{"jwks_uri": jwks_uri}],
            "consumer_identity_claim": "sub",
            "consumer_header_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({"sub": "user-123", "email": "user@example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-123"));
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("user@example.com")
    );
}

#[tokio::test]
async fn test_jwks_auth_maps_subject_to_custom_id() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer_with_custom_id("local-user", "idp-subject-12345");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "idp-subject-12345"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "local-user");
}

// ─── Scope/Role Claim-Based Authorization ──────────────────────────────

#[tokio::test]
async fn test_jwks_auth_required_scopes_pass() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read:data", "write:data"]
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Space-delimited scope string (OAuth2 standard format)
    let token = create_rs256_token(
        &json!({"sub": "user", "scope": "read:data write:data admin"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_scopes_fail() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read:data", "write:data"]
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Missing write:data scope
    let token = create_rs256_token(
        &json!({"sub": "user", "scope": "read:data"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_jwks_auth_required_scopes_array_format() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read"]
            }],
            "scope_claim": "scp"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Okta-style array format
    let token = create_rs256_token(
        &json!({"sub": "user", "scp": ["read", "write"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_roles_any_match() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin", "editor"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // User has "editor" — one of the required roles (any match)
    let token = create_rs256_token(
        &json!({"sub": "user", "roles": ["editor", "viewer"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_required_roles_no_match() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // User only has "viewer" — doesn't match required "admin"
    let token = create_rs256_token(
        &json!({"sub": "user", "roles": ["viewer"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_jwks_auth_nested_role_claim_keycloak_style() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"],
                "role_claim": "realm_access.roles"
            }]
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Keycloak-style nested roles
    let token = create_rs256_token(
        &json!({
            "sub": "user",
            "realm_access": {
                "roles": ["admin", "user"]
            }
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwks_auth_no_scopes_or_roles_required_allows_all() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;
    let plugin = JwksAuth::new(&single_provider_config(&jwks_uri), default_client()).unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Minimal token — no scopes or roles at all
    let token = create_rs256_token(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Multi-Provider Tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_multi_provider_routes_by_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    // Both providers use the same key for simplicity, but have different issuers
    let server1 = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks1"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server1)
        .await;

    let server2 = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks2"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server2)
        .await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://idp-one.example.com",
                    "jwks_uri": format!("{}/jwks1", server1.uri()),
                    "required_roles": ["admin"]
                },
                {
                    "issuer": "https://idp-two.example.com",
                    "jwks_uri": format!("{}/jwks2", server2.uri()),
                    "required_roles": ["partner"]
                }
            ],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token from IdP 2 with "partner" role — should pass via second provider
    let token = create_rs256_token(
        &json!({
            "sub": "partner-user",
            "iss": "https://idp-two.example.com",
            "roles": ["partner"]
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("partner-user"));
}

#[tokio::test]
async fn test_jwks_auth_multi_provider_wrong_role_rejected() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server)
        .await;

    let jwks_uri = format!("{}/jwks", server.uri());
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://idp.example.com",
                "jwks_uri": jwks_uri,
                "required_roles": ["admin"]
            }],
            "role_claim": "roles"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token has "viewer" but provider requires "admin"
    let token = create_rs256_token(
        &json!({
            "sub": "user",
            "iss": "https://idp.example.com",
            "roles": ["viewer"]
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(403));
}

// ─── Claim Extraction Helpers ──────────────────────────────────────────

#[test]
fn test_extract_claim_values_space_delimited_string() {
    use ferrum_edge::plugins::jwks_auth::extract_claim_values;

    let claims = json!({"scope": "read:data write:data admin"});
    let values = extract_claim_values(&claims, "scope");
    assert_eq!(values, vec!["read:data", "write:data", "admin"]);
}

#[test]
fn test_extract_claim_values_array() {
    use ferrum_edge::plugins::jwks_auth::extract_claim_values;

    let claims = json!({"scp": ["read", "write"]});
    let values = extract_claim_values(&claims, "scp");
    assert_eq!(values, vec!["read", "write"]);
}

#[test]
fn test_extract_claim_values_nested_dot_path() {
    use ferrum_edge::plugins::jwks_auth::extract_claim_values;

    let claims = json!({"realm_access": {"roles": ["admin", "user"]}});
    let values = extract_claim_values(&claims, "realm_access.roles");
    assert_eq!(values, vec!["admin", "user"]);
}

#[test]
fn test_extract_claim_values_missing_path() {
    use ferrum_edge::plugins::jwks_auth::extract_claim_values;

    let claims = json!({"sub": "user"});
    let values = extract_claim_values(&claims, "nonexistent.path");
    assert!(values.is_empty());
}

#[test]
fn test_extract_claim_values_deeply_nested() {
    use ferrum_edge::plugins::jwks_auth::extract_claim_values;

    // Two levels of nesting (Keycloak resource_access style)
    let claims = json!({
        "resource_access": {
            "my_client": {
                "roles": ["superadmin"]
            }
        }
    });
    let values = extract_claim_values(&claims, "resource_access.my_client.roles");
    assert_eq!(values, vec!["superadmin"]);
}

// ─── Per-Provider Claim Overrides ──────────────────────────────────────

#[tokio::test]
async fn test_jwks_auth_per_provider_scope_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global scope_claim is "scope", but provider overrides to "scp"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "required_scopes": ["read"],
                "scope_claim": "scp"
            }],
            "scope_claim": "scope"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token uses "scp" (Okta style) — should work with provider override
    let token = create_rs256_token(
        &json!({"sub": "user", "scp": ["read", "write"]}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// ─── Per-Provider Consumer Claim Overrides ─────────────────────────────

#[tokio::test]
async fn test_jwks_auth_per_provider_consumer_identity_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global consumer_identity_claim is "sub", but provider overrides to "preferred_username"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "consumer_identity_claim": "preferred_username"
            }],
            "consumer_identity_claim": "sub"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer = create_consumer("keycloak-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token has both "sub" and "preferred_username" — provider override picks "preferred_username"
    let token = create_rs256_token(
        &json!({
            "sub": "some-uuid-12345",
            "preferred_username": "keycloak-user"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // Consumer found via "preferred_username", not "sub"
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "keycloak-user");
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("keycloak-user"));
}

#[tokio::test]
async fn test_jwks_auth_per_provider_consumer_header_claim_override() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Global header claim is "email", provider overrides to "upn"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri,
                "consumer_identity_claim": "sub",
                "consumer_header_claim": "upn"
            }],
            "consumer_identity_claim": "sub",
            "consumer_header_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({
            "sub": "user-123",
            "email": "user@google.com",
            "upn": "user@corp.example.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-123"));
    // Header uses per-provider "upn", not global "email"
    assert_eq!(
        ctx.authenticated_identity_header.as_deref(),
        Some("user@corp.example.com")
    );
}

#[tokio::test]
async fn test_jwks_auth_multi_provider_different_identity_claims() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    // Two providers with different JWKS endpoints and different identity claims
    let server1 = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks1"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server1)
        .await;

    let server2 = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks2"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&server2)
        .await;

    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://google.com",
                    "jwks_uri": format!("{}/jwks1", server1.uri()),
                    "consumer_identity_claim": "email",
                    "consumer_header_claim": "email"
                },
                {
                    "issuer": "https://keycloak.internal",
                    "jwks_uri": format!("{}/jwks2", server2.uri()),
                    "consumer_identity_claim": "preferred_username",
                    "consumer_header_claim": "preferred_username"
                }
            ],
            "consumer_identity_claim": "sub"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    // Token from Google — identity should come from "email" claim
    let token_google = create_rs256_token(
        &json!({
            "sub": "google-uid-123",
            "iss": "https://google.com",
            "email": "alice@gmail.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", token_google),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("alice@gmail.com")
    );

    // Token from Keycloak — identity should come from "preferred_username" claim
    let token_kc = create_rs256_token(
        &json!({
            "sub": "kc-uid-456",
            "iss": "https://keycloak.internal",
            "preferred_username": "bob"
        }),
        private_key_pem,
    );

    let mut ctx2 = make_ctx();
    ctx2.headers
        .insert("authorization".to_string(), format!("Bearer {}", token_kc));
    let result = plugin.authenticate(&mut ctx2, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx2.authenticated_identity.as_deref(), Some("bob"));
}

#[tokio::test]
async fn test_jwks_auth_provider_without_override_uses_global() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let (_server, jwks_uri) = start_jwks_server(public_key_pem).await;

    // Provider has no consumer_identity_claim — should fall back to global "email"
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "jwks_uri": jwks_uri
            }],
            "consumer_identity_claim": "email"
        }),
        default_client(),
    )
    .unwrap();
    plugin.warmup_jwks().await;

    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_rs256_token(
        &json!({
            "sub": "user-123",
            "email": "user@example.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    // Falls back to global consumer_identity_claim="email"
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("user@example.com")
    );
}
