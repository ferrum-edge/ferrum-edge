//! Tests for oauth2_auth plugin

use ferrum_gateway::ConsumerIndex;
use ferrum_gateway::plugins::{Plugin, PluginHttpClient, RequestContext, oauth2_auth::OAuth2Auth};
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

/// Create a consumer (no oauth2 secret needed — JWKS validates via IdP keys, not shared secrets).
fn create_consumer(username: &str) -> ferrum_gateway::config::types::Consumer {
    use chrono::Utc;

    ferrum_gateway::config::types::Consumer {
        id: format!("{}-id", username),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a consumer with a custom_id (for testing subject → custom_id mapping).
fn create_consumer_with_custom_id(
    username: &str,
    custom_id: &str,
) -> ferrum_gateway::config::types::Consumer {
    use chrono::Utc;

    ferrum_gateway::config::types::Consumer {
        id: format!("{}-id", username),
        username: username.to_string(),
        custom_id: Some(custom_id.to_string()),
        credentials: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create an RS256-signed JWT token using the given RSA private key (PEM).
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

/// Create an RS256-signed JWT without a `kid` header.
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

// ─── Basic Plugin Tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_oauth2_auth_plugin_creation() {
    let plugin = OAuth2Auth::new(&json!({}), default_client());
    assert_eq!(plugin.name(), "oauth2_auth");
}

#[tokio::test]
async fn test_oauth2_auth_creation_with_config() {
    let plugin = OAuth2Auth::new(
        &json!({
            "validation_mode": "jwks",
            "expected_issuer": "https://auth.example.com",
            "expected_audience": "my-api"
        }),
        default_client(),
    );
    assert_eq!(plugin.name(), "oauth2_auth");
    assert_eq!(plugin.jwks_uri(), None);
}

#[tokio::test]
async fn test_oauth2_auth_jwks_uri_config() {
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
        }),
        default_client(),
    );
    assert_eq!(
        plugin.jwks_uri(),
        Some("https://auth.example.com/.well-known/jwks.json")
    );
}

#[tokio::test]
async fn test_oauth2_auth_missing_bearer_token() {
    let plugin = OAuth2Auth::new(
        &json!({"jwks_uri": "https://example.com/jwks"}),
        default_client(),
    );
    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);

    let mut ctx = make_ctx();
    // No authorization header
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_non_bearer_scheme() {
    let plugin = OAuth2Auth::new(
        &json!({"jwks_uri": "https://example.com/jwks"}),
        default_client(),
    );
    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_introspection_mode_no_url() {
    let plugin = OAuth2Auth::new(
        &json!({"validation_mode": "introspection"}),
        default_client(),
    );
    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer some-opaque-token".to_string(),
    );
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_jwks_mode_rejects_without_jwks_uri() {
    // JWKS mode without any jwks_uri or discovery_url should return 500 (misconfigured)
    let plugin = OAuth2Auth::new(&json!({"validation_mode": "jwks"}), default_client());
    let consumer_index = ConsumerIndex::new(&[create_consumer("user")]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(500));
}

// ─── JWKS RS256 Validation (IdP Public Keys) ──────────────────────────

#[tokio::test]
async fn test_oauth2_jwks_validates_rs256_token_from_idp() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({"validation_mode": "jwks", "jwks_uri": jwks_uri}),
        default_client(),
    );
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
}

#[tokio::test]
async fn test_oauth2_jwks_rejects_token_signed_with_wrong_key() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let other_public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public_other.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(other_public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({"validation_mode": "jwks", "jwks_uri": jwks_uri}),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer("idp-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Signed with private key that doesn't match the public key in JWKS
    let token = create_rs256_token(&json!({"sub": "idp-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_jwks_rejects_unknown_subject() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({"validation_mode": "jwks", "jwks_uri": jwks_uri}),
        default_client(),
    );
    plugin.warmup_jwks().await;

    // Consumer index doesn't contain "unknown-user"
    let consumer = create_consumer("real-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "unknown-user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_jwks_validates_with_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "expected_issuer": "https://auth.example.com"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer("user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token with matching issuer
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
async fn test_oauth2_jwks_rejects_wrong_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "expected_issuer": "https://auth.example.com"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer("user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token with wrong issuer
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
async fn test_oauth2_jwks_validates_with_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "expected_audience": "my-api"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer("user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(&json!({"sub": "user", "aud": "my-api"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_oauth2_jwks_token_without_kid_tries_all_keys() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(&json!({"jwks_uri": jwks_uri}), default_client());
    plugin.warmup_jwks().await;

    let consumer = create_consumer("user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token without kid — should still validate by trying all keys
    let token = create_rs256_token_no_kid(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_oauth2_jwks_maps_subject_to_custom_id() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/jwks.json"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
    let plugin = OAuth2Auth::new(&json!({"jwks_uri": jwks_uri}), default_client());
    plugin.warmup_jwks().await;

    // Consumer has custom_id matching the IdP's sub claim
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

// ─── Configurable consumer_claim Tests ──────────────────────────────────

#[tokio::test]
async fn test_oauth2_jwks_consumer_claim_defaults_to_sub() {
    // Without consumer_claim configured, should use "sub" by default
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/jwks", mock_server.uri());
    let plugin = OAuth2Auth::new(&json!({"jwks_uri": jwks_uri}), default_client());
    plugin.warmup_jwks().await;

    let consumer = create_consumer("sub-user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(
        &json!({"sub": "sub-user", "email": "different@example.com"}),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "sub-user");
}

#[tokio::test]
async fn test_oauth2_jwks_consumer_claim_email() {
    // Configure consumer_claim to use "email" instead of "sub"
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/jwks", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "consumer_claim": "email"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    // Consumer's custom_id matches the email claim
    let consumer = create_consumer_with_custom_id("local-user", "jeremy@example.com");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(
        &json!({
            "sub": "auth0|12345",
            "email": "jeremy@example.com",
            "preferred_username": "jjustus"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "local-user");
}

#[tokio::test]
async fn test_oauth2_jwks_consumer_claim_preferred_username() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/jwks", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "consumer_claim": "preferred_username"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    // Consumer's username matches the preferred_username claim
    let consumer = create_consumer("jjustus");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(
        &json!({
            "sub": "some-opaque-id",
            "preferred_username": "jjustus",
            "email": "j@example.com"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "jjustus");
}

#[tokio::test]
async fn test_oauth2_jwks_consumer_claim_custom_field() {
    // Use a completely custom claim like "user_id" from a non-standard IdP
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/jwks", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "consumer_claim": "user_id"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer_with_custom_id("internal-user", "uid-98765");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_rs256_token(
        &json!({
            "sub": "irrelevant-sub",
            "user_id": "uid-98765"
        }),
        private_key_pem,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "internal-user");
}

#[tokio::test]
async fn test_oauth2_jwks_consumer_claim_missing_rejects() {
    // Token doesn't have the configured claim at all — should reject
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

    let mock_server = wiremock::MockServer::start().await;
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem);
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&mock_server)
        .await;

    let jwks_uri = format!("{}/jwks", mock_server.uri());
    let plugin = OAuth2Auth::new(
        &json!({
            "jwks_uri": jwks_uri,
            "consumer_claim": "email"
        }),
        default_client(),
    );
    plugin.warmup_jwks().await;

    let consumer = create_consumer("user");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token has "sub" but not "email"
    let token = create_rs256_token(&json!({"sub": "user"}), private_key_pem);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ─── Warmup Hostnames ──────────────────────────────────────────────────

#[tokio::test]
async fn test_oauth2_warmup_hostnames_includes_all_endpoints() {
    let plugin = OAuth2Auth::new(
        &json!({
            "validation_mode": "introspection",
            "introspection_url": "https://introspect.example.com/oauth/introspect",
            "jwks_uri": "https://jwks.example.com/.well-known/jwks.json",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration"
        }),
        default_client(),
    );

    let hosts = plugin.warmup_hostnames();
    assert!(hosts.contains(&"introspect.example.com".to_string()));
    assert!(hosts.contains(&"jwks.example.com".to_string()));
    assert!(hosts.contains(&"idp.example.com".to_string()));
}

// ─── Test Helpers ──────────────────────────────────────────────────────

/// Build a JWKS JSON response from an RSA public key PEM.
fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pem_str = std::str::from_utf8(public_key_pem).unwrap();
    let der = extract_der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);

    json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-key-1",
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
