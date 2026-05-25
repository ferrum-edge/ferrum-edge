use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, RequestContext, oauth2_introspection::Oauth2Introspection, priority,
};
use serde_json::json;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{assert_continue, assert_reject};

fn make_ctx(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

fn config(endpoint: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "introspection_endpoint": endpoint,
            "client_auth": {"method": "none"}
        }]
    })
}

#[test]
fn new_rejects_empty_providers() {
    assert!(
        Oauth2Introspection::new(&json!({"providers": []}), PluginHttpClient::default()).is_err()
    );
}

#[test]
fn new_rejects_none_client_auth_for_remote_endpoint() {
    let err = match Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("remote none auth should reject"),
        Err(err) => err,
    };
    assert!(err.contains("only allowed"));
}

#[test]
fn new_accepts_none_client_auth_for_localhost_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://localhost:8080/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn new_rejects_none_client_auth_for_local_mdns_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://idp.local/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn active_token_sets_authenticated_identity_when_no_consumer_match() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "scope": "read:data"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.priority(), priority::OAUTH2_INTROSPECTION);
    let mut ctx = make_ctx("opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert_eq!(ctx.auth_method, Some("oauth2_introspection"));
}

#[tokio::test]
async fn inactive_token_rejects_with_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    let mut ctx = make_ctx("opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn claims_to_headers_and_forward_original_false_strip_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "email": "user@example.com"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "forward_original_token": false,
                "claim_headers": {"email": "X-User-Email"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx("opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);

    let mut headers = HashMap::from([(
        "authorization".to_string(),
        "Bearer opaque-token".to_string(),
    )]);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(!headers.contains_key("authorization"));
    assert_eq!(
        headers.get("x-user-email").map(String::as_str),
        Some("user@example.com")
    );
}
