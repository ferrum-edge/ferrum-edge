//! Tests for key_auth plugin

use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{Consumer, default_namespace};
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, key_auth::KeyAuth, priority,
};
use http::HeaderMap;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_context,
};

const UNICODE_API_KEY: &str = "ユニコード-api-key-value-32chars-min";

fn create_unicode_key_consumer() -> Consumer {
    let mut keyauth = Map::new();
    keyauth.insert(
        "key".to_string(),
        Value::String(UNICODE_API_KEY.to_string()),
    );
    let mut credentials = HashMap::new();
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth)]),
    );
    Consumer {
        id: "consumer-unimap".to_string(),
        namespace: default_namespace(),
        username: "ユーザー".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn context_with_materialized_raw_header(name: &str, value: &str) -> RequestContext {
    context_with_materialized_raw_header_bytes(name, value.as_bytes())
}

fn context_with_materialized_raw_header_bytes(name: &str, value: &[u8]) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.headers.clear();
    ctx.identified_consumer = None;

    let mut raw = HeaderMap::new();
    let header_name = http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
    raw.insert(
        header_name,
        http::HeaderValue::from_bytes(value).expect("valid header bytes"),
    );
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    match std::str::from_utf8(value) {
        // Valid UTF-8 — including non-ASCII — is materialized byte-exact so the
        // outbound builders can forward it (issue #5010).
        Ok(decoded) => assert_eq!(
            ctx.headers
                .get(name.to_ascii_lowercase().as_str())
                .map(String::as_str),
            Some(decoded),
            "valid UTF-8 header values must be materialized byte-exact in this repro"
        ),
        Err(_) => assert!(
            !ctx.headers.contains_key(name.to_ascii_lowercase().as_str())
                && !ctx.headers.contains_key(name),
            "non-UTF-8 header values must stay out of the materialized map in this repro"
        ),
    }
    ctx
}

fn context_with_materialized_repeated_raw_header_bytes(
    name: &str,
    values: &[&[u8]],
) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.headers.clear();
    ctx.identified_consumer = None;

    let mut raw = HeaderMap::new();
    let header_name = http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
    for value in values {
        raw.append(
            header_name.clone(),
            http::HeaderValue::from_bytes(value).expect("valid header bytes"),
        );
    }
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx
}

fn assert_reject_body(result: PluginResult, expected_body: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(body, expected_body);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_key_auth_plugin_creation() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();
    assert_eq!(plugin.name(), "key_auth");
}

#[tokio::test]
async fn test_key_auth_plugin_default_config() {
    let config = json!({});
    let plugin = KeyAuth::new(&config).unwrap();
    assert_eq!(plugin.name(), "key_auth");
}

#[test]
fn test_key_auth_plugin_contract() {
    let plugin = KeyAuth::new(&json!({})).unwrap();

    assert_eq!(plugin.priority(), priority::KEY_AUTH);
    assert_eq!(plugin.priority(), 1200);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    assert!(plugin.modifies_request_headers());
    assert_eq!(plugin.request_headers_to_redact(), &["x-api-key"]);
    assert!(!plugin.requires_decoded_query_params());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(!plugin.needs_request_body_bytes());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_key_auth_rejects_invalid_config() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({"key_location": 123}),
        json!({"key_location": ""}),
        json!({"key_location": "cookie:token"}),
        json!({"key_location": "header:"}),
        json!({"key_location": "query:"}),
        json!({"hide_credentials": "yes"}),
        json!({"key_location": "header:Not A Header"}),
        json!({"key_location": "header:X@Api"}),
        json!({"key_location": "header:X\u{7f}Api"}),
        json!({"key_location": "header:X-Àpi"}),
        json!({"key_location": " header:X-API-Key"}),
        json!({"key_location": "header:X-API-Key "}),
        json!({"key_location": "header: X-API-Key"}),
        json!({"key_location": "query: api_key"}),
        json!({"key_location": "query:api_key "}),
        json!({"key_location": "query:   "}),
        json!({"key_location": "query:tenant key"}),
    ];

    for config in invalid_configs {
        assert!(
            KeyAuth::new(&config).is_err(),
            "config should be rejected: {config}"
        );
    }
}

#[test]
fn test_key_auth_rejects_unknown_config_fields() {
    for config in [
        json!({"key_lcoation": "query:api_key"}),
        json!({"key_names": ["X-API-Key"]}),
        json!({"aaa": true, "zzz": false}),
    ] {
        let err = KeyAuth::new(&config)
            .err()
            .expect("unknown key_auth fields must fail closed");
        assert!(err.contains("unknown configuration field"), "{err}");
    }
}

#[test]
fn test_key_auth_accepts_valid_mixed_case_header_token() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-Tenant_Key~V2"
    }))
    .expect("valid HTTP token characters should be accepted");

    assert_eq!(plugin.request_headers_to_redact(), &["x-tenant_key~v2"]);
}

#[test]
fn test_query_key_auth_requests_decoded_h3_query_params() {
    let plugin = KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap();

    assert!(plugin.requires_decoded_query_params());
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.request_headers_to_redact().is_empty());
}

#[tokio::test]
async fn test_key_auth_plugin_successful_auth() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test successful authentication
    let mut valid_ctx = create_test_context();
    valid_ctx
        .headers
        .insert("X-API-Key".to_string(), "test-api-key".to_string());

    let result = plugin.authenticate(&mut valid_ctx, &consumer_index).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_strips_successful_header_credential_before_proxy() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-Tenant-Credential"
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = create_test_context();
    ctx.headers.insert(
        "X-Tenant-Credential".to_string(),
        "test-api-key".to_string(),
    );

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert!(
        backend_headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-tenant-credential"))
    );
}

#[tokio::test]
async fn test_key_auth_can_explicitly_preserve_successful_header_credential() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-API-Key",
        "hide_credentials": false
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "test-api-key".to_string());

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert!(!plugin.modifies_request_headers());
    assert_eq!(
        backend_headers.get("X-API-Key").map(String::as_str),
        Some("test-api-key")
    );
}

#[tokio::test]
async fn test_key_auth_plugin_missing_key() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test failed authentication with missing key
    let mut invalid_ctx = create_test_context();
    invalid_ctx.headers.remove("X-API-Key");
    invalid_ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut invalid_ctx, &consumer_index).await;
    assert_continue(result);
    assert!(invalid_ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_plugin_invalid_key() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test failed authentication with invalid key
    let mut invalid_ctx = create_test_context();
    invalid_ctx
        .headers
        .insert("X-API-Key".to_string(), "invalid-key".to_string());

    let result = plugin.authenticate(&mut invalid_ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_plugin_query_parameter() {
    let config = json!({
        "key_location": "query:api_key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test successful authentication via query parameter
    let mut valid_ctx = create_test_context();
    valid_ctx.headers.remove("X-API-Key");
    valid_ctx.headers.remove("x-api-key");
    valid_ctx.identified_consumer = None;
    valid_ctx
        .query_params
        .insert("api_key".to_string(), "test-api-key".to_string());

    plugin.mark_query_credentials_for_redaction(&mut valid_ctx);
    let result = plugin.authenticate(&mut valid_ctx, &consumer_index).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
    assert_eq!(
        valid_ctx
            .metadata
            .get("auth.query_credential_param.api_key")
            .map(String::as_str),
        Some("true")
    );
    let mut backend_headers = valid_ctx.headers.clone();
    assert_continue(
        plugin
            .before_proxy(&mut valid_ctx, &mut backend_headers)
            .await,
    );
    assert!(!valid_ctx.query_params.contains_key("api_key"));
    assert_eq!(
        valid_ctx
            .metadata
            .get("auth.strip_query_param.api_key")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_key_auth_can_explicitly_preserve_successful_query_credential() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "query:api_key",
        "hide_credentials": false
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = create_test_context();
    ctx.query_params
        .insert("api_key".to_string(), "test-api-key".to_string());

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert_eq!(
        ctx.query_params.get("api_key").map(String::as_str),
        Some("test-api-key")
    );
    assert!(!ctx.metadata.contains_key("auth.strip_query_param.api_key"));
}

#[tokio::test]
async fn test_key_auth_empty_key_in_header_is_rejected() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert("X-API-Key".to_string(), "".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_whitespace_key_is_rejected() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "   ".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_case_insensitive_header_lookup() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Key lookup does lowercase fallback — test with lowercase header
    let mut ctx = create_test_context();
    ctx.headers.remove("X-API-Key");
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_missing_query_param() {
    let config = json!({
        "key_location": "query:apikey"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.query_params.clear();
    ctx.headers.remove("X-API-Key");
    ctx.headers.remove("x-api-key");
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_custom_header_name() {
    let config = json!({
        "key_location": "header:Authorization-Token"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert(
        "Authorization-Token".to_string(),
        "test-api-key".to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_key_auth_multiple_consumers_correct_match() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    // Create two consumers with different keys
    let mut consumer1 = create_test_consumer();
    consumer1.id = "consumer-1".to_string();
    consumer1.username = "user1".to_string();
    let mut keyauth1 = serde_json::Map::new();
    keyauth1.insert(
        "key".to_string(),
        serde_json::Value::String("key-one".to_string()),
    );
    consumer1.credentials.insert(
        "keyauth".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(keyauth1)]),
    );

    let mut consumer2 = create_test_consumer();
    consumer2.id = "consumer-2".to_string();
    consumer2.username = "user2".to_string();
    let mut keyauth2 = serde_json::Map::new();
    keyauth2.insert(
        "key".to_string(),
        serde_json::Value::String("key-two".to_string()),
    );
    consumer2.credentials.insert(
        "keyauth".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(keyauth2)]),
    );

    let consumer_index = ConsumerIndex::new(&[consumer1, consumer2]);

    // Authenticate with consumer2's key
    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "key-two".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "user2",
        "Should match the correct consumer"
    );
}

#[test]
fn test_key_auth_rejects_unknown_key_location_prefix() {
    let config = json!({
        "key_location": "cookie:token"
    });
    let err = match KeyAuth::new(&config) {
        Ok(_) => panic!("cookie key location should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("header:<name>"));
}

#[tokio::test]
async fn test_key_auth_empty_key_does_not_match_any_consumer() {
    // Defense in depth: even if a consumer was somehow registered with an
    // empty `key` value, an empty header value must not authenticate as
    // that consumer. The plugin short-circuits empty/whitespace keys
    // before consulting the consumer index.
    use chrono::Utc;
    use ferrum_edge::config::types::{Consumer, default_namespace};
    use serde_json::{Map, Value};
    use std::collections::HashMap;

    let config = json!({"key_location": "header:X-API-Key"});
    let plugin = KeyAuth::new(&config).unwrap();

    // Build a consumer with empty key (simulates misconfiguration).
    let mut keyauth = Map::new();
    keyauth.insert("key".to_string(), Value::String("".to_string()));
    let mut credentials = HashMap::new();
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth)]),
    );
    let consumer = Consumer {
        id: "empty-key-consumer".to_string(),
        namespace: default_namespace(),
        username: "ghost".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert("X-API-Key".to_string(), "".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_unicode_api_key_authenticates_via_header() {
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-API-Key", UNICODE_API_KEY);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "ユーザー"
    );
}

#[tokio::test]
async fn test_key_auth_unicode_api_key_authenticates_via_query() {
    let plugin = KeyAuth::new(&json!({"key_location": "query:apikey"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = create_test_context();
    ctx.headers.clear();
    ctx.identified_consumer = None;
    ctx.query_params
        .insert("apikey".to_string(), UNICODE_API_KEY.to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "ユーザー"
    );
}

#[tokio::test]
async fn test_key_auth_wrong_unicode_api_key_returns_invalid_not_missing() {
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx =
        context_with_materialized_raw_header("X-API-Key", "ユニコード-api-key-value-32chars-WRONG");

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid API key"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_missing_header_remains_continue_not_invalid_format() {
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = create_test_context();
    ctx.headers.clear();
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_invalid_utf8_header_returns_invalid_format() {
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header_bytes("X-API-Key", b"\xFF\xFE");

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid API key format"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_repeated_header_with_invalid_line_returns_invalid_format() {
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_repeated_raw_header_bytes(
        "X-API-Key",
        &[b"valid-ascii-key", b"\xFF\xFE"],
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid API key format"}"#);
    assert!(ctx.identified_consumer.is_none());
}

// ── Issue #5010: a preserved non-ASCII API key must reach the backend ────────
//
// `hide_credentials: false` documents that the reusable key is forwarded for a
// legacy backend. `RequestContext::materialize_headers()` used to decode field
// values with `HeaderValue::to_str()` (visible ASCII only), so a valid UTF-8
// key was absent from the materialized map — and the outbound merge treats
// absence as a plugin removal. Authentication succeeded and the key silently
// disappeared upstream, while the same route preserved an ASCII key.

#[tokio::test]
async fn test_key_auth_preserved_unicode_header_credential_reaches_the_backend() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-API-Key",
        "hide_credentials": false
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-API-Key", UNICODE_API_KEY);

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert!(!plugin.modifies_request_headers());
    assert_eq!(
        backend_headers.get("x-api-key").map(String::as_str),
        Some(UNICODE_API_KEY),
        "an explicitly preserved Unicode key must be forwarded byte-exact"
    );
}

#[tokio::test]
async fn test_key_auth_preserved_unicode_credential_on_a_custom_header_name() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-Tenant-Credential",
        "hide_credentials": false
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-Tenant-Credential", UNICODE_API_KEY);

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert_eq!(
        backend_headers
            .get("x-tenant-credential")
            .map(String::as_str),
        Some(UNICODE_API_KEY)
    );
}

#[tokio::test]
async fn test_key_auth_default_hide_credentials_still_strips_a_unicode_header_key() {
    // Non-vacuity for the two tests above: the byte-exact materialization must
    // not resurrect a credential the default policy removes.
    let plugin = KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-API-Key", UNICODE_API_KEY);

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    assert!(plugin.modifies_request_headers());
    assert!(
        backend_headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-api-key")),
        "the default policy must still remove a Unicode key"
    );
}

#[tokio::test]
async fn test_key_auth_preserved_invalid_utf8_header_key_is_still_not_forwarded() {
    // A field line that is not valid UTF-8 cannot be represented in the
    // materialized map at all, so it stays out of the backend request. It also
    // never authenticates: extraction reports invalid format, not absent.
    let plugin = KeyAuth::new(&json!({
        "key_location": "header:X-API-Key",
        "hide_credentials": false
    }))
    .unwrap();
    let consumer_index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header_bytes("X-API-Key", b"\xFF\xFE");

    assert_reject_body(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        r#"{"error":"Invalid API key format"}"#,
    );
    assert!(
        ctx.headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-api-key"))
    );
}
