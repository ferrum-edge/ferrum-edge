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

#[test]
fn constructor_type_diagnostics_quote_complete_json_values() {
    for (value, expected) in [
        (json!(9876543210u64), "`key_location` must be a string"),
        (
            json!([["prefix'\"UNREGISTERED_TYPE_TOKEN"]]),
            "`key_location` array element 0 must be a string",
        ),
        (
            json!({"nested": "prefix'\"UNREGISTERED_TYPE_TOKEN"}),
            "`key_location` must be a string",
        ),
    ] {
        let error = KeyAuth::new(&json!({"key_location": value})).err().unwrap();
        let diagnostic = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(diagnostic.contains(expected), "{diagnostic}");
        assert!(diagnostic.contains("<redacted scalar>"), "{diagnostic}");
        assert!(!diagnostic.contains("9876543210"), "{diagnostic}");
        assert!(
            !diagnostic.contains("UNREGISTERED_TYPE_TOKEN"),
            "{diagnostic}"
        );
    }
}

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
        labels: Default::default(),
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
        labels: Default::default(),
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

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (
            json!({(canary): true}),
            &[
                "unknown configuration field",
                "`key_location`",
                "`hide_credentials`",
            ],
        ),
        (
            json!({"key_location": 8675309}),
            &["`key_location`", "must be a string"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("key_auth", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}

// ── `;` sub-parameter credential aliases (query locations) ─────────────────

const AMBIGUOUS_QUERY_BODY: &str = r#"{"error":"Ambiguous API key query parameter"}"#;

/// A request context whose query is parsed exactly as the H1/H2 and H3
/// frontends parse it: the raw wire query retained, then split on `&` only.
fn context_with_raw_query(raw_query: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/resource".to_string(),
    );
    ctx.set_raw_query_string(raw_query.to_string());
    ctx.materialize_query_params();
    ctx
}

/// The reviewed scenario: another mechanism (here simulated by never calling
/// `authenticate`) wins a multi-auth chain while the custom query credential
/// rides only behind a `;`. Discovery runs for every auth instance before the
/// chain short-circuits, and `before_proxy` runs for every plugin, so the
/// alias must be marked for policy redaction AND stripped from the forwarded
/// query.
#[tokio::test]
async fn test_key_auth_hides_a_semicolon_alias_when_another_mechanism_wins() {
    let plugin = KeyAuth::new(&json!({"key_location": "query:tenant_ticket"})).unwrap();
    let mut ctx = context_with_raw_query("carrier=;tenant_ticket=launch-key-0123456789&keep=1");
    assert!(
        !ctx.query_params.contains_key("tenant_ticket"),
        "Ferrum's `&`-only parser does not see the alias as the configured name"
    );

    plugin.mark_query_credentials_for_redaction(&mut ctx);
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.tenant_ticket")
            .map(String::as_str),
        Some("true"),
        "the alias must be marked so delegated-policy payloads redact it"
    );
    let mut backend_headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);

    let forwarded = ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx);
    assert_eq!(forwarded, "keep=1");
    assert!(!forwarded.contains("launch-key-0123456789"));
}

#[tokio::test]
async fn test_key_auth_semicolon_alias_respects_explicit_preservation() {
    let plugin = KeyAuth::new(&json!({
        "key_location": "query:tenant_ticket",
        "hide_credentials": false
    }))
    .unwrap();
    let mut ctx = context_with_raw_query("carrier=;tenant_ticket=launch-key-0123456789&keep=1");
    plugin.mark_query_credentials_for_redaction(&mut ctx);
    // Policy redaction still applies; forwarding is the operator's opt-out.
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.tenant_ticket")
            .map(String::as_str),
        Some("true")
    );
    assert!(
        !ctx.metadata
            .contains_key("auth.strip_query_param.tenant_ticket")
    );
}

#[tokio::test]
async fn test_key_auth_refuses_an_ambiguous_semicolon_query_credential() {
    let plugin = KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    for raw_query in [
        // Only the alias carries the (valid) key: it must not authenticate.
        "carrier=;api_key=test-api-key",
        // A valid ordinary occurrence beside a different aliased value.
        "api_key=test-api-key&carrier=;api_key=other-key-0123456789",
        // The `;` sits in the NAME, so Ferrum's name is `api_key;x`.
        "api_key;x=1&carrier=1",
        // Percent-encoded sub-pair name.
        "carrier=;api%5Fkey=test-api-key",
    ] {
        let mut ctx = context_with_raw_query(raw_query);
        assert_reject_body(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            AMBIGUOUS_QUERY_BODY,
        );
        assert!(ctx.identified_consumer.is_none(), "{raw_query}");
    }
}

#[tokio::test]
async fn test_key_auth_semicolon_inside_a_value_is_not_an_alias() {
    let plugin = KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // Ferrum reads the whole value `test-api-key;x=1`; that is a lookup miss,
    // not an ambiguity.
    let mut ctx = context_with_raw_query("api_key=test-api-key;x=1");
    assert_reject_body(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        r#"{"error":"Invalid API key"}"#,
    );

    // An unrelated `;` elsewhere leaves an ordinary credential authenticating.
    let mut ctx = context_with_raw_query("api_key=test-api-key&carrier=a;b=c");
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert!(ctx.identified_consumer.is_some());
}

// ── Borrowed credential lookup (no behavior change) ────────────────────────

/// The authenticate hook borrows the key from the request instead of copying
/// it into an owned credential. Outcomes must be exactly the shared flow's:
/// a folded repeated header still misses (blank keys stay pinned by
/// `test_key_auth_whitespace_key_is_rejected`), and a successful lookup still
/// commits the consumer and method.
#[tokio::test]
async fn test_key_auth_borrowed_lookup_keeps_the_shared_auth_contract() {
    let plugin = KeyAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let expected_username = create_test_consumer().username;
    let mut single = context_with_materialized_raw_header("x-api-key", "test-api-key");
    assert_continue(plugin.authenticate(&mut single, &consumer_index).await);
    assert_eq!(
        single
            .identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str()),
        Some(expected_username.as_str())
    );
    assert_eq!(single.auth_method, Some("key_auth"));

    let mut repeated = context_with_materialized_repeated_raw_header_bytes(
        "x-api-key",
        &[b"test-api-key", b"test-api-key"],
    );
    assert_reject_body(
        plugin.authenticate(&mut repeated, &consumer_index).await,
        r#"{"error":"Invalid API key"}"#,
    );
    assert!(repeated.identified_consumer.is_none());
}

// Multiple credential locations (issue #6910).

#[test]
fn test_key_auth_array_bounds_and_element_validation() {
    for locations in [
        json!([]),
        json!(vec!["header:X-Key"; 9]),
        json!([null]),
        json!([123]),
        json!([true]),
        json!([{}]),
        json!([["header:X-Key"]]),
        json!(["header:X-Key", ""]),
        json!(["header:X-Key", "cookie:key"]),
        json!(["header:X-Key", "header:"]),
        json!(["header:X-Key", "header:Bad Name"]),
        json!(["header:X-Key", "query:"]),
        json!(["header:X-Key", "query: bad"]),
        json!(["header:X-Key", "query:key "]),
    ] {
        assert!(KeyAuth::new(&json!({"key_location": locations})).is_err());
    }
    for locations in [
        json!(["header:X-Key"]),
        json!(["query:key"]),
        json!(
            (0..8)
                .map(|i| format!("header:X-Key-{i}"))
                .collect::<Vec<_>>()
        ),
    ] {
        assert!(KeyAuth::new(&json!({"key_location": locations})).is_ok());
    }
}

#[tokio::test]
async fn test_key_auth_authenticates_each_location_and_ignores_unconfigured_sources() {
    let plugin = KeyAuth::new(&json!({
        "key_location": ["header:X-First", "query:first", "header:X-Last", "query:last"]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    assert!(plugin.requires_decoded_query_params());
    assert!(plugin.modifies_request_query());
    assert!(plugin.modifies_request_headers());
    assert_eq!(plugin.request_headers_to_redact(), &["x-first", "x-last"]);
    assert_eq!(
        plugin.modified_request_header_names().unwrap(),
        ["x-first", "x-last"]
    );

    for (header, name) in [
        (true, "x-first"),
        (false, "first"),
        (true, "X-Last"),
        (false, "last"),
    ] {
        let mut ctx = context_with_raw_query("unconfigured=test-api-key");
        ctx.headers
            .insert("x-api-key".into(), "unconfigured-key".into());
        if header {
            ctx.headers.insert(name.into(), "test-api-key".into());
        } else {
            ctx.query_params.insert(name.into(), "test-api-key".into());
        }
        assert_continue(plugin.authenticate(&mut ctx, &index).await);
        assert_eq!(ctx.auth_method, Some("key_auth"));
        assert!(ctx.identified_consumer.is_some());
    }
    let mut missing = context_with_raw_query("unconfigured=test-api-key");
    assert_continue(plugin.authenticate(&mut missing, &index).await);
    assert!(missing.identified_consumer.is_none());
}

#[tokio::test]
async fn test_key_auth_refuses_two_different_configured_locations() {
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    // Header/header, query/query, and both mixed orderings must agree. Blank
    // and invalid credentials are still present; equality never excuses two.
    for locations in [
        ["header:X-First", "header:X-Second"],
        ["query:first", "query:second"],
        ["header:X-First", "query:second"],
        ["query:first", "header:X-Second"],
    ] {
        let plugin = KeyAuth::new(&json!({"key_location": locations})).unwrap();
        for values in [
            ["test-api-key", "test-api-key"],
            ["test-api-key", "wrong"],
            ["", "test-api-key"],
            ["test-api-key", ""],
        ] {
            let mut ctx = context_with_raw_query("");
            for (location, value) in locations.into_iter().zip(values) {
                if let Some(name) = location.strip_prefix("header:") {
                    ctx.headers.insert(name.into(), value.into());
                } else {
                    ctx.query_params.insert(
                        location.strip_prefix("query:").unwrap().into(),
                        value.into(),
                    );
                }
            }
            match plugin.authenticate(&mut ctx, &index).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    assert_eq!(status_code, 401);
                    assert_eq!(body, r#"{"error":"Ambiguous API key locations"}"#);
                    assert_eq!(
                        headers.get("WWW-Authenticate").map(String::as_str),
                        Some(r#"ApiKey realm="ferrum-edge""#)
                    );
                }
                other => panic!("expected ambiguous credential rejection, got {other:?}"),
            }
            assert!(ctx.identified_consumer.is_none());
            assert!(ctx.auth_method.is_none());
        }
    }
}

#[tokio::test]
async fn test_key_auth_array_retains_raw_utf8_and_semicolon_validation() {
    let plugin = KeyAuth::new(&json!({
        "key_location": ["header:X-First", "header:X-Last", "query:ticket"]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_unicode_key_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-Last", UNICODE_API_KEY);
    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_eq!(ctx.auth_method, Some("key_auth"));

    let mut malformed = context_with_materialized_raw_header_bytes("X-Last", b"\xff");
    assert_reject_body(
        plugin.authenticate(&mut malformed, &index).await,
        r#"{"error":"Invalid API key format"}"#,
    );
    malformed
        .headers
        .insert("X-First".into(), UNICODE_API_KEY.into());
    assert_reject_body(
        plugin.authenticate(&mut malformed, &index).await,
        r#"{"error":"Ambiguous API key locations"}"#,
    );

    let mut alias = context_with_raw_query("carrier=;ticket=test-api-key");
    assert_reject_body(
        plugin.authenticate(&mut alias, &index).await,
        AMBIGUOUS_QUERY_BODY,
    );
}

#[tokio::test]
async fn test_key_auth_repeated_locations_are_one_source_but_query_case_is_distinct() {
    let plugin = KeyAuth::new(&json!({
        "key_location": ["header:X-Key", "header:x-key", "query:key", "query:key", "query:Key"]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = context_with_materialized_raw_header("x-key", "test-api-key");
    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_eq!(plugin.request_headers_to_redact(), &["x-key"]);
    let mut ctx = context_with_raw_query("key=test-api-key");
    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    let mut ctx = context_with_raw_query("key=test-api-key&Key=test-api-key");
    assert_reject_body(
        plugin.authenticate(&mut ctx, &index).await,
        r#"{"error":"Ambiguous API key locations"}"#,
    );
}

#[tokio::test]
async fn test_key_auth_marks_and_hides_all_locations_when_another_mechanism_wins() {
    for hide in [true, false] {
        let plugin = KeyAuth::new(&json!({
            "key_location": ["header:X-First", "query:first", "header:X-Last", "query:last"],
            "hide_credentials": hide
        }))
        .unwrap();
        // Deliberately skip key_auth.authenticate, as when an earlier mechanism
        // wins. Discovery and before_proxy must still cover all locations.
        let mut ctx = context_with_raw_query("first=a&first=b&carrier=;last=c&keep=1");
        plugin.mark_query_credentials_for_redaction(&mut ctx);
        let mut headers = HashMap::from([
            ("x-first".to_string(), "a".to_string()),
            ("X-Last".to_string(), "c".to_string()),
            ("x-benign".to_string(), "keep".to_string()),
        ]);
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(headers.contains_key("x-first"), !hide);
        assert_eq!(headers.contains_key("X-Last"), !hide);
        assert_eq!(headers.get("x-benign").map(String::as_str), Some("keep"));
        for name in ["first", "last"] {
            assert_eq!(
                ctx.metadata
                    .get(&format!("auth.query_credential_param.{name}"))
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(
                ctx.metadata
                    .contains_key(&format!("auth.strip_query_param.{name}")),
                hide
            );
        }
        let forwarded = ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx);
        assert_eq!(
            forwarded,
            if hide {
                "keep=1"
            } else {
                "first=a&first=b&carrier=;last=c&keep=1"
            }
        );
        assert_eq!(plugin.modifies_request_headers(), hide);
        assert_eq!(plugin.modifies_request_query(), hide);
        assert_eq!(plugin.request_headers_to_redact(), &["x-first", "x-last"]);
    }
}
