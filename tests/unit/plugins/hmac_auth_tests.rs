//! Tests for hmac_auth plugin

use base64::Engine;
use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::{Plugin, RequestContext, hmac_auth::HmacAuth};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const TEST_SECRET: &str = "my-hmac-secret-key";

/// Create a consumer with hmac_auth credentials.
fn create_hmac_consumer() -> Consumer {
    let mut credentials = HashMap::new();
    let mut hmac_creds = Map::new();
    hmac_creds.insert("secret".to_string(), Value::String(TEST_SECRET.to_string()));
    credentials.insert("hmac_auth".to_string(), Value::Object(hmac_creds));

    Consumer {
        id: "hmac-consumer".to_string(),
        username: "hmacuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a consumer without hmac_auth credentials (only has keyauth).
fn create_consumer_without_hmac_creds() -> Consumer {
    let mut credentials = HashMap::new();
    let mut keyauth_creds = Map::new();
    keyauth_creds.insert("key".to_string(), Value::String("some-key".to_string()));
    credentials.insert("keyauth".to_string(), Value::Object(keyauth_creds));

    Consumer {
        id: "no-hmac-consumer".to_string(),
        username: "nokeyuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

/// Generate a current RFC 2822 date string.
fn current_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Compute an HMAC-SHA256 signature over `METHOD\nPATH\nDATE` and return base64.
fn sign_sha256(secret: &str, method: &str, path: &str, date: &str) -> String {
    let signing_string = format!("{}\n{}\n{}", method, path, date);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Compute an HMAC-SHA512 signature over `METHOD\nPATH\nDATE` and return base64.
fn sign_sha512(secret: &str, method: &str, path: &str, date: &str) -> String {
    let signing_string = format!("{}\n{}\n{}", method, path, date);
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Build the Authorization header value.
fn hmac_auth_header(username: &str, algorithm: Option<&str>, signature: &str) -> String {
    match algorithm {
        Some(alg) => format!(
            r#"hmac username="{}", algorithm="{}", signature="{}""#,
            username, alg, signature
        ),
        None => format!(r#"hmac username="{}", signature="{}""#, username, signature),
    }
}

// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_hmac_auth_plugin_creation() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
    assert!(plugin.is_auth_plugin());
}

#[tokio::test]
async fn test_hmac_auth_custom_clock_skew() {
    let plugin = HmacAuth::new(&json!({"clock_skew_seconds": 600})).unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
}

// ── 1. Valid HMAC-SHA256 authentication ──────────────────────────────

#[tokio::test]
async fn test_valid_hmac_sha256() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

// ── 2. Valid HMAC-SHA512 authentication ──────────────────────────────

#[tokio::test]
async fn test_valid_hmac_sha512() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha512"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

// ── 3. Missing Authorization header ──────────────────────────────────

#[tokio::test]
async fn test_missing_authorization_header() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    // No authorization header set
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 4. Invalid auth format (not starting with "hmac ") ──────────────

#[tokio::test]
async fn test_invalid_auth_format_bearer() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_invalid_auth_format_basic() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 5. Missing username in auth header ──────────────────────────────

#[tokio::test]
async fn test_missing_username() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        r#"hmac algorithm="hmac-sha256", signature="abc123""#.to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 6. Missing signature in auth header ──────────────────────────────

#[tokio::test]
async fn test_missing_signature() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        r#"hmac username="hmacuser", algorithm="hmac-sha256""#.to_string(),
    );
    ctx.headers.insert("date".to_string(), current_date());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 7. Missing Date header ──────────────────────────────────────────

#[tokio::test]
async fn test_missing_date_header() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Sign with empty date since that's what the plugin will see
    let signature = sign_sha256(TEST_SECRET, method, path, "");

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    // No date header
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 8. Expired Date header (clock skew exceeded) ─────────────────────

#[tokio::test]
async fn test_expired_date_header() {
    // Use a very tight clock skew of 1 second
    let plugin = HmacAuth::new(&json!({"clock_skew_seconds": 1})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Use a date far in the past
    let old_date = "Mon, 01 Jan 2024 00:00:00 GMT";
    let signature = sign_sha256(TEST_SECRET, method, path, old_date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), old_date.to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_unparseable_date_header() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let bad_date = "not-a-date";
    let signature = sign_sha256(TEST_SECRET, method, path, bad_date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), bad_date.to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 9. Unknown consumer ──────────────────────────────────────────────

#[tokio::test]
async fn test_unknown_consumer() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("nonexistent-user", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_empty_consumer_index() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 10. Consumer without hmac_auth credentials ──────────────────────

#[tokio::test]
async fn test_consumer_without_hmac_credentials() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_consumer_without_hmac_creds();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256("irrelevant-secret", method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("nokeyuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 11. Invalid signature ────────────────────────────────────────────

#[tokio::test]
async fn test_invalid_signature() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(
            "hmacuser",
            Some("hmac-sha256"),
            "dGhpcy1pcy1ub3QtYS12YWxpZC1zaWduYXR1cmU=",
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_secret() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with wrong secret
    let signature = sign_sha256("wrong-secret", method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_method() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with different method
    let signature = sign_sha256(TEST_SECRET, "POST", path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_path() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with different path
    let signature = sign_sha256(TEST_SECRET, method, "/other", &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ── 12. Default algorithm (when algorithm not specified) ─────────────

#[tokio::test]
async fn test_default_algorithm_is_sha256() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with SHA256 (the expected default)
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    // No algorithm specified in header
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", None, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

// ── Additional edge-case tests ───────────────────────────────────────

#[tokio::test]
async fn test_case_insensitive_hmac_prefix() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    // Use uppercase "HMAC" prefix
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            r#"HMAC username="hmacuser", algorithm="hmac-sha256", signature="{}""#,
            signature
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    // The plugin does .to_lowercase().starts_with("hmac "), so HMAC should work
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_rfc3339_date_format() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    // Use RFC 3339 date format
    let date = Utc::now().to_rfc3339();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_algorithm_name_is_case_insensitive() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("HMAC-SHA512"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_unknown_algorithm_rejected() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("sha1"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_sha512_with_default_algorithm_fails() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/test";
    let date = current_date();
    // Sign with SHA512 but don't specify algorithm (defaults to SHA256)
    let signature = sign_sha512(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", None, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    // SHA512 signature won't match SHA256 expected
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_consumer_set_on_successful_auth() {
    let plugin = HmacAuth::new(&json!({})).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "PUT";
    let path = "/api/resource/42";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);

    let identified = ctx.identified_consumer.as_ref().unwrap();
    assert_eq!(identified.id, "hmac-consumer");
    assert_eq!(identified.username, "hmacuser");
}
